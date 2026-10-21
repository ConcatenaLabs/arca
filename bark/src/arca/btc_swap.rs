//! A swap of native BTC, held in a Bitcoin ark through Bark, for an asset
//! held in this operator's tree, under one payment hash.
//!
//! **P** gives `atoms` of an asset X and gets `sats` of BTC; **Q** gives the
//! BTC and gets the X. Either may make the offer. Each leg is one hash-lock:
//! on the Bitcoin side, Q's payment of P's Bark invoice `I_B` (Bark's
//! HTLC-send and HTLC-recv VTXOs, in one Bitcoin ark); on the Sequentia side,
//! P's `htlc-1` send leaf `S` paying the operator's invoice `I_X` for Q's
//! receive, whose leaf `R` the operator issues to Q, settled inside the
//! operator (both wallets are this operator's). Nothing is pegged: the BTC
//! leg is native BTC on Bitcoin, and X is any asset the operator serves.
//!
//! - **The hash is P's.** Bark makes every invoice's preimage itself and
//!   takes no hash, so `H` is the hash of P's Bark invoice, and Q asks its
//!   Arca receive under it ([`Wallet::lightning_receive_under`]).
//! - **P locks first, on the Sequentia side** ([`Wallet::lightning_pay_until`]),
//!   with a send leaf timing out at `t_S` ([`send_timeout`]) late enough that
//!   Q can take `R` home after the latest moment the Bitcoin leg can reveal
//!   the preimage or give Q its BTC back ([`bitcoin_latest`]); the operator
//!   times `R` out its internal gap before `t_S`.
//! - **Q locks second, on the Bitcoin side**, and only once `R` is held
//!   validated, its round final (certified, its anchor buried), its terms
//!   the swap's, and its home date at least an hour past that latest moment
//!   ([`Wallet::btc_swap_ready`]); Q pays `I_B` once.
//! - **P reveals the preimage only by claiming the BTC**, which Bark grants
//!   only against Q's locked payment; P then posts it to the operator, so
//!   `S` is the operator's and Q has a second source. Q takes the preimage
//!   from its payment's status, or from the operator's, and claims `R`.
//! - **P never claims a payment to `I_B` as a fresh invoice**: a payment that
//!   can no longer be claimed ends the Bitcoin leg, and the swap ends by the
//!   Sequentia leg's refund.
//!
//! An abandoned swap leaves each leg with exactly one party: before P locks,
//! nothing is locked; P's lock comes back to P once the operator fails Q's
//! receive back (its leaf never came, or was not claimed by its time); Q's
//! payment comes back to Q once Bark fails it back or cancels P's receive at
//! `I_B`'s expiry.
//!
//! The library never runs Bark: what the Bitcoin side says (Bark's
//! `ark-info`, a fee quote, an invoice, a claim's or a payment's outcome) is
//! handed in by the program that runs it, and [`Wallet::btc_swap_follow`]
//! says what it must run next (`claim`, `pay`, `pay_status`, `cancel_receive`).
//!
//! Clocks meet only in wall time: a Bitcoin height `n` blocks ahead is taken
//! as `2·n·600` seconds away (Bitcoin at half its pace), and each comparison
//! between the chains compares durations, each from its own clock's now.

use std::collections::BTreeMap;
use std::str::FromStr;

use elements::hashes::{sha256, Hash};
use elements::AssetId;
use serde_json::{json, Value};

use super::chain::{hex, unhex32};
use super::lightning::{network_of, parse_invoice, Invoice};
use super::wallet::{amount, Wallet};
use super::{random32, Error};

/// Where the wallet keeps its swaps: a map from the swap's id to its record.
pub(crate) const SWAPS: &str = "btc_swaps";

/// What an offer's and a take's JSON say they are (`kind`), and the prefix
/// of their texts.
pub const OFFER_KIND: &str = "btc-swap-offer";
pub const TAKE_KIND: &str = "btc-swap-take";

/// The time a party has to act once it must: Q to claim `R` after the
/// Bitcoin leg's latest moment (ρ).
pub const REACTION: u64 = 3600;
/// An unroll of a received leaf, at two blocks a step (u).
pub const UNROLL: u64 = 3600;
/// Bitcoin's target spacing (β), on every network Bark serves.
pub const BITCOIN_BLOCK: u64 = 600;
/// Blocks past Bark's HTLC-send expiry delta in which P's claim on the
/// chain confirms, at the latest.
pub const SEND_EXPIRY_EXTRA: u64 = 6;
/// Slack past the Bitcoin leg's latest moment.
pub const LATEST_SLACK: u64 = 600;
/// Q pays `I_B` only while it has this long left before it expires: time
/// for the payment and P's claim, which Bark's server ends at the expiry.
pub const PAY_LEFT: u64 = 600;
/// P locks `S` only while `I_B` has this long left: time for `R`'s round and
/// its finality, and Q's payment.
pub const LOCK_LEFT: u64 = 1800;
/// How many times Q hands a payment of `I_B` to Bark, at most: a retry of a
/// payment Bark failed back fails at once and refunds in full.
pub const PAY_TRIES: u64 = 3;

/// The latest moment, in wall time, the Bitcoin leg can reveal the preimage
/// to Q or give Q its BTC back (W6): `I_B`'s expiry (Bark's server cancels
/// P's receive then, granted or not) or the confirmation of P's claim on the
/// chain before its HTLC-recv VTXOs expire, within Bark's HTLC-send expiry
/// delta and a few blocks more, at half Bitcoin's pace; and ten minutes.
pub fn bitcoin_latest(ark_info: &Value, invoice_expiry: u64, wall_now: u64) -> Result<u64, Error> {
	let delta = ark_info["htlc_send_expiry_delta"].as_u64()
		.ok_or_else(|| Error::Refused("the Bitcoin ark publishes no htlc_send_expiry_delta (ark-info)".into()))?;
	Ok(invoice_expiry.max(wall_now + (delta + SEND_EXPIRY_EXTRA) * 2 * BITCOIN_BLOCK) + LATEST_SLACK)
}

/// The send leaf's timeout `t_S` (W7), a median time: late enough that Q's
/// received leaf, timing out `gap` before it, keeps a home date (its
/// timeout less its unroll, its exit delay `exit_q` and an eighth of its
/// lock) at least [`REACTION`] past the Bitcoin leg's latest moment, and
/// keeps the receive's least lock (eight sevenths of `exit_q` and the
/// operator's window `window`); and an hour more.
pub fn send_timeout(median_now: u64, wall_now: u64, latest: u64, exit_q: u64, window: u64, gap: u64) -> u64 {
	let after_latest = (8 * (latest.saturating_sub(wall_now) + REACTION + UNROLL + exit_q)).div_ceil(7);
	let least = (8 * (exit_q + window)).div_ceil(7);
	median_now + after_latest.max(least) + gap + 3600
}

fn wall_now() -> u64 {
	web_time::SystemTime::now().duration_since(web_time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn encode(kind: &str, v: &Value) -> String {
	format!("{}:{}", kind, hex(v.to_string().as_bytes()))
}

fn decode(kind: &str, s: &str, what: &str) -> Result<Value, Error> {
	let (_, h) = s.trim().split_once(':').ok_or_else(|| Error::Parse(format!("{}: it has no prefix", what)))?;
	if h.len() % 2 != 0 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
		return Err(Error::Parse(format!("{}: not hex after its prefix", what)));
	}
	let bytes = (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16)).collect::<Result<Vec<_>, _>>()
		.map_err(|e| Error::Parse(format!("{}: {}", what, e)))?;
	let v: Value = serde_json::from_slice(&bytes).map_err(|e| Error::Parse(format!("{}: {}", what, e)))?;
	if v["kind"].as_str() != Some(kind) {
		return Err(Error::Parse(format!("{}: the text is not a {}", what, kind)));
	}
	Ok(v)
}

/// What a party gives and gets, and every fee, before anything is locked.
fn shows(role: &str, asset: &str, atoms: u64, sats: u64, op_fee: u64, btc_fee: &Value) -> Value {
	let btc_fee_sat = btc_fee["fee_sat"].as_u64();
	match role {
		"P" => json!({
			"gives": {"asset": asset, "atoms": (atoms + op_fee).to_string(), "of_which_fee": op_fee.to_string(),
				"note": "the asset's atoms go into an htlc-1 leaf of the wallet's own, the operator's fee for the payment with them"},
			"gets": {"asset": "BTC", "sat": btc_fee_sat.map(|f| sats.saturating_sub(f).to_string()), "of": sats.to_string(),
				"bark_fee_sat": btc_fee_sat, "note": "native BTC in the Bitcoin ark, less the Bitcoin ark's fee for receiving it"},
		}),
		_ => json!({
			"gives": {"asset": "BTC", "sat": btc_fee_sat.map(|f| (sats + f).to_string()), "of": sats.to_string(), "bark_fee_sat": btc_fee_sat,
				"note": "native BTC from the Bitcoin ark, with the Bitcoin ark's fee for paying it (its estimate for the coins it would spend now)"},
			"gets": {"asset": asset, "atoms": atoms.saturating_sub(op_fee).to_string(), "of": atoms.to_string(), "operator_fee": op_fee.to_string(),
				"note": "a leaf of the asset, less the operator's fee for receiving it; claiming the leaf takes its transfer's margins too"},
		}),
	}
}

/// The parts of an offer every swap record repeats.
struct Terms {
	asset: AssetId,
	atoms: u64,
	sats: u64,
	maker_gives: String,
}

impl Terms {
	fn of(offer: &Value) -> Result<Terms, Error> {
		let asset = AssetId::from_str(offer["asset"].as_str().unwrap_or("")).map_err(|e| Error::Parse(format!("the offer's asset: {}", e)))?;
		let atoms = amount(&offer["atoms"], "the offer's atoms")?;
		let sats = amount(&offer["sats"], "the offer's satoshis")?;
		let maker_gives = offer["maker_gives"].as_str().filter(|g| matches!(*g, "btc" | "asset"))
			.ok_or_else(|| Error::Parse("the offer says neither that its maker gives BTC nor the asset".into()))?.to_string();
		Ok(Terms { asset, atoms, sats, maker_gives })
	}
}

impl Wallet {
	pub(crate) fn btc_swaps_map(&self) -> Result<BTreeMap<String, Value>, Error> {
		Ok(self.store.meta(SWAPS)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default())
	}

	fn set_btc_swap(&self, id: &str, mut v: Value) -> Result<(), Error> {
		v["updated_at"] = json!(wall_now());
		let mut m = self.btc_swaps_map()?;
		m.insert(id.to_string(), v);
		self.store.set_meta(SWAPS, &serde_json::to_string(&m).expect("a map"))
	}

	fn btc_swap(&self, id: &str) -> Result<Value, Error> {
		self.btc_swaps_map()?.get(id).cloned().ok_or_else(|| Error::Refused(format!("the wallet has no BTC swap {}", id)))
	}

	/// The Lightning terms the operator serves `asset` with: refused when it
	/// serves the asset with no Lightning node that receives, or the node is
	/// down. Its fee for `atoms`.
	fn swap_leg(&self, info: &Value, asset: AssetId, atoms: u64) -> Result<u64, Error> {
		let leg = info["assets"].as_array().into_iter().flatten().find(|a| a["asset"].as_str() == Some(&asset.to_string()))
			.map(|a| a["lightning"].clone())
			.ok_or_else(|| Error::Refused(format!("the operator does not serve asset {}", asset)))?;
		if leg.is_null() || leg["receives"] != true {
			return Err(Error::Refused(format!("the operator receives asset {} over no Lightning node: a swap's Sequentia leg is a \
				payment into its tree", asset)));
		}
		if leg["state"] != "up" {
			return Err(Error::Refused(format!("the operator's Lightning node in asset {} is down: {}", asset,
				leg["reason"].as_str().unwrap_or("no reason given"))));
		}
		let fee = super::lightning::fee_of(info, asset, atoms)?;
		if atoms <= fee || atoms - fee < Self::min_leaf(info, asset)? {
			return Err(Error::Refused(format!("{} atoms of asset {} less the operator's fee of {} are below its smallest leaf", atoms,
				asset, fee)));
		}
		Ok(fee)
	}

	/// The Bitcoin invoice `I_B` of a swap, read and checked: a Bitcoin
	/// invoice on the Bitcoin ark's network, for exactly `sats`, with time
	/// left to run the swap.
	fn swap_invoice(invoice: &str, sats: u64, ark_info: &Value, left: u64) -> Result<(Invoice, u64), Error> {
		let inv = parse_invoice(invoice)?;
		match network_of(&inv.currency) {
			Some((_, false)) => {},
			_ => return Err(Error::Refused(format!("the swap's invoice is not a Bitcoin invoice (currency {:?})", inv.currency))),
		}
		let net = network_of(&inv.currency).map(|n| n.0).unwrap_or("");
		let ark_net = ark_info["network"].as_str().unwrap_or("");
		let same = net == ark_net || (net == "testnet" && matches!(ark_net, "testnet4" | "testnet3"));
		if !same {
			return Err(Error::Refused(format!("the swap's invoice is for {}, and the Bitcoin ark runs on {}", net, ark_net)));
		}
		if inv.amount_msat != Some(sats * 1000) {
			return Err(Error::Refused(format!("the swap's invoice asks {:?} msat, and the swap is for {} sat", inv.amount_msat, sats)));
		}
		let expiry = inv.timestamp + inv.expiry;
		if expiry < wall_now() + left {
			return Err(Error::Refused(format!("the swap's invoice expires at {} (unix time), less than {} s from now: too soon to run \
				the swap", expiry, left)));
		}
		Ok((inv, expiry))
	}

	/// Offers a swap: `gives` is `btc` (the maker is Q, who gives `sats` of
	/// BTC for `atoms` of `asset`) or `asset` (the maker is P, who gives the
	/// atoms for the BTC). `bitcoin` is what the Bitcoin side says:
	/// `ark_info` (Bark's), `fee` (Bark's fee quote for the maker's side),
	/// and, when the maker is P, `invoice`, its Bark invoice for `sats`. The
	/// offer lapses after `lapse_seconds`, or with P's invoice. Nothing is
	/// locked. Returns the swap's id, the offer's text, and what the maker
	/// gives and gets, with every fee.
	pub fn btc_swap_offer(&mut self, gives: &str, asset: AssetId, atoms: u64, sats: u64, lapse_seconds: u64, bitcoin: &Value)
		-> Result<Value, Error>
	{
		let role = match gives {
			"btc" => "Q",
			"asset" => "P",
			other => return Err(Error::Parse(format!("a swap's maker gives btc or the asset, not {:?}", other))),
		};
		if sats == 0 || atoms == 0 {
			return Err(Error::Refused("a swap moves something both ways".into()));
		}
		let info = self.server_info()?;
		let op_fee = self.swap_leg(&info, asset, atoms)?;
		let ark = &bitcoin["ark_info"];
		let ark_key = ark["server_pubkey"].as_str().ok_or_else(|| Error::Refused("the Bitcoin side gave no ark-info".into()))?;
		let mut lapse = wall_now() + lapse_seconds.max(60);
		let mut offer = json!({
			"kind": OFFER_KIND, "v": 1, "genesis_hash": self.genesis.genesis_hash().to_string(), "operator": self.operator.to_string(),
			"server": self.server.base(), "asset": asset.to_string(), "atoms": atoms.to_string(), "sats": sats.to_string(),
			"maker_gives": gives, "bitcoin": {"network": ark["network"], "ark_pubkey": ark_key}, "nonce": hex(&random32()),
		});
		let mut rec = json!({"role": role, "maker": true, "state": "offered", "asset": asset.to_string(), "atoms": atoms.to_string(),
			"sats": sats.to_string(), "created_at": wall_now()});
		if role == "P" {
			let invoice = bitcoin["invoice"].as_str().ok_or_else(|| Error::Refused("P's offer carries its Bark invoice for the BTC, and \
				the Bitcoin side gave none".into()))?;
			let (inv, expiry) = Self::swap_invoice(invoice, sats, ark, LOCK_LEFT)?;
			lapse = lapse.min(expiry.saturating_sub(LOCK_LEFT));
			offer["invoice"] = json!(invoice);
			rec["hash"] = json!(hex(&inv.payment_hash));
			rec["invoice_btc"] = json!(invoice);
			rec["invoice_btc_expiry"] = json!(expiry);
		}
		offer["lapse"] = json!(lapse);
		let id = hex(&sha256::Hash::hash(offer.to_string().as_bytes()).to_byte_array());
		rec["id"] = json!(id);
		rec["offer"] = offer.clone();
		rec["lapse"] = json!(lapse);
		rec["shows"] = shows(role, &asset.to_string(), atoms, sats, op_fee, &bitcoin["fee"]);
		self.set_btc_swap(&id, rec.clone())?;
		Ok(json!({"swap": id, "role": role, "offer": encode(OFFER_KIND, &offer), "shows": rec["shows"], "lapse": lapse}))
	}

	/// Reads an offer as a taker would, before anything is asked or made:
	/// the taker's role, what it gives and gets with every fee (`bitcoin`'s
	/// `fee`, Bark's quote for the taker's side), and why it cannot take it.
	pub fn btc_swap_read(&mut self, offer_text: &str, bitcoin: &Value) -> Result<Value, Error> {
		let offer = decode(OFFER_KIND, offer_text, "the offer")?;
		let t = Terms::of(&offer)?;
		self.check_swap_offer(&offer, &bitcoin["ark_info"])?;
		let role = if t.maker_gives == "btc" { "P" } else { "Q" };
		let info = self.server_info()?;
		let op_fee = self.swap_leg(&info, t.asset, t.atoms)?;
		Ok(json!({"role": role, "asset": t.asset.to_string(), "atoms": t.atoms.to_string(), "sats": t.sats.to_string(),
			"lapse": offer["lapse"], "shows": shows(role, &t.asset.to_string(), t.atoms, t.sats, op_fee, &bitcoin["fee"])}))
	}

	/// What a taker checks of an offer: its chain, its operator (this
	/// wallet's: the Sequentia leg is settled inside the operator), its
	/// Bitcoin ark (the one `ark_info` is of), and its lapse.
	fn check_swap_offer(&self, offer: &Value, ark_info: &Value) -> Result<(), Error> {
		if offer["genesis_hash"].as_str() != Some(&self.genesis.genesis_hash().to_string()) {
			return Err(Error::Refused("the offer is for another chain".into()));
		}
		if offer["operator"].as_str() != Some(&self.operator.to_string()) {
			return Err(Error::Refused(format!("the offer is for operator {}, and this wallet's operator is {}: a swap runs between two \
				wallets of one operator", offer["operator"].as_str().unwrap_or("?"), self.operator)));
		}
		if ark_info["server_pubkey"].as_str().is_none() || offer["bitcoin"]["ark_pubkey"] != ark_info["server_pubkey"] {
			return Err(Error::Refused(format!("the offer's Bitcoin ark is the one of server key {}, and this wallet's Bitcoin ark wallet \
				is in the one of key {}: a swap runs in one Bitcoin ark", offer["bitcoin"]["ark_pubkey"], ark_info["server_pubkey"])));
		}
		if offer["lapse"].as_u64().unwrap_or(0) <= wall_now() {
			return Err(Error::Refused("the offer has lapsed".into()));
		}
		Ok(())
	}

	/// Takes an offer. As Q (the maker gives the asset): asks the operator to
	/// receive the atoms under the hash of P's invoice in the offer. As P (the
	/// maker gives BTC): `bitcoin`'s `invoice` is the wallet's own Bark
	/// invoice for the satoshis, made now. Nothing is locked. Returns the
	/// take's text for the maker, and what the wallet gives and gets.
	pub fn btc_swap_take(&mut self, offer_text: &str, bitcoin: &Value) -> Result<Value, Error> {
		let offer = decode(OFFER_KIND, offer_text, "the offer")?;
		let t = Terms::of(&offer)?;
		self.check_swap_offer(&offer, &bitcoin["ark_info"])?;
		let id = hex(&sha256::Hash::hash(offer.to_string().as_bytes()).to_byte_array());
		if self.btc_swaps_map()?.contains_key(&id) {
			return Err(Error::Refused(format!("the wallet has swap {} already", id)));
		}
		let info = self.server_info()?;
		let op_fee = self.swap_leg(&info, t.asset, t.atoms)?;
		let role = if t.maker_gives == "btc" { "P" } else { "Q" };
		let mut rec = json!({"id": id, "role": role, "maker": false, "state": "taken", "asset": t.asset.to_string(),
			"atoms": t.atoms.to_string(), "sats": t.sats.to_string(), "offer": offer, "lapse": offer["lapse"], "created_at": wall_now(),
			"shows": shows(role, &t.asset.to_string(), t.atoms, t.sats, op_fee, &bitcoin["fee"])});
		let mut take = json!({"kind": TAKE_KIND, "v": 1, "swap": id});
		match role {
			"Q" => {
				let invoice = offer["invoice"].as_str().ok_or_else(|| Error::Refused("the offer carries no Bitcoin invoice".into()))?;
				let (inv, expiry) = Self::swap_invoice(invoice, t.sats, &bitcoin["ark_info"], LOCK_LEFT)?;
				let hash = hex(&inv.payment_hash);
				rec["hash"] = json!(hash);
				rec["invoice_btc"] = json!(invoice);
				rec["invoice_btc_expiry"] = json!(expiry);
				let r = self.lightning_receive_under(t.asset, t.atoms, Some("btc swap"), None, Some(inv.payment_hash))?;
				rec["invoice_x"] = r["invoice"].clone();
			},
			_ => {
				let invoice = bitcoin["invoice"].as_str().ok_or_else(|| Error::Refused("as P the wallet hands the maker its Bark invoice \
					for the BTC, and the Bitcoin side gave none".into()))?;
				let (inv, expiry) = Self::swap_invoice(invoice, t.sats, &bitcoin["ark_info"], LOCK_LEFT)?;
				rec["hash"] = json!(hex(&inv.payment_hash));
				rec["invoice_btc"] = json!(invoice);
				rec["invoice_btc_expiry"] = json!(expiry);
				take["invoice"] = json!(invoice);
			},
		}
		self.set_btc_swap(&id, rec.clone())?;
		Ok(json!({"swap": id, "role": role, "take": encode(TAKE_KIND, &take), "shows": rec["shows"], "hash": rec["hash"]}))
	}

	/// Completes the wallet's offer with a take. As Q (the maker gave BTC):
	/// asks the operator to receive the atoms under the hash of P's invoice in
	/// the take. As P: the swap goes on to its lock.
	pub fn btc_swap_complete(&mut self, take_text: &str, bitcoin: &Value) -> Result<Value, Error> {
		let take = decode(TAKE_KIND, take_text, "the take")?;
		let id = take["swap"].as_str().unwrap_or("").to_string();
		let mut rec = self.btc_swap(&id)?;
		if rec["maker"] != true || rec["state"] != "offered" {
			return Err(Error::Refused(format!("swap {} is {}: a take completes an offer of the wallet's still open", id, rec["state"])));
		}
		if rec["lapse"].as_u64().unwrap_or(0) <= wall_now() {
			return Err(Error::Refused("the offer has lapsed".into()));
		}
		let t = Terms::of(&rec["offer"])?;
		if rec["role"] == "Q" {
			let invoice = take["invoice"].as_str().ok_or_else(|| Error::Refused("the take carries no Bitcoin invoice".into()))?;
			let (inv, expiry) = Self::swap_invoice(invoice, t.sats, &bitcoin["ark_info"], LOCK_LEFT)?;
			rec["hash"] = json!(hex(&inv.payment_hash));
			rec["invoice_btc"] = json!(invoice);
			rec["invoice_btc_expiry"] = json!(expiry);
			let r = self.lightning_receive_under(t.asset, t.atoms, Some("btc swap"), None, Some(inv.payment_hash))?;
			rec["invoice_x"] = r["invoice"].clone();
		}
		rec["state"] = json!("taken");
		self.set_btc_swap(&id, rec.clone())?;
		Ok(json!({"swap": id, "role": rec["role"], "state": "taken", "hash": rec["hash"]}))
	}

	/// Every swap the wallet takes part in, with where it stands; and the
	/// legs a restore found of swaps whose record was lost (a received leaf
	/// under a hash the wallet did not make), with their hash and state.
	pub fn btc_swaps(&self) -> Result<Value, Error> {
		let swaps = self.btc_swaps_map()?;
		let hashes: Vec<String> = swaps.values().filter_map(|s| s["hash"].as_str().map(String::from)).collect();
		let restored: Vec<Value> = self.receives()?.into_iter()
			.filter(|(h, r)| r["hash_given"] == true && !hashes.contains(h))
			.map(|(h, r)| json!({"hash": h, "leg": "the asset leg: a leaf received under the swap's hash", "asset": r["asset"],
				"state": r["state"], "preimage_held": !r["preimage"].is_null(),
				"note": "a swap whose record this wallet does not hold (restored from the mnemonic): its BTC leg is Bark's"}))
			.chain(self.sends()?.into_iter().filter(|(h, s)| s["restored"] == true && !hashes.contains(h))
				.map(|(h, s)| json!({"hash": h, "leg": "a payment out of the tree, restored: when it was a swap's asset leg, the asset comes \
					back once the operator fails the receive back, or is the operator's once the preimage is out", "asset": s["asset"],
					"state": s["state"]})))
			.collect();
		Ok(json!({"swaps": swaps, "restored_legs": restored}))
	}

	/// Cancels a swap before the wallet has locked anything: an offer not
	/// taken, or a take whose lock has not been made. Says what the Bitcoin
	/// side must cancel (P's invoice).
	pub fn btc_swap_cancel(&mut self, id: &str) -> Result<Value, Error> {
		let mut rec = self.btc_swap(id)?;
		if !matches!(rec["state"].as_str(), Some("offered") | Some("taken")) {
			return Err(Error::Refused(format!("swap {} is {}: only one not locked yet can be cancelled", id, rec["state"])));
		}
		rec["state"] = json!("cancelled");
		rec["outcome"] = json!("cancelled before anything was locked");
		self.set_btc_swap(id, rec.clone())?;
		let cancel = (rec["role"] == "P").then(|| rec["invoice_btc"].clone()).filter(|v| !v.is_null());
		Ok(json!({"swap": id, "state": "cancelled", "bitcoin": cancel.map(|i| json!({"action": "cancel_receive", "invoice": i}))}))
	}

	/// Whether Q may pay `I_B` now (W8): `R` held validated, its round final,
	/// its terms the swap's, its home date at least [`REACTION`] past the
	/// Bitcoin leg's latest moment, and `I_B` unexpired with [`PAY_LEFT`] to
	/// run. `Ok(None)` when it may; `Ok(Some(why))` while it may not yet;
	/// `Err` when it never will (the swap is then abandoned, unpaid).
	pub fn btc_swap_ready(&self, rec: &Value, ark_info: &Value) -> Result<Option<String>, Error> {
		let hash = rec["hash"].as_str().unwrap_or("");
		let atoms = amount(&rec["atoms"], "the swap's atoms")?;
		let sats = amount(&rec["sats"], "the swap's satoshis")?;
		let invoice = rec["invoice_btc"].as_str().unwrap_or("");
		let (inv, expiry) = Self::swap_invoice(invoice, sats, ark_info, PAY_LEFT)?;
		if hex(&inv.payment_hash) != hash {
			return Err(Error::Refused("the swap's invoice is under another hash than its receive".into()));
		}
		let (asset, value, home_in) = match self.received_held(hash)? {
			Ok(h) => h,
			Err(why) => return Ok(Some(why)),
		};
		if asset.to_string() != rec["asset"].as_str().unwrap_or("") || value > atoms {
			return Err(Error::Refused(format!("the received leaf is not the swap's: {} of {} under {}, the swap's {} of {}",
				value, asset, hash, atoms, rec["asset"])));
		}
		let wall = wall_now();
		let latest = bitcoin_latest(ark_info, expiry, wall)?;
		let need = latest.saturating_sub(wall) + REACTION;
		if home_in < need {
			return Err(Error::Refused(format!("the received leaf must start home in {} s, and the Bitcoin leg can end up to {} s from \
				now: Q pays only with an hour to spare after it; the swap is not paid", home_in, need - REACTION)));
		}
		Ok(None)
	}

	/// Moves each swap on (or the one `id` names) as far as the Sequentia side
	/// goes, and says what the Bitcoin side must run next. `bitcoin` holds
	/// Bark's `ark_info`. Each step names the swap, its role and state, and,
	/// when Bark must act, `bitcoin: {action, invoice}`: `claim` (P: claim a
	/// payment to `I_B` while the payer pays; never as a fresh invoice), `pay`
	/// (Q: pay `I_B`), `pay_status` (Q: how its payment stands), or
	/// `cancel_receive` (P: the invoice is over). The program runs it and
	/// hands the outcome to [`Self::btc_swap_bitcoin`].
	pub fn btc_swap_follow(&mut self, id: Option<&str>, bitcoin: &Value) -> Result<Vec<Value>, Error> {
		let ids: Vec<String> = match id {
			Some(i) => vec![self.btc_swap(i)?["id"].as_str().unwrap_or(i).to_string()],
			None => self.btc_swaps_map()?.into_iter().filter(|(_, r)| !Self::swap_over(r)).map(|(k, _)| k).collect(),
		};
		if ids.is_empty() {
			return Ok(vec![]);
		}
		// The Sequentia side moves as `sync` moves it: the receive taken up and
		// claimed, the payment out of the tree decided.
		let sync = self.sync().map(|s| s["lightning"].clone()).unwrap_or_else(|e| json!({"error": e.to_string()}));
		let mut out = vec![];
		for id in ids {
			let mut rec = self.btc_swap(&id)?;
			let step = match rec["role"].as_str() {
				Some("P") => self.follow_p(&mut rec, bitcoin),
				_ => self.follow_q(&mut rec, bitcoin),
			};
			let action = match step {
				Ok(a) => a,
				Err(e) => {
					rec["note"] = json!(e.to_string());
					Value::Null
				},
			};
			self.set_btc_swap(&id, rec.clone())?;
			let mut s = json!({"swap": id, "role": rec["role"], "state": rec["state"], "note": rec["note"], "outcome": rec["outcome"]});
			if !action.is_null() {
				s["bitcoin"] = action;
			}
			out.push(s);
		}
		if let Some(first) = out.first_mut() {
			first["sync"] = sync;
		}
		Ok(out)
	}

	fn swap_over(r: &Value) -> bool {
		matches!(r["state"].as_str(), Some("done" | "refunded" | "lapsed" | "cancelled" | "abandoned" | "btc_failed"))
	}

	fn note(rec: &mut Value, what: &str) {
		rec["note"] = json!(what);
		let mut log = rec["log"].as_array().cloned().unwrap_or_default();
		if log.last().and_then(|l| l["what"].as_str()) != Some(what) {
			log.push(json!({"at": wall_now(), "state": rec["state"], "what": what}));
			rec["log"] = json!(log);
		}
	}

	fn end(rec: &mut Value, state: &str, outcome: &str) {
		rec["state"] = json!(state);
		rec["outcome"] = json!(outcome);
		Self::note(rec, outcome);
	}

	/// P: gives the asset, gets the BTC.
	fn follow_p(&mut self, rec: &mut Value, bitcoin: &Value) -> Result<Value, Error> {
		let hash = rec["hash"].as_str().unwrap_or("").to_string();
		let invoice_btc = rec["invoice_btc"].clone();
		let cancel = || json!({"action": "cancel_receive", "invoice": invoice_btc});
		let expiry = rec["invoice_btc_expiry"].as_u64().unwrap_or(0);
		let wall = wall_now();
		match rec["state"].as_str().unwrap_or("") {
			"offered" => {
				if rec["lapse"].as_u64().unwrap_or(0) <= wall {
					Self::end(rec, "lapsed", "the offer lapsed untaken; nothing was locked");
					return Ok(cancel());
				}
				Self::note(rec, "waiting for a taker");
				Ok(Value::Null)
			},
			"taken" => {
				if expiry < wall + LOCK_LEFT {
					Self::end(rec, "lapsed", "the Bitcoin invoice has too little time left to lock the asset; nothing was locked");
					return Ok(cancel());
				}
				let st = match self.lightning_lookup(&hash) {
					Ok(st) => st,
					Err(Error::Server { code, .. }) if code == "unknown_payment" => {
						if rec["lapse"].as_u64().unwrap_or(0) <= wall {
							Self::end(rec, "lapsed", "the taker never asked to receive under the hash; nothing was locked");
							return Ok(cancel());
						}
						Self::note(rec, "waiting for the receive under the hash at the operator");
						return Ok(Value::Null);
					},
					Err(e) => return Err(e),
				};
				if st["state"] != "open" {
					Self::end(rec, "lapsed", &format!("the receive under the hash is {} at the operator: it is not this swap's to pay; \
						nothing was locked", st["state"]));
					return Ok(cancel());
				}
				let t = match self.swap_lock(rec, &st, bitcoin) {
					Ok(t) => t,
					Err(e) => {
						if rec["lapse"].as_u64().unwrap_or(0) <= wall {
							Self::end(rec, "lapsed", &format!("the lock was never possible ({}); nothing was locked", e));
							return Ok(cancel());
						}
						Self::note(rec, &format!("not locking: {}", e));
						return Ok(Value::Null);
					},
				};
				let invoice_x = st["invoice"].as_str().unwrap_or("").to_string();
				let asset = AssetId::from_str(rec["asset"].as_str().unwrap_or("")).map_err(|e| Error::Store(e.to_string()))?;
				// Recorded before the payment is asked, so a restart finds it.
				rec["invoice_x"] = json!(invoice_x);
				rec["send_timeout"] = json!(t);
				rec["state"] = json!("locking");
				self.set_btc_swap(rec["id"].as_str().unwrap_or(""), rec.clone())?;
				match self.lightning_pay_until(&invoice_x, Some(asset), None, Some(t)) {
					Ok(p) => {
						rec["state"] = json!("locked");
						rec["lock"] = p["paying"].clone();
						Self::note(rec, &format!("the asset is locked in an htlc-1 leaf timing out at median time {}; claiming the BTC", t));
						Ok(json!({"action": "claim", "invoice": invoice_btc}))
					},
					Err(e) => {
						// Refused before anything was signed (the operator's node
						// down, the receive not open yet): tried again until the
						// swap lapses.
						rec["state"] = json!("taken");
						Self::note(rec, &format!("the lock was refused, nothing signed: {}; tried again until the swap lapses", e));
						Ok(Value::Null)
					},
				}
			},
			"locking" => {
				// A restart between recording the lock and the operator's answer:
				// the payment, if the wallet made it, is in its sends.
				match self.sends()?.get(&hash) {
					Some(_) => {
						rec["state"] = json!("locked");
						self.follow_p(rec, bitcoin)
					},
					None => {
						rec["state"] = json!("taken");
						self.follow_p(rec, bitcoin)
					},
				}
			},
			"locked" => {
				let send = self.sends()?.get(&hash).cloned().unwrap_or(Value::Null);
				match send["state"].as_str() {
					Some("paid") => {
						Self::end(rec, "done", "the asset leg is the operator's, paid by the preimage the BTC claim revealed");
						Ok(Value::Null)
					},
					Some("returned") | Some("failed") => {
						Self::end(rec, "refunded", &format!("the asset came back to the wallet: {}", send["reason"].as_str().unwrap_or("the \
							payment failed")));
						Ok(cancel())
					},
					_ if expiry <= wall => {
						rec["state"] = json!("btc_lost");
						Self::note(rec, "the Bitcoin invoice expired unclaimed: the asset comes back once the operator fails the receive back");
						Ok(cancel())
					},
					_ => {
						Self::note(rec, "the asset is locked; claiming the BTC while the payer pays");
						Ok(json!({"action": "claim", "invoice": invoice_btc}))
					},
				}
			},
			"claimed" => {
				if rec["posted"] != true {
					let pre = unhex32(rec["preimage"].as_str().unwrap_or(""))?;
					match self.lightning_post_preimage(&hash, &pre) {
						Ok(_) => rec["posted"] = json!(true),
						Err(e) => Self::note(rec, &format!("the preimage could not be posted to the operator yet: {}", e)),
					}
				}
				// The preimage is out once Bark revealed it; the claim goes on
				// until Bark's server has delivered the coins.
				let deliver = (rec["btc_settled"] != true).then(|| json!({"action": "claim", "invoice": invoice_btc}))
					.unwrap_or(Value::Null);
				let send = self.sends()?.get(&hash).cloned().unwrap_or(Value::Null);
				if send["state"] == "paid" && rec["btc_settled"] == true {
					Self::end(rec, "done", "the BTC is claimed, and the asset leg is the operator's");
				} else if send["state"] == "paid" {
					Self::note(rec, "the asset leg is the operator's; Bark is delivering the claimed BTC");
				} else {
					Self::note(rec, "the BTC is claimed; the asset leg is decided once the operator has the preimage");
				}
				Ok(deliver)
			},
			"btc_lost" => {
				let send = self.sends()?.get(&hash).cloned().unwrap_or(Value::Null);
				match send["state"].as_str() {
					Some("returned") => Self::end(rec, "refunded", "the BTC leg ended unclaimed, and the asset came back to the wallet"),
					Some("paid") => Self::end(rec, "done", "the asset leg was paid"),
					_ => Self::note(rec, "the BTC leg ended unclaimed; the asset comes back once the operator fails the receive back"),
				}
				Ok(Value::Null)
			},
			_ => Ok(Value::Null),
		}
	}

	/// P's lock, checked before anything is signed: the receive under the
	/// swap's hash is the operator's own (this wallet's operator), for the
	/// swap's atoms in its asset; the send leaf's timeout `t_S` (W7) lies in
	/// the operator's window for a payment's timeout.
	fn swap_lock(&self, rec: &Value, st: &Value, bitcoin: &Value) -> Result<u32, Error> {
		let hash = rec["hash"].as_str().unwrap_or("");
		let atoms = amount(&rec["atoms"], "the swap's atoms")?;
		let invoice_x = st["invoice"].as_str().unwrap_or("");
		let inv = parse_invoice(invoice_x)?;
		if hex(&inv.payment_hash) != hash || inv.asset.map(|a| a.to_string()).as_deref() != rec["asset"].as_str()
			|| inv.amount_msat != Some(atoms * 1000)
		{
			return Err(Error::Refused(format!("the operator's invoice under the swap's hash is not for {} of {}: {:?} of {:?}", atoms,
				rec["asset"], inv.amount_msat, inv.asset)));
		}
		let info = self.server_info()?;
		let recv = &info["lightning"]["receive"];
		let gap = recv["internal_gap_seconds"].as_u64().ok_or_else(|| Error::Refused("the operator publishes no internal gap: it \
			settles no payment between two of its wallets".into()))?;
		let window = recv["window_seconds"].as_u64().unwrap_or(6 * 3600);
		let exit_q = st["exit_delay_units"].as_u64().ok_or_else(|| Error::Refused("the operator's status names no exit delay for the \
			receiver's leaf".into()))? * 512;
		let expiry = rec["invoice_btc_expiry"].as_u64().unwrap_or(0);
		let (median, wall) = (self.now()?.to_consensus_u32() as u64, wall_now());
		let latest = bitcoin_latest(&bitcoin["ark_info"], expiry, wall)?;
		let need = send_timeout(median, wall, latest, exit_q, window, gap);
		let least = info["lightning"]["send"]["timeout_seconds"].as_u64().unwrap_or(0);
		let (lo, hi) = (median + least, median + 2 * least);
		let t = need.max(lo + 600);
		if t > hi.saturating_sub(60) {
			return Err(Error::Refused(format!("the swap needs the asset locked until median time {} ({} s out: the Bitcoin leg can end \
				{} s from now, the receiver's leaf exits in {} s, and the operator's gap is {} s), and the operator takes a payment's \
				timeout at most {} s out; nothing is signed", need, need - median, latest - wall, exit_q, gap, 2 * least)));
		}
		u32::try_from(t).map_err(|_| Error::Refused("a timeout past 2106".into()))
	}

	/// Q: gives the BTC, gets the asset.
	fn follow_q(&mut self, rec: &mut Value, bitcoin: &Value) -> Result<Value, Error> {
		let hash = rec["hash"].as_str().unwrap_or("").to_string();
		let invoice_btc = rec["invoice_btc"].clone();
		let wall = wall_now();
		let r = self.receives()?.get(&hash).cloned().unwrap_or(Value::Null);
		match rec["state"].as_str().unwrap_or("") {
			"offered" => {
				if rec["lapse"].as_u64().unwrap_or(0) <= wall {
					Self::end(rec, "lapsed", "the offer lapsed untaken; nothing was locked");
				} else {
					Self::note(rec, "waiting for a taker");
				}
				Ok(Value::Null)
			},
			"taken" => {
				match r["state"].as_str() {
					Some("failed") => {
						Self::end(rec, "abandoned", &format!("the receive failed back before the BTC was paid: {}; nothing was paid",
							r["reason"].as_str().unwrap_or("")));
						return Ok(Value::Null);
					},
					Some("received") | Some("claiming") => {
						Self::end(rec, "done", "the asset leaf is claimed");
						return Ok(Value::Null);
					},
					_ => {},
				}
				match self.btc_swap_ready(rec, &bitcoin["ark_info"]) {
					Ok(None) => {
						let tries = rec["pay_tries"].as_u64().unwrap_or(0);
						if tries >= PAY_TRIES {
							Self::end(rec, "btc_failed", "the BTC payment did not go through; the asset leg fails back to its payer");
							return Ok(Value::Null);
						}
						rec["pay_tries"] = json!(tries + 1);
						rec["state"] = json!("paying");
						Self::note(rec, "the asset leaf is held and final: paying the BTC");
						Ok(json!({"action": "pay", "invoice": invoice_btc}))
					},
					Ok(Some(why)) => {
						if r["state"] == "waiting" && rec["invoice_btc_expiry"].as_u64().unwrap_or(0) < wall + PAY_LEFT {
							Self::end(rec, "lapsed", "the Bitcoin invoice expired before the asset was locked; nothing was paid");
						} else {
							Self::note(rec, &format!("not paying yet: {}", why));
						}
						Ok(Value::Null)
					},
					Err(e) => {
						Self::end(rec, "abandoned", &format!("not paying, ever: {}; the asset leg fails back to its payer", e));
						Ok(Value::Null)
					},
				}
			},
			"paying" => {
				// The preimage served by the operator (P posted it) does as well
				// as Bark's.
				if !r["preimage"].is_null() || matches!(r["state"].as_str(), Some("received") | Some("claiming")) {
					rec["state"] = json!("claiming");
					return self.follow_q(rec, bitcoin);
				}
				Self::note(rec, "the BTC payment is with Bark");
				Ok(json!({"action": "pay_status", "invoice": invoice_btc}))
			},
			"claiming" => {
				match r["state"].as_str() {
					Some("received") => Self::end(rec, "done", "the asset leaf is claimed"),
					Some("failed") => Self::end(rec, "done", &format!("the BTC was paid and the asset leaf was lost: {}",
						r["reason"].as_str().unwrap_or(""))),
					_ => Self::note(rec, "claiming the asset leaf with the preimage"),
				}
				Ok(Value::Null)
			},
			_ => Ok(Value::Null),
		}
	}

	/// What Bark did for swap `id`, as the program that ran it says: `{action,
	/// state, preimage?, why?}`. P's claim `claimed` with the preimage
	/// (checked against the hash) is kept, and posted to the operator; `lost`
	/// ends the Bitcoin leg. Q's payment `paid` with the preimage hands it to
	/// the receive, which `sync` claims; one that did not go through is
	/// tried again while the swap may still pay, at most [`PAY_TRIES`] times.
	pub fn btc_swap_bitcoin(&mut self, id: &str, result: &Value) -> Result<Value, Error> {
		let mut rec = self.btc_swap(id)?;
		let hash = rec["hash"].as_str().unwrap_or("").to_string();
		let preimage = result["preimage"].as_str().map(unhex32).transpose()?
			.filter(|p| sha256::Hash::hash(p).to_string() == hash);
		match (rec["role"].as_str(), result["action"].as_str(), result["state"].as_str()) {
			(Some("P"), Some("claim"), Some("claimed")) => {
				let p = preimage.ok_or_else(|| Error::Refused("Bark claimed, and named no preimage of the swap's hash".into()))?;
				rec["preimage"] = json!(hex(&p));
				rec["btc_settled"] = json!(result["settled"] == true);
				rec["state"] = json!("claimed");
				Self::note(&mut rec, "the BTC is claimed");
				self.set_btc_swap(id, rec.clone())?;
				// Posted at once (W4): the asset leg is then the operator's, and
				// Q has the preimage from the operator too.
				let mut rec2 = rec.clone();
				let _ = self.follow_p(&mut rec2, &json!({}));
				self.set_btc_swap(id, rec2)?;
			},
			(Some("P"), Some("claim"), Some("lost")) if rec["state"] == "locked" => {
				rec["state"] = json!("btc_lost");
				Self::note(&mut rec, &format!("the payment to the Bitcoin invoice can no longer be claimed ({}); the asset comes back once \
					the operator fails the receive back", result["why"].as_str().unwrap_or("")));
				self.set_btc_swap(id, rec)?;
			},
			(Some("P"), Some("claim"), Some("waiting")) => {
				let why = result["why"].as_str().map(|w| format!(" (Bark: {})", w)).unwrap_or_default();
				Self::note(&mut rec, &format!("claiming the BTC: no payment claimed yet{}", why));
				self.set_btc_swap(id, rec)?;
			},
			(Some("Q"), Some("pay" | "pay_status"), Some("paid")) => {
				let p = preimage.ok_or_else(|| Error::Refused("Bark paid, and named no preimage of the swap's hash".into()))?;
				rec["preimage"] = json!(hex(&p));
				self.lightning_receive_preimage(&hash, &p)?;
				rec["state"] = json!("claiming");
				Self::note(&mut rec, "the BTC is paid; claiming the asset leaf with the preimage");
				self.set_btc_swap(id, rec)?;
				let _ = self.progress_receives();
				let mut rec = self.btc_swap(id)?;
				let _ = self.follow_q(&mut rec, &json!({}));
				self.set_btc_swap(id, rec)?;
			},
			(Some("Q"), Some("pay" | "pay_status"), Some("pending")) => {
				Self::note(&mut rec, "the BTC payment is in flight");
				self.set_btc_swap(id, rec)?;
			},
			(Some("Q"), Some("pay" | "pay_status"), _) => {
				// Not paid: tried again while the swap may still pay. A retry of
				// a payment Bark failed back fails at once and refunds in full.
				rec["state"] = json!("taken");
				let why = result["why"].as_str().map(String::from).unwrap_or_else(|| format!("Bark's status of the payment is {}, which \
					it reads once it has failed a payment back", result["bark"]["state"].as_str().unwrap_or("unknown")));
				Self::note(&mut rec, &format!("the BTC payment did not go through: {}", why));
				self.set_btc_swap(id, rec)?;
			},
			_ => {
				Self::note(&mut rec, &format!("Bark: {}", result));
				self.set_btc_swap(id, rec)?;
			},
		}
		let rec = self.btc_swap(id)?;
		Ok(json!({"swap": id, "role": rec["role"], "state": rec["state"], "note": rec["note"], "outcome": rec["outcome"]}))
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn the_bitcoin_legs_latest_moment_is_the_later_of_the_invoice_and_the_chain_claim() {
		let ark = json!({"htlc_send_expiry_delta": 258});
		// 264 blocks at half Bitcoin's pace: 88 hours, and ten minutes.
		assert_eq!(bitcoin_latest(&ark, 1_000, 1_000).unwrap(), 1_000 + 264 * 1200 + 600);
		// An invoice expiring later than that rules.
		assert_eq!(bitcoin_latest(&ark, 1_000_000, 1_000).unwrap(), 1_000_600);
		assert!(bitcoin_latest(&json!({}), 1, 1).is_err());
	}

	#[test]
	fn the_send_timeout_leaves_the_receiver_its_home_date_after_the_bitcoin_leg() {
		// The testnet's figures: the Bitcoin leg ends 88 h 10 min out, a
		// 36-hour exit delay, a six-hour window, a gap of 36 units, six hours
		// of stall margin and an hour.
		let (m, w) = (1_000_000, 2_000_000);
		let latest = w + 264 * 1200 + 600;
		let gap = 36 * 512 + 6 * 3600 + 3600;
		let t = send_timeout(m, w, latest, 36 * 3600, 6 * 3600, gap);
		let after = (8 * (264 * 1200 + 600 + 3600 + 3600 + 36 * 3600u64)).div_ceil(7);
		assert_eq!(t, m + after + gap + 3600);
		// About six and a half days out.
		assert_eq!((t - m) / 3600, 157);
		// Its receive leaf, timing out the gap before, has a home date an
		// hour past the Bitcoin leg at least, with an eighth kept in hand.
		let t_r = t - gap;
		let home = t_r - UNROLL - 36 * 3600 - (t_r - m) / 8;
		assert!(home - m >= latest - w + REACTION, "{} vs {}", home - m, latest - w + REACTION);
		// A short Bitcoin leg: the receive's least lock rules.
		let t = send_timeout(m, w, w, 2048, 600, 0);
		assert_eq!(t, m + ((8 * (3600 + 3600 + 2048u64)).div_ceil(7)).max((8 * 2648u64).div_ceil(7)) + 3600);
	}

	#[test]
	fn offer_and_take_texts_say_what_they_are() {
		let v = json!({"kind": OFFER_KIND, "a": 1});
		let s = encode(OFFER_KIND, &v);
		assert!(s.starts_with("btc-swap-offer:"));
		assert_eq!(decode(OFFER_KIND, &s, "the offer").unwrap(), v);
		assert!(decode(TAKE_KIND, &s, "the take").is_err());
		assert!(decode(OFFER_KIND, "btc-swap-offer:zz", "the offer").is_err());
		assert!(decode(OFFER_KIND, "nothing", "the offer").is_err());
	}

	#[test]
	fn each_party_sees_what_it_gives_and_gets_with_every_fee() {
		let p = shows("P", "x", 100_000, 50_000, 100, &json!({"fee_sat": 200}));
		assert_eq!((p["gives"]["atoms"].as_str(), p["gets"]["sat"].as_str()), (Some("100100"), Some("49800")));
		let q = shows("Q", "x", 100_000, 50_000, 100, &json!({"fee_sat": 126}));
		assert_eq!((q["gives"]["sat"].as_str(), q["gets"]["atoms"].as_str()), (Some("50126"), Some("99900")));
	}
}
