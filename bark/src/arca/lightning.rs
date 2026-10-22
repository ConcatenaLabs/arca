//! Paying over Lightning out of the tree, and the BOLT11 invoices it reads.
//!
//! A wallet pays an invoice in asset A out of its coins in A: they go,
//! through checkpoints and a reassignment, into an `htlc-1` leaf of its own
//! key locked to the invoice's payment hash (the operator claims it with the
//! preimage; the wallet refunds it after the timeout) and the change, and the
//! operator pays the invoice through its node in A. Before anything is signed
//! the wallet reads the invoice itself: a Bitcoin invoice is paid in native
//! BTC, never from a Sequentia leaf; an invoice names the asset it is paid in
//! (SeqLN's `a` field), and coins of another asset never pay it; it is for an
//! amount, unexpired, and in an asset the operator serves over Lightning,
//! whose node is up; the operator's fee for it is within the wallet's bound.
//!
//! The payment is then followed until the operator says how it went:
//! `paid`, with a preimage the wallet checks against the hash (the proof of
//! payment, and the leaf the operator's); or `failed`, after which the wallet
//! takes the leaf back through its collaborative path, co-signed, into a new
//! leaf of its own. A payment the operator never decides is the wallet's to
//! take back on the chain by the leaf's refund path, after its timeout and
//! its exit delay (`exit`).

use std::collections::BTreeMap;
use std::str::FromStr;

use elements::AssetId;
use serde_json::{json, Value};

use arca_covenant::{HtlcDirection, HtlcTerms, LeafId, MedianTime, NewLeaf, RelativeTime, Sweep, ValidCoin, ValidOrigin};

use super::chain::hex;
use super::pay::{In, Out};
use super::wallet::{amount, Wallet};
use super::{random32, Error};

/// Where the wallet keeps its payments over Lightning: a map from the
/// payment hash (hex) to what it knows of the payment.
pub(crate) const SENDS: &str = "lightning_sends";

/// A BOLT11 invoice, as far as the wallet reads it. The signature is not
/// checked here: the operator's node checks it before anything is paid, and
/// the wallet reads the fields only to refuse early.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice {
	/// The currency of its human-readable part: `sqrt`, `tsqt` or `sqt` on
	/// Sequentia, `bc`, `tb`, `tbs` or `bcrt` on Bitcoin.
	pub currency: String,
	pub amount_msat: Option<u64>,
	pub timestamp: u64,
	pub payment_hash: [u8; 32],
	/// The asset it is paid in (SeqLN's tagged field `a`, 29); none on
	/// Bitcoin.
	pub asset: Option<AssetId>,
	pub expiry: u64,
	pub description: Option<String>,
}

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(values: &[u8]) -> u32 {
	const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
	let mut chk: u32 = 1;
	for v in values {
		let b = chk >> 25;
		chk = ((chk & 0x1ffffff) << 5) ^ (*v as u32);
		for (i, g) in GEN.iter().enumerate() {
			if (b >> i) & 1 == 1 {
				chk ^= g;
			}
		}
	}
	chk
}

/// `n` bits from `groups` of five, as bytes (the last one padded).
fn to_bytes(groups: &[u8]) -> Vec<u8> {
	let mut out = vec![];
	let (mut acc, mut bits) = (0u32, 0u32);
	for g in groups {
		acc = (acc << 5) | *g as u32;
		bits += 5;
		while bits >= 8 {
			bits -= 8;
			out.push((acc >> bits) as u8);
			acc &= (1 << bits) - 1;
		}
	}
	out
}

fn to_int(groups: &[u8]) -> u64 {
	groups.iter().fold(0u64, |a, g| (a << 5) | *g as u64)
}

/// The networks of each currency: Sequentia's by SeqLN's network name, and
/// Bitcoin's.
pub fn network_of(currency: &str) -> Option<(&'static str, bool)> {
	Some(match currency {
		"sqt" => ("sequentia", true),
		"tsqt" => ("sequentia-testnet", true),
		"sqrt" => ("sequentia-regtest", true),
		"bc" => ("bitcoin", false),
		"tb" => ("testnet", false),
		"tbs" => ("signet", false),
		"bcrt" => ("regtest", false),
		_ => return None,
	})
}

/// Reads a BOLT11 invoice.
pub fn parse_invoice(s: &str) -> Result<Invoice, Error> {
	let bad = |why: &str| Error::Parse(format!("the invoice: {}", why));
	let s = s.trim();
	let s = s.strip_prefix("lightning:").unwrap_or(s);
	if s.chars().any(|c| c.is_ascii_uppercase()) && s.chars().any(|c| c.is_ascii_lowercase()) {
		return Err(bad("mixed case"));
	}
	let s = s.to_lowercase();
	let sep = s.rfind('1').ok_or_else(|| bad("no separator"))?;
	let (hrp, data) = (&s[..sep], &s[sep + 1..]);
	let rest = hrp.strip_prefix("ln").ok_or_else(|| bad("not a Lightning invoice (ln…)"))?;
	let cur_end = rest.find(|c: char| c.is_ascii_digit()).unwrap_or(rest.len());
	let currency = rest[..cur_end].to_string();
	let amount = &rest[cur_end..];
	let amount_msat = if amount.is_empty() { None } else {
		let (digits, mult) = match amount.chars().last() {
			Some(c) if c.is_ascii_digit() => (amount, None),
			Some(c) => (&amount[..amount.len() - 1], Some(c)),
			None => (amount, None),
		};
		let n: u64 = digits.parse().map_err(|_| bad("an amount that is not a number"))?;
		// One unit is 10^11 msat; the multipliers divide it.
		let msat = match mult {
			None => n.checked_mul(100_000_000_000),
			Some('m') => n.checked_mul(100_000_000),
			Some('u') => n.checked_mul(100_000),
			Some('n') => n.checked_mul(100),
			Some('p') if n % 10 == 0 => Some(n / 10),
			_ => None,
		}.ok_or_else(|| bad("an amount it cannot read"))?;
		Some(msat)
	};
	let mut groups = vec![];
	for c in data.bytes() {
		groups.push(CHARSET.iter().position(|x| *x == c).ok_or_else(|| bad("a character outside bech32"))? as u8);
	}
	let mut check: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
	check.push(0);
	check.extend(hrp.bytes().map(|b| b & 31));
	check.extend(&groups);
	if groups.len() < 7 + 104 + 6 || polymod(&check) != 1 {
		return Err(bad("its checksum does not hold"));
	}
	let body = &groups[..groups.len() - 6 - 104];
	let timestamp = to_int(&body[..7]);
	let mut at = 7;
	let (mut payment_hash, mut asset, mut expiry, mut description) = (None, None, 3600, None);
	while at + 3 <= body.len() {
		let tag = body[at];
		let len = to_int(&body[at + 1..at + 3]) as usize;
		let field = body.get(at + 3..at + 3 + len).ok_or_else(|| bad("a tagged field runs past the end"))?;
		match (tag, len) {
			(1, 52) => payment_hash = Some(<[u8; 32]>::try_from(&to_bytes(field)[..32]).expect("32 bytes")),
			(29, 52) => {
				let b = &to_bytes(field)[..32];
				asset = Some(AssetId::from_str(&hex(b)).map_err(|e| bad(&format!("its asset: {}", e)))?);
			},
			(6, _) => expiry = to_int(field),
			(13, _) => description = String::from_utf8(to_bytes(field)).ok(),
			_ => {},
		}
		at += 3 + len;
	}
	Ok(Invoice {
		currency, amount_msat, timestamp, payment_hash: payment_hash.ok_or_else(|| bad("no payment hash"))?, asset, expiry, description,
	})
}

/// The fee the operator charges for a payment of `amount` in `asset`, from
/// its `info`: `lightning_ppm` of it, rounded up, and `lightning_base`.
pub(crate) fn fee_of(info: &Value, asset: AssetId, amount: u64) -> Result<u64, Error> {
	let a = info["assets"].as_array().into_iter().flatten().find(|a| a["asset"].as_str() == Some(&asset.to_string()))
		.ok_or_else(|| Error::Refused(format!("the operator does not serve asset {}", asset)))?;
	let fees = &a["fees"];
	if fees.is_null() {
		return Err(Error::Refused(format!("the operator publishes no fees in asset {} now", asset)));
	}
	let ppm = fees["lightning_ppm"].as_u64().unwrap_or(0);
	let base = if fees["lightning_base"].is_null() { 0 } else { amount_of(&fees["lightning_base"])? };
	Ok(((amount as u128 * ppm as u128).div_ceil(1_000_000) + base as u128).min(u64::MAX as u128) as u64)
}

fn amount_of(v: &Value) -> Result<u64, Error> {
	amount(v, "an amount")
}

impl Wallet {
	pub(crate) fn sends(&self) -> Result<BTreeMap<String, Value>, Error> {
		Ok(self.store.meta(SENDS)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default())
	}

	pub(crate) fn set_send(&self, hash: &str, v: Value) -> Result<(), Error> {
		let mut m = self.sends()?;
		m.insert(hash.to_string(), v);
		self.store.set_meta(SENDS, &serde_json::to_string(&m).expect("a map"))
	}

	/// Pays the BOLT11 `invoice` out of the wallet's coins of its asset: see
	/// the [module documentation](self). `from` names the asset the coins
	/// are to be of, which must be the invoice's. `max_fee_ppm` raises the
	/// wallet's bound on the operator's fee for this payment.
	pub fn lightning_pay(&mut self, invoice: &str, from: Option<AssetId>, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		self.lightning_pay_until(invoice, from, max_fee_ppm, None)
	}

	/// [`Self::lightning_pay`], the `htlc-1` leaf timing out at `timeout` (a
	/// median time) when named: within the operator's window for a payment's
	/// timeout, which the operator checks; a little past its least
	/// otherwise. A payment of the operator's own invoice, for a payment into
	/// its tree, is settled inside the operator, and its receiver's leaf
	/// times out the operator's gap before this one.
	pub fn lightning_pay_until(&mut self, invoice: &str, from: Option<AssetId>, max_fee_ppm: Option<u64>, timeout: Option<u32>)
		-> Result<Value, Error>
	{
		self.lightning_pay_shown(invoice, from, max_fee_ppm, timeout, None)
	}

	/// What paying the BOLT11 `invoice` would take, with nothing signed and
	/// nothing kept: the amount, the operator's fee, the margins of the
	/// coins it would spend, and what leaves the wallet in all (`spends`:
	/// the coins less the change), with the coins (`gives`) and the change. A program shows it, then pays with
	/// `shown` ([`Self::lightning_pay_shown`]).
	pub fn lightning_pay_quote(&mut self, invoice: &str, from: Option<AssetId>, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		let p = self.pay_checks(invoice, from, max_fee_ppm)?;
		// A probe of the leaf the payment would make, for the margins: its key
		// is derived and kept nowhere.
		let nonce = random32();
		let owner = self.keys.leaf_xonly(&nonce)?;
		let terms = HtlcTerms { direction: HtlcDirection::Send, payment_hash: p.inv.payment_hash, timeout: p.default_timeout()?,
			operator_delay: p.operator_delay };
		let exit_delay = self.exit_delay().max(p.owner_delay);
		let leaf = NewLeaf { owner, owner_nonce: nonce, creator_nonce: random32(), exit_delay, htlc: Some(terms), landing: None };
		let mailbox = self.keys.mailbox()?.x_only_public_key().0;
		let htlc = Out { asset: p.asset, value: p.value + p.fee, leaf, mailbox, until: None };
		let min = Self::min_leaf(&p.info, p.asset)?;
		let htlc_out = ExplicitOutputOf::explicit_of(&htlc, self);
		let (inputs, margin, change) = self.choose_coins(&p.info, p.asset, p.value + p.fee, &htlc_out, min)?;
		Ok(Self::pay_quote_of(&p, &inputs, margin, change))
	}

	/// The quote of a payment as [`Self::lightning_pay_quote`] answers it.
	fn pay_quote_of(p: &PayChecks, inputs: &[In], margin: u64, change: u64) -> Value {
		let total: u64 = inputs.iter().map(|i| i.coin.value).sum();
		let checkpoints: u64 = inputs.iter().map(|i| i.coin.value - i.checkpoint_value).sum();
		json!({"payment_hash": hex(&p.inv.payment_hash), "asset": p.asset.to_string(), "amount": p.value.to_string(),
			"fee": p.fee.to_string(), "margins": (checkpoints + margin).to_string(), "spends": total.saturating_sub(change).to_string(),
			"expires_at": p.inv.timestamp.saturating_add(p.inv.expiry), "description": p.inv.description,
			// The coins it would spend and the change it would leave: a program that settles that
			// change in the operator's next round prices it from these.
			"gives": inputs.iter().map(|i| i.row.leaf_id.clone()).collect::<Vec<_>>(), "change": change.to_string()})
	}

	/// [`Self::lightning_pay_until`], going ahead, with `shown`, only on the
	/// fee and on what leaves the wallet in all that a
	/// [`Self::lightning_pay_quote`] showed.
	pub fn lightning_pay_shown(&mut self, invoice: &str, from: Option<AssetId>, max_fee_ppm: Option<u64>, timeout: Option<u32>,
		shown: Option<&Value>) -> Result<Value, Error>
	{
		let p = self.pay_checks(invoice, from, max_fee_ppm)?;
		let PayChecks { asset, value, fee, ref hash, ref info, operator_delay, owner_delay, timeout_seconds, now, .. } = p;
		let inv = p.inv.clone();
		// The timeout a little past the operator's least, well within its
		// most, unless the caller names one.
		let at = timeout.unwrap_or_else(|| now.saturating_add(timeout_seconds).saturating_add(600));
		if at < now.saturating_add(timeout_seconds) || at > now.saturating_add(timeout_seconds.saturating_mul(2)) {
			return Err(Error::Refused(format!("a timeout of median time {} is outside the operator's window for a payment, {} to {}; \
				nothing is signed", at, now.saturating_add(timeout_seconds), now.saturating_add(timeout_seconds.saturating_mul(2)))));
		}
		let timeout = MedianTime::from_consensus(at).map_err(|e| Error::Refused(e.to_string()))?;
		let nonce = random32();
		let owner = self.keys.leaf_xonly(&nonce)?;
		let terms = HtlcTerms { direction: HtlcDirection::Send, payment_hash: inv.payment_hash, timeout, operator_delay };
		let exit_delay = self.exit_delay().max(owner_delay);
		let leaf = NewLeaf { owner, owner_nonce: nonce, creator_nonce: random32(), exit_delay, htlc: Some(terms), landing: None };
		terms.check(exit_delay).map_err(|e| Error::Refused(e.to_string()))?;
		let mailbox = self.keys.mailbox()?.x_only_public_key().0;
		let htlc = Out { asset, value: value + fee, leaf, mailbox, until: None };
		let min = Self::min_leaf(info, asset)?;
		let htlc_out = ExplicitOutputOf::explicit_of(&htlc, self);
		let (inputs, margin, change) = self.choose_coins(info, asset, value + fee, &htlc_out, min)?;
		if let Some(s) = shown {
			let quote = Self::pay_quote_of(&p, &inputs, margin, change);
			for k in ["payment_hash", "asset", "amount", "fee", "spends"] {
				if s[k] != quote[k] {
					return Err(Error::Refused(format!("the payment's {} changed since it was shown: it is now {}; nothing is signed", k,
						quote[k])));
				}
			}
		}
		self.store.put_nonce(&nonce, &owner.serialize(), "lightning")?;
		let hash = hash.clone();
		let mut outs = vec![htlc];
		if change > 0 {
			let leaf = self.own_leaf_for("change")?;
			outs.push(Out { asset, value: change, leaf, mailbox, until: None });
		}
		self.set_send(&hash, json!({"invoice": invoice, "asset": asset.to_string(), "amount": value.to_string(), "fee": fee.to_string(),
			"htlc_owner": hex(&owner.serialize()), "state": "requested"}))?;
		let answer = match self.transfer_paying(&inputs, &outs, invoice) {
			Ok(a) => a,
			Err(e @ Error::Server { .. }) => {
				// Refused: nothing of it stands, and the invoice may be paid
				// again some other way.
				let mut m = self.sends()?;
				m.remove(&hash);
				self.store.set_meta(SENDS, &serde_json::to_string(&m).expect("a map"))?;
				return Err(e);
			},
			Err(e) => return Err(e),
		};
		Ok(json!({
			"paying": {"payment_hash": hash, "asset": asset.to_string(), "amount": value.to_string(), "fee": fee.to_string(),
				"description": inv.description},
			"inputs": inputs.iter().map(|i| i.row.leaf_id.clone()).collect::<Vec<_>>(),
			"margins": {"checkpoints": inputs.iter().map(|i| (i.coin.value - i.checkpoint_value).to_string()).collect::<Vec<_>>(),
				"reassignment": margin.to_string()},
			"change": if change > 0 { json!(change.to_string()) } else { Value::Null },
			"transfer": answer,
		}))
	}

	/// What the wallet reads of an invoice before paying it, and the terms
	/// the operator publishes for a payment: refused as
	/// [`Self::lightning_pay`] says.
	fn pay_checks(&mut self, invoice: &str, from: Option<AssetId>, max_fee_ppm: Option<u64>) -> Result<PayChecks, Error> {
		let inv = parse_invoice(invoice)?;
		match network_of(&inv.currency) {
			Some((net, false)) => return Err(Error::Refused(format!("the invoice is a Bitcoin invoice ({}): it is paid in native BTC, on \
				Bitcoin, over the Bitcoin side, never from a Sequentia leaf; nothing is signed", net))),
			None => return Err(Error::Refused(format!("the invoice's currency {:?} is no network this wallet knows", inv.currency))),
			Some(_) => {},
		}
		let asset = inv.asset.ok_or_else(|| Error::Refused("the invoice names no asset: on Sequentia an invoice names the asset it is \
			paid in (its field a); nothing is signed".into()))?;
		if let Some(f) = from {
			if f != asset {
				return Err(Error::Refused(format!("the invoice is to be paid in asset {}, and the wallet was asked to pay it from coins \
					of asset {}: a coin in one asset never pays an invoice in another; nothing is signed", asset, f)));
			}
		}
		let msat = inv.amount_msat.ok_or_else(|| Error::Refused("the invoice names no amount; nothing is signed".into()))?;
		if msat % 1000 != 0 {
			return Err(Error::Refused(format!("the invoice asks {} msat, not a whole number of atoms; nothing is signed", msat)));
		}
		let value = msat / 1000;
		let wall = web_time::SystemTime::now().duration_since(web_time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
		if inv.timestamp.saturating_add(inv.expiry) <= wall + 60 {
			return Err(Error::Refused("the invoice has expired, or expires within a minute; nothing is signed".into()));
		}
		let hash = hex(&inv.payment_hash);
		if let Some(p) = self.sends()?.get(&hash) {
			return Err(Error::Refused(format!("the wallet is paying this invoice already, or paid it: {}", p)));
		}
		let info = self.server_info()?;
		let leg = info["assets"].as_array().into_iter().flatten().find(|a| a["asset"].as_str() == Some(&asset.to_string()))
			.map(|a| a["lightning"].clone())
			.ok_or_else(|| Error::Refused(format!("the operator does not serve asset {}; nothing is signed", asset)))?;
		if leg.is_null() {
			return Err(Error::Refused(format!("the operator runs no Lightning node in asset {}; nothing is signed", asset)));
		}
		if leg["state"] != "up" {
			return Err(Error::Refused(format!("the operator's Lightning node in asset {} is down: {}; nothing is signed", asset,
				leg["reason"].as_str().unwrap_or("no reason given"))));
		}
		if let (Some(net), Some((inv_net, _))) = (leg["network"].as_str(), network_of(&inv.currency)) {
			if net != inv_net {
				return Err(Error::Refused(format!("the invoice is for {}, and the operator's node runs on {}; nothing is signed", inv_net, net)));
			}
		}
		let fee = fee_of(&info, asset, value)?;
		let bound = max_fee_ppm.unwrap_or(super::DEFAULT_MAX_FEE_PPM);
		if !super::round::fee_within(fee, value, bound) {
			return Err(Error::Refused(format!("the operator charges {} of asset {} to pay {}, above the wallet's bound of {} ppm; nothing \
				is signed (--max-fee-ppm raises it for this payment)", fee, asset, value, bound)));
		}
		let send = &info["lightning"]["send"];
		let units = |k: &str| send[k].as_u64().and_then(|u| u16::try_from(u).ok()).and_then(|u| RelativeTime::from_units(u).ok())
			.ok_or_else(|| Error::Refused(format!("the operator publishes no {} for a payment over Lightning", k)));
		let operator_delay = units("operator_delay_units")?;
		let owner_delay = units("owner_delay_units")?;
		let timeout_seconds = send["timeout_seconds"].as_u64().ok_or_else(|| Error::Refused("the operator publishes no timeout for a \
			payment over Lightning".into()))? as u32;
		let now = self.now()?.to_consensus_u32();
		Ok(PayChecks { inv, asset, value, fee, hash, info, operator_delay, owner_delay, timeout_seconds, now })
	}

	/// What the server answered of a payment (`lightning_send`, or its status
	/// later): the `htlc-1` coin is kept out of what the wallet pays from
	/// while the payment is undecided, and gone once paid.
	pub(crate) fn payment_answered(&mut self, p: &Value) -> Result<(), Error> {
		let hash = p["payment_hash"].as_str().unwrap_or("").to_string();
		let mut rec = self.sends()?.get(&hash).cloned().unwrap_or_else(|| json!({}));
		let leaf = p["htlc_leaf_id"].as_str().unwrap_or("").to_string();
		rec["htlc_leaf_id"] = json!(leaf);
		let state = p["state"].as_str().unwrap_or("");
		match state {
			"paid" => {
				let pre = p["preimage"].as_str().unwrap_or("");
				let bytes = super::chain::unhex32(pre)?;
				if hex(&arca_covenant::script::sha256(&bytes)) != hash {
					return Err(Error::Refused(format!("the operator says payment {} is paid, with a preimage of another hash", hash)));
				}
				rec["state"] = json!("paid");
				rec["preimage"] = json!(pre);
				// The leaf is the operator's now: spent, by the payment.
				if self.store.coin(&leaf)?.is_some_and(|c| c.state != "spent") {
					self.store.set_coin_spent(&leaf, &format!("the payment over Lightning of hash {}, paid (preimage {})", hash, pre))?;
				}
			},
			"failed" => {
				rec["state"] = json!(rec["state"].as_str().filter(|s| *s == "returned").unwrap_or("failed"));
				rec["reason"] = p["reason"].clone();
			},
			_ => {
				rec["state"] = json!("paying");
				if let Some(c) = self.store.coin(&leaf)? {
					if c.state == "live" {
						self.store.set_coin_state(&leaf, "paying", &format!("the htlc-1 leaf of the payment of hash {}: the operator is paying \
							the invoice", hash))?;
					}
				}
			},
		}
		self.set_send(&hash, rec)
	}

	/// Follows every payment over Lightning the operator has not decided:
	/// a paid one is closed with its preimage; a failed one is taken back,
	/// its `htlc-1` leaf co-signed into a new leaf of the wallet's own.
	pub(crate) fn progress_lightning(&mut self) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		for (hash, rec) in self.sends()? {
			let state = rec["state"].as_str().unwrap_or("").to_string();
			if !matches!(state.as_str(), "paying" | "failed") {
				continue;
			}
			if state == "paying" {
				match self.server.post("lightning_send_status", &json!({"payment_hash": hash})) {
					Ok(p) => self.payment_answered(&p)?,
					Err(e) => {
						out.push(json!({"payment_hash": hash, "error": e.to_string()}));
						continue;
					},
				}
			}
			let rec = self.sends()?.get(&hash).cloned().unwrap_or_default();
			if rec["state"] == "failed" {
				out.push(match self.take_back(&hash) {
					Ok(v) => v,
					Err(e) => json!({"payment_hash": hash, "state": "failed", "error": e.to_string()}),
				});
			} else {
				out.push(json!({"payment_hash": hash, "state": rec["state"], "preimage": rec["preimage"]}));
			}
		}
		Ok(out)
	}

	/// Takes back the `htlc-1` leaf of the failed payment `hash`: through its
	/// collaborative path, co-signed, into a new leaf of the wallet's own.
	fn take_back(&mut self, hash: &str) -> Result<Value, Error> {
		let rec = self.sends()?.get(hash).cloned().unwrap_or_default();
		let leaf = rec["htlc_leaf_id"].as_str().unwrap_or("").to_string();
		let row = self.store.coin(&leaf)?.ok_or_else(|| Error::Refused(format!("the wallet holds no htlc-1 coin {}", leaf)))?;
		if row.state == "spent" {
			let mut r = rec.clone();
			r["state"] = json!("returned");
			self.set_send(hash, r)?;
			return Ok(json!({"payment_hash": hash, "state": "returned", "htlc_leaf_id": leaf}));
		}
		let info = self.server_info()?;
		let (_, a) = self.held(&row)?;
		let coin = a.valid;
		let asset = coin.asset;
		let m = super::pay::Margins::of(&info, asset)?;
		let cp = self.checkpoint_margin_of(&coin, &m)?;
		let own = self.own_leaf_for("returned")?;
		let mailbox = self.keys.mailbox()?.x_only_public_key().0;
		let probe = Out { asset, value: 1, leaf: own, mailbox, until: None };
		let re = self.reassignment_margin_of(&coin, &probe, &m)?;
		let value = coin.value.checked_sub(cp + re).filter(|v| *v > 0)
			.ok_or_else(|| Error::Refused(format!("the htlc-1 coin's {} atoms do not cover its margins", coin.value)))?;
		let back = Out { value, ..probe };
		let input = In { row, checkpoint_value: coin.value - cp, coin };
		let answer = self.transfer_back(&[input], &[back])?;
		let mut r = rec;
		r["state"] = json!("returned");
		r["returned_by"] = answer["transfer_id"].clone();
		self.set_send(hash, r)?;
		Ok(json!({"payment_hash": hash, "state": "returned", "htlc_leaf_id": leaf, "transfer": answer}))
	}

	/// Follows the payment `hash` for up to `wait`: until the operator says
	/// it is paid, or it failed and its leaf is taken back. What the wallet
	/// knows of it then.
	pub fn lightning_follow(&mut self, hash: &str, wait: std::time::Duration) -> Result<Value, Error> {
		let start = std::time::Instant::now();
		loop {
			let _ = self.progress_lightning()?;
			let rec = self.sends()?.get(hash).cloned().unwrap_or(Value::Null);
			let done = matches!(rec["state"].as_str(), Some("paid" | "returned"));
			if done || start.elapsed() >= wait {
				return Ok(rec);
			}
			std::thread::sleep(std::time::Duration::from_millis(500));
			super::chain::gap();
		}
	}

	/// Every payment over Lightning the wallet made, with what it knows.
	pub fn lightning_payments(&self) -> Result<Value, Error> {
		Ok(json!(self.sends()?))
	}
}

/// Where the wallet keeps its payments received over Lightning: a map from
/// the payment hash (hex) to what it knows of the payment.
pub(crate) const RECEIVES: &str = "lightning_receives";

/// The tag of a received payment's preimage, derived from its leaf's key.
const RECEIVE_PREIMAGE_TAG: &[u8] = b"Arca/lightning-receive-preimage";

/// The blocks a received leaf's claim keeps in hand at least before the
/// leaf's timeout, at the chain's interval, beyond its unroll and its exit
/// delay: time for the claim to be mined before the operator's refund can
/// be.
pub(crate) const CLAIM_MARGIN_BLOCKS: u64 = 3;

/// The share of a received leaf's lock, from its round's confirmation to its
/// timeout, that its claim keeps in hand when that is more than
/// [`CLAIM_MARGIN_BLOCKS`]: an eighth, so a client that wakes that much
/// late for the leaf's home date still claims it first.
pub(crate) const CLAIM_MARGIN_SHARE: u64 = 8;

/// The receive window the wallet assumes of an operator that publishes none.
const DEFAULT_WINDOW: u64 = 6 * 3600;

/// The `htlc-1` terms a published leaf carries (`htlc`), if any.
pub(crate) fn htlc_terms_of(v: &Value) -> Result<Option<HtlcTerms>, Error> {
	if v.is_null() {
		return Ok(None);
	}
	let bad = |why: String| Error::Parse(format!("a leaf's htlc-1 terms: {}", why));
	let direction = HtlcDirection::from_name(v["direction"].as_str().unwrap_or("")).ok_or_else(|| bad(format!("direction {}", v["direction"])))?;
	let payment_hash = super::chain::unhex32(v["payment_hash"].as_str().unwrap_or(""))?;
	let timeout = MedianTime::from_consensus(v["timeout"].as_u64().unwrap_or(0) as u32).map_err(|e| bad(e.to_string()))?;
	let operator_delay = v["operator_delay_units"].as_u64().and_then(|u| u16::try_from(u).ok())
		.ok_or_else(|| bad("no operator delay".into()))
		.and_then(|u| RelativeTime::from_units(u).map_err(|e| bad(e.to_string())))?;
	Ok(Some(HtlcTerms { direction, payment_hash, timeout, operator_delay }))
}

impl Wallet {
	pub(crate) fn receives(&self) -> Result<BTreeMap<String, Value>, Error> {
		Ok(self.store.meta(RECEIVES)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default())
	}

	pub(crate) fn set_receive(&self, hash: &str, v: Value) -> Result<(), Error> {
		let mut m = self.receives()?;
		m.insert(hash.to_string(), v);
		self.store.set_meta(RECEIVES, &serde_json::to_string(&m).expect("a map"))
	}

	/// The preimage of the payment received into the leaf of `nonce`, derived
	/// from that leaf's key, so the mnemonic and the nonce (which the leaf's
	/// record carries) give it back: `SHA256("Arca/lightning-receive-preimage"
	/// ‖ leaf secret key ‖ nonce)`.
	pub(crate) fn receive_preimage(&self, nonce: &[u8; 32]) -> Result<[u8; 32], Error> {
		use elements::hashes::{sha256, Hash, HashEngine};
		let key = self.keys.leaf(nonce)?;
		let mut e = sha256::Hash::engine();
		e.input(RECEIVE_PREIMAGE_TAG);
		e.input(&key.secret_bytes());
		e.input(nonce);
		Ok(sha256::Hash::from_engine(e).to_byte_array())
	}

	/// Asks to receive `amount` of `asset` over Lightning: an invoice the
	/// operator's node in the asset makes under a payment hash the wallet
	/// chose, whose preimage it alone holds, paid into an `htlc-1` leaf of the
	/// wallet's own in the asset's next round. The operator's fee comes out
	/// of the amount, within the wallet's bound (`max_fee_ppm`). Nothing is
	/// handed over until the wallet holds the leaf: `sync` then claims it
	/// with the preimage, which settles the payment.
	pub fn lightning_receive(&mut self, asset: AssetId, amount: u64, description: Option<&str>, max_fee_ppm: Option<u64>)
		-> Result<Value, Error>
	{
		self.lightning_receive_under(asset, amount, description, max_fee_ppm, None)
	}

	/// [`Self::lightning_receive`], under `hash` when named: a hash the
	/// wallet did not make, whose preimage reaches it later (a swap's, made
	/// on its other side). Such a receive is claimed only once the wallet
	/// holds the preimage ([`Self::lightning_receive_preimage`], or the
	/// operator's status once it knows it); until then its leaf is the
	/// wallet's to hold and counts nowhere.
	pub fn lightning_receive_under(&mut self, asset: AssetId, amount: u64, description: Option<&str>, max_fee_ppm: Option<u64>,
		hash: Option<[u8; 32]>) -> Result<Value, Error>
	{
		let (info, _, _, bound) = self.receive_checks(asset, amount, max_fee_ppm)?;
		let recv = &info["lightning"]["receive"];
		let operator_delay = recv["operator_delay_units"].as_u64().unwrap_or(0);
		let exit_delay = self.exit_delay();
		if exit_delay.units() as u64 <= operator_delay {
			return Err(Error::Refused(format!("the wallet's exit delay of {} units is not longer than the operator's delay of {}",
				exit_delay.units(), operator_delay)));
		}
		let nonce = random32();
		let key = self.keys.leaf(&nonce)?;
		let owner = key.x_only_public_key().0;
		self.store.put_nonce(&nonce, &owner.serialize(), "lightning-receive")?;
		let given = hash.is_some();
		let hash = match hash {
			Some(h) => {
				if self.receives()?.contains_key(&hex(&h)) || self.sends()?.contains_key(&hex(&h)) {
					return Err(Error::Refused(format!("the wallet has a payment under hash {} already", hex(&h))));
				}
				h
			},
			None => arca_covenant::script::sha256(&self.receive_preimage(&nonce)?),
		};
		let digest = super::client::lightning_receive_digest(&self.genesis, &self.operator, &asset, amount, &hash, &owner, &nonce,
			exit_delay.units());
		// The leaf is bound to the wallet's mailbox key when it is made, so a
		// restore from the mnemonic finds it before it is claimed.
		let (mailbox, mailbox_proof) = self.binding(&key)?;
		let mut body = json!({
			"asset": asset.to_string(), "amount": amount.to_string(), "payment_hash": hex(&hash), "owner": hex(&owner.serialize()),
			"owner_nonce": hex(&nonce), "exit_delay_units": exit_delay.units(),
			"owner_sig": hex(super::wallet::sign(&key, &digest).as_ref()), "mailbox": mailbox, "mailbox_proof": mailbox_proof,
		});
		if let Some(d) = description {
			body["description"] = json!(d);
		}
		let hash_hex = hex(&hash);
		let mut rec = json!({"state": "requested", "request": body, "asset": asset.to_string(), "amount": amount.to_string(),
			"nonce": hex(&nonce), "max_fee_ppm": bound, "window": recv["window_seconds"].as_u64().unwrap_or(DEFAULT_WINDOW)});
		if given {
			rec["hash_given"] = json!(true);
		}
		self.set_receive(&hash_hex, rec)?;
		let r = match self.server.post("lightning_receive", &body) {
			Ok(r) => r,
			Err(e @ Error::Server { .. }) => {
				let mut m = self.receives()?;
				m.remove(&hash_hex);
				self.store.set_meta(RECEIVES, &serde_json::to_string(&m).expect("a map"))?;
				return Err(e);
			},
			Err(e) => return Err(e),
		};
		let rec = self.receive_answered(&hash_hex, &r)?;
		Ok(json!({"invoice": rec["invoice"], "payment_hash": hash_hex, "asset": asset.to_string(), "amount": amount.to_string(),
			"fee": rec["fee"], "value": rec["value"], "expires_at": rec["expires_at"], "hash_given": given}))
	}

	/// What receiving `amount` of `asset` over Lightning would leave in the
	/// leaf, with nothing asked of the operator: its fee, out of the amount,
	/// and the leaf's value. Refused as [`Self::lightning_receive`] says.
	pub fn lightning_receive_quote(&mut self, asset: AssetId, amount: u64, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		let (info, fee, value, _) = self.receive_checks(asset, amount, max_fee_ppm)?;
		let claim = self.claim_margins(&info, asset, value)?;
		let claimed = value.checked_sub(claim).filter(|v| *v > 0)
			.ok_or_else(|| Error::Refused(format!("the leaf's {} do not cover the margins of its claim, {}", value, claim)))?;
		Ok(json!({"asset": asset.to_string(), "amount": amount.to_string(), "fee": fee.to_string(), "value": value.to_string(),
			"claim_margins": claim.to_string(), "claimed": claimed.to_string()}))
	}

	/// The margins of the claim of a leaf of `value` received over Lightning,
	/// before the leaf exists: priced as the claim prices them, on a coin of
	/// the leaf's shape (an `htlc-1` receive leaf on the operator's terms)
	/// into a leaf of the wallet's own. A transaction's size depends on its
	/// scripts, not on the leaf's place in its tree, so the claim's margins
	/// are these.
	fn claim_margins(&self, info: &Value, asset: AssetId, value: u64) -> Result<u64, Error> {
		let units = info["lightning"]["receive"]["operator_delay_units"].as_u64().and_then(|u| u16::try_from(u).ok())
			.and_then(|u| RelativeTime::from_units(u).ok())
			.ok_or_else(|| Error::Refused("the operator publishes no delay for a payment received over Lightning".into()))?;
		let timeout = MedianTime::from_consensus(self.now()?.to_consensus_u32().saturating_add(7 * 86_400))
			.map_err(|e| Error::Refused(e.to_string()))?;
		let probe_leaf = |htlc: Option<HtlcTerms>| -> Result<NewLeaf, Error> {
			let nonce = random32();
			Ok(NewLeaf { owner: self.keys.leaf_xonly(&nonce)?, owner_nonce: nonce, creator_nonce: random32(), exit_delay: self.exit_delay(),
				htlc, landing: None })
		};
		let terms = HtlcTerms { direction: HtlcDirection::Receive, payment_hash: [0; 32], timeout, operator_delay: units };
		let leaf = probe_leaf(Some(terms))?.policy(self.operator, self.genesis);
		let sweep = Sweep { token: asset, r_program: [0; 32], operator: self.operator, notice: None, burn: false };
		let coin = ValidCoin { id: LeafId([0; 32]), leaf, asset, value, sweep, expiry: timeout, hops: 0,
			origin: ValidOrigin::Transfer { inputs: vec![], outputs: vec![], index: 0 } };
		let m = super::pay::Margins::of(info, asset)?;
		let mailbox = self.keys.mailbox()?.x_only_public_key().0;
		let own = Out { asset, value: 1, leaf: probe_leaf(None)?, mailbox, until: None };
		Ok(self.checkpoint_margin_of(&coin, &m)? + self.reassignment_margin_of(&coin, &own, &m)?)
	}

	/// What the wallet checks before it asks to receive: the operator serves
	/// the asset over Lightning, its node up and receiving, its fee within
	/// the wallet's bound, the leaf at least the operator's smallest. The
	/// operator's information, the fee, the leaf's value and the bound.
	fn receive_checks(&mut self, asset: AssetId, amount: u64, max_fee_ppm: Option<u64>) -> Result<(Value, u64, u64, u64), Error> {
		let info = self.server_info()?;
		let leg = info["assets"].as_array().into_iter().flatten().find(|a| a["asset"].as_str() == Some(&asset.to_string()))
			.map(|a| a["lightning"].clone())
			.ok_or_else(|| Error::Refused(format!("the operator does not serve asset {}", asset)))?;
		if leg.is_null() {
			return Err(Error::Refused(format!("the operator runs no Lightning node in asset {}", asset)));
		}
		if leg["state"] != "up" {
			return Err(Error::Refused(format!("the operator's Lightning node in asset {} is down: {}", asset,
				leg["reason"].as_str().unwrap_or("no reason given"))));
		}
		if leg["receives"] != true {
			return Err(Error::Refused(format!("the operator's Lightning node in asset {} does not receive (it runs no hold-invoice \
				plugin)", asset)));
		}
		let fee = fee_of(&info, asset, amount)?;
		let bound = max_fee_ppm.unwrap_or(super::DEFAULT_MAX_FEE_PPM);
		if !super::round::fee_within(fee, amount, bound) {
			return Err(Error::Refused(format!("the operator charges {} of asset {} to receive {}, above the wallet's bound of {} ppm \
				(--max-fee-ppm raises it for this payment)", fee, asset, amount, bound)));
		}
		let value = amount.checked_sub(fee).filter(|v| *v > 0).ok_or_else(|| Error::Refused("the fee takes the whole amount".into()))?;
		let min = Self::min_leaf(&info, asset)?;
		if value < min {
			return Err(Error::Refused(format!("the leaf would hold {} (the {} asked, less the fee of {}), below the operator's smallest \
				leaf {}", value, amount, fee, min)));
		}
		Ok((info, fee, value, bound))
	}

	/// The preimage of the payment the wallet receives under `hash`, a hash
	/// it did not make: kept once it opens the hash, and the leaf claimed
	/// with it at the next step.
	pub fn lightning_receive_preimage(&mut self, hash: &str, preimage: &[u8; 32]) -> Result<Value, Error> {
		let mut rec = self.receives()?.get(hash).cloned()
			.ok_or_else(|| Error::Refused(format!("the wallet receives nothing under hash {}", hash)))?;
		if hex(&arca_covenant::script::sha256(preimage)) != hash {
			return Err(Error::Refused(format!("the preimage does not open hash {}", hash)));
		}
		if rec["hash_given"] != true {
			return Err(Error::Refused(format!("the wallet made the preimage of hash {} itself", hash)));
		}
		if rec["preimage"].is_null() {
			rec["preimage"] = json!(hex(preimage));
			self.set_receive(hash, rec.clone())?;
		}
		Ok(json!({"payment_hash": hash, "state": rec["state"], "preimage": "held"}))
	}

	/// The preimage the wallet holds for the payment it receives under
	/// `hash`: its own, derived from the leaf's key, or one handed to it
	/// for a hash it did not make.
	fn preimage_for(&self, hash: &str, rec: &Value) -> Result<Option<[u8; 32]>, Error> {
		if rec["hash_given"] == true {
			return match rec["preimage"].as_str() {
				Some(p) => Ok(Some(super::chain::unhex32(p)?)),
				None => Ok(None),
			};
		}
		let nonce = super::chain::unhex32(rec["nonce"].as_str().unwrap_or(""))?;
		let p = self.receive_preimage(&nonce)?;
		if hex(&arca_covenant::script::sha256(&p)) != hash {
			return Err(Error::Store("the preimage the wallet derives does not open the hash".into()));
		}
		Ok(Some(p))
	}

	/// The preimage that claims the leaf received under `hash` into the leaf
	/// of owner nonce `nonce`: the one the wallet derives, or, for a hash it
	/// did not make, the one it was handed; refused while it has none.
	pub(crate) fn received_preimage(&self, hash: &[u8; 32], nonce: &[u8; 32]) -> Result<[u8; 32], Error> {
		let h = hex(hash);
		if let Some(rec) = self.receives()?.get(&h).filter(|r| r["hash_given"] == true) {
			return self.preimage_for(&h, rec)?.ok_or_else(|| Error::Refused(format!("the leaf received under hash {} is claimed only with \
				its preimage, which the wallet does not hold yet", h)));
		}
		self.receive_preimage(nonce)
	}

	/// The leaves received under a hash the wallet did not make whose
	/// preimage it does not hold yet, by leaf id.
	pub(crate) fn awaiting_preimage(&self) -> Result<std::collections::BTreeSet<String>, Error> {
		let mut out = std::collections::BTreeSet::new();
		for rec in self.receives()?.values() {
			if rec["hash_given"] != true || !rec["preimage"].is_null() {
				continue;
			}
			let Ok(nonce) = super::chain::unhex32(rec["nonce"].as_str().unwrap_or("")) else { continue };
			if let Some(leaf) = self.store.nonce(&nonce)?.and_then(|n| n.leaf_id) {
				out.insert(leaf);
			}
		}
		Ok(out)
	}

	/// The leaf the wallet receives under `hash`, as far as it holds it:
	/// `Ok(Err(why))` while it is not held for good yet (the receive not
	/// taken up, its round not come or not final); once it is held
	/// validated, its round final, an `htlc-1` receive leaf under `hash` of
	/// the value the operator answered the receive with and the operator's
	/// published delay, `Ok(Ok((asset, value, home_in)))`, `home_in` the
	/// seconds of median time to its home date (the latest moment it must
	/// start home to be claimed); `Err` when it never will be.
	pub(crate) fn received_held(&self, hash: &str) -> Result<Result<(AssetId, u64, u64), String>, Error> {
		let r = self.receives()?.get(hash).cloned()
			.ok_or_else(|| Error::Refused(format!("the wallet receives nothing under hash {}", hash)))?;
		if r["state"] != "issuing" {
			return Ok(Err(format!("the receive under hash {} is {}", hash, r["state"])));
		}
		let nonce = super::chain::unhex32(r["nonce"].as_str().unwrap_or(""))?;
		let Some(leaf) = self.store.nonce(&nonce)?.and_then(|n| n.leaf_id) else {
			return Ok(Err("the received leaf's round has not come".into()));
		};
		let row = self.store.coin(&leaf)?.ok_or_else(|| Error::Store(format!("no coin {}", leaf)))?;
		if row.state != "receiving" {
			return Err(Error::Refused(format!("the received leaf is {}", row.state)));
		}
		let (_, a) = self.held(&row)?;
		if !a.all_final() {
			return Ok(Err(format!("the received leaf's round is not final: {}", a.waiting())));
		}
		let coin = a.valid;
		let t = coin.leaf.htlc.ok_or_else(|| Error::Refused("the received leaf is no htlc-1 leaf".into()))?;
		let info = self.server_info()?;
		// The leaf's value is what the operator answered the receive with,
		// which the wallet checked against its fee bound then.
		let value = amount(&r["value"], "the receive's value")?;
		if t.direction != HtlcDirection::Receive || hex(&t.payment_hash) != hash || coin.asset.to_string() != r["asset"].as_str().unwrap_or("")
			|| coin.value != value
		{
			return Err(Error::Refused(format!("the received leaf is not the receive's: {} of {} under {}, the receive's {} of {}",
				coin.value, coin.asset, hex(&t.payment_hash), value, r["asset"])));
		}
		if info["lightning"]["receive"]["operator_delay_units"].as_u64() != Some(t.operator_delay.units() as u64) {
			return Err(Error::Refused("the received leaf's operator delay is not the one the operator publishes".into()));
		}
		let block = info["lightning"]["receive"]["block_seconds"].as_u64().unwrap_or(60).max(1);
		let (home_at, _) = self.receive_home(&coin, &a.bases, t.timeout.to_consensus_u32() as u64, block)?;
		let median = self.now()?.to_consensus_u32() as u64;
		Ok(Ok((coin.asset, coin.value, home_at.saturating_sub(median))))
	}

	/// Whether the wallet may hand over the price of the preimage of `hash`
	/// now, a hash it did not make (its other side's, in a swap): the leaf
	/// it receives under it held for good ([`Self::received_held`]), with
	/// its home date at least `need` seconds away, the time the other side
	/// can take to reveal the preimage and the wallet to claim with it.
	/// `{"ready": true, "home_in"}` when it may; `{"ready": false, "why"}`
	/// while it may not yet; refused when it never will.
	pub fn lightning_receive_ready(&self, hash: &str, need: u64) -> Result<Value, Error> {
		match self.received_held(hash)? {
			Err(why) => Ok(json!({"payment_hash": hash, "ready": false, "why": why})),
			Ok((asset, value, home_in)) if home_in >= need => Ok(json!({"payment_hash": hash, "ready": true, "asset": asset.to_string(),
				"value": value.to_string(), "home_in": home_in})),
			Ok((_, _, home_in)) => Err(Error::Refused(format!("the leaf received under hash {} must start home in {} s, and the other \
				side can take {} s: nothing is to be handed over for it", hash, home_in, need))),
		}
	}

	/// The operator's payment into its tree under `hash`, as it serves it to
	/// anyone holding the hash: its invoice, its state, and the preimage once
	/// it knows it.
	pub fn lightning_lookup(&self, hash: &str) -> Result<Value, Error> {
		self.server.post("lightning_receive_status", &json!({"payment_hash": hash}))
	}

	/// Hands the operator the preimage of a payment into its tree: it decides
	/// a payment held inside the operator, and the operator serves it from
	/// then on.
	pub fn lightning_post_preimage(&self, hash: &str, preimage: &[u8; 32]) -> Result<Value, Error> {
		if hex(&arca_covenant::script::sha256(preimage)) != hash {
			return Err(Error::Refused(format!("the preimage does not open hash {}", hash)));
		}
		self.server.post("lightning_preimage", &json!({"payment_hash": hash, "preimage": hex(preimage)}))
	}

	/// The operator's answer to a request to receive, checked against what
	/// the wallet asked: the hash, asset and amount, a fee within the
	/// wallet's bound, and an invoice for exactly that, on the operator's
	/// node's network. Kept, and returned.
	fn receive_answered(&mut self, hash: &str, r: &Value) -> Result<Value, Error> {
		let mut rec = self.receives()?.get(hash).cloned().ok_or_else(|| Error::Store(format!("no receive {}", hash)))?;
		let asset = AssetId::from_str(rec["asset"].as_str().unwrap_or("")).map_err(|e| Error::Store(e.to_string()))?;
		let amount = amount_of(&rec["amount"])?;
		if r["payment_hash"].as_str() != Some(hash) || r["asset"].as_str() != Some(&asset.to_string()) || amount_of(&r["amount"])? != amount {
			return Err(Error::Refused(format!("the operator answers for another payment than the one asked: {}", r)));
		}
		let fee = amount_of(&r["fee"])?;
		let bound = rec["max_fee_ppm"].as_u64().unwrap_or(super::DEFAULT_MAX_FEE_PPM);
		if fee >= amount || amount_of(&r["value"])? != amount - fee || !super::round::fee_within(fee, amount, bound) {
			return Err(Error::Refused(format!("the operator's fee of {} for {} is above the wallet's bound of {} ppm, or its leaf is not 				the amount less the fee", fee, amount, bound)));
		}
		let invoice = r["invoice"].as_str().unwrap_or("").to_string();
		let inv = parse_invoice(&invoice)?;
		if hex(&inv.payment_hash) != hash || inv.asset != Some(asset) || inv.amount_msat != Some(amount * 1000) {
			return Err(Error::Refused("the operator's invoice is not for the payment the wallet asked for".into()));
		}
		rec["state"] = json!("waiting");
		rec["invoice"] = json!(invoice);
		rec["fee"] = json!(fee.to_string());
		rec["value"] = json!((amount - fee).to_string());
		rec["expires_at"] = r["expires_at"].clone();
		self.set_receive(hash, rec.clone())?;
		Ok(rec)
	}

	/// Moves every payment the wallet asked to receive on: a request the
	/// operator never answered is asked again; once the payment is held,
	/// the operator's participation that wants the leaf is followed as the
	/// wallet's own (its round, the leaf validated from the published tree,
	/// the unroll authorisations handed over: `sync`'s participations); once
	/// the wallet holds the leaf, the leaf is claimed with the preimage, into
	/// a leaf of the wallet's own. A payment the operator failed back is
	/// `failed`, with its reason.
	pub(crate) fn progress_receives(&mut self) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		for (hash, rec) in self.receives()? {
			let state = rec["state"].as_str().unwrap_or("").to_string();
			let step = match state.as_str() {
				"requested" => match self.server.post("lightning_receive", &rec["request"]) {
					Ok(r) => self.receive_answered(&hash, &r).map(|r| json!({"payment_hash": hash, "state": r["state"]})),
					Err(e) => Err(e),
				},
				"waiting" => self.receive_status(&hash),
				"issuing" | "claiming" => self.claim_received(&hash),
				_ => continue,
			};
			out.push(step.unwrap_or_else(|e| json!({"payment_hash": hash, "state": state, "error": e.to_string()})));
		}
		Ok(out)
	}

	/// Asks the operator how the payment `hash` stands: held, its leaf
	/// wanted by a participation the wallet then follows as its own.
	fn receive_status(&mut self, hash: &str) -> Result<Value, Error> {
		let st = self.server.post("lightning_receive_status", &json!({"payment_hash": hash}))?;
		let mut rec = self.receives()?.get(hash).cloned().unwrap_or_default();
		self.take_served_preimage(hash, &mut rec, &st)?;
		match st["state"].as_str() {
			Some("accepted") | Some("claimed") => {
				let pid = st["participation_id"].as_str().ok_or_else(|| Error::Refused("the operator names no participation".into()))?;
				if *pid != hex(&receive_participation_id(&super::chain::unhex32(hash)?)) {
					return Err(Error::Refused(format!("the operator names participation {} for the payment, which is not the one its \
						hash gives", pid)));
				}
				if !self.store.participations()?.iter().any(|p| p.0 == pid) {
					// No coin given up; one leaf wanted, the wallet's.
					let wanted = json!([{"nonce": rec["nonce"], "asset": rec["asset"], "value": rec["value"]}]);
					self.store.atomically(|s| {
						s.put_participation(pid, "{}", "[]", &wanted.to_string())?;
						s.set_participation(pid, "pending", None, None)
					})?;
				}
				rec["state"] = json!("issuing");
				rec["participation"] = json!(pid);
				rec["timeout"] = st["timeout"].clone();
			},
			Some("cancelled") => {
				rec["state"] = json!("failed");
				rec["reason"] = st["reason"].clone();
			},
			_ => {},
		}
		self.set_receive(hash, rec.clone())?;
		Ok(json!({"payment_hash": hash, "state": rec["state"], "operator": st["state"], "reason": rec["reason"]}))
	}

	/// A preimage the operator serves for a payment received under a hash
	/// the wallet did not make, checked against the hash and kept.
	fn take_served_preimage(&self, hash: &str, rec: &mut Value, st: &Value) -> Result<(), Error> {
		if rec["hash_given"] != true || !rec["preimage"].is_null() {
			return Ok(());
		}
		if let Some(p) = st["preimage"].as_str() {
			let bytes = super::chain::unhex32(p)?;
			if hex(&arca_covenant::script::sha256(&bytes)) == hash {
				rec["preimage"] = json!(p);
				self.set_receive(hash, rec.clone())?;
			}
		}
		Ok(())
	}

	/// Claims the leaf of the payment `hash` once the wallet holds it: its
	/// terms checked (received under the wallet's hash, the operator's delay
	/// as published, and time enough before its timeout to take it home
	/// should the operator not co-sign), then the preimage handed over with
	/// its transfer into a leaf of the wallet's own.
	///
	/// The operator's refund of the leaf opens at its timeout: the refund's
	/// two locks, the timeout and the operator's delay from the leaf's
	/// confirmation, run at once, so for a leaf confirmed an operator's delay
	/// before its timeout the refund opens at the timeout itself. The
	/// preimage is handed over only while the wallet could still unroll the
	/// leaf, wait out its exit delay and claim it a margin before then (the
	/// larger of [`CLAIM_MARGIN_BLOCKS`] and an eighth of the leaf's lock,
	/// [`Wallet::receive_home`]); later, the wallet keeps the preimage, the
	/// payment is failed back to its payer, and the leaf is the operator's.
	/// Once the preimage has gone out the payment is never called failed:
	/// should the operator not answer the claim with its co-signature, the
	/// leaf has a home date (`home_at`, the timeout less its exit delay, its
	/// unroll and the margin), at which `sync` takes it home by its claim
	/// ([`Wallet::receive_home_dates`]), before it asks the operator
	/// anything.
	fn claim_received(&mut self, hash: &str) -> Result<Value, Error> {
		let mut rec = self.receives()?.get(hash).cloned().unwrap_or_default();
		let handed = rec["state"] == "claiming";
		let pid = rec["participation"].as_str().unwrap_or("").to_string();
		if let Some(p) = self.store.participations()?.into_iter().find(|p| p.0 == pid).filter(|_| !handed) {
			if matches!(p.4.as_str(), "void" | "expired" | "refused") {
				rec["state"] = json!("failed");
				rec["reason"] = json!(format!("its leaf never came: the participation is {}", p.4));
				self.set_receive(hash, rec.clone())?;
				return Ok(json!({"payment_hash": hash, "state": "failed", "reason": rec["reason"]}));
			}
		}
		let nonce = super::chain::unhex32(rec["nonce"].as_str().unwrap_or(""))?;
		let Some(leaf) = self.store.nonce(&nonce)?.and_then(|n| n.leaf_id) else {
			return Ok(json!({"payment_hash": hash, "state": rec["state"], "note": "waiting for the leaf's round"}));
		};
		let row = self.store.coin(&leaf)?.ok_or_else(|| Error::Store(format!("no coin {}", leaf)))?;
		match row.state.as_str() {
			"receiving" => {},
			"spent" => {
				rec["state"] = json!("received");
				self.set_receive(hash, rec.clone())?;
				return Ok(json!({"payment_hash": hash, "state": "received"}));
			},
			"exited" => {
				rec["state"] = json!("received");
				rec["note"] = json!("claimed on the chain, with the payment's preimage");
				self.set_receive(hash, rec.clone())?;
				return Ok(json!({"payment_hash": hash, "state": "received", "note": rec["note"]}));
			},
			other => return Ok(json!({"payment_hash": hash, "state": rec["state"], "note": format!("the leaf is {}", other)})),
		}
		// A preimage handed over and answered by no co-signature: past the
		// leaf's home date `sync` takes it home by its claim, and no claim is
		// posted again.
		let now = self.now()?.to_consensus_u32() as u64;
		if handed && rec["home_at"].as_u64().is_some_and(|h| now >= h) {
			return Ok(json!({"payment_hash": hash, "state": "claiming", "note": "the operator has not co-signed the claim, and the leaf's \
				home date has come: sync takes it home by its claim"}));
		}
		let info = self.server_info()?;
		let (_, a) = self.held(&row)?;
		let coin = a.valid;
		let t = coin.leaf.htlc.ok_or_else(|| Error::Refused("the leaf is no htlc-1 leaf".into()))?;
		let hash_bytes = super::chain::unhex32(hash)?;
		if t.direction != HtlcDirection::Receive || t.payment_hash != hash_bytes {
			return Err(Error::Refused("the leaf is not one received under the payment's hash".into()));
		}
		if info["lightning"]["receive"]["operator_delay_units"].as_u64() != Some(t.operator_delay.units() as u64) {
			return Err(Error::Refused(format!("the leaf's operator delay of {} units is not the one the operator publishes",
				t.operator_delay.units())));
		}
		// The preimage is handed over only with time to take the leaf home by
		// its claim, should the operator not co-sign: to unroll its branch
		// and enter it (two blocks for each step, at the chain's interval the
		// operator publishes), then its exit delay and a margin of a few
		// blocks, all before the operator's refund could open, at the leaf's
		// timeout.
		let refund_from = t.timeout.to_consensus_u32() as u64;
		let block = info["lightning"]["receive"]["block_seconds"].as_u64().unwrap_or(60).max(1);
		let (home_at, margin) = self.receive_home(&coin, &a.bases, refund_from, block)?;
		let given = rec["hash_given"] == true;
		// A hash the wallet did not make: its preimage comes from elsewhere,
		// and until it has it the leaf is held as it is. That preimage is no
		// secret of the wallet's, whose payer may have it already, so it is
		// handed over whenever it comes, late or not.
		if given && rec["preimage"].is_null() {
			if let Ok(st) = self.server.post("lightning_receive_status", &json!({"payment_hash": hash})) {
				self.take_served_preimage(hash, &mut rec, &st)?;
				// Failed back with no preimage ever in hand (its payer's leg
				// never completed): the leaf is the operator's to refund, and
				// nothing of it was ever the wallet's to count.
				if rec["preimage"].is_null() && st["state"] == "cancelled" {
					rec["state"] = json!("failed");
					rec["reason"] = st["reason"].clone();
					self.set_receive(hash, rec.clone())?;
					self.store.set_coin_spent(&leaf, &format!("the operator's: the payment of hash {}, received under a hash the wallet \
						did not make, was failed back with no preimage in hand ({})", hash, st["reason"].as_str().unwrap_or("")))?;
					return Ok(json!({"payment_hash": hash, "state": "failed", "reason": rec["reason"]}));
				}
			}
			if rec["preimage"].is_null() {
				rec["home_at"] = json!(home_at);
				self.set_receive(hash, rec.clone())?;
				return Ok(json!({"payment_hash": hash, "state": rec["state"], "note": "the leaf is held; waiting for the preimage of a hash \
					the wallet did not make", "home_at": home_at}));
			}
		}
		if !given && !handed && now > home_at {
			rec["state"] = json!("failed");
			rec["reason"] = json!(format!("the leaf came too late to be claimed safely: the operator's refund opens at its timeout (median \
				time {}), and its unroll, its exit delay and a margin of {} s would end after it; the preimage stays with the wallet, \
				the payment fails back to its payer, and the leaf is the operator's", refund_from, margin));
			self.set_receive(hash, rec.clone())?;
			self.store.set_coin_spent(&leaf, &format!("the operator's: the payment of hash {} is failed back to its payer, its preimage \
				never handed over", hash))?;
			return Ok(json!({"payment_hash": hash, "state": "failed", "reason": rec["reason"]}));
		}
		let preimage = self.preimage_for(hash, &rec)?.ok_or_else(|| Error::Store("no preimage for the hash".into()))?;
		if arca_covenant::script::sha256(&preimage) != hash_bytes {
			return Err(Error::Store("the preimage does not open the hash".into()));
		}
		let asset = coin.asset;
		let m = super::pay::Margins::of(&info, asset)?;
		let cp = self.checkpoint_margin_of(&coin, &m)?;
		let own = self.own_leaf_for("received")?;
		let mailbox = self.keys.mailbox()?.x_only_public_key().0;
		let probe = Out { asset, value: 1, leaf: own, mailbox, until: None };
		let re = self.reassignment_margin_of(&coin, &probe, &m)?;
		let value = coin.value.checked_sub(cp + re).filter(|v| *v > 0)
			.ok_or_else(|| Error::Refused(format!("the leaf's {} atoms do not cover its margins", coin.value)))?;
		let back = Out { value, ..probe };
		let input = In { row, checkpoint_value: coin.value - cp, coin };
		// From here the preimage may be out: the payment is never failed,
		// and the leaf comes home by its claim at its home date unless the
		// operator co-signs.
		rec["state"] = json!("claiming");
		if rec["home_at"].is_null() || rec["handed_over_at"].is_null() {
			rec["home_at"] = json!(home_at);
			rec["margin"] = json!(margin);
			rec["handed_over_at"] = json!(now);
		}
		self.set_receive(hash, rec.clone())?;
		let answer = self.transfer_claiming(&[input], &[back], hash, &preimage)?;
		rec["state"] = json!("received");
		rec["received_by"] = answer["transfer_id"].clone();
		rec["leaf"] = answer["outputs"][0].clone();
		self.set_receive(hash, rec)?;
		Ok(json!({"payment_hash": hash, "state": "received", "transfer": answer}))
	}

	/// When the received leaf `coin`, resting on `bases` (its round, as
	/// [`Wallet::assess`] finds it) and timing out at `timeout`, must start
	/// home by its claim, and the margin that date keeps: the timeout less
	/// its exit delay, its unroll (two blocks of `block` seconds for each step
	/// of its branch and its entry) and the margin, the larger of
	/// [`CLAIM_MARGIN_BLOCKS`] and an eighth of the leaf's lock from its
	/// round's confirmation to its timeout ([`CLAIM_MARGIN_SHARE`]). A client
	/// that wakes late for that date by less than the margin still claims the
	/// leaf before the operator's refund opens.
	pub(crate) fn receive_home(&self, coin: &arca_covenant::ValidCoin, bases: &[(elements::Transaction, super::chain::Finality)],
		timeout: u64, block: u64) -> Result<(u64, u64), Error>
	{
		let steps = match &coin.origin {
			arca_covenant::ValidOrigin::Leaf { valid, .. } => valid.branch.nodes.len() as u64 + 2,
			// The exit from the batch, the entry and the claim.
			arca_covenant::ValidOrigin::Accumulator { .. } => 3,
			_ => 2,
		};
		let confirmed = match bases.iter().filter_map(|(_, f)| f.height()).min() {
			Some(h) => self.chain.median_time_at(h)?.map(u64::from),
			None => None,
		};
		let lock = confirmed.map_or(0, |c| timeout.saturating_sub(c));
		let margin = (CLAIM_MARGIN_BLOCKS * block).max(lock / CLAIM_MARGIN_SHARE);
		let home_by = steps * 2 * block + coin.leaf.exit_delay.seconds() + margin;
		Ok((timeout.saturating_sub(home_by), margin))
	}

	/// The home date of every leaf received over Lightning whose claim has
	/// gone out (its preimage with it) and has no co-signed answer, by leaf
	/// id: from then `sync` takes it home by its claim, whatever the
	/// operator does.
	pub(crate) fn receive_home_dates(&self) -> Result<BTreeMap<String, u32>, Error> {
		let mut out = BTreeMap::new();
		for rec in self.receives()?.values() {
			if rec["state"] != "claiming" {
				continue;
			}
			let (Some(at), Ok(nonce)) = (rec["home_at"].as_u64(), super::chain::unhex32(rec["nonce"].as_str().unwrap_or(""))) else { continue };
			if let Some(leaf) = self.store.nonce(&nonce)?.and_then(|n| n.leaf_id) {
				out.insert(leaf, at.min(u32::MAX as u64) as u32);
			}
		}
		Ok(out)
	}

	/// What a restore said of the received leaf of owner nonce `nonce`, when
	/// it came too late to be sure the leaf's claim wins (past its home date
	/// or its timeout).
	pub(crate) fn receive_late(&self, nonce: &[u8; 32]) -> Result<Option<String>, Error> {
		Ok(self.receives()?.values().find(|r| r["nonce"].as_str() == Some(&hex(nonce)))
			.and_then(|r| r["late"].as_str().map(str::to_string)))
	}

	/// When `sync` must run next for the payments over Lightning the wallet
	/// follows, at the latest: a receive asked for, held, or its leaf
	/// wanted, within a quarter of the operator's window (the leaf must be
	/// taken up and claimed within it); a claim unanswered, by its home date;
	/// a payment out of the tree undecided, within an hour.
	pub(crate) fn lightning_wakes(&self, now: u32, base: u32) -> Result<Option<u32>, Error> {
		let mut next: Option<u32> = None;
		let mut at = |t: u32| next = Some(next.map_or(t, |n| n.min(t)));
		let homes = self.receive_home_dates()?;
		for rec in self.receives()?.values() {
			let quarter = (rec["window"].as_u64().unwrap_or(DEFAULT_WINDOW) / 4).max(60) as u32;
			match rec["state"].as_str() {
				Some("requested") | Some("waiting") | Some("issuing") => at(base.saturating_add(quarter)),
				Some("claiming") => {
					let leaf = super::chain::unhex32(rec["nonce"].as_str().unwrap_or("")).ok()
						.and_then(|n| self.store.nonce(&n).ok().flatten()).and_then(|n| n.leaf_id);
					let held = leaf.as_ref().and_then(|l| self.store.coin(l).ok().flatten())
						.is_some_and(|c| matches!(c.state.as_str(), "receiving" | "sending"));
					if held {
						let home = leaf.as_ref().and_then(|l| homes.get(l).copied()).unwrap_or(now);
						at(home.min(base.saturating_add(quarter)));
					}
				},
				_ => {},
			}
		}
		for rec in self.sends()?.values() {
			if matches!(rec["state"].as_str(), Some("paying") | Some("failed")) {
				at(base.saturating_add(3600));
			}
		}
		Ok(next)
	}

	/// Every payment the wallet asked to receive over Lightning, with what it
	/// knows. The preimage is never shown: it stays with the wallet until it
	/// claims.
	pub fn lightning_receives(&self) -> Result<Value, Error> {
		let mut m = self.receives()?;
		for v in m.values_mut() {
			if let Some(o) = v.as_object_mut() {
				o.remove("request");
			}
		}
		Ok(json!(m))
	}
}

/// The id of the participation the operator records for the leaf of the
/// payment received under `hash`: `SHA256("Arca/lightning-receive" ‖ hash)`.
pub fn receive_participation_id(hash: &[u8; 32]) -> [u8; 32] {
	use elements::hashes::{sha256, Hash, HashEngine};
	let mut e = sha256::Hash::engine();
	e.input(super::client::LIGHTNING_RECEIVE_TAG);
	e.input(hash);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// What [`Wallet::pay_checks`] read of an invoice, and the operator's
/// terms for paying it.
struct PayChecks {
	inv: Invoice,
	asset: AssetId,
	value: u64,
	fee: u64,
	hash: String,
	info: Value,
	operator_delay: RelativeTime,
	owner_delay: RelativeTime,
	timeout_seconds: u32,
	now: u32,
}

impl PayChecks {
	/// The timeout a payment takes unless its caller names one.
	fn default_timeout(&self) -> Result<MedianTime, Error> {
		MedianTime::from_consensus(self.now.saturating_add(self.timeout_seconds).saturating_add(600)).map_err(|e| Error::Refused(e.to_string()))
	}
}

/// The explicit output of an [`Out`], from outside `pay`.
struct ExplicitOutputOf;

impl ExplicitOutputOf {
	fn explicit_of(o: &Out, w: &Wallet) -> arca_covenant::ExplicitOutput {
		arca_covenant::ExplicitOutput::new(o.asset, o.value, o.leaf.policy(w.operator, w.genesis).script_pubkey())
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn an_invoice_of_seqln_is_read_with_its_asset() {
		// Written by SeqLN (sequentia-regtest) for 5,000,000 msat of the
		// policy asset.
		let s = "lnsqrt50u1p4vwja6sp5242tp6uz86q5tcxnex99rft2nzphn3dtlctpldfzjhgnfxad50espp5g4ef5sse9090jqmp0duq6ccw7n2ecsqn39ayxxgrhs\
			ere94mhv4qdqzvsap5f5d3wl8x0sjzv0y23a6kkn34yhkpd7ja6gj7xv7p6tfa8ll9u4lsxqyjw5qcqz959qxpqysgq9tu6neufvd7zqn67f540x45knxd89r6tz\
			j99vkast6x26tzqprvqdcyw4gjpyymyvucle4dw6uugv3e8p08us4a2h2jqy6pj2wuuu4qqmas8tg";
		let inv = parse_invoice(s).unwrap();
		assert_eq!(inv.currency, "sqrt");
		assert_eq!(inv.amount_msat, Some(5_000_000));
		assert_eq!(inv.timestamp, 1_791_445_946);
		assert_eq!(hex(&inv.payment_hash), "45729a42192bcaf903617b780d630ef4d59c4013897a431903bc323c96bbbb2a");
		assert_eq!(inv.asset.unwrap().to_string(), "4d1b177ce67c24263c8a8f756b4e3525ec16fa5dd225e333c1d2d3d3ffe5e57f");
		assert_eq!(inv.expiry, 604_800);
		assert_eq!(inv.description.as_deref(), Some("d"));
		// A character changed breaks the checksum.
		let mut bad = s.to_string();
		bad.replace_range(30..31, if &s[30..31] == "q" { "p" } else { "q" });
		assert!(parse_invoice(&bad).is_err());
		assert!(parse_invoice("lnbc1").is_err());
	}
}
