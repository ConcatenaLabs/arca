//! Channel leaves (`channel-1`, [`arca_covenant::channel`]) in the wallet.
//!
//! A channel leaf holds a balance for the wallet and one for the operator.
//! The wallet keeps every state both sides signed, with both signatures, the
//! latest credit note the operator signed it, and a state it signed and sent
//! whose answer it has not seen ([`super::store`]); the server keeps them too
//! and hands them back (`channel_state`), so a restored wallet syncs them.
//!
//! - **Paying** another channel of the operator ([`Wallet::channel_pay`]):
//!   the wallet signs the channel's next state, its balance down by the
//!   amount and every credit not yet folded folded in, and sends it with the
//!   receiver's channel; the answer is the operator's signature on the state
//!   and the receiver's note, which the wallet keeps as its receipt. The
//!   receiver's payment is final then.
//! - **Being paid** needs nothing of the wallet: the operator signs its
//!   channel a note, which the wallet reads when it syncs
//!   ([`Wallet::channel_sync`]), checks, and folds into its balance at its
//!   next state ([`Wallet::channel_fold`], or any payment).
//! - **Closing into a round** is a refresh of the coin: it gives up its side,
//!   the latest balance and every credit not folded, for a leaf of its own.
//! - **Closing on the chain** ([`Wallet::channel_exit`]), run until done:
//!   the coin's path unrolled as any leaf's, the latest state published over
//!   whatever state the coin is in, its settle after the exit delay, the
//!   credit claimed from the operator's side, and the wallet's outputs swept
//!   home with the leaf's key.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use elements::secp256k1_zkp::schnorr::Signature;
use elements::{AssetId, OutPoint, Transaction, TxOut};
use serde_json::{json, Value};

use arca_covenant::channel::{owner_script_pubkey, ChannelPolicy, ChannelSpend, State};
use arca_covenant::sign::verify_digest;
use arca_covenant::{CoinRecord, ExplicitOutput};

use super::chain::{hex, unhex};
use super::exit::{Here, Payer};
use super::store::CoinRow;
use super::wallet::{sign, Wallet};
use super::Error;

/// What a channel code says it is ([`Wallet::channel_code`]).
pub(crate) const CODE_KIND: &str = "channel-code";

/// What the wallet keeps of a channel.
#[derive(Debug, Clone, Default)]
struct Kept {
	/// Every state past the opening both sides signed, oldest first, with
	/// the owner's and the operator's signatures.
	states: Vec<(State, String, String)>,
	/// The latest credit note: the cumulative credit and the operator's
	/// signature.
	credit: u64,
	credit_sig: Option<String>,
	/// A state the wallet signed and sent, not yet answered:
	/// `{state, owner_sig, pay}`.
	pending: Option<Value>,
}

/// The credit of `k` not folded in `latest`, as the chain pays it: a note
/// counts up to the cap of the state it is claimed under, the operator's
/// balance and what was folded, and no further.
fn unfolded(k: &Kept, latest: &State) -> u64 {
	k.credit.min(latest.credit_cap()).saturating_sub(latest.folded)
}

fn state_json(s: &State) -> Value {
	json!({"number": s.number.to_string(), "owner": s.owner.to_string(), "operator": s.operator.to_string(),
		"folded": s.folded.to_string()})
}

fn num(v: &Value, what: &str) -> Result<u64, Error> {
	v.as_str().and_then(|s| s.parse().ok()).or_else(|| v.as_u64())
		.ok_or_else(|| Error::Refused(format!("{}: not a number: {}", what, v)))
}

fn state_of(v: &Value) -> Result<State, Error> {
	Ok(State { number: num(&v["number"], "number")?, owner: num(&v["owner"], "owner")?, operator: num(&v["operator"], "operator")?,
		folded: num(&v["folded"], "folded")? })
}

fn sig_of(s: &str) -> Result<Signature, Error> {
	Signature::from_slice(&unhex(s)?).map_err(|e| Error::Refused(format!("a signature: {}", e)))
}

impl Kept {
	fn load(text: Option<String>) -> Result<Kept, Error> {
		let Some(t) = text else { return Ok(Kept::default()) };
		let v: Value = serde_json::from_str(&t).map_err(|e| Error::Store(e.to_string()))?;
		let mut states = vec![];
		for s in v["states"].as_array().cloned().unwrap_or_default() {
			states.push((state_of(&s["state"])?, s["owner_sig"].as_str().unwrap_or("").to_string(),
				s["operator_sig"].as_str().unwrap_or("").to_string()));
		}
		Ok(Kept {
			states,
			credit: num(&v["credit"], "credit").unwrap_or(0),
			credit_sig: v["credit_sig"].as_str().map(str::to_string),
			pending: v.get("pending").filter(|p| !p.is_null()).cloned(),
		})
	}

	fn json(&self) -> Value {
		json!({
			"states": self.states.iter().map(|(s, o, p)| json!({"state": state_json(s), "owner_sig": o, "operator_sig": p}))
				.collect::<Vec<_>>(),
			"credit": self.credit.to_string(), "credit_sig": self.credit_sig, "pending": self.pending,
		})
	}

	/// The latest state both sides signed, or the opening.
	fn latest(&self, policy: &ChannelPolicy) -> State {
		self.states.last().map_or(policy.opening(), |s| s.0)
	}

	/// The state of number `n` the wallet knows: the opening, or one both
	/// signed.
	fn state(&self, policy: &ChannelPolicy, n: u64) -> Option<State> {
		if n == 0 {
			return Some(policy.opening());
		}
		let pending = self.pending.as_ref().and_then(|p| state_of(&p["state"]).ok()).filter(|p| p.number == n);
		self.states.iter().find(|s| s.0.number == n).map(|s| s.0).or(pending)
	}

	fn adopt(&mut self, s: State, owner_sig: String, operator_sig: String) {
		if self.states.iter().all(|k| k.0.number < s.number) {
			self.states.push((s, owner_sig, operator_sig));
		}
	}
}

impl Wallet {
	/// The terms of a channel leaf of `asset` with `capacity` on the
	/// operator's side, as the operator's `info` publishes what it makes:
	/// refused above its capacity, or in an asset it makes no channels of.
	pub(crate) fn channel_terms(info: &Value, asset: AssetId, capacity: u64) -> Result<arca_covenant::Channel, Error> {
		let a = info["assets"].as_array().and_then(|l| l.iter().find(|a| a["asset"].as_str() == Some(&asset.to_string())))
			.ok_or_else(|| Error::Refused(format!("the operator does not serve asset {}", asset)))?;
		let c = &a["channels"];
		if c.is_null() {
			return Err(Error::Refused(format!("the operator makes no channel leaf of asset {}", asset)));
		}
		let cap = num(&c["capacity"], "the operator's channel capacity")?;
		if capacity == 0 || capacity > cap {
			return Err(Error::Refused(format!("an opening balance of {} on the operator's side; it puts 1 to {} on its side of a channel of \
				asset {}", capacity, cap, asset)));
		}
		let units = c["window_units"].as_u64().and_then(|u| u16::try_from(u).ok())
			.ok_or_else(|| Error::Refused("the operator names no credit window".into()))?;
		Ok(arca_covenant::Channel { capacity, window: arca_covenant::RelativeTime::from_units(units)
			.map_err(|e| Error::Refused(e.to_string()))? })
	}

	/// Opens a channel: gives up the coins `leaf_ids` (every live coin of
	/// one asset when empty) in a round for a channel leaf holding what they
	/// hold less the refresh fee on the wallet's side and `capacity` on the
	/// operator's; with `keep`, that much of it goes to a plain leaf of the
	/// wallet's beside the channel instead.
	pub fn channel_open(&mut self, leaf_ids: &[String], capacity: u64, keep: Option<u64>, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		let mut quote = self.refresh_quote(leaf_ids, max_fee_ppm)?;
		quote.channel = Some(capacity);
		quote.keep = keep;
		self.participate(quote, None)
	}

	/// The wallet's channels that can pay and be paid now, one for each
	/// asset (the one holding most): a live coin whose round is final.
	pub(crate) fn usable_channels(&self) -> Result<BTreeMap<AssetId, (String, u64)>, Error> {
		let mut out: BTreeMap<AssetId, (String, u64)> = BTreeMap::new();
		for c in self.store.coins_in("live")? {
			let Ok((row, _, asset)) = self.channel_coin(&c.leaf_id) else { continue };
			let Ok((_, a)) = self.held(&row) else { continue };
			if !a.all_final() {
				continue;
			}
			let worth = self.channel_worth(&row)?.unwrap_or(0);
			if out.get(&asset).is_none_or(|(_, w)| *w < worth) {
				out.insert(asset, (row.leaf_id.clone(), worth));
			}
		}
		Ok(out)
	}

	/// The wallet's channels that can be paid now, by asset, as a text a
	/// payer reads (`kind` "channel-code"): the chain, the operator, a
	/// channel for each asset and, when given, an address of the wallet's
	/// for a payment on the chain instead. It names no key of the wallet's
	/// and lapses never; a channel closed since is refused by the operator,
	/// and the payer pays otherwise.
	pub fn channel_code(&self, address: Option<&str>) -> Result<Value, Error> {
		let ch = self.usable_channels()?;
		if ch.is_empty() {
			return Err(Error::Refused("the wallet holds no channel that can be paid now".into()));
		}
		let mut v = json!({"kind": CODE_KIND, "genesis_hash": self.genesis.genesis_hash().to_string(), "operator": self.operator.to_string(),
			"channels": ch.iter().map(|(a, (l, _))| (a.to_string(), json!(l))).collect::<serde_json::Map<_, _>>()});
		if let Some(a) = address.filter(|a| !a.is_empty()) {
			v["address"] = json!(a);
		}
		Ok(json!({"code": format!("{}{}", self.spelling.request, hex(v.to_string().as_bytes())), "details": v}))
	}

	/// Reads every live channel of the wallet's from the operator, as
	/// [`Self::channel_sync`] reads one: the notes it was paid, and a state
	/// sent and never answered sent again.
	pub fn channel_sync_all(&self) -> Result<Value, Error> {
		let mut out = vec![];
		for c in self.store.coins_in("live")? {
			if self.channel_coin(&c.leaf_id).is_err() {
				continue;
			}
			out.push(self.channel_sync(&c.leaf_id).unwrap_or_else(|e| json!({"leaf_id": c.leaf_id, "error": e.to_string()})));
		}
		Ok(Value::Array(out))
	}

	/// What a wallet does for its channels by itself (`care` with
	/// `channels`): reads every channel, folds the credit it was paid into
	/// its balance, and, for each asset the operator makes channels of and
	/// the wallet holds leaves of but no channel, opens one in the next
	/// round from those leaves, half of what they hold (after the refresh
	/// fee, under `max_fee_ppm`) in the channel with the operator's whole
	/// capacity on its side, the other half in a plain leaf beside it. Coins
	/// a plan names, resting orders, coins awaiting a preimage and coins of a
	/// supervised asset stay as they are; so do coins too small to split into
	/// two leaves of the operator's smallest.
	pub fn care_channels(&mut self, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		let mut synced = vec![];
		let mut folded = vec![];
		for c in self.store.coins_in("live")? {
			if self.channel_coin(&c.leaf_id).is_err() {
				continue;
			}
			match self.channel_sync(&c.leaf_id) {
				Ok(v) => {
					let unfolded = num(&v["credit_not_folded"], "credit").unwrap_or(0);
					if unfolded > 0 && v["pending"] != json!(true) {
						folded.push(match self.channel_fold(&c.leaf_id) {
							Ok(f) => json!({"leaf_id": c.leaf_id, "folded": unfolded.to_string(), "state": f["state"]}),
							Err(e) => json!({"leaf_id": c.leaf_id, "error": e.to_string()}),
						});
					}
					synced.push(json!({"leaf_id": c.leaf_id, "balance": v["balance"]}));
				},
				Err(e) => synced.push(json!({"leaf_id": c.leaf_id, "error": e.to_string()})),
			}
		}
		let info = self.server_info()?;
		let planned = self.planned_coins()?;
		let awaiting = self.awaiting_preimage()?;
		let mut with_channel: BTreeSet<String> = BTreeSet::new();
		for c in self.store.coins()? {
			if !matches!(c.state.as_str(), "spent" | "exited" | "lost") && self.channel_coin(&c.leaf_id).is_ok() {
				with_channel.insert(c.asset.clone());
			}
		}
		let mut opened = vec![];
		for a in info["assets"].as_array().cloned().unwrap_or_default() {
			let Some(capacity) = a["channels"]["capacity"].as_str().and_then(|c| c.parse::<u64>().ok()).filter(|c| *c > 0) else { continue };
			let Some(asset) = a["asset"].as_str().and_then(|s| AssetId::from_str(s).ok()) else { continue };
			if with_channel.contains(&asset.to_string()) || !matches!(self.landing_rule(&info, asset), Ok(None)) {
				continue;
			}
			let mut coins = vec![];
			for c in self.store.coins_in("live")? {
				if c.asset != asset.to_string() || planned.contains(&c.leaf_id) || awaiting.contains(&c.leaf_id)
					|| super::resting::is_order_coin(&c)
				{
					continue;
				}
				match Self::record_of(&c) {
					Ok(CoinRecord::Leaf { record, .. }) if record.htlc.is_none() && record.channel.is_none() => {},
					Ok(CoinRecord::Leaf { .. }) | Err(_) => continue,
					Ok(_) => {},
				}
				if self.held(&c).is_ok_and(|(_, h)| h.all_final()) {
					coins.push(c.leaf_id.clone());
				}
			}
			if coins.is_empty() {
				continue;
			}
			let min = Self::min_leaf(&info, asset)?;
			let mut q = match self.refresh_quote(&coins, max_fee_ppm) {
				Ok(q) => q,
				Err(e) => {
					opened.push(json!({"asset": asset.to_string(), "error": e.to_string()}));
					continue;
				},
			};
			let after = q.after(&asset).unwrap_or(0);
			let keep = after - after / 2;
			if after / 2 < min || keep < min {
				opened.push(json!({"asset": asset.to_string(), "left": format!("{} after the fee is too little for a channel and a leaf beside 					it, each at least {}", after, min)}));
				continue;
			}
			q.channel = Some(capacity);
			q.keep = Some(keep);
			opened.push(match self.participate(q, None) {
				Ok(v) => json!({"asset": asset.to_string(), "capacity": capacity.to_string(), "kept": keep.to_string(),
					"participation": v["participations"][0]["participation"], "state": v["participations"][0]["state"],
					"error": v["participations"][0].get("error")}),
				Err(e) => json!({"asset": asset.to_string(), "error": e.to_string()}),
			});
		}
		Ok(json!({"synced": synced, "folded": folded, "opened": opened}))
	}

	/// The channel coin `leaf_id`: its row, its channel and its asset.
	fn channel_coin(&self, leaf_id: &str) -> Result<(CoinRow, ChannelPolicy, AssetId), Error> {
		let row = self.store.coin(leaf_id)?.ok_or_else(|| Error::Refused(format!("no coin {}", leaf_id)))?;
		let record = Self::record_of(&row)?;
		let policy = match &record {
			CoinRecord::Leaf { record, .. } => record.leaf().channel_policy(),
			_ => None,
		}.ok_or_else(|| Error::Refused(format!("coin {} is not a channel-1 leaf", leaf_id)))?;
		let asset = AssetId::from_str(&row.asset).map_err(|e| Error::Store(e.to_string()))?;
		Ok((row, policy, asset))
	}

	pub(crate) fn channel_pending(&self, leaf_id: &str) -> Result<bool, Error> {
		Ok(self.kept(leaf_id)?.pending.is_some())
	}

	fn kept(&self, leaf_id: &str) -> Result<Kept, Error> {
		Kept::load(self.store.channel(leaf_id)?)
	}

	fn keep(&self, leaf_id: &str, k: &Kept) -> Result<(), Error> {
		self.store.put_channel(leaf_id, &k.json().to_string())
	}

	/// What a channel coin is worth to the wallet: its latest balance and
	/// every credit not yet folded; `None` for a coin that is no channel.
	pub(crate) fn channel_worth(&self, row: &CoinRow) -> Result<Option<u64>, Error> {
		let Ok(record) = Self::record_of(row) else { return Ok(None) };
		let policy = match &record {
			CoinRecord::Leaf { record, .. } => record.leaf().channel_policy(),
			_ => None,
		};
		let Some(policy) = policy else { return Ok(None) };
		let k = self.kept(&row.leaf_id)?;
		let latest = k.latest(&policy);
		Ok(Some(latest.owner.saturating_add(unfolded(&k, &latest))))
	}

	/// What the wallet holds of channel `leaf_id`, asking nothing.
	fn channel_view(&self, leaf_id: &str, policy: &ChannelPolicy, asset: AssetId, k: &Kept) -> Value {
		let latest = k.latest(policy);
		let unfolded = unfolded(k, &latest);
		json!({
			"leaf_id": leaf_id, "asset": asset.to_string(), "value": policy.terms.value.to_string(),
			"state": state_json(&latest),
			"balance": latest.owner.saturating_add(unfolded).to_string(),
			"credit": k.credit.to_string(), "credit_not_folded": unfolded.to_string(),
			"operator_side": latest.operator.saturating_sub(unfolded).to_string(),
			"pending": k.pending.is_some(),
		})
	}

	/// Every channel coin the wallet holds, with what it holds of each,
	/// asking nothing.
	pub fn channels(&self) -> Result<Value, Error> {
		let mut out = vec![];
		for c in self.store.coins()? {
			if matches!(c.state.as_str(), "spent" | "exited" | "lost") {
				continue;
			}
			if let Ok((_, policy, asset)) = self.channel_coin(&c.leaf_id) {
				let mut v = self.channel_view(&c.leaf_id, &policy, asset, &self.kept(&c.leaf_id)?);
				v["coin_state"] = json!(c.state);
				// Paid and paying only once its round is final.
				v["final"] = json!(self.held(&c).is_ok_and(|(_, a)| a.all_final()));
				out.push(v);
			}
		}
		Ok(Value::Array(out))
	}

	/// Reads channel `leaf_id` from the operator and takes from it every
	/// state both sides signed and every note the operator signed that is
	/// newer than the wallet's, each checked: the state's signatures by the
	/// wallet's key and the operator's over the message the wallet builds,
	/// the note's by the operator's. A state the wallet sent and never saw
	/// answered is sent again.
	pub fn channel_sync(&self, leaf_id: &str) -> Result<Value, Error> {
		let (row, policy, asset) = self.channel_coin(leaf_id)?;
		let key = self.coin_key(&row.owner_nonce)?;
		let id = unhex(leaf_id)?;
		let auth = self.server.auth("channel_state", &key, &self.genesis, &id)?;
		let v = self.server.post("channel_state", &json!({"auth": auth, "leaf_id": leaf_id}))?;
		let mut k = self.kept(leaf_id)?;
		let s = state_of(&v["state"])?;
		if let (Some(o), Some(p)) = (v["owner_sig"].as_str(), v["operator_sig"].as_str()) {
			let d = policy.state_message(&s).map_err(|e| Error::Refused(e.to_string()))?.digest;
			if !verify_digest(&sig_of(o)?, &d, &policy.owner) || !verify_digest(&sig_of(p)?, &d, &self.operator) {
				return Err(Error::Refused(format!("the operator shows state {} of channel {} with signatures that do not verify", s.number,
					leaf_id)));
			}
			k.adopt(s, o.to_string(), p.to_string());
		}
		if let (Some(c), Some(sg)) = (v["note"]["credit"].as_str(), v["note"]["signature"].as_str()) {
			let c: u64 = c.parse().map_err(|_| Error::Refused("a note's credit".into()))?;
			let d = policy.note_message(c).map_err(|e| Error::Refused(e.to_string()))?.digest;
			if !verify_digest(&sig_of(sg)?, &d, &self.operator) {
				return Err(Error::Refused(format!("the operator shows a note of {} for channel {} its key did not sign", c, leaf_id)));
			}
			if c > k.credit {
				k.credit = c;
				k.credit_sig = Some(sg.to_string());
			}
		}
		// A state sent and unanswered: answered by now when the operator's
		// latest is at or past it; else sent again, unchanged.
		if let Some(p) = k.pending.clone() {
			let ps = state_of(&p["state"])?;
			if k.latest(&policy).number >= ps.number {
				k.pending = None;
			} else {
				self.keep(leaf_id, &k)?;
				return self.channel_send(leaf_id, &policy, asset, k, p);
			}
		}
		self.keep(leaf_id, &k)?;
		Ok(self.channel_view(leaf_id, &policy, asset, &k))
	}

	/// Sends `p`, a state the wallet signed (`{state, owner_sig, pay}`), and
	/// takes the answer: the operator's signature, checked, and for a
	/// payment the receiver's note, kept as the receipt.
	fn channel_send(&self, leaf_id: &str, policy: &ChannelPolicy, asset: AssetId, mut k: Kept, p: Value) -> Result<Value, Error> {
		let s = state_of(&p["state"])?;
		let mut body = json!({"leaf_id": leaf_id, "state": state_json(&s), "owner_sig": p["owner_sig"]});
		if !p["pay"].is_null() {
			body["pay"] = p["pay"].clone();
		}
		let answer = match self.server.post("channel_update", &body) {
			Ok(a) => a,
			// Not answered: the state stands, and is sent again.
			Err(Error::Unreachable(why)) => return Err(Error::Unreachable(format!("channel {} state {}: {}", leaf_id, s.number, why))),
			Err(e) => {
				k.pending = None;
				self.keep(leaf_id, &k)?;
				return Err(e);
			},
		};
		let op = answer["operator_sig"].as_str().ok_or_else(|| Error::Refused("no operator signature".into()))?;
		let d = policy.state_message(&s).map_err(|e| Error::Refused(e.to_string()))?.digest;
		if !verify_digest(&sig_of(op)?, &d, &self.operator) {
			return Err(Error::Refused(format!("the operator's signature on state {} of channel {} does not verify", s.number, leaf_id)));
		}
		k.adopt(s, p["owner_sig"].as_str().unwrap_or("").to_string(), op.to_string());
		k.pending = None;
		self.keep(leaf_id, &k)?;
		let mut out = self.channel_view(leaf_id, policy, asset, &k);
		if !answer["note"].is_null() {
			out["receipt"] = answer["note"].clone();
		}
		Ok(out)
	}

	/// The wallet's next state of channel `leaf_id`, paying `pay` (another
	/// channel and an amount) or, with none, folding the credit: signed, kept
	/// as pending, sent, and taken.
	fn channel_next(&self, leaf_id: &str, pay: Option<(&str, u64)>) -> Result<Value, Error> {
		let synced = self.channel_sync(leaf_id)?;
		let (row, policy, asset) = self.channel_coin(leaf_id)?;
		if row.state != "live" {
			return Err(Error::Refused(format!("channel {} is {}, not live", leaf_id, row.state)));
		}
		let mut k = self.kept(leaf_id)?;
		if k.pending.is_some() {
			return Err(Error::Refused(format!("channel {} has a state sent and not answered: {}", leaf_id, synced)));
		}
		let latest = k.latest(&policy);
		let amount = pay.map_or(0, |p| p.1);
		let unfolded = unfolded(&k, &latest);
		if pay.is_none() && unfolded == 0 {
			return Err(Error::Refused(format!("channel {} has no credit to fold", leaf_id)));
		}
		let next = latest.pay(amount, latest.folded + unfolded).ok_or_else(|| Error::Refused(format!(
			"channel {} holds {} and {} of credit not folded: less than {}", leaf_id, latest.owner, unfolded, amount)))?;
		let key = self.coin_key(&row.owner_nonce)?;
		let d = policy.state_message(&next).map_err(|e| Error::Refused(e.to_string()))?.digest;
		let owner_sig = hex(sign(&key, &d).as_ref());
		let p = json!({"state": state_json(&next), "owner_sig": owner_sig,
			"pay": pay.map(|(to, a)| json!({"to": to, "amount": a.to_string()}))});
		k.pending = Some(p.clone());
		self.keep(leaf_id, &k)?;
		self.channel_send(leaf_id, &policy, asset, k, p)
	}

	/// Pays `amount` from channel `from` into channel `to`, another channel
	/// of the operator in the same asset: final for the receiver once
	/// answered.
	pub fn channel_pay(&self, from: &str, to: &str, amount: u64) -> Result<Value, Error> {
		if amount == 0 {
			return Err(Error::Refused("a payment of nothing".into()));
		}
		let mut v = self.channel_next(from, Some((to, amount)))?;
		v["paid"] = json!({"to": to, "amount": amount.to_string()});
		Ok(v)
	}

	/// Folds every credit channel `leaf_id` was paid into its balance.
	pub fn channel_fold(&self, leaf_id: &str) -> Result<Value, Error> {
		self.channel_next(leaf_id, None)
	}

	/// Brings channel `leaf_id` home on the chain, one step a run, as far as
	/// the chain allows now: the coin's path unrolled; the latest state
	/// published over any older state the coin is in; once its exit delay
	/// has run, its settle; the credit not folded claimed from the
	/// operator's side; and the wallet's outputs swept to an address of its
	/// own. Fees come from an on-chain coin in the asset named or chosen.
	pub fn channel_exit(&mut self, leaf_id: &str, fee_asset: Option<AssetId>) -> Result<Value, Error> {
		let (row, policy, asset) = self.channel_coin(leaf_id)?;
		let key = self.coin_key(&row.owner_nonce)?;
		let k = self.kept(leaf_id)?;
		let latest = k.latest(&policy);
		let record = Self::record_of(&row)?;
		let now = self.now()?;
		let prior: Value = match self.store.exit(leaf_id)? {
			Some((_, j, _)) => serde_json::from_str(&j).map_err(|e| Error::Store(e.to_string()))?,
			None => json!({}),
		};
		let mut payer = Payer::new(fee_asset.or_else(|| prior["fee_asset"].as_str().and_then(|a| AssetId::from_str(a).ok())));
		payer.moved = Some(asset);
		let mut steps = vec![];
		// The leaf: where it is, or the path unrolled to it.
		let leaf_at = match prior["leaf"].as_str().map(OutPoint::from_str).transpose().map_err(|e| Error::Store(e.to_string()))? {
			Some(at) => at,
			None => {
				let policy_w = self.followed_policy(row.expiry, now);
				let txs = self.accepted_bases(&record)?;
				let coin = self.resolve(&record, &txs, &policy_w).map_err(|e| Error::Refused(e.to_string()))?;
				let mut path = vec![];
				Self::path_outputs(&coin, &mut path);
				let here = Here { at: self.chain.locate(&path)?, outputs: path };
				let mut built = vec![];
				let at = self.bring(&coin, &mut payer, &mut built, &here)?;
				for u in &built {
					if let Some(e) = self.channel_broadcast(&u.tx, "unroll", &mut steps) {
						return Ok(json!({"leaf_id": leaf_id, "state": "unrolling", "steps": steps, "error": e}));
					}
				}
				self.store.set_exit(leaf_id, "unrolling", &json!({"leaf": at.to_string(),
					"fee_asset": payer.asset.map(|a| a.to_string())}).to_string(), None)?;
				self.store.set_coin_state(leaf_id, "exiting", "its channel is being closed on the chain")?;
				at
			},
		};
		if !self.chain.finality(&leaf_at.txid)?.in_chain() {
			return Ok(json!({"leaf_id": leaf_id, "state": "unrolling", "steps": steps, "leaf": leaf_at.to_string(),
				"next": "the leaf's transaction is not in a block yet; run again once it is"}));
		}
		// Follow the coin through the states published on it.
		let from_height = self.chain.finality(&leaf_at.txid)?.height().unwrap_or(0);
		let mut at = leaf_at;
		let mut state = policy.opening();
		let settled: Option<(Transaction, State)> = loop {
			if self.chain.unspent(&at)? {
				break None;
			}
			let Some((tx, _)) = self.chain.spender(&at, from_height)? else {
				return Ok(json!({"leaf_id": leaf_id, "state": "waiting", "steps": steps,
					"next": format!("channel output {} is spent by a transaction the wallet cannot find yet", at)}));
			};
			let i = tx.input.iter().position(|x| x.previous_output == at).expect("it spends the output");
			// Which leaf the spend ran, read without its annex: whoever
			// published it may have added one, which changes nothing it did.
			let spend = policy.read_spend(&state, &tx.input[i].witness.script_witness).map_err(|e| Error::Refused(format!(
				"channel {}: transaction {}: {}", leaf_id, tx.txid(), e)))?;
			match spend {
				ChannelSpend::Update { to } => {
					state = k.state(&policy, to).ok_or_else(|| Error::Refused(format!("channel {} was moved to state {}, which the \
						wallet never signed", leaf_id, to)))?;
					if tx.output.get(i).map(|o| &o.script_pubkey) != Some(&policy.script_pubkey(&state)) {
						return Err(Error::Refused(format!("channel {}: transaction {} moved it to state {} at an output other than \
							that state's", leaf_id, tx.txid(), to)));
					}
					at = OutPoint::new(tx.txid(), i as u32);
				},
				ChannelSpend::Settle => break Some((tx, state)),
				ChannelSpend::Collab => {
					self.store.set_coin_state(leaf_id, "spent", &format!("its channel was spent by {}, by its collaborative path",
						tx.txid()))?;
					return Ok(json!({"leaf_id": leaf_id, "state": "spent", "spent_by": tx.txid().to_string(),
						"note": "the coin was spent by its collaborative path (a forfeit or a co-signed spend), not by a state"}));
				},
			}
		};
		let Some((settle, settled_state)) = settled else {
			// The coin rests at `at`, in `state`.
			if state.number < latest.number {
				let (_, o, p) = k.states.iter().find(|s| s.0.number == latest.number).expect("the latest is kept").clone();
				let tx = self.with_fee(&mut payer, &|f| policy.update_tx(at, asset, &state, &latest, &sig_of(&p)?, &sig_of(&o)?, f)
					.map_err(|e| Error::Refused(e.to_string())))?.tx;
				if let Some(e) = self.channel_broadcast(&tx, "update to the latest state", &mut steps) {
					return Ok(json!({"leaf_id": leaf_id, "state": "updating", "steps": steps, "error": e}));
				}
				return Ok(json!({"leaf_id": leaf_id, "state": "updating", "steps": steps,
					"next": format!("state {} published over state {}; its settle waits the exit delay from its block", latest.number,
						state.number)}));
			}
			let tx = self.with_fee(&mut payer, &|f| policy.settle_tx(at, asset, &state, f).map_err(|e| Error::Refused(e.to_string())))?.tx;
			return Ok(match self.channel_broadcast(&tx, "settle", &mut steps) {
				None => json!({"leaf_id": leaf_id, "state": "settling", "steps": steps, "state_number": state.number}),
				Some(e) => json!({"leaf_id": leaf_id, "state": "waiting", "steps": steps, "state_number": state.number,
					"next": format!("the settle of state {} waits the exit delay of {} s from its block: {}", state.number,
						policy.exit_delay.seconds(), e)}),
			});
		};
		if !self.chain.finality(&settle.txid())?.in_chain() {
			return Ok(json!({"leaf_id": leaf_id, "state": "settling", "steps": steps, "next": "the settle is not in a block yet"}));
		}
		// The credit not folded, claimed from the operator's side.
		let credit_spk = policy.credit_taproot(&settled_state).script_pubkey();
		if k.credit > settled_state.folded {
			if let Some(sg) = &k.credit_sig {
				for (op, out, _) in self.chain.coins_at(std::slice::from_ref(&credit_spk))? {
					let value_in = out.value.explicit().unwrap_or(0);
					if policy.claim_amounts(&settled_state, k.credit, value_in).is_ok() {
						let note = sig_of(sg)?;
						let tx = self.with_fee(&mut payer, &|f| policy.claim_tx(op, asset, &settled_state, value_in, k.credit, &note, f)
							.map_err(|e| Error::Refused(e.to_string())))?.tx;
						if let Some(e) = self.channel_broadcast(&tx, "credit claim", &mut steps) {
							return Ok(json!({"leaf_id": leaf_id, "state": "claiming", "steps": steps, "error": e}));
						}
						return Ok(json!({"leaf_id": leaf_id, "state": "claiming", "steps": steps,
							"next": "the credit claim is out; run again once it is in a block to sweep"}));
					}
				}
			}
		}
		// The wallet's outputs at OP_1 <A>, swept home.
		let mine = self.chain.coins_at(std::slice::from_ref(&owner_script_pubkey(&policy.owner)))?;
		if mine.is_empty() {
			let swept = prior["swept"].as_str().map(elements::Txid::from_str).transpose().map_err(|e| Error::Store(e.to_string()))?;
			let home = match swept {
				Some(t) => self.chain.finality(&t)?.in_chain(),
				None => settled_state.owner == 0 && k.credit <= settled_state.folded,
			};
			if home {
				self.store.set_coin_state(leaf_id, "exited", "its channel was closed on the chain and its side swept home")?;
				return Ok(json!({"leaf_id": leaf_id, "state": "exited", "steps": steps}));
			}
			return Ok(json!({"leaf_id": leaf_id, "state": "sweeping", "steps": steps, "next": "the sweep home is not in a block yet"}));
		}
		let to_wallet = self.new_script(super::keys::RECEIVE)?;
		let total: u64 = mine.iter().map(|(_, o, _)| o.value.explicit().unwrap_or(0)).sum();
		let fee = self.fee_for(asset, 120 + 60 * mine.len() as u64)?;
		let mut tx = Transaction {
			version: 2, lock_time: elements::LockTime::ZERO,
			input: mine.iter().map(|(op, _, _)| elements::TxIn { previous_output: *op, ..Default::default() }).collect(),
			output: vec![ExplicitOutput::new(asset, total.saturating_sub(fee), to_wallet.clone()).txout(), TxOut::new_fee(fee, asset)],
		};
		let prevouts: Vec<TxOut> = mine.iter().map(|(_, o, _)| o.clone()).collect();
		for i in 0..tx.input.len() {
			self.sign_key_path(&mut tx, i, &prevouts, &key)?;
		}
		if let Some(e) = self.channel_broadcast(&tx, "sweep home", &mut steps) {
			return Ok(json!({"leaf_id": leaf_id, "state": "sweeping", "steps": steps, "error": e}));
		}
		let mut v = prior.clone();
		v["swept"] = json!(tx.txid().to_string());
		self.store.set_exit(leaf_id, "swept", &v.to_string(), Some(&tx.txid().to_string()))?;
		Ok(json!({"leaf_id": leaf_id, "state": "swept", "steps": steps, "home": {"txid": tx.txid().to_string(),
			"amount": total.saturating_sub(fee).to_string(), "to": self.chain.address(&to_wallet)?}}))
	}

	/// Broadcasts `tx`, a step of a channel's exit: noted in `steps`, or
	/// why the node refused it.
	fn channel_broadcast(&self, tx: &Transaction, what: &str, steps: &mut Vec<Value>) -> Option<String> {
		match self.chain.broadcast(tx) {
			Ok(txid) => {
				steps.push(json!({"what": what, "txid": txid.to_string(), "vsize": tx.vsize()}));
				None
			},
			Err(e) => Some(format!("{}: {}", what, e)),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn kept(credit: u64) -> Kept {
		Kept { states: vec![], credit, credit_sig: None, pending: None }
	}

	#[test]
	fn a_note_counts_as_far_as_the_chain_pays_it() {
		let st = State { number: 3, owner: 2_500_000, operator: 1_000_000, folded: 500_000 };
		assert_eq!(unfolded(&kept(0), &st), 0, "no note");
		assert_eq!(unfolded(&kept(400_000), &st), 0, "a note already folded");
		assert_eq!(unfolded(&kept(900_000), &st), 400_000, "within the cap");
		assert_eq!(unfolded(&kept(1_500_000), &st), 1_000_000, "at the cap: the operator's whole balance");
		assert_eq!(unfolded(&kept(9_000_000), &st), 1_000_000, "above the cap, as the claim pays it: the operator's balance, no more");
		assert_eq!(st.owner + unfolded(&kept(9_000_000), &st), st.owner + st.operator, "never beyond the leaf's value");
	}
}
