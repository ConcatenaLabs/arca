//! Paying an address on the chain from the wallet's leaves: a cooperative
//! offboard.
//!
//! A participation gives up leaves of one asset and wants one offboard output
//! of exactly the amount, paying the address's script, and a change leaf
//! where the coins hold more. The operator's round pays the offboard output,
//! hash-locked to the participation's unlock hash; `sync` hands over the
//! forfeits once the round is final, and the operator then unlocks the output
//! with the preimage into the address: its output 0 pays exactly the amount
//! there. Should the operator not unlock it within [`UNLOCK_GRACE_SECONDS`] of
//! the wallet holding the preimage, the wallet unlocks it itself, the margin
//! the output holds paying the fee where the node accepts the asset for fees.
//! A participation the operator drops, voids or lets expire gives the coins
//! back, and nothing is paid.
//!
//! The fee is in the asset moved, as a participation carries one asset: each
//! coin's refresh fee, the offboard's fee by the asset's schedule, and the
//! margin the offboard output holds for its unlock. Where an offboard stands
//! is read from the chain each time it is asked for ([`Wallet::offboards`]).

use std::str::FromStr;

use elements::hashes::{sha256, Hash};
use elements::{AssetId, OutPoint, Script, Txid};
use serde_json::{json, Value};

use arca_covenant::spend::FeeSource;
use arca_covenant::{ExplicitOutput, LeafId, MedianTime, OffboardPolicy, RelativeTime, Template};

use super::chain::{hex, unhex, unhex32};
use super::client::{key_proof_digest, participation_id, Wanted};
use super::order::UNLOCK_GRACE_SECONDS;
use super::pay::{In, Margins};
use super::round::{fee_within, refresh_fee, schedule_of, DEFAULT_MAX_FEE_PPM};
use super::take::offboard_fee;
use super::wallet::{sign, Wallet};
use super::{random32, Error};

/// The wallet's offboards, each `{offboard, asset, amount, script, at?,
/// unlock_after?}`, kept beside its participations.
const OFFBOARDS: &str = "offboards";

/// An offboard, planned: the coins given up, the fee, the margin it holds,
/// the change, and the amount paid out.
struct Plan {
	coins: Vec<In>,
	fee: u64,
	margin: u64,
	change: u64,
	amount: u64,
}

/// What an offboard pays out: an amount, from coins the wallet chooses; or
/// the whole of named coins, less the fee, with no change.
#[derive(Clone, Copy)]
pub enum OffboardOf<'a> {
	Amount(u64),
	Coins(&'a [String]),
}

/// The most an offboard of coins holding `total` can pay out, its refresh
/// fees `refresh` and its output's margin `margin` taken first, the
/// offboard's fee by `schedule` on what it pays: the largest amount whose
/// fee and amount the coins hold. The fee is then all the rest, which is the
/// schedule's fee or one atom more where the schedule's rounding leaves no
/// amount it meets exactly (the operator refuses a fee short of its
/// schedule, never one above it). `None` when the coins hold no more than
/// the fee.
pub(crate) fn whole_amount(schedule: &Value, total: u64, refresh: u64, margin: u64) -> Option<(u64, u64)> {
	let need = |a: u64| a.checked_add(refresh)?.checked_add(offboard_fee(schedule, a))?.checked_add(margin);
	let fixed = need(0)?;
	if total <= fixed {
		return None;
	}
	let ppm = schedule["offboard_ppm"].as_u64().unwrap_or(0) as u128;
	let mut a = (((total - fixed) as u128 * 1_000_000) / (1_000_000 + ppm)).min(u64::MAX as u128) as u64;
	while need(a.saturating_add(1)).is_some_and(|n| n <= total) {
		a += 1;
	}
	while a > 0 && need(a).map_or(true, |n| n > total) {
		a -= 1;
	}
	if a == 0 {
		return None;
	}
	Some((a, total - a))
}

fn parse_outpoint(s: &str) -> Result<OutPoint, Error> {
	let (t, v) = s.split_once(':').ok_or_else(|| Error::Store(format!("an outpoint {:?}", s)))?;
	Ok(OutPoint::new(Txid::from_str(t).map_err(|e| Error::Store(e.to_string()))?,
		v.parse().map_err(|_| Error::Store(format!("an outpoint {:?}", s)))?))
}

impl Wallet {
	/// The wallet's own leaf for the change of a participation that gives
	/// up coins of `asset` out of the tree (an offboard, an on-chain order,
	/// a resting order), with the entry the store keeps of it: for a
	/// supervised asset a landing leaf at the wallet's own landing, of the
	/// template the operator makes ([`Wallet::landing_rule`]), since the
	/// operator makes no other leaf of such an asset; `vtxo-1` otherwise.
	pub(crate) fn change_wanted(&self, info: &Value, asset: AssetId, value: u64, purpose: &str) -> Result<(Wanted, Value), Error> {
		let nonce = random32();
		let owner = self.keys.leaf_xonly(&nonce)?;
		self.store.put_nonce(&nonce, &owner.serialize(), purpose)?;
		let landing = self.landing_rule(info, asset)?;
		let template = landing.map_or(Template::Vtxo1, |l| l.template());
		let mut entry = json!({"nonce": hex(&nonce), "asset": asset.to_string(), "value": value.to_string()});
		if let Some(l) = &landing {
			entry["landing"] = arca_covenant::record_json::landing_json(l);
			if l.own_index {
				entry["template"] = json!(arca_covenant::LANDING_2);
			}
		}
		Ok((Wanted::Leaf { asset, value, template, owner, owner_nonce: nonce, exit_delay: self.exit_delay(), order: None, landing,
			channel: None }, entry))
	}

	/// The script an offboard pays: `address`, an unconfidential address of
	/// the chain the node follows, or `script`, hex. Refused: neither or both,
	/// a confidential address (the offboard pays an explicit output), and a
	/// script the wallet holds as an Arca script (the operator refuses it too).
	pub fn offboard_script(&self, address: Option<&str>, script: Option<&str>) -> Result<Script, Error> {
		let spk = match (address, script) {
			(Some(a), None) => {
				if self.chain.is_confidential(a)? {
					return Err(Error::Refused(format!("{} is a confidential address: an offboard pays an explicit output, so name the \
						address's unconfidential form", a)));
				}
				self.chain.script_of(a)?
			},
			(None, Some(s)) => Script::from(unhex(s)?),
			_ => return Err(Error::Parse("an offboard pays an address or a script: name one of them".into())),
		};
		if spk.is_empty() || spk.len() > 10_000 {
			return Err(Error::Refused(format!("a script of {} bytes: an offboard pays 1 to 10,000", spk.len())));
		}
		Ok(spk)
	}

	/// What paying `amount` of `asset` to `script` on the chain would cost,
	/// before anything is signed, written or asked of the operator but its
	/// published fees: the coins given up, the fee (each coin's refresh fee,
	/// the offboard's fee by the asset's schedule, and the margin the output
	/// holds for its unlock) and the change. Refuses what [`Self::offboard`]
	/// refuses for the same reason.
	pub fn offboard_quote(&mut self, asset: AssetId, amount: u64, script: &Script, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		self.offboard_quote_of(asset, OffboardOf::Amount(amount), script, max_fee_ppm)
	}

	/// [`Self::offboard_quote`] of an amount, or of the whole of named
	/// coins ([`OffboardOf::Coins`]): each must be a live coin of `asset`
	/// the wallet can give up now, else the refusal names it (a coin that a
	/// round must refresh first is [`Error::SettleFirst`], naming it).
	pub fn offboard_quote_of(&mut self, asset: AssetId, of: OffboardOf<'_>, script: &Script, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		let _quote = self.quoting();
		let info = self.server_info()?;
		let q = self.offboard_plan(&info, asset, of, script, max_fee_ppm).map(|(q, _)| q);
		self.quoted(q)
	}

	/// What moving the whole of a coin of `value` of `asset`, with exit
	/// date `expiry`, to `script` would pay out and cost, before the wallet
	/// holds it (a coin a trade is about to bring): the same fee
	/// [`OffboardOf::Coins`] takes of such a coin, from the operator's
	/// published fees, and, when such a coin would arrive past the wallet's
	/// instant limit, the refresh of the round it goes through first
	/// (`fee.settle`, counted in `fee.amount`). `max_fee_ppm` bounds the
	/// settle and the move each on its own, as each is bounded when it is
	/// made, not their sum. Nothing is chosen, signed or asked.
	pub fn offboard_whole_quote(&self, asset: AssetId, value: u64, expiry: u32, script: &Script, max_fee_ppm: Option<u64>)
		-> Result<Value, Error>
	{
		let info = self.server_info()?;
		let schedule = schedule_of(&info, asset);
		let margin = self.offboard_margin(&info, asset, script)?;
		let now = self.now()?.to_consensus_u32();
		// A coin that would arrive past the wallet's instant limit goes
		// through a round of its own first (`settle_first`), which takes a
		// refresh fee of it, and the move then gives up the coin that round
		// made, of the same exit date.
		let settle = if self.would_arrive(asset, value)? { refresh_fee(&schedule, value, expiry, now) } else { 0 };
		let held = value.checked_sub(settle).filter(|v| *v > 0).ok_or_else(|| Error::Refused(format!("a coin of {} of asset {} holds no \
			more than the fee of the round it must go through first ({})", value, asset, settle)))?;
		let refresh = refresh_fee(&schedule, held, expiry, now);
		let (amount, fee) = whole_amount(&schedule, held, refresh, margin).ok_or_else(|| Error::Refused(format!("a coin of {} of asset {} \
			holds no more than the fee of moving it on the chain (settle {}, refresh {}, offboard {}, unlock margin {})", value, asset, settle,
			refresh, offboard_fee(&schedule, 0), margin)))?;
		// Each of the two is held to the wallet's bound on its own, as each
		// is when it is made: the settle of the coin's value, the move of
		// what it pays.
		let bound = max_fee_ppm.unwrap_or(DEFAULT_MAX_FEE_PPM);
		if !fee_within(settle, value, bound) || !fee_within(fee, amount, bound) {
			return Err(Error::Refused(format!("moving a coin of {} of asset {} on the chain costs {} (settle {}), above the wallet's bound \
				of {} ppm (raise it with max_fee_ppm)", value, asset, fee.saturating_add(settle), settle, bound)));
		}
		let fee = fee.saturating_add(settle);
		Self::at_least_min(&info, asset, amount, fee)?;
		Ok(json!({"asset": asset.to_string(), "value": value.to_string(), "expiry": expiry, "amount": amount.to_string(),
			"script": hex(script.as_bytes()), "address": self.chain.address(script)?,
			"fee": {"asset": asset.to_string(), "amount": fee.to_string(), "settle": settle.to_string(), "refresh": refresh.to_string(),
				"offboard": offboard_fee(&schedule, amount).to_string(), "unlock_margin": margin.to_string()},
			"change": "0"}))
	}

	/// Whether a coin of `value` of `asset` the wallet receives now would
	/// arrive past its instant limit ([`super::places`]): then it pays out
	/// of the tree only once a round has refreshed it. False while the
	/// wallet sets no limit; true for an asset the node gives no rate for.
	fn would_arrive(&self, asset: AssetId, value: u64) -> Result<bool, Error> {
		let places = self.places()?;
		let Some(limit) = places.limit else { return Ok(false) };
		// Once a received coin is arriving, every coin received after it
		// arrives too, whatever room the limit has ([`Self::places`]).
		if places.coins.iter().any(|(_, l, p)| *l == super::places::Lineage::Received && *p == super::places::Place::Arriving) {
			return Ok(true);
		}
		let rates = self.chain.fee_rates()?;
		Ok(match rates.get(&asset) {
			None => true,
			Some(r) => places.counted.saturating_add(value as u128 * *r as u128 / 100_000_000) > limit.value,
		})
	}

	/// Refuses a whole move that would pay out less than the operator's
	/// smallest output of `asset`, which it would refuse in the round,
	/// naming the smallest amount that goes and the coin it takes.
	fn at_least_min(info: &Value, asset: AssetId, amount: u64, fee: u64) -> Result<(), Error> {
		let min = Self::min_leaf(info, asset)?;
		if amount < min {
			return Err(Error::Refused(format!("moving it on the chain would pay {} of asset {} after a fee of {}, below the operator's \
				smallest output of {}: a move pays at least {}, from a coin of at least {}", amount, asset, fee, min, min,
				min.saturating_add(fee))));
		}
		Ok(())
	}

	/// The coin the wallet holds now in place of `id`: `id` itself, or, when
	/// a refresh of the wallet's own gave `id` up alone and is released, the
	/// coin that refresh made, followed through each such refresh. A refresh
	/// is a participation that gave up that one coin and wants one plain leaf
	/// of the wallet's own and nothing else (no order, channel or offboard):
	/// a payment, an order or a take that made change is not one, and its
	/// change is never named for the coin it spent. A coin settled first
	/// (`settle_first`) is so named by its old id. `None` when the wallet
	/// holds neither; a refresh that gave up other coins with it made a coin
	/// that is not `id`'s alone, and is refused, named.
	fn successor(&self, id: &str) -> Result<Option<String>, Error> {
		let mut at = id.to_string();
		for _ in 0..8 {
			let Some(c) = self.store.coin(&at)? else { return Ok(None) };
			if c.state != "spent" {
				return Ok(Some(at));
			}
			let Some(pid) = c.spent_by.as_deref().and_then(|s| s.strip_prefix("participation ")) else { return Ok(Some(at)) };
			let Some((_, body, given, wanted, state, _, _)) = self.store.participation(pid)? else { return Ok(Some(at)) };
			if state != "released" {
				return Ok(Some(at));
			}
			// A refresh, and nothing else: one output, a plain leaf.
			let body: Value = serde_json::from_str(&body).map_err(|e| Error::Store(e.to_string()))?;
			let outs = body["outputs"].as_array().cloned().unwrap_or_default();
			let plain = outs.len() == 1 && outs[0]["leaf"].is_object() && outs[0]["leaf"]["order"].is_null()
				&& outs[0]["leaf"]["channel"].is_null() && outs[0]["leaf"]["asset"].as_str() == Some(c.asset.as_str());
			if !plain {
				return Ok(Some(at));
			}
			let given: Vec<String> = serde_json::from_str(&given).map_err(|e| Error::Store(e.to_string()))?;
			if given != [at.clone()] {
				return Err(Error::Refused(format!("coin {} was refreshed together with {} other coins: the coin that round made is not \
					its alone, so it cannot be named for it", id, given.len().saturating_sub(1))));
			}
			let wanted: Value = serde_json::from_str(&wanted).map_err(|e| Error::Store(e.to_string()))?;
			let mut made = vec![];
			for w in wanted.as_array().cloned().unwrap_or_default() {
				if w["asset"].as_str() != Some(c.asset.as_str()) {
					continue;
				}
				if let Some(n) = w["nonce"].as_str().and_then(|n| super::chain::unhex32(n).ok()) {
					if let Some(l) = self.store.nonce(&n)?.and_then(|r| r.leaf_id) {
						made.push(l);
					}
				}
			}
			match made.as_slice() {
				[one] => at = one.clone(),
				_ => return Ok(Some(at)),
			}
		}
		Ok(Some(at))
	}

	/// The margin an offboard output to `script` holds for its unlock, from
	/// the operator's floor in `asset` (it does not depend on the amount: an
	/// explicit value is of one size).
	fn offboard_margin(&self, info: &Value, asset: AssetId, script: &Script) -> Result<u64, Error> {
		let m = Margins::of(info, asset)?;
		let probe = OffboardPolicy { unlock_hash: [0; 32], destination: ExplicitOutput::new(asset, 1, script.clone()),
			operator: self.operator, reclaim_delay: RelativeTime::from_units(1).map_err(|e| Error::Refused(e.to_string()))? };
		Ok(probe.unlock_margin(m.floor, m.multiple))
	}

	/// The named coins of `asset`, each a live coin the wallet can give up
	/// now, with their refresh fees. A named coin a round must refresh first
	/// (arriving, not final yet, at the depth limit) is
	/// [`Error::SettleFirst`] naming it; any other is refused, named.
	fn named_coins(&self, info: &Value, asset: AssetId, ids: &[String], schedule: &Value, now: u32) -> Result<(Vec<In>, u64), Error> {
		if ids.is_empty() {
			return Err(Error::Refused("an offboard of named coins names none".into()));
		}
		if ids.len() > super::round::MAX_GIVEN {
			return Err(Error::Refused(format!("an offboard gives up at most {} coins: {} are named", super::round::MAX_GIVEN, ids.len())));
		}
		let mut seen = std::collections::BTreeSet::new();
		if !ids.iter().all(|i| seen.insert(i)) {
			return Err(Error::Refused("an offboard names one coin twice".into()));
		}
		let mut can = self.coins_to_give(asset, super::places::Spend::Pay)?;
		let mut chosen = vec![];
		let mut first = vec![];
		let mut refresh = 0u64;
		for named in ids {
			// A coin settled first is named by its old id: the coin its
			// refresh made goes in its place.
			let id = &self.successor(named)?.unwrap_or_else(|| named.clone());
			if let Some(k) = can.iter().position(|c| &c.row.leaf_id == id) {
				let c = can.swap_remove(k);
				let (record, held) = self.held(&c.row)?;
				let expiry = self.service_expiry(&record, &held)?;
				refresh = refresh.saturating_add(refresh_fee(schedule, c.coin.value, expiry, now));
				chosen.push(c);
				continue;
			}
			let later = self.round_first(info, asset, super::places::Spend::Pay, None, super::pay::Reads::ALL)?;
			if let Some(h) = later.into_iter().find(|(l, ..)| l == id) {
				first.push(h);
				continue;
			}
			return Err(Error::Refused(format!("coin {} is not a live coin of asset {} the wallet can give up now", named, asset)));
		}
		if !first.is_empty() {
			let more: u64 = first.iter().map(|(_, v, _)| *v).sum();
			let live: u64 = chosen.iter().map(|c| c.coin.value).sum();
			if let Some(e) = self.settle_first_of(asset, live, live.saturating_add(more), first) {
				return Err(e);
			}
		}
		Ok((chosen, refresh))
	}

	fn offboard_plan(&self, info: &Value, asset: AssetId, of: OffboardOf<'_>, script: &Script, max_fee_ppm: Option<u64>)
		-> Result<(Value, Plan), Error>
	{
		let schedule = schedule_of(info, asset);
		let now = self.now()?.to_consensus_u32();
		let amount = match of {
			OffboardOf::Amount(a) => a,
			OffboardOf::Coins(ids) => {
				// The whole of the named coins, less the fee: no change, and
				// no other coin of the wallet's touched.
				let margin = self.offboard_margin(info, asset, script)?;
				let (chosen, refresh) = self.named_coins(info, asset, ids, &schedule, now)?;
				let total: u64 = chosen.iter().map(|c| c.coin.value).sum();
				let (amount, fee) = whole_amount(&schedule, total, refresh, margin).ok_or_else(|| Error::Refused(format!("the named coins \
					of asset {} hold {}, no more than the fee of moving them on the chain (refresh {}, offboard {}, unlock margin {})", asset,
					total, refresh, offboard_fee(&schedule, 0), margin)))?;
				Self::at_least_min(info, asset, amount, fee)?;
				let bound = max_fee_ppm.unwrap_or(DEFAULT_MAX_FEE_PPM);
				if !fee_within(fee, amount, bound) {
					return Err(Error::Refused(format!("paying {} of asset {} on the chain costs {}, above the wallet's bound of {} ppm of the \
						amount (raise it with max_fee_ppm)", amount, asset, fee, bound)));
				}
				let q = json!({
					"asset": asset.to_string(), "amount": amount.to_string(), "script": hex(script.as_bytes()),
					"address": self.chain.address(script)?,
					"fee": {"asset": asset.to_string(), "amount": fee.to_string(), "refresh": refresh.to_string(),
						"offboard": offboard_fee(&schedule, amount).to_string(), "unlock_margin": margin.to_string()},
					"gives": chosen.iter().map(|c| c.row.leaf_id.clone()).collect::<Vec<_>>(),
					"change": "0",
				});
				return Ok((q, Plan { coins: chosen, fee, margin, change: 0, amount }));
			},
		};
		if amount == 0 {
			return Err(Error::Refused("an offboard of nothing".into()));
		}
		let min = Self::min_leaf(info, asset)?;
		let margin = self.offboard_margin(info, asset, script)?;
		let offboard = offboard_fee(&schedule, amount).saturating_add(margin);
		// The coins, furthest from their exit date first and the largest
		// first among one date, until they hold the amount and the fee, with
		// no change or change of at least the operator's smallest leaf.
		// A coin given up in a refresh that waits is taken back first when
		// the live coins fall short.
		self.free_when_short(asset, amount.saturating_add(offboard))?;
		let mut chosen: Vec<In> = vec![];
		let (mut total, mut refresh) = (0u64, 0u64);
		let mut done = None;
		for c in self.coins_to_give(asset, super::places::Spend::Pay)? {
			if chosen.len() == super::round::MAX_GIVEN {
				return Err(Self::too_many_coins(asset, total, amount.saturating_add(refresh).saturating_add(offboard)));
			}
			let (record, held) = self.held(&c.row)?;
			let expiry = self.service_expiry(&record, &held)?;
			refresh = refresh.saturating_add(refresh_fee(&schedule, c.coin.value, expiry, now));
			total = total.saturating_add(c.coin.value);
			chosen.push(c);
			let fee = refresh.saturating_add(offboard);
			if let Some(change) = total.checked_sub(amount.saturating_add(fee)).filter(|c| *c == 0 || *c >= min) {
				done = Some((fee, change));
				break;
			}
		}
		let Some((fee, change)) = done else {
			let need = amount.saturating_add(refresh).saturating_add(offboard);
			// Coins the wallet holds as its own that a participation gives up
			// only once a round has made them final or settled them (arriving
			// past the instant limit, not final yet): said so, naming them, so
			// a program settles them and asks again. The depth limit bars no
			// coin here, a round giving every coin up whatever its depth.
			let held = self.round_first(info, asset, super::places::Spend::Pay, None, super::pay::Reads::ALL)?;
			if let Some(e) = self.settle_first_of(asset, total, need, held) {
				return Err(e);
			}
			return Err(self.short_of(asset, need.saturating_sub(total).max(1), format!("the wallet's live coins of asset {} hold {} and \
				an offboard of {} and its fee need {} (refresh {}, offboard {}), with any change at least the operator's smallest leaf \
				of {}: board or receive more, or pay less", asset, total, amount, need, refresh, offboard, min))?);
		};
		let bound = max_fee_ppm.unwrap_or(DEFAULT_MAX_FEE_PPM);
		if !fee_within(fee, amount, bound) {
			return Err(Error::Refused(format!("paying {} of asset {} on the chain costs {}, above the wallet's bound of {} ppm of the \
				amount (raise it with max_fee_ppm)", amount, asset, fee, bound)));
		}
		let q = json!({
			"asset": asset.to_string(), "amount": amount.to_string(), "script": hex(script.as_bytes()),
			"address": self.chain.address(script)?,
			"fee": {"asset": asset.to_string(), "amount": fee.to_string(), "refresh": refresh.to_string(),
				"offboard": offboard_fee(&schedule, amount).to_string(), "unlock_margin": margin.to_string()},
			"gives": chosen.iter().map(|c| c.row.leaf_id.clone()).collect::<Vec<_>>(),
			"change": change.to_string(),
		});
		Ok((q, Plan { coins: chosen, fee, margin, change, amount }))
	}

	/// Pays `amount` of `asset` to `script` on the chain through the next
	/// round (see the [module documentation](self)). The fee is in `asset`; a
	/// `fee_asset` other than it is refused, a participation carrying one
	/// asset. With `shown`, it goes ahead only on the fee and the coins the
	/// program showed (an [`Self::offboard_quote`]'s `fee` and `gives`).
	/// Answers the offboard, named by its participation; `sync` completes it,
	/// and [`Self::offboards`] says where it stands.
	pub fn offboard(&mut self, asset: AssetId, amount: u64, script: &Script, fee_asset: Option<AssetId>, max_fee_ppm: Option<u64>,
		shown: Option<&Value>) -> Result<Value, Error>
	{
		self.offboard_of(asset, OffboardOf::Amount(amount), script, fee_asset, max_fee_ppm, shown)
	}

	/// [`Self::offboard`] of an amount, or of the whole of named coins
	/// ([`OffboardOf::Coins`]): those coins alone are given up, the amount
	/// paid is what they hold less the fee, and there is no change.
	pub fn offboard_of(&mut self, asset: AssetId, of: OffboardOf<'_>, script: &Script, fee_asset: Option<AssetId>,
		max_fee_ppm: Option<u64>, shown: Option<&Value>) -> Result<Value, Error>
	{
		if let Some(f) = fee_asset.filter(|f| *f != asset) {
			return Err(Error::Refused(format!("an offboard's fee is paid in the asset it moves, {}, as the round that pays it carries that \
				one asset: asset {} cannot pay it", asset, f)));
		}
		self.witnessed_now()?;
		let info = self.server_info()?;
		// The same offboard asked again (same asset, amount and address)
		// while the first is still the wallet's to finish: it goes on.
		let list: Vec<Value> = self.store.meta(OFFBOARDS)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		// Of named coins, the same is one that gives up those coins (each as
		// the wallet holds it now: [`Self::successor`]).
		let named_now: Vec<String> = match of {
			OffboardOf::Coins(ids) => ids.iter().map(|i| self.successor(i).map(|s| s.unwrap_or_else(|| i.clone()))).collect::<Result<_, _>>()?,
			OffboardOf::Amount(_) => vec![],
		};
		for e in list.iter().rev() {
			let pid = e["offboard"].as_str().unwrap_or("");
			let same = e["asset"] == json!(asset.to_string()) && e["script"] == json!(hex(script.as_bytes())) && e["at"].is_null()
				&& match of {
					OffboardOf::Amount(amount) => e["amount"] == json!(amount.to_string()),
					OffboardOf::Coins(_) => self.store.participation(pid)?.and_then(|p| serde_json::from_str::<Vec<String>>(&p.2).ok())
						.is_some_and(|mut g| { let mut n = named_now.clone(); g.sort(); n.sort(); g == n }),
				};
			let open = self.store.participation_state(pid)?.is_some_and(|s| matches!(s.as_str(), "submitting" | "pending" | "issued" | "forfeiting"));
			if same && open {
				if let Some(v) = self.offboard_under_way(pid)? {
					return Ok(v);
				}
			}
		}
		let (quote, plan) = self.offboard_plan(&info, asset, of, script, max_fee_ppm)?;
		let amount = plan.amount;
		if let Some(s) = shown {
			for k in ["fee", "gives"] {
				if s[k] != quote[k] {
					return Err(Error::Refused(format!("the offboard's {} changed since it was shown: it is now {}", k, quote[k])));
				}
			}
		}
		let mut wanted = vec![Wanted::Offboard { asset, value: amount, script: script.clone() }];
		let mut wanted_json = vec![json!({"offboard": {"asset": asset.to_string(), "value": amount.to_string(),
			"script": hex(script.as_bytes()), "margin": plan.margin.to_string()}})];
		if plan.change > 0 {
			let (w, entry) = self.change_wanted(&info, asset, plan.change, "offboard change")?;
			wanted.push(w);
			wanted_json.push(entry);
		}
		let fees = vec![(asset, plan.fee)];
		let ids: Vec<LeafId> = plan.coins.iter().map(|c| c.coin.id).collect();
		let given: Vec<String> = plan.coins.iter().map(|c| c.row.leaf_id.clone()).collect();
		// The same coins, address and amount make the same participation as
		// an earlier offboard. One the operator still holds is that offboard,
		// under way: it goes on, its coins given up again. One the operator
		// does not hold (refused, void, never received) is over: this one is
		// made apart from it by a date it may run from, now.
		let mut not_before = None;
		loop {
			let id = participation_id(&self.genesis, &self.operator, &ids, &wanted, &fees, not_before);
			let pid = hex(&id);
			if self.store.participation_state(&pid)?.is_none() {
				break;
			}
			if not_before.is_none() {
				if let Some(v) = self.offboard_under_way(&pid)? {
					return Ok(v);
				}
			}
			let t = not_before.map_or(self.now()?.to_consensus_u32(), |t: MedianTime| t.to_consensus_u32() + 1);
			not_before = Some(MedianTime::from_consensus(t).map_err(|e| Error::Refused(e.to_string()))?);
		}
		let id = participation_id(&self.genesis, &self.operator, &ids, &wanted, &fees, not_before);
		let mut inputs = vec![];
		for c in &plan.coins {
			let k = self.coin_key(&c.row.owner_nonce)?;
			inputs.push(json!({"leaf_id": c.row.leaf_id, "attestation": hex(sign(&k, &id).as_ref())}));
		}
		let mut outputs = vec![];
		for w in &wanted {
			let mut j = w.json();
			if let Wanted::Leaf { owner_nonce, .. } = w {
				let k = self.keys.leaf(owner_nonce)?;
				j["leaf"]["key_proof"] = json!(hex(sign(&k, &key_proof_digest(&id)).as_ref()));
				let (mailbox, proof) = self.binding(&k)?;
				j["leaf"]["mailbox"] = json!(mailbox);
				j["leaf"]["mailbox_proof"] = json!(proof);
			}
			outputs.push(j);
		}
		let mut body = json!({"inputs": inputs, "outputs": outputs,
			"fees": fees.iter().map(|(a, v)| json!({"asset": a.to_string(), "amount": v.to_string()})).collect::<Vec<_>>()});
		if let Some(t) = not_before {
			body["not_before"] = json!(t.to_consensus_u32());
		}
		let pid = hex(&id);
		let entry = json!({"offboard": pid, "asset": asset.to_string(), "amount": amount.to_string(), "script": hex(script.as_bytes())});
		self.store.atomically(|s| {
			s.put_participation(&pid, &body.to_string(), &serde_json::to_string(&given).expect("strings"),
				&Value::Array(wanted_json.clone()).to_string())?;
			for l in &given {
				s.set_coin_state(l, "given", &format!("offboard {}", pid))?;
			}
			let mut list: Vec<Value> = s.meta(OFFBOARDS)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
			list.push(entry.clone());
			s.set_meta(OFFBOARDS, &Value::Array(list).to_string())
		})?;
		let answer = self.submit_participation_body(&pid, &body, &given)?;
		// When the round that pays it is due: within the operator's interval
		// between rounds while participations wait, when it publishes one.
		let within = info["fills"]["round_interval_seconds"].as_u64().filter(|s| *s > 0);
		Ok(json!({"offboard": pid, "state": answer["state"], "asset": asset.to_string(), "amount": amount.to_string(),
			"address": quote["address"], "script": quote["script"], "fee": quote["fee"], "gives": given,
			"change": plan.change.to_string(), "round_within_seconds": within,
			"note": self.spelling.say("asked: once the operator's round pays the offboard and is final, {sync} hands over the forfeits; \
				the operator then pays the address on the chain. {offboards} says where it stands")}))
	}

	/// The offboard the wallet recorded as participation `pid`, gone on with
	/// when the operator holds it or takes it now: one the operator never
	/// answered is posted again as it stands (the operator takes a
	/// participation it holds already as that one, answering where it
	/// stands); another is asked after. Its coins are given up to it again
	/// and the wallet's record follows the operator's, and it is answered as
	/// under way. `None` when the operator neither holds nor takes it: it is
	/// over, its coins the wallet's.
	fn offboard_under_way(&mut self, pid: &str) -> Result<Option<Value>, Error> {
		let Some((_, body, given, _, state, _, _)) = self.store.participation(pid)? else { return Ok(None) };
		let given: Vec<String> = serde_json::from_str(&given).map_err(|e| Error::Store(e.to_string()))?;
		let st = if state == "submitting" {
			let body: Value = serde_json::from_str(&body).map_err(|e| Error::Store(e.to_string()))?;
			match self.submit_participation_body(pid, &body, &given) {
				Ok(a) => a,
				// Refused: its coins are the wallet's again.
				Err(Error::Server { .. }) => return Ok(None),
				Err(e) => return Err(e),
			}
		} else {
			match self.server.post("participation_status", &json!({"participation_id": pid})) {
				Ok(st) => st,
				Err(Error::Server { code, .. }) if code == "unknown_participation" => return Ok(None),
				Err(e) => return Err(e),
			}
		};
		let now = st["state"].as_str().unwrap_or("").to_string();
		if !matches!(now.as_str(), "pending" | "issued" | "forfeiting" | "released") {
			return Ok(None);
		}
		let local = match now.as_str() {
			// The wallet hands over its forfeits and takes the release on
			// its next sync, from the record of an issued participation.
			"forfeiting" | "released" => "issued",
			s => s,
		};
		self.store.atomically(|s| {
			s.set_participation(pid, local, None, None)?;
			for l in &given {
				s.set_coin_state(l, "given", &format!("offboard {}", pid))?;
			}
			Ok(())
		})?;
		let list: Vec<Value> = self.store.meta(OFFBOARDS)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		let e = list.iter().find(|e| e["offboard"] == json!(pid)).cloned().unwrap_or(Value::Null);
		Ok(Some(json!({"offboard": pid, "state": now, "asset": e["asset"], "amount": e["amount"], "script": e["script"],
			"gives": given, "already": true,
			"note": self.spelling.say("this payment is already under way: the operator holds it, and {sync} completes it. \
				{offboards} says where it stands")})))
	}

	/// Moves each offboard on as far as `sync` takes it: once its
	/// participation is released, the round's offboard output is recorded;
	/// once the wallet has held the preimage for [`UNLOCK_GRACE_SECONDS`] and
	/// the operator has not unlocked the output, the wallet unlocks it
	/// itself, its margin paying the fee where the node accepts the asset.
	pub(crate) fn progress_offboards(&mut self) -> Result<Vec<Value>, Error> {
		let mut list: Vec<Value> = self.store.meta(OFFBOARDS)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		if list.is_empty() {
			return Ok(vec![]);
		}
		let now = self.now()?.to_consensus_u32();
		let mut out = vec![];
		let mut changed = false;
		for e in list.iter_mut() {
			let id = e["offboard"].as_str().unwrap_or("").to_string();
			let Some((_, _, _, _, state, preimage, _)) = self.store.participation(&id)? else { continue };
			let Some(at) = e["at"].as_str().map(str::to_string) else {
				if state == "released" {
					let news: Value = serde_json::from_str(&self.store.participation_news(&id)?.unwrap_or_default())
						.map_err(|e| Error::Store(e.to_string()))?;
					let off = &news["offboards"][0];
					if let (Some(round), Some(vout)) = (news["round"].as_str(), off["vout"].as_u64()) {
						e["at"] = json!(format!("{}:{}", round, vout));
						e["reclaim_units"] = off["reclaim_units"].clone();
						e["unlock_after"] = json!(now.saturating_add(UNLOCK_GRACE_SECONDS));
						changed = true;
						out.push(json!({"offboard": id, "state": "unlocking", "output": e["at"]}));
					}
				}
				continue;
			};
			let off = parse_outpoint(&at)?;
			if !self.chain.unspent(&off)? || e["unlock_after"].as_u64().is_some_and(|t| (now as u64) < t) {
				continue;
			}
			// The operator has not unlocked it: the wallet does, with the
			// preimage it holds.
			let Some(pre) = preimage.as_deref() else { continue };
			match self.unlock_offboard(e, &off, &unhex32(pre)?) {
				Ok(txid) => out.push(json!({"offboard": id, "unlocked": txid.to_string(),
					"note": "the operator had not unlocked the offboard: the wallet did, with the preimage it holds"})),
				Err(err) => out.push(json!({"offboard": id, "unlock": err.to_string()})),
			}
		}
		if changed {
			self.store.set_meta(OFFBOARDS, &Value::Array(list).to_string())?;
		}
		Ok(out)
	}

	/// The unlock of offboard `e`'s output at `off` into its address, its
	/// margin the fee: where the node does not take the asset for fees the
	/// operator's watcher, which attaches a coin, unlocks it.
	fn unlock_offboard(&self, e: &Value, off: &OutPoint, preimage: &[u8; 32]) -> Result<Txid, Error> {
		let asset = AssetId::from_str(e["asset"].as_str().unwrap_or("")).map_err(|err| Error::Store(err.to_string()))?;
		let amount: u64 = e["amount"].as_str().unwrap_or("").parse().map_err(|_| Error::Store("an offboard's amount".into()))?;
		let script = Script::from(unhex(e["script"].as_str().unwrap_or(""))?);
		let tx = self.chain.transaction(&off.txid)?.ok_or_else(|| Error::Node(format!("the node does not have round {}", off.txid)))?;
		let held = tx.output.get(off.vout as usize).and_then(|o| o.value.explicit())
			.ok_or_else(|| Error::Refused(format!("round {} has no explicit output {}", off.txid, off.vout)))?;
		let policy = OffboardPolicy {
			unlock_hash: sha256::Hash::hash(preimage).to_byte_array(),
			destination: ExplicitOutput::new(asset, amount, script), operator: self.operator,
			reclaim_delay: RelativeTime::from_units(e["reclaim_units"].as_u64().unwrap_or(0) as u16)
				.map_err(|err| Error::Refused(err.to_string()))?,
		};
		if self.chain.floor_per_kvb(asset)?.is_none() {
			return Err(Error::Refused(format!("the node does not take asset {} for fees now: the operator's watcher unlocks the \
				offboard, attaching a coin of its own", asset)));
		}
		let u = policy.unlock_tx(*off, held, preimage, &FeeSource::Reserve).map_err(|err| Error::Refused(err.to_string()))?;
		self.chain.broadcast(&u.tx)
	}

	/// Every offboard the wallet asked for, and where it stands, read from
	/// the chain: `waiting` for the operator's round, `in_round` until `sync`
	/// hands over its forfeits, `unlocking` until the round's output is paid
	/// to the address, `paid` (the unlock's txid and whether it is final),
	/// `reclaimed` (the operator took the output back after its delay), or
	/// `not_made` (the participation ended without a round: the coins are the
	/// wallet's again).
	pub fn offboards(&self) -> Result<Value, Error> {
		let list: Vec<Value> = self.store.meta(OFFBOARDS)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		let mut out = vec![];
		for e in &list {
			let id = e["offboard"].as_str().unwrap_or("");
			let state = self.store.participation_state(id)?.unwrap_or_else(|| "unknown".into());
			let script = Script::from(unhex(e["script"].as_str().unwrap_or(""))?);
			let mut v = json!({"offboard": id, "asset": e["asset"], "amount": e["amount"], "address": self.chain.address(&script)?,
				"script": e["script"]});
			match e["at"].as_str() {
				None => {
					v["state"] = json!(match state.as_str() {
						"submitting" | "pending" => "waiting",
						"issued" | "forfeiting" => "in_round",
						"released" => "unlocking",
						_ => "not_made",
					});
				},
				Some(at) => {
					let off = parse_outpoint(at)?;
					v["output"] = json!(at);
					let from = self.chain.finality(&off.txid)?.height().unwrap_or(0).saturating_sub(1);
					match self.chain.spender(&off, from)? {
						None => v["state"] = json!("unlocking"),
						Some((tx, _)) => {
							let i = tx.input.iter().position(|x| x.previous_output == off).unwrap_or(0);
							let paid = tx.output.get(i).and_then(ExplicitOutput::from_txout)
								.is_some_and(|o| o.script_pubkey == script && Some(o.value) == e["amount"].as_str().and_then(|a| a.parse().ok()));
							v["state"] = json!(if paid { "paid" } else { "reclaimed" });
							v["txid"] = json!(tx.txid().to_string());
							// The unlock pays the address at the input's own index.
							if paid {
								v["vout"] = json!(i);
							}
							v["final"] = json!(self.chain.finality(&tx.txid())?.is_final());
						},
					}
				},
			}
			out.push(v);
		}
		Ok(Value::Array(out))
	}
}

#[cfg(test)]
mod test {
	use super::*;

	/// The amount of a whole move: the fee is the schedule's, or one atom
	/// more where its rounding meets no amount exactly; never less.
	#[test]
	fn a_whole_move_pays_all_but_a_fee_never_short_of_the_schedule() {
		for (ppm, base) in [(0u64, "0"), (1_000, "0"), (1_000, "100"), (3_333, "7"), (999_999, "1")] {
			let s = json!({"offboard_ppm": ppm, "offboard_base": base});
			for total in [1u64, 50, 101, 1_000, 1_001, 1_002, 299_999, 300_000, 600_000, 1_234_567, u64::MAX / 4] {
				for (refresh, margin) in [(0u64, 0u64), (25, 60), (3_000, 61)] {
					match whole_amount(&s, total, refresh, margin) {
						None => assert!(total <= refresh + offboard_fee(&s, 1) + margin, "{} {} {} {}", ppm, total, refresh, margin),
						Some((a, fee)) => {
							assert_eq!(a + fee, total);
							let due = refresh + offboard_fee(&s, a) + margin;
							assert!(fee >= due && fee <= due + 1, "ppm {} total {}: fee {} due {}", ppm, total, fee, due);
							// The largest such amount.
							assert!(a + 1 + refresh + offboard_fee(&s, a + 1) + margin > total);
						},
					}
				}
			}
		}
	}
}
