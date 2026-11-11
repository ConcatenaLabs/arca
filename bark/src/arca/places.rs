//! Where each coin of the wallet stands, and the instant limit.
//!
//! A coin's **lineage** is read from its record, back to the rounds and
//! boards it rests on ([`Wallet::lineage`]):
//!
//! - `own`: every reassignment in it spends only the wallet's own coins: a
//!   round's or a board's coin, and the wallet's own change from paying out
//!   of one. Only the wallet's key spends it.
//! - `trade`: a reassignment in it is a trade the wallet took part in (a
//!   swap or an in-tree fill: an input of the wallet's own beside one of
//!   another's) in which every checkpoint has its owner's exit
//!   ([`arca_covenant::checkpoint`]), and nothing in it below the wallet's
//!   own inputs was received. If the trade dies, the coin the wallet gave
//!   comes home by that exit; what the trade paid it is void, and so is
//!   every coin made from it, so a chain of such trades unwinds with every
//!   honest party's coin home.
//! - `received`: anything else: a reassignment in it pays the wallet coins
//!   that are only someone else's (a payment received), or is a trade in
//!   which some checkpoint has no owner's exit. Its sender, with the
//!   operator, could void it until a round refreshes it.
//!
//! A wallet may set an **instant limit** ([`Wallet::set_instant_limit`]): in
//! atoms of the reference unit, at its own node's rates, the most it holds of
//! `received` coins and still counts as its own. The limit taken is the lower
//! of the wallet's own figure and what its operator suggests
//! (`info.bond.instant_limit_value`, and `info.bond.instant_budget_ppm` of
//! the bond's value); while the operator's bond does not stand, it is zero,
//! since nothing then deters a sender and the operator from voiding what was
//! paid. With a limit set, each coin has one **place**:
//!
//! - `settled`: of `own` lineage;
//! - `proceeds`: of `trade` lineage;
//! - `counted`: `received`, inside the limit;
//! - `arriving`: `received`, past the limit, or not valued by the node;
//!   and any coin not final yet (`pending`: its round, or a block it rests
//!   on, not certified with its anchor buried, as after an anchor
//!   rollback), and any coin on its way home on the chain (`exiting`),
//!   whatever its lineage.
//!
//! Received coins are counted oldest first (by the signer's record entry of
//! the transfer that made them, then by when the wallet stored them), until
//! the next would pass the limit; that one and every later one are arriving.
//! Once counted a coin stays counted while the wallet holds it, so a rise in
//! prices never moves a coin back from counted to arriving. A coin that
//! arrives is refreshed at the next round ([`Wallet::refresh_needed`]), and
//! is then `settled`.
//!
//! With a limit set, the wallet spends no `arriving` coin but in a refresh,
//! and no `proceeds` coin in a payment that leaves the Arca (a payment on
//! the chain, over Lightning, the Bitcoin side of a cross-chain swap, an
//! order on the chain): the other side there could not give its money back
//! if the trade died. Without a limit no place restricts anything, and every
//! received coin counts at once, as `counted`.
//!
//! The limit is the wallet's product setting: the library sets none.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use elements::AssetId;
use serde_json::{json, Value};

use arca_covenant::CoinRecord;

use super::store::CoinRow;
use super::wallet::{owner_of, record_hops};
use super::{Error, Wallet};

/// The store's note of the wallet's instant limit, in atoms of the
/// reference unit, or absent.
pub const INSTANT_LIMIT: &str = "instant_limit";
/// The received coins the wallet counted, by leaf id: counted once, a coin
/// stays counted while the wallet holds it.
pub const INSTANT_COUNTED: &str = "instant_counted";
/// The limit the operator side allowed when it was last read (its suggestion
/// and its bond's share, or zero for a bond that does not stand): taken while
/// the operator or the node cannot be read, so a sync that fails moves no
/// coin.
pub const INSTANT_CAP_SEEN: &str = "instant_cap_seen";

/// The states of a coin that still counts as the wallet's in a place.
pub const PLACED: [&str; 7] = ["live", "pending", "offered", "sending", "given", "forfeited", "exiting"];

/// A coin's lineage, back to the rounds and boards it rests on: see the
/// [module documentation](self). Ordered from the safest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Lineage {
	Own,
	Trade,
	Received,
}

/// A coin's place: see the [module documentation](self).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Place {
	Settled,
	Proceeds,
	Counted,
	Arriving,
}

impl Place {
	pub fn name(self) -> &'static str {
		match self {
			Place::Settled => "settled",
			Place::Proceeds => "proceeds",
			Place::Counted => "counted",
			Place::Arriving => "arriving",
		}
	}
}

/// What a selection of coins pays for, which decides the places it may
/// spend from while the wallet sets an instant limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Spend {
	/// A payment to another wallet of the same operator, out of round.
	Pay,
	/// A trade: a swap or an in-tree fill.
	Trade,
	/// Anything that leaves the Arca, or that the library does not know to
	/// stay in it: a payment on the chain, over Lightning, the Bitcoin side
	/// of a cross-chain swap, an order on the chain.
	Leave,
}

/// The instant limit the wallet applies, in atoms of the reference unit.
#[derive(Debug, Clone)]
pub struct Limit {
	/// The wallet's own figure.
	pub own: u128,
	/// The operator's suggestion, as a figure (`info.bond.instant_limit_value`).
	pub operator: Option<u128>,
	/// The operator's suggested share of its bond, valued at the wallet's
	/// node's rate (`info.bond.instant_budget_ppm`).
	pub bond_share: Option<u128>,
	/// Where the bond stands, as [`Wallet::bond_standing`] says, or `seen`
	/// when the operator or the node could not be read and the last limit
	/// read is taken.
	pub bond: String,
	/// The limit taken: the lowest of them, zero while the bond does not
	/// stand.
	pub value: u128,
}

/// Every coin the wallet holds in a place, and what decided it.
#[derive(Debug, Clone)]
pub struct Places {
	/// `None` while the wallet sets no instant limit.
	pub limit: Option<Limit>,
	/// Each coin, in the store's order, with its lineage and place.
	pub coins: Vec<(CoinRow, Lineage, Place)>,
	/// What the counted coins are worth, in atoms of the reference unit.
	pub counted: u128,
	/// The assets of received coins the node gives no rate for.
	pub unvalued: Vec<String>,
}

impl Places {
	/// The place of the coin `leaf_id`, when the wallet holds it in one.
	pub fn of(&self, leaf_id: &str) -> Option<Place> {
		self.coins.iter().find(|(c, ..)| c.leaf_id == leaf_id).map(|(_, _, p)| *p)
	}
}

impl Wallet {
	/// Whether `record` names a coin of the wallet's own key.
	pub(crate) fn is_mine(&self, record: &CoinRecord) -> bool {
		let (owner, nonce) = owner_of(record);
		self.keys.leaf_xonly(&nonce).is_ok_and(|k| k == owner)
	}

	/// The lineage of the coin `record` names: see the [module
	/// documentation](self).
	pub fn lineage(&self, record: &CoinRecord) -> Lineage {
		match record {
			CoinRecord::Transfer(t) => self.joint(t.inputs.iter().map(|i| (&i.coin, Some(i.exit))).collect()),
			// A fill's order coin goes into no checkpoint: it is spent only by
			// a fill that confirms, and comes home as its maker's order
			// otherwise. Its taker's coins go into checkpoints.
			CoinRecord::Fill(f) => self.joint(std::iter::once((&f.fill.order, None))
				.chain(f.fill.inputs.iter().map(|i| (&i.coin, Some(i.exit)))).collect()),
			CoinRecord::Leaf { .. } | CoinRecord::Board(_) | CoinRecord::Accumulator { .. } => Lineage::Own,
		}
	}

	/// The lineage of a coin a reassignment of `inputs` made, each input with
	/// whether its checkpoint has its owner's exit (`None`: it goes into no
	/// checkpoint). Another's input's own lineage is not read: whatever ends
	/// a trade, the wallet's coin comes home by its exit.
	fn joint(&self, inputs: Vec<(&CoinRecord, Option<bool>)>) -> Lineage {
		let (mine, theirs): (Vec<_>, Vec<_>) = inputs.iter().partition(|(c, _)| self.is_mine(c));
		let below = mine.iter().map(|(c, _)| self.lineage(c)).max().unwrap_or(Lineage::Own);
		if theirs.is_empty() {
			return below;
		}
		if mine.is_empty() || !inputs.iter().all(|(_, exit)| exit.unwrap_or(true)) {
			return Lineage::Received;
		}
		below.max(Lineage::Trade)
	}

	/// Sets the wallet's instant limit, in atoms of the reference unit at its
	/// node's rates; `None` sets none. See the [module documentation](self).
	pub fn set_instant_limit(&self, value: Option<u128>) -> Result<Value, Error> {
		match value {
			Some(v) => self.store.set_meta(INSTANT_LIMIT, &v.to_string())?,
			None => self.store.set_meta(INSTANT_LIMIT, "")?,
		}
		Ok(json!({"instant_limit": value.map(|v| v.to_string())}))
	}

	/// [`Self::set_instant_limit`] from atoms written as text, or `"off"`.
	pub fn set_instant_limit_text(&self, value: &str) -> Result<Value, Error> {
		if value == "off" {
			return self.set_instant_limit(None);
		}
		let v: u128 = value.parse().map_err(|_| Error::Parse(format!("an instant limit of {:?}: atoms of the reference unit, or off", value)))?;
		self.set_instant_limit(Some(v))
	}

	/// The instant limit the wallet set, in atoms of the reference unit.
	pub(crate) fn own_instant_limit(&self) -> Result<Option<u128>, Error> {
		Ok(self.store.meta(INSTANT_LIMIT)?.and_then(|v| v.parse::<u128>().ok()))
	}

	/// The instant limit the wallet applies, `None` while it sets none: the
	/// lowest of its own figure, the operator's suggested figure and the
	/// operator's suggested share of its bond; zero while the bond does not
	/// stand. When the operator or the node cannot be read, the operator's
	/// side as last read.
	pub fn instant_limit(&self) -> Result<Option<Limit>, Error> {
		let Some(own) = self.own_instant_limit()? else { return Ok(None) };
		let read = || -> Result<(String, Option<u128>, Option<u128>, u128), Error> {
			let info = self.server_info()?;
			let s = self.bond_standing(&info)?;
			let operator = info["bond"]["instant_limit_value"].as_str().and_then(|v| v.parse::<u128>().ok())
				.or_else(|| info["bond"]["instant_limit_value"].as_u64().map(u128::from));
			if s.state != "bonded" {
				return Ok((s.state.to_string(), operator, None, 0));
			}
			let rates = self.chain.fee_rates()?;
			let bond = rates.get(&s.asset.expect("bonded")).map(|r| s.value.expect("bonded") as u128 * *r as u128 / 100_000_000);
			let ppm = info["bond"]["instant_budget_ppm"].as_u64().filter(|p| *p > 0);
			let share = match (bond, ppm) {
				(Some(b), Some(p)) => Some(b * p as u128 / 1_000_000),
				_ => None,
			};
			// A bond the node cannot value backs nothing it can weigh.
			let cap = match bond {
				None => 0,
				Some(b) => [Some(b), operator, share].into_iter().flatten().min().unwrap_or(b),
			};
			Ok((s.state.to_string(), operator, share, cap))
		};
		let (bond, operator, share, cap) = match read() {
			Ok(r) => {
				self.store.set_meta(INSTANT_CAP_SEEN, &json!({"bond": r.0, "operator": r.1.map(|v| v.to_string()),
					"share": r.2.map(|v| v.to_string()), "cap": r.3.to_string()}).to_string())?;
				r
			},
			Err(_) => {
				let seen: Value = self.store.meta(INSTANT_CAP_SEEN)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or(Value::Null);
				let n = |k: &str| seen[k].as_str().and_then(|v| v.parse::<u128>().ok());
				("seen".to_string(), n("operator"), n("share"), n("cap").unwrap_or(0))
			},
		};
		Ok(Some(Limit { own, operator, bond_share: share, bond, value: own.min(cap) }))
	}

	/// Every coin the wallet holds in a place: see the [module
	/// documentation](self). The coins newly counted are noted, so they stay
	/// counted.
	pub fn places(&self) -> Result<Places, Error> {
		let limit = self.instant_limit()?;
		let rows = self.store.coins_in_states(&PLACED)?;
		let mut coins: Vec<(CoinRow, Lineage, Place)> = Vec::with_capacity(rows.len());
		let mut received: Vec<(u64, usize)> = vec![];
		for (i, c) in rows.into_iter().enumerate() {
			let lineage = Self::record_of(&c).map(|r| self.lineage(&r)).unwrap_or(Lineage::Received);
			// Not final yet, or on its way home on the chain: arriving, and
			// outside the count, whatever it is.
			let place = if matches!(c.state.as_str(), "pending" | "exiting") { Place::Arriving } else { match lineage {
				Lineage::Own => Place::Settled,
				Lineage::Trade => Place::Proceeds,
				Lineage::Received => {
					received.push((self.store.coin_entry(&c.leaf_id)?.unwrap_or(u64::MAX), i));
					Place::Counted
				},
			} };
			coins.push((c, lineage, place));
		}
		let Some(limit) = limit else {
			return Ok(Places { limit: None, coins, counted: 0, unvalued: vec![] });
		};
		received.sort();
		let held: BTreeSet<String> = received.iter().map(|(_, i)| coins[*i].0.leaf_id.clone()).collect();
		let mut sticky: BTreeSet<String> = self.store.meta(INSTANT_COUNTED)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		let before = sticky.len();
		sticky.retain(|id| held.contains(id));
		let pruned = sticky.len() != before;
		let rates = self.chain.fee_rates().unwrap_or_default();
		let worth = |c: &CoinRow| AssetId::from_str(&c.asset).ok().and_then(|a| rates.get(&a)).filter(|r| **r > 0)
			.map(|r| c.value as u128 * *r as u128 / 100_000_000);
		let mut counted = 0u128;
		let mut unvalued: BTreeSet<String> = BTreeSet::new();
		for (_, i) in &received {
			let c = &coins[*i].0;
			if sticky.contains(&c.leaf_id) {
				counted += worth(c).unwrap_or(0);
			}
		}
		let mut grew = false;
		let mut open = true;
		for (_, i) in &received {
			let c = &coins[*i].0;
			if sticky.contains(&c.leaf_id) {
				continue;
			}
			let place = match worth(c) {
				None => {
					unvalued.insert(c.asset.clone());
					Place::Arriving
				},
				Some(v) if open && counted + v <= limit.value => {
					counted += v;
					sticky.insert(c.leaf_id.clone());
					grew = true;
					Place::Counted
				},
				Some(_) => {
					open = false;
					Place::Arriving
				},
			};
			coins[*i].2 = place;
		}
		if grew || pruned {
			self.store.set_meta(INSTANT_COUNTED, &serde_json::to_string(&sticky).expect("a set"))?;
		}
		Ok(Places { limit: Some(limit), coins, counted, unvalued: unvalued.into_iter().collect() })
	}

	/// The coins a selection for `spend` may not take, by leaf id: none
	/// while the wallet sets no instant limit. When the places cannot be
	/// read, every coin of a lineage other than the wallet's own.
	pub(crate) fn unspendable(&self, spend: Spend) -> Result<BTreeSet<String>, Error> {
		if self.own_instant_limit()?.is_none() {
			return Ok(BTreeSet::new());
		}
		let barred = |p: Place| p == Place::Arriving || (spend == Spend::Leave && p == Place::Proceeds);
		Ok(match self.places() {
			Ok(p) => p.coins.into_iter().filter(|(_, _, p)| barred(*p)).map(|(c, ..)| c.leaf_id).collect(),
			Err(_) => self.store.coins_in("live")?.into_iter()
				.filter(|c| Self::record_of(c).map(|r| self.lineage(&r)).unwrap_or(Lineage::Received) != Lineage::Own)
				.map(|c| c.leaf_id).collect(),
		})
	}

	/// `coin_places`: every coin the wallet holds in a place, the totals of
	/// each place by asset, what can be spent now by asset (`settled`,
	/// `proceeds` and `counted` coins that are live), and the instant limit.
	/// See the [module documentation](self).
	pub fn coin_places(&self) -> Result<Value, Error> {
		let p = self.places()?;
		let mut totals: BTreeMap<String, BTreeMap<&'static str, u128>> = BTreeMap::new();
		let mut spendable: BTreeMap<String, u128> = BTreeMap::new();
		let mut coins = vec![];
		for (c, lineage, place) in &p.coins {
			*totals.entry(c.asset.clone()).or_default().entry(place.name()).or_default() += c.value as u128;
			if c.state == "live" && *place != Place::Arriving {
				*spendable.entry(c.asset.clone()).or_default() += c.value as u128;
			}
			let hops = Self::record_of(c).map(|r| record_hops(&r)).unwrap_or(0);
			coins.push(json!({"leaf_id": c.leaf_id, "asset": c.asset, "value": c.value.to_string(), "state": c.state,
				"lineage": match lineage { Lineage::Own => "own", Lineage::Trade => "trade", Lineage::Received => "received" },
				"place": place.name(), "hops": hops}));
		}
		let totals: serde_json::Map<String, Value> = totals.into_iter()
			.map(|(a, m)| (a, json!(m.into_iter().map(|(k, v)| (k.to_string(), json!(v.to_string()))).collect::<serde_json::Map<_, _>>())))
			.collect();
		let limit = p.limit.as_ref().map(|l| json!({"value": l.value.to_string(), "own": l.own.to_string(),
			"operator": l.operator.map(|v| v.to_string()), "bond_share": l.bond_share.map(|v| v.to_string()), "bond": l.bond,
			"counted": p.counted.to_string(), "room": l.value.saturating_sub(p.counted).to_string()}));
		Ok(json!({
			"instant_limit": limit, "coins": coins, "totals": totals,
			"spendable": spendable.into_iter().map(|(a, v)| (a, json!(v.to_string()))).collect::<serde_json::Map<_, _>>(),
			"unvalued": p.unvalued,
		}))
	}
}
