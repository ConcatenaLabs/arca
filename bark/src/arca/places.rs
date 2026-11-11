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
//!   whatever its lineage; and a channel coin, which is the wallet's only
//!   once its close has made it a coin, counted at the wallet's side of it
//!   alone (`channel`).
//!
//! Received coins are counted oldest first (by the signer's record entry of
//! the transfer that made them, then by when the wallet stored them), until
//! the next would pass the limit; that one and every later one are arriving.
//! Once counted a coin stays counted while the wallet holds it, so a rise in
//! prices never moves a coin back from counted to arriving. A coin made from
//! counted coins keeps their place, counted, ahead of every coin arriving:
//! the change of the wallet's own payment out of one, and what a trade with
//! its owner's exit on every checkpoint paid for one. What one trade pays
//! the wallet counts, all together, at most what the coins given were worth
//! when it took their place; what the trade brought beyond that counts
//! nothing against the limit, and the wallet's own payments out of such a
//! coin carry that bound on. A coin that
//! arrives is refreshed at the next round ([`Wallet::refresh_needed`]), and
//! is then `settled`.
//!
//! With a limit set, the wallet spends no `arriving` coin but in a refresh,
//! and no `proceeds` coin in the leg of a cross-chain swap paid to another
//! party, who could not give its money back if the trade died; when only
//! proceeds would pay that leg, they go into the next round at once and the
//! swap goes ahead after it. Proceeds pay everything else at once: a payment
//! inside the Arca, one over Lightning (through the operator's own node, so
//! the risk is the operator's, and its watcher's), one on the chain (made in
//! a round). Without a limit no place restricts anything, and every received
//! coin counts at once, as `counted`.
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
/// For each counted coin a trade bought with counted coins, by leaf id, the
/// most it counts against the limit: what those coins were worth when it
/// took their place (atoms of the reference unit, as text).
pub const INSTANT_COUNTED_CAPS: &str = "instant_counted_caps";
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
	/// A payment: inside the Arca, over Lightning through the operator's
	/// node, on the chain in a round, a claim, an order or a take.
	Pay,
	/// A trade: a swap or an in-tree fill.
	Trade,
	/// The leg of a cross-chain swap paid to another party.
	CrossChain,
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
	/// The channel coins, by leaf id, each counted at the wallet's side.
	pub channels: BTreeSet<String>,
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
		// A coin whose exit's claim is out is held as the claim's output on the
		// chain, not here.
		let rows: Vec<CoinRow> = rows.into_iter().filter(|c| !(c.state == "exiting" && c.note.starts_with("claimed by"))).collect();
		let mut channels: BTreeSet<String> = BTreeSet::new();
		for (i, mut c) in rows.into_iter().enumerate() {
			let lineage = Self::record_of(&c).map(|r| self.lineage(&r)).unwrap_or(Lineage::Received);
			// A channel coin counts the wallet's side of it alone, as the
			// balance does.
			let channel = match self.channel_worth(&c) {
				Ok(Some(w)) => {
					c.value = w;
					channels.insert(c.leaf_id.clone());
					true
				},
				_ => false,
			};
			// Not final yet, on its way home on the chain, or a channel's: with a
			// limit set, arriving, and outside the count, whatever it is.
			let place = if matches!(c.state.as_str(), "pending" | "exiting") || (channel && limit.is_some()) { Place::Arriving } else { match lineage {
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
			return Ok(Places { limit: None, coins, counted: 0, unvalued: vec![], channels });
		};
		received.sort();
		let held: BTreeSet<String> = received.iter().map(|(_, i)| coins[*i].0.leaf_id.clone()).collect();
		let mut sticky: BTreeSet<String> = self.store.meta(INSTANT_COUNTED)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		let rates = self.chain.fee_rates().unwrap_or_default();
		let worth = |c: &CoinRow| AssetId::from_str(&c.asset).ok().and_then(|a| rates.get(&a)).filter(|r| **r > 0)
			.map(|r| c.value as u128 * *r as u128 / 100_000_000);
		// The most a counted coin bought in a trade counts, by leaf id: what the
		// counted coins given for it were worth when it took their place.
		let mut caps: BTreeMap<String, u128> = self.store.meta(INSTANT_COUNTED_CAPS)?
			.and_then(|v| serde_json::from_str::<BTreeMap<String, String>>(&v).ok()).unwrap_or_default()
			.into_iter().filter_map(|(k, v)| v.parse::<u128>().ok().map(|v| (k, v))).collect();
		// A coin made from counted coins of the wallet's keeps their place,
		// ahead of every coin arriving: read while the parents, spent now, are
		// still in the note.
		// - The change of the wallet's own payment out of one.
		// - What a trade with its owner's exit on every checkpoint paid the
		//   wallet for one: it takes the place of the coin given, and counts at
		//   most what that coin was worth then; what it brought beyond that
		//   counts nothing against the limit (the trade's gain, which a dead
		//   trade takes back with the coin given coming home).
		let mut inherited = false;
		let unplaced: Vec<usize> = received.iter().map(|(_, i)| *i).filter(|i| !sticky.contains(&coins[*i].0.leaf_id)).collect();
		if !unplaced.is_empty() && !sticky.is_empty() {
			let by_record: std::collections::HashMap<Vec<u8>, CoinRow> = self.store.coins()?.into_iter().map(|c| (c.record.clone(), c)).collect();
			let mut budget: BTreeMap<Vec<String>, u128> = BTreeMap::new();
			for i in unplaced {
				let Ok(record) = Self::record_of(&coins[i].0) else { continue };
				let inputs: Vec<(&CoinRecord, Option<bool>)> = match &record {
					CoinRecord::Transfer(t) => t.inputs.iter().map(|x| (&x.coin, Some(x.exit))).collect(),
					CoinRecord::Fill(f) => std::iter::once((&f.fill.order, None)).chain(f.fill.inputs.iter().map(|x| (&x.coin, Some(x.exit)))).collect(),
					_ => continue,
				};
				let mine: Vec<&CoinRecord> = inputs.iter().filter(|(c, _)| self.is_mine(c)).map(|(c, _)| *c).collect();
				let own_payment = mine.len() == inputs.len();
				let trade = !own_payment && !mine.is_empty() && inputs.iter().all(|(_, e)| e.unwrap_or(true));
				if !own_payment && !trade {
					continue;
				}
				let given: Vec<&CoinRow> = mine.iter().filter_map(|c| c.to_bytes().ok().and_then(|b| by_record.get(&b)))
					.filter(|row| sticky.contains(&row.leaf_id)).collect();
				if given.is_empty() {
					continue;
				}
				sticky.insert(coins[i].0.leaf_id.clone());
				// The coins one transfer pays the wallet out of counted coins
				// share what those coins counted: each counts at most what is
				// left of it, in the order the wallet holds them. A trade's is
				// what the coins given were worth then; an own payment's carries
				// on the caps of the coins it spent, so paying itself never
				// turns a trade's gain into counted value.
				if trade || given.iter().any(|g| caps.contains_key(&g.leaf_id)) {
					let mut key: Vec<String> = given.iter().map(|g| g.leaf_id.clone()).collect();
					key.sort();
					let left = budget.entry(key).or_insert_with(|| given.iter().map(|g| {
						let w = worth(g).unwrap_or(0);
						if trade { w } else { caps.get(&g.leaf_id).map_or(w, |c| w.min(*c)) }
					}).sum());
					let cap = worth(&coins[i].0).unwrap_or(0).min(*left);
					*left -= cap;
					caps.insert(coins[i].0.leaf_id.clone(), cap);
				}
				inherited = true;
			}
		}
		let before = sticky.len();
		sticky.retain(|id| held.contains(id));
		caps.retain(|id, _| sticky.contains(id));
		let pruned = sticky.len() != before || inherited;
		let counts = |c: &CoinRow| {
			let w = worth(c).unwrap_or(0);
			caps.get(&c.leaf_id).map_or(w, |cap| w.min(*cap))
		};
		let mut counted = 0u128;
		let mut unvalued: BTreeSet<String> = BTreeSet::new();
		for (_, i) in &received {
			let c = &coins[*i].0;
			if sticky.contains(&c.leaf_id) {
				counted += counts(c);
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
			// Both at once: a coin counted for a trade is never kept without
			// the most it counts.
			let caps: BTreeMap<String, String> = caps.into_iter().map(|(k, v)| (k, v.to_string())).collect();
			self.store.set_metas(&[(INSTANT_COUNTED, serde_json::to_string(&sticky).expect("a set")),
				(INSTANT_COUNTED_CAPS, serde_json::to_string(&caps).expect("a map"))])?;
		}
		Ok(Places { limit: Some(limit), coins, counted, unvalued: unvalued.into_iter().collect(), channels })
	}

	/// The coins a selection for `spend` may not take, by leaf id: none
	/// while the wallet sets no instant limit. When the places cannot be
	/// read, every coin of a lineage other than the wallet's own.
	pub(crate) fn unspendable(&self, spend: Spend) -> Result<BTreeSet<String>, Error> {
		if self.own_instant_limit()?.is_none() {
			return Ok(BTreeSet::new());
		}
		let barred = |p: Place| p == Place::Arriving || (spend == Spend::CrossChain && p == Place::Proceeds);
		Ok(match self.places() {
			Ok(p) => p.coins.into_iter().filter(|(_, _, p)| barred(*p)).map(|(c, ..)| c.leaf_id).collect(),
			Err(_) => self.store.coins_in("live")?.into_iter()
				.filter(|c| Self::record_of(c).map(|r| self.lineage(&r)).unwrap_or(Lineage::Received) != Lineage::Own)
				.map(|c| c.leaf_id).collect(),
		})
	}

	/// Gives up in the next round every live coin of `asset` placed as trade
	/// proceeds, so that a payment only settled coins may make goes ahead
	/// after it; answers what it gave up (0 when none, or with no limit set).
	pub(crate) fn settle_proceeds(&mut self, asset: AssetId) -> Result<u64, Error> {
		if self.own_instant_limit()?.is_none() {
			return Ok(0);
		}
		let p = self.places()?;
		let ids: Vec<String> = p.coins.iter().filter(|(c, _, pl)| *pl == Place::Proceeds && c.state == "live" && c.asset == asset.to_string())
			.map(|(c, ..)| c.leaf_id.clone()).collect();
		let value: u64 = p.coins.iter().filter(|(c, ..)| ids.contains(&c.leaf_id)).map(|(c, ..)| c.value).sum();
		if ids.is_empty() {
			return Ok(0);
		}
		let quote = self.refresh_quote(&ids, None)?;
		self.participate(quote, None)?;
		Ok(value)
	}

	/// `settle_first`: puts through the operator's next round the coins a
	/// spend waits for ([`Error::SettleFirst`] names them, as `coins`), or,
	/// with `asset` alone, every coin of it that pays out of round only
	/// after a round ([`Wallet::round_first`] for a payment) and every coin
	/// of it a round of the wallet's holds now (given up, not final yet). Each coin
	/// still live is given up in a refresh for a coin of the wallet's own
	/// (`settling`); one already given up, or not final yet, waits for its
	/// round as it is (`waiting`); one the wallet no longer holds is through
	/// (`done`); one the operator would not take now stays live, with why
	/// (`left`). Asked again it gives up nothing twice, so a program asks it
	/// again while it waits. `ready` once nothing named is settling or
	/// waiting: the spend can be asked again. Costs the refresh's fee per
	/// coin given up, within `max_fee_ppm` (by default the wallet's bound).
	pub fn settle_first(&mut self, coins: &[String], asset: Option<AssetId>, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		let ids: Vec<String> = if !coins.is_empty() {
			coins.to_vec()
		} else if let Some(a) = asset {
			let info = self.server_info()?;
			let mut ids: Vec<String> = self.round_first(a, Spend::Pay, super::pay::depth_limit(&info), false)?.into_iter().map(|(l, ..)| l).collect();
			// And every coin of it the wallet's own rounds hold now (given up in a
			// refresh, or not final yet), which a spend waits for as it is.
			for c in self.store.coins_in_states(&["given", "pending"])? {
				if c.asset == a.to_string() && !ids.contains(&c.leaf_id) {
					ids.push(c.leaf_id);
				}
			}
			ids
		} else {
			return Err(Error::Parse("name the coins to settle, or the asset".into()));
		};
		let (mut give, mut waiting, mut done) = (vec![], vec![], vec![]);
		for id in ids {
			match self.store.coin(&id)?.map(|c| c.state) {
				Some(st) if st == "live" => give.push(id),
				Some(st) if st == "given" || st == "pending" => waiting.push(id),
				_ => done.push(id),
			}
		}
		let mut left = vec![];
		let mut settling = vec![];
		if !give.is_empty() {
			// All in one refresh when the operator takes them so; else each
			// alone, so one it refuses holds back no other.
			match self.refresh_quote(&give, max_fee_ppm) {
				Ok(q) => {
					self.participate(q, None)?;
					settling = give;
				},
				Err(_) => for id in give {
					match self.refresh_quote(std::slice::from_ref(&id), max_fee_ppm) {
						Ok(q) => {
							self.participate(q, None)?;
							settling.push(id);
						},
						Err(e) => left.push(json!({"leaf_id": id, "why": e.to_string()})),
					}
				},
			}
		}
		let ready = settling.is_empty() && waiting.is_empty();
		Ok(json!({"settling": settling, "waiting": waiting, "done": done, "left": left, "ready": ready}))
	}

	/// `coin_places`: every coin the wallet holds in a place (with its kind:
	/// a `board` arriving waits on its board's block and anchor), the totals of
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
			if c.state == "live" && *place != Place::Arriving && !p.channels.contains(&c.leaf_id) {
				*spendable.entry(c.asset.clone()).or_default() += c.value as u128;
			}
			let hops = Self::record_of(c).map(|r| record_hops(&r)).unwrap_or(0);
			let mut v = json!({"leaf_id": c.leaf_id, "asset": c.asset, "value": c.value.to_string(), "state": c.state, "kind": c.kind,
				"lineage": match lineage { Lineage::Own => "own", Lineage::Trade => "trade", Lineage::Received => "received" },
				"place": place.name(), "hops": hops});
			if p.channels.contains(&c.leaf_id) {
				v["channel"] = json!(true);
			}
			coins.push(v);
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
