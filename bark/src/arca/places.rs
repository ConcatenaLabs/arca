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
//! coin carry that bound on. While the node gives no rate for a coin a trade
//! paid, or for a coin given for it, what that trade paid the wallet is
//! arriving and the room the coins given held stays taken; the next read
//! with rates places it. A coin that
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
use super::chain::Finality;
use super::{Error, Wallet};

/// What [`Wallet::final_within`] counts a round's wait in. The operator's
/// round interval, block time, window for a held round's forfeits and the
/// time its passes over the rounds take are read from its `info`
/// (`fills.round_interval_seconds`, `fills.block_seconds`,
/// `fills.forfeit_window_seconds`, `fills.round_pass_seconds`), and its
/// anchor depth from `finality.anchor_depth`; these three values stand only
/// for an operator that publishes none (one that publishes no pass time is
/// counted as in [`Wallet::final_within`]). A Bitcoin block is Bitcoin's target
/// interval, ten minutes, for each anchor block still to bury a round.
/// The most working pieces a refresh with `spread` cuts an asset's
/// holding into, beside one reserve coin ([`Wallet::spread_of`]): with a
/// trade every 15 s and a round about two minutes from asked to spendable,
/// four coins of an asset, each used up three trades at a time, keep one
/// with room while the others go through rounds.
pub const SPREAD_PIECES: usize = 3;
/// A working piece is at least this many times the operator's smallest
/// leaf in its asset.
pub const SPREAD_LEAF_MULTIPLE: u64 = 10;
/// A working piece is at least this many times what one coin's exit costs
/// on the chain: an exit never takes more than a hundredth of a piece.
pub const SPREAD_EXIT_MULTIPLE: u64 = 100;
/// The vbytes a coin's exit is counted at for [`SPREAD_EXIT_MULTIPLE`]: one
/// leaf's whole exit measured 1,119 to 1,792 vbytes on regtest.
pub const SPREAD_EXIT_VSIZE: u64 = 2_000;

/// [`Wallet::spread_of`] for a holding of `held` atoms, the operator's
/// smallest leaf `min`, one exit's cost `exit` (atoms) and `others` coins of
/// the asset the refresh leaves as they are: pieces of `held` / 6, but at
/// least the floor, as many as fit in half the holding, up to
/// [`SPREAD_PIECES`] less `others`, so the wallet holds at most
/// [`SPREAD_PIECES`] + 1 coins of it; `None` when not one fits.
pub(crate) fn spread_plan(held: u64, min: u64, exit: u64, others: usize) -> Option<(u64, usize)> {
	let floor = min.saturating_mul(SPREAD_LEAF_MULTIPLE).max(exit.saturating_mul(SPREAD_EXIT_MULTIPLE)).max(1);
	let piece = (held / (2 * SPREAD_PIECES as u64)).max(floor);
	let count = ((held / 2) / piece).min(SPREAD_PIECES.saturating_sub(others) as u64) as usize;
	(count > 0).then_some((piece, count))
}

const ROUND_SECONDS: u64 = 60;
const BLOCK_SECONDS: u64 = 60;
const FORFEIT_WINDOW_SECONDS: u64 = 600;
const BITCOIN_BLOCK_SECONDS: u64 = 600;

/// [`Wallet::final_within`]'s count, for a round where `finality` says
/// (`None` for a round not built yet) on an operator that publishes `info`
/// and counts finality at anchor depth `depth`.
pub(crate) fn wait_counts(info: &Value, depth: u64, finality: Option<&Finality>) -> Within {
	let round_s = info["fills"]["round_interval_seconds"].as_u64().filter(|s| *s > 0).unwrap_or(ROUND_SECONDS);
	let block_s = info["fills"]["block_seconds"].as_u64().filter(|s| *s > 0).unwrap_or(BLOCK_SECONDS);
	let forfeits_s = info["fills"]["forfeit_window_seconds"].as_u64().filter(|s| *s > 0).unwrap_or(FORFEIT_WINDOW_SECONDS);
	// The operator builds a round and releases its participations in its
	// passes over the rounds, which run at its round interval and on each
	// block. An operator that publishes how long its passes take
	// (`fills.round_pass_seconds`, its finality poll included) is counted one
	// pass to build the round and three to release it (a build and a pass
	// that may be under way when the round turns final, and the pass after
	// them); one that does not, a round interval and a block to release it.
	let pass_s = info["fills"]["round_pass_seconds"].as_u64().filter(|s| *s > 0);
	let build = pass_s.unwrap_or(0);
	let release = pass_s.map_or(round_s + block_s, |p| 3 * p);
	let bury = |have: u64| depth.saturating_sub(have).saturating_mul(BITCOIN_BLOCK_SECONDS);
	let held = info["batches"]["no_sweep"].as_bool() == Some(true);
	let after_block = 2 * block_s + bury(0) + release;
	let w = |most: u64, usual: u64, step: Wait| Within { most, usual, step };
	match finality {
		None if held => w(round_s + build + forfeits_s + after_block, 2 * round_s + build + after_block, Wait::Round),
		None => w(round_s + build + after_block, round_s + build + after_block, Wait::Round),
		Some(Finality::NotInChain { in_mempool: false }) => w(forfeits_s + after_block, round_s + after_block, Wait::Forfeits),
		Some(Finality::NotInChain { in_mempool: true }) => w(after_block, after_block, Wait::Block),
		Some(Finality::Unsettled { .. }) => w(block_s + bury(0) + release, block_s + bury(0) + release, Wait::Certificate),
		Some(Finality::Settled { depth: d, .. }) => w(bury(*d).max(block_s) + release, bury(*d).max(block_s) + release, Wait::Anchor),
		Some(Finality::Final { .. }) => w(release, release, Wait::Release),
	}
}

#[cfg(test)]
mod wait_tests {
	use super::*;

	fn info(extra: Value) -> Value {
		let mut v = json!({"fills": {"round_interval_seconds": 60, "block_seconds": 60, "forfeit_window_seconds": 600},
			"batches": {"no_sweep": true}});
		if let (Some(o), Some(e)) = (v["fills"].as_object_mut(), extra.as_object()) {
			for (k, x) in e {
				o.insert(k.clone(), x.clone());
			}
		}
		v
	}

	/// A spread keeps at most half the holding in up to three working pieces
	/// of a sixth, the rest one reserve coin; never a piece below ten
	/// smallest leaves or a hundred exits; never more than four coins with
	/// those the wallet keeps.
	#[test]
	fn a_spread_is_bounded_by_the_holding_the_smallest_leaf_and_an_exit() {
		// 6,000,000 held, smallest leaf 10,000, an exit 800: three pieces of 1,000,000.
		assert_eq!(spread_plan(6_000_000, 10_000, 800, 0), Some((1_000_000, 3)));
		// Two coins kept beside: one piece more makes four.
		assert_eq!(spread_plan(6_000_000, 10_000, 800, 2), Some((1_000_000, 1)));
		assert_eq!(spread_plan(6_000_000, 10_000, 800, 3), None, "four coins already");
		// A piece is at least ten smallest leaves (100,000): 300,000 held makes one.
		assert_eq!(spread_plan(300_000, 10_000, 800, 0), Some((100_000, 1)));
		// And at least a hundred exits (80,000 × 100 = 8,000,000).
		assert_eq!(spread_plan(6_000_000, 10_000, 80_000, 0), None, "a small holding stays one coin");
		assert_eq!(spread_plan(20_000_000, 10_000, 80_000, 0), Some((8_000_000, 1)));
		assert_eq!(spread_plan(150_000, 10_000, 800, 0), None);
	}

	#[test]
	fn the_testnets_wait_term_by_term() {
		// Round 60, held for forfeits 600 (usual: one round more), block 60,
		// certificate 60, depth 0, release a round and a block 120.
		let w = wait_counts(&info(json!({})), 0, None);
		assert_eq!((w.most, w.usual, w.step), (60 + 600 + 120 + 120, 60 + 60 + 120 + 120, Wait::Round));
		let w = wait_counts(&info(json!({})), 0, Some(&Finality::NotInChain { in_mempool: false }));
		assert_eq!((w.most, w.usual, w.step), (600 + 120 + 120, 60 + 120 + 120, Wait::Forfeits));
		let w = wait_counts(&info(json!({})), 0, Some(&Finality::NotInChain { in_mempool: true }));
		assert_eq!((w.most, w.step), (120 + 120, Wait::Block));
		let w = wait_counts(&info(json!({})), 0, Some(&Finality::Unsettled { height: 1 }));
		assert_eq!((w.most, w.step), (60 + 120, Wait::Certificate));
		let w = wait_counts(&info(json!({})), 0, Some(&Finality::Final { height: 1, depth: 0 }));
		assert_eq!((w.most, w.usual, w.step), (120, 120, Wait::Release));
		// Depth 2: two Bitcoin blocks more until buried.
		let w = wait_counts(&info(json!({})), 2, Some(&Finality::Settled { height: 1, depth: 1 }));
		assert_eq!((w.most, w.step), (600 + 120, Wait::Anchor));
	}

	#[test]
	fn a_published_pass_time_replaces_the_release_guess() {
		let fast = info(json!({"round_pass_seconds": 3}));
		let w = wait_counts(&fast, 0, Some(&Finality::Final { height: 1, depth: 0 }));
		assert_eq!(w.most, 9, "a build and a pass under way, and the next pass, 3 s each");
		let w = wait_counts(&fast, 0, None);
		assert_eq!(w.usual, 60 + 3 + 60 + 120 + 9, "a pass to build, the forfeits, block and certificate, three passes to release");
		let unheld = json!({"fills": {"round_interval_seconds": 30, "block_seconds": 60}});
		assert_eq!(wait_counts(&unheld, 0, None).most, 30 + 120 + 30 + 60, "a sweeping operator holds no round for forfeits");
	}
}

/// `settle_first`'s sorting of the coins it is asked for ([`Wallet::sorted`]).
struct Sorted {
	give: Vec<String>,
	waiting: Vec<String>,
	done: Vec<String>,
	rounds: Vec<Option<String>>,
	/// The most seconds left of the hold of a coin held out as spent
	/// elsewhere ([`Wallet::spent_elsewhere`]), when one is waiting: such a
	/// coin waits for no round of this store's, only for its hold to end.
	held_left: Option<u64>,
}

/// What [`Wallet::final_within`] answers: the most seconds a round still
/// takes, what it usually takes, and the step it waits for.
pub(crate) struct Within {
	pub most: u64,
	pub usual: u64,
	pub step: Wait,
}

/// The step a settling round waits for, earliest first: the operator's
/// next round; a round held unbroadcast until every participation in it
/// has handed its forfeits over; its transaction's block; that block's
/// certificate; its anchor buried at the operator's depth; and the
/// operator's release of the new coins once it holds the round final.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Wait {
	Round,
	Forfeits,
	Block,
	Certificate,
	Anchor,
	Release,
}

impl Wait {
	pub(crate) fn name(self) -> &'static str {
		match self {
			Wait::Round => "round",
			Wait::Forfeits => "forfeits",
			Wait::Block => "block",
			Wait::Certificate => "certificate",
			Wait::Anchor => "anchor",
			Wait::Release => "release",
		}
	}
}

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
pub const PLACED: [&str; 8] = ["live", "pending", "offered", "sending", "given", "forfeited", "exiting", super::lock::LOCK_IN];

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
	/// What each counted coin counts of `counted`, by leaf id (a coin
	/// waiting on a reserve for coins it was made from is in `counted` only
	/// through that reserve, and not here).
	pub counted_of: BTreeMap<String, u128>,
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
		if self.keys.leaf_xonly(&nonce).is_ok_and(|k| k == owner) {
			return true;
		}
		// A lock the wallet made as its payer is its own value by script:
		// nothing takes it before its timeout but its payee with the preimage,
		// which the wallet alone reveals, nor after it but the wallet. So what
		// its refund makes is of the lineage of the coins it locked.
		super::lock::lock_terms(record).is_some_and(|(t, _, _, creator)| {
			self.keys.leaf_xonly(&super::lock::refund_nonce(&creator)).is_ok_and(|k| k == t.refunder)
		})
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
			return Ok(Places { limit: None, coins, counted: 0, counted_of: BTreeMap::new(), unvalued: vec![], channels });
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
		// What one transfer paid the wallet out of counted coins is placed
		// whole or not at all: while the node gives no rate for a coin it
		// paid, or for a coin given for it, those coins arrive, the coins
		// given stay noted so that a later read places them, and the room
		// the coins given held stays taken, so no payment counts in it
		// meanwhile. A cap is never written from a missing rate.
		let mut deferred: BTreeSet<String> = BTreeSet::new();
		let mut keep: BTreeSet<String> = BTreeSet::new();
		let mut reserved = 0u128;
		let mut reserve_unknown = false;
		let unplaced: Vec<usize> = received.iter().map(|(_, i)| *i).filter(|i| !sticky.contains(&coins[*i].0.leaf_id)).collect();
		if !unplaced.is_empty() && !sticky.is_empty() {
			let by_record: std::collections::HashMap<Vec<u8>, CoinRow> = self.store.coins()?.into_iter().map(|c| (c.record.clone(), c)).collect();
			// Each unplaced coin made from counted coins: the coins given (by
			// leaf id, sorted), whether a trade made it, and whether it takes
			// a cap.
			let mut from: Vec<(usize, Vec<&CoinRow>, Vec<String>, bool, bool)> = vec![];
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
				let capped = trade || given.iter().any(|g| caps.contains_key(&g.leaf_id));
				let mut key: Vec<String> = given.iter().map(|g| g.leaf_id.clone()).collect();
				key.sort();
				from.push((i, given, key, trade, capped));
			}
			// What a coin given counts toward the coins made from it: a
			// trade's, its whole worth then; an own payment's, at most its cap.
			let room = |g: &CoinRow, trade: bool, caps: &BTreeMap<String, u128>| worth(g).map(|w| if trade { w } else { caps.get(&g.leaf_id).map_or(w, |c| w.min(*c)) });
			let mut waits: BTreeMap<Vec<String>, (Vec<&CoinRow>, bool)> = BTreeMap::new();
			for (i, given, key, trade, capped) in &from {
				if *capped && (worth(&coins[*i].0).is_none() || given.iter().any(|g| worth(g).is_none())) {
					waits.insert(key.clone(), (given.clone(), *trade));
				}
			}
			for (given, trade) in waits.values() {
				keep.extend(given.iter().map(|g| g.leaf_id.clone()));
				match given.iter().map(|g| room(g, *trade, &caps)).sum::<Option<u128>>() {
					Some(v) => reserved += v,
					None => reserve_unknown = true,
				}
			}
			let mut budget: BTreeMap<Vec<String>, u128> = BTreeMap::new();
			for (i, given, key, trade, capped) in from {
				if waits.contains_key(&key) {
					deferred.insert(coins[i].0.leaf_id.clone());
					continue;
				}
				sticky.insert(coins[i].0.leaf_id.clone());
				// The coins one transfer pays the wallet out of counted coins
				// share what those coins counted: each counts at most what is
				// left of it, in the order the wallet holds them. A trade's is
				// what the coins given were worth then; an own payment's carries
				// on the caps of the coins it spent, so paying itself never
				// turns a trade's gain into counted value. Every coin here is
				// valued: one that is not waits above.
				if capped {
					let left = budget.entry(key).or_insert_with(|| given.iter().map(|g| room(g, trade, &caps).unwrap_or(0)).sum());
					let cap = worth(&coins[i].0).unwrap_or(0).min(*left);
					*left -= cap;
					caps.insert(coins[i].0.leaf_id.clone(), cap);
				}
				inherited = true;
			}
		}
		let before = sticky.len();
		sticky.retain(|id| held.contains(id) || keep.contains(id));
		caps.retain(|id, _| sticky.contains(id));
		let pruned = sticky.len() != before || inherited;
		let counts = |c: &CoinRow| {
			let w = worth(c).unwrap_or(0);
			caps.get(&c.leaf_id).map_or(w, |cap| w.min(*cap))
		};
		let mut counted = reserved;
		let mut counted_of: BTreeMap<String, u128> = BTreeMap::new();
		let mut unvalued: BTreeSet<String> = BTreeSet::new();
		for (_, i) in &received {
			let c = &coins[*i].0;
			if sticky.contains(&c.leaf_id) {
				let n = counts(c);
				counted += n;
				counted_of.insert(c.leaf_id.clone(), n);
			}
		}
		let mut grew = false;
		let mut open = !reserve_unknown;
		for (_, i) in &received {
			let c = &coins[*i].0;
			if sticky.contains(&c.leaf_id) {
				continue;
			}
			if deferred.contains(&c.leaf_id) {
				if worth(c).is_none() {
					unvalued.insert(c.asset.clone());
				}
				coins[*i].2 = Place::Arriving;
				continue;
			}
			let place = match worth(c) {
				None => {
					unvalued.insert(c.asset.clone());
					Place::Arriving
				},
				Some(v) if open && counted + v <= limit.value => {
					counted += v;
					counted_of.insert(c.leaf_id.clone(), v);
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
		Ok(Places { limit: Some(limit), coins, counted, counted_of, unvalued: unvalued.into_iter().collect(), channels })
	}

	/// The coins a selection for `spend` may not take, by leaf id: none
	/// while the wallet sets no instant limit. When the places cannot be
	/// read, every coin of a lineage other than the wallet's own.
	pub(crate) fn unspendable(&self, spend: Spend) -> Result<BTreeSet<String>, Error> {
		// A coin another store of the mnemonic spent, which no catch-up has
		// settled yet, is never taken ([`Wallet::spent_elsewhere`]).
		let mut out = self.spent_elsewhere()?;
		if self.own_instant_limit()?.is_none() {
			return Ok(out);
		}
		let barred = |p: Place| p == Place::Arriving || (spend == Spend::CrossChain && p == Place::Proceeds);
		out.extend(match self.places() {
			Ok(p) => p.coins.into_iter().filter(|(_, _, p)| barred(*p)).map(|(c, ..)| c.leaf_id).collect::<Vec<_>>(),
			Err(_) => self.store.coins_in("live")?.into_iter()
				.filter(|c| Self::record_of(c).map(|r| self.lineage(&r)).unwrap_or(Lineage::Received) != Lineage::Own)
				.map(|c| c.leaf_id).collect(),
		});
		Ok(out)
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
	/// of it a round of the wallet's holds now (given up, not final yet, or
	/// final with its new coins not taken yet). Each coin still live is
	/// given up in a refresh for a coin of the wallet's own (`settling`).
	/// One already given up waits for its round as it is (`waiting`), and so
	/// does one whose round is through while the coins it made cannot be
	/// spent yet: their round not final, or final with the operator's
	/// preimage for them still to come. One the wallet no longer holds and
	/// whose round left it coins it can spend is through (`done`); one the
	/// operator would not take now stays live, with why (`left`). Asked again
	/// it gives up nothing twice, so a program asks it again while it waits.
	/// `ready` once nothing named is settling or waiting: the spend can be
	/// asked again, and pays. While not ready, `final_in_seconds` is the
	/// most it should take from now, read from where each round stands on
	/// the chain, the operator's round interval and block time, and the
	/// anchor depth it counts finality at ([`Self::final_within`]), and
	/// `usual_in_seconds` what it usually takes (less than the most only
	/// while a round may be held for other participations' forfeits, which
	/// usually come within a round interval and may take the operator's
	/// whole window), and `waiting_for` the step the furthest of them waits
	/// for ([`Wait`]):
	/// `round`, `forfeits`, `block`, `certificate`, `anchor` or `release`. Each answer
	/// counts again from where things stand, so a wait past its time (an
	/// operator slow to release, a parent chain slow to bury) keeps
	/// answering the same step and its usual time: a program that told a
	/// person a time keeps it, and moves it on only when `waiting_for` goes
	/// back to an earlier step (a new round, an anchor rollback). Costs
	/// the refresh's fee per coin given up, within `max_fee_ppm` (by
	/// default the wallet's bound).
	pub fn settle_first(&mut self, coins: &[String], asset: Option<AssetId>, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		self.settle_first_spread(coins, asset, max_fee_ppm, false)
	}

	/// [`Self::settle_first`], and with `spread` each asset's refresh cut
	/// into pieces as [`Self::spread_of`] plans them (a small holding, or a
	/// supervised asset, stays one coin), so a wallet that trades on uses
	/// up one coin's room at a time while the others trade. The fee is the
	/// same: the operator charges for the coins given up, not for the
	/// leaves made.
	pub fn settle_first_spread(&mut self, coins: &[String], asset: Option<AssetId>, max_fee_ppm: Option<u64>, spread: bool)
		-> Result<Value, Error>
	{
		// Coins another store of the mnemonic spent are settled by a catch-up,
		// which this one runs while any is held out: one it settled is through.
		if let Err(e) = self.settle_spent_elsewhere() {
			self.store.refused("the catch-up for coins spent elsewhere", &e.to_string())?;
		}
		let info = self.server_info()?;
		let ids: Vec<String> = if !coins.is_empty() {
			coins.to_vec()
		} else if let Some(a) = asset {
			let mut ids: Vec<String> = self.round_first(&info, a, Spend::Pay, super::pay::depth_limit(&info), super::pay::Reads::ALL)?.into_iter().map(|(l, ..)| l).collect();
			// And every coin of it the wallet's own rounds hold now (given up in a
			// refresh, or not final yet), which a spend waits for as it is.
			for c in self.store.coins_in_states(&["given", "pending"])? {
				// A board the operator holds lost waits for no round.
				let lost_board = c.kind == "board" && c.note.contains(super::wallet::BOARD_LOST);
				if c.asset == a.to_string() && !ids.contains(&c.leaf_id) && !lost_board {
					ids.push(c.leaf_id);
				}
			}
			ids
		} else {
			return Err(Error::Parse("name the coins to settle, or the asset".into()));
		};
		let Sorted { give, waiting, done, mut rounds, held_left } = self.sorted(ids)?;
		let mut left = vec![];
		let mut settling = vec![];
		// With `spread`, each asset on its own, so each is cut by its own
		// plan; else all together.
		let groups: Vec<Vec<String>> = if spread {
			let mut by: BTreeMap<String, Vec<String>> = BTreeMap::new();
			for id in give {
				let a = self.store.coin(&id)?.map(|c| c.asset).unwrap_or_default();
				by.entry(a).or_default().push(id);
			}
			by.into_values().collect()
		} else if give.is_empty() {
			vec![]
		} else {
			vec![give]
		};
		for give in groups {
			let plan = match (spread, self.store.coin(&give[0])?) {
				(true, Some(c)) => self.spread_of(&info, AssetId::from_str(&c.asset).map_err(|e| Error::Store(e.to_string()))?, &give)?,
				_ => None,
			};
			let cut = |q: &mut super::round::RefreshQuote| {
				if let Some((piece, count)) = plan {
					// A plan the value cannot be cut by leaves it one coin.
					let _ = q.in_pieces(piece, count);
				}
			};
			// All in one refresh when the operator takes them so; else each
			// alone, so one it refuses holds back no other.
			match self.refresh_quote(&give, max_fee_ppm) {
				Ok(mut q) => {
					cut(&mut q);
					self.participate(q, None)?;
					settling.extend(give);
				},
				Err(_) => for id in give {
					match self.refresh_quote(std::slice::from_ref(&id), max_fee_ppm) {
						Ok(mut q) => {
							cut(&mut q);
							self.participate(q, None)?;
							settling.push(id);
						},
						Err(e) => left.push(json!({"leaf_id": id, "why": e.to_string()})),
					}
				},
			}
		}
		if !settling.is_empty() {
			rounds.push(None);
			self.keep_settling(&settling)?;
		}
		let ready = settling.is_empty() && waiting.is_empty();
		let mut v = json!({"settling": settling, "waiting": waiting, "done": done, "left": left, "ready": ready});
		if !ready {
			let w = self.wait_with_holds(&info, &rounds, held_left)?;
			v["final_in_seconds"] = json!(w.most);
			v["usual_in_seconds"] = json!(w.usual);
			v["waiting_for"] = json!(w.step.name());
		}
		Ok(v)
	}

	/// How [`Self::settle_first_spread`] cuts a refresh of `asset`: pieces
	/// of what size, and at most how many, the rest one reserve coin
	/// ([`super::round::pieces_of`]); `None` for one coin. The wallet's
	/// holding of the asset `h` (its own coins live, in a refresh or in a
	/// round) keeps at most half in up to [`SPREAD_PIECES`] working pieces
	/// of `h` / 6, and the rest in one reserve coin: at most
	/// [`SPREAD_PIECES`] + 1 coins with the wallet's others of the asset
	/// (`giving` are those the refresh gives up), as many as the makers
	/// keep working,
	/// and a trade of up to half the holding still goes from one coin. A
	/// piece is never below [`SPREAD_LEAF_MULTIPLE`] times the operator's
	/// smallest leaf, nor below [`SPREAD_EXIT_MULTIPLE`] times what one
	/// coin's exit costs on the chain at the reserves' cover of the node's
	/// floor ([`SPREAD_EXIT_VSIZE`] vbytes), so a small holding stays one
	/// coin and the pieces grow in number with the holding. A supervised
	/// asset's leaf is a landing leaf, which is not cut: one coin.
	pub(crate) fn spread_of(&self, info: &Value, asset: AssetId, giving: &[String]) -> Result<Option<(u64, usize)>, Error> {
		if self.landing_rule(info, asset)?.is_some() {
			return Ok(None);
		}
		let (mut held, mut others): (u64, usize) = (0, 0);
		// A coin held out as spent by another device is not the wallet's to count.
		let elsewhere = self.spent_elsewhere()?;
		for c in self.store.coins_in_states(&["live", "given", "pending", "forfeited"])? {
			if c.asset != asset.to_string() || super::resting::is_order_coin(&c) || self.channel_worth(&c)?.is_some()
				|| elsewhere.contains(&c.leaf_id)
			{
				continue;
			}
			held = held.saturating_add(c.value);
			others += usize::from(!giving.contains(&c.leaf_id));
		}
		let min = Self::min_leaf(info, asset)?;
		let exit = self.chain.floor_per_kvb(asset)?
			.map(|f| SPREAD_EXIT_VSIZE.saturating_mul(f).saturating_mul(super::wallet::RESERVE_MULTIPLE) / 1_000).unwrap_or(0);
		Ok(spread_plan(held, min, exit, others))
	}

	/// `ids` as `settle_first` sorts them: the live ones it gives up, the
	/// ones that wait for a round as they are, the ones that are through,
	/// and the round each waiting one waits for (`None` or empty for one not
	/// built yet; a live one, once given up, waits for one not built yet).
	fn sorted(&self, ids: Vec<String>) -> Result<Sorted, Error> {
		let (mut give, mut waiting, mut done) = (vec![], vec![], vec![]);
		let mut rounds: Vec<Option<String>> = vec![];
		let elsewhere = self.spent_elsewhere_until()?;
		let now = if elsewhere.is_empty() { 0 } else { self.now()?.to_consensus_u32() };
		let mut held_left: Option<u64> = None;
		for id in ids {
			let Some(c) = self.store.coin(&id)? else {
				done.push(id);
				continue;
			};
			// Another store's round spends it: never given up here; it waits
			// for that round, which this store learns of only once a
			// catch-up finds it released, or for its hold to end, whichever
			// is first: the hold's end is the wait that really ends.
			if let Some(until) = elsewhere.get(&id) {
				let left = u64::from(until.saturating_sub(now));
				held_left = Some(held_left.map_or(left, |h| h.max(left)));
				waiting.push(id);
				continue;
			}
			match c.state.as_str() {
				"live" => give.push(id),
				"given" => {
					// The round the operator built for it, once the wallet has
					// read it (a held round, before its forfeits); else none yet.
					rounds.push(Self::participation_of(&c).and_then(|p| self.store.participation(&p).ok().flatten()).and_then(|p| p.6));
					waiting.push(id);
				},
				"pending" => {
					rounds.push(c.bases.last().cloned());
					waiting.push(id);
				},
				"forfeited" | "spent" => match self.made_by_round_waits(&c)? {
					Some(round) => {
						rounds.push(Some(round));
						waiting.push(id);
					},
					None => done.push(id),
				},
				_ => done.push(id),
			}
		}
		Ok(Sorted { give, waiting, done, rounds, held_left })
	}

	/// The wait of `rounds` together: the round furthest from done names the
	/// step waited for, the most it takes and what it usually takes.
	/// [`Self::wait_of`] `rounds`, and `held_left` seconds for a coin held
	/// out as spent elsewhere, whose hold ends then at the latest.
	fn wait_with_holds(&self, info: &Value, rounds: &[Option<String>], held_left: Option<u64>) -> Result<Within, Error> {
		let mut w = if rounds.is_empty() { Within { most: 0, usual: 0, step: Wait::Release } } else { self.wait_of(info, rounds)? };
		if let Some(h) = held_left {
			w.most = w.most.max(h);
			w.usual = w.usual.max(h);
			w.step = w.step.min(Wait::Round);
		}
		Ok(w)
	}

	fn wait_of(&self, info: &Value, rounds: &[Option<String>]) -> Result<Within, Error> {
		let mut out = Within { most: 0, usual: 0, step: Wait::Release };
		for r in rounds {
			let w = self.final_within(info, r.as_deref())?;
			out.most = out.most.max(w.most);
			out.usual = out.usual.max(w.usual);
			out.step = out.step.min(w.step);
		}
		Ok(out)
	}

	/// How long the coins a [`Error::SettleFirst`] names wait, as
	/// `settle_first` would answer once asked for them: `(final_in_seconds,
	/// usual_in_seconds, waiting_for)`, the refusal's own reading of when the
	/// spend can be asked again. `None` when it cannot be read now.
	pub(crate) fn settle_wait(&self, coins: &[String]) -> Option<(u64, u64, &'static str)> {
		let info = self.server_info().ok()?;
		let Sorted { give, rounds, held_left, .. } = self.sorted(coins.to_vec()).ok()?;
		let mut rounds = rounds;
		if !give.is_empty() {
			rounds.push(None);
		}
		if rounds.is_empty() && held_left.is_none() {
			return None;
		}
		let w = self.wait_with_holds(&info, &rounds, held_left).ok()?;
		Some((w.most, w.usual, w.step.name()))
	}

	/// For a coin given up (`forfeited`) or spent (`spent`) by a
	/// participation of the wallet's own, while the coins that participation
	/// makes, or the coin itself, cannot be spent yet: the round they wait
	/// for, empty for a round not built yet.
	/// - The participation waits for a round (`submitting`, `pending`), as
	///   after a held round it was in was dropped: a round not built yet.
	/// - Its forfeits are signed and the operator's preimage is still to
	///   come (`issued`, `forfeiting`): its round, unless that round was held
	///   and is neither in a block nor in the mempool, and the operator says
	///   the participation waits for a round again (the held round dropped):
	///   a round not built yet.
	/// - It is released and a coin it made is `pending` (its round not
	///   final): its round.
	/// - It is void or expired, and the operator gave the coin back while a
	///   forfeit it signed for a round that is not gone stands (D75, marked
	///   by `given_back_key`): the coin is the wallet's again once that round
	///   can no longer confirm, and then goes into a round anew, so a round
	///   not built yet. A coin the operator keeps under its forfeit is not
	///   waiting for a round: it goes home by the claim, the refund or its
	///   exit.
	/// `None` once they can be spent, or for a coin spent otherwise.
	fn made_by_round_waits(&self, c: &CoinRow) -> Result<Option<String>, Error> {
		// The participation its note or `spent_by` names, else, for a coin
		// held under a forfeit, the one its latest forfeit was signed for.
		let pid = match Self::participation_of(c) {
			Some(p) => p,
			None if c.state == "forfeited" => match self.store.forfeits_of(&c.leaf_id)?.into_iter().last() {
				Some(f) => f.participation,
				None => return Ok(None),
			},
			None => return Ok(None),
		};
		let Some((_, _, _, _, state, _, round)) = self.store.participation(&pid)? else { return Ok(None) };
		let round = round.or_else(|| self.store.participation_news(&pid).ok().flatten()
			.and_then(|n| serde_json::from_str::<Value>(&n).ok()).and_then(|n| n["round"].as_str().map(str::to_string)));
		match state.as_str() {
			"submitting" | "pending" => Ok(Some(String::new())),
			"issued" | "forfeiting" => {
				let round = round.unwrap_or_default();
				// A held round neither in a block nor in the node's mempool may
				// have been dropped, the participation waiting for a round again:
				// the operator says which.
				if let Ok(txid) = elements::Txid::from_str(&round) {
					if matches!(self.chain.finality(&txid)?, Finality::NotInChain { in_mempool: false }) {
						if let Ok(st) = self.server.post("participation_status", &json!({"participation_id": pid})) {
							if st["state"] == "pending" {
								return Ok(Some(String::new()));
							}
						}
					}
				}
				Ok(Some(round))
			},
			"released" => {
				let Some(round) = round else { return Ok(None) };
				let made_pending = self.store.coins_in("pending")?.into_iter().any(|n| n.bases.contains(&round));
				Ok(made_pending.then_some(round))
			},
			"void" | "expired" if c.state == "forfeited" && self.store.meta(&super::round::given_back_key(&c.leaf_id))?.is_some() => {
				Ok(Some(String::new()))
			},
			_ => Ok(None),
		}
	}

	/// The most seconds until `round` (a txid; empty or `None` for a round
	/// not built yet) is final at the operator's anchor depth and its coins
	/// are the wallet's, and the step it waits for now. Each step counts
	/// every step after it: the operator's next round when it is not built
	/// (`fills.round_interval_seconds`); for a round built and held
	/// unbroadcast (neither in a block nor in the node's mempool), the
	/// operator's window for the other participations' forfeits
	/// (`fills.forfeit_window_seconds`); a block for its transaction to be
	/// mined and one more for the certificate a block above may carry
	/// (`fills.block_seconds`); a Bitcoin block for each anchor block still
	/// to bury it; and one round interval for the operator's release of the
	/// new coins, which it makes in its pass over the rounds once it holds
	/// the round final. An operator whose batches have no sweep
	/// (`batches.no_sweep`) holds every round so, so a round not built yet
	/// counts that window too. What it usually takes counts a round interval
	/// for the forfeits in place of the window.
	pub(crate) fn final_within(&self, info: &Value, round: Option<&str>) -> Result<Within, Error> {
		let txid = round.and_then(|t| elements::Txid::from_str(t).ok());
		let finality = match txid {
			Some(t) => Some(self.chain.finality(&t)?),
			None => None,
		};
		Ok(wait_counts(info, self.chain.anchor_depth(), finality.as_ref()))
	}

	/// `coin_places`: every coin the wallet holds in a place (with its kind:
	/// a `board` arriving waits on its board's block and anchor), the totals of
	/// each place by asset, what can be spent now by asset (`settled`,
	/// `proceeds` and `counted` coins that are live), and the instant limit.
	/// Each coin says whether the wallet counts it at risk out of round now
	/// (`at_risk`): what the operator, with someone other than the wallet,
	/// could take by signing twice, which the bond and the instant budget
	/// weigh ([`super::bond`]); the coins so marked sum, by asset, to the
	/// bond answer's `out_of_round`. A caller reads that mark, not the
	/// lineage and the state, to know what counts against the budget. When a
	/// coin's record cannot be read the mark is `null` for every coin and
	/// `at_risk_error` says why; the places still answer.
	/// See the [module documentation](self).
	pub fn coin_places(&self) -> Result<Value, Error> {
		let p = self.places()?;
		// Unknown (`null`) for every coin, with why, when it cannot be read: the
		// places still answer.
		let (at_risk, at_risk_error) = match self.at_risk_coins() {
			Ok(cs) => (Some(cs.into_iter().map(|c| c.leaf_id).collect::<BTreeSet<String>>()), None),
			Err(e) => (None, Some(e.to_string())),
		};
		// A coin held out as spent elsewhere is the wallet's still, and not
		// spendable now ([`Wallet::spent_elsewhere`]).
		let held = self.spent_elsewhere_until()?;
		let mut totals: BTreeMap<String, BTreeMap<&'static str, u128>> = BTreeMap::new();
		let mut spendable: BTreeMap<String, u128> = BTreeMap::new();
		let mut coins = vec![];
		for (c, lineage, place) in &p.coins {
			*totals.entry(c.asset.clone()).or_default().entry(place.name()).or_default() += c.value as u128;
			if c.state == "live" && *place != Place::Arriving && !p.channels.contains(&c.leaf_id) && !held.contains_key(&c.leaf_id) {
				*spendable.entry(c.asset.clone()).or_default() += c.value as u128;
			}
			let hops = Self::record_of(c).map(|r| record_hops(&r)).unwrap_or(0);
			let mut v = json!({"leaf_id": c.leaf_id, "asset": c.asset, "value": c.value.to_string(), "state": c.state, "kind": c.kind,
				"lineage": match lineage { Lineage::Own => "own", Lineage::Trade => "trade", Lineage::Received => "received" },
				"place": place.name(), "hops": hops, "at_risk": at_risk.as_ref().map(|a| a.contains(&c.leaf_id))});
			if p.channels.contains(&c.leaf_id) {
				v["channel"] = json!(true);
			}
			if let Some(until) = held.get(&c.leaf_id) {
				v["spent_elsewhere_until"] = json!(until);
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
			"unvalued": p.unvalued, "at_risk_error": at_risk_error,
		}))
	}
}
