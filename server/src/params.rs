//! The operator's published parameters: what the server accepts, and the
//! bounds every leaf it takes part in must keep.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::AssetId;

use arca_covenant::record::MAX_VALUE;
use arca_covenant::transfer::DEPTH_LIMIT;
use arca_covenant::{Chain, MedianTime, RelativeTime, ReserveFloor, WalletPolicy};

use crate::rates::{atoms_of, unix_now, RateConfig, RateError, Rates};

/// An amount the operator sets: in the asset's atoms, or as a value in
/// atoms of the reference unit, taken in the asset's atoms at its rate
/// ([`crate::rates`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Amount {
	Atoms(u64),
	Value(u64),
}

impl Default for Amount {
	fn default() -> Amount {
		Amount::Atoms(0)
	}
}

impl Amount {
	/// The amount in the asset's atoms at `rate`, rounded up; `None` for a
	/// value with no rate to take it at.
	pub fn atoms(&self, rate: Option<u64>) -> Option<u64> {
		match self {
			Amount::Atoms(a) => Some(*a),
			Amount::Value(0) => Some(0),
			Amount::Value(v) => rate.map(|r| atoms_of(*v, r)),
		}
	}

	/// The value set, when the amount is one.
	pub fn value(&self) -> Option<u64> {
		match self {
			Amount::Atoms(_) => None,
			Amount::Value(v) => Some(*v),
		}
	}
}

/// What the operator charges in one asset, as it sets it: the parts per
/// million of a refresh and of an offboard, and a fixed part of each, in the
/// asset's atoms or as a value ([`Amount`]). Taken in atoms at the asset's
/// rate, it is the asset's [`FeeSchedule`] ([`Params::fees`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AssetFees {
	pub refresh_ppm: u64,
	pub offboard_ppm: u64,
	pub refresh_base: Amount,
	pub offboard_base: Amount,
	/// A payment over Lightning, either way: parts per million of what it
	/// moves, and a fixed part.
	pub lightning_ppm: u64,
	pub lightning_base: Amount,
}

/// What the operator serves for one asset.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AssetParams {
	/// The smallest leaf the operator takes, in the asset's atoms: a leaf
	/// smaller than its own exit cost is not protected.
	pub min_leaf: u64,
	/// The smallest leaf as a value, in atoms of the reference unit, when the
	/// operator sets it so: converted at the asset's rate, it takes the place
	/// of `min_leaf` ([`Params::min_leaf`]).
	pub min_leaf_value: Option<u64>,
	/// Where the asset's rate comes from ([`crate::rates`]); none when the
	/// operator prices nothing of the asset from a rate.
	pub rate: Option<RateConfig>,
	/// What the operator charges in the asset.
	pub fees: AssetFees,
}

/// The assets the operator serves, in the order its configuration lists
/// them, and the assets a round's fee is paid in. Every component reads
/// them through one shared handle, so an asset added to the configuration
/// is served by every entry, every round and the watcher at once when the
/// server reloads its configuration ([`crate::server::Server::reload`]),
/// without a restart. Each asset has a pool of its own: the operator's
/// wallet's coins of that asset, which fund that asset's batches and
/// nothing else, and its own rounds, which carry that asset alone.
#[derive(Debug, Clone, Default)]
pub struct Assets(Arc<RwLock<Served>>);

#[derive(Debug, Clone, Default)]
struct Served {
	order: Vec<AssetId>,
	map: BTreeMap<AssetId, AssetParams>,
	/// The assets a round's fee is paid in, as configured; the served assets,
	/// in their order, when the configuration names none.
	fee_assets: Option<Vec<AssetId>>,
	/// The schedule an asset takes where it sets none of its own, as
	/// `[fees]` sets it.
	default_fees: FeeSchedule,
}

impl Assets {
	/// `list`, in its order, each asset once.
	pub fn new(list: Vec<(AssetId, AssetParams)>, fee_assets: Option<Vec<AssetId>>) -> Assets {
		let a = Assets::default();
		a.replace(list, fee_assets);
		a
	}

	/// Serves `list` from now on, in its order, and pays rounds' fees in
	/// `fee_assets` (the served assets, in order, when `None`).
	pub fn replace(&self, list: Vec<(AssetId, AssetParams)>, fee_assets: Option<Vec<AssetId>>) {
		let default_fees = self.read().default_fees;
		let mut served = Served { fee_assets, default_fees, ..Default::default() };
		for (a, p) in list {
			if served.map.insert(a, p).is_none() {
				served.order.push(a);
			}
		}
		*self.0.write().unwrap_or_else(|e| e.into_inner()) = served;
	}

	fn read(&self) -> std::sync::RwLockReadGuard<'_, Served> {
		self.0.read().unwrap_or_else(|e| e.into_inner())
	}

	/// What the operator serves for `asset`, if it serves it.
	pub fn get(&self, asset: &AssetId) -> Option<AssetParams> {
		self.read().map.get(asset).cloned()
	}

	pub fn contains(&self, asset: &AssetId) -> bool {
		self.read().map.contains_key(asset)
	}

	/// The assets served, in the configuration's order.
	pub fn ids(&self) -> Vec<AssetId> {
		self.read().order.clone()
	}

	/// The assets served with what is served of each, in the
	/// configuration's order.
	pub fn all(&self) -> Vec<(AssetId, AssetParams)> {
		let s = self.read();
		s.order.iter().map(|a| (*a, s.map[a].clone())).collect()
	}

	/// The schedule an asset takes where it sets none of its own (`[fees]`),
	/// published at the top of `info` for wallets that read no asset's own.
	pub fn default_fees(&self) -> FeeSchedule {
		self.read().default_fees
	}

	/// Sets [`Assets::default_fees`].
	pub fn set_default_fees(&self, fees: FeeSchedule) {
		self.0.write().unwrap_or_else(|e| e.into_inner()).default_fees = fees;
	}

	/// The assets a round's fee is paid in, in order of preference.
	pub fn fee_assets(&self) -> Vec<AssetId> {
		let s = self.read();
		s.fee_assets.clone().unwrap_or_else(|| s.order.clone())
	}
}

/// What the operator charges in one asset, in that asset's atoms. Transfers
/// inside the tree are free. A refresh, or an offboard, costs nothing in the free window, the
/// two days before a coin's exit deadline: from [`FeeSchedule::FREE_FROM`]
/// (five days) before its first expiry to three days before it, where the
/// operator stops taking it ([`Params::participation_policy`]). Before the
/// window the fee rises with the time left beyond it, to `refresh_ppm` parts
/// per million of the coin's value for a coin [`FeeSchedule::FULL_AFTER`] or
/// more from the window. A coin resting on a board takes the board's service
/// expiry for its first expiry, when that comes first ([`Params::BOARD_LIFETIME`]).
/// The fixed part of a refresh, `refresh_base` for each coin given up, is
/// charged as its proportional part is: in full 23 days or more before the
/// window, falling to nothing in it. An offboard adds `offboard_ppm` of what
/// it pays out, `offboard_base`, and the margin of the output the round
/// pays, which the unlock spends as its fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FeeSchedule {
	pub refresh_ppm: u64,
	pub offboard_ppm: u64,
	/// The fixed part of a refresh for each coin given up, in atoms.
	pub refresh_base: u64,
	/// The fixed part of an offboard, in atoms.
	pub offboard_base: u64,
	/// A payment over Lightning, either way: parts per million of what it
	/// moves, and a fixed part in atoms.
	pub lightning_ppm: u64,
	pub lightning_base: u64,
}

impl FeeSchedule {
	/// A refresh costs nothing from five days before a coin's first expiry:
	/// the two days before its exit deadline.
	pub const FREE_FROM: u32 = 5 * 86_400;
	/// The time left beyond the free window at which the whole refresh fee is
	/// due: the rest of a 28-day batch.
	pub const FULL_AFTER: u32 = 23 * 86_400;

	/// The refresh fee for a coin of `value` whose earliest expiry is
	/// `expiry`, at `now`.
	pub fn refresh(&self, value: u64, expiry: MedianTime, now: MedianTime) -> u64 {
		let left = expiry.to_consensus_u32().saturating_sub(now.to_consensus_u32()).saturating_sub(Self::FREE_FROM);
		let charged = left.min(Self::FULL_AFTER) as u128;
		let full = value as u128 * self.refresh_ppm as u128 + self.refresh_base as u128 * 1_000_000;
		let fee = (full * charged).div_ceil(Self::FULL_AFTER as u128 * 1_000_000);
		fee.min(u64::MAX as u128) as u64
	}

	/// The fee for a payment over Lightning of `amount`, either way: its
	/// parts per million, rounded up, and the fixed part.
	pub fn lightning(&self, amount: u64) -> u64 {
		let fee = (amount as u128 * self.lightning_ppm as u128).div_ceil(1_000_000) + self.lightning_base as u128;
		fee.min(u64::MAX as u128) as u64
	}

	/// The offboard fee for paying out `value`, the round's output holding
	/// `margin` more for its unlock.
	pub fn offboard(&self, value: u64, margin: u64) -> u64 {
		let fee = (value as u128 * self.offboard_ppm as u128).div_ceil(1_000_000) + self.offboard_base as u128 + margin as u128;
		fee.min(u64::MAX as u128) as u64
	}
}

/// The operator's published parameters. See the [module documentation](self).
#[derive(Debug, Clone)]
pub struct Params {
	/// The chain, named by its genesis hash.
	pub chain: Chain,
	/// The operator key `S`.
	pub operator: XOnlyPublicKey,
	/// The bounds on every leaf's exit delay.
	pub min_exit_delay: RelativeTime,
	pub max_exit_delay: RelativeTime,
	/// The assets served, each with its own minimum leaf, and the assets a
	/// round's fee is paid in: a live table ([`Assets`]).
	pub assets: Assets,
	/// The operator's rate for each asset that names a source
	/// ([`crate::rates`]): shared, as `assets` is.
	pub rates: Rates,
	/// The most reassignments a coin may be from a round or a board.
	pub depth_limit: usize,
	/// The delay after which the owner of a leaf given up may take its
	/// forfeit back: long enough for the operator to claim it, and well
	/// before a new batch's exit deadline.
	pub refund_delay: RelativeTime,
	/// How long after a round confirms the operator may reclaim an offboard
	/// output nobody unlocked: longer than unrolling the leaf given up, its
	/// exit delay, the forfeit's refund delay and a margin to unlock.
	pub offboard_reclaim_delay: RelativeTime,
	/// The most margin a co-signed transfer may leave, as a multiple of the
	/// least: four times the node's floor in an asset it accepts for fees,
	/// one atom in one it does not.
	pub max_margin_multiple: u64,
}

/// The default cap on a transfer's margins, as a multiple of the least.
pub const MAX_MARGIN_MULTIPLE: u64 = 25;

impl Params {
	/// The specification's parameters: an exit delay of 36 to 48 hours and a
	/// depth limit of 5.
	pub fn new(chain: Chain, operator: XOnlyPublicKey, assets: BTreeMap<AssetId, AssetParams>) -> Params {
		let any_time = MedianTime::from_consensus(arca_covenant::time::LOCKTIME_THRESHOLD).expect("the first time");
		let spec = WalletPolicy::new(chain, operator, any_time);
		let rates = Rates::default();
		rates.configure(&assets.iter().map(|(a, p)| (*a, p.rate.clone())).collect::<Vec<_>>());
		let assets = Assets::new(assets.into_iter().collect(), None);
		let mut p = Params {
			chain, operator,
			rates,
			min_exit_delay: spec.min_exit_delay,
			max_exit_delay: spec.max_exit_delay,
			assets,
			depth_limit: DEPTH_LIMIT,
			refund_delay: spec.max_exit_delay,
			offboard_reclaim_delay: spec.max_exit_delay,
			max_margin_multiple: MAX_MARGIN_MULTIPLE,
		};
		p.set_delays();
		p
	}

	/// Sets the forfeit's refund delay and the offboard's reclaim delay from
	/// the exit-delay bounds: the refund delay is the longest exit delay, and
	/// the reclaim delay that plus the longest exit delay plus two days (one
	/// to unroll the leaf given up, one to unlock the output).
	pub fn set_delays(&mut self) {
		self.refund_delay = self.max_exit_delay;
		let units = 2 * self.max_exit_delay.units() as u32 + (2 * 86_400u32).div_ceil(512);
		self.offboard_reclaim_delay = RelativeTime::from_units(units.min(u16::MAX as u32) as u16).expect("a relative time");
	}

	/// The assets the operator pays a round's fee in, in order of
	/// preference: a round pays in its own asset when the node accepts it for
	/// fees and it is on this list, or else in the first of these the node
	/// accepts. Never an asset outside this list, and never one the node does
	/// not accept.
	pub fn fee_assets(&self) -> Vec<AssetId> {
		self.assets.fee_assets()
	}

	pub fn exit_delay_ok(&self, delay: RelativeTime) -> bool {
		(self.min_exit_delay.units()..=self.max_exit_delay.units()).contains(&delay.units())
	}

	/// Serves `list` from now on, in its order, with each asset's rate
	/// source, and pays rounds' fees in `fee_assets` (the served assets, in
	/// order, when `None`).
	pub fn serve(&self, list: Vec<(AssetId, AssetParams)>, fee_assets: Option<Vec<AssetId>>) {
		self.rates.configure(&list.iter().map(|(a, p)| (*a, p.rate.clone())).collect::<Vec<_>>());
		self.assets.replace(list, fee_assets);
	}

	/// The smallest leaf of `asset` the operator takes now, in the asset's
	/// atoms: its `min_leaf`, or its `min_leaf_value` at the asset's last
	/// rate, rounded up. A rate gone stale still sets it: new work in the
	/// asset is refused before it is asked ([`Params::fresh_rate`]), and work
	/// already taken goes on.
	pub fn min_leaf(&self, asset: &AssetId) -> Result<u64, String> {
		let a = self.assets.get(asset).ok_or_else(|| format!("asset {} is not served by this operator", asset))?;
		match a.min_leaf_value {
			None => Ok(a.min_leaf),
			Some(v) => match self.rates.last(asset) {
				Some(rate) => Ok(atoms_of(v, rate).max(1)),
				None => Err(format!("asset {}'s smallest leaf is a value of {} in the reference unit, and the operator has no rate for \
					it yet", asset, v)),
			},
		}
	}

	/// What the operator charges in `asset` now, in its atoms: its
	/// [`AssetFees`], a value taken at the asset's last rate. A rate gone
	/// stale still sets it, as for [`Params::min_leaf`].
	pub fn fees(&self, asset: &AssetId) -> Result<FeeSchedule, String> {
		let a = self.assets.get(asset).ok_or_else(|| format!("asset {} is not served by this operator", asset))?;
		let rate = self.rates.last(asset);
		let atoms = |what: &str, x: Amount| x.atoms(rate).ok_or_else(|| format!("asset {}'s {} is a value of {} in the reference unit, \
			and the operator has no rate for it yet", asset, what, x.value().unwrap_or(0)));
		Ok(FeeSchedule {
			refresh_ppm: a.fees.refresh_ppm,
			offboard_ppm: a.fees.offboard_ppm,
			refresh_base: atoms("refresh_base", a.fees.refresh_base)?,
			offboard_base: atoms("offboard_base", a.fees.offboard_base)?,
			lightning_ppm: a.fees.lightning_ppm,
			lightning_base: atoms("lightning_base", a.fees.lightning_base)?,
		})
	}

	/// `asset`'s rate for new work now: `None` for an asset with no rate
	/// source, else its rate while it is fresh, and why the server takes no
	/// new work in the asset (a board, a participation) otherwise.
	pub fn fresh_rate(&self, asset: &AssetId) -> Result<Option<u64>, RateError> {
		self.rates.fresh(asset, unix_now())
	}

	/// Why a leaf of `asset` and `value` is outside the published bounds, if
	/// it is.
	pub fn check_value(&self, asset: AssetId, value: u64) -> Result<(), String> {
		let min = self.min_leaf(&asset)?;
		if value < min {
			return Err(format!("{} atoms is below the smallest leaf of asset {}, {}", value, asset, min));
		}
		if value > MAX_VALUE {
			return Err(format!("{} atoms is above the largest value a leaf holds, {}", value, MAX_VALUE));
		}
		Ok(())
	}

	/// The policy a coin given up in a participation is checked under when
	/// the participation is accepted, at `now`: [`Params::policy`], whose
	/// horizon is the exit deadline. A participation accepts a coin only up to
	/// its exit deadline, three days before its first expiry: past it the
	/// owner should be exiting, and a refresh that stalled would leave no time
	/// to.
	pub fn participation_policy(&self, now: MedianTime) -> WalletPolicy {
		WalletPolicy { horizon: Self::PARTICIPATION_HORIZON, ..self.policy(now) }
	}

	/// How long before its first expiry a coin may still be given up, in
	/// seconds: the exit deadline, three days.
	pub const PARTICIPATION_HORIZON: u32 = WalletPolicy::EXIT_DEADLINE;

	/// The policy a pending participation's coins are checked under when a
	/// round is built, and at every pass over the rounds, at `now`: the same
	/// horizon, the exit deadline. A pending participation with a coin past
	/// its exit deadline can never run and is voided, its coins given back:
	/// from then on the coin's owner takes it on the chain, and a round
	/// that took it after would leave no time to.
	pub fn round_policy(&self, now: MedianTime) -> WalletPolicy {
		WalletPolicy { horizon: Self::PARTICIPATION_HORIZON, ..self.policy(now) }
	}

	/// How long the operator serves a board, and every coin resting on it, in
	/// seconds from the median time of the block that confirms the board: a
	/// batch's lifetime, 28 days, so that a board carries the dates a batch
	/// made then would have. Its exit deadline is [`WalletPolicy::EXIT_DEADLINE`]
	/// before its expiry. Up to the exit deadline the server co-signs spends of
	/// a coin resting on the board and takes it into a refresh, as for a coin
	/// resting on a batch; after it, the coin's owner takes it on the chain.
	/// The watcher publishes the lineage of a forfeited coin resting on boards
	/// before the expiry only when no coin another holder may still hold rests
	/// on it, or to answer an exit.
	pub const BOARD_LIFETIME: u32 = 28 * 86_400;

	/// The service expiry of a board confirmed in a block of median time
	/// `confirmed`.
	pub fn board_expiry(confirmed: u32) -> u32 {
		confirmed.saturating_add(Self::BOARD_LIFETIME)
	}

	/// How long after its round is final a participation's forfeits may come
	/// and be co-signed at least, in seconds: one day. They are taken until
	/// the later of that and the exit deadline of the coins the participation
	/// gave up ([`crate::rounds::Rounds::exit_deadline_of`]), so a refresh
	/// asked for in a coin's free window completes at any sync before the
	/// coin's exit date. A participation not released by then expires, whether
	/// its forfeits never came or came and were never co-signed (the signer
	/// away, or its keepers): each forfeit without the operator's half is
	/// dropped, never to be asked for again, the coins it gave up are the
	/// owner's again (one under a forfeit the operator holds whole excepted),
	/// and its new leaves, whose preimage never goes out, are swept with their
	/// batch.
	pub const FORFEIT_DEADLINE: u32 = 86_400;

	/// The policy the server checks records and coins under, at `now`: its
	/// own chain and key, its exit-delay bounds, and the receipt horizon (a
	/// coin's first expiry past the exit deadline), as a receiver would.
	pub fn policy(&self, now: MedianTime) -> WalletPolicy {
		WalletPolicy {
			min_exit_delay: self.min_exit_delay,
			max_exit_delay: self.max_exit_delay,
			min_reserve: ReserveFloor::Atoms(1),
			..WalletPolicy::new(self.chain, self.operator, now).receipt()
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn t(s: u32) -> MedianTime {
		MedianTime::from_consensus(s).unwrap()
	}

	#[test]
	fn a_refresh_is_free_in_the_two_days_before_the_exit_deadline() {
		const DAY: u32 = 86_400;
		let f = FeeSchedule { refresh_ppm: 23_000, ..Default::default() };
		let e = 1_800_000_000;
		let value = 1_000_000;
		// 23,000 ppm of a million atoms is 23,000 atoms for 23 days or more
		// before the window: 1,000 atoms a day.
		assert_eq!(f.refresh(value, t(e), t(e - 28 * DAY)), 23_000);
		assert_eq!(f.refresh(value, t(e), t(e - 6 * DAY)), 1_000, "a day before the window");
		assert_eq!(f.refresh(value, t(e), t(e - 5 * DAY - 1)), 1, "a second before the window, rounded up");
		assert_eq!(f.refresh(value, t(e), t(e - 5 * DAY)), 0, "the window opens five days before the expiry");
		assert_eq!(f.refresh(value, t(e), t(e - 4 * DAY)), 0);
		assert_eq!(f.refresh(value, t(e), t(e - 3 * DAY)), 0, "free up to the exit deadline");
		assert_eq!(FeeSchedule::FREE_FROM - Params::PARTICIPATION_HORIZON, 2 * DAY, "the window is two days");
	}

	#[test]
	fn a_fixed_part_falls_with_the_proportional_one() {
		const DAY: u32 = 86_400;
		let e = 1_800_000_000;
		// 2,300 atoms a coin and nothing in proportion: 100 atoms a day
		// before the window.
		let f = FeeSchedule { refresh_base: 2_300, ..Default::default() };
		assert_eq!(f.refresh(1_000_000, t(e), t(e - 28 * DAY)), 2_300);
		assert_eq!(f.refresh(5, t(e), t(e - 6 * DAY)), 100, "whatever the coin's value");
		assert_eq!(f.refresh(1_000_000, t(e), t(e - 5 * DAY)), 0, "nothing in the free window");
		// Both parts together are charged as one.
		let g = FeeSchedule { refresh_ppm: 23_000, refresh_base: 2_300, ..Default::default() };
		assert_eq!(g.refresh(1_000_000, t(e), t(e - 28 * DAY)), 23_000 + 2_300);
		let o = FeeSchedule { offboard_ppm: 1_000, offboard_base: 500, ..Default::default() };
		assert_eq!(o.offboard(1_000_000, 70), 1_000 + 500 + 70);
	}

	#[test]
	fn an_amount_set_as_a_value_is_taken_at_the_rate() {
		assert_eq!(Amount::Atoms(7).atoms(None), Some(7));
		assert_eq!(Amount::Value(1_000).atoms(None), None);
		assert_eq!(Amount::Value(0).atoms(None), Some(0));
		assert_eq!(Amount::Value(1_000).atoms(Some(250_000_000)), Some(400));
	}

	#[test]
	fn a_board_carries_the_dates_of_a_batch_made_when_it_confirmed() {
		assert_eq!(Params::BOARD_LIFETIME, crate::rounds::RoundConfig::default().lifetime, "a batch's lifetime");
		assert_eq!(Params::board_expiry(1_800_000_000), 1_800_000_000 + 28 * 86_400);
		assert_eq!(Params::board_expiry(u32::MAX - 1), u32::MAX);
	}
}
