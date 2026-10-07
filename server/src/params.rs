//! The operator's published parameters: what the server accepts, and the
//! bounds every leaf it takes part in must keep.

use std::collections::BTreeMap;

use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::AssetId;

use arca_covenant::record::MAX_VALUE;
use arca_covenant::transfer::DEPTH_LIMIT;
use arca_covenant::{Chain, MedianTime, RelativeTime, ReserveFloor, WalletPolicy};

/// What the operator serves for one asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetParams {
	/// The smallest leaf the operator takes, in the asset's atoms: a leaf
	/// smaller than its own exit cost is not protected.
	pub min_leaf: u64,
}

/// What the operator charges, in the asset moved. Transfers inside the tree
/// are free. A refresh, or an offboard, costs nothing in the free window, the
/// two days before a coin's exit deadline: from [`FeeSchedule::FREE_FROM`]
/// (five days) before its first expiry to three days before it, where the
/// operator stops taking it ([`Params::participation_policy`]). Before the
/// window the fee rises with the time left beyond it, to `refresh_ppm` parts
/// per million of the coin's value for a coin [`FeeSchedule::FULL_AFTER`] or
/// more from the window. A coin resting on a board takes the board's service
/// expiry for its first expiry, when that comes first ([`Params::BOARD_LIFETIME`]).
/// An offboard adds `offboard_ppm` of what it pays out, and the
/// margin of the output the round pays, which the unlock spends as its fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FeeSchedule {
	pub refresh_ppm: u64,
	pub offboard_ppm: u64,
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
		let fee = (value as u128 * self.refresh_ppm as u128 * charged).div_ceil(Self::FULL_AFTER as u128 * 1_000_000);
		fee.min(u64::MAX as u128) as u64
	}

	/// The offboard fee for paying out `value`, the round's output holding
	/// `margin` more for its unlock.
	pub fn offboard(&self, value: u64, margin: u64) -> u64 {
		let fee = (value as u128 * self.offboard_ppm as u128).div_ceil(1_000_000) + margin as u128;
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
	/// The assets served, each with its own minimum leaf.
	pub assets: BTreeMap<AssetId, AssetParams>,
	/// The most reassignments a coin may be from a round or a board.
	pub depth_limit: usize,
	/// The assets the operator pays a round's fee in, in order of preference:
	/// a round pays in the first of its own batches' assets the node accepts
	/// for fees, or else in the first of these it accepts. Never an asset
	/// outside this list, and never one the node does not accept.
	pub fee_assets: Vec<AssetId>,
	pub fees: FeeSchedule,
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
		let fee_assets = assets.keys().copied().collect();
		let mut p = Params {
			chain, operator,
			min_exit_delay: spec.min_exit_delay,
			max_exit_delay: spec.max_exit_delay,
			assets,
			depth_limit: DEPTH_LIMIT,
			fee_assets,
			fees: FeeSchedule::default(),
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

	pub fn exit_delay_ok(&self, delay: RelativeTime) -> bool {
		(self.min_exit_delay.units()..=self.max_exit_delay.units()).contains(&delay.units())
	}

	/// Why a leaf of `asset` and `value` is outside the published bounds, if
	/// it is.
	pub fn check_value(&self, asset: AssetId, value: u64) -> Result<(), String> {
		let a = self.assets.get(&asset).ok_or_else(|| format!("asset {} is not served by this operator", asset))?;
		if value < a.min_leaf {
			return Err(format!("{} atoms is below the smallest leaf of asset {}, {}", value, asset, a.min_leaf));
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
	/// and be co-signed, in seconds: one day. A participation not released by
	/// then expires, whether its forfeits never came or came and were never
	/// co-signed (the signer away, or its keepers): each forfeit without the
	/// operator's half is dropped, never to be asked for again, the coins it
	/// gave up are the owner's again (one under a forfeit the operator holds
	/// whole excepted), and its new leaves, whose preimage never goes out, are
	/// swept with their batch.
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
		let f = FeeSchedule { refresh_ppm: 23_000, offboard_ppm: 0 };
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
	fn a_board_carries_the_dates_of_a_batch_made_when_it_confirmed() {
		assert_eq!(Params::BOARD_LIFETIME, crate::rounds::RoundConfig::default().lifetime, "a batch's lifetime");
		assert_eq!(Params::board_expiry(1_800_000_000), 1_800_000_000 + 28 * 86_400);
		assert_eq!(Params::board_expiry(u32::MAX - 1), u32::MAX);
	}
}
