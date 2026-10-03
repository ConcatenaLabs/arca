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
/// are free. A refresh, or an offboard, costs nothing for a coin whose batch
/// expires within [`FeeSchedule::FREE_WINDOW`], and rises with the time left
/// beyond it to `refresh_ppm` parts per million of the coin's value for a
/// coin [`FeeSchedule::FULL_AFTER`] or more from that window; a coin from
/// boards alone never expires and pays the whole of it. An offboard adds
/// `offboard_ppm` of what it pays out, and the margin of the output the round
/// pays, which the unlock spends as its fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FeeSchedule {
	pub refresh_ppm: u64,
	pub offboard_ppm: u64,
}

impl FeeSchedule {
	/// A refresh costs nothing in the last two days before a coin's expiry.
	pub const FREE_WINDOW: u32 = 2 * 86_400;
	/// The time left beyond the free window at which the whole refresh fee is
	/// due: the rest of a 28-day batch.
	pub const FULL_AFTER: u32 = 26 * 86_400;

	/// The refresh fee for a coin of `value` whose earliest expiry is
	/// `expiry`, at `now`.
	pub fn refresh(&self, value: u64, expiry: MedianTime, now: MedianTime) -> u64 {
		let left = expiry.to_consensus_u32().saturating_sub(now.to_consensus_u32()).saturating_sub(Self::FREE_WINDOW);
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
}

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

	/// The policy a coin given up in a participation is checked under, at
	/// `now`: [`Params::policy`], with the coin's first expiry at least
	/// [`Params::PARTICIPATION_HORIZON`] after now, so that the coin can still
	/// be refreshed inside the free window of the last two days, while the
	/// round has time to become final and the forfeit to come in.
	pub fn participation_policy(&self, now: MedianTime) -> WalletPolicy {
		WalletPolicy { horizon: Self::PARTICIPATION_HORIZON, ..self.policy(now) }
	}

	/// How long before its first expiry a coin may still be given up, in
	/// seconds: one day.
	pub const PARTICIPATION_HORIZON: u32 = 86_400;

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
