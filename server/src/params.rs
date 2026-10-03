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
}

impl Params {
	/// The specification's parameters: an exit delay of 36 to 48 hours and a
	/// depth limit of 5.
	pub fn new(chain: Chain, operator: XOnlyPublicKey, assets: BTreeMap<AssetId, AssetParams>) -> Params {
		let any_time = MedianTime::from_consensus(arca_covenant::time::LOCKTIME_THRESHOLD).expect("the first time");
		let spec = WalletPolicy::new(chain, operator, any_time);
		Params {
			chain, operator,
			min_exit_delay: spec.min_exit_delay,
			max_exit_delay: spec.max_exit_delay,
			assets,
			depth_limit: DEPTH_LIMIT,
		}
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
