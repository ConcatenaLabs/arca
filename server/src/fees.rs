//! The relay floor in an asset's own atoms, which sizes every margin and
//! reserve the server leaves for a transaction someone may broadcast later.
//!
//! The node accepts a fee in an asset only while that asset is on its fee
//! whitelist, valued at the node's rate at the moment it arrives. So a margin
//! is priced from the node's floor and rate now, in the asset it is held in;
//! an asset the node does not accept now gets the least margin the scripts
//! allow, and whoever broadcasts attaches a coin in an accepted asset.

use elements::AssetId;

use crate::chain::{ChainError, FinalityService};

/// How many times the floor every margin and reserve holds: the
/// specification's cover for a fourfold rise in the fee floor.
pub const MULTIPLE: u64 = 4;

/// The node's relay floor in `asset`'s own atoms per 1,000 vbytes, now; `None`
/// when the node does not accept `asset` for fees.
pub async fn floor_per_kvb(finality: &FinalityService, asset: AssetId) -> Result<Option<u64>, ChainError> {
	let rates = finality.call(|c| c.fee_rates()).await?;
	let rate = match rates.get(&asset) {
		Some(r) if *r > 0 => *r as u128,
		_ => return Ok(None),
	};
	let floor = finality.call(|c| c.relay_floor_per_kvb()).await? as u128;
	// The node values a atoms at a × rate / 10^8 reference units.
	Ok(Some((floor * 100_000_000).div_ceil(rate).max(1).min(u64::MAX as u128) as u64))
}

/// `multiple` times the floor for `vsize` vbytes, in the asset's atoms.
pub fn atoms_for(floor_per_kvb: u64, vsize: u64, multiple: u64) -> u64 {
	vsize.saturating_mul(floor_per_kvb).div_ceil(1000).saturating_mul(multiple)
}
