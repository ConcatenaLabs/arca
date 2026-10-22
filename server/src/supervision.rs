//! The supervised profile: an asset whose issuer can freeze holdings by
//! consensus rule, served so that a frozen holder can neither move nor
//! escape.
//!
//! A supervised asset is one the node lists in `getsupervisedassets`: its
//! supervision descriptor is committed in the asset id at issuance, so it can
//! never be added or removed, and the operator serves such an asset under
//! this profile whatever its configuration says ([`crate::server`] reads it
//! from the node at start and at every reload). A freeze binds only
//! single-owner spends (P2WPKH, a taproot key path), and every Arca output is
//! spent by a script path, so a freeze never reaches the tree. The profile
//! brings it back to the holder:
//!
//! - every leaf of the asset, in a batch, a board or a reassignment, is
//!   `landing-1` (`arca_covenant::landing`), whose exit pays only P2WPKH of
//!   the owner's own landing key, explicitly in the asset, all but the
//!   published allowance; no other template holds it. Every output of every
//!   transaction that moves it is explicit, as consensus requires;
//! - the operator mirrors freezes: before it co-signs anything that spends a
//!   coin of the asset it asks its node whether the coin's landing is frozen,
//!   or the asset paused ([`check`]), and refuses (`frozen`) while it is. A
//!   freeze binds here as soon as its record is in a block of the operator's
//!   node; a lifting binds only once the block at which the node first showed
//!   the target free is final (a hold, kept in the database), so an
//!   anchor-driven reorganisation that restores the freeze on the chain
//!   finds it still held here. The operator reads every freeze and pause of
//!   the assets it serves after each pass over the chain ([`observe`]), not
//!   only when a coin is asked about, so a freeze no request met while it
//!   lasted is held to its final lifting all the same;
//! - what stays the holder's: its coin leaves the tree by its landing, an
//!   unroll and an exit by script paths that confirm under any freeze, into
//!   its own key, where the freeze binds on the chain.
//!
//! The node is asked about a landing's P2WPKH only, never about an Arca
//! script: `isassetfrozen` says frozen for an Arca script once it is named in
//! a record or the asset is paused, although its script-path spends confirm,
//! so reading that flag would stop the operator answering exits or sweeping
//! where nothing is stuck.

use std::sync::Arc;

use elements::AssetId;

use arca_covenant::{CoinRecord, LandingTerms, LeafId};

use crate::chain::{ChainError, FinalityService};
use crate::params::Params;
use crate::store::{BlockRow, HoldRow, Store, StoreError};

/// The refusal code of a co-signature refused for a freeze.
pub const FROZEN: &str = "frozen";

/// The hold target of an asset's pause, which freezes every holder.
pub const PAUSE: [u8; 32] = [0; 32];

/// Why a coin's holder is frozen in the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Freeze {
	/// A freeze record names the coin's landing.
	Named,
	/// The asset is paused: every single-owner holding of it is frozen.
	Paused,
	/// The node shows the landing free since the block at this height, which
	/// is not final yet: the freeze binds until it is.
	Lifting { height: u64 },
}

impl std::fmt::Display for Freeze {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Freeze::Named => write!(f, "a freeze record of the asset's issuer names its landing"),
			Freeze::Paused => write!(f, "the asset's issuer has paused it, freezing every holding of it"),
			Freeze::Lifting { height } => write!(f, "its freeze is lifted on the chain, as the operator's node has shown since block {}, \
				and the operator takes the lifting only once that block is final (certified, its anchor buried), as an anchor \
				reorganisation could restore it", height),
		}
	}
}

/// Why the supervised profile refuses a coin.
#[derive(Debug, thiserror::Error)]
pub enum SupervisionError {
	#[error("coin {leaf} of supervised asset {asset} is frozen: {why}. Its landing, P2WPKH {program}, is where its exit pays: \
		the operator co-signs nothing that spends the coin (no transfer, swap, refresh, offboard, take, fill, distribution, plan or \
		Lightning payment), and its holder takes it home by its landing, where it stays frozen until the issuer lifts the freeze")]
	Frozen { leaf: LeafId, asset: AssetId, program: String, why: Freeze },
	#[error("coin {leaf} of supervised asset {asset} is not a landing-1 leaf: a supervised asset is held in the tree in landing-1 \
		leaves only")]
	NotLanding { leaf: LeafId, asset: AssetId },
	#[error("the node: {0}")]
	Chain(String),
	#[error(transparent)]
	Store(#[from] StoreError),
}

impl From<ChainError> for SupervisionError {
	fn from(e: ChainError) -> SupervisionError {
		SupervisionError::Chain(e.to_string())
	}
}

impl SupervisionError {
	pub fn code(&self) -> &'static str {
		match self {
			SupervisionError::Frozen { .. } => "frozen",
			SupervisionError::NotLanding { .. } => "out_of_bounds",
			SupervisionError::Chain(_) => "not_synced",
			SupervisionError::Store(_) => "internal",
		}
	}
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Checks every coin `leaves` names against the freeze, before anything else
/// about a request that gives them up: a coin of a supervised asset whose
/// holder is frozen is refused ([`check`]). A coin the server does not know,
/// or of an asset it does not serve supervised, passes here and meets the
/// rest of the request's checks.
pub async fn gate(store: &Store, finality: &FinalityService, params: &Params, leaves: &[LeafId]) -> Result<(), SupervisionError> {
	for id in leaves {
		let row = match store.leaf(&id.0).await? {
			Some(r) => r,
			None => continue,
		};
		let asset = AssetId::from_byte_array(row.asset);
		if params.supervised(&asset).is_none() {
			continue;
		}
		let landing = CoinRecord::from_bytes(&row.record).ok().and_then(|r| r.landing());
		check(store, finality, id, asset, landing.as_ref()).await?;
	}
	Ok(())
}

/// Whether the holder of coin `leaf`, of the supervised asset `asset`,
/// landing at `landing`, is frozen in the tree now: see the [module
/// documentation](self). Frozen while the node shows the landing frozen or
/// the asset paused, and while a hold on the landing or on the asset's pause
/// waits for its lifting to be final.
pub async fn check(store: &Store, finality: &FinalityService, leaf: &LeafId, asset: AssetId, landing: Option<&LandingTerms>)
	-> Result<(), SupervisionError>
{
	let terms = landing.ok_or(SupervisionError::NotLanding { leaf: *leaf, asset })?;
	let asset_bytes = asset.into_inner().to_byte_array();
	let program = terms.program;
	let script = terms.script_pubkey();
	let status = finality.call(move |c| c.freeze_status(&asset, &script)).await?;
	let target = status.target.ok_or_else(|| SupervisionError::Chain("the node named no targethash for the landing".into()))?;
	let tip = store.tip_block().await?.ok_or_else(|| SupervisionError::Chain("the server follows no block yet".into()))?;
	let frozen = |why| SupervisionError::Frozen { leaf: *leaf, asset, program: hex(&program), why };
	if status.paused {
		store.hold_frozen(&asset_bytes, &PAUSE, tip.height).await?;
		return Err(frozen(Freeze::Paused));
	}
	if status.frozen {
		store.hold_frozen(&asset_bytes, &target, tip.height).await?;
		return Err(frozen(Freeze::Named));
	}
	for t in [PAUSE, target] {
		if let Some(hold) = store.supervision_hold(&asset_bytes, &t).await? {
			if let Some(height) = lifting(store, finality, &hold, &tip).await? {
				return Err(frozen(Freeze::Lifting { height }));
			}
		}
	}
	Ok(())
}

/// Moves the hold `h` on, its target shown free at `tip`: its lifting
/// counted from the tip the first time, the hold dropped once that block is
/// final. The height its lifting counts from while the hold binds; `None`
/// once it is dropped.
async fn lifting(store: &Store, finality: &FinalityService, h: &HoldRow, tip: &BlockRow) -> Result<Option<u64>, SupervisionError> {
	match h.lifted {
		None => {
			store.hold_lifted_at(&h.asset, &h.target, &tip.hash, tip.height).await?;
			Ok(Some(tip.height))
		},
		Some((hash, height)) => match finality.block_final(&hash).await.map_err(|e| SupervisionError::Chain(e.to_string()))? {
			Some(true) => {
				store.drop_hold(&h.asset, &h.target).await?;
				log::info!("supervision: the {} of asset {} is lifted, final since block {}",
					if h.target == PAUSE { "pause".to_string() } else { format!("freeze of target {}", hex(&h.target)) },
					AssetId::from_byte_array(h.asset), height);
				Ok(None)
			},
			Some(false) => Ok(Some(height)),
			// The block that showed it free left the chain: the lifting starts
			// again at the tip.
			None => {
				store.hold_lifted_at(&h.asset, &h.target, &tip.hash, tip.height).await?;
				Ok(Some(tip.height))
			},
		},
	}
}

/// The operator's watch on its node, after each pass over the chain: every
/// script a freeze record of each of `assets` names now, and each one's
/// pause, held; every hold the node no longer shows frozen moved on
/// ([`lifting`]). A freeze that lasts from one pass to the next is held
/// to its final lifting whether or not any coin was asked about while it
/// lasted.
pub async fn observe(store: &Store, finality: &FinalityService, assets: &[AssetId]) -> Result<(), SupervisionError> {
	if assets.is_empty() {
		return Ok(());
	}
	let Some(tip) = store.tip_block().await? else { return Ok(()) };
	let listed = finality.call(|c| c.supervised_assets()).await?;
	for asset in assets {
		let a = asset.into_inner().to_byte_array();
		let id = *asset;
		let mut frozen = finality.call(move |c| c.asset_freezes(&id)).await?;
		if listed.iter().any(|s| s.asset == *asset && s.paused) {
			frozen.push(PAUSE);
		}
		for t in &frozen {
			store.hold_frozen(&a, t, tip.height).await?;
		}
		for h in store.supervision_holds_of(&a).await? {
			if !frozen.contains(&h.target) {
				lifting(store, finality, &h, &tip).await?;
			}
		}
	}
	Ok(())
}

/// The supervised assets among `served`, as the node lists them now.
pub async fn supervised_among(finality: &Arc<FinalityService>, served: &[AssetId]) -> Result<Vec<AssetId>, ChainError> {
	let listed = finality.call(|c| c.supervised_assets()).await?;
	Ok(served.iter().copied().filter(|a| listed.iter().any(|s| s.asset == *a)).collect())
}
