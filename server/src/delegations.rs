//! Release delegation: the operator's half of RECLAIM-D.
//!
//! A batch built with `delegated_reclaim` carries RECLAIM-D beside RECLAIM on
//! every lowest node ([`arca_covenant::node::ReleaseTree`]). When a coin
//! resting on such a node moves into a reassignment (a payment, a swap, a
//! Lightning send, a fill), its key signs a delegation of its release to the
//! owner keys of every output of that reassignment, in output order. The
//! server takes it with the transfer ([`crate::cosign`]), or afterwards for a
//! coin a fill spent ([`Delegations::take`]), checks it against the outputs it
//! recorded, and keeps it. Each holder that refreshes a coin resting on such
//! a node signs a release of every one of them it rests on, naming its new
//! round ([`crate::forfeits`]).
//!
//! The watcher reclaims a lowest node once every one of its slots has its
//! consent ([`consent`]): the slot's batch leaf released by its owner, or its
//! delegation and, for each output it names, that coin's consent in turn,
//! down to the coins' current holders. A coin that moved into a reassignment
//! consents only through its delegation, never by a release of its own key:
//! the chain cannot tell a release by a key that has already delegated from
//! its holder's, so the operator, whose signature every reclaim needs, uses
//! only the releases of coins nothing has spent but their holder's refresh.
//! That is the whole of the rule against stale delegations and releases.

use std::future::Future;
use std::pin::Pin;

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, TxOut};

use arca_covenant::message::Chain;
use arca_covenant::node::{connector_index, ReleaseTree, RECLAIM_STEPS};
use arca_covenant::{Delegation, ExplicitOutput, LeafPolicy, ValidCoin};

use crate::store::{SpentBy, Store, StoreError};

/// Checks `sig`, `coin`'s key's delegation into a reassignment of `outputs`,
/// each the leaf `leaves` names at its index.
pub fn check(coin: &ValidCoin, chain: Chain, outputs: &[ExplicitOutput], leaves: &[LeafPolicy], sig: &Signature) -> Result<(), String> {
	let d = Delegation::for_outputs(coin.leaf.owner, chain, outputs, leaves).map_err(|e| e.to_string())?;
	d.verify(sig).map_err(|e| e.to_string())
}

/// One slot's consent to a reclaim by RECLAIM-D, before the reclaim's inputs
/// are chosen: [`ReleaseTree`] with each release's round in place of the
/// input that holds its connector asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Consent {
	/// `key` released the node for round `round_id`, whose connector asset is
	/// `connector`.
	Release { key: XOnlyPublicKey, sig: Signature, round_id: i64, connector: AssetId },
	/// `key` delegated to the owner keys of the outputs, each consenting in
	/// turn.
	Delegation { key: XOnlyPublicKey, sig: Signature, to: Vec<Consent> },
}

impl Consent {
	/// Whether this is the slot owner's own release (RECLAIM takes it).
	pub fn direct(&self) -> bool {
		matches!(self, Consent::Release { .. })
	}

	/// RECLAIM-D's steps it takes.
	pub fn steps(&self) -> usize {
		match self {
			Consent::Release { .. } => 1,
			Consent::Delegation { to, .. } => 1 + to.iter().map(Consent::steps).sum::<usize>(),
		}
	}

	/// The rounds whose connector assets its releases name.
	pub fn rounds(&self, out: &mut Vec<i64>) {
		match self {
			Consent::Release { round_id, .. } => {
				if !out.contains(round_id) {
					out.push(*round_id);
				}
			},
			Consent::Delegation { to, .. } => to.iter().for_each(|c| c.rounds(out)),
		}
	}

	/// The tree RECLAIM-D takes, each release naming the input of `prevouts`
	/// that holds its connector asset.
	pub fn tree(&self, prevouts: &[TxOut]) -> Result<ReleaseTree, String> {
		Ok(match self {
			Consent::Release { key, sig, connector, .. } => ReleaseTree::Release {
				key: *key, sig: *sig,
				connector_input: connector_index(prevouts, *connector).ok_or("a release names a connector asset no input holds")?,
			},
			Consent::Delegation { key, sig, to } => ReleaseTree::Delegation {
				key: *key, sig: *sig, to: to.iter().map(|c| c.tree(prevouts)).collect::<Result<_, _>>()?,
			},
		})
	}
}

/// The consent of `leaf_id`, a coin of key `key` resting on the lowest node
/// whose children hash is `node_hash`, or `None` while some coin it became
/// has not released the node. A coin a signed reassignment spent consents
/// through its delegation into that reassignment, and only so; any other
/// spent coin (one given up in a refresh) by its own release, of the latest
/// round it named. `budget` is the most RECLAIM-D steps the consent may take.
pub fn consent<'a>(store: &'a Store, leaf_id: [u8; 32], key: XOnlyPublicKey, node_hash: [u8; 32], budget: usize)
	-> Pin<Box<dyn Future<Output = Result<Option<Consent>, StoreError>> + Send + 'a>>
{
	Box::pin(async move {
		if budget == 0 {
			return Ok(None);
		}
		match store.spent_by(&leaf_id).await? {
			SpentBy::Reassignment { transfer_id, outputs } => {
				let Some(d) = store.delegation(&leaf_id).await? else { return Ok(None) };
				if d.transfer_id != transfer_id || outputs.is_empty() {
					return Ok(None);
				}
				let Ok(sig) = Signature::from_slice(&d.signature) else { return Ok(None) };
				let mut left = budget - 1;
				let mut to = Vec::with_capacity(outputs.len());
				for (out, k) in outputs {
					let Ok(k) = XOnlyPublicKey::from_slice(&k) else { return Ok(None) };
					match consent(store, out, k, node_hash, left).await? {
						Some(c) => {
							left = left.saturating_sub(c.steps());
							to.push(c);
						},
						None => return Ok(None),
					}
				}
				Ok(Some(Consent::Delegation { key, sig, to }))
			},
			SpentBy::Other => {
				let rows = store.holder_releases(&leaf_id, &node_hash).await?;
				let Some(r) = rows.last() else { return Ok(None) };
				let Ok(sig) = Signature::from_slice(&r.signature) else { return Ok(None) };
				Ok(Some(Consent::Release { key, sig, round_id: r.round_id, connector: AssetId::from_slice(&r.connector_asset)
					.map_err(|e| StoreError::Corrupt(e.to_string()))? }))
			},
			SpentBy::Nothing => Ok(None),
		}
	})
}

/// The consents of every slot of a lowest node, in owner order, when all
/// of them have one within RECLAIM-D's steps.
pub async fn node_consents(store: &Store, slots: &[([u8; 32], XOnlyPublicKey)], node_hash: [u8; 32]) -> Result<Option<Vec<Consent>>, StoreError> {
	let mut left = RECLAIM_STEPS;
	let mut out = Vec::with_capacity(slots.len());
	for (leaf, key) in slots {
		match consent(store, *leaf, *key, node_hash, left).await? {
			Some(c) => {
				left = left.saturating_sub(c.steps());
				out.push(c);
			},
			None => return Ok(None),
		}
	}
	Ok(Some(out))
}
