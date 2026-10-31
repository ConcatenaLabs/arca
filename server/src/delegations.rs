//! Release delegation: the operator's half of RECLAIM-D.
//!
//! A batch built with `delegated_reclaim` carries RECLAIM-D beside RECLAIM on
//! every lowest node ([`arca_covenant::node::ReleaseTree`]). When a coin
//! resting on such a node moves into a reassignment (a payment, a swap, a
//! Lightning send, a fill), its key signs a delegation of its release to the
//! owner keys of every output of that reassignment, in output order. The
//! server takes it with the transfer ([`crate::cosign`]), checks it against
//! the outputs it builds, and keeps it. A fill takes each taker coin's with
//! the fill ([`crate::orders`]), and its order coin's afterwards: the maker is
//! away when its order is filled, and delegates once its wallet holds a coin
//! the fill made ([`crate::orders::Orders::delegate`]). Each holder that
//! refreshes a coin resting on such a node signs a release of every one of
//! them it rests on, naming its new round ([`crate::forfeits`]); the sender
//! of a paid Lightning payment out of the tree releases its `htlc-1` leaf's
//! nodes, naming the latest final round ([`crate::lightning::send`]).
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

use crate::store::{HolderReleaseRow, SendState, SpentBy, Store, StoreError};

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
				if is_rest(store, &leaf_id).await? != Some(false) {
					return Ok(None);
				}
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
			SpentBy::Other => match is_rest(store, &leaf_id).await? {
				Some(false) => release_of(key, store.holder_releases(&leaf_id, &node_hash).await?),
				_ => Ok(None),
			},
			// The htlc-1 leaf of a payment out of the tree that was paid is
			// the operator's, and its sender's key releases it.
			SpentBy::Nothing => match store.send_of_leaf(&leaf_id).await? {
				Some(s) if s.state == SendState::Paid => release_of(key, store.paid_send_releases(&leaf_id, &node_hash).await?),
				_ => Ok(None),
			},
		}
	})
}

/// Whether the coin `leaf` is an order resting again after a fill, by its
/// record; `None` for a coin the store does not hold. Its key is its
/// order's, which delegated at the fill, so it consents to no reclaim: not
/// by a release of its own, and not by a delegation into its next move,
/// which would fit the order's first coin's slot as well as its own
/// ([`arca_covenant::ValidCoin::is_rest`]). A delegation a wallet signed for
/// one before wallets stopped signing them may be in the store; it is never
/// followed.
async fn is_rest(store: &Store, leaf: &[u8; 32]) -> Result<Option<bool>, StoreError> {
	Ok(store.leaf(leaf).await?.map(|row| matches!(arca_covenant::CoinRecord::from_bytes(&row.record),
		Ok(arca_covenant::CoinRecord::Fill(f)) if matches!(f.leaf, arca_covenant::transfer::FillLeaf::Rest { .. }))))
}

/// `key`'s consent by the latest of its releases `rows`, if any.
fn release_of(key: XOnlyPublicKey, rows: Vec<HolderReleaseRow>) -> Result<Option<Consent>, StoreError> {
	let Some(r) = rows.last() else { return Ok(None) };
	let Ok(sig) = Signature::from_slice(&r.signature) else { return Ok(None) };
	Ok(Some(Consent::Release { key, sig, round_id: r.round_id, connector: AssetId::from_slice(&r.connector_asset)
		.map_err(|e| StoreError::Corrupt(e.to_string()))? }))
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

/// Whether the lowest node whose children hash is `node_hash`, its slots
/// `slots` in owner order, can still come back by its holders' releases
/// within RECLAIM-D's steps, by the same tree [`consent`] builds: every coin
/// it became either still held, or given up in a refresh whose release is
/// recorded or can still come (its participation not completed yet), or
/// moved into a signed reassignment with a delegation into it, the same down
/// each of its outputs. The `htlc-1` leaf of a payment out of the tree counts
/// as held while the payment is undecided or failed (it goes back to its
/// sender), and once paid when its sender's release is recorded. A coin
/// given up in a refresh or an offboard that completed with no release, a
/// coin that moved without a delegation, the order resting again after a fill
/// once it moves on at all (its key delegated at the fill), an `htlc-1` leaf
/// of a payment into the tree, or a tree past [`RECLAIM_STEPS`] steps, keeps
/// the node until its batch expires.
pub async fn can_complete(store: &Store, slots: &[[u8; 32]], node_hash: [u8; 32]) -> Result<bool, StoreError> {
	let mut left = RECLAIM_STEPS;
	for leaf in slots {
		match reach(store, *leaf, node_hash, left).await? {
			Some(n) if n <= left => left -= n,
			_ => return Ok(false),
		}
	}
	Ok(true)
}

/// The steps `leaf`'s consent would take once every holder under it
/// releases ([`can_complete`]), or `None` when it never can within `budget`.
fn reach<'a>(store: &'a Store, leaf: [u8; 32], node_hash: [u8; 32], budget: usize)
	-> Pin<Box<dyn Future<Output = Result<Option<usize>, StoreError>> + Send + 'a>>
{
	Box::pin(async move {
		if budget == 0 {
			return Ok(None);
		}
		match store.spent_by(&leaf).await? {
			SpentBy::Reassignment { transfer_id, outputs } => {
				if is_rest(store, &leaf).await? != Some(false) {
					return Ok(None);
				}
				match store.delegation(&leaf).await? {
					Some(d) if d.transfer_id == transfer_id && !outputs.is_empty() => {},
					_ => return Ok(None),
				}
				let mut used = 1;
				for (out, _) in outputs {
					match reach(store, out, node_hash, budget.saturating_sub(used)).await? {
						Some(n) => used += n,
						None => return Ok(None),
					}
				}
				Ok((used <= budget).then_some(used))
			},
			SpentBy::Other => {
				// An order resting again releases nothing: its key delegated
				// at the fill. Given up in a refresh, it never consents.
				let Some(rest) = is_rest(store, &leaf).await? else { return Ok(None) };
				let comes = !rest && (!store.holder_releases(&leaf, &node_hash).await?.is_empty() || store.refresh_open(&leaf).await?);
				Ok(comes.then_some(1))
			},
			SpentBy::Nothing => {
				let Some(row) = store.leaf(&leaf).await? else { return Ok(None) };
				let held = match arca_covenant::CoinRecord::from_bytes(&row.record) {
					Ok(arca_covenant::CoinRecord::Transfer(t)) => match t.leaf.htlc {
						None => true,
						Some(h) if h.direction == arca_covenant::HtlcDirection::Send => match store.send_of_leaf(&leaf).await? {
							Some(s) if s.state == SendState::Paid => !store.paid_send_releases(&leaf, &node_hash).await?.is_empty(),
							_ => true,
						},
						Some(_) => false,
					},
					_ => true,
				};
				Ok(held.then_some(1))
			},
		}
	})
}
