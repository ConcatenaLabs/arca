//! The release: an owner's consent that the operator reclaim the lowest node
//! above a coin it gave up, bound to the round that made its new leaf.
//!
//! When every owner under a lowest node has moved on, by a refresh or an
//! offboard, the operator need not wait for the batch to expire: each owner
//! signs a release of the node, and the operator spends it at once by its
//! RECLAIM leaf ([`crate::node`]). The release is
//!
//! ```text
//! SHA256("Arca/release" ‖ genesis_hash ‖ H ‖ M)
//! ```
//!
//! with `H` the lowest node's children hash, the genesis hash and `M` in
//! internal byte order. `M` is the connector asset of the round that made the
//! owner's new leaf (or paid its offboard): the asset that spending that
//! round's connector output issues with a zero contract hash
//! ([`crate::forfeit::connector_asset`]). RECLAIM reads `M` from the input the
//! witness names, explicitly, so a reclaim confirms only with an atom of `M`
//! among its inputs, and `M` can be issued only while that round is in the
//! chain. A release is therefore void with the round it names: if that round
//! is lost to a rollback, the owner keeps its old coin, whatever releases the
//! operator holds. The forfeit is bound to its round the same way, so neither
//! half of a refresh outlives the round.
//!
//! What a release authorises: the spend, by RECLAIM, of any output that
//! carries this node's script (this chain, this `H`, this owner key), provided
//! every other owner under the node has released it too, the operator signs,
//! and an atom of `M` is an input. The owner key is the old leaf's own, used on
//! no other leaf, so a release fills only its own slot. The operator issues one
//! atom of each round's `M` and uses it for every claim and reclaim of that
//! round, paying it back to itself each time ([`crate::node::reclaim_tx`]).
//!
//! When a wallet signs one. Only once it holds the preimage of its new leaf
//! and the round that made it is final: before then `M` names a round that may
//! still be replaced. [`Release::for_refresh`] and [`Release::for_offboard`]
//! take `H` from the old leaf the wallet validated and `M` from the round its
//! new leaf (or offboard) was validated against, never from what it was told.
//! The server neither asks for nor accepts a release for a coin with an open
//! out-of-round reassignment: the release key is the key the coin was built
//! with, so its sender and the operator could otherwise void the receiver's
//! chain.

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Transaction};

use crate::forfeit::{connector_asset, ConnectorPolicy};
use crate::message::{Chain, CsfsMessage};
use crate::offboard::OffboardPolicy;
use crate::record::ValidLeaf;
use crate::sign::verify_digest;
use crate::spend::SpendError;

/// An owner's release of the lowest node above a coin it gave up: see the
/// [module documentation](self).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Release {
	/// The chain the node is on.
	pub chain: Chain,
	/// `H`, the lowest node's children hash.
	pub node_hash: [u8; 32],
	/// The key that signs: the old leaf's owner key, which RECLAIM names in
	/// that leaf's slot.
	pub owner: XOnlyPublicKey,
	/// `M`, the connector asset of the round that made the owner's new leaf.
	pub connector: AssetId,
}

impl Release {
	/// The release of the lowest node above `old`, a leaf the wallet holds
	/// and validated, given up for `new`, a leaf it validated against
	/// `round`, whose connector output is `c`. Refuses a `round` other than
	/// the one `new` was validated against, an output `c` that is not the
	/// operator's connector, and an old leaf under another operator.
	pub fn for_refresh(old: &ValidLeaf, new: &ValidLeaf, round: &Transaction, c: u32) -> Result<Release, SpendError> {
		let round_txid = round.txid();
		if round_txid != new.round_txid {
			return Err(SpendError::NotTheRound);
		}
		if old.branch.leaf.operator != new.branch.leaf.operator {
			return Err(SpendError::OtherOperator);
		}
		Release::from_round(old, round, c)
	}

	/// The release of the lowest node above `old`, given up for the offboard
	/// output `offboard` that `round` pays, whose connector output is `c`.
	/// Refuses a round that does not pay the offboard, an output `c` that is
	/// not the operator's connector, and an offboard of another operator.
	pub fn for_offboard(old: &ValidLeaf, offboard: &OffboardPolicy, round: &Transaction, c: u32) -> Result<Release, SpendError> {
		if old.branch.leaf.operator != offboard.operator {
			return Err(SpendError::OtherOperator);
		}
		offboard.find(round)?;
		Release::from_round(old, round, c)
	}

	fn from_round(old: &ValidLeaf, round: &Transaction, c: u32) -> Result<Release, SpendError> {
		ConnectorPolicy { operator: old.branch.leaf.operator }.check(round, c)?;
		let lowest = old.branch.nodes.last().ok_or(SpendError::NoLowestNode)?;
		if lowest.reclaim.is_none() {
			return Err(SpendError::NoLowestNode);
		}
		Ok(Release {
			chain: old.branch.leaf.chain,
			node_hash: lowest.children_hash(),
			owner: old.branch.leaf.owner,
			connector: connector_asset(round.txid(), c),
		})
	}

	/// What the owner signs: `SHA256("Arca/release" ‖ genesis_hash ‖ H ‖ M)`.
	pub fn message(&self) -> CsfsMessage {
		self.chain.release_message(&self.node_hash, self.connector)
	}

	/// The server's check of a release handed to it: `sig` is the owner's
	/// signature over [`Release::message`].
	pub fn verify(&self, sig: &Signature) -> Result<(), SpendError> {
		if verify_digest(sig, &self.message().digest, &self.owner) {
			Ok(())
		} else {
			Err(SpendError::Signature("owner"))
		}
	}
}
