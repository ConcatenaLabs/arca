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
//!
//! # Delegation
//!
//! A coin that moves out of round passes the right to release its place in
//! its batch to the coins it moved into. Its key signs a [`Delegation`] to
//! the owner keys of every output of the reassignment, in output order:
//!
//! ```text
//! SHA256("Arca/delegate" ‖ genesis_hash ‖ K_1 ‖ … ‖ K_m)
//! ```
//!
//! On a lowest node built with RECLAIM-D ([`crate::node`]), the release of
//! an owner's slot is then a tree ([`crate::node::ReleaseTree`]): the owner's
//! own release, or its delegation and, for each key it names, a tree in turn.
//! Every leaf of the tree is a release by the key of a coin still resting on
//! the slot, bound like any release to the round of that holder's new coin
//! ([`Release::for_holder`]). Naming every output means no co-receiver (a
//! payer's change, a swap's other side) can release the slot without the
//! others, so a delegation adds no one a coin must trust: its senders, with
//! the operator, could already spend the coins it came from twice.
//!
//! What a delegation authorises: nothing alone. It makes the releases of the
//! keys it names, all of them, stand for the signer's release, on every node
//! the signer's coin rests on, on this chain. The signer's key is one coin's
//! own, so it names a slot only through that coin. The chain cannot know
//! whether a key has delegated, so a release by a key that did is accepted
//! by RECLAIM-D as its holder's: the operator refuses one, and refuses the
//! release of any coin that has moved on.

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Transaction};

use crate::accumulator::ValidAccumulatorLeaf;
use crate::leaf::LeafPolicy;
use crate::node::MAX_DELEGATES;
use crate::script::ExplicitOutput;
use crate::transfer::{NewLeaf, ValidCoin};
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

	/// [`Release::for_refresh`] for `new`, a leaf of an accumulator batch.
	pub fn for_accumulator_refresh(old: &ValidLeaf, new: &ValidAccumulatorLeaf, round: &Transaction, c: u32) -> Result<Release, SpendError> {
		if round.txid() != new.round_txid {
			return Err(SpendError::NotTheRound);
		}
		if old.branch.leaf.operator != new.leaf.operator {
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

impl Release {
	/// The releases a coin's holder signs once it has refreshed the coin
	/// into `new`, a leaf it validated against `round` (whose connector
	/// output is `c`): one for each lowest node with RECLAIM-D that the coin
	/// rests on ([`ValidCoin::release_nodes`]), each naming the round's
	/// connector asset and signed by the coin's own key. For a coin that is
	/// itself a batch leaf this is [`Release::for_refresh`]'s release when its
	/// node carries RECLAIM-D. Refuses a `round` other than the one `new` was
	/// validated against, an output `c` that is not the operator's connector
	/// and a coin under another operator.
	pub fn for_holder(coin: &ValidCoin, new: &ValidLeaf, round: &Transaction, c: u32) -> Result<Vec<Release>, SpendError> {
		if round.txid() != new.round_txid {
			return Err(SpendError::NotTheRound);
		}
		if coin.leaf.operator != new.branch.leaf.operator {
			return Err(SpendError::OtherOperator);
		}
		ConnectorPolicy { operator: coin.leaf.operator }.check(round, c)?;
		let connector = connector_asset(round.txid(), c);
		Ok(coin.release_nodes().into_iter().map(|(chain, node_hash)| Release {
			chain, node_hash, owner: coin.leaf.owner, connector,
		}).collect())
	}
}

impl Release {
	/// [`Release::for_holder`] for a coin given up for `offboard`, an
	/// offboard output `round` pays, whose connector output is `c`: one
	/// release for each lowest node with RECLAIM-D the coin rests on, naming
	/// the round's connector asset. Refuses a round that does not pay the
	/// offboard, an output `c` that is not the operator's connector, and an
	/// offboard of another operator.
	pub fn for_holder_offboard(coin: &ValidCoin, offboard: &OffboardPolicy, round: &Transaction, c: u32) -> Result<Vec<Release>, SpendError> {
		if coin.leaf.operator != offboard.operator {
			return Err(SpendError::OtherOperator);
		}
		offboard.find(round)?;
		ConnectorPolicy { operator: coin.leaf.operator }.check(round, c)?;
		let connector = connector_asset(round.txid(), c);
		Ok(coin.release_nodes().into_iter().map(|(chain, node_hash)| Release {
			chain, node_hash, owner: coin.leaf.owner, connector,
		}).collect())
	}
}

/// A coin's key's delegation of its release to the owner keys of a
/// reassignment's outputs: see the [module documentation](self).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Delegation {
	pub chain: Chain,
	/// The coin's owner key, which signs.
	pub from: XOnlyPublicKey,
	/// The owner keys of every output of the reassignment, in output order.
	pub to: Vec<XOnlyPublicKey>,
}

impl Delegation {
	/// `from`'s delegation to `to`: 1 to 4 keys.
	pub fn new(chain: Chain, from: XOnlyPublicKey, to: Vec<XOnlyPublicKey>) -> Result<Delegation, crate::Error> {
		if to.is_empty() || to.len() > MAX_DELEGATES {
			return Err(crate::Error::OutputCount(to.len()));
		}
		Ok(Delegation { chain, from, to })
	}

	/// The delegation of `coin`, a coin the wallet holds and is giving, into
	/// a reassignment of `outputs`, each the leaf `leaves` names at its index
	/// (under `coin`'s operator and chain). Refuses outputs and leaves that
	/// differ in number, and an output that is not its leaf's script, asset
	/// and all: the keys must be the outputs' own, or the delegation would
	/// leave the slot to keys that hold nothing.
	pub fn for_reassignment(coin: &ValidCoin, outputs: &[ExplicitOutput], leaves: &[NewLeaf]) -> Result<Delegation, SpendError> {
		let (operator, chain) = (coin.leaf.operator, coin.leaf.chain);
		let policies: Vec<LeafPolicy> = leaves.iter().map(|l| l.policy(operator, chain)).collect();
		Delegation::for_outputs(coin.leaf.owner, chain, outputs, &policies)
	}

	/// [`Delegation::for_reassignment`] from the outputs' leaf policies, for
	/// the operator's check of a delegation handed to it with a reassignment.
	pub fn for_outputs(from: XOnlyPublicKey, chain: Chain, outputs: &[ExplicitOutput], leaves: &[LeafPolicy]) -> Result<Delegation, SpendError> {
		if outputs.len() != leaves.len() {
			return Err(SpendError::Delegation("the outputs and their leaves differ in number"));
		}
		if outputs.iter().zip(leaves).any(|(o, l)| o.script_pubkey != l.script_pubkey() || l.chain != chain) {
			return Err(SpendError::Delegation("an output is not the leaf named for it"));
		}
		Delegation::new(chain, from, leaves.iter().map(|l| l.owner).collect())
			.map_err(|_| SpendError::Delegation("a reassignment has 1 to 4 outputs"))
	}

	/// What the coin's key signs:
	/// `SHA256("Arca/delegate" ‖ genesis_hash ‖ K_1 ‖ … ‖ K_m)`.
	pub fn message(&self) -> CsfsMessage {
		self.chain.delegation_message(&self.to).expect("1 to 4 keys")
	}

	/// The check of a delegation handed to the operator: `sig` is `from`'s
	/// signature over [`Delegation::message`].
	pub fn verify(&self, sig: &Signature) -> Result<(), SpendError> {
		if verify_digest(sig, &self.message().digest, &self.from) {
			Ok(())
		} else {
			Err(SpendError::Signature("delegation"))
		}
	}
}
