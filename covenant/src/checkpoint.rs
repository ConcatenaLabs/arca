//! The checkpoint output.
//!
//! An off-chain transfer is two linked transactions: each input leaf is first
//! spent into a checkpoint output, and the reassignment then spends the
//! checkpoints into the receivers' leaves.
//!
//! ```text
//! collab:  <A> and <S>, rebindable, with the checkpoint's own salt
//! sweep:   the sweep with notice of the input's batch
//! exit:    the coin's own exit, where the checkpoint has one:
//!          <delay> CSV DROP <A> CHECKSIG, or a landing coin's landing
//! ```
//!
//! The checkpoint of a coin of a batch without a sweep has no sweep path
//! (`sweep` is `None`).
//!
//! A `vtxo-2` coin's checkpoint has `arca/collab-2` and its data leaf in place
//! of the tapscript collaborative path ([`crate::collab`]).
//!
//! # The owner's exit
//!
//! A reassignment that spends coins of several owners (a swap, or a fill of
//! a resting order) completes only if every input reaches it. When one
//! input's owner and the operator sign a second spend of that owner's
//! checkpoint, the reassignment can never confirm, and every other owner's
//! coin stands in a checkpoint that only that owner and the operator
//! together can spend. A checkpoint with an exit (`exit` is `Some`) gives the
//! owner its coin back alone, after the delay:
//!
//! ```text
//! [collab, exit]                      without a sweep
//! [collab, [sweep, exit]]             with one
//! [[arca/collab-2, data], exit]       a vtxo-2 coin's, without a sweep
//! [[arca/collab-2, data], [sweep, exit]]   and with one
//! ```
//!
//! The delay is the coin's own exit delay, and the exit is the very script of
//! the coin's leaf's exit. Every receiver checked that delay against its
//! bounds when it took the coin, and every party already answers a leaf's
//! exit within it: a good reassignment completes inside it, as the answer to
//! a stale exit does, by publishing the other checkpoints and the
//! reassignment. A dead one gives the coin home one exit delay after its
//! checkpoint confirms, as soon as its owner's own exit would. Once the
//! reassignment confirms, the checkpoint is spent and the exit is gone.
//!
//! The exit's signature commits to its own transaction alone (a taproot
//! signature hash over every spent output), so it spends nothing else: not
//! the leaf, whose exit has the same script under another output, and not
//! another checkpoint. The collaborative path and its message are those of
//! a checkpoint without an exit: the message names the checkpoint's salt and
//! never the spent script. A `vtxo-2` checkpoint's message names each
//! checkpoint output, so its pairs are made for one form or the other.
//!
//! A coin of a supervised asset (`landing-1`, `landing-2`) exits only by its
//! landing, so
//! its checkpoint's exit is the landing: the output at the spending input's
//! own index pays P2WPKH of the holder's landing key, in the asset,
//! explicitly, at least the checkpoint's value less the coin's allowance
//! ([`CheckpointExit::landing`], [`LandingTerms::script_at_own_index`]), so
//! two landings spent together each need an output of their own. The
//! checkpoint is a script path, which no freeze reaches, exactly as the
//! leaf; the landed coin is a single-owner output, where the issuer's freeze
//! and pause bind, as they bind on a coin landed from its leaf. Only a coin
//! of a plain leaf or a landing leaf has a checkpoint with an exit
//! ([`exit_allowed`]). A coin of a restricted asset (`enclave-1`) is never
//! in a reassignment of several owners: a transfer of one moves that asset
//! alone, from one holder.
//!
//! The checkpoint's salt differs from the leaf's, so a reassignment's
//! signatures do not fit the leaf and a checkpoint's do not fit the checkpoint:
//! the two steps can be neither skipped nor reordered.

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Script};

use crate::collab::Collab2;
use crate::landing::LandingTerms;
use crate::leaf::{exit_script, rebindable_two_party, two_party_items, two_party_message, LeafPolicy};
use crate::message::{Chain, CsfsMessage};
use crate::script::ExplicitOutput;
use crate::sweep::Sweep;
use crate::taptree::TapOutput;
use crate::time::RelativeTime;
use crate::Error;

/// A checkpoint output's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointPolicy {
	pub owner: XOnlyPublicKey,
	pub operator: XOnlyPublicKey,
	/// The checkpoint's own salt, unique to this checkpoint.
	pub salt: [u8; 32],
	pub chain: Chain,
	/// The input batch's sweep with notice; `None` for a coin of a batch
	/// without a sweep.
	pub sweep: Option<Sweep>,
	/// The checkpoint of a `vtxo-2` coin: its collaborative path is
	/// `arca/collab-2` ([`crate::collab`]), `[[program, data], sweep]`.
	pub v2: bool,
	/// The owner's exit; `None` for a checkpoint that only owner and
	/// operator together spend. See the [module documentation](self).
	pub exit: Option<CheckpointExit>,
}

/// A checkpoint's exit: the coin's own exit delay, and for a coin of a
/// supervised asset its landing over the checkpoint's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointExit {
	pub delay: RelativeTime,
	/// The landing leaf's terms over the checkpoint, at the spending input's
	/// own index whichever the leaf: the holder's landing program,
	/// the asset, and the checkpoint's value less the coin's allowance.
	pub landing: Option<LandingTerms>,
}

impl CheckpointExit {
	/// The plain exit after `delay`.
	pub fn plain(delay: RelativeTime) -> CheckpointExit {
		CheckpointExit { delay, landing: None }
	}
}

/// Whether a coin of `leaf` may move into a checkpoint with an exit: a plain
/// leaf (`vtxo-1`, `vtxo-2`), whose exit pays wherever its owner signs, or a
/// landing leaf (`landing-1`, `landing-2`), whose checkpoint lands as the
/// leaf does, at its own index.
pub fn exit_allowed(leaf: &LeafPolicy) -> bool {
	leaf.htlc.is_none() && leaf.order.is_none() && leaf.enclave.is_none() && leaf.channel.is_none() && leaf.claim.is_none()
}

impl CheckpointPolicy {
	pub fn leaf_constant(&self) -> [u8; 32] {
		self.chain.leaf_constant(&self.salt)
	}

	pub fn collab_script(&self) -> Script {
		rebindable_two_party(&self.owner, &self.operator, &self.leaf_constant())
	}

	/// The sweep leaf, when the coin's batch has one.
	pub fn sweep_script(&self) -> Option<Script> {
		self.sweep.map(|s| s.script())
	}

	/// The parameters of `arca/collab-2` for this checkpoint.
	pub fn collab2(&self) -> Collab2 {
		Collab2 { owner: self.owner, operator: self.operator, salt: self.salt, chain: self.chain }
	}

	/// The owner's exit leaf, when the checkpoint has one: the coin's own
	/// exit script, `<delay> CSV DROP <A> CHECKSIG`, or its landing, which
	/// inspects the output at the spending input's own index
	/// ([`LandingTerms::script_at_own_index`]).
	pub fn exit_script(&self) -> Option<Script> {
		self.exit.map(|e| match e.landing {
			Some(l) => l.script_at_own_index(&self.owner, e.delay),
			None => exit_script(&self.owner, e.delay),
		})
	}

	/// `[collab, sweep]`, both at depth 1; a `vtxo-2` coin's checkpoint
	/// `[[arca/collab-2, data], sweep]`. Without a sweep: `[collab]`, or
	/// `[arca/collab-2, data]`. With the owner's exit, the shapes the
	/// [module documentation](self) gives.
	pub fn taproot(&self) -> TapOutput {
		match (self.v2, self.sweep_script(), self.exit_script()) {
			(true, sweep, None) => self.collab2().taproot_of(sweep),
			(true, None, Some(exit)) => self.collab2().taproot_of(Some(exit)),
			(true, Some(sweep), Some(exit)) => self.collab2().taproot_beside(sweep, exit),
			(false, Some(sweep), None) => TapOutput::new(vec![(1, self.collab_script()), (1, sweep)]),
			(false, None, None) => TapOutput::new(vec![(0, self.collab_script())]),
			(false, None, Some(exit)) => TapOutput::new(vec![(1, self.collab_script()), (1, exit)]),
			(false, Some(sweep), Some(exit)) => TapOutput::new(vec![(1, self.collab_script()), (2, sweep), (2, exit)]),
		}
	}

	pub fn script_pubkey(&self) -> Script {
		self.taproot().script_pubkey()
	}

	/// The message owner and operator sign for the reassignment. For a
	/// `vtxo-2` coin's checkpoint it is a reassignment of this checkpoint
	/// alone; [`crate::Rebindable::message_in`] names every input.
	pub fn collab_message(&self, asset_in: AssetId, value_in: u64, outputs: &[ExplicitOutput]) -> Result<CsfsMessage, Error> {
		if self.v2 {
			let coin = ExplicitOutput::new(asset_in, value_in, self.script_pubkey()).txout();
			let outs: Vec<elements::TxOut> = outputs.iter().map(|o| o.txout()).collect();
			return self.collab2().message(0, &[coin], &outs);
		}
		two_party_message(&self.leaf_constant(), asset_in, value_in, outputs)
	}

	/// The collaborative witness for `m` committed outputs; for a `vtxo-2`
	/// coin's checkpoint, spent alone at input 0.
	pub fn collab_witness(&self, operator_sig: &Signature, owner_sig: &Signature, m: u8) -> Vec<Vec<u8>> {
		if self.v2 {
			return self.collab2().witness_at(&self.taproot(), &crate::Pair { operator: *operator_sig, owner: *owner_sig }, 1, m);
		}
		self.taproot().witness(&self.collab_script(), two_party_items(operator_sig, owner_sig, m))
	}

	/// The full sweep witness, when the checkpoint has a sweep.
	pub fn sweep_witness(&self, sig: &Signature, k: u32) -> Option<Vec<Vec<u8>>> {
		Some(self.taproot().witness(&self.sweep_script()?, Sweep::witness_items(sig, k)))
	}

	/// The owner's exit witness, when the checkpoint has an exit.
	pub fn exit_witness(&self, owner_sig: &Signature) -> Option<Vec<Vec<u8>>> {
		Some(self.taproot().witness(&self.exit_script()?, vec![owner_sig.as_ref().to_vec()]))
	}
}
