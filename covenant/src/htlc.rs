//! `htlc-1`: the hash-locked leaf of the Lightning legs.
//!
//! An `htlc-1` leaf is a leaf ([`crate::LeafPolicy`]) whose exit is replaced
//! by a hash-locked pair. It keeps the leaf's collaborative path, the very
//! script `vtxo-1` carries under the leaf's own salt, and in place of the
//! exit it has two paths, each behind a relative delay on the output's
//! confirmation:
//!
//! ```text
//! collab:  the leaf's collaborative path                                          # <sig_S> <sig_A> <m>
//! claim:   <claim delay> OP_CHECKSEQUENCEVERIFY OP_DROP
//!          OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <h> OP_EQUALVERIFY
//!          <claimer> OP_CHECKSIG                                                  # <sig> <preimage>
//! refund:  <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP
//!          <refund delay> OP_CHECKSEQUENCEVERIFY OP_DROP <refunder> OP_CHECKSIG   # <sig>
//! ```
//!
//! The tree is `[collab, [claim, refund]]`.
//!
//! | Direction | Claims with the preimage | Refunds after the timeout |
//! |---|---|---|
//! | [`HtlcDirection::Send`], a payment out of the tree | the operator, after the operator's delay | the owner, after the leaf's exit delay |
//! | [`HtlcDirection::Receive`], a payment into it | the owner, after the leaf's exit delay | the operator, after the operator's delay |
//!
//! The operator's delay is the shorter ([`HtlcTerms::check`]). Two things
//! follow, and they are why the delays are there.
//!
//! - **The side holding the preimage, or the one that waited out the timeout,
//!   always has time to answer.** Out of the tree, once the operator has paid
//!   the invoice and learned the preimage, an owner who puts the output
//!   on-chain past the timeout cannot refund it in the block that creates it:
//!   the operator claims first, in the gap between the two delays. Into the
//!   tree, an owner who never claimed cannot take the output once the
//!   operator's Lightning payment has been failed back: past the timeout the
//!   operator's refund opens before the owner's claim.
//! - **The collaborative path waits for nothing**, so it answers both unilateral
//!   paths. A failed payment goes back to its owner at once, as a new leaf
//!   spent by this path through a checkpoint and a reassignment; a payment
//!   into the tree is claimed the same way once the owner has handed over the
//!   preimage. Whoever then holds that new leaf publishes the spend the moment
//!   the output appears on-chain, before either unilateral path opens.
//!
//! The leaf's owner key and salt are its own, as for every leaf: an `htlc-1`
//! leaf is never funded twice, and a pair made for it fits no other leaf.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::Script;

use crate::entry::hash_gate;
use crate::script::BuilderExt;
use crate::time::{MedianTime, RelativeTime};
use crate::Error;

/// Which way the payment runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HtlcDirection {
	/// Out of the tree: the operator claims with the preimage, the owner
	/// refunds after the timeout.
	Send,
	/// Into the tree: the owner claims with the preimage, the operator
	/// refunds after the timeout.
	Receive,
}

impl HtlcDirection {
	/// Its byte in the encodings: 0 send, 1 receive.
	pub fn byte(self) -> u8 {
		match self {
			HtlcDirection::Send => 0,
			HtlcDirection::Receive => 1,
		}
	}

	/// The direction of a byte.
	pub fn from_byte(b: u8) -> Option<HtlcDirection> {
		match b {
			0 => Some(HtlcDirection::Send),
			1 => Some(HtlcDirection::Receive),
			_ => None,
		}
	}

	/// Its name: `send` or `receive`.
	pub fn name(self) -> &'static str {
		match self {
			HtlcDirection::Send => "send",
			HtlcDirection::Receive => "receive",
		}
	}

	/// The direction of a name.
	pub fn from_name(s: &str) -> Option<HtlcDirection> {
		match s {
			"send" => Some(HtlcDirection::Send),
			"receive" => Some(HtlcDirection::Receive),
			_ => None,
		}
	}
}

/// The paths of an `htlc-1` leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HtlcPath {
	Collab,
	Claim,
	Refund,
}

/// What an `htlc-1` leaf adds to a leaf: the hash it is locked to, the
/// timeout, and the operator's delay. The owner's delay is the leaf's exit
/// delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HtlcTerms {
	pub direction: HtlcDirection,
	/// `h`: the payment hash, `SHA256(preimage)`.
	pub payment_hash: [u8; 32],
	/// The median time from which the refund path opens.
	pub timeout: MedianTime,
	/// The relative delay on the operator's path: its claim out of the tree,
	/// its refund into it. Shorter than the owner's.
	pub operator_delay: RelativeTime,
}

impl HtlcTerms {
	/// Refuses terms the leaf cannot carry: the operator's delay must be
	/// shorter than the owner's, which is `exit_delay`. Without that the side
	/// that should answer could be answered instead.
	pub fn check(&self, exit_delay: RelativeTime) -> Result<(), Error> {
		if self.operator_delay >= exit_delay {
			return Err(Error::HtlcDelays { operator: self.operator_delay.units(), owner: exit_delay.units() });
		}
		Ok(())
	}

	/// The key that claims with the preimage.
	pub fn claimer(&self, owner: XOnlyPublicKey, operator: XOnlyPublicKey) -> XOnlyPublicKey {
		match self.direction {
			HtlcDirection::Send => operator,
			HtlcDirection::Receive => owner,
		}
	}

	/// The key that refunds after the timeout.
	pub fn refunder(&self, owner: XOnlyPublicKey, operator: XOnlyPublicKey) -> XOnlyPublicKey {
		match self.direction {
			HtlcDirection::Send => owner,
			HtlcDirection::Receive => operator,
		}
	}

	/// The claim's relative delay, for a leaf of exit delay `exit_delay`.
	pub fn claim_delay(&self, exit_delay: RelativeTime) -> RelativeTime {
		match self.direction {
			HtlcDirection::Send => self.operator_delay,
			HtlcDirection::Receive => exit_delay,
		}
	}

	/// The refund's relative delay, for a leaf of exit delay `exit_delay`.
	pub fn refund_delay(&self, exit_delay: RelativeTime) -> RelativeTime {
		match self.direction {
			HtlcDirection::Send => exit_delay,
			HtlcDirection::Receive => self.operator_delay,
		}
	}

	/// `<delay> CSV DROP`, the hash gate, `<claimer> CHECKSIG`.
	pub(crate) fn claim_script(&self, owner: &XOnlyPublicKey, operator: &XOnlyPublicKey, exit_delay: RelativeTime) -> Script {
		let b = Builder::new().push_int(self.claim_delay(exit_delay).to_sequence() as i64).ops(&[OP_CSV, OP_DROP]);
		hash_gate(b, &self.payment_hash).push_slice(&self.claimer(*owner, *operator).serialize())
			.push_opcode(OP_CHECKSIG).into_script()
	}

	/// `<timeout> CLTV DROP <delay> CSV DROP <refunder> CHECKSIG`.
	pub(crate) fn refund_script(&self, owner: &XOnlyPublicKey, operator: &XOnlyPublicKey, exit_delay: RelativeTime) -> Script {
		Builder::new().push_int(self.timeout.to_consensus_u32() as i64).ops(&[OP_CLTV, OP_DROP])
			.push_int(self.refund_delay(exit_delay).to_sequence() as i64).ops(&[OP_CSV, OP_DROP])
			.push_slice(&self.refunder(*owner, *operator).serialize()).push_opcode(OP_CHECKSIG).into_script()
	}

	/// The items below the claim script: the claimer's signature and the
	/// preimage.
	pub fn claim_items(sig: &Signature, preimage: &[u8; 32]) -> Vec<Vec<u8>> {
		vec![sig.as_ref().to_vec(), preimage.to_vec()]
	}
}
