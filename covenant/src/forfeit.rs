//! The forfeit output.
//!
//! An old leaf is spent through its collaborative path into a forfeit output:
//!
//! ```text
//! claim:   OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <h> OP_EQUALVERIFY <S> OP_CHECKSIG
//! refund:  <delay> OP_CHECKSEQUENCEVERIFY OP_DROP <A> OP_CHECKSIG
//! ```
//!
//! The operator can take the old coin only by publishing the preimage that
//! unlocks the owner's new entry. If it withholds the preimage, the owner
//! recovers the old coin after the delay. The refund delay must end before the
//! new batch's exit deadline; that ordering is a parameter rule the scripts do
//! not enforce.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::Script;

use crate::entry::hash_gate;
use crate::leaf::exit_script;
use crate::taptree::TapOutput;
use crate::time::RelativeTime;

/// A forfeit output's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ForfeitPolicy {
	/// `h`: the new entry's unlock hash.
	pub unlock_hash: [u8; 32],
	/// The owner `A` of the old leaf.
	pub owner: XOnlyPublicKey,
	/// The operator `S`.
	pub operator: XOnlyPublicKey,
	pub refund_delay: RelativeTime,
}

impl ForfeitPolicy {
	pub fn claim_script(&self) -> Script {
		hash_gate(Builder::new(), &self.unlock_hash)
			.push_slice(&self.operator.serialize()).push_opcode(OP_CHECKSIG).into_script()
	}

	pub fn refund_script(&self) -> Script {
		exit_script(&self.owner, self.refund_delay)
	}

	/// `[claim, refund]`, both at depth 1.
	pub fn taproot(&self) -> TapOutput {
		TapOutput::new(vec![(1, self.claim_script()), (1, self.refund_script())])
	}

	pub fn script_pubkey(&self) -> Script {
		self.taproot().script_pubkey()
	}

	/// The full claim witness: the operator's signature and the preimage,
	/// which the claim publishes.
	pub fn claim_witness(&self, operator_sig: &Signature, preimage: &[u8; 32]) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.claim_script(), vec![operator_sig.as_ref().to_vec(), preimage.to_vec()])
	}

	/// The full refund witness: the owner's signature, on a version 2
	/// transaction whose input sequence is the refund delay.
	pub fn refund_witness(&self, owner_sig: &Signature) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.refund_script(), vec![owner_sig.as_ref().to_vec()])
	}
}
