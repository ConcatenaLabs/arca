//! The offboard: leaving the tree for an on-chain output.
//!
//! The owner forfeits a leaf against a hash `h` the operator chose
//! ([`crate::forfeit::Forfeit`]). A round carries an output, below, that
//! anyone can move to the owner's destination by presenting the preimage of
//! `h`, and that the operator reclaims after a delay:
//!
//! ```text
//! unlock:   OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <h> OP_EQUALVERIFY
//!           <record of the output at this input's index> OP_SHA256 <SHA256(record of the destination)> OP_EQUAL
//! reclaim:  <delay> OP_CHECKSEQUENCEVERIFY OP_DROP <S> OP_CHECKSIG
//! ```
//!
//! The record is the tree's injective output record (asset, its prefix, the
//! value's prefix, value, program, witness version + 2), so the destination
//! may be any script, a witness program of any version or not, and its asset
//! and value are explicit. The unlock needs no signature, because its
//! destination is pinned: whoever learns the preimage can broadcast it and
//! choose how the fee is paid (the output's own margin, or a coin of theirs).
//! It pins the output at the input's own index, not output 0, so two offboards
//! that pay one destination the same amount can each be unlocked, in one
//! transaction or two, and one output can never stand for both.
//!
//! The operator learns nothing it needs from the owner after the round: it
//! claims the forfeit by revealing the preimage, which releases the owner's
//! output. If it withholds the preimage, the owner starts its exit of the old
//! leaf at once; the operator must then publish the forfeit within the leaf's
//! exit delay and claim it within the forfeit's refund delay, revealing the
//! preimage, or the owner refunds the forfeit. So the reclaim delay must be
//! longer than the time to unroll the old leaf, plus its exit delay, plus the
//! forfeit's refund delay, plus a margin to broadcast the unlock. That
//! ordering is a parameter rule the scripts do not enforce; a wallet signs an
//! offboard's forfeit only when the delays satisfy it, and starts its exit as
//! soon as the preimage fails to arrive.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{LockTime, OutPoint, Script, Sequence, Transaction};

use crate::entry::hash_gate;
use crate::leaf::exit_script;
use crate::script::{sha256, BuilderExt, ExplicitOutput};
use crate::spend::{assemble, FeeSource, KeySpend, SpendError, UnrollTx, FINAL};
use crate::taptree::TapOutput;
use crate::time::RelativeTime;

/// The longest destination script an offboard pins: the node's limit on a
/// script's size.
pub const MAX_DESTINATION: usize = 10_000;

/// Why an offboard output is not where a round should have it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OffboardError {
	#[error("the round pays no output carrying the offboard with at least the destination's value")]
	Missing,
	#[error("the round pays the offboard {0} times")]
	Repeated(usize),
}

/// An offboard output's policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OffboardPolicy {
	/// `h`: the forfeit's unlock hash, whose preimage releases the output.
	pub unlock_hash: [u8; 32],
	/// What the owner receives: asset, value and script, at the unlocking
	/// input's own index.
	pub destination: ExplicitOutput,
	/// The operator `S`.
	pub operator: XOnlyPublicKey,
	/// How long after the output confirms the operator may reclaim it.
	pub reclaim_delay: RelativeTime,
}

impl OffboardPolicy {
	pub fn unlock_script(&self) -> Script {
		hash_gate(Builder::new(), &self.unlock_hash)
			.current_output_record().push_opcode(OP_SHA256)
			.push_slice(&sha256(&self.destination.record())).push_opcode(OP_EQUAL)
			.into_script()
	}

	pub fn reclaim_script(&self) -> Script {
		exit_script(&self.operator, self.reclaim_delay)
	}

	/// `[unlock, reclaim]`, both at depth 1.
	pub fn taproot(&self) -> TapOutput {
		TapOutput::new(vec![(1, self.unlock_script()), (1, self.reclaim_script())])
	}

	pub fn script_pubkey(&self) -> Script {
		self.taproot().script_pubkey()
	}

	/// The output a round pays: the destination's value plus `reserve`, the
	/// margin that pays the unlock's fee.
	pub fn output(&self, reserve: u64) -> ExplicitOutput {
		ExplicitOutput::new(self.destination.asset, self.destination.value.saturating_add(reserve), self.script_pubkey())
	}

	/// The full unlock witness: the preimage alone.
	pub fn unlock_witness(&self, preimage: &[u8; 32]) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.unlock_script(), vec![preimage.to_vec()])
	}

	/// The full reclaim witness: the operator's signature.
	pub fn reclaim_witness(&self, sig: &Signature) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.reclaim_script(), vec![sig.as_ref().to_vec()])
	}

	/// The unlock of the output at `coin`, holding `value`, into the
	/// destination at output 0, with the preimage of the unlock hash. What the
	/// output holds beyond the destination pays the fee as `fee` says.
	pub fn unlock_tx(&self, coin: OutPoint, value: u64, preimage: &[u8; 32], fee: &FeeSource) -> Result<UnrollTx, SpendError> {
		let spent = ExplicitOutput::new(self.destination.asset, value, self.script_pubkey());
		let mut u = assemble(LockTime::ZERO, vec![(coin, spent.txout(), FINAL)], std::slice::from_ref(&self.destination), fee, FINAL)?;
		u.tx.input[0].witness.script_witness = self.unlock_witness(preimage);
		Ok(u)
	}

	/// The operator's reclaim of the output at `coin`, holding `value`, into
	/// `outputs`, the reclaim delay after the output confirmed. Finish it with
	/// `[signature]`.
	pub fn reclaim(&self, coin: OutPoint, value: u64, outputs: &[ExplicitOutput], fee: &FeeSource) -> Result<KeySpend, SpendError> {
		let spent = ExplicitOutput::new(self.destination.asset, value, self.script_pubkey()).txout();
		KeySpend::build(self.taproot(), self.reclaim_script(), vec![(coin, spent, Sequence(self.reclaim_delay.to_sequence()))], outputs, fee)
	}

	/// The owner's check of the round before it signs the forfeit: the round
	/// pays exactly one output carrying this offboard, explicit, in the
	/// destination's asset and holding at least its value. Returns its index.
	/// Whether the round is final is for the caller to establish.
	pub fn find(&self, round: &Transaction) -> Result<u32, OffboardError> {
		let spk = self.script_pubkey();
		let found: Vec<u32> = round.output.iter().enumerate()
			.filter(|(_, o)| o.script_pubkey == spk)
			.map(|(i, o)| (i, ExplicitOutput::from_txout(o)))
			.filter(|(_, o)| matches!(o, Some(o) if o.asset == self.destination.asset && o.value >= self.destination.value))
			.map(|(i, _)| i as u32)
			.collect();
		match found[..] {
			[] => Err(OffboardError::Missing),
			[i] => Ok(i),
			_ => Err(OffboardError::Repeated(found.len())),
		}
	}
}
