//! The hash-locked entry.
//!
//! In a round, a lowest node does not pay a leaf directly. It pays an entry
//! that can only move into the owner's leaf, and only with the preimage of an
//! unlock hash the operator chose; the operator reveals the preimage when it
//! claims the forfeit of the owner's old leaf, which makes a refresh atomic.
//!
//! ```text
//! unlock:  OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <h> OP_EQUALVERIFY
//!          OP_0 OP_INSPECTOUTPUTASSET OP_1 OP_EQUALVERIFY <asset> OP_EQUALVERIFY
//!          OP_0 OP_INSPECTOUTPUTVALUE OP_1 OP_EQUALVERIFY <value_le8> OP_EQUALVERIFY
//!          OP_0 OP_INSPECTOUTPUTSCRIPTPUBKEY OP_1 OP_EQUALVERIFY <leaf program> OP_EQUAL
//! sweep:   the batch's sweep with notice
//! ```
//!
//! The unlock needs no signature, because its destination is pinned. An entry
//! the owner never unlocks is the operator's to sweep with the rest of the
//! batch.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::{AssetId, Script};

use crate::script::asset_bytes;
use crate::sweep::Sweep;
use crate::taptree::TapOutput;

/// `OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <h> OP_EQUALVERIFY`: a 32-byte
/// preimage of `h`, taken from the witness.
pub(crate) fn hash_gate(b: Builder, h: &[u8; 32]) -> Builder {
	b.push_opcode(OP_SIZE).push_int(32).push_opcode(OP_EQUALVERIFY)
		.push_opcode(OP_SHA256).push_slice(h).push_opcode(OP_EQUALVERIFY)
}

/// A hash-locked entry's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryPolicy {
	/// `h`, the SHA256 of the operator's preimage.
	pub unlock_hash: [u8; 32],
	/// The leaf's asset and value, which output 0 must carry.
	pub asset: AssetId,
	pub value: u64,
	/// The leaf's witness v1 program, which output 0 must pay.
	pub leaf_program: [u8; 32],
	/// The batch's sweep with notice.
	pub sweep: Sweep,
}

impl EntryPolicy {
	pub fn unlock_script(&self) -> Script {
		hash_gate(Builder::new(), &self.unlock_hash)
			.push_int(0).push_opcode(OP_INSPECTOUTPUTASSET).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&asset_bytes(self.asset)).push_opcode(OP_EQUALVERIFY)
			.push_int(0).push_opcode(OP_INSPECTOUTPUTVALUE).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.value.to_le_bytes()).push_opcode(OP_EQUALVERIFY)
			.push_int(0).push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.leaf_program).push_opcode(OP_EQUAL)
			.into_script()
	}

	pub fn sweep_script(&self) -> Script {
		self.sweep.script()
	}

	/// `[unlock, sweep]`, both at depth 1.
	pub fn taproot(&self) -> TapOutput {
		TapOutput::new(vec![(1, self.unlock_script()), (1, self.sweep_script())])
	}

	pub fn script_pubkey(&self) -> Script {
		self.taproot().script_pubkey()
	}

	/// The full unlock witness: the preimage alone.
	pub fn unlock_witness(&self, preimage: &[u8; 32]) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.unlock_script(), vec![preimage.to_vec()])
	}

	/// The full sweep witness.
	pub fn sweep_witness(&self, sig: &elements::secp256k1_zkp::schnorr::Signature, k: u32) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.sweep_script(), Sweep::witness_items(sig, k))
	}
}
