//! The sweep, behind the token.
//!
//! The right to sweep a batch is one atom of an asset `T`, issued by the round
//! into the batch's first clock. A sweep path holds no time lock of its own: it
//! requires, as another input of the same transaction, the atom resting at the
//! script `R`, where it arrives only through a clock's RELEASE. It checks the
//! script that holds the atom, not merely the asset, because a roll also spends
//! the atom.
//!
//! ```text
//! # witness, bottom to top: <sig_S> <k>, k the index of the input that carries T
//! OP_DUP OP_INSPECTINPUTASSET OP_1 OP_EQUALVERIFY <T> OP_EQUALVERIFY
//! OP_INSPECTINPUTSCRIPTPUBKEY OP_1 OP_EQUALVERIFY <R> OP_EQUALVERIFY
//! [<W> OP_CHECKSEQUENCEVERIFY OP_DROP]          # with notice
//! [burn body]                                   # issuer-operated batches
//! <S> OP_CHECKSIG
//! ```
//!
//! The batch output's sweep has no notice of its own: the token's wait at `R`
//! is the notice. Every other output above a leaf (inner and lowest nodes,
//! entries, checkpoints) adds `<W> OP_CHECKSEQUENCEVERIFY`, so an output that
//! first appears during or after the notice still gets `W` from its own
//! confirmation.
//!
//! The burn body lets the operator spend only into a bare `OP_RETURN` at the
//! input's own index, carrying the input's full amount of the input's asset.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Script};

use crate::script::{asset_bytes, scriptnum, sha256, BuilderExt};
use crate::time::RelativeTime;

/// A sweep path of one output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sweep {
	/// The sweep token's asset.
	pub token: AssetId,
	/// The witness program of `R`.
	pub r_program: [u8; 32],
	/// The operator's key `S`.
	pub operator: XOnlyPublicKey,
	/// The notice `W` this output waits after its own confirmation; `None`
	/// for the batch output.
	pub notice: Option<RelativeTime>,
	/// Burn-only: the swept value can only be destroyed.
	pub burn: bool,
}

impl Sweep {
	/// The script leaf.
	pub fn script(&self) -> Script {
		let mut b = Builder::new()
			.ops(&[OP_DUP, OP_INSPECTINPUTASSET]).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&asset_bytes(self.token)).push_opcode(OP_EQUALVERIFY)
			.push_opcode(OP_INSPECTINPUTSCRIPTPUBKEY).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.r_program).push_opcode(OP_EQUALVERIFY);
		if let Some(w) = self.notice {
			b = b.push_int(w.to_sequence() as i64).ops(&[OP_CSV, OP_DROP]);
		}
		if self.burn {
			b = b
				.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTVALUE]).push_int(1).push_opcode(OP_EQUALVERIFY)
				.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTVALUE]).push_int(1)
				.ops(&[OP_EQUALVERIFY, OP_EQUALVERIFY])
				.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTASSET]).push_int(1).push_opcode(OP_EQUALVERIFY)
				.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTASSET]).push_int(1)
				.ops(&[OP_EQUALVERIFY, OP_EQUALVERIFY])
				.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTSCRIPTPUBKEY]).push_int(-1)
				.push_opcode(OP_EQUALVERIFY)
				.push_slice(&sha256(&[OP_RETURN.into_u8()])).push_opcode(OP_EQUALVERIFY);
		}
		b.push_slice(&self.operator.serialize()).push_opcode(OP_CHECKSIG).into_script()
	}

	/// The witness items below the script: the operator's signature over the
	/// sweep transaction, and `k`, the index of the input holding the token.
	pub fn witness_items(sig: &Signature, k: u32) -> Vec<Vec<u8>> {
		vec![sig.as_ref().to_vec(), scriptnum(k as i64)]
	}

	/// The sequence this output's input must carry: the notice, or a
	/// non-final sequence when there is none.
	pub fn sequence(&self) -> u32 {
		self.notice.map(|w| w.to_sequence()).unwrap_or(0xffff_fffe)
	}
}
