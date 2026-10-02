//! The leaf: a per-user output at the bottom of the tree.
//!
//! Two script leaves and no operator path. The leaf is spent by owner and
//! operator together, or by the owner alone after the exit delay:
//!
//! ```text
//! collab:  <A> and <S>, each a rebindable signature over the coin spent and the outputs they authorise
//! exit:    <delay> OP_CHECKSEQUENCEVERIFY OP_DROP <A> OP_CHECKSIG
//! ```
//!
//! The collaborative path verifies both signatures with
//! `OP_CHECKSIGFROMSTACK` over a message the script builds from the coin being
//! spent and outputs `0..m-1` ([`crate::message::rebind_message`]), so a pair
//! made before the tree is unrolled stays valid whatever outpoint the leaf ends
//! up at. One script serves every `m` from 1 to 4:
//!
//! ```text
//! # witness, bottom to top: <sig_S> <sig_A> <m>
//! OP_SIZE OP_1 OP_EQUALVERIFY OP_DUP OP_1 OP_5 OP_WITHIN OP_VERIFY
//! OP_DUP <K> <this input's asset and value> OP_CAT OP_SWAP OP_CAT OP_SWAP
//! <record 0> OP_SHA256 OP_ROT OP_SWAP OP_CAT OP_SWAP
//! { OP_DUP <j> OP_GREATERTHAN OP_IF <record j> OP_SHA256 OP_ROT OP_SWAP OP_CAT OP_SWAP OP_ENDIF }  # j = 1, 2, 3
//! OP_DROP OP_SHA256 OP_TUCK <A> OP_CHECKSIGFROMSTACKVERIFY <S> OP_CHECKSIGFROMSTACK
//! ```
//!
//! A pair is valid for every output that carries the leaf's script with the
//! same asset and amount, so the salt is unique to each leaf instance and a
//! leaf script is never funded twice.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Script};

use crate::message::{rebind_message, Chain, CsfsMessage};
use crate::script::{BuilderExt, ExplicitOutput};
use crate::taptree::TapOutput;
use crate::time::RelativeTime;
use crate::Error;

/// The most outputs a rebindable two-party spend commits to.
pub const MAX_OUTPUTS: u8 = 4;

/// The rebindable two-party script for the constant `k`, shared by the leaf
/// and the checkpoint.
pub(crate) fn rebindable_two_party(owner: &XOnlyPublicKey, operator: &XOnlyPublicKey, k: &[u8; 32]) -> Script {
	let slot = |b: Builder, j: i64| b.output_record(j).ops(&[OP_SHA256, OP_ROT, OP_SWAP, OP_CAT, OP_SWAP]);
	let mut b = Builder::new()
		.push_opcode(OP_SIZE).push_int(1).push_opcode(OP_EQUALVERIFY)
		.push_opcode(OP_DUP).push_int(1).push_int(MAX_OUTPUTS as i64 + 1).ops(&[OP_WITHIN, OP_VERIFY])
		.push_opcode(OP_DUP).push_slice(k).current_input_record().ops(&[OP_CAT, OP_SWAP, OP_CAT, OP_SWAP]);
	b = slot(b, 0);
	for j in 1..MAX_OUTPUTS as i64 {
		b = b.push_opcode(OP_DUP).push_int(j).ops(&[OP_GREATERTHAN, OP_IF]);
		b = slot(b, j).push_opcode(OP_ENDIF);
	}
	b.ops(&[OP_DROP, OP_SHA256]).two_party_csfs(owner, operator).into_script()
}

/// `OP_TUCK <A> OP_CHECKSIGFROMSTACKVERIFY <S> OP_CHECKSIGFROMSTACK`: both
/// signatures over the digest on top, `sig_S` below `sig_A`.
pub(crate) trait TwoPartyCsfs {
	fn two_party_csfs(self, owner: &XOnlyPublicKey, operator: &XOnlyPublicKey) -> Self;
}

impl TwoPartyCsfs for Builder {
	fn two_party_csfs(self, owner: &XOnlyPublicKey, operator: &XOnlyPublicKey) -> Builder {
		self.push_opcode(OP_TUCK).push_slice(&owner.serialize()).push_opcode(OP_CHECKSIGFROMSTACKVERIFY)
			.push_slice(&operator.serialize()).push_opcode(OP_CHECKSIGFROMSTACK)
	}
}

/// The message both parties sign for a rebindable two-party spend.
pub(crate) fn two_party_message(
	k: &[u8; 32],
	asset_in: AssetId,
	value_in: u64,
	outputs: &[ExplicitOutput],
) -> Result<CsfsMessage, Error> {
	if outputs.is_empty() || outputs.len() > MAX_OUTPUTS as usize {
		return Err(Error::OutputCount(outputs.len()));
	}
	rebind_message(k, asset_in, value_in, outputs)
}

/// The witness items below a rebindable two-party script.
pub(crate) fn two_party_items(operator_sig: &Signature, owner_sig: &Signature, m: u8) -> Vec<Vec<u8>> {
	vec![operator_sig.as_ref().to_vec(), owner_sig.as_ref().to_vec(), vec![m]]
}

/// A leaf's policy (`vtxo-1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeafPolicy {
	/// The owner's key `A`.
	pub owner: XOnlyPublicKey,
	/// The operator's key `S`.
	pub operator: XOnlyPublicKey,
	/// Unique to this leaf instance.
	pub salt: [u8; 32],
	pub chain: Chain,
	pub exit_delay: RelativeTime,
}

impl LeafPolicy {
	/// `K` for this leaf.
	pub fn leaf_constant(&self) -> [u8; 32] {
		self.chain.leaf_constant(&self.salt)
	}

	pub fn collab_script(&self) -> Script {
		rebindable_two_party(&self.owner, &self.operator, &self.leaf_constant())
	}

	pub fn exit_script(&self) -> Script {
		exit_script(&self.owner, self.exit_delay)
	}

	/// `[collab, exit]`, both at depth 1.
	pub fn taproot(&self) -> TapOutput {
		TapOutput::new(vec![(1, self.collab_script()), (1, self.exit_script())])
	}

	pub fn script_pubkey(&self) -> Script {
		self.taproot().script_pubkey()
	}

	pub fn program(&self) -> [u8; 32] {
		self.taproot().program()
	}

	/// The message owner and operator sign to spend a coin of this leaf,
	/// holding `value_in` of `asset_in`, into `outputs` at indices `0..m`.
	pub fn collab_message(&self, asset_in: AssetId, value_in: u64, outputs: &[ExplicitOutput]) -> Result<CsfsMessage, Error> {
		two_party_message(&self.leaf_constant(), asset_in, value_in, outputs)
	}

	/// The full collaborative witness for `m` committed outputs.
	pub fn collab_witness(&self, operator_sig: &Signature, owner_sig: &Signature, m: u8) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.collab_script(), two_party_items(operator_sig, owner_sig, m))
	}

	/// The full exit witness: the owner's signature over the exit claim, a
	/// version 2 transaction whose input sequence is the exit delay.
	pub fn exit_witness(&self, owner_sig: &Signature) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.exit_script(), vec![owner_sig.as_ref().to_vec()])
	}
}

/// `<delay> OP_CHECKSEQUENCEVERIFY OP_DROP <key> OP_CHECKSIG`: the leaf's exit
/// and the forfeit's refund.
pub(crate) fn exit_script(key: &XOnlyPublicKey, delay: RelativeTime) -> Script {
	Builder::new().push_int(delay.to_sequence() as i64).ops(&[OP_CSV, OP_DROP])
		.push_slice(&key.serialize()).push_opcode(OP_CHECKSIG).into_script()
}
