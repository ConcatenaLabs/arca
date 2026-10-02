//! The checkpoint output.
//!
//! An off-chain transfer is two linked transactions: each input leaf is first
//! spent into a checkpoint output, and the reassignment then spends the
//! checkpoints into the receivers' leaves.
//!
//! ```text
//! collab:  <A> and <S>, rebindable, with the checkpoint's own salt
//! sweep:   the sweep with notice of the input's batch
//! ```
//!
//! The checkpoint's salt differs from the leaf's, so a reassignment's
//! signatures do not fit the leaf and a checkpoint's do not fit the checkpoint:
//! the two steps can be neither skipped nor reordered.

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Script};

use crate::leaf::{rebindable_two_party, two_party_items, two_party_message};
use crate::message::{Chain, CsfsMessage};
use crate::script::ExplicitOutput;
use crate::sweep::Sweep;
use crate::taptree::TapOutput;
use crate::Error;

/// A checkpoint output's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointPolicy {
	pub owner: XOnlyPublicKey,
	pub operator: XOnlyPublicKey,
	/// The checkpoint's own salt, unique to this checkpoint.
	pub salt: [u8; 32],
	pub chain: Chain,
	/// The input batch's sweep with notice.
	pub sweep: Sweep,
}

impl CheckpointPolicy {
	pub fn leaf_constant(&self) -> [u8; 32] {
		self.chain.leaf_constant(&self.salt)
	}

	pub fn collab_script(&self) -> Script {
		rebindable_two_party(&self.owner, &self.operator, &self.leaf_constant())
	}

	pub fn sweep_script(&self) -> Script {
		self.sweep.script()
	}

	/// `[collab, sweep]`, both at depth 1.
	pub fn taproot(&self) -> TapOutput {
		TapOutput::new(vec![(1, self.collab_script()), (1, self.sweep_script())])
	}

	pub fn script_pubkey(&self) -> Script {
		self.taproot().script_pubkey()
	}

	/// The message owner and operator sign for the reassignment.
	pub fn collab_message(&self, asset_in: AssetId, value_in: u64, outputs: &[ExplicitOutput]) -> Result<CsfsMessage, Error> {
		two_party_message(&self.leaf_constant(), asset_in, value_in, outputs)
	}

	pub fn collab_witness(&self, operator_sig: &Signature, owner_sig: &Signature, m: u8) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.collab_script(), two_party_items(operator_sig, owner_sig, m))
	}

	pub fn sweep_witness(&self, sig: &Signature, k: u32) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.sweep_script(), Sweep::witness_items(sig, k))
	}
}
