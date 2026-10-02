//! `htlc-1`: the hash-locked leaf for Lightning and cross-chain legs.
//!
//! Four paths. Each rebindable one has its own salt and commits to output 0
//! with the rebindable message at `m = 1`:
//!
//! ```text
//! claim:        OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <h> OP_EQUALVERIFY
//!               <K_claim> <this input's asset and value> OP_CAT OP_1 OP_CAT
//!               <record 0> OP_SHA256 OP_CAT OP_SHA256 <claimer> OP_CHECKSIGFROMSTACK
//! claim_both:   the same hash gate and message with K_claim_both, then
//!               OP_TUCK <A> OP_CHECKSIGFROMSTACKVERIFY <S> OP_CHECKSIGFROMSTACK
//! refund:       <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <refunder> OP_CHECKSIG
//! refund_both:  <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP, the message with K_refund_both,
//!               then both signatures
//! ```
//!
//! The tree is `[[claim, claim_both], [refund, refund_both]]`. For a payment
//! out of the tree the operator claims and the owner refunds; for a payment
//! into it the owner claims and the operator refunds.
//!
//! Witnesses, bottom to top: claim `<sig> <preimage>`; claim_both
//! `<sig_S> <sig_A> <preimage>`; refund `<sig>`; refund_both `<sig_S> <sig_A>`.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Script};

use crate::entry::hash_gate;
use crate::leaf::TwoPartyCsfs;
use crate::message::{rebind_message, Chain, CsfsMessage};
use crate::script::{BuilderExt, ExplicitOutput};
use crate::taptree::TapOutput;
use crate::time::MedianTime;

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

/// One salt per rebindable path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HtlcSalts {
	pub claim: [u8; 32],
	pub claim_both: [u8; 32],
	pub refund_both: [u8; 32],
}

/// The paths of `htlc-1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HtlcPath {
	Claim,
	ClaimBoth,
	Refund,
	RefundBoth,
}

/// An `htlc-1` output's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HtlcPolicy {
	pub owner: XOnlyPublicKey,
	pub operator: XOnlyPublicKey,
	pub direction: HtlcDirection,
	pub payment_hash: [u8; 32],
	/// The median time after which the refund paths open.
	pub timeout: MedianTime,
	pub salts: HtlcSalts,
	pub chain: Chain,
}

/// The rebindable message at `m = 1`, built in script.
fn one_output_message(b: Builder, k: &[u8; 32]) -> Builder {
	b.push_slice(k).current_input_record().push_opcode(OP_CAT).push_int(1).push_opcode(OP_CAT)
		.output_record(0).ops(&[OP_SHA256, OP_CAT, OP_SHA256])
}

impl HtlcPolicy {
	/// The key that claims alone.
	pub fn claimer(&self) -> XOnlyPublicKey {
		match self.direction {
			HtlcDirection::Send => self.operator,
			HtlcDirection::Receive => self.owner,
		}
	}

	/// The key that refunds alone.
	pub fn refunder(&self) -> XOnlyPublicKey {
		match self.direction {
			HtlcDirection::Send => self.owner,
			HtlcDirection::Receive => self.operator,
		}
	}

	/// `K` of a rebindable path; `None` for the plain refund.
	pub fn leaf_constant(&self, path: HtlcPath) -> Option<[u8; 32]> {
		let salt = match path {
			HtlcPath::Claim => &self.salts.claim,
			HtlcPath::ClaimBoth => &self.salts.claim_both,
			HtlcPath::RefundBoth => &self.salts.refund_both,
			HtlcPath::Refund => return None,
		};
		Some(self.chain.leaf_constant(salt))
	}

	fn k(&self, path: HtlcPath) -> [u8; 32] {
		self.leaf_constant(path).expect("a rebindable path")
	}

	pub fn script(&self, path: HtlcPath) -> Script {
		let timeout = |b: Builder| b.push_int(self.timeout.to_consensus_u32() as i64).ops(&[OP_CLTV, OP_DROP]);
		match path {
			HtlcPath::Claim => one_output_message(hash_gate(Builder::new(), &self.payment_hash), &self.k(path))
				.push_slice(&self.claimer().serialize()).push_opcode(OP_CHECKSIGFROMSTACK).into_script(),
			HtlcPath::ClaimBoth => one_output_message(hash_gate(Builder::new(), &self.payment_hash), &self.k(path))
				.two_party_csfs(&self.owner, &self.operator).into_script(),
			HtlcPath::Refund => timeout(Builder::new())
				.push_slice(&self.refunder().serialize()).push_opcode(OP_CHECKSIG).into_script(),
			HtlcPath::RefundBoth => one_output_message(timeout(Builder::new()), &self.k(path))
				.two_party_csfs(&self.owner, &self.operator).into_script(),
		}
	}

	/// `[[claim, claim_both], [refund, refund_both]]`, all at depth 2.
	pub fn taproot(&self) -> TapOutput {
		TapOutput::new(vec![
			(2, self.script(HtlcPath::Claim)),
			(2, self.script(HtlcPath::ClaimBoth)),
			(2, self.script(HtlcPath::Refund)),
			(2, self.script(HtlcPath::RefundBoth)),
		])
	}

	pub fn script_pubkey(&self) -> Script {
		self.taproot().script_pubkey()
	}

	/// The message a rebindable path signs, for a coin of `value_in` of
	/// `asset_in` spent into `output` at index 0; `None` for the plain refund.
	pub fn message(&self, path: HtlcPath, asset_in: AssetId, value_in: u64, output: &ExplicitOutput) -> Option<CsfsMessage> {
		let k = self.leaf_constant(path)?;
		Some(rebind_message(&k, asset_in, value_in, std::slice::from_ref(output)).expect("one output"))
	}

	/// The full claim witness: the claimer's signature and the preimage.
	pub fn claim_witness(&self, sig: &Signature, preimage: &[u8; 32]) -> Vec<Vec<u8>> {
		let s = self.script(HtlcPath::Claim);
		self.taproot().witness(&s, vec![sig.as_ref().to_vec(), preimage.to_vec()])
	}

	pub fn claim_both_witness(&self, operator_sig: &Signature, owner_sig: &Signature, preimage: &[u8; 32]) -> Vec<Vec<u8>> {
		let s = self.script(HtlcPath::ClaimBoth);
		self.taproot().witness(&s, vec![operator_sig.as_ref().to_vec(), owner_sig.as_ref().to_vec(), preimage.to_vec()])
	}

	/// The full refund witness: the refunder's signature over a transaction
	/// with `nLockTime` at least the timeout and a non-final sequence.
	pub fn refund_witness(&self, sig: &Signature) -> Vec<Vec<u8>> {
		let s = self.script(HtlcPath::Refund);
		self.taproot().witness(&s, vec![sig.as_ref().to_vec()])
	}

	pub fn refund_both_witness(&self, operator_sig: &Signature, owner_sig: &Signature) -> Vec<Vec<u8>> {
		let s = self.script(HtlcPath::RefundBoth);
		self.taproot().witness(&s, vec![operator_sig.as_ref().to_vec(), owner_sig.as_ref().to_vec()])
	}
}
