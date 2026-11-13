//! `htlc-2`: a hash-lock between two holders.
//!
//! A payer `P` locks a coin for a payee `Q` under a hash `h` until a timeout
//! `T`, a median time. The operator `S` co-signs the lock's two
//! collaborative endings and can take the coin by neither alone:
//!
//! | Path | Script | Witness |
//! |---|---|---|
//! | CLAIM-C | the hash gate, then the collaborative path of `Q` and `S` under the leaf's salt | `<sig_S> <sig_Q> <m> <preimage>` |
//! | REFUND-C | `<T> CLTV DROP`, then the collaborative path of `P` and `S` under the same salt | `<sig_S> <sig_P> <m>` |
//! | CLAIM | `<Q's delay> CSV DROP`, the hash gate, `<Q> CHECKSIG` | `<sig_Q> <preimage>` |
//! | REFUND | `<T> CLTV DROP <P's delay> CSV DROP <P> CHECKSIG` | `<sig_P>` |
//!
//! The tree is `[[CLAIM-C, REFUND-C], [CLAIM, REFUND]]`. No path spends the
//! leaf without the preimage before `T`, and none from `T` on without the
//! preimage or `P`. Unlike `htlc-1` ([`crate::htlc`]) the leaf has no
//! collaborative path without a condition: one of `Q` and `S` would take the
//! coin without the preimage, and `P`'s refund would rest on them.
//!
//! Both collaborative paths sign the message the leaf's collaborative path
//! signs ([`crate::leaf`]), under the leaf's one constant `K`. A claim pair
//! and a refund pair of one lock are then two different messages `S` signed
//! under one salt, the evidence the bond slashes ([`crate::bond`]): the
//! operator decides a lock one way only. `S`'s signature of one ending, set
//! beside the other ending's holder's, pays only the outputs that pair
//! committed to, so it moves nothing the first ending did not.
//!
//! The owner of the leaf is `Q`; its exit delay is `Q`'s delay on the chain.
//! `regtest/t29_htlc2_lock.py` proves every path and refusal on a node, and
//! `regtest/vectors.py` exports the scripts this module reproduces.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::Script;

use elements::AssetId;

use crate::entry::hash_gate;
use crate::leaf::{rebindable_two_party, two_party_items, two_party_message};
use crate::message::{Chain, CsfsMessage};
use crate::{Error, ExplicitOutput};
use crate::script::BuilderExt;
use crate::taptree::TapOutput;
use crate::time::{MedianTime, RelativeTime};

/// The paths of an `htlc-2` leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockPath {
	/// `Q` and `S` with the preimage.
	ClaimTogether,
	/// `P` and `S` from the timeout on.
	RefundTogether,
	/// `Q` alone on the chain, with the preimage, after its delay.
	Claim,
	/// `P` alone on the chain, from the timeout on and after its delay.
	Refund,
}

/// What an `htlc-2` leaf locks to: the hash, the timeout, and the payer's
/// key and delay. The payee is the leaf's owner and its delay the leaf's
/// exit delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LockTerms {
	/// `h`: `SHA256(preimage)`.
	pub payment_hash: [u8; 32],
	/// `T`, the median time from which the refund paths open.
	pub timeout: MedianTime,
	/// `P`: the key the coin returns to.
	pub refunder: XOnlyPublicKey,
	/// `P`'s delay on the chain.
	pub refund_delay: RelativeTime,
}

/// An `htlc-2` leaf: its keys, salt and chain, `Q`'s delay, and its terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LockPolicy {
	/// `Q`, the payee: the leaf's owner.
	pub owner: XOnlyPublicKey,
	/// `S`.
	pub operator: XOnlyPublicKey,
	pub salt: [u8; 32],
	pub chain: Chain,
	/// `Q`'s delay on the chain: the leaf's exit delay.
	pub exit_delay: RelativeTime,
	pub terms: LockTerms,
}

/// Why an `htlc-2` leaf cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LockError {
	/// The payee, the payer and the operator must be three keys.
	#[error("an htlc-2 leaf names three distinct keys: payee, payer and operator")]
	SharedKey,
}

impl LockPolicy {
	/// Refuses a lock whose payee, payer and operator are not three keys:
	/// with two of them one, a path meant for one side answers the other.
	pub fn check(&self) -> Result<(), LockError> {
		let (q, s, p) = (self.owner, self.operator, self.terms.refunder);
		if q == s || q == p || s == p {
			return Err(LockError::SharedKey);
		}
		Ok(())
	}

	/// `K` for this leaf, over its salt.
	pub fn leaf_constant(&self) -> [u8; 32] {
		self.chain.leaf_constant(&self.salt)
	}

	/// CLAIM-C: the hash gate, then `Q` and `S` over the outputs.
	pub fn claim_together_script(&self) -> Script {
		let gate = hash_gate(Builder::new(), &self.terms.payment_hash).into_script();
		join(&gate, &rebindable_two_party(&self.owner, &self.operator, &self.leaf_constant()))
	}

	/// REFUND-C: `<T> CLTV DROP`, then `P` and `S` over the outputs.
	pub fn refund_together_script(&self) -> Script {
		let lock = Builder::new().push_int(self.terms.timeout.to_consensus_u32() as i64).ops(&[OP_CLTV, OP_DROP]).into_script();
		join(&lock, &rebindable_two_party(&self.terms.refunder, &self.operator, &self.leaf_constant()))
	}

	/// CLAIM: `<Q's delay> CSV DROP`, the hash gate, `<Q> CHECKSIG`.
	pub fn claim_script(&self) -> Script {
		let b = Builder::new().push_int(self.exit_delay.to_sequence() as i64).ops(&[OP_CSV, OP_DROP]);
		hash_gate(b, &self.terms.payment_hash).push_slice(&self.owner.serialize()).push_opcode(OP_CHECKSIG).into_script()
	}

	/// REFUND: `<T> CLTV DROP <P's delay> CSV DROP <P> CHECKSIG`.
	pub fn refund_script(&self) -> Script {
		Builder::new().push_int(self.terms.timeout.to_consensus_u32() as i64).ops(&[OP_CLTV, OP_DROP])
			.push_int(self.terms.refund_delay.to_sequence() as i64).ops(&[OP_CSV, OP_DROP])
			.push_slice(&self.terms.refunder.serialize()).push_opcode(OP_CHECKSIG).into_script()
	}

	/// The script of a path.
	pub fn script(&self, path: LockPath) -> Script {
		match path {
			LockPath::ClaimTogether => self.claim_together_script(),
			LockPath::RefundTogether => self.refund_together_script(),
			LockPath::Claim => self.claim_script(),
			LockPath::Refund => self.refund_script(),
		}
	}

	/// `[[CLAIM-C, REFUND-C], [CLAIM, REFUND]]`, every leaf at depth 2.
	pub fn taproot(&self) -> TapOutput {
		TapOutput::new(vec![
			(2, self.claim_together_script()),
			(2, self.refund_together_script()),
			(2, self.claim_script()),
			(2, self.refund_script()),
		])
	}

	/// The message both collaborative paths sign for a spend of the coin
	/// (`asset_in`, `value_in`) into `outputs`: a `vtxo-1` leaf's message
	/// under this leaf's `K`, the same for CLAIM-C and REFUND-C.
	pub fn collab_message(&self, asset_in: AssetId, value_in: u64, outputs: &[ExplicitOutput]) -> Result<CsfsMessage, Error> {
		two_party_message(&self.leaf_constant(), asset_in, value_in, outputs)
	}

	/// The output's scriptPubKey.
	pub fn script_pubkey(&self) -> Script {
		self.taproot().script_pubkey()
	}

	/// The full witness of CLAIM-C for `m` committed outputs.
	pub fn claim_together_witness(&self, operator_sig: &Signature, owner_sig: &Signature, m: u8, preimage: &[u8; 32])
		-> Vec<Vec<u8>>
	{
		let mut below = two_party_items(operator_sig, owner_sig, m);
		below.push(preimage.to_vec());
		self.taproot().witness(&self.claim_together_script(), below)
	}

	/// The full witness of REFUND-C for `m` committed outputs. The spend's
	/// lock time is at least the timeout and its input's sequence below
	/// final.
	pub fn refund_together_witness(&self, operator_sig: &Signature, refunder_sig: &Signature, m: u8) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.refund_together_script(), two_party_items(operator_sig, refunder_sig, m))
	}

	/// The full witness of CLAIM: `Q`'s signature and the preimage. The
	/// input's sequence is `Q`'s delay.
	pub fn claim_witness(&self, sig: &Signature, preimage: &[u8; 32]) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.claim_script(), vec![sig.as_ref().to_vec(), preimage.to_vec()])
	}

	/// The full witness of REFUND: `P`'s signature. The spend's lock time is
	/// at least the timeout and its input's sequence `P`'s delay.
	pub fn refund_witness(&self, sig: &Signature) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.refund_script(), vec![sig.as_ref().to_vec()])
	}
}

/// Two scripts run one after the other, as one.
fn join(a: &Script, b: &Script) -> Script {
	let mut v = a.as_bytes().to_vec();
	v.extend_from_slice(b.as_bytes());
	Script::from(v)
}
