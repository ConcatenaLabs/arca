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
//! | CLAIM | `<Q's delay> CSV DROP`, the hash gate, then `Q` alone over the outputs under `K ‖ 01` | `<sig_Q> <m> <preimage>` |
//! | REFUND | `<T> CLTV DROP <P's delay> CSV DROP`, then `P` alone over the outputs under `K ‖ 02` | `<sig_P> <m>` |
//!
//! The tree is `[[CLAIM-C, REFUND-C], [CLAIM, REFUND]]`. No path spends the
//! leaf without the preimage before `T`; from `T` on, the refunds open
//! beside the claims, which stay open with the preimage. On the chain, for
//! a leaf confirmed at `C`, CLAIM opens at `C + d_Q` and REFUND at
//! `max(T, C + d_P)`. Unlike `htlc-1` ([`crate::htlc`]) the leaf has no
//! collaborative path without a condition: one of `Q` and `S` would take the
//! coin without the preimage, and `P`'s refund would rest on them.
//!
//! A lock's payer's delay is at least its payee's and
//! [`REFUND_DELAY_MARGIN_UNITS`] more ([`LockPolicy::check_delays`]): however late
//! the leaf reaches the chain, CLAIM opens that margin before REFUND, so a
//! payee holding the preimage is never beaten to the coin by the payer's
//! unilateral refund.
//!
//! The unilateral endings are rebindable as the collaborative ones are: the
//! holder signs, with `OP_CHECKSIGFROMSTACK`, the message the script builds
//! from the coin and outputs `0..m-1` ([`crate::leaf`]), never the outpoint.
//! A CLAIM or a REFUND signed in advance (a watchtower holds them) therefore
//! spends the leaf wherever its path brings it on the chain, and leaves the
//! inputs and outputs past those it commits to free, so whoever broadcasts it
//! adds a fee coin. CLAIM's message starts with `K ‖ 01`, REFUND's with
//! `K ‖ 02` ([`ALONE_CLAIM`], [`ALONE_REFUND`]): 76 + 32m bytes, so neither
//! is ever a collaborative message (75 + 32m) under the same `K`, and a
//! holder's signature of one path never opens another. The operator signs
//! no message of either.
//!
//! Both collaborative paths sign the message the leaf's collaborative path
//! signs ([`crate::leaf`]), under the leaf's one constant `K`, over the
//! outputs they commit to and not over the path. A claim pair and a refund
//! pair of one lock over different outputs are two different messages `S`
//! signed under one salt, the evidence the bond slashes ([`crate::bond`]),
//! so the operator decides a lock one way only; over the same outputs they
//! are one message, and one outcome whichever lands. `S`'s signature of one
//! ending, set beside the other ending's holder's, pays only the outputs
//! that pair committed to, so it moves nothing the first ending did not.
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
use crate::leaf::{rebindable_one_party, rebindable_two_party, two_party_items, two_party_message};
use crate::message::{Chain, CsfsMessage};
use crate::{Error, ExplicitOutput};
use crate::script::BuilderExt;
use crate::taptree::TapOutput;
use crate::time::{MedianTime, RelativeTime};

/// What a lock's payer's delay exceeds its payee's by, at least: eight
/// 512-second units (4,096 s), an hour to react with the units' rounding.
pub const REFUND_DELAY_MARGIN_UNITS: u16 = 8;

/// The byte after `K` in the message CLAIM's key signs.
pub const ALONE_CLAIM: u8 = 0x01;

/// The byte after `K` in the message REFUND's key signs.
pub const ALONE_REFUND: u8 = 0x02;

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
	/// The payer's delay is shorter than the payee's and the margin.
	#[error("an htlc-2 leaf's payer's delay of {refund} units is shorter than its payee's delay of {claim} units and {margin} more: \
		a late unroll would let the payer's refund open before the payee's claim")]
	RefundDelay { refund: u16, claim: u16, margin: u16 },
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

	/// Refuses a lock whose payer's delay `d_P` is not at least its payee's
	/// `d_Q` and [`REFUND_DELAY_MARGIN_UNITS`]: on the chain CLAIM opens at
	/// `C + d_Q` and REFUND at `max(T, C + d_P)` for a leaf confirmed at
	/// `C`, so with it a payee holding the preimage claims before the
	/// payer's refund opens however late the leaf is unrolled. The scripts
	/// hold without it; a lock made for a purchase is checked with it.
	pub fn check_delays(&self) -> Result<(), LockError> {
		let (refund, claim, margin) = (self.terms.refund_delay.units(), self.exit_delay.units(), REFUND_DELAY_MARGIN_UNITS);
		if (refund as u32) < claim as u32 + margin as u32 {
			return Err(LockError::RefundDelay { refund, claim, margin });
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

	/// The prefix CLAIM's or REFUND's message starts with: `K ‖ byte`.
	pub fn alone_prefix(&self, byte: u8) -> Vec<u8> {
		let mut k = self.leaf_constant().to_vec();
		k.push(byte);
		k
	}

	/// CLAIM: `<Q's delay> CSV DROP`, the hash gate, then `Q` alone over the
	/// outputs under `K ‖ 01`.
	pub fn claim_script(&self) -> Script {
		let b = Builder::new().push_int(self.exit_delay.to_sequence() as i64).ops(&[OP_CSV, OP_DROP]);
		let gate = hash_gate(b, &self.terms.payment_hash).into_script();
		join(&gate, &rebindable_one_party(&self.owner, &self.alone_prefix(ALONE_CLAIM)))
	}

	/// REFUND: `<T> CLTV DROP <P's delay> CSV DROP`, then `P` alone over the
	/// outputs under `K ‖ 02`.
	pub fn refund_script(&self) -> Script {
		let lock = Builder::new().push_int(self.terms.timeout.to_consensus_u32() as i64).ops(&[OP_CLTV, OP_DROP])
			.push_int(self.terms.refund_delay.to_sequence() as i64).ops(&[OP_CSV, OP_DROP]).into_script();
		join(&lock, &rebindable_one_party(&self.terms.refunder, &self.alone_prefix(ALONE_REFUND)))
	}

	/// The message `Q` signs for CLAIM of the coin (`asset_in`, `value_in`)
	/// into `outputs`, at indices `0..m`: under `K ‖ 01`.
	pub fn claim_message(&self, asset_in: AssetId, value_in: u64, outputs: &[ExplicitOutput]) -> Result<CsfsMessage, Error> {
		two_party_message(&self.alone_prefix(ALONE_CLAIM), asset_in, value_in, outputs)
	}

	/// The message `P` signs for REFUND of the coin into `outputs`: under
	/// `K ‖ 02`.
	pub fn refund_message(&self, asset_in: AssetId, value_in: u64, outputs: &[ExplicitOutput]) -> Result<CsfsMessage, Error> {
		two_party_message(&self.alone_prefix(ALONE_REFUND), asset_in, value_in, outputs)
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

	/// The full witness of CLAIM for `m` committed outputs: `Q`'s signature
	/// of [`Self::claim_message`] and the preimage. The input's sequence is
	/// `Q`'s delay.
	pub fn claim_witness(&self, sig: &Signature, m: u8, preimage: &[u8; 32]) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.claim_script(), vec![sig.as_ref().to_vec(), vec![m], preimage.to_vec()])
	}

	/// The full witness of REFUND for `m` committed outputs: `P`'s signature
	/// of [`Self::refund_message`]. The spend's lock time is at least the
	/// timeout and its input's sequence `P`'s delay.
	pub fn refund_witness(&self, sig: &Signature, m: u8) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.refund_script(), vec![sig.as_ref().to_vec(), vec![m]])
	}
}

/// Two scripts run one after the other, as one.
fn join(a: &Script, b: &Script) -> Script {
	let mut v = a.as_bytes().to_vec();
	v.extend_from_slice(b.as_bytes());
	Script::from(v)
}

#[cfg(test)]
mod tests {
	use super::*;
	use elements::hashes::Hash;
	use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey};

	fn key(b: u8) -> XOnlyPublicKey {
		Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[b; 32]).unwrap()).x_only_public_key().0
	}

	/// A payer's delay below the payee's and the margin is refused: a late
	/// unroll would open REFUND before CLAIM.
	#[test]
	fn the_payer_waits_longer_than_the_payee() {
		let at = |d_q: u16, d_p: u16| LockPolicy {
			owner: key(1), operator: key(2), salt: [3; 32], chain: Chain::new(elements::BlockHash::all_zeros()),
			exit_delay: RelativeTime::from_units(d_q).unwrap(),
			terms: LockTerms {
				payment_hash: [4; 32], timeout: MedianTime::from_consensus(1_800_000_000).unwrap(), refunder: key(5),
				refund_delay: RelativeTime::from_units(d_p).unwrap(),
			},
		};
		assert_eq!(at(254, 262).check_delays(), Ok(()));
		assert_eq!(at(254, 338).check_delays(), Ok(()));
		assert_eq!(at(254, 261).check_delays(), Err(LockError::RefundDelay { refund: 261, claim: 254, margin: 8 }));
		assert_eq!(at(254, 254).check_delays(), Err(LockError::RefundDelay { refund: 254, claim: 254, margin: 8 }));
		assert!(at(254, 127).check_delays().is_err());
	}
}
