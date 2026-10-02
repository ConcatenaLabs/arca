//! A tree node: the batch output, an inner node or a lowest node.
//!
//! | Output | Leaves | Control blocks |
//! |---|---|---|
//! | Batch output | UNROLL, SWEEP | 65 bytes each |
//! | Inner node | UNROLL, SWEEP with notice | 65 bytes each |
//! | Lowest node | UNROLL, then SWEEP with notice and RECLAIM one level down | 65, 97, 97 |
//!
//! UNROLL lets a member create the node's children at outputs `0..r-1`, with
//! nothing else in the transaction constrained, so a fee output and further
//! inputs may be added. It is gated ([`crate::gate`]) and takes a timed
//! authorisation:
//!
//! ```text
//! <gate>
//! <records of outputs 0..r-1, joined with OP_CAT> OP_SHA256 OP_DUP <H> OP_EQUALVERIFY
//! OP_SWAP OP_CHECKLOCKTIMEVERIFY OP_CAT
//! <"Arca/unroll"> OP_SWAP OP_CAT OP_SHA256 OP_FROMALTSTACK OP_CHECKSIGFROMSTACK
//! ```
//!
//! The member signs `SHA256("Arca/unroll" ‖ H ‖ t)` once; whoever holds the
//! signature, the key and the path can unroll from median time `t`, with
//! `nLockTime` at least `t` and a non-final sequence.
//!
//! RECLAIM lets the operator spend a lowest node at once when every owner under
//! it has signed a release:
//!
//! ```text
//! # witness, bottom to top: <sig_S> <sig_{n-1}> … <sig_0>
//! <release> OP_DUP OP_TOALTSTACK <A_0> OP_CHECKSIGFROMSTACKVERIFY
//! OP_FROMALTSTACK OP_DUP OP_TOALTSTACK <A_1> OP_CHECKSIGFROMSTACKVERIFY
//! …
//! OP_FROMALTSTACK <A_{n-1}> OP_CHECKSIGFROMSTACKVERIFY
//! <S> OP_CHECKSIG
//! ```
//!
//! For a single owner the script is `<release> <A_0> OP_CHECKSIGFROMSTACKVERIFY
//! <S> OP_CHECKSIG`.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{Script, TxOut};

use crate::gate::{Members, MAX_OWNERS};
use crate::message::{unroll_authorisation, Chain, CsfsMessage, UNROLL_TAG};
use crate::script::{children_hash, BuilderExt, Child};
use crate::sweep::Sweep;
use crate::taptree::TapOutput;
use crate::time::MedianTime;
use crate::Error;

/// The most children a node may pin: seven 75-byte records would pass the
/// 520-byte limit on an `OP_CAT` result.
pub const MAX_CHILDREN: usize = 6;

/// A tree node's policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePolicy {
	children: Vec<Child>,
	operator: XOnlyPublicKey,
	owners: Vec<XOnlyPublicKey>,
	sweep: Sweep,
	reclaim: Option<Chain>,
}

impl NodePolicy {
	/// A node with `children` at outputs `0..r-1`, gated to the operator and
	/// `owners` (every owner under the node, in leaf order), with `sweep` as
	/// its sweep path. A lowest node passes the chain its owners' releases are
	/// bound to in `reclaim`, which adds the RECLAIM leaf.
	pub fn new(
		children: Vec<Child>,
		operator: XOnlyPublicKey,
		owners: Vec<XOnlyPublicKey>,
		sweep: Sweep,
		reclaim: Option<Chain>,
	) -> Result<NodePolicy, Error> {
		if children.is_empty() || children.len() > MAX_CHILDREN {
			return Err(Error::ChildCount(children.len()));
		}
		if owners.len() > MAX_OWNERS {
			return Err(Error::TooManyOwners(owners.len()));
		}
		if reclaim.is_some() && owners.is_empty() {
			return Err(Error::NoOwners);
		}
		Ok(NodePolicy { children, operator, owners, sweep, reclaim })
	}

	pub fn children(&self) -> &[Child] {
		&self.children
	}

	pub fn operator(&self) -> XOnlyPublicKey {
		self.operator
	}

	pub fn owners(&self) -> &[XOnlyPublicKey] {
		&self.owners
	}

	pub fn sweep(&self) -> &Sweep {
		&self.sweep
	}

	pub fn reclaim_chain(&self) -> Option<Chain> {
		self.reclaim
	}

	/// `H`, the hash of the children's records.
	pub fn children_hash(&self) -> [u8; 32] {
		children_hash(&self.children)
	}

	pub fn members(&self) -> Members {
		Members::new(self.operator, &self.owners)
	}

	/// The gated, timed UNROLL leaf.
	pub fn unroll_script(&self) -> Script {
		let mut b = self.members().gate(Builder::new());
		for i in 0..self.children.len() {
			b = b.output_record(i as i64);
			if i > 0 {
				b = b.push_opcode(OP_CAT);
			}
		}
		b.ops(&[OP_SHA256, OP_DUP]).push_slice(&self.children_hash()).push_opcode(OP_EQUALVERIFY)
			.ops(&[OP_SWAP, OP_CLTV, OP_CAT])
			.push_slice(UNROLL_TAG).ops(&[OP_SWAP, OP_CAT, OP_SHA256, OP_FROMALTSTACK, OP_CHECKSIGFROMSTACK])
			.into_script()
	}

	pub fn sweep_script(&self) -> Script {
		self.sweep.script()
	}

	/// The release the owners sign, for a lowest node.
	pub fn release_message(&self) -> Option<CsfsMessage> {
		self.reclaim.map(|c| c.release_message(&self.children_hash()))
	}

	/// The RECLAIM leaf, for a lowest node.
	pub fn reclaim_script(&self) -> Option<Script> {
		let release = self.release_message()?;
		let n = self.owners.len();
		let mut b = Builder::new().push_slice(&release.digest);
		if n == 1 {
			b = b.push_slice(&self.owners[0].serialize()).push_opcode(OP_CHECKSIGFROMSTACKVERIFY);
		} else {
			b = b.ops(&[OP_DUP, OP_TOALTSTACK]).push_slice(&self.owners[0].serialize())
				.push_opcode(OP_CHECKSIGFROMSTACKVERIFY);
			for k in &self.owners[1..n - 1] {
				b = b.ops(&[OP_FROMALTSTACK, OP_DUP, OP_TOALTSTACK]).push_slice(&k.serialize())
					.push_opcode(OP_CHECKSIGFROMSTACKVERIFY);
			}
			b = b.push_opcode(OP_FROMALTSTACK).push_slice(&self.owners[n - 1].serialize())
				.push_opcode(OP_CHECKSIGFROMSTACKVERIFY);
		}
		Some(b.push_slice(&self.operator.serialize()).push_opcode(OP_CHECKSIG).into_script())
	}

	/// The node's output: `[UNROLL, SWEEP]`, or `[UNROLL, [SWEEP, RECLAIM]]`
	/// for a lowest node.
	pub fn taproot(&self) -> TapOutput {
		match self.reclaim_script() {
			None => TapOutput::new(vec![(1, self.unroll_script()), (1, self.sweep_script())]),
			Some(rc) => TapOutput::new(vec![(1, self.unroll_script()), (2, self.sweep_script()), (2, rc)]),
		}
	}

	pub fn script_pubkey(&self) -> Script {
		self.taproot().script_pubkey()
	}

	/// The children's outputs, in the order UNROLL pins them.
	pub fn child_outputs(&self) -> Vec<TxOut> {
		self.children.iter().map(|c| c.output().txout()).collect()
	}

	/// The authorisation a member signs to let its holder unroll this node
	/// from median time `t`.
	pub fn unroll_authorisation(&self, t: MedianTime) -> CsfsMessage {
		unroll_authorisation(&self.children_hash(), t)
	}

	/// The full UNROLL witness for `signer`'s authorisation `sig` at time `t`.
	pub fn unroll_witness(&self, sig: &Signature, t: MedianTime, signer: &XOnlyPublicKey) -> Result<Vec<Vec<u8>>, Error> {
		let members = self.members();
		let index = members.index_of(signer).ok_or(Error::NotAMember)?;
		let mut below = vec![sig.as_ref().to_vec(), t.script_bytes()];
		below.extend(members.witness_items(index));
		let script = self.unroll_script();
		Ok(self.taproot().witness(&script, below))
	}

	/// The full SWEEP witness: the operator's signature over the sweep, and
	/// the index of the input that carries the token at `R`.
	pub fn sweep_witness(&self, sig: &Signature, k: u32) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.sweep_script(), Sweep::witness_items(sig, k))
	}

	/// The full RECLAIM witness: the operator's signature over the reclaim,
	/// and every owner's signature over the release, in owner order.
	pub fn reclaim_witness(&self, operator_sig: &Signature, owner_sigs: &[Signature]) -> Result<Vec<Vec<u8>>, Error> {
		let script = self.reclaim_script().ok_or(Error::NoOwners)?;
		if owner_sigs.len() != self.owners.len() {
			return Err(Error::ReclaimSignatures { given: owner_sigs.len(), needed: self.owners.len() });
		}
		let mut below = vec![operator_sig.as_ref().to_vec()];
		below.extend(owner_sigs.iter().rev().map(|s| s.as_ref().to_vec()));
		Ok(self.taproot().witness(&script, below))
	}
}
