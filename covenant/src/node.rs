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
//! it has signed a release ([`crate::release`]). Owner `i`'s release names
//! `M_i`, the connector asset of the round that made its new leaf, and the
//! script reads `M_i` from the input `k_i` the witness names, explicitly, as the
//! sweep reads the token and the forfeit's claim its connector asset:
//!
//! ```text
//! # witness, bottom to top: <sig_S> <sig_{n-1}> <k_{n-1}> … <sig_0> <k_0>
//! <P> OP_TOALTSTACK                                   P = "Arca/release" ‖ genesis_hash ‖ H
//! OP_INSPECTINPUTASSET OP_1 OP_EQUALVERIFY            M_0, the explicit asset of input k_0
//! OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_SWAP OP_CAT OP_SHA256
//! <A_0> OP_CHECKSIGFROMSTACKVERIFY                    A_0 signed SHA256(P ‖ M_0)
//! …                                                   owners 1 to n-2 the same
//! OP_INSPECTINPUTASSET OP_1 OP_EQUALVERIFY
//! OP_FROMALTSTACK OP_SWAP OP_CAT OP_SHA256
//! <A_{n-1}> OP_CHECKSIGFROMSTACKVERIFY
//! <S> OP_CHECKSIG
//! ```
//!
//! For a single owner the script is `OP_INSPECTINPUTASSET OP_1 OP_EQUALVERIFY
//! <P> OP_SWAP OP_CAT OP_SHA256 <A_0> OP_CHECKSIGFROMSTACKVERIFY <S>
//! OP_CHECKSIG`. Each owner names its own round, so a node whose owners
//! refreshed in different rounds is reclaimed with one atom of each round's
//! connector asset among the inputs; owners of one round share an input.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, OutPoint, Script, TxOut};

use crate::gate::{gate, GateCommitment, Members, MAX_OWNERS};
use crate::message::{release_message, unroll_authorisation, Chain, CsfsMessage, UNROLL_TAG};
use crate::script::{children_hash, scriptnum, BuilderExt, Child, ExplicitOutput};
use crate::spend::{explicit_txout, FeeSource, KeySpend, SpendError, FINAL};
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
		unroll_script(&self.members().commitment(), &self.children)
	}

	pub fn sweep_script(&self) -> Script {
		self.sweep.script()
	}

	/// The fixed part of every release of this node, for a lowest node:
	/// `"Arca/release" ‖ genesis_hash ‖ H`.
	pub fn release_prefix(&self) -> Option<Vec<u8>> {
		self.reclaim.map(|c| c.release_prefix(&self.children_hash()))
	}

	/// The release an owner signs, for a lowest node, naming `connector`,
	/// the connector asset of the round that made the owner's new leaf.
	pub fn release_message(&self, connector: AssetId) -> Option<CsfsMessage> {
		self.release_prefix().map(|p| release_message(&p, connector))
	}

	/// The RECLAIM leaf, for a lowest node.
	pub fn reclaim_script(&self) -> Option<Script> {
		Some(reclaim_script(&self.release_prefix()?, &self.owners, &self.operator))
	}

	/// The node's output: `[UNROLL, SWEEP]`, or `[UNROLL, [SWEEP, RECLAIM]]`
	/// for a lowest node.
	pub fn taproot(&self) -> TapOutput {
		node_taproot(self.unroll_script(), self.sweep_script(), self.reclaim_script())
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
	/// and every owner's release with the index of the input that holds the
	/// connector asset it names, in owner order ([`reclaim_items`]).
	pub fn reclaim_witness(&self, operator_sig: &Signature, releases: &[(Signature, u32)]) -> Result<Vec<Vec<u8>>, Error> {
		let script = self.reclaim_script().ok_or(Error::NoOwners)?;
		let below = reclaim_items(operator_sig, releases, self.owners.len())?;
		Ok(self.taproot().witness(&script, below))
	}

	/// The operator's reclaim of this lowest node at `node`, holding `value`
	/// of its asset: see [`reclaim_tx`].
	pub fn reclaim_tx(
		&self,
		node: OutPoint,
		value: u64,
		connectors: &[(OutPoint, TxOut)],
		outputs: &[ExplicitOutput],
		connector_to: Script,
		fee: &FeeSource,
	) -> Result<KeySpend, SpendError> {
		let script = self.reclaim_script().ok_or(Error::NoOwners)?;
		let spent = explicit_txout(self.children[0].asset, value, self.script_pubkey());
		reclaim_tx(self.taproot(), script, (node, spent), connectors, outputs, connector_to, fee)
	}
}

/// The items below RECLAIM, bottom to top: the operator's signature, then
/// each owner's release signature and the index of the input that holds the
/// connector asset that release names, owner `n-1` first, so owner 0's pair
/// ends on top. `releases` is in owner order and must hold one per owner of
/// the `owners` the node has.
pub fn reclaim_items(operator_sig: &Signature, releases: &[(Signature, u32)], owners: usize) -> Result<Vec<Vec<u8>>, Error> {
	if releases.len() != owners {
		return Err(Error::ReclaimSignatures { given: releases.len(), needed: owners });
	}
	let mut below = vec![operator_sig.as_ref().to_vec()];
	for (sig, k) in releases.iter().rev() {
		below.push(sig.as_ref().to_vec());
		below.push(scriptnum(*k as i64));
	}
	Ok(below)
}

/// The index of the input of `prevouts` (the outputs a transaction's inputs
/// spend, in order) that holds `connector` explicitly: what RECLAIM reads an
/// owner's `M` from.
pub fn connector_index(prevouts: &[TxOut], connector: AssetId) -> Option<u32> {
	prevouts.iter().position(|p| p.asset.explicit() == Some(connector)).map(|i| i as u32)
}

/// The operator's reclaim of a lowest node, an output of `tap` spent by its
/// RECLAIM leaf `script`: input 0 is the node (`node`, the outpoint and the
/// output it spends); inputs 1.. are `connectors`, each an atom of a
/// connector asset some owner's release names (one per round the owners
/// refreshed in), each paid back whole to `connector_to` after `outputs`, for
/// the next claim or reclaim; what is left of the node pays the fee as `fee`
/// says. The operator signs [`KeySpend::sighash`] and finishes it with
/// [`reclaim_items`] over its signature and the releases, each owner's index
/// found with [`connector_index`] in [`KeySpend::prevouts`].
pub fn reclaim_tx(
	tap: TapOutput,
	script: Script,
	node: (OutPoint, TxOut),
	connectors: &[(OutPoint, TxOut)],
	outputs: &[ExplicitOutput],
	connector_to: Script,
	fee: &FeeSource,
) -> Result<KeySpend, SpendError> {
	let mut all = outputs.to_vec();
	let mut inputs = vec![(node.0, node.1, FINAL)];
	for (at, out) in connectors {
		match (out.asset.explicit(), out.value.explicit()) {
			(Some(m), Some(v)) => all.push(ExplicitOutput::new(m, v, connector_to.clone())),
			_ => return Err(SpendError::NotExplicit),
		}
		inputs.push((*at, out.clone(), FINAL));
	}
	KeySpend::build(tap, script, inputs, &all, fee)
}

/// The gated, timed UNROLL leaf of a node whose member tree is `gate_commitment`
/// and whose children are `children`, at outputs `0..r-1`.
pub fn unroll_script(gate_commitment: &GateCommitment, children: &[Child]) -> Script {
	let mut b = gate(Builder::new(), gate_commitment);
	for i in 0..children.len() {
		b = b.output_record(i as i64);
		if i > 0 {
			b = b.push_opcode(OP_CAT);
		}
	}
	b.ops(&[OP_SHA256, OP_DUP]).push_slice(&children_hash(children)).push_opcode(OP_EQUALVERIFY)
		.ops(&[OP_SWAP, OP_CLTV, OP_CAT])
		.push_slice(UNROLL_TAG).ops(&[OP_SWAP, OP_CAT, OP_SHA256, OP_FROMALTSTACK, OP_CHECKSIGFROMSTACK])
		.into_script()
}

/// The RECLAIM leaf over the release prefix `prefix`
/// ([`Chain::release_prefix`]): each owner's signature over
/// `SHA256(prefix ‖ M_i)`, `M_i` read from the input the witness names, in
/// owner order, then the operator's. Panics if `owners` is empty.
pub fn reclaim_script(prefix: &[u8], owners: &[XOnlyPublicKey], operator: &XOnlyPublicKey) -> Script {
	let n = owners.len();
	assert!(n > 0, "a reclaim needs an owner");
	let read_m = |b: Builder| b.push_opcode(OP_INSPECTINPUTASSET).push_int(1).push_opcode(OP_EQUALVERIFY);
	let check = |b: Builder, k: &XOnlyPublicKey| {
		b.ops(&[OP_SWAP, OP_CAT, OP_SHA256]).push_slice(&k.serialize()).push_opcode(OP_CHECKSIGFROMSTACKVERIFY)
	};
	let mut b = Builder::new();
	if n == 1 {
		b = check(read_m(b).push_slice(prefix), &owners[0]);
	} else {
		b = b.push_slice(prefix).push_opcode(OP_TOALTSTACK);
		for k in &owners[..n - 1] {
			b = check(read_m(b).ops(&[OP_FROMALTSTACK, OP_DUP, OP_TOALTSTACK]), k);
		}
		b = check(read_m(b).push_opcode(OP_FROMALTSTACK), &owners[n - 1]);
	}
	b.push_slice(&operator.serialize()).push_opcode(OP_CHECKSIG).into_script()
}

/// A node's output: `[UNROLL, SWEEP]`, or `[UNROLL, [SWEEP, RECLAIM]]` for a
/// lowest node.
pub fn node_taproot(unroll: Script, sweep: Script, reclaim: Option<Script>) -> TapOutput {
	match reclaim {
		None => TapOutput::new(vec![(1, unroll), (1, sweep)]),
		Some(rc) => TapOutput::new(vec![(1, unroll), (2, sweep), (2, rc)]),
	}
}
