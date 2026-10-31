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
//!
//! RECLAIM-D, on a lowest node built with it ([`NodePolicy::with_delegation`]),
//! takes the release of a coin's current holders: for each owner, a tree
//! ([`ReleaseTree`]) whose leaves are releases and whose inner nodes are
//! delegations ([`crate::release::Delegation`]), checked in [`RECLAIM_STEPS`]
//! steps. Each step reads, top first, `a` (empty: nothing to do) and `d`
//! (empty: a release, `0x01`: a delegation):
//!
//! ```text
//! # witness, bottom to top: <sig_S> <P> <Q> <step_31> … <step_0>
//! # release:    <k> <sig> <K> <> <0x01>                K signed SHA256(P ‖ M), M at input k
//! # delegation: <sig> <K> <e3> <e2> <e1> <0x01> <0x01>  K signed SHA256(Q ‖ K_1 ‖ … ‖ K_m)
//! OP_IF
//!   OP_IF                                             a delegation: the last m keys the steps
//!     OP_FROMALTSTACK                                 before it left, m = 1 + the e set
//!     (OP_SWAP OP_IF OP_FROMALTSTACK OP_SWAP OP_CAT OP_ENDIF) × 3
//!     OP_DEPTH OP_3 OP_SUB OP_PICK OP_SWAP OP_CAT     Q, third from the bottom
//!   OP_ELSE
//!     OP_ROT OP_INSPECTINPUTASSET OP_1 OP_EQUALVERIFY
//!     OP_DEPTH OP_2 OP_SUB OP_PICK OP_SWAP OP_CAT     P, second from the bottom
//!   OP_ENDIF
//!   OP_SHA256 OP_OVER OP_SIZE <32> OP_EQUALVERIFY OP_TOALTSTACK OP_SWAP OP_CHECKSIGFROMSTACKVERIFY
//! OP_ENDIF                                            … 32 steps
//! (OP_FROMALTSTACK <A_i> OP_EQUALVERIFY) for i = n-1 … 0
//! <Q> OP_EQUALVERIFY <P> OP_EQUALVERIFY <S> OP_CHECKSIG
//! ```
//!
//! `P = "Arca/release" ‖ genesis_hash ‖ H` and `Q = "Arca/delegate" ‖
//! genesis_hash`. Every key is checked to be 32 bytes: `OP_CHECKSIGFROMSTACK`
//! passes any non-empty signature for a key of another length (an upgradable
//! key type), so two keys of 33 and 31 bytes over the 64 a delegation signed
//! would release a node nobody under it released. The chain cannot know that
//! a key has delegated, so a release by a key that already did confirms as
//! its holder's would: the operator, whose signature every reclaim needs,
//! refuses it, as it refuses to co-sign any spend that would void a coin it
//! confirmed.

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

/// The steps RECLAIM-D runs: the most releases and delegations, summed over
/// every owner's tree, one reclaim can carry.
pub const RECLAIM_STEPS: usize = 32;

/// The most keys one delegation names: a reassignment's outputs.
pub const MAX_DELEGATES: usize = 4;

/// A tree node's policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePolicy {
	children: Vec<Child>,
	operator: XOnlyPublicKey,
	owners: Vec<XOnlyPublicKey>,
	sweep: Sweep,
	reclaim: Option<Chain>,
	delegated: bool,
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
		Ok(NodePolicy { children, operator, owners, sweep, reclaim, delegated: false })
	}

	/// The same lowest node with RECLAIM-D beside RECLAIM, so that the
	/// holders of coins moved out of round can release it. Refuses a node
	/// without RECLAIM.
	pub fn with_delegation(mut self) -> Result<NodePolicy, Error> {
		if self.reclaim.is_none() {
			return Err(Error::NoOwners);
		}
		self.delegated = true;
		Ok(self)
	}

	/// Whether the node carries RECLAIM-D.
	pub fn delegated(&self) -> bool {
		self.delegated
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

	/// The RECLAIM-D leaf, for a lowest node built with it.
	pub fn reclaim_delegated_script(&self) -> Option<Script> {
		if !self.delegated {
			return None;
		}
		let chain = self.reclaim?;
		Some(reclaim_delegated_script(&self.release_prefix()?, &chain.delegation_prefix(), &self.owners, &self.operator))
	}

	/// The node's output: `[UNROLL, SWEEP]`, `[UNROLL, [SWEEP, RECLAIM]]` for
	/// a lowest node, `[UNROLL, [SWEEP, [RECLAIM, RECLAIM-D]]]` for one with
	/// RECLAIM-D.
	pub fn taproot(&self) -> TapOutput {
		node_taproot_delegated(self.unroll_script(), self.sweep_script(), self.reclaim_script(), self.reclaim_delegated_script())
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

	/// The full RECLAIM-D witness: the operator's signature over the reclaim
	/// and one tree per owner, in owner order ([`reclaim_delegated_items`]).
	pub fn reclaim_delegated_witness(&self, operator_sig: &Signature, trees: &[ReleaseTree]) -> Result<Vec<Vec<u8>>, Error> {
		let script = self.reclaim_delegated_script().ok_or(Error::NoOwners)?;
		if trees.len() != self.owners.len() {
			return Err(Error::ReclaimSignatures { given: trees.len(), needed: self.owners.len() });
		}
		let chain = self.reclaim.ok_or(Error::NoOwners)?;
		let below = reclaim_delegated_items(operator_sig, &self.release_prefix().ok_or(Error::NoOwners)?,
			&chain.delegation_prefix(), trees)?;
		Ok(self.taproot().witness(&script, below))
	}

	/// The operator's reclaim of this lowest node by RECLAIM-D: as
	/// [`NodePolicy::reclaim_tx`], finished with
	/// [`NodePolicy::reclaim_delegated_witness`]'s items.
	pub fn reclaim_delegated_tx(
		&self,
		node: OutPoint,
		value: u64,
		connectors: &[(OutPoint, TxOut)],
		outputs: &[ExplicitOutput],
		connector_to: Script,
		fee: &FeeSource,
	) -> Result<KeySpend, SpendError> {
		let script = self.reclaim_delegated_script().ok_or(Error::NoOwners)?;
		let spent = explicit_txout(self.children[0].asset, value, self.script_pubkey());
		reclaim_tx(self.taproot(), script, (node, spent), connectors, outputs, connector_to, fee)
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

/// One owner's consent to a reclaim by RECLAIM-D: its own release, or its
/// delegation to the keys of a reassignment's outputs and, for each of them in
/// order, a tree in turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseTree {
	/// `key` signed the node's release naming the connector asset held by
	/// input `connector_input`.
	Release { key: XOnlyPublicKey, sig: Signature, connector_input: u32 },
	/// `key` signed a delegation to the keys of `to`, in order (1 to 4).
	Delegation { key: XOnlyPublicKey, sig: Signature, to: Vec<ReleaseTree> },
}

impl ReleaseTree {
	/// The key whose consent this is.
	pub fn key(&self) -> XOnlyPublicKey {
		match self {
			ReleaseTree::Release { key, .. } | ReleaseTree::Delegation { key, .. } => *key,
		}
	}

	/// The steps of RECLAIM-D the tree takes: one per release and delegation.
	pub fn steps(&self) -> usize {
		match self {
			ReleaseTree::Release { .. } => 1,
			ReleaseTree::Delegation { to, .. } => 1 + to.iter().map(ReleaseTree::steps).sum::<usize>(),
		}
	}

	/// Each step's items, top first, in the order RECLAIM-D runs them:
	/// children before the delegation that names them.
	fn push_steps(&self, out: &mut Vec<Vec<Vec<u8>>>) -> Result<(), Error> {
		match self {
			ReleaseTree::Release { key, sig, connector_input } => {
				out.push(vec![vec![1], vec![], key.serialize().to_vec(), sig.as_ref().to_vec(), scriptnum(*connector_input as i64)]);
			},
			ReleaseTree::Delegation { key, sig, to } => {
				if to.is_empty() || to.len() > MAX_DELEGATES {
					return Err(Error::OutputCount(to.len()));
				}
				for t in to {
					t.push_steps(out)?;
				}
				let mut step = vec![vec![1], vec![1]];
				step.extend((0..3).map(|i| if i < to.len() - 1 { vec![1] } else { vec![] }));
				step.push(key.serialize().to_vec());
				step.push(sig.as_ref().to_vec());
				out.push(step);
			},
		}
		Ok(())
	}
}

/// The items below RECLAIM-D, bottom to top: the operator's signature, `P`
/// (`prefix`, [`Chain::release_prefix`]), `Q` (`dprefix`,
/// [`Chain::delegation_prefix`]), then the steps of every owner's tree, in
/// owner order, the first step on top, and an empty item for each step left.
/// Refuses trees that need more than [`RECLAIM_STEPS`] steps.
pub fn reclaim_delegated_items(operator_sig: &Signature, prefix: &[u8], dprefix: &[u8], trees: &[ReleaseTree]) -> Result<Vec<Vec<u8>>, Error> {
	let mut steps = Vec::new();
	for t in trees {
		t.push_steps(&mut steps)?;
	}
	if steps.len() > RECLAIM_STEPS {
		return Err(Error::ReclaimSteps(steps.len()));
	}
	let mut below = vec![operator_sig.as_ref().to_vec(), prefix.to_vec(), dprefix.to_vec()];
	below.extend((steps.len()..RECLAIM_STEPS).map(|_| Vec::new()));
	for step in steps.into_iter().rev() {
		below.extend(step.into_iter().rev());
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

/// The RECLAIM-D leaf over the release prefix `prefix` and the delegation
/// prefix `dprefix` ([`Chain::delegation_prefix`]): see the
/// [module documentation](self). Panics if `owners` is empty.
pub fn reclaim_delegated_script(prefix: &[u8], dprefix: &[u8], owners: &[XOnlyPublicKey], operator: &XOnlyPublicKey) -> Script {
	assert!(!owners.is_empty(), "a reclaim needs an owner");
	let take = [OP_SWAP, OP_IF, OP_FROMALTSTACK, OP_SWAP, OP_CAT, OP_ENDIF];
	let mut b = Builder::new();
	for _ in 0..RECLAIM_STEPS {
		b = b.ops(&[OP_IF, OP_IF, OP_FROMALTSTACK]).ops(&take).ops(&take).ops(&take)
			.ops(&[OP_DEPTH, OP_PUSHNUM_3, OP_SUB, OP_PICK, OP_SWAP, OP_CAT])
			.push_opcode(OP_ELSE)
			.ops(&[OP_ROT, OP_INSPECTINPUTASSET, OP_PUSHNUM_1, OP_EQUALVERIFY])
			.ops(&[OP_DEPTH, OP_PUSHNUM_2, OP_SUB, OP_PICK, OP_SWAP, OP_CAT])
			.push_opcode(OP_ENDIF)
			.ops(&[OP_SHA256, OP_OVER, OP_SIZE]).push_int(32).ops(&[OP_EQUALVERIFY, OP_TOALTSTACK, OP_SWAP, OP_CHECKSIGFROMSTACKVERIFY])
			.push_opcode(OP_ENDIF);
	}
	for a in owners.iter().rev() {
		b = b.push_opcode(OP_FROMALTSTACK).push_slice(&a.serialize()).push_opcode(OP_EQUALVERIFY);
	}
	b.push_slice(dprefix).push_opcode(OP_EQUALVERIFY).push_slice(prefix).push_opcode(OP_EQUALVERIFY)
		.push_slice(&operator.serialize()).push_opcode(OP_CHECKSIG).into_script()
}

/// A node's output: `[UNROLL, SWEEP]`, `[UNROLL, [SWEEP, RECLAIM]]` for a
/// lowest node, and `[UNROLL, [SWEEP, [RECLAIM, RECLAIM-D]]]` for one with
/// RECLAIM-D.
pub fn node_taproot_delegated(unroll: Script, sweep: Script, reclaim: Option<Script>, reclaim_d: Option<Script>) -> TapOutput {
	match (reclaim, reclaim_d) {
		(Some(rc), Some(rd)) => TapOutput::new(vec![(1, unroll), (2, sweep), (3, rc), (3, rd)]),
		(reclaim, _) => node_taproot(unroll, sweep, reclaim),
	}
}

/// A node's output: `[UNROLL, SWEEP]`, or `[UNROLL, [SWEEP, RECLAIM]]` for a
/// lowest node.
pub fn node_taproot(unroll: Script, sweep: Script, reclaim: Option<Script>) -> TapOutput {
	match reclaim {
		None => TapOutput::new(vec![(1, unroll), (1, sweep)]),
		Some(rc) => TapOutput::new(vec![(1, unroll), (2, sweep), (2, rc)]),
	}
}
