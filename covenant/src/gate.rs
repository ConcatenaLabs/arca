//! The membership gate on a node's unroll.
//!
//! An unroll needs a signature from one key under the node, proven by a
//! Merkle path to a root in the script. The members are the operator and the
//! owners under the node, in leaf order, padded to a power of two with the
//! operator's key. A member leaf is `SHA256(0x00 ‖ key)` and an inner node
//! `SHA256(0x01 ‖ left ‖ right)`.
//!
//! ```text
//! # witness, bottom to top: <sig> <t> { <sibling> <dir> } per level, top level first, <key>
//! OP_SIZE <32> OP_EQUALVERIFY OP_DUP OP_TOALTSTACK
//! <0x00> OP_SWAP OP_CAT OP_SHA256
//! { OP_SWAP OP_IF OP_SWAP OP_ENDIF OP_CAT OP_1 OP_SWAP OP_CAT OP_SHA256 }  # once per level
//! <root> OP_EQUALVERIFY
//! ```
//!
//! The script commits to the member tree only through its root and depth
//! ([`GateCommitment`]), so a member proves itself with its index and the
//! siblings on its path ([`MemberProof`]) without knowing the other members.
//!
//! The key taken from the witness must be exactly 32 bytes:
//! `OP_CHECKSIGFROMSTACK` treats a key of any other non-zero length as an
//! upgrade placeholder and accepts any non-empty signature for it. The member
//! list only admits [`XOnlyPublicKey`]s.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::XOnlyPublicKey;

use crate::script::{sha256, BuilderExt};

/// The most owners one node takes.
pub const MAX_OWNERS: usize = 1 << 16;

/// The deepest member tree a node may have: `MAX_OWNERS` owners and the
/// operator, padded to `2^17` members.
pub const MAX_DEPTH: usize = 17;

/// One level of a Merkle path, from the member leaf up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathStep {
	pub sibling: [u8; 32],
	/// Whether the running hash is the left operand at this level.
	pub is_left: bool,
}

/// What the gate's script commits to: the member tree's root and its depth
/// (the number of levels between a member leaf and the root).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GateCommitment {
	pub root: [u8; 32],
	pub depth: usize,
}

/// One member's proof of membership: its index in the padded member list and
/// the sibling at each level, bottom level first. The index's bits give the
/// direction at each level, lowest bit first.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemberProof {
	pub index: u32,
	pub siblings: Vec<[u8; 32]>,
}

impl MemberProof {
	/// The path, bottom level first.
	pub fn path(&self) -> Vec<PathStep> {
		self.siblings.iter().enumerate()
			.map(|(level, s)| PathStep { sibling: *s, is_left: self.index.checked_shr(level as u32).unwrap_or(0) & 1 == 0 })
			.collect()
	}

	/// The root this proof reaches from `key`.
	pub fn root(&self, key: &XOnlyPublicKey) -> [u8; 32] {
		self.path().iter().fold(member_leaf(key), |h, step| {
			if step.is_left { inner(&h, &step.sibling) } else { inner(&step.sibling, &h) }
		})
	}

	/// The gate this proof places `key` under.
	pub fn commitment(&self, key: &XOnlyPublicKey) -> GateCommitment {
		GateCommitment { root: self.root(key), depth: self.siblings.len() }
	}

	/// The witness items the gate reads, above the signature and `t`: each
	/// level's sibling and direction, top level first, then the key.
	pub fn witness_items(&self, key: &XOnlyPublicKey) -> Vec<Vec<u8>> {
		let mut w = vec![];
		for step in self.path().iter().rev() {
			w.push(step.sibling.to_vec());
			w.push(if step.is_left { vec![0x01] } else { vec![] });
		}
		w.push(key.serialize().to_vec());
		w
	}
}

/// A node's member tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Members {
	keys: Vec<XOnlyPublicKey>,
	levels: Vec<Vec<[u8; 32]>>,
}

fn member_leaf(key: &XOnlyPublicKey) -> [u8; 32] {
	let mut b = vec![0x00];
	b.extend(key.serialize());
	sha256(&b)
}

fn inner(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
	let mut b = vec![0x01];
	b.extend(left);
	b.extend(right);
	sha256(&b)
}

impl Members {
	/// The operator, then the owners in leaf order, padded with the operator.
	pub fn new(operator: XOnlyPublicKey, owners: &[XOnlyPublicKey]) -> Members {
		let mut keys = Vec::with_capacity(owners.len() + 1);
		keys.push(operator);
		keys.extend_from_slice(owners);
		let n = keys.len().next_power_of_two();
		keys.resize(n, operator);
		let mut level: Vec<[u8; 32]> = keys.iter().map(member_leaf).collect();
		let mut levels = vec![level.clone()];
		while level.len() > 1 {
			level = level.chunks(2).map(|p| inner(&p[0], &p[1])).collect();
			levels.push(level.clone());
		}
		Members { keys, levels }
	}

	/// The padded member list.
	pub fn keys(&self) -> &[XOnlyPublicKey] {
		&self.keys
	}

	pub fn root(&self) -> [u8; 32] {
		self.levels[self.levels.len() - 1][0]
	}

	/// The number of levels between a member leaf and the root.
	pub fn depth(&self) -> usize {
		self.levels.len() - 1
	}

	/// What the gate's script commits to.
	pub fn commitment(&self) -> GateCommitment {
		GateCommitment { root: self.root(), depth: self.depth() }
	}

	/// The proof for the member at `index`. Panics if `index` is past the
	/// padded list.
	pub fn proof(&self, index: usize) -> MemberProof {
		let siblings = self.path(index).iter().map(|s| s.sibling).collect();
		MemberProof { index: index as u32, siblings }
	}

	/// The first position of `key` in the padded list.
	pub fn index_of(&self, key: &XOnlyPublicKey) -> Option<usize> {
		self.keys.iter().position(|k| k == key)
	}

	/// The path from the member at `index` to the root, bottom level first.
	/// Panics if `index` is past the padded list.
	pub fn path(&self, mut index: usize) -> Vec<PathStep> {
		assert!(index < self.keys.len(), "member index out of range");
		let mut path = Vec::with_capacity(self.depth());
		for level in &self.levels[..self.levels.len() - 1] {
			path.push(PathStep { sibling: level[index ^ 1], is_left: index.is_multiple_of(2) });
			index /= 2;
		}
		path
	}

	/// The witness items the gate reads, above the signature and `t`: each
	/// level's sibling and direction, top level first, then the key.
	pub(crate) fn witness_items(&self, index: usize) -> Vec<Vec<u8>> {
		self.proof(index).witness_items(&self.keys[index])
	}
}

/// The gate's opcodes for a member tree known by its commitment, ending with
/// the root check.
pub(crate) fn gate(b: Builder, gate: &GateCommitment) -> Builder {
	let mut b = b.push_opcode(OP_SIZE).push_int(32).push_opcode(OP_EQUALVERIFY)
		.ops(&[OP_DUP, OP_TOALTSTACK]).push_slice(&[0x00]).ops(&[OP_SWAP, OP_CAT, OP_SHA256]);
	for _ in 0..gate.depth {
		b = b.ops(&[OP_SWAP, OP_IF, OP_SWAP, OP_ENDIF, OP_CAT]).push_int(1).ops(&[OP_SWAP, OP_CAT, OP_SHA256]);
	}
	b.push_slice(&gate.root).push_opcode(OP_EQUALVERIFY)
}
