//! The leaf record: what the holder of a leaf keeps, and how it is checked.
//!
//! A record carries everything a holder needs to verify a leaf against the
//! chain and to take it on-chain alone, and nothing secret: the leaf's
//! template and parameters, its asset and value, the hash-locked entry in
//! front of it, the batch's token and clock schedule `(T, R, S, W, E_0 … E_K)`,
//! and the path from the batch output down to the leaf. Every script on that
//! path is rebuilt from the record, so a record is checked by rebuilding the
//! batch output and comparing it with the one the round transaction pays
//! ([`LeafRecord::validate`]).
//!
//! # The path
//!
//! A batch is a tree of nodes over the leaves' entries. The record holds one
//! level per node from the batch output down to the leaf's lowest node. At each
//! level: the index of the child on the leaf's path, the node's reserve, and the
//! node's other children (their values and witness programs, in order). The
//! child on the path is rebuilt from below, so its value and script are not
//! stored. Above the lowest level the record holds the owner's proof in the
//! node's member tree ([`MemberProof`]), which is what the gate commits to and
//! what the owner's unroll witness carries. At the lowest level it holds the
//! other owners under the node, since that node's RECLAIM names each of them;
//! its member tree is rebuilt from them.
//!
//! `R` is not stored: it is rebuilt from `W` and `S`, so it cannot disagree
//! with them. Nor is the salt: the record holds the owner's nonce and the
//! operator's, and the salt is rebuilt from them
//! (`SHA256("Arca/salt" ‖ owner_nonce ‖ operator_nonce)`,
//! [`crate::leaf::leaf_salt`]). A wallet checks that the owner nonce is the one
//! it picked for this leaf ([`LeafRecord::check_owner`]); validation against the
//! round then shows that the leaf on-chain carries the salt built from it.
//!
//! # The binary form, version 2
//!
//! Integers are little-endian. Asset ids, the token and the genesis hash are in
//! internal byte order.
//!
//! ```text
//! u8    format version, 2
//! u8    template, 1 (vtxo)            u8   template version, 1
//! [32]  owner key A                   the vtxo-1 parameters
//! [32]  owner nonce                   the salt is SHA256("Arca/salt" ‖ owner nonce ‖ operator nonce)
//! [32]  operator nonce
//! u16   exit delay, 512-second units
//! [32]  asset                         the leaf and its entry
//! u64   value
//! [32]  unlock hash h
//! u64   entry reserve
//! [32]  genesis hash                  the batch
//! [32]  operator key S
//! [32]  token T
//! u16   notice W, 512-second units
//! u8    flags: bit 0, the sweeps are burn-only; other bits zero
//! u8    expiry count, 1 to 64, then each expiry E_k as u32
//! u8    level count, 1 to 16, then each level from the batch output down:
//!         u8    child count k, 1 to 6
//!         u8    index of the child on the leaf's path, below k
//!         u64   reserve
//!         (k-1) × (u64 value, [32] witness program)    the other children, in order
//!       above the lowest level:
//!         u32   the owner's index in the node's padded member list
//!         u8    member depth D, 1 to 17, then D × [32] siblings, bottom level first
//!       at the lowest level (the last):
//!         (k-1) × [32]                                 the other owners, in order
//! ```
//!
//! A value is at most [`MAX_VALUE`], and so is every sum the tree implies; the
//! leaf's value is at least 1. Decoding refuses an unknown format version, an
//! unknown template or template version, and anything that does not encode back
//! to the same bytes.
//!
//! # The leaf id
//!
//! The leaf id is never an outpoint: a node's fee is left open, so the
//! transactions above a leaf have no fixed id until they are broadcast. It is
//! the BIP340 tagged hash, tag [`LEAF_ID_TAG`], of
//!
//! ```text
//! batch output's witness program (32) ‖ level count (u8)
//! ‖ the index on the path at each level (u8), from the batch output down
//! ‖ the leaf's witness program (32)
//! ```
//!
//! # The JSON form
//!
//! The JSON form (feature `json`, [`crate::record_json`]) has the same fields.

use std::fmt;
use std::str::FromStr;

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Script, Transaction, TxOut};

use crate::checks::{check_round, RoundCheckFailure};
use crate::clock::{ClockSchedule, MAX_STEPS};
use crate::encode::{DecodeError, Reader};
use crate::gate::{GateCommitment, MemberProof, Members, MAX_DEPTH};
use crate::leaf::leaf_salt;
use crate::message::{unroll_authorisation, Chain, CsfsMessage};
use crate::node::{node_taproot, reclaim_script, unroll_script, MAX_CHILDREN};
use crate::script::{asset_bytes, children_hash, sha256, Child, ExplicitOutput};
use crate::sweep::Sweep;
use crate::taptree::TapOutput;
use crate::time::{MedianTime, RelativeTime};
use crate::{EntryPolicy, LeafPolicy};

/// The record format this crate writes and reads.
pub const RECORD_VERSION: u8 = 2;

/// The most levels a record's path has.
pub const MAX_LEVELS: usize = 16;

/// The largest amount any Sequentia chain allows in one output or one
/// transaction: 400,000,000 coins of 10^8 atoms (the node's `MAX_MONEY` on the
/// Sequentia chains; other chains allow less).
pub const MAX_VALUE: u64 = 400_000_000 * 100_000_000;

/// The tag of the leaf id's BIP340 tagged hash.
pub const LEAF_ID_TAG: &[u8] = b"Arca/leaf-id";

/// The leaf templates this crate knows.
///
/// A record names its template and the template's version; a reader refuses
/// any it does not know, so a new template can be added without a new record
/// format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Template {
	/// `vtxo-1`, the ordinary holding ([`LeafPolicy`]).
	Vtxo1,
}

impl Template {
	/// The template id of `vtxo`.
	pub const VTXO: u8 = 1;

	/// Its id in the binary form.
	pub fn id(self) -> u8 {
		match self {
			Template::Vtxo1 => Template::VTXO,
		}
	}

	/// Its version.
	pub fn version(self) -> u8 {
		match self {
			Template::Vtxo1 => 1,
		}
	}

	/// Its name, without the version.
	pub fn name(self) -> &'static str {
		match self {
			Template::Vtxo1 => "vtxo",
		}
	}

	/// The template with this id and version.
	pub fn from_id(id: u8, version: u8) -> Result<Template, RecordError> {
		match (id, version) {
			(Template::VTXO, 1) => Ok(Template::Vtxo1),
			(Template::VTXO, v) => Err(RecordError::TemplateVersion { template: "vtxo".into(), version: v as u64 }),
			(t, _) => Err(RecordError::Template(t.to_string())),
		}
	}
}

impl fmt::Display for Template {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}-{}", self.name(), self.version())
	}
}

impl FromStr for Template {
	type Err = RecordError;

	/// Reads `name-version`, as `vtxo-1`.
	fn from_str(s: &str) -> Result<Template, RecordError> {
		let (name, version) = s.rsplit_once('-').ok_or_else(|| RecordError::Template(s.into()))?;
		let canonical = !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit())
			&& !(version.len() > 1 && version.starts_with('0'));
		if !canonical {
			return Err(RecordError::Template(s.into()));
		}
		match name {
			"vtxo" => match version.parse::<u64>() {
				Ok(1) => Ok(Template::Vtxo1),
				Ok(v) => Err(RecordError::TemplateVersion { template: name.into(), version: v }),
				Err(_) => Err(RecordError::TemplateVersion { template: name.into(), version: u64::MAX }),
			},
			_ => Err(RecordError::Template(s.into())),
		}
	}
}

/// A child of a node on the path other than the one on the leaf's path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sibling {
	pub value: u64,
	/// Its witness v1 program.
	pub program: [u8; 32],
}

/// A level of the path above the lowest node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpperLevel {
	/// The index of the child on the leaf's path.
	pub index: u8,
	/// The node's reserve: its value less its children's.
	pub reserve: u64,
	/// The node's other children, in order.
	pub siblings: Vec<Sibling>,
	/// The owner's proof in the node's member tree.
	pub member: MemberProof,
}

/// The lowest node on the path: the one whose children are entries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LowestLevel {
	/// The index of the leaf's entry.
	pub index: u8,
	pub reserve: u64,
	/// The other entries, in order.
	pub siblings: Vec<Sibling>,
	/// The owners of the other entries, in order.
	pub owners: Vec<XOnlyPublicKey>,
}

/// A leaf's record. See the [module documentation](self) for its forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafRecord {
	pub template: Template,
	/// The owner's key `A`.
	pub owner: XOnlyPublicKey,
	/// The owner's contribution to the leaf's salt.
	pub owner_nonce: [u8; 32],
	/// The operator's contribution to the leaf's salt.
	pub operator_nonce: [u8; 32],
	pub exit_delay: RelativeTime,
	/// The batch's asset.
	pub asset: AssetId,
	/// The leaf's value.
	pub value: u64,
	/// The entry's unlock hash `h`.
	pub unlock_hash: [u8; 32],
	/// The entry's reserve: the entry holds `value + entry_reserve`.
	pub entry_reserve: u64,
	/// The chain, by its genesis hash.
	pub chain: Chain,
	/// `(T, S, W, E_0 … E_K)`; `S` is the operator's key in every script.
	pub schedule: ClockSchedule,
	/// The sweeps are burn-only (an issuer-operated batch).
	pub burn: bool,
	/// The levels above the lowest node, from the batch output down.
	pub upper: Vec<UpperLevel>,
	pub lowest: LowestLevel,
}

/// A leaf's id: see the [module documentation](self).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeafId(pub [u8; 32]);

impl LeafId {
	/// The id of the leaf whose witness program is `leaf_program`, at
	/// `position` (the index at each level, from the batch output down) under
	/// the batch output whose witness program is `batch_program`.
	pub fn compute(batch_program: &[u8; 32], position: &[u8], leaf_program: &[u8; 32]) -> LeafId {
		let tag = sha256(LEAF_ID_TAG);
		let mut b = Vec::with_capacity(64 + 32 + 1 + position.len() + 32);
		b.extend(tag);
		b.extend(tag);
		b.extend(batch_program);
		b.push(position.len() as u8);
		b.extend(position);
		b.extend(leaf_program);
		LeafId(sha256(&b))
	}
}

impl fmt::Display for LeafId {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		for b in self.0 {
			write!(f, "{:02x}", b)?;
		}
		Ok(())
	}
}

impl FromStr for LeafId {
	type Err = RecordError;

	/// 64 lower-case hex digits.
	fn from_str(s: &str) -> Result<LeafId, RecordError> {
		Ok(LeafId(hex32(s).ok_or_else(|| RecordError::Hex("leaf id".into()))?))
	}
}

/// 64 lower-case hex digits.
pub(crate) fn hex32(s: &str) -> Option<[u8; 32]> {
	let v = hex_lower(s)?;
	v.try_into().ok()
}

/// Lower-case hex, an even number of digits.
pub(crate) fn hex_lower(s: &str) -> Option<Vec<u8>> {
	let b = s.as_bytes();
	if b.len() % 2 != 0 {
		return None;
	}
	let digit = |c: u8| match c {
		b'0'..=b'9' => Some(c - b'0'),
		b'a'..=b'f' => Some(c - b'a' + 10),
		_ => None,
	};
	b.chunks(2).map(|p| Some(digit(p[0])? << 4 | digit(p[1])?)).collect()
}

/// Why a record does not decode, is malformed, or does not match the chain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
	#[error(transparent)]
	Decode(#[from] DecodeError),
	#[error("unknown record format version {0}")]
	Version(u64),
	#[error("unknown leaf template {0}")]
	Template(String),
	#[error("leaf template {template} has no version {version} known here")]
	TemplateVersion { template: String, version: u64 },
	#[error("a value of {0} is out of range")]
	Value(u64),
	#[error("the values on the path add up to more than {max}", max = MAX_VALUE)]
	ValueSum,
	#[error("{0} levels; a record has 1 to {max}", max = MAX_LEVELS)]
	Levels(usize),
	#[error("level {level} has {count} children; a node has 1 to {max}", max = MAX_CHILDREN)]
	Children { level: usize, count: usize },
	#[error("level {level}: index {index} is past its {count} children")]
	Index { level: usize, index: usize, count: usize },
	#[error("the lowest level names {owners} other owners for {siblings} other entries")]
	Owners { owners: usize, siblings: usize },
	#[error("level {level}: a member path of {depth} levels; it has 1 to {max}", max = MAX_DEPTH)]
	MemberDepth { level: usize, depth: usize },
	#[error("level {level}: member index {index} is not an owner's place in a tree of depth {depth}")]
	MemberIndex { level: usize, index: u32, depth: usize },
	#[error("level {level}: another child of the node carries the same script as the one on the leaf's path")]
	DuplicateChild { level: usize },
	#[error("the record is for another owner's key")]
	NotOwner,
	#[error("the record's owner nonce is not the one the wallet picked for this leaf")]
	OwnerNonce,
	#[error("the clock schedule: {0}")]
	Schedule(crate::Error),
	#[error("not JSON: {0}")]
	Json(String),
	#[error("JSON field {0}: missing, unknown or misplaced")]
	Field(String),
	#[error("JSON field {0} has the wrong type or is out of range")]
	Type(String),
	#[error("JSON field {0} is not lower-case hex of the right length")]
	Hex(String),
	#[error("JSON field {0} is not a key")]
	Key(String),
	#[error("JSON field {0} is not a canonical decimal amount")]
	Amount(String),
	#[error("the round pays no output equal to the batch output the record rebuilds")]
	BatchOutputMissing,
	#[error("the round pays the batch output the record rebuilds {0} times")]
	BatchOutputRepeated(usize),
	#[error("the output is not the batch output the record rebuilds")]
	BatchOutputMismatch,
	#[error(transparent)]
	Round(#[from] RoundCheckFailure),
}

impl RecordError {
	/// A short name for the kind of error, as the golden vectors name it.
	pub fn kind(&self) -> &'static str {
		use RecordError::*;
		match self {
			Decode(e) => match e {
				DecodeError::UnexpectedEnd => "end",
				DecodeError::TrailingBytes(_) => "trailing",
				DecodeError::Version(_) => "version",
				DecodeError::PolicyType(_) => "template",
				DecodeError::Key => "key",
				DecodeError::Flag(_) => "flag",
				DecodeError::Count(_) | DecodeError::NonCanonical => "count",
				DecodeError::Time(_) => "time",
				DecodeError::Policy(_) => "count",
			},
			Version(_) => "version",
			Template(_) => "template",
			TemplateVersion { .. } => "template_version",
			Value(_) | ValueSum | Amount(_) => "value",
			Levels(_) | Children { .. } | Owners { .. } | MemberDepth { .. } | Schedule(_) => "count",
			Index { .. } | MemberIndex { .. } => "index",
			DuplicateChild { .. } => "duplicate",
			NotOwner | OwnerNonce => "owner",
			Json(_) => "json",
			Field(_) => "field",
			Type(_) => "type",
			Hex(_) => "hex",
			Key(_) => "key",
			BatchOutputMissing | BatchOutputRepeated(_) | BatchOutputMismatch => "batch_output",
			Round(_) => "round",
		}
	}
}

fn sum(a: u64, b: u64) -> Result<u64, RecordError> {
	a.checked_add(b).filter(|v| *v <= MAX_VALUE).ok_or(RecordError::ValueSum)
}

fn bounded(v: u64) -> Result<u64, RecordError> {
	if v > MAX_VALUE { Err(RecordError::Value(v)) } else { Ok(v) }
}

impl LeafRecord {
	/// The number of levels on the path.
	pub fn levels(&self) -> usize {
		self.upper.len() + 1
	}

	/// The index on the path at each level, from the batch output down.
	pub fn position(&self) -> Vec<u8> {
		self.upper.iter().map(|l| l.index).chain([self.lowest.index]).collect()
	}

	/// The operator's key `S`.
	pub fn operator(&self) -> XOnlyPublicKey {
		self.schedule.operator
	}

	/// The leaf's salt, rebuilt from the two nonces.
	pub fn salt(&self) -> [u8; 32] {
		leaf_salt(&self.owner_nonce, &self.operator_nonce)
	}

	/// The wallet's check that the record is for its key and for the nonce it
	/// picked for this leaf, so the salt holds its contribution. A wallet that
	/// never repeats a nonce is then never given a leaf script it already
	/// holds. It runs this as well as [`LeafRecord::validate`].
	pub fn check_owner(&self, owner: &XOnlyPublicKey, owner_nonce: &[u8; 32]) -> Result<(), RecordError> {
		if self.owner != *owner {
			return Err(RecordError::NotOwner);
		}
		if self.owner_nonce != *owner_nonce {
			return Err(RecordError::OwnerNonce);
		}
		Ok(())
	}

	/// Checks the record's shape: counts, indices and value bounds. Every
	/// other method that reads the path runs this first.
	pub fn check(&self) -> Result<(), RecordError> {
		if self.value == 0 || self.value > MAX_VALUE {
			return Err(RecordError::Value(self.value));
		}
		bounded(self.entry_reserve)?;
		sum(self.value, self.entry_reserve)?;
		if self.levels() > MAX_LEVELS {
			return Err(RecordError::Levels(self.levels()));
		}
		let shape = |level: usize, index: u8, siblings: &[Sibling], reserve: u64| -> Result<(), RecordError> {
			let count = siblings.len() + 1;
			if count > MAX_CHILDREN {
				return Err(RecordError::Children { level, count });
			}
			if index as usize >= count {
				return Err(RecordError::Index { level, index: index as usize, count });
			}
			bounded(reserve)?;
			for s in siblings {
				bounded(s.value)?;
			}
			Ok(())
		};
		for (level, l) in self.upper.iter().enumerate() {
			shape(level, l.index, &l.siblings, l.reserve)?;
			let depth = l.member.siblings.len();
			if depth == 0 || depth > MAX_DEPTH {
				return Err(RecordError::MemberDepth { level, depth });
			}
			// Index 0 is the operator's; an owner sits past it and inside the tree.
			if l.member.index == 0 || (l.member.index as u64) >> depth != 0 {
				return Err(RecordError::MemberIndex { level, index: l.member.index, depth });
			}
		}
		let l = &self.lowest;
		shape(self.upper.len(), l.index, &l.siblings, l.reserve)?;
		if l.owners.len() != l.siblings.len() {
			return Err(RecordError::Owners { owners: l.owners.len(), siblings: l.siblings.len() });
		}
		Ok(())
	}

	/// The leaf's policy.
	pub fn leaf(&self) -> LeafPolicy {
		LeafPolicy {
			owner: self.owner,
			operator: self.schedule.operator,
			salt: self.salt(),
			chain: self.chain,
			exit_delay: self.exit_delay,
		}
	}

	/// Rebuilds every output on the path, from the leaf up to the batch output.
	/// This checks the record's shape and its sums, not the chain.
	pub fn branch(&self) -> Result<Branch, RecordError> {
		self.check()?;
		let operator = self.schedule.operator;
		let leaf = self.leaf();
		let entry = EntryPolicy {
			unlock_hash: self.unlock_hash,
			asset: self.asset,
			value: self.value,
			leaf_program: leaf.program(),
			sweep: self.schedule.sweep(true, self.burn),
		};
		let entry_value = sum(self.value, self.entry_reserve)?;
		let entry_tap = entry.taproot();
		let mut child = Child::new(self.asset, entry_value, entry_tap.program());
		let levels = self.levels();
		let mut nodes = Vec::with_capacity(levels);

		// The lowest node: its owners are known, so its member tree is rebuilt.
		let l = &self.lowest;
		let level = levels - 1;
		let children = self.children(level, &l.siblings, l.index, child)?;
		let mut owners = l.owners.clone();
		owners.insert(l.index as usize, self.owner);
		let members = Members::new(operator, &owners);
		let release = self.chain.release_message(&children_hash(&children));
		let reclaim = reclaim_script(&release.digest, &owners, &operator);
		let node = BranchNode::new(
			children, l.index as usize, l.reserve, operator, members.commitment(),
			members.proof(1 + l.index as usize), self.schedule.sweep(level != 0, self.burn),
			Some(Reclaim { owners, release, script: reclaim }),
		)?;
		child = Child::new(self.asset, node.value, node.program());
		nodes.push(node);

		// The levels above, bottom up.
		for (level, u) in self.upper.iter().enumerate().rev() {
			let children = self.children(level, &u.siblings, u.index, child)?;
			let node = BranchNode::new(
				children, u.index as usize, u.reserve, operator, u.member.commitment(&self.owner),
				u.member.clone(), self.schedule.sweep(level != 0, self.burn), None,
			)?;
			child = Child::new(self.asset, node.value, node.program());
			nodes.push(node);
		}
		nodes.reverse();
		Ok(Branch { leaf, entry, entry_value, entry_tap, nodes })
	}

	/// A node's children: the siblings with `child` at `index`. Refuses a
	/// sibling that carries the same script as `child`, which only a node
	/// script funded twice can produce.
	fn children(&self, level: usize, siblings: &[Sibling], index: u8, child: Child) -> Result<Vec<Child>, RecordError> {
		if siblings.iter().any(|s| s.program == child.program) {
			return Err(RecordError::DuplicateChild { level });
		}
		let mut children: Vec<Child> = siblings.iter().map(|s| Child::new(self.asset, s.value, s.program)).collect();
		children.insert(index as usize, child);
		Ok(children)
	}

	/// The leaf's id.
	pub fn leaf_id(&self) -> Result<LeafId, RecordError> {
		Ok(self.branch()?.leaf_id())
	}

	/// Checks the record against the round transaction that created its
	/// batch: the round pays exactly one output equal to the batch output the
	/// record rebuilds (asset, value and script), so the leaf is where the
	/// record says; and the round passes the five client checks on the token
	/// and its clock ([`check_round`]) for the record's schedule and every
	/// sweep path above the leaf.
	///
	/// This is the check a wallet runs before it accepts a leaf. Whether the
	/// round is final (its block certified and its anchor buried) is for the
	/// caller to establish.
	pub fn validate(&self, round: &Transaction) -> Result<ValidLeaf, RecordError> {
		let branch = self.branch()?;
		let out = branch.batch_output();
		let found: Vec<usize> = round.output.iter().enumerate()
			.filter(|(_, o)| ExplicitOutput::from_txout(o).as_ref() == Some(&out))
			.map(|(i, _)| i)
			.collect();
		let batch_vout = match found[..] {
			[] => return Err(RecordError::BatchOutputMissing),
			[i] => i as u32,
			_ => return Err(RecordError::BatchOutputRepeated(found.len())),
		};
		check_round(round, &self.schedule, &branch.sweeps())?;
		Ok(ValidLeaf { leaf_id: branch.leaf_id(), batch_vout, branch })
	}

	/// Checks the path alone against one output: it must be the batch output
	/// the record rebuilds. This does not check the token or the clock, which
	/// only the round transaction shows; a wallet accepts a leaf only after
	/// [`LeafRecord::validate`].
	pub fn validate_batch_output(&self, output: &TxOut) -> Result<Branch, RecordError> {
		let branch = self.branch()?;
		if ExplicitOutput::from_txout(output).as_ref() != Some(&branch.batch_output()) {
			return Err(RecordError::BatchOutputMismatch);
		}
		Ok(branch)
	}

	/// The binary form. Refuses a record that [`LeafRecord::check`] refuses.
	pub fn to_bytes(&self) -> Result<Vec<u8>, RecordError> {
		self.check()?;
		let mut w = Vec::with_capacity(256 + 160 * self.levels());
		w.extend([RECORD_VERSION, self.template.id(), self.template.version()]);
		w.extend(self.owner.serialize());
		w.extend(self.owner_nonce);
		w.extend(self.operator_nonce);
		w.extend(self.exit_delay.units().to_le_bytes());
		w.extend(asset_bytes(self.asset));
		w.extend(self.value.to_le_bytes());
		w.extend(self.unlock_hash);
		w.extend(self.entry_reserve.to_le_bytes());
		w.extend(self.chain.genesis_bytes());
		w.extend(self.schedule.operator.serialize());
		w.extend(asset_bytes(self.schedule.token));
		w.extend(self.schedule.notice.units().to_le_bytes());
		w.push(self.burn as u8);
		w.push(self.schedule.expiries().len() as u8);
		for e in self.schedule.expiries() {
			w.extend(e.to_consensus_u32().to_le_bytes());
		}
		w.push(self.levels() as u8);
		let siblings = |w: &mut Vec<u8>, index: u8, reserve: u64, siblings: &[Sibling]| {
			w.extend([siblings.len() as u8 + 1, index]);
			w.extend(reserve.to_le_bytes());
			for s in siblings {
				w.extend(s.value.to_le_bytes());
				w.extend(s.program);
			}
		};
		for u in &self.upper {
			siblings(&mut w, u.index, u.reserve, &u.siblings);
			w.extend(u.member.index.to_le_bytes());
			w.push(u.member.siblings.len() as u8);
			for s in &u.member.siblings {
				w.extend(s);
			}
		}
		siblings(&mut w, self.lowest.index, self.lowest.reserve, &self.lowest.siblings);
		for o in &self.lowest.owners {
			w.extend(o.serialize());
		}
		Ok(w)
	}

	/// Reads the binary form, which must hold exactly one record.
	pub fn from_bytes(data: &[u8]) -> Result<LeafRecord, RecordError> {
		let mut r = Reader::new(data);
		let version = r.u8()?;
		if version != RECORD_VERSION {
			return Err(RecordError::Version(version as u64));
		}
		let template_id = r.u8()?;
		let template_version = r.u8()?;
		let template = Template::from_id(template_id, template_version)?;
		let owner = r.key()?;
		let owner_nonce = r.array32()?;
		let operator_nonce = r.array32()?;
		let exit_delay = r.relative_time()?;
		let asset = r.asset()?;
		let value = r.u64()?;
		let unlock_hash = r.array32()?;
		let entry_reserve = r.u64()?;
		let chain = r.chain()?;
		let operator = r.key()?;
		let token = r.asset()?;
		let notice = r.relative_time()?;
		let flags = r.u8()?;
		if flags & !1 != 0 {
			return Err(DecodeError::Flag(flags).into());
		}
		let steps = r.u8()? as usize;
		if steps == 0 || steps > MAX_STEPS {
			return Err(DecodeError::Count(steps as u64).into());
		}
		let mut expiries = Vec::with_capacity(steps);
		for _ in 0..steps {
			expiries.push(r.median_time()?);
		}
		let schedule = ClockSchedule::new_unchecked(token, operator, notice, expiries).map_err(RecordError::Schedule)?;
		let levels = r.u8()? as usize;
		if levels == 0 || levels > MAX_LEVELS {
			return Err(RecordError::Levels(levels));
		}
		let mut upper = Vec::with_capacity(levels - 1);
		let read_level = |r: &mut Reader, level: usize| -> Result<(u8, u64, Vec<Sibling>), RecordError> {
			let count = r.u8()? as usize;
			if count == 0 || count > MAX_CHILDREN {
				return Err(RecordError::Children { level, count });
			}
			let index = r.u8()?;
			if index as usize >= count {
				return Err(RecordError::Index { level, index: index as usize, count });
			}
			let reserve = r.u64()?;
			let mut siblings = Vec::with_capacity(count - 1);
			for _ in 1..count {
				siblings.push(Sibling { value: r.u64()?, program: r.array32()? });
			}
			Ok((index, reserve, siblings))
		};
		for level in 0..levels - 1 {
			let (index, reserve, siblings) = read_level(&mut r, level)?;
			let member_index = r.u32()?;
			let depth = r.u8()? as usize;
			if depth == 0 || depth > MAX_DEPTH {
				return Err(RecordError::MemberDepth { level, depth });
			}
			let mut path = Vec::with_capacity(depth);
			for _ in 0..depth {
				path.push(r.array32()?);
			}
			upper.push(UpperLevel { index, reserve, siblings, member: MemberProof { index: member_index, siblings: path } });
		}
		let (index, reserve, siblings) = read_level(&mut r, levels - 1)?;
		let mut owners = Vec::with_capacity(siblings.len());
		for _ in 0..siblings.len() {
			owners.push(r.key()?);
		}
		if r.remaining() != 0 {
			return Err(DecodeError::TrailingBytes(r.remaining()).into());
		}
		let record = LeafRecord {
			template, owner, owner_nonce, operator_nonce, exit_delay, asset, value, unlock_hash, entry_reserve, chain,
			schedule, burn: flags & 1 != 0, upper, lowest: LowestLevel { index, reserve, siblings, owners },
		};
		record.check()?;
		Ok(record)
	}
}

/// What [`LeafRecord::validate`] returns for a leaf it accepts.
#[derive(Debug, Clone)]
pub struct ValidLeaf {
	pub leaf_id: LeafId,
	/// The index of the batch output in the round.
	pub batch_vout: u32,
	pub branch: Branch,
}

/// A lowest node's RECLAIM: its owners, the release they sign, and the script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reclaim {
	pub owners: Vec<XOnlyPublicKey>,
	pub release: CsfsMessage,
	pub script: Script,
}

/// A node on a leaf's path, rebuilt from the record.
#[derive(Debug, Clone)]
pub struct BranchNode {
	/// Its children, at outputs `0..r-1` of its unroll.
	pub children: Vec<Child>,
	/// The child on the leaf's path.
	pub index: usize,
	pub reserve: u64,
	/// Its value: its children's and its reserve.
	pub value: u64,
	pub operator: XOnlyPublicKey,
	pub gate: GateCommitment,
	/// The owner's proof in its member tree.
	pub proof: MemberProof,
	pub sweep: Sweep,
	/// RECLAIM, on the lowest node.
	pub reclaim: Option<Reclaim>,
	unroll: Script,
	taproot: TapOutput,
}

impl BranchNode {
	#[allow(clippy::too_many_arguments)]
	fn new(
		children: Vec<Child>,
		index: usize,
		reserve: u64,
		operator: XOnlyPublicKey,
		gate: GateCommitment,
		proof: MemberProof,
		sweep: Sweep,
		reclaim: Option<Reclaim>,
	) -> Result<BranchNode, RecordError> {
		let value = children.iter().try_fold(reserve, |acc, c| sum(acc, c.value))?;
		let unroll = unroll_script(&gate, &children);
		let taproot = node_taproot(unroll.clone(), sweep.script(), reclaim.as_ref().map(|r| r.script.clone()));
		Ok(BranchNode { children, index, reserve, value, operator, gate, proof, sweep, reclaim, unroll, taproot })
	}

	/// `H`, the hash of the children's records.
	pub fn children_hash(&self) -> [u8; 32] {
		children_hash(&self.children)
	}

	pub fn unroll_script(&self) -> &Script {
		&self.unroll
	}

	pub fn sweep_script(&self) -> Script {
		self.sweep.script()
	}

	pub fn taproot(&self) -> &TapOutput {
		&self.taproot
	}

	pub fn program(&self) -> [u8; 32] {
		self.taproot.program()
	}

	/// The node's output.
	pub fn output(&self) -> ExplicitOutput {
		ExplicitOutput::new(self.children[0].asset, self.value, self.taproot.script_pubkey())
	}

	/// The authorisation a member signs to let its holder unroll this node
	/// from median time `t`.
	pub fn unroll_authorisation(&self, t: MedianTime) -> CsfsMessage {
		unroll_authorisation(&self.children_hash(), t)
	}

	/// The full UNROLL witness for the owner's authorisation `sig` at `t`.
	pub fn unroll_witness(&self, sig: &Signature, t: MedianTime, owner: &XOnlyPublicKey) -> Vec<Vec<u8>> {
		self.member_unroll_witness(sig, t, owner, &self.proof)
	}

	/// The full UNROLL witness for the authorisation `sig` at `t` of another
	/// member, `key`, whose proof is `proof`.
	pub fn member_unroll_witness(&self, sig: &Signature, t: MedianTime, key: &XOnlyPublicKey, proof: &MemberProof) -> Vec<Vec<u8>> {
		let mut below = vec![sig.as_ref().to_vec(), t.script_bytes()];
		below.extend(proof.witness_items(key));
		self.taproot.witness(&self.unroll, below)
	}
}

/// Every output on a leaf's path, rebuilt from its record.
#[derive(Debug, Clone)]
pub struct Branch {
	pub leaf: LeafPolicy,
	pub entry: EntryPolicy,
	/// The entry's value: the leaf's value and the entry's reserve.
	pub entry_value: u64,
	entry_tap: TapOutput,
	/// The nodes from the batch output down to the lowest node.
	pub nodes: Vec<BranchNode>,
}

impl Branch {
	/// The batch output.
	pub fn batch_output(&self) -> ExplicitOutput {
		self.nodes[0].output()
	}

	/// The index on the path at each level, from the batch output down.
	pub fn position(&self) -> Vec<u8> {
		self.nodes.iter().map(|n| n.index as u8).collect()
	}

	pub fn leaf_id(&self) -> LeafId {
		LeafId::compute(&self.nodes[0].program(), &self.position(), &self.leaf.program())
	}

	/// The entry's output.
	pub fn entry_output(&self) -> ExplicitOutput {
		ExplicitOutput::new(self.entry.asset, self.entry_value, self.entry_tap.script_pubkey())
	}

	/// The leaf's output.
	pub fn leaf_output(&self) -> ExplicitOutput {
		ExplicitOutput::new(self.entry.asset, self.entry.value, self.leaf.script_pubkey())
	}

	/// The sweep path of every output above the leaf: each node's, then the
	/// entry's.
	pub fn sweeps(&self) -> Vec<Sweep> {
		self.nodes.iter().map(|n| n.sweep).chain([self.entry.sweep]).collect()
	}
}
