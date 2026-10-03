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
//! [`crate::leaf::leaf_salt`]).
//!
//! # One key, one leaf
//!
//! A leaf's owner key signs for that leaf only. Every leaf instance, every
//! receive included, has its own key, and the owner nonce is random, picked
//! by the wallet for that leaf alone (never derived from a counter, which a
//! restore would repeat). Where one key held two leaves, the operator could
//! take one: a salt the owner had signed under, built into a new leaf, let
//! an old forfeit pair spend it; one release filled two slots of a RECLAIM;
//! two forfeits over one output merged. So the tree builder refuses a key on
//! two leaves of a batch, a record whose lowest level names its own key in
//! another slot is refused, and [`LeafRecord::validate`] takes the key and
//! the nonce the wallet expects for the leaf and refuses a record not built
//! from them.
//!
//! # What a wallet accepts
//!
//! [`LeafRecord::validate`] is the check a wallet runs before it accepts a
//! leaf. Beyond the path and the five client checks it applies the wallet's
//! own policy ([`WalletPolicy`]): its chain, the operator key it was told,
//! the shortest notice `W` it accepts, how far after now the first expiry
//! must lie, the bounds on the exit delay, the deepest path it accepts, no
//! node of one child outside a batch of one leaf, and a floor on every
//! reserve of the path. The first expiry must lie a batch lifetime ahead
//! when a leaf is accepted from a round, and only past the exit deadline for
//! a leaf the wallet holds or receives ([`WalletPolicy::receipt`]). What it
//! accepted names the round it was checked against
//! ([`ValidLeaf::round_txid`]): after a rollback the wallet checks the leaf
//! again against whatever transaction now pays its batch output
//! ([`LeafRecord::recheck`]), which is the same round returned or a new one.
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
use elements::{AssetId, Script, Transaction, TxOut, Txid};

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
use crate::tree::fee_rate_reserve;
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
	/// `board-1`, a board: the owner's coins on-chain, which a cooperative
	/// spend takes as they are and the owner alone takes only by converting
	/// them into a `vtxo-1` leaf ([`crate::board::BoardPolicy`]). A board
	/// record names it; a leaf record never does.
	Board1,
}

impl Template {
	/// The template id of `vtxo`.
	pub const VTXO: u8 = 1;
	/// The template id of `board`.
	pub const BOARD: u8 = 2;

	/// Its id in the binary form.
	pub fn id(self) -> u8 {
		match self {
			Template::Vtxo1 => Template::VTXO,
			Template::Board1 => Template::BOARD,
		}
	}

	/// Its version.
	pub fn version(self) -> u8 {
		match self {
			Template::Vtxo1 | Template::Board1 => 1,
		}
	}

	/// Its name, without the version.
	pub fn name(self) -> &'static str {
		match self {
			Template::Vtxo1 => "vtxo",
			Template::Board1 => "board",
		}
	}

	/// The template with this id and version.
	pub fn from_id(id: u8, version: u8) -> Result<Template, RecordError> {
		match (id, version) {
			(Template::VTXO, 1) => Ok(Template::Vtxo1),
			(Template::BOARD, 1) => Ok(Template::Board1),
			(Template::VTXO, v) => Err(RecordError::TemplateVersion { template: "vtxo".into(), version: v as u64 }),
			(Template::BOARD, v) => Err(RecordError::TemplateVersion { template: "board".into(), version: v as u64 }),
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
		let known = match name {
			"vtxo" => Template::Vtxo1,
			"board" => Template::Board1,
			_ => return Err(RecordError::Template(s.into())),
		};
		match version.parse::<u64>() {
			Ok(1) => Ok(known),
			Ok(v) => Err(RecordError::TemplateVersion { template: name.into(), version: v }),
			Err(_) => Err(RecordError::TemplateVersion { template: name.into(), version: u64::MAX }),
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
	#[error("the lowest level names the record's own key in another slot: one key would hold two leaves")]
	OwnKeyTwice,
	#[error("the record is for another chain than the wallet's")]
	WrongChain,
	#[error("the record names another operator key than the one the wallet was told")]
	WrongOperator,
	#[error("a notice of {notice} units; the wallet accepts {min} at least")]
	NoticeTooShort { notice: u16, min: u16 },
	#[error("the first expiry {expiry} is earlier than {earliest}, the wallet's horizon after now")]
	ExpiryTooSoon { expiry: u32, earliest: u64 },
	#[error("an exit delay of {delay} units; the wallet accepts {min} to {max}")]
	ExitDelay { delay: u16, min: u16, max: u16 },
	#[error("a path of {levels} levels; the wallet accepts {max} at most")]
	TooManyLevels { levels: usize, max: usize },
	#[error("level {level} is a node of one child; only a batch of one leaf has one")]
	OneChild { level: usize },
	#[error("level {level} holds a reserve of {reserve}; the wallet requires {min} at least")]
	NodeReserve { level: usize, reserve: u64, min: u64 },
	#[error("the entry holds a reserve of {reserve}; the wallet requires {min} at least")]
	EntryReserve { reserve: u64, min: u64 },
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
	#[error("the board transaction pays no output equal to the leaf the record rebuilds")]
	BoardOutputMissing,
	#[error("the board transaction pays the leaf the record rebuilds {0} times")]
	BoardOutputRepeated(usize),
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
			NotOwner | OwnerNonce | OwnKeyTwice => "owner",
			WrongChain | WrongOperator | NoticeTooShort { .. } | ExpiryTooSoon { .. } | ExitDelay { .. }
			| TooManyLevels { .. } | OneChild { .. } | NodeReserve { .. } | EntryReserve { .. } => "policy",
			Json(_) => "json",
			Field(_) => "field",
			Type(_) => "type",
			Hex(_) => "hex",
			Key(_) => "key",
			BatchOutputMissing | BatchOutputRepeated(_) | BatchOutputMismatch => "batch_output",
			BoardOutputMissing | BoardOutputRepeated(_) => "board_output",
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

	/// The check that the record is for the wallet's key and for the nonce it
	/// picked for this leaf, so the salt holds its contribution. A wallet that
	/// never repeats a nonce is then never given a leaf script it already
	/// holds. [`LeafRecord::validate`] runs it.
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
		if self.template != Template::Vtxo1 {
			return Err(RecordError::Template(self.template.to_string()));
		}
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
		if l.owners.contains(&self.owner) {
			return Err(RecordError::OwnKeyTwice);
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

	/// The check a wallet runs before it accepts a leaf of its own: the record
	/// is for `owner` and the `owner_nonce` the wallet picked for this leaf
	/// ([`LeafRecord::check_owner`]), within the wallet's `policy`, and it
	/// matches the round transaction that created its batch. The round pays
	/// exactly one output equal to the batch output the record rebuilds
	/// (asset, value and script), so the leaf is where the record says, and
	/// the round passes the five client checks on the token and its clock
	/// ([`check_round`]) for the record's schedule and every sweep path above
	/// the leaf.
	///
	/// Whether the round is final (its block certified and its anchor buried)
	/// is for the caller to establish.
	pub fn validate(&self, round: &Transaction, policy: &WalletPolicy, owner: &XOnlyPublicKey, owner_nonce: &[u8; 32])
		-> Result<ValidLeaf, RecordError>
	{
		self.check_owner(owner, owner_nonce)?;
		self.validate_round(round, policy)
	}

	/// [`LeafRecord::validate`] without the owner's key and nonce: for a leaf
	/// the wallet does not own, such as the start of a coin it receives,
	/// whose owner's nonce it cannot know. A wallet never accepts a leaf of its
	/// own with this alone.
	pub fn validate_round(&self, round: &Transaction, policy: &WalletPolicy) -> Result<ValidLeaf, RecordError> {
		policy.check(self)?;
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
		let sweeps = branch.sweeps();
		check_round(round, &self.schedule, &sweeps[0], &sweeps[1..])?;
		Ok(ValidLeaf { leaf_id: branch.leaf_id(), round_txid: round.txid(), batch_vout, branch })
	}

	/// The wallet's look at a leaf it holds, after a rollback or at any time:
	/// `round` is the transaction the chain now has paying the leaf's batch
	/// output, and `held` what the wallet accepted. The record is checked
	/// against `round` under `policy.receipt()`, so the first expiry need only
	/// lie past the exit deadline.
	///
	/// An operator re-broadcasts a disconnected round unchanged, so the same
	/// transaction returns ([`Recheck::Same`]) and every forfeit signed for it
	/// can still be claimed. Another transaction paying the same batch output
	/// is a new round ([`Recheck::NewRound`]): the forfeits signed for the old
	/// one name a connector asset that can never be issued, so every leaf
	/// given up for it is still its owner's, and nothing the wallet signed for
	/// the old round carries over. An error means the leaf is not where the
	/// record says, or no longer meets the policy; whether to unroll depends on
	/// whether the batch output is on-chain at all.
	pub fn recheck(&self, held: &ValidLeaf, round: &Transaction, policy: &WalletPolicy) -> Result<Recheck, RecordError> {
		let valid = self.validate_round(round, &policy.receipt())?;
		Ok(if valid.round_txid == held.round_txid { Recheck::Same(valid) } else { Recheck::NewRound(valid) })
	}

	/// Checks the path alone against one output: it must be the batch output
	/// the record rebuilds. This does not check the token or the clock, which
	/// only the round transaction shows, nor the wallet's policy; a wallet
	/// accepts a leaf only after [`LeafRecord::validate`].
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
	/// The round the leaf was checked against. Another transaction can pay
	/// the same batch output after a rollback (it may spend the same issuing
	/// coin); the wallet keeps this id and checks again when it changes.
	pub round_txid: Txid,
	/// The index of the batch output in the round.
	pub batch_vout: u32,
	pub branch: Branch,
}

/// What [`LeafRecord::recheck`] finds.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Recheck {
	/// The round the leaf was accepted from pays its batch output.
	Same(ValidLeaf),
	/// Another transaction pays it: a new round.
	NewRound(ValidLeaf),
}

/// What a wallet accepts in a leaf's record, beyond its being well formed and
/// matching the chain: [`LeafRecord::validate`] refuses anything outside it.
///
/// Two moments use it. Accepting a leaf from a round ([`WalletPolicy::new`])
/// asks that the first expiry lie a whole batch lifetime ahead, less the time
/// for the round to become final. Every later look at a leaf the wallet
/// holds, and the receipt of a coin out of round, asks only that the first
/// expiry lie past the exit deadline ([`WalletPolicy::receipt`]): a leaf
/// accepted from a round passes it for most of its batch's life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletPolicy {
	/// The wallet's own chain.
	pub chain: Chain,
	/// The operator key the wallet was told (from the server's `info`, or its
	/// configuration).
	pub operator: XOnlyPublicKey,
	/// The median time the wallet takes as now.
	pub now: MedianTime,
	/// The shortest notice `W` the wallet accepts.
	pub min_notice: RelativeTime,
	/// How long after `now` the first expiry `E_0` must lie, in seconds.
	pub horizon: u32,
	/// The bounds on the exit delay.
	pub min_exit_delay: RelativeTime,
	pub max_exit_delay: RelativeTime,
	/// The most levels a leaf's path may have: the depth of the largest batch
	/// the operator advertises. Every level adds a node transaction to the
	/// leaf's exit.
	pub max_levels: usize,
	/// The least each node on the path and the entry hold back for the fee of
	/// the transaction that spends them.
	pub min_reserve: ReserveFloor,
}

/// The least a reserve on a leaf's path holds, in the batch asset's atoms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReserveFloor {
	/// Every node and the entry hold at least this many atoms. `Atoms(0)`
	/// accepts any reserve.
	Atoms(u64),
	/// The specification's rule at the wallet's own floor, in the batch
	/// asset's atoms per 1,000 vbytes: every node and the entry hold at least
	/// what [`crate::ReserveRule::FeeRate`] gives them at that floor and
	/// multiple. A wallet that sets the floor above the operator's refuses the
	/// operator's honest batches.
	FeeRate { floor_per_kvb: u64, multiple: u64 },
}

impl WalletPolicy {
	/// The specification's notice and exit delay, 36 hours.
	pub const SPEC_DELAY_SECONDS: u64 = 36 * 3600;
	/// The default horizon: a round's batch expires 28 days after it is
	/// created; one day of that is left for the round to become final and for
	/// the participation to complete.
	pub const DEFAULT_HORIZON: u32 = 27 * 86_400;
	/// The exit deadline, three days before the first expiry: a wallet still
	/// holding a leaf then starts its exit, so the unroll, the exit delay and a
	/// margin for an anchor rollback fit before the batch can be swept.
	pub const EXIT_DEADLINE: u32 = 3 * 86_400;
	/// The longest exit delay accepted by default, 48 hours: the exit
	/// deadline lies three days before the expiry, and the unroll and the exit
	/// delay must fit in it.
	pub const DEFAULT_MAX_EXIT_SECONDS: u64 = 48 * 3600;
	/// The default depth: the specification's largest batch, 1,024 leaves at
	/// radix 4.
	pub const DEFAULT_MAX_LEVELS: usize = 5;

	/// The policy for a wallet on `chain` served by `operator`, at `now`,
	/// accepting a leaf from a round, with the specification's parameters: a
	/// notice of at least 36 hours, a first expiry at least 27 days after now,
	/// an exit delay of 36 to 48 hours, at most five levels, and a reserve of
	/// at least one atom on every node and on the entry.
	pub fn new(chain: Chain, operator: XOnlyPublicKey, now: MedianTime) -> WalletPolicy {
		let delay = RelativeTime::from_seconds_ceil(Self::SPEC_DELAY_SECONDS).expect("36 hours is a relative time");
		WalletPolicy {
			chain, operator, now,
			min_notice: delay,
			horizon: Self::DEFAULT_HORIZON,
			min_exit_delay: delay,
			max_exit_delay: RelativeTime::from_seconds_ceil(Self::DEFAULT_MAX_EXIT_SECONDS).expect("48 hours is a relative time"),
			max_levels: Self::DEFAULT_MAX_LEVELS,
			min_reserve: ReserveFloor::Atoms(1),
		}
	}

	/// The same policy for a leaf or a coin the wallet already holds or
	/// receives out of round, and for every re-check after a rollback: the
	/// first expiry need only lie past the exit deadline, three days after
	/// now ([`WalletPolicy::EXIT_DEADLINE`]). The acceptance horizon would
	/// refuse an honest leaf from the second day of its batch.
	pub fn receipt(self) -> WalletPolicy {
		WalletPolicy { horizon: Self::EXIT_DEADLINE, ..self }
	}

	/// Whether `delay` is within the policy's bounds on the exit delay.
	pub fn exit_delay_ok(&self, delay: RelativeTime) -> bool {
		(self.min_exit_delay.units()..=self.max_exit_delay.units()).contains(&delay.units())
	}

	fn exit_delay_error(&self, delay: RelativeTime) -> RecordError {
		RecordError::ExitDelay { delay: delay.units(), min: self.min_exit_delay.units(), max: self.max_exit_delay.units() }
	}

	/// Refuses a record outside the policy: its chain, operator, notice, first
	/// expiry and exit delay; a path deeper than `max_levels`; a node of one
	/// child anywhere but in a batch of one leaf; and a reserve below
	/// `min_reserve` on any node of the path or on the entry.
	pub fn check(&self, record: &LeafRecord) -> Result<(), RecordError> {
		if record.chain != self.chain {
			return Err(RecordError::WrongChain);
		}
		if record.schedule.operator != self.operator {
			return Err(RecordError::WrongOperator);
		}
		let notice = record.schedule.notice.units();
		if notice < self.min_notice.units() {
			return Err(RecordError::NoticeTooShort { notice, min: self.min_notice.units() });
		}
		let expiry = record.schedule.expiries()[0].to_consensus_u32();
		let earliest = self.now.to_consensus_u32() as u64 + self.horizon as u64;
		if (expiry as u64) < earliest {
			return Err(RecordError::ExpiryTooSoon { expiry, earliest });
		}
		if !self.exit_delay_ok(record.exit_delay) {
			return Err(self.exit_delay_error(record.exit_delay));
		}
		let levels = record.levels();
		if levels > self.max_levels {
			return Err(RecordError::TooManyLevels { levels, max: self.max_levels });
		}
		// The builder gives every node 2 to r children; only a batch of one
		// leaf is a single node of one child.
		let children = record.upper.iter().map(|u| u.siblings.len() + 1)
			.chain([record.lowest.siblings.len() + 1]);
		if levels > 1 {
			if let Some(level) = children.clone().position(|n| n == 1) {
				return Err(RecordError::OneChild { level });
			}
		}
		let reserves: Vec<u64> = record.upper.iter().map(|u| u.reserve).chain([record.lowest.reserve]).collect();
		match self.min_reserve {
			ReserveFloor::Atoms(min) => {
				if let Some(level) = reserves.iter().position(|r| *r < min) {
					return Err(RecordError::NodeReserve { level, reserve: reserves[level], min });
				}
				if record.entry_reserve < min {
					return Err(RecordError::EntryReserve { reserve: record.entry_reserve, min });
				}
			},
			ReserveFloor::FeeRate { floor_per_kvb, multiple } => {
				let branch = record.branch()?;
				for (level, node) in branch.nodes.iter().enumerate() {
					let min = node.fee_rate_reserve(floor_per_kvb, multiple);
					if node.reserve < min {
						return Err(RecordError::NodeReserve { level, reserve: node.reserve, min });
					}
				}
				let min = branch.entry_fee_rate_reserve(floor_per_kvb, multiple);
				if record.entry_reserve < min {
					return Err(RecordError::EntryReserve { reserve: record.entry_reserve, min });
				}
			},
		}
		Ok(())
	}
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

	/// What [`crate::ReserveRule::FeeRate`] reserves on this node: `multiple`
	/// times `floor_per_kvb` for its unroll with the reserve as the fee, the
	/// witness at its full length, as the tree builder sizes it.
	pub fn fee_rate_reserve(&self, floor_per_kvb: u64, multiple: u64) -> u64 {
		let widest = MemberProof { index: 0, siblings: vec![[0; 32]; self.gate.depth] };
		let mut below = vec![vec![0; 64], vec![0; 5]];
		below.extend(widest.witness_items(&self.operator));
		let w = self.taproot.witness(&self.unroll, below);
		let outputs = self.children.iter().map(|c| c.output().txout()).collect();
		fee_rate_reserve(floor_per_kvb, multiple, w, outputs, self.children[0].asset)
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

	/// What [`crate::ReserveRule::FeeRate`] reserves on the entry: `multiple`
	/// times `floor_per_kvb` for its unlock into the leaf with the reserve as
	/// the fee.
	pub fn entry_fee_rate_reserve(&self, floor_per_kvb: u64, multiple: u64) -> u64 {
		let w = self.entry_tap.witness(&self.entry.unlock_script(), vec![vec![0; 32]]);
		fee_rate_reserve(floor_per_kvb, multiple, w, vec![self.leaf_output().txout()], self.entry.asset)
	}

	/// The sweep path of every output above the leaf: each node's, then the
	/// entry's.
	pub fn sweeps(&self) -> Vec<Sweep> {
		self.nodes.iter().map(|n| n.sweep).chain([self.entry.sweep]).collect()
	}
}
