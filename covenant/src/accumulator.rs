//! The accumulator batch: a batch output of up to 1,024 leaves from which one
//! owner leaves in one transaction (`arca/accumulator-1`, and
//! `arca/accumulator-2` for a batch without a sweep).
//!
//! A tree takes a leaf on-chain through one node transaction per level. An
//! accumulator batch holds its leaves as a fixed Merkle-sum root of leaf
//! records and a bitmap of the leaves that have left, so one owner's exit is
//! one transaction, the same size at every slot and however many leaves the
//! batch holds, and it changes nothing any other owner holds:
//!
//! ```text
//! batch = P2TR(NUMS, TapBranch( TapBranch(X, D), SWEEP ))
//!   X      arca/accumulator-1, Simplicity (0xbe), from sequentia-contracts
//!   D      H_TapData(ROOT ‖ OPERATOR ‖ BITMAP), hidden
//!   SWEEP  the batch output's sweep: the token at R, the operator's signature
//!
//! rec_j = SHA256(0x00 ‖ j ‖ OWNER ‖ SPK ‖ VALUE ‖ RESERVE)   weight VALUE + RESERVE
//! node  = SHA256(0x01 ‖ h_l ‖ w_l ‖ h_r ‖ w_r)               weight w_l + w_r
//! ```
//!
//! A slot's record names the leaf's owner key, the SHA256 of its hash-locked
//! entry's scriptPubKey, the entry's value and the reserve its exit leaves
//! for the fee ([`Slot`]). The directions of a slot's path are the bits of its
//! index, so a record sits only at its own slot; the tree has depth 10, and an
//! empty slot is 32 zero bytes of weight 0. The bitmap is 16 big-endian
//! 64-bit words; slot `j`'s bit is bit `63 − j mod 64` of word `j / 64`.
//!
//! An exit of slot `j`, the batch output at input `k`, needs the slot's record
//! on its path to `ROOT` with every weight on it the sum of its children, its
//! bit clear, the signature of the owner (or of the operator) over
//! `SHA256(SHA256("Arca/accumulator-exit") ‖ genesis ‖ ROOT ‖ rec_j ‖ t)` with
//! the transaction's lock time a time at or after `t`, the entry at output
//! `2k` and the rest at `2k+1` under the same state with the bit set
//! ([`AccumulatorPolicy::exit_tx`]). The authorisation names no outpoint and
//! no bitmap, so it holds for every state of the batch and a watcher or a
//! receiver can hold it, good from `t`. The entry is the one a tree's lowest
//! node pays, so everything from there on (the unlock with the preimage, the
//! leaf, its exit delay, every signature made for it) is the tree's.
//!
//! The batch output's sweep is a tree's: no notice of its own, the token's
//! wait at `R` after the release being the notice; every entry carries the
//! notice from its own confirmation.
//!
//! # A batch without a sweep: `arca/accumulator-2`
//!
//! A batch built with [`ClockSchedule::never`] has no sweep. Its output is
//! `P2TR(NUMS, TapBranch(X2, D))`, `X2` the program `arca/accumulator-2`, the
//! same state, records and tree, and two actions:
//!
//! - EXIT, as above, the same authorisation;
//! - RELEASE of the slots `j_1 < … < j_n`, `n` from 1 to [`RELEASE_PLACES`]:
//!   each slot's record on its path to `ROOT`, its bit clear, and its owner's
//!   signature over
//!   `SHA256(SHA256("Arca/accumulator-release") ‖ genesis ‖ ROOT ‖ rec_j ‖ M)`
//!   ([`release_digest`]), `M` the explicit asset of the input the slot names:
//!   the connector asset of the round that made the owner's new coin, so a
//!   release is void with that round; and the operator's signature over
//!   `SHA256(SHA256("Arca/accumulator-release-outputs") ‖ genesis ‖ D ‖ k ‖
//!   outputs_hash)` ([`payout_digest`]). The rest is at `2k+1` under the same
//!   state with the bits set, holding the input less every released weight;
//!   output `2k` and what the slots held are the operator's
//!   ([`AccumulatorPolicy::release_tx`]).
//!
//! A release names no outpoint and no bitmap, so releases signed at different
//! times ride one transaction; it names one slot of one batch for one round on
//! one chain, and a slot's bit, once set, refuses it again. Nothing else
//! spends the batch: a slot whose owner neither exits nor releases it stays
//! until its owner, or the operator by EXIT to the owner's entry, takes it
//! out.
//!
//! # The record's binary form, versions 1 and 4
//!
//! [`AccumulatorRecord`] is a leaf record whose path is a slot. Integers are
//! little-endian; asset ids, the token and the genesis hash are in internal
//! byte order. Up to the clock it is a tree leaf record's layout
//! ([`crate::record`]). Version 1 is a batch with a sweep
//! (`arca/accumulator-1`):
//!
//! ```text
//! u8    format version, 1
//! u8    template, u8 template version          as a leaf record's
//! [32]  owner key, [32] owner nonce, [32] operator nonce, u16 exit delay
//!       the template's terms (htlc-1, order-2, landing-1) as a leaf record's
//! [32]  asset, u64 value, [32] unlock hash, u64 entry reserve
//! [32]  genesis hash, [32] operator key S, [32] token T, u16 notice W
//! u8    flags: bit 0, the sweeps are burn-only
//! u8    expiry count, 1 to 64, then each expiry as u32
//! u16   slot, below 1,024
//! u64   the reserve of the slot's exit
//! 10 ×  ([32] sibling, u64 its weight), from the slot up
//! ```
//!
//! Version 4 is a batch without a sweep (`arca/accumulator-2`): no token,
//! notice, burn or expiry, so after the operator key
//!
//! ```text
//! u8    flags, zero
//! u16   slot, below 1,024
//! u64   the reserve of the slot's exit
//! 10 ×  ([32] sibling, u64 its weight), from the slot up
//! ```
//!
//! Every field has one encoding, so a record has one binary form: the
//! no-sweep token is written as version 4 alone. A leaf record's versions
//! are 2 and 3, so the first byte tells the two kinds of record apart. A reader refuses another
//! version, an unknown template, trailing bytes and a record
//! [`AccumulatorRecord::check`] refuses.

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, LockTime, OutPoint, Script, Sequence, Transaction, TxOut, Txid};

use crate::accumulator_programs as programs;
use crate::checks::{check_reissue, check_round};
use crate::clock::{ClockSchedule, MAX_STEPS};
use crate::encode::{DecodeError, Encoding, Reader};
use crate::entry::EntryPolicy;
use crate::forfeit::{connector_asset, ConnectorPolicy, Forfeit};
use crate::offboard::OffboardPolicy;
use crate::htlc::HtlcTerms;
use crate::landing::Landing;
use crate::leaf::{leaf_salt, LeafPolicy};
use crate::message::Chain;
use crate::order::{control_block, tapbranch, tapdata, tapleaf, OrderLeafTerms};
use crate::record::{check_template, leaf_policy, LeafId, RecordError, ReserveFloor, Template, ValidLeaf, WalletPolicy, MAX_VALUE, ORDER_TERMS_BYTES};
use crate::script::{asset_bytes, sha256, ExplicitOutput};
use crate::sign::verify_digest;
use crate::spend::{assemble, FeeSource, SpendError, UnrollTx, FEE_COIN_SEQUENCE, FINAL};
use crate::sweep::{Sweep, Sweepable};
use crate::taptree::{TapNode, TapOutput};
use crate::time::{MedianTime, RelativeTime};
use crate::tree::{build_leaves, fee_rate_reserve, LeafSpec, ReserveRule, TreeError, TreeLeaf, TreeParams, MIN_RADIX};

/// The depth of the Merkle-sum tree: the program folds exactly ten levels.
pub const DEPTH: usize = 10;
/// The slots of a batch, 1,024.
pub const SLOTS: usize = 1 << DEPTH;
/// The bytes of the state in the data leaf: root, operator, bitmap.
pub const STATE_BYTES: usize = 32 + 32 + 128;
/// The bytes of an exit's witness value.
pub const WITNESS_BYTES: usize = STATE_BYTES + 2 + 32 + 32 + 8 + 8 + DEPTH * 40 + 4 + 1 + 64;
/// The tag an exit authorisation's constant is the SHA256 of.
pub const EXIT_TAG: &[u8] = b"Arca/accumulator-exit";
/// The tag an owner's release's constant is the SHA256 of.
pub const RELEASE_TAG: &[u8] = b"Arca/accumulator-release";
/// The tag the operator's signature over a release's outputs starts from.
pub const PAYOUT_TAG: &[u8] = b"Arca/accumulator-release-outputs";
/// The most slots one release takes: the most whose cost the witness pays for
/// with no annex.
pub const RELEASE_PLACES: usize = programs::RELEASE_PLACES;
/// The bytes one released slot adds to a release's witness: its record's
/// fields, path, the index of its connector's input and its signature.
pub const RELEASED_SLOT_BYTES: usize = 2 + 32 + 32 + 8 + 8 + DEPTH * 40 + 4 + 64;

const SIMPLICITY: u8 = 0xbe;
const TAPSCRIPT: u8 = 0xc4;

fn unhex(s: &str) -> Vec<u8> {
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("a hex constant")).collect()
}

/// `arca/accumulator-1`'s commitment root.
pub fn accumulator_cmr() -> [u8; 32] {
	unhex(programs::ACCUMULATOR_CMR).try_into().expect("a 32-byte constant")
}

/// `arca/accumulator-2`'s commitment root.
pub fn accumulator2_cmr() -> [u8; 32] {
	unhex(programs::ACCUMULATOR2_CMR).try_into().expect("a 32-byte constant")
}

/// A hash and its weight: a record, a node or a sibling on a path.
pub type Weighted = ([u8; 32], u64);

/// Why an accumulator batch, a record of one or an exit from one does not
/// hold.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccumulatorError {
	#[error(transparent)]
	Record(#[from] RecordError),
	#[error(transparent)]
	Spend(#[from] SpendError),
	#[error("slot {0} is past the batch's {max} slots", max = SLOTS)]
	Slot(u16),
	#[error("a path of {0} levels; an accumulator's has {depth}", depth = DEPTH)]
	PathLength(usize),
	#[error("the weights on the path overflow")]
	Weight,
	#[error("slot {0} has left the batch already")]
	Left(u16),
	#[error("the record of slot {0} is not on its path to the batch's root")]
	NotInRoot(u16),
	#[error("the exit's entry is not the output slot {0}'s record names")]
	Entry(u16),
	#[error("the batch holds {held}, less than slot {slot}'s weight of {weight}")]
	Short { slot: u16, held: u64, weight: u64 },
	#[error("the authorisation is not the {0}'s signature over this slot's exit")]
	Signature(&'static str),
	#[error("the reserve of the slot's exit is {reserve}, below {min}")]
	ExitReserve { reserve: u64, min: u64 },
	#[error("the spend breaks the program's rule: {0}")]
	Rule(String),
	#[error("a batch with a sweep (arca/accumulator-1) has no release")]
	NoRelease,
	#[error("a release of {0} slots; one takes 1 to {max}", max = RELEASE_PLACES)]
	Places(usize),
	#[error("the slots of a release go in increasing order, each once; slot {0} does not")]
	Order(u16),
	#[error("slot {0}'s release is not its owner's signature for its round's connector asset")]
	ReleaseSignature(u16),
	#[error("no input holds the connector asset slot {0}'s release names, explicitly")]
	Connector(u16),
	#[error("a release pays the operator at output 0; it names no output")]
	NoPayout,
	#[error("the operator's signature is not over this release's outputs")]
	PayoutSignature,
}

/// What a slot's record holds: the key that may take it out, the SHA256 of
/// the scriptPubKey its exit pays, that output's value, and what the exit
/// leaves for its fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Slot {
	pub owner: XOnlyPublicKey,
	pub script_hash: [u8; 32],
	pub value: u64,
	pub reserve: u64,
}

impl Slot {
	/// `rec_j = SHA256(0x00 ‖ j ‖ OWNER ‖ SPK ‖ VALUE ‖ RESERVE)`.
	pub fn record(&self, j: u16) -> [u8; 32] {
		let mut b = Vec::with_capacity(83);
		b.push(0x00);
		b.extend(j.to_be_bytes());
		b.extend(self.owner.serialize());
		b.extend(self.script_hash);
		b.extend(self.value.to_be_bytes());
		b.extend(self.reserve.to_be_bytes());
		sha256(&b)
	}

	/// `VALUE + RESERVE`, or `None` past 64 bits.
	pub fn weight(&self) -> Option<u64> {
		self.value.checked_add(self.reserve)
	}
}

/// An inner node over two weighted children.
pub fn inner(l: Weighted, r: Weighted) -> [u8; 32] {
	let mut b = Vec::with_capacity(81);
	b.push(0x01);
	b.extend(l.0);
	b.extend(l.1.to_be_bytes());
	b.extend(r.0);
	b.extend(r.1.to_be_bytes());
	sha256(&b)
}

/// The root and weight that `leaf` at slot `j` folds to along `path`, as the
/// program folds it: `None` for a slot past the batch, a path of another
/// length, or a weight past 64 bits.
pub fn fold(j: u16, leaf: Weighted, path: &[Weighted]) -> Option<Weighted> {
	if j as usize >= SLOTS || path.len() != DEPTH {
		return None;
	}
	let mut node = leaf;
	let mut at = j;
	for s in path {
		let w = node.1.checked_add(s.1)?;
		let h = if at & 1 == 1 { inner(*s, node) } else { inner(node, *s) };
		node = (h, w);
		at >>= 1;
	}
	Some(node)
}

/// The Merkle-sum tree over a batch's slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotTree {
	/// `levels[0]` the slots, `levels[DEPTH]` the root alone.
	levels: Vec<Vec<Weighted>>,
}

impl SlotTree {
	/// The tree over `slots` (each record and its weight) in slots `0..n`,
	/// every other slot empty. `None` for more than [`SLOTS`] or a weight past
	/// 64 bits.
	pub fn new(slots: &[Weighted]) -> Option<SlotTree> {
		if slots.len() > SLOTS {
			return None;
		}
		let mut first = slots.to_vec();
		first.resize(SLOTS, ([0; 32], 0));
		let mut levels = vec![first];
		for d in 0..DEPTH {
			let mut up = Vec::with_capacity(levels[d].len() / 2);
			for p in levels[d].chunks(2) {
				up.push((inner(p[0], p[1]), p[0].1.checked_add(p[1].1)?));
			}
			levels.push(up);
		}
		Some(SlotTree { levels })
	}

	/// The root and its weight.
	pub fn root(&self) -> Weighted {
		self.levels[DEPTH][0]
	}

	/// Slot `j`'s path: each level's sibling and its weight, from the slot up.
	pub fn path(&self, j: usize) -> Vec<Weighted> {
		(0..DEPTH).map(|d| self.levels[d][(j >> d) ^ 1]).collect()
	}
}

/// The bitmap of the slots that have left.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Bitmap(pub [u64; SLOTS / 64]);

impl Bitmap {
	fn bit(j: u16) -> (usize, u64) {
		(j as usize / 64, 1u64 << (63 - j as u32 % 64))
	}

	/// Whether slot `j` has left.
	pub fn is_left(&self, j: u16) -> bool {
		let (w, m) = Self::bit(j);
		j as usize >= SLOTS || self.0[w] & m != 0
	}

	/// The bitmap with slot `j`'s bit set.
	pub fn with(&self, j: u16) -> Bitmap {
		let (w, m) = Self::bit(j);
		let mut b = *self;
		b.0[w] |= m;
		b
	}

	/// How many slots have left.
	pub fn count(&self) -> u32 {
		self.0.iter().map(|w| w.count_ones()).sum()
	}

	/// The 128 bytes: each word big-endian.
	pub fn to_bytes(&self) -> Vec<u8> {
		self.0.iter().flat_map(|w| w.to_be_bytes()).collect()
	}

	pub fn from_bytes(b: &[u8]) -> Option<Bitmap> {
		if b.len() != SLOTS / 8 {
			return None;
		}
		let mut words = [0u64; SLOTS / 64];
		for (i, c) in b.chunks(8).enumerate() {
			words[i] = u64::from_be_bytes(c.try_into().expect("eight bytes"));
		}
		Some(Bitmap(words))
	}
}

/// `SHA256(SHA256("Arca/accumulator-exit") ‖ genesis ‖ ROOT ‖ rec_j ‖ t)`:
/// what the owner, or the operator, signs to take a slot out. Genesis in
/// internal byte order, `t` four bytes big-endian.
pub fn exit_digest(chain: &Chain, root: &[u8; 32], record: &[u8; 32], time: MedianTime) -> [u8; 32] {
	let mut b = Vec::with_capacity(132);
	b.extend(sha256(EXIT_TAG));
	b.extend(chain.genesis_bytes());
	b.extend(root);
	b.extend(record);
	b.extend(time.to_consensus_u32().to_be_bytes());
	sha256(&b)
}

/// One slot's exit, as its witness presents it: the slot, its record and its
/// path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
	pub slot: u16,
	pub record: Slot,
	pub path: Vec<Weighted>,
}

impl Exit {
	/// The root and weight the record folds to.
	pub fn root(&self) -> Option<Weighted> {
		fold(self.slot, (self.record.record(self.slot), self.record.weight()?), &self.path)
	}
}

/// An authorisation to take a slot out: the owner's signature, or the
/// operator's (`by_operator`), over [`exit_digest`] for `time`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitAuth {
	pub by_operator: bool,
	pub time: MedianTime,
	pub signature: Signature,
}

/// The state an accumulator batch output holds, and its sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccumulatorPolicy {
	pub root: [u8; 32],
	pub operator: XOnlyPublicKey,
	pub bitmap: Bitmap,
	/// The batch output's sweep, no notice of its own (`arca/accumulator-1`);
	/// `None` for a batch without one (`arca/accumulator-2`).
	pub sweep: Option<Sweep>,
}

impl AccumulatorPolicy {
	/// `ROOT ‖ OPERATOR ‖ BITMAP`, 192 bytes.
	pub fn data_bytes(&self) -> Vec<u8> {
		let mut b = Vec::with_capacity(STATE_BYTES);
		b.extend(self.root);
		b.extend(self.operator.serialize());
		b.extend(self.bitmap.to_bytes());
		b
	}

	/// The hidden data leaf `D`.
	pub fn data_leaf(&self) -> [u8; 32] {
		tapdata(&self.data_bytes())
	}

	/// Whether the batch has no sweep, so is spent by `arca/accumulator-2`.
	pub fn no_sweep(&self) -> bool {
		self.sweep.is_none()
	}

	/// The commitment root of the program the output carries.
	pub fn cmr(&self) -> [u8; 32] {
		if self.no_sweep() { accumulator2_cmr() } else { accumulator_cmr() }
	}

	/// The tapleaf hash of `SWEEP`, if the batch has one.
	pub fn sweep_leaf(&self) -> Option<[u8; 32]> {
		self.sweep.map(|s| tapleaf(TAPSCRIPT, s.script().as_bytes()))
	}

	/// The root of the script tree: `TapBranch(TapBranch(X, D), SWEEP)`, or
	/// `TapBranch(X2, D)` without a sweep.
	pub fn tree_root(&self) -> [u8; 32] {
		let program = tapbranch(tapleaf(SIMPLICITY, &self.cmr()), self.data_leaf());
		match self.sweep_leaf() {
			Some(sweep) => tapbranch(program, sweep),
			None => program,
		}
	}

	/// The output's taproot, through which `SWEEP` is spent.
	pub fn taproot(&self) -> TapOutput {
		match self.sweep {
			Some(sweep) => TapOutput::with_nodes(vec![
				(2, TapNode::Simplicity(accumulator_cmr())),
				(2, TapNode::Hidden(self.data_leaf())),
				(1, TapNode::Tapscript(sweep.script())),
			]),
			None => TapOutput::with_nodes(vec![
				(1, TapNode::Simplicity(accumulator2_cmr())),
				(1, TapNode::Hidden(self.data_leaf())),
			]),
		}
	}

	pub fn script_pubkey(&self) -> Script {
		self.taproot().script_pubkey()
	}

	/// The witness program: the tweaked output key.
	pub fn program(&self) -> [u8; 32] {
		self.taproot().program()
	}

	/// The control block of the program's leaf: its parity, the NUMS key,
	/// `D`, then the hash of `SWEEP` when there is one.
	pub fn control_block(&self) -> Vec<u8> {
		let mut path = vec![self.data_leaf()];
		path.extend(self.sweep_leaf());
		control_block(SIMPLICITY, self.tree_root(), &path)
	}

	/// The state once slot `j` has left.
	pub fn after(&self, j: u16) -> AccumulatorPolicy {
		AccumulatorPolicy { bitmap: self.bitmap.with(j), ..*self }
	}

	/// The state once every slot of `slots` has left.
	pub fn after_all(&self, slots: &[u16]) -> AccumulatorPolicy {
		slots.iter().fold(*self, |s, j| s.after(*j))
	}

	/// This output, held at `outpoint`, as a sweep takes it; `None` for a
	/// batch without a sweep.
	pub fn sweepable(&self, outpoint: OutPoint, (asset, value): (AssetId, u64)) -> Option<Sweepable> {
		self.sweep.map(|s| Sweepable::new(outpoint, (asset, value), self.taproot(), s))
	}

	/// The exit's witness: the state, the slot's record and path, the time,
	/// the key's flag and the signature, then the pruned program for an exit
	/// that leaves a rest or for the last (`last`), the commitment root and the
	/// control block.
	pub fn exit_witness(&self, exit: &Exit, auth: &ExitAuth, last: bool) -> Vec<Vec<u8>> {
		let mut bits: Vec<bool> = bits_of(&self.data_bytes());
		if self.no_sweep() {
			// ACTION is Left: an exit.
			bits.push(false);
		}
		let mut bytes = Vec::with_capacity(WITNESS_BYTES);
		bytes.extend(exit.slot.to_be_bytes());
		bytes.extend(exit.record.owner.serialize());
		bytes.extend(exit.record.script_hash);
		bytes.extend(exit.record.value.to_be_bytes());
		bytes.extend(exit.record.reserve.to_be_bytes());
		for (h, w) in &exit.path {
			bytes.extend(h);
			bytes.extend(w.to_be_bytes());
		}
		bytes.extend(auth.time.to_consensus_u32().to_be_bytes());
		bits.extend(bits_of(&bytes));
		bits.push(auth.by_operator);
		bits.extend(bits_of(auth.signature.as_ref()));
		let program = match (self.no_sweep(), last) {
			(false, false) => programs::ACCUMULATOR_EXIT,
			(false, true) => programs::ACCUMULATOR_EXIT_LAST,
			(true, false) => programs::ACCUMULATOR2_EXIT,
			(true, true) => programs::ACCUMULATOR2_EXIT_LAST,
		};
		vec![pack_bits(&bits), unhex(program), self.cmr().to_vec(), self.control_block()]
	}

	/// The exit of `exit`'s slot from this output, held at `coin` with
	/// `held` of an asset: input 0 the batch output, non-final, with the
	/// authorisation's time as the lock time; output 0 the slot's entry
	/// (`entry`, whose script the record names); output 1 the rest under the
	/// next state, unless nothing is left; then the fee as `fee` says, from the
	/// slot's reserve or a coin attached. Refuses an exit the program would
	/// refuse for the slot, its record or the amounts; the signature it checks
	/// against `chain`.
	#[allow(clippy::too_many_arguments)]
	pub fn exit_tx(&self, chain: &Chain, coin: OutPoint, held: (AssetId, u64), exit: &Exit, entry: &ExplicitOutput, auth: &ExitAuth,
		fee: &FeeSource) -> Result<UnrollTx, AccumulatorError>
	{
		let (asset, value) = held;
		self.check_slot(chain, exit, auth)?;
		if sha256(entry.script_pubkey.as_bytes()) != exit.record.script_hash || entry.value != exit.record.value || entry.asset != asset {
			return Err(AccumulatorError::Entry(exit.slot));
		}
		let weight = exit.record.weight().ok_or(AccumulatorError::Weight)?;
		let rest = value.checked_sub(weight).ok_or(AccumulatorError::Short { slot: exit.slot, held: value, weight })?;
		let mut outputs = vec![entry.clone()];
		if rest > 0 {
			outputs.push(ExplicitOutput::new(asset, rest, self.after(exit.slot).script_pubkey()));
		}
		let prev = ExplicitOutput::new(asset, value, self.script_pubkey()).txout();
		let mut u = assemble(LockTime::from_consensus(auth.time.to_consensus_u32()), vec![(coin, prev, Sequence(0xffff_fffe))],
			&outputs, fee, FEE_COIN_SEQUENCE)?;
		u.tx.input[0].witness.script_witness = self.exit_witness(exit, auth, rest == 0);
		Ok(u)
	}

	/// The program's checks on the slot and the authorisation: the slot in the
	/// batch, its record on its path to `ROOT` with no weight past 64 bits, its
	/// bit clear, and the signature the owner's, or the operator's when
	/// `by_operator`, over [`exit_digest`].
	pub fn check_slot(&self, chain: &Chain, exit: &Exit, auth: &ExitAuth) -> Result<(), AccumulatorError> {
		if exit.slot as usize >= SLOTS {
			return Err(AccumulatorError::Slot(exit.slot));
		}
		if exit.path.len() != DEPTH {
			return Err(AccumulatorError::PathLength(exit.path.len()));
		}
		let (root, _) = exit.root().ok_or(AccumulatorError::Weight)?;
		if root != self.root {
			return Err(AccumulatorError::NotInRoot(exit.slot));
		}
		if self.bitmap.is_left(exit.slot) {
			return Err(AccumulatorError::Left(exit.slot));
		}
		let (key, who) = if auth.by_operator { (self.operator, "operator") } else { (exit.record.owner, "owner") };
		let digest = exit_digest(chain, &self.root, &exit.record.record(exit.slot), auth.time);
		if !verify_digest(&auth.signature, &digest, &key) {
			return Err(AccumulatorError::Signature(who));
		}
		Ok(())
	}

	/// Judges a transaction whose input `k` spends `spent` by this state's
	/// exit, by the program's rules, naming the first one it breaks: `spent`
	/// is this state's output, explicit; the slot and the authorisation
	/// ([`AccumulatorPolicy::check_slot`]); the lock time; no annex on input
	/// `k`; the entry at `2k` and the rest at `2k+1`.
	pub fn check(&self, chain: &Chain, tx: &Transaction, k: usize, spent: &TxOut, exit: &Exit, auth: &ExitAuth)
		-> Result<(), AccumulatorError>
	{
		let rule = |s: &str| Err(AccumulatorError::Rule(s.into()));
		let held = match ExplicitOutput::from_txout(spent) {
			Some(o) if o.script_pubkey == self.script_pubkey() => (o.asset, o.value),
			Some(_) => return rule("the coin spent is not this state's output: the witness claims another state"),
			None => return rule("the coin spent is not explicit"),
		};
		self.check_slot(chain, exit, auth)?;
		let t = auth.time.to_consensus_u32();
		let lock = tx.lock_time.to_consensus_u32();
		if !(lock >= 500_000_000 && lock >= t && tx.input.iter().any(|i| i.sequence.0 != 0xffff_ffff)) && t != 0 {
			return rule("the lock time is not a time at or after the authorisation's, with a non-final input");
		}
		if tx.input.get(k).is_some_and(|i| crate::witness::annex(&i.witness.script_witness).is_some()) {
			return rule("the batch input carries an annex, which the authorisation does not name");
		}
		let out = |i: usize| tx.output.get(i).and_then(|o| {
			if !o.nonce.is_null() {
				return None;
			}
			ExplicitOutput::from_txout(o)
		});
		let (asset, value) = held;
		match out(2 * k) {
			Some(o) if o.asset == asset && o.value == exit.record.value && sha256(o.script_pubkey.as_bytes()) == exit.record.script_hash => {},
			_ => return rule("output 2k is not the slot's entry, explicit with no nonce, in the batch's asset"),
		}
		let weight = exit.record.weight().ok_or(AccumulatorError::Weight)?;
		let rest = value.checked_sub(weight).ok_or(AccumulatorError::Short { slot: exit.slot, held: value, weight })?;
		if rest > 0 {
			match out(2 * k + 1) {
				Some(o) if o.asset == asset && o.value == rest && o.script_pubkey == self.after(exit.slot).script_pubkey() => {},
				_ => return rule("output 2k+1 is not the rest under the next state, explicit with no nonce, in the batch's asset"),
			}
		}
		Ok(())
	}
}

/// `SHA256(SHA256("Arca/accumulator-release") ‖ genesis ‖ ROOT ‖ rec_j ‖ M)`:
/// what a slot's owner signs to release it for the round whose connector
/// asset is `connector`. Genesis and `M` in internal byte order.
pub fn release_digest(chain: &Chain, root: &[u8; 32], record: &[u8; 32], connector: AssetId) -> [u8; 32] {
	let mut b = Vec::with_capacity(160);
	b.extend(sha256(RELEASE_TAG));
	b.extend(chain.genesis_bytes());
	b.extend(root);
	b.extend(record);
	b.extend(asset_bytes(connector));
	sha256(&b)
}

/// The chain's commitment to every output of `tx` (Simplicity's
/// `outputs_hash`): the SHA256 of four hashes, each over every output in
/// order, of its asset and amount, of its nonce, of its script's SHA256, and
/// of its range proof's SHA256 (of nothing for an explicit amount), each field
/// as the transaction encodes it.
pub fn outputs_hash(tx: &Transaction) -> [u8; 32] {
	let (mut amounts, mut nonces, mut scripts, mut proofs) = (vec![], vec![], vec![], vec![]);
	for o in &tx.output {
		amounts.extend(elements::encode::serialize(&o.asset));
		amounts.extend(elements::encode::serialize(&o.value));
		nonces.extend(elements::encode::serialize(&o.nonce));
		scripts.extend(sha256(o.script_pubkey.as_bytes()));
		let proof = match (&o.value, &o.witness.rangeproof) {
			(elements::confidential::Value::Confidential(_), Some(p)) => p.serialize(),
			_ => vec![],
		};
		proofs.extend(sha256(&proof));
	}
	sha256(&[sha256(&amounts), sha256(&nonces), sha256(&scripts), sha256(&proofs)].concat())
}

/// `SHA256(SHA256("Arca/accumulator-release-outputs") ‖ genesis ‖ D ‖ k ‖
/// outputs_hash)`: what the operator signs to take the slots a release frees
/// out of the coin at input `k` holding the state whose data leaf is `D`,
/// into every output of `tx`. `k` four bytes big-endian.
pub fn payout_digest(chain: &Chain, state: &AccumulatorPolicy, k: u32, tx: &Transaction) -> [u8; 32] {
	let mut b = Vec::with_capacity(132);
	b.extend(sha256(PAYOUT_TAG));
	b.extend(chain.genesis_bytes());
	b.extend(state.data_leaf());
	b.extend(k.to_be_bytes());
	b.extend(outputs_hash(tx));
	sha256(&b)
}

/// One slot of a release: the slot, its record and path ([`Exit`]), the
/// connector asset `M` its owner's release names, and that release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Released {
	pub exit: Exit,
	pub connector: AssetId,
	pub signature: Signature,
}

/// A release, built and waiting for the operator's signature over its
/// outputs ([`ReleaseSpend::digest`]).
#[derive(Debug, Clone)]
pub struct ReleaseSpend {
	pub tx: Transaction,
	/// The outputs the inputs spend, in input order.
	pub prevouts: Vec<TxOut>,
	state: AccumulatorPolicy,
	slots: Vec<Released>,
	/// The index of the input holding each slot's connector asset.
	inputs: Vec<u32>,
	last: bool,
}

impl ReleaseSpend {
	/// What the operator signs: [`payout_digest`] of the batch at input 0.
	pub fn digest(&self, chain: &Chain) -> [u8; 32] {
		payout_digest(chain, &self.state, 0, &self.tx)
	}

	/// The transaction with the batch input's witness. Every other input's
	/// witness (the connector atoms', a fee coin's) is the operator's to add;
	/// none changes an output, so none changes what it signed.
	pub fn finish(mut self, operator_sig: &Signature) -> Transaction {
		let places: Vec<(&Released, u32)> = self.slots.iter().zip(self.inputs.iter().copied()).collect();
		self.tx.input[0].witness.script_witness = self.state.release_witness(&places, operator_sig, self.last);
		self.tx
	}

	/// The slots it releases, in order.
	pub fn slots(&self) -> Vec<u16> {
		self.slots.iter().map(|r| r.exit.slot).collect()
	}
}

impl AccumulatorPolicy {
	/// The release's witness: the state, the places in order (each a set bit,
	/// the slot's record, path, the index of its connector's input and its
	/// owner's signature), a clear bit unless every place is filled, the
	/// operator's signature; then the pruned program for `slots.len()` slots,
	/// leaving a rest or taking the last (`last`), the commitment root and the
	/// control block. Panics on 0 or more than [`RELEASE_PLACES`] slots, or on
	/// a batch with a sweep.
	pub fn release_witness(&self, slots: &[(&Released, u32)], operator_sig: &Signature, last: bool) -> Vec<Vec<u8>> {
		let n = slots.len();
		assert!((1..=RELEASE_PLACES).contains(&n) && self.no_sweep(), "a release of 1 to {} slots of arca/accumulator-2", RELEASE_PLACES);
		let mut bits: Vec<bool> = bits_of(&self.data_bytes());
		// ACTION is Right: a release.
		bits.push(true);
		for (r, at) in slots {
			bits.push(true);
			let e = &r.exit;
			let mut b = Vec::with_capacity(RELEASED_SLOT_BYTES);
			b.extend(e.slot.to_be_bytes());
			b.extend(e.record.owner.serialize());
			b.extend(e.record.script_hash);
			b.extend(e.record.value.to_be_bytes());
			b.extend(e.record.reserve.to_be_bytes());
			for (h, w) in &e.path {
				b.extend(h);
				b.extend(w.to_be_bytes());
			}
			b.extend(at.to_be_bytes());
			b.extend(r.signature.as_ref());
			bits.extend(bits_of(&b));
		}
		if n < RELEASE_PLACES {
			bits.push(false);
		}
		bits.extend(bits_of(operator_sig.as_ref()));
		let program = if last { programs::ACCUMULATOR2_RELEASE_LAST[n - 1] } else { programs::ACCUMULATOR2_RELEASE[n - 1] };
		vec![pack_bits(&bits), unhex(program), accumulator2_cmr().to_vec(), self.control_block()]
	}

	/// The program's checks on a release's slots, as [`AccumulatorPolicy::check_slot`]
	/// does for an exit: a batch without a sweep, 1 to [`RELEASE_PLACES`]
	/// slots in increasing order, each in the batch with its record on its path
	/// to `ROOT`, its bit clear, and its owner's signature over
	/// [`release_digest`] for its connector asset. Returns what the slots
	/// weigh together.
	pub fn check_release_slots(&self, chain: &Chain, slots: &[Released]) -> Result<u64, AccumulatorError> {
		if !self.no_sweep() {
			return Err(AccumulatorError::NoRelease);
		}
		if !(1..=RELEASE_PLACES).contains(&slots.len()) {
			return Err(AccumulatorError::Places(slots.len()));
		}
		let mut total = 0u64;
		let mut floor = 0u32;
		for r in slots {
			let e = &r.exit;
			if (e.slot as u32) < floor {
				return Err(AccumulatorError::Order(e.slot));
			}
			floor = e.slot as u32 + 1;
			if e.slot as usize >= SLOTS {
				return Err(AccumulatorError::Slot(e.slot));
			}
			if e.path.len() != DEPTH {
				return Err(AccumulatorError::PathLength(e.path.len()));
			}
			let (root, _) = e.root().ok_or(AccumulatorError::Weight)?;
			if root != self.root {
				return Err(AccumulatorError::NotInRoot(e.slot));
			}
			if self.bitmap.is_left(e.slot) {
				return Err(AccumulatorError::Left(e.slot));
			}
			let digest = release_digest(chain, &self.root, &e.record.record(e.slot), r.connector);
			if !verify_digest(&r.signature, &digest, &e.record.owner) {
				return Err(AccumulatorError::ReleaseSignature(e.slot));
			}
			total = total.checked_add(e.record.weight().ok_or(AccumulatorError::Weight)?).ok_or(AccumulatorError::Weight)?;
		}
		Ok(total)
	}

	/// The release of `slots` from this output, held at `coin` with `held`
	/// of an asset: input 0 the batch output; then each coin of `connectors`
	/// (an atom of a connector asset the releases name, explicit), paid back
	/// to `connector_to`; output 0 the first of `pay`, the operator's; output
	/// 1 the rest under the next state, unless nothing is left; the rest of
	/// `pay`; the connector atoms; then the fee as `fee` says. What the slots
	/// held beyond `pay` is the margin `fee` takes. Refuses a release the
	/// program would refuse for its slots, a slot whose connector asset no
	/// coin of `connectors` holds, and an empty `pay`.
	#[allow(clippy::too_many_arguments)]
	pub fn release_tx(&self, chain: &Chain, coin: OutPoint, held: (AssetId, u64), slots: &[Released], connectors: &[(OutPoint, TxOut)],
		pay: &[ExplicitOutput], connector_to: Script, fee: &FeeSource) -> Result<ReleaseSpend, AccumulatorError>
	{
		let (asset, value) = held;
		let weight = self.check_release_slots(chain, slots)?;
		let rest = value.checked_sub(weight).ok_or(AccumulatorError::Short { slot: slots[0].exit.slot, held: value, weight })?;
		let (first, others) = pay.split_first().ok_or(AccumulatorError::NoPayout)?;
		let mut inputs = vec![(coin, ExplicitOutput::new(asset, value, self.script_pubkey()).txout(), FINAL)];
		let mut outputs = vec![first.clone()];
		let next: Vec<u16> = slots.iter().map(|r| r.exit.slot).collect();
		if rest > 0 {
			outputs.push(ExplicitOutput::new(asset, rest, self.after_all(&next).script_pubkey()));
		}
		outputs.extend(others.iter().cloned());
		let mut held_connectors = vec![];
		for (at, out) in connectors {
			let (Some(m), Some(v)) = (out.asset.explicit(), out.value.explicit()) else { return Err(SpendError::NotExplicit.into()) };
			outputs.push(ExplicitOutput::new(m, v, connector_to.clone()));
			inputs.push((*at, out.clone(), FINAL));
			held_connectors.push(m);
		}
		let mut at = Vec::with_capacity(slots.len());
		for r in slots {
			let i = held_connectors.iter().position(|m| *m == r.connector).ok_or(AccumulatorError::Connector(r.exit.slot))?;
			at.push(1 + i as u32);
		}
		let u = assemble(LockTime::ZERO, inputs, &outputs, fee, FINAL)?;
		Ok(ReleaseSpend { tx: u.tx, prevouts: u.prevouts, state: *self, slots: slots.to_vec(), inputs: at, last: rest == 0 })
	}

	/// Judges a transaction whose input `k` spends `spent` by this state's
	/// release of `slots` (with the indices `inputs` of their connectors'
	/// inputs, `prevouts` the outputs every input spends), by the program's
	/// rules, naming the first one it breaks: `spent` is this state's output,
	/// explicit; the slots ([`AccumulatorPolicy::check_release_slots`]); each
	/// named input holding its slot's connector asset, explicitly; no annex on
	/// input `k`; the operator's signature over [`payout_digest`]; and the rest
	/// at `2k+1`.
	#[allow(clippy::too_many_arguments)]
	pub fn check_release(&self, chain: &Chain, tx: &Transaction, k: usize, prevouts: &[TxOut], slots: &[Released], inputs: &[u32],
		operator_sig: &Signature) -> Result<(), AccumulatorError>
	{
		let rule = |s: &str| Err(AccumulatorError::Rule(s.into()));
		let held = match prevouts.get(k).and_then(ExplicitOutput::from_txout) {
			Some(o) if o.script_pubkey == self.script_pubkey() => (o.asset, o.value),
			Some(_) => return rule("the coin spent is not this state's output: the witness claims another state"),
			None => return rule("the coin spent is not explicit"),
		};
		let weight = self.check_release_slots(chain, slots)?;
		if inputs.len() != slots.len() {
			return rule("each slot names the input holding its connector asset");
		}
		for (r, i) in slots.iter().zip(inputs) {
			if prevouts.get(*i as usize).and_then(|o| o.asset.explicit()) != Some(r.connector) {
				return Err(AccumulatorError::Connector(r.exit.slot));
			}
		}
		if tx.input.get(k).is_some_and(|i| crate::witness::annex(&i.witness.script_witness).is_some()) {
			return rule("the batch input carries an annex");
		}
		if !verify_digest(operator_sig, &payout_digest(chain, self, k as u32, tx), &self.operator) {
			return Err(AccumulatorError::PayoutSignature);
		}
		let (asset, value) = held;
		let rest = value.checked_sub(weight).ok_or(AccumulatorError::Short { slot: slots[0].exit.slot, held: value, weight })?;
		if rest > 0 {
			let next: Vec<u16> = slots.iter().map(|r| r.exit.slot).collect();
			let ok = tx.output.get(2 * k + 1).filter(|o| o.nonce.is_null()).and_then(ExplicitOutput::from_txout)
				.is_some_and(|o| o.asset == asset && o.value == rest && o.script_pubkey == self.after_all(&next).script_pubkey());
			if !ok {
				return rule("output 2k+1 is not the rest under the next state, explicit with no nonce, in the batch's asset");
			}
		}
		Ok(())
	}
}

/// An owner's release of its slot in an accumulator batch without a sweep,
/// given up for a coin of a round: see [`release_digest`]. The wallet signs
/// one only once it holds its new coin's preimage and that round is final,
/// as for a tree's release ([`crate::release::Release`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccumulatorRelease {
	pub chain: Chain,
	pub root: [u8; 32],
	pub slot: u16,
	/// `rec_j`, the slot's record.
	pub record: [u8; 32],
	/// The key that signs: the slot's owner.
	pub owner: XOnlyPublicKey,
	/// `M`, the connector asset of the round that made the owner's new coin.
	pub connector: AssetId,
}

impl AccumulatorRelease {
	/// The release of `old`'s slot, a leaf the wallet holds and validated,
	/// given up for `new`, a leaf it validated against `round`, whose
	/// connector output is `c`. Refuses a `round` other than the one `new`
	/// was validated against, an output `c` that is not the operator's
	/// connector, an old leaf under another operator, and a batch with a
	/// sweep, which has no release.
	pub fn for_refresh(old: &ValidAccumulatorLeaf, new: &ValidLeaf, round: &Transaction, c: u32) -> Result<AccumulatorRelease, SpendError> {
		if round.txid() != new.round_txid {
			return Err(SpendError::NotTheRound);
		}
		if old.leaf.operator != new.branch.leaf.operator {
			return Err(SpendError::OtherOperator);
		}
		AccumulatorRelease::from_round(old, round, c)
	}

	/// [`AccumulatorRelease::for_refresh`] for `new`, a leaf of an
	/// accumulator batch.
	pub fn for_accumulator_refresh(old: &ValidAccumulatorLeaf, new: &ValidAccumulatorLeaf, round: &Transaction, c: u32)
		-> Result<AccumulatorRelease, SpendError>
	{
		if round.txid() != new.round_txid {
			return Err(SpendError::NotTheRound);
		}
		if old.leaf.operator != new.leaf.operator {
			return Err(SpendError::OtherOperator);
		}
		AccumulatorRelease::from_round(old, round, c)
	}

	/// The release of `old`'s slot, given up for the offboard output
	/// `offboard` that `round` pays, whose connector output is `c`.
	pub fn for_offboard(old: &ValidAccumulatorLeaf, offboard: &OffboardPolicy, round: &Transaction, c: u32)
		-> Result<AccumulatorRelease, SpendError>
	{
		if old.leaf.operator != offboard.operator {
			return Err(SpendError::OtherOperator);
		}
		offboard.find(round)?;
		AccumulatorRelease::from_round(old, round, c)
	}

	fn from_round(old: &ValidAccumulatorLeaf, round: &Transaction, c: u32) -> Result<AccumulatorRelease, SpendError> {
		if !old.policy.no_sweep() {
			return Err(SpendError::NoLowestNode);
		}
		ConnectorPolicy { operator: old.leaf.operator }.check(round, c)?;
		Ok(AccumulatorRelease {
			chain: old.leaf.chain, root: old.policy.root, slot: old.exit.slot, record: old.exit.record.record(old.exit.slot),
			owner: old.exit.record.owner, connector: connector_asset(round.txid(), c),
		})
	}

	/// What the owner signs.
	pub fn digest(&self) -> [u8; 32] {
		release_digest(&self.chain, &self.root, &self.record, self.connector)
	}

	/// The server's check of a release handed to it.
	pub fn verify(&self, sig: &Signature) -> Result<(), SpendError> {
		if verify_digest(sig, &self.digest(), &self.owner) { Ok(()) } else { Err(SpendError::Signature("owner")) }
	}
}

fn bits_of(b: &[u8]) -> Vec<bool> {
	b.iter().flat_map(|x| (0..8).rev().map(move |i| x >> i & 1 == 1)).collect()
}

fn pack_bits(b: &[bool]) -> Vec<u8> {
	b.chunks(8).map(|c| c.iter().enumerate().fold(0u8, |a, (i, &x)| a | ((x as u8) << (7 - i)))).collect()
}

/// An exit read from a witness found on-chain: the state it spent and the
/// slot it took. Every exit publishes the whole state, so a holder that was
/// away needs only the latest exit to know the batch's bitmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeenExit {
	pub root: [u8; 32],
	pub operator: [u8; 32],
	pub bitmap: Bitmap,
	pub slot: u16,
	pub by_operator: bool,
	pub time: u32,
	/// Whether it took the last of the batch, so left no rest.
	pub last: bool,
}

impl SeenExit {
	/// The bitmap after this exit.
	pub fn bitmap_after(&self) -> Bitmap {
		self.bitmap.with(self.slot)
	}
}

/// A release read from a witness found on-chain: the state it spent and the
/// slots it freed, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenRelease {
	pub root: [u8; 32],
	pub operator: [u8; 32],
	pub bitmap: Bitmap,
	pub slots: Vec<u16>,
	/// Whether it took the last of the batch, so left no rest.
	pub last: bool,
}

impl SeenRelease {
	/// The bitmap after this release.
	pub fn bitmap_after(&self) -> Bitmap {
		self.slots.iter().fold(self.bitmap, |b, j| b.with(*j))
	}
}

/// A spend of an accumulator batch by its program, read from the witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeenSpend {
	Exit(SeenExit),
	Release(SeenRelease),
}

impl SeenSpend {
	pub fn root(&self) -> [u8; 32] {
		match self { SeenSpend::Exit(e) => e.root, SeenSpend::Release(r) => r.root }
	}

	pub fn operator(&self) -> [u8; 32] {
		match self { SeenSpend::Exit(e) => e.operator, SeenSpend::Release(r) => r.operator }
	}

	/// The bitmap of the state it spent.
	pub fn bitmap(&self) -> Bitmap {
		match self { SeenSpend::Exit(e) => e.bitmap, SeenSpend::Release(r) => r.bitmap }
	}

	/// The bitmap of the state it leaves.
	pub fn bitmap_after(&self) -> Bitmap {
		match self { SeenSpend::Exit(e) => e.bitmap_after(), SeenSpend::Release(r) => r.bitmap_after() }
	}

	/// The slots that left by it.
	pub fn slots(&self) -> Vec<u16> {
		match self { SeenSpend::Exit(e) => vec![e.slot], SeenSpend::Release(r) => r.slots.clone() }
	}

	/// Whether it took the last of the batch, so left no rest.
	pub fn last(&self) -> bool {
		match self { SeenSpend::Exit(e) => e.last, SeenSpend::Release(r) => r.last }
	}
}

/// `n` bytes of `bits` from bit `at`, or `None` past the end.
fn bytes_at(bits: &[bool], at: usize, n: usize) -> Option<Vec<u8>> {
	bits.get(at..at + 8 * n).map(pack_bits)
}

/// Reads an exit from an input's witness: `None` when the input does not spend
/// an accumulator batch by an exit ([`read_spend`]).
pub fn read_exit(witness: &[Vec<u8>]) -> Option<SeenExit> {
	match read_spend(witness)? {
		SeenSpend::Exit(e) => Some(e),
		SeenSpend::Release(_) => None,
	}
}

/// Reads an exit or a release from an input's witness: `None` when the input
/// does not spend an accumulator batch by its program. An annex (BIP341),
/// which anyone broadcasting an exit can add, is set aside first
/// ([`crate::witness::without_annex`]): the spend is the same.
pub fn read_spend(witness: &[Vec<u8>]) -> Option<SeenSpend> {
	let [w, program, cmr, _cb] = crate::witness::without_annex(witness) else { return None };
	let v2 = if cmr[..] == accumulator_cmr()[..] {
		false
	} else if cmr[..] == accumulator2_cmr()[..] {
		true
	} else {
		return None;
	};
	let bits = bits_of(w);
	let root: [u8; 32] = w.get(0..32)?.try_into().ok()?;
	let operator: [u8; 32] = w.get(32..64)?.try_into().ok()?;
	let bitmap = Bitmap::from_bytes(w.get(64..192)?)?;
	let is = |p: &str| program[..] == unhex(p)[..];
	let exit_last = if v2 {
		if is(programs::ACCUMULATOR2_EXIT_LAST) { Some(true) } else if is(programs::ACCUMULATOR2_EXIT) { Some(false) } else { None }
	} else if is(programs::ACCUMULATOR_EXIT_LAST) {
		Some(true)
	} else if is(programs::ACCUMULATOR_EXIT) {
		Some(false)
	} else {
		return None;
	};
	if let Some(last) = exit_last {
		if w.len() != WITNESS_BYTES {
			return None;
		}
		// After the state, accumulator-2's ACTION tag (clear for an exit).
		let mut at = STATE_BYTES * 8;
		if v2 {
			if bits[at] {
				return None;
			}
			at += 1;
		}
		let slot = u16::from_be_bytes(bytes_at(&bits, at, 2)?.try_into().ok()?);
		let t_at = at + 8 * (2 + 32 + 32 + 8 + 8 + DEPTH * 40);
		let time = u32::from_be_bytes(bytes_at(&bits, t_at, 4)?.try_into().ok()?);
		let by_operator = *bits.get(t_at + 32)?;
		return Some(SeenSpend::Exit(SeenExit { root, operator, bitmap, slot, by_operator, time, last }));
	}
	let (n, last) = (1..=RELEASE_PLACES).find_map(|n| {
		if is(programs::ACCUMULATOR2_RELEASE[n - 1]) {
			Some((n, false))
		} else if is(programs::ACCUMULATOR2_RELEASE_LAST[n - 1]) {
			Some((n, true))
		} else {
			None
		}
	})?;
	let mut at = STATE_BYTES * 8;
	if !*bits.get(at)? {
		return None;
	}
	at += 1;
	let mut slots = Vec::with_capacity(n);
	for _ in 0..n {
		if !*bits.get(at)? {
			return None;
		}
		at += 1;
		slots.push(u16::from_be_bytes(bytes_at(&bits, at, 2)?.try_into().ok()?));
		at += 8 * RELEASED_SLOT_BYTES;
	}
	if n < RELEASE_PLACES {
		if *bits.get(at)? {
			return None;
		}
		at += 1;
	}
	// The operator's signature, then padding to a whole byte.
	if w.len() != (at + 512).div_ceil(8) {
		return None;
	}
	Some(SeenSpend::Release(SeenRelease { root, operator, bitmap, slots, last }))
}

/// The size of an exit whose fee comes from the slot's reserve, in vbytes, as
/// measured on regtest (`covenant/tests/accumulator.rs`): the same at every
/// slot and in every batch of `arca/accumulator-1`.
pub const EXIT_VBYTES: u64 = 979;
/// [`EXIT_VBYTES`] for `arca/accumulator-2`, the batch without a sweep, whose
/// program also carries the release (`covenant/tests/accumulator_release.rs`).
pub const EXIT2_VBYTES: u64 = 1_072;
/// The size of a gated node's unroll in a tree, in vbytes: the mean of the
/// five levels of a 1,024-leaf radix-4 tree measured beside it (615, 592,
/// 571, 549 and 527).
pub const NODE_VBYTES: u64 = 571;

/// What `exits` exits from a batch of `n` leaves cost on the chain, in
/// vbytes, as an accumulator and as a tree at `radix`: one exit each
/// ([`EXIT_VBYTES`], or [`EXIT2_VBYTES`] for a batch without a sweep,
/// `no_sweep`), against the node transactions they unroll. The leaves leaving
/// are taken as scattered at random, so a level of `N` nodes has
/// `N (1 − (1 − 1/N)^exits)` of them unrolled. Each leaf's entry and its own
/// exit cost the same in both and are left out.
pub fn exit_costs(n: usize, radix: usize, exits: f64, no_sweep: bool) -> (f64, f64) {
	let mut tree = 0.0;
	let mut width = n.max(1);
	loop {
		width = width.div_ceil(radix.max(2));
		let nodes = width as f64;
		tree += nodes * (1.0 - (1.0 - 1.0 / nodes).powf(exits)) * NODE_VBYTES as f64;
		if width == 1 {
			break;
		}
	}
	(exits * if no_sweep { EXIT2_VBYTES } else { EXIT_VBYTES } as f64, tree)
}

/// Whether the operator should build a batch of `n` leaves as an accumulator
/// rather than a tree at `radix`, when it expects `exits` of them to leave on
/// the chain: when it fits (two to 1,024 leaves) and costs less to leave. At
/// 1,024 leaves and radix 4 that is up to 77 exits (19 of 256, 4 of 64, one of
/// 16), and up to 61 for a batch without a sweep (`no_sweep`, 15 of 256, 3 of
/// 64, one of 16), whose exit is larger; past that, or on a run, the tree
/// wins, because its exits share nodes and run in parallel.
pub fn prefer_accumulator(n: usize, radix: usize, exits: f64, no_sweep: bool) -> bool {
	if !(2..=SLOTS).contains(&n) {
		return false;
	}
	let (acc, tree) = exit_costs(n, radix, exits.max(1.0), no_sweep);
	acc < tree
}

/// An accumulator batch's parameters: a tree's, but for the radix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulatorParams {
	pub asset: AssetId,
	pub chain: Chain,
	/// `(T, S, W, E_0 … E_K)`; `S` is the operator's key.
	pub schedule: ClockSchedule,
	/// Burn-only sweeps, for a batch its asset's issuer runs.
	pub burn: bool,
	/// `Fixed { node, entry }` puts `node` on every slot's exit and `entry`
	/// on every entry; `FeeRate` sizes each from the transaction that spends
	/// it.
	pub reserve: ReserveRule,
	pub min_leaf: u64,
}

impl AccumulatorParams {
	fn as_tree(&self) -> TreeParams {
		TreeParams {
			asset: self.asset, chain: self.chain, schedule: self.schedule.clone(), burn: self.burn, delegated_reclaim: false, radix: MIN_RADIX,
			reserve: self.reserve, min_leaf: self.min_leaf,
		}
	}
}

/// What [`ReserveRule::FeeRate`] reserves for a slot's exit, holding an entry
/// paid to a script of `entry_script_len` bytes: `multiple` times the floor
/// for the exit with a rest, its fee from the reserve.
pub fn exit_fee_rate_reserve(state: &AccumulatorPolicy, asset: AssetId, entry_script_len: usize, floor_per_kvb: u64, multiple: u64) -> u64 {
	let program = if state.no_sweep() { programs::ACCUMULATOR2_EXIT } else { programs::ACCUMULATOR_EXIT };
	let w = vec![vec![0; WITNESS_BYTES], unhex(program), state.cmr().to_vec(), state.control_block()];
	let entry = ExplicitOutput::new(asset, 1, Script::from(vec![0; entry_script_len])).txout();
	let rest = ExplicitOutput::new(asset, 1, state.script_pubkey()).txout();
	fee_rate_reserve(floor_per_kvb, multiple, w, vec![entry, rest], asset)
}

/// An accumulator batch built from the leaves of one asset.
#[derive(Debug, Clone)]
pub struct Accumulator {
	params: AccumulatorParams,
	leaves: Vec<TreeLeaf>,
	slots: Vec<Slot>,
	tree: SlotTree,
	policy: AccumulatorPolicy,
	total: u64,
}

impl Accumulator {
	/// Builds the batch over `leaves`, slot `i` holding leaf `i`. Each leaf
	/// sits behind its hash-locked entry exactly as in a tree, under the same
	/// rules (one key per leaf, no operator nonce twice, no leaf script
	/// twice, the leaf's value bounds); the slot's record names the entry and
	/// the reserve of its exit.
	pub fn build(params: AccumulatorParams, leaves: &[LeafSpec]) -> Result<Accumulator, TreeError> {
		let n = leaves.len();
		if n == 0 {
			return Err(TreeError::NoLeaves);
		}
		if n > SLOTS {
			return Err(TreeError::TooManyLeaves(n));
		}
		if let Some(i) = params.schedule.backwards_at() {
			return Err(TreeError::ScheduleBackwards(i));
		}
		// Without a sweep the batch is arca/accumulator-2, whose release takes
		// back the slots their owners gave up; it has no sweep to be burn-only.
		if !params.schedule.expires() && params.burn {
			return Err(TreeError::Policy(crate::Error::NoSweep));
		}
		// A channel-1 leaf's terms, and a claim-1 leaf's, are not in an
		// accumulator record: a channel and a claim go in a tree.
		if let Some(i) = leaves.iter().position(|l| matches!(l.template, Template::Channel1 | Template::Claim1 | Template::Vest1) || l.channel.is_some()
			|| l.claim.is_some()) {
			return Err(TreeError::Template { leaf: i });
		}
		let tree_leaves = build_leaves(&params.as_tree(), leaves)?;
		let operator = params.schedule.operator;
		let sweep = params.schedule.sweep_path(false, params.burn);
		let empty = AccumulatorPolicy { root: [0; 32], operator, bitmap: Bitmap::default(), sweep };
		let mut slots = Vec::with_capacity(n);
		for l in &tree_leaves {
			let entry_script = l.entry.script_pubkey();
			let reserve = match params.reserve {
				ReserveRule::Fixed { node, .. } => node,
				ReserveRule::FeeRate { floor_per_kvb, multiple } =>
					exit_fee_rate_reserve(&empty, params.asset, entry_script.len(), floor_per_kvb, multiple),
			};
			if reserve > MAX_VALUE {
				return Err(TreeError::ValueSum);
			}
			slots.push(Slot { owner: l.spec.owner, script_hash: sha256(entry_script.as_bytes()), value: l.entry_value, reserve });
		}
		let weighted = slots.iter().enumerate()
			.map(|(j, s)| Ok((s.record(j as u16), s.weight().ok_or(TreeError::ValueSum)?)))
			.collect::<Result<Vec<_>, TreeError>>()?;
		let tree = SlotTree::new(&weighted).ok_or(TreeError::ValueSum)?;
		let (root, total) = tree.root();
		if total > MAX_VALUE {
			return Err(TreeError::ValueSum);
		}
		let policy = AccumulatorPolicy { root, ..empty };
		Ok(Accumulator { params, leaves: tree_leaves, slots, tree, policy, total })
	}

	pub fn params(&self) -> &AccumulatorParams {
		&self.params
	}

	pub fn len(&self) -> usize {
		self.leaves.len()
	}

	pub fn is_empty(&self) -> bool {
		self.leaves.is_empty()
	}

	/// The leaves and their entries, slot by slot.
	pub fn leaves(&self) -> &[TreeLeaf] {
		&self.leaves
	}

	pub fn slots(&self) -> &[Slot] {
		&self.slots
	}

	/// The state the round creates: every bit clear.
	pub fn policy(&self) -> &AccumulatorPolicy {
		&self.policy
	}

	/// The root's weight: what the batch output holds.
	pub fn total(&self) -> u64 {
		self.total
	}

	/// The output the round pays.
	pub fn batch_output(&self) -> ExplicitOutput {
		ExplicitOutput::new(self.params.asset, self.total, self.policy.script_pubkey())
	}

	/// The script the round pays the token's atom to: the first clock; `None`
	/// for a batch without a sweep, which has no token.
	pub fn clock0_script_pubkey(&self) -> Option<Script> {
		self.params.schedule.expires().then(|| self.params.schedule.clock0_script_pubkey())
	}

	/// Slot `i`'s exit: its record and path.
	pub fn exit(&self, i: usize) -> Exit {
		Exit { slot: i as u16, record: self.slots[i], path: self.tree.path(i) }
	}

	/// Leaf `i`'s record. Panics if there is no such leaf.
	pub fn record(&self, i: usize) -> AccumulatorRecord {
		let l = &self.leaves[i];
		AccumulatorRecord {
			template: l.spec.template,
			owner: l.spec.owner,
			owner_nonce: l.spec.owner_nonce,
			operator_nonce: l.spec.operator_nonce,
			exit_delay: l.spec.exit_delay,
			htlc: l.spec.htlc,
			order: l.spec.order,
			landing: l.spec.landing,
			asset: self.params.asset,
			value: l.spec.value,
			unlock_hash: l.spec.unlock_hash,
			entry_reserve: l.entry_reserve,
			chain: self.params.chain,
			schedule: self.params.schedule.clone(),
			burn: self.params.burn,
			slot: i as u16,
			exit_reserve: self.slots[i].reserve,
			path: self.tree.path(i),
		}
	}

	/// Every leaf's record, slot by slot.
	pub fn records(&self) -> Vec<AccumulatorRecord> {
		(0..self.len()).map(|i| self.record(i)).collect()
	}
}

/// What the holder of a leaf in an accumulator batch keeps: everything to
/// check the leaf against the round and take it out alone, and nothing
/// secret. The leaf's own fields are a tree leaf record's; the path is the
/// slot, the reserve of its exit and its ten siblings with their weights.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulatorRecord {
	pub template: Template,
	pub owner: XOnlyPublicKey,
	pub owner_nonce: [u8; 32],
	pub operator_nonce: [u8; 32],
	pub exit_delay: RelativeTime,
	pub htlc: Option<HtlcTerms>,
	pub order: Option<OrderLeafTerms>,
	pub landing: Option<Landing>,
	pub asset: AssetId,
	pub value: u64,
	pub unlock_hash: [u8; 32],
	pub entry_reserve: u64,
	pub chain: Chain,
	pub schedule: ClockSchedule,
	pub burn: bool,
	pub slot: u16,
	pub exit_reserve: u64,
	pub path: Vec<Weighted>,
}

/// What [`AccumulatorRecord::validate`] returns for a leaf it accepts.
#[derive(Debug, Clone)]
pub struct ValidAccumulatorLeaf {
	pub leaf_id: LeafId,
	/// The round the leaf was checked against.
	pub round_txid: Txid,
	/// The index of the batch output in the round.
	pub batch_vout: u32,
	/// The state the round created.
	pub policy: AccumulatorPolicy,
	/// What the batch output holds.
	pub total: u64,
	pub exit: Exit,
	pub leaf: LeafPolicy,
	pub entry: EntryPolicy,
	pub entry_value: u64,
}

impl ValidAccumulatorLeaf {
	pub fn entry_output(&self) -> ExplicitOutput {
		ExplicitOutput::new(self.entry.asset, self.entry_value, self.entry.script_pubkey())
	}

	pub fn leaf_output(&self) -> ExplicitOutput {
		ExplicitOutput::new(self.entry.asset, self.entry.value, self.leaf.script_pubkey())
	}

	/// The unlock of the entry held at `outpoint` into the leaf, with the
	/// preimage: the leaf at output 0, then the fee from the entry's reserve
	/// or a coin attached. The same transaction a tree leaf's entry makes.
	pub fn entry_tx(&self, outpoint: OutPoint, preimage: &[u8; 32], fee: &FeeSource) -> Result<UnrollTx, AccumulatorError> {
		let mut u = assemble(LockTime::ZERO, vec![(outpoint, self.entry_output().txout(), Sequence(0xffff_ffff))],
			&[self.leaf_output()], fee, Sequence(0xffff_ffff))?;
		u.tx.input[0].witness.script_witness = self.entry.unlock_witness(preimage);
		Ok(u)
	}

	/// The exit of this leaf's slot from the batch in `state`, held at `coin`
	/// with `held`: [`AccumulatorPolicy::exit_tx`] with this leaf's entry.
	pub fn exit_tx(&self, state: &AccumulatorPolicy, coin: OutPoint, held: u64, auth: &ExitAuth, fee: &FeeSource)
		-> Result<UnrollTx, AccumulatorError>
	{
		state.exit_tx(&self.leaf.chain, coin, (self.entry.asset, held), &self.exit, &self.entry_output(), auth, fee)
	}

	/// What the owner or the operator signs to take this leaf out from `t`.
	pub fn exit_digest(&self, time: MedianTime) -> [u8; 32] {
		exit_digest(&self.leaf.chain, &self.policy.root, &self.exit.record.record(self.exit.slot), time)
	}

	/// The forfeit a wallet signs for `old`, given up in a refresh for this
	/// new leaf of `round`, whose connector output is `c`: as
	/// [`Forfeit::for_refresh`] does for a tree leaf, the unlock hash is this
	/// leaf's entry's and `M` the round's connector asset. Refuses a `round`
	/// other than the one this leaf was validated against, an output `c` that
	/// is not the operator's connector, and an old leaf under another
	/// operator.
	#[allow(clippy::too_many_arguments)]
	pub fn forfeit_for(&self, old: LeafPolicy, (asset, value): (AssetId, u64), old_id: LeafId, round: &Transaction, c: u32,
		refund_delay: RelativeTime, margin: u64) -> Result<Forfeit, SpendError>
	{
		let round_txid = round.txid();
		if round_txid != self.round_txid {
			return Err(SpendError::NotTheRound);
		}
		if old.operator != self.leaf.operator {
			return Err(SpendError::OtherOperator);
		}
		ConnectorPolicy { operator: old.operator }.check(round, c)?;
		Forfeit::new(old, (asset, value), old_id, self.entry.unlock_hash, connector_asset(round_txid, c), refund_delay, margin)
	}
}

impl AccumulatorRecord {
	/// The operator's key `S`.
	pub fn operator(&self) -> XOnlyPublicKey {
		self.schedule.operator
	}

	/// The leaf's salt, rebuilt from the two nonces.
	pub fn salt(&self) -> [u8; 32] {
		leaf_salt(&self.owner_nonce, &self.operator_nonce)
	}

	/// Checks the record's shape: the template and its terms, the value
	/// bounds, the slot and the path's length, and no burn-only sweeps in a
	/// batch without a sweep.
	pub fn check(&self) -> Result<(), AccumulatorError> {
		if self.burn && !self.schedule.expires() {
			return Err(RecordError::Template("burn-only sweeps in a batch without a sweep".into()).into());
		}
		check_template(self.template, &self.htlc, &self.order, &self.landing, &None, self.asset, self.value, &self.owner,
			&self.schedule.operator, self.exit_delay)?;
		if self.value == 0 || self.value > MAX_VALUE {
			return Err(RecordError::Value(self.value).into());
		}
		for v in [self.entry_reserve, self.exit_reserve] {
			if v > MAX_VALUE {
				return Err(RecordError::Value(v).into());
			}
		}
		if self.slot as usize >= SLOTS {
			return Err(AccumulatorError::Slot(self.slot));
		}
		if self.path.len() != DEPTH {
			return Err(AccumulatorError::PathLength(self.path.len()));
		}
		Ok(())
	}

	/// The leaf's policy.
	pub fn leaf(&self) -> LeafPolicy {
		leaf_policy(self.template, (&self.htlc, &self.order, &self.landing, &None), self.owner, self.schedule.operator, self.salt(), self.chain,
			self.exit_delay, self.asset, self.value)
	}

	/// The leaf's hash-locked entry, as a tree's lowest node would pay it.
	pub fn entry(&self) -> EntryPolicy {
		EntryPolicy {
			unlock_hash: self.unlock_hash, asset: self.asset, value: self.value, leaf_program: self.leaf().program(),
			sweep: self.schedule.sweep_path(true, self.burn),
		}
	}

	/// The entry's value: the leaf's value and the entry's reserve.
	pub fn entry_value(&self) -> Result<u64, AccumulatorError> {
		self.value.checked_add(self.entry_reserve).filter(|v| *v <= MAX_VALUE).ok_or(AccumulatorError::Weight)
	}

	/// The slot's exit: its record, rebuilt from the leaf, and its path.
	pub fn exit(&self) -> Result<Exit, AccumulatorError> {
		self.check()?;
		let record = Slot {
			owner: self.owner, script_hash: sha256(self.entry().script_pubkey().as_bytes()), value: self.entry_value()?,
			reserve: self.exit_reserve,
		};
		Ok(Exit { slot: self.slot, record, path: self.path.clone() })
	}

	/// The batch the record names: the state the round creates (every bit
	/// clear) and what the batch output holds, the root's weight.
	pub fn batch(&self) -> Result<(AccumulatorPolicy, u64), AccumulatorError> {
		let (root, total) = self.exit()?.root().ok_or(AccumulatorError::Weight)?;
		if total > MAX_VALUE {
			return Err(AccumulatorError::Weight);
		}
		let policy = AccumulatorPolicy {
			root, operator: self.schedule.operator, bitmap: Bitmap::default(), sweep: self.schedule.sweep_path(false, self.burn),
		};
		Ok((policy, total))
	}

	/// The output the round pays.
	pub fn batch_output(&self) -> Result<ExplicitOutput, AccumulatorError> {
		let (policy, total) = self.batch()?;
		Ok(ExplicitOutput::new(self.asset, total, policy.script_pubkey()))
	}

	/// The leaf's id: the tagged hash of the batch output's program, the
	/// slot's two bytes and the leaf's program.
	pub fn leaf_id(&self) -> Result<LeafId, AccumulatorError> {
		let (policy, _) = self.batch()?;
		Ok(LeafId::compute(&policy.program(), &self.slot.to_be_bytes(), &self.leaf().program()))
	}

	/// Refuses the record outside `policy`: chain, operator, notice, first
	/// expiry and exit delay as for a tree leaf, and the reserves of the
	/// slot's exit and of the entry below the policy's floor.
	pub fn check_policy(&self, policy: &WalletPolicy) -> Result<(), AccumulatorError> {
		policy.check_terms(self.chain, &self.schedule, self.exit_delay)?;
		let (exit_min, entry_min) = match policy.min_reserve {
			ReserveFloor::Atoms(min) => (min, min),
			ReserveFloor::FeeRate { floor_per_kvb, multiple } => {
				let (state, _) = self.batch()?;
				let entry = self.entry();
				let tap = entry.taproot();
				let w = tap.witness(&entry.unlock_script(), vec![vec![0; 32]]);
				let leaf_out = ExplicitOutput::new(self.asset, self.value, self.leaf().script_pubkey()).txout();
				(exit_fee_rate_reserve(&state, self.asset, tap.script_pubkey().len(), floor_per_kvb, multiple),
					fee_rate_reserve(floor_per_kvb, multiple, w, vec![leaf_out], self.asset))
			},
		};
		if self.exit_reserve < exit_min {
			return Err(AccumulatorError::ExitReserve { reserve: self.exit_reserve, min: exit_min });
		}
		if self.entry_reserve < entry_min {
			return Err(RecordError::EntryReserve { reserve: self.entry_reserve, min: entry_min }.into());
		}
		Ok(())
	}

	/// The check a wallet runs before it accepts a leaf of its own in an
	/// accumulator batch: the record is for `owner` and the nonce it picked,
	/// within its `policy`, and the round pays exactly one output equal to the
	/// batch output the record rebuilds (asset, the root's weight, and the
	/// script with this program, the operator's key and every bit clear),
	/// with the five client checks on the token and its clock and the
	/// burn-only rule for a reissuing round. Whether the round is final is for
	/// the caller to establish.
	pub fn validate(&self, round: &Transaction, policy: &WalletPolicy, owner: &XOnlyPublicKey, owner_nonce: &[u8; 32])
		-> Result<ValidAccumulatorLeaf, AccumulatorError>
	{
		if self.owner != *owner {
			return Err(RecordError::NotOwner.into());
		}
		if self.owner_nonce != *owner_nonce {
			return Err(RecordError::OwnerNonce.into());
		}
		self.validate_round(round, policy)
	}

	/// [`AccumulatorRecord::validate`] without the owner's key and nonce, for
	/// a leaf the wallet does not own.
	pub fn validate_round(&self, round: &Transaction, policy: &WalletPolicy) -> Result<ValidAccumulatorLeaf, AccumulatorError> {
		self.check_policy(policy)?;
		let exit = self.exit()?;
		let (state, total) = self.batch()?;
		let out = ExplicitOutput::new(self.asset, total, state.script_pubkey());
		let found: Vec<usize> = round.output.iter().enumerate()
			.filter(|(_, o)| ExplicitOutput::from_txout(o).as_ref() == Some(&out))
			.map(|(i, _)| i)
			.collect();
		let batch_vout = match found[..] {
			[] => return Err(RecordError::BatchOutputMissing.into()),
			[i] => i as u32,
			_ => return Err(RecordError::BatchOutputRepeated(found.len()).into()),
		};
		let entry = self.entry();
		// A batch without a sweep has no token or clock to check, and no
		// path that takes a coin, so a reissuance of its asset gives the
		// operator nothing to take back by script.
		if let (Some(batch_sweep), Some(entry_sweep)) = (state.sweep, entry.sweep) {
			check_round(round, &self.schedule, &batch_sweep, &[entry_sweep]).map_err(RecordError::from)?;
			check_reissue(round, self.asset, &batch_sweep, &[entry_sweep]).map_err(RecordError::from)?;
		}
		Ok(ValidAccumulatorLeaf {
			leaf_id: self.leaf_id()?, round_txid: round.txid(), batch_vout, policy: state, total, exit,
			leaf: self.leaf(), entry, entry_value: self.entry_value()?,
		})
	}
}

/// The format version of [`AccumulatorRecord`]'s binary form for a batch
/// with a sweep.
pub const ACCUMULATOR_RECORD_VERSION: u8 = 1;
/// The format version of a batch without a sweep. Leaf records and
/// accumulator records share one space of format versions (a leaf record is
/// 2 or 3), so a reader that holds either tells them apart by the first byte.
pub const ACCUMULATOR_RECORD_VERSION_NO_SWEEP: u8 = 4;

impl AccumulatorRecord {
	/// The binary form; see the [module documentation](self). Refuses a
	/// record that [`AccumulatorRecord::check`] refuses.
	pub fn to_bytes(&self) -> Result<Vec<u8>, AccumulatorError> {
		self.check()?;
		let mut w = Vec::with_capacity(320 + 40 * DEPTH);
		let expires = self.schedule.expires();
		let version = if expires { ACCUMULATOR_RECORD_VERSION } else { ACCUMULATOR_RECORD_VERSION_NO_SWEEP };
		w.extend([version, self.template.id(), self.template.version()]);
		w.extend(self.owner.serialize());
		w.extend(self.owner_nonce);
		w.extend(self.operator_nonce);
		w.extend(self.exit_delay.units().to_le_bytes());
		if let Some(t) = &self.htlc {
			t.encode_to(&mut w);
		}
		if let Some(o) = &self.order {
			o.encode_to(&mut w);
		}
		if let Some(l) = &self.landing {
			w.extend(l.program);
			w.extend(l.allowance.to_le_bytes());
		}
		w.extend(asset_bytes(self.asset));
		w.extend(self.value.to_le_bytes());
		w.extend(self.unlock_hash);
		w.extend(self.entry_reserve.to_le_bytes());
		w.extend(self.chain.genesis_bytes());
		w.extend(self.schedule.operator.serialize());
		if expires {
			w.extend(asset_bytes(self.schedule.token));
			w.extend(self.schedule.notice.units().to_le_bytes());
			w.push(self.burn as u8);
			w.push(self.schedule.expiries().len() as u8);
			for e in self.schedule.expiries() {
				w.extend(e.to_consensus_u32().to_le_bytes());
			}
		} else {
			// No token, notice, burn or expiry; the flags are all zero.
			w.push(0);
		}
		w.extend(self.slot.to_le_bytes());
		w.extend(self.exit_reserve.to_le_bytes());
		for (h, weight) in &self.path {
			w.extend(h);
			w.extend(weight.to_le_bytes());
		}
		Ok(w)
	}

	/// Reads the binary form, which must hold exactly one record.
	pub fn from_bytes(data: &[u8]) -> Result<AccumulatorRecord, AccumulatorError> {
		let mut r = Reader::new(data);
		let version = r.u8().map_err(RecordError::from)?;
		if version != ACCUMULATOR_RECORD_VERSION && version != ACCUMULATOR_RECORD_VERSION_NO_SWEEP {
			return Err(RecordError::Version(version as u64).into());
		}
		let rec = Self::read_fields(&mut r, version).map_err(AccumulatorError::from)?;
		if r.remaining() != 0 {
			return Err(RecordError::from(DecodeError::TrailingBytes(r.remaining())).into());
		}
		rec.check()?;
		Ok(rec)
	}

	fn read_fields(r: &mut Reader, version: u8) -> Result<AccumulatorRecord, RecordError> {
		let template = Template::from_id(r.u8()?, r.u8()?)?;
		let owner = r.key()?;
		let owner_nonce = r.array32()?;
		let operator_nonce = r.array32()?;
		let exit_delay = r.relative_time()?;
		let htlc = match template {
			Template::Htlc1 => Some(HtlcTerms::decode_from(r)?),
			_ => None,
		};
		let order_bytes = match crate::order::SeqdexVersion::of(template) {
			Some(v) => Some((r.bytes(ORDER_TERMS_BYTES)?, v)),
			None => None,
		};
		let landing = match template {
			Template::Landing1 => {
				let mut program = [0u8; crate::landing::PROGRAM_BYTES];
				program.copy_from_slice(r.bytes(crate::landing::PROGRAM_BYTES)?);
				Some(Landing { program, allowance: r.u64()? })
			},
			_ => None,
		};
		let asset = r.asset()?;
		let order = match order_bytes {
			Some((b, v)) => Some(OrderLeafTerms::decode_from(&mut Reader::new(b), asset, v)?),
			None => None,
		};
		let value = r.u64()?;
		let unlock_hash = r.array32()?;
		let entry_reserve = r.u64()?;
		let chain = r.chain()?;
		let operator = r.key()?;
		let (schedule, flags) = if version == ACCUMULATOR_RECORD_VERSION_NO_SWEEP {
			let flags = r.u8()?;
			if flags != 0 {
				return Err(DecodeError::Flag(flags).into());
			}
			(ClockSchedule::never(operator), flags)
		} else {
			let token = r.asset()?;
			// The no-sweep token is written as format version 4 alone.
			if token == crate::clock::no_sweep_token() {
				return Err(DecodeError::NoSweepToken.into());
			}
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
			(ClockSchedule::new_unchecked(token, operator, notice, expiries).map_err(RecordError::Schedule)?, flags)
		};
		let slot = r.u16()?;
		let exit_reserve = r.u64()?;
		let mut path = Vec::with_capacity(DEPTH);
		for _ in 0..DEPTH {
			path.push((r.array32()?, r.u64()?));
		}
		Ok(AccumulatorRecord {
			template, owner, owner_nonce, operator_nonce, exit_delay, htlc, order, landing, asset, value, unlock_hash, entry_reserve,
			chain, schedule, burn: flags & 1 != 0, slot, exit_reserve, path,
		})
	}
}

/// Follows a batch from the state its round created through `spends`, the
/// transactions that spent it in order (exits, and releases for a batch
/// without a sweep), each at the input that spent the output before: the
/// state each one leaves and where the rest is, or `None` once one took the
/// last. Refuses a transaction whose witness is not an exit or a release of
/// the state it should spend.
pub fn follow(start: &AccumulatorPolicy, spends: &[(&Transaction, usize)]) -> Result<Option<AccumulatorPolicy>, AccumulatorError> {
	let mut state = *start;
	for (n, (tx, vin)) in spends.iter().enumerate() {
		let seen = tx.input.get(*vin).and_then(|i| read_spend(&i.witness.script_witness))
			.ok_or_else(|| AccumulatorError::Rule(format!("transaction {} is not an exit or a release", n)))?;
		if seen.root() != state.root || seen.operator() != state.operator.serialize() || seen.bitmap() != state.bitmap {
			return Err(AccumulatorError::Rule(format!("spend {} spent another state than the one before it left", n)));
		}
		if seen.last() {
			return Ok(None);
		}
		state = state.after_all(&seen.slots());
	}
	Ok(Some(state))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_choice_breaks_even_at_78_exits_of_1024() {
		assert!(prefer_accumulator(1024, 4, 1.0, false));
		assert!(prefer_accumulator(1024, 4, 77.0, false));
		assert!(!prefer_accumulator(1024, 4, 78.0, false));
		assert!(prefer_accumulator(256, 4, 19.0, false));
		assert!(!prefer_accumulator(256, 4, 20.0, false));
		assert!(!prefer_accumulator(1024, 4, 1024.0, false));
		// A batch whose tree is one node: the tree's one unroll is smaller.
		assert!(!prefer_accumulator(4, 4, 1.0, false));
		// Two levels: one exit through the tree costs two nodes.
		assert!(prefer_accumulator(16, 4, 1.0, false));
		assert!(!prefer_accumulator(1025, 4, 1.0, false));
		assert!(!prefer_accumulator(1, 4, 1.0, false));
	}

	#[test]
	fn without_a_sweep_the_choice_breaks_even_at_62_exits_of_1024() {
		// An accumulator-2 exit is 1,072 vB against accumulator-1's 979.
		assert!(prefer_accumulator(1024, 4, 1.0, true));
		assert!(prefer_accumulator(1024, 4, 61.0, true));
		assert!(!prefer_accumulator(1024, 4, 62.0, true));
		assert!(prefer_accumulator(256, 4, 15.0, true));
		assert!(!prefer_accumulator(256, 4, 16.0, true));
		assert!(prefer_accumulator(64, 4, 3.0, true));
		assert!(!prefer_accumulator(64, 4, 4.0, true));
		assert!(prefer_accumulator(64, 4, 4.0, false));
		assert!(prefer_accumulator(16, 4, 1.0, true));
		assert!(!prefer_accumulator(4, 4, 1.0, true));
		// Between the two break-evens the kinds of batch choose differently.
		let (a1, t) = exit_costs(1024, 4, 70.0, false);
		let (a2, t2) = exit_costs(1024, 4, 70.0, true);
		assert_eq!(t, t2);
		assert!(a1 < t && t < a2, "{} < {} < {}", a1, t, a2);
	}

	#[test]
	fn bitmap_bits_are_msb_first_by_slot() {
		let b = Bitmap::default().with(0).with(65).with(1023);
		let bytes = b.to_bytes();
		assert_eq!(bytes[0], 0x80);
		assert_eq!(bytes[8], 0x40);
		assert_eq!(bytes[127], 0x01);
		assert!(b.is_left(0) && b.is_left(65) && b.is_left(1023) && !b.is_left(1) && b.is_left(1024));
		assert_eq!(Bitmap::from_bytes(&bytes), Some(b));
		assert_eq!(b.count(), 3);
	}
}
