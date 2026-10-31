//! The accumulator batch: a batch output of up to 1,024 leaves from which one
//! owner leaves in one transaction (`arca/accumulator-1`).
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
//! # The record's binary form, version 1
//!
//! [`AccumulatorRecord`] is a leaf record whose path is a slot. Integers are
//! little-endian; asset ids, the token and the genesis hash are in internal
//! byte order. Up to the clock it is a tree leaf record's layout
//! ([`crate::record`]):
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
//! Every field has one encoding, so a record has one binary form. A reader
//! refuses another version, an unknown template, trailing bytes and a record
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
use crate::htlc::HtlcTerms;
use crate::landing::Landing;
use crate::leaf::{leaf_salt, LeafPolicy};
use crate::message::Chain;
use crate::order::{control_block, tapbranch, tapdata, tapleaf, OrderLeafTerms};
use crate::record::{check_template, leaf_policy, LeafId, RecordError, ReserveFloor, Template, WalletPolicy, MAX_VALUE, ORDER_TERMS_BYTES};
use crate::script::{asset_bytes, sha256, ExplicitOutput};
use crate::sign::verify_digest;
use crate::spend::{assemble, FeeSource, SpendError, UnrollTx, FEE_COIN_SEQUENCE};
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

const SIMPLICITY: u8 = 0xbe;
const TAPSCRIPT: u8 = 0xc4;

fn unhex(s: &str) -> Vec<u8> {
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("a hex constant")).collect()
}

/// `arca/accumulator-1`'s commitment root.
pub fn accumulator_cmr() -> [u8; 32] {
	unhex(programs::ACCUMULATOR_CMR).try_into().expect("a 32-byte constant")
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
	#[error("the exit breaks the program's rule: {0}")]
	Rule(String),
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
	/// The batch output's sweep: no notice of its own.
	pub sweep: Sweep,
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

	/// The tapleaf hash of `SWEEP`.
	pub fn sweep_leaf(&self) -> [u8; 32] {
		tapleaf(TAPSCRIPT, self.sweep.script().as_bytes())
	}

	/// The root of the script tree, `TapBranch(TapBranch(X, D), SWEEP)`.
	pub fn tree_root(&self) -> [u8; 32] {
		tapbranch(tapbranch(tapleaf(SIMPLICITY, &accumulator_cmr()), self.data_leaf()), self.sweep_leaf())
	}

	/// The output's taproot, through which `SWEEP` is spent.
	pub fn taproot(&self) -> TapOutput {
		TapOutput::with_nodes(vec![
			(2, TapNode::Simplicity(accumulator_cmr())),
			(2, TapNode::Hidden(self.data_leaf())),
			(1, TapNode::Tapscript(self.sweep.script())),
		])
	}

	pub fn script_pubkey(&self) -> Script {
		self.taproot().script_pubkey()
	}

	/// The witness program: the tweaked output key.
	pub fn program(&self) -> [u8; 32] {
		self.taproot().program()
	}

	/// The control block of the program's leaf: its parity, the NUMS key,
	/// `D`, then the hash of `SWEEP`.
	pub fn control_block(&self) -> Vec<u8> {
		control_block(SIMPLICITY, self.tree_root(), &[self.data_leaf(), self.sweep_leaf()])
	}

	/// The state once slot `j` has left.
	pub fn after(&self, j: u16) -> AccumulatorPolicy {
		AccumulatorPolicy { bitmap: self.bitmap.with(j), ..*self }
	}

	/// This output, held at `outpoint`, as a sweep takes it.
	pub fn sweepable(&self, outpoint: OutPoint, (asset, value): (AssetId, u64)) -> Sweepable {
		Sweepable::new(outpoint, (asset, value), self.taproot(), self.sweep)
	}

	/// The exit's witness: the state, the slot's record and path, the time,
	/// the key's flag and the signature, then the pruned program for an exit
	/// that leaves a rest or for the last (`last`), the commitment root and the
	/// control block.
	pub fn exit_witness(&self, exit: &Exit, auth: &ExitAuth, last: bool) -> Vec<Vec<u8>> {
		let mut bytes = self.data_bytes();
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
		let mut bits: Vec<bool> = bits_of(&bytes);
		bits.push(auth.by_operator);
		bits.extend(bits_of(auth.signature.as_ref()));
		let program = if last { programs::ACCUMULATOR_EXIT_LAST } else { programs::ACCUMULATOR_EXIT };
		vec![pack_bits(&bits), unhex(program), accumulator_cmr().to_vec(), self.control_block()]
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

/// Reads an exit from an input's witness: `None` when the input does not spend
/// an accumulator batch by its program. An annex (BIP341), which the
/// authorisation does not cover and anyone broadcasting the exit can add, is
/// set aside first ([`crate::witness::without_annex`]): the exit is the same.
pub fn read_exit(witness: &[Vec<u8>]) -> Option<SeenExit> {
	let [w, program, cmr, _cb] = crate::witness::without_annex(witness) else { return None };
	if cmr[..] != accumulator_cmr()[..] || w.len() != WITNESS_BYTES {
		return None;
	}
	let last = if program[..] == unhex(programs::ACCUMULATOR_EXIT_LAST)[..] {
		true
	} else if program[..] == unhex(programs::ACCUMULATOR_EXIT)[..] {
		false
	} else {
		return None;
	};
	let root: [u8; 32] = w[0..32].try_into().ok()?;
	let operator: [u8; 32] = w[32..64].try_into().ok()?;
	let bitmap = Bitmap::from_bytes(&w[64..192])?;
	let slot = u16::from_be_bytes([w[192], w[193]]);
	let t_at = 194 + 32 + 32 + 8 + 8 + DEPTH * 40;
	let time = u32::from_be_bytes(w[t_at..t_at + 4].try_into().ok()?);
	let by_operator = w[t_at + 4] & 0x80 != 0;
	Some(SeenExit { root, operator, bitmap, slot, by_operator, time, last })
}

/// The size of an exit whose fee comes from the slot's reserve, in vbytes, as
/// measured on regtest (`covenant/tests/accumulator.rs`): the same at every
/// slot and in every batch.
pub const EXIT_VBYTES: u64 = 979;
/// The size of a gated node's unroll in a tree, in vbytes: the mean of the
/// five levels of a 1,024-leaf radix-4 tree measured beside it (615, 592,
/// 571, 549 and 527).
pub const NODE_VBYTES: u64 = 571;

/// What `exits` exits from a batch of `n` leaves cost on the chain, in
/// vbytes, as an accumulator and as a tree at `radix`: one exit each, against
/// the node transactions they unroll. The leaves leaving are taken as
/// scattered at random, so a level of `N` nodes has `N (1 − (1 − 1/N)^exits)`
/// of them unrolled. Each leaf's entry and its own exit cost the same in both
/// and are left out.
pub fn exit_costs(n: usize, radix: usize, exits: f64) -> (f64, f64) {
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
	(exits * EXIT_VBYTES as f64, tree)
}

/// Whether the operator should build a batch of `n` leaves as an accumulator
/// rather than a tree at `radix`, when it expects `exits` of them to leave on
/// the chain: when it fits (two to 1,024 leaves) and costs less to leave. At
/// 1,024 leaves and radix 4 that is up to 77 exits (19 of 256, 4 of 64, one of
/// 16); past that, or on a run, the tree wins, because its exits share nodes
/// and run in parallel.
pub fn prefer_accumulator(n: usize, radix: usize, exits: f64) -> bool {
	if !(2..=SLOTS).contains(&n) {
		return false;
	}
	let (acc, tree) = exit_costs(n, radix, exits.max(1.0));
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
	let w = vec![vec![0; 743], unhex(programs::ACCUMULATOR_EXIT), accumulator_cmr().to_vec(), state.control_block()];
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
		// A channel-1 leaf's terms are not in an accumulator record: a
		// channel goes in a tree.
		if let Some(i) = leaves.iter().position(|l| l.template == Template::Channel1 || l.channel.is_some()) {
			return Err(TreeError::Template { leaf: i });
		}
		let tree_leaves = build_leaves(&params.as_tree(), leaves)?;
		let operator = params.schedule.operator;
		let sweep = params.schedule.sweep(false, params.burn);
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

	/// The script the round pays the token's atom to: the first clock.
	pub fn clock0_script_pubkey(&self) -> Script {
		self.params.schedule.clock0_script_pubkey()
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
	/// bounds, the slot and the path's length.
	pub fn check(&self) -> Result<(), AccumulatorError> {
		check_template(self.template, &self.htlc, &self.order, &self.landing, self.asset, self.value, &self.owner,
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
		leaf_policy(self.template, (&self.htlc, &self.order, &self.landing), self.owner, self.schedule.operator, self.salt(), self.chain,
			self.exit_delay, self.asset, self.value)
	}

	/// The leaf's hash-locked entry, as a tree's lowest node would pay it.
	pub fn entry(&self) -> EntryPolicy {
		EntryPolicy {
			unlock_hash: self.unlock_hash, asset: self.asset, value: self.value, leaf_program: self.leaf().program(),
			sweep: self.schedule.sweep(true, self.burn),
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
			root, operator: self.schedule.operator, bitmap: Bitmap::default(), sweep: self.schedule.sweep(false, self.burn),
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
		check_round(round, &self.schedule, &state.sweep, &[entry.sweep]).map_err(RecordError::from)?;
		check_reissue(round, self.asset, &state.sweep, &[entry.sweep]).map_err(RecordError::from)?;
		Ok(ValidAccumulatorLeaf {
			leaf_id: self.leaf_id()?, round_txid: round.txid(), batch_vout, policy: state, total, exit,
			leaf: self.leaf(), entry, entry_value: self.entry_value()?,
		})
	}
}

/// The format version of [`AccumulatorRecord`]'s binary form.
pub const ACCUMULATOR_RECORD_VERSION: u8 = 1;

impl AccumulatorRecord {
	/// The binary form; see the [module documentation](self). Refuses a
	/// record that [`AccumulatorRecord::check`] refuses.
	pub fn to_bytes(&self) -> Result<Vec<u8>, AccumulatorError> {
		self.check()?;
		let mut w = Vec::with_capacity(320 + 40 * DEPTH);
		w.extend([ACCUMULATOR_RECORD_VERSION, self.template.id(), self.template.version()]);
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
		w.extend(asset_bytes(self.schedule.token));
		w.extend(self.schedule.notice.units().to_le_bytes());
		w.push(self.burn as u8);
		w.push(self.schedule.expiries().len() as u8);
		for e in self.schedule.expiries() {
			w.extend(e.to_consensus_u32().to_le_bytes());
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
		if version != ACCUMULATOR_RECORD_VERSION {
			return Err(RecordError::Version(version as u64).into());
		}
		let rec = Self::read_fields(&mut r).map_err(AccumulatorError::from)?;
		if r.remaining() != 0 {
			return Err(RecordError::from(DecodeError::TrailingBytes(r.remaining())).into());
		}
		rec.check()?;
		Ok(rec)
	}

	fn read_fields(r: &mut Reader) -> Result<AccumulatorRecord, RecordError> {
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

/// Follows a batch from the state its round created through `exits`, the
/// transactions that spent it in order, each at the input that spent the
/// output before: the state each one leaves and where the rest is, or
/// `None` once one took the last. Refuses a transaction whose witness is not
/// an exit of the state it should spend.
pub fn follow(start: &AccumulatorPolicy, exits: &[(&Transaction, usize)]) -> Result<Option<AccumulatorPolicy>, AccumulatorError> {
	let mut state = *start;
	for (n, (tx, vin)) in exits.iter().enumerate() {
		let seen = tx.input.get(*vin).and_then(|i| read_exit(&i.witness.script_witness))
			.ok_or_else(|| AccumulatorError::Rule(format!("transaction {} is not an exit", n)))?;
		if seen.root != state.root || seen.operator != state.operator.serialize() || seen.bitmap != state.bitmap {
			return Err(AccumulatorError::Rule(format!("exit {} spent another state than the one before it left", n)));
		}
		if seen.last {
			return Ok(None);
		}
		state = state.after(seen.slot);
	}
	Ok(Some(state))
}


#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_choice_breaks_even_at_78_exits_of_1024() {
		assert!(prefer_accumulator(1024, 4, 1.0));
		assert!(prefer_accumulator(1024, 4, 77.0));
		assert!(!prefer_accumulator(1024, 4, 78.0));
		assert!(prefer_accumulator(256, 4, 19.0));
		assert!(!prefer_accumulator(256, 4, 20.0));
		assert!(!prefer_accumulator(1024, 4, 1024.0));
		// A batch whose tree is one node: the tree's one unroll is smaller.
		assert!(!prefer_accumulator(4, 4, 1.0));
		// Two levels: one exit through the tree costs two nodes.
		assert!(prefer_accumulator(16, 4, 1.0));
		assert!(!prefer_accumulator(1025, 4, 1.0));
		assert!(!prefer_accumulator(1, 4, 1.0));
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
