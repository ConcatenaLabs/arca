//! Reading witnesses found on-chain.
//!
//! A watcher learns from the chain what others published: the preimage an
//! operator revealed when it claimed a forfeit, which unlocks the owner's
//! entry; the unroll authorisation a third party used. These parsers take a
//! witness as the node serialised it, which anyone can make, so they refuse
//! anything malformed instead of trusting its shape.

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::taproot::ControlBlock;
use elements::Script;

use crate::gate::PathStep;
use crate::script::{scriptnum, sha256};
use crate::time::MedianTime;

/// The annex tag (BIP341).
const ANNEX_TAG: u8 = 0x50;

/// Why a witness is not the expected shape.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WitnessError {
	#[error("the witness is not a script-path spend")]
	NotScriptPath,
	#[error("the control block is malformed")]
	ControlBlock,
	#[error("the witness has {0} items where an unroll has 2 per level plus 3")]
	ItemCount(usize),
	#[error("item {0} is not a 64-byte signature")]
	Signature(usize),
	#[error("the time is not a minimally encoded median time")]
	Time,
	#[error("a direction item is neither empty nor 0x01")]
	Direction,
	#[error("a sibling is not 32 bytes")]
	Sibling,
	#[error("the key is not a 32-byte x-only key")]
	Key,
}

/// A script-path spend split into its parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptPath<'a> {
	/// The items below the script, bottom of the stack first.
	pub items: &'a [Vec<u8>],
	pub script: Script,
	pub control_block: ControlBlock,
	pub annex: Option<&'a [u8]>,
}

impl<'a> ScriptPath<'a> {
	/// Splits a witness stack: an optional annex last, then the control block,
	/// then the script.
	pub fn parse(stack: &'a [Vec<u8>]) -> Result<ScriptPath<'a>, WitnessError> {
		let mut end = stack.len();
		let mut annex = None;
		if end >= 2 && stack[end - 1].first() == Some(&ANNEX_TAG) {
			annex = Some(&stack[end - 1][..]);
			end -= 1;
		}
		if end < 2 {
			return Err(WitnessError::NotScriptPath);
		}
		let control_block = ControlBlock::from_slice(&stack[end - 1]).map_err(|_| WitnessError::ControlBlock)?;
		let script = Script::from(stack[end - 2].clone());
		Ok(ScriptPath { items: &stack[..end - 2], script, control_block, annex })
	}
}

/// The first 32-byte witness item whose SHA256 is `hash`: the preimage a
/// forfeit claim, an entry unlock or an HTLC claim revealed. Every item is
/// scanned, so an annex or a reordered witness does not hide it.
pub fn find_preimage(stack: &[Vec<u8>], hash: &[u8; 32]) -> Option<[u8; 32]> {
	stack.iter().filter(|i| i.len() == 32).find(|i| &sha256(i) == hash).map(|i| i[..].try_into().unwrap())
}

/// An unroll authorisation as a spend of a node's UNROLL leaf carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnrollWitness {
	pub signature: Signature,
	pub time: MedianTime,
	/// The member's path, bottom level first.
	pub path: Vec<PathStep>,
	pub key: XOnlyPublicKey,
}

impl UnrollWitness {
	/// Reads `<sig> <t> { <sibling> <dir> } <key>` from the items below the
	/// script of an UNROLL spend.
	pub fn parse(items: &[Vec<u8>]) -> Result<UnrollWitness, WitnessError> {
		let n = items.len();
		if n < 3 || !(n - 3).is_multiple_of(2) {
			return Err(WitnessError::ItemCount(n));
		}
		let signature = Signature::from_slice(&items[0]).map_err(|_| WitnessError::Signature(0))?;
		let t = parse_time(&items[1]).ok_or(WitnessError::Time)?;
		let levels = (n - 3) / 2;
		let mut path = Vec::with_capacity(levels);
		// Items 2.. hold the top level first; the path is bottom level first.
		for l in (0..levels).rev() {
			let sibling: [u8; 32] = items[2 + 2 * l][..].try_into().map_err(|_| WitnessError::Sibling)?;
			let is_left = match &items[3 + 2 * l][..] {
				[] => false,
				[0x01] => true,
				_ => return Err(WitnessError::Direction),
			};
			path.push(PathStep { sibling, is_left });
		}
		let key = items[n - 1].as_slice();
		if key.len() != 32 {
			return Err(WitnessError::Key);
		}
		let key = XOnlyPublicKey::from_slice(key).map_err(|_| WitnessError::Key)?;
		Ok(UnrollWitness { signature, time: t, path, key })
	}
}

/// A minimally encoded, positive script number that is a median time.
fn parse_time(item: &[u8]) -> Option<MedianTime> {
	if item.is_empty() || item.len() > 5 {
		return None;
	}
	let mut n: u64 = 0;
	for (i, b) in item.iter().enumerate() {
		n |= u64::from(*b) << (8 * i);
	}
	if item[item.len() - 1] & 0x80 != 0 {
		return None; // negative
	}
	let t = u32::try_from(n).ok()?;
	if scriptnum(t as i64) != item {
		return None; // not minimal
	}
	MedianTime::from_consensus(t).ok()
}
