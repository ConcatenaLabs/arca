//! Reading witnesses found on-chain.
//!
//! A watcher learns from the chain what others published: the preimage an
//! operator revealed when it claimed a forfeit, which unlocks the owner's
//! entry; the unroll authorisation a third party used. These parsers take a
//! witness as the node serialised it, which anyone can make, so they refuse
//! anything malformed instead of trusting its shape.
//!
//! A taproot spend may end its witness with an annex (BIP341). Consensus
//! accepts it and drops it before the script runs, so a spend with an annex
//! is the same spend as the one without it. Sequentia's relay policy takes
//! an annex on a Simplicity leaf and refuses one elsewhere, which a block
//! producer can still mine; and nothing signs it where a signed message is
//! built by introspection or over a message of its own, so whoever relays or
//! mines such a spend can add one. Every reader of a spend's items therefore
//! reads them through [`without_annex`], which removes the annex by BIP341's
//! rule exactly, and never counts or indexes the raw stack; only
//! [`find_preimage`] scans the raw stack, annex included.

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

/// The annex of a taproot spend's witness, BIP341's rule exactly: when the
/// witness has at least two items and its last item's first byte is `0x50`,
/// that item. An empty last item, or a lone item however it starts, is no
/// annex.
///
/// The rule is taproot's: it is what consensus applies to a spend of a
/// witness version 1 output, which every Arca coin is. A version 0 spend has
/// no annex; its last item is the witness script or the key, and neither can
/// begin with `0x50` and be valid (the script would start with
/// `OP_RESERVED`, the key would not be one), so reading a spend found on the
/// chain through this function gives the same items either way.
pub fn annex(stack: &[Vec<u8>]) -> Option<&[u8]> {
	match stack {
		[_, .., last] if last.first() == Some(&ANNEX_TAG) => Some(&last[..]),
		_ => None,
	}
}

/// The items of a taproot spend's witness without its annex ([`annex`]): the
/// key path's signature, or the items below the script, the script and the
/// control block. This is the witness the script sees, and the one a reader
/// counts and indexes.
pub fn without_annex(stack: &[Vec<u8>]) -> &[Vec<u8>] {
	match annex(stack) {
		Some(_) => &stack[..stack.len() - 1],
		None => stack,
	}
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
		let annex = annex(stack);
		let end = without_annex(stack).len();
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
/// scanned, the annex too, so neither an annex nor a reordered witness hides
/// it: whatever item opens the hash, the preimage is public once mined. This
/// is the one reader that takes the raw stack rather than
/// [`without_annex`]'s.
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
		if n < 3 || (n - 3) % 2 != 0 {
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

#[cfg(test)]
mod tests {
	use super::*;

	fn items(v: &[&[u8]]) -> Vec<Vec<u8>> {
		v.iter().map(|i| i.to_vec()).collect()
	}

	#[test]
	fn the_annex_is_bip341s_last_item_and_nothing_else() {
		let sig: &[u8] = &[7; 64];
		let script: &[u8] = &[0x51];
		let cb: &[u8] = &[0xc4; 33];
		// A script path, then the same with an annex: the items are the same.
		let plain = items(&[sig, script, cb]);
		let annexed = items(&[sig, script, cb, &[0x50, 1, 2]]);
		assert_eq!(annex(&plain), None);
		assert_eq!(annex(&annexed), Some(&[0x50, 1, 2][..]));
		assert_eq!(without_annex(&annexed), &plain[..]);
		assert_eq!(without_annex(&plain), &plain[..]);
		// A key path with an annex: two items, the second the annex.
		let key_path = items(&[sig, &[0x50]]);
		assert_eq!(annex(&key_path), Some(&[0x50][..]));
		assert_eq!(without_annex(&key_path), &items(&[sig])[..]);
		// A lone item is never an annex, however it starts.
		let lone = items(&[&[0x50, 9]]);
		assert_eq!(annex(&lone), None);
		assert_eq!(without_annex(&lone), &lone[..]);
		// An empty last item is no annex; nor is one that starts otherwise.
		for last in [&[][..], &[0x51][..], &[0x4f, 0x50][..]] {
			let w = items(&[sig, script, cb, last]);
			assert_eq!(annex(&w), None, "{:?}", last);
			assert_eq!(without_annex(&w), &w[..]);
		}
		// Only the last item: an item before it that starts with 0x50 stays.
		let two = items(&[sig, &[0x50, 3], &[0x50, 4]]);
		assert_eq!(without_annex(&two), &items(&[sig, &[0x50, 3]])[..]);
		assert_eq!(without_annex(&[]), &[] as &[Vec<u8>]);
	}

	#[test]
	fn a_preimage_is_found_in_any_item_the_annex_too() {
		let p = [0x50u8; 32];
		let h = sha256(&p);
		assert_eq!(find_preimage(&items(&[&[1; 64], &p, &[0x51], &[0xc4; 33], &[0x50]]), &h), Some(p));
		assert_eq!(find_preimage(&items(&[&[1; 64], &[0x51], &[0xc4; 33], &p]), &h), Some(p));
		assert_eq!(find_preimage(&items(&[&[1; 64], &[0x51], &[0xc4; 33]]), &h), None);
	}
}
