//! The messages Arca's `OP_CHECKSIGFROMSTACK` paths verify.
//!
//! Each is the SHA256 of a byte string the script assembles itself, so a
//! signer signs an ordinary 32-byte digest:
//!
//! - the rebindable message of the collaborative paths, bound to the coin
//!   being spent and to the chain,
//!   `SHA256(K ‖ asset_in ‖ 0x01 ‖ 0x01 ‖ value_in ‖ m ‖ SHA256(record 0) ‖ … ‖ SHA256(record m-1))`
//!   with `K = SHA256(SHA256("ArcaRbd1" ‖ genesis_hash) ‖ salt)`;
//! - the unroll authorisation, `SHA256("Arca/unroll" ‖ H ‖ t)`;
//! - the release a lowest node's owners sign, `SHA256("Arca/release" ‖ genesis_hash ‖ H)`.
//!
//! The genesis hash is in internal byte order, the reverse of what
//! `getblockhash` prints.

use elements::hashes::Hash;
use elements::{AssetId, BlockHash};

use crate::script::{asset_bytes, sha256, ExplicitOutput};
use crate::time::MedianTime;
use crate::Error;

/// The rebindable message's domain tag.
pub const REBIND_TAG: &[u8; 8] = b"ArcaRbd1";
/// The unroll authorisation's domain tag.
pub const UNROLL_TAG: &[u8; 11] = b"Arca/unroll";
/// The release message's domain tag.
pub const RELEASE_TAG: &[u8; 12] = b"Arca/release";

/// A message an `OP_CHECKSIGFROMSTACK` path verifies: the bytes the script
/// assembles, and their SHA256, which is what is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsfsMessage {
	pub preimage: Vec<u8>,
	pub digest: [u8; 32],
}

impl CsfsMessage {
	fn new(preimage: Vec<u8>) -> CsfsMessage {
		let digest = sha256(&preimage);
		CsfsMessage { preimage, digest }
	}
}

/// The chain a policy is bound to, named by its genesis block hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Chain {
	genesis_hash: BlockHash,
}

impl Chain {
	pub fn new(genesis_hash: BlockHash) -> Chain {
		Chain { genesis_hash }
	}

	pub fn genesis_hash(&self) -> BlockHash {
		self.genesis_hash
	}

	/// The genesis hash in internal byte order.
	pub fn genesis_bytes(&self) -> [u8; 32] {
		self.genesis_hash.to_byte_array()
	}

	/// `SHA256("ArcaRbd1" ‖ genesis_hash)`.
	pub fn tag(&self) -> [u8; 32] {
		let mut b = REBIND_TAG.to_vec();
		b.extend(self.genesis_bytes());
		sha256(&b)
	}

	/// `K = SHA256(tag ‖ salt)`: the one constant a rebindable script pushes.
	/// It binds a signature to this protocol, this chain and this salt.
	pub fn leaf_constant(&self, salt: &[u8; 32]) -> [u8; 32] {
		let mut b = self.tag().to_vec();
		b.extend(salt);
		sha256(&b)
	}

	/// The release a lowest node's owners sign for the node whose children
	/// hash is `children_hash`.
	pub fn release_message(&self, children_hash: &[u8; 32]) -> CsfsMessage {
		let mut b = RELEASE_TAG.to_vec();
		b.extend(self.genesis_bytes());
		b.extend(children_hash);
		CsfsMessage::new(b)
	}
}

/// The rebindable message for a spend of a coin of `asset_in` and `value_in`
/// that commits to `outputs` at indices `0..m`. `k` is the script's constant
/// ([`Chain::leaf_constant`]). The format carries `m` in one byte; the scripts
/// take 1 to 4 outputs ([`crate::leaf::MAX_OUTPUTS`]), `htlc-1` exactly one.
pub fn rebind_message(k: &[u8; 32], asset_in: AssetId, value_in: u64, outputs: &[ExplicitOutput]) -> Result<CsfsMessage, Error> {
	if outputs.is_empty() || outputs.len() > 255 {
		return Err(Error::OutputCount(outputs.len()));
	}
	let mut b = Vec::with_capacity(32 + 42 + 1 + 32 * outputs.len());
	b.extend(k);
	b.extend(asset_bytes(asset_in));
	b.extend([0x01, 0x01]);
	b.extend(value_in.to_le_bytes());
	b.push(outputs.len() as u8);
	for o in outputs {
		b.extend(sha256(&o.record()));
	}
	Ok(CsfsMessage::new(b))
}

/// The unroll authorisation for the node whose children hash is
/// `children_hash`, usable from median time `t`.
pub fn unroll_authorisation(children_hash: &[u8; 32], t: MedianTime) -> CsfsMessage {
	let mut b = UNROLL_TAG.to_vec();
	b.extend(children_hash);
	b.extend(t.script_bytes());
	CsfsMessage::new(b)
}
