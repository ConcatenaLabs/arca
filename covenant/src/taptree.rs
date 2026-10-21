//! Taproot outputs with no key path.
//!
//! Every Arca output takes the BIP341 nothing-up-my-sleeve point as its
//! internal key, so it can only be spent by one of its script leaves. Leaves
//! are tapscript (`0xc4`) and the tree hashes with the Elements tags.

use std::sync::OnceLock;

use elements::hashes::Hash;
use elements::script::Builder;
use elements::secp256k1_zkp::{All, Secp256k1, XOnlyPublicKey};
use elements::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use elements::Script;

/// The BIP341 point with no known discrete logarithm.
pub const NUMS: [u8; 32] = [
	0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
	0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

pub(crate) fn secp() -> &'static Secp256k1<All> {
	static SECP: OnceLock<Secp256k1<All>> = OnceLock::new();
	SECP.get_or_init(Secp256k1::new)
}

/// The NUMS point as a key.
pub fn nums() -> XOnlyPublicKey {
	XOnlyPublicKey::from_slice(&NUMS).expect("NUMS is a valid x coordinate")
}

/// A node of a script tree: a tapscript leaf (`0xc4`), a Simplicity leaf
/// (`0xbe`, named by its commitment root), or a hidden node, which no path
/// spends (a data leaf a program reads through its control block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapNode {
	Tapscript(Script),
	Simplicity([u8; 32]),
	Hidden([u8; 32]),
}

/// A taproot output with the NUMS internal key and the given script leaves.
#[derive(Debug, Clone)]
pub struct TapOutput {
	info: TaprootSpendInfo,
	leaves: Vec<(u8, Script)>,
}

impl TapOutput {
	/// The output for `leaves`, each with its depth in the tree, listed in
	/// depth-first order (the order a BIP341 tree is written left to right).
	pub fn new(leaves: Vec<(u8, Script)>) -> TapOutput {
		let mut b = TaprootBuilder::new();
		for (depth, script) in &leaves {
			b = b.add_leaf_with_ver(*depth as usize, script.clone(), LeafVersion::default())
				.expect("the policies only build complete trees");
		}
		let info = b.finalize(secp(), nums()).expect("the policies only build complete trees");
		TapOutput { info, leaves }
	}

	/// The output for a tree that may hold Simplicity leaves and hidden nodes
	/// beside its tapscript leaves, each with its depth, in depth-first order.
	/// [`TapOutput::leaves`] and [`TapOutput::witness`] see the tapscript
	/// leaves alone.
	pub fn with_nodes(nodes: Vec<(u8, TapNode)>) -> TapOutput {
		let mut b = TaprootBuilder::new();
		let mut leaves = vec![];
		for (depth, node) in nodes {
			b = match node {
				TapNode::Tapscript(script) => {
					leaves.push((depth, script.clone()));
					b.add_leaf_with_ver(depth as usize, script, LeafVersion::default())
				},
				TapNode::Simplicity(cmr) => b.add_leaf_with_ver(depth as usize, Script::from(cmr.to_vec()),
					LeafVersion::from_u8(0xbe).expect("0xbe is a leaf version")),
				TapNode::Hidden(hash) => b.add_hidden(depth as usize, elements::hashes::sha256::Hash::from_byte_array(hash)),
			}.expect("the policies only build complete trees");
		}
		let info = b.finalize(secp(), nums()).expect("the policies only build complete trees");
		TapOutput { info, leaves }
	}

	/// The leaves, with their depths, in the order given.
	pub fn leaves(&self) -> &[(u8, Script)] {
		&self.leaves
	}

	/// `OP_1 <output key>`.
	pub fn script_pubkey(&self) -> Script {
		Builder::new().push_int(1).push_slice(&self.program()).into_script()
	}

	/// The witness program: the tweaked output key.
	pub fn program(&self) -> [u8; 32] {
		self.info.output_key().into_inner().serialize()
	}

	pub fn output_key(&self) -> XOnlyPublicKey {
		self.info.output_key().into_inner()
	}

	/// The root of the script tree.
	pub fn merkle_root(&self) -> Option<[u8; 32]> {
		self.info.merkle_root().map(|h| h.to_byte_array())
	}

	/// The control block that proves `script` is a leaf of this output.
	pub fn control_block(&self, script: &Script) -> Option<Vec<u8>> {
		self.info.control_block(&(script.clone(), LeafVersion::default())).map(|c| c.serialize())
	}

	/// A full script-path witness: `below` (bottom of the stack first), then
	/// the script and its control block. Panics if `script` is not a leaf of
	/// this output.
	pub fn witness(&self, script: &Script, below: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
		let cb = self.control_block(script).expect("the script is a leaf of this output");
		let mut w = below;
		w.push(script.to_bytes());
		w.push(cb);
		w
	}
}

/// The tapleaf hash of a tapscript leaf, which its signature hash commits to.
pub fn leaf_hash(script: &Script) -> TapLeafHash {
	TapLeafHash::from_script(script, LeafVersion::default())
}
