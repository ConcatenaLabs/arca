//! Sequentia chain types and a JSON-RPC client for `sequentiad`.
//!
//! Sequentia's encoding differs from upstream Elements in two places: an asset
//! issuance carries a denomination byte, and every block header carries the
//! Bitcoin block it is anchored to. The types come from the `rust-elements`
//! that SWK vendors with its `sequentia` feature, re-exported here as
//! [`elements`], so every crate in this workspace encodes them the same way.
//!
//! On top of those types this crate adds what the protocol code needs and
//! upstream lacks: an amount that always names its asset ([`AssetAmount`]),
//! explicit-output helpers ([`TxOutExt`]), the header's anchor
//! ([`BitcoinAnchor`]), and a node client ([`rpc::Client`]). With the
//! `regtest` feature, [`regtest::Regtest`] runs a throwaway anchored chain for
//! tests.

pub extern crate elements;

pub mod rpc;
#[cfg(feature = "regtest")]
pub mod regtest;

pub use elements::{
	AssetId, AssetIssuance, Block, BlockHash, BlockHeader, OutPoint, Script, Transaction, TxIn,
	TxOut, Txid,
};

use elements::confidential::{Asset, Nonce, Value};
use elements::TxOutWitness;

/// An amount of one asset, in the asset's atoms.
///
/// Sequentia has no privileged asset outside staking, so an amount on its own
/// means nothing: every amount in the protocol travels with its asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AssetAmount {
	pub asset: AssetId,
	pub amount: u64,
}

impl AssetAmount {
	pub fn new(asset: AssetId, amount: u64) -> AssetAmount {
		AssetAmount { asset, amount }
	}
}

/// An output with explicit asset and value, and no nonce: the transparent
/// default on Sequentia.
pub fn explicit_txout(value: AssetAmount, script_pubkey: Script) -> TxOut {
	TxOut {
		asset: Asset::Explicit(value.asset),
		value: Value::Explicit(value.amount),
		nonce: Nonce::Null,
		script_pubkey,
		witness: TxOutWitness::default(),
	}
}

/// A fee output: explicit, with an empty script. A Sequentia transaction pays
/// its fee in exactly one asset, through one such output.
pub fn fee_txout(fee: AssetAmount) -> TxOut {
	TxOut::new_fee(fee.amount, fee.asset)
}

/// Explicit-output accessors for [`TxOut`].
pub trait TxOutExt {
	/// The asset, when it is explicit.
	fn explicit_asset(&self) -> Option<AssetId>;
	/// The value, when it is explicit.
	fn explicit_value(&self) -> Option<u64>;
	/// Asset and value, when both are explicit.
	fn asset_amount(&self) -> Option<AssetAmount> {
		Some(AssetAmount::new(self.explicit_asset()?, self.explicit_value()?))
	}
	/// Whether asset, value and nonce are all explicit or empty, so the
	/// output reveals what it carries.
	fn is_explicit(&self) -> bool;
}

impl TxOutExt for TxOut {
	fn explicit_asset(&self) -> Option<AssetId> {
		self.asset.explicit()
	}

	fn explicit_value(&self) -> Option<u64> {
		self.value.explicit()
	}

	fn is_explicit(&self) -> bool {
		self.asset.is_explicit() && self.value.is_explicit() && self.nonce.is_null()
	}
}

/// The Bitcoin block a Sequentia block is anchored to, committed in its header.
///
/// The block hash is a Bitcoin block hash, held in the type `rust-elements`
/// uses for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BitcoinAnchor {
	pub height: u32,
	pub block_hash: BlockHash,
}

/// Access to the Sequentia-specific fields of a block header.
pub trait BlockHeaderExt {
	/// The header's Bitcoin anchor.
	fn bitcoin_anchor(&self) -> BitcoinAnchor;
}

impl BlockHeaderExt for BlockHeader {
	fn bitcoin_anchor(&self) -> BitcoinAnchor {
		// Under the `sequentia` feature every decoded header carries one.
		let (height, block_hash) = self.bitcoin_anchor
			.expect("a Sequentia block header always carries its Bitcoin anchor");
		BitcoinAnchor { height, block_hash }
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use elements::encode::{deserialize, serialize};
	use elements::hex::FromHex;

	/// Height 2 of an anchored regtest chain (`sequentiad -con_bitcoin_anchor=1`),
	/// anchored to Bitcoin regtest block 10, as the node serialised it.
	/// Decoding and re-encoding give the same bytes, and the hash the node
	/// reported for it.
	#[test]
	fn anchored_header_roundtrip() {
		let hex = "000000a05030bbb8a513d4f480c1d51b7ef8682401d264d5fbddcb34f99207f32fd8a2a0aab0e2451724598471dd4e45f0dca40ca5f4ac62e61957e50925af0859891fcc15f2bf6a020000000a000000a670add9a231fe1aaa24b66a84134eba00b86ac272d7ec049256570e7cac6d06012200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc332604a000000fbee9cea00d8efdc49cfbec328537e0d7032194de6ebf3cf42e5c05bb89a08b100010151";
		let bytes = Vec::<u8>::from_hex(hex).unwrap();
		let header: BlockHeader = deserialize(&bytes).unwrap();
		assert_eq!(serialize(&header), bytes);
		assert_eq!(header.height, 2);
		let anchor = header.bitcoin_anchor();
		assert_eq!(anchor.height, 10);
		assert_eq!(anchor.block_hash.to_string(),
			"066dac7c0e57569204ecd772c26ab800ba4e13846ab624aa1afe31a2d9ad70a6");
		assert_eq!(header.block_hash().to_string(),
			"d52fd45df123c47da71d8ed9ac98fba7c95e92928230d6d941024af852ecd7df");
	}

	#[test]
	fn explicit_outputs() {
		let asset = AssetId::from_slice(&[7; 32]).unwrap();
		let out = explicit_txout(AssetAmount::new(asset, 1000), Script::new());
		assert!(out.is_explicit());
		assert_eq!(out.asset_amount(), Some(AssetAmount::new(asset, 1000)));
		let fee = fee_txout(AssetAmount::new(asset, 5));
		assert!(fee.is_fee());
		assert_eq!(fee.asset_amount(), Some(AssetAmount::new(asset, 5)));
	}
}
