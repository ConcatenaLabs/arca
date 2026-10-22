//! The `vtxo-2` collaborative path: the Simplicity program `arca/collab-2`.
//!
//! A `vtxo-2` leaf, and the checkpoint a `vtxo-2` coin moves into, are
//! spent by owner and operator together through one Simplicity program in
//! place of `vtxo-1`'s tapscript path:
//!
//! ```text
//! leaf:        root = TapBranch( TapBranch(F, D), E )
//! checkpoint:  root = TapBranch( TapBranch(F, D), SWEEP )
//! F      the program arca/collab-2 (one commitment root for every coin)
//! D      the hidden data leaf H_TapData(owner ‖ operator ‖ salt), 96 bytes
//! E      the exit, <delay> OP_CHECKSEQUENCEVERIFY OP_DROP <A> OP_CHECKSIG,
//!        the same script as a vtxo-1 leaf's exit
//! SWEEP  the checkpoint's sweep with notice, as a vtxo-1 checkpoint's
//! ```
//!
//! Both keys sign one digest ([`Collab2::message`]):
//!
//! ```text
//! SHA256( K ‖ k ‖ n ‖ I ‖ m ‖ O )
//! K  SHA256(SHA256("ArcaRbd1" ‖ genesis) ‖ salt), the salt's own constant
//! k  the coin's input index, 4 bytes big-endian, and k < n
//! n  the inputs the signers name, 1 to 16
//! I  SHA256(input_utxo_hash(0) ‖ … ‖ input_utxo_hash(n-1)): each named input
//!    by asset, amount and script, never by outpoint
//! m  the outputs the signers commit to, 1 to 4
//! O  SHA256(output_hash(0) ‖ … ‖ output_hash(m-1)): whole outputs
//! ```
//!
//! The spend carries no annex, which the digest does not cover: the program
//! refuses one, so nobody holding a spend can inflate it, and a reader finds
//! its four witness items where it looks.
//!
//! So beyond the tapscript path a pair binds the coin's index (it never fits
//! a second coin of the same script in one transaction, and two pairs over
//! the same outputs, each made for a coin alone, never fit one transaction)
//! and the inputs it names (a swap leg moves only beside the other leg). Like
//! every Arca pair it names no outpoint, so it holds whatever outpoint an
//! unroll gives the coin. What follows `K` is 70 bytes, which the
//! equivocation bond's slash takes in its rebindable form ([`crate::bond`]).
//!
//! The program prunes to one constant for every spend, so a witness is built
//! with no compiler: the data leaf's bytes, `n`, `m` and the two signatures,
//! then [`COLLAB_PROGRAM`], the root and the control block. Both are copied
//! byte for byte from `sequentia-contracts`,
//! `templates/arca_collab/collab.json`.

use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::taproot::LeafVersion;
use elements::{Script, TxOut};

use crate::message::{Chain, CsfsMessage};
use crate::order::{output_hash, tapdata};
use crate::script::{asset_bytes, sha256};
use crate::spend::Pair;
use crate::taptree::{TapNode, TapOutput};
use crate::Error;

/// The commitment root of `arca/collab-2`.
pub const COLLAB_CMR: &str = "0ac093395a590bea632fc8424d29b77bcd9702fb6a685b60c879df141b6dbf9c";

/// `arca/collab-2`, pruned: one program for every spend (1,158 bytes).
pub const COLLAB_PROGRAM: &str = "e94c3a050e8143a050e8143a050e8143a050830e38e38e38da0e38e38e36e38e38e16416d276741081420c370c3855aae40840a0da4dc4871c70b101a902837023f169c71c70b201c11028370cd588201801bc0e12071181c524d800023e1c5e0842450ce8867390b3cffedf1a67f35f4e6e69c39210d09fddb9189a14c225a77e6c262e17218140cc2dacdba0118047c383038112534440d7fa8b066064fc76756c5a00fd4bf77afe303a974c6923ab0d26d3674b2f0601c000c806a41871c70b86b4e034100703b0100712059b4e01410070936f38e171500da070fb004071805900d807127c2838d481426c40000100bc747e1c2816040a1061c6a28d380e208038e53ab2041f800a0dcb23f1aa48150b11b970839240a8590dcbf37208c39071871f038542d016c1b98c41c920542c86e64d07248150b21b99a36e30e3f0b30e3f0e38542cc2d63734c6e5498720e30e3e070a85a02d84d4010838e16040a0dcbe11a5a0840a0fcc219a634108141b9c838e38dcc71c71c71f70a05a07e658e3733070a80e655028373b87240e608139bb3ec140b020507d26e60bb840200e6f05880e79c1a01e02070403869028373e67e2437199c2a16203520507e401c71c9b008040b066da0840a0dd01071448180640703038681c89039200725c0e5081caf0397813981273085e6085cc205cc380cc3881981cc604e6449cca17992173281732e0330e20660733807354139af273645e6c05cd905cda80cc3881981cdd04e6fd8bf17bab341a1db1a77645961dea1ee3c74aee081bcb7fd32c1012bcfaa66acecbce00b9c20b9c4019871033039c920506e83d6e706fa822e240ce3b26a622ac64ef6267cb85490d6e5da9996799bd2b6386b7f0c030099240e754fcfa9c70b00b98ce5d01d00a273147e63d3600a08160039188141f98a38a240c032036f3f80ddd06a27001509b0facdcfd7680401d0682c40742f940d20ef038701cd701cdc01ce301ce984e7601c94a1e3c0281cef84e7901c90a1e4a0140e7ac0e7e4273fc0e4650f21c0a0740284e80a2740630645607419c27ab3df18dad95a631b354398a69a2127d8120aa476d841cc831e8601801c7640a0dd10a1722014262903a071028374469fa258e38e3920741309d15e6e8964d9a0b931b0a931321882058355c0108141ba27d3f0e31040b001d13e8141ba29c0e88b3f4619c70b0240e84040a0dd1627e8a81401d15e8141ba2dcfd14a70a80e8b640a0dd17c074510281ac0e040707038701c4e071881c6a171d80e8c440a0dd1987e86638e3858b55a0840a0dd1ac7e86738e38e164d540840a0dd1c27e694e38e380e8ca16603a391028374761f9a738e38e385980e0e8141ba3dcfcb338e38e380e8e116801d1f68141ba40607473a0507e90d1c71c71c71c71c71c6e9168a0dca638e38e38e38e38e38e385bdb18083f48cce38e38e38e38e38e13879b98438e38e38e38e38e38e16e01c352283f49c8102e210141c820390e072500e5001cac039700730607386073900740805d1cc03783a3c00e8fa0ba3fc0703174818070517483807071748580709174884070b1748b0070d0749f40e94081d28503a512074a340e94881d2950";

/// The most inputs a pair names.
pub const MAX_NAMED: usize = 16;
/// The most outputs a pair commits to.
pub const MAX_COMMITTED: usize = 4;
/// The data leaf's length: the owner's key, the operator's key, the salt.
pub const DATA_BYTES: usize = 96;
/// The length of what follows `K` in the signed bytes.
pub const REST_BYTES: usize = 70;

fn unhex(s: &str) -> Vec<u8> {
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("a hex constant")).collect()
}

/// `arca/collab-2`'s commitment root.
pub fn collab_cmr() -> [u8; 32] {
	unhex(COLLAB_CMR).try_into().expect("a 32-byte constant")
}

/// The Simplicity leaf version.
pub fn simplicity_version() -> LeafVersion {
	LeafVersion::from_u8(0xbe).expect("0xbe is a leaf version")
}

/// The chain's commitment to a spent output (Simplicity's
/// `input_utxo_hash`): `SHA256(01 ‖ asset ‖ 01 ‖ amount (8, big-endian) ‖
/// SHA256(scriptPubKey))`. `None` unless its asset and amount are explicit.
pub fn utxo_hash(o: &TxOut) -> Option<[u8; 32]> {
	let (asset, value) = (o.asset.explicit()?, o.value.explicit()?);
	let mut b = Vec::with_capacity(32 + 32 + 10 + 32);
	b.push(0x01);
	b.extend(asset_bytes(asset));
	b.push(0x01);
	b.extend(value.to_be_bytes());
	b.extend(sha256(o.script_pubkey.as_bytes()));
	Some(sha256(&b))
}

/// The parameters of a `vtxo-2` leaf or checkpoint: what its data leaf holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Collab2 {
	pub owner: XOnlyPublicKey,
	pub operator: XOnlyPublicKey,
	pub salt: [u8; 32],
	pub chain: Chain,
}

impl Collab2 {
	/// The data leaf's bytes: owner, operator, salt.
	pub fn data_bytes(&self) -> [u8; DATA_BYTES] {
		let mut b = [0u8; DATA_BYTES];
		b[..32].copy_from_slice(&self.owner.serialize());
		b[32..64].copy_from_slice(&self.operator.serialize());
		b[64..].copy_from_slice(&self.salt);
		b
	}

	/// `H_TapData(owner ‖ operator ‖ salt)`.
	pub fn data_leaf(&self) -> [u8; 32] {
		tapdata(&self.data_bytes())
	}

	/// The output whose other leaf is `other` (the leaf's exit, or the
	/// checkpoint's sweep): `TapBranch(TapBranch(F, D), other)`.
	pub fn taproot(&self, other: Script) -> TapOutput {
		TapOutput::with_nodes(vec![
			(2, TapNode::Simplicity(collab_cmr())),
			(2, TapNode::Hidden(self.data_leaf())),
			(1, TapNode::Tapscript(other)),
		])
	}

	/// The bytes both keys sign the digest of, for the coin at input
	/// `index` of a transaction whose first inputs spend `named` (the coin
	/// among them), into `outputs` at indices `0..m`:
	/// `K ‖ k ‖ n ‖ I ‖ m ‖ O`.
	pub fn message(&self, index: u32, named: &[TxOut], outputs: &[TxOut]) -> Result<CsfsMessage, Error> {
		if named.is_empty() || named.len() > MAX_NAMED {
			return Err(Error::NamedCount(named.len()));
		}
		if index as usize >= named.len() {
			return Err(Error::InputIndex(index as usize));
		}
		if outputs.is_empty() || outputs.len() > MAX_COMMITTED {
			return Err(Error::OutputCount(outputs.len()));
		}
		let mut ins = Vec::with_capacity(32 * named.len());
		for (i, o) in named.iter().enumerate() {
			ins.extend(utxo_hash(o).ok_or(Error::NamedNotExplicit(i))?);
		}
		let outs: Vec<u8> = outputs.iter().flat_map(output_hash).collect();
		let mut b = self.chain.leaf_constant(&self.salt).to_vec();
		b.extend(index.to_be_bytes());
		b.push(named.len() as u8);
		b.extend(sha256(&ins));
		b.push(outputs.len() as u8);
		b.extend(sha256(&outs));
		debug_assert_eq!(b.len(), 32 + REST_BYTES);
		Ok(CsfsMessage::from_preimage(b))
	}

	/// The Simplicity witness: the data leaf's bytes, `n`, `m`, the owner's
	/// signature and the operator's.
	pub fn witness_bytes(&self, pair: &Pair, n: u8, m: u8) -> Vec<u8> {
		let mut w = self.data_bytes().to_vec();
		w.extend([n, m]);
		w.extend(pair.owner.as_ref());
		w.extend(pair.operator.as_ref());
		w
	}

	/// The full witness of a spend by this path from the output whose other
	/// leaf is `other`: the Simplicity witness, the pruned program, the root
	/// and the control block.
	pub fn witness(&self, other: Script, pair: &Pair, n: u8, m: u8) -> Vec<Vec<u8>> {
		let tap = self.taproot(other);
		let cb = tap.control_block_at(&Script::from(collab_cmr().to_vec()), simplicity_version())
			.expect("the program is a leaf of this output");
		vec![self.witness_bytes(pair, n, m), unhex(COLLAB_PROGRAM), collab_cmr().to_vec(), cb]
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::encode::{Encoding, Policy};
	use crate::script::ExplicitOutput;
	use crate::{CheckpointPolicy, LeafPolicy, Rebindable, RelativeTime, Template};
	use elements::hashes::Hash;
	use elements::secp256k1_zkp::Keypair;
	use elements::{AssetId, BlockHash};

	fn key(label: &str) -> XOnlyPublicKey {
		Keypair::from_seckey_slice(crate::taptree::secp(), &sha256(label.as_bytes())).unwrap().x_only_public_key().0
	}

	fn leaf(v2: bool) -> LeafPolicy {
		LeafPolicy {
			owner: key("A"), operator: key("S"), salt: [3; 32], chain: Chain::new(BlockHash::from_byte_array([7; 32])),
			exit_delay: RelativeTime::from_units(254).unwrap(), htlc: None, order: None, landing: None, channel: None, enclave: None, v2,
		}
	}

	#[test]
	fn the_program_is_the_contracts_repositorys() {
		assert_eq!(unhex(COLLAB_PROGRAM).len(), 1_158);
		assert_eq!(collab_cmr().len(), 32);
	}

	#[test]
	fn vtxo_2_is_template_vtxo_version_2() {
		assert_eq!(leaf(true).template(), Template::Vtxo2);
		assert_eq!(Template::Vtxo2.to_string(), "vtxo-2");
		assert_eq!("vtxo-2".parse::<Template>().unwrap(), Template::Vtxo2);
		assert_eq!(Template::from_id(Template::VTXO, 2).unwrap(), Template::Vtxo2);
		assert!("vtxo-3".parse::<Template>().is_err());
		assert!(Template::ALL.contains(&Template::Vtxo2));
	}

	#[test]
	fn a_vtxo_2_leaf_keeps_vtxo_1s_exit_and_salt_and_changes_its_address() {
		let (v1, v2) = (leaf(false), leaf(true));
		assert_eq!(v1.exit_script(), v2.exit_script());
		assert_ne!(v1.script_pubkey(), v2.script_pubkey());
		let exit = v2.taproot().control_block(&v2.exit_script()).unwrap();
		assert_eq!(exit.len(), 65, "the exit sits at depth 1, beside the program and its data");
	}

	#[test]
	fn policies_encode_and_decode_with_their_type() {
		for p in [Policy::Leaf(leaf(true)), Policy::Leaf(leaf(false))] {
			let b = p.encode();
			assert_eq!(b[1], if matches!(&p, Policy::Leaf(l) if l.v2) { 12 } else { 1 });
			assert_eq!(Policy::decode(&b).unwrap(), p);
		}
	}

	#[test]
	fn the_message_names_the_index_and_every_named_input() {
		let l = leaf(true);
		let x = AssetId::from_byte_array([9; 32]);
		let coin = ExplicitOutput::new(x, 1_000, l.script_pubkey()).txout();
		let other = ExplicitOutput::new(x, 2_000, elements::Script::from(vec![0x51])).txout();
		let outs = [ExplicitOutput::new(x, 900, elements::Script::from(vec![0x52]))];
		let alone = l.message_in(0, &[coin.clone()], &outs).unwrap();
		assert_eq!(alone, l.collab_message(x, 1_000, &outs).unwrap(), "a coin alone at input 0");
		assert_eq!(alone.preimage.len(), 32 + REST_BYTES);
		assert_eq!(&alone.preimage[..32], &l.leaf_constant(), "the salt's own K");
		let first = l.message_in(0, &[coin.clone(), other.clone()], &outs).unwrap();
		let second = l.message_in(1, &[other.clone(), coin.clone()], &outs).unwrap();
		assert_ne!(alone.digest, first.digest);
		assert_ne!(first.digest, second.digest);
		assert!(l.message_in(2, &[coin.clone(), other], &outs).is_err(), "the coin is one of the named inputs");
		assert!(l.message_in(0, &vec![coin; 17], &outs).is_err(), "at most 16 named inputs");
		let cp = CheckpointPolicy {
			owner: l.owner, operator: l.operator, salt: [4; 32], chain: l.chain,
			sweep: crate::transfer::board_sweep(l.operator, l.exit_delay), v2: true,
		};
		assert!(cp.names_inputs() && l.names_inputs() && !leaf(false).names_inputs());
		let b = Policy::Checkpoint(cp).encode();
		assert_eq!(b[1], 14);
		assert_eq!(Policy::decode(&b).unwrap(), Policy::Checkpoint(cp));
	}
}
