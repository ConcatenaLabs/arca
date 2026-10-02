//! What the consensus and regtest tests share: test keys, transaction
//! assembly and a record of every case with the verdict it got.

#![allow(dead_code)]

pub mod net;

use elements::confidential::{Asset, Nonce, Value};
use elements::hashes::{sha256d, Hash};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use elements::{
	AssetId, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, TxOutWitness, Txid,
};

use arca_covenant::script::sha256;
use arca_covenant::sign::{script_spend_sighash, sign_digest};
use arca_covenant::TapOutput;

pub const ZERO_AUX: [u8; 32] = [0; 32];

/// A test key derived from a label.
pub fn keypair(label: &str) -> Keypair {
	let secret = sha256(format!("Arca test key/{}", label).as_bytes());
	Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&secret).unwrap())
}

pub fn xonly(k: &Keypair) -> XOnlyPublicKey {
	k.x_only_public_key().0
}

pub fn label32(label: &str) -> [u8; 32] {
	sha256(format!("Arca test/{}", label).as_bytes())
}

pub fn asset(label: &str) -> AssetId {
	AssetId::from_byte_array(label32(label))
}

pub fn explicit(asset: AssetId, value: u64, spk: Script) -> TxOut {
	TxOut {
		asset: Asset::Explicit(asset),
		value: Value::Explicit(value),
		nonce: Nonce::Null,
		script_pubkey: spk,
		witness: TxOutWitness::default(),
	}
}

pub fn fee(asset: AssetId, value: u64) -> TxOut {
	TxOut::new_fee(value, asset)
}

/// A coin anyone can spend through a tapscript of `OP_TRUE`: the stand-in
/// for a fee coin.
pub fn op_true() -> TapOutput {
	TapOutput::new(vec![(0, Script::from(vec![0x51]))])
}

pub fn op_true_witness() -> Vec<Vec<u8>> {
	let t = op_true();
	t.witness(&Script::from(vec![0x51]), vec![])
}

/// A transaction under assembly, with the outputs its inputs spend.
#[derive(Clone)]
pub struct Spend {
	pub tx: Transaction,
	pub prevouts: Vec<TxOut>,
}

impl Spend {
	pub fn new(lock_time: u32) -> Spend {
		Spend {
			tx: Transaction { version: 2, lock_time: LockTime::from_consensus(lock_time), input: vec![], output: vec![] },
			prevouts: vec![],
		}
	}

	pub fn input(mut self, outpoint: OutPoint, spent: TxOut, sequence: u32) -> Spend {
		self.tx.input.push(TxIn { previous_output: outpoint, sequence: Sequence(sequence), ..Default::default() });
		self.prevouts.push(spent);
		self
	}

	/// An input spending a made-up outpoint, for script-only verification.
	pub fn fake_input(self, label: &str, spent: TxOut, sequence: u32) -> Spend {
		let txid = Txid::from_raw_hash(sha256d::Hash::hash(label.as_bytes()));
		self.input(OutPoint::new(txid, 0), spent, sequence)
	}

	pub fn output(mut self, out: TxOut) -> Spend {
		self.tx.output.push(out);
		self
	}

	pub fn outputs(mut self, outs: Vec<TxOut>) -> Spend {
		self.tx.output.extend(outs);
		self
	}

	pub fn witness(&mut self, idx: usize, stack: Vec<Vec<u8>>) {
		self.tx.input[idx].witness.script_witness = stack;
	}

	pub fn sighash(&self, idx: usize, leaf: &Script, genesis: BlockHash) -> [u8; 32] {
		script_spend_sighash(&self.tx, idx, &self.prevouts, leaf, genesis).unwrap()
	}

	pub fn sign(&self, key: &Keypair, idx: usize, leaf: &Script, genesis: BlockHash) -> Signature {
		sign_digest(key, &self.sighash(idx, leaf, genesis), &ZERO_AUX)
	}
}

/// A signature over a 32-byte digest.
pub fn sig(key: &Keypair, digest: &[u8; 32]) -> Signature {
	sign_digest(key, digest, &ZERO_AUX)
}
