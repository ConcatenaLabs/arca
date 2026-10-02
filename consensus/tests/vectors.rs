//! The golden vectors against the node's interpreter.
//!
//! `regtest/vectors/arca.json` holds, for every frozen Arca script, a sample
//! transaction that spends it by one path (`regtest/vectors.py` builds them
//! with the regtest suite's own builders). Each one must verify, every input,
//! under the block rules and under the node's mempool script checks, and the
//! witness must carry the leaf and control block the vector names for its
//! output. A vector that does not verify is wrong, and so is every
//! implementation that matches it.

use std::str::FromStr;

use elements::encode::deserialize;
use elements::hex::FromHex;
use elements::{BlockHash, Transaction, TxOut};
use serde_json::Value;

use arca_consensus::Verifier;

const VECTORS: &str = include_str!("../../regtest/vectors/arca.json");

fn hex(v: &Value) -> Vec<u8> {
	Vec::<u8>::from_hex(v.as_str().expect("a hex string")).expect("valid hex")
}

#[test]
fn every_vector_spend_verifies() {
	let v: Value = serde_json::from_str(VECTORS).unwrap();
	let genesis = BlockHash::from_str(v["inputs"]["genesis_hash"]["display"].as_str().unwrap()).unwrap();
	let consensus = Verifier::consensus(genesis);
	let standard = Verifier::standard(genesis);

	let spends = v["spends"].as_array().unwrap();
	assert!(spends.len() >= 28, "the vectors lost spends: {}", spends.len());
	for s in spends {
		let name = s["name"].as_str().unwrap();
		let tx: Transaction = deserialize(&hex(&s["tx"])).unwrap();
		let prevouts: Vec<TxOut> = s["prevouts"].as_array().unwrap().iter()
			.map(|p| deserialize(&hex(p)).unwrap()).collect();
		consensus.verify_tx(&prevouts, &tx)
			.unwrap_or_else(|(i, e)| panic!("{}: input {} fails the block rules: {}", name, i, e));
		standard.verify_tx(&prevouts, &tx)
			.unwrap_or_else(|(i, e)| panic!("{}: input {} fails the mempool checks: {}", name, i, e));

		// The covenant input carries the leaf and control block of its output.
		let idx = s["input_index"].as_u64().unwrap() as usize;
		let leaf = &v["outputs"][s["output"].as_str().unwrap()]["leaves"][s["leaf"].as_str().unwrap()];
		let stack = &tx.input[idx].witness.script_witness;
		assert_eq!(stack[stack.len() - 2], hex(&leaf["script"]), "{}: script", name);
		assert_eq!(stack[stack.len() - 1], hex(&leaf["control_block"]), "{}: control block", name);
		let expected: Vec<Vec<u8>> = s["witness"].as_array().unwrap().iter().map(hex).collect();
		assert_eq!(stack, &expected, "{}: witness", name);
		assert_eq!(prevouts[idx].script_pubkey.as_bytes(),
			&hex(&v["outputs"][s["output"].as_str().unwrap()]["script_pubkey"])[..], "{}: output", name);
	}
}

#[test]
fn a_changed_witness_does_not_verify() {
	// The vectors are not vacuous: flip one byte of the last signature-sized
	// item of each covenant witness, or of its first item, and the spend fails.
	let v: Value = serde_json::from_str(VECTORS).unwrap();
	let genesis = BlockHash::from_str(v["inputs"]["genesis_hash"]["display"].as_str().unwrap()).unwrap();
	let consensus = Verifier::consensus(genesis);
	for s in v["spends"].as_array().unwrap() {
		let name = s["name"].as_str().unwrap();
		let mut tx: Transaction = deserialize(&hex(&s["tx"])).unwrap();
		let prevouts: Vec<TxOut> = s["prevouts"].as_array().unwrap().iter()
			.map(|p| deserialize(&hex(p)).unwrap()).collect();
		let idx = s["input_index"].as_u64().unwrap() as usize;
		let stack = &mut tx.input[idx].witness.script_witness;
		let item = (0..stack.len() - 2).rev().find(|&i| stack[i].len() >= 32).unwrap_or(0);
		let last = stack[item].len() - 1;
		stack[item][last] ^= 0x01;
		assert!(consensus.verify_input(&prevouts, idx, &tx).is_err(), "{}: a changed witness verified", name);
	}
}
