//! The accumulator batch's builders against `regtest/vectors/accumulator.json`,
//! which `regtest/accumulator.py` derives independently: every slot's entry
//! and record, the Merkle-sum root and the batch's weight, the state's data
//! leaf, the batch output's tree, scriptPubKey and control block, two
//! exits, each with its digest, signature, witness value and the state it
//! leaves, and every leaf's record and coin record in binary form with its
//! leaf id, and records a reader refuses.

use elements::hashes::Hash;
use elements::hex::FromHex;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, BlockHash};
use serde_json::Value;

use arca_covenant::accumulator::{exit_digest, read_exit, AccumulatorRecord, Exit, ExitAuth};
use arca_covenant::tree::{LeafSpec, ReserveRule};
use arca_covenant::*;

const VECTORS: &str = include_str!("../../regtest/vectors/accumulator.json");

fn hex(v: &Value) -> Vec<u8> {
	Vec::<u8>::from_hex(v.as_str().unwrap_or_else(|| panic!("not a hex string: {}", v))).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
	hex(v).try_into().unwrap()
}

fn key(v: &Value) -> XOnlyPublicKey {
	XOnlyPublicKey::from_slice(&hex(v)).unwrap()
}

fn same(name: &str, got: &[u8], want: &Value) {
	assert_eq!(got.to_vec(), hex(want), "{}", name);
}

#[test]
fn accumulator_matches_the_regtest_suites_vectors() {
	let v: Value = serde_json::from_str(VECTORS).unwrap();
	same("cmr", &accumulator::accumulator_cmr(), &v["cmr"]);
	let chain = Chain::new(BlockHash::from_byte_array(h32(&v["genesis"])));
	let asset = AssetId::from_byte_array(h32(&v["asset"]));
	let operator = key(&v["operator"]);
	let expiries: Vec<MedianTime> = v["expiries"].as_array().unwrap().iter()
		.map(|e| MedianTime::from_consensus(e.as_u64().unwrap() as u32).unwrap()).collect();
	let schedule = ClockSchedule::new(AssetId::from_byte_array(h32(&v["token"])), operator,
		RelativeTime::from_units(v["notice_units"].as_u64().unwrap() as u16).unwrap(), expiries).unwrap();
	let leaves: Vec<LeafSpec> = v["leaves"].as_array().unwrap().iter().map(|l| LeafSpec { claim: None,
		template: Template::Vtxo1, owner: key(&l["owner"]), value: l["value"].as_u64().unwrap(),
		owner_nonce: h32(&l["owner_nonce"]), operator_nonce: h32(&l["operator_nonce"]),
		exit_delay: RelativeTime::from_units(l["exit_delay_units"].as_u64().unwrap() as u16).unwrap(),
		unlock_hash: h32(&l["unlock_hash"]), htlc: None, order: None, landing: None,
		channel: None,
	}).collect();
	let params = AccumulatorParams {
		asset, chain, schedule, burn: false,
		reserve: ReserveRule::Fixed { node: v["exit_reserve"].as_u64().unwrap(), entry: v["entry_reserve"].as_u64().unwrap() },
		min_leaf: 1,
	};
	let acc = Accumulator::build(params, &leaves).unwrap();
	for (j, s) in v["slots"].as_array().unwrap().iter().enumerate() {
		same(&format!("slot {j} entry"), acc.leaves()[j].entry.script_pubkey().as_bytes(), &s["entry_script_pubkey"]);
		assert_eq!(acc.slots()[j].value, s["value"].as_u64().unwrap(), "slot {j} value");
		assert_eq!(acc.slots()[j].reserve, s["reserve"].as_u64().unwrap(), "slot {j} reserve");
		same(&format!("slot {j} record"), &acc.slots()[j].record(j as u16), &s["record"]);
	}
	let state = *acc.policy();
	same("root", &state.root, &v["root"]);
	assert_eq!(acc.total(), v["total"].as_u64().unwrap(), "total");
	same("sweep script", state.sweep.script().as_bytes(), &v["sweep_script"]);
	same("data", &state.data_bytes(), &v["data"]);
	same("data leaf", &state.data_leaf(), &v["data_leaf"]);
	same("merkle root", &state.tree_root(), &v["merkle_root"]);
	same("taproot's merkle root", &state.taproot().merkle_root().unwrap(), &v["merkle_root"]);
	same("scriptPubKey", state.script_pubkey().as_bytes(), &v["script_pubkey"]);
	same("control block", &state.control_block(), &v["control_block"]);

	// Each record rebuilds the same batch, and the exits.
	let mut at = state;
	for e in v["exits"].as_array().unwrap() {
		let j = e["slot"].as_u64().unwrap() as usize;
		let rec = acc.record(j);
		same(&format!("exit {j}: record's batch output"), rec.batch_output().unwrap().script_pubkey.as_bytes(), &v["script_pubkey"]);
		let exit: Exit = rec.exit().unwrap();
		assert_eq!(exit, acc.exit(j), "exit {j}: the record's exit is the builder's");
		same(&format!("exit {j}: record"), &exit.record.record(j as u16), &e["record"]);
		for (d, p) in e["path"].as_array().unwrap().iter().enumerate() {
			same(&format!("exit {j}: sibling {d}"), &exit.path[d].0, &p["hash"]);
			assert_eq!(exit.path[d].1, p["weight"].as_u64().unwrap(), "exit {j}: sibling {d}'s weight");
		}
		let t = MedianTime::from_consensus(e["time"].as_u64().unwrap() as u32).unwrap();
		same(&format!("exit {j}: digest"), &exit_digest(&chain, &state.root, &exit.record.record(j as u16), t), &e["digest"]);
		let by_operator = e["by_operator"].as_bool().unwrap();
		let auth = ExitAuth { by_operator, time: t, signature: Signature::from_slice(&hex(&e["signature"])).unwrap() };
		at.check_slot(&chain, &exit, &auth).unwrap();
		let w = at.exit_witness(&exit, &auth, false);
		same(&format!("exit {j}: witness"), &w[0], &e["witness"]);
		let seen = read_exit(&w).unwrap();
		assert_eq!((seen.slot as usize, seen.by_operator, seen.bitmap, seen.time), (j, by_operator, at.bitmap, t.to_consensus_u32()));
		at = at.after(j as u16);
		same(&format!("exit {j}: next bitmap"), &at.bitmap.to_bytes(), &e["next_bitmap"]);
		same(&format!("exit {j}: next scriptPubKey"), at.script_pubkey().as_bytes(), &e["next_script_pubkey"]);
	}

	// Every leaf's record and coin record, both ways.
	for h in v["held"].as_array().unwrap() {
		let j = h["slot"].as_u64().unwrap() as usize;
		let rec = acc.record(j);
		same(&format!("slot {j}: record"), &rec.to_bytes().unwrap(), &h["record"]);
		assert_eq!(AccumulatorRecord::from_bytes(&hex(&h["record"])).unwrap(), rec, "slot {j}: the record decodes to the built one");
		same(&format!("slot {j}: leaf program"), &rec.leaf().program(), &h["leaf_program"]);
		same(&format!("slot {j}: leaf id"), &rec.leaf_id().unwrap().0, &h["leaf_id"]);
		let t = MedianTime::from_consensus(h["auth_time"].as_u64().unwrap() as u32).unwrap();
		let coin = CoinRecord::Accumulator {
			record: rec.clone(), preimage: h32(&h["preimage"]),
			auth: (Signature::from_slice(&hex(&h["auth_signature"])).unwrap(), t),
		};
		same(&format!("slot {j}: coin record"), &coin.to_bytes().unwrap(), &h["coin"]);
		assert_eq!(CoinRecord::from_bytes(&hex(&h["coin"])).unwrap(), coin, "slot {j}: the coin record decodes");
	}
	for r in v["refuse"].as_array().unwrap() {
		let e = AccumulatorRecord::from_bytes(&hex(&r["record"])).expect_err(r["why"].as_str().unwrap());
		println!("refused, {}: {}", r["why"].as_str().unwrap(), e);
	}
}
