//! The `vtxo-2` builders against `regtest/vectors/collab2.json`, which
//! `regtest/collab2.py` derives independently: a leaf and its checkpoint
//! (parameters, data leaf, program leaf, exit or sweep, control blocks,
//! merkle root and scriptPubKey), the bytes both keys sign for a spend of
//! each by `arca/collab-2`, the digest, the signatures and the Simplicity
//! witness; and the program the crate carries, by its root and its hash.

use elements::hashes::Hash;
use elements::hex::FromHex;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::taproot::LeafVersion;
use elements::{AssetId, BlockHash, Script, TxOut};
use serde_json::Value;

use arca_covenant::collab::{collab_cmr, simplicity_version, COLLAB_PROGRAM, REST_BYTES};
use arca_covenant::order::{tapbranch, tapdata, tapleaf};
use arca_covenant::script::sha256;
use arca_covenant::sign::verify_digest;
use arca_covenant::sweep::Sweep;
use arca_covenant::*;

const VECTORS: &str = include_str!("../../regtest/vectors/collab2.json");

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

fn coins(v: &Value) -> Vec<TxOut> {
	v.as_array().unwrap().iter().map(|c| ExplicitOutput::new(AssetId::from_byte_array(h32(&c["asset"])), c["value"].as_u64().unwrap(),
		Script::from(hex(&c["script_pubkey"]))).txout()).collect()
}

fn check_output<P: Rebindable>(name: &str, p: &P, other: &Script, v: &Value) {
	let tap = p.tap();
	same(&format!("{name} other leaf"), other.as_bytes(), &v["other"]);
	same(&format!("{name} merkle root"), &tap.merkle_root().unwrap(), &v["merkle_root"]);
	same(&format!("{name} scriptPubKey"), tap.script_pubkey().as_bytes(), &v["script_pubkey"]);
	let cmr = Script::from(collab_cmr().to_vec());
	same(&format!("{name} collab control block"), &tap.control_block_at(&cmr, simplicity_version()).unwrap(),
		&v["control_blocks"]["collab"]);
	same(&format!("{name} other control block"), &tap.control_block_at(other, LeafVersion::default()).unwrap(),
		&v["control_blocks"]["other"]);
	same(&format!("{name} program leaf"), &tapleaf(0xbe, &collab_cmr()), &v["program_leaf"]);
	let root = tapbranch(tapbranch(tapleaf(0xbe, &collab_cmr()), h32(&v["data_leaf"])), tapleaf(0xc4, other.as_bytes()));
	same(&format!("{name} merkle root, by hand"), &root, &v["merkle_root"]);
}

fn check_spend<P: Rebindable>(name: &str, p: &P, params: &[u8], s: &Value) {
	let named = coins(&s["named"]);
	let outs: Vec<ExplicitOutput> = coins(&s["outputs"]).iter().map(|o| ExplicitOutput::from_txout(o).unwrap()).collect();
	let k = s["index"].as_u64().unwrap() as u32;
	let m = p.message_in(k, &named, &outs).unwrap();
	same(&format!("{name} signed bytes"), &m.preimage, &s["preimage"]);
	same(&format!("{name} rest"), &m.preimage[32..], &s["rest"]);
	assert_eq!(m.preimage.len() - 32, REST_BYTES);
	same(&format!("{name} digest"), &m.digest, &s["digest"]);
	let pair = Pair {
		owner: Signature::from_slice(&hex(&s["owner_signature"])).unwrap(),
		operator: Signature::from_slice(&hex(&s["operator_signature"])).unwrap(),
	};
	assert!(verify_digest(&pair.owner, &m.digest, &p.owner()), "{name}: the owner's signature");
	assert!(verify_digest(&pair.operator, &m.digest, &p.operator()), "{name}: the operator's signature");
	p.verify_in(k, &named, &outs, &pair).unwrap();
	let w = p.witness_in(&pair, named.len() as u8, outs.len() as u8);
	same(&format!("{name} Simplicity witness"), &w[0], &s["witness"]);
	assert_eq!(&w[0][..96], params, "{name}: the witness starts with the data leaf's bytes");
	assert_eq!(w[1], Vec::<u8>::from_hex(COLLAB_PROGRAM).unwrap(), "{name}: the pruned program");
	assert_eq!(w[2], collab_cmr().to_vec());
}

#[test]
fn vtxo_2_matches_the_regtest_suites_vectors() {
	let v: Value = serde_json::from_str(VECTORS).unwrap();
	same("commitment root", &collab_cmr(), &v["cmr"]);
	let program = Vec::<u8>::from_hex(COLLAB_PROGRAM).unwrap();
	assert_eq!(program.len() as u64, v["program_bytes"].as_u64().unwrap());
	same("program hash", &sha256(&program), &v["program_sha256"]);
	let chain = Chain::new(BlockHash::from_byte_array(h32(&v["genesis"])));
	let keys = &v["keys"];
	let delay = RelativeTime::from_sequence(v["exit_delay_sequence"].as_u64().unwrap() as u32).unwrap();
	let l = &v["leaf"];
	let leaf = LeafPolicy {
		owner: key(&keys["A"]), operator: key(&keys["S"]), salt: h32(&l["salt"]), chain, exit_delay: delay,
		htlc: None, order: None, landing: None, channel: None, enclave: None, v2: true,
	};
	assert_eq!(leaf.template(), Template::Vtxo2);
	same("leaf params", &leaf.collab2().data_bytes(), &l["params"]);
	same("leaf data leaf", &leaf.collab2().data_leaf(), &l["data_leaf"]);
	same("leaf data leaf, by hand", &tapdata(&hex(&l["params"])), &l["data_leaf"]);
	check_output("leaf", &leaf, &leaf.exit_script(), l);
	let sw = &v["sweep"];
	let sweep = Sweep {
		token: AssetId::from_byte_array(h32(&sw["token"])), r_program: h32(&sw["r_program"]), operator: key(&sw["operator"]),
		notice: Some(RelativeTime::from_sequence(sw["notice"].as_u64().unwrap() as u32).unwrap()), burn: false,
	};
	let c = &v["checkpoint"];
	let cp = CheckpointPolicy {
		owner: leaf.owner, operator: leaf.operator, salt: arca_covenant::transfer::checkpoint_salt(&leaf.salt), chain, sweep: Some(sweep), v2: true,
	};
	same("checkpoint salt", &cp.salt, &c["salt"]);
	same("checkpoint params", &cp.collab2().data_bytes(), &c["params"]);
	check_output("checkpoint", &cp, &cp.sweep_script().unwrap(), c);
	check_spend("the leaf into its checkpoint", &leaf, &hex(&l["params"]), &v["spends"]["leaf_into_checkpoint"]);
	check_spend("the checkpoint at index 1 of a swap", &cp, &hex(&c["params"]), &v["spends"]["checkpoint_in_a_swap"]);
}
