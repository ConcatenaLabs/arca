//! The equivocation bond's builders against `regtest/vectors/bond.json`,
//! which `regtest/bond.py` derives independently: its three scripts, the
//! bond's and the notice output's scriptPubKeys, roots and control blocks,
//! and a slash's evidence, whose digests, signatures and witness items must
//! come out the same.

use elements::hashes::Hash;
use elements::hex::FromHex;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, BlockHash, Script};
use serde_json::Value;

use arca_covenant::bond::{self, BondPolicy, Evidence, Form, Signed};
use arca_covenant::*;

const VECTORS: &str = include_str!("../../regtest/vectors/bond.json");

fn hex(v: &Value) -> Vec<u8> {
	Vec::<u8>::from_hex(v.as_str().unwrap_or_else(|| panic!("not a hex string: {}", v))).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
	hex(v).try_into().unwrap()
}

fn same(name: &str, got: &[u8], want: &Value) {
	assert_eq!(got.to_vec(), hex(want), "{}", name);
}

fn signed(v: &Value) -> Signed {
	Signed { form: Form::from_name(v["form"].as_str().unwrap()).unwrap(), rest: hex(&v["rest"]),
		signature: Signature::from_slice(&hex(&v["signature"])).unwrap() }
}

#[test]
fn the_bond_matches_the_regtest_suites_vectors() {
	let v: Value = serde_json::from_str(VECTORS).unwrap();
	let chain = Chain::new(BlockHash::from_byte_array(h32(&v["genesis"])));
	let key = |k: &str| XOnlyPublicKey::from_slice(&hex(&v["keys"][k])).unwrap();
	let notice = RelativeTime::from_sequence(v["notice_sequence"].as_u64().unwrap() as u32).unwrap();
	let p = BondPolicy::new(chain, key("S"), key("W"), notice).unwrap();
	same("fill prefix", &order::fill_prefix(&chain), &v["fill_prefix"]);
	same("slash", p.slash_script().as_bytes(), &v["scripts"]["slash"]);
	same("notice", p.notice_script().as_bytes(), &v["scripts"]["notice"]);
	same("withdraw", p.withdraw_script().as_bytes(), &v["scripts"]["withdraw"]);
	let (b, n) = (p.taproot(), p.notice_taproot());
	same("bond scriptPubKey", p.script_pubkey().as_bytes(), &v["bond"]["script_pubkey"]);
	same("bond root", &b.merkle_root().unwrap(), &v["bond"]["merkle_root"]);
	same("bond slash control block", &b.control_block(&p.slash_script()).unwrap(), &v["bond"]["control_blocks"]["slash"]);
	same("bond notice control block", &b.control_block(&p.notice_script()).unwrap(), &v["bond"]["control_blocks"]["notice"]);
	same("notice scriptPubKey", p.notice_script_pubkey().as_bytes(), &v["notice_output"]["script_pubkey"]);
	same("notice root", &n.merkle_root().unwrap(), &v["notice_output"]["merkle_root"]);
	same("notice slash control block", &n.control_block(&p.slash_script()).unwrap(),
		&v["notice_output"]["control_blocks"]["slash"]);
	same("notice withdraw control block", &n.control_block(&p.withdraw_script()).unwrap(),
		&v["notice_output"]["control_blocks"]["withdraw"]);

	// The evidence: each rebind rest is the leaf's own message after K, each
	// digest the one S signed, and the slash's items the suite's.
	let e = &v["evidence"];
	let salt = h32(&e["salt"]);
	let asset = AssetId::from_byte_array(h32(&e["asset"]));
	let value = e["value"].as_u64().unwrap();
	for side in ["a", "b"] {
		let outs: Vec<ExplicitOutput> = e[side]["outputs"].as_array().unwrap().iter().map(|o| ExplicitOutput::new(
			AssetId::from_byte_array(h32(&o["asset"])), o["value"].as_u64().unwrap(), Script::from(hex(&o["script_pubkey"])))).collect();
		let m = message::rebind_message(&chain.leaf_constant(&salt), asset, value, &outs).unwrap();
		same(&format!("{side} rest"), &bond::rebind_rest(&m.preimage).unwrap(), &e[side]["rest"]);
		same(&format!("{side} digest"), &m.digest, &e[side]["digest"]);
	}
	let (a, b2, f) = (signed(&e["a"]), signed(&e["b"]), signed(&e["fill"]));
	same("fill digest", &p.digest_of(&salt, &f), &e["fill"]["digest"]);
	for s in [&a, &b2, &f] {
		assert!(p.verify(&salt, s), "S's signature over {:?}", s.form);
	}
	let items = |e: Evidence| BondPolicy::slash_items(&e).unwrap();
	let want = |k: &str| e[k].as_array().unwrap().iter().map(hex).collect::<Vec<_>>();
	assert_eq!(items(Evidence { salt, a: a.clone(), b: b2 }), want("slash_items"), "slash items");
	assert_eq!(items(Evidence { salt, a, b: f }), want("slash_items_with_fill"), "slash items with a fill");
}
