//! The `order-2` builders against `regtest/vectors/order.json`, which
//! `regtest/order.py` derives independently: the parameters, every script
//! leaf, control block, merkle root and scriptPubKey of an order, of its
//! remainder after a fill and of the credit that fill pays, the SeqDEX order
//! it lands as, and the operator's fill digest, whose signature must verify.

use elements::hashes::Hash;
use elements::hex::FromHex;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::{Message, Secp256k1, XOnlyPublicKey};
use elements::{AssetId, BlockHash, Script};
use serde_json::Value;

use arca_covenant::order::{OrderPath, OrderPolicy, OrderTerms, SeqdexOrder};
use arca_covenant::*;

const VECTORS: &str = include_str!("../../regtest/vectors/order.json");

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

fn check_order(name: &str, o: &OrderPolicy, v: &Value) {
	same(&format!("{name} params"), &o.data_bytes(), &v["params"]);
	same(&format!("{name} data leaf"), &o.data_leaf(), &v["data_leaf"]);
	same(&format!("{name} collab"), o.collab_script().as_bytes(), &v["collab"]);
	same(&format!("{name} landing"), o.landing_script().as_bytes(), &v["landing"]);
	same(&format!("{name} land leaf"), &o.land_leaf(), &v["land_leaf"]);
	same(&format!("{name} merkle root"), &o.root(), &v["merkle_root"]);
	same(&format!("{name} scriptPubKey"), o.script_pubkey().as_bytes(), &v["script_pubkey"]);
	same(&format!("{name} collab control block"), &o.control_block(OrderPath::Collab), &v["control_blocks"]["collab"]);
	same(&format!("{name} land control block"), &o.control_block(OrderPath::Land), &v["control_blocks"]["land"]);
	same(&format!("{name} fill control block"), &o.control_block(OrderPath::Fill), &v["control_blocks"]["fill"]);
}

#[test]
fn order_2_matches_the_regtest_suites_vectors() {
	let v: Value = serde_json::from_str(VECTORS).unwrap();
	let t = &v["terms"];
	let terms = OrderTerms { asset_a: AssetId::from_byte_array(h32(&t["asset_a"])), asset_b: AssetId::from_byte_array(h32(&t["asset_b"])),
		rate_num: t["rate_num"].as_u64().unwrap(), rate_den: t["rate_den"].as_u64().unwrap(), min_lot: t["min_lot"].as_u64().unwrap() };
	let keys = &v["keys"];
	let landed = SeqdexOrder { terms, maker: h32(&t["maker"]), expiry: t["expiry"].as_u64().unwrap() as u32, refund_key: key(&keys["refund"]) };
	same("landed params", &landed.data_bytes(), &v["landed"]["params"]);
	same("landed scriptPubKey", landed.script_pubkey().as_bytes(), &v["landed"]["script_pubkey"]);
	let chain = Chain::new(BlockHash::from_byte_array(h32(&v["genesis"])));
	let o = OrderPolicy {
		landed,
		owner: key(&keys["maker"]),
		operator: key(&keys["S"]),
		salt: h32(&v["salt"]),
		chain,
		exit_delay: RelativeTime::from_sequence(v["exit_delay_sequence"].as_u64().unwrap() as u32).unwrap(),
		credits: [0, 1, 2, 3].map(|i| key(&keys[format!("credit{}", i)]).serialize()),
	};
	check_order("order", &o, &v["order"]);
	let n = o.next();
	same("remainder salt", &n.salt, &v["remainder"]["salt"]);
	check_order("remainder", &n, &v["remainder"]);
	same("credit salt", &o.credit_salt(), &v["credit"]["salt"]);
	same("credit scriptPubKey", o.credit_leaf().unwrap().script_pubkey().as_bytes(), &v["credit"]["script_pubkey"]);

	let f = &v["fill"];
	let outs: Vec<elements::TxOut> = f["outputs"].as_array().unwrap().iter().map(|x| {
		ExplicitOutput::new(AssetId::from_byte_array(h32(&x["asset"])), x["value"].as_u64().unwrap(),
			Script::from(hex(&x["script_pubkey"]))).txout()
	}).collect();
	let digest = o.fill_digest(f["locked"].as_u64().unwrap(), &outs).unwrap();
	same("fill digest", &digest, &f["digest"]);
	let plan = o.plan(f["locked"].as_u64().unwrap(), f["filled"].as_u64().unwrap()).unwrap();
	assert_eq!(plan.credit.txout(), outs[0], "the planned credit");
	assert_eq!(plan.rest.unwrap().txout(), outs[1], "the planned remainder");
	let sig = Signature::from_slice(&hex(&f["operator_signature"])).unwrap();
	Secp256k1::verification_only().verify_schnorr(&sig, &Message::from_digest(digest), &o.operator).expect("the operator's signature");
}
