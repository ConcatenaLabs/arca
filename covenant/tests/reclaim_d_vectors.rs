//! RECLAIM-D against `regtest/vectors/reclaim_d.json`, which
//! `regtest/reclaim_d.py` derives independently: the leaf's script and its
//! step, the node's scriptPubKey and control blocks, the release and
//! delegation prefixes and messages, the signatures over them, and the items
//! below RECLAIM-D for a coin paid twice, a swap and a direct release.

use elements::hashes::Hash;
use elements::hex::FromHex;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use elements::{AssetId, BlockHash, Script};
use serde_json::Value;

use arca_covenant::node::{self, ReleaseTree, RECLAIM_STEPS};
use arca_covenant::release::Delegation;
use arca_covenant::script::{children_hash, Child};
use arca_covenant::sign::sign_digest;
use arca_covenant::Chain;

const VECTORS: &str = include_str!("../../regtest/vectors/reclaim_d.json");

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

fn tree(v: &Value) -> ReleaseTree {
	if let Some(r) = v.get("release") {
		ReleaseTree::Release {
			key: key(&r["key"]),
			sig: Signature::from_slice(&hex(&r["sig"])).unwrap(),
			connector_input: r["connector_input"].as_u64().unwrap() as u32,
		}
	} else {
		let d = &v["delegation"];
		ReleaseTree::Delegation {
			key: key(&d["key"]),
			sig: Signature::from_slice(&hex(&d["sig"])).unwrap(),
			to: d["to"].as_array().unwrap().iter().map(tree).collect(),
		}
	}
}

#[test]
fn reclaim_d_matches_the_regtest_suites_vectors() {
	let v: Value = serde_json::from_str(VECTORS).unwrap();
	assert_eq!(v["steps"].as_u64().unwrap() as usize, RECLAIM_STEPS);
	let chain = Chain::new(BlockHash::from_byte_array(h32(&v["genesis_internal"])));
	let operator = key(&v["operator"]);
	let owners: Vec<XOnlyPublicKey> = v["owners"].as_array().unwrap().iter().map(key).collect();
	let children: Vec<Child> = v["children"].as_array().unwrap().iter().map(|c| {
		Child::new(AssetId::from_slice(&hex(&c["asset"])).unwrap(), c["value"].as_u64().unwrap(), h32(&c["program"]))
	}).collect();
	let prefix = chain.release_prefix(&children_hash(&children));
	same("release prefix", &prefix, &v["release_prefix"]);
	same("delegation prefix", &chain.delegation_prefix(), &v["delegation_prefix"]);

	let reclaim = node::reclaim_script(&prefix, &owners, &operator);
	let reclaim_d = node::reclaim_delegated_script(&prefix, &chain.delegation_prefix(), &owners, &operator);
	same("RECLAIM", reclaim.as_bytes(), &v["scripts"]["reclaim"]);
	same("RECLAIM-D", reclaim_d.as_bytes(), &v["scripts"]["reclaim_d"]);
	let step = hex(&v["step_script"]);
	assert_eq!(&reclaim_d.as_bytes()[..step.len() * RECLAIM_STEPS], step.repeat(RECLAIM_STEPS).as_slice(), "the 32 steps");

	let unroll = Script::from(hex(&v["scripts"]["unroll"]));
	let sweep = Script::from(hex(&v["scripts"]["sweep"]));
	let tap = node::node_taproot_delegated(unroll.clone(), Some(sweep.clone()), Some(reclaim.clone()), Some(reclaim_d.clone()));
	same("scriptPubKey", tap.script_pubkey().as_bytes(), &v["script_pubkey"]);
	for (name, s) in [("unroll", &unroll), ("sweep", &sweep), ("reclaim", &reclaim), ("reclaim_d", &reclaim_d)] {
		same(name, &tap.control_block(s).unwrap(), &v["control_blocks"][name]);
	}

	// The messages, and the signatures over them from the keys' secrets.
	let secp = Secp256k1::new();
	let pair = |name: &str| {
		let sk = SecretKey::from_slice(&hex(&v["keys"][name]["secret"])).unwrap();
		Keypair::from_secret_key(&secp, &sk)
	};
	let d = &v["delegation"];
	let delegation = Delegation::new(chain, key(&d["from"]), d["to"].as_array().unwrap().iter().map(key).collect()).unwrap();
	same("delegation digest", &delegation.message().digest, &d["digest"]);
	let r = &v["release"];
	let m = AssetId::from_slice(&hex(&r["connector"])).unwrap();
	same("release digest", &chain.release_message(&children_hash(&children), m).digest, &r["digest"]);
	let trees: Vec<ReleaseTree> = v["trees"].as_array().unwrap().iter().map(tree).collect();
	let b_sig = match &trees[0] {
		ReleaseTree::Delegation { to, .. } => match &to[0] {
			ReleaseTree::Delegation { sig, .. } => *sig,
			_ => panic!("the first successor of owner 0 delegated"),
		},
		_ => panic!("owner 0 delegated"),
	};
	assert_eq!(sign_digest(&pair("B"), &delegation.message().digest, &[0; 32]), b_sig, "B's delegation");
	delegation.verify(&b_sig).unwrap();

	let s_sig = Signature::from_slice(&hex(&v["operator_sig"])).unwrap();
	let items = node::reclaim_delegated_items(&s_sig, &prefix, &chain.delegation_prefix(), &trees).unwrap();
	let want: Vec<Vec<u8>> = v["items"].as_array().unwrap().iter().map(hex).collect();
	assert_eq!(items, want, "the items below RECLAIM-D");
	assert_eq!(trees.iter().map(ReleaseTree::steps).sum::<usize>(), 12);
}
