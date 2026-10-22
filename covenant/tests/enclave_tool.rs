//! `arca-enclave`, the tool a restricted asset's policy server runs, gives
//! the scripts and digests the wallet and the operator build: a board, a
//! transfer of the board's coin, and a transfer of that transfer's output,
//! each checked against [`TransferPlan`], and the refusals.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use elements::hashes::{sha256d, Hash};
use elements::{OutPoint, Txid};
use serde_json::{json, Value};

use arca_covenant::board::BoardRecord;
use arca_covenant::spend::Pair;
use arca_covenant::transfer::{CoinRecord, NewLeaf, Transfer, TransferInput, TransferPlan};
use arca_covenant::{enclave_key, enclave_keypair, Chain, Enclave, ExplicitOutput, MedianTime, Template, WalletPolicy};
use common::*;

const V: u64 = 5_000_000;

fn hexs(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn tool(cmd: &str, req: &Value) -> (bool, Value) {
	let mut c = Command::new(env!("CARGO_BIN_EXE_arca-enclave")).arg(cmd).stdin(Stdio::piped()).stdout(Stdio::piped())
		.spawn().unwrap();
	c.stdin.take().unwrap().write_all(req.to_string().as_bytes()).unwrap();
	let out = c.wait_with_output().unwrap();
	(out.status.success(), serde_json::from_slice(&out.stdout).unwrap())
}

#[test]
fn the_tool_gives_the_wallets_digests() {
	let chain = Chain::new(elements::BlockHash::from_byte_array(label32("enclave tool chain")));
	let genesis = chain.genesis_hash().to_string();
	let s = keypair("tool operator");
	let (h1, h2) = (keypair("tool holder 1"), keypair("tool holder 2"));
	let (kp, ki) = (keypair("tool policy"), keypair("tool issuer"));
	let r = asset("tool restricted");
	let enclave = |h: &elements::secp256k1_zkp::Keypair| Enclave { holder: xonly(h), policy: xonly(&kp), clawback: Some(xonly(&ki)) };
	let n1 = label32("tool n1");
	let b = BoardRecord {
		template: Template::Board1, owner: enclave_key(&xonly(&h1), &n1).unwrap(), owner_nonce: n1, operator_nonce: label32("tool op"),
		exit_delay: common::net::delay(), asset: r, value: V, chain, operator: xonly(&s), landing: None, enclave: Some(enclave(&h1)),
	};
	let fake = OutPoint::new(Txid::from_raw_hash(sha256d::Hash::hash(b"tool coin")), 0);
	let board_tx = b.tx(&[(fake, explicit(r, V, elements::Script::new()))], r, 0, &elements::Script::new()).unwrap().tx;
	let policy = WalletPolicy::new(chain, xonly(&s), MedianTime::from_consensus(1_800_000_000).unwrap());
	let c1 = CoinRecord::Board(b).resolve(&[board_tx.clone()], &policy).unwrap();

	// The board.
	let (ok, v) = tool("board", &json!({"record": hexs(&b.to_bytes().unwrap())}));
	assert!(ok, "{}", v);
	assert_eq!(v["template"], "enclave-1");
	assert_eq!(v["script_pubkey"], hexs(b.output().script_pubkey.as_bytes()));
	assert_eq!(v["leaf_script_pubkey"], hexs(b.leaf().script_pubkey().as_bytes()));
	assert_eq!(v["holder"], hexs(&xonly(&h1).serialize()));
	assert_eq!(v["policy"], hexs(&xonly(&kp).serialize()));
	assert_eq!(v["clawback"], hexs(&xonly(&ki).serialize()));
	assert_eq!(v["operator"], hexs(&xonly(&s).serialize()));
	assert_eq!(v["genesis"], genesis);
	assert_eq!(v["salt"], hexs(&b.salt()));
	assert_eq!(v["value"], V.to_string());
	assert_eq!(v["asset"], r.to_string());
	assert!(v["claw_control"].is_string() && v["leaf_claw_control"].is_string());

	// Hop 1: H1's board coin to H2.
	let n2 = label32("tool n2");
	let leaf2 = NewLeaf {
		owner: enclave_key(&xonly(&h2), &n2).unwrap(), owner_nonce: n2, creator_nonce: label32("tool c2"),
		exit_delay: common::net::delay(), htlc: None, landing: None, enclave: Some(enclave(&h2).terms(r, V)),
	};
	let out2 = vec![ExplicitOutput::new(r, V, leaf2.policy(xonly(&s), chain).script_pubkey())];
	let plan = TransferPlan { inputs: vec![(c1.clone(), V)], outputs: out2.clone() };
	let a1 = enclave_keypair(&h1, &n1).unwrap();
	let (cm, rm) = (plan.checkpoint_message(0).unwrap(), plan.reassignment_message(0).unwrap());
	let req = |coin: &CoinRecord, to: &elements::secp256k1_zkp::Keypair, n: [u8; 32], c: [u8; 32]| json!({
		"genesis": genesis, "operator": hexs(&xonly(&s).serialize()), "policy": hexs(&xonly(&kp).serialize()),
		"clawback": hexs(&xonly(&ki).serialize()),
		"inputs": [{"coin": hexs(&coin.to_bytes().unwrap()), "checkpoint_value": V.to_string()}],
		"outputs": [{"asset": r.to_string(), "value": V.to_string(), "holder": hexs(&xonly(to).serialize()),
			"owner_nonce": hexs(&n), "creator_nonce": hexs(&c), "exit_delay_units": common::net::delay().units()}],
	});
	let (ok, v) = tool("transfer", &req(&CoinRecord::Board(b), &h2, n2, label32("tool c2")));
	assert!(ok, "{}", v);
	assert_eq!(v["inputs"][0]["checkpoint_digest"], hexs(&cm.digest));
	assert_eq!(v["inputs"][0]["reassignment_digest"], hexs(&rm.digest));
	assert_eq!(v["inputs"][0]["salt"], hexs(&b.salt()));
	assert_eq!(v["inputs"][0]["holder"], hexs(&xonly(&h1).serialize()));
	assert_eq!(v["outputs"][0]["script_pubkey"], hexs(out2[0].script_pubkey.as_bytes()));
	assert_eq!(v["outputs"][0]["salt"], hexs(&leaf2.salt()));
	assert_eq!(v["outputs"][0]["holder"], hexs(&xonly(&h2).serialize()));

	// Hop 2: H2's new coin back to H1, its record the reassignment's.
	let pair = |m: &arca_covenant::CsfsMessage, owner: &elements::secp256k1_zkp::Keypair| Pair { operator: sig(&s, &m.digest), owner: sig(owner, &m.digest) };
	let rec2 = CoinRecord::Transfer(Box::new(Transfer {
		inputs: vec![TransferInput { coin: CoinRecord::Board(b), checkpoint_value: V, checkpoint: pair(&cm, &a1), reassignment: pair(&rm, &a1) }],
		outputs: out2, index: 0, leaf: leaf2,
	}));
	let c2 = rec2.resolve(&[board_tx], &policy).unwrap();
	assert_eq!(c2.leaf.template(), Template::Enclave1);
	let n3 = label32("tool n3");
	let leaf3 = NewLeaf {
		owner: enclave_key(&xonly(&h1), &n3).unwrap(), owner_nonce: n3, creator_nonce: label32("tool c3"),
		exit_delay: common::net::delay(), htlc: None, landing: None, enclave: Some(enclave(&h1).terms(r, V)),
	};
	let plan = TransferPlan { inputs: vec![(c2, V)], outputs: vec![ExplicitOutput::new(r, V, leaf3.policy(xonly(&s), chain).script_pubkey())] };
	let (ok, v) = tool("transfer", &req(&rec2, &h1, n3, label32("tool c3")));
	assert!(ok, "{}", v);
	assert_eq!(v["inputs"][0]["checkpoint_digest"], hexs(&plan.checkpoint_message(0).unwrap().digest));
	assert_eq!(v["inputs"][0]["reassignment_digest"], hexs(&plan.reassignment_message(0).unwrap().digest));
	assert_eq!(v["inputs"][0]["holder"], hexs(&xonly(&h2).serialize()));
	println!("the tool's digests are the transfer plan's: a board coin, and a coin two hops from it");

	// Refusals.
	let mut wrong = req(&CoinRecord::Board(b), &h2, n2, label32("tool c2"));
	wrong["operator"] = json!(hexs(&xonly(&keypair("another operator")).serialize()));
	let (ok, v) = tool("transfer", &wrong);
	assert!(!ok);
	println!("another operator: {}", v["error"]);
	let mut wrong = req(&CoinRecord::Board(b), &h2, n2, label32("tool c2"));
	wrong["policy"] = json!(hexs(&xonly(&keypair("another policy")).serialize()));
	let (ok, v) = tool("transfer", &wrong);
	assert!(!ok);
	println!("another policy key: {}", v["error"]);
	let mut wrong = req(&CoinRecord::Board(b), &h2, n2, label32("tool c2"));
	wrong["clawback"] = Value::Null;
	let (ok, v) = tool("transfer", &wrong);
	assert!(!ok);
	println!("no clawback for a clawback asset: {}", v["error"]);
	let plain = BoardRecord { owner: xonly(&h1), enclave: None, ..b };
	let (ok, v) = tool("board", &json!({"record": hexs(&plain.to_bytes().unwrap())}));
	assert!(!ok);
	println!("a vtxo-1 board: {}", v["error"]);
	let (ok, v) = tool("transfer", &req(&CoinRecord::Board(plain), &h2, n2, label32("tool c2")));
	assert!(!ok);
	println!("a vtxo-1 coin: {}", v["error"]);
	let (ok, v) = tool("nothing", &json!({}));
	assert!(!ok);
	println!("an unknown command: {}", v["error"]);
}
