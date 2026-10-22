//! The supervised profile as the `arca` wallet meets it, against a whole Arca
//! server, PostgreSQL and the node, on an anchored proof-of-stake regtest
//! chain: an asset Z issued under the supervision descriptor (with the pause
//! capability), which the operator serves under the profile because its node
//! lists it. A holder boards Z and refreshes it into a supervised batch,
//! which `supervised-check` reads whole from the published tree and the
//! chain; pays another holder out of round, both coins landing in their
//! holders' own keys; is frozen by a targeted freeze of its landing, which
//! `coins` shows and the operator mirrors (a payment and a refresh refused,
//! `frozen`); takes its coin home by its landing into its own key with
//! `exit`, where the coin stays frozen on the chain; and, once the issuer
//! lifts the freeze, spends that coin again and moves in the tree again.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::str::FromStr;

use elements::encode::{deserialize, serialize};
use elements::hex::FromHex;
use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Script, Transaction, TxIn};
use serde_json::{json, Value};

use common::cli::Arca;
use common::node::{self, op_true};
use common::running::{keypair, Running, MIN_LEAF};
use server::server::AssetSection;
use server::store::RoundState;

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn tx_of(h: &str) -> Transaction {
	deserialize(&Vec::<u8>::from_hex(h).unwrap()).unwrap()
}

fn script(v: &Value) -> Script {
	Script::from(Vec::<u8>::from_hex(v["script_pubkey"].as_str().unwrap()).unwrap())
}

fn atoms(v: &Value) -> u64 {
	v.as_str().unwrap_or_else(|| panic!("an amount: {}", v)).parse().unwrap()
}

fn create_args<'a>(server: &'a str, node: &'a str) -> Vec<&'a str> {
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

/// The live coins of `w` in `asset`.
fn live_in(w: &Arca, asset: &str) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == asset).cloned().collect()
}

/// A BIP340 signature by `key` over `digest`.
fn sign(key: &Keypair, digest: &[u8; 32]) -> String {
	hex(arca_covenant::sign::sign_digest(key, digest, &[0; 32]).as_ref())
}

/// The issuer of Z: its operational key signs its records.
struct Issuer {
	z: AssetId,
	op: Keypair,
}

impl Issuer {
	/// Issues Z under the supervision descriptor, with the pause capability,
	/// into the purse, and lists it for fees at 1:1.
	fn issue(r: &mut Running) -> Issuer {
		let op = keypair("Z operational");
		let rec = keypair("Z recovery");
		let coin = r.purse.take_coin(r.purse.policy);
		let tx = node::spend_op_true(&coin, vec![], 20_000);
		let parked = Script::new_v0_wpkh(&elements::WPubkeyHash::from_byte_array([1; 20]));
		let to = address(r, &parked);
		let issued: Value = r.rt.client().call("rawissueasset", &[json!(hex(&serialize(&tx))), json!([{
			"asset_amount": 100, "asset_address": to, "token_amount": 1, "token_address": to, "blind": false,
			"supervision": {"operationalkey": hex(&op.x_only_public_key().0.serialize()),
				"recoverykey": hex(&rec.x_only_public_key().0.serialize()), "pause": true},
		}])]).unwrap();
		let mut tx = tx_of(issued[0]["hex"].as_str().unwrap());
		let z = AssetId::from_str(issued[0]["asset"].as_str().unwrap()).unwrap();
		// The issued coins to the purse's OP_TRUE: the declaration binds the
		// issuance, not where its outputs pay.
		for o in tx.output.iter_mut() {
			if o.script_pubkey == parked {
				o.script_pubkey = op_true();
			}
		}
		let txid = r.rt.client().send_raw_transaction(&tx).unwrap();
		r.rt.produce_block().unwrap();
		for (j, o) in tx.output.iter().enumerate() {
			if o.script_pubkey == op_true() && !o.is_fee() {
				r.purse.put((OutPoint::new(txid, j as u32), o.clone()));
			}
		}
		let listed: Value = r.rt.client().call("getsupervisedassets", &[]).unwrap();
		assert!(listed.as_array().unwrap().iter().any(|a| a["asset"] == json!(z.to_string()) && a["pauseallowed"] == json!(true)));
		node::list_fee_asset(&r.rt, z, 100_000_000);
		println!("Z {} issued under the supervision descriptor, pause allowed", z);
		Issuer { z, op }
	}

	/// A freeze record naming `target`, signed by the operational key and
	/// mined: its outpoint and target hash.
	fn freeze(&self, r: &mut Running, target: &Script) -> (OutPoint, String) {
		let coin = r.purse.take_coin(r.purse.policy);
		let t = json!(hex(target.as_bytes()));
		let h: Value = r.rt.client().call("getsupervisionrecordhash", &[json!("freeze"), json!(self.z.to_string()), t.clone(), Value::Null,
			json!(coin.0.txid.to_string()), json!(coin.0.vout)]).unwrap();
		let digest: [u8; 32] = Vec::<u8>::from_hex(h["sighash"].as_str().unwrap()).unwrap().try_into().unwrap();
		let built: Value = r.rt.client().call("buildsupervisionrecord", &[json!("freeze"), json!(self.z.to_string()), t, Value::Null,
			json!(sign(&self.op, &digest))]).unwrap();
		let tx = node::spend_op_true(&coin, vec![], 20_000);
		let raw: Value = r.rt.client().call("addsupervisionrecordoutput", &[json!(hex(&serialize(&tx))), built["script"].clone(),
			json!(self.z.to_string())]).unwrap();
		let tx = tx_of(raw.as_str().unwrap());
		let txid = r.rt.client().send_raw_transaction(&tx).unwrap();
		r.rt.produce_block().unwrap();
		let record = Vec::<u8>::from_hex(built["script"].as_str().unwrap()).unwrap();
		let mut at = None;
		for (j, o) in tx.output.iter().enumerate() {
			if o.script_pubkey.as_bytes() == &record[..] {
				at = Some(OutPoint::new(txid, j as u32));
			} else if o.script_pubkey == op_true() {
				r.purse.put((OutPoint::new(txid, j as u32), o.clone()));
			}
		}
		(at.expect("the record's output"), built["targethash"].as_str().unwrap().to_string())
	}

	/// Spends the record at `at`, lifting its freeze, and mines it.
	fn lift(&self, r: &mut Running, at: OutPoint, target: &str) {
		let h: Value = r.rt.client().call("getsupervisionunfreezehash", &[json!(at.txid.to_string()), json!(at.vout),
			json!(self.z.to_string()), json!(target)]).unwrap();
		let digest: [u8; 32] = Vec::<u8>::from_hex(h.as_str().unwrap()).unwrap().try_into().unwrap();
		let coin = r.purse.take_coin(r.purse.policy);
		let mut tx = node::spend_op_true(&coin, vec![], 20_000);
		tx.input.insert(0, TxIn { previous_output: at, ..Default::default() });
		let raw: Value = r.rt.client().call("setsupervisionunfreezesig", &[json!(hex(&serialize(&tx))), json!(0),
			json!(sign(&self.op, &digest))]).unwrap();
		let tx = tx_of(raw.as_str().unwrap());
		let txid = r.rt.client().send_raw_transaction(&tx).unwrap();
		r.rt.produce_block().unwrap();
		for (j, o) in tx.output.iter().enumerate() {
			if o.script_pubkey == op_true() {
				r.purse.put((OutPoint::new(txid, j as u32), o.clone()));
			}
		}
	}

	/// What the node says of `spk`'s holding of Z.
	fn status(&self, r: &Running, spk: &Script) -> Value {
		r.rt.client().call("isassetfrozen", &[json!(self.z.to_string()), json!(hex(spk.as_bytes()))]).unwrap()
	}
}

/// The node's address for `spk`.
fn address(r: &Running, spk: &Script) -> String {
	let d: Value = r.rt.client().call("decodescript", &[json!(hex(spk.as_bytes()))]).unwrap();
	d["address"].as_str().or_else(|| d["segwit"]["address"].as_str()).unwrap().to_string()
}

/// The script the node holds for `address`.
fn script_of(r: &Running, address: &str) -> Script {
	let v: Value = r.rt.client().call("validateaddress", &[json!(address)]).unwrap();
	Script::from(Vec::<u8>::from_hex(v["scriptPubKey"].as_str().unwrap()).unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_frozen_holder_lands_its_coin_in_its_own_key() {
	let mut r = Running::start().await;
	let iss = tokio::task::block_in_place(|| Issuer::issue(&mut r));
	let (z, x) = (iss.z.to_string(), r.x.to_string());
	// The operator's signer reads freezes from a node of its own, and serves
	// Z under the profile once its node lists Z as supervised.
	let genesis = r.rt.client().genesis_hash().unwrap();
	let cookie = r.signer.dir.join("node.cookie");
	std::fs::write(&cookie, "arca:arca").unwrap();
	r.signer.halt();
	r.signer.set_extra(vec!["--keeper-timeout-ms".into(), "2000".into(), "--supervision-node".into(), r.node_url(),
		"--supervision-cookie".into(), cookie.to_str().unwrap().into()]);
	tokio::task::block_in_place(|| r.signer.resume(genesis));
	let mut config = r.config.clone();
	config.assets.push(AssetSection::new(iss.z, MIN_LEAF));
	r.server.reload(&config).await.unwrap();
	r.config = config;
	r.fund_server(iss.z, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;

	let (url, node_url) = (r.url(), r.node_url());
	let (a, b) = (Arca::new("SUPA"), Arca::new("SUPB"));
	for w in [&a, &b] {
		w.ok(&create_args(&url, &node_url));
		for (asset, v) in [(iss.z, 3_000_000), (r.x, 2_000_000)] {
			let s = script(&w.ok(&["address"]));
			r.pay_to(s, asset, v);
		}
	}
	r.produce().await;
	let info = a.ok(&["info"]);
	let a_landing = info["landing_address"].as_str().unwrap().to_string();
	let served = info["server_info"]["assets"].as_array().unwrap().iter().find(|s| s["asset"] == z.as_str()).unwrap().clone();
	let allowance = atoms(&served["supervised"]["landing_allowance"]);
	println!("A lands every coin of Z at {}; the operator publishes an allowance of {}", a_landing, allowance);
	let b_landing = b.ok(&["info"])["landing_address"].as_str().unwrap().to_string();
	let a_spk = script_of(&r, &a_landing);

	// ---- Boarded and refreshed into a supervised batch -------------------
	a.ok(&["board", &z, "2000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("A's board credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
	let p = a.ok(&["participate"]);
	assert_eq!(p["participations"].as_array().map(|v| v.len()), Some(1), "{}", p);
	let round = r.server.rounds.run_round().await.unwrap().expect("Z's round");
	let (batch_asset, batch_vout, _) = round.batches[0];
	assert_eq!(batch_asset, iss.z);
	r.produce().await;
	r.bury().await;
	r.round_state(&round.tx.txid(), RoundState::Final).await;
	let s = a.ok(&["sync"]);
	assert!(s["participations"].as_array().unwrap().iter().all(|q| q["state"] == "released"), "{}", s);
	let coin = live_in(&a, &z).into_iter().find(|c| c["kind"] == "batch").unwrap_or_else(|| panic!("A's leaf of Z's round"));
	assert_eq!(coin["landing"], json!(a_landing), "{}", coin);
	assert_eq!(coin["frozen"]["frozen"], json!(false), "{}", coin);
	let check = a.ok(&["supervised-check", &format!("{}:{}", round.tx.txid(), batch_vout)]);
	assert_eq!(check["ok"], json!(true), "{}", check);
	assert_eq!((check["supervised_on_the_node"].clone(), check["explicit"].clone()), (json!(true), json!(true)), "{}", check);
	assert!(check["leaves"].as_array().unwrap().iter().all(|l| l["template"] == "landing-1" && atoms(&l["allowance"]) == allowance),
		"{}", check);
	assert!(check["leaves"].as_array().unwrap().iter().any(|l| l["landing"] == json!(a_landing)), "{}", check);
	println!("CHECKED: round {} batch {} of Z: every leaf landing-1 at the published allowance, every output explicit", round.tx.txid(),
		batch_vout);
	// A supervised coin is never planned: `plan` says why, and `care` leaves
	// it to `sync`'s refresh.
	let leaf = coin["leaf_id"].as_str().unwrap().to_string();
	a.refused(&["plan", &leaf], "supervised asset, whose operator runs no plans for it");
	let care = a.ok(&["care"]);
	assert_eq!(care["supervised"]["coins"], json!(1), "{}", care);
	// A batch of another asset is not a supervised one.
	let x_board = a.ok(&["board", &x, "1000000"])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("A's board of X credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
	a.ok(&["participate", "--leaf", &x_board]);
	let x_round = r.server.rounds.run_round().await.unwrap().expect("X's round");
	r.produce().await;
	r.bury().await;
	r.round_state(&x_round.tx.txid(), RoundState::Final).await;
	a.ok(&["sync"]);
	let other = a.ok(&["supervised-check", &format!("{}:{}", x_round.tx.txid(), x_round.batches[0].1)]);
	assert_eq!(other["ok"], json!(false), "{}", other);
	println!("CHECKED: X's batch is not a supervised one: {}", other["problems"]);

	// ---- Paid out of round, both coins landing at their holders' keys -----
	let req = b.ok(&["receive", "--asset", &z, "--amount", "300000"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req]);
	b.ok(&["sync"]);
	let bob = live_in(&b, &z);
	assert_eq!(bob.len(), 1, "{:?}", bob);
	assert_eq!(bob[0]["landing"], json!(b_landing), "{}", bob[0]);
	let alice = live_in(&a, &z);
	assert_eq!(alice.len(), 1, "A's change: {:?}", alice);
	assert_eq!(alice[0]["landing"], json!(a_landing), "{}", alice[0]);
	let a_coin = alice[0]["leaf_id"].as_str().unwrap().to_string();
	let a_value = atoms(&alice[0]["value"]);
	println!("A paid B 300000 of Z out of round: B's coin lands at {}, A's change at {}", b_landing, a_landing);

	// ---- A targeted freeze of A's landing, shown and mirrored ------------
	let (freeze_at, target) = tokio::task::block_in_place(|| iss.freeze(&mut r, &a_spk));
	r.produce().await;
	r.synced().await;
	println!("freeze record {} names A's landing: isassetfrozen {}", freeze_at, iss.status(&r, &a_spk));
	let shown = live_in(&a, &z);
	assert_eq!(shown[0]["frozen"]["frozen"], json!(true), "{}", shown[0]);
	println!("A's coins show: {}", shown[0]["frozen"]);
	let req2 = b.ok(&["receive", "--asset", &z, "--amount", "100000"])["request"].as_str().unwrap().to_string();
	let m = a.refused(&["send", &req2], "frozen");
	assert!(m.contains("names its landing"), "{}", m);
	a.refused(&["participate", "--leaf", &a_coin], "409 frozen");
	assert_eq!(a.ok(&["record", &a_coin])["state"], "live", "the coin is the wallet's again");
	// B is not frozen, and pays A, whose coin arrives frozen.
	let req3 = a.ok(&["receive", "--asset", &z, "--amount", "50000"])["request"].as_str().unwrap().to_string();
	b.ok(&["send", &req3]);
	let s = a.ok(&["sync"]);
	assert_eq!(s["mailbox"]["accepted"].as_array().map(|v| v.len()), Some(1), "{}", s);
	let from_b = live_in(&a, &z).into_iter().find(|c| c["leaf_id"] != a_coin.as_str()).expect("B's payment");
	assert_eq!((from_b["landing"].clone(), from_b["frozen"]["frozen"].clone()), (json!(a_landing), json!(true)), "{}", from_b);
	let from_b = from_b["leaf_id"].as_str().unwrap().to_string();
	println!("B, not frozen, paid A 50000 of Z: a payment to a frozen landing is co-signed, and arrives frozen");

	// ---- A takes its coin home by its landing, into its own key ----------
	let e = a.ok(&["exit", &a_coin]);
	assert!(matches!(e["state"].as_str(), Some("unrolling" | "waiting")), "{}", e);
	for _ in 0..8 {
		r.produce().await;
		let e = a.ok(&["exit", &a_coin]);
		if e["state"] == "waiting" {
			break;
		}
	}
	tokio::task::block_in_place(|| node::advance_mtp(&r.rt, 512));
	let e = a.ok(&["exit", &a_coin]);
	assert_eq!(e["state"], "claimed", "{}", e);
	let claim_id = elements::Txid::from_str(e["claim"]["txid"].as_str().unwrap()).unwrap();
	r.produce().await;
	r.bury().await;
	let claim = r.rt.client().raw_transaction(&claim_id).unwrap();
	assert_eq!(claim.output[0].script_pubkey, a_spk, "the landing pays A's own landing key");
	assert_eq!(claim.output[0].asset.explicit(), Some(iss.z));
	let landed = claim.output[0].value.explicit().unwrap();
	assert!(landed + allowance >= a_value, "the landing holds the coin's value less at most the allowance: {} of {}", landed, a_value);
	assert!(claim.output.iter().all(|o| o.asset.explicit().is_some() && o.value.explicit().is_some()), "every output explicit");
	let st = iss.status(&r, &a_spk);
	assert_eq!(st["frozen"], json!(true), "{}", st);
	println!("LANDED: {} pays {} of Z to A's landing {} ({} vB); the node shows it frozen: {}", claim_id, landed, a_landing,
		claim.vsize(), st);
	a.ok(&["sync"]);
	assert_eq!(a.ok(&["record", &a_coin])["state"], "exited");
	let bal = a.ok(&["balance", "--without-bitcoin"]);
	assert_eq!(bal["sequentia_onchain_frozen"][&z].as_str().map(|v| v.parse::<u64>().unwrap() >= landed), Some(true), "{}", bal);
	// The wallet keeps the frozen coin out of every spend.
	a.refused(&["board", &z, &(landed - 10_000).to_string()], "on-chain that it can spend");

	// ---- The freeze lifted: the landed coin spent, A moves in the tree ---
	tokio::task::block_in_place(|| iss.lift(&mut r, freeze_at, &target));
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let st = iss.status(&r, &a_spk);
	assert_eq!(st["frozen"], json!(false), "{}", st);
	let bal = a.ok(&["balance", "--without-bitcoin"]);
	assert!(bal.get("sequentia_onchain_frozen").is_none(), "{}", bal);
	let again = a.ok(&["board", &z, &(landed - 10_000).to_string()]);
	let board_tx = elements::Txid::from_str(again["txid"].as_str().unwrap_or_else(|| panic!("the board's txid: {}", again))).unwrap();
	let spent = r.rt.client().raw_transaction(&board_tx).unwrap();
	assert!(spent.input.iter().any(|i| i.previous_output == OutPoint::new(claim_id, 0)), "the board spends the landed coin");
	println!("LIFTED: the landed coin is spent again by A's board {}", board_tx);
	// The coin B paid A rests on the transfer A's exit put on the chain, so
	// the wallet takes it on-chain as well, as any coin whose lineage is on
	// the chain; A's new board, landing at the same key, moves in the tree.
	assert_eq!(a.ok(&["record", &from_b])["state"], "exiting");
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("A's new board credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
	let board = live_in(&a, &z).into_iter().find(|c| c["kind"] == "board").expect("A's new board, live");
	assert_eq!((board["landing"].clone(), board["frozen"]["frozen"].clone()), (json!(a_landing), json!(false)), "{}", board);
	let req4 = b.ok(&["receive", "--asset", &z, "--amount", "10000"])["request"].as_str().unwrap().to_string();
	// The operator counted the lifting from the block that carried it, which
	// is final by now (the server's own test refuses before then).
	a.ok(&["send", &req4]);
	b.ok(&["sync"]);
	println!("A, its freeze lifted and final, pays B again in the tree from its new board");
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
