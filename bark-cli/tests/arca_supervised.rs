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
//! Every leaf the wallet asks for is `landing-2`, since the operator makes
//! it. A second test runs this build beside an older one that reads no
//! `landing-2`, both ways, and with the operator's `landing_2_only` on.
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
	// The operator makes landing-2, so the wallet asks for it.
	assert!(check["leaves"].as_array().unwrap().iter().all(|l| l["template"] == "landing-2" && atoms(&l["allowance"]) == allowance),
		"{}", check);
	assert!(check["leaves"].as_array().unwrap().iter().any(|l| l["landing"] == json!(a_landing)), "{}", check);
	assert_eq!(coin["template"], json!("landing-2"), "{}", coin);
	println!("CHECKED: round {} batch {} of Z: every leaf landing-2 at the published allowance, every output explicit", round.tx.txid(),
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
	assert_eq!(bob[0]["template"], json!("landing-2"), "B's request names landing-2: {}", bob[0]);
	let alice = live_in(&a, &z);
	assert_eq!(alice.len(), 1, "A's change: {:?}", alice);
	assert_eq!(alice[0]["landing"], json!(a_landing), "{}", alice[0]);
	assert_eq!(alice[0]["template"], json!("landing-2"), "{}", alice[0]);
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

/// Serves a new supervised asset Z, its signer reading freezes from a node
/// of its own, as [`a_frozen_holder_lands_its_coin_in_its_own_key`] does.
async fn serve_z(r: &mut Running) -> Issuer {
	let iss = tokio::task::block_in_place(|| Issuer::issue(r));
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
	iss
}

/// The template of `w`'s live coin `leaf`, as `coins` shows it.
fn template_of(w: &Arca, asset: &str, leaf: &str) -> Value {
	live_in(w, asset).into_iter().find(|c| c["leaf_id"] == leaf).map(|c| c["template"].clone()).unwrap_or(Value::Null)
}

/// This build beside an older one (`ARCA_CLI_OLDER`, an `arca` built from a
/// library that reads no `landing-2`), on a supervised asset Z, in both
/// roles, and with the operator's `landing_2_only` on. Skipped when no older
/// build is named.
///
/// - Each boards Z and refreshes it: this build's leaf is `landing-2`, the
///   older one's `landing-1`.
/// - The older build pays this one: the coin is `landing-1` (an older sender
///   reads no `reads`), and this build takes it.
/// - This build pays the older one: a `landing-1` leaf, from the one coin
///   whose past holds no `landing-2` leaf, and the older build takes it; a
///   second payment, every coin left holding one, is refused before
///   anything is signed.
/// - `landing_2_only` on: the older build's refresh and its payment are
///   refused, naming the setting; this build pays a third wallet in
///   `landing-2`.
/// - A wallet restored from this build's mnemonic holds the same coins.
#[tokio::test(flavor = "multi_thread")]
async fn an_older_wallet_and_this_one_pay_each_other_and_the_switch() {
	let Some(older) = std::env::var("ARCA_CLI_OLDER").ok() else {
		println!("LD: no ARCA_CLI_OLDER: old against new not run");
		return;
	};
	let older = std::path::Path::new(&older);
	let mut r = Running::start().await;
	let iss = serve_z(&mut r).await;
	let z = iss.z.to_string();
	let (url, node_url) = (r.url(), r.node_url());
	let (a, o, c) = (Arca::new("LDA"), Arca::built_from("LDO", older), Arca::new("LDC"));
	for w in [&a, &o, &c] {
		w.ok(&create_args(&url, &node_url));
		for (asset, v) in [(iss.z, 3_000_000), (r.x, 2_000_000)] {
			let s = script(&w.ok(&["address"]));
			r.pay_to(s, asset, v);
		}
	}
	r.produce().await;

	// ---- Each boards Z and refreshes it ----------------------------------
	for w in [&a, &o] {
		w.ok(&["board", &z, "2000000"]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	for w in [&a, &o] {
		r.wait("the boards credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
		w.ok(&["sync"]);
		w.ok(&["participate"]);
	}
	let round = r.server.rounds.run_round().await.unwrap().expect("Z's round");
	r.produce().await;
	r.bury().await;
	r.round_state(&round.tx.txid(), RoundState::Final).await;
	for w in [&a, &o] {
		let s = w.ok(&["sync"]);
		assert!(s["participations"].as_array().unwrap().iter().all(|q| q["state"] == "released"), "{}", s);
	}
	let a_round = live_in(&a, &z);
	let o_round = live_in(&o, &z);
	assert_eq!((a_round.len(), o_round.len()), (1, 1), "{:?} {:?}", a_round, o_round);
	assert_eq!(a_round[0]["template"], json!("landing-2"), "{}", a_round[0]);
	assert_ne!(o_round[0]["template"], json!("landing-2"), "the older build asks for landing-1: {}", o_round[0]);
	let a_round_id = a_round[0]["leaf_id"].as_str().unwrap().to_string();
	println!("ROUND {}: this build's leaf landing-2, the older build's {}", round.tx.txid(), o_round[0]["template"]);

	// ---- The older build pays this one ------------------------------------
	let req = a.ok(&["receive", "--asset", &z, "--amount", "200000"])["request"].as_str().unwrap().to_string();
	o.ok(&["send", &req]);
	let s = a.ok(&["sync"]);
	assert_eq!(s["mailbox"]["accepted"].as_array().map(|v| v.len()), Some(1), "{}", s);
	let from_o = live_in(&a, &z).into_iter().find(|c| c["leaf_id"] != a_round_id.as_str()).expect("O's payment");
	assert_eq!(from_o["template"], json!("landing-1"), "an older sender pays landing-1: {}", from_o);
	println!("OLD PAYS NEW: the older build paid this one a landing-1 leaf, taken");

	// ---- This build pays the older one ------------------------------------
	let req = o.ok(&["receive", "--asset", &z, "--amount", "100000"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req]);
	let s = o.ok(&["sync"]);
	assert_eq!(s["mailbox"]["accepted"].as_array().map(|v| v.len()), Some(1), "the older build takes it: {}", s);
	assert_eq!(a.ok(&["record", &a_round_id])["state"], "live", "the landing-2 coin did not pay the older build");
	assert_eq!(a.ok(&["record", from_o["leaf_id"].as_str().unwrap()])["state"], "spent", "the landing-1 coin paid it");
	let o_got = live_in(&o, &z).into_iter().find(|c| c["leaf_id"] != o_round[0]["leaf_id"]).expect("A's payment to O");
	assert_ne!(o_got["template"], json!("landing-2"), "{}", o_got);
	println!("NEW PAYS OLD: a landing-1 leaf, from the coin whose past holds no landing-2 leaf; the older build took it");
	let req = o.ok(&["receive", "--asset", &z, "--amount", "50000"])["request"].as_str().unwrap().to_string();
	let m = a.refused(&["send", &req], "landing-2 leaf");
	println!("REFUSED new pays old, every coin holding a landing-2 leaf: {}", m);
	// Never "settle first": a round makes the coin's landing-2 leaf again,
	// so settling it would never let it pay the older build, and a program
	// that settles on that answer would settle it forever.
	let (ok, v) = a.run(&["send", &req]);
	assert!(!ok && v["error"]["kind"] == "refused", "a landing-2 coin is never named to settle first for a side that reads no landing-2: {}", v);

	// ---- The switch on --------------------------------------------------------
	r.config.landing_2_only = true;
	r.restart_server().await;
	let req = a.ok(&["receive", "--asset", &z, "--amount", "50000"])["request"].as_str().unwrap().to_string();
	let (ok, v, err) = o.run_full(&["send", &req]);
	println!("SWITCH ON: the older build pays this one: {} {}", v, err.lines().last().unwrap_or(""));
	assert!(!ok && (v.to_string() + &err).contains("landing_2_only"), "{} {}", v, err);
	let (ok, v, err) = o.run_full(&["participate"]);
	println!("SWITCH ON: the older build's refresh: {} {}", v, err.lines().last().unwrap_or(""));
	assert!(!ok && (v.to_string() + &err).contains("landing_2_only"), "{} {}", v, err);
	let c_info = c.ok(&["info"]);
	let req = c.ok(&["receive", "--asset", &z, "--amount", "60000"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req]);
	c.ok(&["sync"]);
	let c_coins = live_in(&c, &z);
	assert_eq!(c_coins.len(), 1, "{:?}", c_coins);
	assert_eq!(c_coins[0]["template"], json!("landing-2"), "{}", c_coins[0]);
	assert_eq!(c_coins[0]["landing"], c_info["landing_address"], "{}", c_coins[0]);
	println!("SWITCH ON: this build paid a third wallet landing-2");

	// ---- A restore ----------------------------------------------------------
	let held: std::collections::BTreeSet<String> = live_in(&a, &z).iter().map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap();
	let a2 = Arca::new("LDA2");
	let mut args = create_args(&url, &node_url);
	args.extend(["--mnemonic", mnemonic.trim()]);
	a2.ok(&args);
	a2.ok(&["sync"]);
	let restored: std::collections::BTreeSet<String> = live_in(&a2, &z).iter().map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
	assert_eq!(restored, held, "the restored wallet holds this build's coins of Z");
	for id in &restored {
		assert_eq!(template_of(&a2, &z, id), template_of(&a, &z, id), "coin {}", id);
	}
	println!("RESTORED: {} coins of Z, with their templates", restored.len());
	for w in [&a, &o, &c, &a2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// Every coin of `w` with its state, as `coins` shows them.
fn states(w: &Arca) -> std::collections::BTreeMap<String, Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().map(|c| (c["leaf_id"].as_str().unwrap().to_string(), c["state"].clone())).collect()
}

/// [`states`] of `w`'s coins of `asset`.
fn states_of(w: &Arca, asset: &str) -> std::collections::BTreeMap<String, Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["asset"] == asset)
		.map(|c| (c["leaf_id"].as_str().unwrap().to_string(), c["state"].clone())).collect()
}

/// Trades and payments between this build and an older one
/// (`ARCA_CLI_OLDER`) once the operator makes `landing-2` leaves only:
/// each is refused before the side that cannot complete it signs, and every
/// coin of the older build keeps its state. Skipped when no older build is
/// named.
///
/// - This build offers X for the supervised Z: the offer's leaf is
///   `landing-2`, which the older build cannot parse, so it refuses the
///   offer.
/// - The older build offers X for Z, and Z for X: this build refuses each,
///   since the older build's leaves are `landing-1`.
/// - An offer this build made before the switch carries a `landing-1` leaf:
///   a third wallet refuses it after the switch.
/// - The older build pays this one, and refreshes: refused by the operator,
///   its coins untouched.
#[tokio::test(flavor = "multi_thread")]
async fn under_the_switch_an_older_wallet_is_refused_before_it_signs() {
	let Some(older) = std::env::var("ARCA_CLI_OLDER").ok() else {
		println!("LD: no ARCA_CLI_OLDER: old against new not run");
		return;
	};
	let older = std::path::Path::new(&older);
	let mut r = Running::start().await;
	let iss = serve_z(&mut r).await;
	let (z, x) = (iss.z.to_string(), r.x.to_string());
	let (url, node_url) = (r.url(), r.node_url());
	let (a, o, c) = (Arca::new("LSA"), Arca::built_from("LSO", older), Arca::new("LSC"));
	for w in [&a, &o, &c] {
		w.ok(&create_args(&url, &node_url));
		for (asset, v) in [(iss.z, 3_000_000), (r.x, 3_000_000)] {
			let s = script(&w.ok(&["address"]));
			r.pay_to(s, asset, v);
		}
	}
	r.produce().await;
	for asset in [&z, &x, &x] {
		for w in [&a, &o, &c] {
			w.ok(&["board", asset, "1000000"]);
		}
		r.produce().await;
	}
	r.bury().await;
	r.synced().await;
	for w in [&a, &o, &c] {
		r.wait("the boards credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
		w.ok(&["sync"]);
	}
	// Before the switch: an offer of this build's wants Z in a landing-1
	// leaf, its taker not known.
	let early = a.ok(&["swap", "offer", "--give-asset", &x, "--give", "100000", "--want-asset", &z, "--want", "100000"]);

	r.config.landing_2_only = true;
	r.restart_server().await;
	for w in [&a, &o, &c] {
		w.ok(&["sync"]);
	}

	// ---- This build's offer, the older build its taker ---------------------
	let offer = a.ok(&["swap", "offer", "--give-asset", &x, "--give", "100000", "--want-asset", &z, "--want", "100000"]);
	assert_eq!(offer["details"]["outputs"][0]["template"], json!("landing-2"), "{}", offer["details"]["outputs"][0]);
	let before = states(&o);
	let (ok, v, err) = o.run_full(&["swap", "accept", offer["offer"].as_str().unwrap()]);
	println!("SWITCH ON: the older build takes this build's X-for-Z offer: ok {} {} {}", ok, v, err.lines().last().unwrap_or(""));
	assert!(!ok, "the older build accepted a landing-2 offer: {}", v);
	assert!(v.to_string().contains("landing"), "refused for another reason: {}", v);
	assert_eq!(states(&o), before, "the older build's coins keep their states");
	println!("REFUSED by the older build before signing: {}", v["error"]["message"]);

	// ---- The older build's offers, this build their taker -------------------
	for (give_asset, want_asset) in [(&x, &z), (&z, &x)] {
		let offer = o.ok(&["swap", "offer", "--give-asset", give_asset, "--give", "100000", "--want-asset", want_asset, "--want", "100000"]);
		let before = states(&a);
		let m = a.refused(&["swap", "accept", offer["offer"].as_str().unwrap()], "landing_2_only");
		assert!(m.contains("nothing was signed"), "{}", m);
		assert_eq!(states(&a), before, "this build's coins keep their states");
		println!("REFUSED the older build's offer of {} for {}: {}", give_asset, want_asset, m);
		let (ok, v, err) = o.run_full(&["swap", "cancel", offer["swap"].as_str().unwrap()]);
		println!("the older build cancels its offer: ok {} {} {}", ok, v, err.lines().last().unwrap_or(""));
	}

	// ---- An offer made before the switch -------------------------------------
	let m = c.refused(&["swap", "accept", early["offer"].as_str().unwrap()], "landing-1 leaf");
	println!("REFUSED an offer made before the switch: {}", m);
	a.ok(&["swap", "cancel", early["swap"].as_str().unwrap()]);

	// ---- The older build pays, and refreshes ----------------------------------
	o.ok(&["sync"]);
	let before = states_of(&o, &z);
	let req = a.ok(&["receive", "--asset", &z, "--amount", "50000"])["request"].as_str().unwrap().to_string();
	let (ok, v, err) = o.run_full(&["send", &req]);
	assert!(!ok && (v.to_string() + &err).contains("landing_2_only"), "{} {}", v, err);
	o.ok(&["sync"]);
	assert_eq!(states_of(&o, &z), before, "the older build's Z coins keep their states after its refused payment");
	// Its refresh of X goes ahead; that of Z is refused, its coin live again.
	let p = o.ok(&["participate"]);
	let pz = p["participations"].as_array().unwrap().iter().find(|q| q["asset"] == z.as_str()).expect("Z's participation").clone();
	assert!(pz["error"].as_str().unwrap_or("").contains("landing_2_only"), "{}", pz);
	o.ok(&["sync"]);
	assert_eq!(states_of(&o, &z), before, "the older build's Z coins keep their states after its refused refresh");
	println!("SWITCH ON: the older build's payment and refresh of Z refused, its Z coins as they were: {:?}", before);

	// This build trades with a third wallet of its build under the switch.
	let offer = a.ok(&["swap", "offer", "--give-asset", &x, "--give", "100000", "--want-asset", &z, "--want", "100000"]);
	let acc = c.ok(&["swap", "accept", offer["offer"].as_str().unwrap()]);
	a.ok(&["swap", "complete", acc["accept"].as_str().unwrap()]);
	println!("SWITCH ON: this build's offer taken and completed by a third wallet of this build");
	for w in [&a, &o, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// Posts the operator's equivocation bond with a suggested instant limit,
/// as `arca_coin_places` does: without it the limit a wallet applies is 0,
/// every coin it receives stays arriving, and a trade never shapes a coin.
async fn post_bond(r: &mut Running, limit: u64) {
	let notice = server::bond::min_notice_seconds(server::bond::LIFETIME, arca_covenant::RelativeTime::from_units(338).unwrap())
		.div_ceil(512) as u16;
	let w = keypair("supervised W");
	let s_key = keypair("operator");
	let chain = arca_covenant::Chain::new(r.rt.client().genesis_hash().unwrap());
	let policy = arca_covenant::bond::BondPolicy::new(chain, s_key.x_only_public_key().0, w.x_only_public_key().0,
		arca_covenant::RelativeTime::from_units(notice).unwrap()).unwrap();
	let x = r.x;
	let tx = r.pay_to(policy.script_pubkey(), x, 50_000_000);
	r.produce().await;
	r.bury().await;
	let vout = tx.output.iter().position(|o| o.script_pubkey == policy.script_pubkey()).unwrap() as u32;
	r.config.bond = Some(server::bond::BondSection { withdraw_key: w.x_only_public_key().0.to_string(), notice_units: notice,
		outpoint: Some(format!("{}:{}", tx.txid(), vout)), notice: None, instant_budget_fraction: None,
		instant_limit_value: Some(limit.to_string()) });
	r.restart_server().await;
	r.synced().await;
}

/// With the operator's bond posted, so the wallet applies an instant limit
/// and a trade gives a coin of exactly its value, shaped by a payment to
/// itself first: beside an older build (`ARCA_CLI_OLDER`), skipped without
/// one.
///
/// - The only coin of Z the older maker reads is still arriving: the
///   refusal says so, not that the maker is an older build.
/// - Under the switch, this build refuses the older maker's offer before
///   anything moves: no coin is shaped first.
/// - Under the switch, the older build refuses this build's offer, whose
///   give coin is shaped, before it signs.
#[tokio::test(flavor = "multi_thread")]
async fn with_an_instant_limit_a_refusal_names_its_cause_and_nothing_moves_first() {
	let Some(older) = std::env::var("ARCA_CLI_OLDER").ok() else {
		println!("LD: no ARCA_CLI_OLDER: old against new not run");
		return;
	};
	let older = std::path::Path::new(&older);
	let mut r = Running::start().await;
	let iss = serve_z(&mut r).await;
	post_bond(&mut r, 1_000_000_000_000).await;
	let (z, x) = (iss.z.to_string(), r.x.to_string());
	let (url, node_url) = (r.url(), r.node_url());
	let (a, o) = (Arca::new("LIA"), Arca::built_from("LIO", older));
	for w in [&a, &o] {
		w.ok(&create_args(&url, &node_url));
		for (asset, v) in [(iss.z, 4_000_000), (r.x, 4_000_000)] {
			let s = script(&w.ok(&["address"]));
			r.pay_to(s, asset, v);
		}
	}
	r.produce().await;
	for asset in [&z, &x, &x] {
		for w in [&a, &o] {
			w.ok(&["board", asset, "1000000"]);
		}
		r.produce().await;
	}
	r.bury().await;
	r.synced().await;
	for w in [&a, &o] {
		r.wait("the boards credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
		w.ok(&["sync"]);
	}
	// A's board of Z is landing-2; the older build pays it a landing-1 coin,
	// which arrives under a small limit.
	a.ok(&["instant-limit", "1000"]);
	let req = a.ok(&["receive", "--asset", &z, "--amount", "500000"])["request"].as_str().unwrap().to_string();
	o.ok(&["send", &req]);
	a.ok(&["sync"]);

	// ---- R1: the coin the older maker reads is arriving -----------------------
	let offer = o.ok(&["swap", "offer", "--give-asset", &x, "--give", "100000", "--want-asset", &z, "--want", "100000"]);
	let m = a.refused(&["swap", "accept", offer["offer"].as_str().unwrap()], "still arriving");
	println!("REFUSED, the readable coin arriving: {}", m);
	// Never "settle first": a round would make the arriving coin a landing-2
	// leaf (Z is supervised), which the older maker reads no better, so a
	// program settling on that answer would settle forever.
	let (ok, v) = a.run(&["swap", "accept", offer["offer"].as_str().unwrap()]);
	assert!(!ok && v["error"]["kind"] == "refused", "nothing is named to settle first for a side that reads no landing-2: {}", v);
	o.ok(&["swap", "cancel", offer["swap"].as_str().unwrap()]);

	// ---- R2: the switch on, the older maker's offer, nothing shaped first ----
	a.ok(&["instant-limit", "1000000000000"]);
	a.ok(&["sync"]);
	r.config.landing_2_only = true;
	r.restart_server().await;
	a.ok(&["sync"]);
	let before = states_of(&a, &z);
	let offer = o.ok(&["swap", "offer", "--give-asset", &x, "--give", "100000", "--want-asset", &z, "--want", "100000"]);
	let m = a.refused(&["swap", "accept", offer["offer"].as_str().unwrap()], "landing_2_only");
	a.ok(&["sync"]);
	assert_eq!(states_of(&a, &z), before, "no coin of Z was shaped or spent before the refusal");
	println!("REFUSED the older maker's offer under the switch, A's Z coins as they were ({}): {}", before.len(), m);
	o.ok(&["swap", "cancel", offer["swap"].as_str().unwrap()]);

	// ---- F1 with a shaped give coin --------------------------------------------
	let offer = a.ok(&["swap", "offer", "--give-asset", &x, "--give", "150000", "--want-asset", &z, "--want", "100000"]);
	let before = states(&o);
	let (ok, v, _) = o.run_full(&["swap", "accept", offer["offer"].as_str().unwrap()]);
	assert!(!ok && v.to_string().contains("landing"), "the older build took a landing-2 offer: {}", v);
	assert_eq!(states(&o), before, "the older build's coins keep their states");
	println!("REFUSED by the older build, this build's give coin shaped: {}", v["error"]["message"]);
	for w in [&a, &o] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
