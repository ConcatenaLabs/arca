//! A refresh in pieces: the coins given up come back as leaves of a size the
//! wallet names (`piece`), up to `pieces` of them, and one leaf of the rest.
//! A program that keeps coins of a bounded size (a maker, whose swap puts the
//! whole coin it pays from out of round) cuts them inside a round, never by a
//! payment to itself out of round.
//!
//! 1. A boards 3,000,000 of X and refreshes the board in pieces of 500,000,
//!    four of them, through the library's `quote` and `participate`: the
//!    quote names the leaves, the round issues them, and A holds four live
//!    leaves of 500,000 and one of the 1,000,000 left, worth all it gave up.
//! 2. A refresh of a coin smaller than four pieces gives as many pieces as
//!    it holds and the rest; a rest below the operator's smallest leaf is
//!    never left alone.
//! 3. Refused before anything is signed: pieces below twice the operator's
//!    smallest leaf, `pieces` without a `piece`, and shown fees that differ.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::{AssetId, Script};
use serde_json::{json, Value};

use bark::arca::{command, Wallet};
use common::cli::Arca;
use common::running::Running;
use server::store::RoundState;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

fn library(a: &Arca, cmd: &str, args: Value) -> Result<Value, String> {
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run(&mut w, cmd, &args).map(|v| v["result"].clone()).map_err(|e| e.to_string())
	})
}

fn live(a: &Arca, asset: AssetId) -> Vec<Value> {
	a.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == asset.to_string().as_str()).cloned().collect()
}

fn value(c: &Value) -> u64 {
	c["value"].as_str().unwrap().parse().unwrap()
}

async fn boarded(r: &mut Running, w: &Arca, asset: AssetId, amount: u64) -> String {
	w.ok(&["create", "--server", &r.url(), "--node-url", &r.node_url(), "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	let s = script(&w.ok(&["address"]));
	r.pay_to(s, asset, amount + 3_000_000);
	r.produce().await;
	w.ok(&["board", &asset.to_string(), &amount.to_string(), "--fee-asset", &asset.to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || {
		w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")
	}).await;
	w.ok(&["sync"]);
	let coins = live(w, asset);
	assert_eq!(coins.len(), 1, "{:?}", coins);
	coins[0]["leaf_id"].as_str().unwrap().to_string()
}

/// Gives up `leaf` in a refresh cut into `piece` (`pieces` of them), runs
/// the round to final, and answers the new leaves' values, largest last.
async fn refreshed_in_pieces(r: &mut Running, a: &Arca, leaf: &str, piece: u64, pieces: u64) -> (Value, Vec<u64>) {
	let args = json!({"leaves": [leaf], "piece": piece.to_string(), "pieces": pieces});
	let q = library(a, "quote", args.clone()).unwrap();
	let mut p = args.clone();
	p["shown"] = q["coins"].clone();
	let made = library(a, "participate", p).unwrap();
	let part = &made["participations"][0];
	assert_eq!(part["state"], "pending", "{}", made);
	assert_eq!(part["wants"].as_array().unwrap().len(), q["pieces"].as_object().unwrap().values().next().unwrap().as_array().unwrap().len(),
		"the participation wants the leaves the quote named: {} {}", q, made);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let round = built.tx.txid();
	println!("RP round {}: {} vB for {} leaves", round, built.tx.vsize(), part["wants"].as_array().unwrap().len());
	r.produce().await;
	a.ok(&["sync"]);
	r.bury().await;
	r.round_state(&round, RoundState::Final).await;
	let s = a.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s);
	let mut v: Vec<u64> = s["participations"][0]["new_leaves"].as_array().unwrap().iter()
		.map(|n| a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == n["leaf_id"]).map(value).unwrap()).collect();
	v.sort();
	(q, v)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_in_pieces_gives_leaves_of_the_size_asked_and_a_reserve() {
	let mut r = Running::start().await;
	let x = r.x;
	let a = Arca::new("RP1A");
	let board = boarded(&mut r, &a, x, 3_000_000).await;

	// 1. Four pieces of 500,000 and a reserve of the rest.
	let (q, got) = refreshed_in_pieces(&mut r, &a, &board, 500_000, 4).await;
	let fee: u64 = q["coins"][0]["fee"].as_str().unwrap().parse().unwrap();
	println!("RP1 quote pieces {} fee {}; new leaves {:?}", q["pieces"], fee, got);
	assert_eq!(q["pieces"][x.to_string()], json!(["500000", "500000", "500000", "500000", (1_000_000 - fee).to_string()]), "{}", q);
	let mut want = vec![500_000; 4];
	want.push(1_000_000 - fee);
	want.sort();
	assert_eq!(got, want);
	let now = live(&a, x);
	assert_eq!(now.len(), 5);
	assert!(now.iter().all(|c| c["kind"] == "batch"), "{:?}", now);
	assert_eq!(now.iter().map(value).sum::<u64>(), 3_000_000 - fee, "worth all it gave up, less the fee");

	// 2. The reserve (1,000,000) in pieces of 300,000: three pieces and a
	// rest of 100,000 less the fee, or the last piece and a small rest
	// halved, never a leaf above a piece.
	let reserve = now.iter().max_by_key(|c| value(c)).unwrap()["leaf_id"].as_str().unwrap().to_string();
	let (q2, got2) = refreshed_in_pieces(&mut r, &a, &reserve, 300_000, 14).await;
	println!("RP2 quote pieces {}; new leaves {:?}", q2["pieces"], got2);
	assert!(got2.iter().all(|v| *v <= 300_000), "{:?}", got2);
	assert_eq!(got2.len(), 4, "{:?}", got2);

	// 3. Refusals, before anything is signed.
	let small = live(&a, x).iter().min_by_key(|c| value(c)).unwrap()["leaf_id"].as_str().unwrap().to_string();
	let e = library(&a, "quote", json!({"leaves": [small], "piece": "1"})).unwrap_err();
	println!("RP3 piece 1: {}", e);
	assert!(e.contains("below twice the operator's smallest leaf"), "{}", e);
	let e = library(&a, "quote", json!({"leaves": [small], "pieces": 4})).unwrap_err();
	println!("RP3 pieces alone: {}", e);
	assert!(e.contains("pieces without a piece"), "{}", e);
	let q3 = library(&a, "quote", json!({"leaves": [small], "piece": "100000"})).unwrap();
	let mut wrong = q3["coins"].clone();
	wrong[0]["fee"] = json!("1");
	let e = library(&a, "participate", json!({"leaves": [small], "piece": "100000", "shown": wrong})).unwrap_err();
	println!("RP3 shown differs: {}", e);
	assert!(e.contains("changed since they were shown"), "{}", e);
	assert_eq!(live(&a, x).iter().find(|c| c["leaf_id"] == small.as_str()).unwrap()["state"], "live", "nothing given up");
	let _ = std::fs::remove_dir_all(&a.dir);
}
