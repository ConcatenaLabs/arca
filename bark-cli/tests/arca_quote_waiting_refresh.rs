//! A coin given up in a refresh that waits stays the wallet's to trade with,
//! from a quote on, and `sync` frees any refresh that has waited too long.
//!
//! 1. B gives up a coin it received in a refresh. `coins` names the refresh
//!    the coin waits in. An offboard's, a distribution's, an on-chain order's
//!    and a resting order's quote, and a swap's read, each count the coin as
//!    B's to pay with, say which refresh the trade takes back first
//!    (`takes_back`), and take nothing back: the operator still holds the
//!    refresh pending. The swap, accepted on the terms read, takes the
//!    refresh back and pays with the coin.
//! 2. B quotes an offboard from such a coin, and a round takes the refresh
//!    before the offboard runs: the offboard is refused, nothing is taken
//!    back or signed for it, and the refresh completes as any other; the coin
//!    is spent once, by its round.
//! 3. E gives up a coin with `participate`, which keeps no time it gave the
//!    coin up, as an earlier wallet's refresh does not: the round leaves it
//!    waiting for the operator's funds. `sync` leaves it pending before it
//!    has waited two minutes, and takes it back at the first `sync` after.
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

fn create_args<'a>(server: &'a str, node: &'a str) -> Vec<&'a str> {
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

fn coin_of(w: &Arca, leaf: &str) -> Value {
	w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).cloned().unwrap_or(Value::Null)
}

/// One command of the library on the wallet in `a`'s directory, as a
/// program that embeds the library runs it.
fn library(a: &Arca, cmd: &str, args: Value) -> Result<Value, String> {
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run(&mut w, cmd, &args).map(|v| v["result"].clone()).map_err(|e| e.to_string())
	})
}

/// Creates `w` and boards `amount` of each asset of `assets`, paying each
/// board's fee in X; waits until every board is final and credited.
async fn boarded(r: &mut Running, w: &Arca, assets: &[(AssetId, u64)]) {
	w.ok(&create_args(&r.url(), &r.node_url()));
	let x = r.x;
	for (a, v) in assets {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, *a, v + 3_000_000);
	}
	let s = script(&w.ok(&["address"]));
	r.pay_to(s, x, 3_000_000);
	r.produce().await;
	for (a, v) in assets {
		w.ok(&["board", &a.to_string(), &v.to_string(), "--fee-asset", &x.to_string()]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards to be credited", || {
		w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")
	}).await;
	w.ok(&["sync"]);
}

/// `from` pays `to` `amount` of `asset` out of round; the coin `to` holds.
fn pay(from: &Arca, to: &Arca, asset: AssetId, amount: u64) -> String {
	let req = to.ok(&["receive"])["request"].as_str().unwrap().to_string();
	from.ok(&["send", &req, "--amount", &amount.to_string(), "--asset", &asset.to_string()]);
	let mb = to.ok(&["mailbox"]);
	mb["accepted"].as_array().unwrap().iter().find(|c| c["value"].as_str() == Some(&amount.to_string()) || c["value"] == amount)
		.or_else(|| mb["accepted"].as_array().unwrap().last())
		.and_then(|c| c["leaf_id"].as_str()).expect("the payee holds the coin").to_string()
}

fn server_state(r: &Running, pid: &str) -> Value {
	let body = json!({"participation_id": pid});
	let resp = minreq::post(format!("{}/v1/participation_status", r.url())).with_header("Content-Type", "application/json")
		.with_body(body.to_string()).send().unwrap();
	serde_json::from_str(resp.as_str().unwrap()).unwrap()
}

/// B, holding only a received coin of `amount` of X given up in a refresh
/// the operator holds pending: the coin and the refresh.
async fn given_up(r: &mut Running, a: &Arca, b: &Arca, amount: u64) -> (String, String) {
	b.ok(&create_args(&r.url(), &r.node_url()));
	let got = pay(a, b, r.x, amount);
	let rb = b.ok(&["refresh-received"]);
	assert_eq!(rb["refreshed"][0], got.as_str(), "{}", rb);
	let pid = rb["participations"][0]["participation"].as_str().unwrap().to_string();
	assert_eq!(coin_of(b, &got)["state"], "given");
	assert_eq!(server_state(r, &pid)["state"], "pending");
	(got, pid)
}

fn takes_back(q: &Value, pid: &str, coin: &str) {
	assert_eq!(q["takes_back"], json!([{"participation": pid, "coins": [coin]}]), "{}", q);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_quote_counts_a_coin_in_a_waiting_refresh_and_the_trade_takes_it_back() {
	let mut r = Running::start().await;
	let (x, y) = (r.x, r.y);
	let (a, b) = (Arca::new("RW2QA"), Arca::new("RW2QB"));
	boarded(&mut r, &a, &[(x, 3_000_000), (y, 3_000_000)]).await;
	let (got, pid) = given_up(&mut r, &a, &b, 600_000).await;
	let (xs, ys) = (x.to_string(), y.to_string());

	// The coin names the refresh it waits in.
	assert_eq!(coin_of(&b, &got)["refresh_waiting"], pid.as_str());

	// An offboard's quote.
	let address = a.ok(&["address"])["address"].as_str().unwrap().to_string();
	let q = b.ok(&["offboard", "--asset", &xs, "--amount", "400000", "--address", &address, "--quote"]);
	println!("RW2 quote: offboard: fee {} gives {} takes_back {}", q["fee"], q["gives"], q["takes_back"]);
	takes_back(&q, &pid, &got);

	// A distribution's quote.
	let claims = b.dir.join("claims.txt");
	std::fs::write(&claims, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 300000\n").unwrap();
	let q = b.ok(&["distribute", claims.to_str().unwrap(), "--asset", &xs, "--quote"]);
	println!("RW2 quote: distribute: fee {} coins {} takes_back {}", q["fee"], q["coins"], q["takes_back"]);
	takes_back(&q, &pid, &got);

	// An on-chain order's quote and a resting order's quote.
	let order = |verb: &str| -> Vec<String> {
		["order", verb, "--sell", &xs, "--amount", "400000", "--for", &ys, "--rate-num", "1", "--rate-den", "1", "--min-lot", "100000",
			"--expires-in-hours", "720", "--quote"].iter().map(|s| s.to_string()).collect()
	};
	for verb in ["place", "rest"] {
		let v = order(verb);
		let q = b.ok(&v.iter().map(|s| s.as_str()).collect::<Vec<_>>());
		println!("RW2 quote: order {}: fee {} gives {} takes_back {}", verb, q["fee"], q["gives"], q["takes_back"]);
		takes_back(&q, &pid, &got);
	}

	// A swap's read: A gives 200,000 of Y for 300,000 of X.
	let offer = library(&a, "swap_offer", json!({"give_asset": ys, "give": "200000", "want_asset": xs, "want": "300000"})).unwrap();
	let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap();
	println!("RW2 quote: swap_read: gives {} pays {} change {} takes_back {}", read["gives"], read["pays"], read["change"],
		read["takes_back"]);
	takes_back(&read, &pid, &got);

	// Nothing was taken back by any quote.
	let st = server_state(&r, &pid);
	println!("RW2 quote: after five quotes the refresh is {}, the coin {}", st["state"], coin_of(&b, &got)["state"]);
	assert_eq!(st["state"], "pending");
	assert_eq!(coin_of(&b, &got)["state"], "given");

	// The swap, accepted on the terms read: the refresh is taken back first.
	let accept = library(&b, "swap_accept", json!({"offer": offer["offer"], "shown": read})).unwrap();
	let st = server_state(&r, &pid);
	println!("RW2 quote: swap_accept: refresh {} ({}); coin {}", st["state"], st["void_reason"], coin_of(&b, &got)["state"]);
	assert_eq!(st["state"], "void", "{}", st);
	let done = library(&a, "swap_complete", json!({"accept": accept["accept"]})).unwrap();
	println!("RW2 quote: swap_complete: {}", done["swap"]);
	b.ok(&["mailbox"]);
	assert_eq!(coin_of(&b, &got)["state"], "spent", "the coin paid the swap");
	let ys_live: u64 = b.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == ys.as_str())
		.map(|c| c["value"].as_str().unwrap().parse::<u64>().unwrap()).sum();
	println!("RW2 quote: B now holds {} of Y live", ys_live);
	assert_eq!(ys_live, 200_000);
	assert!(r.server.rounds.run_rounds().await.unwrap().0.is_empty(), "no round for the refresh taken back");
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn a_round_that_takes_the_refresh_after_the_quote_fails_the_trade_cleanly() {
	let mut r = Running::start().await;
	let x = r.x;
	let (a, b) = (Arca::new("RW2RA"), Arca::new("RW2RB"));
	boarded(&mut r, &a, &[(x, 3_000_000)]).await;
	let (got, pid) = given_up(&mut r, &a, &b, 600_000).await;
	let xs = x.to_string();
	let address = a.ok(&["address"])["address"].as_str().unwrap().to_string();
	let args = ["offboard", "--asset", xs.as_str(), "--amount", "400000", "--address", address.as_str()];
	let mut quote = args.to_vec();
	quote.push("--quote");
	let q = b.ok(&quote);
	takes_back(&q, &pid, &got);

	// The round takes the refresh before the offboard runs.
	let (built, errs) = r.server.rounds.run_rounds().await.unwrap();
	assert!(errs.is_empty(), "{:?}", errs);
	assert_eq!(built.len(), 1);
	println!("RW2 race: round {} took the refresh: {}", built[0].tx.txid(), server_state(&r, &pid)["state"]);
	assert_eq!(server_state(&r, &pid)["state"], "issued");
	let shown = q.to_string();
	let mut run = args.to_vec();
	run.extend(["--shown", shown.as_str()]);
	let (ok, v) = b.run(&run);
	println!("RW2 race: the offboard on the quote shown: ok {} {}", ok, v);
	assert!(!ok, "the offboard is refused once the round took the coin");
	assert!(v.to_string().contains("live coins of asset"), "refused for want of live coins: {}", v);
	assert_eq!(coin_of(&b, &got)["state"], "given", "the coin is still given up in its round");
	let offboards = b.ok(&["participations"]).as_array().unwrap().len();
	assert_eq!(offboards, 1, "no participation for the offboard");

	// The round completes the refresh: the coin is spent once, by it.
	r.produce().await;
	r.bury().await;
	r.round_state(&built[0].tx.txid(), RoundState::Final).await;
	b.ok(&["sync"]);
	let parts = b.ok(&["participations"]);
	println!("RW2 race: after the round: {}", parts);
	assert_eq!(parts[0]["state"], "released", "{}", parts);
	assert_eq!(coin_of(&b, &got)["state"], "spent");
	let live: Vec<Value> = b.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live").cloned().collect();
	assert_eq!(live.len(), 1, "the refresh's new leaf: {:?}", live);
	println!("RW2 race: B holds its new leaf {} of {}", live[0]["leaf_id"], live[0]["value"]);
	// The new leaf pays the offboard.
	let q2 = b.ok(&quote);
	assert!(q2.get("takes_back").is_none(), "{}", q2);
	let shown2 = q2.to_string();
	let mut run2 = args.to_vec();
	run2.extend(["--shown", shown2.as_str()]);
	let off = b.ok(&run2);
	println!("RW2 race: the offboard from the new leaf: {}", off["state"]);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_takes_back_a_waiting_refresh_that_kept_no_given_up_time() {
	let mut r = Running::start().await;
	let (x, y) = (r.x, r.y);
	let (a, e) = (Arca::new("RW2WA"), Arca::new("RW2WE"));
	boarded(&mut r, &a, &[(x, 2_000_000), (y, 120_000_000)]).await;
	e.ok(&create_args(&r.url(), &r.node_url()));
	let ey = pay(&a, &e, y, 60_000_000);
	let pe = e.ok(&["participate", "--leaf", &ey]);
	let pid = pe["participations"][0]["participation"].as_str().unwrap().to_string();
	assert_eq!(coin_of(&e, &ey)["refresh_waiting"], pid.as_str());
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	let st = server_state(&r, &pid);
	println!("RW2 sync: {} round(s); E's refresh {} waiting {:?}", built.len(), st["state"], st["waiting"]);
	assert_eq!(st["state"], "pending");
	assert!(st["waiting"].as_str().unwrap_or("").contains("too little of this asset"), "{}", st);

	// Not before it has waited two minutes.
	let early = e.ok(&["sync"]);
	let mine = early["participations"].as_array().unwrap().iter().find(|p| p["participation"] == pid.as_str()).cloned().unwrap();
	println!("RW2 sync: early: {}", mine);
	assert_eq!(mine["state"], "pending");
	assert_eq!(server_state(&r, &pid)["state"], "pending");

	tokio::time::sleep(std::time::Duration::from_secs(bark::arca::WITHDRAW_AFTER + 5)).await;
	let later = e.ok(&["sync"]);
	let mine = later["participations"].as_array().unwrap().iter().find(|p| p["participation"] == pid.as_str()).cloned().unwrap();
	println!("RW2 sync: after {} s: {}", bark::arca::WITHDRAW_AFTER + 5, mine);
	assert_eq!(mine["state"], "void", "{}", mine);
	assert_eq!(server_state(&r, &pid)["state"], "void");
	assert_eq!(coin_of(&e, &ey)["state"], "live");
	assert!(coin_of(&e, &ey).get("refresh_waiting").is_none());
	let to_a = pay(&e, &a, y, 10_000_000);
	println!("RW2 sync: the freed coin pays A {}", to_a);
	for w in [&a, &e] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
