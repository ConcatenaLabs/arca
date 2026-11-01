//! A refresh of received coins never holds a coin the wallet needs: the
//! wallet gives up only what the operator can fund, takes back a refresh
//! that waits, and takes one back first when it pays with its coins.
//!
//! 1. B gives up a coin it received in a refresh, then pays more than its
//!    live coins hold: the payment takes the refresh back
//!    (`withdraw_participation`) and pays from the coin; the operator holds
//!    the refresh void and builds no round for it.
//! 2. The operator can fund 50,000,000 of Y. B received 600,000 of X and
//!    55,000,000 of Y: `refresh-received` gives up the X coin and leaves the
//!    Y coin live, and the X refresh runs. C and D each received 30,000,000
//!    of Y and gave it up; the round takes one, and the other waits for the
//!    operator's funds. Its wallet takes it back once it has waited two
//!    minutes, not before; the coin is live again and pays, and is not given
//!    up again at once.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::{AssetId, Script, Transaction};
use serde_json::Value;

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

/// Every round the operator can build now, each made final.
async fn rounds_final(r: &Running) -> Vec<Transaction> {
	let (built, errs) = r.server.rounds.run_rounds().await.unwrap();
	assert!(errs.is_empty(), "{:?}", errs);
	r.produce().await;
	r.bury().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	built.into_iter().map(|b| b.tx).collect()
}

fn server_state(r: &Running, pid: &str) -> Value {
	let body = serde_json::json!({"participation_id": pid});
	let resp = minreq::post(format!("{}/v1/participation_status", r.url())).with_header("Content-Type", "application/json")
		.with_body(body.to_string()).send().unwrap();
	serde_json::from_str(resp.as_str().unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_payment_from_a_coin_in_a_waiting_refresh_takes_it_back_first() {
	let mut r = Running::start().await;
	let x = r.x;
	let (a, b, c) = (Arca::new("RW1PayA"), Arca::new("RW1PayB"), Arca::new("RW1PayC"));
	boarded(&mut r, &a, &[(x, 3_000_000)]).await;
	b.ok(&create_args(&r.url(), &r.node_url()));
	c.ok(&create_args(&r.url(), &r.node_url()));
	let got = pay(&a, &b, x, 600_000);
	let rb = b.ok(&["refresh-received"]);
	println!("RW1 pay: B's refresh-received: {}", rb);
	assert_eq!(rb["refreshed"][0], got.as_str(), "{}", rb);
	let pid = rb["participations"][0]["participation"].as_str().unwrap().to_string();
	assert_eq!(coin_of(&b, &got)["state"], "given");
	assert_eq!(server_state(&r, &pid)["state"], "pending");

	// B pays 500,000: its only coin is given up in the refresh.
	let paid = pay(&b, &c, x, 500_000);
	println!("RW1 pay: C holds {}", paid);
	let st = server_state(&r, &pid);
	println!("RW1 pay: the refresh at the operator: {} ({})", st["state"], st["void_reason"]);
	assert_eq!(st["state"], "void", "{}", st);
	let parts = b.ok(&["participations"]);
	let mine = parts.as_array().unwrap().iter().find(|p| p["participation"] == pid.as_str()).unwrap();
	assert_eq!(mine["state"], "void", "{}", mine);
	assert_eq!(coin_of(&b, &got)["state"], "spent", "the coin paid C");
	assert!(r.server.rounds.run_rounds().await.unwrap().0.is_empty(), "no round for the refresh taken back");
	for w in [&a, &b, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_waiting_for_funds_is_taken_back_and_one_asset_short_leaves_the_others() {
	let mut r = Running::start().await;
	let (x, y) = (r.x, r.y);
	let info: Value = serde_json::from_str(minreq::get(format!("{}/v1/info", r.url())).send().unwrap().as_str().unwrap()).unwrap();
	let fundable_y = info["assets"].as_array().unwrap().iter().find(|a| a["asset"] == y.to_string()).unwrap()["fundable"].clone();
	println!("RW1 short: the operator can fund {} of Y", fundable_y);
	let (a, b, c, d) = (Arca::new("RW1ShortA"), Arca::new("RW1ShortB"), Arca::new("RW1ShortC"), Arca::new("RW1ShortD"));
	boarded(&mut r, &a, &[(x, 2_000_000), (y, 120_000_000)]).await;
	for w in [&b, &c, &d] {
		w.ok(&create_args(&r.url(), &r.node_url()));
	}
	let bx = pay(&a, &b, x, 600_000);
	let by = pay(&a, &b, y, 55_000_000);
	let cy = pay(&a, &c, y, 30_000_000);
	let dy = pay(&a, &d, y, 30_000_000);

	// One asset short: B's X coin is given up, its Y coin stays live.
	let rb = b.ok(&["refresh-received"]);
	println!("RW1 short: B's refresh-received: {}", rb);
	assert_eq!(rb["refreshed"].as_array().unwrap().len(), 1, "{}", rb);
	assert_eq!(rb["refreshed"][0], bx.as_str());
	let left = rb["left"].as_array().unwrap().iter().find(|l| l["leaf_id"] == by.as_str()).expect("the Y coin is left");
	assert!(left["why"].as_str().unwrap().contains("cannot fund"), "{}", left);
	assert_eq!(coin_of(&b, &by)["state"], "live");

	// C and D each see 50,000,000 of Y fundable and give up 30,000,000.
	let rc = c.ok(&["refresh-received"]);
	let rd = d.ok(&["refresh-received"]);
	let pc = rc["participations"][0]["participation"].as_str().unwrap().to_string();
	let pd = rd["participations"][0]["participation"].as_str().unwrap().to_string();
	let rounds = rounds_final(&r).await;
	println!("RW1 short: {} round(s) built", rounds.len());
	let sb = b.ok(&["sync"]);
	let bp = sb["participations"].as_array().unwrap().iter().find(|p| p["new_leaves"].is_array()).cloned().unwrap_or(Value::Null);
	println!("RW1 short: B's X refresh: {} {}", bp["state"], bp["new_leaves"]);
	assert_eq!(bp["state"], "released", "B's X refresh ran beside the Y short: {}", sb);
	let (sc, sd) = (server_state(&r, &pc), server_state(&r, &pd));
	println!("RW1 short: C's {} waiting {:?}; D's {} waiting {:?}", sc["state"], sc["waiting"], sd["state"], sd["waiting"]);
	let (w, wp, wc) = match (sc["state"].as_str(), sd["state"].as_str()) {
		(Some("issued"), Some("pending")) => (&d, pd.clone(), dy.clone()),
		(Some("pending"), Some("issued")) => (&c, pc.clone(), cy.clone()),
		other => panic!("one of the two runs and the other waits: {:?}", other),
	};
	let waiting = server_state(&r, &wp)["waiting"].as_str().unwrap_or("").to_string();
	assert!(waiting.contains("too little of this asset"), "it waits for the operator's funds: {}", waiting);

	// Not taken back before it has waited two minutes.
	let early = w.ok(&["sync"]);
	assert_eq!(server_state(&r, &wp)["state"], "pending", "{}", early);
	assert_eq!(coin_of(w, &wc)["state"], "given");
	tokio::time::sleep(std::time::Duration::from_secs(bark::arca::WITHDRAW_AFTER + 5)).await;
	let later = w.ok(&["sync"]);
	let taken = later["participations"].as_array().unwrap().iter().find(|p| p["participation"] == wp.as_str()).cloned().unwrap();
	println!("RW1 short: taken back: {}", taken);
	assert_eq!(taken["state"], "void", "{}", taken);
	assert_eq!(server_state(&r, &wp)["state"], "void");
	assert_eq!(coin_of(w, &wc)["state"], "live");
	let again = w.ok(&["refresh-received"]);
	assert_eq!(again["participations"].as_array().unwrap().len(), 0, "not given up again at once: {}", again);
	assert!(again["left"][0]["why"].as_str().unwrap().contains("taken back"), "{}", again);
	// The coin pays.
	let to_a = pay(w, &a, y, 10_000_000);
	println!("RW1 short: A holds {} from the coin taken back", to_a);
	// And B's Y coin, never given up, pays too.
	pay(&b, &a, y, 1_000_000);
	for w in [&a, &b, &c, &d] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
