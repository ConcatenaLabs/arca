//! Several assets, as the `arca` wallet meets them: each asset is refreshed
//! in that asset's own rounds, one participation per asset, against a whole
//! Arca server serving X (listed for fees) and Y (not listed), on an
//! anchored proof-of-stake regtest chain.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::Script;
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

/// The coins of `w` in `state`.
fn coins_in(w: &Arca, state: &str) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == state).cloned().collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_refreshes_each_asset_in_its_own_round() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("AS1");
	a.ok(&create_args(&url, &node));
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, r.x, 10_000_000);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, r.x, 1_000_000);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, r.y, 10_000_000);
	r.produce().await;
	let bx = a.ok(&["board", &x, "2000000"])["leaf_id"].as_str().unwrap().to_string();
	let by = a.ok(&["board", &y, "3000000", "--fee-asset", &x])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("both boards credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
	assert_eq!(coins_in(&a, "live").len(), 2);

	// Every live coin: a participation for each asset.
	let p = a.ok(&["participate"]);
	let ps = p["participations"].as_array().unwrap_or_else(|| panic!("a participation per asset: {}", p)).clone();
	assert_eq!(ps.len(), 2, "{}", p);
	let of = |asset: &str| ps.iter().find(|q| q["asset"] == asset).cloned().unwrap_or_else(|| panic!("none in {}: {}", asset, p));
	let (px, py) = (of(&x), of(&y));
	for (q, board) in [(&px, &bx), (&py, &by)] {
		assert_eq!(q["state"], "pending", "{}", q);
		assert_eq!(q["gives"], serde_json::json!([board]), "{}", q);
		assert_eq!(q["wants"].as_array().unwrap().len(), 1, "{}", q);
	}
	assert!(py["exit_needs_fee_coin"].is_object() && px.get("exit_needs_fee_coin").is_none(), "{}", p);

	// A round for each, X's first in the order the operator serves them.
	let rx = r.server.rounds.run_round().await.unwrap().expect("X's round");
	let ry = r.server.rounds.run_round().await.unwrap().expect("Y's round");
	println!("X's round {} batches {:?}; Y's round {} batches {:?}", rx.tx.txid(), rx.batches, ry.tx.txid(), ry.batches);
	assert_eq!((rx.batches.len(), rx.batches[0].0), (1, r.x));
	assert_eq!((ry.batches.len(), ry.batches[0].0), (1, r.y));
	r.produce().await;
	r.bury().await;
	r.round_state(&rx.tx.txid(), RoundState::Final).await;
	r.round_state(&ry.tx.txid(), RoundState::Final).await;

	// Both released; a new leaf in each asset, each on its own round.
	let s = a.ok(&["sync"]);
	let done = s["participations"].as_array().unwrap();
	assert_eq!(done.len(), 2, "{}", s);
	let live = coins_in(&a, "live");
	assert_eq!(live.len(), 2, "{:?}", live);
	for (q, asset, value, round) in [(&px, &x, "2000000", rx.tx.txid()), (&py, &y, "3000000", ry.tx.txid())] {
		let d = done.iter().find(|d| d["participation"] == q["participation"]).unwrap_or_else(|| panic!("{} in {}", q, s));
		assert_eq!(d["state"], "released", "{}", d);
		assert_eq!(d["round"], round.to_string(), "the participation in {} ran in its own round: {}", asset, d);
		let leaf = d["new_leaves"][0]["leaf_id"].as_str().unwrap();
		let c = live.iter().find(|c| c["leaf_id"] == leaf).unwrap_or_else(|| panic!("the new leaf {}: {:?}", leaf, live));
		assert_eq!((c["asset"].as_str(), c["kind"].as_str(), c["value"].as_str()), (Some(asset.as_str()), Some("batch"), Some(value)), "{}", c);
		println!("the new leaf of {}: {} {}, resting on round {}", asset, c["value"], c["kind"], round);
	}
	let _ = std::fs::remove_dir_all(&a.dir);
}
