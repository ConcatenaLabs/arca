//! Several assets, as the `arca` wallet meets them: each asset is refreshed
//! in that asset's own rounds, one participation per asset, and charged its
//! own schedule, against a whole Arca server serving X (listed for fees) and
//! Y (not listed), on an anchored proof-of-stake regtest chain.
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

/// A coin's fee in a refresh quote, and the schedule it was priced by.
fn quoted<'a>(quote: &'a Value, leaf: &str) -> &'a Value {
	quote.as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).unwrap_or_else(|| panic!("{} in {}", leaf, quote))
}

#[tokio::test(flavor = "multi_thread")]
async fn each_asset_is_charged_its_own_schedule() {
	// X charges 5,000 parts per million of a coin; Y the default 1,000 and
	// 400 atoms a coin.
	let mut r = Running::start_with(|c, x, y| {
		c.fees.refresh_ppm = 1_000;
		c.assets = vec![
			toml::from_str(&format!("asset = \"{}\"\nmin_leaf = \"1000\"\nrefresh_ppm = 5000\n", x)).unwrap(),
			toml::from_str(&format!("asset = \"{}\"\nmin_leaf = \"1000\"\nrefresh_base = \"400\"\n", y)).unwrap(),
		];
	}).await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("AS2");
	a.ok(&create_args(&url, &node));
	for (asset, v) in [(r.x, 10_000_000), (r.x, 1_000_000), (r.y, 10_000_000)] {
		let s = script(&a.ok(&["address"]));
		r.pay_to(s, asset, v);
	}
	r.produce().await;
	let bx = a.ok(&["board", &x, "2000000"])["leaf_id"].as_str().unwrap().to_string();
	let by = a.ok(&["board", &y, "30000", "--fee-asset", &x])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("both boards credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
	let info = a.ok(&["info"]);
	println!("the operator's schedules: X {}, Y {}", info["server_info"]["assets"][0]["fees"], info["server_info"]["assets"][1]["fees"]);

	// Y's coin of 30,000 would pay 400 atoms and more: above the wallet's
	// bound of 10,000 millionths of the coin. Refused before anything is
	// signed, by Y's own schedule.
	let why = a.refused(&["participate"], "--max-fee-ppm");
	assert!(why.contains(&by) && why.contains(&y), "the coin of Y, by Y's schedule: {}", why);
	assert_eq!(coins_in(&a, "live").len(), 2, "nothing was given up");

	// X's coin, by X's schedule; Y's with the bound raised for the command.
	let (ok, px, err) = a.run_full(&["participate", "--leaf", &bx]);
	assert!(ok, "{}", px);
	println!("X: stderr {:?}\n{}", err.trim(), px);
	let qx = quoted(&px["quote"], &bx);
	assert_eq!(qx["schedule"], serde_json::json!({"refresh_ppm": 5000, "refresh_base": "0"}), "{}", qx);
	assert!(err.contains(&format!("refresh fee for coin {}: {} of asset {}", bx, qx["fee"].as_str().unwrap(), x)), "shown first: {}", err);
	let fx: u64 = qx["fee"].as_str().unwrap().parse().unwrap();
	assert!(fx > 9_000 && fx <= 10_000, "5,000 millionths of 2,000,000, by the time left: {}", fx);
	assert_eq!(px["participations"][0]["fees"], serde_json::json!([{"asset": x, "amount": fx.to_string()}]));
	let (ok, py, err) = a.run_full(&["participate", "--leaf", &by, "--max-fee-ppm", "20000"]);
	assert!(ok, "{}", py);
	println!("Y: stderr {:?}\n{}", err.trim(), py);
	let qy = quoted(&py["quote"], &by);
	assert_eq!(qy["schedule"], serde_json::json!({"refresh_ppm": 1000, "refresh_base": "400"}), "{}", qy);
	let fy: u64 = qy["fee"].as_str().unwrap().parse().unwrap();
	assert!(fy > 400 && fy <= 430, "1,000 millionths of 30,000 and 400 a coin, by the time left: {}", fy);

	// A round for each; each new leaf holds its coin less its own fee.
	let (rounds, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty() && rounds.len() == 2, "{:?}", failed);
	r.produce().await;
	r.bury().await;
	for b in &rounds {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	let s = a.ok(&["sync"]);
	assert!(s["participations"].as_array().unwrap().iter().all(|q| q["state"] == "released"), "{}", s);
	let live = coins_in(&a, "live");
	for (asset, value) in [(&x, 2_000_000 - fx), (&y, 30_000 - fy)] {
		let c = live.iter().find(|c| c["asset"] == asset.as_str()).unwrap_or_else(|| panic!("{:?}", live));
		assert_eq!(c["value"], value.to_string(), "{}", c);
		println!("the new leaf of {}: {} (its coin less its fee)", asset, c["value"]);
	}
	let _ = std::fs::remove_dir_all(&a.dir);
}
