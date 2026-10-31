//! Claims that lapse, run with the `arca` binary against a whole Arca server
//! on an anchored proof-of-stake regtest chain. A payer pays three holders in
//! one round with `arca distribute --days 8`: each claim leaf is `claim-1`.
//! One holder takes its claim up at once (`arca claims` shows the deadline,
//! `arca claim` takes it up); two never do. Past the deadline the late
//! holder's `arca claim` takes nothing, saying why, and its `arca claims`
//! names the claim lapsing, not lost; the operator's watcher brings both
//! unclaimed leaves on the chain and lapses them to the payer's return
//! address, which `arca distributions` shows, and the payer's on-chain
//! balance takes them in. The holder that took its claim up still holds its
//! coin.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::io::Write;

use elements::Script;
use serde_json::Value;

use common::cli::Arca;
use common::running::Running;
use server::store::RoundState;

const HOUR: u32 = 3_600;
const DAY: u32 = 86_400;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

fn shown(p: &Arca) -> Value {
	p.ok(&["distributions"])[0].clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn claims_nobody_takes_up_lapse_back_to_the_payer() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca"];

	let payer = Arca::new("lapse payer");
	payer.ok(&create);
	r.pay_to(script(&payer.ok(&["address"])), r.x, 10_000_000);
	r.produce().await;
	payer.ok(&["board", &x, "5000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the payer's board to be credited", || payer.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	payer.ok(&["sync"]);

	let holders: Vec<Arca> = (0..3).map(|i| Arca::new(&format!("lapse holder {}", i))).collect();
	let mut keys = vec![];
	for h in &holders {
		h.ok(&create);
		keys.push(h.ok(&["address"])["key"].as_str().unwrap().to_string());
	}
	let path = payer.dir.join("claims.txt");
	let mut f = std::fs::File::create(&path).unwrap();
	for k in &keys {
		writeln!(f, "{} 1000000", k).unwrap();
	}
	let file = path.to_string_lossy().to_string();
	let quote = payer.ok(&["distribute", &file, "--asset", &x, "--quote"]);
	let fee = quote["fee"].as_str().unwrap().to_string();
	let d = payer.ok(&["distribute", &file, "--asset", &x, "--shown", &fee, "--days", "8"]);
	println!("distribute: {}", d);
	let deadline = d["deadline"].as_u64().unwrap() as u32;
	let allowance: u64 = d["lapse_allowance"].as_str().unwrap().parse().unwrap();
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	payer.ok(&["sync"]);
	let st = shown(&payer);
	assert_eq!(st["state"], "released", "{}", st);
	assert_eq!(st["lapse_deadline"].as_u64(), Some(deadline as u64), "{}", st);

	// Holder 0 takes its claim up, the deadline shown.
	let found = holders[0].ok(&["claims"]);
	println!("holder 0's claims: {}", found);
	assert_eq!(found[0]["state"], "open");
	assert_eq!(found[0]["deadline"].as_u64(), Some(deadline as u64));
	assert!(found[0]["note"].as_str().unwrap().contains("open until"), "{}", found);
	let taken = holders[0].ok(&["claim"]);
	assert!(taken[0]["taken_up"]["transfer_id"].is_string(), "{}", taken);

	// Past the deadline: holder 1 takes nothing and is told why.
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, deadline - now + HOUR));
	r.synced().await;
	let late = holders[1].ok(&["claim"]);
	println!("holder 1, late: {}", late);
	assert_eq!(late[0]["state"], "lapsing", "{}", late);
	let c = holders[1].ok(&["claims"]);
	assert!(c[0]["note"].as_str().unwrap().contains("nothing the wallet held is lost"), "{}", c);
	assert!(holders[1].ok(&["coins"]).as_array().unwrap().is_empty(), "no claim coin, no loss");

	// The watcher lapses both unclaimed leaves to the payer's return address.
	let mut st = Value::Null;
	for pass in 0..40 {
		settle(&r).await;
		if pass % 4 == 3 {
			tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 12 * HOUR));
			r.synced().await;
		}
		st = shown(&payer);
		if st["claims"].as_array().unwrap().iter().filter(|c| c["state"] == "lapsed").count() == 2 {
			break;
		}
	}
	println!("after the deadline: {}", st);
	let states: Vec<&str> = st["claims"].as_array().unwrap().iter().map(|c| c["state"].as_str().unwrap()).collect();
	assert_eq!(states.iter().filter(|s| **s == "lapsed").count(), 2, "{:?}", states);
	assert_eq!(states.iter().filter(|s| **s == "claimed").count(), 1, "{:?}", states);
	assert!(st["returns"].as_array().unwrap().is_empty(), "nothing paid from the operator's coins");
	for c in st["claims"].as_array().unwrap().iter().filter(|c| c["state"] == "lapsed") {
		let tx = r.rt.client().raw_transaction(&c["lapsed_in"].as_str().unwrap().parse().unwrap()).unwrap();
		let paid = tx.output[0].value.explicit().unwrap();
		assert!(paid >= 1_000_000 - allowance, "lapse {} pays {}", tx.txid(), paid);
		println!("lapse {}: {} vB, {} of X back", tx.txid(), tx.vsize(), paid);
	}
	assert_eq!(holders[2].ok(&["claims"])[0]["state"], "lapsed");
	let coins = holders[0].ok(&["coins"]);
	assert!(coins.as_array().unwrap().iter().any(|c| c["state"] == "live" && c["asset"] == x.as_str()), "holder 0 keeps its coin: {}", coins);
	let _ = DAY;
}

async fn settle(r: &Running) {
	r.server.watcher.pass().await.unwrap();
	tokio::time::sleep(std::time::Duration::from_millis(300)).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.server.nursery.pass().await.unwrap();
	r.server.watcher.pass().await.unwrap();
	tokio::time::sleep(std::time::Duration::from_millis(300)).await;
}
