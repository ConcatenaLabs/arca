//! A coin resting on a batch the watcher unrolled, found by its round's txid
//! however old the round: eight wallets refresh into one shared batch (two
//! lowest nodes at radix 4); seven refresh again and release, so the watcher
//! unrolls the batch to reclaim a lowest node they emptied, and the batch
//! output is spent. A thousand blocks on, a wallet made then is paid out of
//! round from the coin that still rests on that batch: the node's set of
//! unspent outputs no longer has the batch output, and the wallet reads
//! blocks only from a thousand before its birthday, so it asks the operator
//! where the leaf's round is (`batch_status`) and reads the round by its
//! txid. Before, it refused the coin: "not on the chain now: no transaction
//! on the chain pays the batch or board output … it rests on" (arca#701, the
//! testnet's resting orders, which no new taker could fill).
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::time::Duration;

use elements::Script;
use serde_json::Value;

use common::cli::Arca;
use common::running::Running;
use server::store::{NurseryState, RoundState};

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

/// Every wallet of `ws` asks for its refresh; the round is built and made
/// final, and every wallet completes it. The rounds built.
async fn refresh_all(r: &Running, ws: &[&Arca]) -> Vec<elements::Txid> {
	for w in ws {
		let p = w.ok(&["participate"]);
		assert!(p["participations"].as_array().unwrap().iter().all(|x| x["state"] == "pending"), "{}", p);
	}
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(!built.is_empty() && failed.is_empty(), "{} built, {} failed", built.len(), failed.len());
	r.produce().await;
	r.bury().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	for w in ws {
		let s = w.ok(&["sync"]);
		let ps = s["participations"].as_array().unwrap();
		assert!(!ps.is_empty() && ps.iter().all(|p| p["state"] == "released"), "{}", s);
	}
	built.iter().map(|b| b.tx.txid()).collect()
}

/// The watcher's passes, a block between them. Its reclaims.
async fn reclaims(r: &Running) -> Vec<server::store::WatcherTxRow> {
	for _ in 0..4 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		let start = std::time::Instant::now();
		while !r.server.store.nursery_in(NurseryState::Pending).await.unwrap().iter().all(|n| n.broadcasts > 0) {
			assert!(start.elapsed() < Duration::from_secs(30));
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		r.produce().await;
	}
	r.bury().await;
	r.synced().await;
	r.server.nursery.pass().await.unwrap();
	r.server.store.watcher_log().await.unwrap().into_iter().filter(|w| w.kind == "reclaim").collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_coin_on_an_unrolled_batch_is_found_by_its_rounds_txid() {
	let mut r = Running::start_with(|c, _, _| {
		c.batches.holder_batches = Some(0);
	}).await;
	let x = r.x.to_string();
	let x_id = r.x;
	r.fund_server(x_id, 100_000_000).await;
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	let ws: Vec<Arca> = (0..8).map(|i| Arca::new(&format!("U{}", i))).collect();
	for w in &ws {
		w.ok(&create);
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, x_id, 3_000_000);
	}
	r.produce().await;
	for w in &ws {
		w.ok(&["board", &x, "2000000"]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("every board credited", || ws.iter().all(|w| w.ok(&["boards"])[0]["server"]["state"] == "credited")).await;

	// Round 1: eight leaves in one shared batch, two lowest nodes.
	let all: Vec<&Arca> = ws.iter().collect();
	let round1 = refresh_all(&r, &all).await;
	assert_eq!(round1.len(), 1);
	let round1 = round1[0];
	let keeper = &ws[7];

	// Round 2: the other seven refresh and release; the watcher unrolls the
	// batch to reclaim the lowest node they emptied.
	refresh_all(&r, &all[..7]).await;
	let ks = reclaims(&r).await;
	println!("{} reclaim(s): {:?}", ks.len(), ks.iter().map(|k| &k.detail).collect::<Vec<_>>());
	assert!(!ks.is_empty(), "a lowest node is reclaimed");
	let tx = r.rt.client().raw_transaction(&round1).unwrap();
	let spent: Vec<usize> = (0..tx.output.len()).filter(|&v| tokio::task::block_in_place(|| {
		r.rt.client().call::<Value>("gettxout", &[serde_json::json!(round1.to_string()), serde_json::json!(v)]).unwrap().is_null()
	})).collect();
	println!("round 1 {}: outputs spent {:?}", round1, spent);
	let held = keeper.ok(&["coins"]);
	let coin = held.as_array().unwrap().iter().find(|c| c["state"] == "live" && c["kind"] == "batch").expect("the keeper's coin").clone();
	println!("the keeper's coin {} rests on round 1, whose batch output the unroll spent", coin["leaf_id"]);

	// A thousand blocks and more, then a wallet made now: its reads of blocks
	// begin after round 1.
	for _ in 0..1002 {
		r.produce().await;
	}
	r.bury().await;
	r.synced().await;
	let t = Arca::new("T");
	t.ok(&create);
	let req = t.ok(&["receive"]);
	let sent = keeper.ok(&["send", req["request"].as_str().unwrap(), "--amount", "500000", "--asset", &x]);
	println!("SENT: {}", sent);
	let mb = t.ok(&["mailbox"]);
	println!("T's mailbox: {}", mb);
	assert_eq!(mb["accepted"].as_array().map(|a| a.len()), Some(1), "the coin on the unrolled batch is taken: {}", mb);
	let live: u64 = t.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live")
		.map(|c| c["value"].as_str().unwrap().parse::<u64>().unwrap()).sum();
	assert_eq!(live, 500_000);
}
