//! A released lowest node comes back early beside wallets that have not
//! released, with the `arca` wallet: five wallets each refresh a board into
//! one shared batch, laid into lowest nodes of three and two. The three in
//! the first refresh again and release; the watcher unrolls the batch output
//! and reclaims their lowest node. A wallet of the second lowest node, which
//! never released, then syncs: its coin is still live and no exit starts (an
//! upper node on the chain shows it no leaf or checkpoint of its coin), and
//! it refreshes in the next round as before.
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

/// Every wallet of `ws` asks for its refresh, in that order; the round is
/// built and made final, and every wallet completes it.
async fn refresh(r: &Running, ws: &[&Arca]) {
	for w in ws {
		let p = w.ok(&["participate"]);
		assert!(p["participations"].as_array().unwrap().iter().all(|x| x["state"] == "pending"), "{}", p);
	}
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(built.len() == 1 && failed.is_empty(), "{} built, {} failed", built.len(), failed.len());
	r.produce().await;
	r.bury().await;
	r.round_state(&built[0].tx.txid(), RoundState::Final).await;
	for w in ws {
		let s = w.ok(&["sync"]);
		let ps = s["participations"].as_array().unwrap();
		assert!(!ps.is_empty() && ps.iter().all(|p| p["state"] == "released"), "{}", s);
	}
}

fn live(w: &Arca) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live").cloned().collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_beside_a_released_lowest_node_keeps_its_coin_through_the_unroll() {
	let mut r = Running::start_with(|c, _, _| {
		c.batches.holder_batches = Some(0);
	}).await;
	let x = r.x.to_string();
	let x_id = r.x;
	r.fund_server(x_id, 100_000_000).await;
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	let ws: Vec<Arca> = ["ER1", "ER2", "ER3", "ER4", "ER5"].iter().map(|n| Arca::new(n)).collect();
	for w in &ws {
		w.ok(&create);
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, x_id, 5_000_000);
	}
	r.produce().await;
	for w in &ws {
		w.ok(&["board", &x, "2000000"]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("every board credited", || ws.iter().all(|w| w.ok(&["boards"])[0]["server"]["state"] == "credited")).await;

	// Round 1: the five boards into one batch.
	refresh(&r, &ws.iter().collect::<Vec<_>>()).await;
	let leaf_of = |w: &Arca| live(w)[0]["leaf_id"].as_str().unwrap().to_string();
	let ids: Vec<String> = ws.iter().map(leaf_of).collect();
	let (_, round1, _, vouts) = r.server.store.rounds_page(0, 10).await.unwrap().into_iter().last().unwrap();
	let (_, leaves) = r.server.store.batch(&round1, vouts[0]).await.unwrap().expect("the batch");
	let hexed = |b: &[u8; 32]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
	let order: Vec<usize> = leaves.iter().map(|l| ids.iter().position(|i| *i == hexed(&l.leaf_id)).expect("a wallet's leaf"))
		.collect();
	println!("round 1: {} leaves, wallets in leaf order {:?}", leaves.len(), order);
	assert_eq!(leaves.len(), 5);
	// Lowest nodes of three and two: the wallets of the first refresh again.
	let first: Vec<&Arca> = order[..3].iter().map(|&i| &ws[i]).collect();
	let w = &ws[order[4]];
	let held = leaf_of(w);

	// Round 2: the first lowest node's wallets refresh and release.
	refresh(&r, &first).await;
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
	let log = r.server.store.watcher_log().await.unwrap();
	for k in log.iter().filter(|k| k.kind == "unroll" || k.kind == "reclaim") {
		let tx: elements::Transaction = elements::encode::deserialize(&k.tx).unwrap();
		println!("{} {} ({:?}), {} vB: {}", k.kind, tx.txid(), k.state, tx.vsize(), k.detail);
		assert_eq!(k.state, NurseryState::Final);
	}
	assert_eq!(log.iter().filter(|k| k.kind == "unroll").count(), 1, "the batch output is unrolled");
	assert_eq!(log.iter().filter(|k| k.kind == "reclaim").count(), 1, "the released lowest node is reclaimed");
	let pool = r.server.store.pool_flow().await.unwrap()[&x_id.into_inner().to_byte_array()].clone();
	println!("pool: locked {}, released {}, reclaimed in the last hour {}", pool.locked, pool.released, pool.reclaimed_last_hour);
	assert!(pool.reclaimed_last_hour > 0);

	// The wallet beside the unrolled node, which never released: its sync
	// starts no exit and its coin is still live.
	let s = w.ok(&["sync"]);
	let changes = s["changes"].as_array().cloned().unwrap_or_default();
	println!("the wallet beside it syncs: changes {}", Value::Array(changes.clone()));
	assert!(changes.iter().all(|c| c["leaf_id"] != held.as_str()), "no change to its coin: {}", s);
	let mine = live(w);
	assert_eq!(mine.len(), 1);
	assert_eq!(mine[0]["leaf_id"], held.as_str(), "its coin is still live");
	assert!(w.ok(&["coins"]).as_array().unwrap().iter().all(|c| c["state"] != "exiting"), "nothing exits");

	// It refreshes in the next round as before.
	refresh(&r, &[w]).await;
	let after = live(w);
	println!("it refreshes after the unroll: its new coin {}", after[0]["leaf_id"]);
	assert_eq!(after.len(), 1);
	assert_ne!(after[0]["leaf_id"], held.as_str());
}
