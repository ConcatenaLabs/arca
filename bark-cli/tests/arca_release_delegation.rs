//! Release delegation with the `arca` wallet against a whole Arca server
//! whose batches carry RECLAIM-D: A and B refresh into one lowest node, A pays
//! C out of round (the wallet signs the delegation with the transfer), then A,
//! B and C refresh (each wallet signs its releases, A's and C's as holders of
//! a coin a reassignment made) and the watcher reclaims the node by RECLAIM-D.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::time::Duration;

use elements::hashes::Hash;
use elements::Script;
use serde_json::Value;

use common::cli::Arca;
use common::running::Running;
use server::store::{NurseryState, RoundState};

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

/// Every wallet of `ws` asks for its refresh; one round is built and made
/// final, and every wallet completes it.
async fn refresh_all(r: &Running, ws: &[&Arca]) {
	for w in ws {
		let p = w.ok(&["participate"]);
		assert_eq!(p["participations"][0]["state"], "pending", "{}", p);
	}
	let built = r.server.rounds.run_round().await.unwrap().expect("a round");
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	for (i, w) in ws.iter().enumerate() {
		let s = w.ok(&["sync"]);
		let done = s["participations"].as_array().unwrap().iter().find(|p| p["state"] == "released").cloned();
		assert!(done.is_some(), "{}", s);
		println!("wallet {}: released {}", i, done.unwrap()["released"]);
	}
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
async fn the_wallet_delegates_at_a_payment_and_releases_as_a_holder() {
	let mut r = Running::start_with(|c, _, _| {
		c.batches.delegated_reclaim = true;
		c.batches.holder_batches = Some(0);
	}).await;
	let x = r.x.to_string();
	let x_id = r.x;
	r.fund_server(x_id, 100_000_000).await;
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	let (a, b, c) = (Arca::new("A"), Arca::new("B"), Arca::new("C"));
	for w in [&a, &b, &c] {
		w.ok(&create);
	}
	for w in [&a, &b] {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, x_id, 5_000_000);
	}
	r.produce().await;
	a.ok(&["board", &x, "2000000"]);
	b.ok(&["board", &x, "2000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("both boards credited", || {
		a.ok(&["boards"])[0]["server"]["state"] == "credited" && b.ok(&["boards"])[0]["server"]["state"] == "credited"
	}).await;

	// Round 1: A's and B's leaves under one lowest node with RECLAIM-D.
	refresh_all(&r, &[&a, &b]).await;

	// A pays C out of round; C takes it from its mailbox.
	let req = c.ok(&["receive"]);
	let sent = a.ok(&["send", req["request"].as_str().unwrap(), "--amount", "600000", "--asset", &x]);
	assert!(sent["change"].is_string(), "{}", sent);
	let mb = c.ok(&["mailbox"]);
	assert_eq!(mb["accepted"].as_array().unwrap().len(), 1, "{}", mb);
	let pool = r.server.store.pool_flow().await.unwrap()[&x_id.into_inner().to_byte_array()].clone();
	println!("after the payment: transferred {}, in flight {}", pool.transferred, pool.in_flight);
	assert!(pool.transferred > 0, "A's leaf is paid on out of round");

	// Round 2: A (its change), B and C refresh and release.
	refresh_all(&r, &[&a, &b, &c]).await;
	let ks = reclaims(&r).await;
	let k = ks.iter().find(|w| w.detail.contains("RECLAIM-D")).unwrap_or_else(|| panic!("no reclaim by RECLAIM-D: {:?}",
		ks.iter().map(|w| &w.detail).collect::<Vec<_>>()));
	let tx: elements::Transaction = elements::encode::deserialize(&k.tx).unwrap();
	println!("reclaim {} ({:?}), {} vB: {}", tx.txid(), k.state, tx.vsize(), k.detail);
	assert_eq!(k.state, NurseryState::Final);
	let pool = r.server.store.pool_flow().await.unwrap()[&x_id.into_inner().to_byte_array()].clone();
	println!("after the reclaim: transferred {}, in flight {}, reclaimed in the last hour {}", pool.transferred, pool.in_flight,
		pool.reclaimed_last_hour);
	assert_eq!(pool.transferred, 0);
}
