//! The `arca` wallet against a whole Arca server that builds batches
//! without a sweep: every refresh round is held until each participation in
//! it has handed over its forfeits, and each wallet's `sync` validates its
//! new leaves against the transaction the status serves and signs before the
//! round is broadcast. A wallet that does not sync is left out: its
//! participation is voided past the window, its coin live again, and the
//! others' round is built again and completes. A pays C out of round, A, B
//! and C refresh and release, and the watcher reclaims the node by RECLAIM-D.
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

/// Every wallet of `ws` asks for its refresh; each round built is held until
/// every wallet has synced (handing its forfeits over before broadcast), then
/// goes out, is made final, and every wallet completes it.
async fn refresh_all(r: &Running, ws: &[&Arca]) {
	for w in ws {
		let p = w.ok(&["participate"]);
		assert!(p["participations"].as_array().unwrap().iter().all(|x| x["state"] == "pending"), "{}", p);
	}
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(!built.is_empty() && failed.is_empty(), "{} built, {} failed", built.len(), failed.len());
	for b in &built {
		assert!(b.broadcast.starts_with("held"), "{}", b.broadcast);
	}
	for (i, w) in ws.iter().enumerate() {
		let s = w.ok(&["sync"]);
		let ps = s["participations"].as_array().unwrap();
		println!("wallet {} before broadcast: {}", i, ps.iter().map(|p| format!("{} {}", p["state"], p["note"])).collect::<Vec<_>>().join("; "));
		assert!(ps.iter().all(|p| p["state"] == "forfeiting"), "{}", s);
	}
	r.server.rounds.pass().await.unwrap();
	for b in &built {
		let row = r.server.store.round_by_txid(&b.tx.txid().to_byte_array()).await.unwrap().unwrap();
		assert_eq!(row.state, RoundState::Broadcast, "broadcast once every wallet's forfeits are in");
	}
	r.produce().await;
	r.bury().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	for (i, w) in ws.iter().enumerate() {
		let s = w.ok(&["sync"]);
		let ps = s["participations"].as_array().unwrap();
		assert!(!ps.is_empty() && ps.iter().all(|p| p["state"] == "released"), "{}", s);
		for p in ps {
			println!("wallet {}: released {}", i, p["released"]);
		}
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
async fn wallets_sign_before_broadcast_and_a_silent_one_is_left_out() {
	let mut r = Running::start_with(|c, _, _| {
		c.batches.no_sweep = true;
		c.batches.delegated_reclaim = true;
		c.batches.holder_batches = Some(0);
	}).await;
	let x = r.x.to_string();
	let x_id = r.x;
	r.fund_server(x_id, 100_000_000).await;
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	let (a, b, c, d) = (Arca::new("A"), Arca::new("B"), Arca::new("C"), Arca::new("D"));
	for w in [&a, &b, &c, &d] {
		w.ok(&create);
	}
	for w in [&a, &b, &d] {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, x_id, 5_000_000);
	}
	r.produce().await;
	for w in [&a, &b, &d] {
		w.ok(&["board", &x, "2000000"]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards credited", || {
		[&a, &b, &d].iter().all(|w| w.ok(&["boards"])[0]["server"]["state"] == "credited")
	}).await;

	// D asks for its refresh and never syncs again: left out.
	for w in [&a, &b, &d] {
		let p = w.ok(&["participate"]);
		assert!(p["participations"].as_array().unwrap().iter().all(|x| x["state"] == "pending"), "{}", p);
	}
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	let dropped = built[0].tx.clone();
	println!("round {} built: {}", dropped.txid(), built[0].broadcast);
	for w in [&a, &b] {
		let s = w.ok(&["sync"]);
		assert!(s["participations"].as_array().unwrap().iter().all(|p| p["state"] == "forfeiting"), "{}", s);
	}
	let sch = a.ok(&["schedule"]);
	println!("A's schedule while its round waits: {}", sch["why"]);
	r.server.rounds.pass().await.unwrap();
	let pool: Vec<String> = r.rt.client().call("getrawmempool", &[]).unwrap();
	assert!(!pool.contains(&dropped.txid().to_string()), "held while D has handed over nothing");
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 700));
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	let row = r.server.store.round_by_txid(&dropped.txid().to_byte_array()).await.unwrap().unwrap();
	assert_eq!(row.state, RoundState::Lost, "the round is dropped unbroadcast");
	let sd = d.ok(&["sync"]);
	println!("D's sync after its round was dropped: {}", sd["participations"]);
	assert_eq!(sd["participations"][0]["state"], "void", "{}", sd);
	let bal = d.ok(&["balance"]);
	println!("D's balance: {}", bal["arca"]);
	// A and B run again once the spend that kills the dropped round is
	// final (it keeps their re-run apart from it), and complete.
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let (again, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(!again.is_empty(), "A's and B's round runs again: {:?}", failed.iter().map(|f| f.1.to_string()).collect::<Vec<_>>());
	assert_eq!(again[0].participations, 2);
	for w in [&a, &b] {
		let s = w.ok(&["sync"]);
		assert!(s["participations"].as_array().unwrap().iter().all(|p| p["state"] == "forfeiting"), "{}", s);
	}
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&again[0].tx.txid(), RoundState::Final).await;
	for w in [&a, &b] {
		let s = w.ok(&["sync"]);
		assert!(s["participations"].as_array().unwrap().iter().all(|p| p["state"] == "released"), "{}", s);
	}
	println!("A and B completed round {}, which never waited for D", again[0].tx.txid());

	// A pays C out of round; C takes it from its mailbox.
	let req = c.ok(&["receive"]);
	let sent = a.ok(&["send", req["request"].as_str().unwrap(), "--amount", "600000", "--asset", &x]);
	assert!(sent["change"].is_string(), "{}", sent);
	let mb = c.ok(&["mailbox"]);
	assert_eq!(mb["accepted"].as_array().unwrap().len(), 1, "{}", mb);

	// A (its change), B and C refresh and release: the node comes back.
	refresh_all(&r, &[&a, &b, &c]).await;
	let ks = reclaims(&r).await;
	let k = ks.iter().find(|w| w.detail.contains("RECLAIM-D")).unwrap_or_else(|| panic!("no reclaim by RECLAIM-D: {:?}",
		ks.iter().map(|w| &w.detail).collect::<Vec<_>>()));
	let tx: elements::Transaction = elements::encode::deserialize(&k.tx).unwrap();
	println!("reclaim {} ({:?}), {} vB: {}", tx.txid(), k.state, tx.vsize(), k.detail);
	assert_eq!(k.state, NurseryState::Final);
}
