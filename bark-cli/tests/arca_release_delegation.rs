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

/// Every wallet of `ws` asks for its refresh; the rounds of every asset are
/// built and made final, and every wallet completes them.
async fn refresh_all(r: &Running, ws: &[&Arca]) {
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

/// The coins of `w` live in `asset`.
fn live(w: &Arca, asset: &str) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == asset).cloned().collect()
}

fn id32(s: &str) -> [u8; 32] {
	let b: Vec<u8> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
	b.try_into().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_swap_delegates_both_sides_and_a_restored_wallet_releases() {
	let mut r = Running::start_with(|c, _, _| {
		c.batches.delegated_reclaim = true;
		c.batches.holder_batches = Some(0);
	}).await;
	let (x_id, y_id) = (r.x, r.y);
	let (x, y) = (x_id.to_string(), y_id.to_string());
	common::node::list_fee_asset(&r.rt, y_id, 100_000_000);
	r.fund_server(x_id, 100_000_000).await;
	r.fund_server(y_id, 100_000_000).await;
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	let (a, b) = (Arca::new("SA"), Arca::new("SB"));
	a.ok(&create);
	b.ok(&create);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, x_id, 5_000_000);
	let s = script(&b.ok(&["address"]));
	r.pay_to(s, y_id, 5_000_000);
	r.produce().await;
	a.ok(&["board", &x, "2000000"]);
	b.ok(&["board", &y, "2000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("both boards credited", || {
		a.ok(&["boards"])[0]["server"]["state"] == "credited" && b.ok(&["boards"])[0]["server"]["state"] == "credited"
	}).await;
	// A's X and B's Y each into a batch with RECLAIM-D.
	refresh_all(&r, &[&a, &b]).await;
	let (ax, by) = (live(&a, &x)[0]["leaf_id"].as_str().unwrap().to_string(), live(&b, &y)[0]["leaf_id"].as_str().unwrap().to_string());

	// A gives X for B's Y in one reassignment: both inputs delegate, A's
	// signed at completion, B's carried in its acceptance.
	let offer = a.ok(&["swap", "offer", "--give-asset", &x, "--give", "600000", "--want-asset", &y, "--want", "700000"]);
	let acc = b.ok(&["swap", "accept", offer["offer"].as_str().unwrap()]);
	a.ok(&["swap", "complete", acc["accept"].as_str().unwrap()]);
	b.ok(&["mailbox"]);
	for (who, leaf) in [("A's X", &ax), ("B's Y", &by)] {
		let d = r.server.store.delegation(&id32(leaf)).await.unwrap();
		println!("{} leaf {}: delegation recorded: {}", who, &leaf[..16], d.is_some());
		assert!(d.is_some(), "{}'s input carries a delegation", who);
	}

	// B is lost and restored from its mnemonic alone.
	let mnemonic = std::fs::read_to_string(b.dir.join("mnemonic")).unwrap();
	let b2 = Arca::new("SB2");
	let mut args: Vec<&str> = create.to_vec();
	args.extend(["--mnemonic", mnemonic.trim()]);
	let made = b2.ok(&args);
	println!("B restored: {}", made["restore"]);
	b2.ok(&["sync"]);

	// Every coin the swap made refreshes and releases: both nodes come back.
	refresh_all(&r, &[&a, &b2]).await;
	let ks = reclaims(&r).await;
	let by_d: Vec<_> = ks.iter().filter(|w| w.detail.contains("RECLAIM-D")).collect();
	for k in &by_d {
		let tx: elements::Transaction = elements::encode::deserialize(&k.tx).unwrap();
		println!("reclaim {} ({:?}), {} vB: {}", tx.txid(), k.state, tx.vsize(), k.detail);
		assert_eq!(k.state, NurseryState::Final);
	}
	assert_eq!(by_d.len(), 2, "the X node and the Y node, each released by both sides of the swap");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lightning_send_carries_the_payers_delegation() {
	let Some(lnd) = common::lightning::lightningd("a_lightning_send_carries_the_payers_delegation") else { return };
	let mut r = Running::start_seqln(|c, _, _| {
		c.batches.delegated_reclaim = true;
		c.batches.holder_batches = Some(0);
		c.lightning.operator_delay_units = 1;
		c.lightning.owner_delay_units = 2;
		c.lightning.send_timeout_seconds = 8 * 3600;
		c.lightning.send_stall_margin_seconds = 3600;
		c.lightning.poll_seconds = 1;
		c.lightning.retry_seconds = 10;
	}).await;
	let x_id = r.x;
	let x = x_id.to_string();
	r.fund_server(x_id, 100_000_000).await;
	let (ox, px) = tokio::task::block_in_place(|| {
		let ox = common::lightning::node(&r.rt, &mut r.purse, &lnd, "dox", true, x_id, 2_000_000_000);
		let px = common::lightning::node(&r.rt, &mut r.purse, &lnd, "dpx", true, x_id, 1_000_000_000);
		ox.open_channel(&r.rt, &px, x_id, 1_000_000_000, 300_000_000);
		(ox, px)
	});
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let mut config = r.config.clone();
	for a in config.assets.iter_mut().filter(|a| a.asset == x) {
		a.lightning = Some(server::server::LegSection { rpc: ox.rpc_path() });
	}
	r.server.reload(&config).await.unwrap();
	r.config = config;
	let g = r.server.gateway.clone();
	r.wait("the leg up", || g.leg(&x_id, true).is_ok()).await;
	let (url, nurl) = (r.url(), r.node_url());
	let a = Arca::new("LD");
	a.ok(&["create", "--server", &url, "--node-url", &nurl, "--node-user", "arca", "--exit-delay-units", "4",
		"--min-exit-delay-units", "1"]);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, x_id, 5_000_000);
	r.produce().await;
	a.ok(&["board", &x, "2000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || a.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	// Its coin into a batch with RECLAIM-D, then paid out over Lightning.
	refresh_all(&r, &[&a]).await;
	let coin = live(&a, &x)[0]["leaf_id"].as_str().unwrap().to_string();
	let (inv, _) = common::lightning::invoice(&px, x_id, 100_000, "delegated-send");
	let p = a.ok(&["lightning", "pay", &inv, "--asset", &x]);
	assert_eq!(p["payment"]["state"], "paid", "{}", p);
	let d = r.server.store.delegation(&id32(&coin)).await.unwrap();
	println!("paid over Lightning from {}: delegation recorded: {}", &coin[..16], d.is_some());
	assert!(d.is_some(), "a Lightning send delegates the coin's release to its outputs, the htlc-1 leaf and the change");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_payee_that_offboards_releases_as_a_holder() {
	let mut r = Running::start_with(|c, _, _| {
		c.batches.delegated_reclaim = true;
		c.batches.holder_batches = Some(0);
	}).await;
	let x_id = r.x;
	let x = x_id.to_string();
	r.fund_server(x_id, 100_000_000).await;
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	let (a, b, c) = (Arca::new("OA"), Arca::new("OB"), Arca::new("OC"));
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
	refresh_all(&r, &[&a, &b]).await;
	let req = c.ok(&["receive"]);
	a.ok(&["send", req["request"].as_str().unwrap(), "--amount", "600000", "--asset", &x]);
	c.ok(&["mailbox"]);
	// C takes the whole coin it got off the tree, to an address on the chain:
	// no new leaf of its own, so its release is the offboard's.
	let to = c.ok(&["address"])["address"].as_str().unwrap().to_string();
	let mut amount = 590_000u64;
	let mut q = Value::Null;
	for _ in 0..4 {
		q = c.ok(&["offboard", "--asset", &x, "--amount", &amount.to_string(), "--address", &to, "--quote"]);
		match q["change"].as_str().and_then(|v| v.parse::<u64>().ok()).filter(|v| *v > 0) {
			Some(ch) => amount += ch,
			None => break,
		}
	}
	println!("C's offboard quote: {}", q);
	c.ok(&["offboard", "--asset", &x, "--amount", &amount.to_string(), "--address", &to, "--shown", &q.to_string()]);
	for w in [&a, &b] {
		w.ok(&["participate"]);
	}
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(!built.is_empty() && failed.is_empty());
	r.produce().await;
	r.bury().await;
	for bt in &built {
		r.round_state(&bt.tx.txid(), RoundState::Final).await;
	}
	for w in [&a, &b, &c] {
		let s = w.ok(&["sync"]);
		println!("released: {}", s["participations"].as_array().unwrap().iter().map(|p| p["released"].to_string()).collect::<Vec<_>>().join(" "));
	}
	let ks = reclaims(&r).await;
	let k = ks.iter().find(|w| w.detail.contains("RECLAIM-D")).unwrap_or_else(|| panic!("no reclaim by RECLAIM-D: {:?}",
		ks.iter().map(|w| &w.detail).collect::<Vec<_>>()));
	let tx: elements::Transaction = elements::encode::deserialize(&k.tx).unwrap();
	println!("reclaim {} ({:?}), {} vB: {}", tx.txid(), k.state, tx.vsize(), k.detail);
	assert_eq!(k.state, NurseryState::Final);
}
