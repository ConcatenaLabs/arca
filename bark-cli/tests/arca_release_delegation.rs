//! Release delegation with the `arca` wallet against a whole Arca server
//! whose batches carry RECLAIM-D: A and B refresh into one lowest node, A pays
//! C out of round (the wallet signs the delegation with the transfer), then A,
//! B and C refresh (each wallet signs its releases, A's and C's as holders of
//! a coin a reassignment made) and the watcher reclaims the node by RECLAIM-D.
//! A swap delegates both sides; a paid Lightning send's htlc-1 leaf is
//! released by its sender's sync; a payee that offboards releases as a
//! holder; and a resting order filled in the tree delegates on both sides,
//! the maker's sync signing for its order's first coin and never for the
//! order resting again, nor its cancel (arca#460).
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
/// The outputs of the reassignment that spent the coin `id` (leaf id and
/// owner key each), or none while it is unspent by one.
async fn moved(r: &Running, id: [u8; 32]) -> Vec<([u8; 32], [u8; 32])> {
	match r.server.store.spent_by(&id).await.unwrap() {
		server::store::SpentBy::Reassignment { outputs, .. } => outputs,
		_ => vec![],
	}
}

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
		a.lightning = Some(server::server::LegSection::at(ox.rpc_path()));
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

	// The paid payment's htlc-1 leaf: the wallet's sync releases its node,
	// the change refreshes, and the node comes back by RECLAIM-D.
	let hash = p["paying"]["payment_hash"].as_str().unwrap().to_string();
	refresh_all(&r, &[&a]).await;
	let terms = r.server.sends.release_terms(&id32(&hash)).await.unwrap();
	println!("the paid payment's htlc-1 leaf rests on {} node(s), {} released by the sender's sync", terms.nodes.len(), terms.released.len());
	assert!(!terms.nodes.is_empty() && terms.released == terms.nodes, "the sender's sync released every node");
	let ks = reclaims(&r).await;
	let k = ks.iter().find(|w| w.detail.contains("RECLAIM-D")).unwrap_or_else(|| panic!("no reclaim by RECLAIM-D: {:?}",
		ks.iter().map(|w| &w.detail).collect::<Vec<_>>()));
	let tx: elements::Transaction = elements::encode::deserialize(&k.tx).unwrap();
	println!("reclaim {} ({:?}), {} vB: {}", tx.txid(), k.state, tx.vsize(), k.detail);
	assert_eq!(k.state, NurseryState::Final);
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

/// A resting order filled in the tree on batches with RECLAIM-D: M rests an
/// order selling X for Y (giving up a board), T refreshes a board of Y into
/// a leaf in the same rounds and fills part of the order (its wallet
/// delegates its coin with the fill). M's `sync` takes up its credit and the
/// order resting again and delegates the order's coin into the fill. T fills
/// part of the rest: M's `sync` takes that credit and delegates nothing, the
/// order's key having delegated at the first fill; M cancels what rests (a
/// transfer, with no delegation either). Every coin then refreshes; the
/// order's node and the taker's wait for their batches' expiry, since a
/// second delegation by the order's key would stand in for the first.
#[tokio::test(flavor = "multi_thread")]
async fn a_resting_order_filled_in_the_tree_delegates_its_first_coin_only() {
	let mut r = Running::start_with(|c, x, _| {
		c.batches.delegated_reclaim = true;
		c.batches.holder_batches = Some(0);
		c.assets[0] = server::server::AssetSection::new(x, 1_000);
	}).await;
	let (x_id, y_id) = (r.x, r.y);
	let (x, y) = (x_id.to_string(), y_id.to_string());
	common::node::list_fee_asset(&r.rt, y_id, 100_000_000);
	r.fund_server(x_id, 100_000_000).await;
	r.fund_server(y_id, 100_000_000).await;
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	let (m, t) = (Arca::new("DM"), Arca::new("DT"));
	for (w, asset) in [(&m, x_id), (&t, y_id)] {
		w.ok(&create);
		r.pay_to(script(&w.ok(&["address"])), asset, 1_600_000);
		r.pay_to(script(&w.ok(&["address"])), x_id, 1_000_000);
	}
	r.produce().await;
	m.ok(&["board", &x, "1500000"]);
	t.ok(&["board", &y, "1500000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("both boards credited", || {
		m.ok(&["boards"])[0]["server"]["state"] == "credited" && t.ok(&["boards"])[0]["server"]["state"] == "credited"
	}).await;

	// M rests 1,000,000 X for Y at 1/1, lots of 100,000; T refreshes its
	// board into a leaf of Y in the same rounds.
	let rested = m.ok(&["order", "rest", "--sell", &x, "--amount", "1000000", "--for", &y, "--rate-num", "1", "--rate-den", "1",
		"--min-lot", "100000", "--expires-in-hours", "720"]);
	assert_eq!(rested["state"], "pending", "{}", rested);
	t.ok(&["participate"]);
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty() && built.len() == 2, "{} built, {:?}", built.len(), failed.len());
	r.produce().await;
	r.bury().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	m.ok(&["sync"]);
	t.ok(&["sync"]);
	let view = m.ok(&["order", "resting"]);
	let order = view["orders"].as_array().unwrap().iter().find(|o| o["rested_by"] == rested["order"]).unwrap()["order"]
		.as_str().unwrap().to_string();
	let tcoin = live(&t, &y)[0]["leaf_id"].as_str().unwrap().to_string();

	// T fills 300,000: its wallet delegates its coin with the fill.
	let f = t.ok(&["order", "fill-resting", &order, "--amount", "300000"]);
	assert_eq!(f["filled"], "300000", "{}", f);
	assert!(r.server.store.delegation(&id32(&tcoin)).await.unwrap().is_some(), "the taker's coin delegates into the fill");
	assert!(r.server.store.delegation(&id32(&order)).await.unwrap().is_none(), "the order's coin has not delegated yet");

	// M comes back: its sync takes the credit and the rest, and delegates.
	let s = m.ok(&["sync"]);
	println!("M's sync, resting: {}", s["resting"]);
	assert!(r.server.store.delegation(&id32(&order)).await.unwrap().is_some(), "the maker's sync delegates the order's coin: {}", s);
	let again = m.ok(&["sync"]);
	assert!(again["resting"].as_array().is_none_or(|a| a.iter().all(|v| v.get("order_coin").is_none())),
		"done once: {}", again["resting"]);
	let rest = moved(&r, id32(&order)).await[1].0;

	// T fills 300,000 of what rests; M's sync takes the credit and signs no
	// delegation for the order resting again.
	let f = t.ok(&["order", "fill-resting", &order, "--amount", "300000"]);
	assert_eq!(f["filled"], "300000", "{}", f);
	let s = m.ok(&["sync"]);
	println!("M's sync after the second fill, resting: {}", s["resting"]);
	assert!(r.server.store.delegation(&rest).await.unwrap().is_none(), "the order resting again delegates nothing: {}", s);
	let rest2 = moved(&r, rest).await[1].0;

	// M cancels what rests: a transfer with no delegation.
	let cq = m.ok(&["order", "cancel-resting", &order, "--quote"]);
	m.ok(&["order", "cancel-resting", &order, "--shown", &cq.to_string()]);
	assert!(!moved(&r, rest2).await.is_empty(), "the cancel spent the order resting again");
	assert!(r.server.store.delegation(&rest2).await.unwrap().is_none(), "the cancel carries no delegation");

	// Every coin refreshes; neither node comes back before its expiry.
	refresh_all(&r, &[&m, &t]).await;
	let ks = reclaims(&r).await;
	for k in &ks {
		let tx: elements::Transaction = elements::encode::deserialize(&k.tx).unwrap();
		println!("reclaim {} ({:?}), {} vB: {}", tx.txid(), k.state, tx.vsize(), k.detail);
	}
	assert!(ks.iter().all(|k| !k.detail.contains("RECLAIM-D")), "no node comes back by RECLAIM-D through the order resting again");
	let flows = r.server.store.pool_flow().await.unwrap();
	let (fx, fy) = (flows[&x_id.into_inner().to_byte_array()].transferred, flows[&y_id.into_inner().to_byte_array()].transferred);
	println!("after every holder refreshed: transferred X {}, Y {}", fx, fy);
	assert!(fx > 0 && fy > 0, "both nodes stay counted until their expiry");
}

/// A coin left at rest beside released ones keeps its node's fronted value
/// out until collection (arca#584). A and B refresh into one lowest node; A
/// refreshes again and releases, so the node holds A's coin in flight and
/// waits on B's alone. B's next sync asks the operator which of its coins
/// hold a node back (`holding_back`), and asks for that coin's refresh at
/// once, its window or not; once that round is final and B releases, the
/// watcher reclaims the node. Before A's release, no sync asks for any
/// refresh: nothing was held back.
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_that_alone_holds_its_node_back_is_refreshed_by_the_next_sync() {
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
	let (a, b) = (Arca::new("HA"), Arca::new("HB"));
	for w in [&a, &b] {
		w.ok(&create);
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
	let s = b.ok(&["sync"]);
	println!("B's sync before A refreshes: refresh {}", s["refresh"]);
	assert!(s["refresh"].as_array().is_none_or(|a| a.is_empty()), "nothing is held back yet: {}", s["refresh"]);

	// Round 2: A alone refreshes and releases.
	refresh_all(&r, &[&a]).await;
	let s = b.ok(&["sync"]);
	println!("B's sync once A released: refresh {}", s["refresh"]);
	let asked = s["refresh"].as_array().cloned().unwrap_or_default();
	assert_eq!(asked.len(), 1, "{}", s["refresh"]);
	assert_eq!(asked[0]["state"], "pending", "{}", asked[0]);

	// Round 3: B's refresh; B releases, and the node comes back.
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	r.produce().await;
	r.bury().await;
	for t in &built {
		r.round_state(&t.tx.txid(), RoundState::Final).await;
	}
	let s = b.ok(&["sync"]);
	assert!(s["participations"].as_array().unwrap().iter().any(|p| p["state"] == "released"), "{}", s["participations"]);
	let ks = reclaims(&r).await;
	println!("{} reclaim(s): {:?}", ks.len(), ks.iter().map(|k| &k.detail).collect::<Vec<_>>());
	assert!(!ks.is_empty(), "the node is reclaimed");
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A payment's change holds its payer's old node back once the payee has
/// refreshed (arca#599). A and B refresh into one lowest node with RECLAIM-D;
/// A pays C out of round, keeping change. B and C refresh and release, A does
/// nothing: the node waits on A's change alone, which rests on it only
/// through the payment. A's next sync asks the operator which of its coins
/// hold a node back (`holding_back`, proving its mailbox key), and asks for
/// the change's refresh at once; once that round is final and A releases,
/// the watcher reclaims the node by RECLAIM-D. Before C refreshes, A's sync
/// asks for nothing: the node waits on C too.
#[tokio::test(flavor = "multi_thread")]
async fn a_payers_change_that_alone_holds_its_node_back_is_refreshed_by_the_next_sync() {
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
	let (a, b, c) = (Arca::new("PCA"), Arca::new("PCB"), Arca::new("PCC"));
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

	// A pays C out of round, keeping change.
	let req = c.ok(&["receive"]);
	let sent = a.ok(&["send", req["request"].as_str().unwrap(), "--amount", "600000", "--asset", &x]);
	assert!(sent["change"].is_string(), "the payment leaves change: {}", sent);
	assert_eq!(c.ok(&["mailbox"])["accepted"].as_array().unwrap().len(), 1);
	let mine = live(&a, &x);
	assert_eq!(mine.len(), 1, "A holds its change alone: {:?}", mine);
	let change = mine[0]["leaf_id"].as_str().unwrap().to_string();
	println!("A's change {} ({})", change, mine[0]["kind"]);

	// Round 2: B alone refreshes and releases; the node still waits on C.
	refresh_all(&r, &[&b]).await;
	let s = a.ok(&["sync"]);
	println!("A's sync while C holds its coin: refresh {}", s["refresh"]);
	assert!(s["refresh"].as_array().is_none_or(|a| a.is_empty()), "the node waits on C as well: {}", s["refresh"]);

	// Round 3: C refreshes and releases; A's sync names its change.
	refresh_all(&r, &[&c]).await;
	let s = a.ok(&["sync"]);
	println!("A's sync once C released: refresh {}", s["refresh"]);
	let asked = s["refresh"].as_array().cloned().unwrap_or_default();
	assert_eq!(asked.len(), 1, "{}", s["refresh"]);
	assert_eq!(asked[0]["leaf_id"], change.as_str(), "{}", asked[0]);
	assert_eq!(asked[0]["state"], "pending", "{}", asked[0]);

	// Round 4: A's refresh; A releases, and the node comes back.
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	assert!(!built.is_empty(), "the change's refresh is built");
	r.produce().await;
	r.bury().await;
	for t in &built {
		r.round_state(&t.tx.txid(), RoundState::Final).await;
	}
	let s = a.ok(&["sync"]);
	assert!(s["participations"].as_array().unwrap().iter().any(|p| p["state"] == "released"), "{}", s["participations"]);
	let ks = reclaims(&r).await;
	println!("{} reclaim(s): {:?}", ks.len(), ks.iter().map(|k| &k.detail).collect::<Vec<_>>());
	let k = ks.iter().find(|w| w.detail.contains("RECLAIM-D")).expect("the node is reclaimed by RECLAIM-D");
	assert_eq!(k.state, NurseryState::Final);
	let pool = r.server.store.pool_flow().await.unwrap()[&x_id.into_inner().to_byte_array()].clone();
	println!("after the reclaim: transferred {}, in flight {}", pool.transferred, pool.in_flight);
	assert_eq!(pool.transferred, 0);
	for w in [&a, &b, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A coin the operator names is refreshed for no fee (arca#607): as
/// `a_coin_that_alone_holds_its_node_back_is_refreshed_by_the_next_sync`, the
/// operator charging 5,000 ppm for a refresh. B's sync refreshes the named
/// coin weeks before its window and pays nothing; the operator, which names
/// it, takes the refresh without a fee.
#[tokio::test(flavor = "multi_thread")]
async fn a_named_coin_is_refreshed_for_no_fee() {
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
	let (a, b) = (Arca::new("NFA"), Arca::new("NFB"));
	for w in [&a, &b] {
		w.ok(&create);
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
	let mut config = r.server.config();
	config.fees.refresh_ppm = 5_000;
	r.server.reload(&config).await.unwrap();
	let p = a.ok(&["participate", "--max-fee-ppm", "10000"]);
	println!("A's own refresh: {}", p["participations"]);
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	r.produce().await;
	r.bury().await;
	for t in &built {
		r.round_state(&t.tx.txid(), RoundState::Final).await;
	}
	a.ok(&["sync"]);
	let s = b.ok(&["sync"]);
	println!("B's sync once A released: refresh {}", s["refresh"]);
	let asked = s["refresh"].as_array().cloned().unwrap_or_default();
	assert_eq!(asked.len(), 1, "{}", s["refresh"]);
	assert_eq!(asked[0]["state"], "pending", "{}", asked[0]);
	let fees = asked[0]["fees"].as_array().cloned().unwrap_or_default();
	println!("fee B pays for the named refresh: {:?}", fees);
	assert!(fees.iter().all(|f| f["amount"] == "0"), "the named refresh pays nothing: {:?}", fees);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A holder named for two coins of one node refreshes them together, for no
/// fee (arca#612). A boards once and B twice; B refreshes each board in a
/// participation of its own, so the round puts A's coin and B's two side by
/// side under one lowest node. The operator charges 5,000 ppm for a refresh;
/// A refreshes and releases, paying it. B's sync then asks for both of its
/// coins in one participation and pays nothing: the operator names both,
/// and waives the fee only for the two together, since the node comes back
/// only once both are refreshed.
#[tokio::test(flavor = "multi_thread")]
async fn a_holders_two_named_coins_are_refreshed_together_for_no_fee() {
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
	let (a, b) = (Arca::new("NTA"), Arca::new("NTB"));
	for w in [&a, &b] {
		w.ok(&create);
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, x_id, 5_000_000);
	}
	r.produce().await;
	a.ok(&["board", &x, "2000000"]);
	b.ok(&["board", &x, "1000000"]);
	// B's second board spends the first one's change, once it is in a block.
	r.produce().await;
	b.ok(&["board", &x, "1000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("every board credited", || {
		let credited = |w: &Arca| w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited");
		credited(&a) && credited(&b) && b.ok(&["boards"]).as_array().unwrap().len() == 2
	}).await;
	// Round 1: A's coin and B's two under one lowest node.
	a.ok(&["participate"]);
	for c in live(&b, &x) {
		let p = b.ok(&["participate", "--leaf", c["leaf_id"].as_str().unwrap()]);
		assert!(p["participations"].as_array().unwrap().iter().all(|x| x["state"] == "pending"), "{}", p);
	}
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(built.len() == 1 && failed.is_empty(), "{} built, {} failed", built.len(), failed.len());
	r.produce().await;
	r.bury().await;
	r.round_state(&built[0].tx.txid(), RoundState::Final).await;
	for w in [&a, &b] {
		w.ok(&["sync"]);
	}
	let mine = live(&b, &x);
	assert_eq!(mine.len(), 2, "B holds two coins of the round: {:?}", mine);

	let mut config = r.server.config();
	config.fees.refresh_ppm = 5_000;
	r.server.reload(&config).await.unwrap();
	let p = a.ok(&["participate", "--max-fee-ppm", "10000"]);
	println!("A's own refresh: {}", p["participations"]);
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	r.produce().await;
	r.bury().await;
	for t in &built {
		r.round_state(&t.tx.txid(), RoundState::Final).await;
	}
	a.ok(&["sync"]);
	let s = b.ok(&["sync"]);
	println!("B's sync once A released: refresh {}", s["refresh"]);
	let asked = s["refresh"].as_array().cloned().unwrap_or_default();
	assert_eq!(asked.len(), 2, "{}", s["refresh"]);
	for e in &asked {
		assert_eq!(e["state"], "pending", "{}", e);
		let fees = e["fees"].as_array().cloned().unwrap_or_default();
		assert!(fees.iter().all(|f| f["amount"] == "0"), "the named refresh pays nothing: {:?}", fees);
	}
	assert_eq!(asked[0]["participation"], asked[1]["participation"], "both in one participation: {}", s["refresh"]);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// From its first call to `path` on, the proxy `p` answers every witness of
/// the operator's signer's record with a 502, and holds that first call for
/// eleven seconds, longer than a witness stands for a wallet (ten): the
/// wallet then reads the answer with its last witness too old to sign on,
/// and no new one to be had.
fn the_witness_fails_from(p: &common::proxy::Proxy, path: &'static str) {
	let (q, once) = (p.clone(), std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)));
	p.rewrite(Some(std::sync::Arc::new(move |at, _, _, _| {
		if at == path && !once.swap(true, std::sync::atomic::Ordering::SeqCst) {
			q.lose("/v1/witness", true);
			std::thread::sleep(Duration::from_secs(11));
		}
		None
	})));
}

/// The witness succeeds again, and nothing is held.
fn the_witness_is_back(p: &common::proxy::Proxy) {
	p.rewrite(None);
	p.lose("/v1/witness", false);
}

/// No release of a paid Lightning payment's leaf is signed once the witness
/// of the operator's signer's record fails. The sender's sync reads the
/// operator's terms for the release, which here take longer than a witness
/// stands, and from then every witness fails: the wallet witnesses again
/// before it signs, signs nothing, hands nothing over and asks the operator
/// for nothing more in that sync. Once the witness succeeds again, its next
/// sync releases every node.
#[tokio::test(flavor = "multi_thread")]
async fn no_release_of_a_paid_send_is_signed_once_the_witness_fails() {
	let Some(lnd) = common::lightning::lightningd("no_release_of_a_paid_send_is_signed_once_the_witness_fails") else { return };
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
		let ox = common::lightning::node(&r.rt, &mut r.purse, &lnd, "wox", true, x_id, 2_000_000_000);
		let px = common::lightning::node(&r.rt, &mut r.purse, &lnd, "wpx", true, x_id, 1_000_000_000);
		ox.open_channel(&r.rt, &px, x_id, 1_000_000_000, 300_000_000);
		(ox, px)
	});
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let mut config = r.config.clone();
	for a in config.assets.iter_mut().filter(|a| a.asset == x) {
		a.lightning = Some(server::server::LegSection::at(ox.rpc_path()));
	}
	r.server.reload(&config).await.unwrap();
	r.config = config;
	let g = r.server.gateway.clone();
	r.wait("the leg up", || g.leg(&x_id, true).is_ok()).await;
	let p = common::proxy::Proxy::start(&r.url());
	let nurl = r.node_url();
	let a = Arca::new("WL");
	a.ok(&["create", "--server", &p.url, "--node-url", &nurl, "--node-user", "arca", "--exit-delay-units", "4",
		"--min-exit-delay-units", "1"]);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, x_id, 5_000_000);
	r.produce().await;
	a.ok(&["board", &x, "2000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || a.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	refresh_all(&r, &[&a]).await;
	// The payment is paid while the operator's terms for the release cannot
	// be read, so the release is left to the wallet's next sync.
	let (inv, _) = common::lightning::invoice(&px, x_id, 100_000, "witnessed-release");
	p.lose("/v1/lightning_send_release_terms", true);
	let paid = a.ok(&["lightning", "pay", &inv, "--asset", &x]);
	p.lose("/v1/lightning_send_release_terms", false);
	assert_eq!(paid["payment"]["state"], "paid", "{}", paid);
	let hash = paid["paying"]["payment_hash"].as_str().unwrap().to_string();
	let terms = r.server.sends.release_terms(&id32(&hash)).await.unwrap();
	assert!(!terms.nodes.is_empty() && terms.released.is_empty(), "the payment's leaf rests on a node not released yet");
	let before = p.calls().len();
	the_witness_fails_from(&p, "/v1/lightning_send_release_terms");
	let (_, s) = a.run(&["sync"]);
	let calls: Vec<(String, u16)> = p.calls()[before..].iter().map(|(path, _, status, _)| (path.clone(), *status)).collect();
	let count = |path: &str| calls.iter().filter(|(c, _)| c == path).count();
	let failed = calls.iter().position(|(c, st)| c == "/v1/witness" && *st == 502);
	let terms = r.server.sends.release_terms(&id32(&hash)).await.unwrap();
	println!("with the witness failing from the release's terms on: terms read {}, releases handed over {}, witnesses {}; the calls \
		after the witness failed: {:?}; nodes {}, released {}; lightning {}; unreachable {}", count("/v1/lightning_send_release_terms"),
		count("/v1/lightning_send_release"), count("/v1/witness"), failed.map(|k| &calls[k + 1..]), terms.nodes.len(),
		terms.released.len(), s["lightning"], s["unreachable"]);
	assert_eq!(count("/v1/lightning_send_release_terms"), 1, "the release's terms were read: {}", s);
	assert_eq!(count("/v1/lightning_send_release"), 0, "a release was signed and handed over while the witness failed: {}", s);
	assert!(terms.released.is_empty(), "the operator holds no release");
	let failed = failed.expect("the wallet witnessed again before it signed");
	assert_eq!(count("/v1/witness"), 2, "one witness as the sync started, one before the signature, and none after it failed");
	assert!(calls[failed + 1..].is_empty(), "the operator was asked after the witness failed: {:?}", &calls[failed + 1..]);
	assert!(s["unreachable"].is_object(), "the sync says the operator could not be witnessed: {}", s);
	// The witness succeeds again: the next sync releases every node.
	the_witness_is_back(&p);
	a.ok(&["sync"]);
	let terms = r.server.sends.release_terms(&id32(&hash)).await.unwrap();
	println!("with the witness back: {} node(s), {} released", terms.nodes.len(), terms.released.len());
	assert!(!terms.nodes.is_empty() && terms.released == terms.nodes, "the sender's sync released every node");
	let _ = std::fs::remove_dir_all(&a.dir);
}

/// No delegation of a filled order's coin is signed once the witness of the
/// operator's signer's record fails. The maker's sync reads the operator's
/// terms for the delegation, which here take longer than a witness stands,
/// and from then every witness fails: the wallet witnesses again before it
/// signs, signs nothing and hands nothing over. Once the witness succeeds
/// again, its next sync delegates.
#[tokio::test(flavor = "multi_thread")]
async fn no_delegation_of_a_filled_order_is_signed_once_the_witness_fails() {
	let mut r = Running::start_with(|c, x, _| {
		c.batches.delegated_reclaim = true;
		c.batches.holder_batches = Some(0);
		c.assets[0] = server::server::AssetSection::new(x, 1_000);
	}).await;
	let (x_id, y_id) = (r.x, r.y);
	let (x, y) = (x_id.to_string(), y_id.to_string());
	common::node::list_fee_asset(&r.rt, y_id, 100_000_000);
	r.fund_server(x_id, 100_000_000).await;
	r.fund_server(y_id, 100_000_000).await;
	let p = common::proxy::Proxy::start(&r.url());
	let (url, node) = (r.url(), r.node_url());
	let (m, t) = (Arca::new("WM"), Arca::new("WT"));
	for (w, server, asset) in [(&m, &p.url, x_id), (&t, &url, y_id)] {
		w.ok(&["create", "--server", server, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1",
			"--min-exit-delay-units", "1"]);
		r.pay_to(script(&w.ok(&["address"])), asset, 1_600_000);
		r.pay_to(script(&w.ok(&["address"])), x_id, 1_000_000);
	}
	r.produce().await;
	m.ok(&["board", &x, "1500000"]);
	t.ok(&["board", &y, "1500000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("both boards credited", || {
		m.ok(&["boards"])[0]["server"]["state"] == "credited" && t.ok(&["boards"])[0]["server"]["state"] == "credited"
	}).await;
	// M rests 1,000,000 X for Y; T refreshes its board in the same rounds
	// and fills 300,000 of the order.
	let rested = m.ok(&["order", "rest", "--sell", &x, "--amount", "1000000", "--for", &y, "--rate-num", "1", "--rate-den", "1",
		"--min-lot", "100000", "--expires-in-hours", "720"]);
	assert_eq!(rested["state"], "pending", "{}", rested);
	t.ok(&["participate"]);
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty() && built.len() == 2, "{} built, {:?}", built.len(), failed.len());
	r.produce().await;
	r.bury().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	m.ok(&["sync"]);
	t.ok(&["sync"]);
	let view = m.ok(&["order", "resting"]);
	let order = view["orders"].as_array().unwrap().iter().find(|o| o["rested_by"] == rested["order"]).unwrap()["order"]
		.as_str().unwrap().to_string();
	let f = t.ok(&["order", "fill-resting", &order, "--amount", "300000"]);
	assert_eq!(f["filled"], "300000", "{}", f);
	assert!(r.server.store.delegation(&id32(&order)).await.unwrap().is_none(), "the order's coin has not delegated yet");
	// M comes back, and the witness fails from the delegation's terms on.
	let before = p.calls().len();
	the_witness_fails_from(&p, "/v1/order_fill_delegation_terms");
	let (_, s) = m.run(&["sync"]);
	let calls: Vec<(String, u16)> = p.calls()[before..].iter().map(|(path, _, status, _)| (path.clone(), *status)).collect();
	let count = |path: &str| calls.iter().filter(|(c, _)| c == path).count();
	let failed = calls.iter().position(|(c, st)| c == "/v1/witness" && *st == 502);
	println!("with the witness failing from the delegation's terms on: terms read {}, delegations handed over {}, witnesses {}; the \
		calls after the witness failed: {:?}; resting {}; unreachable {}", count("/v1/order_fill_delegation_terms"),
		count("/v1/order_fill_delegation"), count("/v1/witness"), failed.map(|k| &calls[k + 1..]), s["resting"], s["unreachable"]);
	assert_eq!(count("/v1/order_fill_delegation_terms"), 1, "the delegation's terms were read: {}", s);
	assert_eq!(count("/v1/order_fill_delegation"), 0, "a delegation was signed and handed over while the witness failed: {}", s);
	assert!(r.server.store.delegation(&id32(&order)).await.unwrap().is_none(), "the operator holds no delegation of the order's coin");
	let failed = failed.expect("the wallet witnessed again before it signed");
	assert_eq!(count("/v1/witness"), 2, "one witness as the sync started, one before the signature, and none after it failed");
	assert!(calls[failed + 1..].is_empty(), "the operator was asked after the witness failed: {:?}", &calls[failed + 1..]);
	assert!(s["unreachable"].is_object(), "the sync says the operator could not be witnessed: {}", s);
	// The witness succeeds again: the next sync delegates.
	the_witness_is_back(&p);
	let s = m.ok(&["sync"]);
	assert!(r.server.store.delegation(&id32(&order)).await.unwrap().is_some(), "the maker's sync delegates the order's coin: {}", s);
	for w in [&m, &t] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
