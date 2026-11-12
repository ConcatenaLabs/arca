//! A board is live once the operator credits it (arca #846), whatever path
//! made the wallet read it final: against a whole Arca server on an anchored
//! regtest chain, at the testnet's settings (certification required, anchor
//! depth BOARD_DEPTH, 0 by default as on the testnet, no sweep; and
//! ARCA_TEST_CHECKPOINT_EXIT=0 for the checkpoint exit off). The operator
//! follows the chain every 30 s, so it is behind the wallet for a while after
//! each block, as on the testnet; a case where it caught up first proves
//! nothing, and fails with "GUARD" (run it again).
//!
//! 1. A wallet restored from its phrase right after a board: the board is
//!    final in the chain, the operator has not credited it yet.
//! 2. The operator answers "credited" while the board is in the mempool; its
//!    board_status cannot be asked at the sync, then answers again while
//!    still behind.
//! 3. A board credited and live, rolled back out of the chain and mined
//!    again: the wallet syncs between the two, and it does not.
//! 4. A board the operator dropped as lost (out of every block for its
//!    window) that the chain then mines: the coin says the operator will not
//!    credit it, no settlement is promised for it, and a payment is refused
//!    as a shortfall rather than told to wait.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::sync::Arc;
use std::time::Duration;

use elements::Script;
use serde_json::{json, Value};

use bark::arca::{command, Wallet};
use common::cli::Arca;
use common::proxy::Proxy;
use common::running::Running;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

fn library(a: &Arca, cmd: &str, args: Value) -> Result<Value, Value> {
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run(&mut w, cmd, &args).map(|v| v["result"].clone()).map_err(|e| command::refusal(&e))
	})
}

fn rpc(r: &Running, method: &str, params: &[Value]) -> Value {
	r.rt.client().call(method, params).unwrap_or_else(|e| panic!("{} {:?}: {}", method, params, e))
}

fn depth() -> u32 {
	std::env::var("BOARD_DEPTH").ok().and_then(|d| d.parse().ok()).unwrap_or(0)
}

const POLL_MS: u64 = 30_000;

async fn start(extra: impl FnOnce(&mut server::server::Config) + Send + 'static) -> Running {
	let d = depth();
	Running::start_with(move |cfg, _, _| {
		cfg.finality.anchor_depth = d;
		cfg.finality.poll_interval_ms = POLL_MS;
		cfg.watcher.enabled = false;
		cfg.batches.no_sweep = true;
		extra(cfg);
	}).await
}

fn create_at(server: &str, r: &Running, w: &Arca, mnemonic: Option<&str>) -> Value {
	let node = r.node_url();
	let mut args = vec!["create", "--server", server, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	if let Some(m) = mnemonic {
		args.extend(["--mnemonic", m]);
	}
	w.ok(&args)
}

fn request(to: &Arca) -> String {
	to.ok(&["receive"])["request"].as_str().unwrap().to_string()
}

/// The operator's state of each board `a` holds, as `boards` reads it.
fn server_states(a: &Arca) -> Vec<Value> {
	a.ok(&["boards"]).as_array().unwrap().iter().map(|b| b["server"]["state"].clone()).collect()
}

/// The board coins of asset `x` `a` holds: (leaf, state, note).
fn board_coins(a: &Arca, x: &str) -> Vec<(String, String, String)> {
	a.ok(&["coins"]).as_array().unwrap().iter().filter(|k| k["asset"] == x && k["kind"] == "board")
		.map(|k| (k["leaf_id"].as_str().unwrap_or("").into(), k["state"].as_str().unwrap_or("").into(), k["note"].as_str().unwrap_or("").into()))
		.collect()
}

/// Funds `a` on the chain and boards 2,000,000 X; the board's txid, not mined yet.
async fn board(r: &mut Running, a: &Arca) -> String {
	let x = r.x;
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, x, 3_000_000);
	r.produce().await;
	r.synced().await;
	let b = a.ok(&["board", &x.to_string(), "2000000", "--fee-asset", &x.to_string()]);
	println!("board: {}", b);
	b["txid"].as_str().unwrap().to_string()
}

async fn mine(r: &Running) {
	r.produce().await;
	if depth() > 0 {
		r.bury().await;
	}
}

/// A payment of 500,000 X from `a` to a new wallet's request: (went, answer).
fn pay(a: &Arca, req: &str, x: &str) -> (bool, Value) {
	a.run(&["send", req, "--amount", "500000", "--asset", x])
}

/// What a payment from a board the operator has not credited must answer:
/// never paid, never the operator's raw `not_live`, `settle_first` with a time.
fn assert_waits(tag: &str, paid: bool, v: &Value) {
	assert!(!paid, "{}: paid from a board the operator has not credited: {}", tag, v);
	assert!(!v.to_string().contains("not_live"), "{}: the operator's raw refusal reached the payer (the wallet held the board live \
		before the operator credited it): {}", tag, v);
	assert_eq!(v["error"]["kind"], "settle_first", "{}: {}", tag, v);
}

// ---------------------------------------------------------------------------
// 1. Restored from the phrase right after the board.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_restored_wallet_holds_an_uncredited_board_waiting() {
	let tag = format!("Board 1 d{}", depth());
	let mut r = start(|_| {}).await;
	let x = r.x.to_string();
	let (a, a2, c) = (Arca::new(&format!("{} A", tag)), Arca::new(&format!("{} A2", tag)), Arca::new(&format!("{} C", tag)));
	let url = r.url();
	create_at(&url, &r, &a, None);
	create_at(&url, &r, &c, None);
	board(&mut r, &a).await;
	mine(&r).await;
	a.ok(&["sync"]);
	println!("{}: A's board coins after its sync: {:?}", tag, board_coins(&a, &x));
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap();
	let made = create_at(&url, &r, &a2, Some(mnemonic.trim()));
	println!("{}: A2's restore: restored {} not_taken {}", tag, made["restore"]["restored"], made["restore"]["not_taken"]);
	a2.ok(&["sync"]);
	let coins = board_coins(&a2, &x);
	let places = library(&a2, "coin_places", json!({})).unwrap();
	let req = request(&c);
	let (paid, v) = pay(&a2, &req, &x);
	let st = server_states(&a2);
	println!("{}: A2's board coins: {:?}\n{}: A2's spendable: {}\n{}: the operator reads {:?}\n{}: A2's payment: {}", tag, coins, tag,
		places["spendable"], tag, st, tag, v);
	assert_eq!(st, vec![json!("pending")], "{}: GUARD: the operator caught up during the case; run it again", tag);
	assert!(coins.iter().all(|k| k.1 != "live"), "{}: the restored wallet holds as live a board the operator has not credited: {:?}",
		tag, coins);
	assert_waits(&tag, paid, &v);
	for w in [&a, &a2, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// 2. The operator cannot be asked at the sync; the operator lies "credited".
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_operator_that_cannot_be_asked_or_lies() {
	let tag = format!("Board 2 d{}", depth());
	let mut r = start(|_| {}).await;
	let x = r.x.to_string();
	let p = Proxy::start(&r.url());
	let (a, c) = (Arca::new(&format!("{} A", tag)), Arca::new(&format!("{} C", tag)));
	create_at(&p.url, &r, &a, None);
	create_at(&r.url(), &r, &c, None);
	board(&mut r, &a).await;
	// (a) A lie: every board_status answers "credited", the board still in
	// the mempool. The wallet's own reading of the chain must stand.
	p.rewrite(Some(Arc::new(|path: &str, _: &Value, _: u16, v: &mut Value| {
		if path.ends_with("/board_status") {
			v["state"] = json!("credited");
		}
		None
	})));
	a.ok(&["sync"]);
	let lied = board_coins(&a, &x);
	println!("{}: (a) told credited while in the mempool: {:?}", tag, lied);
	assert!(lied.iter().all(|k| k.1 == "pending"), "{}: a board in the mempool held live on the operator's word: {:?}", tag, lied);
	p.rewrite(None);
	// (b) The board mined; at the wallet's sync the operator's board_status
	// is lost on the way (a gateway's 502); then it answers again, still
	// behind the chain.
	mine(&r).await;
	p.lose("/v1/board_status", true);
	a.ok(&["sync"]);
	let at_sync = board_coins(&a, &x);
	p.lose("/v1/board_status", false);
	a.ok(&["sync"]);
	let after = board_coins(&a, &x);
	let req = request(&c);
	let (paid, v) = pay(&a, &req, &x);
	let st = server_states(&a);
	println!("{}: (b) at a sync the operator could not answer: {:?}\n{}: (b) at the next sync: {:?}\n{}: the operator reads {:?}\n\
		{}: the payment: {}", tag, at_sync, tag, after, tag, st, tag, v);
	assert_eq!(st, vec![json!("pending")], "{}: GUARD: the operator caught up during the case; run it again", tag);
	assert!(after.iter().all(|k| k.1 != "live"), "{}: the board went live on a sync that could not ask the operator, and stays \
		live once it answers 'pending': {:?}", tag, after);
	assert_waits(&tag, paid, &v);
	for w in [&a, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// 3. Credited, rolled back, mined again.
// ---------------------------------------------------------------------------

async fn credited(r: &Running, a: &Arca) {
	r.wait("the board to be credited", || server_states(a) == vec![json!("credited")]).await;
}

async fn wait_long<F: FnMut() -> bool>(what: &str, mut f: F) {
	let start = std::time::Instant::now();
	loop {
		if tokio::task::block_in_place(&mut f) {
			return;
		}
		assert!(start.elapsed() < Duration::from_secs(180), "timed out waiting for {}", what);
		tokio::time::sleep(Duration::from_millis(500)).await;
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn a_board_rolled_back_after_its_credit() {
	let tag = format!("Board 3 d{}", depth());
	let mut r = start(|_| {}).await;
	let x = r.x.to_string();
	let (a, c) = (Arca::new(&format!("{} A", tag)), Arca::new(&format!("{} C", tag)));
	create_at(&r.url(), &r, &a, None);
	create_at(&r.url(), &r, &c, None);
	let txid = board(&mut r, &a).await;
	mine(&r).await;
	r.synced().await;
	wait_long("the board credited", || server_states(&a) == vec![json!("credited")]).await;
	a.ok(&["sync"]);
	assert!(board_coins(&a, &x).iter().all(|k| k.1 == "live"), "{}: {:?}", tag, board_coins(&a, &x));
	// (a) The board's block leaves the chain; the wallet syncs while it is
	// out: its coin waits (redoing), not spendable.
	let block = rpc(&r, "getrawtransaction", &[json!(txid), json!(true)])["blockhash"].as_str().unwrap().to_string();
	rpc(&r, "invalidateblock", &[json!(block)]);
	a.ok(&["sync"]);
	let out = board_coins(&a, &x);
	let places = library(&a, "coin_places", json!({})).unwrap();
	println!("{}: (a) the board's block out: {:?}; spendable {}", tag, out, places["spendable"]);
	assert!(out.iter().all(|k| k.1 == "pending" && k.2.starts_with(bark::arca::REDOING)), "{}: {:?}", tag, out);
	// The operator follows the rollback (uncredits) before the board is mined again.
	wait_long("the operator to uncredit the board", || server_states(&a) == vec![json!("pending")]).await;
	mine(&r).await;
	a.ok(&["sync"]);
	let back = board_coins(&a, &x);
	let req = request(&c);
	let (paid, v) = pay(&a, &req, &x);
	let st = server_states(&a);
	println!("{}: (a) mined again: {:?}; the operator reads {:?}; the payment: {}", tag, back, st, v);
	if st == vec![json!("pending")] {
		assert!(back.iter().all(|k| k.1 == "pending"), "{}: {:?}", tag, back);
		assert_waits(&format!("{} (a)", tag), paid, &v);
	}
	credited(&r, &a).await;
	a.ok(&["sync"]);
	assert!(board_coins(&a, &x).iter().all(|k| k.1 == "live"), "{}: comes back once credited: {:?}", tag, board_coins(&a, &x));
	// (b) The same rollback, the wallet not syncing while the board is out
	// (it reads the chain only after the board is mined again).
	let block = rpc(&r, "getrawtransaction", &[json!(txid), json!(true)])["blockhash"].as_str().unwrap().to_string();
	rpc(&r, "invalidateblock", &[json!(block)]);
	wait_long("the operator to uncredit the board", || server_states(&a) == vec![json!("pending")]).await;
	mine(&r).await;
	a.ok(&["sync"]);
	let held = board_coins(&a, &x);
	let (paid, v) = pay(&a, &req, &x);
	let st = server_states(&a);
	println!("{}: (b) mined again, unseen out: {:?}; the operator reads {:?}; the payment: {}", tag, held, st, v);
	assert_eq!(st, vec![json!("pending")], "{}: GUARD: the operator caught up during the case; run it again", tag);
	assert_waits(&format!("{} (b)", tag), paid, &v);
	for w in [&a, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// 4. A board the operator dropped as lost, mined after.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_board_the_operator_dropped_then_mined() {
	let tag = format!("Board 4 d{}", depth());
	let mut r = start(|cfg| cfg.limits.board_unconfirmed_seconds = 5).await;
	let x = r.x.to_string();
	let (a, c) = (Arca::new(&format!("{} A", tag)), Arca::new(&format!("{} C", tag)));
	create_at(&r.url(), &r, &a, None);
	create_at(&r.url(), &r, &c, None);
	board(&mut r, &a).await;
	// No block for the operator's window: it drops the board as lost.
	wait_long("the operator to drop the board", || server_states(&a) == vec![json!("lost")]).await;
	let in_pool = rpc(&r, "getrawmempool", &[]);
	println!("{}: dropped; the node's mempool: {}", tag, in_pool);
	mine(&r).await;
	r.synced().await;
	a.ok(&["sync"]);
	let held = board_coins(&a, &x);
	let s1 = library(&a, "settle_first", json!({"asset": x})).unwrap();
	let t0 = std::time::Instant::now();
	println!("{}: mined after the drop: {:?}; settle_first: {}", tag, held, s1);
	assert_eq!(server_states(&a), vec![json!("lost")], "{}: the operator holds it lost", tag);
	assert!(!held.is_empty() && held.iter().all(|k| k.1 == "pending" && k.2.contains(bark::arca::BOARD_LOST)),
		"{}: the coin says the operator will not credit it, and stays the wallet's to take home: {:?}", tag, held);
	assert_eq!(s1["ready"], true, "{}: no settlement is promised for a board the operator will not credit: {}", tag, s1);
	assert!(s1["final_in_seconds"].is_null(), "{}: {}", tag, s1);
	let (paid, v) = pay(&a, &request(&c), &x);
	println!("{}: a payment: {}", tag, v);
	assert!(!paid, "{}: {}", tag, v);
	assert_ne!(v["error"]["kind"], "settle_first", "{}: never told to wait for a board that never comes: {}", tag, v);
	// What settle_first says, waited out, with a margin of two operator polls.
	if let Some(most) = s1["final_in_seconds"].as_u64() {
		let until = Duration::from_secs(most) + Duration::from_millis(2 * POLL_MS);
		while t0.elapsed() < until {
			tokio::time::sleep(Duration::from_secs(5)).await;
		}
		r.produce().await;
		r.synced().await;
		a.ok(&["sync"]);
		let s2 = library(&a, "settle_first", json!({"asset": x})).unwrap();
		let held2 = board_coins(&a, &x);
		let st = server_states(&a);
		println!("{}: {} s later: {:?}; the operator reads {:?}; settle_first: {}", tag, t0.elapsed().as_secs(), held2, st, s2);
		assert!(s2["ready"] == true || held2.iter().all(|k| k.1 != "pending"), "{}: the board is still held waiting {} s after \
			settle_first said it would be ready within {} s, the operator reading it {:?}, and settle_first now says {}", tag,
			t0.elapsed().as_secs(), most, st, s2);
	}
	for w in [&a, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
