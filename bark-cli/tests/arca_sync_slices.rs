//! `sync` in slices (`budget_ms`), run by the library against a whole Arca
//! server on an anchored regtest chain, the operator reached over a far
//! link (each call waits 150 ms, about a browser's round trip to the
//! testnet's operator) where a test measures time.
//!
//! 1. A firm offer asked while a long sync runs waits one slice at most: a
//!    host's queue (a lock, and a flag a taker's command raises first) runs
//!    the sync in slices of 500 ms and the offer between two of them; the
//!    same sync in one call holds the offer for all of it.
//! 2. The whole pass in slices ends in the same coins and participations as
//!    the pass in one call, two copies of one store compared, with rounds to
//!    complete and refreshes waiting.
//! 3. A cut at every safe point (a budget of 0 ms), each followed by a
//!    command of another kind (a payment, a swap offer, a refresh, a
//!    restore's history step, a read): every slice and every command
//!    answers, a slice ends after every step and inside every step cut
//!    between its items (counted against `slice::STEPS` and `slice::ITEMS`),
//!    and the wallet's value is whole after.
//! 4. Every slice is a call of its own (the library opened afresh, as a
//!    process that stopped between two slices): the pass goes on from the
//!    store. A pass left for more than ten minutes of median time starts
//!    again, re-check included; other arguments start a pass of their own,
//!    and a sync without a budget runs a whole pass and drops every resume
//!    point.
//! 5. With the operator unreachable, a pass waits the witness's patience
//!    once and reaches the step that takes coins home, pass after pass.
//! 6. Two callers syncing in slices with other arguments each end their
//!    own passes.
//! 7. A trade's coin taken in a slice goes to the watchtowers at once, and
//!    the pass answers it.
//! 8. While no witness succeeds, no payment received over Lightning is
//!    asked after.
//! 9. A resumed slice re-checks a tip that moved: a round's block taken out
//!    of the chain between two slices takes its coin out of `live` at once.
//! 10. `deposits` in slices, and the deposits a restore left owed cut
//!    between two coins.
//! 11. A cut at every step with other commands between (a refresh
//!    withdrawn, a swap offered, accepted and completed, an exit, a whole
//!    sync, coin places): the wallet's value is whole after.
//! 12. On a store as large as a busy maker's (seven assets, about six
//!    hundred live coins, a long history), a pass in slices of a second
//!    ends, costs about what one call costs, and no slice holds the wallet
//!    for more than a part of it: what a pass reads once (the operator's
//!    witness and `info`, the coins it holds capital back for) is not read
//!    again in every slice.
//! 13. A slice that resumes its pass once no witness stands in the process
//!    any more witnesses again, and with every witness failing signs
//!    nothing.
//! 14. A witness that fails while a pass runs, in one call or in slices,
//!    ends the pass's work with the operator: nothing is signed, nothing
//!    more is asked, the rest of the pass runs in the same call and says
//!    the operator could not be witnessed.
//! 15. What the bond leaves uncovered is computed again on a new tip: no
//!    coin is given up for a paid refresh on an answer a covering bond has
//!    made stale.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use elements::{AssetId, Script};
use serde_json::{json, Value};

use bark::arca::slice::{ITEMS, LAST, STEPS};
use bark::arca::{command, Wallet};
use common::cli::Arca;
use common::proxy::Proxy;
use common::running::Running;
use server::store::RoundState;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

/// One library command on the wallet at `dir`, opened for it alone.
fn lib_at(dir: &Path, cmd: &str, args: &Value) -> Result<Value, String> {
	let mut w = Wallet::open(dir).expect("open the wallet");
	command::run(&mut w, cmd, args).map(|v| v["result"].clone()).map_err(|e| e.to_string())
}

fn library(a: &Arca, cmd: &str, args: Value) -> Result<Value, String> {
	tokio::task::block_in_place(|| lib_at(&a.dir, cmd, &args))
}

async fn boarded(r: &mut Running, w: &Arca, server: &str, assets: &[(AssetId, u64)]) {
	w.ok(&["create", "--server", server, "--node-url", &r.node_url(), "--node-user", "arca", "--exit-delay-units", "1",
		"--min-exit-delay-units", "1"]);
	for (a, v) in assets {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, *a, v + 3_000_000);
	}
	// One on-chain fee coin a board: a board's change is not spendable until
	// its block.
	let x = r.x;
	for _ in 0..assets.len().max(1) {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, x, 3_000_000);
	}
	r.produce().await;
	for (a, v) in assets {
		w.ok(&["board", &a.to_string(), &v.to_string(), "--fee-asset", &x.to_string()]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards to be credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
}

async fn final_round(r: &Running) {
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
}

/// `from` pays `to` `amount` of `asset` out of round.
fn pay(from: &Arca, to: &Arca, asset: AssetId, amount: u64) {
	let req = to.ok(&["receive"])["request"].as_str().unwrap().to_string();
	from.ok(&["send", &req, "--amount", &amount.to_string(), "--asset", &asset.to_string()]);
	to.ok(&["mailbox"]);
}

/// The wallet `m` made busy: paid `paid` coins by `b`, each given to a
/// refresh of its own; the first `done` of them in a round that is final
/// (their forfeits and new coins for `m`'s next sync to take), the rest
/// waiting for a round.
async fn busy(r: &mut Running, m: &Arca, b: &Arca, paid: usize, done: usize) {
	busy_of(r, m, b, paid, done, 20_000).await;
}

/// [`busy`], with coins of `amount`.
async fn busy_of(r: &mut Running, m: &Arca, b: &Arca, paid: usize, done: usize, amount: u64) {
	pay_many_of(r, m, b, paid, amount).await;
	let received: Vec<String> = m.ok(&["coins"]).as_array().unwrap().iter()
		.filter(|c| c["state"] == "live" && c["kind"] == "transfer").map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
	assert_eq!(received.len(), paid, "{:?}", received);
	for (k, l) in received.iter().enumerate() {
		if k == done && done > 0 {
			final_round(r).await;
		}
		m.ok(&["participate", "--leaf", l]);
	}
	if done == paid {
		final_round(r).await;
	}
}

/// Every round waiting (one an asset), each to final.
async fn final_rounds(r: &Running) {
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed.iter().map(|(a, e)| format!("{}: {}", a, e)).collect::<Vec<_>>());
	r.produce().await;
	r.bury().await;
	for b in built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
}

/// Rounds run and `m` synced until no coin of `m` waits in one.
async fn settled(r: &Running, m: &Arca) {
	for _ in 0..10 {
		final_rounds(r).await;
		m.ok(&["sync"]);
		if !m.ok(&["coins"]).as_array().unwrap().iter().any(|c| c["state"] == "given") {
			return;
		}
	}
	panic!("coins left given: {}", m.ok(&["coins"]));
}

/// `b` pays `m` `n` coins of `amount` X.
async fn pay_many_of(r: &mut Running, m: &Arca, b: &Arca, n: usize, amount: u64) {
	let x = r.x;
	for k in 0..n {
		// The payer's coin goes through a round every four payments, within
		// the operator's depth limit.
		if k > 0 && k % 4 == 0 {
			b.ok(&["participate"]);
			final_round(r).await;
			b.ok(&["sync"]);
		}
		pay(b, m, x, amount);
	}
}

/// The live coins of `asset` worth `value` that `w` holds.
fn live_of(w: &Arca, asset: AssetId, value: u64) -> Vec<String> {
	w.ok(&["coins"]).as_array().unwrap().iter()
		.filter(|c| c["state"] == "live" && c["asset"] == asset.to_string()
			&& (c["value"] == json!(value.to_string()) || c["value"] == json!(value)))
		.map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect()
}

/// A watchtower of its own (`arca watchtower serve`), and its wallet.
struct Tower {
	wallet: Arca,
	child: std::process::Child,
	url: String,
}

impl Tower {
	fn start(r: &Running, name: &str) -> Tower {
		let wallet = Arca::new(name);
		wallet.ok(&["create", "--server", &r.url(), "--node-url", &r.node_url(), "--node-user", "arca", "--exit-delay-units", "1",
			"--min-exit-delay-units", "1"]);
		let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
		let listen = format!("127.0.0.1:{}", port);
		let log = std::fs::File::create(wallet.dir.join("serve.log")).unwrap();
		let child = std::process::Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&wallet.dir)
			.args(["watchtower", "serve", "--listen", &listen, "--interval", "1"])
			.env("ARCA_NODE_PASSWORD", "arca").stdout(std::process::Stdio::null()).stderr(log).spawn().unwrap();
		let t0 = Instant::now();
		while std::net::TcpStream::connect(&listen).is_err() {
			assert!(t0.elapsed() < Duration::from_secs(30), "the watchtower did not start");
			std::thread::sleep(Duration::from_millis(100));
		}
		Tower { wallet, child, url: format!("http://{}", listen) }
	}

	/// The deposits it holds.
	fn held(&self) -> usize {
		self.wallet.ok(&["watchtower", "deposits"]).as_array().unwrap().len()
	}

	fn stop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

impl Drop for Tower {
	fn drop(&mut self) {
		self.stop();
	}
}

/// Items the steps `lightning`, `receives`, `receives again`, `plans`,
/// `orders` and `resting` pass over, two of each, written into the store
/// of the wallet at `dir`: payments over Lightning settled, plans the
/// operator does not know, orders with no participation and resting orders
/// done. Each is an item of its step, which a slice may be cut after.
struct Fakes(PathBuf);

impl Fakes {
	fn put(dir: &Path) -> Fakes {
		let db = rusqlite::Connection::open(dir.join("arca.sqlite")).unwrap();
		let pays = json!({"a1".repeat(32): {"state": "settled"}, "a2".repeat(32): {"state": "settled"}});
		let gets = json!({"b1".repeat(32): {"state": "done"}, "b2".repeat(32): {"state": "done"}});
		for (k, v) in [("lightning_sends", pays), ("lightning_receives", gets)] {
			db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)", [k, &v.to_string()]).unwrap();
		}
		for k in 1..=2 {
			let id = |p: &str| format!("{}{}", p, k).repeat(32);
			db.execute("INSERT INTO plan (id, coin, body, state, status, created_at) VALUES (?1, ?2, '{}', 'waiting', NULL, 0)",
				[id("c"), id("d")]).unwrap();
			db.execute("INSERT INTO maker_order (id, terms, key_index, amount, placed_at, unlock_after, created_at) \
				VALUES (?1, '{}', 0, 0, NULL, NULL, 0)", [id("e")]).unwrap();
			db.execute("INSERT INTO resting_order (id, nonce, terms, amount, credit_nonces, order_leaf, state, created_at) \
				VALUES (?1, zeroblob(32), '{}', 0, '[]', NULL, 'done', 0)", [id("f")]).unwrap();
		}
		Fakes(dir.to_path_buf())
	}

	/// Takes them out again.
	fn take(self) {
		let db = rusqlite::Connection::open(self.0.join("arca.sqlite")).unwrap();
		db.execute("DELETE FROM meta WHERE key IN ('lightning_sends', 'lightning_receives')", []).unwrap();
		for t in ["plan", "maker_order", "resting_order"] {
			db.execute(&format!("DELETE FROM {} WHERE created_at = 0", t), []).unwrap();
		}
	}
}

/// Where the slices of a pass were cut: the steps a slice ended after (the
/// next began in the slice after), and the steps a slice ended inside (the
/// slice ran some of its items, the next ran the rest).
fn cuts(s: &[(Value, u64)]) -> (std::collections::BTreeSet<String>, std::collections::BTreeSet<String>) {
	let index = |k: &str| STEPS.iter().position(|s| *s == k).or((k == LAST).then_some(STEPS.len()));
	let (mut between, mut inside) = (std::collections::BTreeSet::new(), std::collections::BTreeSet::new());
	for (v, _) in s.iter().filter(|(v, _)| v["more"] == json!(true)) {
		let next = v["next"].as_str().unwrap_or("");
		let ran: Vec<&String> = v["cost_by_step"].as_object().map(|o| o.keys().collect()).unwrap_or_default();
		if ran.iter().any(|k| *k == next) {
			inside.insert(next.to_string());
		}
		for k in ran {
			if let (Some(a), Some(b)) = (index(k), index(next)) {
				if a + 1 == b {
					between.insert(k.clone());
				}
			}
		}
	}
	(between, inside)
}

/// Copies the store of `from` into a new wallet named `name`: a second copy
/// of the same wallet, at the same point.
fn copy_of(from: &Arca, name: &str) -> Arca {
	let to = Arca::new(name);
	std::fs::create_dir_all(&to.dir).unwrap();
	for e in std::fs::read_dir(&from.dir).unwrap() {
		let e = e.unwrap();
		if e.file_type().unwrap().is_file() {
			std::fs::copy(e.path(), to.dir.join(e.file_name())).unwrap();
		}
	}
	to
}

/// A sliced sync run to its end, `between` run after every slice but the
/// last: each slice's answer and how long it held the wallet.
fn sliced(dir: &Path, args: &Value, budget: u64, mut between: impl FnMut(usize)) -> Vec<(Value, u64)> {
	let mut out = vec![];
	loop {
		let mut a = args.clone();
		a["budget_ms"] = json!(budget);
		let t = Instant::now();
		let v = tokio::task::block_in_place(|| lib_at(dir, "sync", &a)).expect("a slice answers");
		let ms = t.elapsed().as_millis() as u64;
		let more = v["more"] == json!(true);
		if ms >= 200 && more {
			println!("SL slice {} held the wallet {} ms: {}", out.len() + 1, ms, slow(&v));
		}
		out.push((v, ms));
		if !more {
			return out;
		}
		between(out.len());
		assert!(out.len() < 2_000, "the pass ends");
	}
}

/// Coins by id: (state, value, asset).
fn coins(w: &Arca) -> std::collections::BTreeMap<String, (String, String, String)> {
	w.ok(&["coins"]).as_array().unwrap().iter().map(|c| (c["leaf_id"].as_str().unwrap().to_string(),
		(c["state"].as_str().unwrap().to_string(), c["value"].to_string(), c["asset"].as_str().unwrap_or("").to_string()))).collect()
}

/// Participations by id: their state.
fn participations(w: &Arca) -> std::collections::BTreeMap<String, String> {
	w.ok(&["participations"]).as_array().unwrap().iter()
		.map(|p| (p["participation"].as_str().unwrap().to_string(), p["state"].to_string())).collect()
}

/// The steps of a slice's answer that took 200 ms or more.
fn slow(v: &Value) -> String {
	v["cost_by_step"].as_object().map(|o| o.iter().filter(|(_, c)| c["ms"].as_u64().unwrap_or(0) >= 200)
		.map(|(k, c)| format!("{} {} ms", k, c["ms"])).collect::<Vec<_>>().join(", ")).unwrap_or_default()
}

/// The steps a whole answer names.
fn named_steps(v: &Value) -> Vec<String> {
	v["cost_by_step"].as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default()
}

// The bound a slice of 500 ms stays within here: its budget and the one item
// past it, over a link of 150 ms a call.
const SLICE_BOUND_MS: u64 = 2_000;

/// A host's queue: the sync's slices take `gate`, and wait while a taker's
/// command has raised `asked`; the taker raises it, waits for `gate`, runs
/// its command, and lowers it. What the taker waited for the wallet, and
/// how long the command took.
struct Queue {
	gate: Arc<Mutex<()>>,
	asked: Arc<AtomicBool>,
	started: Arc<AtomicBool>,
}

impl Queue {
	fn new() -> Queue {
		Queue { gate: Arc::new(Mutex::new(())), asked: Arc::new(AtomicBool::new(false)), started: Arc::new(AtomicBool::new(false)) }
	}

	/// Runs the sync on `dir` (in slices of `budget` ms, or in one call) on
	/// a thread of its own, and on another, once the sync has run `after`,
	/// a swap offer: (each slice's ms, the offer's wait, the offer's ms).
	fn run(&self, dir: PathBuf, budget: Option<u64>, after: Duration, offer: Value) -> (Vec<u64>, u64, u64, Value) {
		let (gate, asked, started) = (self.gate.clone(), self.asked.clone(), self.started.clone());
		let d = dir.clone();
		let syncing = std::thread::spawn(move || {
			let mut slices = vec![];
			let last;
			loop {
				while asked.load(Ordering::SeqCst) {
					std::thread::sleep(Duration::from_millis(1));
				}
				let g = gate.lock().unwrap();
				started.store(true, Ordering::SeqCst);
				let mut a = json!({"catch_up": false, "deposits": false});
				if let Some(b) = budget {
					a["budget_ms"] = json!(b);
				}
				let t = Instant::now();
				let v = lib_at(&d, "sync", &a).expect("sync answers");
				let ms = t.elapsed().as_millis() as u64;
				slices.push(ms);
				drop(g);
				if v["more"] == json!(true) {
					println!("SL1 slice {} ({:?}): {} ms: {}", slices.len(), budget, ms, slow(&v));
				}
				// A host yields between two slices.
				std::thread::sleep(Duration::from_millis(2));
				if v["more"] != json!(true) {
					last = v;
					break;
				}
			}
			(slices, last)
		});
		let (gate, asked, started) = (self.gate.clone(), self.asked.clone(), self.started.clone());
		let offering = std::thread::spawn(move || {
			while !started.load(Ordering::SeqCst) {
				std::thread::sleep(Duration::from_millis(1));
			}
			std::thread::sleep(after);
			asked.store(true, Ordering::SeqCst);
			let t = Instant::now();
			let g = gate.lock().unwrap();
			let waited = t.elapsed().as_millis() as u64;
			let t = Instant::now();
			let o = lib_at(&dir, "swap_offer", &offer);
			let took = t.elapsed().as_millis() as u64;
			drop(g);
			asked.store(false, Ordering::SeqCst);
			assert!(o.is_ok(), "the offer answers: {:?}", o);
			(waited, took)
		});
		let (slices, last) = syncing.join().unwrap();
		let (waited, took) = offering.join().unwrap();
		(slices, waited, took, last)
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn a_firm_offer_waits_one_slice_of_a_long_sync_at_most() {
	let mut r = Running::start().await;
	let (x, y) = (r.x, r.y);
	let url = r.url();
	let p = Proxy::start(&url);
	let (m, b) = (Arca::new("SL1 M"), Arca::new("SL1 B"));
	boarded(&mut r, &m, &p.url, &[(x, 3_000_000), (y, 3_000_000)]).await;
	boarded(&mut r, &b, &url, &[(x, 3_000_000)]).await;
	// Twenty refreshes waiting for a round: each read of its state at every
	// sync is one call to the operator.
	busy(&mut r, &m, &b, 20, 0).await;
	let whole = copy_of(&m, "SL1 M whole");
	p.delay(Duration::from_millis(150));
	let offer = json!({"give_asset": x.to_string(), "give": "10000", "want_asset": y.to_string(), "want": "10000"});
	let q = Queue::new();
	let (one, waited_one, took_one, answer_one) = q.run(whole.dir.clone(), None, Duration::from_millis(300), offer.clone());
	println!("SL1 one call: the sync held the wallet {:?} ms; the offer asked 300 ms in waited {} ms and took {} ms; steps {:?}", one,
		waited_one, took_one, named_steps(&answer_one));
	let q = Queue::new();
	let (slices, waited, took, last) = q.run(m.dir.clone(), Some(500), Duration::from_millis(300), offer);
	let longest = slices.iter().copied().max().unwrap();
	println!("SL1 slices of 500 ms: {} slices, each {:?} ms, the longest {} ms; the offer waited {} ms and took {} ms; slices {}", slices.len(),
		slices, longest, waited, took, last["slices"]);
	assert!(one[0] > SLICE_BOUND_MS, "a long sync to slice: {} ms", one[0]);
	assert!(slices.len() > 2, "{:?}", slices);
	assert_eq!(last["slices"], json!(slices.len()), "{}", last);
	assert!(std::env::var_os("SL_MEASURE").is_some() || longest <= SLICE_BOUND_MS, "a slice held the wallet {} ms", longest);
	assert!(waited <= longest + 50, "the offer waited {} ms, longer than a slice ({} ms)", waited, longest);
	assert!(waited_one > waited, "in one call the offer waited {} ms, in slices {} ms", waited_one, waited);
	// Every step ran, as in the one call.
	assert_eq!(named_steps(&last), named_steps(&answer_one));
	assert!(last["schedule"]["error"].is_null() && last["schedule"].is_object(), "{}", last["schedule"]);
	p.delay(Duration::ZERO);
	for w in [&m, &whole, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pass_in_slices_ends_where_the_pass_in_one_call_does() {
	let mut r = Running::start().await;
	let x = r.x;
	let url = r.url();
	let (m, b) = (Arca::new("SL2 M"), Arca::new("SL2 B"));
	boarded(&mut r, &m, &url, &[(x, 3_000_000)]).await;
	boarded(&mut r, &b, &url, &[(x, 3_000_000)]).await;
	// Six refreshes in a round that is final (their forfeits to hand over,
	// their new coins to take) and six waiting.
	busy(&mut r, &m, &b, 12, 6).await;
	let whole = copy_of(&m, "SL2 M whole");
	let args = json!({"catch_up": false});
	let s = sliced(&m.dir, &args, 1, |_| {});
	let last = &s.last().unwrap().0;
	println!("SL2 in slices of 1 ms: {} slices; steps {:?}", s.len(), named_steps(last));
	for (v, _) in &s {
		assert!(v["error"].is_null(), "{}", v);
	}
	let w = library(&whole, "sync", args.clone()).unwrap();
	println!("SL2 in one call: steps {:?}", named_steps(&w));
	assert_eq!(named_steps(last), named_steps(&w));
	assert!(last["participations"].as_array().unwrap().len() >= 12, "{}", last["participations"]);
	let (cs, cw) = (coins(&m), coins(&whole));
	let live = cs.values().filter(|c| c.0 == "live").count();
	println!("SL2 coins: {} ({} live) in slices, {} in one call", cs.len(), live, cw.len());
	assert_eq!(cs, cw, "the same coins in the same states");
	assert_eq!(participations(&m), participations(&whole));
	assert!(cs.values().filter(|c| c.0 == "spent").count() >= 6, "the six refreshes completed: {:?}", cs);
	assert_eq!(m.ok(&["balance"])["total"], whole.ok(&["balance"])["total"]);
	for w in [&m, &whole, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cut_at_every_safe_point_leaves_every_command_its_wallet() {
	let mut r = Running::start().await;
	let (x, y) = (r.x, r.y);
	let url = r.url();
	let (m, b) = (Arca::new("SL3 M"), Arca::new("SL3 B"));
	boarded(&mut r, &m, &url, &[(x, 3_000_000), (y, 1_000_000)]).await;
	boarded(&mut r, &b, &url, &[(x, 3_000_000)]).await;
	// A watchtower, for the deposits to have items.
	let mut tower = Tower::start(&r, "SL3 T");
	m.ok(&["watchtowers", "--default", &tower.url]);
	// Coins of 100,000 X: a payment of 1,000 from one stays within the
	// wallet's bound on margins.
	busy_of(&mut r, &m, &b, 8, 4, 100_000).await;
	b.ok(&["participate"]);
	final_round(&r).await;
	b.ok(&["sync"]);
	pay_many_of(&mut r, &m, &b, 10, 100_000).await;
	// Two exits under way, of coins the four refreshes made.
	m.ok(&["sync"]);
	let made: Vec<String> = m.ok(&["coins"]).as_array().unwrap().iter()
		.filter(|c| c["state"] == "live" && c["kind"] != "transfer" && c["kind"] != "board" && c["asset"] == x.to_string())
		.map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
	assert!(made.len() >= 2, "{:?}", made);
	for l in made.iter().take(2) {
		library(&m, "exit", json!({"leaf_id": l, "fee_asset": x.to_string()})).expect("an exit starts");
	}
	// Two refreshes waiting for a round, for the step `held` to read.
	for l in live_of(&m, x, 100_000).iter().take(2) {
		m.ok(&["participate", "--leaf", l]);
	}
	// Two payments over Lightning sent and two received, two plans, two
	// orders and two resting orders: items the steps pass over, so that each
	// step has two and a slice of 1 ms is cut between them. (The harness has
	// no Lightning gateway, and these steps' work has suites of its own.)
	let fakes = Fakes::put(&m.dir);
	let total = |w: &Arca| -> u64 {
		w.ok(&["coins"]).as_array().unwrap().iter()
			.filter(|c| c["asset"] == x.to_string() && !matches!(c["state"].as_str(), Some("spent" | "lost")))
			.map(|c| c["value"].as_str().map(|v| v.parse::<u64>().unwrap()).unwrap_or_else(|| c["value"].as_u64().unwrap())).sum()
	};
	let before = total(&m);
	let mut paid = 0u64;
	let kinds = ["pay", "offer", "refresh", "history", "read"];
	let mut ran: std::collections::BTreeMap<&str, (usize, usize)> = std::collections::BTreeMap::new();
	let mdir = m.dir.clone();
	let s = sliced(&m.dir, &json!({}), 0, |k| {
		let kind = kinds[k % kinds.len()];
		let ok = match kind {
			"pay" => {
				let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
				let (ok, v) = m.run(&["send", &req, "--amount", "1000", "--asset", &x.to_string()]);
				if ok {
					// What it sent, and its margins, paid to the operator.
					let n = |v: &Value| v.as_str().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
					let margins = n(&v["margins"]["reassignment"])
						+ v["margins"]["checkpoints"].as_array().map(|a| a.iter().map(n).sum::<u64>()).unwrap_or(0);
					paid += 1000 + margins;
				} else {
					println!("SL3 payment refused: {}", v);
				}
				ok
			},
			// An offer made and cancelled, which gives its coin back for the
			// next.
			"offer" => match lib_at(&mdir, "swap_offer", &json!({"give_asset": y.to_string(), "give": "1000", "want_asset": x.to_string(),
				"want": "1000"}))
			{
				Ok(o) => lib_at(&mdir, "swap_cancel", &json!({"swap": o["swap"]})).map_err(|e| println!("SL3 cancel refused: {}", e)).is_ok(),
				Err(e) => {
					println!("SL3 offer refused: {}", e);
					false
				},
			},
			"refresh" => {
				let live = live_of(&m, x, 100_000);
				live.first().is_some_and(|l| {
					let (ok, v) = m.run(&["participate", "--leaf", l]);
					println!("SL3 refresh between slices: {}", v["participations"][0]["state"]);
					ok
				})
			},
			"history" => lib_at(&mdir, "restore_history", &json!({"budget_ms": 100})).is_ok(),
			_ => lib_at(&mdir, "coin_places", &json!({})).is_ok(),
		};
		let e = ran.entry(kind).or_default();
		e.0 += 1;
		if ok {
			e.1 += 1;
		}
	});
	fakes.take();
	let longest = s.iter().map(|(_, ms)| *ms).max().unwrap();
	let last = &s.last().unwrap().0;
	println!("SL3 the pass's participations: {}", last["participations"]);
	println!("SL3 {} slices of 0 ms, the longest {} ms; commands between them (asked, answered): {:?}", s.len(), longest, ran);
	for (v, _) in &s {
		assert!(v["error"].is_null(), "{}", v);
	}
	// Every safe point reached: a cut after each step but the last, and a
	// cut between two items of every step cut so (bark/src/arca/slice.rs,
	// ITEMS), but the deposits a restore left owed, whose cut
	// `deposits_and_a_restores_owed_deposits_run_in_slices` reaches.
	let (between, inside) = cuts(&s);
	println!("SL3 cut after {} of {} steps: {:?}; cut inside {} of {} steps: {:?}", between.len(), STEPS.len(), between, inside.len(),
		ITEMS.len(), inside);
	for k in STEPS.iter() {
		assert!(between.contains(*k), "no slice ended after {}: {:?}", k, between);
	}
	for k in ITEMS.iter().filter(|k| **k != "owed deposits") {
		assert!(inside.contains(*k), "no slice was cut inside {}: {:?}", k, inside);
	}
	for k in kinds {
		let (asked, answered) = ran.get(k).copied().unwrap_or_default();
		assert!(answered > 0, "{} ran between two slices: {:?}", k, ran);
		// A refresh needs a coin of 100,000 left; everything else answers
		// every time.
		assert!(k == "refresh" || answered == asked, "{} answered {} of {}: {:?}", k, answered, asked, ran);
	}
	// Every refresh and payment settles: what the wallet holds of X is what
	// it held, less what it paid. (A payment between two slices may have
	// taken back a waiting refresh to pay with: then no round stands.)
	m.ok(&["sync"]);
	if let Some(built) = r.server.rounds.run_round().await.unwrap() {
		r.produce().await;
		r.bury().await;
		r.round_state(&built.tx.txid(), RoundState::Final).await;
	}
	m.ok(&["sync"]);
	m.ok(&["sync"]);
	let after = total(&m);
	println!("SL3 X held: {} before, {} after, {} paid with margins", before, after, paid);
	assert_eq!(after + paid, before, "nothing lost or made");
	assert!(m.ok(&["coins"]).as_array().unwrap().iter().all(|c| c["state"] != "given"), "no coin left given: {}", m.ok(&["coins"]));
	tower.stop();
	for w in [&m, &b, &tower.wallet] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pass_goes_on_from_the_store_and_starts_again_when_stale() {
	let mut r = Running::start().await;
	let x = r.x;
	let url = r.url();
	let (m, b) = (Arca::new("SL4 M"), Arca::new("SL4 B"));
	boarded(&mut r, &m, &url, &[(x, 3_000_000)]).await;
	boarded(&mut r, &b, &url, &[(x, 3_000_000)]).await;
	busy(&mut r, &m, &b, 6, 3).await;
	let args = json!({"budget_ms": 1});
	// Each slice is a call of its own, the library opened afresh.
	let first = library(&m, "sync", args.clone()).unwrap();
	let second = library(&m, "sync", args.clone()).unwrap();
	println!("SL4 two slices: {} | {}", first, second);
	assert_eq!((first["more"].as_bool(), first["slice"].as_u64()), (Some(true), Some(1)), "{}", first);
	assert_eq!(second["slice"], 2, "the second call goes on: {}", second);
	assert!(library(&m, "schedule", json!({})).unwrap()["due"] == true, "due while a pass is under way");
	// Ten minutes and more of median time: the pass starts again.
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 700));
	r.synced().await;
	let again = library(&m, "sync", args.clone()).unwrap();
	println!("SL4 after 700 s: {}", again);
	assert_eq!(again["slice"], 1, "a stale pass starts again: {}", again);
	assert!(again["cost_by_step"].as_object().unwrap().contains_key("witness"), "{}", again);
	// Other arguments: a pass of their own.
	let other = library(&m, "sync", json!({"budget_ms": 1, "deposits": false})).unwrap();
	assert_eq!(other["slice"], 1, "{}", other);
	// No budget: a whole pass, and no resume point left.
	let whole = library(&m, "sync", json!({})).unwrap();
	assert!(whole["more"].is_null() && whole["slices"].is_null() && whole["schedule"].is_object(), "{}", whole);
	let next = library(&m, "sync", args.clone()).unwrap();
	assert_eq!(next["slice"], 1, "a new pass after a whole one: {}", next);
	// The pass in slices goes to its end.
	let s = sliced(&m.dir, &json!({}), 1, |_| {});
	let last = &s.last().unwrap().0;
	println!("SL4 to the end: {} more slices, the last answers {} slices", s.len(), last["slices"]);
	assert!(last["more"].is_null() && last["schedule"].is_object(), "{}", last);
	assert!(library(&m, "schedule", json!({})).unwrap()["why"] != "a sync in slices is under way: the next call goes on where the last stopped");
	for w in [&m, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// Whether the test operator offers checkpoints with their owners' exit
/// (ARCA_TEST_CHECKPOINT_EXIT, as `common::running` reads it).
fn checkpoint_exit() -> bool {
	!matches!(std::env::var("ARCA_TEST_CHECKPOINT_EXIT").ok().map(|v| v.trim().to_ascii_lowercase()).as_deref(), Some("0" | "false"))
}

/// One library command on the wallet at `dir`, opened for it alone, with a
/// witness patience of `patience` when given.
fn lib_patient(dir: &Path, cmd: &str, args: &Value, patience: Option<Duration>) -> Result<Value, String> {
	let mut w = Wallet::open(dir).expect("open the wallet");
	if let Some(p) = patience {
		w.witness_patience = p;
	}
	command::run(&mut w, cmd, args).map(|v| v["result"].clone()).map_err(|e| e.to_string())
}

/// With the operator unreachable (every witness answered 502), a slice
/// waits out the witness's patience once and then runs the rest of its
/// pass, as one call does: the step that takes coins home when the
/// operator does not answer (`home`, D57) comes in every pass, and a pass
/// pays the patience once, not once a slice.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_operator_costs_a_pass_one_patience_and_home_comes() {
	let mut r = Running::start().await;
	let x = r.x;
	let url = r.url();
	let p = Proxy::start(&url);
	let m = Arca::new("SL5 M");
	boarded(&mut r, &m, &p.url, &[(x, 3_000_000)]).await;
	p.lose("/v1/witness", true);
	// One slice at the library's own patience.
	let t = Instant::now();
	let v = tokio::task::block_in_place(|| lib_patient(&m.dir, "sync", &json!({"budget_ms": 1000}), None)).unwrap();
	let ms = t.elapsed().as_millis() as u64;
	println!("SL5 one slice at the default patience: {} ms, more {}, slices {}, home {}, unreachable {}", ms, v["more"], v["slices"],
		v["cost_by_step"]["home"], v["unreachable"]["why"]);
	assert!(ms >= 60_000, "the patience was waited: {} ms", ms);
	assert!(v["more"].is_null() && v["slices"] == 1, "the pass ended in the slice: {}", v);
	assert!(v["cost_by_step"]["home"].is_object() && v["cost_by_step"]["schedule"].is_object(), "{}", v);
	assert!(v["unreachable"].is_object() && v["home"].is_array(), "{}", v);
	// Pass after pass, the median time moving on as on the testnet (60 s
	// blocks): each pass ends, `home` in each, the patience paid once.
	let patience = Some(Duration::from_secs(3));
	for pass in 1..=3 {
		let mut calls = 0;
		let mut waited = 0;
		let last = loop {
			calls += 1;
			let t = Instant::now();
			let v = tokio::task::block_in_place(|| lib_patient(&m.dir, "sync", &json!({"budget_ms": 1000}), patience)).unwrap();
			if t.elapsed() >= Duration::from_secs(3) {
				waited += 1;
			}
			tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 61));
			r.synced().await;
			if v["more"] != json!(true) {
				break v;
			}
			assert!(calls < 5, "the pass ends: {}", v);
		};
		println!("SL5 pass {}: {} calls, {} waited the patience; home {}", pass, calls, waited, last["cost_by_step"]["home"]);
		assert!(last["cost_by_step"]["home"].is_object() && last["unreachable"].is_object(), "{}", last);
		assert_eq!(waited, 1, "one patience a pass");
	}
	p.lose("/v1/witness", false);
	let _ = std::fs::remove_dir_all(&m.dir);
}

/// Two callers of one library alternating slices with other arguments each
/// go on with their own pass, and each ends its passes.
#[tokio::test(flavor = "multi_thread")]
async fn two_callers_with_other_arguments_each_end_their_passes() {
	let mut r = Running::start().await;
	let x = r.x;
	let url = r.url();
	let m = Arca::new("SL6 M");
	boarded(&mut r, &m, &url, &[(x, 3_000_000)]).await;
	let (a, b) = (json!({"budget_ms": 1}), json!({"budget_ms": 1, "deposits": false}));
	let mut ended = [0, 0];
	let mut most = 0u64;
	for k in 0..60 {
		let v = library(&m, "sync", if k % 2 == 0 { a.clone() } else { b.clone() }).unwrap();
		if v["more"] != json!(true) {
			ended[k % 2] += 1;
			assert!(v["schedule"].is_object() && v["cost_by_step"]["home"].is_object(), "{}", v);
		}
		most = most.max(v["slice"].as_u64().unwrap_or(0));
	}
	println!("SL6 60 alternating slices: passes ended {:?}, the highest slice number {}", ended, most);
	assert!(ended[0] >= 1 && ended[1] >= 1, "each caller ends its pass: {:?}", ended);
	assert!(most > 1);
	let _ = std::fs::remove_dir_all(&m.dir);
}

/// A trade's coin that comes in through the mailbox during a sliced sync
/// goes to the watchtowers at once, as in one call: the deposits a trade
/// makes run outside the step's slice, the mailbox step runs once in its
/// pass, and the pass answers the coins it took.
#[tokio::test(flavor = "multi_thread")]
async fn a_trade_coin_taken_in_a_slice_is_deposited_at_once() {
	let mut r = Running::start().await;
	let (url, node) = (r.url(), r.node_url());
	let (x, y) = (r.x, r.y);
	let m = Arca::new("SL7 M");
	boarded(&mut r, &m, &url, &[(y, 1_000_000)]).await;
	let mut tower = Tower::start(&r, "SL7 T");
	// Two takers, each with the watchtower and four refreshed coins of X
	// not yet deposited: one syncs in slices, the other in one call.
	let mut takers = vec![];
	for name in ["SL7 S", "SL7 W"] {
		let b = Arca::new(name);
		b.ok(&["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
		b.ok(&["watchtowers", "--default", &tower.url]);
		for _ in 0..5 {
			r.pay_to(script(&b.ok(&["address"])), x, 2_000_000);
		}
		r.produce().await;
		for _ in 0..4 {
			b.ok(&["board", &x.to_string(), "1000000"]);
		}
		r.produce().await;
		r.bury().await;
		r.synced().await;
		r.wait("the boards to be credited", || b.ok(&["boards"]).as_array().unwrap().iter().all(|v| v["server"]["state"] == "credited")).await;
		library(&b, "sync", json!({"deposits": false})).unwrap();
		for l in b.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live").map(|c| c["leaf_id"].as_str().unwrap().to_string()) {
			b.ok(&["participate", "--leaf", &l, "--max-fee-ppm", "1000000"]);
		}
		takers.push(b);
	}
	final_round(&r).await;
	for b in &takers {
		library(b, "sync", json!({"deposits": false})).unwrap();
	}
	let mut seen = vec![];
	for (k, b) in takers.iter().enumerate() {
		let o = library(&m, "swap_offer", json!({"give_asset": y.to_string(), "give": "10000", "want_asset": x.to_string(), "want": "10000"}))
			.unwrap();
		let text = o["offer"].as_str().unwrap().to_string();
		let read = library(b, "swap_read", json!({"offer": text})).unwrap();
		let acc = library(b, "swap_accept", json!({"offer": text, "shown": read})).unwrap();
		library(&m, "swap_complete", json!({"accept": acc["accept"]})).unwrap();
		let answer = if k == 0 {
			let s = sliced(&b.dir, &json!({"deposits": false}), 1, |_| {});
			let mailbox_in: Vec<u64> = s.iter().filter(|(v, _)| v["cost_by_step"]["mailbox"].is_object())
				.map(|(v, _)| v["slice"].as_u64().unwrap_or(0)).collect();
			println!("SL7 {} slices; the mailbox step ran in {:?}", s.len(), mailbox_in);
			assert_eq!(mailbox_in.len(), 2, "once, and in the last answer's cost: {:?}", mailbox_in);
			s.last().unwrap().0.clone()
		} else {
			library(b, "sync", json!({"deposits": false})).unwrap()
		};
		let taken: Vec<Value> = answer["mailbox"]["accepted"].as_array().cloned().unwrap_or_default();
		println!("SL7 {} ({}): mailbox accepted {}", b.name, if k == 0 { "in slices" } else { "one call" },
			serde_json::to_string(&taken.iter().map(|t| json!({"leaf": t["leaf_id"], "asset": t["asset"], "watchtowers": t["watchtowers"]}))
				.collect::<Vec<_>>()).unwrap());
		assert!(taken.iter().any(|t| t["asset"] == y.to_string()), "the trade's coin is answered: {}", answer["mailbox"]);
		let later = library(b, "deposits", json!({})).unwrap();
		let made: Vec<String> = later.as_array().unwrap().iter().filter_map(|d| d["leaf_id"].as_str().map(String::from)).collect();
		println!("SL7 {}: the deposits a later `deposits` makes: {:?}", b.name, made);
		// A trade's coins go to the watchtowers at once when they carry
		// their owners' exit, which an operator without checkpoints with
		// their owners' exit (ARCA_TEST_CHECKPOINT_EXIT=0) does not offer:
		// then they wait for the deposits step, in slices as in one call.
		if checkpoint_exit() {
			for t in &taken {
				assert!(t["watchtowers"]["not_held"].is_null() && !t["watchtowers"]["held"].as_array().unwrap().is_empty(),
					"held by the watchtower at once: {}", t);
			}
			assert!(made.is_empty(), "every coin was deposited at once: {:?}", made);
		}
		seen.push((taken.iter().map(|t| (t["asset"].clone(), t["watchtowers"].is_null())).collect::<Vec<_>>(), made.len()));
	}
	println!("SL7 in slices and in one call (coins taken, whether no deposit was asked; deposits left): {:?}", seen);
	assert_eq!(seen[0], seen[1], "in slices as in one call");
	tower.stop();
	for w in [&m, &tower.wallet, &takers[0], &takers[1]] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// While no witness of the operator's signer's record succeeds, `sync`
/// asks the operator nothing about payments received over Lightning.
#[tokio::test(flavor = "multi_thread")]
async fn no_receive_is_asked_while_no_witness_succeeds() {
	let mut r = Running::start().await;
	let x = r.x;
	let url = r.url();
	let p = Proxy::start(&url);
	let m = Arca::new("SL8 M");
	boarded(&mut r, &m, &p.url, &[(x, 1_000_000)]).await;
	let hash = "11".repeat(32);
	{
		let db = rusqlite::Connection::open(m.dir.join("arca.sqlite")).unwrap();
		let v = json!({ hash.clone(): {"state": "waiting", "asset": x.to_string(), "value": "1000", "nonce": "22".repeat(32)} });
		db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('lightning_receives', ?1)", [v.to_string()]).unwrap();
	}
	p.lose("/v1/witness", true);
	let before = p.count("/v1/lightning_receive_status");
	let s = tokio::task::block_in_place(|| lib_patient(&m.dir, "sync", &json!({}), Some(Duration::from_secs(2)))).unwrap();
	let asked = p.count("/v1/lightning_receive_status") - before;
	println!("SL8 witness {}; lightning_receive_status asked {} time(s) with no witness; receives again cost {}", s["witness"], asked,
		s["cost_by_step"]["receives again"]);
	assert!(s["witness"]["error"].is_string(), "{}", s["witness"]);
	assert_eq!(asked, 0, "the operator was asked about a payment while no witness succeeded");
	p.lose("/v1/witness", false);
	// With the witness back, the receive is asked after.
	let s = library(&m, "sync", json!({})).unwrap();
	let asked = p.count("/v1/lightning_receive_status") - before;
	println!("SL8 with the witness: asked {} time(s)", asked);
	assert!(s["witness"]["error"].is_null() && asked >= 1, "{}", s["witness"]);
	let _ = std::fs::remove_dir_all(&m.dir);
}

/// Each resumed slice re-checks the chain's tip as every other command
/// does at its start: the lineage watch while the tip is the one the last
/// complete re-check ran at, the whole re-check when it moved. A round's
/// block taken out of the chain between two slices takes its coin out of
/// `live` at the next slice.
#[tokio::test(flavor = "multi_thread")]
async fn a_resumed_slice_rechecks_a_tip_that_moved() {
	let mut r = Running::start().await;
	let x = r.x;
	let url = r.url();
	let m = Arca::new("SL9 M");
	boarded(&mut r, &m, &url, &[(x, 3_000_000)]).await;
	m.ok(&["participate"]);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	m.ok(&["sync"]);
	let leaf = m.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["state"] == "live").unwrap()["leaf_id"].as_str().unwrap().to_string();
	let state_in_store = |leaf: &str| -> String {
		let db = rusqlite::Connection::open(m.dir.join("arca.sqlite")).unwrap();
		db.query_row("SELECT state FROM coin WHERE leaf_id = ?1", [leaf], |r| r.get(0)).unwrap()
	};
	let height = |r: &Running| r.rt.client().call::<Value>("getblockcount", &[]).unwrap().as_u64().unwrap();
	// One wallet open across the slices, as a host keeps it.
	let mut w = Wallet::open(&m.dir).expect("open the wallet");
	let slice = |w: &mut Wallet| -> Value {
		tokio::task::block_in_place(|| command::run(w, "sync", &json!({"budget_ms": 1}))).map(|v| v["result"].clone()).unwrap()
	};
	let first = slice(&mut w);
	assert_eq!(first["slice"], 1, "{}", first);
	// The tip unchanged: the lineage watch only.
	let second = slice(&mut w);
	println!("SL9 the tip unchanged: slice {} recheck {}", second["slice"], second["recheck"]);
	assert_eq!(second["slice"], 2, "{}", second);
	assert!(second["recheck"]["lineages_only"].is_string(), "{}", second);
	// A block more: the whole re-check, at the new tip.
	r.produce().await;
	r.synced().await;
	let third = slice(&mut w);
	println!("SL9 a block more: slice {} recheck tip {} read_again {}", third["slice"], third["recheck"]["tip"], third["recheck"]["read_again"]);
	assert_eq!(third["slice"], 3, "{}", third);
	assert_eq!(third["recheck"]["tip"]["height"], json!(height(&r)), "{}", third["recheck"]);
	// The round's block taken out of the chain: the next slice, the pass
	// resumed or (the median time having gone back with the tip) started
	// again, sees it before it does anything else.
	let block = r.rt.client().call::<Value>("getrawtransaction", &[json!(built.tx.txid().to_string()), json!(true)]).unwrap()["blockhash"]
		.as_str().unwrap().to_string();
	let _: Value = r.rt.client().call("invalidateblock", &[json!(block)]).unwrap();
	let fourth = slice(&mut w);
	println!("SL9 after the round's block left the chain: slice {} recheck {}", fourth["slice"], fourth["recheck"]);
	let recheck = if fourth["slice"] == 4 { fourth["recheck"].clone() } else {
		// A pass started again answers its re-check in its last slice.
		let mut last = fourth.clone();
		while last["more"] == json!(true) {
			last = slice(&mut w);
		}
		last["recheck"].clone()
	};
	assert_eq!(recheck["reorganised"], true, "{}", recheck);
	assert!(recheck["changes"].as_array().unwrap().iter().any(|c| c["leaf_id"] == json!(leaf) && c["to"] == "pending"), "{}", recheck);
	assert_eq!(state_in_store(&leaf), "pending", "the coin waits on its round again");
	// The round back, final: the pass goes on to its end.
	let _: Value = r.rt.client().call("reconsiderblock", &[json!(block)]).unwrap();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let mut last = slice(&mut w);
	while last["more"] == json!(true) {
		last = slice(&mut w);
	}
	drop(w);
	println!("SL9 the last slice: slices {}, recheck changes {}", last["slices"], last["recheck"]["changes"]);
	assert_eq!(state_in_store(&leaf), "live", "the round back in the chain, final");
	let _ = std::fs::remove_dir_all(&m.dir);
}

/// `deposits {budget_ms}`: each slice deposits at least one coin and
/// answers `{"deposits", "more": true}` until the last; every coin is held
/// in the end; without the budget the answer is the list. And the deposits
/// a restore left owed, `sync`'s first step, run in slices too, cut
/// between two coins.
#[tokio::test(flavor = "multi_thread")]
async fn deposits_and_a_restores_owed_deposits_run_in_slices() {
	let mut r = Running::start().await;
	let (url, node) = (r.url(), r.node_url());
	let x = r.x;
	let a = Arca::new("SL10 A");
	a.ok(&["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	let mut tower = Tower::start(&r, "SL10 T");
	a.ok(&["watchtowers", "--default", &tower.url]);
	for _ in 0..9 {
		r.pay_to(script(&a.ok(&["address"])), x, 2_000_000);
	}
	r.produce().await;
	for _ in 0..8 {
		a.ok(&["board", &x.to_string(), "1000000"]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards to be credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	library(&a, "sync", json!({"deposits": false})).unwrap();
	let live: Vec<String> = a.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live")
		.map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
	// Four coins refreshed: their deposits made by `deposits` in slices.
	for l in &live[..4] {
		a.ok(&["participate", "--leaf", l, "--max-fee-ppm", "1000000"]);
	}
	final_round(&r).await;
	library(&a, "sync", json!({"deposits": false})).unwrap();
	let mut calls = vec![];
	loop {
		let v = library(&a, "deposits", json!({"budget_ms": 1})).unwrap();
		println!("SL10 slice: {}", v);
		assert!(v.is_object() && v["deposits"].is_array(), "{}", v);
		let more = v["more"] == json!(true);
		calls.push(v);
		if !more {
			break;
		}
		assert!(calls.len() < 50, "ends");
	}
	let held = tower.held();
	println!("SL10 {} slices; the watchtower holds {} deposits", calls.len(), held);
	let whole = library(&a, "deposits", json!({})).unwrap();
	println!("SL10 without the budget: {}", whole);
	assert!(whole.is_array(), "{}", whole);
	assert!(calls.len() >= 2, "in slices: {}", calls.len());
	assert!(held >= 4, "every coin held: {} of 4", held);
	// The other four refreshed, and their deposits left owed, as a restore
	// leaves them: `sync`'s first step makes them, in slices.
	for l in &live[4..] {
		a.ok(&["participate", "--leaf", l, "--max-fee-ppm", "1000000"]);
	}
	final_round(&r).await;
	library(&a, "sync", json!({"deposits": false})).unwrap();
	{
		let db = rusqlite::Connection::open(a.dir.join("arca.sqlite")).unwrap();
		db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('deposits_owed', '1')", []).unwrap();
	}
	let s = sliced(&a.dir, &json!({}), 1, |_| {});
	let (_, inside) = cuts(&s);
	let last = &s.last().unwrap().0;
	println!("SL10 the owed deposits in slices: {} slices, cut inside {:?}; deposits {}", s.len(), inside, last["deposits"]);
	assert!(inside.contains("owed deposits"), "{:?}", inside);
	assert!(tower.held() >= 8, "every coin held: {} of 8", tower.held());
	tower.stop();
	for w in [&a, &tower.wallet] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// Cuts with other commands between two slices than the cut test's: a refresh withdrawn, a swap offered, accepted and completed,
/// a coin's exit, a whole sync (once), coin places. The pass then ends, and
/// with rounds run, the wallet's value of X is what it held, plus what the
/// swaps brought.
#[tokio::test(flavor = "multi_thread")]
async fn cuts_with_trades_exits_and_a_whole_sync_between() {
	let mut r = Running::start().await;
	let (x, y) = (r.x, r.y);
	let url = r.url();
	let (m, b) = (Arca::new("SL11 M"), Arca::new("SL11 B"));
	boarded(&mut r, &m, &url, &[(x, 3_000_000), (y, 1_000_000)]).await;
	boarded(&mut r, &b, &url, &[(x, 3_000_000)]).await;
	busy(&mut r, &m, &b, 8, 4).await;
	b.ok(&["participate"]);
	final_round(&r).await;
	b.ok(&["sync"]);
	let held_x = |w: &Arca| -> u64 {
		w.ok(&["coins"]).as_array().unwrap().iter()
			.filter(|c| c["asset"] == x.to_string() && !matches!(c["state"].as_str(), Some("spent" | "lost" | "exited")))
			.map(|c| c["value"].as_str().map(|v| v.parse::<u64>().unwrap()).unwrap_or_else(|| c["value"].as_u64().unwrap())).sum()
	};
	let before = held_x(&m);
	let mut got = 0u64;
	let mut exited: Vec<String> = vec![];
	let kinds = ["withdraw", "swap", "exit", "places", "whole"];
	let mut ran: std::collections::BTreeMap<&str, (usize, usize)> = std::collections::BTreeMap::new();
	let mut slices = 0;
	let mut whole_done = false;
	let mut k = 0usize;
	loop {
		let v = lib_at(&m.dir, "sync", &json!({"budget_ms": 1})).expect("a slice answers");
		slices += 1;
		assert!(v["error"].is_null(), "{}", v);
		if v["more"] != json!(true) {
			println!("SL11 the last slice: slices {} participations {} home {} exits {}", v["slices"], v["participations"], v["home"], v["exits"]);
			break;
		}
		assert!(slices < 400, "the pass ends");
		let mut kind = kinds[k % kinds.len()];
		k += 1;
		if kind == "whole" && whole_done {
			kind = "places";
		}
		let ok = match kind {
			"withdraw" => {
				let ps = lib_at(&m.dir, "participations", &json!({})).unwrap();
				let pending = ps.as_array().unwrap().iter().find(|p| p["state"] == "pending").and_then(|p| p["participation"].as_str())
					.map(str::to_string);
				pending.is_some_and(|pid| {
					let w = lib_at(&m.dir, "withdraw_participation", &json!({"participation": pid}));
					println!("SL11 withdrawn between slices: {:?}", w.as_ref().map(|v| v["state"].clone()));
					w.is_ok()
				})
			},
			"swap" => {
				let o = lib_at(&m.dir, "swap_offer", &json!({"give_asset": y.to_string(), "give": "1000", "want_asset": x.to_string(),
					"want": "1000"}));
				match o {
					Ok(o) => {
						let text = o["offer"].as_str().unwrap().to_string();
						let _ = lib_at(&b.dir, "sync", &json!({}));
						let read = lib_at(&b.dir, "swap_read", &json!({"offer": text})).unwrap();
						match lib_at(&b.dir, "swap_accept", &json!({"offer": text, "shown": read})) {
							Ok(acc) => {
								let done = lib_at(&m.dir, "swap_complete", &json!({"accept": acc["accept"]}));
								println!("SL11 swap between slices: {:?}", done.as_ref().map(|d| d["swap"].clone()));
								if done.is_ok() {
									got += 1000;
								}
								done.is_ok()
							},
							Err(e) => {
								println!("SL11 acceptance refused: {}", e);
								let _ = lib_at(&m.dir, "swap_cancel", &json!({"swap": o["swap"]}));
								false
							},
						}
					},
					Err(e) => {
						println!("SL11 offer refused: {}", e);
						false
					},
				}
			},
			"exit" => {
				let live: Vec<String> = m.ok(&["coins"]).as_array().unwrap().iter()
					.filter(|c| c["state"] == "live" && c["asset"] == x.to_string() && (c["value"] == "20000" || c["value"] == 20000))
					.map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
				live.first().is_some_and(|l| {
					let e = lib_at(&m.dir, "exit", &json!({"leaf_id": l, "fee_asset": x.to_string()}));
					println!("SL11 exit between slices: {:?}", e.as_ref().map(|v| v["state"].clone()).map_err(|e| e.clone()));
					if e.is_ok() {
						exited.push(l.clone());
					}
					e.is_ok()
				})
			},
			"whole" => {
				whole_done = true;
				lib_at(&m.dir, "sync", &json!({})).is_ok()
			},
			_ => lib_at(&m.dir, "coin_places", &json!({})).is_ok(),
		};
		let e = ran.entry(kind).or_default();
		e.0 += 1;
		if ok {
			e.1 += 1;
		}
	}
	println!("SL11 {} slices; commands between them (asked, answered): {:?}; exited {:?}", slices, ran, exited);
	m.ok(&["sync"]);
	if let Some(built) = r.server.rounds.run_round().await.unwrap() {
		r.produce().await;
		r.bury().await;
		r.round_state(&built.tx.txid(), RoundState::Final).await;
	}
	m.ok(&["sync"]);
	m.ok(&["sync"]);
	let ids: Vec<String> = m.ok(&["coins"]).as_array().unwrap().iter().map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
	let unique: std::collections::BTreeSet<&String> = ids.iter().collect();
	assert_eq!(ids.len(), unique.len(), "every coin once");
	let after = held_x(&m);
	println!("SL11 X held: {} before, {} after, {} got by swaps", before, after, got);
	assert_eq!(after, before + got, "nothing lost or made");
	assert!(m.ok(&["coins"]).as_array().unwrap().iter().all(|c| c["state"] != "given"), "no coin left given");
	for w in [&m, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// Rows of a long history written into the store at `dir`, `n` of each
/// kind: payments over Lightning settled, received ones done, and resting
/// orders done. (The harness has no Lightning gateway; a maker's store
/// holds hundreds of each, every one a row its sync's steps read.)
fn history_rows(dir: &Path, n: usize) {
	let db = rusqlite::Connection::open(dir.join("arca.sqlite")).unwrap();
	let id = |p: &str, k: usize| format!("{}{:062x}", p, k);
	let pays: serde_json::Map<String, Value> = (0..n).map(|k| (id("a1", k), json!({"state": "settled"}))).collect();
	let gets: serde_json::Map<String, Value> = (0..n).map(|k| (id("b1", k), json!({"state": "done"}))).collect();
	for (k, v) in [("lightning_sends", Value::Object(pays)), ("lightning_receives", Value::Object(gets))] {
		db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)", [k, &v.to_string()]).unwrap();
	}
	for k in 0..n {
		db.execute("INSERT INTO resting_order (id, nonce, terms, amount, credit_nonces, order_leaf, state, created_at) \
			VALUES (?1, zeroblob(32), '{}', 0, '[]', NULL, 'done', 1)", [id("f1", k)]).unwrap();
	}
}

/// A pass of `sync` with `args` on the wallet at `dir`, opened once for the
/// whole pass as a host keeps it: in one call, or in slices of `budget`
/// ms (at most `most`). Each call's answer, its time and its cost.
fn pass_of(dir: &Path, args: &Value, budget: Option<u64>, most: usize) -> Vec<(Value, u64, Value)> {
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(dir).expect("open the wallet");
		let mut out = vec![];
		loop {
			let mut a = args.clone();
			if let Some(b) = budget {
				a["budget_ms"] = json!(b);
			}
			let t = Instant::now();
			let v = command::run(&mut w, "sync", &a).expect("a slice answers");
			let ms = t.elapsed().as_millis() as u64;
			let more = v["result"]["more"] == json!(true);
			out.push((v["result"].clone(), ms, json!({"start": v["start"].clone(), "cost": v["cost"].clone()})));
			if !more || out.len() >= most {
				return out;
			}
		}
	})
}

/// What a pass cost: slices, ms in all, the longest slice, and the node's
/// and the operator's requests in all (start and command).
fn pass_cost(p: &[(Value, u64, Value)]) -> (usize, u64, u64, u64, u64) {
	let n = |v: &Value| v.as_u64().unwrap_or(0);
	let (mut node, mut op) = (0, 0);
	for (_, _, c) in p {
		node += n(&c["cost"]["start"]["node"]) + n(&c["cost"]["command"]["node"]);
		op += n(&c["cost"]["start"]["operator"]) + n(&c["cost"]["command"]["operator"]);
	}
	(p.len(), p.iter().map(|x| x.1).sum(), p.iter().map(|x| x.1).max().unwrap_or(0), node, op)
}

/// Where a pass's time went: by step, summed over its slices (ms, the
/// node's and the operator's requests, how many slices ran the step).
fn by_step(p: &[(Value, u64, Value)]) -> std::collections::BTreeMap<String, (u64, u64, u64, u64)> {
	let mut m: std::collections::BTreeMap<String, (u64, u64, u64, u64)> = std::collections::BTreeMap::new();
	for (v, _, c) in p {
		// The last answer's `cost_by_step` is the whole pass's: it is what a
		// pass in one call answers too.
		let _ = c;
		if v["more"] != json!(true) {
			m.clear();
		}
		let steps = v["cost_by_step"].clone();
		for (k, s) in steps.as_object().cloned().unwrap_or_default() {
			let e = m.entry(k).or_default();
			e.0 += s["ms"].as_u64().unwrap_or(0);
			e.1 += s["node"].as_u64().unwrap_or(0);
			e.2 += s["operator"].as_u64().unwrap_or(0);
			e.3 = s["slice"].as_u64().unwrap_or(1);
		}
	}
	m
}

/// A store as large as a busy maker's: seven assets, about six hundred live
/// coins (each board refreshed into pieces, a third of those into pieces
/// again), forty payments received and refreshed, ten refreshes waiting for
/// a round, payments sent, and two hundred rows each of Lightning payments
/// sent and received and of resting orders done. A pass in slices of a
/// second costs about what one call costs, and a slice advances by real
/// work for its budget.
#[tokio::test(flavor = "multi_thread")]
async fn a_pass_in_slices_on_a_large_store_costs_about_one_call() {
	let mut r = Running::start_with_assets(5).await;
	let x = r.x;
	let assets: Vec<AssetId> = [r.x, r.y].into_iter().chain(r.more.iter().copied()).collect();
	let url = r.url();
	let p = Proxy::start(&url);
	let (m, b) = (Arca::new("SL12 M"), Arca::new("SL12 B"));
	let t0 = Instant::now();
	let boards: Vec<(AssetId, u64)> = assets.iter().map(|a| (*a, 6_000_000)).collect();
	boarded(&mut r, &m, &p.url, &boards).await;
	boarded(&mut r, &b, &url, &[(x, 3_000_000)]).await;
	// Each board in fourteen pieces of 400,000 and a reserve; then five of
	// each asset's pieces in fourteen of 25,000 and a reserve.
	let split = |m: &Arca, leaves: Vec<String>, piece: u64| {
		for l in leaves {
			let args = json!({"leaves": [l], "piece": piece.to_string(), "pieces": 14});
			let q = library(m, "quote", args.clone()).unwrap();
			let mut a = args.clone();
			a["shown"] = q["coins"].clone();
			let made = library(m, "participate", a).unwrap();
			assert_eq!(made["participations"][0]["state"], "pending", "{}", made);
		}
	};
	for a in &assets {
		let board: Vec<String> = live_of(&m, *a, 6_000_000);
		split(&m, board, 400_000);
	}
	settled(&r, &m).await;
	for a in &assets {
		// The pieces of about 400,000 (less a fee where the operator asks one).
		let l: Vec<String> = coins(&m).into_iter()
			.filter(|(_, c)| c.0 == "live" && c.2 == a.to_string() && (300_000..=400_000).contains(&c.1.trim_matches('"').parse::<u64>().unwrap_or(0)))
			.map(|(id, _)| id).collect();
		assert!(l.len() >= 5, "pieces of {}: {}; its coins {:?}", a, l.len(), coins(&m).values().filter(|c| c.2 == a.to_string()).collect::<Vec<_>>());
		split(&m, l.into_iter().take(5).collect(), 25_000);
	}
	settled(&r, &m).await;
	// Forty payments received, thirty of them refreshed, ten waiting; ten
	// payments sent.
	pay_many_of(&mut r, &m, &b, 40, 20_000).await;
	let received: Vec<String> = m.ok(&["coins"]).as_array().unwrap().iter()
		.filter(|c| c["state"] == "live" && c["kind"] == "transfer").map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
	for l in received.iter().take(30) {
		m.ok(&["participate", "--leaf", l]);
	}
	settled(&r, &m).await;
	m.ok(&["sync"]);
	for _ in 0..10 {
		pay(&m, &b, x, 1_000);
	}
	for l in received.iter().skip(30) {
		m.ok(&["participate", "--leaf", l]);
	}
	history_rows(&m.dir, 200);
	let cs = coins(&m);
	let live = cs.values().filter(|c| c.0 == "live").count();
	let by_asset = assets.iter().map(|a| cs.values().filter(|c| c.0 == "live" && c.2 == a.to_string()).count()).collect::<Vec<_>>();
	println!("SL12 store built in {} s: {} coins, {} live {:?}, {} participations", t0.elapsed().as_secs(), cs.len(), live, by_asset,
		participations(&m).len());
	let mut states: std::collections::BTreeMap<(String, String), usize> = std::collections::BTreeMap::new();
	for c in cs.values() {
		*states.entry((c.2.chars().take(6).collect(), c.0.clone())).or_default() += 1;
	}
	println!("SL12 coins by asset and state: {:?}", states);
	assert!(live >= 550, "a large store: {} live coins", live);
	// The operator over a far link, as in SL1.
	let delay = std::env::var("SL_OPERATOR_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(150);
	p.delay(Duration::from_millis(delay));
	let args = json!({"catch_up": false, "deposits": false});
	let whole = copy_of(&m, "SL12 whole");
	let one = pass_of(&whole.dir, &args, None, 1);
	let (_, one_ms, _, one_node, one_op) = pass_cost(&one);
	println!("SL12 one call ({} ms a call to the operator): {} ms, node {}, operator {}", delay, one_ms, one_node, one_op);
	println!("SL12 one call by step: {:?}", by_step(&one));
	println!("SL12 one call's refresh: {}", one[0].0["cost_by_step"]["refresh"]);
	println!("SL12 one call's held: {}", one[0].0["cost_by_step"]["held"]);
	let budgets: Vec<u64> = std::env::var("SL_BUDGETS").ok().map(|v| v.split(',').filter_map(|b| b.parse().ok()).collect())
		.unwrap_or(vec![1000]);
	let mut results = vec![];
	for b in budgets {
		let c = copy_of(&m, &format!("SL12 sliced {}", b));
		let most = std::env::var("SL_MOST").ok().and_then(|v| v.parse().ok()).unwrap_or(600);
		let s = pass_of(&c.dir, &args, Some(b), most);
		let (n, ms, longest, node, op) = pass_cost(&s);
		let ended = s.last().unwrap().0["more"] != json!(true);
		println!("SL12 slices of {} ms: {} slices{}, {} ms in all, the longest {} ms, node {}, operator {}; {:.2} times one call", b, n,
			if ended { "" } else { " (not ended)" }, ms, longest, node, op, ms as f64 / one_ms.max(1) as f64);
		println!("SL12 slices of {} ms by step (ms, node, operator, the slice it ended in): {:?}", b, by_step(&s));
		for (k, (v, ms, c)) in s.iter().enumerate().take(4) {
			println!("SL12 slice {} of {} ms: {} ms, start {}, cost {}, steps {:?}", k + 1, b, ms, c["cost"]["start"], c["cost"]["command"],
				v["cost_by_step"].as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()).unwrap_or_default());
		}
		results.push((b, n, ms, longest, node, op, ended));
		let _ = std::fs::remove_dir_all(&c.dir);
	}
	p.delay(Duration::ZERO);
	for w in [&m, &whole, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
	// Bounded against the one call on the same machine at the same moment, so
	// that a loaded machine slows both alike: the pass ends, costs at most
	// about twice the one call, asks the operator little more than it, and no
	// slice holds the wallet for more than a fraction of it.
	for (b, n, ms, longest, _, op, ended) in results {
		assert!(ended, "slices of {} ms: the pass ends ({} slices)", b, n);
		assert!(ms <= 2 * one_ms + 5_000, "slices of {} ms: {} ms in all against {} ms in one call", b, ms, one_ms);
		assert!(op <= one_op + 2 * n as u64 + 10, "slices of {} ms: {} requests of the operator against {} in one call, in {} slices", b, op,
			one_op, n);
		assert!(longest * 4 <= one_ms, "slices of {} ms: a slice held the wallet {} ms, against {} ms in one call", b, longest, one_ms);
	}
}

/// A slice that resumes its pass on the same tip does not take the pass's
/// witness as it stood once no witness stands in the process any more (ten
/// seconds): with every witness failing by then, it witnesses again, waits
/// out its patience, signs no cancellation of a stopped plan and asks the
/// operator nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_resumed_slice_rewitnesses_before_signing() {
	let mut r = Running::start().await;
	let x = r.x;
	let url = r.url();
	let p = Proxy::start(&url);
	let m = Arca::new("SL13 M");
	boarded(&mut r, &m, &p.url, &[(x, 1_000_000)]).await;
	let fakes = Fakes::put(&m.dir);
	let mut w = Wallet::open(&m.dir).expect("open the wallet");
	// A patience of three seconds, as the tests' command line runs with.
	w.witness_patience = Duration::from_secs(3);
	let slice = |w: &mut Wallet| -> Value {
		tokio::task::block_in_place(|| command::run(w, "sync", &json!({"budget_ms": 0}))).map(|v| v["result"].clone()).unwrap()
	};
	let first = slice(&mut w);
	assert_eq!(first["next"], "held", "{}", first);
	let witnessed = p.count("/v1/witness");
	let cancelled = p.count("/v1/cancel_plan");
	std::thread::sleep(Duration::from_secs(11));
	p.lose("/v1/witness", true);
	p.rewrite(Some(Arc::new(|path, _, _, v| {
		if path == "/v1/plan_status" {
			*v = json!({"state": "stopped", "steps": []});
			return Some(200);
		}
		None
	})));
	for _ in 0..20 {
		let v = slice(&mut w);
		if v["cost_by_step"]["plans"].is_object() {
			break;
		}
	}
	println!("SL13 witness calls {} -> {}; cancel_plan signatures {} -> {}", witnessed, p.count("/v1/witness"),
		cancelled, p.count("/v1/cancel_plan"));
	assert!(p.count("/v1/witness") > witnessed, "the expired witness was not taken again");
	assert_eq!(p.count("/v1/cancel_plan"), cancelled, "a slice signed while its current witness failed");
	p.lose("/v1/witness", false);
	p.rewrite(None);
	fakes.take();
	let _ = std::fs::remove_dir_all(&m.dir);
}

/// What the bond leaves uncovered is computed again on a new tip: a pass
/// cut inside `refresh` with a received coin uncovered (the wallet requires
/// a bond and the operator posts none), then a bond that covers it posted
/// and a block more. The slices after give up no coin outside its refresh
/// window for a refresh that pays a fee.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_tip_drops_stale_uncovered_before_a_paid_refresh() {
	let mut r = Running::start_with(|c, _, _| c.fees.refresh_ppm = 5_000).await;
	let x = r.x;
	let url = r.url();
	let p = Proxy::start(&url);
	let (m, b) = (Arca::new("SL15 M"), Arca::new("SL15 B"));
	boarded(&mut r, &m, &p.url, &[(x, 3_000_000)]).await;
	boarded(&mut r, &b, &url, &[(x, 3_000_000)]).await;
	pay(&b, &m, x, 100_000);
	p.rewrite(Some(Arc::new(|path, _, _, v| {
		if path == "/v1/holding_back" {
			*v = json!({"leaves": []});
			return Some(200);
		}
		None
	})));
	{
		let db = rusqlite::Connection::open(m.dir.join("arca.sqlite")).unwrap();
		db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('bond_seen', '{\"why\":\"required\"}')", []).unwrap();
	}
	let mut w = Wallet::open(&m.dir).expect("open the wallet");
	let slice = |w: &mut Wallet| -> Value {
		tokio::task::block_in_place(|| command::run(w, "sync", &json!({"budget_ms": 0}))).map(|v| v["result"].clone()).unwrap()
	};
	for _ in 0..40 {
		let v = slice(&mut w);
		if v["next"] == "refresh" && v["cost_by_step"]["refresh"].is_object() {
			println!("SL15 cut inside refresh: {}", v);
			break;
		}
	}
	{
		let db = rusqlite::Connection::open(m.dir.join("arca.sqlite")).unwrap();
		let kept: String = db.query_row("SELECT value FROM meta WHERE key = 'sync_resume'", [], |r| r.get(0)).unwrap();
		println!("SL15 resume at the cut: {}", kept);
	}
	let before = p.count("/v1/submit_participation");
	assert_eq!(before, 0, "the refresh step stopped before its coin");
	let withdraw = common::running::keypair("bond W");
	let operator = common::running::keypair("operator");
	let chain = arca_covenant::Chain::new(r.rt.client().genesis_hash().unwrap());
	let units = server::bond::min_notice_seconds(server::bond::LIFETIME, arca_covenant::RelativeTime::from_units(338).unwrap())
		.div_ceil(512) as u16;
	let policy = arca_covenant::bond::BondPolicy::new(chain, operator.x_only_public_key().0, withdraw.x_only_public_key().0,
		arca_covenant::RelativeTime::from_units(units).unwrap()).unwrap();
	let tx = r.pay_to(policy.script_pubkey(), x, 5_000_000);
	r.produce().await;
	r.bury().await;
	let vout = tx.output.iter().position(|o| o.script_pubkey == policy.script_pubkey()).unwrap() as u32;
	r.config.bond = Some(server::bond::BondSection { withdraw_key: withdraw.x_only_public_key().0.to_string(), notice_units: units,
		outpoint: Some(format!("{}:{}", tx.txid(), vout)), notice: None, instant_budget_fraction: None, instant_limit_value: None });
	r.restart_server().await;
	r.synced().await;
	assert_eq!(library(&m, "bond", json!({})).unwrap()["covers"], true, "the new bond covers the transfer");
	let mut last = slice(&mut w);
	println!("SL15 new-tip resume: {}", last);
	while last["more"] == true {
		last = slice(&mut w);
	}
	let after = p.count("/v1/submit_participation");
	println!("SL15 final answer: {}; paid refresh submissions {} -> {}; last request {:?}", last, before, after,
		p.last("/v1/submit_participation").map(|(q, _, _)| q));
	if after > before {
		let (q, _, _) = p.last("/v1/submit_participation").unwrap();
		assert_eq!(q["fees"][0]["amount"], "500", "the stale answer selected the ordinary paid quote");
	}
	assert_eq!(after, before, "a coin now covered and outside its refresh window was given up");
	p.rewrite(None);
	for w in [&m, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A witness that fails while a pass runs ends the pass's work with the
/// operator. A stopped plan's status takes longer here than a witness stands
/// (ten seconds), and from then every witness of the operator's signer's
/// record fails: the wallet witnesses again before it signs the plan's
/// cancellation, signs nothing, asks the operator nothing more (no second
/// plan, no payment received over Lightning asked after again), runs the
/// rest of its pass in the same call and says the operator could not be
/// witnessed. In one call, and in slices on a wallet kept open, where the
/// slice that meets it had taken the pass's witness as it stood.
#[tokio::test(flavor = "multi_thread")]
async fn a_witness_that_fails_inside_a_pass_ends_its_work_with_the_operator() {
	let mut r = Running::start().await;
	let x = r.x;
	let url = r.url();
	let p = Proxy::start(&url);
	let m = Arca::new("SL14 M");
	boarded(&mut r, &m, &p.url, &[(x, 1_000_000)]).await;
	let fakes = Fakes::put(&m.dir);
	// A payment the wallet waits to receive over Lightning: its status is
	// asked in `receives`, before the plans, and in `receives again`, after.
	{
		let db = rusqlite::Connection::open(m.dir.join("arca.sqlite")).unwrap();
		let gets = json!({"b1".repeat(32): {"state": "done"}, "b2".repeat(32): {"state": "done"}, "b3".repeat(32): {"state": "waiting"}});
		db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('lightning_receives', ?1)", [&gets.to_string()]).unwrap();
	}
	for budget in [None, Some(0u64)] {
		p.lose("/v1/witness", false);
		let (q, once) = (p.clone(), Arc::new(AtomicBool::new(false)));
		p.rewrite(Some(Arc::new(move |path, _, _, v| {
			if path != "/v1/plan_status" {
				return None;
			}
			if !once.swap(true, Ordering::SeqCst) {
				q.lose("/v1/witness", true);
				std::thread::sleep(Duration::from_secs(11));
			}
			*v = json!({"state": "stopped", "steps": []});
			Some(200)
		})));
		let before = p.calls().len();
		let mut w = Wallet::open(&m.dir).expect("open the wallet");
		let mut slices = 0;
		let last = loop {
			let mut a = json!({});
			if let Some(b) = budget {
				a["budget_ms"] = json!(b);
			}
			let v = tokio::task::block_in_place(|| command::run(&mut w, "sync", &a)).map(|v| v["result"].clone()).expect("sync answers");
			slices += 1;
			assert!(slices < 200, "the pass ends");
			if v["more"] != json!(true) {
				break v;
			}
		};
		let calls: Vec<(String, u16)> = p.calls()[before..].iter().map(|(path, _, status, _)| (path.clone(), *status)).collect();
		let count = |path: &str| calls.iter().filter(|(c, _)| c == path).count();
		let failed = calls.iter().position(|(c, s)| c == "/v1/witness" && *s == 502);
		println!("SL14 budget {:?}: {} call(s) of sync; witnesses {}, plan statuses {}, cancellations signed {}, receive statuses {}; \
			the calls after the witness failed: {:?}; unreachable {}", budget, slices, count("/v1/witness"), count("/v1/plan_status"),
			count("/v1/cancel_plan"), count("/v1/lightning_receive_status"), failed.map(|k| &calls[k + 1..]), last["unreachable"]);
		assert_eq!(count("/v1/plan_status"), 1, "the first plan's status was read, and no other after the witness failed: {:?}", calls);
		assert_eq!(count("/v1/cancel_plan"), 0, "a cancellation was signed while the witness failed");
		let failed = failed.expect("the wallet witnessed again before it signed");
		assert!(calls[failed + 1..].is_empty(), "the operator was asked after the witness failed: {:?}", &calls[failed + 1..]);
		assert_eq!(count("/v1/lightning_receive_status"), 1, "asked in `receives`, and not again after the witness failed");
		assert!(last["unreachable"]["why"].is_string(), "the pass says the operator could not be witnessed: {}", last);
		assert!(last["cost_by_step"]["home"].is_object() && last["schedule"].is_object(), "the rest of the pass ran: {}", last);
	}
	p.lose("/v1/witness", false);
	p.rewrite(None);
	fakes.take();
	let _ = std::fs::remove_dir_all(&m.dir);
}
