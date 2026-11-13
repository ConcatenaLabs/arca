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
//! 3. A cut at every safe point (a budget of 1 ms), each followed by a
//!    command of another kind (a payment, a swap offer, a refresh, a
//!    restore's history step, a read): every slice answers, each slice runs
//!    at most one item past its budget, and the wallet's value is whole after.
//! 4. Every slice is a call of its own (the library opened afresh, as a
//!    process that stopped between two slices): the pass goes on from the
//!    store. A pass left for more than ten minutes of median time starts
//!    again, re-check included; so does one asked with other arguments, and a
//!    sync without a budget runs a whole pass and drops the resume point.
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
	let s = script(&w.ok(&["address"]));
	let x = r.x;
	r.pay_to(s, x, 3_000_000);
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
	pay_many(r, m, b, paid).await;
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

/// `b` pays `m` `n` coins of 20,000 X.
async fn pay_many(r: &mut Running, m: &Arca, b: &Arca, n: usize) {
	let x = r.x;
	for k in 0..n {
		// The payer's coin goes through a round every four payments, within
		// the operator's depth limit.
		if k > 0 && k % 4 == 0 {
			b.ok(&["participate"]);
			final_round(r).await;
			b.ok(&["sync"]);
		}
		pay(b, m, x, 20_000);
	}
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
	busy(&mut r, &m, &b, 8, 4).await;
	// Small coins of X for the refreshes between slices; the payments are
	// paid from the board.
	b.ok(&["participate"]);
	final_round(&r).await;
	b.ok(&["sync"]);
	pay_many(&mut r, &m, &b, 10).await;
	let total = |w: &Arca| -> u64 {
		w.ok(&["coins"]).as_array().unwrap().iter()
			.filter(|c| c["asset"] == x.to_string() && !matches!(c["state"].as_str(), Some("spent" | "lost" | "exited")))
			.map(|c| c["value"].as_str().map(|v| v.parse::<u64>().unwrap()).unwrap_or_else(|| c["value"].as_u64().unwrap())).sum()
	};
	let before = total(&m);
	let mut paid = 0u64;
	let kinds = ["pay", "offer", "refresh", "history", "read"];
	let mut ran: std::collections::BTreeMap<&str, (usize, usize)> = std::collections::BTreeMap::new();
	let mdir = m.dir.clone();
	let s = sliced(&m.dir, &json!({}), 1, |k| {
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
			"offer" => lib_at(&mdir, "swap_offer", &json!({"give_asset": y.to_string(), "give": "1000", "want_asset": x.to_string(),
				"want": "1000"})).is_ok(),
			"refresh" => {
				let live: Vec<String> = m.ok(&["coins"]).as_array().unwrap().iter()
					.filter(|c| c["state"] == "live" && c["asset"] == x.to_string() && (c["value"] == "20000" || c["value"] == 20000))
					.map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
				live.first().is_some_and(|l| m.run(&["participate", "--leaf", l]).0)
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
	let longest = s.iter().map(|(_, ms)| *ms).max().unwrap();
	println!("SL3 {} slices of 1 ms, the longest {} ms; commands between them (asked, answered): {:?}", s.len(), longest, ran);
	for (v, _) in &s {
		assert!(v["error"].is_null(), "{}", v);
	}
	assert!(s.len() > 20, "a cut at every step: {} slices", s.len());
	for k in kinds {
		assert!(ran.get(k).is_some_and(|(_, ok)| *ok > 0), "{} ran between two slices: {:?}", k, ran);
	}
	// Every refresh and payment settles: what the wallet holds of X is what
	// it held, less what it paid.
	m.ok(&["sync"]);
	final_round(&r).await;
	m.ok(&["sync"]);
	m.ok(&["sync"]);
	let after = total(&m);
	println!("SL3 X held: {} before, {} after, {} paid with margins", before, after, paid);
	assert_eq!(after + paid, before, "nothing lost or made");
	assert!(m.ok(&["coins"]).as_array().unwrap().iter().all(|c| c["state"] != "given"), "no coin left given: {}", m.ok(&["coins"]));
	for w in [&m, &b] {
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
	// Other arguments: the pass starts again.
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
