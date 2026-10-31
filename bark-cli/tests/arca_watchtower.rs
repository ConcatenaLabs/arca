//! Watchtowers take an absent holder's coin on the chain before its batch can
//! be swept, with the `arca` binary against a whole Arca server on an
//! anchored proof-of-stake regtest chain, the operator's own unroll at
//! release turned off so only the watchtowers act.
//!
//! A, B, D and E board X and refresh it into leaves of one batch. Two
//! watchtowers run, each an `arca watchtower serve` of its own: A and B
//! deposit with T, D with T and T2, E with T. Ten days on, D and E refresh
//! their leaves into a new round, D while T2 is down, so T2 misses D's
//! withdrawal and keeps a deposit for a coin D gave up. A, B and D go away. The batch expires and is
//! released, and the operator stops. The watchtowers act alone: T brings A's
//! and B's coins on the chain, each under its owner's key, sharing the nodes
//! above them, paid from the path's reserves; T2 brings D's old coin on the
//! chain. The operator returns: it answers D's old coin with the forfeit D
//! signed, and after the notice its sweep takes E's old entry, given up and
//! left on the chain by the unroll above it, and nothing of A's or B's; it
//! owes nothing. D's new coin is untouched. A comes back: its wallet finds
//! the coin on the chain, says so in plain words, takes it home and boards
//! it back.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use elements::Script;
use serde_json::Value;

use common::cli::Arca;
use common::running::Running;
use server::store::RoundState;

const HOUR: u32 = 3_600;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

fn create_args<'a>(server: &'a str, node: &'a str) -> Vec<&'a str> {
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

/// A watchtower's `serve` process, stopped when dropped.
struct Tower {
	wallet: Arca,
	url: String,
	listen: String,
	child: Option<Child>,
}

impl Tower {
	fn new(name: &str, server: &str, node: &str) -> Tower {
		let wallet = Arca::new(name);
		wallet.ok(&create_args(server, node));
		let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
		let listen = format!("127.0.0.1:{}", port);
		let mut t = Tower { wallet, url: format!("http://{}", listen), listen, child: None };
		t.start();
		t
	}

	fn start(&mut self) {
		let log = std::fs::File::create(self.wallet.dir.join("serve.log")).unwrap();
		let child = Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&self.wallet.dir)
			.args(["watchtower", "serve", "--listen", &self.listen, "--interval", "1"])
			.env("ARCA_NODE_PASSWORD", "arca").stdout(Stdio::null()).stderr(log).spawn().unwrap();
		self.child = Some(child);
		let start = Instant::now();
		while std::net::TcpStream::connect(&self.listen).is_err() {
			assert!(start.elapsed() < Duration::from_secs(30), "watchtower {} did not start", self.wallet.name);
			std::thread::sleep(Duration::from_millis(100));
		}
	}

	fn stop(&mut self) {
		if let Some(mut c) = self.child.take() {
			let _ = c.kill();
			let _ = c.wait();
		}
	}

	fn deposits(&self) -> Vec<Value> {
		self.wallet.ok(&["watchtower", "deposits"]).as_array().unwrap().clone()
	}

	fn deposit_of(&self, leaf: &str) -> Option<Value> {
		self.deposits().into_iter().find(|d| d["leaf_id"] == leaf)
	}
}

impl Drop for Tower {
	fn drop(&mut self) {
		self.stop();
	}
}

/// Lets the watcher pass, then a block, buried, and the nursery follow.
async fn settle(r: &Running) {
	r.server.watcher.pass().await.unwrap();
	tokio::time::sleep(Duration::from_millis(300)).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.server.nursery.pass().await.unwrap();
	r.server.watcher.pass().await.unwrap();
	tokio::time::sleep(Duration::from_millis(300)).await;
}

/// What the operator's watcher published of `kind`: each one's detail.
async fn of_kind(r: &Running, kind: &str) -> Vec<String> {
	r.server.store.watcher_log().await.unwrap().into_iter().filter(|w| w.kind == kind).map(|w| w.detail).collect()
}

/// Boards `amount` of X for `w` and waits until the server credits it.
async fn board(r: &mut Running, w: &Arca, amount: &str) -> String {
	let x = r.x.to_string();
	r.pay_to(script(&w.ok(&["address"])), r.x, 5_000_000);
	r.produce().await;
	w.ok(&["board", &x, amount]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || w.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	w.ok(&["coins"])[0]["leaf_id"].as_str().unwrap().to_string()
}

/// The leaf `w`'s sync took from its participation.
fn new_leaf(s: &Value) -> (String, u64, u32) {
	let leaf = s["participations"][0]["new_leaves"][0].clone();
	(leaf["leaf_id"].as_str().expect("the refresh's leaf").to_string(), leaf["value"].as_str().unwrap().parse().unwrap(),
		leaf["expiry"].as_u64().unwrap() as u32)
}

#[tokio::test(flavor = "multi_thread")]
async fn watchtowers_take_absent_holders_coins_on_chain_before_the_sweep() {
	// The operator's watcher acts only when the test passes it, so the test
	// stops the operator the moment its release is out.
	let mut r = Running::start_with(|c, _, _| {
		c.watcher.unroll_at_release = false;
		c.watcher.enabled = false;
	}).await;
	let (url, node) = (r.url(), r.node_url());
	let x = r.x.to_string();

	// A, B and D board X and refresh into leaves of one batch.
	let a = Arca::new("wt A");
	let b = Arca::new("wt B");
	let d = Arca::new("wt D");
	let e = Arca::new("wt E");
	for w in [&a, &b, &d, &e] {
		w.ok(&create_args(&url, &node));
	}
	let mut boards = vec![];
	for w in [&a, &b, &d, &e] {
		boards.push(board(&mut r, w, "2000000").await);
	}
	for (w, l) in [&a, &b, &d, &e].iter().zip(&boards) {
		w.ok(&["participate", "--leaf", l, "--max-fee-ppm", "1000000"]);
	}
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	let (la, va, expiry) = new_leaf(&a.ok(&["sync"]));
	let (lb, vb, _) = new_leaf(&b.ok(&["sync"]));
	let (ld, _, _) = new_leaf(&d.ok(&["sync"]));
	let (le, _, _) = new_leaf(&e.ok(&["sync"]));
	println!("one batch: A {} = {}, B {} = {}, D {}; first expiry {}", la, va, lb, vb, ld, expiry);

	// The watchtowers, and the deposits.
	let t = Tower::new("wt T", &url, &node);
	let mut t2 = Tower::new("wt T2", &url, &node);
	println!("watchtower info: {}", minreq::get(format!("{}/v1/info", t.url)).send().unwrap().as_str().unwrap());
	a.ok(&["watchtowers", &t.url]);
	b.ok(&["watchtowers", &t.url]);
	d.ok(&["watchtowers", &t.url, &t2.url]);
	e.ok(&["watchtowers", &t.url]);
	for w in [&a, &b, &d, &e] {
		let s = w.ok(&["sync"]);
		println!("{}'s sync deposits: {}", w.name, s["deposits"]);
	}
	for l in [&la, &lb, &ld, &le] {
		assert_eq!(t.deposit_of(l).expect("T holds the deposit")["state"], "held");
	}
	assert_eq!(t2.deposit_of(&ld).expect("T2 holds D's deposit")["state"], "held");
	// A second sync deposits nothing again.
	assert!(a.ok(&["sync"]).get("deposits").is_none(), "nothing deposited twice");

	// Ten days on, D and E refresh their leaves, D while T2 is down: T2
	// misses D's withdrawal. A and B are away from now on.
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 10 * 24 * HOUR));
	settle(&r).await;
	t2.stop();
	d.ok(&["participate", "--leaf", &ld, "--max-fee-ppm", "1000000"]);
	e.ok(&["participate", "--leaf", &le, "--max-fee-ppm", "1000000"]);
	let built2 = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built2.tx.txid(), RoundState::Final).await;
	let s = d.ok(&["sync"]);
	let (ld2, vd2, _) = new_leaf(&s);
	let s = d.ok(&["sync"]);
	println!("D refreshed {} into {} = {}; its sync's deposits: {}", ld, ld2, vd2, s["deposits"]);
	e.ok(&["sync"]);
	let s = e.ok(&["sync"]);
	println!("E refreshed {}; its sync's deposits: {}", le, s["deposits"]);
	assert!(t.deposit_of(&le).is_none(), "E withdrew its old coin's deposit");
	assert!(t.deposit_of(&ld).is_none(), "D withdrew its old coin's deposit from T");
	assert!(t.deposit_of(&ld2).is_some(), "and deposited its new coin with T");
	t2.start();
	assert_eq!(t2.deposit_of(&ld).expect("T2 still holds D's old coin")["state"], "held");

	// Before the release, the watchtowers do nothing.
	tokio::time::sleep(Duration::from_secs(3)).await;
	for l in [&la, &lb] {
		assert_eq!(t.deposit_of(l).unwrap()["state"], "held", "nothing before the release");
	}

	// A, B and D are away. The batch expires and is released.
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, expiry.saturating_sub(now) + HOUR));
	// The operator stops the moment its release is out: the watchtowers act
	// alone, the release mined by the chain's stakers.
	let mut released = false;
	for _ in 0..8 {
		r.server.watcher.pass().await.unwrap();
		if !of_kind(&r, "release").await.is_empty() {
			released = true;
			break;
		}
		r.produce().await;
		r.bury().await;
		r.synced().await;
		r.server.nursery.pass().await.unwrap();
	}
	assert!(released, "the operator released the batch");
	r.server.stop();
	println!("the operator released the batch and stopped");
	let start = Instant::now();
	loop {
		r.produce().await;
		tokio::time::sleep(Duration::from_secs(2)).await;
		let states: Vec<String> = [&la, &lb].iter().map(|l| t.deposit_of(l).unwrap()["state"].as_str().unwrap().to_string()).collect();
		let d_old = t2.deposit_of(&ld).unwrap()["state"].as_str().unwrap().to_string();
		if states.iter().all(|s| s == "on_chain") && d_old == "on_chain" {
			break;
		}
		if start.elapsed() > Duration::from_secs(60) {
			let log: Vec<(String, String)> = r.server.store.watcher_log().await.unwrap().into_iter().map(|w| (w.kind, w.detail)).collect();
			println!("DIAG watcher log: {:?}", log);
			let tip: u64 = r.rt.client().call::<Value>("getblockcount", &[]).unwrap().as_u64().unwrap();
			for h in tip.saturating_sub(15)..=tip {
				let hash: Value = r.rt.client().call("getblockhash", &[serde_json::json!(h)]).unwrap();
				let b: Value = r.rt.client().call("getblock", &[hash, serde_json::json!(2)]).unwrap();
				for tx in b["tx"].as_array().unwrap() {
					println!("DIAG block {} tx {} vin {:?} vout {}", h, tx["txid"], tx["vin"].as_array().unwrap().iter()
						.map(|i| format!("{}:{}", i["txid"].as_str().unwrap_or("cb"), i["vout"])).collect::<Vec<_>>(), tx["vout"].as_array().unwrap().len());
				}
			}
			panic!("the watchtowers did not bring the coins on the chain: {:?} {}", states, d_old);
		}
	}
	// What it cost, per coin brought.
	let mut vsize = 0u64;
	let mut fees = 0u64;
	let mut txs = 0;
	for l in [&la, &lb] {
		let dep = t.deposit_of(l).unwrap();
		println!("T, {}'s coin: {} | {}", l, dep["note"], dep["broadcast"]);
		for s in dep["broadcast"].as_array().unwrap() {
			assert_eq!(s["paid_by"], "its own reserve");
			vsize += s["vsize"].as_u64().unwrap();
			fees += s["fee"].as_array().unwrap().iter().map(|f| f["amount"].as_str().unwrap().parse::<u64>().unwrap()).sum::<u64>();
			txs += 1;
		}
	}
	println!("T brought 2 coins in {} transactions: {} vB and {} atoms of X in fees, {} vB and {} atoms a coin", txs, vsize, fees,
		vsize / 2, fees / 2);
	let dep = t2.deposit_of(&ld).unwrap();
	println!("T2, D's old coin: {} | {}", dep["note"], dep["broadcast"]);

	// The operator returns: D's old coin is answered by its forfeit; after
	// the notice the sweep takes nothing of A's or B's.
	r.restart_server().await;
	r.synced().await;
	for _ in 0..4 {
		settle(&r).await;
	}
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 37 * HOUR));
	for _ in 0..8 {
		settle(&r).await;
	}
	let sweeps = of_kind(&r, "sweep").await;
	println!("sweeps: {:?}", sweeps);
	for l in [&la, &lb, &ld] {
		let id = l.parse::<arca_covenant::LeafId>().unwrap().0;
		assert!(r.server.store.owed_entry(&id).await.unwrap().is_none(), "nothing owed for {}: the sweep took nothing of it", l);
	}
	let forfeits = of_kind(&r, "forfeit").await;
	println!("forfeits the operator published: {:?}", forfeits);
	assert!(!forfeits.is_empty(), "D's old coin, on the chain, was answered by its forfeit");
	let d_coins = d.ok(&["coins"]);
	assert!(d_coins.as_array().unwrap().iter().any(|c| c["leaf_id"] == ld2.as_str() && c["state"] == "live" && c["value"] == vd2.to_string()),
		"D's new coin is untouched: {}", d_coins);
	println!("D's balance: {}", d.ok(&["balance"])["arca"][&x]);
	// What the sweep took: E's old entry, given up, which nobody unrolled.
	assert_eq!(sweeps.len(), 1, "one sweep: {:?}", sweeps);

	// A comes back: its coin is on the chain, kept safe; the wallet takes
	// it home and, its claim final, boards it back.
	let s = a.ok(&["sync"]);
	println!("A's sync on return: exits {} | recheck changes {}", s["exits"], s["recheck"]["changes"]);
	let coin = a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == la.as_str()).cloned().unwrap();
	println!("A's coin: state {} kept_safe {} note {:?} | {}", coin["state"], coin["kept_safe"], coin["kept_safe_note"], coin["note"]);
	assert_eq!(coin["kept_safe"], true, "{}", coin);
	assert_eq!(coin["kept_safe_note"], "moved out of the Ark to keep it safe while you were away");
	let bal = a.ok(&["balance"]);
	println!("A's balance on return: arca {} | on the chain {}", bal["arca"][&x], bal["sequentia_onchain"][&x]);
	assert_eq!(bal["arca"][&x]["kept_safe"], va.to_string());
	let mut reboard = Value::Null;
	for _ in 0..6 {
		r.produce().await;
		r.bury().await;
		r.synced().await;
		let s = a.ok(&["sync"]);
		if !s["reboards"].is_null() {
			reboard = s["reboards"].clone();
			break;
		}
	}
	println!("A's reboard: {}", reboard);
	assert!(reboard[0]["boarded"].is_object(), "A boarded its coin back: {}", reboard);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("A's board back to be credited", || a.ok(&["boards"]).as_array().unwrap().iter().any(|b| b["server"]["state"] == "credited"
		&& b["leaf_id"] == reboard[0]["boarded"]["leaf_id"])).await;
	let coins = a.ok(&["coins"]);
	let back: Vec<&Value> = coins.as_array().unwrap().iter().filter(|c| c["kind"] == "board" && c["state"] == "live").collect();
	println!("A's coins after the board back: {}", coins);
	assert!(back.iter().any(|c| c["leaf_id"] == reboard[0]["boarded"]["leaf_id"]), "the board back is a live coin");
	let coin = coins.as_array().unwrap().iter().find(|c| c["leaf_id"] == la.as_str()).unwrap();
	assert_eq!((coin["state"].as_str(), coin["reboarded"].as_bool()), (Some("exited"), Some(true)));
	println!("A's balance after the board back: arca {}", a.ok(&["balance"])["arca"][&x]);
}

/// With no watchtower named, the operator brings every live coin of a
/// released batch on the chain under its holder's key before the sweep
/// (`unroll_at_release`, on by default): the sweep owes nothing, and the
/// holder's wallet finds its coin kept safe on its return.
#[tokio::test(flavor = "multi_thread")]
async fn the_operator_brings_live_coins_on_chain_at_release() {
	let mut r = Running::start().await;
	let (url, node) = (r.url(), r.node_url());
	let x = r.x.to_string();
	let a = Arca::new("wt op A");
	a.ok(&create_args(&url, &node));
	a.ok(&["watchtowers", "--none"]);
	let l = board(&mut r, &a, "2000000").await;
	a.ok(&["participate", "--leaf", &l, "--max-fee-ppm", "1000000"]);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	let (la, va, expiry) = new_leaf(&a.ok(&["sync"]));

	// A is away: the batch expires and is released; the operator brings A's
	// coin on the chain, then, after the notice, finds nothing to sweep.
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, expiry.saturating_sub(now) + HOUR));
	for _ in 0..8 {
		settle(&r).await;
	}
	let unrolls: Vec<String> = [of_kind(&r, "unroll").await, of_kind(&r, "entry").await].concat();
	println!("the operator's unrolls at release: {:?}", unrolls);
	assert!(unrolls.iter().any(|d| d.contains(&la[..16]) || d.contains(&la)), "A's coin brought on the chain by the operator");
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 37 * HOUR));
	for _ in 0..6 {
		settle(&r).await;
	}
	println!("sweeps: {:?}", of_kind(&r, "sweep").await);
	let id = la.parse::<arca_covenant::LeafId>().unwrap().0;
	assert!(r.server.store.owed_entry(&id).await.unwrap().is_none(), "nothing owed: the sweep took nothing of A's");

	// A returns and finds its coin kept safe.
	a.ok(&["sync"]);
	let coin = a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == la.as_str()).cloned().unwrap();
	println!("A's coin on return: {} {} | {}", coin["state"], coin["kept_safe_note"], coin["note"]);
	assert_eq!(coin["kept_safe"], true);
	assert_eq!(a.ok(&["balance"])["arca"][&x]["kept_safe"], va.to_string());
}
