//! A wallet's mailbox read costs a few requests to the operator however
//! many receive requests wait unpaid, and still finds every payment to any
//! of them: the mailboxes of its keys are read together (`mailbox_reads`),
//! under one challenge, and an operator without that call is read key by key
//! as before. A payment whose round an anchor reorganisation takes out of the
//! chain reads as not received until the round is back.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::sync::Arc;
use std::time::Instant;

use elements::{AssetId, Script, Transaction};
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

fn create_args<'a>(server: &'a str, node: &'a str) -> Vec<&'a str> {
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

fn coin_of(w: &Arca, leaf: &str) -> Value {
	w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).cloned().unwrap_or(Value::Null)
}

/// Creates `w` on `server` and boards each of `amounts` of `asset` as a coin
/// of its own; waits until every board is final and credited.
async fn boarded(r: &mut Running, w: &Arca, server: &str, asset: AssetId, amounts: &[u64]) -> Vec<String> {
	w.ok(&create_args(server, &r.node_url()));
	for v in amounts {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, asset, v + 3_000_000);
	}
	r.produce().await;
	let mut boards = vec![];
	for v in amounts {
		boards.push(w.ok(&["board", &asset.to_string(), &v.to_string()])["leaf_id"].as_str().unwrap().to_string());
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards to be credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
	boards
}

/// `n` receive requests of the wallet in `a`, drawn by the library as a
/// program does, oldest first. The wallet has read its mailbox once before
/// (its first read sets up the one re-read of what earlier versions could
/// not read, [`bark::arca::Wallet::mailbox`]), as a wallet in use has.
fn requests(a: &Arca, n: usize) -> Vec<String> {
	a.ok(&["mailbox"]);
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		(0..n).map(|_| command::run(&mut w, "receive", &json!({})).unwrap()["result"]["request"].as_str().unwrap().to_string()).collect()
	})
}

/// The calls a mailbox read makes of the operator through `p`, by path, and
/// those that read mailboxes (`challenge`, `mailbox_read`, `mailbox_reads`).
fn calls_since(p: &Proxy, from: usize) -> (Vec<String>, usize) {
	let paths: Vec<String> = p.calls()[from..].iter().map(|(path, ..)| path.clone()).collect();
	let reads = paths.iter().filter(|p| matches!(p.as_str(), "/v1/challenge" | "/v1/mailbox_read" | "/v1/mailbox_reads")).count();
	(paths, reads)
}

/// The wallet's mailbox read through `p`: what it took, the calls it made
/// of the operator that read mailboxes, every call, and how long it took.
fn read(a: &Arca, p: &Proxy) -> (Value, usize, usize, std::time::Duration) {
	let from = p.calls().len();
	let t = Instant::now();
	let v = a.ok(&["mailbox"]);
	let took = t.elapsed();
	let (paths, reads) = calls_since(p, from);
	println!("{} mailbox: {:?}", a.name, paths);
	(v, reads, paths.len(), took)
}

/// A small seeded generator (xorshift64*): the same seed draws the same
/// payments, so a failing seed can be run again (`MAILBOX_SEED`).
struct Draw(u64);

impl Draw {
	fn next(&mut self) -> u64 {
		self.0 ^= self.0 >> 12;
		self.0 ^= self.0 << 25;
		self.0 ^= self.0 >> 27;
		self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
	}

	/// A number in `lo..hi`.
	fn range(&mut self, lo: usize, hi: usize) -> usize {
		lo + (self.next() % (hi - lo) as u64) as usize
	}

	fn coin(&mut self) -> bool {
		self.next() & 1 == 1
	}
}

fn accepted_values(v: &Value) -> Vec<u64> {
	v["accepted"].as_array().map(|a| a.iter().map(|c| c["value"].as_str().unwrap().parse().unwrap()).collect()).unwrap_or_default()
}

/// Any set of a wallet's receive requests, paid in any order, with the
/// wallet reading its mailbox between payments or not: every payment is
/// found, to the atom, whichever request it paid, the oldest and the newest
/// among them; and each read costs a few requests to the operator, not one
/// for each request waiting.
#[tokio::test(flavor = "multi_thread")]
async fn every_payment_to_any_waiting_request_is_found() {
	let mut r = Running::start().await;
	let (url, x) = (r.url(), r.x);
	let proxy = Proxy::start(&url);
	let (b, m) = (Arca::new("MBP"), Arca::new("MBM"));
	boarded(&mut r, &b, &url, x, &[6_000_000, 6_000_000, 6_000_000, 6_000_000]).await;
	m.ok(&create_args(&proxy.url, &r.node_url()));
	let reqs = requests(&m, 120);
	let seed: u64 = std::env::var("MAILBOX_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(691);
	let mut rng = Draw(seed.max(1));
	// Which requests are paid: the oldest, the newest and ten others, in a
	// random order; each payment of a value of its own, which names the
	// request it paid.
	let mut paid: Vec<usize> = vec![0, reqs.len() - 1];
	while paid.len() < 12 {
		let i = rng.range(1, reqs.len() - 1);
		if !paid.contains(&i) {
			paid.push(i);
		}
	}
	for i in (1..paid.len()).rev() {
		paid.swap(i, rng.range(0, i + 1));
	}
	println!("seed {}: paying requests {:?} of {}", seed, paid, reqs.len());
	let value = |i: usize| 1_000_000 + 1_000 * i as u64;
	let mut found: Vec<u64> = vec![];
	let mut most = 0;
	for (n, &i) in paid.iter().enumerate() {
		b.ok(&["send", &reqs[i], "--amount", &value(i).to_string(), "--asset", &x.to_string()]);
		b.ok(&["mailbox"]);
		if rng.coin() || n + 1 == paid.len() {
			let (v, reads, all, took) = read(&m, &proxy);
			println!("read after payment {} (request {}): took {:?} in {:?}, {} mailbox calls of {}", n, i, accepted_values(&v), took, reads,
				all);
			found.extend(accepted_values(&v));
			most = most.max(reads);
		}
	}
	let (v, reads, _, _) = read(&m, &proxy);
	assert!(accepted_values(&v).is_empty(), "nothing more: {}", v);
	most = most.max(reads);
	found.sort();
	let mut want: Vec<u64> = paid.iter().map(|&i| value(i)).collect();
	want.sort();
	assert_eq!(found, want, "every payment found, each once");
	let total: u64 = want.iter().sum();
	assert_eq!(m.ok(&["balance"])["arca"][x.to_string()]["operator-confirmed"], total.to_string());
	// 109 keys waiting and the mailbox key: one challenge, one batch, and a
	// second for the keys that held something.
	assert!(most <= 3, "a read of {} keys made {} mailbox calls", reqs.len() + 1, most);
	println!("{} requests, {} paid: all found; at most {} mailbox calls a read", reqs.len(), paid.len(), most);
	let _ = (std::fs::remove_dir_all(&b.dir), std::fs::remove_dir_all(&m.dir));
}

/// A wallet with 1,000 receive requests waiting reads its mailbox in a few
/// requests and finds a payment to the oldest; through an operator that
/// does not publish `mailbox_reads` (an older one), the same wallet reads
/// every key alone, as it always did, and still finds every payment.
#[tokio::test(flavor = "multi_thread")]
async fn a_thousand_waiting_requests_are_read_in_a_few_calls() {
	let mut r = Running::start().await;
	let (url, x) = (r.url(), r.x);
	let proxy = Proxy::start(&url);
	let (b, m) = (Arca::new("MBSP"), Arca::new("MBSM"));
	boarded(&mut r, &b, &url, x, &[6_000_000]).await;
	m.ok(&create_args(&proxy.url, &r.node_url()));
	let t = Instant::now();
	let reqs = requests(&m, 1_000);
	println!("1,000 requests drawn in {:?}", t.elapsed());
	let (v, reads, all, took) = read(&m, &proxy);
	println!("an empty read of 1,001 keys: {:?}, {} mailbox calls of {} ({:?})", took, reads, all, calls_since(&proxy, proxy.calls().len() - all).0);
	assert!(accepted_values(&v).is_empty());
	// 1,001 keys: one challenge and six batches of at most 200.
	assert!(reads <= 7, "{} mailbox calls", reads);
	b.ok(&["send", &reqs[0], "--amount", "1500000", "--asset", &x.to_string()]);
	let (v, reads, all, took) = read(&m, &proxy);
	println!("a read finding a payment to the oldest of 1,000: {:?}, {} mailbox calls of {}", took, reads, all);
	assert_eq!(accepted_values(&v), vec![1_500_000], "{}", v);
	assert!(reads <= 8, "{} mailbox calls", reads);

	// An operator without the call: every key read alone.
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, _: u16, v: &mut Value| {
		if path == "/v1/info" {
			v.as_object_mut().unwrap().remove("mailbox_reads");
		}
		None
	})));
	b.ok(&["mailbox"]);
	b.ok(&["send", &reqs[1], "--amount", "1600000", "--asset", &x.to_string()]);
	// The wallet keeps the operator's `info` a few seconds.
	std::thread::sleep(std::time::Duration::from_secs(6));
	let (v, reads, all, took) = read(&m, &proxy);
	println!("the same read of an operator without mailbox_reads: {:?}, {} mailbox calls of {}", took, reads, all);
	assert_eq!(accepted_values(&v), vec![1_600_000], "{}", v);
	assert!(reads >= 2 * 1_000, "key by key: {} mailbox calls", reads);
	assert!(!calls_since(&proxy, proxy.calls().len() - all).0.iter().any(|p| p == "/v1/mailbox_reads"), "no batch asked of it");
	let _ = (std::fs::remove_dir_all(&b.dir), std::fs::remove_dir_all(&m.dir));
}

/// A parent block of its own, and the Sequentia tip anchored to it: what is
/// mined next is anchored there, so orphaning it takes that out. Returns its
/// height.
async fn own_anchor(r: &Running) -> u64 {
	tokio::task::block_in_place(|| {
		r.rt.mine_parent(1).unwrap();
		r.rt.anchor_to_parent_tip().unwrap();
	});
	r.rt.parent.client().block_count().unwrap()
}

/// Runs a round, mines it and waits until the server finds it final.
async fn final_round(r: &Running) -> Transaction {
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	built.tx
}

fn confirmed(m: &Arca, x: AssetId) -> String {
	m.ok(&["balance"])["arca"][x.to_string()]["operator-confirmed"].as_str().unwrap_or("0").to_string()
}

/// Bitcoin anchoring is supreme: a payment to the oldest of a wallet's
/// waiting requests, out of a leaf of round R, is read in one batch while R
/// is out of the chain (its parent block orphaned), and is not taken as
/// received; once R is back it is; and once R's parent block is orphaned
/// again the coin reads as not received again.
#[tokio::test(flavor = "multi_thread")]
async fn a_payment_an_anchor_reorg_undoes_reads_as_undone() {
	let mut r = Running::start().await;
	let (url, x) = (r.url(), r.x);
	let proxy = Proxy::start(&url);
	let (b, m) = (Arca::new("MBRB"), Arca::new("MBRM"));
	let boards = boarded(&mut r, &b, &url, x, &[2_000_000]).await;
	m.ok(&create_args(&proxy.url, &r.node_url()));
	let reqs = requests(&m, 50);
	b.ok(&["participate", "--leaf", &boards[0]]);
	let p_r = own_anchor(&r).await;
	let rtx = final_round(&r).await;
	b.ok(&["sync"]);
	let sent = b.ok(&["send", &reqs[0], "--amount", "1500000", "--asset", &x.to_string()]);
	println!("MBRB pays the oldest of 50 requests 1500000 out of its leaf of R {}: {}", rtx.txid(), sent["inputs"]);

	// R goes out of the chain with its parent block, before the wallet reads.
	tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_r)).unwrap();
	let conf = r.rt.client().call::<Value>("getrawtransaction", &[json!(rtx.txid().to_string()), json!(true)]).ok()
		.and_then(|t| t["confirmations"].as_i64()).unwrap_or(0);
	println!("R out of the chain: confirmations {}", conf);
	assert_eq!(conf, 0, "R is in no block");
	let (v, reads, _, _) = read(&m, &proxy);
	println!("read while R is out ({} mailbox calls): {}", reads, v);
	assert!(reads <= 3, "{}", reads);
	let leaf = v["accepted"][0]["leaf_id"].as_str().or(v["waiting"][0]["leaf_id"].as_str()).map(|s| s.to_string());
	if let Some(l) = &leaf {
		assert_ne!(coin_of(&m, l)["state"], "live", "a coin on a round out of the chain is not live");
	}
	m.ok(&["sync"]);
	assert_eq!(confirmed(&m, x), "0", "nothing counted while R is out");

	// R is back: mined again from the mempool, anchored afresh, buried.
	let p_back = own_anchor(&r).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let v = m.ok(&["mailbox"]);
	println!("read with R back: {}", v);
	m.ok(&["sync"]);
	let coins = m.ok(&["coins"]);
	let got = coins.as_array().unwrap().iter().find(|c| c["value"] == "1500000").expect("the payment's coin").clone();
	println!("the payment with R back: {} {} ({})", got["leaf_id"], got["state"], got["note"]);
	assert_eq!(got["state"], "live");
	assert_eq!(confirmed(&m, x), "1500000");

	// R's new parent block is orphaned in turn: the coin is undone again.
	tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_back)).unwrap();
	m.ok(&["mailbox"]);
	m.ok(&["sync"]);
	let again = coin_of(&m, got["leaf_id"].as_str().unwrap());
	println!("the payment with R out again: {} ({})", again["state"], again["note"]);
	assert_ne!(again["state"], "live");
	assert_eq!(confirmed(&m, x), "0", "nothing counted while R is out");
	let _ = (std::fs::remove_dir_all(&b.dir), std::fs::remove_dir_all(&m.dir));
}
