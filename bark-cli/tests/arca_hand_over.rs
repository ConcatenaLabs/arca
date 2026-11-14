//! Every signature the wallet hands the operator goes on a witness of the
//! operator's signer's record that is current at that moment (the rule at
//! `Wallet::hand_over`), with the `arca` binary and the library against a
//! whole Arca server on an anchored proof-of-stake regtest chain, the wallet
//! talking to it through a proxy. In each case the operator's answer that
//! comes last before a hand-over is held longer than a witness stands (ten
//! seconds), and from then every witness fails: the wallet must witness
//! again, find it cannot, and hand nothing over.
//!
//! 1. The forfeits of a held round, after the read of its published tree, in
//!    one call of `sync` and in slices.
//! 2. The releases of a participation's old nodes, each posted alone after
//!    the operator refused them as a set.
//! 3. A swept coin's repayment, an attempt after the operator said the one
//!    before was taken.
//! 4. A channel's state sent and never answered, sent again after the read
//!    of the channel.
//! 5. A plan, after its quote.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use elements::{AssetId, Script};
use serde_json::{json, Value};

use bark::arca::{command, Wallet};
use common::cli::Arca;
use common::proxy::{Proxy, Rewrite};
use common::running::Running;
use server::store::RoundState;

const HOUR: u32 = 3_600;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<_>>())
}

async fn boarded(r: &mut Running, w: &Arca, server: &str, asset: AssetId, value: u64) {
	w.ok(&["create", "--server", server, "--node-url", &r.node_url(), "--node-user", "arca", "--exit-delay-units", "1",
		"--min-exit-delay-units", "1"]);
	r.pay_to(script(&w.ok(&["address"])), asset, value + 3_000_000);
	r.pay_to(script(&w.ok(&["address"])), r.x, 3_000_000);
	r.produce().await;
	w.ok(&["board", &asset.to_string(), &value.to_string(), "--fee-asset", &r.x.to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || w.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	w.ok(&["sync"]);
}

/// On the first answer to `path`: every witness fails from then on, the
/// answer comes after eleven seconds (longer than a witness stands), and,
/// with `refusal`, it is that refusal (status, code) instead.
fn held_then_no_witness(p: &Proxy, path: &'static str, refusal: Option<(u16, &'static str)>) -> Rewrite {
	let (q, once) = (p.clone(), Arc::new(AtomicBool::new(false)));
	Arc::new(move |at, _, _, v| {
		if at != path || once.swap(true, Ordering::SeqCst) {
			return None;
		}
		q.lose("/v1/witness", true);
		std::thread::sleep(Duration::from_secs(11));
		refusal.map(|(status, code)| {
			*v = json!({"error": {"code": code, "message": "refused by the test's proxy"}});
			status
		})
	})
}

/// The calls since `before`, by path and status.
fn calls_since(p: &Proxy, before: usize) -> Vec<(String, u16)> {
	p.calls()[before..].iter().map(|(path, _, status, _)| (path.clone(), *status)).collect()
}

fn count(calls: &[(String, u16)], path: &str) -> usize {
	calls.iter().filter(|(c, _)| c == path).count()
}

fn failed_witness(calls: &[(String, u16)]) -> bool {
	calls.iter().any(|(c, st)| c == "/v1/witness" && *st == 502)
}

/// A takes part in a round held for its forfeits (batches without a sweep);
/// the first published tree it reads comes after eleven seconds, every
/// witness failing from then: no forfeit is handed over, in one call of
/// `sync` (`budget` none) or in slices on a wallet kept open.
async fn no_forfeit_after_the_witness_expires_at_the_tree_read(budget: Option<u64>) {
	let mut r = Running::start_with(|c, _, _| {
		c.batches.no_sweep = true;
		c.batches.delegated_reclaim = true;
		c.batches.holder_batches = Some(0);
	}).await;
	let x = r.x;
	r.fund_server(x, 100_000_000).await;
	let url = r.url();
	let p = Proxy::start(&url);
	let tag = if budget.is_some() { "slices" } else { "one call" };
	let (a, d) = (Arca::new(&format!("hand-over forfeit A, {}", tag)), Arca::new(&format!("hand-over forfeit D, {}", tag)));
	boarded(&mut r, &a, &p.url, x, 2_000_000).await;
	boarded(&mut r, &d, &url, x, 2_000_000).await;
	for w in [&a, &d] {
		w.ok(&["participate"]);
	}
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert_eq!(built.len(), 1);
	assert!(failed.is_empty());
	assert!(built[0].broadcast.starts_with("held"), "{}", built[0].broadcast);
	let before = p.calls().len();
	p.rewrite(Some(held_then_no_witness(&p, "/v1/tree", None)));
	let (ok, last, slices) = match budget {
		None => {
			let (ok, s) = a.run(&["sync"]);
			(ok, s, 1)
		},
		Some(b) => {
			let mut w = Wallet::open(&a.dir).expect("open the wallet");
			let mut slices = 0;
			loop {
				let v = tokio::task::block_in_place(|| command::run(&mut w, "sync", &json!({"budget_ms": b})))
					.map(|v| v["result"].clone()).expect("sync answers");
				slices += 1;
				assert!(slices < 200, "the pass ends");
				if v["more"] != json!(true) {
					break (true, v, slices);
				}
			}
		},
	};
	let calls = calls_since(&p, before);
	println!("forfeits, budget {:?}: {} call(s) of sync, ok {}; witnesses {}, forfeit_leaves {}; calls {:?}; unreachable {}", budget,
		slices, ok, count(&calls, "/v1/witness"), count(&calls, "/v1/forfeit_leaves"), calls, last["unreachable"]);
	p.lose("/v1/witness", false);
	p.rewrite(None);
	assert!(ok, "{}", last);
	assert!(count(&calls, "/v1/tree") >= 1, "the tree was read: {:?}", calls);
	assert_eq!(count(&calls, "/v1/forfeit_leaves"), 0, "a forfeit was handed over after the current witness expired");
	assert!(failed_witness(&calls), "the wallet did not witness again before the hand-over: {:?}", calls);
	for w in [&a, &d] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn no_forfeit_is_handed_over_once_the_witness_expires_in_one_call() {
	no_forfeit_after_the_witness_expires_at_the_tree_read(None).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn no_forfeit_is_handed_over_once_the_witness_expires_in_slices() {
	no_forfeit_after_the_witness_expires_at_the_tree_read(Some(0)).await;
}

/// Every wallet of `ws` refreshes its coins in a round held for forfeits and
/// hands its forfeits over; the round goes out and is made final, and no
/// wallet has completed it yet.
async fn held_round(r: &Running, ws: &[&Arca]) {
	for w in ws {
		w.ok(&["participate"]);
	}
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(!built.is_empty() && failed.is_empty(), "{} built, {} failed", built.len(), failed.len());
	for w in ws {
		assert!(common::cli::handed_over(&w.ok(&["sync"])));
	}
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
}

/// A's coin is a leaf of a batch without a sweep, so its refresh signs the
/// release of the leaf's lowest node. The operator refuses the releases as a
/// set, after eleven seconds, every witness failing from then: the wallet
/// posts none of them alone, and keeps them for the next sync.
#[tokio::test(flavor = "multi_thread")]
async fn no_release_is_posted_alone_once_the_witness_expires() {
	let mut r = Running::start_with(|c, _, _| {
		c.batches.no_sweep = true;
		c.batches.delegated_reclaim = true;
		c.batches.holder_batches = Some(0);
	}).await;
	let x = r.x;
	r.fund_server(x, 100_000_000).await;
	let url = r.url();
	let p = Proxy::start(&url);
	let (a, d) = (Arca::new("hand-over release A"), Arca::new("hand-over release D"));
	boarded(&mut r, &a, &p.url, x, 2_000_000).await;
	boarded(&mut r, &d, &url, x, 2_000_000).await;
	// The boards into leaves of a batch without a sweep.
	held_round(&r, &[&a, &d]).await;
	for w in [&a, &d] {
		let s = w.ok(&["sync"]);
		assert!(s["participations"].as_array().unwrap().iter().all(|p| p["state"] == "released"), "{}", s);
	}
	// Those leaves refreshed: A's completion signs their releases.
	held_round(&r, &[&a, &d]).await;
	let before = p.calls().len();
	p.rewrite(Some(held_then_no_witness(&p, "/v1/release_leaves", Some((409, "open_reassignment")))));
	let (ok, s) = a.run(&["sync"]);
	let calls = calls_since(&p, before);
	println!("releases: ok {}; release_leaves {}; calls {:?}; participations {}", ok, count(&calls, "/v1/release_leaves"), calls,
		s["participations"]);
	p.lose("/v1/witness", false);
	p.rewrite(None);
	assert!(ok, "{}", s);
	assert_eq!(count(&calls, "/v1/release_leaves"), 1, "a release was posted alone after the current witness expired: {:?}", calls);
	assert!(failed_witness(&calls), "the wallet did not witness again before posting a release alone: {:?}", calls);
	let after = a.ok(&["sync"]);
	println!("releases, the witness back: participations {}", after["participations"]);
	for w in [&a, &d] {
		let _ = std::fs::remove_dir_all(&w.dir);
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

/// A's coin is swept while A is away, and owed. A wallet restored from its
/// mnemonic claims it at its first sync: the operator answers the first
/// attempt, after eleven seconds, that its key is taken, every witness
/// failing from then. The wallet makes no second attempt.
#[tokio::test(flavor = "multi_thread")]
async fn no_second_owed_claim_once_the_witness_expires() {
	let mut r = Running::start_with(|c, _, _| {
		c.fees.refresh_ppm = 5_000;
		c.watcher.unroll_at_release = false;
	}).await;
	let x = r.x;
	let (url, node) = (r.url(), r.node_url());
	let p = Proxy::start(&url);
	let a = Arca::new("hand-over owed A");
	boarded(&mut r, &a, &url, x, 2_000_000).await;
	a.ok(&["participate", "--max-fee-ppm", "1000000"]);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	let s = a.ok(&["sync"]);
	let leaf = s["participations"][0]["new_leaves"][0].clone();
	let leaf_id = leaf["leaf_id"].as_str().expect("the refresh's leaf").to_string();
	let expiry = leaf["expiry"].as_u64().unwrap() as u32;
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap();
	let _ = std::fs::remove_dir_all(&a.dir);
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, expiry.saturating_sub(now) + HOUR));
	settle(&r).await;
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 37 * HOUR));
	let mut owed = false;
	for _ in 0..10 {
		settle(&r).await;
		let id = leaf_id.parse::<arca_covenant::LeafId>().unwrap().0;
		if r.server.store.owed_entry(&id).await.unwrap().is_some() {
			owed = true;
			break;
		}
	}
	assert!(owed, "A's coin is owed once the sweep is final");
	let a2 = Arca::new("hand-over owed A2");
	let before = p.calls().len();
	p.rewrite(Some(held_then_no_witness(&p, "/v1/owed_claim", Some((409, "key_reused")))));
	let (made_ok, made) = a2.run(&["create", "--server", &p.url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1",
		"--min-exit-delay-units", "1", "--mnemonic", mnemonic.trim()]);
	println!("owed: create ok {}; restore's sync owed {}", made_ok, made["restore"]["sync"]["owed"]);
	// The claim is made at the restore's sync, or else at the first sync after.
	if count(&calls_since(&p, before), "/v1/owed_claim") == 0 {
		let (ok, s) = a2.run(&["sync"]);
		println!("owed: sync ok {}; owed {}", ok, s["owed"]);
	}
	let calls = calls_since(&p, before);
	println!("owed: owed_claim {}; calls {:?}", count(&calls, "/v1/owed_claim"), calls);
	assert!(count(&calls, "/v1/owed_claim") >= 1, "the restored wallet claimed: {:?}", calls);
	p.lose("/v1/witness", false);
	p.rewrite(None);
	assert_eq!(count(&calls, "/v1/owed_claim"), 1, "a second attempt was handed over after the current witness expired: {:?}", calls);
	assert!(failed_witness(&calls), "the wallet did not witness again before its second attempt: {:?}", calls);
	let _ = std::fs::remove_dir_all(&a2.dir);
}

/// A pays B over their channels and the operator never answers the state
/// A sent. A's next read of its channel comes after eleven seconds, every
/// witness failing from then: A does not send the state again.
#[tokio::test(flavor = "multi_thread")]
async fn no_channel_state_is_sent_again_once_the_witness_expires() {
	let mut r = Running::start_with(|c, _, _| {
		c.assets[0].channel_capacity = Some("2000000".into());
	}).await;
	let x = r.x;
	let url = r.url();
	let p = Proxy::start(&url);
	let (a, b) = (Arca::new("hand-over channel A"), Arca::new("hand-over channel B"));
	boarded(&mut r, &a, &p.url, x, 3_000_000).await;
	boarded(&mut r, &b, &url, x, 3_000_000).await;
	for w in [&a, &b] {
		w.ok(&["channel", "open", "--capacity", "1000000"]);
	}
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	for w in [&a, &b] {
		w.ok(&["sync"]);
	}
	let leaf = |w: &Arca| -> String {
		let l = w.ok(&["channel", "list"]);
		l.as_array().unwrap().iter().find(|c| c["coin_state"] == "live").expect("a channel")["leaf_id"].as_str().unwrap().to_string()
	};
	let (la, lb) = (leaf(&a), leaf(&b));
	p.lose("/v1/channel_update", true);
	let (paid, v) = a.run(&["channel", "pay", &la, &lb, "400000"]);
	assert!(!paid, "the state was not answered: {}", v);
	p.lose("/v1/channel_update", false);
	let sent = p.count("/v1/channel_update");
	let before = p.calls().len();
	p.rewrite(Some(held_then_no_witness(&p, "/v1/channel_state", None)));
	let (ok, s) = a.run(&["channel", "sync", &la]);
	let calls = calls_since(&p, before);
	println!("channel: the state sent {} time(s) unanswered; sync ok {}: {}; calls {:?}", sent, ok, s, calls);
	p.lose("/v1/witness", false);
	p.rewrite(None);
	assert_eq!(count(&calls, "/v1/channel_update"), 0, "the kept state was sent again after the current witness expired: {:?}", calls);
	assert!(failed_witness(&calls), "the wallet did not witness again before sending the state: {:?}", calls);
	let again = a.ok(&["channel", "sync", &la]);
	println!("channel, the witness back: {}", again);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A holder's plan: the operator's quote comes after eleven seconds, every
/// witness failing from then. The plan's signatures are not handed over.
#[tokio::test(flavor = "multi_thread")]
async fn no_plan_is_submitted_once_the_witness_expires_at_its_quote() {
	let mut r = Running::start().await;
	let x = r.x;
	let url = r.url();
	let p = Proxy::start(&url);
	let w = Arca::new("hand-over plan");
	boarded(&mut r, &w, &p.url, x, 2_000_000).await;
	w.ok(&["participate"]);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	let s = w.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s);
	let before = p.calls().len();
	p.rewrite(Some(held_then_no_witness(&p, "/v1/plan_quote", None)));
	let (ok, v) = w.run(&["plan"]);
	let calls = calls_since(&p, before);
	println!("plan: ok {}: {}; calls {:?}", ok, v, calls);
	p.lose("/v1/witness", false);
	p.rewrite(None);
	assert!(count(&calls, "/v1/plan_quote") >= 1, "the plan was quoted: {:?}", calls);
	assert_eq!(count(&calls, "/v1/submit_plan"), 0, "the plan was handed over after the current witness expired: {:?}", calls);
	assert!(failed_witness(&calls), "the wallet did not witness again before the hand-over: {:?}", calls);
	let _ = std::fs::remove_dir_all(&w.dir);
}
