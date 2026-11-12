//! A released offboard whose unlock the node refuses, beside one it takes,
//! in one round, at the public testnet's settings (no_sweep, the round held
//! for its forfeits, certification required, anchor_depth 0), the watcher's
//! whole pass held up throughout (`tests/unlock_lane.rs`).
//!
//! 1. The unlock lane skips the refused one and unlocks the other within the
//!    bound.
//! 2. It does not rebuild and try the refused unlock again at every chain
//!    poll while nothing on the chain has changed: with no block for 10 s, at
//!    most 2 tries.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use elements::hashes::Hash;
use elements::Script;

use common::client::{hex, participation_body, want_leaf};
use common::flow::of_kind;
use common::keys::{keypair, xonly};
use common::rounds::{credited_board, hand_over_held, status, VALUE};
use common::running::Running;
use server::participations::OutputRequest;
use server::server::AssetSection;

const PAID: u64 = 900_000;
const FEE: u64 = 100_000;

/// Counts the watcher's "not taken by the node yet" lines for one subject.
struct Counter {
	needle: Mutex<Option<String>>,
	hits: AtomicUsize,
}

impl log::Log for Counter {
	fn enabled(&self, m: &log::Metadata) -> bool {
		m.level() <= log::Level::Info
	}
	fn log(&self, r: &log::Record) {
		if !self.enabled(r.metadata()) {
			return;
		}
		let s = format!("{}", r.args());
		println!("[log] {} {}", r.level(), s);
		if let Some(n) = &*self.needle.lock().unwrap() {
			if s.contains(n.as_str()) && s.contains("not taken by the node yet") {
				let k = self.hits.fetch_add(1, Ordering::SeqCst) + 1;
				println!("[{:?}] refused try #{}: {}", std::time::SystemTime::now(), k, s);
			}
		}
	}
	fn flush(&self) {}
}

fn counter() -> &'static Counter {
	static C: OnceLock<Counter> = OnceLock::new();
	C.get_or_init(|| Counter { needle: Mutex::new(None), hits: AtomicUsize::new(0) })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_unlock_neither_stalls_the_lane_nor_is_retried_every_poll() {
	log::set_logger(counter()).unwrap();
	log::set_max_level(log::LevelFilter::Info);
	// The testnet node requires standard transactions; a regtest node does not
	// unless told.
	let mut r = Running::start_on(&["-acceptnonstdtxn=0"], |c, y| {
		c.assets.push(AssetSection::new(y, common::running::MIN_LEAF));
		c.batches.no_sweep = true;
		c.finality.anchor_depth = 0;
		c.watcher.enabled = true;
		c.watcher.recovery_interval_seconds = 3_600;
	}).await;
	let x = r.x;
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let info = r.http.get("info").json;
	println!("finality as published: {}", info["finality"]);

	let bad_owner = keypair("refused lane refused owner");
	let good_owner = keypair("refused lane good owner");
	let (bad, _) = credited_board(&mut r, &bad_owner, x).await;
	let (good, _) = credited_board(&mut r, &good_owner, x).await;
	let (other, _) = credited_board(&mut r, &keypair("refused lane a refresh"), x).await;
	let (w, _) = want_leaf(&keypair("refused lane the refresh's new leaf"), x, VALUE);
	let (body, _) = participation_body(&[&other], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");

	// OP_1 OP_1: 2 bytes, inside the server's bounds, non-standard for
	// the node's relay policy, so its unlock is never taken.
	let nonstd = Script::from(vec![0x51, 0x51]);
	let out = OutputRequest::Offboard { asset: x, value: PAID, script: nonstd };
	let (body, bad_id) = participation_body(&[&bad], &[out], &[(x, FEE)], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	let to = Script::new_v0_wpkh(&elements::WPubkeyHash::hash(&keypair("refused lane good, on-chain").public_key().serialize()));
	let out = OutputRequest::Offboard { asset: x, value: PAID, script: to.clone() };
	let (body, good_id) = participation_body(&[&good], &[out], &[(x, FEE)], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");

	let (rounds, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty() && rounds.len() == 1, "{:?}", failed);
	let round = rounds[0].tx.txid();
	println!("round {}: {} offboard(s)", round, rounds[0].offboards);

	// The whole pass held up from here on, as in tests/unlock_lane.rs.
	let (db, conn) = tokio_postgres::connect(&r.db.url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(async move {
		let _ = conn.await;
	});
	db.batch_execute("BEGIN; LOCK TABLE lightning_receive IN ACCESS EXCLUSIVE MODE;").await.unwrap();
	r.produce().await;
	tokio::time::sleep(Duration::from_secs(2)).await;
	let held_since = r.server.watcher.fee_status().last_pass_at;

	let bad_vout_of = |r: &Running| status(r, &bad_id)["outputs"][0]["offboard_vout"].as_u64();
	assert_eq!(hand_over_held(&r, &round).await, 3, "three participations hand their forfeits over");
	let start = Instant::now();
	let mut mined = false;
	let released = loop {
		if status(&r, &good_id)["state"] == "released" && status(&r, &bad_id)["state"] == "released" {
			break Instant::now();
		}
		if !mined && r.rt.client().raw_transaction(&round).is_ok() {
			let vout = bad_vout_of(&r).expect("the refused offboard's vout") as u32;
			let subject = [round.to_byte_array().to_vec(), vout.to_le_bytes().to_vec()].concat();
			*counter().needle.lock().unwrap() = Some(hex(&subject));
			r.produce().await;
			r.bury().await;
			mined = true;
		}
		assert!(start.elapsed() < Duration::from_secs(60), "not released: {} / {}", status(&r, &good_id), status(&r, &bad_id));
		tokio::time::sleep(Duration::from_millis(100)).await;
	};
	let gst = status(&r, &good_id);
	let gvout = gst["outputs"][0]["offboard_vout"].as_u64().unwrap() as u32;
	let gsubject = [round.to_byte_array().to_vec(), gvout.to_le_bytes().to_vec()].concat();

	// 1. The good one is unlocked, the refused one skipped.
	loop {
		if of_kind(&r, "unlock").await.into_iter().any(|w| w.subject == gsubject) {
			break;
		}
		assert!(released.elapsed() < Duration::from_secs(15), "the good offboard was not unlocked within 15 s beside a refused one");
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	println!("good offboard unlocked {} ms after the release, beside a refused one", released.elapsed().as_millis());

	// 2. No block for 10 s: how often does the lane rebuild and re-test the
	// refused unlock?
	let before = counter().hits.load(Ordering::SeqCst);
	tokio::time::sleep(Duration::from_secs(10)).await;
	let tries = counter().hits.load(Ordering::SeqCst) - before;
	assert_eq!(r.server.watcher.fee_status().last_pass_at, held_since, "the whole pass did not run meanwhile");
	println!("refused unlock rebuilt and re-tested {} time(s) in 10 s with no new block (the whole pass held up)", tries);
	db.batch_execute("ROLLBACK;").await.unwrap();
	assert!(tries <= 2, "the lane rebuilt and re-tested a refused unlock {} times in 10 s with no new block", tries);
}
