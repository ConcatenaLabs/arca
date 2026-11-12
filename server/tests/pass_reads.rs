//! The watcher's whole pass reads only the batches something touched (the
//! log the triggers of `V49__pass_reads.sql` fill), those a date called for,
//! and those a step acted on in the last pass: what is settled is not read
//! again. Each test runs with no slice of batches read in order
//! (`[watcher] read_slice = 0`), so nothing but the log brings a batch back,
//! at the public testnet's settings (batches without a sweep, finality at
//! certification with `anchor_depth` 0), the watcher driven a pass at a time.
//!
//! 1. A late change to a batch it stopped reading: a lowest node of two
//!    owners, one of whom released it, is read and left; the batch is then
//!    not read again. The other owner releases a day's worth of passes later
//!    and the next pass reads the batch and reclaims the node.
//! 2. A transaction final yesterday that a reorganisation un-mines today: the
//!    reclaim is final and its batch no longer read; its block is
//!    disconnected, and the next pass reads the batch again. The nursery puts
//!    the same reclaim back; no second reclaim is built.
//! 3. A late commit by a transaction older than the log's read point, and a
//!    batch that changes while a pass reads it: a transaction touches a
//!    batch and stays open across a whole pass; the pass does not read the
//!    batch, nor forget the touch; once it commits, the next pass reads it.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::time::Duration;

use elements::hashes::Hash;
use elements::Txid;
use serde_json::{json, Value};

use common::flow::{log, refresh, release, settle, Coin, Refreshed};
use common::keys::keypair;
use common::node;
use common::rounds::credited_board;
use common::running::Running;
use server::server::AssetSection;

async fn start() -> Running {
	let mut r = Running::start_with(|c, y| {
		c.assets.push(AssetSection::new(y, common::running::MIN_LEAF));
		c.batches.no_sweep = true;
		c.finality.anchor_depth = 0;
		c.watcher.read_slice = 0;
	}).await;
	let x = r.x;
	for _ in 0..4 {
		r.fund_wallet_in(x, 50_000_000).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r
}

async fn db(r: &Running) -> tokio_postgres::Client {
	let (client, conn) = tokio_postgres::connect(&r.db.url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(async move {
		let _ = conn.await;
	});
	client
}

/// A whole pass, then everything it published settled: the batches it read.
async fn pass(r: &Running) -> Vec<(i64, u32)> {
	r.synced().await;
	r.server.watcher.pass().await.unwrap();
	let read = r.server.watcher.last_read();
	settle(r).await;
	read
}

/// The batch of the round `round` (its one batch in X).
async fn batch_of(c: &tokio_postgres::Client, round: &Txid) -> (i64, u32) {
	let row = c.query_one("SELECT b.round_id, b.vout FROM batch b JOIN round r USING (round_id) WHERE r.txid = $1",
		&[&round.to_byte_array().to_vec()]).await.unwrap();
	(row.get(0), row.get::<_, i32>(1) as u32)
}

async fn reclaims(r: &Running) -> Vec<server::store::WatcherTxRow> {
	log(r).await.into_iter().filter(|w| w.kind == "reclaim").collect()
}

/// Two boards refreshed into one round: their two leaves under one lowest
/// node, and the round.
async fn two_leaves(r: &mut Running) -> (Vec<Refreshed>, Txid) {
	let x = r.x;
	let mut coins = vec![];
	for i in 0..2 {
		let (held, tx) = credited_board(r, &keypair(&format!("PR board {}", i)), x).await;
		coins.push(Coin { held, bases: vec![tx] });
	}
	let keys: Vec<_> = (0..2).map(|i| keypair(&format!("PR leaf {}", i))).collect();
	let pairs: Vec<(&Coin, &_)> = coins.iter().zip(keys.iter()).collect();
	let out = refresh(r, &pairs).await;
	let round = out[0].round.txid();
	(out, round)
}

/// Refreshes `x`'s coin and releases its lowest node.
async fn refresh_and_release(r: &mut Running, x: &Refreshed, tag: &str) {
	let k = keypair(tag);
	let done = refresh(r, &[(&x.new, &k)]).await;
	release(r, &done[0]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_late_release_and_a_reorganisation_are_read_again() {
	let mut r = start().await;
	let c = db(&r).await;
	let (leaves, round) = two_leaves(&mut r).await;
	let batch = batch_of(&c, &round).await;
	println!("round {}: batch {:?}, two leaves", round, batch);

	// 1. One owner releases; the node waits for the other.
	refresh_and_release(&mut r, &leaves[0], "PR leaf 0, again").await;
	let first = pass(&r).await;
	assert!(first.contains(&batch), "the release touched the batch: {:?}", first);
	// Settled: what the passes published for it (or for the round, its
	// boards' forfeits) final, nothing touches it any more.
	let mut settled = false;
	for _ in 0..8 {
		if !pass(&r).await.contains(&batch) {
			settled = true;
			break;
		}
	}
	assert!(settled, "the batch settles");
	for _ in 0..3 {
		let read = pass(&r).await;
		assert!(!read.contains(&batch), "a batch nothing touched is not read again: {:?}", read);
	}
	assert!(reclaims(&r).await.is_empty(), "no reclaim while one owner has not released");
	println!("one release: the batch read once, then not again over 3 passes; no reclaim");

	// The other owner, late.
	refresh_and_release(&mut r, &leaves[1], "PR leaf 1, again").await;
	if std::env::var("OP9_MUTANT").is_ok_and(|v| v == "no_release_trigger") {
		// The mutant: the release's touch lost.
		c.batch_execute("DELETE FROM watch_touch").await.unwrap();
	}
	let mut found = false;
	for _ in 0..4 {
		let read = pass(&r).await;
		if !reclaims(&r).await.is_empty() {
			assert!(read.contains(&batch) || found, "the reclaim came from a pass that read the batch");
			found = true;
			break;
		}
	}
	assert!(found, "the late release was read and the node reclaimed");
	for _ in 0..3 {
		pass(&r).await;
	}
	let rc = reclaims(&r).await;
	assert_eq!(rc.len(), 1);
	assert_eq!(rc[0].state, server::store::NurseryState::Final);
	let rtx = Txid::from_byte_array(rc[0].txid);
	let mut settled = false;
	for _ in 0..8 {
		if !pass(&r).await.contains(&batch) {
			settled = true;
			break;
		}
	}
	assert!(settled, "the reclaim final: the batch is not read again");
	println!("the late release: the batch read, the node reclaimed by {} (final), then not read again", rtx);

	// 2. The reclaim's block disconnected: final yesterday, un-mined today.
	let v: Value = r.rt.client().call("getrawtransaction", &[json!(rtx.to_string()), json!(true)]).unwrap();
	let block: elements::BlockHash = v["blockhash"].as_str().unwrap().parse().unwrap();
	node::invalidate(&r.rt, &block);
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0"])).unwrap();
	let store = r.server.store.clone();
	let t = rtx.to_byte_array();
	let mut gone = false;
	for _ in 0..100 {
		r.server.nursery.pass().await.unwrap();
		if store.nursery_get(&t).await.unwrap().is_some_and(|n| n.state != server::store::NurseryState::Final) {
			gone = true;
			break;
		}
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
	assert!(gone, "the nursery no longer holds the reclaim final");
	r.server.watcher.pass().await.unwrap();
	let read = r.server.watcher.last_read();
	assert!(read.contains(&batch), "the disconnection touched the batch, and the pass read it: {:?}", read);
	println!("the reclaim's block disconnected: the next pass read the batch again");
	for _ in 0..20 {
		pass(&r).await;
		if reclaims(&r).await.iter().all(|w| w.state == server::store::NurseryState::Final) {
			break;
		}
	}
	let rc = reclaims(&r).await;
	assert_eq!(rc.len(), 1, "no second reclaim was built");
	assert_eq!(Txid::from_byte_array(rc[0].txid), rtx, "the same reclaim, put back");
	let n = store.nursery_get(&t).await.unwrap().unwrap();
	println!("the same reclaim {}, no second one; the nursery holds it {:?} after {} broadcast(s), last: {:?}", rtx, n.state,
		n.broadcasts, n.last_result);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_touch_committed_after_the_read_point_is_read_by_the_next_pass() {
	let mut r = start().await;
	let c = db(&r).await;
	let (_, round) = two_leaves(&mut r).await;
	let batch = batch_of(&c, &round).await;
	let mut settled = false;
	for _ in 0..8 {
		if !pass(&r).await.contains(&batch) {
			settled = true;
			break;
		}
	}
	assert!(settled, "settled: not read");

	// A transaction touches the batch and stays open across a whole pass,
	// which reads while it runs.
	let late = db(&r).await;
	late.batch_execute(&format!("BEGIN; INSERT INTO watch_touch (round_id, vout) VALUES ({}, {});", batch.0, batch.1)).await.unwrap();
	let during = pass(&r).await;
	assert!(!during.contains(&batch), "an uncommitted touch is not seen: {:?}", during);
	let kept: i64 = c.query_one("SELECT count(*) FROM watch_touch", &[]).await.unwrap().get(0);
	println!("a pass while the touching transaction is open: the batch not read; touches the log keeps (others cannot see it): {}", kept);
	late.batch_execute("COMMIT;").await.unwrap();
	let after = pass(&r).await;
	assert!(after.contains(&batch), "the touch committed after the read point is read by the next pass: {:?}", after);
	let next = pass(&r).await;
	assert!(!next.contains(&batch), "read once, then forgotten: {:?}", next);
	println!("committed late: read by the next pass, then forgotten");
}
