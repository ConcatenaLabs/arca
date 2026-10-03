//! What the calls anyone may make without proving a key leave behind: review
//! R7's load (P3, P3b) turned around. A board is registered only once the
//! node takes its transaction, so junk boards leave no row and nothing in
//! the nursery; operator nonces and challenges are handed out at a bounded
//! rate and deleted once expired; and a board the node took that never
//! confirms is dropped after a set time.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::time::{Duration, Instant};

use elements::hashes::Hash;
use elements::{OutPoint, Sequence, Transaction, Txid};
use serde_json::json;

use common::client::{board_record, random32};
use common::keys::{keypair, xonly};
use common::node::{op_true, spend_op_true};
use common::rounds::VALUE;
use common::running::Running;
use server::server::LimitsSection;
use server::store::{BoardState, NurseryState};

const PER_SECOND: u32 = 20;
const BURST: u32 = 60;
const TTL: u64 = 3;

/// The rows the unauthenticated calls could leave: nonces, challenges,
/// leaves, boards, and the nursery's transactions.
async fn rows(r: &Running) -> [i64; 5] {
	let (client, conn) = tokio_postgres::connect(&r.config.database, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(conn);
	let row = client.query_one(
		"SELECT (SELECT count(*) FROM operator_nonce), (SELECT count(*) FROM auth_challenge), (SELECT count(*) FROM leaf),
		        (SELECT count(*) FROM board), (SELECT count(*) FROM nursery_tx)", &[]).await.unwrap();
	[row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)]
}

/// The mean time of `n` nursery passes.
async fn nursery_pass(r: &Running, n: u32) -> Duration {
	let t = Instant::now();
	for _ in 0..n {
		r.server.nursery.pass().await.unwrap();
	}
	t.elapsed() / n
}

/// A board record, and a transaction paying it from an input that does not
/// exist.
fn junk_board(r: &Running, i: u32, nonce: [u8; 32]) -> (arca_covenant::BoardRecord, Transaction) {
	let owner = keypair(&format!("junk {}", i));
	let record = board_record(&owner, nonce, r.x, VALUE, r.chain, xonly(&r.s));
	let mut b = [0u8; 32];
	b[..4].copy_from_slice(&(i + 1).to_le_bytes());
	let fake = (OutPoint::new(Txid::from_byte_array(b), 0),
		sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(r.x, VALUE + 10_000), op_true()));
	let tx = record.tx(std::slice::from_ref(&fake), r.x, 2_000, &op_true()).unwrap().tx;
	(record, tx)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_reviewers_load_leaves_no_rows() {
	let r = Running::start_with(|c, _| {
		c.limits = LimitsSection {
			issue_per_second: PER_SECOND, issue_burst: BURST, nonce_ttl_seconds: TTL, board_unconfirmed_seconds: 6 * 3600,
			// The test deletes what expired itself, when it wants to.
			cleanup_interval_seconds: 3600,
		};
		c.challenge_ttl_seconds = TTL;
	}).await;
	r.synced().await;
	let before = nursery_pass(&r, 5).await;
	let start = rows(&r).await;
	println!("before the load: nursery pass {:?}; rows nonce|challenge|leaf|board|nursery = {:?}", before, start);

	// P3: 50 junk boards, each with a nonce of the operator's.
	for i in 0..50u32 {
		let nonce = r.http.operator_nonce();
		let (record, tx) = junk_board(&r, i, nonce);
		let a = r.http.register_board(&record, &tx);
		assert_eq!((a.status, a.refusal().0.as_str()), (422, "not_accepted"), "{}", a.json);
		assert!(a.refusal().1.contains("missing-inputs"), "refused for its missing input: {}", a.refusal().1);
		if i == 0 {
			println!("junk board 0: {} {}", a.status, a.json);
		}
	}
	// P3b: 500 more, as fast as they go: a nonce when the rate gives one,
	// else one the operator never issued.
	let t = Instant::now();
	let mut refused = std::collections::BTreeMap::<String, u32>::new();
	for i in 50..550u32 {
		let n = r.http.post("operator_nonce", &json!({}));
		let nonce = if n.status == 200 {
			common::client::unhex(n.json["operator_nonce"].as_str().unwrap()).try_into().unwrap()
		} else {
			assert_eq!((n.status, n.refusal().0.as_str()), (429, "rate_limited"), "{}", n.json);
			random32()
		};
		let (record, tx) = junk_board(&r, i, nonce);
		let a = r.http.register_board(&record, &tx);
		assert_ne!(a.status, 200, "a junk board is never registered: {}", a.json);
		*refused.entry(a.refusal().0).or_default() += 1;
	}
	println!("500 more junk boards in {:?}, every one refused: {:?}", t.elapsed(), refused);

	// 1,000 nonces and 1,000 challenges, as fast as they go.
	let t = Instant::now();
	let (mut nonces, mut challenges) = (0u32, 0u32);
	for _ in 0..1000 {
		let a = r.http.post("operator_nonce", &json!({}));
		match a.status {
			200 => nonces += 1,
			_ => assert_eq!((a.status, a.refusal().0.as_str()), (429, "rate_limited"), "{}", a.json),
		}
	}
	for _ in 0..1000 {
		let a = r.http.post("challenge", &json!({}));
		match a.status {
			200 => challenges += 1,
			_ => assert_eq!((a.status, a.refusal().0.as_str()), (429, "rate_limited"), "{}", a.json),
		}
	}
	let spent = t.elapsed();
	let bound = BURST + (spent.as_secs_f64() * f64::from(PER_SECOND)).ceil() as u32 + 1;
	println!("1,000 nonce and 1,000 challenge requests in {:?}: {} nonces and {} challenges handed out (bound {})",
		spent, nonces, challenges, bound);
	assert!(nonces <= bound && challenges <= bound, "the rate holds");

	for _ in 0..3 {
		r.produce().await;
		r.synced().await;
		r.server.nursery.pass().await.unwrap();
		r.server.boards.pass().await.unwrap();
	}
	let after_load = rows(&r).await;
	println!("after the load: rows nonce|challenge|leaf|board|nursery = {:?}", after_load);
	assert_eq!(after_load[2..], start[2..], "no leaf, board or nursery row");

	// Once expired, the nonces and challenges are deleted.
	tokio::time::sleep(Duration::from_secs(TTL + 1)).await;
	let (n, c) = r.server.store.delete_expired(Duration::from_secs(TTL)).await.unwrap();
	let end = rows(&r).await;
	let after = nursery_pass(&r, 5).await;
	println!("deleted {} nonces and {} challenges; rows nonce|challenge|leaf|board|nursery = {:?}; nursery pass {:?} (before the load {:?})",
		n, c, end, after, before);
	assert_eq!(end, [0, 0, start[2], start[3], start[4]], "the load leaves no row");
	assert!(after < before * 5 + Duration::from_millis(20), "the nursery pass is not slower: {:?} against {:?}", after, before);
}

/// A board the node took whose transaction then loses its parent: it can
/// never confirm, and no final transaction spends its own input, so only
/// the timer drops it.
#[tokio::test(flavor = "multi_thread")]
async fn a_board_that_never_confirms_is_dropped() {
	let mut r = Running::start_with(|c, _| {
		c.limits = LimitsSection { board_unconfirmed_seconds: 2, issue_per_second: 1000, issue_burst: 1000, ..Default::default() };
	}).await;
	let x = r.x;
	// A parent that signals replacement, paying an output the board spends.
	let coin = r.purse.take_coin(x);
	let mut parent = spend_op_true(&coin, vec![sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(x, VALUE + 10_000), op_true())], 5_000);
	parent.input[0].sequence = Sequence(0xffff_fffd);
	r.rt.client().send_raw_transaction(&parent).unwrap();
	let nonce = r.http.operator_nonce();
	let record = board_record(&keypair("never confirms"), nonce, x, VALUE, r.chain, xonly(&r.s));
	let paid = (OutPoint::new(parent.txid(), 0), parent.output[0].clone());
	let tx = record.tx(std::slice::from_ref(&paid), x, 2_000, &op_true()).unwrap().tx;
	let a = r.http.register_board(&record, &tx);
	assert_eq!(a.status, 200, "the node takes it: {}", a.json);
	// The parent is replaced: the board transaction goes with it.
	let replacement = spend_op_true(&coin, vec![], 50_000);
	r.rt.client().send_raw_transaction(&replacement).unwrap();
	r.purse.put((OutPoint::new(replacement.txid(), 0), replacement.output[0].clone()));
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.server.nursery.pass().await.unwrap();
	let n = r.server.store.nursery_get(&tx.txid().to_byte_array()).await.unwrap().unwrap();
	println!("the board's transaction after its parent was replaced: {:?}, last result {:?}", n.state, n.last_result);
	assert_eq!(n.state, NurseryState::Pending, "no final transaction spends its own input: the nursery alone never loses it");
	tokio::time::sleep(Duration::from_secs(3)).await;
	r.server.boards.pass().await.unwrap();
	let b = r.server.store.board(&record.leaf_id().0).await.unwrap().unwrap();
	let n = r.server.store.nursery_get(&tx.txid().to_byte_array()).await.unwrap().unwrap();
	println!("after the set time: board {:?}, its transaction {:?}", b.state, n.state);
	assert_eq!((b.state, n.state), (BoardState::Lost, NurseryState::Lost));
	assert_eq!(r.http.board_status(&record.leaf_id()).ok()["state"], "lost");
}
