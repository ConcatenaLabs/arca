//! A released move to the chain is unlocked within a chain poll of its
//! release, whatever else the watcher has to do: the unlock lane, at the
//! public testnet's settings (batches without a sweep, the round held for its
//! forfeits, finality at certification with `anchor_depth` 0), the server's
//! own loops running and no pass driven by hand.
//!
//! The watcher's whole pass is held up throughout: a test connection holds
//! `lightning_receive`, which the whole pass reads before it comes to the
//! offboards (`refund_unclaimed_receives`), ACCESS EXCLUSIVE, as a pass over
//! a long history keeps it busy for minutes on the testnet. An offboard and a
//! refresh beside it, in one round held for their forfeits, hand them over;
//! the round goes out and is final, the
//! participation is released, and the unlock is in the nursery within
//! seconds while the whole pass has not ended once. Mined, it pays the
//! destination. Once the lock is let go, the whole pass runs and publishes no
//! second unlock of the output. `info.offboards.unlock_within_seconds` is
//! the chain poll, the lane's slack and a block, and never less than what
//! was measured.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::time::{Duration, Instant};

use elements::hashes::Hash;
use elements::{OutPoint, Script, Transaction};

use common::client::{participation_body, want_leaf};
use common::flow::of_kind;
use common::keys::{keypair, xonly};
use common::rounds::{credited_board, hand_over_held, status, VALUE};
use common::running::Running;
use server::participations::OutputRequest;
use server::server::AssetSection;

const PAID: u64 = 900_000;
const FEE: u64 = 100_000;

#[tokio::test(flavor = "multi_thread")]
async fn a_released_offboard_is_unlocked_while_the_whole_pass_is_held_up() {
	let mut r = Running::start_with(|c, y| {
		c.assets.push(AssetSection::new(y, common::running::MIN_LEAF));
		c.batches.no_sweep = true;
		c.finality.anchor_depth = 0;
		c.watcher.enabled = true;
		// The whole pass runs at each block, never on its own clock.
		c.watcher.recovery_interval_seconds = 3_600;
	}).await;
	let x = r.x;
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let owner = keypair("OP9 lane owner");
	let (held, _) = credited_board(&mut r, &owner, x).await;
	// A refresh beside it, as in every round on the testnet: its batch
	// without a sweep holds the round for the forfeits.
	let (other, _) = credited_board(&mut r, &keypair("OP9 lane, a refresh"), x).await;
	let (w, _) = want_leaf(&keypair("OP9 lane, the refresh's new leaf"), x, VALUE);
	let (body, _) = participation_body(&[&other], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	let to = Script::new_v0_wpkh(&elements::WPubkeyHash::hash(&keypair("OP9 lane, on-chain").public_key().serialize()));
	let out = OutputRequest::Offboard { asset: x, value: PAID, script: to.clone() };
	let (body, id) = participation_body(&[&held], &[out], &[(x, FEE)], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	assert_eq!(VALUE, PAID + FEE, "the offboard takes the whole board");
	let (rounds, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty() && rounds.len() == 1, "{:?}", failed);
	let round = rounds[0].tx.txid();
	println!("round {}: held for its forfeits, {} offboard(s), {} batch(es)", round, rounds[0].offboards, rounds[0].batches.len());
	assert!(r.rt.client().raw_transaction(&round).is_err(), "the round is held, not broadcast");

	// The whole pass held up from here on.
	let (db, conn) = tokio_postgres::connect(&r.db.url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(async move {
		let _ = conn.await;
	});
	db.batch_execute("BEGIN; LOCK TABLE lightning_receive IN ACCESS EXCLUSIVE MODE;").await.unwrap();
	r.produce().await;
	tokio::time::sleep(Duration::from_secs(2)).await;
	let held_since = r.server.watcher.fee_status().last_pass_at;
	println!("lightning_receive held ACCESS EXCLUSIVE; the whole pass last ended at {}", held_since);

	assert_eq!(hand_over_held(&r, &round).await, 2, "both participations hand their forfeits over");
	let start = Instant::now();
	let mut mined = false;
	let released = loop {
		if status(&r, &id)["state"] == "released" {
			break Instant::now();
		}
		// The round goes out on its last forfeit; then a block, buried.
		if !mined && r.rt.client().raw_transaction(&round).is_ok() {
			r.produce().await;
			r.bury().await;
			mined = true;
		}
		assert!(start.elapsed() < Duration::from_secs(60), "the participation was not released: {}", status(&r, &id));
		tokio::time::sleep(Duration::from_millis(100)).await;
	};
	let st = status(&r, &id);
	let op = OutPoint::new(round, st["outputs"][0]["offboard_vout"].as_u64().unwrap() as u32);
	let subject = [op.txid.to_byte_array().to_vec(), op.vout.to_le_bytes().to_vec()].concat();
	let unlock = loop {
		if let Some(w) = of_kind(&r, "unlock").await.into_iter().find(|w| w.subject == subject) {
			break w;
		}
		assert!(released.elapsed() < Duration::from_secs(15),
			"no unlock within 15 s of the release while the whole pass is held up (it last ended at {})", held_since);
		tokio::time::sleep(Duration::from_millis(100)).await;
	};
	let took = released.elapsed();
	assert_eq!(r.server.watcher.fee_status().last_pass_at, held_since, "the whole pass did not end meanwhile");
	println!("released → unlock {} in the nursery: {} ms, the whole pass held up throughout", common::flow::txid(&unlock), took.as_millis());
	assert!(took < Duration::from_secs(5), "within a chain poll and the lane's work: {:?}", took);

	// Mined, it pays the destination.
	let tx: Transaction = elements::encode::deserialize(&unlock.tx).unwrap();
	assert_eq!(tx.input[0].previous_output, op);
	assert_eq!((&tx.output[0].script_pubkey, tx.output[0].asset.explicit(), tx.output[0].value.explicit()), (&to, Some(x), Some(PAID)));
	r.produce().await;
	let info = r.http.get("info").json;
	let bound = info["offboards"]["unlock_within_seconds"].as_u64().unwrap_or(0);
	println!("info.offboards.unlock_within_seconds: {}", bound);
	// A chain poll of 200 ms, the lane's 10 s and a block of 60 s.
	assert_eq!(bound, 71, "{}", info["offboards"]);

	// Let go: the whole pass runs, and publishes no second unlock.
	db.batch_execute("ROLLBACK;").await.unwrap();
	r.produce().await;
	let start = Instant::now();
	while r.server.watcher.fee_status().last_pass_at == held_since {
		assert!(start.elapsed() < Duration::from_secs(60), "the whole pass never ended after the lock was let go");
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
	r.produce().await;
	r.bury().await;
	tokio::time::sleep(Duration::from_secs(2)).await;
	let unlocks: Vec<_> = of_kind(&r, "unlock").await.into_iter().filter(|w| w.subject == subject).collect();
	assert_eq!(unlocks.len(), 1, "one unlock of the output, whichever lane published it");
	println!("the whole pass ended once the lock was let go; still one unlock of {}", op);

	// The lane reads a participation's offboard outputs through an index,
	// not a scan of every offboard the operator ever made.
	let plan: Vec<String> = db.query("EXPLAIN SELECT * FROM round_offboard WHERE participation_id = ANY($1)",
		&[&vec![id.to_vec()]]).await.unwrap().iter().map(|r| r.get(0)).collect();
	println!("the lane's read of round_offboard: {}", plan.join(" | "));
	assert!(db.execute("SET enable_seqscan = off", &[]).await.is_ok());
	let plan: Vec<String> = db.query("EXPLAIN SELECT * FROM round_offboard WHERE participation_id = ANY($1)",
		&[&vec![id.to_vec()]]).await.unwrap().iter().map(|r| r.get(0)).collect();
	assert!(plan.iter().any(|l| l.contains("round_offboard_by_participation")), "no index by participation: {}", plan.join(" | "));
}
