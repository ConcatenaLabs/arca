//! A participation the operator's wallet cannot fund in its asset waits, and
//! delays no other: review R7's P2 turned around.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use common::client::{participation_body, want_leaf, Held};
use common::keys::{keypair, xonly};
use common::rounds::{credited_board, start, status, VALUE};
use arca_covenant::CoinRecord;

#[tokio::test(flavor = "multi_thread")]
async fn an_unfundable_participation_delays_no_other() {
	// X and Y served; the wallet holds 100M of X and 50M of Y.
	let mut r = start().await;
	let (x, y) = (r.x, r.y);
	let a = keypair("A, board in X");
	let (a_held, _) = credited_board(&mut r, &a, x).await;
	// B boards 60M of Y, more than the operator's wallet holds of Y.
	let b = keypair("B, board in Y");
	let (rec, _, _) = r.board_in(&b, y, 60_000_000);
	r.produce().await;
	r.bury().await;
	let http = r.http.clone();
	let bid = rec.leaf_id();
	r.wait("B's board credited", || http.board_status(&bid).json["state"] == "credited").await;
	let b_held = Held { key: b, nonce: rec.owner_nonce, id: bid, record: CoinRecord::Board(rec) };

	// B first: the round still takes A.
	let (wb, _) = want_leaf(&keypair("B new"), y, 60_000_000);
	let (body_b, id_b) = participation_body(&[&b_held], &[wb], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body_b).ok()["state"], "pending");
	let (wa, _) = want_leaf(&keypair("A new"), x, VALUE);
	let (body_a, id_a) = participation_body(&[&a_held], &[wa], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body_a).ok()["state"], "pending");

	let built = r.server.rounds.run_round().await.unwrap().expect("a round, with A");
	println!("round {}: {} participation(s), batches {:?}", built.tx.txid(), built.participations, built.batches);
	assert_eq!(built.participations, 1);
	assert_eq!(built.batches.iter().map(|b| b.0).collect::<Vec<_>>(), vec![x], "one batch, in X");
	let (sa, sb) = (status(&r, &id_a), status(&r, &id_b));
	println!("A: {}; B: {}, waiting: {}", sa["state"], sb["state"], sb["waiting"]);
	assert_eq!(sa["state"], "issued");
	assert!(sa.get("waiting").is_none());
	assert_eq!(sb["state"], "pending");
	let why = sb["waiting"].as_str().expect("B says why it waits");
	assert!(why.contains(&format!("of asset {}", y)) && why.contains("can spend 50000000"), "{}", why);

	// Once the wallet holds enough of Y, the next round takes B.
	r.fund_wallet_in(y, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let built = r.server.rounds.run_round().await.unwrap().expect("a round, with B");
	println!("round {}: {} participation(s), batches {:?}", built.tx.txid(), built.participations, built.batches);
	let sb = status(&r, &id_b);
	assert_eq!(sb["state"], "issued");
	assert!(sb.get("waiting").is_none(), "{}", sb);
}
