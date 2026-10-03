//! A leaf is never created under the operator's own key `S`: not by a board,
//! not by a transfer, not by a participation. Such a leaf would be the
//! operator's, with every path the signer signs for `S` open to it (an exit,
//! a board's conversion, a forfeit's refund).

mod common;

use elements::OutPoint;

use common::client::{board_record, new_leaf, participation_body, transfer_body, want_leaf};
use common::keys::{keypair, xonly};
use common::rounds::{credited_board, start, VALUE};
use common::running::Running;

const MARGIN: u64 = 2_000;

#[tokio::test(flavor = "multi_thread")]
async fn a_board_owned_by_s_is_refused() {
	let mut r = Running::start().await;
	let x = r.x;
	let s_key = r.s;
	let nonce = r.http.operator_nonce();
	let record = board_record(&s_key, nonce, x, VALUE, r.chain, xonly(&r.s));
	let coin = r.purse.take_coin(x);
	let tx = record.tx(std::slice::from_ref(&coin), x, 2_000, &common::node::op_true()).unwrap().tx;
	r.rt.client().send_raw_transaction(&tx).unwrap();
	let a = r.http.register_board(&record, &tx);
	assert_eq!(a.status, 422, "{}", a.json);
	assert_eq!(a.refusal().0, "operator_key");
	// Nothing is left behind: the board is not known, its nonce still free.
	assert_eq!(r.http.board_status(&record.leaf_id()).status, 404);
	let other = keypair("a board owned by someone else");
	let record = board_record(&other, nonce, x, VALUE, r.chain, xonly(&r.s));
	let coin = (OutPoint::new(tx.txid(), 1), tx.output[1].clone());
	let tx = record.tx(std::slice::from_ref(&coin), x, 2_000, &common::node::op_true()).unwrap().tx;
	r.rt.client().send_raw_transaction(&tx).unwrap();
	assert_eq!(r.http.register_board(&record, &tx).status, 200, "the nonce is still the owner's to use");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_transfer_to_a_leaf_owned_by_s_is_refused() {
	let mut r = Running::start().await;
	let s = xonly(&r.s);
	let a = keypair("A");
	let x = r.x;
	let (a_held, board_tx) = credited_board(&mut r, &a, x).await;
	let a_valid = a_held.record.resolve(&[board_tx], &r.policy()).unwrap();
	let (mut leaf, _) = new_leaf(&a);
	leaf.owner = s;
	let kept = VALUE - MARGIN;
	let body = transfer_body(&[(&a_held, a_valid.clone(), kept)], &[(x, kept - MARGIN, leaf)], s, r.chain);
	let refused = r.http.post("cosign_transfer", &body);
	assert_eq!(refused.status, 422, "{}", refused.json);
	assert_eq!(refused.refusal().0, "operator_key");
	// A's coin is not spent by the refusal: it pays B.
	let (b_leaf, _) = new_leaf(&keypair("B"));
	let body = transfer_body(&[(&a_held, a_valid, kept)], &[(x, kept - MARGIN, b_leaf)], s, r.chain);
	assert_eq!(r.http.post("cosign_transfer", &body).status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_participation_wanting_a_leaf_owned_by_s_is_refused() {
	let mut r = start().await;
	let x = r.x;
	let a = keypair("A");
	let (a_held, _) = credited_board(&mut r, &a, x).await;
	let (w, _) = want_leaf(&r.s, x, VALUE);
	let (body, _) = participation_body(&[&a_held], &[w], &[], None, xonly(&r.s), r.chain);
	let refused = r.http.post("submit_participation", &body);
	assert_eq!(refused.status, 422, "{}", refused.json);
	assert_eq!(refused.refusal().0, "operator_key");
	// The coin is still A's to give up.
	let (w, _) = want_leaf(&keypair("A new"), x, VALUE);
	let (body, _) = participation_body(&[&a_held], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
}
