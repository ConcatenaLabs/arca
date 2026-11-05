//! When the server's own loop over the rounds acts, with no pass run by
//! hand: a held round goes out as soon as its last forfeit is in, not at the
//! next chain event or round interval; and a final round is checked again
//! for every event that can take its finality away, while a pass reads only
//! the final rounds the store no longer places final.
//!
//! 1. A round held for its forfeits stays built while one of its two
//!    participations has not handed its forfeit over, and is broadcast
//!    within seconds of the last, with the finality service polling every
//!    two minutes and no round interval.
//! 2. A round final and credited, in a Sequentia block anchored to a Bitcoin
//!    block of its own. The parent chain reorganises that block away: the
//!    Sequentia blocks anchored to it go out of the chain, the round's new
//!    leaf is uncredited at once and the round is broadcast again. Mined
//!    again it is in the chain but not final (its anchor not yet buried) and
//!    its leaf stays uncredited; buried, it is final and credited again.
//!    Then a disconnection the rounds never heard of (the round put back to
//!    final and its leaf credited by hand while its block is out of the
//!    chain) is found by the next pass, which reads the final rounds the
//!    store no longer places final, and the leaf is uncredited again.
//! 3. The same for a board: credited by hand while its block is out of the
//!    chain, it is uncredited by the next pass over the boards.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::time::{Duration, Instant};

use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::Txid;
use serde_json::{json, Value};

use common::client::{auths_json, forfeit_sig, hex, made, participation_body, want_leaf, Held};
use common::flow::forfeit_for;
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{created, credited_board, hand_over, start, status, validate_new_leaf, VALUE};
use common::running::Running;
use server::store::RoundState;

fn participate(r: &Running, old: &Held, new_key: &Keypair) -> ([u8; 32], [u8; 32]) {
	let (w, nonce) = want_leaf(new_key, r.x, VALUE);
	let (body, id) = participation_body(&[old], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	(id, nonce)
}

/// The state of `key`'s one leaf, as `leaf_data` reports it.
fn leaf_state(r: &Running, key: &Keypair) -> String {
	let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", key, &r.chain)})).ok();
	ld["leaves"][0]["state"].as_str().unwrap_or("").to_string()
}

async fn round_row_state(r: &Running, txid: &Txid) -> Option<RoundState> {
	r.server.store.round_by_txid(&txid.to_byte_array()).await.unwrap().map(|x| x.state)
}

/// Waits, without running a pass by hand, until `f` holds.
async fn until<F: FnMut() -> bool>(what: &str, secs: u64, mut f: F) -> Duration {
	let start = Instant::now();
	while !f() {
		assert!(start.elapsed() < Duration::from_secs(secs), "{} within {} s", what, secs);
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	start.elapsed()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_held_round_goes_out_when_its_last_forfeit_is_in() {
	let mut r = Running::start_with(|c, _| c.batches.no_sweep = true).await;
	let x = r.x;
	r.fund_wallet_in(x, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let (a, b) = (keypair("W A"), keypair("W B"));
	let (ab, _) = credited_board(&mut r, &a, x).await;
	let (bb, _) = credited_board(&mut r, &b, x).await;
	// From here the finality service polls every two minutes and no round
	// interval runs: a pass comes from a chain event at most every two
	// minutes, or from a wake.
	r.config.finality.poll_interval_ms = 120_000;
	r.restart_server().await;
	let (pa, _) = participate(&r, &ab, &keypair("W A new"));
	let (pb, _) = participate(&r, &bb, &keypair("W B new"));
	let built = r.server.rounds.run_round().await.unwrap().expect("a round");
	let txid = built.tx.txid();
	assert!(built.broadcast.starts_with("held"), "{}", built.broadcast);
	hand_over(&r, &pa, &made(&pa).unwrap()).await;
	tokio::time::sleep(Duration::from_secs(5)).await;
	let rt = &r.rt;
	assert!(!node::in_mempool(rt, &txid), "the round waits for B's forfeit");
	assert_eq!(round_row_state(&r, &txid).await, Some(RoundState::Built));
	println!("A's forfeit in: round {} still built 5 s later, B's forfeit missing", txid);
	let t = Instant::now();
	hand_over(&r, &pb, &made(&pb).unwrap()).await;
	let took = until("the round to reach the node", 15, || node::in_mempool(rt, &txid)).await;
	println!("B's forfeit in: round {} in the node's mempool {} ms later ({} ms after the forfeit was posted)", txid, took.as_millis(),
		t.elapsed().as_millis());
	assert_eq!(round_row_state(&r, &txid).await, Some(RoundState::Broadcast));
	assert_eq!(status(&r, &pb)["state"], "issued");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_credited_round_whose_anchor_is_orphaned_is_uncredited_and_credited_again_once_final() {
	let mut r = start().await;
	let (a, x) = (keypair("O A"), r.x);
	let (a_board, a_tx) = credited_board(&mut r, &a, x).await;
	// A parent block of the round's own, so the reorganisation that orphans
	// it takes out the round's block and what follows.
	r.rt.mine_parent(1).unwrap();
	r.rt.anchor_to_parent_tip().unwrap();
	let parent_height = {
		let tip = r.rt.client().best_block_hash().unwrap();
		sequentia_ext::BlockHeaderExt::bitcoin_anchor(&r.rt.client().block_header(&tip).unwrap()).height as u64
	};
	let a2 = keypair("O A, new");
	let (pa, a2_nonce) = participate(&r, &a_board, &a2);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let txid = built.tx.txid();
	common::rounds::send_held(&r, &txid).await;
	r.produce().await;
	r.bury().await;
	let http = r.http.clone();
	let t = txid.to_byte_array();
	let start_final = Instant::now();
	while round_row_state(&r, &txid).await != Some(RoundState::Final) {
		assert!(start_final.elapsed() < Duration::from_secs(60), "the round final within 60 s");
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	let st = status(&r, &pa);
	let (a2_valid, a2_record, round) = validate_new_leaf(&r, &pa, 0, &a2, &a2_nonce);
	if st["state"] != "released" {
		let a_old = a_board.record.resolve(std::slice::from_ref(&a_tx), &r.policy()).unwrap();
		let f = forfeit_for(&a_old, &a2_valid, &round, &st);
		let done = http.post("forfeit_leaves", &json!({"participation_id": hex(&pa),
			"forfeits": [{"leaf_id": a_board.id.to_string(), "signature": forfeit_sig(&f, &a)}],
			"leaves": [auths_json(&a2_valid, &a2, created(&a2_record))]})).ok();
		assert_eq!(done["state"], "released", "{}", done);
	}
	assert_eq!(leaf_state(&r, &a2), "live");
	println!("round {} final in a block anchored to parent height {}; A2 live", txid, parent_height);

	// Bitcoin reorganises the round's anchor away.
	let orphaned = tokio::task::block_in_place(|| r.rt.orphan_parent_from(parent_height)).unwrap();
	let rr = &r;
	let took = until("A2 to be uncredited", 60, || leaf_state(rr, &a2) == "pending").await;
	println!("parent blocks {}..{} orphaned ({}): A2 uncredited {} ms after the node anchored to the new branch", parent_height,
		parent_height + orphaned.len() as u64 - 1, orphaned.len(), took.as_millis());
	assert_eq!(round_row_state(&r, &txid).await, Some(RoundState::Broadcast));
	let rt = &r.rt;
	until("the round back in the node's mempool", 60, || node::in_mempool(rt, &txid)).await;

	// Mined again, in a block whose anchor is not yet buried: in the chain,
	// not final, and A2 stays uncredited.
	r.produce().await;
	r.synced().await;
	tokio::time::sleep(Duration::from_secs(3)).await;
	let f = r.server.rounds.finality().status(&txid).await.unwrap();
	assert!(f.in_chain() && !f.is_final(), "{:?}", f);
	assert_eq!(leaf_state(&r, &a2), "pending", "never credited before the round is final");
	assert_eq!(round_row_state(&r, &txid).await, Some(RoundState::Broadcast));
	println!("mined again: {:?}; A2 still {}", f, leaf_state(&r, &a2));
	r.bury().await;
	let took = until("A2 to be credited again", 60, || leaf_state(rr, &a2) == "live").await;
	assert_eq!(round_row_state(&r, &txid).await, Some(RoundState::Final));
	println!("buried: round final again, A2 live {} ms after the anchor was buried", took.as_millis());

	// A disconnection the rounds never heard of: the round's block out of the
	// chain, then the round put back to final and its leaf credited by hand,
	// as if the event had been missed. The next pass finds it.
	let block: Value = r.rt.client().call("getrawtransaction", &[json!(txid.to_string()), json!(true)]).unwrap();
	let block: elements::BlockHash = block["blockhash"].as_str().unwrap().parse().unwrap();
	node::invalidate(&r.rt, &block);
	until("A2 to be uncredited", 60, || leaf_state(rr, &a2) == "pending").await;
	// A pass between the two puts the round back to broadcast before its
	// leaf is credited (a final round is credited, no other): then again.
	let row = r.server.store.round_by_txid(&t).await.unwrap().unwrap();
	let mut tries = 0;
	loop {
		tries += 1;
		assert!(tries <= 20, "the round set final and its leaf credited by hand");
		r.server.store.set_round_state(row.round_id, RoundState::Broadcast, RoundState::Final).await.unwrap();
		if r.server.store.credit_round(row.round_id).await.unwrap() > 0 {
			break;
		}
	}
	let took = until("the next pass to find the round no longer final", 30, || leaf_state(rr, &a2) == "pending").await;
	assert_eq!(round_row_state(&r, &txid).await, Some(RoundState::Broadcast));
	println!("a missed disconnection: the round set final and A2 credited by hand while out of the chain; uncredited by the next pass {} ms later",
		took.as_millis());
}

/// The boards' pass reads the credited boards the store no longer places
/// final, in one statement: a board uncredited by a disconnection, then
/// credited again by hand while its block is out of the chain (as if the
/// event had been missed), is uncredited by the next pass.
#[tokio::test(flavor = "multi_thread")]
async fn a_credited_board_out_of_the_chain_is_found_by_the_next_pass() {
	let mut r = start().await;
	let x = r.x;
	let (held, tx) = credited_board(&mut r, &keypair("BD A"), x).await;
	let id = held.id;
	let http = r.http.clone();
	assert_eq!(http.board_status(&id).json["state"], "credited");
	let block: Value = r.rt.client().call("getrawtransaction", &[json!(tx.txid().to_string()), json!(true)]).unwrap();
	let block: elements::BlockHash = block["blockhash"].as_str().unwrap().parse().unwrap();
	node::invalidate(&r.rt, &block);
	let took = until("the board to be uncredited", 60, || http.board_status(&id).json["state"] == "pending").await;
	println!("board {} uncredited {} ms after its block was invalidated", id, took.as_millis());
	assert!(r.server.store.credit_board(&id.0).await.unwrap(), "credited by hand");
	let took = until("the next pass to find the board no longer final", 30, || http.board_status(&id).json["state"] == "pending").await;
	println!("a missed disconnection: board {} credited by hand while out of the chain; uncredited by the next pass {} ms later",
		id, took.as_millis());
}
