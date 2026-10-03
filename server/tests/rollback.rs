//! Rounds and rollbacks, against a whole server on an anchored
//! proof-of-stake regtest chain (`invalidateblock` standing in for an anchor
//! rollback):
//!
//! 1. A final round disconnected: its new leaves are uncredited at once (a
//!    transfer of one is refused), the server broadcasts the same bytes
//!    again to a node that forgot them, the round returns with its txid and
//!    is credited again, and the leaf is paid on.
//! 2. A round that can never return, the operator's coin it spent taken by
//!    another transaction that becomes final: the round is retired, its new
//!    leaves lost, and its participations run again in a new round under new
//!    unlock hashes. The one whose preimage had gone out (giving up a leaf of
//!    an earlier round, whose lowest node its owner had released) runs
//!    forfeit-first: its release is retired, its forfeit for the new round is
//!    taken and its preimage withheld; the one whose preimage had not runs as
//!    before. The coins they gave up stay given up. No release is taken while
//!    a round is not final.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::{BlockHash, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::{CoinRecord, Forfeit, LeafId, RelativeTime, Release, ValidCoin, ValidLeaf};
use common::client::{auths_json, forfeit_sig, hex, new_leaf, participation_body, transfer_body, unhex, want_leaf, Answer, Held};
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{created, credited_board, round_final, round_state, spend_wallet_coin, start, status, validate_new_leaf, VALUE};
use common::running::Running;
use server::store::RoundState;

fn refused(a: Answer, status: i32, code: &str) {
	let (c, m) = a.refusal();
	assert_eq!((a.status, c.as_str()), (status, code), "{}", a.json);
	println!("refused {} {}: {}", status, code, m);
}

fn forfeit_for(old: &ValidCoin, new: &ValidLeaf, round: &Transaction, st: &Value) -> Forfeit {
	let c = st["round"]["connector_vout"].as_u64().unwrap() as u32;
	let delay = RelativeTime::from_units(st["refund_delay_units"].as_u64().unwrap() as u16).unwrap();
	let margin: u64 = st["inputs"][0]["margin"].as_str().unwrap().parse().unwrap();
	Forfeit::for_refresh(old.leaf, (old.asset, old.value), old.id, new, round, c, delay, margin).unwrap()
}

fn forfeit_body(id: &[u8; 32], old: LeafId, sig: String, auths: Value) -> Value {
	json!({"participation_id": hex(id), "forfeits": [{"leaf_id": old.to_string(), "signature": sig}], "leaves": [auths]})
}

fn participate(r: &Running, old: &Held, new_key: &Keypair) -> ([u8; 32], [u8; 32]) {
	let (w, nonce) = want_leaf(new_key, r.x, VALUE);
	let (body, id) = participation_body(&[old], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	(id, nonce)
}

/// The states of `key`'s leaves, as `leaf_data` reports them, sorted.
fn leaf_states(r: &Running, key: &Keypair) -> Vec<String> {
	let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", key, &r.chain)})).ok();
	let mut states: Vec<String> = ld["leaves"].as_array().unwrap().iter().map(|l| l["state"].as_str().unwrap().to_string()).collect();
	states.sort();
	states
}

/// The block that holds `txid`.
fn block_of(r: &Running, txid: &Txid) -> BlockHash {
	let v: Value = r.rt.client().call("getrawtransaction", &[json!(txid.to_string()), json!(true)]).unwrap();
	v["blockhash"].as_str().unwrap().parse().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_round_disconnected_returns_and_is_credited_again() {
	let mut r = start().await;
	let (a, x) = (keypair("A"), r.x);
	let (a_board, a_tx) = credited_board(&mut r, &a, x).await;
	let a2 = keypair("A, new");
	let (pa, a2_nonce) = participate(&r, &a_board, &a2);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let round_txid = built.tx.txid();
	r.produce().await;
	r.bury().await;
	round_final(&r, &round_txid).await;
	let st = status(&r, &pa);
	let (a2_valid, a2_record, round) = validate_new_leaf(&r, &pa, 0, &a2, &a2_nonce);
	let a_old = a_board.record.resolve(std::slice::from_ref(&a_tx), &r.policy()).unwrap();
	let f = forfeit_for(&a_old, &a2_valid, &round, &st);
	let done = r.http.post("forfeit_leaves", &forfeit_body(&pa, a_board.id, forfeit_sig(&f, &a), auths_json(&a2_valid, &a2, created(&a2_record)))).ok();
	assert_eq!(done["state"], "released");
	assert_eq!(leaf_states(&r, &a2), vec!["live"]);

	// A2 is ready to pay B.
	let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", &a2, &r.chain)})).ok();
	let a2_held = Held { key: a2, nonce: a2_nonce, id: a2_valid.leaf_id, record: CoinRecord::from_bytes(&unhex(ld["leaves"][0]["record"].as_str().unwrap())).unwrap() };
	let a2_coin = a2_held.record.resolve(std::slice::from_ref(&round), &r.policy()).unwrap();
	let (b_leaf, b_nonce) = new_leaf(&keypair("B"));
	let pay = transfer_body(&[(&a2_held, a2_coin, VALUE - 2_000)], &[(r.x, VALUE - 4_000, b_leaf)], xonly(&r.s), r.chain);

	// The rollback: the round's block disconnected, the node restarted with
	// an empty mempool, as a node that never saw the round.
	node::invalidate(&r.rt, &block_of(&r, &round_txid));
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0"])).unwrap();
	let http = r.http.clone();
	let chain = r.chain;
	r.wait("A2 to be uncredited", || {
		let ld = http.post("leaf_data", &json!({"auth": http.auth("leaf_data", &a2, &chain)})).ok();
		ld["leaves"][0]["state"] == "pending"
	}).await;
	round_state(&r, &round_txid, RoundState::Broadcast).await;
	println!("after the rollback: round {} broadcast, A2 {:?}", round_txid, leaf_states(&r, &a2));
	refused(r.http.post("cosign_transfer", &pay), 422, "not_live");
	// No release is taken while the round is not final.
	refused(r.http.post("release_leaves", &json!({"participation_id": hex(&pa),
		"releases": [{"leaf_id": a_board.id.to_string(), "signature": hex(&[1; 64])}]})), 422, "round_not_final");
	// The same forfeit request again: the round is not final, nothing changes.
	let rt = &r.rt;
	r.wait("the server to broadcast the round again", || node::in_mempool(rt, &round_txid)).await;
	let again: Transaction = r.rt.client().raw_transaction(&round_txid).unwrap();
	assert_eq!(elements::encode::serialize(&again), elements::encode::serialize(&built.tx), "the same bytes, the same txid");
	let row = r.server.store.nursery_get(&round_txid.to_byte_array()).await.unwrap().unwrap();
	println!("the nursery broadcast the round {} times; last: {:?}", row.broadcasts, row.last_result);
	r.produce().await;
	r.bury().await;
	round_final(&r, &round_txid).await;
	r.wait("A2 to be credited again", || {
		let ld = http.post("leaf_data", &json!({"auth": http.auth("leaf_data", &a2, &chain)})).ok();
		ld["leaves"][0]["state"] == "live"
	}).await;
	println!("the round is final again with its txid, A2 {:?}", leaf_states(&r, &a2));
	let paid = r.http.post("cosign_transfer", &pay).ok();
	let b_record = CoinRecord::from_bytes(&unhex(paid["outputs"][0]["record"].as_str().unwrap())).unwrap();
	b_record.validate(std::slice::from_ref(&round), &r.policy(), &xonly(&keypair("B")), &b_nonce).unwrap();
	println!("A2 paid on to B once credited again; B validated it against the same round");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_round_that_cannot_return_runs_again_forfeit_first() {
	let mut r = start().await;
	let x = r.x;
	let (a0, b) = (keypair("A, board"), keypair("B"));
	let (a0_board, a0_tx) = credited_board(&mut r, &a0, x).await;
	let (b_board, b_tx) = credited_board(&mut r, &b, x).await;

	// Round 0 gives A a batch leaf, the coin A refreshes below.
	let a = keypair("A");
	let (p0, a_nonce) = participate(&r, &a0_board, &a);
	let built0 = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built0.tx.txid()).await;
	let (a_valid0, a_record0, round0) = validate_new_leaf(&r, &p0, 0, &a, &a_nonce);
	let a0_old = a0_board.record.resolve(std::slice::from_ref(&a0_tx), &r.policy()).unwrap();
	let f0 = forfeit_for(&a0_old, &a_valid0, &round0, &status(&r, &p0));
	r.http.post("forfeit_leaves", &forfeit_body(&p0, a0_board.id, forfeit_sig(&f0, &a0), auths_json(&a_valid0, &a, created(&a_record0)))).ok();
	let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", &a, &r.chain)})).ok();
	let a_board = Held { key: a, nonce: a_nonce, id: a_valid0.leaf_id, record: CoinRecord::from_bytes(&unhex(ld["leaves"][0]["record"].as_str().unwrap())).unwrap() };
	let a_tx = round0;

	let (a2, b2) = (keypair("A, new"), keypair("B, new"));
	let (pa, a2_nonce) = participate(&r, &a_board, &a2);
	let (pb, b2_nonce) = participate(&r, &b_board, &b2);

	// Round R: A completes its forfeit and holds R's preimage; B does not.
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let lost_txid = built.tx.txid();
	r.produce().await;
	r.bury().await;
	round_final(&r, &lost_txid).await;
	let st_r = status(&r, &pa);
	let (a2_r, a2_r_record, round_r) = validate_new_leaf(&r, &pa, 0, &a2, &a2_nonce);
	let a_old = a_board.record.resolve(std::slice::from_ref(&a_tx), &r.policy()).unwrap();
	let b_old = b_board.record.resolve(std::slice::from_ref(&b_tx), &r.policy()).unwrap();
	let f_r = forfeit_for(&a_old, &a2_r, &round_r, &st_r);
	let done = r.http.post("forfeit_leaves", &forfeit_body(&pa, a_board.id, forfeit_sig(&f_r, &a), auths_json(&a2_r, &a2, created(&a2_r_record)))).ok();
	let r_preimage = done["preimage"].as_str().unwrap().to_string();
	assert_eq!(status(&r, &pb)["state"], "issued");
	// A, holding R's preimage, releases the lowest node of its old leaf.
	let lowest = a_valid0.branch.nodes.last().unwrap();
	let c_r = st_r["round"]["connector_vout"].as_u64().unwrap() as u32;
	let release = Release::for_refresh(&a_valid0, &a2_r, &round_r, c_r).unwrap().message().digest;
	let rel = r.http.post("release_leaves", &json!({"participation_id": hex(&pa), "releases": [{"leaf_id": a_board.id.to_string(),
		"signature": hex(arca_covenant::sign::sign_digest(&a, &release, &common::client::random32()).as_ref())}]})).ok();
	assert_eq!(rel["released"].as_array().unwrap().len(), 1);
	assert_eq!(r.server.store.releases(&lowest.children_hash()).await.unwrap().len(), 1);

	// The rollback, the server stopped meanwhile: the round's block
	// disconnected, and the operator's coin it spent taken by another
	// transaction, which becomes final. R can never return.
	r.server.stop();
	let w = built.tx.input[0].previous_output;
	let w_out = r.rt.client().raw_transaction(&w.txid).unwrap().output[w.vout as usize].clone();
	node::invalidate(&r.rt, &block_of(&r, &lost_txid));
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0"])).unwrap();
	let elsewhere = spend_wallet_coin(w, &w_out, vec![], 2_000);
	r.rt.client().send_raw_transaction(&elsewhere).unwrap();
	r.produce().await;
	r.bury().await;
	println!("R's input {} spent elsewhere by {}, buried", w, elsewhere.txid());
	r.restart_server().await;
	round_state(&r, &lost_txid, RoundState::Lost).await;
	let row = r.server.store.nursery_get(&lost_txid.to_byte_array()).await.unwrap().unwrap();
	println!("round R is lost: the nursery says {:?} after {} broadcasts, last {:?}", row.state, row.broadcasts, row.last_result);
	assert_eq!(leaf_states(&r, &a2), vec!["lost"]);
	assert_eq!(leaf_states(&r, &b2), vec!["lost"]);
	// The release A gave on the strength of R is retired, never to be used.
	assert!(r.server.store.releases(&lowest.children_hash()).await.unwrap().is_empty());

	// Both participations run again, under new unlock hashes; A forfeit-first.
	let sa = status(&r, &pa);
	let sb = status(&r, &pb);
	println!("A after the loss: {}", sa);
	assert_eq!((sa["state"].as_str(), sa["attempt"].as_u64(), sa["forfeit_first"].as_bool()), (Some("pending"), Some(1), Some(true)));
	assert_eq!((sb["state"].as_str(), sb["attempt"].as_u64(), sb["forfeit_first"].as_bool()), (Some("pending"), Some(1), Some(false)));
	assert_ne!(sa["unlock_hash"], st_r["unlock_hash"]);
	assert_ne!(sa["outputs"][0]["operator_nonce"], st_r["outputs"][0]["operator_nonce"], "a new operator nonce: a new leaf script");
	// The coins they gave up stay given up: no other off-chain spend of them.
	let (c_leaf, _) = new_leaf(&keypair("C"));
	let spend_a = transfer_body(&[(&a_board, a_old.clone(), VALUE - 2_000)], &[(x, VALUE - 4_000, c_leaf)], xonly(&r.s), r.chain);
	refused(r.http.post("cosign_transfer", &spend_a), 409, "double_spend");

	// Round Y: new leaves under the same keys and owner nonces.
	let built_y = r.server.rounds.run_round().await.unwrap().unwrap();
	assert_eq!(built_y.participations, 2);
	r.produce().await;
	r.bury().await;
	round_final(&r, &built_y.tx.txid()).await;
	let (a2_y, a2_y_record, round_y) = validate_new_leaf(&r, &pa, 0, &a2, &a2_nonce);
	assert_ne!(a2_y.leaf_id, a2_r.leaf_id);
	assert_eq!(a2_r_record.validate_round(&round_y, &common::rounds::accept_policy(&r)).unwrap_err(),
		arca_covenant::RecordError::BatchOutputMissing, "R's leaf is not in Y");
	// B, which never had R's preimage, completes as before.
	let st_b = status(&r, &pb);
	let (b2_y, b2_y_record, _) = validate_new_leaf(&r, &pb, 0, &b2, &b2_nonce);
	let fb = forfeit_for(&b_old, &b2_y, &round_y, &st_b);
	let done_b = r.http.post("forfeit_leaves", &forfeit_body(&pb, b_board.id, forfeit_sig(&fb, &b), auths_json(&b2_y, &b2, created(&b2_y_record)))).ok();
	assert_eq!(done_b["state"], "released");
	assert!(done_b["preimage"].is_string());
	// A's forfeit for R does not verify for Y.
	let st_a = status(&r, &pa);
	let a_auths = auths_json(&a2_y, &a2, created(&a2_y_record));
	refused(r.http.post("forfeit_leaves", &forfeit_body(&pa, a_board.id, forfeit_sig(&f_r, &a), a_auths.clone())), 422, "bad_forfeit");
	// A's forfeit for Y: taken, the preimage withheld.
	let f_y = forfeit_for(&a_old, &a2_y, &round_y, &st_a);
	let body = forfeit_body(&pa, a_board.id, forfeit_sig(&f_y, &a), a_auths);
	let done_a = r.http.post("forfeit_leaves", &body).ok();
	println!("A's forfeit for Y: {}", done_a);
	assert_eq!((done_a["state"].as_str(), done_a["forfeit_first"].as_bool()), (Some("issued"), Some(true)));
	assert!(done_a.get("preimage").is_none(), "forfeit-first: no preimage until the forfeit is claimed");
	assert_eq!(r.http.post("forfeit_leaves", &body).ok(), done_a, "the same again");
	assert_eq!(r.server.store.forfeits(&pa, built_y.round_id).await.unwrap().len(), 1, "the forfeit for Y is held");
	assert_eq!(leaf_states(&r, &a2), vec!["lost", "pending"]);
	// No release before the preimage.
	refused(r.http.post("release_leaves", &json!({"participation_id": hex(&pa),
		"releases": [{"leaf_id": a_board.id.to_string(), "signature": hex(&[1; 64])}]})), 422, "release_early");
	println!("A ran again forfeit-first: R's preimage {} is useless, Y's withheld", &r_preimage[..16]);
}
