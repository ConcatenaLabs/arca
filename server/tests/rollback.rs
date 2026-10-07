//! Rounds and rollbacks, against a whole server on an anchored
//! proof-of-stake regtest chain (`invalidateblock` standing in for an anchor
//! rollback):
//!
//! 1. A final round disconnected: its new leaves are uncredited at once (a
//!    transfer of one is refused), the server broadcasts the same bytes
//!    again to a node that forgot them, the round returns with its txid and
//!    is credited again, and the leaf is paid on.
//! 2. A round that is lost, the operator's coin it spent taken by
//!    another transaction that becomes final: the round is retired, its new
//!    leaves lost, and its participations run again in a new round under new
//!    unlock hashes, as ordinary participations, the one whose preimage had
//!    gone out (giving up a leaf of an earlier round, whose lowest node its
//!    owner had released) as well: its release is retired, and its forfeit
//!    for the new round is taken and its new preimage released against it.
//!    The coins they gave up stay given up. No release is taken while a round
//!    is not final. The release, which named the lost round's connector
//!    asset, is void on the chain as well: that asset can no longer be
//!    issued, and the reclaim of the old node with the release and the new
//!    round's connector asset is refused. One that never hands over its
//!    forfeit for the new round expires, and its coin, whose only forfeit is
//!    for the lost round and was never published, is given back. An exit of
//!    an old coin after its re-run completed is answered with its forfeit
//!    for the new round, which the operator claims.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::{BlockHash, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::spend::FeeSource;
use arca_covenant::{
	connector_asset, CoinRecord, ConnectorPolicy, ExplicitOutput, Forfeit, LeafId, RelativeTime, Release, TapOutput, ValidCoin,
	ValidLeaf,
};
use common::client::{auths_json, forfeit_sig, hex, new_leaf, participation_body, transfer_body, unhex, want_leaf, Answer, Held};
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{
	advance_mtp, created, credited_board, round_final, round_state, spend_wallet_coin, start, status, validate_new_leaf, VALUE,
};
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

/// The preimage each leaf record `leaf_data` serves `key` carries, by the
/// leaf's state: `None` for a record served empty or holding no preimage.
fn served_preimages(r: &Running, key: &Keypair) -> Vec<(String, Option<[u8; 32]>)> {
	let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", key, &r.chain)})).ok();
	ld["leaves"].as_array().unwrap().iter().map(|l| {
		let bytes = unhex(l["record"].as_str().unwrap());
		let preimage = if bytes.is_empty() { None } else {
			match arca_covenant::CoinRecord::from_bytes(&bytes).unwrap() {
				arca_covenant::CoinRecord::Leaf { preimage, .. } => Some(preimage),
				_ => None,
			}
		};
		(l["state"].as_str().unwrap().to_string(), preimage)
	}).collect()
}

/// A coin anyone can spend through a tapscript of `OP_TRUE`.
fn op_true_tap() -> TapOutput {
	TapOutput::new(vec![(0, elements::Script::from(vec![0x51]))])
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
		"releases": [{"leaf_id": a_board.id.to_string(), "connector_asset": "0000000000000000000000000000000000000000000000000000000000000000", "signature": hex(&[1; 64])}]})), 422, "round_not_final");
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
async fn a_round_that_cannot_return_runs_its_participations_again_as_ordinary_ones() {
	let mut r = start().await;
	let x = r.x;
	let (a0, b) = (keypair("A, board"), keypair("B"));
	let (a0_board, a0_tx) = credited_board(&mut r, &a0, x).await;
	let (b_board, b_tx) = credited_board(&mut r, &b, x).await;
	let c = keypair("C");
	let (c_board, c_tx) = credited_board(&mut r, &c, x).await;

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
	let c2 = keypair("C, new");
	let (pc, c2_nonce) = participate(&r, &c_board, &c2);

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
	// C completes in R as well.
	let st_c = status(&r, &pc);
	let (c2_r, c2_r_record, _) = validate_new_leaf(&r, &pc, 0, &c2, &c2_nonce);
	let c_old = c_board.record.resolve(std::slice::from_ref(&c_tx), &r.policy()).unwrap();
	let fc = forfeit_for(&c_old, &c2_r, &round_r, &st_c);
	let done_c = r.http.post("forfeit_leaves", &forfeit_body(&pc, c_board.id, forfeit_sig(&fc, &c), auths_json(&c2_r, &c2, created(&c2_r_record)))).ok();
	assert_eq!(done_c["state"], "released");
	// A, holding R's preimage, releases the lowest node of its old leaf.
	let lowest = a_valid0.branch.nodes.last().unwrap();
	let c_r = st_r["round"]["connector_vout"].as_u64().unwrap() as u32;
	let a_release = Release::for_refresh(&a_valid0, &a2_r, &round_r, c_r).unwrap();
	let m_r = a_release.connector;
	let a_release_sig = arca_covenant::sign::sign_digest(&a, &a_release.message().digest, &common::client::random32());
	let rel = r.http.post("release_leaves", &json!({"participation_id": hex(&pa), "releases": [{"leaf_id": a_board.id.to_string(),
		"connector_asset": m_r.to_string(), "signature": hex(a_release_sig.as_ref())}]})).ok();
	assert_eq!(rel["released"].as_array().unwrap().len(), 1);
	assert_eq!(r.server.store.releases(&lowest.children_hash()).await.unwrap().len(), 1);

	// The rollback, the server stopped meanwhile: the round's block
	// disconnected, and the operator's coin it spent taken by another
	// transaction, which becomes final. R is lost.
	r.server.stop();
	let w = built.tx.input[0].previous_output;
	let w_out = r.rt.client().raw_transaction(&w.txid).unwrap().output[w.vout as usize].clone();
	node::invalidate(&r.rt, &block_of(&r, &lost_txid));
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0"])).unwrap();
	// Most of it back to the operator: a re-run spends that output, which
	// keeps it apart from R should R return.
	let (_, to) = server::wallet::Wallet::hand_out_receive_script(&r.db.store, common::keys::MNEMONIC).await.unwrap();
	let back = sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(w_out.asset.explicit().unwrap(),
		w_out.value.explicit().unwrap() - 3_000), to);
	let elsewhere = spend_wallet_coin(w, &w_out, vec![back], 2_000);
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

	// Every participation runs again, under a new unlock hash, as an
	// ordinary one, A's as well, whose preimage had gone out.
	let sa = status(&r, &pa);
	let sb = status(&r, &pb);
	println!("A after the loss: {}", sa);
	assert_eq!((sa["state"].as_str(), sa["attempt"].as_u64()), (Some("pending"), Some(1)));
	assert_eq!((sb["state"].as_str(), sb["attempt"].as_u64()), (Some("pending"), Some(1)));
	assert!(sa.get("forfeit_first").is_none() && sa["void_reason"].is_null());
	assert_ne!(sa["unlock_hash"], st_r["unlock_hash"]);
	assert_ne!(sa["outputs"][0]["operator_nonce"], st_r["outputs"][0]["operator_nonce"], "a new operator nonce: a new leaf script");
	// The coins they gave up stay given up: no other off-chain spend of them.
	let (c_leaf, _) = new_leaf(&keypair("C"));
	let spend_a = transfer_body(&[(&a_board, a_old.clone(), VALUE - 2_000)], &[(x, VALUE - 4_000, c_leaf)], xonly(&r.s), r.chain);
	refused(r.http.post("cosign_transfer", &spend_a), 409, "double_spend");

	// Round Y: new leaves under the same keys and owner nonces.
	let built_y = r.server.rounds.run_round().await.unwrap().unwrap();
	assert_eq!(built_y.participations, 3);
	r.produce().await;
	r.bury().await;
	round_final(&r, &built_y.tx.txid()).await;
	let (a2_y, a2_y_record, round_y) = validate_new_leaf(&r, &pa, 0, &a2, &a2_nonce);
	assert_ne!(a2_y.leaf_id, a2_r.leaf_id);
	assert_eq!(a2_r_record.validate_round(&round_y, &common::rounds::accept_policy(&r)).unwrap_err(),
		arca_covenant::RecordError::BatchOutputMissing, "R's leaf is not in Y");
	// On the chain, A's release for R is void. A's old node (round 0's batch
	// output, its lowest node) is unspent; R's connector asset cannot be
	// issued; with an atom of Y's, the release does not verify.
	let lowest_at = elements::OutPoint::new(built0.tx.txid(), 0);
	assert!(r.unspent(&lowest_at));
	let op = xonly(&r.s);
	let issue = |round: &Transaction, c: u32| -> Transaction {
		let conn = elements::OutPoint::new(round.txid(), c);
		let out = &round.output[c as usize];
		let ks = ConnectorPolicy { operator: op }.issuance(conn, (out.asset.explicit().unwrap(), out.value.explicit().unwrap()),
			op_true_tap().script_pubkey(), &[], &FeeSource::Reserve).unwrap();
		let sg = arca_covenant::sign::sign_digest(&r.s, &ks.sighash(r.chain.genesis_hash()).unwrap(), &common::client::random32());
		ks.finish(vec![sg.as_ref().to_vec()]).tx
	};
	let refused_by_node = |what: &str, tx: &Transaction, why: &str| {
		let a = r.rt.client().test_mempool_accept(&[tx]).unwrap().remove(0);
		let reason = a.reject_reason.unwrap_or_default();
		assert!(!a.allowed && reason.contains(why), "{}: {:?}", what, reason);
		println!("refused by the node, {}: {}", what, reason);
	};
	refused_by_node("the issuance of R's connector asset", &issue(&built.tx, c_r), "missing-inputs");
	let cy = status(&r, &pa)["round"]["connector_vout"].as_u64().unwrap() as u32;
	let issue_y = issue(&built_y.tx, cy);
	r.rt.client().send_raw_transaction(&issue_y).unwrap();
	r.produce().await;
	let m_y = connector_asset(built_y.tx.txid(), cy);
	assert_ne!(m_y, m_r);
	let atom = (elements::OutPoint::new(issue_y.txid(), 0), issue_y.output[0].clone());
	let lowest0 = a_valid0.branch.nodes.last().unwrap();
	let reclaim = |atoms: &[(elements::OutPoint, elements::TxOut)]| -> Transaction {
		let ks = lowest0.reclaim_tx(lowest_at, atoms, &[ExplicitOutput::new(x, lowest0.value - 2_000, op_true_tap().script_pubkey())],
			op_true_tap().script_pubkey(), &FeeSource::Reserve).unwrap();
		let sg = arca_covenant::sign::sign_digest(&r.s, &ks.sighash(r.chain.genesis_hash()).unwrap(), &common::client::random32());
		let mut u = ks.finish(arca_covenant::node::reclaim_items(&sg, &[(a_release_sig, 1)], 1).unwrap());
		for i in 1..u.tx.input.len() {
			u.tx.input[i].witness.script_witness = op_true_tap().witness(&elements::Script::from(vec![0x51]), vec![]);
		}
		u.tx
	};
	refused_by_node("the reclaim of A's old node with its release for R and Y's connector asset", &reclaim(std::slice::from_ref(&atom)),
		"Invalid Schnorr signature");
	refused_by_node("the reclaim of A's old node with its release for R and no connector asset", &reclaim(&[]),
		"Introspection index out of bounds");
	assert!(r.unspent(&lowest_at), "A's old node is still A's");

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
	// No release before the preimage, and no answer carries Y's preimage
	// before A's forfeit for Y: `leaf_data` serves A's pending leaf of Y
	// with an empty record.
	refused(r.http.post("release_leaves", &json!({"participation_id": hex(&pa),
		"releases": [{"leaf_id": a_board.id.to_string(), "connector_asset": "0000000000000000000000000000000000000000000000000000000000000000", "signature": hex(&[1; 64])}]})), 422, "release_early");
	let y_hash: [u8; 32] = unhex(st_a["unlock_hash"].as_str().unwrap()).try_into().unwrap();
	for (state, pre) in served_preimages(&r, &a2) {
		assert!(pre.is_none_or(|p| arca_covenant::script::sha256(&p) != y_hash), "leaf_data serves Y's preimage early ({} leaf)", state);
	}
	// A's forfeit for Y: taken, checked, and Y's preimage released against it.
	let f_y = forfeit_for(&a_old, &a2_y, &round_y, &st_a);
	let body = forfeit_body(&pa, a_board.id, forfeit_sig(&f_y, &a), a_auths);
	let done_a = r.http.post("forfeit_leaves", &body).ok();
	println!("A's forfeit for Y: {}", done_a);
	assert_eq!(done_a["state"], "released");
	let y_preimage: [u8; 32] = unhex(done_a["preimage"].as_str().unwrap()).try_into().unwrap();
	assert_eq!(arca_covenant::script::sha256(&y_preimage), y_hash, "the preimage of Y's leaves");
	assert_ne!(hex(&y_preimage), r_preimage, "not R's");
	assert_eq!(r.http.post("forfeit_leaves", &body).ok(), done_a, "the same again");
	assert_eq!(r.server.store.forfeits(&pa, built_y.round_id).await.unwrap().len(), 1, "the forfeit for Y is held");
	assert_eq!(leaf_states(&r, &a2), vec!["live", "lost"], "A's leaf of Y is live");
	let live: Vec<Option<[u8; 32]>> = served_preimages(&r, &a2).into_iter().filter(|(s, _)| s == "live").map(|(_, p)| p).collect();
	assert_eq!(live, vec![Some(y_preimage)], "once released, leaf_data serves the leaf's record whole");
	println!("A ran again as an ordinary participation: R's preimage {} is useless, Y's released", &r_preimage[..16]);

	// C, which forfeited in R and runs again in Y, never hands over its
	// forfeit for Y: a day after Y is final it expires. Its coin stays given
	// up, since the signer signed a forfeit under its salt, for R, and
	// co-signs no spend under it; the status says it is not given back, and
	// it is C's on the chain. A, whose forfeit for Y came, does not expire.
	assert_eq!(status(&r, &pc)["state"], "issued");
	advance_mtp(&r, 86_400 + 600).await;
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	let sc = status(&r, &pc);
	assert_eq!(sc["state"], "expired");
	assert_eq!(sc["inputs"][0]["returned"], false, "C's coin is not given back");
	assert_eq!(status(&r, &pa)["state"], "released");
	assert_eq!(leaf_states(&r, &c), vec!["spent"], "C's coin, under a forfeit signed for R, stays given up");
	assert_eq!(leaf_states(&r, &c2), vec!["expired", "lost"]);
	let (d_leaf, _) = new_leaf(&keypair("D"));
	let spend_c = transfer_body(&[(&c_board, c_old.clone(), VALUE - 2_000)], &[(x, VALUE - 4_000, d_leaf)], xonly(&r.s), r.chain);
	refused(r.http.post("cosign_transfer", &spend_c), 409, "double_spend");
	assert!(r.unspent(&c_old.board().unwrap().1), "C's board is C's to exit on the chain");
	println!("C expired in Y; its coin stays given up under its forfeit for R, its board C's on the chain");

	// A goes back on its word after its re-run completed: it brings its old
	// coin, round 0's leaf, on the chain by its own authorisations and
	// preimage. The watcher answers with A's forfeit for Y, and claims it.
	let a_old_id = a_board.id.0.to_vec();
	// The atom of Y's connector asset this test issued by hand above, at an
	// output anyone can spend, goes to the operator's wallet, where the
	// watcher keeps its atoms.
	let to = r.server.wallet.receive_script().await.unwrap();
	let policy = r.purse.policy;
	let fee_coin = r.purse.take_coin(policy);
	let fv = fee_coin.1.value.explicit().unwrap();
	let mut mv = Transaction {
		version: 2, lock_time: elements::LockTime::ZERO,
		input: vec![elements::TxIn { previous_output: atom.0, ..Default::default() },
			elements::TxIn { previous_output: fee_coin.0, ..Default::default() }],
		output: vec![
			sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(m_y, 1), to),
			sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(policy, fv - 5_000), node::op_true()),
			sequentia_ext::fee_txout(sequentia_ext::AssetAmount::new(policy, 5_000)),
		],
	};
	mv.input[0].witness.script_witness = op_true_tap().witness(&elements::Script::from(vec![0x51]), vec![]);
	r.rt.client().send_raw_transaction(&mv).unwrap();
	r.purse.put((elements::OutPoint::new(mv.txid(), 1), mv.output[1].clone()));
	r.produce().await;
	let v = a_old.clone();
	let (valid, preimage, auths) = match &v.origin {
		arca_covenant::ValidOrigin::Leaf { valid, preimage, auths } => (valid, preimage, auths),
		_ => panic!("A's old coin is a batch leaf"),
	};
	let txs = valid.branch.unroll(elements::OutPoint::new(valid.round_txid, valid.batch_vout), auths, &vec![FeeSource::Reserve; auths.len()])
		.unwrap();
	for u in &txs {
		r.rt.client().send_raw_transaction(&u.tx).unwrap();
	}
	let entry = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), preimage, &FeeSource::Reserve).unwrap();
	r.rt.client().send_raw_transaction(&entry.tx).unwrap();
	println!("A's stale exit: {} unroll(s) and its entry {}, its old leaf on the chain", txs.len(), entry.tx.txid());
	let mut claimed = false;
	for n in 0..16 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		r.produce().await;
		r.bury().await;
		r.synced().await;
		r.server.nursery.pass().await.unwrap();
		let log = r.server.store.watcher_log().await.unwrap();
		if common::flow::final_of(&log, "claim", &a_old_id) {
			println!("A's forfeit for Y claimed, final, after {} pass(es)", n + 1);
			claimed = true;
			break;
		}
	}
	let log = r.server.store.watcher_log().await.unwrap();
	for w in &log {
		let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
		println!("  watcher: {} {} ({} vB, {:?}): {}", w.kind, Txid::from_byte_array(w.txid), tx.vsize(), w.state, w.detail);
	}
	assert!(claimed, "A's forfeit for Y is claimed");
	let ours: Vec<&server::store::WatcherTxRow> = log.iter().filter(|w| w.subject == a_old_id).collect();
	assert_eq!(ours.iter().map(|w| w.kind.as_str()).collect::<Vec<_>>(), vec!["forfeit"], "the watcher answers A's exit with a forfeit");
	assert!(ours[0].detail.contains(&format!("for round {}", built_y.round_id)), "A's forfeit for Y, never R's: {}", ours[0].detail);
	let ftx: Transaction = elements::encode::deserialize(&ours[0].tx).unwrap();
	assert!(ftx.output.contains(&f_y.output().txout()), "it pays A's forfeit output for Y");
	assert!(!ftx.output.contains(&f_r.output().txout()), "and not R's");
	let claim = common::flow::claim_of(&log, &a_old_id).unwrap();
	let ctx: Transaction = elements::encode::deserialize(&claim.tx).unwrap();
	// One claim may take several forfeits of a round: A's is any of its inputs.
	let revealed = ctx.input.iter().find_map(|i| arca_covenant::witness::find_preimage(&i.witness.script_witness, &y_hash))
		.expect("the claim reveals Y's preimage");
	assert_eq!(revealed, y_preimage);
	assert_eq!(status(&r, &pa)["state"], "released");
	println!("A's old coin, exited after its re-run completed, was answered by its forfeit for Y {} and claimed by {}",
		Txid::from_byte_array(ours[0].txid), Txid::from_byte_array(claim.txid));
}
