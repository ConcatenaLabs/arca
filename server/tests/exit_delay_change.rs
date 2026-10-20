//! The operator changes its exit-delay bounds (`exit_delay_units`, taken at a
//! restart) while it holds coins made under the old ones. The bounds govern
//! the leaves it makes from then on; what it took before is still its to
//! answer and to complete:
//!
//! 1. A refreshed batch leaf made under the old bounds and brought back
//!    on-chain by its owner after the change (a stale exit) is answered by
//!    its forfeit and claimed, as before the change.
//! 2. A participation whose round was built before the change takes its
//!    forfeits after it and is released.
//! 3. A participation still pending at the change, which asked for a leaf
//!    outside the new bounds, can never run: the next round voids it, saying
//!    why, rather than failing to build.
//! 4. A board registered before the change is credited after it, and its
//!    registration posted again gets its status, not a refusal.
//! 5. A batch made before the change is released at its expiry and swept
//!    after the notice, as before the change.
//!
//! Every coin here is made at the specification's 254 units; the server is
//! then restarted taking 1 to 2, so each of them lies outside its new bounds.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::{OutPoint, Transaction, Txid};
use serde_json::json;

use arca_covenant::spend::FeeSource;
use arca_covenant::ValidOrigin;
use common::client::{auths_json, forfeit_sig, hex, participation_body, want_leaf};
use common::flow::{claim_of, claimed, drive, final_of, forfeit_for, has, held_by, log, of_kind, refresh, settle, Coin};
use common::keys::{keypair, xonly};
use common::rounds::{advance_mtp, created, credited_board, mtp, round_final, start, status, validate_new_leaf};
use common::running::Running;

fn send(r: &Running, what: &str, tx: &Transaction) -> Txid {
	let txid = r.rt.client().send_raw_transaction(tx).unwrap_or_else(|e| panic!("{}: {}", what, e));
	println!("{}: {} ({} vB)", what, txid, tx.vsize());
	txid
}

/// The unroll of `coin`, a batch leaf, from its batch output down by its
/// owner's own authorisations, and its entry with its preimage, each
/// broadcast: the leaf's outpoint.
fn unroll_to_leaf(r: &Running, coin: &Coin, label: &str) -> OutPoint {
	let v = coin.valid(r);
	let (valid, preimage, auths) = match &v.origin {
		ValidOrigin::Leaf { valid, preimage, auths } => (valid, preimage, auths),
		_ => panic!("not a batch leaf"),
	};
	let txs = valid.branch.unroll(OutPoint::new(valid.round_txid, valid.batch_vout), auths, &vec![FeeSource::Reserve; auths.len()]).unwrap();
	for (level, u) in txs.iter().enumerate() {
		send(r, &format!("{}: unroll, level {}", label, level), &u.tx);
	}
	let entry = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), preimage, &FeeSource::Reserve).unwrap();
	OutPoint::new(send(r, &format!("{}: its entry", label), &entry.tx), 0)
}

/// Restarts the server on the same database taking exit delays of 1 to 2
/// units only.
async fn narrow_bounds(r: &mut Running) {
	r.config.exit_delay_units = Some((1, 2));
	r.restart_server().await;
	let info = r.http.get("info").ok();
	assert_eq!(info["exit_delay_units"], json!({"min": 1, "max": 2}), "{}", info);
	println!("restarted taking exit delays of 1 to 2 units; every coin so far has 254");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_exit_of_a_coin_made_under_other_bounds_is_answered() {
	let mut r = start().await;
	let (held, tx) = { let x = r.x; credited_board(&mut r, &keypair("A, board"), x).await };
	let ca = Coin { held, bases: vec![tx] };
	let a1 = keypair("A, round 1");
	let first = refresh(&mut r, &[(&ca, &a1)]).await;
	let a2 = keypair("A, round 2");
	let _second = refresh(&mut r, &[(&first[0].new, &a2)]).await;
	println!("A's board refreshed in round 1, and its leaf of round 1 in round 2");

	narrow_bounds(&mut r).await;

	// A brings the leaf it gave up in round 2 back on-chain.
	let leaf_at = unroll_to_leaf(&r, &first[0].new, "A's stale exit");
	let id1 = first[0].new.held.id.0.to_vec();
	drive(&r, "the answer to A's stale exit", 6, |l| has(l, "claim", &id1)).await;
	settle(&r).await;
	let l = log(&r).await;
	let forfeit = l.iter().find(|w| w.kind == "forfeit" && w.subject == id1).expect("the watcher published the forfeit");
	let ftx: Transaction = elements::encode::deserialize(&forfeit.tx).unwrap();
	assert_eq!(ftx.input[0].previous_output, leaf_at, "the forfeit spends A's leaf where A put it");
	assert!(final_of(&l, "forfeit", &id1) && final_of(&l, "claim", &id1), "the forfeit and its claim are final");
	assert!(claim_of(&l, &id1).is_some());
	println!("A's stale exit of a 254-unit leaf answered by a server taking 1 to 2");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_round_built_before_the_change_takes_its_forfeits_after_it() {
	let mut r = start().await;
	let (held, tx) = { let x = r.x; credited_board(&mut r, &keypair("B, board"), x).await };
	let coin = Coin { held, bases: vec![tx] };
	let key = keypair("B, round 1");
	let v = coin.valid(&r);
	let (w, nonce) = want_leaf(&key, v.asset, v.value);
	let (body, id) = participation_body(&[&coin.held], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	println!("B's participation issued in round {}, final; its forfeits not yet handed over", built.tx.txid());

	narrow_bounds(&mut r).await;

	let st = status(&r, &id);
	let (new_valid, record, round) = validate_new_leaf(&r, &id, 0, &key, &nonce);
	let f = forfeit_for(&coin.valid(&r), &new_valid, &round, &st);
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&id),
		"forfeits": [{"leaf_id": coin.held.id.to_string(), "signature": forfeit_sig(&f, &coin.held.key)}],
		"leaves": [auths_json(&new_valid, &key, created(&record))]}));
	println!("B's forfeits after the change: {} {}", done.status, done.json);
	assert_eq!(done.ok()["state"], "released", "the participation taken before the change completes");
	let held = held_by(&r, &key, nonce, new_valid.leaf_id);
	assert_eq!(held.id, new_valid.leaf_id);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_participation_pending_across_the_change_is_voided_and_rounds_go_on() {
	let mut r = start().await;
	let (held, tx) = { let x = r.x; credited_board(&mut r, &keypair("C, board"), x).await };
	let coin = Coin { held, bases: vec![tx] };
	let key = keypair("C, round 1");
	let v = coin.valid(&r);
	let (w, _) = want_leaf(&key, v.asset, v.value);
	let (body, id) = participation_body(&[&coin.held], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	println!("C's participation pending, wanting a leaf of 254 units");

	narrow_bounds(&mut r).await;

	for n in 0..2 {
		let built = r.server.rounds.run_round().await;
		println!("round attempt {} after the change: {:?}", n, built.as_ref().map(|b| b.as_ref().map(|b| b.tx.txid())));
		assert!(built.is_ok(), "the round builder goes on: {:?}", built.err());
	}
	let st = status(&r, &id);
	println!("C's participation: {}", st);
	assert_eq!(st["state"], "void", "{}", st);
	assert!(st.to_string().contains("exit delay"), "voided saying why: {}", st);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_board_registered_before_the_change_is_credited_after_it() {
	let mut r = start().await;
	let owner = keypair("D, board");
	let nonce = r.http.operator_nonce();
	let record = common::client::board_record(&owner, nonce, r.x, common::rounds::VALUE, r.chain, xonly(&r.s));
	let coins = vec![r.purse.take_coin(r.x)];
	let tx = record.tx(&coins, r.x, 2_000, &common::node::op_true()).unwrap().tx;
	r.rt.client().send_raw_transaction(&tx).unwrap();
	let first = r.http.register_board(&record, &tx).ok();
	println!("D's board registered: {}", first);
	assert_eq!(first["state"], "pending");

	narrow_bounds(&mut r).await;

	let again = r.http.register_board(&record, &tx);
	println!("D's registration posted again after the change: {} {}", again.status, again.json);
	assert_eq!(again.ok()["state"], "pending", "a board the server holds gets its status");
	r.produce().await;
	r.bury().await;
	let id = record.leaf_id();
	r.wait("D's board credited", || {
		let st = r.http.post("board_status", &json!({"leaf_id": id.to_string()})).ok();
		st["state"] == "credited"
	}).await;
	println!("D's board, registered at 254 units, credited by a server taking 1 to 2");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_batch_made_before_the_change_is_swept_at_its_expiry() {
	let mut r = start().await;
	let mut coins = vec![];
	let mut keys = vec![];
	for i in 0..2 {
		let (held, tx) = { let x = r.x; credited_board(&mut r, &keypair(&format!("E{}, board", i)), x).await };
		coins.push(Coin { held, bases: vec![tx] });
		keys.push(keypair(&format!("E{}, round 1", i)));
	}
	let pairs: Vec<(&Coin, &elements::secp256k1_zkp::Keypair)> = coins.iter().zip(&keys).collect();
	let got = refresh(&mut r, &pairs).await;
	drive(&r, "the two boards given up", 12, |l| claimed(l) == 2).await;
	settle(&r).await;
	let schedule = got[0].new_valid.branch.nodes[0].sweep;
	let e0 = match &got[0].new.held.record {
		arca_covenant::CoinRecord::Leaf { record, .. } => record.schedule.expiries()[0].to_consensus_u32(),
		_ => unreachable!(),
	};
	println!("a batch of two leaves at 254 units, expiring at {}", e0);

	narrow_bounds(&mut r).await;

	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, e0.saturating_sub(now) + 3_600).await;
	let token = schedule.token.into_inner().to_byte_array().to_vec();
	drive(&r, "the release at the expiry", 4, |l| has(l, "release", &token)).await;
	settle(&r).await;
	advance_mtp(&r, 37 * 3_600).await;
	drive(&r, "the sweep after the notice", 4, |l| has(l, "sweep", &token)).await;
	settle(&r).await;
	let sw = of_kind(&r, "sweep").await;
	assert_eq!(sw.len(), 1, "one sweep");
	println!("the batch made at 254 units swept by a server taking 1 to 2: {}", common::flow::txid(&sw[0]));
}
