//! Participations run again after a round that can never return, against a
//! whole server on an anchored proof-of-stake regtest chain, the watcher
//! driven by hand. The round's block is disconnected (`invalidateblock`, for
//! an anchor rollback), the node forgets its mempool, and the operator's coin
//! the round spent is taken by another transaction, buried: the round can
//! never come back.
//!
//! 1. A coin whose forfeit for the lost round the watcher published is never
//!    taken into a re-run: its participation is void, saying why, and the
//!    coin stays given up. The server never broadcasts that forfeit again and
//!    no preimage goes out for the re-run; the forfeit, as anyone who saw it
//!    holds it, confirms, and its owner refunds it once its delay has run.
//!    Another participation of the round, whose forfeit was never published,
//!    runs again as an ordinary one: its forfeit for the new round taken and
//!    its preimage released, and nothing of it goes on the chain.
//! 2. A forfeit for the lost round that the watcher logged and never got onto
//!    the chain is given up: it is not broadcast on a pass, nor once the node
//!    takes its fee asset again, nor after a restart; the log refuses another
//!    naming the round; an exit of a coin given up in the round is not
//!    answered with one, and that coin, its output spent, is never taken into
//!    its re-run.
//! 3. The reviewer's D2 turned around: a sender's change on a board's lineage
//!    stays live off the chain after the receiver's re-run completes, and the
//!    sender pays with it.
//! 4. The same for a transfer made on a batch leaf.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::encode::serialize;
use elements::hashes::Hash;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::Keypair;
use elements::{BlockHash, OutPoint, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::{ExplicitOutput, Forfeit, Pair, RelativeTime};
use common::client::{auths_json, forfeit_sig, hex, new_leaf, participation_body, random32, transfer_body, unhex, want_leaf, Held};
use common::flow::{drive, forfeit_for, has, log, refresh, settle, txid, verdict, Coin};
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{advance_mtp, created, credited_board, mtp, round_final, round_state, spend_wallet_coin, start, status, validate_new_leaf, VALUE};
use common::running::Running;
use server::store::{NewWatcherTx, NurseryState, RoundState, StoreError, WatcherTxRow};

fn block_of(r: &Running, txid: &Txid) -> BlockHash {
	let v: Value = r.rt.client().call("getrawtransaction", &[json!(txid.to_string()), json!(true)]).unwrap();
	v["blockhash"].as_str().unwrap().parse().unwrap()
}

/// Whether a block of the active chain holds `txid`.
fn in_a_block(r: &Running, txid: &Txid) -> bool {
	r.rt.client().call::<Value>("getrawtransaction", &[json!(txid.to_string()), json!(true)]).ok()
		.and_then(|v| v["confirmations"].as_u64()).unwrap_or(0) > 0
}

/// The round `built` can never return: the server stopped, the round's block
/// disconnected, the node restarted with an empty mempool, the operator's
/// coin the round spent taken by another transaction, and that buried;
/// `meanwhile` runs before the server starts again. Waits until the server
/// holds the round lost.
async fn lose<F: FnOnce(&Running)>(r: &mut Running, built: &Transaction, meanwhile: F) {
	r.server.stop();
	let wi = built.input[0].previous_output;
	let w_out = r.rt.client().raw_transaction(&wi.txid).unwrap().output[wi.vout as usize].clone();
	node::invalidate(&r.rt, &block_of(r, &built.txid()));
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0"])).unwrap();
	let elsewhere = spend_wallet_coin(wi, &w_out, vec![], 2_000);
	r.rt.client().send_raw_transaction(&elsewhere).unwrap();
	r.produce().await;
	r.bury().await;
	println!("round {}: its input {} spent elsewhere by {}, buried", built.txid(), wi, elsewhere.txid());
	meanwhile(r);
	r.restart_server().await;
	round_state(r, &built.txid(), RoundState::Lost).await;
}

/// The coin `c` given up for a new leaf under `key` of its whole value:
/// the participation's id and the new leaf's nonce.
fn participate(r: &Running, c: &Coin, key: &Keypair) -> ([u8; 32], [u8; 32]) {
	let v = c.valid(r);
	let (w, nonce) = want_leaf(key, v.asset, v.value);
	let (body, id) = participation_body(&[&c.held], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	(id, nonce)
}

/// The owner of `c` hands over its forfeit for the round participation `p`
/// is in now, for the new leaf under `key`: the forfeit, and the answer.
fn hand_over(r: &Running, p: &[u8; 32], c: &Coin, key: &Keypair, nonce: &[u8; 32]) -> (Forfeit, Value) {
	let st = status(r, p);
	let (new, record, round) = validate_new_leaf(r, p, 0, key, nonce);
	let f = forfeit_for(&c.valid(r), &new, &round, &st);
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(p),
		"forfeits": [{"leaf_id": c.held.id.to_string(), "signature": forfeit_sig(&f, &c.held.key)}],
		"leaves": [auths_json(&new, key, created(&record))]})).ok();
	(f, done)
}

/// Waits until participation `p` is `state`: a round found lost is retired
/// first, and each participation it ran is then looked at.
async fn wait_state(r: &Running, p: &[u8; 32], state: &str) -> Value {
	r.wait(&format!("participation {} to be {}", hex(p), state), || status(r, p)["state"] == state).await;
	status(r, p)
}

/// Runs the watcher, a block after each pass, `n` times.
async fn passes(r: &Running, n: usize) {
	for _ in 0..n {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		r.server.nursery.pass().await.unwrap();
		r.produce().await;
	}
}

fn forfeit_of(l: &[WatcherTxRow], c: &Coin) -> Option<WatcherTxRow> {
	l.iter().find(|w| w.kind == "forfeit" && w.subject == c.held.id.0.to_vec()).cloned()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_coin_whose_forfeit_for_a_lost_round_was_published_is_never_run_again() {
	let mut r = start().await;
	let x = r.x;
	let (a, b) = (keypair("G1 A"), keypair("G1 B"));
	let (ha, ta) = credited_board(&mut r, &a, x).await;
	let (hb, tb) = credited_board(&mut r, &b, x).await;
	let (ca, cb) = (Coin { held: ha, bases: vec![ta] }, Coin { held: hb, bases: vec![tb] });
	let (a2, b2) = (keypair("G1 A2"), keypair("G1 B2"));
	let (pa, a2_nonce) = participate(&r, &ca, &a2);
	let (pb, b2_nonce) = participate(&r, &cb, &b2);

	// Round R, final. A hands over its forfeit, and the watcher publishes it
	// from A's board output; B hands over its forfeit after that pass, and
	// nothing of B's is published.
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let lost = built.tx.txid();
	r.produce().await;
	r.bury().await;
	round_final(&r, &lost).await;
	let (fa_r, done) = hand_over(&r, &pa, &ca, &a2, &a2_nonce);
	assert_eq!(done["state"], "released");
	drive(&r, "A's forfeit for R", 8, |l| has(l, "forfeit", &ca.held.id.0)).await;
	settle(&r).await;
	let fa_txid = txid(&forfeit_of(&log(&r).await, &ca).unwrap());
	let seen: Transaction = r.rt.client().raw_transaction(&fa_txid).unwrap();
	assert!(seen.output.contains(&fa_r.output().txout()) && in_a_block(&r, &fa_txid));
	println!("G1 the watcher published A's forfeit for R: {}, in a block", fa_txid);
	let (_, done_b) = hand_over(&r, &pb, &cb, &b2, &b2_nonce);
	assert_eq!(done_b["state"], "released");

	lose(&mut r, &built.tx, |_| {}).await;

	// A's re-run is never taken: void, saying why; its coin stays given up.
	let sa = wait_state(&r, &pa, "void").await;
	println!("G1 A after R is lost: {} attempt {}: {}", sa["state"], sa["attempt"], sa["void_reason"]);
	assert_eq!(sa["state"], "void");
	let why = sa["void_reason"].as_str().unwrap();
	assert!(why.contains(&fa_txid.to_string()) && why.contains("refund"), "{}", why);
	assert_eq!(sa["inputs"][0]["returned"], false, "its forfeit for R may still confirm: the coin is not given back");
	assert!(sa.get("forfeit_first").is_none());
	// B's runs again as an ordinary participation.
	let sb = status(&r, &pb);
	println!("G1 B after R is lost: {} attempt {}", sb["state"], sb["attempt"]);
	assert_eq!((sb["state"].as_str(), sb["attempt"].as_u64()), (Some("pending"), Some(1)));

	// The server's copy of A's forfeit for R is given up and never broadcast
	// again: not on a pass, and not by the watcher.
	let row = r.server.store.nursery_get(&fa_txid.to_byte_array()).await.unwrap().unwrap();
	assert_eq!(row.state, NurseryState::Lost);
	let broadcasts = row.broadcasts;
	passes(&r, 3).await;
	let row = r.server.store.nursery_get(&fa_txid.to_byte_array()).await.unwrap().unwrap();
	println!("G1 the server's copy of A's forfeit for R: {:?}, {} broadcast(s) before and after; in the mempool {}, in a block {}",
		row.state, broadcasts, node::in_mempool(&r.rt, &fa_txid), in_a_block(&r, &fa_txid));
	assert_eq!(row.broadcasts, broadcasts);
	assert!(!node::in_mempool(&r.rt, &fa_txid) && !in_a_block(&r, &fa_txid));

	// No preimage goes out for A's re-run.
	let again = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&pa),
		"forfeits": [{"leaf_id": ca.held.id.to_string(), "signature": forfeit_sig(&fa_r, &a)}], "leaves": []}));
	println!("G1 A's forfeit for R handed over again: {} {:?}", again.status, again.refusal());
	assert!(again.status >= 400 && again.json["preimage"].is_null());

	// Round Y takes B alone: its forfeit for Y taken, the preimage released.
	let built_y = r.server.rounds.run_round().await.unwrap().unwrap();
	assert_eq!(built_y.participations, 1, "A's re-run is not in Y");
	r.produce().await;
	r.bury().await;
	round_final(&r, &built_y.tx.txid()).await;
	let (_, done_y) = hand_over(&r, &pb, &cb, &b2, &b2_nonce);
	println!("G1 B's forfeit for Y: {}", done_y);
	assert_eq!(done_y["state"], "released");
	let pre: [u8; 32] = unhex(done_y["preimage"].as_str().unwrap()).try_into().unwrap();
	assert_eq!(hex(&arca_covenant::script::sha256(&pre)), status(&r, &pb)["unlock_hash"].as_str().unwrap());
	// What goes on the chain for B's coin is what any board given up in a
	// final round gets: its forfeit, for Y, from the board output, which the
	// operator claims with Y's connector asset. Nothing names R.
	drive(&r, "B's forfeit for Y claimed", 8, |l| has(l, "claim", &cb.held.id.0)).await;
	let l = log(&r).await;
	let of_b: Vec<&WatcherTxRow> = l.iter().filter(|w| w.subject == cb.held.id.0.to_vec()).collect();
	println!("G1 the watcher for B's coin: {:?}", of_b.iter().map(|w| &w.detail).collect::<Vec<_>>());
	assert!(of_b.iter().all(|w| w.kind == "forfeit" && w.detail.ends_with(&format!("round {}", built_y.round_id))), "only B's forfeit for Y");

	// A's forfeit for R, as anyone who saw it holds it, confirms; once its
	// delay has run A refunds it: A's coin is A's on the chain.
	r.rt.client().send_raw_transaction(&seen).unwrap();
	r.produce().await;
	r.bury().await;
	assert!(in_a_block(&r, &fa_txid));
	let refund = RelativeTime::from_units(sa["refund_delay_units"].as_u64().unwrap() as u16).unwrap();
	advance_mtp(&r, refund.seconds() as u32 + 600).await;
	let vout = seen.output.iter().position(|o| *o == fa_r.output().txout()).unwrap() as u32;
	let at = OutPoint::new(fa_txid, vout);
	assert!(r.unspent(&at), "no claim took it: R's connector asset can never be issued");
	let value = fa_r.value - fa_r.margin;
	let ks = fa_r.refund(at, &[ExplicitOutput::new(x, value - 3_000, node::op_true())], &FeeSource::Reserve).unwrap();
	let sig = sign_digest(&a, &ks.sighash(r.chain.genesis_hash()).unwrap(), &random32());
	let refund_tx = ks.finish(vec![sig.as_ref().to_vec()]).tx;
	r.rt.client().send_raw_transaction(&refund_tx).unwrap();
	r.produce().await;
	r.bury().await;
	assert!(r.unspent(&OutPoint::new(refund_tx.txid(), 0)));
	println!("G1 A refunded its forfeit for R: {} pays A {} of X", refund_tx.txid(), value - 3_000);
	assert_eq!(status(&r, &pa)["state"], "void");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lost_rounds_forfeit_is_never_published_again_by_any_path() {
	let mut r = start().await;
	let x = r.x;
	let (a, b) = (keypair("G2 A"), keypair("G2 B"));
	let (ha, ta) = credited_board(&mut r, &a, x).await;
	let (hb, tb) = credited_board(&mut r, &b, x).await;
	let (ca, cb) = (Coin { held: ha, bases: vec![ta] }, Coin { held: hb, bases: vec![tb] });
	let (a2, b2) = (keypair("G2 A2"), keypair("G2 B2"));
	let (pa, a2_nonce) = participate(&r, &ca, &a2);
	let (pb, b2_nonce) = participate(&r, &cb, &b2);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let (fa_r, _) = hand_over(&r, &pa, &ca, &a2, &a2_nonce);
	let (fb_r, _) = hand_over(&r, &pb, &cb, &b2, &b2_nonce);
	let whole = |r: &Running, p: &[u8; 32], f: &Forfeit, c: &Coin| -> Transaction {
		let stored = tokio::runtime::Handle::current().block_on(r.server.store.forfeits(p, built.round_id)).unwrap();
		let pair = Pair { operator: Signature::from_slice(&stored[0].forfeit.operator_sig).unwrap(),
			owner: Signature::from_slice(&stored[0].forfeit.owner_sig).unwrap() };
		let (board, at) = c.valid(r).board().unwrap();
		f.board_tx(&board, at, &pair, &FeeSource::Reserve).unwrap().tx
	};
	let logged = |tx: &Transaction, c: &Coin| NewWatcherTx {
		txid: tx.txid().to_byte_array(), tx: serialize(tx), fee: None, kind: "forfeit", subject: c.held.id.0.to_vec(),
		detail: "a forfeit for round R".into(),
		inputs: tx.input.iter().map(|i| (i.previous_output.txid.to_byte_array(), i.previous_output.vout)).collect(),
		round: Some(built.round_id),
	};

	// The watcher logs A's forfeit for R, and the server stops before it
	// reaches the node; then the node stops taking X for fees, so a
	// broadcast of it is refused; then R can never return.
	r.server.stop();
	let fa_tx = tokio::task::block_in_place(|| whole(&r, &pa, &fa_r, &ca));
	assert!(r.db.store.insert_watcher_tx(&logged(&fa_tx, &ca)).await.unwrap());
	let fa_txid = fa_tx.txid();
	println!("G2 A's forfeit for R in the watcher's log, never broadcast: {}", fa_txid);
	let rates: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
	let rate = rates[x.to_string()].as_u64().unwrap();
	lose(&mut r, &built.tx, |r| {
		let rates: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
		let mut rates = rates.as_object().unwrap().clone();
		rates.remove(&x.to_string());
		let _: Value = r.rt.client().call("setfeeexchangerates", &[Value::Object(rates)]).unwrap();
	}).await;

	// A's re-run is never taken; the forfeit is given up.
	let sa = wait_state(&r, &pa, "void").await;
	println!("G2 A after R is lost: {}: {}", sa["state"], sa["void_reason"]);
	assert_eq!(sa["state"], "void");
	assert!(sa["void_reason"].as_str().unwrap().contains(&fa_txid.to_string()));
	assert_eq!(sa["inputs"][0]["returned"], false);
	let row = r.server.store.nursery_get(&fa_txid.to_byte_array()).await.unwrap().unwrap();
	println!("G2 the server's copy of A's forfeit for R: {:?}, {} broadcast(s), last {:?}", row.state, row.broadcasts, row.last_result);
	assert_eq!(row.state, NurseryState::Lost);
	let broadcasts = row.broadcasts;

	// The node takes X again: a pass, a restart, a pass. The node would take
	// the forfeit now, and nothing sends it.
	node::list_fee_asset(&r.rt, x, rate);
	passes(&r, 2).await;
	r.restart_server().await;
	passes(&r, 2).await;
	println!("G2 the node's verdict on A's forfeit for R now: {:?}", verdict(&r, &fa_tx));
	assert_eq!(verdict(&r, &fa_tx), Ok(()));
	let row = r.server.store.nursery_get(&fa_txid.to_byte_array()).await.unwrap().unwrap();
	assert_eq!((row.state, row.broadcasts), (NurseryState::Lost, broadcasts), "never broadcast again");
	assert!(!node::in_mempool(&r.rt, &fa_txid) && !in_a_block(&r, &fa_txid));

	// The log refuses a forfeit naming R: B's.
	let fb_tx = tokio::task::block_in_place(|| whole(&r, &pb, &fb_r, &cb));
	match r.server.store.insert_watcher_tx(&logged(&fb_tx, &cb)).await {
		Err(StoreError::RoundLost(id)) => {
			assert_eq!(id, built.round_id);
			println!("G2 the log refuses B's forfeit for R: round {} can never return", id);
		},
		other => panic!("B's forfeit for R logged: {:?}", other),
	}

	// B exits its board: no forfeit naming R answers it, and B's re-run,
	// its coin's output spent, is never taken.
	assert_eq!(status(&r, &pb)["state"], "pending");
	let (policy, at) = cb.valid(&r).board().unwrap();
	let fee_coin = r.purse.take_coin(x);
	let conv = policy.conversion(at, &FeeSource::Coin { outpoint: fee_coin.0, coin: fee_coin.1.clone(), fee: 3_000, change: node::op_true() })
		.unwrap();
	let sig = sign_digest(&b, &conv.sighash(r.chain.genesis_hash()).unwrap(), &random32());
	let conv = conv.finish(vec![sig.as_ref().to_vec()]);
	r.rt.client().send_raw_transaction(&conv.tx).unwrap();
	r.produce().await;
	r.bury().await;
	passes(&r, 3).await;
	let l = log(&r).await;
	assert!(forfeit_of(&l, &cb).is_none(), "no forfeit answers B's exit: {:?}", l.iter().map(|w| (&w.kind, &w.detail)).collect::<Vec<_>>());
	assert!(r.unspent(&OutPoint::new(conv.tx.txid(), 0)), "B's conversion stands, its leaf B's");
	assert!(r.server.rounds.run_round().await.unwrap().is_none(), "no participation to run");
	let sb = status(&r, &pb);
	println!("G2 B after its exit: {}: {}", sb["state"], sb["void_reason"]);
	assert_eq!(sb["state"], "void");
	assert!(sb["void_reason"].as_str().unwrap().contains("spent on the chain"));
	assert!(!node::in_mempool(&r.rt, &fb_tx.txid()) && !in_a_block(&r, &fb_tx.txid()));
	let _ = mtp(&r);
}

/// A board for A, paid out of round to B with A's change A2: (B's coin,
/// A2's coin, the transfer id).
async fn paid_from(r: &mut Running, from: &Coin, tag: &str) -> (Coin, Coin, Vec<u8>) {
	let (x, s) = (r.x, xonly(&r.s));
	let (b, a2) = (keypair(&format!("{} B", tag)), keypair(&format!("{} A2", tag)));
	let (b_leaf, b_nonce) = new_leaf(&b);
	let (a2_leaf, a2_nonce) = new_leaf(&a2);
	let v = from.valid(r);
	let kept = v.value - 2_000;
	let change = kept - 600_000 - 2_000;
	let done = r.http.post("cosign_transfer", &transfer_body(&[(&from.held, v, kept)],
		&[(x, 600_000, b_leaf), (x, change, a2_leaf)], s, r.chain)).ok();
	let transfer: Vec<u8> = unhex(done["transfer_id"].as_str().unwrap());
	let (_, b_id, b_record) = r.http.mailbox(&b, &r.chain, 0)[0].clone();
	let cb = Coin { held: Held { key: b, nonce: b_nonce, id: b_id, record: b_record }, bases: from.bases.clone() };
	let (_, a2_id, a2_record) = r.http.mailbox(&a2, &r.chain, 0)[0].clone();
	let ca2 = Coin { held: Held { key: a2, nonce: a2_nonce, id: a2_id, record: a2_record }, bases: from.bases.clone() };
	println!("{} A paid B 600000 out of round, its change A2 {} of {}", tag, a2_id, change);
	(cb, ca2, transfer)
}

/// B refreshes `cb` in round R, released; R can never return; B's re-run
/// completes in round Y as an ordinary participation. Nothing of the
/// lineage `subjects` name goes on the chain, and A pays with its change
/// `ca2`, live off the chain.
async fn rerun_then_pay_on(r: &mut Running, cb: &Coin, ca2: &Coin, subjects: &[Vec<u8>], tag: &str) {
	let x = r.x;
	let b2 = keypair(&format!("{} B, refreshed", tag));
	let (pb, b2_nonce) = participate(r, cb, &b2);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(r, &built.tx.txid()).await;
	let (_, done) = hand_over(r, &pb, cb, &b2, &b2_nonce);
	assert_eq!(done["state"], "released");
	passes(r, 3).await;
	lose(r, &built.tx, |_| {}).await;
	r.server.rounds.pass().await.unwrap();
	let sb = status(r, &pb);
	println!("{} B after R is lost: {} attempt {}", tag, sb["state"], sb["attempt"]);
	assert_eq!((sb["state"].as_str(), sb["attempt"].as_u64()), (Some("pending"), Some(1)));

	// Round Y: B's forfeit for Y taken, its preimage released.
	let built_y = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(r, &built_y.tx.txid()).await;
	let (_, done_y) = hand_over(r, &pb, cb, &b2, &b2_nonce);
	println!("{} B's forfeit for Y: {} {}", tag, done_y["state"], done_y["preimage"]);
	assert_eq!(done_y["state"], "released");
	assert!(done_y["preimage"].is_string());

	// Nothing of the lineage goes on the chain.
	passes(r, 8).await;
	let l = log(r).await;
	for w in &l {
		println!("  watcher: {} {} {:?}: {}", w.kind, txid(w), w.state, w.detail);
	}
	assert!(l.iter().all(|w| !subjects.contains(&w.subject) && w.subject != cb.held.id.0.to_vec()
		&& !["checkpoint", "reassignment", "unroll", "entry"].contains(&w.kind.as_str())), "nothing of the lineage is published");

	// A's change is live off the chain, and A pays with it.
	let (a3_leaf, _) = new_leaf(&keypair(&format!("{} A3", tag)));
	let v2 = ca2.valid(r);
	let paid = r.http.post("cosign_transfer", &transfer_body(&[(&ca2.held, v2.clone(), v2.value - 2_000)],
		&[(x, v2.value - 4_000, a3_leaf)], xonly(&r.s), r.chain));
	println!("{} A pays with its change after B's re-run completed: {}", tag, paid.status);
	let paid = paid.ok();
	assert!(paid["transfer_id"].is_string(), "{}", paid);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_senders_change_on_a_boards_lineage_stays_live_after_the_receivers_rerun() {
	let mut r = start().await;
	let a = keypair("D2 A");
	let x = r.x;
	let (held, tx) = credited_board(&mut r, &a, x).await;
	let ca = Coin { held, bases: vec![tx] };
	let (cb, ca2, transfer) = paid_from(&mut r, &ca, "D2").await;
	rerun_then_pay_on(&mut r, &cb, &ca2, &[ca.held.id.0.to_vec(), transfer], "D2").await;
	assert!(r.unspent(&ca.valid(&r).board().unwrap().1), "A's board is unspent on the chain");
	let _ = VALUE;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_senders_change_on_a_batch_leafs_lineage_stays_live_after_the_receivers_rerun() {
	let mut r = start().await;
	let a0 = keypair("D2b A, board");
	let x = r.x;
	let (held, tx) = credited_board(&mut r, &a0, x).await;
	let c0 = Coin { held, bases: vec![tx] };
	let a = keypair("D2b A");
	let leaf = refresh(&mut r, &[(&c0, &a)]).await.remove(0).new;
	println!("D2b A holds a leaf of round {}", leaf.bases[0].txid());
	let (cb, ca2, transfer) = paid_from(&mut r, &leaf, "D2b").await;
	rerun_then_pay_on(&mut r, &cb, &ca2, &[leaf.held.id.0.to_vec(), transfer], "D2b").await;
	let batch = OutPoint::new(leaf.bases[0].txid(), 0);
	assert!(r.unspent(&batch), "the batch output A's leaf rests on is unspent: nothing of it was unrolled");
}
