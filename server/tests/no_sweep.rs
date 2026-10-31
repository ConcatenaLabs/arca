//! Refresh rounds of batches without a sweep (`[batches] no_sweep`).
//!
//! - A round is built with no token and no clock: its batch output carries
//!   no sweep, its tree is published with the never schedule, and every
//!   leaf's record is of a batch that never expires.
//! - The round is held, built and unbroadcast, until every participation in
//!   it has handed over its forfeits, signed against the transaction its
//!   status serves. A participant that never answers is voided past the
//!   window, its coin its own again; the round is dropped and spent on the
//!   chain by the operator, so it can never confirm (refused by the node and
//!   forced into a block, refused there too), and the participants that did
//!   answer run again in the next round, which completes.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::{OutPoint, Transaction};
use serde_json::{json, Value};

use common::client::{hex, participation_body, unhex, want_leaf, Held};
use common::keys::{keypair, xonly};
use common::rounds::{advance_mtp, credited_board, round_final, status, validate_new_leaf, VALUE};
use common::running::Running;
use server::store::RoundState;

/// A server building batches without a sweep, on an anchored chain without
/// proof of stake (so `generateblock` can force a transaction into a block),
/// its wallet funded and final.
async fn start() -> Running {
	let mut r = Running::start_plain(|c, _| {
		c.batches.no_sweep = true;
		c.batches.holder_batches = Some(0);
	}).await;
	let x = r.x;
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r
}

/// `coin` given up for one leaf of its whole value under `key`: the
/// participation's id and the leaf's nonce.
fn submit(r: &Running, coin: &Held, key: &elements::secp256k1_zkp::Keypair) -> ([u8; 32], [u8; 32]) {
	let (w, nonce) = want_leaf(key, r.x, VALUE);
	let (body, id) = participation_body(&[coin], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	(id, nonce)
}

/// The coin of the operator's among `tx`'s inputs that the wallet has spent
/// since in another transaction, and that transaction.
async fn spent_otherwise(r: &Running, tx: &Transaction) -> Option<(OutPoint, elements::Txid)> {
	let mut found = None;
	for i in &tx.input {
		let op = i.previous_output;
		let Some(c) = r.server.store.wallet_coin_at(&op.txid.to_byte_array(), op.vout).await.unwrap() else { continue };
		if let Some(by) = c.spent_by.filter(|b| *b != tx.txid().to_byte_array()) {
			found = Some((op, elements::Txid::from_byte_array(by)));
		}
	}
	found
}

/// Forces `tx` into a block with `generateblock`: refused, for `expect`.
fn refused_in_block(r: &Running, what: &str, tx: &Transaction, expect: &str) {
	let h0 = r.rt.client().block_count().unwrap();
	let e = match r.rt.client().generate_block("raw(51)", &[tx]) {
		Ok(h) => panic!("{}: MINED in block {}", what, h),
		Err(e) => e.to_string(),
	};
	assert_eq!(r.rt.client().block_count().unwrap(), h0);
	println!("{}: refused in a block: {}", what, e);
	assert!(e.contains(expect), "{}: refused with {:?}, expected {:?}", what, e, expect);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_that_hands_over_no_forfeit_is_left_out_and_its_round_never_confirms() {
	let mut r = start().await;
	let x = r.x;
	let info = r.http.get("info").ok();
	println!("info.batches: {}", info["batches"]);
	assert_eq!(info["batches"]["no_sweep"], true);
	assert_eq!(info["batches"]["collect_after_seconds"], 28 * 86_400);

	let (ka, kb) = (keypair("A board"), keypair("B board"));
	let (a, _) = credited_board(&mut r, &ka, x).await;
	let (b, _) = credited_board(&mut r, &kb, x).await;
	let (a1, b1) = (keypair("A1"), keypair("B1"));
	let (ida, _) = submit(&r, &a, &a1);
	let (idb, _) = submit(&r, &b, &b1);

	// Built, held: no token, no clock.
	let built = r.server.rounds.run_round().await.unwrap().expect("a round");
	let tx = built.tx.clone();
	println!("round {} built ({} vB, {} inputs, {} outputs): {}", tx.txid(), tx.vsize(), tx.input.len(), tx.output.len(), built.broadcast);
	assert!(built.broadcast.starts_with("held"), "{}", built.broadcast);
	assert!(!common::node::in_mempool(&r.rt, &tx.txid()));
	let issued = tx.input.iter().filter(|i| i.has_issuance()).count();
	assert_eq!(issued, 0, "a round of batches without a sweep issues no token");
	assert!(!tx.output.iter().any(|o| o.value.explicit() == Some(1) && o.asset.explicit() != Some(x)), "no token's atom");
	let st = status(&r, &ida);
	let tree = r.http.post("tree", &json!({"txid": st["round"]["txid"], "vout": st["outputs"][0]["batch_vout"]})).ok();
	let schedule = common::client::rebuild(&tree).params().schedule.clone();
	println!("published schedule: token {}, expiries {:?}, expires {}", schedule.token, schedule.expiries(), schedule.expires());
	assert!(!schedule.expires());
	assert_eq!(schedule, arca_covenant::ClockSchedule::never(xonly(&r.s)));

	// A hands over its forfeit against the served transaction; B never does.
	let m = common::client::made(&ida).unwrap();
	let done = common::rounds::hand_over(&r, &ida, &m).await;
	println!("A's forfeit in before broadcast: {}", done);
	assert_eq!(done["state"], "issued");
	r.server.rounds.pass().await.unwrap();
	assert!(!common::node::in_mempool(&r.rt, &tx.txid()), "held while B's forfeit is missing");
	// No half of A's forfeit is asked of the signer for a round the node does not hold.
	r.server.forfeits.fill_unsigned().await.unwrap();
	let row = r.server.store.round_by_txid(&tx.txid().to_byte_array()).await.unwrap().unwrap();
	assert_eq!(r.server.store.forfeit_count(&ida, row.round_id).await.unwrap(), (1, 0, 1));

	// The window passes: the round is dropped unbroadcast, B voided.
	advance_mtp(&r, 700).await;
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	let row = r.server.store.round_by_txid(&tx.txid().to_byte_array()).await.unwrap().unwrap();
	assert_eq!(row.state, RoundState::Lost);
	let stb = status(&r, &idb);
	println!("B: {} — {}", stb["state"], stb["void_reason"]);
	assert_eq!(stb["state"], "void");
	assert!(stb["void_reason"].as_str().unwrap().contains("its forfeits did not come within 600 s"), "{}", stb);
	assert_eq!(stb["inputs"][0]["returned"], true);
	let coin_b = r.server.store.leaf(&b.id.0).await.unwrap().unwrap();
	println!("B's coin: {:?}", coin_b.state);
	assert_eq!(coin_b.state, server::store::LeafState::Live);
	assert_eq!(status(&r, &ida)["state"], "pending", "A runs again");

	// The dropped round can never confirm: one of its coins is spent by the
	// operator, final; the node refuses the round, and so does a block.
	let (coin, by) = spent_otherwise(&r, &tx).await.expect("a coin of the dropped round spent by the operator");
	loop {
		r.produce().await;
		r.bury().await;
		r.synced().await;
		if r.server.finality.status(&by).await.unwrap().is_final() {
			break;
		}
	}
	let (ok, why, _) = tokio::task::block_in_place(|| r.server.finality.source().test_accept(&tx)).unwrap();
	println!("dropped round {}: its coin {} spent by {}, final; the node: {} {:?}", tx.txid(), coin, by, ok, why);
	assert!(!ok);
	refused_in_block(&r, "the dropped round", &tx, "bad-txns-inputs-missingorspent");

	// A runs again, alone, in a round that goes out once its forfeit is in,
	// and completes.
	let again = r.server.rounds.run_round().await.unwrap().expect("A's round");
	assert!(again.broadcast.starts_with("held"));
	assert_eq!(again.participations, 1);
	round_final(&r, &again.tx.txid()).await;
	let sta = status(&r, &ida);
	println!("A after its round is final: {}", sta["state"]);
	let ma = common::client::made(&ida).unwrap();
	let (valid, record, _) = validate_new_leaf(&r, &ida, 0, &a1, &ma.leaves[0].unwrap().1);
	let done = released(&r, &ida, &ma).await;
	assert!(done["preimage"].as_str().is_some(), "{}", done);
	assert_eq!(record.schedule, arca_covenant::ClockSchedule::never(xonly(&r.s)));
	println!("A's new leaf {} in round {}: {} of X, never expires; preimage out", valid.leaf_id, again.tx.txid(), record.value);
	let leaf = r.server.store.leaf(&valid.leaf_id.0).await.unwrap().unwrap();
	assert_eq!(leaf.state, server::store::LeafState::Live);
}

/// The participation `id`, its round final: its forfeits asked for again,
/// as a wallet does at its next sync, and the preimage taken.
async fn released(r: &Running, id: &[u8; 32], m: &common::client::Made) -> Value {
	use common::client::{auths_json, forfeit_sig};
	let st = status(r, id);
	let txid = common::client::txid(st["round"]["txid"].as_str().unwrap());
	let round = r.rt.client().raw_transaction(&txid).unwrap();
	let (owner, nonce) = m.leaves[0].unwrap();
	let key = common::client::key_of(&owner).unwrap();
	let (valid, record, _) = validate_new_leaf(r, id, 0, &key, &nonce);
	let mut forfeits = vec![];
	for h in &m.coins {
		let mut bases = vec![];
		server::coins::bases(&r.server.store, &h.record, &mut bases).await.unwrap();
		let old = h.record.resolve(&bases, &r.policy()).unwrap();
		let f = common::flow::forfeit_for(&old, &valid, &round, &st);
		forfeits.push(json!({"leaf_id": h.id.to_string(), "signature": forfeit_sig(&f, &h.key)}));
	}
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(id), "forfeits": forfeits,
		"leaves": [auths_json(&valid, &key, common::rounds::created(&record))]})).ok();
	assert_eq!(done["state"], "released", "{}", done);
	let _ = unhex;
	done
}

/// The service horizon of the batches: five days, so a coin of round 1 is
/// still taken for two days before its exit deadline.
const HORIZON: u32 = 5 * 86_400;

/// A coin given up, a coin paid on out of round to a receiver who stays
/// away, and a holder who stays away, all in one batch without a sweep: at
/// the batch's service horizon the operator collects it on the chain. The
/// absent holder's coin lands on the chain as its own leaf, under its key;
/// so does the absent receiver's, through its lineage's checkpoint and
/// reassignment; the given-up coin is brought down to its leaf, forfeited
/// and claimed, its value the operator's. Before the horizon nothing of the
/// batch is published, and from three days before it no off-chain spend of
/// its coins is taken.
#[tokio::test(flavor = "multi_thread")]
async fn at_the_horizon_absent_holders_coins_land_on_the_chain_as_their_own() {
	use common::flow::{drive, has, log, refresh, settle, Coin};
	let mut r = Running::start_with(|c, _| {
		c.batches.no_sweep = true;
		c.batches.holder_batches = Some(0);
		c.batches.collect_after_seconds = Some(HORIZON);
	}).await;
	let (x, s) = (r.x, xonly(&r.s));
	for _ in 0..3 {
		r.fund_wallet_in(x, 50_000_000).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let mut boards = vec![];
	for n in ["A", "B", "D"] {
		let k = keypair(&format!("H {} board", n));
		let (held, tx) = credited_board(&mut r, &k, x).await;
		boards.push(Coin { held, bases: vec![tx] });
	}
	let keys: Vec<_> = ["H A", "H B", "H D"].iter().map(|n| keypair(n)).collect();
	let first = refresh(&mut r, &[(&boards[0], &keys[0]), (&boards[1], &keys[1]), (&boards[2], &keys[2])]).await;
	let round1 = first[0].round.clone();
	let row1 = r.server.store.round_by_txid(&round1.txid().to_byte_array()).await.unwrap().unwrap();
	let horizon = row1.created_mtp + HORIZON;
	let b = r.server.store.batches(row1.round_id).await.unwrap().remove(0);
	println!("round 1 {}: one batch without a sweep, {} leaves, its horizon at median time {}", round1.txid(), first.len(), horizon);
	assert_eq!(b.collect_mtp, Some(horizon));
	drive(&r, "round 1's boards forfeited and claimed", 12, |l| common::flow::claimed(l) == 3).await;
	settle(&r).await;

	// A refreshes again and keeps its release; B pays C out of round; D and
	// C stay away.
	let a2 = keypair("H A again");
	let second = refresh(&mut r, &[(&first[0].new, &a2)]).await;
	println!("A's coin given up in round 2 {}", second[0].round.txid());
	let ck = keypair("H C");
	let (c_leaf, c_nonce) = common::client::new_leaf(&ck);
	let vb = first[1].new.valid(&r);
	let kept = vb.value - 2_000;
	let done = r.http.post("cosign_transfer", &common::client::transfer_body(&[(&first[1].new.held, vb.clone(), kept)],
		&[(x, kept - 2_000, c_leaf)], s, r.chain)).ok();
	println!("B paid C {} out of round: transfer {}", kept - 2_000, done["transfer_id"]);
	let (_, c_id, c_record) = r.http.mailbox(&ck, &r.chain, 0)[0].clone();
	let c = Coin { held: Held { key: ck, nonce: c_nonce, id: c_id, record: c_record }, bases: first[1].new.bases.clone() };
	let d = &first[2].new;

	// Before the horizon: nothing of round 1's batch goes on the chain.
	for _ in 0..3 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		r.produce().await;
	}
	let before: Vec<_> = log(&r).await.into_iter().filter(|w| w.kind == "unroll" || w.kind == "entry").collect();
	assert!(before.is_empty(), "nothing unrolled before the horizon: {:?}", before.iter().map(|w| &w.detail).collect::<Vec<_>>());

	// Within three days of the horizon, no off-chain spend of its coins.
	let now = common::rounds::mtp(&r).to_consensus_u32();
	advance_mtp(&r, horizon - 3 * 86_400 + 3_600 - now).await;
	r.synced().await;
	let (l, _) = common::client::new_leaf(&keypair("H D, paid"));
	let vd = d.valid(&r);
	let refused = r.http.post("cosign_transfer", &common::client::transfer_body(&[(&d.held, vd.clone(), vd.value - 2_000)],
		&[(x, vd.value - 4_000, l)], s, r.chain));
	println!("D's transfer within three days of the horizon: {} {:?}", refused.status, refused.refusal());
	assert_eq!(refused.refusal().0, "invalid_coin");
	let (w, _) = want_leaf(&keypair("H D, round"), x, vd.value);
	let (body, _) = participation_body(&[&d.held], &[w], &[], None, s, r.chain);
	let refused = r.http.post("submit_participation", &body);
	println!("D's refresh within three days of the horizon: {} {:?}", refused.status, refused.refusal());
	assert!(refused.refusal().1.contains("whose service ends at median time"), "{:?}", refused.refusal());

	// Past the horizon: the operator collects the batch.
	let pool_before = r.server.wallet.balance().await.unwrap().get(&x).copied().unwrap_or(0);
	let now = common::rounds::mtp(&r).to_consensus_u32();
	advance_mtp(&r, horizon + 600 - now).await;
	let script = |id: &arca_covenant::LeafId| {
		let store = r.server.store.clone();
		let id = id.0;
		async move { store.leaf(&id).await.unwrap().unwrap().script_pubkey }
	};
	let (d_spk, c_spk) = (script(&d.held.id).await, script(&c.held.id).await);
	let a_id = first[0].new.held.id.0.to_vec();
	let blocks = drive(&r, "round 1's batch collected", 30, |l| has(l, "claim", &a_id)
		&& l.iter().any(|w| w.kind == "reassignment")).await;
	for _ in 0..3 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		settle(&r).await;
	}
	let _ = blocks;
	for w in log(&r).await.iter().filter(|w| ["unroll", "entry", "forfeit", "claim", "checkpoint", "reassignment"].contains(&w.kind.as_str())) {
		let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
		println!("  collected: {} {} ({} vB): {}", w.kind, tx.txid(), tx.vsize(), w.detail);
	}
	let on_chain = |spk: Vec<u8>| {
		let store = r.server.store.clone();
		async move { store.sightings_of(&spk).await.unwrap() }
	};
	let d_seen = on_chain(d_spk.clone()).await;
	let c_seen = on_chain(c_spk.clone()).await;
	println!("D's leaf on the chain at {:?}; C's at {:?}", d_seen, c_seen);
	assert_eq!(d_seen.len(), 1, "the absent holder's coin is an on-chain leaf of its own");
	assert_eq!(c_seen.len(), 1, "the absent receiver's coin is an on-chain leaf of its own");
	for (who, seen, spk, value) in [("D", &d_seen, &d_spk, vd.value), ("C", &c_seen, &c_spk, kept - 2_000)] {
		let op = OutPoint::new(elements::Txid::from_byte_array(seen[0].0), seen[0].1);
		assert!(r.unspent(&op), "{}'s leaf is unspent, its holder's to take", who);
		let tx = r.rt.client().raw_transaction(&op.txid).unwrap();
		let out = &tx.output[op.vout as usize];
		assert_eq!(out.script_pubkey.as_bytes(), &spk[..]);
		assert_eq!(out.value.explicit(), Some(value), "{}'s leaf holds its whole coin", who);
		assert!(r.server.finality.status(&op.txid).await.unwrap().is_final(), "{}'s leaf is final", who);
		println!("{}: leaf {} holds {} of X under its own key, final", who, op, value);
	}
	for w in log(&r).await {
		assert_eq!(w.state, server::store::NurseryState::Final, "{} {} is final", w.kind, w.detail);
	}
	let pool_after = r.server.wallet.balance().await.unwrap().get(&x).copied().unwrap_or(0);
	println!("the operator's pool of X: {} before the collection, {} after (A's forfeited coin claimed, less fees)", pool_before, pool_after);
	assert!(pool_after > pool_before + VALUE / 2, "A's forfeited coin is the operator's");
	let st = status(&r, &second[0].id);
	println!("A's refresh: {}", st["state"]);
}
