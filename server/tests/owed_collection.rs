//! Batches without a sweep whose coins the operator is owed are collected
//! early (`[batches] collect_owed_after_seconds`).
//!
//! A batch without a sweep comes back by RECLAIM, by RECLAIM-D, or at its
//! service horizon, 28 days after its round. A coin given up beside a holder
//! who went away holds the operator's capital until then. With the option, a
//! tree batch without a sweep older than the age set has the paths to the
//! coins the operator is owed brought on the chain, forfeited and claimed,
//! long before its horizon: only coins given up in a round that is final,
//! and coins paid on out of round whose transfer's coins were all given up
//! so. No live coin lands: a holder's coin stays in the Ark, refreshable,
//! payable and exitable as before, and the chain refuses the operator any
//! spend of it.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::{AssetId, OutPoint, Transaction};

use arca_covenant::spend::FeeSource;
use arca_covenant::{Forfeit, Pair, RelativeTime};
use common::client::{participation_body, random32, want_leaf, Held};
use common::flow::{drive, has, log, refresh, release, settle, Coin, Refreshed};
use common::keys::{keypair, xonly};
use common::rounds::{advance_mtp, credited_board, hand_over_held, mtp, round_state, status, VALUE};
use common::running::Running;
use server::store::{LeafState, NurseryState, RoundRow, RoundState};

/// The age past which the paths to the coins the operator is owed are
/// collected: three days after the round.
const OWED: u32 = 3 * 86_400;

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

async fn round_of(r: &Running, tx: &Transaction) -> RoundRow {
	r.server.store.round_by_txid(&tx.txid().to_byte_array()).await.unwrap().unwrap()
}

async fn in_flight(r: &Running) -> u64 {
	r.server.store.pool_flow().await.unwrap().values().map(|p| p.in_flight).sum()
}

async fn on_chain(r: &Running, spk: &[u8]) -> Vec<OutPoint> {
	r.server.store.sightings_of(spk).await.unwrap().into_iter()
		.map(|(t, v)| OutPoint::new(elements::Txid::from_byte_array(t), v)).collect()
}

async fn landed(r: &Running, id: [u8; 32]) -> Vec<OutPoint> {
	let row = r.server.store.leaf(&id).await.unwrap().unwrap();
	on_chain(r, &row.script_pubkey).await
}

/// Settles until every transaction of the watcher's is final.
async fn all_final(r: &Running) {
	for _ in 0..10 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		settle(r).await;
		if log(r).await.iter().all(|w| w.state == NurseryState::Final) {
			return;
		}
	}
	panic!("the watcher's transactions are not all final: {:?}", log(r).await.iter().filter(|w| w.state != NurseryState::Final)
		.map(|w| (&w.kind, &w.detail)).collect::<Vec<_>>());
}

/// The live shape: twelve coins refreshed into one batch without a sweep
/// (three lowest nodes of four). On the first node every holder refreshes
/// again and releases it: RECLAIM, which the option leaves to itself. On
/// the second, A gives its coin up beside D, E and Q, who went away. On the
/// third, A2 gives its coin up, B pays C out of round and C gives that coin
/// up, G pays H, who goes away, and F gives its coin up only after the
/// age, in a round broadcast but not yet final.
///
/// - Before the age, nothing of the given-up coins' paths moves.
/// - Past it: A's, A2's and C's forfeits are claimed (C's through B's
///   checkpoint and reassignment), while F's round is not final nothing of
///   F's coin moves, and once it is F's forfeit is claimed too. In flight
///   falls to nothing. No live coin lands: D's, E's, Q's, G's and H's
///   leaves are not on the chain, and the batch keeps its 28-day horizon.
/// - The chain refuses the operator E's coin, forced into blocks with
///   `-par=1`: its entry spent anywhere but E's leaf, and E's leaf spent by
///   a forfeit signed with A's owner signature.
/// - D refreshes its coin for the whole of its value, H pays its coin on out
///   of round, and E takes its coin home: its exit, past its delay, is mined.
#[tokio::test(flavor = "multi_thread")]
async fn given_up_coins_come_back_early_and_no_live_coin_lands() {
	let mut r = Running::start_plain(|c, _| {
		c.batches.no_sweep = true;
		c.batches.holder_batches = Some(0);
		c.batches.collect_owed_after_seconds = Some(OWED);
	}).await;
	let (x, s) = (r.x, xonly(&r.s));
	for _ in 0..4 {
		r.fund_wallet_in(x, 50_000_000).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;

	// Round 1: twelve boards into one batch without a sweep.
	let mut boards = vec![];
	for i in 0..16 {
		let k = keypair(&format!("O{} board", i));
		let (held, tx) = credited_board(&mut r, &k, x).await;
		boards.push(Coin { held, bases: vec![tx] });
	}
	let keys: Vec<_> = (0..16).map(|i| keypair(&format!("O{}", i))).collect();
	let pairs: Vec<_> = boards.iter().zip(&keys).collect();
	let first = refresh(&mut r, &pairs).await;
	let round1 = round_of(&r, &first[0].round).await;
	let b1 = r.server.store.batches(round1.round_id).await.unwrap().remove(0);
	assert_eq!(b1.token, arca_covenant::clock::no_sweep_token().into_inner().to_byte_array(), "round 1's batch has no sweep");
	let horizon = round1.created_mtp + 28 * 86_400;
	assert_eq!(b1.collect_mtp, Some(horizon), "its service horizon, 28 days after its round");
	let (_, leaves) = r.server.store.batch(&round1.txid, b1.vout).await.unwrap().unwrap();
	let idx = |x: &Refreshed| leaves.iter().position(|l| l.leaf_id == x.new.held.id.0).unwrap();
	let mut by_idx: Vec<&Refreshed> = first.iter().collect();
	by_idx.sort_by_key(|x| idx(x));
	let nodes = arca_covenant::tree::spread(16, b1.radix as usize);
	println!("round 1 {}: a batch without a sweep, {} leaves, lowest nodes {:?}, horizon {}", round1.round_id, leaves.len(), nodes,
		horizon);
	assert_eq!(nodes.len(), 4);
	assert!(nodes.iter().all(|n| n.len() == 4));
	let (p, q, t, u) = (&by_idx[0..4], &by_idx[4..8], &by_idx[8..12], &by_idx[12..16]);
	let (a, d, e, qq) = (q[0], q[1], q[2], q[3]);
	let (a2, bb, g, f) = (t[0], t[1], t[2], t[3]);
	let ids: Vec<[u8; 32]> = leaves.iter().map(|l| l.leaf_id).collect();

	// B pays C, G pays H, out of round.
	let pay = |r: &Running, from: &Refreshed, to: &str, payer: &str| {
		let ck = keypair(to);
		let (c_leaf, c_nonce) = common::client::new_leaf(&ck);
		let v = from.new.valid(r);
		let kept = v.value - 2_000;
		let done = r.http.post("cosign_transfer", &common::client::transfer_body(&[(&from.new.held, v.clone(), kept)],
			&[(x, kept - 2_000, c_leaf)], s, r.chain)).ok();
		println!("{} paid {} {} out of round: transfer {}", payer, to, kept - 2_000, done["transfer_id"]);
		let (_, id, record) = r.http.mailbox(&ck, &r.chain, 0)[0].clone();
		Coin { held: Held { key: ck, nonce: c_nonce, id, record }, bases: from.new.bases.clone() }
	};
	let c = pay(&r, bb, "C", "B");
	let h = pay(&r, g, "H", "G");

	// Round 2: the first node's holders, A, A2 and C refresh; the first
	// node's holders release it.
	let gave: Vec<(&Coin, elements::secp256k1_zkp::Keypair)> = p.iter().map(|x| &x.new).chain([&a.new, &a2.new, &c, &u[0].new])
		.enumerate().map(|(i, coin)| (coin, keypair(&format!("O again {}", i)))).collect();
	let gave_refs: Vec<(&Coin, &elements::secp256k1_zkp::Keypair)> = gave.iter().map(|(c, k)| (*c, k)).collect();
	let second = refresh(&mut r, &gave_refs).await;
	for x in &second[0..4] {
		release(&r, x);
	}
	// R, on the fourth node, releases it as it gives its coin up.
	release(&r, &second[7]);
	let round2 = round_of(&r, &second[0].round).await;
	drive(&r, "the first node reclaimed", 20, |l| l.iter().any(|w| w.kind == "reclaim")).await;
	all_final(&r).await;
	println!("the first node, every holder of which released it: reclaimed");

	// Before the age nothing of the given-up coins' paths moves.
	let (a_old, a2_old, c_old, f_old) = (a.new.held.id.0.to_vec(), a2.new.held.id.0.to_vec(), c.held.id.0.to_vec(),
		f.new.held.id.0.to_vec());
	let seen = log(&r).await.len();
	for _ in 0..3 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		r.produce().await;
	}
	let early: Vec<_> = log(&r).await.into_iter().skip(seen)
		.filter(|w| ["unroll", "entry", "checkpoint", "reassignment"].contains(&w.kind.as_str())
			|| ids.iter().any(|i| w.subject == i.to_vec()))
		.map(|w| (w.kind, w.detail)).collect();
	assert!(early.is_empty(), "nothing of round 1's batch before the age: {:?}", early);
	for (who, id) in [("A", &a_old), ("A2", &a2_old), ("C", &c_old)] {
		assert!(landed(&r, id.clone().try_into().unwrap()).await.is_empty(), "{}'s given-up leaf is not on the chain before the age", who);
	}
	let flow_before = in_flight(&r).await;
	println!("in flight before the age: {} (A, A2 and C given up)", flow_before);
	assert!(flow_before >= 3 * VALUE - 10_000, "A's, A2's and C's coins are in flight");

	// Past the age: F gives its coin up, its round broadcast but not final.
	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, round1.created_mtp + OWED + 600 - now).await;
	r.synced().await;
	assert!(mtp(&r).to_consensus_u32() < horizon, "long before the service horizon");
	let fk = keypair("F again");
	let fv = f.new.valid(&r);
	let (w, _) = want_leaf(&fk, x, fv.value);
	let (body, f_part) = participation_body(&[&f.new.held], &[w], &[], None, s, r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().expect("F's round");
	assert_eq!(hand_over_held(&r, &built.tx.txid()).await, 1);
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.synced().await;
	let round3 = r.server.store.round_by_txid(&built.tx.txid().to_byte_array()).await.unwrap().unwrap();
	// The operator's half of F's forfeit, as the server's minute task gives
	// it once the node holds the round: F's forfeit is whole.
	let filled = r.server.forfeits.fill_unsigned().await.unwrap();
	let ff = r.server.store.forfeits_of(&f.new.held.id.0).await.unwrap();
	println!("F's refresh {}: round {} {:?}; {} forfeit(s) given the operator's half, F's whole: {}", common::client::hex(&f_part),
		round3.round_id, round3.state, filled, ff.iter().any(|x| x.round_id == round3.round_id));
	assert_eq!(round3.state, RoundState::Broadcast, "F's round is out, not final");
	assert!(ff.iter().any(|x| x.round_id == round3.round_id), "F's forfeit for round 3 is whole: only the round's state holds it back");

	drive(&r, "A's, A2's and C's coins collected", 40, |l| has(l, "claim", &a_old) && has(l, "claim", &a2_old) && has(l, "claim", &c_old))
		.await;
	let mid = log(&r).await;
	assert!(!mid.iter().any(|w| w.subject == f_old), "nothing of F's coin while its round is not final");
	assert!(landed(&r, f.new.held.id.0).await.is_empty(), "F's leaf is not on the chain while its round is not final");
	assert_eq!(r.server.store.round(round3.round_id).await.unwrap().unwrap().state, RoundState::Broadcast);
	println!("F's round not final: F's coin untouched");

	r.bury().await;
	round_state(&r, &built.tx.txid(), RoundState::Final).await;
	drive(&r, "F's coin collected once its round is final", 40, |l| has(l, "claim", &f_old)).await;
	all_final(&r).await;
	let all = log(&r).await;
	for w in all.iter().skip(seen) {
		let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
		println!("  collected: {} {} ({} vB): {}", w.kind, tx.txid(), tx.vsize(), w.detail);
		assert_eq!(w.state, NurseryState::Final, "{} {} is final", w.kind, w.detail);
		assert_ne!(w.kind, "sweep", "the collection never sweeps");
	}
	for (who, id) in [("A", &a_old), ("A2", &a2_old), ("C", &c_old), ("F", &f_old)] {
		assert!(common::flow::final_of(&all, "claim", id), "{}'s forfeit is claimed", who);
	}
	assert!(all.iter().any(|w| w.kind == "reassignment"), "C's coin came down through B's reassignment");
	assert!(mtp(&r).to_consensus_u32() < horizon, "all of it before the service horizon");

	// No live coin landed, and the batch keeps its horizon.
	for (who, id) in [("D", d.new.held.id.0), ("E", e.new.held.id.0), ("Q", qq.new.held.id.0), ("G", g.new.held.id.0),
		("H", h.held.id.0)] {
		let row = r.server.store.leaf(&id).await.unwrap().unwrap();
		let at = on_chain(&r, &row.script_pubkey).await;
		println!("{}'s coin: {:?}, its leaf on the chain at {:?}", who, row.state, at);
		assert!(at.is_empty(), "{}'s leaf is not landed", who);
	}
	for (who, id) in [("D", d.new.held.id.0), ("E", e.new.held.id.0), ("Q", qq.new.held.id.0), ("H", h.held.id.0)] {
		assert_eq!(r.server.store.leaf(&id).await.unwrap().unwrap().state, LeafState::Live, "{}'s coin is live", who);
	}
	for p in p.iter() {
		assert!(!all.iter().any(|w| w.subject == p.new.held.id.0.to_vec() && w.kind != "reclaim"), "the reclaimed node's coins are left to it");
	}
	assert!(!ids.is_empty());
	assert_eq!(r.server.store.batches(round1.round_id).await.unwrap()[0].collect_mtp, Some(horizon), "the batch keeps its horizon");
	for (n, round) in [("2", &round2), ("3", &round3)] {
		let b = r.server.store.batches(round.round_id).await.unwrap().remove(0);
		let s = r.server.store.tree_sightings(round.round_id, b.vout).await.unwrap();
		assert!(s.iter().all(|o| o.txid == round.txid), "nothing of round {}'s batch on the chain past its batch output: {} output(s)", n, s.len());
	}
	let flow_after = in_flight(&r).await;
	println!("in flight: {} before the age, {} after the collection", flow_before, flow_after);
	assert_eq!(flow_after, 0, "every coin given up is back");

	// The fourth node, unrolled to R's leaf, can no longer be reclaimed. Its
	// other holders come back, refresh and release it: their coins are
	// collected as any others, not left to a RECLAIM that cannot come.
	let r_old = u[0].new.held.id.0.to_vec();
	assert!(common::flow::final_of(&all, "claim", &r_old), "R's forfeit is claimed");
	let back: Vec<(Coin, elements::secp256k1_zkp::Keypair)> = u[1..].iter().enumerate()
		.map(|(i, x)| (x.new.clone(), keypair(&format!("O back {}", i)))).collect();
	let back_refs: Vec<(&Coin, &elements::secp256k1_zkp::Keypair)> = back.iter().map(|(c, k)| (c, k)).collect();
	let fourth = refresh(&mut r, &back_refs).await;
	for x in &fourth {
		release(&r, x);
	}
	println!("the fourth node's other holders refreshed and released it; in flight {}", in_flight(&r).await);
	let olds: Vec<Vec<u8>> = u[1..].iter().map(|x| x.new.held.id.0.to_vec()).collect();
	drive(&r, "the fourth node's coins collected", 40, |l| olds.iter().all(|o| has(l, "claim", o))).await;
	all_final(&r).await;
	let flow_after = in_flight(&r).await;
	println!("in flight once the fourth node's coins are collected: {}", flow_after);
	assert_eq!(flow_after, 0, "every coin given up on the unrolled node is back");

	// The chain refuses the operator E's coin. Its entry is on the chain.
	let ev = &e.new_valid;
	let st = r.server.store.clone();
	let (id1, vout1) = (round1.round_id, b1.vout);
	let tree_out = move |spk: elements::Script| {
		let store = st.clone();
		let (id, vout) = (id1, vout1);
		async move {
			store.tree_sightings(id, vout).await.unwrap().into_iter().filter(|o| o.script_pubkey == spk.as_bytes())
				.map(|o| OutPoint::new(elements::Txid::from_byte_array(o.txid), o.vout)).collect::<Vec<_>>()
		}
	};
	let entry_at = tree_out(ev.branch.entry_output().script_pubkey).await;
	assert_eq!(entry_at.len(), 1, "E's entry is on the chain, where A's path unrolled its node");
	let entry_at = entry_at[0];
	assert!(r.unspent(&entry_at));
	let mut to_bare = ev.branch.entry_tx(entry_at, &e.preimage, &FeeSource::Reserve).unwrap().tx;
	to_bare.output[0].script_pubkey = common::node::op_true();
	refused_in_block(&r, "E's entry, unlocked into a bare script", &to_bare, "Script failed an OP_EQUALVERIFY operation");
	let mut to_operator = ev.branch.entry_tx(entry_at, &e.preimage, &FeeSource::Reserve).unwrap().tx;
	to_operator.output[0].script_pubkey = arca_covenant::ConnectorPolicy { operator: s }.script_pubkey();
	assert_eq!(to_operator.output[0].script_pubkey.as_bytes()[0], 0x51, "a witness v1 program of the operator's");
	refused_in_block(&r, "E's entry, unlocked into the operator's own taproot output", &to_operator,
		"Script evaluated without error but finished with a false/empty top stack element");
	// E brings its own leaf on the chain; the operator holds A's forfeit, not E's.
	let land = ev.branch.entry_tx(entry_at, &e.preimage, &FeeSource::Reserve).unwrap().tx;
	r.rt.client().generate_block("raw(51)", &[&land]).unwrap();
	let e_leaf = OutPoint::new(land.txid(), 0);
	let e_value = land.output[0].value.explicit().unwrap();
	let fa = r.server.store.forfeits_of(&a.new.held.id.0).await.unwrap().pop().expect("A's forfeit");
	let forged = Forfeit::new(ev.branch.leaf, (x, ev.branch.entry.value), ev.leaf_id, fa.forfeit.unlock_hash,
		AssetId::from_byte_array(fa.forfeit.connector_asset), RelativeTime::from_units(fa.forfeit.refund_delay_units).unwrap(),
		fa.forfeit.margin).unwrap();
	let pair = Pair {
		operator: arca_covenant::sign::sign_digest(&r.s, &forged.message().digest, &random32()),
		owner: elements::secp256k1_zkp::schnorr::Signature::from_slice(&fa.forfeit.owner_sig).unwrap(),
	};
	let tx = forged.tx(e_leaf, &pair, &FeeSource::Reserve).unwrap().tx;
	refused_in_block(&r, "E's leaf, forfeited by the operator with A's signature", &tx, "Invalid Schnorr signature");
	let owned = Pair { operator: pair.operator, owner: arca_covenant::sign::sign_digest(&e.new.held.key, &forged.message().digest, &random32()) };
	let ok = forged.tx(e_leaf, &owned, &FeeSource::Reserve).unwrap().tx;
	println!("the same forfeit signed by E: {:?}", common::flow::verdict(&r, &ok));
	assert_eq!(common::flow::verdict(&r, &ok), Ok(()), "with E's signature the node takes it");

	// D refreshes its coin as before, for the whole of it.
	r.synced().await;
	let dv = d.new.valid(&r);
	let again = refresh(&mut r, &[(&d.new, &keypair("D again"))]).await;
	println!("D's coin {} (its entry {:?} on the chain) refreshed into {}: {}", dv.id, tree_out(d.new_valid.branch.entry_output().script_pubkey).await,
		again[0].new.held.id, again[0].new.valid(&r).value);
	assert_eq!(again[0].new.valid(&r).value, dv.value);

	// H, whose coin rests on G's leaf (G's entry on the chain now), pays it
	// on out of round as before.
	let g_entry = tree_out(g.new_valid.branch.entry_output().script_pubkey).await;
	assert_eq!(g_entry.len(), 1, "G's entry is on the chain");
	let hv = h.valid(&r);
	let (i_leaf, _) = common::client::new_leaf(&keypair("I"));
	let done = r.http.post("cosign_transfer", &common::client::transfer_body(&[(&h.held, hv.clone(), hv.value - 2_000)],
		&[(x, hv.value - 4_000, i_leaf)], s, r.chain));
	println!("H's payment out of round, its payer's entry {:?} on the chain: {} {}", g_entry, done.status, done.json["transfer_id"]);
	assert!(done.json["transfer_id"].is_string(), "the operator co-signs H's payment: {}", done.json);

	// E takes its coin home: past its exit delay, its exit is mined.
	r.produce().await;
	advance_mtp(&r, ev.branch.leaf.exit_delay.seconds() as u32 + 600).await;
	let exit = common::flow::exit_tx(&r, &ev.branch.leaf, e_leaf, x, e_value, &e.new.held.key);
	let h0 = r.rt.client().block_count().unwrap();
	r.rt.client().generate_block("raw(51)", &[&exit]).unwrap();
	println!("E's exit {} of {} mined at height {}", exit.txid(), e_value, h0 + 1);
	assert!(!r.unspent(&e_leaf), "E's leaf is spent by E's exit");
	let _ = status(&r, &f_part);
}

/// The age is shorter than the service horizon: otherwise the server refuses
/// to start, in words.
#[tokio::test(flavor = "multi_thread")]
async fn the_age_is_shorter_than_the_horizon() {
	let r = Running::start_plain(|_, _| {}).await;
	r.server.stop();
	let mut c = r.config.clone();
	c.batches.no_sweep = true;
	c.batches.collect_owed_after_seconds = Some(28 * 86_400);
	let e = server::server::Server::start(&c).await.err().expect("refused").to_string();
	println!("an age at the horizon: {}", e);
	assert!(e.contains("collect_owed_after_seconds (2419200) is not less than batches.collect_after_seconds (2419200)"), "{}", e);
	c.batches.collect_owed_after_seconds = Some(0);
	let e = server::server::Server::start(&c).await.err().expect("refused").to_string();
	println!("an age of 0: {}", e);
	assert!(e.contains("collect_owed_after_seconds is at least 1"), "{}", e);
}
