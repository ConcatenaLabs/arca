//! Batches with a sweep made before batches without one, collected early
//! (`[batches] collect_sweep_batches_before`).
//!
//! An operator that turned `no_sweep` on still holds the batches with a
//! sweep it built before. Its capital in them comes back by RECLAIM, by
//! RECLAIM-D, or at their expiry; a coin given up beside a live one, or one
//! paid on out of round, holds it until then. With the option on, each such
//! batch made before the cut gets a service horizon, and past it the
//! operator brings on the chain the coins their owners gave up and claims
//! their forfeits, through the unroll and the forfeit, never the sweep. No
//! live coin lands: a holder's coin stays where it was, its holder's to
//! refresh as before, and the chain refuses the operator any spend of it.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::{AssetId, OutPoint, Transaction};

use arca_covenant::spend::FeeSource;
use arca_covenant::{Forfeit, Pair, RelativeTime};
use common::client::{random32, Held};
use common::flow::{drive, has, log, refresh, release, settle, Coin, Refreshed};
use common::keys::{keypair, xonly};
use common::rounds::{advance_mtp, credited_board, mtp, VALUE};
use common::running::Running;
use server::store::{LeafState, NurseryState, RoundRow};

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

async fn horizon(r: &Running, round: &RoundRow) -> Option<u32> {
	let b = r.server.store.batches(round.round_id).await.unwrap();
	assert_eq!(b.len(), 1, "one batch in round {}", round.round_id);
	b[0].collect_mtp
}

async fn in_flight(r: &Running) -> u64 {
	r.server.store.pool_flow().await.unwrap().values().map(|p| p.in_flight).sum()
}

async fn on_chain(r: &Running, spk: &[u8]) -> Vec<OutPoint> {
	r.server.store.sightings_of(spk).await.unwrap().into_iter()
		.map(|(t, v)| OutPoint::new(elements::Txid::from_byte_array(t), v)).collect()
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

/// The early horizon of the batches with a sweep: three days after their
/// round.
const EARLY: u32 = 3 * 86_400;

/// Twelve coins refreshed into one batch with a sweep (three lowest nodes
/// of four). On the first node every holder refreshes again and releases
/// it: RECLAIM. On the second, A gives its coin up, and D, E and another
/// holder stay. On the third, A2 gives its coin up, B pays C out of round
/// and C gives that coin up, G pays H out of round, H staying away, and B2
/// pays J together with K's coin of a later batch with a sweep, made after
/// the cut, and J gives its coin up. Then the operator turns `no_sweep` on
/// with the batches with a sweep made before the cut collected three days
/// after their round, and builds a batch without a sweep (L).
///
/// - Only the first batch gets a horizon; K's batch, the refresh round's
///   batch, and L's (its own 28 days) keep theirs. Before the horizon
///   nothing of the batch goes on the chain.
/// - Past it: A's, A2's and C's forfeits are claimed (C's through B's
///   checkpoint and reassignment, every coin of which was given up), and
///   nothing else is in flight but J's coin, left to its batches' expiry
///   since its reassignment needs K's leaf of round 2 on the chain; D's,
///   E's, G's, H's, B2's, K's and J's leaves never land; nothing of K's,
///   the refresh round's or L's batch moves; no sweep.
/// - The chain refuses the operator E's coin: its entry spent anywhere but
///   E's leaf, and E's leaf (once E brought it on the chain itself) spent by
///   a forfeit signed by A, forced into a block with `-par=1`.
/// - D, whose coin's entry is on the chain now, refreshes it at the
///   operator as before, for the whole of its value, and H pays its coin on
///   out of round, its payer's entry on the chain.
/// - Turned off again, the horizon is taken off at start.
#[tokio::test(flavor = "multi_thread")]
async fn old_sweep_batches_give_back_given_up_coins_and_land_no_live_coin() {
	let mut r = Running::start_plain(|c, _| {
		c.batches.no_sweep = false;
		c.batches.holder_batches = Some(0);
	}).await;
	let (x, s) = (r.x, xonly(&r.s));
	for _ in 0..4 {
		r.fund_wallet_in(x, 50_000_000).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;

	// Round 1: nine boards into one batch with a sweep.
	let mut boards = vec![];
	for i in 0..12 {
		let k = keypair(&format!("S{} board", i));
		let (held, tx) = credited_board(&mut r, &k, x).await;
		boards.push(Coin { held, bases: vec![tx] });
	}
	let keys: Vec<_> = (0..12).map(|i| keypair(&format!("S{}", i))).collect();
	let pairs: Vec<_> = boards.iter().zip(&keys).collect();
	let first = refresh(&mut r, &pairs).await;
	let round1 = round_of(&r, &first[0].round).await;
	let b1 = r.server.store.batches(round1.round_id).await.unwrap().remove(0);
	assert_ne!(b1.token, arca_covenant::clock::no_sweep_token().into_inner().to_byte_array(), "round 1's batch has a sweep");
	assert_eq!(b1.collect_mtp, None);
	let (_, leaves) = r.server.store.batch(&round1.txid, b1.vout).await.unwrap().unwrap();
	let idx = |x: &Refreshed| leaves.iter().position(|l| l.leaf_id == x.new.held.id.0).unwrap();
	let mut by_idx: Vec<&Refreshed> = first.iter().collect();
	by_idx.sort_by_key(|x| idx(x));
	let nodes = arca_covenant::tree::spread(12, b1.radix as usize);
	println!("round 1 {}: a batch with a sweep, {} leaves, lowest nodes {:?}", round1.round_id, leaves.len(), nodes);
	assert_eq!(nodes.len(), 3);
	assert!(nodes.iter().all(|n| n.len() == 4));
	let (p, q, t) = (&by_idx[0..4], &by_idx[4..8], &by_idx[8..12]);
	let (a, d, e) = (q[0], q[1], q[2]);
	let (a2, bb, g, b2) = (t[0], t[1], t[2], t[3]);
	advance_mtp(&r, 3_600).await;
	r.synced().await;
	let cut = mtp(&r).to_consensus_u32();

	// Round 2, after the cut: K's board, a batch with a sweep left alone.
	let kk = keypair("K board");
	let (held, tx) = credited_board(&mut r, &kk, x).await;
	let k_board = Coin { held, bases: vec![tx] };
	let second = refresh(&mut r, &[(&k_board, &keypair("K"))]).await;
	let round2 = round_of(&r, &second[0].round).await;

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
	// B2 and K together pay J: a transfer spending a leaf of round 1 and
	// one of round 2.
	let jk = keypair("J");
	let (j_leaf, j_nonce) = common::client::new_leaf(&jk);
	let (vb2, vk) = (b2.new.valid(&r), second[0].new.valid(&r));
	let (kb2, kk2) = (vb2.value - 2_000, vk.value - 2_000);
	let done = r.http.post("cosign_transfer", &common::client::transfer_body(&[(&b2.new.held, vb2.clone(), kb2),
		(&second[0].new.held, vk.clone(), kk2)], &[(x, kb2 + kk2 - 2_000, j_leaf)], s, r.chain)).ok();
	println!("B2 and K paid J {} out of round: transfer {}", kb2 + kk2 - 2_000, done["transfer_id"]);
	let (_, j_id, j_record) = r.http.mailbox(&jk, &r.chain, 0)[0].clone();
	let j = Coin { held: Held { key: jk, nonce: j_nonce, id: j_id, record: j_record },
		bases: [b2.new.bases.clone(), second[0].new.bases.clone()].concat() };
	let j_value = kb2 + kk2 - 2_000;

	// Round 3: the first node's holders, A, A2, C and J refresh; the first
	// node's holders release it.
	let gave: Vec<(&Coin, elements::secp256k1_zkp::Keypair)> = p.iter().map(|x| &x.new).chain([&a.new, &a2.new, &c, &j])
		.enumerate().map(|(i, coin)| (coin, keypair(&format!("again {}", i)))).collect();
	let gave_refs: Vec<(&Coin, &elements::secp256k1_zkp::Keypair)> = gave.iter().map(|(c, k)| (*c, k)).collect();
	let third = refresh(&mut r, &gave_refs).await;
	for x in &third[0..4] {
		release(&r, x);
	}
	let round3 = round_of(&r, &third[0].round).await;
	drive(&r, "the first node reclaimed", 20, |l| l.iter().any(|w| w.kind == "reclaim")).await;
	all_final(&r).await;
	println!("the first node, every holder of which released it: reclaimed");
	for w in log(&r).await {
		assert_ne!(w.kind, "sweep");
	}
	let held_before = in_flight(&r).await;
	println!("in flight before the option: {}", held_before);

	// The option, with batches without a sweep.
	r.config.batches.no_sweep = true;
	r.config.batches.collect_sweep_batches_before = Some(cut);
	r.config.batches.collect_sweep_batches_after_seconds = Some(EARLY);
	r.restart_server().await;
	r.synced().await;
	let due = round1.created_mtp + EARLY;
	assert_eq!(horizon(&r, &round1).await, Some(due), "round 1's batch, made before the cut, is collected {} s after it", EARLY);
	assert_eq!(horizon(&r, &round2).await, None, "round 2's batch, made after the cut, keeps its sweep alone");
	assert_eq!(horizon(&r, &round3).await, None, "round 3's batch, made after the cut, keeps its sweep alone");

	// Round 4, without a sweep: its own horizon, untouched by the option.
	let ll = keypair("L board");
	let (held, tx) = credited_board(&mut r, &ll, x).await;
	let l_board = Coin { held, bases: vec![tx] };
	let fourth = refresh(&mut r, &[(&l_board, &keypair("L"))]).await;
	let round4 = round_of(&r, &fourth[0].round).await;
	let own = horizon(&r, &round4).await;
	assert_eq!(own, Some(round4.created_mtp + 28 * 86_400), "a batch without a sweep has its own horizon");
	r.restart_server().await;
	r.synced().await;
	assert_eq!(horizon(&r, &round4).await, own);
	assert_eq!(horizon(&r, &round1).await, Some(due), "the horizon stands across a restart");
	println!("horizons: round 1 {:?} (cut {}), round 2 {:?}, round 3 {:?}, round 4 {:?}", horizon(&r, &round1).await, cut,
		horizon(&r, &round2).await, horizon(&r, &round3).await, horizon(&r, &round4).await);

	// Before the horizon nothing of round 1's batch moves (round 4's board
	// is forfeited and claimed first).
	drive(&r, "round 4's board claimed", 20, |l| l.iter().filter(|w| w.kind == "claim").count() >= 3).await;
	all_final(&r).await;
	let seen = log(&r).await.len();
	for _ in 0..3 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		r.produce().await;
	}
	let early: Vec<_> = log(&r).await.into_iter().skip(seen).map(|w| (w.kind, w.detail)).collect();
	assert!(early.is_empty(), "nothing before the horizon: {:?}", early);
	let flow_before = in_flight(&r).await;

	// Past it, the collection.
	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, due + 600 - now).await;
	let (a_old, a2_old) = (a.new.held.id.0.to_vec(), a2.new.held.id.0.to_vec());
	let c_old = c.held.id.0.to_vec();
	drive(&r, "round 1's given-up coins collected", 40, |l| has(l, "claim", &a_old) && has(l, "claim", &a2_old) && has(l, "claim", &c_old)).await;
	all_final(&r).await;
	let all = log(&r).await;
	for w in all.iter().skip(seen) {
		let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
		println!("  collected: {} {} ({} vB): {}", w.kind, tx.txid(), tx.vsize(), w.detail);
		assert_eq!(w.state, NurseryState::Final, "{} {} is final", w.kind, w.detail);
		assert_ne!(w.kind, "sweep", "the collection never sweeps");
	}
	for (who, x) in [("A", &a_old), ("A2", &a2_old), ("C", &c_old)] {
		assert!(common::flow::final_of(&all, "claim", x), "{}'s forfeit is claimed", who);
	}
	assert!(all.iter().any(|w| w.kind == "reassignment"), "C's coin came down through B's reassignment");
	let j_old = j.held.id.0.to_vec();
	assert!(!all.iter().any(|w| w.subject == j_old), "J's coin, paid from a leaf of round 2 as well, is left to its batch's expiry");

	// No live coin landed.
	let script = |id: [u8; 32]| {
		let store = r.server.store.clone();
		async move { store.leaf(&id).await.unwrap().unwrap() }
	};
	for (who, id) in [("D", d.new.held.id.0), ("E", e.new.held.id.0), ("G", g.new.held.id.0), ("H", h.held.id.0),
		("B2", b2.new.held.id.0), ("K", second[0].new.held.id.0), ("J", j.held.id.0)] {
		let row = script(id).await;
		let landed = on_chain(&r, &row.script_pubkey).await;
		println!("{}'s coin: {:?}, its leaf on the chain at {:?}", who, row.state, landed);
		assert!(landed.is_empty(), "{}'s leaf is not landed", who);
	}
	assert_eq!(script(d.new.held.id.0).await.state, LeafState::Live);
	assert_eq!(script(h.held.id.0).await.state, LeafState::Live);
	for (n, round) in [("2", &round2), ("3", &round3), ("4", &round4)] {
		let b = r.server.store.batches(round.round_id).await.unwrap().remove(0);
		let s = r.server.store.tree_sightings(round.round_id, b.vout).await.unwrap();
		assert!(s.iter().all(|o| o.txid == round.txid), "nothing of round {}'s batch on the chain past its batch output: {} output(s)", n, s.len());
		assert!(r.unspent(&OutPoint::new(elements::Txid::from_byte_array(round.txid), b.vout)), "round {}'s batch output unspent", n);
	}
	let flow_after = in_flight(&r).await;
	println!("in flight: {} before the collection, {} after (A's, A2's and C's {} each back)", flow_before, flow_after, VALUE);
	assert!(flow_before - flow_after >= 3 * VALUE - 10_000, "the given-up coins are no longer in flight");
	assert_eq!(flow_after, j_value, "J's coin alone is still in flight");

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
	// The control: the same transaction with E's own signature is valid
	// (asked of the node, not mined), so only the owner's half refused it.
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

	// Off again: the horizon is taken off at start.
	r.config.batches.collect_sweep_batches_before = None;
	r.restart_server().await;
	assert_eq!(horizon(&r, &round1).await, None, "off, round 1's batch has no horizon");
	assert_eq!(horizon(&r, &round4).await, own, "a batch without a sweep keeps its own");
	let _ = (held_before, k_board);
}

/// The option needs batches without a sweep: without `no_sweep` the server
/// refuses to start, in words.
#[tokio::test(flavor = "multi_thread")]
async fn the_option_needs_no_sweep() {
	let r = Running::start_plain(|_, _| {}).await;
	r.server.stop();
	let mut c = r.config.clone();
	c.batches.no_sweep = false;
	c.batches.collect_sweep_batches_before = Some(1_800_000_000);
	let e = server::server::Server::start(&c).await.err().expect("refused").to_string();
	println!("without no_sweep: {}", e);
	assert!(e.contains("collect_sweep_batches_before needs batches.no_sweep"), "{}", e);
}
