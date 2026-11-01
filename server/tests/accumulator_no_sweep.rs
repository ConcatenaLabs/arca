//! Accumulator batches without a sweep (`arca/accumulator-2`), against a
//! whole server on an anchored proof-of-stake regtest chain: `arca-signer` in
//! its own process, PostgreSQL, the minimal client playing every owner.
//!
//! An operator with `[batches] no_sweep` that expects 1 % of a batch's
//! leaves to leave on their own (`accumulator_exit_rate_ppm = 10000`)
//! refreshes 24 boards in one round:
//!
//! 1. The round pays one accumulator batch without a sweep and no token:
//!    every owner's record is of format version 4 and passes the wallet's
//!    check under `WalletPolicy::no_sweep`.
//! 2. Owners refresh out of it and release their slots; the watcher releases
//!    them on the chain, each release paying the operator what the slots
//!    weighed less its fee: one slot; then four slots of two rounds in one
//!    release, with an atom of each round's connector asset; then sixteen
//!    slots, which take two releases (14 and 2). `pool` shows the batch's
//!    value moving from `locked` to `released` and `reclaimable`, then back.
//! 3. At the batch's service horizon, after the releases, the operator
//!    collects what is left, following the batch through every release: an
//!    absent owner's slot goes out by the operator's own exit authorisation
//!    and lands as the owner's leaf, final; a slot given up with its forfeit
//!    and no release (an older wallet) is brought down to its leaf and its
//!    forfeit claimed; a coin paid on out of round from a slot lands under
//!    its holder's key through its checkpoint and reassignment.
//!
//! A second test loses the refresh round whose releases are stored and
//! brings it back: while it is lost its releases are retired and the watcher
//! tries none; once it is final again they are restored and released.
//!
//! The refusals of the release itself are the covenant's
//! (`covenant/tests/accumulator_release.rs`, every negative forced into a
//! block).
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::{AssetId, OutPoint, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::accumulator::AccumulatorRelease;
use arca_covenant::sign::sign_digest;
use arca_covenant::{
	Batch, ClockSchedule, CoinRecord, Forfeit, RelativeTime, ValidAccumulatorLeaf, ValidLeaf, ValidOrigin,
	WalletPolicy,
};
use common::client::{auths_json, exit_auth_json, forfeit_sig, hex, participation_body, random32, rebuild_batch, two_hours_ago, unhex,
	want_leaf, Held};
use common::flow::{drive, has, held_by, log, settle, Coin};
use common::keys::{keypair, xonly};
use common::rounds::{advance_mtp, created, credited_board, mtp, round_final, status, VALUE};
use common::running::Running;
use server::store::{NurseryState, RoundState, WatcherTxRow};

/// The service horizon: five days, so a coin of the first round is still
/// taken for two days before its exit deadline.
const HORIZON: u32 = 5 * 86_400;
const OWNERS: usize = 24;

async fn start() -> Running {
	let mut r = Running::start_with(|c, _| {
		c.batches.no_sweep = true;
		c.batches.holder_batches = Some(0);
		c.batches.accumulator_exit_rate_ppm = Some(10_000);
		c.batches.collect_after_seconds = Some(HORIZON);
	}).await;
	for _ in 0..4 {
		r.fund_wallet_in(r.x, 50_000_000).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r
}

/// A new leaf as its owner validated it.
#[derive(Clone)]
enum New {
	Tree(ValidLeaf),
	Acc(ValidAccumulatorLeaf),
}

/// A coin refreshed: the new coin, its key, the participation, the round,
/// its connector output and the batch kind of the new leaf.
struct Out {
	coin: Coin,
	id: [u8; 32],
	round: Transaction,
	c: u32,
	new: New,
}

/// The wallet's own check of a new leaf under the policy of a wallet that
/// takes batches without a sweep alone.
fn no_sweep_policy(r: &Running) -> WalletPolicy {
	WalletPolicy::no_sweep(r.chain, xonly(&r.s), mtp(r))
}

/// Gives up each of `coins` for one leaf of its whole value under a fresh key
/// (`tag` and its index), one participation each, in one round, made final;
/// each owner validates its new leaf from the published batch under
/// `WalletPolicy::no_sweep`, hands over its forfeit and authorisations (before
/// the round goes out, as the held round needs, and again for the
/// preimage), and, where `release` says so, releases its old slot.
async fn refresh(r: &mut Running, tag: &str, coins: &[&Coin], release: &[bool]) -> Vec<Out> {
	let mut ids = vec![];
	for (i, coin) in coins.iter().enumerate() {
		let v = coin.valid(r);
		let key = keypair(&format!("{} {}", tag, i));
		let (w, nonce) = want_leaf(&key, v.asset, v.value);
		let (body, id) = participation_body(&[&coin.held], &[w], &[], None, xonly(&r.s), r.chain);
		assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
		ids.push((id, nonce, key));
	}
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	assert!(built.broadcast.starts_with("held"), "{}", built.broadcast);
	round_final(r, &built.tx.txid()).await;
	let mut out = vec![];
	for ((coin, (id, nonce, key)), rel) in coins.iter().zip(ids).zip(release) {
		let st = status(r, &id);
		assert_eq!(st["round"]["txid"].as_str().unwrap(), built.tx.txid().to_string(), "every refresh in the one round");
		let o = &st["outputs"][0];
		let published = r.http.post("tree", &json!({"txid": st["round"]["txid"], "vout": o["batch_vout"]})).ok();
		let index = o["leaf_index"].as_u64().unwrap() as usize;
		let round: Transaction = r.rt.client().raw_transaction(&built.tx.txid()).unwrap();
		let c = st["round"]["connector_vout"].as_u64().unwrap() as u32;
		let delay = RelativeTime::from_units(st["refund_delay_units"].as_u64().unwrap() as u16).unwrap();
		let margin: u64 = st["inputs"][0]["margin"].as_str().unwrap().parse().unwrap();
		let old = coin.valid(r);
		let (new, f, leaf) = match rebuild_batch(&published) {
			Batch::Tree(tree) => {
				let record = tree.record(index);
				let v = record.validate(&round, &no_sweep_policy(r), &xonly(&key), &nonce).unwrap();
				let f = Forfeit::for_refresh(old.leaf, (old.asset, old.value), old.id, &v, &round, c, delay, margin).unwrap();
				let leaf = auths_json(&v, &key, created(&record));
				(New::Tree(v), f, leaf)
			},
			Batch::Accumulator(acc) => {
				let v = acc.record(index).validate(&round, &no_sweep_policy(r), &xonly(&key), &nonce).unwrap();
				let f = v.forfeit_for(old.leaf, (old.asset, old.value), old.id, &round, c, delay, margin).unwrap();
				let leaf = exit_auth_json(&v, &key, two_hours_ago());
				(New::Acc(v), f, leaf)
			},
		};
		let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&id),
			"forfeits": [{"leaf_id": coin.held.id.to_string(), "signature": forfeit_sig(&f, &coin.held.key)}], "leaves": [leaf]})).ok();
		assert_eq!(done["state"], "released", "{}", done);
		let new_id = match &new { New::Tree(v) => v.leaf_id, New::Acc(v) => v.leaf_id };
		let held = held_by(r, &key, nonce, new_id);
		if *rel {
			release_slot(r, &id, coin, &old, &new, &round, c);
		}
		out.push(Out { coin: Coin { held, bases: vec![round.clone()] }, id, round, c, new });
	}
	out
}

/// The owner of `coin`, a slot of an accumulator batch without a sweep it
/// gave up in participation `id` for `new`, releases the slot, naming the
/// connector asset of `round`.
fn release_slot(r: &Running, id: &[u8; 32], coin: &Coin, old: &arca_covenant::ValidCoin, new: &New, round: &Transaction, c: u32) {
	let ValidOrigin::Accumulator { valid: old_acc, .. } = &old.origin else { panic!("a slot of an accumulator batch") };
	let rel = match new {
		New::Tree(v) => AccumulatorRelease::for_refresh(old_acc, v, round, c),
		New::Acc(v) => AccumulatorRelease::for_accumulator_refresh(old_acc, v, round, c),
	}.unwrap();
	let sig = sign_digest(&coin.held.key, &rel.digest(), &random32());
	let a = r.http.post("release_leaves", &json!({"participation_id": hex(id), "releases": [{
		"leaf_id": coin.held.id.to_string(), "connector_asset": rel.connector.to_string(), "signature": hex(sig.as_ref())}]})).ok();
	assert_eq!(a["released"].as_array().unwrap().len(), 1, "{}", a);
}

/// The pool of `asset` as `/v1/chain` shows it.
fn pool(r: &Running, asset: AssetId) -> (u64, u64, u64) {
	let p = &r.http.get("chain").ok()["pool"][asset.to_string()];
	let n = |k: &str| p[k].as_str().unwrap_or("0").parse::<u64>().unwrap();
	(n("locked"), n("released"), n("reclaimable"))
}

/// The watcher's releases of the batch of root `root`.
async fn releases(r: &Running, root: &[u8; 32]) -> Vec<WatcherTxRow> {
	log(r).await.into_iter().filter(|w| w.kind == "reclaim" && w.subject == root.to_vec()).collect()
}

/// Checks the release `w` of `slots` of the batch, from the state `before`:
/// in a block, final; output 0 paying the operator's wallet what the slots
/// weigh less the fee; the rest, if any, under the next state at output 1.
/// Returns the state after it.
async fn check_release(r: &Running, w: &WatcherTxRow, acc: &arca_covenant::Accumulator, before: &arca_covenant::AccumulatorPolicy,
	slots: &[u16]) -> arca_covenant::AccumulatorPolicy
{
	let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
	assert_eq!(w.state, NurseryState::Final, "the release {} is final", tx.txid());
	assert!(r.rt.client().confirmations(&tx.txid()).unwrap() >= 1, "the release {} is in a block", tx.txid());
	let weight: u64 = slots.iter().map(|j| acc.slots()[*j as usize].weight().unwrap()).sum();
	let fee: u64 = tx.output.iter().filter(|o| o.is_fee() && o.asset.explicit() == Some(acc.params().asset)).filter_map(|o| o.value.explicit()).sum();
	let paid = tx.output[0].value.explicit().unwrap();
	let to_wallet = r.server.store.wallet_coin_at(&tx.txid().to_byte_array(), 0).await.unwrap();
	assert!(to_wallet.is_some(), "output 0 pays the operator's wallet");
	assert_eq!(paid + fee, weight, "the release pays the operator what the slots weighed, less its fee");
	let after = before.after_all(slots);
	let left = before.bitmap.count() as usize + slots.len() < acc.len();
	if left {
		assert_eq!(tx.output[1].script_pubkey, after.script_pubkey(), "the rest under the next state");
	}
	println!("  release {} ({} vB): slots {:?}, {} weighed, {} to the operator, fee {}, {} inputs, {} outputs", tx.txid(),
		tx.vsize(), slots, weight, paid, fee, tx.input.len(), tx.output.len());
	after
}

fn tx_of(w: &WatcherTxRow) -> Transaction {
	elements::encode::deserialize(&w.tx).unwrap()
}

/// The slot each of `coins` holds in its accumulator batch.
fn slots_of(coins: &[&Coin]) -> Vec<u16> {
	coins.iter().map(|c| match &c.held.record {
		CoinRecord::Accumulator { record, .. } => record.slot,
		_ => panic!("a slot of the accumulator batch"),
	}).collect()
}

/// Drives the watcher until it has published `n` releases of the batch of
/// `root` in all, then makes them final.
async fn released(r: &Running, what: &str, root: &[u8; 32], n: usize) -> Vec<WatcherTxRow> {
	let root_v = root.to_vec();
	drive(r, what, 8, |l| l.iter().filter(|w| w.kind == "reclaim" && w.subject == root_v).count() >= n).await;
	settle(r).await;
	settle(r).await;
	releases(r, root).await
}

#[tokio::test(flavor = "multi_thread")]
async fn accumulator_slots_are_released_and_collected_without_a_sweep() {
	let mut r = start().await;
	let (x, s) = (r.x, xonly(&r.s));
	let mut boards = vec![];
	for i in 0..OWNERS {
		let (held, tx) = credited_board(&mut r, &keypair(&format!("acc2 board {}", i)), x).await;
		boards.push(Coin { held, bases: vec![tx] });
	}

	// 1. One round, one accumulator batch without a sweep, no token.
	let first = refresh(&mut r, "acc2 U", &boards.iter().collect::<Vec<_>>(), &[false; OWNERS]).await;
	let round1 = first[0].round.clone();
	assert!(!round1.input.iter().any(|i| i.has_issuance()), "the round issues no token");
	let accs: Vec<&ValidAccumulatorLeaf> = first.iter().map(|o| match &o.new {
		New::Acc(v) => v,
		New::Tree(_) => panic!("a leaf of a tree: the operator built no accumulator batch"),
	}).collect();
	let vout = accs[0].batch_vout;
	assert!(accs.iter().all(|v| v.round_txid == round1.txid() && v.batch_vout == vout), "one batch");
	assert!(accs[0].policy.no_sweep());
	assert!(!round1.output.iter().any(|o| o.value.explicit() == Some(1) && o.asset.explicit() != Some(x)), "no token's atom");
	let st = status(&r, &first[0].id);
	let published = r.http.post("tree", &json!({"txid": st["round"]["txid"], "vout": vout})).ok();
	assert_eq!(published["kind"], "accumulator");
	let acc = match rebuild_batch(&published) {
		Batch::Accumulator(a) => a,
		Batch::Tree(_) => unreachable!(),
	};
	assert_eq!(acc.params().schedule, ClockSchedule::never(s));
	assert!(acc.clock0_script_pubkey().is_none());
	let records: Vec<&CoinRecord> = first.iter().map(|o| &o.coin.held.record).collect();
	for (rec, o) in records.iter().zip(&first) {
		let CoinRecord::Accumulator { record, .. } = rec else { panic!("an accumulator coin record") };
		let bytes = record.to_bytes().unwrap();
		assert_eq!(bytes[0], arca_covenant::accumulator::ACCUMULATOR_RECORD_VERSION_NO_SWEEP, "record format 4");
		o.coin.held.record.resolve(&o.coin.bases, &no_sweep_policy(&r)).expect("the wallet's check under WalletPolicy::no_sweep");
	}
	let root = acc.policy().root;
	println!("round {}: one accumulator batch without a sweep at output {}, {} slots holding {}, no token; every record is of format {} \
		and passes WalletPolicy::no_sweep", round1.txid(), vout, acc.len(), acc.total(),
		arca_covenant::accumulator::ACCUMULATOR_RECORD_VERSION_NO_SWEEP);
	let (locked0, released0, _) = pool(&r, x);
	println!("pool of X after round 1: locked {}, released {}", locked0, released0);
	assert!(locked0 >= acc.total());
	settle(&r).await;

	let coins: Vec<Coin> = first.iter().map(|o| o.coin.clone()).collect();
	let mut state = *acc.policy();

	// 2a. One slot.
	let a = refresh(&mut r, "acc2 A", &[&coins[0]], &[true]).await;
	let (l1, rel1, rec1) = pool(&r, x);
	println!("pool after slot 0's release is stored: locked {}, released {}, reclaimable {}", l1, rel1, rec1);
	let w0 = coins[0].valid(&r).value;
	assert!(rel1 >= w0 && rec1 >= w0, "the released slot is released and reclaimable");
	let rs = released(&r, "one slot released", &root, 1).await;
	state = check_release(&r, &rs[0], &acc, &state, &slots_of(&[&coins[0]])).await;
	let (l2, rel2, rec2) = pool(&r, x);
	println!("pool after its release: locked {}, released {}, reclaimable {}", l2, rel2, rec2);
	let back = tx_of(&rs[0]).output[0].value.explicit().unwrap();
	assert_eq!(l1 - l2, back, "locked falls by what the release paid back");
	assert!(rel2 + w0 == rel1 && rec2 + w0 == rec1, "nothing of the slot is released or reclaimable once it is back");
	let _ = a;

	// 2b. Four slots of two rounds, in one release.
	let b1 = refresh(&mut r, "acc2 B1", &[&coins[1], &coins[2]], &[true, true]).await;
	let b2 = refresh(&mut r, "acc2 B2", &[&coins[3], &coins[4]], &[true, true]).await;
	assert_ne!(b1[0].round.txid(), b2[0].round.txid());
	let rs = released(&r, "four slots of two rounds released", &root, 2).await;
	let tx: Transaction = elements::encode::deserialize(&rs[1].tx).unwrap();
	let ms: Vec<AssetId> = tx.input[1..].iter().filter_map(|i| {
		let prev = r.rt.client().raw_transaction(&i.previous_output.txid).ok()?;
		prev.output[i.previous_output.vout as usize].asset.explicit()
	}).filter(|a| *a != x).collect();
	let m1 = arca_covenant::connector_asset(b1[0].round.txid(), b1[0].c);
	let m2 = arca_covenant::connector_asset(b2[0].round.txid(), b2[0].c);
	assert!(ms.contains(&m1) && ms.contains(&m2), "an atom of each round's connector asset: {:?}", ms);
	state = check_release(&r, &rs[1], &acc, &state, &slots_of(&[&coins[1], &coins[2], &coins[3], &coins[4]])).await;

	// 2c. Sixteen slots: two releases.
	let many: Vec<&Coin> = coins[5..21].iter().collect();
	let c = refresh(&mut r, "acc2 C", &many, &[true; 16]).await;
	println!("sixteen slots given up in round {} ({} batch)", c[0].round.txid(), match c[0].new { New::Acc(_) => "an accumulator", New::Tree(_) => "a tree" });
	let rs = released(&r, "sixteen slots released", &root, 4).await;
	let slots = slots_of(&many);
	state = check_release(&r, &rs[2], &acc, &state, &slots[..14]).await;
	state = check_release(&r, &rs[3], &acc, &state, &slots[14..]).await;
	let (l3, rel3, rec3) = pool(&r, x);
	println!("pool after 21 slots are back: locked {}, released {}, reclaimable {}", l3, rel3, rec3);
	assert_eq!((rel3, rec3), (0, 0));

	// 3. The horizon. Slot 21 stays away; 22 refreshes and hands over its
	// forfeit alone, as an older wallet does; 23 pays H out of round, and H
	// stays away.
	let d = refresh(&mut r, "acc2 D", &[&coins[22]], &[false]).await;
	let hk = keypair("acc2 H");
	let (h_leaf, h_nonce) = common::client::new_leaf(&hk);
	let v23 = coins[23].valid(&r);
	let kept = v23.value - 2_000;
	let t = r.http.post("cosign_transfer", &common::client::transfer_body(&[(&coins[23].held, v23.clone(), kept)],
		&[(x, kept - 2_000, h_leaf)], s, r.chain)).ok();
	println!("slot 23 paid H {} out of round: transfer {}", kept - 2_000, t["transfer_id"]);
	let (_, h_id, h_record) = r.http.mailbox(&hk, &r.chain, 0)[0].clone();
	let h = Coin { held: Held { key: hk, nonce: h_nonce, id: h_id, record: h_record }, bases: coins[23].bases.clone() };
	let _ = d;
	let row1 = r.server.store.round_by_txid(&round1.txid().to_byte_array()).await.unwrap().unwrap();
	let horizon = row1.created_mtp + HORIZON;
	r.server.watcher.pass().await.unwrap();
	let before: Vec<_> = log(&r).await.into_iter().filter(|w| w.kind == "unroll" || w.kind == "entry").collect();
	assert!(before.is_empty(), "nothing taken out before the horizon");
	let pool_before = r.server.wallet.balance().await.unwrap().get(&x).copied().unwrap_or(0);
	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, horizon + 600 - now).await;
	let script = |id: &arca_covenant::LeafId| {
		let store = r.server.store.clone();
		let id = id.0;
		async move { store.leaf(&id).await.unwrap().unwrap().script_pubkey }
	};
	let (d21_spk, h_spk) = (script(&coins[21].held.id).await, script(&h.held.id).await);
	let gave = coins[22].held.id.0.to_vec();
	drive(&r, "the batch collected at its horizon", 40, |l| has(l, "claim", &gave) && l.iter().any(|w| w.kind == "reassignment")).await;
	for _ in 0..3 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		settle(&r).await;
	}
	for w in log(&r).await.iter().filter(|w| ["unroll", "entry", "forfeit", "claim", "checkpoint", "reassignment"].contains(&w.kind.as_str())) {
		let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
		println!("  collected: {} {} ({} vB): {}", w.kind, tx.txid(), tx.vsize(), w.detail);
	}
	let exits: Vec<WatcherTxRow> = log(&r).await.into_iter().filter(|w| w.kind == "unroll").collect();
	for c in [&coins[21], &coins[22]] {
		let e = exits.iter().find(|w| w.detail.contains(&c.held.id.to_string())).expect("the slot's exit");
		assert!(e.detail.contains("by the operator's authorisation"), "a batch leaf goes out by the operator's own exit authorisation: {}",
			e.detail);
	}
	// The first exit at the horizon spends the batch where the last release
	// left it.
	let last_release: Transaction = elements::encode::deserialize(&releases(&r, &root).await.last().unwrap().tx).unwrap();
	let first_exit: Transaction = elements::encode::deserialize(&exits[0].tx).unwrap();
	assert_eq!(first_exit.input[0].previous_output, OutPoint::new(last_release.txid(), 1), "the batch followed through its releases");
	for (who, spk, value) in [("slot 21's absent owner", &d21_spk, coins[21].valid(&r).value), ("H", &h_spk, kept - 2_000)] {
		let seen = r.server.store.sightings_of(spk).await.unwrap();
		assert_eq!(seen.len(), 1, "{}'s coin is an on-chain leaf of its own", who);
		let op = OutPoint::new(Txid::from_byte_array(seen[0].0), seen[0].1);
		assert!(r.unspent(&op), "{}'s leaf is unspent, its holder's to take", who);
		let tx = r.rt.client().raw_transaction(&op.txid).unwrap();
		assert_eq!(tx.output[op.vout as usize].value.explicit(), Some(value), "{}'s leaf holds its whole coin", who);
		assert!(r.server.finality.status(&op.txid).await.unwrap().is_final(), "{}'s leaf is final", who);
		println!("{}: leaf {} holds {} of X under its own key, final", who, op, value);
	}
	for w in log(&r).await {
		assert_eq!(w.state, NurseryState::Final, "{} {} is final", w.kind, w.detail);
	}
	let pool_after = r.server.wallet.balance().await.unwrap().get(&x).copied().unwrap_or(0);
	println!("the operator's pool of X: {} before the collection, {} after (slot 22's forfeit claimed, less fees)", pool_before, pool_after);
	assert!(pool_after > pool_before + VALUE / 2, "slot 22's forfeited coin is the operator's");
	let _ = state;
}

// ---------------------------------------------------------------------------
// A refresh round lost and returned
// ---------------------------------------------------------------------------

/// Whether a block of the active chain holds `txid`.
fn in_a_block(r: &Running, txid: &Txid) -> bool {
	r.rt.client().call::<Value>("getrawtransaction", &[json!(txid.to_string()), json!(true)]).ok()
		.and_then(|v| v["confirmations"].as_u64()).unwrap_or(0) > 0
}

/// A parent block of its own, and the Sequentia tip anchored to it: what is
/// mined next is anchored there, so orphaning it takes that out. Its height.
async fn own_anchor(r: &Running) -> u64 {
	tokio::task::block_in_place(|| {
		r.rt.mine_parent(1).unwrap();
		r.rt.anchor_to_parent_tip().unwrap();
	});
	r.rt.parent.client().block_count().unwrap()
}

/// Every Sequentia block of the active chain from height 1, with its
/// transactions after the coinbase.
fn blocks_now(r: &Running) -> Vec<(u64, String, Vec<Transaction>)> {
	let tip: u64 = r.rt.client().call("getblockcount", &[]).unwrap();
	(1..=tip).map(|h| {
		let hash: String = r.rt.client().call("getblockhash", &[json!(h)]).unwrap();
		let b: Value = r.rt.client().call("getblock", &[json!(hash), json!(2)]).unwrap();
		let txs = b["tx"].as_array().unwrap().iter().skip(1)
			.map(|t| elements::encode::deserialize(&unhex(t["hex"].as_str().unwrap())).unwrap()).collect();
		(h, hash, txs)
	}).collect()
}

/// The refresh round `round` goes out of the chain with its parent block
/// (`anchor`), the node forgets its mempool, and X takes the round's first
/// input in a block anchored to a parent block of its own, buried, paying
/// nothing to the operator: the server holds the round lost. Returns X and
/// its parent height.
async fn lose(r: &mut Running, round: &Transaction, anchor: u64) -> (Transaction, u64) {
	r.server.stop();
	let orphaned = tokio::task::block_in_place(|| r.rt.orphan_parent_from(anchor)).unwrap();
	assert!(!in_a_block(r, &round.txid()));
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0"])).unwrap();
	println!("R {}: out of the chain with {} parent block(s) from height {}; the node restarted with an empty mempool", round.txid(),
		orphaned.len(), anchor);
	let p_x = own_anchor(r).await;
	let wi = round.input[0].previous_output;
	let w_out = r.rt.client().raw_transaction(&wi.txid).unwrap().output[wi.vout as usize].clone();
	let x = common::rounds::spend_wallet_coin(wi, &w_out, vec![], 2_000);
	r.rt.client().send_raw_transaction(&x).unwrap();
	r.produce().await;
	r.bury().await;
	println!("X {} takes R's input {}, buried", x.txid(), wi);
	r.restart_server().await;
	common::rounds::round_state(r, &round.txid(), RoundState::Lost).await;
	(x, p_x)
}

/// X goes out with everything anchored at or above `p_x`, the node restarts,
/// R takes X's place and every other transaction of the disconnected blocks
/// is sent again in its order; buried, the server holds R final.
async fn returns(r: &mut Running, round: &Transaction, x: &Transaction, p_x: u64) {
	r.server.stop();
	let before = blocks_now(r);
	tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_x)).unwrap();
	assert!(!in_a_block(r, &x.txid()));
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0"])).unwrap();
	println!("R sent again: {:?}", r.rt.client().send_raw_transaction(round).map(|t| t.to_string()).map_err(|e| e.to_string()));
	let tip: u64 = r.rt.client().call("getblockcount", &[]).unwrap();
	for (h, hash, txs) in &before {
		let now = (*h <= tip).then(|| r.rt.client().call::<String>("getblockhash", &[json!(h)]).unwrap());
		if now.as_deref() == Some(hash.as_str()) {
			continue;
		}
		for t in txs {
			let _ = r.rt.client().send_raw_transaction(t);
		}
	}
	r.produce().await;
	r.produce().await;
	r.bury().await;
	assert!(in_a_block(r, &round.txid()));
	r.restart_server().await;
	common::rounds::round_state(r, &round.txid(), RoundState::Final).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lost_refresh_round_retires_its_slot_releases_and_its_return_restores_them() {
	let mut r = start().await;
	let x = r.x;
	let mut boards = vec![];
	for i in 0..6 {
		let (held, tx) = credited_board(&mut r, &keypair(&format!("acc2 lost board {}", i)), x).await;
		boards.push(Coin { held, bases: vec![tx] });
	}
	let first = refresh(&mut r, "acc2 lost U", &boards.iter().collect::<Vec<_>>(), &[false; 6]).await;
	let New::Acc(v0) = &first[0].new else { panic!("an accumulator batch") };
	let (root, round1, vout) = (v0.policy.root, first[0].round.clone(), v0.batch_vout);
	let acc = match rebuild_batch(&r.http.post("tree", &json!({"txid": round1.txid().to_string(), "vout": vout})).ok()) {
		Batch::Accumulator(a) => a,
		Batch::Tree(_) => unreachable!(),
	};
	let row1 = r.server.store.round_by_txid(&round1.txid().to_byte_array()).await.unwrap().unwrap();
	settle(&r).await;

	// R, alone in a parent block of its own: owners 0 and 1 refresh and
	// release their slots, naming R's connector asset. The watcher has not
	// run since.
	let coins: Vec<Coin> = first.iter().map(|o| o.coin.clone()).collect();
	let p_r = own_anchor(&r).await;
	let out = refresh(&mut r, "acc2 lost A", &[&coins[0], &coins[1]], &[true, true]).await;
	let rtx = out[0].round.clone();
	let stored = r.server.store.slot_releases(row1.round_id, vout).await.unwrap();
	println!("R {} final; {} slot releases stored", rtx.txid(), stored.len());
	assert_eq!(stored.len(), 2);

	// R is lost: its releases are retired, and the watcher tries none.
	let (xtx, p_x) = lose(&mut r, &rtx, p_r).await;
	r.server.rounds.pass().await.unwrap();
	let left = r.server.store.slot_releases(row1.round_id, vout).await.unwrap();
	println!("after R is lost: {} slot releases usable", left.len());
	assert!(left.is_empty(), "the releases naming R's connector asset are retired");
	for _ in 0..3 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		r.produce().await;
	}
	assert!(releases(&r, &root).await.is_empty(), "no release is tried while R is lost");
	let m = arca_covenant::connector_asset(rtx.txid(), out[0].c);
	assert!(!log(&r).await.iter().any(|w| w.kind == "issue" && w.subject == m.into_inner().to_byte_array().to_vec()),
		"no atom of R's connector asset is issued");

	// R returns: its releases are restored and released.
	returns(&mut r, &rtx, &xtx, p_x).await;
	let back = r.server.store.slot_releases(row1.round_id, vout).await.unwrap();
	println!("after R returns: {} slot releases usable", back.len());
	assert_eq!(back.len(), 2);
	let rs = released(&r, "the restored releases", &root, 1).await;
	let tx = tx_of(&rs[0]);
	assert!(in_a_block(&r, &tx.txid()));
	check_release(&r, &rs[0], &acc, acc.policy(), &slots_of(&[&coins[0], &coins[1]])).await;
}
