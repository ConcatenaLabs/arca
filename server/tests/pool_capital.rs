//! The operator's capital comes back: one round never takes the whole pool
//! out of reach, and a holder that refreshes every few minutes has its old
//! batches reclaimed, so the value locked in batches stays bounded however
//! often it refreshes.
//!
//! 1. A pool paid in one coin: the first round spends it and pays its
//!    change as shares of the pool, and the next rounds, built while the
//!    first's change is not final, each take one share; under a wallet that
//!    keeps change whole, the second round waits for the first to be final.
//! 2. A maker refreshing four leaves every round beside a one-off user each
//!    round: with holder batches each refresh lands in a batch of its own,
//!    which the maker's next refresh releases whole and the watcher reclaims;
//!    the value locked grows by the users' leaves alone. With holder batches
//!    off (the control) every maker batch shares a lowest node with a user
//!    who never releases, and the locked value grows by the maker's four
//!    leaves every round. `/v1/chain` reports both (`pool`).
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, Transaction};
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::{CoinRecord, Release, ValidOrigin};
use common::client::{auths_json, forfeit_sig, hex, new_leaf, participation_body, random32, rebuild, transfer_body, want_leaf, Held};
use common::flow::{forfeit_for, held_by, Coin};
use common::keys::{keypair, xonly};
use common::rounds::{created, round_final, status, validate_new_leaf, VALUE};
use common::running::Running;
use server::participations::OutputRequest;

/// What `/v1/chain` says of `asset`'s pool, as numbers.
fn pool(r: &Running, asset: AssetId) -> (u64, u64, u64, u64) {
	let c = r.http.get("chain").json;
	let p = &c["pool"][asset.to_string()];
	let n = |k: &str| p[k].as_str().unwrap_or("0").parse::<u64>().unwrap();
	(n("locked"), n("released"), n("reclaimed_last_hour"), n("drawn_last_hour"))
}

/// A board of `VALUE` for each of `keys`, paid in one block and credited.
async fn boards(r: &mut Running, keys: &[Keypair]) -> Vec<Coin> {
	let mut out = vec![];
	for k in keys {
		let (record, tx, _) = r.board_in(k, r.x, VALUE);
		out.push((k, record, tx));
	}
	r.produce().await;
	r.bury().await;
	let mut coins = vec![];
	for (k, record, tx) in out {
		let id = record.leaf_id();
		let http = r.http.clone();
		r.wait("a board credited", || http.board_status(&id).json["state"] == "credited").await;
		coins.push(Coin { held: Held { key: *k, nonce: record.owner_nonce, id, record: CoinRecord::Board(record) }, bases: vec![tx] });
	}
	coins
}

/// One participation giving up `coins` for a leaf of the same value each
/// under `keys`, bound to `mailbox` when given; submitted. Its id and the
/// nonces of the leaves it wants.
fn submit(r: &Running, coins: &[&Coin], keys: &[Keypair], mailbox: Option<&Keypair>) -> ([u8; 32], Vec<[u8; 32]>) {
	let mut wants: Vec<OutputRequest> = vec![];
	let mut nonces = vec![];
	for (c, k) in coins.iter().zip(keys) {
		let v = c.valid(r);
		let (w, n) = want_leaf(k, v.asset, v.value);
		wants.push(w);
		nonces.push(n);
	}
	let held: Vec<&Held> = coins.iter().map(|c| &c.held).collect();
	let (mut body, id) = participation_body(&held, &wants, &[], None, xonly(&r.s), r.chain);
	if let Some(m) = mailbox {
		for (j, k) in keys.iter().enumerate() {
			let d = server::auth::mailbox_binding_digest(&r.chain, &xonly(&r.s), &xonly(k), &xonly(m));
			body["outputs"][j]["leaf"]["mailbox"] = json!(hex(&xonly(m).serialize()));
			body["outputs"][j]["leaf"]["mailbox_proof"] = json!(hex(sign_digest(k, &d, &random32()).as_ref()));
		}
	}
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending", "{}", body);
	(id, nonces)
}

/// Participation `id`, its round final: each owner validates its new leaf,
/// hands over its forfeits, takes the preimage and, when `release`, releases
/// the lowest node of each old batch leaf. The new coins.
async fn complete(r: &Running, id: &[u8; 32], coins: &[&Coin], keys: &[Keypair], nonces: &[[u8; 32]], release: bool) -> Vec<Coin> {
	let st = status(r, id);
	let mut news = vec![];
	for (j, (k, n)) in keys.iter().zip(nonces).enumerate() {
		news.push(validate_new_leaf(r, id, j, k, n));
	}
	let (first, _, round) = &news[0];
	let mut forfeits = vec![];
	for (i, c) in coins.iter().enumerate() {
		let old = c.valid(r);
		let mut one = st.clone();
		one["inputs"][0] = st["inputs"][i].clone();
		let f = forfeit_for(&old, first, round, &one);
		forfeits.push(json!({"leaf_id": c.held.id.to_string(), "signature": forfeit_sig(&f, &c.held.key)}));
	}
	let leaves: Vec<Value> = news.iter().zip(keys).map(|((v, rec, _), k)| auths_json(v, k, created(rec))).collect();
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(id), "forfeits": forfeits, "leaves": leaves})).ok();
	assert_eq!(done["state"], "released", "{}", done);
	if release {
		let c = st["round"]["connector_vout"].as_u64().unwrap() as u32;
		let mut rels = vec![];
		for co in coins {
			let old = co.valid(r);
			if let ValidOrigin::Leaf { valid, .. } = &old.origin {
				let rel = Release::for_refresh(valid, first, round, c).unwrap();
				rels.push(json!({"leaf_id": old.id.to_string(), "connector_asset": rel.connector.to_string(),
					"signature": hex(sign_digest(&co.held.key, &rel.message().digest, &random32()).as_ref())}));
			}
		}
		if !rels.is_empty() {
			let a = r.http.post("release_leaves", &json!({"participation_id": hex(id), "releases": rels})).ok();
			assert_eq!(a["released"].as_array().unwrap().len(), rels.len(), "{}", a);
		}
	}
	news.iter().zip(keys).zip(nonces).map(|(((v, _, round), k), n)| Coin { held: held_by(r, k, *n, v.leaf_id), bases: vec![round.clone()] })
		.collect()
}

/// The wallet's outputs of `tx` in `asset` (P2WPKH, where every Arca output
/// is taproot): its change.
fn change_outputs(tx: &Transaction, asset: AssetId) -> Vec<u64> {
	tx.output.iter().filter(|o| o.asset.explicit() == Some(asset) && o.script_pubkey.is_v0_p2wpkh())
		.filter_map(|o| o.value.explicit()).collect()
}

async fn one_coin_pool(pool_coins: u32) -> (Running, Vec<Coin>) {
	let mut r = Running::start_with(|c, _| {
		c.pool_coins = pool_coins;
	}).await;
	let x = r.x;
	r.fund_wallet_in(x, 200_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let keys: Vec<Keypair> = (0..3).map(|i| keypair(&format!("P{} board", i))).collect();
	let coins = boards(&mut r, &keys).await;
	(r, coins)
}

#[tokio::test(flavor = "multi_thread")]
async fn one_round_never_takes_the_whole_pool() {
	let (r, coins) = one_coin_pool(server::wallet::POOL_COINS).await;
	let x = r.x;
	// Round 1 spends the one coin of the pool and pays its change in shares.
	let k1 = [keypair("P0 new")];
	let (id1, _) = submit(&r, &[&coins[0]], &k1, None);
	let b1 = r.server.rounds.run_round().await.unwrap().expect("round 1");
	let change = change_outputs(&b1.tx, x);
	println!("round 1 {}: {} vB, {} outputs, its change in X: {} coins, {:?}…", b1.tx.txid(), b1.tx.vsize(), b1.tx.output.len(),
		change.len(), &change[..change.len().min(3)]);
	assert!(change.len() >= 32, "the change of a pool of one coin is paid in shares: {:?}", change);
	r.produce().await;
	r.bury().await;
	round_final(&r, &b1.tx.txid()).await;
	assert_eq!(status(&r, &id1)["state"], "issued");

	// Rounds 2 and 3, back to back, round 2 in a block and not final: each
	// takes one share and leaves the rest spendable.
	let (_, _) = submit(&r, &[&coins[1]], &[keypair("P1 new")], None);
	let b2 = r.server.rounds.run_round().await.unwrap().expect("round 2");
	let inputs2 = b2.tx.input.len();
	r.produce().await;
	r.synced().await;
	let (id3, _) = submit(&r, &[&coins[2]], &[keypair("P2 new")], None);
	let b3 = r.server.rounds.run_round().await.unwrap();
	let st3 = status(&r, &id3);
	println!("round 2 {}: {} input(s); round 3 built while round 2 is not final: {}; P2: {}", b2.tx.txid(), inputs2,
		b3.as_ref().map(|b| b.tx.txid().to_string()).unwrap_or("none".into()), st3["state"]);
	assert!(b3.is_some(), "round 3 runs while round 2's change is not final: {}", st3);
	assert_eq!(st3["state"], "issued");
	let w = r.server.wallet.balance().await.unwrap().get(&x).copied().unwrap_or(0);
	println!("the wallet can spend {} of X with rounds 2 and 3 not final", w);
	assert!(w > 150_000_000, "most of the pool stays spendable: {}", w);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pool_kept_whole_stalls_the_next_round() {
	// The control: a wallet that keeps its change whole (pool_coins 1).
	let (r, coins) = one_coin_pool(1).await;
	let x = r.x;
	let (_, _) = submit(&r, &[&coins[0]], &[keypair("Q0 new")], None);
	let b1 = r.server.rounds.run_round().await.unwrap().expect("round 1");
	assert_eq!(change_outputs(&b1.tx, x).len(), 1, "one change output");
	r.produce().await;
	r.synced().await;
	let (id2, _) = submit(&r, &[&coins[1]], &[keypair("Q1 new")], None);
	let b2 = r.server.rounds.run_round().await.unwrap();
	let st = status(&r, &id2);
	println!("pool kept whole: round 2 while round 1 is not final: {}; Q1 {}, waiting: {}",
		b2.as_ref().map(|b| b.tx.txid().to_string()).unwrap_or("none".into()), st["state"], st["waiting"]);
	assert!(b2.is_none() && st["state"] == "pending", "{}", st);
	assert!(st["waiting"].as_str().unwrap_or("").contains("cannot fund it"), "{}", st);
}

/// A maker refreshing four leaves each round, a one-off user beside it each
/// round; `rounds` rounds. The pool's locked value after each.
async fn maker_rounds(holder_batches: usize, rounds: usize) -> Vec<(u64, u64, u64, u64, usize)> {
	let mut r = Running::start_with(|c, _| {
		c.batches.holder_batches = Some(holder_batches);
	}).await;
	let x = r.x;
	r.fund_wallet_in(x, 300_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let mailbox = keypair("maker's mailbox");
	let maker_boards: Vec<Keypair> = (0..4).map(|i| keypair(&format!("maker board {} hb{}", i, holder_batches))).collect();
	let user_keys: Vec<Keypair> = (0..rounds).map(|i| keypair(&format!("user {} board hb{}", i, holder_batches))).collect();
	let mut all = maker_boards.clone();
	all.extend(user_keys.iter().copied());
	let mut held = boards(&mut r, &all).await;
	let users: Vec<Coin> = held.split_off(4);
	let mut maker: Vec<Coin> = held;
	let mut out = vec![];
	for k in 0..rounds {
		let mk: Vec<Keypair> = (0..4).map(|i| keypair(&format!("maker {} round {} hb{}", i, k, holder_batches))).collect();
		let mrefs: Vec<&Coin> = maker.iter().collect();
		let (mid, mn) = submit(&r, &mrefs, &mk, Some(&mailbox));
		let uk = [keypair(&format!("user {} new hb{}", k, holder_batches))];
		let (uid, un) = submit(&r, &[&users[k]], &uk, None);
		let built = r.server.rounds.run_round().await.unwrap().expect("a round");
		r.produce().await;
		r.bury().await;
		round_final(&r, &built.tx.txid()).await;
		let new_maker = complete(&r, &mid, &mrefs, &mk, &mn, true).await;
		complete(&r, &uid, &[&users[k]], &uk, &un, false).await;
		maker = new_maker;
		// The watcher's passes: unrolls and reclaims of what every owner
		// released, a block between passes.
		let before = common::flow::of_kind(&r, "reclaim").await.len();
		for _ in 0..4 {
			r.synced().await;
			r.server.watcher.pass().await.unwrap();
			common::flow::broadcast_all(&r).await;
			r.produce().await;
		}
		r.bury().await;
		r.synced().await;
		r.server.nursery.pass().await.unwrap();
		let reclaims = common::flow::of_kind(&r, "reclaim").await.len();
		let (locked, released, reclaimed, drawn) = pool(&r, x);
		println!("hb {} round {}: {} batch(es) {:?}; reclaims {} (+{}); locked {}, released {}, reclaimed in the last hour {}, drawn {}",
			holder_batches, k, built.batches.len(), built.batches.iter().map(|b| b.2).collect::<Vec<_>>(), reclaims, reclaims - before,
			locked, released, reclaimed, drawn);
		out.push((locked, released, reclaimed, drawn, reclaims));
	}
	// The maker pays one leaf on out of round: its batch can no longer come
	// back before it expires, and `/v1/chain` says how much is so held.
	let c = &maker[0];
	let v = c.valid(&r);
	let (to, _) = new_leaf(&keypair(&format!("a payee hb{}", holder_batches)));
	let kept = v.value - 2_000;
	let done = r.http.post("cosign_transfer", &transfer_body(&[(&c.held, v.clone(), kept)], &[(x, kept - 2_000, to)], xonly(&r.s), r.chain)).ok();
	assert!(done["outputs"][0]["leaf_id"].is_string(), "{}", done);
	let chain = r.http.get("chain").json;
	let transferred = chain["pool"][x.to_string()]["transferred"].as_str().unwrap().parse::<u64>().unwrap();
	println!("hb {}: a maker leaf of {} paid on out of round: transferred {}", holder_batches, v.value, transferred);
	assert_eq!(transferred, v.value);
	out
}

#[tokio::test(flavor = "multi_thread")]
async fn a_maker_refreshing_every_round_keeps_the_locked_value_bounded() {
	const ROUNDS: usize = 6;
	let with = maker_rounds(8, ROUNDS).await;
	// Each round adds the user's leaf (VALUE) and its reserves; the maker's
	// batch of the round before comes back.
	let grew = with[ROUNDS - 1].0 as i64 - with[2].0 as i64;
	let per_round = grew / (ROUNDS as i64 - 3);
	println!("holder batches: locked grew {} over {} rounds, {} a round; reclaims {}", grew, ROUNDS - 3, per_round, with[ROUNDS - 1].4);
	assert!(with[ROUNDS - 1].4 >= ROUNDS - 2, "the maker's batch of every round from the second on is reclaimed by the next");
	assert!(with[ROUNDS - 1].2 > 0, "/v1/chain counts what reclaims paid back in the last hour");
	assert!(per_round < 2 * VALUE as i64, "the locked value grows by the user's leaf alone: {} a round", per_round);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_holder_batches_the_maker_strands_a_leaf_a_round() {
	const ROUNDS: usize = 6;
	let without = maker_rounds(0, ROUNDS).await;
	let grew = without[ROUNDS - 1].0 as i64 - without[2].0 as i64;
	let per_round = grew / (ROUNDS as i64 - 3);
	println!("no holder batches: locked grew {} over {} rounds, {} a round; reclaims {}", grew, ROUNDS - 3, per_round,
		without[ROUNDS - 1].4);
	// Each round's batch is the maker's four leaves and the user's, laid
	// into lowest nodes of three and two: the maker's first three come back
	// once it refreshes, its fourth shares a lowest node with the user, who
	// never releases.
	assert!(without[ROUNDS - 1].4 >= ROUNDS - 2, "the maker's lowest node of every round from the second on is reclaimed");
	assert!(per_round >= 2 * VALUE as i64 && per_round < 3 * VALUE as i64,
		"the user's leaf and the maker's leaf beside it are held every round, the other three come back: {} a round", per_round);
}

/// A batch of six leaves, laid into lowest nodes of three and three: a
/// maker's first three in one, its fourth beside two users in the other.
/// Once the maker refreshes and releases, the watcher unrolls the batch
/// output and reclaims the maker's lowest node, though the users have not
/// released: the users' coins stay theirs and work as before, one paid on
/// out of round and the other refreshed, and once the second user and the
/// maker's payee have released, the other lowest node comes back too.
#[tokio::test(flavor = "multi_thread")]
async fn a_released_lowest_node_comes_back_beside_owners_who_have_not_released() {
	let mut r = Running::start_with(|c, _| {
		c.batches.holder_batches = Some(0);
	}).await;
	let x = r.x;
	r.fund_wallet_in(x, 300_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let mk0: Vec<Keypair> = (0..4).map(|i| keypair(&format!("shared maker board {}", i))).collect();
	let uk0 = [keypair("shared user A board"), keypair("shared user B board")];
	let mut all = mk0.clone();
	all.extend(uk0);
	let mut held = boards(&mut r, &all).await;
	let users_boards = held.split_off(4);
	let maker_boards = held;

	// Round 1: the maker's four boards and the two users' into one batch.
	let mk1: Vec<Keypair> = (0..4).map(|i| keypair(&format!("shared maker leaf {}", i))).collect();
	let (mid, mn) = submit(&r, &maker_boards.iter().collect::<Vec<_>>(), &mk1, None);
	let ua = [keypair("shared user A leaf")];
	let ub = [keypair("shared user B leaf")];
	let (aid, an) = submit(&r, &[&users_boards[0]], &ua, None);
	let (bid, bn) = submit(&r, &[&users_boards[1]], &ub, None);
	let b1 = r.server.rounds.run_round().await.unwrap().expect("round 1");
	assert_eq!(b1.batches.len(), 1, "one shared batch");
	r.produce().await;
	r.bury().await;
	round_final(&r, &b1.tx.txid()).await;
	let maker1 = complete(&r, &mid, &maker_boards.iter().collect::<Vec<_>>(), &mk1, &mn, true).await;
	let user_a = complete(&r, &aid, &[&users_boards[0]], &ua, &an, false).await.remove(0);
	let user_b = complete(&r, &bid, &[&users_boards[1]], &ub, &bn, false).await.remove(0);
	let tree = rebuild(&r.http.post("tree", &json!({"txid": b1.tx.txid().to_string(), "vout": b1.batches[0].1})).ok());
	let lowest: Vec<std::ops::Range<usize>> = tree.levels()[0].iter().map(|n| n.leaves.clone()).collect();
	println!("round 1 {}: one batch of {} leaves, lowest nodes {:?}", b1.tx.txid(), tree.len(), lowest);
	assert_eq!(lowest, vec![0..3, 3..6], "six leaves at radix 4 make two lowest nodes of three");

	// Round 2: the maker refreshes its four leaves and releases their lowest
	// nodes; the users do nothing.
	let mk2: Vec<Keypair> = (0..4).map(|i| keypair(&format!("shared maker leaf {} again", i))).collect();
	let mrefs: Vec<&Coin> = maker1.iter().collect();
	let (mid2, mn2) = submit(&r, &mrefs, &mk2, None);
	let b2 = r.server.rounds.run_round().await.unwrap().expect("round 2");
	r.produce().await;
	r.bury().await;
	round_final(&r, &b2.tx.txid()).await;
	let maker2 = complete(&r, &mid2, &mrefs, &mk2, &mn2, true).await;
	let (_, released, _, _) = pool(&r, x);
	let reclaimable = r.http.get("chain").json["pool"][x.to_string()]["reclaimable"].as_str().unwrap().parse::<u64>().unwrap();
	println!("after the maker's refresh: released {}, reclaimable {}", released, reclaimable);
	assert_eq!(released, 4 * VALUE, "the maker's four leaves are released");
	assert_eq!(reclaimable, 3 * VALUE, "the lowest node of the maker's first three leaves is whole released");

	// The watcher's passes: the batch output unrolled, the maker's lowest
	// node reclaimed; the other lowest node, with the users' leaves, stays.
	for _ in 0..4 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		common::flow::broadcast_all(&r).await;
		r.produce().await;
	}
	r.bury().await;
	r.synced().await;
	r.server.nursery.pass().await.unwrap();
	let unrolls = common::flow::of_kind(&r, "unroll").await;
	let reclaims = common::flow::of_kind(&r, "reclaim").await;
	for w in unrolls.iter().chain(&reclaims) {
		let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
		println!("  {} {} ({:?}): {} vB, {}", w.kind, tx.txid(), w.state, tx.vsize(), w.detail);
	}
	assert_eq!(unrolls.len(), 1, "the batch output alone is unrolled, toward the maker's lowest node");
	assert_eq!(reclaims.len(), 1, "the maker's lowest node is reclaimed");
	for w in unrolls.iter().chain(&reclaims) {
		assert_eq!(w.state, server::store::NurseryState::Final, "{} final", w.kind);
	}
	let (locked, released, _, _) = pool(&r, x);
	let reclaimable = r.http.get("chain").json["pool"][x.to_string()]["reclaimable"].as_str().unwrap().parse::<u64>().unwrap();
	println!("after the passes: locked {}, released {}, reclaimable {}", locked, released, reclaimable);
	assert_eq!(released, VALUE, "the maker's fourth leaf, beside the users, stays released and held");
	assert_eq!(reclaimable, 0);

	// User A's coin is unchanged by the unroll: it pays on out of round.
	let va = user_a.valid(&r);
	let (to, _) = new_leaf(&keypair("user A's payee"));
	let paid = va.value - 2_000;
	let done = r.http.post("cosign_transfer", &transfer_body(&[(&user_a.held, va.clone(), paid)], &[(x, paid - 2_000, to)], xonly(&r.s), r.chain)).ok();
	println!("user A pays on out of round after the unroll: {}", done["outputs"][0]["leaf_id"]);
	assert!(done["outputs"][0]["leaf_id"].is_string(), "{}", done);

	// User B's coin refreshes in a round as before, and releases.
	let ub2 = [keypair("shared user B leaf again")];
	let (bid2, bn2) = submit(&r, &[&user_b], &ub2, None);
	let b3 = r.server.rounds.run_round().await.unwrap().expect("round 3");
	r.produce().await;
	r.bury().await;
	round_final(&r, &b3.tx.txid()).await;
	complete(&r, &bid2, &[&user_b], &ub2, &bn2, true).await;
	println!("user B refreshes after the unroll: round {} final", b3.tx.txid());
	// The other lowest node still waits for user A's payee, which can
	// release nothing (no RECLAIM-D on this batch): it comes back at expiry.
	for _ in 0..3 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		common::flow::broadcast_all(&r).await;
		r.produce().await;
	}
	assert_eq!(common::flow::of_kind(&r, "reclaim").await.len(), 1, "a lowest node with a coin paid on out of round waits");
	let _ = maker2;
}
