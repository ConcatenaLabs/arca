//! Release delegation: a lowest node whose coins moved out of round comes
//! back once their current holders refresh, by RECLAIM-D.
//!
//! 1. Two batch leaves under one lowest node: A's coin is paid to B (with
//!    change), and B's to C (with change); D holds its own. A, B and D
//!    refresh and release; C does not: the node stays. A release by B's key
//!    of the coin it already paid on, recorded behind the server's back,
//!    changes nothing: a coin that moved is counted only through its
//!    delegation. C refreshes in the next round: the watcher reclaims the
//!    node by RECLAIM-D, on the chain, and `/v1/chain` counts it back.
//!    Refused on the way: a delegation over other keys, a holder's release of
//!    a node its coin does not rest on, and one by a key that delegated.
//! 2. A maker trading every round: each round it pays one coin on out of
//!    round and refreshes the rest, and the payee refreshes what it got. With
//!    RECLAIM-D the maker's batches come back each round and the locked value
//!    stays bounded; without it (the control) every batch with a paid coin
//!    waits for its expiry.
//! 3. The in-flight cap: a refresh beyond an asset's cap waits, in plain
//!    words, and an asset with a cap of 0 and an empty pool holds up none of
//!    the round's other assets. A refresh with no release on a node one of
//!    whose coins was paid on is held by the cap too (arca#450).
//! 4. A resting order filled in the tree (arca#419): the taker's coin
//!    delegates with the fill, the maker's order coin afterwards from a coin
//!    the fill made. A maker whose order is filled whole every round keeps
//!    `transferred` at one order; without its delegation it grows by an
//!    order a round. A fill that leaves the order resting again leaves both
//!    nodes to their batches' expiry: the order resting again carries the
//!    order's key and delegates nothing, and the operator keeps no
//!    delegation one sends (arca#460).
//! 6. An operator acting alone, against the order resting again (arca#460):
//!    with its own store changed, it finds no consent for the order's node;
//!    a delegation by the remainder's key that a wallet signed before
//!    wallets stopped, kept in the store, is not followed; and the reclaim
//!    built by hand with the only delegation the order's key signs is
//!    refused in a block, where the same reclaim with that earlier wallet's
//!    signature would be taken.
//! 5. The `htlc-1` leaf of a paid payment out of the tree (arca#431): its
//!    sender releases it once the payment is paid.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::hashes::Hash;
use elements::{AssetId, Transaction};
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::{CoinRecord, Delegation, ExplicitOutput, NewLeaf, Rebindable, Release, ValidOrigin};
use common::client::{auths_json, forfeit_sig, hex, new_leaf, participation_body, random32, transfer_body, want_leaf, Held};
use common::flow::{forfeit_for, held_by, Coin};
use common::keys::{keypair, xonly};
use common::rounds::{created, round_final, status, validate_new_leaf, VALUE};
use common::running::Running;
use server::participations::OutputRequest;

/// `/v1/chain`'s `pool` for `asset`.
fn pool(r: &Running, asset: AssetId) -> Value {
	r.http.get("chain").json["pool"][asset.to_string()].clone()
}

fn n(v: &Value, k: &str) -> u64 {
	v[k].as_str().unwrap_or("0").parse().unwrap()
}

/// A board of `VALUE` in `asset` for each of `keys`, credited.
async fn boards(r: &mut Running, keys: &[Keypair], asset: AssetId) -> Vec<Coin> {
	let mut out = vec![];
	for k in keys {
		let (record, tx, _) = r.board_in(k, asset, VALUE);
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
/// under `keys`. Its id and the nonces of the leaves it wants.
fn submit(r: &Running, coins: &[&Coin], keys: &[Keypair]) -> ([u8; 32], Vec<[u8; 32]>) {
	submit_to(r, coins, keys, None)
}

/// [`submit`], the new leaves bound to `mailbox` when given: one holder's.
fn submit_to(r: &Running, coins: &[&Coin], keys: &[Keypair], mailbox: Option<&Keypair>) -> ([u8; 32], Vec<[u8; 32]>) {
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

/// The releases a wallet signs for `coins`, given up in participation `id`
/// whose round is final: a batch leaf's own lowest node, and for a coin a
/// reassignment made each lowest node with RECLAIM-D it rests on.
fn releases_of(r: &Running, id: &[u8; 32], coins: &[&Coin], first: &arca_covenant::ValidLeaf, round: &Transaction) -> Vec<Value> {
	let st = status(r, id);
	let c = st["round"]["connector_vout"].as_u64().unwrap() as u32;
	let mut rels = vec![];
	for co in coins {
		let old = co.valid(r);
		match &old.origin {
			ValidOrigin::Leaf { valid, .. } => {
				let rel = Release::for_refresh(valid, first, round, c).unwrap();
				rels.push(json!({"leaf_id": old.id.to_string(), "signature": hex(sign_digest(&co.held.key, &rel.message().digest, &random32()).as_ref())}));
			},
			ValidOrigin::Board { .. } => {},
			_ => for rel in Release::for_holder(&old, first, round, c).unwrap() {
				rels.push(json!({"leaf_id": old.id.to_string(), "node": hex(&rel.node_hash),
					"signature": hex(sign_digest(&co.held.key, &rel.message().digest, &random32()).as_ref())}));
			},
		}
	}
	rels
}

/// Participation `id`, its round final: each owner validates its new leaf,
/// hands over its forfeits, takes the preimage and, when `release`, hands
/// over its releases. The new coins.
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
		let rels = releases_of(r, id, coins, first, round);
		if !rels.is_empty() {
			let a = r.http.post("release_leaves", &json!({"participation_id": hex(id), "releases": rels})).ok();
			assert_eq!(a["released"].as_array().unwrap().len(), rels.len(), "{}", a);
		}
	}
	news.iter().zip(keys).zip(nonces).map(|(((v, _, round), k), n)| Coin { held: held_by(r, k, *n, v.leaf_id), bases: vec![round.clone()] })
		.collect()
}

/// Pays `coin` on out of round into one output per key of `to` (value each),
/// the rest less two margins of 2,000 to the last key, delegating its
/// release to every output when `delegate`. The new coins, in order.
fn pay(r: &Running, coin: &Coin, to: &[(Keypair, u64)], delegate: bool) -> Vec<Coin> {
	let (body, nonces) = pay_body(r, coin, to, delegate);
	let done = r.http.post("cosign_transfer", &body).ok();
	let ids: Vec<arca_covenant::LeafId> = done["outputs"].as_array().unwrap().iter()
		.map(|o| o["leaf_id"].as_str().unwrap().parse().unwrap()).collect();
	to.iter().zip(nonces).zip(ids).map(|(((k, _), nonce), id)| Coin { held: held_by(r, k, nonce, id), bases: coin.bases.clone() }).collect()
}

/// [`pay`]'s request body, and the outputs' owner nonces.
fn pay_body(r: &Running, coin: &Coin, to: &[(Keypair, u64)], delegate: bool) -> (Value, Vec<[u8; 32]>) {
	let v = coin.valid(r);
	let kept = v.value - 2_000;
	let x = v.asset;
	let mut outs: Vec<(AssetId, u64, NewLeaf)> = vec![];
	let mut nonces = vec![];
	let mut left = kept - 2_000;
	for (j, (k, value)) in to.iter().enumerate() {
		let (l, nonce) = new_leaf(k);
		let value = if j + 1 == to.len() { left } else { *value };
		left -= value;
		outs.push((x, value, l));
		nonces.push(nonce);
	}
	let mut body = transfer_body(&[(&coin.held, v.clone(), kept)], &outs, xonly(&r.s), r.chain);
	if delegate {
		let plan_outputs: Vec<ExplicitOutput> = outs.iter().map(|(a, val, l)| ExplicitOutput::new(*a, *val, l.policy(xonly(&r.s), r.chain).script_pubkey())).collect();
		let leaves: Vec<NewLeaf> = outs.iter().map(|o| o.2).collect();
		// As a wallet signs it (`Delegation::for_reassignment`), and for an
		// order resting again as a wallet did before arca#460, which
		// `for_reassignment` now refuses.
		let policies: Vec<arca_covenant::LeafPolicy> = leaves.iter().map(|l| l.policy(xonly(&r.s), r.chain)).collect();
		let d = Delegation::for_outputs(v.leaf.owner, r.chain, &plan_outputs, &policies).unwrap();
		body["inputs"][0]["delegation_sig"] = json!(hex(sign_digest(&coin.held.key, &d.message().digest, &random32()).as_ref()));
	}
	(body, nonces)
}

/// The watcher's passes, a block between them, then buried and synced. How
/// many reclaims the log has.
async fn passes(r: &Running) -> Vec<server::store::WatcherTxRow> {
	for _ in 0..4 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		common::flow::broadcast_all(r).await;
		r.produce().await;
	}
	r.bury().await;
	r.synced().await;
	r.server.nursery.pass().await.unwrap();
	common::flow::of_kind(r, "reclaim").await
}

/// Runs a round with everything submitted, makes it final.
async fn round(r: &Running) -> Transaction {
	let built = r.server.rounds.run_round().await.unwrap().expect("a round");
	r.produce().await;
	r.bury().await;
	round_final(r, &built.tx.txid()).await;
	built.tx
}

#[tokio::test(flavor = "multi_thread")]
async fn a_coin_paid_twice_then_refreshed_comes_back_at_the_next_round() {
	let mut r = Running::start_with(|c, _| {
		c.batches.delegated_reclaim = true;
		c.batches.holder_batches = Some(0);
	}).await;
	let x = r.x;
	r.fund_wallet_in(x, 300_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let (ka, kd) = (keypair("A board"), keypair("D board"));
	let bs = boards(&mut r, &[ka, kd], x).await;

	// Round 1: A's and D's leaves under one lowest node with RECLAIM-D.
	let (a1, d1) = (keypair("A1"), keypair("D1"));
	let (ida, na) = submit(&r, &[&bs[0]], &[a1]);
	let (idd, nd) = submit(&r, &[&bs[1]], &[d1]);
	let round1 = round(&r).await;
	let a = complete(&r, &ida, &[&bs[0]], &[a1], &na, false).await.remove(0);
	let d = complete(&r, &idd, &[&bs[1]], &[d1], &nd, false).await.remove(0);
	println!("round 1 {}", round1.txid());
	let nodes = a.valid(&r).release_nodes();
	assert_eq!(nodes.len(), 1, "A's leaf rests on one lowest node with RECLAIM-D");
	let node = nodes[0].1;

	// A delegation over other keys is refused, and nothing is recorded.
	{
		let v = a.valid(&r);
		let (l, _) = new_leaf(&keypair("someone"));
		let mut body = transfer_body(&[(&a.held, v.clone(), v.value - 2_000)], &[(x, v.value - 4_000, l)], xonly(&r.s), r.chain);
		let d = Delegation::new(r.chain, v.leaf.owner, vec![xonly(&keypair("not an output"))]).unwrap();
		body["inputs"][0]["delegation_sig"] = json!(hex(sign_digest(&a.held.key, &d.message().digest, &random32()).as_ref()));
		let e = r.http.post("cosign_transfer", &body).json;
		println!("a delegation over other keys: {}", e);
		assert_eq!(e["error"]["code"], "bad_signature", "{}", e);
		assert!(e["error"]["message"].as_str().unwrap().contains("delegation"), "{}", e);
	}

	// A pays B (change to A2); B pays C (change to B2).
	let (b, a2) = (keypair("B"), keypair("A2"));
	let mut ab = pay(&r, &a, &[(b, VALUE / 2), (a2, 0)], true);
	let (cc, b2) = (keypair("C"), keypair("B2"));
	let bc = pay(&r, &ab[0], &[(cc, VALUE / 4), (b2, 0)], true);
	let a2c = ab.remove(1);
	let (c_coin, b2c) = (bc[0].clone(), bc[1].clone());
	let p = pool(&r, x);
	println!("after two payments: locked {}, transferred {}, in flight {}", n(&p, "locked"), n(&p, "transferred"), n(&p, "in_flight"));
	assert_eq!(n(&p, "transferred"), a.valid(&r).value, "A's leaf is paid on out of round");

	// Round 2: A2, B2 and D refresh and release; C does not.
	let ks = [keypair("A3"), keypair("B3"), keypair("D2")];
	let given = [&a2c, &b2c, &d];
	let mut parts = vec![];
	for (c, k) in given.iter().zip(&ks) {
		parts.push(submit(&r, &[*c], &[*k]));
	}
	round(&r).await;
	for ((c, k), (id, nn)) in given.iter().zip(&ks).zip(&parts) {
		complete(&r, id, &[*c], &[*k], nn, true).await;
	}
	// A release of the node by B's key, for B's coin that it paid on: the
	// chain could not tell it from its holder's. The server refuses it from
	// a wallet, and one recorded behind its back is never counted.
	let bv = ab[0].valid(&r);
	let st = status(&r, &parts[1].0);
	let m = arca_covenant::connector_asset(st["round"]["txid"].as_str().unwrap().parse().unwrap(),
		st["round"]["connector_vout"].as_u64().unwrap() as u32);
	let stale = Release { chain: r.chain, node_hash: node, owner: bv.leaf.owner, connector: m };
	let stale_sig = sign_digest(&ab[0].held.key, &stale.message().digest, &random32());
	let e = r.http.post("release_leaves", &json!({"participation_id": hex(&parts[1].0), "releases": [
		{"leaf_id": bv.id.to_string(), "node": hex(&node), "signature": hex(stale_sig.as_ref())}]})).json;
	println!("B's release of the coin it paid on, from a wallet: {}", e);
	assert_eq!(e["error"]["code"], "open_reassignment", "{}", e);
	let round2_id = r.db.store.round_by_txid(&st["round"]["txid"].as_str().unwrap().parse::<elements::Txid>().unwrap().to_byte_array())
		.await.unwrap().unwrap().round_id;
	r.db.store.insert_release(&bv.id.0, &parts[1].0, round2_id, &node, &m.into_inner().to_byte_array(), stale_sig.as_ref()).await.unwrap();
	// A holder's release of a node its coin does not rest on.
	{
		let (cid, _) = &parts[0];
		let e = r.http.post("release_leaves", &json!({"participation_id": hex(cid), "releases": [
			{"leaf_id": a2c.held.id.to_string(), "node": hex(&[7u8; 32]), "signature": hex(stale_sig.as_ref())}]})).json;
		println!("a release of a node the coin does not rest on: {}", e);
		assert_eq!(e["error"]["code"], "not_on_node", "{}", e);
	}
	let before = passes(&r).await;
	let p = pool(&r, x);
	println!("C still holds its coin: reclaims {}; locked {}, transferred {}, in flight {}", before.len(), n(&p, "locked"),
		n(&p, "transferred"), n(&p, "in_flight"));
	assert!(before.iter().all(|w| w.subject != node.to_vec()), "the node waits for C, whatever B's key signed");

	// Round 3: C refreshes and releases; the node comes back.
	let kc = [keypair("C2")];
	let (idc, nc) = submit(&r, &[&c_coin], &kc);
	round(&r).await;
	complete(&r, &idc, &[&c_coin], &kc, &nc, true).await;
	let after = passes(&r).await;
	let k = after.iter().find(|w| w.subject == node.to_vec()).expect("the node is reclaimed");
	let tx: Transaction = elements::encode::deserialize(&k.tx).unwrap();
	let w = &tx.input[0].witness.script_witness;
	println!("reclaim {} ({:?}): {} vB, leaf script {} bytes, {} witness items; {}", tx.txid(), k.state, tx.vsize(),
		w[w.len() - 2].len(), w.len(), k.detail);
	assert!(k.detail.contains("RECLAIM-D"), "{}", k.detail);
	assert_eq!(k.state, server::store::NurseryState::Final);
	let p = pool(&r, x);
	println!("after the reclaim: locked {}, transferred {}, in flight {}, reclaimed in the last hour {}", n(&p, "locked"),
		n(&p, "transferred"), n(&p, "in_flight"), n(&p, "reclaimed_last_hour"));
	assert_eq!(n(&p, "transferred"), 0);
	assert!(n(&p, "reclaimed_last_hour") > 0);
}

/// A maker holding four coins, trading every round: it pays 100,000 of its
/// first coin on out of round to a new payee, then refreshes its change and
/// its other three coins into a batch of its own, and the payee refreshes
/// what it got (and holds the result). `rounds` rounds; the pool after each:
/// locked, transferred, in flight, reclaims so far.
async fn trading_maker(delegated: bool, rounds: usize) -> Vec<(u64, u64, u64, usize)> {
	let mut r = Running::start_with(|c, _| {
		c.batches.delegated_reclaim = delegated;
		c.batches.holder_batches = Some(8);
	}).await;
	let x = r.x;
	r.fund_wallet_in(x, 300_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let tag = if delegated { "d" } else { "c" };
	let mailbox = keypair(&format!("trading maker's mailbox {}", tag));
	let mk: Vec<Keypair> = (0..4).map(|i| keypair(&format!("trading maker board {} {}", i, tag))).collect();
	let bs = boards(&mut r, &mk, x).await;
	let k0: Vec<Keypair> = (0..4).map(|i| keypair(&format!("trading maker {} round 0 {}", i, tag))).collect();
	let refs: Vec<&Coin> = bs.iter().collect();
	let (id, nn) = submit_to(&r, &refs, &k0, Some(&mailbox));
	round(&r).await;
	let mut maker = complete(&r, &id, &refs, &k0, &nn, true).await;
	let mut out = vec![];
	for k in 1..=rounds {
		let payee = keypair(&format!("payee {} {}", k, tag));
		let change = keypair(&format!("maker change {} {}", k, tag));
		let paid = pay(&r, &maker[0], &[(payee, 100_000), (change, 0)], delegated);
		let mut give: Vec<Coin> = vec![paid[1].clone()];
		give.extend(maker[1..].iter().cloned());
		let keys: Vec<Keypair> = (0..4).map(|i| keypair(&format!("trading maker {} round {} {}", i, k, tag))).collect();
		let grefs: Vec<&Coin> = give.iter().collect();
		let (mid, mn) = submit_to(&r, &grefs, &keys, Some(&mailbox));
		let pk = [keypair(&format!("payee {} new {}", k, tag))];
		let (pid, pn) = submit(&r, &[&paid[0]], &pk);
		let tx = round(&r).await;
		maker = complete(&r, &mid, &grefs, &keys, &mn, true).await;
		complete(&r, &pid, &[&paid[0]], &pk, &pn, true).await;
		let reclaims = passes(&r).await;
		let p = pool(&r, x);
		println!("{} round {} ({} outputs): reclaims {}; locked {}, transferred {}, in flight {}", if delegated { "RECLAIM-D" } else { "control" },
			k, tx.output.len(), reclaims.len(), n(&p, "locked"), n(&p, "transferred"), n(&p, "in_flight"));
		out.push((n(&p, "locked"), n(&p, "transferred"), n(&p, "in_flight"), reclaims.len()));
	}
	out
}

#[tokio::test(flavor = "multi_thread")]
async fn a_maker_trading_every_round_keeps_the_locked_value_bounded() {
	const ROUNDS: usize = 6;
	let with = trading_maker(true, ROUNDS).await;
	let grew = with[ROUNDS - 1].0 as i64 - with[1].0 as i64;
	let per_round = grew / (ROUNDS as i64 - 2);
	println!("RECLAIM-D: locked grew {} over {} rounds, {} a round; reclaims {}", grew, ROUNDS - 2, per_round, with[ROUNDS - 1].3);
	assert!(with[ROUNDS - 1].3 >= ROUNDS - 1, "the maker's batch of every round comes back at the next");
	assert!(per_round < 3 * 100_000 + 50_000, "the locked value grows by the payee's coin alone: {} a round", per_round);
	assert!(with[ROUNDS - 1].1 < VALUE, "transferred stays under one coin: {}", with[ROUNDS - 1].1);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_reclaim_d_a_trading_maker_strands_its_value() {
	const ROUNDS: usize = 6;
	let without = trading_maker(false, ROUNDS).await;
	let grew = without[ROUNDS - 1].0 as i64 - without[1].0 as i64;
	let per_round = grew / (ROUNDS as i64 - 2);
	println!("control: locked grew {} over {} rounds, {} a round; reclaims {}", grew, ROUNDS - 2, per_round, without[ROUNDS - 1].3);
	assert_eq!(without[ROUNDS - 1].3, 0, "every maker batch has a coin paid on out of round: none comes back early");
	assert!(per_round >= 3 * VALUE as i64, "the maker's leaves are stranded every round: {} a round", per_round);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_in_flight_cap_holds_new_refreshes_and_no_other_asset() {
	// X capped at 1.5 coins; Y served with a cap of 0 and nothing in the
	// pool, as an operator serving an asset it has not funded.
	let mut r = Running::start_with(|c, y| {
		c.batches.delegated_reclaim = true;
		c.batches.holder_batches = Some(0);
		c.assets[0].in_flight_cap = Some((VALUE * 3 / 2).to_string());
		let mut s = server::server::AssetSection::new(y, common::running::MIN_LEAF);
		s.in_flight_cap = Some("0".into());
		c.assets.push(s);
	}).await;
	let (x, y) = (r.x, r.y);
	r.fund_wallet_in(x, 300_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let info = r.http.get("info").json;
	let ax = info["assets"].as_array().unwrap().iter().find(|a| a["asset"] == json!(x.to_string())).unwrap().clone();
	println!("/v1/info for X: in_flight_cap {}, in_flight {}", ax["in_flight_cap"], ax["in_flight"]);
	assert_eq!(ax["in_flight_cap"], json!((VALUE * 3 / 2).to_string()));
	let ks: Vec<Keypair> = (0..3).map(|i| keypair(&format!("capped user {}", i))).collect();
	let mut bs = boards(&mut r, &ks, x).await;
	let ky = keypair("Y user");
	let by = boards(&mut r, &[ky], y).await.remove(0);

	// Round 1 from boards (which count for nothing in flight): the three X
	// users and the Y user. Y cannot be funded: it waits, and X runs.
	let k1: Vec<Keypair> = (0..3).map(|i| keypair(&format!("capped user {} r1", i))).collect();
	let mut parts = vec![];
	for (c, k) in bs.iter().zip(&k1) {
		parts.push(submit(&r, &[c], &[*k]));
	}
	let (idy, _) = submit(&r, &[&by], &[keypair("Y user r1")]);
	let (mut rounds, failed) = r.server.rounds.run_rounds().await.unwrap();
	let sty = status(&r, &idy);
	println!("round 1: {} round(s) built, {} failed; the Y user: {}, waiting: {}", rounds.len(), failed.len(), sty["state"], sty["waiting"]);
	assert_eq!(rounds.len(), 1, "the round of X is built, whatever Y waits for");
	let built = rounds.remove(0);
	assert_eq!(sty["state"], "pending", "{}", sty);
	assert!(sty["waiting"].as_str().unwrap().starts_with("This refresh waits for a later round"), "{}", sty);
	assert!(parts.iter().all(|(id, _)| status(&r, id)["state"] == "issued"), "every X refresh ran");
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let mut held = vec![];
	for ((c, k), (id, nn)) in bs.iter().zip(&k1).zip(&parts) {
		held.push(complete(&r, id, &[c], &[*k], nn, true).await.remove(0));
	}
	bs.clear();

	// Round 2: all three refresh again. The first fits the cap; the second
	// would take it past: it waits, in plain words. The third rests on the
	// node the first opened, beside the second... unless it does not; the
	// cap holds what opens a new node.
	let k2: Vec<Keypair> = (0..3).map(|i| keypair(&format!("capped user {} r2", i))).collect();
	let mut parts2 = vec![];
	for (c, k) in held.iter().zip(&k2) {
		parts2.push(submit(&r, &[c], &[*k]));
	}
	let built2 = r.server.rounds.run_round().await.unwrap().expect("a round");
	let states: Vec<Value> = parts2.iter().map(|(id, _)| status(&r, id)).collect();
	for (j, s) in states.iter().enumerate() {
		println!("round 2, user {}: {}, waiting: {}", j, s["state"], s["waiting"]);
	}
	assert_eq!(states[0]["state"], "issued");
	let waiting: Vec<&Value> = states.iter().filter(|s| s["state"] == "pending").collect();
	assert!(!waiting.is_empty(), "a refresh past the cap waits");
	assert!(waiting[0]["waiting"].as_str().unwrap().starts_with("This refresh waits for a later round"), "{}", waiting[0]);
	r.produce().await;
	r.bury().await;
	round_final(&r, &built2.tx.txid()).await;
	for (((c, k), (id, nn)), s) in held.iter().zip(&k2).zip(&parts2).zip(&states) {
		if s["state"] == "issued" {
			complete(&r, id, &[c], &[*k], nn, true).await;
		}
	}
	let p = pool(&r, x);
	println!("after round 2: in flight {} of a cap of {}", n(&p, "in_flight"), p["in_flight_cap"]);
	assert!(n(&p, "in_flight") <= VALUE * 3 / 2 + VALUE);

	// Round 3: the refreshes left rest on the node the earlier ones opened:
	// they complete it, so the cap does not hold them, and the node comes
	// back.
	let built3 = r.server.rounds.run_round().await.unwrap().expect("a round completing the node");
	let states3: Vec<Value> = parts2.iter().map(|(id, _)| status(&r, id)).collect();
	for (j, s) in states3.iter().enumerate() {
		println!("round 3, user {}: {}, waiting: {}", j, s["state"], s["waiting"]);
	}
	assert!(states3.iter().all(|s| s["state"] != "pending"), "the refreshes that complete a node run whatever the cap");
	r.produce().await;
	r.bury().await;
	round_final(&r, &built3.tx.txid()).await;
	for (((c, k), (id, nn)), s) in held.iter().zip(&k2).zip(&parts2).zip(&states) {
		if s["state"] == "pending" {
			complete(&r, id, &[c], &[*k], nn, true).await;
		}
	}
	let reclaims = passes(&r).await;
	let p = pool(&r, x);
	println!("after round 3: reclaims {}; in flight {}", reclaims.len(), n(&p, "in_flight"));
	assert!(!reclaims.is_empty());
	assert_eq!(n(&p, "in_flight"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_transfer_that_carried_a_delegation_gives_its_coin_back() {
	let mut r = Running::start_with(|c, _| {
		c.batches.delegated_reclaim = true;
		c.batches.holder_batches = Some(0);
	}).await;
	let x = r.x;
	r.fund_wallet_in(x, 300_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let genesis = r.rt.client().genesis_hash().unwrap();
	let bs = boards(&mut r, &[keypair("F1 A board"), keypair("F1 D board")], x).await;
	let (ka, kd) = (keypair("F1 A"), keypair("F1 D"));
	let (ida, na) = submit(&r, &[&bs[0]], &[ka]);
	let (idd, nd) = submit(&r, &[&bs[1]], &[kd]);
	round(&r).await;
	let a = complete(&r, &ida, &[&bs[0]], &[ka], &na, false).await.remove(0);
	let d = complete(&r, &idd, &[&bs[1]], &[kd], &nd, false).await.remove(0);
	let (with, _) = pay_body(&r, &a, &[(keypair("F1 B"), VALUE / 2), (keypair("F1 A2"), 0)], true);
	let (without, _) = pay_body(&r, &d, &[(keypair("F1 E"), VALUE / 2), (keypair("F1 D2"), 0)], false);
	// The signer away: each transfer is recorded, and nothing of it signed.
	r.signer.kill();
	for (what, body, coin) in [("with a delegation", &with, &a), ("without one", &without, &d)] {
		let ans = r.http.post("cosign_transfer", body);
		assert_eq!(ans.status, 503, "{}", ans.json);
		let t = r.server.store.spent_by_transfer(&coin.held.id.0).await.unwrap().expect("recorded");
		let delegated = r.server.store.delegation(&coin.held.id.0).await.unwrap().is_some();
		// Refused for good: its record is dropped and its coin given back.
		let back = r.server.store.drop_transfer(&t, "refused for good").await;
		let leaf = r.server.store.leaf(&coin.held.id.0).await.unwrap().unwrap();
		println!("a transfer {} (delegation kept: {}): dropped {:?}; the coin is {:?}", what, delegated, back.as_ref().map(|b| b.len()), leaf.state);
		assert_eq!(back.unwrap().len(), 1, "the coin is given back");
		assert_eq!(leaf.state, server::store::LeafState::Live);
		assert!(r.server.store.delegation(&coin.held.id.0).await.unwrap().is_none(), "the delegation goes with the transfer");
	}
	tokio::task::block_in_place(|| r.signer.restart(&r.s, genesis));
}

/// Round 1: one leaf for each of `names` (at most four), all under one lowest
/// node with RECLAIM-D, on a server whose X is capped at `cap` when given.
async fn first_leaves(cap: Option<u64>, names: &[&str]) -> (Running, Vec<Coin>) {
	let mut r = Running::start_with(|c, _| {
		c.batches.delegated_reclaim = true;
		c.batches.holder_batches = Some(0);
		if let Some(cap) = cap {
			c.assets[0].in_flight_cap = Some(cap.to_string());
		}
	}).await;
	let x = r.x;
	r.fund_wallet_in(x, 300_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let bk: Vec<Keypair> = names.iter().map(|s| keypair(&format!("{} board", s))).collect();
	let bs = boards(&mut r, &bk, x).await;
	let nk: Vec<Keypair> = names.iter().map(|s| keypair(&format!("{} 1", s))).collect();
	let mut parts = vec![];
	for (b, k) in bs.iter().zip(&nk) {
		parts.push(submit(&r, &[b], &[*k]));
	}
	round(&r).await;
	let mut out = vec![];
	for ((b, k), (id, nn)) in bs.iter().zip(&nk).zip(&parts) {
		out.push(complete(&r, id, &[b], &[*k], nn, false).await.remove(0));
	}
	(r, out)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_that_cannot_come_back_does_not_take_refreshes_past_the_cap() {
	let cap = VALUE * 3 / 2;
	let (r, c) = first_leaves(Some(cap), &["F5 U0", "F5 U1", "F5 U2", "F5 U3"]).await;
	let x = r.x;
	// One leaf paid on without a delegation: its node can come back only at
	// its batch's expiry, however its other coins are refreshed.
	let paid = pay(&r, &c[0], &[(keypair("F5 P"), 100_000), (keypair("F5 U0 change"), 0)], false);
	let held: Vec<Coin> = vec![paid[1].clone(), c[1].clone(), c[2].clone(), c[3].clone()];
	let mut pending = vec![];
	for (j, h) in held.iter().enumerate() {
		let k = keypair(&format!("F5 r2 {}", j));
		let (id, nn) = submit(&r, &[h], &[k]);
		pending.push((j, id, nn, k));
	}
	let mut most = 0;
	for rn in 2..=3 {
		if let Some(built) = r.server.rounds.run_round().await.unwrap() {
			r.produce().await;
			r.bury().await;
			round_final(&r, &built.tx.txid()).await;
		}
		let mut left = vec![];
		for (j, id, nn, k) in pending.drain(..) {
			let s = status(&r, &id);
			if s["state"] == "pending" {
				left.push((j, id, nn, k));
			} else {
				complete(&r, &id, &[&held[j]], &[k], &nn, true).await;
			}
		}
		let p = pool(&r, x);
		most = most.max(n(&p, "in_flight"));
		println!("round {}: {} refresh(es) wait; in flight {} of a cap of {}", rn, left.len(), n(&p, "in_flight"), cap);
		pending = left;
	}
	assert!(most <= cap, "nothing runs past the cap on a node that cannot come back: {} in flight", most);
	assert_eq!(pending.len(), 3, "the refreshes beyond the cap wait");
}

/// The cap holds refreshes back so that the pool keeps what holders moving
/// coins out of the Ark need: an offboard (a stake moving out, say) runs
/// whatever the cap, while a refresh beside it waits, and what the offboard
/// gives up counts in flight.
#[tokio::test(flavor = "multi_thread")]
async fn an_offboard_runs_whatever_the_cap() {
	let cap = VALUE * 3 / 2;
	let (r, c) = first_leaves(Some(cap), &["OB U0", "OB U1", "OB U2"]).await;
	let x = r.x;
	// U0 refreshes without a release: its node holds a coin in flight that
	// cannot come back before expiry.
	let k0 = keypair("OB U0 2");
	let (id0, n0) = submit(&r, &[&c[0]], &[k0]);
	round(&r).await;
	complete(&r, &id0, &[&c[0]], &[k0], &n0, false).await;
	let p = pool(&r, x);
	println!("after U0's refresh: in flight {} of a cap of {}", n(&p, "in_flight"), cap);
	assert_eq!(n(&p, "in_flight"), VALUE);

	// U1 refreshes and U2 moves its coin out of the Ark: the refresh would
	// take the asset past the cap and waits; the offboard runs.
	let k1 = keypair("OB U1 2");
	let (id1, _) = submit(&r, &[&c[1]], &[k1]);
	let to = elements::Script::from(vec![0x00, 0x14, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22]);
	let v2 = c[2].valid(&r);
	let out = OutputRequest::Offboard { asset: x, value: VALUE - 100_000, script: to };
	let (body, id2) = participation_body(&[&c[2].held], &[out], &[(x, 100_000)], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending", "{}", body);
	let built = r.server.rounds.run_round().await.unwrap().expect("a round for the offboard");
	let (s1, s2) = (status(&r, &id1), status(&r, &id2));
	println!("U1's refresh: {}, waiting: {}; U2's offboard of {}: {} ({} offboard(s) in round {})", s1["state"], s1["waiting"],
		v2.value, s2["state"], built.offboards, built.tx.txid());
	assert_eq!(s1["state"], "pending", "the refresh waits for the cap: {}", s1);
	assert!(s1["waiting"].as_str().unwrap().starts_with("This refresh waits for a later round"), "{}", s1);
	assert_eq!(s2["state"], "issued", "the offboard runs whatever the cap: {}", s2);
	assert_eq!(built.offboards, 1);
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let p = pool(&r, x);
	println!("after the offboard: in flight {} of a cap of {}", n(&p, "in_flight"), cap);
	assert_eq!(n(&p, "in_flight"), 2 * VALUE, "what the offboard gave up counts in flight");
}

// ---------------------------------------------------------------------------
// Resting orders filled in the tree (arca#419).

const LOT: u64 = 10_000;
const ORDER: u64 = 500_000;

/// A maker's order: its leaf key, its four credit keys and their nonces, and
/// its terms (X for Y, one for one).
struct Maker {
	key: Keypair,
	credits: Vec<Keypair>,
	credit_nonces: [[u8; 32]; 4],
	terms: arca_covenant::order::OrderLeafTerms,
}

fn maker(r: &Running, label: &str) -> Maker {
	use arca_covenant::order::{OrderLeafTerms, OrderTerms, SeqdexOrder, SeqdexVersion};
	let credits: Vec<Keypair> = (0..4).map(|i| keypair(&format!("{}, credit {}", label, i))).collect();
	let mut keys = [[0u8; 32]; 4];
	for (i, c) in credits.iter().enumerate() {
		keys[i] = xonly(c).serialize();
		common::client::hold_key(c);
	}
	let landed = SeqdexOrder {
		terms: OrderTerms { asset_a: r.x, asset_b: r.y, rate_num: 1, rate_den: 1, min_lot: LOT },
		maker: arca_covenant::script::sha256(common::node::op_true().as_bytes()),
		expiry: common::rounds::mtp(r).to_consensus_u32() + 60 * 86_400,
		refund_key: xonly(&keypair(&format!("{}, refund", label))),
		version: SeqdexVersion::V2,
	};
	Maker { key: keypair(label), credits, credit_nonces: [random32(), random32(), random32(), random32()],
		terms: OrderLeafTerms { landed, credits: keys } }
}

/// The wanted `order-3` leaf of `value` of X.
fn want_order(m: &Maker, value: u64, asset: AssetId) -> (OutputRequest, [u8; 32]) {
	common::client::hold_key(&m.key);
	let nonce = random32();
	(OutputRequest::Leaf {
		asset, value, template: arca_covenant::Template::Order3, owner: xonly(&m.key), owner_nonce: nonce,
		exit_delay: common::client::exit_delay(), order: Some(m.terms), landing: None, channel: None,
	}, nonce)
}

/// A participation giving up `coins` for the leaves `wants`; its id.
fn submit_wants(r: &Running, coins: &[&Coin], wants: &[OutputRequest]) -> [u8; 32] {
	let held: Vec<&Held> = coins.iter().map(|c| &c.held).collect();
	let (body, id) = participation_body(&held, wants, &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending", "{}", body);
	id
}

/// Runs every round there is to run (X's first), each made final.
async fn all_rounds(r: &Running) -> usize {
	let mut built = vec![];
	while let Some(b) = r.server.rounds.run_round().await.unwrap() {
		r.produce().await;
		built.push(b.tx.txid());
	}
	r.bury().await;
	for t in &built {
		round_final(r, t).await;
	}
	built.len()
}

/// `m` publishes its order resting at `coin`; the state view of it.
fn publish(r: &Running, m: &Maker, coin: &Coin) -> Value {
	let mailbox = xonly(&keypair("makers' mailbox"));
	let digest = server::orders::publish_digest(&r.chain, &xonly(&r.s), &coin.held.id, &m.credit_nonces, &mailbox);
	let st = r.http.post("order_publish", &json!({
		"record": hex(&coin.held.record.to_bytes().unwrap()),
		"credit_nonces": m.credit_nonces.iter().map(|n| hex(n)).collect::<Vec<_>>(),
		"mailbox": hex(&mailbox.serialize()),
		"signature": hex(sign_digest(&m.key, &digest, &random32()).as_ref()),
	})).ok();
	assert_eq!(st["state"], "resting", "{}", st);
	st
}

/// A taker's fill of `filled` of the order whose state view is `st`, paid
/// with `paid` (its checkpoint keeping all but one atom) into the leaves
/// `got` and `change`, the fill keeping one atom (`order` is the coin the
/// order rests at); its coin's delegation
/// into the fill when `delegate`, signed by `signer`.
#[allow(clippy::too_many_arguments)]
fn fill_body(r: &Running, st: &Value, order: &Coin, paid: &Coin, filled: u64, got: &NewLeaf, change: &NewLeaf, delegate: bool,
	signer: &Keypair) -> (Value, Vec<ExplicitOutput>)
{
	let bases = joined(&[order, paid]);
	let s = xonly(&r.s);
	let record = CoinRecord::from_bytes(&common::client::unhex(st["record"].as_str().unwrap())).unwrap();
	let oc = record.resolve(&bases, &r.policy()).unwrap();
	let p = oc.leaf.order_policy().unwrap();
	let v = paid.valid(r);
	let kept = v.value - 1;
	let plan = p.plan(oc.value, filled).unwrap();
	let change_value = kept - plan.credit.value - 1;
	let mut outputs = vec![plan.credit.clone()];
	outputs.extend(plan.rest.clone());
	outputs.push(ExplicitOutput::new(r.x, filled, got.policy(s, r.chain).script_pubkey()));
	outputs.push(ExplicitOutput::new(v.asset, change_value, change.policy(s, r.chain).script_pubkey()));
	let tplan = arca_covenant::TransferPlan { inputs: vec![(v.clone(), kept)], outputs: outputs.clone() };
	let mut named = vec![oc.output().txout()];
	named.push(tplan.checkpoint_output(0).txout());
	let cp = sign_digest(&paid.held.key, &tplan.checkpoint_message(0).unwrap().digest, &random32());
	let re = sign_digest(&paid.held.key, &tplan.checkpoint(0).message_in(1, &named, &outputs).unwrap().digest, &random32());
	let leaf_json = |asset: AssetId, value: u64, l: &NewLeaf| json!({
		"asset": asset.to_string(), "value": value.to_string(), "owner": hex(&l.owner.serialize()), "owner_nonce": hex(&l.owner_nonce),
		"creator_nonce": hex(&l.creator_nonce), "exit_delay_units": l.exit_delay.units(),
	});
	let mut input = json!({"leaf_id": paid.held.id.to_string(), "checkpoint_value": kept.to_string(), "checkpoint_sig": hex(cp.as_ref()),
		"reassignment_sig": hex(re.as_ref())});
	if delegate {
		let d = Delegation::for_fill(&v.leaf, &p, &outputs, &[*got, *change]).unwrap();
		input["delegation_sig"] = json!(hex(sign_digest(signer, &d.message().digest, &random32()).as_ref()));
	}
	(json!({"order": st["order"], "coin": st["coin"], "filled": filled.to_string(), "inputs": [input],
		"outputs": [leaf_json(r.x, filled, got), leaf_json(v.asset, change_value, change)]}), outputs)
}

/// The transactions the coins' records rest on, each once.
fn joined(coins: &[&Coin]) -> Vec<Transaction> {
	let mut out: Vec<Transaction> = vec![];
	for c in coins {
		for t in &c.bases {
			if !out.iter().any(|o| o.txid() == t.txid()) {
				out.push(t.clone());
			}
		}
	}
	out
}

/// The maker's delegation of its order coin into fill `transfer`, checked
/// against `made` (a coin the fill made the maker) and signed by `signer`.
fn maker_delegation(r: &Running, transfer: &str, made: &arca_covenant::ValidCoin, signer: &Keypair) -> Value {
	let t = r.http.post("order_fill_delegation_terms", &json!({"transfer_id": transfer})).ok();
	let takers: Vec<NewLeaf> = t["takers"].as_array().unwrap().iter().map(|l| NewLeaf {
		enclave: None, v2: false, htlc: None, landing: None,
		owner: elements::secp256k1_zkp::XOnlyPublicKey::from_slice(&common::client::unhex(l["owner"].as_str().unwrap())).unwrap(),
		owner_nonce: common::client::unhex(l["owner_nonce"].as_str().unwrap()).try_into().unwrap(),
		creator_nonce: common::client::unhex(l["creator_nonce"].as_str().unwrap()).try_into().unwrap(),
		exit_delay: arca_covenant::RelativeTime::from_units(l["exit_delay_units"].as_u64().unwrap() as u16).unwrap(),
	}).collect();
	let d = Delegation::for_filled_order(made, &takers).unwrap();
	json!({"transfer_id": transfer, "signature": hex(sign_digest(signer, &d.message().digest, &random32()).as_ref())})
}

/// The coins of a fill's answer, each held by its key and nonce.
fn fill_coins(done: &Value, holders: &[(&Keypair, [u8; 32])], bases: &[Transaction]) -> Vec<Coin> {
	done["outputs"].as_array().unwrap().iter().zip(holders).map(|(o, (k, n))| {
		let record = CoinRecord::from_bytes(&common::client::unhex(o["record"].as_str().unwrap())).unwrap();
		let id: arca_covenant::LeafId = o["leaf_id"].as_str().unwrap().parse().unwrap();
		Coin { held: Held { key: **k, nonce: *n, id, record }, bases: bases.to_vec() }
	}).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_partly_filled_orders_nodes_wait_for_their_expiry() {
	let mut r = Running::start_with(|c, y| {
		c.batches.delegated_reclaim = true;
		c.assets.push(server::server::AssetSection::new(y, common::running::MIN_LEAF));
	}).await;
	let (x, y) = (r.x, r.y);
	// Two coins of X: a round of Y pays its fee in X beside the round of X.
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(y, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let m = maker(&r, "M");
	let (mk2, tk) = (keypair("M, plain"), keypair("T"));
	let bm = boards(&mut r, &[keypair("M, board")], x).await.remove(0);
	let bt = boards(&mut r, &[keypair("T, board")], y).await.remove(0);

	// The order and the maker's plain leaf in one batch of X; the taker's
	// leaf of Y in another.
	let (wo, no) = want_order(&m, ORDER, x);
	let (wp, np) = want_leaf(&mk2, x, VALUE - ORDER);
	let idm = submit_wants(&r, &[&bm], &[wo, wp]);
	let (wt, nt) = want_leaf(&tk, y, VALUE);
	let idt = submit_wants(&r, &[&bt], &[wt]);
	let built = all_rounds(&r).await;
	assert_eq!(built, 2, "a round of X and one of Y");
	let made = complete(&r, &idm, &[&bm], &[m.key, mk2], &[no, np], true).await;
	let (order, plain) = (&made[0], &made[1]);
	let tcoin = complete(&r, &idt, &[&bt], &[tk], &[nt], true).await.remove(0);
	let st = publish(&r, &m, order);
	println!("order {} rests with {} of X; the taker's coin {} holds {} of Y", order.held.id, ORDER, tcoin.held.id, VALUE);

	// The taker fills 200,000: refused first with a delegation by another
	// key, and with one over the outputs of a whole fill.
	let (gk, ck) = (keypair("T, got"), keypair("T, change"));
	let ((got, gn), (change, cn)) = (new_leaf(&gk), new_leaf(&ck));
	let (body, outputs) = fill_body(&r, &st, order, &tcoin, 200_000, &got, &change, true, &mk2);
	let a = r.http.post("order_fill", &body);
	println!("refused, a taker's delegation by another key: {:?}", a.refusal());
	assert_eq!(a.refusal().0, "bad_signature");
	let (mut whole, _) = fill_body(&r, &st, order, &tcoin, 200_000, &got, &change, false, &tk);
	let p = order.valid(&r).leaf.order_policy().unwrap();
	let w = Delegation::new(r.chain, xonly(&tk), vec![p.credit_leaf().unwrap().owner, got.owner, change.owner]).unwrap();
	whole["inputs"][0]["delegation_sig"] = json!(hex(sign_digest(&tk, &w.message().digest, &random32()).as_ref()));
	let a = r.http.post("order_fill", &whole);
	println!("refused, a taker's delegation that leaves out the order resting again: {:?}", a.refusal());
	assert_eq!(a.refusal().0, "bad_signature");
	assert_eq!(outputs.len(), 4);
	let (body, _) = fill_body(&r, &st, order, &tcoin, 200_000, &got, &change, true, &tk);
	let done = r.http.post("order_fill", &body).ok();
	let transfer = done["transfer_id"].as_str().unwrap().to_string();
	let maker_nonce = match &order.held.record { CoinRecord::Leaf { record, .. } => record.owner_nonce, _ => unreachable!() };
	let coins = fill_coins(&done, &[(&m.credits[0], m.credit_nonces[0]), (&m.key, maker_nonce), (&gk, gn), (&ck, cn)], &joined(&[order, &tcoin]));
	let (credit, rest, tgot, tchange) = (&coins[0], &coins[1], &coins[2], &coins[3]);
	println!("filled 200,000: credit {}, rest {}, taker {} and {}; the taker's delegation recorded", credit.held.id, rest.held.id,
		tgot.held.id, tchange.held.id);
	let p = pool(&r, x);
	assert_eq!(n(&p, "transferred"), ORDER, "the order's coin counts as paid on out of round");

	// The maker delegates its order's coin: refused signed by its credit
	// key, and over the taker's leaves in another order; an unknown fill.
	let cv = credit.valid(&r);
	let bad = maker_delegation(&r, &transfer, &cv, &m.credits[0]);
	let a = r.http.post("order_fill_delegation", &bad);
	println!("refused, the maker's delegation by its credit key: {:?}", a.refusal());
	assert_eq!(a.refusal().0, "bad_signature");
	let swapped = Delegation::new(r.chain, xonly(&m.key), vec![xonly(&m.credits[0]), xonly(&m.key), change.owner, got.owner]).unwrap();
	let a = r.http.post("order_fill_delegation", &json!({"transfer_id": transfer,
		"signature": hex(sign_digest(&m.key, &swapped.message().digest, &random32()).as_ref())}));
	println!("refused, the maker's delegation over the taker's leaves swapped: {:?}", a.refusal());
	assert_eq!(a.refusal().0, "bad_signature");
	let a = r.http.post("order_fill_delegation_terms", &json!({"transfer_id": hex(&random32())}));
	println!("refused, the terms of an unknown fill: {} {:?}", a.status, a.refusal());
	assert_eq!((a.status, a.refusal().0.as_str()), (404, "unknown_fill"));
	let by_coin = r.http.post("order_fill_delegation_terms", &json!({"order_coin": order.held.id.to_string()})).ok();
	assert_eq!(by_coin["transfer_id"].as_str(), Some(transfer.as_str()), "a fill named by the order coin it spent");
	let good = maker_delegation(&r, &transfer, &cv, &m.key);
	assert_eq!(r.http.post("order_fill_delegation", &good).ok()["kept"], true);
	assert_eq!(r.http.post("order_fill_delegation_terms", &json!({"transfer_id": transfer})).ok()["delegated"], true);

	// The maker cancels the order resting again into a leaf of its own. A
	// wallet signs no delegation for it (the order's key delegated at the
	// fill); one sent as before arca#460 is not kept. Then everyone
	// refreshes and releases.
	let rv = rest.valid(&r);
	assert!(rv.is_rest() && !order.valid(&r).is_rest() && !credit.valid(&r).is_rest());
	let e = Delegation::for_reassignment(&rv, &[], &[]).unwrap_err();
	println!("a wallet's delegation for the order resting again: refused, {}", e);
	let mc = keypair("M, cancelled");
	let cancelled = pay(&r, rest, &[(mc, 0)], true).remove(0);
	assert!(r.db.store.delegation(&rest.held.id.0).await.unwrap().is_none(), "the cancel's delegation is not kept");
	let ids = [
		submit(&r, &[credit], &[keypair("M, credit new")]),
		submit(&r, &[plain], &[keypair("M, plain new")]),
		submit(&r, &[&cancelled], &[keypair("M, cancelled new")]),
		submit(&r, &[tgot], &[keypair("T, got new")]),
		submit(&r, &[tchange], &[keypair("T, change new")]),
	];
	let keys = ["M, credit new", "M, plain new", "M, cancelled new", "T, got new", "T, change new"];
	let given = [credit, plain, &cancelled, tgot, tchange];
	all_rounds(&r).await;
	for ((id, nn), (c, k)) in ids.iter().zip(given.iter().zip(keys)) {
		complete(&r, id, &[c], &[keypair(k)], nn, true).await;
	}
	let reclaims = passes(&r).await;
	let (px, py) = (pool(&r, x), pool(&r, y));
	println!("after every holder refreshed: reclaims {}; X locked {}, transferred {}; Y locked {}, transferred {}", reclaims.len(),
		n(&px, "locked"), n(&px, "transferred"), n(&py, "locked"), n(&py, "transferred"));
	for w in &reclaims {
		let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
		println!("reclaim {} ({:?}): {} vB; {}", common::flow::txid(w), w.state, tx.vsize(), w.detail);
	}
	let (h, ht) = (order.valid(&r).release_nodes()[0].1, tcoin.valid(&r).release_nodes()[0].1);
	let (ch, cht) = (server::delegations::can_complete(&r.db.store, &[order.held.id.0, plain.held.id.0], h).await.unwrap(),
		server::delegations::can_complete(&r.db.store, &[tcoin.held.id.0], ht).await.unwrap());
	println!("can complete: the order's node {}, the taker's {}", ch, cht);
	assert!(!ch && !cht, "the order resting again moved on without a delegation: neither node can come back early");
	assert!(reclaims.iter().all(|w| w.subject != h.to_vec() && w.subject != ht.to_vec()), "neither node comes back before its expiry");
	assert_eq!((n(&px, "transferred"), n(&py, "transferred")), (ORDER, VALUE), "both stay counted until their expiry");
}

/// A maker resting an order every round, which a taker fills whole: the
/// maker refreshes its credit and its other leaf of X each round, the taker
/// what it got once. The maker delegates its order's coin into each fill
/// when `delegated`. The pool of X after each round: locked, transferred,
/// reclaims so far.
async fn filled_every_round(delegated: bool, rounds: usize) -> Vec<(u64, u64, usize)> {
	let mut r = Running::start_with(|c, y| {
		c.batches.delegated_reclaim = true;
		c.assets.push(server::server::AssetSection::new(y, common::running::MIN_LEAF));
	}).await;
	let (x, y) = (r.x, r.y);
	r.fund_wallet_in(x, 300_000_000).await;
	r.fund_wallet_in(x, 300_000_000).await;
	r.fund_wallet_in(y, 300_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let tag = if delegated { "d" } else { "c" };
	let mb: Vec<Keypair> = (0..rounds).map(|k| keypair(&format!("maker board {} {}", k, tag))).collect();
	let tb: Vec<Keypair> = (0..rounds).map(|k| keypair(&format!("taker board {} {}", k, tag))).collect();
	let mboards = boards(&mut r, &mb, x).await;
	let mut held_x: Option<Coin> = None;
	let mut held_y: Option<Coin> = None;
	let mut last: Option<(Coin, Coin, Coin)> = None; // the credit, the taker's leaf and change
	let mut out = vec![];
	for k in 0..rounds {
		// The maker: its board and its leaf of X for this round's order and
		// a leaf of X; its credit and its leaf of Y for a leaf of Y. The
		// taker refreshes what the last fill gave it.
		let m = maker(&r, &format!("maker {} {}", k, tag));
		let px = keypair(&format!("maker x {} {}", k, tag));
		let mut give_x: Vec<&Coin> = vec![&mboards[k]];
		give_x.extend(held_x.iter());
		let total_x: u64 = give_x.iter().map(|c| c.valid(&r).value).sum();
		let (wo, no) = want_order(&m, ORDER, x);
		let (wp, np) = want_leaf(&px, x, total_x - ORDER);
		let idx = submit_wants(&r, &give_x, &[wo, wp]);
		let mut idy = None;
		let mut taker_ids = vec![];
		if let Some((credit, got, change)) = &last {
			let py = keypair(&format!("maker y {} {}", k, tag));
			let mut give_y: Vec<&Coin> = vec![credit];
			give_y.extend(held_y.iter());
			let total_y: u64 = give_y.iter().map(|c| c.valid(&r).value).sum();
			let (wy, ny) = want_leaf(&py, y, total_y);
			idy = Some((submit_wants(&r, &give_y, &[wy]), py, ny));
			for (c, label) in [(got, "got"), (change, "change")] {
				let nk = keypair(&format!("taker refreshed {} {} {}", label, k, tag));
				taker_ids.push((submit(&r, &[c], &[nk]), c.clone(), nk));
			}
		}
		all_rounds(&r).await;
		let made = complete(&r, &idx, &give_x, &[m.key, px], &[no, np], true).await;
		if let (Some((id, py, ny)), Some((credit, _, _))) = (&idy, &last) {
			let mut give_y: Vec<&Coin> = vec![credit];
			give_y.extend(held_y.iter());
			held_y = Some(complete(&r, id, &give_y, &[*py], &[*ny], true).await.remove(0));
		}
		for ((id, nn), c, nk) in &taker_ids {
			complete(&r, id, &[c], &[*nk], nn, true).await;
		}
		let (order, plain) = (made[0].clone(), made[1].clone());
		held_x = Some(plain);

		// The order rests; the taker fills it whole from a board of Y made
		// now (a board's service expiry must not come before the order's).
		let tboard = boards(&mut r, &tb[k..k + 1], y).await.remove(0);
		let st = publish(&r, &m, &order);
		let (gk, ck) = (keypair(&format!("taker got {} {}", k, tag)), keypair(&format!("taker change {} {}", k, tag)));
		let ((got, gn), (change, cn)) = (new_leaf(&gk), new_leaf(&ck));
		let (body, _) = fill_body(&r, &st, &order, &tboard, ORDER, &got, &change, true, &tb[k]);
		let done = r.http.post("order_fill", &body).ok();
		let transfer = done["transfer_id"].as_str().unwrap().to_string();
		let coins = fill_coins(&done, &[(&m.credits[0], m.credit_nonces[0]), (&gk, gn), (&ck, cn)], &joined(&[&order, &tboard]));
		if delegated {
			let d = maker_delegation(&r, &transfer, &coins[0].valid(&r), &m.key);
			assert_eq!(r.http.post("order_fill_delegation", &d).ok()["kept"], true);
		}
		last = Some((coins[0].clone(), coins[1].clone(), coins[2].clone()));
		let reclaims = passes(&r).await;
		let p = pool(&r, x);
		println!("{} round {}: reclaims {}; X locked {}, transferred {}, in flight {}", if delegated { "maker delegates" } else { "control" },
			k, reclaims.len(), n(&p, "locked"), n(&p, "transferred"), n(&p, "in_flight"));
		out.push((n(&p, "locked"), n(&p, "transferred"), reclaims.len()));
	}
	out
}

#[tokio::test(flavor = "multi_thread")]
async fn a_maker_filled_every_round_keeps_transferred_bounded() {
	const ROUNDS: usize = 5;
	let with = filled_every_round(true, ROUNDS).await;
	println!("maker delegates: transferred by round {:?}; reclaims {}", with.iter().map(|w| w.1).collect::<Vec<_>>(), with[ROUNDS - 1].2);
	assert!(with[ROUNDS - 1].2 >= ROUNDS - 1, "the batch of every round's order comes back at the next");
	assert!(with.iter().all(|w| w.1 <= ORDER), "transferred holds at most the last round's order: {:?}", with);
	let without = filled_every_round(false, ROUNDS).await;
	println!("control: transferred by round {:?}; reclaims {}", without.iter().map(|w| w.1).collect::<Vec<_>>(), without[ROUNDS - 1].2);
	assert_eq!(without[ROUNDS - 1].1, ROUNDS as u64 * ORDER, "without the maker's delegation every filled order waits for its expiry");
}

/// One of four leaves on a node is paid on with its delegation, to P and
/// change; P refreshes, releasing when `release`. Then the change and the
/// other three leaves refresh under a cap of 1,500,000. The most in flight
/// after any round, and whether the node came back (arca#450).
async fn payee_refreshes(tag: &str, release: bool) -> (u64, bool) {
	let cap = VALUE * 3 / 2;
	let names: Vec<String> = (0..4).map(|i| format!("{} U{}", tag, i)).collect();
	let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
	let (r, c) = first_leaves(Some(cap), &refs).await;
	let node = c[0].valid(&r).release_nodes()[0].1;
	assert!(c.iter().all(|co| co.valid(&r).release_nodes()[0].1 == node), "one lowest node for all four");
	let paid = pay(&r, &c[0], &[(keypair(&format!("{} P", tag)), 500_000), (keypair(&format!("{} U0 change", tag)), 0)], true);
	let k = keypair(&format!("{} P new", tag));
	let (pid, nn) = submit(&r, &[&paid[0]], &[k]);
	round(&r).await;
	complete(&r, &pid, &[&paid[0]], &[k], &nn, release).await;
	let held: Vec<Coin> = vec![paid[1].clone(), c[1].clone(), c[2].clone(), c[3].clone()];
	let mut pending = vec![];
	for (j, h) in held.iter().enumerate() {
		let k = keypair(&format!("{} r {}", tag, j));
		let (id, nn) = submit(&r, &[h], &[k]);
		pending.push((j, id, nn, k));
	}
	let (mut most, mut back) = (0, false);
	for rn in 0..4 {
		let Some(built) = r.server.rounds.run_round().await.unwrap() else { break };
		r.produce().await;
		r.bury().await;
		round_final(&r, &built.tx.txid()).await;
		let mut left = vec![];
		for (j, id, nn, k) in pending.drain(..) {
			if status(&r, &id)["state"] == "pending" {
				left.push((j, id, nn, k));
			} else {
				complete(&r, &id, &[&held[j]], &[k], &nn, true).await;
			}
		}
		pending = left;
		let reclaims = passes(&r).await;
		back |= reclaims.iter().any(|w| w.subject == node.to_vec());
		let p = pool(&r, r.x);
		most = most.max(n(&p, "in_flight"));
		println!("{} round {}: {} refreshes wait; in flight {} of a cap of {}; node back {}", tag, rn, pending.len(), n(&p, "in_flight"), cap, back);
		if pending.is_empty() {
			break;
		}
	}
	(most, back)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_payee_that_refreshes_without_a_release_holds_the_cap() {
	let (most, back) = payee_refreshes("norel", false).await;
	assert!(!back, "the node cannot come back: P's release never came");
	assert!(most <= VALUE * 3 / 2, "nothing runs past the cap as completing a node that cannot complete: {}", most);
	let (_, back) = payee_refreshes("control", true).await;
	assert!(back, "with P's release the node comes back");
}

/// The `htlc-1` send leaf of a payment out of the tree (arca#431): a batch
/// leaf pays one, with change, delegating; the payment is then decided as
/// A's node decides it (here written to the store: no Lightning node runs,
/// and `lightning_pay` covers the payment itself). The sender's release is
/// refused while the payment is paying and with another key; once it is
/// paid the sender releases, the change and the other leaf refresh, and the
/// node comes back by RECLAIM-D.
#[tokio::test(flavor = "multi_thread")]
async fn a_paid_sends_leaf_is_released_by_its_sender() {
	use arca_covenant::{HtlcDirection, HtlcTerms, RelativeTime, TransferPlan};
	use server::cosign::{InputRequest, OutputRequest, TransferRequest};
	let (r, c) = first_leaves(None, &["S", "D"]).await;
	let x = r.x;
	let node = c[0].valid(&r).release_nodes()[0].1;
	assert_eq!(c[1].valid(&r).release_nodes()[0].1, node, "one lowest node");
	let v = c[0].valid(&r);
	let (hk, ck) = (keypair("S, htlc"), keypair("S, change"));
	let preimage = random32();
	let hash = arca_covenant::script::sha256(&preimage);
	let (mut hl, _) = new_leaf(&hk);
	hl.htlc = Some(HtlcTerms { direction: HtlcDirection::Send, payment_hash: hash,
		timeout: arca_covenant::MedianTime::from_consensus(common::rounds::mtp(&r).to_consensus_u32() + 7 * 86_400).unwrap(),
		operator_delay: RelativeTime::from_units(hl.exit_delay.units() - 1).unwrap() });
	let (cl, cn) = new_leaf(&ck);
	let kept = v.value - 2_000;
	let outs = [(x, 400_000, hl), (x, kept - 2_000 - 400_000, cl)];
	let outputs: Vec<ExplicitOutput> = outs.iter().map(|(a, val, l)| ExplicitOutput::new(*a, *val, l.policy(xonly(&r.s), r.chain).script_pubkey())).collect();
	let plan = TransferPlan { inputs: vec![(v.clone(), kept)], outputs: outputs.clone() };
	let sk = &c[0].held.key;
	let d = Delegation::for_reassignment(&v, &outputs, &[hl, cl]).unwrap();
	let req = TransferRequest {
		inputs: vec![InputRequest { leaf_id: v.id, checkpoint_value: kept,
			checkpoint_sig: sign_digest(sk, &plan.checkpoint_message(0).unwrap().digest, &random32()),
			reassignment_sig: sign_digest(sk, &plan.reassignment_message(0).unwrap().digest, &random32()),
			delegation_sig: Some(sign_digest(sk, &d.message().digest, &random32())) }],
		outputs: outs.iter().map(|(a, val, l)| OutputRequest { asset: *a, value: *val, leaf: *l, mailbox: None, until: None }).collect(),
	};
	let done = r.server.cosigner.cosign_htlc(&req).await.unwrap();
	let (htlc_id, htlc_record) = done.outputs[0].clone();
	let change = Coin { held: Held { key: ck, nonce: cn, id: done.outputs[1].0, record: done.outputs[1].1.clone() }, bases: c[0].bases.clone() };
	let row = server::store::SendRow { payment_hash: hash, asset: { use elements::hashes::Hash; x.into_inner().to_byte_array() },
		invoice: "lnsq1test".into(), amount: 399_000, fee: 1_000, transfer_id: done.transfer_id, htlc_leaf_id: htlc_id.0,
		state: server::store::SendState::Paying, preimage: None, reason: None };
	r.db.store.record_send(&row).await.unwrap();

	// The terms and a release while the payment is paying: refused.
	let terms_of = || r.http.post("lightning_send_release_terms", &json!({"payment_hash": hex(&hash)}));
	let a = terms_of();
	println!("refused, the release terms of a payment still paying: {:?}", a.refusal());
	assert_eq!(a.refusal().0, "release_early");
	r.db.store.decide_send(&hash, Some(&preimage), None).await.unwrap();
	let t = terms_of().ok();
	assert_eq!(t["nodes"], json!([hex(&node)]), "{}", t);
	assert_eq!(t["released"], json!([]));
	let round_tx: Transaction = elements::encode::deserialize(&common::client::unhex(t["round"]["tx"].as_str().unwrap())).unwrap();
	let cv = t["round"]["connector_vout"].as_u64().unwrap() as u32;
	let hv = htlc_record.resolve(&c[0].bases, &r.policy()).unwrap();
	assert!(Release::for_paid_send(&hv, &random32(), &round_tx, cv).is_err(), "a preimage of another hash");
	let rel = Release::for_paid_send(&hv, &preimage, &round_tx, cv).unwrap();
	assert_eq!(rel.len(), 1);
	let body = |key: &Keypair| json!({"payment_hash": hex(&hash), "round_txid": round_tx.txid().to_string(),
		"releases": [{"node": hex(&rel[0].node_hash), "signature": hex(sign_digest(key, &rel[0].message().digest, &random32()).as_ref())}]});
	let a = r.http.post("lightning_send_release", &body(sk));
	println!("refused, a paid send's release by the coin's sender's old key: {:?}", a.refusal());
	assert_eq!(a.refusal().0, "bad_signature");
	let a = r.http.post("lightning_send_release", &body(&hk)).ok();
	assert_eq!(a["released"], json!([hex(&node)]));
	assert_eq!(terms_of().ok()["released"], json!([hex(&node)]));

	// The change and D refresh and release: the node comes back.
	let (k1, k2) = (keypair("S, change new"), keypair("D new"));
	let (i1, n1) = submit(&r, &[&change], &[k1]);
	let (i2, n2) = submit(&r, &[&c[1]], &[k2]);
	round(&r).await;
	complete(&r, &i1, &[&change], &[k1], &n1, true).await;
	complete(&r, &i2, &[&c[1]], &[k2], &n2, true).await;
	let reclaims = passes(&r).await;
	let mine: Vec<_> = reclaims.iter().filter(|w| w.subject == node.to_vec()).collect();
	for w in &mine {
		let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
		println!("reclaim {} ({:?}): {} vB; {}", common::flow::txid(w), w.state, tx.vsize(), w.detail);
	}
	assert!(mine.iter().any(|w| w.state == server::store::NurseryState::Final), "the node comes back with the sender's release");
	assert_eq!(n(&pool(&r, x), "transferred"), 0);
}

// ---------------------------------------------------------------------------
// The order resting again, against an operator acting alone (arca#460).
// ---------------------------------------------------------------------------

/// The maker's delegation of the order coin a fill spent, as a wallet
/// signed it before arca#460: over the fill's outputs in `made`'s record,
/// whatever its order coin, which `Delegation::for_filled_order` now
/// refuses for an order resting again.
fn maker_delegation_unchecked(made: &arca_covenant::ValidCoin, takers: &[NewLeaf], signer: &Keypair) -> elements::secp256k1_zkp::schnorr::Signature {
	let ValidOrigin::Fill { order, outputs, .. } = &made.origin else { panic!("a coin a fill made") };
	let d = Delegation::for_fill(&order.leaf, &order.leaf.order_policy().unwrap(), outputs, takers).unwrap();
	sign_digest(signer, &d.message().digest, &random32())
}

/// The taker's leaves of fill `transfer`, as the operator names them.
fn takers_of(r: &Running, transfer: &str) -> Vec<NewLeaf> {
	let t = r.http.post("order_fill_delegation_terms", &json!({"transfer_id": transfer})).ok();
	t["takers"].as_array().unwrap().iter().map(|l| NewLeaf {
		enclave: None, v2: false, htlc: None, landing: None,
		owner: elements::secp256k1_zkp::XOnlyPublicKey::from_slice(&common::client::unhex(l["owner"].as_str().unwrap())).unwrap(),
		owner_nonce: common::client::unhex(l["owner_nonce"].as_str().unwrap()).try_into().unwrap(),
		creator_nonce: common::client::unhex(l["creator_nonce"].as_str().unwrap()).try_into().unwrap(),
		exit_delay: arca_covenant::RelativeTime::from_units(l["exit_delay_units"].as_u64().unwrap() as u16).unwrap(),
	}).collect()
}

/// An atom of the connector asset of each round of `rounds`, issued from
/// the round's connector output to a bare `OP_TRUE` and confirmed, as an
/// operator acting alone issues them: each its outpoint and output.
async fn atoms_by_hand(r: &Running, rounds: &[i64]) -> Vec<(elements::OutPoint, elements::TxOut)> {
	use arca_covenant::spend::FeeSource;
	let mut out = vec![];
	for id in rounds {
		let row = r.db.store.round(*id).await.unwrap().unwrap();
		let round: Transaction = elements::encode::deserialize(&row.tx).unwrap();
		let conn = elements::OutPoint::new(round.txid(), row.connector_vout);
		let held = ExplicitOutput::from_txout(&round.output[row.connector_vout as usize]).unwrap();
		let ks = arca_covenant::ConnectorPolicy { operator: xonly(&r.s) }
			.issuance(conn, (held.asset, held.value), common::node::op_true(), &[], &FeeSource::Reserve).unwrap();
		let sig = sign_digest(&r.s, &ks.sighash(r.chain.genesis_hash()).unwrap(), &random32());
		let tx = ks.finish(vec![sig.as_ref().to_vec()]).tx;
		r.rt.client().send_raw_transaction(&tx).unwrap();
		out.push((elements::OutPoint::new(tx.txid(), 0), tx.output[0].clone()));
	}
	r.produce().await;
	out
}

/// The reclaim by RECLAIM-D of the lowest node at the top of `order`'s
/// one-level tree (its batch output), with one tree per owner `slots` in
/// owner order, built and signed by hand as an operator acting alone would:
/// the node's value less 5,000 to `OP_TRUE`, its reserve the fee, the
/// connector atoms `atoms` back to `OP_TRUE`.
fn reclaim_by_hand(r: &Running, order: &Coin, atoms: &[(elements::OutPoint, elements::TxOut)],
	slots: &[server::delegations::Consent]) -> Transaction
{
	use arca_covenant::spend::FeeSource;
	let v = order.valid(r);
	let ValidOrigin::Leaf { valid, .. } = &v.origin else { panic!("the order's first coin is a batch leaf") };
	assert_eq!(valid.branch.nodes.len(), 1, "a one-level tree: its lowest node is the batch output");
	let lowest = &valid.branch.nodes[0];
	let at = elements::OutPoint::new(valid.round_txid, valid.batch_vout);
	let asset = lowest.children[0].asset;
	let outs = [ExplicitOutput::new(asset, lowest.value - 5_000, common::node::op_true())];
	let ks = lowest.reclaim_delegated_tx(at, atoms, &outs, common::node::op_true(), &FeeSource::Reserve).unwrap();
	let trees: Vec<_> = slots.iter().map(|c| c.tree(&ks.prevouts).unwrap()).collect();
	let sig = sign_digest(&r.s, &ks.sighash(r.chain.genesis_hash()).unwrap(), &random32());
	let items = lowest.reclaim_delegated_items(r.chain, &sig, &trees).unwrap();
	ks.finish(items).tx
}

/// RV5's reproduction of arca#460, after the fix. An order O of 500,000
/// (key K) rests on lowest node H beside the maker's plain leaf. Taker 1
/// fills 200,000: credit 1, the order resting again R (also K), taker 1's
/// two leaves; the maker delegates O into the fill. Then R moves on: filled
/// whole by taker 2 (`cancel` false), or cancelled by its maker into a leaf
/// of its own (`cancel` true). The wallets sign no delegation for R; the
/// one a wallet signed before the fix is not kept. Only the coins of R's
/// move and the plain leaf refresh and release; credit 1 and taker 1's
/// coins are held. Then the operator, alone:
/// - points O's slot at R in its own store (RV5's row): no reclaim of H;
/// - also keeps the earlier wallet's delegation of R: not followed;
/// - builds the reclaim of H by hand with RV5's tree, the only delegation
///   K signs (O's into fill 1) in R's place: refused in a block, for the
///   signature. The same reclaim with the earlier wallet's signature is
///   taken by the node, so the refusal is that signature's and nothing
///   else's.
async fn rest_moves_on(cancel: bool) {
	let tag = if cancel { "cancel" } else { "fill2" };
	let mut r = Running::start_plain_on(&["-acceptnonstdtxn"], |c, y| {
		c.batches.delegated_reclaim = true;
		c.assets.push(server::server::AssetSection::new(y, common::running::MIN_LEAF));
	}).await;
	let (x, y) = (r.x, r.y);
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(y, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let m = maker(&r, &format!("{} M", tag));
	let (mk2, tk1, tk2) = (keypair(&format!("{} M plain", tag)), keypair(&format!("{} T1", tag)), keypair(&format!("{} T2", tag)));
	let bm = boards(&mut r, &[keypair(&format!("{} M board", tag))], x).await.remove(0);
	let bt = boards(&mut r, &[keypair(&format!("{} T1 board", tag)), keypair(&format!("{} T2 board", tag))], y).await;
	let (wo, no) = want_order(&m, ORDER, x);
	let (wp, np) = want_leaf(&mk2, x, VALUE - ORDER);
	let idm = submit_wants(&r, &[&bm], &[wo, wp]);
	let (w1, n1) = want_leaf(&tk1, y, VALUE);
	let id1 = submit_wants(&r, &[&bt[0]], &[w1]);
	let (w2, n2) = want_leaf(&tk2, y, VALUE);
	let id2 = submit_wants(&r, &[&bt[1]], &[w2]);
	all_rounds(&r).await;
	let made = complete(&r, &idm, &[&bm], &[m.key, mk2], &[no, np], true).await;
	let (order, plain) = (&made[0], &made[1]);
	let t1 = complete(&r, &id1, &[&bt[0]], &[tk1], &[n1], true).await.remove(0);
	let t2 = complete(&r, &id2, &[&bt[1]], &[tk2], &[n2], true).await.remove(0);
	let h = order.valid(&r).release_nodes()[0].1;
	let st = publish(&r, &m, order);

	// Fill 1, by taker 1: 200,000 of the 500,000; both delegate.
	let (gk1, ck1) = (keypair(&format!("{} T1 got", tag)), keypair(&format!("{} T1 change", tag)));
	let ((got1, gn1), (ch1, cn1)) = (new_leaf(&gk1), new_leaf(&ck1));
	let (body, _) = fill_body(&r, &st, order, &t1, 200_000, &got1, &ch1, true, &tk1);
	let done = r.http.post("order_fill", &body).ok();
	let tr1 = done["transfer_id"].as_str().unwrap().to_string();
	let maker_nonce = match &order.held.record { CoinRecord::Leaf { record, .. } => record.owner_nonce, _ => unreachable!() };
	let c1 = fill_coins(&done, &[(&m.credits[0], m.credit_nonces[0]), (&m.key, maker_nonce), (&gk1, gn1), (&ck1, cn1)], &joined(&[order, &t1]));
	let (credit1, rest, tgot1, tch1) = (&c1[0], &c1[1], &c1[2], &c1[3]);
	let d = maker_delegation(&r, &tr1, &credit1.valid(&r), &m.key);
	assert_eq!(r.http.post("order_fill_delegation", &d).ok()["kept"], true);
	assert!(rest.valid(&r).is_rest() && rest.valid(&r).leaf.owner == order.valid(&r).leaf.owner, "R is the order resting again, under K");
	assert!(tgot1.valid(&r).release_nodes().iter().any(|(_, n)| *n == h), "taker 1's leaf rests on H");
	let d1 = r.db.store.delegation(&order.held.id.0).await.unwrap().expect("O's delegation into fill 1");
	let d1_sig = elements::secp256k1_zkp::schnorr::Signature::from_slice(&d1.signature).unwrap();
	println!("{}: order {} (key K) on H {}; fill 1: credit {}, rest {} (K), taker 1 {} and {}", tag, order.held.id, hex(&h),
		credit1.held.id, rest.held.id, tgot1.held.id, tch1.held.id);

	// R moves on. A wallet signs no delegation for it; the one a wallet
	// signed before the fix (`old`) is sent and not kept.
	let mut refresh: Vec<(Coin, Keypair)> = vec![(plain.clone(), keypair(&format!("{} M plain new", tag)))];
	let old = if cancel {
		let e = Delegation::for_reassignment(&rest.valid(&r), &[], &[]).unwrap_err();
		println!("{}: the wallet's delegation of R into its cancel: refused, {}", tag, e);
		let mc = keypair(&format!("{} M cancelled", tag));
		let (body, nonces) = pay_body(&r, rest, &[(mc, 0)], true);
		let old = elements::secp256k1_zkp::schnorr::Signature::from_slice(&common::client::unhex(body["inputs"][0]["delegation_sig"].as_str().unwrap())).unwrap();
		let done = r.http.post("cosign_transfer", &body).ok();
		let id: arca_covenant::LeafId = done["outputs"][0]["leaf_id"].as_str().unwrap().parse().unwrap();
		let cancelled = Coin { held: held_by(&r, &mc, nonces[0], id), bases: rest.bases.clone() };
		println!("{}: the maker cancels R into {}; the delegation sent with it as before the fix: kept {}", tag, cancelled.held.id,
			r.db.store.delegation(&rest.held.id.0).await.unwrap().is_some());
		refresh.push((cancelled, keypair(&format!("{} M cancelled new", tag))));
		old
	} else {
		let st2 = r.http.post("order_state", &json!({"orders": [st["order"]]})).ok()["orders"][0].clone();
		assert_eq!(st2["coin"].as_str().unwrap(), rest.held.id.to_string(), "the order rests at R");
		let (gk2, ck2) = (keypair(&format!("{} T2 got", tag)), keypair(&format!("{} T2 change", tag)));
		let ((got2, gn2), (ch2, cn2)) = (new_leaf(&gk2), new_leaf(&ck2));
		let (body, _) = fill_body(&r, &st2, rest, &t2, 300_000, &got2, &ch2, true, &tk2);
		let done = r.http.post("order_fill", &body).ok();
		let tr2 = done["transfer_id"].as_str().unwrap().to_string();
		let c2 = fill_coins(&done, &[(&m.credits[1], m.credit_nonces[1]), (&gk2, gn2), (&ck2, cn2)], &joined(&[rest, &t2]));
		let e = Delegation::for_filled_order(&c2[0].valid(&r), &takers_of(&r, &tr2)).unwrap_err();
		println!("{}: the wallet's delegation of R into fill 2: refused, {}", tag, e);
		let old = maker_delegation_unchecked(&c2[0].valid(&r), &takers_of(&r, &tr2), &m.key);
		let a = r.http.post("order_fill_delegation", &json!({"transfer_id": tr2, "signature": hex(old.as_ref())})).ok();
		println!("{}: taker 2 fills R whole: credit 2 {}, taker 2 {} and {}; R's delegation as before the fix: kept {}", tag,
			c2[0].held.id, c2[1].held.id, c2[2].held.id, a["kept"]);
		assert_eq!(a["kept"], false);
		for (co, l) in c2.iter().zip(["credit2 new", "T2 got new", "T2 change new"]) {
			refresh.push((co.clone(), keypair(&format!("{} {}", tag, l))));
		}
		old
	};
	assert!(r.db.store.delegation(&rest.held.id.0).await.unwrap().is_none(), "R's delegation is not kept");
	let ids: Vec<_> = refresh.iter().map(|(c, k)| submit(&r, &[c], &[*k])).collect();
	all_rounds(&r).await;
	for ((id, nn), (c, k)) in ids.iter().zip(&refresh) {
		complete(&r, id, &[c], &[*k], nn, true).await;
	}
	let of_h = |v: &[server::store::WatcherTxRow]| v.iter().filter(|w| w.subject == h.to_vec()).count();
	let slots = [order.held.id.0, plain.held.id.0];
	let honest = passes(&r).await;
	let cc = server::delegations::can_complete(&r.db.store, &slots, h).await.unwrap();
	println!("{}: honest operator: reclaims of H {} (of {}); can_complete(H) {}", tag, of_h(&honest), honest.len(), cc);
	assert!(of_h(&honest) == 0 && !cc);

	// The operator's store: O's slot named by R (RV5's row).
	let (c, conn) = tokio_postgres::connect(&r.db.url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(async move { let _ = conn.await; });
	let n = c.execute("UPDATE batch_leaf SET leaf_id = $1 WHERE leaf_id = $2", &[&&rest.held.id.0[..], &&order.held.id.0[..]]).await.unwrap();
	assert_eq!(n, 1);
	let after = passes(&r).await;
	println!("{}: O's slot named by R in the store: reclaims of H {}", tag, of_h(&after));
	assert_eq!(of_h(&after), 0);

	// And the earlier wallet's delegation of R, kept as a server before
	// the fix kept it: not followed.
	let server::store::SpentBy::Reassignment { transfer_id, outputs } = r.db.store.spent_by(&rest.held.id.0).await.unwrap() else {
		panic!("R moved by a reassignment")
	};
	assert!(r.db.store.insert_delegation(&rest.held.id.0, &transfer_id, old.as_ref()).await.unwrap());
	let after = passes(&r).await;
	let cc = server::delegations::can_complete(&r.db.store, &[rest.held.id.0, plain.held.id.0], h).await.unwrap();
	println!("{}: with the earlier wallet's delegation of R kept too: reclaims of H {}; can_complete {}", tag, of_h(&after), cc);
	assert!(of_h(&after) == 0 && !cc);
	for (label, co) in [("credit 1", credit1), ("taker 1 got", tgot1), ("taker 1 change", tch1)] {
		let s: String = c.query_one("SELECT state::TEXT FROM leaf WHERE leaf_id = $1", &[&&co.held.id.0[..]]).await.unwrap().get(0);
		println!("{}: {} {}: {} in the store, rests on H", tag, label, co.held.id, s);
	}

	// By hand, RV5's tree: O's slot by K's delegation into R's move, each
	// of its outputs by its holder's release; the plain leaf's by its own.
	let mut to = vec![];
	for (out, k) in &outputs {
		let k = elements::secp256k1_zkp::XOnlyPublicKey::from_slice(k).unwrap();
		to.push(server::delegations::consent(&r.db.store, *out, k, h, 30).await.unwrap().expect("a refreshed holder's release"));
	}
	let p = server::delegations::consent(&r.db.store, plain.held.id.0, plain.valid(&r).leaf.owner, h, 30).await.unwrap().expect("the plain leaf's release");
	let key = order.valid(&r).leaf.owner;
	let slot = |sig| server::delegations::Consent::Delegation { key, sig, to: to.clone() };
	let mut rounds = vec![];
	slot(d1_sig).rounds(&mut rounds);
	p.rounds(&mut rounds);
	let atoms = atoms_by_hand(&r, &rounds).await;
	let forged = reclaim_by_hand(&r, order, &atoms, &[slot(d1_sig), p.clone()]);
	let control = reclaim_by_hand(&r, order, &atoms, &[slot(old), p.clone()]);
	let steps = slot(old).steps() + p.steps();
	let t = r.rt.client().test_mempool_accept(&[&control]).unwrap().remove(0);
	println!("{}: control, the earlier wallet's signature in R's place: {} vB, {} steps; testmempoolaccept allowed {} {:?}", tag,
		control.vsize(), steps, t.allowed, t.reject_reason);
	assert!(t.allowed, "the reclaim is built right: only the signature can refuse it");
	let h0 = r.rt.client().block_count().unwrap();
	let e = match r.rt.client().generate_block("raw(51)", &[&forged]) {
		Ok(b) => panic!("{}: the reclaim with K's only delegation was MINED in {}", tag, b),
		Err(e) => e.to_string(),
	};
	assert_eq!(r.rt.client().block_count().unwrap(), h0);
	println!("{}: RESULT the reclaim of H with K's only delegation (O's into fill 1) in R's place, {} vB: refused in a block: {}", tag,
		forged.vsize(), e);
	assert!(e.contains("Invalid Schnorr signature"), "{}", e);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_order_resting_again_cannot_release_the_orders_node_by_a_second_fill() {
	rest_moves_on(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_order_resting_again_cannot_release_the_orders_node_by_a_cancel() {
	rest_moves_on(true).await;
}
