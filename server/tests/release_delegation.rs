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
//!    the round's other assets.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::hashes::Hash;
use elements::{AssetId, Transaction};
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::{CoinRecord, Delegation, ExplicitOutput, NewLeaf, Release, ValidOrigin};
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
		let d = Delegation::for_reassignment(&v, &plan_outputs, &leaves).unwrap();
		body["inputs"][0]["delegation_sig"] = json!(hex(sign_digest(&coin.held.key, &d.message().digest, &random32()).as_ref()));
	}
	let done = r.http.post("cosign_transfer", &body).ok();
	let ids: Vec<arca_covenant::LeafId> = done["outputs"].as_array().unwrap().iter()
		.map(|o| o["leaf_id"].as_str().unwrap().parse().unwrap()).collect();
	to.iter().zip(nonces).zip(ids).map(|(((k, _), nonce), id)| Coin { held: held_by(r, k, nonce, id), bases: coin.bases.clone() }).collect()
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
	assert!(["delegated", "open_reassignment", "not_participating"].contains(&e["error"]["code"].as_str().unwrap_or("")), "{}", e);
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
