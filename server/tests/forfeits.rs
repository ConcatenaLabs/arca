//! The forfeit swap, against a whole server on an anchored proof-of-stake
//! regtest chain: a refresh end to end (board, participation, round final,
//! forfeit, preimage, release), the new leaf live and paid on out of round,
//! and every refusal by its code: forfeits before the round or before it is
//! final, for the wrong unlock hash, the wrong connector, another coin or
//! another margin, a forfeit set or an authorisation set that is not exact,
//! authorisations by another key or not yet usable, a release before the
//! preimage, a release of a coin with an open reassignment, of a coin not in
//! the participation, of a board, and by another key.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::Transaction;
use serde_json::{json, Value};

use arca_covenant::script::sha256;
use arca_covenant::sign::sign_digest;
use arca_covenant::{connector_asset, CoinRecord, Forfeit, LeafId, MedianTime, RelativeTime, Release, ValidCoin, ValidLeaf};
use common::client::{auths_json, forfeit_sig, hex, new_leaf, participation_body, random32, transfer_body, unhex, want_leaf, Answer, Held};
use common::keys::{keypair, xonly};
use common::rounds::{created, credited_board, round_final, start, status, validate_new_leaf, VALUE};
use common::running::Running;

fn refused(a: Answer, status: i32, code: &str) {
	let (c, m) = a.refusal();
	assert_eq!((a.status, c.as_str()), (status, code), "{}", a.json);
	println!("refused {} {}: {}", status, code, m);
}

/// A coin the owner gives up: its record resolved, as its owner holds it.
fn coin_of(r: &Running, held: &Held, bases: &[Transaction]) -> ValidCoin {
	held.record.resolve(bases, &r.policy()).unwrap()
}

/// The forfeit of `old` for the new leaf `new` of the round `round`, as its
/// owner builds it: from the validated leaf and round, with the refund delay
/// and margin the participation's status names.
fn forfeit_for(old: &ValidCoin, new: &ValidLeaf, round: &Transaction, st: &Value, input: usize) -> Forfeit {
	let c = st["round"]["connector_vout"].as_u64().unwrap() as u32;
	let delay = RelativeTime::from_units(st["refund_delay_units"].as_u64().unwrap() as u16).unwrap();
	let margin: u64 = st["inputs"][input]["margin"].as_str().unwrap().parse().unwrap();
	Forfeit::for_refresh(old.leaf, (old.asset, old.value), old.id, new, round, c, delay, margin).unwrap()
}

fn forfeit_body(id: &[u8; 32], forfeits: &[(LeafId, String)], leaves: &[Value]) -> Value {
	json!({
		"participation_id": hex(id),
		"forfeits": forfeits.iter().map(|(l, s)| json!({"leaf_id": l.to_string(), "signature": s})).collect::<Vec<_>>(),
		"leaves": leaves,
	})
}

/// One refresh: `old` (held under `key`, from `bases`) into a new leaf of the
/// same value for `new_key`; the participation accepted and its id, and the
/// new leaf's nonce.
fn participate(r: &Running, old: &Held, new_key: &Keypair) -> ([u8; 32], [u8; 32]) {
	let (w, nonce) = want_leaf(new_key, r.x, VALUE);
	let (body, id) = participation_body(&[old], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	(id, nonce)
}

/// A forfeit the signer declines for what it asks is refused for good, and
/// it records nothing: the participation is not released and no preimage
/// goes out. The signer here gets every owner's signature with one character
/// changed (a tap in front of it), so none verifies. Once the signer signs
/// again, the same forfeit releases the participation. A signer that cannot
/// be reached leaves the forfeit recorded with its owner's half, and it is
/// completed once the signer answers.
///
/// With batches with a sweep, the forfeit is handed over once the round is
/// final, and the signer is asked for the operator's half in that request:
/// `declined` (422), then `signer_unavailable` (503), then the same request
/// completes it. With batches without a sweep (the round held for its
/// forfeits), the forfeit is handed over before the round goes out, and the
/// signer is asked only once the node holds the round
/// ([`server::forfeits::Forfeits::fill_unsigned`], woken as the round goes
/// out): the declined fill leaves it without the operator's half, an
/// unreachable signer fails the fill, and the fill once the signer answers
/// completes it; the round's release follows.
#[tokio::test(flavor = "multi_thread")]
async fn a_forfeit_the_signer_declines_is_refused_for_good() {
	let mut r = start().await;
	let x = r.x;
	let a = keypair("A");
	let (a_board, a_tx) = credited_board(&mut r, &a, x).await;
	let a2 = keypair("A, new");
	let (pa, a2_nonce) = participate(&r, &a_board, &a2);
	let a_old = coin_of(&r, &a_board, std::slice::from_ref(&a_tx));
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let round_txid = built.tx.txid();
	let held = r.server.store.round_by_txid(&round_txid.to_byte_array()).await.unwrap()
		.is_some_and(|x| x.state == server::store::RoundState::Built);
	let round_id = r.server.store.round_by_txid(&round_txid.to_byte_array()).await.unwrap().unwrap().round_id;
	assert_eq!(r.server.store.round_wakes_fill(round_id).await.unwrap(), held,
		"a refresh round wakes the fill as it goes out exactly when it is held (no sweep)");
	let good = if held {
		let body = common::rounds::hand_over_body(&r, &pa, &common::client::made(&pa).unwrap()).await;
		let done = r.http.post("forfeit_leaves", &body).ok();
		assert!(done.get("preimage").is_none(), "no preimage before the round is broadcast: {}", done);
		body
	} else {
		r.produce().await;
		r.bury().await;
		round_final(&r, &round_txid).await;
		let st = status(&r, &pa);
		let (a2_valid, a2_record, round) = validate_new_leaf(&r, &pa, 0, &a2, &a2_nonce);
		let f = forfeit_for(&a_old, &a2_valid, &round, &st, 0);
		forfeit_body(&pa, &[(a_board.id, forfeit_sig(&f, &a))], &[auths_json(&a2_valid, &a2, created(&a2_record))])
	};
	let entries = r.signer_entries().await.len();
	let genesis = r.chain.genesis_hash();
	let key = r.s;
	let tap = common::signer::SignerTap::on(&r.signer);
	tap.garble(true);
	if held {
		// The round goes out, and the fill it wakes is declined; so is
		// every fill while the signer declines.
		r.server.rounds.pass().await.unwrap();
		assert_eq!(r.server.store.round_by_txid(&round_txid.to_byte_array()).await.unwrap().unwrap().state,
			server::store::RoundState::Broadcast, "the round went out with its forfeits in");
		for _ in 0..2 {
			assert_eq!(r.server.forfeits.fill_unsigned().await.unwrap(), 0, "a declined forfeit is not filled");
		}
	} else {
		for _ in 0..2 {
			refused(r.http.post("forfeit_leaves", &good), 422, "declined");
		}
	}
	assert_eq!(status(&r, &pa)["state"], "issued", "not released");
	assert_eq!(r.signer_entries().await.len(), entries, "the signer recorded nothing");
	drop(tap);
	r.signer.kill();
	if held {
		let e = r.server.forfeits.fill_unsigned().await.unwrap_err().to_string();
		println!("the fill with the signer away: {}", e);
		assert!(e.contains("cannot reach the signer"), "{}", e);
	} else {
		refused(r.http.post("forfeit_leaves", &good), 503, "signer_unavailable");
	}
	tokio::task::block_in_place(|| r.signer.restart(&key, genesis));
	if held {
		// Filled by this call, or by the fill the minute's run made first.
		let filled = r.server.forfeits.fill_unsigned().await.unwrap();
		println!("filled once the signer signs: {}", filled);
		assert_eq!(r.server.forfeits.fill_unsigned().await.unwrap(), 0, "nothing left to fill");
		r.produce().await;
		r.bury().await;
		round_final(&r, &round_txid).await;
		let http = r.http.clone();
		let id = pa;
		r.wait("the participation to be released", || {
			http.post("participation_status", &json!({"participation_id": hex(&id)})).ok()["state"] == "released"
		}).await;
		let done = r.http.post("forfeit_leaves", &good).ok();
		println!("the same forfeit once the signer signs: {} {}", done["state"], done["preimage"]);
		assert_eq!(done["state"], "released", "{}", done);
	} else {
		let done = r.http.post("forfeit_leaves", &good).ok();
		println!("the same forfeit once the signer signs: {} {}", done["state"], done["preimage"]);
		assert_eq!(done["state"], "released", "{}", done);
	}
	assert_eq!(r.signer_entries().await.len(), entries + 1, "the forfeit, recorded once");
}

/// A refresh round held for its forfeits (no sweep) has the operator's half
/// of its forfeits signed as the pass over the rounds hands it to the node,
/// not at the minute's run, which comes up to 60 s after: whole within 20 s
/// of the go-out (tens of milliseconds alone, a few seconds with the suite in
/// parallel on a loaded machine). Without a sweep whatever
/// `ARCA_TEST_NO_SWEEP` says.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_refresh_round_has_its_forfeits_co_signed_as_it_goes_out() {
	let mut r = common::rounds::start_held().await;
	let x = r.x;
	let a = keypair("A");
	let (a_board, _) = credited_board(&mut r, &a, x).await;
	let (pa, _) = participate(&r, &a_board, &keypair("A, new"));
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let round_txid = built.tx.txid();
	let row = r.server.store.round_by_txid(&round_txid.to_byte_array()).await.unwrap().unwrap();
	assert_eq!(row.state, server::store::RoundState::Built, "held for its forfeits");
	assert!(r.server.store.round_wakes_fill(row.round_id).await.unwrap(), "a refresh round without a sweep wakes the fill");
	common::rounds::hand_over_held(&r, &round_txid).await;
	let unsigned = || async { r.server.store.unsigned_forfeits().await.unwrap().iter().filter(|f| f.round_id == row.round_id).count() };
	r.server.rounds.pass().await.unwrap();
	let out = std::time::Instant::now();
	let n = r.server.store.nursery_get(&round_txid.to_byte_array()).await.unwrap().unwrap();
	assert_eq!(n.last_result.as_deref(), Some("accepted"), "the node holds the round");
	loop {
		if unsigned().await == 0 {
			break;
		}
		assert!(out.elapsed() < std::time::Duration::from_secs(20), "the forfeit still lacks the operator's half 20 s after the round went out (the minute's run comes at 60 s)");
		tokio::time::sleep(std::time::Duration::from_millis(20)).await;
	}
	println!("the operator's half filled {} ms after the round went out", out.elapsed().as_millis());
	r.produce().await;
	r.bury().await;
	round_final(&r, &round_txid).await;
	let http = r.http.clone();
	r.wait("the participation to be released", || {
		http.post("participation_status", &json!({"participation_id": hex(&pa)})).ok()["state"] == "released"
	}).await;
}

/// A round held for its forfeits that the node refuses when it goes out (its
/// fee asset delisted there), and takes at the nursery's next broadcast once
/// the asset is listed again, has the operator's half of its forfeits signed
/// as the node takes it, not at the next minute's run: the forfeits are
/// whole within 15 s of the node's acceptance, where the minute's run comes
/// about 30 s after it. Without a sweep whatever
/// `ARCA_TEST_NO_SWEEP` says.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_round_the_node_takes_late_has_its_forfeits_completed_at_once() {
	let mut r = common::rounds::start_held().await;
	let x = r.x;
	let a = keypair("A");
	let (a_board, _) = credited_board(&mut r, &a, x).await;
	let (pa, _) = participate(&r, &a_board, &keypair("A, new"));
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let round_txid = built.tx.txid();
	let row = r.server.store.round_by_txid(&round_txid.to_byte_array()).await.unwrap().unwrap();
	assert_eq!(row.state, server::store::RoundState::Built, "held for its forfeits");
	common::rounds::hand_over_held(&r, &round_txid).await;
	// The node refuses the round: its fee asset is not listed there.
	let fee_asset = elements::AssetId::from_byte_array(row.fee_asset);
	let rates: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
	let rate = rates[fee_asset.to_string()].as_u64().unwrap();
	let mut without = rates.as_object().unwrap().clone();
	without.remove(&fee_asset.to_string());
	let _: Value = r.rt.client().call("setfeeexchangerates", &[Value::Object(without)]).unwrap();
	r.server.rounds.pass().await.unwrap();
	let n = r.server.store.nursery_get(&round_txid.to_byte_array()).await.unwrap().unwrap();
	println!("the round handed to the node: {:?}", n.last_result);
	assert_ne!(n.last_result.as_deref(), Some("accepted"), "the node refused it");
	let unsigned = || async { r.server.store.unsigned_forfeits().await.unwrap().iter().filter(|f| f.round_id == row.round_id).count() };
	assert_eq!(unsigned().await, 1, "the forfeit waits for the node to hold the round");
	// Listed again: the nursery's next broadcast (every 30 s) is taken.
	common::node::list_fee_asset(&r.rt, fee_asset, rate);
	let store = r.server.store.clone();
	let t = round_txid.to_byte_array();
	let taken = loop {
		let n = store.nursery_get(&t).await.unwrap().unwrap();
		if n.last_result.as_deref() == Some("accepted") {
			break std::time::Instant::now();
		}
		tokio::time::sleep(std::time::Duration::from_millis(50)).await;
	};
	println!("the node took the round at the nursery's broadcast #{}", store.nursery_get(&t).await.unwrap().unwrap().broadcasts);
	loop {
		if unsigned().await == 0 {
			break;
		}
		assert!(taken.elapsed() < std::time::Duration::from_secs(15),
			"the forfeit still lacks the operator's half 15 s after the node took the round (the nursery broadcasts every 30 s)");
		tokio::time::sleep(std::time::Duration::from_millis(50)).await;
	}
	println!("the operator's half filled {} ms after the node took the round", taken.elapsed().as_millis());
	r.produce().await;
	r.bury().await;
	round_final(&r, &round_txid).await;
	let http = r.http.clone();
	r.wait("the participation to be released", || {
		http.post("participation_status", &json!({"participation_id": hex(&pa)})).ok()["state"] == "released"
	}).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_end_to_end_and_every_refusal() {
	let mut r = start().await;
	let x = r.x;

	// A and B each bring a board in and refresh it.
	let (a, b) = (keypair("A"), keypair("B"));
	let (a_board, a_tx) = credited_board(&mut r, &a, x).await;
	let (b_board, b_tx) = credited_board(&mut r, &b, x).await;
	let (a2, b2) = (keypair("A, new"), keypair("B, new"));
	let (pa, a2_nonce) = participate(&r, &a_board, &a2);
	let (pb, b2_nonce) = participate(&r, &b_board, &b2);
	let a_old = coin_of(&r, &a_board, std::slice::from_ref(&a_tx));
	let b_old = coin_of(&r, &b_board, std::slice::from_ref(&b_tx));

	// Before any round: nothing to forfeit for.
	refused(r.http.post("forfeit_leaves", &forfeit_body(&pa, &[(a_board.id, hex(&[1; 64]))], &[])), 422, "not_in_round");

	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let round_txid = built.tx.txid();
	println!("round {}: {} vB", round_txid, built.tx.vsize());
	// Before the round is final.
	refused(r.http.post("forfeit_leaves", &forfeit_body(&pa, &[(a_board.id, hex(&[1; 64]))], &[])), 422, "round_not_final");
	r.produce().await;
	r.bury().await;
	round_final(&r, &round_txid).await;

	// A validates its new leaf from the published tree and builds its forfeit.
	let st = status(&r, &pa);
	let (a2_valid, a2_record, round) = validate_new_leaf(&r, &pa, 0, &a2, &a2_nonce);
	let f = forfeit_for(&a_old, &a2_valid, &round, &st, 0);
	let t = created(&a2_record);
	let a_auths = auths_json(&a2_valid, &a2, t);
	let good = forfeit_body(&pa, &[(a_board.id, forfeit_sig(&f, &a))], std::slice::from_ref(&a_auths));

	// --- Refusals ---

	// The wrong unlock hash, the wrong connector (another output of the round,
	// and the right output of another round), another coin, another margin,
	// another refund delay: each signs another forfeit output.
	let c = built.connector_vout;
	let delay = f.policy.refund_delay;
	let wrong = |h: [u8; 32], m, id: LeafId, margin: u64, d: RelativeTime| {
		let f = Forfeit::new(a_old.leaf, (a_old.asset, a_old.value), id, h, m, d, margin).unwrap();
		forfeit_body(&pa, &[(a_board.id, forfeit_sig(&f, &a))], std::slice::from_ref(&a_auths))
	};
	let h = f.policy.unlock_hash;
	let m = connector_asset(round_txid, c);
	refused(r.http.post("forfeit_leaves", &wrong(sha256(&random32()), m, a_old.id, f.margin, delay)), 422, "bad_forfeit");
	refused(r.http.post("forfeit_leaves", &wrong(h, connector_asset(round_txid, c - 1), a_old.id, f.margin, delay)), 422, "bad_forfeit");
	refused(r.http.post("forfeit_leaves", &wrong(h, connector_asset(elements::Txid::from_byte_array([5; 32]), c), a_old.id, f.margin, delay)), 422, "bad_forfeit");
	refused(r.http.post("forfeit_leaves", &wrong(h, m, b_old.id, f.margin, delay)), 422, "bad_forfeit");
	refused(r.http.post("forfeit_leaves", &wrong(h, m, a_old.id, f.margin + 1, delay)), 422, "bad_forfeit");
	refused(r.http.post("forfeit_leaves", &wrong(h, m, a_old.id, f.margin, RelativeTime::from_units(delay.units() - 1).unwrap())), 422, "bad_forfeit");
	// The wallet itself refuses to sign for a connector output that is not
	// the operator's.
	let bad_c = Forfeit::for_refresh(a_old.leaf, (a_old.asset, a_old.value), a_old.id, &a2_valid, &round, c - 1, delay, f.margin).unwrap_err();
	println!("the wallet refuses a forfeit for output {} of the round: {}", c - 1, bad_c);
	// The right forfeit signed by another key.
	refused(r.http.post("forfeit_leaves", &forfeit_body(&pa, &[(a_board.id, forfeit_sig(&f, &b))], std::slice::from_ref(&a_auths))), 422, "bad_forfeit");
	// Not exactly the coins given up: none, another, one twice, one more.
	refused(r.http.post("forfeit_leaves", &forfeit_body(&pa, &[], std::slice::from_ref(&a_auths))), 422, "forfeit_set");
	refused(r.http.post("forfeit_leaves", &forfeit_body(&pa, &[(b_board.id, forfeit_sig(&f, &a))], std::slice::from_ref(&a_auths))), 422, "forfeit_set");
	refused(r.http.post("forfeit_leaves", &forfeit_body(&pa, &[(a_board.id, forfeit_sig(&f, &a)), (a_board.id, forfeit_sig(&f, &a))],
		std::slice::from_ref(&a_auths))), 422, "forfeit_set");
	refused(r.http.post("forfeit_leaves", &forfeit_body(&pa, &[(a_board.id, forfeit_sig(&f, &a)), (b_board.id, forfeit_sig(&f, &b))],
		std::slice::from_ref(&a_auths))), 422, "forfeit_set");
	// Not one authorisation set per new leaf; sets by another key, or not
	// usable yet.
	refused(r.http.post("forfeit_leaves", &forfeit_body(&pa, &[(a_board.id, forfeit_sig(&f, &a))], &[])), 422, "leaf_set");
	refused(r.http.post("forfeit_leaves", &forfeit_body(&pa, &[(a_board.id, forfeit_sig(&f, &a))], &[auths_json(&a2_valid, &b2, t)])), 422, "invalid_leaf");
	let later = MedianTime::from_consensus(t.to_consensus_u32() + 30 * 86_400).unwrap();
	refused(r.http.post("forfeit_leaves", &forfeit_body(&pa, &[(a_board.id, forfeit_sig(&f, &a))], &[auths_json(&a2_valid, &a2, later)])), 422, "invalid_leaf");
	// A release before the preimage (refused before its M is looked at).
	refused(r.http.post("release_leaves", &json!({"participation_id": hex(&pa),
		"releases": [{"leaf_id": a_board.id.to_string(), "connector_asset": "0000000000000000000000000000000000000000000000000000000000000000", "signature": hex(&[1; 64])}]})), 422, "release_early");
	// None of these changed anything.
	assert_eq!(status(&r, &pa)["state"], "issued");

	// --- The swap ---

	let done = r.http.post("forfeit_leaves", &good).ok();
	println!("forfeit accepted: {}", done);
	assert_eq!(done["state"], "released");
	let preimage: [u8; 32] = unhex(done["preimage"].as_str().unwrap()).try_into().unwrap();
	assert_eq!(sha256(&preimage), a2_valid.branch.entry.unlock_hash, "the preimage opens the new leaf's entry");
	// The same request again: the same preimage.
	assert_eq!(r.http.post("forfeit_leaves", &good).ok(), done);
	assert_eq!(status(&r, &pa)["state"], "released");
	// The server reads the new round leaf's dates whatever the time, as it does
	// for a participation that gives it up: under the latest of its unroll
	// authorisations' times, since a fixed early time refuses every one of
	// them as not usable yet.
	let a2_id = a2_valid.leaf_id;
	let any = server::coins::resolve_any_time(&r.server.store, |t| r.server.params.taken_policy(t), &a2_id).await.unwrap();
	assert_eq!(any.coin.id, a2_id);
	let early = MedianTime::from_consensus(500_000_000).unwrap();
	let fixed = arca_covenant::WalletPolicy { horizon: 0, ..r.server.params.taken_policy(early) };
	let refused_early = server::coins::resolve(&r.server.store, &fixed, &a2_id).await.err().map(|e| e.to_string()).unwrap_or_default();
	assert!(refused_early.contains("not usable until later than now"), "{}", refused_early);
	println!("the new round leaf's dates read whatever the time; a fixed early time refuses it: {}", refused_early);
	// The forfeit the server holds is both halves over exactly that output.
	let stored = r.server.store.forfeits(&pa, built.round_id).await.unwrap();
	assert_eq!(stored.len(), 1);
	let pair = arca_covenant::Pair {
		operator: elements::secp256k1_zkp::schnorr::Signature::from_slice(&stored[0].forfeit.operator_sig).unwrap(),
		owner: elements::secp256k1_zkp::schnorr::Signature::from_slice(&stored[0].forfeit.owner_sig).unwrap(),
	};
	f.verify(&pair).unwrap();
	// A's new leaf is live, its full record held; the board is spent.
	let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", &a2, &r.chain)})).ok();
	assert_eq!(ld["leaves"][0]["state"], "live");
	let a2_coin_record = CoinRecord::from_bytes(&unhex(ld["leaves"][0]["record"].as_str().unwrap())).unwrap();
	assert!(matches!(&a2_coin_record, CoinRecord::Leaf { preimage: p, .. } if *p == preimage));
	let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", &a, &r.chain)})).ok();
	assert_eq!(ld["leaves"][0]["state"], "spent");
	// A board has no lowest node to release.
	let rel = sign_digest(&a, &[0; 32], &random32());
	refused(r.http.post("release_leaves", &json!({"participation_id": hex(&pa),
		"releases": [{"leaf_id": a_board.id.to_string(), "connector_asset": "0000000000000000000000000000000000000000000000000000000000000000", "signature": hex(rel.as_ref())}]})), 422, "no_lowest_node");

	// B completes too, and pays its new leaf on out of round to C, which
	// validates it against the round.
	let stb = status(&r, &pb);
	let (b2_valid, b2_record, _) = validate_new_leaf(&r, &pb, 0, &b2, &b2_nonce);
	let fb = forfeit_for(&b_old, &b2_valid, &round, &stb, 0);
	r.http.post("forfeit_leaves", &forfeit_body(&pb, &[(b_board.id, forfeit_sig(&fb, &b))], &[auths_json(&b2_valid, &b2, created(&b2_record))])).ok();
	let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", &b2, &r.chain)})).ok();
	let b2_held = Held { key: b2, nonce: b2_nonce, id: b2_valid.leaf_id, record: CoinRecord::from_bytes(&unhex(ld["leaves"][0]["record"].as_str().unwrap())).unwrap() };
	let b2_coin = coin_of(&r, &b2_held, std::slice::from_ref(&round));
	let c_key = keypair("C");
	let (c_leaf, c_nonce) = new_leaf(&c_key);
	let body = transfer_body(&[(&b2_held, b2_coin, VALUE - 2_000)], &[(x, VALUE - 4_000, c_leaf)], xonly(&r.s), r.chain);
	let paid = r.http.post("cosign_transfer", &body).ok();
	let c_record = CoinRecord::from_bytes(&unhex(paid["outputs"][0]["record"].as_str().unwrap())).unwrap();
	let c_valid = c_record.validate(std::slice::from_ref(&round), &r.policy(), &xonly(&c_key), &c_nonce).unwrap();
	println!("B's new leaf paid on to C out of round: C validated {} ({} atoms, {} hop) against the round", c_valid.id, c_valid.value, c_valid.hops);

	// --- A second refresh: A's batch leaf into a new one, then its release ---

	let a3 = keypair("A, third");
	let a2_held = Held { key: a2, nonce: a2_nonce, id: a2_valid.leaf_id, record: a2_coin_record };
	let (pa3, a3_nonce) = participate(&r, &a2_held, &a3);
	let built2 = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built2.tx.txid()).await;
	let st3 = status(&r, &pa3);
	let (a3_valid, a3_record, round2) = validate_new_leaf(&r, &pa3, 0, &a3, &a3_nonce);
	let a2_old = coin_of(&r, &a2_held, std::slice::from_ref(&round));
	let f3 = forfeit_for(&a2_old, &a3_valid, &round2, &st3, 0);
	// The release of A's old batch leaf, signed with that leaf's key.
	// It names the connector asset M of round 2, which made A's new leaf.
	let c2 = st3["round"]["connector_vout"].as_u64().unwrap() as u32;
	let a_release = Release::for_refresh(&a2_valid, &a3_valid, &round2, c2).unwrap();
	let m2 = a_release.connector;
	assert_eq!(m2, connector_asset(round2.txid(), c2));
	let release = a_release.message().digest;
	let rel_body_m = |key: &Keypair, leaf: LeafId, m: elements::AssetId, digest: &[u8; 32]| json!({"participation_id": hex(&pa3),
		"releases": [{"leaf_id": leaf.to_string(), "connector_asset": m.to_string(),
			"signature": hex(sign_digest(key, digest, &random32()).as_ref())}]});
	let rel_body = |key: &Keypair, leaf: LeafId| rel_body_m(key, leaf, m2, &release);
	refused(r.http.post("release_leaves", &rel_body(&a2, a2_valid.leaf_id)), 422, "release_early");
	let done3 = r.http.post("forfeit_leaves", &forfeit_body(&pa3, &[(a2_valid.leaf_id, forfeit_sig(&f3, &a2))],
		&[auths_json(&a3_valid, &a3, created(&a3_record))])).ok();
	assert_eq!(done3["state"], "released");
	refused(r.http.post("release_leaves", &rel_body(&a3, a2_valid.leaf_id)), 422, "bad_signature");
	// A release naming another round's M (round 1's, which made A's old
	// leaf), signed for it; and one over the message that named no round.
	let c1_round = status(&r, &pa)["round"]["connector_vout"].as_u64().unwrap() as u32;
	let m1 = connector_asset(round.txid(), c1_round);
	let lowest = a2_valid.branch.nodes.last().unwrap().reclaim.as_ref().unwrap();
	refused(r.http.post("release_leaves", &rel_body_m(&a2, a2_valid.leaf_id, m1, &lowest.release_message(m1).digest)), 422, "wrong_round");
	refused(r.http.post("release_leaves", &rel_body_m(&a2, a2_valid.leaf_id, m2, &sha256(&lowest.prefix))), 422, "bad_signature");
	let rel = r.http.post("release_leaves", &rel_body(&a2, a2_valid.leaf_id)).ok();
	assert_eq!(rel["released"], json!([a2_valid.leaf_id.to_string()]));
	assert_eq!(r.http.post("release_leaves", &rel_body(&a2, a2_valid.leaf_id)).ok(), rel, "a release again changes nothing");
	// A release that does not name its M is checked over the round's own.
	let unnamed = json!({"participation_id": hex(&pa3), "releases": [{"leaf_id": a2_valid.leaf_id.to_string(),
		"signature": hex(sign_digest(&a2, &release, &random32()).as_ref())}]});
	assert_eq!(r.http.post("release_leaves", &unnamed).ok(), rel, "taken over the round's own M");
	let unnamed_old = json!({"participation_id": hex(&pa3), "releases": [{"leaf_id": a2_valid.leaf_id.to_string(),
		"signature": hex(sign_digest(&a2, &sha256(&a2_valid.branch.nodes.last().unwrap().reclaim.as_ref().unwrap().prefix), &random32()).as_ref())}]});
	refused(r.http.post("release_leaves", &unnamed_old), 422, "bad_signature");
	let node_hash = a2_valid.branch.nodes.last().unwrap().children_hash();
	assert_eq!(r.server.store.releases(&node_hash).await.unwrap().len(), 1);
	println!("A released the lowest node of its old leaf {}", a2_valid.leaf_id);
	// A coin not in this participation, and B's new leaf, which has an open
	// reassignment to C: refused whatever participation is named.
	refused(r.http.post("release_leaves", &rel_body(&a2, b_board.id)), 422, "not_participating");
	let c1 = stb["round"]["connector_vout"].as_u64().unwrap() as u32;
	let mb = connector_asset(round.txid(), c1);
	let b_rel = b2_valid.branch.nodes.last().unwrap().reclaim.as_ref().unwrap().release_message(mb).digest;
	refused(r.http.post("release_leaves", &json!({"participation_id": hex(&pb),
		"releases": [{"leaf_id": b2_valid.leaf_id.to_string(), "connector_asset": mb.to_string(),
			"signature": hex(sign_digest(&b2, &b_rel, &random32()).as_ref())}]})), 422, "open_reassignment");
}
