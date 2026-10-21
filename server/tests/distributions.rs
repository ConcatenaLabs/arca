//! Claim trees against a whole server on an anchored proof-of-stake regtest
//! chain: a payer's distribution of five claims in one round, each leaf owned
//! by the claim key of a key the payer named; holders that find their claims
//! by a lookup proven with their named keys; one holder that takes its claim
//! up (its unroll authorisations, then a transfer to a fresh leaf of its own)
//! and refreshes the coin in its free window; one that hands over its
//! authorisations and stops there; three that do nothing. After the claim
//! batch's expiry, the release, the notice and the sweep, the watcher pays the
//! four claims nobody took up back to the payer's return script, exactly, in
//! one transaction; the holder that took its claim up still holds its coin.
//! Every refusal the server makes of a distribution, a claims lookup and a
//! claim leaf's authorisations is printed verbatim.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, Script, Transaction};
use serde_json::{json, Value};

use arca_covenant::claim::{claim_key, claim_keypair};
use arca_covenant::sign::sign_digest;
use arca_covenant::{Claim, CoinRecord, Distribution, LeafId, LeafRecord, MedianTime, RelativeTime, ValidLeaf};

use common::client::{exit_delay, forfeit_sig, hex, new_leaf, random32, rebuild, transfer_body, unhex, Held};
use common::flow::{drive, forfeit_for, held_by, refresh, settle, Coin};
use common::keys::{keypair, xonly};
use common::rounds::{accept_policy, advance_mtp, credited_board, mtp, round_final, status, VALUE};
use common::running::Running;

const HOUR: u32 = 3_600;
const DAY: u32 = 86_400;

/// A distribution's request body and its id: `coins` given up, each attested
/// by its owner over the id, for `claims` of `asset`, returning to `ret`.
fn distribute_body(r: &Running, coins: &[&Held], asset: AssetId, claims: &[Claim], ret: &Script, fees: &[(AssetId, u64)],
	delay: RelativeTime) -> (Value, [u8; 32])
{
	let d = Distribution {
		inputs: coins.iter().map(|h| h.id).collect(), asset, exit_delay: delay, claims: claims.to_vec(), return_script: ret.clone(),
		fees: fees.to_vec(), not_before: None,
	};
	let id = d.id(&r.chain, &xonly(&r.s));
	(json!({
		"inputs": coins.iter().map(|h| json!({"leaf_id": h.id.to_string(), "attestation": hex(sign_digest(&h.key, &id, &random32()).as_ref())}))
			.collect::<Vec<_>>(),
		"asset": asset.to_string(),
		"exit_delay_units": delay.units(),
		"claims": claims.iter().map(|c| json!({"key": hex(&c.named.serialize()), "nonce": hex(&c.nonce), "value": c.value.to_string()}))
			.collect::<Vec<_>>(),
		"return_script": hex(ret.as_bytes()),
		"fees": fees.iter().map(|(a, v)| json!({"asset": a.to_string(), "amount": v.to_string()})).collect::<Vec<_>>(),
	}), id)
}

/// A claims lookup proven by each of `keys`, under one challenge.
fn lookup(r: &Running, keys: &[&Keypair]) -> common::client::Answer {
	let v = r.http.post("challenge", &json!({})).ok();
	let challenge: [u8; 32] = unhex(v["challenge"].as_str().unwrap()).try_into().unwrap();
	let proofs: Vec<Value> = keys.iter().map(|k| {
		let d = server::auth::auth_digest(&r.chain, "claims", &challenge, &xonly(k), &[]);
		json!({"key": hex(&xonly(k).serialize()), "signature": hex(sign_digest(k, &d, &random32()).as_ref())})
	}).collect();
	r.http.post("claims", &json!({"challenge": hex(&challenge), "keys": proofs}))
}

/// A claim leaf as its holder checks it: the leaf the lookup `found` names,
/// rebuilt from the published tree and validated against the round under the
/// claim key of `named` and the claim's nonce.
fn checked(r: &Running, found: &Value, named: &Keypair) -> (ValidLeaf, LeafRecord, Transaction) {
	let nonce: [u8; 32] = unhex(found["nonce"].as_str().unwrap()).try_into().unwrap();
	let tree = rebuild(&r.http.post("tree", &json!({"txid": found["round"], "vout": found["batch_vout"]})).ok());
	let record = tree.record(found["leaf_index"].as_u64().unwrap() as usize);
	assert_eq!(hex(&record.to_bytes().unwrap()), found["record"].as_str().unwrap(), "the lookup serves the published record");
	let round = r.rt.client().raw_transaction(&common::client::txid(found["round"].as_str().unwrap())).unwrap();
	let owner = claim_key(&xonly(named), &nonce).unwrap();
	let valid = record.validate(&round, &accept_policy(r), &owner, &nonce).unwrap();
	(valid, record, round)
}

/// The holder's unroll authorisations for `valid`, signed by `key` at `t`.
fn auths(valid: &ValidLeaf, key: &Keypair, t: MedianTime) -> Vec<(elements::secp256k1_zkp::schnorr::Signature, MedianTime)> {
	valid.branch.nodes.iter().map(|n| (sign_digest(key, &n.unroll_authorisation(t).digest, &random32()), t)).collect()
}

fn auths_body(leaf: &LeafId, a: &[(elements::secp256k1_zkp::schnorr::Signature, MedianTime)]) -> Value {
	json!({"leaf_id": leaf.to_string(), "auths": a.iter().map(|(s, t)| json!({"signature": hex(s.as_ref()), "time": t.to_consensus_u32()}))
		.collect::<Vec<_>>()})
}

fn refused(a: common::client::Answer, code: &str, what: &str) -> String {
	let (c, m) = a.refusal();
	println!("refused, {}: {} {}: {}", what, a.status, c, m);
	assert_eq!(c, code, "{}: {}", what, a.json);
	m
}

#[tokio::test(flavor = "multi_thread")]
async fn a_distribution_pays_its_holders_and_what_nobody_takes_up_goes_back_to_its_payer() {
	let mut r = common::rounds::start().await;
	let x = r.x;
	let payer = keypair("D payer");
	let (b1, tx1) = credited_board(&mut r, &payer, x).await;
	let payer2 = keypair("D payer, second coin");
	let (b2, tx2) = credited_board(&mut r, &payer2, x).await;
	let holders: Vec<Keypair> = (0..5).map(|i| keypair(&format!("D holder {}", i))).collect();
	let claims: Vec<Claim> = holders.iter().map(|h| Claim { named: xonly(h), nonce: random32(), value: 2 * VALUE / 5 }).collect();
	let ret = Script::from([vec![0x00, 0x14], vec![7u8; 20]].concat());
	let (body, id) = distribute_body(&r, &[&b1, &b2], x, &claims, &ret, &[], exit_delay());
	let st = r.http.post("distribute", &body).ok();
	assert_eq!(st["state"], "pending", "{}", st);
	assert_eq!(st["outputs"].as_array().unwrap().len(), 5);
	let ds = r.http.post("distribution_status", &json!({"distribution_id": hex(&id)})).ok();
	println!("before the round: {}", ds);
	assert!(ds["claims"].as_array().unwrap().iter().all(|c| c["state"] == "pending"));
	// A holder finds nothing it can take before the distribution is released:
	// the claim, its state pending, and no record nor preimage.
	let early = lookup(&r, &[&holders[0]]).ok();
	assert_eq!(early["claims"][0]["state"], "pending");
	assert!(early["claims"][0].get("preimage").is_none() && early["claims"][0].get("record").is_none());

	// The round, final; the payer validates a claim leaf and forfeits its coins
	// against it, handing over no authorisation for any claim leaf.
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let st = status(&r, &id);
	let txid = st["round"]["txid"].as_str().unwrap().to_string();
	let vout = st["outputs"][0]["batch_vout"].as_u64().unwrap();
	let tree = rebuild(&r.http.post("tree", &json!({"txid": txid, "vout": vout})).ok());
	let round = r.rt.client().raw_transaction(&common::client::txid(&txid)).unwrap();
	let idx0 = st["outputs"][0]["leaf_index"].as_u64().unwrap() as usize;
	let new0 = tree.record(idx0).validate(&round, &accept_policy(&r), &claims[0].owner().unwrap(), &claims[0].nonce).unwrap();
	let mut forfeits = vec![];
	for (k, (coin, tx)) in [(&b1, &tx1), (&b2, &tx2)].iter().enumerate() {
		let old = coin.record.resolve(std::slice::from_ref(*tx), &r.policy()).unwrap();
		let mut sk = st.clone();
		sk["inputs"][0] = st["inputs"][k].clone();
		let f = forfeit_for(&old, &new0, &round, &sk);
		forfeits.push(json!({"leaf_id": coin.id.to_string(), "signature": forfeit_sig(&f, &coin.key)}));
	}
	// With authorisations for a claim leaf: refused, the payer holds no claim key.
	let with = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&id), "forfeits": forfeits,
		"leaves": [common::client::auths_json(&new0, &payer, MedianTime::from_consensus(mtp(&r).to_consensus_u32() - HOUR).unwrap())]}));
	refused(with, "leaf_set", "the payer's forfeit step with authorisations for a claim leaf");
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&id), "forfeits": forfeits, "leaves": []})).ok();
	assert_eq!(done["state"], "released", "{}", done);
	let ds = r.http.post("distribution_status", &json!({"distribution_id": hex(&id)})).ok();
	println!("released: {}", ds);
	assert!(ds["claims"].as_array().unwrap().iter().all(|c| c["state"] == "open"));
	let expiry = ds["expiry"].as_u64().unwrap() as u32;
	assert_eq!(ds["deadline"].as_u64().unwrap() as u32, expiry - 3 * DAY);

	// The lookup: each holder proves its named key and finds its claim with its
	// record and the preimage. A key with no claim finds nothing; a proof by
	// another key is refused.
	let found = lookup(&r, &[&holders[0], &holders[1]]).ok();
	assert_eq!(found["claims"].as_array().unwrap().len(), 2, "{}", found);
	let none = lookup(&r, &[&keypair("D nobody")]).ok();
	assert!(none["claims"].as_array().unwrap().is_empty());
	let v = r.http.post("challenge", &json!({})).ok();
	let challenge: [u8; 32] = unhex(v["challenge"].as_str().unwrap()).try_into().unwrap();
	let d = server::auth::auth_digest(&r.chain, "claims", &challenge, &xonly(&holders[2]), &[]);
	let forged = r.http.post("claims", &json!({"challenge": hex(&challenge), "keys": [
		{"key": hex(&xonly(&holders[2]).serialize()), "signature": hex(sign_digest(&holders[3], &d, &random32()).as_ref())}]}));
	refused(forged, "unauthenticated", "a claims lookup for holder 2's key signed by holder 3");
	let pick = |k: &Keypair| found["claims"].as_array().unwrap().iter().find(|c| c["key"] == json!(hex(&xonly(k).serialize()))).unwrap().clone();
	let f0 = pick(&holders[0]);
	let f1 = pick(&holders[1]);
	assert_eq!(f0["state"], "open");
	let pre: [u8; 32] = unhex(f0["preimage"].as_str().unwrap()).try_into().unwrap();
	assert_eq!(arca_covenant::script::sha256(&pre), tree.record(idx0).unlock_hash, "the preimage opens the claim leaves");

	// Holder 0 takes its claim up: its authorisations (by the named key: refused;
	// by the claim key: kept), then a transfer to a fresh leaf of its own.
	let (v0, rec0, round0) = checked(&r, &f0, &holders[0]);
	let n0: [u8; 32] = unhex(f0["nonce"].as_str().unwrap()).try_into().unwrap();
	let claim0 = claim_keypair(&holders[0], &n0).unwrap();
	let t = MedianTime::from_consensus(mtp(&r).to_consensus_u32() - HOUR).unwrap();
	let by_named = r.http.post("claim_leaf", &auths_body(&v0.leaf_id, &auths(&v0, &holders[0], t)));
	refused(by_named, "invalid_coin", "a claim leaf's authorisations signed by the named key");
	refused(r.http.post("claim_leaf", &auths_body(&LeafId([9; 32]), &auths(&v0, &claim0, t))), "unknown_leaf",
		"authorisations for a leaf that is no claim");
	let a0 = auths(&v0, &claim0, t);
	let ok = r.http.post("claim_leaf", &auths_body(&v0.leaf_id, &a0)).ok();
	assert_eq!(ok["state"], "open");
	let held0 = Held { key: claim0, nonce: n0, id: v0.leaf_id, record: CoinRecord::Leaf { record: rec0, preimage: pre, auths: a0 } };
	let c0 = held0.record.resolve(std::slice::from_ref(&round0), &r.policy()).unwrap();
	let mine = keypair("D holder 0, its own leaf");
	let (to, to_nonce) = new_leaf(&mine);
	let kept = c0.value - 2_000;
	let done = r.http.post("cosign_transfer", &transfer_body(&[(&held0, c0.clone(), kept)], &[(x, kept - 2_000, to)], xonly(&r.s), r.chain)).ok();
	let new_id: LeafId = done["outputs"][0]["leaf_id"].as_str().unwrap().parse().unwrap();
	let ds = r.http.post("distribution_status", &json!({"distribution_id": hex(&id)})).ok();
	assert_eq!(ds["claims"][f0["index"].as_u64().unwrap() as usize]["state"], "claimed");
	// A second spend of the claim leaf: refused, it is taken up.
	let (again, _) = new_leaf(&keypair("D holder 0, again"));
	refused(r.http.post("cosign_transfer", &transfer_body(&[(&held0, c0, kept)], &[(x, kept - 3_000, again)], xonly(&r.s), r.chain)),
		"double_spend", "a second spend of a claim leaf taken up");

	// Holder 1 hands over its authorisations and goes no further.
	let (v1, _, _) = checked(&r, &f1, &holders[1]);
	let n1: [u8; 32] = unhex(f1["nonce"].as_str().unwrap()).try_into().unwrap();
	let claim1 = claim_keypair(&holders[1], &n1).unwrap();
	assert_eq!(r.http.post("claim_leaf", &auths_body(&v1.leaf_id, &auths(&v1, &claim1, t))).ok()["state"], "open");

	// In holder 0's coin's free window, it is refreshed into a later batch.
	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, expiry - 4 * DAY - now).await;
	r.synced().await;
	let coin0 = Coin { held: held_by(&r, &mine, to_nonce, new_id), bases: vec![round0.clone()] };
	let refreshed = refresh(&mut r, &[(&coin0, &keypair("D holder 0, refreshed"))]).await;
	let later = refreshed[0].new.held.id;

	// The claim batch's expiry, its release, the notice, its sweep, final; then
	// the watcher pays back the four claims nobody took up.
	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, expiry.saturating_sub(now) + HOUR).await;
	let token = new0.branch.nodes[0].sweep.token.into_inner().to_byte_array().to_vec();
	drive(&r, "the release at the claim batch's expiry", 4, |l| common::flow::has(l, "release", &token)).await;
	settle(&r).await;
	advance_mtp(&r, 37 * HOUR).await;
	drive(&r, "the sweep after the notice", 4, |l| common::flow::has(l, "sweep", &token)).await;
	settle(&r).await;
	let mut paid = None;
	for _ in 0..8 {
		r.server.watcher.pass().await.unwrap();
		settle(&r).await;
		let ds = r.http.post("distribution_status", &json!({"distribution_id": hex(&id)})).ok();
		if ds["returns"].as_array().is_some_and(|a| a.first().is_some_and(|x| x["state"] == "final")) {
			paid = Some(ds);
			break;
		}
	}
	let ds = paid.expect("the return is paid and final");
	println!("after the sweep: {}", ds);
	assert_eq!(ds["returned"], json!((4 * (2 * VALUE / 5)).to_string()), "the four claims nobody took up, exactly");
	let ret_txid = ds["returns"][0]["txid"].as_str().unwrap();
	let ret_tx = r.rt.client().raw_transaction(&common::client::txid(ret_txid)).unwrap();
	let to_payer: u64 = ret_tx.output.iter().filter(|o| o.script_pubkey == ret && o.asset.explicit() == Some(x))
		.map(|o| o.value.explicit().unwrap()).sum();
	assert_eq!(to_payer, 4 * (2 * VALUE / 5), "the return script is paid the unclaimed sum in the distribution's asset");
	println!("the return {}: {} vB, {} of X to the payer's script", ret_txid, ret_tx.vsize(), to_payer);
	for (k, c) in ds["claims"].as_array().unwrap().iter().enumerate() {
		let want = if c["key"] == json!(hex(&xonly(&holders[0]).serialize())) { "claimed" } else { "returned" };
		assert_eq!(c["state"], want, "claim {}", k);
	}
	// The holder that took its claim up still holds its coin, live, in the
	// later batch.
	let row = r.server.store.leaf(&later.0).await.unwrap().unwrap();
	assert_eq!(row.state, server::store::LeafState::Live, "holder 0's refreshed coin");
	// Nothing more is paid at a later pass.
	r.server.watcher.pass().await.unwrap();
	settle(&r).await;
	let ds2 = r.http.post("distribution_status", &json!({"distribution_id": hex(&id)})).ok();
	assert_eq!(ds2["returns"].as_array().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_distribution_is_refused_for_what_it_breaks() {
	let mut r = common::rounds::start().await;
	let (x, y) = (r.x, r.y);
	let payer = keypair("DR payer");
	let (b1, _) = credited_board(&mut r, &payer, x).await;
	let h: Vec<Keypair> = (0..3).map(|i| keypair(&format!("DR holder {}", i))).collect();
	let ret = Script::from([vec![0x00, 0x14], vec![5u8; 20]].concat());
	let claim = |k: &Keypair, v: u64| Claim { named: xonly(k), nonce: random32(), value: v };
	let good = vec![claim(&h[0], VALUE / 2), claim(&h[1], VALUE / 2)];
	let try_ = |r: &Running, claims: &[Claim], ret: &Script, fees: &[(AssetId, u64)], delay: RelativeTime, code: &str, what: &str| {
		let (body, _) = distribute_body(r, &[&b1], x, claims, ret, fees, delay);
		refused(r.http.post("distribute", &body), code, what)
	};
	try_(&r, &[claim(&h[0], VALUE / 2), Claim { nonce: random32(), ..claim(&h[0], VALUE / 2) }], &ret, &[], exit_delay(), "malformed",
		"one key named twice");
	try_(&r, &[claim(&h[0], VALUE / 2), claim(&h[1], VALUE / 2 - 1)], &ret, &[], exit_delay(), "unbalanced",
		"claims one atom short of the coins");
	try_(&r, &[claim(&h[0], VALUE - 10), claim(&h[1], 10)], &ret, &[], exit_delay(), "out_of_bounds", "a claim below the smallest leaf");
	try_(&r, &good, &ret, &[], RelativeTime::from_units(400).unwrap(), "out_of_bounds", "an exit delay above the operator's");
	try_(&r, &[claim(&h[0], VALUE / 2), claim(&h[1], VALUE / 2 - 100)], &ret, &[(y, 100)], exit_delay(), "out_of_bounds",
		"a fee in another asset");
	let board_spk = match &b1.record {
		CoinRecord::Board(b) => b.policy().script_pubkey(),
		_ => unreachable!(),
	};
	try_(&r, &good, &board_spk, &[], exit_delay(), "script_reused", "a return script that is an Arca script");
	try_(&r, &good, &Script::new(), &[], exit_delay(), "malformed", "no return script");
	// An attestation by another key.
	let (mut body, _) = distribute_body(&r, &[&b1], x, &good, &ret, &[], exit_delay());
	body["inputs"][0]["attestation"] = json!(hex(sign_digest(&h[2], &[1; 32], &random32()).as_ref()));
	refused(r.http.post("distribute", &body), "bad_attestation", "an attestation by another key");
	// An asset the operator does not serve.
	let other = AssetId::from_slice(&[0x42; 32]).unwrap();
	let (mut body, _) = distribute_body(&r, &[&b1], x, &good, &ret, &[], exit_delay());
	body["asset"] = json!(other.to_string());
	refused(r.http.post("distribute", &body), "out_of_bounds", "an asset the operator does not serve");
	// A claim whose claim key is taken: the same key and nonce in a second
	// distribution, once the first holds it.
	let (body, _) = distribute_body(&r, &[&b1], x, &good, &ret, &[], exit_delay());
	assert_eq!(r.http.post("distribute", &body).ok()["state"], "pending");
	let (b2, _) = credited_board(&mut r, &keypair("DR payer 2"), x).await;
	let (body, _) = distribute_body(&r, &[&b2], x, &good, &ret, &[], exit_delay());
	refused(r.http.post("distribute", &body), "key_reused", "a claim key a pending distribution wants already");
	// Authorisations for a claim leaf whose distribution is not released.
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let found = lookup(&r, &[&h[0]]).ok();
	assert_eq!(found["claims"][0]["state"], "pending", "the forfeits are not in: {}", found);
	let ds = r.http.post("distribution_status", &json!({"distribution_id": found["claims"][0]["distribution_id"]})).ok();
	let leaf: LeafId = ds["claims"][0]["leaf_id"].as_str().unwrap().parse().unwrap();
	refused(r.http.post("claim_leaf", &json!({"leaf_id": leaf.to_string(), "auths": []})), "not_live",
		"authorisations for a claim leaf before its distribution is released");
	refused(lookup(&r, &[]), "malformed", "a lookup naming no key");
}
