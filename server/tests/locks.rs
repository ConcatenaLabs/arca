//! `htlc-2` locks between two holders ([`server::locks`]): a payer locks a
//! coin to a payee out of round; the operator co-signs the payee's claim
//! with the preimage before the timeout less its margin, or the payer's
//! refund from the timeout, never both; and refuses a lock whose timeout,
//! keys or depth leave an ending out of reach, and any other use of a lock.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::secp256k1_zkp::Keypair;
use serde_json::{json, Value};

use arca_covenant::script::sha256;
use arca_covenant::{CoinRecord, LockSpend, LockTerms, MedianTime, NewLeaf};
use common::client::{exit_delay, hex, new_leaf, participation_body, random32, transfer_body, transfer_body_locks, want_leaf, Held};
use common::flow::Coin;
use common::keys::{keypair, xonly};
use common::rounds::{accept_policy, advance_mtp, credited_board, mtp, start};
use common::running::Running;

/// The payer's delay: the payee's and the margin.
fn refund_delay() -> arca_covenant::RelativeTime {
	arca_covenant::RelativeTime::from_units(exit_delay().units() + arca_covenant::REFUND_DELAY_MARGIN_UNITS).unwrap()
}

/// What each step leaves for its fee.
const MARGIN: u64 = 2_000;

/// A lock of `value` from `payer`'s coin to `payee`, under `preimage`'s hash
/// until `timeout`, refunded to `refunder`; the payer's change to a new key.
fn lock_body(r: &Running, coin: &Coin, payee: &Keypair, refunder: &Keypair, preimage: &[u8; 32], timeout: u32, value: u64)
	-> (Value, NewLeaf, NewLeaf, Keypair)
{
	let v = coin.valid(r);
	let (q_leaf, _) = new_leaf(payee);
	let terms = LockTerms {
		payment_hash: sha256(preimage), timeout: MedianTime::from_consensus(timeout).unwrap(), refunder: xonly(refunder),
		refund_delay: refund_delay(),
	};
	let lock = NewLeaf { lock: Some(terms), ..q_leaf };
	let change_key = keypair(&format!("L change {}", hex(&random32()[..4])));
	let (change, _) = new_leaf(&change_key);
	let kept = v.value - MARGIN;
	let body = transfer_body(&[(&coin.held, v, kept)], &[(r.x, value, lock), (r.x, kept - value - MARGIN, change)],
		xonly(&r.s), r.chain);
	(body, lock, change, change_key)
}

/// The coin whose leaf is `leaf` in `key`'s mailbox, held by `key`.
fn received(r: &Running, key: &Keypair, leaf: &NewLeaf) -> Held {
	let script = leaf.policy(xonly(&r.s), r.chain).script_pubkey();
	let (_, id, record) = r.http.mailbox(key, &r.chain, 0).into_iter()
		.find(|(_, _, rec)| match rec {
			CoinRecord::Transfer(t) => t.outputs[t.index as usize].script_pubkey == script,
			_ => false,
		})
		.unwrap_or_else(|| panic!("no coin of leaf {} in the mailbox", hex(&leaf.owner.serialize())));
	Held { key: *key, nonce: leaf.owner_nonce, id, record }
}

fn refused(r: &Running, call: &str, body: &Value, code: &str, what: &str) -> String {
	let a = r.http.post(call, body);
	let (c, m) = a.refusal();
	println!("L {}: {} {}: {}", what, a.status, c, m);
	assert!(a.status >= 400, "{}: {}", what, a.json);
	assert_eq!(c, code, "{}: {}", what, m);
	m
}

fn status(r: &Running, preimage: &[u8; 32]) -> Value {
	r.http.post("lock_status", &json!({"payment_hash": hex(&sha256(preimage))})).ok()
}

/// The claim with the preimage, before the timeout; every other ending and
/// every misuse refused; the lock posted to both holders.
#[tokio::test(flavor = "multi_thread")]
async fn a_lock_is_claimed_out_of_round_and_never_refunded() {
	let mut r = start().await;
	let x = r.x;
	let info = r.http.get("info").ok();
	assert!(info["templates"]["list"].as_array().unwrap().contains(&json!("htlc-2")), "{}", info["templates"]);
	println!("L info.locks: {}", info["locks"]);
	let p = keypair("L P");
	let (held, tx) = credited_board(&mut r, &p, x).await;
	let ca = Coin { held, bases: vec![tx] };
	let q = keypair("L Q");
	let pp = keypair("L P refund");
	let preimage = random32();
	let now = mtp(&r).to_consensus_u32();
	let soonest = now + exit_delay().seconds() as u32 + 3_600;
	let t = soonest + 2 * 86_400;

	// Locks the operator refuses.
	let (b, ..) = lock_body(&r, &ca, &q, &pp, &preimage, soonest - 600, 600_000);
	refused(&r, "cosign_transfer", &b, "lock", "a timeout before the payee can claim on the chain");
	let (b, ..) = lock_body(&r, &ca, &q, &pp, &preimage, now + 15 * 86_400, 600_000);
	refused(&r, "cosign_transfer", &b, "lock", "a timeout more than fourteen days out");
	let (b, ..) = lock_body(&r, &ca, &q, &q, &preimage, t, 600_000);
	refused(&r, "cosign_transfer", &b, "lock", "a payer's key that is the payee's");
	let (b, ..) = lock_body(&r, &ca, &q, &r.s.clone(), &preimage, t, 600_000);
	refused(&r, "cosign_transfer", &b, "lock", "a payer's key that is the operator's");
	let short = {
		let v = ca.valid(&r);
		let (q_leaf, _) = new_leaf(&q);
		let lock = NewLeaf { lock: Some(LockTerms { payment_hash: sha256(&preimage), timeout: MedianTime::from_consensus(t).unwrap(),
			refunder: xonly(&pp), refund_delay: exit_delay() }), ..q_leaf };
		let (change, _) = new_leaf(&keypair("L change short"));
		transfer_body(&[(&ca.held, v.clone(), v.value - MARGIN)], &[(x, 600_000, lock), (x, v.value - 600_000 - 2 * MARGIN, change)],
			xonly(&r.s), r.chain)
	};
	refused(&r, "cosign_transfer", &short, "lock", "a payer's delay no longer than the payee's");

	// The lock.
	let (b, lock_leaf, change_leaf, change_key) = lock_body(&r, &ca, &q, &pp, &preimage, t, 600_000);
	let made = r.http.post("cosign_transfer", &b).ok();
	println!("L the lock: transfer {}", made["transfer_id"]);
	let lock = received(&r, &q, &lock_leaf);
	let policy = accept_policy(&r);
	let valid = lock.record.validate(&ca.bases, &policy, &xonly(&q), &lock_leaf.owner_nonce).unwrap();
	assert_eq!((valid.leaf.lock, valid.value, valid.hops), (lock_leaf.lock, 600_000, 1));
	let at_payer = received(&r, &pp, &lock_leaf);
	assert_eq!(at_payer.id, lock.id, "the payer's mailbox, under its key for the lock, holds the lock too");
	let st = status(&r, &preimage);
	println!("L lock_status: {}", st);
	assert_eq!(st["locks"][0]["state"], "open");
	assert!(st["preimage"].is_null());
	let lock_coin = Coin { held: lock.clone(), bases: ca.bases.clone() };
	let lv = lock_coin.valid(&r);

	// The payer's key for the lock is its alone: a second lock under it is refused.
	let change = Coin { held: received(&r, &change_key, &change_leaf), bases: ca.bases.clone() };
	let (b, ..) = lock_body(&r, &change, &keypair("L Q other"), &pp, &random32(), t, 100_000);
	refused(&r, "cosign_transfer", &b, "key_reused", "a second lock refunded to the same key");

	// The lock goes into no round.
	let (want, _) = want_leaf(&keypair("L Q refresh"), x, 590_000);
	let (pb, _) = participation_body(&[&lock], &[want], &[(x, 10_000)], None, xonly(&r.s), r.chain);
	let a = r.http.post("submit_participation", &pb);
	println!("L the lock given to a round: {} {:?}", a.status, a.refusal());
	assert!(a.status >= 400 && a.refusal().1.contains("htlc-2"), "{}", a.json);

	// Endings refused.
	let (q2_leaf, _) = new_leaf(&keypair("L Q claimed"));
	let out = [(x, lv.value - 2 * MARGIN, q2_leaf)];
	let kept = lv.value - MARGIN;
	let plain = transfer_body(&[(&lock, lv.clone(), kept)], &out, xonly(&r.s), r.chain);
	refused(&r, "cosign_transfer", &plain, "lock", "a lock given up with no ending named");
	let wrong = transfer_body_locks(&[(&lock, lv.clone(), kept)], &[Some((LockSpend::Claim { preimage: random32() }, q))], &out,
		xonly(&r.s), r.chain, false);
	refused(&r, "cosign_transfer", &wrong, "lock", "a claim whose preimage does not open the hash");
	let early = transfer_body_locks(&[(&lock, lv.clone(), kept)], &[Some((LockSpend::Refund, pp))], &out, xonly(&r.s), r.chain, false);
	refused(&r, "cosign_transfer", &early, "lock", "a refund before the timeout");
	let by_payer = transfer_body_locks(&[(&lock, lv.clone(), kept)], &[Some((LockSpend::Claim { preimage }, pp))], &out,
		xonly(&r.s), r.chain, false);
	refused(&r, "cosign_transfer", &by_payer, "bad_signature", "a claim signed by the payer");

	// The claim.
	let claim = transfer_body_locks(&[(&lock, lv.clone(), kept)], &[Some((LockSpend::Claim { preimage }, q))], &out,
		xonly(&r.s), r.chain, false);
	let c = r.http.post("cosign_transfer", &claim).ok();
	println!("L the claim: transfer {}", c["transfer_id"]);
	let again = r.http.post("cosign_transfer", &claim).ok();
	assert_eq!(again["transfer_id"], c["transfer_id"], "the same claim again gets its answer");
	let q2 = received(&r, &keypair("L Q claimed"), &q2_leaf);
	let v2 = q2.record.validate(&ca.bases, &accept_policy(&r), &q2_leaf.owner, &q2_leaf.owner_nonce).unwrap();
	assert_eq!((v2.hops, v2.value, v2.leaf.lock), (2, 600_000 - 2 * MARGIN, None));
	let st = status(&r, &preimage);
	println!("L lock_status after the claim: {}", st);
	assert_eq!(st["locks"][0]["state"], "claimed");
	assert_eq!(st["preimage"], json!(hex(&preimage)), "the claim's preimage is served to the payer");
	let salt = lv.leaf.salt;
	assert_eq!(r.signer_entries().await.iter().filter(|e| e.salt == salt).count(), 1, "one spend of the lock");

	// From the timeout, no refund of a claimed lock.
	advance_mtp(&r, t - mtp(&r).to_consensus_u32() + 60).await;
	r.synced().await;
	let (p2_leaf, _) = new_leaf(&keypair("L P refunded"));
	let late = transfer_body_locks(&[(&lock, lv.clone(), kept)], &[Some((LockSpend::Refund, pp))], &[(x, lv.value - 2 * MARGIN, p2_leaf)],
		xonly(&r.s), r.chain, false);
	let a = r.http.post("cosign_transfer", &late);
	println!("L a refund of the claimed lock: {} {:?}", a.status, a.refusal());
	assert!(a.status >= 400, "{}", a.json);
	assert_eq!(r.signer_entries().await.iter().filter(|e| e.salt == salt).count(), 1, "still one spend of the lock");
}

/// The refund from the timeout; the claim then refused; and the depth rule:
/// a lock is made only where its claim and its refund can each follow.
#[tokio::test(flavor = "multi_thread")]
async fn a_lock_is_refunded_from_its_timeout_and_leaves_room_for_its_ending() {
	let mut r = start().await;
	let x = r.x;
	let p = keypair("R P");
	let (held, tx) = credited_board(&mut r, &p, x).await;
	let ca = Coin { held, bases: vec![tx] };
	let q = keypair("R Q");
	let pp = keypair("R P refund");
	let preimage = random32();
	let now = mtp(&r).to_consensus_u32();
	let t = now + exit_delay().seconds() as u32 + 3_600 + 600;
	let (b, lock_leaf, ..) = lock_body(&r, &ca, &q, &pp, &preimage, t, 700_000);
	r.http.post("cosign_transfer", &b).ok();
	let lock = received(&r, &pp, &lock_leaf);
	let lv = Coin { held: lock.clone(), bases: ca.bases.clone() }.valid(&r);
	let kept = lv.value - MARGIN;

	// Past the timeout less the margin, the claim is refused; from the
	// timeout, the refund is co-signed.
	advance_mtp(&r, t - mtp(&r).to_consensus_u32() + 60).await;
	r.synced().await;
	let p2_key = keypair("R P refunded");
	let (p2_leaf, _) = new_leaf(&p2_key);
	let out = [(x, lv.value - 2 * MARGIN, p2_leaf)];
	let late = transfer_body_locks(&[(&lock, lv.clone(), kept)], &[Some((LockSpend::Claim { preimage }, q))], &out,
		xonly(&r.s), r.chain, false);
	refused(&r, "cosign_transfer", &late, "lock", "a claim past the timeout less its margin");
	let refund = transfer_body_locks(&[(&lock, lv.clone(), kept)], &[Some((LockSpend::Refund, pp))], &out, xonly(&r.s), r.chain, false);
	let a = r.http.post("cosign_transfer", &refund).ok();
	println!("L the refund: transfer {}", a["transfer_id"]);
	let p2 = received(&r, &p2_key, &p2_leaf);
	let v2 = p2.record.validate(&ca.bases, &accept_policy(&r), &p2_leaf.owner, &p2_leaf.owner_nonce).unwrap();
	assert_eq!((v2.hops, v2.value), (2, 700_000 - 2 * MARGIN));
	let st = status(&r, &preimage);
	println!("L lock_status after the refund: {}", st);
	assert_eq!(st["locks"][0]["state"], "refunded");
	let (other, _) = new_leaf(&keypair("R Q after"));
	let claim_after = transfer_body_locks(&[(&lock, lv.clone(), kept)], &[Some((LockSpend::Claim { preimage }, q))],
		&[(x, lv.value - 2 * MARGIN, other)], xonly(&r.s), r.chain, false);
	refused(&r, "cosign_transfer", &claim_after, "double_spend", "a claim of the refunded lock");
	assert_eq!(r.signer_entries().await.iter().filter(|e| e.salt == lv.leaf.salt).count(), 1, "one spend of the lock");

	// The depth rule. The refunded coin is 2 reassignments from its board;
	// one transfer more makes a coin of 3, from which a lock (4) leaves room
	// for its ending (5); a lock from that lock's change (4) would not.
	let c3_key = keypair("R C3");
	let (c3_leaf, _) = new_leaf(&c3_key);
	let p2c = Coin { held: p2.clone(), bases: ca.bases.clone() };
	let pv = p2c.valid(&r);
	r.http.post("cosign_transfer", &transfer_body(&[(&p2, pv.clone(), pv.value - MARGIN)], &[(x, pv.value - 2 * MARGIN, c3_leaf)],
		xonly(&r.s), r.chain)).ok();
	let c3 = Coin { held: received(&r, &c3_key, &c3_leaf), bases: ca.bases.clone() };
	assert_eq!(c3.valid(&r).hops, 3);
	let now = mtp(&r).to_consensus_u32();
	let t = now + exit_delay().seconds() as u32 + 3_600 + 86_400;
	let (b, _, change4_leaf, change4_key) = lock_body(&r, &c3, &keypair("R Q4"), &keypair("R P4 refund"), &random32(), t, 100_000);
	r.http.post("cosign_transfer", &b).ok();
	let c4 = Coin { held: received(&r, &change4_key, &change4_leaf), bases: ca.bases.clone() };
	assert_eq!(c4.valid(&r).hops, 4);
	let (b, ..) = lock_body(&r, &c4, &keypair("R Q5"), &keypair("R P5 refund"), &random32(), t, 100_000);
	refused(&r, "cosign_transfer", &b, "depth_limit", "a lock from a coin 4 reassignments deep");
	let c4v = c4.valid(&r);
	let (c5_leaf, _) = new_leaf(&keypair("R C5"));
	r.http.post("cosign_transfer", &transfer_body(&[(&c4.held, c4v.clone(), c4v.value - MARGIN)],
		&[(x, c4v.value - 2 * MARGIN, c5_leaf)], xonly(&r.s), r.chain)).ok();
	println!("L a plain transfer from the same coin is co-signed (5 reassignments deep)");
}
