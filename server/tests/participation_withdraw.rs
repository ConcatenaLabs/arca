//! A pending participation is withdrawn by the owners of its coins
//! (`withdraw_participation`), under the lock a round build holds: a
//! withdrawal and a round never both take a coin.
//!
//! 1. A withdrawal and a round build, in either order and at once, many
//!    times: exactly one wins. Withdrawn, the participation is void, the next
//!    round runs without it and the coin pays out of round. Taken by the
//!    round, the withdrawal is refused (`in_round`), the participation is
//!    issued in that round and the coin pays nothing out of round.
//! 2. What a withdrawal is refused for: a signature by another key, the
//!    coin's attestation over the id, a withdrawal digest of another
//!    participation or another chain, one coin's owner signing for another's
//!    coin, the wrong count, an unknown participation, and a participation in
//!    a round (issued, then released). A withdrawal answered again is the same
//!    void participation.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::hashes::Hash;
use elements::Transaction;
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::Chain;
use common::client::{forfeit_sig, hex, new_leaf, participation_body, random32, transfer_body, want_leaf, Answer, Held};
use common::flow::forfeit_for;
use common::keys::{keypair, xonly};
use common::rounds::{credited_board, round_final, status, validate_new_leaf, VALUE};
use common::running::Running;

/// The checkpoint margin a transfer of a board coin leaves here.
const MARGIN: u64 = 2_000;

fn refused(a: &Answer, status: i32, code: &str) -> String {
	let (c, m) = a.refusal();
	assert_eq!((a.status, c.as_str()), (status, code), "{}", a.json);
	println!("refused {} {}: {}", status, code, m);
	m
}

/// The body withdrawing participation `id`: each of `keys` signs the
/// withdrawal digest of `id` under `chain`.
fn withdraw_body(r: &Running, chain: &Chain, id: &[u8; 32], keys: &[&Keypair]) -> Value {
	let d = server::participations::withdraw_digest(chain, &xonly(&r.s), id);
	json!({"participation_id": hex(id), "signatures": keys.iter().map(|k| hex(sign_digest(k, &d, &random32()).as_ref())).collect::<Vec<_>>()})
}

/// A board for a fresh key, credited, given up in a refresh of its whole
/// value for a leaf under another fresh key: the coin, its board, the
/// participation's id and body.
async fn waiting(r: &mut Running, label: &str) -> (Held, Transaction, [u8; 32], Value) {
	let owner = keypair(label);
	let x = r.x;
	let (held, tx) = credited_board(r, &owner, x).await;
	let (w, _) = want_leaf(&keypair(&format!("{} new", label)), x, VALUE);
	let (body, id) = participation_body(&[&held], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending", "{}", body);
	(held, tx, id, body)
}

/// An out-of-round payment of `held`'s coin to a fresh key: what the operator
/// answers.
fn pay_out_of_round(r: &Running, held: &Held, board: &Transaction, label: &str) -> Answer {
	let valid = held.record.resolve(std::slice::from_ref(board), &r.policy()).unwrap();
	let (leaf, _) = new_leaf(&keypair(label));
	r.http.post("cosign_transfer", &transfer_body(&[(held, valid, VALUE - MARGIN)], &[(r.x, VALUE - 2 * MARGIN, leaf)], xonly(&r.s), r.chain))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawal_and_a_round_never_both_take_a_coin() {
	let mut r = common::rounds::start().await;
	let x = r.x;
	let (mut withdrawn, mut refreshed, mut waited) = (0, 0, 0);
	// Two of each order, then twelve at once, the round started 0 to 64 ms
	// after the withdrawal was sent.
	let orders: Vec<(u8, u64)> = vec![(0, 0), (1, 0), (0, 0), (1, 0)].into_iter()
		.chain([0u64, 0, 1, 2, 3, 5, 8, 12, 16, 24, 40, 64].into_iter().map(|d| (2u8, d))).collect();
	let n = orders.len();
	for (k, (order, delay)) in orders.into_iter().enumerate() {
		let label = format!("race {}", k);
		let (held, board, id, _) = waiting(&mut r, &label).await;
		let body = withdraw_body(&r, &r.chain.clone(), &id, &[&held.key]);
		let t0 = std::time::Instant::now();
		let (built, answer, timing) = match order {
			0 => {
				let a = r.http.post("withdraw_participation", &body);
				(r.server.rounds.run_round_of(x).await.unwrap(), a, String::new())
			},
			1 => {
				let b = r.server.rounds.run_round_of(x).await.unwrap();
				(b, r.http.post("withdraw_participation", &body), String::new())
			},
			_ => {
				let http = r.http.clone();
				let w = tokio::task::spawn_blocking(move || {
					let a = http.post("withdraw_participation", &body);
					(a, t0.elapsed())
				});
				tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
				let started = t0.elapsed();
				let b = r.server.rounds.run_round_of(x).await.unwrap();
				let ended = t0.elapsed();
				let (a, answered) = w.await.unwrap();
				// The withdrawal answered after the round build ended, though
				// the build began before it was answered: it waited for the lock.
				if answered >= ended && started < answered {
					waited += 1;
				}
				(b, a, format!(" [delay {} ms; build {:?}..{:?}; withdrawal answered at {:?}]", delay, started, ended, answered))
			},
		};
		let st = status(&r, &id);
		let leaf = r.server.store.leaf(&held.id.0).await.unwrap().unwrap();
		let pay = pay_out_of_round(&r, &held, &board, &format!("{} payee", label));
		let in_round = built.as_ref().map(|b| b.tx.txid().to_string()) == st["round"]["txid"].as_str().map(str::to_string);
		println!("race {} (order {}): withdrawal {} {}, participation {}, round {:?}, coin {:?}, pay out of round {} {}{}", k, order,
			answer.status, answer.json["error"]["code"], st["state"], built.as_ref().map(|b| b.tx.txid()), leaf.state, pay.status,
			pay.json["error"]["code"], timing);
		if answer.status == 200 {
			assert_eq!(answer.json["state"], "void", "{}", answer.json);
			assert_eq!(st["state"], "void");
			assert_eq!(st["inputs"][0]["returned"], true, "{}", st);
			assert!(built.is_none(), "no other participation waits, so no round is built");
			assert_eq!(pay.status, 200, "the coin is free: {}", pay.json);
			withdrawn += 1;
		} else {
			refused(&answer, 409, "in_round");
			assert_eq!(st["state"], "issued");
			assert!(in_round, "the participation is in the round just built: {}", st);
			refused(&pay, 409, "double_spend");
			let b = built.unwrap();
			r.produce().await;
			r.bury().await;
			round_final(&r, &b.tx.txid()).await;
			refreshed += 1;
		}
	}
	println!("withdrawn {}, refreshed {}, of {}; {} withdrawal(s) at once waited for a build under way", withdrawn, refreshed, n, waited);
	assert!(withdrawn >= 3 && refreshed >= 3, "each winner occurs: {} withdrawn, {} refreshed", withdrawn, refreshed);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawal_is_refused_unless_the_coins_owners_sign_it_before_a_round() {
	let mut r = common::rounds::start().await;
	let x = r.x;
	let s = xonly(&r.s);
	let chain = r.chain;
	assert_eq!(r.http.get("info").json["participations"]["withdraw"], true);

	let (held, board, id, body) = waiting(&mut r, "W1").await;
	let other = keypair("not W1");
	refused(&r.http.post("withdraw_participation", &withdraw_body(&r, &chain, &id, &[&other])), 422, "bad_signature");
	// The coin's attestation, its owner's signature over the id itself.
	let attestation = body["inputs"][0]["attestation"].clone();
	refused(&r.http.post("withdraw_participation", &json!({"participation_id": hex(&id), "signatures": [attestation]})), 422,
		"bad_signature");
	// Its owner's withdrawal of another chain's participation of that id.
	let elsewhere = Chain::new(elements::BlockHash::from_byte_array([7; 32]));
	refused(&r.http.post("withdraw_participation", &withdraw_body(&r, &elsewhere, &id, &[&held.key])), 422, "bad_signature");
	refused(&r.http.post("withdraw_participation", &json!({"participation_id": hex(&id), "signatures": []})), 400, "malformed");
	refused(&r.http.post("withdraw_participation", &withdraw_body(&r, &chain, &[9; 32], &[&held.key])), 404, "unknown_participation");

	// Two coins, two owners: each signs for its own coin.
	let (h2, _) = credited_board(&mut r, &keypair("W2a"), x).await;
	let (h3, _) = credited_board(&mut r, &keypair("W2b"), x).await;
	let (w, _) = want_leaf(&keypair("W2 new"), x, 2 * VALUE);
	let (b2, id2) = participation_body(&[&h2, &h3], &[w], &[], None, s, chain);
	assert_eq!(r.http.post("submit_participation", &b2).ok()["state"], "pending");
	refused(&r.http.post("withdraw_participation", &withdraw_body(&r, &chain, &id2, &[&h2.key, &h2.key])), 422, "bad_signature");
	// W1's withdrawal, presented for the other participation.
	let mut swapped = withdraw_body(&r, &chain, &id, &[&held.key, &held.key]);
	swapped["participation_id"] = json!(hex(&id2));
	refused(&r.http.post("withdraw_participation", &swapped), 422, "bad_signature");
	let ok = r.http.post("withdraw_participation", &withdraw_body(&r, &chain, &id2, &[&h2.key, &h3.key])).ok();
	assert_eq!((ok["state"].as_str(), ok["inputs"][0]["returned"].as_bool(), ok["inputs"][1]["returned"].as_bool()),
		(Some("void"), Some(true), Some(true)), "{}", ok);
	println!("withdrawn: {}", ok["void_reason"]);
	// Again: the same void participation.
	let again = r.http.post("withdraw_participation", &withdraw_body(&r, &chain, &id2, &[&h2.key, &h3.key])).ok();
	assert_eq!(again["state"], "void");
	// The request again is the same participation, void: it is not taken anew.
	assert_eq!(r.http.post("submit_participation", &b2).ok()["state"], "void");
	// The coins are free: a new refresh gives them up.
	let (w, _) = want_leaf(&keypair("W2 newer"), x, 2 * VALUE);
	let (b3, _) = participation_body(&[&h2, &h3], &[w], &[], None, s, chain);
	assert_eq!(r.http.post("submit_participation", &b3).ok()["state"], "pending");

	// In a round: refused while issued, and once released.
	let built = r.server.rounds.run_round_of(x).await.unwrap().unwrap();
	assert_eq!(status(&r, &id)["state"], "issued");
	let w1 = withdraw_body(&r, &chain, &id, &[&held.key]);
	refused(&r.http.post("withdraw_participation", &w1), 409, "in_round");
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let st = status(&r, &id);
	let new_key = keypair("W1 new");
	let n = body["outputs"][0]["leaf"]["owner_nonce"].as_str().unwrap();
	let nonce: [u8; 32] = common::client::unhex(n).try_into().unwrap();
	let (new_valid, record, round) = validate_new_leaf(&r, &id, 0, &new_key, &nonce);
	let old = held.record.resolve(std::slice::from_ref(&board), &r.policy()).unwrap();
	let f = forfeit_for(&old, &new_valid, &round, &st);
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&id),
		"forfeits": [{"leaf_id": held.id.to_string(), "signature": forfeit_sig(&f, &held.key)}],
		"leaves": [common::client::auths_json(&new_valid, &new_key, common::rounds::created(&record))]})).ok();
	assert_eq!(done["state"], "released", "{}", done);
	refused(&r.http.post("withdraw_participation", &w1), 409, "in_round");
}
