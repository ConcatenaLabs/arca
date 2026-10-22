//! Channel leaves (`channel-1`) on a whole server: two boards refreshed in a
//! round into channel leaves, the operator funding its side of each; a
//! payment each way between them, each answered at once with the operator's
//! signature on the payer's state and the receiver's note, with no round
//! between; the refusals of a state that does not follow the channel's
//! latest, of a payment the receiver's side cannot take, of one more than the
//! payer holds and of a state signed by another key; a request repeated after
//! a lost answer answered the same; one channel closed into a round for its
//! owner's side, the latest balance and the credit not folded, and nothing of
//! it moving after; and the signer's own refusal of a state for a coin whose
//! forfeit it signed.

mod common;

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::Keypair;
use serde_json::{json, Value};

use arca_covenant::sign::{sign_digest, verify_digest};
use arca_covenant::{ChannelPolicy, LeafId, State, Template};
use common::client::{auths_json, forfeit_sig, hex, participation_body, random32, unhex, want_channel, want_leaf};
use common::flow::{forfeit_for, held_by, Coin};
use common::keys::{keypair, xonly};
use common::rounds::{created, credited_board, round_final, status, validate_new_leaf, VALUE};
use common::running::{Running, MIN_LEAF};
use server::server::AssetSection;
use server::signer::SignerClient;

const CAPACITY: u64 = 400_000;

async fn start() -> Running {
	let mut r = Running::start_with(|c, y| {
		c.assets[0].channel_capacity = Some("500000".into());
		c.assets.push(AssetSection::new(y, MIN_LEAF));
	}).await;
	let x = r.x;
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r
}

/// A channel leaf held, its policy, and its owner's key.
struct Chan {
	coin: Coin,
	key: Keypair,
	policy: ChannelPolicy,
}

impl Chan {
	fn id(&self) -> LeafId {
		self.coin.held.id
	}
}

fn state_json(s: &State) -> Value {
	json!({"number": s.number.to_string(), "owner": s.owner.to_string(), "operator": s.operator.to_string(),
		"folded": s.folded.to_string()})
}

fn sign_state(c: &Chan, s: &State) -> String {
	hex(sign_digest(&c.key, &c.policy.state_message(s).unwrap().digest, &random32()).as_ref())
}

fn update(r: &Running, c: &Chan, s: &State, pay: Option<(&Chan, u64)>) -> common::client::Answer {
	let mut body = json!({"leaf_id": c.id().to_string(), "state": state_json(s), "owner_sig": sign_state(c, s)});
	if let Some((to, amount)) = pay {
		body["pay"] = json!({"to": to.id().to_string(), "amount": amount.to_string()});
	}
	r.http.post("channel_update", &body)
}

fn sig_of(v: &Value) -> Signature {
	Signature::from_slice(&unhex(v.as_str().unwrap())).unwrap()
}

/// Boards for each key, refreshed in one round into channel leaves of
/// `VALUE + CAPACITY`, the operator funding `CAPACITY` of each.
async fn open(r: &mut Running, keys: &[Keypair]) -> Vec<Chan> {
	let x = r.x;
	let mut boards = vec![];
	for k in keys {
		boards.push(credited_board(r, k, x).await);
	}
	let window = r.server.params.channel_window;
	let mut asks = vec![];
	for ((held, _), k) in boards.iter().zip(keys) {
		let new = keypair(&format!("channel of {}", hex(&xonly(k).serialize())));
		// The owner gives up VALUE; the leaf holds VALUE + CAPACITY.
		let (w, nonce) = want_channel(&new, x, VALUE + CAPACITY, CAPACITY, window);
		let (body, id) = participation_body(&[held], &[w], &[], None, xonly(&r.s), r.chain);
		let st = r.http.post("submit_participation", &body).ok();
		assert_eq!(st["state"], "pending", "{}", st);
		asks.push((id, nonce, new));
	}
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(r, &built.tx.txid()).await;
	let mut out = vec![];
	for ((held, tx), (id, nonce, key)) in boards.iter().zip(asks) {
		let st = status(r, &id);
		let (valid, record, round) = validate_new_leaf(r, &id, 0, &key, &nonce);
		assert_eq!(record.template, Template::Channel1);
		let old = held.record.resolve(std::slice::from_ref(tx), &r.policy()).unwrap();
		let f = forfeit_for(&old, &valid, &round, &st);
		let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&id),
			"forfeits": [{"leaf_id": held.id.to_string(), "signature": forfeit_sig(&f, &held.key)}],
			"leaves": [auths_json(&valid, &key, created(&record))]})).ok();
		assert_eq!(done["state"], "released", "{}", done);
		let h = held_by(r, &key, nonce, valid.leaf_id);
		let policy = record.leaf().channel_policy().unwrap();
		out.push(Chan { coin: Coin { held: h, bases: vec![round] }, key, policy });
	}
	out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channels_pay_each_other_at_once_and_close_into_a_round() {
	let mut r = start().await;
	assert!(r.http.get("info").ok()["templates"]["list"].as_array().unwrap().contains(&json!("channel-1")));
	let info = r.http.get("info").ok();
	println!("asset X's channels: {}", info["assets"][0]["channels"]);
	let ch = open(&mut r, &[keypair("alice"), keypair("bob")]).await;
	let (a, b) = (&ch[0], &ch[1]);
	let s = xonly(&r.s);
	assert_eq!(a.policy.opening(), State { number: 0, owner: VALUE, operator: CAPACITY, folded: 0 });

	// A pays B 100,000: one request, both signatures back.
	let a1 = a.policy.opening().pay(100_000, 0).unwrap();
	let ans = update(&r, a, &a1, Some((b, 100_000))).ok();
	assert!(verify_digest(&sig_of(&ans["operator_sig"]), &a.policy.state_message(&a1).unwrap().digest, &s), "{}", ans);
	assert_eq!(ans["note"]["leaf_id"], json!(b.id().to_string()));
	assert_eq!(ans["note"]["credit"], "100000");
	assert!(verify_digest(&sig_of(&ans["note"]["signature"]), &b.policy.note_message(100_000).unwrap().digest, &s));
	println!("A -> B 100000: state 1 co-signed, B's note of 100000 signed: final at once");

	// The same request again: the same answer, nothing new.
	let again = update(&r, a, &a1, Some((b, 100_000))).ok();
	assert_eq!(again["note"]["credit"], "100000");

	// Refusals.
	let skip = State { number: 3, ..a.policy.opening().pay(10, 0).unwrap() };
	let e = update(&r, a, &skip, Some((b, 10))).refusal();
	assert_eq!(e.0, "channel_state", "{:?}", e);
	println!("refused, a state that skips a number: {}", e.1);
	let other = a.policy.opening().pay(99_999, 0).unwrap();
	let e = update(&r, a, &other, Some((b, 99_999))).refusal();
	assert_eq!(e.0, "channel_state", "{:?}", e);
	println!("refused, another state 1: {}", e.1);
	let too_much = a1.pay(VALUE, 0);
	assert!(too_much.is_none());
	let over = State { number: 2, owner: 0, operator: VALUE + CAPACITY, folded: 0 };
	let e = update(&r, a, &over, Some((b, a1.owner + 1))).refusal();
	assert_eq!(e.0, "channel_state", "{:?}", e);
	println!("refused, paying more than the owner holds: {}", e.1);
	// B's side holds CAPACITY + 0 - 100,000 of capacity for more credit: 300,000.
	let big = a1.pay(300_001, 0).unwrap();
	let e = update(&r, a, &big, Some((b, 300_001))).refusal();
	assert_eq!(e.0, "channel_state", "{:?}", e);
	println!("refused, more than the receiver's side can take: {}", e.1);
	let forged = State { number: 2, ..a1.pay(1_000, 0).unwrap() };
	let body = json!({"leaf_id": a.id().to_string(), "state": state_json(&forged), "owner_sig":
		hex(sign_digest(&b.key, &a.policy.state_message(&forged).unwrap().digest, &random32()).as_ref()),
		"pay": {"to": b.id().to_string(), "amount": "1000"}});
	let e = r.http.post("channel_update", &body).refusal();
	assert_eq!(e.0, "channel_state", "{:?}", e);
	println!("refused, a state signed by another key: {}", e.1);

	// B pays A 30,000, folding its credit of 100,000 in the same state.
	let b1 = b.policy.opening().pay(30_000, 100_000).unwrap();
	assert_eq!(b1, State { number: 1, owner: VALUE + 70_000, operator: CAPACITY - 70_000, folded: 100_000 });
	let ans = update(&r, b, &b1, Some((a, 30_000))).ok();
	assert_eq!(ans["note"]["credit"], "30000");
	println!("B -> A 30000, folding 100000: state 1 co-signed, A's note of 30000 signed");

	// What the server holds of A, read by its owner.
	let view = r.http.post("channel_state", &json!({"auth": r.http.auth_for("channel_state", &a.key, &r.chain, &a.id().0),
		"leaf_id": a.id().to_string()})).ok();
	assert_eq!(view["state"]["number"], "1");
	assert_eq!(view["note"]["credit"], "30000");
	assert_eq!(view["pending"], false);
	let e = r.http.post("channel_state", &json!({"auth": r.http.auth_for("channel_state", &b.key, &r.chain, &a.id().0),
		"leaf_id": a.id().to_string()})).refusal();
	assert_eq!(e.0, "unauthenticated");

	// A closes into a round: its side is 900,000 + 30,000 not folded.
	let share = a1.owner + 30_000;
	let new_key = keypair("alice after the channel");
	let (w, _) = want_leaf(&new_key, r.x, share + 1);
	let (body, _) = participation_body(&[&a.coin.held], &[w], &[], None, s, r.chain);
	let e = r.http.post("submit_participation", &body).refusal();
	assert_eq!(e.0, "unbalanced", "{:?}", e);
	println!("refused, a close for one atom more than the owner's side: {}", e.1);
	let (w, nonce) = want_leaf(&new_key, r.x, share);
	let (body, id) = participation_body(&[&a.coin.held], &[w], &[], None, s, r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	// Given up: nothing of the channel moves, in or out.
	let a2 = a1.pay(1_000, 30_000).unwrap();
	let e = update(&r, a, &a2, Some((b, 1_000))).refusal();
	assert_eq!(e.0, "in_use", "{:?}", e);
	let b2 = b1.pay(1_000, 100_000).unwrap();
	let e = update(&r, b, &b2, Some((a, 1_000))).refusal();
	assert_eq!(e.0, "in_use", "{:?}", e);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let st = status(&r, &id);
	let (valid, record, round) = validate_new_leaf(&r, &id, 0, &new_key, &nonce);
	assert_eq!(record.value, share);
	let old = a.coin.valid(&r);
	let f = forfeit_for(&old, &valid, &round, &st);
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&id),
		"forfeits": [{"leaf_id": a.id().to_string(), "signature": forfeit_sig(&f, &a.key)}],
		"leaves": [auths_json(&valid, &new_key, created(&record))]})).ok();
	assert_eq!(done["state"], "released", "{}", done);
	println!("A closed into a round: a vtxo-1 leaf of {} (900000 + 30000 credit), the forfeit of the whole channel coin signed", share);

	// The signer, on its own: no state for a coin whose forfeit it signed.
	let signer = SignerClient::new(&r.signer.socket);
	let owner_sig = sign_digest(&a.key, &a.policy.state_message(&a2).unwrap().digest, &random32());
	let e = signer.channel_state(&a.policy, &a2, &owner_sig).await.unwrap_err();
	println!("the signer refuses: {}", e);
	assert!(e.to_string().contains("given up or paid on"), "{}", e);
	let e = signer.channel_note(&a.policy, &a1, None, 40_000).await.unwrap_err();
	println!("the signer refuses a note: {}", e);
}
