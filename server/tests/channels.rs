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
//! forfeit it signed. Then the watcher: a live channel brought on the chain
//! at its opening, older than its latest state, is answered by the latest,
//! published over it; and a channel given up in a round and moved on the
//! chain to a later state by its owner is answered there by its forfeit.

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
	assert!(matches!(e, server::signer::SignerError::Declined(_)) && e.is_final(), "refused for good: {}", e);
	let e = signer.channel_note(&a.policy, &a1, None, 40_000).await.unwrap_err();
	println!("the signer refuses a note: {}", e);
}

/// What the server holds of channel `c`, read by its owner.
fn view(r: &Running, c: &Chan) -> Value {
	r.http.post("channel_state", &json!({"auth": r.http.auth_for("channel_state", &c.key, &r.chain, &c.id().0),
		"leaf_id": c.id().to_string()})).ok()
}

/// A state the signer cannot sign now is kept: the signer away, A's payment
/// to B is answered `signer_unavailable` (503), the state waits for the
/// signer, and the same request completes it once the signer is back. A state
/// the signer refuses for good is dropped: with a spend of A's coin in the
/// signer's record (one the database never heard of), A's next payment is
/// refused `channel_state` (422), the same request again is refused the same
/// way, and nothing of it waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_state_the_signer_cannot_sign_now_waits_and_one_it_refuses_is_dropped() {
	let mut r = start().await;
	let ch = open(&mut r, &[keypair("carol"), keypair("dave")]).await;
	let (a, b) = (&ch[0], &ch[1]);
	let genesis = r.chain.genesis_hash();
	let key = r.s;
	let a1 = a.policy.opening().pay(100_000, 0).unwrap();
	r.signer.kill();
	let e = update(&r, a, &a1, Some((b, 100_000)));
	let (code, message) = e.refusal();
	println!("A -> B with the signer away: {} {}: {}", e.status, code, message);
	assert_eq!((e.status, code.as_str()), (503, "signer_unavailable"));
	assert_eq!(view(&r, a)["pending"], true, "the state waits for the signer");
	tokio::task::block_in_place(|| r.signer.restart(&key, genesis));
	let ans = update(&r, a, &a1, Some((b, 100_000))).ok();
	assert_eq!(ans["note"]["credit"], "100000");
	assert_eq!((view(&r, a)["state"]["number"].as_str(), view(&r, a)["pending"].as_bool()), (Some("1"), Some(false)));
	println!("the signer back: the same request completed, state 1 and B's note of 100000");

	// A spend of A's coin in the signer's record.
	let signer = SignerClient::new(&r.signer.socket);
	let v = a.coin.valid(&r);
	let out = arca_covenant::ExplicitOutput::new(v.asset, v.value - 1_000, elements::Script::from(vec![0x51]));
	let m = arca_covenant::message::rebind_message(&r.chain.leaf_constant(&a.policy.salt), v.asset, v.value, std::slice::from_ref(&out))
		.unwrap();
	signer.rebind(&a.policy.owner, &sign_digest(&a.key, &m.digest, &random32()), &a.policy.salt, None, v.asset, v.value,
		std::slice::from_ref(&out), None).await.unwrap();
	let a2 = a1.pay(50_000, 0).unwrap();
	for _ in 0..2 {
		let e = update(&r, a, &a2, Some((b, 50_000)));
		let (code, message) = e.refusal();
		println!("A -> B with a spend of A's coin in the signer's record: {} {}: {}", e.status, code, message);
		assert_eq!((e.status, code.as_str()), (422, "channel_state"));
		assert!(message.contains("given up or paid on"), "{}", message);
	}
	let after = view(&r, a);
	assert_eq!((after["state"]["number"].as_str(), after["pending"].as_bool()), (Some("1"), Some(false)), "dropped: {}", after);
	assert_eq!(view(&r, b)["note"]["credit"], "100000", "B's note is the one signed before");
}

/// The unroll of channel `c`'s path and its entry, each broadcast (a level
/// already on the chain is passed over): the leaf's outpoint, the
/// channel's state-0 output.
fn bring(r: &Running, c: &Chan) -> elements::OutPoint {
	use arca_covenant::spend::FeeSource;
	use arca_covenant::ValidOrigin;
	let v = c.coin.valid(r);
	let (valid, preimage, auths) = match &v.origin {
		ValidOrigin::Leaf { valid, preimage, auths } => (valid, preimage, auths),
		_ => panic!("a batch leaf"),
	};
	let txs = valid.branch.unroll(elements::OutPoint::new(valid.round_txid, valid.batch_vout), auths,
		&vec![FeeSource::Reserve; auths.len()]).unwrap();
	for u in &txs {
		let _ = r.rt.client().send_raw_transaction(&u.tx);
	}
	let entry = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), preimage, &FeeSource::Reserve).unwrap();
	elements::OutPoint::new(r.rt.client().send_raw_transaction(&entry.tx).unwrap(), 0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_watcher_answers_an_older_state_and_a_given_up_channel_at_any_state() {
	use common::flow::{drive, has, log};
	let mut r = start().await;
	let ch = open(&mut r, &[keypair("carol"), keypair("dave")]).await;
	let (c, d) = (&ch[0], &ch[1]);
	let x = r.x;

	// C pays D: C's latest is state 1. D folds its credit: D's latest is 1.
	let c1 = c.policy.opening().pay(100_000, 0).unwrap();
	update(&r, c, &c1, Some((d, 100_000))).ok();
	let d1 = d.policy.opening().pay(0, 100_000).unwrap();
	let d1_ans = update(&r, d, &d1, None).ok();
	println!("C paid D 100000; D folded it: both channels at state 1");

	// C brings its leaf on the chain: its state 0, older than its latest.
	let c_leaf = bring(&r, c);
	r.produce().await;
	let cid = c.id().0.to_vec();
	drive(&r, "the answer to C's older state", 6, |l| has(l, "channel_update", &cid)).await;
	let l = log(&r).await;
	let w = l.iter().find(|w| w.kind == "channel_update" && w.subject == cid).unwrap();
	let tx: elements::Transaction = elements::encode::deserialize(&w.tx).unwrap();
	assert_eq!(tx.input[0].previous_output, c_leaf, "the update spends C's leaf where C put it");
	assert_eq!(tx.output[0].script_pubkey, c.policy.script_pubkey(&c1), "to the output of C's latest state");
	println!("the watcher published state 1 over C's state 0 at {}: {} ({} vB)", c_leaf, tx.txid(), tx.vsize());

	// D closes into a round, then brings its leaf on the chain and moves it
	// to its state 1 itself: the forfeit answers it there.
	let new_key = keypair("dave after the channel");
	let (w, nonce) = want_leaf(&new_key, x, d1.owner);
	let (body, id) = participation_body(&[&d.coin.held], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let st = status(&r, &id);
	let (valid, record, round) = validate_new_leaf(&r, &id, 0, &new_key, &nonce);
	let f = forfeit_for(&d.coin.valid(&r), &valid, &round, &st);
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&id),
		"forfeits": [{"leaf_id": d.id().to_string(), "signature": forfeit_sig(&f, &d.key)}],
		"leaves": [auths_json(&valid, &new_key, created(&record))]})).ok();
	assert_eq!(done["state"], "released", "{}", done);
	let d_leaf = bring(&r, d);
	r.produce().await;
	let fee_coin = r.purse.take_coin(x);
	let owner_sig = sign_digest(&d.key, &d.policy.state_message(&d1).unwrap().digest, &random32());
	let fee = arca_covenant::spend::FeeSource::Coin { outpoint: fee_coin.0, coin: fee_coin.1.clone(), fee: 3_000,
		change: common::node::op_true() };
	let up = d.policy.update_tx(d_leaf, x, &d.policy.opening(), &d1, &sig_of(&d1_ans["operator_sig"]), &owner_sig, &fee).unwrap();
	let up_id = r.rt.client().send_raw_transaction(&up.tx).unwrap();
	r.produce().await;
	let at1 = elements::OutPoint::new(up_id, 0);
	println!("D, its channel given up, moved it to state 1 itself: {} ({} vB)", up_id, up.tx.vsize());
	let did = d.id().0.to_vec();
	drive(&r, "the forfeit of D's channel at its state 1", 6, |l| has(l, "forfeit", &did)).await;
	let l = log(&r).await;
	let w = l.iter().find(|w| w.kind == "forfeit" && w.subject == did).unwrap();
	let tx: elements::Transaction = elements::encode::deserialize(&w.tx).unwrap();
	assert_eq!(tx.input[0].previous_output, at1, "the forfeit spends D's coin at its state-1 output");
	println!("the watcher answered D's channel at its state-1 output {} with its forfeit: {} ({} vB)", at1, tx.txid(), tx.vsize());
}
