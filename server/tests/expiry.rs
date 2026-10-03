//! The times a participation keeps to, against a whole server on an anchored
//! proof-of-stake regtest chain, the chain's median time moved on with the
//! node's clock:
//!
//! 1. A participation whose forfeits have not come a day after its round was
//!    found final expires: its coin is live again and is given up again in a
//!    new participation, its new leaf is expired and never credited, its
//!    forfeit is refused, and its new leaf's key is free again: the new
//!    participation wants a leaf under it. A participation of the same round
//!    whose forfeits came is untouched.
//! 2. The refresh window and the exit deadline, on batch leaves of a round
//!    whose first expiry is `E`: at `E` less six days a refresh is charged for
//!    the day before the window; at `E` less four days it is free and runs, and
//!    a round time asked for past the exit deadline is refused; past the exit
//!    deadline a coin is refused; and a participation accepted before the
//!    deadline whose coin passes `E` less one day before any round takes it is
//!    voided, its coin given back.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::Transaction;
use serde_json::{json, Value};

use arca_covenant::{CoinRecord, Forfeit, LeafId, LeafRecord, RelativeTime, ValidCoin, ValidLeaf};
use common::client::{auths_json, forfeit_sig, hex, participation_body, unhex, want_leaf, Answer, Held};
use common::keys::{keypair, xonly};
use common::rounds::{advance_mtp, created, credited_board, mtp, round_final, start, status, validate_new_leaf, VALUE};
use common::running::{Running, MIN_LEAF};
use server::params::{FeeSchedule, Params};
use server::server::{AssetSection, FeesSection};

const DAY: u32 = 86_400;

fn refused(a: Answer, status: i32, code: &str) -> String {
	let (c, m) = a.refusal();
	assert_eq!((a.status, c.as_str()), (status, code), "{}", a.json);
	println!("refused {} {}: {}", status, code, m);
	m
}

fn forfeit_for(old: &ValidCoin, new: &ValidLeaf, round: &Transaction, st: &Value) -> Forfeit {
	let c = st["round"]["connector_vout"].as_u64().unwrap() as u32;
	let delay = RelativeTime::from_units(st["refund_delay_units"].as_u64().unwrap() as u16).unwrap();
	let margin: u64 = st["inputs"][0]["margin"].as_str().unwrap().parse().unwrap();
	Forfeit::for_refresh(old.leaf, (old.asset, old.value), old.id, new, round, c, delay, margin).unwrap()
}

fn forfeit_body(id: &[u8; 32], old: LeafId, sig: String, auths: Value) -> Value {
	json!({"participation_id": hex(id), "forfeits": [{"leaf_id": old.to_string(), "signature": sig}], "leaves": [auths]})
}

/// A participation giving up `old` for one leaf of `value` under `new_key`,
/// paying `fee`, from round time `not_before`: the answer, its id and the new
/// leaf's nonce.
fn submit(r: &Running, old: &Held, new_key: &Keypair, value: u64, fee: u64, not_before: Option<u32>) -> (Answer, [u8; 32], [u8; 32]) {
	let (w, nonce) = want_leaf(new_key, r.x, value);
	let fees: Vec<(elements::AssetId, u64)> = if fee > 0 { vec![(r.x, fee)] } else { vec![] };
	let (body, id) = participation_body(&[old], &[w], &fees, not_before, xonly(&r.s), r.chain);
	(r.http.post("submit_participation", &body), id, nonce)
}

/// The states of `key`'s leaves, as `leaf_data` reports them, sorted.
fn leaf_states(r: &Running, key: &Keypair) -> Vec<String> {
	let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", key, &r.chain)})).ok();
	let mut states: Vec<String> = ld["leaves"].as_array().unwrap().iter().map(|l| l["state"].as_str().unwrap().to_string()).collect();
	states.sort();
	states
}

/// Completes participation `id` (giving up `old`, held under `old_key`, for
/// the leaf `new_key` with `nonce`): its forfeit and authorisations handed
/// over. Returns the new leaf as a held coin, its validated form and record.
async fn complete(r: &Running, id: &[u8; 32], old: &Held, old_key: &Keypair, old_base: &Transaction, new_key: &Keypair,
	nonce: &[u8; 32]) -> (Held, ValidLeaf, LeafRecord, Transaction)
{
	let st = status(r, id);
	let (valid, record, round) = validate_new_leaf(r, id, 0, new_key, nonce);
	let old_coin = old.record.resolve(std::slice::from_ref(old_base), &r.policy()).unwrap();
	let f = forfeit_for(&old_coin, &valid, &round, &st);
	let done = r.http.post("forfeit_leaves", &forfeit_body(id, old.id, forfeit_sig(&f, old_key), auths_json(&valid, new_key, created(&record)))).ok();
	assert_eq!(done["state"], "released", "{}", done);
	let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", new_key, &r.chain)})).ok();
	let entry = ld["leaves"].as_array().unwrap().iter().find(|l| l["leaf_id"] == json!(valid.leaf_id.to_string())).unwrap().clone();
	let held = Held { key: *new_key, nonce: *nonce, id: valid.leaf_id, record: CoinRecord::from_bytes(&unhex(entry["record"].as_str().unwrap())).unwrap() };
	(held, valid, record, round)
}

// ---------------------------------------------------------------------------
// 1. Forfeits a day overdue
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_participation_whose_forfeits_never_come_expires() {
	let mut r = start().await;
	let x = r.x;
	let (a, b) = (keypair("A"), keypair("B"));
	let (a_board, a_tx) = credited_board(&mut r, &a, x).await;
	let (b_board, b_tx) = credited_board(&mut r, &b, x).await;
	let (a2, b2) = (keypair("A, new"), keypair("B, new"));
	let (ans, pa, a2_nonce) = submit(&r, &a_board, &a2, VALUE, 0, None);
	assert_eq!(ans.ok()["state"], "pending");
	let (ans, pb, b2_nonce) = submit(&r, &b_board, &b2, VALUE, 0, None);
	assert_eq!(ans.ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let found = r.server.store.round_by_txid(&elements::hashes::Hash::to_byte_array(built.tx.txid())).await.unwrap().unwrap();
	let final_at = found.final_mtp.expect("a final round knows when it was found final");
	println!("round {} found final at median time {}", built.tx.txid(), final_at);

	// A validates its new leaf, and could hand over its forfeit; B does.
	let (a2_valid, a2_record, round) = validate_new_leaf(&r, &pa, 0, &a2, &a2_nonce);
	let st_a = status(&r, &pa);
	complete(&r, &pb, &b_board, &b, &b_tx, &b2, &b2_nonce).await;
	assert!(r.server.rounds.expire().await.unwrap().is_empty(), "nothing is overdue yet");
	assert_eq!(status(&r, &pa)["state"], "issued");

	// A day after the round was found final, A's participation expires.
	// (The server's own pass on the new blocks may expire it first.)
	advance_mtp(&r, DAY + 600).await;
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	let tip = r.server.store.tip_block().await.unwrap().unwrap();
	assert!(tip.median_time as u32 >= final_at + DAY);
	let sa = status(&r, &pa);
	println!("A after a day: {}", sa);
	assert_eq!(sa["state"], "expired");
	assert_eq!(status(&r, &pb)["state"], "released");
	assert_eq!(leaf_states(&r, &a), vec!["live"], "A's board is A's again");
	assert_eq!(leaf_states(&r, &a2), vec!["expired"], "A's new leaf is never credited");
	assert_eq!(leaf_states(&r, &b2), vec!["live"]);

	// Too late for A's forfeit, a good one included: no preimage goes out.
	let a_old = a_board.record.resolve(std::slice::from_ref(&a_tx), &r.policy()).unwrap();
	let f = forfeit_for(&a_old, &a2_valid, &round, &st_a);
	refused(r.http.post("forfeit_leaves", &forfeit_body(&pa, a_board.id, forfeit_sig(&f, &a), auths_json(&a2_valid, &a2, created(&a2_record)))),
		422, "not_in_round");
	assert!(r.server.store.forfeits(&pa, built.round_id).await.unwrap().is_empty());
	// A forfeit step already past its first check when the expiry ran is
	// refused where it records: nothing is stored, the participation is not
	// released.
	match r.server.store.complete_participation(&pa, 0, built.round_id, &[], &[], true).await {
		Err(server::store::StoreError::NotInRound(state)) => assert_eq!(state, "expired"),
		other => panic!("an expired participation completed: {:?}", other.map(|_| ())),
	}
	assert_eq!(status(&r, &pa)["state"], "expired");
	// A's new leaf was never credited: its key is free again, and A's board,
	// given back by the expiry, is given up again in a new participation that
	// wants a leaf under that same key.
	let (ans, pa3, _) = submit(&r, &a_board, &a2, VALUE, 0, None);
	assert_eq!(ans.ok()["state"], "pending");
	assert_ne!(pa3, pa);
	assert_eq!(leaf_states(&r, &a), vec!["spent"]);
	println!("A's board, given back by the expiry, is given up again in {}", hex(&pa3));
}

// ---------------------------------------------------------------------------
// 2. The refresh window and the exit deadline
// ---------------------------------------------------------------------------

/// [`start`], charging up to 23,000 parts per million for a refresh: 1,000
/// atoms a day of a million-atom coin before the free window.
async fn start_charging() -> Running {
	let mut r = Running::start_with(|c, y| {
		c.assets.push(AssetSection { asset: y.to_string(), min_leaf: MIN_LEAF.to_string() });
		c.fees = FeesSection { refresh_ppm: 23_000, ..Default::default() };
	}).await;
	let (x, y) = (r.x, r.y);
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(y, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r
}

/// Moves the median time to at least `t`, and the server with it.
async fn to_time(r: &Running, t: u32) {
	let now = mtp(r).to_consensus_u32();
	assert!(t > now, "{} is not ahead of {}", t, now);
	advance_mtp(r, t - now).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_refresh_window_and_the_exit_deadline() {
	let mut r = start_charging().await;
	let x = r.x;
	let fees = FeeSchedule { refresh_ppm: 23_000, offboard_ppm: 0 };

	// Three batch leaves of one round, from boards: A, B and C. A board just
	// confirmed has its whole service ahead of it and pays the whole fee.
	let full = fees.refresh(VALUE, arca_covenant::transfer::NEVER, mtp(&r));
	assert_eq!(full, 23_000);
	let cv = VALUE - full;
	let mut held = vec![];
	let mut ids = vec![];
	for name in ["A", "B", "C"] {
		let k = keypair(name);
		let (board, tx) = credited_board(&mut r, &k, x).await;
		let n = keypair(&format!("{}, batch", name));
		let (ans, id, nonce) = submit(&r, &board, &n, VALUE - full, full, None);
		assert_eq!(ans.ok()["state"], "pending");
		ids.push(id);
		held.push((k, board, tx, n, nonce));
	}
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let mut coins = vec![];
	for (id, (k, board, tx, n, nonce)) in ids.iter().zip(&held) {
		let (coin, _, record, round) = complete(&r, id, board, k, tx, n, nonce).await;
		coins.push((*n, coin, record, round));
	}
	let e = coins[0].2.schedule.expiries()[0].to_consensus_u32();
	println!("A, B and C hold batch leaves whose first expiry is {}", e);
	let (a, b, c) = (&coins[0], &coins[1], &coins[2]);

	// Six days before E: the day before the free window is charged.
	to_time(&r, e - 6 * DAY).await;
	let now = mtp(&r);
	let due = fees.refresh(cv, arca_covenant::MedianTime::from_consensus(e).unwrap(), now);
	println!("at E - {} s a refresh of A is charged {} atoms", e - now.to_consensus_u32(), due);
	assert!(due > 0 && due <= 1_000, "the day before the window: {}", due);
	let (ans, _, _) = submit(&r, &a.1, &keypair("A, refreshed early"), cv - (due - 1), due - 1, None);
	let m = refused(ans, 422, "fee");
	assert!(m.contains(&format!("asks {}", due)), "{}", m);

	// Four days before E, inside the window: free. A refreshes for nothing,
	// and its round runs; B asks for a round past its exit deadline, which is
	// refused, and then for one just before it, which is taken.
	to_time(&r, e - 4 * DAY).await;
	assert_eq!(fees.refresh(cv, arca_covenant::MedianTime::from_consensus(e).unwrap(), mtp(&r)), 0);
	let a3 = keypair("A, refreshed in the window");
	let (ans, pa, a3_nonce) = submit(&r, &a.1, &a3, cv, 0, None);
	assert_eq!(ans.ok()["state"], "pending");
	let deadline = e - Params::PARTICIPATION_HORIZON;
	let (ans, _, _) = submit(&r, &b.1, &keypair("B, too late"), cv, 0, Some(deadline + 600));
	refused(ans, 422, "out_of_bounds");
	let (ans, pb, _) = submit(&r, &b.1, &keypair("B, deferred"), cv, 0, Some(deadline - 600));
	assert_eq!(ans.ok()["state"], "pending");
	let built_a = r.server.rounds.run_round().await.unwrap().unwrap();
	assert_eq!(built_a.participations, 1, "A only: B's round time has not come");
	r.produce().await;
	r.bury().await;
	round_final(&r, &built_a.tx.txid()).await;
	let (a_round_tx, a_k) = (&a.3, &a.0);
	complete(&r, &pa, &a.1, a_k, a_round_tx, &a3, &a3_nonce).await;
	println!("A refreshed for nothing in the window");

	// Past the exit deadline a coin is refused.
	to_time(&r, deadline + 600).await;
	let (ans, _, _) = submit(&r, &c.1, &keypair("C, too late"), cv, 0, None);
	let m = refused(ans, 422, "invalid_coin");
	assert!(m.contains("earlier than"), "{}", m);

	// B's participation, accepted before the deadline, finds no round before
	// E less one day: the next round voids it, and B's coin is B's again.
	to_time(&r, e - Params::ROUND_HORIZON + 600).await;
	assert!(r.server.rounds.run_round().await.unwrap().is_none(), "no participation can run");
	assert_eq!(status(&r, &pb)["state"], "void");
	assert_eq!(leaf_states(&r, &b.0), vec!["live"]);
	println!("B's deferred participation could never run: void, its coin live again");
}
