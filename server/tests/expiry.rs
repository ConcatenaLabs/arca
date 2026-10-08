//! The times a participation keeps to, against a whole server on an anchored
//! proof-of-stake regtest chain, the chain's median time moved on with the
//! node's clock:
//!
//! 1. A participation whose forfeits have not come a day after its round was
//!    found final expires: its coin is live again and is given up again in a
//!    new participation, its new leaf is expired and never credited, its
//!    forfeit is refused, and its new leaf's key is free again: the new
//!    participation wants a leaf under it. A participation of the same round
//!    whose forfeits came is untouched. So does one whose forfeit came and
//!    was never co-signed (the signer away): the forfeit without the
//!    operator's half is dropped, never asked of the signer again, and the
//!    coin, live again, is given up in a new participation that completes.
//! 2. The refresh window and the exit deadline, on batch leaves of a round
//!    whose first expiry is `E`: at `E` less six days a refresh is charged for
//!    the day before the window; at `E` less four days it is free and runs, and
//!    a round time asked for past the exit deadline is refused; past the exit
//!    deadline a coin is refused; and a participation accepted before the
//!    deadline whose coin passes its exit deadline before any round takes it
//!    is voided by the next pass over the rounds, no round built, its coin
//!    given back.
//! 3. No participation stuck (D59.2): a coin under a forfeit or a spend the
//!    signer holds is refused when offered; one taken before that check,
//!    its other forfeit whole, is released on the watcher's claim.
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

	// A day after the round was found final A's participation still waits:
	// its forfeits are taken until its coin's exit deadline, which is later.
	advance_mtp(&r, DAY + 600).await;
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	let tip = r.server.store.tip_block().await.unwrap().unwrap();
	assert!(tip.median_time as u32 >= final_at + DAY);
	assert_eq!(status(&r, &pa)["state"], "issued", "a day on, before its coin's exit deadline");
	// At its coin's exit deadline it expires. (The server's own pass on the
	// new blocks may expire it first.)
	let deadline = board_exit_deadline(&r, &a_board.id).await;
	to_time(&r, deadline + 600).await;
	r.server.rounds.pass().await.unwrap();
	let sa = status(&r, &pa);
	println!("A past its coin's exit deadline ({}): {}", deadline, sa);
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
	match r.server.store.complete_participation(&pa, 0, built.round_id, &[], &[]).await {
		Err(server::store::StoreError::NotInRound(state)) => assert_eq!(state, "expired"),
		other => panic!("an expired participation completed: {:?}", other.map(|_| ())),
	}
	assert_eq!(status(&r, &pa)["state"], "expired");
	// A's new leaf was never credited: its key is free again, wanted by a new
	// participation giving up another board of A's. (A's board, given back
	// past its exit deadline, is its owner's to take on the chain.)
	let a_other = keypair("A, another board");
	let (other, _) = credited_board(&mut r, &a_other, x).await;
	let (ans, pa3, _) = submit(&r, &other, &a2, VALUE, 0, None);
	assert_eq!(ans.ok()["state"], "pending");
	assert_ne!(pa3, pa);
	println!("A's new leaf's key, free again, is wanted in {}", hex(&pa3));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_participation_whose_forfeits_are_never_cosigned_expires() {
	let mut r = start().await;
	let x = r.x;
	let a = keypair("A");
	let (a_board, a_tx) = credited_board(&mut r, &a, x).await;
	let a2 = keypair("A, new");
	let (ans, pa, a2_nonce) = submit(&r, &a_board, &a2, VALUE, 0, None);
	assert_eq!(ans.ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;

	// The signer away: A's forfeit is recorded with A's half alone.
	let (valid, record, round) = validate_new_leaf(&r, &pa, 0, &a2, &a2_nonce);
	let st = status(&r, &pa);
	let old = a_board.record.resolve(std::slice::from_ref(&a_tx), &r.policy()).unwrap();
	let f = forfeit_for(&old, &valid, &round, &st);
	r.signer.kill();
	let ans = r.http.post("forfeit_leaves", &forfeit_body(&pa, a_board.id, forfeit_sig(&f, &a), auths_json(&valid, &a2, created(&record))));
	println!("A's forfeit with the signer away: {} {}", ans.status, ans.json);
	assert_eq!(ans.status, 503, "{}", ans.json);
	assert_eq!(r.server.store.unsigned_forfeits().await.unwrap().len(), 1, "recorded, not co-signed");
	assert!(r.server.rounds.expire().await.unwrap().is_empty(), "nothing is overdue yet");
	assert_eq!(status(&r, &pa)["state"], "issued");

	// A day after the round was found final it waits; at its coin's exit
	// deadline it expires all the same.
	advance_mtp(&r, DAY + 600).await;
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	assert_eq!(status(&r, &pa)["state"], "issued", "a day on, before its coin's exit deadline");
	let deadline = board_exit_deadline(&r, &a_board.id).await;
	to_time(&r, deadline + 600).await;
	r.server.rounds.pass().await.unwrap();
	let sa = status(&r, &pa);
	println!("A past its coin's exit deadline, its forfeit never co-signed: {}", sa);
	assert_eq!(sa["state"], "expired", "{}", sa);
	// The forfeit was recorded and the signer asked for its half: it may be
	// in the signer's record, which then co-signs no spend of the coin, so
	// the coin is not given back as payable. It stays given up, its owner's
	// way home its exit.
	assert_eq!(sa["inputs"][0]["returned"], false, "{}", sa);
	assert!(r.server.store.unsigned_forfeits().await.unwrap().is_empty(), "the forfeit without the operator's half is dropped");
	assert!(r.server.store.forfeits(&pa, built.round_id).await.unwrap().is_empty());
	assert_eq!(leaf_states(&r, &a), vec!["spent"], "A's board stays given up");
	assert_eq!(leaf_states(&r, &a2), vec!["expired"], "A's new leaf is never credited");

	// The signer back: nothing is asked of it for the expired participation.
	let genesis = r.rt.client().genesis_hash().unwrap();
	r.signer.restart(&r.s, genesis);
	assert_eq!(r.server.forfeits.fill_unsigned().await.unwrap(), 0);
	let _ = a_tx;
}

/// The exit deadline of the board coin `id`, as the server dates it: its
/// service expiry, [`Params::BOARD_LIFETIME`] after the median time of the
/// block holding the board, less the exit deadline.
async fn board_exit_deadline(r: &Running, id: &LeafId) -> u32 {
	let b = r.server.store.board(&id.0).await.unwrap().expect("a board");
	let block = r.server.store.tx_location(&b.txid).await.unwrap().expect("in a block");
	Params::board_expiry(block.median_time as u32) - Params::PARTICIPATION_HORIZON
}

/// R7h F2 at the server. A participation's forfeits are taken until the
/// later of a day after its round was found final and its coins' exit
/// deadline, so a holder that asked in its coin's free window completes the
/// refresh at any sync before the coin's exit date. A and B give up boards
/// in one round. 25 hours after the round was found final neither has
/// expired, and A's forfeit, handed over then, releases A's. B's, never
/// handed over, is still issued ten minutes before its coin's exit deadline,
/// and expires at the first pass after it, its board given back.
#[tokio::test(flavor = "multi_thread")]
async fn the_forfeits_are_taken_until_the_coins_exit_deadline() {
	let mut r = start().await;
	let x = r.x;
	let (a, b) = (keypair("A"), keypair("B"));
	let (a_board, a_tx) = credited_board(&mut r, &a, x).await;
	let (b_board, _) = credited_board(&mut r, &b, x).await;
	let (a2, b2) = (keypair("A, new"), keypair("B, new"));
	let (ans, pa, a2_nonce) = submit(&r, &a_board, &a2, VALUE, 0, None);
	assert_eq!(ans.ok()["state"], "pending");
	let (ans, pb, _) = submit(&r, &b_board, &b2, VALUE, 0, None);
	assert_eq!(ans.ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let found = r.server.store.round_by_txid(&elements::hashes::Hash::to_byte_array(built.tx.txid())).await.unwrap().unwrap();
	let final_at = found.final_mtp.expect("a final round knows when it was found final");
	let deadline = board_exit_deadline(&r, &b_board.id).await;
	println!("round {} found final at median time {}; B's board's exit deadline {}", built.tx.txid(), final_at, deadline);
	// A validates its new leaf now, as its wallet does when it asks.
	let (a2_valid, a2_record, round) = validate_new_leaf(&r, &pa, 0, &a2, &a2_nonce);
	let st_a = status(&r, &pa);

	advance_mtp(&r, DAY + 3_600).await;
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	let now = mtp(&r).to_consensus_u32();
	let (sa, sb) = (status(&r, &pa), status(&r, &pb));
	println!("25 hours on (median time {}, {} s after the round was found final): A {} | B {}", now, now - final_at, sa["state"], sb["state"]);
	assert!(now >= final_at + DAY + 3_600);
	assert_eq!(sa["state"], "issued", "A's forfeits are still taken: {}", sa);
	assert_eq!(sb["state"], "issued", "{}", sb);
	let a_old = a_board.record.resolve(std::slice::from_ref(&a_tx), &r.policy()).unwrap();
	let f = forfeit_for(&a_old, &a2_valid, &round, &st_a);
	let done = r.http.post("forfeit_leaves", &forfeit_body(&pa, a_board.id, forfeit_sig(&f, &a), auths_json(&a2_valid, &a2,
		created(&a2_record)))).ok();
	assert_eq!(done["state"], "released", "{}", done);
	assert_eq!(leaf_states(&r, &a2), vec!["live"], "A's new leaf is credited");
	println!("A's forfeit, handed over 25 hours after the round was found final, released it");

	to_time(&r, deadline - 600).await;
	r.server.rounds.pass().await.unwrap();
	let sb = status(&r, &pb);
	println!("ten minutes before B's coin's exit deadline: B {}", sb["state"]);
	assert_eq!(sb["state"], "issued", "{}", sb);
	to_time(&r, deadline + 600).await;
	r.server.rounds.pass().await.unwrap();
	let sb = status(&r, &pb);
	println!("ten minutes after it: B {}", sb);
	assert_eq!(sb["state"], "expired", "{}", sb);
	assert_eq!(leaf_states(&r, &b), vec!["live"], "B's board, under no forfeit, is B's again");
	assert_eq!(leaf_states(&r, &b2), vec!["expired"], "B's new leaf is never credited");
}

// ---------------------------------------------------------------------------
// 2. The refresh window and the exit deadline
// ---------------------------------------------------------------------------

/// [`start`], charging up to 23,000 parts per million for a refresh: 1,000
/// atoms a day of a million-atom coin before the free window.
async fn start_charging() -> Running {
	let mut r = Running::start_with(|c, y| {
		c.assets.push(AssetSection::new(y, MIN_LEAF));
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
	let fees = FeeSchedule { refresh_ppm: 23_000, ..Default::default() };

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

	// B's participation, accepted before the deadline, found no round
	// before it: the next pass over the rounds voids it, with no round built
	// (the server's own pass on the blocks above may have voided it first),
	// and B's coin is B's again, to take on the chain.
	r.server.rounds.pass().await.unwrap();
	let sb = status(&r, &pb);
	println!("B's deferred participation past its coin's exit deadline: {}", sb);
	assert_eq!(sb["state"], "void", "{}", sb);
	assert!(sb["void_reason"].as_str().unwrap_or("").contains("past its exit deadline"), "{}", sb);
	assert_eq!(leaf_states(&r, &b.0), vec!["live"]);
	assert!(r.server.rounds.run_round().await.unwrap().is_none(), "no participation can run");
	println!("B's deferred participation could never run: void at its coin's exit deadline, its coin live again");
}

// ---------------------------------------------------------------------------
// 3. A forfeit the operator can claim ends in a release (D59)
// ---------------------------------------------------------------------------

/// R7h F3 (a) at the server. A's forfeit is recorded while the signer is
/// away (`signer_unavailable`); the signer back, the server's minute task
/// fills in the operator's half, and the next pass over the rounds releases
/// the participation, whose forfeit the operator now holds whole: A's new
/// leaf is credited, and A's forfeit step asked again returns the preimage.
#[tokio::test(flavor = "multi_thread")]
async fn a_forfeit_completed_late_releases_its_participation() {
	let mut r = start().await;
	let x = r.x;
	let a = keypair("A");
	let (a_board, a_tx) = credited_board(&mut r, &a, x).await;
	let a2 = keypair("A, new");
	let (ans, pa, a2_nonce) = submit(&r, &a_board, &a2, VALUE, 0, None);
	assert_eq!(ans.ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let (valid, record, round) = validate_new_leaf(&r, &pa, 0, &a2, &a2_nonce);
	let st = status(&r, &pa);
	let old = a_board.record.resolve(std::slice::from_ref(&a_tx), &r.policy()).unwrap();
	let f = forfeit_for(&old, &valid, &round, &st);
	let body = forfeit_body(&pa, a_board.id, forfeit_sig(&f, &a), auths_json(&valid, &a2, created(&record)));
	r.signer.kill();
	let ans = r.http.post("forfeit_leaves", &body);
	println!("A's forfeit with the signer away: {} {}", ans.status, ans.json);
	assert_eq!(ans.status, 503, "{}", ans.json);
	let genesis = r.rt.client().genesis_hash().unwrap();
	r.signer.restart(&r.s, genesis);
	let filled = r.server.forfeits.fill_unsigned().await.unwrap();
	r.server.rounds.pass().await.unwrap();
	let sa = status(&r, &pa);
	println!("the signer back: {} forfeit(s) filled in; A at the server: {}; A's new leaf {:?}", filled, sa["state"], leaf_states(&r, &a2));
	assert_eq!(filled, 1);
	assert_eq!(sa["state"], "released", "a forfeit the operator holds whole ends in a release: {}", sa);
	assert_eq!(leaf_states(&r, &a2), vec!["live"], "A's new leaf is credited");
	let again = r.http.post("forfeit_leaves", &body).ok();
	assert_eq!(again["state"], "released", "{}", again);
	assert!(again["preimage"].is_string(), "{}", again);
}

/// A gate in front of the signer's socket: it passes every request, but
/// answers the forfeits past the first `allow` of them as a signer whose
/// keepers are away does, without passing them on.
struct SignerGate {
	path: std::path::PathBuf,
	allow: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl SignerGate {
	fn start(signer: &std::path::Path, allow: usize) -> SignerGate {
		use std::sync::atomic::Ordering;
		use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
		let path = signer.with_extension("gate.sock");
		let _ = std::fs::remove_file(&path);
		let listener = tokio::net::UnixListener::bind(&path).unwrap();
		let allow = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(allow));
		let (a, target) = (allow.clone(), signer.to_path_buf());
		tokio::spawn(async move {
			while let Ok((s, _)) = listener.accept().await {
				let (a, target) = (a.clone(), target.clone());
				tokio::spawn(async move {
					let (r, mut w) = s.into_split();
					let mut line = String::new();
					if BufReader::new(r).read_line(&mut line).await.is_err() {
						return;
					}
					let forfeit = serde_json::from_str::<Value>(&line).is_ok_and(|v| !v["forfeit"].is_null());
					if forfeit && a.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_err() {
						let _ = w.write_all(b"{\"error\":\"keepers_unavailable: the test's gate holds this forfeit back\"}\n").await;
						return;
					}
					let Ok(t) = tokio::net::UnixStream::connect(&target).await else { return };
					let (tr, mut tw) = t.into_split();
					if tw.write_all(line.as_bytes()).await.is_err() {
						return;
					}
					let mut answer = String::new();
					if BufReader::new(tr).read_line(&mut answer).await.is_ok() {
						let _ = w.write_all(answer.as_bytes()).await;
					}
				});
			}
		});
		SignerGate { path, allow }
	}

	fn open(&self) {
		self.allow.store(usize::MAX, std::sync::atomic::Ordering::SeqCst);
	}
}

/// R7h F3's two-coin case, run. A gives up two boards in one participation
/// for one leaf of both values. Its forfeit step stops between the two
/// co-signatures: a gate in front of the signer lets the first forfeit
/// through and holds the second back, so the first is whole and the second
/// recorded without the operator's half, never signed. Past the forfeit
/// deadline the participation is not expired, the second forfeit stays
/// recorded, and neither coin is given back: the claim of the first forfeit,
/// which opens the leaf of both values, cannot leave the second coin with A.
/// The gate opened, the server's minute task completes the second forfeit,
/// the next pass releases the participation and credits the new leaf, and
/// the watcher takes both boards by their forfeits: the operator pays for
/// each coin once.
#[tokio::test(flavor = "multi_thread")]
async fn two_coins_one_forfeit_whole_and_nothing_is_paid_twice() {
	let mut r = start().await;
	let x = r.x;
	let (a, b) = (keypair("A, first board"), keypair("A, second board"));
	let (a_board, a_tx) = credited_board(&mut r, &a, x).await;
	let (b_board, b_tx) = credited_board(&mut r, &b, x).await;
	let n = keypair("A, new leaf of both");
	let (w, nonce) = want_leaf(&n, x, 2 * VALUE);
	let (body, pa) = participation_body(&[&a_board, &b_board], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let (valid, record, round) = validate_new_leaf(&r, &pa, 0, &n, &nonce);
	let st = status(&r, &pa);
	let c = st["round"]["connector_vout"].as_u64().unwrap() as u32;
	let delay = RelativeTime::from_units(st["refund_delay_units"].as_u64().unwrap() as u16).unwrap();
	let mut forfeits = vec![];
	for (k, (held, tx, key)) in [(&a_board, &a_tx, &a), (&b_board, &b_tx, &b)].into_iter().enumerate() {
		let old = held.record.resolve(std::slice::from_ref(tx), &r.policy()).unwrap();
		let margin: u64 = st["inputs"][k]["margin"].as_str().unwrap().parse().unwrap();
		let f = Forfeit::for_refresh(old.leaf, (old.asset, old.value), old.id, &valid, &round, c, delay, margin).unwrap();
		forfeits.push(json!({"leaf_id": held.id.to_string(), "signature": forfeit_sig(&f, key)}));
	}
	let body = json!({"participation_id": hex(&pa), "forfeits": forfeits, "leaves": [auths_json(&valid, &n, created(&record))]});

	// The server behind the gate: the first forfeit through, the second held.
	let gate = SignerGate::start(&r.signer.socket, 1);
	r.config.signer_socket = gate.path.clone();
	r.restart_server().await;
	let ans = r.http.post("forfeit_leaves", &body);
	println!("A's forfeits, the second held back: {} {}", ans.status, ans.json);
	assert_eq!(ans.status, 503, "{}", ans.json);
	let whole = r.server.store.forfeits(&pa, built.round_id).await.unwrap();
	let unsigned = r.server.store.unsigned_forfeits().await.unwrap();
	println!("whole: {:?}; without the operator's half: {:?}", whole.iter().map(|f| LeafId(f.forfeit.leaf_id).to_string()).collect::<Vec<_>>(),
		unsigned.iter().map(|f| LeafId(f.forfeit.leaf_id).to_string()).collect::<Vec<_>>());
	assert_eq!((whole.len(), unsigned.len()), (1, 1), "the step stopped between the two co-signatures");

	// Past the forfeit deadline, the gate still shut.
	common::rounds::past_forfeit_deadline(&r, &pa).await;
	let _ = r.server.forfeits.fill_unsigned().await;
	r.server.rounds.pass().await.unwrap();
	let sa = status(&r, &pa);
	let (sa_board, sb_board) = (leaf_state(&r, &a_board.id).await, leaf_state(&r, &b_board.id).await);
	println!("past the forfeit deadline, the second forfeit still held: A {} | inputs returned {} {} | the boards at the server {} {} | \
		unsigned forfeits {}", sa["state"], sa["inputs"][0]["returned"], sa["inputs"][1]["returned"], sa_board, sb_board,
		r.server.store.unsigned_forfeits().await.unwrap().len());
	assert_eq!(sa["state"], "issued", "not expired while the signer can still sign the rest: {}", sa);
	assert_eq!((sa_board.as_str(), sb_board.as_str()), ("spent", "spent"), "no coin given back while a forfeit of it is whole");
	assert_eq!(r.server.store.unsigned_forfeits().await.unwrap().len(), 1, "the second forfeit stays recorded");

	// The gate opened: the minute task completes the second forfeit, and the
	// next pass releases the participation.
	gate.open();
	let filled = r.server.forfeits.fill_unsigned().await.unwrap();
	r.server.rounds.pass().await.unwrap();
	let sa = status(&r, &pa);
	println!("the gate opened: {} filled in; A {} | its new leaf {:?}", filled, sa["state"], leaf_states(&r, &n));
	assert_eq!(filled, 1);
	assert_eq!(sa["state"], "released", "{}", sa);
	assert_eq!(leaf_states(&r, &n), vec!["live"], "the leaf of both values is credited");
	assert_eq!(r.server.store.forfeits(&pa, built.round_id).await.unwrap().len(), 2, "both forfeits whole");

	// The watcher takes both boards by their forfeits, and claims them.
	let (ida, idb) = (a_board.id.0.to_vec(), b_board.id.0.to_vec());
	common::flow::drive(&r, "both boards taken by their forfeits", 10,
		|l| common::flow::has(l, "claim", &ida) && common::flow::has(l, "claim", &idb)).await;
	common::flow::settle(&r).await;
	let l = common::flow::log(&r).await;
	for (who, id) in [("the first", &ida), ("the second", &idb)] {
		assert!(common::flow::final_of(&l, "forfeit", id) && common::flow::final_of(&l, "claim", id), "{} board's forfeit and claim are final", who);
	}
	println!("both boards taken by their forfeits and claimed; A holds the leaf of both values, once");
}

/// The state of the coin `id` at the server.
async fn leaf_state(r: &Running, id: &LeafId) -> String {
	r.server.store.leaf(&id.0).await.unwrap().map(|l| format!("{:?}", l.state).to_lowercase()).unwrap_or_default()
}

/// R7h F3 (b), a coin given back by an older server while its forfeit stood
/// in the signer's record. A's refresh completes, so the signer holds A's
/// forfeit under the board's salt; the database is then put as an older
/// server's expiry left it: the participation expired, its forfeit dropped,
/// the board live again. A payment out of the board is refused
/// `double_spend`, naming the forfeit: the transfer's record is dropped and
/// the board given back, so the same payment again is refused the same way,
/// never `in_use`, and no coin of the transfer is left behind.
#[tokio::test(flavor = "multi_thread")]
async fn a_spend_refused_for_a_forfeit_drops_its_record() {
	let mut r = start().await;
	let x = r.x;
	let a = keypair("A");
	let (a_board, a_tx) = credited_board(&mut r, &a, x).await;
	let a2 = keypair("A, new");
	let (ans, pa, a2_nonce) = submit(&r, &a_board, &a2, VALUE, 0, None);
	assert_eq!(ans.ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let (new_held, new_valid, _, _) = complete(&r, &pa, &a_board, &a, &a_tx, &a2, &a2_nonce).await;
	let (db, conn) = tokio_postgres::connect(&r.config.database, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(async move {
		let _ = conn.await;
	});
	db.execute("UPDATE participation SET state = 'expired' WHERE participation_id = $1", &[&&pa[..]]).await.unwrap();
	db.execute("DELETE FROM forfeit WHERE participation_id = $1", &[&&pa[..]]).await.unwrap();
	db.execute("UPDATE participation_input SET active = false WHERE participation_id = $1", &[&&pa[..]]).await.unwrap();
	db.execute("UPDATE leaf SET state = 'live', spent_by = NULL WHERE leaf_id = $1", &[&&a_board.id.0[..]]).await.unwrap();
	db.execute("UPDATE leaf SET state = 'expired' WHERE leaf_id = $1", &[&&new_valid.leaf_id.0[..]]).await.unwrap();
	let _ = new_held;
	let a_old = a_board.record.resolve(std::slice::from_ref(&a_tx), &r.policy()).unwrap();
	for attempt in ["first", "second"] {
		let (d_leaf, _) = common::client::new_leaf(&keypair(&format!("D, {}", attempt)));
		let spend = common::client::transfer_body(&[(&a_board, a_old.clone(), VALUE - 2_000)], &[(x, VALUE - 4_000, d_leaf)],
			xonly(&r.s), r.chain);
		let ans = r.http.post("cosign_transfer", &spend);
		let (code, m) = ans.refusal();
		let inputs = db.query("SELECT transfer_id FROM transfer_input WHERE leaf_id = $1", &[&&a_board.id.0[..]]).await.unwrap().len();
		println!("the {} payment out of the board: {} {} | {} | the board at the server {} | its transfer records {}", attempt, ans.status,
			code, m, leaf_state(&r, &a_board.id).await, inputs);
		assert_eq!((ans.status, code.as_str()), (409, "double_spend"), "{}", ans.json);
		assert!(m.contains("already co-signed the forfeit"), "{}", m);
		assert_eq!(leaf_state(&r, &a_board.id).await, "live", "the board is given back");
		assert_eq!(inputs, 0, "the transfer's record is dropped");
	}
}

/// R7i W1: a coin given back by an older server while its forfeit stood in
/// the signer's record, given as a later input. A's refresh of board C
/// completes; the database is then put as an older server's expiry left it.
/// A payment out of good board G, then C, and a swap of another owner's
/// board H against C, are each refused `double_spend`, naming C and the
/// forfeit the signer holds, before the signer signs anything: its record
/// gains no entry, nothing is under the first input's salt, the transfer's
/// record is dropped and both coins given back. G, and then H, pay alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_forfeit_at_a_later_input_signs_nothing_of_the_transfer() {
	let mut r = start().await;
	let x = r.x;
	let a = keypair("W1 A");
	let (c_board, c_tx) = credited_board(&mut r, &a, x).await;
	let g_key = keypair("W1 A, good board");
	let (g_board, g_tx) = credited_board(&mut r, &g_key, x).await;
	let h_key = keypair("W1 H, the swap's other owner");
	let (h_board, h_tx) = credited_board(&mut r, &h_key, x).await;
	let a2 = keypair("W1 A, new");
	let (ans, pa, a2_nonce) = submit(&r, &c_board, &a2, VALUE, 0, None);
	assert_eq!(ans.ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let (_, new_valid, _, _) = complete(&r, &pa, &c_board, &a, &c_tx, &a2, &a2_nonce).await;
	let (db, conn) = tokio_postgres::connect(&r.config.database, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(async move {
		let _ = conn.await;
	});
	db.execute("UPDATE participation SET state = 'expired' WHERE participation_id = $1", &[&&pa[..]]).await.unwrap();
	db.execute("DELETE FROM forfeit WHERE participation_id = $1", &[&&pa[..]]).await.unwrap();
	db.execute("UPDATE participation_input SET active = false WHERE participation_id = $1", &[&&pa[..]]).await.unwrap();
	db.execute("UPDATE leaf SET state = 'live', spent_by = NULL WHERE leaf_id = $1", &[&&c_board.id.0[..]]).await.unwrap();
	db.execute("UPDATE leaf SET state = 'expired' WHERE leaf_id = $1", &[&&new_valid.leaf_id.0[..]]).await.unwrap();
	let old_c = c_board.record.resolve(std::slice::from_ref(&c_tx), &r.policy()).unwrap();
	let old_g = g_board.record.resolve(std::slice::from_ref(&g_tx), &r.policy()).unwrap();
	let old_h = h_board.record.resolve(std::slice::from_ref(&h_tx), &r.policy()).unwrap();
	for (case, first, old_first, first_key) in [("a payment out of G, then C", &g_board, &old_g, "W1 D"), ("a swap of H against C", &h_board, &old_h, "W1 E")] {
		let before = r.signer_entries().await.len();
		let (to_first, _) = common::client::new_leaf(&keypair(&format!("{}, to the first owner", first_key)));
		let (to_a, _) = common::client::new_leaf(&keypair(&format!("{}, to A", first_key)));
		let body = common::client::transfer_body(&[(first, old_first.clone(), VALUE - 2_000), (&c_board, old_c.clone(), VALUE - 2_000)],
			&[(x, VALUE - 3_000, to_first), (x, VALUE - 3_000, to_a)], xonly(&r.s), r.chain);
		let ans = r.http.post("cosign_transfer", &body);
		let (code, m) = ans.refusal();
		let after = r.signer_entries().await;
		let under_first: Vec<String> = after.iter().filter(|e| e.salt == old_first.leaf.salt).map(|e| format!("entry {} {:?}", e.n, e.kind)).collect();
		let records = db.query("SELECT transfer_id FROM transfer_input WHERE leaf_id = $1 OR leaf_id = $2",
			&[&&first.id.0[..], &&c_board.id.0[..]]).await.unwrap().len();
		println!("W1 {}: {} {} | {}", case, ans.status, code, m);
		println!("W1 {}: the signer's entries {} before, {} after; under the first input's salt {:?} | the first at the server {} | C {} | \
			transfer records {}", case, before, after.len(), under_first, leaf_state(&r, &first.id).await, leaf_state(&r, &c_board.id).await,
			records);
		assert_eq!((ans.status, code.as_str()), (409, "double_spend"), "{}", ans.json);
		assert!(m.contains(&c_board.id.to_string()) && m.contains("already co-signed the forfeit"), "{}", m);
		assert!(m.contains(&format!("under salt {} ", hex(&old_c.leaf.salt))), "the refusal names C's salt: {}", m);
		assert_eq!(after.len(), before, "the signer signed nothing of the transfer");
		assert!(under_first.is_empty(), "{:?}", under_first);
		assert_eq!((leaf_state(&r, &first.id).await.as_str(), leaf_state(&r, &c_board.id).await.as_str()), ("live", "live"));
		assert_eq!(records, 0, "the transfer's record is dropped");
		// The first coin pays alone.
		let (to_d, _) = common::client::new_leaf(&keypair(&format!("{}, alone", first_key)));
		let alone = common::client::transfer_body(&[(first, old_first.clone(), VALUE - 2_000)], &[(x, VALUE - 4_000, to_d)], xonly(&r.s), r.chain);
		let paid = r.http.post("cosign_transfer", &alone);
		println!("W1 {}: the first coin alone: {} {}", case, paid.status, &paid.json.to_string()[..paid.json.to_string().len().min(160)]);
		assert_eq!(paid.status, 200, "{}", paid.json);
	}
}

/// R7h F3 (a), and the race it opens: a forfeit completed after its coin's
/// exit delay ran. A's forfeit is recorded while the signer is away; A takes
/// its board home, its conversion in a block and its exit delay run. The
/// signer back, the minute task fills in the operator's half: every forfeit
/// is whole, but A's coin is on the chain, and A could still claim it, so the
/// participation is not released and A's forfeit step returns no preimage.
/// A claims its board; the claim is final: the participation is never
/// released, A holds its board's value and never the new leaf, and the
/// operator pays nothing twice.
#[tokio::test(flavor = "multi_thread")]
async fn a_forfeit_completed_after_its_coins_exit_delay_waits_for_the_claim() {
	use arca_covenant::sign::sign_digest;
	use arca_covenant::spend::FeeSource;
	let mut r = start().await;
	let x = r.x;
	let a = keypair("A");
	let (a_board, a_tx) = credited_board(&mut r, &a, x).await;
	let a2 = keypair("A, new");
	let (ans, pa, a2_nonce) = submit(&r, &a_board, &a2, VALUE, 0, None);
	assert_eq!(ans.ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let (valid, record, round) = validate_new_leaf(&r, &pa, 0, &a2, &a2_nonce);
	let st = status(&r, &pa);
	let old = a_board.record.resolve(std::slice::from_ref(&a_tx), &r.policy()).unwrap();
	let f = forfeit_for(&old, &valid, &round, &st);
	let body = forfeit_body(&pa, a_board.id, forfeit_sig(&f, &a), auths_json(&valid, &a2, created(&record)));
	r.signer.kill();
	assert_eq!(r.http.post("forfeit_leaves", &body).status, 503);

	// A takes its board home: the conversion in a block, the exit delay run.
	let (policy, at) = old.board().unwrap();
	let fee_coin = r.purse.take_coin(x);
	let conv = policy.conversion(at, &FeeSource::Coin { outpoint: fee_coin.0, coin: fee_coin.1.clone(), fee: 3_000,
		change: common::node::op_true() }).unwrap();
	let sig = sign_digest(&a, &conv.sighash(r.chain.genesis_hash()).unwrap(), &common::client::random32());
	let conv = conv.finish(vec![sig.as_ref().to_vec()]);
	r.rt.client().send_raw_transaction(&conv.tx).unwrap();
	r.produce().await;
	r.bury().await;
	let leaf_at = elements::OutPoint::new(conv.tx.txid(), 0);
	advance_mtp(&r, old.leaf.exit_delay.seconds() as u32 + 600).await;
	r.synced().await;
	let claim = common::flow::exit_tx(&r, &old.leaf, leaf_at, x, VALUE, &a);
	assert_eq!(common::flow::verdict(&r, &claim), Ok(()), "A's exit delay has run: A can claim");

	// The signer back: the forfeit is filled in, whole, but not released.
	let genesis = r.rt.client().genesis_hash().unwrap();
	r.signer.restart(&r.s, genesis);
	assert_eq!(r.server.forfeits.fill_unsigned().await.unwrap(), 1);
	r.server.rounds.pass().await.unwrap();
	let sa = status(&r, &pa);
	let again = r.http.post("forfeit_leaves", &body);
	println!("the forfeit whole, A's board leaf on the chain past its exit delay: A {} | A's step again: {} {}", sa["state"], again.status,
		again.json);
	assert_eq!(sa["state"], "issued", "not released while A can still claim its coin: {}", sa);
	assert!(again.json["preimage"].is_null(), "no preimage handed out: {}", again.json);

	// A claims its board, final: never released.
	r.rt.client().send_raw_transaction(&claim).unwrap();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	let sa = status(&r, &pa);
	println!("A's claim {} final: A {} | A's new leaf {:?}", claim.txid(), sa["state"], leaf_states(&r, &a2));
	assert_eq!(sa["state"], "issued");
	assert_eq!(leaf_states(&r, &a2), vec!["pending"], "the new leaf is never credited");
	r.purse.put(fee_coin);
}

/// What a database that lost a spend leaves: the operator's signer holds a
/// spend of `held`'s coin (resting on `base`) under its salt, co-signed at
/// the owner's request, which the database does not know.
async fn signer_holds_a_spend(r: &Running, held: &Held, base: &Transaction) {
	use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
	let c = held.record.resolve(std::slice::from_ref(base), &r.policy()).unwrap();
	let o = arca_covenant::ExplicitOutput::new(c.asset, c.value - 2_000, elements::Script::from(vec![0x51, 7]));
	let m = arca_covenant::message::rebind_message(&r.chain.leaf_constant(&c.leaf.salt), c.asset, c.value, std::slice::from_ref(&o)).unwrap();
	let sig = arca_covenant::sign::sign_digest(&held.key, &m.digest, &[2; 32]);
	let line = json!({
		"op": "rebind", "owner": hex(&xonly(&held.key).serialize()), "owner_sig": hex(sig.as_ref()), "salt": hex(&c.leaf.salt),
		"asset_in": c.asset.to_string(), "value_in": c.value.to_string(), "outputs": [server::signer::WireOutput::from_output(&o)],
	}).to_string();
	let mut s = tokio::net::UnixStream::connect(&r.signer.socket).await.unwrap();
	s.write_all(format!("{}\n", line).as_bytes()).await.unwrap();
	let mut out = String::new();
	BufReader::new(s).read_line(&mut out).await.unwrap();
	let v: Value = serde_json::from_str(&out).unwrap();
	assert!(v["signature"].is_string(), "the signer co-signs the spend: {}", v);
}

/// D59.2: no participation can be stuck. A coin under something the
/// operator's signer already holds under its salt is refused when it is
/// offered, `double_spend`, the refusal naming the coin and what the signer
/// holds: (a) a board an older server gave back while its forfeit stood in
/// the signer's record (the database put as that server's expiry left it),
/// offered again with another board; (b) a board whose spend the signer
/// co-signed and the database lost.
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_under_a_forfeit_or_spend_the_signer_holds_is_refused_when_offered() {
	let mut r = start().await;
	let x = r.x;
	let a = keypair("A");
	let (a_board, a_tx) = credited_board(&mut r, &a, x).await;
	let a2 = keypair("A, new");
	let (ans, pa, a2_nonce) = submit(&r, &a_board, &a2, VALUE, 0, None);
	assert_eq!(ans.ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let (_, new_valid, _, _) = complete(&r, &pa, &a_board, &a, &a_tx, &a2, &a2_nonce).await;
	let (db, conn) = tokio_postgres::connect(&r.config.database, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(async move {
		let _ = conn.await;
	});
	db.execute("UPDATE participation SET state = 'expired' WHERE participation_id = $1", &[&&pa[..]]).await.unwrap();
	db.execute("DELETE FROM forfeit WHERE participation_id = $1", &[&&pa[..]]).await.unwrap();
	db.execute("UPDATE participation_input SET active = false WHERE participation_id = $1", &[&&pa[..]]).await.unwrap();
	db.execute("UPDATE leaf SET state = 'live', spent_by = NULL WHERE leaf_id = $1", &[&&a_board.id.0[..]]).await.unwrap();
	db.execute("UPDATE leaf SET state = 'expired' WHERE leaf_id = $1", &[&&new_valid.leaf_id.0[..]]).await.unwrap();

	// (a) The board given back under its forfeit, offered with board C.
	let c = keypair("A, board C");
	let (c_board, _) = credited_board(&mut r, &c, x).await;
	let n = keypair("A, new leaf of both");
	let (w, _) = want_leaf(&n, x, 2 * VALUE);
	let (body, pa2) = participation_body(&[&a_board, &c_board], &[w], &[], None, xonly(&r.s), r.chain);
	let ans = r.http.post("submit_participation", &body);
	println!("D592 (a) the board given back under its forfeit, offered again with C: {} {}", ans.status, ans.json);
	let st = r.server.store.participation(&pa2).await.unwrap().map(|p| format!("{:?}", p.state));
	println!("D592 (a) the participation at the server: {:?}; C at the server {}", st, leaf_state(&r, &c_board.id).await);

	// (b) A board whose spend the signer co-signed and the database lost.
	let d = keypair("D");
	let (d_board, d_tx) = credited_board(&mut r, &d, x).await;
	signer_holds_a_spend(&r, &d_board, &d_tx).await;
	let d2 = keypair("D, new");
	let (ans_b, pd, _) = submit(&r, &d_board, &d2, VALUE, 0, None);
	println!("D592 (b) the board whose spend the signer holds, offered: {} {}", ans_b.status, ans_b.json);
	let st_b = r.server.store.participation(&pd).await.unwrap().map(|p| format!("{:?}", p.state));
	println!("D592 (b) the participation at the server: {:?}; D at the server {}", st_b, leaf_state(&r, &d_board.id).await);

	let m = refused(ans, 409, "double_spend");
	assert!(m.contains(&a_board.id.to_string()) && m.contains("already co-signed the forfeit"), "{}", m);
	assert!(st.is_none(), "nothing recorded");
	assert_eq!(leaf_state(&r, &c_board.id).await, "live", "C is not taken");
	let m = refused(ans_b, 409, "double_spend");
	assert!(m.contains(&d_board.id.to_string()) && m.contains("already co-signed the spend"), "{}", m);
	assert!(st_b.is_none(), "nothing recorded");
}

/// D59.2, a participation stuck from old state is released on the watcher's
/// claim. A gives up boards A and C for one leaf of both; the round is
/// final; then the signer is found to hold a spend under A's salt that the
/// database lost (old state: the participation was taken before any check
/// asked the signer). A's forfeit step: A's forfeit is refused for good
/// (`already_signed`), C's is filled in whole by the minute task: neither
/// released nor expired, past the forfeit deadline too. C's owner takes its
/// board home; the watcher answers with C's forfeit and claims it, which
/// puts the preimage out: the next pass releases the participation and
/// credits its leaf.
#[tokio::test(flavor = "multi_thread")]
async fn a_participation_stuck_from_old_state_is_released_on_the_watchers_claim() {
	use arca_covenant::sign::sign_digest;
	use arca_covenant::spend::FeeSource;
	let mut r = start().await;
	let x = r.x;
	let (a, c) = (keypair("A, stuck"), keypair("C, stuck"));
	let (a_board, a_tx) = credited_board(&mut r, &a, x).await;
	let (c_board, c_tx) = credited_board(&mut r, &c, x).await;
	let n = keypair("A, new leaf of both, stuck");
	let (w, nonce) = want_leaf(&n, x, 2 * VALUE);
	let (body, pa) = participation_body(&[&a_board, &c_board], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	signer_holds_a_spend(&r, &a_board, &a_tx).await;
	let (valid, record, round) = validate_new_leaf(&r, &pa, 0, &n, &nonce);
	let st = status(&r, &pa);
	let cv = st["round"]["connector_vout"].as_u64().unwrap() as u32;
	let delay = RelativeTime::from_units(st["refund_delay_units"].as_u64().unwrap() as u16).unwrap();
	let mut forfeits = vec![];
	for (k, (held, tx, key)) in [(&a_board, &a_tx, &a), (&c_board, &c_tx, &c)].into_iter().enumerate() {
		let old = held.record.resolve(std::slice::from_ref(tx), &r.policy()).unwrap();
		let margin: u64 = st["inputs"][k]["margin"].as_str().unwrap().parse().unwrap();
		let f = Forfeit::for_refresh(old.leaf, (old.asset, old.value), old.id, &valid, &round, cv, delay, margin).unwrap();
		forfeits.push(json!({"leaf_id": held.id.to_string(), "signature": forfeit_sig(&f, key)}));
	}
	let step = json!({"participation_id": hex(&pa), "forfeits": forfeits, "leaves": [auths_json(&valid, &n, created(&record))]});
	let ans = r.http.post("forfeit_leaves", &step);
	println!("D592S A's forfeit step: {} {}", ans.status, ans.json);
	let filled = r.server.forfeits.fill_unsigned().await.unwrap();
	common::rounds::past_forfeit_deadline(&r, &pa).await;
	let _ = r.server.forfeits.fill_unsigned().await;
	r.server.rounds.pass().await.unwrap();
	let whole = r.server.store.forfeits(&pa, built.round_id).await.unwrap().len();
	let unsigned = r.server.store.unsigned_forfeits().await.unwrap().len();
	let sa = status(&r, &pa);
	println!("D592S {} filled in; past the forfeit deadline: whole {} | without the operator's half {} | A {} | the new leaf {:?}", filled,
		whole, unsigned, sa["state"], leaf_states(&r, &n));
	assert_eq!((whole, unsigned), (1, 1), "C's forfeit whole, A's refused for good");
	assert_eq!(sa["state"], "issued", "stuck: neither released nor expired");

	// C's owner takes its board home: the conversion in a block.
	let old_c = c_board.record.resolve(std::slice::from_ref(&c_tx), &r.policy()).unwrap();
	let (policy, at) = old_c.board().unwrap();
	let fee_coin = r.purse.take_coin(x);
	let conv = policy.conversion(at, &FeeSource::Coin { outpoint: fee_coin.0, coin: fee_coin.1.clone(), fee: 3_000,
		change: common::node::op_true() }).unwrap();
	let sig = sign_digest(&c, &conv.sighash(r.chain.genesis_hash()).unwrap(), &common::client::random32());
	let conv = conv.finish(vec![sig.as_ref().to_vec()]);
	r.rt.client().send_raw_transaction(&conv.tx).unwrap();
	r.produce().await;
	r.bury().await;
	let cid = c_board.id.0.to_vec();
	common::flow::drive(&r, "C's forfeit claimed", 12, |l| common::flow::has(l, "claim", &cid)).await;
	common::flow::settle(&r).await;
	r.server.rounds.pass().await.unwrap();
	let sa = status(&r, &pa);
	println!("D592S C's board taken by its forfeit and claimed: A {} | the new leaf {:?}", sa["state"], leaf_states(&r, &n));
	assert_eq!(sa["state"], "released", "released on the watcher's claim: {}", sa);
	assert_eq!(leaf_states(&r, &n), vec!["live"], "its leaf credited");
	r.purse.put(fee_coin);
}
