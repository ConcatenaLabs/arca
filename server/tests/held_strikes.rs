//! Held rounds that a participant drops out of (`[batches] no_sweep`, and
//! fill rounds): nobody is held back by the same participant twice.
//!
//! - After a drop, the participations that handed their forfeits over run
//!   again at once, alone: a newcomer that arrived meanwhile waits for the
//!   next round.
//! - The coins of a participation voided for its missing forfeits are
//!   struck: given up again, they wait (the window, doubling with each
//!   strike) and then run only in a round of their own. A coin paid on out of
//!   round from a struck coin is struck with it. A round that goes out with
//!   them clears the strike.
//! - A wallet that hands over its forfeits only after broadcast is refused
//!   when it submits, in words, by an operator building batches without a
//!   sweep, and still taken by one with a sweep.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::Txid;
use serde_json::Value;

use common::client::{new_leaf, participation_body, transfer_body, unhex, want_leaf, Held};
use common::keys::{keypair, xonly};
use common::rounds::{advance_mtp, credited_board, mtp, status, VALUE};
use common::running::Running;
use server::store::RoundState;

async fn start() -> Running {
	let mut r = Running::start_plain(|c, _| {
		c.batches.no_sweep = true;
		c.batches.holder_batches = Some(0);
	}).await;
	let x = r.x;
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r
}

/// `coin` given up for one leaf of `value` under `key`: its id.
fn submit(r: &Running, coin: &Held, key: &Keypair, value: u64) -> [u8; 32] {
	let (w, _) = want_leaf(key, r.x, value);
	let (body, id) = participation_body(&[coin], &[w], &[], None, xonly(&r.s), r.chain);
	let a = r.http.post("submit_participation", &body).ok();
	assert_eq!(a["state"], "pending", "{}", a);
	id
}

/// The participations of the round `txid`.
async fn members(r: &Running, txid: &Txid) -> Vec<[u8; 32]> {
	let row = r.server.store.round_by_txid(&txid.to_byte_array()).await.unwrap().unwrap();
	r.server.store.round_participations(row.round_id).await.unwrap()
}

async fn state_of(r: &Running, txid: &Txid) -> RoundState {
	r.server.store.round_by_txid(&txid.to_byte_array()).await.unwrap().unwrap().state
}

/// Hands over `id`'s forfeits against its held round.
async fn answer(r: &Running, id: &[u8; 32]) {
	let m = common::client::made(id).unwrap();
	let done = common::rounds::hand_over(r, id, &m).await;
	assert_eq!(done["state"], "issued", "{}", done);
}

/// Lets the forfeit window (600 s) pass and runs a pass over the rounds.
async fn window_passes(r: &Running) {
	advance_mtp(r, 700).await;
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
}

fn reason(v: &Value, key: &str) -> String {
	v[key].as_str().unwrap_or("").to_string()
}

/// A hostile B joins with the same coin again and again and never hands its
/// forfeit over. Each cycle a new honest participant refreshes too. Every
/// honest refresh goes out, and B is never again in a round with anyone.
#[tokio::test(flavor = "multi_thread")]
async fn a_participant_that_drops_out_holds_back_nobody_twice() {
	let mut r = start().await;
	let x = r.x;
	let kb = keypair("B board");
	let (b, _) = credited_board(&mut r, &kb, x).await;
	let mut honest_out = 0;
	let mut b_rounds_alone = 0;
	let mut idb = submit(&r, &b, &keypair("B 0"), VALUE);
	let mut prev_until: Option<u32> = None;
	let mut prev_wait: Option<u32> = None;
	for cycle in 0..4 {
		let ka = keypair(&format!("A{} board", cycle));
		let (a, _) = credited_board(&mut r, &ka, x).await;
		let ida = submit(&r, &a, &keypair(&format!("A{} new", cycle)), VALUE);

		let built = r.server.rounds.run_round().await.unwrap().expect("a round");
		let txid = built.tx.txid();
		let ids = members(&r, &txid).await;
		println!("cycle {}: round {} with {} participation(s), B in it: {}", cycle, txid, ids.len(), ids.contains(&idb));
		assert!(built.broadcast.starts_with("held"));
		assert!(ids.contains(&ida));
		if cycle == 0 {
			// B has not dropped out yet: it shares the first round.
			assert!(ids.contains(&idb));
			answer(&r, &ida).await;
			r.server.rounds.pass().await.unwrap();
			window_passes(&r).await;
			assert_eq!(state_of(&r, &txid).await, RoundState::Lost);
			let st = status(&r, &idb);
			println!("cycle 0: B {}: {}", st["state"], reason(&st, "void_reason"));
			assert_eq!(st["state"], "void");
			assert!(reason(&st, "void_reason").contains("run again only in a round of their own"), "{}", st);
			assert_eq!(status(&r, &ida)["state"], "pending");
			// B submits again at once, and a newcomer N arrives.
			idb = submit(&r, &b, &keypair("B 1"), VALUE);
			let kn = keypair("N board");
			let (n, _) = credited_board(&mut r, &kn, x).await;
			let idn = submit(&r, &n, &keypair("N new"), VALUE);
			// The re-run goes first, alone: neither B nor N joins it.
			let again = r.server.rounds.run_round().await.unwrap().expect("A's round again");
			let ids = members(&r, &again.tx.txid()).await;
			println!("cycle 0: rebuilt round {} with {} participation(s): A {}, B {}, N {}", again.tx.txid(), ids.len(),
				ids.contains(&ida), ids.contains(&idb), ids.contains(&idn));
			assert_eq!(ids, vec![ida], "the answering participation alone");
			let stb = status(&r, &idb);
			println!("cycle 0: B waits: {}", reason(&stb, "waiting"));
			assert_eq!(stb["state"], "pending");
			assert!(reason(&stb, "waiting").contains("a round of their own"), "{}", stb);
			answer(&r, &ida).await;
			r.server.rounds.pass().await.unwrap();
			assert_eq!(state_of(&r, &again.tx.txid()).await, RoundState::Broadcast, "A's refresh goes out");
			honest_out += 1;
			// N runs in the next round, without B.
			let next = r.server.rounds.run_round().await.unwrap().expect("N's round");
			let ids = members(&r, &next.tx.txid()).await;
			assert_eq!(ids, vec![idn]);
			answer(&r, &idn).await;
			r.server.rounds.pass().await.unwrap();
			assert_eq!(state_of(&r, &next.tx.txid()).await, RoundState::Broadcast, "N's refresh goes out");
			honest_out += 1;
			r.produce().await;
			r.bury().await;
			r.synced().await;
			continue;
		}
		// From the first drop on, B never shares a round.
		assert!(!ids.contains(&idb), "B is never in a round with others");
		answer(&r, &ida).await;
		r.server.rounds.pass().await.unwrap();
		assert_eq!(state_of(&r, &txid).await, RoundState::Broadcast, "cycle {}: the honest refresh goes out", cycle);
		honest_out += 1;
		// B's wait is over: it runs alone, and drops out again.
		let mut st = status(&r, &idb);
		if st["state"] == "pending" {
			let until: u32 = reason(&st, "waiting").split("median time ").nth(1).and_then(|s| s.split(':').next())
				.and_then(|s| s.parse().ok()).expect("the wait names its end");
			let now = mtp(&r).to_consensus_u32();
			let wait = until.saturating_sub(now.min(until));
			println!("cycle {}: B waits until {} ({} s from now)", cycle, until, wait);
			if let (Some(pu), Some(pw)) = (prev_until, prev_wait) {
				assert!(until > pu, "each strike waits longer");
				let _ = pw;
			}
			prev_until = Some(until);
			prev_wait = Some(wait);
			advance_mtp(&r, wait + 1).await;
			r.synced().await;
		}
		let solo = r.server.rounds.run_round().await.unwrap().expect("B's round of its own");
		let ids = members(&r, &solo.tx.txid()).await;
		println!("cycle {}: B's round {} alone: {:?}", cycle, solo.tx.txid(), ids.len());
		assert_eq!(ids, vec![idb], "B runs alone");
		b_rounds_alone += 1;
		window_passes(&r).await;
		assert_eq!(state_of(&r, &solo.tx.txid()).await, RoundState::Lost);
		st = status(&r, &idb);
		assert_eq!(st["state"], "void");
		println!("cycle {}: B void again: {}", cycle, reason(&st, "void_reason"));
		idb = submit(&r, &b, &keypair(&format!("B {}", cycle + 1)), VALUE);
		r.produce().await;
		r.bury().await;
		r.synced().await;
	}
	// The waits doubled: the strike count is the number of drops.
	let strikes = r.server.store.strike_of(&[b.id.0]).await.unwrap().expect("B's coin is struck");
	println!("{} honest refreshes out in {} cycles; B ran alone {} times; B's coin struck {} times, waiting until {}", honest_out, 4,
		b_rounds_alone, strikes.0, strikes.1);
	assert_eq!(honest_out, 5);
	assert_eq!(strikes.0, 1 + b_rounds_alone);
	assert_eq!(b_rounds_alone, 3);
}

/// A struck coin that answers in its round of its own goes out, and its
/// strike is cleared; one paid on out of round from a struck coin is struck
/// with it.
#[tokio::test(flavor = "multi_thread")]
async fn a_struck_coin_runs_alone_and_its_strike_ends_when_it_answers() {
	let mut r = start().await;
	let (x, s) = (r.x, xonly(&r.s));
	let (kb, kc) = (keypair("B board"), keypair("C board"));
	let (b, btx) = credited_board(&mut r, &kb, x).await;
	let (c, _) = credited_board(&mut r, &kc, x).await;
	// B and C both drop out of one round.
	let idb = submit(&r, &b, &keypair("B 1"), VALUE);
	let idc = submit(&r, &c, &keypair("C 1"), VALUE);
	let built = r.server.rounds.run_round().await.unwrap().expect("a round");
	assert_eq!(members(&r, &built.tx.txid()).await.len(), 2);
	window_passes(&r).await;
	assert_eq!(status(&r, &idb)["state"], "void");
	assert_eq!(status(&r, &idc)["state"], "void");

	// B pays its coin on out of round to D: D's coin rests on B's struck board.
	let kd = keypair("D");
	let valid = b.record.resolve(std::slice::from_ref(&btx), &r.policy()).unwrap();
	let (leaf, d_nonce) = new_leaf(&kd);
	let paid = r.http.post("cosign_transfer", &transfer_body(&[(&b, valid, VALUE - 2_000)], &[(x, VALUE - 4_000, leaf)], s, r.chain)).ok();
	let d_record = arca_covenant::CoinRecord::from_bytes(&unhex(paid["outputs"][0]["record"].as_str().unwrap())).unwrap();
	let d_id = d_record.validate(std::slice::from_ref(&btx), &r.policy(), &xonly(&kd), &d_nonce).unwrap().id;
	let d = Held { key: kd, nonce: d_nonce, id: d_id, record: d_record };
	let idd = submit(&r, &d, &keypair("D new"), VALUE - 4_000);
	assert!(r.server.rounds.run_round().await.unwrap().is_none(), "nothing runs while the strikes wait");
	let std = status(&r, &idd);
	println!("D, paid on from B's struck coin: {} — {}", std["state"], reason(&std, "waiting"));
	assert!(reason(&std, "waiting").contains("a round of their own"), "{}", std);

	// C gives its coin up again, waits, and runs alone, answering this time.
	let idc2 = submit(&r, &c, &keypair("C 2"), VALUE);
	// Two rounds held at once take two coins of the operator's wallet.
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	advance_mtp(&r, 700).await;
	r.bury().await;
	r.synced().await;
	let mut alone = vec![];
	for _ in 0..2 {
		let Some(solo) = r.server.rounds.run_round().await.unwrap() else {
			panic!("no round of its own: C {}, D {}", status(&r, &idc2), status(&r, &idd));
		};
		let ids = members(&r, &solo.tx.txid()).await;
		assert_eq!(ids.len(), 1, "alone");
		alone.push((ids[0], solo.tx.txid()));
	}
	let (_, c_round) = alone.iter().find(|(id, _)| *id == idc2).copied().expect("C's round of its own");
	assert!(alone.iter().any(|(id, _)| *id == idd), "D runs alone too");
	answer(&r, &idc2).await;
	r.server.rounds.pass().await.unwrap();
	assert_eq!(state_of(&r, &c_round).await, RoundState::Broadcast, "C's refresh goes out");
	assert_eq!(r.server.store.strike_of(&[c.id.0]).await.unwrap(), None, "C's strike is cleared");
	assert!(r.server.store.strike_of(&[b.id.0]).await.unwrap().is_some(), "B's stays");
	r.produce().await;
	r.bury().await;
	common::rounds::round_state(&r, &c_round, RoundState::Final).await;
	println!("C answered alone: round {} out, strike cleared; D's round of its own stands apart", c_round);
}

/// A wallet that hands over its forfeits only after broadcast says nothing
/// of `forfeits_before_broadcast`: refused in words where batches have no
/// sweep, its coin untouched; taken where they have one.
#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_that_forfeits_after_broadcast_is_refused_in_words_and_loses_nothing() {
	let mut r = start().await;
	let x = r.x;
	let info = r.http.get("info").ok();
	assert_eq!(info["participations"]["forfeits_before_broadcast"], true);
	let ka = keypair("A board");
	let (a, _) = credited_board(&mut r, &ka, x).await;
	let (w, _) = want_leaf(&keypair("A new"), x, VALUE);
	let (mut body, _) = participation_body(&[&a], &[w], &[], None, xonly(&r.s), r.chain);
	body["forfeits_before_broadcast"] = Value::Bool(false);
	let ans = r.http.post("submit_participation", &body);
	let (code, msg) = ans.refusal();
	println!("an older wallet's refresh: {} {}: {}", ans.status, code, msg);
	assert_eq!((ans.status, code.as_str()), (422, "forfeits_after_broadcast"));
	assert!(msg.contains("update the wallet") && msg.contains("Nothing was taken"), "{}", msg);
	assert_eq!(r.server.store.leaf(&a.id.0).await.unwrap().unwrap().state, server::store::LeafState::Live);
	// The same wallet, flag and all, is taken by an operator with a sweep.
	let mut s = common::rounds::start().await;
	let sx = s.x;
	let (a2, _) = credited_board(&mut s, &keypair("A2 board"), sx).await;
	let (w, _) = want_leaf(&keypair("A2 new"), s.x, VALUE);
	let (mut body, _) = participation_body(&[&a2], &[w], &[], None, xonly(&s.s), s.chain);
	body["forfeits_before_broadcast"] = Value::Bool(false);
	let ans = s.http.post("submit_participation", &body);
	println!("the same, to an operator with a sweep: {} {}", ans.status, ans.json["state"]);
	assert_eq!(ans.ok()["state"], "pending");
}
