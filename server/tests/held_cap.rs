//! The in-flight cap counts the refreshes of a round held for its
//! forfeits (`[batches] no_sweep`): a refresh judged while an earlier round
//! of its asset is built and held waits as it would once that round is out,
//! so the rounds of one forfeit window cannot together front past the cap.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::AssetId;
use serde_json::Value;

use common::client::{participation_body, want_leaf, Held};
use common::flow::{refresh, Coin};
use common::keys::{keypair, xonly};
use common::rounds::{credited_board, hand_over_held, status, VALUE};
use common::running::Running;

async fn start(cap: u64) -> Running {
	let mut r = Running::start_plain(|c, _| {
		c.batches.no_sweep = true;
		c.batches.holder_batches = Some(0);
		c.assets[0].in_flight_cap = Some(cap.to_string());
	}).await;
	let x = r.x;
	for _ in 0..4 {
		r.fund_wallet_in(x, 50_000_000).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r
}

fn submit(r: &Running, coin: &Held, tag: &str) -> [u8; 32] {
	let (w, _) = want_leaf(&keypair(tag), r.x, VALUE);
	let (body, id) = participation_body(&[coin], &[w], &[], None, xonly(&r.s), r.chain);
	let a = r.http.post("submit_participation", &body).ok();
	assert_eq!(a["state"], "pending", "{}", a);
	id
}

fn in_flight(r: &Running, asset: AssetId) -> u64 {
	let p: Value = r.http.get("chain").json["pool"][asset.to_string()].clone();
	p["in_flight"].as_str().unwrap_or("0").parse().unwrap()
}

/// Two batch leaves, each on a node of its own, against a cap of one and a
/// half coins. Refreshing L0 opens its node, one coin in flight, from the
/// moment its round is built and held for its forfeits: L1's refresh,
/// judged then, waits, and only L0's round goes out.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_beside_a_held_round_is_judged_with_it() {
	let cap = VALUE * 3 / 2;
	let mut r = start(cap).await;
	let x = r.x;
	let leaves = two_leaves(&mut r, "H").await;
	assert_eq!(in_flight(&r, x), 0);
	let id0 = submit(&r, &leaves[0].held, "H L0 new");
	let b0 = r.server.rounds.run_round().await.unwrap().expect("L0's round");
	assert!(b0.broadcast.starts_with("held"), "L0's round is held for its forfeits: {}", b0.broadcast);
	println!("L0's round {} held; in flight {} of a cap of {}", b0.tx.txid(), in_flight(&r, x), cap);
	assert_eq!(in_flight(&r, x), VALUE, "L0's refresh counts in flight while its round is held");
	let id1 = submit(&r, &leaves[1].held, "H L1 new");
	let b1 = r.server.rounds.run_round().await.unwrap();
	let st = status(&r, &id1);
	println!("L1's refresh beside it: round {:?}; state {}; waiting {}", b1.as_ref().map(|b| b.tx.txid()), st["state"], st["waiting"]);
	assert!(b1.is_none(), "no second round");
	assert_eq!(st["state"], "pending");
	assert!(st["waiting"].as_str().unwrap().contains("1000000 of a cap of 1500000 in flight; this refresh would take it to 2000000"),
		"{}", st["waiting"]);
	assert_eq!(hand_over_held(&r, &b0.tx.txid()).await, 1);
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	let f = in_flight(&r, x);
	println!("L0's round out: in flight {} against a cap of {}; L0 {}, L1 {}", f, cap, status(&r, &id0)["state"], status(&r, &id1)["state"]);
	assert_eq!(f, VALUE, "one coin in flight, within the cap");
	assert_eq!(status(&r, &id1)["state"], "pending");
}

/// Control: the same, but L0's round goes out before L1's refresh is judged.
/// The cap then holds L1's refresh.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_beside_a_round_out_waits() {
	let cap = VALUE * 3 / 2;
	let mut r = start(cap).await;
	let x = r.x;
	let leaves = two_leaves(&mut r, "HC").await;
	submit(&r, &leaves[0].held, "HC L0 new");
	let b = r.server.rounds.run_round().await.unwrap().expect("the first round");
	hand_over_held(&r, &b.tx.txid()).await;
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	println!("control: L0's round out; in flight {} of a cap of {}", in_flight(&r, x), cap);
	let id1 = submit(&r, &leaves[1].held, "HC L1 new");
	let b1 = r.server.rounds.run_round().await.unwrap();
	let st = status(&r, &id1);
	println!("control: L1's refresh: round {:?}; state {}; waiting {}", b1.map(|b| b.tx.txid()), st["state"], st["waiting"]);
	assert_eq!(st["state"], "pending");
}

/// Two boards refreshed, each in a round of its own, into batch leaves.
async fn two_leaves(r: &mut Running, tag: &str) -> Vec<Coin> {
	let x = r.x;
	let mut out = vec![];
	for j in 0..2 {
		let kb = keypair(&format!("{} B{} board", tag, j));
		let (h, tx) = credited_board(r, &kb, x).await;
		let b = Coin { held: h, bases: vec![tx] };
		let k = keypair(&format!("{} L{}", tag, j));
		out.push(refresh(r, &[(&b, &k)]).await.remove(0).new);
	}
	out
}
