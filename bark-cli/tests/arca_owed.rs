//! A swept coin is repaid, with the `arca` binary against a whole Arca server
//! on an anchored proof-of-stake regtest chain whose operator charges a
//! refresh fee of 5,000 parts per million. A boards X, refreshes it into a
//! round leaf and its device is lost. The batch expires, is released and,
//! after the notice, swept, with A's coin in it: the server owes A the coin
//! less the late-refresh fee. A wallet restored from A's mnemonic, never
//! online before, finds what is owed at its first sync, claims it by itself
//! and counts it as returning in its balance. That wallet is lost as well: a
//! third, restored from the same mnemonic, recognises the claim as its own,
//! and once the repayment's round is final its next sync holds a new coin of
//! exactly the coin's value less the fee, and nothing is returning any more.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::Script;
use serde_json::Value;

use common::cli::Arca;
use common::running::Running;
use server::store::RoundState;

const HOUR: u32 = 3_600;
const PPM: u64 = 5_000;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

fn create_args<'a>(server: &'a str, node: &'a str) -> Vec<&'a str> {
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

/// Lets the watcher pass, then a block, buried, and the nursery follow.
async fn settle(r: &Running) {
	r.server.watcher.pass().await.unwrap();
	tokio::time::sleep(std::time::Duration::from_millis(300)).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.server.nursery.pass().await.unwrap();
	r.server.watcher.pass().await.unwrap();
	tokio::time::sleep(std::time::Duration::from_millis(300)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_coin_swept_while_its_holder_was_away_is_claimed_after_a_restore_and_repaid() {
	// What follows is the sweep of A's live coin and its repayment: the
	// operator does not take it on the chain at its batch's release first.
	let mut r = Running::start_with(|c, _, _| {
		c.fees.refresh_ppm = PPM;
		c.watcher.unroll_at_release = false;
	}).await;
	let (url, node) = (r.url(), r.node_url());
	let x = r.x.to_string();

	// A boards X and refreshes it into a round leaf.
	let a = Arca::new("owed A");
	a.ok(&create_args(&url, &node));
	r.pay_to(script(&a.ok(&["address"])), r.x, 5_000_000);
	r.produce().await;
	a.ok(&["board", &x, "2000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("A's board to be credited", || a.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	let board = a.ok(&["coins"])[0]["leaf_id"].as_str().unwrap().to_string();
	a.ok(&["participate", "--leaf", &board, "--max-fee-ppm", "1000000"]);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	let s = a.ok(&["sync"]);
	let leaf = s["participations"][0]["new_leaves"][0].clone();
	let leaf_id = leaf["leaf_id"].as_str().expect("the refresh's leaf").to_string();
	let value: u64 = leaf["value"].as_str().unwrap().parse().unwrap();
	let expiry = leaf["expiry"].as_u64().unwrap() as u32;
	println!("A holds {} = {} of X, expiring at {}", leaf_id, value, expiry);
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap();
	drop(a);

	// A is away: the batch expires, is released and, after the notice, swept.
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, expiry.saturating_sub(now) + HOUR));
	settle(&r).await;
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 37 * HOUR));
	let mut entry = None;
	for _ in 0..10 {
		settle(&r).await;
		let id = leaf_id.parse::<arca_covenant::LeafId>().unwrap().0;
		if let Some(e) = r.server.store.owed_entry(&id).await.unwrap() {
			entry = Some(e);
			break;
		}
	}
	let entry = entry.expect("A's coin is owed once the sweep is final");
	let fee = (value as u128 * PPM as u128).div_ceil(1_000_000) as u64;
	println!("the server owes A {} of X for {}: {} less the late-refresh fee {}", entry.owed(), leaf_id, value, entry.fee);
	assert_eq!((entry.value, entry.fee), (value, fee), "the fee is the refresh fee at its full charge");

	// A2, restored from A's mnemonic, claims at its first sync, by itself.
	let a2 = Arca::new("owed A2");
	let mut args = create_args(&url, &node);
	args.extend(["--mnemonic", mnemonic.trim()]);
	let made = a2.ok(&args);
	println!("A2's restore: not recovered {} | sync's owed {}", made["restore"]["not_recovered"], made["restore"]["sync"]["owed"]);
	let s = a2.ok(&["sync"]);
	println!("A2's sync: owed {}", s["owed"]);
	let owed = a2.ok(&["owed"]);
	println!("A2's owed: {}", owed);
	assert_eq!(owed[0]["leaf_id"], leaf_id.as_str());
	assert_eq!(owed[0]["state"], "claimed", "the restored wallet claimed by itself: {}", owed);
	let b = a2.ok(&["balance"]);
	println!("A2's balance while it returns: {}", b);
	assert_eq!(b["arca"][&x]["returning"], (value - fee).to_string(), "what is owed is returning");
	let onchain: u64 = b["sequentia_onchain"][&x].as_str().unwrap_or("0").parse().unwrap();
	let held: u64 = b["held"][&x].as_str().unwrap().parse().unwrap();
	assert_eq!(held - onchain, value - fee, "and counted in what is held, off the chain");

	// A2 is lost too, its claim made: A3, restored from the same mnemonic,
	// recognises the claim as its own and takes it up.
	drop(a2);
	let a2 = Arca::new("owed A3");
	let claimed_by = owed[0]["participation_id"].as_str().unwrap().to_string();
	let made = a2.ok(&args);
	println!("A3's restore, its sync's owed: {}", made["restore"]["sync"]["owed"]);
	let parts = a2.ok(&["participations"]);
	println!("A3's participations: {}", parts);
	assert!(parts.as_array().unwrap().iter().any(|p| p["participation"] == claimed_by.as_str()), "A3 took up A2's claim {}", claimed_by);
	assert_eq!(a2.ok(&["balance"])["arca"][&x]["returning"], (value - fee).to_string());

	// The repayment's round, final: A3's next sync holds the new coin.
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	let s = a2.ok(&["sync"]);
	println!("A2's sync after the repayment's round: participations {}", s["participations"]);
	let live: Vec<Value> = a2.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == x.as_str()).cloned().collect();
	assert_eq!(live.len(), 1, "{:?}", live);
	assert_eq!(live[0]["value"], (value - fee).to_string(), "the new coin holds the coin's value less the fee, exactly");
	assert_ne!(live[0]["leaf_id"], leaf_id.as_str());
	println!("A2 holds {} = {} of X, in round {}", live[0]["leaf_id"], live[0]["value"], built.tx.txid());
	r.server.watcher.pass().await.unwrap();
	let owed = a2.ok(&["owed"]);
	assert_eq!(owed[0]["state"], "repaid", "{}", owed);
	let b = a2.ok(&["balance"]);
	assert!(b["arca"][&x].get("returning").is_none(), "nothing returning once repaid: {}", b);
	let onchain: u64 = b["sequentia_onchain"][&x].as_str().unwrap_or("0").parse().unwrap();
	let held: u64 = b["held"][&x].as_str().unwrap().parse().unwrap();
	assert_eq!(held - onchain, value - fee, "held off the chain: the new coin alone");
}
