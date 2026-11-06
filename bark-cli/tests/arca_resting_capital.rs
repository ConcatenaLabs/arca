//! What a maker's resting desk has the operator front, at the shape the
//! testnet's leaf maker runs: a ladder of orders resting in the tree, each
//! cancelled and rested again as the price moves, from a wallet whose other
//! coins of the asset are large ones.
//!
//! The operator fronts every coin a round makes until the coins given up for
//! it come back, and counts that against the asset's in-flight cap. Resting
//! an order gives up coins for an `order-3` leaf and a change leaf, so a
//! rest from the wallet's largest coin has the operator front the whole of
//! it again, change included, at every level and every time the level is
//! rested. The wallet gives up the coins that leave the least change, and
//! the desk rests a cancelled level again at what its coin came back with
//! (the order's value less the cancel's fee): so the level is rested from
//! that coin alone, never from the large coin.
//!
//! The maker holds one coin of 2,000,000,000 X, refreshed into a round's leaf.
//! It rests four levels (100,000,000 to 274,400,000 X: a cancel's fee is a few
//! millionths of a level, as on the testnet), one round each, then three
//! times cancels the four and rests each again, one round each. What each rest gives up, and what
//! is in flight after each pass, is printed and checked: no rest after the
//! first pass leaves change. Last, a merge that names the orders'
//! coins (as the testnet's leaf maker's did) ends every order, and the
//! ladder is rested again whole.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use serde_json::{json, Value};

use elements::hashes::Hash;
use common::cli::Arca;
use common::running::Running;
use server::server::AssetSection;
use server::store::RoundState;

fn create_args<'a>(server: &'a str, node: &'a str) -> Vec<&'a str> {
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

/// Runs the operator's rounds until none waits: each held for its forfeits,
/// which the maker's `sync` hands over, broadcast, made final, and the
/// maker's `sync` after takes its leaves and sends its releases.
async fn rounds(r: &mut Running, maker: &Arca) {
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	assert!(!built.is_empty(), "a round");
	maker.ok(&["sync"]);
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	maker.ok(&["sync"]);
	maker.ok(&["sync"]);
}

/// What is in flight of `asset` now, by the operator's own count.
async fn in_flight(r: &Running, asset: elements::AssetId) -> u64 {
	r.server.store.in_flight().await.unwrap().get(&asset.into_inner().to_byte_array()).copied().unwrap_or(0)
}

/// Rests `amount` of X for Y at 2/1, quoted then shown, and runs its round:
/// the order once published, and what the rest gave up (its coins' value).
async fn rest(r: &mut Running, maker: &Arca, amount: u64) -> (String, u64, u64) {
	let (x, y) = (r.x, r.y);
	let args = |extra: &[&str]| -> Vec<String> {
		let mut v: Vec<String> = ["order", "rest", "--sell", &x.to_string(), "--amount", &amount.to_string(), "--for", &y.to_string(),
			"--rate-num", "2", "--rate-den", "1", "--min-lot", &(amount / 4).to_string(), "--expires-in-hours", "720"]
			.iter().map(|s| s.to_string()).collect();
		v.extend(extra.iter().map(|s| s.to_string()));
		v
	};
	let q = maker.ok(&args(&["--quote"]).iter().map(|s| s.as_str()).collect::<Vec<_>>());
	let shown = q.to_string();
	let rested = maker.ok(&args(&["--shown", &shown]).iter().map(|s| s.as_str()).collect::<Vec<_>>());
	assert_eq!(rested["state"], "pending", "{}", rested);
	let fee: u64 = rested["fee"]["amount"].as_str().unwrap().parse().unwrap();
	let change: u64 = rested["change"].as_str().unwrap().parse().unwrap();
	let given = amount + fee + change;
	rounds(r, maker).await;
	let view = maker.ok(&["order", "resting"]);
	let mine = view["orders"].as_array().unwrap().iter().find(|o| o["rested_by"] == rested["order"]).unwrap().clone();
	assert_eq!(mine["state"], "published", "{}", view);
	assert_eq!(mine["operator"]["value"], json!(amount.to_string()));
	(mine["order"].as_str().unwrap().to_string(), given, change)
}

/// Cancels `order`, as quoted: what its coin comes back with (its value less
/// the cancel's fee).
fn cancel(maker: &Arca, order: &str) -> u64 {
	let q = maker.ok(&["order", "cancel-resting", order, "--quote"]);
	let c = maker.ok(&["order", "cancel-resting", order, "--shown", &q.to_string()]);
	assert_eq!(c["state"], "cancelled", "{}", c);
	q["gets"]["amount"].as_str().unwrap().parse().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ladder_rested_again_after_each_cancel_gives_up_its_cancelled_coins_not_the_largest() {
	let mut r = Running::start_with(|c, x, _| {
		c.assets[0] = AssetSection::new(x, 1_000);
		c.batches.no_sweep = true;
		c.batches.delegated_reclaim = true;
	}).await;
	let (x, y) = (r.x, r.y);
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	r.fund_server(x, 30_000_000_000).await;

	// The maker: one coin of 20,000,000 X, boarded and refreshed into a round's leaf.
	let (url, node) = (r.url(), r.node_url());
	let maker = Arca::new("CM");
	maker.ok(&create_args(&url, &node));
	let spk = maker.ok(&["address"])["script_pubkey"].as_str().unwrap().to_string();
	let s = elements::Script::from((0..spk.len()).step_by(2).map(|i| u8::from_str_radix(&spk[i..i + 2], 16).unwrap()).collect::<Vec<u8>>());
	r.pay_to(s, x, 2_000_100_000);
	r.produce().await;
	maker.ok(&["board", &x.to_string(), "2000000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || maker.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	maker.ok(&["sync"]);
	maker.ok(&["participate"]);
	rounds(&mut r, &maker).await;
	let held: Vec<Value> = maker.ok(&["coins"]).as_array().unwrap().iter()
		.filter(|c| c["state"] == "live" && c["asset"] == json!(x.to_string())).cloned().collect();
	assert!(held.len() == 1 && held[0]["kind"] == "batch", "one coin of a round: {:?}", held);
	let large: u64 = held[0]["value"].as_str().unwrap().parse().unwrap();
	println!("the maker holds one coin of a round of {} X; in flight {}", large, in_flight(&r, x).await);

	let levels = [100_000_000u64, 140_000_000, 196_000_000, 274_400_000];
	let ladder: u64 = levels.iter().sum();
	let mut orders = vec![];
	let mut first_given = 0;
	for &a in &levels {
		let (o, given, change) = rest(&mut r, &maker, a).await;
		println!("pass 0: rested {} X, gave up {} (change {})", a, given, change);
		first_given += given;
		orders.push(o);
	}
	println!("pass 0: the ladder of {} X gave up {} X; in flight {}", ladder, first_given, in_flight(&r, x).await);

	let mut again_given = 0;
	let mut worst = 0;
	for pass in 1..=3 {
		let mut given_pass = 0;
		// As the testnet's leaf maker's desk does: the levels the price moved
		// past are cancelled on one pass, and each is rested again on the
		// next at what its coin came back with (within a thousandth of the
		// level), one round each.
		let back: Vec<u64> = orders.iter().map(|o| cancel(&maker, o)).collect();
		for (k, &a) in levels.iter().enumerate() {
			let size = if back[k] <= a && back[k] * 1000 >= a * 999 { back[k] } else { a };
			let (o, given, change) = rest(&mut r, &maker, size).await;
			println!("pass {}: level {} ({} X) cancelled, its coin back with {}, rested again at {}: gave up {} (change {})", pass, k, a,
				back[k], size, given, change);
			given_pass += given;
			worst = worst.max(change);
			orders[k] = o;
		}
		again_given += given_pass;
		println!("pass {}: the ladder of {} X gave up {} X; in flight {}", pass, ladder, given_pass, in_flight(&r, x).await);
	}
	println!("RESULT ladder {} X, 3 passes again: gave up {} X in all, the most change of one rest {}; in flight {}", ladder, again_given,
		worst, in_flight(&r, x).await);
	// What a maker that merges its own resting orders sets off (the testnet's
	// leaf maker did, counting them among the coins it keeps): the merge's
	// refresh of an order's coin cancels the order, so every level is rested
	// again, and each rest gives up coins the operator fronts anew.
	let live: Vec<String> = maker.ok(&["coins"]).as_array().unwrap().iter()
		.filter(|c| c["state"] == "live" && c["asset"] == json!(x.to_string()) && c["value"].as_str().unwrap().parse::<u64>().unwrap() < 1_000_000_000)
		.map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
	let order_coins = maker.ok(&["coins"]).as_array().unwrap().iter()
		.filter(|c| c["state"] == "live" && c["template"].as_str().is_some_and(|t| t.starts_with("order-"))).count();
	assert_eq!(order_coins, levels.len(), "the maker's coins list its resting orders by their template");
	let mut merge = vec!["participate".to_string()];
	for l in &live {
		merge.push("--leaf".into());
		merge.push(l.clone());
	}
	maker.ok(&merge.iter().map(|s| s.as_str()).collect::<Vec<_>>());
	rounds(&mut r, &maker).await;
	let view = maker.ok(&["order", "resting"]);
	let resting = view["orders"].as_array().unwrap().iter().filter(|o| orders.contains(&o["order"].as_str().unwrap_or("").to_string())
		&& o["operator"]["state"] == "resting").count();
	println!("a merge of {} small coins, the {} orders among them: {} of the orders still rest", live.len(), order_coins, resting);
	assert_eq!(resting, 0, "a refresh of an order's coin ends the order: {}", view);
	let mut merged_given = 0;
	for &a in &levels {
		let (_, given, change) = rest(&mut r, &maker, a).await;
		println!("after the merge: rested {} X again, gave up {} (change {})", a, given, change);
		merged_given += given;
	}
	println!("RESULT after a merge that took the orders, resting the ladder of {} X again gave up {} X; in flight {}", ladder,
		merged_given, in_flight(&r, x).await);

	// Every rest after the first pass is made from its level's cancelled coin
	// and leaves no change, where a rest from the large coin leaves nearly
	// 2,000,000,000: the three passes give up the ladder three times, no more.
	assert_eq!(worst, 0, "a rest after a cancel left change: a coin other than its own was given up");
	assert!(again_given <= 3 * ladder, "three passes gave up {} X for a ladder of {}", again_given, ladder);
}
