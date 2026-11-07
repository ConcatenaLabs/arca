//! Which coins a swap pays from (arca #703 to #706, review RV28 of #702):
//! the coin of the latest date that pays it alone, the fewest reassignments
//! deep first and then the smallest, with its real margins; never a coin at
//! the operator's depth limit; a coin over the wallet's margin bound passed
//! over like one that does not hold it; and a swap whose new coins would be
//! past the depth limit refused before anything is signed.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::Script;
use serde_json::{json, Value};

use bark::arca::{command, Wallet};
use common::cli::Arca;
use common::running::{Running, MIN_LEAF};

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

fn coins(w: &Arca, state: &str, asset: &str) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == state && c["asset"] == asset).cloned().collect()
}

fn value(c: &Value) -> u64 {
	c["value"].as_str().unwrap().parse().unwrap()
}

fn num(v: &Value) -> u64 {
	v.as_str().unwrap().parse().unwrap()
}

fn library(a: &Arca, cmd: &str, args: Value) -> Result<Value, String> {
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run(&mut w, cmd, &args).map(|v| v["result"].clone()).map_err(|e| e.to_string())
	})
}

/// Two wallets, A holding X and B holding Y, each boarding the values given
/// in one block (so every coin has one date).
async fn setup(r: &mut Running, tag: &str, a_boards: &[u64], b_boards: &[u64]) -> (Arca, Arca) {
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new(&format!("{}A", tag));
	let b = Arca::new(&format!("{}B", tag));
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	a.ok(&create);
	b.ok(&create);
	// One chain coin per board, so no board waits for another's change.
	for v in a_boards {
		let s = script(&a.ok(&["address"]));
		r.pay_to(s, r.x, v + 1_000_000);
	}
	for v in b_boards {
		let s = script(&b.ok(&["address"]));
		r.pay_to(s, r.y, v + 1_000_000);
		let s = script(&b.ok(&["address"]));
		r.pay_to(s, r.x, 1_000_000);
	}
	r.produce().await;
	for v in a_boards {
		a.ok(&["board", &x, &v.to_string()]);
	}
	for v in b_boards {
		b.ok(&["board", &y, &v.to_string(), "--fee-asset", &x]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the server to credit the boards", || {
		a.ok(&["boards"]).as_array().unwrap().iter().all(|v| v["server"]["state"] == "credited")
			&& b.ok(&["boards"]).as_array().unwrap().iter().all(|v| v["server"]["state"] == "credited")
	}).await;
	a.ok(&["sync"]);
	b.ok(&["sync"]);
	(a, b)
}

fn value_of_leaf(w: &Arca, asset: &str, leaf: &Value) -> u64 {
	coins(w, "offered", asset).iter().chain(coins(w, "live", asset).iter()).find(|c| c["leaf_id"] == *leaf).map(value).unwrap()
}

fn inputs_of(w: &Arca, asset: &str, offer: &Value) -> Vec<u64> {
	offer["details"]["inputs"].as_array().unwrap().iter().map(|i| value_of_leaf(w, asset, &i["leaf_id"])).collect()
}

/// #705: a coin worth what the swap pays plus the smallest leaf cannot pay
/// alone once its margins count; it is passed over for the next coin that
/// pays alone, never paired with it. A coin worth exactly what the swap
/// pays and its margins pays alone, with no change.
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_that_only_just_holds_a_swap_is_passed_over_and_one_of_exact_value_pays_alone() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let give = 100_000u64;
	let (a, b) = setup(&mut r, "SCB", &[2_000_000, give + MIN_LEAF], &[3_000_000, give + MIN_LEAF]).await;
	let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": give.to_string(), "want_asset": y, "want": give.to_string()})).unwrap();
	let ins = inputs_of(&a, &x, &offer);
	println!("MAKER: inputs {:?} pays {}", ins, offer["pays"]);
	assert_eq!(ins, vec![2_000_000], "the band coin passed over, the next that pays alone taken, alone");
	let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap();
	println!("TAKER: coins_spent {} pays {} change {}", read["coins_spent"], read["pays"], read["change"]);
	assert_eq!(read["coins_spent"], 1);
	// The margins the maker's coin leaves, then a coin of exactly the swap and them.
	let exact = give + num(&offer["pays"]["margin"]) + num(&offer["pays"]["margins"]);
	library(&a, "swap_cancel", json!({"swap": offer["swap"]})).unwrap();
	let (c, _d) = setup(&mut r, "SCE", &[2_000_000, exact], &[3_000_000]).await;
	let offer = library(&c, "swap_offer", json!({"give_asset": x, "give": give.to_string(), "want_asset": y, "want": give.to_string()})).unwrap();
	let ins = inputs_of(&c, &x, &offer);
	let outs: Vec<u64> = offer["details"]["outputs"].as_array().unwrap().iter().map(|o| num(&o["value"])).collect();
	println!("EXACT {}: inputs {:?} outputs {:?} pays {}", exact, ins, outs, offer["pays"]);
	assert_eq!(ins, vec![exact], "the coin of exactly the swap and its margins");
	assert_eq!(outs.len(), 1, "no change: {:?}", outs);
}

/// #706: a small coin that holds a small swap but whose margins are past the
/// wallet's 1% bound is passed over, and a larger coin pays it.
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_past_the_margin_bound_is_passed_over() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (a, _b) = setup(&mut r, "SCP", &[2_000_000, 10_000], &[3_000_000]).await;
	let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": MIN_LEAF.to_string(), "want_asset": y, "want": MIN_LEAF.to_string()}))
		.unwrap_or_else(|e| panic!("refused: {}", e));
	let ins = inputs_of(&a, &x, &offer);
	println!("OFFER: inputs {:?} pays {}", ins, offer["pays"]);
	assert_eq!(ins, vec![2_000_000]);
}

/// #703: successive swaps with no round between, each wallet holding three
/// coins of one date: each swap pays from a coin the fewest reassignments
/// deep, so every one completes, and none of the coins spent is at the
/// operator's depth limit.
#[tokio::test(flavor = "multi_thread")]
async fn successive_swaps_spread_over_the_shallowest_coins() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (a, b) = setup(&mut r, "SCH", &[1_000_000, 1_000_000, 1_000_000], &[1_000_000, 1_000_000, 1_000_000]).await;
	let hops_of = |w: &Arca, leaf: &Value| -> u64 {
		w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == *leaf).map(|c| c["hops"].as_u64().unwrap_or(99)).unwrap()
	};
	let mut deepest = 0;
	for k in 1..=8 {
		let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": "100000", "want_asset": y, "want": "100000"}))
			.unwrap_or_else(|e| panic!("swap {}: offer refused: {}", k, e));
		let maker_hops: Vec<u64> = offer["details"]["inputs"].as_array().unwrap().iter().map(|i| hops_of(&a, &i["leaf_id"])).collect();
		let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap_or_else(|e| panic!("swap {}: read refused: {}", k, e));
		let acc = library(&b, "swap_accept", json!({"offer": offer["offer"], "shown": read})).unwrap_or_else(|e| panic!("swap {}: {}", k, e));
		library(&a, "swap_complete", json!({"accept": acc["accept"]})).unwrap_or_else(|e| panic!("swap {}: complete refused: {}", k, e));
		b.ok(&["mailbox"]);
		println!("SWAP {}: maker input hops {:?}, new coins' hops {}", k, maker_hops, read["hops"]);
		deepest = deepest.max(read["hops"].as_u64().unwrap());
	}
	assert!(deepest <= 3, "eight swaps over three coins each side stay shallow: {}", deepest);
}

/// A coin at the operator's depth limit is never taken into a swap: a
/// taker whose only coin is that deep is refused before anything is
/// signed.
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_at_the_depth_limit_is_never_taken_into_a_swap() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (a, b) = setup(&mut r, "SCD", &[1_000_000], &[1_000_000]).await;
	// B's coin of Y, paid to itself five times out of round: five reassignments deep.
	for _ in 0..5 {
		let req = b.ok(&["receive"]);
		let have: u64 = coins(&b, "live", &y).iter().map(value).sum();
		b.ok(&["send", req["request"].as_str().unwrap(), "--amount", &(have - 10_000).to_string(), "--asset", &y]);
		b.ok(&["mailbox"]);
	}
	let deep: Vec<(u64, Value)> = coins(&b, "live", &y).iter().map(|c| (value(c), c["hops"].clone())).collect();
	println!("B's coins of Y: {:?}", deep);
	assert!(deep.iter().any(|(_, h)| h.as_u64() == Some(5)), "{:?}", deep);
	let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": "100000", "want_asset": y, "want": "100000"})).unwrap();
	let e = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap_err();
	println!("READ REFUSED: {}", e);
	assert!(e.contains("at the operator's depth limit"), "{}", e);
	assert!(coins(&b, "offered", &y).is_empty(), "nothing held");
}
