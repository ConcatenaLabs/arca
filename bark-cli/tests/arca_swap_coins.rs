//! Which coins a swap pays from (arca #703 to #706 and #709, review RV28 of
//! #702 and #708): the coin of the latest date that pays it alone with its
//! real margins, coins already at risk first and then the smallest of the
//! rest (a fresh coin or the wallet's own out of round, #892),
//! each the smallest first; never a coin at
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
	assert!(deepest <= 4, "no swap's new coins reach the depth limit of 5 (room is left for a cancel): {}", deepest);
}

/// #709 (D93): between rounds, a swap pays from change already out of round
/// before a fresh coin, so the maker's total out of round stays near a
/// trade's size rather than a coin's: RV28's case, one coin of 2,000,000 and
/// three of 300,000 of one date, six swaps of 100,000 with no round between.
#[tokio::test(flavor = "multi_thread")]
async fn a_swap_spends_change_already_out_of_round_before_a_fresh_coin() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (a, b) = setup(&mut r, "SCO", &[2_000_000, 300_000, 300_000, 300_000], &[1_000_000, 1_000_000, 1_000_000]).await;
	let out_of_round = |w: &Arca| -> u64 {
		w.ok(&["coins"]).as_array().unwrap().iter()
			.filter(|c| c["asset"] == x.as_str() && c["kind"] == "transfer" && (c["state"] == "live" || c["state"] == "offered"))
			.map(value).sum()
	};
	let mut totals = vec![];
	for k in 1..=6 {
		let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": "100000", "want_asset": y, "want": "100000"}))
			.unwrap_or_else(|e| panic!("swap {}: offer refused: {}", k, e));
		let ins = inputs_of(&a, &x, &offer);
		let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap_or_else(|e| panic!("swap {}: read refused: {}", k, e));
		let acc = library(&b, "swap_accept", json!({"offer": offer["offer"], "shown": read})).unwrap_or_else(|e| panic!("swap {}: {}", k, e));
		library(&a, "swap_complete", json!({"accept": acc["accept"]})).unwrap_or_else(|e| panic!("swap {}: complete refused: {}", k, e));
		b.ok(&["mailbox"]);
		a.ok(&["mailbox"]);
		totals.push(out_of_round(&a));
		println!("SWAP {}: inputs {:?}, the maker's X out of round {}", k, ins, totals[k - 1]);
	}
	assert_eq!(totals, vec![199_272, 98_544, 297_816, 197_088, 396_360, 295_632]);
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

/// #711: under an operator whose most margin is its least (`max_margin_multiple`
/// 1), a coin that would pay a swap only by leaving more than that in the
/// margin is passed over, and the swap completes from another coin; the
/// operator would have refused the margin at completion, after the taker
/// signed.
#[tokio::test(flavor = "multi_thread")]
async fn a_remainder_past_the_operators_most_margin_is_not_given_to_it() {
	let mut r = Running::start_with(|c, _, _| c.fees.max_margin_multiple = Some(1)).await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let give = 100_000u64;
	let (a, b) = setup(&mut r, "SCM", &[2_000_000], &[1_000_000]).await;
	let first = library(&a, "swap_offer", json!({"give_asset": x, "give": give.to_string(), "want_asset": y, "want": give.to_string()})).unwrap();
	// A coin of the swap, its checkpoint's margin and a reassignment's with a change output: alone
	// it leaves the change output's margin, more than the least with none.
	let near = give + num(&first["pays"]["margin"]) + num(&first["pays"]["margins"]);
	library(&a, "swap_cancel", json!({"swap": first["swap"]})).unwrap();
	let (c, _) = setup(&mut r, "SCN", &[2_000_000, near], &[1_000_000]).await;
	let offer = library(&c, "swap_offer", json!({"give_asset": x, "give": give.to_string(), "want_asset": y, "want": give.to_string()})).unwrap();
	let ins = inputs_of(&c, &x, &offer);
	println!("NEAR {}: inputs {:?} pays {}", near, ins, offer["pays"]);
	assert_eq!(ins, vec![2_000_000], "the near coin passed over");
	let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap();
	let acc = library(&b, "swap_accept", json!({"offer": offer["offer"], "shown": read})).unwrap();
	library(&c, "swap_complete", json!({"accept": acc["accept"]})).unwrap_or_else(|e| panic!("complete refused: {}", e));
}

/// D93's floor of life: a maker whose one giant coin was made 33 hours after
/// its others pays a small swap from one of those, not the giant. Taken from
/// the coins within a day of the newest, the giant was alone in its day and
/// paid every swap, its change out of round past the maker's share (the
/// testnet's leaf maker: a $4.65M coin, 672 hours to expiry, beside 59 coins
/// of $50k to $100k with 515 to 639).
#[tokio::test(flavor = "multi_thread")]
async fn a_giant_coin_newer_than_the_rest_is_not_the_only_one_tried() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (a, b) = setup(&mut r, "SCG", &[300_000, 300_000], &[1_000_000]).await;
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 33 * 3_600));
	r.produce().await;
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, r.x, 3_000_000);
	r.produce().await;
	a.ok(&["board", &x, "2000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the giant credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|v| v["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
	let live: Vec<(u64, Value)> = coins(&a, "live", &x).iter().map(|c| (value(c), c["expiry"].clone())).collect();
	println!("MAKER COINS (value, expiry): {:?}", live);
	let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": "100000", "want_asset": y, "want": "100000"})).unwrap();
	let ins = inputs_of(&a, &x, &offer);
	println!("OFFER: inputs {:?}", ins);
	assert_eq!(ins, vec![300_000], "a mid-size coin, not the newer giant");
	let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap();
	let acc = library(&b, "swap_accept", json!({"offer": offer["offer"], "shown": read})).unwrap();
	library(&a, "swap_complete", json!({"accept": acc["accept"]})).unwrap();
}

/// What the wallet holds at risk out of round in `asset`: the coins
/// `coin_places` marks `at_risk`, summed.
fn at_risk(w: &Arca, asset: &str) -> u64 {
	let p = library(w, "coin_places", json!({})).unwrap();
	p["coins"].as_array().unwrap().iter().filter(|c| c["asset"] == asset && c["at_risk"] == true).map(value).sum()
}

/// Whether the operator co-signs checkpoints with their owners' exit: a
/// trade's change is then at risk to nobody, and otherwise received, at risk
/// whole until a round refreshes it.
fn checkpoint_exit(w: &Arca) -> bool {
	w.ok(&["info"])["server_info"]["checkpoint_exit"] == true
}

/// The wallet pays itself `amount` of `asset` out of round: a coin of its own
/// lineage, at risk to nobody, one reassignment deep; its leaf id.
fn pay_self(w: &Arca, asset: &str, amount: u64) -> String {
	let req = w.ok(&["receive"]);
	w.ok(&["send", req["request"].as_str().unwrap(), "--amount", &amount.to_string(), "--asset", asset]);
	w.ok(&["mailbox"]);
	coins(w, "live", asset).iter().find(|c| value(c) == amount && c["kind"] == "transfer")
		.map(|c| c["leaf_id"].as_str().unwrap().to_string()).expect("the coin paid to itself")
}

/// One swap of `give` of X for as much Y, offered by `a` (from `leaves` when
/// named) and taken by `b`: the values of the maker's inputs.
fn swap_once(a: &Arca, b: &Arca, x: &str, y: &str, give: u64, leaves: &[String]) -> Vec<u64> {
	let offer = library(a, "swap_offer", json!({"give_asset": x, "give": give.to_string(), "want_asset": y, "want": give.to_string(),
		"leaves": leaves})).unwrap_or_else(|e| panic!("offer refused: {}", e));
	let ins = inputs_of(a, x, &offer);
	let read = library(b, "swap_read", json!({"offer": offer["offer"]})).unwrap_or_else(|e| panic!("read refused: {}", e));
	let acc = library(b, "swap_accept", json!({"offer": offer["offer"], "shown": read})).unwrap_or_else(|e| panic!("accept refused: {}", e));
	library(a, "swap_complete", json!({"accept": acc["accept"]})).unwrap_or_else(|e| panic!("complete refused: {}", e));
	b.ok(&["mailbox"]);
	a.ok(&["mailbox"]);
	ins
}

/// #892: a maker holding its own change of 848,792 out of round (at risk to
/// nobody) beside working coins of 100,000 pays a trade of 20,000 from a
/// working coin, never from the large coin: what it holds at risk after the
/// trade is at most that working coin, on an operator with checkpoint exits
/// and on one without (ARCA_TEST_CHECKPOINT_EXIT=0, the testnet's), where
/// the trade's change is received and at risk whole.
#[tokio::test(flavor = "multi_thread")]
async fn a_small_trade_pays_from_a_working_coin_not_a_large_own_coin_out_of_round() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	// Its change from paying itself 848,792 out of 860,000 is about 10,000,
	// too small for the trade: the large own coin and the working coins pay it.
	let (a, b) = setup(&mut r, "SCW", &[860_000, 100_000, 100_000], &[1_000_000]).await;
	let own = pay_self(&a, &x, 848_792);
	let held: Vec<(u64, String, Value)> = coins(&a, "live", &x).iter().map(|c| (value(c), c["kind"].as_str().unwrap().to_string(), c["hops"].clone())).collect();
	println!("W892 maker's X (value, kind, hops): {:?}; checkpoint_exit {}", held, checkpoint_exit(&a));
	assert_eq!(at_risk(&a, &x), 0, "its own coins are at risk to nobody");
	let ins = swap_once(&a, &b, &x, &y, 20_000, &[]);
	let risk = at_risk(&a, &x);
	println!("W892 the trade of 20,000 paid from {:?}; the maker's X at risk after it: {}, Y at risk {}", ins, risk, at_risk(&a, &y));
	assert_eq!(ins, vec![100_000], "a working coin, not the own coin of 848,792");
	assert!(coins(&a, "live", &x).iter().any(|c| c["leaf_id"] == own.as_str()), "the own coin untouched");
	assert!(risk <= 100_000, "at most the working coin's value at risk: {}", risk);
	// A second trade: the other working coin, or the first one's change, never the large coin.
	let ins = swap_once(&a, &b, &x, &y, 20_000, &[]);
	let risk = at_risk(&a, &x);
	println!("W892 the second trade paid from {:?}; X at risk {}", ins, risk);
	assert!(ins.iter().all(|v| *v <= 100_000), "{:?}", ins);
	assert!(risk <= 200_000, "{}", risk);
}

/// A wallet whose only coin that pays the trade alone is its large own coin
/// still trades from it, and what it then holds at risk is that coin's
/// change on an operator without checkpoint exits, nothing with them.
#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_whose_only_paying_coin_is_large_still_trades() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	// Its change from paying itself 848,792 out of 860,000 is about 10,000:
	// no coin but the large one pays a trade of 20,000.
	let (a, b) = setup(&mut r, "SCL", &[860_000, 10_000], &[1_000_000]).await;
	pay_self(&a, &x, 848_792);
	println!("WLARGE the maker's X: {:?}", coins(&a, "live", &x).iter().map(value).collect::<Vec<_>>());
	let ins = swap_once(&a, &b, &x, &y, 20_000, &[]);
	let change: u64 = coins(&a, "live", &x).iter().filter(|c| c["kind"] == "transfer" && value(c) > 800_000).map(value).sum();
	let risk = at_risk(&a, &x);
	println!("WLARGE paid from {:?}; its change {}; X at risk {} (checkpoint_exit {})", ins, change, risk, checkpoint_exit(&a));
	assert_eq!(ins, vec![848_792], "the only coin that pays it alone");
	assert_eq!(risk, if checkpoint_exit(&a) { 0 } else { change }, "its change, received, at risk whole without checkpoint exits");
}

/// A swap offer names the coins it pays from (`leaves`): it pays from those
/// alone, even where the wallet would choose another; a named coin the
/// wallet cannot pay from now (held by an offer, or no coin of the asset)
/// is refused before anything is held; one that does not cover it is
/// refused, nothing held.
#[tokio::test(flavor = "multi_thread")]
async fn a_swap_offer_pays_from_the_coins_it_names() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (a, b) = setup(&mut r, "SCF", &[1_000_000, 100_000, 300_000], &[1_000_000]).await;
	let leaf_of = |v: u64| coins(&a, "live", &x).iter().find(|c| value(c) == v).map(|c| c["leaf_id"].as_str().unwrap().to_string()).unwrap();
	let (big, mid, small) = (leaf_of(1_000_000), leaf_of(300_000), leaf_of(100_000));
	let ins = swap_once(&a, &b, &x, &y, 20_000, &[mid.clone()]);
	println!("NAMED the 300,000 coin: paid from {:?}", ins);
	assert_eq!(ins, vec![300_000], "the named coin, not the smaller one the wallet would choose");
	let held = library(&a, "swap_offer", json!({"give_asset": x, "give": "20000", "want_asset": y, "want": "20000", "leaves": [big]})).unwrap();
	let e = library(&a, "swap_offer", json!({"give_asset": x, "give": "20000", "want_asset": y, "want": "20000", "leaves": [big]})).unwrap_err();
	println!("NAMED a coin held by an offer: {}", e);
	assert!(e.contains("must each be a live coin") && e.contains(&big), "{}", e);
	library(&a, "swap_cancel", json!({"swap": held["swap"]})).unwrap();
	let ghost = "00".repeat(32);
	let e = library(&a, "swap_offer", json!({"give_asset": x, "give": "20000", "want_asset": y, "want": "20000", "leaves": [ghost]})).unwrap_err();
	println!("NAMED no coin of the wallet's: {}", e);
	assert!(e.contains("must each be a live coin") && e.contains(&ghost), "{}", e);
	let e = library(&a, "swap_offer", json!({"give_asset": x, "give": "500000", "want_asset": y, "want": "20000", "leaves": [small]})).unwrap_err();
	println!("NAMED a coin short of the trade: {}", e);
	assert!(coins(&a, "offered", &x).is_empty(), "nothing held");
	let ins = swap_once(&a, &b, &x, &y, 20_000, &[]);
	println!("UNNAMED: paid from {:?}", ins);
	// Unnamed, the wallet chooses: without checkpoint exits the first trade's
	// change (279,272) is received, at risk already, and goes first, adding
	// nothing at risk; with them it is at risk to nobody, and the smallest
	// coin that pays goes.
	let want = if checkpoint_exit(&a) { 100_000 } else { 279_272 };
	assert_eq!(ins, vec![want], "unnamed, the wallet chooses");
}
