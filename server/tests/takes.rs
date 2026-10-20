//! Takes of on-chain orders, against a whole server on an anchored
//! proof-of-stake regtest chain: an order made with SeqDEX's fill covenant
//! (selling X for Y) rests on the chain; a holder of Y asks the operator to
//! fill it for a leaf of X, and the server checks the order's terms against
//! the chain and the fill asked of them before it takes the request. Every
//! refusal is printed as the server words it.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::{OutPoint, Transaction, TxIn};
use serde_json::{json, Value};

use arca_covenant::FillOrder;
use common::client::{take_body, want_leaf};
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{credited_board, status, VALUE};
use common::running::{Running, MIN_LEAF};
use sequentia_ext::{explicit_txout, fee_txout, AssetAmount};
use server::server::AssetSection;

/// The order's terms: it sells X and is paid in Y at 2 Y an X, at least
/// 10,000 at a time, refundable by its maker from `expiry`.
fn order_terms(r: &Running, expiry: u32, maker: &str) -> FillOrder {
	FillOrder {
		asset_a: r.x,
		asset_b: r.y,
		rate_num: 2,
		rate_den: 1,
		maker_prog: xonly(&keypair(&format!("{} payout", maker))).serialize(),
		min_lot: 10_000,
		expiry_locktime: expiry,
		maker_x: xonly(&keypair(maker)).serialize(),
	}
}

/// Rests `locked` of X under `terms` on the chain, as a maker does: the
/// order's output and its transaction.
fn rest(r: &mut Running, terms: &FillOrder, locked: u64) -> (OutPoint, Transaction) {
	let tx = tokio::task::block_in_place(|| r.purse.pay(&r.rt, vec![explicit_txout(AssetAmount::new(r.x, locked), terms.script_pubkey())]));
	(OutPoint::new(tx.txid(), 0), tx)
}

fn height(r: &Running) -> u32 {
	r.rt.client().blockchain_info().unwrap().blocks as u32
}

/// Posts a take; prints and returns its answer.
fn post(r: &Running, what: &str, body: &Value) -> (i32, Value) {
	let a = r.http.post("take_order", body);
	if a.status == 200 {
		println!("{}: {} {}", what, a.status, a.json["state"]);
	} else {
		let (code, msg) = a.refusal();
		println!("{}: {} {}: {}", what, a.status, code, msg);
	}
	(a.status, a.json)
}

fn refused(r: &Running, what: &str, body: &Value, code: &str, part: &str) {
	let (status, json) = post(r, what, body);
	assert_ne!(status, 200, "{}: taken", what);
	assert_eq!(json["error"]["code"], code, "{}: {}", what, json);
	assert!(json["error"]["message"].as_str().unwrap().contains(part), "{}: {}", what, json);
}

/// A transaction filling the whole order at `order` (holding `locked`)
/// outside the operator, as anyone may: the order's FILL, the maker
/// credited from the purse's coin of Y, the X to `OP_TRUE`.
fn outside_fill(r: &mut Running, terms: &FillOrder, order: OutPoint, locked: u64) -> Transaction {
	let plan = terms.plan(locked, locked).unwrap();
	let coin = r.purse.take_coin(r.y);
	let policy = r.purse.take_coin(r.purse.policy);
	let y_left = coin.1.value.explicit().unwrap() - plan.credit.value;
	let fee = 5_000;
	let p_left = policy.1.value.explicit().unwrap() - fee;
	let mut tx = Transaction {
		version: 2, lock_time: elements::LockTime::ZERO,
		input: vec![
			TxIn { previous_output: order, ..Default::default() },
			TxIn { previous_output: coin.0, ..Default::default() },
			TxIn { previous_output: policy.0, ..Default::default() },
		],
		output: vec![
			plan.credit.txout(),
			// 2k+1 of a full fill: an explicit output in another asset.
			explicit_txout(AssetAmount::new(r.y, y_left), node::op_true()),
			explicit_txout(AssetAmount::new(r.x, locked), node::op_true()),
			explicit_txout(AssetAmount::new(r.purse.policy, p_left), node::op_true()),
			fee_txout(AssetAmount::new(r.purse.policy, fee)),
		],
	};
	tx.input[0].witness.script_witness = terms.witness();
	let txid = tx.txid();
	r.purse.put((OutPoint::new(txid, 1), tx.output[1].clone()));
	r.purse.put((OutPoint::new(txid, 3), tx.output[3].clone()));
	tx
}

#[tokio::test(flavor = "multi_thread")]
async fn a_take_is_checked_against_the_chain_and_its_terms() {
	// Y is served with an offboard fee of 1,000 atoms: a take of a price of
	// 999,000 pays 1,000, and a coin of 1,000,000 holds both.
	let mut r = Running::start_with(|c, y| {
		let mut a = AssetSection::new(y, MIN_LEAF);
		a.offboard_base = Some("1000".into());
		c.assets.push(a);
	}).await;
	let (x, y) = (r.x, r.y);
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(y, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let (s, chain) = (xonly(&r.s), r.chain);

	// Two takers, each holding one coin of 1,000,000 of Y.
	let (t1, t2) = (keypair("taker 1"), keypair("taker 2"));
	let (c1, _) = credited_board(&mut r, &t1, y).await;
	let (c2, _) = credited_board(&mut r, &t2, y).await;
	let (xc, _) = credited_board(&mut r, &keypair("holder of X"), x).await;
	let leaf_of = |k: &str, v: u64| want_leaf(&keypair(k), x, v).0;

	// The order: 600,000 of X, refundable 20,000 blocks from now.
	let terms = order_terms(&r, height(&r) + 20_000, "maker");
	let (order, _) = rest(&mut r, &terms, 600_000);
	let (filled, price, fee) = (499_500u64, 999_000u64, 1_000u64);
	assert_eq!(terms.price(filled), Some(price));
	assert_eq!(VALUE, price + fee);

	// The order is in a block, its anchor not yet buried: not final.
	r.produce().await;
	r.synced().await;
	let (body, _) = take_body(&[&c1], order, &terms, 600_000, filled, &leaf_of("t1 new", filled), (y, fee), s, chain);
	refused(&r, "an order not yet final", &body, "order_not_final", "a round spends only what a rollback cannot take away");
	r.bury().await;
	r.synced().await;

	// Terms that are not the order's, or no resting order's.
	let other = FillOrder { rate_num: 3, ..terms.clone() };
	let (body, _) = take_body(&[&c1], order, &other, 600_000, filled, &leaf_of("t1 new", filled), (y, fee), s, chain);
	refused(&r, "terms that make another script", &body, "order", "the terms do not make the script at");
	let (mut body, _) = take_body(&[&c1], order, &terms, 600_000, filled, &leaf_of("t1 new", filled), (y, fee), s, chain);
	body["order"]["internal_key"] = json!(arca_covenant::fill::base64(&xonly(&keypair("maker")).serialize()));
	refused(&r, "an order with a maker key path", &body, "order", "not the NUMS point");
	let (body, _) = take_body(&[&c1], order, &terms, 600_001, filled, &leaf_of("t1 new", filled), (y, fee), s, chain);
	refused(&r, "what the order holds misread", &body, "order", "holds 600000 of asset");
	let (body, _) = take_body(&[&c1], OutPoint::new(order.txid, 5), &terms, 600_000, filled, &leaf_of("t1 new", filled), (y, fee), s, chain);
	refused(&r, "an outpoint the order's transaction does not have", &body, "order", "has no output 5");

	// Fills the order's FILL leaf refuses.
	let (body, _) = take_body(&[&c1], order, &terms, 600_000, 9_999, &leaf_of("t1 new", 9_999), (y, fee), s, chain);
	refused(&r, "a fill below the order's min_lot", &body, "order", "below the order's min_lot of 10000");
	let (body, _) = take_body(&[&c1], order, &terms, 600_000, 595_000, &leaf_of("t1 new", 595_000), (y, fee), s, chain);
	refused(&r, "a fill leaving less than the lot", &body, "order", "leaves 5000 resting");

	// The leaf, the coins, the amounts.
	let (body, _) = take_body(&[&c1], order, &terms, 600_000, filled, &leaf_of("t1 new", filled - 1), (y, fee), s, chain);
	refused(&r, "a leaf holding less than the fill", &body, "order", "holds what it fills");
	let (body, _) = take_body(&[&c1], order, &terms, 600_000, filled, &want_leaf(&keypair("t1 new"), y, filled).0, (y, fee), s, chain);
	refused(&r, "a leaf in the asset the order is paid in", &body, "order", "holds what it fills");
	let (body, _) = take_body(&[&xc], order, &terms, 600_000, filled, &leaf_of("t1 new", filled), (y, fee), s, chain);
	refused(&r, "a coin of the asset the order sells", &body, "out_of_bounds", "a take gives up coins in the asset the order is paid in");
	let (body, _) = take_body(&[&c1], order, &terms, 600_000, filled - 500, &leaf_of("t1 new", filled - 500), (y, fee), s, chain);
	refused(&r, "coins holding more than the price and the fee", &body, "unbalanced", "the order's price for 499000 atoms is 998000");
	let (body, _) = take_body(&[&c1], order, &terms, 600_000, 500_000, &leaf_of("t1 new", 500_000), (y, 0), s, chain);
	refused(&r, "a fee under the schedule's for an offboard of the price", &body, "fee", "an offboard of the order's price, 1000000: 1000");
	let (body, _) = take_body(&[&c1], order, &terms, 600_000, filled, &leaf_of("t1 new", filled), (x, fee), s, chain);
	refused(&r, "a fee in the asset the order sells", &body, "out_of_bounds", "pays its fee in the asset the order is paid in");
	let (mut body, _) = take_body(&[&c1], order, &terms, 600_000, filled, &leaf_of("t1 new", filled), (y, fee), s, chain);
	body["inputs"][0]["attestation"] = body["leaf"]["key_proof"].clone();
	refused(&r, "an attestation that is not the coin's over the take", &body, "bad_attestation", "input 0");

	// The take: pending, its order shown.
	let (body, id1) = take_body(&[&c1], order, &terms, 600_000, filled, &leaf_of("t1 new", filled), (y, fee), s, chain);
	let (st, a) = post(&r, "taker 1's take", &body);
	assert_eq!((st, a["state"].as_str()), (200, Some("pending")), "{}", a);
	let f = &a["fill"];
	println!("its order: {}", f);
	assert_eq!(f["order"], json!(format!("{}:{}", order.txid, order.vout)));
	assert_eq!((f["filled"].as_str(), f["remainder"].as_str(), f["price"].as_str()), (Some("499500"), Some("100500"), Some("999000")));
	assert_eq!(f["maker_script"], json!(common::client::hex(terms.maker_script_pubkey().as_bytes())));
	assert_eq!(a["outputs"][0]["asset"], json!(x.to_string()));
	assert_eq!(a["inputs"][0]["asset"], json!(y.to_string()));
	// Again: the same take, its status.
	let (st, again) = post(&r, "taker 1's take again", &body);
	assert_eq!((st, &again["participation_id"]), (200, &a["participation_id"]));

	// The same order, taken by another while the first stands.
	let (body2, _) = take_body(&[&c2], order, &terms, 600_000, filled, &leaf_of("t2 new", filled), (y, fee), s, chain);
	refused(&r, "the order taken by a second taker meanwhile", &body2, "order_taken", "is taken by participation");

	// The runner takes a take into no refresh round, and does not void it as
	// one carrying two assets: it builds a round of its own that fills the
	// order.
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	assert_eq!(built.len(), 1);
	assert_eq!((built[0].fills.clone(), built[0].participations), (vec![order], 1));
	assert_eq!(status(&r, &id1)["state"], "issued");

	// An order its maker can refund within six hours: 300 blocks at 60 s.
	let soon = order_terms(&r, height(&r) + 300, "maker of a short order");
	let (short, _) = rest(&mut r, &soon, 600_000);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let (body, _) = take_body(&[&c2], short, &soon, 600_000, filled, &leaf_of("t2 new", filled), (y, fee), s, chain);
	refused(&r, "an order its maker can refund within the margin", &body, "order_expiring", "cannot take back for 360 more blocks");

	// An order filled outside the operator first: spent.
	let third = order_terms(&r, height(&r) + 20_000, "maker of a third order");
	let (taken, _) = rest(&mut r, &third, 600_000);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let fill = outside_fill(&mut r, &third, taken, 600_000);
	r.rt.client().send_raw_transaction(&fill).unwrap();
	let (body, _) = take_body(&[&c2], taken, &third, 600_000, filled, &leaf_of("t2 new", filled), (y, fee), s, chain);
	refused(&r, "an order filled outside the operator, in the mempool", &body, "order_spent", "was filled or refunded before this take");
	r.produce().await;
	r.synced().await;
	refused(&r, "the same, in a block", &body, "order_spent", "is spent");

	// Two takes of one order at once: one is taken, the other refused.
	let fourth = order_terms(&r, height(&r) + 20_000, "maker of a fourth order");
	let (race, _) = rest(&mut r, &fourth, 600_000);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let (t3, t4) = (keypair("taker 3"), keypair("taker 4"));
	let (c3, _) = credited_board(&mut r, &t3, y).await;
	let (c4, _) = credited_board(&mut r, &t4, y).await;
	let (b3, _) = take_body(&[&c3], race, &fourth, 600_000, filled, &leaf_of("t3 new", filled), (y, fee), s, chain);
	let (b4, _) = take_body(&[&c4], race, &fourth, 600_000, filled, &leaf_of("t4 new", filled), (y, fee), s, chain);
	let (h1, h2) = (r.http.clone(), r.http.clone());
	let (a3, a4) = tokio::join!(
		tokio::task::spawn_blocking(move || h1.post("take_order", &b3)),
		tokio::task::spawn_blocking(move || h2.post("take_order", &b4)),
	);
	let mut codes = vec![a3.unwrap(), a4.unwrap()].into_iter()
		.map(|a| if a.status == 200 { "taken".to_string() } else { a.refusal().0 }).collect::<Vec<_>>();
	codes.sort();
	println!("two takes of one order at once: {:?}", codes);
	assert_eq!(codes, vec!["order_taken".to_string(), "taken".to_string()]);
}
