//! Orders resting in the tree (`order-3`), as the `arca` wallet rests, fills,
//! cancels and lands them, against a whole Arca server on an anchored
//! proof-of-stake regtest chain.
//!
//! The maker holds only leaves. It rests an order selling 1,000,000 X for Y
//! at 2/1, lots of 100,000, with `arca order rest`: the fee is quoted and
//! shown, and each refusal is printed as the wallet words it. Once the
//! operator's round is final its `sync` hands over the forfeit and publishes
//! the order; the maker's process then stops. Two takers holding leaves of Y
//! fill it in part, one after the other, with `arca order fill-resting`, each
//! checking the order's coin against its round and holding a leaf of X
//! afterwards. The maker comes back: one `sync` takes up both credits (leaves
//! of Y under its credit keys) and the order resting at the second
//! remainder; `arca order resting` shows both fills. It cancels what rests,
//! and a fill after the cancel is refused. A second maker rests an order and
//! takes it home with `arca exit`: the coin is unrolled, its landing waits
//! out the exit delay (refused before it by the node) and then moves the
//! whole of it into SeqDEX's own order, which a taker on the chain fills
//! with no signature, paying the order key's output.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::str::FromStr;

use elements::{AssetId, OutPoint, Script, Transaction, TxOut};
use serde_json::{json, Value};

use arca_covenant::{CoinRecord, ExplicitOutput};
use common::cli::Arca;
use common::running::Running;
use server::server::AssetSection;
use server::store::RoundState;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn create_args<'a>(server: &'a str, node: &'a str) -> Vec<&'a str> {
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

/// A wallet holding one coin of `asset`, boarded, and `fees` of X on the
/// chain for the fees of what it takes home.
async fn holder(r: &mut Running, name: &str, asset: AssetId, value: u64, fees: u64) -> Arca {
	let (url, node) = (r.url(), r.node_url());
	let w = Arca::new(name);
	w.ok(&create_args(&url, &node));
	let s = script(&w.ok(&["address"]));
	r.pay_to(s.clone(), asset, value + 100_000);
	if fees > 0 {
		let x = r.x;
		r.pay_to(s, x, fees);
	}
	r.produce().await;
	w.ok(&["board", &asset.to_string(), &value.to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
	w
}

fn live_of(w: &Arca, asset: AssetId) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == json!(asset.to_string())).cloned().collect()
}

/// Runs the operator's rounds until none waits, makes them final, and syncs
/// `wallets` (which hands over their forfeits and takes their leaves).
async fn rounds(r: &mut Running, wallets: &[&Arca]) {
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	assert!(!built.is_empty(), "a round");
	r.produce().await;
	r.bury().await;
	r.synced().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	for w in wallets {
		w.ok(&["sync"]);
	}
}

/// Rests `amount` of X for Y at 2/1 in lots of `lot`, quoted then shown, and
/// runs its round: the order's id once the maker's `sync` published it, and
/// the script its landed order's fills pay.
async fn rest(r: &mut Running, maker: &Arca, amount: u64, lot: u64) -> (String, Script) {
	let x = r.x;
	let y = r.y;
	let args = |extra: &[&str]| -> Vec<String> {
		let mut v: Vec<String> = ["order", "rest", "--sell", &x.to_string(), "--amount", &amount.to_string(), "--for", &y.to_string(),
			"--rate-num", "2", "--rate-den", "1", "--min-lot", &lot.to_string(), "--expires-in-hours", "720"]
			.iter().map(|s| s.to_string()).collect();
		v.extend(extra.iter().map(|s| s.to_string()));
		v
	};
	let run = |a: &[String]| -> Vec<String> { a.to_vec() };
	let q = maker.ok(&run(&args(&["--quote"])).iter().map(|s| s.as_str()).collect::<Vec<_>>());
	println!("the quote: fee {} of X, change {}, full price {} of Y", q["fee"]["amount"], q["change"], q["full_price"]);
	let shown = q.to_string();
	let a = args(&["--shown", &shown]);
	let rested = maker.ok(&a.iter().map(|s| s.as_str()).collect::<Vec<_>>());
	assert_eq!(rested["state"], "pending", "{}", rested);
	let pays = Script::from(unhex(rested["landed_pays"].as_str().unwrap()));
	rounds(r, &[maker]).await;
	let view = maker.ok(&["order", "resting"]);
	let mine = view["orders"].as_array().unwrap().iter().find(|o| o["rested_by"] == rested["order"]).unwrap().clone();
	assert_eq!(mine["state"], "published", "the maker's sync published the order: {}", view);
	assert_eq!(mine["operator"]["state"], "resting", "{}", mine);
	assert_eq!(mine["operator"]["value"], json!(amount.to_string()));
	(mine["order"].as_str().unwrap().to_string(), pays)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_order_rests_in_the_tree_fills_with_its_maker_away_and_lands() {
	let mut r = Running::start_with(|c, x, _| {
		c.assets[0] = AssetSection::new(x, 1_000);
	}).await;
	let (x, y) = (r.x, r.y);
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	let maker = holder(&mut r, "RM", x, 1_500_000, 0).await;

	// What the wallet refuses before it signs anything.
	let base = |extra: &[&str]| -> Vec<String> {
		let mut v: Vec<String> = ["order", "rest", "--sell", &x.to_string(), "--amount", "1000000", "--for", &y.to_string(),
			"--rate-num", "2", "--rate-den", "1", "--min-lot", "100000"].iter().map(|s| s.to_string()).collect();
		v.extend(extra.iter().map(|s| s.to_string()));
		v
	};
	let s = |a: &[String]| -> Vec<String> { a.to_vec() };
	let refuse = |a: Vec<String>, why: &str| { maker.refused(&a.iter().map(|x| x.as_str()).collect::<Vec<_>>(), why); };
	refuse(s(&base(&["--expires", "1000"])), "is a height");
	refuse(s(&base(&["--expires-in-hours", "2"])), "the operator co-signs no fill of an order refundable within");
	let mut big = base(&["--expires-in-hours", "720"]);
	big[5] = "5000000".into();
	refuse(big, "the wallet's live coins of asset");
	let mut alike = base(&["--expires-in-hours", "720"]);
	alike[7] = x.to_string();
	refuse(alike, "sells and is paid in the same asset");
	let mut small = base(&["--expires-in-hours", "720"]);
	small[13] = "2000000".into();
	refuse(small, "below its own min_lot");

	// A wallet holding only a board of Y made before the order's round: the
	// board's service expiry comes before the order's coin expires, so the
	// operator takes no fill paid with it, and the wallet does not offer one.
	let t0 = holder(&mut r, "RT0", y, 1_000_000, 0).await;
	// The board's service expiry and the order coin's expiry are both 28 days
	// after the median time of their blocks: the chain's clock moves on an
	// hour first, so the board's comes earlier by that hour, not by however
	// far the clock moved between the two blocks (which can be nothing).
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 3600));
	r.synced().await;

	// M rests its order, and stops.
	let (order, _) = rest(&mut r, &maker, 1_000_000, 100_000).await;
	println!("M rests order {} and stops", order);
	t0.refused(&["order", "fill-resting", &order, "--amount", "100000", "--quote"], "that expire no earlier than the order's coin");

	// Two takers fill it in part, each from a leaf of Y.
	let t1 = holder(&mut r, "RT1", y, 1_000_000, 0).await;
	let t2 = holder(&mut r, "RT2", y, 1_000_000, 0).await;
	t1.refused(&["order", "fill-resting", &order, "--amount", "99999"], "below the order's min_lot");
	t1.refused(&["order", "fill-resting", &order, "--amount", "950000"], "below the order's min_lot of");
	t1.refused(&["order", "fill-resting", &"00".repeat(32), "--amount", "100000"], "has no resting order");
	// T2 is shown a fill of the order where it rests now; T1's fill moves it
	// before T2 goes ahead.
	let q2 = t2.ok(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
	assert_eq!((q2["coin"].as_str(), q2["paid"].as_str(), q2["gets"]["amount"].as_str()), (Some(order.as_str()), Some("400000"), Some("200000")), "{}", q2);
	assert_eq!(q2["fee"]["asset"], json!(y.to_string()), "the fee is in the asset paid: {}", q2);
	let f1 = t1.ok(&["order", "fill-resting", &order, "--amount", "300000"]);
	assert_eq!((f1["filled"].as_str(), f1["paid"].as_str()), (Some("300000"), Some("600000")), "{}", f1);
	let got1 = live_of(&t1, x);
	assert_eq!(got1.len(), 1, "T1 holds a leaf of X: {:?}", got1);
	assert_eq!(got1[0]["value"], "300000");
	// T2's fill as it was shown: the order has moved, the operator refuses it
	// and T2's coins are its own again; a new quote names the coin it rests at.
	t2.refused(&["order", "fill-resting", &order, "--amount", "200000", "--shown", &q2.to_string()], "rests at coin");
	assert_eq!(live_of(&t2, y).len(), 1, "T2's coin of Y is live again");
	let q2b = t2.ok(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
	assert_ne!(q2b["coin"], q2["coin"], "the order rests at its remainder: {}", q2b);
	assert_eq!(q2b["rests"], "700000");
	let f2 = t2.ok(&["order", "fill-resting", &order, "--amount", "200000", "--shown", &q2b.to_string()]);
	assert_eq!((f2["paid"].as_str(), f2["fee"].as_str()), (Some("400000"), q2b["fee"]["amount"].as_str()), "{}", f2);
	assert_eq!(live_of(&t2, x)[0]["value"], "200000");
	println!("T1 and T2 filled 300,000 and 200,000 X, each holding its leaf of X");

	// M comes back.
	let back = maker.ok(&["sync"]);
	println!("M's sync on return: {}", back["mailbox"]);
	let view = maker.ok(&["order", "resting"]);
	let mine = view["orders"].as_array().unwrap().iter().find(|o| o["order"] == json!(order)).unwrap().clone();
	assert_eq!(mine["operator"]["value"], "500000", "{}", mine);
	assert_eq!(mine["operator"]["fills"].as_array().unwrap().len(), 2);
	let credits: Vec<u64> = mine["credits"].as_array().unwrap().iter().map(|c| c["value"].as_str().unwrap().parse().unwrap()).collect();
	assert_eq!(credits, vec![600_000, 400_000], "both credits taken up: {}", mine);
	let rest_coin = maker.ok(&["coins"]).as_array().unwrap().iter()
		.find(|c| c["leaf_id"] == mine["operator"]["coin"]).cloned().unwrap_or_else(|| panic!("the remainder is held: {}", mine));
	assert_eq!((rest_coin["state"].as_str(), rest_coin["value"].as_str()), (Some("live"), Some("500000")));
	assert!(live_of(&maker, y).len() >= 2, "the credits are live coins of Y");

	// M cancels what rests, as the quote showed it; a fill after the cancel is refused.
	let cq = maker.ok(&["order", "cancel-resting", &order, "--quote"]);
	assert_eq!((cq["coin"].clone(), cq["holds"].as_str()), (mine["operator"]["coin"].clone(), Some("500000")), "{}", cq);
	let fee: u64 = cq["fee"]["amount"].as_str().unwrap().parse().unwrap();
	assert_eq!(cq["gets"]["amount"], json!((500_000 - fee).to_string()), "{}", cq);
	let cancelled = maker.ok(&["order", "cancel-resting", &order, "--shown", &cq.to_string()]);
	assert_eq!(cancelled["state"], "cancelled");
	let view = maker.ok(&["order", "resting"]);
	let mine = view["orders"].as_array().unwrap().iter().find(|o| o["order"] == json!(order)).unwrap().clone();
	assert_eq!(mine["operator"]["state"], "cancelled", "{}", mine);
	t2.refused(&["order", "fill-resting", &order, "--amount", "100000"], "it takes no fill");

	// A second maker rests an order and brings it home: it lands as SeqDEX's.
	let n = holder(&mut r, "RN", x, 1_500_000, 200_000).await;
	let (order2, maker_script) = rest(&mut r, &n, 1_000_000, 100_000).await;
	let coin2 = order2.clone();
	let e = n.ok(&["exit", &coin2]);
	assert!(matches!(e["state"].as_str(), Some("unrolling" | "waiting")), "{}", e);
	for _ in 0..6 {
		r.produce().await;
		let e = n.ok(&["exit", &coin2]);
		if e["state"] == "waiting" {
			break;
		}
	}
	let e = n.ok(&["exit", &coin2]);
	assert_eq!(e["state"], "waiting", "the landing waits out the exit delay: {}", e);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 512));
	let e = n.ok(&["exit", &coin2]);
	assert_eq!(e["state"], "claimed", "{}", e);
	r.produce().await;
	let landing_id = elements::Txid::from_str(e["claim"]["txid"].as_str().unwrap()).unwrap();
	let landing = r.rt.client().raw_transaction(&landing_id).unwrap();
	let rec = n.ok(&["record", &coin2]);
	let record = CoinRecord::from_bytes(&unhex(rec["record"].as_str().unwrap())).unwrap();
	let policy = record.order_policy().unwrap();
	assert_eq!(landing.output[0].script_pubkey, policy.landed.script_pubkey(), "the landing pays SeqDEX's order for the same terms");
	assert_eq!(landing.output[0].value.explicit(), Some(1_000_000));
	println!("N's order landed as SeqDEX's order: {} ({} vB)", landing_id, landing.vsize());

	// A taker on the chain fills 100,000 X of it, no signature.
	let pay = r.pay_to(common::node::op_true(), y, 1_000_000);
	let fee = r.pay_to(common::node::op_true(), x, 100_000);
	r.produce().await;
	let landed_at = OutPoint::new(landing_id, 0);
	let lf = 100_000u64;
	let explicit = |a: AssetId, v: u64, spk: Script| ExplicitOutput::new(a, v, spk).txout();
	let mut tx = Transaction {
		version: 2, lock_time: elements::LockTime::ZERO,
		input: [landed_at, OutPoint::new(pay.txid(), 0), OutPoint::new(fee.txid(), 0)].iter()
			.map(|o| elements::TxIn { previous_output: *o, sequence: elements::Sequence(0xffff_ffff), ..Default::default() }).collect(),
		output: vec![
			explicit(y, 2 * lf, maker_script.clone()), explicit(x, 1_000_000 - lf, policy.landed.script_pubkey()), explicit(x, lf, common::node::op_true()),
			explicit(y, 1_000_000 - 2 * lf, common::node::op_true()), explicit(x, 100_000 - 3_000, common::node::op_true()),
			TxOut::new_fee(3_000, x),
		],
	};
	assert_eq!(arca_covenant::script::sha256(maker_script.as_bytes()), policy.landed.maker, "the landed order pays the order key's output");
	tx.input[0].witness.script_witness = policy.landed.fill_witness(true);
	let filled = r.rt.client().send_raw_transaction(&tx).unwrap();
	r.produce().await;
	println!("a taker on the chain filled 100,000 X of the landed order: {} ({} vB)", filled, tx.vsize());
	assert!(r.rt.client().raw_transaction(&filled).is_ok());
}
