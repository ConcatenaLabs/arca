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
//! afterwards; the first fills from a `vtxo-2` leaf, whose checkpoint's pair
//! names the order's coin beside it. The maker comes back: one `sync` takes up both credits (leaves
//! of Y under its credit keys) and the order resting at the second
//! remainder; `arca order resting` shows both fills. It cancels what rests,
//! and a fill after the cancel is refused. A second maker rests an order and
//! takes it home with `arca exit`: the coin is unrolled, its landing waits
//! out the exit delay (refused before it by the node) and then moves the
//! whole of it into SeqDEX's own order, which a taker on the chain fills
//! with no signature, paying the order key's output. Last, the first taker
//! takes its leaf of X home: the fill reaches the chain, its `vtxo-2`
//! checkpoint spent at input 1 by `arca/collab-2`.
//!
//! A taker's quote of a resting order reads the order's round where the
//! operator says it is, never scanning the node's unspent outputs for it.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::str::FromStr;

use elements::{AssetId, OutPoint, Script, Transaction, TxOut};
use serde_json::{json, Value};

use arca_covenant::{CoinRecord, ExplicitOutput};
use common::cli::Arca;
use common::proxy::Proxy;
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
	// T1 refreshes its board into a vtxo-2 leaf, which it fills from.
	assert_eq!(t1.ok(&["leaf-template", "vtxo-2"])["leaf_template"], "vtxo-2");
	t1.ok(&["participate"]);
	rounds(&mut r, &[&t1]).await;
	let l1 = live_of(&t1, y);
	assert!(l1.len() == 1 && l1[0]["template"] == "vtxo-2", "T1 holds a vtxo-2 leaf of Y: {:?}", l1);
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

	// T1 takes home the leaf of X its fill made: the fill reaches the chain,
	// T1's vtxo-2 checkpoint spent at input 1, beside the order's coin, by
	// arca/collab-2.
	let t1_x = got1[0]["leaf_id"].as_str().unwrap().to_string();
	let mut broadcast: Vec<String> = vec![];
	let mut claimed = false;
	for _ in 0..16 {
		let e = t1.ok(&["exit", &t1_x]);
		for t in e["broadcast"].as_array().into_iter().flatten() {
			if let Some(id) = t.as_str().or_else(|| t["txid"].as_str()) {
				broadcast.push(id.to_string());
			}
		}
		if e["state"] == "claimed" {
			claimed = true;
			break;
		}
		r.produce().await;
		r.synced().await;
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 600));
		r.synced().await;
	}
	assert!(claimed, "T1's leaf of X claimed");
	r.produce().await;
	let cmr = arca_covenant::collab::collab_cmr().to_vec();
	let mut in_fill = false;
	for id in broadcast.iter().filter_map(|t| elements::Txid::from_str(t).ok()) {
		let tx = r.rt.client().raw_transaction(&id).unwrap();
		for (i, input) in tx.input.iter().enumerate() {
			let w = arca_covenant::witness::without_annex(&input.witness.script_witness);
			if w.len() == 4 && w[2] == cmr {
				println!("on the chain: {} input {} of {} spends by arca/collab-2 ({} vB)", id, i, tx.input.len(), tx.vsize());
				in_fill |= i >= 1;
			}
		}
	}
	assert!(in_fill, "the fill on the chain, T1's vtxo-2 checkpoint at input 1 by arca/collab-2: {:?}", broadcast);
}

/// The node RPC methods `calls` (a node proxy's log) asked, batches included.
fn node_methods(calls: &[common::proxy::Logged]) -> Vec<String> {
	let mut out = vec![];
	for (_, req, ..) in calls {
		let reqs = match req.as_array() {
			Some(a) => a.clone(),
			None => vec![req.clone()],
		};
		out.extend(reqs.iter().filter_map(|q| q["method"].as_str().map(String::from)));
	}
	out
}

/// A taker's quote of a resting order finds the order's coin where the
/// operator says its round is (`batch_status`), read by txid, and never scans
/// the node's set of unspent outputs for it: on a node many wallets share,
/// that `scantxoutset` took five minutes ahead of every quote, and the
/// wallet answered nothing else meanwhile.
#[tokio::test(flavor = "multi_thread")]
async fn a_resting_quote_reads_the_orders_round_without_a_scan() {
	let mut r = Running::start_with(|c, x, _| {
		c.assets[0] = AssetSection::new(x, 1_000);
	}).await;
	let (x, y) = (r.x, r.y);
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	let maker = holder(&mut r, "SM", x, 1_500_000, 0).await;
	let (order, _) = rest(&mut r, &maker, 1_000_000, 100_000).await;

	// The taker's node is a proxy that logs every call.
	let node = Proxy::start(r.node_url().trim_end_matches('/'));
	let t = Arca::new("ST");
	t.ok(&create_args(&r.url(), &node.url));
	let s = script(&t.ok(&["address"]));
	r.pay_to(s, y, 1_100_000);
	r.produce().await;
	t.ok(&["board", &y.to_string(), "1000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || t.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	t.ok(&["sync"]);

	let from = node.calls().len();
	let q = t.ok(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
	assert_eq!((q["coin"].as_str(), q["gets"]["amount"].as_str()), (Some(order.as_str()), Some("200000")), "{}", q);
	let asked = node_methods(&node.calls()[from..]);
	println!("the quote asked the node: {:?}", asked);
	assert!(!asked.iter().any(|m| m == "scantxoutset"), "no scan of the node's unspent outputs: {:?}", asked);
	let f = t.ok(&["order", "fill-resting", &order, "--amount", "200000", "--shown", &q.to_string()]);
	assert_eq!(f["filled"], "200000", "{}", f);
}

/// With the checkpoint exit required, a resting fill the fill itself would
/// refuse is refused already at its quote (here the operator offers no exit),
/// so a program leaves the order out of its prices; without the requirement
/// the same quote answers.
#[tokio::test(flavor = "multi_thread")]
async fn a_resting_quote_is_refused_as_the_fill_would_be_when_the_exit_is_required() {
	let mut r = Running::start_with(|c, x, _| {
		c.assets[0] = AssetSection::new(x, 1_000);
		c.checkpoint_exit = false;
	}).await;
	let (x, y) = (r.x, r.y);
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	let maker = holder(&mut r, "SQ M", x, 1_500_000, 0).await;
	let (order, _) = rest(&mut r, &maker, 1_000_000, 100_000).await;
	let t = holder(&mut r, "SQ T", y, 1_000_000, 0).await;
	t.ok(&["require-checkpoint-exit", "on"]);
	let why = t.refused(&["order", "fill-resting", &order, "--amount", "200000", "--quote"], "require-checkpoint-exit");
	println!("the quote with the exit required: {}", why);
	assert!(why.contains("the operator does not offer it"), "{}", why);
	t.ok(&["require-checkpoint-exit", "off"]);
	let q = t.ok(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
	assert_eq!(q["gets"]["amount"], "200000", "{}", q);
}

/// A copy of the wallet in `from`'s directory, as a second device holding
/// the same mnemonic and the same store holds it.
fn second_device(from: &Arca, name: &str) -> Arca {
	fn copy(a: &std::path::Path, b: &std::path::Path) {
		std::fs::create_dir_all(b).unwrap();
		for e in std::fs::read_dir(a).unwrap() {
			let e = e.unwrap();
			if e.file_type().unwrap().is_dir() { copy(&e.path(), &b.join(e.file_name())) } else { std::fs::copy(e.path(), b.join(e.file_name())).unwrap(); }
		}
	}
	let d = Arca::new(name);
	copy(&from.dir, &d.dir);
	d
}

/// One phrase on two devices: the second gives the taker's coin to a round;
/// the first, not caught up, fills a resting order from it. The operator
/// refuses the fill (`double_spend`), and the wallet reads what its other
/// store did at once, as it does for a refused transfer (arca #809): it no
/// longer counts the coin given up, holds the round's coin in its place, and
/// the same fill asked again goes from it (arca #839).
#[tokio::test(flavor = "multi_thread")]
async fn a_fill_refused_for_a_coin_spent_elsewhere_catches_up_at_once() {
	let mut r = Running::start_with(|c, x, _| {
		c.assets[0] = AssetSection::new(x, 1_000);
	}).await;
	let (x, y) = (r.x, r.y);
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	let maker = holder(&mut r, "CM", x, 1_500_000, 0).await;
	let (order, _) = rest(&mut r, &maker, 1_000_000, 100_000).await;
	let t = holder(&mut r, "CT", y, 1_000_000, 0).await;
	let coin = live_of(&t, y)[0]["leaf_id"].as_str().unwrap().to_string();
	// The second device gives the coin to a round.
	let t2 = second_device(&t, "CT2");
	t2.ok(&["participate", "--leaf", &coin]);
	rounds(&mut r, &[&t2]).await;
	let fresh: Vec<String> = live_of(&t2, y).iter().map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
	assert!(!fresh.is_empty() && !fresh.contains(&coin), "the second device holds the round's coin: {:?}", fresh);
	let ids = |w: &Arca| -> Vec<String> { live_of(w, y).iter().map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect() };
	assert_eq!(ids(&t), vec![coin.clone()], "the first device, not caught up, still counts the coin given elsewhere");
	// The first device fills from it.
	let q = t.ok(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
	let (ok, e) = t.run(&["order", "fill-resting", &order, "--amount", "200000", "--shown", &q.to_string()]);
	println!("THE FILL FROM THE COIN GIVEN ELSEWHERE: ok {} {}", ok, e);
	assert!(!ok && e.to_string().contains("double_spend"), "{}", e);
	println!("THE TAKER'S LIVE COINS AFTER THE REFUSAL: {:?}", ids(&t));
	assert!(!ids(&t).contains(&coin), "the coin given elsewhere is no longer counted");
	assert!(fresh.iter().all(|f| ids(&t).contains(f)), "the round's coin is held");
	// The same fill asked again goes from the round's coin.
	let q = t.ok(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
	let f = t.ok(&["order", "fill-resting", &order, "--amount", "200000", "--shown", &q.to_string()]);
	println!("THE FILL ASKED AGAIN: {}", f["filled"]);
	assert_eq!(f["filled"], "200000", "{}", f);
}

/// Builds the rounds waiting, has `wallets` hand over their forfeits, and
/// broadcasts them, without making them final: the round ids.
async fn rounds_broadcast(r: &mut Running, wallets: &[&Arca]) -> Vec<elements::Txid> {
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty() && !built.is_empty(), "{} built, {} failed", built.len(), failed.len());
	for w in wallets {
		w.ok(&["sync"]);
	}
	r.server.rounds.pass().await.unwrap();
	built.iter().map(|b| b.tx.txid()).collect()
}

/// Makes the rounds `txids` final and syncs `wallets`.
async fn rounds_final(r: &mut Running, txids: &[elements::Txid], wallets: &[&Arca]) {
	r.produce().await;
	r.bury().await;
	r.synced().await;
	for tx in txids {
		r.round_state(tx, RoundState::Final).await;
	}
	for w in wallets {
		w.ok(&["sync"]);
	}
}

/// [`rest`] on an operator whose forfeits are handed over before its round
/// is broadcast (batches without a sweep): the order's id.
async fn rest_no_sweep(r: &mut Running, maker: &Arca, amount: u64, lot: u64) -> String {
	let (x, y) = (r.x, r.y);
	let args = |extra: &[&str]| -> Vec<String> {
		let mut v: Vec<String> = ["order", "rest", "--sell", &x.to_string(), "--amount", &amount.to_string(), "--for", &y.to_string(),
			"--rate-num", "2", "--rate-den", "1", "--min-lot", &lot.to_string(), "--expires-in-hours", "720"]
			.iter().map(|s| s.to_string()).collect();
		v.extend(extra.iter().map(|s| s.to_string()));
		v
	};
	let q = maker.ok(&args(&["--quote"]).iter().map(|s| s.as_str()).collect::<Vec<_>>());
	let shown = q.to_string();
	let rested = maker.ok(&args(&["--shown", &shown]).iter().map(|s| s.as_str()).collect::<Vec<_>>());
	assert_eq!(rested["state"], "pending", "{}", rested);
	let txids = rounds_broadcast(r, &[maker]).await;
	rounds_final(r, &txids, &[maker]).await;
	maker.ok(&["sync"]);
	let view = maker.ok(&["order", "resting"]);
	let mine = view["orders"].as_array().unwrap().iter().find(|o| o["rested_by"] == rested["order"]).unwrap().clone();
	assert_eq!(mine["state"], "published", "{}", view);
	mine["order"].as_str().unwrap().to_string()
}

/// RV46's P6, on an operator like the testnet's (batches without a sweep,
/// forfeits handed over before the round is broadcast, no checkpoint exit;
/// `ARCA_TEST_ANCHOR_DEPTH=0` for its anchor depth): the second device's
/// round that spends the coin is broadcast and not final, so its
/// participation is not released and a catch-up finds nothing yet. The fill
/// from the coin is refused `double_spend`; the coin is then held out of
/// every spend until a catch-up settles it: the quote asked again at once
/// does not give it, but waits for a round (`settle_first`, naming it), and
/// `settle_first` waits for it, until the round is final. Then a sync
/// catches up (not ten minutes later), the wallet holds the round's coin in
/// its place, `settle_first` answers ready, and the fill goes from that
/// coin. Before, the quote gave the dead coin again and again, and a page's
/// re-prices, all within that window, ended the trade "Returned".
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_spent_in_another_devices_round_not_final_is_held_out_until_caught_up() {
	let mut r = Running::start_with(|c, x, _| {
		c.assets[0] = AssetSection::new(x, 1_000);
		c.checkpoint_exit = false;
		c.batches.no_sweep = true;
		c.batches.holder_batches = Some(0);
		c.batches.collect_after_seconds = Some(2_419_200);
	}).await;
	let (x, y) = (r.x, r.y);
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	let maker = holder(&mut r, "HM", x, 1_500_000, 0).await;
	let order = rest_no_sweep(&mut r, &maker, 1_000_000, 100_000).await;
	let t = holder(&mut r, "HT", y, 1_000_000, 0).await;
	let coin = live_of(&t, y)[0]["leaf_id"].as_str().unwrap().to_string();
	let t2 = second_device(&t, "HT2");
	t2.ok(&["participate", "--leaf", &coin]);
	let txids = rounds_broadcast(&mut r, &[&t2]).await;
	let ids = |w: &Arca| -> Vec<String> { live_of(w, y).iter().map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect() };

	// The fill from the coin, the other device's round broadcast, not final.
	let q = t.ok(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
	let (ok, e) = t.run(&["order", "fill-resting", &order, "--amount", "200000", "--shown", &q.to_string()]);
	println!("THE FILL, THE OTHER DEVICE'S ROUND NOT FINAL: ok {} {}", ok, e);
	assert!(!ok && e.to_string().contains("double_spend"), "{}", e);
	// The quote asked again at once: the dead coin is not given; the trade waits for that round.
	let (ok, q2) = t.run(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
	println!("THE QUOTE ASKED AGAIN AT ONCE: ok {} {}", ok, q2);
	assert!(!ok, "the coin spent elsewhere is not given again: {}", q2);
	assert_eq!(q2["error"]["kind"], "settle_first", "{}", q2);
	assert_eq!(q2["error"]["coins"], json!([coin]), "{}", q2);
	assert!(q2["error"]["message"].as_str().unwrap().contains("given up by another device of this wallet"), "{}", q2);
	let (_, s1) = t.run(&["settle-first", "--coin", &coin]);
	println!("SETTLE FIRST WHILE NOT FINAL: {}", s1);
	assert_eq!(s1["ready"], false, "{}", s1);
	assert_eq!(s1["waiting"], json!([coin]), "nothing given up for a coin another device spent: {}", s1);
	assert_eq!(s1["settling"], json!([]), "{}", s1);

	// The round final: a sync catches up at once, and the wallet holds the round's coin.
	rounds_final(&mut r, &txids, &[&t2]).await;
	t.ok(&["sync"]);
	let fresh = ids(&t2);
	println!("THE TAKER'S LIVE Y ONCE THE ROUND IS FINAL AND IT SYNCED: {:?} (the second device: {:?})", ids(&t), fresh);
	assert!(!ids(&t).contains(&coin), "the coin given elsewhere is no longer counted");
	assert!(!fresh.is_empty() && fresh.iter().all(|f| ids(&t).contains(f)), "the round's coin is held");
	let (_, s2) = t.run(&["settle-first", "--coin", &coin]);
	println!("SETTLE FIRST ONCE CAUGHT UP: {}", s2);
	assert_eq!(s2["ready"], true, "{}", s2);
	let q3 = t.ok(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
	let f = t.ok(&["order", "fill-resting", &order, "--amount", "200000", "--shown", &q3.to_string()]);
	println!("THE FILL ASKED AGAIN: {}", f["filled"]);
	assert_eq!(f["filled"], "200000", "{}", f);
}

// ---------------------------------------------------------------------------
// A coin held out as spent elsewhere is the operator's word with an age
// (RV48 on arca #852): the hold ends when the operator serves the coin live
// again, when a catch-up settles it, or at the latest once the wait the
// wallet stated for it has passed; only a new refusal sets it again. While
// it holds, the coin is the wallet's (in its balance) and not spendable now,
// and its exit is never barred.
// ---------------------------------------------------------------------------

/// An operator like the testnet's: batches without a sweep, forfeits handed
/// over before broadcast, no checkpoint exit (`ARCA_TEST_ANCHOR_DEPTH=0` for
/// its anchor depth).
fn testnet_like(c: &mut server::server::Config, x: AssetId) {
	c.assets[0] = AssetSection::new(x, 1_000);
	c.checkpoint_exit = false;
	c.batches.no_sweep = true;
	c.batches.holder_batches = Some(0);
	c.batches.collect_after_seconds = Some(2_419_200);
}

/// The operator's state of leaf `leaf`.
fn server_state(r: &Running, leaf: &str) -> String {
	let id: [u8; 32] = unhex(leaf).try_into().unwrap();
	let row = tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(r.server.store.leaf(&id))).unwrap().unwrap();
	format!("{:?}", row.state)
}

/// A holder whose wallet talks to the operator at `url` (a proxy).
async fn holder_at(r: &mut Running, name: &str, url: &str, asset: AssetId, value: u64) -> Arca {
	let node = r.node_url();
	let w = Arca::new(name);
	w.ok(&create_args(url, &node));
	let s = script(&w.ok(&["address"]));
	r.pay_to(s, asset, value + 100_000);
	r.produce().await;
	w.ok(&["board", &asset.to_string(), &value.to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
	w
}

/// While `coin` (`value` of `y`) is held out: the balance keeps it, apart
/// (`spent_elsewhere`); what is spendable now leaves it out; settle-first
/// waits for it no longer than its hold has left, which is what it states.
/// The seconds its hold has left.
fn assert_held(tag: &str, t: &Arca, coin: &str, value: u64, y: AssetId) -> u64 {
	let b = t.ok(&["balance"]);
	println!("{} BALANCE: arca {} held {}", tag, b["arca"][y.to_string()], b["held"][y.to_string()]);
	assert_eq!(b["arca"][y.to_string()]["spent_elsewhere"], value.to_string(), "kept in the balance, apart: {}", b);
	let held: u64 = b["held"][y.to_string()].as_str().unwrap().parse().unwrap();
	assert!(held >= value, "the wallet's still, in what it holds: {}", b);
	let p = t.ok(&["coin-places"]);
	let line = p["coins"].as_array().unwrap().iter().find(|c| c["leaf_id"] == coin).cloned().unwrap();
	println!("{} COIN-PLACES spendable {} | the coin {}", tag, p["spendable"], line);
	assert!(p["spendable"][y.to_string()].is_null() || p["spendable"][y.to_string()] == "0", "not spendable now: {}", p["spendable"]);
	let until = line["spent_elsewhere_until"].as_u64().unwrap_or_else(|| panic!("the hold's end is shown: {}", line));
	let (_, s) = t.run(&["settle-first", "--coin", coin]);
	println!("{} SETTLE-FIRST: {}", tag, s);
	assert_eq!(s["ready"], false, "{}", s);
	assert_eq!(s["waiting"], json!([coin]), "{}", s);
	let left = s["final_in_seconds"].as_u64().unwrap();
	assert!(left > 0 && left == s["usual_in_seconds"].as_u64().unwrap(), "the wait stated is the hold's, which ends: {}", s);
	println!("{} THE HOLD ENDS AT MEDIAN TIME {} ({} s left)", tag, until, left);
	left
}

/// The fill from `coin` asked again goes: the coin is spendable again.
fn assert_free(tag: &str, t: &Arca, order: &str, coin: &str, y: AssetId) {
	let b = t.ok(&["balance"]);
	assert!(b["arca"][y.to_string()]["spent_elsewhere"].is_null(), "{}: no longer held: {}", tag, b);
	let (ok, q) = t.run(&["order", "fill-resting", order, "--amount", "200000", "--quote"]);
	println!("{} THE QUOTE: ok {} gives {}", tag, ok, q["gives"]);
	assert!(ok, "{}: the coin is spendable again: {}", tag, q);
	assert!(q.to_string().contains(coin), "{}: from the coin: {}", tag, q);
	let f = t.ok(&["order", "fill-resting", order, "--amount", "200000", "--shown", &q.to_string()]);
	println!("{} THE FILL: {}", tag, f["filled"]);
	assert_eq!(f["filled"], "200000", "{}", f);
}

/// The second device gives `coin` to a participation of its own, not yet in
/// a round; the first device's fill from it is refused `double_spend`, and
/// the coin is held. -> (the participation's id, the order).
async fn held_by_a_pending_participation(r: &mut Running, tag: &str) -> (Arca, Arca, String, String, String) {
	let (x, y) = (r.x, r.y);
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	let maker = holder(r, &format!("{} M", tag), x, 1_500_000, 0).await;
	let order = rest_no_sweep(r, &maker, 1_000_000, 100_000).await;
	let t = holder(r, &format!("{} T", tag), y, 1_000_000, 0).await;
	let coin = live_of(&t, y)[0]["leaf_id"].as_str().unwrap().to_string();
	let t2 = second_device(&t, &format!("{} T2", tag));
	let p = t2.ok(&["participate", "--leaf", &coin]);
	let pid = p["participations"][0]["participation"].as_str().or(p["participations"][0]["id"].as_str())
		.unwrap_or_else(|| panic!("no participation id: {}", p)).to_string();
	println!("{} THE SECOND DEVICE GIVES THE COIN: participation {} | operator's leaf {}", tag, pid, server_state(r, &coin));
	let q = t.ok(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
	let (ok, e) = t.run(&["order", "fill-resting", &order, "--amount", "200000", "--shown", &q.to_string()]);
	println!("{} THE FILL: ok {} {}", tag, ok, e);
	assert!(!ok && e.to_string().contains("double_spend"), "{}", e);
	assert_held(&format!("{} HELD", tag), &t, &coin, 1_000_000, y);
	(t, t2, pid, order, coin)
}

/// RV48 A: the other device withdraws its participation (as the wallet does
/// by itself when a trade falls short): the operator serves the coin live
/// again, and the next sync ends the hold. Before, the coin stayed held
/// out after any number of syncs and after ten minutes.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_coin_is_free_again_once_the_other_devices_participation_is_withdrawn() {
	let mut r = Running::start_with(|c, x, _| testnet_like(c, x)).await;
	let y = r.y;
	let (t, t2, pid, order, coin) = held_by_a_pending_participation(&mut r, "HW").await;
	let w = t2.ok(&["withdraw-participation", &pid]);
	println!("HW THE SECOND DEVICE WITHDRAWS: {} | operator's leaf {}", w["state"], server_state(&r, &coin));
	assert_eq!(server_state(&r, &coin), "Live");
	let s = t.ok(&["sync"]);
	println!("HW ONE SYNC: caught_up {}", s["caught_up"]);
	assert_eq!(s["caught_up"]["live_again"], json!([coin]), "{}", s["caught_up"]);
	assert_free("HW", &t, &order, &coin, y);
}

/// The operator voids the other device's participation: the same.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_coin_is_free_again_once_the_other_devices_participation_is_voided() {
	let mut r = Running::start_with(|c, x, _| testnet_like(c, x)).await;
	let y = r.y;
	let (t, _t2, pid, order, coin) = held_by_a_pending_participation(&mut r, "HV").await;
	let id: [u8; 32] = unhex(&pid).try_into().unwrap();
	assert!(r.server.store.void_participation(&id, "voided by the test's operator").await.unwrap());
	println!("HV VOIDED | operator's leaf {}", server_state(&r, &coin));
	assert_eq!(server_state(&r, &coin), "Live");
	t.ok(&["sync"]);
	assert_free("HV", &t, &order, &coin, y);
}

/// The other device's round is built and held for its forfeits, which never
/// come: the operator drops it before broadcast. However the operator then
/// treats the participation (given back, or run again later), the hold ends
/// at the latest once the wait stated for it has passed, and the coin is
/// then offered again: spendable when the operator gave it back, or refused
/// again (one more stated wait) when it is still spent there.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_coin_whose_other_round_is_dropped_before_broadcast_is_never_held_for_good() {
	let mut r = Running::start_with(|c, x, _| testnet_like(c, x)).await;
	let (x, y) = (r.x, r.y);
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	let maker = holder(&mut r, "HD M", x, 1_500_000, 0).await;
	let order = rest_no_sweep(&mut r, &maker, 1_000_000, 100_000).await;
	let t = holder(&mut r, "HD T", y, 1_000_000, 0).await;
	let coin = live_of(&t, y)[0]["leaf_id"].as_str().unwrap().to_string();
	let t2 = second_device(&t, "HD T2");
	t2.ok(&["participate", "--leaf", &coin]);
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	assert_eq!(built.len(), 1, "the other device's round, held for its forfeits");
	let q = t.ok(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
	let (ok, e) = t.run(&["order", "fill-resting", &order, "--amount", "200000", "--shown", &q.to_string()]);
	assert!(!ok && e.to_string().contains("double_spend"), "{}", e);
	let left = assert_held("HD HELD", &t, &coin, 1_000_000, y);
	// The forfeits never come: the round is dropped.
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 700));
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	let round = r.server.store.round_by_txid(&built[0].tx.txid().to_byte_array()).await.unwrap().unwrap().state;
	println!("HD THE ROUND: {:?} | operator's leaf {}", round, server_state(&r, &coin));
	assert_eq!(round, RoundState::Lost, "dropped before broadcast");
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, left as u32));
	r.synced().await;
	t.ok(&["sync"]);
	let b = t.ok(&["balance"]);
	assert!(b["arca"][y.to_string()]["spent_elsewhere"].is_null(), "the hold ended by its stated wait: {}", b);
	let (ok, q) = t.run(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
	println!("HD THE QUOTE AFTER THE STATED WAIT: ok {} {}", ok, q);
	assert!(ok && q.to_string().contains(&coin), "offered again: {}", q);
	let (ok, f) = t.run(&["order", "fill-resting", &order, "--amount", "200000", "--shown", &q.to_string()]);
	println!("HD THE FILL: ok {} {} | operator's leaf {}", ok, f, server_state(&r, &coin));
	if server_state(&r, &coin) == "Live" && !ok {
		panic!("a coin the operator gave back is spendable: {}", f);
	}
	if !ok {
		assert!(f.to_string().contains("double_spend"), "{}", f);
		assert_held("HD HELD AGAIN", &t, &coin, 1_000_000, y);
	}
}

use elements::hashes::Hash as _;

/// RV48 B: an operator answers `double_spend` for a coin it never saw
/// spent, and serves the coin live: the catch-up that follows the refusal
/// ends the hold at once. One that also serves the coin as spent (lying
/// twice) holds it for the one wait the wallet stated, never longer; and a
/// held coin's exit is never barred.
#[tokio::test(flavor = "multi_thread")]
async fn a_false_double_spend_costs_at_most_one_stated_wait_and_never_bars_the_exit() {
	let mut r = Running::start_with(|c, x, _| testnet_like(c, x)).await;
	let (x, y) = (r.x, r.y);
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	let maker = holder(&mut r, "HF M", x, 1_500_000, 0).await;
	let order = rest_no_sweep(&mut r, &maker, 1_000_000, 100_000).await;
	let proxy = Proxy::start(&r.url());
	let t = holder_at(&mut r, "HF T", &proxy.url.clone(), y, 1_000_000).await;
	let coin = live_of(&t, y)[0]["leaf_id"].as_str().unwrap().to_string();
	let fake = |proxy: &Proxy, coin: &str, serve_spent: bool| {
		let c2 = coin.to_string();
		proxy.rewrite_request(Some(std::sync::Arc::new(|path: &str, body: &mut Value| {
			if path == "/v1/order_fill" {
				body["order"] = json!("00".repeat(32));
			}
		})));
		proxy.rewrite(Some(std::sync::Arc::new(move |path: &str, _: &Value, _: u16, v: &mut Value| {
			if path == "/v1/order_fill" {
				*v = json!({"error": {"code": "double_spend", "message": format!("leaf {} is already spent", c2)}});
				return Some(409);
			}
			if serve_spent && path == "/v1/leaf_data" {
				for l in v["leaves"].as_array_mut().into_iter().flatten() {
					if l["leaf_id"] == c2.as_str() {
						l["state"] = json!("spent");
					}
				}
			}
			None
		})));
	};
	let refused = |t: &Arca| {
		let q = t.ok(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
		let (ok, e) = t.run(&["order", "fill-resting", &order, "--amount", "200000", "--shown", &q.to_string()]);
		assert!(!ok && e.to_string().contains("double_spend"), "{}", e);
	};

	// Lying once: the operator serves the coin live, so the hold ends with the refusal's own catch-up.
	fake(&proxy, &coin, false);
	refused(&t);
	println!("HF ONE FALSE ANSWER | operator's leaf {}", server_state(&r, &coin));
	let b = t.ok(&["balance"]);
	assert!(b["arca"][y.to_string()]["spent_elsewhere"].is_null(), "not held: the operator serves it live: {}", b);
	let (ok, q) = t.run(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
	assert!(ok && q.to_string().contains(&coin), "offered again at once: {}", q);

	// Lying twice: held for the wait stated, then free.
	fake(&proxy, &coin, true);
	refused(&t);
	let left = assert_held("HF LYING TWICE", &t, &coin, 1_000_000, y);
	// Still lying: within the stated wait it stays held; past it, the hold is over.
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, (left / 2) as u32));
	r.synced().await;
	t.ok(&["sync"]);
	assert_held("HF HALF THE WAIT", &t, &coin, 1_000_000, y);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, left as u32));
	r.synced().await;
	t.ok(&["sync"]);
	let b = t.ok(&["balance"]);
	println!("HF PAST THE STATED WAIT, STILL LYING: {}", b["arca"][y.to_string()]);
	assert!(b["arca"][y.to_string()]["spent_elsewhere"].is_null(), "the hold ended with its stated wait: {}", b);
	let p = t.ok(&["coin-places"]);
	assert!(p["coins"].as_array().unwrap().iter().all(|c| c["spent_elsewhere_until"].is_null()), "{}", p["coins"]);
	proxy.rewrite_request(None);
	proxy.rewrite(None);
	assert_free("HF PAST THE STATED WAIT", &t, &order, &coin, y);

	// A held coin's exit is never barred: the change of that fill held the same way, then exited.
	let change = live_of(&t, y).into_iter().map(|c| c["leaf_id"].as_str().unwrap().to_string()).next().expect("the fill's change");
	fake(&proxy, &change, true);
	refused(&t);
	let value: u64 = t.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == change.as_str()).unwrap()["value"].as_str().unwrap().parse().unwrap();
	assert_held("HF THE CHANGE HELD", &t, &change, value, y);
	let ex = t.ok(&["exit", &change]);
	println!("HF THE HELD COIN'S EXIT: {}", ex);
	let mine = t.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == change.as_str()).cloned().unwrap();
	assert_eq!(mine["state"], "exiting", "the exit of a held coin goes: {}", mine);
}

/// The other device's round is final, the first device catches up and
/// holds the round's coin; then Bitcoin drops the round's anchor and the
/// round leaves the chain. The old coin is never offered again (it is
/// spent there), nothing is lost, and the round's coin is waited for, then
/// spent, once the round is final again.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_coin_across_an_anchor_rollback_of_the_other_devices_round() {
	let mut r = Running::start_with(|c, x, _| { testnet_like(c, x); c.finality.anchor_depth = 0; c.watcher.enabled = false }).await;
	let (x, y) = (r.x, r.y);
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	let maker = holder(&mut r, "HR M", x, 1_500_000, 0).await;
	let order = rest_no_sweep(&mut r, &maker, 1_000_000, 100_000).await;
	let t = holder(&mut r, "HR T", y, 1_000_000, 0).await;
	let coin = live_of(&t, y)[0]["leaf_id"].as_str().unwrap().to_string();
	let t2 = second_device(&t, "HR T2");
	t2.ok(&["participate", "--leaf", &coin]);
	tokio::task::block_in_place(|| {
		r.rt.mine_parent(1).unwrap();
		r.rt.anchor_to_parent_tip().unwrap();
	});
	let p_round = r.rt.parent.client().block_count().unwrap();
	let txids = rounds_broadcast(&mut r, &[&t2]).await;
	let q = t.ok(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
	let (ok, e) = t.run(&["order", "fill-resting", &order, "--amount", "200000", "--shown", &q.to_string()]);
	assert!(!ok && e.to_string().contains("double_spend"), "{}", e);
	assert_held("HR HELD", &t, &coin, 1_000_000, y);
	r.produce().await;
	r.synced().await;
	for tx in &txids {
		r.round_state(tx, RoundState::Final).await;
	}
	t2.ok(&["sync"]);
	t.ok(&["sync"]);
	let before: u64 = t.ok(&["balance"])["held"][y.to_string()].as_str().unwrap().parse().unwrap();
	println!("HR CAUGHT UP: holds {} of Y; live {:?}", before, live_of(&t, y).iter().map(|c| c["leaf_id"].clone()).collect::<Vec<_>>());
	assert!(!live_of(&t, y).iter().any(|c| c["leaf_id"] == coin.as_str()), "the old coin is settled");
	let orphaned = tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_round)).unwrap();
	println!("HR PARENT BLOCK(S) ORPHANED: {:?}", orphaned);
	t.ok(&["recheck"]);
	let mid: u64 = t.ok(&["balance"])["held"][y.to_string()].as_str().unwrap().parse().unwrap();
	println!("HR AFTER THE ROLLBACK: holds {} of Y", mid);
	assert!(mid + 10_000 >= before, "nothing is lost while the round is out of the chain: {} {}", before, mid);
	let (ok, q) = t.run(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
	println!("HR THE QUOTE WHILE THE ROUND IS OUT OF THE CHAIN: ok {} {}", ok, q);
	assert!(!q.to_string().contains(&format!("\"{}\"", coin)) || !ok, "the old coin is never offered again: {}", q);
	let mut filled = false;
	for _ in 0..12 {
		r.produce().await;
		r.synced().await;
		t2.ok(&["sync"]);
		t.ok(&["sync"]);
		let (ok, q) = t.run(&["order", "fill-resting", &order, "--amount", "200000", "--quote"]);
		if ok {
			let f = t.ok(&["order", "fill-resting", &order, "--amount", "200000", "--shown", &q.to_string()]);
			println!("HR THE FILL ONCE THE ROUND IS BACK: {}", f["filled"]);
			filled = f["filled"] == "200000";
			break;
		}
		assert_eq!(q["error"]["kind"], "settle_first", "it only ever waits for the round: {}", q);
	}
	assert!(filled, "the fill goes once the round is final again");
}
