//! Many wallets taking parts of one on-chain order, as the `arca` wallet does
//! it, against a whole Arca server on an anchored proof-of-stake regtest
//! chain. The order is a sale in the shape a launchpad lists one: it sells Y
//! for X under SeqDEX's fill covenant, by lots of 10,000, its credit paid to
//! a taproot treasury. Every wallet's take shares the order (the server says
//! it takes shared takes, `info.fills.shared`), so the operator's round
//! spends the order once for all of them: it credits the treasury at `2k` the
//! order's price for their sum, rests the remainder at `2k+1`, and pays each
//! wallet a leaf of its own share. Each wallet checks, before it hands its
//! forfeits over, that the round fills the order by the sum its take's status
//! names and by at least its own share.
//!
//! - Another order is taken first, so the sale stands at input 1; ten wallets
//!   take parts of the sale and are served by one spend of it in one round; a
//!   wallet asking less than the minimum lot is refused by its own wallet
//!   before anything is asked of the operator. The round is mined, then its
//!   Bitcoin anchor is orphaned: the round leaves the chain with it and
//!   returns, the same transaction, and every wallet holds its leaf once it
//!   is final.
//! - Ten more takes of what rests, one of whose wallets never syncs: past the
//!   forfeit window the round is dropped unbroadcast and that take voided,
//!   and the nine others are served by one spend of the sale in the round
//!   built after it.
//!
//! When `ARCA_TEST_OBSERVER` names a program, it is run at each step with the
//! step's name as its argument and the step's facts as JSON on its standard
//! input, and may answer JSON on its standard output; a non-zero exit fails
//! the test. A launchpad's ledger, or an order book, can follow the same
//! rounds through it and check what it reads elsewhere. At the step `order`
//! an observer may answer `{"order": …}`, the order in the relay's form as it
//! serves it, and the wallets take that; at the step `take_with`, given the
//! command line of the first buyer's wallet, it may make that take itself (a
//! page of its own driving the wallet, say) and answer `{"take": …}`.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use elements::{AssetId, OutPoint, Script, Transaction};
use serde_json::{json, Value};

use arca_covenant::{ExplicitOutput, FillOrder};
use common::cli::Arca;
use common::running::{keypair, Running};
use server::server::AssetSection;
use server::store::RoundState;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn create_args<'a>(server: &'a str, node: &'a str) -> Vec<&'a str> {
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

/// The observer named by `ARCA_TEST_OBSERVER`, told of the step `step`:
/// its answer, or `None` when there is no observer.
fn observe(step: &str, facts: &Value) -> Option<Value> {
	let exec = std::env::var("ARCA_TEST_OBSERVER").ok().filter(|e| !e.is_empty())?;
	let mut child = Command::new(&exec).arg(step).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()
		.unwrap_or_else(|e| panic!("run the observer {}: {}", exec, e));
	child.stdin.take().unwrap().write_all(facts.to_string().as_bytes()).unwrap();
	let out = child.wait_with_output().unwrap();
	let text = String::from_utf8_lossy(&out.stdout).to_string();
	assert!(out.status.success(), "the observer failed at step {}: {}", step, text);
	println!("observer at {}: {}", step, text.trim());
	serde_json::from_str(text.trim()).ok()
}

/// Tells the observer the test is over, however it ends.
struct Observed;

impl Drop for Observed {
	fn drop(&mut self) {
		let _ = std::panic::catch_unwind(|| observe("end", &json!({})));
	}
}

/// A sale's terms: it sells Y for X at 3/2 by lots of 10,000, its credit to a
/// taproot treasury, refundable from far ahead.
fn sale_terms(r: &Running, label: &str) -> FillOrder {
	let height = r.rt.client().blockchain_info().unwrap().blocks as u32;
	FillOrder {
		asset_a: r.y, asset_b: r.x, rate_num: 3, rate_den: 2, min_lot: 10_000,
		maker_prog: keypair(&format!("{} treasury", label)).x_only_public_key().0.serialize(),
		expiry_locktime: height + 50_000,
		maker_x: keypair(&format!("{} reclaim", label)).x_only_public_key().0.serialize(),
	}
}

/// Rests `locked` of Y under `t`.
fn rest(r: &mut Running, t: &FillOrder, locked: u64) -> OutPoint {
	let tx = r.pay_to(t.script_pubkey(), r.y, locked);
	OutPoint::new(tx.txid(), 0)
}

/// Writes the order as `arca take @FILE` reads it: `order` as served, or
/// SeqDEX's relay form of `t` at `at`.
fn served(name: &str, t: &FillOrder, at: &OutPoint, order: Option<&Value>) -> String {
	let path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("shared-{}-{}.json", std::process::id(), name));
	let offer = match order {
		Some(o) => o.clone(),
		None => json!({"offer_id": name, "give_asset": t.asset_a.to_string(), "want_asset": t.asset_b.to_string(),
			"covenant": t.to_relay(at)}),
	};
	std::fs::write(&path, offer.to_string()).unwrap();
	format!("@{}", path.display())
}

/// Wallets holding one live coin of `value` of X each, boarded together.
async fn holders(r: &mut Running, prefix: &str, n: usize, value: u64) -> Vec<Arca> {
	let (url, node) = (r.url(), r.node_url());
	let mut ws = vec![];
	for i in 0..n {
		let w = Arca::new(&format!("{}{}", prefix, i));
		w.ok(&create_args(&url, &node));
		let s = Script::from(unhex(w.ok(&["address"])["script_pubkey"].as_str().unwrap()));
		r.pay_to(s, r.x, value + 100_000);
		ws.push(w);
	}
	r.produce().await;
	for w in &ws {
		w.ok(&["board", &r.x.to_string(), &value.to_string()]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	for w in &ws {
		r.wait("the board credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
		w.ok(&["sync"]);
	}
	ws
}

fn print_round(tx: &Transaction) {
	println!("round {} ({} vB):", tx.txid(), tx.vsize());
	for (i, inp) in tx.input.iter().enumerate() {
		println!("  input {}: {}:{}{}", i, inp.previous_output.txid, inp.previous_output.vout, if inp.has_issuance() { " (issues the token)" } else { "" });
	}
	for (j, o) in tx.output.iter().enumerate() {
		println!("  output {}: {} of {}{}", j, o.value.explicit().unwrap(), o.asset.explicit().unwrap(), if o.is_fee() { " (fee)" } else { "" });
	}
}

fn leaf_of(w: &Arca, asset: AssetId, value: u64) -> bool {
	w.ok(&["coins"]).as_array().unwrap().iter().any(|c| c["state"] == "live" && c["asset"] == json!(asset.to_string())
		&& c["value"].as_str().and_then(|v| v.parse::<u64>().ok()).or(c["value"].as_u64()) == Some(value))
}

/// Mines a parent block and anchors the chain to it: the next block is
/// anchored at that parent height, which is returned.
async fn own_anchor(r: &Running) -> u64 {
	tokio::task::block_in_place(|| {
		r.rt.mine_parent(1).unwrap();
		r.rt.anchor_to_parent_tip().unwrap();
	});
	r.rt.parent.client().block_count().unwrap()
}

fn in_mempool(r: &Running, txid: &elements::Txid) -> bool {
	let pool: Value = r.rt.client().call("getrawmempool", &[]).unwrap();
	pool.as_array().unwrap().iter().any(|t| t.as_str() == Some(&txid.to_string()))
}

fn confirmations(r: &Running, txid: &elements::Txid) -> i64 {
	let v: Value = r.rt.client().call("getrawtransaction", &[json!(txid.to_string()), json!(true)]).unwrap_or(Value::Null);
	v["confirmations"].as_i64().unwrap_or(0)
}

/// Every wallet of `ws` syncs: each hands over the forfeits of its take once
/// its round is built, or takes its leaf once the round is final.
fn sync_all(ws: &[&Arca]) {
	for w in ws {
		w.ok(&["sync"]);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn ten_wallets_share_one_order_in_one_round() {
	let _observed = Observed;
	// X carries an offboard fee of 1,000 atoms: a take pays it on the price.
	let mut r = Running::start_with(|c, x, _| {
		c.assets[0] = AssetSection::new(x, 1_000);
		c.assets[0].offboard_base = Some("1000".into());
	}).await;
	let (x, y) = (r.x, r.y);
	observe("start", &json!({"node_url": r.node_url(), "node_user": "arca", "node_password": "arca", "operator_url": r.url(),
		"token": y.to_string(), "payment": x.to_string(), "height": r.rt.client().blockchain_info().unwrap().blocks}));

	let first = holders(&mut r, "SF", 1, 200_000).await.remove(0);
	let buyers = holders(&mut r, "SB", 10, 1_000_000).await;
	let low = holders(&mut r, "SL", 1, 100_000).await.remove(0);

	// The sale, and another order taken first so the sale stands at input 1.
	let sale = sale_terms(&r, "sale");
	let other = FillOrder { maker_prog: keypair("other treasury").x_only_public_key().0.serialize(), ..sale_terms(&r, "other") };
	let at = rest(&mut r, &sale, 2_000_000);
	let at0 = rest(&mut r, &other, 50_000);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let answer = observe("order", &json!({"outpoint": format!("{}:{}", at.txid, at.vout), "asset_a": y.to_string(), "asset_b": x.to_string(),
		"rate_num": sale.rate_num, "rate_den": sale.rate_den, "min_lot": sale.min_lot, "maker_prog": hex(&sale.maker_prog),
		"maker_x": hex(&sale.maker_x), "expiry_locktime": sale.expiry_locktime, "locked": 2_000_000u64,
		"script_pubkey": hex(sale.script_pubkey().as_bytes())}));
	let f = served("sale", &sale, &at, answer.as_ref().and_then(|a| a.get("order")));
	let f0 = served("other", &other, &at0, None);
	first.ok(&["take", &f0, "--max-fee-ppm", "20000"]);

	// The minimum lot, refused by the wallet itself.
	let why = low.refused(&["take", &f, "--amount", "5000"], "below the order's min_lot of 10000");
	println!("a take of 5000 of the sale: refused: {}", why);

	// Ten takes of the sale, every one sharing it.
	let fills: Vec<u64> = (0..10).map(|i| 100_001 + 10_000 * i).collect();
	let sum: u64 = fills.iter().sum();
	let mut takes = vec![];
	for (i, (w, filled)) in buyers.iter().zip(&fills).enumerate() {
		// The first buyer's take may be made by the observer, through a page
		// of its own that drives this wallet's `arca take`.
		if i == 0 {
			let arca = json!([env!("CARGO_BIN_EXE_arca"), "--datadir", w.dir.display().to_string(), "--witness-patience",
				w.patience.get().to_string()]);
			let made = observe("take_with", &json!({"wallet": w.name, "arca": arca, "env": {"ARCA_NODE_PASSWORD": "arca"},
				"amount": filled, "max_fee_ppm": 50_000}));
			if let Some(id) = made.as_ref().and_then(|m| m["take"].as_str()) {
				takes.push(id.to_string());
				continue;
			}
		}
		let k = w.ok(&["take", &f, "--amount", &filled.to_string()]);
		assert_eq!(k["state"], "pending", "{}", k);
		let id = k["take"].as_str().unwrap().to_string();
		observe("take", &json!({"wallet": w.name, "take": id, "filled": filled, "price": k["price"]}));
		takes.push(id);
	}

	// One round: the other order at input 0, the sale at input 1, filled by
	// the sum of the ten.
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	assert_eq!(built.len(), 1);
	let tx = built[0].tx.clone();
	print_round(&tx);
	assert_eq!(built[0].fills, vec![at0, at]);
	assert_eq!(built[0].batches, vec![(y, 4, 11)], "one batch of Y, eleven leaves");
	let plan = sale.plan(2_000_000, sum).unwrap();
	let got = sale.check(&tx, 1, 2_000_000).unwrap();
	assert_eq!((got.filled, got.remainder, got.credited), (sum, 2_000_000 - sum, plan.credit.value));
	assert_eq!(ExplicitOutput::from_txout(&tx.output[2]).unwrap(), plan.credit, "the treasury credited at 2k = 2");
	assert_eq!(ExplicitOutput::from_txout(&tx.output[3]).unwrap(), plan.rest.clone().unwrap(), "the rest at 2k+1 = 3");
	println!("the sale at input 1 filled by {} for ten takes: the treasury credited {} X at output 2, {} Y rest at output 3", sum,
		plan.credit.value, 2_000_000 - sum);
	observe("round", &json!({"txid": tx.txid().to_string(), "k": 1, "state": "built", "takes": takes}));

	// A parent block of the round's own to be anchored to, before it goes
	// out (anchoring mines blocks).
	let p1 = own_anchor(&r).await;
	// Every wallet checks the round and hands its forfeits over; it goes out.
	let all: Vec<&Arca> = std::iter::once(&first).chain(buyers.iter()).collect();
	sync_all(&all);
	r.server.rounds.pass().await.unwrap();
	assert!(in_mempool(&r, &tx.txid()), "broadcast once every wallet's forfeits are in");
	observe("round", &json!({"txid": tx.txid().to_string(), "k": 1, "state": "mempool", "takes": takes}));

	// Mined in a block anchored to that parent block; then the parent block
	// orphaned: the round leaves the chain with it, and comes back, the same
	// transaction.
	r.produce().await;
	r.synced().await;
	assert_eq!(confirmations(&r, &tx.txid()), 1);
	observe("round", &json!({"txid": tx.txid().to_string(), "k": 1, "state": "mined", "takes": takes}));
	let gone = tokio::task::block_in_place(|| r.rt.orphan_parent_from(p1)).unwrap();
	r.synced().await;
	println!("parent blocks orphaned {:?}: the round has {} confirmations", gone, confirmations(&r, &tx.txid()));
	assert!(confirmations(&r, &tx.txid()) < 1, "the round left the chain with its anchor");
	observe("round", &json!({"txid": tx.txid().to_string(), "k": 1, "state": "out", "takes": takes}));
	own_anchor(&r).await;
	r.produce().await;
	r.synced().await;
	assert!(confirmations(&r, &tx.txid()) >= 1, "back in a block");
	observe("round", &json!({"txid": tx.txid().to_string(), "k": 1, "state": "mined", "takes": takes}));
	r.bury().await;
	r.round_state(&tx.txid(), RoundState::Final).await;
	sync_all(&all);
	for (w, filled) in buyers.iter().zip(&fills) {
		assert!(leaf_of(w, y, *filled), "{} holds a leaf of {} Y", w.name, filled);
	}
	println!("final: each of the ten wallets holds a leaf of its share of Y");
	observe("round", &json!({"txid": tx.txid().to_string(), "k": 1, "state": "final", "takes": takes}));

	// Ten more takes of what rests, at the round's 2k+1; the tenth wallet
	// never syncs.
	let rested = OutPoint::new(tx.txid(), 3);
	let locked = 2_000_000 - sum;
	let answer = observe("order", &json!({"outpoint": format!("{}:{}", rested.txid, rested.vout), "locked": locked}));
	let f2 = served("sale-again", &sale, &rested, answer.as_ref().and_then(|a| a.get("order")));
	let fills2: Vec<u64> = (0..10).map(|i| 20_000 + 1_000 * i).collect();
	let mut takes2 = vec![];
	for (w, filled) in buyers.iter().zip(&fills2) {
		let k = w.ok(&["take", &f2, "--amount", &filled.to_string(), "--max-fee-ppm", "50000"]);
		let id = k["take"].as_str().unwrap().to_string();
		observe("take", &json!({"wallet": w.name, "take": id, "filled": filled, "price": k["price"]}));
		takes2.push(id);
	}
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	let round2 = built[0].tx.clone();
	print_round(&round2);
	assert_eq!(sale.check(&round2, 0, locked).unwrap().filled, fills2.iter().sum::<u64>());
	observe("round", &json!({"txid": round2.txid().to_string(), "k": 0, "state": "built", "takes": takes2}));
	let nine: Vec<&Arca> = buyers[..9].iter().collect();
	sync_all(&nine);
	r.server.rounds.pass().await.unwrap();
	assert!(!in_mempool(&r, &round2.txid()), "held while the tenth wallet's forfeits are missing");
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 700));
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	assert_eq!(r.server.store.round_by_txid(&elements::hashes::Hash::to_byte_array(round2.txid())).await.unwrap().unwrap().state,
		RoundState::Lost, "dropped unbroadcast");
	observe("void", &json!({"take": takes2[9]}));
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	let round3 = built[0].tx.clone();
	print_round(&round3);
	let nine_sum: u64 = fills2[..9].iter().sum();
	let f3 = sale.check(&round3, 0, locked).unwrap();
	assert_eq!((f3.filled, f3.remainder), (nine_sum, locked - nine_sum), "the nine served by one spend of the sale");
	assert_eq!(built[0].batches, vec![(y, 2, 9)]);
	observe("round", &json!({"txid": round3.txid().to_string(), "k": 0, "state": "built", "takes": &takes2[..9]}));
	sync_all(&nine);
	r.server.rounds.pass().await.unwrap();
	assert!(in_mempool(&r, &round3.txid()));
	r.produce().await;
	r.synced().await;
	observe("round", &json!({"txid": round3.txid().to_string(), "k": 0, "state": "mined", "takes": &takes2[..9]}));
	r.bury().await;
	r.round_state(&round3.txid(), RoundState::Final).await;
	sync_all(&nine);
	for (w, filled) in buyers[..9].iter().zip(&fills2) {
		assert!(leaf_of(w, y, *filled), "{} holds a leaf of {} Y", w.name, filled);
	}
	let silent = buyers[9].ok(&["sync"]);
	println!("the tenth wallet, syncing at last: {}", silent["participations"]);
	println!("final: nine leaves; {} Y rest at {}:1", locked - nine_sum, round3.txid());
	observe("round", &json!({"txid": round3.txid().to_string(), "k": 0, "state": "final", "takes": &takes2[..9]}));
}
