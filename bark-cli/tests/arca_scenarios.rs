//! The Arca wallet's scenarios, run with the `arca` binary against a whole
//! Arca server on an anchored proof-of-stake regtest chain: two wallets are
//! created; each boards, and a board is credited once final; one pays the
//! other out of round and the receiver validates the coin from its mailbox; a
//! wallet refreshes through a round; the two swap two assets in one
//! reassignment; a rollback makes the re-check un-credit and then re-credit
//! the coins on the round; and a wallet exits a coin from its record alone,
//! with the server stopped. Every refusal a wallet makes is asserted by its
//! reason.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::str::FromStr;

use elements::Script;
use serde_json::{json, Value};

use common::cli::Arca;
use common::running::Running;
use server::store::RoundState;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// The coins of a wallet in `state`, of `asset`.
fn coins(w: &Arca, state: &str, asset: &str) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == state && c["asset"] == asset).cloned().collect()
}

fn coin<'a>(all: &'a Value, leaf: &str) -> &'a Value {
	all.as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).unwrap_or_else(|| panic!("no coin {} in {}", leaf, all))
}

fn value(c: &Value) -> u64 {
	c["value"].as_str().unwrap().parse().unwrap()
}

/// A JSON object re-encoded as the wallet encodes offers and requests.
fn encode(prefix: &str, v: &Value) -> String {
	format!("{}{}", prefix, hex(v.to_string().as_bytes()))
}

#[tokio::test(flavor = "multi_thread")]
async fn create_board_pay_refresh_swap_rollback_and_exit() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	println!("server {}, node {}, asset X {} (listed for fees), asset Y {} (not listed)", url, node, x, y);

	// --- Create ---
	let a = Arca::new("A");
	let b = Arca::new("B");
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	let ia = a.ok(&create);
	b.ok(&create);
	assert_eq!(ia["operator"], ia["server_info"]["operator"]);
	a.refused(&create, "already holds a wallet");
	let b_mailbox = b.ok(&["info"])["mailbox_key"].as_str().unwrap().to_string();

	// On-chain coins for each: X for A; Y and some X for B.
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, r.x, 10_000_000);
	let s = script(&b.ok(&["address"]));
	r.pay_to(s, r.y, 10_000_000);
	let s = script(&b.ok(&["address"]));
	r.pay_to(s, r.x, 1_000_000);
	r.produce().await;
	let bal = a.ok(&["balance"]);
	assert_eq!(bal["sequentia_onchain"][&x], "10000000");
	assert!(bal["bitcoin"]["note"].as_str().unwrap().contains("arca bitcoin create"), "the Bitcoin side is shown: {}", bal);

	// --- Board ---
	a.refused(&["board", &x, "500"], "below the server's smallest leaf");
	a.refused(&["board", &y, "2000000", "--fee-asset", &x], "holds 0 of asset");
	b.refused(&["board", &y, "3000000"], "is not accepted for fees");
	let ab = a.ok(&["board", &x, "2000000"]);
	let a_board = ab["leaf_id"].as_str().unwrap().to_string();
	assert_eq!(ab["fee"]["asset"], x, "the fee is in the asset boarded");
	let bb = b.ok(&["board", &y, "3000000", "--fee-asset", &x]);
	let b_board = bb["leaf_id"].as_str().unwrap().to_string();
	assert_eq!(bb["fee"]["asset"], x, "the fee is in the asset named");
	r.produce().await;
	let c = a.ok(&["coins"]);
	assert_eq!(coin(&c, &a_board)["state"], "pending", "a board in a block, its anchor not buried, is not spendable");
	println!("A's board before burial: {}", coin(&c, &a_board)["note"]);
	r.bury().await;
	r.synced().await;
	let c = a.ok(&["coins"]);
	assert_eq!(coin(&c, &a_board)["state"], "live", "the board is final");
	r.wait("the server to credit both boards", || {
		a.ok(&["boards"])[0]["server"]["state"] == "credited" && b.ok(&["boards"])[0]["server"]["state"] == "credited"
	}).await;
	b.ok(&["sync"]);
	assert_eq!(coin(&b.ok(&["coins"]), &b_board)["state"], "live");

	// --- An out-of-round payment, received through the mailbox ---
	let req = b.ok(&["receive"]);
	let request = req["request"].as_str().unwrap().to_string();
	a.refused(&["send", &request, "--amount", "600000"], "no asset is a default");
	a.refused(&["send", &request, "--amount", "600000", "--asset", &y], "holds 0 of asset");
	let sent = a.ok(&["send", &request, "--amount", "600000", "--asset", &x]);
	assert!(sent["change"].is_string());
	// The request is single use: the server refuses a second leaf under its key.
	a.refused(&["send", &request, "--amount", "600000", "--asset", &x], "key_reused");
	let mb = b.ok(&["mailbox"]);
	let got = &mb["accepted"][0];
	assert_eq!((got["asset"].as_str().unwrap(), got["value"].as_str().unwrap(), got["hops"].as_u64().unwrap(), got["state"].as_str().unwrap()),
		(x.as_str(), "600000", 1, "live"), "{}", mb);
	assert_eq!(b.ok(&["mailbox"])["accepted"], json!([]), "a mailbox read again holds nothing new");

	// A coin for a key B never drew, posted to B's mailbox: A pays its own
	// request, naming B's mailbox. B refuses it; A keeps it from the answer.
	let mut forged = a.ok(&["receive"])["details"].clone();
	forged["mailbox"] = json!(b_mailbox);
	let paid = a.ok(&["send", &encode("arca:", &forged), "--amount", "200000", "--asset", &x]);
	assert_eq!(paid["transfer"]["kept"].as_array().unwrap().len(), 2, "A keeps its own leaf and its change: {}", paid);
	let mb = b.ok(&["mailbox"]);
	assert!(mb["refused"][0]["reason"].as_str().unwrap().contains("which this wallet never drew"), "{}", mb);
	println!("B refused from its mailbox: {}", mb["refused"][0]["reason"]);

	// --- A refresh through a round ---
	let live_x: u64 = coins(&a, "live", &x).iter().map(value).sum();
	let p = a.ok(&["participate"]);
	let pid = p["participation"].as_str().unwrap().to_string();
	assert_eq!(p["state"], "pending");
	assert_eq!(a.ok(&["sync"])["participations"][0]["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let round = built.tx.txid();
	println!("round {}: {} vB", round, built.tx.vsize());
	r.produce().await;
	let s = a.ok(&["sync"]);
	assert!(s["participations"][0]["note"].as_str().unwrap().contains("signs nothing for it before it is final"), "{}", s);
	r.bury().await;
	r.round_state(&round, RoundState::Final).await;
	let s = a.ok(&["sync"]);
	let done = &s["participations"][0];
	assert_eq!((done["participation"].as_str().unwrap(), done["state"].as_str().unwrap()), (pid.as_str(), "released"), "{}", s);
	let a_leaf = done["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	let new_x = coins(&a, "live", &x);
	assert_eq!(new_x.len(), 1);
	assert_eq!(value(&new_x[0]), live_x, "the refresh is free and keeps the value");
	assert_eq!(new_x[0]["kind"], "batch");
	assert_eq!(new_x[0]["leaf_id"], a_leaf.as_str());

	// --- A swap of two assets: A gives X for B's Y ---
	let offer = a.ok(&["swap", "offer", "--give-asset", &x, "--give", "300000", "--want-asset", &y, "--want", "400000"]);
	let offer_text = offer["offer"].as_str().unwrap().to_string();
	let mut cheat = offer["details"].clone();
	cheat["give"]["value"] = json!("350000");
	b.refused(&["swap", "accept", &encode("arca-offer:", &cheat)], "the offered coins keep");
	let acc = b.ok(&["swap", "accept", &offer_text]);
	let acc_text = acc["accept"].as_str().unwrap().to_string();
	let done = a.ok(&["swap", "complete", &acc_text]);
	a.refused(&["swap", "complete", &acc_text], "is not an open offer");
	assert_eq!(done["transfer"]["kept"].as_array().unwrap().len(), 2, "A keeps its Y leaf and its X change: {}", done);
	let mb = b.ok(&["mailbox"]);
	assert_eq!(mb["accepted"].as_array().unwrap().len(), 2, "B gets its X leaf and its Y change: {}", mb);
	assert_eq!(coin(&b.ok(&["coins"]), &b_board)["state"], "spent", "B's board went into the swap");
	let a_y = coins(&a, "live", &y);
	assert_eq!(a_y.len(), 1);
	assert_eq!(value(&a_y[0]), 400_000);
	let a_y = a_y[0]["leaf_id"].as_str().unwrap().to_string();
	assert!(coins(&b, "live", &x).iter().any(|c| value(c) == 300_000));

	// --- A rollback: the re-check un-credits, then credits again ---
	let v: Value = r.rt.client().call("getrawtransaction", &[json!(round.to_string()), json!(true)]).unwrap();
	let block = v["blockhash"].as_str().unwrap().to_string();
	let _: Value = r.rt.client().call("invalidateblock", &[json!(block)]).unwrap();
	let rc = a.ok(&["recheck"]);
	assert_eq!(rc["reorganised"], true, "{}", rc);
	let down: Vec<&Value> = rc["changes"].as_array().unwrap().iter().filter(|c| c["from"] == "live" && c["to"] == "pending").collect();
	assert!(down.len() >= 2, "every coin on the round is un-credited: {}", rc);
	assert!(down.iter().all(|c| c["why"].as_str().unwrap().contains(&round.to_string())), "{}", rc);
	assert!(coins(&a, "live", &y).is_empty(), "the Y leaf rests on the round too");
	a.refused(&["swap", "offer", "--give-asset", &x, "--give", "300000", "--want-asset", &y, "--want", "1000"], "holds 0 of asset");
	r.produce().await;
	r.bury().await;
	r.round_state(&round, RoundState::Final).await;
	let rc = a.ok(&["recheck"]);
	let up: Vec<&Value> = rc["changes"].as_array().unwrap().iter().filter(|c| c["from"] == "pending" && c["to"] == "live").collect();
	assert_eq!(up.len(), down.len(), "every coin un-credited is credited again: {}", rc);
	let v: Value = r.rt.client().call("getrawtransaction", &[json!(round.to_string()), json!(true)]).unwrap();
	assert_ne!(v["blockhash"].as_str().unwrap(), block, "the round returned in another block, with its txid");

	// --- A unilateral exit, from the record alone, the server gone ---
	r.server.stop();
	// Y is not taken for fees: the wallet pays each step with a coin of X,
	// the one asset it holds that the node takes, without being told.
	let e = a.ok(&["exit", &a_y]);
	assert_eq!(e["state"], "unrolling", "{}", e);
	let steps = e["broadcast"].as_array().unwrap();
	assert!(steps.iter().all(|s| s["fee"].as_array().unwrap().iter().all(|f| f["asset"] == x.as_str())), "every fee in X: {}", e);
	println!("A's exit of its Y leaf: {} transactions, {} vB in all", steps.len(), steps.iter().map(|s| s["vsize"].as_u64().unwrap()).sum::<u64>());
	r.produce().await;
	let e = a.ok(&["exit", &a_y, "--fee-asset", &x]);
	assert_eq!(e["state"], "waiting", "the claim waits out the exit delay: {}", e);
	assert!(e["next"].as_str().unwrap().contains("non-BIP68-final"), "{}", e);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 512));
	let e = a.ok(&["exit", &a_y, "--fee-asset", &x]);
	assert_eq!(e["state"], "claimed", "{}", e);
	r.produce().await;
	let claim = elements::Txid::from_str(e["claim"]["txid"].as_str().unwrap()).unwrap();
	let tx = r.rt.client().raw_transaction(&claim).unwrap();
	assert_eq!(tx.output[0].value.explicit(), Some(400_000), "the whole leaf, the fee from a coin of X");
	assert_eq!(tx.output[0].asset.explicit().map(|a| a.to_string()), Some(y.clone()));
	assert_eq!(coin(&a.ok(&["coins"]), &a_y)["state"], "exiting", "the claim is followed until it is final");
	r.bury().await;
	a.ok(&["sync"]);
	assert_eq!(coin(&a.ok(&["coins"]), &a_y)["state"], "exited");
	a.refused(&["exit", &a_y], "there is nothing of the wallet's to exit");

	println!("A's refusals: {}", a.ok(&["refusals"]));
	println!("B's refusals: {}", b.ok(&["refusals"]));
	println!("A's balance: {}", a.ok(&["balance"]));
	println!("B's balance: {}", b.ok(&["balance"]));
	let _ = std::fs::remove_dir_all(&a.dir);
	let _ = std::fs::remove_dir_all(&b.dir);
}

/// The leaf's value, one atom more.
fn more_value(t: &mut Value) {
	let v: u64 = t["leaves"][0]["value"].as_str().unwrap().parse().unwrap();
	t["leaves"][0]["value"] = json!((v + 1).to_string());
}

/// The schedule with its last expiry one second later.
fn later_last_expiry(t: &mut Value) {
	use arca_covenant::encode::Encoding;
	use arca_covenant::{ClockSchedule, MedianTime};
	let h = t["schedule"].as_str().unwrap();
	let bytes: Vec<u8> = (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect();
	let s = ClockSchedule::decode(&bytes).unwrap();
	let mut e: Vec<MedianTime> = s.expiries().to_vec();
	let last = e.len() - 1;
	e[last] = MedianTime::from_consensus(e[last].to_consensus_u32() + 1).unwrap();
	let s = ClockSchedule::new(s.token, s.operator, s.notice, e).unwrap();
	t["schedule"] = json!(hex(&s.encode()));
}

/// The schedule's second expiry moved before its first: a clock that runs
/// backwards.
fn backwards_clock(t: &mut Value) {
	use arca_covenant::encode::Encoding;
	use arca_covenant::{ClockSchedule, MedianTime};
	let h = t["schedule"].as_str().unwrap();
	let bytes: Vec<u8> = (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect();
	let s = ClockSchedule::decode(&bytes).unwrap();
	let mut e: Vec<MedianTime> = s.expiries().to_vec();
	e[1] = MedianTime::from_consensus(e[0].to_consensus_u32() - 1).unwrap();
	let s = ClockSchedule::new_unchecked(s.token, s.operator, s.notice, e).unwrap();
	t["schedule"] = json!(hex(&s.encode()));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dishonest_published_tree_is_refused_before_anything_is_signed() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let proxy = common::proxy::Proxy::start(&r.url());
	let node = r.node_url();
	let c = Arca::new("C");
	c.ok(&["create", "--server", &proxy.url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	let s = script(&c.ok(&["address"]));
	r.pay_to(s, r.x, 5_000_000);
	r.produce().await;
	let board = c.ok(&["board", &x, "2000000"])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || c.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	c.ok(&["participate"]);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;

	// The operator publishes a tree that is not the round's, three ways; the
	// wallet refuses each, and signs no forfeit.
	for (what, t, why) in [
		("a leaf's value changed", more_value as common::proxy::Tamper, "fails the wallet's checks"),
		("the last expiry one second later", later_last_expiry, "check 5"),
		("a clock that runs backwards", backwards_clock, "backwards"),
	] {
		proxy.set(Some(t));
		let s = c.ok(&["sync"]);
		let p = &s["participations"][0];
		let reason = p["refused"].as_str().unwrap_or_else(|| panic!("{}: not refused: {}", what, s));
		assert!(reason.contains(why), "{}: refused for another reason: {}", what, reason);
		assert_eq!(p["state"], "issued");
		println!("published tree with {}: REFUSED: {}", what, reason);
		assert_eq!(coin(&c.ok(&["coins"]), &board)["state"], "given", "the coin is still the owner's: no forfeit was signed");
	}
	// The honest tree: the refresh completes.
	proxy.set(None);
	let s = c.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s);
	assert_eq!(coin(&c.ok(&["coins"]), &board)["state"], "spent");
	let first = s["participations"][0]["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();

	// A second refresh gives up that batch leaf: once the new round is final
	// and the new leaf validated, the wallet releases the old leaf's lowest
	// node for that round.
	c.ok(&["participate"]);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	let s = c.ok(&["sync"]);
	let p = s["participations"].as_array().unwrap().iter().find(|p| p["state"] == "released" && p["round"] == built.tx.txid().to_string())
		.unwrap_or_else(|| panic!("the second refresh: {}", s));
	assert_eq!(p["released"], json!([first]), "the old batch leaf's lowest node is released: {}", s);
	println!("C released the lowest node of {} for round {}", first, built.tx.txid());
	println!("C's refusals: {}", c.ok(&["refusals"]));
	let _ = std::fs::remove_dir_all(&c.dir);
}
