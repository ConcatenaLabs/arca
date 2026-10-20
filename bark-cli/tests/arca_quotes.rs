//! A board's fee and an exit's fees, shown before anything is signed: the
//! wallet library's `board_quote` and `exit_quote` (the command line's
//! `board --quote` and `exit --quote`) sign, ask and broadcast nothing, and a
//! program that passes the fees it showed (`shown`) has the board or the
//! exit go ahead on those fees only, or refused before anything is written,
//! registered or broadcast.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::Script;
use serde_json::{json, Value};

use bark::arca::{command, Wallet};
use common::cli::Arca;
use common::running::Running;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

fn mempool(r: &Running) -> Vec<String> {
	let v: Value = r.rt.client().call("getrawmempool", &[]).unwrap();
	let mut m: Vec<String> = v.as_array().unwrap().iter().map(|t| t.as_str().unwrap().to_string()).collect();
	m.sort();
	m
}

/// One command of the library on the wallet in `a`'s directory, as a
/// program that embeds the library runs it: its result, or its refusal.
fn library(a: &Arca, cmd: &str, args: Value) -> Result<Value, String> {
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run(&mut w, cmd, &args).map(|v| v["result"].clone()).map_err(|e| e.to_string())
	})
}

#[tokio::test(flavor = "multi_thread")]
async fn a_board_and_an_exit_go_ahead_only_on_the_fees_shown() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("Q");
	a.ok(&["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, r.x, 10_000_000);
	r.produce().await;

	// --- The board's quote ---
	a.refused(&["board", &x, "500", "--quote"], "below the server's smallest leaf");
	a.refused(&["board", &y, "2000000", "--quote"], "is not accepted for fees");
	let boards_before = a.ok(&["boards"]);
	let pool_before = mempool(&r);
	let q = a.ok(&["board", &x, "2000000", "--quote"]);
	assert_eq!(q["fee"]["asset"], x, "the fee is in the asset boarded");
	let fee: u64 = q["fee"]["amount"].as_str().unwrap().parse().unwrap();
	assert!(fee > 0 && q["vsize"].as_u64().unwrap() > 0 && q["inputs"] == 1, "{}", q);
	assert_eq!(a.ok(&["boards"]), boards_before, "a quote registers nothing");
	assert_eq!(mempool(&r), pool_before, "a quote broadcasts nothing");
	let lib_q = library(&a, "board_quote", json!({"asset": x, "amount": "2000000"})).unwrap();
	assert_eq!(lib_q["fee"], q["fee"], "the library and the command line quote one fee");

	// A fee other than the one shown: refused before anything is registered.
	let wrong = json!({"asset": x, "amount": (fee + 1).to_string()});
	a.refused(&["board", &x, "2000000", "--shown", &wrong.to_string()], "the board's fee changed since it was shown");
	let e = library(&a, "board", json!({"asset": x, "amount": "2000000", "shown": wrong})).unwrap_err();
	assert!(e.contains("the board's fee changed since it was shown; it is now") && e.contains(&format!("\"amount\":\"{}\"", fee)), "{}", e);
	println!("REFUSED (board, fee shown {}): {}", fee + 1, e);
	let wrong_asset = json!({"asset": y, "amount": fee.to_string()});
	let e = library(&a, "board", json!({"asset": x, "amount": "2000000", "shown": wrong_asset})).unwrap_err();
	assert!(e.contains("the board's fee changed since it was shown"), "{}", e);
	assert_eq!(a.ok(&["boards"]), boards_before, "a refused board registers nothing");
	assert_eq!(mempool(&r), pool_before, "a refused board broadcasts nothing");
	assert!(a.ok(&["coins"]).as_array().unwrap().is_empty(), "a refused board keeps no coin");

	// The fee shown: the board goes ahead and pays exactly it.
	let b = library(&a, "board", json!({"asset": x, "amount": "2000000", "shown": q["fee"]})).unwrap();
	assert_eq!(b["fee"], q["fee"], "the board pays the fee shown: {}", b);
	let leaf = b["leaf_id"].as_str().unwrap().to_string();
	let txid = b["txid"].as_str().unwrap().to_string();
	assert!(mempool(&r).contains(&txid), "the board is broadcast");
	let tx: Value = r.rt.client().call("getrawtransaction", &[json!(txid), json!(true)]).unwrap();
	let paid: Vec<&Value> = tx["vout"].as_array().unwrap().iter().filter(|o| o["scriptPubKey"]["type"] == "fee").collect();
	assert_eq!(paid.len(), 1, "{}", tx);
	println!("board {}: fee output {} (shown {} atoms), {} vB (quoted {} vB)", txid, paid[0]["value"], fee, tx["vsize"], q["vsize"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be live", || a.ok(&["coins"])[0]["state"] == "live").await;

	// --- The exit's quote ---
	let pool_before = mempool(&r);
	let coins_before = a.ok(&["coins"]);
	let eq = a.ok(&["exit", &leaf, "--quote"]);
	assert_eq!(mempool(&r), pool_before, "an exit's quote broadcasts nothing");
	assert_eq!(a.ok(&["coins"]), coins_before, "an exit's quote changes no coin");
	let steps = eq["steps"].as_array().unwrap();
	assert_eq!(steps.len(), 1, "a board's exit is its conversion: {}", eq);
	assert!(eq["unroll"].as_object().unwrap().len() == 1 && eq["claim"]["fee"].is_array(), "{}", eq);
	println!("exit quote: {}", eq);
	a.refused(&["exit", "00", "--quote"], "no coin 00");

	// Fees other than those shown: refused before anything is broadcast.
	let mut wrong = eq["unroll"].clone();
	for (_, v) in wrong.as_object_mut().unwrap() {
		*v = json!((v.as_str().unwrap().parse::<u64>().unwrap() + 1).to_string());
	}
	a.refused(&["exit", &leaf, "--shown", &wrong.to_string()], "the exit's fees changed since they were shown");
	let e = library(&a, "exit", json!({"leaf_id": leaf, "shown": wrong})).unwrap_err();
	assert!(e.contains("the exit's fees changed since they were shown; they are now"), "{}", e);
	println!("REFUSED (exit, fees shown {}): {}", wrong, e);
	assert_eq!(mempool(&r), pool_before, "a refused exit broadcasts nothing");
	assert_eq!(a.ok(&["coins"]), coins_before, "a refused exit leaves the coin as it was");

	// The fees shown: the path is broadcast on exactly them.
	let ex = library(&a, "exit", json!({"leaf_id": leaf, "shown": eq["unroll"]})).unwrap();
	let broadcast = ex["broadcast"].as_array().unwrap();
	assert_eq!(broadcast.len(), 1, "{}", ex);
	assert_eq!(broadcast[0]["fee"], steps[0]["fee"], "the conversion pays the fee shown");
	assert!(mempool(&r).contains(&broadcast[0]["txid"].as_str().unwrap().to_string()));
	assert_eq!(a.ok(&["coins"])[0]["state"], "exiting");
	println!("exit run: {}", ex);
}
