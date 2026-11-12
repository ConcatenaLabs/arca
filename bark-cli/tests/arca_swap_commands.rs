//! An in-tree swap run through the library's commands, as a program that
//! embeds the library runs it (a browser worker, a mobile app's core): the
//! maker's `swap_offer` holds its coins and signs nothing; the taker's
//! `swap_read` checks the offer and shows what it gives, gets and pays, with
//! nothing signed, held or stored; `swap_accept` with `shown` goes ahead only
//! on those terms; the maker's `swap_complete` settles it in one
//! reassignment; `swaps` lists each wallet's swaps and `swap_cancel` frees an
//! offer's coins.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::Script;
use serde_json::{json, Value};

use bark::arca::{command, Wallet};
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

fn coins(w: &Arca, state: &str, asset: &str) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == state && c["asset"] == asset).cloned().collect()
}

fn value(c: &Value) -> u64 {
	c["value"].as_str().unwrap().parse().unwrap()
}

fn total(w: &Arca, state: &str, asset: &str) -> u64 {
	coins(w, state, asset).iter().map(value).sum()
}

fn num(v: &Value) -> u64 {
	v.as_str().unwrap().parse().unwrap()
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
async fn a_swap_through_the_commands_shows_its_terms_before_anything_is_signed() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("SA");
	let b = Arca::new("SB");
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	a.ok(&create);
	b.ok(&create);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, r.x, 10_000_000);
	let s = script(&b.ok(&["address"]));
	r.pay_to(s, r.y, 10_000_000);
	let s = script(&b.ok(&["address"]));
	r.pay_to(s, r.x, 1_000_000);
	r.produce().await;
	a.ok(&["board", &x, "2000000"]);
	b.ok(&["board", &y, "3000000", "--fee-asset", &x]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the server to credit both boards", || {
		a.ok(&["boards"])[0]["server"]["state"] == "credited" && b.ok(&["boards"])[0]["server"]["state"] == "credited"
	}).await;
	a.ok(&["sync"]);
	b.ok(&["sync"]);
	assert_eq!(total(&a, "live", &x), 2_000_000);
	assert_eq!(total(&b, "live", &y), 3_000_000);

	// --- The maker offers: its coins held, nothing signed ---
	assert_eq!(library(&a, "swap_offer", json!({"give_asset": x, "give": "300000", "want_asset": x, "want": "400000"})).unwrap_err(),
		"refused: a swap exchanges two assets");
	let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": "300000", "want_asset": y, "want": "400000"})).unwrap();
	println!("OFFER: gives {} gets {} pays {}", offer["gives"], offer["gets"], offer["pays"]);
	assert_eq!(offer["gives"], json!({"asset": x, "value": "300000"}));
	assert_eq!(offer["gets"], json!({"asset": y, "value": "400000"}));
	assert_eq!(offer["pays"]["asset"], x, "the maker's margins are in the asset it gives");
	assert_eq!(offer["pays"]["margin"], offer["details"]["margin"]);
	let offer_text = offer["offer"].as_str().unwrap().to_string();
	let id = offer["swap"].as_str().unwrap().to_string();
	assert_eq!(total(&a, "offered", &x), 2_000_000, "the maker's coin is held for the swap");
	let listed = library(&a, "swaps", json!({})).unwrap();
	assert_eq!(listed, json!([{"swap": id, "role": "maker", "state": "open", "gives": offer["gives"], "gets": offer["gets"], "offer": offer_text}]));

	// --- The taker reads it: what it gives, gets and pays; nothing signed, held or stored ---
	let mut cheat = offer["details"].clone();
	cheat["give"]["value"] = json!("350000");
	let e = library(&b, "swap_read", json!({"offer": format!("arca-offer:{}", hex(cheat.to_string().as_bytes()))})).unwrap_err();
	assert!(e.contains("the offered coins keep"), "{}", e);
	println!("REFUSED (read, an offer that gives more than its coins keep): {}", e);
	let read = library(&b, "swap_read", json!({"offer": offer_text})).unwrap();
	println!("READ: {}", read);
	assert_eq!(read["swap"], id.as_str());
	assert_eq!(read["gets"], json!({"asset": x, "value": "300000"}));
	assert_eq!(read["gives"], json!({"asset": y, "value": "400000"}));
	assert_eq!(read["pays"]["asset"], y, "the taker's margins are in the asset it gives");
	let pays = num(&read["pays"]["margins"]);
	assert!(pays > 0, "the taker's checkpoint leaves a margin: {}", read);
	assert_eq!(read["maker_pays"]["margin"], offer["pays"]["margin"]);
	assert_eq!(num(&read["change"]["value"]), 3_000_000 - 400_000 - pays, "the taker's change: {}", read);
	// What settling the coin it would get in the next round costs, priced before the
	// wallet holds it, from the dates the read names.
	let settle = library(&b, "settle_quote", json!({"asset": x, "value": "300000", "expiry": read["dates"]["expiry"]})).unwrap();
	println!("SETTLE QUOTE: {}", settle);
	assert_eq!((settle["asset"].as_str(), settle["value"].as_str()), (Some(x.as_str()), Some("300000")));
	assert_eq!(num(&settle["after"]) + num(&settle["fee"]), 300_000, "{}", settle);
	assert!(library(&b, "settle_quote", json!({"asset": x, "value": "300000"})).unwrap_err().contains("the expiry is missing"));
	assert_eq!(library(&b, "swaps", json!({})).unwrap(), json!([]), "a read stores no swap");
	assert_eq!(total(&b, "live", &y), 3_000_000, "a read holds no coin");

	// --- An acceptance on terms other than those shown: refused before anything is signed ---
	let mut wrong = read.clone();
	wrong["pays"]["margins"] = json!((pays - 1).to_string());
	let e = library(&b, "swap_accept", json!({"offer": offer_text, "shown": wrong})).unwrap_err();
	assert!(e.contains("the swap's terms changed since they were shown; they are now") && e.contains(&format!("\"margins\":\"{}\"", pays)), "{}", e);
	println!("REFUSED (accept, margins shown {}): {}", pays - 1, e);
	let mut wrong = read.clone();
	wrong["gets"]["value"] = json!("300001");
	let e = library(&b, "swap_accept", json!({"offer": offer_text, "shown": wrong})).unwrap_err();
	assert!(e.contains("the swap's terms changed since they were shown"), "{}", e);
	assert_eq!(library(&b, "swaps", json!({})).unwrap(), json!([]), "a refused acceptance stores no swap");
	assert_eq!(total(&b, "live", &y), 3_000_000, "a refused acceptance holds no coin");

	// --- Accepted on the terms shown; completed by the maker ---
	let acc = library(&b, "swap_accept", json!({"offer": offer_text, "shown": read})).unwrap();
	assert_eq!(acc["pays"], read["pays"]);
	let acc_text = acc["accept"].as_str().unwrap().to_string();
	assert_eq!(library(&b, "swaps", json!({})).unwrap()[0]["state"], "accepted");
	let done = library(&a, "swap_complete", json!({"accept": acc_text})).unwrap();
	assert_eq!(done["swap"], id.as_str());
	let e = library(&a, "swap_complete", json!({"accept": acc_text})).unwrap_err();
	assert!(e.contains("is not an open offer"), "{}", e);
	assert_eq!(library(&a, "swaps", json!({})).unwrap()[0]["state"], "done");
	assert_eq!(library(&b, "swaps", json!({})).unwrap()[0]["state"], "accepted", "the taker's swap waits for the maker");
	let mb = b.ok(&["mailbox"]);
	assert_eq!(mb["accepted"].as_array().unwrap().len(), 2, "the taker gets its X leaf and its Y change: {}", mb);
	assert_eq!(library(&b, "swaps", json!({})).unwrap()[0]["state"], "done", "once the maker's transfer arrives, the taker's swap is done");
	// The coin it got, held now, costs at most what settle_quote said to refresh.
	let got = coins(&b, "live", &x).into_iter().find(|c| value(c) == 300_000).expect("the coin the swap gave");
	let q = library(&b, "quote", json!({"leaves": [got["leaf_id"]]})).unwrap();
	assert!(num(&q["coins"][0]["fee"]) <= num(&settle["fee"]), "the held coin's refresh fee {} is above the one quoted before, {}", q, settle);
	assert_eq!(total(&a, "live", &y), 400_000, "the maker holds what it wanted");
	assert_eq!(total(&b, "live", &x), 300_000, "the taker holds what it was offered");
	assert_eq!(total(&b, "live", &y), 3_000_000 - 400_000 - pays, "the taker paid what it was shown");
	let a_x = total(&a, "live", &x);
	let maker_paid = num(&offer["pays"]["margin"]) + num(&offer["pays"]["margins"]);
	assert_eq!(a_x, 2_000_000 - 300_000 - maker_paid, "the maker paid what it was shown");
	println!("SETTLED: maker X {} Y {}; taker X {} Y {}", a_x, total(&a, "live", &y), total(&b, "live", &x), total(&b, "live", &y));

	// --- An offer cancelled: its coins free again ---
	let o2 = library(&a, "swap_offer", json!({"give_asset": x, "give": "100000", "want_asset": y, "want": "100000"})).unwrap();
	assert!(total(&a, "offered", &x) > 0);
	let c = library(&a, "swap_cancel", json!({"swap": o2["swap"]})).unwrap();
	assert_eq!(c["cancelled"], true, "{}", c);
	assert_eq!(total(&a, "offered", &x), 0);
	assert_eq!(total(&a, "live", &x), a_x);
	let listed = library(&a, "swaps", json!({})).unwrap();
	assert_eq!(listed.as_array().unwrap().iter().map(|s| s["swap"].clone()).collect::<Vec<_>>(), vec![json!(id), o2["swap"].clone()],
		"swaps are listed in the order they were made, two in one second too");
	assert_eq!(listed[1]["state"], "cancelled");
}

/// A swap pays from the smallest coin of the latest date that holds what it
/// gives, the maker's side and the taker's: its change, out of round until
/// the next round refreshes it, is at most that coin. Taken largest first, a
/// maker's every small swap spent its largest coin and held nearly all of it
/// out of round. A refusal carries what the command cost before it.
#[tokio::test(flavor = "multi_thread")]
async fn a_swap_pays_from_the_smallest_coin_that_holds_it() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("FA");
	let b = Arca::new("FB");
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	a.ok(&create);
	b.ok(&create);
	// A coin on the chain for each board, so the second waits for no change of the first.
	for (w, asset, v) in [(&a, r.x, 10_000_000), (&a, r.x, 1_000_000), (&b, r.y, 10_000_000), (&b, r.y, 1_000_000), (&b, r.x, 1_000_000),
		(&b, r.x, 1_000_000)]
	{
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, asset, v);
	}
	r.produce().await;
	// Each wallet boards a large coin and a small one in one block: two coins of one date.
	a.ok(&["board", &x, "2000000"]);
	a.ok(&["board", &x, "300000"]);
	b.ok(&["board", &y, "3000000", "--fee-asset", &x]);
	b.ok(&["board", &y, "500000", "--fee-asset", &x]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the server to credit the boards", || {
		a.ok(&["boards"]).as_array().unwrap().iter().all(|v| v["server"]["state"] == "credited")
			&& b.ok(&["boards"]).as_array().unwrap().iter().all(|v| v["server"]["state"] == "credited")
	}).await;
	a.ok(&["sync"]);
	b.ok(&["sync"]);
	let small = coins(&a, "live", &x).into_iter().find(|c| value(c) == 300_000).expect("the small coin");
	let expiries: Vec<Value> = coins(&a, "live", &x).iter().map(|c| c["expiry"].clone()).collect();
	println!("MAKER COINS: {:?} expiries {:?}", coins(&a, "live", &x).iter().map(value).collect::<Vec<_>>(), expiries);

	// A refusal names what it cost.
	let refused = tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run_answer(&mut w, "swap_offer", &json!({"give_asset": x, "give": "100000", "want_asset": x, "want": "100000"}))
	}).unwrap_err();
	println!("REFUSED WITH ITS COST: {}", refused);
	assert_eq!(refused["error"]["message"], "refused: a swap exchanges two assets");
	assert!(refused["cost"]["command"]["ms"].is_u64() && refused["cost"]["start"]["ms"].is_u64(), "{}", refused);

	// The maker gives 100,000 from the 300,000 coin, not the 2,000,000 one.
	let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": "100000", "want_asset": y, "want": "100000"})).unwrap();
	let inputs: Vec<Value> = offer["details"]["inputs"].as_array().unwrap().iter().map(|i| i["leaf_id"].clone()).collect();
	println!("OFFER INPUTS: {:?}", inputs);
	assert_eq!(inputs, vec![small["leaf_id"].clone()], "the smallest coin that holds it");
	assert_eq!(total(&a, "offered", &x), 300_000);
	// The taker pays 100,000 from its 500,000 coin: its change is that coin's rest.
	let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap();
	let pays = num(&read["pays"]["margins"]);
	assert_eq!(num(&read["change"]["value"]), 500_000 - 100_000 - pays, "the taker's change, from its small coin: {}", read);
	// A swap only the large coin holds is paid from it.
	library(&a, "swap_cancel", json!({"swap": offer["swap"]})).unwrap();
	let big = library(&a, "swap_offer", json!({"give_asset": x, "give": "1000000", "want_asset": y, "want": "100000"})).unwrap();
	assert_eq!(big["details"]["inputs"].as_array().unwrap().len(), 1);
	assert_eq!(total(&a, "offered", &x), 2_000_000, "the large coin pays what the small one cannot");
	library(&a, "swap_cancel", json!({"swap": big["swap"]})).unwrap();
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

/// A coin given to a round by `w` (a wallet's second device), the round
/// built, made final and completed by `w`: what replaced it.
async fn given_to_a_round(r: &Running, w: &Arca, leaf: &str) -> Value {
	let before: Vec<Value> = w.ok(&["coins"]).as_array().unwrap().iter().map(|c| c["leaf_id"].clone()).collect();
	let p = w.ok(&["participate", "--leaf", leaf]);
	assert_eq!(p["participations"][0]["state"], "pending", "{}", p);
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(!built.is_empty() && failed.is_empty(), "{} built, {} failed", built.len(), failed.len());
	r.produce().await;
	r.bury().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	let s = w.ok(&["sync"]);
	assert!(s["participations"].as_array().unwrap().iter().any(|p| p["state"] == "released"), "{}", s);
	let new = w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["kind"] == "batch" && c["state"] == "live" && !before.contains(&c["leaf_id"]))
		.cloned().unwrap_or_else(|| panic!("no coin replaced {}: {}", leaf, w.ok(&["coins"])));
	println!("SECOND DEVICE GAVE {} TO A ROUND, HOLDS {} OF {}", &leaf[..12], &new["leaf_id"].as_str().unwrap()[..12], new["value"]);
	new
}

/// The coins of `w` of `asset` that are live, by id.
fn live_ids(w: &Arca, asset: &str) -> Vec<String> {
	coins(w, "live", asset).iter().map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect()
}

/// A completion the operator refuses withdraws the offer: the swap does not
/// stand open on coins the maker no longer holds for it. The refusal names
/// the swap, the coin the operator named and whose it is, and an acceptance
/// handed over again is answered at once that the offer is cancelled. Then
/// the taker, whose coin a second device of its own gave to a round before
/// its acceptance named it (as on the testnet, 2026-11-12), cancels: the
/// operator refuses the respend of that coin, the wallet catches up with its
/// other store at once, and ends holding the truth (the dead coin not
/// counted, the round's coin held) with nothing respent. A payment from a
/// coin given elsewhere ends the same way. Last, the maker's own coin given
/// to a round by its second device.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_completion_withdraws_the_offer() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("RA");
	let b = Arca::new("RB");
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	a.ok(&create);
	b.ok(&create);
	for (w, asset, v) in [(&a, r.x, 10_000_000), (&b, r.y, 10_000_000), (&b, r.y, 1_000_000), (&b, r.x, 1_000_000), (&b, r.x, 1_000_000)] {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, asset, v);
	}
	r.produce().await;
	a.ok(&["board", &x, "2000000"]);
	b.ok(&["board", &y, "3000000", "--fee-asset", &x]);
	b.ok(&["board", &y, "500000", "--fee-asset", &x]);
	r.fund_server(r.x, 50_000_000).await;
	r.fund_server(r.y, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the server to credit the boards", || {
		a.ok(&["boards"]).as_array().unwrap().iter().all(|v| v["server"]["state"] == "credited")
			&& b.ok(&["boards"]).as_array().unwrap().iter().all(|v| v["server"]["state"] == "credited")
	}).await;
	a.ok(&["sync"]);
	b.ok(&["sync"]);
	let b2 = second_device(&b, "RB2");
	let a2 = second_device(&a, "RA2");

	// --- The taker's coin, given to a round on its second device ---
	let small = coins(&b2, "live", &y).into_iter().find(|c| value(c) == 500_000).expect("the taker's small coin");
	let small_id = small["leaf_id"].as_str().unwrap().to_string();
	let new = given_to_a_round(&r, &b2, &small_id).await;
	assert!(live_ids(&b, &y).contains(&small_id), "the first device still counts the coin given elsewhere");
	let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": "300000", "want_asset": y, "want": "400000"})).unwrap();
	let id = offer["swap"].as_str().unwrap().to_string();
	let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap();
	let acc = library(&b, "swap_accept", json!({"offer": offer["offer"], "shown": read})).unwrap();
	assert_eq!(total(&b, "offered", &y), 500_000, "the acceptance names the coin given elsewhere");
	let e = tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run_answer(&mut w, "swap_complete", &json!({"accept": acc["accept"]}))
	}).unwrap_err();
	println!("REFUSED (completion, the taker's coin given elsewhere): {}", e["error"]);
	assert_eq!(e["error"]["kind"], "swap_refused", "{}", e);
	assert_eq!(e["error"]["code"], "double_spend", "{}", e);
	assert_eq!(e["error"]["swap"], id.as_str());
	assert_eq!(e["error"]["coin"], small_id.as_str(), "{}", e);
	assert_eq!(e["error"]["whose"], "taker", "{}", e);
	assert_eq!(library(&a, "swaps", json!({})).unwrap()[0]["state"], "cancelled", "the offer is withdrawn");
	assert_eq!(total(&a, "offered", &x), 0, "nothing stays held for it");
	assert_eq!(total(&a, "live", &x), 2_000_000, "the maker's coin is spendable again");
	let again = library(&a, "swap_complete", json!({"accept": acc["accept"]})).unwrap_err();
	println!("REFUSED (the same acceptance again): {}", again);
	assert!(again.contains("is not an open offer") && again.contains("cancelled"), "{}", again);
	// The taker cancels: the respend is refused, the wallet catches up at once.
	let c = library(&b, "swap_cancel", json!({"swap": id})).unwrap();
	println!("TAKER CANCEL: {}", c);
	assert_eq!(c["cancelled"], true, "{}", c);
	assert_eq!(c["spent_elsewhere"], json!([small_id]), "{}", c);
	assert!(c.get("respent").is_none(), "nothing respent for an acceptance that can never complete: {}", c);
	let live = live_ids(&b, &y);
	assert!(!live.contains(&small_id), "the coin given elsewhere is no longer counted: {:?}", live);
	assert!(live.contains(&new["leaf_id"].as_str().unwrap().to_string()), "the round's coin is held: {:?}", live);
	assert_eq!(total(&b, "live", &y), 3_000_000 + value(&new), "the balance is the truth");
	assert_eq!(library(&b, "swaps", json!({})).unwrap()[0]["state"], "cancelled");

	// --- A payment from a coin given to a round on the second device ---
	let new2 = given_to_a_round(&r, &b2, coins(&b2, "live", &y).iter().find(|c| value(c) == 3_000_000).unwrap()["leaf_id"].as_str().unwrap()).await;
	let big_id = coins(&b, "live", &y).iter().find(|c| value(c) == 3_000_000).expect("the first device still counts it")["leaf_id"]
		.as_str().unwrap().to_string();
	let req = library(&a, "receive", json!({"asset": y, "amount": "1000000"})).unwrap();
	let e = library(&b, "send", json!({"request": req["request"]})).unwrap_err();
	println!("REFUSED (a payment from a coin given elsewhere): {}", e);
	assert!(e.contains("double_spend") && e.contains(&big_id), "{}", e);
	let live = live_ids(&b, &y);
	assert!(!live.contains(&big_id), "the coin given elsewhere is no longer counted: {:?}", live);
	assert!(live.contains(&new2["leaf_id"].as_str().unwrap().to_string()), "the round's coin is held: {:?}", live);
	assert_eq!(total(&b, "live", &y), value(&new) + value(&new2), "the balance is the truth");
	let req = library(&a, "receive", json!({"asset": y, "amount": "300000"})).unwrap();
	let paid = library(&b, "send", json!({"request": req["request"]})).unwrap();
	println!("PAID FROM THE ROUND'S COINS: {}", paid);

	// --- The maker's own coin, given to a round on its second device ---
	let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": "300000", "want_asset": y, "want": "100000"})).unwrap();
	let mine = offer["details"]["inputs"][0]["leaf_id"].as_str().unwrap().to_string();
	given_to_a_round(&r, &a2, &mine).await;
	let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap();
	let acc = library(&b, "swap_accept", json!({"offer": offer["offer"], "shown": read})).unwrap();
	let e = tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run_answer(&mut w, "swap_complete", &json!({"accept": acc["accept"]}))
	}).unwrap_err();
	println!("REFUSED (completion, the maker's coin given elsewhere): {}", e["error"]);
	assert_eq!(e["error"]["kind"], "swap_refused", "{}", e);
	assert_eq!(e["error"]["coin"], mine.as_str(), "{}", e);
	assert_eq!(e["error"]["whose"], "maker", "{}", e);
	assert_eq!(library(&a, "swaps", json!({})).unwrap()[1]["state"], "cancelled");
	// The taker's coins are its own: its cancel respends them, so the
	// acceptance it signed can never complete.
	let c = library(&b, "swap_cancel", json!({"swap": acc["swap"]})).unwrap();
	assert_eq!(c["cancelled"], true, "{}", c);
	assert!(c["respent"].as_array().is_some_and(|v| !v.is_empty()), "{}", c);
}
