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
use elements::hashes::Hash as _;
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

/// The maker completes the swap; the taker, which has not read its mailbox
/// since, cancels (as a page does once it has waited for the maker): the
/// respend is refused, and the swap reads done with what it pays the taker
/// held, never "cancelled", whatever order the wallet's reads come in.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_after_the_maker_completed_reads_done() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("DA");
	let b = Arca::new("DB");
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	a.ok(&create);
	b.ok(&create);
	for (w, asset, v) in [(&a, r.x, 10_000_000), (&b, r.y, 1_000_000), (&b, r.x, 1_000_000)] {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, asset, v);
	}
	r.produce().await;
	a.ok(&["board", &x, "2000000"]);
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
	let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": "300000", "want_asset": y, "want": "400000"})).unwrap();
	let id = offer["swap"].as_str().unwrap().to_string();
	let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap();
	let acc = library(&b, "swap_accept", json!({"offer": offer["offer"], "shown": read})).unwrap();
	let x_before = total(&b, "live", &x);
	library(&a, "swap_complete", json!({"accept": acc["accept"]})).unwrap();
	let c = library(&b, "swap_cancel", json!({"swap": id})).unwrap();
	println!("TAKER CANCEL AFTER THE COMPLETION: {}", c);
	assert_eq!(c["done"], true, "{}", c);
	assert_ne!(c["cancelled"], true, "a completed swap is not cancelled: {}", c);
	let state = library(&b, "swaps", json!({})).unwrap().as_array().unwrap().iter().find(|s| s["swap"] == id.as_str()).unwrap()["state"].clone();
	assert_eq!(state, "done", "the taker's record says done");
	assert_eq!(total(&b, "live", &x), x_before + 300_000, "what the swap pays the taker is held");
	assert_eq!(total(&b, "offered", &y), 0, "nothing stays held");
}

/// The text `kind:hex(json)` of an offer or acceptance, read and written.
fn unhex_text(t: &str) -> Value {
	let h = t.split_once(':').unwrap().1;
	serde_json::from_slice(&(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>()).unwrap()
}

fn hex_text(kind: &str, v: &Value) -> String {
	format!("{}:{}", kind, hex(v.to_string().as_bytes()))
}

/// A maker names in its own output of an offer the owner nonce of a coin
/// the taker already holds (what an earlier trade with it paid the taker).
/// The taker's acceptance meets coins its second device gave to rounds, and
/// the maker never completes: the taker's cancel must not read done, since
/// only the swap's own transfer, spending the taker's own inputs into the
/// taker's own outputs, makes it so.
#[tokio::test(flavor = "multi_thread")]
async fn a_maker_chosen_nonce_does_not_make_a_swap_done() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("NA");
	let b = Arca::new("NB");
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	a.ok(&create);
	b.ok(&create);
	for (w, asset, v) in [(&a, r.x, 10_000_000), (&b, r.y, 10_000_000), (&b, r.y, 1_000_000), (&b, r.x, 1_000_000), (&b, r.x, 1_000_000)] {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, asset, v);
	}
	r.produce().await;
	a.ok(&["board", &x, "3000000"]);
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
	let state = |w: &Arca, id: &str| library(w, "swaps", json!({})).unwrap().as_array().unwrap().iter().find(|s| s["swap"] == id).unwrap()["state"].clone();
	// Trade 1, honest: it pays the taker under a nonce the maker sees.
	let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": "300000", "want_asset": y, "want": "1000000"})).unwrap();
	let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap();
	let acc = library(&b, "swap_accept", json!({"offer": offer["offer"], "shown": read})).unwrap();
	library(&a, "swap_complete", json!({"accept": acc["accept"]})).unwrap();
	b.ok(&["sync"]);
	assert_eq!(state(&b, offer["swap"].as_str().unwrap()), "done");
	let n_off = offer["details"]["outputs"].as_array().unwrap().len();
	let held_nonce = unhex_text(acc["accept"].as_str().unwrap())["outputs"][n_off]["owner_nonce"].as_str().unwrap().to_string();
	// Every coin of y the taker holds, given to a round by its second device.
	let b2 = second_device(&b, "NB2");
	for l in coins(&b2, "live", &y).iter().map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect::<Vec<_>>() {
		given_to_a_round(&r, &b2, &l).await;
	}
	// Trade 2: the maker's own output carries the taker's held nonce.
	let offer2 = library(&a, "swap_offer", json!({"give_asset": x, "give": "300000", "want_asset": y, "want": "400000"})).unwrap();
	let mut d = offer2["details"].clone();
	d["outputs"][0]["owner_nonce"] = json!(held_nonce);
	let tampered = hex_text(offer2["offer"].as_str().unwrap().split_once(':').unwrap().0, &d);
	let read = library(&b, "swap_read", json!({"offer": tampered})).unwrap();
	let acc2 = library(&b, "swap_accept", json!({"offer": tampered, "shown": read})).unwrap();
	let id2 = acc2["swap"].as_str().unwrap().to_string();
	// The maker never completes; the taker cancels.
	let c = library(&b, "swap_cancel", json!({"swap": id2})).unwrap();
	println!("TAKER CANCEL OF A SWAP NEVER COMPLETED: {}", c);
	assert_ne!(c["done"], true, "nothing traded, yet the cancel reads done: {}", c);
	assert_ne!(state(&b, &id2), "done", "nothing traded, yet the swap reads done");
}

/// The answer to a cancel's respend is lost, so the coins signed into the
/// acceptance stay `sending`: the respend request stands, and the wallet
/// does not know whether the operator co-signed it. A cancel then never
/// says the acceptance can no longer complete without knowing it. While the
/// operator cannot be reached it says the acceptance may still complete; the
/// maker then completes it, and the next cancel, which posts the standing
/// respend again, reads the swap done. When the operator co-signed the lost
/// respend, the next cancel reads it cancelled, and the maker's completion is
/// refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_whose_respend_was_not_answered_says_what_it_knows() {
	use std::sync::Arc;
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	let proxy = common::proxy::Proxy::start(&url);
	let a = Arca::new("LA");
	let b = Arca::new("LB");
	let create = |u: &str| -> Vec<String> {
		["create", "--server", u, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]
			.iter().map(|s| s.to_string()).collect()
	};
	let ca = create(&url);
	let cb = create(&proxy.url);
	a.ok(&ca.iter().map(|s| s.as_str()).collect::<Vec<_>>());
	b.ok(&cb.iter().map(|s| s.as_str()).collect::<Vec<_>>());
	for (w, asset, v) in [(&a, r.x, 10_000_000), (&b, r.y, 1_000_000), (&b, r.x, 1_000_000)] {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, asset, v);
	}
	r.produce().await;
	a.ok(&["board", &x, "2000000"]);
	b.ok(&["board", &y, "900000", "--fee-asset", &x]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the server to credit the boards", || {
		a.ok(&["boards"]).as_array().unwrap().iter().all(|v| v["server"]["state"] == "credited")
			&& b.ok(&["boards"]).as_array().unwrap().iter().all(|v| v["server"]["state"] == "credited")
	}).await;
	a.ok(&["sync"]);
	b.ok(&["sync"]);
	let state = |w: &Arca, id: &str| library(w, "swaps", json!({})).unwrap().as_array().unwrap().iter().find(|s| s["swap"] == id).unwrap()["state"].clone();

	// --- The respend never reaches the operator, and the maker completes ---
	let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": "300000", "want_asset": y, "want": "400000"})).unwrap();
	let id = offer["swap"].as_str().unwrap().to_string();
	let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap();
	let acc = library(&b, "swap_accept", json!({"offer": offer["offer"], "shown": read})).unwrap();
	let x_before = total(&b, "live", &x);
	proxy.lose("/v1/cosign_transfer", true);
	let c1 = library(&b, "swap_cancel", json!({"swap": id})).unwrap();
	println!("CANCEL, THE RESPEND LOST: {}", c1);
	assert_eq!(c1["cancelled"], false, "{}", c1);
	assert_eq!(total(&b, "sending", &y), 900_000, "the coin signed into the acceptance waits for the respend's answer");
	let c2 = library(&b, "swap_cancel", json!({"swap": id})).unwrap();
	println!("CANCEL AGAIN, THE OPERATOR STILL UNREACHABLE: {}", c2);
	assert_ne!(c2["cancelled"], true, "nothing shows the acceptance can no longer complete: {}", c2);
	assert_eq!(state(&b, &id), "accepted", "the swap is not recorded cancelled");
	// The operator never saw the respend: the acceptance completes.
	library(&a, "swap_complete", json!({"accept": acc["accept"]})).unwrap();
	proxy.lose("/v1/cosign_transfer", false);
	let c3 = library(&b, "swap_cancel", json!({"swap": id})).unwrap();
	println!("CANCEL ONCE THE OPERATOR ANSWERS, AFTER THE COMPLETION: {}", c3);
	assert_eq!(c3["done"], true, "{}", c3);
	assert_ne!(c3["cancelled"], true, "a completed swap is not cancelled: {}", c3);
	assert_eq!(state(&b, &id), "done");
	assert_eq!(total(&b, "live", &x), x_before + 300_000, "what the swap pays the taker is held");
	assert_eq!(total(&b, "offered", &y) + total(&b, "sending", &y), 0, "nothing stays held");

	// --- The operator co-signs the respend, and its answer is lost ---
	let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": "300000", "want_asset": y, "want": "100000"})).unwrap();
	let id = offer["swap"].as_str().unwrap().to_string();
	let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap();
	let acc = library(&b, "swap_accept", json!({"offer": offer["offer"], "shown": read})).unwrap();
	let held = total(&b, "offered", &y);
	assert!(held > 0, "the acceptance holds a coin");
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, _: &mut Value| {
		if path == "/v1/cosign_transfer" && status == 200 { Some(502) } else { None }
	})));
	let c1 = library(&b, "swap_cancel", json!({"swap": id})).unwrap();
	println!("CANCEL, THE RESPEND CO-SIGNED, ITS ANSWER LOST: {}", c1);
	assert_eq!(c1["cancelled"], false, "{}", c1);
	assert_eq!(total(&b, "sending", &y), held);
	proxy.rewrite(None);
	let c2 = library(&b, "swap_cancel", json!({"swap": id})).unwrap();
	println!("CANCEL ONCE THE OPERATOR ANSWERS: {}", c2);
	assert_eq!(c2["cancelled"], true, "{}", c2);
	assert!(c2["respent"].as_array().is_some_and(|v| !v.is_empty()), "the respend is what cancels it: {}", c2);
	assert_eq!(state(&b, &id), "cancelled");
	let e = library(&a, "swap_complete", json!({"accept": acc["accept"]})).unwrap_err();
	println!("MAKER'S COMPLETION AFTER THE RESPEND: {}", e);
	assert!(e.contains("double_spend"), "{}", e);
	assert_eq!(total(&b, "offered", &y) + total(&b, "sending", &y), 0, "nothing stays held");

	// --- The respend lost, the maker completes, a sync posts the respend again ---
	let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": "200000", "want_asset": y, "want": "100000"})).unwrap();
	let id = offer["swap"].as_str().unwrap().to_string();
	let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap();
	let acc = library(&b, "swap_accept", json!({"offer": offer["offer"], "shown": read})).unwrap();
	let x_before = total(&b, "live", &x);
	proxy.lose("/v1/cosign_transfer", true);
	let c1 = library(&b, "swap_cancel", json!({"swap": id})).unwrap();
	assert_eq!(c1["cancelled"], false, "{}", c1);
	library(&a, "swap_complete", json!({"accept": acc["accept"]})).unwrap();
	proxy.lose("/v1/cosign_transfer", false);
	let s = b.ok(&["sync"]);
	println!("SYNC POSTS THE RESPEND AGAIN: {}", s["transfers"]);
	let c2 = library(&b, "swap_cancel", json!({"swap": id})).unwrap();
	println!("CANCEL AFTER THE SYNC: {}", c2);
	assert_ne!(c2["cancelled"], true, "a completed swap is not cancelled: {}", c2);
	assert_eq!(state(&b, &id), "done");
	assert_eq!(total(&b, "live", &x), x_before + 200_000, "what the swap pays the taker is held");
	assert_eq!(total(&b, "offered", &y) + total(&b, "sending", &y), 0, "nothing stays held");
}

/// A board coin that a second device of the wallet gave to a round: the
/// first device's re-check finds the board spent on the chain by nothing it
/// did, and reads what its other stores did at once, rather than at its next
/// catch-up (up to ten minutes later). It then holds the round's coin in place
/// of the board, and a payment that needs the value goes ahead.
#[tokio::test(flavor = "multi_thread")]
async fn a_board_another_device_gave_to_a_round_is_followed_at_once() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("GA");
	let b = Arca::new("GB");
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	a.ok(&create);
	b.ok(&create);
	for (w, asset, v) in [(&a, r.x, 1_000_000), (&b, r.y, 10_000_000), (&b, r.x, 1_000_000)] {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, asset, v);
	}
	r.produce().await;
	a.ok(&["board", &x, "500000"]);
	b.ok(&["board", &y, "3000000", "--fee-asset", &x]);
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
	let b2 = second_device(&b, "GB2");
	let board = coins(&b2, "live", &y).into_iter().find(|c| value(c) == 3_000_000).expect("the board coin");
	let board_id = board["leaf_id"].as_str().unwrap().to_string();
	let new = given_to_a_round(&r, &b2, &board_id).await;
	// The operator publishes the forfeit of a board given up in a final
	// round, from the board's output: the board is spent on the chain.
	for _ in 0..6 {
		r.server.watcher.pass().await.unwrap();
		r.produce().await;
	}
	r.bury().await;
	r.synced().await;
	let req = library(&a, "receive", json!({"asset": y, "amount": "2900000"})).unwrap();
	let paid = library(&b, "send", json!({"request": req["request"]}));
	println!("PAYMENT AFTER THE SECOND DEVICE GAVE THE BOARD TO A ROUND: {:?}", paid.as_ref().map(|v| v["transfer_id"].clone()));
	let paid = paid.unwrap();
	assert!(paid.get("error").is_none(), "{}", paid);
	let states: Vec<Value> = b.ok(&["coins"]).as_array().unwrap().iter()
		.filter(|c| c["leaf_id"] == board_id.as_str() || c["leaf_id"] == new["leaf_id"]).map(|c| json!([c["leaf_id"], c["state"]])).collect();
	println!("THE BOARD AND THE ROUND'S COIN ON THE FIRST DEVICE: {:?}", states);
	assert!(coins(&b, "pending", &y).is_empty(), "nothing left pending: {}", b.ok(&["coins"]));
	assert!(!live_ids(&b, &y).contains(&board_id), "the board given up is not counted");
}

/// The answer to a cancel's respend is lost; a sync posts it again and the
/// operator refuses it for a reason other than a spent coin (a signature the
/// proxy spoils, standing for a margin or fee the operator no longer takes).
/// The coin is held for the swap again, not live: the wallet's refresh cannot
/// give it to a round, where a cancel could miss it and a withdrawal of the
/// refresh would hand it back to a maker still holding the acceptance. The
/// next cancel respends it, and the maker's completion is then refused.
/// (RV41's probe P10.)
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_respend_keeps_the_coin_held_for_the_swap() {
	use std::sync::Arc;
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	let proxy = common::proxy::Proxy::start(&url);
	let a = Arca::new("HA");
	let b = Arca::new("HB");
	a.ok(&["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	b.ok(&["create", "--server", &proxy.url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	for (w, asset, v) in [(&a, r.x, 10_000_000), (&b, r.y, 1_000_000), (&b, r.x, 1_000_000)] {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, asset, v);
	}
	r.produce().await;
	a.ok(&["board", &x, "2000000"]);
	b.ok(&["board", &y, "900000", "--fee-asset", &x]);
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
	let state = |w: &Arca, id: &str| library(w, "swaps", json!({})).unwrap().as_array().unwrap().iter().find(|s| s["swap"] == id).unwrap()["state"].clone();
	let st = |w: &Arca, l: &str| w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == l).map(|c| c["state"].clone()).unwrap_or(Value::Null);
	let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": "300000", "want_asset": y, "want": "400000"})).unwrap();
	let id = offer["swap"].as_str().unwrap().to_string();
	let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap();
	let acc = library(&b, "swap_accept", json!({"offer": offer["offer"], "shown": read})).unwrap();
	let coin = coins(&b, "offered", &y)[0]["leaf_id"].as_str().unwrap().to_string();
	proxy.lose("/v1/cosign_transfer", true);
	let c1 = library(&b, "swap_cancel", json!({"swap": id})).unwrap();
	proxy.lose("/v1/cosign_transfer", false);
	assert_eq!(c1["cancelled"], false, "{}", c1);
	proxy.rewrite_request(Some(Arc::new(|path: &str, body: &mut Value| {
		if path == "/v1/cosign_transfer" {
			body["inputs"][0]["checkpoint_sig"] = json!("11".repeat(64));
		}
	})));
	let s = b.ok(&["sync"]);
	proxy.rewrite_request(None);
	println!("SYNC POSTS THE RESPEND AGAIN, REFUSED: {}", s["transfers"]);
	println!("THE COIN AFTER THE REFUSAL: {}", st(&b, &coin));
	assert_eq!(st(&b, &coin), "offered", "the coin is held for the swap again");
	let (ok, p) = b.run(&["participate", "--leaf", &coin]);
	println!("A REFRESH OF THE COIN: ok {} {}", ok, p);
	// Whatever the refresh did, take it back, as a person or the wallet may.
	if let Some(pid) = b.ok(&["participations"]).as_array().and_then(|a| a.iter().find(|p| p["state"] == "pending")).and_then(|p| p["participation"].as_str()).map(String::from) {
		b.run(&["withdraw-participation", &pid]);
	}
	let c2 = library(&b, "swap_cancel", json!({"swap": id})).unwrap();
	println!("CANCEL AFTER THE REFUSED RESPEND: {}", c2);
	let done = library(&a, "swap_complete", json!({"accept": acc["accept"]}));
	println!("THE MAKER'S COMPLETION AFTER IT: {:?}", done.as_ref().map(|d| d["swap"].clone()));
	assert!(!(c2["cancelled"] == true && done.is_ok()), "the cancel said cancelled, and the maker completed the acceptance after it: {}", c2);
	assert_eq!(c2["cancelled"], true, "{}", c2);
	assert!(c2["respent"].as_array().is_some_and(|v| !v.is_empty()), "{}", c2);
	assert!(done.unwrap_err().contains("double_spend"));
	assert_eq!(state(&b, &id), "cancelled");
}

/// A coin signed into an acceptance is forfeited in a round not final yet.
/// A forfeited coin comes back when its round is dropped (another
/// participant never hands over its forfeits, arca #823), and the maker can
/// then complete the acceptance with it: so until the round is final, a
/// cancel answers that the acceptance stands. Once the round is final and
/// the wallet holds its new coin, the cancel reads the mailbox and answers
/// cancelled, and the maker's completion is refused.
///
/// The coin gets there as it does when another device's refresh holds it in
/// a round that is then dropped: the cancel's respend is lost; a sync posts
/// it again and is answered that the coin is spent (`double_spend`, here by
/// the proxy, the operator refusing the spoiled request), so the coin goes
/// live for the catch-up; it is not spent, and the wallet's own refresh gives
/// it to a round. The operator is the testnet's: batches without a sweep,
/// whose forfeits are taken before the round is broadcast (on a batch with a
/// sweep the wallet signs no forfeit before the round is final).
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_forfeited_in_a_round_not_final_keeps_the_acceptance_standing() {
	use std::sync::Arc;
	let mut r = Running::start_with(|c, _, _| {
		c.batches.no_sweep = true;
		c.batches.holder_batches = Some(0);
	}).await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	let proxy = common::proxy::Proxy::start(&url);
	let a = Arca::new("KA");
	let b = Arca::new("KB");
	a.ok(&["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	b.ok(&["create", "--server", &proxy.url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	for (w, asset, v) in [(&a, r.x, 10_000_000), (&b, r.y, 1_000_000), (&b, r.x, 1_000_000)] {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, asset, v);
	}
	r.produce().await;
	a.ok(&["board", &x, "2000000"]);
	b.ok(&["board", &y, "600000", "--fee-asset", &x]);
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
	let st = |w: &Arca, l: &str| w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == l).map(|c| c["state"].clone()).unwrap_or(Value::Null);
	let state = |w: &Arca, id: &str| library(w, "swaps", json!({})).unwrap().as_array().unwrap().iter().find(|s| s["swap"] == id).unwrap()["state"].clone();
	let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": "300000", "want_asset": y, "want": "400000"})).unwrap();
	let id = offer["swap"].as_str().unwrap().to_string();
	let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap();
	let acc = library(&b, "swap_accept", json!({"offer": offer["offer"], "shown": read})).unwrap();
	let coin = coins(&b, "offered", &y)[0]["leaf_id"].as_str().unwrap().to_string();
	// The cancel's respend is lost.
	proxy.lose("/v1/cosign_transfer", true);
	let c1 = library(&b, "swap_cancel", json!({"swap": id})).unwrap();
	proxy.lose("/v1/cosign_transfer", false);
	assert_eq!(c1["cancelled"], false, "{}", c1);
	// A sync posts it again: the operator refuses the spoiled request, and the
	// answer the wallet reads says the coin is spent.
	let named = coin.clone();
	proxy.rewrite_request(Some(Arc::new(|path: &str, body: &mut Value| {
		if path == "/v1/cosign_transfer" {
			body["inputs"][0]["checkpoint_sig"] = json!("11".repeat(64));
		}
	})));
	proxy.rewrite(Some(Arc::new(move |path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/cosign_transfer" && status != 200 {
			*v = json!({"error": {"code": "double_spend", "message": format!("leaf {} is already spent: the server co-signs one spend of a leaf", named)}});
			return Some(409);
		}
		None
	})));
	let s = b.ok(&["sync"]);
	proxy.rewrite_request(None);
	proxy.rewrite(None);
	println!("SYNC POSTS THE RESPEND AGAIN, ANSWERED SPENT: {}", s["transfers"]);
	println!("THE COIN AFTER IT: {}", st(&b, &coin));
	assert_eq!(st(&b, &coin), "live", "a double_spend leaves the coin live, for the catch-up");
	// The wallet's own refresh gives it to a round, and hands over its
	// forfeit; the round is broadcast and not final.
	let p = b.ok(&["participate", "--leaf", &coin]);
	assert_eq!(p["participations"][0]["state"], "pending", "{}", p);
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(!built.is_empty() && failed.is_empty(), "{} built, {} failed", built.len(), failed.len());
	let s = b.ok(&["sync"]);
	println!("THE TAKER'S SYNC AFTER THE ROUND: {}", s["participations"]);
	r.server.rounds.pass().await.unwrap();
	for t in &built {
		let round = r.server.store.round_by_txid(&t.tx.txid().to_byte_array()).await.unwrap().map(|x| x.state);
		println!("ROUND {}: {:?}", t.tx.txid(), round);
		assert_ne!(round, Some(RoundState::Final), "the round is not final yet");
	}
	println!("THE COIN: {}", st(&b, &coin));
	assert_eq!(st(&b, &coin), "forfeited", "the coin is given up under its forfeit");
	let c2 = library(&b, "swap_cancel", json!({"swap": id})).unwrap();
	println!("CANCEL, THE COIN FORFEITED, THE ROUND NOT FINAL: {}", c2);
	assert_ne!(c2["cancelled"], true, "a coin forfeited in a round not final can come back: the acceptance stands: {}", c2);
	assert_eq!(c2["acceptance_stands"], true, "{}", c2);
	assert_eq!(state(&b, &id), "accepted");
	// The round final, the wallet holding its new coin: the cancel goes on.
	r.produce().await;
	r.bury().await;
	for t in &built {
		r.round_state(&t.tx.txid(), RoundState::Final).await;
	}
	let s = b.ok(&["sync"]);
	println!("THE TAKER'S SYNC AFTER THE ROUND IS FINAL: {}", s["participations"]);
	let c3 = library(&b, "swap_cancel", json!({"swap": id})).unwrap();
	println!("CANCEL, THE ROUND FINAL: {}", c3);
	assert_eq!(c3["cancelled"], true, "{}", c3);
	assert_eq!(state(&b, &id), "cancelled");
	let done = library(&a, "swap_complete", json!({"accept": acc["accept"]}));
	println!("THE MAKER'S COMPLETION AFTER IT: {:?}", done);
	assert!(done.is_err(), "the maker cannot complete an acceptance whose coin is given up in a final round");
}
