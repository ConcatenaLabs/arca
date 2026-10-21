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
	let mb = b.ok(&["mailbox"]);
	assert_eq!(mb["accepted"].as_array().unwrap().len(), 2, "the taker gets its X leaf and its Y change: {}", mb);
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
	assert_eq!(library(&a, "swaps", json!({})).unwrap()[1]["state"], "cancelled");
}
