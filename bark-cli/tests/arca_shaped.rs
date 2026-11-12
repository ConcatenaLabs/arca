//! A trade refused after its coin was shaped (`Error::Shaped`): in default
//! mode (an instant limit set) a trade that no single coin holds first pays
//! the wallet itself a coin of exactly what it gives, and only then accepts.
//! When the coin made is not the one priced, the acceptance is refused as
//! `shaped`, naming what that payment cost, which the terms shown already
//! counted; the coin made is kept, and the next read trades from it with
//! nothing more to pay itself.
//!
//! A shaping payment that comes out other than priced cannot be made on
//! purpose through the shipped wallet, so this test is built only with the
//! `shape-probe` feature (`cargo test -p arca-cli --features shape-probe
//! --test arca_shaped`), which lets its own call to `swap_accept` name
//! `shape_off_by`: the coin is shaped that many atoms off. No shipped build
//! has the feature; CI checks that.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`). `ARCA_TEST_TESTNET=1` with
//! `ARCA_TEST_ANCHOR_DEPTH=0` runs it at the testnet operator's settings.

mod common;

use elements::Script;
use serde_json::{json, Value};

use bark::arca::{command, Wallet};
use common::cli::Arca;
use common::running::Running;

/// One command of the library on the wallet in `a`'s directory, as a
/// program that embeds the library runs it: its result, or its refusal as
/// the program reads it (`kind`, `message` and the refusal's fields).
fn library(a: &Arca, cmd: &str, args: Value) -> Result<Value, Value> {
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run_answer(&mut w, cmd, &args).map(|v| v["result"].clone())
	})
}

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

fn value(c: &Value) -> u64 {
	c["value"].as_str().unwrap().parse().unwrap()
}

fn num(v: &Value) -> u64 {
	v.as_str().unwrap().parse().unwrap()
}

async fn post_bond(r: &mut Running) {
	use arca_covenant::bond::BondPolicy;
	let w = common::running::keypair("mk3 bond W");
	let s_key = common::running::keypair("operator");
	let chain = arca_covenant::Chain::new(r.rt.client().genesis_hash().unwrap());
	let notice = server::bond::min_notice_seconds(server::bond::LIFETIME, arca_covenant::RelativeTime::from_units(338).unwrap()).div_ceil(512) as u16;
	let policy = BondPolicy::new(chain, s_key.x_only_public_key().0, w.x_only_public_key().0,
		arca_covenant::RelativeTime::from_units(notice).unwrap()).unwrap();
	let x = r.x;
	let tx = r.pay_to(policy.script_pubkey(), x, 50_000_000);
	r.produce().await;
	r.bury().await;
	let vout = tx.output.iter().position(|o| o.script_pubkey == policy.script_pubkey()).unwrap() as u32;
	r.config.bond = Some(server::bond::BondSection { withdraw_key: w.x_only_public_key().0.to_string(), notice_units: notice,
		outpoint: Some(format!("{}:{}", tx.txid(), vout)), notice: None, instant_budget_fraction: None, instant_limit_value: None });
	r.restart_server().await;
	r.synced().await;
}

/// What `w` holds of `asset` in every state but spent (and its coins given
/// up: a coin forfeited for a new one is not counted twice).
fn held_all(w: &Arca, asset: &str) -> u64 {
	w.ok(&["coins"]).as_array().unwrap().iter()
		.filter(|c| c["asset"] == asset && !matches!(c["state"].as_str(), Some("spent" | "forfeited" | "exited" | "lost")))
		.map(value).sum()
}

async fn start_at_the_settings_asked() -> Running {
	let testnet = std::env::var("ARCA_TEST_TESTNET").is_ok_and(|v| v == "1");
	println!("SETTINGS: testnet {} anchor depth {:?}", testnet, std::env::var("ARCA_TEST_ANCHOR_DEPTH").ok());
	Running::start_with(move |c, _, _| {
		if testnet {
			c.checkpoint_exit = false;
			c.batches.no_sweep = true;
			c.batches.holder_batches = Some(0);
			c.batches.collect_after_seconds = Some(2_419_200);
		}
	}).await
}

/// The coins `w` holds of `asset` in every state but spent, by id.
fn held_ids(w: &Arca, asset: &str) -> Vec<String> {
	let mut ids: Vec<String> = w.ok(&["coins"]).as_array().unwrap().iter()
		.filter(|c| c["asset"] == asset && !matches!(c["state"].as_str(), Some("spent" | "forfeited" | "exited" | "lost")))
		.map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
	ids.sort();
	ids
}

/// The shaping payment one atom short of what was priced: the acceptance
/// is refused `shaped` with that payment's cost, which is what left the
/// wallet; the coin made is kept; the next read trades from that coin
/// alone, with nothing to shape, and the trade from it takes exactly what
/// its own terms show.
#[tokio::test(flavor = "multi_thread")]
async fn a_shaping_payment_other_than_priced_is_refused_shaped_and_its_coin_trades_next() {
	let mut r = start_at_the_settings_asked().await;
	common::node::list_fee_asset(&r.rt, r.y, 100_000_000);
	post_bond(&mut r).await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	let (a, b) = (Arca::new("SHA"), Arca::new("SHB"));
	a.ok(&create);
	b.ok(&create);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, r.x, 10_000_000);
	for (asset, v) in [(r.y, 10_000_000), (r.x, 2_000_000)] {
		let s = script(&b.ok(&["address"]));
		r.pay_to(s, asset, v);
	}
	r.produce().await;
	a.ok(&["board", &x, "1000000"]);
	r.produce().await;
	for v in [300_000u64, 300_000] {
		b.ok(&["board", &y, &v.to_string(), "--fee-asset", &x]);
		r.produce().await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards credited", || [&a, &b].iter().all(|w| w.ok(&["boards"]).as_array().unwrap().iter().all(|v| v["server"]["state"] == "credited"))).await;
	a.ok(&["sync"]);
	b.ok(&["sync"]);
	library(&b, "instant_limit", json!({"value": "1000000000000"})).unwrap();
	let (y0, ids0) = (held_all(&b, &y), held_ids(&b, &y));

	// Two coins of 300,000; the trade gives 400,000: a coin of it is shaped first.
	let offer = library(&a, "swap_offer", json!({"give_asset": x, "give": "20000", "want_asset": y, "want": "400000"})).unwrap();
	let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap();
	println!("READ: coins_spent {} gets {} pays {}", read["coins_spent"], read["gets"], read["pays"]);
	let shapes = num(&read["pays"]["shapes"]);
	assert!(shapes > 0, "the read counts a shaping payment: {}", read);

	// Shaped one atom short: refused `shaped`, with that payment's cost.
	let e = library(&b, "swap_accept", json!({"offer": offer["offer"], "shown": read, "shape_off_by": -1})).unwrap_err()["error"].clone();
	println!("REFUSED: {}", e);
	assert_eq!(e["kind"], "shaped", "{}", e);
	assert_eq!(e["asset"], y.as_str(), "{}", e);
	assert_eq!(e["fee"].as_u64().or_else(|| e["fee"].as_str().and_then(|f| f.parse().ok())), Some(shapes), "the cost named is the one shown: {}", e);
	let y1 = held_all(&b, &y);
	println!("Y {} -> {} (-{}; shown as the shaping payment's: {})", y0, y1, y0 - y1, shapes);
	assert_eq!(y0 - y1, shapes, "what left the wallet is the shaping payment's cost, shown in the terms, and nothing more");
	// The coin made is kept: one coin of 399,999 the wallet did not hold before.
	let made: Vec<Value> = b.ok(&["coins"]).as_array().unwrap().iter()
		.filter(|c| c["asset"] == y.as_str() && c["state"] == "live" && !ids0.contains(&c["leaf_id"].as_str().unwrap().to_string()))
		.cloned().collect();
	println!("MADE: {:?}", made.iter().map(|c| (c["leaf_id"].clone(), c["value"].clone())).collect::<Vec<_>>());
	// The coin priced held the 400,000 the trade gives and its own checkpoint margin; the one made
	// holds an atom less, the change an atom more.
	let margin = num(&read["pays"]["margins"]) - shapes;
	let coin = made.iter().find(|c| value(c) == 400_000 + margin - 1).unwrap_or_else(|| panic!("the coin shaped is kept: {:?}", made)).clone();
	library(&a, "swap_cancel", json!({"swap": offer["swap"]})).unwrap();

	// The next read trades from that coin: alone, nothing to shape.
	let want2 = value(&coin) - margin;
	let offer2 = library(&a, "swap_offer", json!({"give_asset": x, "give": "19999", "want_asset": y, "want": want2.to_string()})).unwrap();
	let read2 = library(&b, "swap_read", json!({"offer": offer2["offer"]})).unwrap();
	println!("READ AGAIN: coins_spent {} pays {} change {}", read2["coins_spent"], read2["pays"], read2["change"]);
	assert_eq!(read2["coins_spent"], 1, "{}", read2);
	assert_eq!(read2["pays"]["shapes"], "0", "nothing more to shape, nothing charged again: {}", read2);
	assert_eq!(read2["change"]["value"], "0", "{}", read2);
	let acc = library(&b, "swap_accept", json!({"offer": offer2["offer"], "shown": read2})).unwrap();
	library(&a, "swap_complete", json!({"accept": acc["accept"]})).unwrap();
	b.ok(&["sync"]);
	let given = b.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == coin["leaf_id"]).cloned().unwrap();
	println!("THE SHAPED COIN NOW: {}", given["state"]);
	assert_ne!(given["state"], "live", "the trade gave the coin shaped: {}", given);
	let y2 = held_all(&b, &y);
	let out = num(&read2["gives"]["value"]) + num(&read2["pays"]["margins"]);
	println!("Y {} -> {} (-{}; shown {})", y1, y2, y1 - y2, out);
	assert_eq!(y1 - y2, out, "the trade from the coin takes what its terms show, the shaping not again");
}
