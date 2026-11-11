//! `refresh_needed`: whether the coins a wallet received out of round should
//! be given up in a refresh now, and why, by the rules a wallet in use
//! weighs (D95). A received coin given up in a round is not the wallet's to
//! spend until that round is final, so a wallet refreshes only when it must:
//!
//! 1. A small coin received from another wallet, the person active: nothing
//!    needed. Left alone two minutes (`idle_seconds` 130): `idle`.
//! 2. The same coin paid on by its holder until it is one reassignment
//!    short of the operator's depth limit: `depth`, naming that coin.
//! 3. A coin of Y (not the bond's asset X) worth more than half the bond, at
//!    the node's rates: `exposure`. Every asset is weighed, not only the
//!    bond's.
//! 4. A wallet that received nothing: nothing needed, whatever the idle time.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::{AssetId, OutPoint, Script};
use serde_json::{json, Value};

use arca_covenant::bond::BondPolicy;
use arca_covenant::RelativeTime;
use bark::arca::{command, Wallet};
use common::cli::Arca;
use common::running::{keypair, Running};
use server::bond::BondSection;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

fn library(a: &Arca, cmd: &str, args: Value) -> Result<Value, String> {
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run(&mut w, cmd, &args).map(|v| v["result"].clone()).map_err(|e| e.to_string())
	})
}

fn create(r: &Running, w: &Arca) {
	w.ok(&["create", "--server", &r.url(), "--node-url", &r.node_url(), "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
}

const BOND: u64 = 5_000_000;

fn notice_units() -> u16 {
	server::bond::min_notice_seconds(server::bond::LIFETIME, RelativeTime::from_units(338).unwrap()).div_ceil(512) as u16
}

async fn post_bond(r: &mut Running) -> OutPoint {
	let w = keypair("refresh-needed W");
	let s_key = keypair("operator");
	let chain = arca_covenant::Chain::new(r.rt.client().genesis_hash().unwrap());
	let policy = BondPolicy::new(chain, s_key.x_only_public_key().0, w.x_only_public_key().0,
		RelativeTime::from_units(notice_units()).unwrap()).unwrap();
	let x = r.x;
	let tx = r.pay_to(policy.script_pubkey(), x, BOND);
	r.produce().await;
	r.bury().await;
	let vout = tx.output.iter().position(|o| o.script_pubkey == policy.script_pubkey()).unwrap() as u32;
	let op = OutPoint::new(tx.txid(), vout);
	r.config.bond = Some(BondSection { withdraw_key: w.x_only_public_key().0.to_string(), notice_units: notice_units(),
		outpoint: Some(format!("{}:{}", op.txid, op.vout)), notice: None, instant_budget_fraction: None });
	r.restart_server().await;
	r.synced().await;
	op
}

async fn boarded(r: &mut Running, w: &Arca, assets: &[(AssetId, u64)]) {
	create(r, w);
	let x = r.x;
	for (a, v) in assets {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, *a, v + 3_000_000);
	}
	let s = script(&w.ok(&["address"]));
	r.pay_to(s, x, 3_000_000);
	r.produce().await;
	for (a, v) in assets {
		w.ok(&["board", &a.to_string(), &v.to_string(), "--fee-asset", &x.to_string()]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards to be credited", || {
		w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")
	}).await;
	w.ok(&["sync"]);
}

/// `from` pays `to` `amount` of `asset` out of round; the coin `to` holds.
fn pay(from: &Arca, to: &Arca, asset: AssetId, amount: u64) -> String {
	let req = to.ok(&["receive"])["request"].as_str().unwrap().to_string();
	from.ok(&["send", &req, "--amount", &amount.to_string(), "--asset", &asset.to_string()]);
	let mb = to.ok(&["mailbox"]);
	mb["accepted"].as_array().unwrap().last().and_then(|c| c["leaf_id"].as_str()).expect("the payee holds the coin").to_string()
}

fn rules(v: &Value) -> Vec<String> {
	v["reasons"].as_array().unwrap().iter().map(|r| r["rule"].as_str().unwrap().to_string()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_is_needed_only_by_its_rules() {
	let mut r = Running::start().await;
	let (x, y) = (r.x, r.y);
	let a = Arca::new("RN A");
	boarded(&mut r, &a, &[(x, 8_000_000), (y, 8_000_000)]).await;
	// The node prices Y at twice X, as an operator's price server would set it: every asset is
	// weighed at the node's rates.
	let mut set: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
	set[y.to_string()] = json!(200_000_000u64);
	r.rt.client().call::<Value>("setfeeexchangerates", &[set]).unwrap();
	// The operator reads the rates at its start: the bond's restart.
	post_bond(&mut r).await;
	a.ok(&["sync"]);
	let rates: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
	println!("RN the node's rates: {}", rates);
	let rate = |a: AssetId| rates[a.to_string()].as_u64().unwrap_or_else(|| panic!("no rate for {} in {}", a, rates)) as u128;
	let bond_worth = BOND as u128 * rate(x) / 100_000_000;

	// 4. Nothing received: nothing needed, however long left alone.
	let n = Arca::new("RN N");
	create(&r, &n);
	let v = library(&n, "refresh_needed", json!({"idle_seconds": 10_000})).unwrap();
	println!("RN nothing received: {}", v);
	assert_eq!(v["needed"], false, "{}", v);
	assert_eq!(v["rules"], json!(["depth", "exposure", "expiry", "idle"]));

	// 1. A small coin of Y: nothing needed while the person is active; idle after two minutes.
	let b = Arca::new("RN B");
	create(&r, &b);
	let small = 100_000u64;
	assert!(small as u128 * rate(y) / 100_000_000 * 2 < bond_worth, "the small coin is under half the bond");
	let got = pay(&a, &b, y, small);
	let v = library(&b, "refresh_needed", json!({"idle_seconds": 30})).unwrap();
	println!("RN small coin, active: {}", v);
	assert_eq!(v["needed"], false, "{}", v);
	assert_eq!(v["received"], json!([got]));
	let v = library(&b, "refresh_needed", json!({"idle_seconds": 130})).unwrap();
	println!("RN small coin, idle 130 s: {}", v);
	assert_eq!((v["needed"].as_bool(), rules(&v)), (Some(true), vec!["idle".to_string()]), "{}", v);

	// 2. Paid on by B to itself until one reassignment short of the limit.
	let limit = b.ok(&["info"])["server_info"]["depth_limit"].as_u64().unwrap();
	for _ in 0..(limit - 2) {
		let req = b.ok(&["receive"]);
		let have: u64 = b.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == y.to_string().as_str())
			.map(|c| c["value"].as_str().unwrap().parse::<u64>().unwrap()).sum();
		b.ok(&["send", req["request"].as_str().unwrap(), "--amount", &(have - 10_000).to_string(), "--asset", &y.to_string()]);
		b.ok(&["mailbox"]);
	}
	let deep: Vec<(String, u64)> = b.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live")
		.map(|c| (c["leaf_id"].as_str().unwrap().to_string(), c["hops"].as_u64().unwrap_or(0))).collect();
	println!("RN B's coins and their hops (limit {}): {:?}", limit, deep);
	let v = library(&b, "refresh_needed", json!({"idle_seconds": 0})).unwrap();
	println!("RN at the limit less one: {}", v);
	assert_eq!(v["needed"], true, "{}", v);
	let d = v["reasons"].as_array().unwrap().iter().find(|r| r["rule"] == "depth").unwrap_or_else(|| panic!("no depth rule: {}", v)).clone();
	let at: Vec<String> = deep.iter().filter(|(_, h)| *h + 1 >= limit).map(|(l, _)| l.clone()).collect();
	assert!(!at.is_empty() && d["coins"].as_array().unwrap().iter().all(|c| at.contains(&c.as_str().unwrap().to_string())), "{} {:?}", d, at);

	// 3. A coin of Y, not the bond's asset, worth more than half the bond.
	let c = Arca::new("RN C");
	create(&r, &c);
	let big = (bond_worth * 6 / 10 * 100_000_000 / rate(y)) as u64 + 1;
	println!("RN bond worth {} reference atoms; C receives {} of Y, worth {}", bond_worth, big, big as u128 * rate(y) / 100_000_000);
	pay(&a, &c, y, big);
	let v = library(&c, "refresh_needed", json!({"idle_seconds": 0})).unwrap();
	println!("RN large coin of Y: {}", v);
	assert_eq!((v["needed"].as_bool(), rules(&v)), (Some(true), vec!["exposure".to_string()]), "{}", v);
	// Below half: not needed.
	let d2 = Arca::new("RN D");
	create(&r, &d2);
	let under = (bond_worth * 4 / 10 * 100_000_000 / rate(y)) as u64;
	pay(&a, &d2, y, under);
	let v = library(&d2, "refresh_needed", json!({"idle_seconds": 0})).unwrap();
	println!("RN coin of Y under half: {}", v);
	assert_eq!(v["needed"], false, "{}", v);
	for w in [&a, &b, &c, &d2, &n] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
