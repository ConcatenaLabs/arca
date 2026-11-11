//! `watch_bond` keeps what each coin yields: a coin's record never changes,
//! so the evidence its lineage carries (the lines its operator co-signed,
//! its bases and roots) is read once and kept, and a later watch reads no
//! coin's base transactions again. A wallet of a long history is so never
//! held for half a minute by the watch ahead of a person's command (web
//! wallet #667: 571 headers and 796 transactions, 32 s on the testnet).
//!
//! B receives six coins out of round under a posted bond; its first watch
//! reads their lineages from the node, its second and third read only
//! the tip and the mempool (the command's own node count), and all find
//! the same evidence.
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
		outpoint: Some(format!("{}:{}", op.txid, op.vout)), notice: None, instant_budget_fraction: None, instant_limit_value: None });
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

fn mtp(r: &Running) -> u64 {
	let v: Value = r.rt.client().call("getblockchaininfo", &[]).unwrap();
	v["mediantime"].as_u64().unwrap()
}

fn rules(v: &Value) -> Vec<String> {
	v["reasons"].as_array().unwrap().iter().map(|r| r["rule"].as_str().unwrap().to_string()).collect()
}


fn run_cost(a: &Arca, cmd: &str, args: Value) -> (Value, Value) {
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		let v = command::run(&mut w, cmd, &args).expect("the command");
		(v["result"].clone(), v["cost"]["command"].clone())
	})
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_watch_reads_no_coins_base_again() {
	let mut r = Running::start().await;
	let (x, y) = (r.x, r.y);
	let a = Arca::new("BW A");
	boarded(&mut r, &a, &[(x, 8_000_000), (y, 8_000_000)]).await;
	let mut set: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
	set[y.to_string()] = json!(100_000_000u64);
	r.rt.client().call::<Value>("setfeeexchangerates", &[set]).unwrap();
	post_bond(&mut r).await;
	a.ok(&["sync"]);
	let b = Arca::new("BW B");
	create(&r, &b);
	for k in 0..6u64 {
		pay(&a, &b, if k % 2 == 0 { x } else { y }, 50_000 + k);
	}
	let (w1, c1) = run_cost(&b, "watch_bond", json!({}));
	let (w2, c2) = run_cost(&b, "watch_bond", json!({}));
	println!("BW first watch: evidence {} reads {}", w1["evidence"], c1);
	println!("BW second watch: evidence {} reads {}", w2["evidence"], c2);
	let n = |c: &Value| c["node"].as_u64().unwrap_or(0);
	// The first watch reads the coins' lineages from the node (their bases' blocks and headers);
	// the second reads only the chain's tip and mempool, none of a coin's again.
	assert!(n(&c2) < n(&c1), "the second watch reads less of the node: {} then {}", c1, c2);
	let (w3, c3) = run_cost(&b, "watch_bond", json!({}));
	assert_eq!(n(&c3), n(&c2), "and stays there: {}", c3);
	assert_eq!(w3["evidence"], w2["evidence"]);
	assert_eq!(w1["evidence"]["lines"], w2["evidence"]["lines"], "the same evidence both times");
	assert_eq!(w2["evidence"]["unread"], 0);
	assert_eq!(w1["evidence"]["salts"], w2["evidence"]["salts"]);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
