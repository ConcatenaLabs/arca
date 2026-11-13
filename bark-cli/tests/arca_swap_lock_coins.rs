//! Which coin a maker's lock and its next swap pay from (arca #892), as a
//! leaf maker's BTC desk makes them: the lock pays the operator's invoice for
//! another wallet's receive in X, settled inside the operator
//! (`lightning pay`), and the next swap pays from a coin of the maker's
//! choosing. The maker holds working coins and a reserve of one date.
//!
//! A lock that names no coin pays from a working coin, as a swap chooses
//! (`fit_order`: a coin already at risk first, then the smallest that pays
//! alone). In D58's order (furthest from its exit date, the largest of one
//! date first) it took the reserve, left the reserve's change out of round,
//! and the next swap spent that change: 4,968,782 at risk at the testnet's
//! settings. The next swap pays from a working coin too, so what the maker
//! holds at risk after it is at most a working coin, at the harness's
//! settings and at the testnet's (`ARCA_TEST_CHECKPOINT_EXIT=0`), where a
//! trade's change is received and at risk whole. A lock that names its coin
//! (`--leaf`, the library's `leaves`) pays from that coin alone, and one
//! naming a coin the wallet cannot pay from is refused before anything is
//! signed.
//!
//! A coin spent into a lock outlives it (review KR15): the `htlc-1` leaf
//! inherits the earliest expiry of its coins, and its owner's refund opens
//! only at its timeout. A working coin with eight days of life pays a lock of
//! the usual timeout, but for a lock timing out in eight days it is passed
//! over for the reserve with 28, in the quote and in the payment alike;
//! named, it is refused in words; and where the lock needs it, the answer is
//! to settle it first, never to take it.
//!
//! Needs what the other scenarios need, and `LIGHTNINGD_EXEC`.

mod common;

use std::collections::BTreeMap;

use elements::hashes::{sha256, Hash};
use elements::Script;
use serde_json::{json, Value};

use server::server::LegSection;

use bark::arca::{command, Wallet};
use common::cli::Arca;
use common::lightning::{lightningd, node};
use common::running::Running;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

fn value(c: &Value) -> u64 {
	c["value"].as_str().unwrap().parse().unwrap()
}

fn library(a: &Arca, cmd: &str, args: Value) -> Result<Value, String> {
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run(&mut w, cmd, &args).map(|v| v["result"].clone()).map_err(|e| e.to_string())
	})
}

/// Every coin the wallet has held of `asset`, by leaf id: its value.
fn values(w: &Arca, asset: &str) -> BTreeMap<String, u64> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["asset"] == asset)
		.map(|c| (c["leaf_id"].as_str().unwrap().to_string(), value(c))).collect()
}

fn live(w: &Arca, asset: &str) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["asset"] == asset && c["state"] == "live").cloned().collect()
}

/// What the wallet holds at risk out of round in `asset` (`coin_places`).
fn at_risk(w: &Arca, asset: &str) -> u64 {
	let p = library(w, "coin_places", json!({})).unwrap();
	p["coins"].as_array().unwrap().iter().filter(|c| c["asset"] == asset && c["at_risk"] == true).map(value).sum()
}

fn wallet_at(name: &str, r: &Running) -> Arca {
	let a = Arca::new(name);
	let (url, node_url) = (r.url(), r.node_url());
	a.ok(&["create", "--server", &url, "--node-url", &node_url, "--node-user", "arca", "--exit-delay-units", "4", "--min-exit-delay-units", "1"]);
	a
}

/// A hash of this run's, whose preimage nobody here reveals: the lock stays
/// held while the test reads it.
fn a_hash(tag: &str) -> String {
	let seed = format!("{}-{}-{:?}", tag, std::process::id(), std::time::SystemTime::now());
	sha256::Hash::hash(&sha256::Hash::hash(seed.as_bytes()).to_byte_array()).to_string()
}

/// `q` asks to receive `amount` of X under a fresh hash; `p` locks it, paying
/// the invoice from `leaves` when named. The lock's answer.
fn lock(r: &Running, p: &Arca, q: &Arca, amount: u64, leaves: &[&str]) -> Value {
	let x = r.x.to_string();
	let inv = q.ok(&["lightning", "receive", &x, &amount.to_string(), "--hash", &a_hash("lock")]);
	let invoice = inv["invoice"].as_str().unwrap().to_string();
	let mut args = vec!["lightning", "pay", invoice.as_str(), "--wait", "5"];
	for l in leaves {
		args.extend(["--leaf", l]);
	}
	p.ok(&args)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lock_and_the_next_swap_leave_a_maker_at_risk_by_at_most_a_working_coin() {
	let Some(lnd) = lightningd("a_lock_and_the_next_swap_leave_a_maker_at_risk_by_at_most_a_working_coin") else { return };
	let mut r = Running::start_seqln(|c, _, _| {
		c.fees.lightning_ppm = 1_000;
		c.lightning.operator_delay_units = 1;
		c.lightning.owner_delay_units = 2;
		c.lightning.send_timeout_seconds = 8 * 3600;
		c.lightning.send_stall_margin_seconds = 3600;
		c.lightning.poll_seconds = 1;
		c.lightning.retry_seconds = 10;
		c.lightning.receive_window_seconds = 600;
	}).await;
	let (x, y) = (r.x, r.y);
	let (xs, ys) = (x.to_string(), y.to_string());
	let ox = tokio::task::block_in_place(|| {
		let ox = node(&r.rt, &mut r.purse, &lnd, "slo", true, x, 2_000_000_000);
		let px = node(&r.rt, &mut r.purse, &lnd, "slp", true, x, 1_000_000_000);
		ox.open_channel(&r.rt, &px, x, 1_000_000_000, 300_000_000);
		drop(px);
		ox
	});
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let mut config = r.config.clone();
	for a in config.assets.iter_mut() {
		if a.asset == xs {
			a.lightning = Some(LegSection::at(ox.rpc_path()));
		}
	}
	r.server.reload(&config).await.unwrap();
	r.config = config;
	let g = r.server.gateway.clone();
	r.wait("X's leg up", || g.leg(&x, true).is_ok()).await;

	// The maker P: a reserve of 5,000,000 and two working coins of 100,000,
	// boarded in one block (one date). The taker B holds Y; Q receives.
	let p = wallet_at("SLP", &r);
	let b = wallet_at("SLB", &r);
	let q = wallet_at("SLQ", &r);
	for v in [5_000_000u64, 100_000, 100_000] {
		let s = script(&p.ok(&["address"]));
		r.pay_to(s, x, v + 1_000_000);
	}
	let s = script(&b.ok(&["address"]));
	r.pay_to(s, y, 2_000_000);
	let s = script(&b.ok(&["address"]));
	r.pay_to(s, x, 1_000_000);
	r.produce().await;
	for v in [5_000_000u64, 100_000, 100_000] {
		p.ok(&["board", &xs, &v.to_string()]);
	}
	b.ok(&["board", &ys, "1000000", "--fee-asset", &xs]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards credited", || {
		[&p, &b].iter().all(|w| w.ok(&["boards"]).as_array().unwrap().iter().all(|v| v["server"]["state"] == "credited"))
	}).await;
	p.ok(&["sync"]);
	b.ok(&["sync"]);
	let exit = q.ok(&["info"])["server_info"]["checkpoint_exit"] == true;
	println!("SL checkpoint_exit {}; the maker's X: {:?}", exit, live(&p, &xs).iter().map(value).collect::<Vec<_>>());

	// 1. A lock naming no coin pays from a working coin, the reserve untouched.
	let before = values(&p, &xs);
	let l1 = lock(&r, &p, &q, 10_000, &[]);
	let spent: Vec<u64> = l1["inputs"].as_array().unwrap().iter().map(|i| before[i.as_str().unwrap()]).collect();
	println!("SL lock 1 (no coin named) paid from {:?}, change {}; X at risk {}", spent, l1["change"], at_risk(&p, &xs));
	assert_eq!(spent, vec![100_000], "a working coin, not the reserve of 5,000,000");
	assert!(live(&p, &xs).iter().any(|c| value(c) == 5_000_000 && c["hops"] == 0), "the reserve stays in round");
	assert_eq!(at_risk(&p, &xs), 0, "a lock's change is the wallet's own, at risk to nobody");

	// 2. The next swap pays from a working coin or the lock's change, never the reserve.
	let before = values(&p, &xs);
	let offer = library(&p, "swap_offer", json!({"give_asset": xs, "give": "20000", "want_asset": ys, "want": "20000"})).unwrap();
	let ins: Vec<u64> = offer["details"]["inputs"].as_array().unwrap().iter().map(|i| before[i["leaf_id"].as_str().unwrap()]).collect();
	let read = library(&b, "swap_read", json!({"offer": offer["offer"]})).unwrap();
	let acc = library(&b, "swap_accept", json!({"offer": offer["offer"], "shown": read})).unwrap();
	library(&p, "swap_complete", json!({"accept": acc["accept"]})).unwrap();
	p.ok(&["mailbox"]);
	let risk = at_risk(&p, &xs);
	println!("SL the swap of 20,000 paid from {:?}; X at risk after it {} (Y {})", ins, risk, at_risk(&p, &ys));
	assert!(ins.len() == 1 && ins[0] <= 100_000, "a working coin or the lock's change, not the reserve: {:?}", ins);
	assert!(risk <= 100_000, "at most a working coin at risk: {}", risk);

	// 3. A lock naming its coin pays from that coin alone.
	// It names the reserve, which the wallet would never choose by itself.
	let reserve = live(&p, &xs).into_iter().find(|c| value(c) == 5_000_000).expect("the reserve");
	let leaf = reserve["leaf_id"].as_str().unwrap().to_string();
	let l3 = lock(&r, &p, &q, 10_000, &[&leaf]);
	println!("SL lock 3 (named {}) paid from {}", leaf, l3["inputs"]);
	assert_eq!(l3["inputs"], json!([leaf]));

	// 4. A named coin the wallet cannot pay from: refused, nothing signed.
	let paid_before = p.ok(&["lightning", "payments"]);
	let inv = q.ok(&["lightning", "receive", &xs, "10000", "--hash", &a_hash("refused")]);
	let ghost = "00".repeat(32);
	let e = p.refused(&["lightning", "pay", inv["invoice"].as_str().unwrap(), "--leaf", &ghost, "--wait", "5"], "must each be a live coin");
	println!("SL lock naming no coin of the wallet's: {}", e);
	let e = p.refused(&["lightning", "pay", inv["invoice"].as_str().unwrap(), "--leaf", &leaf, "--wait", "5"], "must each be a live coin");
	println!("SL lock naming the coin lock 3 spent: {}", e);
	assert_eq!(p.ok(&["lightning", "payments"]), paid_before, "nothing recorded");
}

/// Review KR15. An operator whose window for a payment's timeout runs to
/// eight days (`send_timeout_seconds` of four); a maker whose working coins
/// have eight days of life left and whose reserve has 28.
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_spent_into_a_lock_outlives_the_lock() {
	let Some(lnd) = lightningd("a_coin_spent_into_a_lock_outlives_the_lock") else { return };
	let mut r = Running::start_seqln(|c, _, _| {
		c.fees.lightning_ppm = 1_000;
		c.lightning.operator_delay_units = 1;
		c.lightning.owner_delay_units = 2;
		c.lightning.send_timeout_seconds = 4 * 86_400;
		c.lightning.send_stall_margin_seconds = 3600;
		c.lightning.poll_seconds = 1;
		c.lightning.retry_seconds = 10;
		c.lightning.receive_window_seconds = 600;
	}).await;
	let x = r.x;
	let xs = x.to_string();
	// The maker's working coins, boarded first; then 20 days pass.
	let p = wallet_at("SOP", &r);
	for v in [100_000u64, 100_000] {
		let s = script(&p.ok(&["address"]));
		r.pay_to(s, x, v + 1_000_000);
	}
	r.produce().await;
	for v in [100_000u64, 100_000] {
		p.ok(&["board", &xs, &v.to_string()]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the working coins credited", || p.ok(&["boards"]).as_array().unwrap().iter().all(|v| v["server"]["state"] == "credited")).await;
	p.ok(&["sync"]);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 20 * 86_400));
	r.produce().await;
	r.bury().await;
	r.synced().await;
	// The operator's Lightning leg in X, and the reserve, boarded now.
	let ox = tokio::task::block_in_place(|| {
		let ox = node(&r.rt, &mut r.purse, &lnd, "soo", true, x, 2_000_000_000);
		let px = node(&r.rt, &mut r.purse, &lnd, "sop", true, x, 1_000_000_000);
		ox.open_channel(&r.rt, &px, x, 1_000_000_000, 300_000_000);
		drop(px);
		ox
	});
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let mut config = r.config.clone();
	for a in config.assets.iter_mut() {
		if a.asset == xs {
			a.lightning = Some(LegSection::at(ox.rpc_path()));
		}
	}
	r.server.reload(&config).await.unwrap();
	r.config = config;
	let g = r.server.gateway.clone();
	r.wait("X's leg up", || g.leg(&x, true).is_ok()).await;
	let s = script(&p.ok(&["address"]));
	r.pay_to(s, x, 6_000_000);
	r.produce().await;
	p.ok(&["board", &xs, "5000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the reserve credited", || p.ok(&["boards"]).as_array().unwrap().iter().all(|v| v["server"]["state"] == "credited")).await;
	p.ok(&["sync"]);
	let q = wallet_at("SOQ", &r);
	let now = common::node::median_time(&r.rt);
	let coins = live(&p, &xs);
	let lives: Vec<(u64, i64)> = coins.iter().map(|c| (value(c), c["expiry"].as_u64().unwrap() as i64 - now as i64)).collect();
	println!("SO the maker's X at median time {} (value, seconds to its expiry): {:?}", now, lives);
	let leaf_of = |v: u64| -> Vec<String> { coins.iter().filter(|c| value(c) == v).map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect() };
	let (working, reserve) = (leaf_of(100_000), leaf_of(5_000_000).remove(0));
	let expiry_of = |leaf: &str| coins.iter().find(|c| c["leaf_id"] == leaf).unwrap()["expiry"].as_u64().unwrap();
	assert_eq!(working.len(), 2);
	// The lock's leaf waits the wallet's exit delay (4 units of 512 s, above
	// the operator's 2 for an owner), and a day goes to the unroll.
	let outlive = |timeout: u64| timeout + 4 * 512 + 86_400;
	let long = now as u64 + 8 * 86_400 - 3_600;
	assert!(expiry_of(&working[0]) >= now as u64 + 7 * 86_400, "a swap would try a working coin alone: seven days of life");
	assert!(expiry_of(&working[0]) < outlive(long) && expiry_of(&reserve) >= outlive(long), "the long lock outlives a working coin only");
	assert!(expiry_of(&working[0]) >= outlive(now as u64 + 4 * 86_400 + 3_600), "a working coin outlives a lock of the usual timeout");
	let invoice = |amount: u64, tag: &str| q.ok(&["lightning", "receive", &xs, &amount.to_string(), "--hash", &a_hash(tag)])["invoice"]
		.as_str().unwrap().to_string();

	// 1. The payment: a lock of 10,000 until the long timeout takes the
	// reserve, which outlives it, not a working coin, which the swap order
	// would try first.
	let paid = p.ok(&["lightning", "pay", &invoice(10_000, "long"), "--timeout", &long.to_string(), "--wait", "5"]);
	println!("SO a lock of 10,000 until {}: paid from {}", long, paid["inputs"]);
	assert_eq!(paid["inputs"], json!([reserve]), "the reserve, which outlives the lock, not a working coin");
	let change = live(&p, &xs).into_iter().find(|c| value(c) > 1_000_000).expect("the reserve's change")["leaf_id"].as_str().unwrap().to_string();

	// 2. The quote counts the same figure from the same timeout: the
	// reserve's change for the long lock, a working coin for the usual one.
	let inv = invoice(10_000, "quote");
	let quoted = library(&p, "lightning_pay_quote", json!({"invoice": inv, "timeout": long})).unwrap();
	println!("SO quote, a timeout of {}: gives {} coins_outlive {}", quoted["timeout"], quoted["gives"], quoted["coins_outlive"]);
	assert_eq!(quoted["gives"], json!([change]), "the working coins do not outlive the lock: {}", quoted);
	assert_eq!((quoted["timeout"].as_u64(), quoted["coins_outlive"].as_u64()), (Some(long), Some(outlive(long))), "{}", quoted);
	let usual = library(&p, "lightning_pay_quote", json!({"invoice": inv})).unwrap();
	println!("SO quote, the usual timeout {}: gives {} coins_outlive {}", usual["timeout"], usual["gives"], usual["coins_outlive"]);
	assert!(working.contains(&usual["gives"][0].as_str().unwrap().to_string()) && usual["gives"].as_array().unwrap().len() == 1, "{}", usual);
	assert_eq!(usual["coins_outlive"].as_u64(), Some(outlive(usual["timeout"].as_u64().unwrap())), "{}", usual);

	// 3. Where the lock needs a coin it would outlive, that coin is not taken:
	// the answer is to settle it first. The same payment of the usual timeout
	// takes the reserve's change and a working coin together.
	let big = invoice(5_050_000, "together");
	let together = library(&p, "lightning_pay_quote", json!({"invoice": big})).unwrap();
	println!("SO quote of 5,050,000, the usual timeout: gives {}", together["gives"]);
	let gives: Vec<String> = together["gives"].as_array().unwrap().iter().map(|l| l.as_str().unwrap().to_string()).collect();
	assert!(gives.len() >= 2 && gives.contains(&change) && gives.iter().any(|l| working.contains(l)), "{}", together);
	let (ok, refusal) = p.run(&["lightning", "pay", &big, "--timeout", &long.to_string(), "--wait", "5"]);
	println!("SO a lock of 5,050,000 until {}: {}", long, refusal);
	assert!(!ok && refusal["error"]["kind"] == "settle_first", "{}", refusal);
	let mut named: Vec<String> = refusal["error"]["coins"].as_array().unwrap().iter().map(|l| l.as_str().unwrap().to_string()).collect();
	named.sort();
	let mut want = working.clone();
	want.sort();
	assert_eq!(named, want, "the two working coins, to settle first");
	assert!(refusal["error"]["message"].as_str().unwrap().contains("too near their exit date to be locked under this payment's hash"), "{}", refusal);
	assert_eq!(live(&p, &xs).len(), 3, "nothing was signed or held");

	// 4. A named coin the lock would outlive is refused in words; named for a
	// lock it outlives, it pays.
	let inv = invoice(10_000, "named");
	let e = p.refused(&["lightning", "pay", &inv, "--timeout", &long.to_string(), "--leaf", &working[0], "--wait", "5"], "must outlive median time");
	println!("SO a named coin the lock would outlive: {}", e);
	assert!(e.contains(&working[0]) && e.contains(&outlive(long).to_string()) && e.contains("nothing was signed"), "{}", e);
	let paid = p.ok(&["lightning", "pay", &inv, "--leaf", &working[0], "--wait", "5"]);
	println!("SO the same coin named for a lock of the usual timeout: paid from {}", paid["inputs"]);
	assert_eq!(paid["inputs"], json!([working[0]]));
}
