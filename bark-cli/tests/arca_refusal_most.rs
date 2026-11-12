//! A payment the wallet's own coins cannot make as asked, with nothing more
//! of it on its way, is refused with what it can pay now as values, not only
//! in the refusal's words: `most`, below which every amount pays (so a
//! program can say "up to"), `all`, the exact amount that pays with no change,
//! and `live`, what it holds in live coins when the margins are what it falls
//! short by. Each figure is true: asking for it goes. Short once the margins
//! are counted, and leaving change below the operator's smallest leaf; with
//! one coin, several, and more than a transfer's sixteen inputs; for a
//! payment to a receive request, for a trade and for a payment over
//! Lightning (whose figures are invoice amounts, the operator's fee on top),
//! with the wallet's instant limit set (default mode, where a trade shapes
//! its coin first) and without.
//! With the `arca` binary against a whole Arca server on an anchored
//! proof-of-stake regtest chain.
//!
//! At the testnet operator's settings: `ARCA_TEST_ANCHOR_DEPTH=0
//! ARCA_TEST_CHECKPOINT_EXIT=0 ARCA_TEST_NO_SWEEP=1` (the last builds
//! batches without a sweep, as the testnet's operator does).
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`); the Lightning case also `LIGHTNINGD_EXEC`.

mod common;

use elements::Script;
use serde_json::{json, Value};

use bark::arca::{command, Wallet};
use server::server::LegSection;
use common::cli::Arca;
use common::lightning::{lightningd, node};
use common::running::Running;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

fn library(a: &Arca, cmd: &str, args: Value) -> Result<Value, Value> {
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run(&mut w, cmd, &args).map(|v| v["result"].clone()).map_err(|e| command::refusal(&e))
	})
}

/// The testnet operator's batches, when the run asks for its settings.
fn testnet_batches(c: &mut server::server::Config) {
	if std::env::var("ARCA_TEST_NO_SWEEP").is_ok_and(|v| v == "1") {
		c.batches.no_sweep = true;
		c.batches.holder_batches = Some(0);
		c.batches.collect_after_seconds = Some(2_419_200);
	}
}

async fn start() -> Running {
	Running::start_with(move |c, _, _| {
		c.watcher.enabled = false;
		testnet_batches(c);
	}).await
}

fn wallet(r: &Running, name: &str) -> Arca {
	wallet_with(r, name, "1")
}

/// A wallet whose coins' exit delay is `units` (a payment over Lightning
/// takes one longer than the operator's).
fn wallet_with(r: &Running, name: &str, units: &str) -> Arca {
	let w = Arca::new(name);
	w.ok(&["create", "--server", &r.url(), "--node-url", &r.node_url(), "--node-user", "arca",
		"--exit-delay-units", units, "--min-exit-delay-units", "1"]);
	w
}

fn request(to: &Arca) -> String {
	to.ok(&["receive"])["request"].as_str().unwrap().to_string()
}

/// Boards each of `values` of `asset` into `w`, its fee in X.
async fn boards(r: &mut Running, w: &Arca, asset: elements::AssetId, values: &[u64]) {
	let x = r.x;
	let s = script(&w.ok(&["address"]));
	r.pay_to(s, asset, values.iter().sum::<u64>() + 1_000_000);
	let s = script(&w.ok(&["address"]));
	r.pay_to(s, x, 5_000_000);
	r.produce().await;
	for v in values {
		w.ok(&["board", &asset.to_string(), &v.to_string(), "--fee-asset", &x.to_string()]);
		r.produce().await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
}

fn live_of(w: &Arca, asset: &str) -> (u64, usize) {
	let c: Vec<u64> = w.ok(&["coins"]).as_array().unwrap().iter().filter(|k| k["asset"] == asset && k["state"] == "live")
		.map(|k| k["value"].as_str().unwrap().parse::<u64>().unwrap()).collect();
	(c.iter().sum(), c.len())
}

fn figure(e: &Value, k: &str) -> Option<u64> {
	e["error"][k].as_str().map(|m| m.parse().unwrap())
}

/// Each figure a refusal of `amount` names goes when asked for: `most`, a run
/// of amounts below it, and `all`. -> the refusal's figures.
fn check<F: Fn(u64) -> Result<Value, Value>>(tag: &str, ask: &F, amount: u64) -> (u64, Option<u64>) {
	let e = ask(amount).expect_err(&format!("{}: {} is more than the wallet pays", tag, amount));
	println!("{}: {} refused: most {:?} all {:?} live {:?}: {}", tag, amount, figure(&e, "most"), figure(&e, "all"), figure(&e, "live"), e["error"]["message"]);
	assert_eq!(e["error"]["kind"], "refused", "{}: {}", tag, e);
	let most = figure(&e, "most").unwrap_or_else(|| panic!("{}: no most: {}", tag, e));
	let all = figure(&e, "all");
	let mut asked = vec![most, most.saturating_sub(1), most.saturating_sub(10), most.saturating_sub(999), most.saturating_sub(1_000), most / 2];
	asked.extend(all);
	for a in asked.into_iter().filter(|a| *a > 0) {
		if let Err(e) = ask(a) {
			panic!("{}: {} (most {}, all {:?}) is refused: {}", tag, a, most, all, e);
		}
	}
	println!("{}: most {} and below, and all {:?}, each go", tag, most, all);
	(most, all)
}

/// Payments to a receive request from one coin, several, and seventeen.
async fn sends(default_mode: bool) {
	let tag = format!("SF8 sends{}", if default_mode { " default" } else { "" });
	let mut r = start().await;
	let x = r.x;
	for (n, coins) in [vec![2_000_000u64], vec![900_000, 700_000, 400_000], vec![1_000_000; 17]].into_iter().enumerate() {
		let t = format!("{} {} coin(s)", tag, coins.len());
		let a = wallet(&r, &format!("{} {} A", tag, n));
		let c = wallet(&r, &format!("{} {} C", tag, n));
		boards(&mut r, &a, x, &coins).await;
		if default_mode {
			library(&a, "instant_limit", json!({"value": "1000000000000"})).unwrap();
		}
		let (held, k) = live_of(&a, &x.to_string());
		assert_eq!(k, coins.len(), "{}", t);
		let to = request(&c);
		let quote = |v: u64| library(&a, "send_quote", json!({"request": to, "amount": v.to_string(), "asset": x.to_string(), "route": "leaf"}));
		let (most, all) = check(&t, &quote, held);
		if let Some(all) = all {
			// The change refusal: an amount just under `all`, whose change is
			// below the smallest leaf, names the same truths.
			check(&format!("{} change", t), &quote, all - 1);
		}
		// And the most is paid, for real.
		let sent = a.ok(&["send", &request(&c), "--amount", &most.to_string(), "--asset", &x.to_string()]);
		println!("{}: sent the most, {}: {} inputs", t, most, sent["inputs"].as_array().map(|v| v.len()).unwrap_or(0));
		for w in [&a, &c] {
			let _ = std::fs::remove_dir_all(&w.dir);
		}
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn the_most_a_payment_can_be_is_paid() {
	sends(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_most_a_payment_can_be_is_paid_in_default_mode() {
	sends(true).await;
}

/// A trade that gives Y for X: B holds the Y (one coin, then several) and
/// reads A's offers wanting it. In default mode it shapes its coin first.
async fn trades(default_mode: bool) {
	let tag = format!("SF8 trades{}", if default_mode { " default" } else { "" });
	let mut r = start().await;
	let (x, y) = (r.x, r.y);
	for (n, coins) in [vec![1_000_000u64], vec![600_000, 300_000, 100_000]].into_iter().enumerate() {
		let t = format!("{} {} coin(s)", tag, coins.len());
		let a = wallet(&r, &format!("{} {} A", tag, n));
		let b = wallet(&r, &format!("{} {} B", tag, n));
		boards(&mut r, &a, x, &[2_000_000]).await;
		boards(&mut r, &b, y, &coins).await;
		if default_mode {
			library(&b, "instant_limit", json!({"value": "1000000000000"})).unwrap();
		}
		let (held, _) = live_of(&b, &y.to_string());
		let read = |want: u64| -> Result<Value, Value> {
			let offer = library(&a, "swap_offer", json!({"give_asset": x.to_string(), "give": "20000", "want_asset": y.to_string(), "want": want.to_string()}))
				.expect("the offer");
			let got = library(&b, "swap_read", json!({"offer": offer["offer"]}));
			let _ = library(&a, "swap_cancel", json!({"swap": offer["swap"]}));
			got
		};
		check(&t, &read, held);
		check(&format!("{} change", t), &read, held - 500);
		for w in [&a, &b] {
			let _ = std::fs::remove_dir_all(&w.dir);
		}
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn the_most_a_trade_can_give_is_given() {
	trades(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_most_a_trade_can_give_is_given_in_default_mode() {
	trades(true).await;
}

/// A payment over Lightning: B pays invoices of C, both wallets of one
/// operator whose node runs in X, its fee 0.1% and a base of 7 atoms. The
/// refusal's figures are amounts an invoice asks for, the fee on top: an
/// invoice of each is quoted, and one of the most is paid. One coin and
/// several; with the instant limit set and without.
#[tokio::test(flavor = "multi_thread")]
async fn the_most_a_lightning_payment_can_be_is_paid() {
	let Some(lnd) = lightningd("the_most_a_lightning_payment_can_be_is_paid") else { return };
	let mut r = Running::start_seqln(|c, x, _| {
		c.watcher.enabled = false;
		testnet_batches(c);
		c.fees.lightning_ppm = 1_000;
		for a in c.assets.iter_mut().filter(|a| a.asset == x.to_string()) {
			a.lightning_base = Some("7".into());
		}
		c.lightning.operator_delay_units = 1;
		c.lightning.owner_delay_units = 2;
		c.lightning.send_timeout_seconds = 8 * 3600;
		c.lightning.send_stall_margin_seconds = 3600;
		c.lightning.poll_seconds = 1;
		c.lightning.retry_seconds = 10;
		c.lightning.receive_window_seconds = 600;
	}).await;
	let x = r.x;
	let xs = x.to_string();
	let ox = tokio::task::block_in_place(|| {
		let ox = node(&r.rt, &mut r.purse, &lnd, "rmo", true, x, 2_000_000_000);
		let px = node(&r.rt, &mut r.purse, &lnd, "rmp", true, x, 1_000_000_000);
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
	for default_mode in [false, true] {
		for (n, coins) in [vec![2_000_000u64], vec![900_000, 700_000, 400_000]].into_iter().enumerate() {
			let t = format!("SF9 lightning{} {} coin(s)", if default_mode { " default" } else { "" }, coins.len());
			let b = wallet_with(&r, &format!("{} {} B", t, n), "4");
			let c = wallet_with(&r, &format!("{} {} C", t, n), "4");
			boards(&mut r, &b, x, &coins).await;
			if default_mode {
				library(&b, "instant_limit", json!({"value": "1000000000000"})).unwrap();
			}
			let (held, k) = live_of(&b, &xs);
			assert_eq!(k, coins.len(), "{}", t);
			let invoice = |v: u64| -> String {
				library(&c, "lightning_receive", json!({"asset": xs, "amount": v.to_string()})).unwrap_or_else(|e| panic!("{}: an invoice of {}: {}", t, v, e))
					["invoice"].as_str().unwrap().to_string()
			};
			let quote = |v: u64| library(&b, "lightning_pay_quote", json!({"invoice": invoice(v), "asset": xs}));
			let (most, all) = check(&t, &quote, held);
			if let Some(all) = all {
				check(&format!("{} change", t), &quote, all - 1);
			}
			// The refusal's figure is the invoice's amount: the fee is on top.
			let q = quote(most).unwrap();
			assert_eq!(q["amount"], json!(most.to_string()), "{}: {}", t, q);
			let inv = invoice(most);
			let q = library(&b, "lightning_pay_quote", json!({"invoice": inv, "asset": xs})).unwrap();
			let paying = library(&b, "lightning_pay", json!({"invoice": inv, "asset": xs, "shown": q}))
				.unwrap_or_else(|e| panic!("{}: paying the most, {}: {}", t, most, e));
			println!("{}: paid the most, {} (fee {}): {} inputs", t, most, q["fee"], paying["inputs"].as_array().map(|v| v.len()).unwrap_or(0));
			for w in [&b, &c] {
				let _ = std::fs::remove_dir_all(&w.dir);
			}
		}
	}
}
