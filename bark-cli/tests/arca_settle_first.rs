//! A spend of coins the wallet shows as its own that waits only for a round
//! answers `settle_first`, naming the coins a round must refresh, at the
//! quote as well as at the spend; `settle_first` puts them through the next
//! round, giving up nothing twice; once that round is final the same spend
//! goes ahead. Run by the `arca` binary against a whole Arca server on an
//! anchored regtest chain.
//!
//! 1. A part sale of a coin too deep to shape: the wallet bought Y at three
//!    reassignments from a round, and a trade giving part of it would shape
//!    a coin first, which the operator's depth limit leaves no room for.
//!    Idle, the wallet's `refresh_needed` names the coin (`shape`).
//! 2. A payment from change at the operator's depth limit (#689).
//! 3. A payment to an older build from coins of the record format it does
//!    not read (a receive request without `reads`, and the real older build
//!    at `ARCA_CLI_OLDER` when it is set).
//! 4. A payment past the instant limit's counted coins, from a payment still
//!    arriving; the round that settles it is taken back out of the chain by
//!    a Bitcoin anchor rollback while the wallet waits: nothing is lost, the
//!    wallet waits on, and pays once the round is final again.
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
use server::store::RoundState;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

/// A library command, in process: its result, or the refusal as the command
/// line prints it (`{"error": {"kind", "message", …}}`).
fn library(a: &Arca, cmd: &str, args: Value) -> Result<Value, Value> {
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run(&mut w, cmd, &args).map(|v| v["result"].clone()).map_err(|e| command::refusal(&e))
	})
}

/// `w` runs `args`, refused with kind `settle_first`: the coins it names.
fn settle_first_named(w: &Arca, args: &[&str]) -> Vec<String> {
	let (ok, v) = w.run(args);
	println!("{} $ arca {:?}\n  -> {}", w.name, &args[..args.len().min(3)], v);
	assert!(!ok, "{} {:?} went ahead, and should wait for a round: {}", w.name, args, v);
	assert_eq!(v["error"]["kind"], "settle_first", "{} {:?}: refused for another reason: {}", w.name, args, v);
	names(&v["error"]["coins"])
}

fn names(v: &Value) -> Vec<String> {
	v.as_array().unwrap_or_else(|| panic!("no list: {}", v)).iter().map(|c| c.as_str().unwrap().to_string()).collect()
}

fn create(r: &Running, w: &Arca) {
	w.ok(&["create", "--server", &r.url(), "--node-url", &r.node_url(), "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
}

const BOND: u64 = 50_000_000;

fn notice_units() -> u16 {
	server::bond::min_notice_seconds(server::bond::LIFETIME, RelativeTime::from_units(338).unwrap()).div_ceil(512) as u16
}

/// Posts the operator's bond: an instant limit counts nothing without it.
async fn post_bond(r: &mut Running) -> OutPoint {
	let w = keypair("settle-first W");
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

fn request(to: &Arca) -> String {
	to.ok(&["receive"])["request"].as_str().unwrap().to_string()
}

/// `from` pays `to` `amount` of `asset` out of round; the coin `to` holds.
fn pay(from: &Arca, to: &Arca, asset: AssetId, amount: u64) -> String {
	from.ok(&["send", &request(to), "--amount", &amount.to_string(), "--asset", &asset.to_string()]);
	let mb = to.ok(&["mailbox"]);
	mb["accepted"].as_array().unwrap().iter().find(|c| c["value"].as_str() == Some(&amount.to_string()) || c["value"] == amount)
		.or_else(|| mb["accepted"].as_array().unwrap().last())
		.and_then(|c| c["leaf_id"].as_str()).expect("the payee holds the coin").to_string()
}

/// Every round the operator can build now, each made final.
async fn rounds_final(r: &Running) {
	let (built, errs) = r.server.rounds.run_rounds().await.unwrap();
	assert!(errs.is_empty(), "{:?}", errs);
	r.produce().await;
	r.bury().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
}

fn rate(r: &Running, a: AssetId) -> u128 {
	let rates: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
	rates[a.to_string()].as_u64().unwrap_or_else(|| panic!("no rate for {} in {}", a, rates)) as u128
}

fn price(r: &Running, a: AssetId, rate: u64) {
	let mut set: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
	set[a.to_string()] = json!(rate);
	r.rt.client().call::<Value>("setfeeexchangerates", &[set]).unwrap();
}

fn worth(r: &Running, a: AssetId, atoms: u64) -> u128 {
	atoms as u128 * rate(r, a) / 100_000_000
}

fn watcher_off() -> impl FnOnce(&mut server::server::Config, AssetId, AssetId) {
	|c, _, _| c.watcher.enabled = false
}

/// `w`'s coins in `coin_places`, by leaf id: (value, state, place, hops).
fn coin_line(w: &Arca, leaf: &str) -> Value {
	let p = library(w, "coin_places", json!({})).unwrap();
	p["coins"].as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).cloned().unwrap_or(Value::Null)
}

/// What `w` holds of `asset` in every place but spent, in atoms.
fn held(w: &Arca, asset: AssetId) -> u64 {
	let p = library(w, "coin_places", json!({})).unwrap();
	p["coins"].as_array().unwrap().iter().filter(|c| c["asset"] == asset.to_string())
		.map(|c| c["value"].as_str().unwrap().parse::<u64>().unwrap()).sum()
}

fn live_of(w: &Arca, asset: AssetId) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|k| k["asset"] == asset.to_string() && k["state"] == "live").cloned().collect()
}

/// `settle-first` for `coins`, after a sync: its answer.
fn settle(w: &Arca, coins: &[String]) -> Value {
	let mut args = vec!["settle-first"];
	for c in coins {
		args.push("--coin");
		args.push(c);
	}
	w.ok(&args)
}

/// Settles `coins` and waits for their round to be final: nothing is given
/// up twice, and the answer is ready once through.
async fn settle_through(r: &Running, w: &Arca, coins: &[String], tag: &str) {
	let first = settle(w, coins);
	assert_eq!(names(&first["settling"]), coins.to_vec(), "{}: every coin named goes into the next round: {}", tag, first);
	assert_eq!(first["ready"], false, "{}", first);
	let again = settle(w, coins);
	assert_eq!((names(&again["settling"]).len(), names(&again["waiting"])), (0, coins.to_vec()),
		"{}: asked again, nothing is given up twice: {}", tag, again);
	rounds_final(r).await;
	w.ok(&["sync"]);
	let done = settle(w, coins);
	assert_eq!((&done["ready"], names(&done["done"])), (&json!(true), coins.to_vec()), "{}: through once the round is final: {}", tag, done);
}

// ---------------------------------------------------------------------------
// 1. A part sale of a coin too deep to shape.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_part_sale_of_a_coin_too_deep_to_shape_settles_first_then_goes() {
	let mut r = Running::start_with(watcher_off()).await;
	let (x, y) = (r.x, r.y);
	let rx = rate(&r, x) as u64;
	price(&r, y, rx);
	post_bond(&mut r).await;
	let (a, c, s) = (Arca::new("SF1 A"), Arca::new("SF1 C"), Arca::new("SF1 S"));
	create(&r, &a);
	boarded(&mut r, &c, &[(y, 2_000_000), (x, 2_000_000)]).await;
	boarded(&mut r, &s, &[(x, 3_000_000)]).await;
	library(&a, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	pay(&s, &a, x, 600_000);
	a.ok(&["require-checkpoint-exit", "on"]);
	// A buys Y with part of its X: the coin it gives is shaped first.
	let offer = a.ok(&["swap", "offer", "--give-asset", &x.to_string(), "--give", "300000", "--want-asset", &y.to_string(), "--want", "600000"]);
	let acc = c.ok(&["swap", "accept", offer["offer"].as_str().unwrap()]);
	a.ok(&["swap", "complete", acc["accept"].as_str().unwrap()]);
	a.ok(&["sync"]);
	let ys = live_of(&a, y);
	assert_eq!(ys.len(), 1, "{:?}", ys);
	let bought = ys[0]["leaf_id"].as_str().unwrap().to_string();
	let line = coin_line(&a, &bought);
	println!("SF1: the Y bought {}… holds {} at {} reassignments from a round", &bought[..8], line["value"], line["hops"]);
	assert!(line["hops"].as_u64().unwrap() + 3 > 5, "{}", line);
	let y_before = held(&a, y);

	// Idle two minutes, the wallet's upkeep names it; not while in use.
	let busy = library(&a, "refresh_needed", json!({"idle_seconds": 0})).unwrap();
	assert!(!busy["reasons"].as_array().unwrap().iter().any(|r| r["rule"] == "shape"), "{}", busy);
	let idle = library(&a, "refresh_needed", json!({"idle_seconds": 130})).unwrap();
	let shape = idle["reasons"].as_array().unwrap().iter().find(|r| r["rule"] == "shape").cloned()
		.unwrap_or_else(|| panic!("an idle wallet refreshes a coin too deep to shape: {}", idle));
	assert_eq!(names(&shape["coins"]), vec![bought.clone()], "{}", shape);

	// A sells part of the Y: refused at the quote and at the acceptance with
	// settle_first, naming the Y, and nothing moves.
	let sell = c.ok(&["swap", "offer", "--give-asset", &x.to_string(), "--give", "100000", "--want-asset", &y.to_string(), "--want", "200000"]);
	let sell_text = sell["offer"].as_str().unwrap().to_string();
	let quoted = library(&a, "swap_read", json!({"offer": sell_text})).expect_err("the quote waits for a round");
	println!("SF1: the quote: {}", quoted);
	assert_eq!(quoted["error"]["kind"], "settle_first", "{}", quoted);
	assert_eq!(names(&quoted["error"]["coins"]), vec![bought.clone()], "{}", quoted);
	assert_eq!(settle_first_named(&a, &["swap", "accept", &sell_text]), vec![bought.clone()]);
	assert_eq!(coin_line(&a, &bought)["state"], "live", "nothing moved");
	assert_eq!(held(&a, y), y_before, "nothing moved");

	// Settled first, then the same sale goes (C's first offer, never taken, is cancelled).
	settle_through(&r, &a, &[bought.clone()], "SF1").await;
	c.ok(&["swap", "cancel", sell["swap"].as_str().unwrap()]);
	let sell = c.ok(&["swap", "offer", "--give-asset", &x.to_string(), "--give", "100000", "--want-asset", &y.to_string(), "--want", "200000"]);
	let sell_text = sell["offer"].as_str().unwrap().to_string();
	library(&a, "swap_read", json!({"offer": sell_text})).expect("priced once settled");
	let acc = a.ok(&["swap", "accept", &sell_text]);
	c.ok(&["swap", "complete", acc["accept"].as_str().unwrap()]);
	a.ok(&["sync"]);
	let y_after = held(&a, y);
	println!("SF1: A held {} of Y before, {} after selling 200000 (the refresh's and the trade's fees the rest)", y_before, y_after);
	assert!(y_after < y_before - 200_000 && y_after > y_before - 300_000, "{} {}", y_before, y_after);
	assert!(live_of(&a, x).iter().any(|k| k["value"] == "100000"), "A got its X: {:?}", live_of(&a, x));
	for w in [&a, &c, &s] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// 2. A payment from change at the operator's depth limit (#689).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_payment_from_change_at_the_depth_limit_settles_first_then_goes() {
	let mut r = Running::start_with(watcher_off()).await;
	let x = r.x;
	let (a, b) = (Arca::new("SF2 A"), Arca::new("SF2 B"));
	boarded(&mut r, &a, &[(x, 3_000_000)]).await;
	create(&r, &b);
	for _ in 0..5 {
		pay(&a, &b, x, 100_000);
	}
	let change = live_of(&a, x);
	assert_eq!(change.len(), 1, "{:?}", change);
	let change = change[0]["leaf_id"].as_str().unwrap().to_string();
	println!("SF2: A's change {}… is at {} reassignments", &change[..8], coin_line(&a, &change)["hops"]);
	assert_eq!(coin_line(&a, &change)["hops"], 5);
	let before = held(&a, x);
	let req = request(&b);
	// The quote and the payment both answer settle_first, naming the change.
	assert_eq!(settle_first_named(&a, &["send-quote", &req, "--amount", "100000", "--asset", &x.to_string()]), vec![change.clone()]);
	assert_eq!(settle_first_named(&a, &["send", &req, "--amount", "100000", "--asset", &x.to_string()]), vec![change.clone()]);
	assert_eq!(held(&a, x), before, "nothing moved");
	settle_through(&r, &a, &[change.clone()], "SF2").await;
	a.ok(&["send", &req, "--amount", "100000", "--asset", &x.to_string()]);
	println!("SF2: paid once settled");
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// 3. A payment to an older build from coins of the exit format.
// ---------------------------------------------------------------------------

fn text_json(text: &str) -> Value {
	let (_, h) = text.split_once(':').unwrap();
	serde_json::from_slice(&unhex(h)).unwrap()
}

/// A receive request as an older build writes it: without `reads`.
fn as_older(text: &str) -> String {
	let (prefix, _) = text.split_once(':').unwrap();
	let mut v = text_json(text);
	v.as_object_mut().unwrap().remove("reads");
	format!("{}:{}", prefix, hex(&serde_json::to_vec(&v).unwrap()))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_payment_to_an_older_build_from_coins_of_the_exit_format_settles_first_then_goes() {
	let mut r = Running::start_with(watcher_off()).await;
	let (x, y) = (r.x, r.y);
	let (a, c, n) = (Arca::new("SF3 A"), Arca::new("SF3 C"), Arca::new("SF3 N"));
	boarded(&mut r, &a, &[(x, 2_000_000)]).await;
	boarded(&mut r, &c, &[(y, 2_000_000)]).await;
	create(&r, &n);
	// A buys Y in a trade whose checkpoints carry their owners' exit: its Y
	// is of the newer record format, and all the Y it holds.
	let offer = a.ok(&["swap", "offer", "--give-asset", &x.to_string(), "--give", "300000", "--want-asset", &y.to_string(), "--want", "400000"]);
	let acc = c.ok(&["swap", "accept", offer["offer"].as_str().unwrap()]);
	a.ok(&["swap", "complete", acc["accept"].as_str().unwrap()]);
	a.ok(&["sync"]);
	let ys = live_of(&a, y);
	assert_eq!(ys.len(), 1, "{:?}", ys);
	let bought = ys[0]["leaf_id"].as_str().unwrap().to_string();
	println!("SF3: A's Y {}… comes from a trade with the exit", &bought[..8]);
	let older = std::env::var("ARCA_CLI_OLDER").ok();
	let o = older.as_ref().map(|p| Arca::built_from("SF3 old O", std::path::Path::new(p)));
	if let Some(o) = &o {
		create(&r, o);
	} else {
		println!("SF3: ARCA_CLI_OLDER is not set: the real older build's half is not run");
	}
	// A request without `reads`, as an older build writes it, and the real
	// older build's: settle_first, naming the Y.
	let older_req = as_older(&request(&n));
	assert_eq!(settle_first_named(&a, &["send", &older_req, "--amount", "100000", "--asset", &y.to_string()]), vec![bought.clone()]);
	if let Some(o) = &o {
		let req = request(o);
		assert_eq!(settle_first_named(&a, &["send", &req, "--amount", "100000", "--asset", &y.to_string()]), vec![bought.clone()]);
	}
	settle_through(&r, &a, &[bought.clone()], "SF3").await;
	pay(&a, &n, y, 100_000);
	if let Some(o) = &o {
		let got = pay(&a, o, y, 100_000);
		println!("SF3: the older build holds {}… once A settled first", &got[..8]);
		assert!(o.ok(&["coins"]).as_array().unwrap().iter().any(|k| k["leaf_id"] == got && k["state"] == "live"), "the older build reads it");
	}
	for w in [&a, &c, &n] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
	if let Some(o) = &o {
		let _ = std::fs::remove_dir_all(&o.dir);
	}
}

// ---------------------------------------------------------------------------
// 4. A payment arriving, settled first, across an anchor rollback.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_payment_from_a_payment_arriving_settles_first_and_an_anchor_rollback_loses_nothing() {
	let mut r = Running::start_with(|cfg, _, _| { cfg.finality.anchor_depth = 0; cfg.watcher.enabled = false }).await;
	let x = r.x;
	post_bond(&mut r).await;
	let (s, a, c) = (Arca::new("SF4 S"), Arca::new("SF4 A"), Arca::new("SF4 C"));
	boarded(&mut r, &s, &[(x, 4_000_000)]).await;
	create(&r, &a);
	create(&r, &c);
	library(&a, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	let arriving = pay(&s, &a, x, 2_000_000);
	assert_eq!(coin_line(&a, &arriving)["place"], "arriving");
	let req = request(&c);
	assert_eq!(settle_first_named(&a, &["send", &req, "--amount", "500000", "--asset", &x.to_string()]), vec![arriving.clone()]);
	let first = settle(&a, &[arriving.clone()]);
	assert_eq!(names(&first["settling"]), vec![arriving.clone()], "{}", first);
	let before = held(&a, x);

	// The round's block anchored to a parent block nothing buries yet.
	tokio::task::block_in_place(|| {
		r.rt.mine_parent(1).unwrap();
		r.rt.anchor_to_parent_tip().unwrap();
	});
	let p_round = r.rt.parent.client().block_count().unwrap();
	let (built, errs) = r.server.rounds.run_rounds().await.unwrap();
	assert!(errs.is_empty(), "{:?}", errs);
	r.produce().await;
	r.synced().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	a.ok(&["sync"]);
	println!("SF4: the round is final, anchored at parent {}: {}", p_round, settle(&a, &[arriving.clone()]));

	// Bitcoin drops the round's anchor: the round leaves the chain.
	let round_txs: Vec<String> = built.iter().map(|b| b.tx.txid().to_string()).collect();
	let confs = |r: &Running| -> Vec<Value> { round_txs.iter().map(|t| r.rt.client().call::<Value>("getrawtransaction", &[json!(t), json!(true)])
		.map(|v| v["confirmations"].clone()).unwrap_or(Value::Null)).collect() };
	println!("SF4: the round's confirmations before the rollback: {:?}", confs(&r));
	let orphaned = tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_round)).unwrap();
	println!("SF4: parent block(s) {:?} orphaned; the round's confirmations now: {:?}", orphaned, confs(&r));
	a.ok(&["recheck"]);
	println!("SF4: A's places rolled back: {}", library(&a, "coin_places", json!({})).unwrap()["coins"]);
	let waiting = settle(&a, &[arriving.clone()]);
	println!("SF4: rolled back: {}", waiting);
	let mid = held(&a, x);
	println!("SF4: A holds {} of X before the round, {} rolled back", before, mid);
	assert!(mid + 10_000 >= before, "nothing is lost while the round is out of the chain: {} {}", before, mid);
	let rolled = library(&a, "coin_places", json!({})).unwrap();
	assert!(rolled["coins"].as_array().unwrap().iter().any(|c| c["state"] == "pending" && c["value"] == "2000000"),
		"the round's coin waits for the round again: {}", rolled["coins"]);
	let (ok, v) = a.run(&["send", &req, "--amount", "500000", "--asset", &x.to_string()]);
	assert!(!ok, "nothing is paid from a round out of the chain: {}", v);
	assert_eq!(v["error"]["kind"], "settle_first", "while the round is out of the chain the payment waits for it: {}", v);
	// Mined again and certified: the payment goes.
	let mut paid = ok;
	for _ in 0..12 {
		if paid {
			break;
		}
		r.produce().await;
		r.synced().await;
		a.ok(&["sync"]);
		if settle(&a, &[arriving.clone()])["ready"] == true {
			let (ok, v) = a.run(&["send", &req, "--amount", "500000", "--asset", &x.to_string()]);
			println!("SF4: after the rollback: {}", v);
			assert!(ok || v["error"]["kind"] == "settle_first", "the payment only ever waits for the round: {}", v);
			paid = ok;
		}
	}
	assert!(paid, "the payment goes once the round is final again");
	for w in [&s, &a, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
