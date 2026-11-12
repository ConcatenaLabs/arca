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
//! 5. An offboard past the instant limit's counted coins, from a payment
//!    still arriving, by amount or naming the arriving coin itself: settled
//!    first, then quoted and asked as any offboard.
//! 6. Between a settling round's broadcast and the wallet taking the coin it
//!    makes, with the operator following the chain behind the wallet (as a
//!    busy operator's round pass does): `settle-first` is not ready and says
//!    when it will be, and a payment, an offboard's quote and a trade's quote
//!    each answer `settle_first`, never a plain shortfall. At anchor depth 0
//!    (the testnet's) and 2.
//! 7. Every spend path in that gap (a payment and its quote, an offboard by
//!    amount and by named coin, a trade's quote and acceptance, an order
//!    placed, rested or filling a resting one) answers `settle_first`, with
//!    batches held for their forfeits (the testnet's) and swept; an order
//!    refused meanwhile never takes the settle back; `final_in_seconds` is
//!    an upper bound against the testnet's clock (rounds and blocks a
//!    minute apart); a settling round dropped unbroadcast waits for the
//!    next round; and a resting order's own leaf is never counted as money
//!    a payment waits for.
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

// ---------------------------------------------------------------------------
// 5. An offboard from a payment still arriving.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_offboard_from_a_payment_arriving_settles_first_then_goes() {
	let mut r = Running::start_with(|cfg, _, _| { cfg.finality.anchor_depth = 0; cfg.watcher.enabled = false }).await;
	let x = r.x;
	post_bond(&mut r).await;
	let (s, a) = (Arca::new("SF5 S"), Arca::new("SF5 A"));
	boarded(&mut r, &s, &[(x, 4_000_000)]).await;
	create(&r, &a);
	library(&a, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	let arriving = pay(&s, &a, x, 2_000_000);
	assert_eq!(coin_line(&a, &arriving)["place"], "arriving");
	let to = a.ok(&["address"]);
	let address = to["address"].as_str().unwrap().to_string();
	let xs = x.to_string();
	// At the quote and at the offboard: settle first, naming the coin.
	assert_eq!(settle_first_named(&a, &["offboard", "--asset", &xs, "--amount", "500000", "--address", &address, "--quote"]),
		vec![arriving.clone()]);
	assert_eq!(settle_first_named(&a, &["offboard", "--asset", &xs, "--amount", "500000", "--address", &address]), vec![arriving.clone()]);
	// Named, the arriving coin itself: settle first too, naming it.
	assert_eq!(settle_first_named(&a, &["offboard", "--asset", &xs, "--coins", &arriving, "--address", &address, "--quote"]),
		vec![arriving.clone()]);
	assert_eq!(settle_first_named(&a, &["offboard", "--asset", &xs, "--coins", &arriving, "--address", &address]), vec![arriving.clone()]);
	// More than the wallet holds at all is still a plain refusal.
	let (ok, v) = a.run(&["offboard", "--asset", &xs, "--amount", "5000000", "--address", &address, "--quote"]);
	println!("SF5: more than held: {}", v);
	assert!(!ok && v["error"]["kind"] != "settle_first", "{}", v);
	settle_through(&r, &a, &[arriving.clone()], "SF5").await;
	// Through: the same offboard is quoted and asked on that quote.
	let q = a.ok(&["offboard", "--asset", &xs, "--amount", "500000", "--address", &address, "--quote"]);
	println!("SF5: quoted once settled: {}", q);
	let asked = a.ok(&["offboard", "--asset", &xs, "--amount", "500000", "--address", &address, "--shown", &q.to_string()]);
	println!("SF5: asked: {}", asked);
	assert!(asked["offboard"].as_str().is_some(), "{}", asked);
	rounds_final(&r).await;
	a.ok(&["sync"]);
	let list = a.ok(&["offboards"]);
	println!("SF5: offboards: {}", list);
	assert!(list.as_array().unwrap().iter().any(|o| o["offboard"] == asked["offboard"] && o["state"] != "not_made"), "{}", list);
	for w in [&s, &a] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// 6. Between a settling round's broadcast and its finality.
// ---------------------------------------------------------------------------

/// What `w` answers, in the window between the settling round's broadcast
/// and its finality, to `settle-first` and to each spend of `asset`: a send
/// to `req`, an offboard to `address`, and the quote of `offer` (a trade).
fn window_answers(w: &Arca, coins: &[String], asset: AssetId, req: &str, address: &str, offer: &str) -> Value {
	let xs = asset.to_string();
	let s = settle(w, coins);
	let send = w.run(&["send", req, "--amount", "500000", "--asset", &xs]).1;
	let off = w.run(&["offboard", "--asset", &xs, "--amount", "500000", "--address", address, "--quote"]).1;
	let swap = library(w, "swap_read", json!({"offer": offer})).unwrap_or_else(|e| e);
	json!({"settle": s, "send": send, "offboard": off, "swap_read": swap})
}

/// The window as the testnet has it: the operator broadcasts a round, the
/// wallet signs its forfeits, and the round's block comes a while later
/// (a minute there). Until the round is final at the operator's anchor
/// depth the coin it makes cannot be spent: `settle-first` is not ready yet
/// and says when it will be, and every spend of the asset answers
/// `settle_first`, never a plain shortfall. Run at depth 0 (the testnet's)
/// and depth 2 (the harness's default and the main chain's least).
async fn window_case(depth: u32) {
	let tag = format!("SF6 d{}", depth);
	let mut r = Running::start_with(move |cfg, _, _| {
		cfg.finality.anchor_depth = depth;
		cfg.watcher.enabled = false;
		// The operator follows the chain every 15 s, so the wallet sees the
		// round final before the operator does.
		cfg.finality.poll_interval_ms = 15_000;
	}).await;
	let (x, y) = (r.x, r.y);
	let rx = rate(&r, x) as u64;
	price(&r, y, rx);
	post_bond(&mut r).await;
	let (s, a, c) = (Arca::new(&format!("{} S", tag)), Arca::new(&format!("{} A", tag)), Arca::new(&format!("{} C", tag)));
	boarded(&mut r, &s, &[(x, 4_000_000)]).await;
	boarded(&mut r, &c, &[(y, 2_000_000), (x, 1_000_000)]).await;
	create(&r, &a);
	library(&a, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	let arriving = pay(&s, &a, x, 2_000_000);
	assert_eq!(coin_line(&a, &arriving)["place"], "arriving");
	let req = request(&c);
	let address = a.ok(&["address"])["address"].as_str().unwrap().to_string();
	let offer = c.ok(&["swap", "offer", "--give-asset", &y.to_string(), "--give", "400000", "--want-asset", &x.to_string(), "--want", "500000"]);
	let offer = offer["offer"].as_str().unwrap().to_string();
	let first = settle(&a, &[arriving.clone()]);
	assert_eq!(names(&first["settling"]), vec![arriving.clone()], "{}: {}", tag, first);

	// The round goes out; the wallet signs its forfeits; no block yet.
	let (built, errs) = r.server.rounds.run_rounds().await.unwrap();
	assert!(errs.is_empty(), "{:?}", errs);
	assert!(!built.is_empty(), "{}: the settling round is built", tag);
	a.ok(&["sync"]);
	// The operator's pass: the round goes out once every forfeit is in;
	// the wallet's next sync finds it broadcast.
	r.server.rounds.pass().await.unwrap();
	a.ok(&["sync"]);
	let states: Vec<Value> = a.ok(&["coins"]).as_array().unwrap().iter().filter(|k| k["asset"] == x.to_string())
		.map(|k| json!([k["leaf_id"].as_str().unwrap()[..8].to_string(), k["state"], k["value"]])).collect();
	println!("{}: A's coins of X in the window: {:?}; the round(s) in the mempool: {:?}", tag, states,
		built.iter().map(|b| r.rt.client().call::<Value>("getmempoolentry", &[json!(b.tx.txid().to_string())]).is_ok()).collect::<Vec<_>>());
	let w1 = window_answers(&a, &[arriving.clone()], x, &req, &address, &offer);
	println!("{}: broadcast, no block: {}", tag, w1);
	// The round's block, final at the operator's depth in the wallet's view
	// (buried at depth 2), while the operator has not followed it yet: the
	// wallet signs its forfeits and is answered with no preimage, its coin
	// given up and the new one not yet in hand.
	r.produce().await;
	if depth > 0 {
		r.bury().await;
	}
	a.ok(&["sync"]);
	let states: Vec<Value> = a.ok(&["coins"]).as_array().unwrap().iter().filter(|k| k["asset"] == x.to_string())
		.map(|k| json!([k["leaf_id"].as_str().unwrap()[..8].to_string(), k["state"], k["value"]])).collect();
	println!("{}: A's coins of X once final in its view, the operator behind: {:?}", tag, states);
	let w2 = window_answers(&a, &[arriving.clone()], x, &req, &address, &offer);
	println!("{}: final in the wallet's view, not yet the operator's: {}", tag, w2);
	assert_eq!(w2["settle"]["waiting_for"], "release", "{}: final, the operator's release still to come: {}", tag, w2["settle"]);
	assert_eq!(w2["settle"]["final_in_seconds"], 120, "{}: the operator's release: a pass under way and one more (a round interval and a block): {}", tag, w2["settle"]);
	for w in [&w1, &w2] {
		assert_eq!(w["settle"]["ready"], false, "{}: not ready while the coin it makes cannot be spent: {}", tag, w["settle"]);
		assert!(w["settle"]["final_in_seconds"].as_u64().is_some(), "{}: it says when: {}", tag, w["settle"]);
		assert!(w["settle"]["waiting_for"].as_str().is_some(), "{}: it says what for: {}", tag, w["settle"]);
		for k in ["send", "offboard", "swap_read"] {
			assert_eq!(w[k]["error"]["kind"], "settle_first", "{}: {} waits for the round, never a plain shortfall: {}", tag, k, w[k]);
			// The refusal says how long itself, and never that a next round is needed.
			assert!(w[k]["error"]["final_in_seconds"].as_u64().is_some() && w[k]["error"]["waiting_for"].as_str().is_some(), "{}: {}", tag, w[k]);
			assert!(!w[k]["error"]["message"].as_str().unwrap_or("").contains("next round"), "{}: {}", tag, w[k]);
		}
	}
	// Final: ready, and every spend goes.
	r.synced().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	a.ok(&["sync"]);
	let done = settle(&a, &[arriving.clone()]);
	println!("{}: final: {}", tag, done);
	assert_eq!(done["ready"], true, "{}: {}", tag, done);
	library(&a, "swap_read", json!({"offer": offer})).unwrap_or_else(|e| panic!("{}: the trade is priced once final: {}", tag, e));
	a.ok(&["offboard", "--asset", &x.to_string(), "--amount", "500000", "--address", &address, "--quote"]);
	a.ok(&["send", &req, "--amount", "500000", "--asset", &x.to_string()]);
	for w in [&s, &a, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn a_spend_settled_first_waits_until_its_round_is_final_at_the_testnets_depth() {
	window_case(0).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_spend_settled_first_waits_until_its_round_is_final_at_depth_two() {
	window_case(2).await;
}

// ---------------------------------------------------------------------------
// 7. Every spend path in the gap, at the testnet's batch mode (no sweep,
// forfeits before broadcast) as well as the harness's; the wait against the
// clock; a settling round dropped unbroadcast; a resting order in the gap.
// ---------------------------------------------------------------------------

/// Builds every round, has `wallets` hand over forfeits, sends it out, and
/// makes it final; each wallet syncs after.
async fn rounds_with_forfeits(r: &Running, wallets: &[&Arca]) {
	let (built, errs) = r.server.rounds.run_rounds().await.unwrap();
	assert!(errs.is_empty(), "{:?}", errs);
	for w in wallets {
		w.ok(&["sync"]);
	}
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	for w in wallets {
		w.ok(&["sync"]);
	}
}

fn kind(v: &Value) -> String {
	match v.get("error") {
		Some(e) => format!("REFUSED {}: {}", e["kind"], e["message"].as_str().unwrap_or("")),
		None => "OK".into(),
	}
}

fn lib(a: &Arca, cmd: &str, args: Value) -> Value {
	library(a, cmd, args).unwrap_or_else(|e| e)
}

/// Every spend of `x` that `a` can be asked, in the gap.
fn gap_probe(a: &Arca, stage: &str, x: AssetId, y: AssetId, old: &str, req: &str, address: &str, offer: &str, expiry: u64,
	resting: &str, onchain_order: &Value, mutate: bool) -> Value
{
	let xs = x.to_string();
	let ys = y.to_string();
	let mut out = serde_json::Map::new();
	out.insert("settle_first".into(), lib(a, "settle_first", json!({"coins": [old]})));
	out.insert("settle_first_asset".into(), lib(a, "settle_first", json!({"asset": xs})));
	if mutate {
		out.insert("send".into(), a.run(&["send", req, "--amount", "500000", "--asset", &xs]).1);
	}
	out.insert("send_quote".into(), lib(a, "send_quote", json!({"request": req, "amount": "500000", "asset": xs})));
	out.insert("offboard_quote_amount".into(), lib(a, "offboard_quote", json!({"asset": xs, "amount": "500000", "address": address})));
	out.insert("offboard_quote_named_old".into(), lib(a, "offboard_quote", json!({"asset": xs, "coins": [old], "address": address})));
	if mutate {
		out.insert("offboard_named_old".into(), lib(a, "offboard", json!({"asset": xs, "coins": [old], "address": address})));
	}
	out.insert("swap_read".into(), lib(a, "swap_read", json!({"offer": offer})));
	if mutate {
		out.insert("swap_accept".into(), lib(a, "swap_accept", json!({"offer": offer})));
	}
	let ask = json!({"sell": xs, "amount": "500000", "want": ys, "rate_num": 1, "rate_den": 1, "expiry": expiry});
	out.insert("order_quote".into(), lib(a, "order_quote", ask.clone()));
	if mutate {
		out.insert("order_place".into(), lib(a, "order_place", ask.clone()));
	}
	out.insert("order_rest_quote".into(), lib(a, "order_rest_quote", ask.clone()));
	if mutate {
		out.insert("order_rest".into(), lib(a, "order_rest", ask.clone()));
	}
	out.insert("order_fill_resting_quote".into(), lib(a, "order_fill_resting_quote", json!({"order": resting, "amount": "200000"})));
	out.insert("take_quote".into(), lib(a, "take_quote", json!({"order": onchain_order, "amount": "200000"})));
	if mutate {
		out.insert("take".into(), lib(a, "take", json!({"order": onchain_order, "amount": "200000"})));
	}
	out.insert("refresh_quote_old".into(), lib(a, "quote", json!({"leaves": [old]})));
	out.insert("balance".into(), lib(a, "balance", json!({}))["arca"].clone());
	println!("{} ---", stage);
	for (k, v) in &out {
		match k.as_str() {
			"settle_first" | "settle_first_asset" | "balance" => println!("  {:26} {}", k, v),
			_ => println!("  {:26} {}", k, kind(v)),
		}
	}
	Value::Object(out)
}

async fn gap_case(depth: u32, no_sweep: bool) {
	let tag = format!("SF7 d{} {}", depth, if no_sweep { "no-sweep" } else { "sweep" });
	let mut r = Running::start_with(move |cfg, _, _| {
		cfg.finality.anchor_depth = depth;
		cfg.watcher.enabled = false;
		cfg.finality.poll_interval_ms = 15_000;
		if no_sweep {
			cfg.batches.no_sweep = true;
			cfg.batches.holder_batches = Some(0);
		}
	}).await;
	let (x, y) = (r.x, r.y);
	r.fund_server(x, 100_000_000).await;
	r.fund_server(y, 100_000_000).await;
	let rx = rate(&r, x) as u64;
	price(&r, y, rx);
	post_bond(&mut r).await;
	let (s, a, c) = (Arca::new(&format!("{} S", tag)), Arca::new(&format!("{} A", tag)), Arca::new(&format!("{} C", tag)));
	boarded(&mut r, &s, &[(x, 4_000_000)]).await;
	boarded(&mut r, &c, &[(y, 2_000_000), (x, 1_000_000)]).await;
	let dm = Arca::new(&format!("{} D", tag));
	boarded(&mut r, &dm, &[(y, 2_000_000)]).await;
	create(&r, &a);
	let mtp = r.rt.client().call::<Value>("getblockchaininfo", &[]).unwrap()["mediantime"].as_u64().unwrap();
	let expiry = mtp + 48 * 3600;
	// C: an order on the chain and one resting in the tree, each selling Y for X.
	let cask = json!({"sell": y.to_string(), "amount": "1000000", "want": x.to_string(), "rate_num": 1, "rate_den": 1, "min_lot": "100000", "expiry": expiry});
	let placed = library(&c, "order_place", cask.clone()).unwrap();
	println!("{}: C placed {}", tag, placed);
	let rested = library(&dm, "order_rest", cask.clone()).unwrap();
	println!("{}: D rested {}", tag, rested);
	rounds_with_forfeits(&r, &[&c, &dm]).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	c.ok(&["sync"]);
	dm.ok(&["sync"]);
	for _ in 0..2 {
		r.produce().await;
		r.bury().await;
		r.synced().await;
		c.ok(&["sync"]);
	}
	println!("{}: C's orders {}", tag, c.ok(&["orders"]));
	let onchain: Value = c.ok(&["orders"]).as_array().unwrap().iter().find(|o| o["state"] == "resting").map(|o| o["offer"].clone()).unwrap_or(Value::Null);
	let view = dm.ok(&["order", "resting"]);
	let resting = view["orders"].as_array().unwrap().iter().find(|o| o["rested_by"] == rested["order"]).map(|o| o["order"].as_str().unwrap_or("").to_string()).unwrap_or_default();
	println!("{}: C's on-chain order {}, resting order {}", tag, !onchain.is_null(), resting);

	library(&a, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	let arriving = pay(&s, &a, x, 2_000_000);
	assert_eq!(coin_line(&a, &arriving)["place"], "arriving");
	let req = request(&c);
	let address = a.ok(&["address"])["address"].as_str().unwrap().to_string();
	let offer = c.ok(&["swap", "offer", "--give-asset", &y.to_string(), "--give", "400000", "--want-asset", &x.to_string(), "--want", "500000"]);
	let offer = offer["offer"].as_str().unwrap().to_string();
	let t0 = std::time::Instant::now();
	let first = settle(&a, &[arriving.clone()]);
	println!("{}: settle at t=0: {}", tag, first);
	let given = gap_probe(&a, &format!("{} given, round not built", tag), x, y, &arriving, &req, &address, &offer, expiry, &resting, &onchain, false);
	let parts = |w: &Arca| -> Value { w.ok(&["participations"]) };
	println!("{}: A's participations before an order is asked: {}", tag, parts(&a));
	let op = lib(&a, "order_place", json!({"sell": x.to_string(), "amount": "500000", "want": y.to_string(), "rate_num": 1, "rate_den": 1, "expiry": expiry}));
	println!("{}: order_place while the settle waits: {}", tag, kind(&op));
	let after_op = parts(&a);
	println!("{}: A's participations after it: {}", tag, after_op);
	let sf_after = lib(&a, "settle_first", json!({"coins": [arriving.clone()]}));
	println!("{}: settle_first after the order was asked: {}", tag, sf_after);
	let withdrew = sf_after["settling"].as_array().is_some_and(|v| !v.is_empty());

	let (built, errs) = r.server.rounds.run_rounds().await.unwrap();
	assert!(errs.is_empty(), "{:?}", errs);
	assert!(!built.is_empty(), "{}: the settling round is built", tag);
	a.ok(&["sync"]);
	let held = gap_probe(&a, &format!("{} round built, forfeits in, held", tag), x, y, &arriving, &req, &address, &offer, expiry, &resting, &onchain, true);
	r.server.rounds.pass().await.unwrap();
	a.ok(&["sync"]);
	let bcast = gap_probe(&a, &format!("{} broadcast, no block", tag), x, y, &arriving, &req, &address, &offer, expiry, &resting, &onchain, true);
	r.produce().await;
	if depth > 0 {
		r.bury().await;
	}
	a.ok(&["sync"]);
	let fin = gap_probe(&a, &format!("{} final for the wallet, operator behind", tag), x, y, &arriving, &req, &address, &offer, expiry, &resting, &onchain, true);
	r.synced().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	a.ok(&["sync"]);
	let after = json!({"settle_first": lib(&a, "settle_first", json!({"coins": [arriving.clone()]})),
		"send_quote": lib(&a, "send_quote", json!({"request": req, "amount": "500000", "asset": x.to_string()}))});
	println!("{} released: {}", tag, after);
	println!("{}: elapsed {:?}", tag, t0.elapsed());
	let mut fails = vec![];
	for (stage, v) in [("given", &given), ("held", &held), ("broadcast", &bcast), ("final-not-released", &fin)] {
		for k in ["send", "send_quote", "offboard_quote_amount", "offboard_quote_named_old", "swap_read", "swap_accept", "order_quote",
			"order_place", "order_rest_quote", "order_rest", "order_fill_resting_quote"] {
			// What this stage did not ask (a spend that moves coins, asked only
			// once the round is built) is not counted.
			if v.get(k).is_none() {
				continue;
			}
			if v[k].get("error").map(|e| e["kind"] != "settle_first").unwrap_or(true) {
				fails.push(format!("{} {}: {}", stage, k, kind(&v[k])));
			}
		}
		if v["settle_first"]["ready"] != false {
			fails.push(format!("{} settle_first ready: {}", stage, v["settle_first"]));
		}
	}
	if withdrew {
		fails.push(format!("given: order_place took back the settle refresh ({}), and settle_first gave the coin up again: {}", kind(&op), sf_after));
	}
	if after["settle_first"]["ready"] != true {
		fails.push(format!("released: settle_first not ready: {}", after["settle_first"]));
	}
	for w in [&s, &a, &c, &dm] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
	assert!(fails.is_empty(), "{}: paths that do not answer settle_first in the gap:\n{}", tag, fails.join("\n"));
}

#[tokio::test(flavor = "multi_thread")]
async fn every_path_in_the_gap_answers_settle_first_with_batches_held_for_forfeits() {
	gap_case(0, true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn every_path_in_the_gap_answers_settle_first_with_batches_swept() {
	gap_case(0, false).await;
}

/// the promise against the clock. The operator runs its own round
/// loop every 60 s (the testnet's `fills.round_interval_seconds`), a block
/// comes every 60 s (its `fills.block_seconds`), anchor depth 0 with
/// certification required, batches without a sweep; the wallet syncs every
/// 5 s and asks `settle_first` every 2 s. Each answer promises ready by
/// `t + final_in_seconds`; the run prints every promise the clock broke.
async fn clock_case(sync_every: u64) {
	let tag = format!("SF7 clock sync{}s", sync_every);
	let mut r = Running::start_with(move |cfg, _, _| {
		cfg.finality.anchor_depth = 0;
		cfg.finality.poll_interval_ms = 1000;
		cfg.watcher.enabled = false;
		cfg.batches.no_sweep = true;
		cfg.batches.holder_batches = Some(0);
		cfg.fills.block_seconds = 60;
	}).await;
	let x = r.x;
	r.fund_server(x, 100_000_000).await;
	post_bond(&mut r).await;
	let (s, a) = (Arca::new(&format!("{} S", tag)), Arca::new(&format!("{} A", tag)));
	boarded(&mut r, &s, &[(x, 4_000_000)]).await;
	create(&r, &a);
	library(&a, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	let arriving = pay(&s, &a, x, 2_000_000);
	// The operator's own loop from here, at the testnet's interval.
	r.config.round_interval_seconds = 60;
	r.restart_server().await;
	r.synced().await;
	let info = a.ok(&["info"]);
	println!("{}: operator info fills {} finality {}", tag, info["fills"], info["finality"]);
	let t0 = std::time::Instant::now();
	let mut last_block = std::time::Instant::now();
	let mut last_sync = std::time::Instant::now();
	let mut samples: Vec<(f64, u64, String)> = vec![];
	let first = settle(&a, &[arriving.clone()]);
	println!("{}: t=0 settle: {}", tag, first);
	samples.push((0.0, first["final_in_seconds"].as_u64().unwrap_or(0), first["waiting_for"].as_str().unwrap_or("").to_string()));
	let ready_at = loop {
		let t = t0.elapsed().as_secs_f64();
		assert!(t < 900.0, "{}: not ready within 15 minutes", tag);
		if last_block.elapsed().as_secs() >= 60 {
			r.produce().await;
			last_block = std::time::Instant::now();
			println!("{}: t={:.0} block", tag, t);
		}
		if last_sync.elapsed().as_secs() >= sync_every {
			a.run(&["sync"]);
			last_sync = std::time::Instant::now();
		}
		let v = lib(&a, "settle_first", json!({"coins": [arriving.clone()]}));
		let t = t0.elapsed().as_secs_f64();
		if v["ready"] == true {
			break t;
		}
		let f = v["final_in_seconds"].as_u64().unwrap_or(0);
		assert!(v["usual_in_seconds"].as_u64().is_some_and(|u| u <= f), "{}: what it usually takes is within the most: {}", tag, v);
		let w = v["waiting_for"].as_str().unwrap_or("").to_string();
		if samples.last().map(|(_, pf, pw)| (*pf, pw.clone())) != Some((f, w.clone())) {
			println!("{}: t={:.0} waiting_for {} final_in_seconds {} (by t={:.0})", tag, t, w, f, t + f as f64);
		}
		samples.push((t, f, w));
		tokio::time::sleep(std::time::Duration::from_secs(2)).await;
	};
	println!("{}: ready at t={:.0}", tag, ready_at);
	let mut broken = vec![];
	for (t, f, w) in &samples {
		let late = ready_at - (t + *f as f64);
		if late > 0.0 {
			broken.push(format!("t={:.0} {} promised {} s, ready {:.0} s late", t, w, f, late));
		}
	}
	println!("{}: {} of {} promises broken", tag, broken.len(), samples.len());
	broken.dedup_by(|a, b| a.split(' ').nth(1) == b.split(' ').nth(1));
	for b in &broken {
		println!("  {}", b);
	}
	for w in [&s, &a] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
	assert!(broken.is_empty(), "{}: final_in_seconds is not an upper bound in the honest case", tag);
}

#[tokio::test(flavor = "multi_thread")]
async fn final_in_seconds_is_an_upper_bound_against_the_testnets_clock() {
	clock_case(5).await;
}

/// the settling round is held for forfeits (no sweep, as the testnet)
/// and dropped because another participant's never came. A's participation
/// runs again in a later round; meanwhile what does A's settle_first name,
/// and what do its spends answer?
#[tokio::test(flavor = "multi_thread")]
async fn a_settling_round_dropped_unbroadcast_waits_for_the_next_round() {
	let tag = "SF7 dropped";
	let mut r = Running::start_with(|cfg, _, _| {
		cfg.finality.anchor_depth = 0;
		cfg.watcher.enabled = false;
		cfg.batches.no_sweep = true;
		cfg.batches.holder_batches = Some(0);
	}).await;
	let x = r.x;
	r.fund_server(x, 100_000_000).await;
	r.fund_server(x, 100_000_000).await;
	post_bond(&mut r).await;
	let (s, a, m, c) = (Arca::new("SF7 dropped S"), Arca::new("SF7 dropped A"), Arca::new("SF7 dropped M slow"), Arca::new("SF7 dropped C"));
	boarded(&mut r, &s, &[(x, 4_000_000)]).await;
	boarded(&mut r, &m, &[(x, 2_000_000)]).await;
	create(&r, &a);
	create(&r, &c);
	library(&a, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	let arriving = pay(&s, &a, x, 2_000_000);
	let req = request(&c);
	let first = settle(&a, &[arriving.clone()]);
	println!("{}: settle: {}", tag, first);
	m.ok(&["participate"]);
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	assert_eq!(built.len(), 1);
	println!("{}: round {} with {} participations: {}", tag, built[0].tx.txid(), built[0].participations, built[0].broadcast);
	a.ok(&["sync"]);
	r.server.rounds.pass().await.unwrap();
	let probe = |stage: &str| {
		let sf = lib(&a, "settle_first", json!({"coins": [arriving.clone()]}));
		let send = a.run(&["send", &req, "--amount", "500000", "--asset", &x.to_string()]).1;
		let st: Vec<Value> = a.ok(&["coins"]).as_array().unwrap().iter().filter(|k| k["asset"] == x.to_string())
			.map(|k| json!([k["leaf_id"].as_str().unwrap()[..8].to_string(), k["state"], k["value"]])).collect();
		let ps: Vec<Value> = library(&a, "participations", json!({})).unwrap_or_default().as_array().cloned().unwrap_or_default().iter()
			.map(|p| json!([p["participation"].as_str().unwrap_or("")[..8].to_string(), p["state"]])).collect();
		println!("SF7 dropped {}: coins {:?} participations {:?}\n  settle_first {}\n  send {}", stage, st, ps, sf, kind(&send));
		(sf, send)
	};
	let held = probe("held for M's forfeits");
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 700));
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	let ps = a.ok(&["sync"]);
	println!("{}: A's sync after the drop: {}", tag, ps["participations"]);
	let dropped = probe("round dropped, A to run again");
	// The next round runs A's participation again.
	let (built2, _) = r.server.rounds.run_rounds().await.unwrap();
	println!("{}: next round: {:?}", tag, built2.iter().map(|b| (b.tx.txid(), b.participations, b.broadcast.clone())).collect::<Vec<_>>());
	a.ok(&["sync"]);
	r.server.rounds.pass().await.unwrap();
	let again = probe("the participation void, its coin held under its forfeit");
	// Rounds go by until the coin is through: once the dropped round can no
	// longer confirm, the coin is the wallet's again and is settled anew
	// (settle_first gives it up again), and a later round takes it.
	for _ in 0..8 {
		if lib(&a, "settle_first", json!({"coins": [arriving.clone()]}))["ready"] == true {
			break;
		}
		let (built, _) = r.server.rounds.run_rounds().await.unwrap();
		a.ok(&["sync"]);
		r.server.rounds.pass().await.unwrap();
		r.produce().await;
		r.synced().await;
		for b in &built {
			r.round_state(&b.tx.txid(), RoundState::Final).await;
		}
		a.ok(&["sync"]);
	}
	let done = probe("through a later round");
	for w in [&s, &a, &m, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
	let mut fails = vec![];
	for (st, (sf, send)) in [("held", &held), ("dropped", &dropped), ("again", &again)] {
		if send["error"]["kind"] != "settle_first" {
			fails.push(format!("{}: send {}", st, kind(send)));
		}
		if sf["ready"] != false {
			fails.push(format!("{}: settle_first {}", st, sf));
		}
	}
	if dropped.0["waiting_for"] != "round" {
		fails.push(format!("dropped: waiting_for {} while A's participation waits for a new round", dropped.0["waiting_for"]));
	}
	if done.0["ready"] != true {
		fails.push(format!("final: not ready: {}", done.0));
	}
	assert!(fails.is_empty(), "{}:\n{}", tag, fails.join("\n"));
}

/// a round of the wallet's own that rests an order (not a settle).
/// While its new leaves are not taken, does a payment count the order's
/// leaf as coming back to pay it?
#[tokio::test(flavor = "multi_thread")]
async fn a_resting_order_in_the_gap_is_not_money_to_spend() {
	let tag = "SF7 rest-gap";
	let mut r = Running::start_with(|cfg, _, _| {
		cfg.finality.anchor_depth = 0;
		cfg.watcher.enabled = false;
		cfg.finality.poll_interval_ms = 15_000;
		cfg.batches.no_sweep = true;
		cfg.batches.holder_batches = Some(0);
	}).await;
	let (x, y) = (r.x, r.y);
	r.fund_server(x, 100_000_000).await;
	r.fund_server(y, 100_000_000).await;
	let rx = rate(&r, x) as u64;
	price(&r, y, rx);
	let (c, d) = (Arca::new("SF7 rest-gap C"), Arca::new("SF7 rest-gap D"));
	boarded(&mut r, &c, &[(x, 1_000_000)]).await;
	create(&r, &d);
	let req = request(&d);
	let mtp = r.rt.client().call::<Value>("getblockchaininfo", &[]).unwrap()["mediantime"].as_u64().unwrap();
	let ask = json!({"sell": x.to_string(), "amount": "800000", "want": y.to_string(), "rate_num": 1, "rate_den": 1, "min_lot": "100000",
		"expiry": mtp + 720 * 3600});
	let rested = library(&c, "order_rest", ask).unwrap();
	println!("{}: rested {}", tag, rested);
	let (built, errs) = r.server.rounds.run_rounds().await.unwrap();
	assert!(errs.is_empty() && !built.is_empty(), "{:?}", errs);
	c.ok(&["sync"]);
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	c.ok(&["sync"]);
	let coins: Vec<Value> = c.ok(&["coins"]).as_array().unwrap().iter().map(|k| json!([k["leaf_id"].as_str().unwrap()[..8].to_string(), k["state"], k["value"]])).collect();
	println!("{}: C's coins in the gap: {:?}", tag, coins);
	let gap = c.run(&["send", &req, "--amount", "500000", "--asset", &x.to_string()]).1;
	println!("{}: send 500000 X in the gap: {}", tag, gap);
	let named = gap["error"]["coins"].as_array().cloned().unwrap_or_default();
	let sf = lib(&c, "settle_first", json!({"coins": named}));
	println!("{}: settle_first of what it named: {}", tag, sf);
	r.synced().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	c.ok(&["sync"]);
	let sf2 = lib(&c, "settle_first", json!({"coins": named}));
	let after = c.run(&["send", &req, "--amount", "500000", "--asset", &x.to_string()]).1;
	println!("{}: released: settle_first {}\n  send {}", tag, sf2, kind(&after));
	for w in [&c, &d] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
	assert!(gap["error"]["kind"] != "settle_first" || after.get("error").is_none(),
		"{}: in the gap the payment was told to settle first and wait, counting the order's own leaf; once released and ready it is refused: {}",
		tag, kind(&after));
}

// ---------------------------------------------------------------------------
// 8. A board the operator has not credited yet (arca #846).
// ---------------------------------------------------------------------------

/// A coin moved in from the chain (a board) whose block the wallet reads
/// final while the operator, following the chain on its own clock, has not
/// credited it yet: the wallet holds it as waiting, `settle-first` says when,
/// and a payment from it answers `settle_first`, never the operator's
/// `422 not_live`. Once the operator credits it, it is live and the payment
/// goes. At anchor depth 0 (the testnet's) and 2.
async fn board_case(depth: u32) {
	let tag = format!("SF8 board d{}", depth);
	let mut r = Running::start_with(move |cfg, _, _| {
		cfg.finality.anchor_depth = depth;
		cfg.watcher.enabled = false;
		cfg.finality.poll_interval_ms = 15_000;
	}).await;
	let x = r.x;
	let (a, c) = (Arca::new(&format!("{} A", tag)), Arca::new(&format!("{} C", tag)));
	create(&r, &a);
	create(&r, &c);
	let info = library(&a, "info", json!({})).unwrap();
	println!("{}: the operator's finality: {}", tag, info["server_info"]["finality"]);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, x, 3_000_000);
	r.produce().await;
	r.synced().await;
	let board = a.ok(&["board", &x.to_string(), "2000000", "--fee-asset", &x.to_string()]);
	println!("{}: board: {}", tag, board);
	r.produce().await;
	if depth > 0 {
		r.bury().await;
	}
	a.ok(&["sync"]);
	let server_state = |a: &Arca| a.ok(&["boards"]).as_array().unwrap().iter().map(|b| b["server"]["state"].clone()).collect::<Vec<_>>();
	let before = server_state(&a);
	let coins: Vec<Value> = a.ok(&["coins"]).as_array().unwrap().iter().filter(|k| k["asset"] == x.to_string())
		.map(|k| json!([k["kind"], k["state"], k["value"], k["note"]])).collect();
	let settled = library(&a, "settle_first", json!({"asset": x.to_string()})).unwrap();
	let req = request(&c);
	let (paid, v) = a.run(&["send", &req, "--amount", "500000", "--asset", &x.to_string()]);
	let after = server_state(&a);
	println!("{}: the operator reads the board {:?} then {:?}; the wallet's coins of X: {:?}", tag, before, after, coins);
	println!("{}: settle-first: {}", tag, settled);
	println!("{}: the payment: {}", tag, v);
	assert_eq!(after, vec![json!("pending")], "{}: the case needs the operator behind the wallet throughout", tag);
	assert!(!paid, "{}: paid from a board the operator has not credited: {}", tag, v);
	assert!(!v.to_string().contains("not_live"), "{}: refused by the operator, not waited for: {}", tag, v);
	assert_eq!(v["error"]["kind"], "settle_first", "{}: it waits for the board, as for any coin not final yet: {}", tag, v);
	assert_eq!(settled["ready"], false, "{}: {}", tag, settled);
	assert!(settled["final_in_seconds"].as_u64().is_some(), "{}: it says when: {}", tag, settled);
	assert!(coins.iter().any(|k| k[0] == "board" && k[1] == "pending"), "{}: the board waits: {:?}", tag, coins);
	// The operator credits it: live, ready, and the payment goes.
	r.synced().await;
	r.wait("the board to be credited", || server_state(&a) == vec![json!("credited")]).await;
	a.ok(&["sync"]);
	let done = library(&a, "settle_first", json!({"asset": x.to_string()})).unwrap();
	assert_eq!(done["ready"], true, "{}: {}", tag, done);
	let sent = a.ok(&["send", &req, "--amount", "500000", "--asset", &x.to_string()]);
	println!("{}: once credited: {}", tag, sent);
	for w in [&a, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn a_board_the_operator_has_not_credited_waits_at_the_testnets_depth() {
	board_case(0).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_board_the_operator_has_not_credited_waits_at_depth_two() {
	board_case(2).await;
}
