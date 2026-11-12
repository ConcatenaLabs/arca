//! A person trading several times in a row, as the default mode's Trade tab
//! does: each trade takes a maker's offer, and while the wallet sets an
//! instant limit it first pays itself a coin of exactly what it gives (the
//! shaping self-payment), out of round. Run by the `arca` binary against a
//! whole Arca server on an anchored regtest chain, at the testnet operator's
//! settings: depth limit 5, finality at anchor depth 0 with certification
//! required, batches held for their forfeits (no sweep), no checkpoint exit.
//!
//! `ARCA_TEST_HARNESS_DEFAULTS=1` runs the same cases at the harness's
//! defaults instead.
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

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

/// A library command, in process: its result, or the refusal as the command
/// line prints it.
fn library(a: &Arca, cmd: &str, args: Value) -> Result<Value, Value> {
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run(&mut w, cmd, &args).map(|v| v["result"].clone()).map_err(|e| command::refusal(&e))
	})
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
	let w = keypair("streak W");
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

/// `w` created and holding one boarded coin of each value in `coins`.
async fn boarded(r: &mut Running, w: &Arca, coins: &[(AssetId, u64)]) {
	create(r, w);
	let x = r.x;
	for (a, v) in coins {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, *a, v + 3_000_000);
	}
	// A fee coin for each board: a board's change is not spendable until mined.
	for _ in 0..coins.len().max(1) {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, x, 3_000_000);
	}
	r.produce().await;
	for (a, v) in coins {
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

/// `w`'s coins of `asset` in `coin_places` that are its own and live:
/// (leaf id, value, hops), deepest first.
fn coins_of(w: &Arca, asset: AssetId) -> Vec<(String, u64, u64)> {
	let p = library(w, "coin_places", json!({})).unwrap();
	let mut out: Vec<(String, u64, u64)> = p["coins"].as_array().unwrap().iter()
		.filter(|c| c["asset"] == asset.to_string() && c["state"] == "live")
		.map(|c| (c["leaf_id"].as_str().unwrap().to_string(), c["value"].as_str().unwrap().parse().unwrap(), c["hops"].as_u64().unwrap_or(0)))
		.collect();
	out.sort_by_key(|c| std::cmp::Reverse(c.2));
	out
}

fn depths(w: &Arca, asset: AssetId) -> String {
	coins_of(w, asset).iter().map(|(_, v, h)| format!("{}@{}", v, h)).collect::<Vec<_>>().join(" ")
}

/// One trade as the Trade tab makes it: maker `m` offers `get` of Y for
/// `give` of X; `a` reads the offer (the quote), accepts it, and `m`
/// completes it. The quote's or the acceptance's refusal, if any.
fn trade(m: &Arca, a: &Arca, x: AssetId, y: AssetId, give: u64, get: u64) -> Result<(), Value> {
	let offer = m.ok(&["swap", "offer", "--give-asset", &y.to_string(), "--give", &get.to_string(), "--want-asset", &x.to_string(),
		"--want", &give.to_string()]);
	let text = offer["offer"].as_str().unwrap().to_string();
	let cancel = |why: Value| {
		m.run(&["swap", "cancel", offer["swap"].as_str().unwrap()]);
		Err(why)
	};
	if let Err(e) = library(a, "swap_read", json!({"offer": text})) {
		return cancel(e);
	}
	let (ok, acc) = a.run(&["swap", "accept", &text]);
	if !ok {
		return cancel(acc);
	}
	m.ok(&["swap", "complete", acc["accept"].as_str().unwrap()]);
	a.ok(&["sync"]);
	Ok(())
}

/// The testnet operator's settings, as its `info` publishes them: anchor
/// depth 0 with certification required, batches held for their forfeits,
/// no checkpoint exit, a block every 60 s. The depth limit (5) is the
/// server's own.
///
/// With `ARCA_TEST_HARNESS_DEFAULTS` set, the harness's own defaults instead
/// (anchor depth 2, batches swept, the checkpoint exit offered), the round
/// loop and the block clock as ever.
fn testnet(cfg: &mut server::server::Config) {
	if std::env::var_os("ARCA_TEST_HARNESS_DEFAULTS").is_some() {
		cfg.watcher.enabled = false;
		cfg.fills.block_seconds = 60;
		return;
	}
	cfg.finality.anchor_depth = 0;
	cfg.finality.certification = "required".into();
	cfg.finality.poll_interval_ms = 1000;
	cfg.watcher.enabled = false;
	cfg.batches.no_sweep = true;
	cfg.batches.holder_batches = Some(0);
	cfg.fills.block_seconds = 60;
	cfg.checkpoint_exit = false;
	cfg.fee_multiple = 4;
	cfg.fees.max_margin_multiple = Some(25);
}

/// A taker `a` with an instant limit, holding `coins` of X, and a maker `m`
/// holding Y in many coins (so its own depth never limits a trade).
async fn streak_setup(tag: &str, coins: &[u64]) -> (Running, Arca, Arca) {
	let mut r = Running::start_with(|cfg, _, _| testnet(cfg)).await;
	let (x, y) = (r.x, r.y);
	let rx = rate(&r, x) as u64;
	price(&r, y, rx);
	post_bond(&mut r).await;
	let (a, m) = (Arca::new(&format!("{} A", tag)), Arca::new(&format!("{} M", tag)));
	let xs: Vec<(AssetId, u64)> = coins.iter().map(|v| (x, *v)).collect();
	boarded(&mut r, &a, &xs).await;
	boarded(&mut r, &m, &[(y, 4_000_000), (y, 4_000_000), (y, 4_000_000), (y, 4_000_000), (y, 4_000_000), (y, 4_000_000)]).await;
	library(&a, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	let info = a.ok(&["info"]);
	let si = &info["server_info"];
	println!("{}: operator depth_limit {} finality {} checkpoint_exit {} batches {} margin multiple {}", tag, si["depth_limit"], si["finality"],
		si["checkpoint_exit"], si["batches"], si["fees"]["margin_multiple"]);
	(r, a, m)
}

/// Trades back to back, no round between them, until the first refusal:
/// how many went, the depth of each coin after each, and the refusal.
async fn streak_until_refused(tag: &str, coins: &[u64], give: u64) -> (usize, Value) {
	let (r, a, m) = streak_setup(tag, coins).await;
	let (x, y) = (r.x, r.y);
	println!("{}: before: X {}", tag, depths(&a, x));
	let mut n = 0;
	let refusal = loop {
		match trade(&m, &a, x, y, give, give) {
			Ok(()) => {
				n += 1;
				println!("{}: trade {} went; X now {}", tag, n, depths(&a, x));
			},
			Err(e) => break e,
		}
		assert!(n < 40, "{}: forty trades went", tag);
	};
	println!("{}: trade {} refused: {}", tag, n + 1, refusal);
	for w in [&a, &m] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
	(n, refusal)
}

// ---------------------------------------------------------------------------
// Measurements
// ---------------------------------------------------------------------------

/// How many trades in a row a fresh wallet makes before the first refusal,
/// from one coin and from four, and how many transfers each trade adds.
#[tokio::test(flavor = "multi_thread")]
async fn measure_trades_in_a_row_before_the_first_refusal() {
	let (one, e1) = streak_until_refused("SF7 one", &[2_000_000], 100_000).await;
	let (four, e4) = streak_until_refused("SF7 four", &[2_000_000, 2_000_000, 2_000_000, 2_000_000], 100_000).await;
	println!("SF7 measured: one coin {} trades, then {}; four coins {} trades, then {}", one, e1["error"]["kind"], four, e4["error"]["kind"]);
}

// ---------------------------------------------------------------------------
// The page's upkeep, and a streak against the testnet's clock
// ---------------------------------------------------------------------------

fn names(v: &Value) -> Vec<String> {
	v.as_array().map(|a| a.iter().filter_map(|c| c.as_str().map(String::from)).collect()).unwrap_or_default()
}

/// What the web wallet's upkeep does on its timer and after every receipt
/// (leaves.js `refreshReceived`): asks `refresh_needed` with the person
/// active; the coins of rule `shape` go through the next round by
/// `settle_first` with the rule's `spread` and `max_fee_ppm`; what other
/// rules name by `refresh_received`. The coins it settled.
fn page_upkeep(a: &Arca) -> Vec<String> {
	page_upkeep_idle(a, 0)
}

/// [`page_upkeep`] with the person away `idle` seconds.
fn page_upkeep_idle(a: &Arca, idle: u64) -> Vec<String> {
	let Ok(v) = library(a, "refresh_needed", json!({"idle_seconds": idle})) else { return vec![] };
	let reasons = v["reasons"].as_array().cloned().unwrap_or_default();
	let mut settled = vec![];
	for r in reasons.iter().filter(|r| r["rule"] == "shape") {
		let coins = names(&r["coins"]);
		let mut args = json!({"coins": coins, "spread": r["spread"] == true});
		if let Some(f) = r["max_fee_ppm"].as_u64() {
			args["max_fee_ppm"] = json!(f);
		}
		if let Ok(s) = library(a, "settle_first", args) {
			settled.extend(names(&s["settling"]));
		}
	}
	// A library that says which received coins go now is followed exactly.
	if let Some(give) = v["give_up"].as_array() {
		if !give.is_empty() {
			let _ = library(a, "refresh_received", json!({"leaves": give}));
		}
		return settled;
	}
	let others: Vec<&Value> = reasons.iter().filter(|r| r["rule"] != "shape").collect();
	if !others.is_empty() {
		let only: Option<Vec<String>> = if others.iter().all(|r| r["rule"] == "arriving") {
			Some(others.iter().flat_map(|r| names(&r["coins"])).collect())
		} else {
			None
		};
		let _ = library(a, "refresh_received", match only { Some(l) => json!({"leaves": l}), None => json!({}) });
	}
	settled
}

/// What `w` holds of `asset` in every place but spent, in atoms.
fn held(w: &Arca, asset: AssetId) -> u64 {
	let p = library(w, "coin_places", json!({})).unwrap();
	p["coins"].as_array().unwrap().iter().filter(|c| c["asset"] == asset.to_string())
		.map(|c| c["value"].as_str().unwrap().parse::<u64>().unwrap()).sum()
}

/// The testnet's clock: a block every 60 s, the operator's round loop every
/// 60 s (set when the streak starts), the wallet's sync every 5 s.
struct Clock {
	t0: std::time::Instant,
	block: std::time::Instant,
	sync: std::time::Instant,
}

impl Clock {
	fn new() -> Clock {
		let n = std::time::Instant::now();
		Clock { t0: n, block: n, sync: n }
	}
	fn t(&self) -> f64 {
		self.t0.elapsed().as_secs_f64()
	}
	async fn tick(&mut self, r: &Running, a: &Arca) {
		if self.block.elapsed().as_secs() >= 60 {
			r.produce().await;
			self.block = std::time::Instant::now();
		}
		if self.sync.elapsed().as_secs() >= 5 {
			a.run(&["sync"]);
			self.sync = std::time::Instant::now();
		}
	}
	/// Ticks until `t`, the page's upkeep every 30 s meanwhile.
	async fn until(&mut self, r: &Running, a: &Arca, t: f64, upkept: &mut f64) {
		while self.t() < t {
			self.tick(r, a).await;
			if self.t() - *upkept >= 30.0 {
				page_upkeep(a);
				*upkept = self.t();
			}
			tokio::time::sleep(std::time::Duration::from_millis(500)).await;
		}
	}
}

/// One trade of the streak: when it was asked, how long it waited for a
/// round (0 when it went at once), the wait the refusal said
/// (`final_in_seconds`, `usual_in_seconds`), and each refusal met.
#[derive(Debug)]
struct Traded {
	asked: f64,
	waited: f64,
	said: Option<(u64, u64)>,
	refusals: Vec<String>,
	/// How many of the wallet's coins of X the trade spent (the shaping
	/// self-payment's inputs): more than one costs a margin per extra coin.
	spent: usize,
	/// Seconds from asked to done (a trade that waited included).
	took: f64,
}

/// The leaf ids of `w`'s coins of `asset` in any place (spent ones are in none).
fn placed(w: &Arca, asset: AssetId) -> Vec<String> {
	library(w, "coin_places", json!({})).unwrap()["coins"].as_array().unwrap().iter().filter(|c| c["asset"] == asset.to_string())
		.map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect()
}

/// How many of `before` (live coins of X before a trade) the trade spent.
fn spent_since(w: &Arca, asset: AssetId, before: &[String]) -> usize {
	let now = placed(w, asset);
	before.iter().filter(|l| !now.contains(l)).count()
}

/// `n` trades of `give` X for Y, one every `every` seconds, as the Trade
/// tab makes them: a trade answered `settle_first` waits as the page does
/// (it settles the coins named, with `spread`, and asks again once
/// `ready`), and goes by itself; any other refusal is recorded and ends
/// the streak. After every trade, the page's upkeep. What A paid in all
/// beyond what it gave (margins and refresh fees), from its X before and
/// after with every round through.
async fn streak(r: &mut Running, a: &Arca, m: &Arca, tag: &str, n: usize, every: f64, give: u64) -> (Vec<Traded>, i128) {
	let (x, y) = (r.x, r.y);
	r.config.round_interval_seconds = 60;
	r.restart_server().await;
	r.synced().await;
	let before = held(a, x);
	let mut clock = Clock::new();
	let mut upkept = 0.0;
	let mut out = vec![];
	for k in 0..n {
		clock.until(r, a, k as f64 * every, &mut upkept).await;
		let asked = clock.t();
		let mut said = None;
		let mut live_before: Vec<String> = coins_of(a, x).into_iter().map(|c| c.0).collect();
		let mut refusals = vec![];
		loop {
			match trade(m, a, x, y, give, give) {
				Ok(()) => break,
				Err(e) if e["error"]["kind"] == "settle_first" => {
					let coins = names(&e["error"]["coins"]);
					if said.is_none() {
						said = Some((e["error"]["final_in_seconds"].as_u64().unwrap_or(0), e["error"]["usual_in_seconds"].as_u64().unwrap_or(0)));
					}
					refusals.push(format!("settle_first {:?}", e["error"]["message"].as_str().unwrap_or("")));
					// The page waits for the round and goes by itself.
					loop {
						let v = library(a, "settle_first", json!({"coins": coins, "spread": true})).unwrap_or_else(|e| e);
						if v["ready"] == true {
							break;
						}
						assert!(clock.t() - asked < 900.0, "{}: trade {} waited 15 minutes: {}", tag, k + 1, v);
						clock.tick(r, a).await;
						tokio::time::sleep(std::time::Duration::from_secs(2)).await;
					}
					live_before = coins_of(a, x).into_iter().map(|c| c.0).collect();
				},
				Err(e) => {
					refusals.push(e.to_string());
					println!("{}: trade {} REFUSED: {}", tag, k + 1, e);
					out.push(Traded { asked, waited: clock.t() - asked, said, refusals, spent: 0, took: clock.t() - asked });
					return (out, 0);
				},
			}
		}
		let took = clock.t() - asked;
		let waited = if refusals.is_empty() { 0.0 } else { took };
		let spent = spent_since(a, x, &live_before);
		let settled = page_upkeep(a);
		upkept = clock.t();
		println!("{}: trade {} at t={:.0} took {:.1} s, spent {} coin(s), {} (X {}){}", tag, k + 1, asked, took, spent,
			if waited > 0.0 { format!("WAITED {:.0} s, said {:?}", waited, said) } else { "went at once".into() }, depths(a, x),
			if settled.is_empty() { String::new() } else { format!("; upkeep settles {} coin(s)", settled.len()) });
		out.push(Traded { asked, waited, said, refusals, spent, took });
	}
	// Every round through, so what A holds is all in coins it can count.
	let mut rounds = 0;
	loop {
		let given = library(a, "coin_places", json!({})).unwrap()["coins"].as_array().unwrap().iter()
			.filter(|c| c["asset"] == x.to_string() && c["state"] != "live").count();
		if given == 0 || rounds > 60 {
			break;
		}
		clock.until(r, a, clock.t() + 10.0, &mut upkept).await;
		rounds += 1;
	}
	let after = held(a, x);
	let paid = before as i128 - after as i128 - (n as u64 * give) as i128;
	println!("{}: X before {} after {}; gave {} in {} trades; paid {} beyond it", tag, before, after, n as u64 * give, n, paid);
	(out, paid)
}

fn waits(t: &[Traded]) -> Vec<(usize, f64)> {
	t.iter().enumerate().filter(|(_, x)| x.waited > 0.0).map(|(k, x)| (k + 1, x.waited)).collect()
}

/// Twenty trades, fifteen seconds apart, from a wallet holding four coins
/// of X, at the testnet's settings and clock: none is refused, none waits
/// for a round; the upkeep refreshes each coin whose room is used up while
/// the others trade. What A paid beyond what it gave is printed, against
/// the same streak on the base (which waits).
#[tokio::test(flavor = "multi_thread")]
async fn twenty_trades_fifteen_seconds_apart_from_several_coins_never_wait() {
	let tag = "SF7 several";
	let (mut r, a, m) = streak_setup(tag, &[1_500_000, 1_500_000, 1_500_000, 1_500_000]).await;
	let (t, paid) = streak(&mut r, &a, &m, tag, 20, 15.0, 100_000).await;
	let w = waits(&t);
	let multi = t.iter().filter(|x| x.spent > 1).count();
	println!("{}: {} trades, waits {:?}, paid {}, trades paid from more than one coin {}", tag, t.len(), w, paid, multi);
	for x in [&a, &m] {
		let _ = std::fs::remove_dir_all(&x.dir);
	}
	assert_eq!(t.len(), 20, "every trade went: {:?}", t);
	assert_eq!(multi, 0, "every trade paid from one coin: {:?}", t);
	assert!(t.iter().all(|x| x.refusals.iter().all(|r| r.starts_with("settle_first"))), "no trade refused: {:?}", t);
	assert!(w.is_empty(), "{}: no trade waited for a round: {:?}", tag, w);
}

/// The same from a wallet holding one coin of X: when its room is used up
/// the trade waits, the wait said (`final_in_seconds`), and goes by itself;
/// the round that settles it cuts the coin into a few, so the trades after
/// it wait no more.
#[tokio::test(flavor = "multi_thread")]
async fn twenty_trades_from_one_coin_wait_once_with_the_wait_said() {
	let tag = "SF7 one coin";
	let (mut r, a, m) = streak_setup(tag, &[6_000_000]).await;
	let (t, paid) = streak(&mut r, &a, &m, tag, 20, 15.0, 100_000).await;
	let w = waits(&t);
	let multi = t.iter().filter(|x| x.spent > 1).count();
	println!("{}: {} trades, waits {:?}, paid {}, trades paid from more than one coin {}", tag, t.len(), w, paid, multi);
	// A trade of more than half of what is left pays from the reserve coin alone.
	let (x, y) = (r.x, r.y);
	let total: u64 = coins_of(&a, x).iter().map(|c| c.1).sum();
	let big = total * 45 / 100;
	let before: Vec<String> = coins_of(&a, x).into_iter().map(|c| c.0).collect();
	println!("{}: X {} (live {}); a trade of {}", tag, depths(&a, x), total, big);
	trade(&m, &a, x, y, big, big).expect("a large trade");
	let spent = spent_since(&a, x, &before);
	println!("{}: the large trade spent {} coin(s); X {}", tag, spent, depths(&a, x));
	assert_eq!(spent, 1, "the reserve coin pays it alone");
	for x in [&a, &m] {
		let _ = std::fs::remove_dir_all(&x.dir);
	}
	assert_eq!(t.len(), 20, "every trade went, waiting or not: {:?}", t);
	for x in t.iter().filter(|x| x.waited > 0.0) {
		let (most, usual) = x.said.expect("a wait is said");
		assert!(most > 0 && usual > 0 && usual <= most, "the wait said: {:?}", x);
	}
	assert!(w.len() <= 1, "{}: one coin waits once, then trades on from the coins its round made: {:?}", tag, w);
}

// ---------------------------------------------------------------------------
// A refresh racing a trade; an anchor rollback during a background refresh;
// an operator that charges for a refresh
// ---------------------------------------------------------------------------

/// Builds every round the operator can now; with batches held for their
/// forfeits (the testnet's), `wallets` hand theirs over at a sync and the
/// operator's pass sends the round out. The rounds built.
async fn rounds_held(r: &Running, wallets: &[&Arca]) -> Vec<server::rounds::Built> {
	let (built, errs) = r.server.rounds.run_rounds().await.unwrap();
	assert!(errs.is_empty(), "{:?}", errs);
	for w in wallets {
		w.ok(&["sync"]);
	}
	r.server.rounds.pass().await.unwrap();
	built
}

/// Trades until the deepest coin of X has no room left, and the upkeep
/// gives it up: the coin it settles, and the trades made.
fn trade_until_upkeep_settles(a: &Arca, m: &Arca, x: AssetId, y: AssetId, give: u64) -> String {
	for _ in 0..6 {
		trade(m, a, x, y, give, give).expect("a trade from coins with room");
		let xs: Vec<String> = coins_of(a, x).into_iter().map(|c| c.0).collect();
		let s = page_upkeep(a);
		if let Some(c) = s.iter().find(|c| xs.contains(c)) {
			return c.clone();
		}
	}
	panic!("the upkeep settled nothing in six trades: X {}", depths(a, x));
}

/// A refresh racing a trade that wants the same coin. (1) The upkeep has
/// given up the coin first, and a trade needs it: the trade waits for its
/// round, by the words (`settle_first` naming it), never a plain refusal,
/// and goes once the round is final. (2) The trade has the coin first (its
/// acceptance holds it): the upkeep's settle gives nothing up, and the
/// trade completes.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_racing_a_trade_for_the_same_coin_never_fails_it() {
	let tag = "SF7 race";
	let (r, a, m) = streak_setup(tag, &[1_500_000, 450_000]).await;
	let (x, y) = (r.x, r.y);
	// (1) Three trades use up the smaller coin's room (of two at depth 0, the
	// smaller first); the upkeep gives it up, the large coin stays live.
	let settling = trade_until_upkeep_settles(&a, &m, x, y, 100_000);
	println!("{}: upkeep gave up {}… ; X {}", tag, &settling[..8], depths(&a, x));
	assert!(coins_of(&a, x).iter().all(|c| c.0 != settling), "the coin is in a round");
	// A trade bigger than the live coin needs the coin in the round too.
	let offer = m.ok(&["swap", "offer", "--give-asset", &y.to_string(), "--give", "1550000", "--want-asset", &x.to_string(), "--want", "1550000"]);
	let text = offer["offer"].as_str().unwrap().to_string();
	let quoted = library(&a, "swap_read", json!({"offer": text})).expect_err("the quote waits for the round");
	println!("{}: the quote: {}", tag, quoted);
	assert_eq!(quoted["error"]["kind"], "settle_first", "waits by the words, never a plain refusal: {}", quoted);
	assert!(names(&quoted["error"]["coins"]).contains(&settling), "{}", quoted);
	let (ok, acc) = a.run(&["swap", "accept", &text]);
	assert!(!ok && acc["error"]["kind"] == "settle_first", "the trade waits: {}", acc);
	// Its round final, the same trade goes.
	let built = rounds_held(&r, &[&a]).await;
	r.produce().await;
	r.bury().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	for _ in 0..20 {
		a.ok(&["sync"]);
		if library(&a, "settle_first", json!({"coins": [settling.clone()], "spread": true})).unwrap()["ready"] == true {
			break;
		}
		r.produce().await;
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;
	}
	let acc = a.ok(&["swap", "accept", &text]);
	m.ok(&["swap", "complete", acc["accept"].as_str().unwrap()]);
	a.ok(&["sync"]);
	println!("{}: (1) the trade went once the round was final; X {}", tag, depths(&a, x));

	// (2) The trade takes a coin first; the upkeep then asks to settle it.
	let offer = m.ok(&["swap", "offer", "--give-asset", &y.to_string(), "--give", "30000", "--want-asset", &x.to_string(), "--want", "30000"]);
	let text = offer["offer"].as_str().unwrap().to_string();
	let acc = a.ok(&["swap", "accept", &text]);
	let held_by_trade: Vec<String> = library(&a, "coin_places", json!({})).unwrap()["coins"].as_array().unwrap().iter()
		.filter(|c| c["state"] == "offered").map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
	assert!(!held_by_trade.is_empty());
	let s = library(&a, "settle_first", json!({"coins": held_by_trade, "spread": true})).unwrap();
	println!("{}: (2) the upkeep's settle of the trade's coin: {}", tag, s);
	assert!(names(&s["settling"]).is_empty(), "nothing the trade holds is given up: {}", s);
	m.ok(&["swap", "complete", acc["accept"].as_str().unwrap()]);
	a.ok(&["sync"]);
	let swaps = library(&a, "swaps", json!({})).unwrap();
	println!("{}: swaps {}", tag, swaps.as_array().unwrap().iter().map(|s| s["state"].as_str().unwrap_or("?")).collect::<Vec<_>>().join(","));
	assert!(swaps.as_array().unwrap().iter().all(|s| s["state"] == "done"), "every trade completed: {}", swaps);
	for w in [&a, &m] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A background refresh whose round's anchor Bitcoin drops: the wallet
/// holds what it held, waits for the round again, and counts the coins'
/// room from what is on the chain: once the round is mined again and
/// final, the coins it made are at depth 0 and trade at once.
#[tokio::test(flavor = "multi_thread")]
async fn an_anchor_rollback_during_a_background_refresh_loses_nothing() {
	let tag = "SF7 rollback";
	let (r, a, m) = streak_setup(tag, &[1_000_000, 1_000_000]).await;
	let (x, y) = (r.x, r.y);
	let settling = trade_until_upkeep_settles(&a, &m, x, y, 100_000);
	let before = held(&a, x);
	println!("{}: upkeep gave up {}…; X {} (held {})", tag, &settling[..8], depths(&a, x), before);
	// The round's block anchored to a parent block nothing buries yet.
	tokio::task::block_in_place(|| {
		r.rt.mine_parent(1).unwrap();
		r.rt.anchor_to_parent_tip().unwrap();
	});
	let p_round = r.rt.parent.client().block_count().unwrap();
	let built = rounds_held(&r, &[&a]).await;
	r.produce().await;
	r.synced().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	a.ok(&["sync"]);
	println!("{}: the round is final, anchored at parent {}: {}", tag, p_round, library(&a, "settle_first", json!({"coins": [settling.clone()]})).unwrap());
	let orphaned = tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_round)).unwrap();
	println!("{}: parent block(s) {:?} orphaned", tag, orphaned);
	a.ok(&["recheck"]);
	let mid = held(&a, x);
	println!("{}: rolled back: X {} (held {}); places {}", tag, depths(&a, x), mid, library(&a, "coin_places", json!({})).unwrap()["coins"]);
	assert!(mid >= before, "nothing is lost while the round is out of the chain: {} {}", before, mid);
	// The trades go on from the coin with room meanwhile.
	trade(&m, &a, x, y, 100_000, 100_000).expect("the other coin trades while the round is out of the chain");
	// Mined again and final: what it made is at depth 0, counted from the chain.
	let mut ready = false;
	for _ in 0..20 {
		r.produce().await;
		r.synced().await;
		a.ok(&["sync"]);
		if library(&a, "settle_first", json!({"coins": [settling.clone()]})).unwrap()["ready"] == true {
			ready = true;
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;
	}
	assert!(ready, "the round is final again");
	let after = coins_of(&a, x);
	println!("{}: after: X {} (held {})", tag, depths(&a, x), held(&a, x));
	assert!(after.iter().any(|c| c.2 == 0), "the round's coins are at depth 0: {:?}", after);
	for w in [&a, &m] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// An operator that charges for a refresh: the upkeep refreshes nothing on
/// its own while the person uses the wallet (the rule names no coin), and
/// the trade that needs the coin waits for it, its fee in that trade's own
/// answer. Left alone two minutes, the rule names it as before.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_that_charges_for_a_refresh_gets_no_background_refresh() {
	let tag = "SF7 charged";
	let (mut r, a, m) = streak_setup(tag, &[1_000_000, 1_000_000]).await;
	let (x, y) = (r.x, r.y);
	r.config.fees.refresh_ppm = 500;
	r.restart_server().await;
	r.synced().await;
	for _ in 0..3 {
		trade(&m, &a, x, y, 100_000, 100_000).expect("a trade");
	}
	println!("{}: X {}", tag, depths(&a, x));
	assert!(coins_of(&a, x).iter().any(|c| c.2 + 3 > 5), "a coin's room is used up");
	let active = library(&a, "refresh_needed", json!({"idle_seconds": 0})).unwrap();
	println!("{}: active: {}", tag, active);
	assert!(!active["reasons"].as_array().unwrap().iter().any(|r| r["rule"] == "shape"), "nothing refreshed on its own for a fee: {}", active);
	assert!(page_upkeep(&a).is_empty());
	let idle = library(&a, "refresh_needed", json!({"idle_seconds": 130})).unwrap();
	assert!(idle["reasons"].as_array().unwrap().iter().any(|r| r["rule"] == "shape" && r.get("max_fee_ppm").is_none()), "{}", idle);
	for w in [&a, &m] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// The upkeep never puts every coin of an asset into a round at once (web
/// wallet #728): a wallet holding two coins of X it received, left alone,
/// refreshes one and keeps the other back, and a trade asked right then is
/// priced at once from the coin kept back.
#[tokio::test(flavor = "multi_thread")]
async fn the_upkeep_keeps_a_coin_of_each_asset_out_of_its_rounds() {
	let tag = "SF7 kept back";
	let (r, a, m) = streak_setup(tag, &[]).await;
	let (x, y) = (r.x, r.y);
	let s = Arca::new(&format!("{} S", tag));
	let mut r = r;
	boarded(&mut r, &s, &[(x, 2_000_000)]).await;
	for v in [300_000u64, 250_000] {
		let req = a.ok(&["receive"])["request"].as_str().unwrap().to_string();
		s.ok(&["send", &req, "--amount", &v.to_string(), "--asset", &x.to_string()]);
		a.ok(&["mailbox"]);
	}
	println!("{}: A holds X {}", tag, depths(&a, x));
	assert_eq!(coins_of(&a, x).len(), 2);
	let v = library(&a, "refresh_needed", json!({"idle_seconds": 130})).unwrap();
	println!("{}: idle: {}", tag, v);
	assert_eq!(v["kept_back"].as_array().map(|k| k.len()), Some(1), "one coin of X kept back: {}", v);
	page_upkeep_idle(&a, 130);
	let live = coins_of(&a, x);
	println!("{}: after the upkeep: X live {}", tag, depths(&a, x));
	assert_eq!(live.len(), 1, "one coin of X stays live: {:?}", live);
	// A trade asked now is priced at once from it.
	let offer = m.ok(&["swap", "offer", "--give-asset", &y.to_string(), "--give", "100000", "--want-asset", &x.to_string(), "--want", "100000"]);
	let quoted = library(&a, "swap_read", json!({"offer": offer["offer"]}));
	println!("{}: the quote: {:?}", tag, quoted);
	assert!(quoted.is_ok(), "priced without waiting for a round: {:?}", quoted);
	for w in [&a, &m, &s] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
