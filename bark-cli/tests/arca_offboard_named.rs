//! An offboard of named coins (`offboard --coins`) where the coin a trade
//! brought is not yet the wallet's to move at once, against a whole Arca
//! server on an anchored proof-of-stake regtest chain. Probes of a review
//! (RV40), kept as tests:
//!
//! 1. The coin arrives past the wallet's instant limit. The move's quote by
//!    the coin's value and date counts the round the coin must go through
//!    first; named, the move answers `settle_first` naming it; once settled
//!    as told, the same name moves the coin that round made, paying out at
//!    least what the value quote said, for no more fee.
//! 2. A coin whose value after the fee is below the operator's smallest
//!    output: both quotes refuse, naming the smallest amount that goes, and
//!    nothing is asked of the operator.
//! 3. A coin spent on a payment out of the tree that made change: its name
//!    never moves the change (only a refresh of that coin alone is
//!    followed).
//! 4. A coin received while an earlier received coin is arriving arrives
//!    too: the value quote counts its settle.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::{AssetId, Script};
use serde_json::{json, Value};

use bark::arca::{command, Wallet};
use common::cli::Arca;
use common::running::Running;
use server::server::AssetSection;
use server::store::RoundState;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

fn create(r: &Running, w: &Arca) {
	w.ok(&["create", "--server", &r.url(), "--node-url", &r.node_url(), "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
}

fn library(a: &Arca, cmd: &str, args: Value) -> Result<Value, Value> {
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run(&mut w, cmd, &args).map(|v| v["result"].clone()).map_err(|e| command::refusal(&e))
	})
}

fn names(v: &Value) -> Vec<String> {
	v.as_array().unwrap_or_else(|| panic!("no list: {}", v)).iter().map(|c| c.as_str().unwrap().to_string()).collect()
}

fn quote_ok(a: &Arca, args: &[&str]) -> (bool, Value) {
	let (ok, v) = a.run(args);
	println!("{} {:?} -> ok={} {}", a.name, &args[..args.len().min(5)], ok, v);
	(ok, v)
}

async fn leaves_only(r: &mut Running, w: &Arca, asset: AssetId, paid: u64) {
	r.pay_to(script(&w.ok(&["address"])), asset, paid);
	r.produce().await;
	let mut amount = paid - paid / 100;
	for _ in 0..4 {
		let q = w.ok(&["board", &asset.to_string(), &amount.to_string(), "--quote"]);
		let fee: u64 = q["fee"]["amount"].as_str().unwrap().parse().unwrap();
		if amount + fee == paid {
			break;
		}
		amount = paid - fee;
	}
	w.ok(&["board", &asset.to_string(), &amount.to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
}

fn live_of(w: &Arca, asset: AssetId) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == json!(asset.to_string())).cloned().collect()
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
	rates[a.to_string()].as_u64().unwrap() as u128
}

fn price(r: &Running, a: AssetId, rate: u64) {
	let mut set: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
	set[a.to_string()] = json!(rate);
	r.rt.client().call::<Value>("setfeeexchangerates", &[set]).unwrap();
}

fn worth(r: &Running, a: AssetId, atoms: u64) -> u128 {
	atoms as u128 * rate(r, a) / 100_000_000
}

const BOND: u64 = 50_000_000;

fn notice_units() -> u16 {
	server::bond::min_notice_seconds(server::bond::LIFETIME, arca_covenant::RelativeTime::from_units(338).unwrap()).div_ceil(512) as u16
}

async fn post_bond(r: &mut Running) {
	use arca_covenant::bond::BondPolicy;
	let w = common::running::keypair("rv40 bond W");
	let s_key = common::running::keypair("operator");
	let chain = arca_covenant::Chain::new(r.rt.client().genesis_hash().unwrap());
	let policy = BondPolicy::new(chain, s_key.x_only_public_key().0, w.x_only_public_key().0,
		arca_covenant::RelativeTime::from_units(notice_units()).unwrap()).unwrap();
	let x = r.x;
	let tx = r.pay_to(policy.script_pubkey(), x, BOND);
	r.produce().await;
	r.bury().await;
	let vout = tx.output.iter().position(|o| o.script_pubkey == policy.script_pubkey()).unwrap() as u32;
	r.config.bond = Some(server::bond::BondSection { withdraw_key: w.x_only_public_key().0.to_string(), notice_units: notice_units(),
		outpoint: Some(format!("{}:{}", tx.txid(), vout)), notice: None, instant_budget_fraction: None, instant_limit_value: None });
	r.restart_server().await;
	r.synced().await;
}

fn fee_of(q: &Value) -> u64 {
	q["fee"]["amount"].as_str().unwrap().parse().unwrap()
}

// ---------------------------------------------------------------------------
// P1. The coin a trade brings arrives past the instant limit (the web
// wallet's default mode sets one). Named, the move answers settle_first
// naming it; once settled as told, the same named move must go.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 1. A named coin arriving past the instant limit.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_named_arriving_coin_is_priced_with_its_settle_and_moves_by_its_name_once_settled() {
	let mut r = Running::start_with(|c, x, _| {
		c.finality.anchor_depth = 0;
		c.watcher.enabled = false;
		c.assets[0] = AssetSection { refresh_ppm: Some(3_000), refresh_base: Some("200".into()), offboard_ppm: Some(3_333),
			offboard_base: Some("7".into()), ..AssetSection::new(x, 1_000) };
	}).await;
	let x = r.x;
	post_bond(&mut r).await;
	let (s, a) = (Arca::new("NAMED S"), Arca::new("NAMED A"));
	create(&r, &s);
	leaves_only(&mut r, &s, x, 4_100_000).await;
	create(&r, &a);
	library(&a, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	let address = a.ok(&["address"])["address"].as_str().unwrap().to_string();
	let xs = x.to_string();
	let arriving = pay(&s, &a, x, 2_000_000);
	let line = a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == arriving.as_str()).cloned().unwrap();
	// The ticket's price of the move, from the coin's value and date: the
	// round it must go through first counted.
	let ticket = a.ok(&["offboard", "--asset", &xs, "--value", "2000000", "--expiry", &line["expiry"].as_u64().unwrap().to_string(),
		"--address", &address, "--quote"]);
	println!("1: the value quote: {}", ticket);
	assert_ne!(ticket["fee"]["settle"], "0", "the settle is counted: {}", ticket);
	// Named: settle first, naming it.
	let (ok, v) = a.run(&["offboard", "--asset", &xs, "--coins", &arriving, "--address", &address]);
	println!("1: the named move: ok={} {}", ok, v);
	assert!(!ok && v["error"]["kind"] == "settle_first", "{}", v);
	assert_eq!(names(&v["error"]["coins"]), vec![arriving.clone()]);
	a.ok(&["settle-first", "--coin", &arriving]);
	rounds_final(&r).await;
	a.ok(&["sync"]);
	let done = a.ok(&["settle-first", "--coin", &arriving]);
	assert_eq!(done["ready"], true, "{}", done);
	let after = live_of(&a, x);
	assert_eq!(after.len(), 1, "{:?}", after);
	let new = after[0]["leaf_id"].as_str().unwrap().to_string();
	assert_ne!(new, arriving);
	// The same name, as the refusal said: the coin the settle made.
	let q = a.ok(&["offboard", "--asset", &xs, "--coins", &arriving, "--address", &address, "--quote"]);
	println!("1: the named move asked again: {}", q);
	assert_eq!(q["gives"], json!([new]), "the coin that replaced it");
	let (amount, quoted): (u64, u64) = (q["amount"].as_str().unwrap().parse().unwrap(), ticket["amount"].as_str().unwrap().parse().unwrap());
	assert!(amount >= quoted && fee_of(&q) + 2_000_000 - after[0]["value"].as_str().unwrap().parse::<u64>().unwrap() <= fee_of(&ticket),
		"the value quote held: it said {} for a fee of {}; the move pays {} for {} after a settle of {}", quoted, fee_of(&ticket), amount,
		fee_of(&q), 2_000_000 - after[0]["value"].as_str().unwrap().parse::<u64>().unwrap());
	let asked = a.ok(&["offboard", "--asset", &xs, "--coins", &arriving, "--address", &address, "--shown", &q.to_string()]);
	assert_eq!(asked["gives"], json!([new]));
	// Asked again by the old name while under way: the same move.
	let again = a.ok(&["offboard", "--asset", &xs, "--coins", &arriving, "--address", &address]);
	assert_eq!((&again["offboard"], &again["already"]), (&asked["offboard"], &json!(true)), "{}", again);
	for w in [&s, &a] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// 2. A named coin below the smallest output after its fee.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_move_below_the_smallest_output_is_refused_at_the_quote() {
	let mut r = Running::start_with(|c, x, _| {
		c.assets[0] = AssetSection { refresh_ppm: Some(3_000), refresh_base: Some("200".into()), offboard_ppm: Some(3_333),
			offboard_base: Some("7".into()), ..AssetSection::new(x, 1_000) };
	}).await;
	let x = r.x;
	let (s, a) = (Arca::new("NAMED P2 S"), Arca::new("NAMED P2 A"));
	create(&r, &s);
	leaves_only(&mut r, &s, x, 600_000).await;
	create(&r, &a);
	let address = a.ok(&["address"])["address"].as_str().unwrap().to_string();
	let xs = x.to_string();
	let small = pay(&s, &a, x, 1_200);
	let line = a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == small.as_str()).cloned().unwrap();
	let expiry = line["expiry"].as_u64().unwrap().to_string();
	for args in [vec!["--value", "1200", "--expiry", expiry.as_str(), "--quote"], vec!["--coins", small.as_str(), "--quote"], vec!["--coins", small.as_str()]] {
		let mut cmd = vec!["offboard", "--asset", xs.as_str(), "--address", address.as_str(), "--max-fee-ppm", "900000"];
		cmd.extend(args.iter().copied());
		let (ok, v) = a.run(&cmd);
		println!("2: {:?}: ok={} {}", args, ok, v["error"]["message"]);
		assert!(!ok && v["error"]["message"].as_str().unwrap().contains("below the operator's smallest output of 1000"), "{}", v);
	}
	assert!(a.ok(&["offboards"]).as_array().unwrap().is_empty(), "nothing asked of the operator");
	assert_eq!(live_of(&a, x).len(), 1);
	for w in [&s, &a] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// 3. A coin spent on a payment that made change.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_coin_spent_on_a_payment_is_never_named_by_its_change() {
	let mut r = Running::start_with(|c, x, _| {
		c.finality.anchor_depth = 0;
		c.assets[0] = AssetSection { offboard_ppm: Some(3_333), offboard_base: Some("7".into()), ..AssetSection::new(x, 1_000) };
	}).await;
	let x = r.x;
	let a = Arca::new("NAMED N1 A");
	create(&r, &a);
	leaves_only(&mut r, &a, x, 600_000).await;
	let b = Arca::new("NAMED N1 B");
	create(&r, &b);
	let address = b.ok(&["address"])["address"].as_str().unwrap().to_string();
	let xs = x.to_string();
	let named = live_of(&a, x)[0]["leaf_id"].as_str().unwrap().to_string();
	// The person pays 100,000 X out to someone else's address from that coin.
	let paid = a.ok(&["offboard", "--asset", &xs, "--amount", "100000", "--address", &address]);
	assert_eq!(paid["gives"], json!([named]), "{}", paid);
	rounds_final(&r).await;
	a.ok(&["sync"]);
	let left = live_of(&a, x);
	println!("N1: live after the payment: {:?}", left.iter().map(|c| (c["leaf_id"].clone(), c["value"].clone())).collect::<Vec<_>>());
	// The named move of the coin that was spent on that payment.
	let mine = a.ok(&["address"])["address"].as_str().unwrap().to_string();
	let (ok, v) = quote_ok(&a, &["offboard", "--asset", &xs, "--coins", &named, "--address", &mine, "--quote"]);
	assert!(!ok, "the coin spent on a payment is named, and the payment's change ({}) is quoted in its place: {}",
		v["gives"], v);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// 4. A coin received after an arriving one.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn the_value_quote_counts_the_settle_when_an_earlier_coin_is_arriving() {
	let mut r = Running::start_with(|c, x, _| {
		c.finality.anchor_depth = 0;
		c.watcher.enabled = false;
		c.assets[0] = AssetSection { refresh_ppm: Some(3_000), refresh_base: Some("200".into()), offboard_ppm: Some(3_333),
			offboard_base: Some("7".into()), ..AssetSection::new(x, 1_000) };
	}).await;
	let x = r.x;
	post_bond(&mut r).await;
	let (s, a) = (Arca::new("NAMED N4 S"), Arca::new("NAMED N4 A"));
	create(&r, &s);
	leaves_only(&mut r, &s, x, 4_100_000).await;
	create(&r, &a);
	library(&a, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	let address = a.ok(&["address"])["address"].as_str().unwrap().to_string();
	let xs = x.to_string();
	let big = pay(&s, &a, x, 2_000_000);
	println!("N4: places: {}", library(&a, "coin_places", json!({})).unwrap()["coins"]);
	let line = a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == big.as_str()).cloned().unwrap();
	let expiry = line["expiry"].as_u64().unwrap().to_string();
	let ticket = a.ok(&["offboard", "--asset", &xs, "--value", "500000", "--expiry", &expiry, "--address", &address, "--quote"]);
	println!("N4: ticket for a coin of 500,000: {}", ticket);
	let small = pay(&s, &a, x, 500_000);
	let place = library(&a, "coin_places", json!({})).unwrap()["coins"].as_array().unwrap().iter()
		.find(|c| c["leaf_id"] == small.as_str()).cloned().unwrap();
	println!("N4: the 500,000 coin is placed {}", place["place"]);
	let (ok, v) = quote_ok(&a, &["offboard", "--asset", &xs, "--coins", &small, "--address", &address]);
	let needs_settle = !ok && v["error"]["kind"] == "settle_first";
	assert!(!(needs_settle && ticket["fee"]["settle"] == "0"), "the ticket counted no settle ({}), and the named move must \
		settle first: {}", ticket["fee"], v);
	for w in [&s, &a] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
