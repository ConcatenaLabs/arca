//! The operator's rate for each asset, from a source of its own, against a
//! whole server on an anchored proof-of-stake regtest chain: X (listed for
//! fees) priced by the node's own rate, Y (not listed) by a file, Z by a
//! command. `info` shows each rate with its source and age, and a smallest
//! leaf set as a value is converted at the asset's rate. Once Y's rate is
//! stale the server takes no new work in Y (a board, a participation),
//! answering `rate_stale` and naming Y, while X goes on and the work in Y
//! taken before (a participation, a payment) goes on too; once Y's rate is
//! fresh again Y is served as before.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use elements::AssetId;
use serde_json::{json, Value};

use common::client::{new_leaf, participation_body, resolve, transfer_body, want_leaf, Http};
use common::keys::{keypair, xonly};
use common::rounds::{credited_board, status, VALUE};
use common::running::Running;
use server::server::AssetSection;

fn now() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// An asset's section of `arcad.toml`, as an operator writes it.
fn section(text: &str) -> AssetSection {
	toml::from_str(text).unwrap_or_else(|e| panic!("{}: {}", text, e))
}

/// Writes Y's rate file: a rate of 2.5 reference coins a coin, taken at
/// `time`.
fn write_rate(path: &std::path::Path, time: u64) {
	std::fs::write(path, json!({"rate": "250000000", "time": time}).to_string()).unwrap();
}

/// `asset`'s entry in `info`.
fn info_of(http: &Http, asset: AssetId) -> Value {
	let info = http.get("info").ok();
	info["assets"].as_array().unwrap().iter().find(|a| a["asset"] == asset.to_string()).cloned()
		.unwrap_or_else(|| panic!("{} is not in {}", asset, info))
}

/// Waits until `asset`'s rate in `info` is stale or fresh, as `stale` says.
async fn rate_is(r: &Running, asset: AssetId, stale: bool) -> Value {
	let start = Instant::now();
	loop {
		let a = info_of(&r.http, asset);
		if a["rate"]["stale"] == stale {
			return a;
		}
		assert!(start.elapsed() < Duration::from_secs(40), "the rate of {} is not stale={}: {}", asset, stale, a);
		tokio::time::sleep(Duration::from_millis(500)).await;
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_rate_refuses_new_work_in_its_asset_alone() {
	let dir = std::env::temp_dir().join(format!("arca-rates-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let y_rate = dir.join("y.rate");
	write_rate(&y_rate, now());
	let file = y_rate.clone();
	let mut r = Running::start_with(move |c, y| {
		let x = c.assets[0].asset.clone();
		c.assets = vec![
			section(&format!("asset = \"{}\"\nmin_leaf = \"1000\"\n[rate]\nsource = \"node\"\nmax_age_seconds = 600\n", x)),
			// Y's smallest leaf is worth 2,500 in the reference unit: 1,000
			// atoms at a rate of 2.5.
			section(&format!("asset = \"{}\"\nmin_leaf_value = \"2500\"\n[rate]\nsource = \"file\"\npath = {:?}\nmax_age_seconds = 600\n",
				y, file.display().to_string())),
		];
	}).await;
	let (x, y, s, chain) = (r.x, r.y, xonly(&r.s), r.chain);
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(y, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;

	// Each rate, its source and its age.
	let (ix, iy) = (info_of(&r.http, x), info_of(&r.http, y));
	println!("info, X: {}\ninfo, Y: {}", ix, iy);
	assert_eq!((ix["rate"]["source"].as_str(), ix["rate"]["rate"].as_str(), ix["rate"]["stale"].as_bool()),
		(Some("node"), Some("100000000"), Some(false)), "X at the node's own rate: {}", ix);
	assert_eq!((iy["rate"]["source"].as_str(), iy["rate"]["rate"].as_str(), iy["rate"]["stale"].as_bool()),
		(Some("file"), Some("250000000"), Some(false)), "{}", iy);
	assert!(iy["rate"]["age_seconds"].as_u64().unwrap() < 600 && iy["rate"]["max_age_seconds"] == 600, "{}", iy);
	assert_eq!((iy["min_leaf_value"].as_str(), iy["min_leaf"].as_str()), (Some("2500"), Some("1000")), "{}", iy);

	// Work taken while Y's rate is fresh: a board, a participation, and a
	// coin to pay on later.
	let (a, b, c) = (keypair("rates: A"), keypair("rates: B"), keypair("rates: C"));
	let (a_coin, _) = credited_board(&mut r, &a, y).await;
	let (b_coin, b_tx) = credited_board(&mut r, &b, y).await;
	let (wa, _) = want_leaf(&keypair("rates: A, new"), y, VALUE);
	let (pa, ida) = participation_body(&[&a_coin], &[wa], &[], None, s, chain);
	assert_eq!(r.http.post("submit_participation", &pa).ok()["state"], "pending");
	let (c_coin, _) = credited_board(&mut r, &c, x).await;

	// Y's price process stops: its file says a time two hours back.
	write_rate(&y_rate, now() - 7_200);
	let iy = rate_is(&r, y, true).await;
	println!("Y's rate, stale: {}", iy["rate"]);
	assert!(iy["rate"]["age_seconds"].as_u64().unwrap() >= 7_200, "{}", iy);

	// No new work in Y: a board, a participation.
	let d = keypair("rates: D");
	let nonce = r.http.operator_nonce();
	let record = common::client::board_record(&d, nonce, y, VALUE, chain, s);
	let coins = vec![r.purse.take_coin(y), r.purse.take_coin(x)];
	let tx = record.tx(&coins, x, 2_000, &common::node::op_true()).unwrap().tx;
	let answer = r.http.register_board(&record, &tx);
	for coin in coins {
		r.purse.put(coin);
	}
	println!("a board of Y: {} {}", answer.status, answer.json);
	let (code, message) = answer.refusal();
	assert_eq!((answer.status, code.as_str()), (503, "rate_stale"), "{}", answer.json);
	assert!(message.contains(&y.to_string()) && message.contains("stale"), "{}", message);
	let (wb, _) = want_leaf(&keypair("rates: B, new"), y, VALUE);
	let (pb, _) = participation_body(&[&b_coin], &[wb], &[], None, s, chain);
	let answer = r.http.post("submit_participation", &pb);
	println!("a participation in Y: {} {}", answer.status, answer.json);
	assert_eq!((answer.status, answer.refusal().0.as_str()), (503, "rate_stale"));

	// X goes on: a participation in X is taken.
	let (wc, _) = want_leaf(&keypair("rates: C, new"), x, VALUE);
	let (pc, idc) = participation_body(&[&c_coin], &[wc], &[], None, s, chain);
	assert_eq!(r.http.post("submit_participation", &pc).ok()["state"], "pending", "X has a fresh rate");

	// The work in Y taken before goes on: A's participation, asked again, is
	// answered, and runs in Y's round beside X's; B's coin is paid on.
	assert_eq!(r.http.post("submit_participation", &pa).ok()["state"], "pending");
	let (rounds, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	assert_eq!(rounds.iter().map(|b| b.batches[0].0).collect::<Vec<_>>(), vec![x, y], "a round of X and a round of Y");
	assert_eq!((status(&r, &ida)["state"].as_str(), status(&r, &idc)["state"].as_str()), (Some("issued"), Some("issued")));
	let valid = resolve(&b_coin, &[b_tx], &r.policy());
	let (leaf, _) = new_leaf(&keypair("rates: B's payee"));
	// Y is not listed for fees: each margin is one atom.
	let body = transfer_body(&[(&b_coin, valid, VALUE - 1)], &[(y, VALUE - 2, leaf)], s, chain);
	let answer = r.http.post("cosign_transfer", &body);
	println!("a payment of B's coin of Y: {} {}", answer.status, if answer.status == 200 { "co-signed".into() } else { answer.json.to_string() });
	assert_eq!(answer.status, 200, "{}", answer.json);

	// Fresh again: Y is served as before.
	write_rate(&y_rate, now());
	rate_is(&r, y, false).await;
	let answer = r.http.register_board(&record, &tx);
	println!("the board of Y with a fresh rate: {} {}", answer.status, answer.json);
	assert!(answer.status != 503, "{}", answer.json);
	let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rate_comes_from_a_file_a_command_or_the_node() {
	let dir = std::env::temp_dir().join(format!("arca-rates-sources-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let y_rate = dir.join("y.rate");
	// A plain line, its time the file's own.
	std::fs::write(&y_rate, "50000000\n").unwrap();
	let file = y_rate.clone();
	let mut r = Running::start_with(move |c, y| {
		let x = c.assets[0].asset.clone();
		c.assets = vec![
			section(&format!("asset = \"{}\"\nmin_leaf_value = \"1000\"\n[rate]\nsource = \"command\"\n\
				command = [\"/bin/sh\", \"-c\", \"echo '{{\\\"rate\\\": 400000000}}'\"]\n", x)),
			section(&format!("asset = \"{}\"\nmin_leaf_value = \"1000\"\n[rate]\nsource = \"file\"\npath = {:?}\n", y,
				file.display().to_string())),
		];
	}).await;
	let (x, y) = (r.x, r.y);
	let (ix, iy) = (info_of(&r.http, x), info_of(&r.http, y));
	println!("info, X (a command): {}\ninfo, Y (a file): {}", ix, iy);
	assert_eq!((ix["rate"]["source"].as_str(), ix["rate"]["rate"].as_str()), (Some("command"), Some("400000000")));
	assert_eq!((iy["rate"]["source"].as_str(), iy["rate"]["rate"].as_str()), (Some("file"), Some("50000000")));
	assert_eq!(ix["rate"]["max_age_seconds"], 3_600, "an hour when not set");
	// A value of 1,000: 250 atoms of X at 4, 2,000 of Y at 0.5.
	assert_eq!((ix["min_leaf"].as_str(), iy["min_leaf"].as_str()), (Some("250"), Some("2000")));

	// A board of Y below its smallest leaf, in atoms at its rate, is refused.
	let d = keypair("sources: D");
	let nonce = r.http.operator_nonce();
	let record = common::client::board_record(&d, nonce, y, 1_999, r.chain, xonly(&r.s));
	let coins = vec![r.purse.take_coin(y), r.purse.take_coin(x)];
	let tx = record.tx(&coins, x, 2_000, &common::node::op_true()).unwrap().tx;
	let answer = r.http.register_board(&record, &tx);
	for coin in coins {
		r.purse.put(coin);
	}
	println!("a board of 1,999 atoms of Y: {} {}", answer.status, answer.json);
	let (code, message) = answer.refusal();
	assert_eq!(code, "out_of_bounds");
	assert!(message.contains("below the smallest leaf") && message.contains("2000"), "{}", message);

	// A file that does not read keeps the last rate, saying why.
	std::fs::write(&y_rate, "a rate\n").unwrap();
	let start = Instant::now();
	let iy = loop {
		let iy = info_of(&r.http, y);
		if iy["rate"]["failed"].is_string() {
			break iy;
		}
		assert!(start.elapsed() < Duration::from_secs(40), "{}", iy);
		tokio::time::sleep(Duration::from_millis(500)).await;
	};
	println!("Y's file unreadable: {}", iy["rate"]);
	assert_eq!(iy["rate"]["rate"], "50000000");
	let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rate_dated_ahead_of_the_clock_is_not_taken() {
	// A price process whose reading says a day ahead would never go stale:
	// its age would read 0 until that day. The server takes no such reading.
	let dir = std::env::temp_dir().join(format!("arca-rates-ahead-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let y_rate = dir.join("y.rate");
	write_rate(&y_rate, now() + 86_400);
	let file = y_rate.clone();
	let r = Running::start_with(move |c, y| {
		c.assets.push(section(&format!("asset = \"{}\"\nmin_leaf = \"1000\"\n[rate]\nsource = \"file\"\npath = {:?}\nmax_age_seconds = 600\n",
			y, file.display().to_string())));
	}).await;
	let iy = info_of(&r.http, r.y);
	println!("info, Y, its file dated a day ahead: {}", iy["rate"]);
	assert_eq!(iy["rate"]["stale"], true, "no rate taken: {}", iy);
	assert!(iy["rate"].get("rate").is_none(), "{}", iy);
	assert!(iy["rate"]["failed"].as_str().unwrap_or("").contains("ahead of the server's clock"), "{}", iy);
	// Dated now, it is taken.
	write_rate(&y_rate, now());
	let iy = rate_is(&r, r.y, false).await;
	println!("info, Y, its file dated now: {}", iy["rate"]);
	let _ = std::fs::remove_dir_all(&dir);
}
