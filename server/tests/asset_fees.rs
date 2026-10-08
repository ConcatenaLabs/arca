//! What the operator charges, set per asset, against a whole server on an
//! anchored proof-of-stake regtest chain: X charges a refresh of its own,
//! its parts per million and a fixed part in X's atoms, and takes `[fees]`'
//! offboard; Y charges `[fees]`' parts per million and a fixed part set as a
//! value in the reference unit, taken in Y's atoms at Y's rate. `info`
//! publishes each asset's schedule, and the defaults at its top; a
//! participation pays its asset's schedule to the atom, and one atom short
//! is refused, naming the asset and its schedule; a new rate moves a fixed
//! part set as a value; and a schedule changed in the configuration is
//! taken on a reload.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use elements::AssetId;
use serde_json::{json, Value};

use arca_covenant::MedianTime;
use common::client::{participation_body, want_leaf, Answer, Http};
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{credited_board, mtp, VALUE};
use common::running::Running;
use server::participations::OutputRequest;
use server::server::AssetSection;

fn now() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn section(text: &str) -> AssetSection {
	toml::from_str(text).unwrap_or_else(|e| panic!("{}: {}", text, e))
}

fn info_of(http: &Http, asset: AssetId) -> Value {
	let info = http.get("info").ok();
	info["assets"].as_array().unwrap().iter().find(|a| a["asset"] == asset.to_string()).cloned()
		.unwrap_or_else(|| panic!("{} is not in {}", asset, info))
}

/// The configuration's assets: X with a schedule of its own, Y with a
/// fixed part set as a value, priced by the file at `rate_file`.
fn assets(x: &str, y: &str, rate_file: &std::path::Path, x_refresh_ppm: u64) -> Vec<AssetSection> {
	vec![
		section(&format!("asset = \"{}\"\nmin_leaf = \"1000\"\nrefresh_ppm = {}\nrefresh_base = \"200\"\noffboard_base = \"300\"\n", x,
			x_refresh_ppm)),
		section(&format!("asset = \"{}\"\nmin_leaf = \"1000\"\nrefresh_base_value = \"1000\"\n[rate]\nsource = \"file\"\npath = {:?}\n", y,
			rate_file.display().to_string())),
	]
}

/// What a refresh of a coin of `value` whose expiry is `expiry` costs at
/// `now` under `ppm` and a fixed part of `base` atoms, as the specification
/// sets it: in full 23 days or more before the free window (the five days
/// before the expiry), falling to nothing in it, rounded up.
fn refresh_due(ppm: u64, base: u64, value: u64, expiry: u32, now: MedianTime) -> u64 {
	let left = expiry.saturating_sub(now.to_consensus_u32()).saturating_sub(5 * 86_400).min(23 * 86_400) as u128;
	((value as u128 * ppm as u128 + base as u128 * 1_000_000) * left).div_ceil(23 * 86_400 * 1_000_000) as u64
}

fn refused(a: &Answer, code: &str) -> String {
	let (c, m) = a.refusal();
	assert_eq!(c, code, "{}", a.json);
	m
}

#[tokio::test(flavor = "multi_thread")]
async fn each_asset_charges_its_own_schedule() {
	let dir = std::env::temp_dir().join(format!("arca-asset-fees-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let rate_file = dir.join("y.rate");
	// Y at 2.5 reference coins a coin: a value of 1,000 is 400 atoms.
	std::fs::write(&rate_file, format!("250000000 {}\n", now())).unwrap();
	let file = rate_file.clone();
	let mut r = Running::start_with(move |c, y| {
		c.fees.refresh_ppm = 1_000;
		c.fees.offboard_ppm = 2_000;
		let x = c.assets[0].asset.clone();
		c.assets = assets(&x, &y.to_string(), &file, 5_000);
	}).await;
	let (x, y, s, chain) = (r.x, r.y, xonly(&r.s), r.chain);
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(y, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;

	// Each asset's schedule, and the defaults at the top.
	let info = r.http.get("info").ok();
	let (fx, fy) = (info_of(&r.http, x)["fees"].clone(), info_of(&r.http, y)["fees"].clone());
	println!("info.fees: {}\nX's fees: {}\nY's fees: {}", info["fees"], fx, fy);
	assert_eq!((info["fees"]["refresh_ppm"].as_u64(), info["fees"]["offboard_ppm"].as_u64()), (Some(1_000), Some(2_000)));
	assert_eq!(fx, json!({"refresh_ppm": 5_000, "refresh_base": "200", "offboard_ppm": 2_000, "offboard_base": "300",
		"lightning_ppm": 0, "lightning_base": "0"}));
	assert_eq!(fy, json!({"refresh_ppm": 1_000, "refresh_base": "400", "refresh_base_value": "1000", "offboard_ppm": 2_000,
		"offboard_base": "0", "lightning_ppm": 0, "lightning_base": "0"}));

	// A refresh in each asset pays its asset's schedule, to the atom.
	for (asset, label, (ppm, base, offboard_ppm, offboard_base)) in [(x, "X", (5_000, 200, 2_000, 300)), (y, "Y", (1_000, 400, 2_000, 0))] {
		let owner = keypair(&format!("asset fees: {}", label));
		let (coin, _) = credited_board(&mut r, &owner, asset).await;
		let expiry = r.http.board_status(&coin.id).ok()["expiry"].as_u64().unwrap() as u32;
		let due = refresh_due(ppm, base, VALUE, expiry, mtp(&r));
		println!("{}'s board, expiry {}: a refresh due {} of {} ({} ppm and {} a coin, by the time left)", label, expiry, due, label,
			ppm, base);
		assert!(due > base, "both parts are charged: {}", due);
		let (w, _) = want_leaf(&keypair(&format!("asset fees: {} new, short", label)), asset, VALUE - due + 1);
		let (short, _) = participation_body(&[&coin], &[w], &[(asset, due - 1)], None, s, chain);
		let answer = r.http.post("submit_participation", &short);
		let why = refused(&answer, "fee");
		println!("a fee of {} of {}, one atom short: REFUSED: {}", due - 1, label, why);
		assert!(why.contains(&asset.to_string()) && why.contains(&format!("refresh {} ppm and {} a coin, offboard {} ppm and {}", ppm,
			base, offboard_ppm, offboard_base)), "{}", why);
		let (w, _) = want_leaf(&keypair(&format!("asset fees: {} new", label)), asset, VALUE - due);
		let (body, _) = participation_body(&[&coin], &[w], &[(asset, due)], None, s, chain);
		let st = r.http.post("submit_participation", &body).ok();
		assert_eq!(st["state"], "pending", "{}", st);
	}

	// An offboard of X pays X's parts per million, its fixed part and its
	// output's margin: a first offboard, over-paid, shows the margin.
	let (coin1, _) = credited_board(&mut r, &keypair("asset fees: offboard 1"), x).await;
	let (coin2, _) = credited_board(&mut r, &keypair("asset fees: offboard 2"), x).await;
	let off = OutputRequest::Offboard { asset: x, value: 500_000, script: node::op_true() };
	let (body, _) = participation_body(&[&coin1], &[off.clone()], &[(x, VALUE - 500_000)], None, s, chain);
	let st = r.http.post("submit_participation", &body).ok();
	let margin: u64 = st["outputs"][0]["margin"].as_str().unwrap().parse().unwrap();
	let expiry = r.http.board_status(&coin2.id).ok()["expiry"].as_u64().unwrap() as u32;
	let refresh = refresh_due(5_000, 200, VALUE, expiry, mtp(&r));
	let due = refresh + 500_000 * 2_000 / 1_000_000 + 300 + margin;
	println!("an offboard of 500000 of X, its coin given up: due {} (the refresh {}; 1000 in parts per million, 300 fixed and a margin \
		of {})", due, refresh, margin);
	let (w, _) = want_leaf(&keypair("asset fees: offboard 2, change short"), x, VALUE - 500_000 - due + 1);
	let (short, _) = participation_body(&[&coin2], &[w, off.clone()], &[(x, due - 1)], None, s, chain);
	let why = refused(&r.http.post("submit_participation", &short), "fee");
	println!("the offboard one atom short: REFUSED: {}", why);
	assert!(why.contains("offboard 2000 ppm and 300"), "{}", why);
	let (w, _) = want_leaf(&keypair("asset fees: offboard 2, change"), x, VALUE - 500_000 - due);
	let (exact, _) = participation_body(&[&coin2], &[w, off], &[(x, due)], None, s, chain);
	assert_eq!(r.http.post("submit_participation", &exact).ok()["state"], "pending");

	// A new rate moves Y's fixed part: at 5 reference coins a coin, a value
	// of 1,000 is 200 atoms.
	std::fs::write(&rate_file, format!("500000000 {}\n", now())).unwrap();
	let start = Instant::now();
	loop {
		let f = info_of(&r.http, y)["fees"].clone();
		if f["refresh_base"] == "200" {
			println!("Y's fees at a rate of 5: {}", f);
			break;
		}
		assert!(start.elapsed() < Duration::from_secs(40), "{}", f);
		tokio::time::sleep(Duration::from_millis(500)).await;
	}

	// A schedule changed in the configuration is taken on a reload, the
	// defaults as well.
	let mut config = r.server.config();
	config.assets = assets(&x.to_string(), &y.to_string(), &rate_file, 7_000);
	config.fees.offboard_ppm = 3_000;
	let reloaded = r.server.reload(&config).await.unwrap();
	println!("reloaded: {:?}", reloaded);
	assert_eq!(reloaded.changed, vec![x, y], "X's own schedule, and Y's by the default it takes");
	assert!(reloaded.needs_restart.is_empty(), "{:?}", reloaded);
	assert_eq!(info_of(&r.http, x)["fees"]["refresh_ppm"], 7_000);
	assert_eq!(info_of(&r.http, y)["fees"]["offboard_ppm"], 3_000, "Y takes the new default");
	assert_eq!(r.http.get("info").ok()["fees"]["offboard_ppm"], 3_000);
	let _ = std::fs::remove_dir_all(&dir);
}
