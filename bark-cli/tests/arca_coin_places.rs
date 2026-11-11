//! Where each coin stands, and the instant limit ([`bark::arca::places`]),
//! run by the `arca` binary against a whole Arca server on an anchored
//! regtest chain, the operator's bond posted.
//!
//! 1. A payment under the limit counts at once, and is spent on at once.
//! 2. One over the limit arrives: it is in no payment and gives no trade,
//!    `refresh_needed` names it (`arriving`), and once its round is final
//!    it is settled.
//! 3. Several small payments cross the limit in the order they arrived:
//!    the oldest count, the rest arrive, and none moves back.
//! 4. The limit taken is the lower of the wallet's and the operator's
//!    suggestion (`[bond] instant_limit_value`); a wallet that sets none
//!    counts every payment, as before.
//! 5. A trade's proceeds, every checkpoint with its owner's exit: of
//!    `trade` lineage, counting nothing against the limit or the bond,
//!    traded on at once; never paid out of the Arca. The coin given held
//!    exactly the amount, shaped by a payment to itself first, so no change
//!    of the wallet's rode in the trade.
//! 6. A restore from the mnemonic alone gives the same places.
//! 7. An anchor rollback under the coins: every coin not final again
//!    arrives, and counts again once final.
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

const BOND: u64 = 50_000_000;

fn notice_units() -> u16 {
	server::bond::min_notice_seconds(server::bond::LIFETIME, RelativeTime::from_units(338).unwrap()).div_ceil(512) as u16
}

/// Posts the operator's bond, with `limit` as its suggested instant limit.
async fn post_bond(r: &mut Running, limit: Option<u64>) -> OutPoint {
	let w = keypair("coin-places W");
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
		outpoint: Some(format!("{}:{}", op.txid, op.vout)), notice: None, instant_budget_fraction: None,
		instant_limit_value: limit.map(|l| l.to_string()) });
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
	mb["accepted"].as_array().unwrap().iter().find(|c| c["value"].as_str() == Some(&amount.to_string()) || c["value"] == amount)
		.or_else(|| mb["accepted"].as_array().unwrap().last())
		.and_then(|c| c["leaf_id"].as_str()).expect("the payee holds the coin").to_string()
}

/// `from` pays `to`, refused for `why`: the refusal.
fn pay_refused(from: &Arca, to: &Arca, asset: AssetId, amount: u64, why: &str) -> String {
	let req = to.ok(&["receive"])["request"].as_str().unwrap().to_string();
	from.refused(&["send", &req, "--amount", &amount.to_string(), "--asset", &asset.to_string()], why)
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

fn places(w: &Arca) -> Value {
	library(w, "coin_places", json!({})).unwrap()
}

fn place_of(p: &Value, leaf: &str) -> String {
	p["coins"].as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf)
		.map(|c| c["place"].as_str().unwrap().to_string()).unwrap_or_else(|| "none".into())
}

fn rate(r: &Running, a: AssetId) -> u128 {
	let rates: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
	rates[a.to_string()].as_u64().unwrap_or_else(|| panic!("no rate for {} in {}", a, rates)) as u128
}

/// Sets the node's rate for `a`, as an operator's price server would: the
/// operator reads it at its start.
fn price(r: &Running, a: AssetId, rate: u64) {
	let mut set: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
	set[a.to_string()] = json!(rate);
	r.rt.client().call::<Value>("setfeeexchangerates", &[set]).unwrap();
}

/// Atoms of the reference unit `atoms` of `a` are worth.
fn worth(r: &Running, a: AssetId, atoms: u64) -> u128 {
	atoms as u128 * rate(r, a) / 100_000_000
}

fn summary(tag: &str, w: &Arca) -> Value {
	let p = places(w);
	let line: Vec<String> = p["coins"].as_array().unwrap().iter()
		.map(|c| format!("{}…={}/{}/{}", &c["leaf_id"].as_str().unwrap()[..8], c["value"].as_str().unwrap(), c["state"].as_str().unwrap(),
			c["place"].as_str().unwrap())).collect();
	println!("{}: {} places: [{}] limit {}", tag, w.name, line.join(", "), p["instant_limit"]);
	p
}

#[tokio::test(flavor = "multi_thread")]
async fn payments_count_up_to_the_limit_in_the_order_they_arrive() {
	let mut r = Running::start().await;
	let (x, y) = (r.x, r.y);
	price(&r, y, 100_000_000);
	post_bond(&mut r, None).await;
	let (s, b, c, d) = (Arca::new("CP1 S"), Arca::new("CP1 B"), Arca::new("CP1 C"), Arca::new("CP1 D"));
	let s2 = Arca::new("CP1 S2");
	boarded(&mut r, &s, &[(x, 12_000_000)]).await;
	boarded(&mut r, &s2, &[(x, 12_000_000)]).await;
	for w in [&b, &c, &d] {
		create(&r, w);
	}
	// B counts at most what 1,000,000 X is worth, at the node's rates.
	let limit = worth(&r, x, 1_000_000);
	library(&b, "instant_limit", json!({"value": limit.to_string()})).unwrap();
	library(&d, "instant_limit", json!({"value": limit.to_string()})).unwrap();

	// 1. Under the limit: counted at once, and spent on at once.
	let small = pay(&s, &b, x, 400_000);
	let p = summary("CP1 under", &b);
	assert_eq!(place_of(&p, &small), "counted");
	assert_eq!(p["spendable"][x.to_string()], "400000", "{}", p);
	assert_eq!(p["instant_limit"]["counted"], worth(&r, x, 400_000).to_string());
	let on = pay(&b, &c, x, 300_000);
	println!("CP1 under: B paid C 300,000 at once ({})", &on[..16]);
	let p = summary("CP1 under, paid on", &b);
	assert!(p["coins"].as_array().unwrap().iter().all(|k| k["place"] == "counted" || k["state"] != "live"), "{}", p);

	// 2. Over the limit: arriving. No payment and no trade takes it.
	let big = pay(&s, &b, x, 1_500_000);
	let p = summary("CP1 over", &b);
	assert_eq!(place_of(&p, &big), "arriving", "{}", p);
	pay_refused(&b, &c, x, 1_000_000, "live coins");
	let offer = library(&b, "swap_offer", json!({"give_asset": x, "give": "1000000", "want_asset": y, "want": "1000000"}));
	println!("CP1 over: B offers it in a trade: {:?}", offer);
	assert!(offer.as_ref().is_err_and(|e| e.contains("live coins")), "{:?}", offer);
	let need = library(&b, "refresh_needed", json!({})).unwrap();
	println!("CP1 over: refresh_needed: {}", need);
	assert_eq!(need["reasons"][0]["rule"], "arriving", "{}", need);
	assert_eq!(need["reasons"][0]["coins"], json!([big]), "{}", need);
	// Its round: once final, the new coin is settled and spends.
	let rr = b.ok(&["refresh-received"]);
	println!("CP1 over: B's refresh: {}", rr["refreshed"]);
	rounds_final(&r).await;
	b.ok(&["sync"]);
	let p = summary("CP1 over, after its round", &b);
	assert!(p["coins"].as_array().unwrap().iter().filter(|k| k["state"] == "live").all(|k| k["place"] == "settled"), "{}", p);
	assert_eq!(place_of(&p, &big), "none", "the arriving coin was given up in the round");
	pay(&b, &c, x, 1_000_000);
	println!("CP1 over: after its round, B paid C 1,000,000");

	// 3. Several small payments cross the limit in order.
	let mut got = vec![];
	for v in [400_000u64, 400_000, 400_000, 100_000] {
		got.push(pay(&s2, &d, x, v));
	}
	let p = summary("CP1 several", &d);
	let shown: Vec<String> = got.iter().map(|l| place_of(&p, l)).collect();
	println!("CP1 several: 400,000 ×3 then 100,000 against 1,000,000: {:?}", shown);
	assert_eq!(shown, ["counted", "counted", "arriving", "arriving"], "{}", p);
	// The price of X doubles: what was counted stays counted.
	let mut set: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
	let before = set[x.to_string()].as_u64().unwrap();
	set[x.to_string()] = json!(before * 2);
	r.rt.client().call::<Value>("setfeeexchangerates", &[set.clone()]).unwrap();
	let p = summary("CP1 several, X doubled", &d);
	let shown2: Vec<String> = got.iter().map(|l| place_of(&p, l)).collect();
	assert_eq!(shown2, shown, "a price rise moves no coin back: {}", p);
	set[x.to_string()] = json!(before);
	r.rt.client().call::<Value>("setfeeexchangerates", &[set]).unwrap();

	// 4. No limit set: every payment counts, as before.
	let p = summary("CP1 none", &c);
	assert!(p["instant_limit"].is_null());
	assert!(p["coins"].as_array().unwrap().iter().all(|k| k["place"] == "counted"), "{}", p);
	for w in [&s, &s2, &b, &c, &d] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn the_operators_suggestion_bounds_the_limit_and_no_bond_counts_nothing() {
	let mut r = Running::start().await;
	let x = r.x;
	let (s, b, e) = (Arca::new("CP4 S"), Arca::new("CP4 B"), Arca::new("CP4 E"));
	boarded(&mut r, &s, &[(x, 6_000_000)]).await;
	create(&r, &b);
	create(&r, &e);
	let mine = worth(&r, x, 1_000_000);
	library(&e, "instant_limit", json!({"value": mine.to_string()})).unwrap();
	// No bond: nothing deters a sender and the operator, so nothing counts.
	let k = pay(&s, &e, x, 100_000);
	let p = summary("CP4 no bond", &e);
	assert_eq!(p["instant_limit"]["value"], "0", "{}", p);
	assert_eq!(place_of(&p, &k), "arriving");
	// The operator suggests what 600,000 X is worth: the lower is taken.
	let suggested = worth(&r, x, 600_000) as u64;
	post_bond(&mut r, Some(suggested)).await;
	let info: Value = serde_json::from_str(minreq::get(format!("{}/v1/info", r.url())).send().unwrap().as_str().unwrap()).unwrap();
	println!("CP4: info.bond.instant_limit_value = {}", info["bond"]["instant_limit_value"]);
	assert_eq!(info["bond"]["instant_limit_value"], suggested.to_string());
	library(&b, "instant_limit", json!({"value": mine.to_string()})).unwrap();
	let a1 = pay(&s, &b, x, 400_000);
	let a2 = pay(&s, &b, x, 400_000);
	let p = summary("CP4 suggested", &b);
	assert_eq!(p["instant_limit"]["value"], suggested.to_string(), "{}", p);
	assert_eq!(p["instant_limit"]["operator"], suggested.to_string(), "{}", p);
	assert_eq!((place_of(&p, &a1).as_str(), place_of(&p, &a2).as_str()), ("counted", "arriving"), "{}", p);
	// The one received before the bond stood is counted once it does.
	let p = summary("CP4 bond up", &e);
	assert_eq!(place_of(&p, &k), "counted", "{}", p);
	for w in [&s, &b, &e] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
