//! Deposits with Bitcoin ark watchtowers ([bark::btc_tower]).
//!
//! `tower_plan` answers what the program running the wallet should send to
//! the towers it names, so the program does the HTTP itself (a page with
//! `fetch`, a native program with its own client) and keeps which deposits
//! each tower holds:
//!
//! - `deposit`: one body per coin worth rescuing ([bark::btc_tower::worth_rescuing]
//!   at the day's fast rate) and per tower that watches its ark and does not
//!   hold it yet, its claim paying the phrase's first BIP84 address (the
//!   address the dual-chain wallet shows for BTC);
//! - `withdraw`: one body per deposit the program lists that names a coin the
//!   wallet no longer holds in the ark;
//! - `covered` and `not_worth`: which coins are watched, by which towers, and
//!   which are too small to rescue, for developer mode;
//! - `refresh_due`: the coins within `2 × M` blocks of expiry, which the wallet
//!   refreshes while it is open, so a holder who opened it recently is never
//!   rescued.
//!
//! Arguments: `{"towers": [{"url", "info"}], "deposited": [{"tower",
//! "vtxo", "claim_txid"}], "fast_rate"?}` (`info` is the tower's `GET
//! /v1/info`; `fast_rate` in sat/vB, the chain's estimate by default).

use anyhow::{anyhow, Context};
use serde_json::{json, Value};

use bark::ark::bitcoin::FeeRate;
use bark::btc_tower::{Deposited, TowerTerms};
use bark::onchain::bdk_wallet::KeychainKind;
use bark::Wallet;

pub const COMMANDS: &[&str] = &["tower_plan"];

pub async fn run(wallet: &Wallet, cmd: &str, args: &Value) -> anyhow::Result<Value> {
	match cmd {
		"tower_plan" => plan(wallet, args).await,
		_ => Err(anyhow!("unknown command {}", cmd)),
	}
}

async fn plan(wallet: &Wallet, args: &Value) -> anyhow::Result<Value> {
	let holder = {
		let f = crate::exit::funding_of(wallet)?;
		let w = f.read().await;
		w.inner.peek_address(KeychainKind::External, 0).address
	};
	let fast = match args.get("fast_rate").and_then(|v| v.as_u64()) {
		Some(r) => FeeRate::from_sat_per_vb(r).context("fast_rate")?,
		None => wallet.chain().fee_rates().await.fast,
	};
	let mut towers = vec![];
	let mut unusable = vec![];
	for t in args.get("towers").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
		let url = t["url"].as_str().unwrap_or("").to_string();
		match TowerTerms::from_info(&t["info"]) {
			Ok(terms) => towers.push((url, terms)),
			Err(e) => unusable.push(json!({"tower": url, "reason": e.to_string()})),
		}
	}
	let deposited: Vec<Deposited> = args.get("deposited").and_then(|v| v.as_array()).cloned().unwrap_or_default()
		.iter().map(|d| Deposited {
			tower: d["tower"].as_str().unwrap_or("").to_string(),
			vtxo: d["vtxo"].as_str().unwrap_or("").to_string(),
			claim_txid: d["claim_txid"].as_str().unwrap_or("").to_string(),
		}).collect();
	let mut v = wallet.btc_tower_plan(&holder, &towers, &deposited, fast).await?;
	if let Some(s) = v["skipped"].as_array_mut() {
		s.extend(unusable);
	}
	Ok(v)
}
