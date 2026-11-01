//! Runs one of the wallet's commands natively against a Bitcoin ark on
//! regtest (`contrib/bitcoin-ark-regtest`), the chain read from its Bitcoin
//! Core; or, with `NETWORK` (testnet4, signet, bitcoin) and `ESPLORA`, against
//! any Bitcoin ark, the chain read from an Esplora server. Each run opens the wallet, runs the command, prints its answer and
//! closes the wallet again, with no daemon: between two runs the wallet is
//! closed, as a browser's is when its page is.
//!
//!     ARK=http://127.0.0.1:23145 BITCOIND=http://127.0.0.1:23142 \
//!     COOKIE=$H/btc/regtest/.cookie MNEMONIC="…" [FEERATE=5] \
//!     cargo run --features native --example regtest_drive -- DATADIR COMMAND [JSON]
//!
//! `sync` is the wallet's own sync (what its daemon runs while it is open),
//! `funding_address` the first address of the phrase's BIP84 account (whose
//! coins pay an exit's fees), `board_funding` `{"sats"}` a board paid from
//! those coins; every other command is one of
//! [arca_bark_wasm::command::COMMANDS].

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;

/// The wallet's log on stderr, at the level `LOG` names (warn by default).
struct Stderr;
impl log::Log for Stderr {
	fn enabled(&self, _: &log::Metadata) -> bool { true }
	fn log(&self, r: &log::Record) {
		if self.enabled(r.metadata()) {
			eprintln!("{} {}: {}", r.level(), r.target(), r.args());
		}
	}
	fn flush(&self) {}
}

fn env(name: &str) -> anyhow::Result<String> {
	std::env::var(name).with_context(|| format!("set {}", name))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	let level = std::env::var("LOG").ok().and_then(|l| l.parse().ok()).unwrap_or(log::LevelFilter::Warn);
	let _ = log::set_logger(&Stderr);
	log::set_max_level(level);

	let mut args = std::env::args().skip(1);
	let datadir = PathBuf::from(args.next().context("name the wallet's data directory")?);
	let cmd = args.next().context("name a command")?;
	let json: serde_json::Value = match args.next() {
		Some(s) => serde_json::from_str(&s).context("the arguments are not JSON")?,
		None => serde_json::json!({}),
	};

	let net = arca_bark_wasm::command::network(&std::env::var("NETWORK").unwrap_or_else(|_| "regtest".into()))?;
	let mnemonic = bark::bip39::Mnemonic::from_str(env("MNEMONIC")?.trim())?;
	let seed = bark::WalletSeed::new_from_mnemonic(net, &mnemonic);
	let mut config = bark::Config::network_default(net);
	config.server_address = env("ARK")?;
	match std::env::var("ESPLORA") {
		Ok(e) => config.esplora_address = Some(e),
		Err(_) => {
			config.bitcoind_address = Some(env("BITCOIND")?);
			config.bitcoind_cookiefile = Some(PathBuf::from(env("COOKIE")?));
		},
	}
	// A regtest node has no fee estimates: the rate the wallet takes instead
	// (sat/vB, `FEERATE`, 5 by default, the regtest ark's own fallback).
	let rate = std::env::var("FEERATE").ok().and_then(|r| r.parse().ok()).unwrap_or(5);
	config.fallback_fee_rate = Some(bark::ark::bitcoin::FeeRate::from_sat_per_vb_u32(rate));
	let mut open = bark::OpenWalletArgs::default();
	open.run_daemon = false;
	open.datadir = Some(datadir);
	arca_bark_wasm::exit::attach_funding(&mut open, net, &env("MNEMONIC")?).await?;
	let wallet = bark::Wallet::open(net, seed, config, open).await?;

	let out = if cmd == "sync" {
		wallet.sync().await;
		serde_json::json!({})
	} else if cmd == "funding_address" {
		// The phrase's first BIP84 address: the one a dual-chain wallet shows first.
		let w = wallet.onchain().context("no funding wallet")?;
		serde_json::json!({ "address": w.write().await.address().await?.to_string() })
	} else if cmd == "board_funding" {
		// Boards `sats` from the phrase's BIP84 coins, signed here: a holder with no
		// other on-chain wallet to build the funding.
		arca_bark_wasm::exit::sync_funding(&wallet).await?;
		let b = wallet.board_amount(bark::ark::bitcoin::Amount::from_sat(
			json["sats"].as_str().context("'sats' is missing")?.parse()?)).await?;
		serde_json::json!({ "funding_txid": b.funding_tx.compute_txid().to_string(), "amount": b.amount.to_sat() })
	} else {
		arca_bark_wasm::run(&wallet, &cmd, &json).await?
	};
	println!("{}", out);
	Ok(())
}
