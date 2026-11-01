//! `arca btc-watchtower`: a watchtower for coins of a Bitcoin ark
//! ([bark::btc_tower]), in `<datadir>/btc-watchtower`.
//!
//! It holds its own phrase and Bitcoin coins, which pay the children that
//! bring deposited coins on chain; its rescue fees are paid to its payout
//! address. `create` writes its settings (`config.json`: the network, the
//! chain source, the arks it watches, its least rate); a bitcoind password is
//! never written there, but read from `ARCA_BITCOIND_PASSWORD` at each start.
//! `serve` answers `GET /v1/info`, `POST /v1/deposit` and `POST /v1/withdraw`
//! over HTTP, with the same server as `arca watchtower serve`, and passes over
//! its deposits every `interval` seconds.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use bark::arca::Error;
use bark::btc_tower::tower::{Tower, TowerConfig};
use bark::btc_tower::RESCUE_MARGIN;
use bark::chain::ChainSourceSpec;
use bitcoin_ext::rpc::Auth;
use clap::Subcommand;
use serde_json::{json, Value};

#[derive(Subcommand)]
pub enum BtcTowerCmd {
	/// Sets the tower up: its phrase (made now), its chain and the arks it
	/// watches.
	Create {
		/// bitcoin, testnet4, signet or regtest.
		#[arg(long)]
		network: String,
		/// A Bitcoin Core node's RPC URL (with -txindex).
		#[arg(long, conflicts_with = "esplora")]
		bitcoind: Option<String>,
		/// The node's cookie file.
		#[arg(long, requires = "bitcoind")]
		bitcoind_cookie: Option<String>,
		/// The node's RPC user; the password is read from
		/// ARCA_BITCOIND_PASSWORD whenever the tower starts.
		#[arg(long, requires = "bitcoind", conflicts_with = "bitcoind_cookie")]
		bitcoind_user: Option<String>,
		/// An Esplora server's URL, instead of a node.
		#[arg(long)]
		esplora: Option<String>,
		/// The server key of an ark whose coins the tower takes (repeat it
		/// for more); none, any ark's.
		#[arg(long = "ark")]
		arks: Vec<String>,
		/// The least rate, in sat/vB, a deposit's rescue fee must cover.
		#[arg(long, default_value_t = 5)]
		min_rate: u64,
		/// The rate used when the chain gives no estimate, in sat/vB.
		#[arg(long)]
		fallback_rate: Option<u64>,
	},
	/// Serves deposits over HTTP and passes over them every `interval`
	/// seconds, until stopped.
	Serve {
		#[arg(long, default_value = "127.0.0.1:3540")]
		listen: String,
		#[arg(long, default_value_t = 30)]
		interval: u64,
	},
	/// One pass over the deposits, then stops.
	Pass,
	/// The deposits held, each with its state.
	Deposits,
	/// What a wallet reads before depositing, and the tower's own coins.
	Info,
	/// An address of the tower's own account, to fund the children it pays.
	Address,
}

fn dir(datadir: &Path) -> PathBuf {
	datadir.join("btc-watchtower")
}

fn err(e: anyhow::Error) -> Error {
	let m = format!("{:#}", e);
	match m.strip_prefix("refused: ") {
		Some(r) => Error::Refused(r.to_string()),
		None => Error::Io(m),
	}
}

fn config(d: &Path) -> Result<TowerConfig, Error> {
	let c: Value = serde_json::from_slice(&std::fs::read(d.join("config.json"))
		.map_err(|_| Error::Refused("no tower here: run `arca btc-watchtower create` first".into()))?)
		.map_err(|e| Error::Parse(e.to_string()))?;
	let network = bitcoin::Network::from_str(c["network"].as_str().unwrap_or("")).map_err(|e| Error::Parse(e.to_string()))?;
	let chain = if let Some(u) = c["esplora"].as_str() {
		ChainSourceSpec::Esplora { url: u.to_string() }
	} else {
		let url = c["bitcoind"].as_str().ok_or_else(|| Error::Parse("no chain source".into()))?.to_string();
		let auth = match (c["bitcoind_cookie"].as_str(), c["bitcoind_user"].as_str()) {
			(Some(f), _) => Auth::CookieFile(PathBuf::from(f)),
			(None, Some(u)) => Auth::UserPass(u.to_string(), std::env::var("ARCA_BITCOIND_PASSWORD")
				.map_err(|_| Error::Refused("set ARCA_BITCOIND_PASSWORD".into()))?),
			(None, None) => return Err(Error::Parse("no bitcoind authentication".into())),
		};
		ChainSourceSpec::Bitcoind { url, auth, zmq: None }
	};
	let rate = |v: &Value| v.as_u64().and_then(bitcoin::FeeRate::from_sat_per_vb);
	Ok(TowerConfig {
		network,
		chain,
		min_rate: rate(&c["min_rate"]).ok_or_else(|| Error::Parse("min_rate".into()))?,
		fallback_rate: rate(&c["fallback_rate"]),
		arks: c["arks"].as_array().map(|a| a.iter().filter_map(|k| k.as_str())
			.filter_map(|k| bitcoin::secp256k1::PublicKey::from_str(k).ok()).collect()).unwrap_or_default(),
		margin: RESCUE_MARGIN,
	})
}

pub fn run(datadir: &Path, cmd: BtcTowerCmd) -> Result<Value, Error> {
	let d = dir(datadir);
	let rt = tokio::runtime::Runtime::new().map_err(|e| Error::Io(e.to_string()))?;
	if let BtcTowerCmd::Create { network, bitcoind, bitcoind_cookie, bitcoind_user, esplora, arks, min_rate, fallback_rate } = cmd {
		if d.join("config.json").exists() {
			return Err(Error::Refused(format!("a tower is already set up in {}", d.display())));
		}
		bitcoin::Network::from_str(&network).map_err(|e| Error::Parse(e.to_string()))?;
		for k in &arks {
			bitcoin::secp256k1::PublicKey::from_str(k).map_err(|e| Error::Parse(format!("--ark {}: {}", k, e)))?;
		}
		if bitcoind.is_none() && esplora.is_none() {
			return Err(Error::Refused("name a chain source: --bitcoind or --esplora".into()));
		}
		std::fs::create_dir_all(&d).map_err(|e| Error::Io(e.to_string()))?;
		let c = json!({"network": network, "bitcoind": bitcoind, "bitcoind_cookie": bitcoind_cookie, "bitcoind_user": bitcoind_user,
			"esplora": esplora, "arks": arks, "min_rate": min_rate, "fallback_rate": fallback_rate});
		std::fs::write(d.join("config.json"), serde_json::to_vec_pretty(&c).unwrap()).map_err(|e| Error::Io(e.to_string()))?;
		let cfg = config(&d)?;
		let t = rt.block_on(Tower::open(&d, cfg)).map_err(err)?;
		return Ok(rt.block_on(t.info()));
	}
	let cfg = config(&d)?;
	let mut t = rt.block_on(Tower::open(&d, cfg)).map_err(err)?;
	match cmd {
		BtcTowerCmd::Create { .. } => unreachable!(),
		BtcTowerCmd::Serve { listen, interval } => super::tower::serve_with(&listen, interval, "arca btc-watchtower", |req| {
			let r = match req {
				Some((call, body)) => rt.block_on(t.call(call, body)),
				None => rt.block_on(t.pass()),
			};
			match r {
				Ok(v) => (200, v),
				Err(e) => {
					let m = format!("{:#}", e);
					match m.strip_prefix("refused: ") {
						Some(r) => (422, json!({"error": {"code": "refused", "message": r}})),
						None => (503, json!({"error": {"code": "unavailable", "message": m}})),
					}
				},
			}
		}),
		BtcTowerCmd::Pass => rt.block_on(t.pass()).map_err(err),
		BtcTowerCmd::Deposits => Ok(t.deposits()),
		BtcTowerCmd::Info => Ok(rt.block_on(t.info())),
		BtcTowerCmd::Address => Ok(json!({"address": rt.block_on(t.funding_address()).map_err(err)?.to_string()})),
	}
}
