//! A blocking JSON-RPC client for `sequentiad`.
//!
//! Blocks, headers and transactions travel as raw bytes and are decoded with
//! Sequentia's encoding, so what the client returns is exactly what the node
//! holds. Calls that have no typed method here go through [`Client::call`].

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;

use base64::Engine;
use elements::encode::{deserialize, serialize};
use elements::hex::{FromHex, ToHex};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value as Json};

use crate::{AssetId, Block, BlockHash, BlockHeader, Transaction, Txid};

/// How the client authenticates to the node.
#[derive(Debug, Clone)]
pub enum Auth {
	/// `-rpcuser` and `-rpcpassword`.
	UserPass(String, String),
	/// The node's cookie file, read on every call so a restarted node's new
	/// cookie is picked up.
	CookieFile(PathBuf),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("cannot reach the node: {0}")]
	Transport(String),
	#[error("cannot read the cookie file: {0}")]
	Cookie(String),
	#[error("the node answered HTTP {status}: {body}")]
	Http { status: i32, body: String },
	#[error("the node's answer is not the expected JSON: {0}")]
	Json(String),
	/// The node ran the call and refused it.
	#[error("RPC error {code}: {message}")]
	Rpc { code: i64, message: String },
	#[error("cannot decode the node's {what}: {error}")]
	Decode { what: &'static str, error: String },
}

/// The part of `getblockchaininfo` the protocol uses.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockchainInfo {
	pub chain: String,
	pub blocks: u64,
	pub headers: u64,
	#[serde(rename = "bestblockhash")]
	pub best_block_hash: BlockHash,
	#[serde(rename = "mediantime")]
	pub median_time: u64,
	#[serde(rename = "initialblockdownload")]
	pub initial_block_download: bool,
}

/// One entry of `testmempoolaccept`.
#[derive(Debug, Clone, Deserialize)]
pub struct MempoolAccept {
	pub txid: Txid,
	pub allowed: bool,
	#[serde(rename = "reject-reason")]
	pub reject_reason: Option<String>,
	pub vsize: Option<u64>,
}

/// The node's fee whitelist: each accepted fee asset and its exchange rate,
/// in reference units per 10^8 atoms of the asset. An asset not listed is not
/// accepted for fees by this node, now; the list changes over time and
/// differs between nodes.
pub type FeeExchangeRates = BTreeMap<AssetId, u64>;

/// A `sequentiad` JSON-RPC client.
#[derive(Debug, Clone)]
pub struct Client {
	url: String,
	auth: Auth,
	timeout_secs: u64,
}

fn decode<T: elements::encode::Decodable>(what: &'static str, hex: &str) -> Result<T, Error> {
	let bytes = Vec::<u8>::from_hex(hex)
		.map_err(|e| Error::Decode { what, error: e.to_string() })?;
	deserialize(&bytes).map_err(|e| Error::Decode { what, error: e.to_string() })
}

impl Client {
	/// A client for the node at `url` (`http://host:port/`).
	pub fn new(url: impl Into<String>, auth: Auth) -> Client {
		Client { url: url.into(), auth, timeout_secs: 120 }
	}

	/// Sets how long one call may take.
	pub fn with_timeout(mut self, secs: u64) -> Client {
		self.timeout_secs = secs;
		self
	}

	fn auth_header(&self) -> Result<String, Error> {
		let cred = match &self.auth {
			Auth::UserPass(u, p) => format!("{}:{}", u, p),
			Auth::CookieFile(path) => std::fs::read_to_string(path)
				.map_err(|e| Error::Cookie(format!("{}: {}", path.display(), e)))?
				.trim().to_string(),
		};
		Ok(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(cred)))
	}

	/// Calls `method` with positional `params`.
	pub fn call<T: DeserializeOwned>(&self, method: &str, params: &[Json]) -> Result<T, Error> {
		let body = json!({"jsonrpc": "1.0", "id": "arca", "method": method, "params": params});
		let resp = minreq::post(&self.url)
			.with_header("Authorization", self.auth_header()?)
			.with_header("Content-Type", "application/json")
			.with_body(body.to_string())
			.with_timeout(self.timeout_secs)
			.send()
			.map_err(|e| Error::Transport(e.to_string()))?;
		let text = resp.as_str().map_err(|e| Error::Json(e.to_string()))?;
		let reply: Json = match serde_json::from_str(text) {
			Ok(v) => v,
			Err(_) => return Err(Error::Http { status: resp.status_code, body: text.to_string() }),
		};
		if !reply["error"].is_null() {
			return Err(Error::Rpc {
				code: reply["error"]["code"].as_i64().unwrap_or(0),
				message: reply["error"]["message"].as_str().unwrap_or("").to_string(),
			});
		}
		serde_json::from_value(reply["result"].clone()).map_err(|e| Error::Json(e.to_string()))
	}

	pub fn blockchain_info(&self) -> Result<BlockchainInfo, Error> {
		self.call("getblockchaininfo", &[])
	}

	pub fn block_count(&self) -> Result<u64, Error> {
		self.call("getblockcount", &[])
	}

	pub fn block_hash(&self, height: u64) -> Result<BlockHash, Error> {
		self.call("getblockhash", &[json!(height)])
	}

	/// The chain's genesis block hash. Sequentia's signature hashes commit to
	/// it, so it identifies the chain a signature is valid on.
	pub fn genesis_hash(&self) -> Result<BlockHash, Error> {
		self.block_hash(0)
	}

	pub fn best_block_hash(&self) -> Result<BlockHash, Error> {
		self.call("getbestblockhash", &[])
	}

	/// The block's serialisation, as the node holds it.
	pub fn block_bytes(&self, hash: &BlockHash) -> Result<Vec<u8>, Error> {
		let hex: String = self.call("getblock", &[json!(hash.to_string()), json!(0)])?;
		Vec::<u8>::from_hex(&hex).map_err(|e| Error::Decode { what: "block", error: e.to_string() })
	}

	pub fn block(&self, hash: &BlockHash) -> Result<Block, Error> {
		let hex: String = self.call("getblock", &[json!(hash.to_string()), json!(0)])?;
		decode("block", &hex)
	}

	pub fn block_header(&self, hash: &BlockHash) -> Result<BlockHeader, Error> {
		let hex: String = self.call("getblockheader", &[json!(hash.to_string()), json!(false)])?;
		decode("block header", &hex)
	}

	/// The transaction's serialisation. Needs `-txindex` unless the
	/// transaction is in the mempool.
	pub fn raw_transaction_bytes(&self, txid: &Txid) -> Result<Vec<u8>, Error> {
		let hex: String = self.call("getrawtransaction", &[json!(txid.to_string())])?;
		Vec::<u8>::from_hex(&hex).map_err(|e| Error::Decode { what: "transaction", error: e.to_string() })
	}

	pub fn raw_transaction(&self, txid: &Txid) -> Result<Transaction, Error> {
		let hex: String = self.call("getrawtransaction", &[json!(txid.to_string())])?;
		decode("transaction", &hex)
	}

	/// The number of confirmations of a transaction, 0 while in the mempool.
	pub fn confirmations(&self, txid: &Txid) -> Result<u64, Error> {
		let v: Json = self.call("getrawtransaction", &[json!(txid.to_string()), json!(true)])?;
		Ok(v["confirmations"].as_u64().unwrap_or(0))
	}

	pub fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, Error> {
		self.call("sendrawtransaction", &[json!(serialize(tx).to_hex())])
	}

	pub fn test_mempool_accept(&self, txs: &[&Transaction]) -> Result<Vec<MempoolAccept>, Error> {
		let hexes: Vec<String> = txs.iter().map(|tx| serialize(*tx).to_hex()).collect();
		self.call("testmempoolaccept", &[json!(hexes)])
	}

	/// The node's asset labels (`dumpassetlabels`).
	pub fn asset_labels(&self) -> Result<BTreeMap<String, AssetId>, Error> {
		self.call("dumpassetlabels", &[])
	}

	/// The node's fee whitelist (`getfeeexchangerates`), keyed by asset id. The
	/// node names a labelled asset by its label; this resolves it.
	pub fn fee_exchange_rates(&self) -> Result<FeeExchangeRates, Error> {
		let rates: BTreeMap<String, u64> = self.call("getfeeexchangerates", &[])?;
		let labels = self.asset_labels()?;
		rates.into_iter().map(|(name, rate)| {
			let asset = match labels.get(&name) {
				Some(a) => *a,
				None => AssetId::from_str(&name).map_err(|e| Error::Decode {
					what: "fee whitelist asset", error: format!("{}: {}", name, e),
				})?,
			};
			Ok((asset, rate))
		}).collect()
	}

	/// Mines `n` blocks paying the coinbase to `descriptor` (regtest).
	pub fn generate_to_descriptor(&self, n: u64, descriptor: &str) -> Result<Vec<BlockHash>, Error> {
		self.call("generatetodescriptor", &[json!(n), json!(descriptor)])
	}

	/// Mines one block holding exactly `txs`, without the mempool (regtest).
	/// A transaction that breaks a consensus rule makes the call fail.
	pub fn generate_block(&self, output: &str, txs: &[&Transaction]) -> Result<BlockHash, Error> {
		let hexes: Vec<String> = txs.iter().map(|tx| serialize(*tx).to_hex()).collect();
		let v: Json = self.call("generateblock", &[json!(output), json!(hexes)])?;
		serde_json::from_value(v["hash"].clone()).map_err(|e| Error::Json(e.to_string()))
	}
}
