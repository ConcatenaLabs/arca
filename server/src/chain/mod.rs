//! The chain: what the server asks the node, and the finality service that
//! follows it.
//!
//! [`ChainSource`] is everything the server reads from or sends to the chain,
//! answered by a `sequentiad` ([`NodeSource`]). [`finality::FinalityService`]
//! follows the node's active chain into the database, scans each block for
//! what the server watches, and is the one answer to "is this final".

use std::collections::BTreeMap;
use std::str::FromStr;

use elements::hashes::Hash;
use elements::{AssetId, BlockHash, OutPoint, Transaction, Txid};
use serde_json::{json, Value};

use sequentia_ext::rpc::{Client, Error as RpcError};
use sequentia_ext::{BitcoinAnchor, BlockHeaderExt};

pub mod finality;

pub use finality::{Certification, ChainEvent, Finality, FinalityConfig, FinalityService};

/// Why the chain could not be read or did not accept something.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ChainError {
	#[error("the node: {0}")]
	Node(String),
	/// The node refused a transaction or a call, with its reason.
	#[error("the node refused it: {0}")]
	Refused(String),
	#[error("the node's answer is not what was expected: {0}")]
	Answer(String),
}

impl From<RpcError> for ChainError {
	fn from(e: RpcError) -> ChainError {
		match e {
			RpcError::Rpc { message, .. } => ChainError::Refused(message),
			other => ChainError::Node(other.to_string()),
		}
	}
}

/// What the finality service needs to know of one block header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderInfo {
	pub hash: BlockHash,
	pub height: u64,
	/// `None` for the genesis block.
	pub prev: Option<BlockHash>,
	/// The Bitcoin block the header commits to.
	pub anchor: BitcoinAnchor,
	pub median_time: u64,
	/// Whether the committee certified the block; `None` on a chain with no
	/// committee.
	pub certified: Option<bool>,
}

/// The node's check of its tip's anchor against the parent chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorStatus {
	/// Whether the node validates anchors against the parent chain at all.
	pub validated: bool,
	/// `ok` when the tip's anchor is in the parent's active chain; otherwise
	/// the node's word for what is wrong (`stale`, `not_found`, ...).
	pub status: String,
}

impl AnchorStatus {
	pub fn ok(&self) -> bool {
		self.validated && self.status == "ok"
	}
}

/// Everything the server reads from, or sends to, the chain. Calls block; the
/// async code runs them on the blocking pool.
pub trait ChainSource: Send + Sync + 'static {
	/// The node's active tip.
	fn tip(&self) -> Result<BlockHash, ChainError>;
	fn header(&self, hash: &BlockHash) -> Result<HeaderInfo, ChainError>;
	/// The block's transactions, in order.
	fn block_txs(&self, hash: &BlockHash) -> Result<Vec<Transaction>, ChainError>;
	/// The block the node says holds `txid`, if any. The caller checks it
	/// against the chain it follows.
	fn tx_block(&self, txid: &Txid) -> Result<Option<BlockHash>, ChainError>;
	fn anchor_status(&self) -> Result<AnchorStatus, ChainError>;
	/// The txids in the node's mempool.
	fn mempool(&self) -> Result<Vec<Txid>, ChainError>;
	/// A transaction from the mempool or the chain, if the node has it.
	fn transaction(&self, txid: &Txid) -> Result<Option<Transaction>, ChainError>;
	/// Broadcasts `tx`. A transaction the node already holds is not an error.
	fn broadcast(&self, tx: &Transaction) -> Result<Txid, ChainError>;
	/// The chain's genesis block hash.
	fn genesis(&self) -> Result<BlockHash, ChainError>;
	/// The node's fee whitelist, now: each accepted fee asset and its rate, in
	/// reference units per 10^8 atoms of the asset. An asset not listed is not
	/// accepted for fees by this node.
	fn fee_rates(&self) -> Result<BTreeMap<AssetId, u64>, ChainError>;
	/// The node's relay floor, in reference units per 1,000 vbytes.
	fn relay_floor_per_kvb(&self) -> Result<u64, ChainError>;
	/// Whether the node would accept `tx` into its mempool now, and if not,
	/// why; and its virtual size.
	fn test_accept(&self, tx: &Transaction) -> Result<(bool, Option<String>, Option<u64>), ChainError>;
	/// Whether `outpoint` is an unspent output of the active chain, or, with
	/// `mempool`, of the mempool and spent by nothing in it: its
	/// confirmations (0 in the mempool), or `None` when it is spent or does
	/// not exist.
	fn unspent(&self, outpoint: &OutPoint, mempool: bool) -> Result<Option<u64>, ChainError>;
}

/// A `sequentiad` reached over JSON-RPC. It must run with `-txindex`, and with
/// `-validateanchor`: a node that does not check its anchors has no notion of
/// finality.
pub struct NodeSource {
	client: Client,
}

impl NodeSource {
	pub fn new(client: Client) -> NodeSource {
		NodeSource { client }
	}

	pub fn client(&self) -> &Client {
		&self.client
	}
}

/// Whether a node's error message means "no such transaction".
fn is_not_found(e: &RpcError) -> bool {
	matches!(e, RpcError::Rpc { code: -5, .. })
}

impl ChainSource for NodeSource {
	fn tip(&self) -> Result<BlockHash, ChainError> {
		Ok(self.client.best_block_hash()?)
	}

	fn header(&self, hash: &BlockHash) -> Result<HeaderInfo, ChainError> {
		let raw = self.client.block_header(hash)?;
		let v: Value = self.client.call("getblockheader", &[json!(hash.to_string()), json!(true)])?;
		let height = v["height"].as_u64().ok_or_else(|| ChainError::Answer(format!("no height in header {}", hash)))?;
		let prev = match v["previousblockhash"].as_str() {
			Some(s) => Some(BlockHash::from_str(s).map_err(|e| ChainError::Answer(e.to_string()))?),
			None => None,
		};
		let median_time = v["mediantime"].as_u64().ok_or_else(|| ChainError::Answer("no median time".into()))?;
		Ok(HeaderInfo {
			hash: *hash, height, prev, anchor: raw.bitcoin_anchor(), median_time,
			certified: v["poscertified"].as_bool(),
		})
	}

	fn block_txs(&self, hash: &BlockHash) -> Result<Vec<Transaction>, ChainError> {
		Ok(self.client.block(hash)?.txdata)
	}

	fn tx_block(&self, txid: &Txid) -> Result<Option<BlockHash>, ChainError> {
		match self.client.call::<Value>("getrawtransaction", &[json!(txid.to_string()), json!(true)]) {
			Ok(v) => match v["blockhash"].as_str() {
				Some(s) => Ok(Some(BlockHash::from_str(s).map_err(|e| ChainError::Answer(e.to_string()))?)),
				None => Ok(None),
			},
			Err(e) if is_not_found(&e) => Ok(None),
			Err(e) => Err(e.into()),
		}
	}

	fn anchor_status(&self) -> Result<AnchorStatus, ChainError> {
		let v: Value = self.client.call("getanchorstatus", &[])?;
		Ok(AnchorStatus {
			validated: v["validateanchor"].as_bool().unwrap_or(false),
			status: v["anchorstatus"].as_str().unwrap_or("").to_string(),
		})
	}

	fn mempool(&self) -> Result<Vec<Txid>, ChainError> {
		let ids: Vec<String> = self.client.call("getrawmempool", &[])?;
		ids.iter().map(|s| Txid::from_str(s).map_err(|e| ChainError::Answer(e.to_string()))).collect()
	}

	fn transaction(&self, txid: &Txid) -> Result<Option<Transaction>, ChainError> {
		match self.client.raw_transaction(txid) {
			Ok(tx) => Ok(Some(tx)),
			Err(e) if is_not_found(&e) => Ok(None),
			Err(e) => Err(e.into()),
		}
	}

	fn broadcast(&self, tx: &Transaction) -> Result<Txid, ChainError> {
		match self.client.send_raw_transaction(tx) {
			Ok(txid) => Ok(txid),
			// Already in the mempool, or already confirmed: the transaction
			// is where broadcasting would put it.
			Err(RpcError::Rpc { message, .. }) if message.contains("txn-already-in-mempool")
				|| message.contains("txn-already-known")
				|| message.contains("already in utxo set")
				|| message.contains("already in block chain") => Ok(tx.txid()),
			Err(e) => Err(e.into()),
		}
	}

	fn genesis(&self) -> Result<BlockHash, ChainError> {
		Ok(self.client.genesis_hash()?)
	}

	fn fee_rates(&self) -> Result<BTreeMap<AssetId, u64>, ChainError> {
		Ok(self.client.fee_exchange_rates()?)
	}

	fn relay_floor_per_kvb(&self) -> Result<u64, ChainError> {
		// The node reports it in whole reference units per kvB, as a decimal.
		let v: Value = self.client.call("getmempoolinfo", &[])?;
		let units = v["minrelaytxfee"].as_f64().ok_or_else(|| ChainError::Answer("no minrelaytxfee".into()))?;
		Ok((units * 100_000_000.0).round() as u64)
	}

	fn test_accept(&self, tx: &Transaction) -> Result<(bool, Option<String>, Option<u64>), ChainError> {
		let r = self.client.test_mempool_accept(&[tx])?.into_iter().next()
			.ok_or_else(|| ChainError::Answer("testmempoolaccept returned nothing".into()))?;
		Ok((r.allowed, r.reject_reason, r.vsize))
	}

	fn unspent(&self, outpoint: &OutPoint, mempool: bool) -> Result<Option<u64>, ChainError> {
		let v: Value = self.client.call("gettxout", &[json!(outpoint.txid.to_string()), json!(outpoint.vout), json!(mempool)])?;
		if v.is_null() {
			return Ok(None);
		}
		Ok(Some(v["confirmations"].as_u64().ok_or_else(|| ChainError::Answer("gettxout gave no confirmations".into()))?))
	}
}

/// A block hash, or a txid, as the database stores it: internal byte order.
pub fn hash_bytes<H: Hash<Bytes = [u8; 32]>>(h: &H) -> [u8; 32] {
	h.to_byte_array()
}
