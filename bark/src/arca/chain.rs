//! The wallet's chain source: a `sequentiad` reached over JSON-RPC.
//!
//! The wallet never counts confirmations. A transaction it relies on (a round,
//! a board) is **final** when its block is in the node's active chain,
//! certified by the committee (the node reports the certificate for that block
//! or for one above it), and its Bitcoin anchor is buried: the anchor height of
//! the tip less the block's is at least the anchor depth (2), while the node
//! reports its tip's anchor as validated and `ok`. That is the server's rule
//! and SeqLN's. Sequentia reorganises whenever its anchor does, with no depth
//! limit, so finality is asked again every time it matters, never remembered.
//!
//! The node must run with `-txindex`, so the wallet can fetch any transaction
//! by its id, and with `-validateanchor`, without which it has no notion of
//! finality.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use elements::{AssetId, BlockHash, OutPoint, Script, Transaction, TxOut, Txid};
use serde_json::{json, Value};

use sequentia_ext::rpc::{Auth, Client, Error as RpcError};
use sequentia_ext::BlockHeaderExt;

use super::Error;

/// The Bitcoin blocks that bury a final block's anchor.
pub const ANCHOR_DEPTH: u64 = 2;

/// How far above a block the wallet looks for a committee certificate.
const CERT_LOOKAHEAD: u64 = 200;

/// Where a transaction stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finality {
	/// Not in a block of the active chain (perhaps in the mempool).
	NotInChain { in_mempool: bool },
	/// In a block the committee has not certified.
	Unsettled { height: u64 },
	/// In a certified block, its anchor buried fewer than [`ANCHOR_DEPTH`]
	/// Bitcoin blocks.
	Settled { height: u64, depth: u64 },
	/// Certified, and its anchor buried.
	Final { height: u64, depth: u64 },
}

impl Finality {
	pub fn is_final(&self) -> bool {
		matches!(self, Finality::Final { .. })
	}

	pub fn in_chain(&self) -> bool {
		!matches!(self, Finality::NotInChain { .. })
	}

	pub fn height(&self) -> Option<u64> {
		match self {
			Finality::NotInChain { .. } => None,
			Finality::Unsettled { height } | Finality::Settled { height, .. } | Finality::Final { height, .. } => Some(*height),
		}
	}

	/// One word for people.
	pub fn word(&self) -> &'static str {
		match self {
			Finality::NotInChain { in_mempool: true } => "in_mempool",
			Finality::NotInChain { in_mempool: false } => "not_in_chain",
			Finality::Unsettled { .. } => "unsettled",
			Finality::Settled { .. } => "settled",
			Finality::Final { .. } => "final",
		}
	}
}

/// The tip of the active chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tip {
	pub height: u64,
	pub hash: BlockHash,
	pub median_time: u32,
}

/// The node.
#[derive(Debug, Clone)]
pub struct ChainSource {
	client: Client,
}

fn node(e: RpcError) -> Error {
	Error::Node(e.to_string())
}

fn not_found(e: &RpcError) -> bool {
	matches!(e, RpcError::Rpc { code: -5, .. } | RpcError::Rpc { code: -8, .. })
}

impl ChainSource {
	/// The node at `url`, authenticated with `user` and `password`, or with
	/// its cookie file when `cookie` is given.
	pub fn new(url: &str, user: Option<&str>, password: Option<&str>, cookie: Option<&str>) -> ChainSource {
		let auth = match (cookie, user, password) {
			(Some(c), _, _) => Auth::CookieFile(c.into()),
			(None, Some(u), Some(p)) => Auth::UserPass(u.into(), p.into()),
			(None, Some(u), None) => Auth::UserPass(u.into(), String::new()),
			(None, None, _) => Auth::UserPass(String::new(), String::new()),
		};
		ChainSource { client: Client::new(url, auth).with_timeout(60) }
	}

	pub fn client(&self) -> &Client {
		&self.client
	}

	pub fn genesis(&self) -> Result<BlockHash, Error> {
		self.client.genesis_hash().map_err(node)
	}

	/// The node's chain name (`test`, `sequentia`, `elementsregtest`, …).
	pub fn chain_name(&self) -> Result<String, Error> {
		Ok(self.client.blockchain_info().map_err(node)?.chain)
	}

	pub fn tip(&self) -> Result<Tip, Error> {
		let info = self.client.blockchain_info().map_err(node)?;
		Ok(Tip { height: info.blocks, hash: info.best_block_hash, median_time: info.median_time as u32 })
	}

	/// The hash of the active chain's block at `height`, if the chain is that
	/// long.
	pub fn block_hash(&self, height: u64) -> Result<Option<BlockHash>, Error> {
		match self.client.block_hash(height) {
			Ok(h) => Ok(Some(h)),
			Err(e) if not_found(&e) => Ok(None),
			Err(e) => Err(node(e)),
		}
	}

	/// A transaction from the chain or the mempool, if the node has it.
	pub fn transaction(&self, txid: &Txid) -> Result<Option<Transaction>, Error> {
		match self.client.raw_transaction(txid) {
			Ok(tx) => Ok(Some(tx)),
			Err(e) if not_found(&e) => Ok(None),
			Err(e) => Err(node(e)),
		}
	}

	/// The median time of the active chain's block at `height`.
	pub fn median_time_at(&self, height: u64) -> Result<Option<u32>, Error> {
		let Some(hash) = self.block_hash(height)? else { return Ok(None) };
		let v: Value = self.client.call("getblockheader", &[json!(hash.to_string()), json!(true)]).map_err(node)?;
		Ok(v["mediantime"].as_u64().map(|t| t.min(u32::MAX as u64) as u32))
	}

	/// Whether `txid` is in a block of the active chain, and whether it is in
	/// the mempool: a cheap look, without the finality of the block.
	pub fn whereabouts(&self, txid: &Txid) -> Result<(bool, bool), Error> {
		if self.tx_block(txid)?.is_some() {
			return Ok((true, false));
		}
		Ok((false, self.in_mempool(txid)?))
	}

	fn in_mempool(&self, txid: &Txid) -> Result<bool, Error> {
		match self.client.call::<Value>("getmempoolentry", &[json!(txid.to_string())]) {
			Ok(_) => Ok(true),
			Err(e) if not_found(&e) => Ok(false),
			Err(e) => Err(node(e)),
		}
	}

	/// The active-chain block holding `txid`, and its height.
	fn tx_block(&self, txid: &Txid) -> Result<Option<(BlockHash, u64)>, Error> {
		let v: Value = match self.client.call("getrawtransaction", &[json!(txid.to_string()), json!(true)]) {
			Ok(v) => v,
			Err(e) if not_found(&e) => return Ok(None),
			Err(e) => return Err(node(e)),
		};
		let Some(hash) = v["blockhash"].as_str() else { return Ok(None) };
		let hash = BlockHash::from_str(hash).map_err(|e| Error::Node(e.to_string()))?;
		let h: Value = self.client.call("getblockheader", &[json!(hash.to_string()), json!(true)]).map_err(node)?;
		// A block the node holds off its active chain reports -1.
		if h["confirmations"].as_i64().unwrap_or(-1) < 1 {
			return Ok(None);
		}
		Ok(Some((hash, h["height"].as_u64().unwrap_or(0))))
	}

	fn header(&self, hash: &BlockHash) -> Result<(u64, Option<bool>), Error> {
		let raw = self.client.block_header(hash).map_err(node)?;
		let v: Value = self.client.call("getblockheader", &[json!(hash.to_string()), json!(true)]).map_err(node)?;
		Ok((raw.bitcoin_anchor().height as u64, v["poscertified"].as_bool()))
	}

	/// Where `txid` stands now. See the [module documentation](self).
	pub fn finality(&self, txid: &Txid) -> Result<Finality, Error> {
		let Some((block, height)) = self.tx_block(txid)? else {
			return Ok(Finality::NotInChain { in_mempool: self.in_mempool(txid)? });
		};
		let tip = self.tip()?;
		let (anchor, certified) = self.header(&block)?;
		// A chain without a committee reports no certificate at all; on a
		// committee chain a block is certified when it or a block above it is.
		let certified = match certified {
			None => true,
			Some(true) => true,
			Some(false) => {
				let mut found = false;
				let top = tip.height.min(height + CERT_LOOKAHEAD);
				for h in (height + 1)..=top {
					let Some(hash) = self.block_hash(h)? else { break };
					if self.header(&hash)?.1 == Some(true) {
						found = true;
						break;
					}
				}
				found
			},
		};
		if !certified {
			return Ok(Finality::Unsettled { height });
		}
		let (tip_anchor, _) = self.header(&tip.hash)?;
		let depth = tip_anchor.saturating_sub(anchor);
		let anchor_ok = {
			let v: Value = self.client.call("getanchorstatus", &[]).map_err(node)?;
			v["validateanchor"].as_bool().unwrap_or(false) && v["anchorstatus"].as_str() == Some("ok")
		};
		if depth >= ANCHOR_DEPTH && anchor_ok {
			Ok(Finality::Final { height, depth })
		} else {
			Ok(Finality::Settled { height, depth })
		}
	}

	/// Whether the node validates its anchors against the parent chain.
	pub fn validates_anchors(&self) -> Result<bool, Error> {
		let v: Value = self.client.call("getanchorstatus", &[]).map_err(node)?;
		Ok(v["validateanchor"].as_bool().unwrap_or(false))
	}

	/// Broadcasts `tx`. One the node already holds is not an error.
	pub fn broadcast(&self, tx: &Transaction) -> Result<Txid, Error> {
		match self.client.send_raw_transaction(tx) {
			Ok(txid) => Ok(txid),
			Err(RpcError::Rpc { message, .. }) if message.contains("txn-already-in-mempool")
				|| message.contains("txn-already-known")
				|| message.contains("already in utxo set")
				|| message.contains("already in block chain") => Ok(tx.txid()),
			Err(RpcError::Rpc { message, .. }) => Err(Error::Refused(format!("the node refused {}: {}", tx.txid(), message))),
			Err(e) => Err(node(e)),
		}
	}

	/// The node's fee whitelist now: each accepted fee asset and its rate.
	pub fn fee_rates(&self) -> Result<BTreeMap<AssetId, u64>, Error> {
		self.client.fee_exchange_rates().map_err(node)
	}

	/// The node's relay floor in `asset`'s own atoms per 1,000 vbytes, now;
	/// `None` when the node does not accept `asset` for fees.
	pub fn floor_per_kvb(&self, asset: AssetId) -> Result<Option<u64>, Error> {
		let rates = self.fee_rates()?;
		let rate = match rates.get(&asset) {
			Some(r) if *r > 0 => *r as u128,
			_ => return Ok(None),
		};
		let v: Value = self.client.call("getmempoolinfo", &[]).map_err(node)?;
		let units = v["minrelaytxfee"].as_f64().ok_or_else(|| Error::Node("no minrelaytxfee".into()))?;
		let floor = (units * 100_000_000.0).round() as u128;
		// The node values a atoms at a × rate / 10^8 reference units.
		Ok(Some((floor * 100_000_000).div_ceil(rate).max(1).min(u64::MAX as u128) as u64))
	}

	/// Whether `outpoint` is unspent, the mempool's spends included.
	pub fn unspent(&self, outpoint: &OutPoint) -> Result<bool, Error> {
		let v: Value = self.client.call("gettxout", &[json!(outpoint.txid.to_string()), json!(outpoint.vout), json!(true)])
			.map_err(node)?;
		Ok(!v.is_null())
	}

	/// The unspent outputs of the active chain paying any of `scripts`, each
	/// with its height, read from the node's UTXO set.
	pub fn coins_at(&self, scripts: &[Script]) -> Result<Vec<(OutPoint, TxOut, u64)>, Error> {
		if scripts.is_empty() {
			return Ok(vec![]);
		}
		let descs: Vec<Value> = scripts.iter().map(|s| json!(format!("raw({})", hex(s.as_bytes())))).collect();
		let v: Value = self.client.call("scantxoutset", &[json!("start"), Value::Array(descs)]).map_err(node)?;
		let mut out = vec![];
		for u in v["unspents"].as_array().cloned().unwrap_or_default() {
			let txid = Txid::from_str(u["txid"].as_str().unwrap_or("")).map_err(|e| Error::Node(e.to_string()))?;
			let vout = u["vout"].as_u64().unwrap_or(0) as u32;
			let Some(tx) = self.transaction(&txid)? else { continue };
			let Some(o) = tx.output.get(vout as usize) else { continue };
			out.push((OutPoint::new(txid, vout), o.clone(), u["height"].as_u64().unwrap_or(0)));
		}
		Ok(out)
	}

	/// Where each of `outputs` is now: an output equal to it (asset, value and
	/// script) that is unspent in the active chain's set of unspent outputs or
	/// made by a transaction in the mempool, and spent by nothing in the
	/// mempool; `None` where there is none. Outputs are found by script, so
	/// one paying the script another amount is not taken for it.
	pub fn locate(&self, outputs: &[TxOut]) -> Result<Vec<Option<OutPoint>>, Error> {
		let mut found: Vec<Option<OutPoint>> = vec![None; outputs.len()];
		if outputs.is_empty() {
			return Ok(found);
		}
		let mut scripts: Vec<Script> = outputs.iter().map(|o| o.script_pubkey.clone()).collect();
		scripts.sort();
		scripts.dedup();
		for (op, o, _) in self.coins_at(&scripts)? {
			if let Some(i) = outputs.iter().enumerate().position(|(i, w)| *w == o && found[i].is_none()) {
				if self.unspent(&op)? {
					found[i] = Some(op);
				}
			}
		}
		let ids: Vec<String> = self.client.call("getrawmempool", &[]).map_err(node)?;
		for id in ids {
			let txid = Txid::from_str(&id).map_err(|e| Error::Node(e.to_string()))?;
			let Some(tx) = self.transaction(&txid)? else { continue };
			for (j, o) in tx.output.iter().enumerate() {
				if let Some(i) = outputs.iter().enumerate().position(|(i, w)| w == o && found[i].is_none()) {
					let op = OutPoint::new(txid, j as u32);
					if self.unspent(&op)? {
						found[i] = Some(op);
					}
				}
			}
		}
		Ok(found)
	}

	/// Which of `scripts` an output of the active chain from `from_height` up,
	/// or of the mempool, pays: the index of the chain the lineage check asks.
	pub fn scripts_seen(&self, scripts: &BTreeSet<Script>, from_height: u64) -> Result<BTreeSet<Script>, Error> {
		let mut seen = BTreeSet::new();
		if scripts.is_empty() {
			return Ok(seen);
		}
		let tip = self.tip()?;
		let mut look = |tx: &Transaction| {
			for o in &tx.output {
				if scripts.contains(&o.script_pubkey) {
					seen.insert(o.script_pubkey.clone());
				}
			}
		};
		for h in from_height..=tip.height {
			let Some(hash) = self.block_hash(h)? else { break };
			for tx in self.client.block(&hash).map_err(node)?.txdata {
				look(&tx);
			}
		}
		let ids: Vec<String> = self.client.call("getrawmempool", &[]).map_err(node)?;
		for id in ids {
			let txid = Txid::from_str(&id).map_err(|e| Error::Node(e.to_string()))?;
			if let Some(tx) = self.transaction(&txid)? {
				look(&tx);
			}
		}
		Ok(seen)
	}

	/// The first transaction of the active chain from `from_height` up that
	/// pays `output` (asset, value and script), if any: what a wallet re-checks
	/// a leaf against when its round is gone.
	pub fn find_payment(&self, output: &TxOut, from_height: u64) -> Result<Option<(Transaction, u64)>, Error> {
		let tip = self.tip()?;
		for h in from_height..=tip.height {
			let Some(hash) = self.block_hash(h)? else { break };
			for tx in self.client.block(&hash).map_err(node)?.txdata {
				if tx.output.iter().any(|o| o == output) {
					return Ok(Some((tx, h)));
				}
			}
		}
		Ok(None)
	}

	/// The transaction that spends `outpoint`, in the mempool or in a block
	/// of the active chain from `from_height` up, and its height (`None` for
	/// the mempool).
	pub fn spender(&self, outpoint: &OutPoint, from_height: u64) -> Result<Option<(Transaction, Option<u64>)>, Error> {
		let spends = |tx: &Transaction| tx.input.iter().any(|i| i.previous_output == *outpoint);
		let ids: Vec<String> = self.client.call("getrawmempool", &[]).map_err(node)?;
		for id in ids {
			let txid = Txid::from_str(&id).map_err(|e| Error::Node(e.to_string()))?;
			if let Some(tx) = self.transaction(&txid)? {
				if spends(&tx) {
					return Ok(Some((tx, None)));
				}
			}
		}
		let tip = self.tip()?;
		for h in from_height..=tip.height {
			let Some(hash) = self.block_hash(h)? else { break };
			for tx in self.client.block(&hash).map_err(node)?.txdata {
				if spends(&tx) {
					return Ok(Some((tx, Some(h))));
				}
			}
		}
		Ok(None)
	}

	/// Whether `tx` can never return to the chain: it is in no block of the
	/// active chain and not in the mempool, and one of the coins it spends is
	/// spent by another transaction that is final. One that is merely out of
	/// the chain, its coins unspent or spent only in blocks not yet final,
	/// can still return.
	pub fn gone(&self, tx: &Transaction) -> Result<bool, Error> {
		if self.whereabouts(&tx.txid())? != (false, false) {
			return Ok(false);
		}
		for i in &tx.input {
			let op = i.previous_output;
			let Some((_, height)) = self.tx_block(&op.txid)? else { continue };
			let v: Value = self.client.call("gettxout", &[json!(op.txid.to_string()), json!(op.vout), json!(false)]).map_err(node)?;
			if !v.is_null() {
				continue;
			}
			if let Some((other, Some(_))) = self.spender(&op, height)? {
				if other.txid() != tx.txid() && self.finality(&other.txid())?.is_final() {
					return Ok(true);
				}
			}
		}
		Ok(false)
	}

	/// The node's address for `script`, unblinded, on its own chain.
	pub fn address(&self, script: &Script) -> Result<Option<String>, Error> {
		let v: Value = self.client.call("decodescript", &[json!(hex(script.as_bytes()))]).map_err(node)?;
		Ok(v["address"].as_str().or_else(|| v["segwit"]["address"].as_str()).map(|s| s.to_string()))
	}
}

/// Lower-case hex.
pub fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Bytes from hex.
pub fn unhex(s: &str) -> Result<Vec<u8>, Error> {
	if s.len() % 2 != 0 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
		return Err(Error::Parse(format!("not hex: {}", s)));
	}
	Ok((0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("checked")).collect())
}

/// 32 bytes from hex.
pub fn unhex32(s: &str) -> Result<[u8; 32], Error> {
	unhex(s)?.try_into().map_err(|_| Error::Parse(format!("not 32 bytes: {}", s)))
}
