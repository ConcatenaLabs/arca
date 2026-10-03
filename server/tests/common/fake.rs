//! A chain held in memory, for driving the finality service through cases a
//! live chain will not produce on demand: a block the committee has not
//! certified, a certificate that arrives late, an anchor gone stale, a
//! rollback below where the service started.

use std::collections::HashMap;
use std::sync::Mutex;

use elements::confidential::{Asset, Nonce, Value};
use elements::hashes::{sha256d, Hash};
use elements::{AssetId, BlockHash, LockTime, OutPoint, Script, Transaction, TxIn, TxOut, TxOutWitness, Txid};

use sequentia_ext::BitcoinAnchor;
use server::chain::{AnchorStatus, ChainError, ChainSource, HeaderInfo};

#[derive(Clone)]
pub struct FakeBlock {
	pub header: HeaderInfo,
	pub txs: Vec<Transaction>,
}

pub struct FakeChain {
	inner: Mutex<Inner>,
}

struct Inner {
	blocks: HashMap<BlockHash, FakeBlock>,
	/// The active chain, from genesis.
	active: Vec<BlockHash>,
	mempool: Vec<Transaction>,
	anchor: AnchorStatus,
	/// Whether blocks carry certificates at all.
	committee: bool,
	salt: u64,
	rates: std::collections::BTreeMap<AssetId, u64>,
}

/// A transaction unique to `label`.
pub fn tx(label: &str) -> Transaction {
	let h = sha256d::Hash::hash(label.as_bytes());
	Transaction {
		version: 2,
		lock_time: LockTime::ZERO,
		input: vec![TxIn { previous_output: OutPoint::new(Txid::from_raw_hash(h), 0), ..Default::default() }],
		output: vec![TxOut {
			asset: Asset::Explicit(AssetId::from_slice(&[1; 32]).unwrap()),
			value: Value::Explicit(1_000),
			nonce: Nonce::Null,
			script_pubkey: Script::from(h.to_byte_array()[..4].to_vec()),
			witness: TxOutWitness::default(),
		}],
	}
}

impl FakeChain {
	/// A chain of a genesis block anchored at parent height 100.
	pub fn new(committee: bool) -> FakeChain {
		let mut inner = Inner {
			blocks: HashMap::new(), active: vec![], mempool: vec![],
			anchor: AnchorStatus { validated: true, status: "ok".into() }, committee, salt: 0,
			rates: Default::default(),
		};
		inner.push(None, 100, true, vec![]);
		FakeChain { inner: Mutex::new(inner) }
	}

	/// Appends a block anchored at `anchor`, certified or not, holding `txs`,
	/// on the active tip. Returns its hash.
	pub fn mine(&self, anchor: u32, certified: bool, txs: Vec<Transaction>) -> BlockHash {
		let mut i = self.inner.lock().unwrap();
		let tip = *i.active.last().unwrap();
		let mined: Vec<Txid> = txs.iter().map(|t| t.txid()).collect();
		i.mempool.retain(|t| !mined.contains(&t.txid()));
		i.push(Some(tip), anchor, certified, txs)
	}

	/// Drops the active chain above `height`; its transactions go back to the
	/// mempool, as a node's would.
	pub fn rewind_to(&self, height: u64) {
		let mut i = self.inner.lock().unwrap();
		while i.active.len() as u64 > height + 1 {
			let h = i.active.pop().unwrap();
			let txs = i.blocks[&h].txs.clone();
			i.mempool.extend(txs);
		}
	}

	pub fn certify(&self, hash: &BlockHash) {
		let mut i = self.inner.lock().unwrap();
		i.blocks.get_mut(hash).unwrap().header.certified = Some(true);
	}

	pub fn set_anchor_status(&self, validated: bool, status: &str) {
		self.inner.lock().unwrap().anchor = AnchorStatus { validated, status: status.into() };
	}

	pub fn to_mempool(&self, tx: Transaction) {
		self.inner.lock().unwrap().mempool.push(tx);
	}

	pub fn set_rate(&self, asset: AssetId, rate: u64) {
		self.inner.lock().unwrap().rates.insert(asset, rate);
	}

	pub fn height(&self) -> u64 {
		self.inner.lock().unwrap().active.len() as u64 - 1
	}
}

impl Inner {
	fn push(&mut self, prev: Option<BlockHash>, anchor: u32, certified: bool, txs: Vec<Transaction>) -> BlockHash {
		self.salt += 1;
		let height = self.active.len() as u64;
		let hash = BlockHash::from_raw_hash(sha256d::Hash::hash(format!("fake block {} {}", height, self.salt).as_bytes()));
		let header = HeaderInfo {
			hash, height, prev,
			anchor: BitcoinAnchor { height: anchor, block_hash: BlockHash::from_raw_hash(sha256d::Hash::hash(&anchor.to_le_bytes())) },
			median_time: 1_700_000_000 + height * 60,
			certified: if self.committee { Some(certified) } else { None },
		};
		self.blocks.insert(hash, FakeBlock { header, txs });
		self.active.push(hash);
		hash
	}
}

impl ChainSource for FakeChain {
	fn tip(&self) -> Result<BlockHash, ChainError> {
		Ok(*self.inner.lock().unwrap().active.last().unwrap())
	}

	fn header(&self, hash: &BlockHash) -> Result<HeaderInfo, ChainError> {
		self.inner.lock().unwrap().blocks.get(hash).map(|b| b.header.clone())
			.ok_or_else(|| ChainError::Refused("Block not found".into()))
	}

	fn block_txs(&self, hash: &BlockHash) -> Result<Vec<Transaction>, ChainError> {
		self.inner.lock().unwrap().blocks.get(hash).map(|b| b.txs.clone())
			.ok_or_else(|| ChainError::Refused("Block not found".into()))
	}

	fn tx_block(&self, txid: &Txid) -> Result<Option<BlockHash>, ChainError> {
		let i = self.inner.lock().unwrap();
		Ok(i.active.iter().find(|h| i.blocks[*h].txs.iter().any(|t| t.txid() == *txid)).copied())
	}

	fn anchor_status(&self) -> Result<AnchorStatus, ChainError> {
		Ok(self.inner.lock().unwrap().anchor.clone())
	}

	fn mempool(&self) -> Result<Vec<Txid>, ChainError> {
		Ok(self.inner.lock().unwrap().mempool.iter().map(|t| t.txid()).collect())
	}

	fn transaction(&self, txid: &Txid) -> Result<Option<Transaction>, ChainError> {
		let i = self.inner.lock().unwrap();
		Ok(i.mempool.iter().chain(i.blocks.values().flat_map(|b| b.txs.iter())).find(|t| t.txid() == *txid).cloned())
	}

	fn broadcast(&self, tx: &Transaction) -> Result<Txid, ChainError> {
		let mut i = self.inner.lock().unwrap();
		let txid = tx.txid();
		if !i.mempool.iter().any(|t| t.txid() == txid) {
			i.mempool.push(tx.clone());
		}
		Ok(txid)
	}

	fn genesis(&self) -> Result<BlockHash, ChainError> {
		Ok(self.inner.lock().unwrap().active[0])
	}

	fn fee_rates(&self) -> Result<std::collections::BTreeMap<AssetId, u64>, ChainError> {
		Ok(self.inner.lock().unwrap().rates.clone())
	}

	fn relay_floor_per_kvb(&self) -> Result<u64, ChainError> {
		Ok(1_000)
	}

	fn unspent(&self, outpoint: &OutPoint, mempool: bool) -> Result<Option<u64>, ChainError> {
		let i = self.inner.lock().unwrap();
		let tip = i.active.len() as u64;
		let mut found = None;
		for (h, hash) in i.active.iter().enumerate() {
			for tx in &i.blocks[hash].txs {
				if tx.txid() == outpoint.txid && (outpoint.vout as usize) < tx.output.len() {
					found = Some(tip - h as u64);
				}
			}
		}
		if mempool && found.is_none() && i.mempool.iter().any(|t| t.txid() == outpoint.txid && (outpoint.vout as usize) < t.output.len()) {
			found = Some(0);
		}
		let spent = i.active.iter().flat_map(|h| i.blocks[h].txs.iter())
			.chain(i.mempool.iter().filter(|_| mempool))
			.any(|t| t.input.iter().any(|x| x.previous_output == *outpoint));
		Ok(if spent { None } else { found })
	}

	fn test_accept(&self, _tx: &Transaction) -> Result<(bool, Option<String>, Option<u64>), ChainError> {
		Ok((true, None, None))
	}
}
