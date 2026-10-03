//! The finality service: the server's one answer to "is this final".
//!
//! Sequentia reorganises whenever its Bitcoin anchor does, with no depth
//! limit, so nothing in the server counts confirmations or does height
//! arithmetic of its own. It asks this service, which follows the node's
//! active chain block by block into the database and answers, for any
//! transaction it was asked to watch, one of [`Finality`]:
//!
//! - not in the active chain;
//! - in a block the committee has not certified;
//! - settled: in a certified block, its anchor not yet buried enough;
//! - final: certified, and its anchor buried `anchor_depth` Bitcoin blocks.
//!
//! A block is certified when the node reports the committee's certificate for
//! it, or for a block above it: a certified block cannot be left without
//! leaving its ancestors. The anchor's burial is counted as SeqLN counts it:
//! the anchor height of the tip less the anchor height of the block. The node
//! must validate its anchors against the parent chain (`-validateanchor`), and
//! nothing becomes final while it reports its tip's anchor as anything but
//! `ok`.
//!
//! Each pass connects new blocks in order and disconnects, tip first, every
//! block the node's chain no longer holds, however deep. Each change is
//! published as a [`ChainEvent`]: a disconnection names every watched
//! transaction the block held, so whatever relied on one can check again, and
//! a pass ends with [`ChainEvent::Synced`], after which finality may have
//! advanced. A subscriber that falls behind the channel's capacity is told it
//! lagged and checks everything it relies on.
//!
//! Each pass also scans every new block, and the mempool, for outputs paying
//! an Arca script the server knows and for spends of the outpoints it
//! watches, recording each sighting for good.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use elements::hashes::Hash;
use elements::{BlockHash, Txid};
use tokio::sync::{broadcast, Mutex};

use super::{ChainError, ChainSource, HeaderInfo};
use crate::store::{BlockRow, Scan, Store, StoreError};

/// Whether the chain's blocks carry a committee's certificate, and so whether
/// finality waits for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Certification {
	/// Every live Sequentia chain: a block is settled once certified.
	Required,
	/// A chain without a committee (a custom test chain): only the anchor
	/// decides. The service refuses this on a chain whose node reports
	/// certificates.
	NotOnThisChain,
}

#[derive(Debug, Clone)]
pub struct FinalityConfig {
	/// The Bitcoin blocks that must bury a block's anchor for it to be final.
	/// The specification's value is 2.
	pub anchor_depth: u32,
	pub certification: Certification,
	/// The height to start following from on an empty database; the node's
	/// tip when `None`.
	pub start_height: Option<u64>,
	/// How often the service looks at the node.
	pub poll_interval: Duration,
	/// How far below the tip a block not yet certified is asked about again.
	pub cert_lookback: u64,
}

impl FinalityConfig {
	/// The specification's rule: certified, and the anchor buried two Bitcoin
	/// blocks.
	pub fn spec() -> FinalityConfig {
		FinalityConfig {
			anchor_depth: 2,
			certification: Certification::Required,
			start_height: None,
			poll_interval: Duration::from_secs(1),
			cert_lookback: 144,
		}
	}
}

/// Where a transaction stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finality {
	/// Not in a block of the active chain.
	NotInChain,
	/// In a block the committee has not certified.
	Unsettled { height: u64, block: BlockHash },
	/// In a certified block whose anchor is buried `depth` Bitcoin blocks,
	/// fewer than the rule asks.
	Settled { height: u64, block: BlockHash, depth: u64 },
	/// Certified, and its anchor buried `depth` Bitcoin blocks, at least the
	/// rule's.
	Final { height: u64, block: BlockHash, depth: u64 },
}

impl Finality {
	pub fn is_final(&self) -> bool {
		matches!(self, Finality::Final { .. })
	}

	pub fn in_chain(&self) -> bool {
		!matches!(self, Finality::NotInChain)
	}

	/// A short name for the state.
	pub fn name(&self) -> &'static str {
		match self {
			Finality::NotInChain => "not_in_chain",
			Finality::Unsettled { .. } => "unsettled",
			Finality::Settled { .. } => "settled",
			Finality::Final { .. } => "final",
		}
	}
}

/// A change to the active chain, as the service saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainEvent {
	/// A block joined the active chain.
	Connected { height: u64, hash: BlockHash },
	/// A block left the active chain. `watched` lists every watched
	/// transaction it held, with what it was watched for: each is no longer in
	/// the chain, and anything that relied on it is checked again.
	Disconnected { height: u64, hash: BlockHash, watched: Vec<(Txid, String)> },
	/// A pass is complete and the service is at the node's tip.
	Synced { height: u64, hash: BlockHash },
}

#[derive(Debug, thiserror::Error)]
pub enum FinalityError {
	#[error(transparent)]
	Store(#[from] StoreError),
	#[error(transparent)]
	Chain(#[from] ChainError),
	#[error("{0}")]
	Config(String),
}

/// See the [module documentation](self).
pub struct FinalityService {
	store: Store,
	source: Arc<dyn ChainSource>,
	config: FinalityConfig,
	events: broadcast::Sender<ChainEvent>,
	/// Whether the node last reported its tip's anchor as validated and in
	/// the parent's active chain.
	anchor_ok: AtomicBool,
	/// Held for a whole pass, and while a transaction is added to the watch
	/// list, so a transaction watched while its block is scanned is found by
	/// one or the other.
	pass: Mutex<HashSet<Txid>>,
}

/// The most transactions a pass reads from the mempool.
const MEMPOOL_BATCH: usize = 2_000;

impl FinalityService {
	/// A service following `source` into `store`. Refuses a node that does
	/// not validate its anchors, and a certification setting the node
	/// contradicts.
	pub async fn new(store: Store, source: Arc<dyn ChainSource>, config: FinalityConfig)
		-> Result<Arc<FinalityService>, FinalityError>
	{
		let s = Arc::new(FinalityService {
			store, source, config,
			events: broadcast::channel(4096).0,
			anchor_ok: AtomicBool::new(false),
			pass: Mutex::new(HashSet::new()),
		});
		let anchor = s.call(|c| c.anchor_status()).await?;
		if !anchor.validated {
			return Err(FinalityError::Config(
				"the node does not validate its anchors against the parent chain (-validateanchor), \
				 so it has no notion of finality".into(),
			));
		}
		let tip = s.call(|c| c.tip()).await?;
		let header = s.call(move |c| c.header(&tip)).await?;
		match (s.config.certification, header.certified) {
			(Certification::Required, None) => return Err(FinalityError::Config(
				"finality requires certification, and the node reports no committee certificate for its blocks".into(),
			)),
			(Certification::NotOnThisChain, Some(_)) => return Err(FinalityError::Config(
				"the node reports committee certificates; certification cannot be left out of finality on this chain".into(),
			)),
			_ => {},
		}
		Ok(s)
	}

	pub fn config(&self) -> &FinalityConfig {
		&self.config
	}

	pub fn source(&self) -> &Arc<dyn ChainSource> {
		&self.source
	}

	/// Changes to the active chain from now on.
	pub fn subscribe(&self) -> broadcast::Receiver<ChainEvent> {
		self.events.subscribe()
	}

	/// Runs a blocking call on the chain source.
	pub(crate) async fn call<T, F>(&self, f: F) -> Result<T, ChainError>
	where
		T: Send + 'static,
		F: FnOnce(&dyn ChainSource) -> Result<T, ChainError> + Send + 'static,
	{
		let source = self.source.clone();
		tokio::task::spawn_blocking(move || f(source.as_ref()))
			.await
			.map_err(|e| ChainError::Node(format!("the chain call did not finish: {}", e)))?
	}

	/// Follows the node at `poll_interval` until the task is dropped.
	pub fn spawn(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
		let me = self.clone();
		tokio::spawn(async move {
			loop {
				if let Err(e) = me.sync().await {
					log::warn!("finality service: {}", e);
				}
				tokio::time::sleep(me.config.poll_interval).await;
			}
		})
	}

	fn row(h: &HeaderInfo) -> BlockRow {
		BlockRow {
			hash: h.hash.to_byte_array(),
			height: h.height,
			prev_hash: h.prev.map(|p| p.to_byte_array()).unwrap_or([0; 32]),
			anchor_height: h.anchor.height as u64,
			anchor_hash: h.anchor.block_hash.to_byte_array(),
			median_time: h.median_time,
			certified: h.certified.unwrap_or(false),
		}
	}

	/// One pass: brings the stored chain to the node's tip, disconnecting and
	/// connecting as needed, refreshes certificates and the anchor's status,
	/// and scans the mempool.
	pub async fn sync(&self) -> Result<(), FinalityError> {
		let mut seen = self.pass.lock().await;
		let tip = self.call(|c| c.tip()).await?;
		let stored = self.store.tip_block().await?;

		// The node's chain from its tip down to the first block the store
		// holds, or to the lowest stored height.
		let lowest = match &stored {
			Some(_) => self.lowest_stored().await?,
			None => None,
		};
		let mut path: Vec<HeaderInfo> = vec![];
		let mut fork: Option<BlockRow> = None;
		let mut at = Some(tip);
		while let Some(hash) = at {
			if let Some(b) = self.store.block_by_hash(&hash.to_byte_array()).await? {
				fork = Some(b);
				break;
			}
			let h = self.call(move |c| c.header(&hash)).await?;
			let start = match (lowest, self.config.start_height) {
				(Some(l), _) => l,
				(None, Some(s)) => s,
				(None, None) => path.first().map(|t: &HeaderInfo| t.height).unwrap_or(h.height),
			};
			if h.height < start {
				break;
			}
			at = h.prev;
			let done = h.height == start;
			path.push(h);
			if done {
				break;
			}
		}

		// Disconnect, tip first, every stored block above the fork.
		let keep = fork.as_ref().map(|f| f.height);
		while let Some(top) = self.store.tip_block().await? {
			if keep.is_some_and(|k| top.height <= k) {
				break;
			}
			let held = self.store.disconnect_block(&top.hash).await?;
			let watched = held.into_iter().map(|(t, k)| (Txid::from_byte_array(t), k)).collect::<Vec<_>>();
			log::info!("disconnected block {} at height {}; it held {} watched transaction(s)",
				BlockHash::from_byte_array(top.hash), top.height, watched.len());
			let _ = self.events.send(ChainEvent::Disconnected {
				height: top.height, hash: BlockHash::from_byte_array(top.hash), watched,
			});
		}

		// Connect the node's blocks above it, lowest first.
		for h in path.into_iter().rev() {
			let hash = h.hash;
			let txs = self.call(move |c| c.block_txs(&hash)).await?;
			let mut scan = Scan::default();
			for tx in &txs {
				scan.add_tx(tx);
			}
			self.store.connect_block(&Self::row(&h), &scan).await?;
			let _ = self.events.send(ChainEvent::Connected { height: h.height, hash: h.hash });
		}

		// Certificates can arrive after their block.
		if let Some(top) = self.store.tip_block().await? {
			for hash in self.store.uncertified_from(top.height.saturating_sub(self.config.cert_lookback)).await? {
				let bh = BlockHash::from_byte_array(hash);
				let h = self.call(move |c| c.header(&bh)).await?;
				if h.certified == Some(true) {
					self.store.set_certified(&hash, true).await?;
				}
			}
		}

		let anchor = self.call(|c| c.anchor_status()).await?;
		if !anchor.ok() && self.anchor_ok.load(Ordering::SeqCst) {
			log::warn!("the node reports its tip's anchor as {:?}; nothing becomes final until it is ok", anchor.status);
		}
		self.anchor_ok.store(anchor.ok(), Ordering::SeqCst);

		self.scan_mempool(&mut seen).await?;

		if let Some(top) = self.store.tip_block().await? {
			let _ = self.events.send(ChainEvent::Synced { height: top.height, hash: BlockHash::from_byte_array(top.hash) });
		}
		Ok(())
	}

	async fn lowest_stored(&self) -> Result<Option<u64>, StoreError> {
		self.store.lowest_block_height().await
	}

	/// Scans transactions new to the mempool for sightings and spends.
	async fn scan_mempool(&self, seen: &mut HashSet<Txid>) -> Result<(), FinalityError> {
		let now: HashSet<Txid> = self.call(|c| c.mempool()).await?.into_iter().collect();
		seen.retain(|t| now.contains(t));
		let fresh: Vec<Txid> = now.iter().filter(|t| !seen.contains(*t)).take(MEMPOOL_BATCH).copied().collect();
		if fresh.is_empty() {
			return Ok(());
		}
		let mut scan = Scan::default();
		for txid in fresh {
			if let Some(tx) = self.call(move |c| c.transaction(&txid)).await? {
				scan.add_tx(&tx);
			}
			seen.insert(txid);
		}
		self.store.record_mempool_scan(&scan).await?;
		Ok(())
	}

	/// Watches `txid` for `kind` and returns where it stands. A transaction
	/// already in a block of the followed chain is found at once; one that
	/// confirms later is found as its block is connected.
	pub async fn watch(&self, txid: Txid, kind: &str) -> Result<Finality, FinalityError> {
		{
			let _pass = self.pass.lock().await;
			self.store.watch_tx(&txid.to_byte_array(), kind).await?;
			if let Some(block) = self.call(move |c| c.tx_block(&txid)).await? {
				self.store.record_tx_block(&txid.to_byte_array(), &block.to_byte_array()).await?;
			}
		}
		self.status(&txid).await
	}

	/// Where the watched transaction `txid` stands. A transaction never
	/// watched is reported as not in the chain.
	pub async fn status(&self, txid: &Txid) -> Result<Finality, FinalityError> {
		let block = match self.store.tx_location(&txid.to_byte_array()).await? {
			Some(b) => b,
			None => return Ok(Finality::NotInChain),
		};
		let hash = BlockHash::from_byte_array(block.hash);
		let certified = match self.config.certification {
			Certification::NotOnThisChain => true,
			Certification::Required => self.store.certified_at_or_above(block.height).await?,
		};
		if !certified {
			return Ok(Finality::Unsettled { height: block.height, block: hash });
		}
		let tip = self.store.tip_block().await?.ok_or_else(|| StoreError::Corrupt("a located block with no tip".into()))?;
		let depth = tip.anchor_height.saturating_sub(block.anchor_height);
		if depth >= self.config.anchor_depth as u64 && self.anchor_ok.load(Ordering::SeqCst) {
			Ok(Finality::Final { height: block.height, block: hash, depth })
		} else {
			Ok(Finality::Settled { height: block.height, block: hash, depth })
		}
	}
}
