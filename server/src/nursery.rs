//! The nursery: keeps the transactions the server relies on broadcast until
//! the finality service calls them final, and broadcasts them again,
//! unchanged, whenever a rollback takes them out.
//!
//! A transaction enters the nursery byte for byte and is only ever broadcast
//! again as those same bytes: the nursery never builds a replacement, so a
//! round returns with its txid and every forfeit signed for it still holds,
//! and a board returns as the board the owner signed. It holds the server's
//! own transactions (a round, a wallet transaction, each naming its fee asset)
//! and the ones it relies on without having built them (a board).
//!
//! What the nursery does, and when:
//!
//! - **On a disconnection.** The finality service names the watched
//!   transactions a disconnected block held; each the nursery holds goes back
//!   to pending and is broadcast again at once, before anything else, oldest
//!   first, so a parent precedes its child.
//! - **On each pass.** A pending transaction the finality service calls final
//!   is marked final. One not in the chain is broadcast again, at most every
//!   `rebroadcast_interval`. One whose input a final transaction of another
//!   txid has spent can never confirm: it is marked lost, and its wallet
//!   coins, if the wallet built it, are freed. A final transaction stays
//!   watched: a rollback can take it out again, and then it is pending.
//!
//! The nursery decides nothing about finality itself; it asks the finality
//! service.

use std::sync::Arc;
use std::time::{Duration, Instant};

use elements::encode::{deserialize, serialize};
use elements::hashes::Hash;
use elements::{Transaction, Txid};
use tokio::sync::{broadcast, Mutex};

use sequentia_ext::AssetAmount;

use crate::chain::{ChainEvent, FinalityService};
use crate::store::{NurseryRow, NurseryState, Store, StoreError};
use crate::wallet::Wallet;

/// What a transaction in the nursery is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NurseryKind {
	/// A board an owner paid, relied on until final.
	Board,
	/// A transaction the operator's wallet built.
	Wallet,
	/// A round transaction.
	Round,
	/// A transaction the watcher built: an answer to a stale exit, a claim,
	/// a release, a sweep, a reclaim, an offboard's unlock or reclaim.
	Watcher,
}

impl NurseryKind {
	pub fn as_str(self) -> &'static str {
		match self {
			NurseryKind::Board => "board",
			NurseryKind::Wallet => "wallet",
			NurseryKind::Round => "round",
			NurseryKind::Watcher => "watcher",
		}
	}
}

/// Something the nursery did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NurseryEvent {
	/// It broadcast `txid` (again), and the node answered `result`.
	Broadcast { txid: Txid, result: String },
	Final { txid: Txid },
	/// A rollback took `txid` out of the chain after it was final.
	Unfinal { txid: Txid },
	/// `txid` can no longer confirm: `by`, final, spent one of its inputs.
	Lost { txid: Txid, kind: String, by: Txid },
}

#[derive(Debug, thiserror::Error)]
pub enum NurseryError {
	#[error(transparent)]
	Store(#[from] StoreError),
	#[error("the finality service: {0}")]
	Finality(String),
	#[error("a stored transaction does not decode: {0}")]
	Decode(String),
}

/// See the [module documentation](self).
pub struct Nursery {
	store: Store,
	finality: Arc<FinalityService>,
	wallet: Option<Arc<Wallet>>,
	rebroadcast_interval: Duration,
	/// When each transaction was last broadcast by this process.
	last: Mutex<std::collections::HashMap<Txid, Instant>>,
	events: broadcast::Sender<NurseryEvent>,
}

impl Nursery {
	pub fn new(store: Store, finality: Arc<FinalityService>, wallet: Option<Arc<Wallet>>, rebroadcast_interval: Duration)
		-> Arc<Nursery>
	{
		Arc::new(Nursery {
			store, finality, wallet, rebroadcast_interval,
			last: Mutex::new(Default::default()),
			events: broadcast::channel(4096).0,
		})
	}

	pub fn subscribe(&self) -> broadcast::Receiver<NurseryEvent> {
		self.events.subscribe()
	}

	/// Takes `tx` into the nursery and broadcasts it. `fee` names the fee
	/// asset and amount of a transaction the server built.
	pub async fn submit(&self, tx: &Transaction, kind: NurseryKind, fee: Option<AssetAmount>) -> Result<String, NurseryError> {
		let txid = tx.txid();
		let inputs: Vec<([u8; 32], u32)> = tx.input.iter()
			.map(|i| (i.previous_output.txid.to_byte_array(), i.previous_output.vout)).collect();
		let fee = fee.map(|f| (f.asset.into_inner().to_byte_array(), f.amount));
		self.store.nursery_insert(&txid.to_byte_array(), &serialize(tx), kind.as_str(), fee, &inputs).await?;
		self.finality.watch(txid, kind.as_str()).await.map_err(|e| NurseryError::Finality(e.to_string()))?;
		let row = self.store.nursery_get(&txid.to_byte_array()).await?.expect("just stored");
		self.broadcast(&row).await
	}

	/// Takes a transaction of the watcher's into the nursery with its log
	/// entry, whole ([`Store::insert_watcher_tx`]), and broadcasts it.
	pub async fn submit_watcher(&self, w: &crate::store::NewWatcherTx) -> Result<String, NurseryError> {
		self.store.insert_watcher_tx(w).await?;
		let txid = Txid::from_byte_array(w.txid);
		self.finality.watch(txid, NurseryKind::Watcher.as_str()).await.map_err(|e| NurseryError::Finality(e.to_string()))?;
		let row = self.store.nursery_get(&w.txid).await?.expect("just stored");
		self.broadcast(&row).await
	}

	/// Broadcasts the stored bytes of `row` and records the answer.
	async fn broadcast(&self, row: &NurseryRow) -> Result<String, NurseryError> {
		let tx: Transaction = deserialize(&row.tx).map_err(|e| NurseryError::Decode(e.to_string()))?;
		let txid = tx.txid();
		let result = match self.finality.call(move |c| c.broadcast(&tx)).await {
			Ok(_) => "accepted".to_string(),
			Err(e) => e.to_string(),
		};
		self.store.nursery_broadcast(&row.txid, &result).await?;
		self.last.lock().await.insert(txid, Instant::now());
		log::info!("nursery: broadcast {} ({}): {}", txid, row.kind, result);
		let _ = self.events.send(NurseryEvent::Broadcast { txid, result: result.clone() });
		Ok(result)
	}

	/// Handles a change to the chain: a disconnection sends each transaction
	/// of the nursery's it held back out, unchanged, at once.
	pub async fn on_chain_event(&self, event: &ChainEvent) -> Result<(), NurseryError> {
		if let ChainEvent::Disconnected { watched, .. } = event {
			for (txid, _) in watched {
				if let Some(row) = self.store.nursery_get(&txid.to_byte_array()).await? {
					if row.state == NurseryState::Lost {
						continue;
					}
					if row.state == NurseryState::Final {
						let _ = self.events.send(NurseryEvent::Unfinal { txid: *txid });
					}
					self.store.nursery_set_state(&row.txid, NurseryState::Pending).await?;
					self.broadcast(&row).await?;
				}
			}
		}
		Ok(())
	}

	/// One pass over every transaction not lost: see the [module
	/// documentation](self).
	pub async fn pass(&self) -> Result<(), NurseryError> {
		let mut rows = self.store.nursery_in(NurseryState::Pending).await?;
		rows.extend(self.store.nursery_in(NurseryState::Final).await?);
		for row in rows {
			let txid = Txid::from_byte_array(row.txid);
			let status = self.finality.status(&txid).await.map_err(|e| NurseryError::Finality(e.to_string()))?;
			if status.is_final() {
				if row.state != NurseryState::Final {
					self.store.nursery_set_state(&row.txid, NurseryState::Final).await?;
					log::info!("nursery: {} ({}) is final", txid, row.kind);
					let _ = self.events.send(NurseryEvent::Final { txid });
				}
				continue;
			}
			if row.state == NurseryState::Final {
				// Out of finality without a disconnection seen (the service
				// lagged): back to pending.
				self.store.nursery_set_state(&row.txid, NurseryState::Pending).await?;
				let _ = self.events.send(NurseryEvent::Unfinal { txid });
			}
			if status.in_chain() {
				continue;
			}
			if let Some(by) = self.final_conflict(&row).await? {
				self.store.nursery_set_state(&row.txid, NurseryState::Lost).await?;
				log::warn!("nursery: {} ({}) is lost: {} spent its input and is final", txid, row.kind, by);
				if row.kind != NurseryKind::Board.as_str() {
					if let Some(w) = &self.wallet {
						w.release(&txid).await.map_err(|e| NurseryError::Finality(e.to_string()))?;
					}
				}
				let _ = self.events.send(NurseryEvent::Lost { txid, kind: row.kind.clone(), by });
				continue;
			}
			let due = match self.last.lock().await.get(&txid) {
				Some(at) => at.elapsed() >= self.rebroadcast_interval,
				None => true,
			};
			if due {
				self.broadcast(&row).await?;
			}
		}
		Ok(())
	}

	/// A final transaction of another txid spending one of `row`'s inputs:
	/// any spend the finality service recorded of an outpoint it spends,
	/// whatever watched that outpoint first (a board output the watcher's
	/// forfeit spends is watched for its board).
	async fn final_conflict(&self, row: &NurseryRow) -> Result<Option<Txid>, NurseryError> {
		let tx: Transaction = deserialize(&row.tx).map_err(|e| NurseryError::Decode(e.to_string()))?;
		let mut spenders = self.store.conflicting_spends(&row.txid).await?;
		for i in &tx.input {
			if let Some(by) = self.store.outpoint_spender(&i.previous_output.txid.to_byte_array(), i.previous_output.vout).await? {
				if by != row.txid && !spenders.contains(&by) {
					spenders.push(by);
				}
			}
		}
		for by in spenders {
			let by = Txid::from_byte_array(by);
			let s = self.finality.status(&by).await.map_err(|e| NurseryError::Finality(e.to_string()))?;
			if s.is_final() {
				return Ok(Some(by));
			}
		}
		Ok(None)
	}

	/// Follows the finality service's events until the task is dropped: each
	/// disconnection at once, a pass after each sync, and a pass over
	/// everything if the events lagged.
	pub fn spawn(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
		let me = self.clone();
		let mut rx = self.finality.subscribe();
		tokio::spawn(async move {
			loop {
				let r = match rx.recv().await {
					Ok(ChainEvent::Synced { .. }) => me.pass().await,
					Ok(e) => me.on_chain_event(&e).await,
					Err(broadcast::error::RecvError::Lagged(n)) => {
						log::warn!("nursery: {} chain events missed; checking everything", n);
						me.pass().await
					},
					Err(broadcast::error::RecvError::Closed) => return,
				};
				if let Err(e) = r {
					log::warn!("nursery: {}", e);
				}
			}
		})
	}
}
