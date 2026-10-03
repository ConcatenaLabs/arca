//! Board registration and crediting.
//!
//! An owner brings its own coins into Arca with a board (`board-1`): it asks
//! the server for an operator nonce, builds its board record with it, pays its
//! coins to the board output and registers the record with the transaction.
//! The server checks the record under its own policy (its chain, its key, its
//! exit-delay bounds, an asset it serves, a value within the bounds, the board
//! output paid exactly once, an owner key other than `S`), the leaf's salt,
//! which it must never have seen on a leaf or promised to one, and the
//! nonce, which it must have handed out and never seen taken. Then the node must
//! take the transaction: it is in a block or the mempool already, or the
//! node's `testmempoolaccept` allows it. A transaction the node refuses (an
//! input that does not exist, say) registers nothing, so no board nobody can
//! pay sits in the database or the nursery. Only then does the server take
//! the nonce, which it never hands out twice, record the board's scripts,
//! which it never accepts twice, and take the transaction into the nursery.
//!
//! The board is credited, and its leaf becomes live, only once the finality
//! service calls its transaction final: certified, and its anchor buried two
//! Bitcoin blocks. The operator carries the risk of a board that is rolled
//! back, which is why it waits. A rollback that takes a credited board out
//! uncredits it at once; the nursery broadcasts it again, unchanged, and it is
//! credited again when final again. A board whose transaction can no longer
//! confirm is lost, and so is one never credited whose transaction is in no
//! block a set time after it was registered (`board_unconfirmed_seconds`):
//! the nursery stops broadcasting it.

use std::sync::Arc;
use std::time::Duration;

use elements::encode::serialize;
use elements::hashes::Hash;
use elements::{Transaction, Txid};
use tokio::sync::broadcast;

use arca_covenant::{BoardRecord, CoinRecord, LeafId, MedianTime, RecordError};

use crate::chain::{ChainEvent, Finality, FinalityService};
use crate::nursery::{Nursery, NurseryKind};
use crate::params::Params;
use crate::store::{BoardRow, BoardState, LeafKind, LeafState, NewCoin, NewScript, NurseryState, ScriptKind, Store, StoreError};

/// Why a board was refused, or could not be handled.
#[derive(Debug, thiserror::Error)]
pub enum BoardError {
	#[error("the board record is refused: {0}")]
	Record(#[from] RecordError),
	#[error("the board is outside the operator's published bounds: {0}")]
	OutOfBounds(String),
	#[error("the board transaction is refused: {0}")]
	Transaction(String),
	#[error("the node does not take the board transaction: {0}")]
	NotAccepted(String),
	#[error("another board is registered for this leaf")]
	Exists,
	#[error("the board's key is the operator's own key S: a leaf has its owner's key, never the operator's")]
	OperatorKey,
	#[error("the board's salt {0} is already known to the server: every leaf has a salt of its own")]
	SaltReused(String),
	#[error("the server has not followed the chain yet")]
	NotSynced,
	#[error(transparent)]
	Store(#[from] StoreError),
	#[error("{0}")]
	Internal(String),
}

impl BoardError {
	/// A stable name for the refusal.
	pub fn code(&self) -> &'static str {
		match self {
			BoardError::Record(e) => match e {
				RecordError::WrongChain => "wrong_chain",
				RecordError::WrongOperator => "wrong_operator",
				RecordError::ExitDelay { .. } => "out_of_bounds",
				RecordError::BoardOutputMissing | RecordError::BoardOutputRepeated(_) => "board_output",
				_ => "invalid_record",
			},
			BoardError::OutOfBounds(_) => "out_of_bounds",
			BoardError::Transaction(_) => "invalid_transaction",
			BoardError::NotAccepted(_) => "not_accepted",
			BoardError::Exists => "board_exists",
			BoardError::OperatorKey => "operator_key",
			BoardError::SaltReused(_) | BoardError::Store(StoreError::SaltReused(_)) => "salt",
			BoardError::NotSynced => "not_synced",
			BoardError::Store(StoreError::NonceUnknown) => "nonce_unknown",
			BoardError::Store(StoreError::NonceUsed) => "nonce_used",
			BoardError::Store(StoreError::ScriptReused) => "script_reused",
			BoardError::Store(StoreError::KeyReused) => "key_reused",
			BoardError::Store(_) | BoardError::Internal(_) => "internal",
		}
	}
}

/// Where a board stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardStatus {
	pub leaf_id: LeafId,
	pub txid: Txid,
	pub vout: u32,
	pub state: BoardState,
	pub finality: Finality,
}

/// See the [module documentation](self).
pub struct Boards {
	store: Store,
	finality: Arc<FinalityService>,
	nursery: Arc<Nursery>,
	params: Arc<Params>,
	/// How long a board never credited may stay out of every block.
	unconfirmed: Duration,
}

impl Boards {
	/// The boards, each dropped when never credited and out of every block
	/// `unconfirmed` after it was registered.
	pub fn new(store: Store, finality: Arc<FinalityService>, nursery: Arc<Nursery>, params: Arc<Params>, unconfirmed: Duration)
		-> Arc<Boards>
	{
		Arc::new(Boards { store, finality, nursery, params, unconfirmed })
	}

	/// The median time of the tip the finality service follows.
	async fn now(&self) -> Result<MedianTime, BoardError> {
		let tip = self.store.tip_block().await?.ok_or(BoardError::NotSynced)?;
		MedianTime::from_consensus(tip.median_time as u32).map_err(|e| BoardError::Internal(e.to_string()))
	}

	/// Registers the board `record` paid by `tx`: see the [module
	/// documentation](self). Registering the same board again returns its
	/// status.
	pub async fn register(&self, record: &BoardRecord, tx: &Transaction) -> Result<BoardStatus, BoardError> {
		let policy = self.params.policy(self.now().await?);
		record.check()?;
		if record.owner == self.params.operator {
			return Err(BoardError::OperatorKey);
		}
		self.params.check_value(record.asset, record.value).map_err(BoardError::OutOfBounds)?;
		let valid = record.validate(tx, &policy)?;
		let leaf_id = valid.leaf_id;
		let record_bytes = record.to_bytes()?;
		if let Some(b) = self.store.board(&leaf_id.0).await? {
			if b.record == record_bytes && b.txid == valid.txid.to_byte_array() {
				return self.status(&leaf_id).await?.ok_or(BoardError::Internal("a board vanished".into()));
			}
			return Err(BoardError::Exists);
		}
		// The salt, then the nonce, before anything is asked of the node.
		if let Some(known) = self.store.known_salts(&[record.salt()]).await?.first() {
			return Err(BoardError::SaltReused(crate::signer::hex(known)));
		}
		self.store.check_nonce(&record.operator_nonce).await?;
		self.accepted(tx).await?;
		let board = record.policy();
		let coin = NewCoin {
			leaf_id: leaf_id.0,
			kind: LeafKind::Board,
			asset: record.asset.into_inner().to_byte_array(),
			value: record.value,
			owner_key: record.owner.serialize(),
			script_pubkey: board.script_pubkey().to_bytes(),
			hops: 0,
			record: CoinRecord::Board(*record).to_bytes().map_err(|e| BoardError::Internal(e.to_string()))?,
			state: LeafState::Pending,
			salt: record.salt(),
			promised_to: None,
			operator_nonce: Some(record.operator_nonce),
			scripts: vec![
				NewScript { script_pubkey: board.script_pubkey().to_bytes(), kind: ScriptKind::Board },
				NewScript { script_pubkey: board.leaf.script_pubkey().to_bytes(), kind: ScriptKind::Leaf },
			],
		};
		self.store.insert_board(&coin, &record_bytes, &valid.txid.to_byte_array(), valid.vout, &serialize(tx)).await?;
		log::info!("board {} registered, paid by {}:{}", leaf_id, valid.txid, valid.vout);
		self.nursery.submit(tx, NurseryKind::Board, None).await.map_err(|e| BoardError::Internal(e.to_string()))?;
		self.check(&leaf_id.0).await?;
		self.status(&leaf_id).await?.ok_or(BoardError::Internal("a board vanished".into()))
	}

	/// Whether the node takes `tx`: it holds it already, in a block or its
	/// mempool, or would take it into its mempool now.
	async fn accepted(&self, tx: &Transaction) -> Result<(), BoardError> {
		let txid = tx.txid();
		let known = self.finality.call(move |c| c.transaction(&txid)).await.map_err(|e| BoardError::Internal(e.to_string()))?;
		if known.is_some() {
			return Ok(());
		}
		let probe = tx.clone();
		let (allowed, reason, _) = self.finality.call(move |c| c.test_accept(&probe)).await
			.map_err(|e| BoardError::Internal(e.to_string()))?;
		if !allowed {
			return Err(BoardError::NotAccepted(reason.unwrap_or_else(|| "no reason given".into())));
		}
		Ok(())
	}

	/// Where the board `leaf_id` stands.
	pub async fn status(&self, leaf_id: &LeafId) -> Result<Option<BoardStatus>, BoardError> {
		let b = match self.store.board(&leaf_id.0).await? {
			Some(b) => b,
			None => return Ok(None),
		};
		let txid = Txid::from_byte_array(b.txid);
		let finality = self.finality.status(&txid).await.map_err(|e| BoardError::Internal(e.to_string()))?;
		Ok(Some(BoardStatus { leaf_id: *leaf_id, txid, vout: b.vout, state: b.state, finality }))
	}

	/// Credits the board if final, uncredits it if it no longer is, marks it
	/// lost if the nursery says its transaction can no longer confirm.
	async fn check_row(&self, b: &BoardRow) -> Result<(), BoardError> {
		if b.state == BoardState::Lost {
			return Ok(());
		}
		let txid = Txid::from_byte_array(b.txid);
		if let Some(n) = self.store.nursery_get(&b.txid).await? {
			if n.state == NurseryState::Lost {
				self.store.lose_board(&b.leaf_id).await?;
				log::warn!("board {} lost: its transaction {} can no longer confirm", LeafId(b.leaf_id), txid);
				return Ok(());
			}
		}
		let fin = self.finality.status(&txid).await.map_err(|e| BoardError::Internal(e.to_string()))?;
		let changed = match (b.state, fin.is_final()) {
			(BoardState::Pending, true) => self.store.credit_board(&b.leaf_id).await?.then_some("credited"),
			(BoardState::Credited, false) => self.store.uncredit_board(&b.leaf_id).await?.then_some("uncredited"),
			_ => None,
		};
		if let Some(what) = changed {
			log::info!("board {} {}: its transaction is {:?}", LeafId(b.leaf_id), what, fin);
		}
		Ok(())
	}

	async fn check(&self, leaf_id: &[u8; 32]) -> Result<(), BoardError> {
		if let Some(b) = self.store.board(leaf_id).await? {
			self.check_row(&b).await?;
		}
		Ok(())
	}

	/// One pass over every board not lost; then each board never credited
	/// whose transaction is still in no block `unconfirmed` after it was
	/// registered is dropped: marked lost, its transaction no longer
	/// broadcast.
	pub async fn pass(&self) -> Result<(), BoardError> {
		let mut rows = self.store.boards_in(BoardState::Pending).await?;
		rows.extend(self.store.boards_in(BoardState::Credited).await?);
		for b in rows {
			self.check_row(&b).await?;
		}
		for b in self.store.boards_never_credited(self.unconfirmed.as_secs()).await? {
			let txid = Txid::from_byte_array(b.txid);
			let fin = self.finality.status(&txid).await.map_err(|e| BoardError::Internal(e.to_string()))?;
			if fin.in_chain() {
				continue;
			}
			self.store.lose_board(&b.leaf_id).await?;
			self.store.nursery_set_state(&b.txid, NurseryState::Lost).await?;
			log::warn!("board {} dropped: its transaction {} is in no block {} s after it was registered",
				LeafId(b.leaf_id), txid, self.unconfirmed.as_secs());
		}
		Ok(())
	}

	/// Handles a change to the chain: a disconnection uncredits, at once,
	/// every board whose transaction the block held.
	pub async fn on_chain_event(&self, event: &ChainEvent) -> Result<(), BoardError> {
		if let ChainEvent::Disconnected { watched, .. } = event {
			for (txid, kind) in watched {
				if kind != NurseryKind::Board.as_str() {
					continue;
				}
				for b in self.store.boards_by_txid(&txid.to_byte_array()).await? {
					if self.store.uncredit_board(&b.leaf_id).await? {
						log::warn!("board {} uncredited: a rollback took {} out", LeafId(b.leaf_id), txid);
					}
				}
			}
		}
		Ok(())
	}

	/// Follows the finality service's events until the task is dropped.
	pub fn spawn(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
		let me = self.clone();
		let mut rx = self.finality.subscribe();
		tokio::spawn(async move {
			loop {
				let r = match rx.recv().await {
					Ok(ChainEvent::Synced { .. }) => me.pass().await,
					Ok(e) => me.on_chain_event(&e).await,
					Err(broadcast::error::RecvError::Lagged(_)) => me.pass().await,
					Err(broadcast::error::RecvError::Closed) => return,
				};
				if let Err(e) = r {
					log::warn!("boards: {}", e);
				}
			}
		})
	}
}
