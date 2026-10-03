//! The check every coin the server is asked to take off an owner passes,
//! whether for an out-of-round transfer ([`crate::cosign`]) or a round's
//! participation ([`crate::participations`]).
//!
//! A coin given up must be one the server knows, live (a board once
//! credited) and held by nothing else; its record must resolve under the
//! server's policy against the transactions its bases came from; every board
//! it rests on must be credited and unspent; and nothing of its lineage, its
//! own leaf included, may have been seen paid on the chain, in a block or in
//! the mempool: an Arca leaf on the chain past its exit delay can be exited by
//! its owner at once, so the server takes no off-chain spend of it.

use elements::hashes::Hash;
use elements::Transaction;

use arca_covenant::{CoinRecord, LeafId, TransferError, ValidCoin, WalletPolicy};

use crate::store::{BoardState, LeafState, RoundState, Store, StoreError};

/// A coin given up, checked.
#[derive(Debug, Clone)]
pub struct Checked {
	pub record: CoinRecord,
	pub coin: ValidCoin,
	/// The transactions its bases came from: each board's.
	pub bases: Vec<Transaction>,
}

/// Why a coin cannot be given up.
#[derive(Debug, thiserror::Error)]
pub enum CoinError {
	#[error("leaf {0} is not known to this server")]
	UnknownLeaf(LeafId),
	#[error("leaf {0} is {1}, not live: a board is live once its transaction is final")]
	NotLive(LeafId, &'static str),
	/// Spent off-chain, or given up in a participation, by something else.
	#[error("leaf {0} is already spent or given up")]
	Spent(LeafId),
	#[error("leaf {0} rests on a board that is not credited: its transaction is not final")]
	BoardNotFinal(LeafId),
	#[error("leaf {0} rests on a leaf of a round that is not final")]
	RoundNotFinal(LeafId),
	#[error("leaf {leaf}: {what} is on-chain, so its owner could take it under the receiver; the server takes no off-chain spend of it")]
	OnChain { leaf: LeafId, what: String },
	#[error("leaf {leaf}'s coin does not check out: {error}")]
	InvalidCoin { leaf: LeafId, error: TransferError },
	#[error(transparent)]
	Store(#[from] StoreError),
	#[error("{0}")]
	Internal(String),
}

/// The transactions a coin record's bases came from: each board's, as
/// registered, and each batch leaf's round, which must be final.
pub async fn bases(store: &Store, record: &CoinRecord, out: &mut Vec<Transaction>) -> Result<(), CoinError> {
	match record {
		CoinRecord::Board(b) => {
			let row = store.board(&b.leaf_id().0).await?
				.ok_or_else(|| CoinError::Internal(format!("board {} of a known coin is not registered", b.leaf_id())))?;
			let tx: Transaction = elements::encode::deserialize(&row.tx).map_err(|e| CoinError::Internal(e.to_string()))?;
			out.push(tx);
		},
		CoinRecord::Transfer(t) => {
			for i in &t.inputs {
				Box::pin(bases(store, &i.coin, out)).await?;
			}
		},
		CoinRecord::Leaf { record, .. } => {
			let id = record.leaf_id().map_err(|e| CoinError::Internal(e.to_string()))?;
			let leaf = store.batch_leaf(&id.0).await?
				.ok_or_else(|| CoinError::Internal(format!("leaf {} of a known coin is in no batch the server built", id)))?;
			let round = store.round(leaf.round_id).await?
				.ok_or_else(|| CoinError::Internal(format!("the round of leaf {} is not recorded", id)))?;
			if round.state != RoundState::Final {
				return Err(CoinError::RoundNotFinal(id));
			}
			let tx: Transaction = elements::encode::deserialize(&round.tx).map_err(|e| CoinError::Internal(e.to_string()))?;
			if !out.iter().any(|t| t.txid() == tx.txid()) {
				out.push(tx);
			}
		},
	}
	Ok(())
}

/// The coin `id`, resolved from its record under `policy`, with nothing
/// checked of its state or of the chain: what a step already taken for it
/// is verified again against.
pub async fn resolve(store: &Store, policy: &WalletPolicy, id: &LeafId) -> Result<Checked, CoinError> {
	let row = store.leaf(&id.0).await?.ok_or(CoinError::UnknownLeaf(*id))?;
	let record = CoinRecord::from_bytes(&row.record).map_err(|error| CoinError::InvalidCoin { leaf: *id, error })?;
	let mut found = vec![];
	bases(store, &record, &mut found).await?;
	let coin = record.resolve(&found, policy).map_err(|error| CoinError::InvalidCoin { leaf: *id, error })?;
	if coin.id != *id {
		return Err(CoinError::Internal(format!("the record of leaf {} gives the id {}", id, coin.id)));
	}
	Ok(Checked { record, coin, bases: found })
}

/// Checks the coin `id` given up by `holder` (a transfer, or a
/// participation): see the [module documentation](self). A coin already
/// spent by `holder` itself passes, so a repeated request gets its answer.
pub async fn check(store: &Store, policy: &WalletPolicy, id: &LeafId, holder: &[u8; 32]) -> Result<Checked, CoinError> {
	let row = store.leaf(&id.0).await?.ok_or(CoinError::UnknownLeaf(*id))?;
	match row.state {
		LeafState::Live => {},
		LeafState::Spent if row.spent_by.as_deref() == Some(&holder[..]) => {},
		LeafState::Spent => return Err(CoinError::Spent(*id)),
		LeafState::Pending => return Err(CoinError::NotLive(*id, "pending")),
		LeafState::Lost => return Err(CoinError::NotLive(*id, "lost")),
		LeafState::Expired => return Err(CoinError::NotLive(*id, "expired")),
	}
	let Checked { record, coin, bases: found } = resolve(store, policy, id).await?;
	// Its own leaf and every leaf and checkpoint it descends from.
	let mut scripts = vec![coin.output().script_pubkey.to_bytes()];
	scripts.extend(coin.lineage().iter().map(|o| o.output.script_pubkey.to_bytes()));
	let seen = store.sighted(&scripts).await?;
	if seen.contains(&scripts[0]) {
		return Err(CoinError::OnChain { leaf: *id, what: "its own leaf".into() });
	}
	coin.check_lineage(|s| seen.contains(&s.to_bytes()))
		.map_err(|e| CoinError::OnChain { leaf: *id, what: e.to_string() })?;
	// Every board it rests on: credited, and its output unspent.
	for b in coin.boards() {
		let txid = b.txid.to_byte_array();
		let board = store.boards_by_txid(&txid).await?.into_iter().find(|r| r.vout == b.vout)
			.ok_or_else(|| CoinError::Internal(format!("board output {} is not registered", b)))?;
		if board.state != BoardState::Credited {
			return Err(CoinError::BoardNotFinal(*id));
		}
		if let Some(by) = store.outpoint_spender(&txid, b.vout).await? {
			return Err(CoinError::OnChain {
				leaf: *id,
				what: format!("the board output {} is spent by {}", b, elements::Txid::from_byte_array(by)),
			});
		}
	}
	Ok(Checked { record, coin, bases: found })
}
