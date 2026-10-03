//! What the watcher reads and writes: the outputs above every leaf of a
//! batch and their sightings, and the transactions the watcher publishes.

use super::coins::ScriptKind;
use super::nursery::NurseryState;
use super::participations::{ForfeitRow, NewForfeit};
use super::{array32, Store, StoreError};

/// What an output above a leaf is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeScriptKind {
	/// A node: the batch output, an inner node or a lowest node.
	Node,
	/// A leaf's hash-locked entry.
	Entry,
}

impl TreeScriptKind {
	pub(crate) fn as_str(self) -> &'static str {
		match self {
			TreeScriptKind::Node => "node",
			TreeScriptKind::Entry => "entry",
		}
	}

	fn parse(s: &str) -> Result<TreeScriptKind, StoreError> {
		match s {
			"node" => Ok(TreeScriptKind::Node),
			"entry" => Ok(TreeScriptKind::Entry),
			other => Err(StoreError::Corrupt(format!("tree script kind {}", other))),
		}
	}
}

/// A node or an entry of a batch, to record with the batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTreeScript {
	pub script_pubkey: Vec<u8>,
	pub kind: TreeScriptKind,
	/// A node's level, the lowest nodes 0; -1 for an entry.
	pub level: i16,
	/// A node's index in its level; an entry's leaf index.
	pub idx: u32,
	pub value: u64,
}

/// An output seen paying a node or an entry of a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeOutput {
	pub script_pubkey: Vec<u8>,
	pub kind: TreeScriptKind,
	pub level: i16,
	pub idx: u32,
	pub value: u64,
	pub txid: [u8; 32],
	pub vout: u32,
}

/// A transaction the watcher publishes, with what it is and acts for.
#[derive(Debug, Clone)]
pub struct NewWatcherTx {
	pub txid: [u8; 32],
	/// The transaction, in Sequentia's encoding.
	pub tx: Vec<u8>,
	/// The fee asset and amount it pays.
	pub fee: Option<([u8; 32], u64)>,
	pub kind: &'static str,
	pub subject: Vec<u8>,
	pub detail: String,
	/// The outpoints it spends.
	pub inputs: Vec<([u8; 32], u32)>,
}

/// A transaction the watcher published, and where the nursery has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatcherTxRow {
	pub txid: [u8; 32],
	pub kind: String,
	pub subject: Vec<u8>,
	pub detail: String,
	pub state: NurseryState,
	pub tx: Vec<u8>,
}

const WATCHER_COLUMNS: &str = "w.txid, w.kind, w.subject, w.detail, n.state::text, n.tx";

fn watcher_row(r: &tokio_postgres::Row) -> Result<WatcherTxRow, StoreError> {
	Ok(WatcherTxRow {
		txid: array32(r.get(0), "txid")?,
		kind: r.get(1),
		subject: r.get(2),
		detail: r.get(3),
		state: NurseryState::parse(r.get(4))?,
		tx: r.get(5),
	})
}

fn i64_of(v: u64) -> Result<i64, StoreError> {
	i64::try_from(v).map_err(|_| StoreError::Corrupt(format!("amount {}", v)))
}

impl Store {
	/// Every output seen paying a node or an entry of the batch at output
	/// `batch_vout` of the round `round_id`, in a block or the mempool: the
	/// candidates for what of the batch is on-chain.
	pub async fn tree_sightings(&self, round_id: i64, batch_vout: u32) -> Result<Vec<TreeOutput>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT t.script_pubkey, t.kind, t.level, t.idx, t.value, s.txid, s.vout
			 FROM tree_script t JOIN tree_sighting s ON s.script_pubkey = t.script_pubkey
			 WHERE t.round_id = $1 AND t.batch_vout = $2 ORDER BY t.level DESC, t.idx, s.seen_at",
			&[&round_id, &(batch_vout as i32)],
		).await?;
		rows.iter().map(|r| Ok(TreeOutput {
			script_pubkey: r.get(0),
			kind: TreeScriptKind::parse(r.get(1))?,
			level: r.get(2),
			idx: r.get::<_, i32>(3) as u32,
			value: r.get::<_, i64>(4) as u64,
			txid: array32(r.get(5), "txid")?,
			vout: r.get::<_, i32>(6) as u32,
		})).collect()
	}

	/// Takes a transaction of the watcher's into the nursery (kind
	/// `watcher`), its inputs watched for spends, with its log entry and the
	/// outpoints it spends, whole or not at all. A transaction already there
	/// is left as it was; returns whether it is new.
	pub async fn insert_watcher_tx(&self, w: &NewWatcherTx) -> Result<bool, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let (fee_asset, fee) = match w.fee {
			Some((a, f)) => (Some(a.to_vec()), Some(i64_of(f)?)),
			None => (None, None),
		};
		let n = t.execute(
			"INSERT INTO nursery_tx (txid, tx, kind, fee_asset, fee) VALUES ($1, $2, 'watcher', $3, $4) ON CONFLICT DO NOTHING",
			&[&&w.txid[..], &w.tx, &fee_asset, &fee],
		).await?;
		if n == 0 {
			return Ok(false);
		}
		t.execute("INSERT INTO watcher_tx (txid, kind, subject, detail) VALUES ($1, $2, $3, $4)",
			&[&&w.txid[..], &w.kind, &w.subject, &w.detail]).await?;
		for (pt, pv) in &w.inputs {
			t.execute(
				"INSERT INTO watched_outpoint (txid, vout, kind, watched_for) VALUES ($1, $2, 'nursery', $3) ON CONFLICT DO NOTHING",
				&[&&pt[..], &(*pv as i32), &&w.txid[..]],
			).await?;
			t.execute("INSERT INTO watcher_input (prev_txid, prev_vout, txid) VALUES ($1, $2, $3)",
				&[&&pt[..], &(*pv as i32), &&w.txid[..]]).await?;
		}
		t.commit().await?;
		Ok(true)
	}

	/// The watcher's transaction spending `txid:vout` that the nursery holds
	/// and has not found lost, if any.
	pub async fn watcher_spend(&self, txid: &[u8; 32], vout: u32) -> Result<Option<WatcherTxRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(
			&format!("SELECT {} FROM watcher_input i JOIN watcher_tx w ON w.txid = i.txid JOIN nursery_tx n ON n.txid = w.txid
				WHERE i.prev_txid = $1 AND i.prev_vout = $2 AND n.state <> 'lost' ORDER BY w.created_at DESC LIMIT 1", WATCHER_COLUMNS),
			&[&&txid[..], &(vout as i32)],
		).await?;
		r.as_ref().map(watcher_row).transpose()
	}

	/// The watcher's transactions of `kind` acting for `subject`, oldest
	/// first, lost ones included.
	pub async fn watcher_txs(&self, kind: &str, subject: &[u8]) -> Result<Vec<WatcherTxRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			&format!("SELECT {} FROM watcher_tx w JOIN nursery_tx n ON n.txid = w.txid
				WHERE w.kind = $1 AND w.subject = $2 ORDER BY w.created_at, w.txid", WATCHER_COLUMNS),
			&[&kind, &subject],
		).await?;
		rows.iter().map(watcher_row).collect()
	}

	/// Every transaction the watcher has published, oldest first.
	pub async fn watcher_log(&self) -> Result<Vec<WatcherTxRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			&format!("SELECT {} FROM watcher_tx w JOIN nursery_tx n ON n.txid = w.txid ORDER BY w.created_at, w.txid", WATCHER_COLUMNS),
			&[],
		).await?;
		rows.iter().map(watcher_row).collect()
	}

	/// Every output seen paying the leaf or the checkpoint of a coin the
	/// server holds as spent off-chain (given up in a transfer or a
	/// participation): what a stale exit, or an answer to one, puts on the
	/// chain. `(kind, the coin's leaf id, txid, vout)`, oldest first.
	pub async fn spent_coin_sightings(&self) -> Result<Vec<(ScriptKind, [u8; 32], [u8; 32], u32)>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT a.kind, a.leaf_id, s.txid, s.vout FROM script_sighting s
			 JOIN arca_script a ON a.script_pubkey = s.script_pubkey
			 JOIN leaf l ON l.leaf_id = a.leaf_id
			 WHERE a.kind IN ('leaf', 'checkpoint') AND l.state = 'spent'
			 ORDER BY s.seen_at, s.txid, s.vout",
			&[],
		).await?;
		rows.iter().map(|r| {
			let kind = match r.get::<_, &str>(0) {
				"leaf" => ScriptKind::Leaf,
				"checkpoint" => ScriptKind::Checkpoint,
				other => return Err(StoreError::Corrupt(format!("script kind {}", other))),
			};
			Ok((kind, array32(r.get(1), "leaf id")?, array32(r.get(2), "txid")?, r.get::<_, i32>(3) as u32))
		}).collect()
	}

	/// The outputs seen paying `script_pubkey`, an Arca script the server
	/// knows: `(txid, vout)`, oldest first.
	pub async fn sightings_of(&self, script_pubkey: &[u8]) -> Result<Vec<([u8; 32], u32)>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query("SELECT txid, vout FROM script_sighting WHERE script_pubkey = $1 ORDER BY seen_at, txid, vout",
			&[&script_pubkey]).await?;
		rows.iter().map(|r| Ok((array32(r.get(0), "txid")?, r.get::<_, i32>(1) as u32))).collect()
	}

	/// Every forfeit stored for `leaf_id`, for any round.
	pub async fn forfeits_of(&self, leaf_id: &[u8; 32]) -> Result<Vec<ForfeitRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT leaf_id, owner_sig, operator_sig, refund_delay_units, margin, unlock_hash, connector_asset, round_id,
			        participation_id, attempt
			 FROM forfeit WHERE leaf_id = $1 ORDER BY created_at",
			&[&&leaf_id[..]],
		).await?;
		rows.iter().map(|r| {
			let a: Vec<u8> = r.get(1);
			let b: Vec<u8> = r.get(2);
			Ok(ForfeitRow {
				forfeit: NewForfeit {
					leaf_id: array32(r.get(0), "leaf id")?,
					owner_sig: a.try_into().map_err(|_| StoreError::Corrupt("signature".into()))?,
					operator_sig: b.try_into().map_err(|_| StoreError::Corrupt("signature".into()))?,
					refund_delay_units: r.get::<_, i32>(3) as u16,
					margin: r.get::<_, i64>(4) as u64,
					unlock_hash: array32(r.get(5), "unlock hash")?,
					connector_asset: array32(r.get(6), "connector asset")?,
				},
				round_id: r.get(7),
				participation_id: array32(r.get(8), "participation id")?,
				attempt: r.get::<_, i32>(9) as u32,
			})
		}).collect()
	}

	/// The preimage participation `id` had at `attempt`: its current one, or
	/// one of an earlier attempt.
	pub async fn attempt_preimage(&self, id: &[u8; 32], attempt: u32) -> Result<Option<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(
			"SELECT preimage FROM participation WHERE participation_id = $1 AND attempt = $2
			 UNION ALL SELECT preimage FROM participation_attempt WHERE participation_id = $1 AND attempt = $2",
			&[&&id[..], &(attempt as i32)],
		).await?;
		r.map(|r| array32(r.get(0), "preimage")).transpose()
	}

	/// The participation ids that run forfeit-first and wait for their
	/// forfeits to be claimed: issued, with their forfeits for the round
	/// they are in stored.
	pub async fn forfeit_first_waiting(&self) -> Result<Vec<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT p.participation_id FROM participation p WHERE p.state = 'issued' AND p.forfeit_first
			   AND EXISTS (SELECT 1 FROM forfeit f WHERE f.participation_id = p.participation_id AND f.round_id = p.round_id)
			 ORDER BY p.created_at, p.participation_id",
			&[],
		).await?;
		rows.iter().map(|r| array32(r.get(0), "participation id")).collect()
	}

	/// Every coin a transfer made that is given up in a participation and
	/// has a forfeit stored.
	pub async fn forfeited_transfer_coins(&self) -> Result<Vec<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT DISTINCT l.leaf_id FROM leaf l JOIN forfeit f ON f.leaf_id = l.leaf_id
			 WHERE l.kind = 'transfer' AND l.state = 'spent' ORDER BY l.leaf_id",
			&[],
		).await?;
		rows.iter().map(|r| array32(r.get(0), "leaf id")).collect()
	}
}
