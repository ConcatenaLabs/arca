//! Boards: registered, credited when final, uncredited when a rollback takes
//! them out.

use super::coins::insert_coin;
use super::{array32, NewCoin, Store, StoreError};

/// Where a board stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoardState {
	/// Registered; its transaction is not final.
	Pending,
	/// Final: its leaf is live.
	Credited,
	/// Its transaction can no longer confirm.
	Lost,
}

impl BoardState {
	fn as_str(self) -> &'static str {
		match self {
			BoardState::Pending => "pending",
			BoardState::Credited => "credited",
			BoardState::Lost => "lost",
		}
	}

	fn parse(s: &str) -> Result<BoardState, StoreError> {
		Ok(match s {
			"pending" => BoardState::Pending,
			"credited" => BoardState::Credited,
			"lost" => BoardState::Lost,
			other => return Err(StoreError::Corrupt(format!("board state {}", other))),
		})
	}
}

/// A board as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardRow {
	pub leaf_id: [u8; 32],
	/// The board record, binary form.
	pub record: Vec<u8>,
	pub txid: [u8; 32],
	pub vout: u32,
	/// The board transaction.
	pub tx: Vec<u8>,
	pub state: BoardState,
	pub credits: i32,
	pub uncredits: i32,
}

const BOARD_COLUMNS: &str = "leaf_id, record, txid, vout, tx, state::text, credits, uncredits";

fn board_row(r: &tokio_postgres::Row) -> Result<BoardRow, StoreError> {
	Ok(BoardRow {
		leaf_id: array32(r.get(0), "leaf id")?,
		record: r.get(1),
		txid: array32(r.get(2), "txid")?,
		vout: r.get::<_, i32>(3) as u32,
		tx: r.get(4),
		state: BoardState::parse(r.get(5))?,
		credits: r.get(6),
		uncredits: r.get(7),
	})
}

impl Store {
	/// Registers a board: its coin (taking its operator nonce and recording
	/// its scripts), the board with its transaction, and its output watched
	/// for a spend. All or nothing.
	pub async fn insert_board(&self, coin: &NewCoin, record: &[u8], txid: &[u8; 32], vout: u32, tx: &[u8])
		-> Result<(), StoreError>
	{
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		insert_coin(&t, coin).await?;
		t.execute(
			"INSERT INTO board (leaf_id, record, txid, vout, tx, state) VALUES ($1, $2, $3, $4, $5, 'pending')",
			&[&&coin.leaf_id[..], &record, &&txid[..], &(vout as i32), &tx],
		).await?;
		t.execute(
			"INSERT INTO watched_outpoint (txid, vout, kind, watched_for) VALUES ($1, $2, 'board', $3) ON CONFLICT DO NOTHING",
			&[&&txid[..], &(vout as i32), &&coin.leaf_id[..]],
		).await?;
		t.commit().await?;
		Ok(())
	}

	pub async fn board(&self, leaf_id: &[u8; 32]) -> Result<Option<BoardRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(&format!("SELECT {} FROM board WHERE leaf_id = $1", BOARD_COLUMNS), &[&&leaf_id[..]]).await?;
		r.as_ref().map(board_row).transpose()
	}

	pub async fn boards_by_txid(&self, txid: &[u8; 32]) -> Result<Vec<BoardRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!("SELECT {} FROM board WHERE txid = $1", BOARD_COLUMNS), &[&&txid[..]]).await?;
		rows.iter().map(board_row).collect()
	}

	pub async fn boards_in(&self, state: BoardState) -> Result<Vec<BoardRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!("SELECT {} FROM board WHERE state = $1::text::board_state ORDER BY created_at", BOARD_COLUMNS),
			&[&state.as_str()]).await?;
		rows.iter().map(board_row).collect()
	}

	/// Credits a pending board: its leaf becomes live, unless spent already.
	/// Returns whether it was pending.
	pub async fn credit_board(&self, leaf_id: &[u8; 32]) -> Result<bool, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let n = t.execute(
			"UPDATE board SET state = 'credited', credits = credits + 1, credited_at = now()
			 WHERE leaf_id = $1 AND state = 'pending'",
			&[&&leaf_id[..]],
		).await?;
		if n == 1 {
			t.execute("UPDATE leaf SET state = 'live', updated_at = now() WHERE leaf_id = $1 AND state = 'pending'",
				&[&&leaf_id[..]]).await?;
		}
		t.commit().await?;
		Ok(n == 1)
	}

	/// Takes the credit back from a board a rollback took out: its leaf is no
	/// longer live, unless spent already. Returns whether it was credited.
	pub async fn uncredit_board(&self, leaf_id: &[u8; 32]) -> Result<bool, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let n = t.execute(
			"UPDATE board SET state = 'pending', uncredits = uncredits + 1, credited_at = NULL
			 WHERE leaf_id = $1 AND state = 'credited'",
			&[&&leaf_id[..]],
		).await?;
		if n == 1 {
			t.execute("UPDATE leaf SET state = 'pending', updated_at = now() WHERE leaf_id = $1 AND state = 'live'",
				&[&&leaf_id[..]]).await?;
		}
		t.commit().await?;
		Ok(n == 1)
	}

	/// The boards registered more than `seconds` ago, still pending and never
	/// credited: their transaction has not been final once since.
	pub async fn boards_never_credited(&self, seconds: u64) -> Result<Vec<BoardRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!(
			"SELECT {} FROM board WHERE state = 'pending' AND credits = 0 AND created_at < now() - make_interval(secs => $1)
			 ORDER BY created_at", BOARD_COLUMNS), &[&(seconds as f64)]).await?;
		rows.iter().map(board_row).collect()
	}

	/// Marks a board lost: its transaction can no longer confirm.
	pub async fn lose_board(&self, leaf_id: &[u8; 32]) -> Result<(), StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		t.execute("UPDATE board SET state = 'lost', credited_at = NULL WHERE leaf_id = $1", &[&&leaf_id[..]]).await?;
		t.execute("UPDATE leaf SET state = 'lost', updated_at = now() WHERE leaf_id = $1 AND state IN ('pending', 'live')",
			&[&&leaf_id[..]]).await?;
		t.commit().await?;
		Ok(())
	}
}
