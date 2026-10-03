//! The nursery's transactions, and the outpoints watched for spends.

use super::{array32, Store, StoreError};

/// Where a transaction in the nursery stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NurseryState {
	/// Kept broadcast until final.
	Pending,
	/// Certified and its anchor buried; watched still, since a rollback can
	/// take it out again.
	Final,
	/// An input is spent by another transaction that is final: it can no
	/// longer confirm.
	Lost,
}

impl NurseryState {
	pub(crate) fn as_str(self) -> &'static str {
		match self {
			NurseryState::Pending => "pending",
			NurseryState::Final => "final",
			NurseryState::Lost => "lost",
		}
	}

	pub(crate) fn parse(s: &str) -> Result<NurseryState, StoreError> {
		Ok(match s {
			"pending" => NurseryState::Pending,
			"final" => NurseryState::Final,
			"lost" => NurseryState::Lost,
			other => return Err(StoreError::Corrupt(format!("nursery state {}", other))),
		})
	}
}

/// A transaction in the nursery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NurseryRow {
	pub txid: [u8; 32],
	/// The transaction, byte for byte as it was taken in.
	pub tx: Vec<u8>,
	pub kind: String,
	/// The fee asset and amount a transaction the server built names.
	pub fee: Option<([u8; 32], u64)>,
	pub state: NurseryState,
	pub broadcasts: i32,
	pub last_result: Option<String>,
}

const NURSERY_COLUMNS: &str = "txid, tx, kind, fee_asset, fee, state::text, broadcasts, last_result";

fn nursery_row(r: &tokio_postgres::Row) -> Result<NurseryRow, StoreError> {
	let fee_asset: Option<Vec<u8>> = r.get(3);
	let fee: Option<i64> = r.get(4);
	Ok(NurseryRow {
		txid: array32(r.get(0), "txid")?,
		tx: r.get(1),
		kind: r.get(2),
		fee: match (fee_asset, fee) {
			(Some(a), Some(f)) => Some((array32(a, "fee asset")?, f as u64)),
			_ => None,
		},
		state: NurseryState::parse(r.get(5))?,
		broadcasts: r.get(6),
		last_result: r.get(7),
	})
}

impl Store {
	/// Takes a transaction into the nursery, with the outpoints it spends
	/// watched for spends. A transaction already there keeps the bytes it was
	/// first taken in with; returns whether it was new.
	pub async fn nursery_insert(&self, txid: &[u8; 32], tx: &[u8], kind: &str, fee: Option<([u8; 32], u64)>,
		inputs: &[([u8; 32], u32)]) -> Result<bool, StoreError>
	{
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let (fee_asset, fee) = match fee {
			Some((a, f)) => (Some(a.to_vec()), Some(i64::try_from(f).map_err(|_| StoreError::Corrupt(format!("fee {}", f)))?)),
			None => (None, None),
		};
		let n = t.execute(
			"INSERT INTO nursery_tx (txid, tx, kind, fee_asset, fee) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
			&[&&txid[..], &tx, &kind, &fee_asset, &fee],
		).await?;
		for (pt, pv) in inputs {
			t.execute(
				"INSERT INTO watched_outpoint (txid, vout, kind, watched_for) VALUES ($1, $2, 'nursery', $3)
				 ON CONFLICT DO NOTHING",
				&[&&pt[..], &(*pv as i32), &&txid[..]],
			).await?;
		}
		t.commit().await?;
		Ok(n == 1)
	}

	pub async fn nursery_get(&self, txid: &[u8; 32]) -> Result<Option<NurseryRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(&format!("SELECT {} FROM nursery_tx WHERE txid = $1", NURSERY_COLUMNS), &[&&txid[..]]).await?;
		r.as_ref().map(nursery_row).transpose()
	}

	/// The transactions in `state`, oldest first, so a parent goes out
	/// before its child.
	pub async fn nursery_in(&self, state: NurseryState) -> Result<Vec<NurseryRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			&format!("SELECT {} FROM nursery_tx WHERE state = $1::text::nursery_state ORDER BY created_at, txid", NURSERY_COLUMNS),
			&[&state.as_str()],
		).await?;
		rows.iter().map(nursery_row).collect()
	}

	pub async fn nursery_set_state(&self, txid: &[u8; 32], state: NurseryState) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute("UPDATE nursery_tx SET state = $2::text::nursery_state WHERE txid = $1", &[&&txid[..], &state.as_str()]).await?;
		Ok(())
	}

	/// Records a broadcast of `txid` and what the node said.
	pub async fn nursery_broadcast(&self, txid: &[u8; 32], result: &str) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute(
			"UPDATE nursery_tx SET broadcasts = broadcasts + 1, last_broadcast_at = now(), last_result = $2 WHERE txid = $1",
			&[&&txid[..], &result],
		).await?;
		Ok(())
	}

	/// The transactions seen spending `txid`'s inputs that are not `txid`.
	pub async fn conflicting_spends(&self, txid: &[u8; 32]) -> Result<Vec<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT DISTINCT spent_by FROM watched_outpoint WHERE kind = 'nursery' AND watched_for = $1
			 AND spent_by IS NOT NULL AND spent_by <> $1",
			&[&&txid[..]],
		).await?;
		rows.iter().map(|r| array32(r.get(0), "spending txid")).collect()
	}

	/// Watches the outpoint `txid:vout` for a spend, on behalf of `watched_for`.
	pub async fn watch_outpoint(&self, txid: &[u8; 32], vout: u32, kind: &str, watched_for: &[u8; 32]) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute(
			"INSERT INTO watched_outpoint (txid, vout, kind, watched_for) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
			&[&&txid[..], &(vout as i32), &kind, &&watched_for[..]],
		).await?;
		Ok(())
	}

	/// The transaction seen spending `txid:vout`, if any.
	pub async fn outpoint_spender(&self, txid: &[u8; 32], vout: u32) -> Result<Option<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt("SELECT spent_by FROM watched_outpoint WHERE txid = $1 AND vout = $2", &[&&txid[..], &(vout as i32)]).await?;
		match r {
			Some(r) => r.get::<_, Option<Vec<u8>>>(0).map(|v| array32(v, "spending txid")).transpose(),
			None => Ok(None),
		}
	}
}
