//! The freezes the operator holds in the tree until their lifting is final
//! ([`crate::supervision`]).

use super::{array32, Store, StoreError};

/// A freeze the operator has seen for an asset: of one script, named by the
/// node's hash of it, or the asset's pause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldRow {
	pub asset: [u8; 32],
	/// The node's `targethash` of the frozen script, or
	/// [`crate::supervision::PAUSE`].
	pub target: [u8; 32],
	/// The tip's height when the node last showed it frozen.
	pub seen_frozen_at: u64,
	/// The block at which the node first showed it free, and its height;
	/// `None` while the node shows it frozen.
	pub lifted: Option<([u8; 32], u64)>,
}

const COLUMNS: &str = "asset, target, seen_frozen_at, lifted_hash, lifted_height";

fn hold_row(r: &tokio_postgres::Row) -> Result<HoldRow, StoreError> {
	let lifted = match (r.get::<_, Option<Vec<u8>>>(3), r.get::<_, Option<i64>>(4)) {
		(Some(h), Some(height)) => Some((array32(h, "lifted hash")?, height as u64)),
		_ => None,
	};
	Ok(HoldRow {
		asset: array32(r.get(0), "asset")?,
		target: array32(r.get(1), "target")?,
		seen_frozen_at: r.get::<_, i64>(2) as u64,
		lifted,
	})
}

impl Store {
	/// The hold on `target` for `asset`, if the operator holds one.
	pub async fn supervision_hold(&self, asset: &[u8; 32], target: &[u8; 32]) -> Result<Option<HoldRow>, StoreError> {
		let conn = self.conn().await?;
		let row = conn.query_opt(&format!("SELECT {} FROM supervision_hold WHERE asset = $1 AND target = $2", COLUMNS),
			&[&&asset[..], &&target[..]]).await?;
		row.as_ref().map(hold_row).transpose()
	}

	/// Every hold the operator keeps for `asset`.
	pub async fn supervision_holds_of(&self, asset: &[u8; 32]) -> Result<Vec<HoldRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!("SELECT {} FROM supervision_hold WHERE asset = $1 ORDER BY target", COLUMNS),
			&[&&asset[..]]).await?;
		rows.iter().map(hold_row).collect()
	}

	/// Every hold the operator keeps.
	pub async fn supervision_holds(&self) -> Result<Vec<HoldRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!("SELECT {} FROM supervision_hold ORDER BY asset, target", COLUMNS), &[]).await?;
		rows.iter().map(hold_row).collect()
	}

	/// Records that the node shows `target` frozen for `asset` at height
	/// `height`: any lifting seen before is forgotten.
	pub async fn hold_frozen(&self, asset: &[u8; 32], target: &[u8; 32], height: u64) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute(
			"INSERT INTO supervision_hold (asset, target, seen_frozen_at) VALUES ($1, $2, $3)
			 ON CONFLICT (asset, target) DO UPDATE SET seen_frozen_at = $3, lifted_hash = NULL, lifted_height = NULL",
			&[&&asset[..], &&target[..], &(height as i64)],
		).await?;
		Ok(())
	}

	/// Records the block at which the node first showed `target` free.
	pub async fn hold_lifted_at(&self, asset: &[u8; 32], target: &[u8; 32], hash: &[u8; 32], height: u64) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute(
			"UPDATE supervision_hold SET lifted_hash = $3, lifted_height = $4 WHERE asset = $1 AND target = $2",
			&[&&asset[..], &&target[..], &&hash[..], &(height as i64)],
		).await?;
		Ok(())
	}

	/// Drops the hold: its lifting is final.
	pub async fn drop_hold(&self, asset: &[u8; 32], target: &[u8; 32]) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute("DELETE FROM supervision_hold WHERE asset = $1 AND target = $2", &[&&asset[..], &&target[..]]).await?;
		Ok(())
	}
}
