//! Resting orders and their fills in the tree ([`crate::orders`]).
//!
//! A resting order is recorded when its maker publishes it: the coin a round
//! made of it, the record of that coin as the maker handed it over, the
//! nonces of its credit keys, its mailbox, and the coin it rests at now. A
//! fill is a transfer (the taker's coins through their checkpoints, the
//! fill's outputs as the transfer's) recorded together with the spend of the
//! order's coin and a row naming the order coin it spends, in one database
//! transaction, before anything of it is signed ([`Store::record_order_fill`]);
//! the order coin is spent by one fill at most, which the database's unique
//! key holds whatever the timing.
//!
//! A resting order refreshed in a round goes on at the coin the round made
//! of it ([`Store::continue_resting_order`]): its row takes that coin's
//! record, credit keys and mailbox, keeps its id, and counts the fills made
//! before (`fills_before`), so the new coin's credit keys are counted from
//! its own first fill.

use super::transfers::{record_transfer_in, NewReassignment, NewTransferInput, NewTransferOutput};
use super::{array32, Store, StoreError};

/// A resting order as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestingOrderRow {
	/// The leaf id of the coin a round made of the order.
	pub order_id: [u8; 32],
	pub maker_key: [u8; 32],
	pub mailbox_key: [u8; 32],
	/// The record of the first coin of its current lineage (the coin a round
	/// made of it, first or at its latest refresh), as the maker handed it
	/// over.
	pub record: Vec<u8>,
	/// The nonces of that coin's four credit keys, the first credit's first.
	pub credit_nonces: [[u8; 32]; 4],
	/// The coin it rests at now: a coin a round made of it, or a fill's
	/// remainder.
	pub current_leaf: [u8; 32],
	/// The coin record formats its maker's wallet reads, as it named them
	/// when it published the order; none for an older build.
	pub record_formats: Vec<String>,
	/// How many fills the order made before its current lineage began (at
	/// its latest refresh): the current lineage's fills are counted from
	/// there.
	pub fills_before: u32,
}

impl RestingOrderRow {
	/// The leaf id of the first coin of the order's current lineage: the coin
	/// whose record [`RestingOrderRow::record`] is.
	pub fn record_leaf(&self) -> Option<[u8; 32]> {
		match arca_covenant::CoinRecord::from_bytes(&self.record).ok()? {
			arca_covenant::CoinRecord::Leaf { record, .. } => record.leaf_id().ok().map(|l| l.0),
			_ => None,
		}
	}
}

/// A fill of a resting order made in the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderFillRow {
	/// The id of the transfer that is the fill.
	pub transfer_id: [u8; 32],
	pub order_id: [u8; 32],
	/// The order coin it spends.
	pub order_leaf: [u8; 32],
	/// Its place along the order's lineage, from 0.
	pub seq: u32,
	pub filled: u64,
	pub credited: u64,
	pub partial: bool,
	/// The outputs the operator's signature commits to.
	pub m: u8,
	/// The operator's fill signature, once made.
	pub signature: Option<[u8; 64]>,
}

/// A fill to record.
#[derive(Debug, Clone)]
pub struct NewOrderFill {
	pub order_id: [u8; 32],
	pub order_leaf: [u8; 32],
	pub seq: u32,
	pub filled: u64,
	pub credited: u64,
	pub partial: bool,
	pub m: u8,
	/// The fill's request as its taker sent it
	/// ([`crate::orders::FillRequest::to_bytes`]).
	pub request: Vec<u8>,
}

fn nonces(b: Vec<u8>) -> Result<[[u8; 32]; 4], StoreError> {
	if b.len() != 128 {
		return Err(StoreError::Corrupt(format!("credit nonces of {} bytes", b.len())));
	}
	let mut out = [[0u8; 32]; 4];
	for (i, c) in b.chunks(32).enumerate() {
		out[i].copy_from_slice(c);
	}
	Ok(out)
}

fn order_row(r: &tokio_postgres::Row) -> Result<RestingOrderRow, StoreError> {
	Ok(RestingOrderRow {
		order_id: array32(r.get(0), "order id")?,
		maker_key: array32(r.get(1), "maker key")?,
		mailbox_key: array32(r.get(2), "mailbox key")?,
		record: r.get(3),
		credit_nonces: nonces(r.get(4))?,
		current_leaf: array32(r.get(5), "current leaf")?,
		record_formats: r.get(6),
		fills_before: r.get::<_, i32>(7) as u32,
	})
}

fn fill_row(r: &tokio_postgres::Row) -> Result<OrderFillRow, StoreError> {
	let sig: Option<Vec<u8>> = r.get(8);
	Ok(OrderFillRow {
		transfer_id: array32(r.get(0), "transfer id")?,
		order_id: array32(r.get(1), "order id")?,
		order_leaf: array32(r.get(2), "order leaf")?,
		seq: r.get::<_, i32>(3) as u32,
		filled: r.get::<_, i64>(4) as u64,
		credited: r.get::<_, i64>(5) as u64,
		partial: r.get(6),
		m: r.get::<_, i16>(7) as u8,
		signature: sig.map(|s| s.try_into().map_err(|_| StoreError::Corrupt("a fill signature".into()))).transpose()?,
	})
}

const ORDER_COLUMNS: &str = "order_id, maker_key, mailbox_key, record, credit_nonces, current_leaf, record_formats, fills_before";
const FILL_COLUMNS: &str = "transfer_id, order_id, order_leaf, seq, filled, credited, partial, m, signature";

impl Store {
	/// Records the resting order whose first coin is `order_id`, unless it is
	/// recorded already; returns it as recorded.
	pub async fn insert_resting_order(&self, order_id: &[u8; 32], maker_key: &[u8; 32], mailbox_key: &[u8; 32], record: &[u8],
		credit_nonces: &[[u8; 32]; 4], record_formats: &[String]) -> Result<RestingOrderRow, StoreError>
	{
		let conn = self.conn().await?;
		let n: Vec<u8> = credit_nonces.iter().flatten().copied().collect();
		conn.execute(
			"INSERT INTO resting_order (order_id, maker_key, mailbox_key, record, credit_nonces, current_leaf, record_formats)
			 VALUES ($1, $2, $3, $4, $5, $1, $6) ON CONFLICT (order_id) DO NOTHING",
			&[&&order_id[..], &&maker_key[..], &&mailbox_key[..], &record, &n, &record_formats],
		).await?;
		drop(conn);
		self.resting_order(order_id).await?.ok_or_else(|| StoreError::Corrupt("a resting order just recorded is gone".into()))
	}

	/// The resting order `order_id`.
	pub async fn resting_order(&self, order_id: &[u8; 32]) -> Result<Option<RestingOrderRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(&format!("SELECT {} FROM resting_order WHERE order_id = $1", ORDER_COLUMNS), &[&&order_id[..]]).await?;
		r.map(|r| order_row(&r)).transpose()
	}

	/// Every resting order whose coin it rests at now is live: one a taker
	/// could fill, and one its maker could still cancel, refresh or land.
	pub async fn live_resting_orders(&self) -> Result<Vec<RestingOrderRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!(
			"SELECT {} FROM resting_order r WHERE EXISTS (SELECT 1 FROM leaf l WHERE l.leaf_id = r.current_leaf AND l.state = 'live')
			 ORDER BY r.order_id", ORDER_COLUMNS.split(", ").map(|c| format!("r.{}", c)).collect::<Vec<_>>().join(", ")), &[]).await?;
		rows.iter().map(order_row).collect()
	}

	/// The resting order a coin is a coin of: its first coin, a coin a fill of
	/// it spent, a coin a refresh of it gave up or made, or the coin it rests
	/// at now.
	pub async fn resting_order_of_leaf(&self, leaf_id: &[u8; 32]) -> Result<Option<RestingOrderRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(&format!(
			"SELECT {} FROM resting_order WHERE order_id = $1 OR current_leaf = $1
			 OR order_id = (SELECT order_id FROM order_fill WHERE order_leaf = $1)
			 OR order_id = (SELECT order_id FROM resting_order_refresh WHERE to_leaf = $1 OR from_leaf = $1 LIMIT 1)", ORDER_COLUMNS),
			&[&&leaf_id[..]]).await?;
		r.map(|r| order_row(&r)).transpose()
	}

	/// The participations that give up, or gave up, the coin `leaf_id` and
	/// may still run or ran (none void or expired), the latest first.
	pub async fn participations_giving_up(&self, leaf_id: &[u8; 32]) -> Result<Vec<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT i.participation_id FROM participation_input i JOIN participation p USING (participation_id)
			 WHERE i.leaf_id = $1 AND i.active AND p.state NOT IN ('void', 'expired') ORDER BY p.created_at DESC",
			&[&&leaf_id[..]]).await?;
		rows.iter().map(|r| array32(r.get(0), "participation id")).collect()
	}

	/// The participation whose round made the leaf `leaf_id`, if a
	/// participation's did.
	pub async fn participation_making(&self, leaf_id: &[u8; 32]) -> Result<Option<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt("SELECT participation_id FROM participation_output WHERE leaf_id = $1", &[&&leaf_id[..]]).await?;
		r.map(|r| array32(r.get(0), "participation id")).transpose()
	}

	/// The resting order `order_id`, resting at `from_leaf`, goes on at
	/// `to_leaf`, a coin a refresh of it made: its row takes that coin's
	/// record, credit nonces, maker key, mailbox and record formats, and the
	/// fills made so far are counted as before its new lineage. All or
	/// nothing; refused when the order rests elsewhere by now
	/// ([`StoreError::LeafSpent`] of `from_leaf`). Returns the row.
	#[allow(clippy::too_many_arguments)]
	pub async fn continue_resting_order(&self, order_id: &[u8; 32], from_leaf: &[u8; 32], to_leaf: &[u8; 32], maker_key: &[u8; 32],
		mailbox_key: &[u8; 32], record: &[u8], credit_nonces: &[[u8; 32]; 4], record_formats: &[String]) -> Result<RestingOrderRow, StoreError>
	{
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let fills: i64 = t.query_one("SELECT count(*) FROM order_fill WHERE order_id = $1", &[&&order_id[..]]).await?.get(0);
		let fills = fills as i32;
		let n: Vec<u8> = credit_nonces.iter().flatten().copied().collect();
		let moved = t.execute(
			"UPDATE resting_order SET maker_key = $3, mailbox_key = $4, record = $5, credit_nonces = $6, current_leaf = $7,
			 record_formats = $8, fills_before = $9, updated_at = now() WHERE order_id = $1 AND current_leaf = $2",
			&[&&order_id[..], &&from_leaf[..], &&maker_key[..], &&mailbox_key[..], &record, &n, &&to_leaf[..], &record_formats, &fills],
		).await?;
		if moved != 1 {
			return Err(StoreError::LeafSpent(super::hex(from_leaf)));
		}
		t.execute("INSERT INTO resting_order_refresh (to_leaf, order_id, from_leaf, fills_before) VALUES ($1, $2, $3, $4)",
			&[&&to_leaf[..], &&order_id[..], &&from_leaf[..], &fills]).await?;
		t.commit().await?;
		self.resting_order(order_id).await?.ok_or_else(|| StoreError::Corrupt("a resting order just continued is gone".into()))
	}

	/// Every fill of the resting order `order_id`, in the order they were made.
	pub async fn order_fills(&self, order_id: &[u8; 32]) -> Result<Vec<OrderFillRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!("SELECT {} FROM order_fill WHERE order_id = $1 ORDER BY seq", FILL_COLUMNS),
			&[&&order_id[..]]).await?;
		rows.iter().map(fill_row).collect()
	}

	/// Every fill recorded and not signed, the oldest first: its transfer's
	/// id and the request it was recorded from, when it was kept.
	pub async fn unsigned_order_fills(&self) -> Result<Vec<([u8; 32], Option<Vec<u8>>)>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query("SELECT transfer_id, request FROM order_fill WHERE signature IS NULL ORDER BY created_at, transfer_id", &[]).await?;
		rows.iter().map(|r| Ok((super::array32(r.get(0), "transfer id")?, r.get(1)))).collect()
	}

	/// The fill that spends the order coin `order_leaf`, if any.
	pub async fn order_fill_of(&self, order_leaf: &[u8; 32]) -> Result<Option<OrderFillRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(&format!("SELECT {} FROM order_fill WHERE order_leaf = $1", FILL_COLUMNS), &[&&order_leaf[..]]).await?;
		r.map(|r| fill_row(&r)).transpose()
	}

	/// The fill that is the transfer `transfer_id`, if it is one.
	pub async fn order_fill_by_transfer(&self, transfer_id: &[u8; 32]) -> Result<Option<OrderFillRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(&format!("SELECT {} FROM order_fill WHERE transfer_id = $1", FILL_COLUMNS), &[&&transfer_id[..]]).await?;
		r.map(|r| fill_row(&r)).transpose()
	}

	/// Records a fill before anything of it is signed: its transfer (as
	/// [`Store::record_transfer`] records one), the order coin spent by it,
	/// and its row, all or nothing. Refuses an order coin that is not live
	/// or already spent, by this fill or another.
	#[allow(clippy::too_many_arguments)]
	pub async fn record_order_fill<F>(&self, transfer_id: &[u8; 32], reassignment: &NewReassignment, admit: F,
		inputs: &[NewTransferInput], outputs: &[NewTransferOutput], messages: &[super::SignerMessage], fill: &NewOrderFill)
		-> Result<(), StoreError>
	where
		F: FnOnce(&[(Vec<u8>, Vec<u8>)]) -> Result<(), String>,
	{
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let spent = t.execute("UPDATE leaf SET state = 'spent', spent_by = $2, updated_at = now() WHERE leaf_id = $1 AND state = 'live'",
			&[&&fill.order_leaf[..], &&transfer_id[..]]).await?;
		if spent != 1 {
			return Err(StoreError::LeafSpent(super::hex(&fill.order_leaf)));
		}
		record_transfer_in(&t, transfer_id, reassignment, admit, inputs, outputs, messages).await?;
		let r = t.execute(
			"INSERT INTO order_fill (transfer_id, order_id, order_leaf, seq, filled, credited, partial, m, request)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
			&[&&transfer_id[..], &&fill.order_id[..], &&fill.order_leaf[..], &(fill.seq as i32), &(fill.filled as i64),
				&(fill.credited as i64), &fill.partial, &(fill.m as i16), &fill.request],
		).await;
		if let Err(e) = r {
			if StoreError::is_unique(&e, "order_fill_order_leaf_key") || StoreError::is_unique(&e, "order_fill_order_id_seq_key") {
				return Err(StoreError::LeafSpent(super::hex(&fill.order_leaf)));
			}
			return Err(e.into());
		}
		t.commit().await?;
		Ok(())
	}

	/// The operator's signature over the fill `transfer_id`, once made; the
	/// order now rests at `rests_at` (the fill's remainder) when the fill was
	/// partial.
	pub async fn sign_order_fill(&self, transfer_id: &[u8; 32], signature: &[u8; 64], rests_at: Option<[u8; 32]>) -> Result<(), StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let r = t.query_one("UPDATE order_fill SET signature = $2 WHERE transfer_id = $1 RETURNING order_id",
			&[&&transfer_id[..], &&signature[..]]).await?;
		let order_id: Vec<u8> = r.get(0);
		if let Some(leaf) = rests_at {
			t.execute("UPDATE resting_order SET current_leaf = $2, updated_at = now() WHERE order_id = $1",
				&[&order_id, &&leaf[..]]).await?;
		}
		t.commit().await?;
		Ok(())
	}

	/// Drops a fill recorded and never signed: its transfer (and so its
	/// taker's coins back) as [`Store::drop_transfer`] drops one, the order
	/// coin given back, and its row.
	/// What a maker's delegation of its order coin into fill `transfer_id`
	/// is checked against: the request kept with the fill, when it was kept,
	/// and the outputs its reassignment commits to, as `cosign` encodes them.
	pub async fn order_fill_terms(&self, transfer_id: &[u8; 32]) -> Result<Option<(Option<Vec<u8>>, Vec<u8>)>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(
			"SELECT f.request, r.outputs FROM order_fill f JOIN reassignment r USING (transfer_id) WHERE f.transfer_id = $1",
			&[&&transfer_id[..]]).await?;
		Ok(r.map(|r| (r.get(0), r.get(1))))
	}

	pub async fn drop_order_fill(&self, transfer_id: &[u8; 32], reason: &str) -> Result<(), StoreError> {
		let Some(f) = self.order_fill_by_transfer(transfer_id).await? else { return Ok(()) };
		if f.signature.is_some() {
			return Ok(());
		}
		{
			let conn = self.conn().await?;
			conn.execute("DELETE FROM order_fill WHERE transfer_id = $1 AND signature IS NULL", &[&&transfer_id[..]]).await?;
			conn.execute("UPDATE leaf SET state = 'live', spent_by = NULL, updated_at = now() WHERE leaf_id = $1 AND spent_by = $2",
				&[&&f.order_leaf[..], &&transfer_id[..]]).await?;
		}
		self.drop_transfer(transfer_id, reason).await?;
		Ok(())
	}
}
