//! Payments over Lightning (`schema/V18__lightning_send.sql`).

use super::{array32, Store, StoreError};

/// Where a payment out of the tree stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendState {
	/// The invoice is being paid, or its outcome is not known yet.
	Paying,
	/// Paid: the preimage is known, and the htlc-1 coin is the operator's.
	Paid,
	/// Failed, with no part of it pending on the node: the coin may go back.
	Failed,
}

impl SendState {
	pub fn name(self) -> &'static str {
		match self {
			SendState::Paying => "paying",
			SendState::Paid => "paid",
			SendState::Failed => "failed",
		}
	}

	fn parse(s: &str) -> Result<SendState, StoreError> {
		match s {
			"paying" => Ok(SendState::Paying),
			"paid" => Ok(SendState::Paid),
			"failed" => Ok(SendState::Failed),
			other => Err(StoreError::Corrupt(format!("a payment in state {:?}", other))),
		}
	}
}

/// One payment out of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendRow {
	pub payment_hash: [u8; 32],
	pub asset: [u8; 32],
	pub invoice: String,
	pub amount: u64,
	pub fee: u64,
	pub transfer_id: [u8; 32],
	pub htlc_leaf_id: [u8; 32],
	pub state: SendState,
	pub preimage: Option<[u8; 32]>,
	pub reason: Option<String>,
}

const COLUMNS: &str = "payment_hash, asset, invoice, amount, fee, transfer_id, htlc_leaf_id, state, preimage, reason";

fn row_of(r: &tokio_postgres::Row) -> Result<SendRow, StoreError> {
	Ok(SendRow {
		payment_hash: array32(r.get(0), "payment hash")?,
		asset: array32(r.get(1), "asset")?,
		invoice: r.get(2),
		amount: r.get::<_, i64>(3) as u64,
		fee: r.get::<_, i64>(4) as u64,
		transfer_id: array32(r.get(5), "transfer id")?,
		htlc_leaf_id: array32(r.get(6), "leaf id")?,
		state: SendState::parse(r.get(7))?,
		preimage: r.get::<_, Option<Vec<u8>>>(8).map(|p| array32(p, "preimage")).transpose()?,
		reason: r.get(9),
	})
}

impl Store {
	/// Records a payment as `paying`, unless one is recorded for its hash
	/// already: then returns that one, whatever it is.
	pub async fn record_send(&self, s: &SendRow) -> Result<SendRow, StoreError> {
		let conn = self.conn().await?;
		conn.execute(
			"INSERT INTO lightning_send (payment_hash, asset, invoice, amount, fee, transfer_id, htlc_leaf_id, state)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, 'paying') ON CONFLICT (payment_hash) DO NOTHING",
			&[&&s.payment_hash[..], &&s.asset[..], &s.invoice, &(s.amount as i64), &(s.fee as i64), &&s.transfer_id[..],
				&&s.htlc_leaf_id[..]],
		).await?;
		drop(conn);
		self.send(&s.payment_hash).await?.ok_or_else(|| StoreError::Corrupt("a payment recorded is gone".into()))
	}

	/// The payment for `payment_hash`.
	pub async fn send(&self, payment_hash: &[u8; 32]) -> Result<Option<SendRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(&format!("SELECT {} FROM lightning_send WHERE payment_hash = $1", COLUMNS), &[&&payment_hash[..]]).await?;
		r.as_ref().map(row_of).transpose()
	}

	/// The payment whose htlc-1 coin is `leaf_id`.
	pub async fn send_of_leaf(&self, leaf_id: &[u8; 32]) -> Result<Option<SendRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(&format!("SELECT {} FROM lightning_send WHERE htlc_leaf_id = $1", COLUMNS), &[&&leaf_id[..]]).await?;
		r.as_ref().map(row_of).transpose()
	}

	/// Every payment still `paying`.
	pub async fn sends_paying(&self) -> Result<Vec<SendRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!("SELECT {} FROM lightning_send WHERE state = 'paying' ORDER BY created_at", COLUMNS), &[]).await?;
		rows.iter().map(row_of).collect()
	}

	/// Every payment `paid`, with its preimage.
	pub async fn sends_paid(&self) -> Result<Vec<SendRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!("SELECT {} FROM lightning_send WHERE state = 'paid' ORDER BY created_at", COLUMNS), &[]).await?;
		rows.iter().map(row_of).collect()
	}

	/// Moves a payment that is `paying` to `paid` with its preimage, or to
	/// `failed` with the reason. A payment decided already stays as it is:
	/// returns whether this call decided it.
	pub async fn decide_send(&self, payment_hash: &[u8; 32], preimage: Option<&[u8; 32]>, reason: Option<&str>)
		-> Result<bool, StoreError>
	{
		let conn = self.conn().await?;
		let state = if preimage.is_some() { "paid" } else { "failed" };
		let n = conn.execute(
			"UPDATE lightning_send SET state = $2, preimage = $3, reason = $4, updated_at = now()
			 WHERE payment_hash = $1 AND state = 'paying'",
			&[&&payment_hash[..], &state, &preimage.map(|p| p.to_vec()), &reason],
		).await?;
		Ok(n == 1)
	}
}

impl Store {
	/// Whether `hash` is an unlock hash of a participation, now or in an
	/// attempt before: a payment over Lightning never takes one, since the
	/// operator hands its preimage out.
	pub async fn is_unlock_hash(&self, hash: &[u8; 32]) -> Result<bool, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_one(
			"SELECT EXISTS (SELECT 1 FROM participation WHERE unlock_hash = $1)
			     OR EXISTS (SELECT 1 FROM participation_attempt WHERE unlock_hash = $1)",
			&[&&hash[..]],
		).await?;
		Ok(r.get(0))
	}
}
