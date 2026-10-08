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

/// Where a payment into the tree stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveState {
	/// The invoice is out; nothing is held.
	Open,
	/// The payment is held at the node, and its leaf wanted in a round.
	Accepted,
	/// The preimage is known: the payment is the operator's to settle.
	Claimed,
	/// The payment was failed back, or is to be.
	Cancelled,
}

impl ReceiveState {
	pub fn name(self) -> &'static str {
		match self {
			ReceiveState::Open => "open",
			ReceiveState::Accepted => "accepted",
			ReceiveState::Claimed => "claimed",
			ReceiveState::Cancelled => "cancelled",
		}
	}

	fn parse(s: &str) -> Result<ReceiveState, StoreError> {
		match s {
			"open" => Ok(ReceiveState::Open),
			"accepted" => Ok(ReceiveState::Accepted),
			"claimed" => Ok(ReceiveState::Claimed),
			"cancelled" => Ok(ReceiveState::Cancelled),
			other => Err(StoreError::Corrupt(format!("a receive in state {:?}", other))),
		}
	}
}

/// A payment into the tree to record, `open`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReceive {
	pub payment_hash: [u8; 32],
	pub asset: [u8; 32],
	pub amount: u64,
	pub fee: u64,
	pub invoice: String,
	pub expires_at: u64,
	pub owner_key: [u8; 32],
	pub owner_nonce: [u8; 32],
	pub exit_delay_units: u16,
}

/// One payment into the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveRow {
	pub new: NewReceive,
	pub state: ReceiveState,
	pub participation_id: Option<[u8; 32]>,
	pub timeout: Option<u32>,
	pub htlc_expiry: Option<u32>,
	pub preimage: Option<[u8; 32]>,
	pub settled: bool,
	pub failed_back: bool,
	pub reason: Option<String>,
}

const RECEIVE_COLUMNS: &str = "payment_hash, asset, amount, fee, invoice, expires_at, owner_key, owner_nonce, exit_delay_units, state, \
	participation_id, timeout, htlc_expiry, preimage, settled, failed_back, reason";

fn receive_of(r: &tokio_postgres::Row) -> Result<ReceiveRow, StoreError> {
	Ok(ReceiveRow {
		new: NewReceive {
			payment_hash: array32(r.get(0), "payment hash")?,
			asset: array32(r.get(1), "asset")?,
			amount: r.get::<_, i64>(2) as u64,
			fee: r.get::<_, i64>(3) as u64,
			invoice: r.get(4),
			expires_at: r.get::<_, i64>(5) as u64,
			owner_key: array32(r.get(6), "owner key")?,
			owner_nonce: array32(r.get(7), "owner nonce")?,
			exit_delay_units: r.get::<_, i32>(8) as u16,
		},
		state: ReceiveState::parse(r.get(9))?,
		participation_id: r.get::<_, Option<Vec<u8>>>(10).map(|p| array32(p, "participation id")).transpose()?,
		timeout: r.get::<_, Option<i64>>(11).map(|t| t as u32),
		htlc_expiry: r.get::<_, Option<i64>>(12).map(|t| t as u32),
		preimage: r.get::<_, Option<Vec<u8>>>(13).map(|p| array32(p, "preimage")).transpose()?,
		settled: r.get(14),
		failed_back: r.get(15),
		reason: r.get(16),
	})
}

impl Store {
	/// Records a payment into the tree, `open`, unless one is recorded for
	/// its hash already: then returns that one, whatever it is.
	pub async fn insert_receive(&self, n: &NewReceive) -> Result<ReceiveRow, StoreError> {
		let conn = self.conn().await?;
		let r = conn.execute(
			"INSERT INTO lightning_receive (payment_hash, asset, amount, fee, invoice, expires_at, owner_key, owner_nonce, exit_delay_units,
			 state) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'open') ON CONFLICT (payment_hash) DO NOTHING",
			&[&&n.payment_hash[..], &&n.asset[..], &(n.amount as i64), &(n.fee as i64), &n.invoice, &(n.expires_at as i64),
				&&n.owner_key[..], &&n.owner_nonce[..], &(n.exit_delay_units as i32)],
		).await;
		if let Err(e) = r {
			if StoreError::is_unique(&e, "lightning_receive_owner_key_key") {
				return Err(StoreError::KeyReused);
			}
			return Err(e.into());
		}
		drop(conn);
		self.receive(&n.payment_hash).await?.ok_or_else(|| StoreError::Corrupt("a receive recorded is gone".into()))
	}

	/// The payment into the tree for `payment_hash`.
	pub async fn receive(&self, payment_hash: &[u8; 32]) -> Result<Option<ReceiveRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(&format!("SELECT {} FROM lightning_receive WHERE payment_hash = $1", RECEIVE_COLUMNS),
			&[&&payment_hash[..]]).await?;
		r.as_ref().map(receive_of).transpose()
	}

	/// Whether a payment into the tree wants a leaf under `key`.
	pub async fn receive_key(&self, key: &[u8; 32]) -> Result<bool, StoreError> {
		let conn = self.conn().await?;
		Ok(conn.query_opt("SELECT 1 FROM lightning_receive WHERE owner_key = $1", &[&&key[..]]).await?.is_some())
	}

	/// Every payment into the tree in `state`, oldest first.
	pub async fn receives_in(&self, state: ReceiveState) -> Result<Vec<ReceiveRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!("SELECT {} FROM lightning_receive WHERE state = $1 ORDER BY created_at", RECEIVE_COLUMNS),
			&[&state.name()]).await?;
		rows.iter().map(receive_of).collect()
	}

	/// Every payment into the tree the node has yet to resolve: claimed and
	/// not settled, or cancelled and not failed back.
	pub async fn receives_unresolved(&self) -> Result<Vec<ReceiveRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!("SELECT {} FROM lightning_receive
			WHERE (state = 'claimed' AND NOT settled) OR (state = 'cancelled' AND NOT failed_back) ORDER BY created_at", RECEIVE_COLUMNS),
			&[]).await?;
		rows.iter().map(receive_of).collect()
	}

	/// Moves an `open` payment to `accepted`: held, its leaf wanted by the
	/// participation `participation_id`, timing out at `timeout`. Returns
	/// whether this call moved it.
	pub async fn accept_receive(&self, payment_hash: &[u8; 32], participation_id: &[u8; 32], timeout: u32, htlc_expiry: u32)
		-> Result<bool, StoreError>
	{
		let conn = self.conn().await?;
		let n = conn.execute(
			"UPDATE lightning_receive SET state = 'accepted', participation_id = $2, timeout = $3, htlc_expiry = $4, updated_at = now()
			 WHERE payment_hash = $1 AND state = 'open'",
			&[&&payment_hash[..], &&participation_id[..], &(timeout as i64), &(htlc_expiry as i64)],
		).await?;
		Ok(n == 1)
	}

	/// Records the preimage of an `accepted` payment: `claimed`. Returns
	/// whether this call recorded it.
	pub async fn claim_receive(&self, payment_hash: &[u8; 32], preimage: &[u8; 32]) -> Result<bool, StoreError> {
		let conn = self.conn().await?;
		let n = conn.execute(
			"UPDATE lightning_receive SET state = 'claimed', preimage = $2, updated_at = now() WHERE payment_hash = $1 AND state = 'accepted'",
			&[&&payment_hash[..], &&preimage[..]],
		).await?;
		Ok(n == 1)
	}

	/// Marks a claimed payment settled at the node.
	pub async fn set_receive_settled(&self, payment_hash: &[u8; 32]) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute("UPDATE lightning_receive SET settled = true, updated_at = now() WHERE payment_hash = $1 AND state = 'claimed'",
			&[&&payment_hash[..]]).await?;
		Ok(())
	}

	/// Cancels an `open` or `accepted` payment, with the reason: it is to
	/// be failed back. Returns whether this call cancelled it.
	pub async fn cancel_receive(&self, payment_hash: &[u8; 32], reason: &str) -> Result<bool, StoreError> {
		let conn = self.conn().await?;
		let n = conn.execute(
			"UPDATE lightning_receive SET state = 'cancelled', reason = $2, updated_at = now()
			 WHERE payment_hash = $1 AND state IN ('open', 'accepted')",
			&[&&payment_hash[..], &reason],
		).await?;
		Ok(n == 1)
	}

	/// Marks a cancelled payment failed back at the node.
	pub async fn set_receive_failed_back(&self, payment_hash: &[u8; 32]) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute("UPDATE lightning_receive SET failed_back = true, updated_at = now() WHERE payment_hash = $1 AND state = 'cancelled'",
			&[&&payment_hash[..]]).await?;
		Ok(())
	}
}
