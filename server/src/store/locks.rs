//! The `htlc-2` locks the operator co-signed, and how each ended
//! ([`crate::cosign`]).

use super::{array32, Store, StoreError};

/// How a lock stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
	/// Neither ending co-signed.
	Open,
	/// The payee's claim co-signed, with the preimage.
	Claimed,
	/// The payer's refund co-signed.
	Refunded,
}

impl LockState {
	pub fn as_str(self) -> &'static str {
		match self {
			LockState::Open => "open",
			LockState::Claimed => "claimed",
			LockState::Refunded => "refunded",
		}
	}

	fn parse(s: &str) -> Result<LockState, StoreError> {
		Ok(match s {
			"open" => LockState::Open,
			"claimed" => LockState::Claimed,
			"refunded" => LockState::Refunded,
			other => return Err(StoreError::Corrupt(format!("a lock in state {:?}", other))),
		})
	}
}

/// One lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockRow {
	pub leaf_id: [u8; 32],
	pub payment_hash: [u8; 32],
	pub payee: [u8; 32],
	pub payer: [u8; 32],
	/// `T`, a median time.
	pub timeout: u32,
	/// The transfer that made it.
	pub made_by: [u8; 32],
	pub state: LockState,
	/// The transfer that ended it.
	pub ended_by: Option<[u8; 32]>,
	pub preimage: Option<[u8; 32]>,
}

/// A lock to keep, as the transfer making it is recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLock {
	pub leaf_id: [u8; 32],
	pub payment_hash: [u8; 32],
	pub payee: [u8; 32],
	pub payer: [u8; 32],
	pub timeout: u32,
}

const COLUMNS: &str = "leaf_id, payment_hash, payee, payer, timeout, made_by, state, ended_by, preimage";

fn row_of(r: &tokio_postgres::Row) -> Result<LockRow, StoreError> {
	let opt = |v: Option<Vec<u8>>, what: &str| v.map(|b| array32(b, what)).transpose();
	Ok(LockRow {
		leaf_id: array32(r.get(0), "lock leaf id")?,
		payment_hash: array32(r.get(1), "lock payment hash")?,
		payee: array32(r.get(2), "lock payee")?,
		payer: array32(r.get(3), "lock payer")?,
		timeout: r.get::<_, i64>(4) as u32,
		made_by: array32(r.get(5), "lock transfer")?,
		state: LockState::parse(r.get(6))?,
		ended_by: opt(r.get(7), "lock ending")?,
		preimage: opt(r.get(8), "lock preimage")?,
	})
}

impl Store {
	/// Keeps the locks transfer `made_by` makes; one kept already stays as
	/// it is, so a repeated request keeps nothing twice.
	pub async fn insert_locks(&self, made_by: &[u8; 32], locks: &[NewLock]) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		for l in locks {
			conn.execute(
				"INSERT INTO swap_lock (leaf_id, payment_hash, payee, payer, timeout, made_by) VALUES ($1, $2, $3, $4, $5, $6)
				 ON CONFLICT (leaf_id) DO NOTHING",
				&[&&l.leaf_id[..], &&l.payment_hash[..], &&l.payee[..], &&l.payer[..], &(l.timeout as i64), &&made_by[..]],
			).await?;
		}
		Ok(())
	}

	/// The lock whose leaf is `leaf_id`.
	pub async fn lock(&self, leaf_id: &[u8; 32]) -> Result<Option<LockRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(&format!("SELECT {} FROM swap_lock WHERE leaf_id = $1", COLUMNS), &[&&leaf_id[..]]).await?;
		r.as_ref().map(row_of).transpose()
	}

	/// Every lock under `payment_hash`, oldest first.
	pub async fn locks_by_hash(&self, payment_hash: &[u8; 32]) -> Result<Vec<LockRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!("SELECT {} FROM swap_lock WHERE payment_hash = $1 ORDER BY created_at, leaf_id", COLUMNS),
			&[&&payment_hash[..]]).await?;
		rows.iter().map(row_of).collect()
	}

	/// Ends lock `leaf_id` as `state` by transfer `transfer`, keeping the
	/// claim's preimage: only an open lock, or one this same transfer ended
	/// (a repeated request). Returns whether it is now so ended.
	pub async fn end_lock(&self, leaf_id: &[u8; 32], state: LockState, preimage: Option<&[u8; 32]>, transfer: &[u8; 32])
		-> Result<bool, StoreError>
	{
		let conn = self.conn().await?;
		let n = conn.execute(
			"UPDATE swap_lock SET state = $2, ended_by = $3, preimage = COALESCE($4, preimage), updated_at = now()
			 WHERE leaf_id = $1 AND (state = 'open' OR (state = $2 AND ended_by = $3))",
			&[&&leaf_id[..], &state.as_str(), &&transfer[..], &preimage.map(|p| p.to_vec())],
		).await?;
		Ok(n == 1)
	}

	/// Keeps `preimage` for every lock under its hash that has none: the
	/// caller checked that it opens the hash. Returns how many it kept it for.
	pub async fn lock_preimage(&self, payment_hash: &[u8; 32], preimage: &[u8; 32]) -> Result<u64, StoreError> {
		let conn = self.conn().await?;
		Ok(conn.execute(
			"UPDATE swap_lock SET preimage = $2, updated_at = now() WHERE payment_hash = $1 AND preimage IS NULL",
			&[&&payment_hash[..], &&preimage[..]],
		).await?)
	}
}

impl Store {
	/// Whether `key` owns a leaf the server knows, or refunds a lock it keeps.
	pub async fn key_owns_or_refunds(&self, key: &[u8; 32]) -> Result<bool, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_one(
			"SELECT EXISTS (SELECT 1 FROM leaf WHERE owner_key = $1) OR EXISTS (SELECT 1 FROM swap_lock WHERE payer = $1)",
			&[&&key[..]],
		).await?;
		Ok(r.get(0))
	}
}
