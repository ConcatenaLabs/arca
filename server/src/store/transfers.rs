//! Out-of-round transfers, in two steps around the operator's signature.
//!
//! [`Store::record_transfer`] runs before any signature exists: it marks every
//! input spent by the transfer, takes the output leaves' operator nonces, and
//! reserves their keys and every new script, in one database transaction.
//! Only then does the server ask for `S`'s signatures, so a spend it signs is
//! always one it has durably recorded, and a second spend of the same leaf is
//! refused by the database whatever the timing. [`Store::complete_transfer`]
//! stores the signatures and the receivers' coin records and posts them to
//! their mailboxes. A request repeated byte for byte finds its transfer and
//! gets the same answer.

use std::collections::HashSet;

use super::coins::{insert_coin, leaf_row};
use super::{array32, LeafRow, NewCoin, Store, StoreError};

/// One input of a transfer to record.
#[derive(Debug, Clone)]
pub struct NewTransferInput {
	pub leaf_id: [u8; 32],
	pub checkpoint_value: u64,
	pub checkpoint_owner_sig: [u8; 64],
	pub reassignment_owner_sig: [u8; 64],
	/// The checkpoint the input moves into: a new Arca script.
	pub checkpoint_script: Vec<u8>,
}

/// One output of a transfer to record: its coin (pending, its record empty
/// until signed) and the mailbox it goes to.
#[derive(Debug, Clone)]
pub struct NewTransferOutput {
	pub coin: NewCoin,
	pub mailbox_key: [u8; 32],
}

/// An input of a stored transfer: its leaf id, its checkpoint's value, and
/// the operator's checkpoint and reassignment signatures once made.
pub type StoredInput = ([u8; 32], u64, Option<([u8; 64], [u8; 64])>);

/// A transfer as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRow {
	pub transfer_id: [u8; 32],
	pub signed: bool,
	/// In order.
	pub inputs: Vec<StoredInput>,
	/// `(leaf id, mailbox key)`, in order.
	pub outputs: Vec<([u8; 32], [u8; 32])>,
}

fn sig64(v: Vec<u8>) -> Result<[u8; 64], StoreError> {
	v.try_into().map_err(|v: Vec<u8>| StoreError::Corrupt(format!("a signature of {} bytes", v.len())))
}

impl Store {
	/// The transfer `transfer_id`, if recorded.
	pub async fn transfer(&self, transfer_id: &[u8; 32]) -> Result<Option<TransferRow>, StoreError> {
		let conn = self.conn().await?;
		let row = conn.query_opt("SELECT state FROM transfer WHERE transfer_id = $1", &[&&transfer_id[..]]).await?;
		let signed = match row {
			Some(r) => r.get::<_, &str>(0) == "signed",
			None => return Ok(None),
		};
		let ins = conn.query(
			"SELECT leaf_id, checkpoint_value, checkpoint_operator_sig, reassignment_operator_sig
			 FROM transfer_input WHERE transfer_id = $1 ORDER BY idx",
			&[&&transfer_id[..]],
		).await?;
		let inputs = ins.iter().map(|r| {
			let cp: Option<Vec<u8>> = r.get(2);
			let re: Option<Vec<u8>> = r.get(3);
			let sigs = match (cp, re) {
				(Some(a), Some(b)) => Some((sig64(a)?, sig64(b)?)),
				_ => None,
			};
			Ok((array32(r.get(0), "leaf id")?, r.get::<_, i64>(1) as u64, sigs))
		}).collect::<Result<Vec<_>, StoreError>>()?;
		let outs = conn.query("SELECT leaf_id, mailbox_key FROM transfer_output WHERE transfer_id = $1 ORDER BY idx",
			&[&&transfer_id[..]]).await?;
		let outputs = outs.iter().map(|r| Ok((array32(r.get(0), "leaf id")?, array32(r.get(1), "mailbox key")?)))
			.collect::<Result<Vec<_>, StoreError>>()?;
		Ok(Some(TransferRow { transfer_id: *transfer_id, signed, inputs, outputs }))
	}

	/// Records a transfer before it is signed: see the [module
	/// documentation](self). Refuses an input that is not live or is spent
	/// already, a nonce not issued or taken, a key or script already known.
	pub async fn record_transfer(&self, transfer_id: &[u8; 32], inputs: &[NewTransferInput], outputs: &[NewTransferOutput])
		-> Result<(), StoreError>
	{
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		for i in inputs {
			let r = t.query_opt(
				"SELECT leaf_id, kind::text, asset, value, owner_key, script_pubkey, hops, record, state::text, spent_by
				 FROM leaf WHERE leaf_id = $1 FOR UPDATE",
				&[&&i.leaf_id[..]],
			).await?;
			let leaf: LeafRow = match r {
				Some(r) => leaf_row(&r)?,
				None => return Err(StoreError::LeafUnknown(super::hex(&i.leaf_id))),
			};
			match leaf.state {
				super::LeafState::Live => {},
				super::LeafState::Spent => return Err(StoreError::LeafSpent(super::hex(&i.leaf_id))),
				other => return Err(StoreError::LeafNotLive(super::hex(&i.leaf_id), other.as_str())),
			}
		}
		t.execute("INSERT INTO transfer (transfer_id, request_hash, state) VALUES ($1, $1, 'recorded')",
			&[&&transfer_id[..]]).await?;
		for (k, i) in inputs.iter().enumerate() {
			let value = i64::try_from(i.checkpoint_value).map_err(|_| StoreError::Corrupt("value".into()))?;
			let r = t.execute(
				"INSERT INTO transfer_input (transfer_id, idx, leaf_id, checkpoint_value, checkpoint_owner_sig, reassignment_owner_sig)
				 VALUES ($1, $2, $3, $4, $5, $6)",
				&[&&transfer_id[..], &(k as i16), &&i.leaf_id[..], &value, &&i.checkpoint_owner_sig[..], &&i.reassignment_owner_sig[..]],
			).await;
			if let Err(e) = r {
				if StoreError::is_unique(&e, "transfer_input_leaf_id_key") {
					return Err(StoreError::LeafSpent(super::hex(&i.leaf_id)));
				}
				return Err(e.into());
			}
			t.execute("UPDATE leaf SET state = 'spent', spent_by = $2, updated_at = now() WHERE leaf_id = $1",
				&[&&i.leaf_id[..], &&transfer_id[..]]).await?;
			let r = t.execute("INSERT INTO arca_script (script_pubkey, kind, leaf_id) VALUES ($1, 'checkpoint', $2)",
				&[&i.checkpoint_script, &&i.leaf_id[..]]).await;
			if let Err(e) = r {
				if StoreError::is_unique(&e, "arca_script_pkey") {
					return Err(StoreError::ScriptReused);
				}
				return Err(e.into());
			}
		}
		for (k, o) in outputs.iter().enumerate() {
			insert_coin(&t, &o.coin).await?;
			t.execute("INSERT INTO transfer_output (transfer_id, idx, leaf_id, mailbox_key) VALUES ($1, $2, $3, $4)",
				&[&&transfer_id[..], &(k as i16), &&o.coin.leaf_id[..], &&o.mailbox_key[..]]).await?;
		}
		t.commit().await?;
		Ok(())
	}

	/// Completes a recorded transfer: the operator's signatures, each output's
	/// coin record, live, and posted to its mailbox. All or nothing.
	pub async fn complete_transfer(&self, transfer_id: &[u8; 32], sigs: &[([u8; 64], [u8; 64])], records: &[([u8; 32], Vec<u8>)])
		-> Result<(), StoreError>
	{
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let state = t.query_one("SELECT state FROM transfer WHERE transfer_id = $1 FOR UPDATE", &[&&transfer_id[..]]).await?;
		if state.get::<_, &str>(0) == "signed" {
			return Ok(());
		}
		for (k, (cp, re)) in sigs.iter().enumerate() {
			t.execute(
				"UPDATE transfer_input SET checkpoint_operator_sig = $3, reassignment_operator_sig = $4
				 WHERE transfer_id = $1 AND idx = $2",
				&[&&transfer_id[..], &(k as i16), &&cp[..], &&re[..]],
			).await?;
		}
		for (leaf_id, record) in records {
			t.execute("UPDATE leaf SET record = $2, state = 'live', updated_at = now() WHERE leaf_id = $1 AND state = 'pending'",
				&[&&leaf_id[..], &record]).await?;
			t.execute(
				"INSERT INTO mailbox_message (mailbox_key, kind, leaf_id, payload)
				 SELECT mailbox_key, 'coin', leaf_id, $2 FROM transfer_output WHERE transfer_id = $1 AND leaf_id = $3",
				&[&&transfer_id[..], &record, &&leaf_id[..]],
			).await?;
		}
		t.execute("UPDATE transfer SET state = 'signed' WHERE transfer_id = $1", &[&&transfer_id[..]]).await?;
		t.commit().await?;
		Ok(())
	}

	/// Which of `scripts` have been seen paid by an output, in the mempool or a
	/// block.
	pub async fn sighted(&self, scripts: &[Vec<u8>]) -> Result<HashSet<Vec<u8>>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query("SELECT DISTINCT script_pubkey FROM script_sighting WHERE script_pubkey = ANY($1)", &[&scripts]).await?;
		Ok(rows.iter().map(|r| r.get(0)).collect())
	}

	/// Whether `leaf_id` is the input of a transfer: an open out-of-round
	/// reassignment, until a round takes the coins it made.
	pub async fn spent_by_transfer(&self, leaf_id: &[u8; 32]) -> Result<Option<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt("SELECT transfer_id FROM transfer_input WHERE leaf_id = $1", &[&&leaf_id[..]]).await?;
		r.map(|r| array32(r.get(0), "transfer id")).transpose()
	}
}
