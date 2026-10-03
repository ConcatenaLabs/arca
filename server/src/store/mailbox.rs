//! Mailboxes: coin records waiting for receivers who may be offline.

use super::{Store, StoreError};

/// One message in a mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxMessage {
	/// Increases with every message the server stores; a reader passes the
	/// last cursor it read to get what came after.
	pub cursor: i64,
	pub kind: String,
	pub leaf_id: Option<[u8; 32]>,
	pub payload: Vec<u8>,
}

impl Store {
	/// Posts a coin record for `leaf_id` to the mailbox of `mailbox_key`.
	pub async fn mailbox_post(&self, mailbox_key: &[u8; 32], leaf_id: &[u8; 32], record: &[u8]) -> Result<i64, StoreError> {
		let conn = self.conn().await?;
		let row = conn.query_one(
			"INSERT INTO mailbox_message (mailbox_key, kind, leaf_id, payload) VALUES ($1, 'coin', $2, $3) RETURNING cursor",
			&[&&mailbox_key[..], &&leaf_id[..], &record],
		).await?;
		Ok(row.get(0))
	}

	/// Up to `limit` messages of `mailbox_key` after `after`, oldest first.
	pub async fn mailbox_read(&self, mailbox_key: &[u8; 32], after: i64, limit: i64) -> Result<Vec<MailboxMessage>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT cursor, kind, leaf_id, payload FROM mailbox_message
			 WHERE mailbox_key = $1 AND cursor > $2 ORDER BY cursor LIMIT $3",
			&[&&mailbox_key[..], &after, &limit],
		).await?;
		rows.iter().map(|r| {
			let leaf: Option<Vec<u8>> = r.get(2);
			Ok(MailboxMessage {
				cursor: r.get(0),
				kind: r.get(1),
				leaf_id: leaf.map(|l| super::array32(l, "leaf id")).transpose()?,
				payload: r.get(3),
			})
		}).collect()
	}
}
