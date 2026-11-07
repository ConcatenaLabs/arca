//! Mailboxes: coin records waiting for receivers who may be offline.

use super::{Store, StoreError};

/// One message in a mailbox: a coin (`kind` `coin`, its record the payload),
/// or a notice of one (`pending`, a transfer recorded and not yet signed;
/// `withdrawn`, that transfer dropped), its JSON the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxMessage {
	/// Increases with every message the server stores; a reader passes the
	/// last cursor it read to get what came after.
	pub cursor: i64,
	pub kind: String,
	pub leaf_id: Option<[u8; 32]>,
	pub payload: Vec<u8>,
	/// For a coin a transfer made, the head of the signer's record that
	/// transfer's last signature was recorded as.
	pub signer_head: Option<super::transfers::RecordHeadRow>,
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

	/// Up to `limit` messages of `mailbox_key` after `after`, oldest first:
	/// coins, and when `notices`, the notices of coins pending and withdrawn
	/// too (a reader that does not ask for them reads coins alone).
	pub async fn mailbox_read(&self, mailbox_key: &[u8; 32], after: i64, limit: i64, notices: bool)
		-> Result<Vec<MailboxMessage>, StoreError>
	{
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT m.cursor, m.kind, m.leaf_id, m.payload, t.signer_entry, t.signer_hash, t.signer_sig FROM mailbox_message m
			 LEFT JOIN transfer_output o ON o.leaf_id = m.leaf_id
			 LEFT JOIN transfer t ON t.transfer_id = o.transfer_id
			 WHERE m.mailbox_key = $1 AND m.cursor > $2 AND (m.kind = 'coin' OR $4) ORDER BY m.cursor LIMIT $3",
			&[&&mailbox_key[..], &after, &limit, &notices],
		).await?;
		rows.iter().map(|r| message_of(r, 0)).collect()
	}

	/// The mailboxes of several keys in one statement, each read as
	/// [`Self::mailbox_read`] reads it after its own cursor: for each
	/// `(key, after)` of `reads`, in order, up to `limit` messages after
	/// `after`, oldest first. At most `rows` rows are read in all, a key
	/// whose mailbox is empty counting one: the answer holds the keys from
	/// the first up to where they ran out, the last of them with as many of
	/// its messages as fitted (a page shorter than `limit`, which its reader
	/// reads on from), and none of the keys after it, which its reader asks
	/// for again.
	pub async fn mailbox_read_many(&self, reads: &[([u8; 32], i64)], limit: i64, notices: bool, rows: i64)
		-> Result<Vec<([u8; 32], Vec<MailboxMessage>)>, StoreError>
	{
		let keys: Vec<&[u8]> = reads.iter().map(|(k, _)| &k[..]).collect();
		let afters: Vec<i64> = reads.iter().map(|(_, a)| *a).collect();
		let conn = self.conn().await?;
		let found = conn.query(
			"SELECT q.i, m.cursor, m.kind, m.leaf_id, m.payload, m.signer_entry, m.signer_hash, m.signer_sig
			 FROM unnest($1::bytea[], $2::bigint[]) WITH ORDINALITY AS q(key, after, i)
			 LEFT JOIN LATERAL (
				SELECT m.cursor, m.kind, m.leaf_id, m.payload, t.signer_entry, t.signer_hash, t.signer_sig FROM mailbox_message m
				LEFT JOIN transfer_output o ON o.leaf_id = m.leaf_id
				LEFT JOIN transfer t ON t.transfer_id = o.transfer_id
				WHERE m.mailbox_key = q.key AND m.cursor > q.after AND (m.kind = 'coin' OR $4) ORDER BY m.cursor LIMIT $3
			 ) m ON true
			 ORDER BY q.i, m.cursor LIMIT $5",
			&[&keys, &afters, &limit, &notices, &rows],
		).await?;
		let mut out: Vec<([u8; 32], Vec<MailboxMessage>)> = vec![];
		for r in &found {
			let i: i64 = r.get(0);
			let key = reads.get(usize::try_from(i - 1).unwrap_or(usize::MAX)).map(|(k, _)| *k)
				.ok_or_else(|| StoreError::Corrupt(format!("a mailbox read answered key {} of {}", i, reads.len())))?;
			if out.last().is_none_or(|(k, _)| *k != key) {
				out.push((key, vec![]));
			}
			let cursor: Option<i64> = r.get(1);
			if cursor.is_some() {
				out.last_mut().expect("a key").1.push(message_of(r, 1)?);
			}
		}
		Ok(out)
	}
}

/// One message of a mailbox from its row, its columns from `at`: the
/// cursor, kind, leaf, payload and the signer's head.
fn message_of(r: &tokio_postgres::Row, at: usize) -> Result<MailboxMessage, StoreError> {
	let leaf: Option<Vec<u8>> = r.get(at + 2);
	Ok(MailboxMessage {
		cursor: r.get(at),
		kind: r.get(at + 1),
		leaf_id: leaf.map(|l| super::array32(l, "leaf id")).transpose()?,
		payload: r.get(at + 3),
		signer_head: super::transfers::head_of(r.get(at + 4), r.get(at + 5), r.get(at + 6))?,
	})
}
