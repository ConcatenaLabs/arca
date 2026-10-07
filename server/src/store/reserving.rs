//! Re-serving a key's leaves: every leaf the server holds for the key a
//! caller proves, a page at a time, with what each rests on and every way it
//! was given up, each with the owner's own signature that gave it up.
//!
//! A leaf is served to its own owner key, and to the mailbox key its owner
//! key bound it to (`leaf_mailbox`, [`Store::bind_mailbox`]); a transfer's
//! output also to the mailbox the transfer posted it to.

use super::coins::{leaf_row, LeafKind};
use super::participations::{read_participation, ParticipationRow};
use super::{array32, LeafRow, Store, StoreError};

/// Where a leaf of a batch sits: its round, the batch output, its index in
/// the tree, the participation it was made for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedBatch {
	pub round_txid: [u8; 32],
	/// `built`, `broadcast`, `final` or `lost`.
	pub round_state: String,
	pub batch_vout: u32,
	pub leaf_index: u32,
	pub owner_nonce: [u8; 32],
	pub participation_id: [u8; 32],
	/// The head of the signer's record when the round was built.
	pub signer_head: Option<(u64, [u8; 32], Option<[u8; 64]>)>,
}

/// A board's transaction output and state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedBoard {
	pub txid: [u8; 32],
	pub vout: u32,
	/// `pending`, `credited` or `lost`.
	pub state: String,
}

/// The transfer that made a coin, with the head of the signer's record its
/// last signature was recorded at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedMadeBy {
	pub transfer_id: [u8; 32],
	pub signer_head: Option<super::transfers::RecordHeadRow>,
}

/// A transfer a coin was given up to: its id, whether the operator signed
/// it, the coin's checkpoint value, and its owner's signature over the
/// coin's move into its checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedTransferSpend {
	pub transfer_id: [u8; 32],
	pub signed: bool,
	pub checkpoint_value: u64,
	pub checkpoint_owner_sig: [u8; 64],
}

/// A forfeit of a coin, with the round it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedForfeit {
	pub participation_id: [u8; 32],
	pub round_txid: [u8; 32],
	pub connector_vout: u32,
	pub unlock_hash: [u8; 32],
	pub refund_delay_units: u16,
	pub margin: u64,
	pub owner_sig: [u8; 64],
	/// Whether the operator's half is recorded too.
	pub cosigned: bool,
}

/// A leaf as the server re-serves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedLeaf {
	/// The cursor a next page starts after.
	pub seq: i64,
	pub leaf: LeafRow,
	pub batch: Option<ServedBatch>,
	pub board: Option<ServedBoard>,
	pub made_by: Option<ServedMadeBy>,
	pub transfers: Vec<ServedTransferSpend>,
	/// Every participation the coin was given up to, oldest first.
	pub participations: Vec<ParticipationRow>,
	pub forfeits: Vec<ServedForfeit>,
}

impl Store {
	/// Binds the leaf of `owner` to `mailbox`, the owner key's `proof`
	/// checked by the caller: kept only for a key that owns a leaf or is
	/// wanted by a participation, so a stranger writes no row. A key bound
	/// before keeps its binding. Returns the mailbox the key is bound to, or
	/// `None` for a key the server knows no leaf of.
	pub async fn bind_mailbox(&self, owner: &[u8; 32], mailbox: &[u8; 32], proof: &[u8; 64]) -> Result<Option<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		conn.execute(
			"INSERT INTO leaf_mailbox (owner_key, mailbox_key, proof)
			 SELECT $1, $2, $3 WHERE EXISTS (SELECT 1 FROM leaf WHERE owner_key = $1)
			     OR EXISTS (SELECT 1 FROM participation_output WHERE owner_key = $1 AND kind = 'leaf')
			 ON CONFLICT (owner_key) DO NOTHING",
			&[&&owner[..], &&mailbox[..], &&proof[..]],
		).await?;
		let r = conn.query_opt("SELECT mailbox_key FROM leaf_mailbox WHERE owner_key = $1", &[&&owner[..]]).await?;
		r.map(|r| array32(r.get(0), "mailbox key")).transpose()
	}

	/// The mailbox the leaf of `owner` is bound to, if it is.
	pub async fn mailbox_of(&self, owner: &[u8; 32]) -> Result<Option<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt("SELECT mailbox_key FROM leaf_mailbox WHERE owner_key = $1", &[&&owner[..]]).await?;
		r.map(|r| array32(r.get(0), "mailbox key")).transpose()
	}

	/// Up to `limit` leaves served to `key` after cursor `after`, in the
	/// order the server learned of them: those it owns, those whose owner
	/// key is bound to it, and the transfer outputs posted to it. A batch
	/// leaf's record holds its participation's preimage, so it is served
	/// empty until that preimage went out, as [`Store::leaves_by_owner`]
	/// serves it.
	pub async fn served_leaves(&self, key: &[u8; 32], after: i64, limit: i64) -> Result<Vec<ServedLeaf>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT l.leaf_id, l.kind::text, l.asset, l.value, l.owner_key, l.script_pubkey, l.hops,
			        CASE WHEN l.kind = 'batch' AND NOT EXISTS (
			            SELECT 1 FROM batch_leaf b JOIN participation p ON p.participation_id = b.participation_id
			            WHERE b.leaf_id = l.leaf_id AND p.attempt = b.attempt AND p.state = 'released'
			            UNION ALL
			            SELECT 1 FROM batch_leaf b JOIN participation_attempt a
			              ON a.participation_id = b.participation_id AND a.attempt = b.attempt
			            WHERE b.leaf_id = l.leaf_id AND a.released)
			        THEN ''::bytea ELSE l.record END,
			        l.state::text, l.spent_by, l.seq
			 FROM leaf l
			 WHERE l.seq > $2 AND l.leaf_id IN (
			     SELECT leaf_id FROM leaf WHERE owner_key = $1
			     UNION SELECT x.leaf_id FROM leaf_mailbox m JOIN leaf x ON x.owner_key = m.owner_key WHERE m.mailbox_key = $1
			     UNION SELECT leaf_id FROM transfer_output WHERE mailbox_key = $1)
			 ORDER BY l.seq LIMIT $3",
			&[&&key[..], &after, &limit],
		).await?;
		let mut out = Vec::with_capacity(rows.len());
		for r in &rows {
			let leaf = leaf_row(r)?;
			let seq: i64 = r.get(10);
			let id = leaf.leaf_id;
			let batch = match leaf.kind {
				LeafKind::Batch => {
					let b = conn.query_opt(
						"SELECT r.txid, r.state, b.vout, b.idx, b.owner_nonce, b.participation_id, r.signer_entry, r.signer_hash, r.signer_sig
						 FROM batch_leaf b JOIN round r ON r.round_id = b.round_id WHERE b.leaf_id = $1",
						&[&&id[..]],
					).await?;
					match b {
						Some(b) => {
							let entry: Option<i64> = b.get(6);
							let hash: Option<Vec<u8>> = b.get(7);
							let sig: Option<Vec<u8>> = b.get(8);
							let signer_head = match (entry, hash) {
								(Some(n), Some(h)) => Some((n as u64, array32(h, "signer hash")?,
									sig.map(|s| s.try_into().map_err(|_| StoreError::Corrupt("a round's head signature".into()))).transpose()?)),
								_ => None,
							};
							Some(ServedBatch {
								round_txid: array32(b.get(0), "txid")?,
								round_state: b.get(1),
								batch_vout: b.get::<_, i32>(2) as u32,
								leaf_index: b.get::<_, i32>(3) as u32,
								owner_nonce: array32(b.get(4), "owner nonce")?,
								participation_id: array32(b.get(5), "participation id")?,
								signer_head,
							})
						},
						None => None,
					}
				},
				_ => None,
			};
			let board = match leaf.kind {
				LeafKind::Board => conn.query_opt("SELECT txid, vout, state::text FROM board WHERE leaf_id = $1", &[&&id[..]]).await?
					.map(|b| Ok::<_, StoreError>(ServedBoard { txid: array32(b.get(0), "txid")?, vout: b.get::<_, i32>(1) as u32, state: b.get(2) }))
					.transpose()?,
				_ => None,
			};
			let made_by = match leaf.kind {
				LeafKind::Transfer => conn.query_opt(
					"SELECT t.transfer_id, t.signer_entry, t.signer_hash, t.signer_sig FROM transfer_output o
					 JOIN transfer t ON t.transfer_id = o.transfer_id WHERE o.leaf_id = $1",
					&[&&id[..]],
				).await?.map(|t| Ok::<_, StoreError>(ServedMadeBy {
					transfer_id: array32(t.get(0), "transfer id")?,
					signer_head: super::transfers::head_of(t.get(1), t.get(2), t.get(3))?,
				})).transpose()?,
				_ => None,
			};
			let mut transfers = vec![];
			for t in conn.query(
				"SELECT t.transfer_id, t.state, i.checkpoint_value, i.checkpoint_owner_sig FROM transfer_input i
				 JOIN transfer t ON t.transfer_id = i.transfer_id WHERE i.leaf_id = $1",
				&[&&id[..]],
			).await? {
				let sig: Vec<u8> = t.get(3);
				transfers.push(ServedTransferSpend {
					transfer_id: array32(t.get(0), "transfer id")?,
					signed: t.get::<_, &str>(1) == "signed",
					checkpoint_value: t.get::<_, i64>(2) as u64,
					checkpoint_owner_sig: sig.try_into().map_err(|_| StoreError::Corrupt("a checkpoint signature".into()))?,
				});
			}
			let mut participations = vec![];
			for p in conn.query(
				"SELECT i.participation_id FROM participation_input i JOIN participation p ON p.participation_id = i.participation_id
				 WHERE i.leaf_id = $1 ORDER BY p.created_at, i.participation_id",
				&[&&id[..]],
			).await? {
				let pid = array32(p.get(0), "participation id")?;
				if let Some(row) = read_participation(&*conn, &pid).await? {
					participations.push(row);
				}
			}
			let mut forfeits = vec![];
			for f in conn.query(
				"SELECT f.participation_id, r.txid, c.vout, f.unlock_hash, f.refund_delay_units, f.margin, f.owner_sig,
				        f.operator_sig IS NOT NULL
				 FROM forfeit f JOIN round r ON r.round_id = f.round_id JOIN connector_output c ON c.round_id = f.round_id
				 WHERE f.leaf_id = $1 ORDER BY f.created_at, f.round_id",
				&[&&id[..]],
			).await? {
				let sig: Vec<u8> = f.get(6);
				forfeits.push(ServedForfeit {
					participation_id: array32(f.get(0), "participation id")?,
					round_txid: array32(f.get(1), "txid")?,
					connector_vout: f.get::<_, i32>(2) as u32,
					unlock_hash: array32(f.get(3), "unlock hash")?,
					refund_delay_units: f.get::<_, i32>(4) as u16,
					margin: f.get::<_, i64>(5) as u64,
					owner_sig: sig.try_into().map_err(|_| StoreError::Corrupt("a forfeit signature".into()))?,
					cosigned: f.get(7),
				});
			}
			out.push(ServedLeaf { seq, leaf, batch, board, made_by, transfers, participations, forfeits });
		}
		Ok(out)
	}
}
