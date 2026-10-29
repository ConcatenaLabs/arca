//! What the store keeps of the operator's debts for swept coins
//! ([`crate::owed`]): each sweep whose coins were counted, and an entry per
//! coin it took from its holder.

use std::collections::BTreeMap;

use super::participations::{insert_participation_in, NewParticipation};
use super::{array32, Store, StoreError};

/// A coin a final sweep took from its holder, to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOwed {
	pub leaf_id: [u8; 32],
	pub owner_key: [u8; 32],
	pub owner_nonce: [u8; 32],
	pub asset: [u8; 32],
	pub value: u64,
	pub fee: u64,
}

/// Where an entry stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwedState {
	/// Owed, not yet claimed.
	Owed,
	/// A repayment participation wants its new leaf.
	Claimed,
	/// That participation is released: the holder holds its new leaf.
	Repaid,
	/// Its sweep is not final now (a rollback took it out): nothing is
	/// owed, and nothing is paid, until it is final again.
	Withdrawn,
}

impl OwedState {
	pub fn as_str(self) -> &'static str {
		match self {
			OwedState::Owed => "owed",
			OwedState::Claimed => "claimed",
			OwedState::Repaid => "repaid",
			OwedState::Withdrawn => "withdrawn",
		}
	}

	fn parse(s: &str) -> Result<OwedState, StoreError> {
		Ok(match s {
			"owed" => OwedState::Owed,
			"claimed" => OwedState::Claimed,
			"repaid" => OwedState::Repaid,
			"withdrawn" => OwedState::Withdrawn,
			other => return Err(StoreError::Corrupt(format!("owed state {:?}", other))),
		})
	}
}

/// An entry as it stands: its state is `withdrawn` while its sweep is not
/// final, unless it was repaid already.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwedRow {
	pub leaf_id: [u8; 32],
	pub sweep_txid: [u8; 32],
	pub owner_key: [u8; 32],
	pub owner_nonce: [u8; 32],
	pub asset: [u8; 32],
	pub value: u64,
	pub fee: u64,
	pub state: OwedState,
	pub participation_id: Option<[u8; 32]>,
}

impl OwedRow {
	/// What the operator repays: the coin's value less the fee.
	pub fn owed(&self) -> u64 {
		self.value - self.fee
	}
}

/// How a claim of an entry went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
	/// Recorded now: the entry is claimed by the participation.
	Claimed,
	/// The entry is claimed by this very participation already.
	Again,
	/// No entry for the coin.
	Unknown,
	/// Its sweep is not final now.
	Withdrawn,
	/// Claimed by another participation, or repaid: its state and that
	/// participation.
	Taken(OwedState, Option<[u8; 32]>),
}

const OWED_COLUMNS: &str = "o.leaf_id, o.sweep_txid, o.owner_key, o.owner_nonce, o.asset, o.value, o.fee,
	CASE WHEN o.state <> 'repaid' AND s.state = 'withdrawn' THEN 'withdrawn' ELSE o.state END, o.participation_id";
const OWED_FROM: &str = "owed o JOIN owed_sweep s ON s.txid = o.sweep_txid";

fn owed_row(r: &tokio_postgres::Row) -> Result<OwedRow, StoreError> {
	let value: i64 = r.get(5);
	let fee: i64 = r.get(6);
	let state: String = r.get(7);
	Ok(OwedRow {
		leaf_id: array32(r.get(0), "leaf id")?,
		sweep_txid: array32(r.get(1), "sweep txid")?,
		owner_key: array32(r.get(2), "owner key")?,
		owner_nonce: array32(r.get(3), "owner nonce")?,
		asset: array32(r.get(4), "asset")?,
		value: u64::try_from(value).map_err(|_| StoreError::Corrupt(format!("owed value {}", value)))?,
		fee: u64::try_from(fee).map_err(|_| StoreError::Corrupt(format!("owed fee {}", fee)))?,
		state: OwedState::parse(&state)?,
		participation_id: r.get::<_, Option<Vec<u8>>>(8).map(|p| array32(p, "participation id")).transpose()?,
	})
}

fn i64_of(v: u64) -> Result<i64, StoreError> {
	i64::try_from(v).map_err(|_| StoreError::Corrupt(format!("{} above 2^63", v)))
}

impl Store {
	/// The watcher's sweeps that are final and whose coins are not counted
	/// yet: each txid, with the batch token it names.
	pub async fn sweeps_to_count(&self) -> Result<Vec<([u8; 32], Vec<u8>)>, StoreError> {
		let conn = self.conn().await?;
		conn.query(
			"SELECT w.txid, w.subject FROM watcher_tx w JOIN nursery_tx n ON n.txid = w.txid AND n.state = 'final'
			 WHERE w.kind = 'sweep' AND NOT EXISTS (SELECT 1 FROM owed_sweep s WHERE s.txid = w.txid)
			 ORDER BY w.created_at, w.txid",
			&[],
		).await?.iter().map(|r| Ok((array32(r.get(0), "txid")?, r.get(1)))).collect()
	}

	/// The counted sweeps whose finality moved since: each txid, and whether
	/// it is final now.
	pub async fn owed_sweeps_moved(&self) -> Result<Vec<([u8; 32], bool)>, StoreError> {
		let conn = self.conn().await?;
		conn.query(
			"SELECT s.txid, COALESCE(n.state = 'final', false) FROM owed_sweep s LEFT JOIN nursery_tx n ON n.txid = s.txid
			 WHERE (s.state = 'final') <> COALESCE(n.state = 'final', false)",
			&[],
		).await?.iter().map(|r| Ok((array32(r.get(0), "txid")?, r.get(1)))).collect()
	}

	/// Records that `sweep`, final, took the coins `entries`, in one
	/// database transaction: the sweep counted and an entry per coin. A coin
	/// with an entry already keeps it, unless that entry's sweep is
	/// withdrawn and the coin is not repaid: then the entry moves to this
	/// sweep, which took the coin instead. Returns how many entries this
	/// sweep holds now; `None` when the sweep was counted already.
	pub async fn record_owed(&self, sweep: &[u8; 32], entries: &[NewOwed]) -> Result<Option<usize>, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let n = t.execute("INSERT INTO owed_sweep (txid, state) VALUES ($1, 'final') ON CONFLICT DO NOTHING", &[&&sweep[..]]).await?;
		if n == 0 {
			return Ok(None);
		}
		for e in entries {
			t.execute(
				"INSERT INTO owed (leaf_id, sweep_txid, owner_key, owner_nonce, asset, value, fee, state)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, 'owed')
				 ON CONFLICT (leaf_id) DO UPDATE SET sweep_txid = EXCLUDED.sweep_txid, updated_at = now()
				 WHERE owed.state <> 'repaid' AND (SELECT state FROM owed_sweep WHERE txid = owed.sweep_txid) = 'withdrawn'",
				&[&&e.leaf_id[..], &&sweep[..], &&e.owner_key[..], &&e.owner_nonce[..], &&e.asset[..], &i64_of(e.value)?, &i64_of(e.fee)?],
			).await?;
		}
		let held: i64 = t.query_one("SELECT count(*) FROM owed WHERE sweep_txid = $1", &[&&sweep[..]]).await?.get(0);
		t.commit().await?;
		Ok(Some(held as usize))
	}

	/// Sets a counted sweep final again, or withdrawn while a rollback keeps
	/// it from being final: every entry of it follows.
	pub async fn set_owed_sweep(&self, sweep: &[u8; 32], is_final: bool) -> Result<bool, StoreError> {
		let conn = self.conn().await?;
		let n = conn.execute("UPDATE owed_sweep SET state = $2, updated_at = now() WHERE txid = $1 AND state <> $2",
			&[&&sweep[..], &if is_final { "final" } else { "withdrawn" }]).await?;
		Ok(n > 0)
	}

	/// Moves each claimed entry on by its participation: repaid once it is
	/// released, owed again once it is void or expired (its new leaf never
	/// credited). Returns how many were repaid and how many owed again.
	pub async fn settle_owed(&self) -> Result<(u64, u64), StoreError> {
		let conn = self.conn().await?;
		let repaid = conn.execute(
			"UPDATE owed o SET state = 'repaid', updated_at = now() FROM participation p
			 WHERE o.participation_id = p.participation_id AND o.state = 'claimed' AND p.state = 'released'",
			&[],
		).await?;
		let again = conn.execute(
			"UPDATE owed o SET state = 'owed', participation_id = NULL, updated_at = now() FROM participation p
			 WHERE o.participation_id = p.participation_id AND o.state = 'claimed' AND p.state IN ('void', 'expired')",
			&[],
		).await?;
		Ok((repaid, again))
	}

	/// The entry for coin `leaf`.
	pub async fn owed_entry(&self, leaf: &[u8; 32]) -> Result<Option<OwedRow>, StoreError> {
		let conn = self.conn().await?;
		conn.query_opt(&format!("SELECT {} FROM {} WHERE o.leaf_id = $1", OWED_COLUMNS, OWED_FROM), &[&&leaf[..]]).await?
			.as_ref().map(owed_row).transpose()
	}

	/// The entry participation `id` repays.
	pub async fn owed_repaid_by(&self, id: &[u8; 32]) -> Result<Option<OwedRow>, StoreError> {
		let conn = self.conn().await?;
		conn.query_opt(&format!("SELECT {} FROM {} WHERE o.participation_id = $1", OWED_COLUMNS, OWED_FROM), &[&&id[..]]).await?
			.as_ref().map(owed_row).transpose()
	}

	/// Every entry for a coin owned by one of `owners`, or bound to or
	/// posted to one of the mailbox keys `mailboxes`, oldest first.
	pub async fn owed_of(&self, owners: &[[u8; 32]], mailboxes: &[[u8; 32]]) -> Result<Vec<OwedRow>, StoreError> {
		let conn = self.conn().await?;
		let owners: Vec<&[u8]> = owners.iter().map(|k| &k[..]).collect();
		let mailboxes: Vec<&[u8]> = mailboxes.iter().map(|k| &k[..]).collect();
		conn.query(
			&format!("SELECT {} FROM {} WHERE o.owner_key = ANY($1)
			 OR o.owner_key IN (SELECT owner_key FROM leaf_mailbox WHERE mailbox_key = ANY($2))
			 OR o.leaf_id IN (SELECT leaf_id FROM transfer_output WHERE mailbox_key = ANY($2))
			 ORDER BY o.created_at, o.leaf_id", OWED_COLUMNS, OWED_FROM),
			&[&owners, &mailboxes],
		).await?.iter().map(owed_row).collect()
	}

	/// What is owed now, per asset: the sum of every entry owed or claimed
	/// whose sweep is final, and how many coins that is.
	pub async fn owed_totals(&self) -> Result<BTreeMap<[u8; 32], (u64, u64)>, StoreError> {
		let conn = self.conn().await?;
		let mut out = BTreeMap::new();
		for r in conn.query(
			"SELECT o.asset, sum(o.value - o.fee)::BIGINT, count(*) FROM owed o JOIN owed_sweep s ON s.txid = o.sweep_txid
			 WHERE o.state IN ('owed', 'claimed') AND s.state = 'final' GROUP BY o.asset",
			&[],
		).await? {
			let total: i64 = r.get(1);
			let n: i64 = r.get(2);
			out.insert(array32(r.get(0), "asset")?, (total as u64, n as u64));
		}
		Ok(out)
	}

	/// Claims the entry for coin `leaf` by the repayment participation `p`,
	/// in one database transaction: the participation recorded and the entry
	/// claimed by it, only while the entry is owed and its sweep final.
	pub async fn claim_owed(&self, leaf: &[u8; 32], p: &NewParticipation) -> Result<ClaimOutcome, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let r = t.query_opt(
			"SELECT o.state, o.participation_id, s.state FROM owed o JOIN owed_sweep s ON s.txid = o.sweep_txid
			 WHERE o.leaf_id = $1 FOR UPDATE OF o",
			&[&&leaf[..]],
		).await?;
		let Some(r) = r else { return Ok(ClaimOutcome::Unknown) };
		let state = OwedState::parse(r.get::<_, &str>(0))?;
		let by = r.get::<_, Option<Vec<u8>>>(1).map(|p| array32(p, "participation id")).transpose()?;
		let sweep_final = r.get::<_, &str>(2) == "final";
		if state == OwedState::Claimed && by == Some(p.id) {
			return Ok(ClaimOutcome::Again);
		}
		if state != OwedState::Owed {
			return Ok(ClaimOutcome::Taken(state, by));
		}
		if !sweep_final {
			return Ok(ClaimOutcome::Withdrawn);
		}
		insert_participation_in(&t, p, false).await?;
		t.execute("UPDATE owed SET state = 'claimed', participation_id = $2, updated_at = now() WHERE leaf_id = $1",
			&[&&leaf[..], &&p.id[..]]).await?;
		t.commit().await?;
		Ok(ClaimOutcome::Claimed)
	}

	/// The outputs of the transfer that spent coin `leaf`: the coins resting
	/// on it, one reassignment on.
	pub async fn transfer_outputs_of(&self, leaf: &[u8; 32]) -> Result<Vec<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		conn.query(
			"SELECT o.leaf_id FROM transfer_input i JOIN transfer_output o USING (transfer_id) WHERE i.leaf_id = $1 ORDER BY o.idx",
			&[&&leaf[..]],
		).await?.iter().map(|r| array32(r.get(0), "leaf id")).collect()
	}

	/// The batches whose sweep token is `token`.
	pub async fn batches_of_token(&self, token: &[u8]) -> Result<Vec<([u8; 32], u32)>, StoreError> {
		let conn = self.conn().await?;
		conn.query(
			"SELECT r.txid, b.vout FROM batch b JOIN round r ON r.round_id = b.round_id WHERE b.token = $1",
			&[&token],
		).await?.iter().map(|r| Ok((array32(r.get(0), "txid")?, r.get::<_, i32>(1) as u32))).collect()
	}
}
