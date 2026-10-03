//! Rounds: the transactions the operator built, their batches with every leaf
//! the tree builder took, their offboard outputs, and their connector output.

use super::coins::{insert_coin, NewCoin};
use super::{array32, hex, Store, StoreError};

/// Where a round stands. See the schema for each state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundState {
	Built,
	Broadcast,
	Final,
	Lost,
}

impl RoundState {
	pub fn as_str(self) -> &'static str {
		match self {
			RoundState::Built => "built",
			RoundState::Broadcast => "broadcast",
			RoundState::Final => "final",
			RoundState::Lost => "lost",
		}
	}

	fn parse(s: &str) -> Result<RoundState, StoreError> {
		Ok(match s {
			"built" => RoundState::Built,
			"broadcast" => RoundState::Broadcast,
			"final" => RoundState::Final,
			"lost" => RoundState::Lost,
			other => return Err(StoreError::Corrupt(format!("round state {}", other))),
		})
	}
}

/// A round as the database holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundRow {
	pub round_id: i64,
	pub txid: [u8; 32],
	pub tx: Vec<u8>,
	pub state: RoundState,
	pub fee_asset: [u8; 32],
	pub fee: u64,
	pub created_mtp: u32,
	/// The tip's median time when the round was last found final; `None`
	/// while it is not final.
	pub final_mtp: Option<u32>,
	/// The connector output: its index, asset, value and the connector asset.
	pub connector_vout: u32,
	pub connector_asset: [u8; 32],
}

/// A leaf of a batch to record: its coin (pending, its record empty), its
/// place in the tree, the participation output it is, the parts the builder
/// took and the leaf record it gave.
#[derive(Debug, Clone)]
pub struct NewBatchLeaf {
	pub coin: NewCoin,
	pub idx: u32,
	pub participation_id: [u8; 32],
	pub output_idx: u16,
	pub attempt: u32,
	pub template: String,
	pub owner_key: [u8; 32],
	pub owner_nonce: [u8; 32],
	pub operator_nonce: [u8; 32],
	pub exit_delay_units: u16,
	pub value: u64,
	pub unlock_hash: [u8; 32],
	pub record: Vec<u8>,
}

/// A tree's reserve rule, as stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredReserve {
	FeeRate { floor_per_kvb: u64, multiple: u64 },
	Fixed { node: u64, entry: u64 },
}

/// A batch: its output, its token and schedule, the builder's parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchRow {
	pub round_id: i64,
	pub vout: u32,
	pub asset: [u8; 32],
	pub value: u64,
	pub token: [u8; 32],
	pub token_vout: u32,
	pub issuer: ([u8; 32], u32),
	/// The schedule, in arca-covenant's canonical encoding.
	pub schedule: Vec<u8>,
	pub burn: bool,
	pub radix: u16,
	pub reserve: StoredReserve,
	pub min_leaf: u64,
}

/// A batch to record, with its leaves in tree order and the scripts of its
/// nodes and entries.
#[derive(Debug, Clone)]
pub struct NewBatch {
	pub batch: BatchRow,
	pub leaves: Vec<NewBatchLeaf>,
	pub scripts: Vec<super::NewTreeScript>,
}

/// A leaf of a batch, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchLeafRow {
	pub leaf_id: [u8; 32],
	pub round_id: i64,
	pub vout: u32,
	pub idx: u32,
	pub participation_id: [u8; 32],
	pub output_idx: u16,
	pub attempt: u32,
	pub template: String,
	pub owner_key: [u8; 32],
	pub owner_nonce: [u8; 32],
	pub operator_nonce: [u8; 32],
	pub exit_delay_units: u16,
	pub value: u64,
	pub unlock_hash: [u8; 32],
	pub record: Vec<u8>,
}

/// An offboard output of a round, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffboardRow {
	pub round_id: i64,
	pub vout: u32,
	pub participation_id: [u8; 32],
	pub output_idx: u16,
	pub attempt: u32,
	/// The output's value: the destination's and the margin for its unlock.
	pub value: u64,
}

/// An offboard output a round pays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOffboard {
	pub vout: u32,
	pub participation_id: [u8; 32],
	pub output_idx: u16,
	pub attempt: u32,
	pub value: u64,
}

/// A round to record.
#[derive(Debug, Clone)]
pub struct NewRound {
	pub txid: [u8; 32],
	pub tx: Vec<u8>,
	pub fee_asset: [u8; 32],
	pub fee: u64,
	pub created_mtp: u32,
	/// The connector output: index, asset, value, and the connector asset.
	pub connector: (u32, [u8; 32], u64, [u8; 32]),
	pub batches: Vec<NewBatch>,
	pub offboards: Vec<NewOffboard>,
	/// Every participation the round runs, with the attempt it runs.
	pub participations: Vec<([u8; 32], u32)>,
	/// The latest entry of the signer's record the database knew when the
	/// round was built, and its running hash.
	pub signer_head: Option<(u64, [u8; 32])>,
}

/// Where a participation's outputs are in the round of its current attempt.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Placement {
	/// `(output index, leaf id, batch output index, index among the batch's leaves)`.
	pub leaves: Vec<(u16, [u8; 32], u32, u32)>,
	/// `(output index, the offboard output's index)`.
	pub offboards: Vec<(u16, u32)>,
}

fn i64_of(v: u64) -> Result<i64, StoreError> {
	i64::try_from(v).map_err(|_| StoreError::Corrupt(format!("amount {}", v)))
}

fn u64_of(v: i64, what: &str) -> Result<u64, StoreError> {
	u64::try_from(v).map_err(|_| StoreError::Corrupt(format!("{} {}", what, v)))
}

const ROUND_COLUMNS: &str = "r.round_id, r.txid, r.tx, r.state, r.fee_asset, r.fee, r.created_mtp, c.vout, c.connector_asset, r.final_mtp";

fn round_row(r: &tokio_postgres::Row) -> Result<RoundRow, StoreError> {
	Ok(RoundRow {
		round_id: r.get(0),
		txid: array32(r.get(1), "txid")?,
		tx: r.get(2),
		state: RoundState::parse(r.get(3))?,
		fee_asset: array32(r.get(4), "fee asset")?,
		fee: u64_of(r.get(5), "fee")?,
		created_mtp: r.get::<_, i64>(6) as u32,
		connector_vout: r.get::<_, i32>(7) as u32,
		connector_asset: array32(r.get(8), "connector asset")?,
		final_mtp: r.get::<_, Option<i64>>(9).map(|t| t as u32),
	})
}

const BATCH_COLUMNS: &str = "round_id, vout, asset, value, token, token_vout, issuer_txid, issuer_vout, schedule, burn, radix,
	reserve_kind, reserve_a, reserve_b, min_leaf";

fn batch_row(r: &tokio_postgres::Row) -> Result<BatchRow, StoreError> {
	let (a, b) = (u64_of(r.get(12), "reserve")?, u64_of(r.get(13), "reserve")?);
	Ok(BatchRow {
		round_id: r.get(0),
		vout: r.get::<_, i32>(1) as u32,
		asset: array32(r.get(2), "asset")?,
		value: u64_of(r.get(3), "value")?,
		token: array32(r.get(4), "token")?,
		token_vout: r.get::<_, i32>(5) as u32,
		issuer: (array32(r.get(6), "issuer txid")?, r.get::<_, i32>(7) as u32),
		schedule: r.get(8),
		burn: r.get(9),
		radix: r.get::<_, i16>(10) as u16,
		reserve: match r.get::<_, &str>(11) {
			"fee_rate" => StoredReserve::FeeRate { floor_per_kvb: a, multiple: b },
			"fixed" => StoredReserve::Fixed { node: a, entry: b },
			other => return Err(StoreError::Corrupt(format!("reserve kind {}", other))),
		},
		min_leaf: u64_of(r.get(14), "min leaf")?,
	})
}

const LEAF_COLUMNS: &str = "leaf_id, round_id, vout, idx, participation_id, output_idx, attempt, template, owner_key, owner_nonce,
	operator_nonce, exit_delay_units, value, unlock_hash, record";

fn batch_leaf_row(r: &tokio_postgres::Row) -> Result<BatchLeafRow, StoreError> {
	Ok(BatchLeafRow {
		leaf_id: array32(r.get(0), "leaf id")?,
		round_id: r.get(1),
		vout: r.get::<_, i32>(2) as u32,
		idx: r.get::<_, i32>(3) as u32,
		participation_id: array32(r.get(4), "participation id")?,
		output_idx: r.get::<_, i16>(5) as u16,
		attempt: r.get::<_, i32>(6) as u32,
		template: r.get(7),
		owner_key: array32(r.get(8), "owner key")?,
		owner_nonce: array32(r.get(9), "owner nonce")?,
		operator_nonce: array32(r.get(10), "operator nonce")?,
		exit_delay_units: r.get::<_, i32>(11) as u16,
		value: u64_of(r.get(12), "value")?,
		unlock_hash: array32(r.get(13), "unlock hash")?,
		record: r.get(14),
	})
}

impl Store {
	/// The latest entry of the signer's record the database knew when round
	/// `round_id` was built, and its running hash; `None` for a round built
	/// before rounds kept it.
	pub async fn round_signer_head(&self, round_id: i64) -> Result<Option<(u64, [u8; 32])>, StoreError> {
		let conn = self.conn().await?;
		let row = conn.query_opt("SELECT signer_entry, signer_hash FROM round WHERE round_id = $1", &[&round_id]).await?;
		match row.map(|r| (r.get::<_, Option<i64>>(0), r.get::<_, Option<Vec<u8>>>(1))) {
			Some((Some(n), Some(h))) => Ok(Some((n as u64, super::array32(h, "signer hash")?))),
			_ => Ok(None),
		}
	}

	/// Records a round, whole or not at all: the round (built), its connector
	/// output, each batch with each of its leaves as a pending coin (its
	/// script new to the server, its key owning no other leaf), each offboard
	/// output, and every participation it runs moved from pending to issued
	/// in it. A participation no longer pending at its attempt refuses the
	/// whole round. Returns the round's id.
	pub async fn insert_round(&self, r: &NewRound) -> Result<i64, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let row = t.query_one(
			"INSERT INTO round (txid, tx, state, fee_asset, fee, created_mtp, signer_entry, signer_hash)
			 VALUES ($1, $2, 'built', $3, $4, $5, $6, $7) RETURNING round_id",
			&[&&r.txid[..], &r.tx, &&r.fee_asset[..], &i64_of(r.fee)?, &(r.created_mtp as i64),
				&r.signer_head.map(|h| h.0 as i64), &r.signer_head.map(|h| h.1.to_vec())],
		).await?;
		let round_id: i64 = row.get(0);
		let (cv, ca, cval, cm) = &r.connector;
		t.execute(
			"INSERT INTO connector_output (round_id, vout, asset, value, connector_asset) VALUES ($1, $2, $3, $4, $5)",
			&[&round_id, &(*cv as i32), &&ca[..], &i64_of(*cval)?, &&cm[..]],
		).await?;
		for (pid, attempt) in &r.participations {
			let n = t.execute(
				"UPDATE participation SET state = 'issued', round_id = $2, updated_at = now()
				 WHERE participation_id = $1 AND state = 'pending' AND attempt = $3",
				&[&&pid[..], &round_id, &(*attempt as i32)],
			).await?;
			if n != 1 {
				return Err(StoreError::Corrupt(format!("participation {} is no longer pending at attempt {}", hex(pid), attempt)));
			}
		}
		for b in &r.batches {
			let x = &b.batch;
			let (kind, a, bb) = match x.reserve {
				StoredReserve::FeeRate { floor_per_kvb, multiple } => ("fee_rate", floor_per_kvb, multiple),
				StoredReserve::Fixed { node, entry } => ("fixed", node, entry),
			};
			t.execute(
				"INSERT INTO batch (round_id, vout, asset, value, token, token_vout, issuer_txid, issuer_vout, schedule, burn,
				 radix, reserve_kind, reserve_a, reserve_b, min_leaf)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
				&[&round_id, &(x.vout as i32), &&x.asset[..], &i64_of(x.value)?, &&x.token[..], &(x.token_vout as i32),
					&&x.issuer.0[..], &(x.issuer.1 as i32), &x.schedule, &x.burn, &(x.radix as i16), &kind, &i64_of(a)?,
					&i64_of(bb)?, &i64_of(x.min_leaf)?],
			).await?;
			for sc in &b.scripts {
				t.execute(
					"INSERT INTO tree_script (script_pubkey, round_id, batch_vout, kind, level, idx, value)
					 VALUES ($1, $2, $3, $4, $5, $6, $7)",
					&[&sc.script_pubkey, &round_id, &(x.vout as i32), &sc.kind.as_str(), &sc.level, &(sc.idx as i32), &i64_of(sc.value)?],
				).await?;
			}
			for l in &b.leaves {
				insert_coin(&t, &l.coin).await?;
				t.execute(
					"INSERT INTO batch_leaf (leaf_id, round_id, vout, idx, participation_id, output_idx, attempt, template,
					 owner_key, owner_nonce, operator_nonce, exit_delay_units, value, unlock_hash, record)
					 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
					&[&&l.coin.leaf_id[..], &round_id, &(x.vout as i32), &(l.idx as i32), &&l.participation_id[..],
						&(l.output_idx as i16), &(l.attempt as i32), &l.template, &&l.owner_key[..], &&l.owner_nonce[..],
						&&l.operator_nonce[..], &(l.exit_delay_units as i32), &i64_of(l.value)?, &&l.unlock_hash[..], &l.record],
				).await?;
				t.execute(
					"UPDATE participation_output SET leaf_id = $3 WHERE participation_id = $1 AND idx = $2",
					&[&&l.participation_id[..], &(l.output_idx as i16), &&l.coin.leaf_id[..]],
				).await?;
			}
		}
		for o in &r.offboards {
			t.execute(
				"INSERT INTO round_offboard (round_id, vout, participation_id, output_idx, attempt, value) VALUES ($1, $2, $3, $4, $5, $6)",
				&[&round_id, &(o.vout as i32), &&o.participation_id[..], &(o.output_idx as i16), &(o.attempt as i32), &i64_of(o.value)?],
			).await?;
		}
		t.commit().await?;
		Ok(round_id)
	}

	/// The round `round_id`.
	pub async fn round(&self, round_id: i64) -> Result<Option<RoundRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(
			&format!("SELECT {} FROM round r JOIN connector_output c ON c.round_id = r.round_id WHERE r.round_id = $1", ROUND_COLUMNS),
			&[&round_id],
		).await?;
		r.as_ref().map(round_row).transpose()
	}

	/// The round whose transaction is `txid`.
	pub async fn round_by_txid(&self, txid: &[u8; 32]) -> Result<Option<RoundRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(
			&format!("SELECT {} FROM round r JOIN connector_output c ON c.round_id = r.round_id WHERE r.txid = $1", ROUND_COLUMNS),
			&[&&txid[..]],
		).await?;
		r.as_ref().map(round_row).transpose()
	}

	/// The rounds in `state`, oldest first.
	pub async fn rounds_in(&self, state: RoundState) -> Result<Vec<RoundRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			&format!("SELECT {} FROM round r JOIN connector_output c ON c.round_id = r.round_id WHERE r.state = $1 ORDER BY r.round_id",
				ROUND_COLUMNS),
			&[&state.as_str()],
		).await?;
		rows.iter().map(round_row).collect()
	}

	/// Moves the round `round_id` from `from` to `to`; returns whether it was
	/// in `from`. A round leaving final forgets when it was found final.
	pub async fn set_round_state(&self, round_id: i64, from: RoundState, to: RoundState) -> Result<bool, StoreError> {
		let conn = self.conn().await?;
		let n = conn.execute(
			"UPDATE round SET state = $3, final_mtp = CASE WHEN $3 = 'final' THEN final_mtp END, updated_at = now()
			 WHERE round_id = $1 AND state = $2",
			&[&round_id, &from.as_str(), &to.as_str()],
		).await?;
		Ok(n == 1)
	}

	/// Moves the round `round_id` from broadcast to final, found so at the
	/// tip's median time `mtp`; returns whether it was broadcast.
	pub async fn mark_round_final(&self, round_id: i64, mtp: u32) -> Result<bool, StoreError> {
		let conn = self.conn().await?;
		let n = conn.execute(
			"UPDATE round SET state = 'final', final_mtp = $2, updated_at = now() WHERE round_id = $1 AND state = 'broadcast'",
			&[&round_id, &(mtp as i64)],
		).await?;
		Ok(n == 1)
	}

	/// The batch paid by output `vout` of the round whose transaction is
	/// `txid`, with its leaves in tree order.
	pub async fn batch(&self, txid: &[u8; 32], vout: u32) -> Result<Option<(BatchRow, Vec<BatchLeafRow>)>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(
			&format!("SELECT {} FROM batch WHERE round_id = (SELECT round_id FROM round WHERE txid = $1) AND vout = $2", BATCH_COLUMNS),
			&[&&txid[..], &(vout as i32)],
		).await?;
		let batch = match r {
			Some(r) => batch_row(&r)?,
			None => return Ok(None),
		};
		let rows = conn.query(
			&format!("SELECT {} FROM batch_leaf WHERE round_id = $1 AND vout = $2 ORDER BY idx", LEAF_COLUMNS),
			&[&batch.round_id, &(vout as i32)],
		).await?;
		let leaves = rows.iter().map(batch_leaf_row).collect::<Result<_, _>>()?;
		Ok(Some((batch, leaves)))
	}

	/// The batches of the round `round_id`.
	pub async fn batches(&self, round_id: i64) -> Result<Vec<BatchRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!("SELECT {} FROM batch WHERE round_id = $1 ORDER BY vout", BATCH_COLUMNS), &[&round_id]).await?;
		rows.iter().map(batch_row).collect()
	}

	/// The leaf of a batch whose id is `leaf_id`.
	pub async fn batch_leaf(&self, leaf_id: &[u8; 32]) -> Result<Option<BatchLeafRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(&format!("SELECT {} FROM batch_leaf WHERE leaf_id = $1", LEAF_COLUMNS), &[&&leaf_id[..]]).await?;
		r.as_ref().map(batch_leaf_row).transpose()
	}

	/// The leaves of batches of the round `round_id`.
	pub async fn round_leaves(&self, round_id: i64) -> Result<Vec<BatchLeafRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!("SELECT {} FROM batch_leaf WHERE round_id = $1 ORDER BY vout, idx", LEAF_COLUMNS), &[&round_id]).await?;
		rows.iter().map(batch_leaf_row).collect()
	}

	/// Where the outputs of participation `id` are in the round of its
	/// attempt `attempt`.
	pub async fn placement(&self, id: &[u8; 32], attempt: u32) -> Result<Placement, StoreError> {
		let conn = self.conn().await?;
		let mut p = Placement::default();
		for r in conn.query(
			"SELECT output_idx, leaf_id, vout, idx FROM batch_leaf WHERE participation_id = $1 AND attempt = $2 ORDER BY output_idx",
			&[&&id[..], &(attempt as i32)],
		).await? {
			p.leaves.push((r.get::<_, i16>(0) as u16, array32(r.get(1), "leaf id")?, r.get::<_, i32>(2) as u32, r.get::<_, i32>(3) as u32));
		}
		for r in conn.query(
			"SELECT output_idx, vout FROM round_offboard WHERE participation_id = $1 AND attempt = $2 ORDER BY output_idx",
			&[&&id[..], &(attempt as i32)],
		).await? {
			p.offboards.push((r.get::<_, i16>(0) as u16, r.get::<_, i32>(1) as u32));
		}
		Ok(p)
	}

	/// Every offboard output of the rounds in `state`.
	pub async fn offboards_in(&self, state: RoundState) -> Result<Vec<OffboardRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT o.round_id, o.vout, o.participation_id, o.output_idx, o.attempt, o.value
			 FROM round_offboard o JOIN round r ON r.round_id = o.round_id WHERE r.state = $1 ORDER BY o.round_id, o.vout",
			&[&state.as_str()],
		).await?;
		rows.iter().map(|r| Ok(OffboardRow {
			round_id: r.get(0),
			vout: r.get::<_, i32>(1) as u32,
			participation_id: array32(r.get(2), "participation id")?,
			output_idx: r.get::<_, i16>(3) as u16,
			attempt: r.get::<_, i32>(4) as u32,
			value: r.get::<_, i64>(5) as u64,
		})).collect()
	}
}
