//! Participations: the coins an owner gives up for a round, the outputs it
//! wants, its unlock hash and its fee.

use rand::RngCore;

use super::coins::leaf_row;
use super::{array32, hex, Store, StoreError};

/// Where a participation stands. See the schema for each state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParticipationState {
	Pending,
	Issued,
	Released,
	Void,
}

impl ParticipationState {
	pub fn as_str(self) -> &'static str {
		match self {
			ParticipationState::Pending => "pending",
			ParticipationState::Issued => "issued",
			ParticipationState::Released => "released",
			ParticipationState::Void => "void",
		}
	}

	fn parse(s: &str) -> Result<ParticipationState, StoreError> {
		Ok(match s {
			"pending" => ParticipationState::Pending,
			"issued" => ParticipationState::Issued,
			"released" => ParticipationState::Released,
			"void" => ParticipationState::Void,
			other => return Err(StoreError::Corrupt(format!("participation state {}", other))),
		})
	}
}

/// A coin given up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipationInput {
	pub leaf_id: [u8; 32],
	pub asset: [u8; 32],
	pub value: u64,
	/// What the forfeit leaves uncommitted for its own fee.
	pub margin: u64,
	pub attestation: [u8; 64],
}

/// What an output wanted is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WantedKind {
	/// A leaf: its template's name, owner key and nonce, exit delay, and the
	/// operator nonce of the current attempt (drawn by the store).
	Leaf { template: String, owner_key: [u8; 32], owner_nonce: [u8; 32], exit_delay_units: u16, operator_nonce: [u8; 32] },
	/// An offboard's on-chain output: the destination script, the margin the
	/// round's output holds for its unlock, the operator's reclaim delay.
	Offboard { script: Vec<u8>, margin: u64, reclaim_delay_units: u16 },
}

/// An output wanted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipationOutput {
	pub asset: [u8; 32],
	pub value: u64,
	pub kind: WantedKind,
	/// The leaf the current attempt's round made of it.
	pub leaf_id: Option<[u8; 32]>,
}

/// A participation to record. The operator nonce of each leaf wanted is
/// drawn by the store; whatever the caller put there is replaced.
#[derive(Debug, Clone)]
pub struct NewParticipation {
	pub id: [u8; 32],
	pub unlock_hash: [u8; 32],
	pub preimage: [u8; 32],
	pub not_before: Option<u32>,
	pub refund_delay_units: u16,
	pub inputs: Vec<ParticipationInput>,
	pub outputs: Vec<ParticipationOutput>,
	pub fees: Vec<([u8; 32], u64)>,
}

/// A participation as the database holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipationRow {
	pub id: [u8; 32],
	pub unlock_hash: [u8; 32],
	pub preimage: [u8; 32],
	pub attempt: u32,
	pub round_id: Option<i64>,
	pub state: ParticipationState,
	pub forfeit_first: bool,
	pub not_before: Option<u32>,
	pub refund_delay_units: u16,
	pub inputs: Vec<ParticipationInput>,
	pub outputs: Vec<ParticipationOutput>,
	pub fees: Vec<([u8; 32], u64)>,
}

fn u64_of(v: i64, what: &str) -> Result<u64, StoreError> {
	u64::try_from(v).map_err(|_| StoreError::Corrupt(format!("{} {}", what, v)))
}

fn i64_of(v: u64) -> Result<i64, StoreError> {
	i64::try_from(v).map_err(|_| StoreError::Corrupt(format!("amount {}", v)))
}

/// A fresh operator nonce, recorded as issued and taken by `by` at once.
pub(super) async fn draw_nonce(t: &tokio_postgres::Transaction<'_>, by: &[u8; 32]) -> Result<[u8; 32], StoreError> {
	loop {
		let mut nonce = [0u8; 32];
		rand::rngs::OsRng.fill_bytes(&mut nonce);
		let n = t.execute(
			"INSERT INTO operator_nonce (nonce, used_at, used_by) VALUES ($1, now(), $2) ON CONFLICT DO NOTHING",
			&[&&nonce[..], &&by[..]],
		).await?;
		if n == 1 {
			return Ok(nonce);
		}
	}
}

/// Reads the participation `id` inside `c` (a connection or a transaction).
pub(super) async fn read_participation<C: tokio_postgres::GenericClient>(c: &C, id: &[u8; 32])
	-> Result<Option<ParticipationRow>, StoreError>
{
	let r = c.query_opt(
		"SELECT participation_id, unlock_hash, preimage, attempt, round_id, state::text, forfeit_first, not_before,
		        refund_delay_units
		 FROM participation WHERE participation_id = $1",
		&[&&id[..]],
	).await?;
	let r = match r {
		Some(r) => r,
		None => return Ok(None),
	};
	let attempt: i32 = r.get(3);
	let not_before: Option<i64> = r.get(7);
	let refund: i32 = r.get(8);
	let mut row = ParticipationRow {
		id: array32(r.get(0), "participation id")?,
		unlock_hash: array32(r.get(1), "unlock hash")?,
		preimage: array32(r.get(2), "preimage")?,
		attempt: attempt as u32,
		round_id: r.get(4),
		state: ParticipationState::parse(r.get(5))?,
		forfeit_first: r.get(6),
		not_before: not_before.map(|t| t as u32),
		refund_delay_units: refund as u16,
		inputs: vec![],
		outputs: vec![],
		fees: vec![],
	};
	for r in c.query(
		"SELECT leaf_id, asset, value, margin, attestation FROM participation_input WHERE participation_id = $1 ORDER BY idx",
		&[&&id[..]],
	).await? {
		let att: Vec<u8> = r.get(4);
		row.inputs.push(ParticipationInput {
			leaf_id: array32(r.get(0), "leaf id")?,
			asset: array32(r.get(1), "asset")?,
			value: u64_of(r.get(2), "value")?,
			margin: u64_of(r.get(3), "margin")?,
			attestation: att.try_into().map_err(|_| StoreError::Corrupt("attestation".into()))?,
		});
	}
	for r in c.query(
		"SELECT kind, asset, value, template, owner_key, owner_nonce, exit_delay_units, operator_nonce, leaf_id,
		        script, margin, reclaim_delay_units
		 FROM participation_output WHERE participation_id = $1 ORDER BY idx",
		&[&&id[..]],
	).await? {
		let kind = match r.get::<_, &str>(0) {
			"leaf" => WantedKind::Leaf {
				template: r.get(3),
				owner_key: array32(r.get(4), "owner key")?,
				owner_nonce: array32(r.get(5), "owner nonce")?,
				exit_delay_units: r.get::<_, i32>(6) as u16,
				operator_nonce: array32(r.get(7), "operator nonce")?,
			},
			"offboard" => WantedKind::Offboard {
				script: r.get(9),
				margin: u64_of(r.get(10), "margin")?,
				reclaim_delay_units: r.get::<_, i32>(11) as u16,
			},
			other => return Err(StoreError::Corrupt(format!("output kind {}", other))),
		};
		let leaf_id: Option<Vec<u8>> = r.get(8);
		row.outputs.push(ParticipationOutput {
			asset: array32(r.get(1), "asset")?,
			value: u64_of(r.get(2), "value")?,
			kind,
			leaf_id: leaf_id.map(|l| array32(l, "leaf id")).transpose()?,
		});
	}
	for r in c.query("SELECT asset, amount FROM participation_fee WHERE participation_id = $1 ORDER BY asset", &[&&id[..]]).await? {
		row.fees.push((array32(r.get(0), "asset")?, u64_of(r.get(1), "fee")?));
	}
	Ok(Some(row))
}

impl Store {
	/// Records a participation, whole or not at all: every coin given up is
	/// live and becomes spent by it (a coin is given up once), every leaf
	/// wanted takes a fresh operator nonce, and no key wanted owns a leaf or
	/// is wanted by another participation. A participation already recorded
	/// under the same id is [`StoreError::ParticipationExists`].
	pub async fn insert_participation(&self, p: &NewParticipation) -> Result<(), StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let r = t.execute(
			"INSERT INTO participation (participation_id, unlock_hash, preimage, not_before, refund_delay_units)
			 VALUES ($1, $2, $3, $4, $5)",
			&[&&p.id[..], &&p.unlock_hash[..], &&p.preimage[..], &p.not_before.map(|t| t as i64), &(p.refund_delay_units as i32)],
		).await;
		if let Err(e) = r {
			if StoreError::is_unique(&e, "participation_pkey") {
				return Err(StoreError::ParticipationExists);
			}
			return Err(e.into());
		}
		for (k, i) in p.inputs.iter().enumerate() {
			let r = t.query_opt(
				"SELECT leaf_id, kind::text, asset, value, owner_key, script_pubkey, hops, record, state::text, spent_by
				 FROM leaf WHERE leaf_id = $1 FOR UPDATE",
				&[&&i.leaf_id[..]],
			).await?;
			let leaf = match r {
				Some(r) => leaf_row(&r)?,
				None => return Err(StoreError::LeafUnknown(hex(&i.leaf_id))),
			};
			match leaf.state {
				super::LeafState::Live => {},
				super::LeafState::Spent => return Err(StoreError::LeafSpent(hex(&i.leaf_id))),
				other => return Err(StoreError::LeafNotLive(hex(&i.leaf_id), other.as_str())),
			}
			let r = t.execute(
				"INSERT INTO participation_input (participation_id, idx, leaf_id, asset, value, margin, attestation)
				 VALUES ($1, $2, $3, $4, $5, $6, $7)",
				&[&&p.id[..], &(k as i16), &&i.leaf_id[..], &&i.asset[..], &i64_of(i.value)?, &i64_of(i.margin)?, &&i.attestation[..]],
			).await;
			if let Err(e) = r {
				if StoreError::is_unique(&e, "participation_input_leaf_id_key") {
					return Err(StoreError::LeafSpent(hex(&i.leaf_id)));
				}
				return Err(e.into());
			}
			t.execute("UPDATE leaf SET state = 'spent', spent_by = $2, updated_at = now() WHERE leaf_id = $1",
				&[&&i.leaf_id[..], &&p.id[..]]).await?;
		}
		for (k, o) in p.outputs.iter().enumerate() {
			let r = match &o.kind {
				WantedKind::Leaf { template, owner_key, owner_nonce, exit_delay_units, .. } => {
					if t.query_opt("SELECT 1 FROM leaf WHERE owner_key = $1 AND state <> 'lost'", &[&&owner_key[..]]).await?.is_some() {
						return Err(StoreError::KeyReused);
					}
					let nonce = draw_nonce(&t, &p.id).await?;
					t.execute(
						"INSERT INTO participation_output
						 (participation_id, idx, kind, asset, value, template, owner_key, owner_nonce, exit_delay_units, operator_nonce)
						 VALUES ($1, $2, 'leaf', $3, $4, $5, $6, $7, $8, $9)",
						&[&&p.id[..], &(k as i16), &&o.asset[..], &i64_of(o.value)?, template, &&owner_key[..], &&owner_nonce[..],
							&(*exit_delay_units as i32), &&nonce[..]],
					).await
				},
				WantedKind::Offboard { script, margin, reclaim_delay_units } => t.execute(
					"INSERT INTO participation_output
					 (participation_id, idx, kind, asset, value, script, margin, reclaim_delay_units)
					 VALUES ($1, $2, 'offboard', $3, $4, $5, $6, $7)",
					&[&&p.id[..], &(k as i16), &&o.asset[..], &i64_of(o.value)?, script, &i64_of(*margin)?, &(*reclaim_delay_units as i32)],
				).await,
			};
			if let Err(e) = r {
				if StoreError::is_unique(&e, "participation_output_owner_key") {
					return Err(StoreError::KeyReused);
				}
				return Err(e.into());
			}
		}
		for (asset, amount) in &p.fees {
			t.execute("INSERT INTO participation_fee (participation_id, asset, amount) VALUES ($1, $2, $3)",
				&[&&p.id[..], &&asset[..], &i64_of(*amount)?]).await?;
		}
		t.commit().await?;
		Ok(())
	}

	/// The participation `id`, with its inputs, outputs and fees.
	pub async fn participation(&self, id: &[u8; 32]) -> Result<Option<ParticipationRow>, StoreError> {
		let conn = self.conn().await?;
		read_participation(&*conn, id).await
	}

	/// The ids of the participations in `state`, oldest first.
	pub async fn participations_in(&self, state: ParticipationState) -> Result<Vec<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT participation_id FROM participation WHERE state = $1::text::participation_state
			 ORDER BY created_at, participation_id",
			&[&state.as_str()],
		).await?;
		rows.iter().map(|r| array32(r.get(0), "participation id")).collect()
	}
}
