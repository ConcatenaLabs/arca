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
	Expired,
}

impl ParticipationState {
	pub fn as_str(self) -> &'static str {
		match self {
			ParticipationState::Pending => "pending",
			ParticipationState::Issued => "issued",
			ParticipationState::Released => "released",
			ParticipationState::Void => "void",
			ParticipationState::Expired => "expired",
		}
	}

	fn parse(s: &str) -> Result<ParticipationState, StoreError> {
		Ok(match s {
			"pending" => ParticipationState::Pending,
			"issued" => ParticipationState::Issued,
			"released" => ParticipationState::Released,
			"void" => ParticipationState::Void,
			"expired" => ParticipationState::Expired,
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
	/// Given back to its owner, live again: by a participation that will
	/// never run, or whose forfeits never came.
	pub returned: bool,
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

/// A forfeit to record: the coin given up, both signatures over its move into
/// the forfeit output, and what that output names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewForfeit {
	pub leaf_id: [u8; 32],
	pub owner_sig: [u8; 64],
	pub operator_sig: [u8; 64],
	pub refund_delay_units: u16,
	pub margin: u64,
	pub unlock_hash: [u8; 32],
	pub connector_asset: [u8; 32],
}

/// An owner's release as stored: the coin, the connector asset of the round
/// it names, the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseRow {
	pub leaf_id: [u8; 32],
	pub round_id: i64,
	pub connector_asset: [u8; 32],
	pub signature: [u8; 64],
}

/// A forfeit as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForfeitRow {
	pub forfeit: NewForfeit,
	pub round_id: i64,
	pub participation_id: [u8; 32],
	pub attempt: u32,
}

/// An earlier attempt of a participation: the round it was in, its unlock
/// hash and preimage then, whether that preimage went out, and whether the
/// round is lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptRow {
	pub attempt: u32,
	pub round_id: i64,
	pub unlock_hash: [u8; 32],
	pub preimage: [u8; 32],
	pub released: bool,
	pub round_lost: bool,
}

/// What [`Store::restore_round`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Restored {
	/// The participations back as they stood in the round.
	pub restored: Vec<[u8; 32]>,
	/// Those left where they are, and why.
	pub left: Vec<([u8; 32], String)>,
	/// The rounds retired with it.
	pub retired: Vec<i64>,
	/// The participations of those rounds that run again, never in this one.
	pub rerun: Vec<[u8; 32]>,
	/// How many of its new leaves were credited.
	pub credited: u64,
	/// How many coins made out of its leaves by transfers are live again.
	pub revived: u64,
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
	pub not_before: Option<u32>,
	pub refund_delay_units: u16,
	pub inputs: Vec<ParticipationInput>,
	pub outputs: Vec<ParticipationOutput>,
	pub fees: Vec<([u8; 32], u64)>,
	/// Why a round that could have taken it did not, while it is pending.
	pub waiting: Option<String>,
	/// Why it will never run, once void.
	pub void_reason: Option<String>,
}

fn u64_of(v: i64, what: &str) -> Result<u64, StoreError> {
	u64::try_from(v).map_err(|_| StoreError::Corrupt(format!("{} {}", what, v)))
}

fn i64_of(v: u64) -> Result<i64, StoreError> {
	i64::try_from(v).map_err(|_| StoreError::Corrupt(format!("amount {}", v)))
}

/// A fresh operator nonce for a leaf `by` wants under `owner_nonce`,
/// recorded as issued and taken by `by` at once, whose salt with
/// `owner_nonce` is new to the server and now promised to `by`.
pub(super) async fn draw_salted_nonce(t: &tokio_postgres::Transaction<'_>, by: &[u8; 32], owner_nonce: &[u8; 32])
	-> Result<[u8; 32], StoreError>
{
	loop {
		let nonce = draw_nonce(t, by).await?;
		if super::coins::promise_salt(t, &arca_covenant::leaf::leaf_salt(owner_nonce, &nonce), by).await? {
			return Ok(nonce);
		}
	}
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
		"SELECT participation_id, unlock_hash, preimage, attempt, round_id, state::text, void_reason, not_before,
		        refund_delay_units, waiting
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
		not_before: not_before.map(|t| t as u32),
		refund_delay_units: refund as u16,
		inputs: vec![],
		outputs: vec![],
		fees: vec![],
		waiting: r.get(9),
		void_reason: r.get(6),
	};
	for r in c.query(
		"SELECT leaf_id, asset, value, margin, attestation, active FROM participation_input WHERE participation_id = $1 ORDER BY idx",
		&[&&id[..]],
	).await? {
		let att: Vec<u8> = r.get(4);
		row.inputs.push(ParticipationInput {
			leaf_id: array32(r.get(0), "leaf id")?,
			asset: array32(r.get(1), "asset")?,
			value: u64_of(r.get(2), "value")?,
			margin: u64_of(r.get(3), "margin")?,
			attestation: att.try_into().map_err(|_| StoreError::Corrupt("attestation".into()))?,
			returned: !r.get::<_, bool>(5),
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
	/// live and becomes spent by it (a coin is given up by one participation
	/// at a time), every leaf
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
					if t.query_opt("SELECT 1 FROM leaf WHERE owner_key = $1 AND state NOT IN ('lost', 'expired')", &[&&owner_key[..]]).await?.is_some() {
						return Err(StoreError::KeyReused);
					}
					let nonce = draw_salted_nonce(&t, &p.id, owner_nonce).await?;
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

	/// Begins the forfeit step of participation `id` at `attempt`, in the
	/// round `round_id`, whole or not at all, before the signer is asked for
	/// anything: records each forfeit with its owner's half and without the
	/// operator's (a forfeit already recorded stays as it was), fills in each
	/// new leaf's coin record (a record already there stays; a batch leaf's
	/// record is served only once its preimage went out), and records
	/// `messages`, the forfeits' messages the signer is to sign. Refused with
	/// [`StoreError::NotInRound`] once the participation is neither issued nor
	/// released.
	pub async fn begin_forfeits(&self, id: &[u8; 32], attempt: u32, round_id: i64, forfeits: &[NewForfeit],
		records: &[([u8; 32], Vec<u8>)], messages: &[super::SignerMessage]) -> Result<(), StoreError>
	{
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		lock_in_round(&t, id, attempt, round_id).await?;
		for f in forfeits {
			t.execute(
				"INSERT INTO forfeit (leaf_id, round_id, participation_id, attempt, owner_sig, operator_sig, refund_delay_units,
				 margin, unlock_hash, connector_asset)
				 VALUES ($1, $2, $3, $4, $5, NULL, $6, $7, $8, $9) ON CONFLICT DO NOTHING",
				&[&&f.leaf_id[..], &round_id, &&id[..], &(attempt as i32), &&f.owner_sig[..],
					&(f.refund_delay_units as i32), &i64_of(f.margin)?, &&f.unlock_hash[..], &&f.connector_asset[..]],
			).await?;
		}
		for (leaf, record) in records {
			t.execute("UPDATE leaf SET record = $2, updated_at = now() WHERE leaf_id = $1 AND kind = 'batch' AND record = ''::bytea",
				&[&&leaf[..], record]).await?;
		}
		super::insert_messages(&t, messages).await?;
		t.commit().await?;
		Ok(())
	}

	/// The operator's half of the forfeit of `leaf_id` for the round
	/// `round_id`, filled in where it is missing.
	pub async fn set_forfeit_operator_sig(&self, leaf_id: &[u8; 32], round_id: i64, sig: &[u8; 64]) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute("UPDATE forfeit SET operator_sig = $3 WHERE leaf_id = $1 AND round_id = $2 AND operator_sig IS NULL",
			&[&&leaf_id[..], &round_id, &&sig[..]]).await?;
		Ok(())
	}

	/// Every forfeit recorded without the operator's half: the signer was
	/// asked for it and the answer never stored (the server stopped, the
	/// signer went away), or not asked yet.
	pub async fn unsigned_forfeits(&self) -> Result<Vec<ForfeitRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT leaf_id, owner_sig, refund_delay_units, margin, unlock_hash, connector_asset, round_id, participation_id, attempt
			 FROM forfeit WHERE operator_sig IS NULL ORDER BY created_at, leaf_id",
			&[],
		).await?;
		rows.iter().map(|r| {
			let a: Vec<u8> = r.get(1);
			Ok(ForfeitRow {
				forfeit: NewForfeit {
					leaf_id: array32(r.get(0), "leaf id")?,
					owner_sig: a.try_into().map_err(|_| StoreError::Corrupt("signature".into()))?,
					operator_sig: [0; 64],
					refund_delay_units: r.get::<_, i32>(2) as u16,
					margin: r.get::<_, i64>(3) as u64,
					unlock_hash: array32(r.get(4), "unlock hash")?,
					connector_asset: array32(r.get(5), "connector asset")?,
				},
				round_id: r.get(6),
				participation_id: array32(r.get(7), "participation id")?,
				attempt: r.get::<_, i32>(8) as u32,
			})
		}).collect()
	}

	/// Completes the forfeit step of participation `id` at `attempt`, in the
	/// round `round_id`, whole or not at all: records each forfeit whole (the
	/// operator's half filled in where [`Store::begin_forfeits`] left it
	/// out; a whole forfeit already recorded stays as it was), fills in each
	/// new leaf's coin record (a record already there stays), and moves the
	/// participation from issued to released (it may be released already)
	/// and credits its new leaves if the round is final.
	pub async fn complete_participation(&self, id: &[u8; 32], attempt: u32, round_id: i64, forfeits: &[NewForfeit],
		records: &[([u8; 32], Vec<u8>)]) -> Result<(), StoreError>
	{
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let state = lock_in_round(&t, id, attempt, round_id).await?;
		for f in forfeits {
			t.execute(
				"INSERT INTO forfeit (leaf_id, round_id, participation_id, attempt, owner_sig, operator_sig, refund_delay_units,
				 margin, unlock_hash, connector_asset)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
				 ON CONFLICT (leaf_id, round_id) DO UPDATE SET operator_sig = EXCLUDED.operator_sig WHERE forfeit.operator_sig IS NULL",
				&[&&f.leaf_id[..], &round_id, &&id[..], &(attempt as i32), &&f.owner_sig[..], &&f.operator_sig[..],
					&(f.refund_delay_units as i32), &i64_of(f.margin)?, &&f.unlock_hash[..], &&f.connector_asset[..]],
			).await?;
		}
		for (leaf, record) in records {
			t.execute("UPDATE leaf SET record = $2, updated_at = now() WHERE leaf_id = $1 AND kind = 'batch' AND record = ''::bytea",
				&[&&leaf[..], record]).await?;
		}
		if state == ParticipationState::Issued {
			t.execute("UPDATE participation SET state = 'released', updated_at = now() WHERE participation_id = $1",
				&[&&id[..]]).await?;
			credit(&t, round_id).await?;
		}
		t.commit().await?;
		Ok(())
	}

	/// A new leaf of participation `id`, of a lost round, that was spent
	/// before the round was lost: the leaf, the round's transaction, and what
	/// spent it (a transfer's id or a participation's).
	pub async fn spent_leaf_of_lost_round(&self, id: &[u8; 32]) -> Result<Option<([u8; 32], [u8; 32], [u8; 32])>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(
			"SELECT l.leaf_id, r.txid, l.spent_by FROM leaf l JOIN batch_leaf bl ON bl.leaf_id = l.leaf_id
			 JOIN round r ON r.round_id = bl.round_id
			 WHERE bl.participation_id = $1 AND l.state = 'spent' AND r.state = 'lost' ORDER BY bl.round_id DESC LIMIT 1",
			&[&&id[..]],
		).await?;
		r.map(|r| Ok((array32(r.get(0), "leaf id")?, array32(r.get(1), "txid")?, array32(r.get(2), "spent by")?))).transpose()
	}

	/// The participation the forfeit of `leaf_id` for the round `round_id`
	/// was signed for.
	pub async fn forfeit_participation(&self, leaf_id: &[u8; 32], round_id: i64) -> Result<Option<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt("SELECT participation_id FROM forfeit WHERE leaf_id = $1 AND round_id = $2", &[&&leaf_id[..], &round_id]).await?;
		r.map(|r| array32(r.get(0), "participation id")).transpose()
	}

	/// The forfeits of participation `id` for the round `round_id`.
	pub async fn forfeits(&self, id: &[u8; 32], round_id: i64) -> Result<Vec<ForfeitRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT leaf_id, owner_sig, operator_sig, refund_delay_units, margin, unlock_hash, connector_asset, round_id,
			        participation_id, attempt
			 FROM forfeit WHERE participation_id = $1 AND round_id = $2 AND operator_sig IS NOT NULL ORDER BY leaf_id",
			&[&&id[..], &round_id],
		).await?;
		rows.iter().map(|r| {
			let a: Vec<u8> = r.get(1);
			let b: Vec<u8> = r.get(2);
			Ok(ForfeitRow {
				forfeit: NewForfeit {
					leaf_id: array32(r.get(0), "leaf id")?,
					owner_sig: a.try_into().map_err(|_| StoreError::Corrupt("signature".into()))?,
					operator_sig: b.try_into().map_err(|_| StoreError::Corrupt("signature".into()))?,
					refund_delay_units: r.get::<_, i32>(3) as u16,
					margin: u64_of(r.get(4), "margin")?,
					unlock_hash: array32(r.get(5), "unlock hash")?,
					connector_asset: array32(r.get(6), "connector asset")?,
				},
				round_id: r.get(7),
				participation_id: array32(r.get(8), "participation id")?,
				attempt: r.get::<_, i32>(9) as u32,
			})
		}).collect()
	}

	/// Credits the new leaves of every released participation of the round
	/// `round_id`, if the round is final: each pending one becomes live.
	/// Returns how many did.
	pub async fn credit_round(&self, round_id: i64) -> Result<u64, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let n = credit(&t, round_id).await?;
		t.commit().await?;
		Ok(n)
	}

	/// Records an owner's release of the lowest node of `leaf_id`, given up in
	/// participation `id`, for its round `round_id`, whose connector asset
	/// the release names. A release already recorded for that coin and round
	/// stays as it was; returns whether this one is new.
	#[allow(clippy::too_many_arguments)]
	pub async fn insert_release(&self, leaf_id: &[u8; 32], id: &[u8; 32], round_id: i64, node_hash: &[u8; 32],
		connector_asset: &[u8; 32], signature: &[u8; 64]) -> Result<bool, StoreError>
	{
		let conn = self.conn().await?;
		let n = conn.execute(
			"INSERT INTO node_release (leaf_id, round_id, participation_id, node_hash, connector_asset, signature)
			 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
			&[&&leaf_id[..], &round_id, &&id[..], &&node_hash[..], &&connector_asset[..], &&signature[..]],
		).await?;
		Ok(n == 1)
	}

	/// The releases recorded for the lowest node whose children hash is
	/// `node_hash`, but those retired with a lost round: each coin, the round
	/// and connector asset it names, and its owner's signature. A reclaim
	/// needs one atom of each connector asset named.
	pub async fn releases(&self, node_hash: &[u8; 32]) -> Result<Vec<ReleaseRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT leaf_id, round_id, connector_asset, signature FROM node_release
			 WHERE node_hash = $1 AND NOT retired ORDER BY leaf_id",
			&[&&node_hash[..]]).await?;
		rows.iter().map(|r| {
			let sig: Vec<u8> = r.get(3);
			Ok(ReleaseRow {
				leaf_id: array32(r.get(0), "leaf id")?,
				round_id: r.get(1),
				connector_asset: array32(r.get(2), "connector asset")?,
				signature: sig.try_into().map_err(|_| StoreError::Corrupt("signature".into()))?,
			})
		}).collect()
	}

	/// Uncredits the live new leaves of the round `round_id`, which is no
	/// longer final: each goes back to pending until the round is final
	/// again. A leaf already spent stays spent; what rests on it is refused
	/// while its round is not final. Returns how many.
	pub async fn uncredit_round(&self, round_id: i64) -> Result<u64, StoreError> {
		let conn = self.conn().await?;
		Ok(conn.execute(
			"UPDATE leaf SET state = 'pending', updated_at = now()
			 WHERE state = 'live' AND leaf_id IN (SELECT leaf_id FROM batch_leaf WHERE round_id = $1)",
			&[&round_id],
		).await?)
	}

	/// Retires the round `round_id`, which went out of the chain, whole or not
	/// at all: the round is lost, its new leaves not yet spent are lost, and
	/// every participation it ran runs again in a later round as an ordinary
	/// participation, under a new unlock hash, with a new operator nonce for
	/// each leaf it wants (its keys and owner nonces as before), the attempt
	/// it leaves recorded, and any release of the coins it gave up retired.
	/// The coins those participations gave up stay given up. The round's row
	/// lock orders this against [`Store::insert_watcher_tx`]: a forfeit naming
	/// the round is logged before it is lost, or never. Returns the
	/// participations that run again.
	pub async fn retire_round(&self, round_id: i64) -> Result<Vec<[u8; 32]>, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let again = retire_in(&t, round_id, &std::collections::HashSet::new()).await?.unwrap_or_default();
		t.commit().await?;
		Ok(again)
	}

	/// The earlier attempts of participation `id`: each round it was in that
	/// went out of the chain, or that another of its rounds replaced, newest
	/// first.
	pub async fn attempts(&self, id: &[u8; 32]) -> Result<Vec<AttemptRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT a.attempt, a.round_id, a.unlock_hash, a.preimage, a.released, r.state = 'lost'
			 FROM participation_attempt a JOIN round r ON r.round_id = a.round_id
			 WHERE a.participation_id = $1 ORDER BY a.attempt DESC",
			&[&&id[..]],
		).await?;
		rows.iter().map(|r| Ok(AttemptRow {
			attempt: r.get::<_, i32>(0) as u32,
			round_id: r.get(1),
			unlock_hash: array32(r.get(2), "unlock hash")?,
			preimage: array32(r.get(3), "preimage")?,
			released: r.get(4),
			round_lost: r.get(5),
		})).collect()
	}

	/// The participations with an earlier attempt in the round `round_id`,
	/// and the round each is in now, if any.
	pub async fn earlier_in(&self, round_id: i64) -> Result<Vec<([u8; 32], Option<i64>)>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT p.participation_id, p.round_id FROM participation_attempt a
			 JOIN participation p ON p.participation_id = a.participation_id
			 WHERE a.round_id = $1 ORDER BY p.participation_id",
			&[&round_id],
		).await?;
		rows.iter().map(|r| Ok((array32(r.get(0), "participation id")?, r.get(1)))).collect()
	}

	/// Restores the round `round_id`, held as lost, which is final in the
	/// chain again, whole or not at all: the round is final, every round in
	/// `retire` (each one that ran its participations again, which can now
	/// never confirm beside it) is retired, and every participation it ran is
	/// back as it stood when the round was final, under that round's unlock
	/// hash and operator nonces, its new leaves pending again (credited at
	/// once if it was released), its releases for the round good again, and
	/// every forfeit naming the round in the watcher's log followed by the
	/// nursery again; a leaf of it in a retired round that it paid on is lost,
	/// resting on a round that can never confirm beside this one. A
	/// participation is left where it is when the round it is in now is not
	/// retired (it stands too), when it was never released in the round and
	/// gave a coin back since, or when a key it wants has been taken by
	/// another since; its leaves of the round stay lost. Nothing runs
	/// a third time for a participation brought back: a round in `retire`
	/// runs again only those of its participations that were never in this
	/// one. Returns `None` when the round is not lost.
	///
	/// A participation in `uncredited` (one of whose coins was spent on the
	/// chain otherwise than by its forfeit for the round, and why) is left
	/// void, saying why, its new leaves of the round never credited
	/// (`expired`: theirs to take on the chain who holds their records, the
	/// operator's loss, and swept with their batch if left).
	pub async fn restore_round(&self, round_id: i64, retire: &[i64], final_mtp: u32, uncredited: &[([u8; 32], String)])
		-> Result<Option<Restored>, StoreError>
	{
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let n = t.execute(
			"UPDATE round SET state = 'final', final_mtp = $2, updated_at = now() WHERE round_id = $1 AND state = 'lost'",
			&[&round_id, &(final_mtp as i64)],
		).await?;
		if n != 1 {
			return Ok(None);
		}
		let back = t.query(
			"SELECT participation_id, attempt, unlock_hash, preimage, released FROM participation_attempt WHERE round_id = $1
			 ORDER BY participation_id",
			&[&round_id],
		).await?;
		let keep: std::collections::HashSet<[u8; 32]> = back.iter().map(|r| array32(r.get(0), "participation id")).collect::<Result<_, _>>()?;
		let mut out = Restored::default();
		for y in retire {
			if let Some(again) = retire_in(&t, *y, &keep).await? {
				out.retired.push(*y);
				out.rerun.extend(again);
			}
		}
		for r in back {
			let id = array32(r.get(0), "participation id")?;
			let attempt: i32 = r.get(1);
			let unlock_hash: Vec<u8> = r.get(2);
			let preimage: Vec<u8> = r.get(3);
			let released: bool = r.get(4);
			let cur = t.query_one(
				"SELECT p.state::text, p.round_id, p.attempt, p.unlock_hash, p.preimage, r.state
				 FROM participation p LEFT JOIN round r ON r.round_id = p.round_id WHERE p.participation_id = $1 FOR UPDATE OF p",
				&[&&id[..]],
			).await?;
			let (state, cur_round, cur_attempt): (&str, Option<i64>, i32) = (cur.get(0), cur.get(1), cur.get(2));
			let cur_round_state: Option<String> = cur.get(5);
			if let Some((_, why)) = uncredited.iter().find(|(p, _)| *p == id) {
				t.execute(
					"UPDATE leaf SET state = 'expired', updated_at = now() WHERE state IN ('lost', 'pending', 'live') AND leaf_id IN (
					   SELECT leaf_id FROM batch_leaf WHERE participation_id = $1 AND round_id = $2 AND attempt = $3)",
					&[&&id[..], &round_id, &attempt],
				).await?;
				// Void, whatever it stands at now: its round of now, if
				// another, was retired here or is lost.
				let cur_lost = cur_round.is_none_or(|c| c == round_id || out.retired.contains(&c)) || cur_round_state.as_deref() == Some("lost");
				if state == "void" || cur_lost {
					t.execute("UPDATE participation SET state = 'void', round_id = NULL, void_reason = $2, waiting = NULL, updated_at = now()
					           WHERE participation_id = $1", &[&&id[..], why]).await?;
				}
				out.left.push((id, why.clone()));
				continue;
			}
			if cur_round.is_some_and(|c| c != round_id) && cur_round_state.as_deref() != Some("lost") {
				out.left.push((id, "the round it is in now stands".into()));
				continue;
			}
			if !released && t.query_opt("SELECT 1 FROM participation_input WHERE participation_id = $1 AND NOT active", &[&&id[..]])
				.await?.is_some()
			{
				out.left.push((id, "it was never released in the round, and a coin it gave up was given back since".into()));
				continue;
			}
			// A leaf of a round retired here that it paid on rests on a round
			// that can never confirm beside this one: lost, its key free for
			// the leaf brought back.
			t.execute(
				"UPDATE leaf SET state = 'lost', spent_by = NULL, updated_at = now() WHERE state = 'spent' AND leaf_id IN (
				   SELECT leaf_id FROM batch_leaf WHERE participation_id = $1 AND round_id = ANY($2))",
				&[&&id[..], &out.retired],
			).await?;
			let taken = t.query_opt(
				"SELECT 1 FROM participation_output o WHERE o.participation_id = $1 AND o.kind = 'leaf' AND (
				   EXISTS (SELECT 1 FROM participation_output x WHERE x.owner_key = o.owner_key AND x.kind = 'leaf' AND x.active
				           AND x.participation_id <> $1)
				   OR EXISTS (SELECT 1 FROM leaf l WHERE l.owner_key = o.owner_key AND l.state NOT IN ('lost', 'expired')
				           AND l.leaf_id NOT IN (SELECT leaf_id FROM batch_leaf WHERE participation_id = $1 AND round_id = $2 AND attempt = $3)))",
				&[&&id[..], &round_id, &attempt],
			).await?;
			if taken.is_some() {
				out.left.push((id, "a key it wants a leaf under has been taken by another since".into()));
				continue;
			}
			// The attempt it is in now, if it has a round, is kept with the
			// others, so that round can be restored in turn.
			if let Some(c) = cur_round.filter(|c| *c != round_id) {
				let cur_hash: Vec<u8> = cur.get(3);
				let cur_pre: Vec<u8> = cur.get(4);
				t.execute(
					"INSERT INTO participation_attempt (participation_id, attempt, round_id, unlock_hash, preimage, released)
					 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
					&[&&id[..], &cur_attempt, &c, &cur_hash, &cur_pre, &(state == "released")],
				).await?;
			}
			t.execute("DELETE FROM participation_attempt WHERE participation_id = $1 AND attempt = $2", &[&&id[..], &attempt]).await?;
			t.execute(
				"UPDATE participation SET state = $2::text::participation_state, round_id = $3, attempt = $4, unlock_hash = $5,
				 preimage = $6, void_reason = NULL, waiting = NULL, updated_at = now() WHERE participation_id = $1",
				&[&&id[..], &if released { "released" } else { "issued" }, &round_id, &attempt, &unlock_hash, &preimage],
			).await?;
			t.execute(
				"UPDATE participation_output o SET operator_nonce = bl.operator_nonce, leaf_id = bl.leaf_id
				 FROM batch_leaf bl WHERE bl.participation_id = $1 AND bl.round_id = $2 AND bl.attempt = $3
				   AND o.participation_id = $1 AND o.idx = bl.output_idx",
				&[&&id[..], &round_id, &attempt],
			).await?;
			t.execute("UPDATE participation_output SET active = true WHERE participation_id = $1", &[&&id[..]]).await?;
			t.execute(
				"UPDATE leaf SET state = 'pending', updated_at = now() WHERE state = 'lost' AND leaf_id IN (
				   SELECT leaf_id FROM batch_leaf WHERE participation_id = $1 AND round_id = $2 AND attempt = $3)",
				&[&&id[..], &round_id, &attempt],
			).await?;
			t.execute("UPDATE node_release SET retired = false WHERE participation_id = $1 AND round_id = $2", &[&&id[..], &round_id]).await?;
			out.restored.push(id);
		}
		out.credited = credit(&t, round_id).await?;
		// Every coin a transfer made out of a leaf of the round that is lost
		// is the holder's again, unless it rests on another round still lost,
		// or on a board lost: live once the transfer is signed.
		let lost = t.query(
			&format!("{} SELECT l.leaf_id, tr.state FROM leaf l JOIN transfer_output o ON o.leaf_id = l.leaf_id
			 JOIN transfer tr ON tr.transfer_id = o.transfer_id
			 WHERE l.kind = 'transfer' AND l.state = 'lost' AND l.leaf_id IN (SELECT leaf_id FROM d)", DESCENDANTS),
			&[&round_id],
		).await?;
		for r in lost {
			let leaf: Vec<u8> = r.get(0);
			let signed = r.get::<_, &str>(1) == "signed";
			let still = t.query_one(
				"WITH RECURSIVE a(leaf_id) AS (
				   SELECT $1::bytea
				   UNION
				   SELECT i.leaf_id FROM a JOIN transfer_output o ON o.leaf_id = a.leaf_id JOIN transfer_input i ON i.transfer_id = o.transfer_id)
				 SELECT EXISTS (SELECT 1 FROM a JOIN batch_leaf bl ON bl.leaf_id = a.leaf_id JOIN round r ON r.round_id = bl.round_id
				                WHERE r.state = 'lost')
				     OR EXISTS (SELECT 1 FROM a JOIN board b ON b.leaf_id = a.leaf_id WHERE b.state = 'lost')",
				&[&leaf],
			).await?;
			if !still.get::<_, bool>(0) {
				t.execute("UPDATE leaf SET state = $2::text::leaf_state, updated_at = now() WHERE leaf_id = $1",
					&[&leaf, &if signed { "live" } else { "pending" }]).await?;
				out.revived += 1;
			}
		}
		// Every forfeit naming the round can be claimed again: the nursery
		// follows each, and judges it again, as it does any transaction.
		t.execute(
			"UPDATE nursery_tx SET state = 'pending' WHERE state = 'lost'
			 AND (txid IN (SELECT txid FROM watcher_tx WHERE kind = 'forfeit' AND round_id = $1)
			      OR txid = (SELECT txid FROM round WHERE round_id = $1))",
			&[&round_id],
		).await?;
		t.commit().await?;
		Ok(Some(out))
	}

	/// The forfeits in the watcher's log of a coin participation `id` gave
	/// up, not yet given up on by the nursery: `(txid, the coin's leaf id)`.
	/// Every forfeit of such a coin names a round of the participation's.
	pub async fn logged_forfeits_of(&self, id: &[u8; 32]) -> Result<Vec<([u8; 32], [u8; 32])>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT w.txid, w.subject FROM watcher_tx w JOIN nursery_tx n ON n.txid = w.txid
			 WHERE w.kind = 'forfeit' AND n.state <> 'lost'
			   AND w.subject IN (SELECT leaf_id FROM participation_input WHERE participation_id = $1)
			 ORDER BY w.created_at, w.txid",
			&[&&id[..]],
		).await?;
		rows.iter().map(|r| Ok((array32(r.get(0), "txid")?, array32(r.get(1), "leaf id")?))).collect()
	}

	/// Says why the pending participation `id` waits, or that it does not
	/// (`None`).
	pub async fn set_waiting(&self, id: &[u8; 32], why: Option<&str>) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute("UPDATE participation SET waiting = $2 WHERE participation_id = $1 AND waiting IS DISTINCT FROM $2",
			&[&&id[..], &why]).await?;
		Ok(())
	}

	/// Voids the pending participation `id`, which will not run, for the
	/// reason `why`, which its status shows: each coin it gave up for which
	/// no forfeit was ever signed is given back ([`give_back`]). Returns
	/// whether it was pending.
	pub async fn void_participation(&self, id: &[u8; 32], why: &str) -> Result<bool, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let n = t.execute(
			"UPDATE participation SET state = 'void', void_reason = $2, updated_at = now() WHERE participation_id = $1 AND state = 'pending'",
			&[&&id[..], &why],
		).await?;
		if n != 1 {
			return Ok(false);
		}
		give_back(&t, id).await?;
		free_keys(&t, id).await?;
		t.commit().await?;
		Ok(true)
	}

	/// Expires every participation issued in a round found final at or
	/// before median time `cutoff` and not released since: its forfeits for
	/// that round never came, or came and were never all co-signed. Each
	/// becomes expired, its new leaves expired (never credited; their
	/// preimage never goes out, and the operator sweeps them); each of its
	/// forfeits for that round without the operator's half is dropped, so the
	/// signer is never asked for it again ([`Store::unsigned_forfeits`]); and
	/// each coin it gave up under no forfeit left is given back
	/// ([`give_back`]). A coin under a forfeit the operator holds whole stays
	/// given up: that forfeit's claim would reveal the preimage, and its
	/// owner's way home is its refund or its exit. Returns the participations
	/// expired.
	pub async fn expire_participations(&self, cutoff: u32) -> Result<Vec<[u8; 32]>, StoreError> {
		let mut expired = vec![];
		for id in self.overdue_participations(cutoff).await? {
			if self.expire_participation(&id, cutoff).await? {
				expired.push(id);
			}
		}
		Ok(expired)
	}

	/// The participations issued in a round found final at or before median
	/// time `cutoff` and not released since, oldest id first: those
	/// [`Store::expire_participation`] may expire.
	pub async fn overdue_participations(&self, cutoff: u32) -> Result<Vec<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let due = conn.query(
			"SELECT p.participation_id FROM participation p JOIN round r ON r.round_id = p.round_id
			 WHERE p.state = 'issued' AND r.state = 'final' AND r.final_mtp <= $1
			 ORDER BY p.participation_id",
			&[&(cutoff as i64)],
		).await?;
		due.iter().map(|r| array32(r.get(0), "participation id")).collect()
	}

	/// [`Store::expire_participations`] for one participation, whole or not
	/// at all, its row locked first so that a forfeit step in flight either
	/// completes before it, and the participation does not expire, or finds
	/// it expired and stores nothing: a co-signature the signer gave it then
	/// is dropped with the request. Returns whether it expired.
	pub async fn expire_participation(&self, id: &[u8; 32], cutoff: u32) -> Result<bool, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let row = t.query_opt(
			"SELECT p.round_id, p.attempt FROM participation p JOIN round r ON r.round_id = p.round_id
			 WHERE p.participation_id = $1 AND p.state = 'issued' AND r.state = 'final' AND r.final_mtp <= $2
			 FOR UPDATE OF p",
			&[&&id[..], &(cutoff as i64)],
		).await?;
		let (round_id, attempt): (i64, i32) = match row {
			Some(r) => (r.get(0), r.get(1)),
			None => return Ok(false),
		};
		t.execute("DELETE FROM forfeit WHERE participation_id = $1 AND round_id = $2 AND operator_sig IS NULL", &[&&id[..], &round_id])
			.await?;
		t.execute("UPDATE participation SET state = 'expired', updated_at = now() WHERE participation_id = $1", &[&&id[..]]).await?;
		t.execute(
			"UPDATE leaf SET state = 'expired', updated_at = now()
			 WHERE state = 'pending' AND leaf_id IN (
				SELECT leaf_id FROM batch_leaf WHERE participation_id = $1 AND round_id = $2 AND attempt = $3)",
			&[&&id[..], &round_id, &attempt],
		).await?;
		give_back(&t, id).await?;
		free_keys(&t, id).await?;
		t.commit().await?;
		Ok(true)
	}

	/// Whether `key` owns a leaf that is neither lost nor expired (a leaf of a
	/// participation that expired was never credited).
	pub async fn key_owns_leaf(&self, key: &[u8; 32]) -> Result<bool, StoreError> {
		let conn = self.conn().await?;
		Ok(conn.query_opt("SELECT 1 FROM leaf WHERE owner_key = $1 AND state NOT IN ('lost', 'expired')", &[&&key[..]]).await?.is_some())
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

/// The coins a transfer made out of a leaf of the round `$1`, at any depth:
/// the common table `d`.
const DESCENDANTS: &str = "WITH RECURSIVE d(leaf_id) AS (
	SELECT leaf_id FROM batch_leaf WHERE round_id = $1
	UNION
	SELECT o.leaf_id FROM d JOIN transfer_input i ON i.leaf_id = d.leaf_id JOIN transfer_output o ON o.transfer_id = i.transfer_id)";

/// [`Store::retire_round`] inside `t`, but the participations in `keep`,
/// whose attempt in the round is kept with the others and which the caller
/// moves on itself: `None` when the round was lost already, else the
/// participations that run again. A participation runs again under an
/// attempt number above every one it has had.
async fn retire_in(t: &tokio_postgres::Transaction<'_>, round_id: i64, keep: &std::collections::HashSet<[u8; 32]>)
	-> Result<Option<Vec<[u8; 32]>>, StoreError>
{
	let n = t.execute(
		"UPDATE round SET state = 'lost', final_mtp = NULL, updated_at = now() WHERE round_id = $1 AND state <> 'lost'",
		&[&round_id],
	).await?;
	if n != 1 {
		return Ok(None);
	}
	t.execute(
		"UPDATE leaf SET state = 'lost', updated_at = now()
		 WHERE state IN ('pending', 'live') AND leaf_id IN (SELECT leaf_id FROM batch_leaf WHERE round_id = $1)",
		&[&round_id],
	).await?;
	// Every coin a transfer made out of a leaf of the round, at any depth,
	// rests on the round: lost while it is out.
	t.execute(
		&format!("{} UPDATE leaf SET state = 'lost', updated_at = now()
		 WHERE kind = 'transfer' AND state IN ('pending', 'live') AND leaf_id IN (SELECT leaf_id FROM d)", DESCENDANTS),
		&[&round_id],
	).await?;
	let rows = t.query(
		"SELECT participation_id, attempt, unlock_hash, preimage, state::text FROM participation
		 WHERE round_id = $1 AND state IN ('issued', 'released') FOR UPDATE",
		&[&round_id],
	).await?;
	let mut again = Vec::with_capacity(rows.len());
	for r in rows {
		let id = array32(r.get(0), "participation id")?;
		let attempt: i32 = r.get(1);
		let unlock_hash: Vec<u8> = r.get(2);
		let preimage: Vec<u8> = r.get(3);
		let released = r.get::<_, &str>(4) == "released";
		t.execute(
			"INSERT INTO participation_attempt (participation_id, attempt, round_id, unlock_hash, preimage, released)
			 VALUES ($1, $2, $3, $4, $5, $6)",
			&[&&id[..], &attempt, &round_id, &unlock_hash, &preimage, &released],
		).await?;
		// Releases given for this round name its connector asset, which
		// is not issued while the round is out of the chain.
		t.execute("UPDATE node_release SET retired = true WHERE participation_id = $1 AND round_id = $2",
			&[&&id[..], &round_id]).await?;
		if keep.contains(&id) {
			continue;
		}
		let mut new_preimage = [0u8; 32];
		rand::rngs::OsRng.fill_bytes(&mut new_preimage);
		let new_hash = arca_covenant::script::sha256(&new_preimage);
		t.execute(
			"UPDATE participation SET state = 'pending', round_id = NULL,
			 attempt = GREATEST(attempt, (SELECT coalesce(max(attempt), 0) FROM participation_attempt WHERE participation_id = $1)) + 1,
			 unlock_hash = $2, preimage = $3, updated_at = now() WHERE participation_id = $1",
			&[&&id[..], &&new_hash[..], &&new_preimage[..]],
		).await?;
		let outputs = t.query(
			"SELECT idx, owner_nonce FROM participation_output WHERE participation_id = $1 AND kind = 'leaf' ORDER BY idx",
			&[&&id[..]],
		).await?;
		for o in outputs {
			let idx: i16 = o.get(0);
			let owner_nonce = array32(o.get(1), "owner nonce")?;
			let nonce = draw_salted_nonce(t, &id, &owner_nonce).await?;
			t.execute(
				"UPDATE participation_output SET operator_nonce = $3, leaf_id = NULL WHERE participation_id = $1 AND idx = $2",
				&[&&id[..], &idx, &&nonce[..]],
			).await?;
		}
		t.execute("UPDATE participation_output SET leaf_id = NULL WHERE participation_id = $1", &[&&id[..]]).await?;
		again.push(id);
	}
	Ok(Some(again))
}

/// Locks participation `id` inside `t`, at `attempt` in the round
/// `round_id`, and returns its state: issued or released, or
/// [`StoreError::NotInRound`] when it expired meanwhile (its coins are the
/// owner's again, and nothing is taken for it).
async fn lock_in_round(t: &tokio_postgres::Transaction<'_>, id: &[u8; 32], attempt: u32, round_id: i64)
	-> Result<ParticipationState, StoreError>
{
	let row = t.query_opt(
		"SELECT state::text FROM participation WHERE participation_id = $1 AND attempt = $2 AND round_id = $3 FOR UPDATE",
		&[&&id[..], &(attempt as i32), &round_id],
	).await?;
	let state = match row {
		Some(r) => ParticipationState::parse(r.get(0))?,
		None => return Err(StoreError::Corrupt(format!("participation {} is not in round {} at attempt {}", hex(id), round_id, attempt))),
	};
	if !matches!(state, ParticipationState::Issued | ParticipationState::Released) {
		return Err(StoreError::NotInRound(state.as_str()));
	}
	Ok(state)
}

/// The keys participation `id` wanted, free again: it is void or expired, and
/// no leaf of it was ever credited.
async fn free_keys(t: &tokio_postgres::Transaction<'_>, id: &[u8; 32]) -> Result<u64, StoreError> {
	Ok(t.execute("UPDATE participation_output SET active = false WHERE participation_id = $1 AND kind = 'leaf'", &[&&id[..]]).await?)
}

/// Gives back, inside `t`, each coin the participation `id` gave up for which
/// no forfeit was ever signed, in any of its attempts: the coin is live again
/// and its input inactive, so it can be given up again. A coin with a forfeit
/// signed, for a lost round included, stays given up: the
/// signer co-signs no spend under a salt it has signed a forfeit under, and
/// such a forfeit may still confirm if the operator published it. The coin
/// is its owner's on the chain, by that forfeit's refund or by its exit.
async fn give_back(t: &tokio_postgres::Transaction<'_>, id: &[u8; 32]) -> Result<u64, StoreError> {
	let free = "SELECT leaf_id FROM participation_input i WHERE i.participation_id = $1 AND i.active
		AND NOT EXISTS (SELECT 1 FROM forfeit f WHERE f.participation_id = $1 AND f.leaf_id = i.leaf_id)";
	let n = t.execute(
		&format!("UPDATE leaf SET state = 'live', spent_by = NULL, updated_at = now()
		 WHERE spent_by = $1 AND state = 'spent' AND leaf_id IN ({})", free),
		&[&&id[..]],
	).await?;
	t.execute(&format!("UPDATE participation_input SET active = false WHERE participation_id = $1 AND leaf_id IN ({})", free),
		&[&&id[..]]).await?;
	Ok(n)
}

/// Credits, inside `t`, the new leaves of every released participation of
/// the round `round_id` if it is final.
async fn credit(t: &tokio_postgres::Transaction<'_>, round_id: i64) -> Result<u64, StoreError> {
	Ok(t.execute(
		"UPDATE leaf SET state = 'live', updated_at = now()
		 WHERE state = 'pending' AND record <> ''::bytea AND leaf_id IN (
			SELECT bl.leaf_id FROM batch_leaf bl
			JOIN participation p ON p.participation_id = bl.participation_id AND p.attempt = bl.attempt AND p.round_id = bl.round_id
			WHERE bl.round_id = $1 AND p.state = 'released')
		 AND EXISTS (SELECT 1 FROM round WHERE round_id = $1 AND state = 'final')",
		&[&round_id],
	).await?)
}
