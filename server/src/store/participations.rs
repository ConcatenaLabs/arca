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

	/// Completes the forfeit step of participation `id` at `attempt`, in the
	/// round `round_id`, whole or not at all: records each forfeit (a forfeit
	/// already recorded stays as it was), fills in each new leaf's coin record
	/// (a record already there stays), and, when `release`, moves the
	/// participation from issued to released and credits its new leaves if
	/// the round is final. Returns whether the participation is released.
	pub async fn complete_participation(&self, id: &[u8; 32], attempt: u32, round_id: i64, forfeits: &[NewForfeit],
		records: &[([u8; 32], Vec<u8>)], release: bool) -> Result<bool, StoreError>
	{
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let row = t.query_opt(
			"SELECT state::text FROM participation WHERE participation_id = $1 AND attempt = $2 AND round_id = $3 FOR UPDATE",
			&[&&id[..], &(attempt as i32), &round_id],
		).await?;
		let state = match row {
			Some(r) => ParticipationState::parse(r.get(0))?,
			None => return Err(StoreError::Corrupt(format!("participation {} is not in round {} at attempt {}", hex(id), round_id, attempt))),
		};
		// It expired meanwhile: its coins are the owner's again, and nothing
		// is taken for it.
		if !matches!(state, ParticipationState::Issued | ParticipationState::Released) {
			return Err(StoreError::NotInRound(state.as_str()));
		}
		for f in forfeits {
			t.execute(
				"INSERT INTO forfeit (leaf_id, round_id, participation_id, attempt, owner_sig, operator_sig, refund_delay_units,
				 margin, unlock_hash, connector_asset)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT DO NOTHING",
				&[&&f.leaf_id[..], &round_id, &&id[..], &(attempt as i32), &&f.owner_sig[..], &&f.operator_sig[..],
					&(f.refund_delay_units as i32), &i64_of(f.margin)?, &&f.unlock_hash[..], &&f.connector_asset[..]],
			).await?;
		}
		for (leaf, record) in records {
			t.execute("UPDATE leaf SET record = $2, updated_at = now() WHERE leaf_id = $1 AND kind = 'batch' AND record = ''::bytea",
				&[&&leaf[..], record]).await?;
		}
		let released = match (state, release) {
			(ParticipationState::Released, _) => true,
			(ParticipationState::Issued, true) => {
				t.execute("UPDATE participation SET state = 'released', updated_at = now() WHERE participation_id = $1",
					&[&&id[..]]).await?;
				credit(&t, round_id).await?;
				true
			},
			_ => false,
		};
		t.commit().await?;
		Ok(released)
	}

	/// The forfeits of participation `id` for the round `round_id`.
	pub async fn forfeits(&self, id: &[u8; 32], round_id: i64) -> Result<Vec<ForfeitRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT leaf_id, owner_sig, operator_sig, refund_delay_units, margin, unlock_hash, connector_asset, round_id,
			        participation_id, attempt
			 FROM forfeit WHERE participation_id = $1 AND round_id = $2 ORDER BY leaf_id",
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

	/// Retires the round `round_id`, which can never return, whole or not at
	/// all: the round is lost, its new leaves not yet spent are lost, and every
	/// participation it ran runs again in a later round, under a new unlock
	/// hash, with a new operator nonce for each leaf it wants (its keys and
	/// owner nonces as before), the attempt it leaves recorded, and any
	/// release of the coins it gave up retired. A participation whose
	/// preimage had gone out runs again forfeit-first.
	/// The coins those participations gave up stay given up. Returns the
	/// participations that run again, and which of them forfeit-first.
	pub async fn retire_round(&self, round_id: i64) -> Result<Vec<([u8; 32], bool)>, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let n = t.execute(
			"UPDATE round SET state = 'lost', updated_at = now() WHERE round_id = $1 AND state <> 'lost'",
			&[&round_id],
		).await?;
		if n != 1 {
			return Ok(vec![]);
		}
		t.execute(
			"UPDATE leaf SET state = 'lost', updated_at = now()
			 WHERE state IN ('pending', 'live') AND leaf_id IN (SELECT leaf_id FROM batch_leaf WHERE round_id = $1)",
			&[&round_id],
		).await?;
		let rows = t.query(
			"SELECT participation_id, attempt, unlock_hash, preimage, state::text, forfeit_first FROM participation
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
			let forfeit_first = r.get::<_, bool>(5) || released;
			t.execute(
				"INSERT INTO participation_attempt (participation_id, attempt, round_id, unlock_hash, preimage, released)
				 VALUES ($1, $2, $3, $4, $5, $6)",
				&[&&id[..], &attempt, &round_id, &unlock_hash, &preimage, &released],
			).await?;
			let mut new_preimage = [0u8; 32];
			rand::rngs::OsRng.fill_bytes(&mut new_preimage);
			let new_hash = arca_covenant::script::sha256(&new_preimage);
			t.execute(
				"UPDATE participation SET state = 'pending', round_id = NULL, attempt = attempt + 1, unlock_hash = $2,
				 preimage = $3, forfeit_first = $4, updated_at = now() WHERE participation_id = $1",
				&[&&id[..], &&new_hash[..], &&new_preimage[..], &forfeit_first],
			).await?;
			let outputs = t.query(
				"SELECT idx FROM participation_output WHERE participation_id = $1 AND kind = 'leaf' ORDER BY idx", &[&&id[..]],
			).await?;
			for o in outputs {
				let idx: i16 = o.get(0);
				let nonce = draw_nonce(&t, &id).await?;
				t.execute(
					"UPDATE participation_output SET operator_nonce = $3, leaf_id = NULL WHERE participation_id = $1 AND idx = $2",
					&[&&id[..], &idx, &&nonce[..]],
				).await?;
			}
			t.execute("UPDATE participation_output SET leaf_id = NULL WHERE participation_id = $1", &[&&id[..]]).await?;
			// Releases given for this round name its connector asset, which
			// can never be issued now: they are never used.
			t.execute("UPDATE node_release SET retired = true WHERE participation_id = $1 AND round_id = $2",
				&[&&id[..], &round_id]).await?;
			again.push((id, forfeit_first));
		}
		t.commit().await?;
		Ok(again)
	}

	/// Voids the pending participation `id`, which will not run: each coin it
	/// gave up for which no forfeit was ever signed is given back
	/// ([`give_back`]). Returns whether it was pending.
	pub async fn void_participation(&self, id: &[u8; 32]) -> Result<bool, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let n = t.execute(
			"UPDATE participation SET state = 'void', updated_at = now() WHERE participation_id = $1 AND state = 'pending'",
			&[&&id[..]],
		).await?;
		if n != 1 {
			return Ok(false);
		}
		give_back(&t, id).await?;
		t.commit().await?;
		Ok(true)
	}

	/// Expires every participation issued in a round found final at or
	/// before median time `cutoff` whose forfeits for that round have not
	/// come: each becomes expired, its new leaves expired (never credited;
	/// their preimage never goes out, and the operator sweeps them), and each
	/// coin it gave up for which no forfeit was ever signed is given back
	/// ([`give_back`]). Returns the participations expired.
	pub async fn expire_participations(&self, cutoff: u32) -> Result<Vec<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let due = conn.query(
			"SELECT p.participation_id FROM participation p JOIN round r ON r.round_id = p.round_id
			 WHERE p.state = 'issued' AND r.state = 'final' AND r.final_mtp <= $1
			   AND NOT EXISTS (SELECT 1 FROM forfeit f WHERE f.participation_id = p.participation_id AND f.round_id = p.round_id)
			 ORDER BY p.participation_id",
			&[&(cutoff as i64)],
		).await?;
		drop(conn);
		let mut expired = vec![];
		for r in due {
			let id = array32(r.get(0), "participation id")?;
			if self.expire_participation(&id, cutoff).await? {
				expired.push(id);
			}
		}
		Ok(expired)
	}

	/// [`Store::expire_participations`] for one participation, whole or not
	/// at all, its row locked first so that a forfeit step in flight either
	/// completes before it, and the participation does not expire, or finds
	/// it expired.
	async fn expire_participation(&self, id: &[u8; 32], cutoff: u32) -> Result<bool, StoreError> {
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
		if t.query_opt("SELECT 1 FROM forfeit WHERE participation_id = $1 AND round_id = $2", &[&&id[..], &round_id]).await?.is_some() {
			return Ok(false);
		}
		t.execute("UPDATE participation SET state = 'expired', updated_at = now() WHERE participation_id = $1", &[&&id[..]]).await?;
		t.execute(
			"UPDATE leaf SET state = 'expired', updated_at = now()
			 WHERE state = 'pending' AND leaf_id IN (
				SELECT leaf_id FROM batch_leaf WHERE participation_id = $1 AND round_id = $2 AND attempt = $3)",
			&[&&id[..], &round_id, &attempt],
		).await?;
		give_back(&t, id).await?;
		t.commit().await?;
		Ok(true)
	}

	/// Whether `key` owns a leaf that is not lost.
	pub async fn key_owns_leaf(&self, key: &[u8; 32]) -> Result<bool, StoreError> {
		let conn = self.conn().await?;
		Ok(conn.query_opt("SELECT 1 FROM leaf WHERE owner_key = $1 AND state <> 'lost'", &[&&key[..]]).await?.is_some())
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

/// Gives back, inside `t`, each coin the participation `id` gave up for which
/// no forfeit was ever signed, in any of its attempts: the coin is live again
/// and its input inactive, so it can be given up again. A coin with a forfeit
/// signed for an earlier round that could not return stays given up: the
/// operator co-signs no other off-chain spend of it.
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
