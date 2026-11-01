//! What the store keeps of distributions: the claims of each, by the key its
//! payer named, and the operator's payments of what no holder took up.

use super::{array32, LeafState, ParticipationState, Store, StoreError};

/// What a distribution adds to its participation: where the unclaimed sum is
/// paid, and the key named for each of its outputs, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDistribution {
	pub return_script: Vec<u8>,
	pub named: Vec<[u8; 32]>,
}

/// One claim, with its leaf as it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRow {
	pub participation_id: [u8; 32],
	pub idx: u16,
	pub named_key: [u8; 32],
	/// The claim key the leaf is owned by, and its owner nonce.
	pub owner_key: [u8; 32],
	pub owner_nonce: [u8; 32],
	pub asset: [u8; 32],
	pub value: u64,
	pub exit_delay_units: u16,
	/// The leaf the participation's current attempt made of it, once a round
	/// did, with its state and what spent it.
	pub leaf_id: Option<[u8; 32]>,
	pub leaf_state: Option<LeafState>,
	pub spent_by: Option<Vec<u8>>,
	/// Whether the leaf's record holds its owner's unroll authorisations
	/// (`claim_leaf`), so the server can resolve and co-sign it.
	pub authorised: bool,
	pub participation_state: ParticipationState,
	/// The payment that returned it to the payer.
	pub returned_in: Option<[u8; 32]>,
	/// A `claim-1` leaf's lapse: its distribution's deadline, the allowance
	/// and the return script; `None` for a `vtxo-1` claim leaf.
	pub lapse: Option<arca_covenant::Lapse>,
	/// The watcher's lapse that paid the leaf back to the payer.
	pub lapsed_in: Option<[u8; 32]>,
}

/// A payment of unclaimed leaves to a distribution's payer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnRow {
	pub txid: [u8; 32],
	pub participation_id: [u8; 32],
	pub value: u64,
	pub tx: Vec<u8>,
	pub fee_asset: [u8; 32],
	pub fee: u64,
}

/// A distribution, its claims in order and its returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributionRow {
	pub participation_id: [u8; 32],
	pub return_script: Vec<u8>,
	pub claims: Vec<ClaimRow>,
	pub returns: Vec<ReturnRow>,
}

const CLAIM_COLUMNS: &str = "c.participation_id, c.idx, c.named_key, o.owner_key, o.owner_nonce, o.asset, o.value, o.exit_delay_units,
	o.leaf_id, l.state::text, l.spent_by, (l.record IS NOT NULL AND l.record <> ''::bytea), p.state::text, c.returned_in, o.claim, c.lapsed_in, o.vest";

const CLAIM_FROM: &str = "distribution_claim c
	JOIN participation_output o ON o.participation_id = c.participation_id AND o.idx = c.idx
	JOIN participation p ON p.participation_id = c.participation_id
	LEFT JOIN leaf l ON l.leaf_id = o.leaf_id";

fn claim_row(r: &tokio_postgres::Row) -> Result<ClaimRow, StoreError> {
	let state: Option<String> = r.get(9);
	let value: i64 = r.get(6);
	let delay: i32 = r.get(7);
	Ok(ClaimRow {
		participation_id: array32(r.get(0), "participation id")?,
		idx: r.get::<_, i16>(1) as u16,
		named_key: array32(r.get(2), "named key")?,
		owner_key: array32(r.get(3), "owner key")?,
		owner_nonce: array32(r.get(4), "owner nonce")?,
		asset: array32(r.get(5), "asset")?,
		value: u64::try_from(value).map_err(|_| StoreError::Corrupt(format!("a claim's value {}", value)))?,
		exit_delay_units: u16::try_from(delay).map_err(|_| StoreError::Corrupt(format!("a claim's exit delay {}", delay)))?,
		leaf_id: r.get::<_, Option<Vec<u8>>>(8).map(|v| array32(v, "leaf id")).transpose()?,
		leaf_state: state.map(|s| LeafState::parse(&s)).transpose()?,
		spent_by: r.get(10),
		authorised: r.get::<_, Option<bool>>(11).unwrap_or(false),
		participation_state: ParticipationState::parse(&r.get::<_, String>(12))?,
		returned_in: r.get::<_, Option<Vec<u8>>>(13).map(|v| array32(v, "return txid")).transpose()?,
		lapse: r.get::<_, Option<Vec<u8>>>(14).map(|b| super::participations::claim_with_vest(&b, r.get(16))).transpose()?,
		lapsed_in: r.get::<_, Option<Vec<u8>>>(15).map(|v| array32(v, "lapse txid")).transpose()?,
	})
}

fn return_row(r: &tokio_postgres::Row) -> Result<ReturnRow, StoreError> {
	let value: i64 = r.get(2);
	let fee: i64 = r.get(5);
	Ok(ReturnRow {
		txid: array32(r.get(0), "txid")?,
		participation_id: array32(r.get(1), "participation id")?,
		value: u64::try_from(value).map_err(|_| StoreError::Corrupt(format!("a return's value {}", value)))?,
		tx: r.get(3),
		fee_asset: array32(r.get(4), "fee asset")?,
		fee: u64::try_from(fee).map_err(|_| StoreError::Corrupt(format!("a return's fee {}", fee)))?,
	})
}

/// Records `d` for the participation `id` inside the transaction that
/// records the participation.
pub(super) async fn insert_distribution(t: &tokio_postgres::Transaction<'_>, id: &[u8; 32], d: &NewDistribution) -> Result<(), StoreError> {
	t.execute("INSERT INTO distribution (participation_id, return_script) VALUES ($1, $2)", &[&&id[..], &d.return_script]).await?;
	for (k, named) in d.named.iter().enumerate() {
		t.execute("INSERT INTO distribution_claim (participation_id, idx, named_key) VALUES ($1, $2, $3)",
			&[&&id[..], &(k as i16), &&named[..]]).await?;
	}
	Ok(())
}

impl Store {
	/// The distribution of participation `id`, if it is one.
	pub async fn distribution(&self, id: &[u8; 32]) -> Result<Option<DistributionRow>, StoreError> {
		let conn = self.conn().await?;
		let Some(r) = conn.query_opt("SELECT return_script FROM distribution WHERE participation_id = $1", &[&&id[..]]).await? else {
			return Ok(None);
		};
		let return_script: Vec<u8> = r.get(0);
		let claims = conn.query(&format!("SELECT {} FROM {} WHERE c.participation_id = $1 ORDER BY c.idx", CLAIM_COLUMNS, CLAIM_FROM),
			&[&&id[..]]).await?.iter().map(claim_row).collect::<Result<Vec<_>, _>>()?;
		let returns = conn.query(
			"SELECT txid, participation_id, value, tx, fee_asset, fee FROM distribution_return WHERE participation_id = $1 ORDER BY created_at, txid",
			&[&&id[..]]).await?.iter().map(return_row).collect::<Result<Vec<_>, _>>()?;
		Ok(Some(DistributionRow { participation_id: *id, return_script, claims, returns }))
	}

	/// Whether participation `id` is a distribution.
	pub async fn is_distribution(&self, id: &[u8; 32]) -> Result<bool, StoreError> {
		let conn = self.conn().await?;
		Ok(conn.query_opt("SELECT 1 FROM distribution WHERE participation_id = $1", &[&&id[..]]).await?.is_some())
	}

	/// Every claim under one of `keys`, the newest distribution first, at
	/// most `limit`.
	pub async fn claims_named(&self, keys: &[[u8; 32]], limit: i64) -> Result<Vec<ClaimRow>, StoreError> {
		let conn = self.conn().await?;
		let keys: Vec<Vec<u8>> = keys.iter().map(|k| k.to_vec()).collect();
		let rows = conn.query(&format!("SELECT {} FROM {} JOIN distribution d ON d.participation_id = c.participation_id
			WHERE c.named_key = ANY($1) ORDER BY d.created_at DESC, c.participation_id, c.idx LIMIT $2", CLAIM_COLUMNS, CLAIM_FROM),
			&[&keys, &limit]).await?;
		rows.iter().map(claim_row).collect()
	}

	/// The claim whose leaf is `leaf_id`, if that leaf is a claim's.
	pub async fn claim_of_leaf(&self, leaf_id: &[u8; 32]) -> Result<Option<ClaimRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(&format!("SELECT {} FROM {} WHERE o.leaf_id = $1", CLAIM_COLUMNS, CLAIM_FROM), &[&&leaf_id[..]]).await?;
		r.as_ref().map(claim_row).transpose()
	}

	/// The released distributions with a claim not yet returned, oldest
	/// first: the ones a return may still be due for.
	pub async fn distributions_open(&self) -> Result<Vec<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT d.participation_id FROM distribution d JOIN participation p USING (participation_id)
			 WHERE p.state = 'released'
			   AND EXISTS (SELECT 1 FROM distribution_claim c WHERE c.participation_id = d.participation_id AND c.returned_in IS NULL
			     AND c.lapsed_in IS NULL)
			 ORDER BY d.created_at, d.participation_id",
			&[]).await?;
		rows.into_iter().map(|r| array32(r.get(0), "participation id")).collect()
	}

	/// Records the payment `ret` of the claims `idxs` of its distribution,
	/// whole or not at all. `false`, recording nothing, when one of them was
	/// returned already.
	pub async fn record_return(&self, ret: &ReturnRow, idxs: &[u16]) -> Result<bool, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let value = i64::try_from(ret.value).map_err(|_| StoreError::Corrupt("a return's value".into()))?;
		let fee = i64::try_from(ret.fee).map_err(|_| StoreError::Corrupt("a return's fee".into()))?;
		t.execute(
			"INSERT INTO distribution_return (txid, participation_id, value, tx, fee_asset, fee) VALUES ($1, $2, $3, $4, $5, $6)",
			&[&&ret.txid[..], &&ret.participation_id[..], &value, &ret.tx, &&ret.fee_asset[..], &fee]).await?;
		for i in idxs {
			let n = t.execute(
				"UPDATE distribution_claim SET returned_in = $3 WHERE participation_id = $1 AND idx = $2 AND returned_in IS NULL",
				&[&&ret.participation_id[..], &(*i as i16), &&ret.txid[..]]).await?;
			if n != 1 {
				return Ok(false);
			}
		}
		t.commit().await?;
		Ok(true)
	}

	/// Records that the watcher's lapse `txid` pays claim `idx` of the
	/// distribution `id` back to its payer.
	pub async fn record_lapse(&self, id: &[u8; 32], idx: u16, txid: &[u8; 32]) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute("UPDATE distribution_claim SET lapsed_in = $3 WHERE participation_id = $1 AND idx = $2",
			&[&&id[..], &(idx as i16), &&txid[..]]).await?;
		Ok(())
	}

	/// Every return recorded, oldest first: each must be in the nursery.
	pub async fn returns(&self) -> Result<Vec<ReturnRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query("SELECT txid, participation_id, value, tx, fee_asset, fee FROM distribution_return ORDER BY created_at, txid", &[])
			.await?;
		rows.iter().map(return_row).collect()
	}

	/// Stores the full record of a claim leaf of the round `round_id`, its
	/// owner's unroll authorisations with it, when the leaf has none yet, and
	/// credits it as every leaf of a released participation is credited once
	/// its record is whole and its round final. Whether it was stored now.
	pub async fn set_claim_record(&self, leaf_id: &[u8; 32], round_id: i64, record: &[u8]) -> Result<bool, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let n = t.execute("UPDATE leaf SET record = $2, updated_at = now() WHERE leaf_id = $1 AND kind = 'batch' AND record = ''::bytea",
			&[&&leaf_id[..], &record]).await?;
		super::participations::credit(&t, round_id).await?;
		t.commit().await?;
		Ok(n == 1)
	}
}
