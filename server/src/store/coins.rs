//! Operator nonces, Arca scripts and the coins keyed by leaf id.

use rand::RngCore;

use super::{array32, Store, StoreError};

/// What kind of coin a leaf is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafKind {
	Board,
	Batch,
	Transfer,
}

impl LeafKind {
	fn as_str(self) -> &'static str {
		match self {
			LeafKind::Board => "board",
			LeafKind::Batch => "batch",
			LeafKind::Transfer => "transfer",
		}
	}

	fn parse(s: &str) -> Result<LeafKind, StoreError> {
		Ok(match s {
			"board" => LeafKind::Board,
			"batch" => LeafKind::Batch,
			"transfer" => LeafKind::Transfer,
			other => return Err(StoreError::Corrupt(format!("leaf kind {}", other))),
		})
	}
}

/// Where a leaf stands. See the schema for each state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafState {
	Pending,
	Live,
	Spent,
	Lost,
	/// A new leaf of a participation whose forfeits never came: never the
	/// owner's; the operator sweeps it with its batch.
	Expired,
}

impl LeafState {
	pub(crate) fn as_str(self) -> &'static str {
		match self {
			LeafState::Pending => "pending",
			LeafState::Live => "live",
			LeafState::Spent => "spent",
			LeafState::Lost => "lost",
			LeafState::Expired => "expired",
		}
	}

	pub(crate) fn parse(s: &str) -> Result<LeafState, StoreError> {
		Ok(match s {
			"pending" => LeafState::Pending,
			"live" => LeafState::Live,
			"spent" => LeafState::Spent,
			"lost" => LeafState::Lost,
			"expired" => LeafState::Expired,
			other => return Err(StoreError::Corrupt(format!("leaf state {}", other))),
		})
	}
}

/// What an Arca script the server knows is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptKind {
	/// A leaf: of a batch, a transfer's output, or a board's converted leaf.
	Leaf,
	/// A board output.
	Board,
	/// A checkpoint between a leaf and the reassignment that spends it.
	Checkpoint,
	/// The operator's connector script, which every round pays.
	Connector,
}

impl ScriptKind {
	pub(crate) fn as_str(self) -> &'static str {
		match self {
			ScriptKind::Leaf => "leaf",
			ScriptKind::Board => "board",
			ScriptKind::Checkpoint => "checkpoint",
			ScriptKind::Connector => "connector",
		}
	}
}

/// An Arca script to record for a leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewScript {
	pub script_pubkey: Vec<u8>,
	pub kind: ScriptKind,
}

/// A coin to record: the leaf, the operator nonce its salt took if any, and every
/// Arca script it brings (its own leaf script first).
#[derive(Debug, Clone)]
pub struct NewCoin {
	pub leaf_id: [u8; 32],
	pub kind: LeafKind,
	pub asset: [u8; 32],
	pub value: u64,
	pub owner_key: [u8; 32],
	/// The coin's own output script: the leaf, or the board output.
	pub script_pubkey: Vec<u8>,
	pub hops: u16,
	/// The coin record, binary form.
	pub record: Vec<u8>,
	pub state: LeafState,
	/// The leaf's salt: no other leaf the server knows, or has promised to a
	/// participation, has it.
	pub salt: [u8; 32],
	/// The participation that was promised the salt, for a leaf of a batch:
	/// the leaf takes that promise. `None` for any other leaf, whose salt
	/// must be new to the server.
	pub promised_to: Option<[u8; 32]>,
	/// The operator nonce in the leaf's salt, for a leaf the operator
	/// created (a board); `None` for a leaf a reassignment created, whose
	/// salt takes its sender's creator nonce, and for a leaf whose nonce the
	/// server has already taken (a batch leaf the round runner records after
	/// building the tree).
	pub operator_nonce: Option<[u8; 32]>,
	/// Every Arca script the coin brings, its own included.
	pub scripts: Vec<NewScript>,
}

/// A coin as the database holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafRow {
	pub leaf_id: [u8; 32],
	pub kind: LeafKind,
	pub asset: [u8; 32],
	pub value: u64,
	pub owner_key: [u8; 32],
	pub script_pubkey: Vec<u8>,
	pub hops: u16,
	pub record: Vec<u8>,
	pub state: LeafState,
	pub spent_by: Option<Vec<u8>>,
}

const LEAF_COLUMNS: &str = "leaf_id, kind::text, asset, value, owner_key, script_pubkey, hops, record, state::text, spent_by";

pub(super) fn leaf_row(r: &tokio_postgres::Row) -> Result<LeafRow, StoreError> {
	let value: i64 = r.get(3);
	let hops: i16 = r.get(6);
	Ok(LeafRow {
		leaf_id: array32(r.get(0), "leaf id")?,
		kind: LeafKind::parse(r.get(1))?,
		asset: array32(r.get(2), "asset")?,
		value: u64::try_from(value).map_err(|_| StoreError::Corrupt(format!("value {}", value)))?,
		owner_key: array32(r.get(4), "owner key")?,
		script_pubkey: r.get(5),
		hops: u16::try_from(hops).map_err(|_| StoreError::Corrupt(format!("hops {}", hops)))?,
		record: r.get(7),
		state: LeafState::parse(r.get(8))?,
		spent_by: r.get(9),
	})
}

/// Takes an operator nonce for `leaf_id` inside `tx`: it must have been issued
/// and never taken.
pub(super) async fn take_nonce(tx: &tokio_postgres::Transaction<'_>, nonce: &[u8; 32], leaf_id: &[u8; 32])
	-> Result<(), StoreError>
{
	let row = tx.query_opt("SELECT used_at IS NOT NULL FROM operator_nonce WHERE nonce = $1 FOR UPDATE", &[&&nonce[..]]).await?;
	match row {
		None => return Err(StoreError::NonceUnknown),
		Some(r) if r.get::<_, bool>(0) => return Err(StoreError::NonceUsed),
		Some(_) => {},
	}
	tx.execute("UPDATE operator_nonce SET used_at = now(), used_by = $2 WHERE nonce = $1", &[&&nonce[..], &&leaf_id[..]]).await?;
	Ok(())
}

/// Records inside `tx` that `participation` wants a leaf under `salt`:
/// false, and nothing recorded, when the salt is already known.
pub(super) async fn promise_salt(tx: &tokio_postgres::Transaction<'_>, salt: &[u8; 32], participation: &[u8; 32])
	-> Result<bool, StoreError>
{
	let n = tx.execute("INSERT INTO leaf_salt (salt, participation_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
		&[&&salt[..], &&participation[..]]).await?;
	Ok(n == 1)
}

/// Records inside `tx` that `coin` takes its salt: a salt new to the server,
/// or, for a leaf of a batch, the one promised to its participation.
async fn take_salt(tx: &tokio_postgres::Transaction<'_>, coin: &NewCoin) -> Result<(), StoreError> {
	if let Some(p) = &coin.promised_to {
		let n = tx.execute(
			"UPDATE leaf_salt SET leaf_id = $2 WHERE salt = $1 AND participation_id = $3 AND leaf_id IS NULL",
			&[&&coin.salt[..], &&coin.leaf_id[..], &&p[..]],
		).await?;
		if n == 1 {
			return Ok(());
		}
	}
	let r = tx.execute("INSERT INTO leaf_salt (salt, leaf_id) VALUES ($1, $2)", &[&&coin.salt[..], &&coin.leaf_id[..]]).await;
	match r {
		Ok(_) => Ok(()),
		Err(e) if StoreError::is_unique(&e, "leaf_salt_pkey") => Err(StoreError::SaltReused(super::hex(&coin.salt))),
		Err(e) if StoreError::is_unique(&e, "leaf_salt_leaf_id") => Err(StoreError::LeafExists(super::hex(&coin.leaf_id))),
		Err(e) => Err(e.into()),
	}
}

/// Inserts `coin` inside `tx`: takes its nonce and its salt, records its
/// scripts, writes the leaf. A key wanted by a participation that stands is
/// refused for any coin but the batch leaf that participation's round makes.
pub(super) async fn insert_coin(tx: &tokio_postgres::Transaction<'_>, coin: &NewCoin) -> Result<(), StoreError> {
	if let Some(nonce) = &coin.operator_nonce {
		take_nonce(tx, nonce, &coin.leaf_id).await?;
	}
	// A key a participation wants is promised to the leaf its round makes,
	// while the participation stands.
	if coin.kind != LeafKind::Batch
		&& tx.query_opt("SELECT 1 FROM participation_output WHERE owner_key = $1 AND kind = 'leaf' AND active",
			&[&&coin.owner_key[..]]).await?.is_some()
	{
		return Err(StoreError::KeyReused);
	}
	for s in &coin.scripts {
		let r = tx.execute(
			"INSERT INTO arca_script (script_pubkey, kind, leaf_id) VALUES ($1, $2, $3)",
			&[&s.script_pubkey, &s.kind.as_str(), &&coin.leaf_id[..]],
		).await;
		if let Err(e) = r {
			if StoreError::is_unique(&e, "arca_script_pkey") {
				return Err(StoreError::ScriptReused);
			}
			return Err(e.into());
		}
	}
	let value = i64::try_from(coin.value).map_err(|_| StoreError::Corrupt(format!("value {}", coin.value)))?;
	let r = tx.execute(
		"INSERT INTO leaf (leaf_id, kind, asset, value, owner_key, script_pubkey, hops, record, state, spent_by)
		 VALUES ($1, $2::text::leaf_kind, $3, $4, $5, $6, $7, $8, $9::text::leaf_state, NULL)",
		&[
			&&coin.leaf_id[..], &coin.kind.as_str(), &&coin.asset[..], &value, &&coin.owner_key[..],
			&coin.script_pubkey, &(coin.hops as i16), &coin.record, &coin.state.as_str(),
		],
	).await;
	match r {
		Ok(_) => take_salt(tx, coin).await,
		Err(e) if StoreError::is_unique(&e, "leaf_pkey") => Err(StoreError::LeafExists(super::hex(&coin.leaf_id))),
		Err(e) if StoreError::is_unique(&e, "leaf_owner_key_key") => Err(StoreError::KeyReused),
		Err(e) if StoreError::is_unique(&e, "leaf_script_pubkey_key") => Err(StoreError::ScriptReused),
		Err(e) => Err(e.into()),
	}
}

impl Store {
	/// A fresh operator nonce: 32 random bytes, recorded as issued before it
	/// is returned, so it can be taken by one leaf and never handed out again.
	pub async fn issue_nonce(&self) -> Result<[u8; 32], StoreError> {
		let conn = self.conn().await?;
		loop {
			let mut nonce = [0u8; 32];
			rand::rngs::OsRng.fill_bytes(&mut nonce);
			let n = conn.execute(
				"INSERT INTO operator_nonce (nonce) VALUES ($1) ON CONFLICT DO NOTHING", &[&&nonce[..]],
			).await?;
			if n == 1 {
				return Ok(nonce);
			}
		}
	}

	/// Whether `nonce` can be taken: issued, and not taken. Nothing is
	/// changed; the nonce is taken with the coin that uses it.
	pub async fn check_nonce(&self, nonce: &[u8; 32]) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		match conn.query_opt("SELECT used_at IS NOT NULL FROM operator_nonce WHERE nonce = $1", &[&&nonce[..]]).await? {
			None => Err(StoreError::NonceUnknown),
			Some(r) if r.get::<_, bool>(0) => Err(StoreError::NonceUsed),
			Some(_) => Ok(()),
		}
	}

	/// Deletes every operator nonce handed out more than `nonce_ttl` ago and
	/// never taken. Returns how many went.
	pub async fn delete_expired(&self, nonce_ttl: std::time::Duration) -> Result<u64, StoreError> {
		let conn = self.conn().await?;
		let nonces = conn.execute(
			"DELETE FROM operator_nonce WHERE used_at IS NULL AND issued_at < now() - make_interval(secs => $1)",
			&[&nonce_ttl.as_secs_f64()],
		).await?;
		Ok(nonces)
	}

	/// Every leaf's salt and record, as kept: what the signer's record is
	/// compacted against (`arcad <config> expired-salts`).
	pub async fn leaf_salts(&self) -> Result<Vec<([u8; 32], Vec<u8>)>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query("SELECT s.salt, l.record FROM leaf_salt s JOIN leaf l ON l.leaf_id = s.leaf_id ORDER BY s.salt", &[]).await?;
		rows.iter().map(|r| Ok((array32(r.get(0), "salt")?, r.get(1)))).collect()
	}

	/// Records `coins` together, or none of them: each takes its operator
	/// nonce, each script is new to the server, each key owns no other leaf.
	pub async fn insert_coins(&self, coins: &[NewCoin]) -> Result<(), StoreError> {
		let mut conn = self.conn().await?;
		let tx = conn.transaction().await?;
		for c in coins {
			insert_coin(&tx, c).await?;
		}
		tx.commit().await?;
		Ok(())
	}

	/// The coin with leaf id `leaf_id`.
	pub async fn leaf(&self, leaf_id: &[u8; 32]) -> Result<Option<LeafRow>, StoreError> {
		let conn = self.conn().await?;
		let row = conn.query_opt(&format!("SELECT {} FROM leaf WHERE leaf_id = $1", LEAF_COLUMNS), &[&&leaf_id[..]]).await?;
		row.as_ref().map(leaf_row).transpose()
	}

	/// The coins owned by `key` (one that is not lost at most: a key owns one
	/// leaf), as their owner may see them. A batch leaf's record holds its
	/// participation's preimage, so it is served empty until that preimage
	/// went out: the participation released at the leaf's attempt, then or
	/// at an earlier attempt that a round it was in could never return
	/// retired.
	pub async fn leaves_by_owner(&self, key: &[u8; 32]) -> Result<Vec<LeafRow>, StoreError> {
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
			        l.state::text, l.spent_by
			 FROM leaf l WHERE l.owner_key = $1",
			&[&&key[..]],
		).await?;
		rows.iter().map(leaf_row).collect()
	}

	/// Which of `salts` the server has seen, on a leaf or promised to one.
	pub async fn known_salts(&self, salts: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let list: Vec<Vec<u8>> = salts.iter().map(|s| s.to_vec()).collect();
		let rows = conn.query("SELECT salt FROM leaf_salt WHERE salt = ANY($1)", &[&list]).await?;
		rows.into_iter().map(|r| array32(r.get(0), "salt")).collect()
	}

	/// Whether the server knows `script_pubkey` as an Arca script, and for
	/// which leaf.
	pub async fn arca_script(&self, script_pubkey: &[u8]) -> Result<Option<(ScriptKind, [u8; 32])>, StoreError> {
		let conn = self.conn().await?;
		let row = conn.query_opt("SELECT kind, leaf_id FROM arca_script WHERE script_pubkey = $1", &[&script_pubkey]).await?;
		row.map(|r| {
			let kind = match r.get::<_, &str>(0) {
				"leaf" => ScriptKind::Leaf,
				"board" => ScriptKind::Board,
				"checkpoint" => ScriptKind::Checkpoint,
				"connector" => ScriptKind::Connector,
				other => return Err(StoreError::Corrupt(format!("script kind {}", other))),
			};
			Ok((kind, array32(r.get(1), "leaf id")?))
		}).transpose()
	}
}
