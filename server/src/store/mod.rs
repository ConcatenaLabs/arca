//! The server's durable state, in PostgreSQL.
//!
//! The schema is `schema/V1__arca.sql` and the migrations after it
//! (`schema/V2__watcher.sql`, `schema/V3__operator_scripts.sql`,
//! `schema/V4__participation_waiting.sql`, `schema/V5__leaf_salt.sql`,
//! `schema/V6__signer_head.sql`, `schema/V7__signer_messages.sql`,
//! `schema/V8__stateless_challenges.sql`, `schema/V9__wanted_keys_freed.sql`,
//! `schema/V10__round_signer_head.sql`, `schema/V11__signed_record_heads.sql`,
//! `schema/V12__challenge_key.sql`, `schema/V13__reruns_are_ordinary.sql`,
//! `schema/V14__keeper_acks.sql`),
//! built from
//! nothing by [`Store::connect`] and
//! applied in order, each once, under a lock. Every
//! rule that two requests could otherwise race past is held by the database
//! itself: a leaf script appears once ([`StoreError::ScriptReused`]), a leaf
//! salt is taken once, by one leaf or one leaf a participation wants
//! ([`StoreError::SaltReused`]), an
//! operator nonce is taken once ([`StoreError::NonceUsed`]), a key owns one leaf
//! ([`StoreError::KeyReused`]; a leaf of a participation that expired, never
//! credited, owns none, and a key a void or expired participation wanted is
//! free again), a leaf is given up once, by one transfer or by
//! one participation at a time (a participation that never runs, or whose
//! forfeits never come, gives back the coins no forfeit was signed for), and
//! no forfeit naming a round that can never return enters the watcher's log
//! ([`StoreError::RoundLost`]). Each
//! operation that changes more than one row runs in one transaction, so it
//! happens whole or not at all.
//!
//! Leaves are keyed by their leaf id, never by an outpoint.

use std::time::Duration;

use bb8::{Pool, PooledConnection};
use bb8_postgres::PostgresConnectionManager;
use tokio_postgres::error::SqlState;
use tokio_postgres::NoTls;

mod boards;
mod chain;
mod coins;
mod mailbox;
mod nursery;
mod participations;
mod rounds;
mod transfers;
mod wallet;
mod watcher;

pub use boards::{BoardRow, BoardState};
pub use chain::{BlockRow, Scan, ScannedOutput};
pub use coins::{LeafKind, LeafRow, LeafState, NewCoin, NewScript, ScriptKind};
pub use mailbox::MailboxMessage;
pub use nursery::{NurseryRow, NurseryState};
pub use participations::{
	ForfeitRow, NewForfeit, NewParticipation, ParticipationInput, ParticipationOutput, ParticipationRow, ParticipationState, ReleaseRow,
	WantedKind,
};
pub use rounds::{
	BatchLeafRow, BatchRow, NewBatch, NewBatchLeaf, NewOffboard, NewRound, OffboardRow, Placement, RoundRow, RoundState, StoredReserve,
};
pub use transfers::{NewReassignment, NewTransferInput, NewTransferOutput, RecordHeadRow, StoredInput, TransferRow};
pub use wallet::{WalletCoin, WalletRefusal};
pub use watcher::{NewTreeScript, NewWatcherTx, TreeOutput, TreeScriptKind, WatcherTxRow};

/// The migrations, in order: `(version, SQL)`. The schema is squashed into the
/// first; a change to a schema a server has run is a new entry, never an edit
/// of an old one.
const MIGRATIONS: &[(i32, &str)] = &[
	(1, include_str!("../../schema/V1__arca.sql")),
	(2, include_str!("../../schema/V2__watcher.sql")),
	(3, include_str!("../../schema/V3__operator_scripts.sql")),
	(4, include_str!("../../schema/V4__participation_waiting.sql")),
	(5, include_str!("../../schema/V5__leaf_salt.sql")),
	(6, include_str!("../../schema/V6__signer_head.sql")),
	(7, include_str!("../../schema/V7__signer_messages.sql")),
	(8, include_str!("../../schema/V8__stateless_challenges.sql")),
	(9, include_str!("../../schema/V9__wanted_keys_freed.sql")),
	(10, include_str!("../../schema/V10__round_signer_head.sql")),
	(11, include_str!("../../schema/V11__signed_record_heads.sql")),
	(12, include_str!("../../schema/V12__challenge_key.sql")),
	(13, include_str!("../../schema/V13__reruns_are_ordinary.sql")),
	(14, include_str!("../../schema/V14__keeper_acks.sql")),
];

/// A rebindable message the server asks the signer to sign, recorded before
/// it asks: the leaf it is for (its owner key and salt), its digest, and
/// whether it is a forfeit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerMessage {
	pub owner: [u8; 32],
	pub salt: [u8; 32],
	pub digest: [u8; 32],
	pub forfeit: bool,
}

/// Records `messages` inside `t`; one recorded before is left as it is.
pub(crate) async fn insert_messages(t: &tokio_postgres::Transaction<'_>, messages: &[SignerMessage]) -> Result<(), StoreError> {
	for m in messages {
		t.execute(
			"INSERT INTO signer_message (owner, salt, digest, kind) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
			&[&&m.owner[..], &&m.salt[..], &&m.digest[..], &if m.forfeit { "forfeit" } else { "spend" }],
		).await?;
	}
	Ok(())
}

/// An arbitrary key for the advisory lock that serialises migrations.
const MIGRATION_LOCK: i64 = 0x4172_6361_5363_6865;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
	#[error("cannot get a database connection: {0}")]
	Pool(String),
	#[error("database error: {0}")]
	Db(#[from] tokio_postgres::Error),
	#[error("the database holds a value this server cannot read: {0}")]
	Corrupt(String),
	#[error("an output script is already known to the server: a leaf script is never funded twice")]
	ScriptReused,
	#[error("the key already owns a leaf: every leaf has a key of its own")]
	KeyReused,
	/// A leaf's salt the server has seen before, on a leaf or promised to
	/// one: the salt, hex.
	#[error("salt {0} is already known to the server: every leaf has a salt of its own")]
	SaltReused(String),
	#[error("the operator nonce was not issued by this server")]
	NonceUnknown,
	#[error("the operator nonce has already been used")]
	NonceUsed,
	#[error("leaf {0} is already known")]
	LeafExists(String),
	#[error("leaf {0} is not known")]
	LeafUnknown(String),
	#[error("leaf {0} is already spent")]
	LeafSpent(String),
	#[error("leaf {0} is {1}, not live")]
	LeafNotLive(String, &'static str),
	/// The merge rule refused a reassignment.
	#[error("{0}")]
	Mergeable(String),
	#[error("a participation with this id is already recorded")]
	ParticipationExists,
	/// The participation is no longer in its round's forfeit step.
	#[error("the participation is {0}")]
	NotInRound(&'static str),
	/// A forfeit names a round that can never return: the server never
	/// publishes it.
	#[error("round {0} can never return: no forfeit naming it is published")]
	RoundLost(i64),
}

impl StoreError {
	fn from_pool(e: bb8::RunError<tokio_postgres::Error>) -> StoreError {
		StoreError::Pool(e.to_string())
	}

	/// Whether `e` is a violation of the unique constraint `constraint`.
	fn is_unique(e: &tokio_postgres::Error, constraint: &str) -> bool {
		e.as_db_error().is_some_and(|d| {
			*d.code() == SqlState::UNIQUE_VIOLATION && d.constraint() == Some(constraint)
		})
	}
}

type Conn<'a> = PooledConnection<'a, PostgresConnectionManager<NoTls>>;

/// The server's database.
#[derive(Clone)]
pub struct Store {
	pool: Pool<PostgresConnectionManager<NoTls>>,
}

impl Store {
	/// Connects to the database at `url` (a PostgreSQL connection string,
	/// `postgres://user@host:port/db` or the key-value form) and brings its
	/// schema up to date.
	pub async fn connect(url: &str) -> Result<Store, StoreError> {
		let config: tokio_postgres::Config = url.parse()?;
		let manager = PostgresConnectionManager::new(config, NoTls);
		let pool = Pool::builder()
			.max_size(16)
			.connection_timeout(Duration::from_secs(10))
			.build(manager)
			.await?;
		let store = Store { pool };
		store.migrate().await?;
		Ok(store)
	}

	async fn conn(&self) -> Result<Conn<'_>, StoreError> {
		self.pool.get().await.map_err(StoreError::from_pool)
	}

	/// Applies every migration the database has not seen, in order, each in
	/// its own transaction, under an advisory lock so two servers starting at
	/// once do not both apply one.
	pub async fn migrate(&self) -> Result<(), StoreError> {
		let mut conn = self.conn().await?;
		let tx = conn.transaction().await?;
		tx.execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK]).await?;
		tx.batch_execute(
			"CREATE TABLE IF NOT EXISTS arca_schema (
				version    INTEGER PRIMARY KEY,
				applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
			)",
		).await?;
		let row = tx.query_one("SELECT coalesce(max(version), 0) FROM arca_schema", &[]).await?;
		let current: i32 = row.get(0);
		for (version, sql) in MIGRATIONS {
			if *version > current {
				tx.batch_execute(sql).await?;
				tx.execute("INSERT INTO arca_schema (version) VALUES ($1)", &[version]).await?;
				log::info!("database schema migrated to version {}", version);
			}
		}
		tx.commit().await?;
		Ok(())
	}

	/// The key of every challenge's keyed check: drawn by the first server
	/// to ask, kept, and the same for every server on the database after.
	pub async fn challenge_key(&self) -> Result<[u8; 32], StoreError> {
		let mut fresh = [0u8; 32];
		rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut fresh);
		let conn = self.conn().await?;
		conn.execute("INSERT INTO challenge_key (one, key) VALUES (true, $1) ON CONFLICT (one) DO NOTHING", &[&&fresh[..]]).await?;
		let row = conn.query_one("SELECT key FROM challenge_key", &[]).await?;
		array32(row.get(0), "challenge key")
	}

	/// The latest entry of the signer's record the server was given: its
	/// number and running hash; `None` before the first.
	pub async fn signer_head(&self) -> Result<Option<(u64, [u8; 32])>, StoreError> {
		let conn = self.conn().await?;
		let row = conn.query_opt("SELECT entry, hash FROM signer_head", &[]).await?;
		row.map(|r| {
			let n: i64 = r.get(0);
			Ok((u64::try_from(n).map_err(|_| StoreError::Corrupt(format!("entry {}", n)))?, array32(r.get(1), "hash")?))
		}).transpose()
	}

	/// Remembers entry `entry` of the signer's record, with its running
	/// hash, when it is later than the one remembered.
	pub async fn set_signer_head(&self, entry: u64, hash: &[u8; 32]) -> Result<(), StoreError> {
		self.set_signer_head_signed(entry, hash, None).await
	}

	/// Remembers entry `entry` of the signer's record, with its running hash
	/// and the signer's signature over them, when it is later than the one
	/// remembered, or the same without a signature.
	pub async fn set_signer_head_signed(&self, entry: u64, hash: &[u8; 32], signature: Option<&elements::secp256k1_zkp::schnorr::Signature>)
		-> Result<(), StoreError>
	{
		let conn = self.conn().await?;
		let n = i64::try_from(entry).map_err(|_| StoreError::Corrupt(format!("entry {}", entry)))?;
		let sig: Option<Vec<u8>> = signature.map(|s| s.as_ref().to_vec());
		conn.execute(
			"INSERT INTO signer_head (one, entry, hash, signature) VALUES (true, $1, $2, $3)
			 ON CONFLICT (one) DO UPDATE SET entry = EXCLUDED.entry, hash = EXCLUDED.hash, signature = EXCLUDED.signature,
			   updated_at = now()
			 WHERE signer_head.entry < EXCLUDED.entry
			   OR (signer_head.entry = EXCLUDED.entry AND signer_head.hash = EXCLUDED.hash AND signer_head.signature IS NULL)",
			&[&n, &&hash[..], &sig],
		).await?;
		Ok(())
	}

	/// The latest entry of the signer's record the server was given, with
	/// the signer's signature over it when the signer gave one.
	pub async fn signer_head_signed(&self) -> Result<Option<(u64, [u8; 32], Option<[u8; 64]>)>, StoreError> {
		let conn = self.conn().await?;
		let row = conn.query_opt("SELECT entry, hash, signature FROM signer_head", &[]).await?;
		row.map(|r| {
			let n: i64 = r.get(0);
			let sig: Option<Vec<u8>> = r.get(2);
			Ok((u64::try_from(n).map_err(|_| StoreError::Corrupt(format!("entry {}", n)))?, array32(r.get(1), "hash")?,
				sig.map(|s| s.try_into().map_err(|_| StoreError::Corrupt("a signature of another length".into()))).transpose()?))
		}).transpose()
	}

	/// Keeps the keepers' acknowledgements `acks` of head `entry`, `hash` of
	/// the signer's record; one kept before is left as it is.
	pub async fn put_head_acks(&self, entry: u64, hash: &[u8; 32], acks: &[crate::keeper::WireAck]) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		let n = i64::try_from(entry).map_err(|_| StoreError::Corrupt(format!("entry {}", entry)))?;
		for a in acks {
			let bytes = |s: &str| crate::signer::unhex(s).map_err(StoreError::Corrupt);
			conn.execute(
				"INSERT INTO record_head_ack (entry, hash, keeper, nonce, signature) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
				&[&n, &&hash[..], &bytes(&a.key)?, &bytes(&a.nonce)?, &bytes(&a.signature)?],
			).await?;
		}
		Ok(())
	}

	/// The keepers' acknowledgements kept of head `entry`, `hash` of the
	/// signer's record.
	pub async fn head_acks(&self, entry: u64, hash: &[u8; 32]) -> Result<Vec<crate::keeper::WireAck>, StoreError> {
		let conn = self.conn().await?;
		let n = i64::try_from(entry).map_err(|_| StoreError::Corrupt(format!("entry {}", entry)))?;
		let rows = conn.query("SELECT keeper, nonce, signature FROM record_head_ack WHERE entry = $1 AND hash = $2 ORDER BY keeper",
			&[&n, &&hash[..]]).await?;
		Ok(rows.iter().map(|r| {
			let (k, nonce, s): (Vec<u8>, Vec<u8>, Vec<u8>) = (r.get(0), r.get(1), r.get(2));
			crate::keeper::WireAck { key: crate::signer::hex(&k), nonce: crate::signer::hex(&nonce), signature: crate::signer::hex(&s) }
		}).collect())
	}

	/// Which of `messages` (the leaf's owner key, its salt, the digest) the
	/// server never recorded asking the signer for: their indices.
	pub async fn unknown_messages(&self, messages: &[([u8; 32], [u8; 32], [u8; 32])]) -> Result<Vec<usize>, StoreError> {
		let conn = self.conn().await?;
		let stmt = conn.prepare("SELECT 1 FROM signer_message WHERE owner = $1 AND salt = $2 AND digest = $3").await?;
		let mut unknown = vec![];
		for (i, (o, s, d)) in messages.iter().enumerate() {
			if conn.query_opt(&stmt, &[&&o[..], &&s[..], &&d[..]]).await?.is_none() {
				unknown.push(i);
			}
		}
		Ok(unknown)
	}

	/// The schema version the database is at.
	pub async fn schema_version(&self) -> Result<i32, StoreError> {
		let conn = self.conn().await?;
		Ok(conn.query_one("SELECT coalesce(max(version), 0) FROM arca_schema", &[]).await?.get(0))
	}
}

/// Reads a fixed-length byte column.
fn array32(v: Vec<u8>, what: &str) -> Result<[u8; 32], StoreError> {
	v.try_into().map_err(|v: Vec<u8>| StoreError::Corrupt(format!("{} of {} bytes", what, v.len())))
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}
