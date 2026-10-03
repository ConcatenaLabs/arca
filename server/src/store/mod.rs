//! The server's durable state, in PostgreSQL.
//!
//! One schema, `schema/V1__arca.sql`, built from nothing by [`Store::connect`]
//! (the migrations it holds are applied in order, once, under a lock). Every
//! rule that two requests could otherwise race past is held by the database
//! itself: a leaf script appears once ([`StoreError::ScriptReused`]), an
//! operator nonce is taken once ([`StoreError::NonceUsed`]), a key owns one leaf
//! ([`StoreError::KeyReused`]), a leaf is the input of one transfer. Each
//! operation that changes more than one row runs in one transaction, so it
//! happens whole or not at all.
//!
//! Leaves are keyed by their leaf id, never by an outpoint.

use std::time::Duration;

use bb8::{Pool, PooledConnection};
use bb8_postgres::PostgresConnectionManager;
use tokio_postgres::error::SqlState;
use tokio_postgres::NoTls;

mod auth;
mod boards;
mod chain;
mod coins;
mod mailbox;
mod nursery;
mod wallet;

pub use auth::ChallengeError;
pub use boards::{BoardRow, BoardState};
pub use chain::{BlockRow, Scan, ScannedOutput};
pub use coins::{LeafKind, LeafRow, LeafState, NewCoin, NewScript, ScriptKind};
pub use mailbox::MailboxMessage;
pub use nursery::{NurseryRow, NurseryState};
pub use wallet::{WalletCoin, WalletRefusal};

/// The migrations, in order: `(version, SQL)`. The schema is squashed into the
/// first; a change to a schema a server has run is a new entry, never an edit
/// of an old one.
const MIGRATIONS: &[(i32, &str)] = &[(1, include_str!("../../schema/V1__arca.sql"))];

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
	#[error("the operator nonce was not issued by this server")]
	NonceUnknown,
	#[error("the operator nonce has already been used")]
	NonceUsed,
	#[error("leaf {0} is already known")]
	LeafExists(String),
	#[error("leaf {0} is not known")]
	LeafUnknown(String),
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
