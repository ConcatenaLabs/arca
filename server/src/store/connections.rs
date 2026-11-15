//! The server's connection pool: how large it is, how long a task waits for
//! a connection, and the check every connection passes before it is handed
//! out.
//!
//! A connection can come back to the pool with a statement still running on
//! it: when the task that ran it is dropped mid-statement (an HTTP client
//! that gives up and closes its connection drops the handler), PostgreSQL
//! goes on running the statement, and anything the next holder sends waits
//! behind it. bb8's own check would wait there too, for the whole of a
//! task's wait, and then hand the connection back, still busy, to the next
//! task, so one abandoned statement of a minute fails every task that draws
//! that connection for a minute. Here the check has a short limit of its own
//! ([`CHECK_WITHIN`]): a connection that does not answer within it has the
//! statement on it cancelled and is closed, and the task takes another
//! connection or a new one.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bb8_postgres::PostgresConnectionManager;
use tokio_postgres::NoTls;

/// How the pool is sized and how long a task waits ([`crate::store::Store::connect_with`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSettings {
	/// The most connections the pool keeps open.
	pub size: u32,
	/// How long a task waits for a connection before it is refused one
	/// ([`crate::store::StoreError::Busy`]).
	pub wait: Duration,
	/// The longest a statement may run before PostgreSQL cancels it
	/// (`statement_timeout`); zero for no limit. Migrations run without one.
	pub statement_timeout: Duration,
}

impl PoolSettings {
	/// Thirty-two connections, a wait of ten seconds and statements of at
	/// most thirty seconds. Thirty-two covers the server's own tasks (each
	/// holds one connection at a time) beside a burst of wallets' requests,
	/// and stays well within PostgreSQL's default of a hundred connections
	/// with a second server on the same database host. The slowest
	/// statements the server runs on a store of some 50,000 batch leaves
	/// take a few seconds (the in-flight reads a round makes); thirty
	/// seconds leaves them room tenfold, and ends a statement gone wrong
	/// before it holds a connection for minutes.
	pub const DEFAULT: PoolSettings = PoolSettings {
		size: 32,
		wait: Duration::from_secs(10),
		statement_timeout: Duration::from_secs(30),
	};
}

impl Default for PoolSettings {
	fn default() -> PoolSettings {
		PoolSettings::DEFAULT
	}
}

/// How long a connection has to answer the check before it is handed out:
/// an empty statement, which a connection with nothing running answers in a
/// round trip.
pub const CHECK_WITHIN: Duration = Duration::from_secs(1);

/// Why a connection could not be made or failed its check.
#[derive(Debug, thiserror::Error)]
pub enum ConnError {
	#[error(transparent)]
	Db(#[from] tokio_postgres::Error),
	#[error("a connection did not answer its check within {0:?}, a statement abandoned on it still running: \
		the statement was cancelled and the connection closed")]
	Stuck(Duration),
}

/// What the pool has been through since the server started, beside what
/// bb8 counts itself ([`crate::store::Store::pool_status`]).
#[derive(Debug, Default)]
pub(crate) struct Counters {
	/// Connections closed because they did not answer their check in time.
	pub stuck: AtomicU64,
}

/// bb8's manager for PostgreSQL with a time limit on the check
/// ([`CHECK_WITHIN`]).
pub(crate) struct Manager {
	inner: PostgresConnectionManager<NoTls>,
	check_within: Duration,
	counters: Arc<Counters>,
}

impl Manager {
	pub(crate) fn new(config: tokio_postgres::Config, check_within: Duration, counters: Arc<Counters>) -> Manager {
		Manager { inner: PostgresConnectionManager::new(config, NoTls), check_within, counters }
	}
}

impl bb8::ManageConnection for Manager {
	type Connection = tokio_postgres::Client;
	type Error = ConnError;

	async fn connect(&self) -> Result<tokio_postgres::Client, ConnError> {
		Ok(bb8::ManageConnection::connect(&self.inner).await?)
	}

	async fn is_valid(&self, conn: &mut tokio_postgres::Client) -> Result<(), ConnError> {
		match tokio::time::timeout(self.check_within, conn.simple_query("")).await {
			Ok(r) => r.map(|_| ()).map_err(ConnError::from),
			Err(_) => {
				// Whatever runs on it is a statement nobody waits for: ask
				// PostgreSQL to cancel it, on a connection of its own, and
				// let bb8 close this one.
				let token = conn.cancel_token();
				tokio::spawn(async move {
					if let Err(e) = token.cancel_query(NoTls).await {
						log::warn!("database: cancelling a statement left running on a connection: {}", e);
					}
				});
				self.counters.stuck.fetch_add(1, Ordering::Relaxed);
				Err(ConnError::Stuck(self.check_within))
			},
		}
	}

	fn has_broken(&self, conn: &mut tokio_postgres::Client) -> bool {
		conn.is_closed()
	}
}

/// Logs what bb8 reports of connections it could not make or closed.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LogSink;

impl bb8::ErrorSink<ConnError> for LogSink {
	fn sink(&self, error: ConnError) {
		log::warn!("database: {}", error);
	}

	fn boxed_clone(&self) -> Box<dyn bb8::ErrorSink<ConnError>> {
		Box::new(*self)
	}
}
