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
//! ([`CHECK_WITHIN`]): a connection that does not answer within it is set
//! aside, out of the pool, until PostgreSQL answers on it, and then closed;
//! the task takes another connection or a new one.
//!
//! Nothing here ever cancels the statement left running. What waits on such
//! a connection may be a COMMIT: an operator that keeps every commit off the
//! machine (a synchronous standby, or WAL archiving through a synchronous
//! receiver) has each COMMIT wait until the standby holds it, and a cancel
//! sent to a backend in that wait ends the wait, not the transaction.
//! PostgreSQL then answers "canceling wait for synchronous replication due
//! to user request; the transaction has already committed locally, but
//! might not have been replicated to the standby", and the server would go
//! on from a commit its backup never got. So the statement is left to end
//! by itself: a COMMIT when the standby has it, anything else at the
//! statement limit ([`PoolSettings::statement_timeout`]), which ends a
//! runaway statement and never a commit's wait for the standby.
//!
//! A connection set aside still counts toward the pool's size: the pool and
//! what is set aside never hold more than [`PoolSettings::size`] connections
//! together, so a standby that stalls while clients give up cannot use up
//! PostgreSQL's connections, which other databases of the cluster share.
//! With every connection set aside, a task waits out its wait and is
//! refused `busy`, until a statement ends.

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
	/// (`statement_timeout`); zero for no limit. Migrations and the start-up
	/// rewrite after a restore run without one. A COMMIT waiting for a
	/// synchronous standby is not a statement running: the limit never ends
	/// that wait.
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
		it is set aside until the statement ends, and closed then")]
	Stuck(Duration),
	#[error("every connection the pool may hold is in use or set aside with a statement still running on it ({0} set aside): \
		none is opened until one ends")]
	Full(u64),
}

/// What the pool has been through since the server started, beside what
/// bb8 counts itself ([`crate::store::Store::pool_status`]).
#[derive(Debug, Default)]
pub(crate) struct Counters {
	/// Connections taken out of the pool because they did not answer their
	/// check in time.
	pub stuck: AtomicU64,
	/// Of those, the ones still waiting for PostgreSQL to answer.
	pub set_aside: AtomicU64,
	/// Coins whose rows were read ahead of a walk ([`crate::store::Store::coins_read_ahead`]).
	pub read_ahead: AtomicU64,
	/// Connections open: the pool's and the ones set aside.
	open: AtomicU64,
}

/// One of the connections the pool may hold ([`PoolSettings::size`]), from
/// before it is opened until it is closed.
struct Slot(Arc<Counters>);

impl Slot {
	fn take(counters: &Arc<Counters>, size: u32) -> Option<Slot> {
		if counters.open.fetch_add(1, Ordering::SeqCst) >= u64::from(size) {
			counters.open.fetch_sub(1, Ordering::SeqCst);
			return None;
		}
		Some(Slot(counters.clone()))
	}
}

impl Drop for Slot {
	fn drop(&mut self) {
		self.0.open.fetch_sub(1, Ordering::SeqCst);
	}
}

/// A connection of the pool. It reads as the client it holds.
pub struct Pooled(Option<(tokio_postgres::Client, Slot)>);

impl std::ops::Deref for Pooled {
	type Target = tokio_postgres::Client;

	fn deref(&self) -> &tokio_postgres::Client {
		// Emptied only by a failed check, after which bb8 drops it unused.
		&self.0.as_ref().expect("a connection handed out holds its client").0
	}
}

impl std::ops::DerefMut for Pooled {
	fn deref_mut(&mut self) -> &mut tokio_postgres::Client {
		&mut self.0.as_mut().expect("a connection handed out holds its client").0
	}
}

/// bb8's manager for PostgreSQL with a time limit on the check
/// ([`CHECK_WITHIN`]) and a bound on the connections open, set aside ones
/// included.
pub(crate) struct Manager {
	inner: PostgresConnectionManager<NoTls>,
	check_within: Duration,
	size: u32,
	counters: Arc<Counters>,
}

impl Manager {
	pub(crate) fn new(config: tokio_postgres::Config, check_within: Duration, size: u32, counters: Arc<Counters>) -> Manager {
		Manager { inner: PostgresConnectionManager::new(config, NoTls), check_within, size, counters }
	}
}

impl bb8::ManageConnection for Manager {
	type Connection = Pooled;
	type Error = ConnError;

	async fn connect(&self) -> Result<Pooled, ConnError> {
		let Some(slot) = Slot::take(&self.counters, self.size) else {
			return Err(ConnError::Full(self.counters.set_aside.load(Ordering::SeqCst)));
		};
		let client = bb8::ManageConnection::connect(&self.inner).await?;
		Ok(Pooled(Some((client, slot))))
	}

	async fn is_valid(&self, conn: &mut Pooled) -> Result<(), ConnError> {
		let Some((client, _)) = conn.0.as_ref() else { return Err(ConnError::Stuck(self.check_within)) };
		match tokio::time::timeout(self.check_within, client.simple_query("")).await {
			Ok(r) => r.map(|_| ()).map_err(ConnError::from),
			Err(_) => {
				// Never cancelled (see the module's note): taken out of the
				// pool, and closed once PostgreSQL answers on it, when the
				// statement left on it has ended, or the connection breaks.
				// Until then it keeps its slot of the pool's size.
				let (client, slot) = conn.0.take().expect("checked above");
				self.counters.stuck.fetch_add(1, Ordering::SeqCst);
				self.counters.set_aside.fetch_add(1, Ordering::SeqCst);
				let counters = self.counters.clone();
				tokio::spawn(async move {
					let since = std::time::Instant::now();
					let _ = client.simple_query("").await;
					counters.set_aside.fetch_sub(1, Ordering::SeqCst);
					log::info!("database: a connection set aside is closed, the statement left on it over after {:?}", since.elapsed());
					drop((client, slot));
				});
				Err(ConnError::Stuck(self.check_within))
			},
		}
	}

	fn has_broken(&self, conn: &mut Pooled) -> bool {
		conn.0.as_ref().is_some_and(|(client, _)| client.is_closed())
	}
}

/// Logs what bb8 reports of connections it could not make or closed. A pool
/// held full by connections set aside is not logged here, once for every
/// task that waits: the tasks' own refusals say it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LogSink;

impl bb8::ErrorSink<ConnError> for LogSink {
	fn sink(&self, error: ConnError) {
		match error {
			ConnError::Full(_) => log::debug!("database: {}", error),
			_ => log::warn!("database: {}", error),
		}
	}

	fn boxed_clone(&self) -> Box<dyn bb8::ErrorSink<ConnError>> {
		Box::new(*self)
	}
}
