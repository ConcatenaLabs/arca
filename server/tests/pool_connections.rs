//! The store's connection pool against a real PostgreSQL: a statement left
//! running on a connection by a caller that gave up fails no later request
//! and is never cancelled, least of all a COMMIT waiting for its standby; a
//! statement over the limit is cancelled, named and counted; a pool whose
//! every connection is held answers `busy`, which HTTP answers 503 with a
//! `Retry-After`.
//!
//! A statement is held running by a lock another session keeps on the table
//! it reads, so the test controls exactly how long it runs. The test of a
//! COMMIT's wait requires a synchronous standby that is not there
//! ([`AbsentStandby`]), which takes a superuser and changes the cluster's
//! settings while it runs: `ARCA_TEST_POSTGRES` names a throwaway server.

mod common;

use std::time::{Duration, Instant};

use axum::response::IntoResponse;
use common::db::TestDb;
use server::store::{PoolSettings, CHECK_WITHIN};
use server::{Store, StoreError};
use tokio_postgres::NoTls;

/// A session of the test's own, named so the counts below leave it out.
async fn session(url: &str) -> tokio_postgres::Client {
	let (client, conn) = tokio_postgres::connect(url, NoTls).await.expect("connect");
	tokio::spawn(async move {
		let _ = conn.await;
	});
	client.batch_execute("SET application_name = 'arca-test'").await.expect("name the session");
	client
}

/// The store's connections to the test's database open now.
async fn store_backends(admin: &tokio_postgres::Client, db: &str) -> i64 {
	admin.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND application_name <> 'arca-test'", &[&db])
		.await.expect("pg_stat_activity").get(0)
}

/// The backends of the test's database waiting for a synchronous standby.
async fn waiting_on_standby(admin: &tokio_postgres::Client, db: &str) -> i64 {
	admin.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND wait_event = 'SyncRep'", &[&db])
		.await.expect("pg_stat_activity").get(0)
}

/// Polls until `f` holds, at most `within`.
async fn until<F, Fut>(what: &str, within: Duration, mut f: F)
where
	F: FnMut() -> Fut,
	Fut: std::future::Future<Output = bool>,
{
	let t = Instant::now();
	while !f().await {
		assert!(t.elapsed() < within, "{}", what);
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}

/// While it lives, the cluster requires a synchronous standby that is not
/// there: a commit of a session with `synchronous_commit = on` waits for it
/// (as an operator's does while its WAL backup stream stalls), and every
/// other session commits locally. One at a time on a cluster, and only on a
/// cluster that requires no standby of its own.
struct AbsentStandby {
	admin_url: String,
	_lock: tokio_postgres::Client,
}

impl AbsentStandby {
	async fn require(admin_url: &str) -> Option<AbsentStandby> {
		let c = session(admin_url).await;
		let superuser: bool = c.query_one("SELECT rolsuper FROM pg_roles WHERE rolname = current_user", &[]).await.unwrap().get(0);
		assert!(superuser, "the test of a COMMIT waiting for its standby needs a superuser on ARCA_TEST_POSTGRES");
		c.execute("SELECT pg_advisory_lock(4714233902817210705)", &[]).await.expect("one at a time");
		let own: String = c.query_one("SHOW synchronous_standby_names", &[]).await.unwrap().get(0);
		if !own.is_empty() {
			println!("SKIPPED: this cluster requires standbys of its own ({}); the test changes that setting and runs on a throwaway server", own);
			return None;
		}
		for sql in ["ALTER SYSTEM SET synchronous_commit = 'local'", "SELECT pg_reload_conf()",
			"ALTER SYSTEM SET synchronous_standby_names = 'arca_test_absent'", "SELECT pg_reload_conf()"]
		{
			c.batch_execute(sql).await.expect(sql);
		}
		let me = AbsentStandby { admin_url: admin_url.to_string(), _lock: c };
		// In force once a commit asking for the standby waits.
		let t = Instant::now();
		loop {
			let probe = session(admin_url).await;
			probe.batch_execute("SET synchronous_commit = on").await.unwrap();
			// A commit waits for the standby only when its transaction wrote something.
			let write = probe.query_one("SELECT pg_logical_emit_message(true, 'arca-test', 'a commit that asks for the standby')", &[]);
			if tokio::time::timeout(Duration::from_millis(500), write).await.is_err() {
				return Some(me);
			}
			assert!(t.elapsed() < Duration::from_secs(20), "the cluster took up the standby required");
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}

	async fn lift(admin_url: &str) {
		let c = session(admin_url).await;
		for sql in ["ALTER SYSTEM RESET synchronous_standby_names", "ALTER SYSTEM RESET synchronous_commit", "SELECT pg_reload_conf()"] {
			let _ = c.batch_execute(sql).await;
		}
	}
}

impl Drop for AbsentStandby {
	fn drop(&mut self) {
		let admin_url = self.admin_url.clone();
		let _ = std::thread::spawn(move || {
			tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(AbsentStandby::lift(&admin_url))
		}).join();
	}
}

/// A session holding `table` locked against every read, until it is dropped.
async fn locked(url: &str, table: &str) -> tokio_postgres::Client {
	let c = session(url).await;
	c.batch_execute(&format!("BEGIN; LOCK TABLE {} IN ACCESS EXCLUSIVE MODE", table)).await.expect("lock");
	c
}

/// The statements of the test's database waiting on a lock now.
async fn waiting_on_locks(admin: &tokio_postgres::Client, db: &str) -> i64 {
	admin.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'", &[&db])
		.await.expect("pg_stat_activity").get(0)
}

fn db_name(url: &str) -> String {
	url.rsplit_once('/').expect("a database").1.to_string()
}

/// Opens `n` of the pool's connections at once, so the pool holds them idle.
async fn warm(store: &Store, n: usize) {
	let mut set = tokio::task::JoinSet::new();
	for _ in 0..n {
		let s = store.clone();
		set.spawn(async move { s.pool_flow().await.map(|_| ()) });
	}
	while let Some(r) = set.join_next().await {
		r.unwrap().expect("a read");
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_statement_abandoned_on_a_connection_fails_no_later_request() {
	let db = TestDb::new().await;
	let wait = Duration::from_secs(5);
	let admin = session(&db.url).await;
	let name = db_name(&db.url);
	// The connections of the test database's own store, left out below.
	let others = store_backends(&admin, &name).await;
	let store = Store::connect_with(&db.url, PoolSettings { size: 4, wait, statement_timeout: Duration::from_secs(60) }).await.unwrap();
	warm(&store, 4).await;

	// A read of the pool's flow, stuck behind a lock on `batch`, given up by
	// its caller (as an HTTP client that closes its connection drops the
	// handler): its connection goes back to the pool with the statement
	// still running on it.
	let lock = locked(&db.url, "batch").await;
	let s = store.clone();
	let abandoned = tokio::spawn(async move { s.pool_flow().await });
	let t = Instant::now();
	while waiting_on_locks(&admin, &name).await == 0 {
		assert!(t.elapsed() < Duration::from_secs(5), "the read reached the lock");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	abandoned.abort();
	let _ = abandoned.await;
	assert_eq!(waiting_on_locks(&admin, &name).await, 1, "the statement runs on after its caller gave up");

	// Sixteen requests at once, the lock still held: each draws a
	// connection from a pool of four, the stuck one among them, and every
	// one is answered within its wait.
	let before = store.pool_status();
	let mut set = tokio::task::JoinSet::new();
	for i in 0..16u8 {
		let s = store.clone();
		set.spawn(async move {
			let t = Instant::now();
			let r = s.leaf(&[i; 32]).await;
			(r, t.elapsed())
		});
	}
	let mut slowest = Duration::ZERO;
	while let Some(r) = set.join_next().await {
		let (r, took) = r.unwrap();
		assert!(r.expect("every request is answered").is_none());
		slowest = slowest.max(took);
	}
	let after = store.pool_status();
	println!("16 requests, slowest {:?}; pool before {:?}, after {:?}", slowest, before, after);
	assert!(slowest < wait, "each within its wait");
	assert!(slowest < CHECK_WITHIN + Duration::from_secs(2), "the stuck connection costs one check's limit at most");
	assert_eq!(after.timed_out, before.timed_out, "no request waited in vain");
	assert_eq!(after.closed_stuck, before.closed_stuck + 1, "the stuck connection was taken out of the pool");
	assert_eq!(after.set_aside, 1, "and is set aside while its statement runs");

	// The abandoned statement is never cancelled: it still waits on the
	// lock, on a connection that still counts toward the pool's four.
	tokio::time::sleep(Duration::from_millis(500)).await;
	assert_eq!(waiting_on_locks(&admin, &name).await, 1, "the abandoned statement was not cancelled");
	assert!(store_backends(&admin, &name).await - others <= 4, "the pool and what is set aside hold four connections at most");

	// Once it ends, its connection is closed.
	drop(lock);
	until("the connection set aside is closed once its statement ends", Duration::from_secs(5), || async {
		store.pool_status().set_aside == 0
	}).await;
	warm(&store, 4).await;
	assert!(store_backends(&admin, &name).await - others <= 4);
}

/// The fund-safety case of the checkout check: the statement left running
/// on a connection is a COMMIT waiting for the synchronous standby (an
/// operator's WAL backup stream, stalled). A cancel would end the wait and
/// leave the transaction committed without the standby holding it. The
/// server sends none: the connection is set aside, the COMMIT goes on
/// waiting past the statement limit too, and it is done only once the
/// standby's requirement is met.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_commit_waiting_for_its_standby_is_never_forced_through() {
	let db = TestDb::new().await;
	let admin_url = std::env::var("ARCA_TEST_POSTGRES").unwrap();
	let wait = Duration::from_secs(5);
	let limit = Duration::from_secs(2);
	// The store's sessions ask for the standby, as the operator's role does.
	let url = format!("{}?options=-c%20synchronous_commit%3Don", db.url);
	let store = Store::connect_with(&url, PoolSettings { size: 4, wait, statement_timeout: limit }).await.unwrap();
	warm(&store, 4).await;
	let admin = session(&db.url).await;
	let name = db_name(&db.url);
	let nonces = || async { admin.query_one("SELECT count(*) FROM operator_nonce", &[]).await.unwrap().get::<_, i64>(0) };
	assert_eq!(nonces().await, 0);
	let Some(standby) = AbsentStandby::require(&admin_url).await else { return };

	// A request that writes, given up by its caller while its commit waits.
	let s = store.clone();
	let abandoned = tokio::spawn(async move { s.issue_nonce().await });
	until("the commit waits for the standby", Duration::from_secs(10), || async { waiting_on_standby(&admin, &name).await == 1 }).await;
	abandoned.abort();
	let _ = abandoned.await;

	// The next requests: all answered, the stuck connection set aside.
	let mut set = tokio::task::JoinSet::new();
	for i in 0..16u8 {
		let s = store.clone();
		set.spawn(async move { s.leaf(&[i; 32]).await });
	}
	while let Some(r) = set.join_next().await {
		assert!(r.unwrap().expect("every request is answered").is_none());
	}
	let status = store.pool_status();
	println!("pool after the checkout: {:?}", status);
	assert_eq!((status.closed_stuck, status.set_aside, status.timed_out), (1, 1, 0));

	// Past the statement limit as well: the commit still waits, and no
	// other session sees its row. Nothing forced it through.
	tokio::time::sleep(limit + Duration::from_secs(1)).await;
	assert_eq!(waiting_on_standby(&admin, &name).await, 1, "the commit still waits for the standby");
	assert_eq!(nonces().await, 0, "the transaction was not forced through");

	// The standby's requirement met (here: lifted), PostgreSQL ends the wait
	// itself, the row is there, and the connection set aside is closed.
	drop(standby);
	until("the commit is done once the standby allows it", Duration::from_secs(10), || async { nonces().await == 1 }).await;
	until("the connection set aside is closed", Duration::from_secs(5), || async { store.pool_status().set_aside == 0 }).await;
	store.issue_nonce().await.expect("and the store writes again");
}

/// Connections set aside keep their places of the pool's size: with every
/// one of them set aside nothing more is opened, and a request is refused
/// `busy` until a statement ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_set_aside_count_toward_the_pool() {
	let db = TestDb::new().await;
	let admin = session(&db.url).await;
	let name = db_name(&db.url);
	let others = store_backends(&admin, &name).await;
	let store = Store::connect_with(&db.url, PoolSettings { size: 2, wait: Duration::from_secs(3), statement_timeout: Duration::from_secs(60) })
		.await.unwrap();
	warm(&store, 2).await;
	let lock = locked(&db.url, "batch").await;
	let abandoned: Vec<_> = (0..2).map(|_| {
		let s = store.clone();
		tokio::spawn(async move { s.pool_flow().await })
	}).collect();
	until("both reads reached the lock", Duration::from_secs(5), || async { waiting_on_locks(&admin, &name).await == 2 }).await;
	for a in abandoned {
		a.abort();
		let _ = a.await;
	}
	let e = store.leaf(&[1; 32]).await.expect_err("both connections are set aside, and no third is opened");
	assert!(e.is_busy(), "{}", e);
	let status = store.pool_status();
	println!("pool with both connections set aside: {:?}", status);
	assert_eq!((status.closed_stuck, status.set_aside), (2, 2));
	assert_eq!(store_backends(&admin, &name).await - others, 2, "two connections, as the pool's size allows");
	assert_eq!(waiting_on_locks(&admin, &name).await, 2, "neither statement was cancelled");
	drop(lock);
	until("the connections set aside are closed once their statements end", Duration::from_secs(5), || async {
		store.pool_status().set_aside == 0
	}).await;
	store.leaf(&[1; 32]).await.expect("and the pool opens connections again");
}

/// After a restore the server's start rewrites whole tables
/// ([`Store::cursor_epoch_at_start`]): it runs without the statement limit,
/// as migrations do, or a server could not start on a restored database.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_rewrite_after_a_restore_runs_without_the_statement_limit() {
	let db = TestDb::new().await;
	let limit = Duration::from_secs(1);
	let store = Store::connect_with(&db.url, PoolSettings { size: 2, wait: Duration::from_secs(5), statement_timeout: limit })
		.await.unwrap();
	let admin = session(&db.url).await;
	// A leaf served at a transaction the database's counter is behind: a
	// database restored from a dump. (The row alone, without its leaf.)
	admin.batch_execute("SET session_replication_role = replica").await.unwrap();
	admin.execute("INSERT INTO leaf_served (mailbox_key, served_xid, seq, leaf_id) VALUES ($1, '900000000000'::xid8, 1, $2)",
		&[&&[1u8; 32][..], &&[2u8; 32][..]]).await.expect("a served leaf");
	// The rewrite, held past the limit by a lock on one of its tables.
	let lock = locked(&db.url, "leaf").await;
	let s = store.clone();
	let start = tokio::spawn(async move { s.cursor_epoch_at_start().await });
	tokio::time::sleep(limit + Duration::from_millis(1500)).await;
	assert!(!start.is_finished(), "the rewrite is not cut off at the statement limit");
	drop(lock);
	start.await.unwrap().expect("the rewrite runs to its end");
	let served: String = admin.query_one("SELECT served_xid::text FROM leaf_served", &[]).await.unwrap().get(0);
	assert_eq!(served, "0", "every served transaction set to 0");
	// The limit still holds for the statements after it.
	let lock = locked(&db.url, "batch").await;
	assert!(store.pool_flow().await.is_err());
	drop(lock);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_statement_over_the_limit_is_cancelled() {
	let db = TestDb::new().await;
	let limit = Duration::from_secs(1);
	let store = Store::connect_with(&db.url, PoolSettings { size: 2, wait: Duration::from_secs(5), statement_timeout: limit })
		.await.unwrap();
	let lock = locked(&db.url, "batch").await;
	let t = Instant::now();
	let before = store.pool_status().statements_cancelled;
	let e = store.pool_flow().await.expect_err("cancelled at the limit");
	let took = t.elapsed();
	println!("cancelled after {:?}: {}", took, e);
	assert!(matches!(&e, StoreError::Db(d) if d.cancelled()), "{}", e);
	// Named: where the store ran it, PostgreSQL's code and its words.
	let text = e.to_string();
	assert!(text.contains("store/pool.rs:") && text.contains("57014") && text.contains("statement timeout"), "{}", text);
	// Counted (by the process: other tests' statements count too).
	assert!(store.pool_status().statements_cancelled > before, "the cancelled statement is counted");
	assert!(took >= limit && took < limit + Duration::from_secs(2), "{:?}", took);
	drop(lock);
	store.pool_flow().await.expect("the connection serves the next statement");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pool_with_every_connection_held_answers_busy() {
	let db = TestDb::new().await;
	let wait = Duration::from_secs(1);
	let store = Store::connect_with(&db.url, PoolSettings { size: 1, wait, statement_timeout: Duration::from_secs(60) }).await.unwrap();
	let lock = locked(&db.url, "batch").await;
	// The only connection, held by a read that waits on the lock and whose
	// caller still waits for it.
	let s = store.clone();
	let held = tokio::spawn(async move { s.pool_flow().await });
	tokio::time::sleep(Duration::from_millis(300)).await;
	let t = Instant::now();
	let e = store.leaf(&[1; 32]).await.expect_err("no connection comes free");
	assert!(e.is_busy(), "{}", e);
	assert!(t.elapsed() >= wait, "it waited the whole of the wait");
	assert_eq!(store.pool_status().timed_out, 1);

	// Over HTTP: 503, `busy`, with a Retry-After.
	let response = server::http::Refusal::from(e).into_response();
	assert_eq!(response.status().as_u16(), 503);
	assert_eq!(response.headers().get("retry-after").and_then(|v| v.to_str().ok()),
		Some(server::http::BUSY_RETRY_AFTER.to_string().as_str()));
	let body = axum::body::to_bytes(response.into_body(), 1 << 16).await.unwrap();
	let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
	assert_eq!(v["error"]["code"], "busy");
	println!("answered: {}", v);

	drop(lock);
	held.await.unwrap().expect("the held read ends once the lock goes");
	store.leaf(&[1; 32]).await.expect("and the pool serves again");
}
