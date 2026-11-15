//! The store's connection pool against a real PostgreSQL: a statement left
//! running on a connection by a caller that gave up fails no later request;
//! a statement over the limit is cancelled; a pool whose every connection is
//! held answers `busy`, which HTTP answers 503 with a `Retry-After`.
//!
//! A statement is held running by a lock another session keeps on the table
//! it reads, so the test controls exactly how long it runs.

mod common;

use std::time::{Duration, Instant};

use axum::response::IntoResponse;
use common::db::TestDb;
use server::store::{PoolSettings, CHECK_WITHIN};
use server::{Store, StoreError};
use tokio_postgres::NoTls;

async fn session(url: &str) -> tokio_postgres::Client {
	let (client, conn) = tokio_postgres::connect(url, NoTls).await.expect("connect");
	tokio::spawn(async move {
		let _ = conn.await;
	});
	client
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
	let store = Store::connect_with(&db.url, PoolSettings { size: 4, wait, statement_timeout: Duration::from_secs(60) }).await.unwrap();
	warm(&store, 4).await;
	let admin = session(&db.url).await;
	let name = db_name(&db.url);

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
	assert_eq!(after.closed_stuck, before.closed_stuck + 1, "the stuck connection was closed");

	// The abandoned statement was cancelled, not left to run until the lock
	// goes: nothing waits on the lock any more.
	let t = Instant::now();
	while waiting_on_locks(&admin, &name).await > 0 {
		assert!(t.elapsed() < Duration::from_secs(5), "the abandoned statement was cancelled");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	drop(lock);
	warm(&store, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_statement_over_the_limit_is_cancelled() {
	let db = TestDb::new().await;
	let limit = Duration::from_secs(1);
	let store = Store::connect_with(&db.url, PoolSettings { size: 2, wait: Duration::from_secs(5), statement_timeout: limit })
		.await.unwrap();
	let lock = locked(&db.url, "batch").await;
	let t = Instant::now();
	let e = store.pool_flow().await.expect_err("cancelled at the limit");
	let took = t.elapsed();
	println!("cancelled after {:?}: {}", took, e);
	assert!(matches!(&e, StoreError::Db(d) if d.as_db_error().is_some_and(|d| d.code() == &tokio_postgres::error::SqlState::QUERY_CANCELED)),
		"{}", e);
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
