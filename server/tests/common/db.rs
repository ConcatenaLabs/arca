//! A database of its own for each test.
//!
//! `ARCA_TEST_POSTGRES` names a PostgreSQL server and a database to connect to
//! for administration (`postgres://user@host:port/postgres`). Each test creates
//! a fresh database there, builds the schema in it from nothing, and drops it
//! when the test ends.

use std::sync::atomic::{AtomicUsize, Ordering};

use server::Store;
use tokio_postgres::NoTls;

pub struct TestDb {
	pub store: Store,
	pub url: String,
	name: String,
	admin: String,
}

fn admin_url() -> String {
	std::env::var("ARCA_TEST_POSTGRES").expect(
		"ARCA_TEST_POSTGRES must name a PostgreSQL server for the store's tests, \
		 as postgres://user@host:port/postgres",
	)
}

/// `url` with its database replaced by `db`.
fn with_database(url: &str, db: &str) -> String {
	let (base, _) = url.rsplit_once('/').expect("a database in the URL");
	format!("{}/{}", base, db)
}

async fn admin(url: &str) -> tokio_postgres::Client {
	let (client, conn) = tokio_postgres::connect(url, NoTls).await.expect("connect to ARCA_TEST_POSTGRES");
	tokio::spawn(async move {
		let _ = conn.await;
	});
	client
}

impl TestDb {
	/// A fresh, migrated database.
	pub async fn new() -> TestDb {
		static N: AtomicUsize = AtomicUsize::new(0);
		let admin_url = admin_url();
		let name = format!("arca_test_{}_{}_{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst),
			rand::random::<u32>());
		admin(&admin_url).await.batch_execute(&format!("CREATE DATABASE {}", name)).await.expect("create the test database");
		let url = with_database(&admin_url, &name);
		let store = Store::connect(&url).await.expect("connect and migrate");
		TestDb { store, url, name, admin: admin_url }
	}
}

impl Drop for TestDb {
	fn drop(&mut self) {
		let (admin_url, name) = (self.admin.clone(), self.name.clone());
		// Drop runs inside the test's runtime, which cannot block on itself.
		let _ = std::thread::spawn(move || {
			let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
			rt.block_on(async {
				admin(&admin_url).await
					.batch_execute(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", name)).await
			})
		}).join();
	}
}
