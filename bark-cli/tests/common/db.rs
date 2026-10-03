//! A PostgreSQL database of its own for each test, dropped at the end.

use std::sync::atomic::{AtomicUsize, Ordering};

use tokio_postgres::NoTls;

pub struct TestDb {
	pub url: String,
	name: String,
	admin: String,
}

fn admin_url() -> String {
	std::env::var("ARCA_TEST_POSTGRES").expect(
		"ARCA_TEST_POSTGRES must name a PostgreSQL server for the server's database, as postgres://user@host:port/postgres",
	)
}

async fn admin(url: &str) -> tokio_postgres::Client {
	let (client, conn) = tokio_postgres::connect(url, NoTls).await.expect("connect to ARCA_TEST_POSTGRES");
	tokio::spawn(async move {
		let _ = conn.await;
	});
	client
}

impl TestDb {
	pub async fn new() -> TestDb {
		static N: AtomicUsize = AtomicUsize::new(0);
		let admin_url = admin_url();
		let name = format!("arca_cli_test_{}_{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst));
		admin(&admin_url).await.batch_execute(&format!("CREATE DATABASE {}", name)).await.expect("create the test database");
		let (base, _) = admin_url.rsplit_once('/').expect("a database in the URL");
		TestDb { url: format!("{}/{}", base, name), name, admin: admin_url }
	}
}

impl Drop for TestDb {
	fn drop(&mut self) {
		let (admin_url, name) = (self.admin.clone(), self.name.clone());
		let _ = std::thread::spawn(move || {
			let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
			rt.block_on(async { admin(&admin_url).await.batch_execute(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", name)).await })
		}).join();
	}
}
