//! A database restored from an older copy: review R7's P1 turned around. The
//! signer keeps its own record of every spend it co-signed, so a restored
//! database that has forgotten a transfer cannot have `S` co-sign a second
//! spend of the same coin; and the server refuses to start on a database that
//! does not know what the chain shows of the operator's: a round, or a
//! board spent by its collaborative path.
//!
//! The copy is taken as an operator's backup would be, with the server
//! stopped, by PostgreSQL itself (`CREATE DATABASE … TEMPLATE`), so the test
//! needs no client tools beyond the server named by `ARCA_TEST_POSTGRES`.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::OutPoint;

use arca_covenant::spend::FeeSource;
use arca_covenant::{CoinRecord, ValidOrigin};
use common::client::{new_leaf, participation_body, transfer_body, unhex, want_leaf};
use common::keys::{keypair, xonly};
use common::rounds::{credited_board, start, VALUE};
use common::running::Running;
use server::server::Server;

const MARGIN: u64 = 2_000;

async fn admin() -> tokio_postgres::Client {
	let url = std::env::var("ARCA_TEST_POSTGRES").unwrap();
	let (client, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(conn);
	client
}

fn db_name(r: &Running) -> String {
	r.config.database.rsplit_once('/').unwrap().1.to_string()
}

/// Ends every session on `db`, so it can be copied or dropped.
async fn disconnect(a: &tokio_postgres::Client, db: &str) {
	a.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()", &[&db])
		.await.unwrap();
}

/// The operator's backup, the server stopped: a copy of the database.
async fn backup(r: &mut Running) -> String {
	r.server.stop();
	let a = admin().await;
	let db = db_name(r);
	let copy = format!("{}_backup", db);
	disconnect(&a, &db).await;
	a.batch_execute(&format!("CREATE DATABASE {} TEMPLATE {}", copy, db)).await.unwrap();
	println!("backup: {} copied to {}", db, copy);
	r.server = Server::start(&r.config).await.unwrap();
	r.http = common::client::Http { base: format!("http://{}", r.server.addr) };
	r.synced().await;
	copy
}

/// The database lost and restored from `copy`; the server not started.
async fn restore(r: &mut Running, copy: &str) {
	r.server.stop();
	let a = admin().await;
	let db = db_name(r);
	disconnect(&a, &db).await;
	a.batch_execute(&format!("DROP DATABASE {}", db)).await.unwrap();
	disconnect(&a, copy).await;
	a.batch_execute(&format!("CREATE DATABASE {} TEMPLATE {}", db, copy)).await.unwrap();
	a.batch_execute(&format!("DROP DATABASE {}", copy)).await.unwrap();
	println!("restore: {} dropped and made again from {}", db, copy);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restored_database_cannot_cosign_a_second_spend() {
	let mut r = Running::start().await;
	let s = xonly(&r.s);
	let x = r.x;
	let a = keypair("A");
	let (a_held, board_tx) = credited_board(&mut r, &a, x).await;
	let bases = vec![board_tx.clone()];
	let policy = r.policy();
	let a_valid = a_held.record.resolve(&bases, &policy).unwrap();
	let copy = backup(&mut r).await;

	// A pays B: co-signed. A second spend to C is refused by the database.
	let b = keypair("B");
	let (b_leaf, b_nonce) = new_leaf(&b);
	let kept = VALUE - MARGIN;
	let done_b = r.http.post("cosign_transfer", &transfer_body(&[(&a_held, a_valid.clone(), kept)], &[(x, kept - MARGIN, b_leaf)], s, r.chain)).ok();
	let c = keypair("C");
	let (c_leaf, _) = new_leaf(&c);
	let to_c = transfer_body(&[(&a_held, a_valid.clone(), kept)], &[(x, kept - MARGIN, c_leaf)], s, r.chain);
	let before = r.http.post("cosign_transfer", &to_c);
	println!("A -> C before the restore: {} {}", before.status, before.json);
	assert_eq!((before.status, before.refusal().0.as_str()), (409, "double_spend"));

	// The database is restored from the backup, which knows nothing of B.
	restore(&mut r, &copy).await;
	r.server = Server::start(&r.config).await.unwrap();
	r.http = common::client::Http { base: format!("http://{}", r.server.addr) };
	r.synced().await;
	assert!(r.server.store.spent_by_transfer(&a_held.id.0).await.unwrap().is_none(), "the restored database has forgotten A -> B");

	// A asks again to pay C: the signer refuses, from its own record.
	let after = r.http.post("cosign_transfer", &to_c);
	println!("A -> C after the restore: {} {}", after.status, after.json);
	assert_eq!((after.status, after.refusal().0.as_str()), (409, "double_spend"));
	assert!(after.refusal().1.contains("already_signed"), "refused by the signer's record: {}", after.refusal().1);
	assert!(after.json.get("outputs").is_none(), "C gets no coin record");

	// B's coin stays valid: as B checks it, and on the chain, where its
	// checkpoint and reassignment are taken.
	let rec_b = CoinRecord::from_bytes(&unhex(done_b["outputs"][0]["record"].as_str().unwrap())).unwrap();
	let vb = rec_b.validate(&bases, &policy, &xonly(&b), &b_nonce).unwrap();
	let inputs_b = match &vb.origin { ValidOrigin::Transfer { inputs, .. } => inputs.clone(), _ => unreachable!() };
	let cp = inputs_b[0].board_checkpoint_tx(&FeeSource::Reserve).unwrap();
	let cpt = r.rt.client().send_raw_transaction(&cp.tx).unwrap();
	let re_b = vb.reassignment_tx(&[OutPoint::new(cpt, 0)], &FeeSource::Reserve).unwrap();
	let rbt = r.rt.client().send_raw_transaction(&re_b.tx).unwrap();
	println!("B's coin {} validates ({} atoms); its checkpoint {} and reassignment {} are taken by the node", vb.id, vb.value, cpt, rbt);
	r.produce().await;
	assert!(r.unspent(&OutPoint::new(rbt, 0)), "B's leaf is on the chain");

	// The chain now shows A's board spent by its collaborative path, which
	// the restored database holds unspent: the server refuses to start.
	r.bury().await;
	r.server.stop();
	let e = Server::start(&r.config).await.err().expect("the server refuses to start");
	println!("start after the chain shows the forgotten spend: {}", e);
	assert!(e.to_string().contains(&format!("spends board {} by its collaborative path, which the database has no record", a_held.id)), "{}", e);
	assert!(e.to_string().contains(&cpt.to_string()), "it names the spend: {}", e);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restored_database_that_forgot_a_round_does_not_start() {
	let mut r = start().await;
	let x = r.x;
	let a = keypair("A");
	let (a_held, _) = credited_board(&mut r, &a, x).await;
	let copy = backup(&mut r).await;
	let (w, _) = want_leaf(&keypair("A new"), x, VALUE);
	let (body, _) = participation_body(&[&a_held], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	println!("round {} built and buried after the backup", built.tx.txid());

	restore(&mut r, &copy).await;
	let e = Server::start(&r.config).await.err().expect("the server refuses to start");
	println!("start on the restored database: {}", e);
	assert!(e.to_string().contains(&format!("transaction {} pays the operator's connector script", built.tx.txid())), "{}", e);
}
