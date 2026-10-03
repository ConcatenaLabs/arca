//! A database restored from an older copy: reviews R7's P1 and R7b's P5
//! turned around. The server records every message it asks the signer to
//! sign before it asks, so it refuses to start on a database that has
//! forgotten a transfer or a forfeit the signer signed, naming each entry of
//! the signer's record it does not know; and on a database that does not
//! know what the chain shows of the operator's: a round, or a board spent by
//! its collaborative path. A forfeit recorded and never given the
//! operator's half is completed at start.
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
	static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
	let copy = format!("{}_backup{}", db, N.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
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
async fn a_restored_database_that_forgot_a_transfer_does_not_start() {
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

	// The database is restored from the backup, which knows nothing of B:
	// the server does not start on it, naming the two entries of the
	// signer's record A -> B made (A's checkpoint, its reassignment).
	restore(&mut r, &copy).await;
	let e = Server::start(&r.config).await.err().expect("the server refuses to start on a copy older than the signer's record");
	println!("start on the restored database: {}", e);
	let a_key: String = xonly(&a).serialize().iter().map(|b| format!("{:02x}", b)).collect();
	assert!(e.to_string().contains("entry 1, the spend") && e.to_string().contains("entry 2, the spend"), "{}", e);
	assert!(e.to_string().contains(&format!("of the leaf of {}", a_key)), "it names A's leaf: {}", e);

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
	// the restored database holds unspent. Behind the record's check the
	// chain's refuses the start as well: reached here by a database made by
	// hand to know the signer's messages and not the transfer, which the
	// server never writes (it records both in one transaction).
	r.bury().await;
	let (pg, conn) = tokio_postgres::connect(&r.config.database, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(conn);
	for entry in r.signer_entries().await {
		pg.execute("INSERT INTO signer_message (owner, salt, digest, kind) VALUES ($1, $2, $3, 'spend')",
			&[&&entry.owner[..], &&entry.salt[..], &&entry.digest[..]]).await.unwrap();
	}
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

/// A participation of one board, run in a round made final; returns the
/// running server, the board, its owner, the participation and what the
/// owner needs to hand over its forfeit.
async fn round_awaiting_forfeit() -> (Running, common::client::Held, elements::secp256k1_zkp::Keypair, [u8; 32],
	elements::secp256k1_zkp::Keypair, [u8; 32])
{
	use common::rounds::round_final;
	let mut r = start().await;
	let x = r.x;
	let s = xonly(&r.s);
	let a = keypair("A board");
	let (a_held, _) = credited_board(&mut r, &a, x).await;
	let a_new = keypair("A new");
	let (want, nonce) = want_leaf(&a_new, x, VALUE);
	let (body, pid) = participation_body(&[&a_held], &[want], &[], None, s, r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	(r, a_held, a, pid, a_new, nonce)
}

/// The owner hands over its forfeit and gets its preimage.
async fn hand_over(r: &Running, a_held: &common::client::Held, a: &elements::secp256k1_zkp::Keypair, pid: &[u8; 32],
	a_new: &elements::secp256k1_zkp::Keypair, nonce: &[u8; 32])
{
	use common::client::{auths_json, forfeit_sig, hex};
	use common::flow::forfeit_for;
	use common::rounds::{created, status, validate_new_leaf};
	use serde_json::json;
	let st = status(r, pid);
	let (new_valid, record, round) = validate_new_leaf(r, pid, 0, a_new, nonce);
	let board_txid = match &a_held.record {
		CoinRecord::Board(b) => r.server.store.board(&b.leaf_id().0).await.unwrap()
			.map(|row| elements::Txid::from_raw_hash(elements::hashes::Hash::from_byte_array(row.txid))).unwrap(),
		_ => unreachable!(),
	};
	let old = a_held.record.resolve(&[r.rt.client().raw_transaction(&board_txid).unwrap()], &r.policy()).unwrap();
	let f = forfeit_for(&old, &new_valid, &round, &st);
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(pid),
		"forfeits": [{"leaf_id": a_held.id.to_string(), "signature": forfeit_sig(&f, a)}],
		"leaves": [auths_json(&new_valid, a_new, created(&record))]})).ok();
	assert_eq!(done["state"], "released");
	println!("A's forfeit taken, its preimage handed over");
}

/// R7b's P5 turned around: a copy taken mid-round, after the round is final
/// and before the owners hand over their forfeits. Nothing on the chain
/// shows what the copy forgot, but the signer's record does: the server
/// refuses to start on it, naming the forfeit. On the database's latest
/// state it starts.
#[tokio::test(flavor = "multi_thread")]
async fn a_copy_taken_mid_round_does_not_start() {
	let (mut r, a_held, a, pid, a_new, nonce) = round_awaiting_forfeit().await;
	// The operator's copy, the round final, no forfeit handed over yet.
	let copy = backup(&mut r).await;
	hand_over(&r, &a_held, &a, &pid, &a_new, &nonce).await;
	let latest = backup(&mut r).await;

	// Restored from the copy taken before: refused, naming A's forfeit.
	restore(&mut r, &copy).await;
	let started = Server::start(&r.config).await;
	let e = started.err().expect("no start on the mid-round copy");
	println!("start on the copy taken mid-round: {}", e);
	let a_key: String = xonly(&a).serialize().iter().map(|b| format!("{:02x}", b)).collect();
	assert!(e.to_string().contains("entry 1, the forfeit") && e.to_string().contains(&format!("of the leaf of {}", a_key)), "{}", e);

	// Restored to its latest state: it starts, the forfeit there.
	restore(&mut r, &latest).await;
	r.server = Server::start(&r.config).await.unwrap();
	assert_eq!(r.server.store.forfeits_of(&a_held.id.0).await.unwrap().len(), 1, "the latest state holds A's forfeit");
	println!("start on the latest state: started, A's forfeit held");
}

/// A forfeit left without the operator's half (a server stopped between
/// asking the signer and storing its answer, or a database restored to a
/// point between the two) is given it at start; the signer signs again what
/// it signed, so its record does not grow.
#[tokio::test(flavor = "multi_thread")]
async fn a_forfeit_without_the_operators_half_is_completed_at_start() {
	let (mut r, a_held, a, pid, a_new, nonce) = round_awaiting_forfeit().await;
	hand_over(&r, &a_held, &a, &pid, &a_new, &nonce).await;
	r.server.stop();
	let (pg, conn) = tokio_postgres::connect(&r.config.database, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(conn);
	assert_eq!(pg.execute("UPDATE forfeit SET operator_sig = NULL WHERE leaf_id = $1", &[&&a_held.id.0[..]]).await.unwrap(), 1);
	let entries = r.signer_entries().await.len();
	r.server = Server::start(&r.config).await.unwrap();
	let fs = r.server.store.forfeits_of(&a_held.id.0).await.unwrap();
	assert_eq!(fs.len(), 1, "the forfeit is whole again");
	let left: i64 = pg.query_one("SELECT count(*) FROM forfeit WHERE operator_sig IS NULL", &[]).await.unwrap().get(0);
	assert_eq!(left, 0);
	assert_eq!(r.signer_entries().await.len(), entries, "the signer's record did not grow");
	println!("a forfeit without the operator's half: given it at start; the signer's record still {} entries", entries);
}
