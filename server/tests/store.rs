//! The store against a real PostgreSQL: the schema builds from nothing, and
//! each rule the database holds refuses what breaks it.

mod common;

use common::db::TestDb;
use server::store::{LeafKind, LeafState, NewCoin, NewScript, ScriptKind};
use server::StoreError;

fn coin(n: u8, nonce: [u8; 32]) -> NewCoin {
	let script = vec![0x51, 0x20, n, n, n];
	NewCoin {
		leaf_id: [n; 32],
		kind: LeafKind::Board,
		asset: [0xaa; 32],
		value: 1_000,
		owner_key: [n; 32],
		script_pubkey: script.clone(),
		hops: 0,
		record: vec![n],
		state: LeafState::Pending,
		salt: [n; 32],
		promised_to: None,
		operator_nonce: Some(nonce),
		scripts: vec![NewScript { script_pubkey: script, kind: ScriptKind::Board }],
	}
}

#[tokio::test]
async fn schema_from_nothing() {
	let db = TestDb::new().await;
	assert_eq!(db.store.schema_version().await.unwrap(), 13);
	// Migrating again changes nothing.
	db.store.migrate().await.unwrap();
	let again = server::Store::connect(&db.url).await.unwrap();
	assert_eq!(again.schema_version().await.unwrap(), 13);
}

/// A database of schema 12, with a participation running again
/// forfeit-first, moves to 13 in place: the participation is an ordinary
/// re-run, pending, with no reason to be void.
#[tokio::test]
async fn a_schema_12_database_with_a_forfeit_first_run_moves_in_place() {
	let db = TestDb::new().await;
	let (client, conn) = tokio_postgres::connect(&db.url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(async move {
		let _ = conn.await;
	});
	// Schema 12 as a server before it left it.
	client.batch_execute(
		"ALTER TABLE participation ADD COLUMN forfeit_first BOOLEAN NOT NULL DEFAULT false;
		 ALTER TABLE participation DROP COLUMN void_reason;
		 ALTER TABLE watcher_tx DROP COLUMN round_id;
		 DELETE FROM arca_schema WHERE version = 13;"
	).await.unwrap();
	assert_eq!(db.store.schema_version().await.unwrap(), 12);
	let id = [7u8; 32];
	client.execute(
		"INSERT INTO participation (participation_id, unlock_hash, preimage, attempt, state, forfeit_first, refund_delay_units)
		 VALUES ($1, $2, $3, 1, 'pending', true, 338)",
		&[&&id[..], &&[8u8; 32][..], &&[9u8; 32][..]],
	).await.unwrap();
	db.store.migrate().await.unwrap();
	assert_eq!(db.store.schema_version().await.unwrap(), 13);
	let p = db.store.participation(&id).await.unwrap().unwrap();
	assert_eq!((p.state, p.attempt, p.void_reason.clone()), (server::store::ParticipationState::Pending, 1, None));
	println!("schema 12 -> 13: the forfeit-first run is now {:?} at attempt {}, void_reason {:?}", p.state, p.attempt, p.void_reason);
	let cols: Vec<String> = client.query("SELECT column_name FROM information_schema.columns WHERE table_name = 'participation'", &[])
		.await.unwrap().iter().map(|r| r.get(0)).collect();
	assert!(!cols.contains(&"forfeit_first".to_string()) && cols.contains(&"void_reason".to_string()));
}

#[tokio::test]
async fn nonce_is_taken_once() {
	let db = TestDb::new().await;
	let s = &db.store;
	let n1 = s.issue_nonce().await.unwrap();
	let n2 = s.issue_nonce().await.unwrap();
	assert_ne!(n1, n2);

	s.insert_coins(&[coin(1, n1)]).await.unwrap();
	// The same nonce for another leaf.
	let e = s.insert_coins(&[coin(2, n1)]).await.unwrap_err();
	assert!(matches!(e, StoreError::NonceUsed), "{:?}", e);
	// A nonce the server never issued.
	let e = s.insert_coins(&[coin(3, [7; 32])]).await.unwrap_err();
	assert!(matches!(e, StoreError::NonceUnknown), "{:?}", e);
	// Nothing of a refused coin was written: its scripts are free and n2
	// still is.
	assert!(s.leaf(&[2; 32]).await.unwrap().is_none());
	assert!(s.arca_script(&[0x51, 0x20, 2, 2, 2]).await.unwrap().is_none());
	s.insert_coins(&[coin(2, n2)]).await.unwrap();
}

#[tokio::test]
async fn script_and_key_are_unique() {
	let db = TestDb::new().await;
	let s = &db.store;
	let n1 = s.issue_nonce().await.unwrap();
	s.insert_coins(&[coin(1, n1)]).await.unwrap();

	// Another leaf paying the same script.
	let mut c = coin(2, s.issue_nonce().await.unwrap());
	c.scripts[0].script_pubkey = vec![0x51, 0x20, 1, 1, 1];
	c.script_pubkey = c.scripts[0].script_pubkey.clone();
	let e = s.insert_coins(&[c]).await.unwrap_err();
	assert!(matches!(e, StoreError::ScriptReused), "{:?}", e);

	// Another leaf of the same key.
	let mut c = coin(3, s.issue_nonce().await.unwrap());
	c.owner_key = [1; 32];
	let e = s.insert_coins(&[c]).await.unwrap_err();
	assert!(matches!(e, StoreError::KeyReused), "{:?}", e);

	// The same leaf id twice.
	let mut c = coin(4, s.issue_nonce().await.unwrap());
	c.leaf_id = [1; 32];
	let e = s.insert_coins(&[c]).await.unwrap_err();
	assert!(matches!(e, StoreError::LeafExists(_)), "{:?}", e);

	// Two coins in one call are written together or not at all: the second
	// reuses the first's script, so neither is written.
	let a = coin(5, s.issue_nonce().await.unwrap());
	let mut b = coin(6, s.issue_nonce().await.unwrap());
	b.scripts.push(NewScript { script_pubkey: a.script_pubkey.clone(), kind: ScriptKind::Checkpoint });
	let e = s.insert_coins(&[a, b]).await.unwrap_err();
	assert!(matches!(e, StoreError::ScriptReused), "{:?}", e);
	assert!(s.leaf(&[5; 32]).await.unwrap().is_none());

	let row = s.leaf(&[1; 32]).await.unwrap().unwrap();
	assert_eq!(row.kind, LeafKind::Board);
	assert_eq!(row.state, LeafState::Pending);
	assert_eq!(row.value, 1_000);
	assert_eq!(s.leaves_by_owner(&[1; 32]).await.unwrap(), vec![row]);
	assert_eq!(s.arca_script(&[0x51, 0x20, 1, 1, 1]).await.unwrap(), Some((ScriptKind::Board, [1; 32])));
}

/// A leaf salt is taken once, whatever the leaf (D44): a second leaf under a
/// salt the server knows is refused, and nothing of it is written.
#[tokio::test]
async fn salt_is_unique() {
	let db = TestDb::new().await;
	let s = &db.store;
	s.insert_coins(&[coin(1, s.issue_nonce().await.unwrap())]).await.unwrap();
	assert_eq!(s.known_salts(&[[1; 32], [2; 32]]).await.unwrap(), vec![[1; 32]]);

	// Another leaf, its own key, script and id, under the first one's salt.
	let mut c = coin(2, s.issue_nonce().await.unwrap());
	c.salt = [1; 32];
	let e = s.insert_coins(&[c]).await.unwrap_err();
	assert!(matches!(&e, StoreError::SaltReused(h) if *h == "01".repeat(32)), "{:?}", e);
	assert!(s.leaf(&[2; 32]).await.unwrap().is_none());
	assert!(s.arca_script(&[0x51, 0x20, 2, 2, 2]).await.unwrap().is_none());

	// A leaf of a batch may take only the salt promised to its own
	// participation; a promise of another's is no use to it.
	let mut c = coin(3, s.issue_nonce().await.unwrap());
	c.salt = [1; 32];
	c.promised_to = Some([9; 32]);
	let e = s.insert_coins(&[c]).await.unwrap_err();
	assert!(matches!(e, StoreError::SaltReused(_)), "{:?}", e);

	// Two coins in one call under one salt: neither is written.
	let a = coin(4, s.issue_nonce().await.unwrap());
	let mut b = coin(5, s.issue_nonce().await.unwrap());
	b.salt = a.salt;
	let e = s.insert_coins(&[a, b]).await.unwrap_err();
	assert!(matches!(e, StoreError::SaltReused(_)), "{:?}", e);
	assert!(s.leaf(&[4; 32]).await.unwrap().is_none());
	assert!(s.known_salts(&[[4; 32]]).await.unwrap().is_empty());
}

#[tokio::test]
async fn mailbox_by_cursor() {
	let db = TestDb::new().await;
	let s = &db.store;
	s.insert_coins(&[coin(1, s.issue_nonce().await.unwrap()), coin(2, s.issue_nonce().await.unwrap())]).await.unwrap();
	let c1 = s.mailbox_post(&[9; 32], &[1; 32], b"one").await.unwrap();
	let _other = s.mailbox_post(&[8; 32], &[2; 32], b"elsewhere").await.unwrap();
	let c2 = s.mailbox_post(&[9; 32], &[2; 32], b"two").await.unwrap();
	let all = s.mailbox_read(&[9; 32], 0, 10).await.unwrap();
	assert_eq!(all.iter().map(|m| m.payload.clone()).collect::<Vec<_>>(), vec![b"one".to_vec(), b"two".to_vec()]);
	assert_eq!(all[0].cursor, c1);
	let rest = s.mailbox_read(&[9; 32], c1, 10).await.unwrap();
	assert_eq!(rest.len(), 1);
	assert_eq!(rest[0].cursor, c2);
	assert_eq!(rest[0].leaf_id, Some([2; 32]));
	assert!(s.mailbox_read(&[9; 32], c2, 10).await.unwrap().is_empty());
	assert_eq!(s.mailbox_read(&[9; 32], 0, 1).await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_challenge_is_checked_and_stored_nowhere() {
	use server::auth::{check_challenge, issue_challenge, ChallengeError};
	let db = TestDb::new().await;
	let (client, conn) = tokio_postgres::connect(&db.url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(conn);
	let tables: i64 = client.query_one("SELECT count(*) FROM information_schema.tables WHERE table_name = 'auth_challenge'", &[])
		.await.unwrap().get(0);
	assert_eq!(tables, 0, "the schema keeps no challenge");
	let key = [5u8; 32];
	let c = issue_challenge(&key, 1_800_000_000, [3; 12]);
	assert_eq!(check_challenge(&key, &c, 1_800_000_060, 120), Ok(()));
	assert_eq!(check_challenge(&key, &[1; 32], 1_800_000_060, 120), Err(ChallengeError::Unknown));
	assert_eq!(check_challenge(&key, &c, 1_800_000_121, 120), Err(ChallengeError::Expired));
}
