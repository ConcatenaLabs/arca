//! The store against a real PostgreSQL: the schema builds from nothing, and
//! each rule the database holds refuses what breaks it.

mod common;

use common::db::TestDb;
use server::store::{ChallengeError, LeafKind, LeafState, NewCoin, NewScript, ScriptKind};
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
	assert_eq!(db.store.schema_version().await.unwrap(), 5);
	// Migrating again changes nothing.
	db.store.migrate().await.unwrap();
	let again = server::Store::connect(&db.url).await.unwrap();
	assert_eq!(again.schema_version().await.unwrap(), 5);
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
async fn challenge_used_once() {
	let db = TestDb::new().await;
	let s = &db.store;
	let c = s.issue_challenge(std::time::Duration::from_secs(60)).await.unwrap();
	assert_eq!(s.use_challenge(&c).await.unwrap(), Ok(()));
	assert_eq!(s.use_challenge(&c).await.unwrap(), Err(ChallengeError::Used));
	assert_eq!(s.use_challenge(&[1; 32]).await.unwrap(), Err(ChallengeError::Unknown));
	let short = s.issue_challenge(std::time::Duration::from_millis(1)).await.unwrap();
	tokio::time::sleep(std::time::Duration::from_millis(50)).await;
	assert_eq!(s.use_challenge(&short).await.unwrap(), Err(ChallengeError::Expired));
}
