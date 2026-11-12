//! A database that still holds a coin of the retired `enclave-1`.
//!
//! This build reads no `enclave-1` record: its watcher could not defend such
//! a coin, and a holder's own conversion of an `enclave-1` board would stop a
//! later start. So `Server::start` refuses, before anything else, a database
//! holding one, naming each coin, and starts on a database without one as
//! before. The records are a real `enclave-1` coin and its board, as a build
//! that served the template wrote them (`data/enclave1_coin.hex`: a coin
//! record of tag 7 whose input is a board of record version 4).
//!
//! Needs `ARCA_TEST_POSTGRES`; no node.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::db::TestDb;
use common::fake::FakeChain;
use server::chain::{Certification, ChainSource, FinalityConfig, FinalityService};
use server::server::{unknown_to_the_database, Config, Server};

/// The old coin record: tag 7, its input a board of record version 4.
fn old_coin() -> Vec<u8> {
	let h = include_str!("data/enclave1_coin.hex").trim();
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

/// The board record inside it, and that board's own coin record (tag 2).
fn old_board() -> (Vec<u8>, Vec<u8>) {
	let c = old_coin();
	assert_eq!((c[1], c[3]), (7, 2), "a coin of tag 7 whose input is a board");
	let len = u16::from_le_bytes([c[4], c[5]]) as usize;
	let board = c[6..6 + len].to_vec();
	assert_eq!(board[0], 4, "a board of record version 4");
	let mut coin = vec![c[0], 2];
	coin.extend(&c[4..6]);
	coin.extend(&board);
	(board, coin)
}

/// The same board as record version 2: an ordinary `vtxo-1` board's header.
fn plain_board() -> (Vec<u8>, Vec<u8>) {
	let (mut board, mut coin) = old_board();
	board[0] = 2;
	coin[4] = 2;
	(board, coin)
}

async fn conn(url: &str) -> tokio_postgres::Client {
	let (c, conn) = tokio_postgres::connect(url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(async move {
		let _ = conn.await;
	});
	c
}

/// A coin row, `n` naming it, with `record` in `state`.
async fn leaf(c: &tokio_postgres::Client, n: u8, kind: &str, record: &[u8], state: &str) -> [u8; 32] {
	let id = [n; 32];
	let script = vec![0x51u8, n];
	c.execute("INSERT INTO arca_script (script_pubkey, kind, leaf_id) VALUES ($1, 'leaf', $2)", &[&script, &&id[..]]).await.unwrap();
	let spent_by: Option<Vec<u8>> = (state == "spent").then(|| vec![0xeeu8; 32]);
	c.execute(
		&format!("INSERT INTO leaf (leaf_id, kind, asset, value, owner_key, script_pubkey, hops, record, state, spent_by)
		 VALUES ($1, '{}', $2, 700000, $3, $4, 0, $5, '{}', $6)", kind, state),
		&[&&id[..], &vec![0xaau8; 32], &vec![n; 32], &script, &record, &spent_by],
	).await.unwrap();
	id
}

/// A board row for coin `id`.
async fn board(c: &tokio_postgres::Client, id: [u8; 32], record: &[u8], state: &str) {
	c.execute(
		&format!("INSERT INTO board (leaf_id, record, txid, vout, tx, state) VALUES ($1, $2, $3, 0, $4, '{}')", state),
		&[&&id[..], &record, &vec![id[0]; 32], &vec![0u8; 10]],
	).await.unwrap();
}

/// The example configuration on `db`, its node at a port nothing listens on:
/// a start that passes the check stops at the node.
fn config(db: &TestDb) -> Config {
	let example = include_str!("../arcad.example.toml")
		.replace("<asset id>", "25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a");
	let mut c: Config = toml::from_str(&example).expect("the example parses");
	c.database = db.url.clone();
	c.node.rpc_url = "http://127.0.0.1:1/".into();
	c
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// The rows the start counts, and those it leaves.
#[tokio::test(flavor = "multi_thread")]
async fn the_rows_of_a_retired_enclave_coin_are_counted() {
	let db = TestDb::new().await;
	let c = conn(&db.url).await;
	assert!(db.store.retired_enclave_coins().await.unwrap().is_empty(), "a fresh database holds none");
	let (old_b, old_b_coin) = old_board();
	let (plain_b, plain_b_coin) = plain_board();
	// An enclave-1 board paid away: its coin spent, the board credited. The
	// watcher would have to answer its holder's conversion (A1).
	let paid_away = leaf(&c, 1, "board", &old_b_coin, "spent").await;
	board(&c, paid_away, &old_b, "credited").await;
	// An enclave-1 board still held, and one lost.
	let held = leaf(&c, 2, "board", &old_b_coin, "live").await;
	board(&c, held, &old_b, "credited").await;
	let lost = leaf(&c, 3, "board", &old_b_coin, "lost").await;
	board(&c, lost, &old_b, "lost").await;
	// enclave-1 coins of a transfer: live, pending, spent, expired.
	let live = leaf(&c, 4, "transfer", &old_coin(), "live").await;
	let pending = leaf(&c, 5, "transfer", &old_coin(), "pending").await;
	leaf(&c, 6, "transfer", &old_coin(), "spent").await;
	leaf(&c, 7, "transfer", &old_coin(), "expired").await;
	// An ordinary board and its coin, live and spent: not counted.
	let plain = leaf(&c, 8, "board", &plain_b_coin, "live").await;
	board(&c, plain, &plain_b, "credited").await;
	let plain2 = leaf(&c, 9, "board", &plain_b_coin, "spent").await;
	board(&c, plain2, &plain_b, "credited").await;

	let found = db.store.retired_enclave_coins().await.unwrap();
	for (id, what) in &found {
		println!("counted {}: {}", hex(id), what);
	}
	let ids: Vec<[u8; 32]> = found.iter().map(|(id, _)| *id).collect();
	assert_eq!(ids, vec![paid_away, held, lost, live, pending], "every enclave-1 board, and every enclave-1 coin not spent or expired");
	assert_eq!(found[0].1, "an enclave-1 board, credited, its coin spent");
	assert_eq!(found[3].1, "an enclave-1 coin, live");
}

/// `Server::start` refuses such a database before anything else, naming each
/// coin and the way home, and leaves it as it was; without them it goes on
/// to the node.
#[tokio::test(flavor = "multi_thread")]
async fn a_database_holding_one_does_not_start() {
	let db = TestDb::new().await;
	let c = conn(&db.url).await;
	let e = Server::start(&config(&db)).await.err().expect("no node: the start stops").0;
	println!("a database without one: {}", e);
	assert!(!e.contains("enclave-1"), "a database without an enclave-1 coin passes the check: {}", e);

	let (old_b, old_b_coin) = old_board();
	let paid_away = leaf(&c, 1, "board", &old_b_coin, "spent").await;
	board(&c, paid_away, &old_b, "credited").await;
	let live = leaf(&c, 4, "transfer", &old_coin(), "live").await;
	let before: i64 = c.query_one("SELECT count(*) FROM leaf", &[]).await.unwrap().get(0);
	let e = Server::start(&config(&db)).await.err().expect("an enclave-1 coin: the start is refused").0;
	println!("a database with two: {}", e);
	assert!(e.starts_with("the database holds 2 coin(s) of the retired enclave-1"), "{}", e);
	assert!(e.contains(&hex(&paid_away)) && e.contains(&hex(&live)), "each coin named: {}", e);
	assert!(e.contains("previous release") && e.contains("exit to its enclave"), "the way home: {}", e);
	assert!(e.contains("https://github.com/ConcatenaLabs/arca/issues"), "where to report it: {}", e);
	let after: i64 = c.query_one("SELECT count(*) FROM leaf", &[]).await.unwrap().get(0);
	assert_eq!(before, after);
}

/// A2: an `enclave-1` board whose output a transaction the server did not
/// build spends (its holder's conversion) is skipped when the start checks
/// what the chain shows that the database does not know, instead of
/// stopping the start on its record. That holds even where the start's first
/// check is never reached.
#[tokio::test(flavor = "multi_thread")]
async fn a_spent_enclave_board_does_not_stop_the_chain_check() {
	let db = TestDb::new().await;
	let c = conn(&db.url).await;
	let (old_b, old_b_coin) = old_board();
	let id = leaf(&c, 1, "board", &old_b_coin, "spent").await;
	board(&c, id, &old_b, "credited").await;
	c.execute("INSERT INTO watched_outpoint (txid, vout, kind, watched_for, spent_by, spent_at) VALUES ($1, 0, 'board', $2, $3, now())",
		&[&vec![1u8; 32], &&id[..], &vec![0xccu8; 32]]).await.unwrap();
	let chain = Arc::new(FakeChain::new(false));
	let finality = FinalityService::new(db.store.clone(), chain as Arc<dyn ChainSource>, FinalityConfig {
		anchor_depth: 2, certification: Certification::NotOnThisChain, start_height: Some(0), poll_interval: Duration::from_millis(50),
		cert_lookback: 144,
	}).await.unwrap();
	let operator = common::keys::xonly(&common::keys::keypair("operator"));
	let r = unknown_to_the_database(&db.store, &finality, operator).await;
	println!("the chain check over a spent enclave-1 board: {:?}", r.as_ref().map_err(|e| e.0.clone()));
	assert_eq!(r.map_err(|e| e.0).unwrap(), Vec::<String>::new());
}
