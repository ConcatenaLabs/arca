//! The three passes that find a transaction held final that is no longer
//! final (`nursery_final_not_final`, `boards_credited_not_final`,
//! `rounds_final_not_final`) give exactly what the full statements they
//! replaced gave, kept here as the oracle, on the same tables: after every
//! kind of change to the chain as the store follows it and to the rows held
//! final.
//!
//! 1. Named steps: blocks appended; certification rising; a certification
//!    that disappears; a rollback that takes out blocks holding final rows;
//!    a Bitcoin reorg, the tip's anchor dropping; rows entering and leaving
//!    the state; a transaction recorded in an older block after the fact; no
//!    block certified; an anchor lower than its parent's; no block at all.
//! 2. Random steps of all of those, from a fixed seed.
//!
//! Each check runs every statement, old and new, for certification required
//! and not, and for anchor depths 0, 1, 2, 6 and the largest there is.
//!
//! Needs `ARCA_TEST_POSTGRES`.

mod common;

use common::db::TestDb;
use rand::{Rng, SeedableRng};
use server::store::{BlockRow, NurseryState, Scan};

/// The statement each pass ran before, word for word but for its outer
/// select (`still` is the set of transactions final).
fn oracle(join: &str, outer: &str) -> String {
	format!("WITH tip AS (SELECT anchor_height FROM block ORDER BY height DESC LIMIT 1),
	  cert AS (SELECT max(height) AS h FROM block WHERE certified),
	  loc AS (SELECT DISTINCT ON (t.txid) t.txid, b.height, b.anchor_height FROM tx_block t
	          JOIN block b ON b.hash = t.block_hash {}
	          ORDER BY t.txid, b.height),
	  still AS (SELECT loc.txid FROM loc, tip, cert
	            WHERE (NOT $1 OR loc.height <= cert.h) AND GREATEST(tip.anchor_height - loc.anchor_height, 0) >= $2)
	 {}", join, outer)
}

fn oracle_nursery() -> String {
	oracle("JOIN nursery_tx n ON n.txid = t.txid AND n.state = 'final'",
		"SELECT txid FROM nursery_tx WHERE state = 'final' AND txid NOT IN (SELECT txid FROM still) ORDER BY created_at, txid")
}

fn oracle_boards() -> String {
	oracle("JOIN board d ON d.txid = t.txid AND d.state = 'credited'",
		"SELECT leaf_id FROM board WHERE state = 'credited' AND txid NOT IN (SELECT txid FROM still) ORDER BY created_at")
}

fn oracle_rounds() -> String {
	oracle("JOIN round f ON f.txid = t.txid AND f.state = 'final'",
		"SELECT r.round_id FROM round r JOIN connector_output c ON c.round_id = r.round_id
		 WHERE r.state = 'final' AND r.txid NOT IN (SELECT txid FROM still) ORDER BY r.round_id")
}

/// Transactions 0..TXS; those at or above UNWATCHED are never watched, so
/// never in a block.
const TXS: u32 = 48;
const UNWATCHED: u32 = 44;
/// Boards: two outputs of each of the transactions 0, 4, 8, ...
const BOARD_EVERY: u32 = 4;
/// Rounds: one per transaction 1, 6, 11, ...
const ROUND_EVERY: u32 = 5;

fn txid(i: u32) -> [u8; 32] {
	let mut t = [0x7a; 32];
	t[..4].copy_from_slice(&i.to_be_bytes());
	t
}

struct World {
	db: TestDb,
	sql: tokio_postgres::Client,
	/// The chain as the store follows it, lowest first.
	chain: Vec<BlockRow>,
	next_hash: u64,
	checks: usize,
	/// Checks in which some statement found a row not final.
	nonempty: usize,
	rows_seen: usize,
}

impl World {
	async fn new() -> World {
		let db = TestDb::new().await;
		let (sql, conn) = tokio_postgres::connect(&db.url, tokio_postgres::NoTls).await.unwrap();
		tokio::spawn(conn);
		// Boards and rounds without the leaves, batches and participations
		// they hang from: this session skips foreign keys while it inserts
		// them. The store's own
		// connections, which connect and disconnect blocks, keep them, so a
		// rollback cascades to tx_block as it does in the server.
		sql.batch_execute("SET session_replication_role = replica").await.unwrap();
		for i in 0..TXS {
			if i < UNWATCHED {
				db.store.watch_tx(&txid(i), "nursery").await.unwrap();
			}
			sql.execute(
				"INSERT INTO nursery_tx (txid, tx, kind, state, created_at)
				 VALUES ($1, '\\x00', 'wallet', 'pending', now() + $2 * interval '1 s')",
				&[&&txid(i)[..], &(i as f64)],
			).await.unwrap();
			if i % BOARD_EVERY == 0 {
				for vout in 0..2i32 {
					let mut leaf = txid(i);
					leaf[31] = vout as u8;
					leaf[30] = 0x1e;
					sql.execute(
						"INSERT INTO board (leaf_id, record, txid, vout, tx, state, created_at)
						 VALUES ($1, '\\x00', $2, $3, '\\x00', 'pending', now() + $4 * interval '1 s')",
						&[&&leaf[..], &&txid(i)[..], &vout, &((TXS - i) as f64 + vout as f64 / 2.0)],
					).await.unwrap();
				}
			}
			if i % ROUND_EVERY == 1 {
				let id = 1000 + i as i64;
				sql.execute(
					"INSERT INTO round (round_id, txid, tx, state, fee_asset, fee, created_mtp)
					 VALUES ($1, $2, '\\x00', 'broadcast', $3, 1, 0)",
					&[&id, &&txid(i)[..], &&[0xaau8; 32][..]],
				).await.unwrap();
				let mut connector = txid(i);
				connector[30] = 0xc0;
				sql.execute(
					"INSERT INTO connector_output (round_id, vout, asset, value, connector_asset) VALUES ($1, 0, $2, 1, $3)",
					&[&id, &&[0xaau8; 32][..], &&connector[..]],
				).await.unwrap();
			}
		}
		// From here on the session's writes (rows entering and leaving the
		// final state) fire the triggers as the server's own writes do: a
		// replica role skips them along with the foreign keys.
		sql.batch_execute("SET session_replication_role = origin").await.unwrap();
		World { db, sql, chain: vec![], next_hash: 1, checks: 0, nonempty: 0, rows_seen: 0 }
	}

	/// Connects a block on the tip holding `txs`.
	async fn append(&mut self, anchor: u64, certified: bool, txs: &[u32]) {
		let mut hash = [0xbb; 32];
		hash[..8].copy_from_slice(&self.next_hash.to_be_bytes());
		self.next_hash += 1;
		let height = self.chain.last().map(|b| b.height + 1).unwrap_or(100);
		let prev_hash = self.chain.last().map(|b| b.hash).unwrap_or([0; 32]);
		let block = BlockRow { hash, height, prev_hash, anchor_height: anchor, anchor_hash: [0xcc; 32], median_time: height,
			certified };
		let scan = Scan { txids: txs.iter().map(|i| txid(*i)).collect(), ..Default::default() };
		self.db.store.connect_block(&block, &scan).await.unwrap();
		self.chain.push(block);
	}

	fn tip_anchor(&self) -> u64 {
		self.chain.last().map(|b| b.anchor_height).unwrap_or(5000)
	}

	/// Takes out the top `n` blocks, the tip first.
	async fn rollback(&mut self, n: usize) {
		for _ in 0..n.min(self.chain.len()) {
			let b = self.chain.pop().unwrap();
			self.db.store.disconnect_block(&b.hash).await.unwrap();
		}
	}

	async fn certify(&mut self, index: usize, certified: bool) {
		self.chain[index].certified = certified;
		self.db.store.set_certified(&self.chain[index].hash, certified).await.unwrap();
	}

	/// Certifies every block up to `index`.
	async fn certify_to(&mut self, index: usize) {
		for i in 0..=index.min(self.chain.len().saturating_sub(1)) {
			if !self.chain[i].certified {
				self.certify(i, true).await;
			}
		}
	}

	async fn nursery(&self, i: u32, state: NurseryState) {
		self.db.store.nursery_set_state(&txid(i), state).await.unwrap();
	}

	async fn board(&self, i: u32, vout: u8, state: &str) {
		let mut leaf = txid(i);
		leaf[31] = vout;
		leaf[30] = 0x1e;
		self.sql.execute("UPDATE board SET state = $2::text::board_state WHERE leaf_id = $1", &[&&leaf[..], &state]).await.unwrap();
	}

	async fn round(&self, i: u32, state: &str) {
		self.sql.execute("UPDATE round SET state = $2 WHERE txid = $1", &[&&txid(i)[..], &state]).await.unwrap();
	}

	/// Every final row, of every kind, made final (or credited).
	async fn all_final(&self) {
		self.sql.batch_execute("UPDATE nursery_tx SET state = 'final'; UPDATE board SET state = 'credited';
			UPDATE round SET state = 'final'").await.unwrap();
	}

	/// The old statements and the new give the same rows in the same order,
	/// for every requirement and depth.
	async fn check(&mut self, what: &str) {
		let mut found = 0;
		for certification in [true, false] {
			for depth in [0u64, 1, 2, 6, u64::MAX] {
				let d = i64::try_from(depth).unwrap_or(i64::MAX);
				let params: [&(dyn tokio_postgres::types::ToSql + Sync); 2] = [&certification, &d];

				let old: Vec<Vec<u8>> = self.sql.query(&oracle_nursery(), &params).await.unwrap().iter().map(|r| r.get(0)).collect();
				let new: Vec<Vec<u8>> = self.db.store.nursery_final_not_final(certification, depth).await.unwrap()
					.iter().map(|r| r.txid.to_vec()).collect();
				assert_eq!(new, old, "nursery, {}: certification {}, depth {}", what, certification, depth);
				found += old.len();

				let old: Vec<Vec<u8>> = self.sql.query(&oracle_boards(), &params).await.unwrap().iter().map(|r| r.get(0)).collect();
				let new: Vec<Vec<u8>> = self.db.store.boards_credited_not_final(certification, depth).await.unwrap()
					.iter().map(|r| r.leaf_id.to_vec()).collect();
				assert_eq!(new, old, "boards, {}: certification {}, depth {}", what, certification, depth);
				found += old.len();

				let old: Vec<i64> = self.sql.query(&oracle_rounds(), &params).await.unwrap().iter().map(|r| r.get(0)).collect();
				let new: Vec<i64> = self.db.store.rounds_final_not_final(certification, depth).await.unwrap()
					.iter().map(|r| r.round_id).collect();
				assert_eq!(new, old, "rounds, {}: certification {}, depth {}", what, certification, depth);
				found += old.len();
			}
		}
		self.checks += 1;
		self.rows_seen += found;
		if found > 0 {
			self.nonempty += 1;
		}
		println!("{}: the same {} rows not final, over 10 settings", what, found);
	}

	/// The answer at certification required, depth 2, of each kind:
	/// transactions, boards' leaves (as their transactions), rounds' transactions.
	async fn unfinal(&self) -> (Vec<u32>, Vec<u32>, Vec<u32>) {
		let of = |t: &[u8; 32]| u32::from_be_bytes(t[..4].try_into().unwrap());
		let n = self.db.store.nursery_final_not_final(true, 2).await.unwrap().iter().map(|r| of(&r.txid)).collect();
		let b = self.db.store.boards_credited_not_final(true, 2).await.unwrap().iter().map(|r| of(&r.txid)).collect();
		let r = self.db.store.rounds_final_not_final(true, 2).await.unwrap().iter().map(|r| of(&r.txid)).collect();
		(n, b, r)
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn named_changes() {
	let mut w = World::new().await;
	w.check("nothing final, no block").await;
	w.all_final().await;
	w.check("everything final, no block").await;

	// Twenty blocks, anchors a Bitcoin block every two, the transactions
	// 0..40 two to a block; certified up to the 18th.
	for k in 0..20u32 {
		w.append(5000 + k as u64 / 2, false, &[2 * k, 2 * k + 1]).await;
	}
	w.certify_to(17).await;
	w.check("twenty blocks").await;
	let (n, _, _) = w.unfinal().await;
	assert!(n.contains(&36) && n.contains(&40) && n.contains(&47) && !n.contains(&0), "{:?}", n);

	// A block appended, holding 40 and 41.
	w.append(5010, false, &[40, 41]).await;
	w.check("a block appended").await;
	w.certify_to(20).await;
	w.check("certified to the tip").await;

	// Certification disappears from the top three blocks.
	for i in 18..21 {
		w.certify(i, false).await;
	}
	w.check("certification gone from the top three").await;
	let (n, _, _) = w.unfinal().await;
	assert!(n.contains(&36), "a transaction above the highest certified block is not final: {:?}", n);

	// Certification gone from every block.
	for i in 0..w.chain.len() {
		w.certify(i, false).await;
	}
	w.check("no block certified").await;
	w.certify_to(19).await;

	// Ten more blocks, buried under further anchors.
	for k in 0..10u64 {
		w.append(5011 + k, true, &[]).await;
	}
	w.check("ten more blocks").await;
	assert!(w.unfinal().await.0.iter().all(|i| *i >= 40), "only the transactions in no block and the newest");

	// A rollback that takes out blocks holding final rows (0..1 stay; the
	// blocks of 30..41 go).
	w.rollback(16).await;
	w.check("a rollback of sixteen blocks").await;
	let (n, b, r) = w.unfinal().await;
	assert!(n.contains(&30) && b.contains(&32) && r.contains(&31), "{:?} {:?} {:?}", n, b, r);

	// A Bitcoin reorg: the tip's anchor drops below the anchors of blocks
	// that were buried.
	let low = w.tip_anchor() - 4;
	w.rollback(1).await;
	w.append(low, true, &[30, 31]).await;
	w.check("the tip's anchor dropped").await;
	let (n, _, _) = w.unfinal().await;
	assert!(n.contains(&20), "a transaction whose anchor is no longer buried: {:?}", n);
	for k in 1..8u64 {
		w.append(low + k, true, &[]).await;
	}
	w.check("the chain grew past the reorg").await;

	// Rows leave the state, and enter it.
	w.nursery(30, NurseryState::Pending).await;
	w.nursery(2, NurseryState::Lost).await;
	w.board(32, 0, "pending").await;
	w.round(31, "lost").await;
	w.check("rows left the state").await;
	w.nursery(30, NurseryState::Final).await;
	w.board(32, 0, "credited").await;
	w.round(31, "final").await;
	w.check("rows entered the state").await;

	// A transaction held by a later block as well as an older one: its
	// lowest block decides.
	let old = w.chain[3].hash;
	w.append(w.tip_anchor(), true, &[6, 7]).await;
	w.check("a transaction in two blocks, the newer not final").await;
	w.db.store.record_tx_block(&txid(43), &old).await.unwrap();
	w.check("a transaction recorded in an older block after the fact").await;
	assert!(!w.unfinal().await.0.contains(&43));

	// An anchor lower than its parent's.
	let a = w.tip_anchor();
	w.append(a - 6, true, &[42]).await;
	w.append(a, true, &[]).await;
	w.check("an anchor lower than its parent's").await;

	// No block at all.
	let n = w.chain.len();
	w.rollback(n).await;
	w.check("no block").await;
	assert_eq!(w.unfinal().await.0.len(), TXS as usize - 1, "every final transaction (2 is lost)");
	assert!(w.nonempty > 10, "the checks saw rows not final");
}

#[tokio::test(flavor = "multi_thread")]
async fn random_changes() {
	let seed: u64 = std::env::var("FINAL_PASSES_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x5eed_f1a1);
	println!("seed {}", seed);
	let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
	let mut w = World::new().await;
	let mut anchor = 5000u64;
	for step in 0..250 {
		let what = match rng.gen_range(0..100) {
			0..=34 => {
				// Appended: the anchor usually climbs, sometimes stays or
				// steps back; a few transactions, some already in a block.
				anchor = match rng.gen_range(0..10) {
					0 => anchor.saturating_sub(rng.gen_range(1..4)),
					1..=4 => anchor,
					_ => anchor + rng.gen_range(1..3),
				};
				let txs: Vec<u32> = (0..rng.gen_range(0..4)).map(|_| rng.gen_range(0..TXS)).collect();
				let certified = rng.gen_bool(0.3);
				w.append(anchor, certified, &txs).await;
				"append"
			},
			35..=44 => {
				let n = rng.gen_range(1..5);
				w.rollback(n).await;
				anchor = w.tip_anchor();
				"rollback"
			},
			45..=49 => {
				// A Bitcoin reorg: blocks out, then the chain again on a
				// lower anchor.
				let n = rng.gen_range(1..4);
				w.rollback(n).await;
				anchor = w.tip_anchor().saturating_sub(rng.gen_range(1..6));
				for _ in 0..n {
					w.append(anchor, rng.gen_bool(0.5), &[rng.gen_range(0..TXS)]).await;
				}
				"anchor reorg"
			},
			50..=59 if !w.chain.is_empty() => {
				let to = rng.gen_range(0..w.chain.len());
				w.certify_to(to).await;
				"certify"
			},
			60..=64 if !w.chain.is_empty() => {
				let i = rng.gen_range(0..w.chain.len());
				w.certify(i, false).await;
				"certification gone"
			},
			65..=69 if !w.chain.is_empty() => {
				let i = rng.gen_range(0..w.chain.len());
				let hash = w.chain[i].hash;
				w.db.store.record_tx_block(&txid(rng.gen_range(0..TXS)), &hash).await.unwrap();
				"recorded in an older block"
			},
			_ => {
				let i = rng.gen_range(0..TXS);
				let fin = rng.gen_bool(0.7);
				match rng.gen_range(0..3) {
					0 => w.nursery(i, if fin { NurseryState::Final } else if rng.gen_bool(0.5) { NurseryState::Pending } else { NurseryState::Lost }).await,
					1 => {
						let i = i - i % BOARD_EVERY;
						w.board(i, rng.gen_range(0..2), if fin { "credited" } else { "pending" }).await;
					},
					_ => {
						let i = (i / ROUND_EVERY) * ROUND_EVERY + 1;
						if i < TXS {
							w.round(i, if fin { "final" } else { "broadcast" }).await;
						}
					},
				}
				"state"
			},
		};
		w.check(&format!("step {} ({}), {} blocks", step, what, w.chain.len())).await;
	}
	println!("{} checks, {} with rows not final, {} rows in all", w.checks, w.nonempty, w.rows_seen);
	assert!(w.nonempty > w.checks / 2, "most checks saw rows not final");
}
