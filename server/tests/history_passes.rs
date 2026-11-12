//! How long the operator's passes take with a long history behind them: a
//! measurement, run by hand, not in the suite.
//!
//! A base history is made through the server's own flows, at the public
//! testnet's settings (batches without a sweep, finality at certification
//! with `anchor_depth` 0): boards, three generations of refreshes (so the
//! first generations' lowest nodes are released and reclaimed), board
//! forfeits claimed, an offboard unlocked; every transaction final. That
//! history is then cloned in the database, every 32-byte id (txids, leaf ids,
//! scripts, hashes) mapped to a fresh one and every round id moved on, until
//! the operator holds `HISTORY_ROUNDS` final rounds (the testnet's operator
//! held 20,911 on 2026-11-12) times `HISTORY_SCALE`. The clones are what a
//! long-running operator holds: rounds final, their batches reclaimed, their
//! forfeits claimed, their watcher transactions final. The node knows none of
//! their transactions.
//!
//! Then the server's passes are timed, each run by hand: the watcher's whole
//! pass, the pass over the rounds, the nursery's, and a round built over
//! waiting refreshes of an asset with an in-flight cap.
//!
//! ```text
//! HISTORY_SCALE=1 cargo test -p arca-server --test history_passes -- --ignored --nocapture
//! HISTORY_SCALE=10 cargo test -p arca-server --test history_passes -- --ignored --nocapture
//! ```
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::time::{Duration, Instant};


use common::flow::{refresh, release, settle, Coin};
use common::keys::keypair;
use common::rounds::{credited_board, VALUE};
use common::running::Running;

fn env(name: &str, default: u64) -> u64 {
	std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// The tables never cloned: the chain, the operator's own keys, wallet and
/// signer state, and the migrations' record.
const KEEP: &[&str] = &["refinery_schema_history", "arca_schema", "block", "chain_event", "wallet_key", "wallet_coin", "challenge_key",
	"signer_head", "signer_message", "keeper", "keeper_ack", "watch_touch", "watch_cursor", "tx_unblocked"];

async fn db(r: &Running) -> tokio_postgres::Client {
	let (client, conn) = tokio_postgres::connect(&r.db.url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(async move {
		let _ = conn.await;
	});
	client
}

/// Clones every row of the history `n` times: each bytea id of 32 bytes (or
/// a script of 34, or a subject of 36 starting with one) mapped to a fresh
/// one per clone, each round id moved on by a clone's offset, every other
/// column as it was. Foreign keys are not checked while it runs; the mapping
/// is one function of the old value and the clone, so every reference stays
/// consistent.
async fn clone_history(c: &tokio_postgres::Client, n: i64) {
	let t = Instant::now();
	// The token of every batch without a sweep is one and the same.
	let no_sweep = common::client::hex(&{ use elements::hashes::Hash; arca_covenant::clock::no_sweep_token().into_inner().to_byte_array() });
	c.batch_execute(&format!("
		CREATE OR REPLACE FUNCTION op9_f(x bytea, k int) RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
		  SELECT CASE WHEN x IS NULL THEN NULL WHEN x = '\\x{no_sweep}'::bytea THEN x
		    WHEN octet_length(x) = 32 THEN decode(md5(encode(x, 'hex') || k::text) || md5(k::text || encode(x, 'hex')), 'hex')
		    WHEN octet_length(x) = 34 AND get_byte(x, 0) = 81 THEN substring(x FROM 1 FOR 2) ||
		      decode(md5(encode(substring(x FROM 3), 'hex') || k::text) || md5(k::text || encode(substring(x FROM 3), 'hex')), 'hex')
		    WHEN octet_length(x) = 36 THEN
		      decode(md5(encode(substring(x FROM 1 FOR 32), 'hex') || k::text) || md5(k::text || encode(substring(x FROM 1 FOR 32), 'hex')), 'hex')
		      || substring(x FROM 33)
		    ELSE x END $$;")).await.unwrap();
	let off: i64 = c.query_one("SELECT coalesce(max(round_id), 0) + 1 FROM round", &[]).await.unwrap().get(0);
	let tables: Vec<String> = c.query("SELECT table_name::text FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
		ORDER BY 1", &[]).await.unwrap().iter().map(|r| r.get(0)).collect();
	let mut sql = String::from("BEGIN; SET LOCAL session_replication_role = replica;\n");
	let mut cloned = vec![];
	for t in tables.iter().filter(|t| !KEEP.contains(&t.as_str())) {
		let rows: i64 = c.query_one(&format!("SELECT count(*) FROM {}", t), &[]).await.unwrap().get(0);
		if rows == 0 {
			continue;
		}
		let cols = c.query("SELECT column_name::text, data_type::text, coalesce(column_default, '') FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = $1 ORDER BY ordinal_position", &[&t]).await.unwrap();
		// A table of one row (keyed by `one`) is the operator's own setting.
		if cols.iter().any(|c| c.get::<_, String>(0) == "one") {
			continue;
		}
		let mut names = vec![];
		let mut exprs = vec![];
		for col in &cols {
			let (name, ty, default): (String, String, String) = (col.get(0), col.get(1), col.get(2));
			let is_round = name == "round_id" || name == "batch_round";
			if default.starts_with("nextval(") && !is_round {
				continue;
			}
			names.push(format!("\"{}\"", name));
			// Asset ids and block hashes name what the clones share with the
			// base: the assets served and the chain's blocks.
			let shared = (name.contains("asset") && name != "connector_asset") || name.contains("block_hash") || name == "anchor_hash";
			exprs.push(if ty == "bytea" && !shared {
				format!("op9_f(b.\"{}\", k)", name)
			} else if is_round {
				format!("b.\"{}\" + k * {}", name, off)
			} else {
				format!("b.\"{}\"", name)
			});
		}
		sql.push_str(&format!("CREATE TEMP TABLE op9_base_{t} AS SELECT * FROM {t};\n\
			INSERT INTO {t} ({}) SELECT {} FROM op9_base_{t} b CROSS JOIN generate_series(1, {n}) k;\n", names.join(", "), exprs.join(", ")));
		cloned.push(format!("{} {}", t, rows));
	}
	sql.push_str(&format!("SELECT setval(pg_get_serial_sequence('round', 'round_id'), (SELECT max(round_id) FROM round));\nCOMMIT;\nANALYZE;\n"));
	c.batch_execute(&sql).await.unwrap();
	println!("history: cloned {} times in {:.0} s: {}", n, t.elapsed().as_secs_f64(), cloned.join(", "));
}

fn median(v: &mut [f64]) -> f64 {
	v.sort_by(|a, b| a.partial_cmp(b).unwrap());
	if v.is_empty() { 0.0 } else { v[v.len() / 2] }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "a measurement, run by hand"]
async fn passes_with_a_history_behind_them() {
	let scale = env("HISTORY_SCALE", 1) as i64;
	let rounds_at_1 = env("HISTORY_ROUNDS", 20_911) as i64;
	let mut r = Running::start_with(|c, y| {
		c.assets.push(server::server::AssetSection::new(y, common::running::MIN_LEAF));
		c.batches.no_sweep = true;
		c.finality.anchor_depth = 0;
		c.assets[0].in_flight_cap = Some("100000000000000".into());
	}).await;
	let x = r.x;
	for _ in 0..6 {
		r.fund_wallet_in(x, 50_000_000).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;

	// The base: 4 rounds of 6 boards refreshed, refreshed again and once more
	// for half of them, every release reclaimed and every forfeit claimed.
	let t = Instant::now();
	let mut gen: Vec<Coin> = vec![];
	for b in 0..4 {
		let mut coins = vec![];
		for i in 0..6 {
			let (held, tx) = credited_board(&mut r, &keypair(&format!("H{} board {}", b, i)), x).await;
			coins.push(Coin { held, bases: vec![tx] });
		}
		let keys: Vec<_> = (0..coins.len()).map(|i| keypair(&format!("H{} g1 {}", b, i))).collect();
		let pairs: Vec<(&Coin, &_)> = coins.iter().zip(keys.iter()).collect();
		gen.extend(refresh(&mut r, &pairs).await.into_iter().map(|x| x.new));
	}
	for g in 2..4 {
		let take = if g == 2 { gen.len() } else { gen.len() / 2 };
		let mut next = vec![];
		for (k, chunk) in gen[..take].chunks(6).enumerate() {
			let keys: Vec<_> = (0..chunk.len()).map(|i| keypair(&format!("G{} {} {}", g, k, i))).collect();
			let pairs: Vec<(&Coin, &_)> = chunk.iter().zip(keys.iter()).collect();
			for x in refresh(&mut r, &pairs).await {
				release(&r, &x);
				next.push(x.new);
			}
		}
		next.extend(gen.drain(take..));
		gen = next;
	}
	for _ in 0..12 {
		r.server.watcher.pass().await.unwrap();
		settle(&r).await;
	}
	let c = db(&r).await;
	let pending: i64 = c.query_one("SELECT count(*) FROM nursery_tx WHERE state <> 'final'", &[]).await.unwrap().get(0);
	let kinds: Vec<String> = c.query("SELECT kind || ' ' || count(*) FROM watcher_tx GROUP BY kind ORDER BY 1", &[]).await.unwrap()
		.iter().map(|r| r.get(0)).collect();
	let finals: i64 = c.query_one("SELECT count(*) FROM round WHERE state = 'final'", &[]).await.unwrap().get(0);
	println!("base: {} final rounds, watcher txs {}, {} not final in the nursery, {:.0} s", finals, kinds.join(", "), pending,
		t.elapsed().as_secs_f64());
	assert_eq!(pending, 0, "the base history is settled");
	assert_eq!(VALUE, 1_000_000);

	let want = rounds_at_1 * scale;
	let n = ((want + finals - 1) / finals - 1).max(0);
	clone_history(&c, n).await;
	let sizes: Vec<String> = c.query("SELECT relname || ' ' || n_live_tup FROM pg_stat_user_tables WHERE n_live_tup > 0
		ORDER BY n_live_tup DESC LIMIT 14", &[]).await.unwrap().iter().map(|r| r.get(0)).collect();
	let finals: i64 = c.query_one("SELECT count(*) FROM round WHERE state = 'final'", &[]).await.unwrap().get(0);
	println!("history ×{}: {} final rounds; {}", scale, finals, sizes.join(", "));
	r.restart_server().await;
	r.synced().await;

	// The passes, each run by hand.
	let mut watcher = vec![];
	for _ in 0..5 {
		let t = Instant::now();
		r.server.watcher.pass().await.unwrap();
		watcher.push(t.elapsed().as_secs_f64() * 1000.0);
	}
	let mut rounds = vec![];
	for _ in 0..5 {
		let t = Instant::now();
		r.server.rounds.pass().await.unwrap();
		rounds.push(t.elapsed().as_secs_f64() * 1000.0);
	}
	let mut nursery = vec![];
	for _ in 0..5 {
		let t = Instant::now();
		r.server.nursery.pass().await.unwrap();
		nursery.push(t.elapsed().as_secs_f64() * 1000.0);
	}
	// A round over three waiting refreshes of X, whose cap is read.
	let mut built = vec![];
	for (k, chunk) in gen.chunks(3).take(2).enumerate() {
		for (i, coin) in chunk.iter().enumerate() {
			let key = keypair(&format!("M{} {}", k, i));
			let (w, _) = common::client::want_leaf(&key, x, coin.valid(&r).value);
			let (body, _) = common::client::participation_body(&[&coin.held], &[w], &[], None, common::keys::xonly(&r.s), r.chain);
			assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
		}
		let t = Instant::now();
		let (made, failed) = r.server.rounds.run_rounds().await.unwrap();
		built.push(t.elapsed().as_secs_f64() * 1000.0);
		assert!(failed.is_empty() && !made.is_empty(), "{:?}", failed);
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	println!("TIMES ×{} ({} final rounds): watcher pass first {:.0} ms, median {:.0} ms; rounds pass median {:.0} ms; nursery pass median {:.0} ms; \
		run_rounds over 3 capped refreshes {:?} ms", scale, finals, watcher[0], median(&mut watcher.clone()), median(&mut rounds),
		median(&mut nursery), built.iter().map(|b| b.round() as u64).collect::<Vec<_>>());
}
