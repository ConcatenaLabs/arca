//! The passes over the whole history read only the items logged as they may
//! have opened (`pass_open`, filled by the triggers of `V49__pass_reads.sql`;
//! `store::open`): the sightings of coins given up, the forfeited coins of
//! transfers, the forfeits not claimed, the boards to recover, and the coins
//! whose value is in flight. Each check is the store's own recount: the
//! whole statement and the logged read in one snapshot, every row of the
//! whole statement logged.
//!
//! 1. Writes through the server's own flows: boards, three generations of
//!    refreshes (the first generations' lowest nodes released and
//!    reclaimed, the last not released, so in flight), forfeits published
//!    and claimed, everything final, at the
//!    public testnet's settings (batches without a sweep, finality at
//!    certification with `anchor_depth` 0). The logs start empty and the
//!    triggers alone fill them.
//! 2. Then random writes to every state the statements read, with the
//!    triggers as the server's writes have them: a transaction of the
//!    watcher's final yesterday taken out of the final state today (as a
//!    reorganisation does), lost, final again; coins spent and live again;
//!    boards credited and not; participations and rounds moving; coins
//!    given up and given back; a batch's collection horizon set and
//!    cleared; forfeits removed. After each, every log is pruned and
//!    recounted.
//!
//! 3. Named writes, each the only one that reopens its item: a coin in flight
//!    given back and given up again; a board's claim taken out of the final
//!    state, the board then not credited, and credited again.
//!
//! Not made here: a coin paid on out of round whose earlier leaf was
//! collected, for the trigger on a batch's collection horizon.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use rand::{Rng, SeedableRng};

use common::flow::{refresh, release, settle, Coin};
use common::keys::keypair;
use common::rounds::credited_board;
use common::running::Running;
use server::server::AssetSection;
use server::store::open::{Pass, WATCHER_PASSES};

const PASSES: [Pass; 5] = [WATCHER_PASSES[0], WATCHER_PASSES[1], WATCHER_PASSES[2], WATCHER_PASSES[3], Pass::Flight];

async fn db(r: &Running) -> tokio_postgres::Client {
	let (client, conn) = tokio_postgres::connect(&r.db.url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(async move {
		let _ = conn.await;
	});
	client
}

/// Every pass's log pruned, then recounted: the rows of each whole
/// statement, and none the log lacked.
async fn check(r: &Running, what: &str) -> Vec<u64> {
	let mut rows = vec![];
	for pass in PASSES {
		r.db.store.prune_open(pass).await.unwrap();
		let (whole, missing) = r.db.store.recount_open(pass).await.unwrap();
		assert_eq!(missing, 0, "{}: the {} pass's whole statement has {} row(s) its log lacked, of {}", what, pass.name(), missing, whole);
		rows.push(whole);
	}
	rows
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_hold_every_open_item() {
	let mut r = Running::start_with(|c, y| {
		c.assets.push(AssetSection::new(y, common::running::MIN_LEAF));
		c.batches.no_sweep = true;
		c.finality.anchor_depth = 0;
		c.assets[0].in_flight_cap = Some("100000000000000".into());
	}).await;
	let x = r.x;
	for _ in 0..4 {
		r.fund_wallet_in(x, 50_000_000).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	// The logs start here, empty, and marked filled, so no first count of
	// the server's fills them: what follows is logged by the triggers alone.
	let c = db(&r).await;
	for pass in PASSES {
		c.execute("INSERT INTO watch_cursor (name, value) VALUES ($1, 1) ON CONFLICT (name) DO NOTHING",
			&[&format!("open:{}", pass.name())]).await.unwrap();
	}
	tokio::time::sleep(std::time::Duration::from_secs(2)).await;
	c.batch_execute("DELETE FROM pass_open").await.unwrap();

	// 1. The server's own flows.
	let mut gen: Vec<Coin> = vec![];
	for b in 0..2 {
		let mut coins = vec![];
		for i in 0..4 {
			let (held, tx) = credited_board(&mut r, &keypair(&format!("O{} board {}", b, i)), x).await;
			coins.push(Coin { held, bases: vec![tx] });
		}
		let keys: Vec<_> = (0..coins.len()).map(|i| keypair(&format!("O{} g1 {}", b, i))).collect();
		let pairs: Vec<(&Coin, &_)> = coins.iter().zip(keys.iter()).collect();
		gen.extend(refresh(&mut r, &pairs).await.into_iter().map(|x| x.new));
		check(&r, &format!("boards of round {} refreshed", b)).await;
	}
	for g in 2..4 {
		let take = if g == 2 { gen.len() } else { gen.len() / 2 };
		let mut next = vec![];
		for (k, chunk) in gen[..take].chunks(4).enumerate() {
			let keys: Vec<_> = (0..chunk.len()).map(|i| keypair(&format!("O{} {} {}", g, k, i))).collect();
			let pairs: Vec<(&Coin, &_)> = chunk.iter().zip(keys.iter()).collect();
			for x in refresh(&mut r, &pairs).await {
				release(&r, &x);
				next.push(x.new);
			}
			check(&r, &format!("generation {} refreshed", g)).await;
		}
		next.extend(gen.drain(take..));
		gen = next;
	}
	// Coins given up and not released: their value stays in flight.
	{
		let keys: Vec<_> = (0..4).map(|i| keypair(&format!("O held {}", i))).collect();
		let pairs: Vec<(&Coin, &_)> = gen[..4].iter().zip(keys.iter()).collect();
		refresh(&mut r, &pairs).await;
		check(&r, "refreshed, not released").await;
	}
	for i in 0..8 {
		r.server.watcher.pass().await.unwrap();
		check(&r, &format!("watcher pass {}", i)).await;
		settle(&r).await;
		check(&r, &format!("settled after watcher pass {}", i)).await;
	}
	let kinds: Vec<String> = c.query("SELECT kind || ' ' || count(*) FROM watcher_tx GROUP BY kind ORDER BY 1", &[]).await.unwrap()
		.iter().map(|r| r.get(0)).collect();
	println!("flows: watcher transactions {}; open rows now {:?}", kinds.join(", "), check(&r, "the flows").await);

	// Two shapes these flows do not make, made here: an output on the chain
	// paying the leaf of a coin given up (an exit), recorded as the chain's
	// scan records one, some spent by a transaction of the watcher's; and a
	// coin of a transfer given up with a forfeit, the forfeit published and
	// claimed (four forfeited coins taken as transfer coins, a change no
	// write of the server's makes, so the log takes them in by a count, as
	// at its first count after the schema step).
	c.batch_execute("
		INSERT INTO script_sighting (script_pubkey, txid, vout, seen_in)
		SELECT DISTINCT a.script_pubkey, sha256(a.script_pubkey), 7, 'block' FROM arca_script a
		JOIN forfeit f ON f.leaf_id = a.leaf_id WHERE a.kind = 'leaf' ORDER BY 1 LIMIT 8;
		INSERT INTO watcher_input (prev_txid, prev_vout, txid)
		SELECT s.txid, s.vout, w.txid
		FROM (SELECT txid, vout, row_number() OVER (ORDER BY txid) AS k FROM script_sighting WHERE vout = 7) s
		JOIN (SELECT txid, row_number() OVER (ORDER BY txid) AS k FROM watcher_tx) w ON w.k = s.k WHERE s.k % 2 = 0
		ON CONFLICT DO NOTHING;
		SET session_replication_role = replica;
		UPDATE leaf SET kind = 'transfer' WHERE leaf_id IN (SELECT subject FROM watcher_tx WHERE kind = 'forfeit' ORDER BY txid LIMIT 4);
		SET session_replication_role = origin;").await.unwrap();
	for pass in PASSES {
		r.db.store.recount_open(pass).await.unwrap();
	}
	println!("made: open rows now {:?}", check(&r, "the shapes made").await);

	// Named writes, each the only one that reopens its item.
	// A coin in flight given back, then given up again.
	let root: Vec<u8> = c.query_one("SELECT k FROM pass_open WHERE pass = 'flight' ORDER BY k LIMIT 1", &[]).await.unwrap().get(0);
	let before = check(&r, "before a coin is given back").await[4];
	c.execute("UPDATE participation_input SET active = false WHERE leaf_id = $1 AND active", &[&root]).await.unwrap();
	assert_eq!(check(&r, "a coin in flight given back").await[4], before - 1);
	c.execute("UPDATE participation_input SET active = true WHERE leaf_id = $1", &[&root]).await.unwrap();
	assert_eq!(check(&r, "the coin given up again").await[4], before);
	// A board given up whose forfeit's claim of the board output is taken
	// out of the final state (opens), the board then not credited (closes),
	// and credited again (opens).
	let (board, spender): (Vec<u8>, Vec<u8>) = {
		let row = c.query_one("SELECT b.leaf_id, wi.txid FROM board b JOIN leaf l ON l.leaf_id = b.leaf_id AND l.state = 'spent'
			JOIN watcher_input wi ON wi.prev_txid = b.txid AND wi.prev_vout = b.vout JOIN nursery_tx n ON n.txid = wi.txid AND n.state = 'final'
			WHERE b.state = 'credited' AND EXISTS (SELECT 1 FROM forfeit f WHERE f.leaf_id = b.leaf_id) ORDER BY b.leaf_id LIMIT 1", &[]).await.unwrap();
		(row.get(0), row.get(1))
	};
	let before = check(&r, "before a board's spender leaves the final state").await[3];
	c.execute("UPDATE nursery_tx SET state = 'pending' WHERE txid = $1", &[&spender]).await.unwrap();
	assert_eq!(check(&r, "a board's spender out of the final state").await[3], before + 1);
	c.execute("UPDATE board SET state = 'pending' WHERE leaf_id = $1", &[&board]).await.unwrap();
	assert_eq!(check(&r, "the board not credited").await[3], before);
	c.execute("UPDATE board SET state = 'credited' WHERE leaf_id = $1", &[&board]).await.unwrap();
	assert_eq!(check(&r, "the board credited again").await[3], before + 1);
	c.execute("UPDATE nursery_tx SET state = 'final' WHERE txid = $1", &[&spender]).await.unwrap();
	assert_eq!(check(&r, "the spender final again").await[3], before);

	// 2. Random writes.
	let seed: u64 = std::env::var("OPEN_PASSES_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x09e4_5eed);
	println!("seed {}", seed);
	let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
	let mut seen = [0u64; 5];
	let mut nonempty = [0u64; 5];
	let mut applied = std::collections::BTreeMap::new();
	let mut refused = std::collections::BTreeMap::new();
	const STEPS: usize = 300;
	for step in 0..STEPS {
		let pick = rng.gen_range(0..1_000_000i64);
		let (what, sql, arg): (&str, &str, &str) = match rng.gen_range(0..100) {
			0..=29 => ("nursery", "UPDATE nursery_tx SET state = $2::text::nursery_state WHERE txid = (SELECT txid FROM nursery_tx
				ORDER BY txid OFFSET $1 % greatest((SELECT count(*) FROM nursery_tx), 1) LIMIT 1)",
				["final", "pending", "lost", "final"][rng.gen_range(0..4)]),
			// Mostly a coin the statements name: with a forfeit, a sighting or
			// a board.
			30..=34 => ("leaf", "UPDATE leaf SET state = $2::text::leaf_state,
				spent_by = CASE WHEN $2 = 'spent' THEN coalesce(spent_by, sha256(leaf_id)) END WHERE leaf_id = (SELECT leaf_id FROM leaf
				ORDER BY leaf_id OFFSET $1 % greatest((SELECT count(*) FROM leaf), 1) LIMIT 1)",
				["spent", "live", "lost"][rng.gen_range(0..3)]),
			35..=44 => ("leaf named", "WITH x AS (SELECT leaf_id FROM forfeit UNION SELECT a.leaf_id FROM arca_script a JOIN script_sighting USING (script_pubkey)
				UNION SELECT leaf_id FROM board)
				UPDATE leaf SET state = $2::text::leaf_state,
				spent_by = CASE WHEN $2 = 'spent' THEN coalesce(spent_by, sha256(leaf_id)) END WHERE leaf_id = (SELECT leaf_id FROM x
				ORDER BY leaf_id OFFSET $1 % greatest((SELECT count(*) FROM x), 1) LIMIT 1)",
				["spent", "live", "lost"][rng.gen_range(0..3)]),
			45..=54 => ("board", "UPDATE board SET state = $2::text::board_state WHERE leaf_id = (SELECT leaf_id FROM board
				ORDER BY leaf_id OFFSET $1 % greatest((SELECT count(*) FROM board), 1) LIMIT 1)",
				["credited", "pending"][rng.gen_range(0..2)]),
			55..=64 => ("participation", "UPDATE participation SET state = $2::text::participation_state,
				round_id = CASE WHEN $2 IN ('issued', 'released') THEN coalesce(round_id, (SELECT bl.round_id FROM batch_leaf bl
				  WHERE bl.participation_id = participation.participation_id LIMIT 1)) END WHERE participation_id = (
				SELECT participation_id FROM participation ORDER BY participation_id
				OFFSET $1 % greatest((SELECT count(*) FROM participation), 1) LIMIT 1)",
				["issued", "released", "void", "pending"][rng.gen_range(0..4)]),
			65..=74 => ("round", "UPDATE round SET state = $2 WHERE round_id = (SELECT round_id FROM round
				ORDER BY round_id OFFSET $1 % greatest((SELECT count(*) FROM round), 1) LIMIT 1)",
				["built", "broadcast", "final", "lost", "final"][rng.gen_range(0..5)]),
			75..=82 => ("coin given", "UPDATE participation_input SET active = ($2 = 'true') WHERE (participation_id, idx) = (
				SELECT participation_id, idx FROM participation_input ORDER BY participation_id, idx
				OFFSET $1 % greatest((SELECT count(*) FROM participation_input), 1) LIMIT 1)",
				["true", "false"][rng.gen_range(0..2)]),
			83..=92 => ("collection", "UPDATE batch SET collect_mtp = CASE WHEN $2 = 'set' THEN 1 END WHERE (round_id, vout) = (
				SELECT round_id, vout FROM batch ORDER BY round_id, vout OFFSET $1 % greatest((SELECT count(*) FROM batch), 1) LIMIT 1)",
				["set", "clear"][rng.gen_range(0..2)]),
			_ => ("forfeit gone", "DELETE FROM forfeit WHERE ($2 = $2) AND (leaf_id, round_id) = (SELECT leaf_id, round_id FROM forfeit
				ORDER BY leaf_id, round_id OFFSET $1 % greatest((SELECT count(*) FROM forfeit), 1) LIMIT 1)", "x"),
		};
		// A write a constraint refuses changes nothing; the next step goes on.
		match c.execute(sql, &[&pick, &arg]).await {
			Ok(n) => *applied.entry(what).or_insert(0) += n,
			Err(e) => *refused.entry(format!("{}: {}", what, e.as_db_error().map_or(e.to_string(), |d| d.message().to_string()))).or_insert(0) += 1,
		}
		let rows = check(&r, &format!("step {} ({} {})", step, what, arg)).await;
		for (i, n) in rows.iter().enumerate() {
			seen[i] += n;
			nonempty[i] += (*n > 0) as u64;
		}
	}
	println!("{} random writes; rows written by kind {:?}; refused {:?}", STEPS, applied, refused);
	println!("open rows seen by pass {:?}, checks with some open {:?}", seen, nonempty);
	for (i, pass) in PASSES.iter().enumerate() {
		assert!(nonempty[i] >= 3, "the {} pass had open items in few checks: {:?}", pass.name(), nonempty);
	}
}
