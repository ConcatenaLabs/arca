//! How long a refresh waits on the rounds when the operator has a history
//! behind it: batches whose lowest nodes hold fronted value, thousands of
//! rounds final and hundreds lost, and refreshes coming steadily. The server
//! runs its own loop at the public testnet's pace (a round interval of 60 s, a
//! block every 60 s, the chain polled every second, finality at certification
//! with `anchor_depth` 0), and a
//! wallet hands its forfeits over as soon as its round is built. The server's
//! log, at info, then carries the lines `op8_round_latency_read.sh` reads from
//! arcad's journal: each round built, broadcast, final at the nursery and
//! credited; and every step of the rounds that took longer than
//! [`server::rounds::SLOW_STEP`], with what its parts took.
//!
//! A measurement, run by hand, not in the suite:
//!
//! ```text
//! RUST_LOG=info ROUND_LATENCY_MINUTES=60 cargo test -p arca-server --test round_latency -- --ignored --nocapture
//! ```
//!
//! The operator serves `ROUND_LATENCY_ASSETS` assets (6 by default, as the
//! public testnet's does), two of them with channel leaves, and its wallet
//! holds `ROUND_LATENCY_WALLET_COINS` coins of each (1,500 by default; the
//! testnet's holds 1,600 to 2,100 of each of five). Y is over its in-flight
//! cap throughout, as tSEQ is on the public testnet: eight refreshes of it
//! wait, and every round interval reads the cap for them again. The others'
//! refreshes flow, one every 20 s, each asset in turn.
//!
//! `ROUND_LATENCY_HISTORY` scales the batches of the history (1 by default:
//! 50 rounds of 8 boards, then rounds of 30 giving up 300 of their leaves);
//! 5,000 rounds final and 300 lost are put beside them whatever the scale.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::time::{Duration, Instant};

use serde_json::Value;

use arca_covenant::CoinRecord;
use common::client::{made, participation_body, want_leaf, Held};
use common::flow::{refresh, Coin};
use common::keys::{keypair, xonly};
use common::rounds::{hand_over, status, VALUE};
use common::running::{Running, MIN_LEAF};
use elements::AssetId;
use server::server::AssetSection;

/// High enough that the cap never holds a refresh back, while every round
/// still reads it ([`server::rounds`]'s `within_cap`).
const CAP: u64 = 100_000_000_000_000;

fn env(name: &str, default: u64) -> u64 {
	std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// `n` credited boards in `asset`, twenty to a block.
async fn boards(r: &mut Running, asset: AssetId, n: usize, tag: &str) -> Vec<Coin> {
	let mut out = vec![];
	let mut waiting = vec![];
	for i in 0..n {
		let k = keypair(&format!("{} board {}", tag, i));
		let (record, tx, _) = r.board_in(&k, asset, VALUE);
		waiting.push((k, record, tx));
		if waiting.len() == 20 || i + 1 == n {
			r.produce().await;
			r.bury().await;
			for (k, record, tx) in waiting.drain(..) {
				let id = record.leaf_id();
				let http = r.http.clone();
				r.wait("a board to be credited", || http.board_status(&id).json["state"] == "credited").await;
				out.push(Coin { held: Held { key: k, nonce: record.owner_nonce, id, record: CoinRecord::Board(record) }, bases: vec![tx] });
			}
		}
	}
	out
}

/// Clones the first final round `final_n` times as final, each in the block
/// that holds it, and `lost_n` times as lost: what a pass over the rounds
/// reads of an operator that has run thousands of rounds.
async fn clone_rounds(r: &Running, final_n: i64, lost_n: i64) {
	let (client, conn) = tokio_postgres::connect(&r.db.url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(async move {
		let _ = conn.await;
	});
	client.batch_execute(&format!("
		CREATE TEMP TABLE clone AS SELECT n,
		  decode(md5('t' || n || random()) || md5('u' || n || random()), 'hex') AS txid,
		  decode(md5('c' || n || random()) || md5('d' || n || random()), 'hex') AS casset,
		  n <= {f} AS fin FROM generate_series(1, {t}) n;
		INSERT INTO round (txid, tx, state, fee_asset, fee, created_mtp, final_mtp)
		  SELECT c.txid, s.tx, CASE WHEN c.fin THEN 'final' ELSE 'lost' END, s.fee_asset, s.fee, s.created_mtp,
		         CASE WHEN c.fin THEN s.final_mtp END
		  FROM clone c, (SELECT * FROM round WHERE state = 'final' ORDER BY round_id LIMIT 1) s;
		INSERT INTO connector_output (round_id, vout, asset, value, connector_asset)
		  SELECT r.round_id, s.vout, s.asset, s.value, c.casset FROM clone c JOIN round r ON r.txid = c.txid,
		  (SELECT * FROM connector_output ORDER BY round_id LIMIT 1) s;
		INSERT INTO watched_tx (txid, kind) SELECT txid, 'round' FROM clone WHERE fin;
		INSERT INTO tx_block (txid, block_hash) SELECT c.txid, b.block_hash FROM clone c,
		  (SELECT t.block_hash FROM tx_block t JOIN round r ON r.txid = t.txid WHERE r.state = 'final' ORDER BY r.round_id LIMIT 1) b
		  WHERE c.fin;", f = final_n, t = final_n + lost_n)).await.unwrap();
	let rows = client.query("SELECT state, count(*) FROM round GROUP BY state ORDER BY state", &[]).await.unwrap();
	let counts: Vec<String> = rows.iter().map(|r| format!("{} {}", r.get::<_, String>(0), r.get::<_, i64>(1))).collect();
	println!("history: rounds {}", counts.join(", "));
}

fn median(v: &mut [f64]) -> f64 {
	v.sort_by(|a, b| a.partial_cmp(b).unwrap());
	if v.is_empty() { 0.0 } else { v[v.len() / 2] }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "a measurement of an hour, run by hand"]
async fn refreshes_wait_on_rounds_with_a_history_behind_them() {
	let scale = env("ROUND_LATENCY_HISTORY", 1) as usize;
	let minutes = env("ROUND_LATENCY_MINUTES", 10);
	let mut r = Running::start_with(|c, y| {
		c.batches.no_sweep = true;
		c.finality.anchor_depth = 0;
		c.assets[0].in_flight_cap = Some(CAP.to_string());
		let mut ys = AssetSection::new(y, MIN_LEAF);
		ys.in_flight_cap = Some(CAP.to_string());
		c.assets.push(ys);
	}).await;
	let (x, y) = (r.x, r.y);
	for i in 0..10 * scale + 2 {
		r.fund_wallet_in(if i < 10 * scale { x } else { y }, 300_000_000).await;
		if i % 10 == 9 {
			r.produce().await;
		}
	}
	// The other assets, the first two with channel leaves.
	let mut others = vec![];
	for k in 0..env("ROUND_LATENCY_ASSETS", 6).saturating_sub(2) {
		let a = tokio::task::block_in_place(|| r.purse.issue(&r.rt, &format!("asset O{}", k), 100_000_000_000));
		let mut sec = AssetSection::new(a, MIN_LEAF);
		sec.in_flight_cap = Some(CAP.to_string());
		if k < 2 {
			sec.channel_capacity = Some("500000".into());
		}
		r.config.assets.push(sec);
		others.push(a);
	}
	r.restart_server().await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	// The wallet's coins: as many of each asset as the testnet's holds.
	let per = env("ROUND_LATENCY_WALLET_COINS", 1_500) as usize;
	let mut paid = 0;
	for a in [x, y].iter().chain(others.iter()) {
		let mut left = per;
		while left > 0 {
			let n = left.min(250);
			let mut outs = vec![];
			for _ in 0..n {
				let to = r.server.wallet.receive_script().await.unwrap();
				outs.push(sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(*a, 2_000_000), to));
			}
			tokio::task::block_in_place(|| r.purse.pay(&r.rt, outs));
			left -= n;
			paid += 1;
			if paid % 5 == 0 {
				r.produce().await;
			}
		}
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	println!("history: {} assets, {} wallet coins of each", 2 + others.len(), per);

	// The history: 50 rounds of 8 boards each, then 10 rounds giving up 300
	// of their leaves, which leaves their nodes holding fronted value.
	let t = Instant::now();
	let mut leaves = vec![];
	for b in 0..50 * scale {
		let coins = boards(&mut r, x, 8, &format!("H{}", b)).await;
		let keys: Vec<_> = (0..coins.len()).map(|i| keypair(&format!("H{} leaf {}", b, i))).collect();
		let pairs: Vec<(&Coin, &_)> = coins.iter().zip(keys.iter()).collect();
		for x in refresh(&mut r, &pairs).await {
			leaves.push(x.new);
		}
	}
	println!("history: {} leaves in {} rounds, {:.0} s", leaves.len(), 50 * scale, t.elapsed().as_secs_f64());
	let given: Vec<Coin> = leaves.into_iter().enumerate().filter(|(i, _)| i % 8 < 6).map(|(_, c)| c).collect();
	let mut flow = vec![];
	for (k, chunk) in given.chunks(30).enumerate() {
		let keys: Vec<_> = (0..chunk.len()).map(|i| keypair(&format!("G{} leaf {}", k, i))).collect();
		let pairs: Vec<(&Coin, &_)> = chunk.iter().zip(keys.iter()).collect();
		for x in refresh(&mut r, &pairs).await {
			flow.push(x.new);
		}
	}
	// Leaves of the other assets for the flow: 5 rounds of 8 boards each.
	let mut other_leaves: Vec<Vec<Coin>> = vec![];
	for (k, a) in others.iter().enumerate() {
		let mut mine = vec![];
		for b in 0..5 {
			let coins = boards(&mut r, *a, 8, &format!("O{} {}", k, b)).await;
			let keys: Vec<_> = (0..coins.len()).map(|i| keypair(&format!("O{} {} leaf {}", k, b, i))).collect();
			let pairs: Vec<(&Coin, &_)> = coins.iter().zip(keys.iter()).collect();
			for x in refresh(&mut r, &pairs).await {
				mine.push(x.new);
			}
		}
		other_leaves.push(mine);
	}
	// The flow takes each flowing asset in turn.
	let mut lanes: Vec<std::vec::IntoIter<Coin>> = vec![flow.into_iter()];
	lanes.extend(other_leaves.into_iter().map(|v| v.into_iter()));
	let mut flow = vec![];
	loop {
		let before = flow.len();
		for l in lanes.iter_mut() {
			if let Some(c) = l.next() {
				flow.push(c);
			}
		}
		if flow.len() == before {
			break;
		}
	}
	let p: Value = r.http.get("chain").json["pool"][x.to_string()].clone();
	println!("history: {} leaves given up, in flight {}, {:.0} s", given.len(), p["in_flight"], t.elapsed().as_secs_f64());
	// Y, as tSEQ on the public testnet: over its in-flight cap from the
	// flow on, so its refreshes wait, and every round interval reads the
	// cap for them again. 10 rounds of 8 boards, 40 of their leaves given up.
	let mut y_leaves = vec![];
	for b in 0..10 {
		let coins = boards(&mut r, y, 8, &format!("Y{}", b)).await;
		let keys: Vec<_> = (0..coins.len()).map(|i| keypair(&format!("Y{} leaf {}", b, i))).collect();
		let pairs: Vec<(&Coin, &_)> = coins.iter().zip(keys.iter()).collect();
		for x in refresh(&mut r, &pairs).await {
			y_leaves.push(x.new);
		}
	}
	let (y_given, y_wait): (Vec<(usize, Coin)>, Vec<(usize, Coin)>) = y_leaves.into_iter().enumerate().partition(|(i, _)| i % 2 == 0);
	for (k, chunk) in y_given.chunks(20).enumerate() {
		let keys: Vec<_> = (0..chunk.len()).map(|i| keypair(&format!("YG{} leaf {}", k, i))).collect();
		let pairs: Vec<(&Coin, &_)> = chunk.iter().map(|(_, c)| c).zip(keys.iter()).collect();
		refresh(&mut r, &pairs).await;
	}
	clone_rounds(&r, 5_000, 300).await;

	// The flow: the server's own loop at the testnet's pace.
	r.config.round_interval_seconds = 60;
	r.config.finality.poll_interval_ms = 1_000;
	r.config.assets[1].in_flight_cap = Some(VALUE.to_string());
	r.restart_server().await;
	r.synced().await;
	// Eight refreshes of Y, which wait for the cap throughout.
	for (_, c) in y_wait.iter().take(8) {
		let k = keypair(&format!("YW {}", c.held.id));
		let (w, _) = want_leaf(&k, y, VALUE);
		let (body, _) = participation_body(&[&c.held], &[w], &[], None, xonly(&r.s), r.chain);
		assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	}
	println!("flow: {} minutes, a refresh every 20 s, a block every 60 s, a round interval of 60 s", minutes);
	let start = Instant::now();
	let end = start + Duration::from_secs(minutes * 60);
	let (mut next_submit, mut next_block, mut blocks) = (start, start + Duration::from_secs(60), 0u64);
	let mut coins = flow.into_iter();
	// Each refresh: its id, when it was accepted, when its forfeits went in.
	let mut open: Vec<([u8; 32], Instant, Option<Instant>)> = vec![];
	let (mut waited, mut handed, mut done) = (vec![], vec![], 0usize);
	while Instant::now() < end || !open.is_empty() {
		let now = Instant::now();
		if now >= next_submit && now < end {
			if let Some(c) = coins.next() {
				let k = keypair(&format!("F {}", c.held.id));
				let asset = c.valid(&r).asset;
				let (w, _) = want_leaf(&k, asset, VALUE);
				let (body, id) = participation_body(&[&c.held], &[w], &[], None, xonly(&r.s), r.chain);
				let a = r.http.post("submit_participation", &body).ok();
				assert_eq!(a["state"], "pending", "{}", a);
				open.push((id, now, None));
			}
			next_submit += Duration::from_secs(20);
		}
		let mut k = 0;
		while k < open.len() {
			let (id, at, forfeits) = open[k];
			let st = status(&r, &id);
			match st["state"].as_str().unwrap_or("") {
				"issued" if forfeits.is_none() => {
					hand_over(&r, &id, &made(&id).unwrap()).await;
					handed.push((Instant::now() - at).as_secs_f64());
					open[k].2 = Some(Instant::now());
				},
				"released" => {
					waited.push((Instant::now() - at).as_secs_f64());
					done += 1;
					open.remove(k);
					continue;
				},
				"void" | "expired" => panic!("refresh {} is {}: {}", common::client::hex(&id), st["state"], st),
				_ => {},
			}
			k += 1;
		}
		if now >= next_block {
			r.produce().await;
			blocks += 1;
			if blocks % 10 == 0 {
				r.bury().await;
			}
			next_block += Duration::from_secs(60);
		}
		assert!(Instant::now() < end + Duration::from_secs(1800), "refreshes still open half an hour after the flow ended");
		tokio::time::sleep(Duration::from_millis(500)).await;
	}
	let (mh, mw) = (median(&mut handed), median(&mut waited));
	let max = waited.iter().cloned().fold(0.0, f64::max);
	println!("flow: {} refreshes released; accepted → forfeits in: median {:.0} s; accepted → released (credited): median {:.0} s, max {:.0} s",
		done, mh, mw, max);
}
