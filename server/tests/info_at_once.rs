//! The operator's `info`, which every wallet, maker and tool reads before it
//! acts, answers at once whatever its node and its database are doing.
//!
//! The server runs on its own, its watcher and nursery acting as they follow
//! the chain, while a round refreshes two holders' boards. Meanwhile:
//!
//! - its node takes [`NODE_STALL`] to answer each call `info` makes of it
//!   (`getmempoolinfo` and `getfeeexchangerates`, the floors), as a node on a
//!   saturated disk does;
//! - another connection holds every table `info` reads (what is owed, the
//!   wallet's coins, the signer's head, the participations' inputs) under an
//!   exclusive lock, for [`LOCK_HOLD`] at a time, as a long write does.
//!
//! `info` is read 100 times in a row, over longer than any part of it is
//! kept, and answers each time within [`AT_ONCE`]. What it publishes stays
//! true: its signer head is never below the latest entry the server handed
//! out, and once the stalls end its parts are read again.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use elements::secp256k1_zkp::Keypair;

use common::flow::{refresh, Coin};
use common::keys::keypair;
use common::rounds::credited_board;
use common::running::{Running, MIN_LEAF};

/// How long the node takes over each call `info` makes of it while it stalls.
const NODE_STALL: Duration = Duration::from_secs(3);
/// How long the other connection holds the tables at a time.
const LOCK_HOLD: Duration = Duration::from_secs(3);
/// What "at once" means for `info`.
const AT_ONCE: Duration = Duration::from_millis(100);

/// Whether the node stalls.
static STALL: AtomicBool = AtomicBool::new(false);

/// A proxy in front of the node's RPC at `upstream`: a request naming a call
/// `info` makes waits [`NODE_STALL`] before it goes on while [`STALL`] is
/// set. Returns its port.
fn stalling_proxy(upstream: u16) -> u16 {
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let port = listener.local_addr().unwrap().port();
	std::thread::spawn(move || {
		for client in listener.incoming().flatten() {
			std::thread::spawn(move || {
				let Ok(node) = TcpStream::connect(("127.0.0.1", upstream)) else { return };
				let (mut from_node, mut to_client) = (node.try_clone().unwrap(), client.try_clone().unwrap());
				std::thread::spawn(move || {
					let _ = std::io::copy(&mut from_node, &mut to_client);
					let _ = to_client.shutdown(std::net::Shutdown::Both);
				});
				let (mut from_client, mut to_node) = (client, node);
				let mut buf = vec![0u8; 64 * 1024];
				loop {
					let n = match from_client.read(&mut buf) {
						Ok(0) | Err(_) => break,
						Ok(n) => n,
					};
					let chunk = String::from_utf8_lossy(&buf[..n]);
					if STALL.load(Ordering::SeqCst) && (chunk.contains("getmempoolinfo") || chunk.contains("getfeeexchangerates")) {
						std::thread::sleep(NODE_STALL);
					}
					if to_node.write_all(&buf[..n]).is_err() {
						break;
					}
				}
				let _ = to_node.shutdown(std::net::Shutdown::Both);
			});
		}
	});
	port
}

/// Holds the tables `info` reads under an exclusive lock, [`LOCK_HOLD`] at a
/// time with a moment between, until `stop`. A lock not taken within 200 ms
/// is let go and asked for again, so the holder never waits on the server
/// while it holds a table the server waits for. Returns how many holds it
/// made.
async fn hold_tables(url: String, stop: Arc<AtomicBool>) -> usize {
	let (client, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(async move {
		let _ = conn.await;
	});
	let mut holds = 0;
	while !stop.load(Ordering::SeqCst) {
		client.batch_execute("BEGIN; SET LOCAL lock_timeout = '200ms'").await.unwrap();
		match client.batch_execute("LOCK TABLE owed, owed_sweep, wallet_coin, signer_head, participation_input IN ACCESS EXCLUSIVE MODE").await {
			Ok(()) => {
				holds += 1;
				tokio::time::sleep(LOCK_HOLD).await;
			},
			Err(_) => {},
		}
		client.batch_execute("ROLLBACK").await.unwrap();
		tokio::time::sleep(Duration::from_millis(300)).await;
	}
	holds
}

async fn board_coin(r: &mut Running, key: &Keypair) -> Coin {
	let (held, tx) = credited_board(r, key, r.x).await;
	Coin { held, bases: vec![tx] }
}

#[tokio::test(flavor = "multi_thread")]
async fn info_answers_at_once_while_the_node_stalls_and_its_tables_are_held() {
	let mut r = Running::start_with(|c, y| {
		let mut ay = server::server::AssetSection::new(y, MIN_LEAF);
		ay.in_flight_cap = Some("1000000000".into());
		c.assets.push(ay);
		c.assets[0].in_flight_cap = Some("1000000000".into());
		c.watcher.enabled = true;
		let node: u16 = c.node.rpc_url.trim_end_matches('/').rsplit(':').next().unwrap().parse().unwrap();
		c.node.rpc_url = format!("http://127.0.0.1:{}/", stalling_proxy(node));
	}).await;
	let (x, y) = (r.x, r.y);
	for asset in [x, x, x, y] {
		r.fund_wallet_in(asset, 50_000_000).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let (a, b) = (keypair("info at once A"), keypair("info at once B"));
	let ca = board_coin(&mut r, &a).await;
	let cb = board_coin(&mut r, &b).await;

	let first = r.http.get("info");
	assert_eq!(first.status, 200);
	println!("info before the stalls: floors {}, signer record at {}", first.json["fees"]["floors"], first.json["signer_record"]["entry"]);

	STALL.store(true, Ordering::SeqCst);
	let stop = Arc::new(AtomicBool::new(false));
	let holder = tokio::spawn(hold_tables(r.config.database.clone(), stop.clone()));
	// Reads in a row, 150 ms apart, until the round is done and at least 100
	// were made: longer than any part of `info` is kept (10 s at the most),
	// each part read again under the stalls more than once, the signer's
	// record moving on meanwhile.
	let (http, store, round_done) = (r.http.clone(), r.server.store.clone(), Arc::new(AtomicBool::new(false)));
	let done = round_done.clone();
	let reads = tokio::task::spawn_blocking(move || {
		(0..).take_while(|i| *i < 100 || !done.load(Ordering::SeqCst)).map(|_| {
			let handed_out = store.signer_head_seen();
			let t = Instant::now();
			let a = http.get("info");
			let took = t.elapsed();
			assert_eq!(a.status, 200, "{}", a.json);
			std::thread::sleep(Duration::from_millis(150));
			(took, a.json, handed_out)
		}).collect::<Vec<_>>()
	});
	// A round meanwhile, through the stalls and the held tables.
	let t = Instant::now();
	let (a2, b2) = (keypair("info at once A, refreshed"), keypair("info at once B, refreshed"));
	let refreshed = refresh(&mut r, &[(&ca, &a2), (&cb, &b2)]).await;
	println!("a round refreshed {} boards under the stalls in {:.1} s", refreshed.len(), t.elapsed().as_secs_f64());
	// The round hands its heads out at its end: the reads go on a little
	// longer, past the head's period, to see them.
	tokio::time::sleep(Duration::from_secs(3)).await;
	round_done.store(true, Ordering::SeqCst);
	let reads = reads.await.unwrap();
	stop.store(true, Ordering::SeqCst);
	let holds = holder.await.unwrap();
	STALL.store(false, Ordering::SeqCst);

	let mut times: Vec<Duration> = reads.iter().map(|(t, _, _)| *t).collect();
	let slow: Vec<String> = times.iter().filter(|t| **t >= AT_ONCE).map(|t| format!("{} ms", t.as_millis())).collect();
	times.sort();
	let n = times.len();
	println!("info, {} reads in a row under {} hold(s) of its tables and the node's stalls: median {} ms, slowest {} ms; {} of {} \
		at {} ms or more {:?}", n, holds, times[n / 2].as_micros() as f64 / 1000.0, times[n - 1].as_micros() as f64 / 1000.0, slow.len(),
		n, AT_ONCE.as_millis(), slow);
	assert!(n >= 100);
	assert!(holds >= 3, "the tables were held under the reads");
	assert!(slow.is_empty(), "every read answered within {} ms", AT_ONCE.as_millis());

	// What it published stayed true: its signer head never below the latest
	// entry handed out when the read began.
	for (i, (_, v, handed_out)) in reads.iter().enumerate() {
		let shown = v["signer_record"]["entry"].as_u64();
		assert!(shown.is_some_and(|e| e >= *handed_out), "read {}: info shows the signer's record at {:?}, below entry {} handed out",
			i, shown, handed_out);
	}
	let heads: Vec<u64> = reads.iter().filter_map(|(_, v, _)| v["signer_record"]["entry"].as_u64()).collect();
	println!("the signer record info showed, read by read: {:?}", heads);
	assert!(heads.last() > heads.first(), "the signer's record moved on during the reads");
	let handed_out = r.server.store.signer_head().await.unwrap().map(|h| h.0).unwrap_or(0);
	let fresh = r.http.get("info").json;
	assert!(fresh["signer_record"]["entry"].as_u64().unwrap() >= handed_out, "info shows no head below one handed out: {}",
		fresh["signer_record"]);
	// Once the stalls end, the floors are read again.
	let start = Instant::now();
	loop {
		let v = r.http.get("info").json;
		if v["fees"]["floors"].is_array() {
			println!("after the stalls: floors {} ({:.1} s)", v["fees"]["floors"], start.elapsed().as_secs_f64());
			break;
		}
		assert!(start.elapsed() < Duration::from_secs(30), "the floors are read again once the node answers");
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
}
