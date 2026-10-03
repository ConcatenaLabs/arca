//! What the calls anyone may make without proving a key leave behind: review
//! R7's load (P3, P3b) turned around. A board is registered only once the
//! node takes its transaction, so junk boards leave no row and nothing in
//! the nursery; operator nonces are handed out at a bounded rate and deleted
//! once expired; a challenge is checked, never stored, and leaves no row;
//! and a board the node took that never confirms is dropped after a set
//! time. A few sources asking as fast as they can leave an honest caller
//! every challenge and every nonce it asks for.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::time::{Duration, Instant};

use elements::hashes::Hash;
use elements::{OutPoint, Sequence, Transaction, Txid};
use serde_json::json;

use common::client::{board_record, random32};
use common::keys::{keypair, xonly};
use common::node::{op_true, spend_op_true};
use common::rounds::VALUE;
use common::running::Running;
use server::server::LimitsSection;
use server::store::{BoardState, NurseryState};

const PER_SECOND: u32 = 20;
const BURST: u32 = 60;
const TTL: u64 = 3;

/// The rows the unauthenticated calls could leave: nonces, leaves, boards,
/// and the nursery's transactions. A challenge has no table.
async fn rows(r: &Running) -> [i64; 4] {
	let (client, conn) = tokio_postgres::connect(&r.config.database, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(conn);
	let row = client.query_one(
		"SELECT (SELECT count(*) FROM operator_nonce), (SELECT count(*) FROM leaf), (SELECT count(*) FROM board),
		        (SELECT count(*) FROM nursery_tx)", &[]).await.unwrap();
	[row.get(0), row.get(1), row.get(2), row.get(3)]
}

/// The mean time of `n` nursery passes.
async fn nursery_pass(r: &Running, n: u32) -> Duration {
	let t = Instant::now();
	for _ in 0..n {
		r.server.nursery.pass().await.unwrap();
	}
	t.elapsed() / n
}

/// A board record, and a transaction paying it from an input that does not
/// exist.
fn junk_board(r: &Running, i: u32, nonce: [u8; 32]) -> (arca_covenant::BoardRecord, Transaction) {
	let owner = keypair(&format!("junk {}", i));
	let record = board_record(&owner, nonce, r.x, VALUE, r.chain, xonly(&r.s));
	let mut b = [0u8; 32];
	b[..4].copy_from_slice(&(i + 1).to_le_bytes());
	let fake = (OutPoint::new(Txid::from_byte_array(b), 0),
		sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(r.x, VALUE + 10_000), op_true()));
	let tx = record.tx(std::slice::from_ref(&fake), r.x, 2_000, &op_true()).unwrap().tx;
	(record, tx)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_reviewers_load_leaves_no_rows() {
	let r = Running::start_with(|c, _| {
		c.limits = LimitsSection {
			issue_per_second: PER_SECOND, issue_burst: BURST, nonce_ttl_seconds: TTL, board_unconfirmed_seconds: 6 * 3600,
			// One caller here: its own bound is the overall one.
			source_per_second: PER_SECOND, source_burst: BURST, trusted_proxies: vec!["127.0.0.1".into()],
			// The test deletes what expired itself, when it wants to.
			cleanup_interval_seconds: 3600,
		};
		c.challenge_ttl_seconds = TTL;
	}).await;
	r.synced().await;
	let before = nursery_pass(&r, 5).await;
	let start = rows(&r).await;
	println!("before the load: nursery pass {:?}; rows nonce|leaf|board|nursery = {:?}", before, start);

	// P3: 50 junk boards, each with a nonce of the operator's.
	for i in 0..50u32 {
		let nonce = r.http.operator_nonce();
		let (record, tx) = junk_board(&r, i, nonce);
		let a = r.http.register_board(&record, &tx);
		assert_eq!((a.status, a.refusal().0.as_str()), (422, "not_accepted"), "{}", a.json);
		assert!(a.refusal().1.contains("missing-inputs"), "refused for its missing input: {}", a.refusal().1);
		if i == 0 {
			println!("junk board 0: {} {}", a.status, a.json);
		}
	}
	// P3b: 500 more, as fast as they go: a nonce when the rate gives one,
	// else one the operator never issued.
	let t = Instant::now();
	let mut refused = std::collections::BTreeMap::<String, u32>::new();
	for i in 50..550u32 {
		let n = r.http.post("operator_nonce", &json!({}));
		let nonce = if n.status == 200 {
			common::client::unhex(n.json["operator_nonce"].as_str().unwrap()).try_into().unwrap()
		} else {
			assert_eq!((n.status, n.refusal().0.as_str()), (429, "rate_limited"), "{}", n.json);
			random32()
		};
		let (record, tx) = junk_board(&r, i, nonce);
		let a = r.http.register_board(&record, &tx);
		assert_ne!(a.status, 200, "a junk board is never registered: {}", a.json);
		*refused.entry(a.refusal().0).or_default() += 1;
	}
	println!("500 more junk boards in {:?}, every one refused: {:?}", t.elapsed(), refused);

	// 1,000 nonces and 1,000 challenges, as fast as they go: the nonces
	// within the rate, every challenge handed out, none stored.
	let t = Instant::now();
	let (mut nonces, mut challenges) = (0u32, 0u32);
	for _ in 0..1000 {
		let a = r.http.post("operator_nonce", &json!({}));
		match a.status {
			200 => nonces += 1,
			_ => assert_eq!((a.status, a.refusal().0.as_str()), (429, "rate_limited"), "{}", a.json),
		}
	}
	let spent = t.elapsed();
	for _ in 0..1000 {
		let a = r.http.post("challenge", &json!({}));
		assert_eq!(a.status, 200, "{}", a.json);
		challenges += 1;
	}
	let bound = BURST + (spent.as_secs_f64() * f64::from(PER_SECOND)).ceil() as u32 + 1;
	println!("1,000 nonce requests in {:?}: {} handed out (bound {}); 1,000 challenge requests: {} handed out",
		spent, nonces, bound, challenges);
	assert!(nonces <= bound, "the rate holds");

	for _ in 0..3 {
		r.produce().await;
		r.synced().await;
		r.server.nursery.pass().await.unwrap();
		r.server.boards.pass().await.unwrap();
	}
	let after_load = rows(&r).await;
	println!("after the load: rows nonce|leaf|board|nursery = {:?}", after_load);
	assert_eq!(after_load[2..], start[2..], "no leaf, board or nursery row");

	// Once expired, the nonces are deleted.
	tokio::time::sleep(Duration::from_secs(TTL + 1)).await;
	let n = r.server.store.delete_expired(Duration::from_secs(TTL)).await.unwrap();
	let end = rows(&r).await;
	let after = nursery_pass(&r, 5).await;
	println!("deleted {} nonces; rows nonce|leaf|board|nursery = {:?}; nursery pass {:?} (before the load {:?})",
		n, end, after, before);
	assert_eq!(end, [0, start[1], start[2], start[3]], "the load leaves no row");
	assert!(after < before * 5 + Duration::from_millis(20), "the nursery pass is not slower: {:?} against {:?}", after, before);
}

/// A board the node took whose transaction then loses its parent: it can
/// never confirm, and no final transaction spends its own input, so only
/// the timer drops it.
#[tokio::test(flavor = "multi_thread")]
async fn a_board_that_never_confirms_is_dropped() {
	let mut r = Running::start_with(|c, _| {
		c.limits = LimitsSection {
			board_unconfirmed_seconds: 2, issue_per_second: 1000, issue_burst: 1000, source_per_second: 1000, source_burst: 1000,
			..Default::default()
		};
	}).await;
	let x = r.x;
	// A parent that signals replacement, paying an output the board spends.
	let coin = r.purse.take_coin(x);
	let mut parent = spend_op_true(&coin, vec![sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(x, VALUE + 10_000), op_true())], 5_000);
	parent.input[0].sequence = Sequence(0xffff_fffd);
	r.rt.client().send_raw_transaction(&parent).unwrap();
	let nonce = r.http.operator_nonce();
	let record = board_record(&keypair("never confirms"), nonce, x, VALUE, r.chain, xonly(&r.s));
	let paid = (OutPoint::new(parent.txid(), 0), parent.output[0].clone());
	let tx = record.tx(std::slice::from_ref(&paid), x, 2_000, &op_true()).unwrap().tx;
	let a = r.http.register_board(&record, &tx);
	assert_eq!(a.status, 200, "the node takes it: {}", a.json);
	// The parent is replaced: the board transaction goes with it.
	let replacement = spend_op_true(&coin, vec![], 50_000);
	r.rt.client().send_raw_transaction(&replacement).unwrap();
	r.purse.put((OutPoint::new(replacement.txid(), 0), replacement.output[0].clone()));
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.server.nursery.pass().await.unwrap();
	let n = r.server.store.nursery_get(&tx.txid().to_byte_array()).await.unwrap().unwrap();
	println!("the board's transaction after its parent was replaced: {:?}, last result {:?}", n.state, n.last_result);
	assert_eq!(n.state, NurseryState::Pending, "no final transaction spends its own input: the nursery alone never loses it");
	tokio::time::sleep(Duration::from_secs(3)).await;
	r.server.boards.pass().await.unwrap();
	let b = r.server.store.board(&record.leaf_id().0).await.unwrap().unwrap();
	let n = r.server.store.nursery_get(&tx.txid().to_byte_array()).await.unwrap().unwrap();
	println!("after the set time: board {:?}, its transaction {:?}", b.state, n.state);
	assert_eq!((b.state, n.state), (BoardState::Lost, NurseryState::Lost));
	assert_eq!(r.http.board_status(&record.leaf_id()).ok()["state"], "lost");
}

/// Review R7b's probe P6 turned around: the nonces anyone may ask for are
/// bounded for each source, so a stranger asking as fast as it can leaves an
/// honest wallet its share; a challenge, stored nowhere, is handed to every
/// caller. The server sits behind a proxy on this machine, which names each
/// request's source in `X-Forwarded-For`; a request that does not come from a
/// trusted proxy is counted against the address that connected, whatever it
/// claims.
#[tokio::test(flavor = "multi_thread")]
async fn one_caller_cannot_use_up_what_every_caller_needs() {
	use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
	use std::sync::Arc;

	fn ask(base: &str, call: &str, from: &str) -> i32 {
		minreq::post(format!("{}/v1/{}", base, call)).with_header("Content-Type", "application/json")
			.with_header("X-Forwarded-For", from).with_body("{}").with_timeout(5).send().map(|r| r.status_code).unwrap_or(0)
	}

	/// A stranger asking about 100 times a second for each call, from
	/// `from` (a function of the request's number), for as long as `body`
	/// runs; how many nonces it got.
	async fn hammered<F, B, T>(base: &str, from: F, body: B) -> (T, usize, usize, u64)
	where
		F: Fn(usize) -> String + Send + Sync + 'static,
		B: std::future::Future<Output = T>,
	{
		let stop = Arc::new(AtomicBool::new(false));
		let (sent, given) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
		let from = Arc::new(from);
		let began = Instant::now();
		let mut hammers = vec![];
		for call in ["challenge", "operator_nonce"] {
			let (base, stop, sent, given, from) = (base.to_string(), stop.clone(), sent.clone(), given.clone(), from.clone());
			hammers.push(std::thread::spawn(move || {
				while !stop.load(Ordering::SeqCst) {
					let n = sent.fetch_add(1, Ordering::SeqCst);
					if ask(&base, call, &from(n)) == 200 && call == "operator_nonce" {
						given.fetch_add(1, Ordering::SeqCst);
					}
					std::thread::sleep(Duration::from_millis(10));
				}
			}));
		}
		let out = body.await;
		stop.store(true, Ordering::SeqCst);
		for h in hammers {
			h.join().unwrap();
		}
		(out, sent.load(Ordering::SeqCst), given.load(Ordering::SeqCst), began.elapsed().as_secs() + 1)
	}

	// The defaults: nonces at 1 a second for each source, with bursts of 10,
	// within a high bound overall. The proxy is on this machine.
	let r = Running::start_with(|c, _| c.limits = LimitsSection::default()).await;
	let base = r.http.base.clone();
	let ((ok, limited), sent, given, secs) = hammered(&base, |_| "203.0.113.7".to_string(), async {
		// Let the stranger's burst, and everyone's, drain first.
		tokio::time::sleep(Duration::from_secs(12)).await;
		let (mut ok, mut limited) = ((0, 0), (0, 0));
		for _ in 0..20 {
			for (k, call) in ["challenge", "operator_nonce"].iter().enumerate() {
				match tokio::task::block_in_place(|| ask(&base, call, "198.51.100.9")) {
					200 => if k == 0 { ok.0 += 1 } else { ok.1 += 1 },
					429 => if k == 0 { limited.0 += 1 } else { limited.1 += 1 },
					s => panic!("{} answered {}", call, s),
				}
			}
			tokio::time::sleep(Duration::from_millis(1000)).await;
		}
		(ok, limited)
	}).await;
	println!("P6 a stranger asking about 100/s for each through the proxy (sent {}, nonces given {}); an honest wallet asking once a \
		second for 20 s: challenges {} given, {} rate_limited; nonces {} given, {} rate_limited", sent, given, ok.0, limited.0, ok.1, limited.1);
	assert_eq!((ok, limited), ((20, 20), (0, 0)), "the honest wallet gets every one it asks for");
	// Its own burst of 10 and one a second.
	assert!(given as u64 <= 10 + secs, "the stranger gets its own share of nonces and no more: {} of {} in {} s", given, sent, secs);

	// No proxy trusted: a caller that names a new source in every request is
	// still one source, the address that connected.
	drop(r);
	let r = Running::start_with(|c, _| c.limits = LimitsSection { trusted_proxies: vec!["192.0.2.1".into()], ..LimitsSection::default() })
		.await;
	let base = r.http.base.clone();
	let (_, sent, given, secs) = hammered(&base, |n| format!("198.51.{}.{}", (n / 250) % 250, n % 250), async {
		tokio::time::sleep(Duration::from_secs(5)).await;
	}).await;
	println!("P6 a caller naming a new source in every request, from no trusted proxy, for 5 s: nonces given {} of {}", given, sent);
	assert!(given as u64 <= 10 + secs, "counted against the address that connected: {} of {} in {} s", given, sent, secs);
}

/// Review R7c's probe L1 turned around. Six sources, each asking for a
/// challenge and a nonce every 10 ms through the proxy, each held to its own
/// rate: with a challenge checked rather than stored there is no budget they
/// share, and the overall bound on nonces lies far above six sources' rates.
/// An honest caller from a seventh source, asking once a second for 30 s, gets
/// every challenge and every nonce it asks for.
#[tokio::test(flavor = "multi_thread")]
async fn a_few_sources_leave_an_honest_caller_served() {
	use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
	use std::sync::Arc;

	fn ask(base: &str, call: &str, from: &str) -> i32 {
		minreq::post(format!("{}/v1/{}", base, call)).with_header("Content-Type", "application/json")
			.with_header("X-Forwarded-For", from).with_body("{}").with_timeout(5).send().map(|r| r.status_code).unwrap_or(0)
	}

	let r = Running::start_with(|c, _| c.limits = LimitsSection::default()).await;
	let base = r.http.base.clone();
	let d = LimitsSection::default();
	println!("defaults: nonces overall {}/s burst {}; per source {}/s burst {}; trusted proxies {:?}",
		d.issue_per_second, d.issue_burst, d.source_per_second, d.source_burst, d.trusted_proxies);
	let sources: Vec<String> = (1..=6).map(|i| format!("203.0.113.{}", i)).collect();
	let stop = Arc::new(AtomicBool::new(false));
	let (given, sent) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
	let mut hammers = vec![];
	for s in &sources {
		for call in ["challenge", "operator_nonce"] {
			let (base, stop, given, sent, s) = (base.clone(), stop.clone(), given.clone(), sent.clone(), s.clone());
			hammers.push(std::thread::spawn(move || {
				while !stop.load(Ordering::SeqCst) {
					sent.fetch_add(1, Ordering::SeqCst);
					if ask(&base, call, &s) == 200 {
						given.fetch_add(1, Ordering::SeqCst);
					}
					std::thread::sleep(Duration::from_millis(10));
				}
			}));
		}
	}
	// Every source's own burst used up first.
	tokio::time::sleep(Duration::from_secs(15)).await;
	let t = Instant::now();
	let (mut ok, mut limited) = ([0u32; 2], [0u32; 2]);
	for _ in 0..30 {
		for (k, call) in ["challenge", "operator_nonce"].iter().enumerate() {
			match tokio::task::block_in_place(|| ask(&base, call, "198.51.100.9")) {
				200 => ok[k] += 1,
				429 => limited[k] += 1,
				s => panic!("{} answered {}", call, s),
			}
		}
		tokio::time::sleep(Duration::from_millis(1000)).await;
	}
	stop.store(true, Ordering::SeqCst);
	for h in hammers {
		h.join().unwrap();
	}
	println!("L1 {} sources, each asking each call every 10 ms: {} requests, {} granted; an honest caller from another source, 30 s, \
		one challenge and one nonce a second: challenges {} given, {} rate_limited; nonces {} given, {} rate_limited ({:?})",
		sources.len(), sent.load(Ordering::SeqCst), given.load(Ordering::SeqCst), ok[0], limited[0], ok[1], limited[1], t.elapsed());
	assert_eq!((ok, limited), ([30, 30], [0, 0]), "the honest caller gets every challenge and every nonce it asks for");
}
