//! The finality service: through a chain held in memory for the cases a live
//! chain will not produce on demand, and against an anchored proof-of-stake
//! regtest chain for the real thing.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::db::TestDb;
use common::fake::{tx, FakeChain};
use server::chain::finality::{FinalityError, MEMPOOL_BUDGET};
use server::chain::{Certification, ChainEvent, ChainSource, Finality, FinalityConfig, FinalityService};

fn config(certification: Certification) -> FinalityConfig {
	FinalityConfig {
		anchor_depth: 2, certification, start_height: Some(0), poll_interval: Duration::from_millis(50),
		cert_lookback: 144,
	}
}

async fn service(db: &TestDb, chain: &Arc<FakeChain>) -> Arc<FinalityService> {
	FinalityService::new(db.store.clone(), chain.clone() as Arc<dyn ChainSource>, config(Certification::Required))
		.await.unwrap()
}

/// Drains the events received so far.
fn drain(rx: &mut tokio::sync::broadcast::Receiver<ChainEvent>) -> Vec<ChainEvent> {
	let mut v = vec![];
	while let Ok(e) = rx.try_recv() {
		v.push(e);
	}
	v
}

#[tokio::test]
async fn unsettled_settled_final() {
	let db = TestDb::new().await;
	let chain = Arc::new(FakeChain::new(true));
	let f = service(&db, &chain).await;
	let t = tx("board");
	let txid = t.txid();

	assert_eq!(f.watch(txid, "board").await.unwrap(), Finality::NotInChain);
	let b1 = chain.mine(100, false, vec![t]);
	f.sync().await.unwrap();
	assert_eq!(f.status(&txid).await.unwrap(), Finality::Unsettled { height: 1, block: b1 });

	// Its anchor buried, but no certificate yet: still not final.
	chain.mine(102, false, vec![]);
	f.sync().await.unwrap();
	assert!(matches!(f.status(&txid).await.unwrap(), Finality::Unsettled { .. }));

	// The certificate arrives after its block.
	chain.certify(&b1);
	f.sync().await.unwrap();
	assert_eq!(f.status(&txid).await.unwrap(), Finality::Final { height: 1, block: b1, depth: 2 });

	// The node reports its tip's anchor stale: nothing is final.
	chain.set_anchor_status(true, "stale");
	f.sync().await.unwrap();
	assert_eq!(f.status(&txid).await.unwrap(), Finality::Settled { height: 1, block: b1, depth: 2 });
	chain.set_anchor_status(true, "ok");
	f.sync().await.unwrap();
	assert!(f.status(&txid).await.unwrap().is_final());
}

#[tokio::test]
async fn anchor_depth_counts_parent_blocks() {
	let db = TestDb::new().await;
	let chain = Arc::new(FakeChain::new(true));
	let f = service(&db, &chain).await;
	let t = tx("round");
	let txid = t.txid();
	f.watch(txid, "round").await.unwrap();
	let b = chain.mine(100, true, vec![t]);
	// Many Sequentia blocks on one parent block bury nothing.
	for _ in 0..5 {
		chain.mine(100, true, vec![]);
	}
	f.sync().await.unwrap();
	assert_eq!(f.status(&txid).await.unwrap(), Finality::Settled { height: 1, block: b, depth: 0 });
	chain.mine(101, true, vec![]);
	f.sync().await.unwrap();
	assert_eq!(f.status(&txid).await.unwrap(), Finality::Settled { height: 1, block: b, depth: 1 });
	chain.mine(102, true, vec![]);
	f.sync().await.unwrap();
	assert_eq!(f.status(&txid).await.unwrap(), Finality::Final { height: 1, block: b, depth: 2 });
}

#[tokio::test]
async fn a_certified_descendant_certifies() {
	let db = TestDb::new().await;
	let chain = Arc::new(FakeChain::new(true));
	let f = service(&db, &chain).await;
	let t = tx("transfer");
	let txid = t.txid();
	f.watch(txid, "wallet").await.unwrap();
	let b1 = chain.mine(100, false, vec![t]);
	chain.mine(101, false, vec![]);
	f.sync().await.unwrap();
	assert!(matches!(f.status(&txid).await.unwrap(), Finality::Unsettled { .. }));
	chain.mine(102, true, vec![]);
	f.sync().await.unwrap();
	assert_eq!(f.status(&txid).await.unwrap(), Finality::Final { height: 1, block: b1, depth: 2 });
}

#[tokio::test]
async fn rollback_disconnects_and_reports() {
	let db = TestDb::new().await;
	let chain = Arc::new(FakeChain::new(true));
	let f = service(&db, &chain).await;
	let mut rx = f.subscribe();
	let t = tx("board");
	let txid = t.txid();
	f.watch(txid, "board").await.unwrap();
	chain.mine(100, true, vec![]);
	let b2 = chain.mine(101, true, vec![t.clone()]);
	chain.mine(103, true, vec![]);
	chain.mine(104, true, vec![]);
	f.sync().await.unwrap();
	assert_eq!(f.status(&txid).await.unwrap(), Finality::Final { height: 2, block: b2, depth: 3 });
	drain(&mut rx);

	// The anchor of block 2 is orphaned: the node drops blocks 2 to 4, final
	// as block 2 was.
	chain.rewind_to(1);
	let c2 = chain.mine(102, true, vec![]);
	f.sync().await.unwrap();
	let events = drain(&mut rx);
	let disconnected: Vec<u64> = events.iter().filter_map(|e| match e {
		ChainEvent::Disconnected { height, .. } => Some(*height),
		_ => None,
	}).collect();
	assert_eq!(disconnected, vec![4, 3, 2], "tip first: {:?}", events);
	let held: Vec<_> = events.iter().filter_map(|e| match e {
		ChainEvent::Disconnected { watched, .. } if !watched.is_empty() => Some(watched.clone()),
		_ => None,
	}).collect();
	assert_eq!(held, vec![vec![(txid, "board".to_string())]]);
	assert!(events.contains(&ChainEvent::Connected { height: 2, hash: c2 }));
	assert!(matches!(events.last(), Some(ChainEvent::Synced { height: 2, .. })));
	assert_eq!(f.status(&txid).await.unwrap(), Finality::NotInChain);

	// It confirms again on the new branch, and is final again once buried.
	let c3 = chain.mine(102, true, vec![t]);
	chain.mine(104, true, vec![]);
	f.sync().await.unwrap();
	assert_eq!(f.status(&txid).await.unwrap(), Finality::Final { height: 3, block: c3, depth: 2 });
	let kinds: Vec<String> = db.store.chain_events().await.unwrap().into_iter()
		.map(|(k, h, _)| format!("{}{}", &k[..1], h)).collect();
	assert_eq!(kinds.join(" "), "c0 c1 c2 c3 c4 d4 d3 d2 c2 c3 c4");
}

#[tokio::test]
async fn rollback_below_where_it_started() {
	let db = TestDb::new().await;
	let chain = Arc::new(FakeChain::new(true));
	for a in 101..=105 {
		chain.mine(a, true, vec![]);
	}
	// Following from height 4 only.
	let mut c = config(Certification::Required);
	c.start_height = Some(4);
	let f = FinalityService::new(db.store.clone(), chain.clone() as Arc<dyn ChainSource>, c).await.unwrap();
	f.sync().await.unwrap();
	assert_eq!(db.store.lowest_block_height().await.unwrap(), Some(4));
	let mut rx = f.subscribe();
	chain.rewind_to(2);
	let t = tx("late");
	f.watch(t.txid(), "board").await.unwrap();
	for a in 106..=108 {
		chain.mine(a, true, vec![t.clone()].into_iter().filter(|_| a == 108).collect());
	}
	f.sync().await.unwrap();
	let events = drain(&mut rx);
	assert!(events.iter().any(|e| matches!(e, ChainEvent::Disconnected { height: 5, .. })));
	assert!(events.iter().any(|e| matches!(e, ChainEvent::Disconnected { height: 4, .. })));
	let tip = db.store.tip_block().await.unwrap().unwrap();
	assert_eq!(tip.height, 5);
	assert_eq!(f.status(&t.txid()).await.unwrap().name(), "settled");
}

#[tokio::test]
async fn rollback_while_stopped() {
	let db = TestDb::new().await;
	let chain = Arc::new(FakeChain::new(true));
	let t = tx("board");
	{
		let f = service(&db, &chain).await;
		f.watch(t.txid(), "board").await.unwrap();
		chain.mine(100, true, vec![t.clone()]);
		chain.mine(102, true, vec![]);
		f.sync().await.unwrap();
		assert!(f.status(&t.txid()).await.unwrap().is_final());
	}
	// The chain rolls back while no service runs; the next one to start sees
	// it on its first pass.
	chain.rewind_to(0);
	chain.mine(100, true, vec![]);
	let f = service(&db, &chain).await;
	let mut rx = f.subscribe();
	f.sync().await.unwrap();
	let events = drain(&mut rx);
	assert!(events.iter().any(|e| matches!(e, ChainEvent::Disconnected { height: 1, watched, .. } if watched.len() == 1)),
		"{:?}", events);
	assert_eq!(f.status(&t.txid()).await.unwrap(), Finality::NotInChain);
}

#[tokio::test]
async fn watched_after_it_confirmed() {
	let db = TestDb::new().await;
	let chain = Arc::new(FakeChain::new(true));
	let f = service(&db, &chain).await;
	let t = tx("earlier");
	let b = chain.mine(100, true, vec![t.clone()]);
	chain.mine(102, true, vec![]);
	f.sync().await.unwrap();
	// Not watched when its block was scanned: found from the node at once.
	assert_eq!(f.watch(t.txid(), "board").await.unwrap(), Finality::Final { height: 1, block: b, depth: 2 });
	// A transaction never watched is not reported as in the chain.
	let u = tx("unwatched");
	chain.mine(102, true, vec![u.clone()]);
	f.sync().await.unwrap();
	assert_eq!(f.status(&u.txid()).await.unwrap(), Finality::NotInChain);
}

#[tokio::test]
async fn refuses_a_node_without_finality() {
	let db = TestDb::new().await;
	// No anchor validation.
	let chain = Arc::new(FakeChain::new(true));
	chain.set_anchor_status(false, "not_validated");
	let e = FinalityService::new(db.store.clone(), chain.clone() as Arc<dyn ChainSource>, config(Certification::Required))
		.await.err().unwrap();
	assert!(matches!(&e, FinalityError::Config(m) if m.contains("does not validate its anchors")), "{}", e);
	println!("no anchor validation: {}", e);
	// A chain with no committee, where certification is required.
	let chain = Arc::new(FakeChain::new(false));
	let e = FinalityService::new(db.store.clone(), chain.clone() as Arc<dyn ChainSource>, config(Certification::Required))
		.await.err().unwrap();
	assert!(matches!(&e, FinalityError::Config(m) if m.contains("no committee certificate")), "{}", e);
	println!("no committee: {}", e);
	// Waiving certification on a chain that has a committee.
	let chain = Arc::new(FakeChain::new(true));
	let e = FinalityService::new(db.store.clone(), chain.clone() as Arc<dyn ChainSource>, config(Certification::NotOnThisChain))
		.await.err().unwrap();
	assert!(matches!(&e, FinalityError::Config(m) if m.contains("cannot be left out")), "{}", e);
	println!("waived on a committee chain: {}", e);
	// On a chain without a committee, waived, the anchor alone decides.
	let chain = Arc::new(FakeChain::new(false));
	let f = FinalityService::new(db.store.clone(), chain.clone() as Arc<dyn ChainSource>, config(Certification::NotOnThisChain))
		.await.unwrap();
	let t = tx("no committee");
	f.watch(t.txid(), "board").await.unwrap();
	chain.mine(100, false, vec![t.clone()]);
	chain.mine(102, false, vec![]);
	f.sync().await.unwrap();
	assert!(f.status(&t.txid()).await.unwrap().is_final());
}

/// A mempool of thousands of transactions behind a slow node delays only the
/// sightings: each pass reads the mempool for at most its budget, so blocks
/// are followed and finality advances in every pass, the rest of the mempool
/// is read over the next ones, and the service says how far behind it is.
#[tokio::test]
async fn a_flooded_mempool_never_holds_finality_back() {
	let db = TestDb::new().await;
	let chain = Arc::new(FakeChain::new(true));
	let f = service(&db, &chain).await;
	for i in 0..5_000 {
		chain.to_mempool(tx(&format!("flood {}", i)));
	}
	// 5 ms a read: 25 s to read the whole mempool.
	chain.set_transaction_delay(Duration::from_millis(5));
	let t = tx("round");
	let txid = t.txid();
	f.watch(txid, "round").await.unwrap();
	chain.mine(100, true, vec![t]);
	chain.mine(102, true, vec![]);

	let t0 = Instant::now();
	f.sync().await.unwrap();
	let took = t0.elapsed();
	assert!(took < MEMPOOL_BUDGET + Duration::from_secs(3), "a pass took {:?}", took);
	assert!(f.status(&txid).await.unwrap().is_final(), "the round is final after the first pass");
	let p = f.progress();
	assert_eq!((p.height, p.node_height, p.anchor_ok), (2, 2, true));
	assert!(p.mempool_behind > 1_000 && p.mempool_behind < 5_000, "{} left of the mempool", p.mempool_behind);
	assert!(p.last_pass_ms >= MEMPOOL_BUDGET.as_millis() as u64);

	// A block mined while the mempool is still being read is followed by the
	// next pass, at once.
	let t2 = tx("round 2");
	f.watch(t2.txid(), "round").await.unwrap();
	chain.mine(104, true, vec![t2.clone()]);
	f.sync().await.unwrap();
	assert_eq!(f.progress().height, 3);
	assert!(matches!(f.status(&t2.txid()).await.unwrap(), Finality::Settled { .. }));

	for _ in 0..10 {
		if f.progress().mempool_behind == 0 {
			break;
		}
		f.sync().await.unwrap();
	}
	assert_eq!(f.progress().mempool_behind, 0, "the whole mempool is read over the following passes");
}

/// While the tip's anchor stands at one Bitcoin height (the parent chain
/// contested above it, the node anchoring at its last uncontested height), a
/// certified round stays settled and the service says since when the anchor
/// has not moved; once it moves two blocks the round is final.
#[tokio::test]
async fn an_anchor_standing_still_is_reported() {
	let db = TestDb::new().await;
	let chain = Arc::new(FakeChain::new(true));
	let f = service(&db, &chain).await;
	let t = tx("round in a contested hour");
	f.watch(t.txid(), "round").await.unwrap();
	chain.mine(158096, true, vec![t.clone()]);
	f.sync().await.unwrap();
	let first = f.progress();
	assert_eq!(first.anchor_height, 158096);
	// many Sequentia blocks, every one anchored at the same Bitcoin height
	for _ in 0..5 {
		chain.mine(158096, true, vec![]);
		tokio::time::sleep(Duration::from_millis(1100)).await;
		f.sync().await.unwrap();
	}
	let p = f.progress();
	assert_eq!((p.height, p.anchor_height), (6, 158096));
	assert_eq!(p.anchor_since, first.anchor_since, "the anchor has not moved since the round's block");
	assert!(matches!(f.status(&t.txid()).await.unwrap(), Finality::Settled { depth: 0, .. }));
	// Bitcoin settles: two blocks over the anchor
	chain.mine(158098, true, vec![]);
	f.sync().await.unwrap();
	assert!(f.progress().anchor_since > first.anchor_since);
	assert!(f.status(&t.txid()).await.unwrap().is_final());
}
