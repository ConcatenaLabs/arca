//! The finality service against an anchored proof-of-stake regtest chain:
//! a transaction is settled once its certified block is connected, final once
//! two parent blocks bury its anchor, and back to not in the chain when its
//! block is invalidated, with the disconnection naming it.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::sync::Arc;

use common::db::TestDb;
use common::node;
use server::chain::{ChainEvent, ChainSource, Finality, FinalityConfig, FinalityService, NodeSource};

#[tokio::test(flavor = "multi_thread")]
async fn finality_on_regtest() {
	let db = TestDb::new().await;
	let rt = tokio::task::block_in_place(node::start);
	let source = Arc::new(NodeSource::new(rt.client().clone()));
	let f = FinalityService::new(db.store.clone(), source as Arc<dyn ChainSource>, FinalityConfig::spec()).await.unwrap();
	f.sync().await.unwrap();
	let mut rx = f.subscribe();

	let coin = node::free_coins(&rt);
	let tx = node::spend_op_true(&coin, vec![], 10_000);
	let txid = rt.client().send_raw_transaction(&tx).unwrap();
	assert_eq!(f.watch(txid, "board").await.unwrap(), Finality::NotInChain);
	println!("in the mempool: {}", f.status(&txid).await.unwrap().name());

	let b1 = tokio::task::block_in_place(|| rt.produce_block()).unwrap();
	f.sync().await.unwrap();
	let s = f.status(&txid).await.unwrap();
	assert_eq!(s, Finality::Settled { height: 1, block: b1, depth: 0 });
	println!("in certified block 1: {:?}", s);

	tokio::task::block_in_place(|| rt.mine_parent(1)).unwrap();
	tokio::task::block_in_place(|| rt.anchor_to_parent_tip()).unwrap();
	f.sync().await.unwrap();
	let s = f.status(&txid).await.unwrap();
	assert!(matches!(s, Finality::Settled { depth: 1, .. }), "{:?}", s);
	println!("one parent block later: {:?}", s);

	tokio::task::block_in_place(|| rt.mine_parent(1)).unwrap();
	tokio::task::block_in_place(|| rt.anchor_to_parent_tip()).unwrap();
	f.sync().await.unwrap();
	let s = f.status(&txid).await.unwrap();
	assert!(matches!(s, Finality::Final { height: 1, depth: 2, .. }), "{:?}", s);
	println!("two parent blocks later: {:?}", s);
	while rx.try_recv().is_ok() {}

	// A rollback below it, final as it was.
	node::invalidate(&rt, &b1);
	f.sync().await.unwrap();
	let mut disconnected = vec![];
	while let Ok(e) = rx.try_recv() {
		if let ChainEvent::Disconnected { height, watched, .. } = e {
			disconnected.push((height, watched));
		}
	}
	assert_eq!(disconnected.last().unwrap(), &(1, vec![(txid, "board".to_string())]), "{:?}", disconnected);
	assert_eq!(f.status(&txid).await.unwrap(), Finality::NotInChain);
	assert!(node::in_mempool(&rt, &txid), "the node put it back in its mempool");
	println!("after invalidateblock {}: {} block(s) disconnected, the last holding it; {}", b1,
		disconnected.len(), f.status(&txid).await.unwrap().name());

	// It confirms again in a new block, and is final again once buried.
	let c1 = tokio::task::block_in_place(|| rt.produce_block()).unwrap();
	f.sync().await.unwrap();
	assert!(matches!(f.status(&txid).await.unwrap(), Finality::Settled { height: 1, block, depth: 0 } if block == c1));
	tokio::task::block_in_place(|| rt.mine_parent(2)).unwrap();
	tokio::task::block_in_place(|| rt.anchor_to_parent_tip()).unwrap();
	f.sync().await.unwrap();
	let s = f.status(&txid).await.unwrap();
	assert!(matches!(s, Finality::Final { height: 1, depth: 2, block } if block == c1), "{:?}", s);
	println!("in block {} again: {:?}", c1, s);
}
