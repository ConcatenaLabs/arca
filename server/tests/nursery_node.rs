//! The nursery against an anchored proof-of-stake regtest chain: a wallet
//! transaction kept broadcast until final; a rollback, with the node's
//! mempool emptied, that takes it out after it was final and the identical
//! bytes broadcast again at once; and a transaction whose input a final
//! transaction of another txid spent, marked lost and never rebuilt.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::db::TestDb;
use common::keys::{keypair, xonly, MNEMONIC};
use common::node::{self, Purse};
use elements::encode::serialize;
use elements::hashes::Hash;
use elements::{Transaction, Txid};
use sequentia_ext::{explicit_txout, AssetAmount};
use server::chain::{ChainEvent, ChainSource, FinalityConfig, FinalityService, NodeSource};
use server::nursery::{Nursery, NurseryEvent, NurseryKind};
use server::store::NurseryState;
use server::wallet::{BuildRequest, SpendFrom, Wallet, WalletConfig};

use arca_covenant::ExplicitOutput;

/// Syncs the finality service and hands every event to the nursery in order,
/// as its task would.
async fn follow(f: &FinalityService, n: &Nursery, rx: &mut tokio::sync::broadcast::Receiver<ChainEvent>) -> Vec<ChainEvent> {
	f.sync().await.unwrap();
	let mut seen = vec![];
	while let Ok(e) = rx.try_recv() {
		match &e {
			ChainEvent::Synced { .. } => n.pass().await.unwrap(),
			other => n.on_chain_event(other).await.unwrap(),
		}
		seen.push(e);
	}
	seen
}

fn node_has(rt: &sequentia_ext::regtest::Regtest, txid: &Txid) -> Option<Vec<u8>> {
	rt.client().raw_transaction_bytes(txid).ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn nursery_on_regtest() {
	let db = TestDb::new().await;
	let mut rt = tokio::task::block_in_place(node::start);
	let mut purse = tokio::task::block_in_place(|| Purse::new(&rt));
	let x = tokio::task::block_in_place(|| purse.issue(&rt, "asset X", 100_000_000_000));
	node::list_fee_asset(&rt, x, 100_000_000);

	let source = Arc::new(NodeSource::new(rt.client().clone()));
	let finality = FinalityService::new(db.store.clone(), source as Arc<dyn ChainSource>, FinalityConfig::spec()).await.unwrap();
	let mut rx = finality.subscribe();
	let wallet = Arc::new(Wallet::new(db.store.clone(), finality.clone(), xonly(&keypair("operator")),
		WalletConfig { mnemonic: MNEMONIC.into(), fee_multiple: 2, spend_from: SpendFrom::Final, pool_coins: server::wallet::POOL_COINS }).unwrap());
	let nursery = Nursery::new(db.store.clone(), finality.clone(), Some(wallet.clone()), Duration::ZERO);
	let mut events = nursery.subscribe();
	follow(&finality, &nursery, &mut rx).await;

	let to = wallet.receive_script().await.unwrap();
	tokio::task::block_in_place(|| purse.pay(&rt, vec![explicit_txout(AssetAmount::new(x, 9_000_000), to)]));
	tokio::task::block_in_place(|| rt.produce_block()).unwrap();
	tokio::task::block_in_place(|| node::bury(&rt));
	follow(&finality, &nursery, &mut rx).await;

	// A round-shaped transaction into the nursery, kept until final.
	let built = wallet.build(&BuildRequest {
		outputs: vec![ExplicitOutput::new(x, 1_000_000, node::op_true())],
		connector: Some(AssetAmount::new(x, 10_000)), fee_asset: x,
	}).await.unwrap();
	let a = built.tx.clone();
	let a_bytes = serialize(&a);
	assert_eq!(nursery.submit(&a, NurseryKind::Round, Some(built.fee)).await.unwrap(), "accepted");
	let row = db.store.nursery_get(&a.txid().to_byte_array()).await.unwrap().unwrap();
	assert_eq!(row.fee, Some((x.into_inner().to_byte_array(), built.fee.amount)), "the fee asset is named");
	tokio::task::block_in_place(|| rt.produce_block()).unwrap();
	follow(&finality, &nursery, &mut rx).await;
	assert_eq!(db.store.nursery_get(&a.txid().to_byte_array()).await.unwrap().unwrap().state, NurseryState::Pending);
	tokio::task::block_in_place(|| node::bury(&rt));
	follow(&finality, &nursery, &mut rx).await;
	assert_eq!(db.store.nursery_get(&a.txid().to_byte_array()).await.unwrap().unwrap().state, NurseryState::Final);
	println!("{} final, fee {} atoms of X", a.txid(), built.fee.amount);

	// Its block invalidated after it was final, and the node restarted with
	// no mempool: only the nursery can bring it back.
	let block = db.store.tx_location(&a.txid().to_byte_array()).await.unwrap().unwrap();
	node::invalidate(&rt, &elements::BlockHash::from_byte_array(block.hash));
	tokio::task::block_in_place(|| rt.node.restart(&["-persistmempool=0"])).unwrap();
	assert!(!node::in_mempool(&rt, &a.txid()), "the node no longer holds it");
	while events.try_recv().is_ok() {}
	let seen = follow(&finality, &nursery, &mut rx).await;
	assert!(seen.iter().any(|e| matches!(e, ChainEvent::Disconnected { watched, .. } if watched.iter().any(|(t, _)| *t == a.txid()))));
	let mut got = vec![];
	while let Ok(e) = events.try_recv() {
		got.push(e);
	}
	assert_eq!(got.first(), Some(&NurseryEvent::Unfinal { txid: a.txid() }), "{:?}", got);
	assert_eq!(got.get(1), Some(&NurseryEvent::Broadcast { txid: a.txid(), result: "accepted".into() }), "{:?}", got);
	assert!(node::in_mempool(&rt, &a.txid()), "broadcast again");
	assert_eq!(node_has(&rt, &a.txid()).unwrap(), a_bytes, "the identical bytes");
	println!("after the rollback: {:?}, then {:?}", got[0], got[1]);
	tokio::task::block_in_place(|| rt.produce_block()).unwrap();
	tokio::task::block_in_place(|| node::bury(&rt));
	follow(&finality, &nursery, &mut rx).await;
	assert_eq!(db.store.nursery_get(&a.txid().to_byte_array()).await.unwrap().unwrap().state, NurseryState::Final);
	println!("{} final again, same txid", a.txid());

	// B in the nursery; after a rollback, B' of another txid spends the same
	// coin and becomes final: B is lost, and the nursery builds nothing.
	let request = BuildRequest { outputs: vec![ExplicitOutput::new(x, 500_000, node::op_true())], connector: None, fee_asset: x };
	let b = wallet.build(&request).await.unwrap();
	nursery.submit(&b.tx, NurseryKind::Wallet, Some(b.fee)).await.unwrap();
	tokio::task::block_in_place(|| rt.produce_block()).unwrap();
	follow(&finality, &nursery, &mut rx).await;
	// The wallet would build the same spend again, to another change script.
	wallet.release(&b.tx.txid()).await.unwrap();
	let b2: Transaction = wallet.build(&request).await.unwrap().tx;
	assert_ne!(b2.txid(), b.tx.txid());
	assert_eq!(b2.input[0].previous_output, b.tx.input[0].previous_output, "the same coin");
	let block = db.store.tx_location(&b.tx.txid().to_byte_array()).await.unwrap().unwrap();
	node::invalidate(&rt, &elements::BlockHash::from_byte_array(block.hash));
	tokio::task::block_in_place(|| rt.node.restart(&["-persistmempool=0"])).unwrap();
	rt.client().send_raw_transaction(&b2).unwrap();
	tokio::task::block_in_place(|| rt.produce_block()).unwrap();
	tokio::task::block_in_place(|| node::bury(&rt));
	while events.try_recv().is_ok() {}
	follow(&finality, &nursery, &mut rx).await;
	let row = db.store.nursery_get(&b.tx.txid().to_byte_array()).await.unwrap().unwrap();
	assert_eq!(row.state, NurseryState::Lost);
	println!("B broadcast again after the rollback: {}", row.last_result.unwrap());
	let mut got = vec![];
	while let Ok(e) = events.try_recv() {
		got.push(e);
	}
	assert!(got.contains(&NurseryEvent::Lost { txid: b.tx.txid(), kind: "wallet".into(), by: b2.txid() }), "{:?}", got);
	assert!(!node::in_mempool(&rt, &b.tx.txid()));
	// The coin is B''s, as the chain says.
	let coin = db.store.wallet_coins(None).await.unwrap();
	assert!(coin.iter().all(|c| (Txid::from_byte_array(c.txid), c.vout) != (b.tx.input[0].previous_output.txid, b.tx.input[0].previous_output.vout)));
	println!("B lost: {} spent its coin and is final", b2.txid());
}

/// A pass of the nursery while it holds many final transactions, and a
/// rollback it never hears of. The finality service ends a pass every poll
/// interval, so a nursery whose passes looked up each final transaction it
/// ever held fell behind once that took longer, and then only ever missed
/// events (the testnet's operator, 2026-11-02 to 11-04: about 30,000 final
/// transactions, 75 s a pass, "chain events missed" every pass). A pass now
/// looks again only at what the store no longer places final, in one
/// statement, and still finds a final transaction whose block left the chain
/// while its disconnection never reached the nursery.
#[tokio::test(flavor = "multi_thread")]
async fn a_pass_reads_only_what_is_no_longer_final() {
	let db = TestDb::new().await;
	let mut rt = tokio::task::block_in_place(node::start);
	let mut purse = tokio::task::block_in_place(|| Purse::new(&rt));
	let x = tokio::task::block_in_place(|| purse.issue(&rt, "asset X", 100_000_000_000));
	node::list_fee_asset(&rt, x, 100_000_000);
	let source = Arc::new(NodeSource::new(rt.client().clone()));
	let finality = FinalityService::new(db.store.clone(), source as Arc<dyn ChainSource>, FinalityConfig::spec()).await.unwrap();
	let mut rx = finality.subscribe();
	let wallet = Arc::new(Wallet::new(db.store.clone(), finality.clone(), xonly(&keypair("operator")),
		WalletConfig { mnemonic: MNEMONIC.into(), fee_multiple: 2, spend_from: SpendFrom::Final, pool_coins: server::wallet::POOL_COINS }).unwrap());
	let nursery = Nursery::new(db.store.clone(), finality.clone(), Some(wallet.clone()), Duration::ZERO);
	follow(&finality, &nursery, &mut rx).await;
	let to = wallet.receive_script().await.unwrap();
	tokio::task::block_in_place(|| purse.pay(&rt, vec![explicit_txout(AssetAmount::new(x, 9_000_000), to)]));
	tokio::task::block_in_place(|| rt.produce_block()).unwrap();
	tokio::task::block_in_place(|| node::bury(&rt));
	follow(&finality, &nursery, &mut rx).await;

	let built = wallet.build(&BuildRequest {
		outputs: vec![ExplicitOutput::new(x, 1_000_000, node::op_true())], connector: None, fee_asset: x,
	}).await.unwrap();
	let a = built.tx.clone();
	nursery.submit(&a, NurseryKind::Wallet, Some(built.fee)).await.unwrap();
	tokio::task::block_in_place(|| rt.produce_block()).unwrap();
	tokio::task::block_in_place(|| node::bury(&rt));
	follow(&finality, &nursery, &mut rx).await;
	assert_eq!(db.store.nursery_get(&a.txid().to_byte_array()).await.unwrap().unwrap().state, NurseryState::Final);
	let block = db.store.tx_location(&a.txid().to_byte_array()).await.unwrap().unwrap();

	// 5,000 more final transactions in A's block, as a long-running
	// operator's nursery holds them.
	const MANY: usize = 5_000;
	let (client, conn) = tokio_postgres::connect(&db.url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(conn);
	client.execute(
		"WITH t AS (SELECT sha256(int8send(g)) AS txid FROM generate_series(1, $3::BIGINT) g),
		  w AS (INSERT INTO watched_tx (txid, kind) SELECT txid, 'nursery' FROM t RETURNING txid),
		  b AS (INSERT INTO tx_block (txid, block_hash) SELECT txid, $2 FROM w RETURNING txid)
		 INSERT INTO nursery_tx (txid, tx, kind, state) SELECT txid, $1, 'wallet', 'final' FROM b",
		&[&serialize(&a), &&block.hash[..], &(MANY as i64)]).await.unwrap();
	let still = db.store.nursery_final_not_final(true, 2).await.unwrap();
	assert!(still.is_empty(), "every one is final: {}", still.len());
	let t = std::time::Instant::now();
	nursery.pass().await.unwrap();
	let took = t.elapsed();
	println!("a pass with {} final transactions held: {:?}", MANY + 1, took);
	for r in db.store.nursery_in(NurseryState::Final).await.unwrap() {
		assert!(finality.status(&Txid::from_byte_array(r.txid)).await.unwrap().is_final(), "the statement agrees with status");
	}
	assert_eq!(db.store.nursery_in(NurseryState::Final).await.unwrap().len(), MANY + 1, "a pass leaves them final");

	// A's block rolled back with the node's mempool emptied; the service
	// follows it, but the nursery is handed none of its events (it lagged).
	node::invalidate(&rt, &elements::BlockHash::from_byte_array(block.hash));
	tokio::task::block_in_place(|| rt.node.restart(&["-persistmempool=0"])).unwrap();
	finality.sync().await.unwrap();
	while rx.try_recv().is_ok() {}
	let back = db.store.nursery_final_not_final(true, 2).await.unwrap();
	println!("after the rollback the store no longer places {} final", back.len());
	assert!(back.iter().any(|r| r.txid == a.txid().to_byte_array()), "A is among them");
	nursery.pass().await.unwrap();
	assert_eq!(db.store.nursery_get(&a.txid().to_byte_array()).await.unwrap().unwrap().state, NurseryState::Pending);
	assert!(node::in_mempool(&rt, &a.txid()), "broadcast again");
	println!("A found out of finality by a pass, and broadcast again");
}
