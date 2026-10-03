//! The on-chain wallet against an anchored proof-of-stake regtest chain, with
//! no policy asset in it: it holds asset X (listed for fees) and asset Y (not
//! listed), finds its coins as blocks connect, spends only final ones, builds
//! a round-shaped transaction with its connector output and the fee in X, and
//! refuses every other fee asset rather than fall back to one.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::sync::Arc;

use common::db::TestDb;
use common::keys::{keypair, xonly, MNEMONIC};
use common::node::{self, Purse};
use elements::hashes::Hash;
use elements::Txid;
use sequentia_ext::{explicit_txout, AssetAmount, TxOutExt};
use server::chain::{ChainSource, FinalityConfig, FinalityService, NodeSource};
use server::wallet::{BuildRequest, SpendFrom, Wallet, WalletConfig, WalletError};

use arca_covenant::{ConnectorPolicy, ExplicitOutput};

#[tokio::test(flavor = "multi_thread")]
async fn wallet_without_the_policy_asset() {
	let db = TestDb::new().await;
	let rt = tokio::task::block_in_place(node::start);
	let mut purse = tokio::task::block_in_place(|| Purse::new(&rt));
	let x = tokio::task::block_in_place(|| purse.issue(&rt, "asset X", 100_000_000_000));
	let y = tokio::task::block_in_place(|| purse.issue(&rt, "asset Y", 100_000_000_000));
	node::list_fee_asset(&rt, x, 100_000_000);
	println!("policy asset {}, X {} (listed 1:1), Y {} (not listed)", purse.policy, x, y);

	let source = Arc::new(NodeSource::new(rt.client().clone()));
	let finality = FinalityService::new(db.store.clone(), source as Arc<dyn ChainSource>, FinalityConfig::spec()).await.unwrap();
	finality.sync().await.unwrap();
	let s = keypair("operator");
	let wallet = Wallet::new(db.store.clone(), finality.clone(), xonly(&s),
		WalletConfig { mnemonic: MNEMONIC.into(), fee_multiple: 2, spend_from: SpendFrom::Final }).unwrap();

	// The wallet is paid X and Y, never the policy asset.
	let r1 = wallet.receive_script().await.unwrap();
	let r2 = wallet.receive_script().await.unwrap();
	let fund = tokio::task::block_in_place(|| purse.pay(&rt, vec![
		explicit_txout(AssetAmount::new(x, 5_000_000), r1.clone()),
		explicit_txout(AssetAmount::new(x, 3_000_000), r2.clone()),
		explicit_txout(AssetAmount::new(y, 1_000_000), r1.clone()),
	]));
	tokio::task::block_in_place(|| rt.produce_block()).unwrap();
	finality.sync().await.unwrap();
	let coins = db.store.wallet_coins(None).await.unwrap();
	assert_eq!(coins.len(), 3);
	assert!(coins.iter().all(|c| c.in_chain && c.txid == fund.txid().to_byte_array()));
	// Not final yet: nothing to spend.
	assert!(wallet.balance().await.unwrap().is_empty());
	let request = BuildRequest {
		outputs: vec![ExplicitOutput::new(x, 1_000_000, node::op_true())],
		connector: Some(AssetAmount::new(x, 10_000)),
		fee_asset: x,
	};
	let e = wallet.build(&request).await.unwrap_err();
	assert!(matches!(e, WalletError::Insufficient { asset, have: 0, .. } if asset == x), "{}", e);
	println!("before the coins are final: {}", e);

	tokio::task::block_in_place(|| node::bury(&rt));
	finality.sync().await.unwrap();
	let balance = wallet.balance().await.unwrap();
	assert_eq!(balance.get(&x), Some(&8_000_000));
	assert_eq!(balance.get(&y), Some(&1_000_000));
	assert!(!balance.contains_key(&purse.policy));
	println!("final balance: X {}, Y {}, policy asset none", balance[&x], balance[&y]);

	// A round-shaped transaction: the outputs, the connector, change, the fee
	// in X.
	let built = wallet.build(&request).await.unwrap();
	let tx = &built.tx;
	assert_eq!(built.connector_vout, Some(1));
	ConnectorPolicy { operator: xonly(&s) }.check(tx, 1).unwrap();
	assert_eq!(tx.output[1].asset_amount(), Some(AssetAmount::new(x, 10_000)));
	let fee: Vec<_> = tx.output.iter().filter(|o| o.is_fee()).collect();
	assert_eq!(fee.len(), 1);
	assert_eq!(fee[0].asset_amount(), Some(built.fee));
	assert_eq!(built.fee.asset, x);
	assert!(tx.output.iter().all(|o| o.explicit_asset() != Some(purse.policy)), "no output in the policy asset");
	assert!(tx.output.iter().all(|o| o.is_explicit()));
	let accept = rt.client().test_mempool_accept(&[tx]).unwrap().remove(0);
	assert!(accept.allowed, "{:?}", accept.reject_reason);
	println!("round-shaped transaction {}: {} inputs, {} outputs, {} vB, fee {} atoms of X",
		tx.txid(), tx.input.len(), tx.output.len(), accept.vsize.unwrap(), built.fee.amount);
	let txid = rt.client().send_raw_transaction(tx).unwrap();
	tokio::task::block_in_place(|| rt.produce_block()).unwrap();
	finality.sync().await.unwrap();
	assert!(rt.client().confirmations(&txid).unwrap() >= 1);
	// Its coins are spent by it; its change is a coin once confirmed.
	let left = db.store.wallet_coins(Some(&x.into_inner().to_byte_array())).await.unwrap();
	assert!(left.iter().any(|c| Txid::from_byte_array(c.txid) == txid), "the change came back");

	// The policy asset as the fee asset: the node lists it, the wallet holds
	// none, so it is refused, and nothing is paid in another asset instead.
	let e = wallet.build(&BuildRequest { fee_asset: purse.policy, ..request.clone() }).await.unwrap_err();
	assert!(matches!(e, WalletError::Insufficient { asset, have: 0, .. } if asset == purse.policy), "{}", e);
	println!("fee in the policy asset: {}", e);
	// Y as the fee asset: the wallet holds it, the node does not accept it.
	tokio::task::block_in_place(|| node::bury(&rt));
	finality.sync().await.unwrap();
	let e = wallet.build(&BuildRequest {
		outputs: vec![ExplicitOutput::new(y, 1_000, node::op_true())], connector: None, fee_asset: y,
	}).await.unwrap_err();
	assert!(matches!(e, WalletError::FeeAssetNotAccepted(a) if a == y), "{}", e);
	println!("fee in Y: {}", e);
	// The same payment of Y, the fee named in X, is built.
	let built = wallet.build(&BuildRequest {
		outputs: vec![ExplicitOutput::new(y, 1_000, node::op_true())], connector: None, fee_asset: x,
	}).await.unwrap();
	assert_eq!(built.fee.asset, x);
	let accept = rt.client().test_mempool_accept(&[&built.tx]).unwrap().remove(0);
	assert!(accept.allowed, "{:?}", accept.reject_reason);
	wallet.release(&built.tx.txid()).await.unwrap();

	// A rollback takes the funding's block away: its coins leave the chain.
	let funded_in = db.store.tx_location(&fund.txid().to_byte_array()).await.unwrap().unwrap();
	node::invalidate(&rt, &elements::BlockHash::from_byte_array(funded_in.hash));
	finality.sync().await.unwrap();
	assert!(wallet.balance().await.unwrap().is_empty(), "nothing in the chain is the wallet's");
	assert!(db.store.wallet_coins(None).await.unwrap().iter().all(|c| !c.in_chain));
	println!("after the funding block is invalidated: balance empty");
}
