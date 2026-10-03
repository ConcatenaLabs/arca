//! The wallet at its boundary, on a chain held in memory: it takes an explicit
//! output paying it as a coin, and refuses, and records, an output paying it
//! that hides its asset or value or carries a nonce.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::db::TestDb;
use common::fake::{tx, FakeChain};
use common::keys::{keypair, xonly, MNEMONIC};
use elements::confidential::{Asset, Nonce, Value};
use elements::hashes::Hash;
use elements::secp256k1_zkp::{Generator, PedersenCommitment, Secp256k1, Tag, Tweak};
use elements::{AssetId, TxOut, TxOutWitness};
use server::chain::{Certification, ChainSource, FinalityConfig, FinalityService};
use server::wallet::{SpendFrom, Wallet, WalletConfig};

#[tokio::test]
async fn refuses_what_it_cannot_see() {
	let db = TestDb::new().await;
	let chain = Arc::new(FakeChain::new(true));
	let config = FinalityConfig {
		anchor_depth: 2, certification: Certification::Required, start_height: Some(0),
		poll_interval: Duration::from_millis(50), cert_lookback: 144,
	};
	let finality = FinalityService::new(db.store.clone(), chain.clone() as Arc<dyn ChainSource>, config).await.unwrap();
	let wallet = Wallet::new(db.store.clone(), finality.clone(), xonly(&keypair("operator")),
		WalletConfig { mnemonic: MNEMONIC.into(), fee_multiple: 1, spend_from: SpendFrom::Final }).unwrap();
	let script = wallet.receive_script().await.unwrap();
	let x = AssetId::from_slice(&[7; 32]).unwrap();

	let secp = Secp256k1::new();
	let generator = Generator::new_blinded(&secp, Tag::from([1u8; 32]), Tweak::from_inner([2; 32]).unwrap());
	let commitment = PedersenCommitment::new(&secp, 5_000, Tweak::from_inner([3; 32]).unwrap(), generator);
	let out = |asset: Asset, value: Value, nonce: Nonce| TxOut {
		asset, value, nonce, script_pubkey: script.clone(), witness: TxOutWitness::default(),
	};
	let mut t = tx("payments to the wallet");
	t.output = vec![
		out(Asset::Explicit(x), Value::Explicit(5_000), Nonce::Null),
		out(Asset::Confidential(generator), Value::Confidential(commitment), Nonce::Null),
		out(Asset::Explicit(x), Value::Confidential(commitment), Nonce::Null),
		out(Asset::Confidential(generator), Value::Explicit(5_000), Nonce::Null),
		out(Asset::Explicit(x), Value::Explicit(5_000), Nonce::Confidential(secp256k1_point())),
	];
	chain.mine(100, true, vec![t.clone()]);
	chain.mine(102, true, vec![]);
	finality.sync().await.unwrap();

	let coins = db.store.wallet_coins(None).await.unwrap();
	assert_eq!(coins.len(), 1, "only the explicit output is a coin");
	assert_eq!((coins[0].vout, coins[0].value), (0, 5_000));
	let refused = db.store.wallet_refusals().await.unwrap();
	assert_eq!(refused.iter().map(|r| r.vout).collect::<Vec<_>>(), vec![1, 2, 3, 4]);
	assert!(refused.iter().all(|r| r.txid == t.txid().to_byte_array()));
	println!("refused: {}", refused[0].reason);
	assert_eq!(wallet.balance().await.unwrap().into_iter().collect::<Vec<_>>(), vec![(x, 5_000)]);
}

fn secp256k1_point() -> elements::secp256k1_zkp::PublicKey {
	keypair("a nonce").public_key()
}
