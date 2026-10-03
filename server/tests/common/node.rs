//! An anchored proof-of-stake regtest chain for the server's tests, and the
//! genesis block's free coins to spend on it.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use elements::{AssetId, LockTime, OutPoint, Script, Transaction, TxIn, TxOut, Txid};
use serde_json::{json, Value};

use sequentia_ext::regtest::Regtest;
use sequentia_ext::{explicit_txout, fee_txout, AssetAmount, TxOutExt};

/// A fresh chain under its own directory: tests in one binary run in parallel.
pub fn start() -> Regtest {
	static N: AtomicUsize = AtomicUsize::new(0);
	let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
		.join(format!("server-regtest-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
	Regtest::pos_from_env(&dir, &["-par=1"])
}

/// A bare `OP_TRUE`: anyone spends it with an empty witness, through the
/// mempool on a chain started with `-acceptnonstdtxn`.
pub fn op_true() -> Script {
	Script::from(vec![0x51])
}

/// The genesis block's free coins: their outpoint and output.
pub fn free_coins(rt: &Regtest) -> (OutPoint, TxOut) {
	let genesis = rt.client().genesis_hash().unwrap();
	let block = rt.client().block(&genesis).unwrap();
	block.txdata.iter().flat_map(|tx| {
		tx.output.iter().enumerate().map(move |(i, o)| (OutPoint::new(tx.txid(), i as u32), o.clone()))
	}).find(|(_, o)| o.script_pubkey == op_true()).expect("the genesis block pays the free coins to OP_TRUE")
}

/// A transaction spending the bare `OP_TRUE` coin `coin` into `outputs`, the
/// rest of its asset less `fee` back to `OP_TRUE` at the end, and the fee in
/// the coin's asset.
pub fn spend_op_true(coin: &(OutPoint, TxOut), outputs: Vec<TxOut>, fee: u64) -> Transaction {
	let have = coin.1.asset_amount().expect("an explicit coin");
	let spent: u64 = outputs.iter().filter(|o| o.explicit_asset() == Some(have.asset))
		.map(|o| o.explicit_value().unwrap()).sum();
	let mut output = outputs;
	output.push(explicit_txout(AssetAmount::new(have.asset, have.amount - spent - fee), op_true()));
	output.push(fee_txout(AssetAmount::new(have.asset, fee)));
	Transaction {
		version: 2, lock_time: LockTime::ZERO,
		input: vec![TxIn { previous_output: coin.0, ..Default::default() }],
		output,
	}
}

/// The policy asset of the chain.
pub fn policy_asset(rt: &Regtest) -> AssetId {
	let info: Value = rt.client().call("getsidechaininfo", &[]).unwrap();
	info["pegged_asset"].as_str().unwrap().parse().unwrap()
}

pub fn invalidate(rt: &Regtest, block: &elements::BlockHash) {
	let _: Value = rt.client().call("invalidateblock", &[json!(block.to_string())]).unwrap();
}

pub fn in_mempool(rt: &Regtest, txid: &Txid) -> bool {
	let ids: Vec<String> = rt.client().call("getrawmempool", &[]).unwrap();
	ids.contains(&txid.to_string())
}
