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
	start_with(&[])
}

/// [`start`], the node given `extra` arguments as well.
pub fn start_with(extra: &[&str]) -> Regtest {
	static N: AtomicUsize = AtomicUsize::new(0);
	let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
		.join(format!("server-regtest-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
	let mut args = vec!["-par=1"];
	args.extend_from_slice(extra);
	Regtest::pos_from_env(&dir, &args)
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

/// The test's own coins, at a bare `OP_TRUE`, one per asset: the source of
/// every coin a test gives the server or a client. Its fees are paid in the
/// policy asset, which is the test's business, not the server's.
pub struct Purse {
	pub policy: AssetId,
	coins: Vec<(OutPoint, TxOut)>,
}

impl Purse {
	/// Moves the genesis block's free coins into the purse.
	pub fn new(rt: &Regtest) -> Purse {
		let policy = policy_asset(rt);
		let free = free_coins(rt);
		let tx = spend_op_true(&free, vec![], 10_000);
		let txid = rt.client().send_raw_transaction(&tx).unwrap();
		rt.produce_block().unwrap();
		Purse { policy, coins: vec![(OutPoint::new(txid, 0), tx.output[0].clone())] }
	}

	/// A purse coin of `asset`, given away: the caller spends it.
	pub fn take_coin(&mut self, asset: AssetId) -> (OutPoint, TxOut) {
		self.take(asset)
	}

	/// Puts a coin at a bare `OP_TRUE` back in the purse.
	pub fn put(&mut self, coin: (OutPoint, TxOut)) {
		self.coins.push(coin);
	}

	fn take(&mut self, asset: AssetId) -> (OutPoint, TxOut) {
		let i = self.coins.iter().position(|(_, o)| o.explicit_asset() == Some(asset)).expect("a purse coin of the asset");
		self.coins.remove(i)
	}

	/// Issues `amount` of a new asset (denomination 8) into the purse, and
	/// returns it. The transaction is in a block when this returns.
	pub fn issue(&mut self, rt: &Regtest, label: &str, amount: u64) -> AssetId {
		use elements::hashes::{sha256, Hash};
		let coin = self.take(self.policy);
		let contract = sha256::Hash::hash(label.as_bytes()).to_byte_array();
		let asset = AssetId::new_issuance(coin.0, elements::ContractHash::from_byte_array(contract));
		let mut tx = spend_op_true(&coin, vec![explicit_txout(AssetAmount::new(asset, amount), op_true())], 10_000);
		tx.input[0].asset_issuance = elements::AssetIssuance {
			asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK,
			asset_entropy: contract,
			amount: elements::confidential::Value::Explicit(amount),
			inflation_keys: elements::confidential::Value::Null,
			denomination: 8,
		};
		let txid = rt.client().send_raw_transaction(&tx).unwrap();
		rt.produce_block().unwrap();
		self.coins.push((OutPoint::new(txid, 0), tx.output[0].clone()));
		self.coins.push((OutPoint::new(txid, 1), tx.output[1].clone()));
		asset
	}

	/// Pays `outputs` from the purse, change back to it, the fee in the
	/// policy asset. Broadcast, not mined.
	pub fn pay(&mut self, rt: &Regtest, outputs: Vec<TxOut>) -> Transaction {
		let fee = 20_000u64;
		let mut assets: Vec<AssetId> = outputs.iter().map(|o| o.explicit_asset().unwrap()).collect();
		assets.push(self.policy);
		assets.sort();
		assets.dedup();
		let mut input = vec![];
		let mut change = vec![];
		for a in &assets {
			let coin = self.take(*a);
			let spent: u64 = outputs.iter().filter(|o| o.explicit_asset() == Some(*a)).map(|o| o.explicit_value().unwrap()).sum();
			let less = if *a == self.policy { fee } else { 0 };
			change.push(explicit_txout(AssetAmount::new(*a, coin.1.explicit_value().unwrap() - spent - less), op_true()));
			input.push(TxIn { previous_output: coin.0, ..Default::default() });
		}
		let n = outputs.len();
		let mut output = outputs;
		output.extend(change);
		output.push(fee_txout(AssetAmount::new(self.policy, fee)));
		let tx = Transaction { version: 2, lock_time: LockTime::ZERO, input, output };
		let txid = rt.client().send_raw_transaction(&tx).unwrap();
		for (j, o) in tx.output.iter().enumerate().skip(n) {
			if !o.is_fee() {
				self.coins.push((OutPoint::new(txid, j as u32), o.clone()));
			}
		}
		tx
	}
}

/// Lists `asset` for fees on the node at `rate` (reference units per 10^8
/// atoms), keeping what is listed.
pub fn list_fee_asset(rt: &Regtest, asset: AssetId, rate: u64) {
	let rates: Value = rt.client().call("getfeeexchangerates", &[]).unwrap();
	let mut rates = rates.as_object().unwrap().clone();
	rates.insert(asset.to_string(), json!(rate));
	let _: Value = rt.client().call("setfeeexchangerates", &[Value::Object(rates)]).unwrap();
}

/// Mines two parent blocks and anchors the tip to the parent's tip: every
/// block before it is then buried two Bitcoin blocks.
pub fn bury(rt: &Regtest) {
	rt.mine_parent(2).unwrap();
	rt.anchor_to_parent_tip().unwrap();
}
