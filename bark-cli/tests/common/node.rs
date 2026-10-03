//! An anchored proof-of-stake regtest chain, and the genesis block's free
//! coins (at a bare `OP_TRUE`) as the test's purse.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use elements::{AssetId, LockTime, OutPoint, Script, Transaction, TxIn, TxOut};
use serde_json::{json, Value};

use sequentia_ext::regtest::Regtest;
use sequentia_ext::{explicit_txout, fee_txout, AssetAmount, TxOutExt};

/// A fresh chain under its own directory.
pub fn start() -> Regtest {
	static N: AtomicUsize = AtomicUsize::new(0);
	let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
		.join(format!("arca-cli-regtest-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
	Regtest::pos_from_env(&dir, &["-par=1"])
}

pub fn op_true() -> Script {
	Script::from(vec![0x51])
}

fn free_coins(rt: &Regtest) -> (OutPoint, TxOut) {
	let genesis = rt.client().genesis_hash().unwrap();
	let block = rt.client().block(&genesis).unwrap();
	block.txdata.iter().flat_map(|tx| tx.output.iter().enumerate().map(move |(i, o)| (OutPoint::new(tx.txid(), i as u32), o.clone())))
		.find(|(_, o)| o.script_pubkey == op_true()).expect("the genesis block pays the free coins to OP_TRUE")
}

fn spend_op_true(coin: &(OutPoint, TxOut), outputs: Vec<TxOut>, fee: u64) -> Transaction {
	let have = coin.1.asset_amount().expect("an explicit coin");
	let spent: u64 = outputs.iter().filter(|o| o.explicit_asset() == Some(have.asset)).map(|o| o.explicit_value().unwrap()).sum();
	let mut output = outputs;
	output.push(explicit_txout(AssetAmount::new(have.asset, have.amount - spent - fee), op_true()));
	output.push(fee_txout(AssetAmount::new(have.asset, fee)));
	Transaction { version: 2, lock_time: LockTime::ZERO, input: vec![TxIn { previous_output: coin.0, ..Default::default() }], output }
}

pub fn policy_asset(rt: &Regtest) -> AssetId {
	let info: Value = rt.client().call("getsidechaininfo", &[]).unwrap();
	info["pegged_asset"].as_str().unwrap().parse().unwrap()
}

/// The test's own coins, at a bare `OP_TRUE`; its fees in the policy asset,
/// which is the test's business, not the wallets'.
pub struct Purse {
	pub policy: AssetId,
	coins: Vec<(OutPoint, TxOut)>,
}

impl Purse {
	pub fn new(rt: &Regtest) -> Purse {
		let policy = policy_asset(rt);
		let free = free_coins(rt);
		let tx = spend_op_true(&free, vec![], 10_000);
		let txid = rt.client().send_raw_transaction(&tx).unwrap();
		rt.produce_block().unwrap();
		Purse { policy, coins: vec![(OutPoint::new(txid, 0), tx.output[0].clone())] }
	}

	fn take(&mut self, asset: AssetId) -> (OutPoint, TxOut) {
		let i = self.coins.iter().position(|(_, o)| o.explicit_asset() == Some(asset)).expect("a purse coin of the asset");
		self.coins.remove(i)
	}

	/// Issues `amount` of a new asset into the purse, mined.
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

	/// Pays `outputs`, change back to the purse, the fee in the policy asset.
	/// Broadcast, not mined.
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

/// Lists `asset` for fees on the node at `rate`, keeping what is listed.
pub fn list_fee_asset(rt: &Regtest, asset: AssetId, rate: u64) {
	let rates: Value = rt.client().call("getfeeexchangerates", &[]).unwrap();
	let mut rates = rates.as_object().unwrap().clone();
	rates.insert(asset.to_string(), json!(rate));
	let _: Value = rt.client().call("setfeeexchangerates", &[Value::Object(rates)]).unwrap();
}

/// Buries everything in the chain two Bitcoin blocks deep.
pub fn bury(rt: &Regtest) {
	rt.mine_parent(2).unwrap();
	rt.anchor_to_parent_tip().unwrap();
}

pub fn median_time(rt: &Regtest) -> u32 {
	rt.client().blockchain_info().unwrap().median_time as u32
}

/// Moves the chain's median time at least `seconds` on.
pub fn advance_mtp(rt: &Regtest, seconds: u32) {
	let start = median_time(rt);
	let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
	let mock = now.max(start as u64) + seconds as u64 + 60;
	let _: Value = rt.client().call("setmocktime", &[json!(mock)]).unwrap();
	for _ in 0..12 {
		rt.produce_block().unwrap();
	}
	assert!(median_time(rt) >= start + seconds, "the median time moved from {} to {}", start, median_time(rt));
}
