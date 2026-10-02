//! The anchored regtest harness the regtest tests share: a Sequentia node
//! on an `elementsregtest` chain anchored to a Bitcoin regtest parent, a purse
//! of coins in the policy asset and two issued assets, and helpers that
//! broadcast a transaction that must confirm or force one that must not into a
//! block, asserting why the block refused it.

use std::path::PathBuf;
use std::str::FromStr;

use elements::encode::deserialize;
use elements::hex::FromHex;
use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, AssetIssuance, BlockHash, ContractHash, OutPoint, Script, Transaction, TxOut, Txid};
use serde_json::{json, Value};

use arca_covenant::{Chain, LeafPolicy, MedianTime, RelativeTime};
use sequentia_ext::regtest::Regtest;
use sequentia_ext::rpc::Error as RpcError;

use super::*;

pub const H: u32 = 3600;

#[derive(Clone, Debug)]
pub struct Coin {
	pub outpoint: OutPoint,
	pub txout: TxOut,
}

pub struct Row {
	pub name: String,
	pub vsize: String,
	pub mempool: String,
	pub block: String,
}

pub struct Net {
	pub rt: Regtest,
	pub genesis: BlockHash,
	pub chain: Chain,
	pub policy: AssetId,
	pub x: AssetId,
	pub y: AssetId,
	/// One coin per asset at the OP_TRUE tapscript, spent and replaced by its change.
	pub purse: Vec<Coin>,
	pub mock: u64,
	pub rows: Vec<Row>,
	pub refused: usize,
	pub confirmed: usize,
}

pub fn op_true_spk() -> Script {
	op_true().script_pubkey()
}

impl Net {
	pub fn start() -> Net {
		let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("covenant-regtest-{}", std::process::id()));
		// Scripts are checked inline, so a block refused for a script failure
		// names it, and each negative case asserts why its block was refused.
		let rt = Regtest::from_env(&dir, &["-par=1"]);
		let c = rt.client();
		let genesis = c.genesis_hash().unwrap();
		let info: Value = c.call("getsidechaininfo", &[]).unwrap();
		let policy = AssetId::from_str(info["pegged_asset"].as_str().unwrap()).unwrap();
		let block: Value = c.call("getblock", &[json!(genesis.to_string()), json!(2)]).unwrap();
		let mut free = None;
		for tx in block["tx"].as_array().unwrap() {
			for o in tx["vout"].as_array().unwrap() {
				if o["scriptPubKey"]["hex"] == "51" {
					let t: Transaction = deserialize(&Vec::<u8>::from_hex(tx["hex"].as_str().unwrap()).unwrap()).unwrap();
					let v = o["n"].as_u64().unwrap() as u32;
					free = Some(Coin { outpoint: OutPoint::new(t.txid(), v), txout: t.output[v as usize].clone() });
				}
			}
		}
		let free = free.expect("the genesis block pays the free coins to OP_TRUE");
		let mut net = Net {
			rt, genesis, chain: Chain::new(genesis), policy, x: policy, y: policy, purse: vec![], mock: 0,
			rows: vec![], refused: 0, confirmed: 0,
		};
		net.mock = net.tip_time() + 1;
		net.set_mock(net.mock);
		net.mine(1);

		// The free coins (a bare OP_TRUE, not standard to spend) move to the
		// OP_TRUE tapscript, which is.
		let total = free.txout.value.explicit().unwrap();
		let mut tx = Spend::new(0).input(free.outpoint, free.txout.clone(), 0xffff_ffff)
			.outputs(vec![explicit(policy, 1_000_000_000, op_true_spk()), explicit(policy, 1_000_000_000, op_true_spk()),
				explicit(policy, total - 2_000_000_000 - 10_000, op_true_spk()), fee(policy, 10_000)]).tx;
		tx.input[0].witness.script_witness = vec![];
		net.rt.client().generate_block("raw(51)", &[&tx]).unwrap();
		let txid = tx.txid();
		net.purse.push(Coin { outpoint: OutPoint::new(txid, 2), txout: tx.output[2].clone() });
		let issuers = [Coin { outpoint: OutPoint::new(txid, 0), txout: tx.output[0].clone() },
			Coin { outpoint: OutPoint::new(txid, 1), txout: tx.output[1].clone() }];

		// Two issued assets, X and Y, neither the policy asset. X is listed for
		// fees at 1:1; Y is not listed at all.
		let mut issued = vec![];
		for (i, coin) in issuers.iter().enumerate() {
			let contract = label32(&format!("asset {}", i));
			let a = AssetId::new_issuance(coin.outpoint, ContractHash::from_byte_array(contract));
			let mut s = Spend::new(0).input(coin.outpoint, coin.txout.clone(), 0xffff_ffff)
				.outputs(vec![explicit(a, 100_000_000_000, op_true_spk()),
					explicit(policy, 1_000_000_000 - 5_000, op_true_spk()), fee(policy, 5_000)]);
			s.tx.input[0].asset_issuance = AssetIssuance {
				asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: contract,
				amount: elements::confidential::Value::Explicit(100_000_000_000),
				inflation_keys: elements::confidential::Value::Null, denomination: 8,
			};
			s.witness(0, op_true_witness());
			let txid = net.pass_quiet(&s.tx);
			net.purse.push(Coin { outpoint: OutPoint::new(txid, 0), txout: s.tx.output[0].clone() });
			issued.push(a);
		}
		net.x = issued[0];
		net.y = issued[1];
		let rates: Value = net.rt.client().call("getfeeexchangerates", &[]).unwrap();
		let mut rates = rates.as_object().unwrap().clone();
		rates.insert(net.x.to_string(), json!(100_000_000));
		let _: Value = net.rt.client().call("setfeeexchangerates", &[Value::Object(rates)]).unwrap();
		println!("elementsregtest on genesis {}; X {} (listed 1:1), Y {} (not listed)", genesis, net.x, net.y);
		net
	}

	pub fn rpc(&self, method: &str, params: Value) -> Value {
		self.rt.client().call::<Value>(method, params.as_array().unwrap())
			.unwrap_or_else(|e| panic!("{} failed: {}", method, e))
	}

	pub fn tip_time(&self) -> u64 {
		let h = self.rt.client().best_block_hash().unwrap();
		self.rpc("getblockheader", json!([h.to_string()]))["time"].as_u64().unwrap()
	}

	pub fn mtp(&self) -> u64 {
		let h = self.rt.client().best_block_hash().unwrap();
		self.rpc("getblockheader", json!([h.to_string()]))["mediantime"].as_u64().unwrap()
	}

	/// The latest time the chain has seen: median time lags the tip by hours
	/// after a run of time jumps, so a lock meant to lie ahead starts here.
	pub fn now(&self) -> u64 {
		self.mock.max(self.tip_time())
	}

	pub fn height(&self) -> u64 {
		self.rt.client().block_count().unwrap()
	}

	pub fn set_mock(&self, t: u64) {
		self.rpc("setmocktime", json!([t]));
	}

	pub fn mine(&self, n: u64) {
		self.rt.client().generate_to_descriptor(n, "raw(51)").unwrap();
	}

	/// Mines until the tip's median time past is later than `t`.
	pub fn mtp_past(&mut self, t: u64) {
		while self.mtp() <= t {
			let gap = t - self.mtp();
			self.mock = self.mock.max(self.tip_time()) + (gap / 6 + 60).min(6 * H as u64);
			self.set_mock(self.mock);
			self.mine(1);
		}
	}

	/// The earliest tip median time at which an output of `txid`, under a
	/// time-based relative lock of `lock`, can be spent (BIP68).
	pub fn csv_ready(&self, txid: &Txid, lock: RelativeTime) -> u64 {
		let v = self.rpc("getrawtransaction", json!([txid.to_string(), true]));
		let block = v["blockhash"].as_str().unwrap();
		let height = self.rpc("getblockheader", json!([block]))["height"].as_u64().unwrap();
		let prev = self.rpc("getblockhash", json!([height - 1]));
		let coin_time = self.rpc("getblockheader", json!([prev]))["mediantime"].as_u64().unwrap();
		coin_time + lock.seconds() - 1
	}

	pub fn wait_csv(&mut self, txid: &Txid, lock: RelativeTime) {
		let t = self.csv_ready(txid, lock);
		self.mtp_past(t);
	}

	/// Pays `outs` from the purse, each output an asset's own coin, the fee in
	/// the policy asset. Returns the new coins, in order.
	pub fn fund(&mut self, outs: Vec<TxOut>) -> Vec<Coin> {
		let mut assets: Vec<AssetId> = outs.iter().map(|o| o.asset.explicit().unwrap()).collect();
		assets.push(self.policy);
		assets.sort();
		assets.dedup();
		let mut s = Spend::new(0);
		let mut change = vec![];
		for a in &assets {
			let i = self.purse.iter().enumerate().filter(|(_, c)| c.txout.asset.explicit() == Some(*a))
				.max_by_key(|(_, c)| c.txout.value.explicit()).map(|(i, _)| i).expect("a purse coin");
			let coin = self.purse.remove(i);
			let spent: u64 = outs.iter().filter(|o| o.asset.explicit() == Some(*a)).map(|o| o.value.explicit().unwrap()).sum();
			let fee_part = if *a == self.policy { 5_000 } else { 0 };
			change.push(explicit(*a, coin.txout.value.explicit().unwrap() - spent - fee_part, op_true_spk()));
			s = s.input(coin.outpoint, coin.txout, 0xffff_ffff);
		}
		let n = outs.len();
		s = s.outputs(outs).outputs(change).output(fee(self.policy, 5_000));
		for i in 0..s.tx.input.len() {
			s.witness(i, op_true_witness());
		}
		let txid = self.pass_quiet(&s.tx);
		for (j, o) in s.tx.output.iter().enumerate().skip(n) {
			if !o.is_fee() {
				self.purse.push(Coin { outpoint: OutPoint::new(txid, j as u32), txout: o.clone() });
			}
		}
		(0..n).map(|j| Coin { outpoint: OutPoint::new(txid, j as u32), txout: s.tx.output[j].clone() }).collect()
	}

	pub fn fee_coin(&mut self) -> Coin {
		self.fund(vec![explicit(self.policy, 20_000, op_true_spk())]).remove(0)
	}

	pub fn pass_quiet(&mut self, tx: &Transaction) -> Txid {
		let r = self.rt.client().test_mempool_accept(&[tx]).unwrap().remove(0);
		assert!(r.allowed, "refused: {:?}", r.reject_reason);
		let txid = self.rt.client().send_raw_transaction(tx).unwrap();
		self.mine(1);
		txid
	}

	/// Must be accepted by the mempool, broadcast and mined.
	pub fn pass(&mut self, name: &str, tx: &Transaction) -> Txid {
		let r = self.rt.client().test_mempool_accept(&[tx]).unwrap().remove(0);
		assert!(r.allowed, "{}: refused by testmempoolaccept: {:?}", name, r.reject_reason);
		let txid = self.rt.client().send_raw_transaction(tx).unwrap();
		self.mine(1);
		assert!(self.rt.client().confirmations(&txid).unwrap() >= 1, "{}: not confirmed", name);
		self.confirmed += 1;
		self.rows.push(Row { name: name.into(), vsize: r.vsize.map(|v| v.to_string()).unwrap_or_default(),
			mempool: "accepted".into(), block: "confirmed".into() });
		txid
	}

	/// Must be refused by the mempool, by sendrawtransaction, and in a block.
	pub fn refuse(&mut self, name: &str, tx: &Transaction, expect: &str) {
		let r = self.rt.client().test_mempool_accept(&[tx]).unwrap().remove(0);
		assert!(!r.allowed, "{}: ACCEPTED by testmempoolaccept", name);
		let reason = r.reject_reason.unwrap_or_default();
		let send = match self.rt.client().send_raw_transaction(tx) {
			Ok(_) => panic!("{}: BROADCAST", name),
			Err(RpcError::Rpc { code, message }) => format!("{} (code {})", message, code),
			Err(e) => panic!("{}: {}", name, e),
		};
		assert!(send.contains(expect), "{}: sendrawtransaction said {:?}, expected {:?}", name, send, expect);
		let h0 = self.height();
		let block = match self.rt.client().generate_block("raw(51)", &[tx]) {
			Ok(_) => panic!("{}: MINED by generateblock", name),
			Err(RpcError::Rpc { code, message }) => format!("{} (code {})", message, code),
			Err(e) => panic!("{}: {}", name, e),
		};
		assert_eq!(self.height(), h0);
		let why = block_reason(&reason);
		assert!(block.contains(&why), "{}: the block was refused with {:?}, not for the mempool's reason {:?}", name, block, why);
		self.refused += 1;
		self.rows.push(Row { name: name.into(), vsize: String::new(), mempool: send, block });
	}

	/// Accepted by the mempool and mined if this node's relay policy allows
	/// it; otherwise refused by relay policy with `expect` and mined with
	/// `generateblock`. Either way the block takes it.
	pub fn pass_or_mine(&mut self, name: &str, tx: &Transaction, expect: &str) -> Txid {
		let r = self.rt.client().test_mempool_accept(&[tx]).unwrap().remove(0);
		if r.allowed {
			self.pass(name, tx)
		} else {
			self.mine_policy_refused(name, tx, expect)
		}
	}

	/// Refused by relay policy with `expect`, valid in a block: mined with
	/// `generateblock`.
	pub fn mine_policy_refused(&mut self, name: &str, tx: &Transaction, expect: &str) -> Txid {
		let r = self.rt.client().test_mempool_accept(&[tx]).unwrap().remove(0);
		assert!(!r.allowed, "{}: accepted by testmempoolaccept", name);
		let reason = r.reject_reason.unwrap_or_default();
		assert!(reason.contains(expect), "{}: refused with {:?}, expected {:?}", name, reason, expect);
		self.rt.client().generate_block("raw(51)", &[tx]).unwrap();
		let txid = tx.txid();
		assert!(self.rt.client().confirmations(&txid).unwrap() >= 1);
		self.confirmed += 1;
		self.rows.push(Row { name: name.into(), vsize: r.vsize.map(|v| v.to_string()).unwrap_or_default(),
			mempool: format!("refused: {}", reason), block: "mined with generateblock".into() });
		txid
	}

	pub fn print(&self) {
		println!("\n{:<62} {:>6}  {:<70} | block", "transaction", "vsize", "mempool");
		for r in &self.rows {
			println!("{:<62} {:>6}  {:<70} | {}", r.name, r.vsize, r.mempool, r.block);
		}
		println!("\n{} transactions confirmed, {} negative cases refused by the mempool and in a block",
			self.confirmed, self.refused);
	}

	pub fn leaf(&self, owner: &Keypair, operator: &Keypair, salt: &str) -> LeafPolicy {
		LeafPolicy { owner: xonly(owner), operator: xonly(operator), salt: label32(salt), chain: self.chain,
			exit_delay: delay() }
	}

	pub fn witness_of(&self, txid: &Txid, vin: usize) -> Vec<Vec<u8>> {
		let tx = self.rt.client().raw_transaction(txid).unwrap();
		tx.input[vin].witness.script_witness.clone()
	}
}

pub fn delay() -> RelativeTime {
	RelativeTime::from_seconds_ceil(36 * H as u64).unwrap()
}

pub fn mt(t: u64) -> MedianTime {
	MedianTime::from_consensus(t as u32).unwrap()
}

/// What a block refused by a node checking scripts inline reports for a
/// transaction the mempool refused with `mempool`: the same script failure,
/// for a lock not yet reached `bad-txns-nonfinal`, and for an input that does
/// not exist or is spent `bad-txns-inputs-missingorspent`.
pub fn block_reason(mempool: &str) -> String {
	match mempool {
		"non-final" | "non-BIP68-final" => "bad-txns-nonfinal".into(),
		"missing-inputs" => "bad-txns-inputs-missingorspent".into(),
		other => other.into(),
	}
}

/// A transaction under assembly whose inputs are coins.
pub fn spend(lock: u32) -> Spend {
	Spend::new(lock)
}

pub trait SpendExt {
	fn coin(self, c: &Coin, seq: u32) -> Self;
}

impl SpendExt for Spend {
	fn coin(self, c: &Coin, seq: u32) -> Spend {
		self.input(c.outpoint, c.txout.clone(), seq)
	}
}

pub fn coin_of(txid: Txid, vout: u32, tx: &Transaction) -> Coin {
	Coin { outpoint: OutPoint::new(txid, vout), txout: tx.output[vout as usize].clone() }
}


/// The token a coin will issue.
pub fn token_of(issuer: &Coin) -> AssetId {
	AssetId::new_issuance(issuer.outpoint, ContractHash::from_byte_array([0; 32]))
}
