//! Rounds, leaves and transfers on the anchored regtest chain, for the tests
//! that follow a coin from its round to an exit: a batch's schedule and tree,
//! a round that pays the batch output, its token and its connector, and the
//! transactions that bring a leaf on-chain and exit it.

use elements::secp256k1_zkp::Keypair;
use elements::{AssetIssuance, OutPoint, Script, Transaction, Txid};
use serde_json::json;

use arca_covenant::script::sha256;
use arca_covenant::sign::sign_digest;
use arca_covenant::spend::{FeeSource, KeySpend, UnrollTx};
use arca_covenant::transfer::Transfer;
use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeParams};
use arca_covenant::*;

use super::net::*;
use super::*;

pub const DAY: u64 = 24 * H as u64;
pub const LEAF: u64 = 10_000_000;
pub const MARGIN: u64 = 1_200;

/// A regtest chain and its relay floor.
pub struct Arca {
	pub net: Net,
	pub floor_per_kvb: u64,
}

impl Arca {
	pub fn start() -> Arca {
		let net = Net::start();
		let info = net.rpc("getmempoolinfo", json!([]));
		let floor_per_kvb = (info["minrelaytxfee"].as_f64().unwrap() * 1e8).round() as u64;
		Arca { net, floor_per_kvb }
	}

	/// A coin to issue a batch's token, and the schedule under `s`: expiries
	/// 28 and 56 days ahead.
	pub fn schedule(&mut self, s: &Keypair) -> (Coin, ClockSchedule) {
		let issuer = self.net.fund(vec![explicit(self.net.x, 2_000_000_000, op_true_spk())]).remove(0);
		let now = self.net.now();
		let sched = ClockSchedule::new(token_of(&issuer), xonly(s), delay(), vec![mt(now + 28 * DAY), mt(now + 56 * DAY)]).unwrap();
		(issuer, sched)
	}

	/// The tree of `leaves` in X at radix 4, reserves at four times the floor.
	pub fn tree(&self, sched: &ClockSchedule, leaves: &[LeafSpec]) -> Tree {
		Tree::build(TreeParams {
			asset: self.net.x, chain: self.net.chain, schedule: sched.clone(), burn: false, radix: 4,
			reserve: ReserveRule::FeeRate { floor_per_kvb: self.floor_per_kvb, multiple: 4 }, min_leaf: 1,
		}, leaves).unwrap()
	}

	/// The specification's policy for a wallet told `s`, at the tip's median time.
	pub fn policy(&self, s: &Keypair) -> WalletPolicy {
		WalletPolicy::new(self.net.chain, xonly(s), mt(self.net.mtp()))
	}

	/// Whether an unspent output on-chain pays `spk`: a receiver's index of
	/// the chain, here the node's set of unspent outputs.
	pub fn on_chain(&self, spk: &Script) -> bool {
		let hex: String = spk.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
		let r = self.net.rpc("scantxoutset", json!(["start", [format!("raw({})", hex)]]));
		!r["unspents"].as_array().unwrap().is_empty()
	}

	/// Whether `at` is an unspent output on-chain.
	pub fn unspent(&self, at: &OutPoint) -> bool {
		!self.net.rpc("gettxout", json!([at.txid.to_string(), at.vout])).is_null()
	}

	/// The block that holds `txid`.
	pub fn block_of(&self, txid: &Txid) -> String {
		let info = self.net.rpc("getrawtransaction", json!([txid.to_string(), true]));
		info["blockhash"].as_str().unwrap().to_string()
	}

	/// Disconnects the block that holds `txid`, a stand-in for an anchor
	/// rollback, and moves the clock on a minute.
	pub fn roll_back(&mut self, txid: &Txid) {
		let block = self.block_of(txid);
		self.net.rpc("invalidateblock", json!([block]));
		self.net.mock += 60;
		self.net.set_mock(self.net.mock);
	}

	/// Mines one block holding exactly `txs`, whatever the mempool holds.
	pub fn mine_with(&mut self, txs: &[&Transaction]) {
		self.net.rt.client().generate_block("raw(51)", txs).unwrap();
		for t in txs {
			assert!(self.net.rt.client().confirmations(&t.txid()).unwrap() >= 1);
		}
	}

	/// Brings a validated batch leaf on-chain: each node, then the entry with
	/// `preimage`, every fee from its reserve. Returns the leaf's outpoint.
	pub fn bring_leaf(&mut self, name: &str, valid: &ValidLeaf, auths: &[UnrollAuth], preimage: &[u8; 32]) -> OutPoint {
		let txs = valid.branch.unroll(OutPoint::new(valid.round_txid, valid.batch_vout), auths,
			&vec![FeeSource::Reserve; auths.len()]).unwrap();
		for (level, u) in txs.iter().enumerate() {
			self.net.pass(&format!("{}: unroll, level {}", name, level), &u.tx);
		}
		let e = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), preimage, &FeeSource::Reserve).unwrap();
		let id = self.net.pass(&format!("{}: entry into the leaf", name), &e.tx);
		OutPoint::new(id, 0)
	}

	/// [`Arca::bring_leaf`] for a coin that is a batch leaf.
	pub fn bring_coin(&mut self, name: &str, coin: &ValidCoin) -> OutPoint {
		match &coin.origin {
			ValidOrigin::Leaf { valid, preimage, auths } => self.bring_leaf(name, valid, auths, preimage),
			_ => unreachable!("a batch leaf"),
		}
	}
}

/// A leaf of `value` for `owner`, behind `h`, with nonces from `label`.
pub fn spec(owner: &Keypair, label: &str, value: u64, h: [u8; 32]) -> LeafSpec {
	LeafSpec {
		template: Template::Vtxo1, owner: xonly(owner), value,
		owner_nonce: label32(&format!("{} owner nonce", label)),
		operator_nonce: label32(&format!("{} operator nonce", label)),
		exit_delay: delay(), unlock_hash: h,
		htlc: None,
	}
}

/// A round spending `issuer` (which issues the token) and `more`: the batch
/// output, the token to clock 0, the connector output under the schedule's
/// operator, change in X and the fee. Returns it and the connector's index.
pub fn round_tx(net: &Net, issuer: &Coin, more: &[Coin], batch: &ExplicitOutput, sched: &ClockSchedule) -> (Transaction, u32) {
	let total: u64 = std::iter::once(issuer).chain(more).map(|c| c.txout.value.explicit().unwrap()).sum();
	let mut outs = vec![batch.txout(), explicit(sched.token, 1, sched.clock0_script_pubkey()),
		ConnectorPolicy { operator: sched.operator }.output(net.x, 5_000).txout()];
	let spent: u64 = outs.iter().filter(|o| o.asset.explicit() == Some(net.x)).map(|o| o.value.explicit().unwrap()).sum();
	outs.push(explicit(net.x, total - spent - 2_000, op_true_spk()));
	outs.push(fee(net.x, 2_000));
	let mut s = spend(0).coin(issuer, 0xffff_ffff);
	for c in more {
		s = s.coin(c, 0xffff_ffff);
	}
	let mut s = s.outputs(outs);
	s.tx.input[0].asset_issuance = AssetIssuance {
		asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: [0; 32],
		amount: elements::confidential::Value::Explicit(1), inflation_keys: elements::confidential::Value::Null,
		denomination: 0,
	};
	for i in 0..s.tx.input.len() {
		s.witness(i, op_true_witness());
	}
	(s.tx, 2)
}

/// Signs `ks` with `key` and finishes it with the signature, then `after`.
pub fn signed(net: &Net, ks: KeySpend, key: &Keypair, after: Vec<Vec<u8>>) -> UnrollTx {
	let sg = sign_digest(key, &ks.sighash(net.genesis).unwrap(), &ZERO_AUX);
	let mut below = vec![sg.as_ref().to_vec()];
	below.extend(after);
	ks.finish(below)
}

/// The owner's exit of `leaf` at `at`, holding `value` of `asset`, less 1,500
/// atoms of fee.
pub fn exit_tx(net: &Net, leaf: &LeafPolicy, at: OutPoint, asset: elements::AssetId, value: u64, key: &Keypair) -> Transaction {
	let ks = leaf.exit_tx(at, asset, value, &[ExplicitOutput::new(asset, value - 1_500, op_true_spk())], &FeeSource::Reserve).unwrap();
	signed(net, ks, key, vec![]).tx
}

/// The owner's unroll authorisations for every node of `valid`, at `t`.
pub fn owner_auths(valid: &ValidLeaf, owner: &Keypair, t: MedianTime) -> Vec<UnrollAuth> {
	valid.branch.nodes.iter().map(|n| n.owner_auth(sig(owner, &n.unroll_authorisation(t).digest), t, xonly(owner))).collect()
}

/// The base record of `tree`'s leaf `i`, as its owner hands it on.
pub fn base(tree: &Tree, i: usize, owner: &Keypair, preimage: [u8; 32], t: MedianTime) -> CoinRecord {
	let record = tree.record(i);
	let auths = record.branch().unwrap().nodes.iter().map(|n| (sig(owner, &n.unroll_authorisation(t).digest), t)).collect();
	CoinRecord::Leaf { record, preimage, auths }
}

/// One hop: `coin`, held under `prev`, paid by `owner` to the leaf `to`.
pub fn one_hop(prev: &CoinRecord, coin: &ValidCoin, owner: &Keypair, s: &Keypair, to: NewLeaf, chain: Chain) -> CoinRecord {
	let cpv = coin.value - MARGIN;
	let plan = TransferPlan {
		inputs: vec![(coin.clone(), cpv)],
		outputs: vec![ExplicitOutput::new(coin.asset, cpv - MARGIN, to.policy(xonly(s), chain).script_pubkey())],
	};
	let cp = plan.checkpoint_message(0).unwrap().digest;
	let re = plan.reassignment_message(0).unwrap().digest;
	CoinRecord::Transfer(Box::new(Transfer {
		inputs: vec![TransferInput {
			coin: prev.clone(), checkpoint_value: cpv,
			checkpoint: Pair { operator: sig(s, &cp), owner: sig(owner, &cp) },
			reassignment: Pair { operator: sig(s, &re), owner: sig(owner, &re) },
		}],
		outputs: plan.outputs.clone(), index: 0, leaf: to,
	}))
}

/// A receiver: its key and the leaf it is paid into, with delay `d`: the key
/// and owner nonce it publishes, and the creator nonce the sender draws.
pub fn party(label: &str, d: RelativeTime) -> (Keypair, NewLeaf) {
	let k = keypair(&format!("party {} key", label));
	let leaf = NewLeaf {
		owner: xonly(&k), owner_nonce: label32(&format!("party {} owner nonce", label)),
		creator_nonce: label32(&format!("party {} creator nonce", label)), exit_delay: d,
		htlc: None,
	};
	(k, leaf)
}

/// The inputs of a coin a reassignment created.
pub fn inputs(coin: &ValidCoin) -> Vec<ValidInput> {
	match &coin.origin {
		ValidOrigin::Transfer { inputs, .. } => inputs.clone(),
		_ => unreachable!("a reassignment's output"),
	}
}

/// A leaf funded straight on-chain, standing for an old leaf being given
/// up, and its id in the board form.
pub fn funded_leaf(net: &mut Net, owner: &Keypair, s: &Keypair, label: &str, value: u64) -> (LeafPolicy, Coin, LeafId) {
	let leaf = LeafPolicy {
		owner: xonly(owner), operator: xonly(s),
		salt: arca_covenant::leaf::leaf_salt(&label32(&format!("{} owner nonce", label)), &label32(&format!("{} operator nonce", label))),
		chain: net.chain, exit_delay: delay(),
		htlc: None,
	};
	let coin = net.fund(vec![explicit(net.x, value, leaf.script_pubkey())]).remove(0);
	let p = leaf.program();
	(leaf, coin, LeafId::compute(&p, &[], &p))
}

/// The pair owner and operator make over `f`'s message.
pub fn forfeit_pair(f: &Forfeit, owner: &Keypair, s: &Keypair) -> Pair {
	let d = f.message().digest;
	Pair { operator: sig(s, &d), owner: sig(owner, &d) }
}

/// The operator's issuance of `round`'s connector asset, signed by `s`.
pub fn issuance_tx(net: &Net, round: &Transaction, c: u32, s: &Keypair) -> Transaction {
	let conn = coin_of(round.txid(), c, round);
	let (a, v) = (conn.txout.asset.explicit().unwrap(), conn.txout.value.explicit().unwrap());
	let ks = ConnectorPolicy { operator: xonly(s) }.issuance(conn.outpoint, (a, v), op_true_spk(), &[], &FeeSource::Reserve).unwrap();
	signed(net, ks, s, vec![]).tx
}

/// The operator's claim of `f` at `f_coin`, with the connector asset's coin
/// `m` at input 1, publishing `preimage`; all but 1,500 atoms to OP_TRUE.
pub fn claim_tx(net: &Net, f: &Forfeit, f_coin: OutPoint, m: &Coin, s: &Keypair, preimage: &[u8; 32]) -> Transaction {
	let ks = f.claim(f_coin, (m.outpoint, m.txout.clone()),
		&[ExplicitOutput::new(f.asset, f.output().value - 1_500, op_true_spk())], op_true_spk(), &FeeSource::Reserve).unwrap();
	let mut u = signed(net, ks, s, vec![preimage.to_vec(), arca_covenant::script::scriptnum(Forfeit::CONNECTOR_INPUT as i64)]);
	u.tx.input[1].witness.script_witness = op_true_witness();
	u.tx
}

/// The owner's refund of `f` at `f_coin`, all but 1,500 atoms to OP_TRUE.
pub fn refund_tx(net: &Net, f: &Forfeit, f_coin: OutPoint, owner: &Keypair) -> Transaction {
	let ks = f.refund(f_coin, &[ExplicitOutput::new(f.asset, f.output().value - 1_500, op_true_spk())], &FeeSource::Reserve).unwrap();
	signed(net, ks, owner, vec![]).tx
}

/// What output 0 of the confirmed transaction `txid` pays.
pub fn paid(net: &Net, txid: &Txid) -> u64 {
	net.rt.client().raw_transaction(txid).unwrap().output[0].value.explicit().unwrap()
}

/// `SHA256(preimage)`.
pub fn hash(preimage: &[u8; 32]) -> [u8; 32] {
	sha256(preimage)
}
