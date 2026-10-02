//! What a receiver refuses, on a Sequentia regtest chain: a coin whose
//! lineage holds a leaf outside its policy, a coin whose lineage holds a leaf
//! already on-chain, and a record whose layout makes its exit cost more than
//! the batch's own builder would.
//!
//! Each test shows the refusal, then runs on-chain what accepting the coin
//! would have cost: every transaction is built with this crate's builders,
//! signed with test keys and broadcast to a node on an anchored
//! `elementsregtest` chain started with `-par=1`; a negative case is refused
//! by the mempool and again when forced into a block, the block for the
//! mempool's reason.
//!
//! 1. An intermediate leaf with an exit delay of 512 seconds: the last
//!    receiver refuses the coin; the intermediate owner alone brings its leaf
//!    on-chain and exits it before the receiver's checkpoint can answer.
//! 2. A leaf transferred after it reached the chain and its exit delay
//!    passed: the receipt policy (the exit deadline, not the acceptance
//!    horizon) accepts the record, and the check of its lineage against the
//!    chain refuses it; the sender exits in the next block.
//! 3. Sixteen levels of one child each with no reserves, paid by a confirmed
//!    round: refused for its depth, its one-child nodes and its reserves.
//!
//! Needs `SEQUENTIAD_EXEC`; `--nocapture` prints every transaction.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::{AssetIssuance, OutPoint, Script, Transaction};
use serde_json::json;

use arca_covenant::gate::Members;
use arca_covenant::record::{LowestLevel, UpperLevel};
use arca_covenant::script::sha256;
use arca_covenant::sign::sign_digest;
use arca_covenant::spend::{FeeSource, KeySpend, UnrollTx};
use arca_covenant::transfer::Transfer;
use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeParams};
use arca_covenant::*;

use common::net::*;
use common::*;

const DAY: u64 = 24 * H as u64;
const LEAF: u64 = 10_000_000;
const MARGIN: u64 = 1_200;

struct Ctx {
	net: Net,
	floor_per_kvb: u64,
}

fn ctx() -> Ctx {
	let net = Net::start();
	let info = net.rpc("getmempoolinfo", json!([]));
	let floor_per_kvb = (info["minrelaytxfee"].as_f64().unwrap() * 1e8).round() as u64;
	Ctx { net, floor_per_kvb }
}

impl Ctx {
	fn schedule(&mut self, s: &Keypair) -> (Coin, ClockSchedule) {
		let issuer = self.net.fund(vec![explicit(self.net.x, 2_000_000_000, op_true_spk())]).remove(0);
		let now = self.net.now();
		let sched = ClockSchedule::new(token_of(&issuer), xonly(s), delay(), vec![mt(now + 28 * DAY), mt(now + 56 * DAY)]).unwrap();
		(issuer, sched)
	}

	fn tree(&self, sched: &ClockSchedule, leaves: &[LeafSpec]) -> Tree {
		Tree::build(TreeParams {
			asset: self.net.x, chain: self.net.chain, schedule: sched.clone(), burn: false, radix: 4,
			reserve: ReserveRule::FeeRate { floor_per_kvb: self.floor_per_kvb, multiple: 4 }, min_leaf: 1,
		}, leaves).unwrap()
	}

	fn policy(&self, s: &Keypair) -> WalletPolicy {
		WalletPolicy::new(self.net.chain, xonly(s), mt(self.net.mtp()))
	}

	/// Whether any output on-chain pays `spk`: the receiver's index of the
	/// chain, here the node's set of unspent outputs.
	fn on_chain(&self, spk: &Script) -> bool {
		let hex: String = spk.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
		let r = self.net.rpc("scantxoutset", json!(["start", [format!("raw({})", hex)]]));
		!r["unspents"].as_array().unwrap().is_empty()
	}
}

fn spec(owner: &Keypair, label: &str, value: u64, h: [u8; 32]) -> LeafSpec {
	LeafSpec {
		template: Template::Vtxo1, owner: xonly(owner), value,
		owner_nonce: label32(&format!("{} owner nonce", label)),
		operator_nonce: label32(&format!("{} operator nonce", label)),
		exit_delay: delay(), unlock_hash: h,
	}
}

/// A round spending `issuer`: the batch output, the token to clock 0, the
/// connector output, change and the fee.
fn round_tx(net: &Net, issuer: &Coin, batch: &ExplicitOutput, sched: &ClockSchedule) -> Transaction {
	let total = issuer.txout.value.explicit().unwrap();
	let mut outs = vec![batch.txout(), explicit(sched.token, 1, sched.clock0_script_pubkey()),
		ConnectorPolicy { operator: sched.operator }.output(net.x, 5_000).txout()];
	let spent: u64 = outs.iter().filter(|o| o.asset.explicit() == Some(net.x)).map(|o| o.value.explicit().unwrap()).sum();
	outs.push(explicit(net.x, total - spent - 2_000, op_true_spk()));
	outs.push(fee(net.x, 2_000));
	let mut s = spend(0).coin(issuer, 0xffff_ffff).outputs(outs);
	s.tx.input[0].asset_issuance = AssetIssuance {
		asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: [0; 32],
		amount: elements::confidential::Value::Explicit(1), inflation_keys: elements::confidential::Value::Null,
		denomination: 0,
	};
	s.witness(0, op_true_witness());
	s.tx
}

fn signed(net: &Net, ks: KeySpend, key: &Keypair) -> UnrollTx {
	let sg = sign_digest(key, &ks.sighash(net.genesis).unwrap(), &ZERO_AUX);
	ks.finish(vec![sg.as_ref().to_vec()])
}

/// Brings a batch leaf on-chain from its validated coin: the unroll, then the
/// entry, each paying from its reserve. Returns the leaf's outpoint.
fn bring_leaf(c: &mut Ctx, name: &str, coin: &ValidCoin) -> OutPoint {
	let (valid, preimage, auths) = match &coin.origin {
		ValidOrigin::Leaf { valid, preimage, auths } => (valid, preimage, auths),
		_ => unreachable!("a batch leaf"),
	};
	let txs = valid.branch.unroll(OutPoint::new(valid.round_txid, valid.batch_vout), auths,
		&vec![FeeSource::Reserve; auths.len()]).unwrap();
	for (level, u) in txs.iter().enumerate() {
		c.net.pass(&format!("{}: unroll, level {}", name, level), &u.tx);
	}
	let e = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), preimage, &FeeSource::Reserve).unwrap();
	let id = c.net.pass(&format!("{}: entry into the leaf", name), &e.tx);
	OutPoint::new(id, 0)
}

fn exit_tx(net: &Net, leaf: &LeafPolicy, at: OutPoint, asset: elements::AssetId, value: u64, key: &Keypair) -> Transaction {
	let ks = leaf.exit_tx(at, asset, value, &[ExplicitOutput::new(asset, value - 1_500, op_true_spk())], &FeeSource::Reserve).unwrap();
	signed(net, ks, key).tx
}

/// The base record of `tree`'s leaf `i`, as its owner hands it on.
fn base(tree: &Tree, i: usize, owner: &Keypair, preimage: [u8; 32], t: MedianTime) -> CoinRecord {
	let record = tree.record(i);
	let auths = record.branch().unwrap().nodes.iter().map(|n| (sig(owner, &n.unroll_authorisation(t).digest), t)).collect();
	CoinRecord::Leaf { record, preimage, auths }
}

/// One hop: `coin`, held under `prev`, paid by `owner` to the leaf `to`.
fn one_hop(prev: &CoinRecord, coin: &ValidCoin, owner: &Keypair, s: &Keypair, to: NewLeaf, chain: Chain) -> CoinRecord {
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

fn party(label: &str, d: RelativeTime) -> (Keypair, NewLeaf) {
	let k = keypair(&format!("lineage {} key", label));
	let leaf = NewLeaf {
		owner: xonly(&k), owner_nonce: label32(&format!("lineage {} owner nonce", label)),
		operator_nonce: label32(&format!("lineage {} operator nonce", label)), exit_delay: d,
	};
	(k, leaf)
}

fn inputs(coin: &ValidCoin) -> Vec<ValidInput> {
	match &coin.origin {
		ValidOrigin::Transfer { inputs, .. } => inputs.clone(),
		_ => unreachable!("a reassignment's output"),
	}
}

// ---------------------------------------------------------------------------
// 1. An intermediate leaf with a 512-second exit delay
// ---------------------------------------------------------------------------

#[test]
fn a_short_exit_delay_up_the_lineage_is_refused() {
	let mut c = ctx();
	let x = c.net.x;
	let s = keypair("lineage e2 operator");
	let a = keypair("lineage e2 A");
	let preimage = label32("lineage e2 preimage");
	let (issuer, sched) = c.schedule(&s);
	let tree = c.tree(&sched, &[spec(&a, "lineage e2 A", LEAF, sha256(&preimage)),
		spec(&keypair("lineage e2 bystander"), "lineage e2 bystander", LEAF, sha256(&label32("lineage e2 other")))]);
	let round = round_tx(&c.net, &issuer, &tree.batch_output(), &sched);
	c.net.pass("e2/round", &round);
	let rounds = vec![round];
	let a_base = base(&tree, 0, &a, preimage, mt(c.net.mtp() - 60));
	let policy = c.policy(&s);
	let a_coin = a_base.resolve(&rounds, &policy).unwrap();

	// A pays B, whose new leaf has an exit delay of one unit (512 s); B pays
	// D, whose own leaf has the specification's delay.
	let short = RelativeTime::from_units(1).unwrap();
	let (b, b_leaf) = party("e2 B", short);
	let b_record = one_hop(&a_base, &a_coin, &a, &s, b_leaf, c.net.chain);
	let b_coin = b_record.resolve(&rounds, &WalletPolicy { min_exit_delay: short, ..policy }).unwrap();
	let (_d, d_leaf) = party("e2 D", delay());
	let d_record = one_hop(&b_record, &b_coin, &b, &s, d_leaf, c.net.chain);

	// D refuses the coin, for B's leaf.
	let e = d_record.validate(&rounds, &policy.receipt(), &d_leaf.owner, &d_leaf.owner_nonce).unwrap_err();
	println!("e2: D REFUSES the coin: {} ({})", e, e.kind());
	assert!(matches!(e, TransferError::LineageExitDelay { hops: 1, delay: 1, .. }), "{}", e);

	// What D would have lost: B alone brings its leaf on-chain from its own
	// record and exits it 512 s later, before D's checkpoint.
	let a_at = bring_leaf(&mut c, "e2/A's leaf", &a_coin);
	let hop1 = inputs(&b_coin);
	let cpt = c.net.pass("e2/A's checkpoint (hop 1)", &hop1[0].checkpoint_tx(a_at, &FeeSource::Reserve).unwrap().tx);
	let ret = c.net.pass("e2/the reassignment creating B's leaf", &b_coin.reassignment_tx(&[OutPoint::new(cpt, 0)], &FeeSource::Reserve).unwrap().tx);
	let b_at = OutPoint::new(ret, 0);
	let ex = exit_tx(&c.net, &b_coin.leaf, b_at, x, b_coin.value, &b);
	c.net.refuse("e2/neg B's exit at once", &ex, "non-BIP68-final");
	let h0 = c.net.height();
	c.net.wait_csv(&ret, short);
	c.net.pass("e2/B's exit, 512 s after its leaf confirmed", &ex);
	println!("e2: B exited {} blocks after its leaf confirmed", c.net.height() - h0 - 1);
	// The checkpoint D would hold: built from D's record, accepted under a
	// policy that believes B's delay, it has nothing left to spend.
	let lax = WalletPolicy { min_exit_delay: short, ..policy.receipt() };
	let d_coin = d_record.validate(&rounds, &lax, &d_leaf.owner, &d_leaf.owner_nonce).unwrap();
	let dcp = inputs(&d_coin)[0].checkpoint_tx(b_at, &FeeSource::Reserve).unwrap();
	c.net.refuse("e2/neg D's checkpoint of B's leaf after B's exit", &dcp.tx, "bad-txns-inputs-missingorspent");
	c.net.print();
}

// ---------------------------------------------------------------------------
// 2. A leaf on-chain past its delay, transferred out of round
// ---------------------------------------------------------------------------

#[test]
fn a_leaf_already_on_chain_is_not_received() {
	let mut c = ctx();
	let x = c.net.x;
	let s = keypair("lineage e3 operator");
	let a = keypair("lineage e3 A");
	let preimage = label32("lineage e3 preimage");
	let (issuer, sched) = c.schedule(&s);
	let tree = c.tree(&sched, &[spec(&a, "lineage e3 A", LEAF, sha256(&preimage)),
		spec(&keypair("lineage e3 bystander"), "lineage e3 bystander", LEAF, sha256(&label32("lineage e3 other")))]);
	let round = round_tx(&c.net, &issuer, &tree.batch_output(), &sched);
	c.net.pass("e3/round", &round);
	let rounds = vec![round];
	let a_base = base(&tree, 0, &a, preimage, mt(c.net.mtp() - 60));
	let a_coin = a_base.resolve(&rounds, &c.policy(&s)).unwrap();

	// A unrolls its own leaf and waits out the exit delay.
	let a_at = bring_leaf(&mut c, "e3/A's leaf", &a_coin);
	c.net.wait_csv(&a_at.txid, delay());
	println!("e3: A's leaf is on-chain at {} and its exit delay has passed", a_at);

	// A pays B out of round. The record is good under the receipt policy,
	// which asks only for the exit deadline; the acceptance horizon would
	// refuse a coin from a round 36 hours old.
	let (_b, b_leaf) = party("e3 B", delay());
	let b_record = one_hop(&a_base, &a_coin, &a, &s, b_leaf, c.net.chain);
	let accept = c.policy(&s);
	let e = b_record.validate(&rounds, &accept, &b_leaf.owner, &b_leaf.owner_nonce).unwrap_err();
	assert!(matches!(e, TransferError::Record(RecordError::ExpiryTooSoon { .. })), "{}", e);
	let b_coin = b_record.validate(&rounds, &accept.receipt(), &b_leaf.owner, &b_leaf.owner_nonce).unwrap();
	println!("e3: the record validates under the receipt policy ({} atoms, {} hop)", b_coin.value, b_coin.hops);

	// B looks its lineage up on the chain, and refuses the coin.
	let lineage = b_coin.lineage();
	assert_eq!(lineage.len(), 2);
	assert_eq!(lineage[0].output, a_coin.output());
	let e = b_coin.check_lineage(|spk| c.on_chain(spk)).unwrap_err();
	println!("e3: B REFUSES the coin: {} ({})", e, e.kind());
	assert!(matches!(&e, TransferError::OnChain { kind: LineageKind::Leaf, script } if *script == a_coin.output().script_pubkey));

	// What B would have lost: A exits at once, and B's checkpoint has
	// nothing left to spend.
	c.net.pass("e3/A's exit of the leaf it gave B", &exit_tx(&c.net, &a_coin.leaf, a_at, x, LEAF, &a));
	let cp = inputs(&b_coin)[0].checkpoint_tx(a_at, &FeeSource::Reserve).unwrap();
	c.net.refuse("e3/neg B's checkpoint after A's exit", &cp.tx, "bad-txns-inputs-missingorspent");
	c.net.print();
}

// ---------------------------------------------------------------------------
// 3. Sixteen one-child levels with no reserves
// ---------------------------------------------------------------------------

#[test]
fn a_degenerate_layout_is_refused() {
	let mut c = ctx();
	let s = keypair("lineage e4 operator");
	let a = keypair("lineage e4 owner");
	let preimage = label32("lineage e4 preimage");
	let (issuer, sched) = c.schedule(&s);
	let proof = Members::new(xonly(&s), &[xonly(&a)]).proof(1);
	let owner_nonce = label32("lineage e4 owner nonce");
	let record = LeafRecord {
		template: Template::Vtxo1, owner: xonly(&a), owner_nonce, operator_nonce: label32("lineage e4 operator nonce"),
		exit_delay: delay(), asset: c.net.x, value: LEAF, unlock_hash: sha256(&preimage), entry_reserve: 0,
		chain: c.net.chain, schedule: sched.clone(), burn: false,
		upper: (0..15).map(|_| UpperLevel { index: 0, reserve: 0, siblings: vec![], member: proof.clone() }).collect(),
		lowest: LowestLevel { index: 0, reserve: 0, siblings: vec![], owners: vec![] },
	};
	let record = LeafRecord::from_bytes(&record.to_bytes().unwrap()).unwrap();
	let round = round_tx(&c.net, &issuer, &record.branch().unwrap().batch_output(), &sched);
	c.net.pass("e4/round paying the sixteen-level batch output", &round);
	let policy = c.policy(&s);
	let refuse = |p: &WalletPolicy| {
		let e = record.validate(&round, p, &xonly(&a), &owner_nonce).unwrap_err();
		println!("e4: REFUSED: {} ({})", e, e.kind());
		e
	};
	assert!(matches!(refuse(&policy), RecordError::TooManyLevels { levels: 16, max: 5 }));
	let deep = WalletPolicy { max_levels: arca_covenant::record::MAX_LEVELS, ..policy };
	assert!(matches!(refuse(&deep), RecordError::OneChild { level: 0 }));
	// The round does pay the batch output the record rebuilds: only the
	// policy stands between the wallet and the record.
	record.validate_batch_output(&round.output[0]).unwrap();
	let blind = WalletPolicy { min_reserve: ReserveFloor::Atoms(0), ..deep };
	assert!(matches!(refuse(&blind), RecordError::OneChild { level: 0 }), "whatever the floor");
	// A batch of one leaf is one node of one child; with no reserves it is
	// refused for its reserve alone.
	let (issuer, sched) = c.schedule(&s);
	let alone = LeafRecord { upper: vec![], schedule: sched.clone(), ..record.clone() };
	let round = round_tx(&c.net, &issuer, &alone.branch().unwrap().batch_output(), &sched);
	c.net.pass("e4/round paying a one-leaf batch with no reserves", &round);
	let e = alone.validate(&round, &policy, &xonly(&a), &owner_nonce).unwrap_err();
	println!("e4: a one-leaf batch with no reserves: {} ({})", e, e.kind());
	assert!(matches!(e, RecordError::NodeReserve { level: 0, reserve: 0, min: 1 }));
	alone.validate(&round, &blind, &xonly(&a), &owner_nonce).unwrap();
	c.net.print();
}
