//! A checkpoint with its owner's exit, on regtest: a reassignment of several
//! owners' coins that can never complete gives each owner's coin back alone.
//!
//! A swap is one reassignment of A's X and C's Y. C and the operator sign a
//! second spend of C's checkpoint, so the swap can never confirm. A's
//! checkpoint is `[collab, exit]`: A takes its coin home after its exit
//! delay with no operator signature, and only then. A good swap completes
//! inside the delay, and A cannot pull out of it after. The same for a fill
//! of a resting order killed by a second fill the operator signs alone, for
//! a batch with a sweep (`[collab, [sweep, exit]]`), and for `vtxo-2` coins.
//!
//! Each negative case is refused by the mempool and again in a block
//! (`generateblock`), for the mempool's reason (the node checks scripts
//! inline, `-par=1`).
//!
//! Needs `SEQUENTIAD_EXEC`; `--nocapture` prints every transaction.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Script, Transaction};
use serde_json::json;

use arca_covenant::script::sha256;
use arca_covenant::spend::{collab_tx, FeeSource};
use arca_covenant::transfer::{reassignment_tx, FillCoin, FillLeaf, OrderFill, COIN_RECORD_VERSION, COIN_RECORD_VERSION_EXIT};
use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeParams};
use arca_covenant::*;

use common::chain::{record_for, sign_plan};
use common::net::*;
use common::round::*;
use common::*;

/// One node at a time in this binary: the harness picks each node's ports
/// by binding and releasing them, so nodes started at once can be handed the
/// same port and answer for each other.
static ONE_NODE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn one_node() -> std::sync::MutexGuard<'static, ()> {
	ONE_NODE.lock().unwrap_or_else(|e| e.into_inner())
}

const SIG: &str = "Invalid Schnorr signature";
const GONE: &str = "bad-txns-inputs-missingorspent";
const EARLY: &str = "non-BIP68-final";
const SHORT: &str = "Locktime requirement not satisfied";

/// A batch of `asset` without a sweep (or with `sched`'s), RECLAIM-D on its
/// lowest nodes, as the testnet's operator builds them.
fn tree_of(c: &Arca, s: &Keypair, asset: AssetId, sched: Option<&ClockSchedule>, leaves: &[LeafSpec]) -> Tree {
	Tree::build(TreeParams {
		asset, chain: c.net.chain, schedule: sched.cloned().unwrap_or_else(|| ClockSchedule::never(xonly(s))), burn: false,
		delegated_reclaim: true, radix: 4, reserve: ReserveRule::FeeRate { floor_per_kvb: c.floor_per_kvb, multiple: 4 }, min_leaf: 1,
	}, leaves).unwrap()
}

/// A round paying `batch`, with a connector output in X and, for a batch
/// with a sweep, the clock's token from `sched`'s issuer.
fn round(c: &mut Arca, name: &str, s: &Keypair, batch: &ExplicitOutput, clock: Option<(&Coin, &ClockSchedule)>) -> Transaction {
	if let Some((issuer, sched)) = clock {
		if batch.asset == c.net.x {
			let (tx, _) = round_tx(&c.net, issuer, &[], batch, sched);
			c.net.pass(name, &tx);
			return tx;
		}
		// The batch in another asset: its value from a coin of that asset.
		let funds = c.net.fund(vec![explicit(batch.asset, batch.value, op_true_spk())]).remove(0);
		let xin = issuer.txout.value.explicit().unwrap();
		let mut sp = spend(0).coin(issuer, 0xffff_ffff).coin(&funds, 0xffff_ffff).outputs(vec![batch.txout(),
			explicit(sched.token, 1, sched.clock0_script_pubkey()), ConnectorPolicy { operator: sched.operator }.output(c.net.x, 5_000).txout(),
			explicit(c.net.x, xin - 5_000 - 2_000, op_true_spk()), fee(c.net.x, 2_000)]);
		sp.tx.input[0].asset_issuance = elements::AssetIssuance {
			asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: [0; 32],
			amount: elements::confidential::Value::Explicit(1), inflation_keys: elements::confidential::Value::Null, denomination: 0,
		};
		sp.witness(0, op_true_witness());
		sp.witness(1, op_true_witness());
		c.net.pass(name, &sp.tx);
		return sp.tx;
	}
	let x = c.net.x;
	let mut outs = vec![explicit(x, 200_000, op_true_spk())];
	if batch.asset != x {
		outs.push(explicit(batch.asset, batch.value, op_true_spk()));
	} else {
		outs[0] = explicit(x, batch.value + 200_000, op_true_spk());
	}
	let coins = c.net.fund(outs);
	let xin = coins[0].txout.value.explicit().unwrap();
	let xb = if batch.asset == x { batch.value } else { 0 };
	let out = vec![batch.txout(), ConnectorPolicy { operator: xonly(s) }.output(x, 5_000).txout(),
		explicit(x, xin - xb - 5_000 - 2_000, op_true_spk()), fee(x, 2_000)];
	let mut sp = spend(0);
	for k in &coins {
		sp = sp.coin(k, 0xffff_ffff);
	}
	let mut sp = sp.outputs(out);
	for i in 0..coins.len() {
		sp.witness(i, op_true_witness());
	}
	c.net.pass(name, &sp.tx);
	sp.tx
}

/// Brings a batch leaf on-chain, skipping the nodes already there.
fn bring(c: &mut Arca, name: &str, coin: &ValidCoin) -> OutPoint {
	let ValidOrigin::Leaf { valid, preimage, auths } = &coin.origin else { unreachable!() };
	let txs = valid.branch.unroll(OutPoint::new(valid.round_txid, valid.batch_vout), auths,
		&vec![FeeSource::Reserve; auths.len()]).unwrap();
	for (level, u) in txs.iter().enumerate() {
		if c.net.rt.client().confirmations(&u.tx.txid()).unwrap_or(0) == 0 {
			c.net.pass(&format!("{}: unroll, level {}", name, level), &u.tx);
		}
	}
	let e = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), preimage, &FeeSource::Reserve).unwrap();
	OutPoint::new(c.net.pass(&format!("{}: entry", name), &e.tx), 0)
}

/// The owner's exit of checkpoint `cp` at `at` (holding `value` of `asset`),
/// signed by `key`, input 0's sequence lowered by `short` units.
fn cp_exit(c: &Arca, cp: &CheckpointPolicy, at: OutPoint, asset: AssetId, value: u64, key: &Keypair, short: u32) -> Transaction {
	let ks = cp.exit_tx(at, asset, value, &[ExplicitOutput::new(asset, value - 2_000, op_true_spk())], &FeeSource::Reserve).unwrap();
	let mut u = signed(&c.net, ks, key, vec![]);
	if short > 0 {
		// Re-signed over the shorter sequence, so only the lock fails.
		let mut ks = cp.exit_tx(at, asset, value, &[ExplicitOutput::new(asset, value - 2_000, op_true_spk())], &FeeSource::Reserve).unwrap();
		ks.tx.input[0].sequence = elements::Sequence(ks.tx.input[0].sequence.0 - short);
		u = signed(&c.net, ks, key, vec![]);
	}
	u.tx
}

fn thief() -> Script {
	op_true_spk()
}

/// C and the operator's second reassignment of C's checkpoint `ccp` (C's
/// coin `cc`, checkpoint value `cpv`, input `w_in` of the swap), all to the
/// adversary.
fn kill(c: &mut Arca, tag: &str, s: &Keypair, ck: &Keypair, cc: &ValidCoin, w_in: &ValidInput, ccp: OutPoint, cpv: u64) {
	let back = vec![ExplicitOutput::new(cc.asset, cpv - MARGIN, thief())];
	let bp = TransferPlan { checkpoint_exit: w_in.checkpoint.exit.is_some(), inputs: vec![(cc.clone(), cpv)], outputs: back.clone() };
	assert_eq!(bp.checkpoint(0), w_in.checkpoint, "the second spend is of the same checkpoint");
	let d = bp.reassignment_message(0).unwrap().digest;
	let second = ValidInput { reassignment_pair: Pair { operator: sig(s, &d), owner: sig(ck, &d) }, ..w_in.clone() };
	c.net.pass(&format!("{}/ATTACK C + operator: a second reassignment of C's checkpoint", tag),
		&reassignment_tx(&[second], &back, &[ccp], &FeeSource::Reserve).unwrap().tx);
}

/// A swap of A's X for C's Y in batches `tx_` and `ty_` (rounds `rounds`),
/// dead or good, under `policy`, every checkpoint with its owner's exit.
#[allow(clippy::too_many_arguments)]
fn swap_case(c: &mut Arca, tag: &str, s: &Keypair, policy: &WalletPolicy, rounds: &[Transaction], (tx_, ty_): (&Tree, &Tree), i: usize,
	keys: (&Keypair, &Keypair), pre: ([u8; 32], [u8; 32]), dead: bool, v2: bool, t: MedianTime)
{
	let (x, y) = (c.net.x, c.net.y);
	let (ak, ck) = keys;
	let policy = &WalletPolicy { now: mt(c.net.mtp()), ..policy.clone() };
	let ab = base(tx_, i, ak, pre.0, t);
	let cb = base(ty_, i, ck, pre.1, t);
	let (acoin, ccoin) = (ab.resolve(rounds, policy).unwrap(), cb.resolve(rounds, policy).unwrap());
	assert_eq!((acoin.leaf.v2, ccoin.leaf.v2), (v2, v2));
	let leaf = |what: &str| {
		let (_, mut l) = party(&format!("{} {}", tag, what), delay());
		l.v2 = v2;
		l
	};
	let (ay_leaf, cx_leaf, ac_leaf) = (leaf("A gets Y"), leaf("C gets X"), leaf("A change"));
	let cpv = LEAF - MARGIN;
	let plan = TransferPlan { checkpoint_exit: true, inputs: vec![(acoin.clone(), cpv), (ccoin.clone(), cpv)],
		outputs: vec![ExplicitOutput::new(y, cpv, ay_leaf.policy(xonly(s), c.net.chain).script_pubkey()),
			ExplicitOutput::new(x, 4_000_000, cx_leaf.policy(xonly(s), c.net.chain).script_pubkey()),
			ExplicitOutput::new(x, cpv - 4_000_000 - MARGIN, ac_leaf.policy(xonly(s), c.net.chain).script_pubkey())] };
	let pw = sign_plan(&plan, &[ak, ck], s);
	let rec = record_for(&plan, &[&ab, &cb], &pw, 0, ay_leaf);
	let bytes = rec.to_bytes().unwrap();
	assert_eq!(bytes[0], COIN_RECORD_VERSION_EXIT, "a record with a checkpoint exit is format version 2");
	assert_eq!(CoinRecord::from_bytes(&bytes).unwrap(), rec, "the binary form reads back");
	let ay = rec.validate(rounds, &policy.receipt(), &ay_leaf.owner, &ay_leaf.owner_nonce).unwrap();
	assert!(ay.has_checkpoint_exit());
	let w_in = inputs(&ay);
	let acp = w_in[0].checkpoint;
	assert_eq!(acp.exit, Some(acoin.leaf.exit_delay), "the exit waits the coin's own exit delay");
	assert_eq!(acp.exit_script().unwrap(), arca_covenant::LeafPolicy { v2: false, ..acoin.leaf }.exit_script(),
		"the exit is the coin's own exit script");
	// The pair into the exit checkpoint does not fit a checkpoint without one.
	let a_at_probe = acoin.leaf.clone();
	let plain_cp = ExplicitOutput::new(x, cpv, acoin.checkpoint().script_pubkey());
	assert!(a_at_probe.verify(x, acoin.value, &[plain_cp], &w_in[0].checkpoint_pair).is_err(),
		"the checkpoint pair names the checkpoint's output, exit included");

	let c_at = bring(c, &format!("{}/C's leaf on-chain", tag), &ccoin);
	let ccp = OutPoint::new(c.net.pass(&format!("{}/C's checkpoint", tag), &w_in[1].checkpoint_tx(c_at, &FeeSource::Reserve).unwrap().tx), 0);
	if dead {
		kill(c, tag, s, ck, &ccoin, &w_in[1], ccp, cpv);
	}
	let a_at = bring(c, &format!("{}/A's leaf on-chain", tag), &acoin);
	// The checkpoint pair rebound to a checkpoint without the exit.
	let rebound = collab_tx(&acoin.leaf, a_at, x, acoin.value, &[ExplicitOutput::new(x, cpv, acoin.checkpoint().script_pubkey())],
		&w_in[0].checkpoint_pair, &FeeSource::Reserve).unwrap().tx;
	// A vtxo-2 leaf's program checks the pair inside a jet.
	c.net.refuse(&format!("{}/neg A's checkpoint pair rebound to a checkpoint with no exit", tag), &rebound,
		if v2 { "Assertion failed inside jet" } else { SIG });
	let acp_tx = w_in[0].checkpoint_tx(a_at, &FeeSource::Reserve).unwrap().tx;
	let acp_id = c.net.pass(&format!("{}/A's checkpoint with its exit, from the record", tag), &acp_tx);
	let acp_at = OutPoint::new(acp_id, 0);
	c.net.refuse(&format!("{}/neg A's checkpoint exit before its delay", tag), &cp_exit(c, &acp, acp_at, x, cpv, ak, 0), EARLY);
	let swap = ay.reassignment_tx(&[acp_at, ccp], &FeeSource::Reserve).unwrap().tx;
	if dead {
		c.net.refuse(&format!("{}/neg the swap's reassignment", tag), &swap, GONE);
		c.net.wait_csv(&acp_id, delay());
		c.net.refuse(&format!("{}/neg A's checkpoint exit signed by the operator", tag), &cp_exit(c, &acp, acp_at, x, cpv, s, 0), SIG);
		c.net.refuse(&format!("{}/neg A's checkpoint exit signed by C", tag), &cp_exit(c, &acp, acp_at, x, cpv, ck, 0), SIG);
		c.net.refuse(&format!("{}/neg A's checkpoint exit, sequence one unit short", tag), &cp_exit(c, &acp, acp_at, x, cpv, ak, 1), SHORT);
		let home = cp_exit(c, &acp, acp_at, x, cpv, ak, 0);
		c.net.pass(&format!("{}/A's own exit of its checkpoint after the delay, no operator", tag), &home);
		assert_eq!(home.output[0].value.explicit(), Some(cpv - 2_000));
	} else {
		let id = c.net.pass(&format!("{}/the swap's reassignment inside the delay", tag), &swap);
		assert_eq!(swap.output[0].script_pubkey, ay.leaf.script_pubkey());
		c.net.wait_csv(&id, delay());
		c.net.wait_csv(&acp_id, delay());
		c.net.refuse(&format!("{}/neg A pulls out of the completed swap by its checkpoint exit", tag), &cp_exit(c, &acp, acp_at, x, cpv, ak, 0), GONE);
	}
}

fn y_listed(c: &Arca) {
	let rates = c.net.rpc("getfeeexchangerates", json!([]));
	let mut rates = rates.as_object().unwrap().clone();
	rates.insert(c.net.y.to_string(), json!(100_000_000));
	c.net.rpc("setfeeexchangerates", json!([serde_json::Value::Object(rates)]));
}

#[test]
fn a_dead_swap_returns_each_coin_by_its_checkpoint_exit() {
	let _one = one_node();
	let mut c = Arca::start();
	y_listed(&c);
	let (x, y) = (c.net.x, c.net.y);
	let s = keypair("ob1 operator");
	let strict = WalletPolicy::no_sweep(c.net.chain, xonly(&s), mt(c.net.mtp()));
	let ak: Vec<Keypair> = (0..2).map(|i| keypair(&format!("ob1 A{}", i))).collect();
	let ck: Vec<Keypair> = (0..2).map(|i| keypair(&format!("ob1 C{}", i))).collect();
	let apre: Vec<[u8; 32]> = (0..2).map(|i| label32(&format!("ob1 A pre {}", i))).collect();
	let cpre: Vec<[u8; 32]> = (0..2).map(|i| label32(&format!("ob1 C pre {}", i))).collect();
	let aspec: Vec<LeafSpec> = (0..2).map(|i| spec(&ak[i], &format!("ob1 A leaf {}", i), LEAF, sha256(&apre[i]))).collect();
	let cspec: Vec<LeafSpec> = (0..2).map(|i| spec(&ck[i], &format!("ob1 C leaf {}", i), LEAF, sha256(&cpre[i]))).collect();
	let tx_ = tree_of(&c, &s, x, None, &aspec);
	let ty_ = tree_of(&c, &s, y, None, &cspec);
	let rx = round(&mut c, "round X (no sweep)", &s, &tx_.batch_output(), None);
	let ry = round(&mut c, "round Y (no sweep)", &s, &ty_.batch_output(), None);
	let rounds = vec![rx, ry];
	let t0 = mt(c.net.mtp() - 60);
	for (i, dead) in [(0usize, true), (1, false)] {
		let tag = if dead { "dead swap" } else { "good swap" };
		swap_case(&mut c, tag, &s, &strict, &rounds, (&tx_, &ty_), i, (&ak[i], &ck[i]), (apre[i], cpre[i]), dead, false, t0);
	}
	c.net.print();
}

#[test]
fn a_dead_swap_in_batches_with_a_sweep() {
	let _one = one_node();
	let mut c = Arca::start();
	y_listed(&c);
	let (x, y) = (c.net.x, c.net.y);
	let s = keypair("ob1 sweep operator");
	let policy = c.policy(&s);
	let (ak, ck) = (keypair("ob1 sweep A"), keypair("ob1 sweep C"));
	let (apre, cpre) = (label32("ob1 sweep A pre"), label32("ob1 sweep C pre"));
	let (issuer_x, sched_x) = c.schedule(&s);
	let tx_ = tree_of(&c, &s, x, Some(&sched_x), &[spec(&ak, "ob1 sweep A leaf", LEAF, sha256(&apre)),
		spec(&keypair("ob1 sweep by x"), "ob1 sweep by x", LEAF, sha256(&label32("bx")))]);
	let rx = round(&mut c, "round X (with a sweep)", &s, &tx_.batch_output(), Some((&issuer_x, &sched_x)));
	let (issuer_y, sched_y) = c.schedule(&s);
	let ty_ = tree_of(&c, &s, y, Some(&sched_y), &[spec(&ck, "ob1 sweep C leaf", LEAF, sha256(&cpre)),
		spec(&keypair("ob1 sweep by y"), "ob1 sweep by y", LEAF, sha256(&label32("by")))]);
	let ry = round(&mut c, "round Y (with a sweep)", &s, &ty_.batch_output(), Some((&issuer_y, &sched_y)));
	let rounds = vec![rx, ry];
	let t = mt(c.net.mtp() - 60);
	let acoin = base(&tx_, 0, &ak, apre, t).resolve(&rounds, &policy).unwrap();
	let cp = acoin.checkpoint_of(true);
	assert!(cp.sweep.is_some() && cp.exit.is_some());
	assert_eq!(cp.taproot().script_pubkey(),
		arca_covenant::taptree::TapOutput::new(vec![(1, cp.collab_script()), (2, cp.sweep_script().unwrap()), (2, cp.exit_script().unwrap())])
			.script_pubkey(), "[collab, [sweep, exit]]");
	swap_case(&mut c, "sweep dead swap", &s, &policy, &rounds, (&tx_, &ty_), 0, (&ak, &ck), (apre, cpre), true, false, t);
	c.net.print();
}

#[test]
fn a_dead_swap_of_vtxo2_coins() {
	let _one = one_node();
	let mut c = Arca::start();
	y_listed(&c);
	let (x, y) = (c.net.x, c.net.y);
	let s = keypair("ob1 v2 operator");
	let strict = WalletPolicy::no_sweep(c.net.chain, xonly(&s), mt(c.net.mtp()));
	let ak: Vec<Keypair> = (0..2).map(|i| keypair(&format!("ob1 v2 A{}", i))).collect();
	let ck: Vec<Keypair> = (0..2).map(|i| keypair(&format!("ob1 v2 C{}", i))).collect();
	let apre: Vec<[u8; 32]> = (0..2).map(|i| label32(&format!("ob1 v2 A pre {}", i))).collect();
	let cpre: Vec<[u8; 32]> = (0..2).map(|i| label32(&format!("ob1 v2 C pre {}", i))).collect();
	let v2 = |k: &Keypair, l: &str, h| LeafSpec { template: Template::Vtxo2, ..spec(k, l, LEAF, h) };
	let aspec: Vec<LeafSpec> = (0..2).map(|i| v2(&ak[i], &format!("ob1 v2 A leaf {}", i), sha256(&apre[i]))).collect();
	let cspec: Vec<LeafSpec> = (0..2).map(|i| v2(&ck[i], &format!("ob1 v2 C leaf {}", i), sha256(&cpre[i]))).collect();
	let tx_ = tree_of(&c, &s, x, None, &aspec);
	let ty_ = tree_of(&c, &s, y, None, &cspec);
	let rx = round(&mut c, "round X of vtxo-2 leaves", &s, &tx_.batch_output(), None);
	let ry = round(&mut c, "round Y of vtxo-2 leaves", &s, &ty_.batch_output(), None);
	let rounds = vec![rx, ry];
	let t0 = mt(c.net.mtp() - 60);
	for (i, dead) in [(0usize, true), (1, false)] {
		let tag = if dead { "v2 dead swap" } else { "v2 good swap" };
		swap_case(&mut c, tag, &s, &strict, &rounds, (&tx_, &ty_), i, (&ak[i], &ck[i]), (apre[i], cpre[i]), dead, true, t0);
	}
	c.net.print();
}

/// A record's exit flag is part of what its pairs sign: a record that
/// claims the exit for pairs made without it, or the other way round, is
/// refused; a version 1 record never carries the flag, and a version 2
/// record without any exit is not its encoding.
#[test]
fn the_exit_flag_is_signed_and_has_one_encoding() {
	let _one = one_node();
	let mut c = Arca::start();
	let x = c.net.x;
	let s = keypair("ob1 flag operator");
	let strict = WalletPolicy::no_sweep(c.net.chain, xonly(&s), mt(c.net.mtp()));
	let a = keypair("ob1 flag A");
	let pre = label32("ob1 flag pre");
	let t_ = tree_of(&c, &s, x, None, &[spec(&a, "ob1 flag leaf", LEAF, sha256(&pre)),
		spec(&keypair("ob1 flag by"), "ob1 flag by", LEAF, sha256(&label32("fb")))]);
	let r = round(&mut c, "round X", &s, &t_.batch_output(), None);
	let rounds = vec![r];
	let ab = base(&t_, 0, &a, pre, mt(c.net.mtp() - 60));
	let coin = ab.resolve(&rounds, &strict).unwrap();
	let (_, to) = party("ob1 flag B", delay());
	for exit in [false, true] {
		let plan = TransferPlan { checkpoint_exit: exit, inputs: vec![(coin.clone(), LEAF - MARGIN)],
			outputs: vec![ExplicitOutput::new(x, LEAF - 2 * MARGIN, to.policy(xonly(&s), c.net.chain).script_pubkey())] };
		let p = sign_plan(&plan, &[&a], &s);
		let rec = record_for(&plan, &[&ab], &p, 0, to);
		let bytes = rec.to_bytes().unwrap();
		assert_eq!(bytes[0], if exit { COIN_RECORD_VERSION_EXIT } else { COIN_RECORD_VERSION });
		rec.validate(&rounds, &strict.receipt(), &to.owner, &to.owner_nonce).unwrap();
		// The flag flipped under the same signatures.
		let CoinRecord::Transfer(mut t) = rec.clone() else { unreachable!() };
		t.inputs[0].exit = !exit;
		let e = CoinRecord::Transfer(t.clone()).validate(&rounds, &strict.receipt(), &to.owner, &to.owner_nonce).unwrap_err();
		println!("exit {} flipped to {}: refused, {} ({})", exit, !exit, e, e.kind());
		assert!(matches!(e, arca_covenant::transfer::TransferError::Pair { pair: "checkpoint", .. }), "{}", e);
		if exit {
			// Version 1 bytes with the flag byte: the version names no flag.
			let mut v1 = bytes.clone();
			v1[0] = COIN_RECORD_VERSION;
			assert!(CoinRecord::from_bytes(&v1).is_err());
			// Version 2 with the one flag cleared: a version 2 record with no
			// exit anywhere is not that record's one encoding.
			let at = 1 + 1 + 1 + (ab.to_bytes().unwrap().len() - 1) + 8 + 4 * 64;
			assert_eq!(bytes[at], 1, "the input's exit flag");
			let mut b = bytes.clone();
			b[at] = 0;
			let e = CoinRecord::from_bytes(&b).unwrap_err();
			println!("a version 2 record with no exit: refused, {}", e);
		}
	}
	// A reader of version 1 alone takes a version 2 record as a format it
	// does not know (as a version 3 is to this one), never as malformed.
	let unknown = CoinRecord::from_bytes(&[COIN_RECORD_VERSION_EXIT + 1]).unwrap_err();
	assert!(unknown.is_unknown_format());
}

// ---------------------------------------------------------------------------
// A fill of a resting order
// ---------------------------------------------------------------------------

const N: u64 = 10_000_000;

fn plain(key: &Keypair) -> Script {
	elements::script::Builder::new().push_int(1).push_slice(&xonly(key).serialize()).into_script()
}

/// The fill of `filled` of `order` by the taker coin `coin`, its checkpoint
/// with the owner's exit, the operator's signature by `s`.
#[allow(clippy::too_many_arguments)]
fn make_fill(order_rec: &CoinRecord, order: &ValidCoin, coin_rec: &CoinRecord, coin: &ValidCoin, payer: &Keypair, to: &NewLeaf,
	change: &NewLeaf, filled: u64, s: &Keypair) -> OrderFill
{
	let op = order.leaf.order_policy().unwrap();
	let plan = op.plan(order.value, filled).unwrap();
	let price = plan.credit.value;
	let mut outputs = vec![plan.credit.clone()];
	if let Some(r) = &plan.rest {
		outputs.push(r.clone());
	}
	outputs.push(ExplicitOutput::new(order.asset, filled, to.policy(xonly(s), op.chain).script_pubkey()));
	outputs.push(ExplicitOutput::new(coin.asset, coin.value - price - 2_000, change.policy(xonly(s), op.chain).script_pubkey()));
	let txouts: Vec<_> = outputs.iter().map(|o| o.txout()).collect();
	let digest = op.fill_digest(order.value, &txouts).unwrap();
	let cp = coin.checkpoint_of(true);
	let cp_out = ExplicitOutput::new(coin.asset, coin.value, cp.script_pubkey());
	let m_cp = coin.leaf.collab_message(coin.asset, coin.value, std::slice::from_ref(&cp_out)).unwrap();
	let m_f = cp.collab_message(coin.asset, coin.value, &outputs).unwrap();
	OrderFill {
		order: order_rec.clone(),
		signature: sig(s, &digest),
		partial: plan.rest.is_some(),
		inputs: vec![TransferInput { exit: true,
			coin: coin_rec.clone(), checkpoint_value: coin.value,
			checkpoint: Pair { operator: sig(s, &m_cp.digest), owner: sig(payer, &m_cp.digest) },
			reassignment: Pair { operator: sig(s, &m_f.digest), owner: sig(payer, &m_f.digest) },
		}],
		outputs,
	}
}

#[test]
fn a_dead_fill_returns_the_takers_coin() {
	let _one = one_node();
	let mut c = Arca::start();
	y_listed(&c);
	let (x, y) = (c.net.x, c.net.y);
	let s = keypair("ob1 fill operator");
	let t0 = mt(c.net.mtp() - 60);
	let maker = keypair("ob1 fill maker");
	let credit_keys: Vec<_> = (0..4).map(|i| keypair(&format!("ob1 fill credit {}", i))).collect();
	let refund = keypair("ob1 fill refund");
	let terms = order::OrderLeafTerms {
		landed: order::SeqdexOrder {
			terms: order::OrderTerms { asset_a: x, asset_b: y, rate_num: 2, rate_den: 1, min_lot: 1_000_000 },
			maker: sha256(plain(&refund).as_bytes()),
			expiry: (c.net.now() + 30 * DAY) as u32,
			refund_key: xonly(&refund),
			version: order::SeqdexVersion::V2,
		},
		credits: [0, 1, 2, 3].map(|i| xonly(&credit_keys[i]).serialize()),
	};
	let (issuer_x, sched_x) = c.schedule(&s);
	let mut xs = vec![LeafSpec { template: Template::Order3, order: Some(terms), ..spec(&maker, "ob1 fill order", N, sha256(&label32("ox"))) }];
	xs.push(spec(&keypair("ob1 fill x 1"), "ob1 fill x 1", N, sha256(&label32("x1"))));
	let tx_ = tree_of(&c, &s, x, Some(&sched_x), &xs);
	let rx = round(&mut c, "round: an order-3 leaf in a batch of X", &s, &tx_.batch_output(), Some((&issuer_x, &sched_x)));
	let (issuer_y, sched_y) = c.schedule(&s);
	let takers: Vec<_> = (0..2).map(|i| keypair(&format!("ob1 fill taker {}", i))).collect();
	let ys: Vec<_> = (0..2).map(|i| spec(&takers[i], &format!("ob1 fill y {}", i), 3 * N, sha256(&label32(&format!("y{}", i))))).collect();
	let ty = tree_of(&c, &s, y, Some(&sched_y), &ys);
	let ry = round(&mut c, "round: the takers' leaves in a batch of Y", &s, &ty.batch_output(), Some((&issuer_y, &sched_y)));
	let rounds = vec![rx, ry];
	let policy = c.policy(&s);
	let order_rec = base(&tx_, 0, &maker, label32("ox"), t0);
	let order = order_rec.resolve(&rounds, &policy).unwrap();
	let recs: Vec<CoinRecord> = (0..2).map(|i| base(&ty, i, &takers[i], label32(&format!("y{}", i)), t0)).collect();
	let coins: Vec<ValidCoin> = recs.iter().map(|r| r.resolve(&rounds, &policy).unwrap()).collect();
	let leaf = |w: &str| party(&format!("ob1 fill {}", w), delay()).1;
	// Taker 0's fill; then the operator alone signs a second fill of the
	// same order for taker 1, which it controls, and mines it first.
	let f0 = make_fill(&order_rec, &order, &recs[0], &coins[0], &takers[0], &leaf("t0 x"), &leaf("t0 change"), 4_000_000, &s);
	let f1 = make_fill(&order_rec, &order, &recs[1], &coins[1], &takers[1], &leaf("t1 x"), &leaf("t1 change"), 4_000_000, &s);
	let got = CoinRecord::Fill(Box::new(FillCoin { fill: f0.clone(), index: 2, leaf: FillLeaf::New(leaf("t0 x")) }));
	assert_eq!(got.to_bytes().unwrap()[0], COIN_RECORD_VERSION_EXIT);
	let got_coin = got.resolve(&rounds, &policy).unwrap();
	let other = CoinRecord::Fill(Box::new(FillCoin { fill: f1, index: 2, leaf: FillLeaf::New(leaf("t1 x")) })).resolve(&rounds, &policy).unwrap();
	let ValidOrigin::Fill { inputs: in0, .. } = &got_coin.origin else { unreachable!() };
	let ValidOrigin::Fill { inputs: in1, .. } = &other.origin else { unreachable!() };
	let cp0 = in0[0].checkpoint;
	assert_eq!(cp0.exit, Some(coins[0].leaf.exit_delay));

	let order_at = bring(&mut c, "the order's path", &order);
	let t1_at = bring(&mut c, "taker 1's path", &coins[1]);
	let fee_of = |c: &mut Arca| { let k = c.net.fee_coin(); FeeSource::Coin { outpoint: k.outpoint, coin: k.txout, fee: 4_000, change: op_true_spk() } };
	let with_coin = |mut tx: Transaction| { let n = tx.input.len(); tx.input[n - 1].witness.script_witness = op_true_witness(); tx };
	let fs = fee_of(&mut c);
	let cp1 = c.net.pass("taker 1's checkpoint", &with_coin(in1[0].checkpoint_tx(t1_at, &fs).unwrap().tx));
	let fs = { let k = c.net.fee_coin(); FeeSource::Coin { outpoint: k.outpoint, coin: k.txout, fee: 6_000, change: op_true_spk() } };
	let mut f1tx = other.fill_tx(order_at, &[OutPoint::new(cp1, 0)], &fs).unwrap().tx;
	let n = f1tx.input.len();
	f1tx.input[n - 1].witness.script_witness = op_true_witness();
	c.net.pass("ATTACK the operator's second fill of the same order, for taker 1", &f1tx);
	let t0_at = bring(&mut c, "taker 0's path", &coins[0]);
	let fs = fee_of(&mut c);
	let cp0_id = c.net.pass("taker 0's checkpoint with its exit, from its record", &with_coin(in0[0].checkpoint_tx(t0_at, &fs).unwrap().tx));
	let cp0_at = OutPoint::new(cp0_id, 0);
	let v = in0[0].checkpoint_value;
	c.net.refuse("neg taker 0's checkpoint exit before its delay", &cp_exit(&c, &cp0, cp0_at, y, v, &takers[0], 0), EARLY);
	let fs = { let k = c.net.fee_coin(); FeeSource::Coin { outpoint: k.outpoint, coin: k.txout, fee: 6_000, change: op_true_spk() } };
	let mut f0tx = got_coin.fill_tx(order_at, &[cp0_at], &fs).unwrap().tx;
	let n = f0tx.input.len();
	f0tx.input[n - 1].witness.script_witness = op_true_witness();
	c.net.refuse("neg taker 0's fill", &f0tx, GONE);
	c.net.wait_csv(&cp0_id, delay());
	c.net.refuse("neg taker 0's checkpoint exit signed by the operator", &cp_exit(&c, &cp0, cp0_at, y, v, &s, 0), SIG);
	c.net.refuse("neg taker 0's checkpoint exit signed by the maker", &cp_exit(&c, &cp0, cp0_at, y, v, &maker, 0), SIG);
	c.net.refuse("neg taker 0's checkpoint exit, sequence one unit short", &cp_exit(&c, &cp0, cp0_at, y, v, &takers[0], 1), SHORT);
	c.net.pass("taker 0's own exit of its checkpoint after the delay, no operator", &cp_exit(&c, &cp0, cp0_at, y, v, &takers[0], 0));
	c.net.print();
}

/// The maker's side of a dead fill. A fill spends the order's coin by the
/// operator's signature alone, never through a checkpoint, so the order's
/// coin is spent only if the fill confirms. When the taker and the operator
/// spend the taker's checkpoint elsewhere, the fill can never confirm and
/// the order's coin stays unspent: its maker brings it on and lands it as
/// its own SeqDEX order, which needs no signature, one exit delay after the
/// coin reaches the chain. The landed order is the maker's: anyone fills it
/// only at its price, paid to the maker's script, and its refund key takes
/// it back after its expiry (SeqDEX's program, not built here).
#[test]
fn a_dead_fill_leaves_the_makers_order_coin_to_land() {
	let _one = one_node();
	let mut c = Arca::start();
	y_listed(&c);
	let (x, y) = (c.net.x, c.net.y);
	let s = keypair("ob1 maker operator");
	let t0 = mt(c.net.mtp() - 60);
	let maker = keypair("ob1 maker maker");
	let credit_keys: Vec<_> = (0..4).map(|i| keypair(&format!("ob1 maker credit {}", i))).collect();
	let refund = keypair("ob1 maker refund");
	let terms = order::OrderLeafTerms {
		landed: order::SeqdexOrder {
			terms: order::OrderTerms { asset_a: x, asset_b: y, rate_num: 2, rate_den: 1, min_lot: 1_000_000 },
			maker: sha256(plain(&refund).as_bytes()),
			expiry: (c.net.now() + 30 * DAY) as u32,
			refund_key: xonly(&refund),
			version: order::SeqdexVersion::V2,
		},
		credits: [0, 1, 2, 3].map(|i| xonly(&credit_keys[i]).serialize()),
	};
	let (issuer_x, sched_x) = c.schedule(&s);
	let xs = vec![LeafSpec { template: Template::Order3, order: Some(terms), ..spec(&maker, "ob1 maker order", N, sha256(&label32("mox"))) },
		spec(&keypair("ob1 maker x 1"), "ob1 maker x 1", N, sha256(&label32("mx1")))];
	let tx_ = tree_of(&c, &s, x, Some(&sched_x), &xs);
	let rx = round(&mut c, "round: an order-3 leaf in a batch of X", &s, &tx_.batch_output(), Some((&issuer_x, &sched_x)));
	let (issuer_y, sched_y) = c.schedule(&s);
	let taker = keypair("ob1 maker taker");
	let ty = tree_of(&c, &s, y, Some(&sched_y), &[spec(&taker, "ob1 maker y 0", 3 * N, sha256(&label32("my0"))),
		spec(&keypair("ob1 maker y 1"), "ob1 maker y 1", 3 * N, sha256(&label32("my1")))]);
	let ry = round(&mut c, "round: the taker's leaf in a batch of Y", &s, &ty.batch_output(), Some((&issuer_y, &sched_y)));
	let rounds = vec![rx, ry];
	let policy = c.policy(&s);
	let order_rec = base(&tx_, 0, &maker, label32("mox"), t0);
	let order = order_rec.resolve(&rounds, &policy).unwrap();
	let taker_rec = base(&ty, 0, &taker, label32("my0"), t0);
	let taker_coin = taker_rec.resolve(&rounds, &policy).unwrap();
	let leaf = |w: &str| party(&format!("ob1 maker {}", w), delay()).1;
	let f = make_fill(&order_rec, &order, &taker_rec, &taker_coin, &taker, &leaf("t x"), &leaf("t change"), 4_000_000, &s);
	let credit = CoinRecord::Fill(Box::new(FillCoin { fill: f, index: 0, leaf: FillLeaf::Credit { owner_nonce: label32("mcredit") } }))
		.resolve(&rounds, &policy).unwrap();
	let ValidOrigin::Fill { inputs, .. } = &credit.origin else { unreachable!() };
	let t_in = inputs[0].clone();

	// The taker and the operator spend the taker's checkpoint elsewhere.
	let t_at = bring(&mut c, "the taker's path", &taker_coin);
	let fee_of = |c: &mut Arca| { let k = c.net.fee_coin(); FeeSource::Coin { outpoint: k.outpoint, coin: k.txout, fee: 4_000, change: op_true_spk() } };
	let with_coin = |mut tx: Transaction| { let n = tx.input.len(); tx.input[n - 1].witness.script_witness = op_true_witness(); tx };
	let fs = fee_of(&mut c);
	let tcp = OutPoint::new(c.net.pass("the taker's checkpoint", &with_coin(t_in.checkpoint_tx(t_at, &fs).unwrap().tx)), 0);
	let back = vec![ExplicitOutput::new(y, t_in.checkpoint_value - MARGIN, thief())];
	let bp = TransferPlan { checkpoint_exit: true, inputs: vec![(taker_coin.clone(), t_in.checkpoint_value)], outputs: back.clone() };
	let d = bp.reassignment_message(0).unwrap().digest;
	let second = ValidInput { reassignment_pair: Pair { operator: sig(&s, &d), owner: sig(&taker, &d) }, ..t_in.clone() };
	c.net.pass("ATTACK taker + operator: a second spend of the taker's checkpoint",
		&reassignment_tx(&[second], &back, &[tcp], &FeeSource::Reserve).unwrap().tx);

	// The fill can never confirm; the order's coin is unspent.
	let order_at = bring(&mut c, "the order's path, by the maker's authorisations", &order);
	let fs = fee_of(&mut c);
	c.net.refuse("neg the fill, its taker's checkpoint spent", &with_coin(credit.fill_tx(order_at, &[tcp], &fs).unwrap().tx), GONE);
	let op = order.leaf.order_policy().unwrap();
	let fs = fee_of(&mut c);
	let early = with_coin(op.landing_tx(order_at, order.value, &fs).unwrap().tx);
	c.net.refuse("neg the maker lands its order before the exit delay", &early, EARLY);
	c.net.wait_csv(&order_at.txid, delay());
	let fs = fee_of(&mut c);
	let land = with_coin(op.landing_tx(order_at, order.value, &fs).unwrap().tx);
	c.net.pass("the maker lands its whole order coin as its own SeqDEX order, no signature", &land);
	assert_eq!(land.output[0], op.landed_output(order.value).txout(), "the landed order holds the whole coin, for the same terms");
	assert_eq!(order.value, N);
	c.net.print();
}
