//! A three-hop out-of-round chain, built from two batches, for the transfer
//! tests: on regtest and through the verifier alone.
//!
//! - Batch 1 holds asset X; owner A holds one of its leaves. Batch 2 holds
//!   asset Y; owner C holds one of its leaves.
//! - Hop 1: A pays B 7,000,000 of X and keeps the change in a new leaf.
//! - Hop 2, a swap of two coins of two owners in two assets: B gives the X it
//!   received, C gives its Y leaf; B receives the Y, C the X.
//! - Hop 3: B pays the Y on to D.
//!
//! Every new leaf has its own key, its owner's nonce and a creator nonce of
//! its sender's. Each signer leaves a margin of 1,200 atoms in the coin's
//! asset at each step, except that the swap commits all of C's checkpointed Y,
//! so the reassignment's margin is in X alone.

use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, Transaction};

use arca_covenant::script::sha256;
use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeParams};
use arca_covenant::*;

use super::*;

pub const MARGIN: u64 = 1_200;

/// A party to the chain: its key, and the leaf it is paid into: the key and
/// nonce it published, and the creator nonce its sender drew.
#[derive(Clone)]
pub struct Party {
	pub key: Keypair,
	pub leaf: NewLeaf,
}

impl Party {
	pub fn new(label: &str, delay: RelativeTime) -> Party {
		let key = keypair(&format!("chain {} key", label));
		Party {
			leaf: NewLeaf {
				owner: xonly(&key), owner_nonce: label32(&format!("chain {} owner nonce", label)),
				creator_nonce: label32(&format!("chain {} creator nonce", label)), exit_delay: delay,
			},
			key,
		}
	}
}

/// The two batches before their rounds: the caller funds them.
pub struct Batches {
	pub s: Keypair,
	pub a: Keypair,
	pub c: Keypair,
	pub batch1: Tree,
	pub batch2: Tree,
	pub preimages1: Vec<[u8; 32]>,
	pub preimages2: Vec<[u8; 32]>,
	/// A's and C's leaves.
	pub a_at: usize,
	pub c_at: usize,
}

/// Batch 1 (X, five leaves, A's at 2) and batch 2 (Y, three leaves, C's at
/// 1), under `sched1` and `sched2`.
#[allow(clippy::too_many_arguments)]
pub fn batches(chain: Chain, x: AssetId, y: AssetId, s: Keypair, sched1: ClockSchedule, sched2: ClockSchedule,
	delay: RelativeTime, reserve: ReserveRule) -> Batches
{
	let a = keypair("chain A key");
	let c = keypair("chain C key");
	let build = |label: &str, asset: AssetId, sched: ClockSchedule, n: usize, at: usize, owner: &Keypair, value: u64| {
		let preimages: Vec<[u8; 32]> = (0..n).map(|i| label32(&format!("chain {} preimage {}", label, i))).collect();
		let leaves: Vec<LeafSpec> = (0..n).map(|i| LeafSpec {
			template: Template::Vtxo1,
			owner: if i == at { xonly(owner) } else { xonly(&keypair(&format!("chain {} bystander {}", label, i))) },
			value,
			owner_nonce: label32(&format!("chain {} owner nonce {}", label, i)),
			operator_nonce: label32(&format!("chain {} operator nonce {}", label, i)),
			exit_delay: delay, unlock_hash: sha256(&preimages[i]),
		}).collect();
		let tree = Tree::build(TreeParams { asset, chain, schedule: sched, burn: false, radix: 4, reserve, min_leaf: 1 }, &leaves).unwrap();
		(tree, preimages)
	};
	let (batch1, preimages1) = build("batch 1", x, sched1, 5, 2, &a, 10_000_000);
	let (batch2, preimages2) = build("batch 2", y, sched2, 3, 1, &c, 5_000_000);
	Batches { s, a, c, batch1, batch2, preimages1, preimages2, a_at: 2, c_at: 1 }
}

/// The base record of a batch leaf, as its owner hands it on: with its
/// entry's preimage and its unroll authorisations, signed for `t`.
pub fn base(tree: &Tree, i: usize, owner: &Keypair, preimage: [u8; 32], t: MedianTime) -> CoinRecord {
	let record = tree.record(i);
	let branch = record.branch().unwrap();
	let auths = branch.nodes.iter().map(|n| (sig(owner, &n.unroll_authorisation(t).digest), t)).collect();
	CoinRecord::Leaf { record, preimage, auths }
}

/// The whole chain: every party, and the record each receiver holds.
pub struct Hops {
	pub b1: Party,
	pub a_change: Party,
	pub b2: Party,
	pub c2: Party,
	pub d: Party,
	/// The records of A's and C's batch leaves.
	pub a_base: CoinRecord,
	pub c_base: CoinRecord,
	/// The record B holds after hop 1, C holds after hop 2, B after hop 2,
	/// and D after hop 3.
	pub b1_record: CoinRecord,
	pub a_change_record: CoinRecord,
	pub c2_record: CoinRecord,
	pub b2_record: CoinRecord,
	pub d_record: CoinRecord,
}

/// Signs the plan's two messages for each input with the input owner's key
/// and the operator's.
fn sign_plan(plan: &TransferPlan, owners: &[&Keypair], s: &Keypair) -> Vec<(Pair, Pair)> {
	(0..plan.inputs.len()).map(|i| {
		let cp = plan.checkpoint_message(i).unwrap().digest;
		let re = plan.reassignment_message(i).unwrap().digest;
		(Pair { operator: sig(s, &cp), owner: sig(owners[i], &cp) }, Pair { operator: sig(s, &re), owner: sig(owners[i], &re) })
	}).collect()
}

fn record_for(plan: &TransferPlan, records: &[&CoinRecord], pairs: &[(Pair, Pair)], index: u8, leaf: NewLeaf) -> CoinRecord {
	CoinRecord::Transfer(Box::new(Transfer {
		inputs: records.iter().zip(pairs).zip(&plan.inputs).map(|((r, (cp, re)), (_, v))| TransferInput {
			coin: (*r).clone(), checkpoint_value: *v, checkpoint: *cp, reassignment: *re,
		}).collect(),
		outputs: plan.outputs.clone(),
		index,
		leaf,
	}))
}

/// Builds the three hops on `b`, whose rounds are `rounds`, under `policy`.
pub fn hops(b: &Batches, rounds: &[Transaction], policy: &WalletPolicy, t: MedianTime, delay: RelativeTime) -> Hops {
	let chain = policy.chain;
	let s = xonly(&b.s);
	let a_base = base(&b.batch1, b.a_at, &b.a, b.preimages1[b.a_at], t);
	let c_base = base(&b.batch2, b.c_at, &b.c, b.preimages2[b.c_at], t);
	let a_coin = a_base.resolve(rounds, policy).unwrap();
	let c_coin = c_base.resolve(rounds, policy).unwrap();
	let (x, y) = (a_coin.asset, c_coin.asset);

	// Hop 1: A to B, with change.
	let b1 = Party::new("B1", delay);
	let a_change = Party::new("A change", delay);
	let cp1 = a_coin.value - MARGIN;
	let plan1 = TransferPlan {
		inputs: vec![(a_coin.clone(), cp1)],
		outputs: vec![
			ExplicitOutput::new(x, 7_000_000, b1.leaf.policy(s, chain).script_pubkey()),
			ExplicitOutput::new(x, cp1 - 7_000_000 - MARGIN, a_change.leaf.policy(s, chain).script_pubkey()),
		],
	};
	let p1 = sign_plan(&plan1, &[&b.a], &b.s);
	let b1_record = record_for(&plan1, &[&a_base], &p1, 0, b1.leaf);
	let a_change_record = record_for(&plan1, &[&a_base], &p1, 1, a_change.leaf);
	let b1_coin = b1_record.validate(rounds, policy, &b1.leaf.owner, &b1.leaf.owner_nonce).unwrap();

	// Hop 2: the swap. B gives X, C gives Y.
	let b2 = Party::new("B2", delay);
	let c2 = Party::new("C2", delay);
	let (cp_b, cp_c) = (b1_coin.value - MARGIN, c_coin.value - MARGIN);
	let plan2 = TransferPlan {
		inputs: vec![(b1_coin.clone(), cp_b), (c_coin.clone(), cp_c)],
		outputs: vec![
			ExplicitOutput::new(y, cp_c, b2.leaf.policy(s, chain).script_pubkey()),
			ExplicitOutput::new(x, cp_b - MARGIN, c2.leaf.policy(s, chain).script_pubkey()),
		],
	};
	let p2 = sign_plan(&plan2, &[&b1.key, &b.c], &b.s);
	let b2_record = record_for(&plan2, &[&b1_record, &c_base], &p2, 0, b2.leaf);
	let c2_record = record_for(&plan2, &[&b1_record, &c_base], &p2, 1, c2.leaf);
	let b2_coin = b2_record.validate(rounds, policy, &b2.leaf.owner, &b2.leaf.owner_nonce).unwrap();

	// Hop 3: B pays the Y on to D.
	let d = Party::new("D", delay);
	let cp3 = b2_coin.value - MARGIN;
	let plan3 = TransferPlan {
		inputs: vec![(b2_coin, cp3)],
		outputs: vec![ExplicitOutput::new(y, cp3 - MARGIN, d.leaf.policy(s, chain).script_pubkey())],
	};
	let p3 = sign_plan(&plan3, &[&b2.key], &b.s);
	let d_record = record_for(&plan3, &[&b2_record], &p3, 0, d.leaf);
	Hops { b1, a_change, b2, c2, d, a_base, c_base, b1_record, a_change_record, c2_record, b2_record, d_record }
}
