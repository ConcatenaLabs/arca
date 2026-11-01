//! A batch without a sweep, on a Sequentia regtest chain.
//!
//! The batch's schedule is [`ClockSchedule::never`]: no token, no clock, and
//! no sweep leaf on the batch output, a node, an entry or a checkpoint. Every
//! transaction is built with this crate's builders and broadcast to a node
//! started with `-par=1`; a negative case is refused by the mempool and again
//! when forced into a block, the block for the mempool's reason.
//!
//! 1. The records: format version 3 in both forms, no token or expiry, and a
//!    wallet that accepts only batches without a sweep
//!    ([`WalletPolicy::no_sweep`]) refuses a record of a batch with one, while
//!    the policy of [`WalletPolicy::new`] accepts both.
//! 2. A refresh between two such batches signs its forfeits and releases
//!    against the built round before it is broadcast: the wallet validates
//!    its new leaf from the unbroadcast transaction, whose txid fixes the
//!    connector asset `M`.
//! 3. The operator recovers the first batch: it unrolls the batch output with
//!    its own authorisation, takes back the lowest node whose owners all
//!    refreshed by RECLAIM-D, unrolls the other lowest node, claims the
//!    forfeit an owner gave up, and opens a dormant owner's entry into its
//!    own leaf, which only that owner can take home. Each removed sweep leaf
//!    is refused on the output it would have spent.
//!
//! Needs `SEQUENTIAD_EXEC`; `--nocapture` prints every transaction.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::{OutPoint, Transaction};

use arca_covenant::node::{node_taproot, node_taproot_delegated, ReleaseTree};
use arca_covenant::script::{asset_bytes, sha256};
use arca_covenant::spend::FeeSource;
use arca_covenant::taptree::TapOutput;
use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeParams};
use arca_covenant::unroll::UnrollAuth;
use arca_covenant::*;

use common::net::*;
use common::round::*;
use common::*;

const MISMATCH: &str = "Witness program hash mismatch";

fn never_tree(c: &Arca, s: &Keypair, leaves: &[LeafSpec], delegated: bool) -> Tree {
	Tree::build(TreeParams {
		asset: c.net.x, chain: c.net.chain, schedule: ClockSchedule::never(xonly(s)), burn: false, delegated_reclaim: delegated,
		radix: 4, reserve: ReserveRule::FeeRate { floor_per_kvb: c.floor_per_kvb, multiple: 4 }, min_leaf: 1,
	}, leaves).unwrap()
}

/// A round of a batch without a sweep: it issues nothing and pays the batch
/// output, the connector output, change and the fee. Built, not broadcast.
fn never_round(net: &mut Net, s: &Keypair, batch: &ExplicitOutput) -> (Transaction, u32) {
	let funding = net.fund(vec![explicit(net.x, batch.value + 200_000, op_true_spk())]).remove(0);
	let total = funding.txout.value.explicit().unwrap();
	let outs = vec![batch.txout(), ConnectorPolicy { operator: xonly(s) }.output(net.x, 5_000).txout(),
		explicit(net.x, total - batch.value - 5_000 - 2_000, op_true_spk()), fee(net.x, 2_000)];
	let mut sp = spend(0).coin(&funding, 0xffff_ffff).outputs(outs);
	sp.witness(0, op_true_witness());
	(sp.tx, 1)
}

/// The operator's own authorisation of `node` (a tree node), at `t`.
fn operator_auth(node: &arca_covenant::tree::TreeNode, s: &Keypair, t: MedianTime) -> UnrollAuth {
	let digest = node.policy.unroll_authorisation(t).digest;
	UnrollAuth { signature: sig(s, &digest), time: t, key: xonly(s), proof: node.members().proof(0) }
}

/// A spend of `coin`, an output of a batch without a sweep, by the sweep leaf
/// `sweep` with the control block it would have in `twin`, the same output
/// with a sweep: the operator's signature and the token's index.
fn by_removed_sweep(net: &Net, coin: &Coin, sweep: &Script, twin: &TapOutput, s: &Keypair, seq: u32) -> Transaction {
	let v = coin.txout.value.explicit().unwrap();
	let mut sp = spend(0).coin(coin, seq).outputs(vec![explicit(net.x, v - 2_000, op_true_spk()), fee(net.x, 2_000)]);
	let sg = sp.sign(s, 0, sweep, net.genesis);
	sp.witness(0, twin.witness(sweep, Sweep::witness_items(&sg, 0)));
	sp.tx
}

#[test]
fn a_batch_without_a_sweep_is_recovered_without_one() {
	let mut c = Arca::start();
	let s = keypair("no-sweep operator");
	let chain = c.net.chain;
	let strict = WalletPolicy::no_sweep(chain, xonly(&s), mt(c.net.mtp()));

	// --- The first batch: eight leaves, RECLAIM-D on its lowest nodes -------
	let owners: Vec<Keypair> = (0..8).map(|i| keypair(&format!("ns owner {}", i))).collect();
	let pre: Vec<[u8; 32]> = (0..8).map(|i| label32(&format!("ns preimage {}", i))).collect();
	let specs: Vec<LeafSpec> = (0..8).map(|i| spec(&owners[i], &format!("ns leaf {}", i), LEAF, sha256(&pre[i]))).collect();
	let tree = never_tree(&c, &s, &specs, true);
	assert!(tree.clock0_script_pubkey().is_none(), "no token is paid");
	let root = tree.root();
	assert!(root.policy.sweep().is_none());
	assert_eq!(root.policy.script_pubkey(), TapOutput::new(vec![(0, root.policy.unroll_script())]).script_pubkey(), "the batch output: [UNROLL]");
	let lowest = &tree.levels()[0];
	for n in lowest {
		let p = &n.policy;
		assert_eq!(p.script_pubkey(), TapOutput::new(vec![(1, p.unroll_script()), (2, p.reclaim_script().unwrap()),
			(2, p.reclaim_delegated_script().unwrap())]).script_pubkey(), "a lowest node: [UNROLL, [RECLAIM, RECLAIM-D]]");
	}
	for l in tree.leaves() {
		assert!(l.entry.sweep.is_none());
		assert_eq!(l.entry.script_pubkey(), TapOutput::new(vec![(0, l.entry.unlock_script())]).script_pubkey(), "an entry: [unlock]");
	}

	// --- 1. The records --------------------------------------------------
	let rec = tree.record(0);
	let bytes = rec.to_bytes().unwrap();
	assert_eq!(bytes[0], record::RECORD_VERSION_NO_SWEEP);
	assert_eq!(LeafRecord::from_bytes(&bytes).unwrap(), rec);
	let json = rec.to_json_string().unwrap();
	assert!(json.contains("\"version\":3") && !json.contains("token") && !json.contains("expiries") && !json.contains("burn"),
		"{}", json);
	assert_eq!(LeafRecord::from_json_str(&json).unwrap(), rec);
	let mut burnt = rec.clone();
	burnt.burn = true;
	assert!(burnt.to_bytes().is_err(), "burn-only names sweeps a batch without one has not");

	// A batch with a sweep, for the policies.
	let (issuer, sched) = c.schedule(&s);
	let old_specs: Vec<LeafSpec> = (0..2).map(|i| spec(&owners[i], &format!("ns swept leaf {}", i), LEAF, sha256(&pre[i]))).collect();
	let swept = c.tree(&sched, &old_specs);
	let (swept_round, _) = round_tx(&c.net, &issuer, &[], &swept.batch_output(), &sched);
	c.net.pass("a batch with a sweep: its round", &swept_round);
	let swept_rec = swept.record(0);
	assert_eq!(swept_rec.validate(&swept_round, &strict, &xonly(&owners[0]), &old_specs[0].owner_nonce).unwrap_err(),
		RecordError::SweepRefused, "a wallet that accepts only batches without a sweep refuses one with a sweep");
	swept_rec.validate(&swept_round, &c.policy(&s), &xonly(&owners[0]), &old_specs[0].owner_nonce)
		.expect("the policy of WalletPolicy::new accepts a batch with a sweep");
	// The no-sweep token in a version 2 record is refused: it is written as version 3 alone.
	let mut v2 = swept_rec.to_bytes().unwrap();
	let at = v2.windows(32).position(|w| w == asset_bytes(sched.token)).unwrap();
	v2[at..at + 32].copy_from_slice(&asset_bytes(no_sweep_token()));
	assert!(matches!(LeafRecord::from_bytes(&v2), Err(RecordError::Decode(encode::DecodeError::NoSweepToken))));

	// --- 2. The round, built; every wallet checks its leaf before broadcast --
	let (round_a, ca) = never_round(&mut c.net, &s, &tree.batch_output());
	let valid_a: Vec<ValidLeaf> = (0..8).map(|i| tree.record(i).validate(&round_a, &strict, &xonly(&owners[i]), &specs[i].owner_nonce)
		.expect("a leaf of a batch without a sweep, under the strict policy")).collect();
	tree.record(0).validate(&round_a, &c.policy(&s), &xonly(&owners[0]), &specs[0].owner_nonce)
		.expect("and under the policy of WalletPolicy::new");
	// Owner 5 gives up an old coin for its new leaf: the forfeit names round A's
	// M, fixed by the built round's txid, and is signed before the broadcast.
	let (old5, old5_coin, old5_id) = funded_leaf(&mut c.net, &owners[5], &s, "ns old coin 5", LEAF + 3_000);
	let f5 = Forfeit::for_refresh(old5, (c.net.x, LEAF + 3_000), old5_id, &valid_a[5], &round_a, ca, delay(), MARGIN).unwrap();
	let f5_pair = forfeit_pair(&f5, &owners[5], &s);
	f5.verify(&f5_pair).unwrap();
	let ra = c.net.pass("round A: no token, no clock", &round_a);
	assert!(round_a.input.iter().all(|i| i.asset_issuance.is_null()), "round A issues nothing");
	let m_a = { let tx = issuance_tx(&c.net, &round_a, ca, &s); let t = c.net.pass("round A: its M issued", &tx); coin_of(t, 0, &tx) };
	let f5_tx = f5.tx(old5_coin.outpoint, &f5_pair, &FeeSource::Reserve).unwrap().tx;
	let f5_at = OutPoint::new(c.net.pass("owner 5's old coin: the forfeit signed before broadcast", &f5_tx), 0);
	let claim = claim_tx(&c.net, &f5, f5_at, &m_a, &s, &pre[5]);
	let claimed = c.net.pass("owner 5's forfeit: claimed with round A's M", &claim);
	let _ = claimed;

	// Round B, where owners 0 to 3 refresh: each signs its forfeit and its
	// release of lowest node 0 against round B before it is broadcast.
	let new_keys: Vec<Keypair> = (0..4).map(|i| keypair(&format!("ns new owner {}", i))).collect();
	let new_pre: Vec<[u8; 32]> = (0..4).map(|i| label32(&format!("ns new preimage {}", i))).collect();
	let new_specs: Vec<LeafSpec> = (0..4).map(|i| spec(&new_keys[i], &format!("ns new leaf {}", i), LEAF - 2_000, sha256(&new_pre[i]))).collect();
	let tree_b = never_tree(&c, &s, &new_specs, true);
	let (round_b, cb) = never_round(&mut c.net, &s, &tree_b.batch_output());
	let valid_b: Vec<ValidLeaf> = (0..4).map(|i| tree_b.record(i).validate(&round_b, &strict, &xonly(&new_keys[i]), &new_specs[i].owner_nonce)
		.unwrap()).collect();
	let releases: Vec<(Release, elements::secp256k1_zkp::schnorr::Signature)> = (0..4).map(|i| {
		let r = Release::for_refresh(&valid_a[i], &valid_b[i], &round_b, cb).unwrap();
		let sg = sig(&owners[i], &r.message().digest);
		(r, sg)
	}).collect();
	let forfeits: Vec<(Forfeit, Pair)> = (0..4).map(|i| {
		let f = Forfeit::for_refresh(valid_a[i].branch.leaf.clone(), (c.net.x, LEAF), valid_a[i].leaf_id, &valid_b[i], &round_b, cb,
			delay(), MARGIN).unwrap();
		let p = forfeit_pair(&f, &owners[i], &s);
		(f, p)
	}).collect();
	assert_eq!(forfeits.len(), 4);
	c.net.pass("round B: owners 0 to 3 refreshed, their forfeits and releases signed before broadcast", &round_b);
	let m_b = { let tx = issuance_tx(&c.net, &round_b, cb, &s); let t = c.net.pass("round B: its M issued", &tx); coin_of(t, 0, &tx) };

	// --- 3. Collection -----------------------------------------------------
	let sweep_root = sched.sweep(false, false).script();
	let sweep_w = sched.sweep(true, false).script();
	let batch_coin = coin_of(ra, 0, &round_a);
	let twin = node_taproot(root.policy.unroll_script(), Some(sweep_root.clone()), None);
	let tx = by_removed_sweep(&c.net, &batch_coin, &sweep_root, &twin, &s, 0xffff_fffe);
	c.net.refuse("removed: the batch output's sweep", &tx, MISMATCH);

	let t = mt(c.net.mtp() - 60);
	let u = valid_a[0].branch.nodes[0].unroll_tx(batch_coin.outpoint, &operator_auth(root, &s, t), &FeeSource::Reserve).unwrap();
	let unrolled = c.net.pass("collect: the operator unrolls the batch output with its own authorisation", &u.tx);
	let node0 = coin_of(unrolled, 0, &u.tx);
	let node1 = coin_of(unrolled, 1, &u.tx);
	for (j, coin) in [(0usize, &node0), (1, &node1)] {
		let p = &lowest[j].policy;
		let twin = node_taproot_delegated(p.unroll_script(), Some(sweep_w.clone()), p.reclaim_script(), p.reclaim_delegated_script());
		let tx = by_removed_sweep(&c.net, coin, &sweep_w, &twin, &s, 0xffff_fffe);
		c.net.refuse(&format!("removed: lowest node {}'s sweep", j), &tx, MISMATCH);
	}

	// Lowest node 0: every owner refreshed in round B and released: RECLAIM-D.
	let n0 = &valid_a[0].branch.nodes[1];
	let trees: Vec<ReleaseTree> = releases.iter().enumerate()
		.map(|(i, (_, sg))| ReleaseTree::Release { key: xonly(&owners[i]), sig: *sg, connector_input: 1 }).collect();
	let reclaim = |trees: &[ReleaseTree]| {
		let ks = n0.reclaim_delegated_tx(node0.outpoint, &[(m_b.outpoint, m_b.txout.clone())],
			&[ExplicitOutput::new(c.net.x, n0.value - 3_000, op_true_spk())], op_true_spk(), &FeeSource::Reserve).unwrap();
		let op = sig(&s, &ks.sighash(c.net.genesis).unwrap());
		let mut u = ks.finish(n0.reclaim_delegated_items(chain, &op, trees).unwrap());
		u.tx.input[1].witness.script_witness = op_true_witness();
		u.tx
	};
	let mut forged = trees.clone();
	forged[3] = ReleaseTree::Release { key: xonly(&owners[3]), sig: sig(&owners[3], &[7; 32]), connector_input: 1 };
	let (forged_tx, good_tx) = (reclaim(&forged), reclaim(&trees));
	c.net.refuse("RECLAIM-D: owner 3's release forged", &forged_tx, "Invalid Schnorr signature");
	c.net.pass("collect: lowest node 0 back by RECLAIM-D", &good_tx);
	assert!(!c.unspent(&node0.outpoint));

	// Lowest node 1: owner 5 gave its leaf up, owner 4 is away for good.
	let n1 = lowest[1].clone();
	let u = valid_a[4].branch.nodes[1].unroll_tx(node1.outpoint, &operator_auth(&n1, &s, t), &FeeSource::Reserve).unwrap();
	let entries = c.net.pass("collect: the operator unrolls lowest node 1", &u.tx);
	let e4 = coin_of(entries, 0, &u.tx);
	let entry4 = &tree.leaves()[4].entry;
	let mut twin_entry = *entry4;
	twin_entry.sweep = Some(sched.sweep(true, false));
	let tx = by_removed_sweep(&c.net, &e4, &sweep_w, &twin_entry.taproot(), &s, 0xffff_fffe);
	c.net.refuse("removed: an entry's sweep", &tx, MISMATCH);
	// Owner 4's entry can only become owner 4's leaf.
	let into_op = valid_a[4].branch.entry_tx(e4.outpoint, &pre[4], &FeeSource::Reserve).unwrap();
	let mut bad = into_op.tx.clone();
	bad.output[0].script_pubkey = op_true_spk();
	c.net.refuse("owner 4's entry opened to the operator", &bad, "false/empty top stack element");
	let l4 = c.net.pass("collect: owner 4's entry opened into owner 4's own leaf", &into_op.tx);
	let leaf4 = valid_a[4].branch.leaf.clone();
	c.net.wait_csv(&l4, delay());
	let at4 = OutPoint::new(l4, 0);
	c.net.refuse("owner 4's leaf: the operator's exit", &exit_tx(&c.net, &leaf4, at4, c.net.x, LEAF, &s), "Invalid Schnorr signature");
	c.net.pass("owner 4 comes back and takes its coin home with its own key", &exit_tx(&c.net, &leaf4, at4, c.net.x, LEAF, &owners[4]));

	// A coin of this batch paid on out of round: its checkpoint has the
	// collaborative path alone, and the coin never expires.
	let base6 = base(&tree, 6, &owners[6], pre[6], t);
	let strict = WalletPolicy::no_sweep(chain, xonly(&s), mt(c.net.mtp()));
	let coin6 = base6.resolve(std::slice::from_ref(&round_a), &strict).unwrap();
	assert_eq!(coin6.expiry, transfer::NEVER);
	let first = match &coin6.origin { ValidOrigin::Leaf { valid, .. } => valid.clone(), _ => unreachable!() };
	let cp = CheckpointPolicy { owner: first.branch.leaf.owner, operator: xonly(&s), salt: transfer::checkpoint_salt(&first.branch.leaf.salt),
		chain, sweep: None, v2: false };
	assert_eq!(cp.script_pubkey(), TapOutput::new(vec![(0, cp.collab_script())]).script_pubkey(), "a checkpoint: [collab]");
	let (_d, d_leaf) = party("ns receiver", delay());
	let paid = one_hop(&base6, &coin6, &owners[6], &s, d_leaf, chain).resolve(std::slice::from_ref(&round_a), &strict).unwrap();
	assert_eq!(paid.expiry, transfer::NEVER, "a coin paid on from a batch without a sweep never expires");
	match &paid.origin {
		ValidOrigin::Transfer { inputs, .. } => {
			assert!(inputs[0].coin.sweep.is_none() && inputs[0].checkpoint.sweep.is_none());
			let cpo = inputs[0].checkpoint;
			assert_eq!(cpo.script_pubkey(), cp.script_pubkey());
			let cp_coin = c.net.fund(vec![explicit(c.net.x, LEAF, cpo.script_pubkey())]).remove(0);
			let mut twin_cp = cpo;
			twin_cp.sweep = Some(sched.sweep(true, false));
			let tx = by_removed_sweep(&c.net, &cp_coin, &sweep_w, &twin_cp.taproot(), &s, 0xffff_fffe);
			c.net.refuse("removed: a checkpoint's sweep", &tx, MISMATCH);
		},
		_ => unreachable!("a reassignment's output"),
	}
	c.net.print();
}

/// An accumulator batch built with the never schedule is
/// `arca/accumulator-2`, which has no sweep (its release and exits are proven
/// on the chain in `accumulator_release.rs`); it has no sweep to be burn-only.
#[test]
fn an_accumulator_batch_without_a_sweep_is_accumulator_2() {
	let s = keypair("no-sweep accumulator operator");
	let chain = Chain::new(elements::BlockHash::from_byte_array(label32("no-sweep chain")));
	let owners: Vec<Keypair> = (0..4).map(|i| keypair(&format!("acc owner {}", i))).collect();
	let leaves: Vec<LeafSpec> = (0..4).map(|i| spec(&owners[i], &format!("acc {}", i), LEAF, label32("acc h"))).collect();
	let params = arca_covenant::accumulator::AccumulatorParams {
		asset: asset("acc asset"), chain, schedule: ClockSchedule::never(xonly(&s)), burn: false,
		reserve: ReserveRule::Fixed { node: 1_000, entry: 1_000 }, min_leaf: 1,
	};
	let acc = arca_covenant::accumulator::Accumulator::build(params.clone(), &leaves).unwrap();
	assert!(acc.policy().no_sweep() && acc.policy().sweep_leaf().is_none() && acc.clock0_script_pubkey().is_none());
	assert!(acc.leaves().iter().all(|l| l.entry.sweep.is_none()), "no entry carries a sweep");
	assert_eq!(acc.record(0).to_bytes().unwrap()[0], arca_covenant::accumulator::ACCUMULATOR_RECORD_VERSION_NO_SWEEP);
	let burnt = arca_covenant::accumulator::AccumulatorParams { burn: true, ..params };
	assert!(arca_covenant::accumulator::Accumulator::build(burnt, &leaves).is_err());
}

#[test]
fn the_never_schedule_is_the_only_one_naming_the_no_sweep_token() {
	let s = xonly(&keypair("never"));
	let never = ClockSchedule::never(s);
	assert!(!never.expires() && never.sweep_path(true, false).is_none());
	assert_eq!(ClockSchedule::new_unchecked(never.token, s, delay(), vec![mt(1_700_000_000)]).unwrap_err(), Error::NoSweepSchedule);
	assert_eq!(ClockSchedule::new_unchecked(never.token, s, never.notice, never.expiries().to_vec()).unwrap(), never);
	use arca_covenant::encode::Encoding;
	assert_eq!(ClockSchedule::decode(&never.encode()).unwrap(), never);
}

use elements::hashes::Hash;
use elements::Script;
