//! The accumulator batch without a sweep (`arca/accumulator-2`) and its
//! release, on a Sequentia regtest chain with Simplicity active.
//!
//! A round pays a batch of 40 leaves of X under [`ClockSchedule::never`]: no
//! token, no clock, and a batch output of the program and its data leaf
//! alone. Its owners refresh: round B gives them new coins and is rolled back
//! and replaced by B2, and round C gives the rest theirs. Each owner signs the
//! release of its old slot for the round of its new coin (`M`, that round's
//! connector asset), and the operator takes the slots back in batches:
//!
//! 1. the records are format version 4 and a wallet that accepts only
//!    batches without a sweep takes them, while it refuses a batch with one;
//! 2. a release of one slot, paying the operator exactly what the slot
//!    weighed; an exit after it; a release of 14 slots of two rounds after
//!    the exit; an exit by the operator to the owner's entry after that; and
//!    the last nine slots, by the program that leaves no rest;
//! 3. every spend read back from the chain alone ([`follow`]).
//!
//! Every negative case is a copy of an accepted control with one property
//! changed, refused by `testmempoolaccept`, by `sendrawtransaction`, and
//! when forced into a block with `generateblock` on a node checking scripts
//! inline (`-par=1`), the block's reason asserted; the Rust judge
//! ([`AccumulatorPolicy::check_release`]) names the rule it breaks:
//!
//! - a release signed by a stranger, by another slot's owner, by the operator
//!   for the owner, and the owner's release under another batch's `ROOT`;
//! - a release for the round that was rolled back, with its connector's atom
//!   (which no longer exists) and with the replacement's;
//! - a slot twice in one release, slots out of order, and a slot whose bit is
//!   already set;
//! - the rest under another `ROOT`, another `OPERATOR`, or one atom short so
//!   the operator takes more than the slots weighed; the operator's
//!   signature missing, or over another payout;
//! - an annex on the release;
//! - the removed SWEEP leaf, with a real token at `R` beside it: on the
//!   batch output by its twin's control block and as a lone leaf, beside a
//!   twin with the sweep that the same leaf, token and signature sweep.
//!
//! Needs `SEQUENTIAD_EXEC`; `--nocapture` prints every transaction.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::{AssetIssuance, OutPoint, Script, Transaction};

use arca_covenant::accumulator::{follow, payout_digest, read_spend, release_digest, AccumulatorRelease, Released, SeenSpend};
use arca_covenant::script::sha256;
use arca_covenant::spend::FeeSource;
use arca_covenant::taptree::TapOutput;
use arca_covenant::tree::{LeafSpec, ReserveRule};
use arca_covenant::*;

use common::net::*;
use common::round::*;
use common::*;

const LEAVES: usize = 40;
const VALUE: u64 = 1_000_000;
/// What a release pays as its fee, out of what the slots weighed.
const FEE: u64 = 5_000;

/// An `assert!` or a jet that fails: every check of the program but one.
const INSIDE_JET: &str = "mempool-script-verify-flag-failed (Assertion failed inside jet)";
/// A leaf the output does not commit to.
const MISMATCH: &str = "Witness program hash mismatch";
/// An annex where the program requires none, in a block: `is_none` of the
/// input's annex hash fails as an assertion the compiler makes. The block's
/// label is `mandatory-` or `mempool-` by the node's build; the block is
/// refused under its consensus flags either way.
const ANNEX: &str = "-script-verify-flag-failed (Assertion failed)";

/// The pieces of a release a negative case changes one at a time.
#[derive(Clone)]
struct RawRelease {
	state: AccumulatorPolicy,
	coin: OutPoint,
	held: u64,
	/// Each slot and the index of the input holding its connector asset.
	slots: Vec<(Released, u32)>,
	connectors: Vec<Coin>,
	/// The operator's payout at output 0.
	pay: u64,
	/// The rest: its value and script, or none.
	rest: Option<(u64, Script)>,
	/// Who signs the payout digest, and over which transaction's outputs
	/// (this one's when `None`).
	operator: Keypair,
	signed_outputs: Option<Transaction>,
	/// The witness's state, when it is not the coin's.
	witness_state: Option<AccumulatorPolicy>,
	annex: Option<Vec<u8>>,
}

impl RawRelease {
	/// The honest release of `slots` from `state`, the connector of each in
	/// `connectors` (inputs 1 on), paying the operator what they weigh less
	/// [`FEE`].
	fn new(state: &AccumulatorPolicy, coin: OutPoint, held: u64, slots: &[Released], connectors: &[Coin], s: &Keypair) -> RawRelease {
		let weight: u64 = slots.iter().map(|r| r.exit.record.weight().unwrap()).sum();
		let at = |r: &Released| 1 + connectors.iter().position(|c| c.txout.asset.explicit() == Some(r.connector)).unwrap() as u32;
		let next: Vec<u16> = slots.iter().map(|r| r.exit.slot).collect();
		let rest = held - weight;
		RawRelease {
			state: *state, coin, held, slots: slots.iter().map(|r| (r.clone(), at(r))).collect(), connectors: connectors.to_vec(),
			pay: weight - FEE, rest: (rest > 0).then(|| (rest, state.after_all(&next).script_pubkey())), operator: s.clone(),
			signed_outputs: None, witness_state: None, annex: None,
		}
	}

	fn tx(&self, net: &Net) -> Transaction {
		let mut outs = vec![explicit(net.x, self.pay, op_true_spk())];
		let mut paid = self.pay;
		if let Some((v, spk)) = &self.rest {
			outs.push(explicit(net.x, *v, spk.clone()));
			paid += v;
		}
		for c in &self.connectors {
			outs.push(explicit(c.txout.asset.explicit().unwrap(), 1, op_true_spk()));
		}
		outs.push(fee(net.x, self.held - paid));
		let mut sp = spend(0).input(self.coin, explicit(net.x, self.held, self.state.script_pubkey()), 0xffff_ffff);
		for c in &self.connectors {
			sp = sp.coin(c, 0xffff_ffff);
		}
		let mut sp = sp.outputs(outs);
		let ws = self.witness_state.unwrap_or(self.state);
		let over = self.signed_outputs.clone().unwrap_or_else(|| sp.tx.clone());
		let op_sig = sig(&self.operator, &payout_digest(&net.chain, &ws, 0, &over));
		let places: Vec<(&Released, u32)> = self.slots.iter().map(|(r, i)| (r, *i)).collect();
		let mut w = ws.release_witness(&places, &op_sig, self.rest.is_none());
		// The control block is always the coin's own: only the witness's
		// claim about the state differs.
		w[3] = self.state.control_block();
		w.extend(self.annex.clone());
		sp.witness(0, w);
		for i in 0..self.connectors.len() {
			sp.witness(1 + i, op_true_witness());
		}
		sp.tx
	}

	/// The Rust judge's verdict on the transaction.
	fn judge(&self, net: &Net, tx: &Transaction) -> Result<(), AccumulatorError> {
		let mut prevouts = vec![explicit(net.x, self.held, self.state.script_pubkey())];
		prevouts.extend(self.connectors.iter().map(|c| c.txout.clone()));
		let ws = self.witness_state.unwrap_or(self.state);
		let slots: Vec<Released> = self.slots.iter().map(|(r, _)| r.clone()).collect();
		let inputs: Vec<u32> = self.slots.iter().map(|(_, i)| *i).collect();
		let over = self.signed_outputs.clone().unwrap_or_else(|| tx.clone());
		let op_sig = sig(&self.operator, &payout_digest(&net.chain, &ws, 0, &over));
		ws.check_release(&net.chain, tx, 0, &prevouts, &slots, &inputs, &op_sig)
	}
}

/// A negative case: refused by the Rust judge, by the mempool and in a block.
fn refuse(net: &mut Net, name: &str, raw: &RawRelease, expect: &str) {
	let tx = raw.tx(net);
	let why = raw.judge(net, &tx).expect_err(&format!("{}: the Rust judge took it", name));
	println!("  {}: the judge says: {}", name, why);
	net.refuse(name, &tx, expect);
}

/// A round of a batch without a sweep, from `funding`: the batch output, the
/// connector output, change and a fee of `fee`. Built, not broadcast.
fn never_round(net: &Net, s: &Keypair, batch: &ExplicitOutput, funding: &Coin, fee_atoms: u64) -> (Transaction, u32) {
	let total = funding.txout.value.explicit().unwrap();
	let outs = vec![batch.txout(), ConnectorPolicy { operator: xonly(s) }.output(net.x, 5_000).txout(),
		explicit(net.x, total - batch.value - 5_000 - fee_atoms, op_true_spk()), fee(net.x, fee_atoms)];
	let mut sp = spend(0).coin(funding, 0xffff_ffff).outputs(outs);
	sp.witness(0, op_true_witness());
	(sp.tx, 1)
}

fn never_params(a: &Arca, s: &Keypair) -> AccumulatorParams {
	AccumulatorParams {
		asset: a.net.x, chain: a.net.chain, schedule: ClockSchedule::never(xonly(s)), burn: false,
		reserve: ReserveRule::FeeRate { floor_per_kvb: a.floor_per_kvb, multiple: 4 }, min_leaf: 1,
	}
}

/// New leaves for the owners `range`, for their refresh into round `label`.
fn new_specs(label: &str, range: std::ops::Range<usize>) -> (Vec<Keypair>, Vec<LeafSpec>) {
	let keys: Vec<Keypair> = range.clone().map(|i| keypair(&format!("{} new owner {}", label, i))).collect();
	let specs = range.enumerate()
		.map(|(n, i)| spec(&keys[n], &format!("{} new leaf {}", label, i), VALUE, sha256(&label32(&format!("{} new preimage {}", label, i)))))
		.collect();
	(keys, specs)
}

#[test]
fn accumulator_release_on_regtest() {
	let mut a = Arca::start();
	let s = keypair("release operator");
	let x = a.net.x;
	let chain = a.net.chain;
	let strict = WalletPolicy::no_sweep(chain, xonly(&s), mt(a.net.mtp()));

	// --- The batch: 40 leaves, no sweep ------------------------------------
	let owners: Vec<Keypair> = (0..LEAVES).map(|i| keypair(&format!("release owner {}", i))).collect();
	let preimages: Vec<[u8; 32]> = (0..LEAVES).map(|i| label32(&format!("release preimage {}", i))).collect();
	let specs: Vec<LeafSpec> = (0..LEAVES)
		.map(|i| spec(&owners[i], &format!("release leaf {}", i), VALUE + 7 * i as u64, sha256(&preimages[i])))
		.collect();
	let acc = Accumulator::build(never_params(&a, &s), &specs).unwrap();
	let state0 = *acc.policy();
	assert!(state0.no_sweep() && acc.clock0_script_pubkey().is_none(), "no sweep, no token");
	assert_eq!(state0.script_pubkey(), TapOutput::with_nodes(vec![
		(1, arca_covenant::taptree::TapNode::Simplicity(arca_covenant::accumulator::accumulator2_cmr())),
		(1, arca_covenant::taptree::TapNode::Hidden(state0.data_leaf())),
	]).script_pubkey(), "the batch output: TapBranch(X2, D)");
	let burnt = AccumulatorParams { burn: true, ..never_params(&a, &s) };
	assert!(Accumulator::build(burnt, &specs).is_err(), "burn-only names a sweep the batch has not");

	// --- 1. The records and the wallet's check ------------------------------
	let rec = acc.record(0);
	let bytes = rec.to_bytes().unwrap();
	assert_eq!(bytes[0], arca_covenant::accumulator::ACCUMULATOR_RECORD_VERSION_NO_SWEEP);
	assert_eq!(AccumulatorRecord::from_bytes(&bytes).unwrap(), rec);
	let funding = a.net.fund(vec![explicit(x, acc.total() + 200_000, op_true_spk())]).remove(0);
	let (round_a, _ca) = never_round(&a.net, &s, &acc.batch_output(), &funding, 2_000);
	let valid: Vec<ValidAccumulatorLeaf> = (0..LEAVES)
		.map(|i| acc.record(i).validate(&round_a, &strict, &xonly(&owners[i]), &specs[i].owner_nonce)
			.unwrap_or_else(|e| panic!("slot {}: {}", i, e)))
		.collect();
	let round_a_id = a.net.pass("round A: a 40-leaf accumulator batch without a sweep", &round_a);
	let batch0 = OutPoint::new(round_a_id, 0);
	println!("every one of the 40 records passes the check of a wallet that accepts only batches without a sweep");
	// A batch with a sweep: refused by that wallet, taken by the general policy.
	let (issuer, sched) = a.schedule(&s);
	let swept_specs: Vec<LeafSpec> = (0..2).map(|i| spec(&owners[i], &format!("release swept leaf {}", i), VALUE, sha256(&preimages[i]))).collect();
	let swept = Accumulator::build(AccumulatorParams { schedule: sched.clone(), ..never_params(&a, &s) }, &swept_specs).unwrap();
	let (swept_round, _) = round_tx(&a.net, &issuer, &[], &swept.batch_output(), &sched);
	a.net.pass("an accumulator batch with a sweep (arca/accumulator-1): its round", &swept_round);
	assert_eq!(swept.record(0).validate(&swept_round, &strict, &xonly(&owners[0]), &swept_specs[0].owner_nonce).unwrap_err(),
		AccumulatorError::Record(RecordError::SweepRefused), "the strict wallet refuses accumulator-1");
	let swept_valid = swept.record(0).validate(&swept_round, &a.policy(&s), &xonly(&owners[0]), &swept_specs[0].owner_nonce)
		.expect("the general policy takes accumulator-1");
	// The no-sweep token in a version 1 record is refused: it is written as version 4 alone.
	let mut v1 = swept.record(0).to_bytes().unwrap();
	let at = v1.windows(32).position(|w| w == arca_covenant::script::asset_bytes(sched.token)).unwrap();
	v1[at..at + 32].copy_from_slice(&arca_covenant::script::asset_bytes(no_sweep_token()));
	assert!(AccumulatorRecord::from_bytes(&v1).is_err());

	// --- 2. Round B, rolled back, and B2 in its place; round C ---------------
	let (b_keys, b_specs) = new_specs("B", 0..20);
	let acc_b = Accumulator::build(never_params(&a, &s), &b_specs).unwrap();
	let fund_b = a.net.fund(vec![explicit(x, acc_b.total() + 200_000, op_true_spk())]).remove(0);
	let (round_b1, cb) = never_round(&a.net, &s, &acc_b.batch_output(), &fund_b, 2_000);
	let (round_b2, _) = never_round(&a.net, &s, &acc_b.batch_output(), &fund_b, 2_100);
	let new_b1: Vec<ValidAccumulatorLeaf> = (0..20).map(|n| acc_b.record(n).validate(&round_b1, &strict, &xonly(&b_keys[n]),
		&b_specs[n].owner_nonce).unwrap()).collect();
	let b1_id = a.net.pass("round B: the new coins of owners 0 to 19", &round_b1);
	let issue_b1 = issuance_tx(&a.net, &round_b1, cb, &s);
	let m_b1_coin = coin_of(a.net.pass("round B: its connector asset M_B issued", &issue_b1), 0, &issue_b1);
	let m_b1 = m_b1_coin.txout.asset.explicit().unwrap();
	// The owners release for round B, which the wallet takes for final.
	let rel = |old: &ValidAccumulatorLeaf, new: &ValidAccumulatorLeaf, round: &Transaction, c: u32, key: &Keypair| {
		let r = AccumulatorRelease::for_accumulator_refresh(old, new, round, c).unwrap();
		let signature = sig(key, &r.digest());
		r.verify(&signature).unwrap();
		Released { exit: old.exit.clone(), connector: r.connector, signature }
	};
	let released_b1: Vec<Released> = (0..20).map(|i| rel(&valid[i], &new_b1[i], &round_b1, cb, &owners[i])).collect();
	assert!(AccumulatorRelease::for_accumulator_refresh(&valid[0], &new_b1[0], &round_b2, cb).is_err(), "a wallet signs only for its round");
	assert!(AccumulatorRelease::for_accumulator_refresh(&swept_valid, &new_b1[0], &round_b1, cb).is_err(),
		"accumulator-1 has no release");
	// B is rolled back with its M, and B2, paying the same coins, takes its place.
	a.roll_back(&b1_id);
	a.mine_with(&[&round_b2]);
	assert!(!a.unspent(&m_b1_coin.outpoint), "round B's connector atom left the chain with it");
	let new_b2: Vec<ValidAccumulatorLeaf> = (0..20).map(|n| acc_b.record(n).validate(&round_b2, &strict, &xonly(&b_keys[n]),
		&b_specs[n].owner_nonce).unwrap()).collect();
	let issue_b2 = issuance_tx(&a.net, &round_b2, cb, &s);
	let m_b2_coin = coin_of(a.net.pass("round B2, which replaced B: its connector asset M_B2 issued", &issue_b2), 0, &issue_b2);
	let m_b2 = m_b2_coin.txout.asset.explicit().unwrap();
	assert_ne!(m_b1, m_b2);
	let released_b2: Vec<Released> = (0..20).map(|i| rel(&valid[i], &new_b2[i], &round_b2, cb, &owners[i])).collect();
	let (c_keys, c_specs) = new_specs("C", 20..LEAVES);
	let acc_c = Accumulator::build(never_params(&a, &s), &c_specs).unwrap();
	let fund_c = a.net.fund(vec![explicit(x, acc_c.total() + 200_000, op_true_spk())]).remove(0);
	let (round_c, cc) = never_round(&a.net, &s, &acc_c.batch_output(), &fund_c, 2_000);
	let new_c: Vec<ValidAccumulatorLeaf> = (0..20).map(|n| acc_c.record(n).validate(&round_c, &strict, &xonly(&c_keys[n]),
		&c_specs[n].owner_nonce).unwrap()).collect();
	a.net.pass("round C: the new coins of owners 20 to 39", &round_c);
	let issue_c = issuance_tx(&a.net, &round_c, cc, &s);
	let m_c_coin = coin_of(a.net.pass("round C: its connector asset M_C issued", &issue_c), 0, &issue_c);
	let released: Vec<Released> = (0..LEAVES).map(|i| if i < 20 { released_b2[i].clone() } else {
		rel(&valid[i], &new_c[i - 20], &round_c, cc, &owners[i])
	}).collect();

	// --- Release 1: slot 3 alone ------------------------------------------
	let held0 = acc.total();
	let built = state0.release_tx(&chain, batch0, (x, held0), &released[3..4], &[(m_b2_coin.outpoint, m_b2_coin.txout.clone())],
		&[ExplicitOutput::new(x, acc.slots()[3].weight().unwrap() - FEE, op_true_spk())], op_true_spk(), &FeeSource::Reserve).unwrap();
	let r1 = RawRelease::new(&state0, batch0, held0, &released[3..4], &[m_b2_coin.clone()], &s);
	let mut lib = built.clone().finish(&sig(&s, &built.digest(&chain)));
	lib.input[1].witness.script_witness = op_true_witness();
	assert_eq!(lib, r1.tx(&a.net), "the library's release is the test's control");
	r1.judge(&a.net, &lib).unwrap();

	// No path takes a slot its owner has not released.
	let stranger = keypair("release stranger");
	let resign = |r: &Released, key: &Keypair, root: &[u8; 32], m| Released {
		signature: sig(key, &release_digest(&chain, root, &r.exit.record.record(r.exit.slot), m)), ..r.clone()
	};
	let mut n = r1.clone();
	n.slots[0].0 = resign(&released[3], &stranger, &state0.root, m_b2);
	refuse(&mut a.net, "neg release signed by a stranger", &n, INSIDE_JET);
	let mut n = r1.clone();
	n.slots[0].0 = resign(&released[3], &owners[4], &state0.root, m_b2);
	refuse(&mut a.net, "neg release signed by another slot's owner", &n, INSIDE_JET);
	let mut n = r1.clone();
	n.slots[0].0 = resign(&released[3], &s, &state0.root, m_b2);
	refuse(&mut a.net, "neg release signed by the operator for the owner", &n, INSIDE_JET);
	let mut n = r1.clone();
	n.slots[0].0 = resign(&released[3], &owners[3], &acc_b.policy().root, m_b2);
	refuse(&mut a.net, "neg release: the owner's release under another batch's ROOT", &n, INSIDE_JET);
	// The rolled-back round: its M's atom is gone; with B2's atom the release
	// signed for B does not verify.
	let mut n = RawRelease::new(&state0, batch0, held0, &released_b1[3..4], &[m_b1_coin.clone()], &s);
	n.slots[0].1 = 1;
	let tx = n.tx(&a.net);
	a.net.refuse("neg release for the rolled-back round B, with its connector's atom", &tx, "bad-txns-inputs-missingorspent");
	let mut n = r1.clone();
	n.slots[0].0 = released_b1[3].clone();
	refuse(&mut a.net, "neg release signed for the rolled-back round B, with B2's atom", &n, INSIDE_JET);
	// The operator's part.
	let mut n = r1.clone();
	n.operator = stranger.clone();
	refuse(&mut a.net, "neg release without the operator's signature (a stranger's)", &n, INSIDE_JET);
	let mut n = r1.clone();
	n.signed_outputs = Some({ let mut t = r1.tx(&a.net); t.output[0].script_pubkey = Script::from(vec![0x52]); t });
	refuse(&mut a.net, "neg release: the operator's signature over another payout", &n, INSIDE_JET);
	let mut n = r1.clone();
	n.rest = n.rest.map(|(v, spk)| (v - 1, spk));
	n.pay += 1;
	refuse(&mut a.net, "neg release: the operator takes one atom more than the slot weighed", &n, INSIDE_JET);
	let mut other_root = state0.after(3);
	other_root.root = acc_b.policy().root;
	let mut n = r1.clone();
	n.rest = n.rest.map(|(v, _)| (v, other_root.script_pubkey()));
	refuse(&mut a.net, "neg release: the rest under another ROOT", &n, INSIDE_JET);
	let mut other_op = state0.after(3);
	other_op.operator = xonly(&stranger);
	let mut n = r1.clone();
	n.rest = n.rest.map(|(v, _)| (v, other_op.script_pubkey()));
	refuse(&mut a.net, "neg release: the rest under another OPERATOR", &n, INSIDE_JET);
	let mut n = r1.clone();
	n.rest = n.rest.map(|(v, _)| (v, state0.script_pubkey()));
	refuse(&mut a.net, "neg release: the rest with the slot's bit clear", &n, INSIDE_JET);
	let mut n = r1.clone();
	n.slots.push(n.slots[0].clone());
	n.rest = n.rest.map(|(v, spk)| (v - acc.slots()[3].weight().unwrap(), spk));
	n.pay += acc.slots()[3].weight().unwrap();
	refuse(&mut a.net, "neg release of one slot twice", &n, INSIDE_JET);
	let mut n = r1.clone();
	n.annex = Some(vec![0x50, 0x00, 0x00]);
	let tx = n.tx(&a.net);
	refuse_relay_any(&mut a.net, "neg release with a 3-byte annex", &tx, ANNEX);
	// The removed SWEEP leaf, a real token at R beside it.
	removed_sweep(&mut a, &s, &state0, batch0, held0, &sched);

	let id1 = a.net.pass("release 1: slot 3, for round B2", &lib);
	let m_b2_coin = moved(id1, &lib, m_b2);
	let paid1 = lib.output[0].value.explicit().unwrap() + fee_of(&lib, x);
	assert_eq!(paid1, acc.slots()[3].weight().unwrap(), "the operator takes exactly what the slot weighed, its fee included");
	let state1 = state0.after(3);
	let held1 = held0 - acc.slots()[3].weight().unwrap();
	let batch1 = OutPoint::new(id1, 1);
	assert_eq!(lib.output[1], explicit(x, held1, state1.script_pubkey()));
	let mut n = RawRelease::new(&state1, batch1, held1, &released[3..5], &[m_b2_coin.clone()], &s);
	n.rest = Some((held1 - acc.slots()[3].weight().unwrap() - acc.slots()[4].weight().unwrap(), state1.after(4).script_pubkey()));
	refuse(&mut a.net, "neg release of a slot whose bit is already set", &n, INSIDE_JET);

	// --- Exit after a release: slot 4 by its owner ---------------------------
	let t0 = mt(a.net.mtp() - 1);
	let auth4 = ExitAuth { by_operator: false, time: t0, signature: sig(&owners[4], &valid[4].exit_digest(t0)) };
	let e = valid[4].exit_tx(&state1, batch1, held1, &auth4, &FeeSource::Reserve).unwrap();
	let id2 = a.net.pass("exit after a release: slot 4 by its owner", &e.tx);
	let state2 = state1.after(4);
	let held2 = held1 - acc.slots()[4].weight().unwrap();
	let batch2 = OutPoint::new(id2, 1);

	// --- Release 2: 14 slots of two rounds, after the exit -------------------
	let fourteen: Vec<usize> = (13..27).collect();
	let r2 = RawRelease::new(&state2, batch2, held2, &fourteen.iter().map(|&i| released[i].clone()).collect::<Vec<_>>(),
		&[m_b2_coin.clone(), m_c_coin.clone()], &s);
	let mut n = r2.clone();
	n.slots.swap(0, 1);
	refuse(&mut a.net, "neg release of 14 slots, two out of order", &n, INSIDE_JET);
	let tx2 = r2.tx(&a.net);
	r2.judge(&a.net, &tx2).unwrap();
	let id3 = a.net.pass("release 2: 14 slots after the exit, owners of rounds B2 and C", &tx2);
	let m_c = m_c_coin.txout.asset.explicit().unwrap();
	let (m_b2_coin, m_c_coin) = (moved(id3, &tx2, m_b2), moved(id3, &tx2, m_c));
	let w14: u64 = fourteen.iter().map(|&i| acc.slots()[i].weight().unwrap()).sum();
	assert_eq!(tx2.output[0].value.explicit().unwrap() + fee_of(&tx2, x), w14, "the operator takes exactly what the 14 weighed");
	let state3 = state2.after_all(&fourteen.iter().map(|&i| i as u16).collect::<Vec<_>>());
	let held3 = held2 - w14;
	let batch3 = OutPoint::new(id3, 1);
	assert_eq!(tx2.output[1], explicit(x, held3, state3.script_pubkey()));

	// --- An exit by the operator after it, to the owner's entry ---------------
	let op_auth = ExitAuth { by_operator: true, time: t0, signature: sig(&s, &valid[30].exit_digest(t0)) };
	let e = valid[30].exit_tx(&state3, batch3, held3, &op_auth, &FeeSource::Reserve).unwrap();
	assert_eq!(e.tx.output[0], valid[30].entry_output().txout(), "the operator's exit pays the owner's entry");
	let id4 = a.net.pass("exit after a release: slot 30 by the operator, to its owner's entry", &e.tx);
	let entry = valid[30].entry_tx(OutPoint::new(id4, 0), &preimages[30], &FeeSource::Reserve).unwrap();
	assert_eq!(entry.tx.output[0], valid[30].leaf_output().txout(), "the entry opens only into the owner's leaf");
	let state4 = state3.after(30);
	let held4 = held3 - acc.slots()[30].weight().unwrap();
	let batch4 = OutPoint::new(id4, 1);

	// --- Release 3: the rest of the batch, then the last nine ---------------
	let more: Vec<usize> = (0..LEAVES).filter(|i| ![3, 4, 30].contains(i) && !fourteen.contains(i)).collect();
	let (first, last) = more.split_at(more.len() - 9);
	let r3 = RawRelease::new(&state4, batch4, held4, &first.iter().map(|&i| released[i].clone()).collect::<Vec<_>>(),
		&[m_b2_coin.clone(), m_c_coin.clone()], &s);
	let tx3 = r3.tx(&a.net);
	let id5 = a.net.pass(&format!("release 3: {} slots after the operator's exit", first.len()), &tx3);
	let m_c_coin = moved(id5, &tx3, m_c);
	let w3: u64 = first.iter().map(|&i| acc.slots()[i].weight().unwrap()).sum();
	let state5 = state4.after_all(&first.iter().map(|&i| i as u16).collect::<Vec<_>>());
	let held5 = held4 - w3;
	let r4 = RawRelease::new(&state5, OutPoint::new(id5, 1), held5, &last.iter().map(|&i| released[i].clone()).collect::<Vec<_>>(),
		&[m_c_coin.clone()], &s);
	assert!(r4.rest.is_none(), "the last nine take the last of the batch");
	let tx4 = r4.tx(&a.net);
	r4.judge(&a.net, &tx4).unwrap();
	a.net.pass("release 4: the last nine slots, no rest", &tx4);

	// --- 3. The batch read back from the chain alone --------------------------
	let txs: Vec<Transaction> = [id1, id2, id3, id4, id5, tx4.txid()].iter().map(|t| a.net.rt.client().raw_transaction(t).unwrap()).collect();
	match read_spend(&txs[2].input[0].witness.script_witness).unwrap() {
		SeenSpend::Release(r) => {
			assert_eq!(r.slots, fourteen.iter().map(|&i| i as u16).collect::<Vec<_>>());
			assert_eq!(r.bitmap, state2.bitmap);
			assert!(!r.last);
		},
		other => panic!("release 2 read as {:?}", other),
	}
	assert!(matches!(read_spend(&txs[3].input[0].witness.script_witness), Some(SeenSpend::Exit(e)) if e.by_operator && e.slot == 30));
	let spends: Vec<(&Transaction, usize)> = txs.iter().map(|t| (t, 0)).collect();
	assert_eq!(follow(&state0, &spends[..5]).unwrap(), Some(state5));
	assert_eq!(follow(&state0, &spends).unwrap(), None, "the last release took the last of the batch");
	println!("the batch's six spends, read back from their witnesses alone: four releases, two exits, nothing left");

	a.net.print();
	println!("\n{} confirmed, {} refused in a block", a.net.confirmed, a.net.refused);
}

/// Where a release paid the connector atom of `m` back: the operator reuses it.
fn moved(txid: elements::Txid, tx: &Transaction, m: elements::AssetId) -> Coin {
	let v = tx.output.iter().position(|o| o.asset.explicit() == Some(m)).unwrap();
	coin_of(txid, v as u32, tx)
}

/// What the fee output of `tx` pays in `asset`.
fn fee_of(tx: &Transaction, asset: elements::AssetId) -> u64 {
	tx.output.iter().filter(|o| o.script_pubkey.is_empty() && o.asset.explicit() == Some(asset)).map(|o| o.value.explicit().unwrap()).sum()
}

/// Refused by relay policy for any reason, and in a block for `block`.
fn refuse_relay_any(net: &mut Net, name: &str, tx: &Transaction, block: &str) {
	let r = net.rt.client().test_mempool_accept(&[tx]).unwrap().remove(0);
	assert!(!r.allowed, "{}: ACCEPTED by testmempoolaccept", name);
	let reason = r.reject_reason.unwrap_or_default();
	let h0 = net.height();
	let refused = match net.rt.client().generate_block("raw(51)", &[tx]) {
		Ok(_) => panic!("{}: MINED by generateblock", name),
		Err(e) => e.to_string(),
	};
	assert_eq!(net.height(), h0);
	assert!(refused.contains(block), "{}: the block was refused with {:?}, expected {:?}", name, refused, block);
	net.refused += 1;
	net.rows.push(Row { name: name.into(), vsize: String::new(), mempool: reason, block: refused });
}

/// The SWEEP leaf an accumulator-1 batch output carries, with a real token at
/// `R`: refused on the accumulator-2 output by its twin's control block and as
/// a lone leaf, while the same leaf, token and signature sweep the twin, an
/// output of the same state with the sweep, funded beside it.
fn removed_sweep(a: &mut Arca, s: &Keypair, state: &AccumulatorPolicy, batch: OutPoint, held: u64, sched: &ClockSchedule) {
	let x = a.net.x;
	// The token, issued straight to R, and its notice waited.
	let issuer = a.net.fund(vec![explicit(x, 100_000, op_true_spk())]).remove(0);
	let token = token_of(&issuer);
	let sched = ClockSchedule::new(token, sched.operator, sched.notice, sched.expiries().to_vec()).unwrap();
	let mut sp = spend(0).coin(&issuer, 0xffff_ffff)
		.outputs(vec![explicit(token, 1, sched.r().script_pubkey()), explicit(x, 98_000, op_true_spk()), fee(x, 2_000)]);
	sp.tx.input[0].asset_issuance = AssetIssuance {
		asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: [0; 32],
		amount: elements::confidential::Value::Explicit(1), inflation_keys: elements::confidential::Value::Null, denomination: 0,
	};
	sp.witness(0, op_true_witness());
	let t_id = a.net.pass("a real token, issued to R", &sp.tx);
	a.net.wait_csv(&t_id, sched.notice);
	let at_r = coin_of(t_id, 0, &sp.tx);
	let sweep = sched.sweep(false, false);
	let twin = AccumulatorPolicy { sweep: Some(sweep), ..*state };
	let twin_coin = a.net.fund(vec![explicit(x, held, twin.script_pubkey())]).remove(0);
	let attempt = |net: &Net, coin: OutPoint, spk: Script, tap: &TapOutput| {
		let mut sp = spend(0).input(coin, explicit(x, held, spk), 0xffff_ffff)
			.input(at_r.outpoint, at_r.txout.clone(), sched.notice.to_sequence())
			.outputs(vec![explicit(x, held - 5_000, op_true_spk()), explicit(token, 1, sched.r().script_pubkey()), fee(x, 5_000)]);
		let s0 = sp.sign(s, 0, &sweep.script(), net.genesis);
		let s1 = sp.sign(s, 1, &sched.r_script(), net.genesis);
		sp.witness(0, tap.witness(&sweep.script(), Sweep::witness_items(&s0, 1)));
		sp.witness(1, sched.r().witness(&sched.r_script(), ClockSchedule::r_witness_items(&s1)));
		sp.tx
	};
	let tx = attempt(&a.net, batch, state.script_pubkey(), &twin.taproot());
	a.net.refuse("neg the removed SWEEP on the batch, its twin's control block, a real token at R", &tx, MISMATCH);
	let tx = attempt(&a.net, batch, state.script_pubkey(), &TapOutput::new(vec![(0, sweep.script())]));
	a.net.refuse("neg the removed SWEEP on the batch as a lone leaf, a real token at R", &tx, MISMATCH);
	let tx = attempt(&a.net, twin_coin.outpoint, twin.script_pubkey(), &twin.taproot());
	a.net.pass("control: the same leaf, token and signature sweep the twin that has it", &tx);
}
