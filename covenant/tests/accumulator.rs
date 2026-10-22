//! The accumulator batch (`arca/accumulator-1`) on an anchored regtest chain
//! with Simplicity active.
//!
//! One round pays a batch of 1,024 leaves of asset X as one accumulator
//! output, its token and its connector. Every owner's wallet check passes on
//! it. The owner of slot 341 leaves in one transaction; every other owner's
//! record and the authorisation each signed before any exit still take its
//! slot out of the new state, and the owner of slot 700 leaves with the
//! authorisation it signed before the first exit. The operator takes slot 5
//! out by its own path, a fee coin paying. Each leaf then goes on through its
//! entry, as a tree leaf does, and exits after its delay.
//!
//! Every negative case is refused by `testmempoolaccept`, by
//! `sendrawtransaction`, and when forced into a block with `generateblock` on
//! a node checking scripts inline (`-par=1`), the block's reason asserted. A
//! Simplicity failure names no rule, so each negative is a copy of an
//! accepted control with one property changed, and the Rust judge
//! (`AccumulatorPolicy::check`) names the rule it breaks:
//!
//! - an exit of a slot that has left, with the state the coin holds and with
//!   the state from before it left;
//! - an exit with a forged path: a sibling, a sibling's weight, the
//!   neighbour's path, a record claiming one atom more;
//! - an exit before its delay: the authorisation's time not reached, by the
//!   program and by the transaction's lock time; the leaf's own exit before
//!   its delay;
//! - a sweep before the notice: inside a roll of the clock, before any
//!   release, and after the release before `W` has passed at `R`;
//! - signatures and outputs: a stranger's signature, the operator's without
//!   its flag, the rest one atom short, the rest under the old state, the
//!   entry to the owner's key, no rest.
//!
//! A 1,024-leaf tree of the same leaves is unrolled to one leaf beside it,
//! for the sizes.
//!
//! Beside it, a batch of 32 leaves: 25 exits chained in the mempool confirm
//! in one block while the 26th waits for it (the mempool's chain limit), and
//! an exit mined in a block anchored to a parent block that is orphaned
//! leaves the chain with it and confirms again under the new branch.
//!
//! Needs `SEQUENTIAD_EXEC`; run with `--nocapture` for the table.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::{OutPoint, Script, Transaction};

use arca_covenant::accumulator::{follow, read_exit, Exit, ExitAuth, SLOTS};
use arca_covenant::spend::FeeSource;
use arca_covenant::tree::{LeafSpec, ReserveRule};
use arca_covenant::*;

use common::net::*;
use common::round::*;
use common::*;

const LEAVES: usize = SLOTS;
const VALUE: u64 = 1_000_000;

/// The pieces of an exit a negative case changes one at a time.
#[derive(Clone)]
struct RawExit {
	state: AccumulatorPolicy,
	coin: OutPoint,
	held: u64,
	exit: Exit,
	entry: ExplicitOutput,
	/// The rest: its value and script, or none.
	rest: Option<(u64, Script)>,
	auth: ExitAuth,
	lock_time: u32,
	/// The witness's state, when it is not the coin's.
	witness_state: Option<AccumulatorPolicy>,
}

impl RawExit {
	/// The honest exit of `exit`'s slot from `state`.
	fn new(state: &AccumulatorPolicy, coin: OutPoint, held: u64, exit: &Exit, entry: &ExplicitOutput, auth: ExitAuth) -> RawExit {
		let rest = held - exit.record.weight().unwrap();
		RawExit {
			state: *state, coin, held, exit: exit.clone(), entry: entry.clone(),
			rest: (rest > 0).then(|| (rest, state.after(exit.slot).script_pubkey())),
			auth, lock_time: auth.time.to_consensus_u32(), witness_state: None,
		}
	}

	/// The transaction: the batch at input 0, the entry and the rest, and
	/// whatever the inputs hold beyond them as the fee, in X.
	fn tx(&self, net: &Net) -> Transaction {
		let mut outs = vec![self.entry.txout()];
		let mut paid = self.entry.value;
		if let Some((v, spk)) = &self.rest {
			outs.push(explicit(net.x, *v, spk.clone()));
			paid += v;
		}
		outs.push(fee(net.x, self.held - paid));
		let prev = explicit(net.x, self.held, self.state.script_pubkey());
		let mut s = spend(self.lock_time).input(self.coin, prev, 0xffff_fffe).outputs(outs);
		let mut w = self.witness_state.unwrap_or(self.state).exit_witness(&self.exit, &self.auth, self.rest.is_none());
		// The control block is always the coin's own: only the witness's
		// claim about the state differs.
		w[3] = self.state.control_block();
		s.witness(0, w);
		s.tx
	}

	/// The Rust judge's verdict on the transaction.
	fn judge(&self, net: &Net, tx: &Transaction) -> Result<(), AccumulatorError> {
		let spent = explicit(net.x, self.held, self.state.script_pubkey());
		self.witness_state.unwrap_or(self.state).check(&net.chain, tx, 0, &spent, &self.exit, &self.auth)
	}
}

/// A negative case: refused by the Rust judge, by the mempool and in a block.
fn refuse(net: &mut Net, name: &str, raw: &RawExit, expect: &str) {
	let tx = raw.tx(net);
	let why = raw.judge(net, &tx).expect_err(&format!("{}: the Rust judge took it", name));
	println!("  {}: the judge says: {}", name, why);
	net.refuse(name, &tx, expect);
}

/// An `assert!` or a jet that fails: every check of the program but one.
const INSIDE_JET: &str = "mempool-script-verify-flag-failed (Assertion failed inside jet)";
/// An `unwrap` of nothing: the program reads an output that is not there.
const NO_OUTPUT: &str = "mempool-script-verify-flag-failed (Assertion failed)";

fn auth(digest: [u8; 32], key: &Keypair, by_operator: bool, t: MedianTime) -> ExitAuth {
	ExitAuth { by_operator, time: t, signature: sig(key, &digest) }
}

#[test]
fn accumulator_batch_on_regtest() {
	let mut a = Arca::start();
	let s = keypair("accumulator operator");
	let x = a.net.x;
	let chain = a.net.chain;

	// --- The batch and its round ---------------------------------------
	let (issuer, sched) = a.schedule(&s);
	let owners: Vec<Keypair> = (0..LEAVES).map(|i| keypair(&format!("accumulator owner {}", i))).collect();
	let preimages: Vec<[u8; 32]> = (0..LEAVES).map(|i| label32(&format!("accumulator preimage {}", i))).collect();
	let specs: Vec<LeafSpec> = (0..LEAVES)
		.map(|i| spec(&owners[i], &format!("accumulator leaf {}", i), VALUE + 7 * i as u64, hash(&preimages[i])))
		.collect();
	let reserve = ReserveRule::FeeRate { floor_per_kvb: a.floor_per_kvb, multiple: 4 };
	let params = AccumulatorParams { asset: x, chain, schedule: sched.clone(), burn: false, reserve, min_leaf: 1 };
	let acc = Accumulator::build(params.clone(), &specs).unwrap();
	let state0 = *acc.policy();
	println!("1,024 leaves; root {}; batch output holds {}; slot 341's exit reserve {}, entry reserve {}",
		hex(&state0.root), acc.total(), acc.slots()[341].reserve, acc.leaves()[341].entry_reserve);
	let (round, _c) = round_tx(&a.net, &issuer, &[], &acc.batch_output(), &sched);
	let round_id = a.net.pass("round: a 1,024-leaf accumulator batch, its token and connector", &round);
	let batch0 = OutPoint::new(round_id, 0);

	// --- Every owner's wallet check --------------------------------------
	let policy = a.policy(&s);
	let floor_policy = WalletPolicy {
		min_reserve: ReserveFloor::FeeRate { floor_per_kvb: a.floor_per_kvb, multiple: 4 }, ..policy
	};
	let valid: Vec<ValidAccumulatorLeaf> = (0..LEAVES)
		.map(|i| acc.record(i).validate(&round, &floor_policy, &xonly(&owners[i]), &specs[i].owner_nonce)
			.unwrap_or_else(|e| panic!("slot {}: {}", i, e)))
		.collect();
	assert!(valid.iter().all(|v| v.batch_vout == 0 && v.round_txid == round_id && v.policy == state0));
	println!("every one of the 1,024 records passes its owner's wallet check against the round");
	wallet_refusals(&acc, &round, &owners, &specs, &policy);

	// Each owner signs its exit authorisation at once, good from now: no
	// outpoint and no bitmap in it.
	let t0 = mt(a.net.mtp() - 1);
	let auths: Vec<ExitAuth> = (0..LEAVES).map(|i| auth(valid[i].exit_digest(t0), &owners[i], false, t0)).collect();

	// The coin a holder keeps: the record, the preimage and its exit
	// authorisation, through its binary form; refused with another preimage,
	// a stranger's authorisation or one not yet good.
	let coin = |i: usize, pre: [u8; 32], au: &ExitAuth| CoinRecord::Accumulator {
		record: acc.record(i), preimage: pre, auth: (au.signature, au.time),
	};
	let held = CoinRecord::from_bytes(&coin(700, preimages[700], &auths[700]).to_bytes().unwrap()).unwrap();
	let vc = held.validate(std::slice::from_ref(&round), &policy, &xonly(&owners[700]), &specs[700].owner_nonce).unwrap();
	assert_eq!(vc.id, valid[700].leaf_id);
	assert!(matches!(&vc.origin, ValidOrigin::Accumulator { auth, .. } if *auth == auths[700]));
	assert_eq!(coin(700, preimages[699], &auths[700]).validate(std::slice::from_ref(&round), &policy, &xonly(&owners[700]),
		&specs[700].owner_nonce).unwrap_err(), TransferError::Preimage);
	assert_eq!(coin(700, preimages[700], &auths[699]).validate(std::slice::from_ref(&round), &policy, &xonly(&owners[700]),
		&specs[700].owner_nonce).unwrap_err(), TransferError::AuthSignature(0));
	let later = mt(a.net.mtp() + 3600);
	assert_eq!(coin(700, preimages[700], &auth(valid[700].exit_digest(later), &owners[700], false, later))
		.validate(std::slice::from_ref(&round), &policy, &xonly(&owners[700]), &specs[700].owner_nonce).unwrap_err(),
		TransferError::AuthTime(0));
	println!("slot 700's coin record resolves to its leaf; another preimage, another owner's authorisation and one not yet good are refused");

	// --- Exit 1: slot 341 by its owner -----------------------------------
	let x1 = RawExit::new(&state0, batch0, acc.total(), &valid[341].exit, &valid[341].entry_output(), auths[341]);
	let built = valid[341].exit_tx(&state0, batch0, acc.total(), &auths[341], &FeeSource::Reserve).unwrap();
	assert_eq!(built.tx, x1.tx(&a.net), "the library's exit is the test's control");
	x1.judge(&a.net, &built.tx).unwrap();
	// Before it goes: the slot's own exit with a forged path, from the round's state.
	let mut n = x1.clone();
	n.exit.path[3].0[0] ^= 1;
	refuse(&mut a.net, "neg exit with a forged path: one sibling changed at level 3", &n, INSIDE_JET);
	let mut n = x1.clone();
	n.exit.path[6].1 += 1;
	refuse(&mut a.net, "neg exit with a forged path: one sibling's weight one more", &n, INSIDE_JET);
	let mut n = x1.clone();
	n.exit.path = valid[340].exit.path.clone();
	refuse(&mut a.net, "neg exit with a forged path: the neighbour's path", &n, INSIDE_JET);
	let mut n = x1.clone();
	n.exit.record.value += 1;
	n.entry.value += 1;
	n.rest = n.rest.map(|(v, spk)| (v - 1, spk));
	refuse(&mut a.net, "neg exit of a record claiming one atom more", &n, INSIDE_JET);
	let mut n = x1.clone();
	n.exit.path[0].1 = u64::MAX;
	refuse(&mut a.net, "neg exit with a sibling weight that overflows", &n, INSIDE_JET);
	let stranger = keypair("accumulator stranger");
	let mut n = x1.clone();
	n.auth = auth(valid[341].exit_digest(t0), &stranger, false, t0);
	refuse(&mut a.net, "neg exit signed by a stranger", &n, INSIDE_JET);
	let mut n = x1.clone();
	n.auth = auth(valid[341].exit_digest(t0), &s, false, t0);
	refuse(&mut a.net, "neg exit signed by the operator without its flag", &n, INSIDE_JET);
	let mut n = x1.clone();
	n.auth = auth(valid[342].exit_digest(t0), &owners[342], false, t0);
	refuse(&mut a.net, "neg exit signed by another slot's owner over its own slot", &n, INSIDE_JET);
	let mut n = x1.clone();
	n.rest = n.rest.map(|(v, spk)| (v - 1, spk));
	refuse(&mut a.net, "neg exit with the rest one atom short", &n, INSIDE_JET);
	let mut n = x1.clone();
	n.rest = n.rest.map(|(v, _)| (v, state0.script_pubkey()));
	refuse(&mut a.net, "neg exit with the rest under the old state", &n, INSIDE_JET);
	let mut n = x1.clone();
	n.rest = n.rest.map(|(v, _)| (v, state0.after(342).script_pubkey()));
	refuse(&mut a.net, "neg exit with the rest marking another slot", &n, INSIDE_JET);
	let mut n = x1.clone();
	n.entry = ExplicitOutput::new(x, n.entry.value, elements::script::Builder::new().push_int(1)
		.push_slice(&xonly(&owners[341]).serialize()).into_script());
	refuse(&mut a.net, "neg exit paying the entry's value to the owner's key", &n, INSIDE_JET);
	let mut n = x1.clone();
	n.rest = None;
	n.witness_state = None;
	refuse(&mut a.net, "neg exit with no rest", &n, NO_OUTPUT);
	// Before its delay: the authorisation's time an hour ahead.
	let ahead = mt(a.net.mtp() + 3600);
	let mut n = x1.clone();
	n.auth = auth(valid[341].exit_digest(ahead), &owners[341], false, ahead);
	refuse(&mut a.net, "neg exit before its authorisation's time, the lock time now", &n, INSIDE_JET);
	n.lock_time = ahead.to_consensus_u32();
	let tx = n.tx(&a.net);
	a.net.refuse("neg exit before its authorisation's time, the lock time that time", &tx, "non-final");

	let id1 = a.net.pass("exit 1: slot 341 by its owner, its reserve paying the fee", &built.tx);
	let batch1 = OutPoint::new(id1, 1);
	let held1 = acc.total() - acc.slots()[341].weight().unwrap();
	let state1 = state0.after(341);
	assert_eq!(a.net.rt.client().raw_transaction(&id1).unwrap().output[1], explicit(x, held1, state1.script_pubkey()));

	// --- Every other owner's proof stays valid ---------------------------
	// The record, the path and the authorisation each owner holds from the
	// round take its slot out of the new state; only slot 341's is refused.
	for (i, v) in valid.iter().enumerate() {
		let r = state1.check_slot(&chain, &v.exit, &auths[i]);
		if i == 341 {
			assert_eq!(r, Err(AccumulatorError::Left(341)));
		} else {
			r.unwrap_or_else(|e| panic!("slot {} after exit 1: {}", i, e));
		}
	}
	println!("after exit 1, the 1,023 other records and their pre-signed authorisations take their slots out of the new state");

	// --- Exit 2: slot 700, with the authorisation signed before exit 1 ----
	let x2 = RawExit::new(&state1, batch1, held1, &valid[700].exit, &valid[700].entry_output(), auths[700]);
	// The slot that has left, beside it.
	let mut n = RawExit::new(&state1, batch1, held1, &valid[341].exit, &valid[341].entry_output(), auths[341]);
	n.rest = Some((held1 - acc.slots()[341].weight().unwrap(), state1.script_pubkey()));
	refuse(&mut a.net, "neg exit of a slot that has left, the state the coin holds", &n, INSIDE_JET);
	n.witness_state = Some(state0);
	refuse(&mut a.net, "neg exit of a slot that has left, the witness claiming the state before", &n, INSIDE_JET);
	let id2 = a.net.pass("exit 2: slot 700, its authorisation signed before exit 1", &x2.tx(&a.net));
	let batch2 = OutPoint::new(id2, 1);
	let held2 = held1 - acc.slots()[700].weight().unwrap();
	let state2 = state1.after(700);

	// --- Exit 3: slot 5 by the operator, a coin of X paying the fee -------
	// The operator's path is the tree's gate, where the operator is a member
	// of every node. The slot's reserve goes to change.
	let op_auth = auth(valid[5].exit_digest(t0), &s, true, t0);
	let fc = a.net.fund(vec![explicit(x, 20_000, op_true_spk())]).remove(0);
	let fee_src = FeeSource::Coin { outpoint: fc.outpoint, coin: fc.txout.clone(), fee: 2_000, change: op_true_spk() };
	let mut x3 = valid[5].exit_tx(&state2, batch2, held2, &op_auth, &fee_src).unwrap();
	x3.tx.input[1].witness.script_witness = op_true_witness();
	let id3 = a.net.pass("exit 3: slot 5 by the operator, a coin of X attached for the fee", &x3.tx);
	let batch3 = OutPoint::new(id3, 1);
	let held3 = held2 - acc.slots()[5].weight().unwrap();
	let state3 = state2.after(5);

	// The state, read back from the chain alone.
	let txs: Vec<Transaction> = [id1, id2, id3].iter().map(|t| a.net.rt.client().raw_transaction(t).unwrap()).collect();
	let seen = read_exit(&txs[1].input[0].witness.script_witness).unwrap();
	assert_eq!((seen.slot, seen.by_operator, seen.bitmap), (700, false, state1.bitmap));
	assert!(read_exit(&txs[2].input[0].witness.script_witness).unwrap().by_operator);
	assert_eq!(follow(&state0, &[(&txs[0], 0), (&txs[1], 0), (&txs[2], 0)]).unwrap(), Some(state3));
	println!("the bitmap after three exits, read back from their witnesses alone: {} slots left", state3.bitmap.count());

	// --- Each leaf goes on as a tree leaf does: entry, then its exit -------
	let e1 = valid[341].entry_tx(OutPoint::new(id1, 0), &preimages[341], &FeeSource::Reserve).unwrap();
	let leaf1 = a.net.pass("entry of slot 341 into its leaf, with the preimage", &e1.tx);
	let leaf = &valid[341].leaf;
	let claim = exit_tx(&a.net, leaf, OutPoint::new(leaf1, 0), x, valid[341].entry.value, &owners[341]);
	a.net.refuse("neg the leaf's exit before its delay", &claim, "non-BIP68-final");
	a.net.wait_csv(&leaf1, leaf.exit_delay);
	a.net.pass("the leaf's exit after its delay (claim)", &claim);

	// --- A sweep before the notice, and after it ---------------------------
	let clock0 = OutPoint::new(round_id, 1);
	let clocks = sched.clocks();
	// Inside a roll of the clock, before any release: the token moves to
	// clock 1, and the batch's sweep, which requires it at R, is refused.
	let roll_in = sweep_in_roll(&a.net, &sched, &state3, batch3, held3, clock0, &s);
	a.net.refuse("neg sweep inside a roll of the clock, before any release", &roll_in,
		"mempool-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)");
	// The release, at the expiry.
	a.net.mtp_past(clocks[0].expiry.to_consensus_u32() as u64);
	let fc = a.net.fee_coin();
	let rel = sched.release_tx(0, clock0, &FeeSource::Coin { outpoint: fc.outpoint, coin: fc.txout.clone(), fee: 2_000,
		change: op_true_spk() }).unwrap();
	let rel = signed(&a.net, rel, &s, vec![]);
	let mut rel_tx = rel.tx;
	rel_tx.input[1].witness.script_witness = op_true_witness();
	let rel_id = a.net.pass("release of the token to R, at the expiry", &rel_tx);
	let at_r = OutPoint::new(rel_id, 0);
	// An owner can still leave during the notice.
	let x4 = RawExit::new(&state3, batch3, held3, &valid[900].exit, &valid[900].entry_output(), auths[900]);
	let id4 = a.net.pass("exit 4: slot 900 by its owner, during the notice", &x4.tx(&a.net));
	let batch4 = OutPoint::new(id4, 1);
	let held4 = held3 - acc.slots()[900].weight().unwrap();
	let state4 = state3.after(900);
	let sweep = |net: &Net| {
		let swept = [state4.sweepable(batch4, (x, held4))];
		let to = [ExplicitOutput::new(x, held4 - 5_000, op_true_spk())];
		let sw = sweep_tx(&sched, at_r, &swept, &to, &FeeSource::Reserve).unwrap();
		let sigs: Vec<_> = (0..2).map(|i| sig(&s, &sw.sighash(i, net.genesis).unwrap())).collect();
		sw.finish(&sigs).unwrap().tx
	};
	let early = sweep(&a.net);
	a.net.refuse("neg sweep of the batch after the release, before W at R", &early, "non-BIP68-final");
	a.net.wait_csv(&rel_id, sched.notice);
	a.net.pass("sweep of the batch after W at R: the operator takes what is left", &sweep(&a.net));

	// --- The last leaf of a batch, by the other pruned program -------------
	last_leaf(&mut a, &s);

	// --- A 1,024-leaf tree of the same leaves, one leaf out, for the sizes --
	tree_beside(&mut a, &s, &owners, &preimages);

	a.net.print();
}

/// A transaction that rolls the token from clock 0 into clock 1 and sweeps
/// the batch in the same breath: the attack the sweep's check of `R` closes.
fn sweep_in_roll(net: &Net, sched: &ClockSchedule, state: &AccumulatorPolicy, batch: OutPoint, held: u64, clock0: OutPoint,
	s: &Keypair) -> Transaction
{
	let clocks = sched.clocks();
	let roll = clocks[0].roll.clone().unwrap();
	let tap = state.taproot();
	let mut sp = spend(0)
		.input(batch, explicit(net.x, held, state.script_pubkey()), 0xffff_fffe)
		.input(clock0, explicit(sched.token, 1, clocks[0].output.script_pubkey()), 0xffff_fffe)
		.outputs(vec![explicit(net.x, held - 5_000, op_true_spk()), explicit(sched.token, 1, clocks[1].output.script_pubkey()),
			fee(net.x, 5_000)]);
	let s0 = sp.sign(s, 0, &state.sweep.script(), net.genesis);
	let s1 = sp.sign(s, 1, &roll, net.genesis);
	sp.witness(0, tap.witness(&state.sweep.script(), Sweep::witness_items(&s0, 1)));
	sp.witness(1, clocks[0].output.witness(&roll, Clock::witness_items(&s1)));
	sp.tx
}

/// What a wallet refuses: a round paying the batch output one atom short, a
/// record whose path is forged, a record under an operator it was not told,
/// another owner's record as its own.
fn wallet_refusals(acc: &Accumulator, round: &Transaction, owners: &[Keypair], specs: &[LeafSpec], policy: &WalletPolicy) {
	let r = acc.record(12);
	let mut short = round.clone();
	short.output[0].value = elements::confidential::Value::Explicit(acc.total() - 1);
	let e = r.validate(&short, policy, &xonly(&owners[12]), &specs[12].owner_nonce).unwrap_err();
	println!("  wallet refuses a round paying the batch one atom short: {}", e);
	assert_eq!(e, AccumulatorError::Record(RecordError::BatchOutputMissing));
	let mut forged = r.clone();
	forged.path[2].1 -= 1;
	let e = forged.validate(round, policy, &xonly(&owners[12]), &specs[12].owner_nonce).unwrap_err();
	println!("  wallet refuses a record whose path is forged: {}", e);
	assert_eq!(e, AccumulatorError::Record(RecordError::BatchOutputMissing));
	let other = WalletPolicy { operator: xonly(&keypair("another operator")), ..*policy };
	let e = r.validate(round, &other, &xonly(&owners[12]), &specs[12].owner_nonce).unwrap_err();
	println!("  wallet refuses a batch of an operator it was not told: {}", e);
	assert_eq!(e, AccumulatorError::Record(RecordError::WrongOperator));
	let e = acc.record(13).validate(round, policy, &xonly(&owners[12]), &specs[12].owner_nonce).unwrap_err();
	println!("  wallet refuses another owner's record as its own: {}", e);
	assert_eq!(e, AccumulatorError::Record(RecordError::NotOwner));
}

/// A batch of one leaf, whose exit takes the last of it and leaves no rest.
fn last_leaf(a: &mut Arca, s: &Keypair) {
	let (issuer, sched) = a.schedule(s);
	let owner = keypair("accumulator lone owner");
	let pre = label32("accumulator lone preimage");
	let one = vec![spec(&owner, "accumulator lone leaf", VALUE, hash(&pre))];
	let params = AccumulatorParams {
		asset: a.net.x, chain: a.net.chain, schedule: sched.clone(), burn: false,
		reserve: ReserveRule::FeeRate { floor_per_kvb: a.floor_per_kvb, multiple: 4 }, min_leaf: 1,
	};
	let acc = Accumulator::build(params, &one).unwrap();
	let (round, _) = round_tx(&a.net, &issuer, &[], &acc.batch_output(), &sched);
	let id = a.net.pass("round: an accumulator batch of one leaf", &round);
	let v = acc.record(0).validate(&round, &a.policy(s), &xonly(&owner), &one[0].owner_nonce).unwrap();
	let t = mt(a.net.mtp() - 1);
	let au = auth(v.exit_digest(t), &owner, false, t);
	let x = v.exit_tx(acc.policy(), OutPoint::new(id, 0), acc.total(), &au, &FeeSource::Reserve).unwrap();
	assert_eq!(x.tx.output.len(), 2, "the entry and the fee, no rest");
	let mut with_rest = RawExit::new(acc.policy(), OutPoint::new(id, 0), acc.total(), &v.exit, &v.entry_output(), au);
	with_rest.entry.value -= 1;
	refuse(&mut a.net, "neg last exit paying the entry one atom short", &with_rest, INSIDE_JET);
	a.net.pass("exit of the last leaf: no rest", &x.tx);
}

/// The same 1,024 leaves in a radix-4 tree, one leaf unrolled and exited.
fn tree_beside(a: &mut Arca, s: &Keypair, owners: &[Keypair], preimages: &[[u8; 32]]) {
	let (issuer, sched) = a.schedule(s);
	let specs: Vec<LeafSpec> = (0..LEAVES)
		.map(|i| spec(&owners[i], &format!("tree leaf {}", i), VALUE + 7 * i as u64, hash(&preimages[i])))
		.collect();
	let tree = a.tree(&sched, &specs);
	let (round, _) = round_tx(&a.net, &issuer, &[], &tree.batch_output(), &sched);
	let id = a.net.pass("round: the same 1,024 leaves as a radix-4 tree", &round);
	let v = tree.record(341).validate(&round, &a.policy(s), &xonly(&owners[341]), &specs[341].owner_nonce).unwrap();
	let auths = owner_auths(&v, &owners[341], mt(a.net.mtp() - 1));
	let at = a.bring_leaf("tree, slot 341", &v, &auths, &preimages[341]);
	let claim = exit_tx(&a.net, &v.branch.leaf, at, a.net.x, v.branch.entry.value, &owners[341]);
	a.net.wait_csv(&at.txid, v.branch.leaf.exit_delay);
	a.net.pass("tree, slot 341: the leaf's exit after its delay (claim)", &claim);
	assert_eq!(v.round_txid, id);
}

/// Exits are serial: each spends the rest the one before it left. 25 exits
/// of one batch, chained in the mempool, go into one block; the 26th is
/// refused by the mempool's chain limit while they wait (it is valid in a
/// block, and goes in the next). Then an exit mined in a block anchored to a
/// parent block that is orphaned leaves the chain with it: the batch output
/// it spent is unspent again in the chain, the exit returns to the mempool,
/// and it confirms again under the new parent branch, the same transaction.
#[test]
fn chained_exits_in_one_block_and_an_exit_reorganised_by_its_anchor() {
	const N: usize = 32;
	let mut a = Arca::start();
	let s = keypair("accumulator chain operator");
	let (issuer, sched) = a.schedule(&s);
	let owners: Vec<Keypair> = (0..N).map(|i| keypair(&format!("accumulator chain owner {}", i))).collect();
	let preimages: Vec<[u8; 32]> = (0..N).map(|i| label32(&format!("accumulator chain preimage {}", i))).collect();
	let specs: Vec<LeafSpec> = (0..N)
		.map(|i| spec(&owners[i], &format!("accumulator chain leaf {}", i), VALUE, hash(&preimages[i])))
		.collect();
	let params = AccumulatorParams {
		asset: a.net.x, chain: a.net.chain, schedule: sched.clone(), burn: false,
		reserve: ReserveRule::FeeRate { floor_per_kvb: a.floor_per_kvb, multiple: 4 }, min_leaf: 1,
	};
	let acc = Accumulator::build(params, &specs).unwrap();
	let (round, _) = round_tx(&a.net, &issuer, &[], &acc.batch_output(), &sched);
	let id = a.net.pass("round: a 32-leaf accumulator batch", &round);
	let policy = a.policy(&s);
	let valid: Vec<ValidAccumulatorLeaf> = (0..N)
		.map(|i| acc.record(i).validate(&round, &policy, &xonly(&owners[i]), &specs[i].owner_nonce).unwrap())
		.collect();
	let t = mt(a.net.mtp() - 1);
	let auths: Vec<ExitAuth> = (0..N).map(|i| auth(valid[i].exit_digest(t), &owners[i], false, t)).collect();

	// 25 exits chained in the mempool, then the 26th.
	let (mut state, mut at, mut held) = (*acc.policy(), OutPoint::new(id, 0), acc.total());
	let next = |state: &mut AccumulatorPolicy, at: &mut OutPoint, held: &mut u64, i: usize| -> Transaction {
		let x = valid[i].exit_tx(state, *at, *held, &auths[i], &FeeSource::Reserve).unwrap().tx;
		*state = state.after(valid[i].exit.slot);
		*at = OutPoint::new(x.txid(), 1);
		*held = x.output[1].value.explicit().unwrap();
		x
	};
	let mut chain = vec![];
	for i in 0..25 {
		let x = next(&mut state, &mut at, &mut held, i);
		a.net.rt.client().send_raw_transaction(&x).unwrap_or_else(|e| panic!("exit {} of the chain: {}", i + 1, e));
		chain.push(x);
	}
	let after25 = state;
	let x26 = next(&mut state, &mut at, &mut held, 25);
	let r = a.net.rt.client().test_mempool_accept(&[&x26]).unwrap().remove(0);
	assert!(!r.allowed, "the 26th exit of one unconfirmed chain is refused by the mempool");
	let why = r.reject_reason.unwrap_or_default();
	assert!(why.contains("too-long-mempool-chain"), "{}", why);
	println!("25 exits of one batch chained in the mempool; the 26th refused while they wait: {}", why);
	a.net.mine(1);
	let blocks: std::collections::BTreeSet<String> = chain.iter()
		.map(|x| a.net.rpc("getrawtransaction", serde_json::json!([x.txid().to_string(), true]))["blockhash"].as_str().unwrap().to_string())
		.collect();
	assert_eq!(blocks.len(), 1, "the 25 exits are in one block");
	let exits: Vec<(&Transaction, usize)> = chain.iter().map(|x| (x, 0)).collect();
	assert_eq!(follow(acc.policy(), &exits).unwrap(), Some(after25), "the state read back from the 25 witnesses");
	println!("the 25 exits confirmed in one block {}, {} vB each; the state read back from their witnesses is the state built",
		blocks.iter().next().unwrap(), chain[0].vsize());
	a.net.pass("exit 26, after the block", &x26);

	// An exit in a block anchored to a parent block that is then orphaned.
	a.net.rt.mine_parent(1).unwrap();
	a.net.rt.anchor_to_parent_tip().unwrap();
	let p = a.net.rt.parent.client().block_count().unwrap();
	let x27 = next(&mut state, &mut at, &mut held, 26);
	let spent = x27.input[0].previous_output;
	let id27 = a.net.rt.client().send_raw_transaction(&x27).unwrap();
	a.net.mine(1);
	assert_eq!(a.net.rt.client().confirmations(&id27).unwrap(), 1);
	let gone = a.net.rt.orphan_parent_from(p).unwrap();
	let in_chain = |net: &Net, op: &OutPoint| -> bool {
		!net.rpc("gettxout", serde_json::json!([op.txid.to_string(), op.vout, false])).is_null()
	};
	assert!(a.net.rt.client().confirmations(&id27).unwrap_or(0) < 1, "exit 27 left the chain with its anchor");
	assert!(in_chain(&a.net, &spent), "the batch output exit 27 spent is unspent again in the chain");
	let pool: Vec<String> = serde_json::from_value(a.net.rpc("getrawmempool", serde_json::json!([]))).unwrap();
	assert!(pool.contains(&id27.to_string()), "exit 27 is back in the mempool");
	println!("parent block(s) {:?} orphaned: exit 27 left the chain, the batch output it spent is unspent there again, and the exit \
		waits in the mempool", gone);
	a.net.rt.mine_parent(1).unwrap();
	a.net.rt.anchor_to_parent_tip().unwrap();
	a.net.mine(1);
	assert!(a.net.rt.client().confirmations(&id27).unwrap() >= 1, "exit 27 confirms again under the new parent branch");
	assert!(!in_chain(&a.net, &spent));
	println!("exit 27 confirmed again under the new parent branch, the same transaction {}", id27);
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}
