//! Two reassignments merged into one transaction, on a Sequentia regtest
//! chain.
//!
//! A rebindable pair names the outputs it commits to, never the inputs. Two
//! reassignments whose committed outputs agree at every index both commit to
//! are satisfied by one transaction that spends the checkpoints of both and
//! creates the outputs once; the value of one reassignment's inputs goes to
//! whoever broadcasts it. Two payments to one receive request, with no change,
//! commit to one output set unless the receiver's leaf carries something of
//! the sender's: the creator nonce, which the sender's wallet draws for every
//! leaf it creates.
//!
//! Every transaction is built with this crate's builders, signed with test
//! keys and broadcast to a node on an anchored `elementsregtest` chain started
//! with `-par=1`; a negative case is refused by the mempool and again when
//! forced into a block, the block for the mempool's reason.
//!
//! 1. Two senders pay one receive request, each drawing the creator nonce of
//!    the leaf it creates: the operator co-signs both, the receiver holds two
//!    leaves, and the transaction that would satisfy both reassignments with
//!    one output set is refused; each reassignment confirms on its own.
//! 2. A sender that repeats another reassignment's outputs (the same creator
//!    nonce): the operator's rule refuses to co-sign it, for the same outputs
//!    and for one set that is the first outputs of the other. What the rule
//!    prevents is then run: pairs made anyway merge, and the broadcaster takes
//!    a sender's coin, in both shapes. A receiver offered a coin that rests on
//!    the one leaf twice refuses it; after the merge, only one of that coin's
//!    two checkpoints can be made.
//!
//! Needs `SEQUENTIAD_EXEC`; `--nocapture` prints every transaction.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::{OutPoint, Script, Transaction, Txid};

use arca_consensus::Verifier;
use arca_covenant::script::sha256;
use arca_covenant::spend::{FeeSource, UnrollTx};
use arca_covenant::transfer::reassignment_tx;
use arca_covenant::*;

use common::net::*;
use common::round::*;
use common::*;

/// A sender's batch leaf: its key, record and resolved coin.
struct Sender {
	key: Keypair,
	base: CoinRecord,
	coin: ValidCoin,
}

/// A batch of one leaf per sender, `values` of X, in one round.
fn senders(c: &mut Arca, s: &Keypair, label: &str, values: &[u64]) -> (Vec<Sender>, Vec<Transaction>) {
	let keys: Vec<Keypair> = (0..values.len()).map(|i| keypair(&format!("{} sender {}", label, i))).collect();
	let preimages: Vec<[u8; 32]> = (0..values.len()).map(|i| label32(&format!("{} preimage {}", label, i))).collect();
	let specs: Vec<_> = keys.iter().zip(values).enumerate()
		.map(|(i, (k, v))| spec(k, &format!("{} sender {}", label, i), *v, sha256(&preimages[i]))).collect();
	let (issuer, sched) = c.schedule(s);
	let tree = c.tree(&sched, &specs);
	let (round, _) = round_tx(&c.net, &issuer, &[], &tree.batch_output(), &sched);
	c.net.pass(&format!("{}/round", label), &round);
	let rounds = vec![round];
	let t = mt(c.net.mtp() - 60);
	let policy = c.policy(s);
	let out = keys.into_iter().enumerate().map(|(i, key)| {
		let base = base(&tree, i, &key, preimages[i], t);
		let coin = base.resolve(&rounds, &policy).unwrap();
		Sender { key, base, coin }
	}).collect();
	(out, rounds)
}

/// Brings every sender's leaf on-chain: the path once, then each entry.
fn bring_all(c: &mut Arca, label: &str, senders: &[Sender]) -> Vec<OutPoint> {
	let mut at = vec![];
	for (i, sd) in senders.iter().enumerate() {
		let ValidOrigin::Leaf { valid, preimage, auths } = &sd.coin.origin else { unreachable!() };
		let txs = valid.branch.unroll(OutPoint::new(valid.round_txid, valid.batch_vout), auths,
			&vec![FeeSource::Reserve; auths.len()]).unwrap();
		for (level, u) in txs.iter().enumerate() {
			if c.net.rt.client().confirmations(&u.tx.txid()).unwrap_or(0) == 0 {
				c.net.pass(&format!("{}/unroll, level {}", label, level), &u.tx);
			}
		}
		let e = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), preimage, &FeeSource::Reserve).unwrap();
		at.push(OutPoint::new(c.net.pass(&format!("{}/sender {}'s leaf", label, i), &e.tx), 0));
	}
	at
}

/// What a sender's wallet builds to pay `outputs` from its whole coin less a
/// margin, and the record of output `index` for `leaf`, both pairs signed.
fn pay(sd: &Sender, s: &Keypair, outputs: Vec<ExplicitOutput>, index: u8, leaf: NewLeaf) -> (TransferPlan, CoinRecord) {
	let plan = TransferPlan { inputs: vec![(sd.coin.clone(), sd.coin.value - MARGIN)], outputs };
	let (cp, re) = (plan.checkpoint_message(0).unwrap().digest, plan.reassignment_message(0).unwrap().digest);
	let rec = CoinRecord::Transfer(Box::new(Transfer {
		inputs: vec![TransferInput {
			coin: sd.base.clone(), checkpoint_value: sd.coin.value - MARGIN,
			checkpoint: Pair { operator: sig(s, &cp), owner: sig(&sd.key, &cp) },
			reassignment: Pair { operator: sig(s, &re), owner: sig(&sd.key, &re) },
		}],
		outputs: plan.outputs.clone(), index, leaf,
	}));
	(plan, rec)
}

/// The broadcaster's own output script: a key spend of its own.
fn broadcaster() -> Script {
	let k = keypair("merge broadcaster");
	TapOutput::new(vec![(0, Script::from([&[0x20u8][..], &xonly(&k).serialize(), &[0xac]].concat()))]).script_pubkey()
}

/// The transaction that spends the checkpoints of `inputs`, at `cps`, into
/// one copy of `outputs`, each input under its own reassignment pair over its
/// first `ms[i]` outputs; the broadcaster attaches a fee coin and takes what
/// the outputs leave.
fn merge_tx(c: &mut Arca, inputs: &[ValidInput], ms: &[u8], outputs: &[ExplicitOutput], cps: &[OutPoint]) -> UnrollTx {
	let fc = c.net.fee_coin();
	let mut u = reassignment_tx(inputs, outputs, cps,
		&FeeSource::Coin { outpoint: fc.outpoint, coin: fc.txout, fee: 4_000, change: broadcaster() }).unwrap();
	for (i, (inp, m)) in inputs.iter().zip(ms).enumerate() {
		u.tx.input[i].witness.script_witness = inp.checkpoint.witness(&inp.reassignment_pair, *m);
	}
	u.tx.input[inputs.len()].witness.script_witness = op_true_witness();
	u
}

/// What the confirmed transaction `txid` pays in X: to each committed output
/// and to the broadcaster.
fn paid_out(c: &Arca, txid: &Txid, outputs: &[ExplicitOutput]) -> (Vec<u64>, u64) {
	let tx = c.net.rt.client().raw_transaction(txid).unwrap();
	let to = outputs.iter().map(|o| tx.output.iter().filter(|t| t.script_pubkey == o.script_pubkey)
		.map(|t| t.value.explicit().unwrap()).sum()).collect();
	let thief = tx.output.iter().filter(|t| t.script_pubkey == broadcaster() && t.asset.explicit() == Some(c.net.x))
		.map(|t| t.value.explicit().unwrap()).sum();
	(to, thief)
}

fn outputs_of(coin: &ValidCoin) -> Vec<ExplicitOutput> {
	match &coin.origin {
		ValidOrigin::Transfer { outputs, .. } => outputs.clone(),
		_ => unreachable!("a reassignment's output"),
	}
}

fn hex(s: &Script) -> String {
	s.as_bytes().iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// 1. Two payments to one receive request: two leaves
// ---------------------------------------------------------------------------

#[test]
fn two_payments_to_one_request_make_two_leaves() {
	let mut c = Arca::start();
	let s = keypair("merge 1 operator");
	let (sd, rounds) = senders(&mut c, &s, "merge 1", &[LEAF, LEAF]);
	let policy = c.policy(&s);

	// One receive request: the receiver's key and nonce. Each sender draws
	// the creator nonce of the leaf it creates.
	let r = keypair("merge 1 receiver");
	let request = (xonly(&r), label32("merge 1 receive request nonce"));
	let leaf = |i: usize| NewLeaf {
		owner: request.0, owner_nonce: request.1, creator_nonce: label32(&format!("merge 1 sender {} creator nonce", i)),
		exit_delay: delay(),
	};
	let v = LEAF - 2 * MARGIN;
	let mut seen = SeenReassignments::new();
	let mut coins = vec![];
	for (i, sender) in sd.iter().enumerate() {
		let to = leaf(i).policy(xonly(&s), c.net.chain).script_pubkey();
		let (plan, rec) = pay(sender, &s, vec![ExplicitOutput::new(c.net.x, v, to)], 0, leaf(i));
		plan.admit(&mut seen).unwrap();
		coins.push(rec.validate(&rounds, &policy.receipt(), &request.0, &request.1).unwrap());
	}
	assert_eq!(seen.len(), 2, "the operator co-signs both");
	let (o1, o2) = (outputs_of(&coins[0]), outputs_of(&coins[1]));
	assert_ne!(o1[0].script_pubkey, o2[0].script_pubkey);
	println!("merge 1: the receiver validates two coins of {} atoms each, at two leaves:\n  {}\n  {}",
		v, hex(&o1[0].script_pubkey), hex(&o2[0].script_pubkey));

	let at = bring_all(&mut c, "merge 1", &sd);
	let ins: Vec<ValidInput> = coins.iter().map(|k| inputs(k).remove(0)).collect();
	let cps: Vec<OutPoint> = ins.iter().zip(&at).enumerate().map(|(i, (inp, a))| {
		let id = c.net.pass(&format!("merge 1/sender {}'s checkpoint", i), &inp.checkpoint_tx(*a, &FeeSource::Reserve).unwrap().tx);
		OutPoint::new(id, 0)
	}).collect();

	// Both checkpoints into sender 0's outputs alone: sender 1's pair commits
	// to its own leaf at output 0, which is not there, and no transaction has
	// both leaves at output 0. The node's interpreter names the input that
	// fails: the one whose pair is over the other output set.
	let verifier = Verifier::consensus(c.net.genesis);
	let merged = merge_tx(&mut c, &ins, &[1, 1], &o1, &cps);
	verifier.verify_input(&merged.prevouts, 0, &merged.tx).unwrap();
	let e = verifier.verify_input(&merged.prevouts, 1, &merged.tx).unwrap_err();
	verifier.verify_input(&merged.prevouts, 2, &merged.tx).unwrap();
	println!("merge 1: inputs 0 and 2 verify; input 1, sender 1's checkpoint: {}", e);
	c.net.refuse("merge 1/neg both reassignments in one transaction, one output set", &merged.tx,
		"Invalid Schnorr signature");
	let merged = merge_tx(&mut c, &[ins[1].clone(), ins[0].clone()], &[1, 1], &o2, &[cps[1], cps[0]]);
	verifier.verify_input(&merged.prevouts, 0, &merged.tx).unwrap();
	verifier.verify_input(&merged.prevouts, 1, &merged.tx).unwrap_err();
	c.net.refuse("merge 1/neg the same, in sender 1's output set", &merged.tx,
		"Invalid Schnorr signature");

	// Each reassignment on its own: the receiver holds both leaves.
	let mut total = 0;
	for (i, k) in coins.iter().enumerate() {
		let id = c.net.pass(&format!("merge 1/sender {}'s reassignment", i), &k.reassignment_tx(&[cps[i]], &FeeSource::Reserve).unwrap().tx);
		let (to, _) = paid_out(&c, &id, &outputs_of(k));
		assert_eq!(to, vec![v]);
		total += to[0];
	}
	println!("merge 1: the receiver holds {} atoms in two leaves, both payments", total);
	assert_eq!(total, 2 * v);
	c.net.print();
}

// ---------------------------------------------------------------------------
// 2. A sender that repeats another reassignment's outputs
// ---------------------------------------------------------------------------

#[test]
fn outputs_repeated_by_a_sender_are_refused_and_would_merge() {
	let mut c = Arca::start();
	let x = c.net.x;
	let s = keypair("merge 2 operator");
	// Senders 0 and 1 pay the same output; sender 2 pays one output and
	// sender 3 the same output and its own change after it.
	let (sd, rounds) = senders(&mut c, &s, "merge 2", &[LEAF, LEAF, LEAF, LEAF + 1_000_000]);
	let policy = c.policy(&s);
	let v = LEAF - 2 * MARGIN;
	let chain = c.net.chain;
	let r = keypair("merge 2 receiver");
	let new_leaf = |owner: &Keypair, label: &str| NewLeaf {
		owner: xonly(owner), owner_nonce: label32(&format!("merge 2 {} owner nonce", label)),
		creator_nonce: label32(&format!("merge 2 {} creator nonce", label)), exit_delay: delay(),
	};
	// Sender 1's wallet repeats the creator nonce of sender 0's leaf.
	let same = new_leaf(&r, "receive request");
	let same_out = ExplicitOutput::new(x, v, same.policy(xonly(&s), chain).script_pubkey());
	let (plan0, rec0) = pay(&sd[0], &s, vec![same_out.clone()], 0, same);
	let (plan1, rec1) = pay(&sd[1], &s, vec![same_out.clone()], 0, same);
	// Sender 3's output set starts with sender 2's.
	let r2 = keypair("merge 2 second receiver");
	let first = new_leaf(&r2, "second request");
	let first_out = ExplicitOutput::new(x, v, first.policy(xonly(&s), chain).script_pubkey());
	let change = new_leaf(&sd[3].key, "sender 3 change");
	let change_out = ExplicitOutput::new(x, LEAF + 1_000_000 - 2 * MARGIN - v, change.policy(xonly(&s), chain).script_pubkey());
	let (plan2, rec2) = pay(&sd[2], &s, vec![first_out.clone()], 0, first);
	let (plan3, _) = pay(&sd[3], &s, vec![first_out.clone(), change_out.clone()], 0, first);

	// The operator's rule.
	let mut seen = SeenReassignments::new();
	plan0.admit(&mut seen).unwrap();
	let e = plan1.admit(&mut seen).unwrap_err();
	println!("merge 2: the operator refuses sender 1's plan: {} ({})", e, e.kind());
	assert!(matches!(e, TransferError::Mergeable));
	plan0.admit(&mut seen).unwrap();
	plan2.admit(&mut seen).unwrap();
	assert!(matches!(plan3.admit(&mut seen).unwrap_err(), TransferError::Mergeable), "the other's outputs first");
	let mut other_order = SeenReassignments::new();
	plan3.admit(&mut other_order).unwrap();
	assert!(matches!(plan2.admit(&mut other_order).unwrap_err(), TransferError::Mergeable), "the first outputs of the other's");
	assert_eq!(seen.len(), 2);
	println!("merge 2: refused as well: an output set that starts with one seen before, and one that another starts with; \
		the same reassignment again is not refused");

	// What the rule prevents, run: the pairs are made anyway. Each record
	// is sound on its own, so the receivers validate them.
	let k0 = rec0.validate(&rounds, &policy.receipt(), &same.owner, &same.owner_nonce).unwrap();
	let k1 = rec1.validate(&rounds, &policy.receipt(), &same.owner, &same.owner_nonce).unwrap();
	let k2 = rec2.validate(&rounds, &policy.receipt(), &first.owner, &first.owner_nonce).unwrap();
	let k3 = pay(&sd[3], &s, vec![first_out.clone(), change_out.clone()], 1, change).1
		.validate(&rounds, &policy.receipt(), &change.owner, &change.owner_nonce).unwrap();
	assert_ne!(k0.id, k1.id);
	assert_eq!(k0.output(), k1.output(), "two coins at one leaf");

	let at = bring_all(&mut c, "merge 2", &sd);
	let ins: Vec<ValidInput> = [&k0, &k1, &k2, &k3].iter().map(|k| inputs(k).remove(0)).collect();
	let cps: Vec<OutPoint> = ins.iter().zip(&at).enumerate().map(|(i, (inp, a))| {
		let id = c.net.pass(&format!("merge 2/sender {}'s checkpoint", i), &inp.checkpoint_tx(*a, &FeeSource::Reserve).unwrap().tx);
		OutPoint::new(id, 0)
	}).collect();

	// The same outputs: one leaf for two payments.
	let m = merge_tx(&mut c, &ins[0..2], &[1, 1], std::slice::from_ref(&same_out), &cps[0..2]);
	let id = c.net.pass("merge 2/senders 0 and 1 merged, the same outputs", &m.tx);
	let (to, thief) = paid_out(&c, &id, std::slice::from_ref(&same_out));
	println!("merge 2: in {} + {} of X; the receiver's leaf gets {}, the broadcaster {}",
		ins[0].checkpoint_value, ins[1].checkpoint_value, to[0], thief);
	assert_eq!((to[0], thief), (v, ins[0].checkpoint_value + ins[1].checkpoint_value - v));
	let merged_leaf = OutPoint::new(id, 0);

	// One output set the first outputs of the other: sender 3's reassignment
	// creates everything sender 2's commits to, so sender 2's checkpoint pays
	// nothing.
	let m = merge_tx(&mut c, &ins[2..4], &[1, 2], &[first_out.clone(), change_out.clone()], &cps[2..4]);
	let id = c.net.pass("merge 2/senders 2 and 3 merged, one set the first outputs of the other", &m.tx);
	let (to, thief) = paid_out(&c, &id, &[first_out.clone(), change_out.clone()]);
	println!("merge 2: in {} + {} of X; the second receiver gets {}, sender 3's change {}, the broadcaster {}",
		ins[2].checkpoint_value, ins[3].checkpoint_value, to[0], to[1], thief);
	assert_eq!(thief, ins[2].checkpoint_value + ins[3].checkpoint_value - to[0] - to[1]);
	assert_eq!(thief, ins[2].checkpoint_value + MARGIN, "sender 2's whole checkpoint, and sender 3's margin");

	// The receiver of the two coins at one leaf pays both on to D. D refuses
	// the record: it rests on one leaf twice.
	let d = keypair("merge 2 D");
	let d_leaf = new_leaf(&d, "D");
	let (c0, c1) = (v - MARGIN, v - 2 * MARGIN);
	let d_out = ExplicitOutput::new(x, c0 + c1 - MARGIN, d_leaf.policy(xonly(&s), chain).script_pubkey());
	let plan = TransferPlan { inputs: vec![(k0.clone(), c0), (k1.clone(), c1)], outputs: vec![d_out] };
	let pairs: Vec<(Pair, Pair)> = (0..2).map(|i| {
		let (cp, re) = (plan.checkpoint_message(i).unwrap().digest, plan.reassignment_message(i).unwrap().digest);
		(Pair { operator: sig(&s, &cp), owner: sig(&r, &cp) }, Pair { operator: sig(&s, &re), owner: sig(&r, &re) })
	}).collect();
	let d_rec = CoinRecord::Transfer(Box::new(Transfer {
		inputs: [(&rec0, c0), (&rec1, c1)].iter().zip(&pairs).map(|((rec, cv), (cp, re))| TransferInput {
			coin: (*rec).clone(), checkpoint_value: *cv, checkpoint: *cp, reassignment: *re,
		}).collect(),
		outputs: plan.outputs.clone(), index: 0, leaf: d_leaf,
	}));
	let e = d_rec.validate(&rounds, &policy.receipt(), &d_leaf.owner, &d_leaf.owner_nonce).unwrap_err();
	println!("merge 2: D REFUSES a coin of {} atoms resting on one leaf twice: {} ({})", c0 + c1 - MARGIN, e, e.kind());
	assert!(matches!(e, TransferError::SaltTwice { .. }), "{}", e);
	assert_eq!(e.kind(), "salt");

	// What D would have held: after the merge the leaf exists once, so one of
	// the coin's two checkpoints has nothing to spend.
	let d_inputs: Vec<ValidInput> = [(&k0, c0), (&k1, c1)].iter().zip(&pairs).map(|((k, cv), (cp, re))| ValidInput {
		coin: (*k).clone(), checkpoint: k.checkpoint(), checkpoint_value: *cv, checkpoint_pair: *cp, reassignment_pair: *re,
	}).collect();
	c.net.pass("merge 2/D's first checkpoint, on the merged leaf", &d_inputs[0].checkpoint_tx(merged_leaf, &FeeSource::Reserve).unwrap().tx);
	c.net.refuse("merge 2/neg D's second checkpoint: the leaf is spent", &d_inputs[1].checkpoint_tx(merged_leaf, &FeeSource::Reserve).unwrap().tx,
		"bad-txns-inputs-missingorspent");
	c.net.print();
}
