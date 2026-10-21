//! Offline refresh's refund on a Sequentia regtest chain: a holder signs its
//! halves before the new leaf, its tree or its round exists, and the
//! operator uses them only by paying the holder.
//!
//! `L(0)` stands for the coin a plan starts from, funded straight on-chain:
//! the holder has brought it home, which is when the operator needs the
//! refund. Every new leaf `L(i)` is a leaf of a round's tree, which the
//! operator unrolls with its own authorisations (it is a member of every
//! node) and opens with the plan's preimage. Every negative case is refused
//! by `testmempoolaccept`, by `sendrawtransaction`, and again when forced
//! into a block with `generateblock`, the block for the same reason (the
//! node checks scripts inline, `-par=1`).
//!
//! 1. Plan A: the refund of step 1, the operator's answer to the holder
//!    bringing `L(0)` home after step 1 made `L(1)`: refused when output 0, its
//!    value or output 1 is changed, when the outputs are swapped, when the
//!    halves of two steps are mixed, when a half was made for another salt,
//!    another chain or another amount, with the operator's signature in both
//!    slots, and with the operator's signature alone; then mined with the
//!    margin as its fee, output 0 paying the holder.
//! 2. Plan B: step 2's refund answers the holder bringing home `L(1)`, a
//!    leaf step 1 made, which the holder opened and unrolled with its own
//!    keys; the fee from an outside coin in another asset.
//! 3. Plan C: step 1's round disconnected and replaced by another spending
//!    the same token issuer, without `L(1)`: the refund naming `L(1)`'s
//!    outpoint is refused (the coin does not exist), and `L(0)` is the
//!    holder's: its exit confirms after the delay.
//! 4. Plan F: step 1's round replaced and the step run again under the same
//!    leaf in another round: the refund signed before either round is mined
//!    on the second.
//! 5. Plan D: what consensus accepts and leaves the holder whole: `L(0)`
//!    spent alone by its half, the operator funding the outputs; `L(1)` spent
//!    alone by its half; and plan E: a step never run, the operator funding
//!    a copy of `L(1)` itself to take `L(0)`. Each pays the holder output 0.
//!
//! Needs `SEQUENTIAD_EXEC`; `--nocapture` prints every transaction and every
//! refusal.

mod common;

use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::{OutPoint, Script, Transaction, Txid};

use arca_covenant::plan::key_proof_digest;
use arca_covenant::script::sha256;
use arca_covenant::spend::FeeSource;
use arca_covenant::tree::Tree;
use arca_covenant::*;

use common::net::*;
use common::round::*;
use common::*;

const MARGIN_ATOMS: u64 = 10_000;

/// A script standing for an address: a v0 witness program of a label.
fn address(label: &str) -> Script {
	let mut b = vec![0x00, 0x14];
	b.extend_from_slice(&label32(label)[..20]);
	Script::from(b)
}

/// A plan's parties and parts.
struct P {
	s: Keypair,
	keys: Vec<Keypair>,
	preimages: Vec<[u8; 32]>,
	plan: Plan,
	l0: Coin,
}

/// A plan of `steps` steps from a coin `L(0)` funded straight on-chain, every
/// leaf holding `LEAF`, the fee nothing, the margin `MARGIN_ATOMS`.
fn plan(c: &mut Arca, label: &str, steps: usize) -> P {
	let s = keypair(&format!("{} operator", label));
	let keys: Vec<Keypair> = (0..=steps).map(|i| keypair(&format!("{} holder key {}", label, i))).collect();
	let preimages: Vec<[u8; 32]> = (0..=steps).map(|i| label32(&format!("{} preimage {}", label, i))).collect();
	let (first, l0, coin) = funded_leaf(&mut c.net, &keys[0], &s, &format!("{} leaf 0", label), LEAF);
	let steps = (1..=steps).map(|i| PlanStep {
		value: LEAF, fee: 0, owner: xonly(&keys[i]),
		owner_nonce: label32(&format!("{} leaf {} owner nonce", label, i)),
		operator_nonce: label32(&format!("{} leaf {} operator nonce", label, i)),
		exit_delay: delay(), unlock_hash: sha256(&preimages[i]),
		holder_script: address(&format!("{} holder address {}", label, i)),
		operator_script: address(&format!("{} operator address {}", label, i)),
		margin: MARGIN_ATOMS,
	}).collect();
	let plan = Plan { chain: c.net.chain, operator: xonly(&s), coin, first, asset: c.net.x, value: LEAF, steps };
	plan.check().unwrap();
	P { s, keys, preimages, plan, l0 }
}

/// The holder's two halves of step `i`'s refund, made from the plan alone.
fn halves(p: &P, i: usize) -> (elements::secp256k1_zkp::schnorr::Signature, elements::secp256k1_zkp::schnorr::Signature) {
	let r = p.plan.refund(i).unwrap();
	(sig(&p.keys[i - 1], &r.old_message().unwrap().digest), sig(&p.keys[i], &r.new_message().unwrap().digest))
}

/// The operator completes the holder's halves into the two pairs.
fn pairs(p: &P, i: usize) -> (Pair, Pair) {
	let r = p.plan.refund(i).unwrap();
	let (ho, hn) = halves(p, i);
	(Pair { operator: sig(&p.s, &r.old_message().unwrap().digest), owner: ho },
	 Pair { operator: sig(&p.s, &r.new_message().unwrap().digest), owner: hn })
}

/// A round of step `i`: a tree holding `L(i)` behind its unlock hash among two
/// other owners' leaves. Returns the tree, the round and the leaf's index.
fn step_round(c: &mut Arca, p: &P, i: usize, label: &str) -> (Tree, Transaction, Coin) {
	let st = &p.plan.steps[i - 1];
	let (issuer, sched) = c.schedule(&p.s);
	let mine = LeafSpec {
		template: Template::Vtxo1, owner: st.owner, value: st.value, owner_nonce: st.owner_nonce,
		operator_nonce: st.operator_nonce, exit_delay: st.exit_delay, unlock_hash: st.unlock_hash, htlc: None,
	};
	let others: Vec<LeafSpec> = (0..2).map(|k| spec(&keypair(&format!("{} other {}", label, k)), &format!("{} other {}", label, k),
		LEAF, sha256(&label32(&format!("{} other preimage {}", label, k))))).collect();
	let tree = c.tree(&sched, &[others[0].clone(), mine, others[1].clone()]);
	assert_eq!(tree.batch_output().script_pubkey, tree.batch_output().script_pubkey);
	let (round, _) = round_tx(&c.net, &issuer, &[], &tree.batch_output(), &sched);
	c.net.pass(&format!("{}: the round of step {}", label, i), &round);
	(tree, round, issuer)
}

/// The operator's own unroll authorisations for every node above leaf 1 of
/// `tree`, at `t`: its key is member 0 of every node.
fn operator_auths(tree: &Tree, s: &Keypair, t: MedianTime) -> Vec<UnrollAuth> {
	let valid_branch = tree.record(1);
	let branch = valid_branch.branch().unwrap();
	tree.path(1).iter().zip(&branch.nodes).map(|((node, _), bn)| UnrollAuth {
		signature: sig(s, &bn.unroll_authorisation(t).digest), time: t, key: xonly(s), proof: node.members().proof(0),
	}).collect()
}

/// Brings leaf 1 of `tree` on-chain from `round` with `auths` and `preimage`,
/// every fee from the reserves. Returns the leaf's coin.
fn bring(c: &mut Arca, name: &str, tree: &Tree, round: &Transaction, auths: &[UnrollAuth], preimage: &[u8; 32]) -> (Coin, Vec<Transaction>) {
	let branch = tree.record(1).branch().unwrap();
	let txs = branch.unroll(OutPoint::new(round.txid(), 0), auths, &vec![FeeSource::Reserve; auths.len()]).unwrap();
	let mut made = vec![];
	for (level, u) in txs.iter().enumerate() {
		c.net.pass(&format!("{}: unroll, level {}", name, level), &u.tx);
		made.push(u.tx.clone());
	}
	let e = branch.entry_tx(branch.entry_outpoint(&txs).unwrap(), preimage, &FeeSource::Reserve).unwrap();
	let id = c.net.pass(&format!("{}: entry into the leaf", name), &e.tx);
	made.push(e.tx.clone());
	(coin_of(id, 0, &e.tx), made)
}

fn paid_to(c: &Arca, txid: &Txid, vout: usize) -> (Script, u64) {
	let tx = c.net.rt.client().raw_transaction(txid).unwrap();
	(tx.output[vout].script_pubkey.clone(), tx.output[vout].value.explicit().unwrap())
}

/// A refund `r` spending `old` and `new` with `old_pair`, `new_pair`, the
/// margin as the fee, and its outputs replaced by `outputs`.
fn refund_with(r: &Refund, old: &Coin, new: &Coin, old_pair: &Pair, new_pair: &Pair, outputs: Option<Vec<ExplicitOutput>>) -> Transaction {
	let mut u = r.tx(old.outpoint, new.outpoint, old_pair, new_pair, &FeeSource::Reserve).unwrap();
	if let Some(outs) = outputs {
		let held = r.old_value + r.new_value;
		let taken: u64 = outs.iter().map(|o| o.value).sum();
		u.tx.output = outs.iter().map(|o| o.txout()).collect();
		u.tx.output.push(elements::TxOut::new_fee(held - taken, r.asset));
	}
	u.tx
}

#[test]
fn offline_refresh_refunds() {
	let mut c = Arca::start();
	let x = c.net.x;
	let script_failure = "mempool-script-verify-flag-failed";

	// ── Plan A: two steps; the holder signs everything before any round. ──
	let a = plan(&mut c, "A", 2);
	let id = a.plan.id();
	let _proofs: Vec<_> = (1..=2).map(|i| sig(&a.keys[i], &key_proof_digest(&id))).collect();
	let (a1_old, a1_new) = pairs(&a, 1);
	let (a2_old, _a2_new) = pairs(&a, 2);
	let r1 = a.plan.refund(1).unwrap();
	println!("plan A {}: refund 1 commits to {:?}", sha256(&id).iter().take(4).map(|b| format!("{:02x}", b)).collect::<String>(),
		r1.outputs().iter().map(|o| o.value).collect::<Vec<_>>());

	// Step 1's round, after the halves were made: the operator unrolls L(1)
	// with its own authorisations and opens its entry with the plan's
	// preimage, the holder having brought L(0) home.
	let (tree_a1, round_a1, _) = step_round(&mut c, &a, 1, "A");
	let t = mt(c.net.mtp() - 1);
	let auths = operator_auths(&tree_a1, &a.s, t);
	let (l1, _) = bring(&mut c, "A: the operator brings L(1) on-chain", &tree_a1, &round_a1, &auths, &a.preimages[1]);
	assert_eq!(l1.txout.script_pubkey, a.plan.leaf(1).unwrap().script_pubkey(), "the round's leaf is the plan's L(1)");

	// Negatives, every one forced into a block.
	let holder = r1.holder.clone();
	let operator = r1.operator.clone();
	let short = ExplicitOutput::new(x, holder.value - 1, holder.script_pubkey.clone());
	c.net.refuse("A: output 0 one atom short", &refund_with(&r1, &a.l0, &l1, &a1_old, &a1_new, Some(vec![short, operator.clone()])), script_failure);
	let elsewhere = ExplicitOutput::new(x, holder.value, address("A: someone else"));
	c.net.refuse("A: output 0 paying another script", &refund_with(&r1, &a.l0, &l1, &a1_old, &a1_new, Some(vec![elsewhere, operator.clone()])), script_failure);
	let more = ExplicitOutput::new(x, operator.value + 1, operator.script_pubkey.clone());
	c.net.refuse("A: output 1 one atom more", &refund_with(&r1, &a.l0, &l1, &a1_old, &a1_new, Some(vec![holder.clone(), more])), script_failure);
	c.net.refuse("A: outputs swapped", &refund_with(&r1, &a.l0, &l1, &a1_old, &a1_new, Some(vec![operator.clone(), holder.clone()])), script_failure);
	// L(1) under the pair it signed as step 2's old coin.
	c.net.refuse("A: step 2's half on L(1) in step 1's refund", &refund_with(&r1, &a.l0, &l1, &a1_old, &a2_old, None), script_failure);
	// A pair over L(2)'s message (another salt), signed by L(1)'s key.
	let other_salt = a.plan.leaf(2).unwrap().message(x, LEAF, &r1.outputs()).unwrap().digest;
	let wrong_salt = Pair { operator: sig(&a.s, &other_salt), owner: sig(&a.keys[1], &other_salt) };
	c.net.refuse("A: L(1)'s half made for another salt", &refund_with(&r1, &a.l0, &l1, &a1_old, &wrong_salt, None), script_failure);
	// A pair over the message of another chain: the genesis hash in display order.
	let mut g = c.net.chain.genesis_bytes();
	g.reverse();
	let other_chain = Chain::new(elements::BlockHash::from_raw_hash(elements::hashes::sha256d::Hash::from_byte_array(g)));
	let mut l1_elsewhere = a.plan.leaf(1).unwrap();
	l1_elsewhere.chain = other_chain;
	let d = l1_elsewhere.message(x, LEAF, &r1.outputs()).unwrap().digest;
	let wrong_chain = Pair { operator: sig(&a.s, &d), owner: sig(&a.keys[1], &d) };
	c.net.refuse("A: L(1)'s half made for another chain", &refund_with(&r1, &a.l0, &l1, &a1_old, &wrong_chain, None), script_failure);
	// The operator's signature in both slots.
	let both = Pair { operator: a1_new.operator, owner: a1_new.operator };
	c.net.refuse("A: the operator's signature in both slots of L(1)", &refund_with(&r1, &a.l0, &l1, &a1_old, &both, None), script_failure);
	let alone = Pair { operator: a1_old.operator, owner: a1_old.operator };
	c.net.refuse("A: the operator's signature in both slots of L(0)", &refund_with(&r1, &a.l0, &l1, &alone, &a1_new, None), script_failure);
	// A slot left empty: the owner's (the operator alone), then the operator's
	// (the holder's halves alone).
	let empty = elements::secp256k1_zkp::schnorr::Signature::from_slice(&[0u8; 64]).unwrap();
	let mut tx = refund_with(&r1, &a.l0, &l1, &a1_old, &a1_new, None);
	tx.input[1].witness.script_witness[1] = vec![];
	c.net.refuse("A: L(1) with the operator's signature alone", &tx, script_failure);
	let mut tx = refund_with(&r1, &a.l0, &l1, &a1_old, &a1_new, None);
	tx.input[1].witness.script_witness[0] = vec![];
	c.net.refuse("A: L(1) with the holder's half alone", &tx, script_failure);
	let _ = empty;
	// A coin of L(1)'s script holding one atom more: the half binds the amount.
	let copy = c.net.fund(vec![explicit(x, LEAF + 1, l1.txout.script_pubkey.clone())]).remove(0);
	let mut tx = refund_with(&r1, &a.l0, &l1, &a1_old, &a1_new, None);
	tx.input[1].previous_output = copy.outpoint;
	let last = tx.output.len() - 1;
	tx.output[last] = elements::TxOut::new_fee(MARGIN_ATOMS + 1, x);
	c.net.refuse("A: L(1)'s half on a coin of its script holding one atom more", &tx, script_failure);

	// The refund as made: mined, output 0 the holder's v(1).
	let txid = c.net.pass("A: refund of step 1 (margin as the fee)", &refund_with(&r1, &a.l0, &l1, &a1_old, &a1_new, None));
	assert_eq!(paid_to(&c, &txid, 0), (r1.holder.script_pubkey.clone(), LEAF), "output 0 pays the holder v(1)");
	assert_eq!(paid_to(&c, &txid, 1).1, LEAF - MARGIN_ATOMS);

	// ── Plan B: step 2's refund answers the holder bringing home L(1), a leaf
	// step 1 made; the fee from a coin in another asset. ──
	let b = plan(&mut c, "B", 2);
	let (b2_old, b2_new) = pairs(&b, 2);
	let (tree_b1, round_b1, _) = step_round(&mut c, &b, 1, "B");
	let (tree_b2, round_b2, _) = step_round(&mut c, &b, 2, "B");
	// The holder's own unroll of L(1): its key A(1) is a member of every node
	// above it, and it opens the entry with its own preimage.
	let t = mt(c.net.mtp() - 1);
	let rec = tree_b1.record(1);
	let holder_auths = owner_auths(&rec.validate(&round_b1, &c.policy(&b.s), &xonly(&b.keys[1]), &b.plan.steps[0].owner_nonce).unwrap(),
		&b.keys[1], t);
	let (b_l1, _) = bring(&mut c, "B: the holder brings L(1) home", &tree_b1, &round_b1, &holder_auths, &b.preimages[1]);
	let auths = operator_auths(&tree_b2, &b.s, t);
	let (b_l2, _) = bring(&mut c, "B: the operator brings L(2) on-chain", &tree_b2, &round_b2, &auths, &b.preimages[2]);
	let r2 = b.plan.refund(2).unwrap();
	let fee_coin = c.net.fee_coin();
	let by_coin = FeeSource::Coin { outpoint: fee_coin.outpoint, coin: fee_coin.txout.clone(), fee: 2_000, change: op_true_spk() };
	let mut u = r2.tx(b_l1.outpoint, b_l2.outpoint, &b2_old, &b2_new, &by_coin).unwrap();
	u.tx.input[2].witness.script_witness = op_true_witness();
	let txid = c.net.pass("B: refund of step 2 (an outside fee coin)", &u.tx);
	assert_eq!(paid_to(&c, &txid, 0), (r2.holder.script_pubkey.clone(), LEAF), "output 0 pays the holder v(2)");

	// ── Plan C: step 1's round replaced. ──
	let cc = plan(&mut c, "C", 1);
	let (c1_old, c1_new) = pairs(&cc, 1);
	let (tree_c1, round_c1, issuer) = step_round(&mut c, &cc, 1, "C");
	let t = mt(c.net.mtp() - 1);
	let auths = operator_auths(&tree_c1, &cc.s, t);
	let (c_l1, _) = bring(&mut c, "C: the operator brings L(1) on-chain", &tree_c1, &round_c1, &auths, &cc.preimages[1]);
	// The round is disconnected and another round spends its token issuer:
	// a tree of other owners only.
	c.roll_back(&round_c1.txid());
	let sched = tree_c1.params().schedule.clone();
	let others: Vec<LeafSpec> = (0..3).map(|k| spec(&keypair(&format!("C replacement {}", k)), &format!("C replacement {}", k),
		LEAF, sha256(&label32(&format!("C replacement preimage {}", k))))).collect();
	let tree_c1b = c.tree(&sched, &others);
	let (replacement, _) = round_tx(&c.net, &issuer, &[], &tree_c1b.batch_output(), &sched);
	c.mine_with(&[&replacement]);
	assert!(!c.unspent(&c_l1.outpoint), "L(1) left the chain with its round");
	let r1c = cc.plan.refund(1).unwrap();
	c.net.refuse("C: refund of step 1 after its round was replaced", &refund_with(&r1c, &cc.l0, &c_l1, &c1_old, &c1_new, None),
		"bad-txns-inputs-missingorspent");
	// L(0) is the holder's: its exit confirms after the delay.
	let l0_txid = cc.l0.outpoint.txid;
	c.net.wait_csv(&l0_txid, delay());
	let ex = exit_tx(&c.net, &cc.plan.first, cc.l0.outpoint, x, LEAF, &cc.keys[0]);
	c.net.pass("C: the holder's exit of L(0) after the replacement", &ex);

	// ── Plan F: step 1's round replaced, the step run again under the same
	// leaf in another round; the refund, bound to the leaf and not the round,
	// is good on the leaf of the round that runs it again. ──
	let ff = plan(&mut c, "F", 1);
	let (f1_old, f1_new) = pairs(&ff, 1);
	let (tree_f1, round_f1, issuer_f) = step_round(&mut c, &ff, 1, "F");
	c.roll_back(&round_f1.txid());
	let sched_f = tree_f1.params().schedule.clone();
	let others: Vec<LeafSpec> = (0..3).map(|k| spec(&keypair(&format!("F replacement {}", k)), &format!("F replacement {}", k),
		LEAF, sha256(&label32(&format!("F replacement preimage {}", k))))).collect();
	let (replacement_f, _) = round_tx(&c.net, &issuer_f, &[], &c.tree(&sched_f, &others).batch_output(), &sched_f);
	c.mine_with(&[&replacement_f]);
	let (tree_f1b, round_f1b, _) = step_round(&mut c, &ff, 1, "F again");
	assert_ne!(round_f1b.txid(), round_f1.txid());
	let t = mt(c.net.mtp() - 1);
	let auths = operator_auths(&tree_f1b, &ff.s, t);
	let (f_l1, _) = bring(&mut c, "F: the operator brings the re-run's L(1) on-chain", &tree_f1b, &round_f1b, &auths, &ff.preimages[1]);
	assert_eq!(f_l1.txout.script_pubkey, ff.plan.leaf(1).unwrap().script_pubkey());
	let rf = ff.plan.refund(1).unwrap();
	let txid = c.net.pass("F: refund of step 1 on the re-run's L(1)", &refund_with(&rf, &ff.l0, &f_l1, &f1_old, &f1_new, None));
	assert_eq!(paid_to(&c, &txid, 0), (rf.holder.script_pubkey.clone(), LEAF), "output 0 pays the holder v(1)");

	// ── Plan D: each half used alone, the operator funding the rest. ──
	let dd = plan(&mut c, "D", 1);
	let (d1_old, d1_new) = pairs(&dd, 1);
	let rd = dd.plan.refund(1).unwrap();
	// L(0) alone: the operator adds a coin of its own for output 0.
	let op_coin = c.net.fund(vec![explicit(x, LEAF, op_true_spk())]).remove(0);
	let mut s = spend(0).coin(&dd.l0, 0xffff_ffff).coin(&op_coin, 0xffff_ffff)
		.outputs(vec![rd.holder.txout(), rd.operator.txout(), fee(x, MARGIN_ATOMS)]);
	s.witness(0, rd.old.witness(&d1_old, 2));
	s.witness(1, op_true_witness());
	let txid = c.net.pass("D: L(0) alone by its half, the operator funding output 0", &s.tx);
	assert_eq!(paid_to(&c, &txid, 0), (rd.holder.script_pubkey.clone(), LEAF), "output 0 pays the holder v(1)");
	// L(1) alone: the step ran, the operator brings L(1) on-chain and spends it
	// by its half, funding output 1 itself.
	let (tree_d1, round_d1, _) = step_round(&mut c, &dd, 1, "D");
	let t = mt(c.net.mtp() - 1);
	let auths = operator_auths(&tree_d1, &dd.s, t);
	let (d_l1, _) = bring(&mut c, "D: the operator brings L(1) on-chain", &tree_d1, &round_d1, &auths, &dd.preimages[1]);
	let op_coin = c.net.fund(vec![explicit(x, LEAF, op_true_spk())]).remove(0);
	let mut s = spend(0).coin(&d_l1, 0xffff_ffff).coin(&op_coin, 0xffff_ffff)
		.outputs(vec![rd.holder.txout(), rd.operator.txout(), fee(x, MARGIN_ATOMS)]);
	s.witness(0, rd.new.witness(&d1_new, 2));
	s.witness(1, op_true_witness());
	let txid = c.net.pass("D: L(1) alone by its half, the operator funding output 1", &s.tx);
	assert_eq!(paid_to(&c, &txid, 0), (rd.holder.script_pubkey.clone(), LEAF), "output 0 pays the holder v(1) again");

	// ── Plan E: no step ran; the operator funds a copy of L(1) to take L(0). ──
	let ee = plan(&mut c, "E", 1);
	let (e1_old, e1_new) = pairs(&ee, 1);
	let re = ee.plan.refund(1).unwrap();
	let copy = c.net.fund(vec![explicit(x, LEAF, ee.plan.leaf(1).unwrap().script_pubkey())]).remove(0);
	let txid = c.net.pass("E: L(0) with a copy of L(1) the operator funded", &refund_with(&re, &ee.l0, &copy, &e1_old, &e1_new, None));
	assert_eq!(paid_to(&c, &txid, 0), (re.holder.script_pubkey.clone(), LEAF), "output 0 pays the holder v(1)");

	c.net.print();
}
