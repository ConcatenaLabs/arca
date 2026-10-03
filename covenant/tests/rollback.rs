//! Rollbacks and the forfeit, on a Sequentia regtest chain: what each party
//! holds when a round or an answer is disconnected.
//!
//! `invalidateblock` stands in for an anchor-driven rollback. Every
//! transaction is built with this crate's builders, signed with test keys and
//! broadcast to a node on an anchored `elementsregtest` chain started with
//! `-par=1`; a negative case is refused by the mempool and again when forced
//! into a block, the block for the mempool's reason.
//!
//! 1. A round disconnected and broadcast again unchanged returns with its
//!    txid: the re-check finds the same round, `M` is issued, the forfeit is
//!    claimed. The operator ends with the old coin, the owner with the new
//!    leaf.
//! 2. A replacement with another txid paying the same batch output: the
//!    re-check calls it a new round and the wallet will not carry its forfeit
//!    over; `M` of the old round cannot be issued and the new round's does not
//!    satisfy the claim. The owner ends with the old coin and the new leaf,
//!    which is why a round with another txid is always a new round.
//! 3. A round whose third party's input is spent elsewhere cannot return.
//!    The new round has a new tree and new unlock hashes, and the
//!    participations run again; each owner still holds the forfeit it signed
//!    for the lost round, which no claim can answer. Published first, the new
//!    forfeit wins; with the preimage released first, the owner publishes the
//!    old one, refunds it and keeps the new leaf too.
//! 4. A forfeit disconnected late in its refund delay and mined again later:
//!    the delay restarts.
//! 5. A receiver's checkpoint disconnected, the replacing chain running past
//!    the sender's exit delay: the leaf's delay does not restart and a producer
//!    mines the sender's exit.
//! 6. A board's forfeit seen in one block, then disconnected: the owner has no
//!    exit from the board itself; its conversion starts the leaf's delay, and
//!    the same pair's forfeit takes the converted leaf.
//!
//! Needs `SEQUENTIAD_EXEC`; `--nocapture` prints every transaction.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::{OutPoint, Transaction};
use serde_json::json;

use arca_covenant::script::sha256;
use arca_covenant::spend::FeeSource;
use arca_covenant::witness::find_preimage;
use arca_covenant::*;

use common::net::*;
use common::round::*;
use common::*;

/// A refresh: an old leaf on-chain, given up for a new leaf in round X.
struct Refresh {
	s: Keypair,
	owner_old: Keypair,
	owner_new: Keypair,
	old: LeafPolicy,
	old_coin: Coin,
	old_id: LeafId,
	record: LeafRecord,
	preimage: [u8; 32],
	round: Transaction,
	c: u32,
	valid: ValidLeaf,
	forfeit: Forfeit,
	pair: Pair,
}

/// Round X refreshes one owner's old leaf into a new one; the owner signs
/// the forfeit for X, and the operator hands over the preimage.
fn refresh(c: &mut Arca, label: &str) -> Refresh {
	let s = keypair(&format!("{} operator", label));
	let owner_old = keypair(&format!("{} owner, old leaf", label));
	let owner_new = keypair(&format!("{} owner, new leaf", label));
	let (old, old_coin, old_id) = funded_leaf(&mut c.net, &owner_old, &s, &format!("{} old leaf", label), LEAF);
	let preimage = label32(&format!("{} preimage", label));
	let (issuer, sched) = c.schedule(&s);
	let sp = spec(&owner_new, &format!("{} new leaf", label), LEAF - 2_000, sha256(&preimage));
	let tree = c.tree(&sched, &[sp]);
	let (round, cv) = round_tx(&c.net, &issuer, &[], &tree.batch_output(), &sched);
	c.net.pass(&format!("{}/round X", label), &round);
	let record = tree.record(0);
	let valid = record.validate(&round, &c.policy(&s), &xonly(&owner_new), &sp.owner_nonce).unwrap();
	let forfeit = Forfeit::for_refresh(old, (c.net.x, LEAF), old_id, &valid, &round, cv, delay(), 1_500).unwrap();
	let pair = forfeit_pair(&forfeit, &owner_old, &s);
	forfeit.verify(&pair).unwrap();
	Refresh { s, owner_old, owner_new, old, old_coin, old_id, record, preimage, round, c: cv, valid, forfeit, pair }
}

// ---------------------------------------------------------------------------
// 1. The round returns unchanged
// ---------------------------------------------------------------------------

#[test]
fn a_round_broadcast_again_returns_and_its_forfeits_are_claimed() {
	let mut c = Arca::start();
	let x = c.net.x;
	let r = refresh(&mut c, "d1");
	let rt = r.round.txid();
	c.roll_back(&rt);
	let mempool = c.net.rpc("getrawmempool", json!([]));
	assert!(mempool.as_array().unwrap().iter().any(|t| t == &json!(rt.to_string())), "X is back in the mempool");
	c.net.mine(1);
	assert!(c.net.rt.client().confirmations(&rt).unwrap() >= 1);
	println!("d1: round X {} disconnected and mined again with the same txid", rt);
	let now = c.net.rt.client().raw_transaction(&rt).unwrap();
	assert!(matches!(r.record.recheck(&r.valid, &now, &c.policy(&r.s)).unwrap(), Recheck::Same(_)));

	// The owner starts to exit the old leaf; the operator answers with the
	// forfeit, issues M and claims.
	let ft = c.net.pass("d1/the forfeit", &r.forfeit.tx(r.old_coin.outpoint, &r.pair, &FeeSource::Reserve).unwrap().tx);
	let it = c.net.pass("d1/the issuance of M after X returned", &issuance_tx(&c.net, &now, r.c, &r.s));
	let m = coin_of(it, 0, &c.net.rt.client().raw_transaction(&it).unwrap());
	let ct = c.net.pass("d1/the operator's claim", &claim_tx(&c.net, &r.forfeit, OutPoint::new(ft, 0), &m, &r.s, &r.preimage));
	c.net.refuse("d1/neg the owner's refund of the claimed forfeit", &refund_tx(&c.net, &r.forfeit, OutPoint::new(ft, 0), &r.owner_old),
		"bad-txns-inputs-missingorspent");

	// The owner takes the new leaf with the preimage the claim published.
	let learned = find_preimage(&c.net.witness_of(&ct, 0), &sha256(&r.preimage)).unwrap();
	let auths = owner_auths(&r.valid, &r.owner_new, mt(c.net.mtp() - 60));
	let at = c.bring_leaf("d1/the new leaf", &r.valid, &auths, &learned);
	c.net.wait_csv(&at.txid, delay());
	let et = c.net.pass("d1/the owner's exit of the new leaf", &exit_tx(&c.net, &r.valid.branch.leaf, at, x, LEAF - 2_000, &r.owner_new));
	let (op, own) = (paid(&c.net, &ct), paid(&c.net, &et));
	assert_eq!((op, own), (LEAF - 1_500 - 1_500, LEAF - 2_000 - 1_500));
	println!("d1: RESULT the operator holds the old coin ({} atoms), the owner the new leaf ({} atoms)", op, own);
	c.net.print();
}

// ---------------------------------------------------------------------------
// 2. A replacement with another txid, paying the same batch output
// ---------------------------------------------------------------------------

#[test]
fn a_replacement_paying_the_same_batch_output_voids_the_forfeits() {
	let mut c = Arca::start();
	let x = c.net.x;
	let r = refresh(&mut c, "e1");
	let rt = r.round.txid();
	c.roll_back(&rt);
	// Y: the same issuing coin and batch output, one atom more of fee.
	let mut y = r.round.clone();
	let n = y.output.len();
	let v = y.output[n - 2].value.explicit().unwrap();
	y.output[n - 2].value = elements::confidential::Value::Explicit(v - 1);
	y.output[n - 1].value = elements::confidential::Value::Explicit(2_001);
	c.mine_with(&[&y]);
	let yt = y.txid();
	assert_ne!(yt, rt);
	println!("e1: round X {} disconnected, Y {} mined in its place, paying the same batch output", rt, yt);

	// The wallet's re-check: a new round. The leaf is good, and the forfeit
	// signed for X is not carried over to Y.
	let valid_y = match r.record.recheck(&r.valid, &y, &c.policy(&r.s)).unwrap() {
		Recheck::NewRound(v) => v,
		Recheck::Same(_) => panic!("Y is not X"),
	};
	assert_eq!(valid_y.leaf_id, r.valid.leaf_id);
	assert_eq!(Forfeit::for_refresh(r.old, (x, LEAF), r.old_id, &r.valid, &y, r.c, delay(), 1_500).unwrap_err(), SpendError::NotTheRound);

	// The forfeit signed for X cannot be claimed: M of X cannot be issued,
	// and Y's connector asset is not M.
	let ft = c.net.pass("e1/the operator publishes the forfeit signed for X", &r.forfeit.tx(r.old_coin.outpoint, &r.pair, &FeeSource::Reserve).unwrap().tx);
	c.net.refuse("e1/neg the issuance of X's connector asset", &issuance_tx(&c.net, &r.round, r.c, &r.s), "bad-txns-inputs-missingorspent");
	let it = c.net.pass("e1/the issuance of Y's connector asset", &issuance_tx(&c.net, &y, r.c, &r.s));
	let m_y = coin_of(it, 0, &c.net.rt.client().raw_transaction(&it).unwrap());
	c.net.refuse("e1/neg the claim with Y's connector asset", &claim_tx(&c.net, &r.forfeit, OutPoint::new(ft, 0), &m_y, &r.s, &r.preimage),
		"Script failed an OP_EQUALVERIFY operation");

	// The owner refunds the old coin and takes the new leaf from Y.
	c.net.wait_csv(&ft, delay());
	let rf = c.net.pass("e1/the owner's refund of the old coin", &refund_tx(&c.net, &r.forfeit, OutPoint::new(ft, 0), &r.owner_old));
	let auths = owner_auths(&valid_y, &r.owner_new, mt(c.net.mtp() - 60));
	let at = c.bring_leaf("e1/the new leaf from Y", &valid_y, &auths, &r.preimage);
	c.net.wait_csv(&at.txid, delay());
	let et = c.net.pass("e1/the owner's exit of the new leaf", &exit_tx(&c.net, &valid_y.branch.leaf, at, x, LEAF - 2_000, &r.owner_new));
	let (old, new) = (paid(&c.net, &rf), paid(&c.net, &et));
	assert_eq!((old, new), (LEAF - 1_500 - 1_500, LEAF - 2_000 - 1_500));
	println!("e1: RESULT the owner holds the old coin ({} atoms) AND the new leaf ({} atoms); the operator neither", old, new);
	c.net.print();
}

// ---------------------------------------------------------------------------
// 3. A round that cannot return, and the new round after it
// ---------------------------------------------------------------------------

#[test]
fn a_round_that_cannot_return_is_followed_by_a_new_round() {
	let mut c = Arca::start();
	let x = c.net.x;
	let s = keypair("lost operator");
	let (p_old_key, q_old_key) = (keypair("lost P, old leaf"), keypair("lost Q, old leaf"));
	let (p_new_key, q_new_key) = (keypair("lost P, new leaf"), keypair("lost Q, new leaf"));
	let (p_old, p_coin, p_id) = funded_leaf(&mut c.net, &p_old_key, &s, "lost P old leaf", LEAF);
	let (q_old, q_coin, q_id) = funded_leaf(&mut c.net, &q_old_key, &s, "lost Q old leaf", LEAF);

	// Round X refreshes both, and takes a third party's coin (a fill).
	let (issuer, sched) = c.schedule(&s);
	let (pre_px, pre_qx) = (label32("lost P preimage X"), label32("lost Q preimage X"));
	let (sp, sq) = (spec(&p_new_key, "lost P new X", LEAF - 2_000, sha256(&pre_px)), spec(&q_new_key, "lost Q new X", LEAF - 2_000, sha256(&pre_qx)));
	let tree_x = c.tree(&sched, &[sp, sq]);
	let fill = c.net.fund(vec![explicit(x, 50_000, op_true_spk())]).remove(0);
	let (round_x, cx) = round_tx(&c.net, &issuer, std::slice::from_ref(&fill), &tree_x.batch_output(), &sched);
	let rt = c.net.pass("lost/round X, with a third party's input", &round_x);
	let policy = c.policy(&s);
	let vp = tree_x.record(0).validate(&round_x, &policy, &xonly(&p_new_key), &sp.owner_nonce).unwrap();
	let vq = tree_x.record(1).validate(&round_x, &policy, &xonly(&q_new_key), &sq.owner_nonce).unwrap();
	let fpx = Forfeit::for_refresh(p_old, (x, LEAF), p_id, &vp, &round_x, cx, delay(), 1_500).unwrap();
	let fqx = Forfeit::for_refresh(q_old, (x, LEAF), q_id, &vq, &round_x, cx, delay(), 1_500).unwrap();
	let (ppx, pqx) = (forfeit_pair(&fpx, &p_old_key, &s), forfeit_pair(&fqx, &q_old_key, &s));

	// The rollback; the third party spends its coin elsewhere, so X can
	// never return.
	c.roll_back(&rt);
	let mut elsewhere = spend(0).coin(&fill, 0xffff_ffff).outputs(vec![explicit(x, 48_000, op_true_spk()), fee(x, 2_000)]);
	elsewhere.witness(0, op_true_witness());
	c.mine_with(&[&elsewhere.tx]);
	c.net.refuse("lost/neg round X again, its third party's coin spent", &round_x, "bad-txns-inputs-missingorspent");

	// The new round: a new tree, new unlock hashes, no third party's input.
	let (issuer, sched) = c.schedule(&s);
	let (pre_py, pre_qy) = (label32("lost P preimage Y"), label32("lost Q preimage Y"));
	let (spy, sqy) = (spec(&p_new_key, "lost P new Y", LEAF - 2_000, sha256(&pre_py)), spec(&q_new_key, "lost Q new Y", LEAF - 2_000, sha256(&pre_qy)));
	let tree_y = c.tree(&sched, &[spy, sqy]);
	let (round_y, cy) = round_tx(&c.net, &issuer, &[], &tree_y.batch_output(), &sched);
	c.net.pass("lost/round Y, a new round", &round_y);
	assert_eq!(tree_x.record(0).validate_round(&round_y, &policy).unwrap_err(), RecordError::BatchOutputMissing);
	let vpy = tree_y.record(0).validate(&round_y, &policy, &xonly(&p_new_key), &spy.owner_nonce).unwrap();
	let vqy = tree_y.record(1).validate(&round_y, &policy, &xonly(&q_new_key), &sqy.owner_nonce).unwrap();
	let fpy = Forfeit::for_refresh(p_old, (x, LEAF), p_id, &vpy, &round_y, cy, delay(), 1_500).unwrap();
	let fqy = Forfeit::for_refresh(q_old, (x, LEAF), q_id, &vqy, &round_y, cy, delay(), 1_500).unwrap();
	let (ppy, pqy) = (forfeit_pair(&fpy, &p_old_key, &s), forfeit_pair(&fqy, &q_old_key, &s));
	let it = c.net.pass("lost/the issuance of Y's connector asset", &issuance_tx(&c.net, &round_y, cy, &s));
	let m_y = coin_of(it, 0, &c.net.rt.client().raw_transaction(&it).unwrap());

	// P: the operator publishes the forfeit for Y first, and releases the
	// preimage once it is in the chain. P's forfeit for X has no coin left.
	let fpyt = c.net.pass("lost/P's forfeit for Y, published first", &fpy.tx(p_coin.outpoint, &ppy, &FeeSource::Reserve).unwrap().tx);
	c.net.refuse("lost/neg P's forfeit for X, after", &fpx.tx(p_coin.outpoint, &ppx, &FeeSource::Reserve).unwrap().tx,
		"bad-txns-inputs-missingorspent");
	let pct = claim_tx(&c.net, &fpy, OutPoint::new(fpyt, 0), &m_y, &s, &pre_py);
	let pc = c.net.pass("lost/the claim of P's forfeit for Y", &pct);
	let m_y = coin_of(pc, 1, &pct);
	println!("lost: P, forfeit first: the operator holds P's old coin ({} atoms); P its new leaf in Y", paid(&c.net, &pc));

	// Q: the operator releases the preimage on the pair alone, as for a
	// round that stays. Q publishes its forfeit for X, which no claim can
	// answer, and refunds it.
	let fqxt = c.net.pass("lost/Q's forfeit for X, published by Q", &fqx.tx(q_coin.outpoint, &pqx, &FeeSource::Reserve).unwrap().tx);
	c.net.refuse("lost/neg Q's forfeit for Y, after", &fqy.tx(q_coin.outpoint, &pqy, &FeeSource::Reserve).unwrap().tx,
		"bad-txns-inputs-missingorspent");
	c.net.refuse("lost/neg the claim of Q's forfeit for X with Y's connector asset",
		&claim_tx(&c.net, &fqx, OutPoint::new(fqxt, 0), &m_y, &s, &pre_qx), "Script failed an OP_EQUALVERIFY operation");
	c.net.wait_csv(&fqxt, delay());
	let rq = c.net.pass("lost/Q's refund of its forfeit for X", &refund_tx(&c.net, &fqx, OutPoint::new(fqxt, 0), &q_old_key));
	let auths = owner_auths(&vqy, &q_new_key, mt(c.net.mtp() - 60));
	let at = c.bring_leaf("lost/Q's new leaf in Y", &vqy, &auths, &pre_qy);
	c.net.wait_csv(&at.txid, delay());
	let eq = c.net.pass("lost/Q's exit of its new leaf", &exit_tx(&c.net, &vqy.branch.leaf, at, x, LEAF - 2_000, &q_new_key));
	println!("lost: RESULT Q, preimage first: Q holds its old coin ({} atoms) AND its new leaf ({} atoms)",
		paid(&c.net, &rq), paid(&c.net, &eq));
	c.net.print();
}

// ---------------------------------------------------------------------------
// 4. A forfeit disconnected late in its refund delay
// ---------------------------------------------------------------------------

#[test]
fn a_forfeit_rolled_back_restarts_its_refund_delay() {
	let mut c = Arca::start();
	let s = keypair("d2 operator");
	let a = keypair("d2 owner");
	let (old, coin, id) = funded_leaf(&mut c.net, &a, &s, "d2 old leaf", LEAF);
	let f = Forfeit::new(old, (c.net.x, LEAF), id, sha256(&label32("d2 h")), connector_asset(OutPoint::default().txid, 2),
		delay(), 1_500).unwrap();
	let pair = forfeit_pair(&f, &a, &s);
	let ftx = f.tx(coin.outpoint, &pair, &FeeSource::Reserve).unwrap().tx;
	let ft = c.net.pass("d2/the forfeit", &ftx);
	let first = c.net.csv_ready(&ft, delay());
	// Most of the delay passes; then the forfeit's block is disconnected, and
	// the new chain carries the forfeit only six hours later.
	c.net.mtp_past(first - 2 * H as u64);
	c.roll_back(&ft);
	for _ in 0..36 {
		c.net.mock += 600;
		c.net.set_mock(c.net.mock);
		c.mine_with(&[]);
	}
	c.mine_with(&[&ftx]);
	let again = c.net.csv_ready(&ft, delay());
	assert!(again > first + 6 * H as u64 - 600);
	println!("d2: the refund was due at median time {}; after the rollback at {}", first, again);
	c.net.mtp_past(first);
	c.net.refuse("d2/neg the refund at the old time", &refund_tx(&c.net, &f, OutPoint::new(ft, 0), &a), "non-BIP68-final");
	c.net.mtp_past(again);
	c.net.pass("d2/the refund after the restarted delay", &refund_tx(&c.net, &f, OutPoint::new(ft, 0), &a));
	c.net.print();
}

// ---------------------------------------------------------------------------
// 5. A receiver's checkpoint disconnected past the sender's exit delay
// ---------------------------------------------------------------------------

#[test]
fn a_rolled_back_checkpoint_does_not_restart_the_leafs_delay() {
	let mut c = Arca::start();
	let x = c.net.x;
	let s = keypair("d3 operator");
	let a = keypair("d3 A");
	let preimage = label32("d3 preimage");
	let (issuer, sched) = c.schedule(&s);
	let tree = c.tree(&sched, &[spec(&a, "d3 A", LEAF, sha256(&preimage)),
		spec(&keypair("d3 bystander"), "d3 bystander", LEAF, sha256(&label32("d3 other")))]);
	let (round, _) = round_tx(&c.net, &issuer, &[], &tree.batch_output(), &sched);
	c.net.pass("d3/round", &round);
	let rounds = vec![round];
	let a_base = base(&tree, 0, &a, preimage, mt(c.net.mtp() - 60));
	let policy = c.policy(&s);
	let a_coin = a_base.resolve(&rounds, &policy).unwrap();
	let (_b, b_leaf) = party("d3 B", delay());
	let b_coin = one_hop(&a_base, &a_coin, &a, &s, b_leaf, c.net.chain)
		.validate(&rounds, &policy.receipt(), &b_leaf.owner, &b_leaf.owner_nonce).unwrap();

	// A's leaf reaches the chain; B answers at once with the checkpoint.
	let a_at = c.bring_coin("d3/A's leaf", &a_coin);
	let cp = inputs(&b_coin)[0].checkpoint_tx(a_at, &FeeSource::Reserve).unwrap();
	let cpt = c.net.pass("d3/B's checkpoint, the block after A's leaf", &cp.tx);
	let ex = exit_tx(&c.net, &a_coin.leaf, a_at, x, LEAF, &a);
	c.net.refuse("d3/neg A's exit, the checkpoint confirmed", &ex, "bad-txns-inputs-missingorspent");

	// A rollback takes the checkpoint's block; the replacing chain runs past
	// A's exit delay without it. A's leaf stays, and its delay runs on.
	c.roll_back(&cpt);
	let ready = c.net.csv_ready(&a_at.txid, delay());
	let mut blocks = 0;
	while c.net.mtp() <= ready {
		c.net.mock += 3 * H as u64;
		c.net.set_mock(c.net.mock);
		c.mine_with(&[]);
		blocks += 1;
	}
	let r = c.net.rt.client().test_mempool_accept(&[&ex]).unwrap().remove(0);
	assert_eq!((r.allowed, r.reject_reason.as_deref()), (false, Some("txn-mempool-conflict")), "the checkpoint waits in the mempool");
	c.mine_with(&[&ex]);
	c.net.refuse("d3/neg B's checkpoint after A's exit", &cp.tx, "bad-txns-inputs-missingorspent");
	println!("d3: RESULT {} blocks without the checkpoint ran past A's delay; a producer mined A's exit. \
		The leaf's delay did not restart; only the answer was undone", blocks);
	c.net.print();
}

// ---------------------------------------------------------------------------
// 6. A board's forfeit disconnected after one block
// ---------------------------------------------------------------------------

#[test]
fn a_boards_forfeit_rolled_back_still_wins() {
	let mut c = Arca::start();
	let x = c.net.x;
	let s = keypair("d4 operator");
	let a = keypair("d4 board owner");
	let rec = BoardRecord {
		template: Template::Board1, owner: xonly(&a), owner_nonce: label32("d4 board nonce"),
		operator_nonce: label32("d4 board operator nonce"), exit_delay: delay(), asset: x, value: LEAF,
		chain: c.net.chain, operator: xonly(&s),
	};
	let board = rec.policy();
	let coin = c.net.fund(vec![rec.output().txout()]).remove(0);
	c.net.wait_csv(&coin.outpoint.txid, delay());
	// The board's forfeit, for some round: the operator publishes it from the
	// board output, sees it in one block, and hands over the preimage.
	let f = Forfeit::new(rec.leaf(), (x, LEAF), rec.leaf_id(), sha256(&label32("d4 h")), connector_asset(OutPoint::default().txid, 2),
		delay(), 1_500).unwrap();
	let pair = forfeit_pair(&f, &a, &s);
	let ftx = f.board_tx(&board, coin.outpoint, &pair, &FeeSource::Reserve).unwrap().tx;
	let fc = c.net.fee_coin();
	let ft = c.net.pass("d4/the board's forfeit, one block", &ftx);
	c.roll_back(&ft);
	// The owner has no exit from the board itself: it converts, and a
	// producer mines the conversion in place of the forfeit.
	let ks = board.conversion(coin.outpoint, &FeeSource::Coin { outpoint: fc.outpoint, coin: fc.txout, fee: 4_000, change: op_true_spk() }).unwrap();
	let mut conv = signed(&c.net, ks, &a, vec![]);
	conv.tx.input[1].witness.script_witness = op_true_witness();
	let r = c.net.rt.client().test_mempool_accept(&[&conv.tx]).unwrap().remove(0);
	assert_eq!((r.allowed, r.reject_reason.as_deref()), (false, Some("txn-mempool-conflict")), "the forfeit waits in the mempool");
	c.mine_with(&[&conv.tx]);
	let leaf_at = OutPoint::new(conv.tx.txid(), 0);
	// The conversion starts the leaf's delay: the owner's exit waits, and the
	// operator publishes the same pair's forfeit on the leaf.
	let ex = exit_tx(&c.net, &rec.leaf(), leaf_at, x, LEAF, &a);
	c.net.refuse("d4/neg the owner's exit right after the conversion", &ex, "non-BIP68-final");
	c.net.pass("d4/the forfeit again, on the converted leaf", &f.tx(leaf_at, &pair, &FeeSource::Reserve).unwrap().tx);
	c.net.wait_csv(&leaf_at.txid, delay());
	c.net.refuse("d4/neg the owner's exit after the delay", &ex, "bad-txns-inputs-missingorspent");
	println!("d4: RESULT the rollback of the board's forfeit gave the owner no exit: the forfeit took the converted leaf");
	c.net.print();
}
