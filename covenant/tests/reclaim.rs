//! The reclaim of a lowest node, bound to the rounds of its owners' new
//! leaves, on a Sequentia regtest chain.
//!
//! Every transaction is built with this crate's builders, signed with test
//! keys and broadcast to a node on an anchored `elementsregtest` chain started
//! with `-par=1`; a negative case is refused by the mempool and again when
//! forced into a block, the block for the mempool's reason.
//!
//! 1. Owners of an old batch refresh into new rounds and sign releases of
//!    their lowest node, each naming the connector asset `M` of its own new
//!    round ([`Release::for_refresh`]). The reclaim confirms with an atom of
//!    `M` among its inputs, and is refused without it, with another round's
//!    `M`, with another asset, with three releases of four, and with releases
//!    over the old message that named no round. Owners who refreshed in two
//!    rounds are reclaimed with an atom of each. One atom of `M` serves a
//!    forfeit's claim and two reclaims.
//! 2. The owners' round is disconnected and replaced by another with a new
//!    txid: `M` can no longer be issued, the reclaim with the releases the
//!    operator holds is refused with the replacement's `M` and without any,
//!    and the owners' old leaves stay theirs: one is unrolled and exited by
//!    its owner alone.
//! 3. A reclaim already confirmed, then its round's block disconnected and
//!    the round replaced: the issuance of `M` and the reclaim go with it and
//!    cannot return, the node is unspent again, and an owner exits its old
//!    leaf alone.
//! 4. A release given for an offboard ([`Release::for_offboard`]) names the
//!    round that pays the offboard; the one-owner node is reclaimed with that
//!    round's `M`, and not with another round's.
//!
//! Needs `SEQUENTIAD_EXEC`; `--nocapture` prints every transaction.

mod common;

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Transaction, TxOut};

use arca_covenant::node::connector_index;
use arca_covenant::script::sha256;
use arca_covenant::spend::FeeSource;
use arca_covenant::*;

use common::net::*;
use common::round::*;
use common::*;

/// An old batch of one lowest node: its owners, each leaf as its owner
/// validated it, and the round that paid it.
struct Old {
	owners: Vec<Keypair>,
	valid: Vec<ValidLeaf>,
	preimages: Vec<[u8; 32]>,
	round: Transaction,
}

/// A batch of `n` leaves under `s`, paid by its own round: one lowest node,
/// the batch output itself.
fn old_batch(c: &mut Arca, s: &Keypair, label: &str, n: usize) -> Old {
	let owners: Vec<Keypair> = (0..n).map(|i| keypair(&format!("{} owner {}", label, i))).collect();
	let preimages: Vec<[u8; 32]> = (0..n).map(|i| label32(&format!("{} preimage {}", label, i))).collect();
	let specs: Vec<LeafSpec> = owners.iter().zip(&preimages).enumerate()
		.map(|(i, (o, p))| spec(o, &format!("{} leaf {}", label, i), LEAF, sha256(p))).collect();
	let (issuer, sched) = c.schedule(s);
	let tree = c.tree(&sched, &specs);
	let (round, _) = round_tx(&c.net, &issuer, &[], &tree.batch_output(), &sched);
	c.net.pass(&format!("{}: the old batch's round", label), &round);
	let policy = c.policy(s);
	let valid = (0..n).map(|i| tree.record(i).validate(&round, &policy, &xonly(&owners[i]), &specs[i].owner_nonce).unwrap()).collect();
	Old { owners, valid, preimages, round }
}

/// A new round of leaves for `keys`, one each: the round, its connector
/// output's index, and each new leaf as its owner validated it.
fn new_round(c: &mut Arca, s: &Keypair, label: &str, keys: &[Keypair]) -> (Transaction, u32, Vec<ValidLeaf>) {
	let specs: Vec<LeafSpec> = keys.iter().enumerate()
		.map(|(i, k)| spec(k, &format!("{} new leaf {}", label, i), LEAF - 2_000, sha256(&label32(&format!("{} h {}", label, i)))))
		.collect();
	let (issuer, sched) = c.schedule(s);
	let tree = c.tree(&sched, &specs);
	let (round, cv) = round_tx(&c.net, &issuer, &[], &tree.batch_output(), &sched);
	c.net.pass(&format!("{}: the round", label), &round);
	let policy = c.policy(s);
	let valid = (0..keys.len()).map(|i| tree.record(i).validate(&round, &policy, &xonly(&keys[i]), &specs[i].owner_nonce).unwrap()).collect();
	(round, cv, valid)
}

/// The operator's issuance of `round`'s connector asset, mined: its atom.
fn issue_m(c: &mut Arca, name: &str, round: &Transaction, cv: u32, s: &Keypair) -> Coin {
	let tx = issuance_tx(&c.net, round, cv, s);
	let t = c.net.pass(name, &tx);
	coin_of(t, 0, &tx)
}

/// The reclaim of `old`'s lowest node, at output 0 of its round, with the
/// atoms `atoms` at inputs 1.., each paid back to OP_TRUE; `releases` (each
/// owner's signature and the input it names), in owner order; signed by
/// `s`. All but 2,000 atoms of the node to OP_TRUE; the rest is the fee.
fn reclaim(c: &Arca, old: &Old, atoms: &[&Coin], releases: &[(Vec<u8>, u32)], s: &Keypair) -> Transaction {
	let lowest = old.valid[0].branch.nodes.last().unwrap();
	let node = OutPoint::new(old.round.txid(), 0);
	let connectors: Vec<(OutPoint, TxOut)> = atoms.iter().map(|a| (a.outpoint, a.txout.clone())).collect();
	let ks = lowest.reclaim_tx(node, &connectors, &[ExplicitOutput::new(c.net.x, lowest.value - 2_000, op_true_spk())],
		op_true_spk(), &FeeSource::Reserve).unwrap();
	let op = sig(s, &ks.sighash(c.net.genesis).unwrap());
	let mut below = vec![op.as_ref().to_vec()];
	for (sg, k) in releases.iter().rev() {
		below.push(sg.clone());
		below.push(arca_covenant::script::scriptnum(*k as i64));
	}
	let mut u = ks.finish(below);
	for i in 1..u.tx.input.len() {
		u.tx.input[i].witness.script_witness = op_true_witness();
	}
	u.tx
}

/// Each owner's release from `releases`, with the input of `atoms` (at 1..)
/// that holds the asset it names.
fn with_index(releases: &[(Release, Signature)], atoms: &[&Coin]) -> Vec<(Vec<u8>, u32)> {
	let prevouts: Vec<TxOut> = std::iter::once(TxOut::default()).chain(atoms.iter().map(|a| a.txout.clone())).collect();
	releases.iter().map(|(r, sg)| (sg.as_ref().to_vec(), connector_index(&prevouts, r.connector).unwrap_or(1))).collect()
}

/// What output 1 of the confirmed transaction `txid` holds, as a coin.
fn atom_back(c: &Arca, txid: elements::Txid, vout: u32, m: AssetId) -> Coin {
	let tx = c.net.rt.client().raw_transaction(&txid).unwrap();
	let coin = coin_of(txid, vout, &tx);
	assert_eq!(coin.txout.asset.explicit(), Some(m), "the atom of M came back");
	coin
}

// ---------------------------------------------------------------------------
// 1. The reclaim with M, and every way without it
// ---------------------------------------------------------------------------

#[test]
fn a_reclaim_needs_the_connector_asset_of_each_owners_round() {
	let mut c = Arca::start();
	let s = keypair("reclaim operator");
	let b0 = old_batch(&mut c, &s, "B0", 4);
	let b1 = old_batch(&mut c, &s, "B1", 4);
	let new_keys = |label: &str, n: usize| -> Vec<Keypair> { (0..n).map(|i| keypair(&format!("{} new key {}", label, i))).collect() };

	// Round X refreshes B0's four owners, B1's owners 0 and 1, and Q's
	// board-funded leaf; round Y refreshes B1's owners 2 and 3.
	let q = keypair("Q old");
	let (q_old, q_coin, q_id) = funded_leaf(&mut c.net, &q, &s, "Q old leaf", LEAF);
	let (x_keys, y_keys) = (new_keys("X", 7), new_keys("Y", 2));
	let (x, cx, x_new) = new_round(&mut c, &s, "X", &x_keys);
	let (y, cy, y_new) = new_round(&mut c, &s, "Y", &y_keys);
	let (m_x, m_y) = (connector_asset(x.txid(), cx), connector_asset(y.txid(), cy));

	// Each owner signs its release once its new leaf is validated.
	let release = |old: &ValidLeaf, owner: &Keypair, new: &ValidLeaf, round: &Transaction, cv: u32| -> (Release, Signature) {
		let r = Release::for_refresh(old, new, round, cv).unwrap();
		assert_eq!(r.owner, xonly(owner));
		let sg = sig(owner, &r.message().digest);
		r.verify(&sg).unwrap();
		(r, sg)
	};
	let b0_rel: Vec<(Release, Signature)> = (0..4).map(|i| release(&b0.valid[i], &b0.owners[i], &x_new[i], &x, cx)).collect();
	assert!(b0_rel.iter().all(|(r, _)| r.connector == m_x && r.node_hash == b0_rel[0].0.node_hash));
	let b1_rel: Vec<(Release, Signature)> = vec![
		release(&b1.valid[0], &b1.owners[0], &x_new[4], &x, cx),
		release(&b1.valid[1], &b1.owners[1], &x_new[5], &x, cx),
		release(&b1.valid[2], &b1.owners[2], &y_new[0], &y, cy),
		release(&b1.valid[3], &b1.owners[3], &y_new[1], &y, cy),
	];
	// A wallet will not name a round other than its new leaf's, nor an
	// output that is not the connector.
	assert_eq!(Release::for_refresh(&b0.valid[0], &x_new[0], &y, cy).unwrap_err(), SpendError::NotTheRound);
	assert_eq!(Release::for_refresh(&b0.valid[0], &x_new[0], &x, 0).unwrap_err(), SpendError::Connector(0));

	// The operator issues M of X, and claims Q's forfeit with the atom.
	let mut atom_x = issue_m(&mut c, "the issuance of X's connector asset M", &x, cx, &s);
	let f = Forfeit::for_refresh(q_old, (c.net.x, LEAF), q_id, &x_new[6], &x, cx, delay(), 1_500).unwrap();
	let pair = forfeit_pair(&f, &q, &s);
	let ft = c.net.pass("Q's forfeit for X", &f.tx(q_coin.outpoint, &pair, &FeeSource::Reserve).unwrap().tx);
	let ct = c.net.pass("the claim of Q's forfeit, with the atom of M", &claim_tx(&c.net, &f, OutPoint::new(ft, 0), &atom_x, &s,
		&label32("X h 6")));
	atom_x = atom_back(&c, ct, 1, m_x);
	let atom_y = issue_m(&mut c, "the issuance of Y's connector asset M", &y, cy, &s);

	// B0: every way but the right one.
	let good = with_index(&b0_rel, &[&atom_x]);
	c.net.refuse("B0/neg without M", &reclaim(&c, &b0, &[], &good, &s), "Introspection index out of bounds");
	c.net.refuse("B0/neg with another round's M (Y's)", &reclaim(&c, &b0, &[&atom_y], &good, &s), "Invalid Schnorr signature");
	let y_coin = c.net.fund(vec![explicit(c.net.y, 1, op_true_spk())]).remove(0);
	c.net.refuse("B0/neg with another asset", &reclaim(&c, &b0, &[&y_coin], &good, &s), "Invalid Schnorr signature");
	let x_coin = c.net.fund(vec![explicit(c.net.x, 1_000, op_true_spk())]).remove(0);
	c.net.refuse("B0/neg with the batch asset at k", &reclaim(&c, &b0, &[&x_coin], &good, &s), "Invalid Schnorr signature");
	let to_node: Vec<(Vec<u8>, u32)> = good.iter().map(|(sg, _)| (sg.clone(), 0)).collect();
	c.net.refuse("B0/neg k naming the node itself", &reclaim(&c, &b0, &[&atom_x], &to_node, &s), "Invalid Schnorr signature");
	let mut three = good.clone();
	three[2].0 = vec![];
	c.net.refuse("B0/neg three releases of four", &reclaim(&c, &b0, &[&atom_x], &three, &s), "OP_CHECKSIGVERIFY");
	let lowest = b0.valid[0].branch.nodes.last().unwrap();
	let old_digest = sha256(&lowest.reclaim.as_ref().unwrap().prefix);
	let old_msg: Vec<(Vec<u8>, u32)> = b0.owners.iter().map(|o| (sig(o, &old_digest).as_ref().to_vec(), 1)).collect();
	c.net.refuse("B0/neg releases over the old message", &reclaim(&c, &b0, &[&atom_x], &old_msg, &s), "Invalid Schnorr signature");
	let mut by_stranger = good.clone();
	by_stranger[0].0 = sig(&keypair("stranger"), &b0_rel[0].0.message().digest).as_ref().to_vec();
	c.net.refuse("B0/neg one release by another key", &reclaim(&c, &b0, &[&atom_x], &by_stranger, &s), "Invalid Schnorr signature");
	c.net.refuse("B0/neg the operator's signature by another key", &reclaim(&c, &b0, &[&atom_x], &good, &keypair("stranger")),
		"Invalid Schnorr signature");

	// B0 with M of X: confirmed, the atom back to the operator.
	let rt = c.net.pass("B0/the reclaim with M", &reclaim(&c, &b0, &[&atom_x], &good, &s));
	assert!(!c.unspent(&OutPoint::new(b0.round.txid(), 0)));
	atom_x = atom_back(&c, rt, 1, m_x);

	// B1: owners of two rounds, an atom of each.
	let two = with_index(&b1_rel, &[&atom_x, &atom_y]);
	assert_eq!(two.iter().map(|(_, k)| *k).collect::<Vec<_>>(), vec![1, 1, 2, 2]);
	c.net.refuse("B1/neg Y's M missing", &reclaim(&c, &b1, &[&atom_x], &two, &s), "Introspection index out of bounds");
	let all_x: Vec<(Vec<u8>, u32)> = two.iter().map(|(sg, _)| (sg.clone(), 1)).collect();
	c.net.refuse("B1/neg every index naming X's M", &reclaim(&c, &b1, &[&atom_x, &atom_y], &all_x, &s), "Invalid Schnorr signature");
	let rt1 = c.net.pass("B1/the reclaim with M of X and M of Y", &reclaim(&c, &b1, &[&atom_x, &atom_y], &two, &s));
	atom_back(&c, rt1, 1, m_x);
	atom_back(&c, rt1, 2, m_y);
	println!("RESULT one atom of X's M served Q's claim and two reclaims; B1's owners named two rounds");
	c.net.print();
}

// ---------------------------------------------------------------------------
// 2. The round named is replaced: the releases are void
// ---------------------------------------------------------------------------

#[test]
fn a_release_is_void_with_the_round_it_names() {
	let mut c = Arca::start();
	let x_asset = c.net.x;
	let s = keypair("void operator");
	let b0 = old_batch(&mut c, &s, "V0", 4);
	let new_keys: Vec<Keypair> = (0..4).map(|i| keypair(&format!("V new key {}", i))).collect();
	let (x, cx, x_new) = new_round(&mut c, &s, "VX", &new_keys);
	let rel: Vec<(Release, Signature)> = (0..4).map(|i| {
		let r = Release::for_refresh(&b0.valid[i], &x_new[i], &x, cx).unwrap();
		let sg = sig(&b0.owners[i], &r.message().digest);
		(r, sg)
	}).collect();

	// X is disconnected and a replacement with another txid is mined in its
	// place: the same issuing coin and batch output, one atom more of fee.
	let xt = x.txid();
	c.roll_back(&xt);
	let mut y = x.clone();
	let n = y.output.len();
	let v = y.output[n - 2].value.explicit().unwrap();
	y.output[n - 2].value = elements::confidential::Value::Explicit(v - 1);
	let f = y.output[n - 1].value.explicit().unwrap();
	y.output[n - 1].value = elements::confidential::Value::Explicit(f + 1);
	c.mine_with(&[&y]);
	assert_ne!(y.txid(), xt);
	println!("round X {} disconnected; Y {} mined in its place", xt, y.txid());

	// X's M can never be issued; Y's can, and does not fit the releases.
	c.net.refuse("void/neg the issuance of X's M", &issuance_tx(&c.net, &x, cx, &s), "bad-txns-inputs-missingorspent");
	let atom_y = issue_m(&mut c, "void/the issuance of Y's M", &y, cx, &s);
	let held = with_index(&rel, &[&atom_y]);
	c.net.refuse("void/neg the reclaim with the releases and Y's M", &reclaim(&c, &b0, &[&atom_y], &held, &s),
		"Invalid Schnorr signature");
	c.net.refuse("void/neg the reclaim with the releases and no M", &reclaim(&c, &b0, &[], &held, &s),
		"Introspection index out of bounds");
	assert!(c.unspent(&OutPoint::new(b0.round.txid(), 0)), "the old node is unspent");

	// The old leaves stay their owners': owner 0 unrolls its node, takes its
	// leaf with its preimage and exits it alone.
	let auths = owner_auths(&b0.valid[0], &b0.owners[0], mt(c.net.mtp() - 60));
	let at = c.bring_leaf("void/owner 0's old leaf", &b0.valid[0], &auths, &b0.preimages[0]);
	c.net.wait_csv(&at.txid, delay());
	let et = c.net.pass("void/owner 0's exit of its old leaf", &exit_tx(&c.net, &b0.valid[0].branch.leaf, at, x_asset, LEAF, &b0.owners[0]));
	println!("RESULT the releases named X, which is gone: the operator cannot reclaim; owner 0 exited {} atoms", paid(&c.net, &et));
	c.net.print();
}

// ---------------------------------------------------------------------------
// 3. A reclaim already confirmed goes with the round it rests on
// ---------------------------------------------------------------------------

#[test]
fn a_confirmed_reclaim_goes_with_its_round() {
	let mut c = Arca::start();
	let x_asset = c.net.x;
	let s = keypair("undone operator");
	let b0 = old_batch(&mut c, &s, "U0", 4);
	let new_keys: Vec<Keypair> = (0..4).map(|i| keypair(&format!("U new key {}", i))).collect();
	let (x, cx, x_new) = new_round(&mut c, &s, "UX", &new_keys);
	let rel: Vec<(Release, Signature)> = (0..4).map(|i| {
		let r = Release::for_refresh(&b0.valid[i], &x_new[i], &x, cx).unwrap();
		let sg = sig(&b0.owners[i], &r.message().digest);
		(r, sg)
	}).collect();
	let atom = issue_m(&mut c, "undone/the issuance of X's M", &x, cx, &s);
	let reclaim_tx = reclaim(&c, &b0, &[&atom], &with_index(&rel, &[&atom]), &s);
	c.net.pass("undone/the reclaim with M", &reclaim_tx);
	let node = OutPoint::new(b0.round.txid(), 0);
	assert!(!c.unspent(&node));

	// X's block is disconnected, which takes the issuance and the reclaim
	// above it too, and a replacement with another txid is mined: the
	// reclaim cannot come back, and the node is unspent again.
	let xt = x.txid();
	c.roll_back(&xt);
	let mut y = x.clone();
	let n = y.output.len();
	let v = y.output[n - 2].value.explicit().unwrap();
	y.output[n - 2].value = elements::confidential::Value::Explicit(v - 1);
	let f = y.output[n - 1].value.explicit().unwrap();
	y.output[n - 1].value = elements::confidential::Value::Explicit(f + 1);
	c.mine_with(&[&y]);
	let mempool = c.net.rpc("getrawmempool", serde_json::json!([]));
	assert!(mempool.as_array().unwrap().is_empty(), "X, the issuance and the reclaim left the mempool: {}", mempool);
	c.net.refuse("undone/neg the reclaim again", &reclaim_tx, "bad-txns-inputs-missingorspent");
	assert!(c.unspent(&node), "the old node is unspent again");

	// Owner 2 takes its old leaf alone.
	let auths = owner_auths(&b0.valid[2], &b0.owners[2], mt(c.net.mtp() - 60));
	let at = c.bring_leaf("undone/owner 2's old leaf", &b0.valid[2], &auths, &b0.preimages[2]);
	c.net.wait_csv(&at.txid, delay());
	let et = c.net.pass("undone/owner 2's exit of its old leaf", &exit_tx(&c.net, &b0.valid[2].branch.leaf, at, x_asset, LEAF, &b0.owners[2]));
	println!("RESULT the reclaim went with round X; owner 2 exited {} atoms of its old leaf", paid(&c.net, &et));
	c.net.print();
}

// ---------------------------------------------------------------------------
// 4. A release for an offboard names the round that pays it
// ---------------------------------------------------------------------------

#[test]
fn an_offboards_release_names_the_round_that_pays_it() {
	let mut c = Arca::start();
	let x = c.net.x;
	let s = keypair("offboard release operator");
	let b = old_batch(&mut c, &s, "O0", 1);
	let dest = ExplicitOutput::new(x, LEAF - 3_000, elements::Script::from({
		let mut v = vec![0x00, 0x14];
		v.extend(&label32("O0 owner's on-chain address")[..20]);
		v
	}));
	let off = OffboardPolicy {
		unlock_hash: sha256(&label32("O0 offboard")), destination: dest, operator: xonly(&s),
		reclaim_delay: RelativeTime::from_seconds_ceil(5 * DAY).unwrap(),
	};
	// The round that pays the offboard, in the place of a batch output.
	let (issuer, sched) = c.schedule(&s);
	let (round, cv) = round_tx(&c.net, &issuer, &[], &off.output(1_000), &sched);
	c.net.pass("O0: the round paying the offboard", &round);

	let r = Release::for_offboard(&b.valid[0], &off, &round, cv).unwrap();
	assert_eq!(r.connector, connector_asset(round.txid(), cv));
	assert_eq!((r.owner, r.node_hash), (xonly(&b.owners[0]), b.valid[0].branch.nodes[0].children_hash()));
	// Refused: an offboard under another operator, a round that does not pay
	// the offboard, an output that is not the connector.
	let other = OffboardPolicy { operator: xonly(&keypair("another operator")), ..off.clone() };
	assert_eq!(Release::for_offboard(&b.valid[0], &other, &round, cv).unwrap_err(), SpendError::OtherOperator);
	let not_paying = OffboardPolicy { unlock_hash: sha256(&label32("another offboard")), ..off.clone() };
	assert!(matches!(Release::for_offboard(&b.valid[0], &not_paying, &round, cv).unwrap_err(), SpendError::Offboard(_)));
	assert_eq!(Release::for_offboard(&b.valid[0], &off, &round, 1).unwrap_err(), SpendError::Connector(1));

	// The owner's release, and the reclaim of its one-owner node with an atom
	// of that round's M; with an atom of another round's M it is refused.
	let sg = sig(&b.owners[0], &r.message().digest);
	r.verify(&sg).unwrap();
	let atom = issue_m(&mut c, "O0: the issuance of the offboard round's M", &round, cv, &s);
	let (other_round, ocv, _) = new_round(&mut c, &s, "O1", &[keypair("O1 new key")]);
	let other_atom = issue_m(&mut c, "O1: the issuance of another round's M", &other_round, ocv, &s);
	let rel = with_index(&[(r, sg)], &[&other_atom]);
	c.net.refuse("O0/neg the reclaim with another round's M", &reclaim(&c, &b, &[&other_atom], &rel, &s), "Invalid Schnorr signature");
	let rel = with_index(&[(r, sg)], &[&atom]);
	c.net.pass("O0/the reclaim of a one-owner node with the offboard round's M", &reclaim(&c, &b, &[&atom], &rel, &s));
	c.net.print();
}
