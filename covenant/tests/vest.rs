//! vest-1 on a Sequentia regtest chain: a vesting distribution's claim
//! leaves in a batch without a sweep, which no path but the lapse spends,
//! and whose lowest nodes no RECLAIM takes back, before the vest time `V`.
//! Every negative is refused by `testmempoolaccept`, by
//! `sendrawtransaction`, and again when forced into a block with
//! `generateblock`, the block for the mempool's reason (`-par=1`).
//!
//! - The builder refuses a batch that mixes vest-1 with other leaves or
//!   with another vest time, or has a sweep, and a vest time at or after the
//!   deadline. The records are format 3, template `vest-1` (id 9), read back
//!   from both forms, and validate; a record naming another vest time does
//!   not match the round.
//! - Before `V`, with the leaf on the chain past its exit delay: the exit
//!   and the collaborative spend are refused non-final, and with lock time 0
//!   refused by the script's lock; the RECLAIM of the other lowest node,
//!   every owner's release and the operator's signature in it, is refused
//!   the same two ways.
//! - After `V`: a pair signed over the `vtxo-1` message (`K` without `V`)
//!   is refused; the exit, the collaborative spend and the RECLAIM confirm.
//!   The lapse is still refused until `D`, then the unclaimed leaf goes back
//!   to the payer's return script.
//! - A payout of 100 holders is one batch output in its round.
//!
//! Needs `SEQUENTIAD_EXEC`; `--nocapture` prints every transaction and every
//! refusal.

mod common;

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::Keypair;
use elements::{LockTime, OutPoint, Sequence, Txid};

use arca_covenant::claim::{claim_key, claim_keypair};
use arca_covenant::spend::{collab_tx, FeeSource};
use arca_covenant::*;

use common::net::*;
use common::round::*;
use common::*;

/// The leaf specs of a vesting distribution: one per holder, `vest-1` under
/// `lapse`, in X.
fn vest_specs(holders: &[Keypair], nonces: &[[u8; 32]], lapse: &Lapse, h: [u8; 32], label: &str) -> Vec<tree::LeafSpec> {
	holders.iter().zip(nonces).enumerate().map(|(i, (k, n))| tree::LeafSpec {
		claim: Some(lapse.clone()),
		template: Template::Vest1, owner: claim_key(&xonly(k), n).unwrap(), value: LEAF + i as u64,
		owner_nonce: *n, operator_nonce: label32(&format!("{} operator nonce {}", label, i)),
		exit_delay: delay(), unlock_hash: h, htlc: None, order: None, landing: None, channel: None,
	}).collect()
}

fn params(c: &Arca, schedule: ClockSchedule) -> tree::TreeParams {
	tree::TreeParams {
		asset: c.net.x, chain: c.net.chain, schedule, burn: false, delegated_reclaim: false,
		radix: 4, reserve: tree::ReserveRule::FeeRate { floor_per_kvb: c.floor_per_kvb, multiple: 4 }, min_leaf: 1,
	}
}

/// The round paying the batch of `specs`, mined: one batch output, its
/// change and fee.
fn vest_round(c: &mut Arca, s: &Keypair, specs: &[tree::LeafSpec], name: &str) -> (tree::Tree, elements::Transaction, Txid) {
	let t = tree::Tree::build(params(c, ClockSchedule::never(xonly(s))), specs).unwrap();
	let batch = t.batch_output();
	let funding = c.net.fund(vec![explicit(c.net.x, batch.value + 200_000, op_true_spk())]).remove(0);
	let total = funding.txout.value.explicit().unwrap();
	let outs = vec![batch.txout(), explicit(c.net.x, total - batch.value - 2_000, op_true_spk()), fee(c.net.x, 2_000)];
	let mut sp = spend(0).coin(&funding, 0xffff_ffff).outputs(outs);
	sp.witness(0, op_true_witness());
	let id = c.net.pass(name, &sp.tx);
	(t, sp.tx, id)
}

/// `tx` with lock time 0 and every input final.
fn unlocked(mut tx: elements::Transaction) -> elements::Transaction {
	tx.lock_time = LockTime::ZERO;
	for i in &mut tx.input {
		if i.sequence == Sequence::ENABLE_LOCKTIME_NO_RBF {
			i.sequence = Sequence::MAX;
		}
	}
	tx
}

#[test]
fn a_vest_leaf_moves_by_no_path_before_its_time() {
	let mut c = Arca::start();
	let s = keypair("vest operator");
	let x = c.net.x;
	let holders: Vec<Keypair> = (0..6).map(|i| keypair(&format!("vest holder {}", i))).collect();
	let nonces: Vec<[u8; 32]> = (0..6).map(|i| label32(&format!("vest nonce {}", i))).collect();
	let preimage = label32("vest distribution preimage");
	let h = hash(&preimage);
	let now = c.net.now();
	let vest = mt(now + 4 * DAY);
	let deadline = mt(now + 8 * DAY);
	let ret = elements::Script::from([&[0x00u8, 0x14][..], &label32("vest return")[..20]].concat());
	let lapse = Lapse { deadline, allowance: 1_500, return_script: ret.clone(), vest: Some(vest) };
	let specs = vest_specs(&holders, &nonces, &lapse, h, "vest");

	// The builder's refusals.
	let never = ClockSchedule::never(xonly(&s));
	let (_, swept) = c.schedule(&s);
	let build = |sp: &[tree::LeafSpec], sch: ClockSchedule| tree::Tree::build(params(&c, sch), sp).map(|_| ());
	let mut mixed = specs.clone();
	mixed[5] = tree::LeafSpec { claim: Some(Lapse { vest: None, ..lapse.clone() }), template: Template::Claim1, ..mixed[5].clone() };
	assert!(matches!(build(&mixed, never.clone()), Err(tree::TreeError::VestBatch)), "vest-1 beside claim-1");
	let mut plain = specs.clone();
	plain[5] = tree::LeafSpec { claim: None, template: Template::Vtxo1, ..plain[5].clone() };
	assert!(matches!(build(&plain, never.clone()), Err(tree::TreeError::VestBatch)), "vest-1 beside vtxo-1");
	let mut two = specs.clone();
	two[5].claim = Some(Lapse { vest: Some(mt(now + 4 * DAY + 1)), ..lapse.clone() });
	assert!(matches!(build(&two, never.clone()), Err(tree::TreeError::VestBatch)), "two vest times");
	assert!(matches!(build(&specs, swept), Err(tree::TreeError::VestBatch)), "a batch with a sweep");
	let mut late = specs.clone();
	for l in &mut late {
		l.claim = Some(Lapse { vest: Some(deadline), ..lapse.clone() });
	}
	assert!(matches!(build(&late, never.clone()), Err(tree::TreeError::Template { leaf: 0 })), "V at D");
	let mut wrong = specs.clone();
	wrong[0].template = Template::Claim1;
	assert!(build(&wrong, never.clone()).is_err(), "claim-1 named with a vest time");

	// The round, and the records.
	let (t, round, _) = vest_round(&mut c, &s, &specs, "vest/the round, a batch without a sweep");
	let strict = WalletPolicy::no_sweep(c.net.chain, xonly(&s), mt(c.net.mtp()));
	let mut valid = vec![];
	for (i, (k, n)) in holders.iter().zip(&nonces).enumerate() {
		let rec = t.record(i);
		assert_eq!(rec.template, Template::Vest1);
		let bytes = rec.to_bytes().unwrap();
		assert_eq!(bytes[0], record::RECORD_VERSION_NO_SWEEP);
		assert_eq!((bytes[1], bytes[2]), (Template::VEST, 1));
		assert_eq!(LeafRecord::from_bytes(&bytes).unwrap(), rec);
		assert_eq!(LeafRecord::from_json_str(&rec.to_json_string().unwrap()).unwrap(), rec);
		let owner = claim_key(&xonly(k), n).unwrap();
		let v = rec.validate(&round, &strict, &owner, n).unwrap();
		assert_eq!(v.branch.leaf.template(), Template::Vest1);
		assert_eq!(v.branch.leaf.vest(), Some(vest));
		assert_eq!(v.branch.nodes.last().unwrap().reclaim.as_ref().unwrap().lock, Some(vest));
		// A record that names another vest time names other scripts.
		let mut other = rec.clone();
		other.claim = Some(Lapse { vest: Some(mt(now + 4 * DAY + 60)), ..lapse.clone() });
		assert!(other.validate(&round, &strict, &owner, n).is_err(), "holder {}: another vest time matches the round", i);
		valid.push(v);
	}
	assert_eq!(valid[0].branch.nodes.len(), 2, "six leaves at radix 4: two lowest nodes of three under the batch output");

	// Holder 0's leaf on the chain: the batch output, its lowest node, the
	// entry. The batch output's unroll also puts the other lowest node (holders
	// 3 to 5) on the chain.
	let claims: Vec<Keypair> = holders.iter().zip(&nonces).map(|(k, n)| claim_keypair(k, n).unwrap()).collect();
	let tm = mt(c.net.mtp() - 60);
	let txs = valid[0].branch.unroll(OutPoint::new(valid[0].round_txid, valid[0].batch_vout), &owner_auths(&valid[0], &claims[0], tm),
		&[FeeSource::Reserve, FeeSource::Reserve]).unwrap();
	let root_id = c.net.pass("vest/unroll, the batch output", &txs[0].tx);
	c.net.pass("vest/unroll, holder 0's lowest node", &txs[1].tx);
	let e0 = valid[0].branch.entry_tx(valid[0].branch.entry_outpoint(&txs).unwrap(), &preimage, &FeeSource::Reserve).unwrap();
	let at0 = OutPoint::new(c.net.pass("vest/holder 0: entry into the leaf", &e0.tx), 0);
	c.net.wait_csv(&at0.txid, delay());
	assert!(c.net.mtp() < vest.to_consensus_u32() as u64, "the exit delay has run and the leaf has not vested");

	// Before V: the exit.
	let leaf0 = valid[0].branch.leaf.clone();
	let v0 = specs[0].value;
	let exit0 = exit_tx(&c.net, &leaf0, at0, x, v0, &claims[0]);
	assert_eq!(exit0.lock_time, LockTime::from_consensus(vest.to_consensus_u32()), "the exit carries V");
	c.net.refuse("vest/neg the exit before V", &exit0, "non-final");
	let mut ks = leaf0.exit_tx(at0, x, v0, &[ExplicitOutput::new(x, v0 - 1_500, op_true_spk())], &FeeSource::Reserve).unwrap();
	ks.tx.lock_time = LockTime::ZERO;
	c.net.refuse("vest/neg the exit before V, lock time 0", &signed(&c.net, ks, &claims[0], vec![]).tx,
		"Locktime requirement not satisfied");

	// Before V: the collaborative path, signed by owner and operator.
	let out = [ExplicitOutput::new(x, v0 - MARGIN, op_true_spk())];
	let d = leaf0.collab_message(x, v0, &out).unwrap().digest;
	let pair = Pair { operator: sig(&s, &d), owner: sig(&claims[0], &d) };
	let co = collab_tx(&leaf0, at0, x, v0, &out, &pair, &FeeSource::Reserve).unwrap().tx;
	assert_eq!(co.lock_time, LockTime::from_consensus(vest.to_consensus_u32()), "the collaborative spend carries V");
	c.net.refuse("vest/neg the collaborative spend before V", &co, "non-final");
	c.net.refuse("vest/neg the collaborative spend before V, lock time 0", &unlocked(co.clone()), "Locktime requirement not satisfied");

	// Before V: RECLAIM of the other lowest node, every owner's release in it.
	let node_b = OutPoint::new(root_id, 1);
	let lowest_b = valid[3].branch.nodes.last().unwrap().clone();
	assert_eq!(lowest_b.reclaim.as_ref().unwrap().owners, vec![xonly(&claims[3]), xonly(&claims[4]), xonly(&claims[5])]);
	let m = c.net.fee_coin();
	let m_asset = m.txout.asset.explicit().unwrap();
	let release = lowest_b.reclaim.as_ref().unwrap().release_message(m_asset).digest;
	let releases: Vec<(Signature, u32)> = (3..6).map(|i| (sig(&claims[i], &release), 1)).collect();
	let reclaim = |c: &Arca| {
		let ks = lowest_b.reclaim_tx(node_b, &[(m.outpoint, m.txout.clone())],
			&[ExplicitOutput::new(x, lowest_b.value - 2_000, op_true_spk())], op_true_spk(), &FeeSource::Reserve).unwrap();
		let op = sig(&s, &ks.sighash(c.net.genesis).unwrap());
		let mut u = ks.finish(node::reclaim_items(&op, &releases, 3).unwrap());
		u.tx.input[1].witness.script_witness = op_true_witness();
		u.tx
	};
	let rc = reclaim(&c);
	assert_eq!(rc.lock_time, LockTime::from_consensus(vest.to_consensus_u32()), "the reclaim carries V");
	c.net.refuse("vest/neg RECLAIM of a lowest node before V", &rc, "non-final");
	let rc0 = {
		let ks = lowest_b.reclaim_tx(node_b, &[(m.outpoint, m.txout.clone())],
			&[ExplicitOutput::new(x, lowest_b.value - 2_000, op_true_spk())], op_true_spk(), &FeeSource::Reserve).unwrap();
		let mut ks = ks;
		ks.tx = unlocked(ks.tx);
		let op = sig(&s, &ks.sighash(c.net.genesis).unwrap());
		let mut u = ks.finish(node::reclaim_items(&op, &releases, 3).unwrap());
		u.tx.input[1].witness.script_witness = op_true_witness();
		u.tx
	};
	c.net.refuse("vest/neg RECLAIM of a lowest node before V, lock time 0", &rc0, "Locktime requirement not satisfied");

	// After V.
	c.net.mtp_past(vest.to_consensus_u32() as u64);
	assert!(c.net.mtp() < deadline.to_consensus_u32() as u64);
	let unvested = LeafPolicy { claim: leaf0.claim.map(|t| LapseTerms { vest: None, ..t }), ..leaf0.clone() };
	let d_plain = unvested.collab_message(x, v0, &out).unwrap().digest;
	assert_ne!(d_plain, d, "the message names V");
	let plain_pair = Pair { operator: sig(&s, &d_plain), owner: sig(&claims[0], &d_plain) };
	c.net.refuse("vest/neg a pair over the vtxo-1 message (K without V), after V",
		&collab_tx(&leaf0, at0, x, v0, &out, &plain_pair, &FeeSource::Reserve).unwrap().tx, "Invalid Schnorr signature");
	c.net.pass("vest/holder 0's exit after V", &exit0);

	// Holder 1 takes its claim up after V: the collaborative spend, its
	// first step, confirms.
	let txs1 = valid[1].branch.unroll(OutPoint::new(valid[1].round_txid, valid[1].batch_vout), &owner_auths(&valid[1], &claims[1], tm),
		&[FeeSource::Reserve, FeeSource::Reserve]).unwrap();
	let e1 = valid[1].branch.entry_tx(valid[1].branch.entry_outpoint(&txs1).unwrap(), &preimage, &FeeSource::Reserve).unwrap();
	let at1 = OutPoint::new(c.net.pass("vest/holder 1: entry into the leaf", &e1.tx), 0);
	let leaf1 = &valid[1].branch.leaf;
	let v1 = specs[1].value;
	let out1 = [ExplicitOutput::new(x, v1 - MARGIN, op_true_spk())];
	let d1 = leaf1.collab_message(x, v1, &out1).unwrap().digest;
	let pair1 = Pair { operator: sig(&s, &d1), owner: sig(&claims[1], &d1) };
	c.net.pass("vest/holder 1's collaborative spend after V", &collab_tx(leaf1, at1, x, v1, &out1, &pair1, &FeeSource::Reserve).unwrap().tx);
	c.net.pass("vest/RECLAIM of the other lowest node after V", &rc);

	// Holder 2 never takes its claim up: its leaf lapses after D, not
	// before.
	let txs2 = valid[2].branch.unroll(OutPoint::new(valid[2].round_txid, valid[2].batch_vout), &owner_auths(&valid[2], &claims[2], tm),
		&[FeeSource::Reserve, FeeSource::Reserve]).unwrap();
	let e2 = valid[2].branch.entry_tx(valid[2].branch.entry_outpoint(&txs2).unwrap(), &preimage, &FeeSource::Reserve).unwrap();
	let at2 = OutPoint::new(c.net.pass("vest/holder 2: entry into the leaf", &e2.tx), 0);
	c.net.wait_csv(&at2.txid, delay());
	let v2 = specs[2].value;
	let split = FeeSource::Split { fee: 500, change: op_true_spk() };
	let lapse2 = valid[2].branch.leaf.lapse_tx(at2, v2, &ret, &split).unwrap().tx;
	assert!(c.net.mtp() < deadline.to_consensus_u32() as u64, "vested, not yet at the deadline");
	c.net.refuse("vest/neg the lapse after V, before D", &lapse2, "non-final");
	c.net.mtp_past(deadline.to_consensus_u32() as u64);
	let id = c.net.pass("vest/holder 2's unclaimed leaf lapses to the payer after D", &lapse2);
	assert_eq!(paid(&c.net, &id), v2 - 500);
	c.net.print();
}

/// One output pays a hundred holders: the round of a vesting distribution
/// carries one batch output whatever the number of holders, and each
/// holder's leaf validates from its record. A holder who leaves on the chain
/// alone pays its own path.
#[test]
fn a_payout_of_a_hundred_holders_is_one_output() {
	let mut c = Arca::start();
	let s = keypair("vest100 operator");
	let n = 100;
	let holders: Vec<Keypair> = (0..n).map(|i| keypair(&format!("vest100 holder {}", i))).collect();
	let nonces: Vec<[u8; 32]> = (0..n).map(|i| label32(&format!("vest100 nonce {}", i))).collect();
	let preimage = label32("vest100 preimage");
	let now = c.net.now();
	let vest = mt(now + 2 * DAY);
	let ret = elements::Script::from([&[0x00u8, 0x14][..], &label32("vest100 return")[..20]].concat());
	let lapse = Lapse { deadline: mt(now + 30 * DAY), allowance: 1_500, return_script: ret, vest: Some(vest) };
	let specs = vest_specs(&holders, &nonces, &lapse, hash(&preimage), "vest100");
	let (t, round, _) = vest_round(&mut c, &s, &specs, "vest100/the round paying 100 holders");
	let batch_spk = t.batch_output().script_pubkey;
	assert_eq!(round.output.iter().filter(|o| o.script_pubkey == batch_spk).count(), 1, "one batch output");
	assert_eq!(round.output.len(), 3, "the batch output, change and fee");
	let strict = WalletPolicy::no_sweep(c.net.chain, xonly(&s), mt(c.net.mtp()));
	let mut levels = 0;
	for (i, (k, nn)) in holders.iter().zip(&nonces).enumerate() {
		let v = t.record(i).validate(&round, &strict, &claim_key(&xonly(k), nn).unwrap(), nn).unwrap();
		levels = v.branch.nodes.len();
	}
	println!("vest100: 100 records validate; {} levels from the batch output to a leaf", levels);

	// Holder 99 leaves alone after V: its path, its entry, its exit.
	let claim = claim_keypair(&holders[99], &nonces[99]).unwrap();
	let v = t.record(99).validate(&round, &strict, &claim_key(&xonly(&holders[99]), &nonces[99]).unwrap(), &nonces[99]).unwrap();
	let at = c.bring_leaf("vest100/holder 99", &v, &owner_auths(&v, &claim, mt(c.net.mtp() - 60)), &preimage);
	c.net.wait_csv(&at.txid, delay());
	c.net.mtp_past(vest.to_consensus_u32() as u64);
	c.net.pass("vest100/holder 99's exit after V", &exit_tx(&c.net, &v.branch.leaf, at, c.net.x, specs[99].value, &claim));
	c.net.print();
}
