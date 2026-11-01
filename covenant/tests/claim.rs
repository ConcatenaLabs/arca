//! A claim tree on a Sequentia regtest chain: four holders named by address
//! keys (two of each parity), each owning its leaf under the claim key the
//! payer's nonce derives, in one batch. Every negative is refused by
//! `testmempoolaccept`, by `sendrawtransaction`, and again when forced into a
//! block with `generateblock`, the block for the mempool's reason (the node
//! checks scripts inline, `-par=1`).
//!
//! - The records validate for each holder's claim key and nonce, and not for
//!   the named key itself.
//! - The batch output's unroll, authorised by the named key standing in for
//!   the claim key, or by the payer's key, is refused; authorised by the claim
//!   key it confirms, and the leaf comes on the chain by its entry.
//! - The leaf's exit signed by the named key, or by the payer's key, is
//!   refused; signed by the claim key it confirms.
//! - The leaf's collaborative path (a take-up's first step) signed by the
//!   named key with the operator's signature is refused; by the claim key it
//!   confirms.
//!
//! Needs `SEQUENTIAD_EXEC`; `--nocapture` prints every transaction and every
//! refusal.

mod common;

use elements::secp256k1_zkp::{Keypair, Parity};
use elements::OutPoint;

use arca_covenant::claim::{claim_key, claim_keypair};
use arca_covenant::spend::{collab_tx, FeeSource};
use arca_covenant::*;

use common::net::*;
use common::round::*;
use common::*;

/// A key pair whose own point has `parity`, as an on-chain address key may.
fn address_key(label: &str, parity: Parity) -> Keypair {
	(0..).map(|i| keypair(&format!("{} {}", label, i))).find(|k| k.x_only_public_key().1 == parity).unwrap()
}

#[test]
fn a_claim_leaf_is_spent_by_its_claim_key_and_by_no_other() {
	let mut c = Arca::start();
	let s = keypair("claim operator");
	let payer = keypair("claim payer");
	let x = c.net.x;
	let holders: Vec<Keypair> = (0..4).map(|i| address_key(&format!("claim holder {}", i), if i % 2 == 0 { Parity::Odd } else { Parity::Even }))
		.collect();
	let nonces: Vec<[u8; 32]> = (0..4).map(|i| label32(&format!("claim nonce {}", i))).collect();
	let preimage = label32("claim distribution preimage");
	let h = hash(&preimage);

	// The tree: one leaf per holder, under the claim key of its named key and
	// the payer's nonce, the nonce its owner nonce.
	let (issuer, sched) = c.schedule(&s);
	let specs: Vec<_> = holders.iter().zip(&nonces).enumerate().map(|(i, (k, n))| tree::LeafSpec { claim: None,
		template: Template::Vtxo1, owner: claim_key(&xonly(k), n).unwrap(), value: LEAF + i as u64,
		owner_nonce: *n, operator_nonce: label32(&format!("claim operator nonce {}", i)),
		exit_delay: delay(), unlock_hash: h, htlc: None,
		order: None,
		landing: None,
		channel: None,
	}).collect();
	let t = c.tree(&sched, &specs);
	let (round, _) = round_tx(&c.net, &issuer, &[], &t.batch_output(), &sched);
	c.net.pass("claim/the round", &round);
	let policy = c.policy(&s);
	let mut valid = vec![];
	for (i, (k, n)) in holders.iter().zip(&nonces).enumerate() {
		let record = t.record(i);
		let owner = claim_key(&xonly(k), n).unwrap();
		assert_ne!(owner, xonly(k));
		assert!(record.validate(&round, &policy, &xonly(k), n).is_err(), "holder {}: the named key is not the leaf's owner", i);
		valid.push(record.validate(&round, &policy, &owner, n).unwrap());
	}

	// Holder 0 brings its leaf on the chain: the batch output first.
	let claim0 = claim_keypair(&holders[0], &nonces[0]).unwrap();
	let tm = mt(c.net.mtp() - 60);
	let batch = OutPoint::new(valid[0].round_txid, valid[0].batch_vout);
	let unroll_by = |by: &Keypair, member: elements::secp256k1_zkp::XOnlyPublicKey| {
		let auths: Vec<UnrollAuth> = valid[0].branch.nodes.iter()
			.map(|n| n.owner_auth(sig(by, &n.unroll_authorisation(tm).digest), tm, member)).collect();
		valid[0].branch.unroll(batch, &auths, &vec![FeeSource::Reserve; auths.len()]).unwrap().remove(0).tx
	};
	c.net.refuse("claim/neg the unroll authorised by the named key for the claim key", &unroll_by(&holders[0], xonly(&claim0)),
		"Invalid Schnorr signature");
	c.net.refuse("claim/neg the unroll authorised by the named key as a member", &unroll_by(&holders[0], xonly(&holders[0])),
		"Script failed an OP_EQUALVERIFY operation");
	c.net.refuse("claim/neg the unroll authorised by the payer's key", &unroll_by(&payer, xonly(&payer)),
		"Script failed an OP_EQUALVERIFY operation");
	let auths = owner_auths(&valid[0], &claim0, tm);
	let at = c.bring_leaf("claim/holder 0", &valid[0], &auths, &preimage);
	c.net.wait_csv(&at.txid, delay());

	// Its exit: by the named key, by the payer's, then by the claim key.
	let leaf0 = &valid[0].branch.leaf;
	let value0 = specs[0].value;
	c.net.refuse("claim/neg the exit signed by the named key", &exit_tx(&c.net, leaf0, at, x, value0, &holders[0]), "Invalid Schnorr signature");
	c.net.refuse("claim/neg the exit signed by the payer's key", &exit_tx(&c.net, leaf0, at, x, value0, &payer), "Invalid Schnorr signature");
	c.net.pass("claim/holder 0's exit signed by its claim key", &exit_tx(&c.net, leaf0, at, x, value0, &claim0));

	// Holder 1's leaf on the chain by its entry (the batch output, their
	// lowest node, is unrolled already), then spent by its collaborative
	// path, as a take-up's first step spends it.
	let claim1 = claim_keypair(&holders[1], &nonces[1]).unwrap();
	let auths1 = owner_auths(&valid[1], &claim1, tm);
	let txs1 = valid[1].branch.unroll(batch, &auths1, &vec![FeeSource::Reserve; auths1.len()]).unwrap();
	assert_eq!(txs1.len(), 1, "four leaves: the batch output is their lowest node, unrolled already with holder 0's path");
	let e = valid[1].branch.entry_tx(valid[1].branch.entry_outpoint(&txs1).unwrap(), &preimage, &FeeSource::Reserve).unwrap();
	let at1 = OutPoint::new(c.net.pass("claim/holder 1: entry into the leaf", &e.tx), 0);
	let leaf1 = &valid[1].branch.leaf;
	let value1 = specs[1].value;
	let out = [ExplicitOutput::new(x, value1 - MARGIN, op_true_spk())];
	let d = leaf1.collab_message(x, value1, &out).unwrap().digest;
	let by_named = Pair { operator: sig(&s, &d), owner: sig(&holders[1], &d) };
	let neg = collab_tx(leaf1, at1, x, value1, &out, &by_named, &FeeSource::Reserve).unwrap();
	c.net.refuse("claim/neg the collaborative path signed by the named key", &neg.tx, "Invalid Schnorr signature");
	let by_payer = Pair { operator: sig(&s, &d), owner: sig(&payer, &d) };
	let neg = collab_tx(leaf1, at1, x, value1, &out, &by_payer, &FeeSource::Reserve).unwrap();
	c.net.refuse("claim/neg the collaborative path signed by the payer's key", &neg.tx, "Invalid Schnorr signature");
	let by_claim = Pair { operator: sig(&s, &d), owner: sig(&claim1, &d) };
	let pos = collab_tx(leaf1, at1, x, value1, &out, &by_claim, &FeeSource::Reserve).unwrap();
	c.net.pass("claim/holder 1's collaborative spend signed by its claim key", &pos.tx);
	c.net.print();
}

/// A batch without a sweep of claim-1 leaves, its round built and mined.
fn claim_batch(c: &mut Arca, s: &Keypair, specs: &[tree::LeafSpec]) -> (tree::Tree, elements::Transaction) {
	let t = tree::Tree::build(tree::TreeParams {
		asset: c.net.x, chain: c.net.chain, schedule: ClockSchedule::never(xonly(s)), burn: false, delegated_reclaim: false,
		radix: 4, reserve: tree::ReserveRule::FeeRate { floor_per_kvb: c.floor_per_kvb, multiple: 4 }, min_leaf: 1,
	}, specs).unwrap();
	let batch = t.batch_output();
	let funding = c.net.fund(vec![explicit(c.net.x, batch.value + 200_000, op_true_spk())]).remove(0);
	let total = funding.txout.value.explicit().unwrap();
	let outs = vec![batch.txout(), explicit(c.net.x, total - batch.value - 2_000, op_true_spk()), fee(c.net.x, 2_000)];
	let mut sp = spend(0).coin(&funding, 0xffff_ffff).outputs(outs);
	sp.witness(0, op_true_witness());
	c.net.pass("lapse/the round, a batch without a sweep", &sp.tx);
	(t, sp.tx)
}

/// claim-1 on a Sequentia regtest chain: a distribution's claim leaves in a
/// batch without a sweep, which lapse to the payer's return script once the
/// deadline has passed and the leaf has waited its exit delay. Every negative
/// is refused by the mempool and again in a block, for the same reason.
///
/// - The record is format 3, template `claim-1`, and reads back from both
///   forms; the holder's wallet validates it under the claim key and the
///   strict no-sweep policy, and its coin record names the lapse.
/// - Brought on the chain before the deadline, the leaf's lapse is refused
///   (non-final) and the holder's exit confirms.
/// - After the deadline: the lapse to another script and one atom short of
///   the value less the allowance are refused; the lapse the policy builds,
///   its fee from the allowance, confirms.
/// - Brought on the chain after the deadline, the lapse is refused until the
///   exit delay has run, then confirms with a fee coin, the whole value to the
///   return script.
#[test]
fn a_claim_leaf_lapses_to_its_payer_after_the_deadline() {
	let mut c = Arca::start();
	let s = keypair("lapse operator");
	let x = c.net.x;
	let holders: Vec<Keypair> = (0..3).map(|i| keypair(&format!("lapse holder {}", i))).collect();
	let nonces: Vec<[u8; 32]> = (0..3).map(|i| label32(&format!("lapse nonce {}", i))).collect();
	let preimage = label32("lapse distribution preimage");
	let h = hash(&preimage);
	let deadline = mt(c.net.mtp() + 3 * DAY);
	let ret = elements::Script::from([&[0x00u8, 0x14][..], &label32("lapse return")[..20]].concat());
	let lapse = Lapse { deadline, allowance: 1_500, return_script: ret.clone(), vest: None };
	let specs: Vec<tree::LeafSpec> = holders.iter().zip(&nonces).enumerate().map(|(i, (k, n))| tree::LeafSpec {
		claim: Some(lapse.clone()),
		template: Template::Claim1, owner: claim_key(&xonly(k), n).unwrap(), value: LEAF + i as u64,
		owner_nonce: *n, operator_nonce: label32(&format!("lapse operator nonce {}", i)),
		exit_delay: delay(), unlock_hash: h, htlc: None, order: None, landing: None, channel: None,
	}).collect();
	let (t, round) = claim_batch(&mut c, &s, &specs);

	// The records.
	let strict = WalletPolicy::no_sweep(c.net.chain, xonly(&s), mt(c.net.mtp()));
	let mut valid = vec![];
	for (i, (k, n)) in holders.iter().zip(&nonces).enumerate() {
		let rec = t.record(i);
		assert_eq!(rec.template, Template::Claim1);
		let bytes = rec.to_bytes().unwrap();
		assert_eq!(bytes[0], record::RECORD_VERSION_NO_SWEEP);
		assert_eq!((bytes[1], bytes[2]), (Template::CLAIM, 1));
		assert_eq!(LeafRecord::from_bytes(&bytes).unwrap(), rec);
		assert_eq!(LeafRecord::from_json_str(&rec.to_json_string().unwrap()).unwrap(), rec);
		let v = rec.validate(&round, &strict, &claim_key(&xonly(k), n).unwrap(), n).unwrap();
		assert_eq!(v.branch.leaf.template(), Template::Claim1);
		let coin = CoinRecord::Leaf { record: rec, preimage, auths: vec![] };
		assert_eq!(coin.lapse(), Some(&lapse));
		valid.push(v);
	}
	let tm = mt(c.net.mtp() - 60);
	let lapse_of = |v: &ValidLeaf, at: OutPoint, value: u64, fee: &FeeSource| v.branch.leaf.lapse_tx(at, value, &ret, fee).unwrap().tx;
	let split = |f: u64| FeeSource::Split { fee: f, change: op_true_spk() };

	// Holder 0, before the deadline: the lapse is refused, its exit confirms.
	let claim0 = claim_keypair(&holders[0], &nonces[0]).unwrap();
	let at0 = c.bring_leaf("lapse/holder 0", &valid[0], &owner_auths(&valid[0], &claim0, tm), &preimage);
	c.net.wait_csv(&at0.txid, delay());
	assert!(c.net.mtp() < deadline.to_consensus_u32() as u64);
	c.net.refuse("lapse/neg the lapse before the deadline", &lapse_of(&valid[0], at0, specs[0].value, &split(500)), "non-final");
	c.net.pass("lapse/holder 0's exit before the deadline", &exit_tx(&c.net, &valid[0].branch.leaf, at0, x, specs[0].value, &claim0));

	// Holder 1's leaf, on the chain before the deadline, lapsed after it.
	let claim1 = claim_keypair(&holders[1], &nonces[1]).unwrap();
	let auths1 = owner_auths(&valid[1], &claim1, tm);
	let txs1 = valid[1].branch.unroll(OutPoint::new(valid[1].round_txid, valid[1].batch_vout), &auths1,
		&vec![FeeSource::Reserve; auths1.len()]).unwrap();
	let e1 = valid[1].branch.entry_tx(valid[1].branch.entry_outpoint(&txs1).unwrap(), &preimage, &FeeSource::Reserve).unwrap();
	let at1 = OutPoint::new(c.net.pass("lapse/holder 1: entry into the leaf", &e1.tx), 0);
	c.net.mtp_past(deadline.to_consensus_u32() as u64);
	c.net.wait_csv(&at1.txid, delay());
	let v1 = specs[1].value;
	let mut other = lapse_of(&valid[1], at1, v1, &split(500));
	other.output[0].script_pubkey = op_true_spk();
	c.net.refuse("lapse/neg the lapse to another script", &other, "Script failed an OP_EQUALVERIFY operation");
	let mut short = lapse_of(&valid[1], at1, v1, &split(1_500));
	short.output[0].value = elements::confidential::Value::Explicit(v1 - 1_500 - 1);
	let f = short.output.iter().position(|o| o.is_fee()).unwrap();
	short.output[f].value = elements::confidential::Value::Explicit(1_501);
	c.net.refuse("lapse/neg the lapse one atom below the value less the allowance", &short,
		"Script evaluated without error but finished with a false/empty top stack element");
	assert!(valid[1].branch.leaf.lapse_tx(at1, v1, &ret, &split(1_501)).is_err(), "the policy builds no lapse past its allowance");
	assert!(valid[1].branch.leaf.lapse_tx(at1, v1, &op_true_spk(), &split(500)).is_err(), "nor one to another script");
	let whole = lapse_of(&valid[1], at1, v1, &FeeSource::Reserve);
	assert_eq!(whole.output[0].value.explicit(), Some(v1 - 1_500), "with the reserve, the whole allowance is the fee");
	assert_eq!(arca_covenant::claim::lapse_allowance(Some(1_000), 4), 880);
	assert_eq!(arca_covenant::claim::lapse_allowance(None, 4), 0);
	c.net.pass("lapse/holder 1's leaf lapsed after the deadline, the fee from the allowance",
		&lapse_of(&valid[1], at1, v1, &split(500)));

	// Holder 2's leaf, brought on the chain after the deadline: the lapse
	// waits its exit delay, then a fee coin pays and the return gets it all.
	let claim2 = claim_keypair(&holders[2], &nonces[2]).unwrap();
	let auths2 = owner_auths(&valid[2], &claim2, tm);
	let txs2 = valid[2].branch.unroll(OutPoint::new(valid[2].round_txid, valid[2].batch_vout), &auths2,
		&vec![FeeSource::Reserve; auths2.len()]).unwrap();
	let e2 = valid[2].branch.entry_tx(valid[2].branch.entry_outpoint(&txs2).unwrap(), &preimage, &FeeSource::Reserve).unwrap();
	let at2 = OutPoint::new(c.net.pass("lapse/holder 2: entry into the leaf, after the deadline", &e2.tx), 0);
	let v2 = specs[2].value;
	c.net.refuse("lapse/neg the lapse of a leaf confirmed after the deadline, at once", &lapse_of(&valid[2], at2, v2, &split(500)),
		"non-BIP68-final");
	c.net.wait_csv(&at2.txid, delay());
	let fc = c.net.fee_coin();
	let mut tx = lapse_of(&valid[2], at2, v2, &FeeSource::Coin { outpoint: fc.outpoint, coin: fc.txout.clone(), fee: 1_000,
		change: op_true_spk() });
	assert_eq!(tx.output[0].value.explicit(), Some(v2), "with a fee coin the return gets the whole value");
	tx.input[1].witness.script_witness = op_true_witness();
	c.net.pass("lapse/holder 2's leaf lapsed with a fee coin of another asset", &tx);
	c.net.print();
}
