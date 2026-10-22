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
	let specs: Vec<_> = holders.iter().zip(&nonces).enumerate().map(|(i, (k, n))| tree::LeafSpec {
		template: Template::Vtxo1, owner: claim_key(&xonly(k), n).unwrap(), value: LEAF + i as u64,
		owner_nonce: *n, operator_nonce: label32(&format!("claim operator nonce {}", i)),
		exit_delay: delay(), unlock_hash: h, htlc: None,
		order: None,
		landing: None,
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
