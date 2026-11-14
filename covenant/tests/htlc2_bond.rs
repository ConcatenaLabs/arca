//! The bond's reader of an `htlc-2` lock's endings together: what the
//! operator signed is read back from CLAIM-C (with the preimage among its
//! witness items) and from REFUND-C, each with or without an annex, and
//! verifies under the operator's key; a claim pair and a refund pair over
//! different outputs are evidence the bond takes, over the same outputs one
//! message and one outcome; shapes that are no such ending read as nothing.

mod common;

use arca_consensus::Verifier;
use arca_covenant::bond::{self, BondError, Evidence, Form, Signed};
use arca_covenant::script::sha256;
use arca_covenant::*;
use common::*;
use elements::hashes::Hash;
use elements::BlockHash;

#[test]
fn the_bond_reads_both_endings_of_a_lock_together() {
	let genesis = BlockHash::from_byte_array(label32("htlc2 bond genesis"));
	let chain = Chain::new(genesis);
	let (q, s, p, w) = (keypair("htlc2 bond Q"), keypair("htlc2 bond S"), keypair("htlc2 bond P"), keypair("htlc2 bond W"));
	let timeout = MedianTime::from_consensus(1_800_000_000).unwrap();
	let preimage = label32("htlc2 bond preimage");
	let lock = LockPolicy {
		owner: xonly(&q), operator: xonly(&s), salt: label32("htlc2 bond lock"), chain,
		exit_delay: RelativeTime::from_units(254).unwrap(),
		terms: LockTerms { payment_hash: sha256(&preimage), timeout, refunder: xonly(&p), refund_delay: RelativeTime::from_units(127).unwrap() },
	};
	lock.check().unwrap();
	assert_eq!(LockPolicy { operator: xonly(&q), ..lock }.check(), Err(LockError::SharedKey));
	assert_eq!(LockPolicy { owner: xonly(&p), ..lock }.check(), Err(LockError::SharedKey));
	assert_eq!(LockPolicy { terms: LockTerms { refunder: xonly(&s), ..lock.terms }, ..lock }.check(), Err(LockError::SharedKey));

	let x = asset("htlc2 bond X");
	let value = 10_000_000;
	let to_q = ExplicitOutput::new(x, value - 600, op_true().script_pubkey());
	let to_p = ExplicitOutput::new(x, value - 601, op_true().script_pubkey());
	let bond_policy = BondPolicy::new(chain, xonly(&s), xonly(&w), RelativeTime::from_units(10).unwrap()).unwrap();
	let both = |claim_out: &ExplicitOutput, refund_out: &ExplicitOutput| {
		let mc = lock.collab_message(x, value, std::slice::from_ref(claim_out)).unwrap();
		let mr = lock.collab_message(x, value, std::slice::from_ref(refund_out)).unwrap();
		let mut claim = Spend::new(0).fake_input("htlc2 bond lock", explicit(x, value, lock.script_pubkey()), 0xffff_ffff)
			.outputs(vec![claim_out.txout(), fee(x, value - claim_out.value)]);
		claim.witness(0, lock.claim_together_witness(&sig(&s, &mc.digest), &sig(&q, &mc.digest), 1, &preimage));
		let mut refund = Spend::new(timeout.to_consensus_u32())
			.fake_input("htlc2 bond lock", explicit(x, value, lock.script_pubkey()), 0xffff_fffe)
			.outputs(vec![refund_out.txout(), fee(x, value - refund_out.value)]);
		refund.witness(0, lock.refund_together_witness(&sig(&s, &mr.digest), &sig(&p, &mr.digest), 1));
		for spend in [&claim, &refund] {
			Verifier::consensus(genesis).verify_tx(&spend.prevouts, &spend.tx).unwrap();
			Verifier::standard(genesis).verify_tx(&spend.prevouts, &spend.tx).unwrap();
		}
		(claim, refund, mc, mr)
	};
	let read = |u: &Spend| bond::rebind_signed_in(&chain, &lock.salt, &u.tx, 0, &u.prevouts[0]);

	// Different outputs: two messages under one salt, both read from the
	// chain's form of each ending, evidence the bond takes.
	let (claim, refund, mc, mr) = both(&to_q, &to_p);
	let rc = read(&claim).expect("CLAIM-C is read");
	let rr = read(&refund).expect("REFUND-C is read");
	assert_eq!(rc, Signed { form: Form::Rebind, rest: bond::rebind_rest(&mc.preimage).unwrap(), signature: sig(&s, &mc.digest) });
	assert_eq!(rr, Signed { form: Form::Rebind, rest: bond::rebind_rest(&mr.preimage).unwrap(), signature: sig(&s, &mr.digest) });
	assert!(bond_policy.verify(&lock.salt, &rc) && bond_policy.verify(&lock.salt, &rr));
	assert_eq!(bond_policy.check(&Evidence { salt: lock.salt, a: rc.clone(), b: rr.clone() }), Ok(()));
	println!("CLAIM-C and REFUND-C over different outputs: both read, evidence taken");

	// An annex changes nothing the operator signed.
	for (u, signed) in [(&claim, &rc), (&refund, &rr)] {
		let mut annexed = u.clone();
		annexed.tx.input[0].witness.script_witness.push(vec![0x50, 1, 2]);
		assert_eq!(read(&annexed).as_ref(), Some(signed));
	}

	// The same outputs: one message, one outcome, nothing to slash.
	let (same_claim, same_refund, m1, m2) = both(&to_q, &to_q);
	assert_eq!(m1.digest, m2.digest);
	let (a, b) = (read(&same_claim).unwrap(), read(&same_refund).unwrap());
	assert_eq!(a, b);
	assert_eq!(bond_policy.check(&Evidence { salt: lock.salt, a, b }), Err(BondError::SameDigest));
	println!("CLAIM-C and REFUND-C over the same outputs: one message, SameDigest");

	// Shapes that are no ending read as nothing.
	let with = |u: &Spend, f: &dyn Fn(&mut Vec<Vec<u8>>)| {
		let mut v = u.clone();
		f(&mut v.tx.input[0].witness.script_witness);
		read(&v)
	};
	assert_eq!(with(&claim, &|w| w[3] = label32("not it").to_vec()), None, "a preimage that does not open the gate");
	assert_eq!(with(&claim, &|w| w[3].truncate(31)), None, "a preimage of 31 bytes");
	// Without its preimage the spend is invalid, but what the operator
	// signed is the same message, and that is what the reader returns.
	assert_eq!(with(&claim, &|w| { w.remove(3); }).as_ref(), Some(&rc));
	assert_eq!(with(&refund, &|w| w.insert(3, preimage.to_vec())), None, "REFUND-C's script under a preimage: no gate");
	assert_eq!(with(&claim, &|w| w.insert(3, vec![7; 32])), None, "seven items");
	assert_eq!(with(&claim, &|w| w[2] = vec![1, 0]), None, "an m of two bytes");
	assert_eq!(bond::rebind_signed_in(&chain, &label32("another salt"), &claim.tx, 0, &claim.prevouts[0]), None, "another salt");

	// The unilateral endings carry no signature of the operator's: the
	// holder alone signs CLAIM's and REFUND's messages, and the reader takes
	// neither for the operator's.
	let mca = lock.claim_message(x, value, std::slice::from_ref(&to_q)).unwrap();
	let mra = lock.refund_message(x, value, std::slice::from_ref(&to_p)).unwrap();
	let mut alone_claim = Spend::new(0).fake_input("htlc2 bond lock", explicit(x, value, lock.script_pubkey()), lock.exit_delay.to_sequence())
		.outputs(vec![to_q.txout(), fee(x, value - to_q.value)]);
	alone_claim.witness(0, lock.claim_witness(&sig(&q, &mca.digest), 1, &preimage));
	let mut alone_refund = Spend::new(timeout.to_consensus_u32())
		.fake_input("htlc2 bond lock", explicit(x, value, lock.script_pubkey()), lock.terms.refund_delay.to_sequence())
		.outputs(vec![to_p.txout(), fee(x, value - to_p.value)]);
	alone_refund.witness(0, lock.refund_witness(&sig(&p, &mra.digest), 1));
	for spend in [&alone_claim, &alone_refund] {
		Verifier::consensus(genesis).verify_tx(&spend.prevouts, &spend.tx).unwrap();
		assert_eq!(read(spend), None, "a unilateral ending holds nothing the operator signed");
	}
	println!("CLAIM and REFUND alone: valid, and read as nothing of the operator's");
}
