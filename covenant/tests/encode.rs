//! The encodings round-trip and refuse what does not re-encode; the witness
//! readers recover what the builders put in.

mod common;

use elements::hashes::Hash;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::BlockHash;

use arca_covenant::encode::{DecodeError, Encoding, Policy};
use arca_covenant::htlc::HtlcPath;
use arca_covenant::script::sha256;
use arca_covenant::witness::{find_preimage, ScriptPath, UnrollWitness};
use arca_covenant::*;

use common::*;

fn chain() -> Chain {
	Chain::new(BlockHash::from_byte_array(label32("genesis")))
}

fn schedule() -> ClockSchedule {
	let e = |d: u32| MedianTime::from_consensus(1_791_000_000 + d * 86_400).unwrap();
	ClockSchedule::new(asset("T"), xonly(&keypair("S")), RelativeTime::from_seconds_ceil(36 * 3600).unwrap(),
		vec![e(28), e(56), e(84)]).unwrap()
}

fn policies() -> Vec<Policy> {
	let s = xonly(&keypair("S"));
	let a = xonly(&keypair("A"));
	let sch = schedule();
	let leaf = LeafPolicy { owner: a, operator: s, salt: label32("salt"), chain: chain(), exit_delay: sch.notice };
	let owners: Vec<XOnlyPublicKey> = (0..5).map(|i| xonly(&keypair(&format!("o{}", i)))).collect();
	let children = (0..4).map(|i| Child::new(asset("X"), 1_000 + i, label32(&format!("c{}", i)))).collect::<Vec<_>>();
	vec![
		Policy::Leaf(leaf),
		Policy::Node(NodePolicy::new(children.clone(), s, owners.clone(), sch.sweep(false, false), None).unwrap()),
		Policy::Node(NodePolicy::new(children.clone(), s, owners.clone(), sch.sweep(true, true), Some(chain())).unwrap()),
		Policy::Node(NodePolicy::new(children[..1].to_vec(), s, (0..300).map(|_| a).collect(), sch.sweep(true, false), Some(chain())).unwrap()),
		Policy::Entry(EntryPolicy { unlock_hash: label32("h"), asset: asset("X"), value: 77, leaf_program: leaf.program(), sweep: sch.sweep(true, false) }),
		Policy::Forfeit(ForfeitPolicy { unlock_hash: label32("h"), owner: a, operator: s, refund_delay: sch.notice }),
		Policy::Checkpoint(CheckpointPolicy { owner: a, operator: s, salt: label32("cp"), chain: chain(), sweep: sch.sweep(true, false) }),
		Policy::Htlc(HtlcPolicy {
			owner: a, operator: s, direction: HtlcDirection::Receive, payment_hash: label32("p"),
			timeout: MedianTime::from_consensus(1_800_000_000).unwrap(),
			salts: HtlcSalts { claim: label32("1"), claim_both: label32("2"), refund_both: label32("3") }, chain: chain(),
		}),
	]
}

#[test]
fn policies_round_trip() {
	for p in policies() {
		let bytes = p.encode();
		let back = Policy::decode(&bytes).unwrap();
		assert_eq!(back, p);
		assert_eq!(back.encode(), bytes);
		assert_eq!(back.script_pubkey(), p.script_pubkey());
		// Every proper prefix fails, and so does a trailing byte.
		for n in 0..bytes.len() {
			assert!(Policy::decode(&bytes[..n]).is_err(), "a {}-byte prefix decoded", n);
		}
		let mut long = bytes.clone();
		long.push(0);
		assert_eq!(Policy::decode(&long), Err(DecodeError::TrailingBytes(1)));
	}
	let s = schedule();
	assert_eq!(ClockSchedule::decode(&s.encode()).unwrap(), s);
	// A published schedule that runs backwards still decodes: the check refuses it.
	let back = ClockSchedule::new_unchecked(s.token, s.operator, s.notice,
		vec![s.expiries()[1], s.expiries()[0]]).unwrap();
	assert_eq!(ClockSchedule::decode(&back.encode()).unwrap().backwards_at(), Some(1));
}

#[test]
fn malformed_encodings_are_refused() {
	let p = policies();
	let leaf = p[0].encode();
	// version, type
	let mut b = leaf.clone();
	b[0] = 2;
	assert_eq!(Policy::decode(&b), Err(DecodeError::Version(2)));
	let mut b = leaf.clone();
	b[1] = 9;
	assert_eq!(Policy::decode(&b), Err(DecodeError::PolicyType(9)));
	// a key that is not on the curve: x = 0xff..ff is above the field size
	let mut b = leaf.clone();
	b[2..34].copy_from_slice(&[0xff; 32]);
	assert_eq!(Policy::decode(&b), Err(DecodeError::Key));
	// a zero exit delay
	let mut b = leaf.clone();
	let n = b.len();
	b[n - 2..].copy_from_slice(&[0, 0]);
	assert!(matches!(Policy::decode(&b), Err(DecodeError::Time(_))));
	// an htlc timeout that is a height
	let htlc = p[7].encode();
	let mut b = htlc.clone();
	let at = 2 + 32 + 32 + 1 + 32;
	b[at..at + 4].copy_from_slice(&100u32.to_le_bytes());
	assert!(matches!(Policy::decode(&b), Err(DecodeError::Time(_))));
	let mut b = htlc.clone();
	b[2 + 64] = 2;
	assert_eq!(Policy::decode(&b), Err(DecodeError::Flag(2)));
	// node: no child, seven children, an owner count larger than the data
	let node = p[1].encode();
	let mut b = node.clone();
	b[2] = 0;
	assert_eq!(Policy::decode(&b), Err(DecodeError::Count(0)));
	let mut b = node.clone();
	b[2] = 7;
	assert_eq!(Policy::decode(&b), Err(DecodeError::Count(7)));
	let owners_at = 3 + 4 * 72 + 32;
	let mut b = node.clone();
	b[owners_at] = 0xfc;
	assert_eq!(Policy::decode(&b), Err(DecodeError::Count(0xfc)));
	let mut b = node.clone();
	b.splice(owners_at..owners_at + 1, [0xfd, 0x05, 0x00]);
	assert_eq!(Policy::decode(&b), Err(DecodeError::NonCanonical));
	// a reclaim flag that is not 0 or 1, and sweep flags out of range
	let mut b = node.clone();
	let n = b.len();
	b[n - 1] = 2;
	assert_eq!(Policy::decode(&b), Err(DecodeError::Flag(2)));
	let sweep_flags = owners_at + 1 + 5 * 32 + 96;
	let mut b = node.clone();
	b[sweep_flags] = 4;
	assert_eq!(Policy::decode(&b), Err(DecodeError::Flag(4)));
	// a reclaim flag with no owners
	let lowest = NodePolicy::decode(&p[2].encode()[2..]).unwrap();
	let mut b = lowest.encode();
	let at = 1 + 4 * 72 + 32;
	b.splice(at..at + 1 + 5 * 32, [0]);
	assert!(matches!(NodePolicy::decode(&b), Err(DecodeError::Policy(Error::NoOwners))));
	// a schedule with no step, or a step count past the data
	let s = schedule().encode();
	let mut b = s.clone();
	b[1 + 64 + 2] = 0;
	assert_eq!(ClockSchedule::decode(&b), Err(DecodeError::Count(0)));
	let mut b = s.clone();
	b[1 + 64 + 2] = 4;
	assert_eq!(ClockSchedule::decode(&b), Err(DecodeError::UnexpectedEnd));
}

#[test]
fn witness_readers() {
	let s = keypair("S");
	let a = keypair("A");
	let sch = schedule();
	let owners: Vec<XOnlyPublicKey> = (0..4).map(|i| xonly(&keypair(&format!("o{}", i)))).collect();
	let children = (0..4).map(|i| Child::new(asset("X"), 1_000, label32(&format!("c{}", i)))).collect::<Vec<_>>();
	let node = NodePolicy::new(children, xonly(&s), owners.clone(), sch.sweep(true, false), Some(chain())).unwrap();
	let t = MedianTime::from_consensus(1_791_000_000).unwrap();
	let signer = keypair("o2");
	let auth = node.unroll_authorisation(t);
	let sg = sig(&signer, &auth.digest);
	let w = node.unroll_witness(&sg, t, &xonly(&signer)).unwrap();

	let sp = ScriptPath::parse(&w).unwrap();
	assert_eq!(sp.script, node.unroll_script());
	assert!(sp.annex.is_none());
	let uw = UnrollWitness::parse(sp.items).unwrap();
	assert_eq!(uw.signature, sg);
	assert_eq!(uw.time, t);
	assert_eq!(uw.key, xonly(&signer));
	let m = node.members();
	assert_eq!(uw.path, m.path(m.index_of(&xonly(&signer)).unwrap()));
	// With an annex appended, the parts are the same.
	let mut wa = w.clone();
	wa.push(vec![0x50, 1, 2]);
	let sp2 = ScriptPath::parse(&wa).unwrap();
	assert_eq!(sp2.items, sp.items);
	assert_eq!(sp2.annex, Some(&[0x50, 1, 2][..]));
	// Malformed: a direction that is not empty or 0x01, a short key, a time that is a height.
	let mut bad = sp.items.to_vec();
	bad[3] = vec![2];
	assert!(UnrollWitness::parse(&bad).is_err());
	let mut bad = sp.items.to_vec();
	let n = bad.len();
	bad[n - 1].pop();
	assert!(UnrollWitness::parse(&bad).is_err());
	let mut bad = sp.items.to_vec();
	bad[1] = vec![100];
	assert!(UnrollWitness::parse(&bad).is_err());
	let mut bad = sp.items.to_vec();
	bad[1].push(0);
	assert!(UnrollWitness::parse(&bad).is_err(), "a non-minimal time is refused");
	assert!(UnrollWitness::parse(&sp.items[1..]).is_err());

	// The preimage a forfeit claim reveals.
	let pre = label32("pre");
	let forfeit = ForfeitPolicy { unlock_hash: sha256(&pre), owner: xonly(&a), operator: xonly(&s), refund_delay: sch.notice };
	let w = forfeit.claim_witness(&sig(&s, &label32("any")), &pre);
	assert_eq!(find_preimage(&w, &forfeit.unlock_hash), Some(pre));
	assert_eq!(find_preimage(&w, &label32("other")), None);
	let h = HtlcPolicy {
		owner: xonly(&a), operator: xonly(&s), direction: HtlcDirection::Send, payment_hash: sha256(&pre),
		timeout: MedianTime::from_consensus(1_800_000_000).unwrap(),
		salts: HtlcSalts { claim: label32("1"), claim_both: label32("2"), refund_both: label32("3") }, chain: chain(),
	};
	let w = h.claim_both_witness(&sig(&s, &label32("x")), &sig(&a, &label32("x")), &pre);
	assert_eq!(find_preimage(&w, &h.payment_hash), Some(pre));
	assert!(h.leaf_constant(HtlcPath::Refund).is_none());
}
