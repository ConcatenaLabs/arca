//! What a receiver refuses, on a Sequentia regtest chain: a coin whose
//! lineage holds a leaf outside its policy, a coin whose lineage holds a leaf
//! already on-chain, and a record whose layout makes its exit cost more than
//! the batch's own builder would.
//!
//! Each test shows the refusal, then runs on-chain what accepting the coin
//! would have cost: every transaction is built with this crate's builders,
//! signed with test keys and broadcast to a node on an anchored
//! `elementsregtest` chain started with `-par=1`; a negative case is refused
//! by the mempool and again when forced into a block, the block for the
//! mempool's reason.
//!
//! 1. An intermediate leaf with an exit delay of 512 seconds: the last
//!    receiver refuses the coin; the intermediate owner alone brings its leaf
//!    on-chain and exits it before the receiver's checkpoint can answer.
//! 2. A leaf transferred after it reached the chain and its exit delay
//!    passed: the receipt policy (the exit deadline, not the acceptance
//!    horizon) accepts the record, and the check of its lineage against the
//!    chain refuses it; the sender exits in the next block.
//! 3. Sixteen levels of one child each with no reserves, paid by a confirmed
//!    round: refused for its depth, its one-child nodes and its reserves.
//!
//! Needs `SEQUENTIAD_EXEC`; `--nocapture` prints every transaction.

mod common;

use elements::OutPoint;

use arca_covenant::gate::Members;
use arca_covenant::record::{LowestLevel, UpperLevel};
use arca_covenant::script::sha256;
use arca_covenant::spend::FeeSource;
use arca_covenant::*;

use common::net::*;
use common::round::*;
use common::*;

// ---------------------------------------------------------------------------
// 1. An intermediate leaf with a 512-second exit delay
// ---------------------------------------------------------------------------

#[test]
fn a_short_exit_delay_up_the_lineage_is_refused() {
	let mut c = Arca::start();
	let x = c.net.x;
	let s = keypair("lineage e2 operator");
	let a = keypair("lineage e2 A");
	let preimage = label32("lineage e2 preimage");
	let (issuer, sched) = c.schedule(&s);
	let tree = c.tree(&sched, &[spec(&a, "lineage e2 A", LEAF, sha256(&preimage)),
		spec(&keypair("lineage e2 bystander"), "lineage e2 bystander", LEAF, sha256(&label32("lineage e2 other")))]);
	let (round, _) = round_tx(&c.net, &issuer, &[], &tree.batch_output(), &sched);
	c.net.pass("e2/round", &round);
	let rounds = vec![round];
	let a_base = base(&tree, 0, &a, preimage, mt(c.net.mtp() - 60));
	let policy = c.policy(&s);
	let a_coin = a_base.resolve(&rounds, &policy).unwrap();

	// A pays B, whose new leaf has an exit delay of one unit (512 s); B pays
	// D, whose own leaf has the specification's delay.
	let short = RelativeTime::from_units(1).unwrap();
	let (b, b_leaf) = party("lineage e2 B", short);
	let b_record = one_hop(&a_base, &a_coin, &a, &s, b_leaf, c.net.chain);
	let b_coin = b_record.resolve(&rounds, &WalletPolicy { min_exit_delay: short, ..policy }).unwrap();
	let (_d, d_leaf) = party("lineage e2 D", delay());
	let d_record = one_hop(&b_record, &b_coin, &b, &s, d_leaf, c.net.chain);

	// D refuses the coin, for B's leaf.
	let e = d_record.validate(&rounds, &policy.receipt(), &d_leaf.owner, &d_leaf.owner_nonce).unwrap_err();
	println!("e2: D REFUSES the coin: {} ({})", e, e.kind());
	assert!(matches!(e, TransferError::LineageExitDelay { hops: 1, delay: 1, .. }), "{}", e);

	// What D would have lost: B alone brings its leaf on-chain from its own
	// record and exits it 512 s later, before D's checkpoint.
	let a_at = c.bring_coin("e2/A's leaf", &a_coin);
	let hop1 = inputs(&b_coin);
	let cpt = c.net.pass("e2/A's checkpoint (hop 1)", &hop1[0].checkpoint_tx(a_at, &FeeSource::Reserve).unwrap().tx);
	let ret = c.net.pass("e2/the reassignment creating B's leaf", &b_coin.reassignment_tx(&[OutPoint::new(cpt, 0)], &FeeSource::Reserve).unwrap().tx);
	let b_at = OutPoint::new(ret, 0);
	let ex = exit_tx(&c.net, &b_coin.leaf, b_at, x, b_coin.value, &b);
	c.net.refuse("e2/neg B's exit at once", &ex, "non-BIP68-final");
	let h0 = c.net.height();
	c.net.wait_csv(&ret, short);
	c.net.pass("e2/B's exit, 512 s after its leaf confirmed", &ex);
	println!("e2: B exited {} blocks after its leaf confirmed", c.net.height() - h0 - 1);
	// The checkpoint D would hold: built from D's record, accepted under a
	// policy that believes B's delay, it has nothing left to spend.
	let lax = WalletPolicy { min_exit_delay: short, ..policy.receipt() };
	let d_coin = d_record.validate(&rounds, &lax, &d_leaf.owner, &d_leaf.owner_nonce).unwrap();
	let dcp = inputs(&d_coin)[0].checkpoint_tx(b_at, &FeeSource::Reserve).unwrap();
	c.net.refuse("e2/neg D's checkpoint of B's leaf after B's exit", &dcp.tx, "bad-txns-inputs-missingorspent");
	c.net.print();
}

// ---------------------------------------------------------------------------
// 2. A leaf on-chain past its delay, transferred out of round
// ---------------------------------------------------------------------------

#[test]
fn a_leaf_already_on_chain_is_not_received() {
	let mut c = Arca::start();
	let x = c.net.x;
	let s = keypair("lineage e3 operator");
	let a = keypair("lineage e3 A");
	let preimage = label32("lineage e3 preimage");
	let (issuer, sched) = c.schedule(&s);
	let tree = c.tree(&sched, &[spec(&a, "lineage e3 A", LEAF, sha256(&preimage)),
		spec(&keypair("lineage e3 bystander"), "lineage e3 bystander", LEAF, sha256(&label32("lineage e3 other")))]);
	let (round, _) = round_tx(&c.net, &issuer, &[], &tree.batch_output(), &sched);
	c.net.pass("e3/round", &round);
	let rounds = vec![round];
	let a_base = base(&tree, 0, &a, preimage, mt(c.net.mtp() - 60));
	let a_coin = a_base.resolve(&rounds, &c.policy(&s)).unwrap();

	// A unrolls its own leaf and waits out the exit delay.
	let a_at = c.bring_coin("e3/A's leaf", &a_coin);
	c.net.wait_csv(&a_at.txid, delay());
	println!("e3: A's leaf is on-chain at {} and its exit delay has passed", a_at);

	// A pays B out of round. The record is good under the receipt policy,
	// which asks only for the exit deadline; the acceptance horizon would
	// refuse a coin from a round 36 hours old.
	let (_b, b_leaf) = party("lineage e3 B", delay());
	let b_record = one_hop(&a_base, &a_coin, &a, &s, b_leaf, c.net.chain);
	let accept = c.policy(&s);
	let e = b_record.validate(&rounds, &accept, &b_leaf.owner, &b_leaf.owner_nonce).unwrap_err();
	assert!(matches!(e, TransferError::Record(RecordError::ExpiryTooSoon { .. })), "{}", e);
	let b_coin = b_record.validate(&rounds, &accept.receipt(), &b_leaf.owner, &b_leaf.owner_nonce).unwrap();
	println!("e3: the record validates under the receipt policy ({} atoms, {} hop)", b_coin.value, b_coin.hops);

	// B looks its lineage up on the chain, and refuses the coin.
	let lineage = b_coin.lineage();
	assert_eq!(lineage.len(), 2);
	assert_eq!(lineage[0].output, a_coin.output());
	let e = b_coin.check_lineage(|spk| c.on_chain(spk)).unwrap_err();
	println!("e3: B REFUSES the coin: {} ({})", e, e.kind());
	assert!(matches!(&e, TransferError::OnChain { kind: LineageKind::Leaf, script } if *script == a_coin.output().script_pubkey));

	// What B would have lost: A exits at once, and B's checkpoint has
	// nothing left to spend.
	c.net.pass("e3/A's exit of the leaf it gave B", &exit_tx(&c.net, &a_coin.leaf, a_at, x, LEAF, &a));
	let cp = inputs(&b_coin)[0].checkpoint_tx(a_at, &FeeSource::Reserve).unwrap();
	c.net.refuse("e3/neg B's checkpoint after A's exit", &cp.tx, "bad-txns-inputs-missingorspent");
	c.net.print();
}

// ---------------------------------------------------------------------------
// 3. Sixteen one-child levels with no reserves
// ---------------------------------------------------------------------------

#[test]
fn a_degenerate_layout_is_refused() {
	let mut c = Arca::start();
	let s = keypair("lineage e4 operator");
	let a = keypair("lineage e4 owner");
	let preimage = label32("lineage e4 preimage");
	let (issuer, sched) = c.schedule(&s);
	let proof = Members::new(xonly(&s), &[xonly(&a)]).proof(1);
	let owner_nonce = label32("lineage e4 owner nonce");
	let record = LeafRecord {
		template: Template::Vtxo1, owner: xonly(&a), owner_nonce, operator_nonce: label32("lineage e4 operator nonce"),
		exit_delay: delay(), asset: c.net.x, value: LEAF, unlock_hash: sha256(&preimage), entry_reserve: 0,
		chain: c.net.chain, schedule: sched.clone(), burn: false,
		upper: (0..15).map(|_| UpperLevel { index: 0, reserve: 0, siblings: vec![], member: proof.clone() }).collect(),
		lowest: LowestLevel { index: 0, reserve: 0, siblings: vec![], owners: vec![] },
	};
	let record = LeafRecord::from_bytes(&record.to_bytes().unwrap()).unwrap();
	let (round, _) = round_tx(&c.net, &issuer, &[], &record.branch().unwrap().batch_output(), &sched);
	c.net.pass("e4/round paying the sixteen-level batch output", &round);
	let policy = c.policy(&s);
	let refuse = |p: &WalletPolicy| {
		let e = record.validate(&round, p, &xonly(&a), &owner_nonce).unwrap_err();
		println!("e4: REFUSED: {} ({})", e, e.kind());
		e
	};
	assert!(matches!(refuse(&policy), RecordError::TooManyLevels { levels: 16, max: 5 }));
	let deep = WalletPolicy { max_levels: arca_covenant::record::MAX_LEVELS, ..policy };
	assert!(matches!(refuse(&deep), RecordError::OneChild { level: 0 }));
	// The round does pay the batch output the record rebuilds: only the
	// policy stands between the wallet and the record.
	record.validate_batch_output(&round.output[0]).unwrap();
	let blind = WalletPolicy { min_reserve: ReserveFloor::Atoms(0), ..deep };
	assert!(matches!(refuse(&blind), RecordError::OneChild { level: 0 }), "whatever the floor");
	// A batch of one leaf is one node of one child; with no reserves it is
	// refused for its reserve alone.
	let (issuer, sched) = c.schedule(&s);
	let alone = LeafRecord { upper: vec![], schedule: sched.clone(), ..record.clone() };
	let (round, _) = round_tx(&c.net, &issuer, &[], &alone.branch().unwrap().batch_output(), &sched);
	c.net.pass("e4/round paying a one-leaf batch with no reserves", &round);
	let e = alone.validate(&round, &policy, &xonly(&a), &owner_nonce).unwrap_err();
	println!("e4: a one-leaf batch with no reserves: {} ({})", e, e.kind());
	assert!(matches!(e, RecordError::NodeReserve { level: 0, reserve: 0, min: 1 }));
	alone.validate(&round, &blind, &xonly(&a), &owner_nonce).unwrap();
	c.net.print();
}
