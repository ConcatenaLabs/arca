//! An order placed from leaves, and its maker's REFUND, on a Sequentia
//! regtest chain anchored to a Bitcoin parent.
//!
//! A wallet holding only leaves places an ordinary SeqDEX order by
//! offboarding exactly the order's amount into the address its terms make:
//! the round pays an offboard output ([`OffboardPolicy`]) holding the order's
//! amount and its unlock margin ([`OffboardPolicy::unlock_margin`]), and its
//! unlock, with the preimage, pays the order at output 0. Here the offboard
//! output is funded directly and unlocked with its margin as the fee at four
//! times the node's floor: the order rests at the unlock's output 0 holding
//! exactly its amount, under SeqDEX's own two-leaf script.
//!
//! Its maker takes it back with the REFUND leaf once the chain has passed its
//! `expiry_locktime`, a median time ([`FillOrder::refund_tx`], which the
//! wallet's `order refund` builds). Forced into a block on a node checking
//! scripts inline (`-par=1`) and refused, each for its own reason: the REFUND
//! before its time with the lock time at the expiry, and with a lock time
//! below it; the operator's signature in the maker's place after the time.
//! The maker's REFUND at its time is mined.
//!
//! Needs `SEQUENTIAD_EXEC`; run with `--nocapture` for the table.

mod common;

use elements::Script;

use arca_covenant::fill::FillOrder;
use arca_covenant::spend::FeeSource;
use arca_covenant::*;

use common::net::*;
use common::*;

const AMOUNT: u64 = 10_000_000;
const FEE: u64 = 3_000;

fn plain(key: &elements::secp256k1_zkp::Keypair) -> Script {
	elements::script::Builder::new().push_int(1).push_slice(&xonly(key).serialize()).into_script()
}

#[test]
fn an_order_placed_by_an_offboard_and_its_refund() {
	let mut net = Net::start();
	let maker = keypair("order refund maker");
	let operator = keypair("order refund operator");
	let expiry = (net.now() + 6 * H as u64) as u32;
	let terms = FillOrder { asset_a: net.x, asset_b: net.y, rate_num: 2, rate_den: 1,
		maker_prog: xonly(&keypair("order refund maker credit")).serialize(), min_lot: 1_000_000, expiry_locktime: expiry,
		maker_x: xonly(&maker).serialize() };
	terms.check_arithmetic(AMOUNT).unwrap();

	// The offboard output a round pays: the order's amount and the margin
	// for its unlock, priced at the floor the node takes X at.
	let preimage = label32("order refund preimage");
	let policy = OffboardPolicy { unlock_hash: script::sha256(&preimage),
		destination: ExplicitOutput::new(net.x, AMOUNT, terms.script_pubkey()), operator: xonly(&operator), reclaim_delay: delay() };
	let floor = 1_000;
	let margin = policy.unlock_margin(Some(floor), 4);
	assert_eq!(policy.unlock_margin(None, 4), 0, "no margin where the node takes no fee in the asset");
	println!("the unlock margin at {} atoms per 1,000 vbytes, four times over: {}", floor, margin);
	let off = net.fund(vec![policy.output(margin).txout()]).remove(0);
	let u = policy.unlock_tx(off.outpoint, AMOUNT + margin, &preimage, &FeeSource::Reserve).unwrap();
	let ut = net.pass("the offboard unlocked into the order's address, its margin the fee", &u.tx);
	let order = coin_of(ut, 0, &u.tx);
	assert_eq!(order.txout.script_pubkey, terms.script_pubkey(), "the order rests at output 0 under SeqDEX's two-leaf script");
	assert_eq!(order.txout.value.explicit(), Some(AMOUNT), "holding exactly its amount");

	// The REFUND, as the wallet builds it.
	let refund = |net: &Net, key: &elements::secp256k1_zkp::Keypair, lock: Option<u32>| {
		let mut ks = terms.refund_tx(order.outpoint, AMOUNT, &[ExplicitOutput::new(net.x, AMOUNT - FEE, plain(&maker))],
			&FeeSource::Reserve).unwrap();
		if let Some(l) = lock {
			ks.tx.lock_time = elements::LockTime::from_consensus(l);
		}
		let sg = sig(key, &ks.sighash(net.genesis).unwrap());
		ks.finish(vec![sg.as_ref().to_vec()]).tx
	};
	assert_eq!(refund(&net, &maker, None).lock_time.to_consensus_u32(), expiry, "its lock time is the order's expiry");
	net.refuse("neg the REFUND before its time, its lock time at the expiry", &refund(&net, &maker, None), "non-final");
	let below = net.mtp() as u32 - 600;
	net.refuse("neg the REFUND before its time, its lock time below the expiry", &refund(&net, &maker, Some(below)),
		"Locktime requirement not satisfied");
	net.mtp_past(expiry as u64 + 60);
	net.refuse("neg the operator's signature on the REFUND after its time", &refund(&net, &operator, None), "Invalid Schnorr signature");
	let rt = net.pass("the maker's REFUND at its time", &refund(&net, &maker, None));
	let back = net.rt.client().raw_transaction(&rt).unwrap();
	assert_eq!(back.output[0].script_pubkey, plain(&maker));
	assert_eq!(back.output[0].value.explicit(), Some(AMOUNT - FEE));
	net.print();
}
