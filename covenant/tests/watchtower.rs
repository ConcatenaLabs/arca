//! What a watchtower can do with a deposit, on a Sequentia regtest chain:
//! bring the coin on the chain under its owner's key, and nothing else.
//!
//! A wallet deposits each coin it holds as its coin record, the owner's
//! unroll authorisations in it signed for an hour before the batch's first
//! expiry, so the record unrolls nothing before the batch can be released.
//! Here the watchtower holds A's deposit and tries everything the record
//! lets it build: every negative case is refused by the mempool and again
//! when forced into a block (`generateblock`, the node checking scripts
//! inline with `-par=1`), the block for the mempool's reason.
//!
//! 1. The unroll before the deposit's time: refused, non-final.
//! 2. From that time, the batch output's unroll with A's child paid to the
//!    watchtower's own script, and with a child's value moved into the fee:
//!    refused by the unroll's covenant.
//! 3. The entry's unlock into the watchtower's script, and one atom short:
//!    refused by the entry's covenant.
//! 4. The path as the deposit builds it: the leaf on the chain at A's own
//!    leaf script, the fees from the path's reserves.
//! 5. The leaf's exit signed by the watchtower: refused; A's own exit after
//!    its delay: mined.
//!
//! Needs `SEQUENTIAD_EXEC`; `--nocapture` prints every transaction.

mod common;

use elements::OutPoint;

use arca_covenant::script::sha256;
use arca_covenant::spend::FeeSource;
use arca_covenant::*;

use common::net::*;
use common::round::*;
use common::*;

#[test]
fn a_deposit_only_brings_the_coin_on_chain_under_its_owner_key() {
	let mut c = Arca::start();
	let x = c.net.x;
	let s = keypair("tower operator");
	let a = keypair("tower A");
	let tower = keypair("tower itself");
	let tower_spk = elements::Script::new_v1_p2tr(&elements::secp256k1_zkp::Secp256k1::new(), xonly(&tower), None);
	let preimage = label32("tower preimage");
	let (issuer, sched) = c.schedule(&s);
	let tree = c.tree(&sched, &[
		spec(&a, "tower A", LEAF, sha256(&preimage)),
		spec(&keypair("tower B"), "tower B", LEAF, sha256(&label32("tower other B"))),
		spec(&keypair("tower C"), "tower C", LEAF, sha256(&label32("tower other C"))),
	]);
	let (round, _) = round_tx(&c.net, &issuer, &[], &tree.batch_output(), &sched);
	c.net.pass("round", &round);
	let rounds = vec![round];

	// A's deposit: its record, the authorisations timed an hour before the
	// batch's first expiry.
	let e0 = sched.expiries()[0].to_consensus_u32() as u64;
	let t = mt(e0 - 3_600);
	let deposit = base(&tree, 0, &a, preimage, t);
	let bytes = deposit.to_bytes().unwrap();
	let deposit = CoinRecord::from_bytes(&bytes).unwrap();
	// The watchtower checks it as of the authorisations' time.
	let policy = WalletPolicy { horizon: 0, ..c.policy(&s).receipt() };
	let coin = deposit.resolve(&rounds, &WalletPolicy { now: t, ..policy }).unwrap();
	let ValidOrigin::Leaf { valid, preimage: p, auths } = &coin.origin else { unreachable!("a batch leaf") };
	let branch = &valid.branch;
	assert_eq!(auths.len(), 1, "one node above A's entry: the batch output");
	let batch = OutPoint::new(valid.round_txid, valid.batch_vout);

	// 1. Before the deposit's time the record unrolls nothing.
	let early = branch.nodes[0].unroll_tx(batch, &auths[0], &FeeSource::Reserve).unwrap();
	c.net.refuse("neg the deposit's unroll before its time", &early.tx, "non-final");

	// From its time on.
	c.net.mtp_past(t.to_consensus_u32() as u64);

	// 2. The unroll with A's child paid to the watchtower, or a child cut
	// into the fee.
	let mut bad = branch.nodes[0].unroll_tx(batch, &auths[0], &FeeSource::Reserve).unwrap().tx;
	bad.output[branch.nodes[0].index as usize].script_pubkey = tower_spk.clone();
	c.net.refuse("neg the unroll with A's entry paid to the watchtower", &bad, "Script failed an OP_EQUALVERIFY operation");
	let mut bad = branch.nodes[0].unroll_tx(batch, &auths[0], &FeeSource::Reserve).unwrap().tx;
	let k = branch.nodes[0].index as usize;
	let v = bad.output[k].value.explicit().unwrap();
	bad.output[k].value = elements::confidential::Value::Explicit(v - 1_000);
	let f = bad.output.len() - 1;
	let fee = bad.output[f].value.explicit().unwrap();
	bad.output[f].value = elements::confidential::Value::Explicit(fee + 1_000);
	c.net.refuse("neg the unroll with A's entry 1,000 atoms short, the rest to the fee", &bad, "Script failed an OP_EQUALVERIFY operation");

	// 4 (first half). The unroll as the deposit builds it.
	let u = branch.unroll(batch, auths, &[FeeSource::Reserve]).unwrap();
	let id = c.net.pass("the batch output's unroll, by the deposit", &u[0].tx);
	let entry_at = OutPoint::new(id, branch.nodes[0].index as u32);

	// 3. The entry's unlock into the watchtower's script, or one atom short.
	let mut bad = branch.entry_tx(entry_at, p, &FeeSource::Reserve).unwrap().tx;
	bad.output[0].script_pubkey = tower_spk.clone();
	c.net.refuse("neg the entry's unlock into the watchtower's script", &bad,
		"Script evaluated without error but finished with a false/empty top stack element");
	let mut bad = branch.entry_tx(entry_at, p, &FeeSource::Reserve).unwrap().tx;
	let v = bad.output[0].value.explicit().unwrap();
	bad.output[0].value = elements::confidential::Value::Explicit(v - 1);
	let f = bad.output.len() - 1;
	let fee = bad.output[f].value.explicit().unwrap();
	bad.output[f].value = elements::confidential::Value::Explicit(fee + 1);
	c.net.refuse("neg the entry's unlock one atom short", &bad, "Script failed an OP_EQUALVERIFY operation");

	// 4 (second half). The entry into A's leaf.
	let e = branch.entry_tx(entry_at, p, &FeeSource::Reserve).unwrap();
	let leaf_txid = c.net.pass("the entry's unlock into A's leaf, by the deposit", &e.tx);
	let leaf_at = OutPoint::new(leaf_txid, 0);
	assert_eq!(e.tx.output[0].script_pubkey, coin.leaf.script_pubkey(), "the leaf is A's own");
	assert_eq!(e.tx.output[0].value.explicit(), Some(coin.value));

	// 5. Only A's key takes the leaf home.
	c.net.wait_csv(&leaf_txid, delay());
	let stolen = exit_tx(&c.net, &coin.leaf, leaf_at, x, coin.value, &tower);
	c.net.refuse("neg the leaf's exit signed by the watchtower", &stolen, "Invalid Schnorr signature");
	let home = exit_tx(&c.net, &coin.leaf, leaf_at, x, coin.value, &a);
	c.net.pass("A's exit, by A's key", &home);
	c.net.print();
}
