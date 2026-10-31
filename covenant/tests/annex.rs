//! Preimages read from spends whose witnesses end with an annex (BIP341), on
//! an anchored regtest chain.
//!
//! A claim signed by `<key> OP_CHECKSIG` commits to its annex, so only the
//! signer can add one; the signer is the party with a reason to hide the
//! preimage: the operator claiming a forfeit (the owner needs the preimage
//! for its new leaf's entry), the owner claiming an `htlc-1` coin it
//! receives (the operator's gateway needs it to settle the payment it
//! holds), the operator claiming one it sent (the wallet's proof of
//! payment). An entry's unlock carries no signature, so anyone who mines it
//! can add one. Each is refused by the mempool (`bad-witness-nonstandard`),
//! mined with `generateblock`, read back from the node, and its preimage
//! found by [`find_preimage`], the reader every wallet and the gateway use.
//!
//! Needs `SEQUENTIAD_EXEC`.

mod common;

use elements::hashes::Hash;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::Keypair;
use elements::sighash::{Annex, Prevouts, SighashCache};
use elements::{OutPoint, SchnorrSighashType, Script, Transaction, TxOut, Txid};

use arca_covenant::script::sha256;
use arca_covenant::sign::sign_digest;
use arca_covenant::taptree::leaf_hash;
use arca_covenant::witness::{annex, find_preimage, without_annex};
use arca_covenant::*;

use common::net::*;
use common::*;

const LEAF: u64 = 10_000_000;
const FEE: u64 = 1_500;

/// A signature over input `idx`'s taproot signature hash with `annex`
/// present: what a signer who adds an annex signs.
fn sign_annexed(key: &Keypair, tx: &Transaction, idx: usize, prevouts: &[TxOut], leaf: &Script, annex: &[u8], net: &Net) -> Signature {
	let h = SighashCache::new(tx).taproot_sighash(idx, &Prevouts::All(prevouts), Some(Annex::new(annex).unwrap()),
		Some((leaf_hash(leaf), 0xFFFF_FFFF)), SchnorrSighashType::Default, net.genesis).unwrap();
	sign_digest(key, &h.to_byte_array(), &ZERO_AUX)
}

/// Mines `tx` with `generateblock` (the mempool refuses an annex), reads it
/// back from the node and checks that its preimage for `hash` is found.
fn mine_and_read(net: &mut Net, name: &str, tx: &Transaction, hash: &[u8; 32], expect: &[u8; 32]) -> Txid {
	let id = net.mine_policy_refused(name, tx, "bad-witness-nonstandard");
	let w = net.witness_of(&id, 0);
	let a = annex(&w).expect("the block carries the annex").to_vec();
	println!("{}: {} witness items on the chain, the annex {} ({} items without it)", name, w.len(), hex(&a), without_annex(&w).len());
	let found = find_preimage(&w, hash);
	println!("  find_preimage: {:?}", found.map(|p| hex(&p)));
	assert_eq!(found, Some(*expect), "{}: the preimage is read from the annexed spend", name);
	id
}

#[test]
fn preimages_are_read_from_annexed_claims() {
	let mut net = Net::start();
	let s_key = keypair("annex operator");
	let a = keypair("annex owner");
	let x = net.x;

	// --- A forfeit claimed by the operator, an annex under its signature ---
	let sched = ClockSchedule::new(asset("annex token"), xonly(&s_key), delay(), vec![mt(net.now() + 28 * 24 * H as u64)]).unwrap();
	let conn = ConnectorPolicy { operator: xonly(&s_key) };
	let connector = net.fund(vec![conn.output(x, 5_000).txout()]).remove(0);
	let m = connector_asset(connector.outpoint.txid, connector.outpoint.vout);
	let new = net.leaf(&a, &s_key, "annex new leaf");
	let preimage = label32("annex forfeit preimage");
	let entry = EntryPolicy { unlock_hash: sha256(&preimage), asset: x, value: LEAF, leaf_program: new.program(),
		sweep: Some(sched.sweep(true, false)) };
	let f = ForfeitPolicy {
		unlock_hash: sha256(&preimage), owner: xonly(&a), operator: xonly(&s_key), refund_delay: delay(),
		leaf_id: LeafId(label32("annex old leaf id")), connector: m,
	};
	let coins = net.fund(vec![explicit(x, LEAF, f.script_pubkey()), explicit(x, LEAF + 1_000, entry.script_pubkey())]);
	let (f_coin, entry_coin) = (coins[0].clone(), coins[1].clone());
	let ks = conn.issuance(connector.outpoint, (x, 5_000), op_true_spk(), &[], &FeeSource::Reserve).unwrap();
	let sg = sig(&s_key, &ks.sighash(net.genesis).unwrap());
	let iss = ks.finish(vec![sg.as_ref().to_vec()]);
	let it = net.pass("the issuance of the connector asset M", &iss.tx);
	let m_coin = coin_of(it, 0, &iss.tx);
	let annex_bytes = vec![0x50, 0xf0, 0x0d];
	let mut s = spend(0).coin(&f_coin, 0xffff_ffff).coin(&m_coin, 0xffff_ffff).outputs(vec![
		explicit(x, LEAF - FEE, op_true_spk()), explicit(m, 1, op_true_spk()), fee(x, FEE)]);
	let sc = f.claim_script();
	let sg = sign_annexed(&s_key, &s.tx, 0, &s.prevouts, &sc, &annex_bytes, &net);
	let mut w = f.taproot().witness(&sc, ForfeitPolicy::claim_items(&sg, &preimage, 1));
	w.push(annex_bytes.clone());
	s.witness(0, w);
	s.witness(1, op_true_witness());
	mine_and_read(&mut net, "the operator's forfeit claim, an annex under its signature", &s.tx, &entry.unlock_hash, &preimage);
	// The owner unlocks its entry with the preimage it read.
	let mut u = spend(0).coin(&entry_coin, 0xffff_ffff).outputs(vec![explicit(x, LEAF, new.script_pubkey()), fee(x, 1_000)]);
	u.witness(0, entry.unlock_witness(&preimage));
	net.pass("the owner's entry, unlocked with the preimage read from the annexed claim", &u.tx);

	// --- An entry's unlock, an annex added by whoever mines it ---------------
	let p2 = label32("annex entry preimage");
	let entry2 = EntryPolicy { unlock_hash: sha256(&p2), asset: x, value: LEAF, leaf_program: new.program(), sweep: Some(sched.sweep(true, false)) };
	let e2 = net.fund(vec![explicit(x, LEAF + 1_000, entry2.script_pubkey())]).remove(0);
	let mut u = spend(0).coin(&e2, 0xffff_ffff).outputs(vec![explicit(x, LEAF, new.script_pubkey()), fee(x, 1_000)]);
	let mut w = entry2.unlock_witness(&p2);
	w.push(vec![0x50]);
	u.witness(0, w);
	mine_and_read(&mut net, "an entry's unlock, an annex added by its miner", &u.tx, &entry2.unlock_hash, &p2);

	// --- htlc-1: the owner's claim of a receive, the operator's of a send ---
	let pay = label32("annex htlc payment");
	let timeout = net.now() + 6 * H as u64;
	let operator_delay = RelativeTime::from_units(delay().units() / 3).unwrap();
	let mk = |direction, salt: &str| LeafPolicy { enclave: None, claim: None,
		owner: xonly(&a), operator: xonly(&s_key), salt: label32(salt), chain: net.chain, exit_delay: delay(),
		htlc: Some(HtlcTerms { direction, payment_hash: sha256(&pay), timeout: mt(timeout), operator_delay }),
		order: None, landing: None, channel: None, v2: false,
	};
	let (sent, received) = (mk(HtlcDirection::Send, "annex htlc sent"), mk(HtlcDirection::Receive, "annex htlc received"));
	let coins = net.fund(vec![explicit(x, LEAF, sent.script_pubkey()), explicit(x, LEAF, received.script_pubkey())]);
	let funding = coins[0].outpoint.txid;
	let to = ExplicitOutput::new(x, LEAF - FEE, op_true_spk());
	let claim = |net: &Net, h: &LeafPolicy, coin: &Coin, key: &Keypair| -> Transaction {
		let ks = h.claim_tx(coin.outpoint, x, LEAF, std::slice::from_ref(&to), &FeeSource::Reserve).unwrap();
		let sg = sign_annexed(key, &ks.tx, 0, &ks.prevouts, &ks.script, &[0x50, 0x01], net);
		let mut u = ks.finish(HtlcTerms::claim_items(&sg, &pay));
		u.tx.input[0].witness.script_witness.push(vec![0x50, 0x01]);
		u.tx
	};
	net.wait_csv(&funding, operator_delay);
	let tx = claim(&net, &sent, &coins[0], &s_key);
	mine_and_read(&mut net, "htlc-1 send: the operator's claim, an annex under its signature", &tx, &sha256(&pay), &pay);
	net.wait_csv(&funding, delay());
	let tx = claim(&net, &received, &coins[1], &a);
	mine_and_read(&mut net, "htlc-1 receive: the owner's claim, an annex under its signature", &tx, &sha256(&pay), &pay);
	let _ = OutPoint::null();
	net.print();
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}
