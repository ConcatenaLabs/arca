//! `enclave-1` on a real node: a restricted asset in the tree.
//!
//! A restricted asset `R` (an issued asset the node does not take for fees)
//! is boarded by its holder `H1` into an `enclave-1` board, on an anchored
//! regtest chain whose node checks scripts inline (`-par=1`). Every negative
//! case is refused by the mempool and again when forced into a block, the
//! block refused for the script's reason:
//!
//! - the collaborative path signed over the plain constant `K`, and over
//!   another holder's `K ‖ D`;
//! - the exit before its delay, to another holder's enclave, to a script that
//!   is no enclave, one atom short, in another asset, and signed by the
//!   holder's registered key in place of its leaf key;
//! - the clawback with the operator's key in place of the policy key;
//! - the clawback of a board and of a leaf of an asset that elected none.
//!
//! Beside them confirm: the collaborative spend into `H2`'s `enclave-1` leaf,
//! its exit into `H2`'s enclave, the landed coin spent by the enclave's own
//! transfer leaf (holder and policy key), a board's conversion, and the
//! clawback of a board and of a leaf, each paying the issuer's enclave.
//!
//! The enclave itself is checked against openampd's golden vectors.

mod common;

use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, Script, Transaction};
use serde_json::Value;

use arca_covenant::board::BoardRecord;
use arca_covenant::spend::{FeeSource, Pair, Rebindable};
use arca_covenant::{enclave_key, enclave_keypair, Enclave, ExplicitOutput, LeafPolicy, Template};
use common::net::*;
use common::*;

const V: u64 = 250_000_000;
const FEE: u64 = 3_000;

fn hexs(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

struct Keys {
	h1: Keypair,
	h2: Keypair,
	issuer_holder: Keypair,
	policy: Keypair,
	issuer: Keypair,
	operator: Keypair,
}

impl Keys {
	fn new() -> Keys {
		Keys {
			h1: keypair("enclave holder 1"), h2: keypair("enclave holder 2"), issuer_holder: keypair("enclave issuer account"),
			policy: keypair("enclave policy key"), issuer: keypair("enclave issuer key"), operator: keypair("enclave operator"),
		}
	}

	fn enclave(&self, holder: &Keypair, clawback: bool) -> Enclave {
		Enclave { holder: xonly(holder), policy: xonly(&self.policy), clawback: clawback.then(|| xonly(&self.issuer)) }
	}
}

/// The `enclave-1` leaf of `holder` for owner nonce `nonce`.
fn leaf(net: &Net, k: &Keys, holder: &Keypair, nonce: [u8; 32], salt: &str, asset: AssetId, value: u64, clawback: bool) -> LeafPolicy {
	LeafPolicy {
		owner: enclave_key(&xonly(holder), &nonce).unwrap(), operator: xonly(&k.operator), salt: label32(salt), chain: net.chain,
		exit_delay: delay(), htlc: None, order: None, landing: None, channel: None,
		enclave: Some(k.enclave(holder, clawback).terms(asset, value)), v2: false,
	}
}

fn board(net: &Net, k: &Keys, holder: &Keypair, nonce: [u8; 32], operator_nonce: &str, asset: AssetId, clawback: bool) -> BoardRecord {
	BoardRecord {
		template: Template::Board1, owner: enclave_key(&xonly(holder), &nonce).unwrap(), owner_nonce: nonce,
		operator_nonce: label32(operator_nonce), exit_delay: delay(), asset, value: V, chain: net.chain, operator: xonly(&k.operator),
		landing: None, enclave: Some(k.enclave(holder, clawback)),
	}
}

fn fee_source(c: &Coin) -> FeeSource {
	FeeSource::Coin { outpoint: c.outpoint, coin: c.txout.clone(), fee: FEE, change: op_true_spk() }
}

/// A spend of `coin` by `script` of `tap` into `outs`, a fee coin of the
/// policy asset attached at input 1, with `below` under the script, each key
/// signing input 0's signature hash in the order given.
fn script_spend(net: &mut Net, coin: &Coin, seq: u32, outs: Vec<elements::TxOut>, script: &Script, control: Vec<u8>,
	signers: &[&Keypair]) -> Transaction
{
	let fc = net.fee_coin();
	let change = fc.txout.value.explicit().unwrap() - FEE;
	let mut sp = spend(0).coin(coin, seq).coin(&fc, 0xffff_ffff).outputs(outs)
		.output(explicit(net.policy, change, op_true_spk())).output(fee(net.policy, FEE));
	let mut items: Vec<Vec<u8>> = signers.iter().map(|k| sp.sign(k, 0, script, net.genesis).as_ref().to_vec()).collect();
	items.reverse();
	items.push(script.to_bytes());
	items.push(control);
	sp.witness(0, items);
	sp.witness(1, op_true_witness());
	sp.tx
}

#[test]
fn the_enclave_is_openampds() {
	let v: Value = serde_json::from_str(include_str!("openamp_enclave_vectors.json")).unwrap();
	let x = |k: &str| elements::secp256k1_zkp::XOnlyPublicKey::from_slice(
		&elements::hex::FromHex::from_hex(v["enclave"][k].as_str().unwrap()).map(|b: Vec<u8>| b).unwrap()).unwrap();
	let with = Enclave { holder: x("user_x"), policy: x("policy_x"), clawback: Some(x("issuer_x")) };
	assert_eq!(hexs(with.transfer_script().as_bytes()), v["enclave"]["transfer_script"].as_str().unwrap());
	assert_eq!(hexs(with.claw_script().unwrap().as_bytes()), v["enclave"]["claw_script"].as_str().unwrap());
	assert_eq!(hexs(with.script_pubkey().as_bytes()), v["enclave"]["spk"].as_str().unwrap());
	assert_eq!(hexs(&with.taproot().control_block(&with.claw_script().unwrap()).unwrap()), v["enclave"]["claw_control"].as_str().unwrap());
	let without = Enclave { clawback: None, ..with };
	assert_eq!(hexs(without.script_pubkey().as_bytes()), v["enclave_single"]["spk"].as_str().unwrap());
	assert_eq!(hexs(&without.taproot().control_block(&without.transfer_script()).unwrap()), v["enclave_single"]["control"].as_str().unwrap());
	println!("enclave: openampd's vectors, with and without clawback, byte for byte");
}

#[test]
fn records_carry_the_enclave() {
	let k = Keys::new();
	let net_chain = arca_covenant::Chain::new(elements::BlockHash::from_byte_array([3; 32]));
	let a = asset("restricted");
	for clawback in [false, true] {
		let nonce = label32("records nonce");
		let b = BoardRecord {
			template: Template::Board1, owner: enclave_key(&xonly(&k.h1), &nonce).unwrap(), owner_nonce: nonce,
			operator_nonce: label32("op"), exit_delay: delay(), asset: a, value: V, chain: net_chain, operator: xonly(&k.operator),
			landing: None, enclave: Some(k.enclave(&k.h1, clawback)),
		};
		let bytes = b.to_bytes().unwrap();
		assert_eq!(bytes[0], 4);
		assert_eq!(BoardRecord::from_bytes(&bytes).unwrap(), b);
		assert_eq!(BoardRecord::from_json_str(&b.to_json_string().unwrap()).unwrap(), b);
		assert_eq!(b.leaf().template(), Template::Enclave1);
		// The owner key must be the holder's for the nonce.
		let wrong = BoardRecord { owner: xonly(&k.h1), ..b };
		assert_eq!(wrong.check().unwrap_err().kind(), "enclave");
		let p = arca_covenant::encode::Policy::Leaf(b.leaf());
		let enc = arca_covenant::encode::Encoding::encode(&p);
		assert_eq!(enc[1], 11);
		let back: arca_covenant::encode::Policy = arca_covenant::encode::Encoding::decode(&enc).unwrap();
		assert_eq!(back.script_pubkey(), b.leaf().script_pubkey());
	}
	println!("board record format 4, its JSON and the policy encoding (type 11) round-trip; a board whose owner key is not the holder's is refused");
}

#[test]
fn a_restricted_asset_stays_in_enclaves() {
	let mut net = Net::start();
	let k = Keys::new();
	let r = net.y; // not taken for fees, as a restricted asset is not
	let genesis = net.genesis;
	println!("restricted asset R = {}", r);

	// ---- a board of R with clawback, and the collaborative path -------------
	let n1 = label32("h1 board nonce");
	let b1 = board(&net, &k, &k.h1, n1, "board 1", r, true);
	let a1 = enclave_keypair(&k.h1, &n1).unwrap();
	assert_eq!(xonly(&a1), b1.owner);
	let p1 = b1.policy();
	println!("enclave-1 leaf: collab {} B, exit {} B, claw {} B; board convert {} B",
		b1.leaf().collab_script().len(), b1.leaf().exit_script().len(), b1.leaf().claw_script().unwrap().len(), p1.convert_script().len());
	let c1 = net.fund(vec![p1.output().txout()]).remove(0);
	println!("board of {} R confirmed at {}", V, c1.outpoint);

	// The coin moves to H2's enclave-1 leaf, its whole value, a fee coin of
	// the policy asset attached: the shape of a checkpoint or reassignment.
	let n2 = label32("h2 leaf nonce");
	let l2 = leaf(&net, &k, &k.h2, n2, "h2 leaf", r, V, true);
	let outs = vec![ExplicitOutput::new(r, V, l2.script_pubkey())];
	let collab = |net: &mut Net, prefix: &[u8]| {
		let m = arca_covenant::message::rebind_message(prefix, r, V, &outs).unwrap();
		let fc = net.fee_coin();
		let change = fc.txout.value.explicit().unwrap() - FEE;
		let mut sp = spend(0).coin(&c1, 0xffff_ffff).coin(&fc, 0xffff_ffff)
			.outputs(vec![outs[0].txout(), explicit(net.policy, change, op_true_spk()), fee(net.policy, FEE)]);
		sp.witness(0, p1.witness(&Pair { operator: sig(&k.operator, &m.digest), owner: sig(&a1, &m.digest) }, 1));
		sp.witness(1, op_true_witness());
		sp.tx
	};
	let plain = net.chain.leaf_constant(&b1.salt()).to_vec();
	let t = collab(&mut net, &plain);
	net.refuse("collab signed over the plain constant K (no enclave digest)", &t, "Invalid Schnorr signature");
	let other = net.chain.enclave_prefix(&b1.salt(), &k.enclave(&k.h2, true).digest());
	let t = collab(&mut net, &other);
	net.refuse("collab signed over another holder's K ‖ D", &t, "Invalid Schnorr signature");
	let t = collab(&mut net, &b1.leaf().collab_prefix());
	let txid = net.pass("collab of the board, K ‖ D, into H2's enclave-1 leaf (whole value, fee coin attached)", &t);
	let c2 = coin_of(txid, 0, &t);

	// ---- the exit: only to the holder's enclave, in full --------------------
	let a2 = enclave_keypair(&k.h2, &n2).unwrap();
	let exit_seq = delay().to_sequence();
	let exit_script = l2.exit_script();
	let control = l2.taproot().control_block(&exit_script).unwrap();
	let e2 = k.enclave(&k.h2, true);
	let e1 = k.enclave(&k.h1, true);
	let to = |spk: Script, asset: AssetId, value: u64| explicit(asset, value, spk);
	let t = script_spend(&mut net, &c2, exit_seq, vec![to(e2.script_pubkey(), r, V)], &exit_script, control.clone(), &[&a2]);
	net.refuse("enclave-1 exit before its delay", &t, "non-BIP68-final");
	net.wait_csv(&txid, delay());
	let t = script_spend(&mut net, &c2, exit_seq, vec![to(e1.script_pubkey(), r, V)], &exit_script, control.clone(), &[&a2]);
	net.refuse("enclave-1 exit to another holder's enclave", &t, "Script failed an OP_EQUALVERIFY operation");
	let t = script_spend(&mut net, &c2, exit_seq, vec![to(op_true_spk(), r, V)], &exit_script, control.clone(), &[&a2]);
	net.refuse("enclave-1 exit to another script (no enclave)", &t, "Script failed an OP_EQUALVERIFY operation");
	let t = script_spend(&mut net, &c2, exit_seq, vec![to(e2.script_pubkey(), r, V - 1), to(op_true_spk(), r, 1)], &exit_script,
		control.clone(), &[&a2]);
	net.refuse("enclave-1 exit one atom short (one atom elsewhere)", &t, "Script failed an OP_EQUALVERIFY operation");
	let x_coin = net.fund(vec![explicit(net.x, V, op_true_spk())]).remove(0);
	let t = {
		let fc = net.fee_coin();
		let change = fc.txout.value.explicit().unwrap() - FEE;
		let mut sp = spend(0).coin(&c2, exit_seq).coin(&x_coin, 0xffff_ffff).coin(&fc, 0xffff_ffff)
			.outputs(vec![to(e2.script_pubkey(), net.x, V), to(op_true_spk(), r, V), explicit(net.policy, change, op_true_spk()),
				fee(net.policy, FEE)]);
		let s = sp.sign(&a2, 0, &exit_script, genesis);
		sp.witness(0, vec![s.as_ref().to_vec(), exit_script.to_bytes(), control.clone()]);
		sp.witness(1, op_true_witness());
		sp.witness(2, op_true_witness());
		sp.tx
	};
	net.refuse("enclave-1 exit paying the enclave in another asset", &t, "Script failed an OP_EQUALVERIFY operation");
	let t = script_spend(&mut net, &c2, exit_seq, vec![to(e2.script_pubkey(), r, V)], &exit_script, control.clone(), &[&k.h2]);
	net.refuse("enclave-1 exit signed by the holder's registered key, not its leaf key", &t, "Invalid Schnorr signature");
	// The library builds the exit itself, and builds no other.
	let fc = net.fee_coin();
	assert!(l2.enclave_exit_tx(c2.outpoint, &FeeSource::Split { fee: FEE, change: op_true_spk() }).is_err());
	assert!(l2.exit_tx(c2.outpoint, r, V, &[ExplicitOutput::new(r, V, op_true_spk())], &fee_source(&fc)).is_err());
	let ks = l2.enclave_exit_tx(c2.outpoint, &fee_source(&fc)).unwrap();
	let s = sig(&a2, &ks.sighash(genesis).unwrap());
	let mut exit = ks.finish(vec![s.as_ref().to_vec()]).tx;
	exit.input[1].witness.script_witness = op_true_witness();
	let exit_txid = net.pass("enclave-1 exit into H2's enclave, the whole value, the fee from a coin attached", &exit);
	let landed = coin_of(exit_txid, 0, &exit);
	assert_eq!(landed.txout.script_pubkey, e2.script_pubkey());
	assert_eq!(landed.txout.value.explicit(), Some(V));

	// The landed coin is an enclave coin: its own transfer leaf, the holder's
	// key and the policy key, spends it, and the holder's key alone does not.
	let tscript = e2.transfer_script();
	let tcontrol = e2.taproot().control_block(&tscript).unwrap();
	let t = script_spend(&mut net, &landed, 0xffff_ffff, vec![to(op_true_spk(), r, V)], &tscript, tcontrol.clone(), &[&k.h2, &k.operator]);
	net.refuse("the landed enclave coin spent with the holder's key and the operator's (no policy key)", &t, "Invalid Schnorr signature");
	let t = script_spend(&mut net, &landed, 0xffff_ffff, vec![to(e1.script_pubkey(), r, V)], &tscript, tcontrol, &[&k.h2, &k.policy]);
	net.pass("the landed enclave coin spent by its transfer leaf (holder and policy key) to H1's enclave", &t);

	// ---- the clawback where the asset elected it ----------------------------
	let issuer_enclave = k.enclave(&k.issuer_holder, true);
	let n3 = label32("h1 board 2 nonce");
	let b3 = board(&net, &k, &k.h1, n3, "board 2", r, true);
	let c3 = net.fund(vec![b3.output().txout()]).remove(0);
	let claw = b3.leaf().claw_script().unwrap();
	let ccontrol = b3.policy().taproot().control_block(&claw).unwrap();
	let t = script_spend(&mut net, &c3, 0xffff_ffff, vec![to(issuer_enclave.script_pubkey(), r, V)], &claw, ccontrol.clone(),
		&[&k.issuer, &k.operator]);
	net.refuse("clawback of a board signed by the issuer and the operator (no policy key)", &t, "Invalid Schnorr signature");
	let fc = net.fee_coin();
	let ks = b3.policy().claw_tx(c3.outpoint, &[issuer_enclave.output_of(r, V)], &fee_source(&fc)).unwrap();
	let h = ks.sighash(genesis).unwrap();
	let mut t = ks.finish(vec![sig(&k.policy, &h).as_ref().to_vec(), sig(&k.issuer, &h).as_ref().to_vec()]).tx;
	t.input[1].witness.script_witness = op_true_witness();
	net.pass("clawback of a board by its claw leaf (issuer and policy key) into the issuer's enclave, no delay", &t);

	// A leaf on the chain: the board converted by its owner, then clawed back
	// at once, before the owner's exit delay.
	let n4 = label32("h1 board 3 nonce");
	let b4 = board(&net, &k, &k.h1, n4, "board 3", r, true);
	let c4 = net.fund(vec![b4.output().txout()]).remove(0);
	let fc = net.fee_coin();
	let ks = b4.policy().conversion(c4.outpoint, &fee_source(&fc)).unwrap();
	let a4 = enclave_keypair(&k.h1, &n4).unwrap();
	let h = ks.sighash(genesis).unwrap();
	let mut conv = ks.finish(vec![sig(&a4, &h).as_ref().to_vec()]).tx;
	conv.input[1].witness.script_witness = op_true_witness();
	let conv_txid = net.pass("conversion of an enclave-1 board into its leaf", &conv);
	let leaf4 = coin_of(conv_txid, 0, &conv);
	let fc = net.fee_coin();
	let ks = b4.leaf().claw_tx(leaf4.outpoint, &[issuer_enclave.output_of(r, V)], &fee_source(&fc)).unwrap();
	let h = ks.sighash(genesis).unwrap();
	let mut t = ks.finish(vec![sig(&k.policy, &h).as_ref().to_vec(), sig(&k.issuer, &h).as_ref().to_vec()]).tx;
	t.input[1].witness.script_witness = op_true_witness();
	net.pass("clawback of an enclave-1 leaf by its claw leaf into the issuer's enclave, before the owner's delay", &t);

	// ---- no clawback where the asset elected none ---------------------------
	let n5 = label32("h1 board no claw nonce");
	let b5 = board(&net, &k, &k.h1, n5, "board no claw", r, false);
	assert!(b5.leaf().claw_script().is_err());
	let c5 = net.fund(vec![b5.output().txout()]).remove(0);
	// The claw leaf the asset would have had, and the control block of the
	// tree that would have held it: no such leaf is in this output.
	let would = board(&net, &k, &k.h1, n5, "board no claw", r, true);
	let wclaw = would.leaf().claw_script().unwrap();
	let wcontrol = would.policy().taproot().control_block(&wclaw).unwrap();
	let noclaw_enclave = k.enclave(&k.issuer_holder, false);
	let t = script_spend(&mut net, &c5, 0xffff_ffff, vec![to(noclaw_enclave.script_pubkey(), r, V)], &wclaw, wcontrol,
		&[&k.issuer, &k.policy]);
	net.refuse("clawback of a board of an asset that elected none", &t, "Witness program hash mismatch");
	let fc = net.fee_coin();
	let ks = b5.policy().conversion(c5.outpoint, &fee_source(&fc)).unwrap();
	let a5 = enclave_keypair(&k.h1, &n5).unwrap();
	let h = ks.sighash(genesis).unwrap();
	let mut conv = ks.finish(vec![sig(&a5, &h).as_ref().to_vec()]).tx;
	conv.input[1].witness.script_witness = op_true_witness();
	let conv_txid = net.pass("conversion of a board of an asset without clawback into its leaf", &conv);
	let leaf5 = coin_of(conv_txid, 0, &conv);
	let wcontrol = would.leaf().taproot().control_block(&wclaw).unwrap();
	let t = script_spend(&mut net, &leaf5, 0xffff_ffff, vec![to(noclaw_enclave.script_pubkey(), r, V)], &wclaw, wcontrol,
		&[&k.issuer, &k.policy]);
	net.refuse("clawback of an enclave-1 leaf of an asset that elected none", &t, "Witness program hash mismatch");
	assert!(b5.leaf().claw_tx(leaf5.outpoint, &[noclaw_enclave.output_of(r, V)], &fee_source(&net.fee_coin())).is_err());

	net.print();
}

trait OutputOf {
	fn output_of(&self, asset: AssetId, value: u64) -> ExplicitOutput;
}

impl OutputOf for Enclave {
	fn output_of(&self, asset: AssetId, value: u64) -> ExplicitOutput {
		ExplicitOutput::new(asset, value, self.script_pubkey())
	}
}
