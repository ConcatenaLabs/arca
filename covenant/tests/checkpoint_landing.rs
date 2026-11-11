//! A swap of a supervised asset's coin whose checkpoint carries its owner's
//! exit, on regtest: the exit is the coin's landing, so the issuer's rules
//! hold on the way home.
//!
//! A gives a `landing-1` coin of the supervised asset Z, C gives X, in one
//! reassignment whose checkpoints both have their owners' exit. A's
//! checkpoint is `[collab, landing]`: the landing pays P2WPKH of A's landing
//! key, in Z, explicitly, at least the checkpoint's value less the coin's
//! allowance.
//!
//! - Dead swap: C and the operator spend C's checkpoint elsewhere. A's
//!   landing from its checkpoint is refused before its delay, signed by the
//!   operator, to another key's P2WPKH, to a taproot output, in another
//!   asset, one atom below the minimum, and by the plain exit script (no leaf
//!   of the checkpoint); under a pause, with the checkpoint's script named in
//!   a freeze, it confirms, and the landed coin is frozen by the pause, then
//!   by a freeze of its address, and spent once that is lifted.
//! - Good swap: it completes inside the delay; the landing after it is
//!   refused.
//! - Rollback: the block holding A's checkpoint leaves the chain and the
//!   checkpoint confirms again later; the landing waits the delay from the
//!   new block.
//! - Two landings together: two of A's checkpoints landing at one key,
//!   spent in one transaction sharing output 0 while output 1 pays another
//!   script, are refused (each landing inspects the output at its own
//!   input's index); each landing at its own index, they confirm.
//!
//! Needs `SEQUENTIAD_EXEC`.

mod common;

use std::str::FromStr;

use elements::encode::{deserialize, serialize};
use elements::hashes::{hash160, Hash};
use elements::hex::FromHex;
use elements::secp256k1_zkp::{Keypair, Message, Secp256k1};
use elements::sighash::SighashCache;
use elements::{AssetId, EcdsaSighashType, OutPoint, Script, Transaction, TxOut};
use serde_json::{json, Value};

use arca_covenant::script::sha256;
use arca_covenant::spend::FeeSource;
use arca_covenant::transfer::{reassignment_tx, COIN_RECORD_VERSION_EXIT};
use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeParams};
use arca_covenant::*;

use common::chain::{record_for, sign_plan};
use common::net::*;
use common::round::*;
use common::*;

const ALLOWANCE: u64 = 2_000;
const FEE: u64 = 400;
const SIG: &str = "Invalid Schnorr signature";
const GONE: &str = "bad-txns-inputs-missingorspent";
const EQ: &str = "Script failed an OP_EQUALVERIFY operation";

static ONE_NODE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A batch of `asset` without a sweep (or with `sched`'s), RECLAIM-D on its
/// lowest nodes, as the testnet's operator builds them.
fn tree_of(c: &Arca, s: &Keypair, asset: AssetId, sched: Option<&ClockSchedule>, leaves: &[LeafSpec]) -> Tree {
	Tree::build(TreeParams {
		asset, chain: c.net.chain, schedule: sched.cloned().unwrap_or_else(|| ClockSchedule::never(xonly(s))), burn: false,
		delegated_reclaim: true, radix: 4, reserve: ReserveRule::FeeRate { floor_per_kvb: c.floor_per_kvb, multiple: 4 }, min_leaf: 1,
	}, leaves).unwrap()
}

/// A round paying `batch`, with a connector output in X and, for a batch
/// with a sweep, the clock's token from `sched`'s issuer.
fn round(c: &mut Arca, name: &str, s: &Keypair, batch: &ExplicitOutput, clock: Option<(&Coin, &ClockSchedule)>) -> Transaction {
	if let Some((issuer, sched)) = clock {
		if batch.asset == c.net.x {
			let (tx, _) = round_tx(&c.net, issuer, &[], batch, sched);
			c.net.pass(name, &tx);
			return tx;
		}
		// The batch in another asset: its value from a coin of that asset.
		let funds = c.net.fund(vec![explicit(batch.asset, batch.value, op_true_spk())]).remove(0);
		let xin = issuer.txout.value.explicit().unwrap();
		let mut sp = spend(0).coin(issuer, 0xffff_ffff).coin(&funds, 0xffff_ffff).outputs(vec![batch.txout(),
			explicit(sched.token, 1, sched.clock0_script_pubkey()), ConnectorPolicy { operator: sched.operator }.output(c.net.x, 5_000).txout(),
			explicit(c.net.x, xin - 5_000 - 2_000, op_true_spk()), fee(c.net.x, 2_000)]);
		sp.tx.input[0].asset_issuance = elements::AssetIssuance {
			asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: [0; 32],
			amount: elements::confidential::Value::Explicit(1), inflation_keys: elements::confidential::Value::Null, denomination: 0,
		};
		sp.witness(0, op_true_witness());
		sp.witness(1, op_true_witness());
		c.net.pass(name, &sp.tx);
		return sp.tx;
	}
	let x = c.net.x;
	let mut outs = vec![explicit(x, 200_000, op_true_spk())];
	if batch.asset != x {
		outs.push(explicit(batch.asset, batch.value, op_true_spk()));
	} else {
		outs[0] = explicit(x, batch.value + 200_000, op_true_spk());
	}
	let coins = c.net.fund(outs);
	let xin = coins[0].txout.value.explicit().unwrap();
	let xb = if batch.asset == x { batch.value } else { 0 };
	let out = vec![batch.txout(), ConnectorPolicy { operator: xonly(s) }.output(x, 5_000).txout(),
		explicit(x, xin - xb - 5_000 - 2_000, op_true_spk()), fee(x, 2_000)];
	let mut sp = spend(0);
	for k in &coins {
		sp = sp.coin(k, 0xffff_ffff);
	}
	let mut sp = sp.outputs(out);
	for i in 0..coins.len() {
		sp.witness(i, op_true_witness());
	}
	c.net.pass(name, &sp.tx);
	sp.tx
}

/// Brings a batch leaf on-chain, skipping the nodes already there.
fn bring(c: &mut Arca, name: &str, coin: &ValidCoin) -> OutPoint {
	let ValidOrigin::Leaf { valid, preimage, auths } = &coin.origin else { unreachable!() };
	let txs = valid.branch.unroll(OutPoint::new(valid.round_txid, valid.batch_vout), auths,
		&vec![FeeSource::Reserve; auths.len()]).unwrap();
	for (level, u) in txs.iter().enumerate() {
		if c.net.rt.client().confirmations(&u.tx.txid()).unwrap_or(0) == 0 {
			c.net.pass(&format!("{}: unroll, level {}", name, level), &u.tx);
		}
	}
	let e = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), preimage, &FeeSource::Reserve).unwrap();
	OutPoint::new(c.net.pass(&format!("{}: entry", name), &e.tx), 0)
}

fn thief() -> Script {
	op_true_spk()
}

/// The supervised asset and its operational key.
struct Supervised {
	z: AssetId,
	op: elements::secp256k1_zkp::Keypair,
}

fn hexs(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn tx_of(hex: &str) -> Transaction {
	deserialize(&Vec::<u8>::from_hex(hex).unwrap()).unwrap()
}

/// The address the node prints for `spk`.
fn address(net: &Net, spk: &Script) -> String {
	let d = net.rpc("decodescript", json!([hexs(spk.as_bytes())]));
	d["address"].as_str().or_else(|| d["segwit"]["address"].as_str())
		.unwrap_or_else(|| panic!("no address for {}: {}", spk, d)).to_string()
}

/// `Z`, issued supervised with the pause capability, 10^9 atoms to the OP_TRUE
/// tapscript, its reissuance token there too; listed for fees at 1:1.
fn issue(net: &mut Net) -> Supervised {
	let op = keypair("supervision operational");
	let rec = keypair("supervision recovery");
	let coin = net.fund(vec![explicit(net.policy, 50_000_000, op_true_spk())]).remove(0);
	let s = spend(0).coin(&coin, 0xffff_ffff).outputs(vec![explicit(net.policy, 50_000_000 - 10_000, op_true_spk()),
		fee(net.policy, 10_000)]);
	let to = address(net, &op_true_spk());
	let issued = net.rpc("rawissueasset", json!([hexs(&serialize(&s.tx)), [{
		"asset_amount": 10, "asset_address": to, "token_amount": 1, "token_address": to, "blind": false,
		"supervision": {"operationalkey": hexs(&xonly(&op).serialize()), "recoverykey": hexs(&xonly(&rec).serialize()), "pause": true},
	}]]));
	let mut tx = tx_of(issued[0]["hex"].as_str().unwrap());
	tx.input[0].witness.script_witness = op_true_witness();
	let txid = net.pass_quiet(&tx);
	let z = AssetId::from_str(issued[0]["asset"].as_str().unwrap()).unwrap();
	for (j, o) in tx.output.iter().enumerate() {
		if o.asset.explicit() == Some(z) && o.script_pubkey == op_true_spk() {
			net.purse.push(Coin { outpoint: OutPoint::new(txid, j as u32), txout: o.clone() });
		}
	}
	let listed = net.rpc("getsupervisedassets", json!([]));
	let entry = listed.as_array().unwrap().iter().find(|a| a["asset"] == z.to_string()).expect("Z is supervised");
	assert_eq!(entry["pauseallowed"], json!(true));
	let rates: Value = net.rpc("getfeeexchangerates", json!([]));
	let mut rates = rates.as_object().unwrap().clone();
	rates.insert(z.to_string(), json!(100_000_000));
	net.rpc("setfeeexchangerates", json!([Value::Object(rates)]));
	println!("Z {} issued supervised (pause allowed), listed for fees at 1:1", z);
	Supervised { z, op }
}

impl Supervised {
	/// A freeze record (`kind` freeze naming `target`, a scriptPubKey, or
	/// pause), signed by the operational key, its transaction confirmed.
	/// Returns the record's outpoint and its target hash.
	fn record(&self, net: &mut Net, kind: &str, target: Option<&Script>) -> (OutPoint, String) {
		let coin = net.fund(vec![explicit(net.policy, 20_000_000, op_true_spk())]).remove(0);
		let t = target.map(|s| json!(hexs(s.as_bytes()))).unwrap_or(Value::Null);
		let h = net.rpc("getsupervisionrecordhash", json!([kind, self.z.to_string(), t, null, coin.outpoint.txid.to_string(),
			coin.outpoint.vout]));
		let digest: [u8; 32] = Vec::<u8>::from_hex(h["sighash"].as_str().unwrap()).unwrap().try_into().unwrap();
		let built = net.rpc("buildsupervisionrecord", json!([kind, self.z.to_string(), t, null, hexs(sig(&self.op, &digest).as_ref())]));
		let s = spend(0).coin(&coin, 0xffff_ffff).outputs(vec![explicit(net.policy, 20_000_000 - 10_000, op_true_spk()),
			fee(net.policy, 10_000)]);
		let raw = net.rpc("addsupervisionrecordoutput", json!([hexs(&serialize(&s.tx)), built["script"], self.z.to_string()]));
		let mut tx = tx_of(raw.as_str().unwrap());
		tx.input[0].witness.script_witness = op_true_witness();
		let txid = net.pass_quiet(&tx);
		let vout = tx.output.iter().position(|o| o.script_pubkey.as_bytes() == Vec::<u8>::from_hex(built["script"].as_str().unwrap()).unwrap())
			.unwrap() as u32;
		(OutPoint::new(txid, vout), built["targethash"].as_str().unwrap().to_string())
	}

	/// Spends the record at `at`: the freeze it made is lifted.
	fn lift(&self, net: &mut Net, at: OutPoint, target: &str) {
		let h = net.rpc("getsupervisionunfreezehash", json!([at.txid.to_string(), at.vout, self.z.to_string(), target]));
		let digest: [u8; 32] = Vec::<u8>::from_hex(h.as_str().unwrap()).unwrap().try_into().unwrap();
		let coin = net.fund(vec![explicit(net.policy, 20_000_000, op_true_spk())]).remove(0);
		let record: Transaction = tx_of(net.rpc("getrawtransaction", json!([at.txid.to_string()])).as_str().unwrap());
		let s = spend(0).input(at, record.output[at.vout as usize].clone(), 0xffff_ffff).coin(&coin, 0xffff_ffff)
			.outputs(vec![explicit(net.policy, 20_000_000 - 10_000, op_true_spk()), fee(net.policy, 10_000)]);
		let raw = net.rpc("setsupervisionunfreezesig", json!([hexs(&serialize(&s.tx)), 0, hexs(sig(&self.op, &digest).as_ref())]));
		let mut tx = tx_of(raw.as_str().unwrap());
		tx.input[1].witness.script_witness = op_true_witness();
		net.pass_quiet(&tx);
	}

	fn status(&self, net: &Net, spk: &Script) -> Value {
		let s = net.rpc("isassetfrozen", json!([self.z.to_string(), hexs(spk.as_bytes())]));
		json!({"frozen": s["frozen"], "paused": s["paused"], "freezable": s["freezable"]})
	}
}

/// The P2WPKH spend of `coin` (a single-owner output of `key`) into the OP_TRUE
/// tapscript, its fee in the coin's asset.
fn p2wpkh_spend(coin: &Coin, key: &elements::secp256k1_zkp::Keypair) -> Transaction {
	let asset = coin.txout.asset.explicit().unwrap();
	let value = coin.txout.value.explicit().unwrap();
	let mut tx = spend(0).coin(coin, 0xffff_ffff).outputs(vec![explicit(asset, value - FEE, op_true_spk()), fee(asset, FEE)]).tx;
	let pk = key.public_key();
	let code = Script::new_p2pkh(&elements::PubkeyHash::from_byte_array(hash160::Hash::hash(&pk.serialize()).to_byte_array()));
	let sh = SighashCache::new(&tx).segwitv0_sighash(0, &code, coin.txout.value, EcdsaSighashType::All);
	let secp = Secp256k1::new();
	let sig = secp.sign_ecdsa(&Message::from_digest(sh.to_byte_array()), &key.secret_key());
	let mut der = sig.serialize_der().to_vec();
	der.push(EcdsaSighashType::All as u8);
	tx.input[0].witness.script_witness = vec![der, pk.serialize().to_vec()];
	tx
}

/// A `landing-1` leaf spec of Z for `owner`, landing at `program`.
fn landing_spec(owner: &Keypair, label: &str, program: [u8; 20], h: [u8; 32]) -> LeafSpec {
	LeafSpec { template: Template::Landing1, landing: Some(Landing { program, allowance: ALLOWANCE, own_index: false }), ..spec(owner, label, LEAF, h) }
}

/// A's landing from its checkpoint `cp` at `at` (holding `value` of `asset`)
/// into `outs`, input 0's sequence `seq`, signed by `key`, built by hand so
/// that every refused form can be tried.
fn land(c: &Arca, cp: &CheckpointPolicy, script: &Script, at: OutPoint, asset: AssetId, value: u64, outs: Vec<TxOut>, key: &Keypair, seq: u32)
	-> Transaction
{
	let tap = cp.taproot();
	let mut sp = spend(0).input(at, explicit(asset, value, cp.script_pubkey()), seq).outputs(outs);
	let sg = sp.sign(key, 0, script, c.net.genesis);
	sp.witness(0, tap.witness(script, vec![sg.as_ref().to_vec()]));
	sp.tx
}

struct Case {
	cp: CheckpointPolicy,
	at: OutPoint,
	cp_id: elements::Txid,
	value: u64,
	swap: Transaction,
	land_spk: Script,
}

/// A's Z coin `i` of `tz` swapped for C's X coin `i` of `tx_`: C's
/// checkpoint published (and, when `dead`, spent elsewhere by C and the
/// operator), A's leaf brought on and its checkpoint published.
#[allow(clippy::too_many_arguments)]
fn swap_case(c: &mut Arca, tag: &str, s: &Keypair, rounds: &[Transaction], (tz, tx_): (&Tree, &Tree), i: usize,
	(ak, ck): (&Keypair, &Keypair), pre: ([u8; 32], [u8; 32]), l: &Keypair, dead: bool, t: MedianTime) -> Case
{
	let (z, x) = (tz.batch_output().asset, c.net.x);
	let policy = WalletPolicy { now: mt(c.net.mtp()), ..WalletPolicy::new(c.net.chain, xonly(s), mt(c.net.mtp())) };
	let ab = base(tz, i, ak, pre.0, t);
	let cb = base(tx_, i, ck, pre.1, t);
	let (acoin, ccoin) = (ab.resolve(rounds, &policy).unwrap(), cb.resolve(rounds, &policy).unwrap());
	assert_eq!(acoin.leaf.template(), Template::Landing1);
	let landing = acoin.leaf.landing.unwrap();
	let (_, mut cz_leaf) = party(&format!("{} C gets Z", tag), delay());
	cz_leaf.landing = Some(LandingTerms { program: hash160::Hash::hash(&keypair(&format!("{} C landing", tag)).public_key().serialize())
		.to_byte_array(), asset: z, min_value: 1, own_index: false });
	let (_, ax_leaf) = party(&format!("{} A gets X", tag), delay());
	let (az_v, ax_v) = (LEAF - MARGIN, LEAF - 2 * MARGIN);
	cz_leaf.landing = Some(Landing { program: cz_leaf.landing.unwrap().program, allowance: ALLOWANCE, own_index: false }.terms(z, az_v).unwrap());
	let plan = TransferPlan { checkpoint_exit: true, inputs: vec![(acoin.clone(), LEAF - MARGIN), (ccoin.clone(), LEAF - MARGIN)],
		outputs: vec![ExplicitOutput::new(z, az_v, cz_leaf.policy(xonly(s), c.net.chain).script_pubkey()),
			ExplicitOutput::new(x, ax_v, ax_leaf.policy(xonly(s), c.net.chain).script_pubkey())] };
	assert!(plan.exit(0) && plan.exit(1), "a landing-1 coin's checkpoint has its exit");
	let pw = sign_plan(&plan, &[ak, ck], s);
	let rec = record_for(&plan, &[&ab, &cb], &pw, 1, ax_leaf);
	assert_eq!(rec.to_bytes().unwrap()[0], COIN_RECORD_VERSION_EXIT);
	assert_eq!(CoinRecord::from_bytes(&rec.to_bytes().unwrap()).unwrap(), rec);
	let got = rec.validate(rounds, &policy.receipt(), &ax_leaf.owner, &ax_leaf.owner_nonce).unwrap();
	let ValidOrigin::Transfer { inputs, .. } = &got.origin else { unreachable!() };
	let cp = inputs[0].checkpoint;
	let value = inputs[0].checkpoint_value;
	let e = cp.exit.unwrap();
	assert_eq!(e.delay, acoin.leaf.exit_delay);
	assert_eq!(e.landing, Some(LandingTerms { min_value: value - ALLOWANCE, own_index: true, ..landing }), "the landing over the checkpoint's value");
	assert_eq!(e.landing.unwrap().script_pubkey(), Landing { program: landing.program, allowance: 0, own_index: false }.script_pubkey());
	let _ = l;
	let c_at = bring(c, &format!("{}/C's leaf on-chain", tag), &ccoin);
	let fc = c.net.fee_coin();
	let fs = FeeSource::Coin { outpoint: fc.outpoint, coin: fc.txout, fee: 4_000, change: op_true_spk() };
	let mut ctx = inputs[1].checkpoint_tx(c_at, &fs).unwrap().tx;
	let n = ctx.input.len();
	ctx.input[n - 1].witness.script_witness = op_true_witness();
	let ccp = OutPoint::new(c.net.pass(&format!("{}/C's checkpoint", tag), &ctx), 0);
	if dead {
		let back = vec![ExplicitOutput::new(x, inputs[1].checkpoint_value - MARGIN, thief())];
		let bp = TransferPlan { checkpoint_exit: true, inputs: vec![(ccoin.clone(), inputs[1].checkpoint_value)], outputs: back.clone() };
		let d = bp.reassignment_message(0).unwrap().digest;
		let second = ValidInput { reassignment_pair: Pair { operator: sig(s, &d), owner: sig(ck, &d) }, ..inputs[1].clone() };
		c.net.pass(&format!("{}/ATTACK C + operator: a second reassignment of C's checkpoint", tag),
			&reassignment_tx(&[second], &back, &[ccp], &FeeSource::Reserve).unwrap().tx);
	}
	let a_at = bring(c, &format!("{}/A's Z leaf on-chain", tag), &acoin);
	let fc = c.net.fee_coin();
	let fs = FeeSource::Coin { outpoint: fc.outpoint, coin: fc.txout, fee: 4_000, change: op_true_spk() };
	let mut atx = inputs[0].checkpoint_tx(a_at, &fs).unwrap().tx;
	let n = atx.input.len();
	atx.input[n - 1].witness.script_witness = op_true_witness();
	let cp_id = c.net.pass(&format!("{}/A's checkpoint, its exit the landing", tag), &atx);
	let fc = c.net.fee_coin();
	let fs = FeeSource::Coin { outpoint: fc.outpoint, coin: fc.txout, fee: 6_000, change: op_true_spk() };
	let mut swap = got.reassignment_tx(&[OutPoint::new(cp_id, 0), ccp], &fs).unwrap().tx;
	let n = swap.input.len();
	swap.input[n - 1].witness.script_witness = op_true_witness();
	Case { cp, at: OutPoint::new(cp_id, 0), cp_id, value, swap, land_spk: e.landing.unwrap().script_pubkey() }
}

#[test]
fn a_dead_swap_returns_a_supervised_coin_by_its_landing() {
	let _one = ONE_NODE.lock().unwrap_or_else(|e| e.into_inner());
	let mut c = Arca::start();
	let sup = issue(&mut c.net);
	let (z, x) = (sup.z, c.net.x);
	let s = keypair("ob1 sup operator");
	let ak: Vec<Keypair> = (0..5).map(|i| keypair(&format!("ob1 sup A{}", i))).collect();
	let ck: Vec<Keypair> = (0..5).map(|i| keypair(&format!("ob1 sup C{}", i))).collect();
	let l = keypair("ob1 sup A landing key");
	let program = hash160::Hash::hash(&l.public_key().serialize()).to_byte_array();
	let apre: Vec<[u8; 32]> = (0..5).map(|i| label32(&format!("ob1 sup A pre {}", i))).collect();
	let cpre: Vec<[u8; 32]> = (0..5).map(|i| label32(&format!("ob1 sup C pre {}", i))).collect();
	let zs: Vec<LeafSpec> = (0..5).map(|i| landing_spec(&ak[i], &format!("ob1 sup A leaf {}", i), program, sha256(&apre[i]))).collect();
	let xs: Vec<LeafSpec> = (0..5).map(|i| spec(&ck[i], &format!("ob1 sup C leaf {}", i), LEAF, sha256(&cpre[i]))).collect();
	let tz = tree_of(&c, &s, z, None, &zs);
	let tx_ = tree_of(&c, &s, x, None, &xs);
	let rz = round(&mut c, "round of Z, landing-1 leaves (no sweep)", &s, &tz.batch_output(), None);
	let rx = round(&mut c, "round of X (no sweep)", &s, &tx_.batch_output(), None);
	let rounds = vec![rz, rx];
	let t0 = mt(c.net.mtp() - 60);
	let seq = delay().to_sequence();

	// ---- dead -------------------------------------------------------------
	let d = swap_case(&mut c, "dead", &s, &rounds, (&tz, &tx_), 0, (&ak[0], &ck[0]), (apre[0], cpre[0]), &l, true, t0);
	let script = d.cp.exit_script().unwrap();
	let good = |v: u64| vec![explicit(z, v - FEE, d.land_spk.clone()), fee(z, FEE)];
	c.net.refuse("dead/neg the landing from the checkpoint before its delay", &land(&c, &d.cp, &script, d.at, z, d.value, good(d.value), &ak[0], seq),
		"non-BIP68-final");
	c.net.refuse("dead/neg the swap's reassignment", &d.swap, GONE);
	// Under a pause, with the checkpoint's script named in a freeze.
	let (pause, _) = sup.record(&mut c.net, "pause", None);
	let _named = sup.record(&mut c.net, "freeze", Some(&d.cp.script_pubkey()));
	c.net.mine(1);
	println!("paused, the checkpoint's script named: isassetfrozen on the checkpoint {} (its script path is not single-owner)",
		sup.status(&c.net, &d.cp.script_pubkey()));
	c.net.wait_csv(&d.cp_id, delay());
	c.net.refuse("dead/neg the landing signed by the operator", &land(&c, &d.cp, &script, d.at, z, d.value, good(d.value), &s, seq), SIG);
	let other = Landing { program: hash160::Hash::hash(&keypair("another key").public_key().serialize()).to_byte_array(), allowance: 0, own_index: false };
	c.net.refuse("dead/neg the landing to another key's P2WPKH", &land(&c, &d.cp, &script, d.at, z, d.value,
		vec![explicit(z, d.value - FEE, other.script_pubkey()), fee(z, FEE)], &ak[0], seq), EQ);
	c.net.refuse("dead/neg the landing to a taproot output", &land(&c, &d.cp, &script, d.at, z, d.value,
		vec![explicit(z, d.value - FEE, op_true_spk()), fee(z, FEE)], &ak[0], seq), EQ);
	c.net.refuse("dead/neg the landing one atom below the checkpoint's value less the allowance", &land(&c, &d.cp, &script, d.at, z, d.value,
		vec![explicit(z, d.value - ALLOWANCE - 1, d.land_spk.clone()), explicit(z, ALLOWANCE + 1 - FEE, op_true_spk()), fee(z, FEE)], &ak[0], seq),
		"Script failed an OP_VERIFY operation");
	// The plain exit, the leaf's own form for a coin with no landing, is no
	// leaf of this checkpoint.
	let plain = CheckpointPolicy { exit: Some(CheckpointExit::plain(delay())), ..d.cp }.exit_script().unwrap();
	let mut sp = spend(0).input(d.at, explicit(z, d.value, d.cp.script_pubkey()), seq)
		.outputs(vec![explicit(z, d.value - FEE, op_true_spk()), fee(z, FEE)]);
	let plain_tap = arca_covenant::taptree::TapOutput::new(vec![(1, d.cp.collab_script()), (1, plain.clone())]);
	let sg = sp.sign(&ak[0], 0, &plain, c.net.genesis);
	sp.witness(0, plain_tap.witness(&plain, vec![sg.as_ref().to_vec()]));
	c.net.refuse("dead/neg the plain exit, past the landing, on the checkpoint", &sp.tx, "Witness program hash mismatch");
	// The builder refuses an exit that does not land, before any signature.
	assert!(matches!(d.cp.exit_tx(d.at, z, d.value, &[ExplicitOutput::new(z, d.value - FEE, op_true_spk())], &FeeSource::Reserve),
		Err(arca_covenant::SpendError::Landing(_))));
	let ks = d.cp.exit_tx(d.at, z, d.value, &[ExplicitOutput::new(z, d.value - FEE, d.land_spk.clone())], &FeeSource::Reserve).unwrap();
	let home = signed(&c.net, ks, &ak[0], vec![]).tx;
	let landed_at = c.net.pass("dead/A's coin lands from its checkpoint under the pause, the checkpoint's script named, no operator", &home);
	let landed = coin_of(landed_at, 0, &home);
	assert_eq!(landed.txout.script_pubkey, d.land_spk);
	c.net.refuse("dead/neg the landed coin spent under the pause", &p2wpkh_spend(&landed, &l), "bad-txns-asset-frozen");
	let (freeze, target) = sup.record(&mut c.net, "freeze", Some(&d.land_spk));
	sup.lift(&mut c.net, pause, &"00".repeat(32));
	c.net.mine(1);
	c.net.refuse("dead/neg the landed coin spent, its address frozen", &p2wpkh_spend(&landed, &l), "bad-txns-asset-frozen");
	sup.lift(&mut c.net, freeze, &target);
	c.net.mine(1);
	c.net.pass("dead/the landed coin spent once its freeze is lifted", &p2wpkh_spend(&landed, &l));

	// ---- good -------------------------------------------------------------
	let g = swap_case(&mut c, "good", &s, &rounds, (&tz, &tx_), 1, (&ak[1], &ck[1]), (apre[1], cpre[1]), &l, false, t0);
	let gscript = g.cp.exit_script().unwrap();
	let id = c.net.pass("good/the swap's reassignment inside the delay", &g.swap);
	c.net.wait_csv(&id, delay());
	c.net.refuse("good/neg A lands its checkpoint after the swap completed", &land(&c, &g.cp, &gscript, g.at, z, g.value,
		vec![explicit(z, g.value - FEE, g.land_spk.clone()), fee(z, FEE)], &ak[1], seq), GONE);

	// ---- rollback ----------------------------------------------------------
	let r = swap_case(&mut c, "rollback", &s, &rounds, (&tz, &tx_), 2, (&ak[2], &ck[2]), (apre[2], cpre[2]), &l, true, t0);
	let rscript = r.cp.exit_script().unwrap();
	let block = c.net.rpc("getrawtransaction", json!([r.cp_id.to_string(), true]))["blockhash"].clone();
	c.net.wait_csv(&r.cp_id, delay());
	c.net.rpc("invalidateblock", json!([block]));
	c.net.mine(1);
	let conf = c.net.rt.client().confirmations(&r.cp_id).unwrap_or(0);
	println!("rollback: A's checkpoint taken out with its block and mined again, {} confirmation(s)", conf);
	assert!(conf >= 1, "the checkpoint is in the new chain");
	c.net.refuse("rollback/neg the landing at the old deadline, the checkpoint in a later block", &land(&c, &r.cp, &rscript, r.at, z, r.value,
		vec![explicit(z, r.value - FEE, r.land_spk.clone()), fee(z, FEE)], &ak[2], seq), "non-BIP68-final");
	c.net.wait_csv(&r.cp_id, delay());
	c.net.pass("rollback/the landing once the delay has run from the new block", &land(&c, &r.cp, &rscript, r.at, z, r.value,
		vec![explicit(z, r.value - FEE, r.land_spk.clone()), fee(z, FEE)], &ak[2], seq));

	// ---- two landings together (#763) --------------------------------------
	// Two dead swaps, A's coins landing at one landing key. Landed together,
	// each pays the output at its own index: sharing output 0 would carry
	// one coin's worth to any script, past the landing key where the
	// issuer's freeze binds. Under the leaf's script (output 0 inspected by
	// both) the first case is mined.
	let p = swap_case(&mut c, "pair one", &s, &rounds, (&tz, &tx_), 3, (&ak[3], &ck[3]), (apre[3], cpre[3]), &l, true, t0);
	let q = swap_case(&mut c, "pair two", &s, &rounds, (&tz, &tx_), 4, (&ak[4], &ck[4]), (apre[4], cpre[4]), &l, true, t0);
	assert_eq!(p.land_spk, q.land_spk, "one landing key");
	c.net.wait_csv(&p.cp_id, delay());
	c.net.wait_csv(&q.cp_id, delay());
	let both = |c: &Arca, outs: Vec<TxOut>| -> Transaction {
		let (ps, qs) = (p.cp.exit_script().unwrap(), q.cp.exit_script().unwrap());
		let mut sp = spend(0).input(p.at, explicit(z, p.value, p.cp.script_pubkey()), seq)
			.input(q.at, explicit(z, q.value, q.cp.script_pubkey()), seq).outputs(outs);
		let (s0, s1) = (sp.sign(&ak[3], 0, &ps, c.net.genesis), sp.sign(&ak[4], 1, &qs, c.net.genesis));
		sp.witness(0, p.cp.taproot().witness(&ps, vec![s0.as_ref().to_vec()]));
		sp.witness(1, q.cp.taproot().witness(&qs, vec![s1.as_ref().to_vec()]));
		sp.tx
	};
	let shared = p.value.max(q.value) - ALLOWANCE;
	let attack = both(&c, vec![explicit(z, shared, p.land_spk.clone()), explicit(z, p.value + q.value - shared - FEE, op_true_spk()),
		fee(z, FEE)]);
	c.net.refuse("pair/neg both landed sharing output 0, output 1 paying another script", &attack, EQ);
	let home = both(&c, vec![explicit(z, p.value - FEE, p.land_spk.clone()), explicit(z, q.value, q.land_spk.clone()), fee(z, FEE)]);
	c.net.pass("pair/both landed together, each at its own index", &home);
	c.net.print();
}
