//! `landing-1` on a real node: a supervised asset in a tree, frozen.
//!
//! A supervised asset `Z` is issued under the supervision descriptor, with the
//! pause capability, on an anchored regtest chain whose node checks scripts
//! inline (`-par=1`). A `landing-1` leaf of `Z` is spent by its collaborative
//! path and by its landing; every negative case is refused by the mempool and
//! again when forced into a block, the block refused for the script's reason:
//!
//! - the landing before its delay, paying another key's P2WPKH, a taproot
//!   output, another asset, or one atom below the leaf's value less the
//!   allowance;
//! - the collaborative path signed over the plain constant (no landing
//!   program), and over another landing's prefix;
//! - a round of `Z` with a blinded output (`bad-txns-supervised-blinded`),
//!   beside the same round all explicit, which confirms, and the same blinding
//!   in a round of an open asset, which confirms too.
//!
//! The operator's signature read back from the confirmed collaborative spend,
//! beside a second one under the same salt, is evidence the equivocation bond
//! takes, and the bond is burned with it in a block.
//!
//! Under a pause, with the leaf's own script named in a targeted freeze, the
//! landing confirms; the landed coin, a single-owner P2WPKH output of `Z`, is
//! frozen by the pause and then by a freeze of its address, and spent once
//! that freeze is lifted.

mod common;

use std::str::FromStr;

use elements::confidential::{Nonce, Value as CValue};
use elements::encode::{deserialize, serialize};
use elements::hashes::{hash160, Hash};
use elements::hex::FromHex;
use elements::secp256k1_zkp::{Message, Secp256k1};
use elements::sighash::SighashCache;
use elements::{AssetId, AssetIssuance, EcdsaSighashType, OutPoint, Script, Transaction, TxOut};
use serde_json::{json, Value};

use arca_covenant::bond::{rebind_rest, rebind_signed_in, BondPolicy, Evidence, Form, Signed};
use arca_covenant::landing::{check_explicit, LandingError};
use arca_covenant::spend::FeeSource;
use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeParams};
use arca_covenant::{ClockSchedule, ConnectorPolicy, ExplicitOutput, Landing, LeafPolicy, RelativeTime, Template};
use common::net::*;
use common::round::{signed, DAY};
use common::*;

const V: u64 = 100_000_000;
const ALLOWANCE: u64 = 2_000;
const FEE: u64 = 400;

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

/// A round of `asset`: `issuer` issues the token at input 0, `coin` funds
/// the batch; the batch output, the token, the connector, `asset`'s change
/// and the issuer's change (both blinded to `blind` when given), and the fee.
fn round(net: &Net, issuer: &Coin, coin: &Coin, batch: &ExplicitOutput, sched: &ClockSchedule, blind: Option<&elements::secp256k1_zkp::PublicKey>)
	-> Transaction
{
	let asset = batch.asset;
	let x = issuer.txout.asset.explicit().unwrap();
	// A blinded output's proofs make the transaction larger.
	let fee_x = if blind.is_some() { 60_000 } else { 3_000 };
	let mut change = explicit(asset, coin.txout.value.explicit().unwrap() - batch.value, op_true_spk());
	if let Some(pk) = blind {
		change.nonce = Nonce::Confidential(*pk);
	}
	let mut x_change = explicit(x, issuer.txout.value.explicit().unwrap() - 5_000 - fee_x, op_true_spk());
	if let Some(pk) = blind {
		// Blinding with explicit inputs takes two outputs, so the issuer's
		// change is blinded too.
		x_change.nonce = Nonce::Confidential(*pk);
	}
	let outs = vec![batch.txout(), explicit(sched.token, 1, sched.clock0_script_pubkey()),
		ConnectorPolicy { operator: sched.operator }.output(x, 5_000).txout(), change, x_change, fee(x, fee_x)];
	let mut s = spend(0).coin(issuer, 0xffff_ffff).coin(coin, 0xffff_ffff).outputs(outs);
	s.tx.input[0].asset_issuance = AssetIssuance {
		asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: [0; 32],
		amount: CValue::Explicit(1), inflation_keys: CValue::Null, denomination: 0,
	};
	let mut tx = s.tx;
	if blind.is_some() {
		let amount = |c: &Coin| format!("{:.8}", c.txout.value.explicit().unwrap() as f64 / 1e8);
		let zero = "00".repeat(32);
		let r = net.rpc("rawblindrawtransaction", json!([hexs(&serialize(&tx)), [zero, zero], [amount(issuer), amount(coin)],
			[x.to_string(), asset.to_string()], [zero, zero], "", false]));
		tx = tx_of(r.as_str().unwrap());
	}
	for i in 0..tx.input.len() {
		tx.input[i].witness.script_witness = op_true_witness();
	}
	tx
}

#[test]
fn a_supervised_asset_lands_where_its_freeze_binds() {
	let mut net = Net::start();
	let sup = issue(&mut net);
	let (a, s, l) = (keypair("landing owner"), keypair("landing operator"), keypair("landing key"));
	let program = hash160::Hash::hash(&l.public_key().serialize()).to_byte_array();
	let landing = Landing { program, allowance: ALLOWANCE };
	let land_spk = landing.script_pubkey();
	let (chain, genesis) = (net.chain, net.genesis);
	let leaf = |salt: &str| LeafPolicy {
		owner: xonly(&a), operator: xonly(&s), salt: label32(salt), chain, exit_delay: delay(), htlc: None, order: None,
		landing: Some(landing.terms(sup.z, V).unwrap()),
	};
	assert_eq!(leaf("x").template(), Template::Landing1);
	println!("landing script {} bytes, collaborative script {} bytes", leaf("x").exit_script().len(), leaf("x").collab_script().len());

	// ---- the collaborative path: landing-1's constant, and only it ---------
	let l1 = leaf("collab leaf");
	let c1 = net.fund(vec![explicit(sup.z, V, l1.script_pubkey())]).remove(0);
	let outs = vec![ExplicitOutput::new(sup.z, V - FEE, op_true_spk())];
	let pair_tx = |k: &[u8]| {
		let m = arca_covenant::message::rebind_message(k, sup.z, V, &outs).unwrap();
		let mut sp = spend(0).coin(&c1, 0xffff_ffff).outputs(vec![outs[0].txout(), fee(sup.z, FEE)]);
		sp.witness(0, l1.collab_witness(&sig(&s, &m.digest), &sig(&a, &m.digest), 1));
		sp.tx
	};
	net.refuse("collab signed over the plain constant (no landing program)", &pair_tx(&net.chain.leaf_constant(&l1.salt)),
		"Invalid Schnorr signature");
	net.refuse("collab signed over another landing's prefix", &pair_tx(&net.chain.landing_prefix(&l1.salt, &[7; 20])),
		"Invalid Schnorr signature");
	let collab = pair_tx(&l1.collab_prefix());
	net.pass("collab, landing-1's prefix K ‖ P", &collab);

	// ---- a double-sign under a landing-1 leaf's salt burns the bond --------
	// K is the salt's own, so the operator's signature on the chain, beside a
	// second one under the same salt that a holder kept, is evidence the
	// equivocation bond takes as for any coin.
	let bond = BondPolicy::new(chain, xonly(&s), xonly(&keypair("bond W")), RelativeTime::from_units(4).unwrap()).unwrap();
	let from_chain = rebind_signed_in(&chain, &l1.salt, &collab, 0, &c1.txout).expect("the landing-1 collab spend, read from the chain");
	assert!(bond.verify(&l1.salt, &from_chain), "S's signature as the chain carries it");
	assert_eq!(from_chain.rest[..20], program, "the rest after K starts with the landing program");
	let other = [ExplicitOutput::new(sup.z, V - FEE, land_spk.clone())];
	let m_kept = l1.collab_message(sup.z, V, &other).unwrap();
	let kept = Signed { form: Form::Rebind, rest: rebind_rest(&m_kept.preimage).unwrap(), signature: sig(&s, &m_kept.digest) };
	let evidence = Evidence { salt: l1.salt, a: kept, b: from_chain };
	assert_eq!(bond.check(&evidence), Ok(()));
	let posted = net.fund(vec![explicit(net.x, 1_000_000, bond.script_pubkey())]).remove(0);
	let fee_coin = net.fund(vec![explicit(net.x, 20_000, op_true_spk())]).remove(0);
	let mut slash = bond.slash_tx(&[(posted.outpoint, posted.txout.clone())], &evidence, &FeeSource::Coin {
		outpoint: fee_coin.outpoint, coin: fee_coin.txout.clone(), fee: 2_000, change: op_true_spk() }).unwrap().tx;
	slash.input[1].witness.script_witness = op_true_witness();
	net.pass("slash of the bond on two co-signatures under a landing-1 leaf's salt", &slash);

	// ---- the landing and its covenant --------------------------------------
	let l2 = leaf("landing leaf");
	let c2 = net.fund(vec![explicit(sup.z, V, l2.script_pubkey())]).remove(0);
	// Built by hand: the crate's builder refuses every one of these.
	let landing_tx = |outs: Vec<TxOut>, extra: Option<&Coin>| {
		let mut sp = spend(0).coin(&c2, delay().to_sequence());
		if let Some(x) = extra {
			sp = sp.coin(x, 0xffff_ffff);
		}
		let mut sp = sp.outputs(outs);
		let script = l2.exit_script();
		let sg = sp.sign(&a, 0, &script, genesis);
		sp.witness(0, l2.exit_witness(&sg));
		if extra.is_some() {
			sp.witness(1, op_true_witness());
		}
		sp.tx
	};
	let good = || vec![explicit(sup.z, V - FEE, land_spk.clone()), fee(sup.z, FEE)];
	net.refuse("landing before its delay", &landing_tx(good(), None), "non-BIP68-final");
	net.wait_csv(&c2.outpoint.txid, delay());
	let other = Landing { program: hash160::Hash::hash(&keypair("another key").public_key().serialize()).to_byte_array(), allowance: 0 };
	net.refuse("landing to another key's P2WPKH", &landing_tx(vec![explicit(sup.z, V - FEE, other.script_pubkey()), fee(sup.z, FEE)], None),
		"Script failed an OP_EQUALVERIFY operation");
	net.refuse("landing to a taproot output", &landing_tx(vec![explicit(sup.z, V - FEE, op_true_spk()), fee(sup.z, FEE)], None),
		"Script failed an OP_EQUALVERIFY operation");
	let x_coin = net.fund(vec![explicit(net.x, V, op_true_spk())]).remove(0);
	net.refuse("landing in another asset", &landing_tx(vec![explicit(net.x, V, land_spk.clone()), explicit(sup.z, V - FEE, op_true_spk()),
		fee(sup.z, FEE)], Some(&x_coin)), "Script failed an OP_EQUALVERIFY operation");
	net.refuse("landing one atom below the value less the allowance", &landing_tx(vec![
		explicit(sup.z, V - ALLOWANCE - 1, land_spk.clone()), explicit(sup.z, ALLOWANCE + 1 - FEE, op_true_spk()), fee(sup.z, FEE)], None),
		"Script failed an OP_VERIFY operation");
	// The builder refuses the same, before any signature.
	assert!(matches!(l2.exit_tx(c2.outpoint, sup.z, V, &[ExplicitOutput::new(sup.z, V - FEE, op_true_spk())], &FeeSource::Reserve),
		Err(arca_covenant::SpendError::Landing(LandingError::Output { .. }))));
	let ks = l2.landing_tx(c2.outpoint, sup.z, V, &FeeSource::Split { fee: FEE, change: Script::new() }).unwrap();
	let tx = signed(&net, ks, &a, vec![]).tx;
	assert_eq!(tx.output[0].script_pubkey, land_spk);
	net.pass("landing to the owner's key, the fee from the coin", &tx);

	// ---- under a pause, the leaf's own script named in a freeze -------------
	let l3 = leaf("frozen leaf");
	let c3 = net.fund(vec![explicit(sup.z, V, l3.script_pubkey())]).remove(0);
	let (pause, _) = sup.record(&mut net, "pause", None);
	let _named = sup.record(&mut net, "freeze", Some(&l3.script_pubkey()));
	net.mine(1);
	let leaf_status = sup.status(&net, &l3.script_pubkey());
	let land_status = sup.status(&net, &land_spk);
	println!("paused, the leaf's script named: isassetfrozen on the leaf {} (its script path is not single-owner), \
		on the landing address {}", leaf_status, land_status);
	assert_eq!(leaf_status["frozen"], json!(true), "the trap: the flag says frozen for a tree script");
	net.wait_csv(&c3.outpoint.txid, delay());
	let ks = l3.landing_tx(c3.outpoint, sup.z, V, &FeeSource::Split { fee: FEE, change: Script::new() }).unwrap();
	let tx = signed(&net, ks, &a, vec![]).tx;
	let landed_at = net.pass("landing under a pause, the leaf's script named in a freeze", &tx);
	let landed = coin_of(landed_at, 0, &tx);
	net.refuse("spend of the landed coin under the pause", &p2wpkh_spend(&landed, &l), "bad-txns-asset-frozen");
	let (freeze, target) = sup.record(&mut net, "freeze", Some(&land_spk));
	sup.lift(&mut net, pause, &"00".repeat(32));
	net.mine(1);
	println!("pause lifted, the landing address frozen: {}", sup.status(&net, &land_spk));
	net.refuse("spend of the landed coin, its address frozen", &p2wpkh_spend(&landed, &l), "bad-txns-asset-frozen");
	sup.lift(&mut net, freeze, &target);
	net.mine(1);
	println!("freeze lifted: {}", sup.status(&net, &land_spk));
	net.pass("spend of the landed coin once its freeze is lifted", &p2wpkh_spend(&landed, &l));

	// ---- a round of Z keeps every output explicit ---------------------------
	let leaves: Vec<LeafSpec> = (0..4).map(|i| {
		let owner = keypair(&format!("batch owner {}", i));
		LeafSpec {
			template: Template::Landing1, owner: xonly(&owner), value: 10_000_000,
			owner_nonce: label32(&format!("batch {} owner nonce", i)), operator_nonce: label32(&format!("batch {} operator nonce", i)),
			exit_delay: delay(), unlock_hash: label32(&format!("batch {} unlock", i)), htlc: None, order: None,
			landing: Some(Landing { program: [i as u8 + 1; 20], allowance: ALLOWANCE }),
		}
	}).collect();
	let blinder = keypair("blinding key").public_key();
	let floor = (net.rpc("getmempoolinfo", json!([]))["minrelaytxfee"].as_f64().unwrap() * 1e8).round() as u64;
	let batch_of = |net: &mut Net, asset: AssetId, specs: &[LeafSpec]| {
		let issuer = net.fund(vec![explicit(net.x, 2_000_000_000, op_true_spk())]).remove(0);
		let now = net.now();
		let sched = ClockSchedule::new(token_of(&issuer), xonly(&s), delay(), vec![mt(now + 28 * DAY), mt(now + 56 * DAY)]).unwrap();
		let tree = Tree::build(TreeParams {
			asset, chain: net.chain, schedule: sched.clone(), burn: false, radix: 4,
			reserve: ReserveRule::FeeRate { floor_per_kvb: floor, multiple: 4 }, min_leaf: 1,
		}, specs).unwrap();
		let coin = net.fund(vec![explicit(asset, tree.batch_output().value + 5_000_000, op_true_spk())]).remove(0);
		(issuer, coin, tree, sched)
	};
	let (issuer, coin, tree, sched) = batch_of(&mut net, sup.z, &leaves);
	let blinded = round(&net, &issuer, &coin, &tree.batch_output(), &sched, Some(&blinder));
	assert!(matches!(check_explicit(&blinded), Err(LandingError::Blinded { output: 3 })));
	net.refuse("a round of Z with a blinded output", &blinded, "bad-txns-supervised-blinded");
	let clear = round(&net, &issuer, &coin, &tree.batch_output(), &sched, None);
	check_explicit(&clear).unwrap();
	let round_id = net.pass("a round of Z, every output explicit, every leaf landing-1", &clear);
	for i in 0..4 {
		let r = tree.record(i);
		assert_eq!(r.template, Template::Landing1);
		r.validate_round(&clear, &arca_covenant::WalletPolicy::new(net.chain, xonly(&s), mt(net.mtp()))).unwrap();
	}
	println!("round {} of Z: every leaf's record checks against it", round_id);
	// The same blinding in a round of an open asset confirms: the blinding was
	// sound, and only the supervised rule refused it.
	let open: Vec<LeafSpec> = leaves.iter().map(|l| LeafSpec { template: Template::Vtxo1, landing: None, ..l.clone() }).collect();
	let y = net.y;
	let (issuer, coin, tree, sched) = batch_of(&mut net, y, &open);
	let blinded = round(&net, &issuer, &coin, &tree.batch_output(), &sched, Some(&blinder));
	assert!(check_explicit(&blinded).is_err());
	net.pass_or_mine("a round of an open asset with the same blinded output", &blinded, "min relay fee not met");

	net.print();
}
