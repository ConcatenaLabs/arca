//! The off-chain transactions against their golden vectors.
//!
//! `regtest/vectors/transactions.json` is written by the regtest suite's
//! Python reference (`regtest/offchain.py`), which shares no code with this
//! crate. For each transaction in it, the builder here makes the same
//! transaction from the same inputs, the test keys sign it again, and the
//! result must equal the vector byte for byte, witnesses included; then every
//! input verifies under the block rules and the mempool's script checks. The
//! board record decodes from both forms, encodes back to the same bytes and
//! text, and its refusal vectors are refused for the reason they name.

mod common;

use std::str::FromStr;

use elements::encode::{deserialize, serialize};
use elements::hex::FromHex;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, BlockHash, OutPoint, Script, Sequence, Transaction, TxOut, Txid};
use serde_json::Value;

use arca_consensus::Verifier;
use arca_covenant::script::sha256;
use arca_covenant::sign::sign_digest;
use arca_covenant::spend::{FeeSource, UnrollTx};
use arca_covenant::*;

use common::*;

fn vectors() -> Value {
	let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../regtest/vectors/transactions.json");
	serde_json::from_str(&std::fs::read_to_string(path).expect("regtest/vectors/transactions.json")).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
	Vec::<u8>::from_hex(v.as_str().unwrap()).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
	bytes(v).try_into().unwrap()
}

fn key(v: &Value) -> XOnlyPublicKey {
	XOnlyPublicKey::from_slice(&bytes(v)).unwrap()
}

fn asset_of(v: &Value) -> AssetId {
	AssetId::from_str(v.as_str().unwrap()).unwrap()
}

fn outpoint(v: &Value) -> OutPoint {
	OutPoint::new(Txid::from_str(v["txid"].as_str().unwrap()).unwrap(), v["vout"].as_u64().unwrap() as u32)
}

fn out(v: &Value) -> ExplicitOutput {
	ExplicitOutput::new(asset_of(&v["asset"]), v["value"].as_u64().unwrap(), Script::from(bytes(&v["script_pubkey"])))
}

fn fee_of(v: &Value) -> FeeSource {
	if v == "reserve" {
		return FeeSource::Reserve;
	}
	FeeSource::Coin {
		outpoint: outpoint(&v["outpoint"]),
		coin: out(&v["coin"]).txout(),
		fee: v["fee"].as_u64().unwrap(),
		change: Script::from(bytes(&v["change"])),
	}
}

/// The test keys of the vectors: secret = SHA256("Arca test vector key/" + label)
/// (reduced modulo the group order in the reference, which these labels never
/// reach).
fn vector_key(label: &str) -> elements::secp256k1_zkp::Keypair {
	let d = sha256(format!("Arca test vector key/{}", label).as_bytes());
	elements::secp256k1_zkp::Keypair::from_secret_key(&elements::secp256k1_zkp::Secp256k1::new(),
		&elements::secp256k1_zkp::SecretKey::from_slice(&d).expect("below the group order"))
}

/// The outputs the signer chose: the vector transaction's first output.
fn chosen(t: &Value) -> Vec<ExplicitOutput> {
	let tx: Transaction = deserialize(&bytes(&t["tx"])).unwrap();
	vec![ExplicitOutput::from_txout(&tx.output[0]).unwrap()]
}

struct Fx {
	consensus: Verifier,
	standard: Verifier,
	genesis: BlockHash,
}

impl Fx {
	fn new(v: &Value) -> Fx {
		let genesis = BlockHash::from_str(v["inputs"]["genesis_hash"].as_str().unwrap()).unwrap();
		Fx { consensus: Verifier::consensus(genesis), standard: Verifier::standard(genesis), genesis }
	}

	/// Puts the OP_1 tapscript's witness on every input that spends it, then
	/// compares with the vector and verifies every input.
	fn check(&self, name: &str, mut u: UnrollTx, vector: &Value) -> Transaction {
		let op1 = Script::from(bytes(&vectors()["inputs"]["op_true_script_pubkey"]));
		for (i, p) in u.prevouts.iter().enumerate() {
			if p.script_pubkey == op1 && u.tx.input[i].witness.script_witness.is_empty() {
				u.tx.input[i].witness.script_witness = op_true_witness();
			}
		}
		let expected = bytes(&vector["tx"]);
		assert_eq!(serialize(&u.tx), expected, "{}: the transaction differs from the vector", name);
		let prevouts: Vec<TxOut> = vector["inputs"].as_array().unwrap().iter().map(|i| out(&i["spent"]).txout()).collect();
		assert_eq!(prevouts, u.prevouts, "{}: the spent outputs", name);
		for (i, inp) in vector["inputs"].as_array().unwrap().iter().enumerate() {
			assert_eq!(u.tx.input[i].previous_output, outpoint(&inp["outpoint"]), "{}: input {}", name, i);
			assert_eq!(u.tx.input[i].sequence, Sequence(inp["sequence"].as_u64().unwrap() as u32), "{}: sequence {}", name, i);
		}
		self.consensus.verify_tx(&u.prevouts, &u.tx).unwrap_or_else(|(i, e)| panic!("{}: input {}: {}", name, i, e));
		self.standard.verify_tx(&u.prevouts, &u.tx).unwrap_or_else(|(i, e)| panic!("{}: input {} (standard): {}", name, i, e));
		println!("{:<44} {:>4} vB  rebuilt byte for byte, every input verifies", name, u.tx.vsize());
		u.tx
	}

	/// Signs a key spend with the vector key `label`, checking the sighash
	/// and the signature against the vector, and finishes it with `after`.
	fn sign(&self, name: &str, ks: KeySpend, label: &str, after: Vec<Vec<u8>>, vector: &Value) -> UnrollTx {
		let sh = ks.sighash(self.genesis).unwrap();
		assert_eq!(sh.to_vec(), bytes(&vector["sighash"]), "{}: sighash", name);
		let sg = sign_digest(&vector_key(label), &sh, &ZERO_AUX);
		assert_eq!(sg.as_ref().to_vec(), bytes(&vector["signatures"][label]), "{}: signature", name);
		let mut below = vec![sg.as_ref().to_vec()];
		below.extend(after);
		ks.finish(below)
	}
}

#[test]
fn the_board_and_its_record() {
	let v = vectors();
	let fx = Fx::new(&v);
	let b = &v["board"];
	let rec = BoardRecord::from_bytes(&bytes(&b["record"]["binary"])).unwrap();
	assert_eq!(rec.to_bytes().unwrap(), bytes(&b["record"]["binary"]));
	assert_eq!(BoardRecord::from_json_str(b["record"]["json"].as_str().unwrap()).unwrap(), rec);
	assert_eq!(rec.to_json_string().unwrap(), b["record"]["json"].as_str().unwrap());
	assert_eq!(rec.salt().to_vec(), bytes(&b["record"]["salt"]));
	assert_eq!(rec.leaf().program().to_vec(), bytes(&b["record"]["leaf_program"]));
	assert_eq!(rec.leaf().script_pubkey().as_bytes(), &bytes(&b["record"]["leaf_script_pubkey"])[..]);
	assert_eq!(rec.output().script_pubkey.as_bytes(), &bytes(&b["record"]["script_pubkey"])[..]);
	let policy = rec.policy();
	assert_eq!(policy.convert_script().as_bytes(), &bytes(&b["record"]["convert_script"])[..]);
	assert_eq!(policy.leaf.collab_script().as_bytes(), &bytes(&b["record"]["collab_script"])[..]);
	assert_eq!(rec.leaf_id().to_string(), b["record"]["leaf_id"].as_str().unwrap());
	assert_eq!(rec.operator, key(&v["inputs"]["operator"]));
	println!("board-1: convert script {} bytes, collab script {} bytes (the leaf's own)",
		policy.convert_script().len(), policy.leaf.collab_script().len());

	// The board transaction from the owner's coins, and the record against it
	// under a wallet's policy.
	let t = &b["board_tx"];
	let coins: Vec<(OutPoint, TxOut)> = t["inputs"].as_array().unwrap().iter()
		.map(|i| (outpoint(&i["outpoint"]), out(&i["spent"]).txout())).collect();
	let u = rec.tx(&coins, asset_of(&t["fee_asset"]), t["fee"].as_u64().unwrap(), &Script::from(bytes(&t["change"]))).unwrap();
	let board = fx.check("the board transaction", u, t);
	let wallet = WalletPolicy::new(Chain::new(fx.genesis), rec.operator, MedianTime::from_consensus(1_791_000_000).unwrap());
	let valid = rec.validate(&board, &wallet).unwrap();
	assert_eq!((valid.vout, valid.txid), (t["board_vout"].as_u64().unwrap() as u32, board.txid()));
	let other = WalletPolicy { operator: rec.owner, ..wallet };
	assert_eq!(rec.validate(&board, &other).unwrap_err(), RecordError::WrongOperator);
	let strict = WalletPolicy { min_exit_delay: RelativeTime::from_units(rec.exit_delay.units() + 1).unwrap(), ..wallet };
	assert_eq!(rec.validate(&board, &strict).unwrap_err().kind(), "policy");

	// The owner's conversion, signed, a fee coin attached; then the
	// converted leaf's exit.
	let c = &b["conversion_tx"];
	let ks = policy.conversion(valid.outpoint(), &fee_of(&c["fee"])).unwrap();
	let u = fx.sign("the owner's conversion", ks, "A", vec![], c);
	let conversion = fx.check("the owner's conversion", u, c);
	println!("board-1: the owner's conversion {} vB", conversion.vsize());
	let e = &b["exit_tx"];
	let ks = rec.leaf().exit_tx(OutPoint::new(conversion.txid(), 0), rec.asset, rec.value, &chosen(e), &fee_of(&e["fee"])).unwrap();
	let u = fx.sign("the converted leaf's exit claim", ks, "A", vec![], e);
	fx.check("the converted leaf's exit claim", u, e);

	// One pair over the leaf's message spends the board output, and the leaf
	// the conversion made.
	let pairs = b["by_pair"].as_array().unwrap();
	let outs = chosen(&pairs[0]);
	let d = rec.leaf().collab_message(rec.asset, rec.value, &outs).unwrap().digest;
	let pair = Pair { operator: sign_digest(&vector_key("S"), &d, &ZERO_AUX), owner: sign_digest(&vector_key("A"), &d, &ZERO_AUX) };
	for (x, at, by_board) in [(&pairs[0], valid.outpoint(), true), (&pairs[1], OutPoint::new(conversion.txid(), 0), false)] {
		assert_eq!(d.to_vec(), bytes(&x["message_digest"]));
		let name = x["name"].as_str().unwrap();
		let u = if by_board {
			collab_tx(&policy, at, rec.asset, rec.value, &outs, &pair, &fee_of(&x["fee"])).unwrap()
		} else {
			collab_tx(&rec.leaf(), at, rec.asset, rec.value, &outs, &pair, &fee_of(&x["fee"])).unwrap()
		};
		fx.check(name, u, x);
	}

	for x in b["invalid_binary"].as_array().unwrap() {
		let err = BoardRecord::from_bytes(&bytes(&x["binary"])).err()
			.unwrap_or_else(|| panic!("{}: decoded", x["name"]));
		assert_eq!(err.kind(), x["kind"].as_str().unwrap(), "{}: {}", x["name"], err);
		println!("board record, binary  {:<36} refused: {}", x["name"].as_str().unwrap(), err);
	}
	for x in b["invalid_json"].as_array().unwrap() {
		let err = BoardRecord::from_json_str(x["json"].as_str().unwrap()).err()
			.unwrap_or_else(|| panic!("{}: decoded", x["name"]));
		assert_eq!(err.kind(), x["kind"].as_str().unwrap(), "{}: {}", x["name"], err);
		println!("board record, JSON    {:<36} refused: {}", x["name"].as_str().unwrap(), err);
	}
}

#[test]
fn the_forfeit_its_claim_and_its_refund() {
	let v = vectors();
	let fx = Fx::new(&v);
	let f = &v["forfeit"];
	let inp = &f["inputs"];
	let chain = Chain::new(fx.genesis);
	let leaf = LeafPolicy {
		owner: key(&inp["owner"]), operator: key(&inp["operator"]),
		salt: arca_covenant::leaf::leaf_salt(&h32(&inp["owner_nonce"]), &h32(&inp["operator_nonce"])),
		chain, exit_delay: RelativeTime::from_units(inp["exit_delay_units"].as_u64().unwrap() as u16).unwrap(),
	};
	assert_eq!(leaf.script_pubkey().as_bytes(), &bytes(&f["leaf_script_pubkey"])[..]);
	let p = leaf.program();
	let leaf_id = LeafId::compute(&p, &[], &p);
	assert_eq!(leaf_id.0, h32(&inp["leaf_id"]));
	let round = Txid::from_str(inp["round"]["txid"].as_str().unwrap()).unwrap();
	let c = inp["round"]["connector_vout"].as_u64().unwrap() as u32;
	let m = connector_asset(round, c);
	assert_eq!(m, asset_of(&inp["connector_asset"]), "the connector asset from the round's outpoint alone");
	let ff = Forfeit::new(leaf, (asset_of(&inp["asset"]), inp["value"].as_u64().unwrap()), leaf_id, h32(&inp["unlock_hash"]), m,
		RelativeTime::from_units(inp["refund_delay_units"].as_u64().unwrap() as u16).unwrap(),
		inp["margin"].as_u64().unwrap()).unwrap();
	assert_eq!(ff.output(), out(&f["forfeit_output"]));
	assert_eq!(ff.policy.claim_script().as_bytes(), &bytes(&f["claim_script"])[..]);
	assert_eq!(ff.policy.refund_script().as_bytes(), &bytes(&f["refund_script"])[..]);
	println!("claim script {} bytes, refund script {} bytes", ff.policy.claim_script().len(), ff.policy.refund_script().len());

	// The connector output and the operator's issuance of the connector asset.
	let connector = ConnectorPolicy { operator: key(&inp["operator"]) };
	assert_eq!(connector.script().as_bytes(), &bytes(&f["connector_script"])[..]);
	let iss = &f["issuance"];
	let i0 = &iss["inputs"][0];
	let spent = out(&i0["spent"]);
	assert_eq!(spent.script_pubkey, connector.script_pubkey());
	assert_eq!(spent, out(&f["connector_output"]));
	let ks = connector.issuance(outpoint(&i0["outpoint"]), (spent.asset, spent.value), Script::from(bytes(&iss["to"])), &[],
		&FeeSource::Reserve).unwrap();
	let u = fx.sign("the issuance of the connector asset", ks, "S", vec![], iss);
	let issuance = fx.check("the issuance of the connector asset", u, iss);
	assert_eq!(issuance.input[0].issuance_ids().0, m);
	println!("connector script {} bytes; issuance {} vB", connector.script().len(), issuance.vsize());

	let txs = f["transactions"].as_array().unwrap();
	let leaf_coin = outpoint(&inp["leaf_outpoint"]);
	let d = ff.message().digest;
	let pair = Pair { operator: sign_digest(&vector_key("S"), &d, &ZERO_AUX), owner: sign_digest(&vector_key("A"), &d, &ZERO_AUX) };
	ff.verify(&pair).unwrap();
	let mut forfeit_txid = None;
	for t in txs {
		let name = t["name"].as_str().unwrap();
		let fee = fee_of(&t["fee"]);
		if name.starts_with("the forfeit") {
			assert_eq!(d.to_vec(), bytes(&t["message_digest"]), "{}: message", name);
			assert_eq!(pair.operator.as_ref().to_vec(), bytes(&t["signatures"]["S"]));
			assert_eq!(pair.owner.as_ref().to_vec(), bytes(&t["signatures"]["A"]));
			let tx = fx.check(name, ff.tx(leaf_coin, &pair, &fee).unwrap(), t);
			forfeit_txid.get_or_insert(tx.txid());
		} else if name.starts_with("the operator's claim") {
			let at = OutPoint::new(forfeit_txid.unwrap(), 0);
			let ins = t["inputs"].as_array().unwrap();
			assert_eq!(outpoint(&ins[1]["outpoint"]), OutPoint::new(issuance.txid(), 0));
			let outs = chosen(t);
			let ks = ff.claim(at, (outpoint(&ins[1]["outpoint"]), out(&ins[1]["spent"]).txout()), &outs,
				Script::from(bytes(&t["connector_to"])), &fee).unwrap();
			let after = ForfeitPolicy::claim_items(&sign_digest(&vector_key("S"), &[0; 32], &ZERO_AUX), &h32(&inp["preimage"]),
				t["connector_input"].as_u64().unwrap() as u32)[1..].to_vec();
			let u = fx.sign(name, ks, "S", after, t);
			fx.check(name, u, t);
		} else {
			let at = OutPoint::new(forfeit_txid.unwrap(), 0);
			let ks = ff.refund(at, &chosen(t), &fee).unwrap();
			let u = fx.sign(name, ks, "A", vec![], t);
			fx.check(name, u, t);
		}
	}
}

#[test]
fn the_offboard_unlock_and_reclaim() {
	let v = vectors();
	let fx = Fx::new(&v);
	let o = &v["offboard"];
	let inp = &o["inputs"];
	let pol = OffboardPolicy {
		unlock_hash: h32(&inp["unlock_hash"]), destination: out(&inp["destination"]), operator: key(&inp["operator"]),
		reclaim_delay: RelativeTime::from_units(inp["reclaim_delay_units"].as_u64().unwrap() as u16).unwrap(),
	};
	assert_eq!(pol.unlock_script().as_bytes(), &bytes(&o["unlock_script"])[..]);
	assert_eq!(pol.reclaim_script().as_bytes(), &bytes(&o["reclaim_script"])[..]);
	assert_eq!(pol.taproot().control_block(&pol.unlock_script()).unwrap(), bytes(&o["unlock_control_block"]));
	assert_eq!(pol.taproot().control_block(&pol.reclaim_script()).unwrap(), bytes(&o["reclaim_control_block"]));
	assert_eq!(pol.script_pubkey().as_bytes(), &bytes(&o["script_pubkey"])[..]);
	println!("offboard unlock script {} bytes, reclaim script {} bytes", pol.unlock_script().len(), pol.reclaim_script().len());
	let coin = outpoint(&inp["outpoint"]);
	let value = pol.output(inp["reserve"].as_u64().unwrap()).value;
	for t in o["transactions"].as_array().unwrap() {
		let name = t["name"].as_str().unwrap();
		let fee = fee_of(&t["fee"]);
		if name.starts_with("the unlock") {
			let u = pol.unlock_tx(coin, value, &h32(&inp["preimage"]), &fee).unwrap();
			fx.check(name, u, t);
		} else {
			let ks = pol.reclaim(coin, value, &chosen(t), &fee).unwrap();
			let u = fx.sign(name, ks, "S", vec![], t);
			fx.check(name, u, t);
		}
	}
}

#[test]
fn the_transfer_chain() {
	let v = vectors();
	let fx = Fx::new(&v);
	let t = &v["transfer"];
	// The transactions the records' bases came from: two rounds and a board.
	let rounds: Vec<Transaction> = ["rounds", "boards"].iter()
		.flat_map(|k| t["inputs"][k].as_array().unwrap().iter())
		.map(|r| deserialize(&bytes(r)).unwrap()).collect();
	let now = MedianTime::from_consensus(t["inputs"]["now"].as_u64().unwrap() as u32).unwrap();
	let policy = WalletPolicy::new(Chain::new(fx.genesis), key(&v["inputs"]["operator"]), now);

	// Every receiver's record decodes, encodes back, and validates for it.
	let mut ends = std::collections::BTreeMap::new();
	for (name, r) in t["records"].as_object().unwrap() {
		let b = bytes(&r["binary"]);
		let rec = CoinRecord::from_bytes(&b).unwrap();
		assert_eq!(rec.to_bytes().unwrap(), b, "{}: binary form", name);
		let coin = rec.validate(&rounds, &policy, &key(&r["owner"]), &h32(&r["owner_nonce"]))
			.unwrap_or_else(|e| panic!("{}: refused: {}", name, e));
		assert_eq!(coin.id.to_string(), r["id"].as_str().unwrap(), "{}: coin id", name);
		// The second nonce of the coin's salt is its sender's.
		match &rec {
			CoinRecord::Transfer(t) => assert_eq!(t.leaf.creator_nonce, h32(&r["creator_nonce"]), "{}: creator nonce", name),
			_ => panic!("{}: a reassignment's output", name),
		}
		println!("{:<10} record {:>5} bytes, coin {}, {} hops, {} atoms", name, b.len(), coin.id, coin.hops, coin.value);
		if name == "D" || name == "E" {
			ends.insert(name.clone(), coin);
		}
	}

	// Each refused record decodes, encodes back, and is refused for the
	// reason it names.
	for x in t["refused_records"].as_array().unwrap() {
		let name = x["name"].as_str().unwrap();
		let b = bytes(&x["binary"]);
		let rec = CoinRecord::from_bytes(&b).unwrap();
		assert_eq!(rec.to_bytes().unwrap(), b, "{}: binary form", name);
		let e = rec.validate(&rounds, &policy, &key(&x["owner"]), &h32(&x["owner_nonce"]))
			.err().unwrap_or_else(|| panic!("{}: ACCEPTED", name));
		assert_eq!(e.kind(), x["kind"].as_str().unwrap(), "{}: {}", name, e);
		println!("refused: {}: {} ({})", name, e, e.kind());
	}

	// From D's coin, every checkpoint and reassignment, rebuilt and compared.
	let txs: std::collections::BTreeMap<String, &Value> = t["transactions"].as_array().unwrap().iter()
		.map(|x| (x["name"].as_str().unwrap().to_string(), x)).collect();
	fn walk(fx: &Fx, coin: &ValidCoin, bases: &Value, txs: &std::collections::BTreeMap<String, &Value>, n: &mut usize) -> OutPoint {
		match &coin.origin {
			ValidOrigin::Leaf { .. } => outpoint(&bases[coin.id.to_string()]),
			ValidOrigin::Board { valid, .. } => valid.outpoint(),
			ValidOrigin::Transfer { inputs, index, .. } => {
				let mut cps = vec![];
				for i in inputs {
					let at = walk(fx, &i.coin, bases, txs, n);
					let name = format!("checkpoint of {}", i.coin.id);
					// A board's checkpoint spends the board output itself.
					let u = if i.coin.board().is_some() {
						i.board_checkpoint_tx(&FeeSource::Reserve).unwrap()
					} else {
						i.checkpoint_tx(at, &FeeSource::Reserve).unwrap()
					};
					let cp = fx.check(&name, u, txs[&name]);
					cps.push(OutPoint::new(cp.txid(), 0));
					*n += 1;
				}
				let name = format!("reassignment creating {}", coin.id);
				let re = fx.check(&name, coin.reassignment_tx(&cps, &FeeSource::Reserve).unwrap(), txs[&name]);
				*n += 1;
				OutPoint::new(re.txid(), *index as u32)
			},
		}
	}
	let mut n = 0;
	for coin in ends.values() {
		walk(&fx, coin, &t["inputs"]["bases"], &txs, &mut n);
	}
	// E's coin rests on the board: its lineage holds the board's leaf and its
	// checkpoint, and the board must still be unspent.
	let e = &ends["E"];
	assert_eq!(e.boards(), vec![OutPoint::new(rounds[2].txid(), 0)]);
	assert_eq!(e.lineage().len(), 2);
	assert_eq!(e.expiry, MedianTime::MAX, "a coin from a board alone never expires");
	assert_eq!(n, txs.len(), "every transfer transaction in the vectors was rebuilt");
}
