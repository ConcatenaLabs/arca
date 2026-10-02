//! The verifier against the node.
//!
//! Every spend below is built from a script of the regtest prototype
//! (`arklib.py`: the tree node's unroll in its plain and compact forms, the
//! rebindable two-party path, the sweep and exit leaves; T5's hash-locked
//! forfeit claim; S6's Simplicity `check_lock_distance`). For each one the test
//! asks the verifier and the node's `testmempoolaccept`, and asserts that they
//! agree, including the script error the node names. A spend expected to fail
//! is then forced into a block with `generateblock`, which must refuse it, so a
//! verdict never rests on relay policy alone. A spend expected to pass is
//! mined.
//!
//! Needs `SEQUENTIAD_EXEC`. Run with `--nocapture` to see the table.

mod common;

use std::str::FromStr;

use elements::confidential::{Asset, Nonce, Value};
use elements::encode::serialize;
use elements::hashes::{sha256, Hash};
use elements::hex::{FromHex, ToHex};
use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use elements::sighash::{Prevouts, SighashCache};
use elements::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use elements::{
	AssetId, BlockHash, LockTime, OutPoint, SchnorrSighashType, Script, Sequence, Transaction,
	TxIn, TxOut, TxOutWitness,
};
use serde_json::json;

use arca_consensus::Verifier;
use common::Node;

/// BIP341 nothing-up-my-sleeve point: every internal key, so no key path.
const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
/// The rebindable message's domain tag (`arklib.TAG`).
const TAG: &[u8; 8] = b"ArcaRbd1";
const FEE: u64 = 3_000;
const FUND: u64 = 1_000_000;
/// The exit leaf's relative delay, in blocks.
const DELAY: u16 = 10;
/// S6's `check_lock_distance(10)`, compiled by the Simplicity prototype's
/// simtool: its commitment root and its program, which takes no witness.
const SIM_CMR: &str = "9a20e9c1d976a2bfc04d4163420490c418ac793fc43beaeaeb0e26d06f3f3d33";
const SIM_PROGRAM: &str = "c5362001408f2820";

fn sha(b: &[u8]) -> [u8; 32] {
	sha256::Hash::hash(b).to_byte_array()
}

fn explicit(asset: AssetId, value: u64, spk: Script) -> TxOut {
	TxOut {
		asset: Asset::Explicit(asset), value: Value::Explicit(value), nonce: Nonce::Null,
		script_pubkey: spk, witness: TxOutWitness::default(),
	}
}

/// The asset id as `OP_INSPECTOUTPUTASSET` pushes it: internal byte order.
fn asset_bytes(asset: AssetId) -> [u8; 32] {
	let ser = serialize(&Asset::Explicit(asset));
	ser[1..33].try_into().unwrap()
}

/// `arklib.record`: the injective record of an explicit output.
fn record(asset: AssetId, value: u64, spk: &Script) -> Vec<u8> {
	let b = spk.as_bytes();
	let (ver, prog): (i32, Vec<u8>) = if b.len() >= 4 && (b[0] == 0 || (0x51..=0x60).contains(&b[0]))
		&& b[1] as usize == b.len() - 2
	{
		(if b[0] == 0 { 0 } else { b[0] as i32 - 0x50 }, b[2..].to_vec())
	} else {
		(-1, sha(b).to_vec())
	};
	let mut r = asset_bytes(asset).to_vec();
	r.extend([1u8, 1u8]);
	r.extend(value.to_le_bytes());
	r.extend(prog);
	r.push((ver + 2) as u8);
	r
}

/// `arklib.record_ops(i)`.
fn record_ops(b: Builder, i: i64) -> Builder {
	b.push_int(i).push_opcode(OP_INSPECTOUTPUTASSET).push_opcode(OP_CAT)
		.push_int(i).push_opcode(OP_INSPECTOUTPUTVALUE).push_opcode(OP_SWAP)
		.push_opcode(OP_CAT).push_opcode(OP_CAT)
		.push_int(i).push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY).push_int(2).push_opcode(OP_ADD)
		.push_opcode(OP_CAT).push_opcode(OP_CAT)
}

/// `arklib.unroll_body`: pin asset, value and witness-v1 program of each child.
fn unroll_plain(children: &[(AssetId, u64, [u8; 32])]) -> Script {
	let mut b = Builder::new();
	for (i, (asset, value, prog)) in children.iter().enumerate() {
		let i = i as i64;
		b = b.push_int(i).push_opcode(OP_INSPECTOUTPUTASSET).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&asset_bytes(*asset)).push_opcode(OP_EQUALVERIFY)
			.push_int(i).push_opcode(OP_INSPECTOUTPUTVALUE).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&value.to_le_bytes()).push_opcode(OP_EQUALVERIFY)
			.push_int(i).push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(prog);
		b = b.push_opcode(if i as usize == children.len() - 1 { OP_EQUAL } else { OP_EQUALVERIFY });
	}
	b.into_script()
}

/// `arklib.unroll_compact_body`: the children's records joined with `OP_CAT`,
/// hashed, and compared with one constant.
fn unroll_compact(children: &[(AssetId, u64, [u8; 32])]) -> Script {
	let mut b = Builder::new();
	let mut blob = vec![];
	for (i, (asset, value, prog)) in children.iter().enumerate() {
		b = record_ops(b, i as i64);
		if i > 0 {
			b = b.push_opcode(OP_CAT);
		}
		let spk = Builder::new().push_int(1).push_slice(prog).into_script();
		blob.extend(record(*asset, *value, &spk));
	}
	b.push_opcode(OP_SHA256).push_slice(&sha(&blob)).push_opcode(OP_EQUAL).into_script()
}

/// `arklib.rebind_msg2`: the message both parties sign for the committed outputs.
fn rebind_msg(salt: &[u8; 32], outs: &[(AssetId, u64, Script)]) -> [u8; 32] {
	let mut acc = TAG.to_vec();
	acc.extend(salt);
	acc.push(outs.len() as u8);
	for (a, v, s) in outs {
		acc.extend(sha(&record(*a, *v, s)));
	}
	sha(&acc)
}

/// `arklib.collab_rebind_fixed` with m = 1: witness `<sig_S> <sig_A>`.
fn collab_rebind_fixed(a: XOnlyPublicKey, s: XOnlyPublicKey, salt: &[u8; 32]) -> Script {
	let mut prefix = TAG.to_vec();
	prefix.extend(salt);
	prefix.push(1);
	let b = Builder::new().push_slice(&prefix);
	record_ops(b, 0).push_opcode(OP_SHA256).push_opcode(OP_CAT)
		.push_opcode(OP_SHA256)
		.push_opcode(OP_TUCK).push_slice(&a.serialize()).push_opcode(OP_CHECKSIGFROMSTACKVERIFY)
		.push_slice(&s.serialize()).push_opcode(OP_CHECKSIGFROMSTACK)
		.into_script()
}

/// `arklib.sweep_leaf`: `<expiry> CLTV DROP <S> CHECKSIG`.
fn sweep(expiry: u32, s: XOnlyPublicKey) -> Script {
	Builder::new().push_int(expiry as i64).push_opcode(OP_CLTV).push_opcode(OP_DROP)
		.push_slice(&s.serialize()).push_opcode(OP_CHECKSIG).into_script()
}

/// `arklib.leaf_taptree` exit: `<delay> CSV DROP <A> CHECKSIG`.
fn exit(delay: u16, a: XOnlyPublicKey) -> Script {
	Builder::new().push_int(delay as i64).push_opcode(OP_CSV).push_opcode(OP_DROP)
		.push_slice(&a.serialize()).push_opcode(OP_CHECKSIG).into_script()
}

/// T5's forfeit claim: `SIZE 32 EQUALVERIFY SHA256 <h> EQUALVERIFY <S> CHECKSIG`.
fn hashlock_claim(h: [u8; 32], s: XOnlyPublicKey) -> Script {
	Builder::new().push_opcode(OP_SIZE).push_int(32).push_opcode(OP_EQUALVERIFY)
		.push_opcode(OP_SHA256).push_slice(&h).push_opcode(OP_EQUALVERIFY)
		.push_slice(&s.serialize()).push_opcode(OP_CHECKSIG).into_script()
}

struct Tree {
	info: TaprootSpendInfo,
	spk: Script,
}

impl Tree {
	fn new(leaves: &[(u8, Script, LeafVersion)]) -> Tree {
		let secp = Secp256k1::new();
		let mut b = TaprootBuilder::new();
		for (depth, script, ver) in leaves {
			b = b.add_leaf_with_ver(*depth as usize, script.clone(), *ver).unwrap();
		}
		let info = b.finalize(&secp, XOnlyPublicKey::from_str(NUMS).unwrap()).unwrap();
		let spk = Script::new_v1_p2tr_tweaked(info.output_key());
		Tree { info, spk }
	}

	fn tapscripts(leaves: &[(u8, &Script)]) -> Tree {
		let v: Vec<_> = leaves.iter().map(|(d, s)| (*d, (*s).clone(), LeafVersion::default())).collect();
		Tree::new(&v)
	}

	fn control_block(&self, script: &Script, ver: LeafVersion) -> Vec<u8> {
		self.info.control_block(&(script.clone(), ver)).unwrap().serialize()
	}

	fn program(&self) -> [u8; 32] {
		self.spk.as_bytes()[2..].try_into().unwrap()
	}
}

#[derive(Clone)]
struct Utxo {
	outpoint: OutPoint,
	txout: TxOut,
}

struct Chain {
	node: Node,
	genesis: BlockHash,
	asset: AssetId,
	/// The OP_TRUE output that funds everything.
	op_true: Utxo,
}

impl Chain {
	fn start() -> Chain {
		let node = Node::start("node-agreement", &[]);
		let genesis = BlockHash::from_str(node.rpc("getblockhash", json!([0])).as_str().unwrap()).unwrap();
		let asset = AssetId::from_str(
			node.rpc("getsidechaininfo", json!([]))["pegged_asset"].as_str().unwrap()).unwrap();
		// The genesis block pays the initial free coins to OP_TRUE.
		let block = node.rpc("getblock", json!([genesis.to_string(), 2]));
		let mut op_true = None;
		for tx in block["tx"].as_array().unwrap() {
			for out in tx["vout"].as_array().unwrap() {
				if out["scriptPubKey"]["hex"] == "51" {
					let raw = Vec::<u8>::from_hex(tx["hex"].as_str().unwrap()).unwrap();
					let tx: Transaction = elements::encode::deserialize(&raw).unwrap();
					let vout = out["n"].as_u64().unwrap() as u32;
					op_true = Some(Utxo {
						outpoint: OutPoint::new(tx.txid(), vout),
						txout: tx.output[vout as usize].clone(),
					});
				}
			}
		}
		Chain { node, genesis, asset, op_true: op_true.expect("no OP_TRUE output in genesis") }
	}

	fn height(&self) -> u32 {
		self.node.rpc("getblockcount", json!([])).as_u64().unwrap() as u32
	}

	fn mine(&self, n: u32) {
		self.node.rpc("generatetodescriptor", json!([n, "raw(51)"]));
	}

	/// Pay `FUND` to each script from the OP_TRUE output, in a block built
	/// with `generateblock` (spending a bare OP_TRUE is valid but not standard).
	fn fund(&mut self, spks: &[&Script]) -> Vec<Utxo> {
		let total = self.op_true.txout.value.explicit().unwrap();
		let mut outs: Vec<TxOut> = spks.iter().map(|s| explicit(self.asset, FUND, (*s).clone())).collect();
		let change = total - FUND * spks.len() as u64 - 10_000;
		outs.push(explicit(self.asset, change, Script::from(vec![0x51])));
		outs.push(TxOut::new_fee(10_000, self.asset));
		let tx = Transaction {
			version: 2, lock_time: LockTime::ZERO,
			input: vec![TxIn { previous_output: self.op_true.outpoint, ..Default::default() }],
			output: outs,
		};
		self.node.rpc("generateblock", json!(["raw(51)", [serialize(&tx).to_hex()]]));
		let txid = tx.txid();
		assert!(self.node.rpc("getrawtransaction", json!([txid.to_string(), true]))["confirmations"]
			.as_u64().unwrap() >= 1);
		self.op_true = Utxo { outpoint: OutPoint::new(txid, spks.len() as u32), txout: tx.output[spks.len()].clone() };
		(0..spks.len()).map(|i| Utxo {
			outpoint: OutPoint::new(txid, i as u32), txout: tx.output[i].clone(),
		}).collect()
	}
}

fn sign(key: &Keypair, msg: &Message) -> Vec<u8> {
	Secp256k1::new().sign_schnorr_no_aux_rand(msg, key).as_ref().to_vec()
}

fn key(i: u8) -> Keypair {
	Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[i; 32]).unwrap())
}

fn spend_tx(u: &Utxo, outs: Vec<TxOut>, sequence: u32, lock_time: u32, version: u32) -> Transaction {
	Transaction {
		version,
		lock_time: LockTime::from_consensus(lock_time),
		input: vec![TxIn {
			previous_output: u.outpoint, sequence: Sequence(sequence), ..Default::default()
		}],
		output: outs,
	}
}

fn set_witness(tx: &mut Transaction, stack: Vec<Vec<u8>>) {
	tx.input[0].witness.script_witness = stack;
}

struct Outcome {
	name: String,
	expect_valid: bool,
	mempool: String,
	verifier: String,
	block: String,
}

struct Run {
	chain: Chain,
	outcomes: Vec<Outcome>,
}

impl Run {
	/// Ask the node and the verifier about `tx`; assert they agree with each
	/// other and with `expect_valid`; force a failing spend into a block, mine
	/// a passing one.
	fn check(&mut self, name: &str, tx: &Transaction, spent: &Utxo, expect_valid: bool) {
		let hex = serialize(tx).to_hex();
		let spent = [spent.txout.clone()];
		let consensus = Verifier::consensus(self.chain.genesis).verify_input(&spent, 0, tx);
		let standard = Verifier::standard(self.chain.genesis).verify_input(&spent, 0, tx);
		let tma = &self.chain.node.rpc("testmempoolaccept", json!([[hex]]))[0];
		let allowed = tma["allowed"].as_bool().unwrap();
		let reason = tma["reject-reason"].as_str().unwrap_or("").to_string();

		assert_eq!(allowed, expect_valid, "{}: node said allowed={} ({})", name, allowed, reason);
		assert_eq!(standard.is_ok(), allowed, "{}: verifier (standard) {:?}, node {}", name, standard, reason);
		assert_eq!(consensus.is_ok(), expect_valid, "{}: verifier (consensus) {:?}", name, consensus);
		if let Err(arca_consensus::Error::Script { ref message, .. }) = standard {
			assert!(reason.contains(message.as_str()),
				"{}: node's reason {:?} does not name the verifier's error {:?}", name, reason, message);
		}

		let h0 = self.chain.height();
		let block = match self.chain.node.call("generateblock", json!(["raw(51)", [hex]])) {
			Ok(_) => {
				assert!(expect_valid, "{}: a spend the verifier refuses was MINED", name);
				let conf = self.chain.node.rpc("getrawtransaction", json!([tx.txid().to_string(), true]))
					["confirmations"].as_u64().unwrap_or(0);
				assert!(conf >= 1);
				"mined".to_string()
			},
			Err(e) => {
				assert!(!expect_valid, "{}: valid spend not mined: {}", name, e.message);
				assert_eq!(self.chain.height(), h0);
				format!("refused: {} (code {})", e.message, e.code)
			},
		};
		self.outcomes.push(Outcome {
			name: name.to_string(),
			expect_valid,
			mempool: if allowed { "allowed".into() } else { reason },
			verifier: match consensus {
				Ok(()) => "valid".into(),
				Err(e) => e.to_string(),
			},
			block,
		});
	}
}

#[test]
fn verifier_agrees_with_the_node() {
	let mut chain = Chain::start();
	let (a, s) = (key(1), key(2));
	let (a_x, s_x) = (a.x_only_public_key().0, s.x_only_public_key().0);
	let asset = chain.asset;
	let dest = Tree::tapscripts(&[(0, &exit(DELAY, a_x))]); // any witness-v1 destination

	// Introspection: the tree node's unroll, radix 2, the reserve paying the fee.
	let child = (FUND - FEE) / 2;
	let (k1, k2) = (key(3).x_only_public_key().0, key(4).x_only_public_key().0);
	let c1 = Tree::tapscripts(&[(0, &exit(DELAY, k1))]);
	let c2 = Tree::tapscripts(&[(0, &exit(DELAY, k2))]);
	let kids = [(asset, child, c1.program()), (asset, child, c2.program())];
	let expiry = chain.height() + 5;
	let plain = unroll_plain(&kids);
	let compact = unroll_compact(&kids);
	let node_plain = Tree::tapscripts(&[(1, &plain), (1, &sweep(expiry, s_x))]);
	let node_compact = Tree::tapscripts(&[(1, &compact), (1, &sweep(expiry, s_x))]);

	// OP_CHECKSIGFROMSTACK: the rebindable two-party path.
	let salt = sha(b"arca verifier agreement salt");
	let collab = collab_rebind_fixed(a_x, s_x, &salt);
	let exit_leaf = exit(DELAY, a_x);
	let sweep_leaf = sweep(expiry, s_x);
	let leaf = Tree::tapscripts(&[(1, &collab), (2, &exit_leaf), (2, &sweep_leaf)]);

	// Hash lock: the forfeit's claim path.
	let preimage = sha(b"arca verifier agreement preimage");
	let claim = hashlock_claim(sha(&preimage), s_x);
	let forfeit = Tree::tapscripts(&[(1, &claim), (1, &exit(5, a_x))]);

	// Simplicity, leaf version 0xbe.
	let sim_ver = LeafVersion::from_u8(0xbe).unwrap();
	let cmr = Script::from(Vec::<u8>::from_hex(SIM_CMR).unwrap());
	let sim = Tree::new(&[(0, cmr.clone(), sim_ver)]);

	let u = chain.fund(&[&node_plain.spk, &node_compact.spk, &leaf.spk, &forfeit.spk,
		&leaf.spk, &leaf.spk, &sim.spk]);
	// Let the relative locks and the absolute expiry pass.
	chain.mine(DELAY as u32);
	assert!(chain.height() > expiry);
	let mut run = Run { chain, outcomes: vec![] };

	let tap = LeafVersion::default();
	let pays = |a: u64, b: u64, fee: u64| vec![
		explicit(asset, a, c1.spk.clone()), explicit(asset, b, c2.spk.clone()), TxOut::new_fee(fee, asset),
	];

	// --- introspection, plain unroll
	let unroll_wit = |t: &Tree, s: &Script| vec![s.to_bytes(), t.control_block(s, tap)];
	let mut tx = spend_tx(&u[0], pays(child, child - 1, FEE + 1), 0xffffffff, 0, 2);
	set_witness(&mut tx, unroll_wit(&node_plain, &plain));
	run.check("introspection/unroll_plain/child_value_off_by_one", &tx, &u[0], false);
	let mut tx = spend_tx(&u[0], pays(child, child, FEE), 0xffffffff, 0, 2);
	tx.output[0].script_pubkey = dest.spk.clone();
	set_witness(&mut tx, unroll_wit(&node_plain, &plain));
	run.check("introspection/unroll_plain/child_script_replaced", &tx, &u[0], false);
	let mut tx = spend_tx(&u[0], pays(child, child, FEE), 0xffffffff, 0, 2);
	set_witness(&mut tx, unroll_wit(&node_plain, &plain));
	run.check("introspection/unroll_plain/exact_children", &tx, &u[0], true);

	// --- OP_CAT, compact unroll
	let mut tx = spend_tx(&u[1], pays(child - 1, child, FEE + 1), 0xffffffff, 0, 2);
	set_witness(&mut tx, unroll_wit(&node_compact, &compact));
	run.check("cat/unroll_compact/child_value_off_by_one", &tx, &u[1], false);
	let mut tx = spend_tx(&u[1], pays(child, child, FEE), 0xffffffff, 0, 2);
	set_witness(&mut tx, unroll_wit(&node_compact, &compact));
	run.check("cat/unroll_compact/exact_children", &tx, &u[1], true);

	// --- OP_CHECKSIGFROMSTACK, rebindable 2-of-2
	let out_value = FUND - FEE;
	let msg = rebind_msg(&salt, &[(asset, out_value, dest.spk.clone())]);
	let m = Message::from_digest(msg);
	let (sig_a, sig_s) = (sign(&a, &m), sign(&s, &m));
	let collab_wit = |sa: &[u8], ss: &[u8]| vec![ss.to_vec(), sa.to_vec(), collab.to_bytes(), leaf.control_block(&collab, tap)];
	let mut tx = spend_tx(&u[2], vec![explicit(asset, out_value - 1, dest.spk.clone()), TxOut::new_fee(FEE + 1, asset)], 0xffffffff, 0, 2);
	set_witness(&mut tx, collab_wit(&sig_a, &sig_s));
	run.check("csfs/rebind/output_changed_after_signing", &tx, &u[2], false);
	let mut tx = spend_tx(&u[2], vec![explicit(asset, out_value, dest.spk.clone()), TxOut::new_fee(FEE, asset)], 0xffffffff, 0, 2);
	set_witness(&mut tx, collab_wit(&sign(&key(9), &m), &sig_s));
	run.check("csfs/rebind/owner_signature_by_wrong_key", &tx, &u[2], false);
	let mut tx = spend_tx(&u[2], vec![explicit(asset, out_value, dest.spk.clone()), TxOut::new_fee(FEE, asset)], 0xffffffff, 0, 2);
	set_witness(&mut tx, collab_wit(&sig_a, &sig_s));
	run.check("csfs/rebind/signed_outputs", &tx, &u[2], true);

	// --- hash lock, forfeit claim
	let one_out = |v: u64, fee: u64| vec![explicit(asset, v, dest.spk.clone()), TxOut::new_fee(fee, asset)];
	let genesis = run.chain.genesis;
	let claim_tx = |pre: &[u8]| {
		let mut tx = spend_tx(&u[3], one_out(out_value, FEE), 0xffffffff, 0, 2);
		let sig = sign(&s, &sighash(genesis, &tx, &u[3], &claim, tap));
		set_witness(&mut tx, vec![sig, pre.to_vec(), claim.to_bytes(), forfeit.control_block(&claim, tap)]);
		tx
	};
	let mut wrong = preimage;
	wrong[0] ^= 1;
	run.check("hashlock/claim/wrong_preimage", &claim_tx(&wrong), &u[3], false);
	let mut long = preimage.to_vec();
	long.push(0);
	run.check("hashlock/claim/33_byte_preimage", &claim_tx(&long), &u[3], false);
	run.check("hashlock/claim/right_preimage", &claim_tx(&preimage), &u[3], true);

	// --- OP_CHECKLOCKTIMEVERIFY, sweep
	let sweep_tx = |seq: u32, lock: u32| {
		let mut tx = spend_tx(&u[4], one_out(out_value, FEE), seq, lock, 2);
		let sig = sign(&s, &sighash(genesis, &tx, &u[4], &sweep_leaf, tap));
		set_witness(&mut tx, vec![sig, sweep_leaf.to_bytes(), leaf.control_block(&sweep_leaf, tap)]);
		tx
	};
	run.check("cltv/sweep/locktime_below_expiry", &sweep_tx(0xfffffffe, expiry - 1), &u[4], false);
	run.check("cltv/sweep/final_sequence", &sweep_tx(0xffffffff, expiry), &u[4], false);
	run.check("cltv/sweep/locktime_at_expiry", &sweep_tx(0xfffffffe, expiry), &u[4], true);

	// --- OP_CHECKSEQUENCEVERIFY, exit
	let exit_tx = |seq: u32, version: u32| {
		let mut tx = spend_tx(&u[5], one_out(out_value, FEE), seq, 0, version);
		let sig = sign(&a, &sighash(genesis, &tx, &u[5], &exit_leaf, tap));
		set_witness(&mut tx, vec![sig, exit_leaf.to_bytes(), leaf.control_block(&exit_leaf, tap)]);
		tx
	};
	run.check("csv/exit/sequence_below_delay", &exit_tx(DELAY as u32 - 1, 2), &u[5], false);
	run.check("csv/exit/version_1", &exit_tx(DELAY as u32, 1), &u[5], false);
	run.check("csv/exit/sequence_at_delay", &exit_tx(DELAY as u32, 2), &u[5], true);

	// --- Simplicity, check_lock_distance(10)
	let sim_tx = |seq: u32| {
		let mut tx = spend_tx(&u[6], one_out(out_value, FEE), seq, 0, 2);
		set_witness(&mut tx, vec![vec![], Vec::<u8>::from_hex(SIM_PROGRAM).unwrap(),
			cmr.to_bytes(), sim.control_block(&cmr, sim_ver)]);
		tx
	};
	run.check("simplicity/lock_distance/sequence_9", &sim_tx(9), &u[6], false);
	run.check("simplicity/lock_distance/sequence_10", &sim_tx(10), &u[6], true);

	println!("\n{:<52} {:<6} {:<72} | {:<60} | {}", "case", "expect", "testmempoolaccept", "verifier", "block");
	for o in &run.outcomes {
		println!("{:<52} {:<6} {:<72} | {:<60} | {}", o.name,
			if o.expect_valid { "valid" } else { "bad" }, o.mempool, o.verifier, o.block);
	}
	assert_eq!(run.outcomes.len(), 19);
}

fn sighash(genesis: BlockHash, tx: &Transaction, u: &Utxo, leaf: &Script, ver: LeafVersion) -> Message {
	let h = SighashCache::new(tx).taproot_script_spend_signature_hash(
		0, &Prevouts::All(&[u.txout.clone()]), TapLeafHash::from_script(leaf, ver),
		SchnorrSighashType::Default, genesis,
	).unwrap();
	Message::from_digest(h.to_byte_array())
}

