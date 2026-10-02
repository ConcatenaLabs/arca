//! The covenant tree: the builder against the record vectors, and every
//! branch of every tree from 1 to 100 leaves through the node's interpreter.
//!
//! For each leaf count from 1 to 100 a batch is built at radix 4 with the
//! specification's reserve rule (four times the relay floor for each output's
//! own spend), funded by a round that issues its token, and every leaf's record
//! is validated against that round. Each leaf's branch is then extracted from
//! its record and every node transaction on it, the entry's unlock with them,
//! is verified with `arca-consensus` under the block rules and the mempool's
//! script checks: once with each reserve as the fee, once with a fee coin
//! attached by the broadcaster. In every node transaction one child is then
//! changed by one atom, and the node must refuse it. Other radices are run the
//! same way over fewer leaf counts. `-- --nocapture` prints the totals.

mod common;

use std::collections::HashSet;
use std::str::FromStr;

use elements::hashes::{sha256d, Hash};
use elements::hex::FromHex;
use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, AssetIssuance, BlockHash, ContractHash, OutPoint, Transaction, TxOut, Txid};
use serde_json::Value;

use arca_consensus::Verifier;
use arca_covenant::script::sha256;
use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeError, TreeParams};
use arca_covenant::unroll::{FeeSource, UnrollTx};
use arca_covenant::*;

use common::*;

const EQUALVERIFY: &str = "Script failed an OP_EQUALVERIFY operation";

fn vectors() -> Value {
	let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../regtest/vectors/records.json");
	serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
	Vec::<u8>::from_hex(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

fn key_of(v: &Value) -> elements::secp256k1_zkp::XOnlyPublicKey {
	elements::secp256k1_zkp::XOnlyPublicKey::from_slice(&h32(v)).unwrap()
}

#[test]
fn the_builder_rebuilds_every_record_vector() {
	let v = vectors();
	let genesis = BlockHash::from_str(v["inputs"]["genesis_hash"].as_str().unwrap()).unwrap();
	let asset = AssetId::from_str(v["inputs"]["asset"].as_str().unwrap()).unwrap();
	let operator = key_of(&v["inputs"]["operator"]);
	for b in v["batches"].as_array().unwrap() {
		let name = b["name"].as_str().unwrap();
		let inp = &b["inputs"];
		let expiries = inp["expiries"].as_array().unwrap().iter()
			.map(|e| MedianTime::from_consensus(e.as_u64().unwrap() as u32).unwrap()).collect();
		let schedule = ClockSchedule::new(AssetId::from_str(inp["token"].as_str().unwrap()).unwrap(), operator,
			RelativeTime::from_units(inp["notice_units"].as_u64().unwrap() as u16).unwrap(), expiries).unwrap();
		let params = TreeParams {
			asset, chain: Chain::new(genesis), schedule, burn: inp["burn"].as_bool().unwrap(),
			radix: inp["radix"].as_u64().unwrap() as usize,
			reserve: ReserveRule::Fixed { node: inp["node_reserve"].as_u64().unwrap(), entry: inp["entry_reserve"].as_u64().unwrap() },
			min_leaf: 1,
		};
		let leaves: Vec<LeafSpec> = inp["leaves"].as_array().unwrap().iter().map(|l| LeafSpec {
			template: Template::Vtxo1,
			owner: key_of(&l["owner"]),
			value: l["value"].as_u64().unwrap(),
			salt: h32(&l["salt"]),
			exit_delay: RelativeTime::from_units(l["exit_delay_units"].as_u64().unwrap() as u16).unwrap(),
			unlock_hash: h32(&l["unlock_hash"]),
		}).collect();
		let tree = Tree::build(params, &leaves).unwrap();

		let out = tree.batch_output();
		assert_eq!(out.script_pubkey.as_bytes().to_vec(), Vec::<u8>::from_hex(b["batch_output"]["script_pubkey"].as_str().unwrap()).unwrap(), "{}", name);
		assert_eq!(out.value, b["batch_output"]["value"].as_u64().unwrap(), "{}", name);
		let widths: Vec<u64> = tree.levels().iter().map(|l| l.len() as u64).collect();
		let expected: Vec<u64> = b["levels"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect();
		assert_eq!(widths, expected, "{}: the tree's shape", name);
		assert_eq!(tree.clock0_script_pubkey().as_bytes().to_vec(),
			Vec::<u8>::from_hex(b["clock0_script_pubkey"].as_str().unwrap()).unwrap());
		for r in b["records"].as_array().unwrap() {
			let i = r["leaf"].as_u64().unwrap() as usize;
			let rec = tree.record(i);
			assert_eq!(hexstr(&rec.to_bytes().unwrap()), r["binary"].as_str().unwrap(), "{} / leaf {}: binary", name, i);
			assert_eq!(rec.to_json_string().unwrap(), r["json"].as_str().unwrap(), "{} / leaf {}: JSON", name, i);
			assert_eq!(rec.leaf_id().unwrap().to_string(), r["leaf_id"].as_str().unwrap(), "{} / leaf {}: id", name, i);
		}
		// Every node the record rebuilds is the node the builder made.
		for i in 0..tree.len() {
			let branch = tree.record(i).branch().unwrap();
			for ((node, index), b) in tree.path(i).iter().zip(&branch.nodes) {
				assert_eq!(node.policy.unroll_script(), *b.unroll_script());
				assert_eq!(node.output(), b.output());
				assert_eq!(*index, b.index);
			}
		}
		println!("{}: batch output, {} records and every node rebuilt byte for byte", name, b["records"].as_array().unwrap().len());
	}
}

fn hexstr(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

struct Fx {
	genesis: BlockHash,
	s: Keypair,
	x: AssetId,
	fee_asset: AssetId,
	consensus: Verifier,
	standard: Verifier,
}

struct Batch {
	tree: Tree,
	owners: Vec<Keypair>,
	preimages: Vec<[u8; 32]>,
	round: Transaction,
	created: MedianTime,
}

impl Fx {
	fn new() -> Fx {
		let genesis = BlockHash::from_byte_array(label32("tree genesis"));
		Fx {
			genesis, s: keypair("tree S"), x: asset("tree X"), fee_asset: asset("tree fee asset"),
			consensus: Verifier::consensus(genesis), standard: Verifier::standard(genesis),
		}
	}

	/// `n` leaves at `radix`, with the specification's reserve rule, and a
	/// round that issues the token and pays the batch output.
	fn batch(&self, n: usize, radix: usize, label: &str) -> Batch {
		let created = MedianTime::from_consensus(1_791_000_000).unwrap();
		let day = 86_400;
		let issuer = OutPoint::new(Txid::from_raw_hash(sha256d::Hash::hash(format!("{} issuer", label).as_bytes())), 3);
		let token = AssetId::new_issuance(issuer, ContractHash::from_byte_array([0; 32]));
		let e = |d: u32| MedianTime::from_consensus(1_791_000_000 + d * day).unwrap();
		let w = RelativeTime::from_seconds_ceil(36 * 3600).unwrap();
		let schedule = ClockSchedule::new(token, xonly(&self.s), w, vec![e(28), e(56), e(84)]).unwrap();
		let params = TreeParams {
			asset: self.x, chain: Chain::new(self.genesis), schedule, burn: false, radix,
			reserve: ReserveRule::FeeRate { floor_per_kvb: 100, multiple: 4 }, min_leaf: 100,
		};
		let owners: Vec<Keypair> = (0..n).map(|i| keypair(&format!("{} owner {}", label, i))).collect();
		let preimages: Vec<[u8; 32]> = (0..n).map(|i| label32(&format!("{} preimage {}", label, i))).collect();
		let leaves: Vec<LeafSpec> = (0..n).map(|i| LeafSpec {
			template: Template::Vtxo1, owner: xonly(&owners[i]), value: 1_000_000 + 7 * i as u64,
			salt: label32(&format!("{} salt {}", label, i)), exit_delay: w, unlock_hash: sha256(&preimages[i]),
		}).collect();
		let tree = Tree::build(params, &leaves).unwrap();
		let mut round = Spend::new(0).input(issuer, explicit(self.x, 10_000_000_000, op_true().script_pubkey()), 0xffff_ffff)
			.outputs(vec![tree.batch_output().txout(), explicit(token, 1, tree.clock0_script_pubkey()), fee(self.x, 2_000)]).tx;
		round.input[0].asset_issuance = AssetIssuance {
			asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: [0; 32],
			amount: elements::confidential::Value::Explicit(1), inflation_keys: elements::confidential::Value::Null,
			denomination: 0,
		};
		Batch { tree, owners, preimages, round, created }
	}

	fn verify(&self, what: &str, u: &UnrollTx) {
		self.consensus.verify_tx(&u.prevouts, &u.tx)
			.unwrap_or_else(|(i, e)| panic!("{}: input {} refused by the block rules: {}", what, i, e));
		self.standard.verify_tx(&u.prevouts, &u.tx)
			.unwrap_or_else(|(i, e)| panic!("{}: input {} refused by the mempool checks: {}", what, i, e));
	}
}

#[derive(Default, Debug)]
struct Totals {
	trees: usize,
	branches: usize,
	node_txs: usize,
	entry_txs: usize,
	mutated: usize,
	distinct_nodes: usize,
}

fn fee_coin(fx: &Fx, label: &str) -> FeeSource {
	FeeSource::Coin {
		outpoint: OutPoint::new(Txid::from_raw_hash(sha256d::Hash::hash(label.as_bytes())), 1),
		coin: explicit(fx.fee_asset, 50_000, op_true().script_pubkey()),
		fee: 3_000,
		change: op_true().script_pubkey(),
	}
}

/// Builds the tree of `n` leaves at `radix` and runs every branch.
fn run_tree(fx: &Fx, n: usize, radix: usize, external: bool, totals: &mut Totals) {
	let label = format!("tree {} at radix {}", n, radix);
	let b = fx.batch(n, radix, &label);
	let round_txid = b.round.txid();
	let mut nodes_seen = HashSet::new();
	for i in 0..n {
		let ctx = format!("{} / leaf {}", label, i);
		let rec = b.tree.record(i);
		assert_eq!(LeafRecord::from_bytes(&rec.to_bytes().unwrap()).unwrap(), rec, "{}", ctx);
		let valid = rec.validate(&b.round).unwrap_or_else(|e| panic!("{}: {}", ctx, e));
		let branch = valid.branch;
		let batch = OutPoint::new(round_txid, valid.batch_vout);
		let owner = &b.owners[i];
		let auths: Vec<_> = branch.nodes.iter().map(|n| {
			let sg = sig(owner, &n.unroll_authorisation(b.created).digest);
			n.owner_auth(sg, b.created, xonly(owner))
		}).collect();

		// The reserve pays every fee.
		let txs = branch.unroll(batch, &auths, &vec![FeeSource::Reserve; branch.nodes.len()]).unwrap();
		for (level, u) in txs.iter().enumerate() {
			fx.verify(&format!("{}: node {}, reserve fee", ctx, level), u);
			totals.node_txs += 1;
			// One child one atom off: the node refuses it.
			let node = &branch.nodes[level];
			let c = (i + level) % node.children.len();
			let mut bad = u.tx.clone();
			let v = bad.output[c].value.explicit().unwrap();
			bad.output[c].value = elements::confidential::Value::Explicit(v + 1);
			let e = fx.consensus.verify_input(&u.prevouts, 0, &bad).err()
				.unwrap_or_else(|| panic!("{}: node {} accepts child {} one atom over", ctx, level, c));
			assert!(e.to_string().contains(EQUALVERIFY), "{}: {}", ctx, e);
			totals.mutated += 1;
			// Each distinct node once more, with every child mutated in turn.
			if nodes_seen.insert(node.program()) {
				totals.distinct_nodes += 1;
				for c in 0..node.children.len() {
					let mut bad = u.tx.clone();
					let v = bad.output[c].value.explicit().unwrap();
					bad.output[c].value = elements::confidential::Value::Explicit(v - 1);
					assert!(fx.consensus.verify_input(&u.prevouts, 0, &bad).is_err(), "{}: child {} one atom short", ctx, c);
					totals.mutated += 1;
				}
			}
		}
		let entry_at = branch.entry_outpoint(&txs).unwrap();
		let e = branch.entry_tx(entry_at, &b.preimages[i], &FeeSource::Reserve).unwrap();
		fx.verify(&format!("{}: entry, reserve fee", ctx), &e);
		totals.entry_txs += 1;

		// A fee coin the broadcaster attaches pays every fee instead.
		if external {
			let fees: Vec<FeeSource> = (0..branch.nodes.len()).map(|l| fee_coin(fx, &format!("{} fee {}", ctx, l))).collect();
			let mut ext = branch.unroll(batch, &auths, &fees).unwrap();
			for (level, u) in ext.iter_mut().enumerate() {
				assert_eq!(u.tx.input.len(), 2);
				assert_ne!(u.tx.txid(), txs[level].tx.txid(), "{}: the fee coin changes the id", ctx);
				u.tx.input[1].witness.script_witness = op_true_witness();
				fx.verify(&format!("{}: node {}, fee coin", ctx, level), u);
				totals.node_txs += 1;
			}
			let mut e = branch.entry_tx(branch.entry_outpoint(&ext).unwrap(), &b.preimages[i],
				&fee_coin(fx, &format!("{} entry fee", ctx))).unwrap();
			e.tx.input[1].witness.script_witness = op_true_witness();
			fx.verify(&format!("{}: entry, fee coin", ctx), &e);
			totals.entry_txs += 1;
		}
		totals.branches += 1;
	}
	totals.trees += 1;
}

#[test]
fn every_branch_of_every_tree_from_1_to_100_leaves() {
	let fx = Fx::new();
	let mut totals = Totals::default();
	for n in 1..=100 {
		run_tree(&fx, n, 4, true, &mut totals);
	}
	println!("radix 4, 1 to 100 leaves: {:?}", totals);
	let mut other = Totals::default();
	for radix in [2, 3, 5, 6] {
		for n in 1..=40 {
			run_tree(&fx, n, radix, false, &mut other);
		}
	}
	println!("radix 2, 3, 5 and 6, 1 to 40 leaves, reserve fees: {:?}", other);
}

#[test]
fn reserves_cover_each_spend_at_the_fee_floor() {
	let fx = Fx::new();
	for n in [1, 4, 5, 16, 17, 64, 100] {
		let b = fx.batch(n, 4, &format!("reserve check {}", n));
		for i in [0, n - 1] {
			let branch = b.tree.record(i).branch().unwrap();
			let owner = &b.owners[i];
			let auths: Vec<_> = branch.nodes.iter().map(|nd| {
				nd.owner_auth(sig(owner, &nd.unroll_authorisation(b.created).digest), b.created, xonly(owner))
			}).collect();
			let txs = branch.unroll(OutPoint::new(b.round.txid(), 0), &auths, &vec![FeeSource::Reserve; branch.nodes.len()]).unwrap();
			let mut sizes = vec![];
			for (u, nd) in txs.iter().zip(&branch.nodes) {
				let need = (u.tx.vsize() as u64 * 100).div_ceil(1000) * 4;
				assert!(nd.reserve >= need, "{} leaves: reserve {} for a {} vB unroll", n, nd.reserve, u.tx.vsize());
				// The estimate counts the time at five bytes; the real one has four.
				assert!(nd.reserve <= need + 4, "{} leaves: reserve {} far above {}", n, nd.reserve, need);
				sizes.push(u.tx.vsize());
			}
			let e = branch.entry_tx(branch.entry_outpoint(&txs).unwrap(), &b.preimages[i], &FeeSource::Reserve).unwrap();
			assert_eq!(branch.entry_value - branch.entry.value, (e.tx.vsize() as u64 * 100).div_ceil(1000) * 4);
			println!("{:>3} leaves, leaf {:>2}: unrolls {:?} vB, entry {} vB, reserves {:?} and {}", n, i, sizes,
				e.tx.vsize(), branch.nodes.iter().map(|x| x.reserve).collect::<Vec<_>>(), branch.entry_value - branch.entry.value);
		}
	}
}

#[test]
fn the_builder_refuses() {
	let fx = Fx::new();
	let b = fx.batch(3, 4, "refusals");
	let params = b.tree.params().clone();
	let leaves: Vec<LeafSpec> = b.tree.leaves().iter().map(|l| l.spec).collect();
	assert_eq!(Tree::build(params.clone(), &[]).unwrap_err(), TreeError::NoLeaves);
	for radix in [0, 1, 7] {
		assert_eq!(Tree::build(TreeParams { radix, ..params.clone() }, &leaves).unwrap_err(), TreeError::Radix(radix));
	}
	let mut small = leaves.clone();
	small[1].value = 99;
	assert!(matches!(Tree::build(params.clone(), &small).unwrap_err(), TreeError::LeafValue { leaf: 1, .. }));
	let mut zero = leaves.clone();
	zero[2].value = 0;
	assert!(matches!(Tree::build(TreeParams { min_leaf: 0, ..params.clone() }, &zero).unwrap_err(), TreeError::LeafValue { leaf: 2, .. }));
	let mut twice = leaves.clone();
	twice[2] = twice[0];
	assert_eq!(Tree::build(params.clone(), &twice).unwrap_err(), TreeError::DuplicateLeaf { first: 0, second: 2 });
	let mut huge = leaves.clone();
	for l in &mut huge {
		l.value = arca_covenant::record::MAX_VALUE / 2;
	}
	assert_eq!(Tree::build(params.clone(), &huge).unwrap_err(), TreeError::ValueSum);
	let backwards = ClockSchedule::new_unchecked(params.schedule.token, params.schedule.operator, params.schedule.notice,
		vec![params.schedule.expiries()[1], params.schedule.expiries()[0]]).unwrap();
	assert_eq!(Tree::build(TreeParams { schedule: backwards, ..params.clone() }, &leaves).unwrap_err(), TreeError::ScheduleBackwards(1));
	let many = vec![leaves[0]; arca_covenant::gate::MAX_OWNERS + 1];
	assert_eq!(Tree::build(params, &many).unwrap_err(), TreeError::TooManyLeaves(arca_covenant::gate::MAX_OWNERS + 1));
	let _ = TxOut::default();
}

#[test]
fn a_1024_leaf_batch_matches_the_specification_sizes() {
	// The specification's table: a node of a 1,024-leaf batch at each member
	// depth, its reserve paying the fee.
	let fx = Fx::new();
	let b = fx.batch(1024, 4, "a 1024-leaf batch");
	assert_eq!(b.tree.levels().iter().map(|l| l.len()).collect::<Vec<_>>(), vec![256, 64, 16, 4, 1]);
	let records = b.tree.records();
	for i in [0, 511, 1023] {
		let v = records[i].validate(&b.round).unwrap();
		let owner = &b.owners[i];
		let auths: Vec<_> = v.branch.nodes.iter().map(|nd| {
			nd.owner_auth(sig(owner, &nd.unroll_authorisation(b.created).digest), b.created, xonly(owner))
		}).collect();
		let txs = v.branch.unroll(OutPoint::new(b.round.txid(), 0), &auths, &vec![FeeSource::Reserve; 5]).unwrap();
		let depths: Vec<usize> = v.branch.nodes.iter().map(|nd| nd.gate.depth).collect();
		let sizes: Vec<usize> = txs.iter().map(|u| u.tx.vsize()).collect();
		for (k, u) in txs.iter().enumerate() {
			fx.verify(&format!("1024 / leaf {} / node {}", i, k), u);
		}
		assert_eq!(depths, vec![11, 9, 7, 5, 3]);
		assert_eq!(sizes, vec![616, 593, 571, 549, 527], "leaf {}", i);
		println!("1,024 leaves, leaf {:>4}: member depths {:?}, unrolls {:?} vB, record {} bytes", i, depths, sizes,
			records[i].to_bytes().unwrap().len());
	}
}
