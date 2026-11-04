//! The mass-exit drill: every holder of a full batch leaves at once, alone,
//! with the operator gone.
//!
//! The operator builds a batch of at most 1,024 leaves (`server/README.md`,
//! Rounds), as a tree at radix 4 or, when it expects few exits, as one
//! accumulator output. Each test here builds the largest such batch with
//! this crate's builder, confirms its round, and from then on the operator
//! does nothing: no signature, no answer, no transaction. Every holder then
//! brings its leaf on the chain from its record alone and claims it after
//! its exit delay, as the wallet's exit does (`bark/src/arca/exit.rs`):
//!
//! - a tree leaf: each node of its path from the lowest one unspent, by its
//!   own unroll authorisations, then its entry with its preimage; a node
//!   another holder already unrolled, in a block or the mempool, is taken as
//!   it stands;
//! - an accumulator leaf: its exit from the batch output where the last
//!   exit left it, in a block or the mempool, then its entry;
//! - then, once the exit delay has run from the leaf's confirmation, the
//!   owner's claim, its fee from the leaf.
//!
//! Every holder tries its next step before every block and tries again
//! before the next one when the node refuses it for the mempool's chain
//! limits (`too-long-mempool-chain`); any other refusal fails the drill.
//! Blocks are the node's own (`generatetodescriptor`), one a minute, filled
//! by its block assembler from the mempool under the testnet's block budget.
//! A testnet block holds 89,999 vB of transactions: 396,000 weight units
//! less 4,000 for the coinbase, 4 for the block's script and 32,000 reserved
//! for the committee's signatures (`node/miner.cpp`). The regtest chain
//! reserves its block proof through its dynamic federation parameters
//! instead, so the drill's node runs with `-blockmaxweight=364000`: 360,000
//! weight units after the coinbase's 4,000, less those parameters, so a
//! block here holds a little under 89,999 vB. The drill asserts that no
//! block holds more than 89,999 and prints the fullest.
//!
//! It prints, block by block, what went on the chain (vbytes by kind, and
//! for a tree by level), the blocks each stage took, the fees by asset, and
//! how long the last holder waited from the round's block to its claim's.
//! No batch on Sequentia is swept, so no holder races an expiry: the wait is
//! the whole cost of leaving.
//!
//! A drill, not a check of every change: the two tests take about ten
//! minutes together, so CI skips them. Run them with
//!
//!     cargo test -p arca-covenant --test mass_exit -- --ignored --nocapture
//!
//! Needs `SEQUENTIAD_EXEC`. Each test has a chain of its own.

mod common;

use std::collections::{BTreeMap, HashMap};

use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Transaction, Txid};
use serde_json::json;

use arca_covenant::accumulator::{ExitAuth, SLOTS};
use arca_covenant::spend::FeeSource;
use arca_covenant::tree::{LeafSpec, ReserveRule};
use arca_covenant::*;

use common::net::*;
use common::round::*;
use common::*;

/// The leaves of a full batch.
const LEAVES: usize = SLOTS;
/// The testnet's payload per block: 396,000 weight units, less 4,000 for the
/// coinbase, 4 for the block's script and 32,000 for its signatures.
const BLOCK_VBYTES: u64 = 89_999;
/// The vbytes the wallet prices a leaf's claim at (`claim_vsize`).
const CLAIM_VSIZE: u64 = 220;

/// What a transaction of the drill is.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Kind {
	/// A tree node's unroll, by its level counted from the batch output (0).
	Unroll(usize),
	/// An exit from an accumulator batch.
	AccExit,
	/// An entry into its leaf.
	Entry,
	/// The owner's claim of its leaf, after the exit delay.
	Claim,
}

impl Kind {
	fn name(&self) -> String {
		match self {
			Kind::Unroll(l) => format!("unroll level {}", l),
			Kind::AccExit => "accumulator exit".into(),
			Kind::Entry => "entry".into(),
			Kind::Claim => "claim".into(),
		}
	}
}

/// The chain as the drill sees it: what it broadcast, block by block.
struct Drill {
	net: Net,
	floor_per_kvb: u64,
	kinds: HashMap<Txid, Kind>,
	/// Per block: its height, its time, and per kind the transactions and vbytes.
	blocks: Vec<(u64, u64, BTreeMap<Kind, (usize, u64)>)>,
	/// Fees paid by the drill's transactions, by asset.
	fees: BTreeMap<AssetId, u64>,
	/// Where each drill transaction confirmed: height and block time.
	confirmed: HashMap<Txid, (u64, u64)>,
	/// Refusals for the mempool's chain limits, by kind.
	chain_limited: BTreeMap<Kind, usize>,
	round_block: (u64, u64),
	/// The most vbytes of transactions any block held.
	fullest: u64,
}

impl Drill {
	fn start() -> Drill {
		let net = Net::start_with(&["-blockmaxweight=364000"]);
		let info = net.rpc("getmempoolinfo", json!([]));
		let floor_per_kvb = (info["minrelaytxfee"].as_f64().unwrap() * 1e8).round() as u64;
		Drill {
			net, floor_per_kvb, kinds: HashMap::new(), blocks: vec![], fees: BTreeMap::new(), confirmed: HashMap::new(),
			chain_limited: BTreeMap::new(), round_block: (0, 0), fullest: 0,
		}
	}

	/// The round of a batch without a sweep, as the operator builds it with
	/// `[batches] no_sweep`: it issues nothing and pays the batch output, the
	/// connector output, change and the fee. Broadcast and mined; returns its
	/// txid and the transaction.
	fn round(&mut self, s: &Keypair, batch: &ExplicitOutput) -> (Txid, Transaction) {
		let funding = self.net.fund(vec![explicit(self.net.x, batch.value + 200_000, op_true_spk())]).remove(0);
		let total = funding.txout.value.explicit().unwrap();
		let outs = vec![batch.txout(), ConnectorPolicy { operator: xonly(s) }.output(self.net.x, 5_000).txout(),
			explicit(self.net.x, total - batch.value - 5_000 - 2_000, op_true_spk()), fee(self.net.x, 2_000)];
		let mut sp = spend(0).coin(&funding, 0xffff_ffff).outputs(outs);
		sp.witness(0, op_true_witness());
		let id = self.net.rt.client().send_raw_transaction(&sp.tx).unwrap();
		self.block();
		let r = self.net.rpc("getrawtransaction", json!([id.to_string(), true]));
		let h = self.net.rpc("getblockheader", json!([r["blockhash"]]));
		self.round_block = (h["height"].as_u64().unwrap(), h["time"].as_u64().unwrap());
		(id, sp.tx)
	}

	/// Broadcasts `tx` of `kind`: true when the mempool took it, false when
	/// it refused it for its chain limits; any other refusal fails the drill.
	fn send(&mut self, kind: Kind, tx: &Transaction) -> bool {
		match self.net.rt.client().send_raw_transaction(tx) {
			Ok(id) => {
				self.kinds.insert(id, kind);
				true
			},
			Err(e) => {
				let why = e.to_string();
				assert!(why.contains("too-long-mempool-chain"), "{} {}: refused: {}", kind.name(), tx.txid(), why);
				*self.chain_limited.entry(kind).or_default() += 1;
				false
			},
		}
	}

	/// One block a minute after the last, from the mempool by the node's own
	/// assembler; records what of the drill it holds.
	fn block(&mut self) -> u64 {
		self.net.mock = self.net.mock.max(self.net.tip_time()) + 60;
		self.net.set_mock(self.net.mock);
		self.net.mine(1);
		let hash = self.net.rpc("getbestblockhash", json!([]));
		let b = self.net.rpc("getblock", json!([hash, 2]));
		let (height, time) = (b["height"].as_u64().unwrap(), b["time"].as_u64().unwrap());
		let mut by_kind: BTreeMap<Kind, (usize, u64)> = BTreeMap::new();
		let mut payload = 0;
		for tx in b["tx"].as_array().unwrap().iter().skip(1) {
			let id: Txid = tx["txid"].as_str().unwrap().parse().unwrap();
			let vsize = tx["vsize"].as_u64().unwrap();
			payload += vsize;
			if let Some(k) = self.kinds.get(&id) {
				let e = by_kind.entry(*k).or_default();
				e.0 += 1;
				e.1 += vsize;
				self.confirmed.insert(id, (height, time));
				for o in tx["vout"].as_array().unwrap() {
					if o["scriptPubKey"]["hex"].as_str() == Some("") {
						let a: AssetId = o["asset"].as_str().unwrap().parse().unwrap();
						let v = (o["value"].as_f64().unwrap() * 1e8).round() as u64;
						*self.fees.entry(a).or_default() += v;
					}
				}
			}
		}
		assert!(payload <= BLOCK_VBYTES, "block {} holds {} vB of transactions, more than {}", height, payload, BLOCK_VBYTES);
		self.fullest = self.fullest.max(payload);
		if !by_kind.is_empty() {
			self.blocks.push((height, time, by_kind));
		}
		height
	}

	/// Whether `txid` is in a block.
	fn in_block(&self, txid: &Txid) -> bool {
		self.confirmed.contains_key(txid)
	}

	/// The claim's fee: the wallet's price for it at four times the floor,
	/// the multiple the reserves are built at.
	fn claim_fee(&self) -> u64 {
		(CLAIM_VSIZE * self.floor_per_kvb * 4).div_ceil(1_000)
	}

	/// Prints the blocks, the stages and the fees; returns the number of
	/// blocks that held any of the drill's transactions.
	fn report(&self, label: &str) -> usize {
		println!("\n{}: block by block (only blocks holding the drill's transactions)", label);
		println!("{:>7} {:>9}  {:>8}  {}", "height", "+minutes", "vbytes", "what");
		for (h, t, kinds) in &self.blocks {
			let total: u64 = kinds.values().map(|(_, v)| v).sum();
			let what: Vec<String> = kinds.iter().map(|(k, (n, v))| format!("{} x{} {} vB", k.name(), n, v)).collect();
			println!("{:>7} {:>9}  {:>8}  {}", h, (t - self.round_block.1) / 60, total, what.join("; "));
		}
		let mut stages: BTreeMap<Kind, (usize, u64, u64, u64, usize)> = BTreeMap::new();
		for (h, _, kinds) in &self.blocks {
			for (k, (n, v)) in kinds {
				let e = stages.entry(*k).or_insert((0, 0, u64::MAX, 0, 0));
				e.0 += n;
				e.1 += v;
				e.2 = e.2.min(*h);
				e.3 = e.3.max(*h);
				e.4 += 1;
			}
		}
		println!("\n{}: by stage", label);
		println!("{:<20} {:>6} {:>9} {:>9} {:>8} {:>10} {:>10}", "stage", "txs", "vbytes", "vB/tx", "blocks", "first", "last");
		let mut all = 0;
		for (k, (n, v, first, last, blocks)) in &stages {
			all += v;
			println!("{:<20} {:>6} {:>9} {:>9.1} {:>8} {:>10} {:>10}", k.name(), n, v, *v as f64 / *n as f64, blocks, first, last);
		}
		println!("all stages: {} vB, {:.2} blocks' worth at {} vB a block; {} blocks held them", all,
			all as f64 / BLOCK_VBYTES as f64, BLOCK_VBYTES, self.blocks.len());
		println!("the fullest block held {} vB of transactions", self.fullest);
		println!("refused for the mempool's chain limits and tried again a block later: {:?}",
			self.chain_limited.iter().map(|(k, n)| (k.name(), *n)).collect::<Vec<_>>());
		for (a, f) in &self.fees {
			println!("fees in {}: {} atoms", a, f);
		}
		self.blocks.len()
	}

	/// Mines until the last of `claims` confirms, trying each owner's claim
	/// once its exit delay has run; returns the last claim's block.
	fn claims(&mut self, mut pending: Vec<(Txid, Box<dyn Fn(&Net) -> Transaction>)>) -> (u64, u64) {
		let mut ready: Vec<Option<u64>> = vec![None; pending.len()];
		let mut sent: Vec<Option<Txid>> = vec![None; pending.len()];
		let mut last = (0, 0);
		for (i, (entry, _)) in pending.iter().enumerate() {
			ready[i] = Some(self.net.csv_ready(entry, delay()));
		}
		while sent.iter().any(|s| s.map_or(true, |id| !self.in_block(&id))) {
			let mtp = self.net.mtp();
			for (i, (_, build)) in pending.iter_mut().enumerate() {
				if sent[i].is_some() {
					continue;
				}
				if mtp > ready[i].unwrap() {
					let tx = build(&self.net);
					if self.send(Kind::Claim, &tx) {
						sent[i] = Some(tx.txid());
					}
				}
			}
			self.block();
			for id in sent.iter().flatten() {
				if let Some(at) = self.confirmed.get(id) {
					last = last.max(*at);
				}
			}
		}
		last
	}
}

/// Every holder of a full 1,024-leaf tree at radix 4 leaves at once.
#[test]
#[ignore = "the mass-exit drill, about ten minutes: run with --ignored"]
fn every_holder_of_a_full_tree_batch_leaves_at_once() {
	let mut d = Drill::start();
	let s = keypair("mass exit operator");
	let x = d.net.x;
	let owners: Vec<Keypair> = (0..LEAVES).map(|i| keypair(&format!("mass exit owner {}", i))).collect();
	let preimages: Vec<[u8; 32]> = (0..LEAVES).map(|i| label32(&format!("mass exit preimage {}", i))).collect();
	let specs: Vec<LeafSpec> = (0..LEAVES)
		.map(|i| spec(&owners[i], &format!("mass exit leaf {}", i), LEAF, hash(&preimages[i]))).collect();
	let tree = Tree::build(TreeParams {
		asset: x, chain: d.net.chain, schedule: ClockSchedule::never(xonly(&s)), burn: false, delegated_reclaim: true, radix: 4,
		reserve: ReserveRule::FeeRate { floor_per_kvb: d.floor_per_kvb, multiple: 4 }, min_leaf: 1,
	}, &specs).unwrap();
	let (round_id, round) = d.round(&s, &tree.batch_output());
	println!("a 1,024-leaf tree at radix 4 without a sweep, RECLAIM-D on its lowest nodes, in X (listed for fees 1:1), floor {} atoms/kvB, reserves at 4x; round {} in block {}",
		d.floor_per_kvb, round_id, d.round_block.0);

	// Each holder checks its record against the round and signs its unroll
	// authorisations; from here the operator does nothing.
	let policy = WalletPolicy::no_sweep(d.net.chain, xonly(&s), mt(d.net.mtp()));
	let t = mt(d.net.mtp() - 1);
	let holders: Vec<(ValidLeaf, Vec<UnrollAuth>)> = (0..LEAVES).map(|i| {
		let v = tree.record(i).validate(&round, &policy, &xonly(&owners[i]), &specs[i].owner_nonce)
			.unwrap_or_else(|e| panic!("leaf {}: {}", i, e));
		let auths = owner_auths(&v, &owners[i], t);
		(v, auths)
	}).collect();
	let levels = holders[0].0.branch.nodes.len();
	println!("{} levels of nodes above each leaf; the operator is gone", levels);

	// Bring every leaf on the chain.
	let mut unrolled: HashMap<[u8; 32], Txid> = HashMap::new();
	let mut entries: Vec<Option<Txid>> = vec![None; LEAVES];
	while entries.iter().any(|e| e.map_or(true, |id| !d.in_block(&id))) {
		for (i, (v, auths)) in holders.iter().enumerate() {
			if entries[i].is_some() {
				continue;
			}
			let mut at = OutPoint::new(round_id, 0);
			let mut blocked = false;
			for (level, (node, auth)) in v.branch.nodes.iter().zip(auths).enumerate() {
				if let Some(id) = unrolled.get(&node.program()) {
					at = OutPoint::new(*id, node.index as u32);
					continue;
				}
				let u = node.unroll_tx(at, auth, &FeeSource::Reserve).unwrap();
				if !d.send(Kind::Unroll(level), &u.tx) {
					blocked = true;
					break;
				}
				unrolled.insert(node.program(), u.tx.txid());
				at = OutPoint::new(u.tx.txid(), node.index as u32);
			}
			if blocked {
				continue;
			}
			let e = v.branch.entry_tx(at, &preimages[i], &FeeSource::Reserve).unwrap();
			if d.send(Kind::Entry, &e.tx) {
				entries[i] = Some(e.tx.txid());
			}
		}
		d.block();
	}
	let nodes = unrolled.len();
	let last_entry = entries.iter().map(|e| d.confirmed[&e.unwrap()]).max().unwrap();
	println!("every leaf on the chain: {} unrolls and {} entries, the last in block {} ({} min after the round)",
		nodes, LEAVES, last_entry.0, (last_entry.1 - d.round_block.1) / 60);
	assert_eq!(nodes, 1 + 4 + 16 + 64 + 256, "every node of the tree unrolled once");

	// Every owner claims its leaf once the exit delay has run.
	let fee = d.claim_fee();
	let claims: Vec<(Txid, Box<dyn Fn(&Net) -> Transaction>)> = (0..LEAVES).map(|i| {
		let leaf = holders[i].0.branch.leaf;
		let at = OutPoint::new(entries[i].unwrap(), 0);
		let owner = owners[i];
		let f: Box<dyn Fn(&Net) -> Transaction> = Box::new(move |net: &Net| {
			let ks = leaf.exit_tx(at, x, LEAF, &[ExplicitOutput::new(x, LEAF - fee, op_true_spk())], &FeeSource::Reserve).unwrap();
			signed(net, ks, &owner, vec![]).tx
		});
		(entries[i].unwrap(), f)
	}).collect();
	let last = d.claims(claims);
	let blocks = d.report("full tree, 1,024 leaves");
	println!("\nthe last holder's claim confirmed in block {}, {} blocks and {:.1} hours after the round's block; \
		its exit delay is {:.1} hours of that", last.0, last.0 - d.round_block.0, (last.1 - d.round_block.1) as f64 / 3600.0,
		delay().seconds() as f64 / 3600.0);
	println!("the claim's fee: {} atoms of X each", fee);
	assert!(blocks > 0);
	assert_eq!(d.kinds.values().filter(|k| **k == Kind::Claim).count(), LEAVES);
}

/// Every holder of a full 1,024-leaf accumulator batch leaves at once.
#[test]
#[ignore = "the mass-exit drill, about ten minutes: run with --ignored"]
fn every_holder_of_a_full_accumulator_batch_leaves_at_once() {
	let mut d = Drill::start();
	let s = keypair("mass exit accumulator operator");
	let x = d.net.x;
	let owners: Vec<Keypair> = (0..LEAVES).map(|i| keypair(&format!("mass exit acc owner {}", i))).collect();
	let preimages: Vec<[u8; 32]> = (0..LEAVES).map(|i| label32(&format!("mass exit acc preimage {}", i))).collect();
	let specs: Vec<LeafSpec> = (0..LEAVES)
		.map(|i| spec(&owners[i], &format!("mass exit acc leaf {}", i), LEAF, hash(&preimages[i]))).collect();
	let acc = Accumulator::build(AccumulatorParams {
		asset: x, chain: d.net.chain, schedule: ClockSchedule::never(xonly(&s)), burn: false,
		reserve: ReserveRule::FeeRate { floor_per_kvb: d.floor_per_kvb, multiple: 4 }, min_leaf: 1,
	}, &specs).unwrap();
	let (round_id, round) = d.round(&s, &acc.batch_output());
	println!("a 1,024-leaf accumulator batch without a sweep in X, floor {} atoms/kvB, reserves at 4x; round {} in block {}",
		d.floor_per_kvb, round_id, d.round_block.0);

	let policy = WalletPolicy::no_sweep(d.net.chain, xonly(&s), mt(d.net.mtp()));
	let t = mt(d.net.mtp() - 1);
	let holders: Vec<(ValidAccumulatorLeaf, ExitAuth)> = (0..LEAVES).map(|i| {
		let v = acc.record(i).validate(&round, &policy, &xonly(&owners[i]), &specs[i].owner_nonce)
			.unwrap_or_else(|e| panic!("slot {}: {}", i, e));
		let a = ExitAuth { by_operator: false, time: t, signature: sig(&owners[i], &v.exit_digest(t)) };
		(v, a)
	}).collect();

	// Each holder, before each block, leaves from the batch output where the
	// last exit left it, in a block or the mempool, then opens its entry, as
	// the wallet's exit does; the exits of one batch spend each other's rest.
	let (mut state, mut at, mut held) = (*acc.policy(), OutPoint::new(round_id, 0), acc.total());
	let mut exits: Vec<Option<Txid>> = vec![None; LEAVES];
	let mut entries: Vec<Option<Txid>> = vec![None; LEAVES];
	let mut order: Vec<usize> = (0..LEAVES).collect();
	let mut pass = 0usize;
	while entries.iter().any(|e| e.map_or(true, |id| !d.in_block(&id))) {
		// Holders act in a different order each pass, as independent
		// wallets do.
		order.rotate_left((pass * 389) % LEAVES);
		pass += 1;
		for &i in &order {
			let (v, a) = &holders[i];
			if exits[i].is_none() {
				let u = v.exit_tx(&state, at, held, a, &FeeSource::Reserve).unwrap();
				if !d.send(Kind::AccExit, &u.tx) {
					continue;
				}
				exits[i] = Some(u.tx.txid());
				state = state.after(v.exit.slot);
				// The rest, at output 1, under the state after this exit;
				// the last exit leaves none.
				if let Some(o) = u.tx.output.get(1).filter(|o| o.script_pubkey == state.script_pubkey()) {
					at = OutPoint::new(u.tx.txid(), 1);
					held = o.value.explicit().unwrap();
				}
			}
			if entries[i].is_none() {
				let e = v.entry_tx(OutPoint::new(exits[i].unwrap(), 0), &preimages[i], &FeeSource::Reserve).unwrap();
				if d.send(Kind::Entry, &e.tx) {
					entries[i] = Some(e.tx.txid());
				}
			}
		}
		d.block();
	}
	let last_entry = entries.iter().map(|e| d.confirmed[&e.unwrap()]).max().unwrap();
	println!("every leaf on the chain: {} exits and {} entries, the last in block {} ({} min after the round)",
		LEAVES, LEAVES, last_entry.0, (last_entry.1 - d.round_block.1) / 60);

	let fee = d.claim_fee();
	let claims: Vec<(Txid, Box<dyn Fn(&Net) -> Transaction>)> = (0..LEAVES).map(|i| {
		let leaf = holders[i].0.leaf;
		let at = OutPoint::new(entries[i].unwrap(), 0);
		let owner = owners[i];
		let f: Box<dyn Fn(&Net) -> Transaction> = Box::new(move |net: &Net| {
			let ks = leaf.exit_tx(at, x, LEAF, &[ExplicitOutput::new(x, LEAF - fee, op_true_spk())], &FeeSource::Reserve).unwrap();
			signed(net, ks, &owner, vec![]).tx
		});
		(entries[i].unwrap(), f)
	}).collect();
	let last = d.claims(claims);
	d.report("accumulator batch, 1,024 leaves");
	println!("\nthe last holder's claim confirmed in block {}, {} blocks and {:.1} hours after the round's block; \
		its exit delay is {:.1} hours of that", last.0, last.0 - d.round_block.0, (last.1 - d.round_block.1) as f64 / 3600.0,
		delay().seconds() as f64 / 3600.0);
	assert_eq!(d.kinds.values().filter(|k| **k == Kind::Claim).count(), LEAVES);
}
