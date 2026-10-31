//! `order-3` on regtest: every way A3.3 found to reverse a spend made in the
//! tree, run against the resting-order template, and each refused; a fill
//! with an annex refused; and an `order-2` leaf, resting from before
//! `order-3`, still filled.
//!
//! Eight `order-3` leaves (orders A to H) and one `order-2` leaf (order O) sit
//! beside seven ordinary leaves in
//! one batch of asset X behind their hash-locked entries; the round and the
//! unroll are the frozen ones, and the operator alone brings the orders to the
//! chain (its own authorisations, the entry preimages it chose): no key of a
//! maker is used. The takers' leaves of Y sit in a batch of their own, so a
//! fill made in the tree is published, as the operator would, with the
//! taker's lineage. Every negative case is refused by `testmempoolaccept`, by
//! `sendrawtransaction`, and when forced into a block with `generateblock` on
//! a node checking scripts inline (`-par=1`), the block's reason asserted.
//! A Simplicity failure names no rule, so each negative is a copy of a control
//! the node accepts with one property changed, and the Rust judge
//! (`OrderPolicy::check`) names the rule it breaks.
//!
//! - **A. The template on the chain.** Fills of order A by the operator's
//!   signature, each credit to a leaf of its own and each remainder under the
//!   next salt, four along one lineage and no fifth; the refusals against
//!   those controls; the landing after the delay, as SeqDEX's own order, which
//!   a taker then fills on the chain.
//! - **B. A taker's fill made in the tree (A3.3's order B).** The maker brings
//!   its order to the chain and tries every way to outrun the fill: its own
//!   fill, the landing at once, the collaborative path alone. Each is refused;
//!   the operator publishes the taker's lineage and the fill, and it is mined.
//! - **C. The taker's coin spent directly (A3.3's order C).** The same, with
//!   no checkpoint on the taker's side: the fill stands, and the taker cannot
//!   take back the coin it paid with.
//! - **D. Past the order's REFUND time (A3.3's order D).** The leaf has no
//!   REFUND: a fill made in the tree before the time stands after it.
//! - **E. Two fills of one size (A3.3's two credits).** Two credits of one
//!   value, each under a script of its own: the maker's pair over one spends
//!   only that one.
//! - **H. Given up in a refresh (A3.3's order H).** The forfeit of the order
//!   leaf, signed by maker and operator: the maker cannot outrun it either,
//!   nor the checkpoint of a cancel.
//! - **The operator alone** cannot take an order: not by the collaborative
//!   path, nor by a fill that pays anyone but the maker, nor by the landing.
//! - **No annex.** The operator's signed fill of A and the on-chain fill of
//!   A's landed order (`seqdex/order` version 2), each with an annex of 3 and
//!   of 1,000 bytes and a zero annex of 1,000 bytes on the order's input, are refused at relay and in a block
//!   by the program (`Assertion failed`), beside the same fills without one,
//!   which are mined.
//! - **O. An `order-2` leaf.** Its program takes an annex nobody signed,
//!   which is why new orders rest as `order-3`: its fill with a 1,000-byte
//!   annex is mined (through the mempool on a node before Sequentia 25.2.4,
//!   which relays it; by `generateblock` on one from it, whose relay refuses
//!   a nonzero annex). The order fills as before: the remainder rests as
//!   `order-2`, and its own fill is mined.
//!
//! Needs `SEQUENTIAD_EXEC`; run with `--nocapture` for the table.

mod common;

use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use elements::hex::FromHex;
use elements::secp256k1_zkp::rand::{CryptoRng, RngCore};
use elements::secp256k1_zkp::{Keypair, Secp256k1};
use elements::{AssetIssuance, Script, Transaction, TxOut, TxOutSecrets};
use serde_json::{json, Value};

use arca_covenant::order::{OrderPolicy, OrderTerms, SeqdexOrder, SeqdexVersion};
use arca_covenant::script::sha256;
use arca_covenant::*;

use common::net::*;
use common::*;

const N: u64 = 10_000_000;
const ENTRY_RESERVE: u64 = 1_000;
const NODE_RESERVE: u64 = 3_000;
const FEE: u64 = 6_000;
const LEAVES: usize = 16;

/// A deterministic generator for the one confidential output.
struct Det(u64);
impl RngCore for Det {
	fn next_u32(&mut self) -> u32 {
		self.next_u64() as u32
	}
	fn next_u64(&mut self) -> u64 {
		self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
		self.0
	}
	fn fill_bytes(&mut self, d: &mut [u8]) {
		for b in d {
			*b = (self.next_u64() >> 33) as u8;
		}
	}
	fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), elements::secp256k1_zkp::rand::Error> {
		self.fill_bytes(d);
		Ok(())
	}
}
impl CryptoRng for Det {}

/// An output whose asset and value are both blinded, with valid proofs: only
/// a script can refuse it.
fn confidential(asset: elements::AssetId, value: u64, spk: Script, inputs: &[(elements::AssetId, u64)]) -> TxOut {
	let secp = Secp256k1::new();
	let secrets: Vec<TxOutSecrets> = inputs.iter()
		.map(|(a, v)| TxOutSecrets::new(*a, AssetBlindingFactor::zero(), *v, ValueBlindingFactor::zero())).collect();
	let blinder = keypair("confidential blinder").public_key();
	let (o, _, _, _) = TxOut::new_last_confidential(&mut Det(7), &secp, value, asset, spk, blinder, &secrets, &[]).unwrap();
	o
}

/// `OP_1 <key>`: a plain key.
fn plain(key: &Keypair) -> Script {
	elements::script::Builder::new().push_int(1).push_slice(&xonly(key).serialize()).into_script()
}

/// A maker's order and its keys.
struct Maker {
	leaf_key: Keypair,
	credit_keys: Vec<Keypair>,
	refund_key: Keypair,
	order: OrderPolicy,
}

fn maker(net: &Net, s: &Keypair, name: &str, terms: OrderTerms, expiry: u32, version: SeqdexVersion) -> Maker {
	let leaf_key = keypair(&format!("order-2 maker {} leaf key", name));
	let credit_keys: Vec<Keypair> = (0..4).map(|i| keypair(&format!("order-2 maker {} credit key {}", name, i))).collect();
	let refund_key = keypair(&format!("order-2 maker {} refund key", name));
	let landed = SeqdexOrder { terms, maker: sha256(plain(&refund_key).as_bytes()), expiry, refund_key: xonly(&refund_key), version };
	let order = OrderPolicy {
		landed,
		owner: xonly(&leaf_key),
		operator: xonly(s),
		salt: label32(&format!("order-2 {} salt", name)),
		chain: net.chain,
		exit_delay: delay(),
		credits: [0, 1, 2, 3].map(|i| xonly(&credit_keys[i]).serialize()),
	};
	Maker { leaf_key, credit_keys, refund_key, order }
}

struct Tree {
	entries: Vec<EntryPolicy>,
	preimages: Vec<[u8; 32]>,
	lowest: Vec<NodePolicy>,
	root: NodePolicy,
	value: u64,
}

/// Sixteen leaves of `asset` under four lowest nodes, each behind its entry:
/// `programs[i]` worth `values[i]`, owned by `owners[i]`.
fn tree(asset: elements::AssetId, net: &Net, s: &Keypair, sched: &ClockSchedule, owners: &[Keypair], programs: &[[u8; 32]],
	values: &[u64], tag: &str) -> Tree
{
	let preimages: Vec<[u8; 32]> = (0..LEAVES).map(|i| label32(&format!("{} batch preimage {}", tag, i))).collect();
	let entries: Vec<EntryPolicy> = (0..LEAVES).map(|i| EntryPolicy {
		unlock_hash: sha256(&preimages[i]), asset, value: values[i], leaf_program: programs[i], sweep: Some(sched.sweep(true, false)),
	}).collect();
	let lowest: Vec<NodePolicy> = (0..4).map(|j| {
		let children = (0..4).map(|i| Child::new(asset, values[4 * j + i] + ENTRY_RESERVE, entries[4 * j + i].taproot().program())).collect();
		NodePolicy::new(children, xonly(s), (0..4).map(|i| xonly(&owners[4 * j + i])).collect(), Some(sched.sweep(true, false)),
			Some(net.chain)).unwrap()
	}).collect();
	let low_values: Vec<u64> = (0..4).map(|j| (0..4).map(|i| values[4 * j + i] + ENTRY_RESERVE).sum::<u64>() + NODE_RESERVE).collect();
	let children = lowest.iter().zip(&low_values).map(|(n, v)| Child::new(asset, *v, n.taproot().program())).collect();
	let root = NodePolicy::new(children, xonly(s), owners.iter().map(xonly).collect(), Some(sched.sweep(false, false)), None).unwrap();
	let value = low_values.iter().sum::<u64>() + NODE_RESERVE;
	Tree { entries, preimages, lowest, root, value }
}

fn unroll(node: &NodePolicy, coin: &Coin, signer: &Keypair, t: u64) -> Transaction {
	let auth = node.unroll_authorisation(mt(t));
	let w = node.unroll_witness(&sig(signer, &auth.digest), mt(t), &xonly(signer)).unwrap();
	let asset = coin.txout.asset.explicit().unwrap();
	let mut s = spend(t as u32).coin(coin, 0xffff_fffe).outputs(node.child_outputs());
	let kids: u64 = node.children().iter().map(|c| c.value).sum();
	s = s.output(fee(asset, coin.txout.value.explicit().unwrap() - kids));
	s.witness(0, w);
	s.tx
}

fn unlock(t: &Tree, i: usize, coin: &Coin, spk: Script) -> Transaction {
	let e = &t.entries[i];
	let mut s = spend(0).coin(coin, 0xffff_ffff).outputs(vec![explicit(e.asset, e.value, spk), fee(e.asset, ENTRY_RESERVE)]);
	s.witness(0, e.unlock_witness(&t.preimages[i]));
	s.tx
}

/// A round for `tree`, its token to its first clock, from `issuer`.
fn round(net: &mut Net, name: &str, issuer: &Coin, sched: &ClockSchedule, t: &Tree) -> (Transaction, elements::Txid) {
	let asset = issuer.txout.asset.explicit().unwrap();
	let total = issuer.txout.value.explicit().unwrap();
	let mut r = spend(0).coin(issuer, 0xffff_ffff).outputs(vec![
		explicit(asset, t.value, t.root.script_pubkey()),
		explicit(sched.token, 1, sched.clock0_script_pubkey()),
		explicit(asset, total - t.value - 2_000, op_true_spk()),
		fee(asset, 2_000),
	]);
	r.tx.input[0].asset_issuance = AssetIssuance {
		asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: [0; 32],
		amount: elements::confidential::Value::Explicit(1), inflation_keys: elements::confidential::Value::Null,
		denomination: 0,
	};
	r.witness(0, op_true_witness());
	let txid = net.pass(name, &r.tx);
	(r.tx, txid)
}

/// A fill of the order coin `oc` of `o`: input 0 the order by its fill path,
/// signed by `signer` over `signed[..m]`; then `payers` with their
/// witnesses; outputs `outs`, then the change of a fee coin in the policy
/// asset and the fee.
fn fill(net: &mut Net, o: &OrderPolicy, oc: &Coin, outs: Vec<TxOut>, signed: &[TxOut], m: u8, partial: bool, signer: &Keypair,
	payers: Vec<(Coin, Vec<Vec<u8>>)>) -> Transaction
{
	let locked = oc.txout.value.explicit().unwrap();
	let digest = o.fill_digest(locked, &signed[..m as usize]).unwrap();
	let fc = net.fee_coin();
	let mut s = spend(0).coin(oc, 0xffff_ffff);
	for (p, _) in &payers {
		s = s.coin(p, 0xffff_ffff);
	}
	s = s.coin(&fc, 0xffff_ffff).outputs(outs)
		.outputs(vec![explicit(net.policy, fc.txout.value.explicit().unwrap() - FEE, op_true_spk()), fee(net.policy, FEE)]);
	s.witness(0, o.fill_witness(&sig(signer, &digest), m, partial).unwrap());
	for (i, (_, w)) in payers.iter().enumerate() {
		s.witness(i + 1, w.clone());
	}
	let n = s.tx.input.len();
	s.witness(n - 1, op_true_witness());
	s.tx
}

/// What the Rust judge says of a fill, for the table.
fn judged(o: &OrderPolicy, tx: &Transaction, locked: u64, m: u8, partial: bool) -> String {
	let w = &tx.input[0].witness.script_witness;
	let sig_bytes = &w[0][346..410];
	let sg = elements::secp256k1_zkp::schnorr::Signature::from_slice(sig_bytes).unwrap();
	match o.check(tx, 0, locked, m, partial, &sg) {
		Ok(f) => format!("judge: fills {} for {} (credited {})", f.filled, f.price, f.credited),
		Err(e) => format!("judge: {}", e),
	}
}

/// The landing of the order coin `oc` into `out`, sequence `seq`, with a fee coin.
fn landing(net: &mut Net, o: &OrderPolicy, oc: &Coin, out: TxOut, seq: u32) -> Transaction {
	let fc = net.fee_coin();
	let mut s = spend(0).coin(oc, seq).coin(&fc, 0xffff_ffff).output(out)
		.outputs(vec![explicit(net.policy, fc.txout.value.explicit().unwrap() - 4_000, op_true_spk()), fee(net.policy, 4_000)]);
	s.witness(0, o.landing_witness());
	s.witness(1, op_true_witness());
	s.tx
}

/// The collaborative spend of the order coin `oc` into `outs` (committed),
/// signed in the operator's slot by `s_key` and the maker's by `a_key`.
fn collab(net: &mut Net, o: &OrderPolicy, oc: &Coin, outs: &[ExplicitOutput], s_key: &Keypair, a_key: &Keypair) -> Transaction {
	let locked = oc.txout.value.explicit().unwrap();
	let m = o.collab_message(locked, outs).unwrap();
	let fc = net.fee_coin();
	let mut s = spend(0).coin(oc, 0xffff_ffff).coin(&fc, 0xffff_ffff).outputs(outs.iter().map(|x| x.txout()).collect())
		.outputs(vec![explicit(net.policy, fc.txout.value.explicit().unwrap() - 4_000, op_true_spk()), fee(net.policy, 4_000)]);
	let committed: u64 = outs.iter().map(|x| x.value).sum();
	if committed < locked {
		s = s.output(explicit(o.terms().asset_a, locked - committed, op_true_spk()));
	}
	s.witness(0, o.collab_witness(&sig(s_key, &m.digest), &sig(a_key, &m.digest), outs.len() as u8));
	s.witness(1, op_true_witness());
	s.tx
}

/// An annex on a Simplicity leaf the program does not need: relay refuses a
/// nonzero one before the program runs on a node from Sequentia 25.2.4,
/// which relays an annex only when it is zeros and as large as the program's
/// cost needs. On an older node relay runs the program.
const ANNEX_NONZERO: &str = "Simplicity annex must be zeros after its tag";
/// The same node's refusal of a zero annex the program's cost does not need.
const ANNEX_UNNEEDED: &str = "Simplicity annex is larger than the program's cost needs";
/// The program's own refusal of an annex (`current_annex_hash` is none), the
/// block's reason on every node.
const ANNEX_REFUSED: &str = "(Assertion failed)";

/// Refused at relay (for the annex on a node from 25.2.4, by the program on
/// an older one) and by the program in a block.
fn refuse_annexed(net: &mut Net, name: &str, tx: &Transaction) {
	let r = net.rt.client().test_mempool_accept(&[tx]).unwrap().remove(0);
	let reason = r.reject_reason.unwrap_or_default();
	let relay = if reason.contains(ANNEX_NONZERO) { ANNEX_NONZERO } else if reason.contains(ANNEX_UNNEEDED) { ANNEX_UNNEEDED }
		else { ANNEX_REFUSED };
	net.refuse_relay_and_block(name, tx, relay, ANNEX_REFUSED);
}

/// `tx` with an annex of `n` bytes (0x50, then zeros) on input `k`'s witness.
fn zero_annexed(tx: &Transaction, k: usize, n: usize) -> Transaction {
	let mut t = tx.clone();
	let mut a = vec![0; n];
	a[0] = 0x50;
	t.input[k].witness.script_witness.push(a);
	t
}

/// `tx` with an annex of `n` bytes (0x50, then 0xab) on input `k`'s witness.
fn annexed(tx: &Transaction, k: usize, n: usize) -> Transaction {
	let mut t = tx.clone();
	let mut a = vec![0xab; n];
	a[0] = 0x50;
	t.input[k].witness.script_witness.push(a);
	t
}

/// The fill outputs a taker wants: credit, remainder, its leaf of X, change.
fn outputs(o: &OrderPolicy, locked: u64, filled: u64, taker_x: &Script, change: Option<(u64, Script)>) -> Vec<TxOut> {
	let plan = o.plan(locked, filled).unwrap();
	let mut v = vec![plan.credit.txout()];
	if let Some(r) = &plan.rest {
		v.push(r.txout());
	}
	v.push(explicit(o.terms().asset_a, filled, taker_x.clone()));
	if let Some((value, spk)) = change {
		v.push(explicit(o.terms().asset_b, value, spk));
	}
	v
}

#[test]
fn order_3_on_regtest() {
	let mut net = Net::start();
	// The takers' batch is in Y: list it for fees too, so its round, nodes
	// and entries pay from their own reserves.
	let rates: Value = net.rt.client().call("getfeeexchangerates", &[]).unwrap();
	let mut rates = rates.as_object().unwrap().clone();
	rates.insert(net.y.to_string(), json!(100_000_000));
	let _: Value = net.rt.client().call("setfeeexchangerates", &[Value::Object(rates)]).unwrap();
	let s = keypair("order-2 operator");
	let t0 = net.mtp() - 60;
	let terms = OrderTerms { asset_a: net.x, asset_b: net.y, rate_num: 2, rate_den: 1, min_lot: 1_000_000 };
	let far = (net.now() + 30 * 24 * H as u64) as u32;
	let soon = (net.now() + 6 * H as u64) as u32;

	// ------------------------------------------------------------ the batches
	// X: eight orders, A to H, and eight ordinary leaves.
	let issuer_x = net.fund(vec![explicit(net.x, 1_000_000_000, op_true_spk())]).remove(0);
	let sched_x = ClockSchedule::new(token_of(&issuer_x), xonly(&s), delay(), vec![mt(net.now() + 28 * 24 * H as u64)]).unwrap();
	let names = ["A", "B", "C", "D", "E", "F", "G", "H"];
	let makers: Vec<Maker> =
		names.iter().map(|n| maker(&net, &s, n, terms, if *n == "D" { soon } else { far }, SeqdexVersion::V2)).collect();
	assert!(makers.iter().all(|m| m.order.leaf().template() == Template::Order3));
	// Order O, leaf 8: an order-2 leaf, as an order resting from before order-3.
	let old = maker(&net, &s, "O", terms, far, SeqdexVersion::V1);
	assert_eq!(old.order.leaf().template(), Template::Order2);
	let mut owners: Vec<Keypair> = makers.iter().map(|m| m.leaf_key).collect();
	let mut programs: Vec<[u8; 32]> = makers.iter().map(|m| m.order.program()).collect();
	owners.push(old.leaf_key);
	programs.push(old.order.program());
	for i in makers.len() + 1..LEAVES {
		let k = keypair(&format!("order-2 batch owner {}", i));
		programs.push(net.leaf(&k, &s, &format!("order-2 batch leaf {}", i)).program());
		owners.push(k);
	}
	let tx_ = tree(net.x, &net, &s, &sched_x, &owners, &programs, &[N; LEAVES], "x");
	println!("order-3: {} bytes of parameters, collab {} B, landing {} B, fill program {} to {} B",
		makers[0].order.data_bytes().len(), makers[0].order.collab_script().len(), makers[0].order.landing_script().len(),
		arca_covenant::order_programs::ORDER3_FILL_WHOLE_M2.len() / 2, arca_covenant::order_programs::ORDER3_FILL_M4.len() / 2);
	let (rx, rxt) = round(&mut net, "round: one batch of X holding eight order-3 leaves and one order-2 leaf", &issuer_x, &sched_x, &tx_);
	net.purse.push(coin_of(rxt, 2, &rx));

	// Y: the takers' leaves, one per part.
	let takers: Vec<Keypair> = (0..LEAVES).map(|i| keypair(&format!("order-2 taker {}", i))).collect();
	let taker_leaves: Vec<LeafPolicy> = (0..LEAVES).map(|i| net.leaf(&takers[i], &s, &format!("order-2 taker leaf {}", i))).collect();
	let ty_value = 2 * N + 1_000_000;
	let issuer_y = net.fund(vec![explicit(net.y, 1_000_000_000, op_true_spk())]).remove(0);
	let sched_y = ClockSchedule::new(token_of(&issuer_y), xonly(&s), delay(), vec![mt(net.now() + 29 * 24 * H as u64)]).unwrap();
	let ty = tree(net.y, &net, &s, &sched_y, &takers, &taker_leaves.iter().map(|l| l.program()).collect::<Vec<_>>(),
		&[ty_value; LEAVES], "y");
	let (ryx, ryt) = round(&mut net, "round: one batch of Y holding the takers' leaves", &issuer_y, &sched_y, &ty);
	net.purse.push(coin_of(ryt, 2, &ryx));

	// The operator alone unrolls the X batch and the two lowest nodes holding
	// the orders: its own authorisations, no maker's.
	let tx = unroll(&tx_.root, &coin_of(rxt, 0, &rx), &s, t0);
	let root_t = net.pass("A/unroll of the X batch, by the operator", &tx);
	let lows: Vec<Coin> = (0..4).map(|i| coin_of(root_t, i, &tx)).collect();
	let mut entry = vec![];
	for (j, low) in lows.iter().enumerate().take(2) {
		let tx = unroll(&tx_.lowest[j], low, &s, t0);
		let lt = net.pass(&format!("A/unroll of X lowest node {}, by the operator", j), &tx);
		for i in 0..4 {
			entry.push(coin_of(lt, i, &tx));
		}
	}
	let ryroot = coin_of(ryt, 0, &ryx);

	// ---------------------------------------------------------------- A
	let a = &makers[0];
	let tx = unlock(&tx_, 0, &entry[0], a.order.script_pubkey());
	let ut = net.pass("A/order A's entry into its leaf, by the operator (maker offline)", &tx);
	let oa = coin_of(ut, 0, &tx);
	let taker_x = plain(&keypair("order-2 taker A"));
	let pay = net.fund(vec![explicit(net.y, 30_000_000, op_true_spk())]).remove(0);
	let payers = |c: &Coin| vec![(c.clone(), op_true_witness())];
	let f1 = 3_000_000;
	let good = outputs(&a.order, N, f1, &taker_x, Some((30_000_000 - 2 * f1, op_true_spk())));

	// Each negative is `good` with one thing changed.
	let neg = |net: &mut Net, name: &str, outs: Vec<TxOut>, signed: &[TxOut], signer: &Keypair, expect: &str| {
		let t = fill(net, &a.order, &oa, outs, signed, 4, true, signer, payers(&pay));
		println!("{}: {}", name, judged(&a.order, &t, N, 4, true));
		net.refuse(name, &t, expect);
	};
	let jet = "Assertion failed inside jet";
	neg(&mut net, "A/neg no operator: the maker's leaf key signs the fill", good.clone(), &good, &a.leaf_key, jet);
	neg(&mut net, "A/neg no operator: the maker's credit key signs the fill", good.clone(), &good, &a.credit_keys[0], jet);
	let mut swapped = good.clone();
	swapped[2] = explicit(net.x, f1, plain(&a.leaf_key));
	neg(&mut net, "A/neg the operator signed for another taker's leaf at output 2", swapped, &good, &s, jet);
	let mut o = good.clone();
	o[0] = explicit(net.y, 2 * f1 - 1, o[0].script_pubkey.clone());
	o[3] = explicit(net.y, 30_000_000 - 2 * f1 + 1, op_true_spk());
	neg(&mut net, "A/neg the credit one atom under the price", o.clone(), &o, &s, jet);
	let mut o = good.clone();
	o[0] = explicit(net.y, 2 * f1, plain(&a.credit_keys[0]));
	neg(&mut net, "A/neg the credit to the credit key's plain script, not its leaf", o.clone(), &o, &s, jet);
	let mut o = good.clone();
	o[0] = explicit(net.y, 2 * f1, a.order.next().credit_leaf().unwrap().script_pubkey());
	neg(&mut net, "A/neg the credit to the next fill's credit leaf", o.clone(), &o, &s, jet);
	let mut o = good.clone();
	o[0] = explicit(net.y, 2 * f1, plain(&s));
	neg(&mut net, "A/neg the credit to the operator", o.clone(), &o, &s, jet);
	let paypol = net.fund(vec![explicit(net.policy, 30_000_000, op_true_spk())]).remove(0);
	{
		let mut o = good.clone();
		o[0] = explicit(net.policy, 2 * f1, o[0].script_pubkey.clone());
		o[3] = explicit(net.policy, 30_000_000 - 2 * f1, op_true_spk());
		let t = fill(&mut net, &a.order, &oa, o.clone(), &o, 4, true, &s, payers(&paypol));
		println!("A/neg the credit in the policy asset: {}", judged(&a.order, &t, N, 4, true));
		net.refuse("A/neg the credit in the policy asset, not Y", &t, jet);
	}
	{
		// A confidential credit: the amounts balance, so only the program can refuse it.
		let mut o = good.clone();
		o[0] = confidential(net.y, 2 * f1, o[0].script_pubkey.clone(), &[(net.x, N), (net.y, 30_000_000), (net.policy, 20_000)]);
		let t = fill(&mut net, &a.order, &oa, o.clone(), &o, 4, true, &s, payers(&pay));
		net.refuse("A/neg a confidential credit (asset and value blinded, proofs valid)", &t, "Assertion failed");
	}
	let mut o = good.clone();
	o[1] = explicit(net.x, N - f1, a.order.script_pubkey());
	neg(&mut net, "A/neg the remainder under the coin's own script (the old salt)", o.clone(), &o, &s, jet);
	let mut o = good.clone();
	let mut unmoved = a.order.next();
	unmoved.credits = a.order.credits;
	o[1] = explicit(net.x, N - f1, unmoved.script_pubkey());
	neg(&mut net, "A/neg the remainder with the credit keys not moved up", o.clone(), &o, &s, jet);
	let mut o = good.clone();
	o[1] = explicit(net.x, N - f1, a.order.landed.script_pubkey());
	neg(&mut net, "A/neg the remainder landed at once as SeqDEX's order", o.clone(), &o, &s, jet);
	let mut o = good.clone();
	o[1] = explicit(net.x, N - f1, plain(&s));
	neg(&mut net, "A/neg the remainder to the operator", o.clone(), &o, &s, jet);
	{
		let o = outputs(&a.order, N, N - 1_000_000, &taker_x, Some((30_000_000 - 2 * (N - 1_000_000), op_true_spk())));
		let mut o2 = o.clone();
		o2[1] = explicit(net.x, 999_999, o[1].script_pubkey.clone());
		o2[2] = explicit(net.x, N - 999_999, taker_x.clone());
		neg(&mut net, "A/neg a remainder one atom below MIN_LOT", o2.clone(), &o2, &s, jet);
	}
	{
		let o = outputs(&a.order, N, 1_000_000, &taker_x, Some((30_000_000 - 2_000_000, op_true_spk())));
		let mut o2 = o.clone();
		o2[0] = explicit(net.y, 2 * 999_999, o[0].script_pubkey.clone());
		o2[1] = explicit(net.x, N - 999_999, o[1].script_pubkey.clone());
		o2[2] = explicit(net.x, 999_999, taker_x.clone());
		o2[3] = explicit(net.y, 30_000_000 - 2 * 999_999, op_true_spk());
		neg(&mut net, "A/neg a fill one atom below MIN_LOT", o2.clone(), &o2, &s, jet);
	}
	// The control: the same fill, the operator's signature over its outputs.
	let t = fill(&mut net, &a.order, &oa, good.clone(), &good, 4, true, &s, payers(&pay));
	println!("A/fill 1: {}", judged(&a.order, &t, N, 4, true));
	// The operator's signature covers no annex, so a relay could add one: order-3 refuses it.
	assert_eq!(t.input[0].witness.script_witness.len(), 4);
	refuse_annexed(&mut net, "A/neg the operator's signed fill with a 3-byte annex", &annexed(&t, 0, 3));
	refuse_annexed(&mut net, "A/neg the operator's signed fill with a 1,000-byte annex", &annexed(&t, 0, 1_000));
	refuse_annexed(&mut net, "A/neg the operator's signed fill with a 1,000-byte zero annex", &zero_annexed(&t, 0, 1_000));
	let a1 = net.pass("A/fill 1: 3,000,000 X for 6,000,000 Y; credit 0 to its leaf, the rest under the next salt", &t);
	let credit_a1 = coin_of(a1, 0, &t);
	let ra = coin_of(a1, 1, &t);
	assert_eq!(credit_a1.txout.script_pubkey, a.order.credit_leaf().unwrap().script_pubkey());
	assert_eq!(ra.txout.script_pubkey, a.order.next().script_pubkey());
	// Fill 1's signature does not fill the remainder.
	let o1 = a.order.next();
	let pay2 = net.fund(vec![explicit(net.y, 30_000_000, op_true_spk())]).remove(0);
	let good2 = outputs(&o1, N - f1, f1, &taker_x, Some((30_000_000 - 2 * f1, op_true_spk())));
	{
		let digest1 = a.order.fill_digest(N, &good[..4]).unwrap();
		let fc = net.fee_coin();
		let mut sx = spend(0).coin(&ra, 0xffff_ffff).coin(&pay2, 0xffff_ffff).coin(&fc, 0xffff_ffff).outputs(good2.clone())
			.outputs(vec![explicit(net.policy, fc.txout.value.explicit().unwrap() - FEE, op_true_spk()), fee(net.policy, FEE)]);
		sx.witness(0, o1.fill_witness(&sig(&s, &digest1), 4, true).unwrap());
		sx.witness(1, op_true_witness());
		sx.witness(2, op_true_witness());
		net.refuse("A/neg fill 1's operator signature replayed on the remainder", &sx.tx, jet);
	}
	let t = fill(&mut net, &o1, &ra, good2.clone(), &good2, 4, true, &s, payers(&pay2));
	let a2 = net.pass("A/fill 2 of the remainder: its own signature, credit 1, the rest under the next salt", &t);
	let credit_a2 = coin_of(a2, 0, &t);
	assert_ne!(credit_a1.txout.script_pubkey, credit_a2.txout.script_pubkey);
	let mut cur = (o1.next(), coin_of(a2, 1, &t), N - 2 * f1);
	for k in 3..=4 {
		let (o, c, held) = cur.clone();
		let fk = 1_000_000;
		let pay = net.fund(vec![explicit(net.y, 2 * fk, op_true_spk())]).remove(0);
		let outs = outputs(&o, held, fk, &taker_x, None);
		let t = fill(&mut net, &o, &c, outs.clone(), &outs, 3, true, &s, payers(&pay));
		let tk = net.pass(&format!("A/fill {} of the remainder, m = 3 (no change)", k), &t);
		cur = (o.next(), coin_of(tk, 1, &t), held - fk);
	}
	{
		// A fifth fill along one lineage: the credit keys are used up.
		let (o, c, held) = cur.clone();
		assert_eq!(o.fills_left(), 0);
		let pay = net.fund(vec![explicit(net.y, 2_000_000, op_true_spk())]).remove(0);
		let mut prev = o;
		prev.credits[0] = a.order.credits[0];
		let mut outs = outputs(&prev, held, 1_000_000, &taker_x, None);
		outs[1] = explicit(net.x, held - 1_000_000, o.next().script_pubkey());
		let t = fill(&mut net, &o, &c, outs.clone(), &outs, 3, true, &s, payers(&pay));
		net.refuse("A/neg a fifth fill along one lineage (no credit key left)", &t, jet);
	}
	// The exhausted remainder lands after the delay as SeqDEX's own order.
	let (o5, c5, held5) = cur.clone();
	let t = landing(&mut net, &o5, &c5, o5.landed_output(held5).txout(), delay().to_sequence());
	net.refuse("A/neg the landing before the exit delay", &t, "non-BIP68-final");
	let t = landing(&mut net, &o5, &c5, o5.landed_output(held5).txout(), 0xffff_fffe);
	net.refuse("A/neg the landing with no relative lock", &t, "Locktime requirement not satisfied");
	net.wait_csv(&c5.outpoint.txid, delay());
	let t = landing(&mut net, &o5, &c5, explicit(terms.asset_a, held5, plain(&s)), delay().to_sequence());
	net.refuse("A/neg the landing to the operator", &t, "OP_EQUALVERIFY");
	let mut t = landing(&mut net, &o5, &c5, explicit(terms.asset_a, held5 - 1_000, o5.landed.script_pubkey()), delay().to_sequence());
	t.output.push(explicit(terms.asset_a, 1_000, op_true_spk()));
	net.refuse("A/neg the landing 1,000 atoms short (the rest to another output)", &t, "false/empty top stack");
	let lt = landing(&mut net, &o5, &c5, o5.landed_output(held5).txout(), delay().to_sequence());
	let lt_id = net.pass("A/the landing after the delay: the rest, whole, as SeqDEX's own order", &lt);
	let landed = coin_of(lt_id, 0, &lt);
	assert_eq!(landed.txout.script_pubkey, a.order.landed.script_pubkey());
	// An on-chain taker fills the landed order by SeqDEX's own program.
	let lf = 1_000_000;
	let pay = net.fund(vec![explicit(net.y, 2 * lf + 1_000, op_true_spk())]).remove(0);
	let fc = net.fee_coin();
	let mut sx = spend(0).coin(&landed, 0xffff_ffff).coin(&pay, 0xffff_ffff).coin(&fc, 0xffff_ffff).outputs(vec![
		explicit(net.y, 2 * lf, plain(&a.refund_key)), explicit(net.x, held5 - lf, a.order.landed.script_pubkey()),
		explicit(net.x, lf, op_true_spk()), explicit(net.y, 1_000, op_true_spk()),
		explicit(net.policy, fc.txout.value.explicit().unwrap() - FEE, op_true_spk()), fee(net.policy, FEE)]);
	sx.witness(0, a.order.landed.fill_witness(true));
	sx.witness(1, op_true_witness());
	sx.witness(2, op_true_witness());
	let mut short = sx.clone();
	short.tx.output[0] = explicit(net.y, 2 * lf - 1, plain(&a.refund_key));
	short.tx.output[3] = explicit(net.y, 1_001, op_true_spk());
	net.refuse("A/neg an on-chain fill of the landed order one atom short", &short.tx, jet);
	// The fill signs nothing, so anyone could add an annex: seqdex/order version 2 refuses it.
	assert_eq!(a.order.landed.version, SeqdexVersion::V2);
	refuse_annexed(&mut net, "A/neg the on-chain fill of the landed order with a 3-byte annex", &annexed(&sx.tx, 0, 3));
	refuse_annexed(&mut net, "A/neg the on-chain fill of the landed order with a 1,000-byte annex", &annexed(&sx.tx, 0, 1_000));
	refuse_annexed(&mut net, "A/neg the on-chain fill of the landed order with a 1,000-byte zero annex",
		&zero_annexed(&sx.tx, 0, 1_000));
	net.pass("A/an on-chain taker fills the landed order by seqdex/order version 2 (no signature)", &sx.tx);

	// ---------------------------------------------------------------- O
	// An order-2 leaf resting from before order-3 is filled as it always was.
	let tx = unroll(&tx_.lowest[2], &lows[2], &s, t0);
	let l2 = net.pass("O/unroll of X lowest node 2, by the operator", &tx);
	let tx = unlock(&tx_, 8, &coin_of(l2, 0, &tx), old.order.script_pubkey());
	let uo = net.pass("O/order O's entry into its order-2 leaf, by the operator", &tx);
	let oo = coin_of(uo, 0, &tx);
	let pay_o = net.fund(vec![explicit(net.y, 30_000_000, op_true_spk())]).remove(0);
	let good_o = outputs(&old.order, N, f1, &taker_x, Some((30_000_000 - 2 * f1, op_true_spk())));
	let t = fill(&mut net, &old.order, &oo, good_o.clone(), &good_o, 4, true, &s, payers(&pay_o));
	println!("O/fill: {}", judged(&old.order, &t, N, 4, true));
	assert_eq!(t.input[0].witness.script_witness[2], Vec::<u8>::from_hex(arca_covenant::order_programs::ORDER_CMR).unwrap());
	// order-2 takes an annex the operator never signed. A node before
	// Sequentia 25.2.4 relays the fill with one; a node from it refuses the
	// annex at relay (it is not zeros), and a block producer can still mine
	// it: the block takes the padded fill either way, and the order fills.
	let padded = annexed(&t, 0, 1_000);
	assert_eq!(padded.txid(), t.txid(), "the annex is witness data");
	let fo = net.pass_or_mine("O/fill of the order-2 leaf with a 1,000-byte annex nobody signed: 3,000,000 X for 6,000,000 Y, \
		the rest resting as order-2", &padded, ANNEX_NONZERO);
	assert_eq!(net.witness_of(&fo, 0).len(), 5, "the block keeps the annex");
	assert_eq!(coin_of(fo, 1, &t).txout.script_pubkey, old.order.next().script_pubkey());
	assert_eq!(old.order.next().leaf().template(), Template::Order2);
	assert_eq!(coin_of(fo, 0, &t).txout.script_pubkey, old.order.credit_leaf().unwrap().script_pubkey());
	// Its remainder, an order-2 leaf too, fills as it always did.
	let o2n = old.order.next();
	let pay_o2 = net.fund(vec![explicit(net.y, 2 * 2_000_000, op_true_spk())]).remove(0);
	let outs = outputs(&o2n, N - f1, 2_000_000, &taker_x, None);
	let t = fill(&mut net, &o2n, &coin_of(fo, 1, &t), outs.clone(), &outs, 3, true, &s, payers(&pay_o2));
	net.pass("O/fill of the order-2 remainder: 2,000,000 X, m = 3, the rest resting as order-2", &t);

	// The takers' Y tree, down to the lowest nodes, by the operator: the
	// lineage it publishes to answer an order brought to the chain.
	let tx = unroll(&ty.root, &ryroot, &s, t0);
	let yroot_t = net.pass("Y/unroll of the takers' batch, by the operator", &tx);
	let ylows: Vec<Coin> = (0..4).map(|i| coin_of(yroot_t, i, &tx)).collect();
	let tx = unroll(&ty.lowest[0], &ylows[0], &s, t0);
	let ylt = net.pass("Y/unroll of the takers' lowest node 0, by the operator", &tx);
	let yentry: Vec<Coin> = (0..4).map(|i| coin_of(ylt, i, &tx)).collect();

	// A taker's coin, its checkpoint and its fill of an order, all signed
	// before the order reaches the chain. `direct`: no checkpoint.
	struct InTree { fill: Transaction, checkpoint: Option<Transaction>, taker_leaf_tx: Transaction }
	let in_tree = |net: &mut Net, mk: &Maker, i: usize, oc: &Coin, filled: u64, direct: bool| -> InTree {
		let tl = &taker_leaves[i];
		let tk = &takers[i];
		let unl = unlock(&ty, i, &yentry[i], tl.script_pubkey());
		let tlc = coin_of(unl.txid(), 0, &unl);
		let price = mk.order.terms().price(filled).unwrap();
		let new_x = net.leaf(tk, &s, &format!("order-2 taker {} new X leaf", i));
		let change = net.leaf(tk, &s, &format!("order-2 taker {} change leaf", i));
		let outs = outputs(&mk.order, N, filled, &new_x.script_pubkey(), Some((ty_value - price - 10_000, change.script_pubkey())));
		let committed: Vec<ExplicitOutput> = outs.iter().map(|o| ExplicitOutput::from_txout(o).unwrap()).collect();
		let digest = mk.order.fill_digest(N, &outs).unwrap();
		let fc = net.fee_coin();
		if direct {
			let m = tl.collab_message(net.y, ty_value, &committed).unwrap();
			let w = tl.collab_witness(&sig(&s, &m.digest), &sig(tk, &m.digest), 4);
			let mut sx = spend(0).coin(oc, 0xffff_ffff).coin(&tlc, 0xffff_ffff).coin(&fc, 0xffff_ffff).outputs(outs.clone())
				.outputs(vec![explicit(net.y, 10_000, op_true_spk()),
					explicit(net.policy, fc.txout.value.explicit().unwrap() - FEE, op_true_spk()), fee(net.policy, FEE)]);
			sx.witness(0, mk.order.fill_witness(&sig(&s, &digest), 4, true).unwrap());
			sx.witness(1, w);
			sx.witness(2, op_true_witness());
			return InTree { fill: sx.tx, checkpoint: None, taker_leaf_tx: unl };
		}
		let cp = CheckpointPolicy { owner: xonly(tk), operator: xonly(&s), salt: label32(&format!("order-2 taker {} checkpoint", i)),
			chain: net.chain, sweep: Some(sched_y.sweep(true, false)), v2: false };
		let cp_out = ExplicitOutput::new(net.y, ty_value, cp.script_pubkey());
		let m_cp = tl.collab_message(net.y, ty_value, std::slice::from_ref(&cp_out)).unwrap();
		let fcc = net.fee_coin();
		let mut sc = spend(0).coin(&tlc, 0xffff_ffff).coin(&fcc, 0xffff_ffff).outputs(vec![cp_out.txout(),
			explicit(net.policy, fcc.txout.value.explicit().unwrap() - 4_000, op_true_spk()), fee(net.policy, 4_000)]);
		sc.witness(0, tl.collab_witness(&sig(&s, &m_cp.digest), &sig(tk, &m_cp.digest), 1));
		sc.witness(1, op_true_witness());
		let cpc = coin_of(sc.tx.txid(), 0, &sc.tx);
		let m_f = cp.collab_message(net.y, ty_value, &committed).unwrap();
		let mut sx = spend(0).coin(oc, 0xffff_ffff).coin(&cpc, 0xffff_ffff).coin(&fc, 0xffff_ffff).outputs(outs.clone())
			.outputs(vec![explicit(net.y, 10_000, op_true_spk()),
				explicit(net.policy, fc.txout.value.explicit().unwrap() - FEE, op_true_spk()), fee(net.policy, FEE)]);
		sx.witness(0, mk.order.fill_witness(&sig(&s, &digest), 4, true).unwrap());
		sx.witness(1, cp.collab_witness(&sig(&s, &m_f.digest), &sig(tk, &m_f.digest), 4));
		sx.witness(2, op_true_witness());
		InTree { fill: sx.tx, checkpoint: Some(sc.tx), taker_leaf_tx: unl }
	};
	// The maker's ways to outrun a fill, once its order is on the chain.
	let outrun = |net: &mut Net, part: &str, mk: &Maker, oc: &Coin| {
		let mine = outputs(&mk.order, N, N, &plain(&mk.leaf_key), Some((10_000_000, plain(&mk.leaf_key))));
		let mine: Vec<TxOut> = vec![mine[0].clone(), mine[1].clone(), mine[2].clone()];
		let paym = net.fund(vec![explicit(net.y, 2 * N + 10_000_000, op_true_spk())]).remove(0);
		let t = fill(net, &mk.order, oc, mine.clone(), &mine, 3, false, &mk.leaf_key, vec![(paym, op_true_witness())]);
		net.refuse(&format!("{}/neg the maker fills its own order (its own key in the operator's place)", part), &t,
			"Assertion failed inside jet");
		let t = landing(net, &mk.order, oc, mk.order.landed_output(N).txout(), delay().to_sequence());
		net.refuse(&format!("{}/neg the maker lands its order at once", part), &t, "non-BIP68-final");
		let back = ExplicitOutput::new(net.x, N, plain(&mk.leaf_key));
		let t = collab(net, &mk.order, oc, std::slice::from_ref(&back), &mk.leaf_key, &mk.leaf_key);
		net.refuse(&format!("{}/neg the maker alone on the collaborative path", part), &t, "Invalid Schnorr signature");
	};

	// ---------------------------------------------------------------- B
	let b = &makers[1];
	let ub = unlock(&tx_, 1, &entry[1], b.order.script_pubkey());
	let ob = coin_of(ub.txid(), 0, &ub);
	let ib = in_tree(&mut net, b, 0, &ob, 4_000_000, false);
	println!("B/the in-tree fill, judged: {}", judged(&b.order, &ib.fill, N, 4, true));
	net.pass("B/the maker brings its order to the chain (its entry)", &ub);
	outrun(&mut net, "B", b, &ob);
	// The operator answers: the taker's lineage, its checkpoint, the fill.
	net.pass("B/the operator answers: the taker's entry into its leaf", &ib.taker_leaf_tx);
	net.pass("B/the operator answers: the taker's checkpoint", ib.checkpoint.as_ref().unwrap());
	let bf = net.pass("B/the operator answers: the in-tree fill, mined", &ib.fill);
	assert_eq!(coin_of(bf, 1, &ib.fill).txout.script_pubkey, b.order.next().script_pubkey());
	{ let t = landing(&mut net, &b.order, &ob,
		b.order.landed_output(N).txout(), delay().to_sequence()); net.refuse("B/neg the maker's landing of the filled coin after the fill", &t, "missingorspent"); }

	// ---------------------------------------------------------------- C
	let c = &makers[2];
	let uc = unlock(&tx_, 2, &entry[2], c.order.script_pubkey());
	let occ = coin_of(uc.txid(), 0, &uc);
	let ic = in_tree(&mut net, c, 1, &occ, 4_000_000, true);
	net.pass("C/the maker brings its order to the chain", &uc);
	outrun(&mut net, "C", c, &occ);
	let ctl = net.pass("C/the taker's entry into its leaf", &ic.taker_leaf_tx);
	net.pass("C/the in-tree fill, the taker's coin spent directly, mined", &ic.fill);
	net.wait_csv(&ctl, delay());
	{
		let tl = &taker_leaves[1];
		let fce = net.fee_coin();
		let tlc = coin_of(ctl, 0, &ic.taker_leaf_tx);
		let mut sx = spend(0).coin(&tlc, delay().to_sequence()).coin(&fce, 0xffff_ffff).outputs(vec![
			explicit(net.y, ty_value, plain(&takers[1])), explicit(net.policy, fce.txout.value.explicit().unwrap() - 4_000, op_true_spk()),
			fee(net.policy, 4_000)]);
		let sg = sx.sign(&takers[1], 0, &tl.exit_script(), net.genesis);
		sx.witness(0, tl.exit_witness(&sg));
		sx.witness(1, op_true_witness());
		net.refuse("C/neg the taker exits the coin it paid with, after the delay", &sx.tx, "missingorspent");
	}

	// ---------------------------------------------------------------- D
	let d = &makers[3];
	let ud = unlock(&tx_, 3, &entry[3], d.order.script_pubkey());
	let od = coin_of(ud.txid(), 0, &ud);
	let id = in_tree(&mut net, d, 2, &od, 4_000_000, false);
	net.mtp_past(soon as u64 + 60);
	net.pass("D/past the order's REFUND time, the maker brings it to the chain", &ud);
	outrun(&mut net, "D", d, &od);
	{
		// SeqDEX's REFUND path is not a leaf of the order: a witness for it
		// proves no leaf of this output.
		let fc = net.fee_coin();
		let mut sx = spend(soon).coin(&od, 0xffff_fffe).coin(&fc, 0xffff_ffff).outputs(vec![explicit(net.x, N, plain(&d.refund_key)),
			explicit(net.policy, fc.txout.value.explicit().unwrap() - 4_000, op_true_spk()), fee(net.policy, 4_000)]);
		let mut w = d.order.landed.fill_witness(false);
		w[0] = vec![0x80];
		sx.witness(0, w);
		sx.witness(1, op_true_witness());
		net.refuse("D/neg a REFUND of the order leaf after its time (the leaf has none)", &sx.tx, "Witness program hash mismatch");
	}
	net.pass("D/the taker's entry", &id.taker_leaf_tx);
	net.pass("D/the taker's checkpoint", id.checkpoint.as_ref().unwrap());
	net.pass("D/the fill made in the tree before the REFUND time, mined after it", &id.fill);

	// ---------------------------------------------------------------- E
	// Two fills of one size along one lineage: two credits of one value,
	// under two scripts; the maker's pair over one fits only that one.
	let e = &makers[4];
	let ue = unlock(&tx_, 4, &entry[4], e.order.script_pubkey());
	let uet = net.pass("E/order E's entry into its leaf, by the operator", &ue);
	let mut oe = (e.order, coin_of(uet, 0, &ue), N);
	let mut credits = vec![];
	for k in 0..2 {
		let (o, c, held) = oe;
		let pay = net.fund(vec![explicit(net.y, 2_000_000, op_true_spk())]).remove(0);
		let outs = outputs(&o, held, 1_000_000, &op_true_spk(), None);
		let t = fill(&mut net, &o, &c, outs.clone(), &outs, 3, true, &s, payers(&pay));
		let tid = net.pass(&format!("E/fill {} of 1,000,000 X: a credit of 2,000,000 Y", k + 1), &t);
		credits.push((o.credit_leaf().unwrap(), coin_of(tid, 0, &t), k));
		oe = (o.next(), coin_of(tid, 1, &t), held - 1_000_000);
	}
	assert_eq!(credits[0].1.txout.value, credits[1].1.txout.value, "two credits of one value");
	assert_ne!(credits[0].1.txout.script_pubkey, credits[1].1.txout.script_pubkey, "under two scripts");
	let into = ExplicitOutput::new(net.y, 2_000_000, plain(&s));
	let (leaf0, _, _) = &credits[0];
	let m_e = leaf0.collab_message(net.y, 2_000_000, std::slice::from_ref(&into)).unwrap();
	let w_e = leaf0.collab_witness(&sig(&s, &m_e.digest), &sig(&e.credit_keys[0], &m_e.digest), 1);
	let spend_credit = |net: &mut Net, c: &Coin, w: Vec<Vec<u8>>| -> Transaction {
		let fcx = net.fee_coin();
		let mut sx = spend(0).coin(c, 0xffff_ffff).coin(&fcx, 0xffff_ffff).outputs(vec![into.txout(),
			explicit(net.policy, fcx.txout.value.explicit().unwrap() - 4_000, op_true_spk()), fee(net.policy, 4_000)]);
		// The pair commits to the script it spends: put it under the second
		// credit's leaf, whose control block the pair does not change.
		sx.witness(0, w);
		sx.witness(1, op_true_witness());
		sx.tx
	};
	{
		let (leaf1, c1, _) = &credits[1];
		let mut w = w_e.clone();
		let n = w.len();
		w[n - 2] = leaf1.collab_script().to_bytes();
		w[n - 1] = leaf1.taproot().control_block(&leaf1.collab_script()).unwrap();
		let t = spend_credit(&mut net, c1, w);
		net.refuse("E/neg the maker's pair over credit 1 spends credit 2", &t, "Invalid Schnorr signature");
	}
	let t = spend_credit(&mut net, &credits[0].1, w_e);
	net.pass("E/the maker's pair over credit 1 spends credit 1 (control)", &t);
	// The other pruned programs, each spent once: a partial fill whose
	// signature commits to the credit and the remainder alone (m = 2), and
	// whole fills committing to three and to four outputs.
	{
		let (o, c, held) = oe;
		let pay = net.fund(vec![explicit(net.y, 2_000_000, op_true_spk())]).remove(0);
		let outs = outputs(&o, held, 1_000_000, &op_true_spk(), None);
		let t = fill(&mut net, &o, &c, outs.clone(), &outs, 2, true, &s, payers(&pay));
		let tid = net.pass("E/fill 3: the signature commits to the credit and the remainder alone (m = 2)", &t);
		let (o, c, held) = (o.next(), coin_of(tid, 1, &t), held - 1_000_000);
		let pay = net.fund(vec![explicit(net.y, 2 * held + 30_000, op_true_spk())]).remove(0);
		let mut outs = outputs(&o, held, held, &op_true_spk(), Some((10_000, op_true_spk())));
		outs.push(explicit(net.y, 20_000, plain(&e.leaf_key)));
		let t = fill(&mut net, &o, &c, outs.clone(), &outs, 4, false, &s, payers(&pay));
		net.pass("E/fill 4, the rest whole: the signature commits to four outputs (whole, m = 4)", &t);
	}
	{
		let (o, c) = (b.order.next(), coin_of(bf, 1, &ib.fill));
		let held = N - 4_000_000;
		let pay = net.fund(vec![explicit(net.y, 2 * held + 10_000, op_true_spk())]).remove(0);
		let outs = outputs(&o, held, held, &op_true_spk(), Some((10_000, op_true_spk())));
		let t = fill(&mut net, &o, &c, outs.clone(), &outs, 3, false, &s, payers(&pay));
		net.pass("B/the remainder of the in-tree fill, filled whole on the chain (whole, m = 3)", &t);
	}

	// ---------------------------------------------------------------- H
	// Given up in a refresh: the forfeit, signed by maker and operator.
	let h = &makers[7];
	let fp = ForfeitPolicy { unlock_hash: sha256(&label32("order-2 H refresh preimage")), owner: xonly(&h.leaf_key),
		operator: xonly(&s), refund_delay: delay(), leaf_id: LeafId(label32("order-2 H leaf id")),
		connector: asset("order-2 H refresh connector") };
	let fout = ExplicitOutput::new(net.x, N, fp.script_pubkey());
	let uh = unlock(&tx_, 7, &entry[7], h.order.script_pubkey());
	let ohc = coin_of(uh.txid(), 0, &uh);
	let forfeit = collab(&mut net, &h.order, &ohc, std::slice::from_ref(&fout), &s, &h.leaf_key);
	net.pass("H/the maker brings the order it gave up to the chain", &uh);
	outrun(&mut net, "H", h, &ohc);
	net.pass("H/the refresh's forfeit of the order leaf (maker and operator), mined", &forfeit);
	// A cancel's checkpoint, the same way (order G).
	let g = &makers[6];
	let ug = unlock(&tx_, 6, &entry[6], g.order.script_pubkey());
	let og = coin_of(ug.txid(), 0, &ug);
	let cpg = CheckpointPolicy { owner: xonly(&g.leaf_key), operator: xonly(&s), salt: label32("order-2 G cancel checkpoint"),
		chain: net.chain, sweep: Some(sched_x.sweep(true, false)), v2: false };
	let cpo = ExplicitOutput::new(net.x, N, cpg.script_pubkey());
	let cancel = collab(&mut net, &g.order, &og, std::slice::from_ref(&cpo), &s, &g.leaf_key);
	net.pass("G/the maker brings the order it cancelled to the chain", &ug);
	outrun(&mut net, "G", g, &og);
	net.pass("G/the cancel's checkpoint (maker and operator), mined", &cancel);

	// ---------------------------------------------------------------- F
	// The operator alone.
	let f = &makers[5];
	let uf = unlock(&tx_, 5, &entry[5], f.order.script_pubkey());
	let uft = net.pass("F/order F's entry into its leaf", &uf);
	let of = coin_of(uft, 0, &uf);
	let to_s = ExplicitOutput::new(net.x, N, plain(&s));
	let t = collab(&mut net, &f.order, &of, std::slice::from_ref(&to_s), &s, &s);
	net.refuse("F/neg the operator alone: its signature in both slots of the collaborative path", &t, "Invalid Schnorr signature");
	let payf = net.fund(vec![explicit(net.y, 2 * N, op_true_spk())]).remove(0);
	let mut o = outputs(&f.order, N, N, &plain(&s), None);
	o[0] = explicit(net.y, 2 * N, plain(&s));
	let t = fill(&mut net, &f.order, &of, o.clone(), &o, 2, false, &s, payers(&payf));
	net.refuse("F/neg the operator fills and credits itself", &t, "Assertion failed inside jet");
	net.wait_csv(&uft, delay());
	let t = landing(&mut net, &f.order, &of, explicit(terms.asset_a, N, plain(&s)), delay().to_sequence());
	net.refuse("F/neg anyone lands the order to the operator after the delay", &t, "OP_EQUALVERIFY");
	let o = outputs(&f.order, N, N, &plain(&s), None);
	let t = fill(&mut net, &f.order, &of, o.clone(), &o, 2, false, &s, payers(&payf));
	println!("F/the operator as a taker: {}", judged(&f.order, &t, N, 2, false));
	net.pass("F/the operator as a taker: a whole fill at the maker's price (control)", &t);

	net.print();
}
