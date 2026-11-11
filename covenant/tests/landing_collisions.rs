//! `landing-2` on a real node: the two-coin case, and every covenant that
//! can share a transaction with a landing.
//!
//! A covenant that checks "some output pays X" on its own can be satisfied by
//! an output another covenant in the same transaction also counts as its own,
//! and then one coin's worth leaves past what it was bound to. For a landing
//! that is the issuer's freeze: the landing's output is P2WPKH of the
//! holder's landing key, where the freeze binds. Each case below spends a
//! landing (a `landing-2` leaf's, or a checkpoint's landing, both at the
//! spending input's own index) beside another covenant in one transaction
//! whose outputs let one output serve both, and forces it into a block on a
//! node that checks scripts inline (`-par=1`), asserting why the block was
//! refused. The holder's two coins are worth `V` each; the shared output
//! holds one coin's landing minimum, and the rest goes to a script nobody
//! is bound by.
//!
//! - **The two-coin case** (PV3, arca #763): two `landing-1` coins of one
//!   holder share output 0 and the block takes it; two `landing-2` coins
//!   cannot (the second inspects output 1), and each at its own index
//!   confirms. A fee coin at input 0 moves a `landing-2` coin's landing to
//!   output 1.
//! - **A checkpoint's landing** beside a `landing-2` coin: refused.
//! - **A `landing-1` coin** beside a `landing-2` coin or a checkpoint's
//!   landing: refused when the newer one is at an input other than 0, and
//!   taken by the block when it is at input 0, where its own index is 0.
//!   That is `landing-1`'s own hole, which only refreshing the old coin
//!   closes.
//! - **A resting order** (`order-3`) landing as SeqDEX's order at output 0:
//!   refused (its output is a witness v1 program, the landing's v0).
//! - **SeqDEX's own order on the chain**, filled at input `k`, its maker's
//!   credit at `2k`: refused when the maker's script is another; taken when
//!   the maker's script is the landing key itself, where the shared output
//!   holds at least the landing's minimum, frozen, so nothing passes the
//!   freeze (the order's maker and the landing's signer are one holder).
//! - **A claim-1 lapse** (a distribution's refund) paying the landing key:
//!   refused, both at their own index.
//! - **A rebindable pair** (another landing coin's collaborative path, a
//!   checkpoint's without an exit) committing output 0 to the landing key:
//!   refused when the landing is at another input; taken at input 0, the
//!   same hole as `landing-1`'s. The operator's pairs pay leaves only, never
//!   a landing key (`server/src/cosign.rs`), so no such pair exists.
//!
//! Needs `SEQUENTIAD_EXEC`.

mod common;

use elements::hashes::{hash160, Hash};
use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, Script, TxOut};

use arca_covenant::claim::{script_pin, LapseTerms};
use arca_covenant::order::{OrderLeafTerms, OrderTerms, SeqdexOrder, SeqdexVersion};
use arca_covenant::{CheckpointExit, CheckpointPolicy, ExplicitOutput, Landing, LandingTerms, LeafPolicy, Template};
use common::net::*;
use common::*;

const V: u64 = 100_000_000;
const ALLOWANCE: u64 = 2_000;
const FEE: u64 = 1_000;
const EQ: &str = "Script failed an OP_EQUALVERIFY operation";

/// The holder: its key `A`, the operator `S`, and its landing key `L`.
struct Holder {
	a: Keypair,
	s: Keypair,
	program: [u8; 20],
}

impl Holder {
	fn new() -> Holder {
		let l = keypair("collision landing key");
		Holder { a: keypair("collision holder"), s: keypair("collision operator"),
			program: hash160::Hash::hash(&l.public_key().serialize()).to_byte_array() }
	}

	fn land_spk(&self) -> Script {
		Landing { program: self.program, allowance: 0, own_index: false }.script_pubkey()
	}

	/// A landing leaf of `z` and `V`, `landing-2` when `own_index`.
	fn leaf(&self, net: &Net, salt: &str, own_index: bool, z: AssetId) -> LeafPolicy {
		LeafPolicy { enclave: None, claim: None,
			owner: xonly(&self.a), operator: xonly(&self.s), salt: label32(salt), chain: net.chain, exit_delay: delay(), htlc: None,
			order: None, landing: Some(Landing { program: self.program, allowance: ALLOWANCE, own_index }.terms(z, V).unwrap()),
			channel: None, v2: false,
		}
	}

	/// A checkpoint of a landing coin of `z` worth `V`, with its owner's exit.
	fn checkpoint(&self, net: &Net, salt: &str, z: AssetId) -> CheckpointPolicy {
		CheckpointPolicy {
			owner: xonly(&self.a), operator: xonly(&self.s), salt: label32(salt), chain: net.chain, sweep: None, v2: false,
			exit: Some(CheckpointExit { delay: delay(),
				landing: Some(LandingTerms { program: self.program, asset: z, min_value: V - ALLOWANCE, own_index: true }) }),
		}
	}
}

/// How each input of a test transaction is spent.
#[derive(Clone)]
enum Way {
	/// A landing leaf's landing, signed by the holder.
	Leaf(LeafPolicy),
	/// A checkpoint's landing, signed by the holder.
	Checkpoint(CheckpointPolicy),
	/// The OP_TRUE tapscript.
	OpTrue,
	/// A witness already made, which signs nothing.
	Witness(Vec<Vec<u8>>),
	/// A rebindable pair over `outputs` of the coin of this leaf (`asset`,
	/// `value`), by the holder and the operator.
	Pair(LeafPolicy, Vec<ExplicitOutput>),
}

/// The transaction spending `coins` (each with its sequence and the way it is
/// spent) into `outs`, with lock time `lock`.
fn tx(net: &Net, h: &Holder, coins: &[(&Coin, u32, Way)], outs: Vec<TxOut>, lock: u32) -> elements::Transaction {
	let mut sp = spend(lock);
	for (c, seq, _) in coins {
		sp = sp.coin(c, *seq);
	}
	let mut sp = sp.outputs(outs);
	for (i, (c, _, way)) in coins.iter().enumerate() {
		let w = match way {
			Way::Leaf(l) => l.exit_witness(&sp.sign(&h.a, i, &l.exit_script(), net.genesis)),
			Way::Checkpoint(cp) => cp.exit_witness(&sp.sign(&h.a, i, &cp.exit_script().unwrap(), net.genesis)).unwrap(),
			Way::OpTrue => op_true_witness(),
			Way::Witness(w) => w.clone(),
			Way::Pair(l, committed) => {
				let m = l.collab_message(c.txout.asset.explicit().unwrap(), c.txout.value.explicit().unwrap(), committed).unwrap();
				l.collab_witness(&sig(&h.s, &m.digest), &sig(&h.a, &m.digest), committed.len() as u8)
			},
		};
		sp.witness(i, w);
	}
	sp.tx
}

/// Funds `spk` with `V` of `z`.
fn coin(net: &mut Net, z: AssetId, spk: Script) -> Coin {
	net.fund(vec![explicit(z, V, spk)]).remove(0)
}

#[test]
fn landings_never_share_an_output_with_another_covenant() {
	let mut net = Net::start();
	let h = Holder::new();
	let z = net.x;
	let land = h.land_spk();
	let thief = op_true_spk();
	let seq = delay().to_sequence();
	let min = V - ALLOWANCE;
	// One coin's landing, and the other coin's value to a script nobody is
	// bound by: one coin's worth past the freeze.
	let stolen = V + ALLOWANCE - FEE;
	let println_leaf = |l: &LeafPolicy| println!("{}: landing script {} bytes", l.template(), l.exit_script().len());

	// ---- the two-coin case --------------------------------------------------
	let l1a = h.leaf(&net, "two landing-1 a", false, z);
	let l1b = h.leaf(&net, "two landing-1 b", false, z);
	let l2a = h.leaf(&net, "two landing-2 a", true, z);
	let l2b = h.leaf(&net, "two landing-2 b", true, z);
	println_leaf(&l1a);
	println_leaf(&l2a);
	assert_eq!(l2a.template(), Template::Landing2);
	assert_eq!(l1a.exit_script().len(), l2a.exit_script().len(), "the same bytes, OP_PUSHCURRENTINPUTINDEX in place of 0");
	let c1a = coin(&mut net, z, l1a.script_pubkey());
	let c1b = coin(&mut net, z, l1b.script_pubkey());
	let c2a = coin(&mut net, z, l2a.script_pubkey());
	let c2b = coin(&mut net, z, l2b.script_pubkey());
	net.wait_csv(&c2b.outpoint.txid, delay());
	let shared = || vec![explicit(z, min, land.clone()), explicit(z, stolen, thief.clone()), fee(z, FEE)];
	net.pass("landing-1 + landing-1 share output 0: one coin's worth past the freeze (the hole PV3 showed, arca #763)",
		&tx(&net, &h, &[(&c1a, seq, Way::Leaf(l1a.clone())), (&c1b, seq, Way::Leaf(l1b.clone()))], shared(), 0));
	net.refuse("landing-2 + landing-2 share output 0", &tx(&net, &h, &[(&c2a, seq, Way::Leaf(l2a.clone())),
		(&c2b, seq, Way::Leaf(l2b.clone()))], shared(), 0), EQ);
	let each = || vec![explicit(z, V - FEE / 2, land.clone()), explicit(z, V - FEE / 2, land.clone()), fee(z, FEE)];
	net.pass("landing-2 + landing-2, each at its own index", &tx(&net, &h, &[(&c2a, seq, Way::Leaf(l2a.clone())),
		(&c2b, seq, Way::Leaf(l2b.clone()))], each(), 0));
	// A fee coin at input 0: the landing-2 coin at input 1 lands at output 1.
	let l2c = h.leaf(&net, "landing-2 at input 1", true, z);
	let c2c = coin(&mut net, z, l2c.script_pubkey());
	net.wait_csv(&c2c.outpoint.txid, delay());
	let fc = net.fee_coin();
	let fv = fc.txout.value.explicit().unwrap();
	let fa = fc.txout.asset.explicit().unwrap();
	net.refuse("landing-2 at input 1, its landing at output 0", &tx(&net, &h, &[(&fc, 0xffff_ffff, Way::OpTrue),
		(&c2c, seq, Way::Leaf(l2c.clone()))], vec![explicit(z, V, land.clone()), explicit(fa, fv - FEE, thief.clone()), fee(fa, FEE)], 0), EQ);
	net.pass("landing-2 at input 1, a fee coin at input 0: its landing at output 1", &tx(&net, &h, &[(&fc, 0xffff_ffff, Way::OpTrue),
		(&c2c, seq, Way::Leaf(l2c.clone()))], vec![explicit(fa, fv - FEE, thief.clone()), explicit(z, V, land.clone()), fee(fa, FEE)], 0));

	// ---- a checkpoint's landing ---------------------------------------------
	let cp = h.checkpoint(&net, "collision checkpoint a", z);
	let ccp = coin(&mut net, z, cp.script_pubkey());
	let l2d = h.leaf(&net, "landing-2 beside a checkpoint", true, z);
	let c2d = coin(&mut net, z, l2d.script_pubkey());
	net.wait_csv(&c2d.outpoint.txid, delay());
	net.refuse("checkpoint landing (input 0) + landing-2 (input 1) share output 0", &tx(&net, &h, &[
		(&ccp, seq, Way::Checkpoint(cp.clone())), (&c2d, seq, Way::Leaf(l2d.clone()))], shared(), 0), EQ);
	net.refuse("landing-2 (input 0) + checkpoint landing (input 1) share output 0", &tx(&net, &h, &[
		(&c2d, seq, Way::Leaf(l2d.clone())), (&ccp, seq, Way::Checkpoint(cp.clone()))], shared(), 0), EQ);
	net.pass("checkpoint landing + landing-2, each at its own index", &tx(&net, &h, &[
		(&ccp, seq, Way::Checkpoint(cp.clone())), (&c2d, seq, Way::Leaf(l2d.clone()))], each(), 0));

	// ---- a landing-1 coin beside the newer landings -------------------------
	let l1e = h.leaf(&net, "old landing-1 e", false, z);
	let l1f = h.leaf(&net, "old landing-1 f", false, z);
	let l1g = h.leaf(&net, "old landing-1 g", false, z);
	let l2e = h.leaf(&net, "landing-2 e", true, z);
	let l2f = h.leaf(&net, "landing-2 f", true, z);
	let cp2 = h.checkpoint(&net, "collision checkpoint b", z);
	let (c1e, c1f, c1g, c2e, c2f, ccp2) = (coin(&mut net, z, l1e.script_pubkey()), coin(&mut net, z, l1f.script_pubkey()),
		coin(&mut net, z, l1g.script_pubkey()), coin(&mut net, z, l2e.script_pubkey()), coin(&mut net, z, l2f.script_pubkey()),
		coin(&mut net, z, cp2.script_pubkey()));
	net.wait_csv(&ccp2.outpoint.txid, delay());
	net.refuse("landing-1 (input 0) + landing-2 (input 1) share output 0", &tx(&net, &h, &[
		(&c1e, seq, Way::Leaf(l1e.clone())), (&c2e, seq, Way::Leaf(l2e.clone()))], shared(), 0), EQ);
	net.refuse("landing-1 (input 0) + checkpoint landing (input 1) share output 0", &tx(&net, &h, &[
		(&c1e, seq, Way::Leaf(l1e.clone())), (&ccp2, seq, Way::Checkpoint(cp2.clone()))], shared(), 0), EQ);
	net.pass("RESIDUAL landing-2 (input 0) + landing-1 (input 1) share output 0: landing-1's hole, closed only by refreshing it",
		&tx(&net, &h, &[(&c2e, seq, Way::Leaf(l2e.clone())), (&c1e, seq, Way::Leaf(l1e.clone()))], shared(), 0));
	net.pass("RESIDUAL checkpoint landing (input 0) + landing-1 (input 1) share output 0: the same hole",
		&tx(&net, &h, &[(&ccp2, seq, Way::Checkpoint(cp2.clone())), (&c1f, seq, Way::Leaf(l1f.clone()))], shared(), 0));
	net.pass("landing-1 (input 0) + landing-2 (input 1), each at its own output", &tx(&net, &h, &[(&c1g, seq, Way::Leaf(l1g.clone())),
		(&c2f, seq, Way::Leaf(l2f.clone()))], each(), 0));

	// ---- a resting order (order-3) landing as SeqDEX's order ----------------
	let maker = keypair("collision maker");
	let refund = keypair("collision refund");
	let y = net.y;
	let terms = OrderLeafTerms {
		landed: SeqdexOrder {
			terms: OrderTerms { asset_a: z, asset_b: y, rate_num: 1, rate_den: 1, min_lot: 1_000 },
			maker: arca_covenant::script::sha256(land.as_bytes()), expiry: (net.now() + 30 * 86_400) as u32,
			refund_key: xonly(&refund), version: SeqdexVersion::V2,
		},
		credits: [0, 1, 2, 3].map(|i| xonly(&keypair(&format!("collision credit {}", i))).serialize()),
	};
	assert_eq!(terms.template(), Template::Order3);
	let op = terms.policy(xonly(&maker), xonly(&h.s), label32("collision order leaf"), net.chain, delay());
	let corder = coin(&mut net, z, op.script_pubkey());
	let l2g = h.leaf(&net, "landing-2 beside an order", true, z);
	let c2g = coin(&mut net, z, l2g.script_pubkey());
	net.wait_csv(&c2g.outpoint.txid, delay());
	net.refuse("landing-2 (input 0) + an order-3 leaf's landing (input 1) share output 0", &tx(&net, &h, &[
		(&c2g, seq, Way::Leaf(l2g.clone())), (&corder, seq, Way::Witness(op.landing_witness()))], shared(), 0), EQ);
	net.refuse("an order-3 leaf's landing (input 0) + landing-2 (input 1) share output 0", &tx(&net, &h, &[
		(&corder, seq, Way::Witness(op.landing_witness())), (&c2g, seq, Way::Leaf(l2g.clone()))],
		vec![op.landed_output(V).txout(), explicit(z, V - FEE, thief.clone()), fee(z, FEE)], 0), EQ);

	// ---- SeqDEX's own order on the chain, its maker's credit at 2k -----------
	// The order sells Y for Z at 1:1; filled at input 1, its credit is output
	// 2 and its remainder output 3. The landing-2 coin at input 2 inspects
	// output 2.
	let lot = 10_000_000;
	let on_chain = |maker: &Script| SeqdexOrder {
		terms: OrderTerms { asset_a: y, asset_b: z, rate_num: 1, rate_den: 1, min_lot: 1_000 },
		maker: arca_covenant::script::sha256(maker.as_bytes()), expiry: terms.landed.expiry, refund_key: xonly(&refund),
		version: SeqdexVersion::V2,
	};
	for (name, maker_spk, expect) in [
		("SeqDEX's order paying its maker's other script (input 1) + landing-2 (input 2) share output 2", thief.clone(), Some(EQ)),
		("SeqDEX's order whose maker's script IS the landing key (input 1) + landing-2 (input 2) share output 2: the shared output \
			holds the landing's minimum, at the frozen key", land.clone(), None),
	] {
		let order = on_chain(&maker_spk);
		let o = coin(&mut net, y, order.script_pubkey());
		let l = h.leaf(&net, &format!("landing-2 beside an on-chain order {:?}", expect), true, z);
		let c = coin(&mut net, z, l.script_pubkey());
		net.wait_csv(&c.outpoint.txid, delay());
		let fc = net.fee_coin();
		let (fa, fv) = (fc.txout.asset.explicit().unwrap(), fc.txout.value.explicit().unwrap());
		let outs = vec![explicit(fa, fv - FEE, thief.clone()), explicit(y, lot, thief.clone()), explicit(z, min, maker_spk.clone()),
			explicit(y, V - lot, order.script_pubkey()), explicit(z, V - min, thief.clone()), fee(fa, FEE)];
		let t = tx(&net, &h, &[(&fc, 0xffff_ffff, Way::OpTrue), (&o, 0xffff_ffff, Way::Witness(order.fill_witness(true))),
			(&c, seq, Way::Leaf(l.clone()))], outs, 0);
		match expect {
			Some(e) => net.refuse(name, &t, e),
			None => {
				net.pass(name, &t);
			},
		}
	}

	// ---- a claim-1 lapse paying the landing key ------------------------------
	let deadline = mt(net.mtp() - 60);
	let ql = LeafPolicy { enclave: None, owner: xonly(&h.a), operator: xonly(&h.s), salt: label32("collision claim"), chain: net.chain,
		exit_delay: delay(), htlc: None, order: None, landing: None, channel: None, v2: false,
		claim: Some(LapseTerms { deadline, pin: script_pin(&land), asset: z, min_value: min, vest: None }),
	};
	assert_eq!(ql.template(), Template::Claim1);
	let cq = coin(&mut net, z, ql.script_pubkey());
	let l2h = h.leaf(&net, "landing-2 beside a lapse", true, z);
	let c2h = coin(&mut net, z, l2h.script_pubkey());
	net.wait_csv(&c2h.outpoint.txid, delay());
	let lock = deadline.to_consensus_u32();
	net.refuse("landing-2 (input 0) + a claim-1 lapse to the landing key (input 1) share output 0", &tx(&net, &h, &[
		(&c2h, seq, Way::Leaf(l2h.clone())), (&cq, seq, Way::Witness(ql.lapse_witness().unwrap()))], shared(), lock), EQ);
	net.refuse("a claim-1 lapse to the landing key (input 0) + landing-2 (input 1) share output 0", &tx(&net, &h, &[
		(&cq, seq, Way::Witness(ql.lapse_witness().unwrap())), (&c2h, seq, Way::Leaf(l2h.clone()))], shared(), lock), EQ);

	// ---- a rebindable pair committing output 0 to the landing key -----------
	// Another landing coin of the holder, spent by its collaborative path with
	// a pair over [landing key, the coin's value less the fee]: the pair
	// pins output 0, as a checkpoint's pair without an exit does.
	let pl = h.leaf(&net, "collision paired leaf", true, z);
	let cpl = coin(&mut net, z, pl.script_pubkey());
	let l2i = h.leaf(&net, "landing-2 beside a pair", true, z);
	let c2i = coin(&mut net, z, l2i.script_pubkey());
	net.wait_csv(&c2i.outpoint.txid, delay());
	let committed = vec![ExplicitOutput::new(z, min, land.clone())];
	net.refuse("a pair committing output 0 to the landing key (input 0) + landing-2 (input 1) share output 0", &tx(&net, &h, &[
		(&cpl, 0xffff_ffff, Way::Pair(pl.clone(), committed.clone())), (&c2i, seq, Way::Leaf(l2i.clone()))], shared(), 0), EQ);
	net.pass("RESIDUAL landing-2 (input 0) + a pair committing output 0 to the landing key (input 1): no operator signs such a pair",
		&tx(&net, &h, &[(&c2i, seq, Way::Leaf(l2i.clone())), (&cpl, 0xffff_ffff, Way::Pair(pl.clone(), committed.clone()))], shared(), 0));

	net.print();
}
