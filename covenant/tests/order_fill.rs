//! The coin records of an in-tree fill of a resting order, on regtest.
//!
//! An `order-2` leaf rests in a batch of X; a taker's leaf sits in a batch of
//! Y. The taker fills the order in the tree: its coin goes through a
//! checkpoint, and the operator signs the fill. Every coin the fill makes (the
//! maker's credit, the order resting again, the taker's leaf of X and its
//! change) has a record that validates against the two rounds alone, and is
//! refused when anything in it is changed. A second fill of the remainder
//! makes coins two fills deep. Then everything goes on the chain from the
//! records: both paths, the checkpoint and the fill; the credit is exited by
//! its key, and the remainder lands as SeqDEX's own order.
//!
//! Needs `SEQUENTIAD_EXEC`.

mod common;

use elements::{OutPoint, Script, Transaction};
use serde_json::{json, Value};

use arca_covenant::order::{OrderLeafTerms, OrderPolicy, OrderTerms, SeqdexOrder};
use arca_covenant::spend::{FeeSource, UnrollTx};
use arca_covenant::transfer::{FillCoin, FillLeaf, NewLeaf, OrderFill};
use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeParams};
use arca_covenant::*;

use common::net::*;
use common::round::*;
use common::*;

const N: u64 = 10_000_000;

fn plain(key: &elements::secp256k1_zkp::Keypair) -> Script {
	elements::script::Builder::new().push_int(1).push_slice(&xonly(key).serialize()).into_script()
}

fn tree_in(c: &Arca, asset: elements::AssetId, sched: &ClockSchedule, leaves: &[LeafSpec]) -> Tree {
	Tree::build(TreeParams {
		asset, chain: c.net.chain, schedule: sched.clone(), burn: false, radix: 4,
		reserve: ReserveRule::FeeRate { floor_per_kvb: c.floor_per_kvb, multiple: 4 }, min_leaf: 1,
	}, leaves).unwrap()
}

/// A coin of the operator's in `asset` and the batch's round, from `issuer`.
fn round_in(c: &mut Arca, name: &str, asset: elements::AssetId, issuer: &Coin, sched: &ClockSchedule, tree: &Tree) -> Transaction {
	let batch = tree.batch_output();
	let total = issuer.txout.value.explicit().unwrap();
	let mut s = spend(0).coin(issuer, 0xffff_ffff).outputs(vec![batch.txout(), explicit(sched.token, 1, sched.clock0_script_pubkey()),
		explicit(asset, total - batch.value - 2_000, op_true_spk()), fee(asset, 2_000)]);
	s.tx.input[0].asset_issuance = elements::AssetIssuance {
		asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: [0; 32],
		amount: elements::confidential::Value::Explicit(1), inflation_keys: elements::confidential::Value::Null, denomination: 0,
	};
	s.witness(0, op_true_witness());
	c.net.pass(name, &s.tx);
	s.tx
}

/// A fee coin in the policy asset, as a fee source paying `fee`.
fn fee_source(c: &mut Arca, fee: u64) -> FeeSource {
	let coin = c.net.fee_coin();
	FeeSource::Coin { outpoint: coin.outpoint, coin: coin.txout, fee, change: op_true_spk() }
}

/// Finishes an unroll transaction that pays from a fee coin.
fn with_fee_coin(mut u: UnrollTx) -> Transaction {
	let n = u.tx.input.len();
	u.tx.input[n - 1].witness.script_witness = op_true_witness();
	u.tx
}

struct Taker {
	key: elements::secp256k1_zkp::Keypair,
	x_leaf: NewLeaf,
	change: NewLeaf,
}

fn taker(label: &str) -> Taker {
	let key = keypair(&format!("order-fill taker {}", label));
	let leaf = |what: &str| NewLeaf {
		owner: xonly(&key), owner_nonce: label32(&format!("order-fill taker {} {} owner nonce", label, what)),
		creator_nonce: label32(&format!("order-fill taker {} {} creator nonce", label, what)), exit_delay: delay(), htlc: None,
		landing: None, v2: false,
	};
	Taker { x_leaf: leaf("x"), change: leaf("change"), key }
}

/// The fill of `filled` of the order coin `order` (record `order_rec`) by
/// the taker coin `coin` (record `coin_rec`), signed by `s`, with `edit`
/// applied to the outputs before anyone signs.
#[allow(clippy::too_many_arguments)]
fn make_fill(order_rec: &CoinRecord, order: &ValidCoin, coin_rec: &CoinRecord, coin: &ValidCoin, payer: &elements::secp256k1_zkp::Keypair,
	t: &Taker, filled: u64, s: &elements::secp256k1_zkp::Keypair, edit: impl Fn(&mut Vec<ExplicitOutput>)) -> OrderFill
{
	let op = order.leaf.order_policy().unwrap();
	let plan = op.plan(order.value, filled).unwrap();
	let price = plan.credit.value;
	let mut outputs = vec![plan.credit.clone()];
	if let Some(r) = &plan.rest {
		outputs.push(r.clone());
	}
	outputs.push(ExplicitOutput::new(order.asset, filled, t.x_leaf.policy(xonly(s), op.chain).script_pubkey()));
	let margin = 2_000;
	outputs.push(ExplicitOutput::new(coin.asset, coin.value - price - margin, t.change.policy(xonly(s), op.chain).script_pubkey()));
	edit(&mut outputs);
	let txouts: Vec<_> = outputs.iter().map(|o| o.txout()).collect();
	let digest = op.fill_digest(order.value, &txouts).unwrap();
	let cp = coin.checkpoint();
	let cp_out = ExplicitOutput::new(coin.asset, coin.value, cp.script_pubkey());
	let m_cp = coin.leaf.collab_message(coin.asset, coin.value, std::slice::from_ref(&cp_out)).unwrap();
	let m_f = cp.collab_message(coin.asset, coin.value, &outputs).unwrap();
	OrderFill {
		order: order_rec.clone(),
		signature: sig(s, &digest),
		partial: plan.rest.is_some(),
		inputs: vec![TransferInput {
			coin: coin_rec.clone(), checkpoint_value: coin.value,
			checkpoint: Pair { operator: sig(s, &m_cp.digest), owner: sig(payer, &m_cp.digest) },
			reassignment: Pair { operator: sig(s, &m_f.digest), owner: sig(payer, &m_f.digest) },
		}],
		outputs,
	}
}

fn coin_of_fill(fill: &OrderFill, index: u8, leaf: FillLeaf) -> CoinRecord {
	CoinRecord::Fill(Box::new(FillCoin { fill: fill.clone(), index, leaf }))
}

#[test]
fn an_in_tree_fill_and_its_coin_records() {
	let mut c = Arca::start();
	let rates: Value = c.net.rt.client().call("getfeeexchangerates", &[]).unwrap();
	let mut rates = rates.as_object().unwrap().clone();
	rates.insert(c.net.y.to_string(), json!(100_000_000));
	let _: Value = c.net.rt.client().call("setfeeexchangerates", &[Value::Object(rates)]).unwrap();
	let s = keypair("order-fill operator");
	let t0 = mt(c.net.mtp() - 60);

	// The maker's order: X for Y at 2 Y an X, lots of 1,000,000.
	let maker = keypair("order-fill maker");
	let credit_keys: Vec<_> = (0..4).map(|i| keypair(&format!("order-fill credit {}", i))).collect();
	let refund = keypair("order-fill refund");
	let terms = OrderLeafTerms {
		landed: SeqdexOrder {
			terms: OrderTerms { asset_a: c.net.x, asset_b: c.net.y, rate_num: 2, rate_den: 1, min_lot: 1_000_000 },
			maker: arca_covenant::script::sha256(plain(&refund).as_bytes()),
			expiry: (c.net.now() + 30 * DAY) as u32,
			refund_key: xonly(&refund),
		},
		credits: [0, 1, 2, 3].map(|i| xonly(&credit_keys[i]).serialize()),
	};
	let (issuer_x, sched_x) = c.schedule(&s);
	let mut xs = vec![LeafSpec { template: Template::Order2, order: Some(terms), ..spec(&maker, "order-fill order", N, hash(&label32("ox"))) }];
	for i in 1..4 {
		xs.push(spec(&keypair(&format!("order-fill x owner {}", i)), &format!("order-fill x {}", i), N, hash(&label32(&format!("x{}", i)))));
	}
	let tx_ = tree_in(&c, c.net.x, &sched_x, &xs);
	let (x, y) = (c.net.x, c.net.y);
	let round_x = round_in(&mut c, "round: an order-2 leaf in a batch of X", x, &issuer_x, &sched_x, &tx_);

	// The takers' leaves of Y.
	let issuer_y = c.net.fund(vec![explicit(c.net.y, 2_000_000_000, op_true_spk())]).remove(0);
	let sched_y = ClockSchedule::new(token_of(&issuer_y), xonly(&s), delay(), vec![mt(c.net.now() + 29 * DAY)]).unwrap();
	let takers: Vec<_> = (0..4).map(|i| keypair(&format!("order-fill y owner {}", i))).collect();
	let ys: Vec<_> = (0..4).map(|i| spec(&takers[i], &format!("order-fill y {}", i), 3 * N, hash(&label32(&format!("y{}", i))))).collect();
	let ty = tree_in(&c, c.net.y, &sched_y, &ys);
	let round_y = round_in(&mut c, "round: the takers' leaves in a batch of Y", y, &issuer_y, &sched_y, &ty);
	let rounds = vec![round_x.clone(), round_y.clone()];

	let policy = c.policy(&s);
	let order_rec = base(&tx_, 0, &maker, label32("ox"), t0);
	let order = order_rec.validate(&rounds, &policy, &xonly(&maker), &label32("order-fill order owner nonce")).unwrap();
	assert_eq!(order.leaf.template(), Template::Order2);
	let taker_rec = base(&ty, 0, &takers[0], label32("y0"), t0);
	let taker_coin = taker_rec.validate(&rounds, &policy, &xonly(&takers[0]), &label32("order-fill y 0 owner nonce")).unwrap();

	// The fill: 4,000,000 X for 8,000,000 Y.
	let t1 = taker("one");
	let fill = make_fill(&order_rec, &order, &taker_rec, &taker_coin, &takers[0], &t1, 4_000_000, &s, |_| {});
	let credit = coin_of_fill(&fill, 0, FillLeaf::Credit { owner_nonce: label32("credit nonce 0") });
	let rest = coin_of_fill(&fill, 1, FillLeaf::Rest { owner_nonce: label32("order-fill order owner nonce") });
	let got_x = coin_of_fill(&fill, 2, FillLeaf::New(t1.x_leaf));
	let change = coin_of_fill(&fill, 3, FillLeaf::New(t1.change));
	let credit_coin = credit.validate(&rounds, &policy, &xonly(&credit_keys[0]), &label32("credit nonce 0")).unwrap();
	assert_eq!(credit_coin.value, 8_000_000);
	assert_eq!(credit_coin.leaf.template(), Template::Vtxo1);
	let rest_coin = rest.validate(&rounds, &policy, &xonly(&maker), &label32("order-fill order owner nonce")).unwrap();
	assert_eq!(rest_coin.leaf.template(), Template::Order2);
	assert_eq!(rest_coin.value, N - 4_000_000);
	assert_eq!(rest_coin.hops, 1);
	let x_coin = got_x.validate(&rounds, &policy, &xonly(&t1.key), &t1.x_leaf.owner_nonce).unwrap();
	assert_eq!(x_coin.value, 4_000_000);
	change.validate(&rounds, &policy, &xonly(&t1.key), &t1.change.owner_nonce).unwrap();
	println!("fill: credit {} of Y to credit key 0, the rest {} of X resting, the taker's {} of X; lineage of the taker's leaf: {} outputs",
		credit_coin.value, rest_coin.value, x_coin.value, x_coin.lineage().len());
	assert_eq!(credit.owner(), Some((xonly(&credit_keys[0]), label32("credit nonce 0"))));
	assert_eq!(rest.owner(), Some((xonly(&maker), label32("order-fill order owner nonce"))));
	assert_eq!(rest.order_policy(), rest_coin.leaf.order_policy());
	for r in [&credit, &rest, &got_x, &change] {
		assert_eq!(&CoinRecord::from_bytes(&r.to_bytes().unwrap()).unwrap(), r, "the binary form reads back");
	}

	// Refused: each a fill with one thing changed.
	let refuse = |name: &str, r: &CoinRecord, owner: &elements::secp256k1_zkp::Keypair, nonce: [u8; 32]| {
		let e = r.validate(&rounds, &policy, &xonly(owner), &nonce).unwrap_err();
		println!("refused, {}: {} ({})", name, e, e.kind());
		e
	};
	let mut forged = fill.clone();
	forged.signature = sig(&maker, &[7; 32]);
	refuse("a fill not signed by the operator", &coin_of_fill(&forged, 2, FillLeaf::New(t1.x_leaf)), &t1.key, t1.x_leaf.owner_nonce);
	let short = make_fill(&order_rec, &order, &taker_rec, &taker_coin, &takers[0], &t1, 4_000_000, &s, |o| {
		o[0].value -= 1;
		o[3].value += 1;
	});
	refuse("a credit one atom short, signed so", &coin_of_fill(&short, 2, FillLeaf::New(t1.x_leaf)), &t1.key, t1.x_leaf.owner_nonce);
	let wrong_rest = make_fill(&order_rec, &order, &taker_rec, &taker_coin, &takers[0], &t1, 4_000_000, &s, |o| {
		o[1].script_pubkey = o[2].script_pubkey.clone();
		o[2].script_pubkey = plain(&t1.key);
	});
	refuse("the remainder to the taker, signed so", &coin_of_fill(&wrong_rest, 1, FillLeaf::Rest { owner_nonce: label32("order-fill order owner nonce") }), &maker, label32("order-fill order owner nonce"));
	let over = make_fill(&order_rec, &order, &taker_rec, &taker_coin, &takers[0], &t1, 4_000_000, &s, |o| o[2].value += 1);
	refuse("one atom of X more than the order holds", &coin_of_fill(&over, 2, FillLeaf::New(t1.x_leaf)), &t1.key, t1.x_leaf.owner_nonce);
	refuse("the credit claimed by the maker's leaf key", &credit, &maker, label32("credit nonce 0"));
	refuse("the credit read as a taker's leaf", &coin_of_fill(&fill, 0, FillLeaf::New(t1.x_leaf)), &t1.key, t1.x_leaf.owner_nonce);
	refuse("the remainder named the maker's credit", &coin_of_fill(&fill, 1, FillLeaf::Credit { owner_nonce: label32("credit nonce 0") }), &credit_keys[0], label32("credit nonce 0"));
	refuse("the taker's leaf for another taker", &got_x, &maker, t1.x_leaf.owner_nonce);

	// A second fill, of the remainder, by another taker: two fills deep.
	let taker2_rec = base(&ty, 1, &takers[1], label32("y1"), t0);
	let taker2_coin = taker2_rec.validate(&rounds, &policy, &xonly(&takers[1]), &label32("order-fill y 1 owner nonce")).unwrap();
	let t2 = taker("two");
	let fill2 = make_fill(&rest, &rest_coin, &taker2_rec, &taker2_coin, &takers[1], &t2, 3_000_000, &s, |_| {});
	let credit2 = coin_of_fill(&fill2, 0, FillLeaf::Credit { owner_nonce: label32("credit nonce 1") }).validate(&rounds, &policy, &xonly(&credit_keys[1]), &label32("credit nonce 1")).unwrap();
	let rest2 = coin_of_fill(&fill2, 1, FillLeaf::Rest { owner_nonce: label32("order-fill order owner nonce") }).validate(&rounds, &policy, &xonly(&maker), &label32("order-fill order owner nonce")).unwrap();
	assert_eq!((credit2.value, rest2.value, rest2.hops), (6_000_000, 3_000_000, 2));
	assert_ne!(credit2.leaf.script_pubkey(), credit_coin.leaf.script_pubkey(), "each credit under a script of its own");
	println!("fill 2: credit {} to credit key 1, the rest {} resting two fills deep", credit2.value, rest2.value);

	// Everything on the chain, from the records alone.
	let order_at = c.bring_coin("the order's path", &order);
	let taker_at = c.bring_coin("the taker's path", &taker_coin);
	let ValidOrigin::Fill { inputs, .. } = &x_coin.origin else { unreachable!() };
	let fs = fee_source(&mut c, 4_000);
	let cp = with_fee_coin(inputs[0].checkpoint_tx(taker_at, &fs).unwrap());
	let cpt = c.net.pass("the taker's checkpoint, from its record", &cp);
	let fs = fee_source(&mut c, 6_000);
	let f = with_fee_coin(x_coin.fill_tx(order_at, &[OutPoint::new(cpt, 0)], &fs).unwrap());
	let ft = c.net.pass("the fill, from the taker's record", &f);
	assert_eq!(f.output[0].script_pubkey, credit_coin.leaf.script_pubkey());
	// The credit's owner exits it by its key after the delay; the remainder
	// lands as SeqDEX's order.
	c.net.wait_csv(&ft, delay());
	let e = exit_tx(&c.net, &credit_coin.leaf, OutPoint::new(ft, 0), c.net.y, credit_coin.value, &credit_keys[0]);
	c.net.pass("the maker's exit of its credit, by credit key 0", &e);
	let op: OrderPolicy = rest_coin.leaf.order_policy().unwrap();
	let fc = c.net.fee_coin();
	let mut l = spend(0).coin(&coin_of(ft, 1, &f), delay().to_sequence()).coin(&fc, 0xffff_ffff)
		.output(op.landed_output(rest_coin.value).txout())
		.outputs(vec![explicit(c.net.policy, fc.txout.value.explicit().unwrap() - 4_000, op_true_spk()), fee(c.net.policy, 4_000)]);
	l.witness(0, op.landing_witness());
	l.witness(1, op_true_witness());
	c.net.pass("the remainder lands as SeqDEX's order", &l.tx);
	c.net.print();
}
