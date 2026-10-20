//! SeqDEX's fill covenant, as a round fills it.
//!
//! - The FILL and REFUND leaves, their hashes, the output key, the
//!   scriptPubKey and the control block equal SeqDEX's golden vector
//!   (`daemon/pkg/covenant/leaf_test.go` in `ConcatenaLabs/seqdex`, generated
//!   from the Python builder its regtest suite proves).
//! - With `SEQOB_COVENANT_EXEC` naming SeqDEX's own `seqob-covenant` (built from
//!   `daemon/cmd/seqob-covenant`), every order of a set derives the same
//!   script there as here, and its planner (`fill -k`) plans each fill as
//!   [`FillOrder::plan`] does, for `k` beyond 0. Without it that test says so
//!   and passes.
//! - The relay's JSON form of an order reads back to the same order, and
//!   terms a resting order cannot have are refused.
//! - Round-shaped transactions, covenant inputs first at `k = 0` and `k = 1`,
//!   their credits at `2k` and remainders at `2k+1`, the batch after them:
//!   the node's interpreter (`arca-consensus`, block rules) and
//!   [`FillOrder::check`] reach the same verdict on every case, the node
//!   giving its own error for each negative. `-- --nocapture` prints the
//!   table.

mod common;

use std::process::Command;

use elements::confidential::{Asset, Nonce, Value};
use elements::hashes::Hash;
use elements::secp256k1_zkp::{Generator, Secp256k1, Tag, Tweak};
use elements::{AssetId, BlockHash, OutPoint, Script, Transaction, TxOut, TxOutWitness, Txid};
use serde_json::{json, Value as Json};

use arca_consensus::Verifier;
use arca_covenant::fill::{base64, FillError, FillOrder, RefundLock};
use arca_covenant::script::asset_bytes;
use arca_covenant::TapOutput;

use common::*;

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// SeqDEX's fixed order: `asset_a = bytes(range(0,32))`, `asset_b =
/// bytes(range(32,64))`, rate 3/7, min_lot 500000000, maker_prog `0x11*32`,
/// expiry 400, maker_x `0x22*32`, internal key NUMS.
fn golden_order() -> FillOrder {
	let mut a = [0u8; 32];
	let mut b = [0u8; 32];
	for i in 0..32 {
		a[i] = i as u8;
		b[i] = 32 + i as u8;
	}
	FillOrder {
		asset_a: AssetId::from_byte_array(a),
		asset_b: AssetId::from_byte_array(b),
		rate_num: 3,
		rate_den: 7,
		maker_prog: [0x11; 32],
		min_lot: 500_000_000,
		expiry_locktime: 400,
		maker_x: [0x22; 32],
	}
}

const GOLD_FILL_LEAF: &str = "cdc95188cd76938bd59f63cd76938bce518820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f8763cd76938bd1cdca7b8888cd76938bcf518876080065cd1d00000000df6967080000000000000000686708000000000000000068d86976080065cd1d00000000df69080300000000000000d969080600000000000000d769080700000000000000da6977cd7693ce518820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f88cd7693d1518820111111111111111111111111111111111111111111111111111111111111111188cd7693cf51887cdf";
const GOLD_REFUND_LEAF: &str = "029001b175202222222222222222222222222222222222222222222222222222222222222222ac";
const GOLD_FILL_HASH: &str = "4d1a21f10826870560f07e69520416221c532fb8744bc0a0b2bf38032cd03343";
const GOLD_REFUND_HASH: &str = "b36045e27b7a5812d8d7339811db86ef98751c7e382a84a1d34949a83b4ae920";
const GOLD_MERKLE_ROOT: &str = "224a2849e4419e6a81593dad51e14766083c08e31081f0aecaea3d1dc7daf3c3";
const GOLD_OUTPUT_KEY: &str = "b22544534c99090050a06eece12231a2321f4144661ab3964408d5780821afaa";
const GOLD_SPK: &str = "5120b22544534c99090050a06eece12231a2321f4144661ab3964408d5780821afaa";
const GOLD_CTRL_BLOCK: &str = "c550929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0b36045e27b7a5812d8d7339811db86ef98751c7e382a84a1d34949a83b4ae920";

#[test]
fn the_leaves_and_the_output_equal_seqdex_golden_vector() {
	let o = golden_order();
	assert_eq!(hex(o.fill_leaf().as_bytes()), GOLD_FILL_LEAF);
	assert_eq!(hex(o.refund_leaf().as_bytes()), GOLD_REFUND_LEAF);
	assert_eq!(hex(&arca_covenant::taptree::leaf_hash(&o.fill_leaf()).to_byte_array()), GOLD_FILL_HASH);
	assert_eq!(hex(&o.merkle_path()), GOLD_REFUND_HASH);
	let tap: TapOutput = o.output();
	assert_eq!(hex(&tap.merkle_root().unwrap()), GOLD_MERKLE_ROOT);
	assert_eq!(hex(&tap.program()), GOLD_OUTPUT_KEY);
	assert_eq!(hex(o.script_pubkey().as_bytes()), GOLD_SPK);
	assert_eq!(hex(&o.control_block()), GOLD_CTRL_BLOCK);
	assert_eq!(o.witness(), vec![o.fill_leaf().to_bytes(), o.control_block()]);
	assert_eq!(o.refund_lock(), RefundLock::Height(400));
	// ceil(10*1/3) = 4 and ceil(90*1/3) = 30, as SeqDEX's CeilPrice.
	let third = FillOrder { rate_num: 1, rate_den: 3, ..golden_order() };
	assert_eq!((third.price(10), third.price(90)), (Some(4), Some(30)));
}

/// A set of orders whose terms vary in every field the leaves bake in.
fn orders() -> Vec<FillOrder> {
	let mut out = vec![golden_order()];
	for (i, (num, den, lot, expiry)) in [(1u64, 3u64, 5u64, 1u32), (250, 1, 1, 16), (7, 1_000_000, 100_000, 17), (1, 1, 1_000, 65_535),
		(123_456_789, 987_654, 42, 500_000_123), (2, 3, 1, 1_799_999_999)].into_iter().enumerate()
	{
		out.push(FillOrder {
			asset_a: asset(&format!("A{}", i)),
			asset_b: asset(&format!("B{}", i)),
			rate_num: num,
			rate_den: den,
			maker_prog: label32(&format!("maker program {}", i)),
			min_lot: lot,
			expiry_locktime: expiry,
			maker_x: xonly(&keypair(&format!("maker {}", i))).serialize(),
		});
	}
	out
}

fn order_flags(o: &FillOrder) -> Vec<String> {
	[("-a", hex(&asset_bytes(o.asset_a))), ("-b", hex(&asset_bytes(o.asset_b))), ("-num", o.rate_num.to_string()),
		("-den", o.rate_den.to_string()), ("-minlot", o.min_lot.to_string()), ("-prog", hex(&o.maker_prog)),
		("-expiry", o.expiry_locktime.to_string()), ("-makerx", hex(&o.maker_x))]
		.into_iter().flat_map(|(f, v)| [f.to_string(), v]).collect()
}

fn seqob_covenant(exec: &str, args: &[String]) -> Json {
	let out = Command::new(exec).args(args).output().expect("run seqob-covenant");
	assert!(out.status.success(), "seqob-covenant {:?}: {}", args, String::from_utf8_lossy(&out.stderr));
	serde_json::from_slice(&out.stdout).expect("its JSON")
}

#[test]
fn every_order_derives_and_plans_as_seqdex_own_tool_does() {
	let Ok(exec) = std::env::var("SEQOB_COVENANT_EXEC") else {
		println!("skipped: SEQOB_COVENANT_EXEC names no seqob-covenant (SeqDEX's daemon/cmd/seqob-covenant)");
		return;
	};
	let mut planned = 0;
	for o in orders() {
		let mut args = vec!["derive".to_string()];
		args.extend(order_flags(&o));
		let d = seqob_covenant(&exec, &args);
		assert_eq!(d["fill_leaf"], json!(hex(o.fill_leaf().as_bytes())), "{:?}", o);
		assert_eq!(d["refund_leaf"], json!(hex(o.refund_leaf().as_bytes())), "{:?}", o);
		assert_eq!(d["scriptpubkey"], json!(hex(o.script_pubkey().as_bytes())), "{:?}", o);
		assert_eq!(d["control_block"], json!(hex(&o.control_block())), "{:?}", o);
		assert_eq!(d["merkle_branch"], json!(hex(&o.merkle_path())), "{:?}", o);
		let locked = (o.min_lot * 7).max(1_000_000);
		if o.check_arithmetic(locked).is_err() {
			continue;
		}
		for (k, filled) in [(0u32, locked), (1, locked - o.min_lot), (3, o.min_lot), (2, locked / 2)] {
			let ours = o.plan(locked, filled);
			let mut args = vec!["fill".to_string()];
			args.extend(order_flags(&o));
			args.extend(["-locked".into(), locked.to_string(), "-filled".into(), filled.to_string(), "-k".into(), k.to_string()]);
			let out = Command::new(&exec).args(&args).output().expect("run seqob-covenant fill");
			match ours {
				Ok(p) => {
					assert!(out.status.success(), "{:?}: SeqDEX refused a fill we plan: {}", o, String::from_utf8_lossy(&out.stderr));
					let f: Json = serde_json::from_slice(&out.stdout).unwrap();
					assert_eq!(f["input_index"], json!(k));
					assert_eq!(f["credit_index"], json!(2 * k));
					assert_eq!(f["remainder_index"], json!(2 * k + 1));
					assert_eq!(f["filled"], json!(p.filled));
					assert_eq!(f["remainder"], json!(p.remainder));
					assert_eq!(f["required_b"], json!(p.credit.value));
					assert_eq!(f["partial"], json!(p.rest.is_some()));
					assert_eq!(f["order_spk"], json!(hex(o.script_pubkey().as_bytes())));
					planned += 1;
				},
				Err(e) => assert!(!out.status.success(), "{:?}: SeqDEX plans a fill of {} we refuse: {}", o, filled, e),
			}
		}
	}
	println!("{} orders derived alike; {} fills planned alike, at k = 0, 1, 2 and 3", orders().len(), planned);
	assert!(planned >= 10);
}

#[test]
fn the_relay_form_reads_back_and_bad_terms_are_refused() {
	let op = OutPoint::new(Txid::from_byte_array([7; 32]), 3);
	for o in orders() {
		let v = o.to_relay(&op);
		assert_eq!(FillOrder::from_relay(&v).unwrap(), (op, o.clone()));
		// As an offer's settlement, and with the integers as numbers.
		assert_eq!(FillOrder::from_relay(&json!({"offer_id": "x", "covenant": v.clone()})).unwrap().1, o);
		let mut n = v.clone();
		n["rate_num"] = json!(o.rate_num);
		n["min_lot"] = json!(o.min_lot);
		assert_eq!(FillOrder::from_relay(&n).unwrap().1, o);
		// The relay's takers read a missing internal key, and an empty path, as
		// NUMS and nothing to check.
		let mut bare = v.clone();
		bare.as_object_mut().unwrap().remove("internal_key");
		bare["merkle_path"] = json!([]);
		assert_eq!(FillOrder::from_relay(&bare).unwrap().1, o);
	}
	let v = golden_order().to_relay(&op);
	let refused = |f: &dyn Fn(&mut Json)| {
		let mut t = v.clone();
		f(&mut t);
		FillOrder::from_relay(&t).unwrap_err()
	};
	assert_eq!(refused(&|t| t["internal_key"] = json!(base64(&[0x22; 32]))), FillError::NotNums);
	assert_eq!(refused(&|t| t["merkle_path"] = json!([base64(&[0x33; 32])])), FillError::MerklePath);
	assert!(matches!(refused(&|t| t["maker_prog_ver"] = json!(0)), FillError::Terms(m) if m.contains("version 1")));
	assert!(matches!(refused(&|t| t["asset_b"] = t["asset_a"].clone()), FillError::Terms(m) if m.contains("same asset")));
	assert!(matches!(refused(&|t| t["rate_den"] = json!("0")), FillError::Terms(_)));
	assert!(matches!(refused(&|t| t["maker_prog"] = json!(base64(&[1; 20]))), FillError::Terms(m) if m.contains("20 bytes")));
	assert!(matches!(refused(&|t| t["asset_a"] = json!("00ff")), FillError::Terms(_)));
	assert!(matches!(refused(&|t| { t.as_object_mut().unwrap().remove("covenant_txid"); }), FillError::Terms(m) if m.contains("missing")));
}

#[test]
fn a_plan_refuses_what_the_leaf_refuses() {
	let o = FillOrder { rate_num: 1, rate_den: 3, min_lot: 5, ..golden_order() };
	let p = o.plan(90, 90).unwrap();
	assert_eq!((p.filled, p.remainder, p.credit.value, p.rest.is_none()), (90, 0, 30, true));
	let p = o.plan(90, 10).unwrap();
	assert_eq!((p.remainder, p.credit.value), (80, 4));
	assert_eq!(p.rest.unwrap(), arca_covenant::ExplicitOutput::new(o.asset_a, 80, o.script_pubkey()));
	assert_eq!(p.credit.script_pubkey, o.maker_script_pubkey());
	for (filled, why) in [(4, "below the order's min_lot"), (87, "leaves 3 resting"), (91, "holding 90"), (0, "of an order")] {
		match o.plan(90, filled) {
			Err(FillError::Amount(m)) => assert!(m.contains(why), "{}: {}", filled, m),
			other => panic!("{}: {:?}", filled, other),
		}
	}
	// SeqDEX's dead-on-arrival order: 1e10 atoms against a coprime price.
	let dead = FillOrder { rate_num: 400_000_000_000, rate_den: 3, min_lot: 1, ..golden_order() };
	assert!(matches!(dead.plan(10_000_000_000, 10_000_000_000), Err(FillError::Arithmetic { .. })));
	assert_eq!(dead.price(10_000_000_000), None);
}

/// One verdict of the table.
struct Case {
	name: &'static str,
	tx: Transaction,
	prevouts: Vec<TxOut>,
	/// The covenant inputs: its order, its index, what it holds.
	covenants: Vec<(FillOrder, usize, u64)>,
	/// The input the case is about, and what the node says of it: `None`
	/// for valid, else a part of its error.
	at: usize,
	expect: Option<&'static str>,
}

fn blinded(asset: AssetId, value: u64, spk: Script) -> TxOut {
	let secp = Secp256k1::new();
	let tag = Tag::from(asset.into_inner().to_byte_array());
	let generator = Generator::new_blinded(&secp, tag, Tweak::from_slice(&[9; 32]).unwrap());
	TxOut { asset: Asset::Confidential(generator), value: Value::Explicit(value), nonce: Nonce::Null, script_pubkey: spk,
		witness: TxOutWitness::default() }
}

#[test]
fn the_node_and_the_check_agree_on_round_shaped_fills() {
	let verifier = Verifier::consensus(BlockHash::all_zeros());
	// Two orders selling X: the first wants Y, the second Z.
	let (x, y, z) = (asset("X"), asset("Y"), asset("Z"));
	let o1 = FillOrder { asset_a: x, asset_b: y, rate_num: 1, rate_den: 3, min_lot: 1_000, maker_prog: label32("maker 1"),
		expiry_locktime: 400, maker_x: xonly(&keypair("maker 1")).serialize() };
	let o2 = FillOrder { asset_a: x, asset_b: z, rate_num: 5, rate_den: 2, min_lot: 500, maker_prog: label32("maker 2"),
		expiry_locktime: 1_800_000_000, maker_x: xonly(&keypair("maker 2")).serialize() };
	let (l1, l2) = (90_000u64, 40_000u64);
	// Order 1 filled in part (60,000 of 90,000), order 2 in full.
	let p1 = o1.plan(l1, 60_000).unwrap();
	let p2 = o2.plan(l2, l2).unwrap();
	let batch = TapOutput::new(vec![(0, Script::from(vec![0x51, 0x87]))]).script_pubkey();
	let operator = Script::from(vec![0x00, 0x14].into_iter().chain([0xab; 20]).collect::<Vec<u8>>());
	let batch_out = explicit(x, 100_000 + 2_000, batch.clone());
	let gap = explicit(z, 1, operator.clone());
	let shape = |outs: Vec<TxOut>| {
		let mut s = Spend::new(0)
			.fake_input("order 1", explicit(x, l1, o1.script_pubkey()), 0xffff_ffff)
			.fake_input("order 2", explicit(x, l2, o2.script_pubkey()), 0xffff_ffff)
			.fake_input("operator coin", explicit(y, 1_000_000, operator.clone()), 0xffff_ffff)
			.outputs(outs);
		s.witness(0, o1.witness());
		s.witness(1, o2.witness());
		s
	};
	let good = vec![p1.credit.txout(), p1.rest.clone().unwrap().txout(), p2.credit.txout(), gap.clone(), batch_out.clone(),
		fee(y, 500)];
	let mut cases: Vec<Case> = vec![];
	let mut add = |name, outs: Vec<TxOut>, at, expect| {
		let s = shape(outs);
		cases.push(Case { name, tx: s.tx, prevouts: s.prevouts, covenants: vec![(o1.clone(), 0, l1), (o2.clone(), 1, l2)], at, expect });
	};
	add("order 1 at k=0 in part: credit at 0, remainder at 1", good.clone(), 0, None);
	add("order 2 at k=1 in full: credit at 2, another asset at 3, the batch at 4", good.clone(), 1, None);
	let mut v = good.clone();
	v[2] = explicit(z, p2.credit.value + 1_000, o2.maker_script_pubkey());
	add("order 2's credit paid over its price", v, 1, None);
	// Negatives.
	let mut v = good.clone();
	v.swap(2, 4);
	add("order 2's credit at the wrong index (4, the batch at 2)", v, 1, Some("OP_EQUALVERIFY"));
	let mut v = good.clone();
	v[3] = batch_out.clone();
	v[4] = gap.clone();
	add("a batch output in the order's asset at order 2's 2k+1 (3)", v, 1, Some("OP_EQUALVERIFY"));
	let mut v = good.clone();
	v[0] = explicit(y, p1.credit.value - 1, o1.maker_script_pubkey());
	add("order 1's credit one atom under its price", v, 0, Some("false/empty top stack"));
	let mut v = good.clone();
	v[2] = explicit(y, p2.credit.value, o2.maker_script_pubkey());
	add("order 2's credit in the wrong asset", v, 1, Some("OP_EQUALVERIFY"));
	let mut v = good.clone();
	v[2] = explicit(z, p2.credit.value, o1.maker_script_pubkey());
	add("order 2's credit to another maker's program", v, 1, Some("OP_EQUALVERIFY"));
	let mut v = good.clone();
	v[1] = explicit(x, 999, o1.script_pubkey());
	v[4] = explicit(x, 102_000 + 29_001, batch.clone());
	add("order 1's remainder below its min_lot", v, 0, Some("OP_VERIFY"));
	let mut v = good.clone();
	v[1] = explicit(x, 30_000, operator.clone());
	add("order 1's remainder to another script", v, 0, Some("OP_EQUALVERIFY"));
	let mut v = good.clone();
	v[3] = blinded(z, 1, operator.clone());
	add("an output hiding its asset at order 2's 2k+1", v, 1, Some("OP_EQUALVERIFY"));
	add("no output at order 2's 2k (2)", vec![p1.credit.txout(), p1.rest.clone().unwrap().txout()], 1, Some(""));
	// The rule's own empty case: no output at 2k+1 at all.
	let s = {
		let mut s = Spend::new(0).fake_input("order 2", explicit(x, l2, o2.script_pubkey()), 0xffff_ffff).output(p2.credit.txout());
		s.witness(0, o2.witness());
		s
	};
	cases.push(Case { name: "order 2 alone at k=0 in full, no output at 2k+1", tx: s.tx, prevouts: s.prevouts,
		covenants: vec![(o2.clone(), 0, l2)], at: 0, expect: None });

	println!("{:<70} | {}", "case", "verdict (node / check)");
	let (mut valid, mut refused) = (0, 0);
	for c in &cases {
		let node = verifier.verify_input(&c.prevouts, c.at, &c.tx);
		let (order, _, locked) = c.covenants.iter().find(|(_, k, _)| *k == c.at).expect("a covenant input").clone();
		let check = order.check(&c.tx, c.at, locked);
		match (&node, c.expect) {
			(Ok(()), None) => {
				let f = check.unwrap_or_else(|e| panic!("{}: the node takes it, the check refuses it: {}", c.name, e));
				println!("{:<70} | valid / fills {} rests {} credits {} for {}", c.name, f.filled, f.remainder, f.credited, f.price);
				valid += 1;
			},
			(Err(e), Some(part)) => {
				let msg = e.to_string();
				assert!(msg.contains(part), "{}: the node refuses it with {:?}, expected {:?}", c.name, msg, part);
				let why = check.err().unwrap_or_else(|| panic!("{}: the node refuses it ({}), the check takes it", c.name, msg));
				println!("{:<70} | {} / {}", c.name, msg, why);
				refused += 1;
			},
			(other, _) => panic!("{}: the node says {:?}, expected {:?}", c.name, other, c.expect),
		}
	}
	println!("{} valid, {} refused by the node's interpreter, the check agreeing on each", valid, refused);
	assert_eq!((valid, refused), (4, 9));
}
