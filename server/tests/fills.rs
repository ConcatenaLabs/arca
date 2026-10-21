//! A round that fills on-chain orders and pays takers as leaves, against a
//! whole server: orders made with SeqDEX's fill covenant rest on the chain
//! (their scripts derived by SeqDEX's own `seqob-covenant` when
//! `SEQOB_COVENANT_EXEC` names it), holders of other assets take them, and the
//! operator's round fills them under the covenant's rule: the order at input
//! `k` credited at output `2k`, resting again or holding another asset at
//! `2k+1`, the batch after them.
//!
//! - On an anchored proof-of-stake chain: a round fills two orders (one in
//!   part, one whole, paid in two assets), its input and output indices
//!   printed and checked against the rule and against SeqDEX's planner; the
//!   makers credited on the chain, the part left resting again under its
//!   identical script, the takers holding their leaves; an order filled by an
//!   outsider first drops out, its take answered with the reason; and the
//!   order left resting is filled again by a later round.
//! - On an anchored chain without proof of stake, where `generateblock`
//!   forces a transaction the mempool refuses into a block: the round with a
//!   credit at the wrong index, a batch output at a full fill's `2k+1`, and a
//!   credit one atom short, each re-signed by the operator so the covenant is
//!   the only input that fails, refused in a block by the covenant's script;
//!   and an order an outsider fills after the round was broadcast, which takes
//!   the round out: the round is lost, rebuilt without that order, and the
//!   other take completes in the round that replaces it.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::process::Command;
use std::str::FromStr;

use elements::encode::serialize;
use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Script, Transaction, TxIn};
use serde_json::{json, Value};

use arca_covenant::{ExplicitOutput, FillOrder};
use common::client::{auths_json, forfeit_sig, hex, take_body, unhex, want_leaf, Held};
use common::flow::forfeit_for;
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{created, round_final, status, validate_new_leaf};
use common::running::{Running, MIN_LEAF};
use sequentia_ext::{explicit_txout, fee_txout, AssetAmount};
use server::server::AssetSection;

/// The server: X sold by the orders and listed for fees, Y and Z the assets
/// they are paid in (Y's offboard fee 1,000 atoms), its wallet funded in all
/// three, final.
async fn start(plain: bool) -> (Running, AssetId) {
	let z_label = "asset Z";
	let tune = |c: &mut server::server::Config, y: AssetId| {
		let mut a = AssetSection::new(y, MIN_LEAF);
		a.offboard_base = Some("1000".into());
		c.assets.push(a);
	};
	let mut r = if plain { Running::start_plain(tune).await } else { Running::start_with(tune).await };
	let z = tokio::task::block_in_place(|| r.purse.issue(&r.rt, z_label, 100_000_000_000));
	r.config.assets.push(AssetSection::new(z, MIN_LEAF));
	r.server.reload(&r.config).await.unwrap();
	let (x, y) = (r.x, r.y);
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(y, 50_000_000).await;
	r.fund_wallet_in(z, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	(r, z)
}

/// An order's terms: it sells X for `pays` at `num`/`den`, refundable from
/// far ahead.
fn terms(r: &Running, maker: &str, pays: AssetId, num: u64, den: u64, min_lot: u64) -> FillOrder {
	let height = r.rt.client().blockchain_info().unwrap().blocks as u32;
	FillOrder {
		asset_a: r.x, asset_b: pays, rate_num: num, rate_den: den, min_lot,
		maker_prog: xonly(&keypair(&format!("{} payout", maker))).serialize(),
		expiry_locktime: height + 50_000,
		maker_x: xonly(&keypair(maker)).serialize(),
	}
}

fn order_flags(o: &FillOrder) -> Vec<String> {
	let a = |x: AssetId| hex(&arca_covenant::script::asset_bytes(x));
	[("-a", a(o.asset_a)), ("-b", a(o.asset_b)), ("-num", o.rate_num.to_string()), ("-den", o.rate_den.to_string()),
		("-minlot", o.min_lot.to_string()), ("-prog", hex(&o.maker_prog)), ("-expiry", o.expiry_locktime.to_string()),
		("-makerx", hex(&o.maker_x))].into_iter().flat_map(|(f, v)| [f.to_string(), v]).collect()
}

/// SeqDEX's `seqob-covenant`, when named, run with `args`.
fn seqdex(args: &[String]) -> Option<Value> {
	let exec = std::env::var("SEQOB_COVENANT_EXEC").ok()?;
	let out = Command::new(exec).args(args).output().expect("run seqob-covenant");
	assert!(out.status.success(), "seqob-covenant {:?}: {}", args, String::from_utf8_lossy(&out.stderr));
	Some(serde_json::from_slice(&out.stdout).unwrap())
}

/// Rests `locked` of X under `terms`, as a maker does, at the script SeqDEX's
/// own tool derives from the terms when it is named (and checked to be the
/// one `arca-covenant` derives), else at `arca-covenant`'s.
fn rest(r: &mut Running, terms: &FillOrder, locked: u64) -> OutPoint {
	let mut args = vec!["derive".to_string()];
	args.extend(order_flags(terms));
	let spk = match seqdex(&args) {
		Some(d) => {
			let spk = Script::from(unhex(d["scriptpubkey"].as_str().unwrap()));
			assert_eq!(spk, terms.script_pubkey(), "SeqDEX's script and arca-covenant's");
			println!("order made with SeqDEX's seqob-covenant: {}", d["scriptpubkey"]);
			spk
		},
		None => {
			println!("order made with arca-covenant's builder (SEQOB_COVENANT_EXEC names no seqob-covenant)");
			terms.script_pubkey()
		},
	};
	let tx = tokio::task::block_in_place(|| r.purse.pay(&r.rt, vec![explicit_txout(AssetAmount::new(r.x, locked), spk)]));
	OutPoint::new(tx.txid(), 0)
}

/// A transaction filling the whole order at `order` outside the operator,
/// as anyone may: the maker credited from the purse's coin, the order's X to
/// `OP_TRUE`, its change back to the purse.
fn outside_fill(r: &mut Running, terms: &FillOrder, order: OutPoint, locked: u64) -> Transaction {
	let plan = terms.plan(locked, locked).unwrap();
	let coin = r.purse.take_coin(terms.asset_b);
	let policy = r.purse.take_coin(r.purse.policy);
	let fee = 5_000;
	let mut tx = Transaction {
		version: 2, lock_time: elements::LockTime::ZERO,
		input: vec![
			TxIn { previous_output: order, ..Default::default() },
			TxIn { previous_output: coin.0, ..Default::default() },
			TxIn { previous_output: policy.0, ..Default::default() },
		],
		output: vec![
			plan.credit.txout(),
			explicit_txout(AssetAmount::new(terms.asset_b, coin.1.value.explicit().unwrap() - plan.credit.value), node::op_true()),
			explicit_txout(AssetAmount::new(r.x, locked), node::op_true()),
			explicit_txout(AssetAmount::new(r.purse.policy, policy.1.value.explicit().unwrap() - fee), node::op_true()),
			fee_txout(AssetAmount::new(r.purse.policy, fee)),
		],
	};
	tx.input[0].witness.script_witness = terms.witness();
	let txid = tx.txid();
	r.purse.put((OutPoint::new(txid, 1), tx.output[1].clone()));
	r.purse.put((OutPoint::new(txid, 3), tx.output[3].clone()));
	tx
}

/// A holder of `pays` with a coin of exactly `value`, credited.
async fn holder(r: &mut Running, label: &str, pays: AssetId, value: u64) -> (Held, Transaction) {
	let key = keypair(label);
	let (record, tx, _) = r.board_in(&key, pays, value);
	r.produce().await;
	r.bury().await;
	let id = record.leaf_id();
	let http = r.http.clone();
	r.wait("the board to be credited", || http.board_status(&id).json["state"] == "credited").await;
	(Held { key, nonce: record.owner_nonce, id, record: arca_covenant::CoinRecord::Board(record) }, tx)
}

/// A take, posted: `coin` given up for a leaf of `filled` of X under a fresh
/// key. Its id, the key and the leaf's nonce.
fn take(r: &Running, coin: &Held, order: OutPoint, terms: &FillOrder, locked: u64, filled: u64, fee: u64, label: &str)
	-> ([u8; 32], Keypair, [u8; 32])
{
	let key = keypair(&format!("{} new", label));
	let (w, nonce) = want_leaf(&key, r.x, filled);
	let (body, id) = take_body(&[coin], order, terms, locked, filled, &w, (terms.asset_b, fee), xonly(&r.s), r.chain);
	let a = r.http.post("take_order", &body);
	assert_eq!(a.status, 200, "{}: {}", label, a.json);
	println!("{}'s take {}: {} of order {}:{} ({} held) for {} of asset {}", label, hex(&id), filled, order.txid, order.vout, locked,
		terms.price(filled).unwrap(), terms.asset_b);
	(id, key, nonce)
}

/// The take `id`'s forfeits, handed over before its round is broadcast, as a
/// wallet hands them over: its new leaf rebuilt from the published tree and
/// validated against the round's transaction as the take's status serves it
/// (without witnesses, its txid the round's), the forfeit of the coin it
/// gave up signed against it. The server takes them and gives no preimage
/// yet.
fn hand_over(r: &Running, id: &[u8; 32], coin: &Held, bases: &[Transaction], key: &Keypair, nonce: &[u8; 32]) {
	let st = status(r, id);
	assert_eq!(st["state"], "issued", "{}", st);
	let round: Transaction = elements::encode::deserialize(&unhex(st["round"]["tx"].as_str().expect("the unbroadcast round's transaction")))
		.unwrap();
	assert_eq!(round.txid().to_string(), st["round"]["txid"].as_str().unwrap());
	assert!(round.input.iter().all(|i| i.witness.script_witness.is_empty()), "served without its witnesses");
	let o = &st["outputs"][0];
	let published = r.http.post("tree", &json!({"txid": st["round"]["txid"], "vout": o["batch_vout"]})).ok();
	let tree = common::client::rebuild(&published);
	let record = tree.record(o["leaf_index"].as_u64().unwrap() as usize);
	let new_valid = record.validate(&round, &common::rounds::accept_policy(r), &xonly(key), nonce).unwrap();
	let old = coin.record.resolve(bases, &r.policy()).unwrap();
	let f = forfeit_for(&old, &new_valid, &round, &st);
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(id),
		"forfeits": [{"leaf_id": coin.id.to_string(), "signature": forfeit_sig(&f, &coin.key)}],
		"leaves": [auths_json(&new_valid, key, created(&record))]})).ok();
	assert_eq!(done["state"], "issued", "{}", done);
	assert!(done.get("preimage").is_none(), "no preimage before the round is broadcast: {}", done);
	println!("  {}: forfeit handed over before round {} is broadcast; no preimage yet", hex(&id[..4]), round.txid());
}

/// Hands over every take's forfeits, runs the rounds' pass, and checks the
/// round `txid` went out.
async fn broadcast_after(r: &Running, txid: &elements::Txid, takes: &[(&[u8; 32], &Held, &[Transaction], &Keypair, &[u8; 32])]) {
	r.server.rounds.pass().await.unwrap();
	assert!(!node::in_mempool(&r.rt, txid), "not broadcast before the takes' forfeits");
	for (id, coin, bases, key, nonce) in takes {
		hand_over(r, id, coin, bases, key, nonce);
	}
	r.server.rounds.pass().await.unwrap();
	assert!(node::in_mempool(&r.rt, txid), "broadcast once every take's forfeits are in");
	println!("round {} broadcast once every take's forfeits were in", txid);
}

/// The take `id`, its round final, completed as a wallet completes it: its
/// new leaf validated from the published tree, the forfeit of the coin it
/// gave up signed against it, the preimage taken. Returns the leaf's value.
fn complete(r: &Running, id: &[u8; 32], coin: &Held, bases: &[Transaction], key: &Keypair, nonce: &[u8; 32]) -> u64 {
	let st = status(r, id);
	let (new_valid, record, round) = validate_new_leaf(r, id, 0, key, nonce);
	let old = coin.record.resolve(bases, &r.policy()).unwrap();
	let f = forfeit_for(&old, &new_valid, &round, &st);
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(id),
		"forfeits": [{"leaf_id": coin.id.to_string(), "signature": forfeit_sig(&f, &coin.key)}],
		"leaves": [auths_json(&new_valid, key, created(&record))]})).ok();
	assert_eq!(done["state"], "released", "{}", done);
	println!("  completed: its leaf {} holds {} of asset {} in round {} (batch output {}), preimage out", new_valid.leaf_id, record.value,
		record.asset, round.txid(), new_valid.batch_vout);
	record.value
}

/// Prints the round's inputs and outputs, each with its index.
fn print_round(r: &Running, tx: &Transaction, orders: &[(OutPoint, &FillOrder)]) {
	println!("round {} ({} vB): {} inputs, {} outputs", tx.txid(), tx.vsize(), tx.input.len(), tx.output.len());
	for (i, inp) in tx.input.iter().enumerate() {
		let what = match orders.iter().find(|(o, _)| *o == inp.previous_output) {
			Some((o, _)) => format!("order {}:{}, its FILL leaf and control block", o.txid, o.vout),
			None if inp.has_issuance() => "the operator's coin, issuing the batch's token".into(),
			None => "the operator's coin".into(),
		};
		println!("  input {}: {}", i, what);
	}
	for (j, o) in tx.output.iter().enumerate() {
		let (asset, value) = (o.asset.explicit().unwrap(), o.value.explicit().unwrap());
		let name = if asset == r.x { "X".to_string() } else if asset == r.y { "Y".into() } else { format!("{}", &asset.to_string()[..8]) };
		let what = if o.is_fee() { "the fee".to_string() } else {
			match orders.iter().find(|(_, t)| o.script_pubkey == t.maker_script_pubkey()) {
				Some((op, _)) => format!("credit to the maker of {}:{}", op.txid, op.vout),
				None => match orders.iter().find(|(_, t)| o.script_pubkey == t.script_pubkey()) {
					Some((op, _)) => format!("order {}:{} resting again", op.txid, op.vout),
					None => "".into(),
				},
			}
		};
		println!("  output {}: {} of {} {}", j, value, name, what);
	}
}

/// Checks the round against the rule: the order at input `k` with its FILL
/// witness, its credit at `2k`, the rest or another asset at `2k+1`, and no
/// output of the batch in the order's asset at any order's `2k+1`.
fn check_rule(tx: &Transaction, fills: &[(OutPoint, &FillOrder, u64, u64)], batch_vouts: &[u32]) {
	for (k, (op, t, locked, filled)) in fills.iter().enumerate() {
		assert_eq!(tx.input[k].previous_output, *op, "order {} at input {}", op, k);
		assert_eq!(tx.input[k].witness.script_witness, t.witness(), "input {}'s witness is the FILL leaf and its control block", k);
		let p = t.plan(*locked, *filled).unwrap();
		assert_eq!(ExplicitOutput::from_txout(&tx.output[2 * k]).unwrap(), p.credit, "the credit at {}", 2 * k);
		let at = ExplicitOutput::from_txout(&tx.output[2 * k + 1]).unwrap();
		match &p.rest {
			Some(rest) => assert_eq!(&at, rest, "the order resting again at {}", 2 * k + 1),
			None => assert_ne!(at.asset, t.asset_a, "a full fill holds another asset at {}", 2 * k + 1),
		}
		assert!(!batch_vouts.contains(&(2 * k as u32 + 1)), "no batch output at {}", 2 * k + 1);
		let f = t.check(tx, k, *locked).unwrap();
		assert_eq!((f.filled, f.remainder, f.credited), (*filled, locked - filled, p.credit.value));
		// SeqDEX's planner, at this k.
		let mut args = vec!["fill".to_string()];
		args.extend(order_flags(t));
		args.extend(["-locked".into(), locked.to_string(), "-filled".into(), filled.to_string(), "-k".into(), k.to_string()]);
		if let Some(plan) = seqdex(&args) {
			assert_eq!((plan["input_index"].as_u64(), plan["credit_index"].as_u64(), plan["remainder_index"].as_u64()),
				(Some(k as u64), Some(2 * k as u64), Some(2 * k as u64 + 1)));
			assert_eq!(plan["required_b"].as_u64(), Some(p.credit.value));
			assert_eq!(plan["remainder"].as_u64(), Some(locked - filled));
			println!("  SeqDEX's planner at k={}: credit at {}, remainder at {}, required {} , remainder {}: as the round has them", k,
				plan["credit_index"], plan["remainder_index"], plan["required_b"], plan["remainder"]);
		}
	}
	assert!(batch_vouts.iter().all(|v| *v >= 2 * fills.len() as u32), "the batches after the orders' outputs");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_round_fills_two_orders_and_pays_takers_as_leaves() {
	let (mut r, z) = start(false).await;
	let (x, y) = (r.x, r.y);
	// Three holders, of Y, Z and Y: one coin each, worth a take's price and fee.
	let (c1, b1) = holder(&mut r, "taker 1", y, 1_000_000).await;
	let (c2, b2) = holder(&mut r, "taker 2", z, 1_000_000).await;
	let (c3, _) = holder(&mut r, "taker 3", y, 1_000_000).await;
	// Order 1 sells 600,000 X at 2 Y each, by lots of 10,000; order 2 sells
	// 400,000 X at 2.5 Z each; order 3 sells 600,000 X at 2 Y each.
	let o1 = terms(&r, "maker 1", y, 2, 1, 10_000);
	let o2 = terms(&r, "maker 2", z, 5, 2, 1_000);
	let o3 = terms(&r, "maker 3", y, 2, 1, 10_000);
	let at1 = rest(&mut r, &o1, 600_000);
	let at2 = rest(&mut r, &o2, 400_000);
	let at3 = rest(&mut r, &o3, 600_000);
	r.produce().await;
	r.bury().await;
	r.synced().await;

	// Taker 1 takes 499,500 of order 1 (999,000 Y and a fee of 1,000),
	// taker 2 all of order 2 (1,000,000 Z, no fee), taker 3 499,500 of order 3.
	let (id1, k1, n1) = take(&r, &c1, at1, &o1, 600_000, 499_500, 1_000, "taker 1");
	let (id2, k2, n2) = take(&r, &c2, at2, &o2, 400_000, 400_000, 0, "taker 2");
	let (id3, _, _) = take(&r, &c3, at3, &o3, 600_000, 499_500, 1_000, "taker 3");

	// An outsider fills order 3 first: its transaction is in the mempool
	// when the round is built.
	let first = outside_fill(&mut r, &o3, at3, 600_000);
	r.rt.client().send_raw_transaction(&first).unwrap();
	println!("an outsider fills order 3 first: {}", first.txid());

	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	assert_eq!(built.len(), 1, "one fill round of X");
	let b = &built[0];
	let tx = b.tx.clone();
	print_round(&r, &tx, &[(at1, &o1), (at2, &o2)]);
	assert_eq!(b.fills, vec![at1, at2]);
	assert_eq!(b.batches, vec![(x, 4, 2)], "the batch after the orders' four outputs, holding both takers' leaves");
	check_rule(&tx, &[(at1, &o1, 600_000, 499_500), (at2, &o2, 400_000, 400_000)], &[4]);
	println!("built: {}", b.broadcast);
	broadcast_after(&r, &tx.txid(), &[(&id1, &c1, &[b1.clone()], &k1, &n1), (&id2, &c2, &[b2.clone()], &k2, &n2)]).await;
	let st3 = status(&r, &id3);
	println!("taker 3's take: {} — {}", st3["state"], st3["void_reason"]);
	assert_eq!(st3["state"], "void");
	assert!(st3["void_reason"].as_str().unwrap().contains("a round fills an order only while it rests unspent"));
	assert_eq!(st3["inputs"][0]["returned"], true, "its coin is its owner's again");

	// Final: the makers credited on the chain at 2k, order 1's rest resting
	// again at 1 under its own script, order 2 spent whole.
	r.produce().await;
	r.bury().await;
	round_final(&r, &tx.txid()).await;
	let maker1 = o1.maker_script_pubkey();
	assert_eq!((tx.output[0].script_pubkey.clone(), tx.output[0].asset.explicit(), tx.output[0].value.explicit()),
		(maker1, Some(y), Some(999_000)));
	assert_eq!((tx.output[2].script_pubkey.clone(), tx.output[2].asset.explicit(), tx.output[2].value.explicit()),
		(o2.maker_script_pubkey(), Some(z), Some(1_000_000)));
	let rest_at = OutPoint::new(tx.txid(), 1);
	assert!(r.unspent(&rest_at) && r.unspent(&OutPoint::new(tx.txid(), 0)) && r.unspent(&OutPoint::new(tx.txid(), 2)));
	assert!(!r.unspent(&at1) && !r.unspent(&at2));
	println!("final: maker 1 credited 999000 Y at output 0, maker 2 1000000 Z at output 2; order 1's 100500 X rest again at {}:1",
		tx.txid());
	let s1 = status(&r, &id1);
	println!("taker 1's take in the round: {}", s1["fill"]);
	assert_eq!((s1["fill"]["input"].as_u64(), s1["fill"]["credit_vout"].as_u64(), s1["fill"]["remainder_vout"].as_u64()),
		(Some(0), Some(0), Some(1)));
	assert_eq!(status(&r, &id2)["fill"]["input"], 1);

	// The takers hold their leaves.
	assert_eq!(complete(&r, &id1, &c1, &[b1.clone()], &k1, &n1), 499_500);
	assert_eq!(complete(&r, &id2, &c2, &[b2.clone()], &k2, &n2), 400_000);

	// What rests of order 1 is an order again: a later round fills 50,000
	// of it, at k = 0, leaving 50,500 resting.
	let (c4, b4) = holder(&mut r, "taker 4", y, 101_000).await;
	let (id4, k4, n4) = take(&r, &c4, rest_at, &o1, 100_500, 50_000, 1_000, "taker 4");
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	let again = built[0].tx.clone();
	print_round(&r, &again, &[(rest_at, &o1)]);
	check_rule(&again, &[(rest_at, &o1, 100_500, 50_000)], &[2]);
	broadcast_after(&r, &again.txid(), &[(&id4, &c4, &[b4.clone()], &k4, &n4)]).await;
	r.produce().await;
	r.bury().await;
	round_final(&r, &again.txid()).await;
	assert_eq!(complete(&r, &id4, &c4, &[b4.clone()], &k4, &n4), 50_000);
	assert!(r.unspent(&OutPoint::new(again.txid(), 1)));
	println!("order 1 rests again with 50500 X at {}:1", again.txid());
}

/// The round `tx`, its outputs changed by `change`, every input of the
/// operator's signed again over it: the covenant inputs keep their witnesses,
/// so the only input a changed output can fail is a covenant's.
async fn variant(r: &Running, tx: &Transaction, orders: usize, change: impl FnOnce(&mut Vec<elements::TxOut>)) -> Transaction {
	let mut t = tx.clone();
	change(&mut t.output);
	for i in orders..t.input.len() {
		let op = t.input[i].previous_output;
		let coin = r.server.store.wallet_coin_at(&op.txid.to_byte_array(), op.vout).await.unwrap().expect("an operator's coin");
		r.server.wallet.sign_input(&mut t, i, &coin).unwrap();
	}
	t
}

/// Forces `tx` into a block with `generateblock`: refused, for `expect`.
fn refused_in_block(r: &Running, what: &str, tx: &Transaction, expect: &str) {
	let h0 = r.rt.client().block_count().unwrap();
	let e = match r.rt.client().generate_block("raw(51)", &[tx]) {
		Ok(h) => panic!("{}: MINED in block {}", what, h),
		Err(e) => e.to_string(),
	};
	assert_eq!(r.rt.client().block_count().unwrap(), h0);
	println!("{}: refused in a block: {}", what, e);
	assert!(e.contains(expect), "{}: refused with {:?}, expected {:?}", what, e, expect);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_covenant_refuses_a_wrong_round_in_a_block_and_an_order_taken_after_broadcast_drops_out() {
	let (mut r, z) = start(true).await;
	let y = r.y;
	let (c1, b1) = holder(&mut r, "taker 1", y, 1_000_000).await;
	let (c2, b2) = holder(&mut r, "taker 2", z, 1_000_000).await;
	let (c3, b3) = holder(&mut r, "taker 3", y, 1_000_000).await;
	let (c4, b4) = holder(&mut r, "taker 4", z, 1_000_000).await;
	let o1 = terms(&r, "maker 1", y, 2, 1, 10_000);
	let o2 = terms(&r, "maker 2", z, 5, 2, 1_000);
	let o3 = terms(&r, "maker 3", y, 2, 1, 10_000);
	let o4 = terms(&r, "maker 4", z, 5, 2, 1_000);
	let at1 = rest(&mut r, &o1, 600_000);
	let at2 = rest(&mut r, &o2, 400_000);
	let at3 = rest(&mut r, &o3, 600_000);
	let at4 = rest(&mut r, &o4, 400_000);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let (id1, k1, n1) = take(&r, &c1, at1, &o1, 600_000, 499_500, 1_000, "taker 1");
	let (id2, k2, n2) = take(&r, &c2, at2, &o2, 400_000, 400_000, 0, "taker 2");
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	let tx = built[0].tx.clone();
	print_round(&r, &tx, &[(at1, &o1), (at2, &o2)]);
	check_rule(&tx, &[(at1, &o1, 600_000, 499_500), (at2, &o2, 400_000, 400_000)], &[4]);

	// The round re-signed unchanged is the round: signing again changes no
	// byte, so a variant differs from it only where it is changed.
	let same = variant(&r, &tx, 2, |_| {}).await;
	assert_eq!(serialize(&same), serialize(&tx), "signing again changes nothing");

	// Order 2's credit at the wrong index: swapped with the batch output.
	let v1 = variant(&r, &tx, 2, |o| o.swap(2, 4)).await;
	println!("  check: {}", o2.check(&v1, 1, 400_000).unwrap_err());
	refused_in_block(&r, "order 2's credit at the wrong index (4), the batch at 2", &v1,
		"TestBlockValidity failed: mempool-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)");
	// The batch output, in X, at order 2's 2k+1, where the full fill put Z.
	let v2 = variant(&r, &tx, 2, |o| o.swap(3, 4)).await;
	println!("  check: {}", o2.check(&v2, 1, 400_000).unwrap_err());
	refused_in_block(&r, "a batch output at order 2's 2k+1 (3)", &v2,
		"TestBlockValidity failed: mempool-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)");
	// Order 1's credit one atom short, the atom to the operator's change in Y.
	let change_y = tx.output.iter().enumerate().skip(6)
		.position(|(_, o)| o.asset.explicit() == Some(y) && !o.is_fee()).map(|p| p + 6).expect("the operator's change in Y");
	let v3 = variant(&r, &tx, 2, |o| {
		o[0].value = elements::confidential::Value::Explicit(o[0].value.explicit().unwrap() - 1);
		o[change_y].value = elements::confidential::Value::Explicit(o[change_y].value.explicit().unwrap() + 1);
	}).await;
	println!("  check: {}", o1.check(&v3, 0, 600_000).unwrap_err());
	refused_in_block(&r, "order 1's credit one atom under its price", &v3,
		"TestBlockValidity failed: mempool-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)");
	// And the round itself, its takes' forfeits in, forced the same way:
	// taken in a block.
	broadcast_after(&r, &tx.txid(), &[(&id1, &c1, &[b1.clone()], &k1, &n1), (&id2, &c2, &[b2.clone()], &k2, &n2)]).await;
	let h = r.rt.client().generate_block("raw(51)", &[&tx]).unwrap();
	println!("the round itself, forced the same way: mined in block {}", h);
	r.bury().await;
	round_final(&r, &tx.txid()).await;
	assert_eq!(complete(&r, &id1, &c1, &[b1.clone()], &k1, &n1), 499_500);
	assert_eq!(complete(&r, &id2, &c2, &[b2.clone()], &k2, &n2), 400_000);

	// A second round, orders 3 and 4, broadcast; an outsider then fills
	// order 4 and its transaction reaches a block first: the round cannot
	// confirm.
	let (id3, k3, n3) = take(&r, &c3, at3, &o3, 600_000, 499_500, 1_000, "taker 3");
	let (id4, k4, n4) = take(&r, &c4, at4, &o4, 400_000, 400_000, 0, "taker 4");
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	let second = built[0].tx.clone();
	print_round(&r, &second, &[(at3, &o3), (at4, &o4)]);
	check_rule(&second, &[(at3, &o3, 600_000, 499_500), (at4, &o4, 400_000, 400_000)], &[4]);
	broadcast_after(&r, &second.txid(), &[(&id3, &c3, &[b3.clone()], &k3, &n3), (&id4, &c4, &[b4.clone()], &k4, &n4)]).await;
	let outsider = outside_fill(&mut r, &o4, at4, 400_000);
	r.rt.client().generate_block("raw(51)", &[&outsider]).unwrap();
	println!("an outsider's fill of order 4 ({}) is in a block; the round {} cannot confirm", outsider.txid(), second.txid());
	r.bury().await;
	r.synced().await;
	// The nursery finds the round lost, the rounds' pass retires it, and the
	// next round runs taker 3's take again without order 4.
	let store = r.server.store.clone();
	let t = second.txid().to_byte_array();
	let start = std::time::Instant::now();
	loop {
		r.server.nursery.pass().await.unwrap();
		r.server.rounds.pass().await.unwrap();
		if store.round_by_txid(&t).await.unwrap().map(|x| x.state) == Some(server::store::RoundState::Lost) {
			break;
		}
		assert!(start.elapsed() < std::time::Duration::from_secs(60), "the round was not found lost");
		tokio::time::sleep(std::time::Duration::from_millis(200)).await;
	}
	println!("round {} is lost: an input of it is spent by a final transaction", second.txid());
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	let again = built[0].tx.clone();
	print_round(&r, &again, &[(at3, &o3)]);
	check_rule(&again, &[(at3, &o3, 600_000, 499_500)], &[2]);
	broadcast_after(&r, &again.txid(), &[(&id3, &c3, &[b3.clone()], &k3, &n3)]).await;
	let st4 = status(&r, &id4);
	println!("taker 4's take: {} — {}", st4["state"], st4["void_reason"]);
	assert_eq!(st4["state"], "void");
	assert!(st4["void_reason"].as_str().unwrap().contains("is spent"));
	// Its forfeit was handed over for the round that went out of the chain,
	// which could still return with the parent chain: its coin stays given
	// up, its owner's on the chain, as for any participation of a lost round.
	assert_eq!(st4["inputs"][0]["returned"], false, "its coin stays given up, its owner's on the chain");
	assert_eq!(status(&r, &id3)["attempt"], 1, "taker 3's take runs again");
	r.produce().await;
	r.bury().await;
	round_final(&r, &again.txid()).await;
	assert_eq!(complete(&r, &id3, &c3, &[b3.clone()], &k3, &n3), 499_500);
	assert!(r.unspent(&OutPoint::new(again.txid(), 1)), "order 3 rests again");
}

/// A take that hands over no forfeits: its round is never broadcast, so no
/// maker is paid for it. Past the window the round is dropped unbroadcast,
/// the silent take voided, and the take that did hand its forfeits over runs
/// again in the round built after it, without the other, and completes.
#[tokio::test(flavor = "multi_thread")]
async fn a_take_that_hands_over_no_forfeits_gets_no_maker_paid() {
	let (mut r, z) = start(false).await;
	let y = r.y;
	let (c1, b1) = holder(&mut r, "taker 1", y, 1_000_000).await;
	let (c2, _) = holder(&mut r, "taker 2", z, 1_000_000).await;
	let o1 = terms(&r, "maker 1", y, 2, 1, 10_000);
	let o2 = terms(&r, "maker 2", z, 5, 2, 1_000);
	let at1 = rest(&mut r, &o1, 600_000);
	let at2 = rest(&mut r, &o2, 400_000);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let pool = |r: &Running| {
		let (store, y, z) = (r.server.wallet.clone(), y, z);
		async move { let b = store.balance().await.unwrap(); (b.get(&y).copied().unwrap_or(0), b.get(&z).copied().unwrap_or(0)) }
	};
	let before = pool(&r).await;
	let (id1, k1, n1) = take(&r, &c1, at1, &o1, 600_000, 499_500, 1_000, "taker 1");
	let (id2, _, _) = take(&r, &c2, at2, &o2, 400_000, 400_000, 0, "taker 2");
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	let tx = built[0].tx.clone();
	println!("built {}: {}", tx.txid(), built[0].broadcast);
	// Taker 1 hands its forfeits over; taker 2 hands over nothing.
	hand_over(&r, &id1, &c1, &[b1.clone()], &k1, &n1);
	r.server.rounds.pass().await.unwrap();
	assert!(!node::in_mempool(&r.rt, &tx.txid()), "held while taker 2's forfeits are missing");
	println!("round {} held: taker 2 has handed over no forfeits", tx.txid());
	// The window passes: the round is dropped unbroadcast.
	common::rounds::advance_mtp(&r, 700).await;
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	let row = r.server.store.round_by_txid(&tx.txid().to_byte_array()).await.unwrap().unwrap();
	assert_eq!(row.state, server::store::RoundState::Lost);
	assert!(!node::in_mempool(&r.rt, &tx.txid()) && r.unspent(&at1) && r.unspent(&at2), "never broadcast; both orders rest");
	let st2 = status(&r, &id2);
	println!("taker 2's take: {} — {}", st2["state"], st2["void_reason"]);
	assert_eq!(st2["state"], "void");
	assert!(st2["void_reason"].as_str().unwrap().contains("its forfeits did not come within 600 s"));
	assert_eq!(st2["inputs"][0]["returned"], true);
	assert_eq!(pool(&r).await, before, "the operator paid no maker");
	println!("no maker paid: the operator's pools of Y and Z are {:?}, as before", before);
	// Taker 1 runs again, alone, and completes.
	assert_eq!(status(&r, &id1)["state"], "pending");
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	let again = built[0].tx.clone();
	print_round(&r, &again, &[(at1, &o1)]);
	check_rule(&again, &[(at1, &o1, 600_000, 499_500)], &[2]);
	broadcast_after(&r, &again.txid(), &[(&id1, &c1, &[b1.clone()], &k1, &n1)]).await;
	r.produce().await;
	r.bury().await;
	round_final(&r, &again.txid()).await;
	assert_eq!(complete(&r, &id1, &c1, &[b1], &k1, &n1), 499_500);
	assert!(r.unspent(&at2), "order 2 still rests, unpaid");
}

/// The operator's spendable pools of `a` and `b`.
async fn pools(r: &Running, a: AssetId, b: AssetId) -> (u64, u64) {
	let bal = r.server.wallet.balance().await.unwrap();
	(bal.get(&a).copied().unwrap_or(0), bal.get(&b).copied().unwrap_or(0))
}

/// [`hand_over`], when the take `id` is still issued in its unbroadcast
/// round: whether its forfeits went in. A take whose round the server has
/// dropped meanwhile hands nothing over.
fn hand_over_if_held(r: &Running, id: &[u8; 32], coin: &Held, bases: &[Transaction], key: &Keypair, nonce: &[u8; 32]) -> bool {
	let st = status(r, id);
	if st["state"] != "issued" || st["round"]["tx"].as_str().is_none() {
		println!("  {}: nothing to hand over, the take is {}", hex(&id[..4]), st["state"]);
		return false;
	}
	let round: Transaction = elements::encode::deserialize(&unhex(st["round"]["tx"].as_str().unwrap())).unwrap();
	let o = &st["outputs"][0];
	let published = r.http.post("tree", &json!({"txid": st["round"]["txid"], "vout": o["batch_vout"]})).ok();
	let tree = common::client::rebuild(&published);
	let record = tree.record(o["leaf_index"].as_u64().unwrap() as usize);
	let new_valid = record.validate(&round, &common::rounds::accept_policy(r), &xonly(key), nonce).unwrap();
	let old = coin.record.resolve(bases, &r.policy()).unwrap();
	let f = forfeit_for(&old, &new_valid, &round, &st);
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(id),
		"forfeits": [{"leaf_id": coin.id.to_string(), "signature": forfeit_sig(&f, &coin.key)}],
		"leaves": [auths_json(&new_valid, key, created(&record))]}));
	println!("  {}: forfeits handed over for round {}: {} {}", hex(&id[..4]), round.txid(), done.status, done.json["state"]);
	done.status == 200
}

/// The coin of the operator's among the inputs of `tx` past its `orders`
/// order inputs that the wallet has spent since in another transaction, and
/// that transaction.
async fn spent_otherwise(r: &Running, tx: &Transaction, orders: usize) -> Option<(OutPoint, elements::Txid)> {
	let mut found = None;
	for i in tx.input.iter().skip(orders) {
		let op = i.previous_output;
		let Some(c) = r.server.store.wallet_coin_at(&op.txid.to_byte_array(), op.vout).await.unwrap() else { continue };
		if let Some(by) = c.spent_by.filter(|b| *b != tx.txid().to_byte_array()) {
			assert!(found.is_none(), "one coin of the dropped round is spent, not two");
			found = Some((op, elements::Txid::from_byte_array(by)));
		}
	}
	found
}

/// The round `tx`, dropped unbroadcast, can never confirm: the transaction
/// of the operator's wallet spending one of its coins is final, and the node
/// refuses the round for that input.
async fn dead_on_the_chain(r: &Running, tx: &Transaction, orders: usize) -> elements::Txid {
	let (coin, by) = spent_otherwise(r, tx, orders).await.expect("one of the dropped round's own coins is spent");
	let start = std::time::Instant::now();
	loop {
		r.produce().await;
		r.bury().await;
		r.synced().await;
		if r.server.finality.status(&by).await.unwrap().is_final() {
			break;
		}
		assert!(start.elapsed() < std::time::Duration::from_secs(120), "the spend of coin {} never became final", coin);
	}
	let spender: Transaction = r.rt.client().raw_transaction(&by).unwrap();
	assert!(spender.input.iter().any(|i| i.previous_output == coin), "{} spends {}", by, coin);
	assert!(!r.unspent(&coin));
	let (ok, why, _) = tokio::task::block_in_place(|| r.server.finality.source().test_accept(tx)).unwrap();
	println!("round {} can never confirm: its coin {} is spent by {} ({} input(s), {} output(s)), final; the node on the round: {} {:?}",
		tx.txid(), coin, by, spender.input.len(), spender.output.len(), ok, why);
	assert!(!ok);
	let why = why.unwrap_or_default();
	assert!(why.contains("missing-inputs") || why.contains("bad-txns-inputs-missingorspent"), "{}", why);
	by
}

/// R7l's F4 probe, turned around (D73): two takes in one fill round; while
/// the round is held for their forfeits, an outsider fills take 1's order on
/// the chain, and both takes then hand their forfeits over, as far as the
/// server still takes them. The round is never put to the node: before it
/// goes out its orders are checked again at the node, and the spent one
/// drops the round unbroadcast, voids take 1 with the reason and runs take 2
/// again. One of the round's own coins is spent at once in a transaction of
/// the operator's wallet, so the dropped round can never confirm. The
/// operator's pools are free, take 2 completes in the round built after it,
/// a refresh in Y runs, and a restart undoes none of it.
#[tokio::test(flavor = "multi_thread")]
async fn an_order_spent_while_its_round_is_held_drops_the_round() {
	let (mut r, z) = start(false).await;
	let y = r.y;
	let (c1, b1) = holder(&mut r, "held taker 1", y, 1_000_000).await;
	let (c2, b2) = holder(&mut r, "held taker 2", z, 1_000_000).await;
	let (c3, _) = holder(&mut r, "held refresher", y, 500_000).await;
	let o1 = terms(&r, "held maker 1", y, 2, 1, 10_000);
	let o2 = terms(&r, "held maker 2", z, 5, 2, 1_000);
	let at1 = rest(&mut r, &o1, 600_000);
	let at2 = rest(&mut r, &o2, 400_000);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let before = pools(&r, y, z).await;
	let (id1, k1, n1) = take(&r, &c1, at1, &o1, 600_000, 499_500, 1_000, "held taker 1");
	let (id2, k2, n2) = take(&r, &c2, at2, &o2, 400_000, 400_000, 0, "held taker 2");
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	let tx = built[0].tx.clone();
	println!("round built {}: {}", tx.txid(), built[0].broadcast);

	// The outsider fills order 1 while the round is held.
	let out = outside_fill(&mut r, &o1, at1, 600_000);
	r.rt.client().send_raw_transaction(&out).unwrap();
	println!("an outsider fills order 1 while the round is held: {}", out.txid());
	r.produce().await;
	r.bury().await;
	r.synced().await;
	hand_over_if_held(&r, &id1, &c1, &[b1.clone()], &k1, &n1);
	hand_over_if_held(&r, &id2, &c2, &[b2.clone()], &k2, &n2);
	r.server.rounds.pass().await.unwrap();
	let row = r.server.store.round_by_txid(&tx.txid().to_byte_array()).await.unwrap().unwrap();
	let nursery = r.server.store.nursery_get(&tx.txid().to_byte_array()).await.unwrap().map(|n| (n.state, n.last_result));
	println!("after a pass: round {:?} | in the mempool {} | the nursery {:?}", row.state, node::in_mempool(&r.rt, &tx.txid()), nursery);
	assert_eq!(row.state, server::store::RoundState::Lost, "the round is dropped, not broadcast");
	assert!(nursery.is_none(), "never handed to the node");
	assert!(!node::in_mempool(&r.rt, &tx.txid()));
	let st1 = status(&r, &id1);
	println!("take 1: {} — {}", st1["state"], st1["void_reason"]);
	assert_eq!(st1["state"], "void");
	let why = st1["void_reason"].as_str().unwrap();
	assert!(why.contains("is spent") && why.contains("dropped unbroadcast"), "{}", why);
	assert_eq!(st1["inputs"][0]["returned"], true, "no forfeit of it can confirm: the coin is its owner's again");
	let st2 = status(&r, &id2);
	println!("take 2: {} (attempt {})", st2["state"], st2["attempt"]);
	assert_eq!(st2["state"], "pending");
	assert_eq!(st2["attempt"], 1, "take 2 runs again");
	assert_eq!(r.server.store.forfeit_count(&id1, row.round_id).await.unwrap().1, 0, "the signer was asked for nothing");
	let (coin, kill) = spent_otherwise(&r, &tx, 2).await.expect("one of the dropped round's own coins is spent at once");
	println!("the dropped round's coin {} is spent by {} (in the mempool {})", coin, kill, node::in_mempool(&r.rt, &kill));
	assert!(node::in_mempool(&r.rt, &kill));

	// A restart before that spend confirms: the round stays dropped, and its
	// coin is spent once, not twice.
	r.restart_server().await;
	r.synced().await;
	r.server.nursery.pass().await.unwrap();
	r.server.rounds.pass().await.unwrap();
	let row = r.server.store.round_by_txid(&tx.txid().to_byte_array()).await.unwrap().unwrap();
	assert_eq!(row.state, server::store::RoundState::Lost);
	assert_eq!(spent_otherwise(&r, &tx, 2).await.map(|(_, t)| t), Some(kill), "after a restart, the same spend");
	assert_eq!(dead_on_the_chain(&r, &tx, 2).await, kill);

	// Take 2 runs again, alone, and completes.
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	let again = built[0].tx.clone();
	assert_eq!(built[0].fills, vec![at2]);
	print_round(&r, &again, &[(at2, &o2)]);
	check_rule(&again, &[(at2, &o2, 400_000, 400_000)], &[2]);
	broadcast_after(&r, &again.txid(), &[(&id2, &c2, &[b2.clone()], &k2, &n2)]).await;
	r.produce().await;
	r.bury().await;
	round_final(&r, &again.txid()).await;
	assert_eq!(complete(&r, &id2, &c2, &[b2.clone()], &k2, &n2), 400_000);

	// The operator's Y is free and whole: nothing of it went out.
	let after = pools(&r, y, z).await;
	println!("the operator's pools of Y and Z: before {:?} | after {:?}", before, after);
	assert_eq!(after.0, before.0, "the operator's Y is free and whole");
	// A refresh in Y runs.
	let (w3, _) = want_leaf(&keypair("held refresher new"), y, 500_000);
	let (body, pid3) = common::client::participation_body(&[&c3], &[w3], &[], None, xonly(&r.s), r.chain);
	let a = r.http.post("submit_participation", &body);
	assert_eq!(a.status, 200, "{}", a.json);
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	println!("a refresh of Y: built {:?} | failed {:?} | the refresh {}", built.iter().map(|b| b.tx.txid()).collect::<Vec<_>>(), failed,
		status(&r, &pid3)["state"]);
	assert!(failed.is_empty(), "{:?}", failed);
	assert_eq!(status(&r, &pid3)["state"], "issued", "the refresh of Y runs");
}

/// A fill round an older server left broadcast and refused by the node: an
/// outsider filled its order while it was held, before anything watched the
/// order's outpoint, and that server put it to the node anyway (D73's
/// second half, R7l's stuck state). The order is looked up at the node and
/// the round retired as lost: the nursery gives it up, the take whose order
/// was taken is voided (its coin, whose forfeit it handed over, stays given
/// up), the other runs again and completes, and the operator's pools are
/// free. The signer is asked for no half of a forfeit for a round the node
/// does not hold.
#[tokio::test(flavor = "multi_thread")]
async fn a_fill_round_the_node_refused_for_a_taken_order_is_retired_as_lost() {
	refused_round(false).await;
}

/// [`a_fill_round_the_node_refused_for_a_taken_order_is_retired_as_lost`],
/// with take 1's forfeit whole, as an older server's signer left it.
#[tokio::test(flavor = "multi_thread")]
async fn a_fill_round_refused_with_a_forfeit_whole_is_retired_as_lost() {
	refused_round(true).await;
}

async fn refused_round(whole: bool) {
	let (mut r, z) = start(false).await;
	let y = r.y;
	let (c1, b1) = holder(&mut r, "refused taker 1", y, 1_000_000).await;
	let (c2, b2) = holder(&mut r, "refused taker 2", z, 1_000_000).await;
	let o1 = terms(&r, "refused maker 1", y, 2, 1, 10_000);
	let o2 = terms(&r, "refused maker 2", z, 5, 2, 1_000);
	let at1 = rest(&mut r, &o1, 600_000);
	let at2 = rest(&mut r, &o2, 400_000);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let before = pools(&r, y, z).await;
	let (id1, k1, n1) = take(&r, &c1, at1, &o1, 600_000, 499_500, 1_000, "refused taker 1");
	let (id2, k2, n2) = take(&r, &c2, at2, &o2, 400_000, 400_000, 0, "refused taker 2");
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	let tx = built[0].tx.clone();
	let round_id = built[0].round_id;
	assert!(hand_over_if_held(&r, &id1, &c1, &[b1.clone()], &k1, &n1));

	// The server stops; an outsider fills order 1, final; the database is
	// left as an older server left it: the round broadcast, the node's
	// refusal recorded, and (`whole`) take 1's forfeit given an operator's
	// half.
	r.server.stop();
	let out = outside_fill(&mut r, &o1, at1, 600_000);
	r.rt.client().send_raw_transaction(&out).unwrap();
	r.produce().await;
	r.bury().await;
	let store = r.db.store.clone();
	assert!(store.set_round_state(round_id, server::store::RoundState::Built, server::store::RoundState::Broadcast).await.unwrap());
	// Handed to the nursery after the outsider's spend was scanned: the
	// store's index of spends never sees it (none of its inputs is watched
	// from before that block).
	let fee = tx.output.iter().find(|o| o.is_fee()).unwrap();
	store.nursery_insert(&tx.txid().to_byte_array(), &serialize(&tx), "round",
		Some((fee.asset.explicit().unwrap().into_inner().to_byte_array(), fee.value.explicit().unwrap())), &[]).await.unwrap();
	store.nursery_broadcast(&tx.txid().to_byte_array(), "the node refused it: bad-txns-inputs-missingorspent").await.unwrap();
	if whole {
		store.set_forfeit_operator_sig(&c1.id.0, round_id, &[7; 64]).await.unwrap();
	}
	println!("left as an older server leaves it: round {} broadcast and refused, take 1's forfeit {}", tx.txid(),
		if whole { "whole" } else { "the owner's half" });
	r.restart_server().await;
	r.synced().await;

	// No half of a forfeit is asked of the signer while the node does not
	// hold the round (the server asks for missing halves at its start, and
	// every minute).
	r.server.forfeits.fill_unsigned().await.unwrap();
	let counted = r.server.store.forfeit_count(&id1, round_id).await.unwrap();
	println!("take 1's forfeits for the refused round (coins, whole, owner's half only): {:?}", counted);
	if !whole {
		assert_eq!(counted.1, 0, "the signer gave no half for a round the node does not hold");
	}
	let start = std::time::Instant::now();
	loop {
		r.server.nursery.pass().await.unwrap();
		r.server.rounds.pass().await.unwrap();
		let row = r.server.store.round_by_txid(&tx.txid().to_byte_array()).await.unwrap().unwrap();
		if row.state == server::store::RoundState::Lost {
			break;
		}
		assert!(start.elapsed() < std::time::Duration::from_secs(120), "the refused round was never resolved: {:?}", row.state);
		r.produce().await;
		r.bury().await;
		r.synced().await;
	}
	let nursery = r.server.store.nursery_get(&tx.txid().to_byte_array()).await.unwrap().unwrap();
	println!("round {} lost | the nursery {:?}: {:?}", tx.txid(), nursery.state, nursery.last_result);
	assert_eq!(nursery.state, server::store::NurseryState::Lost, "never broadcast again");
	// Lost like any round: its takes run again, and take 1's order is found
	// spent when its round is built.
	let (_, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	let st1 = status(&r, &id1);
	println!("take 1: {} — {} | its coin returned: {}", st1["state"], st1["void_reason"], st1["inputs"][0]["returned"]);
	assert_eq!(st1["state"], "void");
	assert!(st1["void_reason"].as_str().unwrap().contains("is spent"));
	assert_eq!(st1["inputs"][0]["returned"], false, "a coin whose forfeit was handed over stays given up, as for any lost round");
	let st2 = status(&r, &id2);
	println!("take 2: {} (attempt {})", st2["state"], st2["attempt"]);
	assert!(st2["attempt"].as_u64().unwrap() >= 1, "take 2 runs again");
	// Take 2 completes.
	if st2["state"] == "pending" {
		let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
		assert!(failed.is_empty(), "{:?}", failed);
		assert_eq!(built[0].fills, vec![at2]);
	}
	let again = elements::Txid::from_str(status(&r, &id2)["round"]["txid"].as_str().unwrap()).unwrap();
	broadcast_after(&r, &again, &[(&id2, &c2, &[b2.clone()], &k2, &n2)]).await;
	r.produce().await;
	r.bury().await;
	round_final(&r, &again).await;
	assert_eq!(complete(&r, &id2, &c2, &[b2.clone()], &k2, &n2), 400_000);
	let after = pools(&r, y, z).await;
	println!("the operator's pools of Y and Z: before {:?} | after {:?}", before, after);
	assert_eq!(after.0, before.0, "the operator's Y is free and whole");
}

/// A fill round the node holds while the server's record still has it
/// built: the server stopped after handing the round to the node and before
/// recording it as broadcast (or another pass handed it over meanwhile).
/// Its orders are spent, by the round itself; the round is recorded as
/// broadcast and goes on, never dropped, and both takes complete once it is
/// final.
#[tokio::test(flavor = "multi_thread")]
async fn a_fill_round_the_node_holds_is_broadcast_not_dropped() {
	let (mut r, z) = start(false).await;
	let y = r.y;
	let (c1, b1) = holder(&mut r, "sent taker 1", y, 1_000_000).await;
	let (c2, b2) = holder(&mut r, "sent taker 2", z, 1_000_000).await;
	let o1 = terms(&r, "sent maker 1", y, 2, 1, 10_000);
	let o2 = terms(&r, "sent maker 2", z, 5, 2, 1_000);
	let at1 = rest(&mut r, &o1, 600_000);
	let at2 = rest(&mut r, &o2, 400_000);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let (id1, k1, n1) = take(&r, &c1, at1, &o1, 600_000, 499_500, 1_000, "sent taker 1");
	let (id2, k2, n2) = take(&r, &c2, at2, &o2, 400_000, 400_000, 0, "sent taker 2");
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	let tx = built[0].tx.clone();
	assert!(hand_over_if_held(&r, &id1, &c1, &[b1.clone()], &k1, &n1));
	// The server stops; the round reaches the node as the server would have
	// handed it over, its record still built.
	r.server.stop();
	let stored: Transaction = elements::encode::deserialize(&r.db.store.round_by_txid(&tx.txid().to_byte_array()).await.unwrap().unwrap().tx).unwrap();
	r.rt.client().send_raw_transaction(&stored).unwrap();
	assert!(node::in_mempool(&r.rt, &tx.txid()));
	println!("round {} in the node's mempool, recorded built", tx.txid());
	r.restart_server().await;
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	let row = r.server.store.round_by_txid(&tx.txid().to_byte_array()).await.unwrap().unwrap();
	println!("after a restart and a pass: round {:?} | take 1 {} | take 2 {}", row.state, status(&r, &id1)["state"], status(&r, &id2)["state"]);
	assert_eq!(row.state, server::store::RoundState::Broadcast, "recorded as broadcast, not dropped");
	assert_eq!(status(&r, &id1)["state"], "issued");
	assert_eq!(status(&r, &id2)["state"], "issued");
	r.produce().await;
	r.bury().await;
	round_final(&r, &tx.txid()).await;
	assert_eq!(complete(&r, &id1, &c1, &[b1], &k1, &n1), 499_500);
	assert_eq!(complete(&r, &id2, &c2, &[b2], &k2, &n2), 400_000);
}
