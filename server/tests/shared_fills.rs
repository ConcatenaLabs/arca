//! Several takes of one on-chain order in one round, against a whole server:
//! an order made with SeqDEX's fill covenant (the covenant a Levo sale is,
//! byte for byte) rests on the chain, and many holders take parts of it, each
//! saying it shares the order. The operator's round spends the order once,
//! fills it by the sum of the takes, credits the maker the order's price for
//! that sum at `2k`, rests the remainder at `2k+1`, and pays each take a leaf
//! of its own fill in the batch.
//!
//! - On an anchored proof-of-stake chain: ten takes of one order, beside one
//!   take of another order so the shared order stands at input 1, run in one
//!   round; a take below the order's minimum lot, a take that would take the
//!   order alone, and one that would overfill it, are refused when they are
//!   submitted; each take's status names the round's whole fill of the order;
//!   all ten hold their leaves once the round is final. Then ten more takes
//!   of the order where it rests again, one of which never hands its forfeits
//!   over: past the window the round is dropped unbroadcast, the silent take
//!   voided, and the other nine are served by one spend of the order in the
//!   round built after it.
//! - On an anchored chain without proof of stake, where `generateblock`
//!   forces a transaction the mempool refuses into a block: a shared round
//!   whose credit is the price of one take's share while it fills the sum,
//!   re-signed by the operator so the covenant is the only input that fails,
//!   refused in a block by the covenant's script; the round as built, mined.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Transaction};
use serde_json::json;

use arca_covenant::{ExplicitOutput, FillOrder};
use common::client::{auths_json, forfeit_sig, hex, take_body, unhex, want_leaf, Held};
use common::flow::forfeit_for;
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{created, round_final, status, validate_new_leaf};
use common::running::{Running, MIN_LEAF};
use sequentia_ext::{explicit_txout, AssetAmount};
use server::server::AssetSection;

/// The server: X sold by the orders and listed for fees, Y the asset they
/// are paid in (its offboard fee 1,000 atoms), its wallet funded, final.
async fn start(plain: bool) -> Running {
	let tune = |c: &mut server::server::Config, y: AssetId| {
		let mut a = AssetSection::new(y, MIN_LEAF);
		a.offboard_base = Some("1000".into());
		c.assets.push(a);
	};
	let mut r = if plain { Running::start_plain(tune).await } else { Running::start_with(tune).await };
	let (x, y) = (r.x, r.y);
	// Two coins of X: a dropped round's own coin is spent back at once, and
	// the round after it is funded from the other.
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(y, 50_000_000).await;
	r.fund_wallet_in(y, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r
}

/// An order selling X for Y at `num`/`den` by lots of `min_lot`,
/// refundable from far ahead: a sale's terms, its treasury the maker's
/// program.
fn terms(r: &Running, maker: &str, num: u64, den: u64, min_lot: u64) -> FillOrder {
	let height = r.rt.client().blockchain_info().unwrap().blocks as u32;
	FillOrder {
		asset_a: r.x, asset_b: r.y, rate_num: num, rate_den: den, min_lot,
		maker_prog: xonly(&keypair(&format!("{} treasury", maker))).serialize(),
		expiry_locktime: height + 50_000,
		maker_x: xonly(&keypair(maker)).serialize(),
	}
}

/// Rests `locked` of X under `terms`.
fn rest(r: &mut Running, terms: &FillOrder, locked: u64) -> OutPoint {
	let tx = tokio::task::block_in_place(|| r.purse.pay(&r.rt, vec![explicit_txout(AssetAmount::new(r.x, locked), terms.script_pubkey())]));
	OutPoint::new(tx.txid(), 0)
}

/// Holders of Y, each with one coin of the value given, boarded together
/// and credited.
async fn holders(r: &mut Running, label: &str, values: &[u64]) -> Vec<(Held, Transaction)> {
	let y = r.y;
	let mut made = vec![];
	for (i, v) in values.iter().enumerate() {
		let key = keypair(&format!("{} {}", label, i));
		let (record, tx, _) = r.board_in(&key, y, *v);
		made.push((key, record, tx));
	}
	r.produce().await;
	r.bury().await;
	let mut out = vec![];
	for (key, record, tx) in made {
		let id = record.leaf_id();
		let http = r.http.clone();
		r.wait("the board to be credited", || http.board_status(&id).json["state"] == "credited").await;
		out.push((Held { key, nonce: record.owner_nonce, id, record: arca_covenant::CoinRecord::Board(record) }, tx));
	}
	out
}

/// A take of `filled` of the order, sharing it, posted as a wallet posts
/// it: the server's answer.
fn post_take(r: &Running, coin: &Held, order: OutPoint, terms: &FillOrder, locked: u64, filled: u64, share: bool, label: &str)
	-> (common::client::Answer, [u8; 32], Keypair, [u8; 32])
{
	let key = keypair(&format!("{} new", label));
	let (w, nonce) = want_leaf(&key, r.x, filled);
	let fee = 1_000;
	let (mut body, id) = take_body(&[coin], order, terms, locked, filled, &w, (terms.asset_b, fee), xonly(&r.s), r.chain);
	if share {
		body["share"] = json!(true);
	}
	(r.http.post("take_order", &body), id, key, nonce)
}

/// A coin's value for a take of `filled`: its price and the fee.
fn coin_for(terms: &FillOrder, filled: u64) -> u64 {
	terms.price(filled).unwrap() + 1_000
}

/// Hands over the take's forfeits before its round is broadcast, as a
/// wallet does: its new leaf rebuilt from the published tree and validated
/// against the round's transaction without witnesses, which must fill the
/// take's order by what the status says the round fills of it.
fn hand_over(r: &Running, id: &[u8; 32], coin: &Held, bases: &[Transaction], key: &Keypair, nonce: &[u8; 32], terms: &FillOrder,
	locked: u64)
{
	let st = status(r, id);
	assert_eq!(st["state"], "issued", "{}", st);
	let round: Transaction = elements::encode::deserialize(&unhex(st["round"]["tx"].as_str().expect("the unbroadcast round"))).unwrap();
	let k = st["fill"]["input"].as_u64().unwrap() as usize;
	let f = terms.check(&round, k, locked).unwrap();
	assert_eq!(f.filled.to_string(), st["fill"]["round_filled"].as_str().unwrap(), "the round fills what the status says");
	let o = &st["outputs"][0];
	let published = r.http.post("tree", &json!({"txid": st["round"]["txid"], "vout": o["batch_vout"]})).ok();
	let tree = common::client::rebuild(&published);
	let record = tree.record(o["leaf_index"].as_u64().unwrap() as usize);
	let new_valid = record.validate(&round, &common::rounds::accept_policy(r), &xonly(key), nonce).unwrap();
	let old = coin.record.resolve(bases, &r.policy()).unwrap();
	let fo = forfeit_for(&old, &new_valid, &round, &st);
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(id),
		"forfeits": [{"leaf_id": coin.id.to_string(), "signature": forfeit_sig(&fo, &coin.key)}],
		"leaves": [auths_json(&new_valid, key, created(&record))]})).ok();
	assert_eq!(done["state"], "issued", "{}", done);
}

/// Completes the take once its round is final; returns its leaf's value.
fn complete(r: &Running, id: &[u8; 32], coin: &Held, bases: &[Transaction], key: &Keypair, nonce: &[u8; 32]) -> u64 {
	let st = status(r, id);
	let (new_valid, record, round) = validate_new_leaf(r, id, 0, key, nonce);
	let old = coin.record.resolve(bases, &r.policy()).unwrap();
	let f = forfeit_for(&old, &new_valid, &round, &st);
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(id),
		"forfeits": [{"leaf_id": coin.id.to_string(), "signature": forfeit_sig(&f, &coin.key)}],
		"leaves": [auths_json(&new_valid, key, created(&record))]})).ok();
	assert_eq!(done["state"], "released", "{}", done);
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
		let name = if asset == r.x { "X".to_string() } else if asset == r.y { "Y".into() } else { asset.to_string()[..8].to_string() };
		let what = if o.is_fee() { "the fee".to_string() } else {
			match orders.iter().find(|(_, t)| o.script_pubkey == t.maker_script_pubkey()) {
				Some((op, _)) => format!("credit to the treasury of {}:{}", op.txid, op.vout),
				None => match orders.iter().find(|(_, t)| o.script_pubkey == t.script_pubkey()) {
					Some((op, _)) => format!("order {}:{} resting again", op.txid, op.vout),
					None => "".into(),
				},
			}
		};
		println!("  output {}: {} of {} {}", j, value, name, what);
	}
}

struct Taker {
	id: [u8; 32],
	coin: Held,
	board: Transaction,
	key: Keypair,
	nonce: [u8; 32],
	filled: u64,
}

/// `n` takes of the order at `at`, sharing it, the `i`-th filling
/// `fill(i)`, each from a holder of exactly its price and fee.
async fn takers(r: &mut Running, label: &str, at: OutPoint, t: &FillOrder, locked: u64, fills: &[u64]) -> Vec<Taker> {
	let values: Vec<u64> = fills.iter().map(|f| coin_for(t, *f)).collect();
	let held = holders(r, label, &values).await;
	let mut out = vec![];
	for (i, ((coin, board), filled)) in held.into_iter().zip(fills).enumerate() {
		let (a, id, key, nonce) = post_take(r, &coin, at, t, locked, *filled, true, &format!("{} {}", label, i));
		assert_eq!(a.status, 200, "{} {}: {}", label, i, a.json);
		println!("{} {}: take {} of {} of order {}:{} for {} Y", label, i, hex(&id[..8]), filled, at.txid, at.vout, t.price(*filled).unwrap());
		out.push(Taker { id, coin, board, key, nonce, filled: *filled });
	}
	out
}

#[tokio::test(flavor = "multi_thread")]
async fn ten_takes_share_one_order_in_one_round() {
	let mut r = start(false).await;
	let y = r.y;
	// The sale: 2,000,000 X at 3/2 Y each, by lots of 10,000. A second
	// order, taken first, puts the sale at input 1.
	let sale = terms(&r, "sale", 3, 2, 10_000);
	let other = terms(&r, "other maker", 2, 1, 10_000);
	let at = rest(&mut r, &sale, 2_000_000);
	let at0 = rest(&mut r, &other, 50_000);
	r.produce().await;
	r.bury().await;
	r.synced().await;

	let first = holders(&mut r, "first", &[coin_for(&other, 50_000)]).await.remove(0);
	let (a, id0, key0, nonce0) = post_take(&r, &first.0, at0, &other, 50_000, 50_000, false, "first");
	assert_eq!(a.status, 200, "{}", a.json);

	// Ten buyers, 100,001 to 190,001 X each (odd shares, each price rounded
	// up half an atom).
	let fills: Vec<u64> = (0..10).map(|i| 100_001 + 10_000 * i).collect();
	let buyers = takers(&mut r, "buyer", at, &sale, 2_000_000, &fills).await;
	let sum: u64 = fills.iter().sum();

	// Refused when submitted: a share below the minimum lot; a take that
	// would take the order alone; one that would leave less than a lot.
	let more = holders(&mut r, "refused", &[coin_for(&sale, 9_999), coin_for(&sale, 50_000), coin_for(&sale, 545_000)]).await;
	let (a, ..) = post_take(&r, &more[0].0, at, &sale, 2_000_000, 9_999, true, "below the lot");
	println!("a take of 9999, below the lot of 10000: {} {}", a.status, a.json);
	assert_eq!((a.status, a.json["error"]["code"].as_str()), (422, Some("order")));
	assert!(a.json["error"]["message"].as_str().unwrap().contains("a fill of 9999 atoms is below the order's min_lot of 10000"));
	let (a, ..) = post_take(&r, &more[1].0, at, &sale, 2_000_000, 50_000, false, "alone");
	println!("a take of 50000 that takes the order alone: {} {}", a.status, a.json);
	assert_eq!((a.status, a.json["error"]["code"].as_str()), (409, Some("order_taken")));
	let (a, ..) = post_take(&r, &more[2].0, at, &sale, 2_000_000, 545_000, true, "overfill");
	println!("a take of 545000 beside takes of {} of the 2000000: {} {}", sum, a.status, a.json);
	assert_eq!((a.status, a.json["error"]["code"].as_str()), (409, Some("order_taken")));
	assert!(a.json["error"]["message"].as_str().unwrap().contains("would leave 4990 resting"), "{}", a.json);

	// One round, one spend of the sale.
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	assert_eq!(built.len(), 1);
	let tx = built[0].tx.clone();
	print_round(&r, &tx, &[(at0, &other), (at, &sale)]);
	assert_eq!(built[0].fills, vec![at0, at], "the other order at input 0, the sale at input 1");
	assert_eq!(tx.input.iter().filter(|i| i.previous_output == at).count(), 1, "the sale spent once");
	assert_eq!(built[0].batches, vec![(r.x, 4, 11)], "one batch after the orders' four outputs, eleven leaves");
	let f = sale.check(&tx, 1, 2_000_000).unwrap();
	let plan = sale.plan(2_000_000, sum).unwrap();
	assert_eq!((f.filled, f.remainder, f.credited), (sum, 2_000_000 - sum, plan.credit.value));
	assert_eq!(ExplicitOutput::from_txout(&tx.output[2]).unwrap(), plan.credit, "the treasury credited at 2k = 2");
	assert_eq!(ExplicitOutput::from_txout(&tx.output[3]).unwrap(), plan.rest.clone().unwrap(), "the rest at 2k+1 = 3");
	let own: u64 = fills.iter().map(|x| sale.price(*x).unwrap()).sum();
	println!("the sale filled by {} for ten takes: the treasury credited {} Y at output 2 (the takes pay {} Y for their shares), {} X \
		rest at output 3", sum, plan.credit.value, own, 2_000_000 - sum);
	assert!(plan.credit.value <= own && own - plan.credit.value == 5);
	for b in &buyers {
		let st = status(&r, &b.id);
		assert_eq!((st["fill"]["input"].as_u64(), st["fill"]["credit_vout"].as_u64(), st["fill"]["remainder_vout"].as_u64()),
			(Some(1), Some(2), Some(3)), "{}", st);
		assert_eq!((st["fill"]["round_filled"].as_str(), st["fill"]["round_takes"].as_u64()), (Some(sum.to_string().as_str()), Some(10)));
		assert_eq!(st["fill"]["filled"], b.filled.to_string());
	}
	println!("each take's status: input 1, credit 2, rest 3, round_filled {}, round_takes 10", sum);

	// Every take hands its forfeits over; the round goes out.
	r.server.rounds.pass().await.unwrap();
	assert!(!node::in_mempool(&r.rt, &tx.txid()));
	hand_over(&r, &id0, &first.0, &[first.1.clone()], &key0, &nonce0, &other, 50_000);
	for b in &buyers {
		hand_over(&r, &b.id, &b.coin, &[b.board.clone()], &b.key, &b.nonce, &sale, 2_000_000);
	}
	r.server.rounds.pass().await.unwrap();
	assert!(node::in_mempool(&r.rt, &tx.txid()), "broadcast once all eleven takes' forfeits are in");
	r.produce().await;
	r.bury().await;
	round_final(&r, &tx.txid()).await;
	for b in &buyers {
		assert_eq!(complete(&r, &b.id, &b.coin, &[b.board.clone()], &b.key, &b.nonce), b.filled);
	}
	assert_eq!(complete(&r, &id0, &first.0, &[first.1.clone()], &key0, &nonce0), 50_000);
	let rested = OutPoint::new(tx.txid(), 3);
	assert!(r.unspent(&rested) && r.unspent(&OutPoint::new(tx.txid(), 2)));
	assert_eq!((tx.output[2].script_pubkey.clone(), tx.output[2].asset.explicit()), (sale.maker_script_pubkey(), Some(y)));
	println!("final: ten leaves of their shares; the sale rests again with {} X at {}:3", 2_000_000 - sum, tx.txid());

	// Ten more takes of what rests, one of which never hands its forfeits
	// over: the round is dropped past the window, and the nine others are
	// served in the round after it.
	let locked = 2_000_000 - sum;
	let fills2: Vec<u64> = (0..10).map(|i| 20_000 + 1_000 * i).collect();
	let second = takers(&mut r, "second buyer", rested, &sale, locked, &fills2).await;
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	let round2 = built[0].tx.clone();
	print_round(&r, &round2, &[(rested, &sale)]);
	assert_eq!(sale.check(&round2, 0, locked).unwrap().filled, fills2.iter().sum::<u64>());
	for b in &second[..9] {
		hand_over(&r, &b.id, &b.coin, &[b.board.clone()], &b.key, &b.nonce, &sale, locked);
	}
	r.server.rounds.pass().await.unwrap();
	assert!(!node::in_mempool(&r.rt, &round2.txid()), "held while the tenth take's forfeits are missing");
	common::rounds::advance_mtp(&r, 700).await;
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	let row = r.server.store.round_by_txid(&round2.txid().to_byte_array()).await.unwrap().unwrap();
	assert_eq!(row.state, server::store::RoundState::Lost);
	assert!(r.unspent(&rested), "never broadcast: the sale still rests");
	let silent = status(&r, &second[9].id);
	println!("the tenth take: {} — {}", silent["state"], silent["void_reason"]);
	assert_eq!(silent["state"], "void");
	assert!(silent["void_reason"].as_str().unwrap().contains("its forfeits did not come within 600 s"));
	assert_eq!(silent["inputs"][0]["returned"], true);
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	let round3 = built[0].tx.clone();
	print_round(&r, &round3, &[(rested, &sale)]);
	let nine: u64 = fills2[..9].iter().sum();
	let f3 = sale.check(&round3, 0, locked).unwrap();
	assert_eq!((f3.filled, f3.remainder), (nine, locked - nine), "the nine served by one spend of the sale");
	assert_eq!(built[0].batches, vec![(r.x, 2, 9)]);
	for b in &second[..9] {
		assert_eq!(status(&r, &b.id)["fill"]["round_takes"].as_u64(), Some(9));
		hand_over(&r, &b.id, &b.coin, &[b.board.clone()], &b.key, &b.nonce, &sale, locked);
	}
	r.server.rounds.pass().await.unwrap();
	assert!(node::in_mempool(&r.rt, &round3.txid()));
	r.produce().await;
	r.bury().await;
	round_final(&r, &round3.txid()).await;
	for b in &second[..9] {
		assert_eq!(complete(&r, &b.id, &b.coin, &[b.board.clone()], &b.key, &b.nonce), b.filled);
	}
	println!("final: nine leaves; the treasury credited {} Y at output 0; {} X rest at {}:1", sale.price(nine).unwrap(), locked - nine,
		round3.txid());
	assert!(r.unspent(&OutPoint::new(round3.txid(), 1)));
}

/// The round `tx`, its outputs changed by `change`, every input of the
/// operator's signed again over it, so the only input a changed output can
/// fail is a covenant's.
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

#[tokio::test(flavor = "multi_thread")]
async fn the_covenant_judges_a_shared_fill_by_its_sum() {
	let mut r = start(true).await;
	let y = r.y;
	let sale = terms(&r, "judged sale", 3, 2, 10_000);
	let at = rest(&mut r, &sale, 1_000_000);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let buyers = takers(&mut r, "judged buyer", at, &sale, 1_000_000, &[300_000, 200_000]).await;
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	let tx = built[0].tx.clone();
	print_round(&r, &tx, &[(at, &sale)]);
	let plan = sale.plan(1_000_000, 500_000).unwrap();
	assert_eq!(ExplicitOutput::from_txout(&tx.output[0]).unwrap(), plan.credit);

	// The treasury credited the price of the first take's share alone while
	// the round fills both: the difference to the operator's change in Y.
	let short = plan.credit.value - sale.price(300_000).unwrap();
	let change_y = tx.output.iter().enumerate().skip(2)
		.position(|(_, o)| o.asset.explicit() == Some(y) && !o.is_fee() && o.script_pubkey != sale.maker_script_pubkey())
		.map(|p| p + 2).expect("the operator's change in Y");
	let v = variant(&r, &tx, 1, |o| {
		o[0].value = elements::confidential::Value::Explicit(o[0].value.explicit().unwrap() - short);
		o[change_y].value = elements::confidential::Value::Explicit(o[change_y].value.explicit().unwrap() + short);
	}).await;
	println!("  check: {}", sale.check(&v, 0, 1_000_000).unwrap_err());
	let h0 = r.rt.client().block_count().unwrap();
	let e = match r.rt.client().generate_block("raw(51)", &[&v]) {
		Ok(h) => panic!("a credit of one share for the fill of two: MINED in block {}", h),
		Err(e) => e.to_string(),
	};
	assert_eq!(r.rt.client().block_count().unwrap(), h0);
	println!("a credit of {} (the first share's price) for a fill of 500000: refused in a block: {}", sale.price(300_000).unwrap(), e);
	assert!(e.contains("TestBlockValidity failed: mempool-script-verify-flag-failed (Script evaluated without error but finished with a \
		false/empty top stack element)"), "{}", e);

	// The round as built, its forfeits in, forced the same way: mined.
	r.server.rounds.pass().await.unwrap();
	for b in &buyers {
		hand_over(&r, &b.id, &b.coin, &[b.board.clone()], &b.key, &b.nonce, &sale, 1_000_000);
	}
	r.server.rounds.pass().await.unwrap();
	assert!(node::in_mempool(&r.rt, &tx.txid()));
	let h = r.rt.client().generate_block("raw(51)", &[&tx]).unwrap();
	println!("the shared round itself, forced the same way: mined in block {}", h);
	r.bury().await;
	round_final(&r, &tx.txid()).await;
	for b in &buyers {
		assert_eq!(complete(&r, &b.id, &b.coin, &[b.board.clone()], &b.key, &b.nonce), b.filled);
	}
}
