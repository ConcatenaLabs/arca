//! Resting orders in the tree ([`server::orders`]), against a whole server on
//! an anchored proof-of-stake regtest chain: `arca-signer` in its own process,
//! PostgreSQL, the minimal client playing every maker and taker, the watcher
//! driven a pass at a time.
//!
//! One round makes two `order-2` leaves (makers M and N, each selling X for
//! Y at 2 Y an X, lots of 10,000) and the takers' coins. Then:
//!
//! 1. M publishes its order and stops; the state view shows it resting. A
//!    publication not signed by the order's key, and one of a coin that is
//!    not an order, are refused.
//! 2. Taker T1 fills 300,000 X of it from a leaf of Y, T2 then 200,000 of the
//!    remainder, each validating the coins the fill makes. Every way a fill
//!    is refused before it is signed is tried first (an unknown order, the
//!    coin it no longer rests at, payment in the wrong asset, a leaf of
//!    another value than the fill, below the lot, a bad signature, no
//!    margin), and a fill sent twice gets the same answer.
//! 3. M comes back: its mailbox holds both credits and both remainders, each
//!    valid under its own key. It cancels the order resting at the second
//!    remainder by a transfer into a leaf of its own; a fill of it after is
//!    refused.
//! 4. M brings its order's first coin to the chain anyway. The watcher
//!    answers before the landing delay runs out: it brings each taker's coin
//!    on, checkpoints it, and publishes both fills and the cancel's
//!    reassignment; M's landing after the delay is refused, the coin spent.
//! 5. N's order, never filled, is brought on by N and lands after the delay
//!    as SeqDEX's own order (refused before it), which a taker on the chain
//!    fills by SeqDEX's program, with no signature.
//!
//! The refusals of transactions are the mempool's: a proof-of-stake chain
//! takes no block its committee did not make. The covenant's regtest suite
//! (`covenant/tests/order_resting.rs`) forces every negative of the scripts
//! into blocks on a chain that can.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::{OutPoint, Transaction, TxOut};
use serde_json::{json, Value};

use arca_covenant::order::{OrderLeafTerms, OrderPolicy, OrderTerms, SeqdexOrder};
use arca_covenant::record_json::order_terms_from_json;
use arca_covenant::script::sha256;
use arca_covenant::sign::sign_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::{CoinRecord, ExplicitOutput, LeafId, NewLeaf, RelativeTime, Template, TransferPlan, ValidCoin, ValidOrigin};
use common::client::{auths_json, exit_delay, forfeit_sig, hex, hold_key, new_leaf, participation_body, random32, transfer_body, unhex};
use common::flow::{drive, final_of, forfeit_for, held_by, log, settle, txid, verdict, Coin};
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{advance_mtp, created, credited_board, mtp, round_final, start, status, validate_new_leaf, VALUE};
use common::running::Running;
use server::participations::OutputRequest;

const HOUR: u32 = 3_600;
const LOT: u64 = 10_000;

/// A maker: its order's leaf key, its four credit keys, its mailbox, and
/// the order's terms.
struct Maker {
	key: Keypair,
	credits: Vec<Keypair>,
	credit_nonces: [[u8; 32]; 4],
	mailbox: Keypair,
	terms: OrderLeafTerms,
}

fn maker(r: &Running, label: &str) -> Maker {
	let credits: Vec<Keypair> = (0..4).map(|i| keypair(&format!("{}, credit {}", label, i))).collect();
	let mut keys = [[0u8; 32]; 4];
	for (i, c) in credits.iter().enumerate() {
		keys[i] = xonly(c).serialize();
	}
	let landed = SeqdexOrder {
		terms: OrderTerms { asset_a: r.x, asset_b: r.y, rate_num: 2, rate_den: 1, min_lot: LOT },
		// Every fill of the landed order on the chain pays this script.
		maker: sha256(node::op_true().as_bytes()),
		expiry: mtp(r).to_consensus_u32() + 60 * 86_400,
		refund_key: xonly(&keypair(&format!("{}, refund", label))),
	};
	Maker {
		key: keypair(label), credits, credit_nonces: [random32(), random32(), random32(), random32()],
		mailbox: keypair(&format!("{}, mailbox", label)), terms: OrderLeafTerms { landed, credits: keys },
	}
}

/// The wanted leaf of an order of `value` of X.
fn want_order(m: &Maker, value: u64, asset: elements::AssetId) -> (OutputRequest, [u8; 32]) {
	hold_key(&m.key);
	let nonce = random32();
	(OutputRequest::Leaf {
		asset, value, template: Template::Order2, owner: xonly(&m.key), owner_nonce: nonce, exit_delay: exit_delay(),
		order: Some(m.terms),
	}, nonce)
}

fn want_leaf(key: &Keypair, asset: elements::AssetId, value: u64) -> (OutputRequest, [u8; 32]) {
	common::client::want_leaf(key, asset, value)
}

/// Each coin given up for the leaf wanted beside it, each in its own
/// participation, in one round, made final; every owner validates its new
/// leaf from the published tree and hands over its forfeit.
async fn one_round(r: &mut Running, wants: &[(&Coin, &Keypair, OutputRequest, [u8; 32])]) -> Vec<Coin> {
	let mut ids = vec![];
	for (coin, _, w, _) in wants {
		let (body, id) = participation_body(&[&coin.held], std::slice::from_ref(w), &[], None, xonly(&r.s), r.chain);
		let a = r.http.post("submit_participation", &body).ok();
		assert_eq!(a["state"], "pending", "{}", a);
		ids.push(id);
	}
	// A round carries one asset: X's first, so every coin of Y a taker pays
	// with expires no earlier than the orders.
	let mut built = vec![];
	while let Some(b) = r.server.rounds.run_round().await.unwrap() {
		r.produce().await;
		built.push(b.tx.txid());
	}
	r.bury().await;
	for t in &built {
		round_final(r, t).await;
	}
	println!("{} rounds: {:?}", built.len(), built);
	let mut out = vec![];
	for ((coin, key, _, nonce), id) in wants.iter().zip(ids) {
		let st = status(r, &id);
		assert!(st["outputs"][0]["batch_vout"].is_u64(), "the participation is in the round: {}", st);
		let (new_valid, record, round) = validate_new_leaf(r, &id, 0, key, nonce);
		let old = coin.valid(r);
		let f = forfeit_for(&old, &new_valid, &round, &st);
		let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&id),
			"forfeits": [{"leaf_id": coin.held.id.to_string(), "signature": forfeit_sig(&f, &coin.held.key)}],
			"leaves": [auths_json(&new_valid, key, created(&record))]})).ok();
		assert_eq!(done["state"], "released", "{}", done);
		let held = held_by(r, key, *nonce, new_valid.leaf_id);
		out.push(Coin { held, bases: vec![round.clone()] });
	}
	let all: Vec<Transaction> = built.iter().map(|t| r.rt.client().raw_transaction(t).unwrap()).collect();
	out.into_iter().map(|c| Coin { bases: all.clone(), ..c }).collect()
}

fn publish_body(r: &Running, m: &Maker, coin: &Coin, signer: &Keypair) -> Value {
	let digest = server::orders::publish_digest(&r.chain, &xonly(&r.s), &coin.held.id, &m.credit_nonces, &xonly(&m.mailbox));
	json!({
		"record": hex(&coin.held.record.to_bytes().unwrap()),
		"credit_nonces": m.credit_nonces.iter().map(|n| hex(n)).collect::<Vec<_>>(),
		"mailbox": hex(&xonly(&m.mailbox).serialize()),
		"signature": hex(sign_digest(signer, &digest, &random32()).as_ref()),
	})
}

fn order_state(r: &Running, ids: &[LeafId]) -> Vec<Value> {
	let a = r.http.post("order_state", &json!({"orders": ids.iter().map(|i| i.to_string()).collect::<Vec<_>>()})).ok();
	a["orders"].as_array().unwrap().clone()
}

/// The policy of the coin an order rests at, as a taker rebuilds it from the
/// state view; checked against the coin's record, which the taker resolves
/// against its round first: the coin is in the tree.
fn policy_of(r: &Running, st: &Value, bases: &[Transaction]) -> OrderPolicy {
	let terms = order_terms_from_json(&st["terms"], st["asset"].as_str().unwrap().parse().unwrap()).unwrap();
	let owner = elements::secp256k1_zkp::XOnlyPublicKey::from_slice(&unhex(st["owner"].as_str().unwrap())).unwrap();
	let salt: [u8; 32] = unhex(st["salt"].as_str().unwrap()).try_into().unwrap();
	let delay = RelativeTime::from_units(st["exit_delay_units"].as_u64().unwrap() as u16).unwrap();
	let p = terms.policy(owner, xonly(&r.s), salt, r.chain, delay);
	let record = CoinRecord::from_bytes(&unhex(st["record"].as_str().expect("a resting order's record"))).unwrap();
	let coin = record.resolve(bases, &r.policy()).unwrap();
	assert_eq!(coin.id.to_string(), st["coin"].as_str().unwrap());
	assert_eq!(coin.leaf.script_pubkey(), p.script_pubkey(), "the state view's terms are the coin's");
	p
}

/// What a taker sends: its coin `paid` (its checkpoint keeping `kept`) for
/// `filled` of the order at `st`, a leaf of it and a leaf of its change, the
/// fill keeping `margin` beyond its outputs; every signature by `signer`.
#[allow(clippy::too_many_arguments)]
fn fill_body(r: &Running, st: &Value, p: &OrderPolicy, paid: (&Coin, ValidCoin), kept: u64, filled: u64, leaves: (&NewLeaf, &NewLeaf),
	margin: u64, signer: &Keypair, taker_value: Option<u64>) -> Value
{
	let s = xonly(&r.s);
	let value: u64 = st["value"].as_str().unwrap().parse().unwrap();
	let plan = p.plan(value, filled).unwrap();
	let price = plan.credit.value;
	let change = kept - price - margin;
	let taker_value = taker_value.unwrap_or(filled);
	let mut outputs = vec![plan.credit.clone()];
	outputs.extend(plan.rest.clone());
	outputs.push(ExplicitOutput::new(p.terms().asset_a, taker_value, leaves.0.policy(s, r.chain).script_pubkey()));
	outputs.push(ExplicitOutput::new(paid.1.asset, change, leaves.1.policy(s, r.chain).script_pubkey()));
	let tplan = TransferPlan { inputs: vec![(paid.1.clone(), kept)], outputs };
	let cp = sign_digest(signer, &tplan.checkpoint_message(0).unwrap().digest, &random32());
	let re = sign_digest(signer, &tplan.reassignment_message(0).unwrap().digest, &random32());
	let leaf_json = |asset: elements::AssetId, v: u64, l: &NewLeaf| json!({
		"asset": asset.to_string(), "value": v.to_string(), "owner": hex(&l.owner.serialize()), "owner_nonce": hex(&l.owner_nonce),
		"creator_nonce": hex(&l.creator_nonce), "exit_delay_units": l.exit_delay.units(),
	});
	json!({
		"order": st["order"], "coin": st["coin"], "filled": filled.to_string(),
		"inputs": [{"leaf_id": paid.0.held.id.to_string(), "checkpoint_value": kept.to_string(), "checkpoint_sig": hex(cp.as_ref()),
			"reassignment_sig": hex(re.as_ref())}],
		"outputs": [leaf_json(p.terms().asset_a, taker_value, leaves.0), leaf_json(paid.1.asset, change, leaves.1)],
	})
}

/// Posts a fill that must be refused, and returns its code and message.
fn refused(r: &Running, what: &str, body: &Value) -> (i32, String, String) {
	let a = r.http.post("order_fill", body);
	assert_ne!(a.status, 200, "{}: co-signed: {}", what, a.json);
	let (code, message) = a.refusal();
	println!("refused, {}: {} {}: {}", what, a.status, code, message);
	(a.status, code, message)
}

fn send(r: &Running, what: &str, tx: &Transaction) -> elements::Txid {
	let txid = r.rt.client().send_raw_transaction(tx).unwrap_or_else(|e| panic!("{}: {}", what, e));
	println!("{}: {} ({} vB)", what, txid, tx.vsize());
	txid
}

/// The unroll of `coin`, a batch leaf, from its batch output down by its
/// owner's own authorisations, and its entry with its preimage, each
/// broadcast and mined; a level already on the chain (another leaf's unroll
/// put it there) is left as it is. The leaf's outpoint.
async fn unroll_to_leaf(r: &Running, coin: &Coin, label: &str) -> OutPoint {
	let v = coin.valid(r);
	let ValidOrigin::Leaf { valid, preimage, auths } = &v.origin else { panic!("not a batch leaf") };
	let txs = valid.branch.unroll(OutPoint::new(valid.round_txid, valid.batch_vout), auths, &vec![FeeSource::Reserve; auths.len()]).unwrap();
	for (level, u) in txs.iter().enumerate() {
		let on_chain: Value = r.rt.client().call("gettxout", &[json!(u.tx.txid().to_string()), json!(0), json!(true)]).unwrap();
		let spent_in = !r.unspent(&u.tx.input[0].previous_output);
		if !on_chain.is_null() || spent_in {
			println!("{}: level {} is on the chain already", label, level);
			continue;
		}
		send(r, &format!("{}: unroll, level {}, by the owner's authorisation", label, level), &u.tx);
	}
	r.produce().await;
	let entry = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), preimage, &FeeSource::Reserve).unwrap();
	let at = send(r, &format!("{}: its entry, with its preimage", label), &entry.tx);
	r.produce().await;
	OutPoint::new(at, 0)
}

/// The landing of an order on the chain at `at` holding `value`, a purse
/// coin of X paying a fee of 3,000. The coin goes back to the purse unless
/// `sent`; then the landing is broadcast and its change goes back instead.
fn land(r: &mut Running, p: &OrderPolicy, at: OutPoint, value: u64, what: &str, sent: bool) -> Result<Transaction, String> {
	let (outpoint, coin) = r.purse.take_coin(r.x);
	let fee = FeeSource::Coin { outpoint, coin: coin.clone(), fee: 3_000, change: node::op_true() };
	let tx = p.landing_tx(at, value, &fee).unwrap().tx;
	if !sent {
		r.purse.put((outpoint, coin));
		return verdict(r, &tx).map(|_| tx.clone());
	}
	let txid = send(r, what, &tx);
	r.purse.put((OutPoint::new(txid, 1), tx.output[1].clone()));
	Ok(tx)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resting_order_fills_with_its_maker_away_and_every_exit_of_it_is_answered() {
	let mut r = start().await;
	let (x, y, s) = (r.x, r.y, xonly(&r.s));
	let (m, n) = (maker(&r, "M"), maker(&r, "N"));
	let (t1, t2, t3) = (keypair("T1"), keypair("T2"), keypair("T3"));
	let mut boards = vec![];
	for (label, asset) in [("M, board", x), ("N, board", x), ("T1, board", y), ("T2, board", y), ("T3, board", x)] {
		let (held, tx) = credited_board(&mut r, &keypair(label), asset).await;
		boards.push(Coin { held, bases: vec![tx] });
	}
	let (bm, bn, bt1, bt2, bt3) = (&boards[0], &boards[1], &boards[2], &boards[3], &boards[4]);

	// An order whose REFUND opens within the operator's margin takes no fill:
	// the round refuses to make it.
	let mut late = maker(&r, "M, late");
	late.terms.landed.expiry = mtp(&r).to_consensus_u32() + 3_600;
	let (w, _) = want_order(&late, VALUE, x);
	let (body, _) = participation_body(&[&bm.held], &[w], &[], None, s, r.chain);
	let a = r.http.post("submit_participation", &body);
	println!("refused, an order whose REFUND opens within the margin: {} {:?}", a.status, a.refusal());
	assert_eq!(a.refusal().0, "order");

	let (wm, nm) = want_order(&m, VALUE, x);
	let (wn, nn) = want_order(&n, VALUE, x);
	let (w1, n1) = want_leaf(&t1, y, VALUE);
	let (w2, n2) = want_leaf(&t2, y, VALUE);
	let (w3, n3) = want_leaf(&t3, x, VALUE);
	let got = one_round(&mut r, &[(bm, &m.key, wm, nm), (bn, &n.key, wn, nn), (bt1, &t1, w1, n1), (bt2, &t2, w2, n2), (bt3, &t3, w3, n3)])
		.await;
	let (om, on, c1, c2, c3) = (&got[0], &got[1], &got[2], &got[3], &got[4]);
	let bases = om.bases.clone();
	println!("round: orders {} (M) and {} (N), 1,000,000 X each; takers' coins {} and {} of Y, {} of X", om.held.id, on.held.id,
		c1.held.id, c2.held.id, c3.held.id);

	// 1. M publishes, and stops.
	let a = r.http.post("order_publish", &publish_body(&r, &m, om, &t1));
	println!("refused, a publication not signed by the order's key: {} {:?}", a.status, a.refusal());
	assert_eq!((a.status, a.refusal().0.as_str()), (400, "malformed"));
	let not_order = Maker { key: t1, ..maker(&r, "T1 as a maker") };
	let a = r.http.post("order_publish", &publish_body(&r, &not_order, c1, &t1));
	println!("refused, a publication of a vtxo-1 coin: {} {:?}", a.status, a.refusal());
	assert_eq!(a.refusal().0, "not_an_order");
	let st = r.http.post("order_publish", &publish_body(&r, &m, om, &m.key)).ok();
	assert_eq!((st["state"].as_str(), st["value"].as_str(), st["fills_left"].as_u64()), (Some("resting"), Some("1000000"), Some(4)));
	let again = r.http.post("order_publish", &publish_body(&r, &m, om, &m.key)).ok();
	assert_eq!(again["coin"], st["coin"], "a publication sent again gets the order's state");
	r.http.post("order_publish", &publish_body(&r, &n, on, &n.key)).ok();
	let unknown = LeafId(random32());
	let view = order_state(&r, &[om.held.id, on.held.id, unknown]);
	assert_eq!(view.len(), 2, "an order not published is left out of the view");
	println!("M published its order and stopped: {}", serde_json::to_string(&view[0]).unwrap().chars().take(400).collect::<String>());

	// 2. T1 fills 300,000 X, paying 600,000 Y. Each refusal first.
	let st = &view[0];
	let p = policy_of(&r, st, &bases);
	let v1 = c1.valid(&r);
	let t1x_key = keypair("T1, X");
	let (l1, l1n) = new_leaf(&t1x_key);
	let (ch1, ch1n) = new_leaf(&keypair("T1, change"));
	let good = fill_body(&r, st, &p, (c1, v1.clone()), VALUE - 1, 300_000, (&l1, &ch1), 1, &t1, None);

	let mut b = good.clone();
	b["order"] = json!(unknown.to_string());
	assert_eq!(refused(&r, "an order not published", &b).1, "unknown_order");
	let mut b = good.clone();
	b["coin"] = json!(on.held.id.to_string());
	assert_eq!(refused(&r, "a coin the order does not rest at", &b).1, "order_moved");
	let v3 = c3.valid(&r);
	let (l3, _) = new_leaf(&keypair("T3, X"));
	let (ch3, _) = new_leaf(&keypair("T3, change"));
	let mut wrong = fill_body(&r, st, &p, (c3, v3), VALUE - 1, 300_000, (&l3, &ch3), 1, &t3, None);
	// Its change named in Y, as a fill's is: the coin it pays with is what is wrong.
	wrong["outputs"][1]["asset"] = json!(y.to_string());
	let (_, code, msg) = refused(&r, "paid in X, not the order's Y", &wrong);
	assert!(code == "order" && msg.contains("paid in"), "{}", msg);
	let short = fill_body(&r, st, &p, (c1, v1.clone()), VALUE - 1, 300_000, (&l1, &ch1), 1, &t1, Some(299_999));
	assert_eq!(refused(&r, "the taker's leaf holds less than the fill", &short).1, "order");
	let mut small = good.clone();
	small["filled"] = json!((LOT - 1).to_string());
	assert_eq!(refused(&r, "a fill below the lot", &small).1, "order");
	let forged = fill_body(&r, st, &p, (c1, v1.clone()), VALUE - 1, 300_000, (&l1, &ch1), 1, &t2, None);
	assert_eq!(refused(&r, "signed by another key than the coin's", &forged).1, "bad_signature");
	let free = fill_body(&r, st, &p, (c1, v1.clone()), VALUE - 1, 300_000, (&l1, &ch1), 0, &t1, None);
	assert_eq!(refused(&r, "no margin for the fill's fee", &free).1, "margin");

	let done = r.http.post("order_fill", &good).ok();
	let again = r.http.post("order_fill", &good).ok();
	for k in ["transfer_id", "fill_signature", "signatures", "outputs"] {
		assert_eq!(again[k], done[k], "a fill sent twice gets the same answer: {}", k);
	}
	let outs = done["outputs"].as_array().unwrap();
	assert_eq!(outs.len(), 4, "the credit, the order resting again, the taker's leaf and its change");
	let fill1: [u8; 32] = unhex(done["transfer_id"].as_str().unwrap()).try_into().unwrap();
	let rec = |j: usize| CoinRecord::from_bytes(&unhex(outs[j]["record"].as_str().unwrap())).unwrap();
	let t1x = rec(2).validate(&bases, &r.policy(), &xonly(&t1x_key), &l1n).unwrap();
	let t1y = rec(3).validate(&bases, &r.policy(), &xonly(&keypair("T1, change")), &ch1n).unwrap();
	assert_eq!((t1x.asset, t1x.value, t1y.asset, t1y.value), (x, 300_000, y, VALUE - 1 - 600_000 - 1));
	println!("T1 filled 300,000 X for 600,000 Y: its leaf {} and change {}, each valid; the fill {}", t1x.id, t1y.id, hex(&fill1));
	let view = order_state(&r, &[om.held.id]);
	let st = &view[0];
	assert_eq!((st["state"].as_str(), st["value"].as_str(), st["fills_left"].as_u64()), (Some("resting"), Some("700000"), Some(3)));
	assert_eq!(st["coin"].as_str().unwrap(), outs[1]["leaf_id"].as_str().unwrap(), "the order rests at the remainder");
	let mut stale = good.clone();
	stale["coin"] = json!(om.held.id.to_string());
	stale["filled"] = json!("100000");
	assert_eq!(refused(&r, "the coin the order rested at before the fill", &stale).1, "order_moved");

	// T2 fills 200,000 of the remainder.
	let p = policy_of(&r, st, &bases);
	let v2 = c2.valid(&r);
	let t2x_key = keypair("T2, X");
	let (l2, l2n) = new_leaf(&t2x_key);
	let (ch2, _) = new_leaf(&keypair("T2, change"));
	let done2 = r.http.post("order_fill", &fill_body(&r, st, &p, (c2, v2), VALUE - 1, 200_000, (&l2, &ch2), 1, &t2, None)).ok();
	let fill2: [u8; 32] = unhex(done2["transfer_id"].as_str().unwrap()).try_into().unwrap();
	let outs2 = done2["outputs"].as_array().unwrap();
	let t2x = CoinRecord::from_bytes(&unhex(outs2[2]["record"].as_str().unwrap())).unwrap()
		.validate(&bases, &r.policy(), &xonly(&t2x_key), &l2n).unwrap();
	assert_eq!((t2x.asset, t2x.value), (x, 200_000));
	let view = order_state(&r, &[om.held.id]);
	assert_eq!((view[0]["value"].as_str(), view[0]["fills"].as_array().unwrap().len()), (Some("500000"), 2));
	println!("T2 filled 200,000 X of the remainder: fill {}, the order resting at {} with 500,000", hex(&fill2), view[0]["coin"]);

	// 3. M comes back: two credits, two remainders.
	let mail = r.http.mailbox(&m.mailbox, &r.chain, 0);
	assert_eq!(mail.len(), 4, "the maker's mailbox: a credit and a remainder per fill");
	let mut credits = vec![];
	let mut rests = vec![];
	for (_, id, record) in &mail {
		let CoinRecord::Fill(f) = record else { panic!("a fill's coin") };
		match f.leaf {
			arca_covenant::transfer::FillLeaf::Credit { owner_nonce } => {
				let k = credits.len();
				assert_eq!(owner_nonce, m.credit_nonces[k], "credit {} under its own nonce", k);
				credits.push(record.validate(&bases, &r.policy(), &xonly(&m.credits[k]), &owner_nonce).unwrap());
			},
			arca_covenant::transfer::FillLeaf::Rest { owner_nonce } => {
				rests.push((record.clone(), record.validate(&bases, &r.policy(), &xonly(&m.key), &owner_nonce).unwrap()));
			},
			_ => panic!("the maker gets no taker's leaf"),
		}
		println!("M's mailbox: {} ({:?})", id, match f.leaf { arca_covenant::transfer::FillLeaf::Credit { .. } => "credit", _ => "remainder" });
	}
	assert_eq!(credits.iter().map(|c| (c.asset, c.value)).collect::<Vec<_>>(), vec![(y, 600_000), (y, 400_000)]);
	assert_eq!(rests.iter().map(|(_, c)| c.value).collect::<Vec<_>>(), vec![700_000, 500_000]);

	// M cancels the rest: a transfer of the order's coin into its own leaf.
	let (rest_record, rest) = rests.pop().unwrap();
	let rest_held = common::client::Held { key: m.key, nonce: [0; 32], id: rest.id, record: rest_record };
	let (back, back_nonce) = new_leaf(&keypair("M, after the cancel"));
	let cancel = r.http.post("cosign_transfer", &transfer_body(&[(&rest_held, rest.clone(), 500_000 - 2_000)],
		&[(x, 500_000 - 4_000, back)], s, r.chain)).ok();
	let cancel_id: Vec<u8> = unhex(cancel["transfer_id"].as_str().unwrap());
	let back_coin = CoinRecord::from_bytes(&unhex(cancel["outputs"][0]["record"].as_str().unwrap())).unwrap()
		.validate(&bases, &r.policy(), &xonly(&keypair("M, after the cancel")), &back_nonce).unwrap();
	println!("M cancelled: transfer {}, the 500,000 X back in its leaf {}", hex(&cancel_id), back_coin.id);
	let view = order_state(&r, &[om.held.id]);
	assert_eq!(view[0]["state"], "cancelled");
	assert!(view[0]["record"].is_null(), "a cancelled order's coin is not served for a fill");
	let p = rest.leaf.order_policy().unwrap();
	let mut late_st = view[0].clone();
	late_st["record"] = Value::Null;
	let v1b = c1.valid(&r);
	let after = fill_body(&r, &late_st, &p, (c1, v1b), VALUE - 1, 100_000, (&new_leaf(&t1).0, &new_leaf(&t1).0), 1, &t1, None);
	let (_, code, _) = refused(&r, "a fill of the coin its maker cancelled", &after);
	assert!(["double_spend", "not_live", "in_use"].contains(&code.as_str()), "{}", code);

	// 4. M brings its order's first coin on the chain anyway.
	let o_at = unroll_to_leaf(&r, om, "M's stale exit").await;
	let o_policy = om.valid(&r).leaf.order_policy().unwrap();
	let e = land(&mut r, &o_policy, o_at, VALUE, "", false).unwrap_err();
	println!("M's landing of its filled order before the delay: refused, {}", e);
	assert!(e.contains("non-BIP68-final"), "{}", e);
	drive(&r, "the answer to M's stale exit", 40, |l| l.iter().any(|w| w.kind == "reassignment" && w.subject == cancel_id)).await;
	settle(&r).await;
	let l = log(&r).await;
	assert!(final_of(&l, "fill", &fill1) && final_of(&l, "fill", &fill2), "both fills are final");
	assert!(final_of(&l, "reassignment", &cancel_id), "the cancel's reassignment is final");
	let f1 = l.iter().find(|w| w.kind == "fill" && w.subject == fill1).unwrap();
	let f1tx: Transaction = elements::encode::deserialize(&f1.tx).unwrap();
	assert_eq!(f1tx.input[0].previous_output, o_at, "the fill spends the coin where M put it");
	assert_eq!(f1tx.output[2].script_pubkey, t1x.leaf.script_pubkey(), "T1's leaf is on the chain");
	println!("watcher: fill {} ({} vB) and fill {}; T1's leaf at {}:2", txid(f1), f1tx.vsize(),
		txid(l.iter().find(|w| w.kind == "fill" && w.subject == fill2).unwrap()), txid(f1));
	advance_mtp(&r, 37 * HOUR).await;
	let e = land(&mut r, &o_policy, o_at, VALUE, "", false).unwrap_err();
	println!("M's landing of its filled order after the delay: refused, {}", e);
	assert!(e.contains("missingorspent") || e.contains("missing-inputs"), "{}", e);

	// 5. N's order, never filled, lands as SeqDEX's own and is filled there.
	let n_at = unroll_to_leaf(&r, on, "N brings its resting order on").await;
	let n_policy = on.valid(&r).leaf.order_policy().unwrap();
	let e = land(&mut r, &n_policy, n_at, VALUE, "", false).unwrap_err();
	println!("N's landing before the delay: refused, {}", e);
	assert!(e.contains("non-BIP68-final"), "{}", e);
	advance_mtp(&r, 37 * HOUR).await;
	let landing = land(&mut r, &n_policy, n_at, VALUE, "N's landing after the delay, as SeqDEX's order", true).unwrap();
	let landed_at = OutPoint::new(landing.txid(), 0);
	r.produce().await;
	assert_eq!(landing.output[0].script_pubkey, n_policy.landed.script_pubkey());
	let lf = 100_000u64;
	let (pay_at, pay) = r.purse.take_coin(y);
	let (fee_at, fee) = r.purse.take_coin(x);
	let (pv, fv) = (pay.value.explicit().unwrap(), fee.value.explicit().unwrap());
	let explicit = |a, v, spk: elements::Script| ExplicitOutput::new(a, v, spk).txout();
	let mut tx = Transaction {
		version: 2, lock_time: elements::LockTime::ZERO,
		input: [landed_at, pay_at, fee_at].iter().map(|o| elements::TxIn { previous_output: *o, ..Default::default() }).collect(),
		output: vec![
			explicit(y, 2 * lf, node::op_true()), explicit(x, VALUE - lf, n_policy.landed.script_pubkey()), explicit(x, lf, node::op_true()),
			explicit(y, pv - 2 * lf, node::op_true()), explicit(x, fv - 3_000, node::op_true()), TxOut::new_fee(3_000, x),
		],
	};
	for i in &mut tx.input {
		i.sequence = elements::Sequence(0xffff_ffff);
	}
	tx.input[0].witness.script_witness = n_policy.landed.fill_witness(true);
	send(&r, "a taker on the chain fills 100,000 X of N's landed order by SeqDEX's program", &tx);
	r.produce().await;
	assert!(r.rt.client().confirmations(&tx.txid()).unwrap() >= 1);
}
