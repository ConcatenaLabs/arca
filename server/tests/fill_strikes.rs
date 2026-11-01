//! A strike on one side of a fill of a resting order never falls on the
//! other side's own coins, against a whole server (`arca-signer` in its own
//! process, PostgreSQL, the minimal client playing every holder).
//!
//! A fill is one transfer whose outputs belong to two holders: the maker's
//! credit and the order resting again, the taker's leaf and its change. A
//! coin a voided participation gave up is struck (as `Rounds` strikes it,
//! `Store::strike_coins`), and so is every coin paid on from it
//! (`Store::coin_lineage`). Through a fill that is the credit (paid with the
//! taker's coins, and the maker's own) and the taker's leaf (paid from the
//! order, and the taker's own), never the maker's remainder, which is its
//! own unsold coin, nor the taker's change, which is the taker's own unspent
//! coin.
//!
//! 1. Struck T1 fills honest M's order: M's credit and T1's two coins are
//!    struck, M's remainder is not; M cancels it into a leaf of its own and
//!    refreshes beside an untouched coin of T3, in one round.
//! 2. Struck N's order is filled by honest T2: N's credit, N's remainder and
//!    T2's bought leaf are struck, T2's change is not; T2 refreshes it beside
//!    T3's new coin, in one round, while T2's bought leaf waits.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::Transaction;
use serde_json::{json, Value};

use arca_covenant::order::{OrderLeafTerms, OrderPolicy, OrderTerms, SeqdexOrder};
use arca_covenant::record_json::order_terms_from_json;
use arca_covenant::script::sha256;
use arca_covenant::sign::sign_digest;
use arca_covenant::{CoinRecord, ExplicitOutput, LeafId, NewLeaf, RelativeTime, Template, TransferPlan, ValidCoin};
use common::client::{auths_json, exit_delay, forfeit_sig, hex, hold_key, new_leaf, participation_body, random32, transfer_body, unhex};
use common::flow::{forfeit_for, held_by, Coin};
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{created, credited_board, mtp, round_final, start, status, validate_new_leaf, VALUE};
use common::running::Running;
use server::participations::OutputRequest;

const LOT: u64 = 10_000;

/// A maker: its order's leaf key, the nonces of its four credit keys, its mailbox,
/// and the order's terms.
struct Maker {
	key: Keypair,
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
		version: arca_covenant::order::SeqdexVersion::V2,
	};
	Maker {
		key: keypair(label), credit_nonces: [random32(), random32(), random32(), random32()],
		mailbox: keypair(&format!("{}, mailbox", label)), terms: OrderLeafTerms { landed, credits: keys },
	}
}

/// The wanted leaf of an order of `value` of X.
fn want_order(m: &Maker, value: u64, asset: elements::AssetId) -> (OutputRequest, [u8; 32]) {
	hold_key(&m.key);
	let nonce = random32();
	(OutputRequest::Leaf {
		asset, value, template: Template::Order3, owner: xonly(&m.key), owner_nonce: nonce, exit_delay: exit_delay(),
		order: Some(m.terms),
		landing: None,
		channel: None,
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


/// The strike of each of `ids`, by name, printed.
async fn strikes(r: &Running, what: &str, ids: &[([u8; 32], &str)]) -> Vec<Option<(u32, u32)>> {
	let mut out = vec![];
	for (id, name) in ids {
		let s = r.server.store.strike_of(&[*id]).await.unwrap();
		println!("{}: {} strike {:?}", what, name, s);
		out.push(s);
	}
	out
}

#[tokio::test(flavor = "multi_thread")]
async fn a_strike_on_one_side_of_a_fill_never_falls_on_the_others_own_coins() {
	let mut r = start().await;
	let (x, y, s) = (r.x, r.y, xonly(&r.s));
	let (m, n) = (maker(&r, "M fs"), maker(&r, "N fs"));
	let (t1, t2, t3) = (keypair("T1 fs"), keypair("T2 fs"), keypair("T3 fs"));
	let mut boards = vec![];
	for (label, asset) in [("M fs, board", x), ("N fs, board", x), ("T1 fs, board", y), ("T2 fs, board", y), ("T3 fs, board", x)] {
		let (held, tx) = credited_board(&mut r, &keypair(label), asset).await;
		boards.push(Coin { held, bases: vec![tx] });
	}
	let (bm, bn, bt1, bt2, bt3) = (&boards[0], &boards[1], &boards[2], &boards[3], &boards[4]);
	let (wm, nm) = want_order(&m, VALUE, x);
	let (wn, nn) = want_order(&n, VALUE, x);
	let (w1, n1) = want_leaf(&t1, y, VALUE);
	let (w2, n2) = want_leaf(&t2, y, VALUE);
	let (w3, n3) = want_leaf(&t3, x, VALUE);
	let got = one_round(&mut r, &[(bm, &m.key, wm, nm), (bn, &n.key, wn, nn), (bt1, &t1, w1, n1), (bt2, &t2, w2, n2), (bt3, &t3, w3, n3)])
		.await;
	let (om, on, c1, c2, c3) = (&got[0], &got[1], &got[2], &got[3], &got[4]);
	let bases = om.bases.clone();
	r.http.post("order_publish", &publish_body(&r, &m, om, &m.key)).ok();
	r.http.post("order_publish", &publish_body(&r, &n, on, &n.key)).ok();

	// 1. T1's coin is struck, as a voided participation's coins are.
	let now = mtp(&r).to_consensus_u32();
	r.server.store.strike_coins(&[c1.held.id.0], now, 600, 86_400).await.unwrap();
	assert_eq!(r.server.store.strike_of(&[om.held.id.0]).await.unwrap(), None);
	// Struck T1 fills 300,000 X of honest M's order.
	let view = order_state(&r, &[om.held.id]);
	let st = &view[0];
	let p = policy_of(&r, st, &bases);
	let (l1, _) = new_leaf(&keypair("T1 fs, X"));
	let (ch1, _) = new_leaf(&keypair("T1 fs, change"));
	let done = r.http.post("order_fill", &fill_body(&r, st, &p, (c1, c1.valid(&r)), VALUE - 1, 300_000, (&l1, &ch1), 1, &t1, None)).ok();
	let outs = done["outputs"].as_array().unwrap();
	let oid = |j: usize| -> [u8; 32] { unhex(outs[j]["leaf_id"].as_str().unwrap()).try_into().unwrap() };
	let got1 = strikes(&r, "after struck T1's fill of M", &[(oid(0), "M's credit, paid by T1"), (oid(1), "M's remainder, M's own unsold X"),
		(oid(2), "T1's X"), (oid(3), "T1's change")]).await;
	assert!(got1[0].is_some(), "M's credit is paid from T1's struck coin");
	assert_eq!(got1[1], None, "M's own remainder is not T1's");
	assert!(got1[2].is_some() && got1[3].is_some(), "T1's own coins stay struck: no fill launders a strike");

	// M cancels its remainder into a leaf of its own and refreshes it beside
	// T3's untouched coin: one round takes both.
	let mail = r.http.mailbox(&m.mailbox, &r.chain, 0);
	let mut rest = None;
	for (_, _, record) in &mail {
		let CoinRecord::Fill(f) = record else { panic!("a fill's coin") };
		if let arca_covenant::transfer::FillLeaf::Rest { owner_nonce } = f.leaf {
			rest = Some((record.clone(), record.validate(&bases, &r.policy(), &xonly(&m.key), &owner_nonce).unwrap()));
		}
	}
	let (rest_record, rest) = rest.expect("the remainder");
	let rest_held = common::client::Held { key: m.key, nonce: [0; 32], id: rest.id, record: rest_record };
	let mk = keypair("M fs, after the cancel");
	let (back, back_nonce) = new_leaf(&mk);
	let cancel = r.http.post("cosign_transfer", &transfer_body(&[(&rest_held, rest.clone(), 700_000 - 2_000)],
		&[(x, 700_000 - 4_000, back)], s, r.chain)).ok();
	let back_record = CoinRecord::from_bytes(&unhex(cancel["outputs"][0]["record"].as_str().unwrap())).unwrap();
	let back_coin = back_record.validate(&bases, &r.policy(), &xonly(&mk), &back_nonce).unwrap();
	let back_held = common::client::Held { key: mk, nonce: back_nonce, id: back_coin.id, record: back_record };
	assert_eq!(r.server.store.strike_of(&[back_coin.id.0]).await.unwrap(), None);
	let (w3b, _) = want_leaf(&keypair("T3 fs new"), x, VALUE);
	let (b3, id3) = participation_body(&[&c3.held], &[w3b], &[], None, s, r.chain);
	assert_eq!(r.http.post("submit_participation", &b3).ok()["state"], "pending");
	let (wmb, _) = want_leaf(&keypair("M fs new"), x, 700_000 - 4_000);
	let (bmb, idm) = participation_body(&[&back_held], &[wmb], &[], None, s, r.chain);
	assert_eq!(r.http.post("submit_participation", &bmb).ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().expect("a round");
	let row = r.server.store.round_by_txid(&built.tx.txid().to_byte_array()).await.unwrap().unwrap();
	let members = r.server.store.round_participations(row.round_id).await.unwrap();
	println!("round {}: T3 in it {}, M in it {} ({})", built.tx.txid(), members.contains(&id3), members.contains(&idm),
		status(&r, &idm)["state"]);
	assert!(members.contains(&id3) && members.contains(&idm), "M's own coin refreshes beside T3, in one round");

	// 2. N's order coin is struck; honest T2 fills it.
	let now = mtp(&r).to_consensus_u32();
	r.server.store.strike_coins(&[on.held.id.0], now, 600, 86_400).await.unwrap();
	let view = order_state(&r, &[on.held.id]);
	let st = &view[0];
	let p = policy_of(&r, st, &bases);
	let (l2, _) = new_leaf(&keypair("T2 fs, X"));
	let (ch2, _) = new_leaf(&keypair("T2 fs, change"));
	let done2 = r.http.post("order_fill", &fill_body(&r, st, &p, (c2, c2.valid(&r)), VALUE - 1, 200_000, (&l2, &ch2), 1, &t2, None)).ok();
	let outs2 = done2["outputs"].as_array().unwrap();
	let oid2 = |j: usize| -> [u8; 32] { unhex(outs2[j]["leaf_id"].as_str().unwrap()).try_into().unwrap() };
	let got2 = strikes(&r, "after T2's fill of struck N", &[(oid2(0), "N's credit"), (oid2(1), "N's remainder"),
		(oid2(2), "T2's X, bought from struck N"), (oid2(3), "T2's change, T2's own unspent Y")]).await;
	assert!(got2[0].is_some() && got2[1].is_some(), "N's own coins stay struck: no fill launders a strike");
	assert!(got2[2].is_some(), "T2's X is paid from N's struck coin");
	assert_eq!(got2[3], None, "T2's own change is not N's");
	// The lineage of T2's change is T2's coin, and never N's order coin.
	let lineage = r.server.store.coin_lineage(&[oid2(3)]).await.unwrap();
	assert!(lineage.contains(&c2.held.id.0) && !lineage.contains(&on.held.id.0), "T2's change descends from T2's coin alone");
}
