//! A payment between two wallets of one operator: one wallet asks to receive
//! in asset A over Lightning, and another pays the invoice out of its coins
//! in A. The operator's node in A would be paying its own invoice, which it
//! cannot (its self-payment looks the hash up in its own invoice table, and
//! a receive's hash is held by the hold-invoice plugin), so the operator
//! settles it inside the tree: the payer's `htlc-1` send leaf is the held
//! payment, the hold invoice on the node is cancelled, the receiver's
//! `htlc-1` leaf comes in A's next round timing out a gap before the send
//! leaf, and the receiver's preimage decides both. Nothing crosses the
//! node's channels.
//!
//! Needs what the other end-to-end tests need, and `LIGHTNINGD_EXEC`.

mod common;

use std::thread::JoinHandle;

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, Transaction};
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::{CoinRecord, HtlcDirection, HtlcTerms, LeafRecord, MedianTime, RelativeTime, ValidCoin, ValidLeaf, WalletPolicy};
use sequentia_ext::lightning::{call_at, LightningNode};

use common::client::{hex, new_leaf, random32, transfer_body, unhex, Answer, Held};
use common::keys::xonly;
use common::lightning::{channel_balance, gateway, Gateway};
use common::rounds::{advance_mtp, created, credited_board, mtp, round_final};

const MARGIN: u64 = 2_000;
const PPM: u64 = 1_000;
const BASE: u64 = 10;
/// The leaves' exit delay: four units, 2,048 seconds.
const EXIT_UNITS: u16 = 4;
const WINDOW: u32 = 600;

fn fee(amount: u64) -> u64 {
	(amount * PPM).div_ceil(1_000_000) + BASE
}

fn tune(c: &mut server::server::Config, _: AssetId) {
	c.exit_delay_units = Some((1, 338));
	c.fees.max_margin_multiple = Some(1_000_000);
	c.fees.lightning_ppm = PPM;
	for a in c.assets.iter_mut() {
		a.lightning_base = Some(BASE.to_string());
	}
	c.lightning.receive_window_seconds = WINDOW;
	c.lightning.invoice_expiry_seconds = 900;
	c.lightning.owner_delay_units = 3;
}

fn fresh() -> Keypair {
	common::keys::keypair(&hex(&random32()))
}

fn refused(what: &str, a: Answer, code: &str) -> String {
	let (c, m) = a.refusal();
	assert_eq!(c, code, "{}: {}", what, a.json);
	println!("refused [{}] {}: {}", code, what, m);
	m
}

fn policy(g: &Gateway) -> WalletPolicy {
	let d = RelativeTime::from_units(EXIT_UNITS).unwrap();
	WalletPolicy { min_exit_delay: RelativeTime::from_units(1).unwrap(), max_exit_delay: d, ..WalletPolicy::new(g.r.chain, xonly(&g.r.s), mtp(&g.r)) }
}

// ---------------------------------------------------------------------------
// The receiving wallet
// ---------------------------------------------------------------------------

struct Receiving {
	asset: AssetId,
	amount: u64,
	key: Keypair,
	nonce: [u8; 32],
	preimage: [u8; 32],
	hash: [u8; 32],
}

impl Receiving {
	fn new(asset: AssetId, amount: u64) -> Receiving {
		let preimage = random32();
		Receiving { asset, amount, key: fresh(), nonce: random32(), hash: arca_covenant::script::sha256(&preimage), preimage }
	}

	fn ask(&self, g: &Gateway) -> Answer {
		let digest = server::auth::lightning_receive_digest(&g.r.chain, &xonly(&g.r.s), &self.asset, self.amount, &self.hash,
			&xonly(&self.key), &self.nonce, EXIT_UNITS);
		g.r.http.post("lightning_receive", &json!({
			"asset": self.asset.to_string(), "amount": self.amount.to_string(), "payment_hash": hex(&self.hash),
			"owner": hex(&xonly(&self.key).serialize()), "owner_nonce": hex(&self.nonce), "exit_delay_units": EXIT_UNITS,
			"description": "between two wallets", "owner_sig": hex(sign_digest(&self.key, &digest, &random32()).as_ref()),
		}))
	}
}

fn receive_status(g: &Gateway, hash: &[u8; 32]) -> Value {
	g.r.http.post("lightning_receive_status", &json!({ "payment_hash": hex(hash) })).ok()
}

/// The leaf of `w` once its round is final, as its owner holds it.
async fn take_leaf(g: &Gateway, w: &Receiving) -> (Held, ValidLeaf, Transaction) {
	let st = receive_status(g, &w.hash);
	let pid: [u8; 32] = unhex(st["participation_id"].as_str().unwrap()).try_into().unwrap();
	let ps = common::rounds::status(&g.r, &pid);
	let o = &ps["outputs"][0];
	let txid = ps["round"]["txid"].as_str().unwrap().to_string();
	let published = g.r.http.post("tree", &json!({"txid": txid, "vout": o["batch_vout"]})).ok();
	let tree = common::client::rebuild(&published);
	let round = g.r.rt.client().raw_transaction(&common::client::txid(&txid)).unwrap();
	let record: LeafRecord = tree.record(o["leaf_index"].as_u64().unwrap() as usize);
	let valid = record.validate(&round, &policy(g), &xonly(&w.key), &w.nonce).unwrap();
	let t = record.htlc.expect("an htlc-1 leaf");
	assert_eq!((t.direction, t.payment_hash, record.value), (HtlcDirection::Receive, w.hash, w.amount - fee(w.amount)));
	let at = created(&record);
	let auths: Vec<(Signature, MedianTime)> = valid.branch.nodes.iter()
		.map(|n| (sign_digest(&w.key, &n.unroll_authorisation(at).digest, &random32()), at)).collect();
	let done = g.r.http.post("forfeit_leaves", &json!({"participation_id": hex(&pid), "forfeits": [],
		"leaves": [{"leaf_id": valid.leaf_id.to_string(), "auths": auths.iter().map(|(s, t)| json!({"signature": hex(s.as_ref()),
			"time": t.to_consensus_u32()})).collect::<Vec<_>>()}]})).ok();
	assert_eq!(done["state"], "released", "{}", done);
	let unlock: [u8; 32] = unhex(done["preimage"].as_str().unwrap()).try_into().unwrap();
	let coin = CoinRecord::Leaf { record, preimage: unlock, auths };
	(Held { key: w.key, nonce: w.nonce, id: valid.leaf_id, record: coin }, valid, round)
}

fn claim_body(g: &Gateway, w: &Receiving, held: &Held, round: &Transaction, preimage: &[u8; 32]) -> Value {
	let coin = held.record.resolve(std::slice::from_ref(round), &policy(g)).unwrap();
	let (mut leaf, _) = new_leaf(&fresh());
	leaf.exit_delay = RelativeTime::from_units(EXIT_UNITS).unwrap();
	let v = coin.value;
	let mut body = transfer_body(&[(held, coin, v - MARGIN)], &[(w.asset, v - 2 * MARGIN, leaf)], xonly(&g.r.s), g.r.chain);
	body["payment_hash"] = json!(hex(&w.hash));
	body["preimage"] = json!(hex(preimage));
	body
}

// ---------------------------------------------------------------------------
// The paying wallet
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Coin {
	held: Held,
	valid: ValidCoin,
	bases: Vec<Transaction>,
}

async fn coin(g: &mut Gateway, asset: AssetId) -> Coin {
	let key = fresh();
	let (held, tx) = credited_board(&mut g.r, &key, asset).await;
	let bases = vec![tx];
	let valid = held.record.resolve(&bases, &g.r.policy()).unwrap();
	Coin { held, valid, bases }
}

/// The send terms of `hash`, timing out `ahead` seconds past the chain's
/// median time.
fn send_terms(g: &Gateway, hash: [u8; 32], ahead: u32) -> HtlcTerms {
	HtlcTerms {
		direction: HtlcDirection::Send,
		payment_hash: hash,
		timeout: MedianTime::from_consensus(mtp(&g.r).to_consensus_u32() + ahead).unwrap(),
		operator_delay: RelativeTime::from_units(1).unwrap(),
	}
}

struct Payment {
	body: Value,
	key: Keypair,
	nonce: [u8; 32],
}

fn payment(g: &Gateway, c: &Coin, value: u64, t: HtlcTerms, inv: &str) -> Payment {
	let key = fresh();
	let (mut leaf, nonce) = new_leaf(&key);
	leaf.htlc = Some(t);
	let (change, _) = new_leaf(&fresh());
	let kept = c.valid.value - MARGIN;
	let asset = c.valid.asset;
	let outs = vec![(asset, value, leaf), (asset, kept - value - MARGIN, change)];
	let mut body = transfer_body(&[(&c.held, c.valid.clone(), kept)], &outs, xonly(&g.r.s), g.r.chain);
	body["invoice"] = json!(inv);
	Payment { body, key, nonce }
}

fn send_status(g: &Gateway, hash: &[u8; 32]) -> Value {
	g.r.http.post("lightning_send_status", &json!({ "payment_hash": hex(hash) })).ok()
}

fn htlc_coin(g: &Gateway, c: &Coin, p: &Payment, answer: &Value) -> (Held, ValidCoin) {
	let out = &answer["cosigned"]["outputs"][0];
	let record = CoinRecord::from_bytes(&unhex(out["record"].as_str().unwrap())).unwrap();
	let valid = record.validate(&c.bases, &g.r.policy(), &xonly(&p.key), &p.nonce).unwrap();
	(Held { key: p.key, nonce: p.nonce, id: valid.id, record }, valid)
}

/// The payer's `htlc-1` coin back into a leaf of its own, co-signed.
fn take_back(g: &Gateway, held: &Held, valid: &ValidCoin) -> Answer {
	let (back, _) = new_leaf(&fresh());
	let body = transfer_body(&[(held, valid.clone(), valid.value - MARGIN)], &[(valid.asset, valid.value - 2 * MARGIN, back)],
		xonly(&g.r.s), g.r.chain);
	g.r.http.post("cosign_transfer", &body)
}

/// `node` pays `invoice` on a thread of its own.
fn pay_from(node: &LightningNode, invoice: &str) -> JoinHandle<Result<Value, String>> {
	let (rpc, inv) = (node.rpc_path(), invoice.to_string());
	std::thread::spawn(move || call_at(&rpc, "pay", json!({ "bolt11": inv, "retry_for": 20 })))
}

async fn wait_receive(g: &Gateway, hash: &[u8; 32], what: &str, state: &'static str) {
	let (http, h) = (g.r.http.clone(), hex(hash));
	g.r.wait(what, || http.post("lightning_receive_status", &json!({"payment_hash": h})).json["state"] == state).await;
}

async fn wait_send(g: &Gateway, hash: &[u8; 32], what: &str, state: &'static str) {
	let (http, h) = (g.r.http.clone(), hex(hash));
	g.r.wait(what, || http.post("lightning_send_status", &json!({"payment_hash": h})).json["state"] == state).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_payment_between_two_wallets_of_the_operator_is_settled_inside_it() {
	let Some(mut g) = gateway("a_payment_between_two_wallets_of_the_operator_is_settled_inside_it", tune).await else { return };
	let x = g.r.x;
	let books0 = (channel_balance(&g.ox, x), channel_balance(&g.px, x));

	// The receiver asks; the payer pays its invoice out of a coin in X.
	let w = Receiving::new(x, 100_000);
	let r = w.ask(&g).ok();
	let invoice = r["invoice"].as_str().unwrap().to_string();
	println!("the receive: {}", r);
	let c = coin(&mut g, x).await;
	let ahead = g.r.config.lightning.send_timeout_seconds + 600;
	let p = payment(&g, &c, 100_000 + fee(100_000), send_terms(&g, w.hash, ahead), &invoice);
	let answer = g.r.http.post("lightning_send", &p.body).ok();
	println!("the payment: {}", answer["payment"]);
	assert_eq!(answer["payment"]["state"], "paying");

	// Held inside the operator: the receive accepted, held by the send, the
	// hold invoice gone from the node.
	let (http, h) = (g.r.http.clone(), hex(&w.hash));
	g.r.wait("the receive held, or the payment decided", || {
		http.post("lightning_receive_status", &json!({"payment_hash": h})).json["state"] != "open"
			|| http.post("lightning_send_status", &json!({"payment_hash": h})).json["state"] != "paying"
	}).await;
	let st = receive_status(&g, &w.hash);
	let sent = send_status(&g, &w.hash);
	println!("the receive: {}\nthe payment: {}", st, sent);
	assert_eq!((st["state"].as_str(), sent["state"].as_str()), (Some("accepted"), Some("paying")),
		"the payment is held inside the operator, not paid through its node");
	assert_eq!(st["held_by"], "send");
	let hold = g.ox.ok("holdinvoicelookup", json!({ "payment_hash": hex(&w.hash) }));
	println!("the node's hold invoice: {}", hold["state"]);
	assert!(matches!(hold["state"].as_str(), Some("cancelled") | Some("unknown")), "{}", hold);
	// The receiver's leaf times out the gap before the payer's.
	let t_s = send_terms(&g, w.hash, ahead).timeout.to_consensus_u32() as u64;
	let gap = 512 + g.r.config.lightning.send_stall_margin_seconds as u64 + 3600;
	assert!(st["timeout"].as_u64().unwrap() + gap <= t_s + 120, "{} + {} vs {}", st["timeout"], gap, t_s);

	// An outside payer cannot pay the invoice too.
	let outside = pay_from(&g.px, &invoice).join().unwrap();
	println!("an outside payer paying the same invoice: {:?}", outside.as_ref().map(|v| v["status"].clone()));
	assert!(outside.is_err(), "{:?}", outside);

	// The round makes the receiver's leaf; final, the receiver takes it and
	// claims it with its preimage.
	let built = g.r.server.rounds.run_round_of(x).await.unwrap().expect("a round");
	g.r.produce().await;
	g.r.bury().await;
	round_final(&g.r, &built.tx.txid()).await;
	let (held, _, round) = take_leaf(&g, &w).await;
	assert_eq!(send_status(&g, &w.hash)["state"], "paying", "not decided before the preimage");
	let claimed = g.r.http.post("lightning_receive_claim", &claim_body(&g, &w, &held, &round, &w.preimage)).ok();
	println!("claimed: transfer {}", claimed["cosigned"]["transfer_id"]);
	wait_send(&g, &w.hash, "the payment decided", "paid").await;
	let sent = send_status(&g, &w.hash);
	println!("the payment: {}", sent);
	assert_eq!(sent["preimage"].as_str(), Some(hex(&w.preimage).as_str()), "decided by the receiver's preimage");
	let st = receive_status(&g, &w.hash);
	assert_eq!((st["state"].as_str(), st["settled"].as_bool()), (Some("claimed"), Some(true)), "{}", st);
	assert_eq!(st["preimage"].as_str(), Some(hex(&w.preimage).as_str()));

	// Nothing crossed the node's channel; the paid leaf is the operator's.
	assert_eq!((channel_balance(&g.ox, x), channel_balance(&g.px, x)), books0, "no Lightning traffic");
	let (ph, pv) = htlc_coin(&g, &c, &p, &answer);
	refused("the paid htlc-1 coin back to its owner", take_back(&g, &ph, &pv), "htlc");
}

/// What the operator refuses before it signs anything of an internal
/// payment: a send leaf whose timeout leaves the receiver's leaf less than
/// its least lock, and an invoice an outside payer's payment already holds.
#[tokio::test(flavor = "multi_thread")]
async fn an_internal_payment_the_receive_cannot_take_is_refused() {
	let Some(mut g) = gateway("an_internal_payment_the_receive_cannot_take_is_refused", |c, y| {
		tune(c, y);
		c.lightning.send_timeout_seconds = 3600;
		c.lightning.send_stall_margin_seconds = 600;
	}).await else { return };
	let x = g.r.x;

	// Too short: the send's timeout less the gap (512 + 600 + 3,600 s) is
	// under the receive's least lock (eight sevenths of 2,048 + 600 s).
	let w = Receiving::new(x, 100_000);
	let r = w.ask(&g).ok();
	let c = coin(&mut g, x).await;
	let p = payment(&g, &c, 100_000 + fee(100_000), send_terms(&g, w.hash, 3600 + 300), r["invoice"].as_str().unwrap());
	let m = refused("an internal payment whose receive's leaf would be too short", g.r.http.post("lightning_send", &p.body), "htlc");
	assert!(m.contains("inside the operator"), "{}", m);
	assert_eq!(receive_status(&g, &w.hash)["state"], "open", "the receive untouched");
	assert_eq!(g.r.http.post("lightning_send_status", &json!({"payment_hash": hex(&w.hash)})).refusal().0, "unknown_payment");

	// Held already by an outside payer: the internal payment is refused.
	let w2 = Receiving::new(x, 100_000);
	let r2 = w2.ask(&g).ok();
	let inv2 = r2["invoice"].as_str().unwrap().to_string();
	let outside = pay_from(&g.px, &inv2);
	wait_receive(&g, &w2.hash, "the outside payment held", "accepted").await;
	let c2 = coin(&mut g, x).await;
	let p2 = payment(&g, &c2, 100_000 + fee(100_000), send_terms(&g, w2.hash, 2 * 3600), &inv2);
	let m = refused("an internal payment of an invoice an outside payer holds", g.r.http.post("lightning_send", &p2.body), "in_use");
	println!("{}", m);
	assert_eq!(receive_status(&g, &w2.hash)["held_by"], "node");
	drop(outside);
}

/// A receiver's leaf never claimed: the receive is failed back once its time
/// to claim is over, and the internal payment with it, and the payer takes
/// its `htlc-1` coin back.
#[tokio::test(flavor = "multi_thread")]
async fn a_leaf_never_claimed_fails_the_internal_payment_back() {
	let Some(mut g) = gateway("a_leaf_never_claimed_fails_the_internal_payment_back", tune).await else { return };
	let x = g.r.x;
	let w = Receiving::new(x, 100_000);
	let r = w.ask(&g).ok();
	let c = coin(&mut g, x).await;
	let ahead = g.r.config.lightning.send_timeout_seconds + 600;
	let p = payment(&g, &c, 100_000 + fee(100_000), send_terms(&g, w.hash, ahead), r["invoice"].as_str().unwrap());
	let answer = g.r.http.post("lightning_send", &p.body).ok();
	wait_receive(&g, &w.hash, "held inside the operator", "accepted").await;
	let built = g.r.server.rounds.run_round_of(x).await.unwrap().expect("a round");
	g.r.produce().await;
	g.r.bury().await;
	round_final(&g.r, &built.tx.txid()).await;
	let (held, _, round) = take_leaf(&g, &w).await;

	// Not claimed. Before the time to claim is over the payment stands, and
	// the payer's coin is not co-signed back.
	let (ph, pv) = htlc_coin(&g, &c, &p, &answer);
	refused("the payer's coin back while the payment stands", take_back(&g, &ph, &pv), "htlc");
	let timeout = receive_status(&g, &w.hash)["timeout"].as_u64().unwrap() as u32;
	advance_mtp(&g.r, timeout.saturating_sub(mtp(&g.r).to_consensus_u32()) + 512 + 3_700).await;
	g.r.synced().await;
	wait_receive(&g, &w.hash, "the receive failed back", "cancelled").await;
	wait_send(&g, &w.hash, "the payment failed back", "failed").await;
	println!("the receive: {}\nthe payment: {}", receive_status(&g, &w.hash), send_status(&g, &w.hash));

	// The payer takes its coin back, whole but the margins; a late claim of
	// the receiver's leaf is refused.
	let back = take_back(&g, &ph, &pv).ok();
	assert!(back["outputs"][0]["record"].is_string(), "{}", back);
	println!("the payer's coin of {} back as a leaf of {}, co-signed (transfer {})", pv.value, pv.value - 2 * MARGIN,
		back["transfer_id"]);
	assert_eq!(pv.value, 100_000 + fee(100_000));
	refused("the receiver's claim once failed back", g.r.http.post("lightning_receive_claim", &claim_body(&g, &w, &held, &round,
		&w.preimage)), "htlc");
}

/// W4: a preimage handed to the operator by anyone who has it decides the
/// internal payment, and is served in the receive's status; the receiver
/// can still claim its leaf.
#[tokio::test(flavor = "multi_thread")]
async fn a_preimage_handed_to_the_operator_decides_the_internal_payment() {
	let Some(mut g) = gateway("a_preimage_handed_to_the_operator_decides_the_internal_payment", tune).await else { return };
	let x = g.r.x;
	let w = Receiving::new(x, 100_000);
	let r = w.ask(&g).ok();
	let post = |g: &Gateway, hash: &[u8; 32], pre: &[u8; 32]| g.r.http.post("lightning_preimage", &json!({"payment_hash": hex(hash),
		"preimage": hex(pre)}));
	refused("a preimage for a receive with nothing held", post(&g, &w.hash, &w.preimage), "htlc");
	let c = coin(&mut g, x).await;
	let ahead = g.r.config.lightning.send_timeout_seconds + 600;
	let p = payment(&g, &c, 100_000 + fee(100_000), send_terms(&g, w.hash, ahead), r["invoice"].as_str().unwrap());
	g.r.http.post("lightning_send", &p.body).ok();
	wait_receive(&g, &w.hash, "held inside the operator", "accepted").await;
	refused("a preimage before the receiver's leaf is its own", post(&g, &w.hash, &w.preimage), "htlc");
	let built = g.r.server.rounds.run_round_of(x).await.unwrap().expect("a round");
	g.r.produce().await;
	g.r.bury().await;
	round_final(&g.r, &built.tx.txid()).await;
	let (held, _, round) = take_leaf(&g, &w).await;
	refused("a preimage of another hash", post(&g, &w.hash, &random32()), "htlc");
	refused("a preimage for a hash nobody receives under", post(&g, &random32(), &w.preimage), "unknown_payment");
	let posted = post(&g, &w.hash, &w.preimage).ok();
	println!("posted: {}", posted);
	assert_eq!((posted["state"].as_str(), posted["preimage"].as_str()), (Some("claimed"), Some(hex(&w.preimage).as_str())));
	wait_send(&g, &w.hash, "the payment decided by the posted preimage", "paid").await;
	assert_eq!(post(&g, &w.hash, &w.preimage).ok()["state"], "claimed", "posted again, answered the same");
	// The receiver claims its leaf all the same.
	let claimed = g.r.http.post("lightning_receive_claim", &claim_body(&g, &w, &held, &round, &w.preimage)).ok();
	println!("the receiver's claim after the post: transfer {}", claimed["cosigned"]["transfer_id"]);
}
