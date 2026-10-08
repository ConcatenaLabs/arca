//! Receiving over Lightning into the tree: an invoice in asset A, under a
//! hash only the receiving wallet can open, paid by a node of its own to the
//! operator's node in A and held there; the operator wants an `htlc-1` leaf
//! for the wallet in A's next round; the wallet completes the participation
//! (no forfeit, its unroll authorisations), holds the leaf, and only then
//! hands over the preimage with the transfer of the leaf into a leaf of its
//! own, which settles the payment. A leaf never claimed goes back to the
//! operator by its refund, and the payment is failed back.
//!
//! Needs what the other end-to-end tests need, and `LIGHTNINGD_EXEC`.

mod common;

use std::thread::JoinHandle;

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Transaction};
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::{CoinRecord, HtlcDirection, LeafRecord, MedianTime, RelativeTime, ValidLeaf, ValidOrigin, WalletPolicy};
use sequentia_ext::lightning::{call_at, LightningNode};
use server::server::LegSection;

use common::client::{hex, new_leaf, random32, transfer_body, unhex, Answer, Held};
use common::keys::xonly;
use common::lightning::{channel_balance, gateway, settled_balance, Gateway};
use common::rounds::{advance_mtp, created, mtp, round_final};

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

/// The wallet's policy for these leaves, whose exit delay is short.
fn policy(g: &Gateway) -> WalletPolicy {
	let d = RelativeTime::from_units(EXIT_UNITS).unwrap();
	WalletPolicy { min_exit_delay: RelativeTime::from_units(1).unwrap(), max_exit_delay: d, ..WalletPolicy::new(g.r.chain, xonly(&g.r.s), mtp(&g.r)) }
}

/// What the receiving wallet keeps: the leaf's key and nonce, and the
/// preimage only it knows.
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

	/// The request, signed by the leaf's key; `edit` changes it after.
	fn body<F: FnOnce(&mut Value)>(&self, g: &Gateway, exit: u16, signer: &Keypair, edit: F) -> Value {
		let digest = server::auth::lightning_receive_digest(&g.r.chain, &xonly(&g.r.s), &self.asset, self.amount, &self.hash,
			&xonly(&self.key), &self.nonce, exit);
		let mut b = json!({
			"asset": self.asset.to_string(), "amount": self.amount.to_string(), "payment_hash": hex(&self.hash),
			"owner": hex(&xonly(&self.key).serialize()), "owner_nonce": hex(&self.nonce), "exit_delay_units": exit,
			"description": "into the tree", "owner_sig": hex(sign_digest(signer, &digest, &random32()).as_ref()),
		});
		edit(&mut b);
		b
	}

	fn ask(&self, g: &Gateway) -> Answer {
		g.r.http.post("lightning_receive", &self.body(g, EXIT_UNITS, &self.key, |_| {}))
	}
}

fn status(g: &Gateway, hash: &[u8; 32]) -> Value {
	g.r.http.post("lightning_receive_status", &json!({ "payment_hash": hex(hash) })).ok()
}

/// `node` pays `invoice` on a thread of its own: the payment is held until
/// the operator settles or fails it.
fn pay(node: &LightningNode, invoice: &str) -> JoinHandle<Result<Value, String>> {
	let (rpc, inv) = (node.rpc_path(), invoice.to_string());
	std::thread::spawn(move || call_at(&rpc, "pay", json!({ "bolt11": inv })))
}

/// The leaf of the payment `w`, as its owner holds it once the round is
/// final: validated from the published tree, the participation completed
/// with its unroll authorisations (no forfeit), and the entry's preimage.
async fn take_leaf(g: &Gateway, w: &Receiving) -> (Held, ValidLeaf, Transaction) {
	let st = status(g, &w.hash);
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
	println!("the leaf in round {}: {} of {} under htlc-1 ({}, hash {}, timeout {}, operator delay {} units)", txid, record.value,
		record.asset, t.direction.name(), hex(&t.payment_hash), t.timeout.to_consensus_u32(), t.operator_delay.units());
	assert_eq!((t.direction, t.payment_hash, record.value, record.asset), (HtlcDirection::Receive, w.hash, w.amount - fee(w.amount), w.asset));
	assert_eq!(st["timeout"].as_u64(), Some(t.timeout.to_consensus_u32() as u64));
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

/// The claim of `held`, the leaf of `w`, into a new leaf of the owner's,
/// with `preimage`.
fn claim_body(g: &Gateway, w: &Receiving, held: &Held, round: &Transaction, preimage: &[u8; 32]) -> (Value, Keypair, [u8; 32]) {
	let coin = held.record.resolve(std::slice::from_ref(round), &policy(g)).unwrap();
	let key = fresh();
	let (mut leaf, nonce) = new_leaf(&key);
	leaf.exit_delay = RelativeTime::from_units(EXIT_UNITS).unwrap();
	let v = coin.value;
	let mut body = transfer_body(&[(held, coin, v - MARGIN)], &[(w.asset, v - 2 * MARGIN, leaf)], xonly(&g.r.s), g.r.chain);
	body["payment_hash"] = json!(hex(&w.hash));
	body["preimage"] = json!(hex(preimage));
	(body, key, nonce)
}

#[tokio::test(flavor = "multi_thread")]
async fn receives_in_each_asset_into_leaves_claimed_with_the_preimage() {
	let Some(mut g) = gateway("receives_in_each_asset_into_leaves_claimed_with_the_preimage", tune).await else { return };
	let (x, y) = (g.r.x, g.r.y);
	println!("info.lightning.receive: {}", g.r.http.get("info").ok()["lightning"]["receive"]);

	// Forced past a wallet, each request refused, nothing made.
	let w = Receiving::new(x, 100_000);
	refused("a request signed by another key", g.r.http.post("lightning_receive", &w.body(&g, EXIT_UNITS, &fresh(), |_| {})),
		"bad_signature");
	refused("an exit delay not past the operator's delay", g.r.http.post("lightning_receive", &w.body(&g, 1, &w.key, |_| {})),
		"out_of_bounds");
	let small = Receiving::new(x, 15);
	refused("an amount whose leaf, the fee out, is below the smallest leaf", small.ask(&g), "out_of_bounds");
	let z = Receiving::new(AssetId::from_byte_array([7; 32]), 100_000);
	refused("an asset not served", z.ask(&g), "out_of_bounds");

	// X and Y each receive: an invoice, paid by the node of the payer's, held.
	let books0 = [(channel_balance(&g.ox, x), channel_balance(&g.px, x)), (channel_balance(&g.oy, y), channel_balance(&g.py, y))];
	let mut receiving = vec![];
	for (asset, payer, amount) in [(x, &g.px, 100_000u64), (y, &g.py, 200_000)] {
		let w = Receiving::new(asset, amount);
		let r = w.ask(&g).ok();
		println!("receiving {} of {}: {}", amount, asset, r);
		assert_eq!((r["state"].as_str(), r["fee"].as_str()), (Some("open"), Some(fee(amount).to_string().as_str())));
		let again = w.ask(&g).ok();
		assert_eq!(again["invoice"], r["invoice"], "the same request, the same invoice");
		let d = payer.ok("decode", json!({ "string": r["invoice"] }));
		println!("the invoice, as the payer's node reads it: hash {}, asset {}, {} msat, final lock time {} blocks, valid {}",
			d["payment_hash"], d["asset"], d["amount_msat"], d["min_final_cltv_expiry"], d["valid"]);
		assert_eq!((d["valid"].as_bool(), d["payment_hash"].as_str()), (Some(true), Some(hex(&w.hash).as_str())));
		assert_eq!(d["asset"].as_str(), Some(asset.to_string().as_str()));
		// A second request under the same hash, or the same key: refused.
		let mut other = Receiving::new(asset, amount);
		other.hash = w.hash;
		refused("another request under a hash asked for", other.ask(&g), "in_use");
		let mut same_key = Receiving::new(asset, amount);
		same_key.key = w.key;
		refused("another request under a key asked for", same_key.ask(&g), "key_reused");
		let paying = pay(payer, r["invoice"].as_str().unwrap());
		let (http, h) = (g.r.http.clone(), hex(&w.hash));
		g.r.wait("the payment held", || http.post("lightning_receive_status", &json!({"payment_hash": h})).json["state"] == "accepted").await;
		println!("held: {}", status(&g, &w.hash));
		// No leaf yet: nothing to claim.
		let m = refused("a claim before the leaf", g.r.http.post("lightning_receive_claim", &json!({"payment_hash": hex(&w.hash),
			"preimage": hex(&w.preimage), "inputs": [], "outputs": []})), "htlc");
		assert!(m.contains("not the owner's yet"), "{}", m);
		receiving.push((w, paying, payer));
	}

	// The next round of each asset makes each leaf; final, then each owner
	// takes its leaf, and claims it.
	for (k, (w, paying, payer)) in receiving.into_iter().enumerate() {
		let built = g.r.server.rounds.run_round_of(w.asset).await.unwrap().expect("a round");
		g.r.produce().await;
		g.r.bury().await;
		round_final(&g.r, &built.tx.txid()).await;
		let (held, _valid, round) = take_leaf(&g, &w).await;
		let (good, _, _) = claim_body(&g, &w, &held, &round, &w.preimage);
		// Without the preimage, or with another, or as a plain transfer:
		// refused, and the payment still held.
		let (wrong, _, _) = claim_body(&g, &w, &held, &round, &random32());
		refused("a claim with another preimage", g.r.http.post("lightning_receive_claim", &wrong), "htlc");
		let mut plain = good.clone();
		plain.as_object_mut().unwrap().remove("payment_hash");
		plain.as_object_mut().unwrap().remove("preimage");
		refused("the leaf spent by a plain transfer", g.r.http.post("cosign_transfer", &plain), "htlc");
		assert_eq!(status(&g, &w.hash)["state"], "accepted");
		assert!(!paying.is_finished(), "the payer's payment is held until the preimage comes");
		// The claim: the leaf's transfer co-signed, the payment settled.
		let claimed = g.r.http.post("lightning_receive_claim", &good).ok();
		println!("claimed: transfer {}, the payment {}", claimed["cosigned"]["transfer_id"], claimed["receive"]);
		let paid = paying.join().unwrap().unwrap();
		println!("the payer's node: {} {}, preimage {}", paid["status"], paid["amount_sent_msat"], paid["payment_preimage"]);
		assert_eq!((paid["status"].as_str(), paid["payment_preimage"].as_str()), (Some("complete"), Some(hex(&w.preimage).as_str())));
		let (o, p) = if k == 0 { (&g.ox, payer) } else { (&g.oy, payer) };
		// The channel settles the HTLC a moment after the payer learns the
		// preimage.
		let (base, asset) = (books0[k].0, w.asset);
		g.r.wait("the operator's channel settled", || settled_balance(o, asset) == base + w.amount).await;
		let (o1, p1) = (channel_balance(o, w.asset), channel_balance(p, w.asset));
		println!("books in {}: the operator's node {} -> {} (+{}), the payer's {} -> {}; the leaf {} = {} less the fee {}; the new leaf \
			{} (two margins of {})", w.asset, books0[k].0, o1, o1 - books0[k].0, books0[k].1, p1, w.amount - fee(w.amount), w.amount,
			fee(w.amount), w.amount - fee(w.amount) - 2 * MARGIN, MARGIN);
		assert_eq!((o1 - books0[k].0, books0[k].1 - p1), (w.amount, w.amount));
		let st = status(&g, &w.hash);
		assert_eq!((st["state"].as_str(), st["settled"].as_bool()), (Some("claimed"), Some(true)), "{}", st);
		// Asked again: answered as before, nothing more.
		let again = g.r.http.post("lightning_receive_claim", &good).ok();
		assert_eq!(again["cosigned"], claimed["cosigned"]);
	}

	// Y served with no node: a request in Y refused, with the reason.
	let mut config = g.r.config.clone();
	config.assets.iter_mut().find(|a| a.asset == y.to_string()).unwrap().lightning = None;
	g.r.server.reload(&config).await.unwrap();
	refused("receiving in Y with no node", Receiving::new(y, 100_000).ask(&g), "no_lightning");
	config.assets.iter_mut().find(|a| a.asset == y.to_string()).unwrap().lightning = Some(LegSection { rpc: g.oy.rpc_path() });
	g.r.server.reload(&config).await.unwrap();
	g.r.config = config;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_leaf_never_claimed_is_refunded_and_its_payment_failed_back() {
	let Some(g) = gateway("a_leaf_never_claimed_is_refunded_and_its_payment_failed_back", tune).await else { return };
	let x = g.r.x;
	let p0 = channel_balance(&g.px, x);

	// Held, its leaf made and taken by its owner, who never claims it.
	let w = Receiving::new(x, 100_000);
	let r = w.ask(&g).ok();
	let paying = pay(&g.px, r["invoice"].as_str().unwrap());
	let (http, h) = (g.r.http.clone(), hex(&w.hash));
	g.r.wait("the payment held", || http.post("lightning_receive_status", &json!({"payment_hash": h})).json["state"] == "accepted").await;
	let built = g.r.server.rounds.run_round_of(x).await.unwrap().expect("a round");
	g.r.produce().await;
	g.r.bury().await;
	round_final(&g.r, &built.tx.txid()).await;
	let (held, _, round) = take_leaf(&g, &w).await;

	// The owner takes the leaf on-chain and claims nothing.
	let coin = held.record.resolve(std::slice::from_ref(&round), &policy(&g)).unwrap();
	let (valid, unlock, auths) = match &coin.origin {
		ValidOrigin::Leaf { valid, preimage, auths } => (valid.clone(), *preimage, auths.clone()),
		_ => unreachable!(),
	};
	let txs = valid.branch.unroll(OutPoint::new(valid.round_txid, valid.batch_vout), &auths, &vec![FeeSource::Reserve; auths.len()]).unwrap();
	for u in &txs {
		g.r.rt.client().send_raw_transaction(&u.tx).unwrap();
		g.r.produce().await;
	}
	let entry = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), &unlock, &FeeSource::Reserve).unwrap();
	g.r.rt.client().send_raw_transaction(&entry.tx).unwrap();
	g.r.produce().await;
	g.r.synced().await;
	let at = OutPoint::new(entry.tx.txid(), 0);
	println!("the leaf on-chain at {}", at);

	// Before its timeout: no refund. Past it, the operator's delay and the
	// hour after, the payment still stands while the leaf lies unspent on
	// the chain, where its owner could yet claim it; the watcher refunds it.
	g.r.server.watcher.pass().await.unwrap();
	assert!(g.r.server.store.watcher_txs("htlc_refund", &held.id.0).await.unwrap().is_empty(), "not before the timeout");
	let timeout = status(&g, &w.hash)["timeout"].as_u64().unwrap() as u32;
	let ahead = timeout.saturating_sub(mtp(&g.r).to_consensus_u32()) + 600 + 3_700;
	advance_mtp(&g.r, ahead).await;
	g.r.synced().await;
	tokio::time::sleep(std::time::Duration::from_secs(6)).await;
	assert_eq!(status(&g, &w.hash)["state"], "accepted", "not failed back while the leaf can still be claimed on the chain");
	println!("past the time to claim, the leaf unspent on the chain: the payment stands");
	g.r.server.watcher.pass().await.unwrap();
	let refunds = g.r.server.store.watcher_txs("htlc_refund", &held.id.0).await.unwrap();
	assert_eq!(refunds.len(), 1, "the operator's refund");
	println!("watcher: {}", refunds[0].detail);
	g.r.produce().await;
	g.r.synced().await;
	assert!(!g.r.unspent(&at), "the refund spent the leaf");

	// The leaf refunded, the payment is failed back to the payer.
	let (http, h) = (g.r.http.clone(), hex(&w.hash));
	g.r.wait("the payment failed back", || http.post("lightning_receive_status", &json!({"payment_hash": h})).json["state"] == "cancelled")
		.await;
	let paid = paying.join().unwrap();
	println!("the payer's node: {:?}", paid.as_ref().map(|v| v["status"].clone()));
	assert!(paid.is_err(), "the payer's payment failed: {:?}", paid);
	g.r.wait("nothing left the payer's channel", || settled_balance(&g.px, x) == p0).await;
	let st = status(&g, &w.hash);
	println!("the payment: {}", st);
	assert_eq!((st["state"].as_str(), st["settled"].as_bool()), (Some("cancelled"), Some(false)));
	// A claim now: refused, the payment failed back.
	let (late, _, _) = claim_body(&g, &w, &held, &round, &w.preimage);
	refused("a claim once the payment was failed back", g.r.http.post("lightning_receive_claim", &late), "htlc");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_leaf_claimed_on_the_chain_settles_its_payment() {
	let Some(mut g) = gateway("a_leaf_claimed_on_the_chain_settles_its_payment", tune).await else { return };
	let x = g.r.x;
	let o0 = channel_balance(&g.ox, x);

	// Held, its leaf made and taken by its owner.
	let w = Receiving::new(x, 100_000);
	let r = w.ask(&g).ok();
	let paying = pay(&g.px, r["invoice"].as_str().unwrap());
	let (http, h) = (g.r.http.clone(), hex(&w.hash));
	g.r.wait("the payment held", || http.post("lightning_receive_status", &json!({"payment_hash": h})).json["state"] == "accepted").await;
	let built = g.r.server.rounds.run_round_of(x).await.unwrap().expect("a round");
	g.r.produce().await;
	g.r.bury().await;
	round_final(&g.r, &built.tx.txid()).await;
	let (held, _, round) = take_leaf(&g, &w).await;

	// The owner takes the leaf home on the chain, as it would were the
	// operator not to co-sign its claim: unrolled, entered, and claimed with
	// the preimage once its exit delay has run.
	let coin = held.record.resolve(std::slice::from_ref(&round), &policy(&g)).unwrap();
	let (valid, unlock, auths) = match &coin.origin {
		ValidOrigin::Leaf { valid, preimage, auths } => (valid.clone(), *preimage, auths.clone()),
		_ => unreachable!(),
	};
	let txs = valid.branch.unroll(OutPoint::new(valid.round_txid, valid.batch_vout), &auths, &vec![FeeSource::Reserve; auths.len()]).unwrap();
	for u in &txs {
		g.r.rt.client().send_raw_transaction(&u.tx).unwrap();
		g.r.produce().await;
	}
	let entry = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), &unlock, &FeeSource::Reserve).unwrap();
	g.r.rt.client().send_raw_transaction(&entry.tx).unwrap();
	g.r.produce().await;
	let at = OutPoint::new(entry.tx.txid(), 0);
	advance_mtp(&g.r, RelativeTime::from_units(EXIT_UNITS).unwrap().seconds() as u32 + 60).await;
	g.r.synced().await;
	let fee_coin = g.r.purse.take_coin(x);
	let ks = coin.leaf.claim_tx(at, x, coin.value, &[arca_covenant::ExplicitOutput::new(x, coin.value, common::node::op_true())],
		&FeeSource::Coin { outpoint: fee_coin.0, coin: fee_coin.1.clone(), fee: 2_000, change: common::node::op_true() }).unwrap();
	let sig = sign_digest(&w.key, &ks.sighash(g.r.chain.genesis_hash()).unwrap(), &random32());
	let claim = ks.finish(arca_covenant::HtlcTerms::claim_items(&sig, &w.preimage)).tx;
	g.r.rt.client().send_raw_transaction(&claim).unwrap();
	g.r.produce().await;
	g.r.synced().await;
	println!("the owner claimed its leaf on the chain: {}", claim.txid());

	// The operator reads the preimage from the claim and settles.
	let (http, h) = (g.r.http.clone(), hex(&w.hash));
	g.r.wait("the payment settled from the chain", || {
		let st = http.post("lightning_receive_status", &json!({"payment_hash": h})).json;
		st["state"] == "claimed" && st["settled"] == true
	}).await;
	let paid = paying.join().unwrap().unwrap();
	println!("the payer's node: {}, preimage {}", paid["status"], paid["payment_preimage"]);
	assert_eq!((paid["status"].as_str(), paid["payment_preimage"].as_str()), (Some("complete"), Some(hex(&w.preimage).as_str())));
	g.r.wait("the operator's node received the payment", || settled_balance(&g.ox, x) == o0 + w.amount).await;
}
