//! Paying an invoice out of the tree: a coin in asset A pays an invoice in A
//! through A's node, given up into an `htlc-1` leaf locked to the invoice's
//! payment hash. Paid, the leaf is the operator's, which claims it with the
//! preimage should it come on-chain; failed, it goes back to its owner. A
//! coin in one asset never pays an invoice in another, and every term the
//! operator takes is refused when it is not the operator's, before anything
//! is signed.
//!
//! Needs what the other end-to-end tests need, and `LIGHTNINGD_EXEC`.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Transaction};
use serde_json::{json, Value};

use arca_covenant::{CoinRecord, HtlcDirection, HtlcTerms, MedianTime, RelativeTime, ValidCoin};
use server::server::LegSection;

use common::client::{hex, new_leaf, random32, transfer_body, unhex, Answer, Held};
use common::keys::xonly;
use common::lightning::{channel_balance, gateway, invoice, settled_balance, Gateway};
use common::rounds::{advance_mtp, credited_board, mtp};

const MARGIN: u64 = 2_000;
const PPM: u64 = 1_000;
const BASE: u64 = 10;

/// The operator's fee for a payment of `amount`, as its schedule says.
fn fee(amount: u64) -> u64 {
	(amount * PPM).div_ceil(1_000_000) + BASE
}

fn tune(c: &mut server::server::Config, _: AssetId) {
	c.fees.max_margin_multiple = Some(1_000_000);
	c.fees.lightning_ppm = PPM;
	// The owner's least exit delay, three units: two is short of it.
	c.lightning.owner_delay_units = 3;
	for a in c.assets.iter_mut() {
		a.lightning_base = Some(BASE.to_string());
	}
}

/// A fresh key, never used before.
fn fresh() -> Keypair {
	common::keys::keypair(&hex(&random32()))
}

fn refused(what: &str, a: Answer, code: &str) -> String {
	let (c, m) = a.refusal();
	assert_eq!(c, code, "{}: {}", what, a.json);
	println!("refused [{}] {}: {}", code, what, m);
	m
}

/// A coin of the payer's, with the transactions it rests on.
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

/// The terms the operator takes for `hash`: its operator delay, and a
/// timeout a little over `send_timeout_seconds` past the chain's median time.
fn terms(g: &Gateway, hash: [u8; 32]) -> HtlcTerms {
	HtlcTerms {
		direction: HtlcDirection::Send,
		payment_hash: hash,
		timeout: MedianTime::from_consensus(mtp(&g.r).to_consensus_u32() + g.r.config.lightning.send_timeout_seconds + 600).unwrap(),
		operator_delay: RelativeTime::from_units(1).unwrap(),
	}
}

/// A payment the payer makes: its request, and the key and nonce of the
/// `htlc-1` leaf it asks for.
struct Payment {
	body: Value,
	key: Keypair,
	nonce: [u8; 32],
}

/// The request paying `inv` out of `c`: an `htlc-1` leaf of `value` in
/// `asset` under `t`, and the change; `edit` changes the leaf first.
fn payment<F: FnOnce(&mut arca_covenant::NewLeaf)>(g: &Gateway, c: &Coin, asset: AssetId, value: u64, t: HtlcTerms, inv: &str, edit: F)
	-> Payment
{
	let key = fresh();
	let (mut leaf, nonce) = new_leaf(&key);
	leaf.htlc = Some(t);
	edit(&mut leaf);
	let (change, _) = new_leaf(&fresh());
	let kept = c.valid.value - MARGIN;
	let outs = vec![(asset, value, leaf), (asset, kept - value - MARGIN, change)];
	let mut body = transfer_body(&[(&c.held, c.valid.clone(), kept)], &outs, xonly(&g.r.s), g.r.chain);
	body["invoice"] = json!(inv);
	Payment { body, key, nonce }
}

fn status(g: &Gateway, hash: &[u8; 32]) -> Answer {
	g.r.http.post("lightning_send_status", &json!({ "payment_hash": hex(hash) }))
}

/// Waits until the payment of `hash` is decided, and returns it.
async fn decided(g: &Gateway, hash: &[u8; 32]) -> Value {
	let (http, h) = (g.r.http.clone(), hex(hash));
	g.r.wait("the payment to be decided", || {
		http.post("lightning_send_status", &json!({ "payment_hash": h })).json["state"] != "paying"
	}).await;
	status(g, hash).ok()
}

/// The `htlc-1` coin a payment's answer co-signed, held by its payer.
fn htlc_coin(g: &Gateway, c: &Coin, p: &Payment, answer: &Value) -> (Held, ValidCoin) {
	let out = &answer["cosigned"]["outputs"][0];
	let record = CoinRecord::from_bytes(&unhex(out["record"].as_str().unwrap())).unwrap();
	let valid = record.validate(&c.bases, &g.r.policy(), &xonly(&p.key), &p.nonce).unwrap();
	assert_eq!(valid.id.to_string(), out["leaf_id"].as_str().unwrap());
	assert!(valid.leaf.htlc.is_some());
	(Held { key: p.key, nonce: p.nonce, id: valid.id, record }, valid)
}

/// The invoice of `label` on `node`, as the node holds it.
fn invoice_on(node: &sequentia_ext::lightning::LightningNode, label: &str) -> Value {
	node.ok("listinvoices", json!({ "label": label }))["invoices"][0].clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn pays_invoices_in_each_asset_from_leaves_in_it() {
	let Some(mut g) = gateway("pays_invoices_in_each_asset_from_leaves_in_it", tune).await else { return };
	let (x, y) = (g.r.x, g.r.y);
	let info = g.r.http.get("info").ok();
	println!("info.lightning: {}", info["lightning"]);
	for a in info["assets"].as_array().unwrap() {
		println!("asset {}: fees {}, lightning {}", a["asset"], a["fees"], a["lightning"]);
	}
	assert_eq!(info["lightning"]["send"]["operator_delay_units"], 1);

	// The payer's coins: one in X, one in Y.
	let cx = coin(&mut g, x).await;
	let cy = coin(&mut g, y).await;
	let books0 = [(channel_balance(&g.ox, x), channel_balance(&g.px, x)), (channel_balance(&g.oy, y), channel_balance(&g.py, y))];
	println!("channels before: X operator {} payee {}; Y operator {} payee {}", books0[0].0, books0[0].1, books0[1].0, books0[1].1);

	// X's coin pays an invoice in X; Y's an invoice in Y.
	let mut paid = vec![];
	for (asset, c, payee, amount, label) in [(x, &cx, &g.px, 100_000u64, "x-paid"), (y, &cy, &g.py, 200_000, "y-paid")] {
		let (inv, h) = invoice(payee, asset, amount, label);
		let p = payment(&g, c, asset, amount + fee(amount), terms(&g, h), &inv, |_| {});
		let answer = g.r.http.post("lightning_send", &p.body).ok();
		println!("{}: co-signed {}, payment {}", label, answer["cosigned"]["transfer_id"], answer["payment"]);
		assert_eq!(answer["payment"]["state"], "paying");
		assert_eq!(answer["payment"]["fee"], fee(amount).to_string());
		let again = g.r.http.post("lightning_send", &p.body).ok();
		assert_eq!(again["cosigned"], answer["cosigned"], "the same request, the same transfer");
		let st = decided(&g, &h).await;
		println!("{}: {}", label, st);
		assert_eq!(st["state"], "paid");
		let pre: [u8; 32] = unhex(st["preimage"].as_str().unwrap()).try_into().unwrap();
		assert_eq!(arca_covenant::script::sha256(&pre), h, "the preimage is the invoice's");
		let on_payee = invoice_on(payee, label);
		println!("{}: at the payee's node: status {}, received {} msat", label, on_payee["status"], on_payee["amount_received_msat"]);
		assert_eq!(on_payee["status"], "paid");
		assert_eq!(on_payee["amount_received_msat"].as_u64(), Some(amount * 1000));
		let (held, valid) = htlc_coin(&g, c, &p, &answer);
		assert_eq!((valid.asset, valid.value), (asset, amount + fee(amount)));
		paid.push((asset, c.clone(), held, valid, h, amount, p.body));
	}
	// Each channel settles its HTLC a moment after the payment completes.
	for (k, (asset, o, p)) in [(x, &g.ox, &g.px), (y, &g.oy, &g.py)].into_iter().enumerate() {
		let (amount, base) = (paid[k].5, books0[k]);
		g.r.wait("the channels settled", || settled_balance(o, asset) == base.0 - amount && settled_balance(p, asset) == base.1 + amount)
			.await;
	}
	let books1 = [(channel_balance(&g.ox, x), channel_balance(&g.px, x)), (channel_balance(&g.oy, y), channel_balance(&g.py, y))];
	println!("channels after: X operator {} payee {}; Y operator {} payee {}", books1[0].0, books1[0].1, books1[1].0, books1[1].1);
	for (k, (asset, _, _, valid, _, amount, _)) in paid.iter().enumerate() {
		assert_eq!(books0[k].0 - books1[k].0, *amount, "the operator's node paid the invoice in {}, no routing fee", asset);
		assert_eq!(books1[k].1 - books0[k].1, *amount, "the payee's node received it in {}", asset);
		println!("books in {}: the leaf holds {} = {} paid over Lightning + {} the operator's fee", asset, valid.value, amount, fee(*amount));
		assert_eq!(valid.value, amount + fee(*amount));
	}

	// A paid leaf is the operator's: never co-signed back to its owner.
	for (asset, _, held, valid, _, _, _) in &paid {
		let (back, _) = new_leaf(&fresh());
		let body = transfer_body(&[(held, valid.clone(), valid.value - MARGIN)], &[(*asset, valid.value - 2 * MARGIN, back)],
			xonly(&g.r.s), g.r.chain);
		refused(&format!("the paid htlc-1 coin in {} back to its owner", asset), g.r.http.post("cosign_transfer", &body), "htlc");
	}

	// Forced past a wallet: each refused before anything is signed, and no
	// payment recorded. A coin in X and one in Y, spent by none of them.
	let nx = coin(&mut g, x).await;
	let ny = coin(&mut g, y).await;
	let (inv_x, hx) = invoice(&g.px, x, 50_000, "x-refused");
	let (inv_y, hy) = invoice(&g.py, y, 50_000, "y-refused");
	let v = 50_000 + fee(50_000);
	let s = xonly(&g.r.s);
	let send = |g: &Gateway, p: &Payment| g.r.http.post("lightning_send", &p.body);
	let m = refused("X's coin paying Y's invoice, its leaf in X", send(&g, &payment(&g, &nx, x, v, terms(&g, hy), &inv_y, |_| {})), "invoice");
	assert!(m.contains(&format!("paid in asset {}", y)), "{}", m);
	refused("X's coin paying Y's invoice, its leaf in Y", send(&g, &payment(&g, &nx, y, v, terms(&g, hy), &inv_y, |_| {})), "invoice");
	refused("Y's coin paying X's invoice", send(&g, &payment(&g, &ny, x, v, terms(&g, hx), &inv_x, |_| {})), "invoice");
	refused("a leaf one atom short of the fee", send(&g, &payment(&g, &nx, x, v - 1, terms(&g, hx), &inv_x, |_| {})), "fee");
	refused("a leaf one atom over", send(&g, &payment(&g, &nx, x, v + 1, terms(&g, hx), &inv_x, |_| {})), "fee");
	refused("a leaf locked to another hash", send(&g, &payment(&g, &nx, x, v, terms(&g, random32()), &inv_x, |_| {})), "htlc");
	let mut t = terms(&g, hx);
	t.operator_delay = RelativeTime::from_units(2).unwrap();
	refused("another operator delay", send(&g, &payment(&g, &nx, x, v, t, &inv_x, |_| {})), "htlc");
	let mut t = terms(&g, hx);
	t.timeout = MedianTime::from_consensus(mtp(&g.r).to_consensus_u32() + 600).unwrap();
	refused("a timeout too near", send(&g, &payment(&g, &nx, x, v, t, &inv_x, |_| {})), "htlc");
	let mut t = terms(&g, hx);
	t.timeout = MedianTime::from_consensus(mtp(&g.r).to_consensus_u32() + 3 * g.r.config.lightning.send_timeout_seconds).unwrap();
	refused("a timeout too far", send(&g, &payment(&g, &nx, x, v, t, &inv_x, |_| {})), "htlc");
	let mut t = terms(&g, hx);
	t.direction = HtlcDirection::Receive;
	refused("a leaf the owner claims", send(&g, &payment(&g, &nx, x, v, t, &inv_x, |_| {})), "htlc");
	refused("an exit delay below the operator's least", send(&g, &payment(&g, &nx, x, v, terms(&g, hx), &inv_x,
		|l| l.exit_delay = RelativeTime::from_units(2).unwrap())), "htlc");
	let (inv_any, _) = {
		let r = g.px.ok("invoice", json!({ "amount_msat": "any", "label": "x-any", "description": "any", "asset": x.to_string() }));
		(r["bolt11"].as_str().unwrap().to_string(), ())
	};
	refused("an invoice for no amount", send(&g, &payment(&g, &nx, x, v, terms(&g, hx), &inv_any, |_| {})), "invoice");
	let r_old = g.px.ok("invoice", json!({ "amount_msat": 50_000_000u64, "label": "x-old", "description": "old", "asset": x.to_string(),
		"expiry": 30 }));
	let h_old: [u8; 32] = unhex(r_old["payment_hash"].as_str().unwrap()).try_into().unwrap();
	refused("an invoice expiring within a minute", send(&g, &payment(&g, &nx, x, v, terms(&g, h_old), r_old["bolt11"].as_str().unwrap(),
		|_| {})), "invoice");
	let r_far = g.px.ok("invoice", json!({ "amount_msat": 50_000_000u64, "label": "x-far", "description": "far", "asset": x.to_string(),
		"cltv": 1_000 }));
	let h_far: [u8; 32] = unhex(r_far["payment_hash"].as_str().unwrap()).try_into().unwrap();
	refused("an invoice locking longer than the leaf leaves room for", send(&g, &payment(&g, &nx, x, v, terms(&g, h_far),
		r_far["bolt11"].as_str().unwrap(), |_| {})), "invoice");
	refused("no invoice at all", send(&g, &payment(&g, &nx, x, v, terms(&g, hx), "lnsqrt1notaninvoice", |_| {})), "invoice");
	// Two htlc-1 leaves in one payment.
	let mut p = payment(&g, &nx, x, v, terms(&g, hx), &inv_x, |_| {});
	p.body["outputs"][1]["htlc"] = p.body["outputs"][0]["htlc"].clone();
	refused("two htlc-1 leaves", send(&g, &p), "malformed");
	// A plain transfer making an htlc-1 leaf.
	let p = payment(&g, &nx, x, v, terms(&g, hx), &inv_x, |_| {});
	let mut plain = p.body.clone();
	plain.as_object_mut().unwrap().remove("invoice");
	refused("an htlc-1 leaf made by a plain transfer", g.r.http.post("cosign_transfer", &plain), "htlc");
	// The hash of a payment made already, by another transfer.
	let (_, _, _, _, h_paid, _, _) = &paid[0];
	let inv_paid = invoice_on(&g.px, "x-paid")["bolt11"].as_str().unwrap().to_string();
	refused("a second payment of a paid invoice", send(&g, &payment(&g, &nx, x, 100_000 + fee(100_000), terms(&g, *h_paid), &inv_paid,
		|_| {})), "in_use");
	for h in [hx, hy, h_old, h_far] {
		assert_eq!(status(&g, &h).refusal().0, "unknown_payment", "no payment recorded");
	}

	// Y's node unreachable, then Y served with no node: refused with the reason.
	let mut config = g.r.config.clone();
	let leg_of = |c: &mut server::server::Config, l: Option<LegSection>| {
		c.assets.iter_mut().find(|a| a.asset == y.to_string()).unwrap().lightning = l;
	};
	leg_of(&mut config, Some(LegSection { rpc: std::path::PathBuf::from("/nonexistent/lightning-rpc") }));
	g.r.server.reload(&config).await.unwrap();
	let gw = g.r.server.gateway.clone();
	g.r.wait("Y's leg down", || gw.leg(&y, true).is_err()).await;
	let m = refused("Y's invoice with Y's node unreachable", send(&g, &payment(&g, &ny, y, v, terms(&g, hy), &inv_y, |_| {})),
		"lightning_unavailable");
	assert!(m.contains(&y.to_string()), "{}", m);
	let again = g.r.http.post("lightning_send", &paid[1].6).ok();
	assert_eq!(again["payment"]["state"], "paid", "a request repeated is answered as it was, Y's node unreachable or not");
	println!("Y's paid request repeated with Y's node unreachable: answered as before, {}", again["payment"]["state"]);
	leg_of(&mut config, None);
	g.r.server.reload(&config).await.unwrap();
	refused("Y's invoice with Y served by no node", send(&g, &payment(&g, &ny, y, v, terms(&g, hy), &inv_y, |_| {})), "no_lightning");
	leg_of(&mut config, Some(LegSection { rpc: g.oy.rpc_path() }));
	g.r.server.reload(&config).await.unwrap();
	g.r.config = config;
	g.r.wait("Y's leg up", || gw.leg(&y, true).is_ok()).await;
	assert_eq!(status(&g, &hy).refusal().0, "unknown_payment");

	// A payment that fails at the payee: the leaf goes back to its owner, in
	// full, the operator's fee included.
	let (inv_f, hf) = invoice(&g.px, x, 30_000, "x-fails");
	g.px.ok("delinvoice", json!({ "label": "x-fails", "status": "unpaid" }));
	let p = payment(&g, &nx, x, 30_000 + fee(30_000), terms(&g, hf), &inv_f, |_| {});
	let answer = g.r.http.post("lightning_send", &p.body).ok();
	let st = decided(&g, &hf).await;
	println!("x-fails: {}", st);
	assert_eq!(st["state"], "failed");
	let (held, valid) = htlc_coin(&g, &nx, &p, &answer);
	let back_key = fresh();
	let (back, back_nonce) = new_leaf(&back_key);
	let body = transfer_body(&[(&held, valid.clone(), valid.value - MARGIN)], &[(x, valid.value - 2 * MARGIN, back)], s, g.r.chain);
	let done = g.r.http.post("cosign_transfer", &body).ok();
	let record = CoinRecord::from_bytes(&unhex(done["outputs"][0]["record"].as_str().unwrap())).unwrap();
	let returned = record.validate(&nx.bases, &g.r.policy(), &xonly(&back_key), &back_nonce).unwrap();
	assert!(returned.leaf.htlc.is_none());
	println!("x-fails: the htlc-1 coin of {} went back into a new leaf of {} ({} on the two transactions' margins)", valid.value,
		returned.value, 2 * MARGIN);
	assert_eq!(returned.value, 30_000 + fee(30_000) - 2 * MARGIN);
	assert_eq!(channel_balance(&g.ox, x), books1[0].0, "nothing left the operator's node in X");

	// The paid leaf in Y, taken on-chain by its owner: the operator claims
	// it with the preimage once its delay has passed.
	let (_, c, held, valid, h, _, _) = &paid[1];
	let input = match &valid.origin { arca_covenant::ValidOrigin::Transfer { inputs, .. } => inputs[0].clone(), _ => unreachable!() };
	let cp = input.board_checkpoint_tx(&arca_covenant::FeeSource::Reserve).unwrap().tx;
	g.r.rt.client().send_raw_transaction(&cp).unwrap();
	let re = valid.reassignment_tx(&[OutPoint::new(cp.txid(), 0)], &arca_covenant::FeeSource::Reserve).unwrap().tx;
	g.r.rt.client().send_raw_transaction(&re).unwrap();
	g.r.produce().await;
	g.r.synced().await;
	let spk = valid.leaf.script_pubkey();
	let vout = re.output.iter().position(|o| o.script_pubkey == spk).unwrap() as u32;
	let at = OutPoint::new(re.txid(), vout);
	println!("the paid htlc-1 coin {} on-chain at {} (checkpoint {})", held.id, at, cp.txid());
	let _ = c;
	g.r.server.watcher.pass().await.unwrap();
	assert!(g.r.server.store.watcher_txs("htlc_claim", &held.id.0).await.unwrap().is_empty(), "not before the operator's delay");
	advance_mtp(&g.r, 600).await;
	g.r.synced().await;
	g.r.server.watcher.pass().await.unwrap();
	let claims = g.r.server.store.watcher_txs("htlc_claim", &held.id.0).await.unwrap();
	assert_eq!(claims.len(), 1, "the operator's claim");
	println!("watcher: {}", claims[0].detail);
	g.r.produce().await;
	g.r.synced().await;
	assert!(!g.r.unspent(&at), "the claim spent the htlc-1 output");
	let claim: Transaction = elements::encode::deserialize(&claims[0].tx).unwrap();
	let i = claim.input.iter().position(|i| i.previous_output == at).unwrap();
	let pre: [u8; 32] = unhex(status(&g, h).ok()["preimage"].as_str().unwrap()).try_into().unwrap();
	assert!(claim.input[i].witness.script_witness.iter().any(|w| w[..] == pre[..]), "the claim reveals the preimage");
	println!("the claim {} spends {} with the preimage", claim.txid(), at);
}
