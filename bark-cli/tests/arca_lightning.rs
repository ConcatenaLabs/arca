//! Paying and receiving over Lightning, as the `arca` wallet does it: a
//! wallet holding leaves in X and Y pays an invoice in X from its X leaf and
//! one in Y from its Y leaf, through the operator's node in each asset, then
//! receives in X and in Y into leaves of its own, against a whole Arca server
//! and SeqLN nodes on the chain SeqLN's `sequentia-regtest` network assumes.
//! An invoice in Y is refused before anything is signed when the wallet is
//! asked to pay it from X, and a payment that fails comes back to the wallet.
//! Every balance, in both assets and on every node, is accounted for.
//!
//! Needs what the other scenarios need, and `LIGHTNINGD_EXEC`.

mod common;

use elements::hashes::Hash;
use elements::{AssetId, Script};
use serde_json::{json, Value};

use server::server::LegSection;

use common::cli::Arca;
use common::lightning::{channel_balance, invoice, invoice_status, lightningd, node, settled_balance};
use common::running::Running;
use server::store::RoundState;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

const PPM: u64 = 1_000;
const BASE: u64 = 10;

fn fee(amount: u64) -> u64 {
	(amount * PPM).div_ceil(1_000_000) + BASE
}

/// What the wallet holds in `asset` off-chain, by standing, summed.
fn arca_held(w: &Arca, asset: &AssetId) -> u64 {
	let b = w.ok(&["balance"]);
	b["arca"][asset.to_string()].as_object().map(|m| m.values().map(|v| v.as_str().unwrap().parse::<u64>().unwrap()).sum())
		.unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_pays_and_receives_in_each_asset_from_and_into_its_leaves_in_it() {
	let Some(lnd) = lightningd("a_wallet_pays_and_receives_in_each_asset_from_and_into_its_leaves_in_it") else { return };
	let mut r = Running::start_seqln(|c, _, _| {
		c.fees.lightning_ppm = PPM;
		for a in c.assets.iter_mut() {
			a.lightning_base = Some(BASE.to_string());
		}
		c.lightning.operator_delay_units = 1;
		c.lightning.owner_delay_units = 2;
		// SeqLN's final lock time on a Sequentia network is 180 blocks:
		// eight hours leave a payment 240.
		c.lightning.send_timeout_seconds = 8 * 3600;
		c.lightning.send_stall_margin_seconds = 3600;
		c.lightning.poll_seconds = 1;
		c.lightning.retry_seconds = 10;
		c.lightning.receive_window_seconds = 600;
	}).await;
	let (x, y) = (r.x, r.y);
	common::node::list_fee_asset(&r.rt, y, 100_000_000);

	// The operator's node in X and in Y, each with a channel to a payee.
	let (ox, px, oy, py) = tokio::task::block_in_place(|| {
		let ox = node(&r.rt, &mut r.purse, &lnd, "ox", true, x, 2_000_000_000);
		let px = node(&r.rt, &mut r.purse, &lnd, "px", true, x, 1_000_000_000);
		let oy = node(&r.rt, &mut r.purse, &lnd, "oy", true, y, 2_000_000_000);
		let py = node(&r.rt, &mut r.purse, &lnd, "py", true, y, 1_000_000_000);
		ox.open_channel(&r.rt, &px, x, 1_000_000_000, 300_000_000);
		oy.open_channel(&r.rt, &py, y, 1_000_000_000, 300_000_000);
		(ox, px, oy, py)
	});
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let mut config = r.config.clone();
	for a in config.assets.iter_mut() {
		let n = if a.asset == x.to_string() { &ox } else { &oy };
		a.lightning = Some(LegSection { rpc: n.rpc_path() });
	}
	r.server.reload(&config).await.unwrap();
	r.config = config;
	let g = r.server.gateway.clone();
	r.wait("both legs up", || g.leg(&x, true).is_ok() && g.leg(&y, true).is_ok()).await;

	// A wallet with a leaf in X and a leaf in Y.
	let (url, nurl) = (r.url(), r.node_url());
	let a = Arca::new("LN1");
	// Its leaves exit after four units, longer than the operator's delay of
	// one, as a leaf received over Lightning needs.
	a.ok(&["create", "--server", &url, "--node-url", &nurl, "--node-user", "arca", "--exit-delay-units", "4",
		"--min-exit-delay-units", "1"]);
	for (asset, v) in [(x, 10_000_000), (x, 1_000_000), (y, 10_000_000)] {
		let s = script(&a.ok(&["address"]));
		r.pay_to(s, asset, v);
	}
	r.produce().await;
	a.ok(&["board", &x.to_string(), "2000000"]);
	a.ok(&["board", &y.to_string(), "3000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("both boards credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
	let info = a.ok(&["info"]);
	println!("info.lightning: {}", info["server_info"]["lightning"]);

	// Y's invoice, the wallet asked to pay it from X: refused before
	// anything is signed.
	let (inv_y0, _) = invoice(&py, y, 50_000, "y-from-x");
	let before = (arca_held(&a, &x), arca_held(&a, &y));
	a.refused(&["lightning", "pay", &inv_y0, "--asset", &x.to_string()], "a coin in one asset never pays an invoice in another");
	assert_eq!((arca_held(&a, &x), arca_held(&a, &y)), before, "nothing signed, nothing moved");
	assert!(a.ok(&["lightning", "payments"]).as_object().unwrap().is_empty(), "no payment recorded");

	// X's invoice from X's leaf, Y's from Y's: each paid at the payee's node.
	let channels0 = [(channel_balance(&ox, x), channel_balance(&px, x)), (channel_balance(&oy, y), channel_balance(&py, y))];
	for (k, (asset, payee, amount, label)) in [(x, &px, 100_000u64, "x-paid"), (y, &py, 200_000, "y-paid")].into_iter().enumerate() {
		let held0 = arca_held(&a, &asset);
		let (inv, hash) = invoice(payee, asset, amount, label);
		let p = a.ok(&["lightning", "pay", &inv, "--asset", &asset.to_string()]);
		assert_eq!(p["paying"]["fee"], fee(amount).to_string());
		assert_eq!(p["payment"]["state"], "paid", "{}", p);
		let pre = p["payment"]["preimage"].as_str().unwrap();
		use elements::hashes::{sha256, Hash};
		assert_eq!(sha256::Hash::hash(&unhex(pre)).to_string(), hash, "the wallet holds the proof of payment");
		let st = invoice_status(payee, label);
		assert_eq!((st["status"].as_str(), st["amount_received_msat"].as_u64()), (Some("paid"), Some(amount * 1000)), "{}", st);
		let margins: u64 = p["margins"]["checkpoints"].as_array().unwrap().iter().map(|m| m.as_str().unwrap().parse::<u64>().unwrap())
			.sum::<u64>() + p["margins"]["reassignment"].as_str().unwrap().parse::<u64>().unwrap();
		let held1 = arca_held(&a, &asset);
		println!("books in {}: the wallet held {}, holds {}: {} paid + {} the operator's fee + {} the transactions' margins", asset,
			held0, held1, amount, fee(amount), margins);
		assert_eq!(held0 - held1, amount + fee(amount) + margins);
		let o = if k == 0 { &ox } else { &oy };
		// The channel settles the HTLC a moment after the payment completes.
		let (base, a) = (channels0[k], asset);
		r.wait("the channels settled", || settled_balance(o, a) == base.0 - amount && settled_balance(payee, a) == base.1 + amount).await;
		let (o1, p1) = (channel_balance(o, asset), channel_balance(payee, asset));
		println!("channels in {}: the operator's node {} -> {}, the payee's {} -> {}", asset, channels0[k].0, o1, channels0[k].1, p1);
		assert_eq!((channels0[k].0 - o1, p1 - channels0[k].1), (amount, amount));
	}

	// The same invoice again: the wallet refuses it, paid already.
	let inv_x = invoice_status(&px, "x-paid")["bolt11"].as_str().unwrap().to_string();
	a.refused(&["lightning", "pay", &inv_x], "already");

	// An invoice the payee drops: the payment fails, and its leaf comes
	// back to the wallet, the operator's fee included.
	let held0 = arca_held(&a, &x);
	let (inv_f, hash_f) = invoice(&px, x, 30_000, "x-fails");
	px.ok("delinvoice", json!({ "label": "x-fails", "status": "unpaid" }));
	let p = a.ok(&["lightning", "pay", &inv_f]);
	assert_eq!(p["payment"]["state"], "returned", "{}", p);
	println!("x-fails: {}", p["payment"]);
	let payments = a.ok(&["lightning", "payments"]);
	assert_eq!(payments[&hash_f]["state"], "returned");
	assert!(payments[&hash_f]["reason"].is_string(), "{}", payments[&hash_f]);
	let held1 = arca_held(&a, &x);
	println!("x-fails: the wallet held {} in X, holds {}: only the margins of the payment's transfer and of its return", held0, held1);
	assert!(held0 - held1 < 1_000, "the leaf of 30,040 came back, less the margins only: {} -> {}", held0, held1);
	let coins = a.ok(&["coins"]);
	let back = coins.as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == x.to_string()).count();
	assert!(back >= 1, "{}", coins);

	// Every payment, as the wallet keeps it.
	let payments = a.ok(&["lightning", "payments"]);
	assert_eq!(payments.as_object().unwrap().len(), 3);

	// The same wallet receives in X and in Y: each invoice its own, paid by
	// the payer's node, held until the wallet holds its leaf and claims it.
	// A fee above the wallet's bound: refused before anything is asked.
	a.refused(&["lightning", "receive", &x.to_string(), "100000", "--max-fee-ppm", "1"], "above the wallet's bound");
	assert!(a.ok(&["lightning", "receives"]).as_object().unwrap().is_empty());

	for (asset, payer, operator, amount) in [(x, &px, &ox, 100_000u64), (y, &py, &oy, 200_000)] {
		let held0 = arca_held(&a, &asset);
		let (o0, p0) = (channel_balance(operator, asset), channel_balance(payer, asset));
		let inv = a.ok(&["lightning", "receive", &asset.to_string(), &amount.to_string(), "--description", "into the tree"]);
		assert_eq!((inv["fee"].as_str(), inv["value"].as_str()), (Some(fee(amount).to_string().as_str()),
			Some((amount - fee(amount)).to_string().as_str())));
		let hash = inv["payment_hash"].as_str().unwrap().to_string();
		let (rpc, bolt11) = (payer.rpc_path(), inv["invoice"].as_str().unwrap().to_string());
		let paying = std::thread::spawn(move || sequentia_ext::lightning::call_at(&rpc, "pay", json!({ "bolt11": bolt11 })));
		let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
		while receive_state(&r, &hash).await != "accepted" {
			assert!(std::time::Instant::now() < deadline, "the payment was never held");
			tokio::time::sleep(std::time::Duration::from_millis(200)).await;
		}
		// The wallet takes up the operator's participation for its leaf; the
		// next round makes it.
		a.ok(&["sync"]);
		let built = r.server.rounds.run_round_of(asset).await.unwrap().expect("a round");
		r.produce().await;
		r.bury().await;
		r.round_state(&built.tx.txid(), RoundState::Final).await;
		assert!(!paying.is_finished(), "nothing is settled before the wallet holds its leaf");
		// The wallet validates the leaf, hands over its authorisations, holds
		// it, and claims it with the preimage.
		let s = a.ok(&["sync"]);
		println!("sync: lightning {}", s["lightning"]);
		let paid = paying.join().unwrap().unwrap();
		println!("the payer's node: {} {}", paid["status"], paid["amount_sent_msat"]);
		assert_eq!(paid["status"], "complete");
		assert_eq!(paid["payment_preimage"].as_str().map(|p| elements::hashes::sha256::Hash::hash(&unhex(p)).to_string()),
			Some(hash.clone()), "the preimage the wallet handed over opens the hash");
		let rec = &a.ok(&["lightning", "receives"])[&hash];
		assert_eq!(rec["state"], "received", "{}", rec);
		assert!(rec.get("preimage").is_none() && rec.get("request").is_none(), "{}", rec);
		let (sa, op, pa) = (asset, operator, payer);
		r.wait("the channels settled", || settled_balance(op, sa) == o0 + amount && settled_balance(pa, sa) == p0 - amount).await;
		let held1 = arca_held(&a, &asset);
		println!("books in {}: the payer's channel {} -> {}, the operator's {} -> {}; the wallet held {}, holds {}: {} received, less the \
			fee {} and {} of the claim's margins", asset, p0, p0 - amount, o0, o0 + amount, held0, held1, amount, fee(amount),
			amount - fee(amount) - (held1 - held0));
		assert!(held1 > held0 && held1 - held0 <= amount - fee(amount) && amount - fee(amount) - (held1 - held0) < 2_000);
		let coins = a.ok(&["coins"]);
		assert!(coins.as_array().unwrap().iter().all(|c| c["state"] != "receiving"), "the leaf received is claimed");
	}
	drop((ox, px, oy, py));
	let _ = std::fs::remove_dir_all(&a.dir);
}

/// The payment held at the operator's node for `hash`, as the server says.
async fn receive_state(r: &Running, hash: &str) -> String {
	let h: [u8; 32] = unhex(hash).try_into().unwrap();
	r.server.receives.status(&h).await.unwrap().map(|row| row.state.name().to_string()).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Receiving into the tree against an operator that does not answer, a
// restore from the mnemonic, and the operator's cap on what it holds out
// ---------------------------------------------------------------------------


fn mtp(r: &Running) -> u32 {
	common::node::median_time(&r.rt)
}

async fn advance(r: &Running, s: u32) {
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, s));
	r.synced().await;
}

async fn receive_row(r: &Running, hash: &str) -> Option<server::store::ReceiveRow> {
	let h: [u8; 32] = unhex(hash).try_into().unwrap();
	r.server.receives.status(&h).await.unwrap()
}

fn coin_of(w: &Arca, leaf: &str) -> Value {
	w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).cloned().unwrap_or(Value::Null)
}

/// A server whose Lightning delays a test can wait out: the operator's
/// delay one unit, the owner's least two, a receive's window ten minutes.
async fn short_delays() -> Running {
	Running::start_seqln(|c, _, _| {
		c.fees.lightning_ppm = 1_000;
		c.lightning.operator_delay_units = 1;
		c.lightning.owner_delay_units = 2;
		c.lightning.send_timeout_seconds = 8 * 3600;
		c.lightning.send_stall_margin_seconds = 3600;
		c.lightning.poll_seconds = 1;
		c.lightning.retry_seconds = 10;
		c.lightning.receive_window_seconds = 600;
	}).await
}

/// The operator's node in X, holding invoices, and a payer with a channel
/// to it; X's leg configured and up.
async fn leg_in_x(lnd: &std::path::PathBuf, r: &mut Running, tag: &str)
	-> (sequentia_ext::lightning::LightningNode, sequentia_ext::lightning::LightningNode)
{
	let x = r.x;
	let (ox, px) = tokio::task::block_in_place(|| {
		let ox = node(&r.rt, &mut r.purse, lnd, &format!("{}o", tag), true, x, 2_000_000_000);
		let px = node(&r.rt, &mut r.purse, lnd, &format!("{}p", tag), true, x, 1_000_000_000);
		ox.open_channel(&r.rt, &px, x, 1_000_000_000, 300_000_000);
		(ox, px)
	});
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let mut config = r.config.clone();
	for a in config.assets.iter_mut() {
		if a.asset == x.to_string() {
			a.lightning = Some(LegSection { rpc: ox.rpc_path() });
		}
	}
	r.server.reload(&config).await.unwrap();
	r.config = config;
	let g = r.server.gateway.clone();
	r.wait("X's leg up", || g.leg(&x, true).is_ok()).await;
	(ox, px)
}

fn wallet_at(name: &str, server: &str, r: &Running) -> Arca {
	let a = Arca::new(name);
	a.ok(&["create", "--server", server, "--node-url", &r.node_url(), "--node-user", "arca", "--exit-delay-units", "4",
		"--min-exit-delay-units", "1"]);
	a
}

/// `a` asks to receive `amount` of X and `payer` pays the invoice (in a
/// thread) until the operator holds the payment. Returns the hash and the
/// payer's thread.
async fn held(r: &Running, a: &Arca, payer: &sequentia_ext::lightning::LightningNode, amount: u64)
	-> (String, std::thread::JoinHandle<Result<Value, String>>)
{
	let inv = a.ok(&["lightning", "receive", &r.x.to_string(), &amount.to_string()]);
	let hash = inv["payment_hash"].as_str().unwrap().to_string();
	let (rpc, bolt11) = (payer.rpc_path(), inv["invoice"].as_str().unwrap().to_string());
	let paying = std::thread::spawn(move || sequentia_ext::lightning::call_at(&rpc, "pay", json!({ "bolt11": bolt11 })));
	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
	while !receive_row(r, &hash).await.is_some_and(|x| x.state.name() == "accepted") {
		assert!(std::time::Instant::now() < deadline, "the payment was never held");
		tokio::time::sleep(std::time::Duration::from_millis(200)).await;
	}
	(hash, paying)
}

/// The round of X that makes the leaf the operator wants, mined and final.
async fn leaf_round(r: &Running) {
	let built = r.server.rounds.run_round_of(r.x).await.unwrap().expect("a round");
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
}

/// The transaction spending `spk`'s output on the chain, if one is in a block
/// of the last `back` and spends an output paying `spk`: the output, the
/// spender, and the median time of the spender's block.
fn spent_on_chain(r: &Running, spk: &Script, back: u64) -> Option<(elements::OutPoint, elements::Transaction, u32)> {
	let c = r.rt.client();
	let tip = c.blockchain_info().unwrap().blocks;
	let mut outs = vec![];
	for h in tip.saturating_sub(back)..=tip {
		let b = c.block(&c.block_hash(h).unwrap()).unwrap();
		for t in &b.txdata {
			for (v, o) in t.output.iter().enumerate() {
				if o.script_pubkey == *spk {
					outs.push(elements::OutPoint::new(t.txid(), v as u32));
				}
			}
		}
		for t in &b.txdata {
			if let Some(i) = t.input.iter().find(|i| outs.contains(&i.previous_output)) {
				let header: Value = c.call("getblockheader", &[json!(c.block_hash(h).unwrap().to_string())]).unwrap();
				return Some((i.previous_output, t.clone(), header["mediantime"].as_u64().unwrap() as u32));
			}
		}
	}
	None
}

/// R7j F2 (part 1), turned around (D62). The operator takes the preimage of a
/// payment received into the tree, settles the payment, and co-signs
/// nothing: the claim reaches it with its transfer's first signature
/// spoiled, and every claim is answered 500, the mailbox empty. The wallet
/// syncs only when its schedule says. Once its claim has gone out
/// unanswered, its schedule names the leaf's home date (the timeout less its
/// exit delay, the unroll and a margin), and the sync then takes the leaf
/// home by its claim: the claim is in a block before the leaf's timeout,
/// when the operator's refund could first open, so the operator's refund is
/// refused, and the operator ends with the payment it settled and not the
/// leaf it funded. The wallet never says the payment failed.
#[tokio::test(flavor = "multi_thread")]
async fn d62_a_preimage_taken_and_unanswered_is_claimed_on_the_chain_before_the_refund_opens() {
	let Some(lnd) = lightningd("d62_a_preimage_taken_and_unanswered_is_claimed_on_the_chain_before_the_refund_opens") else { return };
	let mut r = short_delays().await;
	let x = r.x;
	let (ox, px) = leg_in_x(&lnd, &mut r, "d62a").await;
	let p = common::proxy::Proxy::start(&r.url());
	let a = wallet_at("D62A", &p.url.clone(), &r);
	let (hash, paying) = held(&r, &a, &px, 100_000).await;
	a.ok(&["sync"]);
	leaf_round(&r).await;
	let timeout = receive_row(&r, &hash).await.unwrap().timeout.unwrap();
	p.rewrite(Some(std::sync::Arc::new(|path: &str, _req: &Value, _status: u16, v: &mut Value| {
		if path == "/v1/lightning_receive_claim" {
			*v = json!({"code": "internal", "message": "the operator took the preimage and answers nothing"});
			return Some(500);
		}
		if path == "/v1/mailbox_read" {
			if let Some(m) = v.get_mut("messages") {
				*m = json!([]);
			}
		}
		None
	})));
	p.rewrite_request(Some(std::sync::Arc::new(|path: &str, body: &mut Value| {
		if path == "/v1/lightning_receive_claim" {
			if let Some(s) = body["inputs"][0]["checkpoint_sig"].as_str() {
				let mut t = s.to_string();
				let last = if t.ends_with('0') { "1" } else { "0" };
				t.replace_range(t.len() - 1.., last);
				body["inputs"][0]["checkpoint_sig"] = json!(t);
			}
		}
	})));
	// The sync that hands the preimage over, its claim unanswered.
	let mut s = a.run(&["sync"]).1;
	println!("D62A the claim at {} ({} s before the timeout {}): lightning {} | schedule next {}", mtp(&r), timeout as i64 - mtp(&r) as i64,
		timeout, s["lightning"], s["schedule"]["next_sync_at"]);
	assert!(p.count("/v1/lightning_receive_claim") >= 1, "the wallet claimed");
	let paid = paying.join().unwrap().unwrap();
	println!("D62A the payer's node: {} (the operator settled with the preimage it took)", paid["status"]);
	assert_eq!(paid["status"], "complete");
	let leaf = a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["kind"] == "batch").cloned().expect("the htlc-1 leaf");
	let leaf_id = leaf["leaf_id"].as_str().unwrap().to_string();
	// The wallet wakes only when its schedule says, until the timeout.
	let mut wakes = 0;
	while let Some(n) = s["schedule"]["next_sync_at"].as_u64().map(|n| n as u32) {
		if n >= timeout || wakes >= 60 {
			break;
		}
		if n > mtp(&r) {
			advance(&r, n - mtp(&r)).await;
		} else {
			advance(&r, 60).await;
		}
		s = a.run(&["sync"]).1;
		// The chain goes on: what the sync broadcast is mined.
		r.produce().await;
		wakes += 1;
		println!("D62A wake {} at {} ({} s before the timeout): coin {} | lightning {} | home {} | exits {} | next {}", wakes, mtp(&r),
			timeout as i64 - mtp(&r) as i64, coin_of(&a, &leaf_id)["state"], s["lightning"], s["home"], s["exits"],
			s["schedule"]["next_sync_at"]);
		if coin_of(&a, &leaf_id)["state"] == "exited" {
			break;
		}
	}
	let rec = CoinRecordOf::of(&a, &leaf_id);
	let claimed = spent_on_chain(&r, &rec.0, 1500);
	println!("D62A the leaf on the chain and its spend: {:?}", claimed.as_ref().map(|(o, t, m)| (o.to_string(), t.txid().to_string(), *m)));
	let (op, claim, at) = claimed.unwrap_or_else(|| panic!("the wallet did not take the leaf home before its timeout {}: coin {} | its \
		schedule {} | the receive {}", timeout, coin_of(&a, &leaf_id), s["schedule"], a.ok(&["lightning", "receives"])[&hash]));
	assert!(at < timeout, "the claim is in a block before the timeout ({} >= {})", at, timeout);
	assert!(claim.input.iter().any(|i| i.previous_output == op && i.witness.script_witness.iter().any(|w| w.len() == 32
		&& elements::hashes::sha256::Hash::hash(w).to_string() == hash)), "the leaf comes home by its claim, with the preimage");
	// The operator's refund, once it could open: the output is spent.
	if mtp(&r) < timeout + 600 {
		advance(&r, timeout + 600 - mtp(&r)).await;
	}
	let refund = rec.refund(&r, op, x);
	let sent: Result<Value, _> = r.rt.client().call("sendrawtransaction", &[json!(elements::encode::serialize_hex(&refund))]);
	println!("D62A the operator's refund past the timeout: {:?}", sent);
	assert!(sent.is_err(), "the operator's refund finds the leaf claimed");
	let rec_w = a.ok(&["lightning", "receives"])[&hash].clone();
	println!("D62A the wallet's receive: {} | balance {}", rec_w, a.ok(&["balance"]));
	assert_ne!(rec_w["state"], "failed", "the payment's preimage went out: never failed");
	drop((ox, px));
	let _ = std::fs::remove_dir_all(&a.dir);
}

/// A received leaf's record in a wallet, as the operator would build its
/// refund: its script and policy.
struct CoinRecordOf(Script, arca_covenant::LeafPolicy);

impl CoinRecordOf {
	fn of(w: &Arca, leaf: &str) -> CoinRecordOf {
		let rec = arca_covenant::CoinRecord::from_bytes(&unhex(w.ok(&["record", leaf])["record"].as_str().unwrap())).unwrap();
		let arca_covenant::CoinRecord::Leaf { record, .. } = rec else { panic!("a round's leaf") };
		let s = common::running::keypair("operator");
		let policy = arca_covenant::LeafPolicy { owner: record.owner, operator: s.x_only_public_key().0, salt: record.salt(),
			chain: record.chain, exit_delay: record.exit_delay, htlc: record.htlc };
		CoinRecordOf(policy.script_pubkey(), policy)
	}

	/// The operator's refund of the leaf's output `op`, signed.
	fn refund(&self, r: &Running, op: elements::OutPoint, x: AssetId) -> elements::Transaction {
		let tx = r.rt.client().raw_transaction(&op.txid).unwrap();
		let value = tx.output[op.vout as usize].value.explicit().unwrap();
		let to = arca_covenant::ExplicitOutput::new(x, value - 5_000, Script::from([0u8, 20].into_iter().chain([7u8; 20]).collect::<Vec<u8>>()));
		let ks = self.1.refund_tx(op, x, value, &[to], &arca_covenant::FeeSource::Reserve).unwrap();
		let sighash = ks.sighash(r.rt.client().genesis_hash().unwrap()).unwrap();
		let sig = arca_covenant::sign::sign_digest(&common::running::keypair("operator"), &sighash, &[7u8; 32]);
		ks.finish(vec![sig.as_ref().to_vec()]).tx
	}
}

/// R7j F2 (part 2), turned around (D62): an honest operator, and a wallet
/// that syncs in the band of one operator's delay before the timeout, where
/// the operator's refund (both its locks run at once) opens before the
/// wallet could take the leaf home by its claim. The wallet does not hand
/// the preimage over: the payment is failed back to its payer, and the leaf
/// is the operator's, held by the wallet nowhere.
#[tokio::test(flavor = "multi_thread")]
async fn d62_in_the_band_before_the_timeout_the_wallet_keeps_the_preimage() {
	let Some(lnd) = lightningd("d62_in_the_band_before_the_timeout_the_wallet_keeps_the_preimage") else { return };
	let mut r = short_delays().await;
	let (ox, px) = leg_in_x(&lnd, &mut r, "d62b").await;
	let a = wallet_at("D62B", &r.url(), &r);
	let (hash, paying) = held(&r, &a, &px, 100_000).await;
	a.ok(&["sync"]);
	leaf_round(&r).await;
	let timeout = receive_row(&r, &hash).await.unwrap().timeout.unwrap();
	// Three steps of two 60-s blocks and the exit delay of 2,048 s end 120 s
	// past the timeout: inside the old rule's band (up to the operator's
	// delay past it), outside the safe one.
	let target = timeout - 2048 - 3 * 120 + 120;
	if mtp(&r) < target {
		advance(&r, target - mtp(&r)).await;
	}
	let s = a.ok(&["sync"]);
	let rec = a.ok(&["lightning", "receives"])[&hash].clone();
	let row = receive_row(&r, &hash).await.unwrap();
	println!("D62B the wallet's sync at {} ({} s before the timeout {}): lightning {} | the receive {} | the server knows the preimage: {}",
		mtp(&r), timeout as i64 - mtp(&r) as i64, timeout, s["lightning"], rec, row.preimage.is_some());
	assert!(row.preimage.is_none(), "the wallet handed the preimage over in the band: the operator's refund opens first");
	assert_eq!(rec["state"], "failed", "{}", rec);
	// Past the time to claim the payment is failed back to its payer.
	while mtp(&r) < timeout + 512 + 3600 + 300 {
		advance(&r, 1200).await;
	}
	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
	while !receive_row(&r, &hash).await.is_some_and(|x| x.state.name() == "cancelled") {
		assert!(std::time::Instant::now() < deadline, "the payment was never failed back");
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;
	}
	let paid = paying.join().unwrap();
	println!("D62B the payer's node: {:?}", paid.as_ref().map(|v| v["status"].clone()));
	assert!(paid.is_err() || paid.as_ref().unwrap()["status"] != "complete", "the payer is repaid");
	let leaf = a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["kind"] == "batch").cloned().unwrap_or(Value::Null);
	println!("D62B the leaf at the wallet: {} | balance {}", leaf, a.ok(&["balance"])["arca"]);
	assert!(!matches!(leaf["state"].as_str(), Some("receiving") | Some("live")), "the leaf is not the wallet's: {}", leaf);
	drop((ox, px));
	let _ = std::fs::remove_dir_all(&a.dir);
}

/// D62: the schedule knows the Lightning states. A wallet that asks to
/// receive syncs only when its schedule says: while the invoice waits to be
/// paid, while the payment is held and its leaf wanted in a round, and once
/// the leaf is its own, the schedule names a time within the operator's
/// window, so the wallet takes the leaf up and claims it, and the payment
/// completes.
#[tokio::test(flavor = "multi_thread")]
async fn d62_the_schedule_wakes_the_wallet_for_a_payment_held_until_it_is_claimed() {
	let Some(lnd) = lightningd("d62_the_schedule_wakes_the_wallet_for_a_payment_held_until_it_is_claimed") else { return };
	let mut r = short_delays().await;
	let (ox, px) = leg_in_x(&lnd, &mut r, "d62c").await;
	let a = wallet_at("D62C", &r.url(), &r);
	let window = 600u64;
	let (hash, paying) = held(&r, &a, &px, 100_000).await;
	let s = a.ok(&["sync"]);
	let now = mtp(&r) as u64;
	println!("D62C the payment held, the leaf wanted in the next round: schedule {}", s["schedule"]);
	let next = s["schedule"]["next_sync_at"].as_u64();
	assert!(next.is_some_and(|n| n <= now + window / 2), "the schedule wakes the wallet within the window: {}", s["schedule"]);
	leaf_round(&r).await;
	// The wallet wakes when its schedule says, until the payment completes.
	let mut s = s;
	for k in 0..8 {
		let n = s["schedule"]["next_sync_at"].as_u64().unwrap_or_else(|| panic!("the schedule names no time with the payment held: {}",
			s["schedule"])) as u32;
		if n > mtp(&r) {
			advance(&r, n - mtp(&r)).await;
		}
		s = a.ok(&["sync"]);
		println!("D62C wake {} at {}: lightning {} | next {}", k, mtp(&r), s["lightning"], s["schedule"]["next_sync_at"]);
		if a.ok(&["lightning", "receives"])[&hash]["state"] == "received" {
			break;
		}
	}
	assert_eq!(a.ok(&["lightning", "receives"])[&hash]["state"], "received");
	assert_eq!(paying.join().unwrap().unwrap()["status"], "complete");
	drop((ox, px));
	let _ = std::fs::remove_dir_all(&a.dir);
}
/// What `w` holds off the chain in `asset`, by standing, summed.
fn held_in(w: &Arca, asset: &AssetId) -> u64 {
	arca_held(w, asset)
}

/// R7j F3, turned around (D63). A wallet pays an invoice over Lightning
/// (paid: its htlc-1 leaf the operator's), has one fail (its leaf returned),
/// and receives one (claimed). Its device is lost and a wallet is restored
/// from its mnemonic: its balance is the lost wallet's, the paid leaf is
/// held spent by the payment, and a payment of the whole balance goes
/// through.
#[tokio::test(flavor = "multi_thread")]
async fn d63_a_restore_meets_leaves_that_went_over_lightning() {
	let Some(lnd) = lightningd("d63_a_restore_meets_leaves_that_went_over_lightning") else { return };
	let mut r = short_delays().await;
	let x = r.x;
	let xs = x.to_string();
	let (ox, px) = leg_in_x(&lnd, &mut r, "d63a").await;
	let url = r.url();
	let a = wallet_at("D63A", &url, &r);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, x, 5_000_000);
	r.produce().await;
	a.ok(&["board", &xs, "2000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
	let (inv, _) = invoice(&px, x, 100_000, "d63-paid");
	let paid = a.ok(&["lightning", "pay", &inv]);
	let htlc_paid = paid["payment"]["htlc_leaf_id"].as_str().unwrap().to_string();
	assert_eq!(paid["payment"]["state"], "paid");
	let (inv_f, _) = invoice(&px, x, 30_000, "d63-fails");
	px.ok("delinvoice", json!({ "label": "d63-fails", "status": "unpaid" }));
	assert_eq!(a.ok(&["lightning", "pay", &inv_f])["payment"]["state"], "returned");
	let (hash, paying) = held(&r, &a, &px, 60_000).await;
	a.ok(&["sync"]);
	leaf_round(&r).await;
	a.ok(&["sync"]);
	assert_eq!(paying.join().unwrap().unwrap()["status"], "complete");
	assert_eq!(a.ok(&["lightning", "receives"])[&hash]["state"], "received");
	a.ok(&["sync"]);
	let bal_a = held_in(&a, &x);
	println!("D63A the wallet's balance in X: {} | the paid leaf {}", bal_a, coin_of(&a, &htlc_paid));

	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap();
	let a2 = Arca::new("D63A2");
	let made = a2.ok(&["create", "--server", &url, "--node-url", &r.node_url(), "--node-user", "arca", "--exit-delay-units", "4",
		"--min-exit-delay-units", "1", "--mnemonic", mnemonic.trim()]);
	println!("D63A restore: served {} restored {} not_recovered {}", made["restore"]["served"], made["restore"]["restored"],
		made["restore"]["not_recovered"]);
	a2.ok(&["sync"]);
	let bal_b = held_in(&a2, &x);
	let leaf_b = coin_of(&a2, &htlc_paid);
	println!("D63A the restored wallet's balance in X: {} | the paid leaf {} | payments {}", bal_b, leaf_b, a2.ok(&["lightning", "payments"]));
	assert_eq!(bal_b, bal_a, "the restored balance is the lost wallet's");
	assert!(matches!(leaf_b["state"].as_str(), Some("spent") | None), "the paid leaf is not held: {}", leaf_b);
	let b = wallet_at("D63B", &url, &r);
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let (ok, v) = a2.run(&["send", &req, "--amount", &(bal_b.saturating_sub(20_000)).to_string(), "--asset", &xs]);
	println!("D63A the restored wallet pays its balance less 20,000: ok={} {}", ok, if ok { v["inputs"].clone() } else { v["error"].clone() });
	assert!(ok, "{}", v);
	drop((ox, px));
	for w in [&a, &a2, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// The second review's F2, turned around (D63, D65). A asks to receive over
/// Lightning; the payment is held, its leaf made in a round and taken up,
/// and the wallet's claim never reaches the operator. The device is lost.
/// A wallet restored from the mnemonic is served the leaf (bound to its
/// mailbox key when the leaf was made), holds it `receiving` with the
/// payment rebuilt from its terms and the nonce, and its sync claims it:
/// the payment settles, and the payer's pay completes.
#[tokio::test(flavor = "multi_thread")]
async fn d63_a_restore_meets_a_received_leaf_not_yet_claimed() {
	let Some(lnd) = lightningd("d63_a_restore_meets_a_received_leaf_not_yet_claimed") else { return };
	let mut r = short_delays().await;
	let (ox, px) = leg_in_x(&lnd, &mut r, "d63b").await;
	let url = r.url();
	let p = common::proxy::Proxy::start(&url);
	let a = wallet_at("D63R", &p.url.clone(), &r);
	let (hash, paying) = held(&r, &a, &px, 100_000).await;
	a.ok(&["sync"]);
	leaf_round(&r).await;
	// The wallet's claim never reaches the operator.
	p.hold("/v1/lightning_receive_claim");
	a.run(&["sync"]);
	let leaf = a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["kind"] == "batch")
		.map(|c| c["leaf_id"].as_str().unwrap().to_string()).expect("the received leaf, held, unclaimed");
	assert!(receive_row(&r, &hash).await.unwrap().preimage.is_none(), "the claim never reached the operator");
	assert!(!paying.is_finished(), "nothing settled before the claim");
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap().trim().to_string();
	let a2 = Arca::new("D63R2");
	let made = a2.ok(&["create", "--server", &url, "--node-url", &r.node_url(), "--node-user", "arca", "--exit-delay-units", "4",
		"--min-exit-delay-units", "1", "--mnemonic", &mnemonic]);
	println!("D63R the restore: served {} | restored {} | not_recovered {}", made["restore"]["served"], made["restore"]["restored"],
		made["restore"]["not_recovered"]);
	let c = coin_of(&a2, &leaf);
	println!("D63R the leaf in the restored wallet: {} | its receives {}", c, a2.ok(&["lightning", "receives"]));
	assert!(!c.is_null(), "the unclaimed received leaf is served to the restore");
	let s = a2.ok(&["sync"]);
	println!("D63R the restored wallet's sync: lightning {}", s["lightning"]);
	let paid = paying.join().unwrap().unwrap();
	println!("D63R the payer's node: {}", paid["status"]);
	assert_eq!(paid["status"], "complete");
	assert_eq!(a2.ok(&["lightning", "receives"])[&hash]["state"], "received");
	assert!(a2.ok(&["coins"]).as_array().unwrap().iter().all(|c| c["state"] != "receiving"), "the leaf is claimed");
	drop((ox, px));
	for w in [&a, &a2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// D62 and D63 together. The operator takes a received payment's preimage,
/// settles the payment and co-signs nothing (its claim's transfer spoiled on
/// the way, every claim answered 500, the mailbox empty); the wallet's
/// device is lost right after its claim. A wallet restored from the
/// mnemonic, against the same operator, finds the leaf, holds it
/// `receiving`, and, its own claim unanswered too, takes the leaf home by
/// its claim on the schedule's date: the claim is in a block before the
/// leaf's timeout, so the operator's refund finds the leaf claimed.
#[tokio::test(flavor = "multi_thread")]
async fn d62_d63_a_restored_wallet_claims_a_leaf_whose_preimage_the_operator_took() {
	let Some(lnd) = lightningd("d62_d63_a_restored_wallet_claims_a_leaf_whose_preimage_the_operator_took") else { return };
	let mut r = short_delays().await;
	let x = r.x;
	let (ox, px) = leg_in_x(&lnd, &mut r, "d6263").await;
	let p = common::proxy::Proxy::start(&r.url());
	let a = wallet_at("D6263A", &p.url.clone(), &r);
	let (hash, paying) = held(&r, &a, &px, 100_000).await;
	a.ok(&["sync"]);
	leaf_round(&r).await;
	let timeout = receive_row(&r, &hash).await.unwrap().timeout.unwrap();
	p.rewrite(Some(std::sync::Arc::new(|path: &str, _req: &Value, _status: u16, v: &mut Value| {
		if path == "/v1/lightning_receive_claim" {
			*v = json!({"code": "internal", "message": "the operator took the preimage and answers nothing"});
			return Some(500);
		}
		if path == "/v1/mailbox_read" {
			if let Some(m) = v.get_mut("messages") {
				*m = json!([]);
			}
		}
		None
	})));
	p.rewrite_request(Some(std::sync::Arc::new(|path: &str, body: &mut Value| {
		if path == "/v1/lightning_receive_claim" {
			if let Some(s) = body["inputs"][0]["checkpoint_sig"].as_str() {
				let mut t = s.to_string();
				let last = if t.ends_with('0') { "1" } else { "0" };
				t.replace_range(t.len() - 1.., last);
				body["inputs"][0]["checkpoint_sig"] = json!(t);
			}
		}
	})));
	a.run(&["sync"]);
	let leaf_id = a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["kind"] == "batch")
		.map(|c| c["leaf_id"].as_str().unwrap().to_string()).expect("the htlc-1 leaf");
	assert_eq!(paying.join().unwrap().unwrap()["status"], "complete", "the operator settled with the preimage it took");
	let rec = CoinRecordOf::of(&a, &leaf_id);
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap().trim().to_string();
	let a2 = Arca::new("D6263A2");
	let made = a2.ok(&["create", "--server", &p.url, "--node-url", &r.node_url(), "--node-user", "arca", "--exit-delay-units", "4",
		"--min-exit-delay-units", "1", "--mnemonic", &mnemonic]);
	println!("D6263 the restore: served {} | restored {} | not_recovered {}", made["restore"]["served"], made["restore"]["restored"],
		made["restore"]["not_recovered"]);
	let c = coin_of(&a2, &leaf_id);
	println!("D6263 the leaf in the restored wallet: {} | receives {}", c, a2.ok(&["lightning", "receives"]));
	assert!(!c.is_null(), "the restored wallet finds the leaf");
	let mut s = a2.run(&["sync"]).1;
	let mut wakes = 0;
	while let Some(n) = s["schedule"]["next_sync_at"].as_u64().map(|n| n as u32) {
		if n >= timeout || wakes >= 60 || coin_of(&a2, &leaf_id)["state"] == "exited" {
			break;
		}
		if n > mtp(&r) {
			advance(&r, n - mtp(&r)).await;
		} else {
			advance(&r, 60).await;
		}
		s = a2.run(&["sync"]).1;
		r.produce().await;
		wakes += 1;
		println!("D6263 wake {} at {} ({} s before the timeout): coin {} | next {}", wakes, mtp(&r), timeout as i64 - mtp(&r) as i64,
			coin_of(&a2, &leaf_id)["state"], s["schedule"]["next_sync_at"]);
	}
	let claimed = spent_on_chain(&r, &rec.0, 1500);
	let (op, claim, at) = claimed.unwrap_or_else(|| panic!("the restored wallet did not take the leaf home before its timeout {}: coin {} \
		| schedule {}", timeout, coin_of(&a2, &leaf_id), s["schedule"]));
	println!("D6263 the claim {} in a block at {} ({} s before the timeout)", claim.txid(), at, timeout as i64 - at as i64);
	assert!(at < timeout, "the claim is in a block before the timeout");
	if mtp(&r) < timeout + 600 {
		advance(&r, timeout + 600 - mtp(&r)).await;
	}
	let refund = rec.refund(&r, op, x);
	let sent: Result<Value, _> = r.rt.client().call("sendrawtransaction", &[json!(elements::encode::serialize_hex(&refund))]);
	println!("D6263 the operator's refund past the timeout: {:?}", sent);
	assert!(sent.is_err(), "the operator's refund finds the leaf claimed");
	drop((ox, px));
	for w in [&a, &a2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
/// R7j F4, with the cap (D64). M asks to receive 45,000,000 of X and pays
/// it from its own node; the payment is held. M asks again for as much: the
/// operator's cap on receive leaves held and not yet claimed (here half its
/// pool in X) refuses it, naming the cap. M takes up its leaf, which the
/// next round makes, and never claims it; H boards 30,000,000 of X and asks
/// to refresh it: the pool still funds it, and H's refresh runs.
#[tokio::test(flavor = "multi_thread")]
async fn d64_unclaimed_receives_are_capped_and_a_refresh_runs() {
	let Some(lnd) = lightningd("d64_unclaimed_receives_are_capped_and_a_refresh_runs") else { return };
	let mut r = Running::start_seqln(|c, _, _| {
		c.fees.lightning_ppm = 1_000;
		c.lightning.operator_delay_units = 1;
		c.lightning.owner_delay_units = 2;
		c.lightning.send_timeout_seconds = 8 * 3600;
		c.lightning.send_stall_margin_seconds = 3600;
		c.lightning.poll_seconds = 1;
		c.lightning.retry_seconds = 10;
		c.lightning.receive_window_seconds = 600;
		// Half the operator's pool in X: one receive of 45,000,000 is
		// within it, a second is not.
		c.lightning.receive_cap_ppm = 500_000;
	}).await;
	let x = r.x;
	let xs = x.to_string();
	let (ox, px) = leg_in_x(&lnd, &mut r, "d64").await;
	let pool0 = r.server.wallet.balance().await.unwrap().get(&x).copied().unwrap_or(0);
	println!("D64 the operator's pool in X: {}", pool0);
	let url = r.url();
	let m = wallet_at("D64M", &url, &r);
	let first = m.ok(&["lightning", "receive", &xs, "45000000", "--max-fee-ppm", "10000"]);
	let hash = first["payment_hash"].as_str().unwrap().to_string();
	let (rpc, bolt11) = (px.rpc_path(), first["invoice"].as_str().unwrap().to_string());
	let paying = std::thread::spawn(move || sequentia_ext::lightning::call_at(&rpc, "pay", json!({ "bolt11": bolt11 })));
	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
	while !receive_row(&r, &hash).await.is_some_and(|x| x.state.name() == "accepted") {
		assert!(std::time::Instant::now() < deadline, "the payment was never held");
		tokio::time::sleep(std::time::Duration::from_millis(200)).await;
	}
	let (ok, v) = m.run(&["lightning", "receive", &xs, "45000000", "--max-fee-ppm", "10000"]);
	println!("D64 M asks to receive 45,000,000 again: ok={} {}", ok, if ok { v.clone() } else { v["error"].clone() });
	assert!(!ok, "a receive beyond the cap is refused: {}", v);
	assert!(v["error"]["message"].as_str().unwrap_or("").contains("cap"), "the refusal names the cap: {}", v);
	m.ok(&["sync"]);
	leaf_round(&r).await;
	let pool1 = r.server.wallet.balance().await.unwrap().get(&x).copied().unwrap_or(0);
	println!("D64 M's leaf made; the pool in X: {} (was {})", pool1, pool0);
	let h = wallet_at("D64H", &url, &r);
	let s = script(&h.ok(&["address"]));
	r.pay_to(s, x, 33_000_000);
	r.produce().await;
	h.ok(&["board", &xs, "30000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("H's board credited", || h.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	h.ok(&["sync"]);
	h.ok(&["participate"]);
	let (rounds, failed) = r.server.rounds.run_rounds().await.unwrap();
	println!("D64 a pass: rounds {} failed {:?}", rounds.len(), failed.iter().map(|(a, e)| format!("{} {}", a, e)).collect::<Vec<_>>());
	let mut waiting = vec![];
	for id in r.server.store.participations_in(server::store::ParticipationState::Pending).await.unwrap() {
		let row = r.server.store.participation(&id).await.unwrap().unwrap();
		waiting.push(row.waiting.clone());
	}
	println!("D64 pending participations after the pass: {:?}", waiting);
	assert!(waiting.is_empty() && rounds.len() == 1, "H's refresh runs: {:?}", waiting);
	drop(paying);
	drop((ox, px));
	for w in [&m, &h] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// A received leaf's way home against an operator that answers slowly, a
// client that wakes late, a restore that meets a claim the server recorded
// or a payment still held, and a wallet that has never synced
// ---------------------------------------------------------------------------

/// The committee's keys, as `sequentia-ext`'s regtest draws them.
fn stakers() -> Vec<String> {
	use elements::bitcoin::hashes::{sha256, Hash};
	(0..3).map(|i| {
		let seed = sha256::Hash::hash(format!("sequentia-ext regtest staker {}", i).as_bytes());
		let key = elements::bitcoin::secp256k1::SecretKey::from_slice(seed.as_byte_array()).unwrap();
		elements::bitcoin::PrivateKey::new(key, elements::bitcoin::NetworkKind::Test).to_wif()
	}).collect()
}

/// One block, a minute after the tip's: the chain at its pace.
fn block_a_minute(c: &sequentia_ext::rpc::Client, wifs: &[String]) {
	let h: Value = c.call("getblockheader", &[json!(c.best_block_hash().unwrap().to_string())]).unwrap();
	let t = h["time"].as_u64().unwrap() + 60;
	let _: Value = c.call("setmocktime", &[json!(t)]).unwrap();
	for _ in 0..40 {
		for w in wifs {
			if c.call::<Value>("generateposblock", &[json!(w), json!(wifs)]).is_ok() {
				return;
			}
		}
		std::thread::sleep(std::time::Duration::from_millis(250));
	}
	panic!("no block");
}

/// The output paying `spk` in a block of the last `back`, and the median time
/// of its block.
fn output_on_chain(r: &Running, spk: &Script, back: u64) -> Option<(elements::OutPoint, u32)> {
	let c = r.rt.client();
	let tip = c.blockchain_info().unwrap().blocks;
	for h in tip.saturating_sub(back)..=tip {
		let b = c.block(&c.block_hash(h).unwrap()).unwrap();
		for t in &b.txdata {
			for (v, o) in t.output.iter().enumerate() {
				if o.script_pubkey == *spk {
					let header: Value = c.call("getblockheader", &[json!(c.block_hash(h).unwrap().to_string())]).unwrap();
					return Some((elements::OutPoint::new(t.txid(), v as u32), header["mediantime"].as_u64().unwrap() as u32));
				}
			}
		}
	}
	None
}

/// Whether `t` spends `op` with the preimage of `hash` in its witness: the
/// owner's claim, not the operator's refund.
fn claims_with_preimage(t: &elements::Transaction, op: &elements::OutPoint, hash: &str) -> bool {
	t.input.iter().any(|i| i.previous_output == *op && i.witness.script_witness.iter().any(|w| w.len() == 32
		&& elements::hashes::sha256::Hash::hash(w).to_string() == hash))
}

/// The median time of the block holding `txid`.
fn block_time_of(r: &Running, txid: &elements::Txid) -> u32 {
	let c = r.rt.client();
	let v: Value = c.call("getrawtransaction", &[json!(txid.to_string()), json!(true)]).unwrap();
	let header: Value = c.call("getblockheader", &[v["blockhash"].clone()]).unwrap();
	header["mediantime"].as_u64().unwrap() as u32
}

/// An operator that takes a received payment's preimage and co-signs
/// nothing: every claim reaches it with its transfer's first signature
/// spoiled (so it records no transfer), and is answered 500.
fn spoiled_claims(path: &str, body: &mut Value) {
	if path == "/v1/lightning_receive_claim" {
		if let Some(s) = body["inputs"][0]["checkpoint_sig"].as_str() {
			let mut t = s.to_string();
			let last = if t.ends_with('0') { "1" } else { "0" };
			t.replace_range(t.len() - 1.., last);
			body["inputs"][0]["checkpoint_sig"] = json!(t);
		}
	}
}

/// The eleventh review's F2, turned around (D67). D62's operator takes a
/// received payment's preimage, settles the payment and co-signs nothing;
/// this one is slow besides. From the leaf's home date on, it answers every
/// request of the wallet's a block late (inside the wallet's 60-s timeout),
/// the chain running a block a minute, and in each sync serves `pages`
/// mailbox pages, each a notice of nothing past the wallet's cursor, before
/// an empty one; once the leaf is on the chain it tries its own refund at
/// every block. The wallet wakes only when its schedule says. Its sync takes
/// every exit step whose date has come before it asks the operator anything,
/// and again whenever one comes while it asks: the leaf's claim, with the
/// preimage, is in a block before the leaf's timeout, and no refund of the
/// operator's is ever taken.
async fn a_slow_operator_with_a_long_mailbox(test: &str, pages: usize) {
	let Some(lnd) = lightningd(test) else { return };
	let mut r = short_delays().await;
	let x = r.x;
	let (ox, px) = leg_in_x(&lnd, &mut r, &format!("slow{}", pages)).await;
	let p = common::proxy::Proxy::start(&r.url());
	let a = wallet_at(&format!("SLOW{}", pages), &p.url.clone(), &r);
	let (hash, paying) = held(&r, &a, &px, 100_000).await;
	a.ok(&["sync"]);
	leaf_round(&r).await;
	let timeout = receive_row(&r, &hash).await.unwrap().timeout.unwrap();
	let slow = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
	let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
	let refund_hex: std::sync::Arc<std::sync::Mutex<Option<String>>> = Default::default();
	let refunds: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
	let calls_log: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
	let client = r.rt.client().clone();
	let wifs = stakers();
	{
		let (slow, refund_hex, refunds, calls_log, wifs) = (slow.clone(), refund_hex.clone(), refunds.clone(), calls_log.clone(), wifs.clone());
		p.rewrite_request(Some(std::sync::Arc::new(move |path: &str, body: &mut Value| {
			spoiled_claims(path, body);
			if slow.load(std::sync::atomic::Ordering::SeqCst) {
				block_a_minute(&client, &wifs);
				let m = client.blockchain_info().unwrap().median_time;
				calls_log.lock().unwrap().push(format!("{} at median time {} ({} s from the timeout)", path, m, m as i64 - timeout as i64));
				let hx = refund_hex.lock().unwrap().clone();
				if let Some(hx) = hx {
					if let Ok(v) = client.call::<Value>("sendrawtransaction", &[json!(hx)]) {
						refunds.lock().unwrap().push(format!("{} at median time {}: {}", path, m, v));
					}
				}
			}
		})));
	}
	{
		let (slow, served) = (slow.clone(), served.clone());
		p.rewrite(Some(std::sync::Arc::new(move |path: &str, req: &Value, _status: u16, v: &mut Value| {
			if path == "/v1/lightning_receive_claim" {
				*v = json!({"code": "internal", "message": "the operator took the preimage and answers nothing"});
				return Some(500);
			}
			if path == "/v1/mailbox_read" {
				let mut msgs = vec![];
				if slow.load(std::sync::atomic::Ordering::SeqCst) && served.fetch_add(1, std::sync::atomic::Ordering::SeqCst) % (pages + 1) < pages {
					let after = req["after"].as_str().and_then(|a| a.parse::<i64>().ok()).unwrap_or(0);
					let k = served.load(std::sync::atomic::Ordering::SeqCst);
					let h = |s: &str| elements::hashes::sha256::Hash::hash(format!("nothing {} {}", s, k).as_bytes()).to_string();
					msgs.push(json!({"cursor": (after + 1).to_string(), "kind": "pending", "leaf_id": h("leaf"), "record": "",
						"notice": {"transfer_id": h("transfer"), "leaf_id": h("leaf"), "owner": h("owner"), "owner_nonce": h("nonce"),
							"asset": "00", "value": "1"}}));
				}
				v["messages"] = json!(msgs);
			}
			None
		})));
	}
	// The sync that hands the preimage over, its claim unanswered.
	let mut s = a.run(&["sync"]).1;
	assert_eq!(paying.join().unwrap().unwrap()["status"], "complete", "the operator settled with the preimage it took");
	let leaf_id = a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["kind"] == "batch").map(|c| c["leaf_id"].as_str().unwrap().to_string())
		.expect("the htlc-1 leaf");
	let rec = CoinRecordOf::of(&a, &leaf_id);
	let home_at = a.ok(&["lightning", "receives"])[&hash]["home_at"].as_u64().expect("a home date once the claim went out") as u32;
	println!("SLOW{} the claim handed over at {}: the leaf's home date {} ({} s before the timeout {})", pages, mtp(&r), home_at,
		timeout as i64 - home_at as i64, timeout);
	let mut wakes = 0;
	let mut on_chain = false;
	while let Some(n) = s["schedule"]["next_sync_at"].as_u64().map(|n| n as u32) {
		if wakes >= 80 || coin_of(&a, &leaf_id)["state"] == "exited" || mtp(&r) > timeout + 1800 {
			break;
		}
		if !on_chain {
			if let Some((op, m)) = output_on_chain(&r, &rec.0, 300) {
				on_chain = true;
				*refund_hex.lock().unwrap() = Some(elements::encode::serialize_hex(&rec.refund(&r, op, x)));
				println!("SLOW{} the leaf's output {} in a block of median time {} ({} s before the timeout)", pages, op, m, timeout as i64 - m as i64);
			}
		}
		// Before the home date the chain moves at once; from it, a block a
		// minute.
		if n + 600 < home_at {
			advance(&r, n.max(mtp(&r) + 60) - mtp(&r)).await;
		} else {
			while mtp(&r) < n {
				tokio::task::block_in_place(|| block_a_minute(r.rt.client(), &wifs));
			}
			r.synced().await;
		}
		let at = mtp(&r);
		if at >= home_at {
			slow.store(true, std::sync::atomic::Ordering::SeqCst);
		}
		let before = p.calls().len();
		s = a.run(&["sync"]).1;
		slow.store(false, std::sync::atomic::Ordering::SeqCst);
		tokio::task::block_in_place(|| block_a_minute(r.rt.client(), &wifs));
		if let Some(hx) = refund_hex.lock().unwrap().clone() {
			if let Ok(v) = r.rt.client().call::<Value>("sendrawtransaction", &[json!(hx)]) {
				refunds.lock().unwrap().push(format!("after the sync at {}: {}", mtp(&r), v));
			}
		}
		wakes += 1;
		println!("SLOW{} wake {} at {} -> {} ({} s from the timeout){}: coin {} | home {} | exits {} | next {} | calls {}", pages, wakes, at, mtp(&r),
			mtp(&r) as i64 - timeout as i64, if at >= home_at { " slow" } else { "" }, coin_of(&a, &leaf_id)["state"], s["home"], s["exits"],
			s["schedule"]["next_sync_at"], p.calls().len() - before);
	}
	let log = calls_log.lock().unwrap().clone();
	println!("SLOW{} {} slow answers, {} mailbox pages served; first {:?}; last {:?}", pages, log.len(), served.load(std::sync::atomic::Ordering::SeqCst),
		log.first(), log.last());
	let refunds = refunds.lock().unwrap().clone();
	let spent = spent_on_chain(&r, &rec.0, 2000);
	println!("SLOW{} the leaf's spend: {:?} | the operator's refunds taken: {:?}", pages, spent.as_ref().map(|(o, t, m)| (o.to_string(),
		t.txid().to_string(), *m, claims_with_preimage(t, o, &hash))), refunds);
	let (op, t, m) = spent.unwrap_or_else(|| panic!("the leaf was never spent on the chain: coin {}", coin_of(&a, &leaf_id)));
	assert!(claims_with_preimage(&t, &op, &hash), "the leaf's spend {} is the operator's refund, not the wallet's claim", t.txid());
	assert!(m < timeout, "the claim is in a block before the timeout ({} >= {})", m, timeout);
	assert!(refunds.is_empty(), "the operator's refund was taken: {:?}", refunds);
	drop((ox, px));
	let _ = std::fs::remove_dir_all(&a.dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn d67_a_slow_operator_with_no_mailbox_does_not_take_the_received_leaf() {
	a_slow_operator_with_a_long_mailbox("d67_a_slow_operator_with_no_mailbox_does_not_take_the_received_leaf", 0).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d67_a_slow_operator_with_two_mailbox_pages_does_not_take_the_received_leaf() {
	a_slow_operator_with_a_long_mailbox("d67_a_slow_operator_with_two_mailbox_pages_does_not_take_the_received_leaf", 2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d67_a_slow_operator_with_thirty_mailbox_pages_does_not_take_the_received_leaf() {
	a_slow_operator_with_a_long_mailbox("d67_a_slow_operator_with_thirty_mailbox_pages_does_not_take_the_received_leaf", 30).await;
}

/// D67: a client that wakes late. The operator takes the preimage and
/// co-signs nothing, and tries its refund at every block once the leaf is on
/// the chain. The wallet's first sync after its claim comes three quarters
/// of the leaf's margin (the larger of three blocks and an eighth of the
/// time from the leaf's round to its timeout) past the leaf's home date
/// (its timeout less its exit delay, two blocks for each step of its
/// unroll, and the margin), the receive window two hours so that the margin
/// is wide; from then it wakes when its schedule says, the chain a block a
/// minute. Its claim is in a block before the timeout, and the operator's
/// refund is never taken.
#[tokio::test(flavor = "multi_thread")]
async fn d67_a_client_that_wakes_late_by_most_of_the_margin_still_claims_first() {
	let Some(lnd) = lightningd("d67_a_client_that_wakes_late_by_most_of_the_margin_still_claims_first") else { return };
	let mut r = Running::start_seqln(|c, _, _| {
		c.fees.lightning_ppm = 1_000;
		c.lightning.operator_delay_units = 1;
		c.lightning.owner_delay_units = 2;
		c.lightning.send_timeout_seconds = 8 * 3600;
		c.lightning.send_stall_margin_seconds = 3600;
		c.lightning.poll_seconds = 1;
		c.lightning.retry_seconds = 10;
		c.lightning.receive_window_seconds = 7200;
	}).await;
	let x = r.x;
	let (ox, px) = leg_in_x(&lnd, &mut r, "late").await;
	let p = common::proxy::Proxy::start(&r.url());
	p.rewrite(Some(std::sync::Arc::new(|path: &str, _req: &Value, _status: u16, v: &mut Value| {
		if path == "/v1/lightning_receive_claim" {
			*v = json!({"code": "internal", "message": "the operator took the preimage and answers nothing"});
			return Some(500);
		}
		None
	})));
	p.rewrite_request(Some(std::sync::Arc::new(spoiled_claims)));
	let a = wallet_at("LATE", &p.url.clone(), &r);
	let (hash, paying) = held(&r, &a, &px, 100_000).await;
	a.ok(&["sync"]);
	let built = r.server.rounds.run_round_of(x).await.unwrap().expect("a round");
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	let timeout = receive_row(&r, &hash).await.unwrap().timeout.unwrap();
	a.run(&["sync"]);
	assert_eq!(paying.join().unwrap().unwrap()["status"], "complete", "the operator settled with the preimage it took");
	let leaf_id = a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["kind"] == "batch").map(|c| c["leaf_id"].as_str().unwrap().to_string())
		.expect("the htlc-1 leaf");
	let rec = CoinRecordOf::of(&a, &leaf_id);
	// The leaf's margin, from the chain (an eighth of its lock from its
	// round's confirmation to its timeout), and the home date the wallet
	// gave it: the wallet wakes three quarters of that margin past it.
	let confirmed = block_time_of(&r, &built.tx.txid());
	let margin = 180u32.max((timeout - confirmed) / 8);
	let receive = a.ok(&["lightning", "receives"])[&hash].clone();
	let home = receive["home_at"].as_u64().expect("a home date once the claim went out") as u32;
	let late = home + margin * 3 / 4;
	println!("LATE the leaf confirmed at {}, its timeout {}: margin {} s; the wallet's home date {} ({} s before the timeout); it wakes \
		at {} ({} s late, {} s before the timeout) | the receive {}", confirmed, timeout, margin, home, timeout - home, late, late - home,
		timeout as i64 - late as i64, receive);
	if mtp(&r) < late {
		advance(&r, late - mtp(&r)).await;
	}
	let wifs = stakers();
	let mut s = a.run(&["sync"]).1;
	let mut refunds = vec![];
	let mut refund_hex: Option<String> = None;
	let mut wakes = 1;
	println!("LATE wake 1 at {} ({} s before the timeout): coin {} | home {} | next {}", mtp(&r), timeout as i64 - mtp(&r) as i64,
		coin_of(&a, &leaf_id)["state"], s["home"], s["schedule"]["next_sync_at"]);
	while mtp(&r) < timeout + 1200 && wakes < 200 {
		tokio::task::block_in_place(|| block_a_minute(r.rt.client(), &wifs));
		if refund_hex.is_none() {
			if let Some((op, m)) = output_on_chain(&r, &rec.0, 300) {
				refund_hex = Some(elements::encode::serialize_hex(&rec.refund(&r, op, x)));
				println!("LATE the leaf's output {} in a block of median time {} ({} s before the timeout)", op, m, timeout as i64 - m as i64);
			}
		}
		if let Some(hx) = &refund_hex {
			if let Ok(v) = r.rt.client().call::<Value>("sendrawtransaction", &[json!(hx)]) {
				refunds.push(format!("at {}: {}", mtp(&r), v));
			}
		}
		if spent_on_chain(&r, &rec.0, 300).is_some() {
			break;
		}
		let due = a.ok(&["schedule"])["due"] == true;
		if due {
			r.synced().await;
			s = a.run(&["sync"]).1;
			wakes += 1;
			println!("LATE wake {} at {} ({} s before the timeout): coin {} | exits {} | next {}", wakes, mtp(&r), timeout as i64 - mtp(&r) as i64,
				coin_of(&a, &leaf_id)["state"], s["exits"], s["schedule"]["next_sync_at"]);
		}
	}
	let spent = spent_on_chain(&r, &rec.0, 2000);
	println!("LATE the leaf's spend: {:?} | the operator's refunds taken: {:?}", spent.as_ref().map(|(o, t, m)| (o.to_string(), t.txid().to_string(),
		*m, claims_with_preimage(t, o, &hash))), refunds);
	let (op, t, m) = spent.unwrap_or_else(|| panic!("the leaf was never spent on the chain: coin {}", coin_of(&a, &leaf_id)));
	assert!(claims_with_preimage(&t, &op, &hash), "the leaf's spend {} is the operator's refund, not the wallet's claim", t.txid());
	assert!(m < timeout, "the claim is in a block before the timeout ({} >= {})", m, timeout);
	assert!(refunds.is_empty(), "the operator's refund was taken: {:?}", refunds);
	drop((ox, px));
	let _ = std::fs::remove_dir_all(&a.dir);
}

/// A received payment whose claim the server recorded and did not co-sign,
/// as the server itself leaves one when its signer is away at the claim:
/// the claim reaches the server (the signer is killed as it does, then
/// started again), which records the preimage, settles the payer and
/// records the claim's transfer, then cannot co-sign it. Returns the server,
/// the lost wallet, the payment's hash, the leaf, its timeout, its record
/// and the two Lightning nodes.
async fn a_claim_the_server_recorded(lnd: &std::path::Path, tag: &str)
	-> (Running, Arca, String, String, u32, CoinRecordOf, sequentia_ext::lightning::LightningNode, sequentia_ext::lightning::LightningNode)
{
	let mut r = short_delays().await;
	let (ox, px) = leg_in_x(&lnd.to_path_buf(), &mut r, &tag.to_lowercase()).await;
	let p = common::proxy::Proxy::start(&r.url());
	let a = wallet_at(tag, &p.url.clone(), &r);
	let (hash, paying) = held(&r, &a, &px, 100_000).await;
	a.ok(&["sync"]);
	leaf_round(&r).await;
	let timeout = receive_row(&r, &hash).await.unwrap().timeout.unwrap();
	let genesis = r.rt.client().genesis_hash().unwrap();
	let pid = r.signer.pid().to_string();
	p.rewrite_request(Some(std::sync::Arc::new(move |path: &str, _: &mut Value| {
		if path == "/v1/lightning_receive_claim" {
			let _ = std::process::Command::new("kill").args(["-9", &pid]).status();
		}
	})));
	let (_, s) = a.run(&["sync"]);
	p.rewrite_request(None);
	r.signer.halt();
	tokio::task::block_in_place(|| r.signer.resume(genesis));
	println!("{} the claim with the signer killed: lightning {} | the server's answer {:?}", tag, s["lightning"],
		p.last("/v1/lightning_receive_claim").map(|(_, st, v)| (st, v)));
	let row = receive_row(&r, &hash).await.unwrap();
	assert!(row.preimage.is_some(), "the server recorded the preimage");
	assert_eq!(paying.join().unwrap().unwrap()["status"], "complete", "the payer's payment settled");
	let leaf = a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["kind"] == "batch").cloned().expect("the htlc-1 leaf");
	let leaf_id = leaf["leaf_id"].as_str().unwrap().to_string();
	let rec = CoinRecordOf::of(&a, &leaf_id);
	(r, a, hash, leaf_id, timeout, rec, ox, px)
}

/// Wakes `w` when its schedule says until its received leaf `leaf` is
/// spent on the chain or the timeout is long past, then checks the spend is
/// its claim, in a block before `timeout`, and that the operator's refund
/// past the timeout finds the leaf claimed.
async fn claims_home_before_the_refund(r: &Running, w: &Arca, tag: &str, hash: &str, leaf: &str, timeout: u32, rec: &CoinRecordOf) {
	let mut s = w.ok(&["schedule"]);
	let mut wakes = 0;
	while let Some(n) = s["next_sync_at"].as_u64().map(|n| n as u32) {
		if wakes >= 90 || n >= timeout + 3600 || spent_on_chain(r, &rec.0, 300).is_some() {
			break;
		}
		if n > mtp(r) {
			advance(r, n - mtp(r)).await;
		}
		let (_, v) = w.run(&["sync"]);
		r.produce().await;
		wakes += 1;
		s = v["schedule"].clone();
		println!("{} wake {} at {} ({} s before the timeout): coin {} | home {} | exits {} | next {}", tag, wakes, mtp(r), timeout as i64 - mtp(r) as i64,
			coin_of(w, leaf)["state"], v["home"], v["exits"], s["next_sync_at"]);
	}
	let spent = spent_on_chain(r, &rec.0, 2000);
	println!("{} the leaf's spend: {:?}", tag, spent.as_ref().map(|(o, t, m)| (o.to_string(), t.txid().to_string(), *m, claims_with_preimage(t, o, hash))));
	let (op, t, m) = spent.unwrap_or_else(|| panic!("the restored wallet never took the leaf home: coin {} | its receives {} | schedule {}",
		coin_of(w, leaf), w.ok(&["lightning", "receives"]), s));
	assert!(claims_with_preimage(&t, &op, hash), "the leaf's spend {} is not the wallet's claim", t.txid());
	assert!(m < timeout, "the claim is in a block before the timeout ({} >= {})", m, timeout);
	if mtp(r) < timeout + 600 {
		advance(r, timeout + 600 - mtp(r)).await;
	}
	let refund = rec.refund(r, op, r.x);
	let sent: Result<Value, _> = r.rt.client().call("sendrawtransaction", &[json!(elements::encode::serialize_hex(&refund))]);
	println!("{} the operator's refund past the timeout: {:?}", tag, sent);
	assert!(sent.is_err(), "the operator's refund finds the leaf claimed");
}

/// The eleventh review's F1, turned around (D68). A restore meets a
/// received leaf whose claim the server recorded and did not co-sign: the
/// leaf is held `receiving`, its payment rebuilt as handed over with its
/// home date, and the restored wallet, waking only when its schedule says,
/// takes it home by its claim before the operator's refund opens.
#[tokio::test(flavor = "multi_thread")]
async fn d68_a_restore_meets_a_claim_the_server_recorded() {
	let Some(lnd) = lightningd("d68_a_restore_meets_a_claim_the_server_recorded") else { return };
	let (r, a, hash, leaf_id, timeout, rec, ox, px) = a_claim_the_server_recorded(&lnd, "D68A").await;
	println!("D68A the leaf at the server: {:?}", r.server.store.leaf(&leaf_id.parse::<arca_covenant::LeafId>().unwrap().0).await.unwrap()
		.map(|l| l.state));
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap().trim().to_string();
	let a2 = Arca::new("D68A2");
	let made = a2.ok(&["create", "--server", &r.url(), "--node-url", &r.node_url(), "--node-user", "arca", "--exit-delay-units", "4",
		"--min-exit-delay-units", "1", "--mnemonic", &mnemonic]);
	println!("D68A restore: served {} | restored {} | not_recovered {} | notes {}", made["restore"]["served"], made["restore"]["restored"],
		made["restore"]["not_recovered"], made["restore"]["notes"]);
	let c = coin_of(&a2, &leaf_id);
	let rv = a2.ok(&["lightning", "receives"])[&hash].clone();
	println!("D68A the restored leaf: {} | its receive {}", c, rv);
	assert_eq!(c["state"], "receiving", "the restored leaf is held receiving: {}", c);
	assert_eq!(rv["state"], "claiming", "the payment is rebuilt as handed over: {}", rv);
	assert!(rv["home_at"].as_u64().is_some_and(|h| h < timeout as u64), "the receive has its home date: {}", rv);
	claims_home_before_the_refund(&r, &a2, "D68A", &hash, &leaf_id, timeout, &rec).await;
	drop((ox, px));
	for w in [&a, &a2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// D68, the served-as-signed lie: the operator serves the claim it recorded
/// and never co-signed as signed. The restored wallet holds no coin the
/// claim made, so it takes the leaf as not spent, holds it `receiving` with
/// its home date, and takes it home by its claim before the refund opens.
#[tokio::test(flavor = "multi_thread")]
async fn d68_a_claim_served_as_signed_is_not_taken_without_its_coin() {
	let Some(lnd) = lightningd("d68_a_claim_served_as_signed_is_not_taken_without_its_coin") else { return };
	let (r, a, hash, leaf_id, timeout, rec, ox, px) = a_claim_the_server_recorded(&lnd, "D68B").await;
	let lie = common::proxy::Proxy::start(&r.url());
	lie.rewrite(Some(std::sync::Arc::new(|path: &str, _req: &Value, _status: u16, v: &mut Value| {
		if path == "/v1/leaf_data" {
			for l in v["leaves"].as_array_mut().into_iter().flatten() {
				for g in l["given"].as_array_mut().into_iter().flatten() {
					if g["transfer"]["state"] == "recorded" {
						g["transfer"]["state"] = json!("signed");
					}
				}
			}
		}
		None
	})));
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap().trim().to_string();
	let a2 = Arca::new("D68B2");
	let made = a2.ok(&["create", "--server", &lie.url, "--node-url", &r.node_url(), "--node-user", "arca", "--exit-delay-units", "4",
		"--min-exit-delay-units", "1", "--mnemonic", &mnemonic]);
	println!("D68B restore against the lie: served {} | restored {} | not_recovered {} | notes {}", made["restore"]["served"],
		made["restore"]["restored"], made["restore"]["not_recovered"], made["restore"]["notes"]);
	let c = coin_of(&a2, &leaf_id);
	let rv = a2.ok(&["lightning", "receives"])[&hash].clone();
	println!("D68B the restored leaf: {} | its receive {}", c, rv);
	assert_ne!(c["state"], "spent", "a claim served as signed is not taken without the coin it made: {}", c);
	assert_eq!(rv["state"], "claiming", "the payment is rebuilt as handed over: {}", rv);
	claims_home_before_the_refund(&r, &a2, "D68B", &hash, &leaf_id, timeout, &rec).await;
	drop((ox, px));
	for w in [&a, &a2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// D68: a restore that comes too late to win, past the received leaf's
/// timeout, says so on the coin rather than holding it quietly.
#[tokio::test(flavor = "multi_thread")]
async fn d68_a_restore_too_late_to_win_says_so() {
	let Some(lnd) = lightningd("d68_a_restore_too_late_to_win_says_so") else { return };
	let (r, a, hash, leaf_id, timeout, _rec, ox, px) = a_claim_the_server_recorded(&lnd, "D68C").await;
	if mtp(&r) < timeout + 60 {
		advance(&r, timeout + 60 - mtp(&r)).await;
	}
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap().trim().to_string();
	let a2 = Arca::new("D68C2");
	let made = a2.ok(&["create", "--server", &r.url(), "--node-url", &r.node_url(), "--node-user", "arca", "--exit-delay-units", "4",
		"--min-exit-delay-units", "1", "--mnemonic", &mnemonic]);
	let c = coin_of(&a2, &leaf_id);
	println!("D68C restored past the timeout: notes {} | the coin {} | its receive {}", made["restore"]["notes"], c,
		a2.ok(&["lightning", "receives"])[&hash]);
	assert!(c["note"].as_str().is_some_and(|n| n.contains("too late")), "the coin says the restore came too late: {}", c);
	drop((ox, px));
	for w in [&a, &a2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// The eleventh review's F4, turned around (D70). G and H each ask to
/// receive 50,000; each payment is held and each wallet's sync takes up the
/// operator's participation for its leaf. G's device is lost before the
/// leaf's round; H's after the round and before H released its leaf. A
/// wallet restored from each mnemonic is served the receive asked under its
/// mailbox key and the operator's participation for it, rebuilds both, takes
/// the leaf up and claims it: each payer's pay completes, and each restored
/// wallet holds the leaf's value.
#[tokio::test(flavor = "multi_thread")]
async fn d70_restores_meet_payments_held_and_leaves_not_yet_released() {
	let Some(lnd) = lightningd("d70_restores_meet_payments_held_and_leaves_not_yet_released") else { return };
	let mut r = short_delays().await;
	let (ox, px) = leg_in_x(&lnd, &mut r, "d70").await;
	let url = r.url();
	let restore = |w: &Arca, name: &str| -> (Arca, Value) {
		let mn = std::fs::read_to_string(w.dir.join("mnemonic")).unwrap().trim().to_string();
		let w2 = Arca::new(name);
		let made = w2.ok(&["create", "--server", &url, "--node-url", &r.node_url(), "--node-user", "arca", "--exit-delay-units", "4",
			"--min-exit-delay-units", "1", "--mnemonic", &mn]);
		(w2, made)
	};
	let g = wallet_at("D70G", &url, &r);
	let h = wallet_at("D70H", &url, &r);
	let (hg, pay_g) = held(&r, &g, &px, 50_000).await;
	let (hh, pay_h) = held(&r, &h, &px, 50_000).await;
	for (w, name) in [(&g, "G"), (&h, "H")] {
		let s = w.ok(&["sync"]);
		println!("D70 {}'s receive held, the participation taken up: lightning {} | participations {}", name, s["lightning"], s["participations"]);
	}
	// G is lost before the leaf's round.
	let (g2, made) = restore(&g, "D70G2");
	println!("D70 G restored before the round: served {} | restored {} | notes {} | receives {} | participations {}", made["restore"]["served"],
		made["restore"]["restored"], made["restore"]["notes"], g2.ok(&["lightning", "receives"]), g2.ok(&["participations"]));
	assert!(!g2.ok(&["lightning", "receives"])[&hg].is_null(), "the receive G asked for is rebuilt");
	leaf_round(&r).await;
	// H is lost after the round, its leaf not yet released.
	let (h2, made) = restore(&h, "D70H2");
	println!("D70 H restored after the round, its leaf not released: served {} | restored {} | notes {} | receives {}", made["restore"]["served"],
		made["restore"]["restored"], made["restore"]["notes"], h2.ok(&["lightning", "receives"]));
	for k in 0..4 {
		for (w, name) in [(&g2, "G2"), (&h2, "H2")] {
			let s = w.ok(&["sync"]);
			println!("D70 {} sync {}: lightning {} | participations {}", name, k, s["lightning"], s["participations"]);
		}
		r.produce().await;
		if g2.ok(&["lightning", "receives"])[&hg]["state"] == "received" && h2.ok(&["lightning", "receives"])[&hh]["state"] == "received" {
			break;
		}
	}
	let (pg, ph) = (pay_g.join().unwrap(), pay_h.join().unwrap());
	println!("D70 the payers: G's {:?} | H's {:?}", pg.as_ref().map(|v| v["status"].clone()), ph.as_ref().map(|v| v["status"].clone()));
	for (w, hash, paid, name) in [(&g2, &hg, &pg, "G2"), (&h2, &hh, &ph, "H2")] {
		let rec = w.ok(&["lightning", "receives"])[hash].clone();
		println!("D70 {}'s receive {} | balance {}", name, rec, w.ok(&["balance"])["arca"]);
		assert_eq!(paid.as_ref().map(|v| v["status"].clone()).ok(), Some(json!("complete")), "{}'s payer is paid", name);
		assert_eq!(rec["state"], "received", "{} claimed the leaf: {}", name, rec);
		assert!(arca_held(w, &r.x) > 45_000, "{} holds the leaf's value", name);
	}
	drop((ox, px));
	for w in [&g, &h, &g2, &h2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// The eleventh review's F6, turned around, for a receive over Lightning.
/// A wallet just created asks to receive 100,000 of X and from then runs
/// `sync` only when `schedule` says it is due, the chain a block a minute:
/// a wallet that has never synced is due at once, so its first read of the
/// schedule wakes it. The operator takes the preimage and co-signs nothing
/// (the claim's first signature spoiled on the way, every claim answered
/// 500, the mailbox empty). The scheduled syncs take the leaf up, hand the
/// preimage over and take the leaf home by its claim before its timeout.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_wallet_receives_over_lightning_on_its_schedule_alone() {
	let Some(lnd) = lightningd("a_new_wallet_receives_over_lightning_on_its_schedule_alone") else { return };
	let mut r = short_delays().await;
	let (ox, px) = leg_in_x(&lnd, &mut r, "due").await;
	let p = common::proxy::Proxy::start(&r.url());
	p.rewrite(Some(std::sync::Arc::new(|path: &str, _req: &Value, _status: u16, v: &mut Value| {
		if path == "/v1/lightning_receive_claim" {
			*v = json!({"code": "internal", "message": "the operator took the preimage and answers nothing"});
			return Some(500);
		}
		if path == "/v1/mailbox_read" {
			if let Some(m) = v.get_mut("messages") {
				*m = json!([]);
			}
		}
		None
	})));
	p.rewrite_request(Some(std::sync::Arc::new(spoiled_claims)));
	let a = wallet_at("DUE", &p.url.clone(), &r);
	let first = a.ok(&["schedule"]);
	println!("DUE a new wallet's schedule: {}", first);
	let inv = a.ok(&["lightning", "receive", &r.x.to_string(), "100000"]);
	let hash = inv["payment_hash"].as_str().unwrap().to_string();
	let (rpc, bolt11) = (px.rpc_path(), inv["invoice"].as_str().unwrap().to_string());
	let paying = std::thread::spawn(move || sequentia_ext::lightning::call_at(&rpc, "pay", json!({ "bolt11": bolt11 })));
	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
	while !receive_row(&r, &hash).await.is_some_and(|x| x.state.name() == "accepted") {
		assert!(std::time::Instant::now() < deadline, "the payment was never held");
		tokio::time::sleep(std::time::Duration::from_millis(200)).await;
	}
	let wifs = stakers();
	let mut syncs = 0;
	let mut round = false;
	let mut timeout = None;
	let mut leaf: Option<String> = None;
	for _ in 0..1500 {
		let sch = a.ok(&["schedule"]);
		if sch["next_sync_at"].is_null() {
			println!("DUE the schedule names no time at {}: {}", mtp(&r), sch);
			break;
		}
		if sch["due"] != true {
			tokio::task::block_in_place(|| block_a_minute(r.rt.client(), &wifs));
			r.synced().await;
			continue;
		}
		let s = a.run(&["sync"]).1;
		syncs += 1;
		tokio::task::block_in_place(|| block_a_minute(r.rt.client(), &wifs));
		let row = receive_row(&r, &hash).await;
		if timeout.is_none() {
			timeout = row.as_ref().and_then(|x| x.timeout);
		}
		// The leaf's round, once the operator holds the participation for it.
		if !round && row.as_ref().is_some_and(|x| x.state.name() == "accepted" && x.participation_id.is_some()) {
			if let Ok(Some(built)) = r.server.rounds.run_round_of(r.x).await {
				r.produce().await;
				r.bury().await;
				r.round_state(&built.tx.txid(), RoundState::Final).await;
				round = true;
				timeout = receive_row(&r, &hash).await.and_then(|x| x.timeout);
			}
		}
		if leaf.is_none() {
			leaf = a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["kind"] == "batch").map(|c| c["leaf_id"].as_str().unwrap().to_string());
		}
		let st = leaf.as_ref().map(|l| coin_of(&a, l)["state"].clone()).unwrap_or(Value::Null);
		println!("DUE sync {} at {} ({} s from the timeout): receive {} | coin {} | next {}", syncs, mtp(&r),
			timeout.map(|t| mtp(&r) as i64 - t as i64).unwrap_or(0), a.ok(&["lightning", "receives"])[&hash]["state"], st,
			s["schedule"]["next_sync_at"]);
		if st == "exited" || timeout.is_some_and(|t| mtp(&r) > t + 1200) {
			break;
		}
	}
	let paid = paying.join().unwrap();
	println!("DUE the payer: {:?} | {} syncs, all on the schedule", paid.as_ref().map(|v| v["status"].clone()), syncs);
	assert_eq!(first["due"], true, "a wallet that has never synced is due at once: {}", first);
	assert_eq!(paid.as_ref().map(|v| v["status"].clone()).ok(), Some(json!("complete")), "the payment completed");
	let l = leaf.expect("the wallet took the leaf up");
	let rec = CoinRecordOf::of(&a, &l);
	let spent = spent_on_chain(&r, &rec.0, 1500);
	let (op, t, m) = spent.unwrap_or_else(|| panic!("the leaf never came home: coin {}", coin_of(&a, &l)));
	println!("DUE the leaf's claim {} at {} (the timeout {:?})", t.txid(), m, timeout);
	assert!(claims_with_preimage(&t, &op, &hash), "the leaf comes home by its claim");
	assert!(m < timeout.unwrap(), "the claim is in a block before the timeout");
	drop((ox, px));
	let _ = std::fs::remove_dir_all(&a.dir);
}

// ---------------------------------------------------------------------------
// D76: the claim of a received leaf is a race the wallet runs to win. R7l's
// probes (a chain stall past the leaf's margin, a claim the block producers
// leave out) turned around, a claim paid from another asset once the node no
// longer takes the leaf's, and the fee race that decides a stall past the
// margin; every wallet driven by its schedule alone (`sync` when `due`,
// `sync --exits-only` when `exit_due`), against D62's operator, which takes
// the preimage, settles the payer and co-signs nothing.
// ---------------------------------------------------------------------------

/// D62's operator, the receive window two hours so the margin is an eighth
/// of the lock, and a wallet that has handed the preimage over. Returns the
/// server, the proxy, the wallet, the hash, the leaf, its record, its
/// timeout, the round's confirmation time and the Lightning nodes.
async fn handed_over(lnd: &std::path::PathBuf, tag: &str, window: u32)
	-> (Running, common::proxy::Proxy, Arca, String, String, CoinRecordOf, u32, u32,
		sequentia_ext::lightning::LightningNode, sequentia_ext::lightning::LightningNode)
{
	let mut r = Running::start_seqln(|c, _, _| {
		c.fees.lightning_ppm = 1_000;
		c.lightning.operator_delay_units = 1;
		c.lightning.owner_delay_units = 2;
		c.lightning.send_timeout_seconds = 8 * 3600;
		c.lightning.send_stall_margin_seconds = 3600;
		c.lightning.poll_seconds = 1;
		c.lightning.retry_seconds = 10;
		c.lightning.receive_window_seconds = window;
	}).await;
	let x = r.x;
	let (ox, px) = leg_in_x(lnd, &mut r, &tag.to_lowercase()).await;
	let p = common::proxy::Proxy::start(&r.url());
	p.rewrite(Some(std::sync::Arc::new(|path: &str, _req: &Value, _status: u16, v: &mut Value| {
		if path == "/v1/lightning_receive_claim" {
			*v = json!({"code": "internal", "message": "the operator took the preimage and answers nothing"});
			return Some(500);
		}
		None
	})));
	p.rewrite_request(Some(std::sync::Arc::new(spoiled_claims)));
	let a = wallet_at(tag, &p.url.clone(), &r);
	let (hash, paying) = held(&r, &a, &px, 100_000).await;
	a.ok(&["sync"]);
	let built = r.server.rounds.run_round_of(x).await.unwrap().expect("a round");
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	let timeout = receive_row(&r, &hash).await.unwrap().timeout.unwrap();
	let s = a.run(&["sync"]).1;
	assert_eq!(paying.join().unwrap().unwrap()["status"], "complete", "the operator settled with the preimage it took");
	let leaf_id = a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["kind"] == "batch").map(|c| c["leaf_id"].as_str().unwrap().to_string())
		.expect("the htlc-1 leaf");
	let rec = CoinRecordOf::of(&a, &leaf_id);
	let confirmed = block_time_of(&r, &built.tx.txid());
	println!("{} handed over at {}: lightning {} | the round confirmed at {}, the timeout {} (lock {} s)", tag, mtp(&r), s["lightning"],
		confirmed, timeout, timeout - confirmed);
	(r, p, a, hash, leaf_id, rec, timeout, confirmed, ox, px)
}

/// One wake on the schedule alone: `sync --exits-only` when `exit_due`,
/// `sync` when `due`, nothing otherwise. Returns what ran.
fn wake(a: &Arca) -> (String, Value) {
	let sch = a.ok(&["schedule"]);
	if sch["exit_due"] == true && sch["due"] != true {
		("sync --exits-only".into(), a.run(&["sync", "--exits-only"]).1)
	} else if sch["due"] == true {
		("sync".into(), a.run(&["sync"]).1)
	} else {
		("-".into(), sch)
	}
}

/// One block whose time is `t`.
fn block_at(c: &sequentia_ext::rpc::Client, wifs: &[String], t: u64) {
	let _: Value = c.call("setmocktime", &[json!(t)]).unwrap();
	for _ in 0..40 {
		for w in wifs {
			if c.call::<Value>("generateposblock", &[json!(w), json!(wifs)]).is_ok() {
				return;
			}
		}
		std::thread::sleep(std::time::Duration::from_millis(250));
	}
	panic!("no block");
}

/// Who took the leaf: its spend on the chain, and whether it carries the
/// preimage (the wallet's claim) or not (the operator's refund). Returns
/// whether the wallet's claim took it, and the spend's fees.
fn outcome(r: &Running, tag: &str, rec: &CoinRecordOf, hash: &str, timeout: u32) -> (bool, Vec<(String, u64)>) {
	let spent = spent_on_chain(r, &rec.0, 3000);
	let (o, t, m) = spent.unwrap_or_else(|| panic!("{}: the leaf is spent on the chain by nothing", tag));
	let claimed = claims_with_preimage(&t, &o, hash);
	let fees: Vec<(String, u64)> = t.output.iter().filter(|x| x.is_fee()).map(|x| (x.asset.explicit().unwrap().to_string()[..8].to_string(),
		x.value.explicit().unwrap())).collect();
	println!("{} THE LEAF'S SPEND: {} by {} in a block of median time {} ({} s from the timeout): {}, fees {:?}", tag, o, t.txid(), m,
		m as i64 - timeout as i64, if claimed { "the wallet's claim, with the preimage" } else { "the operator's refund (no preimage)" }, fees);
	(claimed, fees)
}

/// The operator's refund of the leaf's output `op`, paying `fee` of X.
fn refund_paying(rec: &CoinRecordOf, r: &Running, op: elements::OutPoint, x: AssetId, fee: u64) -> elements::Transaction {
	let tx = r.rt.client().raw_transaction(&op.txid).unwrap();
	let value = tx.output[op.vout as usize].value.explicit().unwrap();
	let to = arca_covenant::ExplicitOutput::new(x, value - fee, Script::from([0u8, 20].into_iter().chain([7u8; 20]).collect::<Vec<u8>>()));
	let ks = rec.1.refund_tx(op, x, value, &[to], &arca_covenant::FeeSource::Reserve).unwrap();
	let sighash = ks.sighash(r.rt.client().genesis_hash().unwrap()).unwrap();
	let sig = arca_covenant::sign::sign_digest(&common::running::keypair("operator"), &sighash, &[7u8; 32]);
	ks.finish(vec![sig.as_ref().to_vec()]).tx
}

/// The chain stalls once the wallet has begun taking the received leaf home
/// at its home date, for the margin and twenty minutes more, and resumes a
/// block a minute: both the claim's and the refund's locks open in one
/// block. The operator tries its refund (paying `refund_fee` of X) after
/// every block once the leaf is on the chain; the wallet wakes on its
/// schedule before each block, and, with `wallet_first`, right after each
/// block too, before the operator. Returns whether the wallet's claim took
/// the leaf, and the spend's fees.
async fn stall(test: &str, tag: &str, wallet_first: bool, refund_fee: u64) -> Option<(bool, Vec<(String, u64)>)> {
	let lnd = lightningd(test)?;
	let (r, _p, a, hash, leaf_id, rec, timeout, confirmed, ox, px) = handed_over(&lnd, tag, 7200).await;
	let x = r.x;
	let margin = 180u32.max((timeout - confirmed) / 8);
	let home = a.ok(&["lightning", "receives"])[&hash]["home_at"].as_u64().unwrap() as u32;
	println!("{} margin {} s; home date {} ({} s before the timeout)", tag, margin, home, timeout - home);
	let wifs = stakers();
	let c = r.rt.client().clone();
	let mut stalled = false;
	let mut refund_hex: Option<String> = None;
	for step in 0..600 {
		let tip_time = { let h: Value = c.call("getblockheader", &[json!(c.best_block_hash().unwrap().to_string())]).unwrap(); h["time"].as_u64().unwrap() };
		if !stalled && mtp(&r) + 600 < home {
			advance(&r, home - 300 - mtp(&r)).await;
		}
		let (ran, v) = wake(&a);
		if ran != "-" {
			println!("{} step {} at {} ({} s from the timeout): {} -> coin {} | exits {}", tag, step, mtp(&r), mtp(&r) as i64 - timeout as i64,
				ran, coin_of(&a, &leaf_id)["state"], v["exits"]);
		}
		if !stalled && coin_of(&a, &leaf_id)["state"] == "exiting" {
			stalled = true;
			let end = tip_time + (timeout - mtp(&r)) as u64 + 1200;
			println!("{} THE STALL: from median time {} (tip time {}), no block until time {} ({} s, the margin is {} s)", tag, mtp(&r), tip_time,
				end, end - tip_time, margin);
			for k in 0..3 {
				let (ran, v) = wake(&a);
				println!("{} during the stall, wake {}: {} -> {}", tag, k, ran, v["schedule"]["next_exit_at"]);
			}
			tokio::task::block_in_place(|| block_at(&c, &wifs, end));
			r.synced().await;
			continue;
		}
		tokio::task::block_in_place(|| block_a_minute(&c, &wifs));
		r.synced().await;
		if wallet_first {
			let (ran, v) = wake(&a);
			if ran != "-" {
				println!("{} wallet first at {} ({} s from the timeout): {} -> coin {} | exits {}", tag, mtp(&r), mtp(&r) as i64 - timeout as i64,
					ran, coin_of(&a, &leaf_id)["state"], v["exits"]);
			}
		}
		if refund_hex.is_none() {
			if let Some((op, m)) = output_on_chain(&r, &rec.0, 400) {
				refund_hex = Some(elements::encode::serialize_hex(&refund_paying(&rec, &r, op, x, refund_fee)));
				println!("{} the leaf's output {} in a block of median time {} ({} s from the timeout)", tag, op, m, m as i64 - timeout as i64);
			}
		}
		if let Some(hx) = &refund_hex {
			let pool: Vec<String> = c.call::<Vec<String>>("getrawmempool", &[]).unwrap_or_default();
			let tried = c.call::<Value>("sendrawtransaction", &[json!(hx), json!(0)]);
			if mtp(&r) + 600 > timeout {
				println!("{} the operator's refund paying {} at {} (mempool before it: {:?}): {:?}", tag, refund_fee, mtp(&r), pool,
					tried.as_ref().map_err(|e| e.to_string()));
			}
		}
		if spent_on_chain(&r, &rec.0, 400).is_some() {
			break;
		}
	}
	tokio::task::block_in_place(|| block_a_minute(&c, &wifs));
	let got = outcome(&r, tag, &rec, &hash, timeout);
	let (ran, v) = wake(&a);
	println!("{} the wallet afterwards: {} -> exits {} | coin {} | balance {}", tag, ran, v["exits"], coin_of(&a, &leaf_id), a.ok(&["balance"]));
	drop((ox, px));
	let _ = std::fs::remove_dir_all(&a.dir);
	Some(got)
}

/// R7l's stall probe, turned around: a stall longer than the margin opens
/// the claim and the refund in one block; the operator's refund (5,000 of
/// fee) goes in first; the wallet, at its next wake, finds it in the mempool
/// and replaces it with its claim at its bid, the whole value from the
/// timeout on. The wallet's claim takes the leaf.
#[tokio::test(flavor = "multi_thread")]
async fn d76_a_stall_past_the_margin_the_claim_outbids_the_refund() {
	let Some((claimed, fees)) = stall("d76_a_stall_past_the_margin_the_claim_outbids_the_refund", "D76S1", false, 5_000).await else { return };
	assert!(claimed, "the wallet's claim took the leaf (fees {:?})", fees);
}

/// The same, the wallet woken right after each block, before the operator:
/// its claim goes out at the whole value past the timeout, and the
/// operator's refund cannot replace it.
#[tokio::test(flavor = "multi_thread")]
async fn d76_a_stall_past_the_margin_the_wallet_first() {
	let Some((claimed, fees)) = stall("d76_a_stall_past_the_margin_the_wallet_first", "D76S1B", true, 5_000).await else { return };
	assert!(claimed, "the wallet's claim took the leaf (fees {:?})", fees);
}

/// What remains, as the documentation states it: past the margin a fee race
/// decides. An operator whose refund pays more in fees than the wallet's
/// best claim (the leaf's whole value less twice the dust its own output
/// keeps) wins it, keeping only its refund's output at the node's dust
/// threshold (300 atoms of X at a rate of 1).
#[tokio::test(flavor = "multi_thread")]
async fn d76_past_the_margin_a_fee_race_decides() {
	let Some((claimed, fees)) = stall("d76_past_the_margin_a_fee_race_decides", "D76S3", false, 99_900 - 300).await else { return };
	assert!(!claimed, "a refund burning all but 300 atoms of the leaf outbids the wallet's best claim (fees {:?})", fees);
	assert_eq!(fees.iter().map(|f| f.1).sum::<u64>(), 99_600, "the operator burnt the leaf to win the race");
}

/// R7l's claim-left-out probe, turned around: the wallet's claim goes out in
/// time, and the block producers leave out every claim paying less than a
/// bar (twenty times the first claim's fee at the node's floor: a congested
/// chain, or producers that value the leaf's asset low), the chain a block a
/// minute. The wallet raises its claim at every wake as the timeout nears;
/// once it clears the bar it is mined, before the timeout. From the timeout
/// the operator's refund, paying 5,000, is tried at every block.
#[tokio::test(flavor = "multi_thread")]
async fn d76_a_claim_left_out_until_its_fee_clears_the_bar() {
	let Some(lnd) = lightningd("d76_a_claim_left_out_until_its_fee_clears_the_bar") else { return };
	let tag = "D76S2";
	let (r, _p, a, hash, leaf_id, rec, timeout, confirmed, ox, px) = handed_over(&lnd, tag, 7200).await;
	let x = r.x;
	let margin = 180u32.max((timeout - confirmed) / 8);
	let home = a.ok(&["lightning", "receives"])[&hash]["home_at"].as_u64().unwrap() as u32;
	println!("{} margin {} s; home date {} ({} s before the timeout)", tag, margin, home, timeout - home);
	let wifs = stakers();
	let c = r.rt.client().clone();
	let mut refund_hex: Option<String> = None;
	let mut seen: Vec<String> = vec![];
	let mut bar: Option<u64> = None;
	let mut raised = 0;
	for step in 0..900 {
		if mtp(&r) + 600 < home {
			advance(&r, home - 300 - mtp(&r)).await;
		}
		let (ran, v) = wake(&a);
		if ran != "-" {
			println!("{} step {} at {} ({} s from the timeout): {} -> coin {} | exits {}", tag, step, mtp(&r), mtp(&r) as i64 - timeout as i64,
				ran, coin_of(&a, &leaf_id)["state"], v["exits"]);
		}
		if let Some((op, _)) = output_on_chain(&r, &rec.0, 400) {
			if refund_hex.is_none() {
				refund_hex = Some(elements::encode::serialize_hex(&refund_paying(&rec, &r, op, x, 5_000)));
				println!("{} the leaf's output {} on the chain", tag, op);
			}
			let pool: Vec<String> = c.call::<Vec<String>>("getrawmempool", &[]).unwrap_or_default();
			for t in pool {
				if seen.contains(&t) {
					continue;
				}
				let raw: Value = c.call("getrawtransaction", &[json!(t), json!(true)]).unwrap();
				let tx: elements::Transaction = elements::encode::deserialize(&unhex(raw["hex"].as_str().unwrap())).unwrap();
				if !claims_with_preimage(&tx, &op, &hash) {
					continue;
				}
				seen.push(t.clone());
				let fee: u64 = tx.output.iter().filter(|o| o.is_fee()).filter_map(|o| o.value.explicit()).sum();
				let bar = *bar.get_or_insert(20 * fee);
				if fee < bar {
					let pr: Result<Value, _> = c.call("prioritisetransaction", &[json!(t), json!(0), json!(-1_000_000_000i64)]);
					println!("{} the wallet's claim {} paying {} in the mempool at {} ({} s before the timeout): below the bar of {}, left \
						out of blocks ({:?})", tag, t, fee, mtp(&r), timeout as i64 - mtp(&r) as i64, bar, pr.is_ok());
				} else {
					raised += 1;
					println!("{} the wallet's claim {} paying {} at {} ({} s before the timeout): clears the bar of {}, taken", tag, t, fee,
						mtp(&r), timeout as i64 - mtp(&r) as i64, bar);
				}
			}
		}
		tokio::task::block_in_place(|| block_a_minute(&c, &wifs));
		r.synced().await;
		if let Some(hx) = &refund_hex {
			if let Ok(v) = c.call::<Value>("sendrawtransaction", &[json!(hx)]) {
				println!("{} the operator's refund accepted at median time {} ({} s from the timeout): {}", tag, mtp(&r),
					mtp(&r) as i64 - timeout as i64, v);
			}
		}
		if spent_on_chain(&r, &rec.0, 400).is_some() || mtp(&r) > timeout + 3600 {
			break;
		}
	}
	tokio::task::block_in_place(|| block_a_minute(&c, &wifs));
	let (claimed, fees) = outcome(&r, tag, &rec, &hash, timeout);
	let (ran, v) = wake(&a);
	println!("{} the wallet afterwards: {} -> exits {} | coin {} | balance {}", tag, ran, v["exits"], coin_of(&a, &leaf_id), a.ok(&["balance"]));
	drop((ox, px));
	let _ = std::fs::remove_dir_all(&a.dir);
	assert!(claimed, "the wallet's claim took the leaf (fees {:?})", fees);
	assert!(raised >= 1, "a claim raised past the bar was taken");
}

/// D76: the leaf's own asset no longer accepted for fees by the node once
/// the leaf is on its way home (producers that stop taking it): the wallet,
/// which holds an on-chain coin of Y, pays its claim's fee from that coin,
/// and the claim takes the leaf before the timeout. The operator's refund,
/// paying its fee in X, is refused throughout.
#[tokio::test(flavor = "multi_thread")]
async fn d76_a_claim_paid_from_another_asset_when_the_leafs_is_not_accepted() {
	let Some(lnd) = lightningd("d76_a_claim_paid_from_another_asset_when_the_leafs_is_not_accepted") else { return };
	let tag = "D76S4";
	let (mut r, _p, a, hash, leaf_id, rec, timeout, _confirmed, ox, px) = handed_over(&lnd, tag, 7200).await;
	let (x, y) = (r.x, r.y);
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, y, 1_000_000);
	r.produce().await;
	let home = a.ok(&["lightning", "receives"])[&hash]["home_at"].as_u64().unwrap() as u32;
	let wifs = stakers();
	let c = r.rt.client().clone();
	let mut delisted = false;
	let mut refund_hex: Option<String> = None;
	for step in 0..900 {
		if mtp(&r) + 600 < home {
			advance(&r, home - 300 - mtp(&r)).await;
		}
		// Once the wallet has begun the leaf's way home, the node stops
		// taking X for fees.
		if !delisted && coin_of(&a, &leaf_id)["state"] == "exiting" {
			let rates: Value = c.call("getfeeexchangerates", &[]).unwrap();
			let mut rates = rates.as_object().unwrap().clone();
			rates.remove(&x.to_string());
			let _: Value = c.call("setfeeexchangerates", &[Value::Object(rates)]).unwrap();
			delisted = true;
			println!("{} the node no longer takes X for fees: {}", tag, c.call::<Value>("getfeeexchangerates", &[]).unwrap());
		}
		let (ran, v) = wake(&a);
		if ran != "-" {
			println!("{} step {} at {} ({} s from the timeout): {} -> coin {} | exits {}", tag, step, mtp(&r), mtp(&r) as i64 - timeout as i64,
				ran, coin_of(&a, &leaf_id)["state"], v["exits"]);
		}
		tokio::task::block_in_place(|| block_a_minute(&c, &wifs));
		r.synced().await;
		if refund_hex.is_none() {
			if let Some((op, _)) = output_on_chain(&r, &rec.0, 400) {
				refund_hex = Some(elements::encode::serialize_hex(&rec.refund(&r, op, x)));
			}
		}
		if let Some(hx) = &refund_hex {
			if let Ok(v) = c.call::<Value>("sendrawtransaction", &[json!(hx)]) {
				println!("{} the operator's refund accepted at median time {}: {}", tag, mtp(&r), v);
			}
		}
		if spent_on_chain(&r, &rec.0, 400).is_some() || mtp(&r) > timeout + 3600 {
			break;
		}
	}
	tokio::task::block_in_place(|| block_a_minute(&c, &wifs));
	let (claimed, fees) = outcome(&r, tag, &rec, &hash, timeout);
	drop((ox, px));
	let _ = std::fs::remove_dir_all(&a.dir);
	assert!(claimed, "the wallet's claim took the leaf (fees {:?})", fees);
	assert!(fees.iter().all(|f| y.to_string().starts_with(&f.0)), "the claim's fee paid in Y: {:?}", fees);
}
