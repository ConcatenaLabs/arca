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
