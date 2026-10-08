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
