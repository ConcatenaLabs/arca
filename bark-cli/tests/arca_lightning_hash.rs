//! Receiving over Lightning under a payment hash the wallet did not make,
//! and paying with a chosen timeout, as the `arca` wallet does it: a payer
//! and a receiver at one operator, whose payment is settled inside the
//! operator, against a whole Arca server and its SeqLN node in X.
//!
//! The receiver asks under a hash whose preimage someone else holds
//! (`lightning receive … --hash`); the payer pays the invoice with an
//! `htlc-1` leaf timing out when it says (`lightning pay … --timeout`). The
//! receiver's leaf comes in the next round and is held apart, counted in no
//! balance, until the preimage reaches the wallet: handed to it
//! (`lightning preimage`), or served by the operator once anyone has posted
//! it (`lightning post-preimage`). Then it is claimed: co-signed, or on the
//! chain by its own claim carrying that preimage. A wallet restored from the
//! mnemonic finds such a leaf and holds it the same way. One whose preimage
//! never comes is failed back by the operator past the time to claim it, the
//! payer's leaf co-signed back to the payer.
//!
//! Needs what the other scenarios need, and `LIGHTNINGD_EXEC`.

mod common;

use elements::hashes::{sha256, Hash};
use elements::{AssetId, Script};
use serde_json::Value;

use server::server::LegSection;

use common::cli::Arca;
use common::lightning::{lightningd, node};
use common::proxy::Proxy;
use common::running::Running;
use server::store::RoundState;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

fn mtp(r: &Running) -> u32 {
	common::node::median_time(&r.rt)
}

async fn advance(r: &Running, s: u32) {
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, s));
	r.synced().await;
}

fn coin_of(w: &Arca, leaf: &str) -> Value {
	w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).cloned().unwrap_or(Value::Null)
}

/// The wallet's balance in `asset`, by standing.
fn standings(w: &Arca, asset: &AssetId) -> Value {
	w.ok(&["balance", "--without-bitcoin"])["arca"][asset.to_string()].clone()
}

/// The wallet's row for `asset`: what it counts.
fn row_total(w: &Arca, asset: &AssetId) -> u64 {
	let b = w.ok(&["balance", "--without-bitcoin"]);
	b["rows"].as_array().unwrap().iter().find(|r| r["asset"] == asset.to_string())
		.map(|r| r["total"].as_str().unwrap().parse().unwrap()).unwrap_or(0)
}

/// A preimage of this run and its hash.
fn preimage(tag: &str) -> ([u8; 32], String) {
	let seed = format!("{}-{}-{:?}", tag, std::process::id(), std::time::SystemTime::now());
	let p = sha256::Hash::hash(seed.as_bytes()).to_byte_array();
	(p, sha256::Hash::hash(&p).to_string())
}

/// The round of X that makes the leaves the operator wants, mined and final.
async fn leaf_round(r: &Running) {
	let built = r.server.rounds.run_round_of(r.x).await.unwrap().expect("a round");
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
}

fn wallet_at(name: &str, server: &str, r: &Running, mnemonic: Option<&str>) -> Arca {
	let a = Arca::new(name);
	let node_url = r.node_url();
	let mut args = vec!["create", "--server", server, "--node-url", &node_url, "--node-user", "arca", "--exit-delay-units", "4",
		"--min-exit-delay-units", "1"];
	if let Some(m) = mnemonic {
		args.extend(["--mnemonic", m]);
	}
	a.ok(&args);
	a
}

/// The leaf the wallet holds received under `hash`.
fn received_leaf(w: &Arca, hash: &str) -> String {
	let rec = &w.ok(&["lightning", "receives"])[hash];
	let nonce = rec["nonce"].as_str().unwrap_or("").to_string();
	w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["kind"] == "batch" && c["state"] == "receiving"
		&& (nonce.is_empty() || c["owner_nonce"].as_str().map_or(true, |n| n == nonce)))
		.map(|c| c["leaf_id"].as_str().unwrap().to_string()).unwrap_or_else(|| panic!("no received leaf for {}: {}", hash, rec))
}

/// `q` asks to receive `amount` of X under `hash`, and `p` pays the invoice
/// from its leaves with a leaf timing out at `timeout`; the operator holds the
/// payment inside it. The invoice.
async fn paid_inside(r: &Running, q: &Arca, p: &Arca, hash: &str, amount: u64, timeout: u32) -> String {
	let x = r.x.to_string();
	let inv = q.ok(&["lightning", "receive", &x, &amount.to_string(), "--hash", hash]);
	assert_eq!((inv["payment_hash"].as_str(), inv["hash_given"].as_bool()), (Some(hash), Some(true)), "{}", inv);
	let invoice = inv["invoice"].as_str().unwrap().to_string();
	let paying = p.ok(&["lightning", "pay", &invoice, "--timeout", &timeout.to_string(), "--wait", "5"]);
	assert_eq!(paying["payment"]["state"], "paying", "{}", paying);
	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
	loop {
		let l = q.ok(&["lightning", "lookup", hash]);
		if l["state"] == "accepted" {
			assert_eq!(l["held_by"], "send", "settled inside the operator: {}", l);
			assert_eq!(l["send_timeout"].as_u64(), Some(timeout as u64), "{}", l);
			assert_eq!(l["exit_delay_units"].as_u64(), Some(4), "{}", l);
			assert!(l["preimage"].is_null(), "no preimage yet: {}", l);
			break;
		}
		assert!(std::time::Instant::now() < deadline, "the payment was never held inside the operator: {}", l);
		tokio::time::sleep(std::time::Duration::from_millis(300)).await;
	}
	invoice
}

#[tokio::test(flavor = "multi_thread")]
async fn a_receive_under_a_given_hash_waits_for_its_preimage_and_is_claimed_with_it() {
	let Some(lnd) = lightningd("a_receive_under_a_given_hash_waits_for_its_preimage_and_is_claimed_with_it") else { return };
	let mut r = Running::start_seqln(|c, _, _| {
		c.fees.lightning_ppm = 1_000;
		c.lightning.operator_delay_units = 1;
		c.lightning.owner_delay_units = 2;
		c.lightning.send_timeout_seconds = 8 * 3600;
		c.lightning.send_stall_margin_seconds = 3600;
		c.lightning.poll_seconds = 1;
		c.lightning.retry_seconds = 10;
		c.lightning.receive_window_seconds = 600;
	}).await;
	let x = r.x;
	let xs = x.to_string();
	let ox = tokio::task::block_in_place(|| {
		let ox = node(&r.rt, &mut r.purse, &lnd, "lho", true, x, 2_000_000_000);
		let px = node(&r.rt, &mut r.purse, &lnd, "lhp", true, x, 1_000_000_000);
		ox.open_channel(&r.rt, &px, x, 1_000_000_000, 300_000_000);
		drop(px);
		ox
	});
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let mut config = r.config.clone();
	for a in config.assets.iter_mut() {
		if a.asset == xs {
			a.lightning = Some(LegSection { rpc: ox.rpc_path() });
		}
	}
	r.server.reload(&config).await.unwrap();
	r.config = config;
	let g = r.server.gateway.clone();
	r.wait("X's leg up", || g.leg(&x, true).is_ok()).await;
	let url = r.url();

	// The payer, P, with a board in X; the receiver, Q, with nothing.
	let p = wallet_at("LHP", &url, &r, None);
	let s = script(&p.ok(&["address"]));
	r.pay_to(s, x, 5_000_000);
	r.produce().await;
	p.ok(&["board", &xs, "3000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || p.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	p.ok(&["sync"]);
	let q = wallet_at("LHQ", &url, &r, None);
	let info = q.ok(&["info"]);
	let gap = info["server_info"]["lightning"]["receive"]["internal_gap_seconds"].as_u64().unwrap();
	println!("LH internal_gap_seconds {} (operator delay 512 s, stall margin 3,600 s, an hour)", gap);
	assert_eq!(gap, 512 + 3600 + 3600);

	// Refused before anything is asked: a BTC invoice takes no hash; a
	// preimage for a hash the wallet receives nothing under.
	let (pre1, h1) = preimage("one");
	println!("LH refused: {}", q.refused(&["lightning", "receive", "btc", "1000", "--hash", &h1], "it takes no payment hash"));
	println!("LH refused: {}", q.refused(&["lightning", "preimage", &h1, &hex(&pre1)], "receives nothing under hash"));

	// 1. A receive under a given hash, paid inside the operator; the leaf is
	// held apart until the wallet is handed the preimage.
	let inv1 = q.ok(&["lightning", "receive", &xs, "100000", "--hash", &h1]);
	println!("LH the receive under a given hash: {}", inv1);
	println!("LH refused: {}", q.refused(&["lightning", "receive", &xs, "100000", "--hash", &h1], "has a payment under hash"));
	let invoice1 = inv1["invoice"].as_str().unwrap().to_string();
	// A timeout outside the operator's window: refused, nothing signed.
	let before = (p.ok(&["coins"]), p.ok(&["lightning", "payments"]));
	let now = mtp(&r);
	for (t, what) in [(now + 600, "below"), (now + 17 * 3600, "above")] {
		println!("LH refused ({} the window): {}", what, p.refused(&["lightning", "pay", &invoice1, "--timeout", &t.to_string()],
			"outside the operator's window"));
	}
	assert_eq!((p.ok(&["coins"]), p.ok(&["lightning", "payments"])), before, "nothing signed, nothing recorded");
	let t1 = mtp(&r) + 8 * 3600 + 1800;
	let paying = p.ok(&["lightning", "pay", &invoice1, "--timeout", &t1.to_string(), "--wait", "5"]);
	assert_eq!(paying["payment"]["state"], "paying", "{}", paying);
	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
	while q.ok(&["lightning", "lookup", &h1])["state"] != "accepted" {
		assert!(std::time::Instant::now() < deadline, "never held");
		tokio::time::sleep(std::time::Duration::from_millis(300)).await;
	}
	let l1 = q.ok(&["lightning", "lookup", &h1]);
	println!("LH the operator's status: {}", l1);
	assert_eq!((l1["held_by"].as_str(), l1["send_timeout"].as_u64()), (Some("send"), Some(t1 as u64)));
	assert_eq!(l1["timeout"].as_u64(), Some(t1 as u64 - gap), "the receiver's leaf times out the gap before the payer's");
	q.ok(&["sync"]);
	leaf_round(&r).await;
	let synced = q.ok(&["sync"]);
	println!("LH the receiver's sync: lightning {}", synced["lightning"]);
	let leaf1 = received_leaf(&q, &h1);
	let st = standings(&q, &x);
	println!("LH the receiver's balance in X: {} | row {}", st, row_total(&q, &x));
	let value1: u64 = st["awaiting_preimage"].as_str().unwrap().parse().unwrap();
	assert_eq!(value1, 100_000 - (100_000u64 * 1_000).div_ceil(1_000_000), "the leaf, the amount less the operator's fee, held apart");
	assert_eq!(row_total(&q, &x), 0, "counted in no row");
	assert!(q.ok(&["balance", "--without-bitcoin"])["total"]["values"].get(&xs).is_none(), "and in no total");
	// Exit refused before anything is broadcast: nothing to claim it by.
	println!("LH refused: {}", q.refused(&["exit", &leaf1], "does not hold yet"));
	assert_eq!(coin_of(&q, &leaf1)["state"], "receiving", "nothing broadcast");
	let again = q.ok(&["sync"]);
	println!("LH a sync with no preimage: {}", again["lightning"]);
	assert_eq!(q.ok(&["lightning", "receives"])[&h1]["state"], "issuing");
	// Another preimage is refused; the right one is kept and the leaf claimed.
	let (wrong, _) = preimage("wrong");
	println!("LH refused: {}", q.refused(&["lightning", "preimage", &h1, &hex(&wrong)], "does not open"));
	let kept = q.ok(&["lightning", "preimage", &h1, &hex(&pre1)]);
	println!("LH the preimage handed to the wallet: {}", kept);
	let claimed = q.ok(&["sync"]);
	println!("LH the claim: {}", claimed["lightning"]);
	assert_eq!(q.ok(&["lightning", "receives"])[&h1]["state"], "received");
	assert!(row_total(&q, &x) > 0 && row_total(&q, &x) < value1, "the claimed leaf is counted, less the claim's margins");
	let sent = p.ok(&["sync"]);
	println!("LH the payer's sync: {}", sent["lightning"]);
	let pay1 = &p.ok(&["lightning", "payments"])[&h1];
	assert_eq!((pay1["state"].as_str(), pay1["preimage"].as_str()), (Some("paid"), Some(hex(&pre1).as_str())), "{}", pay1);

	// 2. The receiver's device is lost while the leaf waits; a wallet
	// restored from the mnemonic holds it the same way, and claims it once
	// the operator serves the preimage someone posted.
	let (pre2, h2) = preimage("two");
	let t2 = mtp(&r) + 8 * 3600 + 1800;
	paid_inside(&r, &q, &p, &h2, 120_000, t2).await;
	q.ok(&["sync"]);
	leaf_round(&r).await;
	q.ok(&["sync"]);
	let leaf2 = received_leaf(&q, &h2);
	let mnemonic = std::fs::read_to_string(q.dir.join("mnemonic")).unwrap().trim().to_string();
	let q2 = wallet_at("LHQ2", &url, &r, Some(&mnemonic));
	q2.ok(&["sync"]);
	let rec2 = q2.ok(&["lightning", "receives"])[&h2].clone();
	println!("LH the restored wallet's receive: {} | the leaf {} | balance {}", rec2, coin_of(&q2, &leaf2), standings(&q2, &x));
	assert_eq!((rec2["hash_given"].as_bool(), rec2["restored"].as_bool()), (Some(true), Some(true)), "{}", rec2);
	assert_eq!(coin_of(&q2, &leaf2)["state"], "receiving");
	assert!(standings(&q2, &x)["awaiting_preimage"].as_str().is_some(), "held apart in the restored wallet too");
	println!("LH refused (a preimage posted for another hash): {}", p.refused(&["lightning", "post-preimage", &h2, &hex(&pre1)],
		"does not open"));
	let posted = p.ok(&["lightning", "post-preimage", &h2, &hex(&pre2)]);
	println!("LH posted: state {} preimage {}", posted["state"], posted["preimage"]);
	assert_eq!(posted["state"], "claimed");
	assert_eq!(q2.ok(&["lightning", "lookup", &h2])["preimage"].as_str(), Some(hex(&pre2).as_str()), "served from then on");
	let c2 = q2.ok(&["sync"]);
	println!("LH the restored wallet's claim: {}", c2["lightning"]);
	assert_eq!(q2.ok(&["lightning", "receives"])[&h2]["state"], "received");
	p.ok(&["sync"]);
	assert_eq!(p.ok(&["lightning", "payments"])[&h2]["state"], "paid");

	// 3. The leaf taken home on the chain by its claim, with the preimage
	// handed to the wallet: the claim carries it, and the operator reads it
	// there and decides the payment out of the tree paid.
	let (pre3, h3) = preimage("three");
	let t3 = mtp(&r) + 8 * 3600 + 1800;
	paid_inside(&r, &q2, &p, &h3, 150_000, t3).await;
	q2.ok(&["sync"]);
	leaf_round(&r).await;
	q2.ok(&["sync"]);
	let leaf3 = received_leaf(&q2, &h3);
	q2.ok(&["lightning", "preimage", &h3, &hex(&pre3)]);
	let mut claim_seen = false;
	for i in 0..12 {
		let e = q2.ok(&["exit", &leaf3]);
		println!("LH exit {}: state {} next {} error {}", i, e["state"], e["next"], e["error"]);
		r.produce().await;
		let lk = q2.ok(&["lightning", "lookup", &h3]);
		if lk["state"] == "claimed" {
			println!("LH the operator read the preimage on the chain: {}", lk);
			assert_eq!(lk["preimage"].as_str(), Some(hex(&pre3).as_str()));
			claim_seen = true;
			break;
		}
		advance(&r, 700).await;
	}
	assert!(claim_seen, "the claim on the chain with the given preimage settles the payment");
	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
	loop {
		p.ok(&["sync"]);
		if p.ok(&["lightning", "payments"])[&h3]["state"] == "paid" {
			break;
		}
		assert!(std::time::Instant::now() < deadline, "the payment out of the tree was never decided paid");
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
	}
	// 4. Nobody ever has the preimage (the hash's maker never claimed what
	// it was owed): past the time to claim, the operator fails the receive
	// back and the payment out of the tree with it, the payer's leaf comes
	// back to it co-signed, and the receiver's leaf, counted nowhere
	// throughout, is the operator's.
	let (_, h4) = preimage("four");
	let t4 = mtp(&r) + 8 * 3600 + 1800;
	paid_inside(&r, &q2, &p, &h4, 110_000, t4).await;
	q2.ok(&["sync"]);
	leaf_round(&r).await;
	q2.ok(&["sync"]);
	let leaf4 = received_leaf(&q2, &h4);
	let row_before = row_total(&q2, &x);
	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
	loop {
		let lk = q2.ok(&["lightning", "lookup", &h4]);
		if lk["state"] == "cancelled" {
			println!("LH failed back at median time {} (the payer's leaf times out at {}, the receiver's at {}): {}", mtp(&r), t4,
				lk["timeout"], lk["reason"]);
			break;
		}
		assert!(std::time::Instant::now() < deadline, "never failed back: {}", lk);
		assert_eq!(row_total(&q2, &x), row_before, "the awaiting leaf is counted nowhere meanwhile");
		advance(&r, 1800).await;
		p.run(&["sync"]);
		q2.run(&["sync"]);
		tokio::time::sleep(std::time::Duration::from_secs(2)).await;
	}
	let mut back = Value::Null;
	for _ in 0..30 {
		p.ok(&["sync"]);
		back = p.ok(&["lightning", "payments"])[&h4].clone();
		if back["state"] == "returned" {
			break;
		}
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
	}
	println!("LH the payer's payment: {}", back);
	assert_eq!(back["state"], "returned", "the payer's leaf comes back to it co-signed");
	let s4 = q2.ok(&["sync"]);
	let rec4 = q2.ok(&["lightning", "receives"])[&h4].clone();
	println!("LH the receiver's sync: {} | its receive {} | the leaf {}", s4["lightning"], rec4, coin_of(&q2, &leaf4));
	assert_eq!(rec4["state"], "failed", "{}", rec4);
	assert_eq!(coin_of(&q2, &leaf4)["state"], "spent", "the leaf is the operator's");
	assert_eq!(row_total(&q2, &x), row_before, "nothing of it was ever counted");
	drop(ox);
	for w in [&p, &q, &q2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A claim the operator co-signs whose answer never reaches the wallet (a
/// timeout, a 5xx from a loaded machine): the coin the claim made comes
/// through the wallet's mailbox, or in the answer when `sync` posts the
/// request again. Either way the receive then names that coin, as an
/// answered claim does, so a program following the payment finds it.
#[tokio::test(flavor = "multi_thread")]
async fn a_claim_answered_only_when_posted_again_names_its_leaf() {
	let Some(lnd) = lightningd("a_claim_answered_only_when_posted_again_names_its_leaf") else { return };
	let mut r = Running::start_seqln(|c, _, _| {
		c.fees.lightning_ppm = 1_000;
		c.lightning.operator_delay_units = 1;
		c.lightning.owner_delay_units = 2;
		c.lightning.send_timeout_seconds = 8 * 3600;
		c.lightning.send_stall_margin_seconds = 3600;
		c.lightning.poll_seconds = 1;
		c.lightning.retry_seconds = 10;
		c.lightning.receive_window_seconds = 600;
	}).await;
	let x = r.x;
	let xs = x.to_string();
	let ox = tokio::task::block_in_place(|| {
		let ox = node(&r.rt, &mut r.purse, &lnd, "lro", true, x, 2_000_000_000);
		let px = node(&r.rt, &mut r.purse, &lnd, "lrp", true, x, 1_000_000_000);
		ox.open_channel(&r.rt, &px, x, 1_000_000_000, 300_000_000);
		drop(px);
		ox
	});
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let mut config = r.config.clone();
	for a in config.assets.iter_mut() {
		if a.asset == xs {
			a.lightning = Some(LegSection { rpc: ox.rpc_path() });
		}
	}
	r.server.reload(&config).await.unwrap();
	r.config = config;
	let g = r.server.gateway.clone();
	r.wait("X's leg up", || g.leg(&x, true).is_ok()).await;
	let url = r.url();
	let proxy = Proxy::start(&url);

	// The payer, P, with a board in X; the receiver, Q, through the proxy.
	let p = wallet_at("LRP", &url, &r, None);
	let s = script(&p.ok(&["address"]));
	r.pay_to(s, x, 5_000_000);
	r.produce().await;
	p.ok(&["board", &xs, "3000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || p.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	p.ok(&["sync"]);
	let q = wallet_at("LRQ", &proxy.url, &r, None);

	// The claim's answer lost, whatever the answer: the first claim posted
	// while `lose` is set, and every mailbox read while `deaf` is.
	let lose = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
	let deaf = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
	let (l, d) = (lose.clone(), deaf.clone());
	proxy.rewrite(Some(std::sync::Arc::new(move |path: &str, _: &Value, status: u16, v: &mut Value| {
		use std::sync::atomic::Ordering::SeqCst;
		let claim = path.ends_with("/lightning_receive_claim") && status == 200 && l.swap(false, SeqCst);
		if claim || (path.ends_with("/mailbox_read") && d.load(SeqCst)) {
			*v = serde_json::json!({"error": {"code": "unavailable", "message": "lost on the way"}});
			return Some(503);
		}
		None
	})));
	let claims = || proxy.calls().iter().filter(|(path, ..)| path.ends_with("/lightning_receive_claim")).count();
	let mut held = 0u64;
	for (k, through) in ["posted again", "the mailbox"].into_iter().enumerate() {
		let (pre, h) = preimage(through);
		let t = mtp(&r) + 8 * 3600 + 1800;
		paid_inside(&r, &q, &p, &h, 100_000 + k as u64 * 10_000, t).await;
		q.ok(&["sync"]);
		leaf_round(&r).await;
		q.ok(&["sync"]);
		let htlc = received_leaf(&q, &h);
		q.ok(&["lightning", "preimage", &h, &hex(&pre)]);
		let before = claims();
		lose.store(true, std::sync::atomic::Ordering::SeqCst);
		deaf.store(k == 0, std::sync::atomic::Ordering::SeqCst);
		let first = q.ok(&["sync"]);
		deaf.store(false, std::sync::atomic::Ordering::SeqCst);
		let rec = q.ok(&["lightning", "receives"])[&h].clone();
		println!("LR {}: the claim's answer lost: sync lightning {} | mailbox {} | receive state {} leaf {} | the received leaf {}", through,
			first["lightning"], first["mailbox"], rec["state"], rec["leaf"], coin_of(&q, &htlc));
		assert!(!lose.load(std::sync::atomic::Ordering::SeqCst), "the operator answered the claim, and the answer was lost");
		assert_eq!(claims(), before + 1);
		if k == 0 {
			// Nothing came: the request stands, posted again by the next sync.
			assert_eq!(rec["state"], "claiming", "{}", rec);
			assert_eq!(coin_of(&q, &htlc)["state"], "sending", "the claim request stands");
			let second = q.ok(&["sync"]);
			println!("LR {}: transfers {} | lightning {}", through, second["transfers"], second["lightning"]);
			assert_eq!(claims(), before + 2, "the claim was posted again");
		}
		let rec = q.ok(&["lightning", "receives"])[&h].clone();
		println!("LR {}: the receive {}", through, rec);
		assert_eq!(rec["state"], "received", "{}", rec);
		let leaf = rec["leaf"].as_str().unwrap_or_else(|| panic!("the receive names no leaf: {}", rec)).to_string();
		let c = coin_of(&q, &leaf);
		let spent = coin_of(&q, &htlc);
		println!("LR {}: the coin it names {} | the received leaf {} spent by {}", through, c, spent["state"], spent["spent_by"]);
		assert_eq!((c["state"].as_str(), c["asset"].as_str()), (Some("live"), Some(xs.as_str())), "{}", c);
		let v: u64 = c["value"].as_str().unwrap().parse().unwrap();
		assert!(v > 0 && v < 100_000 + k as u64 * 10_000, "the amount less the fee and the claim's margins: {}", v);
		assert_eq!(spent["state"], "spent", "the received leaf is spent by the claim");
		held += v;
		p.ok(&["sync"]);
		assert_eq!(p.ok(&["lightning", "payments"])[&h]["state"], "paid");
	}
	// Each coin once: a request posted again makes no second coin.
	let live: u64 = q.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == xs.as_str())
		.map(|c| c["value"].as_str().unwrap().parse::<u64>().unwrap()).sum();
	println!("LR the receiver holds {} of X live, the two claimed coins {}", live, held);
	assert_eq!(live, held);

	drop(ox);
	for w in [&p, &q] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
