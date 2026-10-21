//! A swap of native BTC in a Bitcoin ark for an asset in an Arca tree,
//! under one payment hash, as two `arca` wallets run it (`arca btc-swap`):
//! a whole Arca server with its SeqLN node in X on the chain SeqLN's
//! `sequentia-regtest` network assumes, and a real Bitcoin ark on regtest
//! (`contrib/bitcoin-ark-regtest/`: Bark's server, its Lightning gateway),
//! each wallet's Bitcoin side Bark's own client and daemon on a wallet made
//! from the Arca wallet's mnemonic.
//!
//! P gives X and gets BTC; Q gives BTC and gets X. P locks first, its X in an
//! `htlc-1` leaf paying the operator's invoice for Q's receive under the hash
//! of P's Bark invoice, settled inside the operator; Q pays P's invoice once
//! its received leaf is held and final; P's claim of the BTC reveals the
//! preimage, which P posts to the operator and Q reads from its payment, and
//! Q claims the leaf with it.
//!
//! Needs what the Lightning scenarios need (`LIGHTNINGD_EXEC`), and what the
//! Bitcoin ark test needs (`ARCA_TEST_BITCOIN_ARK`, `ARCA_BARK_EXEC`,
//! `ARCA_BARKD_EXEC`). Skipped otherwise.

mod common;

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use bitcoin::hashes::{sha256, Hash};
use elements::{AssetId, Script};
use serde_json::{json, Value};

use server::server::LegSection;

use common::cli::Arca;
use common::lightning::{lightningd, node};
use common::running::Running;
use server::store::RoundState;

// ---------------------------------------------------------------------------
// The Bitcoin ark
// ---------------------------------------------------------------------------

fn harness() -> Option<PathBuf> {
	std::env::var_os("ARCA_TEST_BITCOIN_ARK").map(PathBuf::from)
}

fn ark(args: &[&str]) -> String {
	let out = Command::new(harness().unwrap()).args(args).output().expect("run the harness");
	assert!(out.status.success(), "regtest.sh {:?}: {}{}", args, String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
	String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn ark_json(args: &[&str]) -> Value {
	let s = ark(args);
	let s = s.find('{').map(|i| &s[i..]).unwrap_or(&s);
	serde_json::from_str(s).unwrap_or_else(|e| panic!("regtest.sh {:?}: not JSON ({}): {}", args, e, s))
}

fn mine(n: u32) {
	ark(&["mine", &n.to_string()]);
}

/// Bark's own JSON, through `arca bitcoin`.
fn bark(a: &Arca, args: &[&str]) -> Value {
	let out = tokio::task::block_in_place(|| Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&a.dir)
		.arg("bitcoin").arg("--quiet").args(args).output().unwrap());
	assert!(out.status.success(), "{} arca bitcoin {:?}: {}", a.name, args, String::from_utf8_lossy(&out.stderr));
	serde_json::from_slice(&out.stdout).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&out.stdout).trim().to_string()))
}

fn spendable_sat(a: &Arca) -> u64 {
	bark(a, &["balance"])["spendable_sat"].as_u64().unwrap()
}

fn maintain(a: &Arca) {
	let _ = tokio::task::block_in_place(|| Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&a.dir)
		.args(["bitcoin", "--quiet", "maintain"]).output());
}

/// Waits up to `secs`, a block mined and each wallet's Bark caught up each
/// time, until `done`.
fn until_btc(ws: &[&Arca], secs: u64, what: &str, mut done: impl FnMut() -> bool) {
	let t0 = Instant::now();
	while !done() {
		assert!(t0.elapsed() < Duration::from_secs(secs), "{}: not within {} s", what, secs);
		mine(1);
		for w in ws {
			maintain(w);
		}
		std::thread::sleep(Duration::from_secs(1));
	}
}

// ---------------------------------------------------------------------------
// The Arca side
// ---------------------------------------------------------------------------

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
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

/// What `w` holds in `asset` off the chain and on it, as its row counts it.
fn x_row(w: &Arca, asset: &AssetId) -> u64 {
	let b = w.ok(&["balance", "--without-bitcoin"]);
	b["rows"].as_array().unwrap().iter().find(|r| r["asset"] == asset.to_string())
		.map(|r| r["total"].as_str().unwrap().parse().unwrap()).unwrap_or(0)
}

/// The round of X that makes the leaves the operator wants, mined and final.
async fn leaf_round(r: &Running) -> elements::Txid {
	let built = r.server.rounds.run_round_of(r.x).await.unwrap().expect("a round");
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	built.tx.txid()
}

async fn receive_row(r: &Running, hash: &str) -> Option<server::store::ReceiveRow> {
	let h: [u8; 32] = unhex(hash).try_into().unwrap();
	r.server.receives.status(&h).await.unwrap()
}

/// An operator whose Lightning terms let a swap run on the regtest Bitcoin
/// ark: a payment's timeout three to six days out, since the Bitcoin leg can
/// end 88 hours after it starts (Bark's HTLC-send expiry delta of 258 blocks
/// at half Bitcoin's pace), and short delays otherwise.
async fn operator(lnd: &PathBuf, tag: &str) -> (Running, sequentia_ext::lightning::LightningNode) {
	operator_with(lnd, tag, 3600).await
}

/// [`operator`], its invoices for payments into the tree good for
/// `invoice_expiry` seconds (a term the operator takes at its start).
async fn operator_with(lnd: &PathBuf, tag: &str, invoice_expiry: u32) -> (Running, sequentia_ext::lightning::LightningNode) {
	let mut r = Running::start_seqln(|c, _, _| {
		c.lightning.invoice_expiry_seconds = invoice_expiry;
		c.fees.lightning_ppm = 1_000;
		c.lightning.operator_delay_units = 1;
		c.lightning.owner_delay_units = 2;
		c.lightning.send_timeout_seconds = 3 * 86_400;
		c.lightning.send_stall_margin_seconds = 3600;
		c.lightning.poll_seconds = 1;
		c.lightning.retry_seconds = 10;
		c.lightning.receive_window_seconds = 600;
	}).await;
	let x = r.x;
	let ox = tokio::task::block_in_place(|| {
		let ox = node(&r.rt, &mut r.purse, lnd, &format!("{}o", tag), true, x, 2_000_000_000);
		let px = node(&r.rt, &mut r.purse, lnd, &format!("{}p", tag), true, x, 1_000_000_000);
		ox.open_channel(&r.rt, &px, x, 1_000_000_000, 300_000_000);
		drop(px);
		ox
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
	(r, ox)
}

/// A mnemonic no earlier run used, so the Bitcoin ark holds nothing of it.
fn fresh_mnemonic(tag: &str) -> String {
	let seed = format!("{}-{}-{:?}", tag, std::process::id(), std::time::SystemTime::now());
	let entropy = sha256::Hash::hash(seed.as_bytes()).to_byte_array();
	bip39::Mnemonic::from_entropy(&entropy[..16]).unwrap().to_string()
}

/// A dual-chain wallet of the operator: an Arca wallet, and its Bitcoin ark
/// wallet made from the same mnemonic, holding about `board_sat` in the ark.
fn dual_wallet(r: &Running, name: &str, board_sat: u64, mnemonic: Option<&str>) -> Arca {
	let a = Arca::new(name);
	let m = mnemonic.map(String::from).unwrap_or_else(|| fresh_mnemonic(name));
	let node_url = r.node_url();
	a.ok(&["create", "--server", &r.url(), "--node-url", &node_url, "--node-user", "arca", "--exit-delay-units", "4",
		"--min-exit-delay-units", "1", "--mnemonic", &m]);
	let info = ark_json(&["info"]);
	let (url, bitcoind, cookie) = (info["ark"].as_str().unwrap(), info["bitcoind"].as_str().unwrap(), info["cookie"].as_str().unwrap());
	a.ok(&["bitcoin", "create", "--regtest", "--ark", url, "--bitcoind", bitcoind, "--bitcoind-cookie", cookie]);
	if board_sat > 0 {
		let addr = bark(&a, &["onchain", "address"])["address"].as_str().unwrap().to_string();
		ark(&["btc", "-rpcwallet=miner", "sendtoaddress", &addr, "0.02"]);
		mine(1);
		until_btc(&[&a], 60, "the on-chain funding", || bark(&a, &["onchain", "balance"])["confirmed_sat"].as_u64().unwrap() >= 2_000_000);
		a.ok(&["bitcoin", "board", &format!("{} sat", board_sat)]);
		until_btc(&[&a], 120, "the board", || spendable_sat(&a) > 0);
	}
	a
}

/// Mines Bitcoin blocks with pauses: the Bitcoin ark's server grants a
/// Lightning receive's HTLCs from a pool of VTXOs it keeps (five of 1,000
/// sat and five of 10,000 on the harness), which it refills on the chain as
/// blocks come; with the pool empty it grants none, and the payer's payment
/// is failed back.
fn refill_pool() {
	for _ in 0..4 {
		mine(1);
		std::thread::sleep(Duration::from_secs(3));
	}
}

/// P's leaves in X: a board, credited and final.
async fn fund_x(r: &mut Running, a: &Arca, atoms: u64) {
	let s = script(&a.ok(&["address"]));
	let x = r.x;
	r.pay_to(s, x, atoms + 1_000_000);
	r.produce().await;
	a.ok(&["board", &r.x.to_string(), &atoms.to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
}

/// `arca btc-swap follow --wait SECS` in a thread of its own, as a client
/// running its follow loop does while the other party acts.
fn follow_in_background(a: &Arca, secs: u64) -> std::thread::JoinHandle<Value> {
	let (dir, name) = (a.dir.clone(), a.name.clone());
	std::thread::spawn(move || {
		let out = Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&dir).arg("--witness-patience").arg("3")
			.args(["btc-swap", "follow", "--wait", &secs.to_string(), "--claim-slice", "15"])
			.env("ARCA_NODE_PASSWORD", "arca").output().expect("run arca");
		let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| json!({"stdout": String::from_utf8_lossy(&out.stdout),
			"stderr": String::from_utf8_lossy(&out.stderr)}));
		println!("{} (background) $ arca btc-swap follow --wait {}\n{}", name, secs, v);
		v
	})
}

fn swap_of(a: &Arca, id: &str) -> Value {
	a.ok(&["btc-swap", "list"])["swaps"][id].clone()
}

/// Follows `a`'s swaps until swap `id` is in `state`, the operator's rounds
/// and the chains moving as `step` makes them.
fn follow_until(a: &Arca, id: &str, state: &str, secs: u64) -> Value {
	let t0 = Instant::now();
	loop {
		let f = a.ok(&["btc-swap", "follow", "--claim-slice", "5"]);
		let s = swap_of(a, id);
		println!("{} swap {}: {} | {}", a.name, &id[..12], s["state"], s["note"]);
		if s["state"] == state {
			return f;
		}
		assert!(t0.elapsed() < Duration::from_secs(secs), "{}: swap {} not {} within {} s: {}", a.name, id, state, secs, s);
		std::thread::sleep(Duration::from_secs(2));
	}
}

fn skip() -> bool {
	let missing = harness().is_none() || std::env::var_os("ARCA_BARK_EXEC").is_none() || std::env::var_os("ARCA_BARKD_EXEC").is_none();
	if missing {
		println!("skipped: ARCA_TEST_BITCOIN_ARK, ARCA_BARK_EXEC and ARCA_BARKD_EXEC name no Bitcoin ark and no Bark");
	}
	missing
}

/// One complete swap between `p` (gives X) and `q` (gives BTC), the maker
/// `maker_p` or not, from the offer to both legs done. Checks each side's
/// books. Returns the swap's id.
async fn complete_swap(r: &Running, p: &Arca, q: &Arca, maker_p: bool, atoms: u64, sats: u64) -> String {
	let xs = r.x.to_string();
	refill_pool();
	let (p_x0, q_x0, p_btc0, q_btc0) = (x_row(p, &r.x), x_row(q, &r.x), spendable_sat(p), spendable_sat(q));
	let (maker, taker) = if maker_p { (p, q) } else { (q, p) };
	let give = if maker_p { "asset" } else { "btc" };
	let offer = maker.ok(&["btc-swap", "offer", "--give", give, "--asset", &xs, "--atoms", &atoms.to_string(), "--sats", &sats.to_string()]);
	let id = offer["swap"].as_str().unwrap().to_string();
	println!("SWAP offer by {} ({}): shows {}", maker.name, offer["role"], offer["shows"]);
	let read = taker.ok(&["btc-swap", "read", offer["offer"].as_str().unwrap()]);
	println!("SWAP read by {} ({}): shows {}", taker.name, read["role"], read["shows"]);
	let take = taker.ok(&["btc-swap", "take", offer["offer"].as_str().unwrap()]);
	assert_eq!(take["swap"].as_str(), Some(id.as_str()));
	maker.ok(&["btc-swap", "complete", take["take"].as_str().unwrap()]);
	let hash = swap_of(p, &id)["hash"].as_str().unwrap().to_string();
	assert_eq!(swap_of(q, &id)["hash"].as_str(), Some(hash.as_str()), "one hash on both sides");

	// P locks its X; the operator holds the payment inside it.
	follow_until(p, &id, "locked", 60);
	let t0 = Instant::now();
	while !receive_row(r, &hash).await.is_some_and(|x| x.state.name() == "accepted") {
		assert!(t0.elapsed() < Duration::from_secs(60), "the operator never held the payment");
		tokio::time::sleep(Duration::from_millis(300)).await;
	}
	let row = receive_row(r, &hash).await.unwrap();
	println!("SWAP the operator holds it inside: held_by_send {} send_timeout {:?} timeout {:?} (median time {})", row.held_by_send,
		row.send_timeout, row.timeout, mtp(r));
	assert!(row.held_by_send);
	// Q's leaf, in the next round, final.
	leaf_round(r).await;
	// P claims while Q pays.
	let pf = follow_in_background(p, 150);
	follow_until(q, &id, "done", 150);
	let _ = pf.join();
	follow_until(p, &id, "done", 120);
	until_btc(&[p, q], 60, "the BTC settled", || spendable_sat(p) > p_btc0);
	let (p_x1, q_x1, p_btc1, q_btc1) = (x_row(p, &r.x), x_row(q, &r.x), spendable_sat(p), spendable_sat(q));
	println!("SWAP books: P's X {} -> {} ({}), Q's X {} -> {} (+{}), P's BTC {} -> {} (+{}), Q's BTC {} -> {} ({})", p_x0, p_x1,
		p_x1 as i64 - p_x0 as i64, q_x0, q_x1, q_x1 as i64 - q_x0 as i64, p_btc0, p_btc1, p_btc1 as i64 - p_btc0 as i64, q_btc0, q_btc1,
		q_btc1 as i64 - q_btc0 as i64);
	let op_fee = (atoms * 1_000).div_ceil(1_000_000);
	assert!(p_x0 - p_x1 >= atoms + op_fee && p_x0 - p_x1 <= atoms + op_fee + 2_000, "P gave the atoms and the operator's fee, and margins");
	assert!(q_x1 - q_x0 <= atoms - op_fee && q_x1 - q_x0 + 2_000 >= atoms - op_fee, "Q got the atoms less the fee and the claim's margins");
	assert_eq!(p_btc1 - p_btc0, sats - (100 + sats * 2_000 / 1_000_000), "P got the satoshis less Bark's receive fee");
	assert!(q_btc0 - q_btc1 > sats && q_btc0 - q_btc1 < sats + 1_000, "Q gave the satoshis and Bark's send fee");
	let pre = swap_of(p, &id)["preimage"].as_str().unwrap().to_string();
	assert_eq!(swap_of(q, &id)["preimage"].as_str(), Some(pre.as_str()), "one preimage");
	assert_eq!(receive_row(r, &hash).await.unwrap().state.name(), "claimed");
	id
}

#[tokio::test(flavor = "multi_thread")]
async fn a_swap_of_btc_for_an_asset_completes_in_each_direction() {
	if skip() {
		return;
	}
	let Some(lnd) = lightningd("a_swap_of_btc_for_an_asset_completes_in_each_direction") else { return };
	let (mut r, ox) = operator(&lnd, "sw1").await;
	let p = dual_wallet(&r, "SWP", 0, None);
	let q = dual_wallet(&r, "SWQ", 600_000, None);
	fund_x(&mut r, &p, 2_000_000).await;
	// The maker gives the asset.
	complete_swap(&r, &p, &q, true, 100_000, 30_000).await;
	// The maker gives the BTC.
	complete_swap(&r, &p, &q, false, 120_000, 25_000).await;
	drop(ox);
	for w in [&p, &q] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// The offer, take and completion of one swap, P the maker or not: its id
/// and hash. Nothing is locked yet.
fn agreed(r: &Running, p: &Arca, q: &Arca, maker_p: bool, atoms: u64, sats: u64, lapse: u64) -> (String, String) {
	let xs = r.x.to_string();
	let (maker, taker) = if maker_p { (p, q) } else { (q, p) };
	let give = if maker_p { "asset" } else { "btc" };
	let offer = maker.ok(&["btc-swap", "offer", "--give", give, "--asset", &xs, "--atoms", &atoms.to_string(), "--sats",
		&sats.to_string(), "--lapse-seconds", &lapse.to_string()]);
	let take = taker.ok(&["btc-swap", "take", offer["offer"].as_str().unwrap()]);
	maker.ok(&["btc-swap", "complete", take["take"].as_str().unwrap()]);
	let id = offer["swap"].as_str().unwrap().to_string();
	let hash = swap_of(p, &id)["hash"].as_str().unwrap().to_string();
	(id, hash)
}

/// `arca btc-swap follow SWAP` once, and the swap after.
fn follow_one(a: &Arca, id: &str) -> Value {
	a.ok(&["btc-swap", "follow", id, "--claim-slice", "5"]);
	swap_of(a, id)
}

/// Bark's own claim of `invoice` in the background, as a P that claims the
/// BTC and then posts nothing (its client stopped right after).
fn bare_claim(a: &Arca, invoice: &str) -> std::thread::JoinHandle<String> {
	let (dir, inv) = (a.dir.clone(), invoice.to_string());
	std::thread::spawn(move || {
		let out = Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&dir)
			.args(["bitcoin", "--quiet", "lightning", "claim", &inv, "--wait"]).output().expect("run arca");
		format!("{} {}", out.status, String::from_utf8_lossy(&out.stderr))
	})
}

/// Section 7 of the design, each row forced: nobody ends holding both legs.
///
/// - A, the offer never taken: it lapses; P's Bark invoice is cancelled.
/// - B, taken and never completed: Q's receive lapses unpaid at the
///   operator; P's late completion locks nothing.
/// - C, P locks and Q's leaf never comes (no round takes it): the operator
///   fails the receive back, and P's lock with it.
/// - D, Q's leaf issued and Q never pays: past the leaf's time the receive
///   fails back, and P's lock with it.
/// - E, Q pays and P never claims (P gone after its lock, the preimage
///   withheld): Bark fails Q's payment back; Q pays again at most twice,
///   each refused at once; then as D.
/// - F, P claims the BTC with Bark alone and never posts the preimage: Q
///   reads it from its payment and claims its leaf, and the operator, from
///   that claim, decides P's payment paid.
#[tokio::test(flavor = "multi_thread")]
async fn each_abandoned_swap_leaves_every_leg_with_one_party() {
	if skip() {
		return;
	}
	let Some(lnd) = lightningd("each_abandoned_swap_leaves_every_leg_with_one_party") else { return };
	// Invoices for payments into the tree good for two minutes, so a receive
	// nobody pays lapses within the test.
	let (mut r, ox) = operator_with(&lnd, "sw2", 120).await;
	let xs = r.x.to_string();
	let p = dual_wallet(&r, "SAP", 0, None);
	let q = dual_wallet(&r, "SAQ", 800_000, None);
	fund_x(&mut r, &p, 3_000_000).await;
	let (p_x0, q_x0, q_btc0) = (x_row(&p, &r.x), x_row(&q, &r.x), spendable_sat(&q));

	// A. Offered, never taken.
	let a = p.ok(&["btc-swap", "offer", "--give", "asset", "--asset", &xs, "--atoms", "50000", "--sats", "10000", "--lapse-seconds", "60"]);
	let a_id = a["swap"].as_str().unwrap().to_string();
	let a_inv = swap_of(&p, &a_id)["invoice_btc"].as_str().unwrap().to_string();
	std::thread::sleep(Duration::from_secs(62));
	println!("ROW A refused: {}", q.refused(&["btc-swap", "take", a["offer"].as_str().unwrap()], "lapsed"));
	let sa = follow_one(&p, &a_id);
	println!("ROW A P's swap: {} | {}", sa["state"], sa["outcome"]);
	assert_eq!(sa["state"], "lapsed");
	let gone = tokio::task::block_in_place(|| Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&p.dir)
		.args(["bitcoin", "--quiet", "lightning", "receive", "status", &a_inv, "--no-sync"]).output().unwrap());
	println!("ROW A Bark's receive after the lapse: {} {}", String::from_utf8_lossy(&gone.stdout).trim(), String::from_utf8_lossy(&gone.stderr).trim());

	// B. Taken, never completed: the maker P gone after the take.
	refill_pool();
	let b = p.ok(&["btc-swap", "offer", "--give", "asset", "--asset", &xs, "--atoms", "50000", "--sats", "10000"]);
	let b_id = b["swap"].as_str().unwrap().to_string();
	let b_take = q.ok(&["btc-swap", "take", b["offer"].as_str().unwrap()]);
	let b_hash = b_take["hash"].as_str().unwrap().to_string();
	let t0 = Instant::now();
	while !receive_row(&r, &b_hash).await.is_some_and(|x| x.state.name() == "cancelled") {
		assert!(t0.elapsed() < Duration::from_secs(200), "the receive never lapsed");
		tokio::time::sleep(Duration::from_secs(2)).await;
	}
	let sb = follow_one(&q, &b_id);
	println!("ROW B Q's swap: {} | {} | the operator: {:?}", sb["state"], sb["outcome"], receive_row(&r, &b_hash).await.unwrap().reason);
	assert_eq!(sb["state"], "abandoned");
	p.ok(&["btc-swap", "complete", b_take["take"].as_str().unwrap()]);
	let sb = follow_one(&p, &b_id);
	println!("ROW B P's late completion: {} | {}", sb["state"], sb["outcome"]);
	assert_eq!(sb["state"], "lapsed", "nothing locked");
	assert_eq!((x_row(&p, &r.x), x_row(&q, &r.x)), (p_x0, q_x0), "rows A and B moved nothing");

	// D, E, F: P locks each; one round issues Q's three leaves.
	refill_pool();
	let (d_id, d_hash) = agreed(&r, &p, &q, false, 60_000, 10_000, 1800);
	let (e_id, e_hash) = agreed(&r, &p, &q, true, 70_000, 12_000, 1800);
	let (f_id, f_hash) = agreed(&r, &p, &q, true, 80_000, 15_000, 1800);
	for id in [&d_id, &e_id, &f_id] {
		follow_until(&p, id, "locked", 60);
	}
	for h in [&d_hash, &e_hash, &f_hash] {
		let t0 = Instant::now();
		while !receive_row(&r, h).await.is_some_and(|x| x.state.name() == "accepted") {
			assert!(t0.elapsed() < Duration::from_secs(60), "never held");
			tokio::time::sleep(Duration::from_millis(300)).await;
		}
	}
	leaf_round(&r).await;
	q.ok(&["sync"]);

	// F: P claims with Bark alone, posting nothing; Q pays and claims.
	let f_inv = swap_of(&p, &f_id)["invoice_btc"].as_str().unwrap().to_string();
	let claim = bare_claim(&p, &f_inv);
	std::thread::sleep(Duration::from_secs(2));
	let t0 = Instant::now();
	loop {
		let s = follow_one(&q, &f_id);
		println!("ROW F Q's swap: {} | {}", s["state"], s["note"]);
		if s["state"] == "done" {
			break;
		}
		assert!(t0.elapsed() < Duration::from_secs(150), "Q never completed F: {}", s);
		std::thread::sleep(Duration::from_secs(2));
	}
	println!("ROW F P's bare Bark claim: {}", claim.join().unwrap());
	let fr = receive_row(&r, &f_hash).await.unwrap();
	println!("ROW F the operator: {} preimage known {}", fr.state.name(), fr.preimage.is_some());
	assert_eq!(fr.state.name(), "claimed", "the operator learned the preimage from Q's claim, not from P");
	assert_ne!(swap_of(&p, &f_id)["posted"], true, "P posted nothing");
	p.ok(&["sync"]);
	assert_eq!(p.ok(&["lightning", "payments"])[&f_hash]["state"], "paid", "P's lock is the operator's");

	// E: Q pays, P never claims: Bark fails the payment back.
	refill_pool();
	let q_btc_e = spendable_sat(&q);
	let t0 = Instant::now();
	loop {
		let s = follow_one(&q, &e_id);
		println!("ROW E Q's swap: {} | {} | tries {}", s["state"], s["note"], s["pay_tries"]);
		if s["state"] == "btc_failed" {
			break;
		}
		assert!(t0.elapsed() < Duration::from_secs(400), "Q's payment never ended: {}", s);
		std::thread::sleep(Duration::from_secs(3));
	}
	until_btc(&[&q], 120, "Q's BTC back", || spendable_sat(&q) >= q_btc_e);
	println!("ROW E Q's BTC: {} before the payment, {} after its fail-back", q_btc_e, spendable_sat(&q));

	// C: P locks, and no round ever takes Q's leaf.
	refill_pool();
	let (c_id, c_hash) = agreed(&r, &p, &q, true, 90_000, 9_000, 1800);
	follow_until(&p, &c_id, "locked", 60);
	let t0 = Instant::now();
	while !receive_row(&r, &c_hash).await.is_some_and(|x| x.state.name() == "accepted") {
		assert!(t0.elapsed() < Duration::from_secs(60), "never held");
		tokio::time::sleep(Duration::from_millis(300)).await;
	}

	// Past every lock's time: C's, D's and E's receives fail back, and P's
	// locks come back to it. Q never paid D, and its payment of E came back.
	let mut ends = vec![];
	for h in [&c_hash, &d_hash, &e_hash] {
		ends.push(receive_row(&r, h).await.unwrap().send_timeout.unwrap());
	}
	let end = *ends.iter().max().unwrap();
	println!("ROWS C D E: the locks time out at median times {:?}; now {}", ends, mtp(&r));
	let t0 = Instant::now();
	loop {
		let mut states = vec![];
		for h in [&c_hash, &d_hash, &e_hash] {
			states.push(receive_row(&r, h).await.unwrap().state.name().to_string());
		}
		if states.iter().all(|s| s == "cancelled") {
			println!("ROWS C D E failed back at median time {}", mtp(&r));
			break;
		}
		assert!(t0.elapsed() < Duration::from_secs(900) && mtp(&r) < end + 7200, "not failed back by median time {}: {:?}", mtp(&r), states);
		advance(&r, 6 * 3600).await;
		p.run(&["sync"]);
		q.run(&["sync"]);
		tokio::time::sleep(Duration::from_secs(2)).await;
	}
	for (id, row) in [(&c_id, "C"), (&d_id, "D"), (&e_id, "E")] {
		let t0 = Instant::now();
		loop {
			let s = follow_one(&p, id);
			if s["state"] == "refunded" {
				println!("ROW {} P's swap: {} | {}", row, s["state"], s["outcome"]);
				break;
			}
			assert!(t0.elapsed() < Duration::from_secs(120), "row {}: P's lock never came back: {}", row, s);
			std::thread::sleep(Duration::from_secs(2));
		}
	}
	q.ok(&["sync"]);
	let recs = q.ok(&["lightning", "receives"]);
	for (h, row) in [(&c_hash, "C"), (&d_hash, "D"), (&e_hash, "E")] {
		println!("ROW {} Q's receive: {} | {}", row, recs[h.as_str()]["state"], recs[h.as_str()]["reason"]);
		assert_eq!(recs[h.as_str()]["state"], "failed", "row {}", row);
	}
	// The books: of all six, only F moved anything; the rest cost P only
	// the margins of taking its locks back.
	let (p_x1, q_x1, q_btc1) = (x_row(&p, &r.x), x_row(&q, &r.x), spendable_sat(&q));
	println!("ROWS books: P's X {} -> {} ({}), Q's X {} -> {} (+{}), Q's BTC {} -> {} ({})", p_x0, p_x1, p_x1 as i64 - p_x0 as i64,
		q_x0, q_x1, q_x1 as i64 - q_x0 as i64, q_btc0, q_btc1, q_btc1 as i64 - q_btc0 as i64);
	assert!(q_x1 > q_x0 && q_x1 - q_x0 <= 80_000, "Q holds F's leaf only");
	assert!(p_x0 - p_x1 >= 80_080 && p_x0 - p_x1 < 80_080 + 10_000, "P gave F's atoms and fee, and margins of three returns");
	assert!(q_btc0 - q_btc1 > 15_000 && q_btc0 - q_btc1 < 15_000 + 1_000, "Q paid F's BTC only");
	drop(ox);
	for w in [&p, &q] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A parent block of the Sequentia chain's own, which the next Sequentia
/// blocks anchor to: its height.
async fn own_anchor(r: &Running) -> u64 {
	tokio::task::block_in_place(|| {
		r.rt.mine_parent(1).unwrap();
		r.rt.anchor_to_parent_tip().unwrap();
	});
	r.rt.parent.client().block_count().unwrap()
}

fn confirmations(r: &Running, txid: &elements::Txid) -> i64 {
	let v: Value = r.rt.client().call("getrawtransaction", &[json!(txid.to_string()), json!(true)]).unwrap_or(Value::Null);
	v["confirmations"].as_i64().unwrap_or(0)
}

/// W10: the Sequentia leg's round rolled back through its Bitcoin anchor,
/// before the swap and after it (`orphan_parent_from`). Before: Q's leaf's
/// round goes out of the chain with the parent block it is anchored to,
/// before it is final; Q does not pay while it is out or not final, and
/// pays once it is back and final, the same transaction. After: the swap
/// done, the parent chain drops the blocks that round is anchored to, three
/// deep, past finality; the round comes back with the same txid, and every
/// coin the swap gave is the same coin again, nobody holding both legs.
#[tokio::test(flavor = "multi_thread")]
async fn the_sequentia_leg_follows_an_anchor_driven_rollback_before_and_after_the_swap() {
	if skip() {
		return;
	}
	let Some(lnd) = lightningd("the_sequentia_leg_follows_an_anchor_driven_rollback_before_and_after_the_swap") else { return };
	let (mut r, ox) = operator(&lnd, "sw3").await;
	let p = dual_wallet(&r, "SRP", 0, None);
	let q = dual_wallet(&r, "SRQ", 400_000, None);
	fund_x(&mut r, &p, 2_000_000).await;
	refill_pool();
	let q_btc0 = spendable_sat(&q);
	let (id, hash) = agreed(&r, &p, &q, true, 100_000, 20_000, 1800);
	follow_until(&p, &id, "locked", 60);
	let t0 = Instant::now();
	while !receive_row(&r, &hash).await.is_some_and(|x| x.state.name() == "accepted") {
		assert!(t0.elapsed() < Duration::from_secs(60), "never held");
		tokio::time::sleep(Duration::from_millis(300)).await;
	}

	// Before: the round in a block anchored to a parent block of its own,
	// not yet final; then that parent block orphaned.
	let p1 = own_anchor(&r).await;
	let built = r.server.rounds.run_round_of(r.x).await.unwrap().expect("a round");
	let round = built.tx.txid();
	r.produce().await;
	let s = follow_one(&q, &id);
	println!("ROLLBACK before: the round {} in a block ({} confirmations), not final: Q's swap {} | {}", round, confirmations(&r, &round),
		s["state"], s["note"]);
	assert_eq!(s["state"], "taken", "Q pays nothing while the round is not final");
	let gone = tokio::task::block_in_place(|| r.rt.orphan_parent_from(p1)).unwrap();
	r.synced().await;
	println!("ROLLBACK before: parent blocks orphaned {:?}; the round has {} confirmations", gone, confirmations(&r, &round));
	assert!(confirmations(&r, &round) < 1, "the round left the chain with its anchor");
	let s = follow_one(&q, &id);
	println!("ROLLBACK before: Q's swap {} | {}", s["state"], s["note"]);
	assert_eq!(s["state"], "taken", "Q pays nothing while the round is out of the chain");
	assert_eq!(spendable_sat(&q), q_btc0, "no BTC moved");
	// Back, the same transaction, buried: Q pays, P claims.
	let p2 = own_anchor(&r).await;
	r.produce().await;
	r.bury().await;
	r.round_state(&round, RoundState::Final).await;
	println!("ROLLBACK before: the round back in a block anchored at parent height {} ({} confirmations)", p2, confirmations(&r, &round));
	let pf = follow_in_background(&p, 150);
	follow_until(&q, &id, "done", 150);
	let _ = pf.join();
	follow_until(&p, &id, "done", 120);
	q.ok(&["sync"]);
	let q_x = x_row(&q, &r.x);
	let coins_before: Vec<Value> = q.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live").cloned().collect();
	println!("ROLLBACK the swap done: Q holds {} of X in {:?}", q_x, coins_before.iter().map(|c| c["leaf_id"].clone()).collect::<Vec<_>>());

	// After: the round's anchor and two blocks above it orphaned, past
	// finality. The round leaves the chain and comes back with the same txid.
	let gone = tokio::task::block_in_place(|| r.rt.orphan_parent_from(p2)).unwrap();
	r.synced().await;
	println!("ROLLBACK after: parent blocks orphaned {:?}; the round has {} confirmations", gone, confirmations(&r, &round));
	assert!(gone.len() >= 3, "a rollback past finality: {:?}", gone);
	assert!(confirmations(&r, &round) < 1);
	let during = q.ok(&["coins"]);
	println!("ROLLBACK after: Q's coins while the round is out: {:?}", during.as_array().unwrap().iter()
		.map(|c| (c["leaf_id"].clone(), c["state"].clone())).collect::<Vec<_>>());
	let bal = q.ok(&["balance", "--without-bitcoin"]);
	println!("ROLLBACK after: Q's balance while the round is out: {}", bal["arca"]);
	r.produce().await;
	r.bury().await;
	r.round_state(&round, RoundState::Final).await;
	q.ok(&["sync"]);
	let coins_after: Vec<Value> = q.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live").cloned().collect();
	println!("ROLLBACK after: the round back ({} confirmations); Q holds {} of X in {:?}", confirmations(&r, &round), x_row(&q, &r.x),
		coins_after.iter().map(|c| c["leaf_id"].clone()).collect::<Vec<_>>());
	assert_eq!(x_row(&q, &r.x), q_x, "Q holds the same X");
	assert_eq!(coins_after.iter().map(|c| c["leaf_id"].clone()).collect::<Vec<_>>(),
		coins_before.iter().map(|c| c["leaf_id"].clone()).collect::<Vec<_>>(), "the same coins");
	assert_eq!(receive_row(&r, &hash).await.unwrap().state.name(), "claimed");
	p.ok(&["sync"]);
	assert_eq!(p.ok(&["lightning", "payments"])[&hash]["state"], "paid", "P's lock stays the operator's");
	drop(ox);
	for w in [&p, &q] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// W12: each party stopped mid-swap and started again, and each restored
/// from its mnemonic mid-swap.
///
/// - Q's client is killed while its BTC payment is with Bark; started again,
///   it reads the payment from Bark and claims its leaf.
/// - Q, its device lost after it paid and before it claimed, is restored
///   from the mnemonic (both sides): its swap record is gone, its leaf is
///   found held for the preimage, and the preimage P posted to the operator
///   claims it.
/// - P, its device lost after its lock and before its claim, is restored:
///   Bark's preimage of its invoice is gone with the device, so the restored
///   wallet cannot claim; Q's payment is failed back to Q, and P's lock comes
///   back to the restored wallet once the operator fails the receive back.
#[tokio::test(flavor = "multi_thread")]
async fn a_swap_survives_a_restart_and_a_restore_of_each_party() {
	if skip() {
		return;
	}
	let Some(lnd) = lightningd("a_swap_survives_a_restart_and_a_restore_of_each_party") else { return };
	let (mut r, ox) = operator(&lnd, "sw4").await;
	let p_m = fresh_mnemonic("SWRP");
	let q_m = fresh_mnemonic("SWRQ");
	let p = dual_wallet(&r, "SWRP", 0, Some(&p_m));
	let q = dual_wallet(&r, "SWRQ", 500_000, Some(&q_m));
	fund_x(&mut r, &p, 2_000_000).await;

	// Q killed while Bark pays; started again.
	refill_pool();
	let (id1, _) = agreed(&r, &p, &q, true, 100_000, 20_000, 1800);
	follow_until(&p, &id1, "locked", 60);
	leaf_round(&r).await;
	let pf = follow_in_background(&p, 180);
	let mut child = Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&q.dir).arg("--witness-patience").arg("3")
		.args(["btc-swap", "follow", &id1, "--wait", "120"]).env("ARCA_NODE_PASSWORD", "arca")
		.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
	let t0 = Instant::now();
	while swap_of(&q, &id1)["state"] != "paying" {
		assert!(t0.elapsed() < Duration::from_secs(90), "Q never paid");
		std::thread::sleep(Duration::from_millis(200));
	}
	child.kill().unwrap();
	let _ = child.wait();
	println!("RESTART Q killed while paying: its swap {}", swap_of(&q, &id1)["state"]);
	follow_until(&q, &id1, "done", 150);
	let _ = pf.join();
	follow_until(&p, &id1, "done", 120);

	// Q restored after it paid, before it claimed.
	refill_pool();
	let (id2, hash2) = agreed(&r, &p, &q, true, 110_000, 21_000, 1800);
	follow_until(&p, &id2, "locked", 60);
	leaf_round(&r).await;
	let pf = follow_in_background(&p, 180);
	let mut child = Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&q.dir).arg("--witness-patience").arg("3")
		.args(["btc-swap", "follow", &id2, "--wait", "120"]).env("ARCA_NODE_PASSWORD", "arca")
		.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
	let t0 = Instant::now();
	while swap_of(&q, &id2)["state"] != "paying" {
		assert!(t0.elapsed() < Duration::from_secs(90), "Q never paid");
		std::thread::sleep(Duration::from_millis(200));
	}
	child.kill().unwrap();
	let _ = child.wait();
	let _ = pf.join();
	let ps = follow_until(&p, &id2, "done", 120);
	let _ = ps;
	let q_x_lost = x_row(&q, &r.x);
	println!("RESTORE Q's device lost: its swap {} (paid, not claimed); P's {}", swap_of(&q, &id2)["state"], swap_of(&p, &id2)["state"]);
	let q2 = dual_wallet(&r, "SWRQ2", 0, Some(&q_m));
	until_btc(&[&q2], 120, "Q's BTC restored", || spendable_sat(&q2) > 0);
	let restored = q2.ok(&["btc-swap", "list"]);
	println!("RESTORE Q restored: swaps {} | restored legs {}", restored["swaps"], restored["restored_legs"]);
	assert!(restored["swaps"].as_object().unwrap().is_empty(), "the swap record went with the device");
	let pay = tokio::task::block_in_place(|| Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&q2.dir)
		.args(["bitcoin", "--quiet", "lightning", "pay", "status", swap_of(&p, &id2)["invoice_btc"].as_str().unwrap(), "--no-sync"])
		.output().unwrap());
	println!("RESTORE Q's restored Bark on its payment: {} {}", String::from_utf8_lossy(&pay.stdout).trim(), String::from_utf8_lossy(&pay.stderr).trim());
	q2.ok(&["sync"]);
	let rec = q2.ok(&["lightning", "receives"])[&hash2].clone();
	println!("RESTORE Q2's receive after a sync: {}", rec);
	assert_eq!(rec["state"], "received", "claimed with the preimage P posted");
	assert!(x_row(&q2, &r.x) > q_x_lost, "the restored wallet holds the swap's X too");

	// P restored after its lock, before its claim.
	refill_pool();
	let q2_btc = spendable_sat(&q2);
	let (id3, hash3) = agreed(&r, &p, &q2, true, 90_000, 18_000, 1800);
	follow_until(&p, &id3, "locked", 60);
	leaf_round(&r).await;
	let p2 = dual_wallet(&r, "SWRP2", 0, Some(&p_m));
	let sends = p2.ok(&["lightning", "payments"]);
	println!("RESTORE P restored: its payment under the hash {} | its swaps {}", sends[&hash3], p2.ok(&["btc-swap", "list"])["restored_legs"]);
	let rs = tokio::task::block_in_place(|| Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&p2.dir)
		.args(["bitcoin", "--quiet", "lightning", "receive", "status", swap_of(&p, &id3)["invoice_btc"].as_str().unwrap(), "--no-sync"])
		.output().unwrap());
	println!("RESTORE P's restored Bark on its invoice: {} {}", String::from_utf8_lossy(&rs.stdout).trim(), String::from_utf8_lossy(&rs.stderr).trim());
	// Q pays; nobody can claim; Bark fails it back.
	let t0 = Instant::now();
	loop {
		let s = follow_one(&q2, &id3);
		println!("RESTORE Q2's swap: {} | {} | tries {}", s["state"], s["note"], s["pay_tries"]);
		if matches!(s["state"].as_str(), Some("btc_failed") | Some("abandoned")) {
			break;
		}
		assert!(t0.elapsed() < Duration::from_secs(400), "Q's payment never ended: {}", s);
		std::thread::sleep(Duration::from_secs(3));
	}
	until_btc(&[&q2], 120, "Q's BTC back", || spendable_sat(&q2) >= q2_btc);
	// Past the lock's time the lock comes back to the restored P.
	let end = receive_row(&r, &hash3).await.unwrap().send_timeout.unwrap();
	let t0 = Instant::now();
	while receive_row(&r, &hash3).await.unwrap().state.name() != "cancelled" {
		assert!(t0.elapsed() < Duration::from_secs(600) && mtp(&r) < end + 7200, "never failed back");
		advance(&r, 6 * 3600).await;
		p2.run(&["sync"]);
		q2.run(&["sync"]);
		tokio::time::sleep(Duration::from_secs(2)).await;
	}
	let mut back = Value::Null;
	for _ in 0..30 {
		p2.ok(&["sync"]);
		back = p2.ok(&["lightning", "payments"])[&hash3].clone();
		if back["state"] == "returned" {
			break;
		}
		std::thread::sleep(Duration::from_secs(1));
	}
	println!("RESTORE P2's lock: {}", back);
	assert_eq!(back["state"], "returned", "the lock comes back to the restored wallet");
	drop(ox);
	for w in [&p, &q, &q2, &p2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
