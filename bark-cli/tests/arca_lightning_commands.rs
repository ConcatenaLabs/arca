//! A payment under a hash between two wallets of one operator, run through
//! the library's commands, as a program that embeds the library runs it (a
//! browser worker, a mobile app's core), against a whole Arca server and its
//! SeqLN node in X: what a trade of BTC for an asset in one hash-lock needs
//! of the asset's side.
//!
//! The receiver's `lightning_receive_quote` says, with nothing asked of the
//! operator, what the leaf will hold once claimed (the operator's fee and the
//! claim's margins out of it); `lightning_receive` asks under a hash the
//! receiver did not make. The payer's `lightning_pay_quote` says what the
//! payment takes in all with nothing signed or kept, and `lightning_pay`
//! with `shown` goes ahead only on it. `lightning_receive_ready` says when
//! the leaf is held for good, its round final and its home date far enough
//! off, to pay the preimage's price; `lightning_receive_preimage` hands the
//! preimage over, and `sync` claims the leaf. The claim leaves exactly what
//! the quote said, and the payer's coins fall by exactly what its quote said.
//!
//! Needs what the other scenarios need, and `LIGHTNINGD_EXEC`.

mod common;

use elements::hashes::{sha256, Hash};
use elements::Script;
use serde_json::{json, Value};

use bark::arca::{command, Wallet};
use server::server::LegSection;
use server::store::RoundState;

use common::cli::Arca;
use common::lightning::{lightningd, node};
use common::running::Running;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

fn num(v: &Value) -> u64 {
	v.as_str().unwrap_or_else(|| panic!("not a number: {}", v)).parse().unwrap()
}

/// What the wallet holds live in `asset`.
fn live(w: &Arca, asset: &str) -> u64 {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == asset)
		.map(|c| num(&c["value"])).sum()
}

/// One command of the library on the wallet in `a`'s directory: its result,
/// or its refusal.
fn library(a: &Arca, cmd: &str, args: Value) -> Result<Value, String> {
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run(&mut w, cmd, &args).map(|v| v["result"].clone()).map_err(|e| e.to_string())
	})
}

fn ok(a: &Arca, cmd: &str, args: Value) -> Value {
	library(a, cmd, args.clone()).unwrap_or_else(|e| panic!("{} {}: {}", cmd, args, e))
}

/// The round of X that makes the leaves the operator wants, mined and final.
async fn leaf_round(r: &Running) {
	let built = r.server.rounds.run_round_of(r.x).await.unwrap().expect("a round");
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_payment_under_a_hash_through_the_commands_moves_exactly_what_its_quotes_said() {
	let Some(lnd) = lightningd("a_payment_under_a_hash_through_the_commands_moves_exactly_what_its_quotes_said") else { return };
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
		let ox = node(&r.rt, &mut r.purse, &lnd, "lco", true, x, 2_000_000_000);
		let px = node(&r.rt, &mut r.purse, &lnd, "lcp", true, x, 1_000_000_000);
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
	let (url, node_url) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node_url, "--node-user", "arca", "--exit-delay-units", "4",
		"--min-exit-delay-units", "1"];

	// The payer, P, with a board in X; the receiver, Q, with nothing.
	let p = Arca::new("LCP");
	p.ok(&create);
	let s = script(&p.ok(&["address"]));
	r.pay_to(s, x, 5_000_000);
	r.produce().await;
	p.ok(&["board", &xs, "3000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || p.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	p.ok(&["sync"]);
	let q = Arca::new("LCQ");
	q.ok(&create);

	// The hash is someone else's: the preimage is the test's.
	let seed = format!("lc-{}-{:?}", std::process::id(), std::time::SystemTime::now());
	let pre = sha256::Hash::hash(seed.as_bytes()).to_byte_array();
	let hash = sha256::Hash::hash(&pre).to_string();

	// 1. What Q's leaf will hold once claimed, before anything is asked.
	let rq = ok(&q, "lightning_receive_quote", json!({"asset": xs, "amount": "100000"}));
	println!("LC the receive's quote: {}", rq);
	assert_eq!(num(&rq["fee"]), (100_000u64 * 1_000).div_ceil(1_000_000));
	assert_eq!(num(&rq["value"]), 100_000 - num(&rq["fee"]));
	assert!(num(&rq["claim_margins"]) > 0);
	assert_eq!(num(&rq["claimed"]), num(&rq["value"]) - num(&rq["claim_margins"]));
	assert!(ok(&q, "lightning_receives", json!({})).as_object().unwrap().is_empty(), "the quote asked nothing of the operator");
	let inv = ok(&q, "lightning_receive", json!({"asset": xs, "amount": "100000", "hash": hash}));
	assert_eq!((inv["payment_hash"].as_str(), inv["hash_given"].as_bool()), (Some(hash.as_str()), Some(true)), "{}", inv);
	assert_eq!(inv["value"], rq["value"]);
	let invoice = inv["invoice"].as_str().unwrap().to_string();

	// 2. What P's payment takes in all, with nothing signed or kept; refused
	// on terms other than the ones shown; then paid on them.
	let before = (p.ok(&["coins"]), ok(&p, "lightning_payments", json!({})));
	let pq = ok(&p, "lightning_pay_quote", json!({"invoice": invoice, "asset": xs}));
	println!("LC the payment's quote: {}", pq);
	assert_eq!((pq["payment_hash"].as_str(), num(&pq["amount"]), num(&pq["fee"])), (Some(hash.as_str()), 100_000, 100));
	assert_eq!(num(&pq["spends"]), 100_000 + 100 + num(&pq["margins"]), "what leaves the wallet: the amount, the fee and the margins");
	let given: u64 = pq["gives"].as_array().unwrap().iter().map(|l| num(&p.ok(&["coins"]).as_array().unwrap().iter()
		.find(|c| c["leaf_id"] == *l).unwrap()["value"])).sum();
	assert_eq!(given, num(&pq["spends"]) + num(&pq["change"]), "the coins it gives are what it spends and the change");
	assert_eq!((p.ok(&["coins"]), ok(&p, "lightning_payments", json!({}))), before, "the quote signed and kept nothing");
	let mut lower = pq.clone();
	lower["spends"] = json!((num(&pq["spends"]) - 1).to_string());
	let e = library(&p, "lightning_pay", json!({"invoice": invoice, "asset": xs, "shown": lower})).unwrap_err();
	println!("LC refused: {}", e);
	assert!(e.contains("changed since it was shown"), "{}", e);
	assert_eq!((p.ok(&["coins"]), ok(&p, "lightning_payments", json!({}))), before, "nothing signed, nothing recorded");
	let x_before = live(&p, &xs);
	let paying = ok(&p, "lightning_pay", json!({"invoice": invoice, "asset": xs, "shown": pq}));
	assert_eq!(paying["paying"]["payment_hash"].as_str(), Some(hash.as_str()), "{}", paying);
	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
	while ok(&q, "lightning_lookup", json!({"hash": hash}))["state"] != "accepted" {
		assert!(std::time::Instant::now() < deadline, "never held inside the operator");
		tokio::time::sleep(std::time::Duration::from_millis(300)).await;
	}

	// 3. Not ready before the leaf's round; then ready, unless the other side
	// may take longer than the leaf's home date allows.
	ok(&q, "sync", json!({}));
	let not_yet = ok(&q, "lightning_receive_ready", json!({"hash": hash, "need_seconds": 600}));
	println!("LC before the round: {}", not_yet);
	assert_eq!(not_yet["ready"], false);
	// The round in a block, not final yet: not held for good, but ready for a
	// holder that takes that round's risk itself (`final: false`).
	let built = r.server.rounds.run_round_of(r.x).await.unwrap().expect("a round");
	r.produce().await;
	r.synced().await;
	ok(&q, "sync", json!({}));
	let strict = ok(&q, "lightning_receive_ready", json!({"hash": hash, "need_seconds": 600}));
	let early = ok(&q, "lightning_receive_ready", json!({"hash": hash, "need_seconds": 600, "final": false}));
	println!("LC the round in a block: {} | not final accepted: {}", strict, early);
	assert_eq!(strict["ready"], false, "{}", strict);
	assert_eq!((early["ready"].as_bool(), early["final"].as_bool(), early["value"].as_str()), (Some(true), Some(false), rq["value"].as_str()), "{}", early);
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	r.synced().await;
	ok(&q, "sync", json!({}));
	let ready = ok(&q, "lightning_receive_ready", json!({"hash": hash, "need_seconds": 600}));
	assert_eq!(ready["final"].as_bool(), Some(true), "{}", ready);
	println!("LC after the round: {}", ready);
	assert_eq!((ready["ready"].as_bool(), ready["value"].as_str()), (Some(true), rq["value"].as_str()));
	let e = library(&q, "lightning_receive_ready", json!({"hash": hash, "need_seconds": 10_000_000})).unwrap_err();
	println!("LC refused: {}", e);
	assert!(e.contains("must start home in"), "{}", e);

	// 4. The preimage handed over: the claim leaves what the quote said.
	let q_before = live(&q, &xs);
	assert_eq!(q_before, 0);
	ok(&q, "lightning_receive_preimage", json!({"hash": hash, "preimage": hex(&pre)}));
	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
	loop {
		ok(&q, "sync", json!({}));
		if ok(&q, "lightning_receives", json!({}))[&hash]["state"] == "received" {
			break;
		}
		assert!(std::time::Instant::now() < deadline, "never claimed: {}", ok(&q, "lightning_receives", json!({})));
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;
	}
	assert_eq!(live(&q, &xs), num(&rq["claimed"]), "the claim leaves exactly what the receive's quote said");

	// 5. The payer's coins fell by exactly what its quote said.
	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
	loop {
		ok(&p, "sync", json!({}));
		if ok(&p, "lightning_payments", json!({}))[&hash]["state"] == "paid" {
			break;
		}
		assert!(std::time::Instant::now() < deadline, "the payment was never settled: {}", ok(&p, "lightning_payments", json!({})));
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;
	}
	assert_eq!(x_before - live(&p, &xs), num(&pq["spends"]), "the payer spent exactly what its quote said");
	println!("LC moved: P -{} X, Q +{} X", num(&pq["spends"]), num(&rq["claimed"]));
}
