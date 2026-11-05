//! Channel leaves (`channel-1`) from the wallet's side, with the `arca`
//! binary against a whole Arca server on an anchored proof-of-stake regtest
//! chain: two wallets open channel leaves in one round, the operator funding
//! its side of each; they pay each other through the operator, each payment
//! final at once, with no round between; B, offline while it is paid, takes
//! the credit on its return and folds it; A closes its channel into a round
//! for a leaf of its side; B closes its channel on the chain alone: unrolled,
//! the latest state published, settled after the exit delay, its credit not
//! folded claimed from the operator's side, and its side swept home.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::Script;
use serde_json::Value;

use common::cli::Arca;
use common::running::Running;
use server::store::RoundState;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

fn num(v: &Value) -> u64 {
	v.as_str().unwrap().parse().unwrap()
}

const BOARD: u64 = 3_000_000;
const CAPACITY: u64 = 1_000_000;

/// The one channel `w` holds.
fn channel(w: &Arca) -> Value {
	let l = w.ok(&["channel", "list"]);
	let open: Vec<&Value> = l.as_array().unwrap().iter().filter(|c| c["coin_state"] == "live" || c["coin_state"] == "exiting").collect();
	assert_eq!(open.len(), 1, "{}", l);
	open[0].clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn channels_pay_at_once_take_credit_offline_and_close_both_ways() {
	let mut r = Running::start_with(|c, _, _| {
		c.assets[0].channel_capacity = Some("2000000".into());
	}).await;
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("channel A");
	let b = Arca::new("channel B");
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1",
		"--min-exit-delay-units", "1"];
	a.ok(&create);
	b.ok(&create);
	for w in [&a, &b] {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, r.x, 5_000_000);
	}
	r.produce().await;
	for w in [&a, &b] {
		w.ok(&["board", &x, &BOARD.to_string()]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the server to credit both boards", || {
		a.ok(&["boards"])[0]["server"]["state"] == "credited" && b.ok(&["boards"])[0]["server"]["state"] == "credited"
	}).await;
	a.ok(&["sync"]);
	b.ok(&["sync"]);

	// --- Both open channels in one round ---
	a.refused(&["channel", "open", "--capacity", "2000001"], "it puts 1 to 2000000 on its side");
	for w in [&a, &b] {
		let p = w.ok(&["channel", "open", "--capacity", &CAPACITY.to_string()]);
		assert_eq!(p["participations"][0]["state"], "pending", "{}", p);
	}
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let round = built.tx.txid();
	r.produce().await;
	r.bury().await;
	r.round_state(&round, RoundState::Final).await;
	for w in [&a, &b] {
		let s = w.ok(&["sync"]);
		assert_eq!(s["participations"][0]["state"], "released", "{}", s);
	}
	let (ca, cb) = (channel(&a), channel(&b));
	let (la, lb) = (ca["leaf_id"].as_str().unwrap().to_string(), cb["leaf_id"].as_str().unwrap().to_string());
	println!("A's channel {}: {}\nB's channel {}: {}", la, ca, lb, cb);
	let a0 = num(&ca["balance"]);
	assert_eq!(num(&ca["value"]), a0 + CAPACITY, "the operator's side on top of the wallet's");
	assert_eq!(num(&ca["operator_side"]), CAPACITY);
	let bal = a.ok(&["balance"]);
	println!("A's balance counts its side alone: {}", bal["arca"][&x]);

	// --- A pays B: final at once, no round between ---
	a.refused(&["channel", "pay", &la, &la, "1000"], "not itself");
	a.refused(&["channel", "pay", &la, &lb, &(a0 + 1).to_string()], "less than");
	a.refused(&["channel", "pay", &la, &lb, &(CAPACITY + 1).to_string()], "takes 1000000 more at most");
	let paid = a.ok(&["channel", "pay", &la, &lb, "400000"]);
	assert_eq!(paid["receipt"]["leaf_id"], lb.as_str());
	assert_eq!(paid["receipt"]["credit"], "400000");
	assert_eq!(num(&paid["balance"]), a0 - 400_000);
	assert_eq!(paid["state"]["number"], "1");
	println!("A paid B 400000 at once: state 1 co-signed, B's note of 400000 signed, no round built");

	// B was offline: it reads its credit on return, and folds it.
	let synced = b.ok(&["channel", "sync", &lb]);
	assert_eq!(synced["credit"], "400000");
	assert_eq!(synced["credit_not_folded"], "400000");
	let b0 = num(&cb["balance"]);
	assert_eq!(num(&synced["balance"]), b0 + 400_000, "the credit counts at once");
	let folded = b.ok(&["channel", "fold", &lb]);
	assert_eq!(folded["state"]["number"], "1");
	assert_eq!(folded["state"]["folded"], "400000");
	assert_eq!(folded["credit_not_folded"], "0");
	b.refused(&["channel", "fold", &lb], "no credit to fold");
	println!("B, back, took its credit of 400000 and folded it: state 1, owner {}", folded["state"]["owner"]);

	// B pays A; A pays B again, folding what it was paid in the same state.
	let back = b.ok(&["channel", "pay", &lb, &la, "150000"]);
	assert_eq!(back["receipt"]["credit"], "150000");
	let again = a.ok(&["channel", "pay", &la, &lb, "50000"]);
	assert_eq!(again["state"]["number"], "2");
	assert_eq!(again["state"]["folded"], "150000", "A's credit folded in the payment's state");
	assert_eq!(again["receipt"]["credit"], "450000");
	let a_side = num(&again["balance"]);
	assert_eq!(a_side, a0 - 400_000 + 150_000 - 50_000);
	let b_view = b.ok(&["channel", "sync", &lb]);
	assert_eq!(b_view["credit_not_folded"], "50000", "{}", b_view);
	let b_side = num(&b_view["balance"]);
	assert_eq!(b_side, b0 + 400_000 - 150_000 + 50_000);

	// --- A closes into a round: a leaf of its side ---
	let p = a.ok(&["participate", "--leaf", &la]);
	assert_eq!(p["participations"][0]["state"], "pending", "{}", p);
	b.refused(&["channel", "pay", &lb, &la, "1000"], "in_use");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let round = built.tx.txid();
	r.produce().await;
	r.bury().await;
	r.round_state(&round, RoundState::Final).await;
	let s = a.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s);
	let leaf = &s["participations"][0]["new_leaves"][0];
	println!("A closed its channel into round {}: {}", round, leaf);
	let coins = a.ok(&["coins"]);
	let new: Vec<&Value> = coins.as_array().unwrap().iter().filter(|c| c["state"] == "live").collect();
	assert_eq!(new.len(), 1, "{}", coins);
	let fee = a_side - num(&new[0]["value"]);
	println!("A's new leaf holds {} of its side {} (refresh fee {})", new[0]["value"], a_side, fee);
	assert!(fee < 10_000, "a refresh fee at most, nothing of the channel lost");

	// --- B closes on the chain alone, with its latest state ---
	let before = num(&b.ok(&["balance"])["sequentia_onchain"][&x]);
	let mut last = Value::Null;
	for step in 0..12 {
		let e = b.ok(&["channel", "exit", &lb]);
		println!("B's channel exit, run {}: {}", step, e["state"]);
		let state = e["state"].as_str().unwrap().to_string();
		last = e;
		if state == "exited" {
			break;
		}
		if state == "waiting" {
			common::node::advance_mtp(&r.rt, 600);
		}
		r.produce().await;
	}
	assert_eq!(last["state"], "exited", "{}", last);
	r.bury().await;
	let after = num(&b.ok(&["balance"])["sequentia_onchain"][&x]);
	println!("B's side {} came home on the chain: on-chain X {} -> {}", b_side, before, after);
	assert!(after > before + b_side - 50_000, "B's side, less the exit's fees, is home");
}

/// A channel closed on the chain by someone else, at a state older than the
/// credit its owner was paid: the owner's own `sync` takes its credit not
/// folded by itself, with no `channel exit` asked. Another store of B's
/// mnemonic, copied before A paid B, stands for whoever closes it (the
/// operator could do the same): it unrolls B's channel, settles its opening
/// state after the exit delay and sweeps B's side, knowing nothing of the
/// note A's payment gave B.
#[tokio::test(flavor = "multi_thread")]
async fn a_channel_closed_by_someone_else_has_its_credit_claimed_by_sync() {
	let mut r = Running::start_with(|c, _, _| {
		c.assets[0].channel_capacity = Some("2000000".into());
	}).await;
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("closed by another A");
	let b = Arca::new("closed by another B");
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1",
		"--min-exit-delay-units", "1"];
	a.ok(&create);
	b.ok(&create);
	for w in [&a, &b] {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, r.x, 5_000_000);
	}
	r.produce().await;
	for w in [&a, &b] {
		w.ok(&["board", &x, &BOARD.to_string()]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the server to credit both boards", || {
		a.ok(&["boards"])[0]["server"]["state"] == "credited" && b.ok(&["boards"])[0]["server"]["state"] == "credited"
	}).await;
	a.ok(&["sync"]);
	b.ok(&["sync"]);
	for w in [&a, &b] {
		w.ok(&["channel", "open", "--capacity", &CAPACITY.to_string()]);
	}
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let round = built.tx.txid();
	r.produce().await;
	r.bury().await;
	r.round_state(&round, RoundState::Final).await;
	for w in [&a, &b] {
		w.ok(&["sync"]);
	}
	let (la, lb) = (channel(&a)["leaf_id"].as_str().unwrap().to_string(), channel(&b)["leaf_id"].as_str().unwrap().to_string());

	// Another store of B's mnemonic, as B stood before it was paid.
	let other = Arca::new("closed by another B, elsewhere");
	std::fs::create_dir_all(&other.dir).unwrap();
	for e in std::fs::read_dir(&b.dir).unwrap() {
		let e = e.unwrap();
		if e.file_type().unwrap().is_file() {
			std::fs::copy(e.path(), other.dir.join(e.file_name())).unwrap();
		}
	}

	// A pays B; B reads its note and does not fold it.
	const PAID: u64 = 300_000;
	a.ok(&["channel", "pay", &la, &lb, &PAID.to_string()]);
	let seen = b.ok(&["channel", "sync", &lb]);
	assert_eq!(num(&seen["credit_not_folded"]), PAID, "{}", seen);

	// The other store closes B's channel at its opening state, and sweeps B's side.
	let mut last = Value::Null;
	for step in 0..12 {
		let e = other.ok(&["channel", "exit", &lb]);
		println!("the other store's exit of B's channel, run {}: {}", step, e);
		let state = e["state"].as_str().unwrap().to_string();
		last = e;
		if state == "exited" {
			break;
		}
		if state == "waiting" {
			common::node::advance_mtp(&r.rt, 600);
		}
		r.produce().await;
	}
	assert_eq!(last["state"], "exited", "{}", last);
	r.produce().await;
	r.bury().await;
	let before = num(&b.ok(&["balance"])["sequentia_onchain"][&x]);

	// B's own sync, as B runs it on its return: the credit claimed by itself.
	let mut home = 0;
	for step in 0..12 {
		let s = b.ok(&["sync"]);
		println!("B's sync, run {}: re-check {}; exits {}", step, s["start"]["recheck"]["changes"], s["exits"]);
		for e in s["exits"].as_array().into_iter().flatten() {
			assert!(e["error"].is_null(), "an exit step of B's sync refused: {}", e);
			if e["leaf_id"] == lb.as_str() && !e["home"].is_null() {
				home += num(&e["home"]["amount"]);
			}
		}
		let l = b.ok(&["channel", "list"]);
		let coin = l.as_array().unwrap().iter().find(|c| c["leaf_id"] == lb.as_str()).cloned().unwrap_or(Value::Null);
		println!("B's channel after it: {}", coin);
		if coin.is_null() || coin["coin_state"] == "exited" {
			break;
		}
		r.produce().await;
	}
	r.produce().await;
	r.bury().await;
	let after = num(&b.ok(&["balance"])["sequentia_onchain"][&x]);
	let coins = b.ok(&["coins"]);
	let state = coins.as_array().unwrap().iter().find(|c| c["leaf_id"] == lb.as_str()).map(|c| c["state"].clone()).unwrap_or(Value::Null);
	println!("B's channel coin is {}; on-chain X {} -> {}", state, before, after);
	assert_eq!(state, "exited", "{}", coins);
	assert!(home > PAID - 50_000 && home <= PAID, "B's credit not folded, less the claim's and the sweep's fees, swept home: {}", home);
	assert!(after >= before + home, "and in B's on-chain balance: {} -> {}", before, after);
}
