//! The wallet's channels by themselves: `care --channels` opens a channel
//! leaf in each asset the operator makes them of, half of the wallet's
//! leaves in it and half kept in a plain leaf beside it; `send` pays a
//! receive request or a channel code over the payer's channel into the
//! receiver's at once when both hold one, and otherwise as before: to the
//! request's leaf, or, for a code, not at all, naming its address; `care`
//! folds what a channel was paid; and `exit` of a channel coin runs the
//! channel's own exit.
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

/// The one live channel `w` holds.
fn channel(w: &Arca) -> Value {
	let l = w.ok(&["channel", "list"]);
	let open: Vec<&Value> = l.as_array().unwrap().iter().filter(|c| c["coin_state"] == "live").collect();
	assert_eq!(open.len(), 1, "{}", l);
	open[0].clone()
}

/// What `w` holds of asset `x` in its leaves, every state together.
fn leaves(w: &Arca, x: &str) -> u64 {
	let b = w.ok(&["balance"]);
	b["arca"][x].as_object().map_or(0, |m| m.values().map(num).sum())
}

#[tokio::test(flavor = "multi_thread")]
async fn wallets_open_pay_over_and_fold_channels_by_themselves() {
	let mut r = Running::start_with(|c, _, _| {
		c.assets[0].channel_capacity = Some(CAPACITY.to_string());
	}).await;
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("route A");
	let b = Arca::new("route B");
	let c = Arca::new("route C");
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1",
		"--min-exit-delay-units", "1"];
	for w in [&a, &b, &c] {
		w.ok(&create);
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, r.x, 5_000_000);
	}
	r.produce().await;
	for w in [&a, &b, &c] {
		w.ok(&["board", &x, &BOARD.to_string()]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the server to credit the boards", || {
		[&a, &b, &c].iter().all(|w| w.ok(&["boards"])[0]["server"]["state"] == "credited")
	}).await;
	for w in [&a, &b, &c] {
		w.ok(&["sync"]);
	}

	// --- care opens a channel: half in it, half kept beside it ---
	for w in [&a, &b] {
		let v = w.ok(&["care", "--channels"]);
		let o = &v["channels"]["opened"][0];
		println!("care opened: {}", o);
		assert_eq!(o["capacity"], CAPACITY.to_string(), "{}", v);
		assert_eq!(o["state"], "pending", "{}", v);
	}
	// C is not asked to: it holds no channel.
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let round = built.tx.txid();
	r.produce().await;
	r.bury().await;
	r.round_state(&round, RoundState::Final).await;
	for w in [&a, &b] {
		let s = w.ok(&["sync"]);
		assert_eq!(s["participations"][0]["state"], "released", "{}", s);
		let v = w.ok(&["care", "--channels"]);
		assert!(v["channels"]["opened"].as_array().unwrap().is_empty(), "a second care opens no second channel: {}", v);
	}
	let (ca, cb) = (channel(&a), channel(&b));
	let (la, lb) = (ca["leaf_id"].as_str().unwrap().to_string(), cb["leaf_id"].as_str().unwrap().to_string());
	let coins = a.ok(&["coins"]);
	let plain: Vec<&Value> = coins.as_array().unwrap().iter().filter(|k| k["state"] == "live" && k["leaf_id"] != la.as_str()).collect();
	assert_eq!(plain.len(), 1, "one plain leaf kept beside the channel: {}", coins);
	let (a_side, a_kept) = (num(&ca["balance"]), num(&plain[0]["value"]));
	println!("A's channel {}: its side {}, the operator's {}; kept beside it {}", la, a_side, ca["operator_side"], a_kept);
	assert!(a_kept.abs_diff(a_side) <= 1, "half and half");
	assert_eq!(num(&ca["operator_side"]), CAPACITY);
	assert_eq!(leaves(&a, &x), a_side + a_kept, "the balance counts the channel's side and the kept leaf");
	let (a0, b0) = (leaves(&a, &x), leaves(&b, &x));

	// --- A pays B's channel code: over the channels, at once ---
	let code = b.ok(&["channel", "code", "--address", "tb1qexampleaddressforachainpayment"]);
	assert_eq!(code["details"]["channels"][&x], lb.as_str(), "{}", code);
	let code = code["code"].as_str().unwrap().to_string();
	let p = a.ok(&["send", &code, "--asset", &x, "--amount", "100000"]);
	assert_eq!(p["route"], "channel", "{}", p);
	assert_eq!(p["channel"]["receipt"]["credit"], "100000", "{}", p);
	println!("A paid B's code 100000 over the channels: {}", p["channel"]["state"]);
	b.ok(&["channel", "sync"]);
	assert_eq!(leaves(&b, &x), b0 + 100_000, "B counts the note at once");
	assert_eq!(leaves(&a, &x), a0 - 100_000);

	// --- A receive request names B's channel: paid over it too ---
	let req = b.ok(&["receive", "--asset", &x]);
	assert_eq!(req["details"]["channels"][&x], lb.as_str(), "{}", req);
	let p = a.ok(&["send", req["request"].as_str().unwrap(), "--amount", "50000"]);
	assert_eq!(p["route"], "channel", "{}", p);
	assert_eq!(p["channel"]["receipt"]["credit"], "150000", "{}", p);
	// B pays A back over its code, folding its credit in the same state.
	let code_a = a.ok(&["channel", "code"])["code"].as_str().unwrap().to_string();
	let p = b.ok(&["send", &code_a, "--asset", &x, "--amount", "30000"]);
	assert_eq!(p["route"], "channel", "{}", p);
	assert_eq!(p["channel"]["state"]["folded"], "150000", "{}", p);
	a.ok(&["channel", "sync"]);
	assert_eq!(leaves(&a, &x), a0 - 150_000 + 30_000);
	assert_eq!(leaves(&b, &x), b0 + 150_000 - 30_000);

	// --- To C, which holds no channel: the request's leaf, as before ---
	let req_c = c.ok(&["receive", "--asset", &x]);
	assert!(req_c["details"]["channels"].is_null(), "{}", req_c);
	let p = a.ok(&["send", req_c["request"].as_str().unwrap(), "--amount", "200000"]);
	assert_eq!(p["route"], "leaf", "{}", p);
	println!("A paid C's request by a leaf: {}", p["not_by_channel"]);
	assert!(p["not_by_channel"].as_str().unwrap().contains("names no channel"), "{}", p);
	// A channel code is never paid to a leaf, and names its address.
	a.refused(&["send", &code, "--asset", &x, "--amount", "1000", "--route", "leaf"], "never to a leaf");

	// --- More than B's channel can take: refused there, nothing stands ---
	let room = CAPACITY - 120_000;
	let too_much = (room + 1).to_string();
	let why = a.refused(&["send", &code, "--asset", &x, "--amount", &too_much], "not paid over a channel");
	assert!(why.contains("more at most") && why.contains("tb1qexampleaddressforachainpayment"), "{}", why);
	assert_eq!(channel(&a)["pending"], false, "the refused state does not stand");
	// To a request the same payment goes to its leaf instead.
	let req = b.ok(&["receive", "--asset", &x]);
	let p = a.ok(&["send", req["request"].as_str().unwrap(), "--amount", "300000", "--route", "channel"]);
	assert_eq!(p["route"], "channel", "within room: {}", p);
	let req = b.ok(&["receive", "--asset", &x]);
	let big = (CAPACITY).to_string();
	let p = a.ok(&["send", req["request"].as_str().unwrap(), "--amount", &big]);
	assert_eq!(p["route"], "leaf", "{}", p);
	println!("past B's room the request's leaf took it: {}", p["not_by_channel"]);
	// A can still pay over its channel: the refused state left nothing.
	let p = a.ok(&["send", &code, "--asset", &x, "--amount", "1000"]);
	assert_eq!(p["route"], "channel", "{}", p);

	// --- care folds what B's channel was paid ---
	let v = b.ok(&["care", "--channels"]);
	let f = &v["channels"]["folded"][0];
	println!("B's care folded: {}", f);
	assert_eq!(f["leaf_id"], lb.as_str(), "{}", v);
	assert_eq!(channel(&b)["credit_not_folded"], "0");

	// --- exit of a channel coin is the channel's exit ---
	a.refused(&["exit", &la, "--quote"], "closes on the chain by its own steps");
	let e = a.ok(&["exit", &la]);
	assert_eq!(e["state"], "unrolling", "{}", e);
	println!("A's exit of its channel coin runs the channel's exit: {}", e["state"]);
}
