//! What a payment to a receive request costs before it is made, and a payment
//! that only the wallet's side of its channel can cover, with the `arca`
//! binary against a whole Arca server on an anchored proof-of-stake regtest
//! chain: A's `send-quote` names the coins and the fee its `send` then gives
//! up, to the atom; A puts part of what it holds in a channel, and a payment
//! larger than the rest is refused naming that channel (`in_channel`), and
//! quoted the same, as is one larger than both; closed into a round, the channel's side comes back as a
//! leaf of A's own, and the payment goes through.
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
const KEEP: u64 = 1_000_000;

/// What `send` gave up for its fees: every checkpoint's margin and the
/// reassignment's.
fn margins(sent: &Value) -> u64 {
	let m = &sent["margins"];
	m["checkpoints"].as_array().unwrap().iter().map(num).sum::<u64>() + num(&m["reassignment"])
}

/// The live channel leaf `w` holds, and its side.
fn channel(w: &Arca) -> (String, u64) {
	let l = w.ok(&["channel", "list"]);
	let open: Vec<&Value> = l.as_array().unwrap().iter().filter(|c| c["coin_state"] == "live").collect();
	assert_eq!(open.len(), 1, "{}", l);
	(open[0]["leaf_id"].as_str().unwrap().to_string(), num(&open[0]["balance"]))
}

/// The live plain leaves `w` holds of asset `x`, summed.
fn plain(w: &Arca, x: &str, channel_leaf: &str) -> u64 {
	let c = w.ok(&["coins"]);
	c.as_array().unwrap().iter()
		.filter(|c| c["state"] == "live" && c["asset"] == x && c["leaf_id"] != channel_leaf)
		.map(|c| num(&c["value"])).sum()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_quote_names_the_fee_and_a_channel_side_is_closed_to_pay() {
	let mut r = Running::start_with(|c, _, _| {
		c.assets[0].channel_capacity = Some("2000000".into());
	}).await;
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("quote A");
	let b = Arca::new("quote B");
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1",
		"--min-exit-delay-units", "1"];
	a.ok(&create);
	b.ok(&create);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, r.x, 5_000_000);
	r.produce().await;
	a.ok(&["board", &x, &BOARD.to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the server to credit A's board", || a.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	a.ok(&["sync"]);

	// --- The quote is the payment's fee, to the atom, and its coins ---
	let req = b.ok(&["receive", "--asset", &x, "--amount", "100000"])["request"].as_str().unwrap().to_string();
	let q = a.ok(&["send-quote", &req]);
	assert_eq!(q["route"], "leaf", "{}", q);
	assert_eq!(q["value"], "100000", "{}", q);
	let fee = num(&q["fee"]);
	assert!(fee > 0, "a transfer leaves margins for its transactions' fees: {}", q);
	let sent = a.ok(&["send", &req]);
	assert_eq!(fee, margins(&sent), "the quote's fee is what the payment gave up: {} / {}", q, sent);
	assert_eq!(q["inputs"], sent["inputs"], "the quote gives up the coins the payment gives up");
	assert_eq!(num(&q["change"]), num(&sent["change"]), "and leaves the same change");
	println!("quoted {} and paid {} in margins", fee, margins(&sent));

	// --- Part of it in a channel ---
	let p = a.ok(&["channel", "open", "--capacity", "1000000", "--keep", &KEEP.to_string()]);
	assert_eq!(p["participations"][0]["state"], "pending", "{}", p);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let round = built.tx.txid();
	r.produce().await;
	r.bury().await;
	r.round_state(&round, RoundState::Final).await;
	let s = a.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s);
	let (leaf, side) = channel(&a);
	let kept = plain(&a, &x, &leaf);
	println!("A keeps {} in a plain leaf and {} on its side of channel {}", kept, side, leaf);
	assert!(kept > 0 && side > 0, "both halves are held");

	// A payment larger than the plain leaf, which the channel's side covers:
	// refused naming the channel, by the quote as by the payment.
	let want = kept + side / 2;
	let req2 = b.ok(&["receive", "--asset", &x, "--amount", &want.to_string()])["request"].as_str().unwrap().to_string();
	for cmd in ["send-quote", "send"] {
		let (ok, v) = a.run(&[cmd, &req2]);
		assert!(!ok, "{} paid what only the channel covers: {}", cmd, v);
		assert_eq!(v["error"]["kind"], "in_channel", "{}: {}", cmd, v);
		assert_eq!(v["error"]["asset"], x.as_str(), "{}", v);
		assert_eq!(v["error"]["close"], serde_json::json!([leaf]), "{}", v);
		let msg = v["error"]["message"].as_str().unwrap();
		assert!(msg.contains("a transfer does not spend"), "{}", msg);
		println!("{} refused: {}", cmd, msg);
	}
	// More than the plain leaf and the channel's side together: still refused
	// naming the channel, since closing it raises the most A can send.
	let over = kept + side + 1;
	let req3 = b.ok(&["receive", "--asset", &x, "--amount", &over.to_string()])["request"].as_str().unwrap().to_string();
	for cmd in ["send-quote", "send"] {
		let (ok, v) = a.run(&[cmd, &req3]);
		assert!(!ok, "{} paid more than A holds: {}", cmd, v);
		assert_eq!(v["error"]["kind"], "in_channel", "{}: {}", cmd, v);
		assert_eq!(v["error"]["close"], serde_json::json!([leaf]), "{}", v);
		assert!(v["error"]["message"].as_str().unwrap().contains("does not cover it all"), "{}", v);
		// The most it can pay once the channel is closed, and that payment's fee.
		assert_eq!(num(&v["error"]["side"]), side, "{}", v);
		assert_eq!(num(&v["error"]["most"]) + num(&v["error"]["fee"]), kept + side, "{}", v);
	}
	let (_, v) = a.run(&["send-quote", &req3]);
	let (most, fee_after) = (num(&v["error"]["most"]), num(&v["error"]["fee"]));
	println!("once the channel is closed: at most {} with {} in margins", most, fee_after);
	// What the plain leaf alone allows is still paid out of it.
	let small = b.ok(&["receive", "--asset", &x, "--amount", "10000"])["request"].as_str().unwrap().to_string();
	assert_eq!(a.ok(&["send-quote", &small])["route"], "leaf");

	// --- Closed into a round, the side comes back as a leaf, and it pays ---
	let p = a.ok(&["participate", "--leaf", &leaf]);
	assert_eq!(p["participations"][0]["state"], "pending", "{}", p);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let round = built.tx.txid();
	r.produce().await;
	r.bury().await;
	r.round_state(&round, RoundState::Final).await;
	let s = a.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s);
	// The most named before the close is paid once it is, with the fee named.
	let req4 = b.ok(&["receive", "--asset", &x, "--amount", &most.to_string()])["request"].as_str().unwrap().to_string();
	let q4 = a.ok(&["send-quote", &req4]);
	assert_eq!(num(&q4["fee"]), fee_after, "the fee named before the close: {}", q4);
	assert_eq!(q4["change"], Value::Null, "the most leaves no change: {}", q4);
	let q2 = a.ok(&["send-quote", &req2]);
	let fee2 = num(&q2["fee"]);
	let sent2 = a.ok(&["send", &req2]);
	assert_eq!(sent2["sent"]["value"], want.to_string().as_str(), "{}", sent2);
	assert_eq!(fee2, margins(&sent2), "{} / {}", q2, sent2);
	println!("paid {} after closing the channel, {} in margins", want, fee2);
}
