//! A payment the wallet's own coins cannot make as asked, with nothing more
//! of it on its way, is refused with the most it can pay now as a value
//! (`most`, and `live`, what it holds in live coins, when the margins are
//! what it falls short by), not only in the refusal's words: short once the
//! margins are counted, and leaving change below the operator's smallest
//! leaf. Paying the figure named goes. With the `arca` binary against a
//! whole Arca server on an anchored proof-of-stake regtest chain.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::Script;
use serde_json::Value;

use common::cli::Arca;
use common::running::Running;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

fn create(r: &Running, w: &Arca) {
	w.ok(&["create", "--server", &r.url(), "--node-url", &r.node_url(), "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
}

fn request(to: &Arca) -> String {
	to.ok(&["receive"])["request"].as_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_most_a_payment_can_be_comes_with_its_refusal() {
	let tag = "SF8 most";
	let mut r = Running::start_with(|c, _, _| c.watcher.enabled = false).await;
	let x = r.x;
	let (a, c, d) = (Arca::new(&format!("{} A", tag)), Arca::new(&format!("{} C", tag)), Arca::new(&format!("{} D", tag)));
	for w in [&a, &c, &d] {
		create(&r, w);
	}
	// A boards 2,000,000 of X, its fee in X.
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, x, 5_000_000);
	r.produce().await;
	a.ok(&["board", &x.to_string(), "2000000", "--fee-asset", &x.to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || {
		a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")
	}).await;
	a.ok(&["sync"]);
	let held: u64 = a.ok(&["coins"]).as_array().unwrap().iter().filter(|k| k["asset"] == x.to_string() && k["state"] == "live")
		.map(|k| k["value"].as_str().unwrap().parse::<u64>().unwrap()).sum();
	println!("{}: A holds {} of X live", tag, held);

	// Short once the margins are counted: the most it pays, and what it holds live.
	let (ok, v) = a.run(&["send", &request(&c), "--amount", &held.to_string(), "--asset", &x.to_string()]);
	println!("{}: the whole of it: {}", tag, v);
	assert!(!ok, "{}", v);
	assert_eq!(v["error"]["kind"], "refused", "{}", v);
	assert!(v["error"]["message"].as_str().unwrap().contains("in live coins"), "{}", v);
	assert_eq!(v["error"]["asset"], x.to_string(), "{}", v);
	assert_eq!(v["error"]["live"], held.to_string(), "what it holds in live coins, as a value: {}", v);
	let most: u64 = v["error"]["most"].as_str().expect("the most, as a value").parse().unwrap();
	assert!(most > 0 && most < held, "{}: {}", most, held);

	// A little less than that leaves change below the smallest leaf: the most
	// that leaves change of the smallest leaf.
	let (ok, w) = a.run(&["send", &request(&c), "--amount", &(most - 10).to_string(), "--asset", &x.to_string()]);
	println!("{}: a little less: {}", tag, w);
	assert!(!ok, "{}", w);
	assert!(w["error"]["message"].as_str().unwrap().contains("smallest leaf"), "{}", w);
	assert!(w["error"].get("live").is_none(), "{}", w);
	let less: u64 = w["error"]["most"].as_str().expect("the most, as a value").parse().unwrap();
	assert!(less < most - 10, "{} {}", less, most);

	// Each figure named goes.
	let sent = a.ok(&["send", &request(&d), "--amount", &less.to_string(), "--asset", &x.to_string()]);
	println!("{}: paid the change's figure: {}", tag, sent);
	for w in [&a, &c, &d] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
