//! A wallet with several exits under way reads the node's set of unspent
//! outputs once a view at most, and not at all across blocks that touch
//! nothing it looks for: each exit step locates the exit's path on the
//! chain, and each locate was a scan of the node's whole set of its own,
//! dropped and made again at every block (a maker with a dozen exits made a
//! dozen scans at every block, seven seconds of its sync in which it
//! answered no taker).
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::Script;
use serde_json::{json, Value};

use bark::arca::{command, Wallet};
use common::cli::Arca;
use common::running::Running;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

/// A sync of the open wallet `w`, as a program that keeps it open runs it:
/// its answer, and the scans of the node's set it made and the answers it
/// carried from an earlier view.
fn sync(w: &mut Wallet) -> (Value, u64, u64) {
	tokio::task::block_in_place(|| {
		let (s0, c0) = w.node_scans();
		let v = command::run(w, "sync", &json!({})).expect("sync");
		let (s1, c1) = w.node_scans();
		(v, s1 - s0, c1 - c0)
	})
}

#[tokio::test(flavor = "multi_thread")]
async fn exits_under_way_scan_the_set_once_a_view_and_not_across_blocks_that_touch_none() {
	let mut r = Running::start().await;
	let x = r.x;
	let url = r.url();
	let a = Arca::new("XS");
	a.ok(&["create", "--server", &url, "--node-url", &r.node_url(), "--node-user", "arca", "--exit-delay-units", "4",
		"--min-exit-delay-units", "1"]);
	// Three boards, each exited: three exits under way, each with a path of
	// its own to locate.
	const EXITS: usize = 3;
	let mut boards = vec![];
	for _ in 0..EXITS {
		let s = Script::from(unhex(a.ok(&["address"])["script_pubkey"].as_str().unwrap()));
		r.pay_to(s, x, 1_000_000 + 3_000_000);
		r.produce().await;
		boards.push(a.ok(&["board", &x.to_string(), "1000000"])["leaf_id"].as_str().unwrap().to_string());
		r.produce().await;
	}
	r.bury().await;
	r.synced().await;
	r.wait("the boards to be credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
	for b in &boards {
		a.ok(&["exit", b]);
	}
	r.produce().await;
	let exiting = |c: &Value| c.as_array().unwrap().iter().filter(|c| c["state"] == "exiting").count();
	assert_eq!(exiting(&a.ok(&["coins"])), EXITS, "every board exiting");

	let mut w = tokio::task::block_in_place(|| Wallet::open(&a.dir)).expect("open the wallet");
	let (first, scans, _) = sync(&mut w);
	println!("first sync: {} scans of the set; exits {}", scans, first["result"]["exits"]);
	assert!(scans <= 1, "one scan answers every exit's path and the on-chain windows: {}", scans);

	// Blocks that pay none of the paths and spend nothing found on them: no
	// scan at all, every answer carried.
	for k in 0..3 {
		r.produce().await;
		r.synced().await;
		let (v, scans, carried) = sync(&mut w);
		let exits = v["result"]["exits"].as_array().map(Vec::len).unwrap_or(0);
		println!("an empty block ({}): {} scans, {} answers carried, {} exits moved on, cost {}", k, scans, carried, exits,
			v["result"]["cost_by_step"]);
		assert!(exits >= EXITS, "each exit step ran: {}", v["result"]["exits"]);
		assert_eq!(scans, 0, "a block that touches none of the scripts scans nothing: {}", scans);
		assert!(carried > 0, "the answers carried");
		// The slice's re-check and its early exit steps are named steps.
		let steps = v["result"]["cost_by_step"].as_object().expect("cost_by_step");
		assert!(steps.contains_key("recheck") && steps.contains_key("early exits"), "{:?}", steps.keys());
	}

	// A block that pays one of the scripts: one scan, of that script and
	// whatever else the wallet watches that the block touched, not one an exit.
	let s = Script::from(unhex(w.address().unwrap()["script_pubkey"].as_str().unwrap()));
	r.pay_to(s, x, 50_000);
	r.produce().await;
	r.synced().await;
	let (_, scans, carried) = sync(&mut w);
	println!("a block paying the wallet: {} scans, {} answers carried", scans, carried);
	assert!(scans <= 1, "one scan at most, for what the block touched: {}", scans);

	// The same answers as a wallet opened afresh, which scans everything.
	let states = |c: &Value| -> Vec<(String, String)> {
		let mut v: Vec<(String, String)> = c.as_array().unwrap().iter()
			.map(|c| (c["leaf_id"].as_str().unwrap().to_string(), c["state"].as_str().unwrap().to_string())).collect();
		v.sort();
		v
	};
	let mine = tokio::task::block_in_place(|| command::run(&mut w, "coins", &json!({}))).unwrap()["result"].clone();
	let fresh = a.ok(&["coins"]);
	assert_eq!(states(&mine), states(&fresh), "the carried answers are the chain's");
	assert_eq!(exiting(&fresh), EXITS);
	let mine = tokio::task::block_in_place(|| command::run(&mut w, "balance", &json!({}))).unwrap()["result"].clone();
	let fresh = a.ok(&["balance"]);
	println!("balance, open: {}\nbalance, afresh: {}", mine, fresh);
	// The command line adds the Bitcoin side and rows for people; the
	// Sequentia side is compared.
	for k in ["arca", "held", "sequentia_onchain"] {
		assert_eq!(mine[k], fresh[k], "{}: the open wallet's balance, the payment included, is the fresh wallet's", k);
	}
	assert!(!mine["sequentia_onchain"].as_object().unwrap().is_empty());
}
