//! Claims that vest, run with the `arca` binary against a whole Arca server
//! building batches without a sweep, on an anchored proof-of-stake regtest
//! chain. A payer pays two holders in one round with `arca distribute --vest
//! T --days 8`: each claim leaf is `vest-1`. Before `T` a holder's `arca
//! claims` names the vest date in words and `arca claim` takes nothing,
//! saying when it can; once the chain's median time has passed `T`, `arca
//! claim` takes the claim up and the holder holds a live coin.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::io::Write;

use elements::Script;
use serde_json::Value;

use common::cli::Arca;
use common::running::Running;
use server::store::RoundState;

const HOUR: u32 = 3_600;
const DAY: u32 = 86_400;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

#[tokio::test(flavor = "multi_thread")]
async fn vesting_claims_are_taken_up_once_they_vest() {
	let mut r = Running::start_with(|c, _, _| {
		c.batches.no_sweep = true;
		c.batches.holder_batches = Some(0);
	}).await;
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca"];

	let payer = Arca::new("vest payer");
	payer.ok(&create);
	r.pay_to(script(&payer.ok(&["address"])), r.x, 10_000_000);
	r.produce().await;
	payer.ok(&["board", &x, "3000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the payer's board to be credited", || payer.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	payer.ok(&["sync"]);

	let holders: Vec<Arca> = (0..2).map(|i| Arca::new(&format!("vest holder {}", i))).collect();
	let path = payer.dir.join("claims.txt");
	let mut f = std::fs::File::create(&path).unwrap();
	for h in &holders {
		h.ok(&create);
		writeln!(f, "{} 1000000", h.ok(&["address"])["key"].as_str().unwrap()).unwrap();
	}
	drop(f);
	let file = path.to_string_lossy().to_string();
	let fee = payer.ok(&["distribute", &file, "--asset", &x, "--quote"])["fee"].as_str().unwrap().to_string();
	let vest = common::node::median_time(&r.rt) + 2 * DAY;
	let d = payer.ok(&["distribute", &file, "--asset", &x, "--shown", &fee, "--vest", &vest.to_string(), "--days", "8"]);
	println!("distribute: {}", d);
	assert_eq!(d["vest"].as_u64(), Some(vest as u64));
	assert_eq!(d["deadline"].as_u64(), Some((vest + 8 * DAY) as u64), "the deadline counts from the vest time");
	let words = d["vests"].as_str().unwrap().to_string();
	assert!(words.split(' ').count() == 3 && words.chars().next().unwrap().is_ascii_digit(), "a date in words: {}", words);
	// A round without a sweep takes the payer's forfeit before it is
	// broadcast.
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	payer.ok(&["sync"]);
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	payer.ok(&["sync"]);
	let st = payer.ok(&["distributions"])[0].clone();
	assert_eq!(st["state"], "released", "{}", st);
	assert_eq!(st["vest"].as_u64(), Some(vest as u64), "{}", st);

	// Before the vest time: the claim is shown vesting, with its date.
	let found = holders[0].ok(&["claims"]);
	println!("holder 0's claims before the vest time: {}", found);
	assert_eq!(found[0]["state"], "vesting");
	assert_eq!(found[0]["vests"].as_str(), Some(words.as_str()));
	assert!(found[0]["note"].as_str().unwrap().contains(&format!("vests on {}", words)), "{}", found);
	let early = holders[0].ok(&["claim"]);
	println!("holder 0's claim before the vest time: {}", early);
	assert_eq!(early[0]["state"], "vesting", "{}", early);
	assert!(holders[0].ok(&["coins"]).as_array().unwrap().is_empty(), "nothing taken before the vest time");

	// After it: the claim is taken up, and the holder holds a live coin.
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, vest - now + HOUR));
	r.synced().await;
	let open = holders[0].ok(&["claims"]);
	assert_eq!(open[0]["state"], "open", "{}", open);
	let taken = holders[0].ok(&["claim"]);
	println!("holder 0's claim after the vest time: {}", taken);
	assert!(taken[0]["taken_up"]["transfer_id"].is_string(), "{}", taken);
	let coins = holders[0].ok(&["coins"]);
	assert!(coins.as_array().unwrap().iter().any(|c| c["asset"] == x.as_str()), "holder 0 holds its coin: {}", coins);
}
