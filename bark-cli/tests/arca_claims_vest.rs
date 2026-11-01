//! Claims that vest, run with the `arca` binary against a whole Arca server
//! building batches without a sweep, on an anchored proof-of-stake regtest
//! chain. A payer pays two holders in one round with `arca distribute --vest
//! T --days 8`: each claim leaf is `vest-1`. Before `T` a holder's `arca
//! claims` names the vest date in words and `arca claim` takes nothing,
//! saying when it can; once the chain's median time has passed `T`, `arca
//! claim` takes the claim up and the holder holds a live coin.
//!
//! A second test vests 40 days after the round, past the 28-day service
//! horizon of an ordinary batch without a sweep: the claims' batch is served
//! until their deadline and the horizon after it (an older server's shorter
//! horizon is moved there at its start), nothing moves it while the claims
//! vest, and after the vest time the holder takes its claim up through the
//! operator and refreshes the coin into a round.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::io::Write;

use elements::hashes::Hash;
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

#[tokio::test(flavor = "multi_thread")]
async fn a_claim_vesting_past_the_service_horizon_is_taken_up_through_the_operator() {
	const HORIZON: u32 = 28 * DAY;
	let mut r = Running::start_with(|c, _, _| {
		c.batches.no_sweep = true;
		c.batches.holder_batches = Some(0);
	}).await;
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca"];
	let payer = Arca::new("far vest payer");
	payer.ok(&create);
	r.pay_to(script(&payer.ok(&["address"])), r.x, 10_000_000);
	r.produce().await;
	payer.ok(&["board", &x, "3000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the payer's board to be credited", || payer.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	payer.ok(&["sync"]);
	let holder = Arca::new("far vest holder");
	holder.ok(&create);
	let path = payer.dir.join("claims.txt");
	std::fs::write(&path, format!("{} 1000000\n", holder.ok(&["address"])["key"].as_str().unwrap())).unwrap();
	let file = path.to_string_lossy().to_string();
	let fee = payer.ok(&["distribute", &file, "--asset", &x, "--quote"])["fee"].as_str().unwrap().to_string();
	let vest = common::node::median_time(&r.rt) + 40 * DAY;
	let deadline = vest + 8 * DAY;
	let d = payer.ok(&["distribute", &file, "--asset", &x, "--shown", &fee, "--vest", &vest.to_string(), "--days", "8"]);
	assert_eq!(d["deadline"].as_u64(), Some(deadline as u64));
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	payer.ok(&["sync"]);
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	payer.ok(&["sync"]);
	assert_eq!(payer.ok(&["distributions"])[0]["state"], "released");

	// The claims' batch is served until the deadline and the horizon after
	// it, not the horizon after the round.
	let round = r.server.store.round_by_txid(&built.tx.txid().to_byte_array()).await.unwrap().unwrap();
	let batches = r.server.store.batches(round.round_id).await.unwrap();
	println!("round {} at median time {}: batches {:?}", built.tx.txid(), common::node::median_time(&r.rt),
		batches.iter().map(|b| (b.vout, b.kind.as_str(), b.collect_mtp)).collect::<Vec<_>>());
	assert_eq!(batches.len(), 1, "the claims' batch alone");
	let b = &batches[0];
	assert_eq!(b.collect_mtp, Some(deadline + HORIZON), "served until the deadline and the horizon after it");

	// A batch an older server stored with the horizon after its round is
	// moved to the same at the next start.
	let older = common::node::median_time(&r.rt) + HORIZON;
	let (db, conn) = tokio_postgres::connect(&r.db.url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(async move { let _ = conn.await; });
	assert_eq!(db.execute("UPDATE batch SET collect_mtp = $3 WHERE round_id = $1 AND vout = $2",
		&[&round.round_id, &(b.vout as i32), &(older as i64)]).await.unwrap(), 1);
	r.restart_server().await;
	let again = r.server.store.batches(round.round_id).await.unwrap();
	println!("stored as an older server did: {}; after a start: {:?}", older, again[0].collect_mtp);
	assert_eq!(again[0].collect_mtp, Some(deadline + HORIZON));

	// Thirty days on, past the horizon after the round and before the vest
	// time: nothing has moved the batch, and the claim is still vesting.
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 30 * DAY));
	r.synced().await;
	r.server.watcher.pass().await.unwrap();
	r.produce().await;
	r.synced().await;
	let out: Value = r.rt.client().call("gettxout", &[serde_json::json!(built.tx.txid().to_string()), serde_json::json!(b.vout)]).unwrap();
	println!("day 30 (median time {}): the batch output {}", common::node::median_time(&r.rt),
		if out.is_null() { "spent".to_string() } else { format!("unspent, {}", out["value"]) });
	assert!(!out.is_null(), "nothing moves the claims' batch before they vest");
	let early = holder.ok(&["claim"]);
	assert_eq!(early[0]["state"], "vesting", "{}", early);
	assert!(holder.ok(&["coins"]).as_array().unwrap().is_empty());

	// After the vest time: taken up through the operator.
	let now2 = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, vest - now2 + HOUR));
	r.synced().await;
	println!("after the vest time: median time {}, {} days after the round", common::node::median_time(&r.rt),
		(common::node::median_time(&r.rt) - now) / DAY);
	let taken = holder.ok(&["claim"]);
	println!("the holder's claim: {}", taken);
	assert!(taken[0]["taken_up"]["transfer_id"].is_string(), "{}", taken);
	let coins = holder.ok(&["coins"]);
	println!("the holder's coins: {}", coins);
	let coin = coins.as_array().unwrap().iter().find(|c| c["asset"] == x.as_str()).expect("the taken-up coin").clone();
	assert_eq!(coin["expiry"].as_u64(), Some((deadline + HORIZON) as u64), "the wallet finds the operator's horizon");

	// And refreshed into a round, the coin out of the claims' batch.
	let p = holder.ok(&["refresh"]);
	println!("the holder's refresh: {}", p);
	let next = r.server.rounds.run_round().await.unwrap().unwrap();
	holder.ok(&["sync"]);
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&next.tx.txid(), RoundState::Final).await;
	holder.ok(&["sync"]);
	let after = holder.ok(&["coins"]);
	println!("the holder's coins after the refresh in round {}: {}", next.tx.txid(), after);
	assert!(after.as_array().unwrap().iter().any(|c| c["asset"] == x.as_str() && c["state"] == "live" && c["leaf_id"] != coin["leaf_id"]),
		"a live coin from the refresh: {}", after);
}
