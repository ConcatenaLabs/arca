//! The wallet with leaves of an accumulator batch without a sweep
//! (`arca/accumulator-2`), run as a user runs it: the `arca` binary against a
//! whole Arca server whose operator builds batches without a sweep
//! (`[batches] no_sweep`) and expects 1 % of a batch's leaves to leave on
//! their own (`accumulator_exit_rate_ppm = 10000`).
//!
//! Six wallets board and refresh in one round, held until every wallet has
//! signed: it pays one accumulator batch without a sweep, and each wallet
//! holds its leaf. Then:
//!
//! 1. A, B and C refresh again. Each wallet's `sync` signs, beside its
//!    forfeit, the release of its old slot, and hands it to the server once
//!    its new round is final; the server stores the three, and the watcher
//!    releases the three slots in one transaction, final.
//! 2. D takes its leaf out alone with `exit`: the wallet follows the batch
//!    from its round through the release, and its exit spends the rest the
//!    release left; its claim after the delay is final.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::str::FromStr;

use elements::{OutPoint, Script, Transaction, Txid};
use serde_json::Value;

use arca_covenant::CoinRecord;
use common::cli::Arca;
use common::running::Running;
use server::store::{NurseryState, RoundState};

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

fn coin_of(w: &Arca, leaf: &str) -> Value {
	w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).cloned().unwrap_or(Value::Null)
}

fn record_of(w: &Arca, leaf: &str) -> CoinRecord {
	CoinRecord::from_bytes(&unhex(w.ok(&["record", leaf])["record"].as_str().unwrap())).unwrap()
}

fn tx(r: &Running, txid: &str) -> Transaction {
	r.rt.client().raw_transaction(&Txid::from_str(txid).unwrap()).unwrap()
}

/// Every wallet of `ws` asks for its refresh; the round is held until every
/// wallet has synced (handing its forfeits over before broadcast), goes out,
/// is made final, and every wallet completes it. Each wallet's last `sync`.
async fn refresh_all(r: &Running, ws: &[&Arca]) -> Vec<Value> {
	for w in ws {
		let p = w.ok(&["participate"]);
		assert!(p["participations"].as_array().unwrap().iter().all(|x| x["state"] == "pending"), "{}", p);
	}
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(built.len() == 1 && failed.is_empty(), "{} built, {} failed", built.len(), failed.len());
	assert!(built[0].broadcast.starts_with("held"), "{}", built[0].broadcast);
	for w in ws {
		let s = w.ok(&["sync"]);
		assert!(s["participations"].as_array().unwrap().iter().all(|p| p["state"] == "forfeiting"), "{}", s);
	}
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built[0].tx.txid(), RoundState::Final).await;
	let mut out = vec![];
	for w in ws {
		let s = w.ok(&["sync"]);
		let ps = s["participations"].as_array().unwrap();
		assert!(!ps.is_empty() && ps.iter().all(|p| p["state"] == "released"), "{}", s);
		out.push(s);
	}
	out
}

/// Runs `exit` on `w`'s `leaf` until its claim is broadcast, with a block
/// and ten minutes between runs; returns each run's answer.
async fn claimed(r: &Running, w: &Arca, leaf: &str) -> Vec<Value> {
	let mut runs = vec![];
	for _ in 0..8 {
		let e = w.ok(&["exit", leaf]);
		let done = e["state"] == "claimed";
		runs.push(e);
		if done {
			return runs;
		}
		r.produce().await;
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 600));
		r.synced().await;
	}
	panic!("{}'s exit of {} was not claimed: {:?}", w.name, leaf, runs);
}

#[tokio::test(flavor = "multi_thread")]
async fn wallets_release_their_slots_and_an_exit_follows_the_release() {
	let mut r = Running::start_with(|c, _, _| {
		c.batches.no_sweep = true;
		c.batches.holder_batches = Some(0);
		c.batches.accumulator_exit_rate_ppm = Some(10_000);
	}).await;
	let x = r.x.to_string();
	r.fund_server(r.x, 100_000_000).await;
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	let names = ["ACR-A", "ACR-B", "ACR-C", "ACR-D", "ACR-E", "ACR-F"];
	let ws: Vec<Arca> = names.iter().map(|n| Arca::new(n)).collect();
	for w in &ws {
		w.ok(&create);
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, r.x, 6_000_000);
	}
	r.produce().await;
	for w in &ws {
		w.ok(&["board", &x, "2000000"]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the server to credit every board", || ws.iter().all(|w| w.ok(&["boards"])[0]["server"]["state"] == "credited")).await;

	// One round, one accumulator batch without a sweep.
	let refs: Vec<&Arca> = ws.iter().collect();
	let first = refresh_all(&r, &refs).await;
	let leaves: Vec<String> = first.iter().map(|s| s["participations"][0]["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string()).collect();
	let records: Vec<arca_covenant::AccumulatorRecord> = ws.iter().zip(&leaves).map(|(w, l)| match record_of(w, l) {
		CoinRecord::Accumulator { record, .. } => record,
		other => panic!("{}'s leaf is held as {:?}, not a leaf of an accumulator batch", w.name, other),
	}).collect();
	assert!(records.iter().all(|rec| !rec.schedule.expires()), "a batch without a sweep");
	let batch = records[0].batch_output().unwrap();
	let mut found = None;
	for row in r.server.store.rounds_in(RoundState::Final).await.unwrap() {
		let t: Transaction = elements::encode::deserialize(&row.tx).unwrap();
		if let Some(v) = t.output.iter().position(|o| arca_covenant::ExplicitOutput::from_txout(o).as_ref() == Some(&batch)) {
			found = Some((row, t, v as u32));
		}
	}
	let (round, round_tx, vout) = found.expect("the round that pays the batch");
	println!("round {}: one accumulator batch without a sweep at output {} holding {}, slots {:?}", round_tx.txid(), vout, batch.value,
		records.iter().map(|r| r.slot).collect::<Vec<_>>());

	// 1. A, B and C refresh and release their slots.
	let (a, b, c, d) = (&ws[0], &ws[1], &ws[2], &ws[3]);
	let second = refresh_all(&r, &[a, b, c]).await;
	for (w, s) in [a, b, c].iter().zip(&second) {
		let rel = &s["participations"][0]["released"];
		println!("{}: released {}", w.name, rel);
		assert_eq!(rel.as_array().map(|v| v.len()), Some(1), "{}'s slot release is taken: {}", w.name, s);
	}
	let stored = r.server.store.slot_releases(round.round_id, vout).await.unwrap();
	assert_eq!(stored.len(), 3, "the server stores the three slot releases");
	let mut release = None;
	for _ in 0..6 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		r.produce().await;
		release = r.server.store.watcher_log().await.unwrap().into_iter().find(|w| w.kind == "reclaim");
		if release.is_some() {
			break;
		}
	}
	let release = release.expect("the watcher releases the slots");
	for _ in 0..2 {
		r.produce().await;
		r.bury().await;
		r.synced().await;
		r.server.nursery.pass().await.unwrap();
	}
	let release_row = r.server.store.watcher_log().await.unwrap().into_iter().find(|w| w.txid == release.txid).unwrap();
	let rtx: Transaction = elements::encode::deserialize(&release_row.tx).unwrap();
	println!("release {} ({} vB, {:?}): {}", rtx.txid(), rtx.vsize(), release_row.state, release_row.detail);
	assert_eq!(release_row.state, NurseryState::Final);
	assert_eq!(rtx.input[0].previous_output, OutPoint::new(round_tx.txid(), vout), "the release spends the round's batch output");
	assert!(release_row.detail.contains(&format!("{:?}", {
		let mut s: Vec<u16> = records[..3].iter().map(|r| r.slot).collect();
		s.sort();
		s
	})), "{}", release_row.detail);

	// 2. D exits alone, from where the release left the batch.
	let ld = &leaves[3];
	let runs = claimed(&r, d, ld).await;
	let d_exit = runs[0]["broadcast"][0]["txid"].as_str().unwrap().to_string();
	println!("D's exit {} ({} vB)", d_exit, runs[0]["broadcast"][0]["vsize"]);
	assert_eq!(tx(&r, &d_exit).input[0].previous_output, OutPoint::new(rtx.txid(), 1), "D's exit spends the rest the release left");
	for _ in 0..4 {
		r.produce().await;
		r.bury().await;
		r.synced().await;
		d.ok(&["sync"]);
		if coin_of(d, ld)["state"] == "exited" {
			break;
		}
	}
	assert_eq!(coin_of(d, ld)["state"], "exited", "{}", coin_of(d, ld));
	println!("D's coin exited: {}", coin_of(d, ld));
}
