//! The `arca` wallet of a holder whose batch with a sweep, made before the
//! operator turned `no_sweep` on, is collected early
//! (`[batches] collect_sweep_batches_before`): the collection brings the
//! coin given up beside it on the chain and claims its forfeit, which puts
//! the holder's entry on the chain; the holder's coin stays in the Ark, its
//! wallet shows it as before, at its whole value, and refreshes it.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::time::Duration;

use elements::hashes::Hash;
use elements::Script;
use serde_json::Value;

use common::cli::Arca;
use common::running::Running;
use server::store::{NurseryState, RoundState};

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

fn value(c: &Value) -> u64 {
	c["value"].as_str().map(|v| v.parse().unwrap()).or(c["value"].as_u64()).unwrap()
}

/// Boards `amount` of `asset` for each of `ws`, credited.
async fn boarded(r: &mut Running, ws: &[&Arca], asset: elements::AssetId, amount: u64) {
	for w in ws {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, asset, amount + 3_000_000);
	}
	r.produce().await;
	for w in ws {
		w.ok(&["board", &asset.to_string(), &amount.to_string()]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards credited", || ws.iter().all(|w| w.ok(&["boards"]).as_array().unwrap().iter()
		.all(|b| b["server"]["state"] == "credited"))).await;
}

/// Every wallet of `ws` refreshes in one round; a round held for its
/// forfeits (without a sweep) goes out once every wallet has synced.
async fn refresh(r: &Running, ws: &[&Arca]) -> Vec<elements::Txid> {
	for w in ws {
		let p = w.ok(&["participate"]);
		assert!(p["participations"].as_array().unwrap().iter().all(|x| x["state"] == "pending"), "{}", p);
	}
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(!built.is_empty() && failed.is_empty(), "{} built, {} failed", built.len(), failed.len());
	if built.iter().any(|b| b.broadcast.starts_with("held")) {
		for w in ws {
			assert!(common::cli::handed_over(&w.ok(&["sync"])));
		}
		r.server.rounds.pass().await.unwrap();
	}
	r.produce().await;
	r.bury().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	for w in ws {
		let s = w.ok(&["sync"]);
		let ps = s["participations"].as_array().unwrap();
		assert!(!ps.is_empty() && ps.iter().all(|p| p["state"] == "released"), "{}", s);
	}
	built.iter().map(|b| b.tx.txid()).collect()
}

fn live(w: &Arca) -> Value {
	w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["state"] == "live").cloned().expect("a live coin")
}

/// E and F refresh into one batch with a sweep; F refreshes again, giving
/// its coin up. The operator turns `no_sweep` on and collects the batches
/// with a sweep made before now, an hour after their round. Past that, the
/// watcher unrolls the batch to F's entry, F's leaf, its forfeit and the
/// claim; E's entry comes on the chain beside F's, its leaf does not. E's
/// coin alone holds its node's fronted value back, so E's next sync asks for
/// its refresh at once, for no fee, as for any such coin: the coin is not
/// taken home nor kept safe, keeps its whole value, and lands in a batch
/// without a sweep, E's balance unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn a_holder_beside_a_collected_coin_keeps_its_coin_and_refreshes_it() {
	let mut r = Running::start_with(|c, _, _| {
		c.batches.no_sweep = false;
		c.batches.holder_batches = Some(0);
	}).await;
	let x = r.x;
	r.fund_server(x, 100_000_000).await;
	r.fund_server(x, 100_000_000).await;
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	let (e, f) = (Arca::new("E early"), Arca::new("F early"));
	for w in [&e, &f] {
		w.ok(&create);
	}
	boarded(&mut r, &[&e, &f], x, 2_000_000).await;
	let first = refresh(&r, &[&e, &f]).await;
	let row = r.server.store.round_by_txid(&first[0].to_byte_array()).await.unwrap().unwrap();
	let b = r.server.store.batches(row.round_id).await.unwrap().remove(0);
	assert_ne!(b.token, arca_covenant::clock::no_sweep_token().into_inner().to_byte_array(), "a batch with a sweep");
	let second = refresh(&r, &[&f]).await;
	let row2 = r.server.store.round_by_txid(&second[0].to_byte_array()).await.unwrap().unwrap();
	let claim_of_f = format!("of round {}, ", row2.round_id);
	let ce = live(&e);
	let e_value = value(&ce);
	let e_balance = e.ok(&["balance"])["arca"].clone();
	println!("E's coin {} of {} in round {}; F's given up", ce["leaf_id"], e_value, row.round_id);

	// The operator: no sweep from now on, the batches before now collected
	// an hour after their round.
	let now = common::node::median_time(&r.rt);
	r.config.batches.no_sweep = true;
	r.config.batches.collect_sweep_batches_before = Some(now + 1);
	r.config.batches.collect_sweep_batches_after_seconds = Some(3_600);
	r.restart_server().await;
	r.synced().await;
	let b = r.server.store.batches(row.round_id).await.unwrap().remove(0);
	assert_eq!(b.collect_mtp, Some(row.created_mtp + 3_600));
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 2 * 3_600));

	let mut claimed = false;
	for _ in 0..20 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		let start = std::time::Instant::now();
		while !r.server.store.nursery_in(NurseryState::Pending).await.unwrap().iter().all(|n| n.broadcasts > 0) {
			assert!(start.elapsed() < Duration::from_secs(30));
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		r.produce().await;
		if r.server.store.watcher_log().await.unwrap().iter().any(|w| w.kind == "claim" && w.detail.contains(&claim_of_f)) {
			claimed = true;
			break;
		}
	}
	for w in r.server.store.watcher_log().await.unwrap() {
		println!("  watcher: {} {}", w.kind, w.detail.chars().take(120).collect::<String>());
		assert_ne!(w.kind, "sweep");
	}
	assert!(claimed, "F's forfeit claimed");
	r.bury().await;
	r.synced().await;
	let hex = ce["leaf_id"].as_str().unwrap();
	let e_id: [u8; 32] = (0..32).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect::<Vec<u8>>().try_into().unwrap();
	let e_spk = Script::from(r.server.store.leaf(&e_id).await.unwrap().expect("E's leaf at the server").script_pubkey);
	assert!(r.server.store.sightings_of(e_spk.as_bytes()).await.unwrap().is_empty(), "E's leaf is not landed");
	let entries = r.server.store.tree_sightings(row.round_id, b.vout).await.unwrap();
	println!("round 1's outputs on the chain: {}", entries.len());
	assert!(entries.len() >= 3, "the batch output and both entries");

	// E comes back. Its coin alone keeps its node's fronted value out, so
	// the operator names it and E's sync asks for its refresh at once, for
	// no fee; nothing else changed about it.
	let s = e.ok(&["sync"]);
	println!("E's sync: changes {} home {} exits {} refresh {}", s["recheck"]["changes"], s["home"], s["exits"], s["refresh"]);
	assert!(s["home"].as_array().is_none_or(|a| a.is_empty()) && s["exits"].as_array().is_none_or(|a| a.is_empty()),
		"E's coin is not taken home: {}", s);
	let coin = e.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == ce["leaf_id"]).cloned().expect("E's coin");
	println!("E's coin after the collection: state {} value {} kept_safe {}", coin["state"], coin["value"], coin["kept_safe"]);
	assert_eq!(value(&coin), e_value, "E's coin keeps its whole value");
	assert_ne!(coin["kept_safe"], true, "E's coin was not moved out of the Ark");
	let asked = s["refresh"].as_array().cloned().unwrap_or_default();
	for a in &asked {
		assert_eq!(a["fees"], serde_json::json!([]), "the refresh the operator names is free: {}", a);
	}
	if asked.is_empty() {
		assert_eq!(coin["state"], "live");
		e.ok(&["participate"]);
	}
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(!built.is_empty() && failed.is_empty());
	assert!(common::cli::handed_over(&e.ok(&["sync"])));
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	let s = e.ok(&["sync"]);
	assert!(s["participations"].as_array().unwrap().iter().any(|p| p["state"] == "released"), "{}", s);
	let new = live(&e);
	println!("E's coin refreshed: {} of {}; balance {}", new["leaf_id"], value(&new), e.ok(&["balance"])["arca"]);
	assert_ne!(new["leaf_id"], ce["leaf_id"]);
	assert_eq!(value(&new), e_value, "E holds the whole of its coin, refreshed");
	assert_eq!(e.ok(&["balance"])["arca"], e_balance, "E's balance is as before");
	let row = r.server.store.round_by_txid(&built[0].tx.txid().to_byte_array()).await.unwrap().unwrap();
	let nb = r.server.store.batches(row.round_id).await.unwrap().remove(0);
	assert_eq!(nb.token, arca_covenant::clock::no_sweep_token().into_inner().to_byte_array(), "into a batch without a sweep");
}
