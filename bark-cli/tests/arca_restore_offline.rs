//! A wallet restored from its mnemonic while its operator is unreachable:
//! created from the operator's signed registry record alone, it takes its
//! coins from the trees the operator published, kept as files, and takes
//! one home on the chain. The server is never asked: the record names an
//! address nothing answers at. Another wallet's leaves in the same trees are
//! not taken, which only the tag of each owner nonce tells apart.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::collections::BTreeSet;

use elements::Script;
use serde_json::{json, Value};

use common::cli::Arca;
use common::running::{keypair, Running};
use server::store::RoundState;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

/// The ids of `w`'s live coins that rest on a round's batch.
fn batch_leaves(w: &Arca) -> BTreeSet<String> {
	w.ok(&["coins"]).as_array().unwrap().iter()
		.filter(|c| c["state"] == "live" && c["kind"] != "board")
		.map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect()
}

/// The operator's registry entry, signed with the test operator's key, its
/// API at `api`.
fn registry_entry(genesis: &str, api: &str) -> Value {
	let key = keypair("operator");
	let record = json!({
		"arca_operator": 1, "operator": key.x_only_public_key().0.to_string(), "genesis_hash": genesis,
		"api": api, "assets": [], "keepers": {"keys": [], "required": 0}, "exit_delay_units": {"min": 1, "max": 2},
		"expiry": {"batch_lifetime_seconds": 2419200, "exit_deadline_seconds": 259200},
		"templates": {"version": 1, "list": ["vtxo-1"]}, "contact": {"name": "test", "domain": "example.org"}, "issued_at": 1,
	});
	let sig = arca_covenant::operator_record::sign(&key, &record, genesis, &[0; 32]).unwrap();
	json!({"record": record, "signature": sig.to_string()})
}

/// Runs `w`'s `exit` of `leaf`, with blocks and its exit delay waited out,
/// until it answers `until`.
async fn exit_until(r: &Running, w: &Arca, leaf: &str, until: &str) -> Value {
	for k in 0..30 {
		let e = w.ok(&["exit", leaf]);
		println!("EXIT {} #{}: {} {}", &leaf[..16], k, e["state"], e["next"].as_str().or(e["error"].as_str()).unwrap_or(""));
		if e["state"] == until {
			return e;
		}
		r.produce().await;
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 600));
		r.bury().await;
		r.synced().await;
	}
	panic!("the exit of {} never reached {}", leaf, until);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_restored_from_published_trees_alone_takes_its_coins_home() {
	let mut r = Running::start_with(|c, _, _| {
		c.batches.no_sweep = true;
	}).await;
	let x = r.x.to_string();
	let x_id = r.x;
	r.fund_server(x_id, 100_000_000).await;
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	let (a, b) = (Arca::new("OFFA"), Arca::new("OFFB"));
	for w in [&a, &b] {
		w.ok(&create);
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, x_id, 5_000_000);
	}
	r.produce().await;
	for w in [&a, &b] {
		w.ok(&["board", &x, "2000000"]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards credited", || [&a, &b].iter().all(|w| w.ok(&["boards"])[0]["server"]["state"] == "credited")).await;

	// A and B refresh into one round, held for their forfeits, then final.
	for w in [&a, &b] {
		let p = w.ok(&["participate"]);
		assert!(p["participations"].as_array().unwrap().iter().all(|x| x["state"] == "pending"), "{}", p);
	}
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(!built.is_empty() && failed.is_empty(), "{} built, {} failed", built.len(), failed.len());
	for w in [&a, &b] {
		let s = w.ok(&["sync"]);
		assert!(common::cli::handed_over(&s), "{}", s);
	}
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	for t in &built {
		r.round_state(&t.tx.txid(), RoundState::Final).await;
	}
	for w in [&a, &b] {
		let s = w.ok(&["sync"]);
		assert!(s["participations"].as_array().unwrap().iter().all(|p| p["state"] == "released"), "{}", s);
	}
	let (mine, theirs) = (batch_leaves(&a), batch_leaves(&b));
	assert!(!mine.is_empty() && !theirs.is_empty(), "A holds {:?}, B {:?}", mine, theirs);
	println!("A's leaves {:?}; B's {:?}", mine, theirs);

	// Every tree the round published, kept as files, as any archive of them
	// keeps them.
	let archive = a.dir.with_extension("trees");
	let _ = std::fs::remove_dir_all(&archive);
	std::fs::create_dir_all(&archive).unwrap();
	let mut kept = 0;
	for t in &built {
		for vout in 0..t.tx.output.len() as u32 {
			let body = json!({"txid": t.tx.txid().to_string(), "vout": vout}).to_string();
			let resp = minreq::post(format!("{}/v1/tree", url)).with_header("Content-Type", "application/json").with_body(body).send().unwrap();
			if resp.status_code != 200 {
				continue;
			}
			let tree: Value = serde_json::from_str(resp.as_str().unwrap()).unwrap();
			std::fs::write(archive.join(format!("{}-{}.json", t.tx.txid(), vout)), tree.to_string()).unwrap();
			kept += 1;
		}
	}
	assert!(kept > 0, "the round published its trees");
	println!("{} tree(s) kept in {}", kept, archive.display());

	// The operator is unreachable: the record names an address where nothing
	// answers. A's mnemonic, the record and the trees are all there is.
	let genesis = r.rt.client().genesis_hash().unwrap().to_string();
	let record_file = archive.with_extension("record.json");
	std::fs::write(&record_file, registry_entry(&genesis, "http://127.0.0.1:9/arca").to_string()).unwrap();
	let words = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap().trim().to_string();
	let a2 = Arca::new("OFFA2");
	let made = a2.ok(&["create", "--operator-record", record_file.to_str().unwrap(), "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1", "--mnemonic", &words]);
	println!("A2 created offline: operator {} | {}", made["operator"], made["restore"]);
	assert_eq!(made["operator"], keypair("operator").x_only_public_key().0.to_string());

	let out = a2.ok(&["restore-trees", archive.to_str().unwrap()]);
	println!("A2 restored from {} tree(s), {} leaves looked at: restored {} | not recovered {} | refused {}", out["trees"],
		out["leaves_looked_at"], out["restored"], out["not_recovered"], out["refused"]);
	assert_eq!(out["refused"], json!([]), "{}", out);
	assert_eq!(out["not_recovered"], json!([]), "{}", out);
	let restored: BTreeSet<String> = out["restored"].as_array().unwrap().iter().map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
	assert_eq!(restored, mine, "A's leaves, and none of B's");
	assert!(restored.is_disjoint(&theirs));
	assert_eq!(batch_leaves(&a2), mine, "held live, as A held them");
	for c in a2.ok(&["coins"]).as_array().unwrap() {
		let held = a.ok(&["coins"]).as_array().unwrap().iter().find(|h| h["leaf_id"] == c["leaf_id"]).cloned().unwrap();
		assert_eq!((&c["asset"], &c["value"]), (&held["asset"], &held["value"]), "{}", c["leaf_id"]);
	}
	// Run again, it takes nothing new; another mnemonic's wallet finds nothing.
	let again = a2.ok(&["restore-trees", archive.to_str().unwrap()]);
	assert_eq!(batch_leaves(&a2), mine, "{}", again);
	let c2 = Arca::new("OFFC2");
	c2.ok(&["create", "--operator-record", record_file.to_str().unwrap(), "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1", "--mnemonic", "legal winner thank year wave sausage worth useful legal winner thank yellow"]);
	let none = c2.ok(&["restore-trees", archive.to_str().unwrap()]);
	assert_eq!(none["restored"], json!([]), "{}", none);

	// A2 takes one of them home on the chain, the operator never asked.
	let leaf = mine.iter().next().unwrap().clone();
	let home = exit_until(&r, &a2, &leaf, "exited").await;
	println!("A2's leaf {} home: {}", &leaf[..16], home);
	for w in [&a, &b, &a2, &c2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
	let _ = std::fs::remove_dir_all(&archive);
	let _ = std::fs::remove_file(&record_file);
}
