//! `vtxo-2` as the `arca` wallet meets it, against a whole Arca server, its
//! signer, PostgreSQL and the node, on an anchored proof-of-stake regtest
//! chain with Simplicity active.
//!
//! Three wallets: A and B ask for `vtxo-2` leaves (`leaf-template vtxo-2`),
//! C starts with `vtxo-1`. A boards and refreshes into a `vtxo-2` leaf while C
//! refreshes into a `vtxo-1` leaf in the same round, one batch holding both.
//! C then asks for `vtxo-2` and refreshes its `vtxo-1` coin into a `vtxo-2`
//! leaf. A pays B out of round: B's request asks for `vtxo-2`, so B's coin
//! and A's change are `vtxo-2`, each moved through a `vtxo-2` checkpoint whose
//! pair the signer builds from the named inputs. B refreshes its `vtxo-2` coin
//! into a new `vtxo-2` leaf (the forfeit of a `vtxo-2` coin). A takes its
//! change home: the unroll, the `vtxo-2` checkpoint and reassignment, then the
//! claim by the exit after its delay. A plan for a `vtxo-2` coin is refused by
//! the wallet and by the operator.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::str::FromStr;

use elements::hex::FromHex;
use elements::Script;
use serde_json::{json, Value};

use arca_covenant::collab::collab_cmr;
use common::cli::Arca;
use common::running::Running;
use server::store::RoundState;

fn script(v: &Value) -> Script {
	Script::from(Vec::<u8>::from_hex(v["script_pubkey"].as_str().unwrap()).unwrap())
}

fn atoms(v: &Value) -> u64 {
	v.as_str().unwrap_or_else(|| panic!("an amount: {}", v)).parse().unwrap()
}

fn create_args<'a>(server: &'a str, node: &'a str) -> Vec<&'a str> {
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

/// The live coins of `w` in `asset`.
fn live_in(w: &Arca, asset: &str) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == asset).cloned().collect()
}

/// Runs a round, buries it and waits until it is final.
async fn round(r: &mut Running, what: &str) -> elements::Txid {
	let round = r.server.rounds.run_round().await.unwrap().unwrap_or_else(|| panic!("{}: a round", what));
	r.produce().await;
	r.bury().await;
	r.round_state(&round.tx.txid(), RoundState::Final).await;
	println!("{}: round {} final", what, round.tx.txid());
	round.tx.txid()
}

/// Whether input `i` of `tx` spends by `arca/collab-2`.
fn by_collab2(tx: &elements::Transaction, i: usize) -> bool {
	let w = arca_covenant::witness::without_annex(&tx.input[i].witness.script_witness);
	w.len() == 4 && w[2] == collab_cmr().to_vec()
}

#[tokio::test(flavor = "multi_thread")]
async fn vtxo_2_leaves_are_refreshed_paid_and_taken_home() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (url, node_url) = (r.url(), r.node_url());
	let (a, b, c) = (Arca::new("V2A"), Arca::new("V2B"), Arca::new("V2C"));
	for w in [&a, &b, &c] {
		w.ok(&create_args(&url, &node_url));
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, r.x, 3_000_000);
	}
	r.produce().await;
	let templates = &a.ok(&["info"])["server_info"]["templates"]["list"];
	assert!(templates.as_array().unwrap().contains(&json!("vtxo-2")), "{}", templates);
	assert_eq!(a.ok(&["leaf-template"])["leaf_template"], "vtxo-1", "the default");
	for w in [&a, &b] {
		assert_eq!(w.ok(&["leaf-template", "vtxo-2"])["leaf_template"], "vtxo-2");
	}
	c.refused(&["leaf-template", "htlc-1"], "vtxo-1 or vtxo-2");
	println!("the operator lists {}; A and B ask for vtxo-2 leaves, C for vtxo-1", templates);

	// ---- One round, a vtxo-2 leaf and a vtxo-1 leaf in one batch ----------
	for w in [&a, &c] {
		w.ok(&["board", &x, "2000000"]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	for w in [&a, &c] {
		r.wait("the boards credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
		w.ok(&["sync"]);
		let p = w.ok(&["participate"]);
		assert_eq!(p["participations"].as_array().map(|v| v.len()), Some(1), "{}", p);
	}
	let round1 = round(&mut r, "A's and C's boards refreshed").await;
	for (w, want) in [(&a, "vtxo-2"), (&c, "vtxo-1")] {
		let s = w.ok(&["sync"]);
		assert!(s["participations"].as_array().unwrap().iter().all(|q| q["state"] == "released"), "{}", s);
		let coins = live_in(w, &x);
		let leaf = coins.iter().find(|c| c["kind"] == "batch").unwrap_or_else(|| panic!("a leaf of round one: {:?}", coins));
		assert_eq!(leaf["template"], want, "{}", leaf);
	}
	let tree: Value = a.ok(&["coins"]);
	println!("round {}: A's board refreshed into a vtxo-2 leaf, C's into a vtxo-1 leaf, one batch ({} coins of A)", round1,
		tree.as_array().unwrap().len());

	// ---- C's vtxo-1 coin refreshed into a vtxo-2 leaf ----------------------
	assert_eq!(c.ok(&["leaf-template", "vtxo-2"])["leaf_template"], "vtxo-2");
	let c_old = live_in(&c, &x).into_iter().find(|c| c["template"] == "vtxo-1").expect("C's vtxo-1 coin");
	let c_old_id = c_old["leaf_id"].as_str().unwrap().to_string();
	c.ok(&["participate", "--leaf", &c_old_id]);
	round(&mut r, "C's vtxo-1 coin refreshed").await;
	let s = c.ok(&["sync"]);
	assert!(s["participations"].as_array().unwrap().iter().all(|q| q["state"] == "released"), "{}", s);
	let c_new = live_in(&c, &x);
	assert_eq!(c_new.len(), 1, "{:?}", c_new);
	assert_eq!(c_new[0]["template"], "vtxo-2", "{}", c_new[0]);
	println!("C's vtxo-1 coin {} refreshed into the vtxo-2 leaf {}", c_old_id, c_new[0]["leaf_id"]);

	// ---- A pays B out of round: both coins vtxo-2 ---------------------------
	let req = b.ok(&["receive", "--asset", &x, "--amount", "700000"]);
	assert_eq!(req["details"]["template"], "vtxo-2", "{}", req);
	a.ok(&["send", req["request"].as_str().unwrap()]);
	b.ok(&["sync"]);
	let bob = live_in(&b, &x);
	assert_eq!(bob.len(), 1, "{:?}", bob);
	assert_eq!((bob[0]["template"].clone(), atoms(&bob[0]["value"])), (json!("vtxo-2"), 700_000), "{}", bob[0]);
	let alice = live_in(&a, &x);
	assert_eq!(alice.len(), 1, "A's change: {:?}", alice);
	assert_eq!(alice[0]["template"], "vtxo-2", "{}", alice[0]);
	let a_change = alice[0]["leaf_id"].as_str().unwrap().to_string();
	println!("A paid B 700000 out of round: B's coin and A's change are vtxo-2");

	// ---- A vtxo-2 coin is never planned -------------------------------------
	let m = a.refused(&["plan", &a_change], "no live coin of a round");
	println!("REFUSED: a plan of A's vtxo-2 change: {}", m);

	// ---- B refreshes its vtxo-2 coin into a vtxo-2 leaf ----------------------
	let b_old = bob[0]["leaf_id"].as_str().unwrap().to_string();
	b.ok(&["participate", "--leaf", &b_old]);
	round(&mut r, "B's vtxo-2 coin refreshed").await;
	let s = b.ok(&["sync"]);
	assert!(s["participations"].as_array().unwrap().iter().all(|q| q["state"] == "released"), "{}", s);
	let b_new = live_in(&b, &x);
	assert_eq!(b_new.len(), 1, "{:?}", b_new);
	assert_eq!((b_new[0]["template"].clone(), b_new[0]["kind"].clone()), (json!("vtxo-2"), json!("batch")), "{}", b_new[0]);
	let leaf = b_new[0]["leaf_id"].as_str().unwrap().to_string();
	b.refused(&["plan", &leaf], "no live coin of a round that no plan names");
	println!("B's vtxo-2 coin {} refreshed into the vtxo-2 leaf {}; a plan of it refused", b_old, leaf);

	// ---- A takes its vtxo-2 change home ---------------------------------------
	let e = a.ok(&["exit", &a_change]);
	assert!(matches!(e["state"].as_str(), Some("unrolling" | "waiting")), "{}", e);
	let mut broadcast: Vec<String> = vec![];
	let mut keep = |e: &Value| {
		for t in e["broadcast"].as_array().into_iter().flatten() {
			if let Some(id) = t.as_str().or_else(|| t["txid"].as_str()) {
				broadcast.push(id.to_string());
			}
		}
	};
	keep(&e);
	for _ in 0..12 {
		r.produce().await;
		let e = a.ok(&["exit", &a_change]);
		keep(&e);
		if e["state"] == "waiting" {
			break;
		}
	}
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 512));
	let e = a.ok(&["exit", &a_change]);
	assert_eq!(e["state"], "claimed", "{}", e);
	r.produce().await;
	r.bury().await;
	let claim_id = elements::Txid::from_str(e["claim"]["txid"].as_str().unwrap()).unwrap();
	let claim = r.rt.client().raw_transaction(&claim_id).unwrap();
	println!("A's exit claim {} ({} vB), by the exit leaf, as vtxo-1's", claim_id, claim.vsize());
	// The checkpoint and the reassignment on the chain spend by arca/collab-2.
	let mut collab2 = 0;
	for id in broadcast.iter().filter_map(|t| elements::Txid::from_str(t).ok()) {
		if let Ok(tx) = r.rt.client().raw_transaction(&id) {
			for i in 0..tx.input.len() {
				if by_collab2(&tx, i) {
					collab2 += 1;
					println!("on the chain: {} input {} spends by arca/collab-2 ({} vB)", id, i, tx.vsize());
				}
			}
		}
	}
	assert!(collab2 >= 2, "the checkpoint and the reassignment spend by arca/collab-2: {} found among {:?}", collab2, broadcast);
	a.ok(&["sync"]);
	assert_eq!(a.ok(&["record", &a_change])["state"], "exited");
	println!("A's vtxo-2 change exited");
}
