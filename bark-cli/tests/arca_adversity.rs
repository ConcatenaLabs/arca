//! The wallet against an operator that lies in an answer, stalls or vanishes,
//! a sender that goes back on a payment, and a chain that rolls back: each
//! case ends with the wallet refusing before it signs anything, or taking
//! its coin on-chain and holding it there, with the reason shown.
//!
//! Each test runs the `arca` binary against a whole Arca server, its watcher
//! on, on an anchored proof-of-stake regtest chain, through a proxy that can
//! rewrite any answer of the server or hold a call unanswered; where the
//! operator or a sender acts on the chain, the test builds that transaction
//! itself.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::str::FromStr;
use std::sync::Arc;

use elements::secp256k1_zkp::schnorr::Signature;
use elements::{AssetId, Script, Transaction};
use serde_json::{json, Value};

use arca_covenant::sign::verify_digest;
use arca_covenant::{connector_asset, CoinRecord, Forfeit, LeafId, RelativeTime};
use common::cli::Arca;
use common::proxy::Proxy;
use common::running::Running;
use server::store::RoundState;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

fn create_args<'a>(server: &'a str, node: &'a str) -> Vec<&'a str> {
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca", "--node-password", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

fn coin_of(w: &Arca, leaf: &str) -> Value {
	w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).cloned().unwrap_or(Value::Null)
}

fn record_of(w: &Arca, leaf: &str) -> CoinRecord {
	CoinRecord::from_bytes(&unhex(w.ok(&["record", leaf])["record"].as_str().unwrap())).unwrap()
}

/// Creates `w` on `server` and boards `amount` of each asset of `assets`, the
/// fee in the asset boarded; waits until every board is final and credited.
async fn boarded(r: &mut Running, w: &Arca, server: &str, assets: &[(AssetId, u64)]) -> Vec<String> {
	w.ok(&create_args(server, &r.node_url()));
	for (a, v) in assets {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, *a, v + 3_000_000);
	}
	r.produce().await;
	let mut boards = vec![];
	for (a, v) in assets {
		boards.push(w.ok(&["board", &a.to_string(), &v.to_string()])["leaf_id"].as_str().unwrap().to_string());
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards to be credited", || {
		w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")
	}).await;
	w.ok(&["sync"]);
	for b in &boards {
		assert_eq!(coin_of(w, b)["state"], "live");
	}
	boards
}

/// Runs a round, mines it and waits until the server finds it final.
async fn final_round(r: &Running) -> Transaction {
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	built.tx
}

// ---------------------------------------------------------------------------
// The refresh: the status's leaves
// ---------------------------------------------------------------------------

/// A refresh of coins in two assets. The operator's status names one new
/// leaf of the two asked for, and then another unlock hash than the leaves
/// carry: the wallet signs no forfeit for either, and both coins stay its
/// own. With the honest status each coin's forfeit is built against the new
/// leaf of its own asset, under the participation's one unlock hash.
#[tokio::test(flavor = "multi_thread")]
async fn a_status_that_hides_a_new_leaf_is_refused_before_any_forfeit() {
	let mut r = Running::start().await;
	common::node::list_fee_asset(&r.rt, r.y, 100_000_000);
	let proxy = Proxy::start(&r.url());
	let c = Arca::new("F1");
	let (x, y) = (r.x, r.y);
	let boards = boarded(&mut r, &c, &proxy.url.clone(), &[(x, 2_000_000), (y, 2_000_000)]).await;
	let p = c.ok(&["participate"]);
	assert_eq!(p["wants"].as_array().unwrap().len(), 2, "one new leaf per asset: {}", p);
	let round = final_round(&r).await;

	// The status names only the first new leaf.
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/participation_status" && status == 200 {
			let first = v["outputs"].as_array().unwrap()[..1].to_vec();
			v["outputs"] = Value::Array(first);
		}
		None
	})));
	let s = c.ok(&["sync"]);
	let why = s["participations"][0]["refused"].as_str().unwrap_or_else(|| panic!("not refused: {}", s)).to_string();
	println!("F1 a status naming 1 of 2 new leaves: REFUSED: {}", why);
	assert!(why.contains("asked for 2"), "{}", why);
	// Another unlock hash than the leaves carry.
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/participation_status" && status == 200 {
			v["unlock_hash"] = json!("11".repeat(32));
		}
		None
	})));
	let s = c.ok(&["sync"]);
	let why = s["participations"][0]["refused"].as_str().unwrap_or_else(|| panic!("not refused: {}", s)).to_string();
	println!("F1 a status naming another unlock hash: REFUSED: {}", why);
	assert!(why.contains("unlock hash"), "{}", why);
	assert_eq!(proxy.count("/v1/forfeit_leaves"), 0, "no forfeit was signed");
	for b in &boards {
		assert_eq!(coin_of(&c, b)["state"], "given", "the coin is still the wallet's");
	}

	// The honest status: the refresh completes, each forfeit against its own
	// asset's leaf under the participation's unlock hash.
	proxy.rewrite(None);
	let s = c.ok(&["sync"]);
	let done = &s["participations"][0];
	assert_eq!(done["state"], "released", "{}", s);
	assert_eq!(done["new_leaves"].as_array().unwrap().len(), 2, "{}", s);
	let (req, _, _) = proxy.last("/v1/forfeit_leaves").unwrap();
	let (_, _, st) = proxy.last("/v1/participation_status").unwrap();
	let h: [u8; 32] = unhex(st["unlock_hash"].as_str().unwrap()).try_into().unwrap();
	let cvout = st["round"]["connector_vout"].as_u64().unwrap() as u32;
	let refund = RelativeTime::from_units(st["refund_delay_units"].as_u64().unwrap() as u16).unwrap();
	for b in &boards {
		let CoinRecord::Board(rec) = record_of(&c, b) else { panic!("a board") };
		let k = st["inputs"].as_array().unwrap().iter().position(|i| i["leaf_id"] == b.as_str()).unwrap();
		let margin: u64 = st["inputs"][k]["margin"].as_str().unwrap().parse().unwrap();
		let f = Forfeit::new(rec.leaf(), (rec.asset, rec.value), LeafId::from_str(b).unwrap(), h, connector_asset(round.txid(), cvout),
			refund, margin).unwrap();
		let sig = req["forfeits"].as_array().unwrap().iter().find(|f| f["leaf_id"] == b.as_str()).unwrap()["signature"].as_str().unwrap();
		assert!(verify_digest(&Signature::from_slice(&unhex(sig)).unwrap(), &f.message().digest, &rec.owner),
			"the forfeit of {} is under the participation's unlock hash and round", b);
		assert_eq!(coin_of(&c, b)["state"], "spent");
	}
	let bal = c.ok(&["balance"]);
	for a in [x, y] {
		assert!(bal["arca"][a.to_string()]["live"].is_string(), "a new leaf in each asset: {}", bal);
	}
	let _ = std::fs::remove_dir_all(&c.dir);
}
