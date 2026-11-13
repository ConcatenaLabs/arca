//! Locks between two holders (`htlc-2`), with the `arca` binary against a
//! whole Arca server on an anchored proof-of-stake regtest chain: a payer P
//! locks a coin of X to a payee Q under a payment hash, out of round; Q holds
//! it at once, claims it with the preimage, and P learns it was claimed; a
//! second lock, never claimed, comes back to P from its timeout, and Q
//! learns it is gone. No round is made between a lock and its ending, and
//! every atom is accounted for on both sides.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use bitcoin::hashes::{sha256, Hash};
use elements::{AssetId, Script};
use serde_json::{json, Value};

use common::cli::Arca;
use common::running::Running;

fn unhex(s: &str) -> Vec<u8> {
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

fn num(v: &Value) -> u64 {
	v.as_str().map(|s| s.parse().unwrap()).or_else(|| v.as_u64()).unwrap_or_else(|| panic!("not a number: {}", v))
}

fn create_args<'a>(server: &'a str, node: &'a str) -> Vec<&'a str> {
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

/// Creates `w` and boards `amount` of `asset`; waits until it is credited.
async fn boarded(r: &mut Running, w: &Arca, asset: AssetId, amount: u64) {
	w.ok(&create_args(&r.url(), &r.node_url()));
	let s = script(&w.ok(&["address"]));
	r.pay_to(s, asset, amount + 3_000_000);
	r.produce().await;
	w.ok(&["board", &asset.to_string(), &amount.to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
}

/// The coins `w` holds of `asset` in `state`, summed.
fn held(w: &Arca, asset: &str, state: &str) -> u64 {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["asset"] == asset && c["state"] == state).map(|c| num(&c["value"])).sum()
}

/// What the transfer `t` gave up for its fees.
fn margins(t: &Value) -> u64 {
	let m = &t["margins"];
	m["checkpoints"].as_array().unwrap().iter().map(num).sum::<u64>() + num(&m["reassignment"])
}

/// How many rounds the operator has made.
async fn rounds(r: &Running) -> usize {
	r.server.store.rounds_page(0, 10_000).await.unwrap().len()
}

fn lock(w: &Arca, hash: &str) -> Value {
	w.ok(&["lock", "list"]).as_array().unwrap().iter().find(|l| l["hash"] == hash).cloned().unwrap_or(Value::Null)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lock_is_held_at_once_claimed_with_the_preimage_and_refunded_from_its_timeout() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let p = Arca::new("lock P");
	let q = Arca::new("lock Q");
	let xa = r.x;
	boarded(&mut r, &p, xa, 3_000_000).await;
	q.ok(&create_args(&r.url(), &r.node_url()));

	// --- The lock, held at once, claimed with the preimage ---
	let preimage = [7u8; 32];
	let hash = hex(&sha256::Hash::hash(&preimage).to_byte_array());
	let p_before = held(&p, &x, "live");
	let rounds_before = rounds(&r).await;
	let req = q.ok(&["lock", "request", "--asset", &x, "--amount", "100000", "--hash", &hash]);
	assert_eq!(req["kind"], "arca-lock-request", "{}", req);
	let locked = p.ok(&["lock", "to", &req.to_string(), "--timeout-in", "7200"]);
	println!("locked: {}", json!({"leaf": locked["leaf_id"], "timeout": locked["timeout"], "refund_delay_units": locked["refund_delay_units"],
		"margins": locked["margins"], "change": locked["change"]}));
	let lock_fee = margins(&locked);
	assert_eq!(held(&p, &x, "live"), p_before - 100_000 - lock_fee, "P holds what it had less the lock and its margins");
	assert_eq!(held(&p, &x, "lock_out"), 100_000, "P holds the lock apart, its own by script");
	q.ok(&["sync"]);
	assert_eq!(held(&q, &x, "lock_in"), 100_000, "Q holds the lock apart from its spendable coins");
	assert_eq!(held(&q, &x, "live"), 0, "nothing spendable yet");
	let ready = q.ok(&["lock", "ready", &hash, "--need", "600"]);
	assert_eq!(ready["ready"], true, "the lock is held at once, out of round: {}", ready);
	println!("ready: {}", ready);
	let claimed = q.ok(&["lock", "claim", &hash, &hex(&preimage)]);
	assert_eq!(claimed["state"], "claimed", "{}", claimed);
	let q_live = held(&q, &x, "live");
	assert!(q_live > 0 && q_live < 100_000, "Q holds the lock less its claim's margins: {}", q_live);
	println!("Q claimed {} of 100000 (margins {})", q_live, 100_000 - q_live);
	assert_eq!(held(&q, &x, "lock_in"), 0);
	let s = p.ok(&["sync"]);
	println!("P's sync: {}", s["locks"]);
	assert_eq!(lock(&p, &hash)["state"], "claimed", "P learns its lock was claimed: {}", lock(&p, &hash));
	assert_eq!(lock(&p, &hash)["preimage"], hex(&preimage), "and the preimage with it");
	assert_eq!(held(&p, &x, "lock_out"), 0, "the claimed lock is P's no more");
	assert_eq!(rounds(&r).await, rounds_before, "no round between the lock and its claim");

	// --- A second lock, never claimed, refunded from its timeout ---
	let preimage2 = [8u8; 32];
	let hash2 = hex(&sha256::Hash::hash(&preimage2).to_byte_array());
	let req2 = q.ok(&["lock", "request", "--asset", &x, "--amount", "50000", "--hash", &hash2]);
	let p_before = held(&p, &x, "live");
	let locked2 = p.ok(&["lock", "to", &req2.to_string(), "--timeout-in", "5000"]);
	let t2 = num(&locked2["timeout"]) as u32;
	let fee2 = margins(&locked2);
	q.ok(&["sync"]);
	assert_eq!(q.ok(&["lock", "ready", &hash2])["ready"], true);
	// Before its timeout the wallet refuses the refund.
	let why = p.refused(&["lock", "refund", &hash2], "refunded from median time");
	println!("refund before T: {}", why);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, t2 - common::node::median_time(&r.rt) + 1));
	r.bury().await;
	r.synced().await;
	let s = p.ok(&["sync"]);
	println!("P's sync past T: {}", s["locks"]);
	assert_eq!(lock(&p, &hash2)["state"], "refunded", "{}", lock(&p, &hash2));
	let back = held(&p, &x, "live") + held(&p, &x, "pending");
	let refund_fee = p_before - fee2 - back;
	assert!(refund_fee > 0 && refund_fee < 50_000, "P has its lock back less the refund's margins: {} back, {} fee", back, refund_fee);
	println!("P refunded: {} of 50000 back (lock margins {}, refund margins {})", 50_000 - refund_fee, fee2, refund_fee);
	q.ok(&["sync"]);
	assert_eq!(lock(&q, &hash2)["state"], "refunded", "Q learns the lock is gone: {}", lock(&q, &hash2));
	assert_eq!(held(&q, &x, "lock_in"), 0);
	// The claim after the refund is refused: one ending per lock.
	let (ok, v) = q.run(&["lock", "claim", &hash2, &hex(&preimage2)]);
	assert!(!ok, "a claim after the refund: {}", v);
	println!("claim after refund: {}", v["error"]);
	assert_eq!(rounds(&r).await, rounds_before, "no round between the locks and their endings");
}
