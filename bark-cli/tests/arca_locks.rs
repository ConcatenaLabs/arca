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

/// Runs `w`'s `exit` of `leaf`, with blocks and the median time moved on,
/// until it answers `until`. Returns the answer.
async fn exit_until(r: &Running, w: &Arca, leaf: &str, until: &str, server_up: bool) -> Value {
	for k in 0..40 {
		let e = w.ok(&["exit", leaf]);
		println!("EXIT {} {} #{}: {} {}", w.name, &leaf[..12], k, e["state"], e["next"].as_str().or(e["error"].as_str()).unwrap_or(""));
		if e["state"] == until {
			return e;
		}
		r.produce().await;
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 600));
		r.bury().await;
		if server_up {
			r.synced().await;
		}
	}
	panic!("the exit of {} never reached {}", leaf, until);
}

/// The transaction `txid` as the node holds it.
fn tx(r: &Running, txid: &str) -> elements::Transaction {
	r.rt.client().raw_transaction(&txid.parse().unwrap()).unwrap()
}

/// The operator stops co-signing anything once two locks are held: the payee
/// of the first, holding its preimage, takes it home on the chain by CLAIM
/// (the preimage in its witness, the payee's key alone); the payer of the
/// second takes it home by REFUND from its timeout. Each claim is in a block
/// and pays its holder what the lock held, less its fees.
#[tokio::test(flavor = "multi_thread")]
async fn each_side_takes_its_lock_home_on_the_chain_when_the_operator_signs_nothing() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let p = Arca::new("lock chain P");
	let q = Arca::new("lock chain Q");
	let xa = r.x;
	boarded(&mut r, &p, xa, 3_000_000).await;
	q.ok(&create_args(&r.url(), &r.node_url()));
	let (pre1, pre2) = ([0x11u8; 32], [0x22u8; 32]);
	let h1 = hex(&sha256::Hash::hash(&pre1).to_byte_array());
	let h2 = hex(&sha256::Hash::hash(&pre2).to_byte_array());
	let req1 = q.ok(&["lock", "request", "--asset", &x, "--amount", "200000", "--hash", &h1]);
	let req2 = q.ok(&["lock", "request", "--asset", &x, "--amount", "150000", "--hash", &h2]);
	let l1 = p.ok(&["lock", "to", &req1.to_string(), "--timeout-in", "30000"]);
	let l2 = p.ok(&["lock", "to", &req2.to_string(), "--timeout-in", "6000"]);
	let (leaf1, leaf2) = (l1["leaf_id"].as_str().unwrap().to_string(), l2["leaf_id"].as_str().unwrap().to_string());
	let t2 = num(&l2["timeout"]) as u32;
	q.ok(&["sync"]);
	assert_eq!(q.ok(&["lock", "ready", &h1])["ready"], true);
	assert_eq!(q.ok(&["lock", "ready", &h2])["ready"], true);

	// The operator signs nothing more.
	r.server.stop();
	// Q learns the first preimage (its BTC payment settled): it is kept, and
	// the claim out of round cannot be made.
	let (ok, v) = q.run(&["lock", "preimage", &h1, &hex(&pre1)]);
	println!("claim out of round with the operator down: ok={} {}", ok, v);
	assert!(!ok, "the operator co-signs nothing: {}", v);
	assert_eq!(lock(&q, &h1)["preimage"], hex(&pre1), "the preimage is kept: {}", lock(&q, &h1));

	// --- Q: CLAIM on the chain ---
	let e = exit_until(&r, &q, &leaf1, "claimed", false).await;
	let claim = tx(&r, e["claim"]["txid"].as_str().unwrap());
	let w = &claim.input[0].witness.script_witness;
	println!("Q's CLAIM {}: {} vB, witness of {} items, pays {:?}", claim.txid(), claim.vsize(), w.len(), claim.output[0].value);
	assert!(w.iter().any(|i| i[..] == pre1[..]), "CLAIM carries the preimage in its witness");
	let paid = claim.output[0].value.explicit().unwrap();
	assert!(paid < 200_000 && paid > 190_000, "Q's claim pays what the lock held less its fee: {}", paid);
	r.produce().await;
	r.bury().await;
	let _ = exit_until(&r, &q, &leaf1, "exited", false).await;

	// --- P: REFUND on the chain, from T ---
	let e = exit_until(&r, &p, &leaf2, "claimed", false).await;
	assert!(common::node::median_time(&r.rt) >= t2, "the refund confirms only from the lock's timeout");
	let refund = tx(&r, e["claim"]["txid"].as_str().unwrap());
	println!("P's REFUND {}: {} vB, lock time {}, T {}, pays {:?}", refund.txid(), refund.vsize(), refund.lock_time.to_consensus_u32(), t2,
		refund.output[0].value);
	assert_eq!(refund.lock_time.to_consensus_u32(), t2, "REFUND's lock time is the lock's timeout");
	assert!(!refund.input[0].witness.script_witness.iter().any(|i| i[..] == pre2[..]), "REFUND needs no preimage");
	let back = refund.output[0].value.explicit().unwrap();
	assert!(back < 150_000 && back > 140_000, "P's refund pays what the lock held less its fee: {}", back);
	r.produce().await;
	r.bury().await;
	let _ = exit_until(&r, &p, &leaf2, "exited", false).await;
	println!("on the chain: Q claimed {} of 200000, P refunded {} of 150000", paid, back);
}

/// A wallet made again from `w`'s phrase alone, under `name`.
fn restored(r: &Running, w: &Arca, name: &str) -> (Arca, Value) {
	let mnemonic = std::fs::read_to_string(w.dir.join("mnemonic")).unwrap();
	let w2 = Arca::new(name);
	let (url, node) = (r.url(), r.node_url());
	let mut args = create_args(&url, &node);
	args.extend(["--mnemonic", mnemonic.trim()]);
	let made = w2.ok(&args);
	(w2, made)
}

/// Both sides lose their device in mid-swap, with two locks open, and are
/// made again from their phrases: the payee's restore finds both locks held
/// apart (never spendable), the payer's finds both as its own to refund. The
/// payee claims the first with its preimage and the payer learns it; the
/// second comes back to the payer from its timeout.
#[tokio::test(flavor = "multi_thread")]
async fn a_restore_from_the_phrase_in_mid_swap_finds_each_side_its_locks() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let p = Arca::new("lock restore P");
	let q = Arca::new("lock restore Q");
	let xa = r.x;
	boarded(&mut r, &p, xa, 3_000_000).await;
	q.ok(&create_args(&r.url(), &r.node_url()));
	let (pre1, pre2) = ([0x31u8; 32], [0x32u8; 32]);
	let h1 = hex(&sha256::Hash::hash(&pre1).to_byte_array());
	let h2 = hex(&sha256::Hash::hash(&pre2).to_byte_array());
	let req1 = q.ok(&["lock", "request", "--asset", &x, "--amount", "120000", "--hash", &h1]);
	let req2 = q.ok(&["lock", "request", "--asset", &x, "--amount", "80000", "--hash", &h2]);
	p.ok(&["lock", "to", &req1.to_string(), "--timeout-in", "30000"]);
	let l2 = p.ok(&["lock", "to", &req2.to_string(), "--timeout-in", "5000"]);
	let t2 = num(&l2["timeout"]) as u32;
	q.ok(&["sync"]);
	let p_live = held(&p, &x, "live");

	let (q2, made) = restored(&r, &q, "lock restore Q2");
	println!("Q2's restore: served {} restored {} mailbox {}", made["restore"]["served"], made["restore"]["restored"], made["restore"]["mailbox"]);
	q2.ok(&["sync"]);
	let (p2, made) = restored(&r, &p, "lock restore P2");
	println!("P2's restore: served {} restored {} mailbox {}", made["restore"]["served"], made["restore"]["restored"], made["restore"]["mailbox"]);
	p2.ok(&["sync"]);
	println!("Q2's coins: {}", q2.ok(&["coins"]));
	println!("P2's coins: {}", p2.ok(&["coins"]));
	assert_eq!(held(&q2, &x, "lock_in"), 200_000, "Q2 holds both locks apart");
	assert_eq!(held(&q2, &x, "live"), 0, "and nothing of them spendable");
	assert_eq!(held(&p2, &x, "lock_out"), 200_000, "P2 holds both locks as its own to refund");
	assert_eq!(held(&p2, &x, "live"), p_live, "and its change as before");
	assert_eq!(lock(&q2, &h1)["state"], "held", "{}", lock(&q2, &h1));
	assert_eq!(lock(&p2, &h2)["state"], "locked", "{}", lock(&p2, &h2));

	// Q2 learns the first preimage: it claims at once.
	let c = q2.ok(&["lock", "preimage", &h1, &hex(&pre1)]);
	assert_eq!(c["state"], "claimed", "{}", c);
	let q_live = held(&q2, &x, "live");
	assert!(q_live > 119_000 && q_live < 120_000, "Q2 holds the first lock less its claim's margins: {}", q_live);
	p2.ok(&["sync"]);
	assert_eq!(lock(&p2, &h1)["state"], "claimed", "P2 learns its first lock was claimed: {}", lock(&p2, &h1));

	// The second comes back to P2 from its timeout.
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, t2 - common::node::median_time(&r.rt) + 1));
	r.bury().await;
	r.synced().await;
	p2.ok(&["sync"]);
	assert_eq!(lock(&p2, &h2)["state"], "refunded", "{}", lock(&p2, &h2));
	let back = held(&p2, &x, "live") - p_live;
	assert!(back > 79_000 && back < 80_000, "P2 has its second lock back less the refund's margins: {}", back);
	q2.ok(&["sync"]);
	assert_eq!(lock(&q2, &h2)["state"], "refunded", "{}", lock(&q2, &h2));
	assert_eq!(held(&q2, &x, "lock_in"), 0);
	println!("after the restore: Q2 claimed {} of 120000, P2 refunded {} of 80000", q_live, back);
}
