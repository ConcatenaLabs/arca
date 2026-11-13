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

/// The payee refuses a lock that is not the one it asked, and the operator
/// refuses one that names a key twice; the payer locks only from a coin
/// whose lock can still be followed by its claim and its refund.
/// - A seller strips the payee's earliest timeout from the request and locks
///   below it: the payee holds the lock and never calls it held, so the
///   buyer never pays (`lock ready` refuses, naming the timeout).
/// - A seller locks less than asked: refused the same way, naming the value.
/// - A lock past the payee's instant limit is never held: a lock goes into
///   no round.
/// - A request whose payee key is the operator's: the operator refuses it
///   (`lock`), nothing is signed into a lock, and the payer's coins are live.
/// - A payer whose only coin that covers the lock is four reassignments
///   deep (the depth limit is five) cannot lock it, while it can still pay
///   it to another holder.
#[tokio::test(flavor = "multi_thread")]
async fn locks_that_break_the_purchase_rule_or_the_depth_limit_are_refused() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let p = Arca::new("lock refuse P");
	let q = Arca::new("lock refuse Q");
	let xa = r.x;
	boarded(&mut r, &p, xa, 3_000_000).await;
	q.ok(&create_args(&r.url(), &r.node_url()));
	let now = common::node::median_time(&r.rt);

	// --- A timeout below the payee's earliest ---
	let h1 = hex(&sha256::Hash::hash(&[0x41u8; 32]).to_byte_array());
	let min = (now + 40_000).to_string();
	let req = q.ok(&["lock", "request", "--asset", &x, "--amount", "60000", "--hash", &h1, "--min-timeout", &min]);
	let why = p.refused(&["lock", "to", &req.to_string(), "--timeout-in", "20000"], "before the payee's earliest");
	println!("an honest payer: {}", why);
	let mut stripped = req.clone();
	stripped.as_object_mut().unwrap().remove("min_timeout");
	p.ok(&["lock", "to", &stripped.to_string(), "--timeout-in", "20000"]);
	q.ok(&["sync"]);
	assert_eq!(held(&q, &x, "lock_in"), 60_000, "the lock arrives and is held apart");
	let why = q.refused(&["lock", "ready", &h1], "before the earliest asked");
	println!("T too near: {}", why);

	// --- Less than asked ---
	let h2 = hex(&sha256::Hash::hash(&[0x42u8; 32]).to_byte_array());
	let req = q.ok(&["lock", "request", "--asset", &x, "--amount", "70000", "--hash", &h2]);
	let mut less = req.clone();
	less["value"] = json!("65000");
	p.ok(&["lock", "to", &less.to_string(), "--timeout-in", "20000"]);
	q.ok(&["sync"]);
	let why = q.refused(&["lock", "ready", &h2], "is not the one asked");
	println!("less than asked: {}", why);

	// --- Past the payee's instant limit ---
	// With no bond posted the limit taken is zero: a lock is never held, and
	// the buyer never pays for it.
	let h5 = hex(&sha256::Hash::hash(&[0x45u8; 32]).to_byte_array());
	let req = q.ok(&["lock", "request", "--asset", &x, "--amount", "50000", "--hash", &h5]);
	q.ok(&["instant-limit", "1000000000000"]);
	p.ok(&["lock", "to", &req.to_string(), "--timeout-in", "20000"]);
	q.ok(&["sync"]);
	let why = q.refused(&["lock", "ready", &h5], "past the wallet's instant limit");
	println!("past the instant limit: {}", why);
	q.ok(&["instant-limit", "off"]);

	// --- A key named twice ---
	let h3 = hex(&sha256::Hash::hash(&[0x43u8; 32]).to_byte_array());
	let req = q.ok(&["lock", "request", "--asset", &x, "--amount", "50000", "--hash", &h3]);
	let mut twice = req.clone();
	let operator = q.ok(&["info"])["operator"].as_str().map(String::from)
		.unwrap_or_else(|| p.ok(&["info"])["server"]["operator"].as_str().unwrap().to_string());
	twice["owner"] = json!(operator);
	let before = held(&p, &x, "live");
	let (ok, v) = p.run(&["lock", "to", &twice.to_string(), "--timeout-in", "20000"]);
	println!("payee key = operator key: ok={} {}", ok, v["error"]);
	assert!(!ok, "{}", v);
	assert_eq!(held(&p, &x, "live"), before, "nothing was locked");

	// --- The depth limit ---
	let depth = |w: &Arca| -> Vec<(u64, u64)> {
		w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == x.as_str())
			.map(|c| (c["hops"].as_u64().unwrap(), num(&c["value"]))).collect()
	};
	// P pays its largest coin around to itself until it is four
	// reassignments deep; each change it leaves is far smaller than the lock.
	for _ in 0..8 {
		let mut live = depth(&p);
		live.sort_by_key(|c| std::cmp::Reverse(c.1));
		if live[0].0 >= 4 {
			break;
		}
		let own = p.ok(&["receive", "--asset", &x])["request"].as_str().unwrap().to_string();
		p.ok(&["send", &own, "--amount", &(live[0].1 - 30_000).to_string()]);
		p.ok(&["sync"]);
	}
	println!("P's live coins (hops, value): {:?}", depth(&p));
	let h4 = hex(&sha256::Hash::hash(&[0x44u8; 32]).to_byte_array());
	let req = q.ok(&["lock", "request", "--asset", &x, "--amount", "200000", "--hash", &h4]);
	// Only the deep coin covers the lock: the changes together hold less.
	let deep = depth(&p).iter().filter(|(h, _)| *h + 2 <= 5).map(|(_, v)| v).sum::<u64>() < 200_000
		&& depth(&p).iter().any(|(h, v)| *h == 4 && *v > 200_000);
	if deep {
		let (ok, v) = p.run(&["lock", "to", &req.to_string(), "--timeout-in", "20000"]);
		println!("a lock from coins too deep: ok={} {}", ok, v["error"]);
		assert!(!ok, "a lock from a coin with no room for its ending: {}", v);
		assert!(v["error"]["message"].as_str().unwrap().contains("depth limit of 5"), "the refusal names the depth limit: {}", v);
		let other = q.ok(&["receive", "--asset", &x])["request"].as_str().unwrap().to_string();
		let sent = p.ok(&["send", &other, "--amount", "200000"]);
		println!("the same coins pay a plain payment: {}", sent["inputs"]);
	} else {
		println!("P holds a coin with room for a lock: the depth case did not form ({:?})", depth(&p));
		panic!("the test did not reach a coin too deep to lock");
	}
}

/// A watchtower's `serve` process, its wallet of its own, stopped when
/// dropped.
struct Tower {
	wallet: Arca,
	url: String,
	listen: String,
	child: Option<std::process::Child>,
}

impl Tower {
	fn new(name: &str, server: &str, node: &str) -> Tower {
		let wallet = Arca::new(name);
		wallet.ok(&create_args(server, node));
		let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
		let listen = format!("127.0.0.1:{}", port);
		let log = std::fs::File::create(wallet.dir.join("serve.log")).unwrap();
		let child = std::process::Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&wallet.dir)
			.args(["watchtower", "serve", "--listen", &listen, "--interval", "1"])
			.env("ARCA_NODE_PASSWORD", "arca").stdout(std::process::Stdio::null()).stderr(log).spawn().unwrap();
		let start = std::time::Instant::now();
		while std::net::TcpStream::connect(&listen).is_err() {
			assert!(start.elapsed() < std::time::Duration::from_secs(30), "watchtower {} did not start", name);
			std::thread::sleep(std::time::Duration::from_millis(100));
		}
		Tower { wallet, url: format!("http://{}", listen), listen, child: Some(child) }
	}

	/// The lock deposit the watchtower holds under `hash`.
	fn lock_deposit(&self, hash: &str) -> Value {
		self.wallet.ok(&["watchtower", "deposits"]).as_array().unwrap().iter().find(|d| d["lock"]["payment_hash"] == hash).cloned()
			.unwrap_or(Value::Null)
	}
}

impl Drop for Tower {
	fn drop(&mut self) {
		if let Some(mut c) = self.child.take() {
			let _ = c.kill();
			let _ = c.wait();
		}
		let _ = &self.listen;
	}
}

/// Both wallets are gone and the operator answers nothing; each side's
/// watchtower ends its lock on the chain by the ending its wallet signed
/// beforehand.
/// - Lock A: the payee's wallet learnt the preimage (its BTC payment
///   settled) and handed it to its watchtower and to the operator, which is
///   down then, before it went away. At the lock's home date the payee's
///   watchtower brings the leaf on the chain and claims it by CLAIM, the
///   preimage in its witness, to the payee's own address.
/// - Lock B, of another payer: never paid. The payee's watchtower, at its
///   home date, does nothing: neither its wallet nor the operator has the preimage. The
///   payer's watchtower, past the lock's timeout and its grace, brings the
///   leaf and refunds it by REFUND to the payer's own address.
#[tokio::test(flavor = "multi_thread")]
async fn each_sides_watchtower_ends_its_lock_with_the_wallets_gone_and_the_operator_down() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let p = Arca::new("lock tower P");
	let p1 = Arca::new("lock tower P1");
	let q = Arca::new("lock tower Q");
	let xa = r.x;
	boarded(&mut r, &p, xa, 3_000_000).await;
	boarded(&mut r, &p1, xa, 1_000_000).await;
	q.ok(&create_args(&r.url(), &r.node_url()));
	let (url, node) = (r.url(), r.node_url());
	let tq = Tower::new("lock tower TQ", &url, &node);
	let tp = Tower::new("lock tower TP", &url, &node);
	// Each watchtower holds a coin of its own for the fees its steps do not
	// pay from their reserves.
	for t in [&tq, &tp] {
		let s = script(&t.wallet.ok(&["address"]));
		r.pay_to(s, xa, 2_000_000);
	}
	r.produce().await;
	r.bury().await;
	q.ok(&["watchtowers", &tq.url]);
	p.ok(&["watchtowers", &tp.url]);

	let (pre_a, pre_b) = ([0x51u8; 32], [0x52u8; 32]);
	let ha = hex(&sha256::Hash::hash(&pre_a).to_byte_array());
	let hb = hex(&sha256::Hash::hash(&pre_b).to_byte_array());
	let req_a = q.ok(&["lock", "request", "--asset", &x, "--amount", "200000", "--hash", &ha]);
	let req_b = q.ok(&["lock", "request", "--asset", &x, "--amount", "150000", "--hash", &hb]);
	// A's payer is another wallet, with no watchtower: a watchtower that
	// brings a payer's coin on the chain brings every lock that shares its
	// reassignment with it, and A's leaf must come only when A's own
	// watchtower brings it, at A's home date.
	let lb = p.ok(&["lock", "to", &req_b.to_string(), "--timeout-in", "8000"]);
	let la = p1.ok(&["lock", "to", &req_a.to_string(), "--timeout-in", "30000"]);
	let (ta, tb) = (num(&la["timeout"]) as u32, num(&lb["timeout"]) as u32);
	let s = q.ok(&["sync"]);
	println!("Q's deposits: {}", s["deposits"]);
	assert_eq!(q.ok(&["lock", "ready", &ha])["ready"], true);
	let s = p.ok(&["sync"]);
	println!("P's deposits: {}", s["deposits"]);
	for (t, role, hs) in [(&tq, "payee", vec![&ha, &hb]), (&tp, "payer", vec![&hb])] {
		for h in hs {
			let d = t.lock_deposit(h);
			println!("{} holds: {}", t.wallet.name, d);
			assert_eq!(d["lock"]["role"], role, "{} holds the {}'s deposit of each lock: {}", t.wallet.name, role, d);
			assert_eq!(d["state"], "held");
		}
	}
	assert_eq!(tq.lock_deposit(&hb)["lock"]["preimage_known"], false);

	// The operator signs nothing more, and answers nothing.
	r.server.stop();
	// Q's BTC payment for lock A settled: its wallet keeps the preimage and
	// hands it on; the claim out of round cannot be made. Then Q is gone.
	let (ok, v) = q.run(&["lock", "preimage", &ha, &hex(&pre_a)]);
	println!("Q learns the preimage with the operator down: ok={} {}", ok, v);
	assert!(!ok, "the operator co-signs nothing: {}", v);
	assert_eq!(tq.lock_deposit(&ha)["lock"]["preimage_known"], true, "Q's watchtower has the preimage: {}", tq.lock_deposit(&ha));
	assert_eq!(tq.lock_deposit(&hb)["lock"]["preimage_known"], false);
	drop(q);
	drop(p);
	drop(p1);

	// Time passes; only the watchtowers act.
	let mut seen_nothing = None;
	let mut tq_brought = None;
	let start = std::time::Instant::now();
	loop {
		let (a_q, b_p, b_q) = (tq.lock_deposit(&ha), tp.lock_deposit(&hb), tq.lock_deposit(&hb));
		println!("median {} | TQ A: {} {} | TP B: {} {} | TQ B: {} {}", common::node::median_time(&r.rt), a_q["state"], a_q["note"],
			b_p["state"], b_p["note"], b_q["state"], b_q["note"]);
		if b_q["note"].as_str().is_some_and(|n| n.contains("neither its wallet nor the operator has the preimage")) {
			seen_nothing.get_or_insert(b_q.clone());
		}
		if a_q["state"] != "held" && tq_brought.is_none() {
			tq_brought = Some(common::node::median_time(&r.rt));
		}
		if a_q["state"] == "ended" && b_p["state"] == "ended" && seen_nothing.is_some() {
			break;
		}
		assert!(start.elapsed() < std::time::Duration::from_secs(900), "the watchtowers did not end both locks");
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 900));
		r.produce().await;
		r.bury().await;
		tokio::time::sleep(std::time::Duration::from_secs(3)).await;
	}
	let b_q = seen_nothing.unwrap();
	assert!(b_q["broadcast"].as_array().is_none_or(|b| b.is_empty()), "without the preimage the payee's watchtower broadcasts nothing: {}", b_q);

	// What each watchtower broadcast, and its ending in a block.
	let ending = |d: &Value| -> elements::Transaction {
		let e = d["broadcast"].as_array().unwrap().iter().find(|s| s["ending"].is_string()).unwrap_or_else(|| panic!("no ending: {}", d)).clone();
		let t = tx(&r, e["txid"].as_str().unwrap());
		let info: Value = r.rt.client().call("getrawtransaction", &[json!(t.txid().to_string()), json!(true)]).unwrap();
		assert!(info["confirmations"].as_u64().unwrap_or(0) >= 1, "the ending is in a block: {}", info["confirmations"]);
		t
	};
	let a_q = tq.lock_deposit(&ha);
	println!("TQ's steps for lock A: {}", a_q["broadcast"]);
	assert!(a_q["broadcast"].as_array().unwrap().len() >= 2, "Q's watchtower brought A's path itself, then claimed: {}", a_q);
	let brought_at = tq_brought.expect("Q's watchtower brought A's leaf");
	assert!(brought_at >= num(&a_q["lock"]["act_from"]) as u32, "at A's home date, not before: {} {}", brought_at, a_q["lock"]["act_from"]);
	let claim = ending(&a_q);
	let w = &claim.input[0].witness.script_witness;
	assert!(w.iter().any(|i| i[..] == pre_a[..]), "CLAIM carries the preimage the watchtower put in");
	let paid = claim.output[0].value.explicit().unwrap();
	assert!(paid < 200_000 && paid > 190_000, "the CLAIM pays the lock less its fee: {}", paid);
	println!("TQ's CLAIM {}: {} vB, pays {} of 200000 to {}", claim.txid(), claim.vsize(), paid, claim.output[0].script_pubkey);
	assert!(common::node::median_time(&r.rt) < ta + 600 || claim.lock_time.to_consensus_u32() == 0, "a CLAIM needs no lock time");

	let b_p = tp.lock_deposit(&hb);
	println!("TP's steps for lock B: {}", b_p["broadcast"]);
	let refund = ending(&b_p);
	assert_eq!(refund.lock_time.to_consensus_u32(), tb, "REFUND's lock time is the lock's timeout");
	assert!(!refund.input[0].witness.script_witness.iter().any(|i| i[..] == pre_b[..]));
	let back = refund.output[0].value.explicit().unwrap();
	assert!(back < 150_000 && back > 140_000, "the REFUND pays the lock less its fee: {}", back);
	println!("TP's REFUND {}: {} vB, lock time {}, pays {} of 150000", refund.txid(), refund.vsize(), tb, back);

}
