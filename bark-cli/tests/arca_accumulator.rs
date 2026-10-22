//! The wallet with leaves of an accumulator batch, run as a user runs it:
//! the `arca` binary against a whole Arca server whose operator expects 1 %
//! of a batch's leaves to leave on their own (`[batches]
//! accumulator_exit_rate_ppm = 10000`), its watcher on, on an anchored
//! proof-of-stake regtest chain.
//!
//! Six wallets board and refresh in one round, which pays one accumulator
//! batch of their six leaves. Each wallet rebuilds the published batch,
//! validates its leaf, signs its forfeit and its one exit authorisation, and
//! holds a coin of the batch. Then:
//!
//! 1. C pays D out of round from its leaf: D's coin rests on C's leaf of the
//!    batch, and resolves. A wallet restored from E's mnemonic alone finds
//!    E's leaf, rebuilt from the published batch.
//! 2. A takes its leaf out alone: the exit from the batch output, the entry,
//!    its claim after the delay. The exit and the entry are mined in a block
//!    anchored to a parent block that is then orphaned: both leave the chain
//!    with it, and A's exit goes on from where the chain holds them.
//! 3. The others' coins stay the wallets' own, and B's exit, by the
//!    authorisation it signed before A's, spends the batch output where A's
//!    exit left it. F refreshes its leaf in a round of its own: it gives the
//!    leaf up under a forfeit, and holds the new round's leaf.
//! 4. D takes its payment out: C's leaf leaves the batch where B's exit left
//!    it, then the payment's checkpoint and reassignment.
//! 5. E holds its leaf past its expiry and the notice, away: the operator's
//!    watcher sweeps the batch output where the last exit left it, and E's
//!    coin is shown lost, with the sweep that took it.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::str::FromStr;

use elements::{OutPoint, Script, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::CoinRecord;
use common::cli::Arca;
use common::running::Running;
use server::store::RoundState;

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

fn confirmations(r: &Running, txid: &str) -> i64 {
	let v: Value = r.rt.client().call("getrawtransaction", &[json!(txid), json!(true)]).unwrap_or(Value::Null);
	v["confirmations"].as_i64().unwrap_or(0)
}

/// The transaction spending `op`, in the mempool or the last 300 blocks.
fn spender_of(r: &Running, op: &OutPoint) -> Option<Transaction> {
	let spends = |t: &Transaction| t.input.iter().any(|i| i.previous_output == *op);
	let mempool: Vec<String> = r.rt.client().call("getrawmempool", &[]).unwrap();
	for id in mempool {
		let t = tx(r, &id);
		if spends(&t) {
			return Some(t);
		}
	}
	let tip = r.rt.client().blockchain_info().unwrap().blocks;
	for h in tip.saturating_sub(300)..=tip {
		let hash = r.rt.client().block_hash(h).unwrap();
		if let Some(t) = r.rt.client().block(&hash).unwrap().txdata.into_iter().find(|t| spends(t)) {
			return Some(t);
		}
	}
	None
}

/// A parent block of its own, and the Sequentia tip anchored to it: the
/// next block is anchored there. Its parent height.
async fn own_anchor(r: &Running) -> u64 {
	tokio::task::block_in_place(|| {
		r.rt.mine_parent(1).unwrap();
		r.rt.anchor_to_parent_tip().unwrap();
	});
	r.rt.parent.client().block_count().unwrap()
}

/// Moves the chain's median time on by `seconds`, and the server with it.
async fn later(r: &Running, seconds: u32) {
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, seconds));
	r.synced().await;
}

/// Runs `exit` on `w`'s `leaf` until its claim is broadcast, with a block
/// and the exit delay between runs; returns the claim's txid.
async fn claimed(r: &Running, w: &Arca, leaf: &str) -> String {
	for _ in 0..6 {
		let e = w.ok(&["exit", leaf]);
		if e["state"] == "claimed" {
			return e["claim"]["txid"].as_str().unwrap().to_string();
		}
		r.produce().await;
		later(r, 600).await;
	}
	panic!("{}'s exit of {} was not claimed: {}", w.name, leaf, w.ok(&["coins"]));
}

/// Mines and buries `w`'s claim, and syncs until its coin `leaf` is exited.
async fn exited(r: &Running, w: &Arca, leaf: &str) {
	for _ in 0..4 {
		r.produce().await;
		r.bury().await;
		r.synced().await;
		w.ok(&["sync"]);
		if coin_of(w, leaf)["state"] == "exited" {
			return;
		}
	}
	panic!("{}'s coin {} is not exited: {}", w.name, leaf, coin_of(w, leaf));
}

#[tokio::test(flavor = "multi_thread")]
async fn accumulator_leaves_are_held_paid_left_and_swept() {
	let mut r = Running::start_with(|c, _, _| {
		c.batches.accumulator_exit_rate_ppm = Some(10_000);
	}).await;
	let (url, node) = (r.url(), r.node_url());
	let x = r.x.to_string();
	let names = ["ACC-A", "ACC-B", "ACC-C", "ACC-D", "ACC-E", "ACC-F"];
	let ws: Vec<Arca> = names.iter().map(|n| Arca::new(n)).collect();
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
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
	r.wait("the server to credit every board", || {
		ws.iter().all(|w| w.ok(&["boards"])[0]["server"]["state"] == "credited")
	}).await;

	// One round, one accumulator batch of the five leaves.
	for w in &ws {
		w.ok(&["sync"]);
		assert_eq!(w.ok(&["participate"])["participations"][0]["state"], "pending");
	}
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let round = built.tx.clone();
	r.produce().await;
	r.bury().await;
	r.round_state(&round.txid(), RoundState::Final).await;
	let mut leaves = vec![];
	for w in &ws {
		let s = w.ok(&["sync"]);
		let p = &s["participations"][0];
		assert_eq!(p["state"], "released", "{}", s);
		let leaf = p["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
		let c = coin_of(w, &leaf);
		assert_eq!((c["state"].as_str(), c["kind"].as_str()), (Some("live"), Some("batch")), "{}", c);
		leaves.push(leaf);
	}
	let records: Vec<_> = ws.iter().zip(&leaves).map(|(w, l)| match record_of(w, l) {
		CoinRecord::Accumulator { record, auth, .. } => (record, auth),
		other => panic!("{}'s leaf is held as {:?}, not a leaf of an accumulator batch", w.name, other),
	}).collect();
	let slots: Vec<u16> = records.iter().map(|(r, _)| r.slot).collect();
	let batch = records[0].0.batch_output().unwrap();
	let vout = round.output.iter().position(|o| arca_covenant::ExplicitOutput::from_txout(o).as_ref() == Some(&batch))
		.expect("the round pays the batch output every record rebuilds") as u32;
	assert!(records.iter().all(|(rec, _)| rec.batch_output().unwrap() == batch), "one batch");
	println!("round {}: one accumulator batch at output {} holding {}, slots {:?}; every wallet holds its leaf with one exit \
		authorisation", round.txid(), vout, batch.value, slots);
	let (a, b, c, d, e, f) = (&ws[0], &ws[1], &ws[2], &ws[3], &ws[4], &ws[5]);
	let (la, lb, lc, le, lf) = (&leaves[0], &leaves[1], &leaves[2], &leaves[4], &leaves[5]);

	// 1. C pays D out of round from its leaf of the batch.
	let req = d.ok(&["receive"]);
	let sent = c.ok(&["send", req["request"].as_str().unwrap(), "--amount", "600000", "--asset", &x]);
	assert!(sent["change"].is_string(), "{}", sent);
	let mb = d.ok(&["mailbox"]);
	let got = &mb["accepted"][0];
	assert_eq!((got["value"].as_str(), got["state"].as_str()), (Some("600000"), Some("live")), "{}", mb);
	let ld = got["leaf_id"].as_str().unwrap().to_string();
	println!("D holds {} paid out of C's accumulator leaf", ld);
	let e2 = Arca::new("ACC-E2");
	let mnemonic = std::fs::read_to_string(e.dir.join("mnemonic")).unwrap();
	let mut args = create.to_vec();
	args.extend(["--mnemonic", mnemonic.trim()]);
	let restore = e2.ok(&args)["restore"].clone();
	assert!(restore["error"].is_null() && restore["not_recovered"] == json!([]), "{}", restore);
	assert_eq!(coin_of(&e2, le)["state"], "live", "{}", e2.ok(&["coins"]));
	assert!(matches!(record_of(&e2, le), CoinRecord::Accumulator { .. }));
	println!("E2, from E's mnemonic alone, holds E's accumulator leaf {}", le);
	let _ = std::fs::remove_dir_all(&e2.dir);

	// 2. A takes its leaf out: exit and entry mined in a block anchored to a
	// parent block that is then orphaned.
	let p = own_anchor(&r).await;
	let ea = a.ok(&["exit", la]);
	assert_eq!(ea["state"], "unrolling", "{}", ea);
	let steps = ea["broadcast"].as_array().unwrap();
	assert_eq!(steps.len(), 2, "the exit from the batch and the entry: {}", ea);
	let a_exit = steps[0]["txid"].as_str().unwrap().to_string();
	let a_entry = steps[1]["txid"].as_str().unwrap().to_string();
	let t = tx(&r, &a_exit);
	assert_eq!(t.input[0].previous_output, OutPoint::new(round.txid(), vout), "A's exit spends the round's batch output");
	println!("A's exit {} ({} vB), its entry {} ({} vB)", a_exit, steps[0]["vsize"], a_entry, steps[1]["vsize"]);
	r.produce().await;
	r.synced().await;
	assert!(confirmations(&r, &a_exit) >= 1 && confirmations(&r, &a_entry) >= 1);
	let gone = tokio::task::block_in_place(|| r.rt.orphan_parent_from(p)).unwrap();
	r.synced().await;
	assert!(confirmations(&r, &a_exit) < 1 && confirmations(&r, &a_entry) < 1, "the exit left the chain with its anchor");
	println!("parent blocks {:?} orphaned: A's exit and entry are out of the chain", gone);
	// Back to the mempool, and into the blocks anchored to the new branch:
	// A's exit goes on from where the chain holds them, building nothing
	// again.
	own_anchor(&r).await;
	let again = a.ok(&["exit", la]);
	assert!(again["state"] == "unrolling" || again["state"] == "waiting", "{}", again);
	assert!(again["broadcast"].as_array().is_none_or(|s| s.iter().all(|s| s["txid"] == a_exit.as_str() || s["txid"] == a_entry.as_str())),
		"A's exit goes on with the same transactions: {}", again);
	r.produce().await;
	r.synced().await;
	assert!(confirmations(&r, &a_exit) >= 1 && confirmations(&r, &a_entry) >= 1, "back in a block");
	println!("A's exit and entry back in blocks anchored to the new parent branch; A's exit run then: {}", again["state"]);
	let a_claim = claimed(&r, a, la).await;
	exited(&r, a, la).await;
	let paid = tx(&r, &a_claim);
	println!("A's claim {}: {} of X home", a_claim, paid.output[0].value.explicit().unwrap());

	// 3. The others' coins are still theirs; B's exit spends the batch output
	// where A's exit left it.
	for (w, l) in [(b, lb), (c, lc), (e, le), (f, lf)] {
		w.ok(&["sync"]);
		let s = coin_of(w, l)["state"].clone();
		assert!(s == "live" || (w.name == "ACC-C" && s == "spent"), "{}'s coin after A's exit: {}", w.name, coin_of(w, l));
	}
	let eb = b.ok(&["exit", lb]);
	let b_exit = eb["broadcast"][0]["txid"].as_str().unwrap().to_string();
	assert_eq!(tx(&r, &b_exit).input[0].previous_output, OutPoint::new(Txid::from_str(&a_exit).unwrap(), 1),
		"B's exit spends the rest A's exit left");
	println!("B's exit {} spends {}:1, by the authorisation B signed when it accepted its leaf", b_exit, a_exit);
	r.produce().await;
	claimed(&r, b, lb).await;
	exited(&r, b, lb).await;

	// F refreshes its leaf of the batch in a round of its own.
	assert_eq!(f.ok(&["participate"])["participations"][0]["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	let s = f.ok(&["sync"]);
	let p = &s["participations"][0];
	assert_eq!(p["state"], "released", "{}", s);
	let lf2 = p["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	assert_eq!(coin_of(f, lf)["state"], "spent", "F's leaf of the accumulator batch went into the refresh");
	assert_eq!(coin_of(f, &lf2)["state"], "live");
	assert!(matches!(record_of(f, &lf2), CoinRecord::Leaf { .. }), "a round of one leaf pays a tree");
	println!("F gave up its accumulator leaf under a forfeit, and holds {} of round {}", lf2, built.tx.txid());

	// 4. D takes its payment out: C's leaf leaves the batch first.
	let ed = d.ok(&["exit", &ld]);
	let d_steps = ed["broadcast"].as_array().unwrap().clone();
	println!("D's exit of its payment: {} transactions", d_steps.len());
	let c_exit = d_steps[0]["txid"].as_str().unwrap().to_string();
	assert_eq!(tx(&r, &c_exit).input[0].previous_output, OutPoint::new(Txid::from_str(&b_exit).unwrap(), 1),
		"C's leaf leaves the batch where B's exit left it");
	r.produce().await;
	claimed(&r, d, &ld).await;
	exited(&r, d, &ld).await;
	let last_rest = OutPoint::new(Txid::from_str(&c_exit).unwrap(), 1);

	// 5. E, away past its expiry and the notice: the sweep.
	let expiry = records[4].0.schedule.expiries()[0].to_consensus_u32();
	let notice = records[4].0.schedule.notice.seconds() as u32;
	let now = common::node::median_time(&r.rt);
	// The release at the expiry, then the notice from it.
	later(&r, (expiry + 600).saturating_sub(now)).await;
	for _ in 0..4 {
		if let Err(e) = r.server.watcher.pass().await {
			println!("watcher: {}", e);
		}
		r.produce().await;
		r.bury().await;
		r.synced().await;
	}
	assert!(spender_of(&r, &last_rest).is_none(), "no sweep during the notice");
	later(&r, notice + 600).await;
	for _ in 0..30 {
		if let Err(e) = r.server.watcher.pass().await {
			println!("watcher: {}", e);
		}
		r.produce().await;
		r.synced().await;
		if spender_of(&r, &last_rest).is_some() {
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;
	}
	let sweep = spender_of(&r, &last_rest).expect("the operator sweeps the batch output where the last exit left it");
	println!("the batch output {} swept by {}", last_rest, sweep.txid());
	r.produce().await;
	r.bury().await;
	r.synced().await;
	e.ok(&["sync"]);
	let ce = coin_of(e, le);
	assert_eq!(ce["state"], "lost", "{}", ce);
	assert!(ce["note"].as_str().unwrap().contains(&sweep.txid().to_string()), "{}", ce);
	println!("E's coin: lost | {}", ce["note"]);
	for w in &ws {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// An offline-refresh plan that starts from a leaf of an accumulator batch.
/// Five wallets refresh into one accumulator batch; P plans its leaf (two
/// steps) and closes its wallet. Step 1 runs in the leaf's free window,
/// giving it up under the plan's terms for a leaf of a new round; P, back,
/// takes that leaf up, and its accumulator leaf is spent.
#[tokio::test(flavor = "multi_thread")]
async fn a_plan_starts_from_an_accumulator_leaf() {
	const HOUR: u32 = 3_600;
	const DAY: u32 = 86_400;
	let mut r = Running::start_with(|c, _, _| {
		c.batches.accumulator_exit_rate_ppm = Some(10_000);
	}).await;
	let (url, node) = (r.url(), r.node_url());
	let x = r.x.to_string();
	let ws: Vec<Arca> = ["ACCP-P", "ACCP-1", "ACCP-2", "ACCP-3", "ACCP-4"].iter().map(|n| Arca::new(n)).collect();
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
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
	r.wait("the server to credit every board", || {
		ws.iter().all(|w| w.ok(&["boards"])[0]["server"]["state"] == "credited")
	}).await;
	for w in &ws {
		w.ok(&["sync"]);
		w.ok(&["participate"]);
	}
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	for w in &ws {
		assert_eq!(w.ok(&["sync"])["participations"][0]["state"], "released");
	}
	let p = &ws[0];
	let live: Vec<Value> = p.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live").cloned().collect();
	assert_eq!(live.len(), 1);
	let coin = live[0]["leaf_id"].as_str().unwrap().to_string();
	assert!(matches!(record_of(p, &coin), CoinRecord::Accumulator { .. }), "P holds a leaf of an accumulator batch");
	let e0 = live[0]["exit_by"].as_u64().unwrap() as u32 + 3 * DAY;

	// P's plan, from its accumulator leaf.
	let q = p.ok(&["plan", "--quote"]);
	assert_eq!((q["plans"][0]["coin"].as_str(), q["plans"][0]["steps"].as_u64()), (Some(coin.as_str()), Some(2)), "{}", q);
	let made = p.ok(&["plan"]);
	let plan = &made["plans"][0];
	assert_eq!(plan["state"], "open", "{}", made);
	let id = plan["plan_id"].as_str().unwrap().to_string();
	println!("P's plan {} from its accumulator leaf {}", id, coin);

	// P away; step 1 in the leaf's free window.
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, (e0 - 5 * DAY + HOUR).saturating_sub(now)));
	r.synced().await;
	let mut stepped = None;
	for _ in 0..10 {
		r.synced().await;
		stepped = r.server.rounds.run_round().await.unwrap();
		if stepped.is_some() {
			break;
		}
		r.bury().await;
		tokio::time::sleep(std::time::Duration::from_millis(200)).await;
	}
	let stepped = stepped.expect("a round for the plan's step");
	r.produce().await;
	r.bury().await;
	r.round_state(&stepped.tx.txid(), RoundState::Final).await;
	r.server.rounds.pass().await.unwrap();
	let row = r.server.store.plan(&unhex(&id).try_into().unwrap()).await.unwrap().unwrap();
	assert_eq!(row.steps[0].state, server::store::StepState::Done, "step 1 is done");
	println!("step 1 ran in round {}", stepped.tx.txid());

	// P back: the step's leaf taken up, its accumulator leaf spent.
	let s = p.ok(&["sync"]);
	let taken = &s["plans"][0]["taken_up"];
	assert_eq!(taken.as_array().map(|t| t.len()), Some(1), "{}", s);
	let new = taken[0]["leaf_id"].as_str().unwrap().to_string();
	assert_eq!(coin_of(p, &new)["state"], "live");
	assert_eq!(coin_of(p, &coin)["state"], "spent", "the accumulator leaf went into the step");
	println!("P took up {} from step 1; its accumulator leaf is spent", new);
	for w in &ws {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
