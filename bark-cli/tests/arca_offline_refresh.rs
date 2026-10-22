//! Offline refresh, run with the `arca` binary against a whole Arca server
//! on an anchored proof-of-stake regtest chain: a holder pre-signs a plan of
//! two steps (`arca plan`) and closes its wallet across two expiries.
//!
//! 1. The operator applies both steps, each in the coin's free window, and
//!    releases and sweeps each old batch after it; the holder comes back to
//!    its value live in the second step's leaf, the coins it gave up spent.
//!    A coin a plan names is paid out of round by no wallet.
//! 2. The operator stops after step 1 and comes back after the coin of step
//!    1 is past its exit deadline: the batch holding it was never released,
//!    step 2 runs late, and a wallet restored from the mnemonic alone after
//!    the absence holds the second step's leaf.
//! 3. The operator stops for good after step 1: nothing is swept, and the
//!    holder, back, takes home the coin it knows (the one the plan started
//!    from) and holds its whole value on the chain.
//! 4. A plan whose step can never run is stopped (the server's own case, a
//!    step's round replaced, is in `server/tests/plans.rs`): the coin the plan
//!    started from is held unreleased past its expiry; the holder, back,
//!    takes that coin home, the plan kept stopped until the coin is home,
//!    then cancelled.
//! 5. An operator that co-signs nothing (its signer stopped) but builds its
//!    rounds: the steps run; the holder, back, cannot witness the signer's
//!    record, so it takes no coin from the operator, and takes home the coin
//!    the plan started from, which the operator cannot answer.
//! 6. A step the holder took up whose round an anchor-driven reorganisation
//!    removes for good (the parent block orphaned, a transaction of the
//!    operator's taking the round's input, final): by its own node the
//!    wallet finds the step did not happen, holds the coin it gave up again,
//!    the step's leaf lost, cancels the stopped plan, and refreshes the coin
//!    in a round, its whole value live.
//! 7. The same, and then the parent chain brings the round back, final: the
//!    wallet holds the step's leaf again and the coin it gave up spent again,
//!    its value counted once.
//!
//! The last test: a wallet that plans every coin it holds is refused a
//! payment its unplanned coins cannot cover, gives one planned coin up in the
//! next round (`arca plan-release`), pays from the new leaf out of round, and
//! keeps the other coin planned.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::Script;
use serde_json::{json, Value};

use arca_covenant::LeafRecord;
use common::cli::Arca;
use common::running::Running;
use server::store::RoundState;

const HOUR: u32 = 3_600;
const DAY: u32 = 86_400;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn atoms(v: &Value) -> u64 {
	v.as_str().map(|s| s.parse().unwrap()).or_else(|| v.as_u64()).unwrap()
}

fn mtp(r: &Running) -> u32 {
	common::node::median_time(&r.rt)
}

/// Moves the median time to `t` at least.
async fn advance_to(r: &Running, t: u32) {
	let now = mtp(r);
	if t > now {
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, t - now));
	}
	r.synced().await;
}

/// Moves the median time to `t` at least, the server stopped.
fn advance_stopped(r: &Running, t: u32) {
	let now = mtp(r);
	if t > now {
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, t - now));
	}
}

/// The coins of `w` in `state`.
fn coins(w: &Arca, state: &str) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == state).cloned().collect()
}

/// A holder with one live coin of a round in X: its wallet, the coin and
/// its value. A board is refused as a plan's coin; it is refreshed in a round
/// first.
async fn holder(r: &mut Running, name: &str) -> (Arca, String, u64, u32) {
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let w = Arca::new(name);
	w.ok(&["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	r.pay_to(script(&w.ok(&["address"])), r.x, 3_000_000);
	r.produce().await;
	w.ok(&["board", &x, "2000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || w.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	w.ok(&["sync"]);
	w.refused(&["plan"], "refresh a board or a received coin in a round first");
	w.ok(&["participate"]);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	let s = w.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s);
	let live = coins(&w, "live");
	assert_eq!(live.len(), 1);
	let c = &live[0];
	let expiry = c["exit_by"].as_u64().unwrap() as u32 + 3 * DAY;
	(w, c["leaf_id"].as_str().unwrap().to_string(), atoms(&c["value"]), expiry)
}

/// The holder's plan of two steps, made and checked: its id, the date it
/// covers the coin until and the date the wallet must sync by.
fn plan(w: &Arca, coin: &str, value: u64, expiry: u32) -> (String, u32, u32) {
	let q = w.ok(&["plan", "--quote"]);
	let q = &q["plans"][0];
	assert_eq!((q["coin"].as_str(), q["fee"].as_str(), q["steps"].as_u64()), (Some(coin), Some("0"), Some(2)), "{}", q);
	let p = w.ok(&["plan"]);
	let p = &p["plans"][0];
	assert_eq!(p["state"], "open", "{}", p);
	let (covered, by) = (p["covered_until"].as_u64().unwrap() as u32, p["sync_by"].as_u64().unwrap() as u32);
	assert!(by > expiry, "the plan carries the wallet past the coin's expiry: sync by {} against expiry {}", by, expiry);
	let sched = w.ok(&["schedule"]);
	assert_eq!(sched["next_sync_at"].as_u64(), Some(by as u64), "the schedule wakes the wallet at the plan's date: {}", sched);
	assert_eq!(sched["plans"][0]["plan_id"], p["plan_id"]);
	let _ = value;
	(p["plan_id"].as_str().unwrap().to_string(), covered, by)
}

/// Runs the round a plan's step joins, follows it to final, and passes over
/// the rounds once more, which completes the step.
async fn step_round(r: &mut Running) -> elements::Txid {
	// The step waits while the operator's wallet cannot fund its round: it
	// spends only coins whose transactions are final, and its coins can all
	// be in transactions not final yet (the watcher's release of an expired
	// batch, published after the clock jumped). The chain goes on, as a live
	// one does, until the round is built.
	let mut built = None;
	for _ in 0..10 {
		r.synced().await;
		built = r.server.rounds.run_round().await.unwrap();
		if built.is_some() {
			break;
		}
		r.bury().await;
		tokio::time::sleep(std::time::Duration::from_millis(200)).await;
	}
	let Some(built) = built else {
		let mut seen = vec![];
		for id in r.server.store.unfinished_plans().await.unwrap() {
			let p = r.server.store.plan(&id).await.unwrap().unwrap();
			let mut steps = vec![];
			for st in &p.steps {
				let part = match st.participation {
					Some(pid) => r.server.store.participation(&pid).await.unwrap()
						.map(|x| format!("{:?} round {:?} attempt {} void {:?} waiting {:?}", x.state, x.round_id, x.attempt, x.void_reason, x.waiting)),
					None => None,
				};
				steps.push(format!("step {} {:?} {:?} participation {:?}", st.step.idx, st.state, st.reason, part));
			}
			let coin = p.current_coin().map(|c| hex(&c));
			seen.push(format!("plan {} {:?} {:?} current {:?} [{}]", hex(&id), p.state, p.reason, coin, steps.join("; ")));
		}
		panic!("no round for the step at median time {}: {}", mtp(r), seen.join(" | "));
	};
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	r.server.rounds.pass().await.unwrap();
	built.tx.txid()
}

/// The plan as the server holds it.
async fn plan_row(r: &Running, id: &str) -> server::store::PlanRow {
	r.server.store.plan(&unhex(id).try_into().unwrap()).await.unwrap().unwrap()
}

/// The first expiry of the leaf step `idx` made.
async fn step_expiry(r: &Running, id: &str, idx: usize) -> u32 {
	let p = plan_row(r, id).await;
	let leaf = p.steps[idx - 1].leaf_id.expect("the step made a leaf");
	let b = r.server.store.batch_leaf(&leaf).await.unwrap().unwrap();
	LeafRecord::from_bytes(&b.record).unwrap().schedule.expiries()[0].to_consensus_u32()
}

/// The token of the batch holding the leaf whose id is `leaf`.
async fn token_of(r: &Running, leaf: &[u8; 32]) -> Vec<u8> {
	let b = r.server.store.batch_leaf(leaf).await.unwrap().unwrap();
	LeafRecord::from_bytes(&b.record).unwrap().schedule.token.into_inner().to_byte_array().to_vec()
}

fn has(log: &[server::store::WatcherTxRow], kind: &str, subject: &[u8]) -> bool {
	log.iter().any(|w| w.kind == kind && w.subject == subject)
}

/// Runs the watcher and a block, up to `blocks` times, until it has
/// published a `kind` for `subject`.
async fn drive(r: &Running, what: &str, blocks: usize, kind: &str, subject: &[u8]) {
	for _ in 0..blocks {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		if has(&r.server.store.watcher_log().await.unwrap(), kind, subject) {
			println!("{}: done", what);
			r.produce().await;
			return;
		}
		r.produce().await;
	}
	panic!("{}: not done after {} blocks", what, blocks);
}

/// The old batch of `leaf` released at its expiry and, after the notice,
/// swept.
async fn released_and_swept(r: &Running, leaf: &[u8; 32], expiry: u32) {
	let token = token_of(r, leaf).await;
	advance_to(r, expiry + HOUR).await;
	drive(r, "the release at the old batch's expiry", 6, "release", &token).await;
	r.bury().await;
	advance_to(r, mtp(r) + 37 * HOUR).await;
	drive(r, "the sweep after the notice", 6, "sweep", &token).await;
	r.bury().await;
}

/// A parent block of its own, and the Sequentia tip anchored to it: what is
/// mined next is anchored there, so orphaning it takes that out. Returns its
/// height.
async fn own_anchor(r: &Running) -> u64 {
	tokio::task::block_in_place(|| {
		r.rt.mine_parent(1).unwrap();
		r.rt.anchor_to_parent_tip().unwrap();
	});
	r.rt.parent.client().block_count().unwrap()
}

/// A transaction of the operator's that takes the first input of `round`
/// and pays it back to the operator's `back`, less a fee, signed: while it
/// stands, `round` can never return.
fn taking(r: &Running, round: &elements::Transaction, back: Script) -> elements::Transaction {
	use elements::hashes::Hash;
	let op = round.input[0].previous_output;
	let prev = r.rt.client().raw_transaction(&op.txid).unwrap().output[op.vout as usize].clone();
	let (a, v) = (prev.asset.explicit().unwrap(), prev.value.explicit().unwrap());
	let mut tx = elements::Transaction { version: 2, lock_time: elements::LockTime::ZERO,
		input: vec![elements::TxIn { previous_output: op, ..Default::default() }],
		output: vec![sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(a, v - 5_000), back),
			sequentia_ext::fee_txout(sequentia_ext::AssetAmount::new(a, 5_000))] };
	let signed = (0..2u8).flat_map(|chain| (0..64u32).map(move |index| (chain, index))).any(|(chain, index)| {
		let coin = server::store::WalletCoin {
			txid: op.txid.to_byte_array(), vout: op.vout, asset: a.into_inner().to_byte_array(), value: v,
			script_pubkey: prev.script_pubkey.to_bytes(), chain, index, in_chain: true, spent_by: None,
		};
		r.server.wallet.sign_input(&mut tx, 0, &coin).is_ok()
	});
	assert!(signed, "the round's first input is the operator's");
	tx
}

/// The tip's block time.
fn tip_time(r: &Running) -> u64 {
	let h = r.rt.client().best_block_hash().unwrap();
	let hdr: Value = r.rt.client().call("getblockheader", &[json!(h.to_string())]).unwrap();
	hdr["time"].as_u64().unwrap()
}

/// The node restarted at the chain's time (its clock
/// runs weeks ahead of this machine's), the mempool forgotten.
fn restart_node_at_chain_time(r: &mut Running) {
	let mock = format!("-mocktime={}", tip_time(r) + 60);
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0", &mock])).unwrap();
}

/// Step 1's round `round` of plan `id`, alone in the parent block at
/// height `p_r`, lost: that block orphaned, and a transaction of the
/// operator's taking the round's first input confirmed in its place, final,
/// under a parent block of its own. The plan stopped at the server. Returns
/// the round and that parent block's height.
async fn lose_step_round(r: &mut Running, p_r: u64, round: &elements::Txid, id: &str) -> (elements::Transaction, u64) {
	let rtx = r.rt.client().raw_transaction(round).unwrap();
	let back = r.server.wallet.receive_script().await.unwrap();
	r.server.stop();
	tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_r)).unwrap();
	restart_node_at_chain_time(r);
	let p_x = own_anchor(r).await;
	let xtx = taking(r, &rtx, back);
	r.rt.client().send_raw_transaction(&xtx).unwrap();
	r.produce().await;
	r.bury().await;
	r.restart_server().await;
	r.synced().await;
	r.round_state(round, RoundState::Lost).await;
	for _ in 0..50 {
		if plan_row(r, id).await.state == server::store::PlanState::Stopped {
			break;
		}
		r.server.rounds.pass().await.unwrap();
		tokio::time::sleep(std::time::Duration::from_millis(200)).await;
	}
	assert_eq!(plan_row(r, id).await.state, server::store::PlanState::Stopped);
	(rtx, p_x)
}

fn leaf_id(s: &str) -> [u8; 32] {
	unhex(s).try_into().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_closed_across_two_expiries_comes_back_to_its_value_live_in_new_leaves() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (a, coin, value, e0) = holder(&mut r, "A").await;
	let (id, covered, by) = plan(&a, &coin, value, e0);
	println!("A's plan {}: coin {} of {} (expiry {}), covered until {}, sync by {}", id, coin, value, e0, covered, by);
	// A coin a plan names is paid out of round by no wallet.
	let b = Arca::new("B");
	let (url, node) = (r.url(), r.node_url());
	b.ok(&["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	let req = b.ok(&["receive", "--asset", &x, "--amount", "100000"]);
	a.refused(&["send", req["request"].as_str().unwrap()], "live coins");

	// A closes its wallet. Step 1 runs in the coin's free window.
	advance_to(&r, e0 - 5 * DAY + HOUR).await;
	let round1 = step_round(&mut r).await;
	println!("step 1 in round {}", round1);
	assert_eq!(plan_row(&r, &id).await.steps[0].state, server::store::StepState::Done);
	// The coin's old batch, released and swept: the operator takes back what
	// it funded, the plan's step having made A's new leaf.
	released_and_swept(&r, &leaf_id(&coin), e0).await;
	// Step 2 in the free window of step 1's leaf; its old batch swept too.
	let e1 = step_expiry(&r, &id, 1).await;
	advance_to(&r, e1 - 5 * DAY + HOUR).await;
	let round2 = step_round(&mut r).await;
	println!("step 2 in round {}", round2);
	let l1 = plan_row(&r, &id).await.steps[0].leaf_id.unwrap();
	released_and_swept(&r, &l1, e1).await;
	let e2 = step_expiry(&r, &id, 2).await;
	assert!(mtp(&r) > e1 && e2 > mtp(&r) + 3 * DAY, "A was away past two expiries ({} and {}) and its last coin lives to {}", e0, e1, e2);
	assert!(e2 >= by + 5 * DAY && covered < e2, "the plan covered A at least until the date it named: {} against {}", e2, covered);

	// A comes back: its value live in step 2's leaf, the coins given up spent.
	let s = a.ok(&["sync"]);
	let taken = &s["plans"][0]["taken_up"];
	assert_eq!(taken.as_array().map(|t| t.len()), Some(2), "{}", s);
	let live = coins(&a, "live");
	assert_eq!(live.len(), 1, "{:?}", live);
	assert_eq!((live[0]["leaf_id"].as_str(), atoms(&live[0]["value"])), (taken[1]["leaf_id"].as_str(), value));
	let spent: Vec<String> = coins(&a, "spent").iter().map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
	assert!(spent.contains(&coin) && spent.contains(&taken[0]["leaf_id"].as_str().unwrap().to_string()), "{:?}", spent);
	let plans = a.ok(&["plans"]);
	assert_eq!(plans["plans"][0]["state"], "done");
	let bal = a.ok(&["balance"]);
	println!("A back at {}: {}", mtp(&r), bal);
	assert_eq!(bal["arca"][&x]["live"], json!(value.to_string()), "A's whole value live");
	// The leaf step 2 made is paid out of round by no wallet either: it is
	// refreshed in a round first.
	let req = b.ok(&["receive", "--asset", &x, "--amount", "100000"]);
	a.refused(&["send", req["request"].as_str().unwrap()], "live coins");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_operator_stopped_after_step_one_runs_step_two_late_and_a_restore_finds_the_leaf() {
	let mut r = Running::start().await;
	let (a, coin, value, e0) = holder(&mut r, "S").await;
	let (id, _, _) = plan(&a, &coin, value, e0);
	advance_to(&r, e0 - 5 * DAY + HOUR).await;
	step_round(&mut r).await;
	let e1 = step_expiry(&r, &id, 1).await;
	let l1 = plan_row(&r, &id).await.steps[0].leaf_id.unwrap();
	released_and_swept(&r, &leaf_id(&coin), e0).await;
	// The operator stops, and comes back after step 1's leaf is past its exit
	// deadline: its batch was never released, and the batch guard holds it
	// now that the plan's current coin is in it.
	r.server.stop();
	advance_stopped(&r, e1 - 2 * DAY);
	r.restart_server().await;
	r.synced().await;
	let token = token_of(&r, &l1).await;
	advance_to(&r, e1 + HOUR).await;
	for _ in 0..3 {
		r.server.watcher.pass().await.unwrap();
		r.produce().await;
	}
	assert!(!has(&r.server.store.watcher_log().await.unwrap(), "release", &token), "the batch of the plan's current coin is held");
	println!("past step 1's leaf's expiry {}, its batch unreleased", e1);
	let round2 = step_round(&mut r).await;
	println!("step 2 late, in round {}", round2);
	assert_eq!(plan_row(&r, &id).await.state, server::store::PlanState::Done);
	drive(&r, "the release once step 2 is done", 6, "release", &token).await;

	// The holder's device is lost: a wallet from the mnemonic alone finds
	// the plan and holds step 2's leaf.
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap();
	let a2 = Arca::new("S2");
	let (url, node) = (r.url(), r.node_url());
	let made = a2.ok(&["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1",
		"--min-exit-delay-units", "1", "--mnemonic", mnemonic.trim()]);
	println!("the restore: plans {} | sync plans {}", made["restore"]["plans"], made["restore"]["sync"]["plans"]);
	assert_eq!(made["restore"]["plans"][0]["plan_id"], json!(id));
	let live = coins(&a2, "live");
	let p = plan_row(&r, &id).await;
	let l2 = p.steps[1].leaf_id.unwrap().iter().map(|b| format!("{:02x}", b)).collect::<String>();
	assert_eq!(live.len(), 1, "{:?}", live);
	assert_eq!((live[0]["leaf_id"].as_str(), atoms(&live[0]["value"])), (Some(l2.as_str()), value), "the restored wallet holds step 2's leaf");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_operator_stopped_for_good_after_step_one_leaves_the_holder_its_coin_home() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (a, coin, value, e0) = holder(&mut r, "G").await;
	let (_id, _, _) = plan(&a, &coin, value, e0);
	advance_to(&r, e0 - 5 * DAY + HOUR).await;
	step_round(&mut r).await;
	// The operator stops for good, before the old batch's expiry: nothing is
	// released or swept again. A, back after its coin's expiry, cannot reach
	// it; the coin it knows is past its exit date, and goes home.
	r.server.stop();
	advance_stopped(&r, e0 + 2 * DAY);
	let before = a.ok(&["balance"])["sequentia_onchain"][&x].as_str().unwrap_or("0").parse::<u64>().unwrap();
	let mut claimed = None;
	for _ in 0..12 {
		let s = a.ok(&["sync"]);
		if let Some(c) = s["exits"].as_array().and_then(|e| e.iter().find(|e| e["state"] == "claimed")) {
			claimed = Some(c.clone());
			break;
		}
		r.produce().await;
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 600));
	}
	let c = claimed.expect("the coin the plan started from comes home");
	println!("home: {}", c);
	r.produce().await;
	let after = a.ok(&["balance"])["sequentia_onchain"][&x].as_str().unwrap_or("0").parse::<u64>().unwrap();
	assert!(after > before + value - 20_000, "A holds its coin's value on the chain, less its exit fees: {} -> {}", before, after);
	println!("on chain: {} -> {} of X (the coin held {})", before, after, value);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stopped_plan_holds_the_coin_unswept_and_the_holder_back_cancels_it_and_takes_the_coin_home() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (a, coin, value, e0) = holder(&mut r, "R").await;
	let (id, _, _) = plan(&a, &coin, value, e0);
	// Step 1 can never run (as when its round is lost for good: the server's
	// own case is in `server/tests/plans.rs`): the plan stops.
	assert!(r.server.store.void_step(&leaf_id(&id), 1, "its round is lost").await.unwrap());
	assert_eq!(plan_row(&r, &id).await.state, server::store::PlanState::Stopped);
	// The coin the plan started from is held past its expiry: its batch is
	// not released while the plan is stopped.
	let token = token_of(&r, &leaf_id(&coin)).await;
	advance_to(&r, e0 + HOUR).await;
	for _ in 0..3 {
		r.server.watcher.pass().await.unwrap();
		r.produce().await;
	}
	assert!(!has(&r.server.store.watcher_log().await.unwrap(), "release", &token), "the coin of a stopped plan is held unswept");
	// The holder, back past the coin's exit date: its sync takes the coin
	// home and keeps the plan stopped, so the operator holds the batch until
	// the coin is on the chain; once the coin is home, the wallet cancels it.
	let before = a.ok(&["balance"])["sequentia_onchain"][&x].as_str().unwrap_or("0").parse::<u64>().unwrap();
	let s = a.ok(&["sync"]);
	assert_eq!(s["plans"][0]["state"], "stopped", "{}", s);
	assert!(s["plans"][0]["note"].as_str().unwrap_or("").contains("until the coin is on the chain"), "{}", s);
	assert_eq!(plan_row(&r, &id).await.state, server::store::PlanState::Stopped, "not cancelled while the coin is on its way home");
	let mut claimed = s["exits"].as_array().is_some_and(|e| e.iter().any(|e| e["state"] == "claimed"));
	for _ in 0..12 {
		if claimed {
			break;
		}
		r.produce().await;
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 600));
		let s = a.ok(&["sync"]);
		claimed = s["exits"].as_array().is_some_and(|e| e.iter().any(|e| e["state"] == "claimed"));
	}
	assert!(claimed, "the coin comes home");
	r.produce().await;
	r.bury().await;
	let after = a.ok(&["balance"])["sequentia_onchain"][&x].as_str().unwrap_or("0").parse::<u64>().unwrap();
	assert!(after > before + value - 20_000, "{} -> {}", before, after);
	println!("a stopped plan: the holder took its coin home, {} -> {} of X", before, after);
	let mut cancelled = false;
	for _ in 0..6 {
		let s = a.ok(&["sync"]);
		if plan_row(&r, &id).await.state == server::store::PlanState::Cancelled {
			assert!(s["plans"][0]["note"].as_str().unwrap_or("").contains("cancelled it"), "{}", s);
			cancelled = true;
			break;
		}
		r.produce().await;
	}
	assert!(cancelled, "the wallet cancels the stopped plan once its coin is home: coin {}", a.ok(&["record", &coin]));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_operator_that_cosigns_nothing_leaves_the_holder_the_coin_it_knows_to_take_home() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (a, coin, value, e0) = holder(&mut r, "N").await;
	let (id, _, _) = plan(&a, &coin, value, e0);
	// The operator's signer stops: it co-signs nothing from here. Its server
	// still builds rounds, which need no co-signature.
	r.signer.halt();
	advance_to(&r, e0 - 5 * DAY + HOUR).await;
	step_round(&mut r).await;
	let e1 = step_expiry(&r, &id, 1).await;
	advance_to(&r, e1 - 5 * DAY + HOUR).await;
	step_round(&mut r).await;
	assert_eq!(plan_row(&r, &id).await.state, server::store::PlanState::Done);
	// Back: the wallet cannot witness the operator's signer's record (the
	// signer answers nothing), so it takes no coin from the operator, the
	// plan's leaves included (D54). The coin it knows, the one the plan
	// started from, is past its exit date: it goes home, and the operator,
	// which co-signs nothing, cannot answer it with the refund.
	let before = a.ok(&["balance"])["sequentia_onchain"][&x].as_str().unwrap_or("0").parse::<u64>().unwrap();
	let s = a.ok(&["sync"]);
	assert!(s["plans"].as_array().is_none_or(|p| p.iter().all(|p| p["taken_up"].as_array().is_none_or(|t| t.is_empty()))), "{}", s);
	let mut claimed = s["exits"].as_array().is_some_and(|e| e.iter().any(|e| e["state"] == "claimed"));
	for _ in 0..16 {
		if claimed {
			break;
		}
		r.produce().await;
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 600));
		let s = a.ok(&["sync"]);
		claimed = s["exits"].as_array().is_some_and(|e| e.iter().any(|e| e["state"] == "claimed"));
	}
	assert!(claimed, "the coin the plan started from comes home");
	r.produce().await;
	let after = a.ok(&["balance"])["sequentia_onchain"][&x].as_str().unwrap_or("0").parse::<u64>().unwrap();
	assert!(after > before + value - 20_000, "{} -> {}", before, after);
	assert!(!has(&r.server.store.watcher_log().await.unwrap(), "refund", &leaf_id(&coin)), "no refund without the operator's signature");
	println!("an operator that co-signs nothing: the holder took the coin the plan started from home, {} -> {} of X", before, after);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_step_taken_up_whose_round_an_anchor_reorg_removes_gives_the_holder_its_coin_back() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (a, coin, value, e0) = holder(&mut r, "H").await;
	let (id, _, _) = plan(&a, &coin, value, e0);
	// Step 1 runs in a round alone in a parent block of its own; the holder,
	// back early, takes its leaf up and holds it live.
	advance_to(&r, e0 - 5 * DAY + HOUR).await;
	let p_r = own_anchor(&r).await;
	let round1 = step_round(&mut r).await;
	let s = a.ok(&["sync"]);
	let l1 = s["plans"][0]["taken_up"][0]["leaf_id"].as_str().unwrap_or_else(|| panic!("step 1 taken up: {}", s)).to_string();
	let state = |l: &str| a.ok(&["record", l])["state"].as_str().unwrap_or("").to_string();
	assert_eq!((state(&coin), state(&l1)), ("spent".to_string(), "live".to_string()));
	// The parent chain orphans step 1's block; a transaction of the
	// operator's takes the round's input, final: the round can never return.
	lose_step_round(&mut r, p_r, &round1, &id).await;
	// The holder's sync: the step did not happen, by the wallet's own node.
	// The coin it gave up is live again, step 1's leaf lost; the plan, its
	// coin still refreshable, cancelled.
	let s = a.ok(&["sync"]);
	println!("H after step 1's round is lost: recheck {} plans {}", s["recheck"]["changes"], s["plans"]);
	assert!(s["recheck"]["changes"].as_array().unwrap().iter().any(|c| c["leaf_id"] == coin.as_str() && c["can_never_return"] == true),
		"{}", s["recheck"]);
	assert!(matches!(state(&coin).as_str(), "live" | "given"), "the coin is the wallet's again: {}", a.ok(&["record", &coin]));
	assert_eq!(state(&l1), "lost");
	assert_eq!(plan_row(&r, &id).await.state, server::store::PlanState::Cancelled, "{}", s["plans"]);
	let plans = a.ok(&["plans"]);
	assert_eq!(plans["plans"][0]["steps"][0]["lost"], true, "{}", plans);
	// The coin is refreshed in a round, free in its window: the holder's
	// whole value live in a new leaf.
	if state(&coin) == "live" {
		a.ok(&["participate", "--leaf", &coin]);
	}
	let built = r.server.rounds.run_round().await.unwrap().expect("the refresh's round");
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	let s = a.ok(&["sync"]);
	let new = s["participations"][0]["new_leaves"][0]["leaf_id"].as_str().unwrap_or_else(|| panic!("{}", s)).to_string();
	let live = coins(&a, "live");
	assert_eq!(live.len(), 1, "{:?}", live);
	assert_eq!((live[0]["leaf_id"].as_str(), atoms(&live[0]["value"])), (Some(new.as_str()), value));
	let bal = a.ok(&["balance"]);
	assert_eq!(bal["arca"][&x]["live"], json!(value.to_string()), "H's whole value live: {}", bal);
	println!("H refreshed the coin back into round {}: {} live", built.tx.txid(), value);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lost_step_round_that_returns_gives_the_holder_the_steps_leaf_and_spends_the_coin_again() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (a, coin, value, e0) = holder(&mut r, "J").await;
	let (id, _, _) = plan(&a, &coin, value, e0);
	advance_to(&r, e0 - 5 * DAY + HOUR).await;
	let p_r = own_anchor(&r).await;
	let round1 = step_round(&mut r).await;
	let s = a.ok(&["sync"]);
	let l1 = s["plans"][0]["taken_up"][0]["leaf_id"].as_str().unwrap_or_else(|| panic!("step 1 taken up: {}", s)).to_string();
	let state = |l: &str| a.ok(&["record", l])["state"].as_str().unwrap_or("").to_string();
	// Step 1's round lost: the wallet's re-check, which asks the operator
	// nothing, holds the coin again and the leaf lost.
	let (rtx, p_x) = lose_step_round(&mut r, p_r, &round1, &id).await;
	let c = a.ok(&["recheck"]);
	assert!(c["changes"].as_array().unwrap().iter().any(|c| c["leaf_id"] == coin.as_str() && c["can_never_return"] == true), "{}", c);
	assert_eq!((state(&coin), state(&l1)), ("live".to_string(), "lost".to_string()));
	// The parent chain takes the operator's transaction out, and the round
	// confirms again, final.
	r.server.stop();
	tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_x)).unwrap();
	restart_node_at_chain_time(&mut r);
	r.rt.client().send_raw_transaction(&rtx).unwrap();
	r.produce().await;
	r.bury().await;
	r.restart_server().await;
	r.synced().await;
	r.round_state(&round1, RoundState::Final).await;
	// The holder follows the round: step 1's leaf is its again, the coin it
	// gave up spent again, its value counted once.
	let c = a.ok(&["recheck"]);
	println!("J after step 1's round returned: recheck {}", c["changes"]);
	assert!(c["changes"].as_array().unwrap().iter().any(|c| c["leaf_id"] == coin.as_str() && c["returned"] == true), "{}", c);
	assert_eq!((state(&coin), state(&l1)), ("spent".to_string(), "live".to_string()));
	let plans = a.ok(&["plans"]);
	assert_eq!(plans["plans"][0]["steps"][0]["lost"], false, "{}", plans);
	let bal = a.ok(&["balance"]);
	assert_eq!(bal["arca"][&x]["live"], json!(value.to_string()), "J's value live once, in step 1's leaf: {}", bal);
	println!("J holds step 1's leaf {} again: {} live", l1, value);
}

/// 8. `arca care`, what a wallet runs by itself at a sync: a coin far from
///    its step window is left unplanned, so it stays free to pay out of
///    round; once its first step could run within ten days it is planned (two
///    steps, no fee in the free window); the wallet closes, step 1 runs, and
///    the wallet back holds its value live in step 1's leaf. That leaf, the
///    plan's coin, is refreshed by hand only once the plan is cancelled; the
///    holder takes it home instead, and the next `care` cancels the plan, its
///    coin having moved.
#[tokio::test(flavor = "multi_thread")]
async fn care_plans_a_coin_near_its_window_and_cancels_a_plan_whose_coin_moved() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (a, coin, value, e0) = holder(&mut r, "K").await;
	let c = a.ok(&["care"]);
	println!("care, the coin young: {}", c);
	assert_eq!(c["planned"].as_array().map(|p| p.len()), Some(0), "{}", c);
	assert_eq!(c["not_yet_planned"], json!(1), "{}", c);
	assert_eq!(a.ok(&["plans"])["plans"].as_array().map(|p| p.len()), Some(0));
	// No plan names the young coin, so it stays one a plan may start from.
	let quote = a.ok(&["plan", "--quote"]);
	assert_eq!(quote["plans"][0]["coin"].as_str(), Some(coin.as_str()));

	// Ten days before its step window opens, less an hour: still not planned.
	let window = e0 - 5 * DAY;
	advance_to(&r, window - 10 * DAY - HOUR).await;
	let c = a.ok(&["care"]);
	assert_eq!((c["planned"].as_array().map(|p| p.len()), &c["not_yet_planned"]), (Some(0), &json!(1)), "{}", c);
	// Within ten days of it: planned, two steps, no fee.
	advance_to(&r, window - 10 * DAY + HOUR).await;
	let c = a.ok(&["care"]);
	println!("care, the coin within reach: {}", c);
	let p = &c["planned"][0];
	assert_eq!((p["coin"].as_str(), p["steps"].as_u64(), p["fee"].as_str()), (Some(coin.as_str()), Some(2), Some("0")), "{}", c);
	let id = p["plan_id"].as_str().unwrap().to_string();
	// A second care plans nothing more.
	let c = a.ok(&["care"]);
	assert_eq!((c["planned"].as_array().map(|p| p.len()), &c["not_yet_planned"]), (Some(0), &json!(0)), "{}", c);

	// A closes its wallet; step 1 runs in the coin's free window, and the old
	// batch is released and swept.
	advance_to(&r, window + HOUR).await;
	let round1 = step_round(&mut r).await;
	println!("step 1 in round {}", round1);
	released_and_swept(&r, &leaf_id(&coin), e0).await;
	// A is back after the coin's expiry: its value live in step 1's leaf.
	assert!(mtp(&r) > e0);
	let s = a.ok(&["sync"]);
	let l1 = s["plans"][0]["taken_up"][0]["leaf_id"].as_str().unwrap_or_default().to_string();
	assert!(!l1.is_empty(), "{}", s);
	let bal = a.ok(&["balance"]);
	println!("A back at {}, past expiry {}: {}", mtp(&r), e0, bal);
	assert_eq!(bal["arca"][&x]["live"], json!(value.to_string()), "A's whole value live");

	// The holder takes step 1's leaf home: the coin moves on the
	// chain, and the next care, once it is home, cancels the plan whose step
	// 2 has nothing left to stand on.
	a.ok(&["exit", &l1]);
	let mut home = false;
	for _ in 0..40 {
		r.produce().await;
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 600));
		r.bury().await;
		a.ok(&["sync"]);
		if coins(&a, "exited").iter().any(|c| c["leaf_id"] == json!(l1)) {
			home = true;
			break;
		}
	}
	assert!(home, "step 1's leaf comes home: {:?}", a.ok(&["coins"]));
	let c = a.ok(&["care"]);
	println!("care, the planned coin moved: {}", c);
	assert_eq!((c["cancelled"][0]["plan_id"].as_str(), c["cancelled"][0]["state"].as_str()), (Some(id.as_str()), Some("cancelled")), "{}", c);
	assert_eq!(a.ok(&["plans"])["plans"][0]["state"], "cancelled");
	// Nothing more to plan: the wallet holds no live coin of a round.
	let c = a.ok(&["care"]);
	assert_eq!((c["cancelled"].as_array().map(|p| p.len()), c["planned"].as_array().map(|p| p.len())), (Some(0), Some(0)), "{}", c);
}

/// 9. `care` with a coin that is no leaf of a round (a board here; a coin
///    received or a claim taken up out of round is the same): left alone
///    while young; once within ten days of its step window, refreshed in a
///    round under the wallet's bound; the round's new leaf, near its window
///    as well, planned at the next `care`.
#[tokio::test(flavor = "multi_thread")]
async fn care_refreshes_a_coin_of_no_round_in_a_round_and_plans_the_new_leaf() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let w = Arca::new("Q");
	w.ok(&["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	r.pay_to(script(&w.ok(&["address"])), r.x, 3_000_000);
	r.produce().await;
	w.ok(&["board", &x, "2000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || w.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	w.ok(&["sync"]);
	let board = coins(&w, "live");
	assert_eq!(board.len(), 1);
	let e0 = board[0]["exit_by"].as_u64().unwrap() as u32 + 3 * DAY;
	let c = w.ok(&["care"]);
	assert_eq!((c["refreshing"].as_array().map(|p| p.len()), &c["not_yet_planned"]), (Some(0), &json!(1)), "{}", c);
	// Within ten days of its step window: refreshed in a round, not planned.
	advance_to(&r, e0 - 5 * DAY - 10 * DAY + HOUR).await;
	let c = w.ok(&["care"]);
	println!("care, the board within reach: {}", c);
	assert_eq!(c["planned"].as_array().map(|p| p.len()), Some(0), "{}", c);
	assert!(c["refreshing"][0]["participation"].is_string() && c["refreshing"][0]["error"].is_null(), "{}", c);
	let built = r.server.rounds.run_round().await.unwrap().expect("a round for the refresh");
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	w.ok(&["sync"]);
	let live = coins(&w, "live");
	assert_eq!(live.len(), 1, "{:?}", live);
	assert_ne!(live[0]["leaf_id"], board[0]["leaf_id"]);
	// The new leaf expires a whole horizon later: planned once it too is
	// within reach.
	let e1 = live[0]["exit_by"].as_u64().unwrap() as u32 + 3 * DAY;
	let c = w.ok(&["care"]);
	assert_eq!((c["planned"].as_array().map(|p| p.len()), &c["not_yet_planned"]), (Some(0), &json!(1)), "{}", c);
	advance_to(&r, e1 - 5 * DAY - 10 * DAY + HOUR).await;
	let c = w.ok(&["care"]);
	println!("care, the new leaf within reach: {}", c);
	assert_eq!((c["planned"][0]["coin"].as_str(), c["planned"][0]["fee"].as_str()), (live[0]["leaf_id"].as_str(), Some("0")), "{}", c);
}

/// 10. A wallet back after its planned coin's exit date, before the operator
///     has released or swept that coin's old batch, whose first command is
///     not `sync` (a page reading its balance on opening): the start's
///     re-check leaves the coin to the plan, and the next `sync` takes the
///     step's leaf up, the whole value live there; nothing goes on the chain.
#[tokio::test(flavor = "multi_thread")]
async fn back_past_the_exit_date_before_the_sweep_the_wallet_takes_the_step_up_rather_than_home() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (a, coin, value, e0) = holder(&mut r, "V").await;
	let (id, _, _) = plan(&a, &coin, value, e0);
	advance_to(&r, e0 - 5 * DAY + HOUR).await;
	let round1 = step_round(&mut r).await;
	println!("step 1 in round {}", round1);
	// Back a day past the coin's expiry; the watcher has not run.
	advance_to(&r, e0 + DAY).await;
	let b = a.ok(&["balance"]);
	println!("A's first command back, balance: {}", b);
	let c = coins(&a, "exiting");
	assert!(c.is_empty(), "the start's re-check took the planned coin home: {:?}", c);
	let s = a.ok(&["sync"]);
	println!("A's sync: plans {} exits {}", s["plans"], s["exits"]);
	assert_eq!(s["plans"][0]["taken_up"].as_array().map(|t| t.len()), Some(1), "{}", s);
	let live = coins(&a, "live");
	assert_eq!((live.len(), atoms(&live[0]["value"])), (1, value), "{:?}", live);
	assert!(coins(&a, "exiting").is_empty());
	assert_eq!(a.ok(&["plans"])["plans"][0]["plan_id"], json!(id));
	assert_eq!(a.ok(&["balance"])["arca"][&x]["live"], json!(value.to_string()));
}

/// A wallet plans every coin it holds; out of round it can pay with none of
/// them. It gives one up in the next round (`arca plan-release`): the plan
/// ends once that round is final and the forfeit handed over, and the new
/// leaf, named by no plan, pays a receiver out of round. The other coin stays
/// planned, its plan open.
#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_that_plans_every_coin_pays_one_through_the_next_round_and_keeps_the_rest_planned() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let w = Arca::new("PR");
	w.ok(&["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	r.pay_to(script(&w.ok(&["address"])), r.x, 3_000_000);
	r.pay_to(script(&w.ok(&["address"])), r.x, 3_000_000);
	r.produce().await;
	let b1 = w.ok(&["board", &x, "2000000"])["leaf_id"].as_str().unwrap().to_string();
	let b2 = w.ok(&["board", &x, "1500000"])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards to be credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
	w.ok(&["participate", "--leaf", &b1]);
	w.ok(&["participate", "--leaf", &b2]);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	w.ok(&["sync"]);
	let live = coins(&w, "live");
	assert_eq!(live.len(), 2, "two leaves of a round: {:?}", live);
	let (ca, cb) = (live[0]["leaf_id"].as_str().unwrap().to_string(), live[1]["leaf_id"].as_str().unwrap().to_string());

	// Every coin planned.
	let p = w.ok(&["plan"]);
	println!("PR plans every coin it holds: {}", p);
	let made = p["plans"].as_array().unwrap();
	assert_eq!(made.len(), 2);
	assert!(made.iter().all(|m| m["state"] == "open"), "{}", p);
	let plan_of = |c: &str| made.iter().find(|m| m["coin"] == json!(c)).unwrap()["plan_id"].as_str().unwrap().to_string();
	let (pa, pb) = (plan_of(&ca), plan_of(&cb));

	// A receiver; a payment no unplanned coin covers is refused, saying how
	// the planned coins are paid.
	let v = Arca::new("PRV");
	v.ok(&["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	let req = v.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let why = w.refused(&["send", &req, "--amount", "500000", "--asset", &x], "plan-release");
	println!("PR pays 500,000 with every coin planned: REFUSED: {}", why);

	// PR gives coin A up in the next round, for a leaf of its own.
	let rel = w.ok(&["plan-release", &ca]);
	println!("PR releases coin {} (plan {}): {}", ca, pa, rel);
	assert_eq!(rel["plans"][0]["plan_id"].as_str(), Some(pa.as_str()));
	assert_eq!(rel["participations"][0]["state"], "pending", "{}", rel);
	let built = r.server.rounds.run_round().await.unwrap().expect("the round of PR's participation");
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	let s = w.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s);
	r.server.rounds.pass().await.unwrap();
	w.ok(&["sync"]);
	let plans = w.ok(&["plans"]);
	let state_of = |id: &str| plans["plans"].as_array().unwrap().iter().find(|p| p["plan_id"] == json!(id)).unwrap().clone();
	println!("PR's plans after the round {}: A {} B {}", built.tx.txid(), state_of(&pa)["state"], state_of(&pb)["state"]);
	assert_eq!(state_of(&pa)["state"], "cancelled", "coin A's plan ended with its coin: {}", state_of(&pa));
	assert!(state_of(&pa)["reason"].as_str().unwrap_or_default().contains("released"), "{}", state_of(&pa));
	assert_eq!(state_of(&pb)["state"], "open", "coin B stays planned");
	let live: Vec<String> = coins(&w, "live").iter().map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
	assert!(live.contains(&cb) && !live.contains(&ca) && live.len() == 2, "B and A's new leaf: {:?}", live);

	// Out of round, from the new leaf: B is not touched.
	let sent = w.ok(&["send", &req, "--amount", "500000", "--asset", &x]);
	println!("PR pays 500,000 out of round: {}", sent);
	let inputs: Vec<String> = sent["inputs"].as_array().unwrap().iter().map(|i| i.as_str().unwrap().to_string()).collect();
	assert!(!inputs.contains(&cb) && !inputs.contains(&ca), "paid from the new leaf: {:?}", inputs);
	let got = v.ok(&["sync"]);
	println!("the receiver's sync: {}", got["mailbox"]);
	assert_eq!(v.ok(&["balance"])["arca"][&x]["operator-confirmed"], json!("500000"), "the receiver holds the payment, operator-confirmed");
	assert_eq!(w.ok(&["plans"])["plans"].as_array().unwrap().iter().find(|p| p["plan_id"] == json!(pb)).unwrap()["state"], "open");
	assert!(coins(&w, "live").iter().any(|c| c["leaf_id"] == json!(cb)), "B is still the wallet's, planned");
}
