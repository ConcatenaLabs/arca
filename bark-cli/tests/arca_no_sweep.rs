//! The `arca` wallet against a whole Arca server that builds batches
//! without a sweep: every refresh round is held until each participation in
//! it has handed over its forfeits, and each wallet's `sync` validates its
//! new leaves against the transaction the status serves and signs before the
//! round is broadcast. A wallet that does not sync is left out: its
//! participation is voided past the window, its coin live again, and the
//! others' round is built again and completes. A pays C out of round, A, B
//! and C refresh and release, and the watcher reclaims the node by RECLAIM-D.
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

/// Every wallet of `ws` asks for its refresh; each round built is held until
/// every wallet has synced (handing its forfeits over before broadcast), then
/// goes out, is made final, and every wallet completes it.
async fn refresh_all(r: &Running, ws: &[&Arca]) {
	for w in ws {
		let p = w.ok(&["participate"]);
		assert!(p["participations"].as_array().unwrap().iter().all(|x| x["state"] == "pending"), "{}", p);
	}
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(!built.is_empty() && failed.is_empty(), "{} built, {} failed", built.len(), failed.len());
	for b in &built {
		assert!(b.broadcast.starts_with("held"), "{}", b.broadcast);
	}
	for (i, w) in ws.iter().enumerate() {
		let s = w.ok(&["sync"]);
		let ps = s["participations"].as_array().unwrap();
		println!("wallet {} before broadcast: {}", i, ps.iter().map(|p| format!("{} {}", p["state"], p["note"])).collect::<Vec<_>>().join("; "));
		assert!(ps.iter().all(|p| p["state"] == "forfeiting"), "{}", s);
	}
	r.server.rounds.pass().await.unwrap();
	for b in &built {
		let row = r.server.store.round_by_txid(&b.tx.txid().to_byte_array()).await.unwrap().unwrap();
		assert_eq!(row.state, RoundState::Broadcast, "broadcast once every wallet's forfeits are in");
	}
	r.produce().await;
	r.bury().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	for (i, w) in ws.iter().enumerate() {
		let s = w.ok(&["sync"]);
		let ps = s["participations"].as_array().unwrap();
		assert!(!ps.is_empty() && ps.iter().all(|p| p["state"] == "released"), "{}", s);
		for p in ps {
			println!("wallet {}: released {}", i, p["released"]);
		}
	}
}

/// The watcher's passes, a block between them. Its reclaims.
async fn reclaims(r: &Running) -> Vec<server::store::WatcherTxRow> {
	for _ in 0..4 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		let start = std::time::Instant::now();
		while !r.server.store.nursery_in(NurseryState::Pending).await.unwrap().iter().all(|n| n.broadcasts > 0) {
			assert!(start.elapsed() < Duration::from_secs(30));
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		r.produce().await;
	}
	r.bury().await;
	r.synced().await;
	r.server.nursery.pass().await.unwrap();
	r.server.store.watcher_log().await.unwrap().into_iter().filter(|w| w.kind == "reclaim").collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn wallets_sign_before_broadcast_and_a_silent_one_is_left_out() {
	let mut r = Running::start_with(|c, _, _| {
		c.batches.no_sweep = true;
		c.batches.delegated_reclaim = true;
		c.batches.holder_batches = Some(0);
	}).await;
	let x = r.x.to_string();
	let x_id = r.x;
	r.fund_server(x_id, 100_000_000).await;
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	let (a, b, c, d) = (Arca::new("A"), Arca::new("B"), Arca::new("C"), Arca::new("D"));
	for w in [&a, &b, &c, &d] {
		w.ok(&create);
	}
	for w in [&a, &b, &d] {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, x_id, 5_000_000);
	}
	r.produce().await;
	for w in [&a, &b, &d] {
		w.ok(&["board", &x, "2000000"]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards credited", || {
		[&a, &b, &d].iter().all(|w| w.ok(&["boards"])[0]["server"]["state"] == "credited")
	}).await;

	// D asks for its refresh and never syncs again: left out.
	for w in [&a, &b, &d] {
		let p = w.ok(&["participate"]);
		assert!(p["participations"].as_array().unwrap().iter().all(|x| x["state"] == "pending"), "{}", p);
	}
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	let dropped = built[0].tx.clone();
	println!("round {} built: {}", dropped.txid(), built[0].broadcast);
	for w in [&a, &b] {
		let s = w.ok(&["sync"]);
		assert!(s["participations"].as_array().unwrap().iter().all(|p| p["state"] == "forfeiting"), "{}", s);
	}
	let sch = a.ok(&["schedule"]);
	println!("A's schedule while its round waits: {}", sch["why"]);
	r.server.rounds.pass().await.unwrap();
	let pool: Vec<String> = r.rt.client().call("getrawmempool", &[]).unwrap();
	assert!(!pool.contains(&dropped.txid().to_string()), "held while D has handed over nothing");
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 700));
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	let row = r.server.store.round_by_txid(&dropped.txid().to_byte_array()).await.unwrap().unwrap();
	assert_eq!(row.state, RoundState::Lost, "the round is dropped unbroadcast");
	let sd = d.ok(&["sync"]);
	println!("D's sync after its round was dropped: {}", sd["participations"]);
	assert_eq!(sd["participations"][0]["state"], "void", "{}", sd);
	let bal = d.ok(&["balance"]);
	println!("D's balance: {}", bal["arca"]);
	// A and B run again once the spend that kills the dropped round is
	// final (it keeps their re-run apart from it), and complete.
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let (again, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(!again.is_empty(), "A's and B's round runs again: {:?}", failed.iter().map(|f| f.1.to_string()).collect::<Vec<_>>());
	assert_eq!(again[0].participations, 2);
	for w in [&a, &b] {
		let s = w.ok(&["sync"]);
		assert!(s["participations"].as_array().unwrap().iter().all(|p| p["state"] == "forfeiting"), "{}", s);
	}
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&again[0].tx.txid(), RoundState::Final).await;
	for w in [&a, &b] {
		let s = w.ok(&["sync"]);
		assert!(s["participations"].as_array().unwrap().iter().all(|p| p["state"] == "released"), "{}", s);
	}
	println!("A and B completed round {}, which never waited for D", again[0].tx.txid());

	// A pays C out of round; C takes it from its mailbox.
	let req = c.ok(&["receive"]);
	let sent = a.ok(&["send", req["request"].as_str().unwrap(), "--amount", "600000", "--asset", &x]);
	assert!(sent["change"].is_string(), "{}", sent);
	let mb = c.ok(&["mailbox"]);
	assert_eq!(mb["accepted"].as_array().unwrap().len(), 1, "{}", mb);

	// A (its change), B and C refresh and release: the node comes back.
	refresh_all(&r, &[&a, &b, &c]).await;
	let ks = reclaims(&r).await;
	let k = ks.iter().find(|w| w.detail.contains("RECLAIM-D")).unwrap_or_else(|| panic!("no reclaim by RECLAIM-D: {:?}",
		ks.iter().map(|w| &w.detail).collect::<Vec<_>>()));
	let tx: elements::Transaction = elements::encode::deserialize(&k.tx).unwrap();
	println!("reclaim {} ({:?}), {} vB: {}", tx.txid(), k.state, tx.vsize(), k.detail);
	assert_eq!(k.state, NurseryState::Final);
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

/// The state of the round `txid` at the server.
async fn round_of(r: &Running, txid: &elements::Txid) -> RoundState {
	r.server.store.round_by_txid(&txid.to_byte_array()).await.unwrap().unwrap().state
}

/// A wallet that drops out of a held round holds back nobody: the wallets
/// that answered run again at once, alone, and go out; the one that dropped
/// out, back again, waits and runs in a round of its own, where it answers
/// and goes out. A wallet built before forfeits came before broadcast for
/// refreshes (the `arca` at `ARCA_CLI_OLDER`, when set) is refused when it
/// asks, in words that tell its holder to update it, and its coin stays its
/// own; it never joins a round.
#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_that_drops_out_holds_back_nobody_and_an_older_one_is_told_to_update() {
	let mut r = Running::start_with(|c, _, _| {
		c.batches.no_sweep = true;
		c.batches.holder_batches = Some(0);
	}).await;
	let x_id = r.x;
	let x = x_id.to_string();
	r.fund_server(x_id, 100_000_000).await;
	r.fund_server(x_id, 100_000_000).await;
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	let (a, h) = (Arca::new("A drop"), Arca::new("H drop"));
	let older = std::env::var("ARCA_CLI_OLDER").ok().map(|p| Arca::built_from("O drop", std::path::Path::new(&p)));
	let mut ws = vec![&a, &h];
	if let Some(o) = &older {
		ws.push(o);
	}
	for w in &ws {
		w.ok(&create);
	}
	boarded(&mut r, &ws, x_id, 2_000_000).await;

	// The older wallet asks for a refresh: refused, in words, nothing taken.
	match &older {
		Some(o) => {
			let (ok, v) = o.run(&["participate"]);
			println!("the older wallet's refresh: ok {} {}", ok, v);
			let text = v.to_string();
						assert!(text.contains("update the wallet"), "the holder is told to update: {}", v);
			assert_ne!(v["error"]["kind"], "unreachable", "taken as the operator's refusal, not as a server it cannot reach: {}", v);
			let coins = o.ok(&["coins"]);
			println!("the older wallet's coins: {}", coins);
			assert!(coins.as_array().unwrap().iter().any(|c| c["state"] == "live"), "its coin is still its own: {}", coins);
		},
		None => println!("ARCA_CLI_OLDER is not set: the older wallet's half is not run"),
	}

	// A and H ask; H goes away before its round is built.
	for w in [&a, &h] {
		let p = w.ok(&["participate"]);
		assert!(p["participations"].as_array().unwrap().iter().all(|x| x["state"] == "pending"), "{}", p);
	}
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	assert_eq!(built.len(), 1);
	assert_eq!(built[0].participations, 2, "A and H share the first round");
	a.ok(&["sync"]);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 700));
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	assert_eq!(round_of(&r, &built[0].tx.txid()).await, RoundState::Lost, "dropped for H");

	// A runs again at once, alone, though a newcomer N asks meanwhile.
	let n = Arca::new("N drop");
	n.ok(&create);
	boarded(&mut r, &[&n], x_id, 2_000_000).await;
	n.ok(&["participate"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let (again, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed.iter().map(|f| f.1.to_string()).collect::<Vec<_>>());
	println!("after the drop: {} round(s) built, of {:?} participation(s)", again.len(), again.iter().map(|b| b.participations).collect::<Vec<_>>());
	assert_eq!(again[0].participations, 1, "A alone, first");
	for w in [&a, &n] {
		w.ok(&["sync"]);
	}
	r.server.rounds.pass().await.unwrap();
	assert_eq!(round_of(&r, &again[0].tx.txid()).await, RoundState::Broadcast, "A's refresh goes out");
	// N's round follows.
	let (next, _) = r.server.rounds.run_rounds().await.unwrap();
	let mut out = vec![again[0].tx.txid()];
	for b in &next {
		out.push(b.tx.txid());
	}
	n.ok(&["sync"]);
	r.server.rounds.pass().await.unwrap();
	for t in &out {
		assert_eq!(round_of(&r, t).await, RoundState::Broadcast);
	}
	r.produce().await;
	r.bury().await;
	for t in &out {
		r.round_state(t, RoundState::Final).await;
	}
	for w in [&a, &n] {
		let s = w.ok(&["sync"]);
		assert!(s["participations"].as_array().unwrap().iter().all(|p| p["state"] == "released"), "{}", s);
	}

	// H comes back: its participation was void, its coin its own. Asked
	// again, it waits, then runs in a round of its own, answers, goes out.
	let sh = h.ok(&["sync"]);
	println!("H back: {}", sh["participations"]);
	assert_eq!(sh["participations"][0]["state"], "void", "{}", sh);
	h.ok(&["participate"]);
	let (none, _) = r.server.rounds.run_rounds().await.unwrap();
	assert!(none.is_empty(), "H's coin waits");
	let st = h.ok(&["sync"]);
	let note = st["participations"][0]["note"].as_str().unwrap_or("").to_string();
	println!("H waits, its sync says: {}", note);
	assert!(note.contains("a round of their own"), "the wallet shows why it waits: {}", st);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 700));
	r.synced().await;
	let (solo, _) = r.server.rounds.run_rounds().await.unwrap();
	assert_eq!(solo.len(), 1);
	assert_eq!(solo[0].participations, 1, "H alone");
	h.ok(&["sync"]);
	r.server.rounds.pass().await.unwrap();
	assert_eq!(round_of(&r, &solo[0].tx.txid()).await, RoundState::Broadcast, "H answered: its refresh goes out");
	r.produce().await;
	r.bury().await;
	r.round_state(&solo[0].tx.txid(), RoundState::Final).await;
	let s = h.ok(&["sync"]);
	assert!(s["participations"].as_array().unwrap().iter().any(|p| p["state"] == "released"), "{}", s);
	println!("H's refresh went out in a round of its own, once it answered");
}

/// arca#488. Two wallets refresh into a batch without a sweep whose service
/// horizon is six days on. F keeps syncing: from its refresh date (two days
/// before its exit date, five before the horizon) its sync asks for the
/// refresh by itself, and its coin moves into a new batch before the
/// horizon. E goes away: at the horizon the operator collects the batch and
/// E's coin lands on the chain under E's key. When E syncs again it shows
/// the coin plainly (moved out of the Ark to keep it safe while you were
/// away), takes it home, and boards it back by itself.
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_collected_at_the_horizon_is_shown_and_boarded_back() {
	const DAY: u32 = 86_400;
	let mut r = Running::start_with(|c, _, _| {
		c.batches.no_sweep = true;
		c.batches.holder_batches = Some(0);
		c.batches.collect_after_seconds = Some(6 * DAY);
	}).await;
	let x_id = r.x;
	let x = x_id.to_string();
	r.fund_server(x_id, 100_000_000).await;
	r.fund_server(x_id, 100_000_000).await;
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	let (e, f) = (Arca::new("E horizon"), Arca::new("F horizon"));
	for w in [&e, &f] {
		w.ok(&create);
	}
	boarded(&mut r, &[&e, &f], x_id, 2_000_000).await;
	refresh_all(&r, &[&e, &f]).await;
	let leaf_of = |w: &Arca| -> Value {
		w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["state"] == "live").cloned().expect("a live coin")
	};
	let (ce, cf) = (leaf_of(&e), leaf_of(&f));
	println!("E's coin {} dates {}; F's coin {}", ce["leaf_id"], ce["dates"], cf["leaf_id"]);
	let e_value: u64 = ce["value"].as_str().map(|v| v.parse().unwrap()).or(ce["value"].as_u64()).unwrap();

	// F syncs each day; from its refresh date its sync asks by itself.
	let mut f_refreshed = false;
	for day in 0..4 {
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, DAY));
		r.synced().await;
		let s = f.ok(&["sync"]);
		let asked = s["participations"].as_array().map(|p| p.iter().any(|x| x["state"] == "pending")).unwrap_or(false)
			|| s.to_string().contains("\"pending\"");
		println!("F's sync on day {}: asked {}", day + 1, asked);
		let (built, _) = r.server.rounds.run_rounds().await.unwrap();
		if !built.is_empty() {
			f.ok(&["sync"]);
			r.server.rounds.pass().await.unwrap();
			r.produce().await;
			r.bury().await;
			for b in &built {
				r.round_state(&b.tx.txid(), RoundState::Final).await;
			}
			let s = f.ok(&["sync"]);
			if s["participations"].as_array().unwrap().iter().any(|p| p["state"] == "released") {
				f_refreshed = true;
				println!("F's coin refreshed by its own sync on day {}", day + 1);
				break;
			}
		}
	}
	assert!(f_refreshed, "F's sync refreshed its coin before the horizon");

	// Past the horizon the operator collects E's coin onto the chain.
	let horizon = ce["expiry"].as_u64().expect("E's coin names its horizon") as u32;
	let now = common::node::median_time(&r.rt);
	println!("E's coin: horizon {} (median time now {})", horizon, now);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, horizon.saturating_sub(now) + 3_600));
	let hex = ce["leaf_id"].as_str().unwrap();
	let e_id: [u8; 32] = (0..32).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect::<Vec<u8>>().try_into().unwrap();
	let e_script = Script::from(r.server.store.leaf(&e_id).await.unwrap().expect("E's leaf at the server").script_pubkey);
	let mut landed = false;
	for _ in 0..12 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		let start = std::time::Instant::now();
		while !r.server.store.nursery_in(NurseryState::Pending).await.unwrap().iter().all(|n| n.broadcasts > 0) {
			assert!(start.elapsed() < Duration::from_secs(30));
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		r.produce().await;
		if !e_script.is_empty() && !r.server.store.sightings_of(e_script.as_bytes()).await.unwrap().is_empty() {
			landed = true;
			break;
		}
	}
	for w in r.server.store.watcher_log().await.unwrap() {
		println!("  watcher: {} {}", w.kind, w.detail.chars().take(110).collect::<String>());
	}
	assert!(landed, "E's leaf landed on the chain at the horizon");
	r.bury().await;
	r.synced().await;

	// E comes back: the coin is shown kept safe, taken home, boarded back.
	let mut reboard = Value::Null;
	for _ in 0..12 {
		let s = e.ok(&["sync"]);
		if !s["reboards"].is_null() && s["reboards"].as_array().is_some_and(|a| !a.is_empty()) {
			reboard = s["reboards"].clone();
			break;
		}
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 1_200));
		r.produce().await;
		r.bury().await;
		r.synced().await;
	}
	let coins = e.ok(&["coins"]);
	let kept = coins.as_array().unwrap().iter().find(|c| c["leaf_id"] == ce["leaf_id"]).cloned().expect("E's coin");
	println!("E's coin after the horizon: state {} kept_safe {} note {:?}", kept["state"], kept["kept_safe"], kept["kept_safe_note"]);
	assert_eq!(kept["kept_safe"], true, "{}", kept);
	assert_eq!(kept["kept_safe_note"], "moved out of the Ark to keep it safe while you were away");
	println!("E's reboard: {}", reboard);
	assert!(reboard[0]["boarded"].is_object(), "E boarded its coin back by itself: {}", reboard);
	let bal = e.ok(&["balance"]);
	println!("E's balance: {} (its coin held {})", bal["arca"], e_value);
	let _ = x;
}

/// Wallets that name the record formats they read refresh beside wallets
/// built before wallets named them (each `arca` named in
/// `ARCA_CLI_OLDER_BUILDS`, separated by `:`, when set), on an operator that
/// builds accumulator batches without a sweep (`accumulator_exit_rate_ppm`).
/// The five current wallets' leaves are slots of one accumulator batch (four
/// leaves are cheaper as a tree, of one level); an older
/// wallet's leaf rests in a tree in the same round, so it reads its record
/// and hands over its forfeits as the others do, and the round goes out
/// without waiting for anyone. An older wallet too old to hand its forfeits
/// over before broadcast is refused in words, its coin live, as ever.
#[tokio::test(flavor = "multi_thread")]
async fn older_wallets_get_a_tree_beside_the_accumulator_slots() {
	let mut r = Running::start_with(|c, _, _| {
		c.batches.no_sweep = true;
		c.batches.holder_batches = Some(0);
		c.batches.accumulator_exit_rate_ppm = Some(10_000);
	}).await;
	let x_id = r.x;
	r.fund_server(x_id, 100_000_000).await;
	r.fund_server(x_id, 100_000_000).await;
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];
	let current: Vec<Arca> = ["F1 fmt", "F2 fmt", "F3 fmt", "F4 fmt", "F5 fmt"].iter().map(|n| Arca::new(n)).collect();
	let older: Vec<Arca> = std::env::var("ARCA_CLI_OLDER_BUILDS").ok().map(|v| v.split(':').filter(|p| !p.is_empty()).enumerate()
		.map(|(i, p)| Arca::built_from(&format!("O{} fmt", i), std::path::Path::new(p))).collect()).unwrap_or_default();
	if older.is_empty() {
		println!("ARCA_CLI_OLDER_BUILDS is not set: current wallets alone");
	}
	let ws: Vec<&Arca> = current.iter().chain(older.iter()).collect();
	for w in &ws {
		w.ok(&create);
	}
	boarded(&mut r, &ws, x_id, 2_000_000).await;

	// Everyone asks a refresh. An older wallet either joins or is refused.
	let mut joined: Vec<&Arca> = current.iter().collect();
	for w in &current {
		let p = w.ok(&["participate"]);
		assert!(p["participations"].as_array().unwrap().iter().all(|x| x["state"] == "pending"), "{}", p);
	}
	for o in &older {
		let (ok, p) = o.run(&["participate"]);
		let states: Vec<String> = p["participations"].as_array().map(|a| a.iter().map(|x| x["state"].to_string()).collect())
			.unwrap_or_default();
		println!("{} (older) participate: ok {}, states {:?}: {}", o.name, ok, states, p);
		if ok && !states.is_empty() && states.iter().all(|s| s == "\"pending\"") {
			joined.push(o);
		} else {
			let coins = o.ok(&["coins"]);
			assert!(coins.as_array().unwrap().iter().any(|c| c["state"] == "live"), "{}: refused, its coin is its own: {}", o.name, coins);
		}
	}
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(built.len() == 1 && failed.is_empty(), "{} built, {} failed", built.len(), failed.len());
	let txid = built[0].tx.txid();
	assert!(built[0].broadcast.starts_with("held"), "{}", built[0].broadcast);
	let row = r.server.store.round_by_txid(&txid.to_byte_array()).await.unwrap().unwrap();
	let batches = r.server.store.batches(row.round_id).await.unwrap();
	let kinds: Vec<String> = batches.iter().map(|b| format!("{} {}", b.vout, b.kind)).collect();
	println!("round {}: {} participations, batches {:?}", txid, r.server.store.round_participations(row.round_id).await.unwrap().len(), kinds);
	assert_eq!(batches.iter().filter(|b| b.kind == arca_covenant::BatchKind::Accumulator).count(), 1, "the current wallets' slots");
	let in_tree = joined.len() - current.len();
	assert_eq!(batches.iter().filter(|b| b.kind == arca_covenant::BatchKind::Tree).count(), usize::from(in_tree > 0),
		"a tree for the older wallets' leaves, and only then");

	// Every wallet that joined hands over its forfeits before broadcast.
	for w in &joined {
		let s = w.ok(&["sync"]);
		let ps = s["participations"].as_array().unwrap();
		println!("{} before broadcast: {}", w.name, ps.iter().map(|p| format!("{} {}", p["state"], p["note"])).collect::<Vec<_>>().join("; "));
		assert!(ps.iter().all(|p| p["state"] == "forfeiting"), "{}: {}", w.name, s);
	}
	r.server.rounds.pass().await.unwrap();
	assert_eq!(round_of(&r, &txid).await, RoundState::Broadcast, "out once every forfeit is in, held back by nobody");
	r.produce().await;
	r.bury().await;
	r.round_state(&txid, RoundState::Final).await;
	for w in &joined {
		let s = w.ok(&["sync"]);
		let ps = s["participations"].as_array().unwrap();
		assert!(!ps.is_empty() && ps.iter().all(|p| p["state"] == "released"), "{}: {}", w.name, s);
		let coins = w.ok(&["coins"]);
		println!("{} after the round: {}", w.name, coins);
		assert!(coins.as_array().unwrap().iter().any(|c| c["state"] == "live"), "{}: its new coin: {}", w.name, coins);
	}

	// A current wallet pays each older one out of round from its slot. An
	// older wallet cannot read that coin's record and refuses it; once
	// updated (the current build on the same wallet directory), its first
	// `sync` reads the mailbox again from the start, once, and it holds the
	// coin, with no `restore` (arca#550). The re-read passes over every
	// coin it holds already, and a second sync reads nothing again.
	let x = x_id.to_string();
	for o in &joined[current.len()..] {
		let req = o.ok(&["receive"]);
		let sent = current[0].ok(&["send", req["request"].as_str().unwrap(), "--amount", "300000", "--asset", &x]);
		assert!(sent["change"].is_string(), "{}", sent);
		let (ok, mb) = o.run(&["mailbox"]);
		println!("{} (older) reads its mailbox: ok {}: {}", o.name, ok, mb);
		let updated = Arca { name: format!("{} updated", o.name), dir: o.dir.clone(), patience: std::cell::Cell::new(o.patience.get()),
			bin: std::path::PathBuf::from(env!("CARGO_BIN_EXE_arca")) };
		let before = updated.ok(&["balance"]);
		println!("{} balance before its first sync: {}", updated.name, before["arca"]);
		let s = updated.ok(&["sync"]);
		println!("{} first sync: mailbox {}", updated.name, s["mailbox"]);
		let coins = updated.ok(&["coins"]);
		println!("{} coins after its first sync: {}", updated.name, coins);
		assert!(coins.as_array().unwrap().iter().any(|c| c["value"] == "300000" && c["state"] == "live"),
			"{}: the coin paid to it out of a slot, after its first sync: {}", updated.name, coins);
		assert!(s["mailbox"]["accepted"].as_array().unwrap().iter().any(|a| a["value"] == "300000"), "{}", s["mailbox"]);
		let again = updated.ok(&["sync"]);
		println!("{} second sync: mailbox {}", updated.name, again["mailbox"]);
		assert!(again["mailbox"]["accepted"].as_array().unwrap().is_empty(), "read again once only: {}", again["mailbox"]);
	}
}
