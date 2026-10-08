//! Several assets, as the `arca` wallet meets them: each asset is refreshed
//! in that asset's own rounds, one participation per asset, and charged its
//! own schedule, against a whole Arca server serving X (listed for fees) and
//! Y (not listed), on an anchored proof-of-stake regtest chain.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::collections::BTreeMap;
use std::str::FromStr;

use elements::Script;
use serde_json::Value;

use common::cli::Arca;
use common::running::Running;
use server::store::RoundState;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

fn create_args<'a>(server: &'a str, node: &'a str) -> Vec<&'a str> {
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

/// The coins of `w` in `state`.
fn coins_in(w: &Arca, state: &str) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == state).cloned().collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_refreshes_each_asset_in_its_own_round() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("AS1");
	a.ok(&create_args(&url, &node));
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, r.x, 10_000_000);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, r.x, 1_000_000);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, r.y, 10_000_000);
	r.produce().await;
	let bx = a.ok(&["board", &x, "2000000"])["leaf_id"].as_str().unwrap().to_string();
	let by = a.ok(&["board", &y, "3000000", "--fee-asset", &x])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("both boards credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
	assert_eq!(coins_in(&a, "live").len(), 2);

	// Every live coin: a participation for each asset.
	let p = a.ok(&["participate"]);
	let ps = p["participations"].as_array().unwrap_or_else(|| panic!("a participation per asset: {}", p)).clone();
	assert_eq!(ps.len(), 2, "{}", p);
	let of = |asset: &str| ps.iter().find(|q| q["asset"] == asset).cloned().unwrap_or_else(|| panic!("none in {}: {}", asset, p));
	let (px, py) = (of(&x), of(&y));
	for (q, board) in [(&px, &bx), (&py, &by)] {
		assert_eq!(q["state"], "pending", "{}", q);
		assert_eq!(q["gives"], serde_json::json!([board]), "{}", q);
		assert_eq!(q["wants"].as_array().unwrap().len(), 1, "{}", q);
	}
	assert!(py["exit_needs_fee_coin"].is_object() && px.get("exit_needs_fee_coin").is_none(), "{}", p);

	// A round for each, X's first in the order the operator serves them.
	let rx = r.server.rounds.run_round().await.unwrap().expect("X's round");
	let ry = r.server.rounds.run_round().await.unwrap().expect("Y's round");
	println!("X's round {} batches {:?}; Y's round {} batches {:?}", rx.tx.txid(), rx.batches, ry.tx.txid(), ry.batches);
	assert_eq!((rx.batches.len(), rx.batches[0].0), (1, r.x));
	assert_eq!((ry.batches.len(), ry.batches[0].0), (1, r.y));
	r.produce().await;
	r.bury().await;
	r.round_state(&rx.tx.txid(), RoundState::Final).await;
	r.round_state(&ry.tx.txid(), RoundState::Final).await;

	// Both released; a new leaf in each asset, each on its own round.
	let s = a.ok(&["sync"]);
	let done = s["participations"].as_array().unwrap();
	assert_eq!(done.len(), 2, "{}", s);
	let live = coins_in(&a, "live");
	assert_eq!(live.len(), 2, "{:?}", live);
	for (q, asset, value, round) in [(&px, &x, "2000000", rx.tx.txid()), (&py, &y, "3000000", ry.tx.txid())] {
		let d = done.iter().find(|d| d["participation"] == q["participation"]).unwrap_or_else(|| panic!("{} in {}", q, s));
		assert_eq!(d["state"], "released", "{}", d);
		assert_eq!(d["round"], round.to_string(), "the participation in {} ran in its own round: {}", asset, d);
		let leaf = d["new_leaves"][0]["leaf_id"].as_str().unwrap();
		let c = live.iter().find(|c| c["leaf_id"] == leaf).unwrap_or_else(|| panic!("the new leaf {}: {:?}", leaf, live));
		assert_eq!((c["asset"].as_str(), c["kind"].as_str(), c["value"].as_str()), (Some(asset.as_str()), Some("batch"), Some(value)), "{}", c);
		println!("the new leaf of {}: {} {}, resting on round {}", asset, c["value"], c["kind"], round);
	}
	let _ = std::fs::remove_dir_all(&a.dir);
}

/// A coin's fee in a refresh quote, and the schedule it was priced by.
fn quoted<'a>(quote: &'a Value, leaf: &str) -> &'a Value {
	quote.as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).unwrap_or_else(|| panic!("{} in {}", leaf, quote))
}

#[tokio::test(flavor = "multi_thread")]
async fn each_asset_is_charged_its_own_schedule() {
	// X charges 5,000 parts per million of a coin; Y the default 1,000 and
	// 400 atoms a coin.
	let mut r = Running::start_with(|c, x, y| {
		c.fees.refresh_ppm = 1_000;
		c.assets = vec![
			toml::from_str(&format!("asset = \"{}\"\nmin_leaf = \"1000\"\nrefresh_ppm = 5000\n", x)).unwrap(),
			toml::from_str(&format!("asset = \"{}\"\nmin_leaf = \"1000\"\nrefresh_base = \"400\"\n", y)).unwrap(),
		];
	}).await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("AS2");
	a.ok(&create_args(&url, &node));
	for (asset, v) in [(r.x, 10_000_000), (r.x, 1_000_000), (r.y, 10_000_000)] {
		let s = script(&a.ok(&["address"]));
		r.pay_to(s, asset, v);
	}
	r.produce().await;
	let bx = a.ok(&["board", &x, "2000000"])["leaf_id"].as_str().unwrap().to_string();
	let by = a.ok(&["board", &y, "30000", "--fee-asset", &x])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("both boards credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
	let info = a.ok(&["info"]);
	println!("the operator's schedules: X {}, Y {}", info["server_info"]["assets"][0]["fees"], info["server_info"]["assets"][1]["fees"]);

	// Y's coin of 30,000 would pay 400 atoms and more: above the wallet's
	// bound of 10,000 millionths of the coin. Refused before anything is
	// signed, by Y's own schedule.
	let why = a.refused(&["participate"], "--max-fee-ppm");
	assert!(why.contains(&by) && why.contains(&y), "the coin of Y, by Y's schedule: {}", why);
	assert_eq!(coins_in(&a, "live").len(), 2, "nothing was given up");

	// X's coin, by X's schedule; Y's with the bound raised for the command.
	let (ok, px, err) = a.run_full(&["participate", "--leaf", &bx]);
	assert!(ok, "{}", px);
	println!("X: stderr {:?}\n{}", err.trim(), px);
	let qx = quoted(&px["quote"], &bx);
	assert_eq!(qx["schedule"], serde_json::json!({"refresh_ppm": 5000, "refresh_base": "0"}), "{}", qx);
	assert!(err.contains(&format!("refresh fee for coin {}: {} of asset {}", bx, qx["fee"].as_str().unwrap(), x)), "shown first: {}", err);
	let fx: u64 = qx["fee"].as_str().unwrap().parse().unwrap();
	assert!(fx > 9_000 && fx <= 10_000, "5,000 millionths of 2,000,000, by the time left: {}", fx);
	assert_eq!(px["participations"][0]["fees"], serde_json::json!([{"asset": x, "amount": fx.to_string()}]));
	let (ok, py, err) = a.run_full(&["participate", "--leaf", &by, "--max-fee-ppm", "20000"]);
	assert!(ok, "{}", py);
	println!("Y: stderr {:?}\n{}", err.trim(), py);
	let qy = quoted(&py["quote"], &by);
	assert_eq!(qy["schedule"], serde_json::json!({"refresh_ppm": 1000, "refresh_base": "400"}), "{}", qy);
	let fy: u64 = qy["fee"].as_str().unwrap().parse().unwrap();
	assert!(fy > 400 && fy <= 430, "1,000 millionths of 30,000 and 400 a coin, by the time left: {}", fy);

	// A round for each; each new leaf holds its coin less its own fee.
	let (rounds, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty() && rounds.len() == 2, "{:?}", failed);
	r.produce().await;
	r.bury().await;
	for b in &rounds {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	let s = a.ok(&["sync"]);
	assert!(s["participations"].as_array().unwrap().iter().all(|q| q["state"] == "released"), "{}", s);
	let live = coins_in(&a, "live");
	for (asset, value) in [(&x, 2_000_000 - fx), (&y, 30_000 - fy)] {
		let c = live.iter().find(|c| c["asset"] == asset.as_str()).unwrap_or_else(|| panic!("{:?}", live));
		assert_eq!(c["value"], value.to_string(), "{}", c);
		println!("the new leaf of {}: {} (its coin less its fee)", asset, c["value"]);
	}
	let _ = std::fs::remove_dir_all(&a.dir);
}

/// What a wallet holds of each asset, as its `balance` shows it: in Arca
/// (every state but those it no longer holds) and on the chain.
fn holdings(w: &Arca) -> BTreeMap<String, (i128, i128)> {
	let b = w.ok(&["balance"]);
	let mut out: BTreeMap<String, (i128, i128)> = BTreeMap::new();
	for (a, states) in b["arca"].as_object().unwrap() {
		out.entry(a.clone()).or_default().0 = states.as_object().unwrap().values().map(|v| v.as_str().unwrap().parse::<i128>().unwrap()).sum();
	}
	for (a, v) in b["sequentia_onchain"].as_object().unwrap() {
		out.entry(a.clone()).or_default().1 = v.as_str().unwrap().parse().unwrap();
	}
	out
}

/// The books: what each wallet must hold of each asset, in Arca and on the
/// chain, by what every command it ran reported.
#[derive(Default)]
struct Books(BTreeMap<String, BTreeMap<String, (i128, i128)>>);

impl Books {
	fn arca(&mut self, w: &str, asset: &str, delta: i128) {
		self.0.entry(w.into()).or_default().entry(asset.into()).or_default().0 += delta;
	}

	fn chain(&mut self, w: &str, asset: &str, delta: i128) {
		self.0.entry(w.into()).or_default().entry(asset.into()).or_default().1 += delta;
	}

	/// Each wallet holds exactly what the books say, in every asset.
	fn check(&self, what: &str, wallets: &[&Arca]) {
		for w in wallets {
			let held = holdings(w);
			let want = self.0.get(&w.name).cloned().unwrap_or_default();
			let assets: std::collections::BTreeSet<&String> = held.keys().chain(want.keys()).collect();
			for a in assets {
				let h = held.get(a).copied().unwrap_or_default();
				let b = want.get(a).copied().unwrap_or_default();
				assert_eq!(h, b, "{}: {} holds (Arca, on-chain) {:?} of {}; the books say {:?}", what, w.name, h, a, b);
			}
			println!("BOOKS {}: {} holds, as the books say, {:?}", what, w.name, held);
		}
	}
}

fn atoms(v: &Value) -> i128 {
	v.as_str().unwrap_or_else(|| panic!("an amount: {}", v)).parse().unwrap()
}

/// The fees `exit` reports for its transactions, in `asset`.
fn exit_fees(e: &Value, asset: &str) -> i128 {
	e["broadcast"].as_array().into_iter().flatten().flat_map(|s| s["fee"].as_array().cloned().unwrap_or_default())
		.filter(|f| f["asset"] == asset).map(|f| atoms(&f["amount"])).sum()
}

/// Two assets refresh independently: the proof of a pool, a fee schedule and
/// a rate source per asset, end to end. X is listed for fees and priced by
/// the node's own rate, with a refresh of 1,000 millionths of a coin; Y is not
/// listed and is priced by the operator's file, with a fixed part of a
/// refresh set as a value; Z is issued on the chain and not served. Two
/// wallets, each holding X and Y, board, pay each other, refresh (a round of
/// X and a round of Y, built in one pass), swap X for Y, refresh again while
/// Y's rate is stale (X goes on, Y waits and then goes on), and exit, each a
/// leaf of Y paying the exit's fees in X; at every step every coin is where
/// the books say, in both assets. Z is refused at every command.
#[tokio::test(flavor = "multi_thread")]
async fn two_assets_refresh_independently() {
	let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("arca-assets-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let rate_file = dir.join("y.rate");
	let now = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
	// Y at 2 reference coins a coin: a value of 1,000 is 500 atoms.
	std::fs::write(&rate_file, format!("200000000 {}\n", now())).unwrap();
	let file = rate_file.clone();
	let mut r = Running::start_with(move |c, x, y| {
		c.assets = vec![
			toml::from_str(&format!("asset = \"{}\"\nmin_leaf = \"1000\"\nrefresh_ppm = 1000\n[rate]\nsource = \"node\"\n", x)).unwrap(),
			toml::from_str(&format!("asset = \"{}\"\nmin_leaf = \"1000\"\nrefresh_base_value = \"1000\"\n[rate]\nsource = \"file\"\n\
				path = {:?}\nmax_age_seconds = 600\n", y, file.display().to_string())).unwrap(),
		];
	}).await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	let z_id = tokio::task::block_in_place(|| r.purse.issue(&r.rt, "asset Z", 100_000_000_000));
	let z = z_id.to_string();
	let (url, node) = (r.url(), r.node_url());
	println!("asset X {} (listed, the node's rate), Y {} (not listed, a file's rate), Z {} (not served)", x, y, z);
	let info = r.server.params.assets.ids();
	assert_eq!(info, vec![r.x, r.y]);

	// --- Two wallets, each paid X and Y on the chain ---
	let (a, b) = (Arca::new("AS3A"), Arca::new("AS3B"));
	let mut books = Books::default();
	for w in [&a, &b] {
		w.ok(&create_args(&url, &node));
		for (asset, id, v) in [(&x, r.x, 10_000_000i128), (&x, r.x, 1_000_000), (&y, r.y, 10_000_000)] {
			let s = script(&w.ok(&["address"]));
			r.pay_to(s, id, v as u64);
			books.chain(&w.name, asset, v);
		}
	}
	r.produce().await;
	books.check("funded", &[&a, &b]);

	// --- Board ---
	for (w, vx, vy) in [(&a, 3_000_000i128, 3_000_000i128), (&b, 2_000_000, 4_000_000)] {
		let bx = w.ok(&["board", &x, &vx.to_string()]);
		books.arca(&w.name, &x, vx);
		books.chain(&w.name, &x, -vx - atoms(&bx["fee"]["amount"]));
		let by = w.ok(&["board", &y, &vy.to_string(), "--fee-asset", &x]);
		books.arca(&w.name, &y, vy);
		books.chain(&w.name, &y, -vy);
		books.chain(&w.name, &x, -atoms(&by["fee"]["amount"]));
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	for w in [&a, &b] {
		r.wait("every board credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
		w.ok(&["sync"]);
	}
	books.check("boarded", &[&a, &b]);

	// --- Pay: A pays B 500,000 of X; B pays A 700,000 of Y ---
	for (from, to, asset, v) in [(&a, &b, &x, 500_000i128), (&b, &a, &y, 700_000)] {
		let req = to.ok(&["receive", "--asset", asset])["request"].as_str().unwrap().to_string();
		let sent = from.ok(&["send", &req, "--amount", &v.to_string(), "--asset", asset]);
		let margins: i128 = sent["margins"]["checkpoints"].as_array().unwrap().iter().map(atoms).sum::<i128>()
			+ atoms(&sent["margins"]["reassignment"]);
		books.arca(&from.name, asset, -v - margins);
		books.arca(&to.name, asset, v);
		let mb = to.ok(&["mailbox"]);
		assert_eq!(mb["accepted"][0]["value"], v.to_string(), "{}", mb);
	}
	books.check("paid", &[&a, &b]);

	// --- Refresh: a participation per asset each, a round per asset in one pass ---
	for w in [&a, &b] {
		let p = w.ok(&["participate"]);
		let ps = p["participations"].as_array().unwrap();
		assert_eq!(ps.len(), 2, "{}", p);
		for q in ps {
			assert_eq!(q["state"], "pending", "{}", q);
			for f in q["fees"].as_array().unwrap() {
				books.arca(&w.name, f["asset"].as_str().unwrap(), -atoms(&f["amount"]));
			}
		}
	}
	let (rounds, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	assert_eq!(rounds.iter().map(|b| (b.batches.len(), b.batches[0].0, b.batches[0].2, b.participations)).collect::<Vec<_>>(),
		vec![(1, r.x, 2, 2), (1, r.y, 2, 2)], "a round of X and a round of Y, each with both wallets' participations");
	let created: Vec<u32> = {
		let mut v = vec![];
		for b in &rounds {
			v.push(r.server.store.round_by_txid(&elements::hashes::Hash::to_byte_array(b.tx.txid())).await.unwrap().unwrap().created_mtp);
		}
		v
	};
	println!("REFRESH: round {} in X and round {} in Y, built in one pass at median time {:?}", rounds[0].tx.txid(), rounds[1].tx.txid(), created);
	assert!(created[1].abs_diff(created[0]) < 60, "in the same minute: {:?}", created);
	r.produce().await;
	r.bury().await;
	for b in &rounds {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	for w in [&a, &b] {
		let s = w.ok(&["sync"]);
		assert!(s["participations"].as_array().unwrap().iter().all(|q| q["state"] == "released"), "{}", s);
	}
	books.check("refreshed", &[&a, &b]);
	// The headline: the total across assets, in the reference unit, where the
	// wallet's node has a rate (X); Y, which it has none for, set apart.
	let bal = a.ok(&["balance"]);
	println!("A's balance: {}", bal);
	let held = holdings(&a);
	assert_eq!(atoms(&bal["total"]["value"]), held[&x].0 + held[&x].1, "X at 1:1, all of it: {}", bal["total"]);
	assert_eq!(bal["total"]["unvalued"], serde_json::json!([y]), "{}", bal["total"]);
	assert_eq!(bal["rows"][0]["asset"], "BTC", "BTC, on its own chain, first among the rows: {}", bal["rows"]);

	// --- Swap: A gives 300,000 of X for 400,000 of B's Y ---
	let (coins_a, coins_b) = (a.ok(&["coins"]), b.ok(&["coins"]));
	// What one side's checkpoints keep back: the margins its own inputs
	// leave (`all`, its coins; an acceptance lists the maker's inputs too).
	let ckpt = |all: &Value, inputs: &Value| -> i128 {
		inputs.as_array().unwrap().iter().filter_map(|i| {
			let c = all.as_array().unwrap().iter().find(|c| c["leaf_id"] == i["leaf_id"])?;
			Some(atoms(&c["value"]) - atoms(&i["checkpoint_value"]))
		}).sum()
	};
	let offer = a.ok(&["swap", "offer", "--give-asset", &x, "--give", "300000", "--want-asset", &y, "--want", "400000"]);
	let acc = b.ok(&["swap", "accept", offer["offer"].as_str().unwrap()]);
	let accept: Value = serde_json::from_slice(&unhex(acc["accept"].as_str().unwrap().split(':').nth(1).unwrap())).unwrap();
	let done = a.ok(&["swap", "complete", acc["accept"].as_str().unwrap()]);
	b.ok(&["mailbox"]);
	let maker = atoms(&offer["details"]["margin"]) + ckpt(&coins_a, &offer["details"]["inputs"]);
	let taker = ckpt(&coins_b, &accept["inputs"]);
	println!("SWAP: A kept {} | A leaves {} of X as margins (reassignment {}), B {} of Y", done["transfer"]["kept"].as_array().unwrap().len(),
		maker, offer["details"]["margin"], taker);
	books.arca(&a.name, &x, -300_000 - maker);
	books.arca(&a.name, &y, 400_000);
	books.arca(&b.name, &x, 300_000);
	books.arca(&b.name, &y, -400_000 - taker);
	books.check("swapped", &[&a, &b]);

	// --- Y's rate stale: no new work in Y, X goes on ---
	std::fs::write(&rate_file, format!("200000000 {}\n", now() - 7_200)).unwrap();
	r.wait("Y's rate stale", || {
		a.ok(&["info"])["server_info"]["assets"][1]["rate"]["stale"] == true
	}).await;
	println!("STALE: Y's rate {}", a.ok(&["info"])["server_info"]["assets"][1]["rate"]);
	// B boards more Y: the server takes no new work in Y now; the board
	// stands, its transaction unbroadcast, and sync posts it again.
	let (ok, bv) = b.run(&["board", &y, "1000000", "--fee-asset", &x]);
	println!("STALE: B's board of Y: ok={} {}", ok, bv);
	assert!(!ok && bv["error"]["kind"] == "unreachable" && bv["error"]["message"].as_str().unwrap().contains("rate_stale"), "{}", bv);
	let pending_board = b.ok(&["boards"]).as_array().unwrap().iter().find(|x| x["server"]["state"] != "credited").cloned()
		.unwrap_or_else(|| panic!("B's board of Y stands"));
	println!("STALE: B's board stands: {}", pending_board);
	// A refreshes everything: X taken, Y standing.
	let p = a.ok(&["participate"]);
	println!("STALE: A's refresh: {}", p);
	let ps = p["participations"].as_array().unwrap();
	let px = ps.iter().find(|q| q["asset"] == x.as_str()).unwrap();
	let py = ps.iter().find(|q| q["asset"] == y.as_str()).unwrap();
	assert_eq!(px["state"], "pending", "{}", px);
	assert!(py["error"].as_str().unwrap().contains("rate_stale") && py["note"].as_str().unwrap().contains("stands"), "{}", py);
	for f in px["fees"].as_array().unwrap() {
		books.arca(&a.name, &x, -atoms(&f["amount"]));
	}
	let (rounds, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	assert_eq!(rounds.iter().map(|b| b.batches[0].0).collect::<Vec<_>>(), vec![r.x], "X's round alone: Y takes no new work");
	println!("STALE: round {} in X alone", rounds[0].tx.txid());
	let x_round = rounds[0].tx.txid();

	// Fresh again: Y's work goes on.
	std::fs::write(&rate_file, format!("200000000 {}\n", now())).unwrap();
	r.wait("Y's rate fresh", || a.ok(&["info"])["server_info"]["assets"][1]["rate"]["stale"] == false).await;
	let s = a.ok(&["sync"]);
	let posted = s["participations"].as_array().unwrap().iter().find(|q| q["state"] == "pending").cloned()
		.unwrap_or_else(|| panic!("A's participation in Y posted again: {}", s));
	println!("FRESH: A's participation in Y posted again: {}", posted);
	// Its fee is the one quoted for its coins, posted again byte for byte.
	let y_fee: i128 = p["quote"].as_array().unwrap().iter().filter(|c| c["asset"] == y.as_str()).map(|c| atoms(&c["fee"])).sum();
	books.arca(&a.name, &y, -y_fee);
	let sb = b.ok(&["sync"]);
	println!("FRESH: B's sync: boards {}", sb["boards"]);
	books.arca(&b.name, &y, 1_000_000);
	books.chain(&b.name, &y, -1_000_000);
	// Its transaction's fee, in X, as the chain holds it.
	let entry = b.ok(&["boards"]).as_array().unwrap().iter().find(|x| x["leaf_id"] == pending_board["leaf_id"]).cloned().unwrap();
	let btx = r.rt.client().raw_transaction(&elements::Txid::from_str(entry["server"]["txid"].as_str().unwrap()).unwrap()).unwrap();
	let bfee: i128 = btx.output.iter().filter(|o| o.is_fee()).map(|o| {
		assert_eq!(o.asset.explicit(), Some(r.x));
		o.value.explicit().unwrap() as i128
	}).sum();
	books.chain(&b.name, &x, -bfee);
	let (rounds, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	assert_eq!(rounds.iter().map(|b| b.batches[0].0).collect::<Vec<_>>(), vec![r.y], "Y's round, now");
	r.produce().await;
	r.bury().await;
	r.round_state(&x_round, RoundState::Final).await;
	r.round_state(&rounds[0].tx.txid(), RoundState::Final).await;
	r.synced().await;
	for w in [&a, &b] {
		r.wait("every board credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
		let s = w.ok(&["sync"]);
		assert!(s["participations"].as_array().unwrap().iter().all(|q| q["state"] == "released"), "{}", s);
	}
	books.check("refreshed while Y's rate was stale", &[&a, &b]);

	// --- Exit: a coin of Y each, the fees in X: named by A, chosen by B ---
	for (w, named) in [(&a, true), (&b, false)] {
		// A coin of Y no one else's coin rests on: A's leaf of Y's last
		// round, B's board of Y.
		let kind = if named { "batch" } else { "board" };
		let leaf = coins_in(w, "live").into_iter().filter(|c| c["asset"] == y.as_str() && c["kind"] == kind)
			.max_by_key(|c| atoms(&c["value"])).unwrap_or_else(|| panic!("{} holds a {} of Y", w.name, kind));
		let id = leaf["leaf_id"].as_str().unwrap().to_string();
		let v = atoms(&leaf["value"]);
		let mut args = vec!["exit", id.as_str()];
		if named {
			args.extend(["--fee-asset", x.as_str()]);
		}
		let e = w.ok(&args);
		assert!(e["broadcast"].as_array().unwrap().iter().all(|s| s["fee"].as_array().unwrap().iter().all(|f| f["asset"] == x.as_str())),
			"every fee in X: {}", e);
		let mut fees = exit_fees(&e, &x);
		// Each step of the leaf's way out is paid by a coin of X, and takes
		// the one atom of Y the operator reserved on it (Y is not accepted
		// for fees) home with the coin's change.
		let mut reserves: i128 = 0;
		for step in e["broadcast"].as_array().unwrap() {
			let t = r.rt.client().raw_transaction(&elements::Txid::from_str(step["txid"].as_str().unwrap()).unwrap()).unwrap();
			reserves += t.output.iter().filter(|o| !o.is_fee() && o.asset.explicit() == Some(r.y) && o.value.explicit() == Some(1)).count() as i128;
		}
		r.produce().await;
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 512));
		let e = w.ok(&args);
		assert_eq!(e["state"], "claimed", "{}", e);
		let claim = elements::Txid::from_str(e["claim"]["txid"].as_str().unwrap()).unwrap();
		let tx = r.rt.client().raw_transaction(&claim).unwrap();
		assert_eq!((tx.output[0].asset.explicit().map(|a| a.to_string()), tx.output[0].value.explicit()), (Some(y.clone()), Some(v as u64)),
			"the whole leaf comes home");
		fees += tx.output.iter().filter(|o| o.is_fee()).filter(|o| o.asset.explicit().map(|a| a.to_string()) == Some(x.clone()))
			.map(|o| o.value.explicit().unwrap() as i128).sum::<i128>();
		r.produce().await;
		r.bury().await;
		w.ok(&["sync"]);
		assert_eq!(w.ok(&["record", &id])["state"], "exited");
		println!("EXIT: {} took its {} {} of {} of Y home, {} the fee asset, {} of X in fees, and {} atom(s) of Y the operator reserved on \
			its path", w.name, kind, id, v, if named { "naming" } else { "the wallet choosing" }, fees, reserves);
		books.arca(&w.name, &y, -v);
		books.chain(&w.name, &y, v + reserves);
		books.chain(&w.name, &x, -fees);
	}
	books.check("exited", &[&a, &b]);

	// --- Z, not served, refused at every command ---
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, z_id, 5_000_000);
	r.produce().await;
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	for (what, args) in [
		("a board of Z", vec!["board", z.as_str(), "1000000", "--fee-asset", x.as_str()]),
		("a request for Z", vec!["receive", "--asset", z.as_str()]),
		("a payment of Z", vec!["send", req.as_str(), "--amount", "100000", "--asset", z.as_str()]),
		("a swap for Z", vec!["swap", "offer", "--give-asset", x.as_str(), "--give", "100000", "--want-asset", z.as_str(), "--want", "100000"]),
	] {
		let why = a.refused(&args, &format!("does not serve asset {}", z));
		println!("Z: {}: REFUSED: {}", what, why);
	}
	let _ = std::fs::remove_dir_all(&a.dir);
	let _ = std::fs::remove_dir_all(&b.dir);
	let _ = std::fs::remove_dir_all(&dir);
}
