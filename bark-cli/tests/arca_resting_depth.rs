//! A resting order and the operator's depth limit, as the `arca` wallet
//! meets them, on an operator like the testnet's (batches without a sweep,
//! forfeits handed over before the round is broadcast, no checkpoint exit,
//! the depth limit of 5).
//!
//! Each fill puts what rests one reassignment deeper (or deeper still, when
//! the taker pays with a deep coin), and a cancel is one reassignment more.
//! So:
//!
//! 1. Order O is filled in part three times, to three reassignments deep,
//!    and refreshed there: a round gives it a fresh coin and it goes on
//!    under the same id, the same terms and amount, a round's leaf again
//!    with four fills ahead of it. While the refresh runs it reads
//!    `refreshing` and takes no fill.
//! 2. Two more part fills (five in all), the second from a taker coin three
//!    deep, bring it to four: a sixth part fill is refused, by the wallet
//!    before anything is signed, and the order is cancelled, one more
//!    reassignment, within the limit.
//! 3. Order O2: a part fill from a taker coin four deep is refused (it would
//!    put what rests at the limit); three part fills bring it to four, a
//!    fourth part is refused and the whole remainder is taken.
//! 4. Order O3's refresh fails mid-round (its round is built and held for
//!    the maker's forfeits, which never come; the operator drops it): the
//!    order rests where it was, at the same coin, and is filled after.
//! 5. The testnet's stuck order: order O4 at four reassignments when the
//!    operator restarts with a depth limit of 4 rests at the limit, where it
//!    can be neither filled nor cancelled (refused `depth_limit`, as on the
//!    testnet). Its refresh brings it back to a round's leaf under the same
//!    id, and it is cancelled into the maker's own leaf.
//!
//! The operator's own refusal of a part fill at the limit, sent by hand past
//! the wallet's check, is in the server's `tests/orders.rs`.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::AssetId;
use serde_json::{json, Value};

use common::cli::Arca;
use common::running::Running;
use server::server::AssetSection;
use server::store::RoundState;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn testnet_like(c: &mut server::server::Config, x: AssetId) {
	c.assets[0] = AssetSection::new(x, 1_000);
	c.checkpoint_exit = false;
	c.batches.no_sweep = true;
	c.batches.holder_batches = Some(0);
	c.batches.collect_after_seconds = Some(2_419_200);
}

/// A wallet holding one coin of `asset`, boarded.
async fn holder(r: &mut Running, name: &str, asset: AssetId, value: u64) -> Arca {
	let (url, node) = (r.url(), r.node_url());
	let w = Arca::new(name);
	w.ok(&["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	let s = elements::Script::from(unhex(w.ok(&["address"])["script_pubkey"].as_str().unwrap()));
	r.pay_to(s, asset, value + 100_000);
	r.produce().await;
	w.ok(&["board", &asset.to_string(), &value.to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
	w
}

/// Builds the rounds waiting, has `wallets` hand over their forfeits, and
/// makes the rounds final.
async fn rounds(r: &mut Running, wallets: &[&Arca]) {
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty() && !built.is_empty(), "{} built, {} failed", built.len(), failed.len());
	for w in wallets {
		w.ok(&["sync"]);
	}
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
	for w in wallets {
		w.ok(&["sync"]);
	}
}

/// Rests `amount` of X for Y at 2/1 in lots of 10,000: the order's id.
async fn rest(r: &mut Running, maker: &Arca, amount: u64) -> String {
	let (x, y) = (r.x, r.y);
	let args = |extra: &[&str]| -> Vec<String> {
		let mut v: Vec<String> = ["order", "rest", "--sell", &x.to_string(), "--amount", &amount.to_string(), "--for", &y.to_string(),
			"--rate-num", "2", "--rate-den", "1", "--min-lot", "10000", "--expires-in-hours", "720"].iter().map(|s| s.to_string()).collect();
		v.extend(extra.iter().map(|s| s.to_string()));
		v
	};
	let q = maker.ok(&args(&["--quote"]).iter().map(|s| s.as_str()).collect::<Vec<_>>());
	let rested = maker.ok(&args(&["--shown", &q.to_string()]).iter().map(|s| s.as_str()).collect::<Vec<_>>());
	rounds(r, &[maker]).await;
	maker.ok(&["sync"]);
	let mine = view(maker, None, rested["order"].as_str());
	assert_eq!(mine["state"], "published", "{}", mine);
	mine["order"].as_str().unwrap().to_string()
}

/// The maker's own order `order` (or the one `rested_by` rested), as
/// `order resting` shows it.
fn view(maker: &Arca, order: Option<&str>, rested_by: Option<&str>) -> Value {
	let v = maker.ok(&["order", "resting"]);
	v["orders"].as_array().unwrap().iter()
		.find(|o| order.is_some_and(|i| o["order"] == json!(i)) || rested_by.is_some_and(|i| o["rested_by"] == json!(i)))
		.cloned().unwrap_or_else(|| panic!("no order {:?} {:?}: {}", order, rested_by, v))
}

/// The operator's view of order `order`, as anyone reads it.
fn served(w: &Arca, order: &str) -> Value {
	let v = w.ok(&["order", "resting", order]);
	v["others"].as_array().unwrap().iter().find(|o| o["order"] == json!(order)).cloned().unwrap_or_else(|| panic!("{}", v))
}

fn hops_of(st: &Value) -> u64 {
	st["hops"].as_u64().unwrap_or_else(|| panic!("no hops: {}", st))
}

/// A fill of `amount` (all of it when `None`) of `order` by `t`, quoted then
/// shown.
fn fill(t: &Arca, order: &str, amount: Option<u64>) -> Value {
	let mut a = vec!["order".to_string(), "fill-resting".into(), order.into()];
	if let Some(v) = amount {
		a.extend(["--amount".to_string(), v.to_string()]);
	}
	let q = t.ok(&[a.clone(), vec!["--quote".into()]].concat().iter().map(|s| s.as_str()).collect::<Vec<_>>());
	t.ok(&[a, vec!["--shown".into(), q.to_string()]].concat().iter().map(|s| s.as_str()).collect::<Vec<_>>())
}

/// A fill of `amount` of `order` by `t` that the wallet refuses before it
/// signs anything: its words.
fn fill_refused(t: &Arca, order: &str, amount: Option<u64>, why: &str) -> String {
	let mut a = vec!["order", "fill-resting", order];
	let s;
	if let Some(v) = amount {
		s = v.to_string();
		a.extend(["--amount", s.as_str()]);
	}
	a.push("--quote");
	let (ok, e) = t.run(&a);
	assert!(!ok && e.to_string().contains(why), "refused for {:?}: {}", why, e);
	e.to_string()
}

/// The live coins of `asset` `w` holds, each with its hops.
fn live_hops(w: &Arca, asset: AssetId) -> Vec<(String, u64, u64)> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == json!(asset.to_string()))
		.map(|c| (c["leaf_id"].as_str().unwrap().to_string(), c["value"].as_str().unwrap().parse().unwrap(), c["hops"].as_u64().unwrap_or(0)))
		.collect()
}

/// Pays `w`'s coins of `asset` on to itself until they are `deep`
/// reassignments from a round.
fn deepen(w: &Arca, asset: AssetId, deep: u64) {
	while live_hops(w, asset).iter().map(|c| c.2).max().unwrap_or(0) < deep {
		let have: u64 = live_hops(w, asset).iter().map(|c| c.1).sum();
		let req = w.ok(&["receive"]);
		w.ok(&["send", req["request"].as_str().unwrap(), "--amount", &(have - 10_000).to_string(), "--asset", &asset.to_string()]);
		w.ok(&["mailbox"]);
	}
}

/// A refresh of `order` by its maker, quoted then shown: the quote and the
/// answer.
fn refresh(m: &Arca, order: &str) -> (Value, Value) {
	let q = m.ok(&["order", "refresh-resting", order, "--quote"]);
	let a = m.ok(&["order", "refresh-resting", order, "--shown", &q.to_string()]);
	assert_eq!(a["state"], "refreshing", "{}", a);
	(q, a)
}

/// The terms a taker sees, less the credit keys, which a refresh renews.
fn landed(terms: &Value) -> Value {
	let mut t = terms.clone();
	if let Some(o) = t.as_object_mut() {
		o.retain(|k, _| !k.contains("credit"));
	}
	t
}

fn server_state(r: &Running, leaf: &str) -> String {
	let id: [u8; 32] = unhex(leaf).try_into().unwrap();
	let row = tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(r.server.store.leaf(&id))).unwrap().unwrap();
	format!("{:?}", row.state)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resting_order_can_always_be_cancelled_and_its_refresh_keeps_it() {
	let mut r = Running::start_with(|c, x, _| testnet_like(c, x)).await;
	let (x, y) = (r.x, r.y);
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	let m = holder(&mut r, "DL M", x, 5_000_000).await;
	let limit = m.ok(&["info"])["server_info"]["depth_limit"].as_u64().unwrap();
	assert_eq!(limit, 5, "the testnet's depth limit");
	assert_eq!(m.ok(&["info"])["server_info"]["fills"]["refresh_keeps_order"], true);
	// Every order first, then the takers' coins: a fill is paid with coins
	// that expire no earlier than the order's.
	let o = rest(&mut r, &m, 1_000_000).await;
	let o2 = rest(&mut r, &m, 500_000).await;
	let o3 = rest(&mut r, &m, 300_000).await;
	let o4 = rest(&mut r, &m, 400_000).await;
	let ta = holder(&mut r, "DL TA", y, 4_000_000).await;
	let tb = holder(&mut r, "DL TB", y, 4_000_000).await;
	let tc = holder(&mut r, "DL TC", y, 2_000_000).await;
	let td = holder(&mut r, "DL TD", y, 2_000_000).await;

	// 1. Three part fills, then a refresh at three reassignments deep.
	for k in 1..=3 {
		fill(&ta, &o, Some(100_000));
		let st = served(&ta, &o);
		println!("DL O after part fill {}: hops {} fills_left {} value {} whole_only {}", k, st["hops"], st["fills_left"], st["value"],
			st["whole_only"]);
		assert_eq!(hops_of(&st), k, "{}", st);
	}
	m.ok(&["sync"]);
	let before = served(&ta, &o);
	assert_eq!((before["value"].as_str(), before["fills_left"].as_u64(), before["whole_only"].as_bool()), (Some("700000"), Some(1), Some(false)));
	let (q, _) = refresh(&m, &o);
	println!("DL REFRESH QUOTE: {}", q);
	assert_eq!((q["coin"].clone(), q["keeps"].as_str(), q["depth"].as_u64()), (before["coin"].clone(), Some("700000"), Some(3)), "{}", q);
	let during = served(&ta, &o);
	println!("DL O while its refresh waits for a round: {}", during["state"]);
	assert_eq!(during["state"], "refreshing");
	fill_refused(&ta, &o, Some(100_000), "takes no fill");
	let (ok, e) = m.run(&["order", "cancel-resting", &o, "--quote"]);
	assert!(!ok && e.to_string().contains("being refreshed"), "{}", e);
	rounds(&mut r, &[&m]).await;
	let after = served(&ta, &o);
	let mine = view(&m, Some(&o), None);
	println!("DL O REFRESHED: wallet {} | operator state {} coin {} value {} hops {} fills_left {}", mine["state"], after["state"],
		after["coin"], after["value"], after["hops"], after["fills_left"]);
	assert_eq!(mine["state"], "published", "{}", mine);
	assert_eq!(after["order"], json!(o), "the same order id");
	assert_ne!(after["coin"], before["coin"], "a fresh coin");
	assert_eq!((after["state"].as_str(), after["value"].as_str(), hops_of(&after), after["fills_left"].as_u64()),
		(Some("resting"), Some("700000"), 0, Some(4)));
	assert_eq!(landed(&after["terms"]), landed(&before["terms"]), "the same pair, rate, lot, expiry and landing");
	assert_eq!(after["asset"], before["asset"]);
	assert_eq!(server_state(&r, before["coin"].as_str().unwrap()), "Spent", "the old coin is given up in the round");
	// The order's coin is a round's now, expiring later than the takers'
	// coins: they refresh theirs to fill it.
	ta.ok(&["participate"]);
	tb.ok(&["participate"]);
	rounds(&mut r, &[&ta, &tb]).await;

	// 2. Two more part fills, the second from a coin three deep: the order at
	//    four. A sixth part fill is refused; the cancel goes.
	fill(&tb, &o, Some(100_000));
	assert_eq!(hops_of(&served(&ta, &o)), 1);
	println!("DL TA's coins of Y before deepening: {:?}", live_hops(&ta, y));
	deepen(&ta, y, 3);
	fill(&ta, &o, Some(100_000));
	let st = served(&ta, &o);
	println!("DL O after five part fills: hops {} whole_only {} value {}", st["hops"], st["whole_only"], st["value"]);
	assert_eq!((hops_of(&st), st["whole_only"].as_bool(), st["value"].as_str()), (4, Some(true), Some("500000")));
	let e = fill_refused(&tb, &o, Some(100_000), "only a fill of the whole remainder");
	println!("DL REFUSED, a sixth part fill: {}", e);
	m.ok(&["sync"]);
	let cq = m.ok(&["order", "cancel-resting", &o, "--quote"]);
	let c = m.ok(&["order", "cancel-resting", &o, "--shown", &cq.to_string()]);
	println!("DL O CANCELLED at four reassignments: {} gets {}", c["state"], cq["gets"]["amount"]);
	assert_eq!(c["state"], "cancelled");
	assert_eq!(served(&ta, &o)["state"], "cancelled");

	// 3. O2: a part fill from a coin four deep is refused; three part fills
	//    bring it to four; a part is refused, the whole remainder taken.
	println!("DL TA's coins of Y: {:?}", live_hops(&ta, y));
	let e = fill_refused(&ta, &o2, Some(100_000), "would land at the operator's depth limit");
	println!("DL REFUSED, a part fill from coins four deep: {}", e);
	for k in 2..=4 {
		fill(&tb, &o2, Some(50_000));
		let st = served(&tb, &o2);
		println!("DL O2: hops {} fills_left {}", st["hops"], st["fills_left"]);
		assert!(hops_of(&st) <= k);
	}
	let st = served(&tb, &o2);
	assert_eq!((hops_of(&st), st["whole_only"].as_bool()), (4, Some(true)), "{}", st);
	fill_refused(&tb, &o2, Some(50_000), "only a fill of the whole remainder");
	let whole = fill(&tb, &o2, None);
	println!("DL O2's whole remainder taken: {} for {}", whole["filled"], whole["paid"]);
	assert_eq!(whole["filled"], st["value"]);
	assert_eq!(served(&tb, &o2)["state"], "filled");

	// 4. O3's refresh fails mid-round: the order rests where it was.
	let at = served(&tb, &o3)["coin"].as_str().unwrap().to_string();
	let (_, a3) = refresh(&m, &o3);
	let pid = a3["participation"].as_str().unwrap().to_string();
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	assert_eq!(built.len(), 1, "the refresh's round, held for the maker's forfeits");
	fill_refused(&tb, &o3, Some(50_000), "takes no fill");
	// The forfeits never come: the operator drops the round.
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 700));
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	let round = r.server.store.round_by_txid(&elements::hashes::Hash::to_byte_array(built[0].tx.txid())).await.unwrap().unwrap().state;
	println!("DL O3's REFRESH ROUND: {:?} | the order's coin at the operator: {}", round, server_state(&r, &at));
	assert_eq!(round, RoundState::Lost, "dropped before broadcast");
	// However the operator treats the participation then (given back, or run
	// again), a participation voided gives the coin back.
	let id: [u8; 32] = unhex(&pid).try_into().unwrap();
	let voided = r.server.store.void_participation(&id, "its round was lost").await.unwrap();
	println!("DL O3's participation {} voided now: {}", pid, voided);
	let s = m.ok(&["sync"]);
	println!("DL M's sync after the lost round: {}", s["resting"]);
	let st = served(&tb, &o3);
	let mine = view(&m, Some(&o3), None);
	println!("DL O3 after its failed refresh: wallet {} | operator {} at {} value {} | operator's leaf {}", mine["state"], st["state"],
		st["coin"], st["value"], server_state(&r, &at));
	assert_eq!((st["state"].as_str(), st["coin"].as_str(), st["value"].as_str()), (Some("resting"), Some(at.as_str()), Some("300000")));
	assert_eq!(mine["state"], "published");
	fill(&td, &o3, Some(50_000));
	assert_eq!(served(&tb, &o3)["value"], "250000", "filled after its failed refresh");

	// 5. The testnet's stuck order: O4 four deep, then the operator's limit
	//    at four.
	deepen(&tc, y, 3);
	fill(&tc, &o4, Some(100_000));
	assert_eq!(hops_of(&served(&tc, &o4)), 4);
	m.ok(&["sync"]);
	r.config.depth_limit = Some(4);
	r.restart_server().await;
	assert_eq!(m.ok(&["info"])["server_info"]["depth_limit"], 4);
	let st = served(&tc, &o4);
	println!("DL O4 at the operator's limit: hops {} whole_only {}", st["hops"], st["whole_only"]);
	let cq = m.ok(&["order", "cancel-resting", &o4, "--quote"]);
	let (ok, e) = m.run(&["order", "cancel-resting", &o4, "--shown", &cq.to_string()]);
	println!("DL REFUSED, O4's cancel at the limit: {}", e);
	assert!(!ok && e.to_string().contains("depth_limit"), "{}", e);
	fill_refused(&tb, &o4, Some(50_000), "co-signs no fill of it until its maker refreshes it");
	let e = fill_refused(&tb, &o4, None, "co-signs no fill of it until its maker refreshes it");
	println!("DL REFUSED, any fill of O4 at the limit: {}", e);
	refresh(&m, &o4);
	rounds(&mut r, &[&m]).await;
	let st = served(&tc, &o4);
	println!("DL O4 REFRESHED: {} at {} value {} hops {} fills_left {}", st["state"], st["coin"], st["value"], st["hops"], st["fills_left"]);
	assert_eq!((st["state"].as_str(), st["value"].as_str(), hops_of(&st)), (Some("resting"), Some("300000"), 0));
	let cq = m.ok(&["order", "cancel-resting", &o4, "--quote"]);
	let c = m.ok(&["order", "cancel-resting", &o4, "--shown", &cq.to_string()]);
	assert_eq!(c["state"], "cancelled");
	let home = c["transfer"].to_string();
	println!("DL O4 HOME: cancelled into the maker's own leaf, {} of X ({})", cq["gets"]["amount"], home.chars().take(200).collect::<String>());
	assert!(live_hops(&m, x).iter().any(|(_, v, h)| v.to_string() == cq["gets"]["amount"].as_str().unwrap() && *h == 1),
		"the maker holds what rested, one reassignment from the refresh's round: {:?}", live_hops(&m, x));
	for w in [&m, &ta, &tb, &tc, &td] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
