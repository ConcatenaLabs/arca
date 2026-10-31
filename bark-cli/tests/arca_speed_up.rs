//! Speeding up the wallet's own transactions on the chain (child pays for
//! parent), and refreshing what it receives out of round at the next round.
//!
//! A transaction is made to wait in the mempool the way it does on a live
//! chain: its fee asset's rate falls after it is broadcast, so the fee it
//! pays is worth less than the producer's floor. It stays in the mempool and
//! no block takes it, until a child pays for it.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::str::FromStr;

use elements::{AssetId, OutPoint, Script, Transaction, TxIn, TxOut, Txid};
use serde_json::Value;

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

fn create_args<'a>(server: &'a str, node: &'a str) -> Vec<&'a str> {
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

fn coin_of(w: &Arca, leaf: &str) -> Value {
	w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).cloned().unwrap_or(Value::Null)
}

fn record_of(w: &Arca, leaf: &str) -> CoinRecord {
	CoinRecord::from_bytes(&unhex(w.ok(&["record", leaf])["record"].as_str().unwrap())).unwrap()
}

/// Creates `w` on `server` and boards `amount` of each asset of `assets`;
/// waits until every board is final and credited.
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
	boards
}

async fn final_round(r: &Running) -> Transaction {
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	built.tx
}

/// A batch leaf of `w`'s, from boarding `amount` of `asset` and refreshing
/// it in a round, with that round.
async fn batch_leaf(r: &mut Running, w: &Arca, amount: u64) -> (String, Transaction) {
	let url = r.url();
	let x = r.x;
	boarded(r, w, &url, &[(x, amount)]).await;
	w.ok(&["participate"]);
	let round = final_round(r).await;
	let s = w.ok(&["sync"]);
	let leaf = s["participations"][0]["new_leaves"][0]["leaf_id"].as_str().expect("a new leaf").to_string();
	(leaf, round)
}

fn rpc(r: &Running, method: &str, params: &[Value]) -> Value {
	r.rt.client().call(method, params).unwrap()
}

fn in_mempool(r: &Running, txid: &str) -> bool {
	rpc(r, "getrawmempool", &[]).as_array().unwrap().iter().any(|t| t == txid)
}

fn confirmations(r: &Running, txid: &str) -> i64 {
	let v: Value = rpc(r, "getrawtransaction", &[serde_json::json!(txid), serde_json::json!(true)]);
	v["confirmations"].as_i64().unwrap_or(0)
}

/// The fee asset `asset`'s rate set to `rate` on the node: halving it halves
/// what every fee already paid in it is worth.
fn rate_of(r: &Running, asset: AssetId, rate: u64) {
	common::node::list_fee_asset(&r.rt, asset, rate);
}

/// The transactions in the mempool that spend an output of `round`, and
/// every descendant of theirs: an exit's steps from that round down.
fn waiting_from(r: &Running, round: &Transaction) -> Vec<String> {
	let pool: Vec<String> = rpc(r, "getrawmempool", &[]).as_array().unwrap().iter().map(|t| t.as_str().unwrap().to_string()).collect();
	let mut out = vec![];
	for t in &pool {
		let tx: Value = rpc(r, "getrawtransaction", &[serde_json::json!(t), serde_json::json!(true)]);
		if tx["vin"].as_array().unwrap().iter().any(|i| i["txid"] == round.txid().to_string()) {
			out.push(t.clone());
			for d in rpc(r, "getmempooldescendants", &[serde_json::json!(t)]).as_array().unwrap() {
				out.push(d.as_str().unwrap().to_string());
			}
		}
	}
	out
}

fn txids_of(exit: &Value) -> Vec<String> {
	exit["broadcast"].as_array().map(|b| b.iter().map(|s| s["txid"].as_str().unwrap().to_string()).collect()).unwrap_or_default()
}

/// Whether `txid` pays a P2WPKH output: an exit step's other outputs are
/// the covenant's, so this is its anchor, the output a child spends.
fn has_anchor(r: &Running, txid: &str) -> bool {
	let tx: Value = rpc(r, "getrawtransaction", &[serde_json::json!(txid), serde_json::json!(true)]);
	tx["vout"].as_array().unwrap().iter().any(|o| o["scriptPubKey"]["type"] == "witness_v0_keyhash")
}

/// A stuck exit is rescued by a child. A batch leaf's exit is broadcast, and
/// its fee asset's rate halves at once, so no block takes its steps. Two
/// blocks later the wallet's `sync` speeds the exit up by a child spending
/// the steps' anchor, which takes every step into the next block; the exit
/// then goes on to its claim. A plain `exit` run again speeds nothing up.
#[tokio::test(flavor = "multi_thread")]
async fn a_stuck_exit_is_rescued_by_a_child() {
	let mut r = Running::start().await;
	let x = r.x;
	let a = Arca::new("CP1A");
	let (leaf, round) = batch_leaf(&mut r, &a, 1_000_000).await;
	println!("CP1 stuck: A's leaf {} of round {}", &leaf[..8], round.txid());

	let e = a.ok(&["exit", &leaf]);
	let steps = txids_of(&e);
	println!("CP1 stuck: the exit broadcast {} steps: {}", steps.len(), e["broadcast"]);
	assert!(!steps.is_empty(), "{}", e);
	assert!(steps.iter().any(|t| has_anchor(&r, t)), "a step leaves the wallet an output to speed it up from");
	// The fee asset's price halves: every step's fee is worth less than the floor.
	rate_of(&r, x, 50_000_000);
	let s = a.ok(&["sync"]);
	assert!(s["exits"][0]["sped_up"].is_null(), "nothing has waited yet: {}", s["exits"]);
	for _ in 0..2 {
		r.produce().await;
	}
	for t in &steps {
		assert!(in_mempool(&r, t) && confirmations(&r, t) == 0, "step {} waits in the mempool, no block takes it", t);
	}
	// Run again, `exit` broadcasts again and speeds nothing up.
	let e = a.ok(&["exit", &leaf]);
	assert!(e["sped_up"].is_null(), "{}", e);
	r.produce().await;
	assert!(steps.iter().all(|t| in_mempool(&r, t)), "still waiting");

	let s = a.ok(&["sync"]);
	let sped = s["exits"][0]["sped_up"].clone();
	println!("CP1 stuck: sync sped the exit up: {}", sped);
	let child = sped["child"].as_str().unwrap_or_else(|| panic!("a child: {}", s["exits"])).to_string();
	assert_eq!(sped["fee"]["asset"], x.to_string(), "the child pays in the coin's own asset, which the node accepts");
	let spent = sped["spends"].as_str().unwrap().split(':').next().unwrap().to_string();
	assert!(steps.contains(&spent), "the child spends a step's anchor: {}", sped);
	println!("CP1 stuck: the anchors held {} atoms; a coin of the wallet's on the chain paid the rest: {}", sped["output_value"],
		!sped["second_input"].is_null());
	let note = coin_of(&a, &leaf)["note"].as_str().unwrap_or("").to_string();
	assert!(note.contains("sped it up"), "{}", note);
	r.produce().await;
	for t in steps.iter().chain(std::iter::once(&child)) {
		assert!(confirmations(&r, t) >= 1, "{} is mined with its child", t);
	}
	let entry: Value = rpc(&r, "getrawtransaction", &[serde_json::json!(child), serde_json::json!(true)]);
	println!("CP1 stuck: child {} of {} vB, every step mined in the next block", &child[..16], entry["vsize"]);

	// The exit goes on to its claim.
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 512));
	let e = a.ok(&["exit", &leaf]);
	assert_eq!(e["state"], "claimed", "{}", e);
	r.produce().await;
	r.bury().await;
	a.ok(&["sync"]);
	assert_eq!(coin_of(&a, &leaf)["state"], "exited");
	let _ = std::fs::remove_dir_all(&a.dir);
}

/// A solo exit beats a hostile operator's stale-fee race. Two holders, A and
/// B, each with a batch leaf of a batch the operator releases at its expiry;
/// each starts its exit during the notice, and the fee asset's price halves
/// as they do, so the reserves' fees no longer reach the producer's floor.
/// A's wallet syncs and speeds its exit up: its leaf is in a block well
/// before the notice runs out. B's wallet only runs `exit`, which never pays
/// more: its steps still wait at the notice's end. The fee asset then stops
/// being accepted, which empties the mempool of B's steps, and the
/// operator's sweep takes B's batch with B's coin in it. A's coin is home.
#[tokio::test(flavor = "multi_thread")]
async fn a_solo_exit_beats_a_hostile_operators_stale_fee_race() {
	let mut r = Running::start_sweeping().await;
	let x = r.x;
	let (a, b) = (Arca::new("CP1RA"), Arca::new("CP1RB"));
	let (la, ra) = batch_leaf(&mut r, &a, 1_000_000).await;
	let (lb, rb) = batch_leaf(&mut r, &b, 1_000_000).await;
	let CoinRecord::Leaf { record, .. } = record_of(&b, &lb) else { panic!("a batch leaf") };
	let notice = record.schedule.notice.seconds() as u32;
	let expiry = coin_of(&b, &lb)["expiry"].as_u64().unwrap() as u32;
	println!("CP1 race: A's leaf {} (round {}), B's {} (round {}), expiry {}, notice {} s", &la[..8], ra.txid(), &lb[..8], rb.txid(), expiry, notice);

	// The operator releases both batches at their expiry.
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, expiry.max(now) - now + 600));
	r.synced().await;
	for _ in 0..2 {
		let _ = r.server.watcher.pass().await;
		r.produce().await;
		r.synced().await;
	}
	// Each wallet's re-check, past the expiry, starts its exit: run once more,
	// and read each exit's steps from the mempool, from its round down.
	a.ok(&["exit", &la]);
	b.ok(&["exit", &lb]);
	let (sa, sb) = (waiting_from(&r, &ra), waiting_from(&r, &rb));
	println!("CP1 race: A's steps waiting {:?}, B's {:?}", sa, sb);
	assert!(!sa.is_empty() && !sb.is_empty());
	rate_of(&r, x, 50_000_000);
	a.ok(&["sync"]);
	for _ in 0..2 {
		r.produce().await;
	}
	let s = a.ok(&["sync"]);
	println!("CP1 race: A's sync: {}", s["exits"][0]["sped_up"]);
	assert!(s["exits"][0]["sped_up"]["child"].is_string(), "{}", s["exits"]);
	r.produce().await;
	let at = common::node::median_time(&r.rt);
	for t in &sa {
		assert!(confirmations(&r, t) >= 1, "A's step {} is mined", t);
	}
	println!("CP1 race: A's steps mined at median time {}, {} s before the notice runs out", at, (expiry + notice) as i64 - at as i64);
	assert!(at < expiry + notice);
	// B ran only `exit`: its steps still wait as the notice runs out.
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, (expiry + notice + 600).saturating_sub(now)));
	b.ok(&["exit", &lb]);
	for t in &sb {
		assert!(in_mempool(&r, t) && confirmations(&r, t) == 0, "B's step {} still waits", t);
	}
	// The producer stops taking the fee asset: B's steps leave the mempool.
	rate_of(&r, x, 0);
	assert!(sb.iter().all(|t| !in_mempool(&r, t)), "B's steps are dropped with their fee asset");
	rate_of(&r, x, 100_000_000);
	let batch = match record_of(&b, &lb) {
		CoinRecord::Leaf { record, .. } => record.branch().unwrap().batch_output(),
		_ => unreachable!(),
	};
	let vout = rb.output.iter().position(|o| arca_covenant::ExplicitOutput::from_txout(o).as_ref() == Some(&batch)).unwrap() as u32;
	let batch_at = OutPoint::new(rb.txid(), vout);
	let mut swept = None;
	for _ in 0..30 {
		let _ = r.server.watcher.pass().await;
		r.produce().await;
		r.synced().await;
		let spent: Value = rpc(&r, "gettxout", &[serde_json::json!(batch_at.txid.to_string()), serde_json::json!(batch_at.vout), serde_json::json!(false)]);
		if spent.is_null() {
			swept = Some(());
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;
	}
	assert!(swept.is_some(), "the operator sweeps B's batch");
	r.bury().await;
	r.synced().await;
	b.ok(&["sync"]);
	let cb = coin_of(&b, &lb);
	println!("CP1 race: B's coin: {} | {}", cb["state"], cb["note"]);
	assert_eq!(cb["state"], "lost", "{}", cb);
	// A's exit goes on to its claim.
	let e = a.ok(&["exit", &la]);
	assert!(matches!(e["state"].as_str(), Some("claimed" | "waiting")), "{}", e);
	r.produce().await;
	r.bury().await;
	a.ok(&["exit", &la]);
	r.produce().await;
	r.bury().await;
	a.ok(&["sync"]);
	assert_eq!(coin_of(&a, &la)["state"], "exited", "A's coin is home");
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A coin of an asset no node accepts for fees, coming home to the wallet's
/// address in a transaction that waits, is sped up by a child that adds a
/// second input in an accepted asset to pay the fee. Naming the coin's own
/// asset for the fee is refused before anything is signed.
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_no_node_takes_for_fees_is_sped_up_by_a_second_input() {
	let mut r = Running::start().await;
	let url = r.url();
	let (x, y) = (r.x, r.y);
	let a = Arca::new("CP1Y");
	// A holds X on the chain beside its board.
	boarded(&mut r, &a, &url, &[(x, 1_000_000)]).await;
	let to = script(&a.ok(&["address"]));
	// Y arrives at A's address, its fee in X at the floor.
	let yc = r.purse.take_coin(y);
	let xc = r.purse.take_coin(x);
	let (yv, xv) = (yc.1.value.explicit().unwrap(), xc.1.value.explicit().unwrap());
	let fee = 35;
	let op_true = common::node::op_true();
	let explicit = |a: AssetId, v: u64, s: Script| TxOut {
		asset: elements::confidential::Asset::Explicit(a), value: elements::confidential::Value::Explicit(v),
		nonce: elements::confidential::Nonce::Null, script_pubkey: s, witness: Default::default(),
	};
	let tx = Transaction {
		version: 2, lock_time: elements::LockTime::ZERO,
		input: vec![TxIn { previous_output: yc.0, ..Default::default() }, TxIn { previous_output: xc.0, ..Default::default() }],
		output: vec![explicit(y, 700_000, to.clone()), explicit(y, yv - 700_000, op_true.clone()), explicit(x, xv - fee, op_true.clone()),
			TxOut::new_fee(fee, x)],
	};
	let parent = r.rt.client().send_raw_transaction(&tx).unwrap();
	println!("CP1 second input: Y comes home in {} ({} vB, {} atoms of X in fees)", parent, tx.vsize(), fee);
	rate_of(&r, x, 50_000_000);
	r.produce().await;
	assert!(in_mempool(&r, &parent.to_string()), "it waits");

	let refused = a.refused(&["speed-up", &parent.to_string(), "--fee-asset", &y.to_string()], "not accepted for fees");
	println!("CP1 second input: the coin's own asset for the fee: {}", refused);
	let v = a.ok(&["speed-up", &parent.to_string()]);
	println!("CP1 second input: {}", v);
	assert_eq!(v["asset_of_output"], y.to_string());
	assert_eq!(v["fee"]["asset"], x.to_string(), "the fee in an accepted asset");
	let second = v["second_input"].as_str().expect("a second input").to_string();
	let child = Txid::from_str(v["child"].as_str().unwrap()).unwrap();
	let c = r.rt.client().raw_transaction(&child).unwrap();
	assert_eq!(c.input.len(), 2);
	let op = c.input[1].previous_output;
	assert_eq!(format!("{}:{}", op.txid, op.vout), second);
	assert!(c.output.iter().any(|o| o.asset.explicit() == Some(y) && o.value.explicit() == Some(700_000)), "the Y comes back whole");
	assert!(c.output.iter().filter(|o| o.is_fee()).all(|o| o.asset.explicit() == Some(x)));
	r.produce().await;
	assert!(confirmations(&r, &parent.to_string()) >= 1 && confirmations(&r, &child.to_string()) >= 1, "both mined");
	println!("CP1 second input: child {} of {} vB; both mined", child, c.vsize());
	// Nothing left to speed up.
	a.refused(&["speed-up", &parent.to_string()], "in a block already");
	let _ = std::fs::remove_dir_all(&a.dir);
}

/// A coin received out of round is refreshed at the next round: B's
/// `refresh-received` gives it up for a batch leaf of its own. A's change
/// from paying B, from A's own board, is not a coin received from another,
/// and stays as it is.
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_received_out_of_round_is_refreshed_at_the_next_round() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let (a, b) = (Arca::new("CP1RecA"), Arca::new("CP1RecB"));
	boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	b.ok(&create_args(&url, &r.node_url()));
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req, "--amount", "600000", "--asset", &x.to_string()]);
	let mb = b.ok(&["mailbox"]);
	let got = mb["accepted"][0]["leaf_id"].as_str().expect("B holds the coin").to_string();
	assert_eq!(coin_of(&b, &got)["standing"], "operator-confirmed");

	let ra = a.ok(&["refresh-received"]);
	println!("CP1 received: A's refresh-received: {}", ra);
	assert_eq!(ra["participations"].as_array().unwrap().len(), 0, "A's change is its own: {}", ra);
	let rb = b.ok(&["refresh-received"]);
	println!("CP1 received: B's refresh-received: {}", rb);
	assert_eq!(rb["refreshed"][0], got.as_str(), "{}", rb);
	assert_eq!(coin_of(&b, &got)["state"], "given");
	final_round(&r).await;
	let s = b.ok(&["sync"]);
	let p = &s["participations"][0];
	println!("CP1 received: B's participation: {} {}", p["state"], p["new_leaves"]);
	assert_eq!(p["state"], "released", "{}", s);
	let new = p["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	let c = coin_of(&b, &new);
	assert_eq!((c["kind"].as_str().unwrap(), c["state"].as_str().unwrap()), ("batch", "live"), "{}", c);
	assert_eq!(c["standing"], "live", "no longer resting on its senders");
	// Nothing left to refresh.
	let again = b.ok(&["refresh-received"]);
	assert_eq!(again["participations"].as_array().unwrap().len(), 0, "{}", again);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
