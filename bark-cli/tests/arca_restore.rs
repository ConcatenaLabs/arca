//! A wallet restored from its mnemonic alone, against a whole Arca server on
//! an anchored proof-of-stake regtest chain: what it recovers, checked, and
//! that it ends where the wallet it replaces would be.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use elements::{AssetId, Script, Transaction};
use serde_json::{json, Value};

use arca_covenant::CoinRecord;
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
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca", "--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

fn coin_of(w: &Arca, leaf: &str) -> Value {
	w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).cloned().unwrap_or(Value::Null)
}

/// `w` created against `server`, its boards of `assets` registered and
/// credited.
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
	r.wait("the boards to be credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
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

/// Every coin of `coins`, by its id.
fn by_id(coins: &Value) -> BTreeMap<String, Value> {
	coins.as_array().unwrap().iter().map(|c| (c["leaf_id"].as_str().unwrap().to_string(), c.clone())).collect()
}

/// Where two lists of coins differ, field by field.
fn differences(a: &Value, b: &Value) -> Vec<String> {
	let (a, b) = (by_id(a), by_id(b));
	let mut out = vec![];
	for id in a.keys().chain(b.keys()).collect::<std::collections::BTreeSet<_>>() {
		match (a.get(id), b.get(id)) {
			(Some(x), Some(y)) => {
				for (k, v) in x.as_object().unwrap() {
					if y.get(k) != Some(v) {
						out.push(format!("{} {}: {} | {}", &id[..16], k, v, y.get(k).unwrap_or(&Value::Null)));
					}
				}
				for k in y.as_object().unwrap().keys() {
					if x.get(k).is_none() {
						out.push(format!("{} {}: (none) | {}", &id[..16], k, y[k]));
					}
				}
			},
			(Some(_), None) => out.push(format!("{}: held before, not restored", id)),
			(None, Some(_)) => out.push(format!("{}: restored, not held before", id)),
			(None, None) => {},
		}
	}
	out
}

/// A wallet's schedule without the time it was read at, its coins by id:
/// the store lists them in the order it took them, which a restore cannot
/// know.
fn schedule(s: &Value) -> Value {
	let mut s = s.clone();
	s.as_object_mut().unwrap().remove("now");
	if let Some(c) = s["coins"].as_array_mut() {
		c.sort_by_key(|x| x["leaf_id"].as_str().unwrap_or("").to_string());
	}
	s
}

/// A holds a leaf of a batch, a board, a coin paid out of round resting on a
/// board (its change), a payment to it not yet read, a board given up in a
/// refresh whose forfeit is signed and not co-signed (the keeper down), and a
/// board in a block not yet final; and coins it spent, in a payment and in a
/// refresh. Its device is lost. A2, created from A's mnemonic alone, restores
/// every one of them from what the server serves to its mailbox key, each
/// checked, and holds no other. After a sync each, A2's `coins`, `balance` and
/// schedule are A's, but for the one thing a restore cannot know: receive
/// requests handed out and never paid, for which its schedule holds at a day
/// until they could lapse, until the user says none was outstanding. The
/// refresh then completes in both; with the server stopped, A2 takes its
/// batch leaf on the chain from the published tree, its authorisations signed
/// again from the mnemonic.
#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_restored_from_its_mnemonic_ends_where_the_lost_one_was() {
	let mut r = Running::start_kept(1, None).await;
	let (url, node) = (r.url(), r.node_url());
	let x = r.x;
	let xs = x.to_string();
	let p = Proxy::start(&url);
	let (a, b, a2) = (Arca::new("RSA"), Arca::new("RSB"), Arca::new("RSA2"));
	let boards = boarded(&mut r, &a, &p.url.clone(), &[(x, 2_000_000), (x, 2_000_000), (x, 2_000_000), (x, 2_000_000)]).await;
	boarded(&mut r, &b, &url, &[(x, 3_000_000)]).await;

	// Out of round: A pays B; its change rests on the board it paid from.
	let req_b = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let sent = a.ok(&["send", &req_b, "--amount", "600000", "--asset", &xs]);
	let paid_from = sent["inputs"][0].as_str().unwrap().to_string();
	let change = sent["transfer"]["kept"][0]["leaf_id"].as_str().unwrap().to_string();
	b.ok(&["sync"]);
	let left: Vec<String> = boards.iter().filter(|l| **l != paid_from).cloned().collect();
	// A leaf of a batch: a board refreshed.
	a.ok(&["participate", "--leaf", &left[0], "--max-fee-ppm", "1000000"]);
	final_round(&r).await;
	let s = a.ok(&["sync"]);
	let leaf = s["participations"][0]["new_leaves"][0]["leaf_id"].as_str().expect("the refresh's leaf").to_string();
	// A payment to A, which A does not read before the loss.
	let req_a = a.ok(&["receive"])["request"].as_str().unwrap().to_string();
	b.ok(&["send", &req_a, "--amount", "500000", "--asset", &xs]);
	// A board given up in a refresh: its forfeit is signed, and not co-signed,
	// the keeper down. A's mailbox is hidden from that sync, so the payment
	// stays unread.
	a.ok(&["participate", "--leaf", &left[1], "--max-fee-ppm", "1000000"]);
	final_round(&r).await;
	r.keepers[0].halt();
	p.rewrite(Some(Arc::new(|path: &str, _: &Value, _: u16, v: &mut Value| {
		if path == "/v1/mailbox_read" {
			v["messages"] = json!([]);
		}
		None
	})));
	let s = a.ok(&["sync"]);
	p.rewrite(None);
	println!("RS A's sync, the keeper down: participations {}", s["participations"]);
	assert_eq!(coin_of(&a, &left[1])["state"], "forfeited");
	// A board in a block, not final.
	let pending = a.ok(&["board", &xs, "1500000"])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	assert_eq!(coin_of(&a, &pending)["state"], "pending");
	let still = left[2].clone();
	println!("RS A before the loss: paid from {}, change {}, batch leaf {}, board {}, forfeited {}, pending {}", &paid_from[..16], &change[..16],
		&leaf[..16], &still[..16], &left[1][..16], &pending[..16]);
	let before = a.ok(&["coins"]);

	// The loss: A2 from A's mnemonic alone.
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap();
	let mut args = create_args(&url, &node);
	args.extend(["--mnemonic", mnemonic.trim()]);
	let made = a2.ok(&args);
	let restore = &made["restore"];
	println!("RS A2's restore: served {} | restored {} | not recovered {} | notes {} | mailbox {}", restore["served"], restore["restored"],
		restore["not_recovered"], restore["notes"], restore["mailbox"]);
	assert!(restore["error"].is_null(), "{}", restore);
	assert_eq!(restore["not_recovered"], json!([]), "{}", restore);

	// A syncs, and reads its payment; A2 syncs. Both at one tip.
	let sa = a.ok(&["sync"]);
	let unread = sa["mailbox"]["accepted"][0]["leaf_id"].as_str().expect("A reads its payment").to_string();
	let sa2 = a2.ok(&["sync"]);
	let (ca, ca2) = (a.ok(&["coins"]), a2.ok(&["coins"]));
	let diff = differences(&ca, &ca2);
	println!("RS A's coins: {}", ca);
	println!("RS A2's coins: {}", ca2);
	println!("RS coins differing (A | A2): {:?}", diff);
	assert_eq!(by_id(&ca).len(), by_id(&before).len() + 1, "A holds the payment it read besides what it held");
	for (id, want) in [(&paid_from, "spent"), (&change, "live"), (&left[0], "spent"), (&leaf, "live"), (&still, "live"), (&left[1], "forfeited"),
		(&pending, "pending"), (&unread, "live")]
	{
		assert_eq!(coin_of(&a2, id)["state"], want, "A2's coin {}", id);
	}
	assert!(diff.is_empty(), "A2's coins are A's: {:?}", diff);
	let (ba, ba2) = (a.ok(&["balance"]), a2.ok(&["balance"]));
	println!("RS balances: A {} | A2 {}", json!({"arca": ba["arca"], "onchain": ba["sequentia_onchain"]}),
		json!({"arca": ba2["arca"], "onchain": ba2["sequentia_onchain"]}));
	assert_eq!((&ba["arca"], &ba["sequentia_onchain"], &ba["rows"]), (&ba2["arca"], &ba2["sequentia_onchain"], &ba2["rows"]));
	let (ha, ha2) = (schedule(&sa["schedule"]), schedule(&sa2["schedule"]));
	println!("RS schedules: A {} | A2 {}", ha, ha2);
	assert_eq!(ha["coins"], ha2["coins"], "every coin's dates");
	let restored = ha2["receive_requests"].as_array().unwrap().iter().find(|q| q["owner"] == "restored").cloned().expect("the restore's hold");
	assert_eq!(restored["state"], "waiting");
	assert!(ha2["next_sync_at"].as_u64().unwrap() <= sa2["schedule"]["now"].as_u64().unwrap() + 86_400);
	a2.ok(&["forget-request", "restored"]);
	let sa = a.ok(&["sync"]);
	let sa2 = a2.ok(&["sync"]);
	let (ha, ha2) = (schedule(&sa["schedule"]), schedule(&sa2["schedule"]));
	println!("RS schedules, the hold forgotten: A {} | A2 {}", ha, ha2);
	assert_eq!(ha, ha2, "the schedule is A's");
	let pa2 = a2.ok(&["participations"]);
	println!("RS A2's participations: {}", pa2);

	// The keeper back: the server completes the forfeit and releases the
	// refresh; both wallets take its new leaf.
	r.keepers[0].resume();
	let filled = r.server.forfeits.fill_unsigned().await.unwrap();
	r.server.rounds.pass().await.unwrap();
	let sa = a.ok(&["sync"]);
	let sa2 = a2.ok(&["sync"]);
	println!("RS the keeper back ({} filled): A {} | A2 {}", filled, sa["participations"], sa2["participations"]);
	let (ca, ca2) = (a.ok(&["coins"]), a2.ok(&["coins"]));
	let diff = differences(&ca, &ca2);
	println!("RS coins differing after the release (A | A2): {:?}", diff);
	assert_eq!(coin_of(&a2, &left[1])["state"], "spent");
	assert!(diff.is_empty(), "{:?}", diff);

	// The batch leaf, as A2 holds it: rebuilt from the published tree, its
	// authorisations signed again. The server stopped, A2 takes it on the
	// chain.
	let (ra, ra2) = (a.ok(&["record", &leaf]), a2.ok(&["record", &leaf]));
	assert_eq!(ra["detail"], ra2["detail"], "the same leaf");
	println!("RS the batch leaf's record: A's and A2's differ only in the authorisations: {}", ra["record"] != ra2["record"]);
	r.server.stop();
	let e = a2.ok(&["exit", &leaf]);
	assert_eq!(e["state"], "unrolling", "{}", e);
	let steps = e["broadcast"].as_array().unwrap();
	println!("RS A2's exit of its batch leaf, the server stopped: {} transactions, {} vB", steps.len(),
		steps.iter().map(|s| s["vsize"].as_u64().unwrap()).sum::<u64>());
	r.produce().await;
	let e = a2.ok(&["exit", &leaf]);
	assert_eq!(e["state"], "waiting", "{}", e);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 512));
	let e = a2.ok(&["exit", &leaf]);
	assert_eq!(e["state"], "claimed", "{}", e);
	r.produce().await;
	let claim = elements::Txid::from_str(e["claim"]["txid"].as_str().unwrap()).unwrap();
	let tx = r.rt.client().raw_transaction(&claim).unwrap();
	println!("RS A2's claim {}: pays {:?} of {:?}", claim, tx.output[0].value.explicit(), tx.output[0].asset.explicit().map(|a| a.to_string()));
	r.bury().await;
	a2.ok(&["sync"]);
	assert_eq!(coin_of(&a2, &leaf)["state"], "exited");
	for w in [&a, &b, &a2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A wallet whose coins were made before wallets named their mailbox key
/// (its board registered without the binding, as an older wallet sends it):
/// a restore from its mnemonic finds nothing of them. Its next sync binds
/// every coin it holds, each with the coin's own key's signature, and a
/// restore then finds the board.
#[tokio::test(flavor = "multi_thread")]
async fn an_older_wallets_coins_are_bound_at_its_next_sync_and_then_restored() {
	let mut r = Running::start().await;
	let (url, node) = (r.url(), r.node_url());
	let x = r.x;
	let p = Proxy::start(&url);
	// What an older wallet sends: no mailbox in its board's registration.
	p.rewrite_request(Some(Arc::new(|path: &str, body: &mut Value| {
		if path == "/v1/register_board" {
			let o = body.as_object_mut().unwrap();
			o.remove("mailbox");
			o.remove("mailbox_proof");
		}
	})));
	let (o, o2, o3) = (Arca::new("RBO"), Arca::new("RBO2"), Arca::new("RBO3"));
	o.ok(&create_args(&p.url, &node));
	let s = script(&o.ok(&["address"]));
	r.pay_to(s, x, 5_000_000);
	r.produce().await;
	let board = o.ok(&["board", &x.to_string(), "2000000"])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || o.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	p.rewrite_request(None);
	// The store of a wallet from before: nothing marked bound.
	rusqlite::Connection::open(o.dir.join("arca.sqlite")).unwrap().execute("UPDATE coin SET bound = NULL", []).unwrap();
	let mnemonic = std::fs::read_to_string(o.dir.join("mnemonic")).unwrap();
	let mut args = create_args(&url, &node);
	args.extend(["--mnemonic", mnemonic.trim()]);
	let early = o2.ok(&args);
	println!("RBO a restore before the older wallet's sync: served {} | restored {}", early["restore"]["served"], early["restore"]["restored"]);
	assert_eq!(early["restore"]["served"], 0, "the board is not bound to the mailbox key: {}", early["restore"]);
	let s = o.ok(&["sync"]);
	println!("RBO the older wallet's sync: bound {}", s["bound"]);
	assert_eq!(s["bound"]["bound"], 1, "{}", s);
	assert_eq!(o.ok(&["sync"])["bound"], Value::Null, "bound once");
	let late = o3.ok(&args);
	println!("RBO a restore after it: served {} | restored {}", late["restore"]["served"], late["restore"]["restored"]);
	assert_eq!(late["restore"]["restored"][0]["leaf_id"], board.as_str(), "{}", late["restore"]);
	assert_eq!(coin_of(&o3, &board)["state"], "live");
	for w in [&o, &o2, &o3] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// Rewrites every `leaf_data` page with `f`, every published tree with `t`,
/// `info` and every head with `h`, and every mailbox page with `m`; any of
/// them may be `None`.
type Edit = fn(&mut Value, &Ctx);

/// What a case's edits need to know of the wallet's coins.
#[derive(Clone)]
struct Ctx {
	/// A's leaf of a batch, its board refreshed, the board it paid from, and
	/// the payment to A it has not read.
	leaf: String,
	refreshed: String,
	paid_from: String,
	unread: String,
	/// A board of another wallet, M: its id and record, as M holds it.
	other: String,
	other_record: String,
	other_owner: String,
	other_nonce: String,
}

fn entry_of<'a>(page: &'a mut Value, leaf: &str) -> Option<&'a mut Value> {
	page["leaves"].as_array_mut()?.iter_mut().find(|e| e["leaf_id"] == leaf)
}

fn every_head(v: &mut Value, f: &dyn Fn(&mut Value)) {
	match v {
		Value::Object(o) => {
			if o.contains_key("entry") && o.contains_key("hash") {
				f(v);
				return;
			}
			for (_, x) in o.iter_mut() {
				every_head(x, f);
			}
		},
		Value::Array(a) => a.iter_mut().for_each(|x| every_head(x, f)),
		_ => {},
	}
}

/// A record withheld: the payment to A served without its record, and
/// hidden from the mailbox too.
fn withhold_payment(page: &mut Value, c: &Ctx) {
	if let Some(e) = entry_of(page, &c.unread) {
		e["record"] = json!("");
	}
}

fn hide_payment(mailbox: &mut Value, c: &Ctx) {
	if let Some(m) = mailbox["messages"].as_array_mut() {
		m.retain(|x| x["leaf_id"] != c.unread.as_str());
	}
}

/// A record withheld: the leaf of the batch not served at all.
fn drop_leaf(page: &mut Value, c: &Ctx) {
	if let Some(l) = page["leaves"].as_array_mut() {
		l.retain(|e| e["leaf_id"] != c.leaf.as_str());
	}
}

/// The published tree without the preimage it publishes.
fn no_preimage(t: &mut Value, _: &Ctx) {
	for l in t["leaves"].as_array_mut().unwrap() {
		l.as_object_mut().unwrap().remove("preimage");
	}
}

/// A wrong tree: its batch output listed one atom more.
fn one_atom_more(t: &mut Value, _: &Ctx) {
	let levels = t["nodes"].as_array_mut().unwrap();
	let last = levels.last_mut().unwrap().as_array_mut().unwrap();
	let v: u64 = last[0]["value"].as_str().unwrap().parse().unwrap();
	last[0]["value"] = json!((v + 1).to_string());
}

/// A leaf of another key: M's board served to A's mailbox key, as a board of
/// A's would be.
fn another_keys_leaf(page: &mut Value, c: &Ctx) {
	let Some(template) = entry_of(page, &c.paid_from).cloned() else { return };
	let mut e = template;
	e["leaf_id"] = json!(c.other);
	e["record"] = json!(c.other_record);
	e["owner"] = json!(c.other_owner);
	e["owner_nonce"] = json!(c.other_nonce);
	e["state"] = json!("live");
	e["given"] = json!([]);
	page["leaves"].as_array_mut().unwrap().push(e);
}

/// An old copy of a leaf: the board A paid from, served as it was before the
/// payment, live and given up nowhere.
fn old_copy(page: &mut Value, c: &Ctx) {
	if let Some(e) = entry_of(page, &c.paid_from) {
		e["state"] = json!("live");
		e["given"] = json!([]);
	}
}

/// A keeper set not acknowledged: every head shown without the keepers'
/// acknowledgements.
fn no_acks(v: &mut Value, _: &Ctx) {
	every_head(v, &|h: &mut Value| {
		h.as_object_mut().unwrap().remove("acks");
	});
}

/// A keeper set not acknowledged: `info` names no keeper, while the heads it
/// shows carry a keeper's acknowledgements.
fn no_keepers_named(v: &mut Value, _: &Ctx) {
	if v.get("operator").is_some() && v.get("keepers").is_some() {
		v["keepers"] = json!({"keys": [], "required": 0});
	}
}

/// The operator's answer to a forfeit step without the preimage: the
/// forfeits taken, the preimage held back.
fn no_forfeit_preimage(v: &mut Value) {
	if let Some(o) = v.as_object_mut() {
		o.remove("preimage");
	}
}

/// A proxy rewrite applying a case's edits; with `no_forfeit`, the preimage
/// is held back from the forfeit step's answer too.
fn case_rewrite(c: &Ctx, page: Option<Edit>, tree: Option<Edit>, info: Option<Edit>, mailbox: Option<Edit>, no_forfeit: bool)
	-> common::proxy::Rewrite
{
	let c = c.clone();
	Arc::new(move |path: &str, _: &Value, status: u16, v: &mut Value| {
		if status != 200 {
			return None;
		}
		match path {
			"/v1/leaf_data" => page.into_iter().chain(info).for_each(|f| f(v, &c)),
			"/v1/tree" => tree.into_iter().chain(info).for_each(|f| f(v, &c)),
			"/v1/forfeit_leaves" if no_forfeit => no_forfeit_preimage(v),
			"/v1/info" | "/v1/witness" => info.into_iter().for_each(|f| f(v, &c)),
			"/v1/mailbox_read" => mailbox.into_iter().chain(info).for_each(|f| f(v, &c)),
			_ => {},
		}
		None
	})
}

/// The restore against a server that lies, one way at a time, each on a
/// wallet created afresh from A's mnemonic through a proxy that rewrites what
/// the server serves. A holds a leaf of a batch, its change from a payment and
/// the board that paid it, and a payment to it not yet read; M, another
/// wallet, holds a board. Each lie is refused with its reason and nothing is
/// credited on it:
/// - a record withheld: the payment served without its record and kept from
///   the mailbox is not recovered, and said so; the leaf of the batch not
///   served at all is taken from the published tree, which publishes its
///   preimage, and said so; with the tree withholding that preimage too, it
///   is not recovered;
/// - a wrong tree: the leaf of the batch is refused;
/// - a leaf of another key: M's board served to A's mailbox key is refused;
/// - an old copy of a leaf: the board A paid from, served live and given up
///   nowhere, is counted nowhere while the record of A's change names it,
///   left to the history, whose step holds it spent, by the transfer A's
///   change rests on;
/// - a keeper set not acknowledged: with every acknowledgement stripped, or
///   with `info` naming no keeper while the heads carry a keeper's
///   acknowledgements, nothing is restored.
#[tokio::test(flavor = "multi_thread")]
async fn a_restore_takes_the_operators_word_for_nothing_it_can_check() {
	let mut r = Running::start_kept(1, None).await;
	let (url, node) = (r.url(), r.node_url());
	let x = r.x;
	let xs = x.to_string();
	let (a, b, m) = (Arca::new("RXA"), Arca::new("RXB"), Arca::new("RXM"));
	let boards = boarded(&mut r, &a, &url, &[(x, 2_000_000), (x, 2_000_000)]).await;
	boarded(&mut r, &b, &url, &[(x, 3_000_000)]).await;
	let others = boarded(&mut r, &m, &url, &[(x, 2_000_000)]).await;
	let req_b = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let sent = a.ok(&["send", &req_b, "--amount", "600000", "--asset", &xs]);
	let paid_from = sent["inputs"][0].as_str().unwrap().to_string();
	let change = sent["transfer"]["kept"][0]["leaf_id"].as_str().unwrap().to_string();
	let refreshed = boards.iter().find(|l| **l != paid_from).unwrap().clone();
	a.ok(&["participate", "--leaf", &refreshed, "--max-fee-ppm", "1000000"]);
	final_round(&r).await;
	let s = a.ok(&["sync"]);
	let leaf = s["participations"][0]["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	let req_a = a.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let paid = b.ok(&["send", &req_a, "--amount", "500000", "--asset", &xs]);
	let unread = paid["transfer"]["outputs"].as_array().unwrap().iter().map(|o| o.as_str().unwrap().to_string())
		.find(|o| !paid["transfer"]["kept"].as_array().unwrap().iter().any(|k| k["leaf_id"] == o.as_str())).expect("A's coin");
	let mrec = m.ok(&["record", &others[0]]);
	let c = Ctx {
		leaf: leaf.clone(), refreshed: refreshed.clone(), paid_from: paid_from.clone(), unread: unread.clone(),
		other: others[0].clone(), other_record: mrec["record"].as_str().unwrap().to_string(),
		other_owner: mrec["detail"]["owner"].as_str().unwrap().to_string(), other_nonce: mrec["detail"]["owner_nonce"].as_str().unwrap().to_string(),
	};
	println!("RX A holds: batch leaf {} (from {}), change {} (from {}), unread payment {}; M's board {}", &leaf[..16], &refreshed[..16],
		&change[..16], &paid_from[..16], &unread[..16], &others[0][..16]);
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap().trim().to_string();
	let p = Proxy::start(&url);
	type Check = Box<dyn Fn(&Value, &Arca)>;
	let cases: Vec<(&str, Option<Edit>, Option<Edit>, Option<Edit>, Option<Edit>, Check)> = vec![
		("a record withheld: the payment served without its record, kept from the mailbox", Some(withhold_payment), None, None,
			Some(hide_payment), Box::new({ let c = c.clone(); move |out: &Value, w: &Arca| {
				let why = out["not_recovered"].as_array().unwrap().iter().find(|n| n["leaf_id"] == c.unread.as_str())
					.unwrap_or_else(|| panic!("the withheld payment is not listed: {}", out));
				assert!(why["why"].as_str().unwrap().contains("without its record: withheld"), "{}", why);
				assert_eq!(coin_of(w, &c.unread), Value::Null, "nothing credited");
			}})),
		("a record withheld: the leaf of the batch not served, its preimage in the tree", Some(drop_leaf), None, None, None,
			Box::new({ let c = c.clone(); move |out: &Value, w: &Arca| {
				assert!(out["notes"].as_array().unwrap().iter().any(|n| n["leaf_id"] == c.leaf.as_str()
					&& n["note"].as_str().unwrap_or("").contains("recovered from the published tree")), "{}", out["notes"]);
				assert_eq!(coin_of(w, &c.leaf)["state"], "live", "taken from the tree and the chain");
			}})),
		("a record withheld: the leaf of the batch not served, the tree withholding its preimage", Some(drop_leaf), Some(no_preimage), None, None,
			Box::new({ let c = c.clone(); move |out: &Value, w: &Arca| {
				let why = out["not_recovered"].as_array().unwrap().iter().find(|n| n["leaf_id"] == c.leaf.as_str())
					.unwrap_or_else(|| panic!("the withheld leaf is not listed: {}", out));
				assert!(why["why"].as_str().unwrap().contains("its preimage has not gone out"), "{}", why);
				assert_eq!(coin_of(w, &c.leaf), Value::Null, "nothing credited");
				// The board given up for it stays given up under its forfeit,
				// which the wallet follows on the chain.
				assert_eq!(coin_of(w, &c.refreshed)["state"], "forfeited");
			}})),
		("a wrong tree: its batch output one atom more", None, Some(one_atom_more), None, None,
			Box::new({ let c = c.clone(); move |out: &Value, w: &Arca| {
				let why = out["not_recovered"].as_array().unwrap().iter().find(|n| n["leaf_id"] == c.leaf.as_str())
					.unwrap_or_else(|| panic!("the leaf is not listed: {}", out));
				assert!(why["why"].as_str().unwrap().contains("the published tree is not the tree its parts build: node 0 of level"), "{}", why);
				assert_eq!(coin_of(w, &c.leaf), Value::Null, "nothing credited");
				// The board given up for it stays given up under its forfeit
				// (A's own attestation and forfeit say so), followed on the
				// chain: the leaf it was given up for is not taken on a tree
				// that does not build.
				assert_eq!(coin_of(w, &c.refreshed)["state"], "forfeited");
			}})),
		("a leaf of another key: M's board served to A's mailbox key", Some(another_keys_leaf), None, None, None,
			Box::new({ let c = c.clone(); move |out: &Value, w: &Arca| {
				let why = out["not_recovered"].as_array().unwrap().iter().find(|n| n["leaf_id"] == c.other.as_str())
					.unwrap_or_else(|| panic!("M's board is not listed: {}", out));
				assert!(why["why"].as_str().unwrap().contains("a leaf of another key"), "{}", why);
				assert_eq!(coin_of(w, &c.other), Value::Null, "nothing credited");
			}})),
		("an old copy of a leaf: the board A paid from, live and given up nowhere", Some(old_copy), None, None, None,
			Box::new({ let c = c.clone(); move |out: &Value, w: &Arca| {
				// The record of A's change names it spent: it was left to the
				// history, counted nowhere until its step.
				assert!(out["history"]["left"].as_u64().unwrap() >= 1, "{}", out["history"]);
				assert!(out["notes"].as_array().unwrap().iter().any(|n| n["leaf_id"] == c.paid_from.as_str()
					&& n["note"].as_str().unwrap_or("").contains("an old copy")), "{}", out["notes"]);
				let coin = coin_of(w, &c.paid_from);
				assert_eq!(coin["state"], "spent", "{}", coin);
				assert!(coin["spent_by"].as_str().unwrap().contains("transfer"), "{}", coin);
			}})),
		("a keeper set not acknowledged: every acknowledgement stripped", None, None, Some(no_acks), None,
			Box::new(|out: &Value, w: &Arca| {
				let why = out["error"]["message"].as_str().unwrap_or_else(|| panic!("not refused: {}", out));
				assert!(why.contains("no head of its signer's record it shows comes with their acknowledgements"), "{}", why);
				assert_eq!(w.ok(&["coins"]), json!([]), "nothing credited");
			})),
		("a keeper set not acknowledged: no keeper named, a keeper's acknowledgements shown", None, None, Some(no_keepers_named), None,
			Box::new(|out: &Value, w: &Arca| {
				let why = out["error"]["message"].as_str().unwrap_or_else(|| panic!("not refused: {}", out));
				assert!(why.contains("which the operator does not name among its keepers"), "{}", why);
				assert_eq!(w.ok(&["coins"]), json!([]), "nothing credited");
			})),
	];
	for (k, (what, page, tree, info, mailbox, check)) in cases.into_iter().enumerate() {
		p.rewrite(Some(case_rewrite(&c, page, tree, info, mailbox, what.contains("withholding its preimage"))));
		let w = Arca::new(&format!("RXR{}", k));
		let mut args = create_args(&p.url, &node);
		args.extend(["--mnemonic", &mnemonic]);
		let made = w.ok(&args);
		// The restore's answer, with each step of the history it left: what
		// the two say together is what the restore found.
		let mut out = made["restore"].clone();
		while out["error"].is_null() && out["history"]["left"].as_u64().unwrap_or(0) > out["history"]["checked"].as_u64().unwrap_or(0) {
			let step = w.ok(&["restore-history"]);
			for k in ["restored", "not_recovered", "notes"] {
				let more = step[k].as_array().cloned().unwrap_or_default();
				out[k].as_array_mut().unwrap().extend(more);
			}
			let done = out["history"]["checked"].as_u64().unwrap_or(0) + step["checked"].as_u64().unwrap_or(0);
			out["history"]["checked"] = json!(done);
			if step["left"] == 0 {
				break;
			}
		}
		let out = &out;
		println!("RX {}: restored {} | not recovered {} | notes {} | error {}", what,
			json!(out["restored"].as_array().map(|v| v.iter().map(|x| format!("{} {}", &x["leaf_id"].as_str().unwrap_or("")[..16], x["state"].as_str().unwrap_or(""))).collect::<Vec<_>>())),
			out["not_recovered"], out["notes"], out["error"]["message"]);
		check(out, &w);
		p.rewrite(None);
		let _ = std::fs::remove_dir_all(&w.dir);
	}
	for w in [&a, &b, &m] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// Advances the chain's median time to at least `t`, and waits for the
/// server.
async fn mtp_to(r: &Running, t: u32) {
	let now = common::node::median_time(&r.rt);
	if t > now {
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, t - now));
	}
	r.synced().await;
}

/// The transaction of the chain or the mempool that spends `op`.
fn spender_of(r: &Running, op: &elements::OutPoint) -> Option<Transaction> {
	let spends = |t: &Transaction| t.input.iter().any(|i| i.previous_output == *op);
	let mempool: Vec<String> = serde_json::from_value(r.rt.client().call::<Value>("getrawmempool", &[]).unwrap()).unwrap();
	for id in mempool {
		let t = r.rt.client().raw_transaction(&elements::Txid::from_str(&id).unwrap()).unwrap();
		if spends(&t) {
			return Some(t);
		}
	}
	let tip = r.rt.client().blockchain_info().unwrap().blocks;
	for h in tip.saturating_sub(200)..=tip {
		let hash = r.rt.client().block_hash(h).unwrap();
		if let Some(t) = r.rt.client().block(&hash).unwrap().txdata.into_iter().find(|t| spends(t)) {
			return Some(t);
		}
	}
	None
}

/// The as-of rule on a restore. A and B each hold a leaf of a batch of its
/// own round, and are away. Two hours past both leaves' expiry, before the
/// notice has run: A restored from its mnemonic takes its leaf, checked as of
/// its expiry (its unroll authorisations, signed again, dated before that
/// expiry), and at once on the chain, and brings it home before the notice
/// runs out. Past B's expiry and the notice, the operator's watcher sweeps
/// B's batch; once the sweep is final, B restored from its mnemonic does not
/// take the leaf (its path is gone), says so naming the sweep, and counts it
/// nowhere; the board B gave up for it is spent.
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_restored_past_its_expiry_goes_home_while_its_path_stands() {
	let mut r = Running::start_sweeping().await;
	let (url, node) = (r.url(), r.node_url());
	let x = r.x;
	let (a, b, a2, b2) = (Arca::new("RXPA"), Arca::new("RXPB"), Arca::new("RXPA2"), Arca::new("RXPB2"));
	let ba = boarded(&mut r, &a, &url, &[(x, 1_000_000)]).await;
	a.ok(&["participate", "--leaf", &ba[0], "--max-fee-ppm", "1000000"]);
	final_round(&r).await;
	let la = a.ok(&["sync"])["participations"][0]["new_leaves"][0]["leaf_id"].as_str().expect("A's leaf").to_string();
	let bb = boarded(&mut r, &b, &url, &[(x, 1_000_000)]).await;
	b.ok(&["participate", "--leaf", &bb[0], "--max-fee-ppm", "1000000"]);
	let rb = final_round(&r).await;
	let lb = b.ok(&["sync"])["participations"][0]["new_leaves"][0]["leaf_id"].as_str().expect("B's leaf").to_string();
	let ea = coin_of(&a, &la)["expiry"].as_u64().unwrap() as u32;
	let eb = coin_of(&b, &lb)["expiry"].as_u64().unwrap() as u32;
	let rec = b.ok(&["record", &lb]);
	let CoinRecord::Leaf { record, .. } = CoinRecord::from_bytes(&unhex(rec["record"].as_str().unwrap())).unwrap() else { panic!("a batch leaf") };
	let notice = record.schedule.notice.seconds() as u32;
	println!("RXP A's leaf {} expires at {}; B's {} at {}; the notice {} s", &la[..16], ea, &lb[..16], eb, notice);
	let words = |w: &Arca| {
		let m = std::fs::read_to_string(w.dir.join("mnemonic")).unwrap();
		m.trim().to_string()
	};
	let (ma, mb) = (words(&a), words(&b));

	// Two hours past both expiries, the notice not run: A restored.
	mtp_to(&r, ea.max(eb) + 2 * 3600).await;
	for _ in 0..2 {
		let _ = r.server.watcher.pass().await;
		r.produce().await;
		r.synced().await;
	}
	let mut args = create_args(&url, &node);
	args.extend(["--mnemonic", &ma]);
	let made = a2.ok(&args);
	let out = &made["restore"];
	println!("RXP A restored past its leaf's expiry (median time {}): restored {} | not recovered {}", common::node::median_time(&r.rt),
		out["restored"], out["not_recovered"]);
	assert_eq!(out["not_recovered"], json!([]), "{}", out);
	let c = coin_of(&a2, &la);
	println!("RXP A2's leaf: {} | {}", c["state"], c["note"]);
	assert_eq!(c["state"], "exiting", "taken on the chain at once: {}", c);
	let mut home = None;
	for round in 0..8 {
		r.produce().await;
		a2.ok(&["sync"]);
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 600));
		r.produce().await;
		r.bury().await;
		r.synced().await;
		a2.ok(&["sync"]);
		let s = coin_of(&a2, &la)["state"].as_str().unwrap_or("").to_string();
		println!("RXP A2's leaf after {} round(s) of blocks and syncs: {}", round + 1, s);
		if s == "exited" {
			home = Some(common::node::median_time(&r.rt));
			break;
		}
	}
	let at = home.expect("A2's leaf comes home");
	println!("RXP A2's leaf home at median time {}, {} s past its expiry", at, at - ea);

	// Past the notice from the token's release (at the watcher's first pass
	// after the expiry, two hours past it): the watcher sweeps B's batch.
	mtp_to(&r, eb + 2 * 3600 + notice + 3600).await;
	let batch = record.branch().unwrap().batch_output();
	let bvout = rb.output.iter().position(|o| arca_covenant::ExplicitOutput::from_txout(o).as_ref() == Some(&batch)).unwrap() as u32;
	let batch_at = elements::OutPoint::new(rb.txid(), bvout);
	for _ in 0..30 {
		let _ = r.server.watcher.pass().await;
		r.produce().await;
		r.synced().await;
		if spender_of(&r, &batch_at).is_some() {
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;
	}
	let sweep = spender_of(&r, &batch_at).expect("the operator sweeps B's batch");
	r.produce().await;
	r.bury().await;
	r.synced().await;
	println!("RXP B's batch output {} swept by {}", batch_at, sweep.txid());
	let mut args = create_args(&url, &node);
	args.extend(["--mnemonic", &mb]);
	let made = b2.ok(&args);
	let out = &made["restore"];
	println!("RXP B restored after the sweep: restored {} | not recovered {}", out["restored"], out["not_recovered"]);
	let why = out["not_recovered"].as_array().unwrap().iter().find(|n| n["leaf_id"] == lb.as_str())
		.unwrap_or_else(|| panic!("B's swept leaf is not listed: {}", out));
	let why = why["why"].as_str().unwrap();
	assert!(why.contains("path is gone") && why.contains(&sweep.txid().to_string()) && why.contains("final"), "{}", why);
	assert_eq!(coin_of(&b2, &lb), Value::Null, "counted nowhere");
	// The board B gave up for it, in a participation the operator released,
	// is B's history: its step holds it spent.
	assert_eq!(coin_of(&b2, &bb[0]), Value::Null, "not held before its step");
	b2.ok(&["restore-history"]);
	assert_eq!(coin_of(&b2, &bb[0])["state"], "spent", "the board B gave up for it");
	for w in [&a, &b, &a2, &b2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
// ---------------------------------------------------------------------------
// D66: the mailbox cursor never moves back, and every read is bounded
// ---------------------------------------------------------------------------

/// Pays `w`'s only live coin whole to `request`: walking down from the
/// coin's value, the first amount the wallet takes leaves no change.
fn pay_whole(w: &Arca, request: &str, asset: &str, value: u64) -> Value {
	for v in (value.saturating_sub(4_000)..value).rev() {
		let (ok, out) = w.run(&["send", request, "--amount", &v.to_string(), "--asset", asset]);
		if ok {
			assert!(out["transfer"]["kept"].as_array().unwrap().is_empty(), "paid with change: {}", out);
			return out;
		}
	}
	panic!("no amount just below {} was taken whole", value);
}

/// The second review's F1, turned around (D66), its first half. A server that
/// names another page of `leaf_data` without end: first as the review's
/// probe did (the next cursor one past the last, the same leaves served
/// again), then as a server that keeps its pages consistent (every leaf
/// served again under a new cursor, each page's next its last). The restore
/// ends either way, with a note: at once for the first, at the page cap for
/// the second, and the coin in the mailbox is restored.
#[tokio::test(flavor = "multi_thread")]
async fn d66_a_restore_reads_leaf_data_to_an_end_whatever_the_server_serves() {
	let mut r = Running::start_kept(0, None).await;
	let (url, node) = (r.url(), r.node_url());
	let x = r.x;
	let xs = x.to_string();
	let (a, b) = (Arca::new("D66A"), Arca::new("D66B"));
	boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	b.ok(&create_args(&url, &node));
	let req_b = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let sent = a.ok(&["send", &req_b, "--amount", "500000", "--asset", &xs]);
	let unread = sent["transfer"]["outputs"].as_array().unwrap().iter().map(|o| o.as_str().unwrap().to_string())
		.find(|o| !sent["transfer"]["kept"].as_array().unwrap().iter().any(|k| k["leaf_id"] == o.as_str())).expect("B's coin");
	let mnemonic_b = std::fs::read_to_string(b.dir.join("mnemonic")).unwrap().trim().to_string();
	let p = Proxy::start(&url);
	let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
	// (a) The review's probe: the same leaves again, the next cursor one
	// past the last asked; given up by the proxy after 2,000 pages.
	for (case, consistent) in [("the review's", false), ("a consistent", true)] {
		calls.store(0, std::sync::atomic::Ordering::SeqCst);
		let first: Arc<std::sync::Mutex<Value>> = Arc::new(std::sync::Mutex::new(json!([])));
		let (cc, ff) = (calls.clone(), first.clone());
		p.rewrite(Some(Arc::new(move |path: &str, req: &Value, status: u16, v: &mut Value| {
			if path != "/v1/leaf_data" || status != 200 {
				return None;
			}
			let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
			let after = req["after"].as_str().and_then(|a| a.parse::<i64>().ok()).unwrap_or(0);
			if n >= 2_000 {
				*v = json!({"leaves": [], "next": null});
				return None;
			}
			if n == 0 {
				*ff.lock().unwrap() = v["leaves"].clone();
			}
			if v["leaves"].as_array().unwrap().is_empty() {
				v["leaves"] = ff.lock().unwrap().clone();
			}
			if consistent {
				for l in v["leaves"].as_array_mut().unwrap() {
					l["cursor"] = json!((after + 1).to_string());
				}
			}
			v["next"] = json!((after + 1).to_string());
			None
		})));
		let b2 = Arca::new(if consistent { "D66B3" } else { "D66B2" });
		let mut args = create_args(&p.url, &node);
		args.extend(["--mnemonic", &mnemonic_b]);
		let made = b2.ok(&args);
		let n = calls.load(std::sync::atomic::Ordering::SeqCst);
		println!("D66 {} server, leaf_data without end: {} pages read | restore note {} | the coin {}", case, n, made["restore"]["note"],
			coin_of(&b2, &unread)["state"]);
		assert!(n < 2_000, "the restore read every page the server named: {}", n);
		assert!(made["restore"]["note"].is_string(), "the restore says why it stopped reading: {}", made["restore"]);
		assert_eq!(coin_of(&b2, &unread)["state"], "live", "{}", made["restore"]);
		let _ = std::fs::remove_dir_all(&b2.dir);
	}
	p.rewrite(None);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// The second review's F1, turned around (D66), its second half: the
/// mailbox. B2, restored, pays the first coin away whole; a second payment
/// takes its cursor past that message. The spent coin's message served
/// again, once, does not take the cursor back (the message after it is not
/// read again), and served again on every page the read ends with a note
/// instead of running on. Nothing is credited twice.
#[tokio::test(flavor = "multi_thread")]
async fn d66_a_mailbox_replayed_takes_no_cursor_back_and_ends() {
	let mut r = Running::start_kept(0, None).await;
	let (url, node) = (r.url(), r.node_url());
	let x = r.x;
	let xs = x.to_string();
	let (a, b) = (Arca::new("D66MA"), Arca::new("D66MB"));
	boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	b.ok(&create_args(&url, &node));
	let req_b = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let sent = a.ok(&["send", &req_b, "--amount", "500000", "--asset", &xs]);
	let unread = sent["transfer"]["outputs"].as_array().unwrap().iter().map(|o| o.as_str().unwrap().to_string())
		.find(|o| !sent["transfer"]["kept"].as_array().unwrap().iter().any(|k| k["leaf_id"] == o.as_str())).expect("B's coin");
	let mnemonic_b = std::fs::read_to_string(b.dir.join("mnemonic")).unwrap().trim().to_string();
	let p = Proxy::start(&url);
	// The proxy keeps every mailbox message it passes on, from the restore's
	// read on.
	let msgs: Arc<std::sync::Mutex<BTreeMap<String, Value>>> = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
	let mm = msgs.clone();
	p.rewrite(Some(Arc::new(move |path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/mailbox_read" && status == 200 {
			for m in v["messages"].as_array().into_iter().flatten() {
				if let Some(l) = m["leaf_id"].as_str() {
					mm.lock().unwrap().insert(l.to_string(), m.clone());
				}
			}
		}
		None
	})));
	let b2 = Arca::new("D66MB2");
	let mut args = create_args(&p.url, &node);
	args.extend(["--mnemonic", &mnemonic_b]);
	b2.ok(&args);
	b2.ok(&["sync"]);
	let req_a = a.ok(&["receive"])["request"].as_str().unwrap().to_string();
	pay_whole(&b2, &req_a, &xs, 500_000);
	assert_eq!(coin_of(&b2, &unread)["state"], "spent");
	let req_b2 = b2.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let sent2 = a.ok(&["send", &req_b2, "--amount", "100000", "--asset", &xs]);
	let coin2 = sent2["transfer"]["outputs"].as_array().unwrap().iter().map(|o| o.as_str().unwrap().to_string())
		.find(|o| !sent2["transfer"]["kept"].as_array().unwrap().iter().any(|k| k["leaf_id"] == o.as_str())).expect("B2's second coin");
	let s = b2.ok(&["sync"]);
	assert!(s["mailbox"]["accepted"].as_array().unwrap().iter().any(|c| c["leaf_id"] == coin2.as_str()), "{}", s["mailbox"]);
	let before = b2.ok(&["balance"]);
	let m0 = msgs.lock().unwrap().get(&unread).cloned().expect("the first coin's message, seen by the proxy");
	// Served again once.
	let once = Arc::new(std::sync::atomic::AtomicBool::new(false));
	let (oc, m0c) = (once.clone(), m0.clone());
	p.rewrite(Some(Arc::new(move |path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/mailbox_read" && status == 200 && !oc.swap(true, std::sync::atomic::Ordering::SeqCst) {
			if let Some(m) = v["messages"].as_array_mut() {
				m.push(m0c.clone());
			}
		}
		None
	})));
	let s = b2.ok(&["sync"]);
	println!("D66 a sync with the spent coin's message served again once: mailbox {}", s["mailbox"]);
	let held = s["mailbox"]["already_held"].as_array().cloned().unwrap_or_default();
	assert!(!held.iter().any(|c| c["leaf_id"] == coin2.as_str()), "the cursor went back: the message after the old one was read again: {}",
		s["mailbox"]);
	assert_eq!(coin_of(&b2, &unread)["state"], "spent");
	assert_eq!(b2.ok(&["balance"]), before);
	// Served again on every page; the proxy gives up after 500 reads.
	let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
	let (rc, m0c) = (reads.clone(), m0.clone());
	p.rewrite(Some(Arc::new(move |path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/mailbox_read" && status == 200 && rc.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 500 {
			if let Some(m) = v["messages"].as_array_mut() {
				m.push(m0c.clone());
			}
		}
		None
	})));
	let s = b2.ok(&["sync"]);
	let n = reads.load(std::sync::atomic::Ordering::SeqCst);
	println!("D66 a sync with the spent coin's message served on every page: {} reads | mailbox {}", n, s["mailbox"]);
	assert!(n < 10, "the read ran on while the server served the old message on every page: {} reads", n);
	assert!(s["mailbox"]["note"].is_string(), "the read says why it ended: {}", s["mailbox"]);
	assert_eq!(b2.ok(&["balance"]), before, "nothing credited twice");
	p.rewrite(None);
	for w in [&a, &b, &b2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// A leaf the wallet takes home
// ---------------------------------------------------------------------------

/// `w`'s batch leaf of a board of `value` of X refreshed in a final round.
async fn batch_leaf(r: &mut Running, w: &Arca, value: u64) -> String {
	let x = r.x;
	let url = r.url();
	boarded(r, w, &url, &[(x, value)]).await;
	w.ok(&["participate"]);
	final_round(r).await;
	let s = w.ok(&["sync"]);
	s["participations"][0]["new_leaves"][0]["leaf_id"].as_str().expect("the new leaf").to_string()
}

/// Runs `w`'s `exit` of `leaf`, with blocks and its exit delay waited out,
/// until it answers `until` (`claimed`: the claim broadcast; `exited`: the
/// claim final). Returns the answer.
async fn exit_until(r: &Running, w: &Arca, leaf: &str, until: &str) -> Value {
	for k in 0..30 {
		let e = w.ok(&["exit", leaf]);
		println!("EXIT {} #{}: {} {}", &leaf[..16], k, e["state"], e["next"].as_str().or(e["error"].as_str()).unwrap_or(""));
		if e["state"] == until {
			return e;
		}
		r.produce().await;
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 600));
		r.bury().await;
		r.synced().await;
	}
	panic!("the exit of {} never reached {}", leaf, until);
}

/// W2.5: `exit --quote` on a coin whose claim is already out answers the
/// claim in flight, nothing left to pay, as `exit` follows it to `exited`,
/// instead of refusing that nothing of the leaf's path is unspent.
#[tokio::test(flavor = "multi_thread")]
async fn an_exits_quote_with_its_claim_out_answers_the_claim() {
	let mut r = Running::start().await;
	let a = Arca::new("EQA");
	let leaf = batch_leaf(&mut r, &a, 2_000_000).await;
	let claimed = exit_until(&r, &a, &leaf, "claimed").await;
	let (ok, q) = a.run(&["exit", &leaf, "--quote"]);
	println!("EQ the quote with the claim {} out: ok={} {}", claimed["claim"]["txid"], ok, q);
	assert!(ok, "the quote answers the claim in flight: {}", q);
	assert_eq!(q["state"], "claimed", "{}", q);
	assert_eq!(q["claim"]["txid"], claimed["claim"]["txid"], "{}", q);
	assert_eq!(q["unroll"], json!({}), "nothing left to pay: {}", q);
	let shown = a.ok(&["exit", &leaf, "--shown", &q["unroll"].to_string()]);
	println!("EQ the exit on the quote's fees: {}", shown);
	exit_until(&r, &a, &leaf, "exited").await;
	let _ = std::fs::remove_dir_all(&a.dir);
}
/// W2.5: a leaf the wallet took home (its claim final) before its device was
/// lost is restored `exited`, never `live`: the restored wallet's balance
/// off the chain is the lost wallet's, the leaf not counted beside the
/// on-chain coin its claim paid, and it stays so through a sync.
#[tokio::test(flavor = "multi_thread")]
async fn a_leaf_exited_before_the_device_was_lost_is_restored_exited() {
	let mut r = Running::start().await;
	let a = Arca::new("EXA");
	let leaf = batch_leaf(&mut r, &a, 2_000_000).await;
	exit_until(&r, &a, &leaf, "exited").await;
	for _ in 0..3 {
		r.produce().await;
	}
	r.bury().await;
	r.synced().await;
	a.ok(&["sync"]);
	let bal_a = a.ok(&["balance"]);
	println!("RX the lost wallet: the leaf {} | balance {}", coin_of(&a, &leaf)["state"], bal_a);
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap().trim().to_string();
	let a2 = Arca::new("EXA2");
	let (url, node) = (r.url(), r.node_url());
	let mut args = create_args(&url, &node);
	args.extend(["--mnemonic", &mnemonic]);
	let made = a2.ok(&args);
	println!("RX the restore: restored {} | not_recovered {}", made["restore"]["restored"], made["restore"]["not_recovered"]);
	a2.ok(&["sync"]);
	let c = coin_of(&a2, &leaf);
	let bal_b = a2.ok(&["balance"]);
	println!("RX the restored wallet: the leaf {} | balance {}", c, bal_b);
	assert!(!matches!(c["state"].as_str(), Some("live") | Some("pending")), "the exited leaf is restored live: {}", c);
	assert_eq!(bal_b["arca"], bal_a["arca"], "the restored balance off the chain is the lost wallet's");
	for w in [&a, &a2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// What a wallet's balance says of its coins in the tree.
fn tree_balance(w: &Arca) -> Value {
	w.ok(&["balance"])["arca"].clone()
}

/// The live coins a wallet holds, by id, with their values.
fn live(w: &Arca) -> BTreeMap<String, String> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| matches!(c["state"].as_str(), Some("live" | "pending")))
		.map(|c| (c["leaf_id"].as_str().unwrap().to_string(), c["value"].to_string())).collect()
}

/// Lets ten minutes of median time pass, so the next sync of each wallet
/// catches up with what the server serves to its mailbox key.
async fn catch_up_due(r: &Running) {
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 610));
	r.synced().await;
}

/// Two stores of one mnemonic, both kept, spending in turn: A pays B out of
/// round; A2, restored from A's mnemonic before that, still shows what it
/// held until its next sync catches up, then drops the coin A spent and
/// takes A's change. A2 then offboards part of a coin to an address; A's next
/// sync drops that coin and takes A2's change. A pays again, and A2 follows.
/// Each time both show the same coins and the same balance, and a third
/// store restored from the mnemonic alone shows them too.
#[tokio::test(flavor = "multi_thread")]
async fn two_stores_of_one_mnemonic_spending_in_turn_show_the_same_coins() {
	let mut r = Running::start_kept(1, None).await;
	let (url, node) = (r.url(), r.node_url());
	let x = r.x;
	let xs = x.to_string();
	let (a, a2, a3, b) = (Arca::new("TSA"), Arca::new("TSA2"), Arca::new("TSA3"), Arca::new("TSB"));
	boarded(&mut r, &a, &url, &[(x, 2_000_000), (x, 2_000_000)]).await;
	boarded(&mut r, &b, &url, &[(x, 1_000_000)]).await;
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap().trim().to_string();
	let mut args = create_args(&url, &node);
	args.extend(["--mnemonic", &mnemonic]);
	let made = a2.ok(&args);
	assert!(made["restore"]["error"].is_null(), "{}", made["restore"]);
	let start = tree_balance(&a);
	assert_eq!(tree_balance(&a2), start, "A2 restored holds what A holds");

	// A spends. Until its next catch-up, A2 shows what it held: nothing is
	// hidden while it has not looked.
	let req_b = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let sent = a.ok(&["send", &req_b, "--amount", "600000", "--asset", &xs]);
	let paid_from = sent["inputs"][0].as_str().unwrap().to_string();
	b.ok(&["sync"]);
	a2.ok(&["sync"]);
	assert_eq!(tree_balance(&a2), start, "A2 has not caught up yet, and shows what it held");
	catch_up_due(&r).await;
	let s = a2.ok(&["sync"]);
	println!("TS A2's catch-up after A's payment: {}", s["caught_up"]);
	assert!(s["caught_up"]["error"].is_null(), "{}", s["caught_up"]);
	let gone: Vec<&str> = s["caught_up"]["given_elsewhere"].as_array().unwrap().iter().filter_map(|g| g["leaf_id"].as_str()).collect();
	assert_eq!(gone, vec![paid_from.as_str()], "A2 gives up the coin A spent: {}", s["caught_up"]);
	a.ok(&["sync"]);
	assert_eq!(live(&a2), live(&a), "the same coins after A's payment");
	assert_eq!(tree_balance(&a2), tree_balance(&a), "the same balance after A's payment");
	println!("TS after A's payment: {}", tree_balance(&a));

	// A2 offboards part of a coin to an address: a participation with an
	// offboard and a change leaf.
	let address = b.ok(&["address"])["address"].as_str().unwrap().to_string();
	let q = a2.ok(&["offboard", "--asset", &xs, "--amount", "300000", "--address", &address, "--quote"]);
	let asked = a2.ok(&["offboard", "--asset", &xs, "--amount", "300000", "--address", &address, "--shown", &q.to_string()]);
	println!("TS A2's offboard: {}", asked);
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(built.len() == 1 && failed.is_empty(), "{} built, {} failed", built.len(), failed.len());
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.round_state(&built[0].tx.txid(), RoundState::Final).await;
	let mut paid = false;
	for _ in 0..30 {
		a2.ok(&["sync"]);
		if a2.ok(&["offboards"]).as_array().unwrap().iter().any(|o| o["state"] == "paid") {
			paid = true;
			break;
		}
		r.produce().await;
		r.synced().await;
		tokio::time::sleep(std::time::Duration::from_secs(2)).await;
	}
	assert!(paid, "A2's offboard is paid: {}", a2.ok(&["offboards"]));
	catch_up_due(&r).await;
	let s = a.ok(&["sync"]);
	println!("TS A's catch-up after A2's offboard: {}", s["caught_up"]);
	assert!(s["caught_up"]["error"].is_null(), "{}", s["caught_up"]);
	// The offboard's round spends the board A2 gave up (its forfeit, published from the board): A's
	// re-check at the start of the sync finds the board spent and catches up at once, or the sync's
	// own catch-up does.
	let early = s["recheck"]["changes"].as_array().is_some_and(|c| c.iter().any(|x| x["caught_up"] == true));
	assert!(early || s["caught_up"]["given_elsewhere"].as_array().is_some_and(|g| !g.is_empty()),
		"A gives up the coin A2 offboarded: {} {}", s["recheck"], s["caught_up"]);
	a2.ok(&["sync"]);
	assert_eq!(live(&a), live(&a2), "the same coins after A2's offboard");
	assert_eq!(tree_balance(&a), tree_balance(&a2), "the same balance after A2's offboard");
	println!("TS after A2's offboard: {}", tree_balance(&a));

	// A pays again, from what it took of A2's; A2 follows.
	let req_b = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req_b, "--amount", "100000", "--asset", &xs]);
	b.ok(&["sync"]);
	catch_up_due(&r).await;
	let s = a2.ok(&["sync"]);
	println!("TS A2's catch-up after A's second payment: {}", s["caught_up"]);
	a.ok(&["sync"]);
	assert_eq!(live(&a2), live(&a), "the same coins after A's second payment");
	assert_eq!(tree_balance(&a2), tree_balance(&a), "the same balance after A's second payment");

	// A third store, from the mnemonic alone.
	let made = a3.ok(&args);
	assert!(made["restore"]["error"].is_null(), "{}", made["restore"]);
	a3.ok(&["sync"]);
	assert_eq!(live(&a3), live(&a), "a store restored now holds what both hold");
	assert_eq!(tree_balance(&a3), tree_balance(&a), "and shows the same balance");
	println!("TS the end: A {} | A2 {} | A3 {}", tree_balance(&a), tree_balance(&a2), tree_balance(&a3));
	for w in [&a, &a2, &a3, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// The height of the block holding `txid` on the regtest chain.
fn block_height(r: &Running, txid: &str) -> u64 {
	let tx: Value = r.rt.client().call("getrawtransaction", &[json!(txid), json!(true)]).unwrap();
	let h: Value = r.rt.client().call("getblockheader", &[tx["blockhash"].clone(), json!(true)]).unwrap();
	h["height"].as_u64().unwrap()
}

/// The list of a restore's history a store holds, as stored.
fn history_list(w: &Arca) -> Vec<(String, String)> {
	let db = rusqlite::Connection::open(w.dir.join("arca.sqlite")).unwrap();
	["restore_history", "restore_history_ids"].iter()
		.map(|k| (k.to_string(), db.query_row("SELECT value FROM meta WHERE key = ?1", [k], |r| r.get::<_, String>(0)).unwrap()))
		.collect()
}

/// A store's birthday: the height its reads of the chain start from.
fn birthday(w: &Arca) -> u64 {
	let db = rusqlite::Connection::open(w.dir.join("arca.sqlite")).unwrap();
	db.query_row("SELECT value FROM meta WHERE key = 'birthday'", [], |r| r.get::<_, String>(0)).unwrap().parse().unwrap()
}

/// A wallet with a long history (#721): A pays B forty-five times out of
/// round, each payment from the change of the one before, and refreshes its
/// change in a round after every four (a coin goes at most five
/// reassignments from a round), so over fifty of the coins the server
/// serves to its mailbox key are spent: in transfers, and in participations
/// the operator released. A2, restored from A's mnemonic alone, checks first
/// the one coin that makes A's balance, with the coin it was made from: its
/// balance is A's when the restore returns, while the balance says the
/// history is loading; its history holds every other spent coin
/// (`history.left`), counted nowhere, and its birthday is the block of
/// the board everything rests on, as a restore that checked everything at
/// once sets it. A step checks twenty of them, each spent on its owner's own
/// signatures; the same step cut short after taking its coins resumes the list
/// and settles them first. A restore run again meanwhile takes
/// nothing twice and leaves the rest. A pays once more, from the coin both
/// stores hold: A2's next sync catches up (it gives that coin up and takes
/// A's change, leaving the listed coins to their steps) and runs the next
/// step. Once none is left, A2's coins are A's, field by field, and those
/// of A3, restored with every coin checked before its restore returned.
#[tokio::test(flavor = "multi_thread")]
async fn a_long_history_is_restored_after_the_balance() {
	let mut r = Running::start_kept(1, None).await;
	let (url, node) = (r.url(), r.node_url());
	let x = r.x;
	let xs = x.to_string();
	let (a, a2, b) = (Arca::new("LHA"), Arca::new("LHA2"), Arca::new("LHB"));
	let boards = boarded(&mut r, &a, &url, &[(x, 3_000_000)]).await;
	boarded(&mut r, &b, &url, &[(x, 1_000_000)]).await;
	let board_tx = a.ok(&["boards"])[0]["server"]["txid"].as_str().unwrap().to_string();
	let mut spent: Vec<String> = vec![];
	for k in 0..45 {
		if k > 0 && k % 4 == 0 {
			let coin: Vec<String> = live(&a).into_keys().collect();
			a.ok(&["participate", "--leaf", &coin[0], "--max-fee-ppm", "1000000"]);
			final_round(&r).await;
			a.ok(&["sync"]);
			spent.push(coin[0].clone());
		}
		let req_b = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
		let sent = a.ok(&["send", &req_b, "--amount", "20000", "--asset", &xs]);
		spent.push(sent["inputs"][0].as_str().unwrap().to_string());
	}
	assert_eq!(spent[0], boards[0]);
	b.ok(&["sync"]);
	a.ok(&["sync"]);
	let held: Vec<String> = live(&a).into_keys().collect();
	assert_eq!(held.len(), 1, "A holds its last change alone: {:?}", held);
	let history = spent.len();
	assert!(history > 20, "{} spent", history);

	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap().trim().to_string();
	let mut args = create_args(&url, &node);
	args.extend(["--mnemonic", &mnemonic]);
	let made = a2.ok(&args);
	let restore = &made["restore"];
	println!("LH A2's restore: served {} | restored {} | history {} | cost {}", restore["served"], restore["restored"], restore["history"],
		restore["cost_by_step"]);
	assert!(restore["error"].is_null(), "{}", restore);
	assert_eq!(restore["not_recovered"], json!([]), "{}", restore);
	// The coin the live change was made from is judged with it, at once
	// (a coin is judged beside the coins it was made from): held, spent.
	let parent = spent.last().unwrap().clone();
	assert_eq!(restore["history"]["left"], history - 1, "{}", restore["history"]);
	assert_eq!(tree_balance(&a2), tree_balance(&a), "A2's balance is A's when the restore returns");
	assert_eq!(live(&a2), live(&a), "the coin A holds");
	assert_eq!(coin_of(&a2, &parent)["state"], "spent", "the coin the change was made from, taken with it");
	for id in spent.iter().filter(|id| **id != parent) {
		assert_eq!(coin_of(&a2, id), Value::Null, "spent coin {} is not held before its step", id);
	}
	assert_eq!(birthday(&a2), block_height(&r, &board_tx), "the birthday is the board's block");
	// While the history fills, the balance says so: an activity view reads
	// it as still loading, never as complete.
	let bal = a2.ok(&["balance"]);
	assert_eq!(bal["history"], json!({"loading": true, "left": history - 1}), "{}", bal);
	assert!(a.ok(&["balance"])["history"].is_null(), "A's history is whole");
	assert_eq!(restore["deposits"]["owed"], true, "{}", restore);
	let list_before = history_list(&a2);

	let step = a2.ok(&["restore-history"]);
	println!("LH A2's first step: checked {} | left {} | notes {}", step["checked"], step["left"], step["notes"]);
	// A refresh the step completes takes its new leaf, a coin listed
	// further on: that coin is settled with the step, by its own entry.
	let left = step["left"].as_u64().unwrap();
	assert_eq!(step["checked"], 20, "{}", step);
	assert!(left > 0 && left <= history as u64 - 21, "{}", step);
	assert_eq!(step["not_recovered"], json!([]), "{}", step);
	let checked: Vec<Value> = spent.iter().map(|id| coin_of(&a2, id)).filter(|c| !c.is_null()).collect();
	assert_eq!(checked.len() as u64, history as u64 - left, "every coin off the list is held");
	assert!(checked.iter().all(|c| c["state"] == "spent"), "each of them spent: {:?}", checked);
	assert_eq!(tree_balance(&a2), tree_balance(&a), "a step moves no balance");

	// The same step cut short (the program closed mid-step): the coins it
	// took are held as it took them, before how each was given up was
	// applied, and the list is as before the step. The step run again
	// resumes the list where it stopped: it settles those coins first, by
	// their own records, then goes on with the coins after them; nothing it
	// took is left counted.
	let cut: Vec<String> = checked.iter().map(|c| c["leaf_id"].as_str().unwrap().to_string()).filter(|id| *id != parent).collect();
	{
		let db = rusqlite::Connection::open(a2.dir.join("arca.sqlite")).unwrap();
		for id in &cut {
			db.execute("UPDATE coin SET state = 'live', spent_by = NULL, note = '' WHERE leaf_id = ?1", [id]).unwrap();
		}
		for (k, v) in &list_before {
			db.execute("INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2", [k, v]).unwrap();
		}
	}
	assert_ne!(tree_balance(&a2), tree_balance(&a), "cut short, the coins the step took are counted");
	let resumed = a2.ok(&["restore-history"]);
	println!("LH A2's step resumed after one cut short: checked {} | left {} | restored {}", resumed["checked"], resumed["left"],
		resumed["restored"]);
	let taken_again: Vec<&str> = resumed["restored"].as_array().unwrap().iter().filter_map(|c| c["leaf_id"].as_str())
		.filter(|id| cut.iter().any(|c| c == id)).collect();
	assert!(taken_again.is_empty(), "nothing taken twice: {:?}", taken_again);
	assert_eq!(resumed["checked"].as_u64().unwrap(), left.min(20), "it goes on with the coins after them: {}", resumed);
	for id in &cut {
		assert_eq!(coin_of(&a2, id)["state"], "spent", "coin {} settled again", id);
	}
	assert_eq!(tree_balance(&a2), tree_balance(&a), "resumed, nothing it took is counted");
	let left = resumed["left"].as_u64().unwrap();
	assert!(left > 0, "{}", resumed);

	// A restore run again, as after one cut short: nothing twice.
	let again = a2.ok(&["restore"]);
	println!("LH A2's restore run again: restored {} | history {}", again["restored"], again["history"]);
	assert_eq!(again["restored"], json!([]), "{}", again);
	assert_eq!(again["history"]["left"], left, "{}", again["history"]);
	assert_eq!(tree_balance(&a2), tree_balance(&a), "a restore run again moves no balance");

	// A pays from the coin both hold; A2 catches up and takes the next step.
	let req_b = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req_b, "--amount", "20000", "--asset", &xs]);
	b.ok(&["sync"]);
	catch_up_due(&r).await;
	let s = a2.ok(&["sync"]);
	println!("LH A2's sync: caught up {} | history {}", s["caught_up"], s["history"]);
	assert!(s["caught_up"]["error"].is_null(), "{}", s["caught_up"]);
	let gone: Vec<&str> = s["caught_up"]["given_elsewhere"].as_array().unwrap().iter().filter_map(|g| g["leaf_id"].as_str()).collect();
	assert_eq!(gone, vec![held[0].as_str()], "A2 gives up the coin A spent: {}", s["caught_up"]);
	assert!(s["history"]["checked"].as_u64().unwrap() >= 1, "{}", s["history"]);
	let mut left = s["history"]["left"].as_u64().unwrap();
	a.ok(&["sync"]);
	while left > 0 {
		assert_eq!(tree_balance(&a2), tree_balance(&a), "no step moves the balance");
		left = a2.ok(&["sync"])["history"]["left"].as_u64().unwrap();
	}
	let s = a2.ok(&["sync"]);
	assert!(s["history"].is_null(), "no step once none is left: {}", s["history"]);
	a.ok(&["sync"]);
	let (ca, ca2) = (a.ok(&["coins"]), a2.ok(&["coins"]));
	let diff = differences(&ca, &ca2);
	println!("LH coins differing (A | A2): {:?}", diff);
	assert!(diff.is_empty(), "A2's coins are A's: {:?}", diff);
	assert_eq!(tree_balance(&a2), tree_balance(&a));
	assert_eq!(birthday(&a2), block_height(&r, &board_tx));
	assert!(a2.ok(&["balance"])["history"].is_null(), "the history is whole: no longer loading");

	// The reference: A3, restored from the same mnemonic with every coin
	// checked before the restore returns, as a restore did before the
	// history waited. A2's store, its history complete, is A3's: every coin
	// and every field of it, the birthday too.
	let a3 = Arca::new("LHA3");
	let mut args = create_args(&url, &node);
	args.extend(["--mnemonic", &mnemonic, "--restore-at-once"]);
	let made3 = a3.ok(&args);
	assert!(made3["restore"]["error"].is_null(), "{}", made3["restore"]);
	assert_eq!(made3["restore"]["history"]["left"], 0, "{}", made3["restore"]["history"]);
	a2.ok(&["sync"]);
	a3.ok(&["sync"]);
	let (c2, c3) = (a2.ok(&["coins"]), a3.ok(&["coins"]));
	println!("LH coins differing (A3 at once | A2 stepped): {:?}", differences(&c3, &c2));
	assert_eq!(by_id(&c2), by_id(&c3), "A2's coins are byte for byte those of the restore that checks everything at once");
	assert_eq!(serde_json::to_string(&by_id(&c2)).unwrap(), serde_json::to_string(&by_id(&c3)).unwrap());
	assert_eq!(birthday(&a2), birthday(&a3));
	assert_eq!(tree_balance(&a2), tree_balance(&a3));
	for w in [&a, &a2, &a3, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A restore's listed coin waits for a transaction it rests on only so long
/// (`HISTORY_WAIT_MOST`): A pays B twice out of round from its board, so the
/// board waits in A2's history. The server names for it, beside its own, a
/// transaction that is in the mempool and never confirms. A2's step leaves the
/// board waiting (`waiting_for_the_chain`), and the history stays loading.
/// Once the wait is older than the bound (its `waiting_since` aged in the
/// store, as six hours passing would leave it), the step takes the board as a
/// restore that takes everything at once does, the history is complete, and
/// A2's coins are A's.
#[tokio::test(flavor = "multi_thread")]
async fn a_listed_coin_waits_for_a_transaction_that_never_confirms_only_so_long() {
	let mut r = Running::start_kept(1, None).await;
	let (url, node) = (r.url(), r.node_url());
	let x = r.x;
	let xs = x.to_string();
	let (a, a2, b) = (Arca::new("WWA"), Arca::new("WWA2"), Arca::new("WWB"));
	let board = boarded(&mut r, &a, &url, &[(x, 3_000_000)]).await[0].clone();
	boarded(&mut r, &b, &url, &[(x, 1_000_000)]).await;
	for amount in ["1000000", "500000"] {
		let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
		a.ok(&["send", &req, "--amount", amount, "--asset", &xs]);
		b.ok(&["sync"]);
		a.ok(&["sync"]);
	}
	// A transaction that never confirms: in the mempool, kept out of blocks.
	let stuck = r.pay_to(script(&b.ok(&["address"])), x, 10_000).txid().to_string();
	let c = r.rt.client();
	let _: Value = c.call("prioritisetransaction", &[json!(stuck), json!(0), json!(-1_000_000_000i64)]).unwrap();
	r.produce().await;
	let tx: Value = c.call("getrawtransaction", &[json!(stuck), json!(true)]).unwrap();
	assert!(tx["blockhash"].is_null(), "the transaction is in no block");

	let lie = Proxy::start(&url);
	let (bid, st) = (board.clone(), stuck.clone());
	lie.rewrite(Some(Arc::new(move |path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/leaf_data" && status == 200 {
			for l in v["leaves"].as_array_mut().into_iter().flatten() {
				if l["leaf_id"] == bid.as_str() {
					if let Some(bases) = l["bases"].as_array_mut() {
						bases.push(json!({"txid": st}));
					} else {
						l["bases"] = json!([{"txid": st}]);
					}
				}
			}
		}
		None
	})));
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap().trim().to_string();
	let mut args = create_args(&lie.url, &node);
	args.extend(["--mnemonic", &mnemonic]);
	let made = a2.ok(&args);
	println!("WW A2's restore: history {}", made["restore"]["history"]);
	assert_eq!(made["restore"]["history"]["left"], 1, "the board is listed: {}", made["restore"]["history"]);
	let step = a2.ok(&["restore-history"]);
	println!("WW A2's step: {}", step);
	assert_eq!((step["checked"].clone(), step["waiting_for_the_chain"].clone(), step["left"].clone()), (json!(0), json!(1), json!(1)), "{}", step);
	assert_eq!(a2.ok(&["balance"])["history"]["loading"], true);
	// Six hours pass while the transaction stays out of every block.
	{
		let db = rusqlite::Connection::open(a2.dir.join("arca.sqlite")).unwrap();
		let list: String = db.query_row("SELECT value FROM meta WHERE key = 'restore_history'", [], |r| r.get(0)).unwrap();
		let mut list: Value = serde_json::from_str(&list).unwrap();
		let since = list[0]["waiting_since"].as_u64().expect("the wait is noted");
		list[0]["waiting_since"] = json!(since - 6 * 3600 - 1);
		db.execute("UPDATE meta SET value = ?1 WHERE key = 'restore_history'", [list.to_string()]).unwrap();
	}
	let step = a2.ok(&["restore-history"]);
	println!("WW A2's step past the bound: checked {} | left {} | waiting {} | not_recovered {}", step["checked"], step["left"],
		step["waiting_for_the_chain"], step["not_recovered"]);
	assert_eq!((step["checked"].clone(), step["left"].clone()), (json!(1), json!(0)), "{}", step);
	assert!(step["waiting_for_the_chain"].is_null(), "{}", step);
	assert!(a2.ok(&["balance"])["history"].is_null(), "the history is complete");
	a.ok(&["sync"]);
	a2.ok(&["sync"]);
	let diff = differences(&a.ok(&["coins"]), &a2.ok(&["coins"]));
	println!("WW coins differing (A | A2): {:?}", diff);
	assert!(diff.is_empty(), "A2's coins are A's: {:?}", diff);
	assert_eq!(tree_balance(&a2), tree_balance(&a));
	for w in [&a, &a2, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// Bitcoin anchoring is supreme, also while a restore's history waits: A
/// holds a board B1 and pays B out of round twice from a board B2 whose block
/// is anchored to Bitcoin parent block p, so B2 and its first change are
/// spent and the second change, resting on B2, is live. A2, restored from
/// A's mnemonic, holds B1, the first change (spent) and the second when its
/// restore returns, B2 left to its history. Then p is orphaned: B2's block leaves the chain with
/// it, and the change resting on it is no longer live, in A and in A2 alike,
/// their balances equal. A2's history step meets coins whose board is in no
/// block: it takes nothing on them. B2 is mined again and buried: the change
/// is live again in both. A2's catch-up then takes what its step could not,
/// and its coins are A's.
#[tokio::test(flavor = "multi_thread")]
async fn an_anchor_reorganisation_while_a_restores_history_waits() {
	let mut r = Running::start_kept(1, None).await;
	let (url, node) = (r.url(), r.node_url());
	let x = r.x;
	let xs = x.to_string();
	let (a, a2, b) = (Arca::new("ARA"), Arca::new("ARA2"), Arca::new("ARB"));
	boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	boarded(&mut r, &b, &url, &[(x, 1_000_000)]).await;
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, x, 4_000_000);
	r.produce().await;
	// A parent block of B2's own: orphaning it takes B2's block, and every
	// block after it, out of the chain.
	let p = tokio::task::block_in_place(|| {
		r.rt.mine_parent(1).unwrap();
		r.rt.anchor_to_parent_tip().unwrap();
		r.rt.parent.client().block_count().unwrap()
	});
	let b2 = a.ok(&["board", &xs, "3000000"])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("B2 to be credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
	let b2_tx = a.ok(&["boards"]).as_array().unwrap().iter().find(|v| v["leaf_id"] == b2.as_str()).unwrap()["server"]["txid"]
		.as_str().unwrap().to_string();
	// Two payments from B2's lineage (a wallet pays from the coin furthest
	// from its exit date first: B2, then its change): B2 and the first
	// change spent, the second change live on B2.
	let req_b = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let sent = a.ok(&["send", &req_b, "--amount", "1000000", "--asset", &xs]);
	assert_eq!(sent["inputs"], json!([b2]), "{}", sent);
	let change1 = sent["transfer"]["kept"][0]["leaf_id"].as_str().unwrap().to_string();
	let req_b = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let sent = a.ok(&["send", &req_b, "--amount", "1000000", "--asset", &xs]);
	assert_eq!(sent["inputs"], json!([change1]), "{}", sent);
	let spent = vec![b2.clone(), change1.clone()];
	let change = sent["transfer"]["kept"][0]["leaf_id"].as_str().unwrap().to_string();
	b.ok(&["sync"]);
	a.ok(&["sync"]);

	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap().trim().to_string();
	let mut args = create_args(&url, &node);
	args.extend(["--mnemonic", &mnemonic]);
	let made = a2.ok(&args);
	let restore = &made["restore"];
	println!("AR A2's restore: restored {} | history {}", restore["restored"], restore["history"]);
	assert!(restore["error"].is_null(), "{}", restore);
	// B2 waits in the history; the first change, which the live change was
	// made from, is judged with it at once.
	assert_eq!(restore["history"]["left"], 1, "{}", restore["history"]);
	assert_eq!(coin_of(&a2, &b2), Value::Null, "B2 is left to the history");
	assert_eq!(coin_of(&a2, &change1)["state"], "spent");
	assert_eq!(tree_balance(&a2), tree_balance(&a), "the balance when the restore returns");
	assert_eq!(coin_of(&a2, &change)["state"], "live");

	// The parent block orphaned: B2's block leaves the chain, B2 back in the
	// mempool and kept out of blocks.
	let c = r.rt.client();
	let _: Value = c.call("prioritisetransaction", &[json!(b2_tx), json!(0), json!(-1_000_000_000i64)]).unwrap();
	tokio::task::block_in_place(|| r.rt.orphan_parent_from(p)).unwrap();
	r.produce().await;
	r.synced().await;
	let tx: Result<Value, _> = c.call("getrawtransaction", &[json!(b2_tx), json!(true)]);
	assert!(tx.map(|t| t["blockhash"].is_null()).unwrap_or(true), "B2 is in no block");
	let sa = a.ok(&["sync"]);
	let sa2 = a2.ok(&["sync"]);
	println!("AR after the reorganisation: A's change {} | A2's change {} | A2's step {}", coin_of(&a, &change)["state"],
		coin_of(&a2, &change)["state"], sa2["history"]);
	let _ = sa;
	assert_ne!(coin_of(&a, &change)["state"], "live", "A: a coin on a board in no block is not live");
	assert_eq!(coin_of(&a2, &change)["state"], coin_of(&a, &change)["state"], "A2 follows the chain as A does");
	assert_eq!(tree_balance(&a2), tree_balance(&a), "the same balance through the reorganisation");
	for id in &spent {
		assert_ne!(coin_of(&a2, id)["state"], "live", "a coin of the history is never live: {}", id);
	}
	assert_eq!(sa2["history"]["checked"], 0, "the step takes nothing on a board in no block: {}", sa2["history"]);
	assert_eq!(sa2["history"]["waiting_for_the_chain"], 1, "{}", sa2["history"]);
	assert_eq!(sa2["history"]["left"], 1, "B2 waits in the list: {}", sa2["history"]);
	assert_eq!(coin_of(&a2, &b2), Value::Null, "B2 not taken while its board is out of the chain");

	// B2 mined again and buried: the change is live again in both.
	let _: Value = c.call("prioritisetransaction", &[json!(b2_tx), json!(0), json!(1_000_000_000i64)]).unwrap();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	a.ok(&["sync"]);
	a2.ok(&["sync"]);
	assert_eq!(coin_of(&a, &change)["state"], "live");
	assert_eq!(coin_of(&a2, &change)["state"], "live", "A2's change live again");
	assert_eq!(tree_balance(&a2), tree_balance(&a));
	// Whatever the step could not take, the history (or a catch-up) takes now.
	for _ in 0..3 {
		a2.ok(&["restore-history"]);
	}
	catch_up_due(&r).await;
	a.ok(&["sync"]);
	let s = a2.ok(&["sync"]);
	println!("AR A2's catch-up: {}", s["caught_up"]);
	let (ca, ca2) = (a.ok(&["coins"]), a2.ok(&["coins"]));
	let diff = differences(&ca, &ca2);
	println!("AR coins differing (A | A2): {:?}", diff);
	assert!(diff.is_empty(), "A2's coins are A's: {:?}", diff);
	assert_eq!(tree_balance(&a2), tree_balance(&a));
	for w in [&a, &a2, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
