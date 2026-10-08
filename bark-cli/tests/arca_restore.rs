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
///   nowhere, is held spent, by the transfer A's change rests on;
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
				assert!(out["notes"].as_array().unwrap().iter().any(|n| n["leaf_id"] == c.paid_from.as_str()
					&& n["note"].as_str().unwrap_or("").contains("an old copy")), "{}", out["notes"]);
				let coin = coin_of(w, &c.paid_from);
				assert_eq!(coin["state"], "spent", "{}", coin);
				assert!(coin["spent_by"].as_str().unwrap().starts_with("transfer "), "{}", coin);
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
		let out = &made["restore"];
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
