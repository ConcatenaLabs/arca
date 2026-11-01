//! The wallet library's commands for a program that keeps one wallet open
//! (a browser's worker, a phone app's core), run as such a program runs them
//! (`command::run`): between tip changes each command reads the chain from
//! what its chain source kept for the view (a few calls of the node), and
//! answers as a wallet opened afresh does; every change to the chain, the
//! operator or the wallet's coins between two commands is seen before the
//! next one signs: a rollback of a coin's round, a spend of its lineage in
//! the mempool, an operator showing another key, a coin received.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::sync::Arc;

use elements::{AssetId, OutPoint, Script, Transaction};
use serde_json::{json, Value};

use arca_covenant::{CoinRecord, FeeSource};
use bark::arca::{command, Wallet};
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

fn record_of(w: &Arca, leaf: &str) -> CoinRecord {
	CoinRecord::from_bytes(&unhex(w.ok(&["record", leaf])["record"].as_str().unwrap())).unwrap()
}

fn rpc(r: &Running, method: &str, params: &[Value]) -> Value {
	r.rt.client().call(method, params).unwrap_or_else(|e| panic!("{} {:?}: {}", method, params, e))
}

/// Creates `w` on `server` and boards `amount` of `asset`; waits until the
/// board is final and credited.
async fn boarded(r: &mut Running, w: &Arca, server: &str, asset: AssetId, amount: u64) -> String {
	w.ok(&create_args(server, &r.node_url()));
	let s = script(&w.ok(&["address"]));
	r.pay_to(s, asset, amount + 3_000_000);
	r.produce().await;
	let board = w.ok(&["board", &asset.to_string(), &amount.to_string()])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
	board
}

// Whether each command [`library`] runs asks for the coins-only start
// (`"recheck": "coins"`), as a maker's answer path does. Each test runs on
// a thread of its own runtime, so the flag is the thread's.
std::thread_local! {
	static COINS_ONLY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// One command of the library on the open wallet `w`: its result, or its
/// refusal, and the requests it made of the node.
fn library(w: &mut Wallet, cmd: &str, args: Value) -> (Result<Value, String>, u64) {
	let (r, n, _) = library_start(w, cmd, args);
	(r, n)
}

/// [`library`], with what the command's start found.
fn library_start(w: &mut Wallet, cmd: &str, mut args: Value) -> (Result<Value, String>, u64, Value) {
	if COINS_ONLY.with(|c| c.get()) {
		args["recheck"] = json!("coins");
	}
	tokio::task::block_in_place(|| {
		let before = w.node_calls().0;
		let r = command::run(w, cmd, &args).map_err(|e| e.to_string());
		let start = r.as_ref().map(|v| v["start"].clone()).unwrap_or(Value::Null);
		(r.map(|v| v["result"].clone()), w.node_calls().0 - before, start)
	})
}

/// The same command on the wallet opened afresh, as a command line runs it.
fn afresh(a: &Arca, cmd: &str, args: Value) -> (Result<Value, String>, u64) {
	let mut w = tokio::task::block_in_place(|| Wallet::open(&a.dir)).expect("open the wallet");
	library(&mut w, cmd, args)
}

fn state_of(coins: &Value, leaf: &str) -> String {
	coins.as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).map(|c| c["state"].as_str().unwrap().to_string()).unwrap_or_default()
}

/// Signs input `i`, a P2WPKH coin `prev` of `key`.
fn sign_p2wpkh(tx: &mut Transaction, i: usize, prev: &elements::TxOut, key: &elements::secp256k1_zkp::Keypair) {
	use elements::hashes::Hash;
	let pk = key.public_key();
	let h = elements::hashes::hash160::Hash::hash(&pk.serialize());
	let code = Script::new_p2pkh(&elements::PubkeyHash::from_raw_hash(h));
	let sighash = elements::sighash::SighashCache::new(&*tx).segwitv0_sighash(i, &code, prev.value, elements::EcdsaSighashType::All);
	let msg = elements::secp256k1_zkp::Message::from_digest(sighash.to_byte_array());
	let sig = elements::secp256k1_zkp::Secp256k1::new().sign_ecdsa_low_r(&msg, &key.secret_key());
	let mut der = sig.serialize_der().to_vec();
	der.push(elements::EcdsaSighashType::All as u8);
	tx.input[i].witness.script_witness = vec![der, pk.serialize().to_vec()];
}

#[tokio::test(flavor = "multi_thread")]
async fn an_open_wallet_answers_from_the_view_and_sees_every_change_before_it_signs() {
	sees_every_change(false).await
}

/// The same changes, every command asking for the coins-only start
/// (`"recheck": "coins"`, a maker's answer path): each is still seen before
/// the next command signs, and the start leaves the participations' rounds
/// to `sync`.
#[tokio::test(flavor = "multi_thread")]
async fn the_coins_only_start_sees_every_change_to_a_coin_before_it_signs() {
	sees_every_change(true).await
}

async fn sees_every_change(coins_only: bool) {
	let mut r = Running::start().await;
	let x = r.x;
	let xs = x.to_string();
	let url = r.url();
	// A reaches the operator through a proxy that can make it show another key.
	let proxy = Proxy::start(&url);
	let a = Arca::new(if coins_only { "VCA" } else { "VA" });
	let b = Arca::new(if coins_only { "VCB" } else { "VB" });
	boarded(&mut r, &a, &proxy.url, x, 2_000_000).await;
	let b_board = boarded(&mut r, &b, &url, x, 3_000_000).await;
	// A refreshes its board into a leaf of a round.
	a.ok(&["participate"]);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let round = built.tx.txid();
	r.produce().await;
	r.bury().await;
	r.round_state(&round, RoundState::Final).await;
	a.ok(&["sync"]);
	let coins = a.ok(&["coins"]);
	let leaf = coins.as_array().unwrap().iter().find(|c| c["kind"] == "batch" && c["state"] == "live").expect("A's round leaf")["leaf_id"]
		.as_str().unwrap().to_string();

	let mut w = tokio::task::block_in_place(|| Wallet::open(&a.dir)).expect("open A's wallet");
	if coins_only {
		// A new block, so the first command's start re-checks rather than
		// watching lineages only: the coins-only start runs the coins and
		// their lineages, and not the participations' rounds.
		r.produce().await;
		r.synced().await;
		let (c, _, start) = library_start(&mut w, "coins", json!({"recheck": "coins"}));
		c.unwrap();
		println!("the coins-only start: {}", start["recheck"]);
		assert!(start["recheck"]["coins_only"].is_string(), "{}", start);
		let ms = start["recheck"]["ms"].as_object().unwrap();
		assert!(ms.contains_key("coins") && ms.contains_key("lineages"), "{}", start);
		assert!(!ms.contains_key("participations") && !ms.contains_key("rounds"), "{}", start);
		// Not taken for a complete re-check: a command asking for none runs it.
		let (_, _, full) = library_start(&mut w, "coins", json!({}));
		println!("the next start, asking for none: {}", full["recheck"]["ms"]);
		assert!(full["recheck"]["ms"].get("participations").is_some(), "{}", full);
		COINS_ONLY.with(|c| c.set(true));
	}

	// --- Between tip changes ---
	let (first, n_first) = library(&mut w, "coins", json!({}));
	let first = first.unwrap();
	let (again, n_again) = library(&mut w, "coins", json!({}));
	let (fresh, n_fresh) = afresh(&a, "coins", json!({}));
	println!("coins: {} node calls opened afresh, {} for the first command of the open wallet, {} for the next", n_fresh, n_first, n_again);
	assert_eq!(again.unwrap(), first, "the open wallet answers the same between tip changes");
	assert_eq!(fresh.unwrap(), first, "and the same as a wallet opened afresh");
	assert!(n_again <= 8 && n_again < n_fresh, "the chain read again from the view: {} calls against {}", n_again, n_fresh);
	for cmd in ["balance", "swaps", "participations"] {
		let (_, n) = library(&mut w, cmd, json!({}));
		let (_, n2) = library(&mut w, cmd, json!({}));
		println!("{}: {} node calls, then {}", cmd, n, n2);
		assert!(n2 <= 8, "{}: {} calls between tip changes", cmd, n2);
	}

	// --- A rollback of the coin's round between two commands ---
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let block = rpc(&r, "getrawtransaction", &[json!(round.to_string()), json!(true)])["blockhash"].as_str().unwrap().to_string();
	let _ = rpc(&r, "invalidateblock", &[json!(block)]);
	let (sent, n) = library(&mut w, "send", json!({"request": req, "amount": "300000", "asset": xs}));
	let why = sent.expect_err("nothing is paid from a coin whose round the chain no longer holds");
	println!("REFUSED (send after the round's block left the chain, {} node calls): {}", n, why);
	assert!(why.contains("in live coins"), "{}", why);
	let (c, _) = library(&mut w, "coins", json!({}));
	let c = c.unwrap();
	assert_eq!(state_of(&c, &leaf), "pending", "the round's leaf waits on the round again: {}", c);
	let _ = rpc(&r, "reconsiderblock", &[json!(block)]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let (c, _) = library(&mut w, "coins", json!({}));
	assert_eq!(state_of(&c.unwrap(), &leaf), "live", "the round back in the chain, final");

	// --- An operator showing another key between two commands ---
	let other = common::running::keypair("another operator").x_only_public_key().0.to_string();
	let shown = other.clone();
	proxy.rewrite(Some(Arc::new(move |path: &str, _: &Value, _: u16, answer: &mut Value| {
		if path.ends_with("/info") {
			answer["operator"] = json!(shown.clone());
		}
		None
	})));
	let (c, _) = library(&mut w, "coins", json!({}));
	assert!(c.is_ok(), "a command that signs nothing and asks the operator nothing answers: {:?}", c);
	let (sent, _) = library(&mut w, "send", json!({"request": req, "amount": "300000", "asset": xs}));
	let why = sent.expect_err("nothing is signed for an operator showing another key");
	println!("REFUSED (send, the operator showing key {}): {}", other, why);
	assert!(why.contains("the server now names operator key") && why.contains(&other), "{}", why);
	let (q, _) = library(&mut w, "quote", json!({}));
	let why = q.expect_err("nor quoted");
	assert!(why.contains("the server now names operator key"), "{}", why);
	proxy.rewrite(None);
	let (sent, _) = library(&mut w, "send", json!({"request": req, "amount": "300000", "asset": xs}));
	sent.expect("the operator's own key again: the payment goes ahead");
	assert_eq!(b.ok(&["mailbox"])["accepted"].as_array().unwrap().len(), 1, "B gets its coin");

	// --- A coin received between two commands: checked before it is counted ---
	let (rq, _) = library(&mut w, "receive", json!({"asset": xs, "amount": "400000"}));
	let rq = rq.unwrap()["request"].as_str().unwrap().to_string();
	b.ok(&["send", &rq, "--amount", "400000", "--asset", &xs]);
	let total = |v: &Value| -> u64 { v["held"][&xs].as_str().and_then(|s| s.parse().ok()).unwrap_or(0) };
	let (bal0, _) = library(&mut w, "balance", json!({}));
	let bal0 = bal0.unwrap();
	let (s, _) = library(&mut w, "sync", json!({}));
	let s = s.unwrap();
	let got = s["mailbox"]["accepted"].as_array().cloned().unwrap_or_default();
	assert_eq!(got.len(), 1, "the coin is read from the mailbox and checked: {}", s["mailbox"]);
	let coin = got[0]["leaf_id"].as_str().unwrap().to_string();
	let (bal1, _) = library(&mut w, "balance", json!({}));
	let bal1 = bal1.unwrap();
	println!("balance in leaves of X: {} before the sync, {} after", total(&bal0), total(&bal1));
	assert_eq!(total(&bal1), total(&bal0) + 400_000, "counted once checked: {} then {}", bal0, bal1);
	let (fresh, _) = afresh(&a, "balance", json!({}));
	assert_eq!(fresh.unwrap(), bal1, "as a wallet opened afresh counts it");

	// --- A spend of a coin's root in a block between two commands ---
	// B boards again and pays A from that board, then converts the board
	// with its own key, and the conversion is in a block before A's next
	// command: the wallet never sees it in the mempool. The new tip's re-check
	// finds the board spent and takes the coin on the chain at once.
	let mnemonic = std::fs::read_to_string(b.dir.join("mnemonic")).unwrap();
	let b_keys = bark::arca::keys::Keys::new(mnemonic.trim(), 0, 1).unwrap();
	r.pay_to(script(&b.ok(&["address"])), x, 13_000_000);
	r.produce().await;
	let b_board2 = b.ok(&["board", &xs, "10000000"])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("B's second board to be credited", || b.ok(&["boards"]).as_array().unwrap().iter().all(|x| x["server"]["state"] == "credited")).await;
	b.ok(&["sync"]);
	let (rq2, _) = library(&mut w, "receive", json!({"asset": xs, "amount": "5000000"}));
	let rq2 = rq2.unwrap()["request"].as_str().unwrap().to_string();
	b.ok(&["send", &rq2, "--amount", "5000000", "--asset", &xs]);
	let (s2, _) = library(&mut w, "sync", json!({}));
	let got2 = s2.unwrap()["mailbox"]["accepted"].as_array().cloned().unwrap_or_default();
	assert_eq!(got2.len(), 1, "A takes B's second payment");
	let coin2 = got2[0]["leaf_id"].as_str().unwrap().to_string();
	let CoinRecord::Board(rec2) = record_of(&b, &b_board2) else { panic!("a board") };
	let leaf_key2 = b_keys.leaf(&rec2.owner_nonce).unwrap();
	let found2 = rpc(&r, "scantxoutset", &[json!("start"), json!([format!("raw({})", hex(rec2.output().txout().script_pubkey.as_bytes()))])]);
	let u2 = &found2["unspents"][0];
	let board2_at = OutPoint::new(u2["txid"].as_str().unwrap().parse().unwrap(), u2["vout"].as_u64().unwrap() as u32);
	let fee_key2 = common::running::keypair("sender fee coin 2");
	let fee_script2 = bark::arca::keys::p2wpkh(&fee_key2);
	let paid2 = r.pay_to(fee_script2.clone(), x, 100_000);
	r.produce().await;
	let (c, _) = library(&mut w, "coins", json!({}));
	assert_eq!(state_of(&c.unwrap(), &coin2), "live", "the second coin, before B goes back on it");
	let j2 = paid2.output.iter().position(|o| o.script_pubkey == fee_script2).unwrap();
	let fee_coin2 = (OutPoint::new(paid2.txid(), j2 as u32), paid2.output[j2].clone());
	let genesis2 = r.rt.client().genesis_hash().unwrap();
	let ks2 = rec2.policy().conversion(board2_at, &FeeSource::Coin { outpoint: fee_coin2.0, coin: fee_coin2.1.clone(), fee: 2_000,
		change: fee_script2.clone() }).unwrap();
	let sig2 = arca_covenant::sign::sign_digest(&leaf_key2, &ks2.sighash(genesis2).unwrap(), &[0; 32]);
	let mut conv2 = ks2.finish(vec![sig2.as_ref().to_vec()]).tx;
	let fi2 = conv2.input.iter().position(|i| i.previous_output == fee_coin2.0).unwrap();
	sign_p2wpkh(&mut conv2, fi2, &fee_coin2.1, &fee_key2);
	// The operator stopped, so that its watcher does not answer first.
	r.server.stop();
	let conv2_id = r.rt.client().send_raw_transaction(&conv2).expect("the conversion relays");
	r.produce().await;
	assert!(rpc(&r, "getrawtransaction", &[json!(conv2_id.to_string()), json!(true)])["blockhash"].is_string(), "the conversion is in a block");
	let (c, n) = library(&mut w, "coins", json!({}));
	let c = c.unwrap();
	println!("coins after B's conversion {} was mined ({} node calls): the coin {}", conv2_id, n, state_of(&c, &coin2));
	assert_eq!(state_of(&c, &coin2), "exiting", "the new tip's re-check finds the board spent and takes the coin on the chain: {}", c);
	r.restart_server().await;

	// --- A spend of the coin's lineage in the mempool between two commands ---
	// B converts the board it paid from with its own key: the transaction
	// sits in the mempool; the chain's tip has not moved.
	let CoinRecord::Board(rec) = record_of(&b, &b_board) else { panic!("a board") };
	let mnemonic = std::fs::read_to_string(b.dir.join("mnemonic")).unwrap();
	let keys = bark::arca::keys::Keys::new(mnemonic.trim(), 0, 1).unwrap();
	let leaf_key = keys.leaf(&rec.owner_nonce).unwrap();
	let found = rpc(&r, "scantxoutset", &[json!("start"), json!([format!("raw({})", hex(rec.output().txout().script_pubkey.as_bytes()))])]);
	let u = &found["unspents"][0];
	let board_at = OutPoint::new(u["txid"].as_str().unwrap().parse().unwrap(), u["vout"].as_u64().unwrap() as u32);
	let fee_key = common::running::keypair("sender fee coin");
	let fee_script = bark::arca::keys::p2wpkh(&fee_key);
	let paid = r.pay_to(fee_script.clone(), x, 100_000);
	r.produce().await;
	assert_eq!(state_of(&library(&mut w, "coins", json!({})).0.unwrap(), &coin), "live", "the received coin, before B goes back on it");
	let j = paid.output.iter().position(|o| o.script_pubkey == fee_script).unwrap();
	let fee_coin = (OutPoint::new(paid.txid(), j as u32), paid.output[j].clone());
	let genesis = r.rt.client().genesis_hash().unwrap();
	let ks = rec.policy().conversion(board_at, &FeeSource::Coin { outpoint: fee_coin.0, coin: fee_coin.1.clone(), fee: 2_000,
		change: fee_script.clone() }).unwrap();
	let sig = arca_covenant::sign::sign_digest(&leaf_key, &ks.sighash(genesis).unwrap(), &[0; 32]);
	let mut conv = ks.finish(vec![sig.as_ref().to_vec()]).tx;
	let fi = conv.input.iter().position(|i| i.previous_output == fee_coin.0).unwrap();
	sign_p2wpkh(&mut conv, fi, &fee_coin.1, &fee_key);
	// The operator stopped, so that its watcher does not answer first.
	r.server.stop();
	let tip = rpc(&r, "getbestblockhash", &[]);
	let conv_id = r.rt.client().send_raw_transaction(&conv).expect("the conversion relays");
	assert_eq!(rpc(&r, "getbestblockhash", &[]), tip, "the tip has not moved");
	let (c, n) = library(&mut w, "coins", json!({}));
	let c = c.unwrap();
	println!("coins after B's conversion {} entered the mempool ({} node calls): the coin {}", conv_id, n, state_of(&c, &coin));
	assert_eq!(state_of(&c, &coin), "exiting", "the next command's re-check takes the coin on the chain at once: {}", c);
	let pool = rpc(&r, "getrawmempool", &[]);
	let answered = pool.as_array().unwrap().iter().filter_map(|t| t.as_str()).filter(|t| *t != conv_id.to_string())
		.any(|t| r.rt.client().raw_transaction(&t.parse().unwrap()).unwrap().input.iter().any(|i| i.previous_output.txid == conv_id));
	assert!(answered, "A's checkpoint answers the converted leaf in the mempool");
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}
