//! Swaps whose checkpoints carry their owners' exit, run by the `arca`
//! binary against a whole Arca server on an anchored regtest chain.
//!
//! - Two wallets of this build swap: the offer asks for the exit, the
//!   acceptance signs so, and the coins the swap makes have records of
//!   format version 2. The counterparty and the operator then spend the
//!   counterparty's checkpoint elsewhere: the maker's re-check finds the
//!   coin it got cut, starts taking the coin it gave home by its
//!   checkpoint, waits its exit delay, claims it with its own key, and the
//!   coin is exited, the trade undone.
//! - The same swap, the maker restored from its mnemonic in the middle of
//!   that return: the restored wallet finishes it.
//! - A maker pulls out of a good swap by publishing its own checkpoint: the
//!   taker's re-check answers with its checkpoint and the reassignment, and
//!   the maker's exit after the delay finds its checkpoint spent.
//! - An operator that does not offer the exit: the offer does not ask, and
//!   the records are version 1.
//! - Old against new, in both roles (`ARCA_CLI_OLDER`, an `arca` built from
//!   a library without the exit): the swap completes without it. A coin of
//!   the newer record format is never handed to the older build: a payment
//!   or a trade that could pay only with such coins is refused, and the
//!   wallet that requires the exit refuses a trade with it.
//! - A watchtower named by both sides holds the trade's coins before the
//!   swap is reported done, and with both wallets away it answers the
//!   taker's checkpoint published early by bringing the maker's on and
//!   publishing the reassignment.
//! - A taker holding only coins of the newer format fills an older
//!   maker's resting order: refused before signing, naming the older build;
//!   a taker with a coin of the older format fills it, and the maker reads
//!   its credit.
//! - Older parties as their texts show them (an offer, an acceptance, a
//!   receive request without the fields this build adds): no coin of the
//!   newer format goes to them, and the wallet that requires the exit
//!   refuses each before signing.
//!
//! The operator's watcher is off in every test that stages an attack, so
//! its answer does not race the test's.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use elements::{AssetId, OutPoint, Script, Transaction};
use serde_json::{json, Value};

use arca_covenant::spend::FeeSource;
use arca_covenant::transfer::reassignment_tx;
use arca_covenant::{Chain, CoinRecord, ExplicitOutput, MedianTime, Pair, TransferPlan, ValidCoin, ValidInput, ValidOrigin, WalletPolicy};
use common::cli::Arca;
use common::running::{keypair, Running};

const DELAY: u32 = 512;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
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

fn record_bytes(w: &Arca, leaf: &str) -> Vec<u8> {
	unhex(w.ok(&["record", leaf])["record"].as_str().unwrap())
}

/// The JSON a swap text (an offer, an acceptance) carries.
fn text_json(text: &str) -> Value {
	let (_, h) = text.split_once(':').unwrap();
	serde_json::from_slice(&unhex(h)).unwrap()
}

fn rpc(r: &Running, method: &str, params: &[Value]) -> Value {
	r.rt.client().call(method, params).unwrap()
}

/// The node's UTXO scan for `spk`. The node runs one scan at a time, and a
/// watchtower a test starts scans the same node: a scan refused as already
/// in progress is asked again.
fn scan(r: &Running, spk: &Script) -> Value {
	let start = std::time::Instant::now();
	loop {
		match r.rt.client().call::<Value>("scantxoutset", &[json!("start"), json!([format!("raw({})", hex(spk.as_bytes()))])]) {
			Ok(v) => return v,
			Err(e) if e.to_string().contains("Scan already in progress") && start.elapsed() < std::time::Duration::from_secs(60) => {
				std::thread::sleep(std::time::Duration::from_millis(200));
			},
			Err(e) => panic!("scantxoutset: {}", e),
		}
	}
}

fn find_unspent(r: &Running, out: &elements::TxOut) -> OutPoint {
	let found = scan(r, &out.script_pubkey);
	let u = found["unspents"].as_array().unwrap().first().unwrap_or_else(|| panic!("nothing pays {}", hex(out.script_pubkey.as_bytes())));
	OutPoint::new(elements::Txid::from_str(u["txid"].as_str().unwrap()).unwrap(), u["vout"].as_u64().unwrap() as u32)
}

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

/// Creates `w` on `server` and boards `amount` of `asset`; waits until the
/// board is credited. Its leaf id.
async fn boarded(r: &mut Running, w: &Arca, server: &str, asset: AssetId, amount: u64) -> String {
	w.ok(&create_args(server, &r.node_url()));
	let s = script(&w.ok(&["address"]));
	r.pay_to(s.clone(), asset, amount + 3_000_000);
	// Y is not accepted for fees: its board's fee is paid in X.
	let x = r.x;
	if asset != x {
		r.pay_to(s, x, 3_000_000);
	}
	r.produce().await;
	let (a, v, xs) = (asset.to_string(), amount.to_string(), x.to_string());
	let mut args = vec!["board", &a, &v];
	if asset != x {
		args.extend(["--fee-asset", &xs]);
	}
	let board = w.ok(&args)["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
	board
}

/// A fee coin of X paid to a key of the test's: its outpoint, its output and
/// its key.
async fn fee_coin(r: &mut Running, label: &str) -> (OutPoint, elements::TxOut, elements::secp256k1_zkp::Keypair) {
	let key = keypair(label);
	let s = bark::arca::keys::p2wpkh(&key);
	let paid = r.pay_to(s.clone(), r.x, 100_000);
	r.produce().await;
	let j = paid.output.iter().position(|o| o.script_pubkey == s).unwrap();
	(OutPoint::new(paid.txid(), j as u32), paid.output[j].clone(), key)
}

/// The transaction of `w`'s board `board`, while it is unspent.
fn board_tx(r: &Running, w: &Arca, board: &str) -> Transaction {
	let CoinRecord::Board(b) = CoinRecord::from_bytes(&record_bytes(w, board)).unwrap() else { panic!("a board") };
	let at = find_unspent(r, &b.output().txout());
	r.rt.client().raw_transaction(&at.txid).unwrap()
}

/// `w`'s coin `leaf`, resolved against the board transactions `bases`.
fn valid(r: &Running, w: &Arca, leaf: &str, bases: &[Transaction]) -> ValidCoin {
	let record = CoinRecord::from_bytes(&record_bytes(w, leaf)).unwrap();
	let genesis = r.rt.client().genesis_hash().unwrap();
	let now = MedianTime::from_consensus(common::node::median_time(&r.rt) as u32).unwrap();
	// The wallets here take exit delays down to one unit.
	let policy = WalletPolicy { min_exit_delay: arca_covenant::RelativeTime::from_units(1).unwrap(),
		..WalletPolicy::new(Chain::new(genesis), keypair("operator").x_only_public_key().0, now) };
	record.resolve(bases, &policy).unwrap()
}

fn inputs(c: &ValidCoin) -> Vec<ValidInput> {
	match &c.origin {
		ValidOrigin::Transfer { inputs, .. } => inputs.clone(),
		_ => panic!("a reassignment's coin"),
	}
}

struct Swapped {
	a: Arca,
	c: Arca,
	a_board: String,
	c_board: String,
	/// A's coin of Y, and C's coin of X.
	a_gets: String,
	c_gets: String,
	/// The two boards' transactions.
	bases: Vec<Transaction>,
	/// The maker's answer to `swap complete`.
	done: Value,
}

/// The text `text` (an offer, an acceptance, a receive request) as an older
/// build writes it: without the fields `drop`.
fn as_older(text: &str, drop: &[&str]) -> String {
	let (prefix, _) = text.split_once(':').unwrap();
	let mut v = text_json(text);
	for f in drop {
		v.as_object_mut().unwrap().remove(*f);
	}
	format!("{}:{}", prefix, hex(&serde_json::to_vec(&v).unwrap()))
}

/// A boards X, C boards Y; A offers 300,000 of X for 400,000 of Y and C
/// takes it.
async fn swap(r: &mut Running, tag: &str, a: Arca, c: Arca, exit: bool) -> Swapped {
	swap_towers(r, tag, a, c, exit, &[]).await
}

/// [`swap`], both sides naming the watchtowers `towers` first.
async fn swap_towers(r: &mut Running, tag: &str, a: Arca, c: Arca, exit: bool, towers: &[&str]) -> Swapped {
	let url = r.url();
	let (x, y) = (r.x, r.y);
	let a_board = boarded(r, &a, &url, x, 2_000_000).await;
	let c_board = boarded(r, &c, &url, y, 2_000_000).await;
	if !towers.is_empty() {
		for w in [&a, &c] {
			let mut args = vec!["watchtowers"];
			args.extend(towers);
			w.ok(&args);
		}
	}
	let bases = vec![board_tx(r, &a, &a_board), board_tx(r, &c, &c_board)];
	let offer = a.ok(&["swap", "offer", "--give-asset", &x.to_string(), "--give", "300000", "--want-asset", &y.to_string(), "--want", "400000"]);
	let offer_text = offer["offer"].as_str().unwrap().to_string();
	println!("{}: the offer asks for checkpoints with their owners' exit: {}", tag, text_json(&offer_text)["checkpoint_exit"]);
	let acc = c.ok(&["swap", "accept", &offer_text]);
	let acc_text = acc["accept"].as_str().unwrap().to_string();
	println!("{}: the acceptance signs so: {}", tag, text_json(&acc_text)["checkpoint_exit"]);
	let done = a.ok(&["swap", "complete", &acc_text]);
	println!("{}: the maker's watchtowers when the swap is reported done: {}", tag, done["watchtowers"]);
	if exit {
		let t = &done["watchtowers"];
		assert!(t["held"].is_array(), "{}: the answer says which watchtowers hold the trade's coins: {}", tag, done);
		if towers.is_empty() {
			assert!(t["not_held"].as_array().is_some_and(|n| !n.is_empty()), "{}", t);
			assert!(t["note"].as_str().unwrap().contains("the trade rests on this wallet"), "{}", t);
		}
	}
	a.ok(&["sync"]);
	let cs = c.ok(&["sync"]);
	if exit {
		println!("{}: the taker's watchtowers when it takes its coin: {}", tag,
			cs.to_string().contains("\"watchtowers\":{\"held\""));
	}
	let got = |w: &Arca, asset: AssetId, board: &str| w.ok(&["coins"]).as_array().unwrap().iter()
		.find(|k| k["asset"] == asset.to_string() && k["leaf_id"] != board && k["state"] == "live"
			&& k["value"].as_str().unwrap().parse::<u64>().unwrap() < 1_000_000)
		.unwrap_or_else(|| panic!("{}: the swap's coin of {}", tag, asset))["leaf_id"].as_str().unwrap().to_string();
	let (a_gets, c_gets) = (got(&a, y, &a_board), got(&c, x, &c_board));
	for (w, l) in [(&a, &a_gets), (&c, &c_gets)] {
		let v = record_bytes(w, l)[0];
		println!("{}: {}'s coin {} has a record of format version {}", tag, w.name, &l[..16], v);
		assert_eq!(v, if exit { 2 } else { 1 }, "{}: the record format", tag);
	}
	Swapped { a, c, a_board, c_board, a_gets, c_gets, bases, done }
}

/// Publishes `i`'s checkpoint from its board output, its fee from a coin of
/// the test's; mined unless `hold`.
async fn publish_board_checkpoint(r: &mut Running, i: &ValidInput, label: &str, hold: bool) -> OutPoint {
	let (op, out, key) = fee_coin(r, label).await;
	let mut tx = i.board_checkpoint_tx(&FeeSource::Coin { outpoint: op, coin: out.clone(), fee: 3_000, change: bark::arca::keys::p2wpkh(&key) })
		.unwrap().tx;
	let k = tx.input.iter().position(|x| x.previous_output == op).unwrap();
	sign_p2wpkh(&mut tx, k, &out, &key);
	let id = r.rt.client().send_raw_transaction(&tx).expect("the checkpoint relays");
	if !hold {
		r.produce().await;
	}
	println!("{}: {} ({} vB)", label, id, tx.vsize());
	OutPoint::new(id, 0)
}

/// The owner key of `w`'s board `board`, from its mnemonic.
fn board_key(w: &Arca, board: &str) -> elements::secp256k1_zkp::Keypair {
	let CoinRecord::Board(rec) = CoinRecord::from_bytes(&record_bytes(w, board)).unwrap() else { panic!("a board") };
	let mnemonic = std::fs::read_to_string(w.dir.join("mnemonic")).unwrap();
	bark::arca::keys::Keys::new(mnemonic.trim(), 0, 1).unwrap().leaf(&rec.owner_nonce).unwrap()
}

/// C and the operator spend C's checkpoint elsewhere: the swap can never
/// complete. Where C's checkpoint is.
async fn kill(r: &mut Running, sw: &Swapped, tag: &str) -> OutPoint {
	let a_gets = valid(r, &sw.a, &sw.a_gets, &sw.bases);
	kill_input(r, &a_gets, &sw.c, &sw.c_board, tag).await
}

/// The owner of board `board` (in wallet `w`), an input of the trade that
/// made `made`, and the operator spend its checkpoint elsewhere: the trade
/// can never complete. Where that checkpoint is.
async fn kill_input(r: &mut Running, made: &ValidCoin, w: &Arca, board: &str, tag: &str) -> OutPoint {
	let ins = inputs(made);
	let ci = ins.iter().find(|i| i.coin.id.to_string() == board).expect("the board is an input").clone();
	assert!(ci.checkpoint.exit.is_some());
	// Everything first: any run of the owner's wallet (each re-checks on
	// start) would answer its checkpoint with the trade, as an honest wallet
	// does.
	let ck = board_key(w, board);
	let (op, out, key) = fee_coin(r, &format!("{} attack fee", tag)).await;
	let back = vec![ExplicitOutput::new(ci.coin.asset, ci.checkpoint_value, Script::from(vec![0x51]))];
	let plan = TransferPlan { locks: vec![], checkpoint_exit: true, inputs: vec![(ci.coin.clone(), ci.checkpoint_value)], outputs: back.clone() };
	let d = plan.reassignment_message(0).unwrap().digest;
	let sig = |k: &elements::secp256k1_zkp::Keypair| arca_covenant::sign::sign_digest(k, &d, &[0; 32]);
	let second = ValidInput { reassignment_pair: Pair { operator: sig(&keypair("operator")), owner: sig(&ck) }, ..ci.clone() };
	let cp = publish_board_checkpoint(r, &ci, &format!("{}: {}'s checkpoint from its board", tag, w.name), true).await;
	let mut tx = reassignment_tx(&[second], &back, &[cp], &FeeSource::Coin { outpoint: op, coin: out.clone(), fee: 3_000,
		change: bark::arca::keys::p2wpkh(&key) }).unwrap().tx;
	let k = tx.input.iter().position(|x| x.previous_output == op).unwrap();
	sign_p2wpkh(&mut tx, k, &out, &key);
	let id = r.rt.client().send_raw_transaction(&tx).expect("the second reassignment relays");
	r.produce().await;
	println!("{}: ATTACK {} + operator: a second reassignment of its checkpoint {} ({} vB)", tag, w.name, id, tx.vsize());
	cp
}

/// Moves `w`'s return of its board on until it is exited, the delay run.
async fn finish_return(r: &Running, w: &Arca, board: &str, tag: &str) -> Value {
	let early = w.ok(&["exit", board]);
	println!("{}: the return before the delay: {}", tag, early);
	assert!(matches!(early["state"].as_str(), Some("waiting") | Some("unrolling")), "{}", early);
	common::node::advance_mtp(&r.rt, DELAY + 120);
	let claimed = w.ok(&["exit", board]);
	println!("{}: the return after the delay: {}", tag, claimed);
	assert_eq!(claimed["state"], "claimed", "{}", claimed);
	assert_eq!(claimed["returned"], true);
	r.produce().await;
	r.bury().await;
	let done = w.ok(&["exit", board]);
	println!("{}: the return once the claim is final: {}", tag, done);
	done
}

/// A watchtower's `serve` process, stopped when dropped.
struct Tower {
	wallet: Arca,
	url: String,
	child: Child,
}

impl Tower {
	fn new(name: &str, server: &str, node: &str) -> Tower {
		let wallet = Arca::new(name);
		wallet.ok(&create_args(server, node));
		let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
		let listen = format!("127.0.0.1:{}", port);
		let log = std::fs::File::create(wallet.dir.join("serve.log")).unwrap();
		let child = Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&wallet.dir)
			.args(["watchtower", "serve", "--listen", &listen, "--interval", "1"])
			.env("ARCA_NODE_PASSWORD", "arca").stdout(Stdio::null()).stderr(log).spawn().unwrap();
		let start = Instant::now();
		while std::net::TcpStream::connect(&listen).is_err() {
			assert!(start.elapsed() < Duration::from_secs(30), "watchtower {} did not start", name);
			std::thread::sleep(Duration::from_millis(100));
		}
		Tower { wallet, url: format!("http://{}", listen), child }
	}
}

impl Drop for Tower {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
		let _ = std::fs::remove_dir_all(&self.wallet.dir);
	}
}

/// `w`'s swaps, as the library lists them.
fn swaps_of(w: &Arca) -> Value {
	tokio::task::block_in_place(|| {
		let mut ww = bark::arca::Wallet::open(&w.dir).expect("open the wallet");
		bark::arca::command::run(&mut ww, "swaps", &json!({})).map(|v| v["result"].clone()).unwrap()
	})
}

/// The one swap of `w`'s in state `state`, or that returns coin `given`.
fn returning_swap(w: &Arca, given: &str) -> Value {
	let all = swaps_of(w);
	all.as_array().unwrap().iter().find(|s| s["return"]["coins"].to_string().contains(given)).cloned()
		.unwrap_or_else(|| panic!("{}: no swap returns coin {}: {}", w.name, given, all))
}

fn watcher_off() -> impl FnOnce(&mut server::server::Config, AssetId, AssetId) {
	|c, _, _| c.watcher.enabled = false
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dead_swap_returns_the_makers_coin_by_its_checkpoint() {
	let mut r = Running::start_with(watcher_off()).await;
	let sw = swap(&mut r, "CE1", Arca::new("CE1 A"), Arca::new("CE1 C"), true).await;
	kill(&mut r, &sw, "CE1").await;
	// A's re-check finds the coin of Y it got cut, and starts its board's return.
	let rc = sw.a.ok(&["recheck"]);
	println!("CE1: A's re-check: {}", rc["changes"]);
	let given = coin_of(&sw.a, &sw.a_board);
	println!("CE1: A's board after the re-check: {}", given);
	assert_eq!(given["state"], "exiting", "{}", given);
	assert!(given["note"].as_str().unwrap_or("").contains("comes home by its checkpoint's own exit"), "{}", given);
	// While the coin it gave comes home, the coin the dead trade made is out
	// of the balance, its note saying why.
	let y = coin_of(&sw.a, &sw.a_gets);
	println!("CE1: A's coin of Y while the return waits: {}", y);
	assert_eq!(y["state"], "lost", "{}", y);
	let why = y["note"].as_str().unwrap_or("");
	assert!(why.contains("the trade that made it was undone") || why.contains("the trade that made it can never complete"), "{}", y);
	let ret = returning_swap(&sw.a, &sw.a_board);
	println!("CE1: A's swap while the return waits: {}", ret);
	assert_eq!(ret["state"], "returning", "{}", ret);
	assert_eq!(ret["return"]["asset"], r.x.to_string());
	assert!(ret["return"]["value"].as_str().unwrap().parse::<u64>().unwrap() >= 300_000, "{}", ret);
	assert!(ret["return"]["claim_from"].is_u64(), "{}", ret);
	let bal = sw.a.ok(&["balance"]);
	println!("CE1: A's balance while the return waits: {}", bal);
	assert!(bal["held"][r.y.to_string()].is_null() || bal["held"][r.y.to_string()] == "0", "{}", bal);
	let done = finish_return(&r, &sw.a, &sw.a_board, "CE1").await;
	assert_eq!(done["state"], "exited", "{}", done);
	let given = coin_of(&sw.a, &sw.a_board);
	println!("CE1: A's board at the end: {}", given);
	assert_eq!(given["state"], "exited");
	assert!(given["note"].as_str().unwrap_or("").contains("returned"), "{}", given);
	let y = coin_of(&sw.a, &sw.a_gets);
	println!("CE1: A's coin of Y at the end: {}", y);
	assert_ne!(y["state"], "live", "the coin the dead swap was to pay is not shown as held");
	let why = y["note"].as_str().unwrap_or("");
	assert!(why.contains("was undone") || why.contains("the trade that made it can never complete"), "{}", y);
	let swaps = swaps_of(&sw.a);
	println!("CE1: A's swaps at the end: {}", swaps);
	assert!(swaps.as_array().unwrap().iter().any(|s| s["state"] == "returned"), "the swap is recorded as returned: {}", swaps);
	// A restore once the claim is final: the given coin reads as exited, by
	// the checkpoint's exit leaf, though the restored wallet drew another
	// claim address.
	let a2 = Arca::new("CE1 A2");
	let mnemonic = std::fs::read_to_string(sw.a.dir.join("mnemonic")).unwrap();
	let (url, node) = (r.url(), r.node_url());
	let mut args = create_args(&url, &node);
	args.extend(["--mnemonic", mnemonic.trim()]);
	a2.ok(&args);
	a2.ok(&["sync"]);
	a2.ok(&["recheck"]);
	let after = a2.ok(&["exit", &sw.a_board]);
	println!("CE1: the restored wallet's return of the board A gave: {}", after);
	assert_eq!(after["state"], "exited", "{}", after);
	assert_eq!(coin_of(&a2, &sw.a_board)["state"], "exited");
	let ret = returning_swap(&a2, &sw.a_board);
	println!("CE1: the restored wallet's swaps: {}", ret);
	assert_eq!(ret["state"], "returned", "{}", ret);
	let y = coin_of(&a2, &sw.a_gets);
	println!("CE1: the restored wallet's coin of Y: {}", y);
	assert_ne!(y["state"], "live", "{}", y);
	for w in [&sw.a, &sw.c, &a2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restore_in_the_middle_of_a_return_finishes_it() {
	let mut r = Running::start_with(watcher_off()).await;
	let sw = swap(&mut r, "CE2", Arca::new("CE2 A"), Arca::new("CE2 C"), true).await;
	kill(&mut r, &sw, "CE2").await;
	sw.a.ok(&["recheck"]);
	let started = sw.a.ok(&["exit", &sw.a_board]);
	println!("CE2: A's return started: {}", started);
	r.produce().await;
	// A is lost; A2 from its mnemonic alone.
	let a2 = Arca::new("CE2 A2");
	let mnemonic = std::fs::read_to_string(sw.a.dir.join("mnemonic")).unwrap();
	let (url, node) = (r.url(), r.node_url());
	let mut args = create_args(&url, &node);
	args.extend(["--mnemonic", mnemonic.trim()]);
	let made = a2.ok(&args);
	println!("CE2: A2's restore: {}", made["restore"]);
	a2.ok(&["sync"]);
	a2.ok(&["recheck"]);
	let given = coin_of(&a2, &sw.a_board);
	println!("CE2: A2's view of the board A gave: {}", given);
	assert_eq!(given["state"], "exiting", "{}", given);
	let ret = returning_swap(&a2, &sw.a_board);
	println!("CE2: A2's swaps while the return waits: {}", ret);
	assert_eq!((ret["state"].as_str(), ret["return"]["asset"].as_str()), (Some("returning"), Some(r.x.to_string().as_str())), "{}", ret);
	let done = finish_return(&r, &a2, &sw.a_board, "CE2").await;
	assert_eq!(done["state"], "exited", "{}", done);
	assert_eq!(returning_swap(&a2, &sw.a_board)["state"], "returned");
	for w in [&sw.a, &sw.c, &a2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn a_maker_that_pulls_out_of_a_good_swap_is_answered_by_the_taker() {
	let mut r = Running::start_with(watcher_off()).await;
	let sw = swap(&mut r, "CE3", Arca::new("CE3 A"), Arca::new("CE3 C"), true).await;
	let a_gets = valid(&r, &sw.a, &sw.a_gets, &sw.bases);
	let ai = inputs(&a_gets).into_iter().find(|i| i.coin.id.to_string() == sw.a_board).unwrap();
	let a_cp = publish_board_checkpoint(&mut r, &ai, "CE3: A publishes its own checkpoint, to pull out", false).await;
	// C's re-check answers: its checkpoint and the reassignment.
	let rc = sw.c.ok(&["recheck"]);
	let ch = rc["changes"].as_array().unwrap().iter().find(|c| c["leaf_id"] == sw.c_gets.as_str()).cloned()
		.unwrap_or_else(|| panic!("C's re-check acts on its coin: {}", rc));
	println!("CE3: C's re-check: {}", ch);
	r.produce().await;
	let c_x = valid(&r, &sw.c, &sw.c_gets, &sw.bases);
	let leaf_at = find_unspent(&r, &c_x.output().txout());
	println!("CE3: C's coin of X is on the chain at {}", leaf_at);
	// A's exit of its checkpoint after the delay: spent.
	common::node::advance_mtp(&r.rt, DELAY + 120);
	let ak = board_key(&sw.a, &sw.a_board);
	let ks = ai.checkpoint.exit_tx(a_cp, ai.coin.asset, ai.checkpoint_value, &[ExplicitOutput::new(ai.coin.asset,
		ai.checkpoint_value - 2_000, Script::from(vec![0x51]))], &FeeSource::Reserve).unwrap();
	let genesis = r.rt.client().genesis_hash().unwrap();
	let sig = arca_covenant::sign::sign_digest(&ak, &ks.sighash(genesis).unwrap(), &[0; 32]);
	let e = r.rt.client().send_raw_transaction(&ks.finish(vec![sig.as_ref().to_vec()]).tx).expect_err("A's exit finds its checkpoint spent");
	println!("CE3: A's exit of its checkpoint after the delay: REFUSED: {}", e);
	assert!(e.to_string().contains("missingorspent") || e.to_string().contains("missing-inputs"), "{}", e);
	for w in [&sw.a, &sw.c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn an_operator_that_does_not_offer_the_exit_gets_swaps_without_it() {
	let mut r = Running::start_with(|c, _, _| c.checkpoint_exit = false).await;
	let sw = swap(&mut r, "CE4", Arca::new("CE4 A"), Arca::new("CE4 C"), false).await;
	// A wallet that requires the exit trades with nobody here.
	sw.a.ok(&["require-checkpoint-exit", "on"]);
	let (x, y) = (r.x.to_string(), r.y.to_string());
	sw.a.refused(&["swap", "offer", "--give-asset", &x, "--give", "100000", "--want-asset", &y, "--want", "100000"],
		"the operator does not offer it");
	let offer = sw.c.ok(&["swap", "offer", "--give-asset", &y, "--give", "100000", "--want-asset", &x, "--want", "100000"]);
	sw.a.refused(&["swap", "accept", offer["offer"].as_str().unwrap()], "the maker's offer does not ask for it");
	for w in [&sw.a, &sw.c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// Old against new, in both roles: an `arca` built from a library without
/// the exit (`ARCA_CLI_OLDER`) and this build swap without it, whichever
/// makes the offer. Skipped when no older build is named.
#[tokio::test(flavor = "multi_thread")]
async fn old_and_new_wallets_swap_without_the_exit_in_both_roles() {
	let Some(older) = std::env::var("ARCA_CLI_OLDER").ok() else {
		println!("CE5: no ARCA_CLI_OLDER: old against new not run");
		return;
	};
	let older = std::path::Path::new(&older);
	let mut r = Running::start().await;
	let sw = swap(&mut r, "CE5 old maker", Arca::built_from("CE5 old A", older), Arca::new("CE5 new C"), false).await;
	let sw2 = swap(&mut r, "CE5 new maker", Arca::new("CE5 new A"), Arca::built_from("CE5 old C", older), false).await;
	// Two wallets of this build trade with the exit: every coin of the
	// trade, change included, has a record of the newer format.
	let sw3 = swap(&mut r, "CE5 new pair", Arca::new("CE5 new A3"), Arca::new("CE5 new C3"), true).await;
	let (url, x, y) = (r.url(), r.x, r.y);
	let (xs, ys) = (x.to_string(), y.to_string());
	let o = Arca::built_from("CE5 old O", older);
	boarded(&mut r, &o, &url, x, 1_000_000).await;
	// A payment to the older build, from coins only of the newer format.
	let req = o.ok(&["receive", "--asset", &ys, "--amount", "100000"])["request"].as_str().unwrap().to_string();
	sw3.a.refused(&["send", &req, "--amount", "100000", "--asset", &ys], "older build");
	// The older build makes an offer; C3's coins of Y are all of the newer
	// format.
	let o_offer = o.ok(&["swap", "offer", "--give-asset", &xs, "--give", "100000", "--want-asset", &ys, "--want", "100000"]);
	let offer = o_offer["offer"].as_str().unwrap().to_string();
	sw3.c.refused(&["swap", "accept", &offer], "older build");
	sw3.c.ok(&["require-checkpoint-exit", "on"]);
	sw3.c.refused(&["swap", "accept", &offer], "the maker's offer does not ask for it");
	// O's coin of X is held for that offer: given up, it pays the next.
	o.ok(&["swap", "cancel", o_offer["swap"].as_str().expect("the offer's swap id")]);
	// The older build takes an offer made from coins of the newer format:
	// its library reads no such record, and nothing is signed.
	let offer3 = sw3.a.ok(&["swap", "offer", "--give-asset", &ys, "--give", "100000", "--want-asset", &xs, "--want", "100000"])["offer"]
		.as_str().unwrap().to_string();
	let (ok, v) = o.run(&["swap", "accept", &offer3]);
	println!("CE5: the older build takes an offer made from coins of the newer format: {}", v);
	assert!(!ok, "the older build refuses it: {}", v);
	// A maker that requires the exit, the older build its taker: refused
	// when it completes, before it signs.
	let a4 = Arca::new("CE5 new A4");
	boarded(&mut r, &a4, &url, y, 1_000_000).await;
	a4.ok(&["require-checkpoint-exit", "on"]);
	let offer4 = a4.ok(&["swap", "offer", "--give-asset", &ys, "--give", "100000", "--want-asset", &xs, "--want", "100000"])["offer"]
		.as_str().unwrap().to_string();
	let acc4 = o.ok(&["swap", "accept", &offer4])["accept"].as_str().unwrap().to_string();
	println!("CE5: the older build's acceptance asks for the exit: {}", text_json(&acc4)["checkpoint_exit"]);
	a4.refused(&["swap", "complete", &acc4], "the taker signed the swap without it");
	for w in [&sw.a, &sw.c, &sw2.a, &sw2.c, &sw3.a, &sw3.c, &o, &a4] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// The chain follows a rollback, and so does the wallet. A's return of the
/// coin it gave waits its delay when the block holding the attack (C's
/// checkpoint and its second spend) leaves the chain; the replacing block
/// carries the swap instead (C's checkpoint, A's, and the reassignment).
/// A's next step reads the chain as it is now, finds its checkpoint spent
/// by the swap, and holds the coin as spent by the trade, which completed:
/// nothing it worked out before the rollback is kept.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_of_the_attack_while_the_return_waits_is_followed() {
	let mut r = Running::start_with(watcher_off()).await;
	let sw = swap(&mut r, "CE6", Arca::new("CE6 A"), Arca::new("CE6 C"), true).await;
	let a_y = valid(&r, &sw.a, &sw.a_gets, &sw.bases);
	let ins = inputs(&a_y);
	let c_cp = kill(&mut r, &sw, "CE6").await;
	let attack_block = rpc(&r, "getbestblockhash", &[]);
	sw.a.ok(&["recheck"]);
	r.produce().await;
	let waiting = sw.a.ok(&["exit", &sw.a_board]);
	println!("CE6: A's return before the rollback: {}", waiting);
	assert_eq!(waiting["state"], "waiting", "{}", waiting);
	// The rollback: the attack's block and every block above it leave.
	let a_cp = OutPoint::from_str(waiting["checkpoint"].as_str().unwrap().trim_start_matches("[elements]")).unwrap();
	assert_eq!(r.rt.client().raw_transaction(&a_cp.txid).unwrap().output[0], ins[0].checkpoint_output().txout());
	let a_cp_tx = r.rt.client().raw_transaction(&a_cp.txid).unwrap();
	let c_cp_tx = r.rt.client().raw_transaction(&c_cp.txid).unwrap();
	rpc(&r, "invalidateblock", &[attack_block.clone()]);
	// The node restarts with an empty mempool: the attack is gone with its block.
	let tip = rpc(&r, "getbestblockhash", &[]);
	let tip_time = rpc(&r, "getblockheader", &[tip])["time"].as_u64().unwrap();
	let mock = format!("-mocktime={}", tip_time + 120);
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0", &mock])).unwrap();
	let swap_tx = a_y.reassignment_tx(&[a_cp, c_cp], &FeeSource::Reserve).unwrap().tx;
	for (what, t) in [("C's checkpoint", &c_cp_tx), ("A's checkpoint", &a_cp_tx), ("the swap's reassignment", &swap_tx)] {
		let id = r.rt.client().send_raw_transaction(t).unwrap_or_else(|e| panic!("{}: {}", what, e));
		println!("CE6: after the rollback, {} {} ({} vB)", what, id, t.vsize());
	}
	r.produce().await;
	println!("CE6: the attack's block {} rolled back; the blocks replacing it carry C's checkpoint, A's and the swap", attack_block);
	r.bury().await;
	let after = sw.a.ok(&["exit", &sw.a_board]);
	println!("CE6: A's return after the rollback: {}", after);
	assert_eq!(after["state"], "spent", "{}", after);
	assert_eq!(coin_of(&sw.a, &sw.a_board)["state"], "spent");
	let y = coin_of(&sw.a, &sw.a_gets);
	println!("CE6: A's coin of Y after the rollback: {}", y);
	assert_ne!(y["state"], "lost", "{}", y);
	for w in [&sw.a, &sw.c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A watchtower both sides name holds the trade's coins before the swap is
/// reported done; with both wallets away, it answers the taker's checkpoint
/// published early: the maker's checkpoint and the reassignment, so the
/// maker's coin of Y stands on the chain.
#[tokio::test(flavor = "multi_thread")]
async fn a_watchtower_holds_the_trade_before_it_is_done_and_answers_a_pull_out() {
	let mut r = Running::start_with(watcher_off()).await;
	let (url, node) = (r.url(), r.node_url());
	let t = Tower::new("CE7 T", &url, &node);
	let sw = swap_towers(&mut r, "CE7", Arca::new("CE7 A"), Arca::new("CE7 C"), true, &[&t.url]).await;
	let held = &sw.done["watchtowers"]["held"];
	println!("CE7: the watchtowers holding the maker's coins of the trade: {}", held);
	assert!(held.as_array().unwrap().iter().any(|h| h["leaf_id"] == sw.a_gets.as_str() && h["watchtowers"].to_string().contains(&t.url)),
		"the watchtower holds A's coin of Y before the swap is done: {}", sw.done);
	assert!(sw.done["watchtowers"]["not_held"].is_null(), "{}", sw.done);
	// C pulls out: its checkpoint, early. Neither wallet runs again.
	let a_y = valid(&r, &sw.a, &sw.a_gets, &sw.bases);
	let ci = inputs(&a_y).into_iter().find(|i| i.coin.id.to_string() == sw.c_board).unwrap();
	publish_board_checkpoint(&mut r, &ci, "CE7: C publishes its own checkpoint, to pull out", false).await;
	let out = a_y.output().txout();
	let start = Instant::now();
	let at = loop {
		r.produce().await;
		let found = scan(&r, &out.script_pubkey);
		if let Some(u) = found["unspents"].as_array().and_then(|u| u.first()) {
			break format!("{}:{}", u["txid"].as_str().unwrap(), u["vout"]);
		}
		assert!(start.elapsed() < Duration::from_secs(120), "the watchtower did not answer C's checkpoint: {}",
			t.wallet.ok(&["watchtower", "deposits"]));
		tokio::time::sleep(Duration::from_secs(1)).await;
	};
	println!("CE7: the watchtower answered: A's coin of Y is on the chain at {}", at);
	println!("CE7: the watchtower's deposits: {}", t.wallet.ok(&["watchtower", "deposits"]));
	for w in [&sw.a, &sw.c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// Older parties as their texts show them: a receive request, an offer and
/// an acceptance without the fields this build adds (`reads`,
/// `checkpoint_exit`). No coin of the newer record format goes to them, and
/// a wallet that requires the exit refuses each trade before signing.
#[tokio::test(flavor = "multi_thread")]
async fn older_parties_get_no_coin_of_the_newer_format() {
	let mut r = Running::start().await;
	let sw = swap(&mut r, "CE8", Arca::new("CE8 A"), Arca::new("CE8 C"), true).await;
	let (url, node, x, y) = (r.url(), r.node_url(), r.x, r.y);
	let (xs, ys) = (x.to_string(), y.to_string());
	// A payment: A's coins of Y are all of the newer format.
	let b = Arca::new("CE8 B");
	b.ok(&create_args(&url, &node));
	let req = b.ok(&["receive", "--asset", &ys, "--amount", "100000"])["request"].as_str().unwrap().to_string();
	println!("CE8: B's request names the formats it reads: {}", text_json(&req)["reads"]);
	sw.a.refused(&["send", &as_older(&req, &["reads"]), "--amount", "100000", "--asset", &ys], "older build");
	sw.a.ok(&["send", &req, "--amount", "100000", "--asset", &ys]);
	b.ok(&["sync"]);
	let got = b.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["asset"] == ys.as_str()).cloned().expect("B's coin of Y");
	assert_eq!(record_bytes(&b, got["leaf_id"].as_str().unwrap())[0], 2, "a reader of the newer format is paid in it");
	// A trade with an older maker: C's coins of X are all of the newer format.
	let d = Arca::new("CE8 D");
	boarded(&mut r, &d, &url, y, 1_000_000).await;
	let offer = d.ok(&["swap", "offer", "--give-asset", &ys, "--give", "100000", "--want-asset", &xs, "--want", "100000"])["offer"]
		.as_str().unwrap().to_string();
	let older_offer = as_older(&offer, &["checkpoint_exit", "reads"]);
	sw.c.refused(&["swap", "accept", &older_offer], "older build");
	sw.c.ok(&["require-checkpoint-exit", "on"]);
	sw.c.refused(&["swap", "accept", &older_offer], "the maker's offer does not ask for it");
	// A maker that requires the exit, an older taker's acceptance.
	d.ok(&["require-checkpoint-exit", "on"]);
	let acc = sw.c.ok(&["swap", "accept", &offer])["accept"].as_str().unwrap().to_string();
	d.refused(&["swap", "complete", &as_older(&acc, &["checkpoint_exit", "reads"])], "the taker signed the swap without it");
	// The same acceptance as this build wrote it completes.
	let done = d.ok(&["swap", "complete", &acc]);
	println!("CE8: the swap D required the exit for completes: {}", done["watchtowers"]);
	for w in [&sw.a, &sw.c, &b, &d] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A taker away when its trade died: A, the maker, and the operator spend
/// A's checkpoint elsewhere before C's wallet ever reads the coin the swap
/// pays it. C's wallet runs again more than three days later: the coin in
/// its mailbox is refused for good, and the coin C gave comes home by its
/// checkpoint's own exit. The swap reads `returning`, with what comes home
/// and when, until the claim is final, then `returned`; the coin of X it
/// was to get is neither counted nor listed as pending.
#[tokio::test(flavor = "multi_thread")]
async fn a_taker_away_when_its_trade_died_gets_its_coin_back_days_later() {
	let mut r = Running::start_with(watcher_off()).await;
	let url = r.url();
	let (x, y) = (r.x, r.y);
	let (a, c) = (Arca::new("CE9 A"), Arca::new("CE9 C"));
	let a_board = boarded(&mut r, &a, &url, x, 2_000_000).await;
	let c_board = boarded(&mut r, &c, &url, y, 2_000_000).await;
	let bases = vec![board_tx(&r, &a, &a_board), board_tx(&r, &c, &c_board)];
	let offer = a.ok(&["swap", "offer", "--give-asset", &x.to_string(), "--give", "300000", "--want-asset", &y.to_string(), "--want", "400000"])
		["offer"].as_str().unwrap().to_string();
	let acc = c.ok(&["swap", "accept", &offer])["accept"].as_str().unwrap().to_string();
	a.ok(&["swap", "complete", &acc]);
	a.ok(&["sync"]);
	let a_gets = a.ok(&["coins"]).as_array().unwrap().iter()
		.find(|k| k["asset"] == y.to_string() && k["state"] == "live").expect("A's coin of Y")["leaf_id"].as_str().unwrap().to_string();
	let made = valid(&r, &a, &a_gets, &bases);
	kill_input(&mut r, &made, &a, &a_board, "CE9").await;
	common::node::advance_mtp(&r.rt, 3 * 86_400 + 600);
	r.produce().await;
	r.bury().await;
	println!("CE9: three days and more later, C's wallet runs again");
	let s = c.ok(&["sync"]);
	println!("CE9: C's sync, its mailbox: {}", s["mailbox"]);
	c.ok(&["recheck"]);
	let given = coin_of(&c, &c_board);
	println!("CE9: the board C gave: {}", given);
	assert_eq!(given["state"], "exiting", "{}", given);
	let ret = returning_swap(&c, &c_board);
	println!("CE9: C's swap: {}", ret);
	assert_eq!(ret["state"], "returning", "{}", ret);
	assert_eq!(ret["return"]["asset"], y.to_string());
	assert!(ret["return"]["claim_from"].is_u64(), "{}", ret);
	let bal = c.ok(&["balance"]);
	println!("CE9: C's balance while the return waits: {}", bal);
	assert!(bal["arca"][x.to_string()].is_null(), "the coin of X the dead swap was to pay is not counted: {}", bal);
	let again = c.ok(&["sync"]);
	assert!(!again.to_string().contains("\"pending\":[{"), "nothing of the dead swap is listed as pending: {}", again);
	let done = finish_return(&r, &c, &c_board, "CE9").await;
	assert_eq!(done["state"], "exited", "{}", done);
	let ret = returning_swap(&c, &c_board);
	println!("CE9: C's swap at the end: {}", ret);
	assert_eq!(ret["state"], "returned", "{}", ret);
	for w in [&a, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A wallet holding one coin of `asset`, boarded, with `fees` of X on the
/// chain (as `arca_resting.rs` makes them).
async fn holder(r: &mut Running, w: Arca, asset: AssetId, value: u64, fees: u64) -> Arca {
	let (url, node) = (r.url(), r.node_url());
	w.ok(&create_args(&url, &node));
	let s = script(&w.ok(&["address"]));
	r.pay_to(s.clone(), asset, value + 100_000);
	if fees > 0 {
		let x = r.x;
		r.pay_to(s, x, fees);
	}
	r.produce().await;
	w.ok(&["board", &asset.to_string(), &value.to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
	w
}

/// Runs the operator's rounds to final, then each wallet's sync.
async fn rounds(r: &mut Running, wallets: &[&Arca]) {
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	assert!(!built.is_empty(), "a round");
	r.produce().await;
	r.bury().await;
	r.synced().await;
	for b in &built {
		r.round_state(&b.tx.txid(), server::store::RoundState::Final).await;
	}
	for w in wallets {
		w.ok(&["sync"]);
	}
}

/// `maker` rests `amount` of X for Y at 2/1 in lots of `lot`: the order's id.
async fn rest(r: &mut Running, maker: &Arca, amount: u64, lot: u64) -> String {
	let (x, y) = (r.x, r.y);
	let args = |extra: &[&str]| -> Vec<String> {
		let mut v: Vec<String> = ["order", "rest", "--sell", &x.to_string(), "--amount", &amount.to_string(), "--for", &y.to_string(),
			"--rate-num", "2", "--rate-den", "1", "--min-lot", &lot.to_string(), "--expires-in-hours", "720"]
			.iter().map(|s| s.to_string()).collect();
		v.extend(extra.iter().map(|s| s.to_string()));
		v
	};
	let q = maker.ok(&args(&["--quote"]).iter().map(|s| s.as_str()).collect::<Vec<_>>());
	let shown = q.to_string();
	let rested = maker.ok(&args(&["--shown", &shown]).iter().map(|s| s.as_str()).collect::<Vec<_>>());
	rounds(r, &[maker]).await;
	let view = maker.ok(&["order", "resting"]);
	let mine = view["orders"].as_array().unwrap().iter().find(|o| o["rested_by"] == rested["order"]).unwrap().clone();
	assert_eq!(mine["state"], "published", "{}", view);
	mine["order"].as_str().unwrap().to_string()
}

/// Each coin of `w` and its state.
fn states(w: &Arca) -> Vec<(String, String)> {
	w.ok(&["coins"]).as_array().unwrap().iter()
		.map(|c| (c["leaf_id"].as_str().unwrap().to_string(), c["state"].as_str().unwrap().to_string())).collect()
}

/// A taker of this build whose coins of Y are all of format 2 fills an
/// older maker's resting order (`ARCA_CLI_OLDER`): refused before signing,
/// naming the older build. A taker with a coin of format 1 fills it without
/// the exit, and the older maker reads its credit.
#[tokio::test(flavor = "multi_thread")]
async fn a_taker_of_the_newer_format_and_an_older_resting_maker() {
	let Some(older) = std::env::var("ARCA_CLI_OLDER").ok() else {
		println!("CE10: no ARCA_CLI_OLDER: not run");
		return;
	};
	let older = std::path::PathBuf::from(older);
	let mut r = Running::start_with(|c, x, _| {
		c.assets[0] = server::server::AssetSection::new(x, 1_000);
	}).await;
	let (x, y) = (r.x, r.y);
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	let maker = holder(&mut r, Arca::built_from("CE10 old maker", &older), x, 1_500_000, 0).await;
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 3600));
	r.synced().await;
	let order = rest(&mut r, &maker, 1_000_000, 100_000).await;
	// T gets Y by a swap with the exit: its only coin of Y is of format 2.
	let sw = swap(&mut r, "CE10", Arca::new("CE10 T"), Arca::new("CE10 C"), true).await;
	let before = states(&sw.a);
	sw.a.refused(&["order", "fill-resting", &order, "--amount", "100000"], "the order's maker runs an older build");
	assert_eq!(before, states(&sw.a), "nothing of T's moved");
	let u = holder(&mut r, Arca::new("CE10 U"), y, 1_000_000, 0).await;
	let f = u.ok(&["order", "fill-resting", &order, "--amount", "100000"]);
	println!("CE10: U (format-1 Y) fills: {}", f);
	maker.ok(&["sync"]);
	let coins = maker.ok(&["coins"]);
	assert!(coins.as_array().unwrap().iter().any(|k| k["asset"] == y.to_string() && k["state"] == "live"),
		"the older maker holds a live credit of Y: {}", coins);
	for w in [&maker, &sw.a, &sw.c, &u] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
