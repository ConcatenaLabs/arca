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
//!   a library without the exit): the swap completes without it.
//!
//! The operator's watcher is off in every test that stages an attack, so
//! its answer does not race the test's.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::str::FromStr;

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

fn find_unspent(r: &Running, out: &elements::TxOut) -> OutPoint {
	let found = rpc(r, "scantxoutset", &[json!("start"), json!([format!("raw({})", hex(out.script_pubkey.as_bytes()))])]);
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
}

/// A boards X, C boards Y; A offers 300,000 of X for 400,000 of Y and C
/// takes it.
async fn swap(r: &mut Running, tag: &str, a: Arca, c: Arca, exit: bool) -> Swapped {
	let url = r.url();
	let (x, y) = (r.x, r.y);
	let a_board = boarded(r, &a, &url, x, 2_000_000).await;
	let c_board = boarded(r, &c, &url, y, 2_000_000).await;
	let bases = vec![board_tx(r, &a, &a_board), board_tx(r, &c, &c_board)];
	let offer = a.ok(&["swap", "offer", "--give-asset", &x.to_string(), "--give", "300000", "--want-asset", &y.to_string(), "--want", "400000"]);
	let offer_text = offer["offer"].as_str().unwrap().to_string();
	println!("{}: the offer asks for checkpoints with their owners' exit: {}", tag, text_json(&offer_text)["checkpoint_exit"]);
	let acc = c.ok(&["swap", "accept", &offer_text]);
	let acc_text = acc["accept"].as_str().unwrap().to_string();
	println!("{}: the acceptance signs so: {}", tag, text_json(&acc_text)["checkpoint_exit"]);
	a.ok(&["swap", "complete", &acc_text]);
	a.ok(&["sync"]);
	c.ok(&["sync"]);
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
	Swapped { a, c, a_board, c_board, a_gets, c_gets, bases }
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
	let ins = inputs(&a_gets);
	let ci = ins.iter().find(|i| i.coin.id.to_string() == sw.c_board).expect("C's board is an input").clone();
	assert!(ci.checkpoint.exit.is_some());
	// Everything first: any run of C's own wallet (each re-checks on start)
	// would answer C's checkpoint with the swap, as an honest wallet does.
	let ck = board_key(&sw.c, &sw.c_board);
	let (op, out, key) = fee_coin(r, &format!("{} attack fee", tag)).await;
	let back = vec![ExplicitOutput::new(ci.coin.asset, ci.checkpoint_value, Script::from(vec![0x51]))];
	let plan = TransferPlan { checkpoint_exit: true, inputs: vec![(ci.coin.clone(), ci.checkpoint_value)], outputs: back.clone() };
	let d = plan.reassignment_message(0).unwrap().digest;
	let sig = |k: &elements::secp256k1_zkp::Keypair| arca_covenant::sign::sign_digest(k, &d, &[0; 32]);
	let second = ValidInput { reassignment_pair: Pair { operator: sig(&keypair("operator")), owner: sig(&ck) }, ..ci.clone() };
	let cp = publish_board_checkpoint(r, &ci, &format!("{}: C's checkpoint from its board", tag), true).await;
	let mut tx = reassignment_tx(&[second], &back, &[cp], &FeeSource::Coin { outpoint: op, coin: out.clone(), fee: 3_000,
		change: bark::arca::keys::p2wpkh(&key) }).unwrap().tx;
	let k = tx.input.iter().position(|x| x.previous_output == op).unwrap();
	sign_p2wpkh(&mut tx, k, &out, &key);
	let id = r.rt.client().send_raw_transaction(&tx).expect("the second reassignment relays");
	r.produce().await;
	println!("{}: ATTACK C + operator: a second reassignment of C's checkpoint {} ({} vB)", tag, id, tx.vsize());
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
	let done = finish_return(&r, &sw.a, &sw.a_board, "CE1").await;
	assert_eq!(done["state"], "exited", "{}", done);
	let given = coin_of(&sw.a, &sw.a_board);
	println!("CE1: A's board at the end: {}", given);
	assert_eq!(given["state"], "exited");
	assert!(given["note"].as_str().unwrap_or("").contains("returned"), "{}", given);
	let y = coin_of(&sw.a, &sw.a_gets);
	println!("CE1: A's coin of Y at the end: {}", y);
	assert_ne!(y["state"], "live", "the coin the dead swap was to pay is not shown as held");
	assert!(y["note"].as_str().unwrap_or("").contains("was undone"), "{}", y);
	let swaps = tokio::task::block_in_place(|| {
		let mut w = bark::arca::Wallet::open(&sw.a.dir).expect("open the wallet");
		bark::arca::command::run(&mut w, "swaps", &json!({})).map(|v| v["result"].clone()).unwrap()
	});
	println!("CE1: A's swaps at the end: {}", swaps);
	assert!(swaps.as_array().unwrap().iter().any(|s| s["state"] == "returned"), "the swap is recorded as returned: {}", swaps);
	for w in [&sw.a, &sw.c] {
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
	let done = finish_return(&r, &a2, &sw.a_board, "CE2").await;
	assert_eq!(done["state"], "exited", "{}", done);
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
	for w in [&sw.a, &sw.c, &sw2.a, &sw2.c] {
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
