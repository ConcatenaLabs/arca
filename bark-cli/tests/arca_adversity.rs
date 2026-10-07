//! The wallet against an operator that lies in an answer, stalls or vanishes,
//! a sender that goes back on a payment, and a chain that rolls back: each
//! case ends with the wallet refusing before it signs anything, or taking
//! its coin on-chain and holding it there, with the reason shown.
//!
//! Each test runs the `arca` binary against a whole Arca server, its watcher
//! on, on an anchored proof-of-stake regtest chain, through a proxy that can
//! rewrite any answer of the server or hold a call unanswered; where the
//! operator or a sender acts on the chain, the test builds that transaction
//! itself.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::str::FromStr;
use std::sync::Arc;

use elements::secp256k1_zkp::schnorr::Signature;
use elements::{AssetId, Script, Transaction};
use serde_json::{json, Value};

use arca_covenant::sign::verify_digest;
use arca_covenant::{connector_asset, CoinRecord, Forfeit, LeafId, RelativeTime};
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
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

fn coin_of(w: &Arca, leaf: &str) -> Value {
	w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).cloned().unwrap_or(Value::Null)
}

fn record_of(w: &Arca, leaf: &str) -> CoinRecord {
	CoinRecord::from_bytes(&unhex(w.ok(&["record", leaf])["record"].as_str().unwrap())).unwrap()
}

/// Creates `w` on `server` and boards `amount` of each asset of `assets`, the
/// fee in the asset boarded; waits until every board is final and credited.
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
	for b in &boards {
		assert_eq!(coin_of(w, b)["state"], "live");
	}
	boards
}

/// Runs a round, mines it and waits until the server finds it final.
async fn final_round(r: &Running) -> Transaction {
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	built.tx
}

// ---------------------------------------------------------------------------
// The refresh: the status's leaves
// ---------------------------------------------------------------------------

/// A refresh of coins in two assets. The operator's status names one new
/// leaf of the two asked for, and then another unlock hash than the leaves
/// carry: the wallet signs no forfeit for either, and both coins stay its
/// own. With the honest status each coin's forfeit is built against the new
/// leaf of its own asset, under the participation's one unlock hash.
#[tokio::test(flavor = "multi_thread")]
async fn a_status_that_hides_a_new_leaf_is_refused_before_any_forfeit() {
	let mut r = Running::start().await;
	common::node::list_fee_asset(&r.rt, r.y, 100_000_000);
	let proxy = Proxy::start(&r.url());
	let c = Arca::new("F1");
	let (x, y) = (r.x, r.y);
	let boards = boarded(&mut r, &c, &proxy.url.clone(), &[(x, 2_000_000), (y, 2_000_000)]).await;
	let p = c.ok(&["participate"]);
	assert_eq!(p["wants"].as_array().unwrap().len(), 2, "one new leaf per asset: {}", p);
	let round = final_round(&r).await;

	// The status names only the first new leaf.
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/participation_status" && status == 200 {
			let first = v["outputs"].as_array().unwrap()[..1].to_vec();
			v["outputs"] = Value::Array(first);
		}
		None
	})));
	let s = c.ok(&["sync"]);
	let why = s["participations"][0]["refused"].as_str().unwrap_or_else(|| panic!("not refused: {}", s)).to_string();
	println!("F1 a status naming 1 of 2 new leaves: REFUSED: {}", why);
	assert!(why.contains("asked for 2"), "{}", why);
	// Another unlock hash than the leaves carry.
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/participation_status" && status == 200 {
			v["unlock_hash"] = json!("11".repeat(32));
		}
		None
	})));
	let s = c.ok(&["sync"]);
	let why = s["participations"][0]["refused"].as_str().unwrap_or_else(|| panic!("not refused: {}", s)).to_string();
	println!("F1 a status naming another unlock hash: REFUSED: {}", why);
	assert!(why.contains("unlock hash"), "{}", why);
	assert_eq!(proxy.count("/v1/forfeit_leaves"), 0, "no forfeit was signed");
	for b in &boards {
		assert_eq!(coin_of(&c, b)["state"], "given", "the coin is still the wallet's");
	}

	// The honest status: the refresh completes, each forfeit against its own
	// asset's leaf under the participation's unlock hash.
	proxy.rewrite(None);
	let s = c.ok(&["sync"]);
	let done = &s["participations"][0];
	assert_eq!(done["state"], "released", "{}", s);
	assert_eq!(done["new_leaves"].as_array().unwrap().len(), 2, "{}", s);
	let (req, _, _) = proxy.last("/v1/forfeit_leaves").unwrap();
	let (_, _, st) = proxy.last("/v1/participation_status").unwrap();
	let h: [u8; 32] = unhex(st["unlock_hash"].as_str().unwrap()).try_into().unwrap();
	let cvout = st["round"]["connector_vout"].as_u64().unwrap() as u32;
	let refund = RelativeTime::from_units(st["refund_delay_units"].as_u64().unwrap() as u16).unwrap();
	for b in &boards {
		let CoinRecord::Board(rec) = record_of(&c, b) else { panic!("a board") };
		let k = st["inputs"].as_array().unwrap().iter().position(|i| i["leaf_id"] == b.as_str()).unwrap();
		let margin: u64 = st["inputs"][k]["margin"].as_str().unwrap().parse().unwrap();
		let f = Forfeit::new(rec.leaf(), (rec.asset, rec.value), LeafId::from_str(b).unwrap(), h, connector_asset(round.txid(), cvout),
			refund, margin).unwrap();
		let sig = req["forfeits"].as_array().unwrap().iter().find(|f| f["leaf_id"] == b.as_str()).unwrap()["signature"].as_str().unwrap();
		assert!(verify_digest(&Signature::from_slice(&unhex(sig)).unwrap(), &f.message().digest, &rec.owner),
			"the forfeit of {} is under the participation's unlock hash and round", b);
		assert_eq!(coin_of(&c, b)["state"], "spent");
	}
	let bal = c.ok(&["balance"]);
	for a in [x, y] {
		assert!(bal["arca"][a.to_string()]["live"].is_string(), "a new leaf in each asset: {}", bal);
	}
	let _ = std::fs::remove_dir_all(&c.dir);
}

// ---------------------------------------------------------------------------
// After a rollback: the round the chain holds
// ---------------------------------------------------------------------------

fn rpc(r: &Running, method: &str, params: &[Value]) -> Value {
	r.rt.client().call(method, params).unwrap_or_else(|e| panic!("{} {:?}: {}", method, params, e))
}

fn block_of(r: &Running, txid: &str) -> String {
	rpc(r, "getrawtransaction", &[json!(txid), json!(true)])["blockhash"].as_str().unwrap().to_string()
}

fn confirmations(r: &Running, txid: &elements::Txid) -> i64 {
	rpc(r, "getrawtransaction", &[json!(txid.to_string()), json!(true)])["confirmations"].as_i64().unwrap_or(0)
}

/// Signs every input of `tx` the operator's on-chain wallet owns.
fn operator_signs(r: &Running, tx: &mut Transaction) {
	for i in 0..tx.input.len() {
		operator_signs_input(r, tx, i);
	}
}

/// Signs input `i` of `tx`, a coin of the operator's on-chain wallet.
fn operator_signs_input(r: &Running, tx: &mut Transaction, i: usize) {
	use elements::hashes::Hash;
	{
		let op = tx.input[i].previous_output;
		let prev = r.rt.client().raw_transaction(&op.txid).unwrap().output[op.vout as usize].clone();
		let signed = (0..2u8).flat_map(|chain| (0..64u32).map(move |index| (chain, index))).any(|(chain, index)| {
			let coin = server::store::WalletCoin {
				txid: op.txid.to_byte_array(), vout: op.vout, asset: prev.asset.explicit().unwrap().into_inner().to_byte_array(),
				value: prev.value.explicit().unwrap(), script_pubkey: prev.script_pubkey.to_bytes(), chain, index,
				in_chain: true, spent_by: None,
			};
			r.server.wallet.sign_input(tx, i, &coin).is_ok()
		});
		assert!(signed, "input {} of the operator's transaction is the operator's", i);
	}
}

/// A transaction of the operator's that takes the first input of `round`
/// and pays it back to the operator's `back`, less a fee: the round's
/// participations run again in a round that spends this output, which keeps
/// the two apart. Not signed.
fn taking(r: &Running, round: &Transaction, back: Script) -> Transaction {
	let op = round.input[0].previous_output;
	let prev = r.rt.client().raw_transaction(&op.txid).unwrap().output[op.vout as usize].clone();
	let (a, v) = (prev.asset.explicit().unwrap(), prev.value.explicit().unwrap());
	Transaction { version: 2, lock_time: elements::LockTime::ZERO,
		input: vec![elements::TxIn { previous_output: op, ..Default::default() }],
		output: vec![sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(a, v - 5_000), back),
			sequentia_ext::fee_txout(sequentia_ext::AssetAmount::new(a, 5_000))] }
}

/// The operator rolls back a final round and confirms in its place a
/// transaction that pays the same batch output and issues the sweep token
/// twice, one atom at `R` (what check 1 answers). The wallet's re-check
/// reads the batch output's payer from the chain, finds that it fails check 1
/// and takes the coin on-chain at once, from the replacement; it claims the
/// leaf after its exit delay, and the operator's sweep of the batch output
/// finds nothing to take.
#[tokio::test(flavor = "multi_thread")]
async fn a_replacement_round_that_fails_a_check_puts_the_coin_into_exit_at_once() {
	use arca_covenant::{ExplicitOutput, FeeSource, Sweepable};
	use elements::{OutPoint, TxOut};
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let c = Arca::new("F2");
	boarded(&mut r, &c, &url, &[(x, 2_000_000)]).await;
	c.ok(&["participate"]);
	let r1 = final_round(&r).await;
	let s = c.ok(&["sync"]);
	let leaf = s["participations"][0]["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	assert_eq!(coin_of(&c, &leaf)["state"], "live");
	let CoinRecord::Leaf { record, .. } = record_of(&c, &leaf) else { panic!("a batch leaf") };
	let token = record.schedule.token;
	let r_script = record.schedule.r().script_pubkey();

	// The operator: the round's block rolled back, the mempool emptied, and
	// R1 re-signed with the token issued as two atoms, one paid to R.
	r.server.stop();
	let block = block_of(&r, &r1.txid().to_string());
	rpc(&r, "invalidateblock", &[json!(block)]);
	r.rt.node.restart(&["-persistmempool=0"]).unwrap();
	let mut r2 = r1.clone();
	let k = r2.input.iter().position(|i| i.has_issuance() && i.issuance_ids().0 == token).unwrap();
	r2.input[k].asset_issuance.amount = elements::confidential::Value::Explicit(2);
	let fee_at = r2.output.iter().position(|o| o.is_fee()).unwrap();
	r2.output.insert(fee_at, TxOut {
		asset: elements::confidential::Asset::Explicit(token), value: elements::confidential::Value::Explicit(1),
		nonce: elements::confidential::Nonce::Null, script_pubkey: r_script.clone(), witness: Default::default(),
	});
	operator_signs(&r, &mut r2);
	let r2id = r.rt.client().send_raw_transaction(&r2).expect("the replacement relays");
	r.produce().await;
	r.bury().await;
	println!("F2 replacement {} issues 2 atoms of the token, one at R; confirmations {}", r2id, confirmations(&r, &r2id));

	// The wallet's re-check: the coin goes into its exit at once, from R2.
	let rc = c.ok(&["recheck"]);
	let ch = rc["changes"].as_array().unwrap().iter().find(|ch| ch["leaf_id"] == leaf.as_str())
		.unwrap_or_else(|| panic!("the re-check changes the coin: {}", rc)).clone();
	println!("F2 the wallet's re-check: {}", ch);
	assert_eq!(ch["to"], "exiting", "{}", ch);
	let why = ch["why"].as_str().unwrap();
	assert!(why.contains(&r2id.to_string()) && why.contains("check 1"), "the reason names the replacement and the check: {}", why);
	let steps = ch["exit"]["broadcast"].as_array().unwrap_or_else(|| panic!("the exit ran: {}", ch)).clone();
	assert!(!steps.is_empty(), "{}", ch);
	let first = elements::Txid::from_str(steps[0]["txid"].as_str().unwrap()).unwrap();
	let first = r.rt.client().raw_transaction(&first).unwrap();
	assert_eq!(first.input[0].previous_output.txid, r2id, "the unroll starts from the round the chain holds");
	r.produce().await;
	let e = c.ok(&["exit", &leaf]);
	assert_eq!(e["state"], "waiting", "the claim waits out the exit delay: {}", e);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 512));
	let e = c.ok(&["exit", &leaf]);
	assert_eq!(e["state"], "claimed", "{}", e);
	r.produce().await;
	let claim = elements::Txid::from_str(e["claim"]["txid"].as_str().unwrap()).unwrap();
	let ctx = r.rt.client().raw_transaction(&claim).unwrap();
	assert!(confirmations(&r, &claim) >= 1);
	assert_eq!(ctx.output[0].asset.explicit(), Some(x));
	println!("F2 the wallet's claim {} pays {} of X to its own address, confirmed", claim, ctx.output[0].value.explicit().unwrap());
	r.bury().await;
	c.ok(&["sync"]);
	assert_eq!(coin_of(&c, &leaf)["state"], "exited", "once its claim is final");

	// The operator's sweep of the batch output, once the notice has run.
	let branch = record.branch().unwrap();
	let batch = branch.batch_output();
	let bvout = r2.output.iter().position(|o| ExplicitOutput::from_txout(o).as_ref() == Some(&batch)).unwrap() as u32;
	let tvout = r2.output.iter().position(|o| o.asset.explicit() == Some(token) && o.script_pubkey == r_script).unwrap() as u32;
	let node0 = &branch.nodes[0];
	let swept = Sweepable::new(OutPoint::new(r2id, bvout), (batch.asset, batch.value), node0.taproot().clone(), node0.sweep);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, record.schedule.notice.seconds() as u32));
	let st = arca_covenant::sweep_tx(&record.schedule, OutPoint::new(r2id, tvout), &[swept],
		&[ExplicitOutput::new(batch.asset, batch.value - 3_000, Script::from(vec![0x54]))], &FeeSource::Reserve).unwrap();
	let genesis = r.rt.client().genesis_hash().unwrap();
	let s_key = common::running::keypair("operator");
	let sigs: Vec<_> = (0..st.leaves.len()).map(|i| arca_covenant::sign::sign_digest(&s_key, &st.sighash(i, genesis).unwrap(), &[0; 32])).collect();
	let sweep = st.finish(&sigs).unwrap().tx;
	let refused = r.rt.client().send_raw_transaction(&sweep).expect_err("the batch output is the wallet's unroll's");
	println!("F2 the operator's sweep of the batch output: REFUSED: {}", refused);
	assert!(refused.to_string().contains("missingorspent"), "{}", refused);
	let _ = std::fs::remove_dir_all(&c.dir);
}

// ---------------------------------------------------------------------------
// A coin handed over stays the wallet's until the chain says otherwise
// ---------------------------------------------------------------------------

/// The unspent outpoint paying exactly `out`, found by its script.
fn find_unspent(r: &Running, out: &elements::TxOut) -> elements::OutPoint {
	let found = rpc(r, "scantxoutset", &[json!("start"), json!([format!("raw({})", hex(out.script_pubkey.as_bytes()))])]);
	let u = found["unspents"].as_array().unwrap().first().unwrap_or_else(|| panic!("nothing pays {}", hex(out.script_pubkey.as_bytes())));
	elements::OutPoint::new(elements::Txid::from_str(u["txid"].as_str().unwrap()).unwrap(), u["vout"].as_u64().unwrap() as u32)
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// The transaction spending `op` in the last 200 blocks or the mempool.
fn spender_of(r: &Running, op: &elements::OutPoint) -> Option<Transaction> {
	let spends = |t: &Transaction| t.input.iter().any(|i| i.previous_output == *op);
	let mempool: Vec<String> = serde_json::from_value(rpc(r, "getrawmempool", &[])).unwrap();
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

/// Runs `exit` on `leaf` until it is claimed: once to bring the coin
/// on-chain, again after a block (waiting out the delay), and again once
/// the exit delay has run. Returns the confirmed claim.
async fn exit_and_claim(r: &Running, w: &Arca, leaf: &str, fee_asset: Option<&str>) -> Transaction {
	let mut args = vec!["exit", leaf];
	if let Some(a) = fee_asset {
		args.extend(["--fee-asset", a]);
	}
	let e = w.ok(&args);
	assert!(matches!(e["state"].as_str(), Some("unrolling" | "waiting")), "{}", e);
	r.produce().await;
	let e = w.ok(&args);
	assert_eq!(e["state"], "waiting", "the claim waits out the exit delay: {}", e);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 512));
	let e = w.ok(&args);
	assert_eq!(e["state"], "claimed", "{}", e);
	r.produce().await;
	let claim = elements::Txid::from_str(e["claim"]["txid"].as_str().unwrap()).unwrap();
	assert!(confirmations(r, &claim) >= 1, "the claim confirms");
	assert_eq!(coin_of(w, leaf)["state"], "exiting", "the claim is followed until it is final");
	r.bury().await;
	w.ok(&["sync"]);
	assert_eq!(coin_of(w, leaf)["state"], "exited", "the claim is final");
	r.rt.client().raw_transaction(&claim).unwrap()
}

/// A coin given to a participation is the wallet's while no forfeit of it is
/// signed: when the participation expires (its forfeit day passed while the
/// wallet was away) the coin is live again, and a coin given to a
/// participation the operator never runs can be exited.
#[tokio::test(flavor = "multi_thread")]
async fn a_given_coin_comes_back_when_its_participation_expires_and_can_be_exited() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let c = Arca::new("F3a");
	let boards = boarded(&mut r, &c, &url, &[(x, 2_000_000)]).await;
	let board = &boards[0];
	let p = c.ok(&["participate"]);
	let pid = p["participation"].as_str().unwrap().to_string();
	assert_eq!(coin_of(&c, board)["state"], "given");
	final_round(&r).await;
	// The wallet is away for the forfeit day: the participation expires.
	let expired = r.server.store.expire_participations(u32::MAX).await.unwrap();
	assert!(expired.iter().any(|e| hex(e) == pid), "the server expires the participation");
	let s = c.ok(&["sync"]);
	println!("F3a the wallet's sync after the expiry: {}", s["participations"]);
	assert_eq!(s["participations"][0]["state"], "expired", "{}", s);
	assert_eq!(coin_of(&c, board)["state"], "live", "an expired participation gives its coin back");
	// The wallet says the refresh expired, not that the operator refused it.
	let home = coin_of(&c, board)["home"].as_str().unwrap_or("").to_string();
	println!("F3a the coin's note: {}", home);
	assert!(home.contains("expired at the server") && !home.contains("refused"), "{}", home);

	// Given again, and the operator never runs a round: the wallet exits it.
	c.ok(&["participate"]);
	assert_eq!(coin_of(&c, board)["state"], "given");
	let claim = exit_and_claim(&r, &c, board, Some(&x.to_string())).await;
	println!("F3a the given coin exited: claim {} pays {} of X", claim.txid(), claim.output[0].value.explicit().unwrap());
	let paid = claim.output[0].value.explicit().unwrap();
	assert_eq!(claim.output[0].asset.explicit(), Some(x));
	assert!(paid > 1_999_900, "the board's value, less its claim's fee: {}", paid);
	assert_eq!(coin_of(&c, board)["state"], "exited");
	let _ = std::fs::remove_dir_all(&c.dir);
}

/// The operator vanishes while a payment is in flight: the transfer request
/// is never answered. The coin can be exited, and the request is not posted
/// again once it is.
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_in_flight_when_the_operator_vanishes_is_exited() {
	let mut r = Running::start().await;
	let proxy = Proxy::start(&r.url());
	let url = r.url();
	let x = r.x;
	let a = Arca::new("F3bA");
	let b = Arca::new("F3bB");
	let boards = boarded(&mut r, &a, &proxy.url.clone(), &[(x, 2_000_000)]).await;
	b.ok(&create_args(&url, &r.node_url()));
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	proxy.hold("/v1/cosign_transfer");
	let (ok, v) = a.run(&["send", &req, "--amount", "600000", "--asset", &x.to_string()]);
	println!("F3b send, the operator gone mid-call: ok={} {}", ok, v);
	assert!(!ok);
	r.server.stop();
	assert_eq!(coin_of(&a, &boards[0])["state"], "sending");
	let claim = exit_and_claim(&r, &a, &boards[0], Some(&x.to_string())).await;
	println!("F3b the coin in flight exited: claim {} pays {} of X", claim.txid(), claim.output[0].value.explicit().unwrap());
	let s = a.ok(&["sync"]);
	assert_eq!(s["transfers"], json!([]), "the abandoned request is not posted again: {}", s);
	assert_eq!(proxy.count("/v1/cosign_transfer"), 1);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// The server takes the forfeit and withholds the preimage, then calls the
/// participation void. A coin under a forfeit signed for a round in the
/// chain is not given back by a void: it is not spent again. The operator's
/// claim of the forfeit on the chain publishes the preimage, which the
/// wallet reads from the claim's witness: the new leaf is its own.
#[tokio::test(flavor = "multi_thread")]
async fn a_withheld_preimage_is_read_from_the_claim_and_void_frees_no_forfeited_coin() {
	let mut r = Running::start().await;
	let proxy = Proxy::start(&r.url());
	let c = Arca::new("F7");
	let d = Arca::new("F7D");
	let x = r.x;
	let boards = boarded(&mut r, &c, &proxy.url.clone(), &[(x, 2_000_000)]).await;
	d.ok(&create_args(&r.url(), &r.node_url()));
	c.ok(&["participate"]);
	final_round(&r).await;
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/forfeit_leaves" && status == 200 {
			v["preimage"] = Value::Null;
		}
		None
	})));
	let s = c.ok(&["sync"]);
	println!("F7 the forfeit handed over, the preimage withheld: {}", s["participations"][0]);
	assert_eq!(s["participations"][0]["state"], "forfeiting", "{}", s);
	assert_eq!(coin_of(&c, &boards[0])["state"], "forfeited");
	// The operator calls it void.
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/participation_status" && status == 200 {
			v["state"] = json!("void");
		}
		if path == "/v1/forfeit_leaves" && status == 200 {
			v["preimage"] = Value::Null;
		}
		None
	})));
	let s = c.ok(&["sync"]);
	println!("F13 the status says void after the forfeit: {}", s["participations"][0]);
	assert_eq!(coin_of(&c, &boards[0])["state"], "forfeited", "a void does not free a coin under a forfeit for a round in the chain");
	let req = d.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let why = c.refused(&["send", &req, "--amount", "500000", "--asset", &x.to_string()], "in live coins");
	println!("F13 a second spend of the forfeited coin: REFUSED: {}", why);
	assert_eq!(proxy.count("/v1/cosign_transfer"), 0, "nothing was signed for a second spend");

	// The operator claims the forfeit on the chain, which publishes the
	// preimage; the wallet reads it there.
	let mut done = Value::Null;
	for _ in 0..30 {
		r.produce().await;
		let s = c.ok(&["sync"]);
		if let Some(f) = s["forfeits"].as_array().and_then(|a| a.iter().find(|f| f["state"] == "claimed" || f["state"] == "claiming")) {
			done = f.clone();
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;
	}
	println!("F7 the wallet's watch of its forfeit: {}", done);
	assert!(done["state"] == "claimed" || done["state"] == "claiming", "the claim is read from the chain: {}", done);
	let leaf = done["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	// Followed until the claim is final: a block for it, its anchor buried,
	// as many times as that takes.
	let mut state = done["state"].clone();
	for _ in 0..10 {
		if state == "claimed" {
			break;
		}
		r.produce().await;
		r.bury().await;
		let s = c.ok(&["sync"]);
		if let Some(f) = s["forfeits"].as_array().unwrap().iter().find(|f| f["leaf_id"] == boards[0].as_str()) {
			state = f["state"].clone();
		}
	}
	assert_eq!(state, "claimed", "the claim is followed until final");
	assert_eq!(coin_of(&c, &leaf)["state"], "live", "the new leaf is the wallet's: {}", coin_of(&c, &leaf));
	assert_eq!(coin_of(&c, &boards[0])["state"], "spent");
	for w in [&c, &d] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A lost round, and the participations it ran (D50). The wallet refreshes
/// two boards and a leaf of an earlier round in round R; the operator's
/// watcher publishes both boards' forfeits for R, as it does for every board
/// given up in a final round. Then R is lost (one of its inputs is spent by
/// a transaction of the operator's, final, paying the operator back, and the
/// node forgets its mempool),
/// and one board's forfeit is sent again by someone who saw it. The new
/// leaves of R are lost, and the wallet follows each participation as the
/// operator runs it again: the leaf's re-run is taken in round Y, the wallet
/// hands over its forfeit for Y and takes its new leaf; each board's re-run
/// is never taken, which the wallet shows with the operator's reason and
/// does not wait on. The board whose forfeit for R is on the chain is
/// refunded once its delay has run; the other, whose forfeit is not on the
/// chain, is exited at once.
#[tokio::test(flavor = "multi_thread")]
async fn after_a_lost_round_the_wallet_follows_each_participation_run_again() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let c = Arca::new("D50c");
	let boards = boarded(&mut r, &c, &url, &[(x, 2_000_000), (x, 2_000_000), (x, 2_000_000)]).await;
	// A leaf of an earlier round, from the first board.
	c.ok(&["participate", "--leaf", &boards[0]]);
	final_round(&r).await;
	let s = c.ok(&["sync"]);
	let leaf = s["participations"][0]["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	assert_eq!(coin_of(&c, &leaf)["state"], "live");
	let outs: Vec<_> = boards[1..].iter().map(|b| {
		let CoinRecord::Board(rec) = record_of(&c, b) else { panic!("a board") };
		find_unspent(&r, &rec.output().txout())
	}).collect();
	// Round R: the two other boards and the leaf.
	let mut pids = vec![];
	for l in [&boards[1], &boards[2], &leaf] {
		pids.push(c.ok(&["participate", "--leaf", l])["participation"].as_str().unwrap().to_string());
	}
	let r1 = final_round(&r).await;
	let s = c.ok(&["sync"]);
	assert!(s["participations"].as_array().unwrap().iter().all(|p| p["state"] == "released"), "{}", s["participations"]);
	// The watcher publishes each board's forfeit for R.
	let mut forfeits = vec![None, None];
	for _ in 0..40 {
		for (k, op) in outs.iter().enumerate() {
			if forfeits[k].is_none() {
				forfeits[k] = spender_of(&r, op);
			}
		}
		if forfeits.iter().all(Option::is_some) {
			break;
		}
		r.produce().await;
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;
	}
	let first = forfeits[0].clone().expect("the watcher publishes the first board's forfeit");
	let second = forfeits[1].clone().expect("the watcher publishes the second board's forfeit");
	println!("D50c the operator's forfeits for R: {} and {}", first.txid(), second.txid());

	// R is lost: rolled back, the mempool emptied, one of its inputs spent
	// by another transaction, which pays the operator back, buried; someone
	// who saw the first board's forfeit sends it again.
	let back = r.server.wallet.receive_script().await.unwrap();
	r.server.stop();
	let block = block_of(&r, &r1.txid().to_string());
	rpc(&r, "invalidateblock", &[json!(block)]);
	r.rt.node.restart(&["-persistmempool=0"]).unwrap();
	let mut conflict = taking(&r, &r1, back);
	operator_signs(&r, &mut conflict);
	let cid = r.rt.client().send_raw_transaction(&conflict).expect("the conflict relays");
	let fid = r.rt.client().send_raw_transaction(&first).expect("the forfeit relays without its round");
	r.produce().await;
	r.bury().await;
	println!("D50c conflict {} confirmed: round {} is lost; the first board's forfeit {} confirmed", cid, r1.txid(), fid);
	r.restart_server().await;
	r.synced().await;
	r.round_state(&r1.txid(), RoundState::Lost).await;

	// The wallet follows: the leaf's run again is pending; each board's is
	// void, with the operator's reason.
	let s = c.ok(&["sync"]);
	println!("D50c the wallet's sync after R is lost: recheck {} participations {}", s["recheck"]["changes"], s["participations"]);
	let of = |s: &Value, pid: &str| s["participations"].as_array().unwrap().iter().find(|p| p["participation"] == pid).cloned()
		.unwrap_or(Value::Null);
	for (k, b) in boards[1..].iter().enumerate() {
		let p = of(&s, &pids[k]);
		println!("D50c board {}'s participation: {}", k + 1, p);
		assert!(p["void_reason"].as_str().is_some_and(|w| w.contains("operator's log")), "the operator's reason, shown: {}", p);
		assert_ne!(coin_of(&c, b)["state"], "live", "a board under a forfeit for R is not the wallet's off the chain");
	}
	assert_eq!(coin_of(&c, &boards[1])["state"], "forfeited", "its forfeit for R is on the chain: {}", coin_of(&c, &boards[1]));
	assert!(of(&s, &pids[0])["held"][0]["exit"].is_null(), "a coin whose forfeit is on the chain is refunded, not exited");
	// The second board's forfeit for R is not on the chain: the wallet takes
	// the board on the chain at once, its conversion's fee paid with a coin
	// of the wallet's it chooses (D57: the moved asset, X).
	let tried = &of(&s, &pids[1])["held"][0]["exit"];
	println!("D50c the second board's exit, at once: {}", tried);
	assert!(tried["error"].is_null() && tried["state"] == "unrolling", "{}", tried);
	assert!(tried["broadcast"][0]["fee"][0]["asset"] == x.to_string().as_str(), "{}", tried);
	assert_eq!(coin_of(&c, &boards[2])["state"], "exiting");
	assert_eq!(of(&s, &pids[2])["state"], "pending", "the leaf's run again waits for a round: {}", s["participations"]);
	let s = c.ok(&["sync"]);
	for pid in &pids[..2] {
		assert!(of(&s, pid).is_null(), "a void participation is not followed again: {}", s["participations"]);
	}

	// Round Y takes the leaf's: the wallet hands over its forfeit for Y and
	// takes its new leaf.
	final_round(&r).await;
	let s = c.ok(&["sync"]);
	let p = of(&s, &pids[2]);
	println!("D50c the leaf's participation in Y: {}", p);
	assert_eq!(p["state"], "released", "{}", s["participations"]);
	let new = p["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	assert_eq!(coin_of(&c, &new)["state"], "live");
	assert_eq!(coin_of(&c, &leaf)["state"], "spent");

	// The second board is exited and claimed.
	let claim = exit_and_claim(&r, &c, &boards[2], Some(&x.to_string())).await;
	println!("D50c the second board, exited: claim {} pays {} of X", claim.txid(), claim.output[0].value.explicit().unwrap());
	// The first board's forfeit for R is refunded once its delay has run.
	let refund_s = r.config.exit_delay_units.unwrap().1 as u32 * 512;
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, refund_s));
	let s = c.ok(&["sync"]);
	let f = s["forfeits"].as_array().unwrap().iter().find(|f| f["leaf_id"] == boards[1].as_str()).cloned()
		.unwrap_or_else(|| panic!("the forfeit is watched: {}", s));
	println!("D50c the wallet's refund of the first board's forfeit for R: {}", f);
	assert_eq!(f["state"], "refunding", "{}", f);
	r.produce().await;
	r.bury().await;
	let s = c.ok(&["sync"]);
	let f = s["forfeits"].as_array().unwrap().iter().find(|f| f["leaf_id"] == boards[1].as_str()).cloned()
		.unwrap_or_else(|| panic!("the forfeit is followed until its refund is final: {}", s));
	assert_eq!(f["state"], "refunded", "{}", f);
	assert_eq!(coin_of(&c, &boards[1])["state"], "exited");
	let _ = (second, std::fs::remove_dir_all(&c.dir));
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

/// A lost round that returns, with the wallet following. A leaf of the
/// wallet's is refreshed in round R, which goes out of the chain with its
/// parent block while another transaction X of the operator's takes R's
/// input (paying the operator back), buried. The operator runs the
/// participation again in Y, which spends X's output; the wallet takes Y's
/// leaf. Then the parent chain takes X out and R, sent by anyone who holds
/// it, confirms in its place: Y never can. The wallet follows R: its leaf of
/// R is live again and its leaf of Y lost, so it holds one leaf for the coin
/// it gave up, as it did at every step.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_round_that_returns_is_followed_by_the_wallet_in_place_of_its_rerun() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let c = Arca::new("D53w");
	let boards = boarded(&mut r, &c, &url, &[(x, 2_000_000)]).await;
	c.ok(&["participate", "--leaf", &boards[0]]);
	final_round(&r).await;
	let s = c.ok(&["sync"]);
	let leaf0 = s["participations"][0]["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	let held = |c: &Arca| -> Vec<(String, String, String)> {
		c.ok(&["coins"]).as_array().unwrap().iter().filter(|k| matches!(k["state"].as_str(), Some("live" | "pending")))
			.map(|k| (k["leaf_id"].as_str().unwrap().to_string(), k["state"].as_str().unwrap().to_string(), k["value"].as_str().unwrap().to_string()))
			.collect()
	};

	// Round R, alone in a parent block of its own; the wallet takes its leaf.
	let pid = c.ok(&["participate", "--leaf", &leaf0])["participation"].as_str().unwrap().to_string();
	let p_r = own_anchor(&r).await;
	let rtx = final_round(&r).await;
	let s = c.ok(&["sync"]);
	let of = |s: &Value| s["participations"].as_array().unwrap().iter().find(|p| p["participation"] == pid.as_str()).cloned()
		.unwrap_or(Value::Null);
	let leaf_r = of(&s)["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	println!("D53w R = {}; the wallet holds {:?}", rtx.txid(), held(&c));
	assert_eq!(held(&c).len(), 1);

	// R goes out with its parent block; X takes its input, paying the
	// operator back; buried.
	let back = r.server.wallet.receive_script().await.unwrap();
	r.server.stop();
	tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_r)).unwrap();
	assert!(confirmations(&r, &rtx.txid()) < 1);
	r.rt.node.restart(&["-persistmempool=0"]).unwrap();
	let p_x = own_anchor(&r).await;
	let mut xtx = taking(&r, &rtx, back);
	operator_signs(&r, &mut xtx);
	r.rt.client().send_raw_transaction(&xtx).unwrap();
	r.produce().await;
	r.bury().await;
	r.restart_server().await;
	r.synced().await;
	r.round_state(&rtx.txid(), RoundState::Lost).await;
	let s = c.ok(&["sync"]);
	println!("D53w after R is lost: the participation {}; the wallet holds {:?}", of(&s), held(&c));
	assert_eq!(coin_of(&c, &leaf_r)["state"], "lost");
	assert_eq!(of(&s)["state"], "pending", "{}", s["participations"]);

	// Y runs it again, spending X's output; the wallet takes Y's leaf.
	let ytx = final_round(&r).await;
	assert!(ytx.input.iter().any(|i| i.previous_output == elements::OutPoint::new(xtx.txid(), 0)), "Y spends X's output");
	let s = c.ok(&["sync"]);
	let leaf_y = of(&s)["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	println!("D53w Y = {}; the wallet holds {:?}", ytx.txid(), held(&c));
	assert_eq!(held(&c), vec![(leaf_y.clone(), "live".to_string(), coin_of(&c, &leaf_y)["value"].as_str().unwrap().to_string())]);

	// The parent chain takes X out; R confirms in its place.
	r.server.stop();
	tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_x)).unwrap();
	assert!(confirmations(&r, &xtx.txid()) < 1 && confirmations(&r, &ytx.txid()) < 1);
	r.rt.node.restart(&["-persistmempool=0"]).unwrap();
	r.rt.client().send_raw_transaction(&rtx).unwrap();
	r.produce().await;
	r.bury().await;
	r.restart_server().await;
	r.synced().await;
	r.round_state(&rtx.txid(), RoundState::Final).await;
	let y_verdict = r.rt.client().test_mempool_accept(&[&ytx]).unwrap().remove(0);
	println!("D53w R back in the chain; the node's verdict on Y: {:?}", y_verdict.reject_reason);
	assert!(!y_verdict.allowed);

	// The wallet follows R: one leaf for the coin it gave up.
	let s = c.ok(&["sync"]);
	println!("D53w the wallet's sync: recheck {}", s["recheck"]["changes"]);
	println!("D53w the wallet holds {:?}", held(&c));
	assert_eq!(coin_of(&c, &leaf_r)["state"], "live", "{}", coin_of(&c, &leaf_r));
	assert_eq!(coin_of(&c, &leaf_y)["state"], "lost", "{}", coin_of(&c, &leaf_y));
	assert_eq!(held(&c).len(), 1);
	let bal = c.ok(&["balance"]);
	println!("D53w balance {}", bal);
	assert_eq!(bal["arca"][x.to_string()]["live"], coin_of(&c, &leaf_r)["value"]);
	assert!(bal["arca"][x.to_string()].get("pending").is_none());
	let _ = std::fs::remove_dir_all(&c.dir);
}

/// A coin paid out of a lost round's leaf (review R7e, F3's B and M). B
/// refreshes a leaf of an earlier round in round R and pays its new leaf on
/// to M out of round. R goes out of the chain with its parent block while a
/// transaction of the operator's takes R's input (paying the operator back),
/// buried: M's coin rests on R. The server holds M's coin lost, and B's
/// re-run void, saying its leaf of R was paid on; M's wallet shows the coin
/// lost, resting on a round out of the chain, not live. Then the parent
/// chain takes that transaction out and R returns: M's coin is live again,
/// at the server and in M's wallet, and B's participation is back in R.
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_paid_out_of_a_lost_rounds_leaf_is_as_final_as_that_round() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let (b, m) = (Arca::new("PB"), Arca::new("PM"));
	let boards = boarded(&mut r, &b, &url, &[(x, 2_000_000)]).await;
	b.ok(&["participate", "--leaf", &boards[0]]);
	final_round(&r).await;
	let s = b.ok(&["sync"]);
	let leaf0 = s["participations"][0]["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	let pid = b.ok(&["participate", "--leaf", &leaf0])["participation"].as_str().unwrap().to_string();
	let p_r = own_anchor(&r).await;
	let rtx = final_round(&r).await;
	b.ok(&["sync"]);
	// B pays M out of its leaf of R.
	m.ok(&create_args(&url, &r.node_url()));
	let req = m.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let sent = b.ok(&["send", &req, "--amount", "1500000", "--asset", &x.to_string()]);
	println!("PB pays M 1500000 out of its leaf of R: {}", sent["inputs"]);
	let got = m.ok(&["mailbox"])["accepted"][0]["leaf_id"].as_str().unwrap().to_string();
	assert_eq!(coin_of(&m, &got)["state"], "live");
	let got_id: [u8; 32] = unhex(&got).try_into().unwrap();
	let server_state = |r: &Running| tokio::runtime::Handle::current().block_on(r.server.store.leaf(&got_id)).unwrap().unwrap().state;

	// R goes out of the chain; X takes its input, paying the operator back.
	let back = r.server.wallet.receive_script().await.unwrap();
	r.server.stop();
	tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_r)).unwrap();
	r.rt.node.restart(&["-persistmempool=0"]).unwrap();
	let p_x = own_anchor(&r).await;
	let mut xtx = taking(&r, &rtx, back);
	operator_signs(&r, &mut xtx);
	r.rt.client().send_raw_transaction(&xtx).unwrap();
	r.produce().await;
	r.bury().await;
	r.restart_server().await;
	r.synced().await;
	r.round_state(&rtx.txid(), RoundState::Lost).await;
	let pid32: [u8; 32] = unhex(&pid).try_into().unwrap();
	r.wait("B's re-run looked at", || tokio::runtime::Handle::current().block_on(r.server.store.participation(&pid32)).unwrap().unwrap()
		.state == server::store::ParticipationState::Void).await;
	let p = r.server.store.participation(&pid32).await.unwrap().unwrap();
	let lost_at_server = tokio::task::block_in_place(|| server_state(&r));
	println!("PB R lost: M's coin at the server {:?}; B's re-run {:?}: {}", lost_at_server, p.state, p.void_reason.clone().unwrap_or_default());
	assert_eq!(lost_at_server, server::store::LeafState::Lost);
	let why = p.void_reason.unwrap();
	assert!(why.contains("paid on out of round") && why.contains(&rtx.txid().to_string()), "{}", why);
	m.ok(&["sync"]);
	let mc = coin_of(&m, &got);
	println!("PM M's coin while R is out: {} ({})", mc["state"], mc["note"]);
	assert_eq!(mc["state"], "lost");
	assert!(mc["note"].as_str().unwrap().contains("out of the chain") && mc["note"].as_str().unwrap().contains(&rtx.txid().to_string()));
	assert!(m.ok(&["balance"])["arca"].as_object().is_none_or(|a| a.is_empty()), "nothing of it counted");

	// The parent chain takes X out; R confirms in its place.
	r.server.stop();
	tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_x)).unwrap();
	r.rt.node.restart(&["-persistmempool=0"]).unwrap();
	r.rt.client().send_raw_transaction(&rtx).unwrap();
	r.produce().await;
	r.bury().await;
	r.restart_server().await;
	r.synced().await;
	r.round_state(&rtx.txid(), RoundState::Final).await;
	let p = r.server.store.participation(&pid32).await.unwrap().unwrap();
	let back_at_server = tokio::task::block_in_place(|| server_state(&r));
	println!("PB R back: M's coin at the server {:?}; B's participation {:?} attempt {}", back_at_server, p.state, p.attempt);
	assert_eq!(back_at_server, server::store::LeafState::Live);
	assert_eq!((p.state, p.attempt), (server::store::ParticipationState::Released, 0));
	let s = m.ok(&["sync"]);
	println!("PM M's sync with R back: {}", s["recheck"]["changes"]);
	assert_eq!(coin_of(&m, &got)["state"], "live", "{}", coin_of(&m, &got));
	assert_eq!(m.ok(&["balance"])["arca"][x.to_string()]["operator-confirmed"], "1500000");
	let _ = (std::fs::remove_dir_all(&b.dir), std::fs::remove_dir_all(&m.dir));
}

// ---------------------------------------------------------------------------
// The fee a refresh pays
// ---------------------------------------------------------------------------

/// The operator publishes a refresh fee of half of every coin: the wallet
/// refuses it before it signs or submits anything, says what it would cost,
/// and pays it only when the user raises the bound for that one command,
/// printing the fee first. A coin in its free window pays nothing, whatever
/// window the operator publishes.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_fee_above_the_bound_is_refused_before_anything_is_signed() {
	let mut r = Running::start().await;
	let proxy = Proxy::start(&r.url());
	let c = Arca::new("F4");
	let x = r.x;
	let boards = boarded(&mut r, &c, &proxy.url.clone(), &[(x, 2_000_000), (x, 2_000_000)]).await;
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/info" && status == 200 {
			v["fees"]["refresh_ppm"] = json!(500_000);
		}
		None
	})));
	let why = c.refused(&["participate", "--leaf", &boards[0]], "--max-fee-ppm");
	println!("F4 a refresh fee of 500000 ppm published: REFUSED: {}", why);
	assert!(why.contains("1000000") && why.contains("500000 ppm") && why.contains("10000 ppm"), "{}", why);
	assert_eq!(proxy.count("/v1/submit_participation"), 0, "nothing was signed or submitted");
	assert_eq!(coin_of(&c, &boards[0])["state"], "live");
	// Raised for one command: printed before anything is signed, then paid.
	let (ok, p, err) = c.run_full(&["participate", "--leaf", &boards[0], "--max-fee-ppm", "500000"]);
	println!("F4 with the bound raised: stderr {:?}; {}", err.trim(), p);
	assert!(ok, "{}", p);
	assert!(err.contains(&format!("refresh fee for coin {}: 1000000 of asset {}", boards[0], x)), "the fee is printed: {}", err);
	assert_eq!(p["fees"][0]["amount"], "1000000");
	assert_eq!(p["wants"][0]["value"], "1000000");
	proxy.rewrite(None);

	// A batch leaf in its free window: the operator publishes a fee and no
	// free window; the wallet pays nothing there.
	c.ok(&["participate", "--leaf", &boards[1]]);
	final_round(&r).await;
	let s = c.ok(&["sync"]);
	let leaf = s["participations"].as_array().unwrap().iter().find_map(|p| p["new_leaves"][0]["leaf_id"].as_str())
		.unwrap_or_else(|| panic!("the refresh completes: {}", s)).to_string();
	let CoinRecord::Leaf { record, .. } = record_of(&c, &leaf) else { panic!("a batch leaf") };
	let e0 = record.schedule.expiries()[0].to_consensus_u32();
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, e0 - now - 4 * 86_400 - 43_200));
	r.bury().await;
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/info" && status == 200 {
			v["fees"]["refresh_ppm"] = json!(5_000);
			v["fees"]["free_window_seconds"] = json!(0);
		}
		None
	})));
	// Four and a half days before its expiry, in its free window: `sync` asks
	// for its refresh by itself, and refuses the fee before anything is
	// signed; the leaf stays live.
	let submitted = proxy.count("/v1/submit_participation");
	let s = c.ok(&["sync"]);
	let asked = s["refresh"].as_array().unwrap().iter().find(|x| x["leaf_id"] == leaf.as_str()).cloned()
		.unwrap_or_else(|| panic!("sync asks for the refresh: {}", s));
	println!("F4 sync's own refresh, a fee published in the free window: {}", asked["error"]);
	assert!(asked["error"].as_str().unwrap_or("").contains("free window"), "{}", asked);
	assert_eq!(proxy.count("/v1/submit_participation"), submitted, "nothing was submitted");
	assert_eq!(coin_of(&c, &leaf)["state"], "live", "in its free window the leaf is still live");
	let why = c.refused(&["participate", "--leaf", &leaf], "free window");
	println!("F4 a fee inside the free window: REFUSED: {}", why);
	assert_eq!(proxy.count("/v1/submit_participation"), submitted, "nothing was submitted");
	proxy.rewrite(None);
	let p = c.ok(&["participate", "--leaf", &leaf]);
	assert_eq!(p["fees"], json!([]), "the honest schedule asks nothing in the free window: {}", p);
	let _ = std::fs::remove_dir_all(&c.dir);
}

// ---------------------------------------------------------------------------
// A sender going back on a payment
// ---------------------------------------------------------------------------

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

/// The sender of a payment converts, with its own key, the board it paid
/// from: a stale exit. The receiver's re-check sees the board spent and the
/// converted leaf on the chain, and answers at once with what it holds:
/// the checkpoint from the converted leaf, then the reassignment; it claims
/// its leaf after its exit delay, and the sender's claim of the converted
/// leaf finds it spent.
#[tokio::test(flavor = "multi_thread")]
async fn a_receiver_answers_a_stale_board_conversion_at_once() {
	use arca_covenant::{ExplicitOutput, FeeSource};
	use elements::OutPoint;
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let a = Arca::new("F5A");
	let b = Arca::new("F5B");
	let boards = boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	b.ok(&create_args(&url, &r.node_url()));
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req, "--amount", "600000", "--asset", &x.to_string()]);
	let got = b.ok(&["mailbox"]);
	let coin = got["accepted"][0]["leaf_id"].as_str().unwrap().to_string();
	assert_eq!(coin_of(&b, &coin)["state"], "live");

	// The sender converts its board with its own key, a fee coin of its own.
	let CoinRecord::Board(rec) = record_of(&a, &boards[0]) else { panic!("a board") };
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap();
	let keys = bark::arca::keys::Keys::new(mnemonic.trim(), 0, 1).unwrap();
	let leaf_key = keys.leaf(&rec.owner_nonce).unwrap();
	let board_at = find_unspent(&r, &rec.output().txout());
	let fee_key = common::running::keypair("sender fee coin");
	let fee_script = bark::arca::keys::p2wpkh(&fee_key);
	let paid = r.pay_to(fee_script.clone(), x, 100_000);
	r.produce().await;
	let j = paid.output.iter().position(|o| o.script_pubkey == fee_script).unwrap();
	let fee_coin = (OutPoint::new(paid.txid(), j as u32), paid.output[j].clone());
	let genesis = r.rt.client().genesis_hash().unwrap();
	let ks = rec.policy().conversion(board_at, &FeeSource::Coin { outpoint: fee_coin.0, coin: fee_coin.1.clone(), fee: 2_000,
		change: fee_script.clone() }).unwrap();
	let sig = arca_covenant::sign::sign_digest(&leaf_key, &ks.sighash(genesis).unwrap(), &[0; 32]);
	let mut conv = ks.finish(vec![sig.as_ref().to_vec()]).tx;
	let fi = conv.input.iter().position(|i| i.previous_output == fee_coin.0).unwrap();
	sign_p2wpkh(&mut conv, fi, &fee_coin.1, &fee_key);
	// The operator is gone: the receiver answers on its own, from what it
	// holds, and the test does not race the operator's watcher, which
	// answers the same stale exit when it runs.
	r.server.stop();
	let conv_id = r.rt.client().send_raw_transaction(&conv).expect("the conversion relays");
	r.produce().await;
	println!("F5 the sender's conversion {} ({} vB), confirmations {}", conv_id, conv.vsize(), confirmations(&r, &conv_id));

	// The receiver's re-check answers at once.
	let rc = b.ok(&["recheck"]);
	let ch = rc["changes"].as_array().unwrap().iter().find(|c| c["leaf_id"] == coin.as_str()).cloned()
		.unwrap_or_else(|| panic!("the re-check acts on the coin: {}", rc));
	println!("F5 the receiver's re-check: {}", ch);
	assert_eq!(ch["to"], "exiting", "{}", ch);
	assert!(ch["why"].as_str().unwrap().contains("spent"), "{}", ch);
	// The answer, the receiver's own: the checkpoint from the converted
	// leaf, then the reassignment.
	let steps = ch["exit"]["broadcast"].as_array().unwrap_or_else(|| panic!("the answer is published: {}", ch)).clone();
	assert!(!steps.is_empty(), "{}", ch);
	let checkpoint = spender_of(&r, &OutPoint::new(conv_id, 0)).expect("the converted leaf is answered with its checkpoint");
	assert_eq!(steps[0]["txid"], checkpoint.txid().to_string(), "the receiver's own checkpoint answers: {}", ch);
	let CoinRecord::Transfer(t) = record_of(&b, &coin) else { panic!("a coin of a transfer") };
	assert_eq!(checkpoint.output[0].value.explicit(), Some(t.inputs[0].checkpoint_value), "the checkpoint the receiver holds: {}", ch);
	println!("F5 the converted leaf answered by checkpoint {}; the receiver published {} step(s)", checkpoint.txid(), steps.len());
	r.produce().await;
	let claim = exit_and_claim(&r, &b, &coin, None).await;
	println!("F5 the receiver's claim {} pays {} of X", claim.txid(), claim.output[0].value.explicit().unwrap());
	assert!(claim.output[0].value.explicit().unwrap() > 599_000);

	// The sender's claim of the converted leaf after its delay.
	let leaf = rec.leaf();
	let ks = leaf.exit_tx(OutPoint::new(conv_id, 0), rec.asset, rec.value, &[ExplicitOutput::new(rec.asset, rec.value - 2_000,
		Script::from(vec![0x53]))], &FeeSource::Reserve).unwrap();
	let sig = arca_covenant::sign::sign_digest(&leaf_key, &ks.sighash(genesis).unwrap(), &[0; 32]);
	let stale = ks.finish(vec![sig.as_ref().to_vec()]).tx;
	let refused = r.rt.client().send_raw_transaction(&stale).expect_err("the converted leaf is the receiver's checkpoint's");
	println!("F5 the sender's claim of its converted leaf: REFUSED: {}", refused);
	assert!(refused.to_string().contains("missingorspent"), "{}", refused);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// The way to the server
// ---------------------------------------------------------------------------

/// A TLS server on this machine whose certificate no root vouches for, as
/// `openssl s_server` runs it.
struct TlsServer {
	child: std::process::Child,
	dir: std::path::PathBuf,
	port: u16,
}

impl TlsServer {
	fn start() -> TlsServer {
		let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("arca-cli-tls-{}", std::process::id()));
		std::fs::create_dir_all(&dir).unwrap();
		let ok = std::process::Command::new("openssl")
			.args(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
				"-subj", "/CN=127.0.0.1", "-keyout"]).arg(dir.join("key.pem")).arg("-out").arg(dir.join("cert.pem"))
			.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().expect("openssl");
		assert!(ok.success());
		let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
		let child = std::process::Command::new("openssl")
			.args(["s_server", "-quiet", "-www", "-accept", &port.to_string(), "-cert"]).arg(dir.join("cert.pem"))
			.arg("-key").arg(dir.join("key.pem"))
			.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().expect("openssl s_server");
		let start = std::time::Instant::now();
		while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
			assert!(start.elapsed() < std::time::Duration::from_secs(10), "s_server did not listen");
			std::thread::sleep(std::time::Duration::from_millis(100));
		}
		TlsServer { child, dir, port }
	}
}

impl Drop for TlsServer {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
		let _ = std::fs::remove_dir_all(&self.dir);
	}
}

/// The wallet speaks TLS to a server named `https://`, and refuses a server
/// whose certificate no root vouches for; it speaks plain HTTP to this
/// machine alone, refusing any other host before it sends anything; and
/// `create` shows the operator key it pins, for the user to compare.
#[tokio::test(flavor = "multi_thread")]
async fn the_server_is_reached_over_tls_and_plain_http_only_on_this_machine() {
	let r = Running::start().await;
	let node = r.node_url();
	let ca = Arca::new("F8a");
	let why = ca.refused(&create_args("http://192.0.2.1:3535/arca", &node), "plain http");
	println!("F8 plain http to another host: REFUSED: {}", why);
	let tls = tokio::task::block_in_place(TlsServer::start);
	let cb = Arca::new("F8b");
	let url = format!("https://127.0.0.1:{}/arca", tls.port);
	let why = cb.refused(&create_args(&url, &node), "cannot reach the server");
	println!("F8 https to a server with a certificate no root vouches for: REFUSED: {}", why);
	assert!(!why.contains("https feature"), "{}", why);
	assert!(why.to_lowercase().contains("certificate") || why.to_lowercase().contains("issuer"), "TLS refused it: {}", why);
	let c = Arca::new("F8c");
	let (ok, info, err) = c.run_full(&create_args(&r.url(), &node));
	assert!(ok, "{}", info);
	println!("F8 create: {}", err.trim());
	let op = info["operator"].as_str().unwrap();
	assert!(info["operator_key_check"].as_str().unwrap().contains(op) && err.contains(op), "the pinned key is shown: {}", info);
	for w in [&ca, &cb, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// An answer lost, a coin not yet backed
// ---------------------------------------------------------------------------

/// The server co-signs a payment and the answer comes back as a gateway's
/// 502. That is no refusal: the coin stays in flight, `sync` posts the same
/// bytes again, and the server's same answer spends the coin and keeps the
/// change.
#[tokio::test(flavor = "multi_thread")]
async fn a_5xx_after_the_server_cosigned_keeps_the_payment_and_posts_it_again() {
	let mut r = Running::start().await;
	let proxy = Proxy::start(&r.url());
	let url = r.url();
	let x = r.x;
	let a = Arca::new("F9A");
	let b = Arca::new("F9B");
	let boards = boarded(&mut r, &a, &proxy.url.clone(), &[(x, 2_000_000)]).await;
	b.ok(&create_args(&url, &r.node_url()));
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/cosign_transfer" && status == 200 {
			*v = json!({"error": {"code": "bad_gateway", "message": "upstream timed out"}});
			return Some(502);
		}
		None
	})));
	let (ok, v) = a.run(&["send", &req, "--amount", "600000", "--asset", &x.to_string()]);
	println!("F9 A's send answered 502 after the server co-signed: ok={} {}", ok, v);
	assert!(!ok);
	assert_eq!(v["error"]["kind"], "unreachable", "a 502 is not a refusal: {}", v);
	proxy.rewrite(None);
	assert_eq!(coin_of(&a, &boards[0])["state"], "sending", "the coin is still in flight, not live");
	let m = b.ok(&["mailbox"]);
	assert_eq!(m["accepted"][0]["value"], "600000", "the receiver has its coin: {}", m);
	let s = a.ok(&["sync"]);
	println!("F9 A's sync: transfers {}", s["transfers"]);
	assert!(s["transfers"][0]["transfer_id"].is_string(), "the request posted again gets the server's answer: {}", s);
	let calls: Vec<Value> = proxy.calls().into_iter().filter(|(p, ..)| p == "/v1/cosign_transfer").map(|(_, q, ..)| q).collect();
	assert_eq!(calls.len(), 2);
	assert_eq!(calls[0], calls[1], "the same request, byte for byte");
	assert_eq!(coin_of(&a, &boards[0])["state"], "spent");
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A payment asked for while the signer is away: the server records the
/// transfer, its coin spent by it, and answers 503 before anything is
/// signed; the sender's wallet keeps the request standing. The board's exit
/// deadline passes before the sender looks again. Posted again, the request
/// completes whatever the board's dates have become since: it was within
/// them when the server recorded it. The sender's change and the receiver's
/// coin, past their board's exit deadline, are each taken and taken on the
/// chain at once (D57), from the lineage either published first; a refresh
/// of the receiver's is refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_payment_recorded_while_the_signer_was_away_completes_past_the_boards_exit_deadline() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let (a, w) = (Arca::new("T1A"), Arca::new("T1W"));
	let p = Proxy::start(&url);
	let boards = boarded(&mut r, &a, &p.url.clone(), &[(x, 2_000_000)]).await;
	w.ok(&create_args(&url, &r.node_url()));
	let req = w.ok(&["receive"])["request"].as_str().unwrap().to_string();
	// The signer goes away after A's witness, as the payment reaches the
	// server.
	signer_goes_away_at_the_payment(&p, &r);
	let (ok, v) = a.run(&["send", &req, "--amount", "600000", "--asset", &x.to_string()]);
	p.rewrite_request(None);
	r.signer.halt();
	println!("T1 A pays W with the signer away: ok={} {}", ok, v);
	assert!(!ok);
	assert_eq!(v["error"]["kind"], "unreachable", "a 503 is not a refusal: {}", v);
	assert_eq!(coin_of(&a, &boards[0])["state"], "sending");
	let id: LeafId = boards[0].parse().unwrap();
	let at_server = r.server.store.leaf(&id.0).await.unwrap().unwrap();
	println!("T1 A's coin at the server: {:?}", at_server.state);
	assert_eq!(at_server.state, server::store::LeafState::Spent, "the server recorded the transfer");
	// The board's exit deadline passes.
	let deadline = coin_of(&a, &boards[0])["exit_deadline"].as_u64().unwrap() as u32;
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, deadline - now + 3_600));
	r.bury().await;
	r.synced().await;
	println!("T1 now {}: past the board's exit deadline {}", common::node::median_time(&r.rt), deadline);
	let genesis = r.rt.client().genesis_hash().unwrap();
	tokio::task::block_in_place(|| r.signer.resume(genesis));
	let s = a.ok(&["sync"]);
	println!("T1 A's sync, the signer back: transfers {}", s["transfers"]);
	assert!(s["transfers"][0]["transfer_id"].is_string(), "the request posted again completes: {}", s);
	assert_eq!(coin_of(&a, &boards[0])["state"], "spent");
	// A's change rests on the board past its exit deadline: D57 takes it on
	// the chain at once.
	let kept = &s["transfers"][0]["kept"][0];
	println!("T1 A's change: {}", kept);
	assert_eq!(kept["state"], "exiting", "{}", kept);
	assert!(kept["note"].as_str().unwrap().contains("a day or less from its exit date"), "{}", kept);
	let s = w.ok(&["sync"]);
	let m = s["mailbox"].clone();
	println!("T1 W's mailbox: {}", m);
	let got = m["accepted"][0].clone();
	// Past its exit deadline the coin is not refreshed: W takes it, and takes
	// it on the chain at once; a refresh of it is refused.
	assert_eq!((got["value"].as_str(), got["state"].as_str()), (Some("600000"), Some("exiting")), "{}", m);
	assert!(got["board"]["note"].as_str().unwrap().contains("past its exit deadline"), "{}", got);
	assert!(got["note"].as_str().unwrap().contains("a day or less from its exit date"), "{}", got);
	let leaf = got["leaf_id"].as_str().unwrap().to_string();
	let c = coin_of(&w, &leaf);
	assert_eq!(c["state"], "exiting", "{}", c);
	let (ok, v) = w.run(&["participate", "--leaf", &leaf]);
	println!("T1 W's refresh of it: ok={} {}", ok, v["error"]["message"]);
	assert!(!ok);
	d57_home(&r, &w, std::slice::from_ref(&leaf)).await;
	for c in [&a, &w] {
		let _ = std::fs::remove_dir_all(&c.dir);
	}
}

/// Takes the operator's signer away (its process killed) when the next
/// payment reaches the server through `p`: after the paying wallet's witness,
/// which needs the signer, and before the server asks the signer to co-sign.
fn signer_goes_away_at_the_payment(p: &Proxy, r: &Running) {
	let pid = r.signer.pid().to_string();
	p.rewrite_request(Some(Arc::new(move |path: &str, _: &mut Value| {
		if path == "/v1/cosign_transfer" {
			let _ = std::process::Command::new("kill").args(["-9", &pid]).status();
		}
	})));
}

/// R7d F5. A payment out of a batch leaf, recorded while the operator's
/// signer was away, completes when it is asked again whatever has changed
/// since: the node's floor in the asset fell a hundredfold, which puts the
/// margins the server took above its bound of the moment, and the batch's
/// exit deadline passed. The margins are judged as they were when the
/// transfer was recorded, and only the batch's expiry would refuse it. The
/// receiver takes the coin, past that deadline, and exits it at once, as
/// the sender does its change; the receiver claims it.
#[tokio::test(flavor = "multi_thread")]
async fn a_payment_recorded_while_the_signer_was_away_completes_whatever_changed_since() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let (a, w) = (Arca::new("F5RA"), Arca::new("F5RW"));
	let p = Proxy::start(&url);
	boarded(&mut r, &a, &p.url.clone(), &[(x, 2_000_000)]).await;
	a.ok(&["participate"]);
	final_round(&r).await;
	let s = a.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s["participations"]);
	let leaf = s["participations"][0]["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	assert_eq!(coin_of(&a, &leaf)["state"], "live");
	w.ok(&create_args(&url, &r.node_url()));
	let req = w.ok(&["receive"])["request"].as_str().unwrap().to_string();
	signer_goes_away_at_the_payment(&p, &r);
	let (ok, v) = a.run(&["send", &req, "--amount", "600000", "--asset", &x.to_string()]);
	p.rewrite_request(None);
	r.signer.halt();
	println!("F5R A pays W out of its batch leaf with the signer away: ok={} {}", ok, v);
	assert!(!ok);
	assert_eq!(v["error"]["kind"], "unreachable", "a 503 is not a refusal: {}", v);
	let id: LeafId = leaf.parse().unwrap();
	assert_eq!(r.server.store.leaf(&id.0).await.unwrap().unwrap().state, server::store::LeafState::Spent, "the server recorded it");

	// The floor in X falls a hundredfold: X is worth a hundred times more.
	let rates = rpc(&r, "getfeeexchangerates", &[]);
	let rate = rates[x.to_string()].as_u64().expect("X is listed");
	common::node::list_fee_asset(&r.rt, x, rate * 100);
	// The batch's exit deadline passes.
	let deadline = coin_of(&a, &leaf)["exit_deadline"].as_u64().unwrap() as u32;
	let expiry = coin_of(&a, &leaf)["expiry"].as_u64().unwrap() as u32;
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, deadline - now + 3_600));
	r.bury().await;
	r.synced().await;
	let now = common::node::median_time(&r.rt);
	println!("F5R now {}: past the batch's exit deadline {}, before its expiry {}", now, deadline, expiry);
	assert!(now > deadline && now < expiry);

	let genesis = r.rt.client().genesis_hash().unwrap();
	tokio::task::block_in_place(|| r.signer.resume(genesis));
	let s = a.ok(&["sync"]);
	println!("F5R A's sync, the signer back: transfers {}", s["transfers"]);
	assert!(s["transfers"][0]["transfer_id"].is_string(), "the request posted again completes: {}", s);
	assert_eq!(coin_of(&a, &leaf)["state"], "spent");
	let kept = &s["transfers"][0]["kept"][0];
	println!("F5R A's change: {}", kept);
	assert_eq!(kept["state"], "exiting", "the change, past the batch's exit deadline, is exited at once: {}", kept);
	let m = w.ok(&["sync"])["mailbox"].clone();
	println!("F5R W's mailbox: {}", m);
	let got = m["accepted"][0].clone();
	assert_eq!(got["value"].as_str(), Some("600000"), "{}", m);
	assert_eq!(got["state"], "exiting", "{}", got);
	assert!(got["batch"]["note"].as_str().unwrap().contains("past its exit deadline"), "{}", got);
	assert!(got["exit"]["error"].is_null(), "{}", got["exit"]);
	let new = got["leaf_id"].as_str().unwrap().to_string();
	let claim = exit_and_claim(&r, &w, &new, None).await;
	println!("F5R W's claim: {} ({} vB), before the batch's expiry", claim.txid(), claim.vsize());
	assert!(common::node::median_time(&r.rt) < expiry);
	for c in [&a, &w] {
		let _ = std::fs::remove_dir_all(&c.dir);
	}
}

/// A participation the server took, its answer lost as a gateway's 502: the
/// wallet keeps it `submitting` and `sync` posts its stored body again. The
/// body is posted without its key proofs, as a wallet stored it before they
/// existed. The server holds the participation, so it answers with its
/// status whatever the body lacks: the coin stays given up, and the wallet
/// completes the participation once its round is final, its new leaf live. A
/// participation the server does not hold still needs its proofs.
#[tokio::test(flavor = "multi_thread")]
async fn a_participation_the_server_holds_is_answered_whatever_its_body_lacks() {
	let mut r = Running::start().await;
	let proxy = Proxy::start(&r.url());
	let x = r.x;
	let a = Arca::new("M1A");
	let boards = boarded(&mut r, &a, &proxy.url.clone(), &[(x, 2_000_000), (x, 1_000_000)]).await;
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/submit_participation" && status == 200 {
			*v = json!({"error": {"code": "bad_gateway", "message": "upstream timed out"}});
			return Some(502);
		}
		None
	})));
	let (ok, v) = a.run(&["participate", "--leaf", &boards[0]]);
	println!("M1 participate, answered 502 after the server took it: ok={} {}", ok, v);
	assert!(!ok);
	assert_eq!(v["error"]["kind"], "unreachable", "a 502 is not a refusal: {}", v);
	proxy.rewrite(None);
	assert_eq!(coin_of(&a, &boards[0])["state"], "given");
	// Posted again without its key proofs.
	let strip: common::proxy::RewriteRequest = Arc::new(|path: &str, body: &mut Value| {
		if path == "/v1/submit_participation" {
			for o in body["outputs"].as_array_mut().into_iter().flatten() {
				if let Some(l) = o["leaf"].as_object_mut() {
					l.remove("key_proof");
				}
			}
		}
	});
	proxy.rewrite_request(Some(strip.clone()));
	let s = a.ok(&["sync"]);
	println!("M1 sync, the stored body posted again without its key proofs: participations {}", s["participations"]);
	let (req, status, answer) = proxy.last("/v1/submit_participation").unwrap();
	assert!(req["outputs"][0]["leaf"].get("key_proof").is_none(), "{}", req);
	println!("M1 the server's answer: {} {}", status, answer);
	assert_eq!((status, answer["state"].as_str()), (200, Some("pending")), "{}", answer);
	assert_eq!(s["participations"][0]["state"], "pending", "{}", s);
	assert_eq!(coin_of(&a, &boards[0])["state"], "given", "the coin the server holds stays given up");
	// A participation the server does not hold: refused without its proofs.
	let (ok, v) = a.run(&["participate", "--leaf", &boards[1]]);
	println!("M1 a new participation without its key proofs: ok={} {}", ok, v);
	assert!(!ok);
	assert_eq!((v["error"]["status"].as_i64(), v["error"]["code"].as_str()), (Some(422), Some("bad_attestation")), "{}", v);
	assert_eq!(coin_of(&a, &boards[1])["state"], "live", "a refusal gives the coin back");
	proxy.rewrite_request(None);
	// The round runs it; the wallet completes it.
	final_round(&r).await;
	let s = a.ok(&["sync"]);
	println!("M1 sync once the round is final: {}", s["participations"]);
	let done = s["participations"].as_array().unwrap().iter().find(|p| p["state"] == "released").cloned()
		.unwrap_or_else(|| panic!("the participation completes: {}", s));
	let new = done["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	assert_eq!(coin_of(&a, &boards[0])["state"], "spent");
	assert_eq!(coin_of(&a, &new)["state"], "live", "{}", coin_of(&a, &new));
	let _ = std::fs::remove_dir_all(&a.dir);
}

/// The server registers a board, and broadcasts it itself, but the answer
/// comes back as a gateway's 502. That is no refusal: the coin stays pending
/// with its transaction, `sync` posts the same registration again, and the
/// coin is live once the board is final.
#[tokio::test(flavor = "multi_thread")]
async fn a_board_whose_answer_is_lost_stays_pending_and_is_registered_again() {
	let mut r = Running::start().await;
	let proxy = Proxy::start(&r.url());
	let x = r.x;
	let a = Arca::new("F1A");
	a.ok(&create_args(&proxy.url, &r.node_url()));
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, x, 5_000_000);
	r.produce().await;
	let onchain = |w: &Arca| w.ok(&["balance"])["sequentia_onchain"][x.to_string()].as_str().unwrap_or("0").parse::<u64>().unwrap();
	let before = onchain(&a);
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/register_board" && status == 200 {
			*v = json!({"error": {"code": "bad_gateway", "message": "upstream timed out"}});
			return Some(502);
		}
		None
	})));
	let (ok, v) = a.run(&["board", &x.to_string(), "2000000"]);
	println!("F1 board, answered 502 after the server registered it: ok={} {}", ok, v);
	assert!(!ok);
	assert_eq!(v["error"]["kind"], "unreachable", "a 502 is not a refusal: {}", v);
	proxy.rewrite(None);
	let coins = a.ok(&["coins"]);
	let leaf = coins[0]["leaf_id"].as_str().unwrap().to_string();
	assert_eq!(coins[0]["state"], "pending", "the board is not lost: {}", coins);
	assert!(v["error"]["message"].as_str().unwrap().contains("kept pending with its transaction"), "{}", v);
	let id: LeafId = leaf.parse().unwrap();
	let row = r.server.store.board(&id.0).await.unwrap().expect("the server took the board");
	println!("F1 the server's board: {:?}", row.state);
	let s = a.ok(&["sync"]);
	println!("F1 sync: boards {}", s["boards"]);
	assert_eq!(s["boards"][0]["registered"], true, "{}", s);
	let calls: Vec<Value> = proxy.calls().into_iter().filter(|(p, ..)| p == "/v1/register_board").map(|(_, q, ..)| q).collect();
	assert_eq!(calls.len(), 2);
	assert_eq!(calls[0], calls[1], "the same registration, byte for byte");
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the server to credit the board", || {
		a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")
	}).await;
	a.ok(&["sync"]);
	assert_eq!(coin_of(&a, &leaf)["state"], "live", "the board is the wallet's: {}", coin_of(&a, &leaf));
	assert_eq!(a.ok(&["balance"])["arca"][x.to_string()]["live"], "2000000");
	assert!(before - onchain(&a) >= 2_000_000);
	let _ = std::fs::remove_dir_all(&a.dir);
}

/// A board answered with a refusal although the server took it (a proxy's
/// own 4xx, or a wallet that once took every failure for a refusal): the
/// wallet holds it as lost, then follows it again once the server reports it
/// credited and its transaction is in the chain.
#[tokio::test(flavor = "multi_thread")]
async fn a_board_held_as_lost_is_followed_again_once_the_server_credits_it() {
	let mut r = Running::start().await;
	let proxy = Proxy::start(&r.url());
	let x = r.x;
	let a = Arca::new("F1bA");
	a.ok(&create_args(&proxy.url, &r.node_url()));
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, x, 5_000_000);
	r.produce().await;
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/register_board" && status == 200 {
			*v = json!({"error": {"code": "not_accepted", "message": "a refusal the server never made"}});
			return Some(422);
		}
		None
	})));
	let (ok, v) = a.run(&["board", &x.to_string(), "1500000"]);
	println!("F1b a board answered with a refusal after the server registered it: ok={} {}", ok, v);
	assert!(!ok);
	proxy.rewrite(None);
	let second = a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["value"] == "1500000").cloned().unwrap();
	let second_leaf = second["leaf_id"].as_str().unwrap().to_string();
	assert_eq!(second["state"], "lost", "{}", second);
	let id: LeafId = second_leaf.parse().unwrap();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	// The server's own record, not a command of the wallet's: each command
	// re-checks the wallet's coins when it starts.
	r.wait("the server to credit the board", || {
		tokio::runtime::Handle::current().block_on(async {
			r.server.boards.pass().await.ok();
			r.server.store.board(&id.0).await.unwrap().map(|b| format!("{:?}", b.state)) == Some("Credited".into())
		})
	}).await;
	let re = a.ok(&["recheck"]);
	println!("F1b recheck: {}", re);
	assert!(re["changes"].as_array().unwrap().iter().any(|c| c["leaf_id"] == second_leaf && c["from"] == "lost" && c["to"] == "live"), "{}", re);
	assert_eq!(coin_of(&a, &second_leaf)["state"], "live");
	assert_eq!(a.ok(&["balance"])["arca"][x.to_string()]["live"], "1500000");
	let _ = std::fs::remove_dir_all(&a.dir);
}

/// A coin paid to the wallet while the board it rests on is rolled out of
/// the chain is refused for a passing reason, kept, and accepted once the
/// board is back.
#[tokio::test(flavor = "multi_thread")]
async fn a_mailbox_coin_refused_during_a_rollback_is_taken_once_its_board_returns() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let a = Arca::new("F10A");
	let b = Arca::new("F10B");
	let boards = boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	b.ok(&create_args(&url, &r.node_url()));
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req, "--amount", "600000", "--asset", &x.to_string()]);
	let CoinRecord::Board(rec) = record_of(&a, &boards[0]) else { panic!("a board") };
	let board_txid = find_unspent(&r, &rec.output().txout()).txid.to_string();
	let block = block_of(&r, &board_txid);
	rpc(&r, "invalidateblock", &[json!(block)]);
	let m = b.ok(&["mailbox"]);
	println!("F10 B's mailbox during the rollback: {}", m);
	assert_eq!(m["refused"], json!([]), "{}", m);
	assert!(m["waiting"][0]["reason"].as_str().unwrap().contains("no transaction on the chain pays"), "{}", m);
	rpc(&r, "reconsiderblock", &[json!(block)]);
	r.produce().await;
	r.bury().await;
	let m = b.ok(&["mailbox"]);
	println!("F10 B's mailbox once the board is back: {}", m);
	assert_eq!(m["accepted"][0]["value"], "600000", "{}", m);
	assert_eq!(b.ok(&["mailbox"])["waiting"], json!([]));
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// What the wallet accepts, and what it shows
// ---------------------------------------------------------------------------

/// Sets the node's fee whitelist to exactly `rates`.
fn set_fee_rates(r: &Running, rates: &[(AssetId, u64)]) {
	let map: serde_json::Map<String, Value> = rates.iter().map(|(a, v)| (a.to_string(), json!(v))).collect();
	rpc(r, "setfeeexchangerates", &[Value::Object(map)]);
}

/// A round whose tree in asset Y holds one-atom reserves, the operator's
/// rule for an asset the node does not take for fees, while the wallet's
/// node does take Y: the wallet refuses the leaf before it signs anything,
/// since its reserves would not pay its own exit. Where the node does not
/// take Y, one atom is the rule, and the wallet says, before it gives up a
/// coin and again when it takes the leaf, that every exit of it needs a fee
/// coin.
#[tokio::test(flavor = "multi_thread")]
async fn a_tree_whose_reserves_cannot_pay_its_exit_is_refused() {
	let mut r = Running::start().await;
	let url = r.url();
	let (x, y) = (r.x, r.y);
	let c = Arca::new("F11");
	c.ok(&create_args(&url, &r.node_url()));
	for (a, v) in [(y, 5_000_000), (x, 1_000_000)] {
		let s = script(&c.ok(&["address"]));
		r.pay_to(s, a, v);
	}
	r.produce().await;
	let board = c.ok(&["board", &y.to_string(), "2000000", "--fee-asset", &x.to_string()])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || c.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	c.ok(&["sync"]);
	let p = c.ok(&["participate", "--leaf", &board]);
	println!("F11 participate in Y, which the node does not take for fees: {}", p["exit_needs_fee_coin"]);
	assert_eq!(p["exit_needs_fee_coin"]["assets"], json!([y.to_string()]), "stated before the coin is given up: {}", p);
	let round = final_round(&r).await;
	println!("F11 round {} built while Y is not taken for fees", round.txid());
	// The wallet's node now takes Y for fees.
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	let s = c.ok(&["sync"]);
	let why = s["participations"][0]["refused"].as_str().unwrap_or_else(|| panic!("not refused: {}", s)).to_string();
	println!("F11 one-atom reserves in an asset the node takes for fees: REFUSED: {}", why);
	assert!(why.contains("reserve of 1"), "{}", why);
	assert_eq!(coin_of(&c, &board)["state"], "given", "no forfeit was signed");
	// The node no longer takes Y: one atom is the rule there.
	set_fee_rates(&r, &[(x, 100_000_000)]);
	let s = c.ok(&["sync"]);
	let done = &s["participations"][0];
	println!("F11 the same tree where the node does not take Y: {}", done["exit_needs_fee_coin"]);
	assert_eq!(done["state"], "released", "{}", s);
	assert_eq!(done["exit_needs_fee_coin"]["assets"], json!([y.to_string()]), "{}", s);
	let _ = std::fs::remove_dir_all(&c.dir);
}

/// D51. A swap's taker sees the dates of the coins it would get before it
/// signs: they rest on every coin the swap spends, so they carry the
/// earliest dates among them. A swap of fresh coins is taken at once, its
/// dates shown. After 23½ days, the maker's change rests on boards whose
/// exit deadline is a day and a half away: the taker's accept is refused,
/// saying so, and taken with `--accept-near-deadline`, whose coins arrive
/// with the dates it showed.
#[tokio::test(flavor = "multi_thread")]
async fn a_swap_shows_the_dates_it_gives_and_is_refused_near_the_exit_deadline() {
	let mut r = Running::start().await;
	let url = r.url();
	let (x, y) = (r.x, r.y);
	let (a, b) = (Arca::new("D51A"), Arca::new("D51B"));
	boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	b.ok(&create_args(&url, &r.node_url()));
	for (asset, v) in [(y, 10_000_000), (x, 1_000_000)] {
		let s = script(&b.ok(&["address"]));
		r.pay_to(s, asset, v);
	}
	r.produce().await;
	b.ok(&["board", &y.to_string(), "3000000", "--fee-asset", &x.to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || b.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	b.ok(&["sync"]);
	let offer = a.ok(&["swap", "offer", "--give-asset", &x.to_string(), "--give", "300000", "--want-asset", &y.to_string(), "--want", "400000"]);
	let acc = b.ok(&["swap", "accept", offer["offer"].as_str().unwrap()]);
	let now = common::node::median_time(&r.rt) as u64;
	println!("D51 a swap of fresh coins: taken; the coins it gives: {}", acc["coins"]);
	let d = acc["dates"]["exit_deadline"].as_u64().unwrap();
	assert!(d > now + 20 * 86_400, "{}", acc["dates"]);
	assert_eq!(acc["dates"]["rests_on_board"], true);
	a.ok(&["swap", "complete", acc["accept"].as_str().unwrap()]);
	let got = b.ok(&["sync"])["mailbox"]["accepted"].as_array().unwrap().iter()
		.find(|c| c["asset"] == x.to_string().as_str()).cloned().unwrap();
	println!("D51 the coin it got: {}", got["board"]);
	assert_eq!(got["board"]["exit_deadline"].as_u64(), Some(d), "the dates shown are the coin's");

	// 23½ days on: the exit deadline of every coin here is a day and a half
	// away. (No sync of A's here: in that window `sync` would ask for the
	// refresh of its coins, which this test keeps live to swap them.)
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 23 * 86_400 + 43_200));
	r.bury().await;
	r.synced().await;
	// B pays from a fresh board: the swap's coins still carry the maker's
	// change's dates, the earliest.
	b.ok(&["board", &y.to_string(), "4000000", "--fee-asset", &x.to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || b.ok(&["boards"]).as_array().unwrap().iter().all(|x| x["server"]["state"] == "credited")).await;
	b.ok(&["sync"]);
	let offer = a.ok(&["swap", "offer", "--give-asset", &x.to_string(), "--give", "300000", "--want-asset", &y.to_string(), "--want", "200000"]);
	let why = b.refused(&["swap", "accept", offer["offer"].as_str().unwrap()], "earliest exit deadline");
	println!("D51 near the deadline, refused: {}", why);
	assert!(why.contains("--accept-near-deadline"), "{}", why);
	let acc = b.ok(&["swap", "accept", offer["offer"].as_str().unwrap(), "--accept-near-deadline"]);
	let now = common::node::median_time(&r.rt) as u64;
	let left = acc["dates"]["seconds_to_exit_deadline"].as_u64().unwrap();
	println!("D51 taken with --accept-near-deadline: {} ({} s to the exit deadline)", acc["dates"], left);
	assert!(left < 2 * 86_400 && left > 0, "{}", acc["dates"]);
	let d = acc["dates"]["exit_deadline"].as_u64().unwrap();
	assert_eq!(d as u64, now + left);
	// The maker gets coins resting on the same coins: refused alike, and
	// completed only when it takes them anyway.
	let why = a.refused(&["swap", "complete", acc["accept"].as_str().unwrap()], "earliest exit deadline");
	println!("D51 the maker near the deadline, refused: {}", why);
	let done = a.ok(&["swap", "complete", acc["accept"].as_str().unwrap(), "--accept-near-deadline"]);
	assert_eq!(done["dates"]["exit_deadline"].as_u64(), Some(d), "{}", done["dates"]);
	let got = b.ok(&["sync"])["mailbox"]["accepted"].as_array().unwrap().iter()
		.find(|c| c["asset"] == x.to_string().as_str()).cloned().unwrap();
	println!("D51 the coin it got: {}", got["board"]);
	assert_eq!(got["board"]["exit_deadline"].as_u64(), Some(d), "the dates shown are the coin's");
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// D51, the maker's side (review R7e, F6). The taker's coin rests on a
/// board a day and a half from its exit deadline, the maker's on a fresh
/// one: every coin the swap makes rests on both, so the coin the maker gets
/// carries the taker's board's dates. The maker sees them before it signs,
/// and its completion is refused until it takes them anyway, as a taker's
/// acceptance is.
#[tokio::test(flavor = "multi_thread")]
async fn a_swap_shows_the_maker_the_dates_it_gets_and_is_refused_near_the_exit_deadline() {
	let mut r = Running::start().await;
	let url = r.url();
	let (x, y) = (r.x, r.y);
	let (a, b) = (Arca::new("D51mA"), Arca::new("D51mB"));
	// The taker boards first.
	b.ok(&create_args(&url, &r.node_url()));
	for (asset, v) in [(y, 10_000_000), (x, 1_000_000)] {
		let s = script(&b.ok(&["address"]));
		r.pay_to(s, asset, v);
	}
	r.produce().await;
	b.ok(&["board", &y.to_string(), "3000000", "--fee-asset", &x.to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || b.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	b.ok(&["sync"]);
	// 23½ days on, the maker boards: its coin is fresh, the taker's a day
	// and a half from its exit deadline. (No sync of B's here: in that window
	// `sync` would ask for the refresh of its coin, which this test keeps
	// live to swap it.)
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 23 * 86_400 + 43_200));
	r.bury().await;
	r.synced().await;
	boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	let offer = a.ok(&["swap", "offer", "--give-asset", &x.to_string(), "--give", "300000", "--want-asset", &y.to_string(), "--want", "400000"]);
	let acc = b.ok(&["swap", "accept", offer["offer"].as_str().unwrap(), "--accept-near-deadline"]);
	let d = acc["dates"]["exit_deadline"].as_u64().unwrap();
	println!("D51m the taker accepts, its own coin near its deadline: {}", acc["dates"]);
	let why = a.refused(&["swap", "complete", acc["accept"].as_str().unwrap()], "earliest exit deadline");
	println!("D51m the maker, the taker's coin near its deadline, refused: {}", why);
	assert!(why.contains("--accept-near-deadline"), "{}", why);
	let held = a.ok(&["coins"]);
	assert!(held.as_array().unwrap().iter().any(|c| c["state"] == "offered"), "nothing signed, the offer stands: {}", held);
	let done = a.ok(&["swap", "complete", acc["accept"].as_str().unwrap(), "--accept-near-deadline"]);
	let now = common::node::median_time(&r.rt) as u64;
	println!("D51m completed with --accept-near-deadline: {}", done["dates"]);
	let left = done["dates"]["seconds_to_exit_deadline"].as_u64().unwrap();
	assert!(left < 2 * 86_400 && left > 0, "{}", done["dates"]);
	assert_eq!(done["dates"]["exit_deadline"].as_u64(), Some(d));
	assert_eq!(d, now + left);
	// The maker takes its own outputs when the server answers.
	a.ok(&["sync"]);
	let got = a.ok(&["coins"]).as_array().unwrap().iter()
		.find(|c| c["asset"] == y.to_string().as_str() && c["state"] != "spent").cloned().unwrap();
	println!("D51m the coin the maker got: {}", got);
	assert_eq!(got["exit_deadline"].as_u64(), Some(d), "the dates shown are the coin's");
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// Two payments from one payer share its first transfer: A pays B twice,
/// the second payment out of the first's change, so both of B's coins
/// descend from A's first transfer. B pays C the sum of both, less the
/// margins, in one transfer, which the server co-signs and C accepts. C
/// then exits the coin: the exit builds A's first transfer once, and C
/// claims the coin.
#[tokio::test(flavor = "multi_thread")]
async fn two_payments_from_one_payer_are_paid_on_together_and_exited() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let (a, b, c) = (Arca::new("SHA"), Arca::new("SHB"), Arca::new("SHC"));
	boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	b.ok(&create_args(&url, &r.node_url()));
	c.ok(&create_args(&url, &r.node_url()));
	for v in ["300000", "100000"] {
		let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
		let sent = a.ok(&["send", &req, "--amount", v, "--asset", &x.to_string()]);
		println!("SH A pays B {} from {:?}", v, sent["inputs"]);
		assert_eq!(b.ok(&["mailbox"])["accepted"].as_array().unwrap().len(), 1);
	}
	let held: Vec<Value> = b.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live").cloned().collect();
	assert_eq!(held.len(), 2, "B holds the two payments");
	let total: u64 = held.iter().map(|c| c["value"].as_str().unwrap().parse::<u64>().unwrap()).sum();
	assert_eq!(total, 400_000);

	// The most B can pay out of both: the sum less the margins, which the
	// wallet's refusal of the whole sum names.
	let req = c.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let msg = b.refused(&["send", &req, "--amount", "400000", "--asset", &x.to_string()], " takes ");
	let takes: u64 = msg.split(" takes ").nth(1).and_then(|t| t.split(' ').next()).and_then(|t| t.parse().ok()).expect("what paying takes");
	let most = total - (takes - total);
	b.refused(&["send", &req, "--amount", &(most + 1).to_string(), "--asset", &x.to_string()], &format!("takes {} ", total + 1));
	let sent = b.ok(&["send", &req, "--amount", &most.to_string(), "--asset", &x.to_string()]);
	println!("SH B pays C out of both coins: {}", sent);
	let mut inputs: Vec<&str> = sent["inputs"].as_array().unwrap().iter().map(|i| i.as_str().unwrap()).collect();
	let mut ids: Vec<&str> = held.iter().map(|c| c["leaf_id"].as_str().unwrap()).collect();
	inputs.sort();
	ids.sort();
	assert_eq!(inputs, ids, "both of B's coins in one transfer");
	assert!(sent["change"].is_null(), "the sum of both, less the margins: {}", sent);
	let got = c.ok(&["mailbox"])["accepted"][0].clone();
	let leaf = got["leaf_id"].as_str().expect("C accepts the coin").to_string();
	assert_eq!(got["value"].as_str(), sent["sent"]["value"].as_str());
	// The coin's record reaches A's first transfer through both inputs.
	let CoinRecord::Transfer(t) = record_of(&c, &leaf) else { panic!("a transfer") };
	let first = |r: &CoinRecord| -> Option<Vec<arca_covenant::ExplicitOutput>> {
		let mut r = r;
		let mut last = None;
		while let CoinRecord::Transfer(t) = r {
			last = Some(t.outputs.clone());
			r = &t.inputs[0].coin;
		}
		last
	};
	assert_eq!(first(&t.inputs[0].coin), first(&t.inputs[1].coin), "both inputs descend from A's first transfer");

	// C exits the coin: A's first transfer is built once.
	let s = script(&c.ok(&["address"]));
	r.pay_to(s, x, 2_000_000);
	r.produce().await;
	let e = c.ok(&["exit", &leaf, "--fee-asset", &x.to_string()]);
	println!("SH C's exit: {}", e);
	assert!(e["error"].is_null(), "every step of the exit is taken: {}", e);
	let txids: Vec<&str> = e["broadcast"].as_array().map(|b| b.iter().map(|s| s["txid"].as_str().unwrap()).collect()).unwrap_or_default();
	let mut unique = txids.clone();
	unique.sort();
	unique.dedup();
	assert_eq!(unique.len(), txids.len(), "no step built twice: {:?}", txids);
	let claim = exit_and_claim(&r, &c, &leaf, Some(&x.to_string())).await;
	println!("SH C's claim: {} ({} vB)", claim.txid(), claim.vsize());
	for w in [&a, &b, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A taker accepts an offer and cancels: the wallet spends the coin it
/// signed into the acceptance to a fresh leaf of its own, so the maker's
/// completion is refused. That leaf rests on a reassignment the operator
/// co-signed and is shown as operator-confirmed until a round.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_acceptance_cannot_complete() {
	let mut r = Running::start().await;
	let url = r.url();
	let (x, y) = (r.x, r.y);
	let a = Arca::new("F14A");
	let b = Arca::new("F14B");
	boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	b.ok(&create_args(&url, &r.node_url()));
	for (asset, v) in [(y, 5_000_000), (x, 1_000_000)] {
		let s = script(&b.ok(&["address"]));
		r.pay_to(s, asset, v);
	}
	r.produce().await;
	let bb = b.ok(&["board", &y.to_string(), "3000000", "--fee-asset", &x.to_string()])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || b.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	b.ok(&["sync"]);
	let offer = a.ok(&["swap", "offer", "--give-asset", &x.to_string(), "--give", "300000", "--want-asset", &y.to_string(), "--want", "400000"]);
	let acc = b.ok(&["swap", "accept", offer["offer"].as_str().unwrap()]);
	let cancel = b.ok(&["swap", "cancel", acc["swap"].as_str().unwrap()]);
	println!("F14 the taker cancels its acceptance: {}", cancel);
	assert_eq!(cancel["cancelled"], true, "{}", cancel);
	assert_eq!(coin_of(&b, &bb)["state"], "spent", "the coin signed into the acceptance is spent elsewhere");
	let why = a.refused(&["swap", "complete", acc["accept"].as_str().unwrap()], "double_spend");
	println!("F14 the maker completes after the cancel: REFUSED: {}", why);
	let bal = b.ok(&["balance"]);
	println!("F12 the taker's balance: {}", bal["arca"]);
	let kept: u64 = bal["arca"][y.to_string()]["operator-confirmed"].as_str().unwrap_or_else(|| panic!("{}", bal)).parse().unwrap();
	assert!(kept > 2_999_000, "the coin, less its margins, operator-confirmed: {}", bal);
	assert!(bal["arca"][y.to_string()].get("live").is_none(), "{}", bal);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// What the wallet keeps, and what it finds again
// ---------------------------------------------------------------------------

/// The node's password is never an argument: the wallet reads it once from
/// the environment and keeps it in a file of its own directory that only its
/// owner can read, never in its database, which only its owner can read too.
/// A fresh wallet shows one row, 0 BTC. A wallet restored from the mnemonic
/// finds on-chain coins past the first window of unused addresses, gap by
/// gap, and hands out no address it found in use.
#[tokio::test(flavor = "multi_thread")]
async fn secrets_stay_private_a_fresh_wallet_shows_btc_and_a_restore_finds_its_coins() {
	use std::os::unix::fs::PermissionsExt;
	let mut r = Running::start().await;
	let url = r.url();
	let node = r.node_url();
	let x = r.x;
	let a = Arca::new("F16");
	let args = create_args(&url, &node);
	assert!(!args.contains(&"--node-password"), "the password is not an argument");
	a.ok(&args);
	let mode = |f: &str| std::fs::metadata(a.dir.join(f)).unwrap().permissions().mode() & 0o777;
	println!("F16 modes: dir {:o}, mnemonic {:o}, node_password {:o}, arca.sqlite {:o}", mode(""), mode("mnemonic"),
		mode("node_password"), mode("arca.sqlite"));
	assert_eq!((mode(""), mode("mnemonic"), mode("node_password"), mode("arca.sqlite")), (0o700, 0o600, 0o600, 0o600));
	for f in ["arca.sqlite", "arca.sqlite-wal"] {
		let bytes = std::fs::read(a.dir.join(f)).unwrap_or_default();
		assert!(!bytes.windows(13).any(|w| w == b"node_password"), "{} holds no node password", f);
	}
	let bal = a.ok(&["balance"]);
	println!("F16 a fresh wallet's balance rows: {}", bal["rows"]);
	assert_eq!(bal["rows"], json!([{"asset": "BTC", "total": "0", "unit": "sat"}]), "one row, 0 BTC: {}", bal);

	// Coins at receive indices 15 and 30, the second past the first window.
	let addrs: Vec<Value> = (0..31).map(|_| a.ok(&["address"])).collect();
	r.pay_to(script(&addrs[15]), x, 700_000);
	r.pay_to(script(&addrs[30]), x, 300_000);
	r.produce().await;
	assert_eq!(a.ok(&["balance"])["sequentia_onchain"][x.to_string()], "1000000");
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap();
	let b = Arca::new("F16R");
	let mut args = create_args(&url, &node);
	args.extend(["--mnemonic", mnemonic.trim()]);
	b.ok(&args);
	let bal = b.ok(&["balance"]);
	println!("F16 the restored wallet's on-chain balance: {}", bal["sequentia_onchain"]);
	assert_eq!(bal["sequentia_onchain"][x.to_string()], "1000000", "both coins are found: {}", bal);
	let next = b.ok(&["address"]);
	assert!(addrs.iter().all(|u| u["address"] != next["address"]), "no address found in use is handed out again: {}", next);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// A coin under a forfeit, decided by the chain
// ---------------------------------------------------------------------------

/// The participation's status from the server's database (the server is
/// stopped): what the wallet was shown before.
fn stored_status(r: &Running, pid: &str) -> (u16, u32, u64, [u8; 32]) {
	let pid32: [u8; 32] = unhex(pid).try_into().unwrap();
	let store = r.server.store.clone();
	let p = tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(store.participation(&pid32))).unwrap().unwrap();
	let round = tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(store.round(p.round_id.unwrap())))
		.unwrap().unwrap();
	(p.refund_delay_units as u16, round.connector_vout, p.inputs[0].margin, p.unlock_hash)
}

fn in_mempool(r: &Running, txid: &elements::Txid) -> bool {
	let pool: Vec<String> = serde_json::from_value(rpc(r, "getrawmempool", &[])).unwrap();
	pool.iter().any(|t| *t == txid.to_string())
}

/// A board refreshed, its forfeit handed over and the preimage withheld;
/// the operator's watcher publishes the forfeit and the round's atom, then
/// the operator stops, holding back its claim, and the refund delay runs.
/// Returns the board, the participation, the forfeit's txid and the atom's,
/// and the preimage the operator holds.
async fn forfeit_left_unclaimed(r: &mut Running, proxy: &Proxy, c: &Arca) -> (String, String, elements::Txid, elements::Txid, [u8; 32]) {
	use elements::hashes::Hash;
	let x = r.x;
	let board = boarded(r, c, &proxy.url.clone(), &[(x, 2_000_000)]).await.remove(0);
	let pid = c.ok(&["participate"])["participation"].as_str().unwrap().to_string();
	final_round(r).await;
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/forfeit_leaves" && status == 200 {
			v["preimage"] = Value::Null;
		}
		None
	})));
	let s = c.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "forfeiting", "{}", s);
	let (mut forfeit, mut atom) = (None, None);
	for _ in 0..60 {
		let log = r.server.store.watcher_log().await.unwrap();
		forfeit = log.iter().find(|w| w.kind == "forfeit").map(|w| elements::Txid::from_byte_array(w.txid));
		atom = log.iter().find(|w| w.kind == "issue").map(|w| elements::Txid::from_byte_array(w.txid));
		assert!(!log.iter().any(|w| w.kind == "claim"), "the server is stopped before any claim");
		if forfeit.is_some() && atom.is_some() {
			break;
		}
		if forfeit.is_none() {
			r.produce().await;
		}
		tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
	}
	let (forfeit, atom) = (forfeit.expect("the watcher publishes the forfeit"), atom.expect("and the atom"));
	let pid32: [u8; 32] = unhex(&pid).try_into().unwrap();
	let preimage = r.server.store.participation(&pid32).await.unwrap().unwrap().preimage;
	r.server.stop();
	r.produce().await;
	assert!(confirmations(r, &forfeit) >= 1 && confirmations(r, &atom) >= 1, "the forfeit and the atom confirm");
	let (units, _, _, _) = stored_status(r, &pid);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, units as u32 * 512));
	(board, pid, forfeit, atom, preimage)
}

/// Review R8b's probe P2 turned around. Once the refund delay of a forfeit
/// the operator published has run, the wallet sends its refund; the
/// operator's claim, paying more, replaces it in the mempool and confirms,
/// its witness carrying the preimage. The refund in the mempool decided
/// nothing: the wallet follows the forfeit's output until a spend of it is
/// final, reads the preimage from the claim and holds the new leaf, and the
/// coin given up is spent, not exited.
#[tokio::test(flavor = "multi_thread")]
async fn a_refund_replaced_by_the_operators_claim_leaves_the_wallet_its_new_leaf() {
	use arca_covenant::spend::FeeSource;
	use arca_covenant::ExplicitOutput;
	use elements::OutPoint;
	let mut r = Running::start().await;
	let proxy = Proxy::start(&r.url());
	let c = Arca::new("P2claim");
	let (board, pid, forfeit_txid, atom_txid, preimage) = forfeit_left_unclaimed(&mut r, &proxy, &c).await;
	let (units, cvout, margin, unlock) = stored_status(&r, &pid);

	// The wallet takes its refund: sent, and nothing decided.
	let s = c.ok(&["sync"]);
	let f = s["forfeits"].as_array().unwrap().iter().find(|f| f["leaf_id"] == board.as_str()).cloned()
		.unwrap_or_else(|| panic!("the forfeit is followed: {}", s));
	println!("P2 the wallet's refund: {}", f);
	assert_eq!(f["state"], "refunding", "{}", f);
	let refund = elements::Txid::from_str(f["refund"]["txid"].as_str().unwrap()).unwrap();
	assert!(in_mempool(&r, &refund), "the refund is in the mempool");
	assert_eq!(coin_of(&c, &board)["state"], "forfeited", "a refund in the mempool decides nothing: {}", coin_of(&c, &board));

	// The operator's claim, paying more, replaces it, and confirms.
	let CoinRecord::Board(rec) = record_of(&c, &board) else { panic!("a board") };
	let board_txid = r.server.store.board(&rec.leaf_id().0).await.unwrap().map(|b| b.txid).expect("the board is registered");
	let board_tx = r.rt.client().raw_transaction(&elements::hashes::Hash::from_byte_array(board_txid)).unwrap();
	let mtp = rpc(&r, "getblockchaininfo", &[])["mediantime"].as_u64().unwrap() as u32;
	let old = CoinRecord::Board(rec).resolve(std::slice::from_ref(&board_tx), &arca_covenant::WalletPolicy {
		min_exit_delay: RelativeTime::from_units(1).unwrap(), horizon: 0,
		..arca_covenant::WalletPolicy::new(rec.chain, rec.operator, arca_covenant::MedianTime::from_consensus(mtp).unwrap())
	}).unwrap();
	let round_txid = r.server.store.round(r.server.store.participation(&unhex(&pid).try_into().unwrap()).await.unwrap().unwrap()
		.round_id.unwrap()).await.unwrap().unwrap().txid;
	let m = connector_asset(elements::hashes::Hash::from_byte_array(round_txid), cvout);
	let forfeit = Forfeit::new(old.leaf, (old.asset, old.value), old.id, unlock, m, RelativeTime::from_units(units).unwrap(), margin).unwrap();
	let fo = forfeit.output();
	let atx = r.rt.client().raw_transaction(&atom_txid).unwrap();
	let av = atx.output.iter().position(|o| o.asset.explicit() == Some(m)).unwrap() as u32;
	let m_out = atx.output[av as usize].clone();
	let ct = arca_covenant::batch_claim_tx(&[(&forfeit, OutPoint::new(forfeit_txid, 0))], (OutPoint::new(atom_txid, av), m_out.clone()),
		&[ExplicitOutput::new(fo.asset, fo.value - 40_000, common::node::op_true())], m_out.script_pubkey.clone(), &FeeSource::Reserve).unwrap();
	let genesis = r.rt.client().genesis_hash().unwrap();
	let sig = arca_covenant::sign::sign_digest(&common::running::keypair("operator"), &ct.sighash(0, genesis).unwrap(), &[0; 32]);
	let mut claim = ct.finish(&[sig], &[preimage]).unwrap().tx;
	operator_signs_input(&r, &mut claim, 1);
	r.rt.client().send_raw_transaction(&claim).expect("the claim replaces the refund");
	assert!(!in_mempool(&r, &refund), "the refund is out of the mempool");
	r.produce().await;
	let refund_seen = r.rt.client().call::<Value>("getrawtransaction", &[json!(refund.to_string()), json!(true)]).ok();
	assert!(confirmations(&r, &claim.txid()) >= 1 && refund_seen.is_none(), "the claim confirms, the refund is gone: {:?}", refund_seen);
	println!("P2 the operator's claim {} replaced the refund and confirmed", claim.txid());

	// The wallet reads the preimage from the claim at once, and holds the
	// new leaf; the forfeit is followed until the claim is final.
	let s = c.ok(&["sync"]);
	let f = s["forfeits"].as_array().unwrap().iter().find(|f| f["leaf_id"] == board.as_str()).cloned()
		.unwrap_or_else(|| panic!("the forfeit is followed: {}", s));
	println!("P2 the claim in a block, not yet final: {}", f);
	assert_eq!(f["state"], "claiming", "{}", f);
	let leaf = f["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	r.bury().await;
	let s = c.ok(&["sync"]);
	let f = s["forfeits"].as_array().unwrap().iter().find(|f| f["leaf_id"] == board.as_str()).cloned()
		.unwrap_or_else(|| panic!("the forfeit is followed until final: {}", s));
	println!("P2 the claim final: {}", f);
	assert_eq!(f["state"], "claimed", "{}", f);
	c.ok(&["sync"]);
	println!("P2 RESULT: the coin given up is {}, the new leaf {} is {}", coin_of(&c, &board)["state"], leaf, coin_of(&c, &leaf)["state"]);
	assert_eq!(coin_of(&c, &board)["state"], "spent", "the coin given up is the operator's: {}", coin_of(&c, &board));
	assert_eq!(coin_of(&c, &leaf)["state"], "live", "the new leaf is the wallet's: {}", coin_of(&c, &leaf));
	let _ = std::fs::remove_dir_all(&c.dir);
}

/// The other way the chain may decide: the operator never claims, the
/// wallet's refund confirms, and the coin is the wallet's on the chain
/// (`exited`) only once that refund is final.
#[tokio::test(flavor = "multi_thread")]
async fn a_refund_decides_the_coin_only_once_it_is_final() {
	let mut r = Running::start().await;
	let proxy = Proxy::start(&r.url());
	let c = Arca::new("P2refund");
	let (board, _, _, _, _) = forfeit_left_unclaimed(&mut r, &proxy, &c).await;
	let s = c.ok(&["sync"]);
	let f = s["forfeits"].as_array().unwrap().iter().find(|f| f["leaf_id"] == board.as_str()).cloned().unwrap();
	assert_eq!(f["state"], "refunding", "{}", f);
	let refund = elements::Txid::from_str(f["refund"]["txid"].as_str().unwrap()).unwrap();
	r.produce().await;
	assert!(confirmations(&r, &refund) >= 1);
	let s = c.ok(&["sync"]);
	let f = s["forfeits"].as_array().unwrap().iter().find(|f| f["leaf_id"] == board.as_str()).cloned().unwrap();
	println!("P2 the refund in a block, not yet final: {} (coin {})", f["state"], coin_of(&c, &board)["state"]);
	assert_eq!(f["state"], "refunding", "{}", f);
	assert_eq!(coin_of(&c, &board)["state"], "forfeited");
	r.bury().await;
	let s = c.ok(&["sync"]);
	let f = s["forfeits"].as_array().unwrap().iter().find(|f| f["leaf_id"] == board.as_str()).cloned().unwrap();
	println!("P2 the refund final: {} (coin {})", f["state"], coin_of(&c, &board)["state"]);
	assert_eq!(f["state"], "refunded", "{}", f);
	assert_eq!(coin_of(&c, &board)["state"], "exited");
	let _ = std::fs::remove_dir_all(&c.dir);
}

/// Review R7c's probe P3a turned around. The wallet's refund is final
/// (`refunded`, the coin `exited`); then the Bitcoin parent block the
/// refund's block is anchored to is orphaned, with every parent block above
/// it, and the node disconnects every Sequentia block anchored to them: a
/// rollback deeper than finality, which the chain must follow. The
/// operator's claim, carrying the preimage, confirms in the refund's place.
/// The wallet still follows the forfeit it had decided: the refund no longer
/// final makes it undecided again, the claim decides it, and the wallet
/// reads the preimage from the claim and holds its new leaf.
#[tokio::test(flavor = "multi_thread")]
async fn a_final_refund_orphaned_with_its_anchor_gives_way_to_the_claim_and_the_new_leaf() {
	use arca_covenant::spend::FeeSource;
	use arca_covenant::ExplicitOutput;
	use elements::OutPoint;
	let mut r = Running::start().await;
	let proxy = Proxy::start(&r.url());
	let c = Arca::new("FRO");
	let (board, pid, forfeit_txid, atom_txid, preimage) = forfeit_left_unclaimed(&mut r, &proxy, &c).await;
	let (units, cvout, margin, unlock) = stored_status(&r, &pid);
	let s = c.ok(&["sync"]);
	let f = s["forfeits"].as_array().unwrap().iter().find(|f| f["leaf_id"] == board.as_str()).cloned().unwrap();
	assert_eq!(f["state"], "refunding", "{}", f);
	let refund = elements::Txid::from_str(f["refund"]["txid"].as_str().unwrap()).unwrap();
	r.produce().await;
	let refund_block = block_of(&r, &refund.to_string());
	r.bury().await;
	let s = c.ok(&["sync"]);
	let f = s["forfeits"].as_array().unwrap().iter().find(|f| f["leaf_id"] == board.as_str()).cloned().unwrap();
	println!("F2 the refund final: {} (coin {})", f["state"], coin_of(&c, &board)["state"]);
	assert_eq!(f["state"], "refunded", "{}", f);
	assert_eq!(coin_of(&c, &board)["state"], "exited");
	// Still followed, and nothing changes while the refund is final.
	let s = c.ok(&["sync"]);
	assert!(!s["forfeits"].as_array().unwrap().iter().any(|f| f["leaf_id"] == board.as_str()), "{}", s);
	assert_eq!(coin_of(&c, &board)["state"], "exited");

	// The operator's claim, built as the watcher builds it.
	let CoinRecord::Board(rec) = record_of(&c, &board) else { panic!("a board") };
	let board_txid = r.server.store.board(&rec.leaf_id().0).await.unwrap().map(|b| b.txid).expect("the board is registered");
	let board_tx = r.rt.client().raw_transaction(&elements::hashes::Hash::from_byte_array(board_txid)).unwrap();
	let mtp = rpc(&r, "getblockchaininfo", &[])["mediantime"].as_u64().unwrap() as u32;
	let old = CoinRecord::Board(rec).resolve(std::slice::from_ref(&board_tx), &arca_covenant::WalletPolicy {
		min_exit_delay: RelativeTime::from_units(1).unwrap(), horizon: 0,
		..arca_covenant::WalletPolicy::new(rec.chain, rec.operator, arca_covenant::MedianTime::from_consensus(mtp).unwrap())
	}).unwrap();
	let round_txid = r.server.store.round(r.server.store.participation(&unhex(&pid).try_into().unwrap()).await.unwrap().unwrap()
		.round_id.unwrap()).await.unwrap().unwrap().txid;
	let m = connector_asset(elements::hashes::Hash::from_byte_array(round_txid), cvout);
	let forfeit = Forfeit::new(old.leaf, (old.asset, old.value), old.id, unlock, m, RelativeTime::from_units(units).unwrap(), margin).unwrap();
	let fo = forfeit.output();
	let atx = r.rt.client().raw_transaction(&atom_txid).unwrap();
	let av = atx.output.iter().position(|o| o.asset.explicit() == Some(m)).unwrap() as u32;
	let m_out = atx.output[av as usize].clone();
	let ct = arca_covenant::batch_claim_tx(&[(&forfeit, OutPoint::new(forfeit_txid, 0))], (OutPoint::new(atom_txid, av), m_out.clone()),
		&[ExplicitOutput::new(fo.asset, fo.value - 40_000, common::node::op_true())], m_out.script_pubkey.clone(), &FeeSource::Reserve).unwrap();
	let genesis = r.rt.client().genesis_hash().unwrap();
	let sig = arca_covenant::sign::sign_digest(&common::running::keypair("operator"), &ct.sighash(0, genesis).unwrap(), &[0; 32]);
	let mut claim = ct.finish(&[sig], &[preimage]).unwrap().tx;
	operator_signs_input(&r, &mut claim, 1);

	// Deeper than final, driven by the anchor.
	let hash: elements::BlockHash = refund_block.parse().unwrap();
	let anchor = sequentia_ext::BlockHeaderExt::bitcoin_anchor(&r.rt.client().block_header(&hash).unwrap()).height as u64;
	let orphaned = tokio::task::block_in_place(|| r.rt.orphan_parent_from(anchor)).unwrap();
	println!("F2 the refund's block {} is anchored to parent height {}; {} parent blocks orphaned; the refund's confirmations now {}",
		refund_block, anchor, orphaned.len(), confirmations(&r, &refund));
	assert!(confirmations(&r, &refund) < 1, "the rollback took the refund out of the chain");
	if in_mempool(&r, &refund) {
		// Back in the mempool: the operator's claim, paying more, replaces it.
		println!("F2 the refund is back in the mempool");
	}
	r.rt.client().send_raw_transaction(&claim).expect("the claim takes the forfeit's output");
	r.produce().await;
	assert!(confirmations(&r, &claim.txid()) >= 1, "the claim confirms");
	assert!(confirmations(&r, &refund) < 1, "the refund is not in the chain");
	let s = c.ok(&["sync"]);
	println!("F2 the wallet's sync after the claim took the place of its final refund: forfeits {}", s["forfeits"]);
	let forfeits = s["forfeits"].as_array().unwrap();
	assert!(forfeits.iter().any(|f| f["leaf_id"] == board.as_str() && f["was"] == "refunded" && f["state"] == "refunding"),
		"the forfeit is undecided again: {}", s["forfeits"]);
	let f = forfeits.iter().find(|f| f["leaf_id"] == board.as_str() && f["claim"].is_string()).cloned()
		.unwrap_or_else(|| panic!("the claim decides the forfeit again: {}", s["forfeits"]));
	assert_eq!(f["claim"], claim.txid().to_string());
	let leaf = f["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	r.bury().await;
	let s = c.ok(&["sync"]);
	println!("F2 the claim final: forfeits {}", s["forfeits"]);
	c.ok(&["sync"]);
	println!("F2 RESULT: the coin given up is {} ({}); the new leaf {} is {}", coin_of(&c, &board)["state"], coin_of(&c, &board)["note"],
		leaf, coin_of(&c, &leaf)["state"]);
	assert_eq!(coin_of(&c, &board)["state"], "spent", "the coin given up is the operator's: {}", coin_of(&c, &board));
	assert_eq!(coin_of(&c, &leaf)["state"], "live", "the new leaf is the wallet's: {}", coin_of(&c, &leaf));
	let _ = std::fs::remove_dir_all(&c.dir);
}

/// Review R7d's probe P1e turned around. The operator's claim of a forfeit is
/// final and the wallet has read the preimage from it, holding its new leaf.
/// A rollback then takes the claim's block out, and the node restarts with an
/// empty mempool before the operator sends the claim again; the refund delay
/// has long run. The wallet holds the preimage of the participation, and the
/// round can return, so the forfeit's output is the operator's claim to make:
/// it sends no refund, keeps its new leaf, and follows the output. The
/// claim, sent again, is taken, and decides the forfeit again.
#[tokio::test(flavor = "multi_thread")]
async fn a_claim_rolled_back_is_left_to_the_operator_by_a_wallet_holding_the_preimage() {
	use arca_covenant::spend::FeeSource;
	use arca_covenant::ExplicitOutput;
	use elements::OutPoint;
	let mut r = Running::start().await;
	let proxy = Proxy::start(&r.url());
	let c = Arca::new("P1e");
	let (board, pid, forfeit_txid, atom_txid, preimage) = forfeit_left_unclaimed(&mut r, &proxy, &c).await;
	let (units, cvout, margin, unlock) = stored_status(&r, &pid);
	// The operator's claim, built as the watcher builds it, final before the
	// wallet looks again.
	let CoinRecord::Board(rec) = record_of(&c, &board) else { panic!("a board") };
	let board_txid = r.server.store.board(&rec.leaf_id().0).await.unwrap().map(|b| b.txid).expect("the board is registered");
	let board_tx = r.rt.client().raw_transaction(&elements::hashes::Hash::from_byte_array(board_txid)).unwrap();
	let mtp = rpc(&r, "getblockchaininfo", &[])["mediantime"].as_u64().unwrap() as u32;
	let old = CoinRecord::Board(rec).resolve(std::slice::from_ref(&board_tx), &arca_covenant::WalletPolicy {
		min_exit_delay: RelativeTime::from_units(1).unwrap(), horizon: 0,
		..arca_covenant::WalletPolicy::new(rec.chain, rec.operator, arca_covenant::MedianTime::from_consensus(mtp).unwrap())
	}).unwrap();
	let round_txid = r.server.store.round(r.server.store.participation(&unhex(&pid).try_into().unwrap()).await.unwrap().unwrap()
		.round_id.unwrap()).await.unwrap().unwrap().txid;
	let m = connector_asset(elements::hashes::Hash::from_byte_array(round_txid), cvout);
	let forfeit = Forfeit::new(old.leaf, (old.asset, old.value), old.id, unlock, m, RelativeTime::from_units(units).unwrap(), margin).unwrap();
	let fo = forfeit.output();
	let atx = r.rt.client().raw_transaction(&atom_txid).unwrap();
	let av = atx.output.iter().position(|o| o.asset.explicit() == Some(m)).unwrap() as u32;
	let m_out = atx.output[av as usize].clone();
	let ct = arca_covenant::batch_claim_tx(&[(&forfeit, OutPoint::new(forfeit_txid, 0))], (OutPoint::new(atom_txid, av), m_out.clone()),
		&[ExplicitOutput::new(fo.asset, fo.value - 40_000, common::node::op_true())], m_out.script_pubkey.clone(), &FeeSource::Reserve).unwrap();
	let genesis = r.rt.client().genesis_hash().unwrap();
	let sig = arca_covenant::sign::sign_digest(&common::running::keypair("operator"), &ct.sighash(0, genesis).unwrap(), &[0; 32]);
	let mut claim = ct.finish(&[sig], &[preimage]).unwrap().tx;
	operator_signs_input(&r, &mut claim, 1);
	r.rt.client().send_raw_transaction(&claim).expect("the claim");
	r.produce().await;
	let claim_block = block_of(&r, &claim.txid().to_string());
	r.bury().await;
	r.bury().await;
	let mut leaf = String::new();
	for _ in 0..3 {
		let s = c.ok(&["sync"]);
		if let Some(l) = s["forfeits"].as_array().unwrap().iter().find_map(|f| f["new_leaves"][0]["leaf_id"].as_str()) {
			leaf = l.to_string();
		}
		r.bury().await;
	}
	c.ok(&["sync"]);
	let f = c.ok(&["coins"]);
	println!("P1e the claim final: new leaf {} {}, the coin given up {}", leaf, coin_of(&c, &leaf)["state"], coin_of(&c, &board)["state"]);
	assert_eq!(coin_of(&c, &leaf)["state"], "live", "{}", f);
	assert_eq!(coin_of(&c, &board)["state"], "spent");
	// The claim's block taken out; the node restarts at its own clock with
	// an empty mempool; the operator has not sent the claim again.
	rpc(&r, "invalidateblock", &[json!(claim_block)]);
	let tip = rpc(&r, "getbestblockhash", &[]);
	let tip_time = rpc(&r, "getblockheader", &[tip])["time"].as_u64().unwrap();
	let mock = format!("-mocktime={}", tip_time + 120);
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0", &mock])).unwrap();
	r.produce().await;
	println!("P1e the claim's block invalidated, the node restarted: the claim's confirmations {}, in the mempool {}; the forfeit's {}",
		confirmations(&r, &claim.txid()), in_mempool(&r, &claim.txid()), confirmations(&r, &forfeit_txid));
	assert!(confirmations(&r, &claim.txid()) <= 0 && !in_mempool(&r, &claim.txid()));
	assert!(confirmations(&r, &forfeit_txid) >= 1);
	for k in 0..2 {
		let s = c.ok(&["sync"]);
		println!("P1e the wallet's sync {} after the rollback: forfeits {}", k, s["forfeits"]);
		let sent = s["forfeits"].as_array().unwrap().iter().any(|f| f["refund"].is_object() || f["state"] == "refunding");
		assert!(!sent, "no refund while the wallet holds the preimage and the round can return: {}", s["forfeits"]);
		r.produce().await;
	}
	let pool: Vec<String> = serde_json::from_value(rpc(&r, "getrawmempool", &[])).unwrap();
	assert!(pool.is_empty(), "nothing of the wallet's in the mempool: {:?}", pool);
	assert_eq!(coin_of(&c, &leaf)["state"], "live");
	assert_eq!(coin_of(&c, &board)["state"], "spent");
	// The operator's claim, sent again, is taken; it decides the forfeit
	// again.
	r.rt.client().send_raw_transaction(&claim).expect("the claim, sent again, is taken");
	r.produce().await;
	r.bury().await;
	r.bury().await;
	let mut state = Value::Null;
	for _ in 0..3 {
		let s = c.ok(&["sync"]);
		if let Some(f) = s["forfeits"].as_array().unwrap().iter().find(|f| f["leaf_id"] == board.as_str()) {
			state = f["state"].clone();
		}
		r.bury().await;
	}
	println!("P1e the claim sent again: confirmations {}; the wallet's forfeit {}; the balance {}", confirmations(&r, &claim.txid()), state,
		c.ok(&["balance"])["arca"]);
	assert!(confirmations(&r, &claim.txid()) >= 1);
	assert_eq!(coin_of(&c, &leaf)["state"], "live");
	assert_eq!(coin_of(&c, &board)["state"], "spent");
	let _ = std::fs::remove_dir_all(&c.dir);
}

/// Review R7e, F6: the refund withheld while the wallet holds the preimage
/// has an end. The wallet reads the preimage of its new leaf from the
/// operator's claim; then the round's block is taken out, the node forgets
/// its mempool, and the operator is gone: the round is in no block and no
/// mempool, its inputs unspent, and only the forfeit, sent again by someone
/// who saw it, is on the chain. Returns the wallet, its board and new leaf,
/// the round and the forfeit.
async fn round_out_forfeit_on_chain(r: &mut Running, proxy: &Proxy, c: &Arca, tag: &str)
	-> (String, String, Transaction, elements::Txid)
{
	use arca_covenant::spend::FeeSource;
	use arca_covenant::ExplicitOutput;
	use elements::OutPoint;
	let (board, pid, forfeit_txid, atom_txid, preimage) = forfeit_left_unclaimed(r, proxy, c).await;
	let (units, cvout, margin, unlock) = stored_status(r, &pid);
	let CoinRecord::Board(rec) = record_of(c, &board) else { panic!("a board") };
	let board_txid = r.server.store.board(&rec.leaf_id().0).await.unwrap().map(|b| b.txid).expect("the board is registered");
	let board_tx = r.rt.client().raw_transaction(&elements::hashes::Hash::from_byte_array(board_txid)).unwrap();
	let mtp = rpc(r, "getblockchaininfo", &[])["mediantime"].as_u64().unwrap() as u32;
	let old = CoinRecord::Board(rec).resolve(std::slice::from_ref(&board_tx), &arca_covenant::WalletPolicy {
		min_exit_delay: RelativeTime::from_units(1).unwrap(), horizon: 0,
		..arca_covenant::WalletPolicy::new(rec.chain, rec.operator, arca_covenant::MedianTime::from_consensus(mtp).unwrap())
	}).unwrap();
	let round_txid: elements::Txid = elements::hashes::Hash::from_byte_array(r.server.store.round(r.server.store
		.participation(&unhex(&pid).try_into().unwrap()).await.unwrap().unwrap().round_id.unwrap()).await.unwrap().unwrap().txid);
	let round = r.rt.client().raw_transaction(&round_txid).unwrap();
	let m = connector_asset(round_txid, cvout);
	let forfeit = Forfeit::new(old.leaf, (old.asset, old.value), old.id, unlock, m, RelativeTime::from_units(units).unwrap(), margin).unwrap();
	let fo = forfeit.output();
	let atx = r.rt.client().raw_transaction(&atom_txid).unwrap();
	let av = atx.output.iter().position(|o| o.asset.explicit() == Some(m)).unwrap() as u32;
	let m_out = atx.output[av as usize].clone();
	let ct = arca_covenant::batch_claim_tx(&[(&forfeit, OutPoint::new(forfeit_txid, 0))], (OutPoint::new(atom_txid, av), m_out.clone()),
		&[ExplicitOutput::new(fo.asset, fo.value - 40_000, common::node::op_true())], m_out.script_pubkey.clone(), &FeeSource::Reserve).unwrap();
	let genesis = r.rt.client().genesis_hash().unwrap();
	let sig = arca_covenant::sign::sign_digest(&common::running::keypair("operator"), &ct.sighash(0, genesis).unwrap(), &[0; 32]);
	let mut claim = ct.finish(&[sig], &[preimage]).unwrap().tx;
	operator_signs_input(r, &mut claim, 1);
	r.rt.client().send_raw_transaction(&claim).expect("the claim");
	r.produce().await;
	r.bury().await;
	let mut leaf = String::new();
	for _ in 0..3 {
		let s = c.ok(&["sync"]);
		if let Some(l) = s["forfeits"].as_array().unwrap().iter().find_map(|f| f["new_leaves"][0]["leaf_id"].as_str()) {
			leaf = l.to_string();
		}
		r.bury().await;
	}
	c.ok(&["sync"]);
	assert_eq!(coin_of(c, &leaf)["state"], "live");
	let forfeit_tx = r.rt.client().raw_transaction(&forfeit_txid).unwrap();
	// The round's block taken out, and everything after it; the node
	// restarts at its own clock with an empty mempool; the forfeit, sent
	// again by someone who saw it, confirms without its round.
	let round_block = block_of(r, &round_txid.to_string());
	rpc(r, "invalidateblock", &[json!(round_block)]);
	let tip = rpc(r, "getbestblockhash", &[]);
	let tip_time = rpc(r, "getblockheader", &[tip])["time"].as_u64().unwrap();
	let mock = format!("-mocktime={}", tip_time + 120);
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0", &mock])).unwrap();
	r.rt.client().send_raw_transaction(&forfeit_tx).expect("the forfeit, without its round");
	r.produce().await;
	println!("{} the round {} in a block {} or the mempool {}; the forfeit {} confirmations {}; the claim {} confirmations {}", tag, round_txid,
		confirmations(r, &round_txid) >= 1, in_mempool(r, &round_txid), forfeit_txid, confirmations(r, &forfeit_txid), claim.txid(),
		confirmations(r, &claim.txid()));
	assert!(confirmations(r, &round_txid) <= 0 && !in_mempool(r, &round_txid));
	assert!(confirmations(r, &forfeit_txid) >= 1 && confirmations(r, &claim.txid()) <= 0);
	(board, leaf, round, forfeit_txid)
}

/// The round out of every block and mempool, its inputs unspent: the wallet
/// holding the preimage sends the round again from its own copy, which
/// confirms, and sends no refund.
#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_holding_the_preimage_sends_its_round_again_when_no_one_else_does() {
	let mut r = Running::start().await;
	let proxy = Proxy::start(&r.url());
	let c = Arca::new("F6a");
	let (board, leaf, round, _) = round_out_forfeit_on_chain(&mut r, &proxy, &c, "F6a").await;
	let s = c.ok(&["sync"]);
	println!("F6a the wallet's sync: forfeits {}", s["forfeits"]);
	let f = s["forfeits"].as_array().unwrap().iter().filter(|f| f["leaf_id"] == board.as_str()).last().cloned().unwrap();
	assert_eq!(f["round_sent"]["txid"], round.txid().to_string(), "{}", f);
	assert!(f["refund"].is_null() && f["state"] != "refunding", "no refund: {}", f);
	assert!(in_mempool(&r, &round.txid()));
	r.produce().await;
	r.bury().await;
	let s = c.ok(&["sync"]);
	println!("F6a the round sent again: confirmations {}; the leaf {}", confirmations(&r, &round.txid()), coin_of(&c, &leaf)["state"]);
	assert!(confirmations(&r, &round.txid()) >= 1);
	assert!(s["forfeits"].as_array().unwrap().iter().all(|f| f["state"] != "refunding" && f["refund"].is_null()), "{}", s["forfeits"]);
	assert_eq!(coin_of(&c, &leaf)["state"], "live");
	assert_eq!(coin_of(&c, &board)["state"], "spent");
	let _ = std::fs::remove_dir_all(&c.dir);
}

/// The same, the round the wallet sends again never confirming (the node
/// forgets it) and the wallet away until the new leaf's batch has expired:
/// no preimage opens anything then, and the wallet takes its coin back by
/// the forfeit's refund.
#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_holding_the_preimage_refunds_once_the_new_leafs_batch_has_expired() {
	let mut r = Running::start().await;
	let proxy = Proxy::start(&r.url());
	let c = Arca::new("F6b");
	let (board, leaf, round, _) = round_out_forfeit_on_chain(&mut r, &proxy, &c, "F6b").await;
	let s = c.ok(&["sync"]);
	let f = s["forfeits"].as_array().unwrap().iter().filter(|f| f["leaf_id"] == board.as_str()).last().cloned().unwrap();
	assert_eq!(f["round_sent"]["txid"], round.txid().to_string(), "{}", f);
	let tip = rpc(&r, "getbestblockhash", &[]);
	let tip_time = rpc(&r, "getblockheader", &[tip])["time"].as_u64().unwrap();
	let mock = format!("-mocktime={}", tip_time + 120);
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0", &mock])).unwrap();
	assert!(!in_mempool(&r, &round.txid()), "the node forgot the round the wallet sent");
	let CoinRecord::Leaf { record, .. } = record_of(&c, &leaf) else { panic!("a batch leaf") };
	let last = record.schedule.expiries().last().unwrap().to_consensus_u32();
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, last.saturating_sub(now) + 3_600));
	let s = c.ok(&["sync"]);
	println!("F6b past the new leaf's last expiry ({}), the wallet's sync: forfeits {}", last, s["forfeits"]);
	let f = s["forfeits"].as_array().unwrap().iter().filter(|f| f["leaf_id"] == board.as_str()).last().cloned().unwrap();
	assert_eq!(f["state"], "refunding", "{}", f);
	assert!(f["round_sent"].is_null(), "{}", f);
	assert!(!in_mempool(&r, &round.txid()));
	r.produce().await;
	r.bury().await;
	let s = c.ok(&["sync"]);
	let f = s["forfeits"].as_array().unwrap().iter().filter(|f| f["leaf_id"] == board.as_str()).last().cloned().unwrap();
	println!("F6b the refund: {}; the board {}", f, coin_of(&c, &board)["state"]);
	assert_eq!(f["state"], "refunded");
	assert_eq!(coin_of(&c, &board)["state"], "exited");
	let _ = std::fs::remove_dir_all(&c.dir);
}

// ---------------------------------------------------------------------------
// A board's dates
// ---------------------------------------------------------------------------

/// Review R7c's F3 turned around. A boards and pays B twice out of round,
/// keeping change that rests on two reassignments from its board. B
/// refreshes both coins, its round final and its forfeits handed over. A's
/// change is still live off chain: the watcher publishes nothing of the
/// shared lineage, and A's wallet finds nothing of it on the chain. Every
/// coin shows the board's dates, and B's wallet said so when it received
/// its coins. After the board's expiry the operator brings the lineage on the
/// chain and collects B's forfeited coins; A's change, on the chain with it,
/// is A's to exit, on a date both of them knew.
#[tokio::test(flavor = "multi_thread")]
async fn a_receivers_refresh_leaves_the_senders_change_live_until_the_boards_expiry() {
	use elements::hashes::Hash;
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let a = Arca::new("F3A");
	let b = Arca::new("F3B");
	let board = boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await.remove(0);
	b.ok(&create_args(&url, &r.node_url()));
	let mut received = vec![];
	for v in ["300000", "100000"] {
		let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
		a.ok(&["send", &req, "--amount", v, "--asset", &x.to_string()]);
		let m = b.ok(&["mailbox"]);
		let got = m["accepted"][0].clone();
		println!("F3 B receives {}: {}", v, got);
		received.push(got);
	}
	let change_id = a.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["state"] == "live" && c["kind"] == "transfer")
		.map(|c| c["leaf_id"].as_str().unwrap().to_string()).expect("A's change");
	// B refreshes everything it holds: the two coins from A.
	b.ok(&["participate"]);
	final_round(&r).await;
	let s = b.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s["participations"]);
	let given: Vec<String> = received.iter().map(|g| g["leaf_id"].as_str().unwrap().to_string()).collect();
	for _ in 0..4 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		r.produce().await;
	}
	r.bury().await;
	r.synced().await;
	r.server.watcher.pass().await.unwrap();
	let log = r.server.store.watcher_log().await.unwrap();
	println!("F3 the watcher's log after B's refresh: {:?}", log.iter().map(|w| (&w.kind, &w.detail)).collect::<Vec<_>>());
	assert!(!log.iter().any(|w| w.kind == "checkpoint" || w.kind == "reassignment"), "nothing of the shared lineage is published");
	let (ok, v, stderr) = a.run_full(&["sync"]);
	assert!(ok, "{}", v);
	println!("F3 A's sync after B's refresh: recheck {} exits {}", v["recheck"], v["exits"]);
	assert!(!stderr.contains("exiting") && v["recheck"]["changes"] == json!([]), "A's coin is not touched: {} {}", stderr, v);
	assert_eq!(coin_of(&a, &change_id)["state"], "live", "A's change is still live off chain");

	// The board's dates: those of a batch made when it confirmed.
	let CoinRecord::Board(rec) = record_of(&a, &board) else { panic!("a board") };
	let board_txid = elements::Txid::from_byte_array(r.server.store.board(&rec.leaf_id().0).await.unwrap().unwrap().txid);
	let confirmed = rpc(&r, "getblockheader", &[json!(block_of(&r, &board_txid.to_string()))])["mediantime"].as_u64().unwrap() as u32;
	let expiry = confirmed + 28 * 86_400;
	for got in &received {
		assert!(got["board"]["note"].as_str().unwrap_or("").contains("rests on a board"), "the wallet said so: {}", got);
		assert_eq!(got["board"]["expiry"], json!(expiry));
		assert_eq!(got["board"]["exit_deadline"], json!(expiry - 3 * 86_400));
	}
	let change = coin_of(&a, &change_id);
	println!("F3 A's change: {}", change);
	assert_eq!(change["rests_on_board"], true);
	assert_eq!(change["expiry"], json!(expiry), "the change carries the board's dates");
	assert_eq!(change["exit_deadline"], json!(expiry - 3 * 86_400));

	// The board's expiry passes: the operator collects B's forfeited coins,
	// bringing the lineage on the chain, and A's change with it.
	let now = rpc(&r, "getblockchaininfo", &[])["mediantime"].as_u64().unwrap() as u32;
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, expiry - now + 3_600));
	r.bury().await;
	r.synced().await;
	// Each of B's coins forfeited on the chain, and that forfeit claimed.
	let claimed = |r: &Running| {
		let log = tokio::runtime::Handle::current().block_on(r.server.store.watcher_log()).unwrap();
		let claims: Vec<Transaction> = log.iter().filter(|w| w.kind == "claim").map(|w| elements::encode::deserialize(&w.tx).unwrap()).collect();
		given.iter().all(|l| log.iter().filter(|w| w.kind == "forfeit" && w.subject == l.parse::<LeafId>().unwrap().0.to_vec())
			.any(|f| claims.iter().any(|c| c.input.iter().any(|i| i.previous_output.txid.to_byte_array() == f.txid))))
	};
	for _ in 0..12 {
		if tokio::task::block_in_place(|| claimed(&r)) {
			break;
		}
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		r.produce().await;
	}
	let log = r.server.store.watcher_log().await.unwrap();
	for w in &log {
		println!("F3 watcher: {} {}", w.kind, w.detail);
	}
	assert!(tokio::task::block_in_place(|| claimed(&r)), "the operator claimed B's two forfeited coins");
	let first = log.iter().find(|w| w.kind == "checkpoint").expect("the board's checkpoint");
	let at = rpc(&r, "getblockheader", &[json!(block_of(&r, &elements::Txid::from_byte_array(first.txid).to_string()))])["mediantime"]
		.as_u64().unwrap() as u32;
	println!("F3 the lineage reached the chain in a block of median time {}; the board's expiry {}", at, expiry);
	assert!(at >= expiry, "not before the board's expiry");
	let s = a.ok(&["sync"]);
	println!("F3 A's sync once the lineage is on the chain: recheck {}", s["recheck"]);
	assert_eq!(coin_of(&a, &change_id)["state"], "exiting", "A's change is on the chain, A's to exit: {}", coin_of(&a, &change_id));
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// The signer's record, witnessed by the wallet
// ---------------------------------------------------------------------------

/// D48 and D49. Every `info` and every published tree carries the signer's
/// record's latest entry and running hash, signed by the signer, and the
/// wallet keeps each one it is shown. A pays B, and B refreshes the coin: the
/// round's published tree carries the record's head when the round was
/// built. A head whose hash an operator altered no longer carries the
/// signer's signature, and is refused. Then the operator's database and
/// record are copied (a backup), A pays B again, which A's wallet sees as a
/// later entry; both are rolled back to the copy, and the server starts on
/// them, since the database knows nothing the record lacks and the chain
/// shows nothing new of the operator's. A's next command witnesses the
/// record: it ends below a head A holds, signed, which stops the signer; A
/// takes its change of the second payment on the chain and refuses to go
/// on, saying why.
#[tokio::test(flavor = "multi_thread")]
async fn a_record_and_database_rolled_back_together_are_refused_by_a_wallet_that_saw_them() {
	use server::server::Server;
	let mut r = Running::start().await;
	let addr = r.server.addr;
	let x = r.x;
	let proxy = Proxy::start(&r.url());
	let a = Arca::new("D48A");
	let b = Arca::new("D48B");
	boarded(&mut r, &a, &proxy.url.clone(), &[(x, 4_000_000)]).await;
	b.ok(&create_args(&r.url(), &r.node_url()));
	let first = a.ok(&["info"])["server_info"]["signer_record"].clone();
	println!("D48 the operator's record at first: {}", first);
	assert_eq!(first["entry"], 0);

	// A pays B (entries 1 and 2), and B refreshes the coin: the round's tree
	// carries the record's head when it was built.
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req, "--amount", "600000", "--asset", &x.to_string()]);
	b.ok(&["mailbox"]);
	b.ok(&["participate"]);
	let round = final_round(&r).await;
	assert_eq!(b.ok(&["sync"])["participations"][0]["state"], "released");
	let tree: Value = serde_json::from_str(minreq::post(format!("{}/v1/tree", r.url())).with_header("Content-Type", "application/json")
		.with_body(json!({"txid": round.txid().to_string(), "vout": 0}).to_string()).send().unwrap().as_str().unwrap()).unwrap();
	println!("D48 the round's published tree carries the record at {}", tree["signer_record"]);
	assert_eq!(tree["signer_record"]["entry"], 2, "the latest entry when the round was built");
	assert!(tree["signer_record"]["signature"].is_string(), "signed");

	// A head whose hash is altered no longer carries the signer's signature.
	let c2 = Arca::new("D48C");
	c2.ok(&create_args(&proxy.url, &r.node_url()));
	c2.ok(&["info"]);
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/info" && status == 200 {
			v["signer_record"]["hash"] = json!("ab".repeat(32));
		}
		None
	})));
	let shown = c2.ok(&["info"]);
	println!("D48 a head with an altered hash: {}", shown["server_info"]);
	assert!(shown["server_info"]["unreachable"].as_str().unwrap_or("").contains("a signature that is not its signer's"), "{}", shown);
	proxy.rewrite(None);

	// The operator's backup: server and signer stopped, database and record
	// copied.
	let (admin_url, db) = {
		let url = std::env::var("ARCA_TEST_POSTGRES").unwrap();
		let db = r.config.database.rsplit_once('/').unwrap().1.to_string();
		(url, db)
	};
	let (admin, conn) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(conn);
	let disconnect = |name: String| {
		let admin = &admin;
		async move {
			admin.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()", &[&name])
				.await.unwrap();
		}
	};
	let genesis = r.rt.client().genesis_hash().unwrap();
	let config = |r: &Running| {
		let mut c = r.config.clone();
		c.listen = addr.to_string();
		c
	};
	r.server.stop();
	r.signer.halt();
	tokio::time::sleep(std::time::Duration::from_millis(300)).await;
	disconnect(db.clone()).await;
	admin.batch_execute(&format!("CREATE DATABASE {}_backup TEMPLATE {}", db, db)).await.unwrap();
	let record_backup = std::fs::read(r.signer.record()).unwrap();
	let backed_up = String::from_utf8_lossy(&record_backup).lines().count() - 1;
	r.signer.resume(genesis);
	r.server = Server::start(&config(&r)).await.unwrap();
	r.synced().await;

	// A pays B again, which A's wallet is shown.
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req, "--amount", "300000", "--asset", &x.to_string()]);
	let seen = a.ok(&["info"])["server_info"]["signer_record"].clone();
	println!("D48 the backup holds {} entries; A's wallet after its second payment is shown the record at {}", backed_up, seen);
	assert_eq!(seen["entry"].as_u64(), Some(backed_up as u64 + 2));

	// Both rolled back to the copy; the server starts on them.
	r.server.stop();
	r.signer.halt();
	tokio::time::sleep(std::time::Duration::from_millis(300)).await;
	disconnect(db.clone()).await;
	admin.batch_execute(&format!("DROP DATABASE {}", db)).await.unwrap();
	disconnect(format!("{}_backup", db)).await;
	admin.batch_execute(&format!("CREATE DATABASE {} TEMPLATE {}_backup", db, db)).await.unwrap();
	admin.batch_execute(&format!("DROP DATABASE {}_backup", db)).await.unwrap();
	std::fs::write(r.signer.record(), &record_backup).unwrap();
	r.signer.resume(genesis);
	r.server = Server::start(&config(&r)).await.expect("the server starts on a database and record rolled back together");
	r.synced().await;
	let info: Value = serde_json::from_str(minreq::get(format!("{}/v1/info", r.url())).send().unwrap().as_str().unwrap()).unwrap();
	println!("D48 database and record rolled back together; the server started on them, its record at {}", info["signer_record"]);
	assert_eq!(info["signer_record"]["entry"].as_u64(), Some(backed_up as u64));

	// A's next command witnesses the record and refuses to go on, with the
	// reason; the signer is stopped.
	let why = a.refused(&["send", &req, "--amount", "100000", "--asset", &x.to_string()], "rolled back");
	println!("D48 A's wallet: {}", why);
	assert!(why.contains(&format!("past entry {}", backed_up))
		&& why.contains(&format!("the signer's record ends at entry {}, signed with the wallet's nonce", backed_up)), "{}", why);
	let info = a.ok(&["info"]);
	assert!(info["server_info"]["unreachable"].as_str().unwrap_or("").contains("rolled back"), "{}", info);
	assert!(a.ok(&["refusals"]).as_array().unwrap().iter().any(|f| f["what"] == "the operator's signer's record"));
	assert!(server::signer::stopped_path(&r.signer.record()).exists(), "the signer is stopped");
	for w in [&a, &b, &c2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// The operator's database and signer's record, copied with the server and
/// signer stopped, as a snapshot of the box takes them, and put back
/// together; the server keeps its address, so wallets keep their URL.
struct Backup {
	admin: tokio_postgres::Client,
	db: String,
	record: Vec<u8>,
	addr: std::net::SocketAddr,
	/// How many entries the copied record holds.
	entries: u64,
}

impl Backup {
	async fn disconnect(&self, name: &str) {
		self.admin.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()", &[&name])
			.await.unwrap();
	}

	async fn take(r: &mut Running) -> Backup {
		let url = std::env::var("ARCA_TEST_POSTGRES").unwrap();
		let db = r.config.database.rsplit_once('/').unwrap().1.to_string();
		let (admin, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await.unwrap();
		tokio::spawn(conn);
		let addr = r.server.addr;
		r.server.stop();
		r.signer.halt();
		tokio::time::sleep(std::time::Duration::from_millis(300)).await;
		let record = std::fs::read(r.signer.record()).unwrap();
		let entries = String::from_utf8_lossy(&record).lines().count() as u64 - 1;
		let b = Backup { admin, db, record, addr, entries };
		b.disconnect(&b.db).await;
		b.admin.batch_execute(&format!("CREATE DATABASE {}_backup TEMPLATE {}", b.db, b.db)).await.unwrap();
		b.start(r).await;
		b
	}

	async fn start(&self, r: &mut Running) {
		let genesis = r.rt.client().genesis_hash().unwrap();
		r.signer.resume(genesis);
		let mut c = r.config.clone();
		c.listen = self.addr.to_string();
		r.server = server::server::Server::start(&c).await.expect("the server starts");
		r.synced().await;
	}

	/// Database and record rolled back together to the copy; the server
	/// starts on them.
	async fn restore(&self, r: &mut Running) {
		self.restore_files(r).await;
		self.start(r).await;
	}

	/// Server and signer stopped, database and record rolled back together
	/// to the copy; nothing started.
	async fn restore_files(&self, r: &mut Running) {
		r.server.stop();
		r.signer.halt();
		tokio::time::sleep(std::time::Duration::from_millis(300)).await;
		self.disconnect(&self.db).await;
		self.admin.batch_execute(&format!("DROP DATABASE {}", self.db)).await.unwrap();
		self.disconnect(&format!("{}_backup", self.db)).await;
		self.admin.batch_execute(&format!("CREATE DATABASE {} TEMPLATE {}_backup", self.db, self.db)).await.unwrap();
		std::fs::write(r.signer.record(), &self.record).unwrap();
	}
}

/// A copy of wallet `w`'s directory, as a user restores a wallet from an
/// older backup of it.
fn copy_wallet(w: &Arca, name: &str) -> Arca {
	let c = Arca::new(name);
	std::fs::create_dir_all(&c.dir).unwrap();
	for e in std::fs::read_dir(&w.dir).unwrap() {
		let e = e.unwrap();
		if e.file_type().unwrap().is_file() {
			std::fs::copy(e.path(), c.dir.join(e.file_name())).unwrap();
		}
	}
	c
}

fn info_of(r: &Running) -> Value {
	serde_json::from_str(minreq::get(format!("{}/v1/info", r.url())).send().unwrap().as_str().unwrap()).unwrap()
}

/// What A, B and M hold before the operator's snapshot is restored: A, with
/// boards of 4,000,000 and 1,000,000, paid B 600,000 (P1) from the first
/// and, after the snapshot, 300,000 more from its change C_A (P2); B only
/// syncs, and A's older wallet copy, taken at the snapshot, still holds C_A
/// and the second board as its own.
struct JointRollback {
	r: Running,
	/// A receive request of M's, made before the snapshot.
	m_req: String,
	/// A, and its older copy, reach the server through it.
	proxy: Proxy,
	a: Arca,
	a_old: Arca,
	b: Arca,
	m: Arca,
	p1: String,
	p2: String,
	c_a: String,
	backup: Backup,
	head_at_backup: Value,
}

async fn joint_rollback(tag: &str) -> JointRollback {
	joint_rollback_kept(tag, 0).await
}

/// [`joint_rollback`], the operator's signer handing every head to
/// `keepers` keepers of its own, on other machines: the snapshot restores
/// the signer's record and the database, not the keepers.
async fn joint_rollback_kept(tag: &str, keepers: usize) -> JointRollback {
	let mut r = Running::start_kept(keepers, None).await;
	let url = r.url();
	let x = r.x;
	let proxy = Proxy::start(&url);
	let (a, b, m) = (Arca::new(&format!("{}A", tag)), Arca::new(&format!("{}B", tag)), Arca::new(&format!("{}M", tag)));
	boarded(&mut r, &a, &proxy.url.clone(), &[(x, 4_000_000), (x, 1_000_000)]).await;
	b.ok(&create_args(&url, &r.node_url()));
	m.ok(&create_args(&url, &r.node_url()));
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req, "--amount", "600000", "--asset", &x.to_string()]);
	let p1 = b.ok(&["sync"])["mailbox"]["accepted"][0]["leaf_id"].as_str().unwrap().to_string();
	// M's request, made before the snapshot: M holds no later head.
	let m_req = m.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let backup = Backup::take(&mut r).await;
	let head_at_backup = info_of(&r)["signer_record"].clone();
	println!("{} the operator's snapshot: {} entries, its head {}", tag, backup.entries, head_at_backup);
	let a_old = copy_wallet(&a, &format!("{}Aold", tag));
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let paid = a.ok(&["send", &req, "--amount", "300000", "--asset", &x.to_string()]);
	let c_a = paid["inputs"][0].as_str().unwrap().to_string();
	let got = b.ok(&["sync"]);
	let p2 = got["mailbox"]["accepted"][0]["leaf_id"].as_str().unwrap().to_string();
	println!("{} A paid B 300000 from C_A {} after the snapshot: B's P2 {}; the record at {}", tag, c_a, p2, info_of(&r)["signer_record"]);
	backup.restore(&mut r).await;
	println!("{} database and record rolled back together; the server started on them, its record at {}", tag, info_of(&r)["signer_record"]);
	if keepers == 0 {
		assert_eq!(info_of(&r)["signer_record"]["entry"].as_u64(), Some(backup.entries));
	}
	JointRollback { r, m_req, proxy, a, a_old, b, m, p1, p2, c_a, backup, head_at_backup }
}

/// R7d's W1 turned around (D49). A receiver that only syncs witnesses the
/// operator's signer's record on every contact: after the operator's
/// database and record are rolled back together, B's next `sync` hands back
/// the signed head of P2's transfer, which the record lost. The signer
/// stops, B finds the record agrees with it up to the snapshot and takes
/// P2, which rests on a transfer recorded after it, on the chain at once.
/// Every other wallet that witnesses learns the signer is stopped, and goes
/// no further with the operator. The older copy of A's wallet, shown the
/// record as it was by a proxy, finds C_A's lineage on the chain (P2's
/// exit), and pays from its other coin: the stopped signer refuses it. B's
/// P2 is on the chain.
#[tokio::test(flavor = "multi_thread")]
async fn a_joint_rollback_is_caught_by_a_receiver_that_only_syncs_and_stops_the_signer() {
	let JointRollback { mut r, proxy, a, a_old, b, m, p1, p2, c_a, backup, head_at_backup, .. } = joint_rollback("W1").await;
	let x = r.x;
	let m_req = m.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let s = b.ok(&["sync"]);
	println!("W1 B's sync after the rollback: witness {}", s["witness"]);
	assert_eq!(s["witness"]["rolled_back"]["at"].as_u64(), Some(backup.entries), "{}", s["witness"]);
	let exits = s["witness"]["exits"].as_array().unwrap();
	assert!(exits.iter().any(|e| e["leaf_id"] == p2.as_str() && e["exit"]["state"].is_string()), "P2 goes on the chain: {:?}", exits);
	assert!(!exits.iter().any(|e| e["leaf_id"] == p1.as_str()), "P1 rests on what the record still holds: {:?}", exits);
	assert_eq!(coin_of(&b, &p2)["state"], "exiting");
	// P1 rests on the transfer that made C_A too: P2's unroll brings its
	// leaf on the chain, where the re-check takes it into its exit.
	println!("W1 B's P1: {} | {}", coin_of(&b, &p1)["state"], coin_of(&b, &p1)["note"]);
	assert!(matches!(coin_of(&b, &p1)["state"].as_str(), Some("live" | "exiting")));
	let w = info_of(&r);
	println!("W1 the operator's info after B's sync: signer_record {}", w["signer_record"]);
	assert!(w["signer_record"].is_null(), "a stopped signer hands out no signed head");
	let stopped = std::fs::read_to_string(server::signer::stopped_path(&r.signer.record())).expect("the proof beside the record");
	println!("W1 the signer's proof: {}", stopped.lines().next().unwrap());
	assert!(stopped.contains("past the record's end"), "{}", stopped);
	// B goes no further with the operator.
	let why = b.refused(&["receive"], "rolled back");
	println!("W1 B after: {}", why);

	// The older copy of A's wallet spends C_A again, to M, through a proxy
	// that shows it the record as it was at the snapshot: the stopped signer
	// refuses the second spend.
	let head = head_at_backup.clone();
	proxy.rewrite(Some(Arc::new(move |path: &str, req: &Value, _: u16, v: &mut Value| {
		match path {
			"/v1/info" => v["signer_record"] = head.clone(),
			"/v1/witness" => {
				*v = json!({"head": head.clone(), "stopped": null, "hashes": req["heads"].as_array().unwrap().iter()
					.map(|h| json!({"entry": h["entry"], "hash": h["hash"]})).collect::<Vec<_>>()});
				return Some(200);
			},
			_ => {},
		}
		None
	})));
	let (ok, v) = a_old.run(&["send", &m_req, "--amount", "300000", "--asset", &x.to_string()]);
	println!("W1 A's older copy pays M, shown a witness answer the signer did not make: ok={} {}", ok, v);
	println!("W1 C_A in A's older copy: {} | {}", coin_of(&a_old, &c_a)["state"], coin_of(&a_old, &c_a)["note"]);
	assert_ne!(coin_of(&a_old, &c_a)["state"], "live", "C_A's lineage is on the chain: no off-chain spend of it");
	assert!(!ok);
	assert!(v["error"]["message"].as_str().unwrap().contains("carries no proof the signer made"),
		"without the signer's own witness the wallet signs nothing: {}", v);
	// Shown the signer's own answer, it learns of the stop on the signer's
	// proof, and goes no further with the operator.
	proxy.rewrite(None);
	let (ok, v) = a_old.run(&["send", &m_req, "--amount", "300000", "--asset", &x.to_string()]);
	println!("W1 A's older copy pays M, shown the signer's own witness: ok={} {}", ok, v);
	assert!(!ok);
	assert!(v["error"]["message"].as_str().unwrap().contains("the operator's signer is stopped on its own proof"), "{}", v);
	let id: LeafId = c_a.parse().unwrap();
	println!("W1 C_A at the server: {:?}", r.server.store.leaf(&id.0).await.unwrap().map(|l| l.state));

	// P2 on the chain.
	r.produce().await;
	let s = b.ok(&["sync"]);
	println!("W1 B's exits: {}", s["exits"]);
	let e = b.ok(&["exit", &p2]);
	println!("W1 B's P2 now: {} | {}", e["state"], coin_of(&b, &p2)["note"]);
	assert!(matches!(e["state"].as_str(), Some("waiting" | "claimed")), "P2's leaf is on the chain: {}", e);
	let _ = (&a, &mut r);
	for w in [&a, &a_old, &b, &m] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// R7d's W2 turned around (D49). After the joint rollback, and before any
/// wallet witnesses the record, the older copy of A's wallet spends C_A
/// again, to M: the rolled-back record co-signs it, and another payment
/// takes the record past every entry B holds, so a count no longer shows
/// the rollback. B's next `sync` asks for the hash at its own highest
/// entry, finds another one, stops the signer, and takes P2 on the chain at
/// once; M's exit of the coin of the second spend then cannot take C_A.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_spend_before_any_witness_is_answered_by_the_receivers_next_sync() {
	let JointRollback { mut r, a, a_old, b, m, p1, p2, c_a, backup, .. } = joint_rollback("W2").await;
	let x = r.x;
	let url = r.url();
	let m_req = m.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let paid = a_old.ok(&["send", &m_req, "--amount", "300000", "--asset", &x.to_string()]);
	println!("W2 A's older copy spends C_A {} again, to M: inputs {}", c_a, paid["inputs"]);
	assert_eq!(paid["inputs"][0].as_str(), Some(c_a.as_str()));
	let got_m = m.ok(&["sync"])["mailbox"]["accepted"][0]["leaf_id"].as_str().unwrap().to_string();
	// Another payment: the record goes past every entry B holds.
	let d = Arca::new("W2D");
	d.ok(&create_args(&url, &r.node_url()));
	let req_d = d.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a_old.ok(&["send", &req_d, "--amount", "100000", "--asset", &x.to_string()]);
	let now = info_of(&r)["signer_record"]["entry"].as_u64().unwrap();
	println!("W2 the record now at entry {} (the snapshot held {}; B's highest is past it)", now, backup.entries);
	assert!(now >= backup.entries + 4);
	let s = b.ok(&["sync"]);
	println!("W2 B's sync: witness {}", s["witness"]);
	assert_eq!(s["witness"]["rolled_back"]["at"].as_u64(), Some(backup.entries), "{}", s["witness"]);
	let exits = s["witness"]["exits"].as_array().unwrap();
	let p2_exit = exits.iter().find(|e| e["leaf_id"] == p2.as_str()).unwrap_or_else(|| panic!("P2 goes on the chain: {:?}", exits));
	println!("W2 P2's exit: {}", p2_exit);
	assert!(!exits.iter().any(|e| e["leaf_id"] == p1.as_str()));
	assert!(std::fs::read_to_string(server::signer::stopped_path(&r.signer.record())).unwrap().contains("is not the record's"));
	r.produce().await;
	// M's exit of the coin of the second spend.
	let (ok, v) = m.run(&["exit", &got_m]);
	println!("W2 M's exit of its coin: ok={} {}", ok, v);
	r.produce().await;
	b.ok(&["sync"]);
	let e = b.ok(&["exit", &p2]);
	println!("W2 B's P2 after M's attempt: {} | {}", e["state"], coin_of(&b, &p2)["note"]);
	assert!(matches!(e["state"].as_str(), Some("waiting" | "claimed")), "P2's leaf is on the chain: {}", e);
	let (ok, v) = m.run(&["exit", &got_m]);
	println!("W2 M's exit again: ok={} {}", ok, v);
	assert!(!(ok && v["state"] == "waiting"), "the second spend's coin does not reach the chain: {}", v);
	assert!(v["error"]["message"].as_str().unwrap_or("").contains(&format!("co-signed another spend of coin {}", c_a)),
		"the refusal names the coin paid twice: {}", v);
	let _ = (&a, &mut r);
	for w in [&a, &a_old, &b, &m, &d] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// R7e F4 turned around (D54). Whoever answers a wallet's witness call (a
/// TLS-terminating proxy, a compromised `arcad`) rewrites the answer for one
/// wallet, while nobody rolled anything back: another running hash at the
/// wallet's highest entry; an older head the signer really signed, as the
/// latest and as the record's end; a whole earlier answer replayed; a stop
/// without proof, and with a "proof" the record holds; and an older signed
/// head in `info`. None of them is the signer's proof, so each is an
/// unreachable server: the wallet exits nothing and refuses nothing for
/// good, takes no coin from its mailbox while the answers lie, and goes on
/// as before once they are honest. The signer is never stopped.
#[tokio::test(flavor = "multi_thread")]
async fn a_rewritten_witness_is_an_unreachable_server_and_takes_nothing() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let pb = Proxy::start(&url);
	let (a, b) = (Arca::new("D54A"), Arca::new("D54B"));
	boarded(&mut r, &a, &url, &[(x, 4_000_000)]).await;
	b.ok(&create_args(&pb.url, &r.node_url()));
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req, "--amount", "600000", "--asset", &x.to_string()]);
	let p1 = b.ok(&["sync"])["mailbox"]["accepted"][0]["leaf_id"].as_str().unwrap().to_string();
	let old_head = info_of(&r)["signer_record"].clone();
	println!("D54 a head the signer signed, kept by anyone who read info: {}", old_head);
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req, "--amount", "500000", "--asset", &x.to_string()]);
	let p2 = b.ok(&["sync"])["mailbox"]["accepted"][0]["leaf_id"].as_str().unwrap().to_string();
	let honest = pb.last("/v1/witness").expect("B witnessed").2;
	println!("D54 B's last honest witness answer: end {} | head {}", honest["end"], honest["head"]["entry"]);
	assert!(honest["end"]["signature"].is_string(), "the record's end, signed with B's nonce: {}", honest);
	let paid = a.ok(&["receive"])["request"].as_str().unwrap().to_string();
	// A coin waits in B's mailbox while the answers lie.
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req, "--amount", "100000", "--asset", &x.to_string()]);
	let _ = paid;

	type Lie = Arc<dyn Fn(&mut Value) + Send + Sync>;
	let flip = |s: &str| if s.starts_with('0') { format!("1{}", &s[1..]) } else { format!("0{}", &s[1..]) };
	let old = old_head.clone();
	let old2 = old_head.clone();
	let replay = honest.clone();
	let held = honest["head"].clone();
	let lies: Vec<(&str, Lie)> = vec![
		("one running hash rewritten", Arc::new(move |v: &mut Value| {
			let h = v["hashes"][0]["hash"].as_str().unwrap_or("").to_string();
			v["hashes"][0]["hash"] = json!(flip(&h));
		})),
		("an older signed head as the latest", Arc::new(move |v: &mut Value| v["head"] = old.clone())),
		("an older signed head as the latest and as the end", Arc::new(move |v: &mut Value| {
			v["head"] = old2.clone();
			v["end"] = old2.clone();
		})),
		("a whole earlier answer replayed", Arc::new(move |v: &mut Value| *v = replay.clone())),
		("a stop without proof", Arc::new(|v: &mut Value| v["stopped"] = json!("stopped: the signer's record was rolled back"))),
		("a stop on a head the record holds", Arc::new(move |v: &mut Value| {
			v["stopped"] = json!("stopped: the signer's record was rolled back or replaced");
			v["proof"] = json!({"head": held.clone(), "held": held.clone()});
		})),
	];
	std::thread::sleep(std::time::Duration::from_secs(11));
	for (what, lie) in lies {
		let lie2 = lie.clone();
		pb.rewrite(Some(Arc::new(move |path: &str, _: &Value, _: u16, v: &mut Value| {
			if path == "/v1/witness" {
				lie2(v);
			}
			None
		})));
		let s = b.ok(&["sync"]);
		println!("D54 {}: B's sync: witness {} | mailbox {}", what, s["witness"], s["mailbox"]);
		assert!(s["witness"]["rolled_back"].is_null(), "{}: no rollback without the signer's proof: {}", what, s["witness"]);
		assert!(s["witness"]["error"].as_str().unwrap_or("").contains("carries no proof the signer made"), "{}: {}", what, s["witness"]);
		assert!(s["mailbox"]["accepted"].as_array().is_none_or(|a| a.is_empty()), "{}: no coin taken while the answers lie: {}", what,
			s["mailbox"]);
		for p in [&p1, &p2] {
			assert_eq!(coin_of(&b, p)["state"], "live", "{}: nothing exited", what);
		}
	}
	// An older signed head in `info`.
	let old = old_head.clone();
	pb.rewrite(Some(Arc::new(move |path: &str, _: &Value, _: u16, v: &mut Value| {
		if path == "/v1/info" {
			v["signer_record"] = old.clone();
		}
		None
	})));
	let shown = b.ok(&["info"]);
	println!("D54 an older signed head in info: {}", shown["server_info"]);
	assert!(shown["server_info"]["unreachable"].as_str().unwrap_or("").contains("proves no rollback"), "{}", shown);
	pb.rewrite(None);

	// Honest again: nothing was refused for good.
	assert!(!server::signer::stopped_path(&r.signer.record()).exists(), "the signer was never stopped");
	let s = b.ok(&["sync"]);
	println!("D54 B honest again: witness {} | mailbox {}", s["witness"], s["mailbox"]["accepted"]);
	assert!(s["witness"]["witnessed"].is_number(), "{}", s["witness"]);
	assert_eq!(s["mailbox"]["accepted"].as_array().map(|a| a.len()), Some(1), "the coin that waited is taken now");
	b.ok(&["receive"]);
	for p in [&p1, &p2] {
		assert_eq!(coin_of(&b, p)["state"], "live");
	}
	assert!(!b.ok(&["refusals"]).as_array().unwrap().iter().any(|f| f["reason"].as_str().unwrap_or("").contains("goes no further")));
	// D52.3: an operator with no keeper, said in `info` and on every coin
	// received out of round.
	let i = b.ok(&["info"]);
	println!("D54 B's info on an operator with no keeper: {}", i["keepers"]);
	assert!(i["keepers"]["note"].as_str().unwrap_or("").contains("rests on the operator's machine alone"));
	assert!(coin_of(&b, &p1)["record_held"].as_str().unwrap_or("").contains("rests on the operator's machine alone"), "{}", coin_of(&b, &p1));
	r.produce().await;
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// R7e F6 turned around. A wallet whose witness of the operator's signer's
/// record fails (the server denies it, here with a 503 on the way) takes no
/// coin and signs no spend through the operator until one succeeds: the
/// library witnesses inside every entry point, whatever its caller did
/// first. `send`, `board`, `participate` and a swap's offer are refused
/// before anything is signed, the mailbox is not read, and `sync` does only
/// what it does on the chain. Once the witness answers again, all of it
/// goes on: the coin that waited in the mailbox is taken, and the payment
/// goes through.
#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_whose_witness_fails_takes_no_coin_and_signs_no_spend() {
	let mut r = Running::start().await;
	let url = r.url();
	let (x, y) = (r.x, r.y);
	let pb = Proxy::start(&url);
	let (a, b) = (Arca::new("F6A"), Arca::new("F6B"));
	boarded(&mut r, &a, &url, &[(x, 4_000_000)]).await;
	let board = boarded(&mut r, &b, &pb.url.clone(), &[(x, 2_000_000)]).await.remove(0);
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req, "--amount", "300000", "--asset", &x.to_string()]);
	let to_a = a.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let onchain_before = b.ok(&["balance"])["sequentia_onchain"].clone();
	pb.rewrite(Some(Arc::new(|path: &str, _: &Value, _: u16, v: &mut Value| {
		if path == "/v1/witness" {
			*v = json!({"error": {"code": "signer_unavailable", "message": "the signer is not answering"}});
			return Some(503);
		}
		None
	})));
	let calls = |w: &str| pb.count(w);
	let (sends, boards_posted, mails) = (calls("/v1/cosign_transfer"), calls("/v1/register_board"), calls("/v1/mailbox_read"));
	for (what, args) in [
		("send", vec!["send", to_a.as_str(), "--amount", "100000", "--asset", &x.to_string()]),
		("board", vec!["board", &x.to_string(), "1000000"]),
		("participate", vec!["participate"]),
		("swap offer", vec!["swap", "offer", "--give-asset", &x.to_string(), "--give", "100000", "--want-asset", &y.to_string(), "--want", "100000"]),
		("mailbox", vec!["mailbox"]),
	] {
		let (ok, v) = b.run(&args);
		println!("F6 with the witness failing, {}: ok={} {}", what, ok, v["error"]);
		assert!(!ok && v["error"]["kind"] == "unreachable", "{} is refused while no witness succeeds: {}", what, v);
	}
	let s = b.ok(&["sync"]);
	println!("F6 with the witness failing, sync: witness {} | mailbox {} | participations {}", s["witness"], s["mailbox"], s["participations"]);
	assert!(s["witness"]["error"].is_string());
	assert!(s["mailbox"]["note"].as_str().unwrap_or("").contains("takes no coin and signs no spend"), "{}", s["mailbox"]);
	assert_eq!((calls("/v1/cosign_transfer"), calls("/v1/register_board"), calls("/v1/mailbox_read")), (sends, boards_posted, mails),
		"nothing was asked of the operator that signs a spend or takes a coin");
	let coins = b.ok(&["coins"]);
	assert_eq!(coins.as_array().unwrap().len(), 1, "no coin taken: {}", coins);
	assert_eq!(coin_of(&b, &board)["state"], "live", "the board was not given up nor spent");
	assert_eq!(b.ok(&["balance"])["sequentia_onchain"], onchain_before, "no board transaction");

	// The witness answers again: everything goes on.
	pb.rewrite(None);
	let s = b.ok(&["sync"]);
	println!("F6 the witness answers again: mailbox {}", s["mailbox"]["accepted"]);
	assert_eq!(s["mailbox"]["accepted"].as_array().map(|a| a.len()), Some(1));
	let sent = b.ok(&["send", &to_a, "--amount", "100000", "--asset", &x.to_string()]);
	assert!(sent["transfer"]["transfer_id"].is_string(), "{}", sent);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// R7e F1 turned around (D52): the reviewer's W2r with a keeper running.
/// After the operator's snapshot restores the signer's record and the
/// database together (the keeper, on another machine, is not restored), the
/// signer asks the keeper for its latest before it serves anything: the
/// keeper holds the head of P2's transfer, past the restored record's end,
/// and the signer stops at once, before any wallet contact. A's older copy
/// then tries the second spend of C_A to M: nothing is co-signed, and M gets
/// nothing. B's next sync learns of the stop on the signer's own proof (the
/// keeper's head) and takes P2 on the chain; P1 stays.
#[tokio::test(flavor = "multi_thread")]
async fn w2r_with_a_keeper_the_restored_signer_stops_before_any_second_spend() {
	let JointRollback { mut r, m_req, proxy, a, a_old, b, m, p1, p2, c_a, backup, .. } = joint_rollback_kept("W2K", 1).await;
	let x = r.x;
	println!("W2K the keeper holds up to entry {:?}; the restored record ends at entry {}", r.keepers[0].latest(), backup.entries);
	assert!(r.keepers[0].latest() > Some(backup.entries));
	let stopped = std::fs::read_to_string(server::signer::stopped_path(&r.signer.record())).expect("stopped at start, before any wallet");
	println!("W2K the signer's proof, at start: {}", stopped.lines().next().unwrap());
	assert!(stopped.contains("past the record's end"), "{}", stopped);
	assert!(info_of(&r)["signer_record"].is_null(), "a stopped signer hands out no head");

	proxy.rewrite(None);
	let (ok, v) = a_old.run(&["send", &m_req, "--amount", "300000", "--asset", &x.to_string()]);
	println!("W2K A's older copy spends C_A {} again, to M: ok={} {}", c_a, ok, v["error"]["message"]);
	assert!(!ok, "the second spend is not co-signed");
	let id: LeafId = c_a.parse().unwrap();
	println!("W2K C_A at the server: {:?}", r.server.store.leaf(&id.0).await.unwrap().map(|l| l.state));
	let got = m.ok(&["sync"]);
	println!("W2K M's sync: mailbox {}", got["mailbox"]);
	assert!(m.ok(&["coins"]).as_array().unwrap().is_empty(), "M gets nothing");

	let s = b.ok(&["sync"]);
	println!("W2K B's sync: rolled_back {} | exits {}", s["witness"]["rolled_back"], s["witness"]["exits"]);
	assert_eq!(s["witness"]["rolled_back"]["at"].as_u64(), Some(backup.entries));
	let exits = s["witness"]["exits"].as_array().unwrap();
	assert!(exits.iter().any(|e| e["leaf_id"] == p2.as_str()), "P2 goes on the chain: {:?}", exits);
	assert!(!exits.iter().any(|e| e["leaf_id"] == p1.as_str()));
	r.produce().await;
	let e = b.ok(&["exit", &p2]);
	println!("W2K B's P2: {} | {}", e["state"], coin_of(&b, &p2)["note"]);
	assert!(matches!(e["state"].as_str(), Some("waiting" | "claimed")), "P2's leaf is on the chain: {}", e);
	let _ = (&a, &mut r);
	for w in [&a, &a_old, &b, &m] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// D55, R7f's K1 turned around (F1 to F3). The keepers are part of the
/// operator's identity, written into its signer's record when it is made.
/// The operator runs with a keeper; A pays B 600,000 (P1); the box's
/// snapshot; A pays B 300,000 from its change C_A (P2), which the keeper
/// holds. The restore brings back record and database, and a start without
/// `--keeper`: the signer refuses to start, naming the record's keeper that
/// has no address. R7f's K2 and K2b cannot be set up either: a start with
/// a keeper of another key is refused, naming that key. Started with its
/// keeper, the keeper's head stops it before any wallet contact. M, a
/// wallet made after the restore, pins the record's keeper from `info` and
/// asks for no payment from a stopped operator; A's older copy's second
/// spend of C_A to N, whose request was made before the snapshot, is not
/// co-signed: N gets nothing. B's sync proves the rollback and takes P2 on
/// the chain.
#[tokio::test(flavor = "multi_thread")]
async fn a_restored_signer_without_its_keepers_does_not_start() {
	let mut r = Running::start_kept(1, None).await;
	let url = r.url();
	let x = r.x;
	let genesis = r.rt.client().genesis_hash().unwrap();
	let kept = r.keepers[0].xonly().to_string();
	let (a, b, n) = (Arca::new("K1A"), Arca::new("K1B"), Arca::new("K1N"));
	boarded(&mut r, &a, &url, &[(x, 4_000_000), (x, 1_000_000)]).await;
	b.ok(&create_args(&url, &r.node_url()));
	n.ok(&create_args(&url, &r.node_url()));
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req, "--amount", "600000", "--asset", &x.to_string()]);
	let p1 = b.ok(&["sync"])["mailbox"]["accepted"][0]["leaf_id"].as_str().unwrap().to_string();
	assert_eq!(b.ok(&["info"])["keepers"]["keys"], serde_json::json!([kept]));
	let n_req = n.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let record = std::fs::read_to_string(r.signer.record()).unwrap();
	println!("K1 the record's first line: {}", record.lines().next().unwrap());
	assert!(record.lines().next().unwrap().ends_with(&format!(" keepers=1:{}", kept)));
	let backup = Backup::take(&mut r).await;
	let a_old = copy_wallet(&a, "K1Aold");
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let paid = a.ok(&["send", &req, "--amount", "300000", "--asset", &x.to_string()]);
	let c_a = paid["inputs"][0].as_str().unwrap().to_string();
	let p2 = b.ok(&["sync"])["mailbox"]["accepted"][0]["leaf_id"].as_str().unwrap().to_string();
	println!("K1 after the snapshot: A paid B 300000 from C_A {} (P2 {}); the keeper holds up to entry {:?}; the snapshot's record ends at {}",
		c_a, p2, r.keepers[0].latest(), backup.entries);
	assert!(r.keepers[0].latest() > Some(backup.entries));

	// The restore, with the snapshot's start script, which lost --keeper.
	backup.restore_files(&mut r).await;
	let with_keeper = vec!["--keeper".to_string(), r.keepers[0].arg(), "--keeper-timeout-ms".into(), "2000".into()];
	r.signer.set_extra(vec![]);
	let e = r.signer.try_resume(genesis).expect_err("no start without the record's keeper");
	println!("K1 the restored signer started without --keeper: {}", e.lines().last().unwrap_or(""));
	assert!(e.starts_with("exit Some(2)") && e.contains(&format!("the record's keeper {} has no address", kept)), "{}", e);
	// K2, K2b: the keeper replaced by one of another key.
	let other = tokio::task::block_in_place(|| common::keeper::KeeperProcess::start(&common::running::keypair("keeper replaced"),
		common::running::keypair("operator").x_only_public_key().0, genesis));
	r.signer.set_extra(vec!["--keeper".to_string(), other.arg()]);
	let e = r.signer.try_resume(genesis).expect_err("no start with another keeper");
	println!("K1 (K2, K2b) started with a keeper of another key: {}", e.lines().last().unwrap_or(""));
	assert!(e.contains(&format!("={}: that key is not one of the record's keepers", other.xonly())), "{}", e);
	assert!(!server::signer::stopped_path(&r.signer.record()).exists(), "nothing started, nothing signed");
	drop(other);

	// Started with its keeper: the keeper's head stops it at once.
	r.signer.set_extra(with_keeper);
	backup.start(&mut r).await;
	let stopped = std::fs::read_to_string(server::signer::stopped_path(&r.signer.record())).expect("stopped at start, before any wallet");
	println!("K1 started with its keeper: {}", stopped.lines().next().unwrap());
	assert!(stopped.contains("past the record's end"), "{}", stopped);
	let i = info_of(&r);
	println!("K1 info: signer_record {} | keepers {}", i["signer_record"], i["keepers"]);
	assert_eq!(i["keepers"], serde_json::json!({"keys": [kept], "required": 1}), "info shows what the record says");

	// M, made now, pins the record's keeper, and asks a stopped operator
	// for no payment.
	let m = Arca::new("K1M");
	m.ok(&create_args(&url, &r.node_url()));
	let pinned = m.ok(&["info"])["keepers"].clone();
	println!("K1 M pinned: {}", pinned);
	assert_eq!(pinned["keys"], serde_json::json!([kept]));
	let (ok, v) = m.run(&["receive"]);
	println!("K1 M asks for a payment: ok={} {}", ok, v["error"]["message"]);
	assert!(!ok && v["error"]["message"].as_str().unwrap_or("").contains("the operator's signer is stopped on its own proof"), "{}", v);
	// The second spend of C_A, to N's request from before the snapshot.
	let (ok, v) = a_old.run(&["send", &n_req, "--amount", "300000", "--asset", &x.to_string()]);
	println!("K1 A's older copy spends C_A again, to N: ok={} {}", ok, v["error"]["message"]);
	assert!(!ok, "the second spend is not co-signed");
	let id: LeafId = c_a.parse().unwrap();
	println!("K1 C_A at the server: {:?}", r.server.store.leaf(&id.0).await.unwrap().map(|l| l.state));
	let got = n.ok(&["sync"]);
	println!("K1 N's sync: mailbox {}", got["mailbox"]);
	assert!(n.ok(&["coins"]).as_array().unwrap().is_empty(), "N gets nothing");
	let s = b.ok(&["sync"]);
	println!("K1 B's sync: rolled_back {} | exits {}", s["witness"]["rolled_back"]["at"], s["witness"]["exits"]);
	assert_eq!(s["witness"]["rolled_back"]["at"].as_u64(), Some(backup.entries));
	let exits = s["witness"]["exits"].as_array().unwrap();
	assert!(exits.iter().any(|e| e["leaf_id"] == p2.as_str()) && !exits.iter().any(|e| e["leaf_id"] == p1.as_str()), "{:?}", exits);
	for w in [&a, &a_old, &b, &m, &n] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// D55 at the wallet. A wallet made before keepers existed has none pinned,
/// and pins them from the first `info` it reads: its `info` shows the
/// keepers it pinned on that very call, not "no keeper" (R7f F9). From then
/// on the keepers are part of the operator's identity: an operator showing
/// others (a proxy rewrites them) is refused, as an operator key it was not
/// created with is.
#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_pins_the_keepers_as_part_of_the_operator() {
	let r = Running::start_kept(1, None).await;
	let url = r.url();
	let kept = r.keepers[0].xonly().to_string();
	let proxy = Proxy::start(&url);
	let b = Arca::new("PKB");
	b.ok(&create_args(&proxy.url.clone(), &r.node_url()));
	// As made before keepers existed: no keepers pinned.
	{
		let c = rusqlite::Connection::open(b.dir.join("arca.sqlite")).unwrap();
		assert_eq!(c.execute("DELETE FROM meta WHERE key = 'keepers'", []).unwrap(), 1);
	}
	let i = b.ok(&["info"]);
	println!("PK the first info of a wallet with no keepers pinned: keepers {}", i["keepers"]);
	assert_eq!(i["keepers"]["keys"], serde_json::json!([kept]), "the call that pins the keepers shows them: {}", i["keepers"]);
	assert_eq!(i["keepers"]["required"], 1);
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, _: u16, v: &mut Value| {
		if path == "/v1/info" {
			v["keepers"] = serde_json::json!({"keys": [], "required": 0});
		}
		None
	})));
	let i = b.ok(&["info"]);
	println!("PK the operator showing no keeper: {}", i["server_info"]);
	assert!(i["server_info"]["unreachable"].as_str().unwrap_or("").contains("the server now names the keepers"), "{}", i["server_info"]);
	assert_eq!(i["keepers"]["keys"], serde_json::json!([kept]), "the pin stands");
	let (ok, v) = b.run(&["sync"]);
	println!("PK its sync: ok={} {}", ok, v["witness"]);
	drop(r);
	let _ = std::fs::remove_dir_all(&b.dir);
}

/// D52.4, the control for the test above: the same restore with no keeper.
/// The signer starts on the restored record and co-signs the older copy's
/// second spend of C_A, as an operator with no keeper is documented to do:
/// such an operator is for its own coins. M takes that coin on the chain
/// first, and B's P2, whose coin the operator co-signed another spend of, is
/// then shown as lost with that reason (D49 amended), not as pending.
#[tokio::test(flavor = "multi_thread")]
async fn w2r_without_a_keeper_the_second_spend_is_still_cosigned() {
	let JointRollback { r, m_req, a, a_old, b, m, c_a, p2, .. } = joint_rollback_kept("W2N", 0).await;
	let x = r.x;
	assert!(!server::signer::stopped_path(&r.signer.record()).exists(), "nothing at start shows the restore");
	let paid = a_old.ok(&["send", &m_req, "--amount", "300000", "--asset", &x.to_string()]);
	println!("W2N with no keeper, A's older copy spends C_A {} again, to M: inputs {}", c_a, paid["inputs"]);
	assert_eq!(paid["inputs"][0].as_str(), Some(c_a.as_str()), "co-signed");
	// D49 amended: M takes its coin on the chain first; B's P2, whose coin
	// the operator co-signed another spend of, is shown as lost, with that
	// reason, once that spend is final, and not as pending.
	let got_m = m.ok(&["sync"])["mailbox"]["accepted"][0]["leaf_id"].as_str().unwrap().to_string();
	println!("W2N M's exit at once: {}", m.ok(&["exit", &got_m])["state"]);
	r.produce().await;
	m.ok(&["exit", &got_m]);
	r.produce().await;
	r.bury().await;
	let s = b.ok(&["sync"]);
	println!("W2N B's sync: rolled_back {} | exits {}", s["witness"]["rolled_back"]["at"], s["exits"]);
	let s = b.ok(&["sync"]);
	let p2_now = coin_of(&b, &p2);
	println!("W2N B's P2 now: {} | {}", p2_now["state"], p2_now["note"]);
	assert_eq!(p2_now["state"], "lost", "{} | exits {}", p2_now, s["exits"]);
	assert!(p2_now["note"].as_str().unwrap().contains(&format!("co-signed another spend of coin {}", c_a)), "{}", p2_now);
	assert!(b.ok(&["balance"])["arca"].to_string().find("pending").is_none(), "P2 is not counted as pending");
	for w in [&a, &a_old, &b, &m] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// R7e F2 turned around, and D49 amended: after a stop the wallet brings
/// everything home. A pays U 200,000 while U is offline; the operator's
/// snapshot; A pays B 300,000; database and record restored together, and
/// B's sync stops the signer. U then comes online: its mailbox is still read,
/// the coin it was sent checked as ever and taken on the chain at once
/// (its lineage already there from B's exit), and U ends with it on the
/// chain. A's second board, which no transfer made, is shown with the date
/// by which it must be exited and kept; within three days of that date,
/// A's sync takes it on the chain.
#[tokio::test(flavor = "multi_thread")]
async fn after_a_stop_every_coin_comes_home() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let (a, b, u) = (Arca::new("HOA"), Arca::new("HOB"), Arca::new("HOU"));
	let boards = boarded(&mut r, &a, &url, &[(x, 4_000_000), (x, 1_000_000)]).await;
	b.ok(&create_args(&url, &r.node_url()));
	u.ok(&create_args(&url, &r.node_url()));
	let req_u = u.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req_u, "--amount", "200000", "--asset", &x.to_string()]);
	let backup = Backup::take(&mut r).await;
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req, "--amount", "300000", "--asset", &x.to_string()]);
	b.ok(&["sync"]);
	backup.restore(&mut r).await;
	let s = b.ok(&["sync"]);
	println!("HO B's sync after the joint rollback: rolled_back {}", s["witness"]["rolled_back"]["at"]);
	assert_eq!(s["witness"]["rolled_back"]["at"].as_u64(), Some(backup.entries));
	assert!(server::signer::stopped_path(&r.signer.record()).exists());
	r.produce().await;

	// U comes online.
	let s = u.ok(&["sync"]);
	println!("HO U comes online: mailbox {}", s["mailbox"]["accepted"]);
	let leaf = s["mailbox"]["accepted"][0]["leaf_id"].as_str().expect("U's coin is read and taken").to_string();
	assert_eq!(s["mailbox"]["accepted"][0]["value"], "200000");
	assert!(s["mailbox"]["note"].as_str().unwrap_or("").contains("takes every coin it is sent on the chain at once"), "{}", s["mailbox"]);
	assert_eq!(coin_of(&u, &leaf)["state"], "exiting", "on its way to the chain at once");
	r.produce().await;
	u.ok(&["exit", &leaf]);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 512));
	let e = u.ok(&["exit", &leaf]);
	println!("HO U's claim: {} {}", e["state"], e["claim"]);
	r.produce().await;
	r.bury().await;
	u.ok(&["sync"]);
	let c = coin_of(&u, &leaf);
	let onchain = u.ok(&["balance"])["sequentia_onchain"][x.to_string()].as_str().unwrap_or("0").parse::<u64>().unwrap();
	println!("HO U at the end: {} | {} | on the chain {}", c["state"], c["note"], onchain);
	assert_eq!(c["state"], "exited");
	assert!(onchain > 199_000 && onchain <= 200_000, "U ends with its 200,000 on the chain, less its claim's fee: {}", onchain);

	// A's second board: shown with its date, kept; taken within three days
	// of it.
	let s = a.ok(&["sync"]);
	let board = &boards[1];
	let shown = s["home"].as_array().unwrap().iter().find(|h| h["leaf_id"] == board.as_str()).cloned()
		.unwrap_or_else(|| panic!("A's second board is shown: {}", s["home"]));
	println!("HO A's second board after the stop: {}", shown);
	let by = shown["exit_by"].as_u64().expect("its exit date") as u32;
	assert!(shown["exit"].is_null(), "not taken yet: its date is weeks away");
	assert_eq!(coin_of(&a, board)["state"], "live");
	assert_eq!(coin_of(&a, board)["exit_by"].as_u64(), Some(by as u64), "coins shows the date too");
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, by - now - 2 * 86_400));
	let s = a.ok(&["sync"]);
	let shown = s["home"].as_array().unwrap().iter().find(|h| h["leaf_id"] == board.as_str()).cloned().unwrap();
	println!("HO two days before its date: {}", shown["exit"]);
	assert!(shown["exit"]["state"].is_string(), "{}", shown);
	assert_eq!(coin_of(&a, board)["state"], "exiting");
	for w in [&a, &b, &u] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// D57, R7f's U2 and R7g's U4 turned around (F4). A wallet that cannot
/// reach the operator takes nothing on the chain for that before a day ahead
/// of a coin's exit date, and from then takes every coin not refreshed. A's
/// server withholds the signer's proof from every witness (a proxy drops
/// `end` and `proof`), and G's server is simply gone: each `sync` shows each
/// coin's dates and says nothing is taken before `home_from`, and so does
/// `coins`; a date weeks off, five days off, and two days off (inside the
/// refresh window) takes nothing. With the operator answering two days
/// before, A's refresh of its board is asked for and waits, and A's other
/// coin, whose refresh the operator refuses, is asked for again, refused
/// again, and stays. An hour before `home_from`, the proof withheld again,
/// nothing goes; at `home_from`, every coin of A and G goes on the chain.
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_the_operator_cannot_refresh_goes_home_a_day_before_its_date() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let proxy = Proxy::start(&url);
	let (a, g) = (Arca::new("D56A"), Arca::new("D56G"));
	let a_boards = boarded(&mut r, &a, &proxy.url.clone(), &[(x, 1_000_000), (x, 1_100_000)]).await;
	let g_boards = boarded(&mut r, &g, &url, &[(x, 1_000_000)]).await;
	let (board, refused, g_board) = (a_boards[0].clone(), a_boards[1].clone(), g_boards[0].clone());
	let refuse = Arc::new(std::sync::Mutex::new(Some(refused.clone())));
	let refuse_in = refuse.clone();
	// The operator refuses every refresh of A's second board.
	let refuse_submit = move || {
		let r = refuse_in.clone();
		Arc::new(move |path: &str, req: &Value, _: u16, v: &mut Value| {
			let leaf = r.lock().unwrap().clone();
			if path == "/v1/submit_participation" && leaf.is_some_and(|l| req.to_string().contains(&l)) {
				*v = json!({"error": {"code": "not_accepted", "message": "the operator refuses this refresh"}});
				return Some(409u16);
			}
			None
		}) as common::proxy::Rewrite
	};
	proxy.rewrite(Some(refuse_submit()));
	let (ok, v) = a.run(&["participate", "--leaf", &refused]);
	println!("D57 A's refresh of {} refused: ok={} {}", &refused[..8], ok, v["error"]["message"]);
	assert!(!ok);
	assert_eq!(coin_of(&a, &refused)["state"], "live");
	let withhold = || proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, _: u16, v: &mut Value| {
		if path == "/v1/witness" {
			if let Some(o) = v.as_object_mut() {
				o.remove("end");
				o.remove("proof");
			}
		}
		None
	})));
	let home_of = |s: &Value, leaf: &str| s["home"].as_array().and_then(|h| h.iter().find(|x| x["leaf_id"] == leaf).cloned());

	// The proof withheld: weeks before the date, the dates shown, nothing taken.
	withhold();
	let s = a.ok(&["sync"]);
	println!("D57 A's sync, the proof withheld: witness {} | unreachable {}", s["witness"]["error"], s["unreachable"]["note"]);
	assert!(s["witness"]["error"].as_str().unwrap_or("").contains("carries no proof the signer made"), "{}", s["witness"]);
	let shown = home_of(&s, &board).expect("the board is shown");
	let by = shown["exit_by"].as_u64().expect("its exit date") as u32;
	let home_from = shown["home_from"].as_u64().expect("from when it goes home") as u32;
	assert_eq!(home_from, by - 86_400);
	println!("D57 A's board {}: exit_by {} home_from {} | {}", &board[..8], by, home_from, shown["note"]);
	assert!(shown["exit"].is_null() && shown["note"].as_str().unwrap().contains("nothing is taken on the chain for that before"), "{}", shown);
	assert!(s["unreachable"]["note"].as_str().unwrap().contains("at least once a day"), "{}", s);
	let c = coin_of(&a, &board);
	assert_eq!((c["state"].as_str(), c["exit_by"].as_u64()), (Some("live"), Some(by as u64)), "coins shows the date: {}", c);
	assert!(c["home"].as_str().unwrap().contains("nothing is taken on the chain for that before"), "{}", c);

	// Five days before the date: nothing. The server gone: the same for G.
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, by - now - 5 * 86_400));
	let s = a.ok(&["sync"]);
	assert!(home_of(&s, &board).unwrap()["exit"].is_null(), "{}", s["home"]);
	r.server.stop();
	let s = g.ok(&["sync"]);
	println!("D57 G's sync, the server gone: witness {} | home {}", s["witness"]["error"], s["home"]);
	assert!(s["witness"]["error"].as_str().unwrap_or("").contains("cannot reach the server"), "{}", s["witness"]);
	assert!(s["witness"]["tries"].as_u64().unwrap_or(0) >= 2, "tried again before taking it for unreachable: {}", s["witness"]);
	let shown = home_of(&s, &g_board).expect("G's board is shown");
	assert!(shown["exit"].is_null() && shown["exit_by"].as_u64().is_some(), "{}", shown);

	// Two days before, inside the refresh window: still nothing goes for
	// want of an answer, A's proof withheld and G's server gone.
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, by - now - 2 * 86_400 + 600));
	for (w, leaf) in [(&a, &board), (&g, &g_board)] {
		let s = w.ok(&["sync"]);
		println!("D57 {}'s sync two days before, unreachable: home {}", w.name, s["home"]);
		assert!(home_of(&s, leaf).unwrap()["exit"].is_null(), "nothing goes before home_from: {}", s["home"]);
		assert_eq!(coin_of(w, leaf)["state"], "live");
	}
	// The operator answers again: A's board's refresh is asked for and waits
	// for a round; the refused coin is asked for again, refused, and stays.
	proxy.rewrite(Some(refuse_submit()));
	r.restart_server().await;
	r.synced().await;
	let s = a.ok(&["sync"]);
	println!("D57 A's sync two days before, the operator answering: refresh {} | home {}", s["refresh"], s["home"]);
	assert!(s["witness"]["error"].is_null() && s["unreachable"].is_null(), "{}", s);
	let asked: Vec<&Value> = s["refresh"].as_array().unwrap().iter().collect();
	assert!(asked.iter().any(|x| x["leaf_id"] == board.as_str() && x["state"] == "pending"), "{}", s["refresh"]);
	assert!(asked.iter().any(|x| x["leaf_id"] == refused.as_str() && x["error"].as_str().unwrap_or("").contains("refuses")), "{}", s["refresh"]);
	assert_eq!((coin_of(&a, &board)["state"].as_str(), coin_of(&a, &refused)["state"].as_str()), (Some("given"), Some("live")));
	assert!(coin_of(&a, &refused)["home"].as_str().unwrap().contains("refused"), "{}", coin_of(&a, &refused));

	// An hour before home_from, the proof withheld again: nothing goes.
	withhold();
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, home_from - now - 3_600));
	let s = a.ok(&["sync"]);
	assert!(home_of(&s, &board).unwrap()["exit"].is_null() && home_of(&s, &refused).unwrap()["exit"].is_null(), "{}", s["home"]);
	// From home_from: every coin of A goes, the proof withheld; and G's,
	// its server gone.
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, home_from - now + 600));
	let s = a.ok(&["sync"]);
	for leaf in [&board, &refused] {
		let shown = home_of(&s, leaf).unwrap();
		println!("D57 A's sync from home_from, the proof withheld: {} {}", &leaf[..8], shown["exit"]["state"]);
		assert!(shown["exit"]["state"].is_string(), "{}", shown);
		let c = coin_of(&a, leaf);
		assert_eq!(c["state"], "exiting");
		assert!(c["note"].as_str().unwrap().contains("its refresh has not completed a day before its exit date"), "{}", c);
	}
	r.server.stop();
	let s = g.ok(&["sync"]);
	let shown = home_of(&s, &g_board).unwrap();
	println!("D57 G's sync from home_from, the server gone: {}", shown["exit"]["state"]);
	assert!(shown["exit"]["state"].is_string(), "{}", shown);
	assert_eq!(coin_of(&g, &g_board)["state"], "exiting");
	r.produce().await;
	for (w, leaf) in [(&a, &board), (&a, &refused), (&g, &g_board)] {
		let e = w.ok(&["exit", leaf]);
		println!("D57 {}'s exit of {}: {}", w.name, &leaf[..8], e["state"]);
		assert!(matches!(e["state"].as_str(), Some("unrolling" | "waiting" | "claimed")), "on its way to the chain: {}", e);
	}
	let _ = refuse;
	for w in [&a, &g] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// D52. A keeper down holds a payment up: the server records it, the
/// signer records the entry and answers `keepers_unavailable`, and the
/// wallet keeps the request standing, nothing taken. Once the keeper is
/// back, the sender's `sync` posts it again and it completes; the receiver
/// takes the coin, whose head comes with the keeper's acknowledgement, and
/// shows the keeper it pinned when it was created.
#[tokio::test(flavor = "multi_thread")]
async fn a_keeper_down_holds_a_payment_up_until_it_returns() {
	let mut r = Running::start_kept(1, None).await;
	let url = r.url();
	let x = r.x;
	let (a, b) = (Arca::new("KDA"), Arca::new("KDB"));
	let boards = boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	b.ok(&create_args(&url, &r.node_url()));
	let info = b.ok(&["info"]);
	println!("KD B's wallet pinned the keepers: {}", info["keepers"]);
	assert_eq!(info["keepers"]["keys"][0].as_str(), Some(r.keepers[0].xonly().to_string().as_str()));
	assert_eq!(info["keepers"]["required"], 1);
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	r.keepers[0].halt();
	let (ok, v) = a.run(&["send", &req, "--amount", "600000", "--asset", &x.to_string()]);
	println!("KD A pays B with the keeper down: ok={} {}", ok, v["error"]["message"]);
	assert!(!ok && v["error"]["kind"] == "unreachable", "{}", v);
	assert!(v["error"]["message"].as_str().unwrap().contains("keepers_unavailable"), "{}", v);
	assert_eq!(coin_of(&a, &boards[0])["state"], "sending", "the request stands");
	assert!(b.ok(&["sync"])["mailbox"]["accepted"].as_array().unwrap().is_empty());

	r.keepers[0].resume();
	let s = a.ok(&["sync"]);
	println!("KD A's sync with the keeper back: transfers {}", s["transfers"]);
	assert!(s["transfers"][0]["transfer_id"].is_string(), "{}", s["transfers"]);
	let got = b.ok(&["sync"]);
	let leaf = got["mailbox"]["accepted"][0]["leaf_id"].as_str().expect("B takes the coin").to_string();
	assert_eq!(coin_of(&b, &leaf)["value"], "600000");
	assert!(!coin_of(&b, &leaf)["note"].as_str().unwrap_or("").contains("no keeper"));
	let msg = minreq::get(format!("{}/v1/info", url)).send().unwrap();
	let i: Value = serde_json::from_str(msg.as_str().unwrap()).unwrap();
	println!("KD info: keepers {} | head {} with {} acknowledgement(s)", i["keepers"], i["signer_record"]["entry"],
		i["signer_record"]["acks"].as_array().map(|a| a.len()).unwrap_or(0));
	assert_eq!(i["signer_record"]["acks"].as_array().map(|a| a.len()), Some(1));
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// D52.3. A wallet that pinned the operator's keepers takes no coin and
/// keeps no head without their acknowledgements. A proxy strips them from
/// what the server answers B: the co-signature of B's own payment (the
/// request stands, nothing taken), and the head of a coin in B's mailbox
/// (the coin waits, and its message is read again). With the answers whole
/// again, the payment completes and the coin is taken.
#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_takes_no_coin_without_its_keepers_acknowledgements() {
	let mut r = Running::start_kept(1, None).await;
	let url = r.url();
	let x = r.x;
	let pb = Proxy::start(&url);
	let (a, b) = (Arca::new("KAA"), Arca::new("KAB"));
	boarded(&mut r, &a, &url, &[(x, 4_000_000)]).await;
	let boards = boarded(&mut r, &b, &pb.url.clone(), &[(x, 2_000_000)]).await;
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req, "--amount", "300000", "--asset", &x.to_string()]);
	let to_a = a.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let strip = |v: &mut Value| {
		if let Some(o) = v.as_object_mut() {
			o.remove("acks");
		}
	};
	pb.rewrite(Some(Arc::new(move |path: &str, _: &Value, _: u16, v: &mut Value| {
		match path {
			"/v1/cosign_transfer" => strip(&mut v["signer_record"]),
			"/v1/mailbox_read" => for m in v["messages"].as_array_mut().into_iter().flatten() {
				strip(&mut m["signer_record"]);
			},
			_ => {},
		}
		None
	})));
	let s = b.ok(&["sync"]);
	println!("KA B's mailbox, the acknowledgements stripped: {}", s["mailbox"]);
	assert!(s["mailbox"]["accepted"].as_array().unwrap().is_empty());
	let waited = s["mailbox"]["waiting"][0]["leaf_id"].as_str().unwrap().to_string();
	assert!(s["mailbox"]["waiting"][0]["reason"].as_str().unwrap_or("").contains("acknowledgements of its keepers"), "{}", s["mailbox"]);
	let (ok, v) = b.run(&["send", &to_a, "--amount", "500000", "--asset", &x.to_string()]);
	println!("KA B pays A, the co-signature's acknowledgements stripped: ok={} {}", ok, v["error"]["message"]);
	assert!(!ok && v["error"]["kind"] == "unreachable", "{}", v);
	assert_eq!(coin_of(&b, &boards[0])["state"], "sending", "the request stands, nothing taken");
	assert_eq!(b.ok(&["coins"]).as_array().unwrap().len(), 1, "no coin taken");

	pb.rewrite(None);
	let s = b.ok(&["sync"]);
	println!("KA B with the answers whole: transfers {} | mailbox {}", s["transfers"][0]["transfer_id"], s["mailbox"]["accepted"]);
	assert!(s["transfers"][0]["transfer_id"].is_string());
	assert!(s["mailbox"]["accepted"].as_array().unwrap().iter().any(|c| c["leaf_id"] == waited.as_str() && c["already_held"].is_null()),
		"the coin that waited is read again and taken: {}", s["mailbox"]);
	assert_eq!(coin_of(&b, &waited)["value"], "300000");
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// R7f F9. Once a mailbox coin waits (its head without the keeper's
/// acknowledgement, stripped by a proxy), the messages after it are read
/// again on every read until it is taken: the coins among them the wallet
/// took already are reported as held, never again as accepted.
#[tokio::test(flavor = "multi_thread")]
async fn a_mailbox_read_again_reports_no_held_coin_as_taken() {
	let mut r = Running::start_kept(1, None).await;
	let url = r.url();
	let x = r.x;
	let pb = Proxy::start(&url);
	let (a, b) = (Arca::new("MRA"), Arca::new("MRB"));
	boarded(&mut r, &a, &url, &[(x, 4_000_000)]).await;
	b.ok(&create_args(&pb.url.clone(), &r.node_url()));
	for amount in ["100000", "200000"] {
		let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
		a.ok(&["send", &req, "--amount", amount, "--asset", &x.to_string()]);
	}
	// The first message's head loses its acknowledgements on the way.
	let first: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
	let f2 = first.clone();
	pb.rewrite(Some(Arc::new(move |path: &str, _: &Value, _: u16, v: &mut Value| {
		if path == "/v1/mailbox_read" {
			for m in v["messages"].as_array_mut().into_iter().flatten() {
				let leaf = m["leaf_id"].as_str().unwrap_or("").to_string();
				let mut f = f2.lock().unwrap();
				if f.is_none() {
					*f = Some(leaf.clone());
				}
				if f.as_deref() == Some(leaf.as_str()) {
					if let Some(o) = m["signer_record"].as_object_mut() {
						o.remove("acks");
					}
				}
			}
		}
		None
	})));
	let held_in_accepted = |s: &Value| s["mailbox"]["accepted"].as_array().unwrap().iter().any(|c| !c["already_held"].is_null());
	let s = b.ok(&["sync"]);
	println!("MR B's first read: accepted {} | waiting {}", s["mailbox"]["accepted"], s["mailbox"]["waiting"]);
	let p2 = s["mailbox"]["accepted"][0]["leaf_id"].as_str().expect("the second coin taken").to_string();
	assert_eq!(s["mailbox"]["waiting"].as_array().unwrap().len(), 1);
	let s = b.ok(&["sync"]);
	println!("MR B's second read: accepted {} | already_held {} | waiting {}", s["mailbox"]["accepted"], s["mailbox"]["already_held"],
		s["mailbox"]["waiting"]);
	assert!(!held_in_accepted(&s) && s["mailbox"]["accepted"].as_array().unwrap().is_empty(), "nothing is reported taken: {}", s["mailbox"]);
	assert_eq!(s["mailbox"]["already_held"][0]["leaf_id"].as_str(), Some(p2.as_str()), "{}", s["mailbox"]);
	pb.rewrite(None);
	let s = b.ok(&["sync"]);
	println!("MR B's read with the answers whole: accepted {} | already_held {}", s["mailbox"]["accepted"], s["mailbox"]["already_held"]);
	assert!(!held_in_accepted(&s));
	assert_eq!(s["mailbox"]["accepted"][0]["leaf_id"].as_str(), first.lock().unwrap().as_deref(), "the coin that waited is taken");
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// R7f F9. A rollback note kept by an older version of the wallet without
/// the signer's proof (R7e F4's lie, believed before the wallet asked for
/// proof) is checked once against the signer: its witness proves no
/// rollback, so the note is dropped, saying so, nothing is exited, and the
/// wallet goes on with the operator.
#[tokio::test(flavor = "multi_thread")]
async fn an_older_wallets_rollback_note_without_proof_is_dropped() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let a = Arca::new("ONA");
	let boards = boarded(&mut r, &a, &url, &[(x, 1_000_000)]).await;
	{
		let c = rusqlite::Connection::open(a.dir.join("arca.sqlite")).unwrap();
		c.execute("INSERT INTO meta (key, value) VALUES ('operator_rolled_back', ?1)",
			[r#"{"at":0,"why":"the server says the record ends before entry 1"}"#]).unwrap();
	}
	let s = a.ok(&["sync"]);
	println!("ON A's sync with an older wallet's note: witness {} | home {}", s["witness"], s["home"]);
	assert!(s["witness"]["rolled_back"].is_null() && s["witness"]["error"].is_null(), "{}", s["witness"]);
	assert!(s["home"].is_null(), "nothing brought home: {}", s["home"]);
	let refusals = a.ok(&["refusals"]);
	let dropped = refusals.as_array().unwrap().iter().find(|r| r["reason"].as_str().unwrap_or("").contains("whose witness proves no rollback: dropped"))
		.cloned();
	println!("ON the wallet's record of it: {:?}", dropped.as_ref().map(|d| d["reason"].clone()));
	assert!(dropped.is_some(), "{}", refusals);
	assert_eq!(coin_of(&a, &boards[0])["state"], "live");
	let req = a.ok(&["receive"]);
	assert!(req["request"].is_string(), "the wallet goes on with the operator: {}", req);
	let _ = std::fs::remove_dir_all(&a.dir);
}

/// A wallet asks where its participations stand, from its own store, as
/// often as it likes: `sync` reports a release once, and a client that
/// missed that report (the testnet trial's script waited an hour on it)
/// asks `participations`, which names each one's state, its round, the coins
/// it gave up and its new leaves, the same before and after the release is
/// reported, and with the operator gone.
#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_lists_its_participations_with_their_round_and_new_leaves() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let c = Arca::new("PL");
	let boards = boarded(&mut r, &c, &url, &[(x, 2_000_000)]).await;
	assert_eq!(c.ok(&["participations"]), json!([]));
	let p = c.ok(&["participate"]);
	let pid = p["participation"].as_str().unwrap().to_string();
	let listed = c.ok(&["participations"]);
	println!("PL before the round: {}", listed);
	assert_eq!(listed[0]["participation"].as_str(), Some(pid.as_str()));
	assert_eq!(listed[0]["state"], "pending");
	assert_eq!(listed[0]["gives"][0], json!({"leaf_id": boards[0], "state": "given"}));
	assert!(listed[0]["round"].is_null() && listed[0]["new_leaves"][0]["leaf_id"].is_null() && listed[0]["released"] == false);
	let round = final_round(&r).await;
	let s = c.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s["participations"]);
	// The report missed: asked again, twice, and with the operator gone.
	let first = c.ok(&["participations"]);
	println!("PL after the release: {}", first);
	assert_eq!(c.ok(&["participations"]), first, "the same answer each time");
	assert_eq!((first[0]["state"].as_str(), first[0]["released"].as_bool()), (Some("released"), Some(true)));
	assert_eq!(first[0]["round"].as_str(), Some(round.txid().to_string().as_str()));
	let leaf = first[0]["new_leaves"][0]["leaf_id"].as_str().expect("its new leaf").to_string();
	assert_eq!(first[0]["new_leaves"][0]["state"], "live");
	assert_eq!(first[0]["new_leaves"][0]["value"], coin_of(&c, &leaf)["value"]);
	assert_eq!(first[0]["gives"][0]["state"], "spent");
	r.server.stop();
	assert_eq!(c.ok(&["participations"]), first, "from the wallet's own store, the operator gone");
	let _ = std::fs::remove_dir_all(&c.dir);
}

/// R7c's F8: the forfeit's margin is bounded from the floor the operator
/// publishes, as a transfer's margins are, whatever the wallet's own node
/// makes of the asset. A wallet whose node values X five times higher than
/// the operator's (its floor in X atoms five times lower) completes its
/// refresh; a bound from its own node would have refused the forfeit.
#[tokio::test(flavor = "multi_thread")]
async fn the_forfeit_margin_is_bounded_from_the_operators_floor() {
	let mut r = Running::start().await;
	let x = r.x;
	let url = r.url();
	let node_proxy = Proxy::start(&r.node_url().trim_end_matches('/'));
	let w = Arca::new("F8M");
	w.ok(&["create", "--server", &url, "--node-url", &node_proxy.url, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	let s = script(&w.ok(&["address"]));
	r.pay_to(s, x, 5_000_000);
	r.produce().await;
	let board = w.ok(&["board", &x.to_string(), "2000000"])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
	assert_eq!(coin_of(&w, &board)["state"], "live");
	w.ok(&["participate"]);
	final_round(&r).await;
	// From here the wallet's node values X five times higher.
	node_proxy.rewrite(Some(rates_rewrite(x, Some(5.0), None)));
	let s = w.ok(&["sync"]);
	println!("F8 the refresh with the wallet's node valuing X five times higher: {}", s["participations"][0]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s["participations"]);
	assert_eq!(coin_of(&w, &board)["state"], "spent");
	let _ = std::fs::remove_dir_all(&w.dir);
}

// ---------------------------------------------------------------------------
// Margins: the operator's, within the wallet's bound
// ---------------------------------------------------------------------------

/// A rewrite of the node's `getfeeexchangerates` answer for `asset`, as
/// another node on the same chain may value it: scaled by `factor`, dropped
/// (not accepted for fees), or set to `set`.
fn rates_rewrite(asset: AssetId, factor: Option<f64>, set: Option<u64>) -> common::proxy::Rewrite {
	let a = asset.to_string();
	Arc::new(move |_: &str, req: &Value, _: u16, v: &mut Value| {
		if req["method"] != "getfeeexchangerates" {
			return None;
		}
		let rates = v["result"].as_object_mut()?;
		match (factor, set) {
			(_, Some(r)) => {
				rates.insert(a.clone(), json!(r));
			},
			(Some(f), None) => {
				if let Some(r) = rates.get(&a).and_then(|r| r.as_u64()) {
					rates.insert(a.clone(), json!((r as f64 * f) as u64));
				}
			},
			(None, None) => {
				rates.remove(&a);
			},
		}
		None
	})
}

/// Review R8b's probe P4 turned around. Nodes value an asset each for
/// itself, so a wallet's node may value X higher or lower than the
/// operator's, or not accept it, or accept Y, which the operator's node does
/// not. The wallet prices its margins from the floors the operator
/// publishes (`info.fees.floors`), never from its own node, so each of these
/// wallets sends; and it refuses, before anything is signed, margins an
/// operator's floor would take above its own bound.
#[tokio::test(flavor = "multi_thread")]
async fn the_margins_are_the_operators_whatever_the_wallets_node_says() {
	let mut r = Running::start().await;
	let (x, y) = (r.x, r.y);
	let url = r.url();
	let cases: Vec<(&str, AssetId, common::proxy::Rewrite)> = vec![
		("the wallet's node is the operator's", x, Arc::new(|_: &str, _: &Value, _: u16, _: &mut Value| None)),
		("the wallet's node values X 10% higher", x, rates_rewrite(x, Some(1.10), None)),
		("the wallet's node values X 25% higher", x, rates_rewrite(x, Some(1.25), None)),
		("the wallet's node values X 10% lower", x, rates_rewrite(x, Some(0.90), None)),
		("the wallet's node does not accept X for fees", x, rates_rewrite(x, None, None)),
		("the wallet's node accepts Y for fees, the operator's does not", y, rates_rewrite(y, None, Some(100_000_000))),
	];
	let b = Arca::new("P4recv");
	b.ok(&create_args(&url, &r.node_url()));
	let mut wallets = vec![];
	for (k, (what, asset, rewrite)) in cases.into_iter().enumerate() {
		// The wallet's node: the operator's, through a proxy that answers
		// as the wallet's own node would, once the wallet holds its coin.
		let node = Proxy::start(&r.node_url().trim_end_matches('/').to_string());
		let w = Arca::new(&format!("P4w{}", k));
		w.ok(&create_args(&url, &format!("{}/", node.url)));
		let s = script(&w.ok(&["address"]));
		r.pay_to(s.clone(), asset, 5_000_000);
		if asset != x {
			r.pay_to(s, x, 5_000_000);
		}
		r.produce().await;
		let mut args = vec!["board".to_string(), asset.to_string(), "2000000".into()];
		if asset != x {
			args.extend(["--fee-asset".into(), x.to_string()]);
		}
		w.ok(&args.iter().map(|a| a.as_str()).collect::<Vec<_>>());
		wallets.push((what, asset, w, node, rewrite));
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	for (_, _, w, node, rewrite) in &wallets {
		r.wait("the board to be credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited"))
			.await;
		w.ok(&["sync"]);
		node.rewrite(Some(rewrite.clone()));
	}
	for (what, asset, w, _, _) in &wallets {
		let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
		let (ok, v) = w.run(&["send", &req, "--amount", "600000", "--asset", &asset.to_string()]);
		println!("P4 {}: send {} {}", what, if ok { "co-signed, margins" } else { "refused:" },
			if ok { v["margins"].to_string() } else { v["error"]["message"].to_string() });
		assert!(ok, "{}: {}", what, v);
	}

	// An operator publishing a floor that would take margins above the
	// wallet's bound: refused before anything is signed.
	let server = Proxy::start(&url);
	let greedy = Arca::new("P4greedy");
	let board = boarded(&mut r, &greedy, &server.url.clone(), &[(x, 2_000_000)]).await;
	let xs = x.to_string();
	server.rewrite(Some(Arc::new(move |path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/info" && status == 200 {
			for f in v["fees"]["floors"].as_array_mut().into_iter().flatten() {
				if f["asset"] == xs.as_str() {
					f["floor_per_kvb"] = json!("10000");
				}
			}
		}
		None
	})));
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let why = greedy.refused(&["send", &req, "--amount", "600000", "--asset", &x.to_string()], "bound");
	println!("P4 an operator's floor taking margins above the wallet's bound: REFUSED: {}", why);
	assert_eq!(server.count("/v1/cosign_transfer"), 0, "nothing was sent to be signed");
	assert_eq!(coin_of(&greedy, &board[0])["state"], "live");
	for w in wallets.iter().map(|(_, _, w, _, _)| w).chain([&b, &greedy]) {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// The production delays
// ---------------------------------------------------------------------------

/// The specification's delays, run on the regtest chain's clock: a wallet
/// made with its defaults asks a 36-hour exit delay of its leaves, and the
/// operator's forfeits a 48-hour refund delay. A board exited: its claim is
/// refused by the node an hour before the exit delay has run from the
/// leaf's confirmation and taken after it, and the coin is `exited` once the
/// claim is final. A forfeit the operator published and never claimed: no
/// refund an hour before its delay has run, then the refund, final, and the
/// coin the wallet's on the chain. The watcher is on throughout.
#[tokio::test(flavor = "multi_thread")]
async fn an_exit_and_a_refund_run_at_the_production_delays() {
	use elements::hashes::Hash;
	let mut r = Running::start().await;
	let proxy = Proxy::start(&r.url());
	let x = r.x;
	let hour = 3_600u32;
	let spec = |w: &Arca, server: &str, node: &str| w.ok(&["create", "--server", server, "--node-url", node, "--node-user", "arca"]);
	let board = |w: &Arca, r: &mut Running| {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, x, 5_000_000);
	};

	// The exit at 36 hours.
	let e = Arca::new("P8E");
	let created = spec(&e, &r.url(), &r.node_url());
	let delay = created["exit_delay_units"].as_u64().unwrap() as u32 * 512;
	println!("P8 a wallet with its defaults: exit delay {} units ({} s), accepted {}", created["exit_delay_units"], delay,
		created["accepted_exit_delay_units"]);
	assert!((36 * hour..=36 * hour + 512).contains(&delay));
	board(&e, &mut r);
	r.produce().await;
	let leaf = e.ok(&["board", &x.to_string(), "2000000"])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || e.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	e.ok(&["sync"]);
	let xs = x.to_string();
	let exit_args = ["exit", leaf.as_str(), "--fee-asset", xs.as_str()];
	let first = e.ok(&exit_args);
	println!("P8 the exit: {}", first["state"]);
	r.produce().await;
	r.bury().await;
	let w = e.ok(&exit_args);
	assert_eq!(w["state"], "waiting", "{}", w);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, delay - hour));
	let w = e.ok(&exit_args);
	println!("P8 an hour before the exit delay has run: {} | {}", w["state"], w["next"]);
	assert_eq!(w["state"], "waiting", "{}", w);
	assert!(w["next"].as_str().unwrap_or("").contains("non-BIP68-final"), "{}", w);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 2 * hour));
	let c = e.ok(&exit_args);
	println!("P8 past it: {} {}", c["state"], c["claim"]);
	assert_eq!(c["state"], "claimed", "{}", c);
	r.produce().await;
	r.bury().await;
	e.ok(&["sync"]);
	assert_eq!(coin_of(&e, &leaf)["state"], "exited", "{}", coin_of(&e, &leaf));
	let paid = e.ok(&["balance"])["sequentia_onchain"][x.to_string()].as_str().unwrap().to_string();
	println!("P8 the board exited at 36 hours: {}; on-chain X {}", coin_of(&e, &leaf)["note"], paid);

	// The refund at 48 hours.
	let f = Arca::new("P8F");
	spec(&f, &proxy.url, &r.node_url());
	board(&f, &mut r);
	r.produce().await;
	let given = f.ok(&["board", &x.to_string(), "2000000"])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || f.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	f.ok(&["sync"]);
	let pid = f.ok(&["participate"])["participation"].as_str().unwrap().to_string();
	final_round(&r).await;
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/forfeit_leaves" && status == 200 {
			v["preimage"] = Value::Null;
		}
		None
	})));
	let s = f.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "forfeiting", "{}", s);
	let mut forfeit = None;
	for _ in 0..60 {
		let log = r.server.store.watcher_log().await.unwrap();
		forfeit = log.iter().find(|w| w.kind == "forfeit").map(|w| elements::Txid::from_byte_array(w.txid));
		assert!(!log.iter().any(|w| w.kind == "claim"), "the server is stopped before any claim");
		if forfeit.is_some() && log.iter().any(|w| w.kind == "issue") {
			break;
		}
		if forfeit.is_none() {
			r.produce().await;
		}
		tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
	}
	let forfeit = forfeit.expect("the watcher publishes the forfeit");
	r.server.stop();
	r.produce().await;
	r.bury().await;
	let (units, _, _, _) = stored_status(&r, &pid);
	let refund_delay = units as u32 * 512;
	println!("P8 the operator's forfeit {} published, the operator stopped; its refund delay {} units ({} s)", forfeit, units, refund_delay);
	assert!((48 * hour..=48 * hour + 512).contains(&refund_delay));
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, refund_delay - hour));
	let s = f.ok(&["sync"]);
	let fo = s["forfeits"].as_array().unwrap().iter().find(|x| x["leaf_id"] == given.as_str()).cloned().unwrap();
	println!("P8 an hour before the refund delay has run: {} | {}", fo["state"], fo["note"]);
	assert_eq!(fo["state"], "published", "{}", fo);
	assert!(fo.get("refund").is_none());
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 2 * hour));
	let s = f.ok(&["sync"]);
	let fo = s["forfeits"].as_array().unwrap().iter().find(|x| x["leaf_id"] == given.as_str()).cloned().unwrap();
	println!("P8 past it: {} {}", fo["state"], fo["refund"]);
	assert_eq!(fo["state"], "refunding", "{}", fo);
	r.produce().await;
	r.bury().await;
	f.ok(&["sync"]);
	f.ok(&["sync"]);
	println!("P8 the forfeit refunded at 48 hours: {} | {}", coin_of(&f, &given)["state"], coin_of(&f, &given)["note"]);
	assert_eq!(coin_of(&f, &given)["state"], "exited", "{}", coin_of(&f, &given));
	for w in [&e, &f] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// D57: the wallet keeps its coins alive by itself
// ---------------------------------------------------------------------------

/// Moves the chain's median time on to at least `t`, and the server with it.
async fn d57_to(r: &Running, t: u32) {
	let now = common::node::median_time(&r.rt);
	if t > now {
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, t - now));
	}
	r.synced().await;
}

/// The latest exit date (`exit_by`, a median time) among `leaves`, as `w`'s
/// `coins` shows them; every one must show one.
fn d57_latest_exit_by(w: &Arca, leaves: &[String]) -> u32 {
	let coins = w.ok(&["coins"]);
	leaves.iter().map(|l| {
		let c = coins.as_array().unwrap().iter().find(|c| c["leaf_id"] == l.as_str()).unwrap_or_else(|| panic!("no coin {}", l));
		c["exit_by"].as_u64().unwrap_or_else(|| panic!("coin {} shows no exit date: {}", l, c)) as u32
	}).max().unwrap()
}

/// The states of `leaves` in `w`.
fn d57_states(w: &Arca, leaves: &[String]) -> Vec<String> {
	let coins = w.ok(&["coins"]);
	leaves.iter().map(|l| coins.as_array().unwrap().iter().find(|c| c["leaf_id"] == l.as_str())
		.map(|c| c["state"].as_str().unwrap_or("").to_string()).unwrap_or_default()).collect()
}

/// Runs `w`'s `sync` with blocks, the exit delay waited out and the parent
/// chain burying them, until every coin of `leaves` is `exited`: its claim
/// final. Returns the median time then.
async fn d57_home(r: &Running, w: &Arca, leaves: &[String]) -> u32 {
	for round in 0..8 {
		r.produce().await;
		w.ok(&["sync"]);
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 600));
		r.produce().await;
		r.bury().await;
		r.synced().await;
		w.ok(&["sync"]);
		let states = d57_states(w, leaves);
		println!("D57 {}'s coins after {} round(s) of blocks and syncs: {:?}", w.name, round + 1, states);
		if states.iter().all(|s| s == "exited") {
			return common::node::median_time(&r.rt);
		}
	}
	panic!("{}'s coins did not all come home: {:?} {}", w.name, d57_states(w, leaves), w.ok(&["coins"]));
}

/// D57, R7g's U1, U5 and U6 turned around (F2). The operator loses its one
/// keeper for good: it answers every witness and `info`, builds rounds, and
/// co-signs nothing. A holds two batch leaves it paid B from (L1 and L2,
/// `sending`: a payment spends the coins furthest from their exit date
/// first), a board it never touches (bS), and a board in asset Y whose refresh ran in a round its
/// forfeit could not be co-signed for (bF, `forfeited`; the operator takes
/// that participation's forfeits until bF's exit deadline, so it is still
/// issued). A syncs once a day in its coins' last three days before their
/// exit date, and no more: at three days nothing moves; at two days `sync`
/// asks for the refresh of bS, which a round takes and nobody co-signs; at
/// one day every coin
/// goes on the chain, each paying what its own reserves cannot with a fee
/// coin the wallet chooses (Y is not taken for fees: an X coin pays bF's),
/// and is claimed, every claim final before the first expiry: nothing of
/// A's is left for the operator's sweep.
#[tokio::test(flavor = "multi_thread")]
async fn d57_an_operator_that_lost_its_keeper_has_every_coin_brought_home_before_its_expiry() {
	let mut r = Running::start_kept(1, None).await;
	let url = r.url();
	let (x, y) = (r.x, r.y);
	let (a, b) = (Arca::new("D57KA"), Arca::new("D57KB"));
	let boards = boarded(&mut r, &a, &url, &[(x, 1_000_000), (x, 1_100_000), (x, 3_000_000)]).await;
	b.ok(&create_args(&url, &r.node_url()));
	// A board in Y, which the node does not take for fees: its fee in X.
	let to_a = script(&a.ok(&["address"]));
	r.pay_to(to_a, y, 2_000_000);
	r.produce().await;
	let bf = a.ok(&["board", &y.to_string(), "1000000", "--fee-asset", &x.to_string()])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the Y board to be credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
	assert_eq!(coin_of(&a, &bf)["state"], "live");
	let bs = boards[2].clone();
	// L1 and L2: refreshes of the first two boards, released while the
	// keeper still answers.
	a.ok(&["participate", "--leaf", &boards[0]]);
	a.ok(&["participate", "--leaf", &boards[1]]);
	let r1 = final_round(&r).await;
	let s = a.ok(&["sync"]);
	let mut news: Vec<(String, String)> = s["participations"].as_array().unwrap().iter()
		.map(|p| (p["new_leaves"][0]["leaf_id"].as_str().expect("a new leaf").to_string(), p["new_leaves"][0]["value"].as_str().unwrap().to_string()))
		.collect();
	news.sort_by_key(|(_, v)| v.parse::<u64>().unwrap());
	let (l1, l2) = (news[0].0.clone(), news[1].0.clone());
	println!("D57 A's batch leaves of round {}: L1 {} and L2 {}", r1.txid(), &l1[..8], &l2[..8]);

	// The keeper is gone for good.
	r.keepers[0].halt();
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let (ok, v) = a.run(&["send", &req, "--amount", "500000", "--asset", &x.to_string()]);
	println!("D57 A pays B 500000 with the keeper gone: ok={} {}", ok, v["error"]["message"]);
	assert!(!ok && v["error"]["message"].as_str().unwrap_or("").contains("keepers_unavailable"), "{}", v);
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let (ok, v) = a.run(&["send", &req, "--amount", "400000", "--asset", &x.to_string()]);
	assert!(!ok && v["error"]["message"].as_str().unwrap_or("").contains("keepers_unavailable"), "{}", v);
	a.ok(&["participate", "--leaf", &bf]);
	let r2 = final_round(&r).await;
	let s = a.ok(&["sync"]);
	println!("D57 bF's refresh in round {}: {}", r2.txid(), s["participations"]);
	let all = vec![l1.clone(), l2.clone(), bs.clone(), bf.clone()];
	let states = d57_states(&a, &all);
	println!("D57 L1, L2, bS, bF: {:?}", states);
	// A payment spends the coins furthest from their exit date first: the
	// two batch leaves, younger than the boards. The board bS is untouched.
	assert_eq!(states, vec!["sending", "sending", "live", "forfeited"]);

	let by = d57_latest_exit_by(&a, &all);
	let first_expiry = a.ok(&["coins"]).as_array().unwrap().iter().filter(|c| all.contains(&c["leaf_id"].as_str().unwrap_or("").to_string()))
		.map(|c| c["expiry"].as_u64().unwrap() as u32).min().unwrap();
	println!("D57 the latest exit date {}; the first expiry {}", by, first_expiry);

	// Three days before: shown, nothing moves. bF's participation, its
	// forfeit never co-signed, is still issued at the server, which takes its
	// forfeits until bF's exit deadline: bF stays forfeited.
	d57_to(&r, by - 3 * 86_400 + 600).await;
	let s = a.ok(&["sync"]);
	println!("D57 A three days before: participations {} | home {}", s["participations"], s["home"]);
	assert!(s["witness"]["error"].is_null() && s["unreachable"].is_null(), "the operator answers: {}", s);
	for h in s["home"].as_array().expect("the coins in their last three days are shown") {
		assert!(h["exit"].is_null(), "nothing is taken three days before: {}", h);
		assert!(h["refresh_from"].is_u64() && h["home_from"].is_u64() && h["exit_by"].is_u64(), "{}", h);
	}
	assert!(s["participations"].as_array().unwrap().iter().all(|p| p["state"] != "expired"), "{}", s["participations"]);
	assert_eq!(d57_states(&a, &all), vec!["sending", "sending", "live", "forfeited"]);
	let c = coin_of(&a, &bs);
	println!("D57 bS three days before: {}", c);
	assert_eq!(c["home_from"].as_u64(), Some(c["exit_by"].as_u64().unwrap() - 86_400));
	assert!(c["sync"].as_str().unwrap().contains("at least once a day"), "{}", c);
	assert!(s["schedule"]["due"].is_boolean() && s["schedule"]["next_sync_at"].is_u64(), "{}", s["schedule"]);

	// Two days before: the refresh window. The refresh of bS is asked for
	// and runs in a round; nobody co-signs its forfeits.
	d57_to(&r, by - 2 * 86_400 + 600).await;
	let s = a.ok(&["sync"]);
	println!("D57 A two days before: refresh {}", s["refresh"]);
	for l in [&bs] {
		let asked = s["refresh"].as_array().expect("sync asks for the refreshes").iter().find(|x| x["leaf_id"] == l.as_str()).cloned()
			.unwrap_or_else(|| panic!("{} is refreshed: {}", l, s));
		assert_eq!(asked["state"], "pending", "{}", asked);
		assert_eq!(asked["fees"], json!([]), "free in the window: {}", asked);
	}
	assert_eq!(d57_states(&a, &all), vec!["sending", "sending", "given", "forfeited"]);
	let r3 = final_round(&r).await;
	println!("D57 the operator's round {} takes the refreshes", r3.txid());

	// One day before: every coin goes on the chain.
	d57_to(&r, by - 86_400 + 600).await;
	let s = a.ok(&["sync"]);
	println!("D57 A a day before: participations {} | home {}", s["participations"], s["home"]);
	let home = s["home"].as_array().unwrap();
	for l in &all {
		let h = home.iter().find(|h| h["leaf_id"] == l.as_str()).unwrap_or_else(|| panic!("{} goes home: {}", l, s["home"]));
		assert!(h["exit"]["error"].is_null() && h["exit"]["state"].is_string(), "{} is on its way: {}", l, h);
	}
	assert_eq!(d57_states(&a, &all), vec!["exiting"; 4]);
	let bf_note = coin_of(&a, &bf)["note"].as_str().unwrap().to_string();
	assert!(bf_note.contains("its refresh has not completed a day before its exit date"), "{}", bf_note);
	let at = d57_home(&r, &a, &all).await;
	println!("D57 every coin of A exited, its claim final, at median time {}: {} s before the first expiry", at, first_expiry as i64 - at as i64);
	assert!(at < first_expiry, "home before the expiry");
	// bF's exit paid its fees with an X coin: Y is not taken for fees.
	let rec = a.ok(&["coins"]);
	let bf_row = rec.as_array().unwrap().iter().find(|c| c["leaf_id"] == bf.as_str()).unwrap();
	println!("D57 bF: {}", bf_row);
	// Past the expiry and the notice, the operator's watcher sweeps what is
	// left of its batches: nothing of A's.
	let r1_batch = elements::OutPoint::new(r1.txid(), 0);
	d57_to(&r, first_expiry + 2 * 86_400).await;
	for _ in 0..3 {
		let _ = r.server.watcher.pass().await;
		r.produce().await;
		r.synced().await;
	}
	let after = d57_states(&a, &all);
	println!("D57 after the sweep's time: {:?} | round 1's first output spent by {:?}", after,
		spender_of(&r, &r1_batch).map(|t| t.txid()));
	assert_eq!(after, vec!["exited"; 4]);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// D57, R7g's U3 turned around (F2), and a wallet that syncs once. The
/// operator answers and builds no round. A's board: at two days before its
/// exit date `sync` asks for its refresh, which waits for a round; at one
/// day before, unrefreshed, the coin goes on the chain (the wallet withdraws
/// from the participation), and at its exit date the operator's next pass
/// voids the participation, no round built. W never syncs until a day
/// before the exit date of its board and of a batch leaf it holds, then
/// once: both go on the chain, and come home.
#[tokio::test(flavor = "multi_thread")]
async fn d57_no_round_built_and_a_wallet_that_syncs_once_bring_every_coin_home() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let (a, w) = (Arca::new("D57NA"), Arca::new("D57NW"));
	let a_boards = boarded(&mut r, &a, &url, &[(x, 1_500_000)]).await;
	let w_boards = boarded(&mut r, &w, &url, &[(x, 1_000_000), (x, 1_200_000)]).await;
	// W's batch leaf, from a refresh of its second board.
	w.ok(&["participate", "--leaf", &w_boards[1]]);
	final_round(&r).await;
	let s = w.ok(&["sync"]);
	let wl = s["participations"][0]["new_leaves"][0]["leaf_id"].as_str().expect("W's new leaf").to_string();
	let ab = a_boards[0].clone();
	let w_coins = vec![w_boards[0].clone(), wl.clone()];
	let by_a = d57_latest_exit_by(&a, std::slice::from_ref(&ab));
	let by_w = d57_latest_exit_by(&w, &w_coins);

	// Two days before A's exit date: the refresh is asked for, and waits.
	d57_to(&r, by_a - 2 * 86_400 + 600).await;
	let s = a.ok(&["sync"]);
	println!("D57 A two days before: refresh {} | home {}", s["refresh"], s["home"]);
	let pid = s["refresh"][0]["participation"].as_str().expect("A's refresh is asked for").to_string();
	assert_eq!(s["refresh"][0]["state"], "pending");
	assert_eq!(coin_of(&a, &ab)["state"], "given");
	assert!(s["home"][0]["exit"].is_null(), "nothing goes on the chain yet: {}", s["home"]);
	// A day before: no round came; the coin goes home.
	d57_to(&r, by_a - 86_400 + 600).await;
	let s = a.ok(&["sync"]);
	println!("D57 A a day before: participations {} | home {}", s["participations"], s["home"]);
	assert_eq!(s["participations"][0]["state"], "pending", "still no round: {}", s["participations"]);
	let h = &s["home"][0];
	assert!(h["exit"]["state"].is_string() && h["exit"]["error"].is_null(), "{}", h);
	let c = coin_of(&a, &ab);
	assert_eq!(c["state"], "exiting");
	assert!(c["note"].as_str().unwrap().contains("its refresh has not completed a day before its exit date"), "{}", c);
	assert!(c["note"].as_str().unwrap().contains("it was given"), "{}", c);
	let participations = a.ok(&["participations"]);
	assert_eq!(participations[0]["state"], "withdrawn", "{}", participations);

	// W: one sync, a day before its coins' exit date, its first since its
	// refresh.
	d57_to(&r, by_w - 86_400 + 600).await;
	assert!(common::node::median_time(&r.rt) < by_w.min(d57_latest_exit_by(&w, &w_coins[..1])), "W syncs before its exit dates");
	assert_eq!(d57_states(&w, &w_coins), vec!["live", "live"]);
	let s = w.ok(&["sync"]);
	println!("D57 W's one sync a day before: home {}", s["home"]);
	for l in &w_coins {
		let h = s["home"].as_array().unwrap().iter().find(|h| h["leaf_id"] == l.as_str()).unwrap_or_else(|| panic!("{}", s["home"]));
		assert!(h["exit"]["state"].is_string() && h["exit"]["error"].is_null(), "{}", h);
	}
	let w_first_expiry = w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| w_coins.contains(&c["leaf_id"].as_str().unwrap_or("").to_string()))
		.map(|c| c["expiry"].as_u64().unwrap() as u32).min().unwrap();

	// At the exit date, the operator voids A's participation, no round built.
	d57_to(&r, by_a + 600).await;
	r.server.rounds.pass().await.unwrap();
	let id: [u8; 32] = unhex(&pid).try_into().unwrap();
	let p = r.server.store.participation(&id).await.unwrap().unwrap();
	println!("D57 A's participation at the server past the exit date: {:?} ({:?})", p.state, p.void_reason);
	assert_eq!(p.state, server::store::ParticipationState::Void);
	let at = d57_home(&r, &a, std::slice::from_ref(&ab)).await;
	println!("D57 A's board home at median time {}", at);
	let at = d57_home(&r, &w, &w_coins).await;
	println!("D57 W's coins home at median time {}, {} s before their first expiry", at, w_first_expiry as i64 - at as i64);
	assert!(at < w_first_expiry);
	for wl in [&a, &w] {
		let _ = std::fs::remove_dir_all(&wl.dir);
	}
}

/// D57, R7g's U4 turned around (F4). One `sync` in the free window at the
/// moment the witness budget answers `429 rate_limited`, three times running,
/// and the wallet's default patience: the witness is tried again and
/// succeeds, nothing goes on the chain, the refresh of both boards is asked
/// for, for nothing, and completes in the operator's next round.
#[tokio::test(flavor = "multi_thread")]
async fn d57_a_rate_limited_witness_exits_nothing_and_the_free_refresh_completes() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let proxy = Proxy::start(&url);
	let a = Arca::new("D57RA");
	let boards = boarded(&mut r, &a, &proxy.url.clone(), &[(x, 2_000_000), (x, 1_000_000)]).await;
	let by = d57_latest_exit_by(&a, &boards);
	d57_to(&r, by - 2 * 86_400 + 3_600).await;
	let refused = Arc::new(std::sync::atomic::AtomicUsize::new(0));
	let count = refused.clone();
	proxy.rewrite(Some(Arc::new(move |path: &str, _: &Value, _: u16, v: &mut Value| {
		if path == "/v1/witness" && count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 3 {
			*v = json!({"error": {"code": "rate_limited", "message": "too many witnesses"}});
			return Some(429);
		}
		None
	})));
	a.patience.set(bark::arca::WITNESS_PATIENCE.as_secs());
	let s = a.ok(&["sync"]);
	a.patience.set(common::cli::TEST_PATIENCE);
	println!("D57 A's sync, the witness answered 429 three times: witness {} | refresh {} | home {}", s["witness"], s["refresh"], s["home"]);
	assert!(refused.load(std::sync::atomic::Ordering::SeqCst) >= 3);
	assert!(s["witness"]["error"].is_null() && s["witness"]["tries"].as_u64().unwrap_or(1) >= 2, "tried again: {}", s["witness"]);
	assert!(s["unreachable"].is_null(), "{}", s);
	for h in s["home"].as_array().cloned().unwrap_or_default() {
		assert!(h["exit"].is_null(), "nothing goes on the chain: {}", h);
	}
	let asked = s["refresh"].as_array().expect("both refreshes are asked for");
	assert_eq!(asked.len(), 2, "{}", s["refresh"]);
	assert!(asked.iter().all(|x| x["state"] == "pending" && x["fees"] == json!([])), "free: {}", s["refresh"]);
	proxy.rewrite(None);
	let round = final_round(&r).await;
	let s = a.ok(&["sync"]);
	println!("D57 A's sync after round {}: {}", round.txid(), s["participations"]);
	let news: Vec<String> = s["participations"].as_array().unwrap().iter().map(|p| {
		assert_eq!(p["state"], "released", "{}", p);
		p["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string()
	}).collect();
	assert_eq!(d57_states(&a, &boards), vec!["spent", "spent"]);
	assert_eq!(d57_states(&a, &news), vec!["live", "live"]);
	assert!(a.ok(&["coins"]).as_array().unwrap().iter().all(|c| c["state"] != "exiting"), "nothing went on the chain");
	let sched = &s["schedule"];
	let next = sched["next_sync_at"].as_u64().unwrap() as u32;
	let l = coin_of(&a, &news[0]);
	println!("D57 the schedule after the refresh: next sync at {} | new leaf {} refresh_from {}", next, &news[0][..8], l["refresh_from"]);
	assert_eq!(sched["due"], false, "{}", sched);
	assert!(next >= by + 20 * 86_400, "the next sync is due in the new leaves' window, weeks on: {}", sched);
	let _ = std::fs::remove_dir_all(&a.dir);
}

/// D57: a coin whose asset the node has delisted for fees comes home with a
/// fee coin of the wallet's in an asset the node takes, chosen by the
/// wallet; a wallet holding none says so when it takes such a coin and on
/// every listing, and its coin comes home once it holds one.
#[tokio::test(flavor = "multi_thread")]
async fn d57_a_coin_in_a_delisted_asset_comes_home_with_a_fee_coin_the_wallet_chooses() {
	let mut r = Running::start().await;
	let url = r.url();
	let (x, y) = (r.x, r.y);
	let (a, z) = (Arca::new("D57FA"), Arca::new("D57FZ"));
	let a_boards = boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	let z_boards = boarded(&mut r, &z, &url, &[(x, 1_000_000)]).await;
	// A holds Y on the chain; the node takes Y for fees and delists X.
	let to_a = script(&a.ok(&["address"]));
	r.pay_to(to_a, y, 2_000_000);
	r.produce().await;
	let rates: Value = rpc(&r, "getfeeexchangerates", &[]);
	let mut rates = rates.as_object().unwrap().clone();
	rates.remove(&x.to_string());
	rates.insert(y.to_string(), json!(100_000_000));
	rpc(&r, "setfeeexchangerates", &[Value::Object(rates)]);
	println!("D57 the node's fee assets now: {}", rpc(&r, "getfeeexchangerates", &[]));
	// The floors the operator publishes are read again after five seconds.
	tokio::time::sleep(std::time::Duration::from_secs(6)).await;
	let ca = coin_of(&a, &a_boards[0]);
	let cz = coin_of(&z, &z_boards[0]);
	println!("D57 A's board: {}\nD57 Z's board: {}", ca["exit_fee"], cz["exit_fee"]);
	assert_eq!(ca["exit_fee"]["fee_coin"], "needed");
	assert_eq!(ca["exit_fee"]["asset"], y.to_string(), "the one asset A holds that the node takes");
	assert_eq!(cz["exit_fee"]["fee_coin"], "missing");
	assert!(cz["exit_fee"]["note"].as_str().unwrap().contains("cannot come home until the wallet holds an on-chain coin"), "{}", cz);
	// A pays Z out of round in X: Z says so when it takes the coin.
	let req = z.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req, "--amount", "300000", "--asset", &x.to_string()]);
	let s = z.ok(&["sync"]);
	let took = &s["mailbox"]["accepted"][0];
	println!("D57 Z takes A's coin: {}", took);
	assert_eq!(took["exit_fee"]["fee_coin"], "missing", "{}", took);
	let zc = took["leaf_id"].as_str().unwrap().to_string();

	// A day before the exit dates.
	let mut a_coins: Vec<String> = a.ok(&["coins"]).as_array().unwrap().iter()
		.filter(|c| c["state"] == "live").map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
	a_coins.sort();
	let z_coins = vec![z_boards[0].clone(), zc.clone()];
	let by = d57_latest_exit_by(&a, &a_coins).max(d57_latest_exit_by(&z, &z_coins));
	d57_to(&r, by - 86_400 + 600).await;
	let s = z.ok(&["sync"]);
	println!("D57 Z's sync a day before, no fee coin: {}", s["home"]);
	for h in s["home"].as_array().unwrap() {
		assert!(h["exit"]["error"].as_str().unwrap_or("").contains("cannot come home until the wallet holds an on-chain coin"), "{}", h);
	}
	assert_eq!(d57_states(&z, &z_coins), vec!["live", "live"], "nothing went: {}", z.ok(&["coins"]));
	// Z gets a Y coin: its next sync takes both home, paid in Y.
	let to_z = script(&z.ok(&["address"]));
	r.pay_to(to_z, y, 1_000_000);
	r.produce().await;
	let s = z.ok(&["sync"]);
	println!("D57 Z's sync with a Y coin: {}", s["home"]);
	for h in s["home"].as_array().unwrap() {
		assert!(h["exit"]["error"].is_null() && h["exit"]["state"].is_string(), "{}", h);
		let fees: Vec<&Value> = h["exit"]["broadcast"].as_array().unwrap().iter().flat_map(|b| b["fee"].as_array().unwrap().iter()).collect();
		assert!(!fees.is_empty() && fees.iter().all(|f| f["asset"] == y.to_string()), "every fee in Y: {}", h["exit"]);
	}
	// A's change rests on the steps Z's exit published: A's sync finds its
	// leaf on the chain and goes on from there (its re-check, or its home).
	let s = a.ok(&["sync"]);
	println!("D57 A's sync a day before: recheck {} | home {}", s["recheck"]["changes"], s["home"]);
	assert_eq!(d57_states(&a, &a_coins), vec!["exiting"; a_coins.len()], "{}", s);
	d57_home(&r, &a, &a_coins).await;
	d57_home(&r, &z, &z_coins).await;
	for w in [&a, &z] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// D57: past its exit date, and past its first expiry, the wallet goes on
/// bringing a coin home until the chain says it is gone: a batch is swept
/// only once its token has waited the notice. A's batch leaf, its wallet
/// away until after the leaf's expiry: its first `sync` then unrolls the
/// leaf ahead of the sweep, and the coin comes home. B's batch leaf, its
/// wallet away until the operator's watcher has swept the batch: its `sync`
/// shows the coin lost, with the sweep that took it, once that is final.
#[tokio::test(flavor = "multi_thread")]
async fn d57_past_its_expiry_a_coin_goes_on_until_the_chain_says_it_is_gone() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let (a, b) = (Arca::new("D57XA"), Arca::new("D57XB"));
	boarded(&mut r, &a, &url, &[(x, 1_000_000)]).await;
	a.ok(&["participate"]);
	let ra = final_round(&r).await;
	let la = a.ok(&["sync"])["participations"][0]["new_leaves"][0]["leaf_id"].as_str().expect("A's leaf").to_string();
	boarded(&mut r, &b, &url, &[(x, 1_000_000)]).await;
	b.ok(&["participate"]);
	let rb = final_round(&r).await;
	let lb = b.ok(&["sync"])["participations"][0]["new_leaves"][0]["leaf_id"].as_str().expect("B's leaf").to_string();
	let ea = coin_of(&a, &la)["expiry"].as_u64().unwrap() as u32;
	let eb = coin_of(&b, &lb)["expiry"].as_u64().unwrap() as u32;
	let CoinRecord::Leaf { record, .. } = record_of(&b, &lb) else { panic!("a batch leaf") };
	let notice = record.schedule.notice.seconds() as u32;
	println!("D57 A's leaf {} of round {} expires at {}; B's {} of round {} at {}; the notice {} s", &la[..8], ra.txid(), ea, &lb[..8],
		rb.txid(), eb, notice);

	// Past A's expiry, the notice not run: A's first sync since.
	d57_to(&r, ea.max(eb) + 600).await;
	for _ in 0..2 {
		let _ = r.server.watcher.pass().await;
		r.produce().await;
		r.synced().await;
	}
	let s = a.ok(&["sync"]);
	// Its re-check, or its home, starts the exit: either way it goes ahead.
	let started: Vec<Value> = s["recheck"]["changes"].as_array().into_iter().flatten()
		.chain(s["home"].as_array().into_iter().flatten()).filter(|c| c["leaf_id"] == la.as_str()).map(|c| c["exit"].clone()).collect();
	println!("D57 A's sync past its leaf's expiry: {:?}", started);
	assert!(started.iter().any(|e| e["error"].is_null() && e["broadcast"].as_array().is_some_and(|b| !b.is_empty())),
		"the wallet goes on past the expiry, and unrolls the leaf: {}", s);
	assert_eq!(coin_of(&a, &la)["state"], "exiting");
	let at = d57_home(&r, &a, std::slice::from_ref(&la)).await;
	println!("D57 A's leaf home at median time {}, {} s past its expiry, {} s before the notice runs out", at, at - ea,
		(ea + notice) as i64 - at as i64);
	assert!(at < ea + notice);

	// Past B's expiry and the notice: the watcher sweeps B's batch.
	d57_to(&r, eb + notice + 600).await;
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
	println!("D57 B's batch output {} swept by {}", batch_at, sweep.txid());
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let s = b.ok(&["sync"]);
	println!("D57 B's sync after the sweep: home {}", s["home"]);
	let c = coin_of(&b, &lb);
	println!("D57 B's leaf: {} | {}", c["state"], c["note"]);
	assert_eq!(c["state"], "lost", "{}", c);
	assert!(c["note"].as_str().unwrap().contains(&sweep.txid().to_string()) && c["note"].as_str().unwrap().contains("sweep"), "{}", c);
	let s = b.ok(&["sync"]);
	assert!(s["home"].as_array().is_none_or(|h| h.iter().all(|x| x["leaf_id"] != lb.as_str())), "a lost coin is no longer taken: {}", s);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// R7g's KA, its second half turned around (F5). An operator with one
/// keeper co-signs a payment; its signer's record is compacted, and its
/// first line edited to name no keeper, the carried hash computed again (no
/// key needed): the signer starts on it without the keeper, every running
/// hash the one the database knows. `arcad`, which pinned the keeper set in
/// its database the first time it read it, goes on showing that set in
/// `info` while it runs, so no wallet made now pins "no keeper". Once it reads
/// the swapped signer's keepers it stops serving, every call answered
/// `signer_replaced` with the reason; and a new start against that signer is
/// refused, naming both sets.
#[tokio::test(flavor = "multi_thread")]
async fn arcad_refuses_a_signer_whose_record_names_other_keepers() {
	use elements::hashes::{sha256, Hash, HashEngine};
	let mut r = Running::start_kept(1, None).await;
	let url = r.url();
	let x = r.x;
	let (a, b) = (Arca::new("PinA"), Arca::new("PinB"));
	boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	b.ok(&create_args(&url, &r.node_url()));
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	a.ok(&["send", &req, "--amount", "600000", "--asset", &x.to_string()]);
	let pinned = info_of(&r)["keepers"].clone();
	println!("PK the operator's keepers, pinned: {}", pinned);
	assert_eq!(pinned["required"], 1);

	// The record compacted (nothing dropped), its keepers field edited.
	r.signer.halt();
	let record = r.signer.record();
	let key = r.signer.dir.join("operator.key");
	let drop_file = r.signer.dir.join("expired.salts");
	std::fs::write(&drop_file, "").unwrap();
	let compacted = r.signer.dir.join("signer.record.new");
	let genesis = r.rt.client().genesis_hash().unwrap();
	let out = std::process::Command::new(common::signer::signer_exe())
		.args(["--key-file", key.to_str().unwrap(), "--genesis", &genesis.to_string(), "--record", record.to_str().unwrap(),
			"--compact-into", compacted.to_str().unwrap(), "--drop-salts", drop_file.to_str().unwrap()])
		.output().unwrap();
	assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
	let text = std::fs::read_to_string(&compacted).unwrap();
	let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
	let header: Vec<String> = lines[0].split(' ').map(str::to_string).collect();
	assert!(header[4].starts_with("keepers=1:"), "{}", lines[0]);
	let carried: usize = header[7].parse().unwrap();
	let mut e = sha256::Hash::engine();
	e.input(server::signer::RECORD_CARRIED_TAG);
	e.input(b"keepers=none\n");
	for l in &lines[1..1 + carried] {
		e.input(l.as_bytes());
		e.input(b"\n");
	}
	let mut edited = header.clone();
	edited[4] = "keepers=none".into();
	edited[8] = hex(&sha256::Hash::from_engine(e).to_byte_array());
	lines[0] = edited.join(" ");
	std::fs::write(&record, format!("{}\n", lines.join("\n"))).unwrap();
	println!("PK the compacted record, its first line edited: {}", lines[0]);
	r.signer.set_extra(vec![]);
	tokio::task::block_in_place(|| r.signer.try_resume(genesis)).expect("the edited record opens: its hashes are the database's");
	println!("PK the signer on it, without a keeper: {}", r.signer.log().lines().last().unwrap_or(""));

	// The running server stops serving, with the reason, once it reads the
	// swapped signer's keepers (at `info`, and once a minute): it never
	// shows the edited record's set.
	tokio::time::sleep(std::time::Duration::from_secs(6)).await;
	let first = info_of(&r);
	println!("PK the running server's info, the signer swapped: keepers {} | error {}", first["keepers"], first["error"]);
	assert!(first["keepers"] == pinned || first["error"]["code"] == "signer_replaced", "{}", first);
	let then = info_of(&r);
	println!("PK the running server, asked again: {}", then);
	assert_eq!(then["error"]["code"], "signer_replaced", "{}", then);
	assert!(then["error"]["message"].as_str().unwrap().contains("another record"), "{}", then);
	let (ok, v) = a.run(&["sync"]);
	println!("PK A's sync: ok={} witness {} | unreachable {}", ok, v["witness"], v["unreachable"]);
	assert!(v["unreachable"]["why"].as_str().unwrap_or("").contains("signer_replaced"), "{}", v);
	// A new start against the signer: refused.
	r.server.stop();
	let refused = server::server::Server::start(&r.config).await.err().map(|e| e.to_string())
		.expect("arcad refuses a signer naming another keeper set");
	println!("PK arcad started again: {}", refused);
	assert!(refused.contains("this server pinned") && refused.contains("another record"), "{}", refused);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A batch leaf's exit at the specification's delays, through `arca`, the
/// watcher on, the clock driven. G's wallet, made with its defaults, asks
/// for 36-hour exit delays: its leaf of a round is unrolled (every node and
/// the entry), the claim refused by the node an hour before the delay has
/// run from the leaf's confirmation and taken after it, `exited` once final.
/// And the operator's answer to a stale exit inside that delay: H refreshes
/// its leaf (released, the new leaf H's), and a copy of H's wallet from
/// before the refresh unrolls the old leaf; the watcher publishes H's
/// forfeit and claims it, revealing the preimage, hours before the delay has
/// run, and the copy's claim after it is refused by the node, the leaf spent
/// by the forfeit, while H holds its new leaf.
#[tokio::test(flavor = "multi_thread")]
async fn a_batch_leafs_exit_and_the_answer_to_a_stale_one_run_at_the_production_delays() {
	use elements::hashes::Hash;
	let mut r = Running::start().await;
	let x = r.x;
	let hour = 3_600u32;
	let url = r.url();
	let spec = |w: &Arca, r: &Running| w.ok(&["create", "--server", &url, "--node-url", &r.node_url(), "--node-user", "arca"]);
	let leaf_of = |r: &mut Running, w: &Arca| {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, x, 5_000_000);
	};
	let (g, h) = (Arca::new("P9G"), Arca::new("P9H"));
	let created = spec(&g, &r);
	let delay = created["exit_delay_units"].as_u64().unwrap() as u32 * 512;
	assert!((36 * hour..=36 * hour + 512).contains(&delay), "{}", created);
	spec(&h, &r);
	for w in [&g, &h] {
		leaf_of(&mut r, w);
	}
	r.produce().await;
	let gb = g.ok(&["board", &x.to_string(), "2000000"])["leaf_id"].as_str().unwrap().to_string();
	let hb = h.ok(&["board", &x.to_string(), "2000000"])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards to be credited", || [&g, &h].iter().all(|w| w.ok(&["boards"])[0]["server"]["state"] == "credited")).await;
	g.ok(&["sync"]);
	h.ok(&["sync"]);
	g.ok(&["participate", "--leaf", &gb]);
	h.ok(&["participate", "--leaf", &hb]);
	let round = final_round(&r).await;
	let gl = g.ok(&["sync"])["participations"][0]["new_leaves"][0]["leaf_id"].as_str().expect("G's leaf").to_string();
	let hl = h.ok(&["sync"])["participations"][0]["new_leaves"][0]["leaf_id"].as_str().expect("H's leaf").to_string();
	let CoinRecord::Leaf { record, .. } = record_of(&g, &gl) else { panic!("a batch leaf") };
	println!("P9 G's leaf {} and H's {} of round {}; G's exit delay {} units ({} s), the notice {} units", &gl[..8], &hl[..8],
		round.txid(), record.exit_delay.units(), delay, record.schedule.notice.units());
	assert_eq!(record.exit_delay.seconds() as u32, delay);

	// G's exit: every node and the entry, then the claim at 36 hours.
	let first = g.ok(&["exit", &gl]);
	let steps = first["broadcast"].as_array().unwrap().len();
	println!("P9 G's exit: {} transaction(s) to the leaf: {}", steps, first["state"]);
	assert!(steps >= 2, "a node and the entry at least: {}", first);
	r.produce().await;
	r.bury().await;
	let w = g.ok(&["exit", &gl]);
	assert_eq!(w["state"], "waiting", "{}", w);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, delay - hour));
	let w = g.ok(&["exit", &gl]);
	println!("P9 an hour before the exit delay has run: {} | {}", w["state"], w["next"]);
	assert_eq!(w["state"], "waiting", "{}", w);
	assert!(w["next"].as_str().unwrap_or("").contains("non-BIP68-final"), "{}", w);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 2 * hour));
	let c = g.ok(&["exit", &gl]);
	println!("P9 past it: {} {}", c["state"], c["claim"]);
	assert_eq!(c["state"], "claimed", "{}", c);
	r.produce().await;
	r.bury().await;
	g.ok(&["sync"]);
	assert_eq!(coin_of(&g, &gl)["state"], "exited", "{}", coin_of(&g, &gl));
	println!("P9 G's batch leaf exited at 36 hours: {}", coin_of(&g, &gl)["note"]);

	// H refreshes its leaf; a copy of H's wallet from before unrolls it.
	let stale = copy_wallet(&h, "P9Hstale");
	r.produce().await;
	r.bury().await;
	r.synced().await;
	h.ok(&["participate", "--leaf", &hl]);
	final_round(&r).await;
	let s = h.ok(&["sync"]);
	let h2 = s["participations"].as_array().unwrap().iter().find(|p| p["state"] == "released" && p["released"][0] == hl.as_str())
		.map(|p| p["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string()).unwrap_or_else(|| panic!("H's refresh is released: {}", s));
	assert_eq!(coin_of(&h, &hl)["state"], "spent");
	let e = stale.ok(&["exit", &hl]);
	println!("P9 the stale copy unrolls H's old leaf: {} ({} transactions)", e["state"], e["broadcast"].as_array().map(|b| b.len()).unwrap_or(0));
	assert!(e["error"].is_null() && e["state"] == "unrolling", "{}", e);
	r.produce().await;
	let unrolled_at = common::node::median_time(&r.rt);
	// The watcher answers: the forfeit, then its claim, an hour at a time.
	let id = hex(&LeafId::from_str(&hl).unwrap().0);
	let mut answered = None;
	for i in 0..24 {
		let _ = r.server.watcher.pass().await;
		r.produce().await;
		r.bury().await;
		r.synced().await;
		let log = r.server.store.watcher_log().await.unwrap();
		// The forfeit of H's old leaf, and the claim that spends it.
		let forfeit = log.iter().find(|w| w.kind == "forfeit" && hex(&w.subject) == id).map(|w| elements::Txid::from_byte_array(w.txid));
		let claim = forfeit.and_then(|f| log.iter().filter(|w| w.kind == "claim").find(|w| {
			let t: Transaction = elements::encode::deserialize(&w.tx).unwrap();
			t.input.iter().any(|i| i.previous_output.txid == f)
		}));
		if let (Some(f), Some(c)) = (forfeit, claim) {
			println!("P9 the forfeit {} and its claim {} ({})", f, elements::Txid::from_byte_array(c.txid), c.detail);
			answered = Some(common::node::median_time(&r.rt));
			println!("P9 the watcher's forfeit and claim, after {} hour(s)", i);
			break;
		}
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, hour));
	}
	for w in r.server.store.watcher_log().await.unwrap() {
		println!("P9 watcher log: {} {} {:?} {}", w.kind, elements::Txid::from_byte_array(w.txid), w.state, w.detail);
	}
	let answered = answered.expect("the watcher answers the stale exit with the forfeit and claims it");
	println!("P9 answered {} s after the stale unroll, {} s inside the exit delay", answered - unrolled_at, delay as i64 - (answered - unrolled_at) as i64);
	assert!(answered - unrolled_at < delay, "inside the exit delay");
	// Past the delay, the copy's claim: refused, the leaf spent by the forfeit.
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, delay));
	let c = stale.run(&["exit", &hl]);
	println!("P9 the stale copy's claim past the delay: ok={} {}", c.0, c.1);
	assert!(c.1["claim"].is_null(), "no claim of the forfeited leaf: {}", c.1);
	assert_eq!(coin_of(&h, &h2)["state"], "live", "H holds its new leaf");
	for w in [&g, &h, &stale] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// R7h F2, FW turned around (D58.4). Holders that sync once in each day of
/// their coins' last three days complete the free refresh `sync` asked for,
/// whatever the hour: the server takes a participation's forfeits until the
/// later of a day after its round was found final and its coins' exit
/// deadline. A and C board together (one exit date) and sync two days and
/// two hours before it, in the free window: `sync` asks for each refresh,
/// and the operator's round takes both and is final. A syncs again 25 hours
/// after asking, C 45 hours after (an hour before its exit date). Each sync
/// hands over the forfeits and is released, nothing goes on the chain, and
/// each wallet holds its new leaf, live.
#[tokio::test(flavor = "multi_thread")]
async fn d58_syncs_a_day_apart_complete_the_free_refresh() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let (a, c) = (Arca::new("D58FA"), Arca::new("D58FC"));
	let ab = boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	let cb = boarded(&mut r, &c, &url, &[(x, 2_000_000)]).await;
	let by = d57_latest_exit_by(&a, &ab).max(d57_latest_exit_by(&c, &cb));
	d57_to(&r, by - 2 * 86_400 + 2 * 3_600).await;
	let asked_at = common::node::median_time(&r.rt);
	for w in [&a, &c] {
		let s = w.ok(&["sync"]);
		println!("D58F {} asks at median time {}: refresh {}", w.name, asked_at, s["refresh"]);
		assert_eq!(s["refresh"][0]["state"], "pending", "{}", s["refresh"]);
	}
	let round = final_round(&r).await;
	println!("D58F the round {} final at median time {}", round.txid(), common::node::median_time(&r.rt));
	for (w, b, gap) in [(&a, &ab[0], 25u32), (&c, &cb[0], 45u32)] {
		d57_to(&r, asked_at + gap * 3_600).await;
		let now = common::node::median_time(&r.rt);
		let s = w.ok(&["sync"]);
		println!("D58F {} syncs {} h after asking (median time {}, {} s before its exit date): participations {} | home {}", w.name, gap,
			now, by as i64 - now as i64, s["participations"], s["home"]);
		assert!(now < by, "before the exit date");
		assert_eq!(s["participations"][0]["state"], "released", "{}: {}", w.name, s["participations"]);
		let home = s["home"].as_array().cloned().unwrap_or_default();
		assert!(home.iter().all(|h| h["exit"].is_null()), "{}: nothing goes on the chain: {}", w.name, s["home"]);
		let coins = w.ok(&["coins"]);
		let board = coin_of(w, b);
		println!("D58F {}'s board: {} | coins {}", w.name, board["state"], coins);
		assert_ne!(board["state"], "exiting", "{}", board);
		let new_live = coins.as_array().unwrap().iter().any(|k| k["kind"] == "batch" && k["state"] == "live");
		assert!(new_live, "{} holds its new leaf, live: {}", w.name, coins);
	}
	for w in [&a, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// R7h F3 (a), DH3 turned around (D59.1): the operator's half ten minutes
/// late, at the specification's delays. One keeper. A's board: `sync` asks
/// for its refresh in the free window and the round is final; the keeper
/// goes down. 23 hours later, in the coin's last day, A's sync hands over
/// the forfeit (recorded, held back) and, the refresh not complete, takes
/// the board home. Ten minutes on the keeper is back, the server's minute
/// task fills in the operator's half, and the next pass releases the
/// participation, whose forfeit the operator now holds whole: A's new leaf
/// is credited, the watcher answers A's exit with the forfeit, A holds its
/// new leaf live, at the server too, and pays B out of it. A day on the
/// participation is still released.
#[tokio::test(flavor = "multi_thread")]
async fn d59_a_forfeit_completed_late_releases_the_new_leaf() {
	let mut r = Running::start_kept(1, None).await;
	let url = r.url();
	let x = r.x;
	let (a, b) = (Arca::new("D59HA"), Arca::new("D59HB"));
	a.ok(&["create", "--server", &url, "--node-url", &r.node_url(), "--node-user", "arca"]);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, x, 5_000_000);
	r.produce().await;
	let board = a.ok(&["board", &x.to_string(), "2000000"])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
	// B at the same delays, so A takes B's output as a receiver checks it.
	b.ok(&["create", "--server", &url, "--node-url", &r.node_url(), "--node-user", "arca"]);
	let by = d57_latest_exit_by(&a, std::slice::from_ref(&board));
	d57_to(&r, by - 2 * 86_400 + 2 * 3_600).await;
	let asked = common::node::median_time(&r.rt);
	let s = a.ok(&["sync"]);
	let pid = s["refresh"][0]["participation"].as_str().expect("asked").to_string();
	let id: [u8; 32] = unhex(&pid).try_into().unwrap();
	final_round(&r).await;
	r.keepers[0].halt();
	d57_to(&r, asked + 23 * 3_600).await;
	let s = a.ok(&["sync"]);
	println!("D59H A's sync 23 h on, the keeper down: participations {} | home {}", s["participations"], s["home"]);
	assert_eq!(r.server.store.unsigned_forfeits().await.unwrap().len(), 1, "the forfeit is recorded, held back");
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 600));
	r.keepers[0].resume();
	r.synced().await;
	let filled = r.server.forfeits.fill_unsigned().await.unwrap();
	r.server.rounds.pass().await.unwrap();
	let p = r.server.store.participation(&id).await.unwrap().unwrap();
	println!("D59H the keeper back ten minutes on: {} filled in; the participation at the server: {:?}", filled, p.state);
	assert_eq!(filled, 1);
	// A's board is on the chain: released once the watcher has answered
	// A's exit with the forfeit and claimed it, never before.
	assert_eq!(p.state, server::store::ParticipationState::Issued);
	for i in 0..14 {
		let _ = r.server.watcher.pass().await;
		r.produce().await;
		r.bury().await;
		r.synced().await;
		let s = a.ok(&["sync"]);
		let c = coin_of(&a, &board);
		println!("D59H pass {}: board {} | forfeits {} | participations {}", i, c["state"], s["forfeits"], s["participations"]);
		if c["state"] == "spent" || c["state"] == "exited" {
			break;
		}
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 1_200));
	}
	r.server.rounds.pass().await.unwrap();
	let p = r.server.store.participation(&id).await.unwrap().unwrap();
	println!("D59H the watcher's claim made: the participation at the server: {:?}", p.state);
	assert_eq!(p.state, server::store::ParticipationState::Released);
	let coins = a.ok(&["coins"]);
	let news: Vec<String> = coins.as_array().unwrap().iter().filter(|c| c["kind"] == "batch" && c["state"] == "live")
		.map(|c| c["leaf_id"].as_str().unwrap().to_string()).collect();
	println!("D59H A's coins: {}", coins);
	assert_eq!(news.len(), 1, "A holds its new leaf, live: {}", coins);
	let leaf: [u8; 32] = unhex(&news[0]).try_into().unwrap();
	let at_server = r.server.store.leaf(&leaf).await.unwrap().unwrap().state;
	println!("D59H A's new leaf {} at the server: {:?}", &news[0][..8], at_server);
	assert_eq!(at_server, server::store::LeafState::Live);
	let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let (ok, v) = a.run(&["send", &req, "--amount", "500000", "--asset", &x.to_string()]);
	println!("D59H A pays B 500000: ok={} {}", ok, if ok { v["sent"].clone() } else { v["error"].clone() });
	assert!(ok, "{}", v);
	d57_to(&r, asked + 2 * 86_400).await;
	r.server.rounds.pass().await.unwrap();
	let p = r.server.store.participation(&id).await.unwrap().unwrap();
	println!("D59H a day on: the participation at the server: {:?}", p.state);
	assert_eq!(p.state, server::store::ParticipationState::Released);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// R7h F3 (b), DG turned around (D59.2, D59.3). A participation whose
/// forfeit reached the signer's record, its release held back by a keeper
/// down. With the keeper back before the forfeit deadline, the server's
/// minute task completes the forfeit, the participation is released, and A
/// pays B out of its new leaf. With the keeper down past the deadline, the
/// participation expires and the board is not given back: the wallet shows
/// it given up and takes it home, never offering it for a payment (no
/// `double_spend`, no `in_use`), and it comes home whole less its fees.
#[tokio::test(flavor = "multi_thread")]
async fn d59_a_coin_whose_forfeit_reached_the_record_is_paid_on_or_given_up() {
	for keeper_back_in_time in [true, false] {
		let tag = if keeper_back_in_time { "the keeper back in time" } else { "the keeper down past the deadline" };
		let mut r = Running::start_kept(1, None).await;
		let url = r.url();
		let x = r.x;
		let n = if keeper_back_in_time { 1 } else { 2 };
		let (a, b) = (Arca::new(&format!("D59GA{}", n)), Arca::new(&format!("D59GB{}", n)));
		let boards = boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
		b.ok(&create_args(&url, &r.node_url()));
		let board = boards[0].clone();
		let p = a.ok(&["participate", "--leaf", &board, "--max-fee-ppm", "1000000"]);
		let pid = p["participation"].as_str().unwrap().to_string();
		let id: [u8; 32] = unhex(&pid).try_into().unwrap();
		final_round(&r).await;
		r.keepers[0].halt();
		let s = a.ok(&["sync"]);
		println!("D59G {}: A's sync, the keeper down: participations {}", tag, s["participations"]);
		assert_eq!(r.server.store.unsigned_forfeits().await.unwrap().len(), 1, "the forfeit is recorded, held back");
		let req = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
		if keeper_back_in_time {
			r.keepers[0].resume();
			let filled = r.server.forfeits.fill_unsigned().await.unwrap();
			r.server.rounds.pass().await.unwrap();
			let st = r.server.store.participation(&id).await.unwrap().unwrap().state;
			let s = a.ok(&["sync"]);
			println!("D59G {}: {} filled in; at the server {:?}; A's sync: participations {}", tag, filled, st, s["participations"]);
			assert_eq!(st, server::store::ParticipationState::Released);
			let (ok, v) = a.run(&["send", &req, "--amount", "500000", "--asset", &x.to_string()]);
			println!("D59G {}: A pays B 500000: ok={} {}", tag, ok, if ok { v["inputs"].clone() } else { v["error"].clone() });
			assert!(ok, "A pays out of its new leaf: {}", v);
		} else {
			let deadline = r.server.rounds.exit_deadline_of(&id).await.unwrap().expect("a board has a date");
			d57_to(&r, deadline + 600).await;
			r.server.rounds.pass().await.unwrap();
			let st = r.server.store.participation(&id).await.unwrap().unwrap().state;
			let leaf: [u8; 32] = unhex(&board).try_into().unwrap();
			let at_server = r.server.store.leaf(&leaf).await.unwrap().unwrap().state;
			println!("D59G {}: past the deadline the participation {:?}, the board at the server {:?}", tag, st, at_server);
			assert_eq!(st, server::store::ParticipationState::Expired);
			assert_eq!(at_server, server::store::LeafState::Spent, "the board is not given back as payable");
			r.keepers[0].resume();
			let s = a.ok(&["sync"]);
			let c = coin_of(&a, &board);
			println!("D59G {}: A's sync: participations {} | home {} | the board {} | {}", tag, s["participations"], s["home"], c["state"],
				c["note"]);
			assert!(matches!(c["state"].as_str(), Some("forfeited") | Some("exiting")), "shown as given up, on its way home: {}", c);
			let (ok, v) = a.run(&["send", &req, "--amount", "500000", "--asset", &x.to_string()]);
			let e = v["error"]["message"].as_str().unwrap_or("").to_string();
			println!("D59G {}: A pays B 500000: ok={} {}", tag, ok, e);
			assert!(!ok && !e.contains("double_spend") && !e.contains("in_use"), "the wallet never offers the board: {}", v);
			let at = d57_home(&r, &a, std::slice::from_ref(&board)).await;
			let c = coin_of(&a, &board);
			println!("D59G {}: the board home at median time {}: {} | {}", tag, at, c["state"], c["note"]);
			assert_eq!(c["state"], "exited");
		}
		for w in [&a, &b] {
			let _ = std::fs::remove_dir_all(&w.dir);
		}
	}
}

/// R7h F1, SM turned around (D58.1, D58.2). A's leaf L of an early round; B
/// boards ten days later, so its own coin's dates are weeks ahead. In L's
/// free window B hands A a receive request: B's schedule names a time a day
/// ahead at most, saying it waits for a payment. A pays B 600,000 out of L,
/// and D 300,000 out of its change (both coins rest on L), and refreshes
/// what is left. B syncs when its schedule says, and is paid: read in its
/// last day, the coin goes home at once, and comes home. D, away, syncs only past
/// L's expiry, before any sweep: the coin, checked as of its expiry with its
/// path still on the chain, is kept and taken on the chain at once, and
/// comes home.
#[tokio::test(flavor = "multi_thread")]
async fn d58_a_receiver_on_its_schedule_is_paid_and_a_late_coin_comes_home() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let (a, b, d) = (Arca::new("D58SA"), Arca::new("D58SB"), Arca::new("D58SD"));
	boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	a.ok(&["participate"]);
	final_round(&r).await;
	let la = a.ok(&["sync"])["participations"][0]["new_leaves"][0]["leaf_id"].as_str().expect("A's leaf").to_string();
	let ea = coin_of(&a, &la)["expiry"].as_u64().unwrap() as u32;
	let now = common::node::median_time(&r.rt);
	d57_to(&r, now + 10 * 86_400).await;
	boarded(&mut r, &b, &url, &[(x, 1_000_000)]).await;
	d.ok(&create_args(&url, &r.node_url()));
	let by_a = coin_of(&a, &la)["exit_by"].as_u64().unwrap() as u32;

	// L's free window: B asks to be paid; its schedule.
	d57_to(&r, by_a - 2 * 86_400 + 3_600).await;
	b.ok(&["sync"]);
	let req_b = b.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let req_d = d.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let s = b.ok(&["sync"]);
	let now = common::node::median_time(&r.rt);
	let next = s["schedule"]["next_sync_at"].as_u64().expect("a time") as u32;
	println!("D58S B's schedule, waiting for a payment, at median time {}: next_sync_at {} ({} s ahead) | why {}", now, next, next as i64 - now as i64,
		s["schedule"]["why"]);
	assert!(next <= now + 86_400, "a day ahead at most while B waits for a payment: {}", s["schedule"]);
	assert!(s["schedule"]["why"].as_str().unwrap_or("").contains("waits for a payment"), "{}", s["schedule"]);
	let paid = a.ok(&["send", &req_b, "--amount", "600000", "--asset", &x.to_string()]);
	println!("D58S A pays B 600000 out of L: inputs {}", paid["inputs"]);
	let paid = a.ok(&["send", &req_d, "--amount", "300000", "--asset", &x.to_string()]);
	println!("D58S A pays D 300000 out of its change: inputs {}", paid["inputs"]);
	a.ok(&["sync"]);
	final_round(&r).await;
	a.ok(&["sync"]);

	// B syncs when its schedule says, and is paid.
	d57_to(&r, next).await;
	let s = b.ok(&["sync"]);
	println!("D58S B's sync at its next_sync_at: mailbox {} | refresh {}", s["mailbox"], s["refresh"]);
	let got = s["mailbox"]["accepted"].as_array().cloned().unwrap_or_default();
	assert_eq!(got.len(), 1, "B is paid: {}", s["mailbox"]);
	assert_eq!(got[0]["value"], "600000");
	let bl = got[0]["leaf_id"].as_str().unwrap().to_string();
	// Read a day or less from its exit date, the coin goes home at once.
	println!("D58S B's coin: {}", coin_of(&b, &bl));
	assert!(matches!(coin_of(&b, &bl)["state"].as_str(), Some("live") | Some("given") | Some("exiting")), "{}", coin_of(&b, &bl));
	let at = d57_home(&r, &b, std::slice::from_ref(&bl)).await;
	println!("D58S B's coin home at median time {}: {}", at, coin_of(&b, &bl)["state"]);
	assert_eq!(coin_of(&b, &bl)["state"], "exited");

	// D, away, syncs past L's expiry, before any sweep.
	d57_to(&r, ea + 600).await;
	let s = d.ok(&["sync"]);
	println!("D58S D's sync past L's expiry ({}): mailbox {}", ea, s["mailbox"]);
	let got = s["mailbox"]["accepted"].as_array().cloned().unwrap_or_default();
	assert_eq!(got.len(), 1, "D keeps the coin past its expiry: {}", s["mailbox"]);
	let dl = got[0]["leaf_id"].as_str().unwrap().to_string();
	assert!(got[0]["note"].as_str().unwrap_or("").contains("past its batch's expiry"), "{}", got[0]);
	let at = d57_home(&r, &d, std::slice::from_ref(&dl)).await;
	let c = coin_of(&d, &dl);
	println!("D58S D's coin home at median time {}: {} | {}", at, c["state"], c["note"]);
	assert_eq!(c["state"], "exited");
	for w in [&a, &b, &d] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// D58.3. A payment spends the coins furthest from their exit date first,
/// so a receiver gets the longest life the sender can give it: A holds L, a
/// leaf of an early round, and a board ten days younger and half L's value;
/// paying C 300,000 takes the board, not L.
#[tokio::test(flavor = "multi_thread")]
async fn d58_a_payment_spends_the_coin_furthest_from_its_exit_date() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let (a, c) = (Arca::new("D58PA"), Arca::new("D58PC"));
	boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	a.ok(&["participate"]);
	final_round(&r).await;
	let la = a.ok(&["sync"])["participations"][0]["new_leaves"][0]["leaf_id"].as_str().expect("A's leaf").to_string();
	let now = common::node::median_time(&r.rt);
	d57_to(&r, now + 10 * 86_400).await;
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, x, 3_000_000);
	r.produce().await;
	let young = a.ok(&["board", &x.to_string(), "1000000"])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
	c.ok(&create_args(&url, &r.node_url()));
	println!("D58P L {} exit_by {} value {}; the board {} exit_by {} value {}", &la[..8], coin_of(&a, &la)["exit_by"], coin_of(&a, &la)["value"],
		&young[..8], coin_of(&a, &young)["exit_by"], coin_of(&a, &young)["value"]);
	let req = c.ok(&["receive"])["request"].as_str().unwrap().to_string();
	let paid = a.ok(&["send", &req, "--amount", "300000", "--asset", &x.to_string()]);
	println!("D58P A pays C 300000: inputs {}", paid["inputs"]);
	assert_eq!(paid["inputs"], json!([young]), "the coin furthest from its exit date, not the largest");
	assert_eq!(coin_of(&a, &la)["state"], "live");
	for w in [&a, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// R7h F5. The back-off's last try lands just past the patience: a server
/// that answers `502` to every witness for 6.5 s, against a wallet whose
/// patience is 6 s, is reached by the try a second past it (the fourth, at
/// about 7 s), and nothing is taken for unreachable.
#[tokio::test(flavor = "multi_thread")]
async fn f5_the_back_off_reaches_a_server_back_just_past_the_patience() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let proxy = Proxy::start(&url);
	let a = Arca::new("F5Back");
	boarded(&mut r, &a, &proxy.url.clone(), &[(x, 1_000_000)]).await;
	let since = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
	let down = since.clone();
	proxy.rewrite(Some(Arc::new(move |path: &str, _: &Value, _: u16, v: &mut Value| {
		if path == "/v1/witness" && down.lock().unwrap().elapsed() < std::time::Duration::from_millis(6_500) {
			*v = json!({"error": {"code": "internal", "message": "the server is restarting"}});
			return Some(502u16);
		}
		None
	})));
	a.patience.set(6);
	*since.lock().unwrap() = std::time::Instant::now();
	let t = std::time::Instant::now();
	let s = a.ok(&["sync"]);
	let took = t.elapsed().as_secs_f64();
	println!("F5B the sync, the witness answered 502 for 6.5 s, patience 6 s: took {:.1} s | witness tries {} | unreachable {}", took,
		s["witness"]["tries"], s["unreachable"]);
	assert!(s["unreachable"].is_null(), "{}", s["unreachable"]);
	assert_eq!(s["witness"]["tries"], 4, "{}", s["witness"]);
	assert!(took >= 6.5, "the last try came past the patience");
	let _ = std::fs::remove_dir_all(&a.dir);
}

/// R7h F5. A participation whose coin is on its way home on the chain is
/// not posted again at every sync. One keeper. A's board: its refresh asked
/// for in the free window, the round final, the keeper down; in the coin's
/// last day A's sync hands over the forfeit (held back) and takes the board
/// home. Two more syncs post no forfeit; with the keeper back, the server
/// releases the participation, and the next sync posts the forfeits once
/// and takes the new leaf.
#[tokio::test(flavor = "multi_thread")]
async fn f5_a_participation_whose_coin_goes_home_is_not_posted_again() {
	let mut r = Running::start_kept(1, None).await;
	let url = r.url();
	let x = r.x;
	let proxy = Proxy::start(&url);
	let a = Arca::new("F5Post");
	let boards = boarded(&mut r, &a, &proxy.url.clone(), &[(x, 2_000_000)]).await;
	let board = boards[0].clone();
	let by = d57_latest_exit_by(&a, &boards);
	d57_to(&r, by - 2 * 86_400 + 600).await;
	let s = a.ok(&["sync"]);
	let pid = s["refresh"][0]["participation"].as_str().expect("asked").to_string();
	let id: [u8; 32] = unhex(&pid).try_into().unwrap();
	final_round(&r).await;
	r.keepers[0].halt();
	d57_to(&r, by - 86_400 + 600).await;
	let s = a.ok(&["sync"]);
	println!("F5P A's sync in the last day, the keeper down: participations {} | board {}", s["participations"], coin_of(&a, &board)["state"]);
	assert_eq!(coin_of(&a, &board)["state"], "exiting");
	let posted = proxy.count("/v1/forfeit_leaves");
	for _ in 0..2 {
		r.produce().await;
		let s = a.ok(&["sync"]);
		println!("F5P A's next sync: participations {}", s["participations"]);
	}
	let again = proxy.count("/v1/forfeit_leaves") - posted;
	println!("F5P forfeits posted again in two syncs while the board goes home: {}", again);
	assert_eq!(again, 0, "not posted again while the coin goes home and the participation is issued");
	r.keepers[0].resume();
	assert_eq!(r.server.forfeits.fill_unsigned().await.unwrap(), 1);
	// The board on the chain: released once the watcher has answered its
	// exit with the forfeit and claimed it.
	for _ in 0..10 {
		let _ = r.server.watcher.pass().await;
		r.produce().await;
		r.bury().await;
		r.synced().await;
		r.server.rounds.pass().await.unwrap();
		if r.server.store.participation(&id).await.unwrap().unwrap().state == server::store::ParticipationState::Released {
			break;
		}
	}
	assert_eq!(r.server.store.participation(&id).await.unwrap().unwrap().state, server::store::ParticipationState::Released);
	let s = a.ok(&["sync"]);
	println!("F5P the keeper back, the participation released: A's sync: participations {}", s["participations"]);
	assert_eq!(proxy.count("/v1/forfeit_leaves") - posted, 1, "posted once the operator released it");
	assert_eq!(s["participations"][0]["state"], "released", "{}", s["participations"]);
	let _ = std::fs::remove_dir_all(&a.dir);
}

/// R7h F5. A refused refresh is asked for again a day after it was asked,
/// not at every sync. The operator refuses every refresh of A's board: in
/// the free window `sync` asks, refused; an hour on it does not ask again,
/// and its schedule names the coin's `home_from` (a day after the ask), not
/// the next hour.
#[tokio::test(flavor = "multi_thread")]
async fn f5_a_refused_refresh_is_asked_again_a_day_on_not_at_every_sync() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let proxy = Proxy::start(&url);
	let a = Arca::new("F5Ref");
	let boards = boarded(&mut r, &a, &proxy.url.clone(), &[(x, 1_000_000)]).await;
	let board = boards[0].clone();
	let leaf = board.clone();
	proxy.rewrite(Some(Arc::new(move |path: &str, req: &Value, _: u16, v: &mut Value| {
		if path == "/v1/submit_participation" && req.to_string().contains(&leaf) {
			*v = json!({"error": {"code": "not_accepted", "message": "the operator refuses this refresh"}});
			return Some(409u16);
		}
		None
	})));
	let by = d57_latest_exit_by(&a, &boards);
	d57_to(&r, by - 2 * 86_400 + 600).await;
	let s = a.ok(&["sync"]);
	println!("F5R the free window: refresh {}", s["refresh"]);
	assert!(s["refresh"][0]["error"].as_str().unwrap_or("").contains("refuses"), "{}", s["refresh"]);
	let asked = proxy.count("/v1/submit_participation");
	d57_to(&r, by - 2 * 86_400 + 600 + 3_600).await;
	let s = a.ok(&["sync"]);
	let now = common::node::median_time(&r.rt);
	let next = s["schedule"]["next_sync_at"].as_u64().unwrap() as u32;
	println!("F5R an hour on: refresh {} | asked again {} | next_sync_at {} ({} s ahead; home_from {})", s["refresh"],
		proxy.count("/v1/submit_participation") - asked, next, next as i64 - now as i64, by - 86_400);
	assert_eq!(proxy.count("/v1/submit_participation"), asked, "not asked again an hour on");
	assert!(s["refresh"].is_null() || s["refresh"].as_array().is_some_and(|a| a.is_empty()), "{}", s["refresh"]);
	assert_eq!(next, by - 86_400, "the schedule wakes at home_from, not every hour");
	assert!(coin_of(&a, &board)["home"].as_str().unwrap_or("").contains("refused"), "{}", coin_of(&a, &board));
	let _ = std::fs::remove_dir_all(&a.dir);
}
