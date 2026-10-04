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

/// Two boards refreshed in one round, whose forfeits the operator's watcher
/// publishes; then the round can never return (one of its inputs is spent
/// elsewhere, final), and the operator publishes one board's forfeit again.
/// The new leaves are lost; the board whose forfeit is not on the chain is
/// live again and is exited; the other's forfeit output, unclaimable without
/// the round, is refunded to the wallet once its delay has run.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_round_gives_back_its_coins_and_a_published_forfeit_is_refunded() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let c = Arca::new("F3c");
	let boards = boarded(&mut r, &c, &url, &[(x, 2_000_000), (x, 2_000_000)]).await;
	let outs: Vec<_> = boards.iter().map(|b| {
		let CoinRecord::Board(rec) = record_of(&c, b) else { panic!("a board") };
		find_unspent(&r, &rec.output().txout())
	}).collect();
	for b in &boards {
		c.ok(&["participate", "--leaf", b]);
	}
	let r1 = final_round(&r).await;
	let s = c.ok(&["sync"]);
	let leaves: Vec<String> = s["participations"].as_array().unwrap().iter()
		.map(|p| p["new_leaves"][0]["leaf_id"].as_str().unwrap_or_else(|| panic!("released: {}", s)).to_string()).collect();
	// The watcher publishes each board's forfeit.
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
	let second = forfeits[1].clone().expect("the watcher publishes the second board's forfeit");
	println!("F3c the operator's forfeit of the second board: {} ({} vB)", second.txid(), second.vsize());

	// The round can never return: rolled back, the mempool emptied, one of
	// its inputs spent by another transaction, buried.
	r.server.stop();
	let block = block_of(&r, &r1.txid().to_string());
	rpc(&r, "invalidateblock", &[json!(block)]);
	r.rt.node.restart(&["-persistmempool=0"]).unwrap();
	let op = r1.input[0].previous_output;
	let prev = r.rt.client().raw_transaction(&op.txid).unwrap().output[op.vout as usize].clone();
	let (a, v) = (prev.asset.explicit().unwrap(), prev.value.explicit().unwrap());
	let mut conflict = Transaction { version: 2, lock_time: elements::LockTime::ZERO,
		input: vec![elements::TxIn { previous_output: op, ..Default::default() }],
		output: vec![sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(a, v - 5_000), common::node::op_true()),
			sequentia_ext::fee_txout(sequentia_ext::AssetAmount::new(a, 5_000))] };
	operator_signs(&r, &mut conflict);
	let cid = r.rt.client().send_raw_transaction(&conflict).expect("the conflict relays");
	// The operator publishes the second board's forfeit again.
	let fid = r.rt.client().send_raw_transaction(&second).expect("the forfeit relays without its round");
	r.produce().await;
	r.bury().await;
	println!("F3c conflict {} confirmed: round {} can never return; forfeit {} confirmed", cid, r1.txid(), fid);

	let rc = c.ok(&["recheck"]);
	println!("F3c the wallet's re-check: {}", rc["changes"]);
	for l in &leaves {
		assert_eq!(coin_of(&c, l)["state"], "lost", "the new leaf of the lost round");
	}
	assert_eq!(coin_of(&c, &boards[0])["state"], "live", "the board whose forfeit is not on the chain is the wallet's again: {}",
		coin_of(&c, &boards[0]));
	assert_eq!(coin_of(&c, &boards[1])["state"], "forfeited", "the board in its published forfeit: {}", coin_of(&c, &boards[1]));
	let claim = exit_and_claim(&r, &c, &boards[0], Some(&x.to_string())).await;
	println!("F3c the board given back is exited: claim {} pays {} of X", claim.txid(), claim.output[0].value.explicit().unwrap());

	// The refund, once its delay has run.
	let refund_s = r.config.exit_delay_units.unwrap().1 as u32 * 512;
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, refund_s));
	let s = c.ok(&["sync"]);
	let f = s["forfeits"].as_array().unwrap().iter().find(|f| f["leaf_id"] == boards[1].as_str()).cloned()
		.unwrap_or_else(|| panic!("the forfeit is watched: {}", s));
	println!("F3c the wallet's refund of the second board's forfeit: {}", f);
	assert_eq!(f["state"], "refunding", "sent, which decides nothing yet: {}", f);
	assert_eq!(coin_of(&c, &boards[1])["state"], "forfeited", "a refund in the mempool decides nothing");
	r.produce().await;
	let refund = elements::Txid::from_str(f["refund"]["txid"].as_str().unwrap()).unwrap();
	assert!(confirmations(&r, &refund) >= 1, "the refund confirms");
	r.bury().await;
	let s = c.ok(&["sync"]);
	let f = s["forfeits"].as_array().unwrap().iter().find(|f| f["leaf_id"] == boards[1].as_str()).cloned()
		.unwrap_or_else(|| panic!("the forfeit is followed until its refund is final: {}", s));
	assert_eq!(f["state"], "refunded", "{}", f);
	assert_eq!(coin_of(&c, &boards[1])["state"], "exited");
	let _ = std::fs::remove_dir_all(&c.dir);
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
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, e0 - now - 4 * 86_400));
	r.bury().await;
	c.ok(&["sync"]);
	assert_eq!(coin_of(&c, &leaf)["state"], "live", "four days before its expiry the leaf is still live");
	proxy.rewrite(Some(Arc::new(|path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/info" && status == 200 {
			v["fees"]["refresh_ppm"] = json!(5_000);
			v["fees"]["free_window_seconds"] = json!(0);
		}
		None
	})));
	let submitted = proxy.count("/v1/submit_participation");
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
	let c = Arca::new("F8a");
	let why = c.refused(&create_args("http://192.0.2.1:3535/arca", &node), "plain http");
	println!("F8 plain http to another host: REFUSED: {}", why);
	let tls = tokio::task::block_in_place(TlsServer::start);
	let c = Arca::new("F8b");
	let url = format!("https://127.0.0.1:{}/arca", tls.port);
	let why = c.refused(&create_args(&url, &node), "cannot reach the server");
	println!("F8 https to a server with a certificate no root vouches for: REFUSED: {}", why);
	assert!(!why.contains("https feature"), "{}", why);
	assert!(why.to_lowercase().contains("certificate") || why.to_lowercase().contains("issuer"), "TLS refused it: {}", why);
	let c = Arca::new("F8c");
	let (ok, info, err) = c.run_full(&create_args(&r.url(), &node));
	assert!(ok, "{}", info);
	println!("F8 create: {}", err.trim());
	let op = info["operator"].as_str().unwrap();
	assert!(info["operator_key_check"].as_str().unwrap().contains(op) && err.contains(op), "the pinned key is shown: {}", info);
	for d in ["F8a", "F8b", "F8c"] {
		let _ = std::fs::remove_dir_all(Arca::new(d).dir);
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
/// them when the server recorded it. The receiver takes the coin, past its
/// board's exit deadline, as one it can only refresh or exit, and refreshes
/// it.
#[tokio::test(flavor = "multi_thread")]
async fn a_payment_recorded_while_the_signer_was_away_completes_past_the_boards_exit_deadline() {
	let mut r = Running::start().await;
	let url = r.url();
	let x = r.x;
	let (a, w) = (Arca::new("T1A"), Arca::new("T1W"));
	let boards = boarded(&mut r, &a, &url, &[(x, 2_000_000)]).await;
	w.ok(&create_args(&url, &r.node_url()));
	let req = w.ok(&["receive"])["request"].as_str().unwrap().to_string();
	r.signer.halt();
	let (ok, v) = a.run(&["send", &req, "--amount", "600000", "--asset", &x.to_string()]);
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
	let kept = &s["transfers"][0]["kept"][0];
	println!("T1 A's change: {}", kept);
	assert_eq!(kept["state"], "live", "{}", kept);
	let m = w.ok(&["sync"])["mailbox"].clone();
	println!("T1 W's mailbox: {}", m);
	let got = m["accepted"][0].clone();
	assert_eq!((got["value"].as_str(), got["state"].as_str()), (Some("600000"), Some("live")), "{}", m);
	assert!(got["board"]["note"].as_str().unwrap().contains("past its exit deadline"), "{}", got);
	// W refreshes it: the operator takes it into a refresh until a day
	// before the board's expiry.
	let p = w.ok(&["participate"]);
	println!("T1 W refreshes the coin: {}", p["state"]);
	assert_eq!(p["state"], "pending");
	final_round(&r).await;
	let s = w.ok(&["sync"]);
	println!("T1 W's sync once the round is final: {}", s["participations"]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s);
	let new = s["participations"][0]["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	assert_eq!(coin_of(&w, &new)["state"], "live");
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
	// away.
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 23 * 86_400 + 43_200));
	r.bury().await;
	r.synced().await;
	a.ok(&["sync"]);
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
	a.ok(&["swap", "complete", acc["accept"].as_str().unwrap()]);
	let got = b.ok(&["sync"])["mailbox"]["accepted"].as_array().unwrap().iter()
		.find(|c| c["asset"] == x.to_string().as_str()).cloned().unwrap();
	println!("D51 the coin it got: {}", got["board"]);
	assert_eq!(got["board"]["exit_deadline"].as_u64(), Some(d), "the dates shown are the coin's");
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
	let c = Arca::new("F2");
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
	assert!(why.contains(&format!("past entry {}", backed_up)) && why.contains(&format!("past the record's end at entry {}", backed_up)),
		"{}", why);
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
		r.server.stop();
		r.signer.halt();
		tokio::time::sleep(std::time::Duration::from_millis(300)).await;
		self.disconnect(&self.db).await;
		self.admin.batch_execute(&format!("DROP DATABASE {}", self.db)).await.unwrap();
		self.disconnect(&format!("{}_backup", self.db)).await;
		self.admin.batch_execute(&format!("CREATE DATABASE {} TEMPLATE {}_backup", self.db, self.db)).await.unwrap();
		std::fs::write(r.signer.record(), &self.record).unwrap();
		self.start(r).await;
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
	let mut r = Running::start().await;
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
	assert_eq!(info_of(&r)["signer_record"]["entry"].as_u64(), Some(backup.entries));
	JointRollback { r, proxy, a, a_old, b, m, p1, p2, c_a, backup, head_at_backup }
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
	let JointRollback { mut r, proxy, a, a_old, b, m, p1, p2, c_a, backup, head_at_backup } = joint_rollback("W1").await;
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
	println!("W1 A's older copy pays M: ok={} {}", ok, v);
	println!("W1 C_A in A's older copy: {} | {}", coin_of(&a_old, &c_a)["state"], coin_of(&a_old, &c_a)["note"]);
	assert_ne!(coin_of(&a_old, &c_a)["state"], "live", "C_A's lineage is on the chain: no off-chain spend of it");
	assert!(!ok);
	assert!(v["error"]["message"].as_str().unwrap().contains("stopped"), "the stopped signer refuses it: {}", v);
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
