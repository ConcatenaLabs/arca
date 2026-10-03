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
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca", "--node-password", "arca",
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
	use elements::hashes::Hash;
	for i in 0..tx.input.len() {
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
	assert_eq!(coin_of(&c, &leaf)["state"], "exited");

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
		if let Some(f) = s["forfeits"].as_array().and_then(|a| a.iter().find(|f| f["state"] == "claimed")) {
			done = f.clone();
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;
	}
	println!("F7 the wallet's watch of its forfeit: {}", done);
	assert_eq!(done["state"], "claimed", "the claim is read from the chain");
	let leaf = done["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	r.bury().await;
	c.ok(&["sync"]);
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
	assert_eq!(f["state"], "refunded", "{}", f);
	r.produce().await;
	let refund = elements::Txid::from_str(f["refund"]["txid"].as_str().unwrap()).unwrap();
	assert!(confirmations(&r, &refund) >= 1, "the refund confirms");
	assert_eq!(coin_of(&c, &boards[1])["state"], "exited");
	let _ = std::fs::remove_dir_all(&c.dir);
}
