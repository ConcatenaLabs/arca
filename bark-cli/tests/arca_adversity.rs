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
