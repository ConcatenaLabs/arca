//! A transfer's margins are bounded when it is co-signed, and the watcher
//! pays from a margin only the fee its transaction needs: review R7's F6 and
//! F5 (P9) turned around.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::Transaction;

use arca_covenant::spend::FeeSource;
use arca_covenant::CoinRecord;
use common::client::{new_leaf, random32, transfer_body, Held};
use common::flow::{drive, log};
use common::keys::{keypair, xonly};
use common::rounds::{credited_board, start, VALUE};
use common::running::Running;
use sequentia_ext::TxOutExt;

#[tokio::test(flavor = "multi_thread")]
async fn margins_outside_the_bounds_are_refused() {
	let mut r = start().await;
	let (x, y, s) = (r.x, r.y, xonly(&r.s));
	let a = keypair("A, X");
	let (held, btx) = credited_board(&mut r, &a, x).await;
	let valid = held.record.resolve(&[btx], &r.policy()).unwrap();
	let info = r.http.get("info").ok();
	println!("info.fees: {}", info["fees"]);
	assert_eq!((info["fees"]["margin_multiple"].as_u64(), info["fees"]["max_margin_multiple"].as_u64()), (Some(4), Some(25)));
	// (checkpoint keeps, B gets): the checkpoint's margin, then the reassignment's.
	let cases: [(&str, u64, u64); 4] = [
		("no checkpoint margin", VALUE, VALUE - 2_000),
		("no reassignment margin", VALUE - 2_000, VALUE - 2_000),
		("a checkpoint margin past the cap", VALUE - 500_000, VALUE - 502_000),
		("a reassignment margin past the cap", VALUE - 2_000, VALUE - 502_000),
	];
	for (what, kept, paid) in cases {
		let (leaf, _) = new_leaf(&keypair(&format!("B {}", what)));
		let a_ = r.http.post("cosign_transfer", &transfer_body(&[(&held, valid.clone(), kept)], &[(x, paid, leaf)], s, r.chain));
		println!("X, {}: {} {}", what, a_.status, a_.json);
		assert_eq!((a_.status, a_.refusal().0.as_str()), (422, "margin"), "{}", what);
	}
	let (leaf, _) = new_leaf(&keypair("B within"));
	let ok = r.http.post("cosign_transfer", &transfer_body(&[(&held, valid, VALUE - 2_000)], &[(x, VALUE - 4_000, leaf)], s, r.chain));
	assert_eq!(ok.status, 200, "margins of 2,000 in X are within the bounds: {}", ok.json);

	// In Y, which the node does not accept for fees: one atom is the least.
	let c = keypair("C, Y");
	let (held, btx) = credited_board(&mut r, &c, y).await;
	let valid = held.record.resolve(&[btx], &r.policy()).unwrap();
	for (what, kept, paid) in [("no checkpoint margin", VALUE, VALUE - 1), ("no reassignment margin", VALUE - 1, VALUE - 1)] {
		let (leaf, _) = new_leaf(&keypair(&format!("D {}", what)));
		let a_ = r.http.post("cosign_transfer", &transfer_body(&[(&held, valid.clone(), kept)], &[(y, paid, leaf)], s, r.chain));
		println!("Y, {}: {} {}", what, a_.status, a_.json);
		assert_eq!((a_.status, a_.refusal().0.as_str()), (422, "margin"), "{}", what);
	}
	let (leaf, _) = new_leaf(&keypair("D within"));
	let ok = r.http.post("cosign_transfer", &transfer_body(&[(&held, valid, VALUE - 1)], &[(y, VALUE - 2, leaf)], s, r.chain));
	assert_eq!(ok.status, 200, "one atom each in Y: {}", ok.json);
}

/// R7's P9: a margin far above the fee. Here the operator's cap allows it,
/// and the watcher's answer pays the fee its transaction needs and returns
/// the rest of the margin to the operator's wallet; the node takes it.
#[tokio::test(flavor = "multi_thread")]
async fn a_large_margin_pays_the_fee_and_the_rest_comes_back() {
	use arca_covenant::sign::sign_digest;
	let mut r = Running::start_with(|c, _| c.fees.max_margin_multiple = Some(10_000_000)).await;
	let (x, s) = (r.x, xonly(&r.s));
	for _ in 0..3 {
		r.fund_wallet_in(x, 50_000_000).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let a = keypair("A");
	let big = 100_000_000u64;
	let (rec, btx, _) = r.board_in(&a, x, big);
	r.produce().await;
	r.bury().await;
	let (http, id) = (r.http.clone(), rec.leaf_id());
	r.wait("A's board credited", || http.board_status(&id).json["state"] == "credited").await;
	let held = Held { key: a, nonce: rec.owner_nonce, id, record: CoinRecord::Board(rec) };
	let a_valid = held.record.resolve(std::slice::from_ref(&btx), &r.policy()).unwrap();
	// The checkpoint keeps all but 2,000; B is paid 1,000; the rest of the
	// coin is the reassignment's margin.
	let (b_leaf, _) = new_leaf(&keypair("B"));
	let done = r.http.post("cosign_transfer", &transfer_body(&[(&held, a_valid.clone(), big - 2_000)], &[(x, 1_000, b_leaf)], s, r.chain));
	assert_eq!(done.status, 200, "{}", done.json);
	let transfer = common::client::unhex(done.json["transfer_id"].as_str().unwrap());
	// A converts its board: a stale exit, which the watcher answers.
	let (policy, at) = a_valid.board().unwrap();
	let fee_coin = r.purse.take_coin(x);
	let conv = policy.conversion(at, &FeeSource::Coin { outpoint: fee_coin.0, coin: fee_coin.1.clone(), fee: 3_000, change: common::node::op_true() }).unwrap();
	let sig = sign_digest(&a, &conv.sighash(r.chain.genesis_hash()).unwrap(), &random32());
	r.rt.client().send_raw_transaction(&conv.finish(vec![sig.as_ref().to_vec()]).tx).unwrap();
	drive(&r, "the reassignment", 6, |l| l.iter().any(|w| w.kind == "reassignment" && w.subject == transfer)).await;
	let to_wallet = r.server.wallet.receive_script().await.unwrap();
	let _ = to_wallet;
	for w in log(&r).await {
		let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
		let fee: u64 = tx.output.iter().filter(|o| o.is_fee()).map(|o| o.explicit_value().unwrap()).sum();
		let rest: Vec<u64> = tx.output.iter().filter(|o| !o.is_fee()).map(|o| o.explicit_value().unwrap()).collect();
		println!("{}: {} vB, fee {}, other outputs {:?}", w.kind, tx.vsize(), fee, rest);
		assert!(fee < 10_000, "{}: a fee of {} is the fee it needs, not its margin", w.kind, fee);
		if w.kind == "reassignment" {
			assert!(rest.contains(&1_000), "B's leaf");
			assert!(rest.iter().any(|v| *v > big - 20_000), "the rest of the margin goes to the operator's wallet: {:?}", rest);
		}
	}
	r.produce().await;
	r.synced().await;
	let re = log(&r).await.into_iter().find(|w| w.kind == "reassignment").unwrap();
	let txid = elements::Txid::from_byte_array(re.txid);
	let conf: serde_json::Value = r.rt.client().call("getrawtransaction", &[serde_json::json!(txid.to_string()), serde_json::json!(true)]).unwrap();
	println!("the reassignment {} is in block {}", txid, conf["blockhash"]);
	assert!(conf["blockhash"].is_string(), "the node took the reassignment and a block holds it");
}

/// `info` publishes the operator's node's floor in every asset served, from
/// which a wallet prices the margins the operator bounds: X, which the node
/// accepts for fees, at its floor now; Y, which it does not, as `null` (a
/// margin of one atom).
#[tokio::test(flavor = "multi_thread")]
async fn info_publishes_the_operators_floors() {
	let r = common::rounds::start().await;
	let info = r.http.get("info").ok();
	let floors = info["fees"]["floors"].as_array().expect("the floors are published");
	let of = |a: elements::AssetId| floors.iter().find(|f| f["asset"] == a.to_string().as_str()).cloned().unwrap();
	let x = server::fees::floor_per_kvb(&r.server.finality, r.x).await.unwrap().expect("X is accepted for fees");
	println!("info.fees.floors: {}", info["fees"]["floors"]);
	assert_eq!(of(r.x)["floor_per_kvb"], serde_json::json!(x.to_string()));
	assert!(of(r.y)["floor_per_kvb"].is_null());
	assert_eq!(floors.len(), 2);
}
