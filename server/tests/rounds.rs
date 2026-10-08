//! Rounds, against a whole server on an anchored proof-of-stake regtest
//! chain: participations in two assets turned into a round transaction for
//! each asset, each with its batch and sweep token and the connector, one
//! with an offboard; the rounds final; each batch published; and a wallet
//! validating its new leaf from the published tree alone, the five checks on
//! the token and its clock among them, while a published tree changed in any
//! part is refused. The server's wallet holds no policy asset at any point.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::encode::deserialize;
use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::{Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::{RecordError, RoundCheckFailure, WalletPolicy};
use common::client::{hex, participation_body, rebuild, txid, want_leaf};
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{accept_policy, credited_board, round_final, start, VALUE};
use server::participations::OutputRequest;

#[tokio::test(flavor = "multi_thread")]
async fn a_round_in_two_assets_published_and_validated() {
	let mut r = start().await;
	let (x, y, s, chain) = (r.x, r.y, xonly(&r.s), r.chain);
	let policy_asset = r.purse.policy;
	let balance = r.server.wallet.balance().await.unwrap();
	assert!(!balance.contains_key(&policy_asset), "the wallet holds no policy asset: {:?}", balance);
	println!("the server's wallet: {:?}", balance);

	// Three owners: A refreshes into X, B into X with an offboard, C into Y.
	let (a, b, c) = (keypair("A"), keypair("B"), keypair("C"));
	let (a_coin, _) = credited_board(&mut r, &a, x).await;
	let (b_coin, _) = credited_board(&mut r, &b, x).await;
	let (c_coin, _) = credited_board(&mut r, &c, y).await;
	let (a2, b2, c2) = (keypair("A, new"), keypair("B, new"), keypair("C, new"));
	let (wa, a2_nonce) = want_leaf(&a2, x, VALUE);
	let (wb, _) = want_leaf(&b2, x, 600_000);
	let off = OutputRequest::Offboard { asset: x, value: 300_000, script: node::op_true() };
	let (wc, c2_nonce) = want_leaf(&c2, y, VALUE);
	let (pa, ida) = participation_body(&[&a_coin], &[wa], &[], None, s, chain);
	let (pb, idb) = participation_body(&[&b_coin], &[wb, off], &[(x, 100_000)], None, s, chain);
	let (pc, idc) = participation_body(&[&c_coin], &[wc], &[], None, s, chain);
	for p in [&pa, &pb, &pc] {
		assert_eq!(r.http.post("submit_participation", p).ok()["state"], "pending");
	}

	// The rounds: X's (A, and B with its offboard) and Y's (C), in one pass.
	let (rounds, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	assert_eq!(rounds.len(), 2, "a round for each asset");
	let (bx, by) = (&rounds[0], &rounds[1]);
	for b in &rounds {
		let tx = &b.tx;
		println!("round {}: {} vB, {} inputs, {} outputs, {:?}, broadcast: {}", tx.txid(), tx.vsize(), tx.input.len(),
			tx.output.len(), b.batches, b.broadcast);
		assert_eq!(b.broadcast, "accepted");
		assert_eq!(tx.lock_time, elements::LockTime::ZERO, "nLockTime 0, so it returns after a rollback");
		// The operator's coins only, one of them issuing the token.
		let wallet_coins: Vec<(Txid, u32)> = r.server.store.wallet_coins(None).await.unwrap().iter()
			.map(|c| (Txid::from_byte_array(c.txid), c.vout)).collect();
		let spent: Vec<_> = tx.input.iter().map(|i| (i.previous_output.txid, i.previous_output.vout)).collect();
		assert!(spent.iter().all(|o| !wallet_coins.contains(o)), "every input is a wallet coin, now taken by the round");
		assert_eq!(tx.input.iter().filter(|i| i.has_issuance()).count(), 1, "one token for its batch");
		// The fee: one output, in X, never in the policy asset.
		let fees: Vec<_> = tx.output.iter().filter(|o| o.is_fee()).collect();
		assert_eq!(fees.len(), 1);
		assert_eq!(fees[0].asset.explicit(), Some(x));
		assert!(tx.output.iter().all(|o| o.asset.explicit() != Some(policy_asset)));
	}
	// One batch each, followed by its token; X's offboard, then the connector.
	assert_eq!(bx.batches, vec![(x, 0, 2)]);
	assert_eq!((bx.offboards, bx.participations, bx.connector_vout), (1, 2, 3));
	assert_eq!(by.batches, vec![(y, 0, 1)]);
	assert_eq!((by.offboards, by.participations, by.connector_vout), (0, 1, 2));
	// Nothing can be swept or refreshed twice: a second pass finds nothing.
	assert!(r.server.rounds.run_round().await.unwrap().is_none());

	// The participations are issued in their asset's round.
	let st = r.http.post("participation_status", &json!({"participation_id": hex(&ida)})).ok();
	assert_eq!(st["state"], "issued");
	assert_eq!(st["round"]["txid"], bx.tx.txid().to_string());
	assert_eq!(st["round"]["connector_vout"], 3);
	assert_eq!(st["outputs"][0]["batch_vout"], 0);
	let stb = r.http.post("participation_status", &json!({"participation_id": hex(&idb)})).ok();
	assert_eq!(stb["outputs"][1]["offboard_vout"], 2);
	let stc = r.http.post("participation_status", &json!({"participation_id": hex(&idc)})).ok();
	assert_eq!(stc["round"]["txid"], by.tx.txid().to_string());
	assert_eq!(stc["outputs"][0]["batch_vout"], 0);
	println!("A's status: {}", st);

	// Final.
	r.produce().await;
	r.bury().await;
	for b in &rounds {
		round_final(&r, &b.tx.txid()).await;
		let onchain: Transaction = deserialize(&elements::encode::serialize(&r.rt.client().raw_transaction(&b.tx.txid()).unwrap())).unwrap();
		assert_eq!(onchain, b.tx);
	}

	// A validates its new leaf from the published tree alone.
	let policy = accept_policy(&r);
	for (status, key, nonce, label) in [(&st, &a2, &a2_nonce, "A"), (&stc, &c2, &c2_nonce, "C")] {
		let vout = status["outputs"][0]["batch_vout"].as_u64().unwrap() as u32;
		let index = status["outputs"][0]["leaf_index"].as_u64().unwrap() as usize;
		let rtx = txid(status["round"]["txid"].as_str().unwrap());
		let published = r.http.post("tree", &json!({"txid": rtx.to_string(), "vout": vout})).ok();
		let tree = rebuild(&published);
		let round = r.rt.client().raw_transaction(&txid(published["round_txid"].as_str().unwrap())).unwrap();
		let record = tree.record(index);
		let valid = record.validate(&round, &policy, &xonly(key), nonce).unwrap();
		assert_eq!(valid.leaf_id.to_string(), status["outputs"][0]["leaf_id"].as_str().unwrap());
		assert_eq!(valid.batch_vout, vout);
		assert_eq!((record.asset, record.value, record.owner, record.exit_delay), (tree.params().asset, VALUE, xonly(key), common::client::exit_delay()));
		assert_eq!(record.unlock_hash.to_vec(), common::client::unhex(status["unlock_hash"].as_str().unwrap()));
		assert_eq!(published["token_vout"], vout + 1);
		println!("{} validated leaf {} from the published tree of {}:{}: {} levels, expiries {:?}, reserve {}",
			label, valid.leaf_id, rtx, vout, record.levels(), record.schedule.expiries(), published["reserve"]);

		// The same tree changed in any part is refused: what the server
		// publishes is checked, not trusted.
		let mut bad = published.clone();
		bad["leaves"][0]["value"] = json!((VALUE + 1).to_string());
		refuse(&bad, &round, &policy, key, nonce, index, "a leaf's value");
		let mut bad = published.clone();
		bad["leaves"][0]["unlock_hash"] = json!(hex(&[3; 32]));
		refuse(&bad, &round, &policy, key, nonce, index, "a leaf's unlock hash");
		// The last expiry a second later: hidden in clock 0's commitment,
		// which the round's token output then does not match (check 5).
		let mut bad = published.clone();
		let mut sched = common::client::unhex(published["schedule"].as_str().unwrap());
		let n = sched.len();
		sched[n - 4] = sched[n - 4].wrapping_add(1);
		bad["schedule"] = json!(hex(&sched));
		refuse(&bad, &round, &policy, key, nonce, index, "the last expiry, hidden in clock 0");
		// The last expiry before the one ahead of it: the builder refuses a
		// clock that runs backwards.
		let e1 = u32::from_le_bytes(sched[n - 8..n - 4].try_into().unwrap());
		sched[n - 4..].copy_from_slice(&(e1 - 1).to_le_bytes());
		bad["schedule"] = json!(hex(&sched));
		let e = common::client::try_rebuild(&bad).unwrap_err();
		println!("a published tree whose clock runs backwards: refused by the builder, {}", e);
		let mut bad = published.clone();
		if bad["reserve"].get("fee_rate").is_some() {
			bad["reserve"]["fee_rate"]["multiple"] = json!("5");
		} else {
			bad["reserve"]["fixed"]["node"] = json!("2");
		}
		refuse(&bad, &round, &policy, key, nonce, index, "the reserve rule");
	}
	// A tree for an output that pays no batch.
	let a = r.http.post("tree", &json!({"txid": bx.tx.txid().to_string(), "vout": 1}));
	assert_eq!((a.status, a.refusal().0.as_str()), (404, "unknown_batch"));
}

fn refuse(published: &Value, round: &Transaction, policy: &WalletPolicy, key: &Keypair, nonce: &[u8; 32], index: usize, what: &str) {
	let tree = rebuild(published);
	let e = tree.record(index).validate(round, policy, &xonly(key), nonce).unwrap_err();
	println!("a published tree with {} changed: refused, {}", what, e);
	assert!(matches!(e, RecordError::BatchOutputMissing | RecordError::Round(RoundCheckFailure::NotClockZero)), "{}", e);
}

#[tokio::test(flavor = "multi_thread")]
async fn round_sizes_by_leaves() {
	let mut r = start().await;
	let (x, s, chain) = (r.x, xonly(&r.s), r.chain);
	for n in [1usize, 4, 16] {
		let mut bodies = vec![];
		for i in 0..n {
			let k = keypair(&format!("size {} owner {}", n, i));
			let (coin, _) = credited_board(&mut r, &k, x).await;
			let (w, _) = want_leaf(&keypair(&format!("size {} owner {} new", n, i)), x, VALUE);
			bodies.push(participation_body(&[&coin], &[w], &[], None, s, chain).0);
		}
		for b in &bodies {
			r.http.post("submit_participation", b).ok();
		}
		let built = r.server.rounds.run_round().await.unwrap().unwrap();
		let tx = &built.tx;
		println!("round of {} leaves: {} vB ({} weight), {} inputs, {} outputs", n, tx.vsize(), tx.weight(), tx.input.len(), tx.output.len());
		assert_eq!(built.batches[0].2, n);
		r.produce().await;
		r.bury().await;
		round_final(&r, &tx.txid()).await;
	}
}
