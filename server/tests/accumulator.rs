//! The accumulator batch, against a whole server on an anchored proof-of-stake
//! regtest chain: `arca-signer` in its own process, PostgreSQL, the wallet
//! paid in X, the minimal client playing every owner.
//!
//! An operator that expects 1 % of a batch's leaves to leave on their own
//! (`[batches] accumulator_exit_rate_ppm = 10000`) refreshes twenty boards
//! in one round:
//!
//! 1. The round pays one accumulator batch: published with its kind, no
//!    nodes. Each owner rebuilds it from the published parts, validates its
//!    leaf against the round, hands over its forfeit and its exit
//!    authorisation, and holds a coin record of the accumulator kind that
//!    resolves.
//! 2. One owner takes its leaf out on its own: the exit from the batch
//!    output by its authorisation, the entry with its preimage, the leaf's
//!    exit after its delay. Every other owner's coin still resolves, and its
//!    authorisation, signed before the exit, takes its slot out of the new
//!    state.
//! 3. The expiry: nothing before `E`; the release at `E`; no sweep during
//!    the notice; then one sweep of the batch output where the exit left it.
//!    The leaf that left is not touched.
//!
//! The refusals of the exit itself are the covenant's
//! (`covenant/tests/accumulator.rs`, every negative forced into a block).
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::{OutPoint, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::{Batch, CoinRecord, RelativeTime, ValidOrigin};
use common::client::{hex, participation_body, random32, rebuild_batch, resolve, want_leaf, Held};
use common::flow::{drive, exit_tx, has, held_by, of_kind, settle, txid};
use common::keys::{keypair, xonly};
use common::rounds::{accept_policy, advance_mtp, credited_board, mtp, round_final, status};
use common::running::{Running, MIN_LEAF};

const HOUR: u32 = 3_600;
const OWNERS: usize = 20;

fn send(r: &Running, what: &str, tx: &Transaction) -> Txid {
	let t = r.rt.client().send_raw_transaction(tx).unwrap_or_else(|e| panic!("{}: {}", what, e));
	println!("{}: {} ({} vB)", what, t, tx.vsize());
	t
}

#[tokio::test(flavor = "multi_thread")]
async fn an_accumulator_batch_is_built_held_left_and_swept() {
	let mut r = Running::start_with(|c, y| {
		// What follows is the sweep of a live coin: the operator does not take
		// it on the chain at its batch's release first.
		c.watcher.unroll_at_release = false;
		c.assets.push(server::server::AssetSection::new(y, MIN_LEAF));
		c.batches.accumulator_exit_rate_ppm = Some(10_000);
	}).await;
	let x = r.x;
	for _ in 0..3 {
		r.fund_wallet_in(x, 50_000_000).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;

	// Twenty boards, each refreshed into a leaf of its own in one round.
	let mut boards: Vec<(Held, Transaction)> = vec![];
	for i in 0..OWNERS {
		boards.push(credited_board(&mut r, &keypair(&format!("accumulator U{} board", i)), x).await);
	}
	let keys: Vec<Keypair> = (0..OWNERS).map(|i| keypair(&format!("accumulator U{}", i))).collect();
	let mut wanted = vec![];
	for ((held, tx), key) in boards.iter().zip(&keys) {
		let old = resolve(held, std::slice::from_ref(tx), &r.policy());
		let (w, nonce) = want_leaf(key, old.asset, old.value);
		let (body, id) = participation_body(&[held], &[w], &[], None, xonly(&r.s), r.chain);
		assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
		wanted.push((id, nonce, old));
	}
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	assert_eq!(built.batches.len(), 1);
	let round: Transaction = r.rt.client().raw_transaction(&built.tx.txid()).unwrap();

	// 1. The published batch, each owner's leaf, its forfeit and its exit
	// authorisation.
	let st0 = status(&r, &wanted[0].0);
	let vout = st0["outputs"][0]["batch_vout"].as_u64().unwrap() as u32;
	let published: Value = r.http.post("tree", &json!({"txid": built.tx.txid().to_string(), "vout": vout})).ok();
	assert_eq!(published["kind"], "accumulator", "{}", published["kind"]);
	assert!(published.get("nodes").is_none_or(|n| n.as_array().is_none_or(|a| a.is_empty())), "an accumulator batch has no nodes");
	let acc = match rebuild_batch(&published) {
		Batch::Accumulator(a) => a,
		Batch::Tree(_) => panic!("the published batch rebuilds as a tree"),
	};
	assert_eq!(round.output[vout as usize].value.explicit(), Some(acc.total()));
	println!("round {}: one accumulator batch of {} leaves at output {}, holding {}", round.txid(), acc.len(), vout, acc.total());
	let t0 = arca_covenant::MedianTime::from_consensus(acc.params().schedule.expiries()[0].to_consensus_u32() - 28 * 86_400 - HOUR).unwrap();
	let mut coins = vec![];
	for (i, ((id, nonce, old), key)) in wanted.iter().zip(&keys).enumerate() {
		let st = status(&r, id);
		let index = st["outputs"][0]["leaf_index"].as_u64().unwrap() as usize;
		let valid = acc.record(index).validate(&round, &accept_policy(&r), &xonly(key), nonce).unwrap();
		assert_eq!(valid.leaf_id.to_string(), st["outputs"][0]["leaf_id"].as_str().unwrap());
		let c = st["round"]["connector_vout"].as_u64().unwrap() as u32;
		let delay = RelativeTime::from_units(st["refund_delay_units"].as_u64().unwrap() as u16).unwrap();
		let margin: u64 = st["inputs"][0]["margin"].as_str().unwrap().parse().unwrap();
		let f = valid.forfeit_for(old.leaf, (old.asset, old.value), old.id, &round, c, delay, margin).unwrap();
		let exit_sig = sign_digest(key, &valid.exit_digest(t0), &random32());
		let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(id),
			"forfeits": [{"leaf_id": old.id.to_string(), "signature": hex(sign_digest(&boards[i].0.key, &f.message().digest, &random32()).as_ref())}],
			"leaves": [{"leaf_id": valid.leaf_id.to_string(), "auths": [{"signature": hex(exit_sig.as_ref()), "time": t0.to_consensus_u32()}]}]}))
			.ok();
		assert_eq!(done["state"], "released", "{}", done);
		let held = held_by(&r, key, *nonce, valid.leaf_id);
		assert!(matches!(held.record, CoinRecord::Accumulator { .. }), "the server keeps an accumulator coin record");
		let coin = resolve(&held, std::slice::from_ref(&round), &r.policy());
		assert!(matches!(coin.origin, ValidOrigin::Accumulator { .. }));
		coins.push((held, coin));
	}
	println!("every owner validated its leaf from the published parts, handed over its forfeit and its exit authorisation, and holds an \
		accumulator coin that resolves");
	settle(&r).await;

	// 2. Owner 7 leaves on its own: the exit, the entry, the leaf's exit.
	let (valid7, pre7, auth7) = match &coins[7].1.origin {
		ValidOrigin::Accumulator { valid, preimage, auth } => (valid.clone(), *preimage, *auth),
		_ => unreachable!(),
	};
	let batch_at = OutPoint::new(round.txid(), vout);
	let exit = valid7.exit_tx(acc.policy(), batch_at, acc.total(), &auth7, &FeeSource::Reserve).unwrap();
	let exit_id = send(&r, "owner 7's exit from the accumulator batch, by its own authorisation", &exit.tx);
	r.produce().await;
	let entry = valid7.entry_tx(OutPoint::new(exit_id, 0), &pre7, &FeeSource::Reserve).unwrap();
	let leaf_id = send(&r, "owner 7's entry, with its preimage", &entry.tx);
	r.produce().await;
	let state1 = acc.policy().after(valid7.exit.slot);
	for (i, (_, coin)) in coins.iter().enumerate().filter(|(i, _)| *i != 7) {
		let ValidOrigin::Accumulator { valid, auth, .. } = &coin.origin else { unreachable!() };
		state1.check_slot(&r.chain, &valid.exit, auth).unwrap_or_else(|e| panic!("owner {}'s slot after the exit: {}", i, e));
		resolve(&coins[i].0, std::slice::from_ref(&round), &r.policy());
	}
	println!("after owner 7's exit the other {} coins resolve and their authorisations take their slots out of the new state", OWNERS - 1);
	advance_mtp(&r, 37 * HOUR).await;
	let claim = exit_tx(&r, &valid7.leaf, OutPoint::new(leaf_id, 0), x, valid7.entry.value, &keys[7]);
	let claimed = send(&r, "owner 7's leaf, its exit after its delay", &claim);
	r.produce().await;
	assert!(r.rt.client().confirmations(&claimed).unwrap() >= 1);

	// 3. The expiry: the release at E, nothing during the notice, then the
	// sweep of the batch output where the exit left it.
	let schedule = acc.params().schedule.clone();
	let token_subject = schedule.token.into_inner().to_byte_array().to_vec();
	r.server.watcher.pass().await.unwrap();
	assert!(of_kind(&r, "release").await.is_empty(), "nothing before the expiry");
	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, schedule.expiries()[0].to_consensus_u32().saturating_sub(now) + HOUR).await;
	drive(&r, "the release at the expiry", 4, |l| has(l, "release", &token_subject)).await;
	settle(&r).await;
	r.server.watcher.pass().await.unwrap();
	assert!(of_kind(&r, "sweep").await.is_empty(), "no sweep before the token has waited W at R");
	println!("after the release: no sweep during the notice");
	advance_mtp(&r, 37 * HOUR).await;
	drive(&r, "the sweep after the notice", 4, |l| has(l, "sweep", &token_subject)).await;
	settle(&r).await;
	let sw = of_kind(&r, "sweep").await.remove(0);
	let swtx: Transaction = elements::encode::deserialize(&sw.tx).unwrap();
	let swept: Vec<OutPoint> = swtx.input.iter().map(|i| i.previous_output).collect();
	println!("the sweep {} takes {:?}", txid(&sw), swept);
	assert!(swept.contains(&OutPoint::new(exit_id, 1)), "the batch output where owner 7's exit left it");
	assert_eq!(swtx.input.len(), 2, "the batch output and the token at R: the entry owner 7 unlocked is gone");
	assert!(r.rt.client().confirmations(&swtx.txid()).unwrap() >= 1);
}
