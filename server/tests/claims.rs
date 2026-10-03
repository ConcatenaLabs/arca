//! Every forfeit of a round is claimed before its refund opens, however many
//! boards the round took: review R7's P4 turned around, at 16, 200 and 2,000
//! forfeits in one round.
//!
//! The chain runs as the live ones do: one block a minute (the node's clock
//! moved by hand) and blocks of 400,000 weight units. Each forfeit's refund
//! delay is the shortest there is, one unit (512 s, under nine blocks). The
//! watcher passes once a block, as its own task does; after each block every
//! owner whose forfeit is in a block and unclaimed tries its refund, and the
//! test fails at the first the node takes. The watcher claims every forfeit
//! of the round that is in a block, in one transaction against one atom of
//! the round's connector asset, and publishes board forfeits no faster than
//! its share of a block lets them be claimed.
//!
//! 2,000 forfeits take several minutes: that case is ignored by default, and
//! run with `cargo test -p arca-server --test claims -- --ignored`.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::time::Instant;

use elements::hashes::Hash;
use elements::{OutPoint, Transaction, Txid};
use serde_json::json;

use arca_covenant::sign::sign_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::{BoardRecord, CoinRecord, ExplicitOutput, Forfeit, RelativeTime, Template, WalletPolicy};
use common::client::{auths_json, forfeit_sig, hex, participation_body, random32, rebuild, Held};
use common::flow::{claimed, log};
use common::keys::{keypair, xonly};
use common::node::op_true;
use common::rounds::{created, mtp, round_final, status};
use common::running::Running;
use sequentia_ext::{explicit_txout, AssetAmount, TxOutExt};
use server::participations::OutputRequest;
use server::store::NurseryState;

const VALUE: u64 = 1_000_000;

fn tip_time(r: &Running) -> u64 {
	let h = r.rt.client().best_block_hash().unwrap();
	let v: serde_json::Value = r.rt.client().call("getblockheader", &[json!(h.to_string())]).unwrap();
	v["time"].as_u64().unwrap()
}

/// One block a minute after the last.
async fn minute(r: &Running) {
	let t = tip_time(r) + 60;
	let _: serde_json::Value = r.rt.client().call("setmocktime", &[json!(t)]).unwrap();
	r.produce().await;
}

/// Produces blocks a minute apart until the mempool is empty.
async fn drain(r: &Running) {
	for _ in 0..40 {
		let pool: Vec<String> = r.rt.client().call("getrawmempool", &[]).unwrap();
		if pool.is_empty() {
			return;
		}
		minute(r).await;
	}
	panic!("the mempool did not empty");
}

async fn claims_keep_up(n: usize) {
	let one = RelativeTime::from_units(1).unwrap();
	let mut r = Running::start_on(&["-con_maxblockweight=400000"], |c, _| {
		c.exit_delay_units = Some((1, 1));
		// The server's own tasks follow the chain at the default pace; the
		// test drives the watcher itself.
		c.finality.poll_interval_ms = 1000;
	}).await;
	let x = r.x;
	let s = xonly(&r.s);
	let t0 = Instant::now();
	// The operator's wallet: enough of X for the round's leaves.
	r.fund_wallet_in(x, n as u64 * VALUE + 100_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	// A coin per board, from fan-outs of the purse.
	let mut coins = vec![];
	for chunk in (0..n).collect::<Vec<_>>().chunks(500) {
		let outs = vec![explicit_txout(AssetAmount::new(x, VALUE + 10_000), op_true()); chunk.len()];
		let tx = tokio::task::block_in_place(|| r.purse.pay(&r.rt, outs));
		for i in 0..chunk.len() {
			coins.push((OutPoint::new(tx.txid(), i as u32), tx.output[i].clone()));
		}
	}
	drain(&r).await;
	r.bury().await;
	r.synced().await;

	// N boards, each paid, broadcast and registered.
	let mut boards = vec![];
	for (i, coin) in coins.into_iter().enumerate() {
		let key = keypair(&format!("board {} of {}", i, n));
		let nonce = r.http.operator_nonce();
		let record = BoardRecord { template: Template::Board1, owner: xonly(&key), owner_nonce: random32(), operator_nonce: nonce,
			exit_delay: one, asset: x, value: VALUE, chain: r.chain, operator: s };
		let tx = record.tx(&[coin], x, 2_000, &op_true()).unwrap().tx;
		r.rt.client().send_raw_transaction(&tx).unwrap();
		assert_eq!(r.http.register_board(&record, &tx).status, 200);
		boards.push((key, record, tx));
		if boards.len() % 200 == 0 {
			minute(&r).await;
		}
	}
	drain(&r).await;
	r.bury().await;
	r.synced().await;
	let started = Instant::now();
	while r.server.store.boards_in(server::store::BoardState::Credited).await.unwrap().len() < n {
		assert!(started.elapsed().as_secs() < 300, "the boards were not credited");
		r.server.boards.pass().await.unwrap();
		tokio::time::sleep(std::time::Duration::from_millis(200)).await;
	}
	println!("N = {}: {} boards credited ({:?})", n, n, t0.elapsed());

	// Participations of sixteen boards each, for one leaf of their value.
	let mut parts = vec![];
	for (j, group) in boards.chunks(16).enumerate() {
		let held: Vec<Held> = group.iter().map(|(k, rec, _)| Held { key: *k, nonce: rec.owner_nonce, id: rec.leaf_id(), record: CoinRecord::Board(*rec) }).collect();
		let new_key = keypair(&format!("new leaf {} of {}", j, n));
		let nonce = random32();
		common::client::hold_key(&new_key);
		let w = OutputRequest::Leaf { asset: x, value: VALUE * group.len() as u64, template: Template::Vtxo1, owner: xonly(&new_key),
			owner_nonce: nonce, exit_delay: one };
		let refs: Vec<&Held> = held.iter().collect();
		let (body, id) = participation_body(&refs, &[w], &[], None, s, r.chain);
		assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
		parts.push((held, group.iter().map(|(_, _, t)| t.clone()).collect::<Vec<Transaction>>(), new_key, nonce, id));
	}
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	assert_eq!(built.participations, parts.len());
	drain(&r).await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;

	// Every owner hands over its forfeits and gets its preimage.
	let mut forfeits: Vec<(elements::secp256k1_zkp::Keypair, arca_covenant::LeafId, Forfeit)> = vec![];
	for (held, txs, new_key, nonce, id) in &parts {
		let st = status(&r, id);
		let o = &st["outputs"][0];
		let published = r.http.post("tree", &json!({"txid": st["round"]["txid"], "vout": o["batch_vout"]})).ok();
		let record = rebuild(&published).record(o["leaf_index"].as_u64().unwrap() as usize);
		let policy = WalletPolicy { min_exit_delay: one, max_exit_delay: one, ..WalletPolicy::new(r.chain, s, mtp(&r)) };
		let new_valid = record.validate(&built.tx, &policy, &xonly(new_key), nonce).unwrap();
		let c = st["round"]["connector_vout"].as_u64().unwrap() as u32;
		let mut sigs = vec![];
		for (k, (h, t)) in held.iter().zip(txs).enumerate() {
			let old = h.record.resolve(std::slice::from_ref(t), &WalletPolicy { min_exit_delay: one, max_exit_delay: one, ..r.policy() }).unwrap();
			let margin: u64 = st["inputs"][k]["margin"].as_str().unwrap().parse().unwrap();
			let f = Forfeit::for_refresh(old.leaf, (old.asset, old.value), old.id, &new_valid, &built.tx, c, one, margin).unwrap();
			sigs.push(json!({"leaf_id": h.id.to_string(), "signature": forfeit_sig(&f, &h.key)}));
			forfeits.push((h.key, h.id, f));
		}
		let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(id), "forfeits": sigs,
			"leaves": [auths_json(&new_valid, new_key, created(&record))]})).ok();
		assert_eq!(done["state"], "released", "{}", done);
	}
	println!("N = {}: round {} final, {} participations released, every owner holds its preimage ({:?})",
		n, built.tx.txid(), parts.len(), t0.elapsed());

	// A minute a block; the median time five blocks behind the tip, as on
	// a live chain.
	for _ in 0..12 {
		minute(&r).await;
	}
	let mut first_block = None;
	for block in 0..400 {
		r.synced().await;
		r.server.nursery.pass().await.unwrap();
		r.server.watcher.pass().await.unwrap();
		let l = log(&r).await;
		// Every forfeit in a block whose claim is not: its refund must not be
		// open. A refund can go in the next block once the tip's median time
		// is the refund delay past that of the block before the forfeit's.
		let by_leaf: std::collections::HashMap<Vec<u8>, &server::store::WatcherTxRow> =
			l.iter().filter(|w| w.kind == "forfeit").map(|w| (w.subject.clone(), w)).collect();
		let tip_mtp = mtp(&r).to_consensus_u32() as u64;
		let mut tried = 0;
		for (key, id, f) in &forfeits {
			let fw = match by_leaf.get(&id.0.to_vec()) { Some(w) => w, None => continue };
			let op = OutPoint::new(Txid::from_byte_array(fw.txid), 0);
			let in_chain: serde_json::Value = r.rt.client().call("gettxout", &[json!(op.txid.to_string()), json!(0), json!(false)]).unwrap();
			if in_chain.is_null() {
				continue;
			}
			let raw: serde_json::Value = r.rt.client().call("getrawtransaction", &[json!(op.txid.to_string()), json!(true)]).unwrap();
			let held: serde_json::Value = r.rt.client().call("getblockheader", &[raw["blockhash"].clone()]).unwrap();
			let before: serde_json::Value = r.rt.client().call("getblockheader", &[held["previousblockhash"].clone()]).unwrap();
			let opens = before["mediantime"].as_u64().unwrap() + 512;
			assert!(tip_mtp < opens, "N = {}: pass {}: the refund of {}'s forfeit is open (tip median time {}, opens at {}) and \
				no claim of it is in a block", n, block, id, tip_mtp, opens);
			// Its owner tries anyway: the node refuses it.
			tried += 1;
			let ks = f.refund(op, &[ExplicitOutput::new(x, f.output().value - 3_000, op_true())], &FeeSource::Reserve).unwrap();
			let sig = sign_digest(key, &ks.sighash(r.chain.genesis_hash()).unwrap(), &random32());
			let tx = ks.finish(vec![sig.as_ref().to_vec()]).tx;
			let a = r.rt.client().test_mempool_accept(&[&tx]).unwrap().remove(0);
			assert!(!a.allowed, "N = {}: block {}: the owner of {} can refund its forfeit", n, block, id);
		}
		let published = l.iter().filter(|w| w.kind == "forfeit").count();
		let claims_final = l.iter().filter(|w| w.kind == "claim" && w.state == NurseryState::Final).map(|w| w.subject.len() / 32).sum::<usize>();
		if published > 0 && first_block.is_none() {
			first_block = Some(block);
		}
		if block % 5 == 0 || claimed(&l) == n {
			println!("N = {}: block {:3}: forfeits published {:4}, claimed {:4} ({} final), refunds tried {} and refused",
				n, block, published, claimed(&l), claims_final, tried);
		}
		if claimed(&l) == n {
			break;
		}
		minute(&r).await;
	}
	// Every claim into a block.
	drain(&r).await;
	r.bury().await;
	r.synced().await;
	r.server.nursery.pass().await.unwrap();
	let l = log(&r).await;
	assert_eq!(claimed(&l), n, "every forfeit claimed");
	let claims: Vec<Transaction> = l.iter().filter(|w| w.kind == "claim").map(|w| elements::encode::deserialize(&w.tx).unwrap()).collect();
	assert!(l.iter().filter(|w| w.kind == "claim").all(|w| w.state == NurseryState::Final), "every claim final");
	let forfeit_vsize = l.iter().filter(|w| w.kind == "forfeit").map(|w| elements::encode::deserialize::<Transaction>(&w.tx).unwrap().vsize())
		.max().unwrap();
	let biggest = claims.iter().max_by_key(|t| t.input.len()).unwrap();
	let fee: u64 = claims.iter().flat_map(|t| t.output.iter()).filter(|o| o.is_fee()).map(|o| o.explicit_value().unwrap()).sum();
	println!("N = {}: RESULT: {} forfeits ({} vB each), {} claimed in {} claim transaction(s), the largest {} forfeits in {} vB; \
		no refund opened; claim fees {} atoms of X; {:?}",
		n, n, forfeit_vsize, claimed(&l), claims.len(), biggest.input.len() - 1, biggest.vsize(), fee, t0.elapsed());
	let _ = first_block;
}

#[tokio::test(flavor = "multi_thread")]
async fn sixteen_forfeits_are_claimed_before_any_refund_opens() {
	claims_keep_up(16).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn two_hundred_forfeits_are_claimed_before_any_refund_opens() {
	claims_keep_up(200).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "takes minutes: run with --ignored"]
async fn two_thousand_forfeits_are_claimed_before_any_refund_opens() {
	claims_keep_up(2000).await;
}
