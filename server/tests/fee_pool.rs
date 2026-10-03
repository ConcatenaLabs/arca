//! The watcher's work in an asset the node does not accept for fees, where
//! a coin of the operator's wallet pays every forfeit and every claim: review
//! R7's P5 turned around. The watcher works by deadline (answers to exits,
//! then claims, then new forfeits), spends the change of its own pending
//! transactions rather than wait for it to be final, and publishes no forfeit
//! whose claim the fee pool cannot cover, saying so in its metric and its log.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::{OutPoint, Txid};
use serde_json::json;

use arca_covenant::sign::sign_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::{BoardRecord, CoinRecord, ExplicitOutput, Forfeit, RelativeTime, Template, WalletPolicy};
use common::client::{auths_json, forfeit_sig, hex, participation_body, random32, rebuild, Held};
use common::flow::{claimed, log};
use common::keys::{keypair, xonly};
use common::rounds::{created, mtp, round_final, status};
use common::running::Running;
use server::participations::OutputRequest;

const N: usize = 8;
const VALUE: u64 = 1_000_000;

fn tip_time(r: &Running) -> u64 {
	let h = r.rt.client().best_block_hash().unwrap();
	let v: serde_json::Value = r.rt.client().call("getblockheader", &[json!(h.to_string())]).unwrap();
	v["time"].as_u64().unwrap()
}

/// Eight boards of Y given up in one round, each owner released and holding
/// its preimage; their forfeits, and their owners' keys.
async fn eight_boards_of_y(r: &mut Running, d: RelativeTime) -> Vec<(elements::secp256k1_zkp::Keypair, arca_covenant::LeafId, Forfeit)> {
	let (x, y, s) = (r.x, r.y, xonly(&r.s));
	let mut boards = vec![];
	for i in 0..N {
		let key = keypair(&format!("board of Y {}", i));
		let nonce = r.http.operator_nonce();
		let record = BoardRecord { template: Template::Board1, owner: xonly(&key), owner_nonce: random32(), operator_nonce: nonce,
			exit_delay: d, asset: y, value: VALUE, chain: r.chain, operator: s };
		let coins = vec![r.purse.take_coin(y), r.purse.take_coin(x)];
		let tx = record.tx(&coins, x, 2_000, &common::node::op_true()).unwrap().tx;
		for (j, o) in tx.output.iter().enumerate().skip(1) {
			if !o.is_fee() { r.purse.put((OutPoint::new(tx.txid(), j as u32), o.clone())); }
		}
		r.rt.client().send_raw_transaction(&tx).unwrap();
		assert_eq!(r.http.register_board(&record, &tx).status, 200);
		boards.push((key, record, tx));
	}
	r.produce().await;
	r.bury().await;
	for (_, rec, _) in &boards {
		let (http, id) = (r.http.clone(), rec.leaf_id());
		r.wait("a board credited", || http.board_status(&id).json["state"] == "credited").await;
	}
	let mut parts = vec![];
	for (i, (key, rec, _)) in boards.iter().enumerate() {
		let held = Held { key: *key, nonce: rec.owner_nonce, id: rec.leaf_id(), record: CoinRecord::Board(*rec) };
		let new_key = keypair(&format!("new leaf of Y {}", i));
		let nonce = random32();
		let w = OutputRequest::Leaf { asset: y, value: VALUE, template: Template::Vtxo1, owner: xonly(&new_key), owner_nonce: nonce, exit_delay: d };
		let (body, id) = participation_body(&[&held], &[w], &[], None, s, r.chain);
		assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
		parts.push((held, new_key, nonce, id));
	}
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(r, &built.tx.txid()).await;
	let mut forfeits = vec![];
	for ((held, new_key, nonce, id), (_, _, btx)) in parts.iter().zip(&boards) {
		let st = status(r, id);
		let o = &st["outputs"][0];
		let published = r.http.post("tree", &json!({"txid": st["round"]["txid"], "vout": o["batch_vout"]})).ok();
		let record = rebuild(&published).record(o["leaf_index"].as_u64().unwrap() as usize);
		let policy = WalletPolicy { min_exit_delay: d, max_exit_delay: d, ..WalletPolicy::new(r.chain, s, mtp(r)) };
		let new_valid = record.validate(&built.tx, &policy, &xonly(new_key), nonce).unwrap();
		let old = held.record.resolve(std::slice::from_ref(btx), &WalletPolicy { min_exit_delay: d, max_exit_delay: d, ..r.policy() }).unwrap();
		let f = common::flow::forfeit_for(&old, &new_valid, &built.tx, &st);
		let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(id),
			"forfeits": [{"leaf_id": held.id.to_string(), "signature": forfeit_sig(&f, &held.key)}],
			"leaves": [auths_json(&new_valid, new_key, created(&record))]})).ok();
		assert_eq!(done["state"], "released", "{}", done);
		forfeits.push((held.key, held.id, f));
	}
	forfeits
}

/// Blocks a minute apart, a parent block every ten, the watcher passing
/// after each; every owner whose forfeit is on the chain tries its refund,
/// paying the fee in X with a coin of its own. Returns the refunds the node
/// took, once every forfeit is claimed or after `blocks`.
async fn run(r: &mut Running, forfeits: &[(elements::secp256k1_zkp::Keypair, arca_covenant::LeafId, Forfeit)], blocks: usize, label: &str) -> usize {
	let (x, y) = (r.x, r.y);
	let mut clock = tip_time(r);
	for _ in 0..12 {
		clock += 60;
		let _: serde_json::Value = r.rt.client().call("setmocktime", &[json!(clock)]).unwrap();
		r.produce().await;
	}
	let mut refunded = 0;
	for block in 0..blocks {
		r.synced().await;
		r.server.nursery.pass().await.unwrap();
		r.server.watcher.pass().await.unwrap();
		let l = log(r).await;
		let published = l.iter().filter(|w| w.kind == "forfeit").count();
		for (key, id, f) in forfeits {
			let fw = match l.iter().find(|w| w.kind == "forfeit" && w.subject == id.0.to_vec()) { Some(w) => w, None => continue };
			let op = OutPoint::new(Txid::from_byte_array(fw.txid), 0);
			if !r.unspent(&op) { continue; }
			let fc = r.purse.take_coin(x);
			let src = FeeSource::Coin { outpoint: fc.0, coin: fc.1.clone(), fee: 3_000, change: common::node::op_true() };
			let ks = f.refund(op, &[ExplicitOutput::new(y, f.output().value, common::node::op_true())], &src).unwrap();
			let sig = sign_digest(key, &ks.sighash(r.chain.genesis_hash()).unwrap(), &random32());
			let tx = ks.finish(vec![sig.as_ref().to_vec()]).tx;
			if r.rt.client().send_raw_transaction(&tx).is_ok() {
				refunded += 1;
				for (j, o) in tx.output.iter().enumerate() {
					if !o.is_fee() && o.asset.explicit() == Some(x) {
						r.purse.put((OutPoint::new(tx.txid(), j as u32), o.clone()));
					}
				}
			} else {
				r.purse.put(fc);
			}
		}
		let st = r.server.watcher.fee_status();
		println!("{}: block {:3} (mtp {}): forfeits published {}, claimed {}, refunds {}; held for fees {}, pool {:?}",
			label, block, mtp(r).to_consensus_u32(), published, claimed(&l), refunded, st.held_for_fees, st.pools);
		if claimed(&l) + refunded >= N {
			break;
		}
		clock += 60;
		let _: serde_json::Value = r.rt.client().call("setmocktime", &[json!(clock)]).unwrap();
		if block % 10 == 9 {
			r.rt.mine_parent(1).unwrap();
		}
		r.produce().await;
	}
	refunded
}

/// R7's P5: two coins of X pay for eight forfeits and their claims in Y,
/// a parent block every ten blocks. Every forfeit is claimed; no refund.
#[tokio::test(flavor = "multi_thread")]
async fn two_fee_coins_serve_eight_forfeits_of_an_unlisted_asset() {
	let d = RelativeTime::from_units(8).unwrap();
	let mut r = Running::start_with(|c, y| {
		c.exit_delay_units = Some((8, 8));
		c.assets.push(server::server::AssetSection { asset: y.to_string(), min_leaf: common::running::MIN_LEAF.to_string() });
	}).await;
	let (x, y) = (r.x, r.y);
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(y, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let forfeits = eight_boards_of_y(&mut r, d).await;
	let coins = r.server.store.wallet_coins(Some(&x.into_inner().to_byte_array())).await.unwrap();
	println!("P5: {} boards of Y given up and released; the wallet holds {} coin(s) of X", N, coins.len());
	let refunded = run(&mut r, &forfeits, 150, "P5").await;
	let l = log(&r).await;
	println!("P5: RESULT: {} forfeits, {} claimed, {} refunded", N, claimed(&l), refunded);
	assert_eq!((claimed(&l), refunded), (N, 0));
}

/// A fee pool too small for every forfeit's claim: the watcher publishes
/// only the forfeits it can fund, says so, and publishes the rest once the
/// wallet is paid more.
#[tokio::test(flavor = "multi_thread")]
async fn no_forfeit_goes_out_unfunded() {
	let d = RelativeTime::from_units(8).unwrap();
	let mut r = Running::start_with(|c, y| {
		c.exit_delay_units = Some((8, 8));
		c.assets.push(server::server::AssetSection { asset: y.to_string(), min_leaf: common::running::MIN_LEAF.to_string() });
		// Fees a thousand times the floor: a small pool covers few of them.
		c.fee_multiple = 1_000;
		c.metrics_listen = Some("127.0.0.1:0".into());
	}).await;
	let (x, y) = (r.x, r.y);
	r.fund_wallet_in(x, 400_000).await;
	r.fund_wallet_in(y, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let forfeits = eight_boards_of_y(&mut r, d).await;
	r.synced().await;
	r.server.watcher.pass().await.unwrap();
	let st = r.server.watcher.fee_status();
	let l = log(&r).await;
	let published = l.iter().filter(|w| w.kind == "forfeit").count();
	println!("short pool: {} forfeit(s) published, {} held for fees, pools {:?}", published, st.held_for_fees, st.pools);
	assert!(published < N && st.held_for_fees == N - published, "the pool covers fewer than eight");
	let (pool, owed) = st.pools[&x];
	assert!(owed * 2 <= pool, "what is outstanding fits the pool twice over: {} of {}", owed, pool);
	let metrics = minreq::get(format!("http://{}/metrics", r.server.metrics_addr.unwrap())).send().unwrap();
	let text = metrics.as_str().unwrap().to_string();
	println!("{}", text.trim());
	assert!(text.contains(&format!("arca_watcher_forfeits_held{{reason=\"fee_pool\"}} {}", N - published)));
	// The wallet is paid more X: the rest go out, and every one is claimed.
	r.fund_wallet_in(x, 100_000_000).await;
	r.produce().await;
	r.bury().await;
	let refunded = run(&mut r, &forfeits, 150, "funded").await;
	let l = log(&r).await;
	println!("funded: RESULT: {} forfeits, {} claimed, {} refunded", N, claimed(&l), refunded);
	assert_eq!((claimed(&l), refunded), (N, 0));
}
