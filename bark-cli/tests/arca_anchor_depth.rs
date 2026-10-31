//! The wallet judges finality by the anchor depth its operator publishes.
//!
//! An operator at depth 0 (the public testnet's setting) calls a round final
//! once its block is certified, its anchor buried by no Bitcoin block, and
//! the wallet does too: the coin it takes from the round is live, and
//! spendable, at once. Bitcoin anchoring stays supreme: when the parent
//! chain reorganises the block the round's block anchors to, the round
//! leaves the chain with it, and the wallet shows the coin as being redone,
//! still counted in its balance; once the round is in a block again and
//! certified, the coin is live again, the balance the same throughout.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::{AssetId, Script};
use serde_json::{json, Value};

use common::cli::Arca;
use common::running::Running;
use server::store::RoundState;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn coin_of(w: &Arca, leaf: &str) -> Value {
	w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).cloned().unwrap_or(Value::Null)
}

fn rpc(r: &Running, method: &str, params: &[Value]) -> Value {
	r.rt.client().call(method, params).unwrap()
}

/// The Bitcoin height the anchor of Sequentia block `hash` commits to.
fn anchor_of(r: &Running, hash: &str) -> u64 {
	let hash: elements::BlockHash = hash.parse().unwrap();
	sequentia_ext::BlockHeaderExt::bitcoin_anchor(&r.rt.client().block_header(&hash).unwrap()).height as u64
}

/// Where `txid` is: its block's hash and its confirmations, or none and 0.
fn block_of(r: &Running, txid: &elements::Txid) -> (Option<String>, i64) {
	let v = rpc(r, "getrawtransaction", &[json!(txid.to_string()), json!(true)]);
	(v["blockhash"].as_str().map(str::to_string), v["confirmations"].as_i64().unwrap_or(0))
}

/// Creates `w` and boards `amount` of `asset`, the fee in the asset boarded;
/// waits until the board is credited.
async fn boarded(r: &mut Running, w: &Arca, server: &str, asset: AssetId, amount: u64) -> String {
	w.ok(&["create", "--server", server, "--node-url", &r.node_url(), "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	let s = Script::from(unhex(w.ok(&["address"])["script_pubkey"].as_str().unwrap()));
	r.pay_to(s, asset, amount + 3_000_000);
	r.produce().await;
	let board = w.ok(&["board", &asset.to_string(), &amount.to_string()])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
	assert_eq!(coin_of(w, &board)["state"], "live");
	board
}

/// Produces Sequentia blocks until the server calls round `txid` final, and
/// returns the block holding it. No parent block is mined: a block is final
/// at depth 0 once it is certified.
async fn certified(r: &Running, txid: &elements::Txid) -> String {
	for _ in 0..10 {
		r.produce().await;
		r.synced().await;
		r.server.rounds.pass().await.unwrap();
		if r.server.store.round_by_txid(&elements::hashes::Hash::to_byte_array(*txid)).await.unwrap().map(|x| x.state) == Some(RoundState::Final) {
			return block_of(r, txid).0.expect("a final round is in a block");
		}
	}
	panic!("round {} did not become final at depth 0", txid);
}

#[tokio::test(flavor = "multi_thread")]
async fn at_depth_zero_a_certified_coin_is_live_and_a_bitcoin_reorg_redoes_it() {
	let mut r = Running::start_with(|cfg, _, _| cfg.finality.anchor_depth = 0).await;
	let url = r.url();
	let x = r.x;
	let c = Arca::new("FD1");
	let board = boarded(&mut r, &c, &url, x, 2_000_000).await;
	let info = c.ok(&["info"]);
	println!("FD1 the operator publishes {}; the wallet counts anchor depth {}", info["server_info"]["finality"], info["anchor_depth"]);
	assert_eq!(info["server_info"]["finality"]["anchor_depth"], 0);
	assert_eq!(info["anchor_depth"], 0, "the wallet follows the operator's depth");

	// Round R, in a block anchored to a parent block of its own; nothing
	// buries that anchor.
	let pid = c.ok(&["participate", "--leaf", &board])["participations"][0]["participation"].as_str().unwrap().to_string();
	tokio::task::block_in_place(|| {
		r.rt.mine_parent(1).unwrap();
		r.rt.anchor_to_parent_tip().unwrap();
	});
	let p_r = r.rt.parent.client().block_count().unwrap();
	let started = std::time::Instant::now();
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let rtx = built.tx.txid();
	let block = certified(&r, &rtx).await;
	let tip = rpc(&r, "getbestblockhash", &[]);
	let depth = anchor_of(&r, tip.as_str().unwrap()) - anchor_of(&r, &block);
	println!("FD1 round {} final at the server in block {} (anchored at parent {}), anchor buried {} block(s)", rtx, block, p_r, depth);
	assert_eq!(depth, 0, "final with its anchor buried by no Bitcoin block");
	let s = c.ok(&["sync"]);
	let p = s["participations"].as_array().unwrap().iter().find(|p| p["participation"] == pid.as_str()).cloned().unwrap();
	let leaf = p["new_leaves"][0]["leaf_id"].as_str().unwrap().to_string();
	let coin = coin_of(&c, &leaf);
	println!("FD1 the wallet's coin of R, {} ms after the round: {}", started.elapsed().as_millis(), coin);
	assert_eq!(coin["state"], "live", "certified is final at depth 0: {}", coin);
	assert_eq!(coin["redoing"], false);
	let held = c.ok(&["balance"])["held"][x.to_string()].clone();
	println!("FD1 balance before the reorganisation: {}", c.ok(&["balance"]));

	// The parent chain reorganises the block R's block anchors to: the node
	// disconnects R's block and every block above it, and R is in its
	// mempool again.
	let orphaned = tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_r)).unwrap();
	let (at, confs) = block_of(&r, &rtx);
	println!("FD1 parent block(s) {:?} orphaned: R in block {:?}, {} confirmation(s), in the mempool: {}", orphaned, at, confs,
		rpc(&r, "getrawmempool", &[]).as_array().unwrap().iter().any(|t| t == &json!(rtx.to_string())));
	assert!(confs < 1, "R left the chain with its anchor");
	let re = c.ok(&["recheck"]);
	println!("FD1 the wallet's re-check after the reorganisation: {}", re["changes"]);
	let coin = coin_of(&c, &leaf);
	println!("FD1 the coin while R is out of the chain: {}", coin);
	assert_eq!(coin["state"], "pending", "not final while its round is out of the chain: {}", coin);
	assert_eq!(coin["redoing"], true, "shown as being redone, not lost: {}", coin);
	assert!(coin["note"].as_str().unwrap().starts_with(bark::arca::REDOING), "{}", coin);
	let bal = c.ok(&["balance"]);
	println!("FD1 balance while R is redone: {}", bal);
	assert_eq!(bal["held"][x.to_string()], held, "still counted in what the wallet holds");

	// R is mined again and certified: the coin is live again.
	r.synced().await;
	let again = certified(&r, &rtx).await;
	println!("FD1 R in block {} again", again);
	assert_ne!(again, block);
	let s = c.ok(&["sync"]);
	println!("FD1 the wallet's sync: recheck {}", s["recheck"]["changes"]);
	let coin = coin_of(&c, &leaf);
	println!("FD1 the coin after R is redone: {}", coin);
	assert_eq!(coin["state"], "live", "{}", coin);
	assert_eq!(coin["redoing"], false);
	assert_eq!(c.ok(&["balance"])["held"][x.to_string()], held);
	let _ = std::fs::remove_dir_all(&c.dir);
}
