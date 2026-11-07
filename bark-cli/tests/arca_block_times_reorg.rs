//! A coin's dates follow the chain the node holds now. The wallet reads a
//! block's median time once, by the block's hash, and keeps it; whether the
//! block is in the active chain is read again in every view. So when an
//! anchor reorganisation takes a board's block out of the chain and the board
//! is mined again in another block, the wallet that read the first block's
//! time dates the coin from the new block, never from the time it kept for
//! the orphaned one.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::Script;
use serde_json::{json, Value};

use bark::arca::{command, Wallet};
use common::cli::Arca;
use common::node::advance_mtp;
use common::running::Running;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

/// The coin `leaf` as the wallet lists it, after the re-check the command
/// runs first. The same open wallet each time, so what its chain source
/// kept from earlier commands is kept here too.
fn coin(w: &mut Wallet, leaf: &str) -> Value {
	let v = tokio::task::block_in_place(|| command::run(w, "coins", &json!({}))).expect("coins");
	v["result"].as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).cloned().unwrap_or(Value::Null)
}

/// The block holding `txid` and its median time, as the node has it now.
fn block_of(r: &Running, txid: &str) -> Option<(String, u64)> {
	let c = r.rt.client();
	let t: Value = c.call("getrawtransaction", &[json!(txid), json!(true)]).ok()?;
	let hash = t["blockhash"].as_str()?.to_string();
	let h: Value = c.call("getblockheader", &[json!(hash), json!(true)]).unwrap();
	Some((hash, h["mediantime"].as_u64().unwrap()))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_coins_dates_follow_its_board_into_another_block() {
	let mut r = Running::start().await;
	let (url, x) = (r.url(), r.x);
	let a = Arca::new("BTRA");
	a.ok(&["create", "--server", &url, "--node-url", &r.node_url(), "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, x, 5_000_000);
	r.produce().await;

	// A parent block of the board's own: orphaning it takes the board's
	// block, and every block after it, out of the chain.
	let p = tokio::task::block_in_place(|| {
		r.rt.mine_parent(1).unwrap();
		r.rt.anchor_to_parent_tip().unwrap();
		r.rt.parent.client().block_count().unwrap()
	});
	let pool_before: Vec<String> = r.rt.client().call("getrawmempool", &[]).unwrap();
	let leaf = a.ok(&["board", &x.to_string(), "2000000"])["leaf_id"].as_str().unwrap().to_string();
	let pool: Vec<String> = r.rt.client().call("getrawmempool", &[]).unwrap();
	let board: Vec<String> = pool.into_iter().filter(|t| !pool_before.contains(t)).collect();
	assert_eq!(board.len(), 1, "the board alone: {:?}", board);
	let board = board[0].clone();
	// One wallet open from here on, as a program keeps it: it reads the
	// board's block, and keeps its time, as soon as the board is mined.
	let mut w = tokio::task::block_in_place(|| Wallet::open(&a.dir)).expect("open the wallet");
	r.produce().await;
	let (first_block, first_time) = block_of(&r, &board).expect("the board in a block");
	let mined = coin(&mut w, &leaf);
	println!("the board {} in block {} (median time {}): the coin {} expires {}", board, first_block, first_time, mined["state"],
		mined["expiry"]);
	let lifetime = mined["expiry"].as_u64().expect("dated once in a block") - first_time;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	let first = coin(&mut w, &leaf);
	println!("buried and credited: the coin {} expires {}", first["state"], first["expiry"]);
	assert_eq!(first["state"], "live", "{}", first);
	assert_eq!(first["expiry"].as_u64(), Some(first_time + lifetime));

	// The board's block goes out of the chain with its parent block; the
	// board is back in the mempool, and kept out of blocks while the chain's
	// median time moves on an hour.
	let c = r.rt.client();
	let _: Value = c.call("prioritisetransaction", &[json!(board), json!(0), json!(-1_000_000_000i64)]).unwrap();
	tokio::task::block_in_place(|| r.rt.orphan_parent_from(p)).unwrap();
	assert!(block_of(&r, &board).is_none(), "the board is in no block");
	let out = coin(&mut w, &leaf);
	println!("the board out of the chain: the coin {} ({})", out["state"], out["note"]);
	assert_ne!(out["state"], "live", "a coin on a board in no block is not live");
	tokio::task::block_in_place(|| advance_mtp(&r.rt, 3_600));
	assert!(block_of(&r, &board).is_none(), "the board kept out of the blocks the median time moved in");

	// Mined again, in another block an hour later, and buried.
	let _: Value = c.call("prioritisetransaction", &[json!(board), json!(0), json!(1_000_000_000i64)]).unwrap();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let (again_block, again_time) = block_of(&r, &board).expect("the board mined again");
	assert_ne!(again_block, first_block);
	assert!(again_time >= first_time + 3_600, "the new block is an hour later: {} then {}", first_time, again_time);
	let again = coin(&mut w, &leaf);
	println!("the board in block {} (median time {}): the coin {} expires {}", again_block, again_time, again["state"], again["expiry"]);
	assert_eq!(again["state"], "live", "{}", again);
	assert_eq!(again["expiry"].as_u64(), Some(again_time + lifetime), "dated from the block the chain holds now, not the orphaned one");
	let _ = std::fs::remove_dir_all(&a.dir);
}
