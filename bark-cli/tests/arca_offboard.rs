//! Paying an address on the chain from leaves (`arca offboard`), as the
//! wallet does it, against a whole Arca server on an anchored proof-of-stake
//! regtest chain.
//!
//! A wallet holding only leaves of X pays 300,000 X to another wallet's
//! on-chain address: the fee is quoted and shown, the offboard goes ahead on
//! that very quote, the operator's round pays the offboard output, `sync`
//! hands over the forfeit once the round is final, and the operator's watcher
//! unlocks the output into the address: its output 0 pays exactly 300,000 X
//! there, and `arca offboards` says it is paid and final. The change comes
//! back as a leaf of the round: the wallet takes the operator's release whole,
//! passing over the offboard's output, which sits in no batch. Refused beside it,
//! the coins staying the wallet's: a fee in another asset, more than the
//! wallet holds, a quote that is no longer the offboard's, and the operator's
//! refusal of an offboard paying one of the wallet's own leaf scripts, which
//! is final (a 4xx with its code): the wallet puts its coins back and posts
//! nothing again.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::{AssetId, Script, Txid};
use serde_json::{json, Value};

use arca_covenant::CoinRecord;
use common::cli::Arca;
use common::proxy::Proxy;
use common::running::Running;
use server::server::AssetSection;
use server::store::RoundState;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn create_args<'a>(server: &'a str, node: &'a str) -> Vec<&'a str> {
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

/// A wallet whose only holding of `asset` is one coin boarded whole.
async fn leaves_only(r: &mut Running, name: &str, asset: AssetId, paid: u64) -> Arca {
	let url = r.url();
	leaves_only_at(r, name, asset, paid, &url).await
}

/// [`leaves_only`], the wallet talking to the operator at `url`.
async fn leaves_only_at(r: &mut Running, name: &str, asset: AssetId, paid: u64, url: &str) -> Arca {
	let (url, node) = (url.to_string(), r.node_url());
	let w = Arca::new(name);
	w.ok(&create_args(&url, &node));
	r.pay_to(script(&w.ok(&["address"])), asset, paid);
	r.produce().await;
	let mut amount = paid - paid / 100;
	for _ in 0..4 {
		let q = w.ok(&["board", &asset.to_string(), &amount.to_string(), "--quote"]);
		let fee: u64 = q["fee"]["amount"].as_str().unwrap().parse().unwrap();
		if amount + fee == paid {
			break;
		}
		amount = paid - fee;
	}
	w.ok(&["board", &asset.to_string(), &amount.to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
	w
}

fn live_of(w: &Arca, asset: AssetId) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == json!(asset.to_string())).cloned().collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_offboard_pays_an_address_on_the_chain_and_a_refused_one_gives_the_coins_back() {
	let mut r = Running::start_with(|c, x, _| c.assets[0] = AssetSection::new(x, 1_000)).await;
	let (x, y) = (r.x, r.y);
	let a = leaves_only(&mut r, "OBA", x, 600_000).await;
	let b = Arca::new("OBB");
	b.ok(&create_args(&r.url(), &r.node_url()));
	let to = b.ok(&["address"]);
	let (address, spk) = (to["address"].as_str().unwrap().to_string(), script(&to));
	let coins = live_of(&a, x);
	assert_eq!(coins.len(), 1);
	let (xs, amount) = (x.to_string(), "300000");

	// Refused by the wallet, before anything is signed.
	let (ok, v) = a.run(&["offboard", "--asset", &xs, "--amount", amount, "--address", &address, "--fee-asset", &y.to_string()]);
	println!("a fee in Y: ok={} {}", ok, v["error"]["message"]);
	assert!(!ok && v["error"]["message"].as_str().unwrap().contains("paid in the asset it moves"), "{}", v);
	let (ok, v) = a.run(&["offboard", "--asset", &xs, "--amount", "5000000", "--address", &address]);
	println!("more than the wallet holds: ok={} {}", ok, v["error"]["message"]);
	assert!(!ok, "{}", v);
	let q = a.ok(&["offboard", "--asset", &xs, "--amount", amount, "--address", &address, "--quote"]);
	println!("the quote: {}", q);
	assert_eq!((q["amount"].as_str(), q["address"].as_str()), (Some(amount), Some(address.as_str())));
	let mut stale = q.clone();
	stale["fee"]["amount"] = json!("1");
	let (ok, v) = a.run(&["offboard", "--asset", &xs, "--amount", amount, "--address", &address, "--shown", &stale.to_string()]);
	println!("a quote that is not the offboard's: ok={} {}", ok, v["error"]["message"]);
	assert!(!ok && v["error"]["message"].as_str().unwrap().contains("changed since it was shown"), "{}", v);

	// Refused by the operator, for good: an offboard paying the wallet's own
	// leaf script. The coins are the wallet's again and nothing is posted
	// again.
	// The coin is a board: the script of its board output is one the
	// operator knows as an Arca script.
	let rec = a.ok(&["record", coins[0]["leaf_id"].as_str().unwrap()]);
	let own = match CoinRecord::from_bytes(&unhex(rec["record"].as_str().unwrap())).unwrap() {
		CoinRecord::Board(bd) => bd.output().script_pubkey,
		other => panic!("a boarded coin, not {:?}", other),
	};
	let own_hex: String = own.as_bytes().iter().map(|x| format!("{:02x}", x)).collect();
	let (ok, v) = a.run(&["offboard", "--asset", &xs, "--amount", amount, "--script", &own_hex]);
	println!("an offboard to the wallet's own board script: ok={} {}", ok, v["error"]);
	assert!(!ok);
	assert_eq!((v["error"]["kind"].as_str(), v["error"]["code"].as_str(), v["error"]["status"].as_i64()),
		(Some("server_refused"), Some("script_reused"), Some(409)), "{}", v);
	assert_eq!(live_of(&a, x).len(), 1, "the coin is the wallet's again");
	let s = a.ok(&["sync"]);
	assert!(s["participations"].as_array().is_none_or(|p| p.iter().all(|e| e["state"] != "pending")), "nothing posted again: {}",
		s["participations"]);
	assert_eq!(a.ok(&["offboards"])[0]["state"], "not_made");

	// Paid: the offboard on the quote shown, the round, the forfeit, the
	// operator's unlock into the address.
	let q = a.ok(&["offboard", "--asset", &xs, "--amount", amount, "--address", &address, "--quote"]);
	let asked = a.ok(&["offboard", "--asset", &xs, "--amount", amount, "--address", &address, "--shown", &q.to_string()]);
	println!("asked: {}", asked);
	let id = asked["offboard"].as_str().unwrap().to_string();
	assert_eq!(a.ok(&["offboards"])[1]["state"], "waiting");
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	assert_eq!(built[0].offboards, 1);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.round_state(&built[0].tx.txid(), RoundState::Final).await;
	let s = a.ok(&["sync"]);
	println!("the sync once the round is final: participations {}, offboards {}", s["participations"], s["offboards"]);
	let mut paid = Value::Null;
	for _ in 0..30 {
		r.produce().await;
		r.synced().await;
		let o = a.ok(&["offboards"])[1].clone();
		if o["state"] == "paid" {
			paid = o;
			break;
		}
		tokio::time::sleep(std::time::Duration::from_secs(2)).await;
	}
	println!("the offboard: {}", paid);
	assert_eq!((paid["offboard"].as_str(), paid["state"].as_str()), (Some(id.as_str()), Some("paid")), "{}", a.ok(&["offboards"]));
	let txid: Txid = paid["txid"].as_str().unwrap().parse().unwrap();
	let tx = r.rt.client().raw_transaction(&txid).unwrap();
	let out = &tx.output[0];
	assert_eq!((&out.script_pubkey, out.asset.explicit(), out.value.explicit()), (&spk, Some(x), Some(300_000)));
	// Final once its block is certified and its anchor buried.
	let mut o = Value::Null;
	for _ in 0..6 {
		r.produce().await;
		r.bury().await;
		r.synced().await;
		o = a.ok(&["offboards"])[1].clone();
		if o["final"] == true {
			break;
		}
	}
	println!("buried: {}", o);
	assert_eq!(o["final"], true, "{}", o);
	// A round found final at a complete re-check is not looked at again while
	// the chain only grows: the next re-check, a block later, skips it.
	let first = a.ok(&["recheck"]);
	r.produce().await;
	r.synced().await;
	let next = a.ok(&["recheck"]);
	println!("re-checks: rounds skipped as final {} then {}", first["rounds_final_skipped"], next["rounds_final_skipped"]);
	assert!(next["rounds_final_skipped"].as_u64().unwrap_or(0) >= 1, "{}", next);
	// The change, a leaf of the round, is the wallet's: the release is taken
	// whole. Asking a tree for the offboard's output, in no batch, was refused
	// ("invalid type: null, expected u32"), and the coin given up stayed
	// counted beside its change, which was never taken.
	let mut change = vec![];
	for _ in 0..5 {
		let s = a.ok(&["sync"]);
		let refused: Vec<&Value> = s["participations"].as_array().map(|p| p.iter().filter(|p| p.get("refused").is_some()).collect()).unwrap_or_default();
		assert!(refused.is_empty(), "the release refused: {:?}", refused);
		change = live_of(&a, x);
		if change.len() == 1 && change[0]["leaf_id"] != coins[0]["leaf_id"] {
			break;
		}
		r.produce().await;
		r.synced().await;
	}
	println!("the change: {:?}", change);
	assert_eq!(change.len(), 1, "{}", a.ok(&["coins"]));
	assert_ne!(change[0]["leaf_id"], coins[0]["leaf_id"], "the coin given up is not the wallet's any more");
	assert!(a.ok(&["coins"]).as_array().unwrap().iter().all(|c| c["state"] != "forfeited"), "{}", a.ok(&["coins"]));
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// A participation the server released while the wallet was away, as the
/// live operator released an offboard with change: at the forfeit step the
/// keeper is down, so the server records the forfeit without the operator's
/// half and the participation stands `forfeiting`; the keeper back, the
/// server completes the forfeit and releases the participation. The wallet's
/// next sync takes the release (`take_released`), rebuilding the round's new
/// leaves to find their preimage, and an offboard with change is taken whole
/// there too: the offboard's output, which sits in no batch, is passed over,
/// the change is the wallet's leaf and the coin given up is gone. Asking a
/// tree for the offboard's output (`"vout": null`) was refused on every sync
/// ("invalid type: null, expected u32"), and the coin given up stayed counted
/// beside its change, which was never taken.
#[tokio::test(flavor = "multi_thread")]
async fn an_offboard_with_change_released_while_the_wallet_was_away_is_taken_whole() {
	let mut r = Running::start_kept(1, None).await;
	let x = r.x;
	let a = leaves_only(&mut r, "OBC", x, 600_000).await;
	let b = Arca::new("OBD");
	b.ok(&create_args(&r.url(), &r.node_url()));
	let address = b.ok(&["address"])["address"].as_str().unwrap().to_string();
	let given = live_of(&a, x);
	assert_eq!(given.len(), 1);
	let (xs, amount) = (x.to_string(), "300000");
	let q = a.ok(&["offboard", "--asset", &xs, "--amount", amount, "--address", &address, "--quote"]);
	let asked = a.ok(&["offboard", "--asset", &xs, "--amount", amount, "--address", &address, "--shown", &q.to_string()]);
	let pid = asked["offboard"].as_str().unwrap().to_string();
	let id: [u8; 32] = unhex(&pid).try_into().unwrap();
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(built.len() == 1 && failed.is_empty(), "{} built, {} failed", built.len(), failed.len());
	assert_eq!(built[0].offboards, 1);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.round_state(&built[0].tx.txid(), RoundState::Final).await;
	// The forfeit goes in with the keeper down: held back, the participation `forfeiting`.
	r.keepers[0].halt();
	let s = a.ok(&["sync"]);
	println!("the sync with the keeper down: {}", s["participations"]);
	assert_eq!(r.server.store.unsigned_forfeits().await.unwrap().len(), 1, "the forfeit is recorded, held back");
	r.keepers[0].resume();
	r.server.forfeits.fill_unsigned().await.unwrap();
	r.server.rounds.pass().await.unwrap();
	let st = r.server.store.participation(&id).await.unwrap().unwrap().state;
	println!("the keeper back: at the server {:?}", st);
	assert_eq!(st, server::store::ParticipationState::Released);
	let mut change = vec![];
	for _ in 0..5 {
		let s = a.ok(&["sync"]);
		println!("a sync once released: {}", s["participations"]);
		let refused: Vec<&Value> = s["participations"].as_array().map(|p| p.iter().filter(|p| p.get("refused").is_some()).collect()).unwrap_or_default();
		assert!(refused.is_empty(), "the release refused: {:?}", refused);
		change = live_of(&a, x);
		if change.len() == 1 && change[0]["leaf_id"] != given[0]["leaf_id"] {
			break;
		}
		r.produce().await;
		r.synced().await;
	}
	println!("the change: {:?}", change);
	assert_eq!(change.len(), 1, "{}", a.ok(&["coins"]));
	assert_ne!(change[0]["leaf_id"], given[0]["leaf_id"], "the coin given up is not the wallet's any more");
	assert!(a.ok(&["coins"]).as_array().unwrap().iter().all(|c| c["state"] != "forfeited"), "{}", a.ok(&["coins"]));
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// The amount of an offboard of every coin of `asset` to `to` (`--address`
/// or `--script` and its value): no change.
fn whole(w: &Arca, asset: AssetId, to: [&str; 2]) -> String {
	let held: u64 = live_of(w, asset).iter().map(|c| c["value"].as_str().map_or_else(|| c["value"].as_u64().unwrap(), |v| v.parse().unwrap())).sum();
	let mut amount = held - held / 50;
	for _ in 0..6 {
		let q = w.ok(&["offboard", "--asset", &asset.to_string(), "--amount", &amount.to_string(), to[0], to[1], "--quote"]);
		let change: u64 = q["change"].as_str().unwrap().parse().unwrap();
		if change == 0 {
			return amount.to_string();
		}
		amount += change;
	}
	panic!("no offboard of every coin of {} found", asset);
}

/// The same coins, address and amount make the same participation as an
/// earlier offboard. Asked again, the wallet goes on with the one it has not
/// finished, and makes a new one beside one the operator refused: it never
/// fails on its own record of the first ("the store: UNIQUE constraint
/// failed: participation.id", arca#590), and never leaves the coins "still
/// arriving".
///
/// First the wallet's own board script, which the operator refuses for good
/// (`script_reused`): asked again, the operator refuses it again in its own
/// words. Then, each paying every coin of a wallet to an address:
/// - W1's offboard gets no answer (the operator slow past the wallet's
///   timeout, the call never reaching it: the live testnet's EURX payment):
///   its coin waits, given up; asked again, the offboard is posted again as
///   it stood and is under way;
/// - W2's answer is turned into a refusal on its way back while the operator
///   takes it (an answer misread): its coin is live again in its own eyes;
///   asked again, it is the offboard under way, its coin given up again.
/// One round pays both, and each wallet's next syncs show it paid.
#[tokio::test(flavor = "multi_thread")]
async fn an_offboard_asked_again_goes_on_with_the_first() {
	let mut r = Running::start_with(|c, x, _| c.assets[0] = AssetSection::new(x, 1_000)).await;
	let x = r.x;
	let xs = x.to_string();
	let proxy = Proxy::start(&r.url());
	let purl = proxy.url.clone();
	let w1 = leaves_only_at(&mut r, "OBW1", x, 600_000, &purl).await;
	let w2 = leaves_only_at(&mut r, "OBW2", x, 600_000, &purl).await;

	let coins = live_of(&w2, x);
	let rec = w2.ok(&["record", coins[0]["leaf_id"].as_str().unwrap()]);
	let own = match CoinRecord::from_bytes(&unhex(rec["record"].as_str().unwrap())).unwrap() {
		CoinRecord::Board(bd) => bd.output().script_pubkey,
		other => panic!("a boarded coin, not {:?}", other),
	};
	let own_hex: String = own.as_bytes().iter().map(|x| format!("{:02x}", x)).collect();
	let amount = whole(&w2, x, ["--script", &own_hex]);
	for attempt in 0..2 {
		let (ok, v) = w2.run(&["offboard", "--asset", &xs, "--amount", &amount, "--script", &own_hex]);
		println!("to the wallet's own board script, attempt {}: ok={} {}", attempt, ok, v["error"]);
		assert!(!ok);
		assert_eq!(v["error"]["code"].as_str(), Some("script_reused"), "{}", v);
		assert_eq!(live_of(&w2, x).len(), 1, "the coin is the wallet's again");
	}

	let b = Arca::new("OBW3");
	b.ok(&create_args(&r.url(), &r.node_url()));
	let to = b.ok(&["address"]);
	let (address, spk) = (to["address"].as_str().unwrap().to_string(), script(&to));

	// W1: no answer.
	let a1 = whole(&w1, x, ["--address", &address]);
	proxy.hold("/v1/submit_participation");
	let t = std::time::Instant::now();
	let (ok, v) = w1.run(&["offboard", "--asset", &xs, "--amount", &a1, "--address", &address]);
	proxy.release("/v1/submit_participation");
	println!("W1's offboard, unanswered: ok={} after {:.0} s: {}", ok, t.elapsed().as_secs_f64(), v["error"]);
	assert!(!ok);
	assert!(live_of(&w1, x).is_empty(), "the coin waits, given up to the offboard");
	assert_eq!(w1.ok(&["offboards"])[0]["state"], "waiting");
	let again = w1.ok(&["offboard", "--asset", &xs, "--amount", &a1, "--address", &address]);
	println!("W1 asks again: {}", again);
	assert_eq!((again["already"].as_bool(), again["state"].as_str()), (Some(true), Some("pending")), "{}", again);
	let id1 = again["offboard"].as_str().unwrap().to_string();

	// W2: its answer misread as a refusal.
	let a2 = whole(&w2, x, ["--address", &address]);
	proxy.rewrite(Some(std::sync::Arc::new(|path: &str, _: &Value, status: u16, answer: &mut Value| {
		(path.ends_with("submit_participation") && status == 200).then(|| {
			*answer = json!({"error": {"code": "declined", "message": "the answer was misread on its way back"}});
			409
		})
	})));
	let (ok, v) = w2.run(&["offboard", "--asset", &xs, "--amount", &a2, "--address", &address]);
	proxy.rewrite(None);
	println!("W2's offboard, its answer misread: ok={} {}", ok, v["error"]);
	assert!(!ok);
	assert_eq!(live_of(&w2, x).len(), 1, "the wallet holds the coin live again");
	let again = w2.ok(&["offboard", "--asset", &xs, "--amount", &a2, "--address", &address]);
	println!("W2 asks again: {}", again);
	assert_eq!((again["already"].as_bool(), again["state"].as_str()), (Some(true), Some("pending")), "{}", again);
	assert!(live_of(&w2, x).is_empty(), "the coin is given up to the offboard again");
	let id2 = again["offboard"].as_str().unwrap().to_string();

	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	assert_eq!(built[0].offboards, 2, "one round pays both");
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.round_state(&built[0].tx.txid(), RoundState::Final).await;
	for (w, id, amount) in [(&w1, &id1, &a1), (&w2, &id2, &a2)] {
		let mut paid = Value::Null;
		for _ in 0..30 {
			w.ok(&["sync"]);
			r.produce().await;
			r.synced().await;
			if let Some(o) = w.ok(&["offboards"]).as_array().unwrap().iter().find(|o| o["offboard"] == json!(id) && o["state"] == "paid") {
				paid = o.clone();
				break;
			}
			tokio::time::sleep(std::time::Duration::from_secs(2)).await;
		}
		println!("{}'s offboard: {}", w.name, paid);
		assert_eq!(paid["state"], "paid", "{}", w.ok(&["offboards"]));
		let txid: Txid = paid["txid"].as_str().unwrap().parse().unwrap();
		let tx = r.rt.client().raw_transaction(&txid).unwrap();
		let i = tx.output.iter().position(|o| o.script_pubkey == spk && o.value.explicit() == Some(amount.parse::<u64>().unwrap()));
		assert!(i.is_some(), "the address is paid {}: {:?}", amount, tx.output);
		assert!(w.ok(&["coins"]).as_array().unwrap().iter().all(|c| c["asset"] != json!(xs) || c["state"] != "given"),
			"nothing left given up: {}", w.ok(&["coins"]));
	}
	for w in [&w1, &w2, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

/// An offboard of named coins (`--coins`) gives up those coins alone, whole:
/// it pays what they hold less the fee, with no change, and leaves every other
/// coin of the wallet's as it was, though the wallet's own choice for that
/// amount would have taken the other first and made change. Before the wallet
/// holds a coin, `--value` and `--expiry` quote the same move of a coin of
/// that value and date, so a program can price it beforehand. The unlock
/// pays the address exactly the quoted amount, at the output `offboards`
/// names (`vout`). Refused beside it, nothing signed: a coin the wallet does
/// not hold, and a quote that is no longer the offboard's.
#[tokio::test(flavor = "multi_thread")]
async fn an_offboard_of_named_coins_moves_them_whole_and_touches_no_other() {
	// Fees on both parts, so the whole move's arithmetic is tested.
	let mut r = Running::start_with(|c, x, _| c.assets[0] = AssetSection { refresh_ppm: Some(3_000), refresh_base: Some("200".into()),
		offboard_ppm: Some(3_333), offboard_base: Some("7".into()), ..AssetSection::new(x, 1_000) }).await;
	let x = r.x;
	let a = leaves_only(&mut r, "OBN", x, 600_000).await;
	// A second coin.
	r.pay_to(script(&a.ok(&["address"])), x, 250_000);
	r.produce().await;
	let q = a.ok(&["board", &x.to_string(), "240000", "--quote"]);
	let fee: u64 = q["fee"]["amount"].as_str().unwrap().parse().unwrap();
	a.ok(&["board", &x.to_string(), &(250_000 - fee).to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards credited", || a.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	a.ok(&["sync"]);
	let coins = live_of(&a, x);
	assert_eq!(coins.len(), 2, "{:?}", coins);
	let b = Arca::new("OBM");
	b.ok(&create_args(&r.url(), &r.node_url()));
	let to = b.ok(&["address"]);
	let (address, spk) = (to["address"].as_str().unwrap().to_string(), script(&to));
	let xs = x.to_string();
	// The coin named is one the wallet's own choice for the same amount
	// passes over: the wallet orders its coins by exit date, then by size,
	// so for one of the two it takes the other first.
	let mut pick = None;
	for c in &coins {
		let (value, expiry) = (c["value"].as_str().unwrap().to_string(), c["expiry"].as_u64().unwrap().to_string());
		let whole = a.ok(&["offboard", "--asset", &xs, "--value", &value, "--expiry", &expiry, "--address", &address, "--quote"]);
		println!("the move of a coin of {} by its value: {}", value, whole);
		let amount = whole["amount"].as_str().unwrap().to_string();
		let fee: u64 = whole["fee"]["amount"].as_str().unwrap().parse().unwrap();
		assert_eq!(amount.parse::<u64>().unwrap() + fee, value.parse::<u64>().unwrap(), "the amount and the fee are the whole coin");
		assert_eq!(whole["change"], "0");
		let free = a.ok(&["offboard", "--asset", &xs, "--amount", &amount, "--address", &address, "--quote"]);
		println!("the wallet's own choice for {}: {}", amount, free["gives"]);
		if free["gives"] != json!([c["leaf_id"]]) {
			pick = Some((c.clone(), whole, amount));
			break;
		}
	}
	let (named, whole, amount) = pick.expect("for one of the coins the wallet's own choice is another: else the test proves nothing");
	let other = coins.iter().find(|c| c["leaf_id"] != named["leaf_id"]).unwrap().clone();
	let id = named["leaf_id"].as_str().unwrap().to_string();

	// Refused, nothing signed.
	let (ok, v) = a.run(&["offboard", "--asset", &xs, "--coins", &"00".repeat(36), "--address", &address, "--quote"]);
	println!("a coin the wallet does not hold: ok={} {}", ok, v["error"]["message"]);
	assert!(!ok && v["error"]["message"].as_str().unwrap().contains("is not a live coin"), "{}", v);
	let q = a.ok(&["offboard", "--asset", &xs, "--coins", &id, "--address", &address, "--quote"]);
	println!("the move of the named coin: {}", q);
	assert_eq!((&q["gives"], &q["change"], &q["amount"], &q["fee"]["amount"]), (&json!([id]), &json!("0"), &whole["amount"], &whole["fee"]["amount"]),
		"the named coin alone, whole, at the fee its value and date quoted");
	let mut stale = q.clone();
	stale["fee"]["amount"] = json!("1");
	let (ok, v) = a.run(&["offboard", "--asset", &xs, "--coins", &id, "--address", &address, "--shown", &stale.to_string()]);
	println!("a quote that is not the offboard's: ok={} {}", ok, v["error"]["message"]);
	assert!(!ok && v["error"]["message"].as_str().unwrap().contains("changed since it was shown"), "{}", v);

	// Paid: the round, the forfeit, the unlock into the address.
	let asked = a.ok(&["offboard", "--asset", &xs, "--coins", &id, "--address", &address, "--shown", &q.to_string()]);
	println!("asked: {}", asked);
	assert_eq!((&asked["gives"], &asked["change"], &asked["amount"]), (&json!([id]), &json!("0"), &json!(amount)));
	let again = a.ok(&["offboard", "--asset", &xs, "--coins", &id, "--address", &address]);
	assert_eq!((&again["offboard"], &again["already"]), (&asked["offboard"], &json!(true)), "asked again, it is the same: {}", again);
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	assert_eq!(built[0].offboards, 1);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.round_state(&built[0].tx.txid(), RoundState::Final).await;
	a.ok(&["sync"]);
	let mut paid = Value::Null;
	for _ in 0..30 {
		r.produce().await;
		r.synced().await;
		let o = a.ok(&["offboards"])[0].clone();
		if o["state"] == "paid" {
			paid = o;
			break;
		}
		tokio::time::sleep(std::time::Duration::from_secs(2)).await;
	}
	println!("the offboard: {}", paid);
	assert_eq!(paid["state"], "paid", "{}", a.ok(&["offboards"]));
	let txid: Txid = paid["txid"].as_str().unwrap().parse().unwrap();
	let tx = r.rt.client().raw_transaction(&txid).unwrap();
	let out = &tx.output[paid["vout"].as_u64().unwrap() as usize];
	assert_eq!((&out.script_pubkey, out.asset.explicit(), out.value.explicit()), (&spk, Some(x), Some(amount.parse::<u64>().unwrap())));
	// No change, and the other coin as it was.
	for _ in 0..3 {
		a.ok(&["sync"]);
		r.produce().await;
		r.synced().await;
	}
	let left = live_of(&a, x);
	println!("left: {:?}", left);
	assert_eq!(left.len(), 1, "{}", a.ok(&["coins"]));
	assert_eq!((&left[0]["leaf_id"], &left[0]["value"]), (&other["leaf_id"], &other["value"]), "the other coin untouched");
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
