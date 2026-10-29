//! Paying an address on the chain from leaves (`arca offboard`), as the
//! wallet does it, against a whole Arca server on an anchored proof-of-stake
//! regtest chain.
//!
//! A wallet holding only leaves of X pays 300,000 X to another wallet's
//! on-chain address: the fee is quoted and shown, the offboard goes ahead on
//! that very quote, the operator's round pays the offboard output, `sync`
//! hands over the forfeit once the round is final, and the operator's watcher
//! unlocks the output into the address: its output 0 pays exactly 300,000 X
//! there, and `arca offboards` says it is paid and final. Refused beside it,
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
	let (url, node) = (r.url(), r.node_url());
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
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
