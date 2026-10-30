//! `arcad withdraw`, on an anchored proof-of-stake regtest chain: the
//! operator's wallet pays an asset to an address from final coins, beside the
//! running server; more than the wallet can pay now is refused before
//! anything is built, as is a confidential address; the coins it takes are
//! the wallet's no longer, and what the server can fund falls by the amount
//! and the fee.

mod common;

use serde_json::{json, Value};

use common::running::Running;
use sequentia_ext::rpc::{Auth, Client};
use server::server::withdraw;

fn wallet_rpc(r: &Running, name: &str) -> Client {
	Client::new(format!("http://127.0.0.1:{}/wallet/{}", r.rt.node.rpc_port(), name), Auth::UserPass("arca".into(), "arca".into()))
}

fn fundable(r: &Running) -> u64 {
	let info = r.http.get("info").ok();
	let x = r.x.to_string();
	info["assets"].as_array().unwrap().iter().find(|a| a["asset"] == json!(x)).unwrap()["fundable"].as_str().unwrap().parse().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_operator_withdraws_what_it_can_fund_and_no_more() {
	let mut r = Running::start_on(&["-disablewallet=0"], |c, _| {
		c.assets[0].rate = Some(toml::from_str("source = \"node\"").unwrap());
	}).await;
	let x = r.x;
	let _: Value = r.rt.client().call("createwallet", &[json!("treasury")]).unwrap();
	let to: String = wallet_rpc(&r, "treasury").call("getnewaddress", &[json!(""), json!("bech32")]).unwrap();
	let ai: Value = wallet_rpc(&r, "treasury").call("getaddressinfo", &[json!(to)]).unwrap();
	let plain = ai["unconfidential"].as_str().unwrap_or(&to).to_string();

	r.fund_wallet(4_000_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let before = fundable(&r);
	println!("fundable before: {}", before);
	assert!(before >= 4_000_000_000, "the funding is final");

	// More than it can pay: refused, nothing built.
	let e = withdraw(&r.config, &x.to_string(), &(before + 1).to_string(), &plain, None).await.unwrap_err();
	println!("withdraw of {}: {}", before + 1, e);
	assert!(e.to_string().contains("at most may leave"), "{}", e);
	// A confidential address: refused.
	if ai["confidential"].as_str().is_some_and(|c| c != plain) {
		let e = withdraw(&r.config, &x.to_string(), "1000", ai["confidential"].as_str().unwrap(), None).await.unwrap_err();
		println!("withdraw to a confidential address: {}", e);
		assert!(e.to_string().contains("confidential"), "{}", e);
	}
	assert_eq!(fundable(&r), before, "a refused withdrawal takes nothing");

	// Half of it, beside the running server.
	let half = before / 2;
	let out = withdraw(&r.config, &x.to_string(), &half.to_string(), &plain, None).await.unwrap();
	println!("withdraw of {}: {}", half, out);
	assert_eq!(out["value"], half.to_string());
	assert_eq!(out["fee_asset"], x.to_string(), "the fee in the asset moved");
	let fee: u64 = out["fee"].as_str().unwrap().parse().unwrap();
	let txid = out["txid"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let tx: Value = r.rt.client().call("getrawtransaction", &[json!(txid), json!(true)]).unwrap();
	assert!(tx["confirmations"].as_u64().unwrap_or(0) >= 1, "in a block");
	let paid: Vec<&Value> = tx["vout"].as_array().unwrap().iter()
		.filter(|o| o["scriptPubKey"]["address"].as_str() == Some(plain.as_str()) || o["scriptPubKey"]["address"].as_str() == Some(to.as_str()))
		.collect();
	assert_eq!(paid.len(), 1, "one output to the address: {}", tx);
	let value = paid[0]["value"].as_f64().unwrap();
	assert_eq!((value * 1e8).round() as u64, half, "exactly the atoms asked");
	// What the server can fund is read again every FUNDABLE_FOR.
	let want = before - half - fee;
	let mut after = fundable(&r);
	let start = std::time::Instant::now();
	while after != want && start.elapsed() < server::rounds::FUNDABLE_FOR * 3 {
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;
		after = fundable(&r);
	}
	println!("fundable after: {} (was {}, withdrew {}, fee {})", after, before, half, fee);
	assert_eq!(after, want, "the pool falls by what left and its fee, its change the wallet's again");

	// Again, more than is left: refused.
	let e = withdraw(&r.config, &x.to_string(), &(after + 1).to_string(), &plain, None).await.unwrap_err();
	assert!(e.to_string().contains("at most may leave"), "{}", e);
}
