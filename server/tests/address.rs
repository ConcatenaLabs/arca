//! `arcad <config> address`: the operator funds its wallet. The binary, run
//! beside a running server on the same database, hands out a receive address
//! of the operator's wallet and records it; a coin paid to it is the wallet's
//! once its block connects, and the server's own next script is another one.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::process::Command;

use common::running::Running;
use elements::Script;
use sequentia_ext::{explicit_txout, AssetAmount};
use serde_json::Value;

/// The configuration the server runs with, as `arcad` reads it.
fn config_file(r: &Running) -> std::path::PathBuf {
	let c = &r.config;
	let text = format!(
		"listen = \"127.0.0.1:0\"\ndatabase = {:?}\nsigner_socket = {:?}\nwallet_mnemonic_file = {:?}\n\
		 [node]\nrpc_url = {:?}\nrpc_user = \"arca\"\nrpc_password = \"arca\"\n\
		 [[assets]]\nasset = \"{}\"\nmin_leaf = \"1000\"\n",
		c.database, c.signer_socket.display().to_string(), c.wallet_mnemonic_file.display().to_string(),
		c.node.rpc_url, r.x,
	);
	let path = r.signer.dir.join("arcad.toml");
	std::fs::write(&path, text).unwrap();
	path
}

fn address(config: &std::path::Path) -> Value {
	let out = Command::new(env!("CARGO_BIN_EXE_arcad")).arg(config).arg("address").output().unwrap();
	assert!(out.status.success(), "arcad address: {}", String::from_utf8_lossy(&out.stderr));
	serde_json::from_slice(&out.stdout).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_operator_funds_its_wallet_through_an_address_arcad_hands_out() {
	let mut r = Running::start().await;
	let config = config_file(&r);

	let first = tokio::task::block_in_place(|| address(&config));
	let second = tokio::task::block_in_place(|| address(&config));
	println!("arcad address: {}\narcad address: {}", first, second);
	assert_eq!(first["index"].as_u64().unwrap() + 1, second["index"].as_u64().unwrap());
	assert_ne!(first["address"], second["address"]);
	// The address is the node's for the script printed.
	let v: Value = r.rt.client().call("validateaddress", &[first["address"].clone()]).unwrap();
	assert_eq!(v["isvalid"], true);
	assert_eq!(v["scriptPubKey"], first["script_pubkey"]);
	let script = Script::from(hex(first["script_pubkey"].as_str().unwrap()));

	// The server's own next script is neither.
	let own = r.server.wallet.receive_script().await.unwrap();
	assert_ne!(own, script);
	assert_ne!(own, Script::from(hex(second["script_pubkey"].as_str().unwrap())));

	// A coin paid to the address is the wallet's, and spendable once final.
	let x = r.x;
	tokio::task::block_in_place(|| r.purse.pay(&r.rt, vec![explicit_txout(AssetAmount::new(x, 7_000_000), script.clone())]));
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let balance = r.server.wallet.balance().await.unwrap();
	assert_eq!(balance.get(&x), Some(&7_000_000), "{:?}", balance);
	println!("the wallet holds {} of X paid to {}", balance[&x], first["address"]);

	// Handed out again after a restart, the index goes on.
	r.restart_server().await;
	let third = tokio::task::block_in_place(|| address(&config));
	assert_eq!(third["index"].as_u64().unwrap(), second["index"].as_u64().unwrap() + 2);
}

fn hex(s: &str) -> Vec<u8> {
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
