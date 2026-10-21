//! The wallet and an issuer-operated asset: an asset whose batches its issuer
//! funds by a mint in each round, through the asset's mint limiter, and whose
//! sweeps only burn.
//!
//! Against a whole server serving Z issuer-operated (its reissuance token in
//! a mint limiter, the signer minting through the limiter's tool) and X as
//! any asset, on an anchored proof-of-stake regtest chain with Simplicity
//! active, through a proxy that can rewrite the server's answers:
//!
//! 1. A wallet refreshes a coin of Z: the round mints the batch, the wallet
//!    takes the burn-only leaf, `coins` names its batch `issuer-operated`,
//!    `info` shows Z's limiter, and `supply` reads the operator's mint again
//!    from the wallet's own node.
//! 2. The operator's `info` claims X is issuer-operated: the wallet refuses
//!    X's new batch, whose sweep pays the operator, before it signs any
//!    forfeit; with the honest `info` the refresh completes, its batch `open`.
//! 3. The operator's `info` serves Z as no issuer-operated asset: the wallet
//!    refuses Z's burn-only batch, the statement and the scripts disagreeing.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES`, `arca-signer` (see
//! `tests/common/mod.rs`) and `MINT_LIMITER` (the limiter's tool, with `sign`).

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use elements::hashes::Hash;
use elements::{AssetId, AssetIssuance, ContractHash, OutPoint, Script};
use serde_json::{json, Value};

use arca_covenant::limiter::{self, LimiterParams, LimiterState};
use common::cli::Arca;
use common::proxy::Proxy;
use common::running::{keypair, Running};
use sequentia_ext::{explicit_txout, AssetAmount};
use server::issuer::IssuerSection;
use server::server::AssetSection;
use server::store::RoundState;

fn tool() -> PathBuf {
	PathBuf::from(std::env::var("MINT_LIMITER").expect("MINT_LIMITER names the mint limiter's tool (sequentia-contracts \
		tools/mint-limiter, with `sign`)"))
}

fn tool_json(args: &[&str]) -> Value {
	let out = Command::new(tool()).args(args).output().unwrap();
	assert!(out.status.success(), "mint-limiter {:?}: {}", args, String::from_utf8_lossy(&out.stderr));
	serde_json::from_slice(&out.stdout).unwrap()
}

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

fn coin_of(w: &Arca, leaf: &str) -> Value {
	w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).cloned().unwrap_or(Value::Null)
}

/// Z, issued with one explicit atom of reissuance token straight into a new
/// mint limiter; the signer started again with the limiter, and Z served
/// issuer-operated.
async fn serve_z(r: &mut Running, dir: &Path) -> AssetId {
	let words = dir.join("mint.words");
	let op = tool_json(&["key", "--new", "--mnemonic-file", words.to_str().unwrap()])["key"].as_str().unwrap().to_string();
	let cold = keypair("Z's cold key").x_only_public_key().0.to_string();
	let coin = r.purse.take_coin(r.purse.policy);
	let contract = arca_covenant::script::sha256(b"asset Z, issuer-operated, for the wallet");
	let z = AssetId::new_issuance(coin.0, ContractHash::from_byte_array(contract));
	let entropy = AssetId::generate_asset_entropy(coin.0, ContractHash::from_byte_array(contract)).to_byte_array();
	let entropy_hex = elements::hashes::sha256::Midstate::from_byte_array(entropy).to_string();
	let genesis = r.rt.client().genesis_hash().unwrap();
	let inst = tool_json(&["instance", "--asset", &z.to_string(), "--token", &limiter::token_of_entropy(entropy).to_string(), "--entropy",
		&entropy_hex, "--operator-key", &op, "--cold-key", &cold, "--window", "1000", "--allowance", "100000000", "--recovery-delay", "10",
		"--genesis", &genesis.to_string()]);
	let mut file = inst.clone();
	file.as_object_mut().unwrap().remove("address");
	let instance = dir.join("limiter.json");
	std::fs::write(&instance, file.to_string()).unwrap();
	let (l, _) = LimiterParams::from_instance_json(&file.to_string()).unwrap();
	let mut tx = common::node::spend_op_true(&coin, vec![
		explicit_txout(AssetAmount::new(z, 10_000_000_000), common::node::op_true()),
		explicit_txout(AssetAmount::new(l.token, 1), l.script_pubkey(LimiterState::default())),
	], 10_000);
	tx.input[0].asset_issuance = AssetIssuance {
		asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: contract,
		amount: elements::confidential::Value::Explicit(10_000_000_000), inflation_keys: elements::confidential::Value::Explicit(1),
		denomination: 8,
	};
	let txid = tokio::task::block_in_place(|| {
		let t = r.rt.client().send_raw_transaction(&tx).unwrap();
		r.rt.produce_block().unwrap();
		t
	});
	r.purse.put((OutPoint::new(txid, 0), tx.output[0].clone()));
	r.purse.put((OutPoint::new(txid, 2), tx.output[2].clone()));
	r.produce().await;
	r.bury().await;
	r.synced().await;
	tokio::task::block_in_place(|| {
		r.signer.halt();
		r.signer.set_extra(vec!["--issuer".into(), format!("{}={}", instance.display(), words.display()), "--mint-limiter".into(),
			tool().display().to_string()]);
		r.signer.resume(genesis);
	});
	let mut section = AssetSection::new(z, 1_000);
	section.issuer = Some(IssuerSection { limiter: instance, entropy: entropy_hex, coin: format!("{}:1", txid), state: None });
	r.config.assets.push(section);
	let config = r.config.clone();
	r.server.reload(&config).await.unwrap();
	z
}

/// Creates `w` on `server` and boards `amount` of `asset`, credited.
async fn boarded(r: &mut Running, w: &Arca, server: &str, asset: AssetId, amount: u64) -> String {
	if !w.dir.exists() {
		w.ok(&["create", "--server", server, "--node-url", &r.node_url(), "--node-user", "arca",
			"--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
	}
	let s = script(&w.ok(&["address"]));
	r.pay_to(s, asset, amount + 3_000_000);
	let x = r.x;
	let s = script(&w.ok(&["address"]));
	r.pay_to(s, x, 3_000_000);
	r.produce().await;
	let b = w.ok(&["board", &asset.to_string(), &amount.to_string(), "--fee-asset", &x.to_string()])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board to be credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
	assert_eq!(coin_of(w, &b)["state"], "live");
	b
}

/// A round of whatever waits, mined and final.
async fn final_round(r: &Running) -> elements::Transaction {
	let built = r.server.rounds.run_round().await.unwrap().expect("a round");
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	built.tx
}

/// Every new leaf of the wallet's in `asset`, by `coins`.
fn leaves_in(w: &Arca, asset: AssetId) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter()
		.filter(|c| c["kind"] == "batch" && c["asset"] == json!(asset.to_string()) && c["state"] == "live").cloned().collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_wallet_takes_an_issuer_operated_batch_and_refuses_one_that_contradicts_the_profile() {
	let mut r = Running::start_on(&["-evbparams=simplicity:-1:::"], |_, _, _| {}).await;
	let x = r.x;
	let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("arca-cli-issuer-{}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	let z = serve_z(&mut r, &dir).await;
	let proxy = Proxy::start(&r.url());
	let w = Arca::new("I1");

	// 1. A refresh of Z into a batch the round mints.
	let b = boarded(&mut r, &w, &proxy.url.clone(), z, 2_000_000).await;
	let info = w.ok(&["info"]);
	let za = info["server_info"]["assets"].as_array().unwrap().iter().find(|a| a["asset"] == json!(z.to_string())).unwrap().clone();
	println!("I1 info, Z: {}", za["issuer"]);
	assert!(!za["issuer"].is_null());
	w.ok(&["participate", "--leaf", &b]);
	let round = final_round(&r).await;
	assert_eq!(arca_covenant::issuer::reissuing_inputs(&round, z), vec![0], "the round mints Z at input 0");
	let s = w.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s);
	let new = leaves_in(&w, z);
	assert_eq!(new.len(), 1, "{:?}", new);
	println!("I1 the new leaf of Z: batch_profile {}", new[0]["batch_profile"]);
	assert_eq!(new[0]["batch_profile"], "issuer-operated");
	let sup = w.ok(&["supply", &z.to_string()]);
	println!("I1 supply: minted {} burned {} in batches {}, checked on the node {}", sup["minted"], sup["burned"], sup["in_batches"],
		sup["checked_on_the_node"]);
	assert_eq!(sup["checked_on_the_node"], true, "{}", sup);
	assert_eq!(sup["mints"].as_array().unwrap().len(), 1);
	assert_eq!(sup["mints"][0]["txid"], json!(round.txid().to_string()));

	// 2. The operator says X is issuer-operated; X's batch pays the operator.
	let w2 = Arca::new("I2");
	let bx = boarded(&mut r, &w2, &proxy.url.clone(), x, 2_000_000).await;
	let xs = x.to_string();
	proxy.rewrite(Some(Arc::new(move |path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/info" && status == 200 {
			for a in v["assets"].as_array_mut().unwrap() {
				if a["asset"] == json!(xs) {
					a["issuer"] = json!({"limiter": limiter::LIMITER_TEMPLATE, "token": "00".repeat(32), "operator_key": "00".repeat(32),
						"cold_key": "00".repeat(32), "allowance": "1", "window_blocks": 2, "recovery_delay_units": 1});
				}
			}
		}
		None
	})));
	w2.ok(&["participate", "--leaf", &bx]);
	final_round(&r).await;
	let s = w2.ok(&["sync"]);
	let why = s["participations"][0]["refused"].as_str().unwrap_or_else(|| panic!("not refused: {}", s)).to_string();
	println!("I2 X claimed issuer-operated, its batch's sweep the operator's: REFUSED: {}", why);
	assert!(why.contains("issuer-operated") && why.contains("pays the operator"), "{}", why);
	assert_eq!(proxy.count("/v1/forfeit_leaves"), 1, "no forfeit for X's batch: only I1's");
	assert_eq!(coin_of(&w2, &bx)["state"], "given", "the coin is still the wallet's");
	proxy.rewrite(None);
	let s = w2.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s);
	assert_eq!(leaves_in(&w2, x)[0]["batch_profile"], "open");

	// 3. The operator says Z is served as any asset; Z's batch is burn-only.
	let w3 = Arca::new("I3");
	let bz = boarded(&mut r, &w3, &proxy.url.clone(), z, 2_000_000).await;
	let zs = z.to_string();
	proxy.rewrite(Some(Arc::new(move |path: &str, _: &Value, status: u16, v: &mut Value| {
		if path == "/v1/info" && status == 200 {
			for a in v["assets"].as_array_mut().unwrap() {
				if a["asset"] == json!(zs) {
					a.as_object_mut().unwrap().remove("issuer");
				}
			}
		}
		None
	})));
	w3.ok(&["participate", "--leaf", &bz]);
	final_round(&r).await;
	let s = w3.ok(&["sync"]);
	let why = s["participations"][0]["refused"].as_str().unwrap_or_else(|| panic!("not refused: {}", s)).to_string();
	println!("I3 Z served as any asset, its batch burn-only: REFUSED: {}", why);
	assert!(why.contains("burn-only") && why.contains("no issuer-operated asset"), "{}", why);
	assert_eq!(coin_of(&w3, &bz)["state"], "given");
	proxy.rewrite(None);
	let s = w3.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s);
	for w in [&w, &w2, &w3] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
	let _ = std::fs::remove_dir_all(&dir);
}
