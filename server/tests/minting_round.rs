//! A round of an issuer-operated asset that mints spends the mint limiter's
//! coin at its input 0, and the limiter's `arm` path (the brake) spends that
//! coin with the cold key's arm signature alone, made once in advance and
//! kept at a watcher: someone other than the operator can spend an input of
//! such a round first, and the round is then lost. So the operator's half of
//! its forfeits is not asked of the signer the moment the node holds it
//! (`Store::round_wakes_fill`): a coin whose forfeit the signer co-signed is
//! never run again once its round is lost.
//!
//! No sweep, anchor depth 0, checkpoint exit off, on a plain anchored chain
//! so `generateblock` can stand for a producer that took the arm first. A
//! holder refreshes a board of Z; the round is held, its forfeit handed over,
//! and it goes to the node; the arm then spends the limiter's coin in a
//! block, and the round is lost. The holder's forfeit was not co-signed, so
//! its participation runs again.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `MINT_LIMITER`.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use elements::hashes::Hash;
use elements::{AssetId, AssetIssuance, ContractHash, OutPoint, Transaction};
use serde_json::{json, Value};

use arca_covenant::limiter::{self, LimiterParams, LimiterState};
use common::client::{hex, participation_body, want_leaf};
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{credited_board, hand_over_held, status, VALUE};
use common::running::{Running, MIN_LEAF};
use sequentia_ext::{explicit_txout, AssetAmount};
use server::issuer::IssuerSection;
use server::server::AssetSection;
use server::store::RoundState;

const ISSUED: u64 = 10_000_000_000;

fn tool() -> PathBuf {
	PathBuf::from(std::env::var("MINT_LIMITER").expect("MINT_LIMITER"))
}

fn tool_json(args: &[&str]) -> Value {
	let out = Command::new(tool()).args(args).output().unwrap();
	assert!(out.status.success(), "mint-limiter {:?}: {}", args, String::from_utf8_lossy(&out.stderr));
	serde_json::from_slice(&out.stdout).unwrap()
}

fn tool_json_in(args: &[&str], input: &Value) -> Result<Value, String> {
	use std::io::Write;
	let mut c = Command::new(tool()).args(args).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
		.stderr(std::process::Stdio::piped()).spawn().unwrap();
	c.stdin.take().unwrap().write_all(input.to_string().as_bytes()).unwrap();
	let out = c.wait_with_output().unwrap();
	if !out.status.success() {
		return Err(String::from_utf8_lossy(&out.stderr).to_string());
	}
	Ok(serde_json::from_slice(&out.stdout).unwrap())
}

struct Issued {
	z: AssetId,
	entropy: [u8; 32],
	coin: OutPoint,
	issue_tx: Transaction,
	instance: PathBuf,
	words: PathBuf,
	cold_words: PathBuf,
}

fn issue_into_limiter(r: &mut Running, dir: &Path) -> Issued {
	let words = dir.join("mint.words");
	let cold_words = dir.join("cold.words");
	let op = tool_json(&["key", "--new", "--mnemonic-file", words.to_str().unwrap()])["key"].as_str().unwrap().to_string();
	let cold = tool_json(&["key", "--new", "--mnemonic-file", cold_words.to_str().unwrap()])["key"].as_str().unwrap().to_string();
	let coin = r.purse.take_coin(r.purse.policy);
	let contract = arca_covenant::script::sha256(b"asset Z, issuer-operated, minting round");
	let z = AssetId::new_issuance(coin.0, ContractHash::from_byte_array(contract));
	let entropy = AssetId::generate_asset_entropy(coin.0, ContractHash::from_byte_array(contract)).to_byte_array();
	let token = limiter::token_of_entropy(entropy);
	let genesis = r.rt.client().genesis_hash().unwrap();
	let inst = tool_json(&["instance", "--asset", &z.to_string(), "--token", &token.to_string(), "--entropy",
		&elements::hashes::sha256::Midstate::from_byte_array(entropy).to_string(), "--operator-key", &op, "--cold-key", &cold,
		"--window", "120", "--allowance", &(4 * VALUE).to_string(), "--recovery-delay", "10", "--genesis", &genesis.to_string()]);
	let mut file = inst.clone();
	file.as_object_mut().unwrap().remove("address");
	let instance = dir.join("limiter.json");
	std::fs::write(&instance, file.to_string()).unwrap();
	let (lp, _) = LimiterParams::from_instance_json(&file.to_string()).unwrap();
	let mut tx = node::spend_op_true(&coin, vec![
		explicit_txout(AssetAmount::new(z, ISSUED), node::op_true()),
		explicit_txout(AssetAmount::new(token, 1), lp.script_pubkey(LimiterState::default())),
	], 10_000);
	tx.input[0].asset_issuance = AssetIssuance {
		asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: contract,
		amount: elements::confidential::Value::Explicit(ISSUED), inflation_keys: elements::confidential::Value::Explicit(1),
		denomination: 8,
	};
	tokio::task::block_in_place(|| {
		r.rt.client().send_raw_transaction(&tx).unwrap();
		r.rt.produce_block().unwrap();
	});
	r.purse.put((OutPoint::new(tx.txid(), 0), tx.output[0].clone()));
	// Output 2 (the policy asset's change) is kept for the arm's fee.
	Issued { z, entropy, coin: OutPoint::new(tx.txid(), 1), issue_tx: tx, instance, words, cold_words }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_armed_limiter_kills_a_held_minting_round_and_its_refresh_runs_again() {
	let mut r = Running::start_plain_on(&["-evbparams=simplicity:-1:::"], |c, _| {
		c.batches.no_sweep = true;
		c.finality.anchor_depth = 0;
		c.checkpoint_exit = false;
	}).await;
	let x = r.x;
	for _ in 0..4 {
		r.fund_wallet_in(x, 20_000_000).await;
	}
	let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("minting-round-{}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	let i = issue_into_limiter(&mut r, &dir);
	let z = i.z;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let genesis = r.rt.client().genesis_hash().unwrap();
	tokio::task::block_in_place(|| r.signer.restart_with(genesis, &["--issuer".into(),
		format!("{}={}", i.instance.display(), i.words.display()), "--mint-limiter".into(), tool().display().to_string()]));
	let mut section = AssetSection::new(z, MIN_LEAF);
	section.issuer = Some(IssuerSection {
		limiter: i.instance.clone(),
		entropy: elements::hashes::sha256::Midstate::from_byte_array(i.entropy).to_string(),
		coin: format!("{}:{}", i.coin.txid, i.coin.vout),
		state: None,
	});
	r.config.assets.push(section);
	let config = r.config.clone();
	r.server.reload(&config).await.unwrap();

	// The cold key's arm signature, made in advance (it names no coin).
	let arm = tool_json(&["arm-signature", "--instance", i.instance.to_str().unwrap(), "--mnemonic-file", i.cold_words.to_str().unwrap()]);
	println!("arm-signature reply: {}", arm);
	let arm_sig = arm.as_object().unwrap().values().find_map(|v| v.as_str().filter(|s| s.len() == 128)).expect("a signature").to_string();

	// A holder refreshes a board of Z; the round mints and is held.
	let (board, _) = credited_board(&mut r, &keypair("minting round board"), z).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let (w, _) = want_leaf(&keypair("minting round new"), z, VALUE);
	let (body, id) = participation_body(&[&board], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	let (rounds, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty() && rounds.len() == 1, "{:?}", failed);
	let round = rounds[0].tx.clone();
	assert!(rounds[0].broadcast.starts_with("held"), "{}", rounds[0].broadcast);
	assert_eq!(round.input[0].previous_output, i.coin, "the limiter's coin is the round's input 0");
	println!("round {} held; input 0 = the limiter's coin {}, its sequence {:#x} (signals replacement: {})", round.txid(), i.coin,
		round.input[0].sequence.0, round.input[0].sequence.0 < 0xffff_fffe);
	assert_eq!(hand_over_held(&r, &round.txid()).await, 1);
	let row = r.server.store.round_by_txid(&round.txid().to_byte_array()).await.unwrap().unwrap();
	assert!(!r.server.store.round_wakes_fill(row.round_id).await.unwrap(),
		"a minting round's input 0 is the limiter's coin, not the operator wallet's: it does not wake the forfeit fill");
	r.server.rounds.pass().await.unwrap();
	assert!(node::in_mempool(&r.rt, &round.txid()), "the round went to the node");
	let out = Instant::now();
	let mut fc = r.server.store.forfeit_count(&id, row.round_id).await.unwrap();
	while fc.1 == 0 && out.elapsed() < Duration::from_secs(3) {
		tokio::time::sleep(Duration::from_millis(50)).await;
		fc = r.server.store.forfeit_count(&id, row.round_id).await.unwrap();
	}
	println!("{} ms after the round went to the node: forfeits (inputs, whole, without) {:?}", out.elapsed().as_millis(), fc);

	// The arm: the limiter's coin spent by the brake, in a block.
	let req = json!({
		"path": "arm",
		"coin": {"tx": hex(&elements::encode::serialize(&i.issue_tx)), "vout": 1},
		"state": {"minted": "0", "elapsed": 0, "armed": 0},
		"arm_signature": arm_sig,
		"fee": {"coins": [{"tx": hex(&elements::encode::serialize(&i.issue_tx)), "vout": 2}], "atoms": "5000",
			"change_to": hex(node::op_true().as_bytes())},
	});
	let built = tool_json_in(&["build", "--instance", i.instance.to_str().unwrap()], &req).expect("the arm builds");
	let arm_tx: Transaction = elements::encode::deserialize(&common::client::unhex(built["hex"].as_str().unwrap())).unwrap();
	println!("arm {}: spends {:?}", arm_tx.txid(), arm_tx.input.iter().map(|i| i.previous_output).collect::<Vec<_>>());
	assert_eq!(arm_tx.input[0].previous_output, i.coin, "the arm spends the round's input 0");
	let h = tokio::task::block_in_place(|| r.rt.client().generate_block("raw(51)", &[&arm_tx]));
	println!("the arm in a block: {:?}", h);
	h.expect("a block takes the arm");
	r.bury().await;
	r.synced().await;
	for _ in 0..20 {
		let _ = r.server.rounds.pass().await;
		let st = r.server.store.round(row.round_id).await.unwrap().unwrap().state;
		if st == RoundState::Lost {
			break;
		}
		tokio::time::sleep(Duration::from_millis(300)).await;
	}
	let lost = r.server.store.round(row.round_id).await.unwrap().unwrap();
	let fc = r.server.store.forfeit_count(&id, row.round_id).await.unwrap();
	println!("after the arm: round state {:?}; the holder's forfeit for it (inputs, whole, without) {:?}; participation {}", lost.state, fc,
		status(&r, &id));
	assert_eq!(lost.state, RoundState::Lost, "the armed limiter killed the round");
	assert_eq!(fc.1, 0, "the operator's half was not signed for the round another key's path killed (the minute's run had not \
		come)");
	let st = status(&r, &id);
	assert_ne!(st["state"], "void", "the refresh is not voided: its coin was never barred: {}", st);
	println!("the holder's refresh after the lost round: {} (attempt {})", st["state"], st["attempt"]);
}
