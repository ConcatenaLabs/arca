//! Issuer-operated batches against a whole server: the asset's reissuance
//! token rests in a mint limiter (sequentia-contracts `templates/mint_limiter`),
//! each round of the asset mints exactly what it pays of it at input 0, the
//! signer signing the mint through the limiter's own tool, and every sweep
//! of its batches burns.
//!
//! 1. On an anchored proof-of-stake regtest chain, Simplicity active: a
//!    holder boards Z, refreshes into a round that mints the batch's value,
//!    and again into a second; the watcher burns the board it takes back; an
//!    offboard that would pass the limiter's allowance in its window waits,
//!    saying why, and runs once the window ends, minting its output; both
//!    batches expire and are burned by their sweeps; the asset's supply,
//!    read from every block of the chain, is back at its level before the
//!    first round less the one fee the holder paid, which was burned; the
//!    operator's supply report says the same, transaction by transaction.
//! 2. On an anchored chain without proof of stake: the server's round mints
//!    within the allowance; the same round minting one atom over it, its
//!    mint and its wallet inputs signed again, is refused in a block beside
//!    the server's round as control; and a second participation that would
//!    pass the allowance waits.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `MINT_LIMITER` (the
//! limiter's tool, `mint-limiter sign` and after).

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use elements::hashes::Hash;
use elements::secp256k1_zkp::{schnorr::Signature, Keypair, Message, Secp256k1, XOnlyPublicKey};
use elements::{AssetId, AssetIssuance, ContractHash, OutPoint, Script, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::issuer;
use arca_covenant::limiter::{self, LimiterParams, LimiterState};
use common::client::{hex, participation_body, unhex};
use common::flow::{claimed, drive, of_kind, refresh, settle, txid, Coin};
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{advance_mtp, credited_board, round_final, status, VALUE};
use common::running::{Running, MIN_LEAF};
use sequentia_ext::{explicit_txout, AssetAmount};
use server::issuer::IssuerSection;
use server::participations::OutputRequest;
use server::server::AssetSection;

const HOUR: u32 = 3_600;
const DAY: u32 = 86_400;
const ISSUED: u64 = 10_000_000_000;

fn tool() -> PathBuf {
	PathBuf::from(std::env::var("MINT_LIMITER").expect("MINT_LIMITER names the mint limiter's tool (sequentia-contracts \
		tools/mint-limiter, with `sign`)"))
}

fn tool_json(args: &[&str]) -> Value {
	let out = Command::new(tool()).args(args).output().unwrap();
	assert!(out.status.success(), "mint-limiter {:?}: {}", args, String::from_utf8_lossy(&out.stderr));
	serde_json::from_slice(&out.stdout).unwrap()
}

fn tool_json_in(args: &[&str], input: &Value) -> Value {
	use std::io::Write;
	let mut c = Command::new(tool()).args(args).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
		.stderr(std::process::Stdio::piped()).spawn().unwrap();
	c.stdin.take().unwrap().write_all(input.to_string().as_bytes()).unwrap();
	let out = c.wait_with_output().unwrap();
	assert!(out.status.success(), "mint-limiter {:?}: {}", args, String::from_utf8_lossy(&out.stderr));
	serde_json::from_slice(&out.stdout).unwrap()
}

fn work_dir(label: &str) -> PathBuf {
	let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("issuer-{}-{}", label, std::process::id()));
	let _ = std::fs::remove_dir_all(&d);
	std::fs::create_dir_all(&d).unwrap();
	d
}

/// An issuer-operated asset Z: its issuance, with one explicit atom of its
/// reissuance token paid straight into a fresh mint limiter.
struct Issued {
	z: AssetId,
	entropy: [u8; 32],
	limiter: LimiterParams,
	coin: OutPoint,
	instance: PathBuf,
	words: PathBuf,
}

fn issue_into_limiter(r: &mut Running, dir: &Path, allowance: u64, window: u16) -> Issued {
	let words = dir.join("mint.words");
	let op = tool_json(&["key", "--new", "--mnemonic-file", words.to_str().unwrap()])["key"].as_str().unwrap().to_string();
	let cold = hex(&xonly(&keypair("Z's cold key")).serialize());
	let coin = r.purse.take_coin(r.purse.policy);
	let contract = arca_covenant::script::sha256(b"asset Z, issuer-operated");
	let z = AssetId::new_issuance(coin.0, ContractHash::from_byte_array(contract));
	let entropy = AssetId::generate_asset_entropy(coin.0, ContractHash::from_byte_array(contract)).to_byte_array();
	let token = limiter::token_of_entropy(entropy);
	let genesis = r.rt.client().genesis_hash().unwrap();
	let inst = tool_json(&["instance", "--asset", &z.to_string(), "--token", &token.to_string(), "--entropy",
		&elements::hashes::sha256::Midstate::from_byte_array(entropy).to_string(), "--operator-key", &op, "--cold-key", &cold,
		"--window", &window.to_string(), "--allowance", &allowance.to_string(), "--recovery-delay", "10", "--genesis", &genesis.to_string()]);
	let mut file = inst.clone();
	file.as_object_mut().unwrap().remove("address");
	let instance = dir.join("limiter.json");
	std::fs::write(&instance, file.to_string()).unwrap();
	let (limiter, _) = LimiterParams::from_instance_json(&file.to_string()).unwrap();
	// The server's reading of the instance is the tool's.
	let at = tool_json(&["address", "--instance", instance.to_str().unwrap()]);
	assert_eq!(at["script_pubkey"].as_str().unwrap(), hex(limiter.script_pubkey(LimiterState::default()).as_bytes()));
	let mut tx = node::spend_op_true(&coin, vec![
		explicit_txout(AssetAmount::new(z, ISSUED), node::op_true()),
		explicit_txout(AssetAmount::new(token, 1), limiter.script_pubkey(LimiterState::default())),
	], 10_000);
	tx.input[0].asset_issuance = AssetIssuance {
		asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: contract,
		amount: elements::confidential::Value::Explicit(ISSUED), inflation_keys: elements::confidential::Value::Explicit(1),
		denomination: 8,
	};
	let txid = tokio::task::block_in_place(|| {
		let t = r.rt.client().send_raw_transaction(&tx).unwrap();
		r.rt.produce_block().unwrap();
		t
	});
	r.purse.put((OutPoint::new(txid, 0), tx.output[0].clone()));
	r.purse.put((OutPoint::new(txid, 2), tx.output[2].clone()));
	println!("Z {} issued, {} atoms, its token {} in the limiter at {}:1 (allowance {} a window of {} blocks)", z, ISSUED, token, txid,
		allowance, window);
	Issued { z, entropy, limiter, coin: OutPoint::new(txid, 1), instance, words }
}

/// The signer started again with Z's limiter, and Z served issuer-operated.
async fn serve_issuer_operated(r: &mut Running, i: &Issued) {
	let genesis = r.rt.client().genesis_hash().unwrap();
	tokio::task::block_in_place(|| r.signer.restart_with(genesis, &["--issuer".into(),
		format!("{}={}", i.instance.display(), i.words.display()), "--mint-limiter".into(), tool().display().to_string()]));
	let mut section = AssetSection::new(i.z, MIN_LEAF);
	section.issuer = Some(IssuerSection {
		limiter: i.instance.clone(),
		entropy: elements::hashes::sha256::Midstate::from_byte_array(i.entropy).to_string(),
		coin: format!("{}:{}", i.coin.txid, i.coin.vout),
		state: None,
	});
	r.config.assets.push(section);
	let config = r.config.clone();
	r.server.reload(&config).await.unwrap();
}

/// What every block of the chain issues and burns of `asset`, read from the
/// chain alone.
fn supply_of(r: &Running, asset: AssetId) -> (u64, u64) {
	let c = r.rt.client();
	let tip = c.block_count().unwrap();
	let (mut issued, mut burned) = (0u64, 0u64);
	for h in 0..=tip {
		let block = c.block(&c.block_hash(h).unwrap()).unwrap();
		for tx in &block.txdata {
			issued += issuer::issued(tx, asset).expect("explicit issuances");
			burned += issuer::burned(tx, asset);
		}
	}
	(issued, burned)
}

fn supply(r: &Running, asset: AssetId) -> u64 {
	let (i, b) = supply_of(r, asset);
	i - b
}

/// Every output of `tx` paying `asset`, its index and value.
fn outputs_of(tx: &Transaction, asset: AssetId) -> Vec<(usize, u64, Script)> {
	tx.output.iter().enumerate().filter(|(_, o)| o.asset.explicit() == Some(asset))
		.map(|(k, o)| (k, o.value.explicit().unwrap(), o.script_pubkey.clone())).collect()
}

/// A destination script of the owner's: a v0 key hash of `key`.
fn destination(key: &Keypair) -> Script {
	Script::new_v0_wpkh(&elements::WPubkeyHash::hash(&key.public_key().serialize()))
}

#[tokio::test(flavor = "multi_thread")]
async fn an_issuer_operated_asset_mints_its_refresh_liquidity_and_burns_it_at_expiry() {
	let mut r = Running::start_on(&["-evbparams=simplicity:-1:::"], |_, _| {}).await;
	let x = r.x;
	for _ in 0..10 {
		r.fund_wallet_in(x, 20_000_000).await;
	}
	let dir = work_dir("pos");
	// Two refreshes of one coin fit the window's allowance; a third mint of
	// the coin's value does not.
	let allowance = 2 * VALUE + 100;
	let window = 120u16;
	let i = issue_into_limiter(&mut r, &dir, allowance, window);
	let z = i.z;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	serve_issuer_operated(&mut r, &i).await;

	// The operator states the profile.
	let info = r.http.get("info").ok();
	let za = info["assets"].as_array().unwrap().iter().find(|a| a["asset"] == json!(z.to_string())).unwrap().clone();
	println!("info, asset Z: {}", za["issuer"]);
	assert_eq!(za["issuer"]["allowance"], json!(allowance.to_string()));
	assert_eq!(za["issuer"]["token"], json!(i.limiter.token.to_string()));
	assert!(info["assets"].as_array().unwrap().iter().filter(|a| a["asset"] != json!(z.to_string())).all(|a| a["issuer"].is_null()));

	// A holder boards Z: the level before the first round.
	let (held, btx) = credited_board(&mut r, &keypair("H, board"), z).await;
	let board = Coin { held, bases: vec![btx.clone()] };
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let level = supply(&r, z);
	assert_eq!(supply_of(&r, z), (ISSUED, 0));
	println!("level before the first round: {} of Z (issued {}, burned 0)", level, ISSUED);

	// Round 1: the board refreshed into a burn-only batch the round mints.
	let got = refresh(&mut r, &[(&board, &keypair("H, leaf 1"))]).await;
	let round1 = got[0].round.clone();
	assert_eq!(round1.input[0].previous_output, i.coin, "the limiter's coin is input 0");
	let zs = outputs_of(&round1, z);
	let v1: u64 = zs.iter().map(|o| o.1).sum();
	assert_eq!(issuer::issued(&round1, z), Some(v1), "the round mints exactly what it pays of Z");
	assert_eq!(issuer::reissuing_inputs(&round1, z), vec![0]);
	assert_eq!(round1.output[0].asset.explicit(), Some(i.limiter.token), "the limiter's successor is output 0");
	let s1 = i.limiter.mint(LimiterState::default(), round1.input[0].sequence.0 as u16, v1).unwrap();
	assert_eq!(round1.output[0].script_pubkey, i.limiter.script_pubkey(s1));
	assert!(got[0].new_valid.branch.sweeps().iter().all(|s| s.burn), "every sweep above the leaf is burn-only");
	let w = &round1.input[0].witness.script_witness;
	println!("round 1 {}: {} vB, input 0 the limiter's coin (age {}), its witness {} + {} + {} + {} bytes; mints {} into the batch at output {}",
		round1.txid(), round1.vsize(), round1.input[0].sequence.0, w[0].len(), w[1].len(), w[2].len(), w[3].len(), v1, zs[0].0);
	assert_eq!(supply(&r, z), level + v1);

	// The watcher takes the board back and burns it whole.
	drive(&r, "the board's forfeit and its claim", 12, |l| claimed(l) == 1).await;
	settle(&r).await;
	let mut board_burned = 0;
	for w in of_kind(&r, "forfeit").await.iter().chain(of_kind(&r, "claim").await.iter()) {
		let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
		let b = issuer::burned(&tx, z);
		assert!(outputs_of(&tx, z).iter().all(|o| issuer::is_burn(&o.2) || w.kind == "forfeit"), "the claim pays nothing of Z but burns");
		println!("  {} {}: burns {} of Z; its fee in {}", w.kind, txid(w), b,
			if tx.output.iter().any(|o| o.is_fee() && o.asset.explicit() == Some(x)) { "X" } else { "another asset" });
		board_burned += b;
	}
	assert_eq!(board_burned, VALUE, "the board's whole value is burned");
	assert_eq!(supply(&r, z), level + v1 - VALUE);

	// Round 2: the leaf refreshed again, minted again.
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let got2 = refresh(&mut r, &[(&got[0].new, &keypair("H, leaf 2"))]).await;
	let round2 = got2[0].round.clone();
	let v2: u64 = outputs_of(&round2, z).iter().map(|o| o.1).sum();
	assert_eq!(round2.input[0].previous_output, OutPoint::new(round1.txid(), 0), "round 2 mints from round 1's successor");
	assert_eq!(issuer::issued(&round2, z), Some(v2));
	println!("round 2 {}: {} vB, mints {} from {}:0", round2.txid(), round2.vsize(), v2, round1.txid());
	assert_eq!(supply(&r, z), level + v1 - VALUE + v2);
	// Both batches are live: the report names each batch output it counts.
	let rep = r.http.post("issuer_supply", &json!({"asset": z.to_string()})).ok();
	let outs = rep["in_batches_outputs"].as_array().cloned().unwrap_or_default();
	println!("in batches after round 2: {} in {}", rep["in_batches"], serde_json::to_string(&outs).unwrap());
	assert_eq!(rep["in_batches"], json!((v1 + v2).to_string()));
	let named: Vec<(String, String)> = outs.iter().map(|o| (o["outpoint"].as_str().unwrap().to_string(), o["kind"].as_str().unwrap().to_string())).collect();
	for (round, v) in [(&round1, v1), (&round2, v2)] {
		let vout = outputs_of(round, z).iter().find(|o| o.1 == v).expect("the batch output").0;
		assert!(named.contains(&(format!("{}:{}", round.txid(), vout), "batch".to_string())), "{:?}", named);
	}

	// An offboard of the second leaf: its mint would pass the window's
	// allowance, so it waits, saying why.
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let leaf2 = &got2[0].new;
	let lv = leaf2.valid(&r);
	let paid = lv.value - 50_000;
	let home = destination(&keypair("H, home"));
	let out = OutputRequest::Offboard { asset: z, value: paid, script: home.clone() };
	let (body, id) = participation_body(&[&leaf2.held], &[out], &[(z, lv.value - paid)], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending", "{}", body);
	assert!(r.server.rounds.run_round().await.unwrap().is_none(), "no round: the mint does not fit the allowance");
	let why = status(&r, &id)["waiting"].as_str().unwrap_or("").to_string();
	println!("the offboard waits: {}", why);
	assert!(why.contains("mint limiter allows") && why.contains("window ends in"), "{}", why);

	// Once the window ends, it runs and mints its output.
	for _ in 0..window {
		r.produce().await;
	}
	r.bury().await;
	r.synced().await;
	let built = r.server.rounds.run_round().await.unwrap().expect("the offboard's round, its window over");
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let round3 = built.tx.clone();
	let v3: u64 = outputs_of(&round3, z).iter().map(|o| o.1).sum();
	assert_eq!(issuer::issued(&round3, z), Some(v3));
	assert_eq!(round3.input[0].previous_output, OutPoint::new(round2.txid(), 0));
	println!("round 3 {}: {} vB, mints {} for the offboard (a new window: the limiter's count restarts)", round3.txid(), round3.vsize(), v3);
	// The holder hands over its forfeit; the watcher unlocks the output to
	// its destination, burning the margin.
	let st = status(&r, &id);
	let c = st["round"]["connector_vout"].as_u64().unwrap() as u32;
	let units = st["outputs"][0]["reclaim_delay_units"].as_u64().unwrap() as u16;
	let policy = arca_covenant::OffboardPolicy {
		unlock_hash: unhex(st["unlock_hash"].as_str().unwrap()).try_into().unwrap(),
		destination: arca_covenant::ExplicitOutput::new(z, paid, home.clone()),
		operator: xonly(&r.s),
		reclaim_delay: arca_covenant::RelativeTime::from_units(units).unwrap(),
	};
	let delay = arca_covenant::RelativeTime::from_units(st["refund_delay_units"].as_u64().unwrap() as u16).unwrap();
	let margin: u64 = st["inputs"][0]["margin"].as_str().unwrap().parse().unwrap();
	let f = arca_covenant::Forfeit::for_offboard(lv.leaf, (lv.asset, lv.value), lv.id, &policy, &round3, c, delay, margin).unwrap();
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&id),
		"forfeits": [{"leaf_id": leaf2.held.id.to_string(), "signature": common::client::forfeit_sig(&f, &leaf2.held.key)}], "leaves": []})).ok();
	assert_eq!(done["state"], "released", "{}", done);
	drive(&r, "the offboard's unlock", 6, |l| l.iter().any(|w| w.kind == "unlock")).await;
	settle(&r).await;
	let unlock = of_kind(&r, "unlock").await.remove(0);
	let utx: Transaction = elements::encode::deserialize(&unlock.tx).unwrap();
	assert!(utx.output.iter().any(|o| o.script_pubkey == home && o.value.explicit() == Some(paid)), "the holder is paid at home");
	println!("  unlock {}: pays {} of Z home, burns {}", utx.txid(), paid, issuer::burned(&utx, z));

	// Both batches expire: released, then burned after the notice.
	let e = |c: &Coin| match &c.held.record {
		arca_covenant::CoinRecord::Leaf { record, .. } => record.schedule.expiries()[0].to_consensus_u32(),
		_ => unreachable!(),
	};
	let latest = e(&got[0].new).max(e(leaf2));
	let now = common::rounds::mtp(&r).to_consensus_u32();
	advance_mtp(&r, latest.saturating_sub(now) + HOUR).await;
	drive(&r, "both releases", 6, |l| l.iter().filter(|w| w.kind == "release").count() == 2).await;
	settle(&r).await;
	advance_mtp(&r, 37 * HOUR).await;
	drive(&r, "both sweeps", 6, |l| l.iter().filter(|w| w.kind == "sweep").count() == 2).await;
	settle(&r).await;
	for w in of_kind(&r, "sweep").await {
		let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
		assert!(outputs_of(&tx, z).iter().all(|o| issuer::is_burn(&o.2)), "a sweep of a burn-only batch only burns");
		println!("  sweep {}: {} vB, burns {} of Z, its fee in {}", txid(&w), tx.vsize(), issuer::burned(&tx, z),
			if tx.output.iter().any(|o| o.is_fee() && o.asset.explicit() == Some(x)) { "X" } else { "another asset" });
	}

	// The supply, read from the chain: back at its level, less the fee the
	// holder paid for its offboard, which was burned.
	let (issued, burned) = supply_of(&r, z);
	let fee_paid = lv.value - paid;
	println!("Z read from every block: issued {}, burned {}, supply {}; level {}; minted by rounds {} + {} + {}; the holder paid {} home \
		and {} in fees", issued, burned, issued - burned, level, v1, v2, v3, paid, fee_paid);
	assert_eq!(issued, ISSUED + v1 + v2 + v3);
	assert_eq!(issued - burned, level - fee_paid, "the supply is back at its level, less the fee the holder paid, burned");

	// The operator's report says the same, transaction by transaction.
	let rep = r.http.post("issuer_supply", &json!({"asset": z.to_string()})).ok();
	println!("issuer_supply: {}", serde_json::to_string_pretty(&rep).unwrap());
	assert_eq!(rep["minted"], json!((v1 + v2 + v3).to_string()));
	assert_eq!(rep["burned"], json!((burned).to_string()), "every burn of Z on the chain is the operator's");
	assert_eq!(rep["in_batches"], json!("0"));
	assert_eq!(rep["mints"].as_array().unwrap().len(), 3);
	let _ = DAY;
}

/// The BIP340 signature over `msg` by `key` inside `witness`, at whatever
/// bit offset the program's witness encoding put it; and the witness with
/// `new` in its place.
fn replace_signature(witness: &[u8], key: &XOnlyPublicKey, msg: &[u8; 32], new: &[u8; 64]) -> Vec<u8> {
	let secp = Secp256k1::verification_only();
	let bits: Vec<bool> = witness.iter().flat_map(|b| (0..8).rev().map(move |i| b >> i & 1 == 1)).collect();
	let m = Message::from_digest(*msg);
	for at in 0..=bits.len().saturating_sub(512) {
		let mut sig = [0u8; 64];
		for (k, bit) in bits[at..at + 512].iter().enumerate() {
			if *bit {
				sig[k / 8] |= 1 << (7 - k % 8);
			}
		}
		let Ok(s) = Signature::from_slice(&sig) else { continue };
		if secp.verify_schnorr(&s, &m, key).is_ok() {
			let mut out = bits.clone();
			for k in 0..512 {
				out[at + k] = new[k / 8] >> (7 - k % 8) & 1 == 1;
			}
			return out.chunks(8).map(|c| c.iter().fold(0u8, |a, b| a << 1 | *b as u8) << (8 - c.len())).collect();
		}
	}
	panic!("no signature by the operator key over the mint in the witness");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mint_beyond_the_allowance_is_refused_in_a_block() {
	let mut r = Running::start_plain_on(&["-evbparams=simplicity:-1:::"], |_, _| {}).await;
	let x = r.x;
	for _ in 0..6 {
		r.fund_wallet_in(x, 20_000_000).await;
	}
	let dir = work_dir("plain");
	// One refresh fits; nothing more in the window.
	let allowance = VALUE + 10;
	let i = issue_into_limiter(&mut r, &dir, allowance, 500);
	let z = i.z;
	for _ in 0..3 {
		r.produce().await;
	}
	r.bury().await;
	r.synced().await;
	serve_issuer_operated(&mut r, &i).await;
	let (held, btx) = credited_board(&mut r, &keypair("P, board"), z).await;
	let board = Coin { held, bases: vec![btx] };
	let (held2, btx2) = credited_board(&mut r, &keypair("Q, board"), z).await;
	let board2 = Coin { held: held2, bases: vec![btx2] };
	r.produce().await;
	r.bury().await;
	r.synced().await;

	// The server's round, within the allowance: the control.
	let key = keypair("P, leaf");
	let v = board.valid(&r);
	let (w, _) = common::client::want_leaf(&key, z, v.value);
	let (body, _) = participation_body(&[&board.held], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().expect("a round within the allowance");
	let control = built.tx.clone();
	let minted = issuer::issued(&control, z).unwrap();
	println!("the control: round {} ({} vB) mints {} of Z, the allowance {}", control.txid(), control.vsize(), minted, allowance);

	// The same round minting one atom over the allowance: the extra atoms in
	// its batch output (the same size, so the same fee rate), the limiter's
	// signature made again over this transaction, the wallet's inputs
	// signed again.
	let over = allowance + 1;
	let mut neg = control.clone();
	neg.input[0].asset_issuance = limiter::reissuance(i.entropy, over);
	let (bv, held_z, _) = outputs_of(&control, z).remove(0);
	neg.output[bv].value = elements::confidential::Value::Explicit(held_z + over - minted);
	let prevouts: Vec<String> = control.input.iter().map(|t| {
		let p = r.rt.client().raw_transaction(&t.previous_output.txid).unwrap();
		hex(&elements::encode::serialize(&p.output[t.previous_output.vout as usize]))
	}).collect();
	let state = json!({"minted": "0", "elapsed": 0, "armed": 0});
	let sighash = |tx: &Transaction| -> [u8; 32] {
		let v = tool_json_in(&["sighash", "--instance", i.instance.to_str().unwrap()],
			&json!({"tx": hex(&elements::encode::serialize(tx)), "prevouts": prevouts, "state": state}));
		unhex(v["sig_all_hash"].as_str().unwrap()).try_into().unwrap()
	};
	let words = std::fs::read_to_string(&i.words).unwrap();
	let signer = lwk_signer::SwSigner::new(words.trim(), false).unwrap();
	let xprv = signer.derive_xprv(&"m/8383h/1h/0h/0/0".parse().unwrap()).unwrap();
	let secp = Secp256k1::new();
	let kp = Keypair::from_secret_key(&secp, &xprv.private_key);
	assert_eq!(kp.x_only_public_key().0, i.limiter.operator, "the test's key is the limiter's operator key");
	let new_sig = secp.sign_schnorr(&Message::from_digest(sighash(&neg)), &kp);
	let mut stack = control.input[0].witness.script_witness.clone();
	stack[0] = replace_signature(&stack[0], &i.limiter.operator, &sighash(&control), new_sig.as_ref().try_into().unwrap());
	neg.input[0].witness.script_witness = stack;
	for k in 1..neg.input.len() {
		let op = neg.input[k].previous_output;
		let coin = r.server.store.wallet_coin_at(&op.txid.to_byte_array(), op.vout).await.unwrap().expect("a wallet coin");
		r.server.wallet.sign_input(&mut neg, k, &coin).unwrap();
	}
	// The control is in the mempool, so the mempool refuses the negative as
	// a replacement before it runs its scripts; the block is the proof.
	let accept = r.rt.client().test_mempool_accept(&[&neg]).unwrap().remove(0);
	println!("one atom over: testmempoolaccept {:?} (the control holds its inputs in the mempool)", accept.reject_reason);
	assert!(!accept.allowed);
	let h0 = r.rt.client().block_count().unwrap();
	let block = r.rt.client().generate_block("raw(51)", &[&neg]);
	let err = format!("{:?}", block.expect_err("the block takes no mint beyond the allowance"));
	println!("one atom over, forced into a block: {}", err);
	assert!(err.contains("Assertion failed inside jet"), "{}", err);
	assert_eq!(r.rt.client().block_count().unwrap(), h0);

	// A second refresh while the control is in no block: the limiter's coin
	// is the control's, so no round mints from it again.
	let key2 = keypair("Q, leaf");
	let v2 = board2.valid(&r);
	let (w2, _) = common::client::want_leaf(&key2, z, v2.value);
	let (body2, id2) = participation_body(&[&board2.held], &[w2], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body2).ok()["state"], "pending");
	assert!(r.server.rounds.run_round().await.unwrap().is_none(), "no second round spends the limiter's coin");
	let why = status(&r, &id2)["waiting"].as_str().unwrap_or("").to_string();
	println!("a second refresh, the control in the mempool, waits: {}", why);
	assert!(why.contains(&format!("is spent by the round {}, which is in no block yet", control.txid())), "{}", why);

	// The control, the server's own round, is mined.
	r.produce().await;
	r.bury().await;
	round_final(&r, &control.txid()).await;
	println!("the control {} is final", control.txid());

	// The second refresh would pass the allowance: it waits, saying why.
	r.produce().await;
	r.bury().await;
	r.synced().await;
	assert!(r.server.rounds.run_round().await.unwrap().is_none());
	let why = status(&r, &id2)["waiting"].as_str().unwrap_or("").to_string();
	println!("the second refresh, the control final, waits: {}", why);
	assert!(why.contains("mint limiter allows"), "{}", why);

	// A configuration whose only fee asset is the issuer-operated one is
	// refused: its rounds and sweeps would have no asset to pay fees in.
	let mut c = r.config.clone();
	c.fee_assets = Some(vec![z.to_string()]);
	let e = r.server.reload(&c).await.expect_err("no fee asset but the issuer-operated one");
	println!("fee_assets = [Z]: reload refused: {}", e.0);
	assert!(e.0.contains("every fee asset is issuer-operated"), "{}", e.0);
	let _ = (Txid::all_zeros(), DAY, &dir, xonly(&key));
}
