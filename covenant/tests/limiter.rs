//! The mint limiter as a round reads it, against the template's own address
//! vectors (`limiter_vectors.json`, copied from sequentia-contracts), and the
//! program's rule for the state a mint leads to.

mod common;

use elements::confidential::Value;
use elements::hashes::Hash;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid};
use serde_json::Value as Json;

use arca_covenant::limiter::{self, LIMITER_TEMPLATE, MIN_AGE};
use arca_covenant::{LimiterError, LimiterParams, LimiterSpend, LimiterState};
use common::*;

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Vec<u8> {
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn vectors() -> Vec<Json> {
	let v: Json = serde_json::from_str(include_str!("limiter_vectors.json")).unwrap();
	v["addresses"].as_array().unwrap().clone()
}

fn params_of(p: &Json) -> LimiterParams {
	let asset = |k: &str| AssetId::from_slice(&unhex(p[k].as_str().unwrap())).unwrap();
	let key = |k: &str| XOnlyPublicKey::from_slice(&unhex(p[k].as_str().unwrap())).unwrap();
	let num = |k: &str| u64::from_str_radix(p[k].as_str().unwrap(), 16).unwrap();
	LimiterParams {
		asset: asset("ASSET"), token: asset("TOKEN"), operator: key("OPERATOR_KEY"), cold: key("COLD_KEY"),
		window: num("WINDOW") as u16, allowance: num("ALLOWANCE"), recovery_delay: num("RECOVERY_DELAY") as u16,
	}
}

fn state_of(s: &Json) -> LimiterState {
	let num = |k: &str| u64::from_str_radix(s[k].as_str().unwrap(), 16).unwrap();
	LimiterState { minted: num("MINTED"), elapsed: num("ELAPSED") as u16, armed: num("ARMED") == 1 }
}

#[test]
fn every_address_vector_is_rebuilt() {
	let v = vectors();
	assert_eq!(v.len(), 8);
	for a in &v {
		let (p, s) = (params_of(&a["params"]), state_of(&a["slots"]));
		let name = a["name"].as_str().unwrap();
		assert_eq!(hex(&p.data(s)), a["data"].as_str().unwrap(), "{}: data", name);
		assert_eq!(hex(&p.merkle_root(s)), a["merkle_root"].as_str().unwrap(), "{}: merkle root", name);
		assert_eq!(hex(p.script_pubkey(s).as_bytes()), a["script_pubkey"].as_str().unwrap(), "{}: script", name);
		assert_eq!(p.taproot(s).merkle_root().map(|r| hex(&r)), Some(a["merkle_root"].as_str().unwrap().to_string()), "{}", name);
	}
}

#[test]
fn an_instance_file_reads_as_the_tool_writes_it() {
	let a = &vectors()[0];
	let genesis = "ddd11d54c87a2bd94400fd31ce05d8e1110bb4b78e7103f738342086fc4ea92e";
	let file = serde_json::json!({"instance": 2, "template_hash": LIMITER_TEMPLATE, "params": a["params"],
		"slots": a["slots"], "genesis": genesis});
	let (p, g) = LimiterParams::from_instance_json(&file.to_string()).unwrap();
	assert_eq!(p, params_of(&a["params"]));
	assert_eq!(g.to_string(), genesis);
	assert_eq!(hex(p.script_pubkey(LimiterState::default()).as_bytes()), a["script_pubkey"].as_str().unwrap());
	// Another template, one key for both roles, an empty allowance: refused.
	let mut other = file.clone();
	other["template_hash"] = Json::String("00".repeat(32));
	assert!(LimiterParams::from_instance_json(&other.to_string()).is_err());
	let mut one_key = file.clone();
	one_key["params"]["COLD_KEY"] = one_key["params"]["OPERATOR_KEY"].clone();
	assert!(LimiterParams::from_instance_json(&one_key.to_string()).is_err());
	let mut empty = file;
	empty["params"]["ALLOWANCE"] = Json::String("0".repeat(16));
	assert!(LimiterParams::from_instance_json(&empty.to_string()).is_err());
}

fn small() -> LimiterParams {
	LimiterParams { window: 20, allowance: 1_000, ..params_of(&vectors()[0]["params"]) }
}

fn st(minted: u64, elapsed: u16) -> LimiterState {
	LimiterState { minted, elapsed, armed: false }
}

/// The program's rule, as the tool's own unit test states it.
#[test]
fn a_mint_leads_where_the_program_says() {
	let p = small();
	assert_eq!(p.mint(st(0, 0), 2, 500), Ok(st(500, 2)));
	assert_eq!(p.mint(st(500, 2), 2, 500), Ok(st(1_000, 4)));
	assert_eq!(p.mint(st(500, 2), 2, 501), Err(LimiterError::OverAllowance { amount: 501, count: 1_001, allowance: 1_000 }));
	// The window ends once the blocks behind the coin and its age reach 20.
	assert!(p.mint(st(1_000, 4), 15, 1).is_err());
	assert_eq!(p.mint(st(1_000, 4), 16, 1_000), Ok(st(1_000, 0)));
	assert_eq!(p.mint(st(0, 0), 1, 1), Err(LimiterError::TooYoung(1)));
	assert_eq!(p.mint(LimiterState { armed: true, ..st(0, 0) }, 2, 1), Err(LimiterError::Braked));
	assert_eq!(p.mint(st(0, 0), 2, 0), Err(LimiterError::Zero));
	assert_eq!(p.room(st(700, 3), 2), 300);
	assert_eq!(p.room(st(700, 3), 17), 1_000);
	assert_eq!(p.room(st(700, 3), MIN_AGE - 1), 0);
	assert_eq!(p.blocks_to_new_window(st(700, 3), 2), 15);
}

fn spend_of(p: &LimiterParams, next: Option<LimiterState>, issue: Option<(u64, u32)>, at: usize) -> Transaction {
	let coin = TxIn { previous_output: OutPoint::new(Txid::from_byte_array(label32("limiter coin")), 0), ..Default::default() };
	let other = TxIn { previous_output: OutPoint::new(Txid::from_byte_array(label32("fee coin")), 0), ..Default::default() };
	let mut input = if at == 0 { vec![coin, other] } else { vec![other, coin] };
	if let Some((amount, seq)) = issue {
		input[at].asset_issuance = limiter::reissuance([7; 32], amount);
		input[at].sequence = Sequence(seq);
	}
	let mut output = vec![];
	if let Some(n) = next {
		output.push(explicit(p.token, 1, p.script_pubkey(n)));
	}
	output.push(TxOut::new_fee(500, p.asset));
	Transaction { version: 2, lock_time: elements::LockTime::ZERO, input, output }
}

#[test]
fn a_spend_of_the_coin_is_followed_to_its_state() {
	let p = small();
	let s = st(200, 5);
	let mint = spend_of(&p, Some(st(500, 7)), Some((300, 2)), 0);
	assert_eq!(p.follow(s, &mint, 0), Some(LimiterSpend::Mint { amount: 300, age: 2, next: st(500, 7) }));
	// A successor that is not the program's state is no path of it.
	assert_eq!(p.follow(s, &spend_of(&p, Some(st(400, 7)), Some((300, 2)), 0), 0), None);
	// An age in time is no mint.
	assert_eq!(p.follow(s, &spend_of(&p, Some(st(500, 7)), Some((300, 1 << 22 | 2)), 0), 0), None);
	// The coin at input 1: the program refuses it.
	assert_eq!(p.follow(s, &spend_of(&p, Some(st(500, 7)), Some((300, 2)), 1), 1), None);
	let armed = LimiterState { armed: true, ..s };
	assert_eq!(p.follow(s, &spend_of(&p, Some(armed), None, 0), 0), Some(LimiterSpend::Arm { next: armed }));
	assert_eq!(p.follow(armed, &spend_of(&p, Some(s), None, 0), 0), Some(LimiterSpend::Disarm { next: s }));
	assert_eq!(p.follow(armed, &spend_of(&p, None, None, 0), 0), Some(LimiterSpend::Recover));
	assert_eq!(p.follow(s, &spend_of(&p, None, None, 0), 0), None);
}

#[test]
fn a_reissuance_names_its_asset_and_token() {
	let e = limiter::entropy_from_hex("6c4b9d1ec53a1f7d13e48a4e5fc7c80e3ad2f3cc7b14b5b4fdeaad8b8d6c2c1f").unwrap();
	let i = limiter::reissuance(e, 1_000);
	assert_eq!(i.amount, Value::Explicit(1_000));
	assert_ne!(i.asset_blinding_nonce, elements::secp256k1_zkp::ZERO_TWEAK);
	assert_eq!(i.denomination, 8);
	let mut tx = spend_of(&small(), None, None, 0);
	tx.input[0].asset_issuance = i;
	assert_eq!(tx.input[0].issuance_ids().0, limiter::asset_of_entropy(e));
	assert_ne!(limiter::token_of_entropy(e), limiter::asset_of_entropy(e));
}
