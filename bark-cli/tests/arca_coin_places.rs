//! Where each coin stands, and the instant limit ([`bark::arca::places`]),
//! run by the `arca` binary against a whole Arca server on an anchored
//! regtest chain, the operator's bond posted.
//!
//! 1. A payment under the limit counts at once, and is spent on at once.
//! 2. One over the limit arrives: it is in no payment and gives no trade,
//!    `refresh_needed` names it (`arriving`), and once its round is final
//!    it is settled.
//! 3. Several small payments cross the limit in the order they arrived:
//!    the oldest count, the rest arrive, and none moves back.
//! 4. The limit taken is the lower of the wallet's and the operator's
//!    suggestion (`[bond] instant_limit_value`); a wallet that sets none
//!    counts every payment, as before.
//! 5. A trade's proceeds, every checkpoint with its owner's exit: of
//!    `trade` lineage, counting nothing against the limit or the bond,
//!    traded on at once; never paid out of the Arca. The coin given held
//!    exactly the amount, shaped by a payment to itself first, so no change
//!    of the wallet's rode in the trade.
//! 6. A restore from the mnemonic alone gives the same places.
//! 7. An anchor rollback under the coins: every coin not final again
//!    arrives, and counts again once final.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use elements::{AssetId, OutPoint, Script};
use serde_json::{json, Value};

use arca_covenant::bond::BondPolicy;
use arca_covenant::RelativeTime;
use bark::arca::{command, Wallet};
use common::cli::Arca;
use common::running::{keypair, Running};
use server::bond::BondSection;
use server::store::RoundState;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

fn library(a: &Arca, cmd: &str, args: Value) -> Result<Value, String> {
	tokio::task::block_in_place(|| {
		let mut w = Wallet::open(&a.dir).expect("open the wallet");
		command::run(&mut w, cmd, &args).map(|v| v["result"].clone()).map_err(|e| e.to_string())
	})
}

fn create(r: &Running, w: &Arca) {
	w.ok(&["create", "--server", &r.url(), "--node-url", &r.node_url(), "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]);
}

const BOND: u64 = 50_000_000;

fn notice_units() -> u16 {
	server::bond::min_notice_seconds(server::bond::LIFETIME, RelativeTime::from_units(338).unwrap()).div_ceil(512) as u16
}

/// Posts the operator's bond, with `limit` as its suggested instant limit.
async fn post_bond(r: &mut Running, limit: Option<u64>) -> OutPoint {
	let w = keypair("coin-places W");
	let s_key = keypair("operator");
	let chain = arca_covenant::Chain::new(r.rt.client().genesis_hash().unwrap());
	let policy = BondPolicy::new(chain, s_key.x_only_public_key().0, w.x_only_public_key().0,
		RelativeTime::from_units(notice_units()).unwrap()).unwrap();
	let x = r.x;
	let tx = r.pay_to(policy.script_pubkey(), x, BOND);
	r.produce().await;
	r.bury().await;
	let vout = tx.output.iter().position(|o| o.script_pubkey == policy.script_pubkey()).unwrap() as u32;
	let op = OutPoint::new(tx.txid(), vout);
	r.config.bond = Some(BondSection { withdraw_key: w.x_only_public_key().0.to_string(), notice_units: notice_units(),
		outpoint: Some(format!("{}:{}", op.txid, op.vout)), notice: None, instant_budget_fraction: None,
		instant_limit_value: limit.map(|l| l.to_string()) });
	r.restart_server().await;
	r.synced().await;
	op
}

async fn boarded(r: &mut Running, w: &Arca, assets: &[(AssetId, u64)]) {
	create(r, w);
	let x = r.x;
	for (a, v) in assets {
		let s = script(&w.ok(&["address"]));
		r.pay_to(s, *a, v + 3_000_000);
	}
	let s = script(&w.ok(&["address"]));
	r.pay_to(s, x, 3_000_000);
	r.produce().await;
	for (a, v) in assets {
		w.ok(&["board", &a.to_string(), &v.to_string(), "--fee-asset", &x.to_string()]);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the boards to be credited", || {
		w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")
	}).await;
	w.ok(&["sync"]);
}

/// `from` pays `to` `amount` of `asset` out of round; the coin `to` holds.
fn pay(from: &Arca, to: &Arca, asset: AssetId, amount: u64) -> String {
	let req = to.ok(&["receive"])["request"].as_str().unwrap().to_string();
	from.ok(&["send", &req, "--amount", &amount.to_string(), "--asset", &asset.to_string()]);
	let mb = to.ok(&["mailbox"]);
	mb["accepted"].as_array().unwrap().iter().find(|c| c["value"].as_str() == Some(&amount.to_string()) || c["value"] == amount)
		.or_else(|| mb["accepted"].as_array().unwrap().last())
		.and_then(|c| c["leaf_id"].as_str()).expect("the payee holds the coin").to_string()
}

/// `from` pays `to`, refused for `why`: the refusal.
fn pay_refused(from: &Arca, to: &Arca, asset: AssetId, amount: u64, why: &str) -> String {
	let req = to.ok(&["receive"])["request"].as_str().unwrap().to_string();
	from.refused(&["send", &req, "--amount", &amount.to_string(), "--asset", &asset.to_string()], why)
}

/// Every round the operator can build now, each made final.
async fn rounds_final(r: &Running) {
	let (built, errs) = r.server.rounds.run_rounds().await.unwrap();
	assert!(errs.is_empty(), "{:?}", errs);
	r.produce().await;
	r.bury().await;
	for b in &built {
		r.round_state(&b.tx.txid(), RoundState::Final).await;
	}
}

fn places(w: &Arca) -> Value {
	library(w, "coin_places", json!({})).unwrap()
}

fn place_of(p: &Value, leaf: &str) -> String {
	p["coins"].as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf)
		.map(|c| c["place"].as_str().unwrap().to_string()).unwrap_or_else(|| "none".into())
}

fn rate(r: &Running, a: AssetId) -> u128 {
	let rates: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
	rates[a.to_string()].as_u64().unwrap_or_else(|| panic!("no rate for {} in {}", a, rates)) as u128
}

/// Sets the node's rate for `a`, as an operator's price server would: the
/// operator reads it at its start.
fn price(r: &Running, a: AssetId, rate: u64) {
	let mut set: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
	set[a.to_string()] = json!(rate);
	r.rt.client().call::<Value>("setfeeexchangerates", &[set]).unwrap();
}

/// Atoms of the reference unit `atoms` of `a` are worth.
fn worth(r: &Running, a: AssetId, atoms: u64) -> u128 {
	atoms as u128 * rate(r, a) / 100_000_000
}

fn summary(tag: &str, w: &Arca) -> Value {
	let p = places(w);
	let line: Vec<String> = p["coins"].as_array().unwrap().iter()
		.map(|c| format!("{}…={}/{}/{}", &c["leaf_id"].as_str().unwrap()[..8], c["value"].as_str().unwrap(), c["state"].as_str().unwrap(),
			c["place"].as_str().unwrap())).collect();
	println!("{}: {} places: [{}] limit {}", tag, w.name, line.join(", "), p["instant_limit"]);
	p
}

#[tokio::test(flavor = "multi_thread")]
async fn payments_count_up_to_the_limit_in_the_order_they_arrive() {
	let mut r = Running::start().await;
	let (x, y) = (r.x, r.y);
	price(&r, y, 100_000_000);
	post_bond(&mut r, None).await;
	let (s, b, c, d) = (Arca::new("CP1 S"), Arca::new("CP1 B"), Arca::new("CP1 C"), Arca::new("CP1 D"));
	let s2 = Arca::new("CP1 S2");
	boarded(&mut r, &s, &[(x, 12_000_000)]).await;
	boarded(&mut r, &s2, &[(x, 12_000_000)]).await;
	for w in [&b, &c, &d] {
		create(&r, w);
	}
	// B counts at most what 1,000,000 X is worth, at the node's rates.
	let limit = worth(&r, x, 1_000_000);
	library(&b, "instant_limit", json!({"value": limit.to_string()})).unwrap();
	library(&d, "instant_limit", json!({"value": limit.to_string()})).unwrap();

	// 1. Under the limit: counted at once, and spent on at once.
	let small = pay(&s, &b, x, 400_000);
	let p = summary("CP1 under", &b);
	assert_eq!(place_of(&p, &small), "counted");
	assert_eq!(p["spendable"][x.to_string()], "400000", "{}", p);
	assert_eq!(p["instant_limit"]["counted"], worth(&r, x, 400_000).to_string());
	let on = pay(&b, &c, x, 300_000);
	println!("CP1 under: B paid C 300,000 at once ({})", &on[..16]);
	let p = summary("CP1 under, paid on", &b);
	assert!(p["coins"].as_array().unwrap().iter().all(|k| k["place"] == "counted" || k["state"] != "live"), "{}", p);

	// 2. Over the limit: arriving. No payment and no trade takes it.
	let big = pay(&s, &b, x, 1_500_000);
	let p = summary("CP1 over", &b);
	assert_eq!(place_of(&p, &big), "arriving", "{}", p);
	pay_refused(&b, &c, x, 1_000_000, "live coins");
	let offer = library(&b, "swap_offer", json!({"give_asset": x, "give": "1000000", "want_asset": y, "want": "1000000"}));
	println!("CP1 over: B offers it in a trade: {:?}", offer);
	assert!(offer.as_ref().is_err_and(|e| e.contains("live coins")), "{:?}", offer);
	let need = library(&b, "refresh_needed", json!({})).unwrap();
	println!("CP1 over: refresh_needed: {}", need);
	assert_eq!(need["reasons"][0]["rule"], "arriving", "{}", need);
	assert_eq!(need["reasons"][0]["coins"], json!([big]), "{}", need);
	// Its round: once final, the new coin is settled and spends.
	let rr = b.ok(&["refresh-received"]);
	println!("CP1 over: B's refresh: {}", rr["refreshed"]);
	rounds_final(&r).await;
	b.ok(&["sync"]);
	let p = summary("CP1 over, after its round", &b);
	assert!(p["coins"].as_array().unwrap().iter().filter(|k| k["state"] == "live").all(|k| k["place"] == "settled"), "{}", p);
	assert_eq!(place_of(&p, &big), "none", "the arriving coin was given up in the round");
	pay(&b, &c, x, 1_000_000);
	println!("CP1 over: after its round, B paid C 1,000,000");

	// 3. Several small payments cross the limit in order.
	let mut got = vec![];
	for v in [400_000u64, 400_000, 400_000, 100_000] {
		got.push(pay(&s2, &d, x, v));
	}
	let p = summary("CP1 several", &d);
	let shown: Vec<String> = got.iter().map(|l| place_of(&p, l)).collect();
	println!("CP1 several: 400,000 ×3 then 100,000 against 1,000,000: {:?}", shown);
	assert_eq!(shown, ["counted", "counted", "arriving", "arriving"], "{}", p);
	// The price of X doubles: what was counted stays counted.
	let mut set: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
	let before = set[x.to_string()].as_u64().unwrap();
	set[x.to_string()] = json!(before * 2);
	r.rt.client().call::<Value>("setfeeexchangerates", &[set.clone()]).unwrap();
	let p = summary("CP1 several, X doubled", &d);
	let shown2: Vec<String> = got.iter().map(|l| place_of(&p, l)).collect();
	assert_eq!(shown2, shown, "a price rise moves no coin back: {}", p);
	set[x.to_string()] = json!(before);
	r.rt.client().call::<Value>("setfeeexchangerates", &[set]).unwrap();

	// 6. A restore from the mnemonic alone gives the same places.
	let d2 = Arca::new("CP1 D2");
	let mnemonic = std::fs::read_to_string(d.dir.join("mnemonic")).unwrap();
	let made = d2.ok(&["create", "--server", &r.url(), "--node-url", &r.node_url(), "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1", "--mnemonic", mnemonic.trim()]);
	println!("CP1 restore: restored {} | not recovered {}", made["restore"]["restored"], made["restore"]["not_recovered"]);
	library(&d2, "instant_limit", json!({"value": limit.to_string()})).unwrap();
	d2.ok(&["sync"]);
	let p2 = summary("CP1 restored", &d2);
	let shown3: Vec<String> = got.iter().map(|l| place_of(&p2, l)).collect();
	assert_eq!(shown3, shown, "the restored wallet places every coin as the lost one did: {}", p2);
	let _ = std::fs::remove_dir_all(&d2.dir);

	// 4. No limit set: every payment counts, as before.
	let p = summary("CP1 none", &c);
	assert!(p["instant_limit"].is_null());
	assert!(p["coins"].as_array().unwrap().iter().all(|k| k["place"] == "counted"), "{}", p);
	for w in [&s, &s2, &b, &c, &d] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn the_operators_suggestion_bounds_the_limit_and_no_bond_counts_nothing() {
	let mut r = Running::start().await;
	let x = r.x;
	let (s, b, e) = (Arca::new("CP4 S"), Arca::new("CP4 B"), Arca::new("CP4 E"));
	boarded(&mut r, &s, &[(x, 6_000_000)]).await;
	create(&r, &b);
	create(&r, &e);
	let mine = worth(&r, x, 1_000_000);
	library(&e, "instant_limit", json!({"value": mine.to_string()})).unwrap();
	// No bond: nothing deters a sender and the operator, so nothing counts.
	let k = pay(&s, &e, x, 100_000);
	let p = summary("CP4 no bond", &e);
	assert_eq!(p["instant_limit"]["value"], "0", "{}", p);
	assert_eq!(place_of(&p, &k), "arriving");
	// The operator suggests what 600,000 X is worth: the lower is taken.
	let suggested = worth(&r, x, 600_000) as u64;
	post_bond(&mut r, Some(suggested)).await;
	let info: Value = serde_json::from_str(minreq::get(format!("{}/v1/info", r.url())).send().unwrap().as_str().unwrap()).unwrap();
	println!("CP4: info.bond.instant_limit_value = {}", info["bond"]["instant_limit_value"]);
	assert_eq!(info["bond"]["instant_limit_value"], suggested.to_string());
	library(&b, "instant_limit", json!({"value": mine.to_string()})).unwrap();
	let a1 = pay(&s, &b, x, 400_000);
	let a2 = pay(&s, &b, x, 400_000);
	let p = summary("CP4 suggested", &b);
	assert_eq!(p["instant_limit"]["value"], suggested.to_string(), "{}", p);
	assert_eq!(p["instant_limit"]["operator"], suggested.to_string(), "{}", p);
	assert_eq!((place_of(&p, &a1).as_str(), place_of(&p, &a2).as_str()), ("counted", "arriving"), "{}", p);
	// The one received before the bond stood is counted once it does.
	let p = summary("CP4 bond up", &e);
	assert_eq!(place_of(&p, &k), "counted", "{}", p);
	for w in [&s, &b, &e] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// 5. Trades: proceeds traded on at once, and a chain unwound.
// ---------------------------------------------------------------------------

mod trade {
	use std::str::FromStr;

	use elements::{OutPoint, Script, Transaction};
	use serde_json::Value;

	use arca_covenant::spend::FeeSource;
	use arca_covenant::transfer::reassignment_tx;
	use arca_covenant::{Chain, CoinRecord, ExplicitOutput, MedianTime, Pair, TransferPlan, ValidCoin, ValidInput, ValidOrigin, WalletPolicy};
	use super::common::cli::Arca;
	use super::common::running::{keypair, Running};

	pub fn unhex(h: &str) -> Vec<u8> {
		super::unhex(h)
	}

	pub fn hex(b: &[u8]) -> String {
		b.iter().map(|x| format!("{:02x}", x)).collect()
	}

	pub fn record_bytes(w: &Arca, leaf: &str) -> Vec<u8> {
		unhex(w.ok(&["record", leaf])["record"].as_str().unwrap())
	}

	/// The JSON a swap text (an offer, an acceptance) carries.
	pub fn text_json(text: &str) -> Value {
		let (_, h) = text.split_once(':').unwrap();
		serde_json::from_slice(&unhex(h)).unwrap()
	}

	fn find_unspent(r: &Running, out: &elements::TxOut) -> OutPoint {
		let found: Value = r.rt.client().call("scantxoutset", &[serde_json::json!("start"),
			serde_json::json!([format!("raw({})", hex(out.script_pubkey.as_bytes()))])]).unwrap();
		let u = found["unspents"].as_array().unwrap().first().unwrap_or_else(|| panic!("nothing pays {}", hex(out.script_pubkey.as_bytes())));
		OutPoint::new(elements::Txid::from_str(u["txid"].as_str().unwrap()).unwrap(), u["vout"].as_u64().unwrap() as u32)
	}

	fn sign_p2wpkh(tx: &mut Transaction, i: usize, prev: &elements::TxOut, key: &elements::secp256k1_zkp::Keypair) {
		use elements::hashes::Hash;
		let pk = key.public_key();
		let h = elements::hashes::hash160::Hash::hash(&pk.serialize());
		let code = Script::new_p2pkh(&elements::PubkeyHash::from_raw_hash(h));
		let sighash = elements::sighash::SighashCache::new(&*tx).segwitv0_sighash(i, &code, prev.value, elements::EcdsaSighashType::All);
		let msg = elements::secp256k1_zkp::Message::from_digest(sighash.to_byte_array());
		let sig = elements::secp256k1_zkp::Secp256k1::new().sign_ecdsa_low_r(&msg, &key.secret_key());
		let mut der = sig.serialize_der().to_vec();
		der.push(elements::EcdsaSighashType::All as u8);
		tx.input[i].witness.script_witness = vec![der, pk.serialize().to_vec()];
	}

	async fn fee_coin(r: &mut Running, label: &str) -> (OutPoint, elements::TxOut, elements::secp256k1_zkp::Keypair) {
		let key = keypair(label);
		let s = bark::arca::keys::p2wpkh(&key);
		let paid = r.pay_to(s.clone(), r.x, 100_000);
		r.produce().await;
		let j = paid.output.iter().position(|o| o.script_pubkey == s).unwrap();
		(OutPoint::new(paid.txid(), j as u32), paid.output[j].clone(), key)
	}

	/// The transaction of `w`'s board `board`, while it is unspent.
	pub fn board_tx(r: &Running, w: &Arca, board: &str) -> Transaction {
		let CoinRecord::Board(b) = CoinRecord::from_bytes(&record_bytes(w, board)).unwrap() else { panic!("a board") };
		let at = find_unspent(r, &b.output().txout());
		r.rt.client().raw_transaction(&at.txid).unwrap()
	}

	fn valid(r: &Running, w: &Arca, leaf: &str, bases: &[Transaction]) -> ValidCoin {
		let record = CoinRecord::from_bytes(&record_bytes(w, leaf)).unwrap();
		let genesis = r.rt.client().genesis_hash().unwrap();
		let now = MedianTime::from_consensus(super::common::node::median_time(&r.rt) as u32).unwrap();
		let policy = WalletPolicy { min_exit_delay: arca_covenant::RelativeTime::from_units(1).unwrap(),
			..WalletPolicy::new(Chain::new(genesis), keypair("operator").x_only_public_key().0, now) };
		record.resolve(bases, &policy).unwrap()
	}

	fn board_key(w: &Arca, board: &str) -> elements::secp256k1_zkp::Keypair {
		let CoinRecord::Board(rec) = CoinRecord::from_bytes(&record_bytes(w, board)).unwrap() else { panic!("a board") };
		let mnemonic = std::fs::read_to_string(w.dir.join("mnemonic")).unwrap();
		bark::arca::keys::Keys::new(mnemonic.trim(), 0, 1).unwrap().leaf(&rec.owner_nonce).unwrap()
	}

	/// The counterparty `c` and the operator spend `c`'s checkpoint, of its
	/// board `c_board`, elsewhere: the trade that made `w`'s coin `gets`
	/// can never complete.
	pub async fn kill(r: &mut Running, w: &Arca, gets: &str, c: &Arca, c_board: &str, bases: &[Transaction], tag: &str) {
		let got = valid(r, w, gets, bases);
		let ValidOrigin::Transfer { inputs, .. } = &got.origin else { panic!("a reassignment's coin") };
		let ci: ValidInput = inputs.iter().find(|i| i.coin.id.to_string() == c_board).expect("the board is an input").clone();
		assert!(ci.checkpoint.exit.is_some(), "{}: the counterparty's checkpoint has its owner's exit", tag);
		let ck = board_key(c, c_board);
		let (op, out, key) = fee_coin(r, &format!("{} attack fee", tag)).await;
		let back = vec![ExplicitOutput::new(ci.coin.asset, ci.checkpoint_value, Script::from(vec![0x51]))];
		let plan = TransferPlan { checkpoint_exit: true, inputs: vec![(ci.coin.clone(), ci.checkpoint_value)], outputs: back.clone() };
		let d = plan.reassignment_message(0).unwrap().digest;
		let sig = |k: &elements::secp256k1_zkp::Keypair| arca_covenant::sign::sign_digest(k, &d, &[0; 32]);
		let second = ValidInput { reassignment_pair: Pair { operator: sig(&keypair("operator")), owner: sig(&ck) }, ..ci.clone() };
		// The checkpoint, from the board.
		let (fop, fout, fkey) = fee_coin(r, &format!("{} checkpoint fee", tag)).await;
		let mut ctx = ci.board_checkpoint_tx(&FeeSource::Coin { outpoint: fop, coin: fout.clone(), fee: 3_000,
			change: bark::arca::keys::p2wpkh(&fkey) }).unwrap().tx;
		let k = ctx.input.iter().position(|x| x.previous_output == fop).unwrap();
		sign_p2wpkh(&mut ctx, k, &fout, &fkey);
		let cid = r.rt.client().send_raw_transaction(&ctx).expect("the checkpoint relays");
		println!("{}: C's checkpoint from its board {} ({} vB)", tag, cid, ctx.vsize());
		let cp = OutPoint::new(cid, 0);
		let mut tx = reassignment_tx(&[second], &back, &[cp], &FeeSource::Coin { outpoint: op, coin: out.clone(), fee: 3_000,
			change: bark::arca::keys::p2wpkh(&key) }).unwrap().tx;
		let k = tx.input.iter().position(|x| x.previous_output == op).unwrap();
		sign_p2wpkh(&mut tx, k, &out, &key);
		let id = r.rt.client().send_raw_transaction(&tx).expect("the second reassignment relays");
		r.produce().await;
		println!("{}: ATTACK C + operator: a second reassignment of C's checkpoint {} ({} vB)", tag, id, tx.vsize());
	}
}

fn watcher_off() -> impl FnOnce(&mut server::server::Config, AssetId, AssetId) {
	|c, _, _| c.watcher.enabled = false
}

fn coin_of(w: &Arca, leaf: &str) -> Value {
	w.ok(&["coins"]).as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).cloned().unwrap_or(Value::Null)
}

/// The leaf id of the coin `w` holds live of `asset` that is not in `not`,
/// the smallest.
fn newest_of(w: &Arca, asset: AssetId, not: &[&str]) -> String {
	let mut cs: Vec<Value> = w.ok(&["coins"]).as_array().unwrap().iter()
		.filter(|k| k["asset"] == asset.to_string() && k["state"] == "live" && !not.contains(&k["leaf_id"].as_str().unwrap()))
		.cloned().collect();
	cs.sort_by_key(|k| k["value"].as_str().unwrap().parse::<u64>().unwrap());
	cs.first().unwrap_or_else(|| panic!("{} holds no other live coin of {}", w.name, asset))["leaf_id"].as_str().unwrap().to_string()
}

/// Moves `w`'s return of `coin` on until it is exited, the delay run.
async fn finish_return(r: &Running, w: &Arca, coin: &str, tag: &str) -> Value {
	for _ in 0..8 {
		let step = w.ok(&["exit", coin]);
		println!("{}: {}'s return of {}…: {}", tag, w.name, &coin[..8], step["state"]);
		if step["state"] == "exited" {
			return step;
		}
		common::node::advance_mtp(&r.rt, 512 + 120);
		r.produce().await;
		r.bury().await;
	}
	w.ok(&["exit", coin])
}

#[tokio::test(flavor = "multi_thread")]
async fn proceeds_trade_on_at_once_and_a_dead_first_trade_unwinds_the_chain() {
	let mut r = Running::start_with(watcher_off()).await;
	let (x, y) = (r.x, r.y);
	price(&r, y, 100_000_000);
	post_bond(&mut r, None).await;
	let (a, c, e) = (Arca::new("CP5 A"), Arca::new("CP5 C"), Arca::new("CP5 E"));
	boarded(&mut r, &a, &[(x, 2_000_000)]).await;
	boarded(&mut r, &c, &[(y, 2_000_000)]).await;
	boarded(&mut r, &e, &[(x, 2_000_000)]).await;
	let board_of = |w: &Arca| w.ok(&["coins"]).as_array().unwrap()[0]["leaf_id"].as_str().unwrap().to_string();
	let (a_board, c_board, e_board) = (board_of(&a), board_of(&c), board_of(&e));
	let bases = vec![trade::board_tx(&r, &a, &a_board), trade::board_tx(&r, &c, &c_board), trade::board_tx(&r, &e, &e_board)];
	library(&a, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();

	// Trade 1: A gives 300,000 X for 400,000 Y. A's give coin holds exactly
	// that: shaped by a payment to itself first.
	let offer = a.ok(&["swap", "offer", "--give-asset", &x.to_string(), "--give", "300000", "--want-asset", &y.to_string(), "--want", "400000"]);
	let o = trade::text_json(offer["offer"].as_str().unwrap());
	println!("CP5 trade 1: A's offer: {} input(s), outputs {}, checkpoint_exit {}", o["inputs"].as_array().unwrap().len(),
		o["outputs"], o["checkpoint_exit"]);
	assert_eq!(o["checkpoint_exit"], true);
	assert_eq!(o["inputs"].as_array().unwrap().len(), 1);
	assert_eq!(o["outputs"].as_array().unwrap().len(), 1, "no change of A's rides in the trade: {}", o["outputs"]);
	let shaped = o["inputs"][0]["leaf_id"].as_str().unwrap().to_string();
	assert_ne!(shaped, a_board, "the coin given is the shaped one");
	let acc = c.ok(&["swap", "accept", offer["offer"].as_str().unwrap()]);
	a.ok(&["swap", "complete", acc["accept"].as_str().unwrap()]);
	a.ok(&["sync"]);
	c.ok(&["sync"]);
	let a_y = newest_of(&a, y, &[]);
	let p = summary("CP5 after trade 1", &a);
	assert_eq!(place_of(&p, &a_y), "proceeds", "{}", p);
	assert!(p["coins"].as_array().unwrap().iter().filter(|k| k["asset"] == x.to_string() && k["state"] == "live")
		.all(|k| k["place"] == "settled"), "A's own X stays settled: {}", p);
	let bond = a.ok(&["bond"]);
	println!("CP5: A's bond view: out of round {}", bond["out_of_round"]);
	assert_eq!(bond["out_of_round"], json!([]), "proceeds count nothing against the bond");
	// Proceeds never leave the Arca before their round.
	let addr = a.ok(&["address"]);
	let off = library(&a, "offboard_quote", json!({"asset": y, "amount": "100000", "script": addr["script_pubkey"]}));
	println!("CP5: A pays the proceeds on the chain: {:?}", off);
	assert!(off.is_err(), "{:?}", off);

	// Trade 2, at once: A gives Y of its proceeds for X from E.
	let offer2 = a.ok(&["swap", "offer", "--give-asset", &y.to_string(), "--give", "200000", "--want-asset", &x.to_string(), "--want", "150000"]);
	let o2 = trade::text_json(offer2["offer"].as_str().unwrap());
	assert_eq!(o2["outputs"].as_array().unwrap().len(), 1, "{}", o2["outputs"]);
	let acc2 = e.ok(&["swap", "accept", offer2["offer"].as_str().unwrap()]);
	a.ok(&["swap", "complete", acc2["accept"].as_str().unwrap()]);
	a.ok(&["sync"]);
	e.ok(&["sync"]);
	let a_x2 = newest_of(&a, x, &[&shaped]);
	let p = summary("CP5 after trade 2", &a);
	assert_eq!(place_of(&p, &a_x2), "proceeds", "what a trade of proceeds pays is proceeds: {}", p);
	let e_y = newest_of(&e, y, &[]);
	summary("CP5 after trade 2", &e);

	// C and the operator kill trade 1.
	trade::kill(&mut r, &a, &a_y, &c, &c_board, &bases, "CP5").await;
	let rc = a.ok(&["recheck"]);
	println!("CP5: A's re-check: {}", rc["changes"]);
	let re = e.ok(&["recheck"]);
	println!("CP5: E's re-check: {}", re["changes"]);
	let a_given = coin_of(&a, &shaped);
	let e_given = coin_of(&e, &e_board);
	println!("CP5: A's given coin: {}", a_given);
	println!("CP5: E's given coin: {}", e_given);
	assert_eq!(a_given["state"], "exiting", "A's coin comes home: {}", a_given);
	assert_eq!(e_given["state"], "exiting", "E's coin comes home: {}", e_given);
	let a_done = finish_return(&r, &a, &shaped, "CP5").await;
	let e_done = finish_return(&r, &e, &e_board, "CP5").await;
	println!("CP5: A's return: {}", a_done);
	println!("CP5: E's return: {}", e_done);
	assert_eq!(a_done["state"], "exited");
	assert_eq!(e_done["state"], "exited");
	for (w, l) in [(&a, &a_y), (&a, &a_x2), (&e, &e_y)] {
		let k = coin_of(w, l);
		println!("CP5: {}'s void coin {}…: {} ({})", w.name, &l[..8], k["state"], k["note"]);
		assert_ne!(k["state"], "live");
	}
	// The change of A's shaping payment went on the chain with the coin it
	// unrolled: it is on its way home too, and arrives there.
	let p = summary("CP5 after the returns", &a);
	let change = p["coins"].as_array().unwrap().iter().find(|k| k["state"] == "exiting").map(|k| k["leaf_id"].as_str().unwrap().to_string())
		.expect("the shaping payment's change is exiting");
	assert_eq!(place_of(&p, &change), "arriving", "{}", p);
	let done = finish_return(&r, &a, &change, "CP5").await;
	println!("CP5: the change's return: {}", done);
	assert_eq!(done["state"], "exited");
	let p = summary("CP5 at the end", &a);
	assert!(p["coins"].as_array().unwrap().is_empty(), "{}", p);
	let bal = a.ok(&["balance"]);
	println!("CP5: A's balance at the end: {}", bal["held"]);
	let held_x: u64 = bal["held"][x.to_string()].as_str().unwrap().parse().unwrap();
	assert!(held_x > 1_990_000, "A holds its X again, less the exits' fees: {}", held_x);
	for w in [&a, &c, &e] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// 7. An anchor rollback under the coins.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_anchor_rollback_makes_every_coin_on_it_arrive_until_final_again() {
	let mut r = Running::start_with(|cfg, _, _| cfg.finality.anchor_depth = 0).await;
	let x = r.x;
	post_bond(&mut r, None).await;
	let (s, b, c) = (Arca::new("CP7 S"), Arca::new("CP7 B"), Arca::new("CP7 C"));
	// S's board in a block anchored to a parent block of its own, which
	// nothing buries.
	create(&r, &s);
	create(&r, &b);
	create(&r, &c);
	let addr = script(&s.ok(&["address"]));
	r.pay_to(addr, x, 9_000_000);
	r.produce().await;
	r.bury().await;
	tokio::task::block_in_place(|| {
		r.rt.mine_parent(1).unwrap();
		r.rt.anchor_to_parent_tip().unwrap();
	});
	let p_board = r.rt.parent.client().block_count().unwrap();
	let board = s.ok(&["board", &x.to_string(), "6000000"])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.synced().await;
	r.wait("the board to be credited", || s.ok(&["boards"]).as_array().unwrap().iter().all(|k| k["server"]["state"] == "credited")).await;
	s.ok(&["sync"]);
	println!("CP7: S's board {}… in a block anchored at parent {}", &board[..8], p_board);
	library(&b, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	let counted = pay(&s, &b, x, 400_000);
	let arriving = pay(&s, &b, x, 1_500_000);
	let p = summary("CP7 before", &b);
	assert_eq!((place_of(&p, &counted).as_str(), place_of(&p, &arriving).as_str()), ("counted", "arriving"));

	// The parent chain drops the board's anchor: the board leaves the chain.
	let orphaned = tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_board)).unwrap();
	println!("CP7: parent block(s) {:?} orphaned", orphaned);
	let re = b.ok(&["recheck"]);
	println!("CP7: B's re-check: {}", re["changes"]);
	let p = summary("CP7 rolled back", &b);
	for l in [&counted, &arriving] {
		assert_eq!(place_of(&p, l), "arriving", "a coin not final again arrives: {}", p);
	}
	assert_eq!(p["spendable"], json!({}), "nothing is spendable while its base is out of the chain: {}", p);
	b.refused(&["send", c.ok(&["receive"])["request"].as_str().unwrap(), "--amount", "100000", "--asset", &x.to_string()], "");

	// The board is mined again and certified: the coins are back where they were.
	for _ in 0..10 {
		r.produce().await;
		r.synced().await;
		b.ok(&["sync"]);
		let p = places(&b);
		if place_of(&p, &counted) == "counted" {
			break;
		}
	}
	let p = summary("CP7 final again", &b);
	assert_eq!((place_of(&p, &counted).as_str(), place_of(&p, &arriving).as_str()), ("counted", "arriving"), "{}", p);
	pay(&b, &c, x, 300_000);
	println!("CP7: B paid from its counted coin again");
	for w in [&s, &b, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
