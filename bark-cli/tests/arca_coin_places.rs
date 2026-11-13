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
//! 16. A coin given to a round participation the operator holds back at its
//!    in-flight cap counts against the bond and the instant budget as it
//!    does while live: the wallet's own change nothing, a payment received
//!    its whole value; `coin_places` marks each coin counted (`at_risk`),
//!    and the marks sum to the bond's `out_of_round`.
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

	// 2. Over the limit: arriving. No payment and no trade takes it: each
	// waits for its round (`settle_first`), naming it.
	let big = pay(&s, &b, x, 1_500_000);
	let p = summary("CP1 over", &b);
	assert_eq!(place_of(&p, &big), "arriving", "{}", p);
	let why = pay_refused(&b, &c, x, 1_000_000, "settle_first");
	assert!(why.contains("are arriving"), "{}", why);
	let offer = library(&b, "swap_offer", json!({"give_asset": x, "give": "1000000", "want_asset": y, "want": "1000000"}));
	println!("CP1 over: B offers it in a trade: {:?}", offer);
	assert!(offer.as_ref().is_err_and(|e| e.contains("settle_first") && e.contains("are arriving")), "{:?}", offer);
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
	// Proceeds pay on the chain at once: an offboard is made in a round.
	let addr = a.ok(&["address"]);
	let off = library(&a, "offboard_quote", json!({"asset": y, "amount": "100000", "script": addr["script_pubkey"]}));
	println!("CP5: A quotes paying the proceeds on the chain: {:?}", off.as_ref().map(|v| v["gives"].clone()));
	assert!(off.is_ok(), "{:?}", off);

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

// ---------------------------------------------------------------------------
// 8. The operator runs a refresh of payments arriving past its in-flight cap.
// ---------------------------------------------------------------------------

fn server_state(r: &Running, pid: &str) -> Value {
	let body = json!({"participation_id": pid});
	let resp = minreq::post(format!("{}/v1/participation_status", r.url())).with_header("Content-Type", "application/json")
		.with_body(body.to_string()).send().unwrap();
	serde_json::from_str(resp.as_str().unwrap()).unwrap()
}

fn in_flight(r: &Running, asset: AssetId) -> String {
	let v: Value = serde_json::from_str(minreq::get(format!("{}/v1/info", r.url())).send().unwrap().as_str().unwrap()).unwrap();
	v["assets"].as_array().unwrap().iter().find(|a| a["asset"] == asset.to_string()).map(|a| a["in_flight"].to_string())
		.unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_of_payments_arriving_runs_past_a_full_in_flight_cap() {
	cap_run(true).await;
}

/// Control: B sets no instant limit, so it names nothing arriving: the cap
/// holds B's refresh behind H's, as it holds any refresh.
#[tokio::test(flavor = "multi_thread")]
async fn without_payments_arriving_the_cap_holds_the_later_refresh() {
	cap_run(false).await;
}

async fn cap_run(limit: bool) {
	// The watcher off: the nodes of coins given up do not come back, so what
	// is fronted stays in flight.
	let mut r = Running::start_with(|c, _, _| {
		c.assets[0].in_flight_cap = Some("1500000".into());
		c.watcher.enabled = false;
	}).await;
	let x = r.x;
	post_bond(&mut r, None).await;
	let info: Value = serde_json::from_str(minreq::get(format!("{}/v1/info", r.url())).send().unwrap().as_str().unwrap()).unwrap();
	println!("CP8: info.participations = {}", info["participations"]);
	assert_eq!(info["participations"]["arriving"], true);
	let tag = if limit { "CP8" } else { "CP8c" };
	let (s, b, h) = (Arca::new(&format!("{} S", tag)), Arca::new(&format!("{} B", tag)), Arca::new(&format!("{} H", tag)));
	boarded(&mut r, &s, &[(x, 6_000_000)]).await;
	create(&r, &b);
	create(&r, &h);
	// S's coin in a round: the cap weighs coins resting on a round's batch.
	s.ok(&["participate"]);
	rounds_final(&r).await;
	s.ok(&["sync"]);
	println!("CP8: in flight {} of a cap of 1500000", in_flight(&r, x));
	if limit {
		library(&b, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	}
	let arriving = pay(&s, &b, x, 1_500_000);
	pay(&s, &h, x, 500_000);
	assert_eq!(place_of(&places(&b), &arriving), if limit { "arriving" } else { "counted" });
	// H's ordinary refresh first, B's of a payment arriving after it: the two
	// take 2,000,000 past a cap of 1,500,000, so one waits.
	let hp = h.ok(&["refresh-received"])["participations"][0]["participation"].as_str().unwrap().to_string();
	let bp = b.ok(&["refresh-received"])["participations"][0]["participation"].as_str().unwrap().to_string();
	let (built, errs) = r.server.rounds.run_rounds().await.unwrap();
	assert!(errs.is_empty(), "{:?}", errs);
	let (hs, bs) = (server_state(&r, &hp), server_state(&r, &bp));
	println!("CP8: {} round(s); H's ordinary refresh: {} ({}); B's refresh of a payment arriving: {}", built.len(), hs["state"],
		hs["waiting"], bs["state"]);
	if !limit {
		assert_eq!(bs["state"], "pending", "control: the cap holds the later refresh: {}", bs);
		assert_ne!(hs["state"], "pending", "control: {}", hs);
		for w in [&s, &b, &h] {
			let _ = std::fs::remove_dir_all(&w.dir);
		}
		return;
	}
	assert_eq!(hs["state"], "pending", "the cap holds the ordinary refresh: {}", hs);
	assert!(hs["waiting"].as_str().unwrap_or("").contains("in flight"), "{}", hs);
	assert_ne!(bs["state"], "pending", "the refresh of a payment arriving runs: {}", bs);
	r.produce().await;
	r.bury().await;
	for k in &built {
		r.round_state(&k.tx.txid(), RoundState::Final).await;
	}
	b.ok(&["sync"]);
	let p = summary("CP8 after its round", &b);
	assert!(p["coins"].as_array().unwrap().iter().filter(|k| k["state"] == "live").all(|k| k["place"] == "settled"), "{}", p);
	for w in [&s, &b, &h] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// 9. A wallet cannot name its own coins as arriving, and the allowance is
//    bounded.
// ---------------------------------------------------------------------------

/// The operator's stored participation `pid` names `leaves` as arriving: what
/// it would hold had its wallet sent them (the server checks only that each
/// is an input when it takes the request).
async fn name_arriving(r: &Running, pid: &str, leaves: &[&str]) {
	let (db, conn) = tokio_postgres::connect(&r.db.url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(conn);
	let id: Vec<u8> = unhex(pid);
	let named: Vec<String> = leaves.iter().map(|l| l.to_string()).collect();
	let n = db.execute("UPDATE participation SET arriving = $2 WHERE participation_id = $1", &[&id, &named]).await.unwrap();
	assert_eq!(n, 1, "the participation is stored");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_naming_its_own_change_as_arriving_is_judged_as_any_refresh() {
	let mut r = Running::start_with(|c, _, _| {
		c.assets[0].in_flight_cap = Some("1500000".into());
		c.watcher.enabled = false;
	}).await;
	let x = r.x;
	post_bond(&mut r, None).await;
	let (s, h, liar, c) = (Arca::new("CP9 S"), Arca::new("CP9 H"), Arca::new("CP9 L"), Arca::new("CP9 C"));
	boarded(&mut r, &s, &[(x, 3_000_000)]).await;
	boarded(&mut r, &liar, &[(x, 3_000_000)]).await;
	create(&r, &h);
	create(&r, &c);
	for w in [&s, &liar] {
		w.ok(&["participate"]);
	}
	rounds_final(&r).await;
	for w in [&s, &liar] {
		w.ok(&["sync"]);
	}
	pay(&s, &h, x, 500_000);
	// The liar pays C, and holds its own change out of round.
	pay(&liar, &c, x, 300_000);
	let change = liar.ok(&["coins"]).as_array().unwrap().iter()
		.find(|k| k["state"] == "live" && k["kind"] == "transfer").expect("the liar's change")["leaf_id"].as_str().unwrap().to_string();
	let hp = h.ok(&["refresh-received"])["participations"][0]["participation"].as_str().unwrap().to_string();
	let lp = liar.ok(&["participate", "--leaf", &change])["participations"][0]["participation"].as_str().unwrap().to_string();
	name_arriving(&r, &lp, &[&change]).await;
	let (built, errs) = r.server.rounds.run_rounds().await.unwrap();
	assert!(errs.is_empty(), "{:?}", errs);
	let (hs, ls) = (server_state(&r, &hp), server_state(&r, &lp));
	println!("CP9 lie: {} round(s); H's refresh: {}; the liar's refresh of its own change named as arriving: {} ({})", built.len(),
		hs["state"], ls["state"], ls["waiting"]);
	assert_ne!(hs["state"], "pending", "{}", hs);
	assert_eq!(ls["state"], "pending", "the lie buys no priority: {}", ls);
	assert!(ls["waiting"].as_str().unwrap_or("").contains("in flight"), "{}", ls);
	for w in [&s, &h, &liar, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn payments_arriving_run_past_the_cap_only_within_the_operators_lane() {
	let mut r = Running::start_with(|c, _, _| {
		c.assets[0].in_flight_cap = Some("1500000".into());
		c.assets[0].arriving_lane = Some("1500000".into());
		c.watcher.enabled = false;
	}).await;
	let x = r.x;
	post_bond(&mut r, None).await;
	let info: Value = serde_json::from_str(minreq::get(format!("{}/v1/info", r.url())).send().unwrap().as_str().unwrap()).unwrap();
	let lane = info["assets"].as_array().unwrap().iter().find(|e| e["asset"] == x.to_string()).unwrap()["arriving_lane"].clone();
	println!("CP10: info publishes the lane: {}", lane);
	assert_eq!(lane, "1500000");
	let s = Arca::new("CP10 S");
	boarded(&mut r, &s, &[(x, 8_000_000)]).await;
	s.ok(&["participate"]);
	rounds_final(&r).await;
	s.ok(&["sync"]);
	let ws: Vec<Arca> = (0..3).map(|i| Arca::new(&format!("CP10 B{}", i))).collect();
	let mut pids = vec![];
	for w in &ws {
		create(&r, w);
		library(w, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
		let k = pay(&s, w, x, 1_500_000);
		assert_eq!(place_of(&places(w), &k), "arriving");
	}
	for w in &ws {
		pids.push(w.ok(&["refresh-received"])["participations"][0]["participation"].as_str().unwrap().to_string());
	}
	let (built, errs) = r.server.rounds.run_rounds().await.unwrap();
	assert!(errs.is_empty(), "{:?}", errs);
	let states: Vec<String> = pids.iter().map(|p| server_state(&r, p)["state"].as_str().unwrap().to_string()).collect();
	println!("CP10: {} round(s); three refreshes of 1,500,000 arriving against a cap of 1,500,000: {:?}", built.len(), states);
	assert_eq!(states.iter().filter(|s| *s != "pending").count(), 2, "two run, to the cap and its lane: {:?}", states);
	assert_eq!(states[2], "pending", "the oldest go first: {:?}", states);
	let waiting = pids.iter().map(|p| server_state(&r, p)).find(|v| v["state"] == "pending").unwrap();
	println!("CP10: the third: {}", waiting["waiting"]);
	assert!(waiting["waiting"].as_str().unwrap_or("").contains("in flight"));
	let _ = std::fs::remove_dir_all(&s.dir);
	for w in &ws {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// 11. Review fixes (RV33): a channel, change of a counted coin, a coin posted
//     to its own key, a missing rate.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_channel_counts_its_owners_side_and_is_coming_back_not_spendable() {
	let mut r = Running::start_with(|c, _, _| c.assets[0].channel_capacity = Some("2000000".into())).await;
	let x = r.x;
	post_bond(&mut r, None).await;
	let (a, b) = (Arca::new("CP11 A"), Arca::new("CP11 B"));
	boarded(&mut r, &a, &[(x, 3_000_000)]).await;
	boarded(&mut r, &b, &[(x, 3_000_000)]).await;
	for w in [&a, &b] {
		w.ok(&["channel", "open", "--capacity", "1000000"]);
	}
	rounds_final(&r).await;
	for w in [&a, &b] {
		w.ok(&["sync"]);
	}
	library(&b, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	let live = |w: &Arca| w.ok(&["channel", "list"]).as_array().unwrap().iter().find(|c| c["coin_state"] == "live").unwrap()["leaf_id"]
		.as_str().unwrap().to_string();
	let (la, lb) = (live(&a), live(&b));
	a.ok(&["channel", "pay", &la, &lb, "400000"]);
	b.ok(&["channel", "sync", &lb]);
	let bal = b.ok(&["balance"]);
	let n = |v: &Value| v.as_str().map(|t| t.parse::<u64>().unwrap()).unwrap_or(0);
	let held = n(&bal["held"][x.to_string()]) - n(&bal["sequentia_onchain"][x.to_string()]);
	let p = summary("CP11 B, a channel paid into", &b);
	let c = p["coins"].as_array().unwrap().iter().find(|k| k["leaf_id"] == lb.as_str()).unwrap().clone();
	println!("CP11: B's balance holds {}; the channel coin in coin_places: {}", held, c);
	assert_eq!(c["channel"], true);
	assert_eq!(c["place"], "arriving", "not the wallet's to spend until its close makes it a coin");
	assert_eq!(c["value"].as_str().unwrap().parse::<u64>().unwrap(), held, "its side alone, as the balance counts it");
	assert!(p["spendable"].get(x.to_string()).is_none(), "{}", p);
	for w in [&a, &b] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn change_of_a_counted_coin_stays_counted_and_the_arriving_refresh_gives_up_arriving_coins_alone() {
	let mut r = Running::start().await;
	let x = r.x;
	post_bond(&mut r, None).await;
	let (s, s2, d, c) = (Arca::new("CP12 S"), Arca::new("CP12 S2"), Arca::new("CP12 D"), Arca::new("CP12 C"));
	boarded(&mut r, &s, &[(x, 4_000_000)]).await;
	boarded(&mut r, &s2, &[(x, 4_000_000)]).await;
	create(&r, &d);
	create(&r, &c);
	library(&d, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	let first = pay(&s, &d, x, 600_000);
	let second = pay(&s2, &d, x, 600_000);
	let p = summary("CP12 two received", &d);
	assert_eq!((place_of(&p, &first).as_str(), place_of(&p, &second).as_str()), ("counted", "arriving"));
	pay(&d, &c, x, 100_000);
	let p = summary("CP12 after D pays C from its counted coin", &d);
	let change = p["coins"].as_array().unwrap().iter().find(|k| k["state"] == "live" && k["leaf_id"] != second.as_str())
		.expect("D's change")["leaf_id"].as_str().unwrap().to_string();
	println!("CP12: the change {}… is {}; the older arriving coin is {}", &change[..8], place_of(&p, &change), place_of(&p, &second));
	assert_eq!(place_of(&p, &change), "counted", "the change keeps its parent's place");
	assert_eq!(place_of(&p, &second), "arriving");
	let need = library(&d, "refresh_needed", json!({})).unwrap();
	let only: Vec<Value> = need["reasons"].as_array().unwrap().iter().filter(|r| r["rule"] == "arriving").flat_map(|r| r["coins"].as_array().unwrap().clone()).collect();
	assert_eq!(only, vec![json!(second)], "{}", need);
	let rr = library(&d, "refresh_received", json!({"leaves": only})).unwrap();
	println!("CP12: the refresh of the arriving coin alone gives up {}", rr["refreshed"]);
	assert_eq!(rr["refreshed"], json!([second]), "{}", rr);
	let p = summary("CP12 during the refresh", &d);
	assert_eq!(p["coins"].as_array().unwrap().iter().find(|k| k["leaf_id"] == change.as_str()).unwrap()["state"], "live",
		"the counted change stays spendable");
	for w in [&s, &s2, &d, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn a_coin_posted_to_its_own_key_named_arriving_gets_no_lane() {
	let mut r = Running::start_with(|c, _, _| {
		c.assets[0].in_flight_cap = Some("1500000".into());
		c.assets[0].arriving_lane = Some("1500000".into());
		c.watcher.enabled = false;
	}).await;
	let x = r.x;
	post_bond(&mut r, None).await;
	let (s, h, liar, c) = (Arca::new("CP13 S"), Arca::new("CP13 H"), Arca::new("CP13 L"), Arca::new("CP13 C"));
	boarded(&mut r, &s, &[(x, 3_000_000)]).await;
	boarded(&mut r, &liar, &[(x, 3_000_000)]).await;
	create(&r, &h);
	create(&r, &c);
	for w in [&s, &liar] {
		w.ok(&["participate"]);
	}
	rounds_final(&r).await;
	for w in [&s, &liar] {
		w.ok(&["sync"]);
	}
	pay(&s, &h, x, 500_000);
	pay(&liar, &c, x, 1_400_000);
	let change = liar.ok(&["coins"]).as_array().unwrap().iter()
		.find(|k| k["state"] == "live" && k["kind"] == "transfer").expect("the liar's change")["leaf_id"].as_str().unwrap().to_string();
	// What the operator holds for an output that named no mailbox: its leaf's own key.
	let (db, conn) = tokio_postgres::connect(&r.db.url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(conn);
	let n = db.execute("UPDATE transfer_output o SET mailbox_key = l.owner_key FROM leaf l WHERE l.leaf_id = o.leaf_id AND o.leaf_id = $1",
		&[&unhex(&change)]).await.unwrap();
	assert_eq!(n, 1);
	let hp = h.ok(&["refresh-received"])["participations"][0]["participation"].as_str().unwrap().to_string();
	rounds_final(&r).await;
	println!("CP13: H's refresh {}; in flight {}", server_state(&r, &hp)["state"], in_flight(&r, x));
	let lp = liar.ok(&["participate", "--leaf", &change])["participations"][0]["participation"].as_str().unwrap().to_string();
	name_arriving(&r, &lp, &[&change]).await;
	let (_, errs) = r.server.rounds.run_rounds().await.unwrap();
	assert!(errs.is_empty(), "{:?}", errs);
	let ls = server_state(&r, &lp);
	println!("CP13: the liar's change posted to its own key, named arriving: {} ({})", ls["state"], ls["waiting"]);
	assert_eq!(ls["state"], "pending", "{}", ls);
	assert!(ls["waiting"].as_str().unwrap_or("").contains("in flight"), "{}", ls);
	for w in [&s, &h, &liar, &c] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_rate_never_stops_receiving_the_coin_arrives() {
	let mut r = Running::start().await;
	let (x, y) = (r.x, r.y);
	post_bond(&mut r, None).await;
	let rates: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
	assert!(rates.get(y.to_string()).is_none(), "the node gives Y no rate: {}", rates);
	let (s, d) = (Arca::new("CP14 S"), Arca::new("CP14 D"));
	boarded(&mut r, &s, &[(y, 3_000_000)]).await;
	create(&r, &d);
	library(&d, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	let k = pay(&s, &d, y, 100_000);
	// A second payment while D holds unvalued coins out of round: refused
	// before, as the bond could not be weighed against them.
	let k2 = pay(&s, &d, y, 50_000);
	let p = summary("CP14 Y unpriced", &d);
	assert_eq!((place_of(&p, &k).as_str(), place_of(&p, &k2).as_str()), ("arriving", "arriving"), "a coin the wallet cannot value arrives");
	let need = library(&d, "refresh_needed", json!({})).unwrap();
	assert_eq!(need["reasons"][0]["rule"], "arriving", "{}", need);
	for w in [&s, &d] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// 15. What a trade buys with counted money keeps the place of what it gave
//     (RV35-4).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn proceeds_of_a_counted_coin_keep_its_place_beside_an_older_arriving_payment() {
	let mut r = Running::start_with(watcher_off()).await;
	let (x, y) = (r.x, r.y);
	let rx = rate(&r, x) as u64;
	price(&r, y, rx);
	post_bond(&mut r, None).await;
	let (a, c, s, s2) = (Arca::new("CP15 A"), Arca::new("CP15 C"), Arca::new("CP15 S"), Arca::new("CP15 S2"));
	create(&r, &a);
	boarded(&mut r, &c, &[(y, 2_000_000)]).await;
	boarded(&mut r, &s, &[(x, 3_000_000)]).await;
	boarded(&mut r, &s2, &[(x, 3_000_000)]).await;
	library(&a, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	let first = pay(&s, &a, x, 600_000);
	let second = pay(&s2, &a, x, 600_000);
	let p = summary("CP15 A holds", &a);
	assert_eq!((place_of(&p, &first).as_str(), place_of(&p, &second).as_str()), ("counted", "arriving"), "{}", p);
	a.ok(&["require-checkpoint-exit", "on"]);
	// C pays twice what A gives, at the node's rates.
	let offer = a.ok(&["swap", "offer", "--give-asset", &x.to_string(), "--give", "300000", "--want-asset", &y.to_string(), "--want", "600000"]);
	let acc = c.ok(&["swap", "accept", offer["offer"].as_str().unwrap()]);
	a.ok(&["swap", "complete", acc["accept"].as_str().unwrap()]);
	a.ok(&["sync"]);
	let got = newest_of(&a, y, &[]);
	let p = summary("CP15 after the trade", &a);
	println!("CP15: the Y bought {}… is {}; the older payment {}… is {}; spendable {}", &got[..8], place_of(&p, &got), &second[..8],
		place_of(&p, &second), p["spendable"]);
	assert_eq!(place_of(&p, &got), "counted", "it takes the place of the counted X it was bought with");
	assert_eq!(place_of(&p, &second), "arriving", "a later payment does not jump ahead of what the wallet already had");
	assert_eq!(p["spendable"][y.to_string()], "600000", "{}", p);
	// The Y counts what the X given for it was worth, not what it is worth:
	// with the change of the shaping, the wallet counts no more than the
	// counted payment it started from.
	let counted: u128 = p["instant_limit"]["counted"].as_str().unwrap().parse().unwrap();
	println!("CP15: counted {} (the first payment was worth {}; the Y is worth {})", counted, worth(&r, x, 600_000), worth(&r, y, 600_000));
	assert!(counted <= worth(&r, x, 600_000), "the trade's gain counts nothing: {}", counted);
	// Its place lets it be traded on; what stops it here is the protocol's
	// depth limit (a board, the shaped give coin and the trade), which a
	// refresh clears, never its place.
	let why = a.refused(&["swap", "offer", "--give-asset", &y.to_string(), "--give", "200000", "--want-asset", &x.to_string(), "--want",
		"200000"], "depth limit");
	assert!(!why.contains("arriving"), "{}", why);
	let after = summary("CP15 after the refused offer", &a);
	assert_eq!(place_of(&after, &got), "counted", "the refused offer moved nothing: {}", after);
	// Paying itself out of the Y (here, to send a part of it on) does not
	// make the trade's gain count.
	pay(&a, &s, y, 100_000);
	let after = summary("CP15 after A pays out of the Y", &a);
	let counted_after: u128 = after["instant_limit"]["counted"].as_str().unwrap().parse().unwrap();
	assert!(counted_after <= counted, "an own payment out of the Y counts no more than the Y did: {} > {}", counted_after, counted);
	// A restore from the phrase alone keeps no caps: it counts again from
	// the operator's record, oldest first, and never past the limit.
	let d2 = Arca::new("CP15 A2");
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap();
	d2.ok(&["create", "--server", &r.url(), "--node-url", &r.node_url(), "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1", "--mnemonic", mnemonic.trim()]);
	library(&d2, "instant_limit", json!({"value": worth(&r, x, 1_000_000).to_string()})).unwrap();
	d2.ok(&["sync"]);
	let p2 = summary("CP15 restored", &d2);
	let counted2: u128 = p2["instant_limit"]["counted"].as_str().unwrap().parse().unwrap();
	println!("CP15 restored: counted {}; the Y is {}, the later payment {}", counted2, place_of(&p2, &got), place_of(&p2, &second));
	assert!(counted2 <= worth(&r, x, 1_000_000), "a restore counts within the limit: {}", counted2);
	for w in [&a, &c, &s, &s2, &d2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// 13. What a trade paid for counted coins, while the node cannot value it or
//     the coins given, arrives, and the room the coins given held stays taken
//     until a read with rates places it; no cap is written from a missing
//     rate (arca #777).
// ---------------------------------------------------------------------------

/// A value of the wallet's store `meta` table, read from the SQLite file.
fn meta_of(w: &Arca, key: &str) -> String {
	let f = std::fs::read_dir(&w.dir).unwrap().filter_map(|e| e.ok()).map(|e| e.path())
		.find(|p| p.extension().is_some_and(|e| e == "sqlite")).expect("the wallet's store");
	let out = std::process::Command::new("python3").args(["-I", "-c",
		"import sqlite3,sys; r=sqlite3.connect(sys.argv[1]).execute('SELECT value FROM meta WHERE key=?',(sys.argv[2],)).fetchone(); print(r[0] if r else '')",
		f.to_str().unwrap(), key]).output().unwrap();
	String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// What the live coins placed `counted` are worth at the node's rates now.
fn counted_worth(r: &Running, p: &Value) -> u128 {
	p["coins"].as_array().unwrap().iter().filter(|c| c["place"] == "counted" && c["state"] == "live")
		.map(|c| {
			let a: AssetId = c["asset"].as_str().unwrap().parse().unwrap();
			worth(r, a, c["value"].as_str().unwrap().parse().unwrap())
		}).sum()
}

/// A holds 600,000 X counted and trades 300,000 of it, with the exit on
/// every checkpoint, for 300,000 Y from C: answers the Y's leaf id.
async fn trade_counted_x_for_y(r: &mut Running, tag: &str) -> (Arca, Arca, Arca, Arca, String) {
	let (x, y) = (r.x, r.y);
	post_bond(r, None).await;
	let (a, c, s, s2) = (Arca::new(&format!("{} A", tag)), Arca::new(&format!("{} C", tag)), Arca::new(&format!("{} S", tag)),
		Arca::new(&format!("{} S2", tag)));
	create(r, &a);
	boarded(r, &c, &[(y, 2_000_000)]).await;
	boarded(r, &s, &[(x, 3_000_000)]).await;
	boarded(r, &s2, &[(x, 3_000_000)]).await;
	library(&a, "instant_limit", json!({"value": worth(r, x, 1_000_000).to_string()})).unwrap();
	let first = pay(&s, &a, x, 600_000);
	assert_eq!(place_of(&summary(&format!("{} A holds", tag), &a), &first), "counted");
	a.ok(&["require-checkpoint-exit", "on"]);
	let offer = a.ok(&["swap", "offer", "--give-asset", &x.to_string(), "--give", "300000", "--want-asset", &y.to_string(), "--want", "300000"]);
	let acc = c.ok(&["swap", "accept", offer["offer"].as_str().unwrap()]);
	a.ok(&["swap", "complete", acc["accept"].as_str().unwrap()]);
	a.ok(&["sync"]);
	let got = newest_of(&a, y, &[]);
	(a, c, s, s2, got)
}

#[tokio::test(flavor = "multi_thread")]
async fn proceeds_in_an_asset_the_node_does_not_value_arrive_and_keep_the_room() {
	let mut r = Running::start_with(watcher_off()).await;
	let (x, y) = (r.x, r.y);
	let limit = worth(&r, x, 1_000_000);
	let (a, c, s, s2, got) = trade_counted_x_for_y(&mut r, "CP16").await;
	let p = summary("CP16 after the trade (Y unpriced)", &a);
	let caps = meta_of(&a, "instant_counted_caps");
	println!("CP16: Y {}… is {}; caps {}; counted {}", &got[..8], place_of(&p, &got), caps, p["instant_limit"]["counted"]);
	assert_eq!(place_of(&p, &got), "arriving", "proceeds the node cannot value are not counted");
	assert!(!caps.contains(&got), "no cap is written for them: {}", caps);
	// The room the 300,000 X given held stays taken: 300,000 X of change and
	// 300,000 reserved leave no room for 700,000 more.
	let third = pay(&s2, &a, x, 700_000);
	let p = summary("CP16 after a further 700,000 X", &a);
	println!("CP16: the further payment {}… is {}", &third[..8], place_of(&p, &third));
	assert_eq!(place_of(&p, &third), "arriving", "the room the coins given held stays taken");
	// Y now priced as X: the trade's Y takes the coins given's place.
	price(&r, y, rate(&r, x) as u64);
	let p = summary("CP16 Y priced as X", &a);
	let held = counted_worth(&r, &p);
	println!("CP16: limit {}; counted reported {}; counted coins worth {}; caps {}; Y {}; further {}", limit, p["instant_limit"]["counted"],
		held, meta_of(&a, "instant_counted_caps"), place_of(&p, &got), place_of(&p, &third));
	assert_eq!(place_of(&p, &got), "counted", "once valued, the trade's Y takes the place of the X given");
	assert_eq!(place_of(&p, &third), "arriving");
	assert!(held <= limit, "coins counted at once are worth {} > the limit {}", held, limit);
	for w in [&a, &c, &s, &s2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn proceeds_placed_while_no_rate_is_read_wait_for_one_and_no_cap_of_zero_is_kept() {
	let mut r = Running::start_with(watcher_off()).await;
	let (x, y) = (r.x, r.y);
	price(&r, y, rate(&r, x) as u64);
	let limit = worth(&r, x, 1_000_000);
	let saved: Value = r.rt.client().call("getfeeexchangerates", &[]).unwrap();
	// The trade is completed and first read with no rate at the node.
	let (a, c, s, s2, got) = {
		post_bond(&mut r, None).await;
		let (a, c, s, s2) = (Arca::new("CP17 A"), Arca::new("CP17 C"), Arca::new("CP17 S"), Arca::new("CP17 S2"));
		create(&r, &a);
		boarded(&mut r, &c, &[(y, 2_000_000)]).await;
		boarded(&mut r, &s, &[(x, 3_000_000)]).await;
		boarded(&mut r, &s2, &[(x, 3_000_000)]).await;
		library(&a, "instant_limit", json!({"value": limit.to_string()})).unwrap();
		let first = pay(&s, &a, x, 600_000);
		assert_eq!(place_of(&summary("CP17 A holds", &a), &first), "counted");
		a.ok(&["require-checkpoint-exit", "on"]);
		let offer = a.ok(&["swap", "offer", "--give-asset", &x.to_string(), "--give", "300000", "--want-asset", &y.to_string(), "--want", "300000"]);
		let acc = c.ok(&["swap", "accept", offer["offer"].as_str().unwrap()]);
		a.ok(&["swap", "complete", acc["accept"].as_str().unwrap()]);
		r.rt.client().call::<Value>("setfeeexchangerates", &[json!({})]).unwrap();
		let got = newest_of(&a, y, &[]);
		(a, c, s, s2, got)
	};
	let p = summary("CP17 placed without rates", &a);
	let caps = meta_of(&a, "instant_counted_caps");
	println!("CP17: Y {}… is {}; caps {}", &got[..8], place_of(&p, &got), caps);
	assert_eq!(place_of(&p, &got), "arriving");
	assert!(!caps.contains(&got), "no cap is written from missing rates: {}", caps);
	r.rt.client().call::<Value>("setfeeexchangerates", &[saved]).unwrap();
	let p = summary("CP17 rates back", &a);
	println!("CP17: Y is {}; caps {}", place_of(&p, &got), meta_of(&a, "instant_counted_caps"));
	assert_eq!(place_of(&p, &got), "counted", "the next read with rates gives the Y the place of the X given");
	let third = pay(&s2, &a, x, 700_000);
	let p = summary("CP17 a further 700,000 X", &a);
	let held = counted_worth(&r, &p);
	println!("CP17: further payment {}; limit {}; counted reported {}; counted coins worth {}; caps {}", place_of(&p, &third), limit,
		p["instant_limit"]["counted"], held, meta_of(&a, "instant_counted_caps"));
	assert_eq!(place_of(&p, &third), "arriving");
	assert!(held <= limit, "coins counted at once are worth {} > the limit {}", held, limit);
	for w in [&a, &c, &s, &s2] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}

// ---------------------------------------------------------------------------
// 16. A coin given to a round is judged by its own lineage.
// ---------------------------------------------------------------------------

/// The bond answer's `out_of_round` and the coins `coin_places` marks
/// `at_risk`, each by asset: the two must agree.
fn risk_views(w: &Arca) -> (std::collections::BTreeMap<String, u64>, std::collections::BTreeMap<String, u64>) {
	let bond = library(w, "bond", json!({})).unwrap();
	let held = bond["out_of_round"].as_array().unwrap().iter()
		.map(|e| (e["asset"].as_str().unwrap().to_string(), e["value"].as_str().unwrap().parse::<u64>().unwrap())).collect();
	let mut marked: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
	for c in places(w)["coins"].as_array().unwrap() {
		assert!(c["at_risk"].is_boolean(), "coin_places names at_risk for every coin: {}", c);
		if c["at_risk"] == true {
			*marked.entry(c["asset"].as_str().unwrap().to_string()).or_default() += c["value"].as_str().unwrap().parse::<u64>().unwrap();
		}
	}
	(held, marked)
}

/// `from` pays `to` `amount` of `asset` out of round on a request naming
/// both, so the payee's bond and budget weigh it as it asks; the coin `to`
/// holds.
fn pay_named(from: &Arca, to: &Arca, asset: AssetId, amount: u64) -> String {
	let (a, v) = (asset.to_string(), amount.to_string());
	let req = to.ok(&["receive", "--asset", &a, "--amount", &v])["request"].as_str().unwrap().to_string();
	from.ok(&["send", &req, "--amount", &v, "--asset", &a]);
	let mb = to.ok(&["mailbox"]);
	mb["accepted"].as_array().unwrap().iter().find(|c| c["value"].as_str() == Some(&v))
		.and_then(|c| c["leaf_id"].as_str()).expect("the payee holds the coin").to_string()
}

fn coin_line(w: &Arca, leaf: &str) -> Value {
	places(w)["coins"].as_array().unwrap().iter().find(|c| c["leaf_id"] == leaf).cloned()
		.unwrap_or_else(|| panic!("coin_places names {}", leaf))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_coin_given_to_a_round_held_at_the_cap_counts_as_its_lineage_does() {
	// The watcher off: the nodes of coins given up do not come back, so what
	// is fronted stays in flight and the cap holds the next refresh.
	let mut r = Running::start_with(|c, _, _| {
		c.assets[0].in_flight_cap = Some("1500000".into());
		c.watcher.enabled = false;
	}).await;
	let x = r.x;
	post_bond(&mut r, None).await;
	let (s, a, c, h) = (Arca::new("CP16 S"), Arca::new("CP16 A"), Arca::new("CP16 C"), Arca::new("CP16 H"));
	boarded(&mut r, &s, &[(x, 6_000_000)]).await;
	boarded(&mut r, &a, &[(x, 3_000_000)]).await;
	create(&r, &c);
	create(&r, &h);
	for w in [&s, &a] {
		w.ok(&["participate"]);
	}
	rounds_final(&r).await;
	for w in [&s, &a] {
		w.ok(&["sync"]);
	}
	println!("CP16: in flight {} of a cap of 1500000", in_flight(&r, x));
	// A pays C out of its round's coin and holds its own change: of its own
	// lineage, kind transfer.
	pay(&a, &c, x, 300_000);
	let change = a.ok(&["coins"]).as_array().unwrap().iter()
		.find(|k| k["state"] == "live" && k["kind"] == "transfer").expect("A's change")["leaf_id"].as_str().unwrap().to_string();
	let line = coin_line(&a, &change);
	println!("CP16: A's change while live: {}", line);
	assert_eq!((line["lineage"].as_str(), line["at_risk"].as_bool()), (Some("own"), Some(false)), "{}", line);
	let change_value: u64 = line["value"].as_str().unwrap().parse().unwrap();
	// An instant budget below the change: a fiftieth of the bond, worth
	// 1,000,000 X.
	library(&a, "instant_budget", json!({"share": "0.02"})).unwrap();
	let budget = library(&a, "bond", json!({})).unwrap()["instant_budget"].clone();
	println!("CP16: A's budget {}", budget);
	assert_eq!(budget["value"], worth(&r, x, 1_000_000).to_string(), "{}", budget);
	assert!(change_value > 1_000_000, "the change is past the budget: {}", change_value);

	// H's refresh of a payment from S goes first and puts value in flight;
	// A gives its change to a refresh after it, which the cap holds back, as
	// the testnet's operator held the maker's.
	pay(&s, &h, x, 500_000);
	let hp = h.ok(&["refresh-received"])["participations"][0]["participation"].as_str().unwrap().to_string();
	let ap = a.ok(&["participate", "--leaf", &change])["participations"][0]["participation"].as_str().unwrap().to_string();
	let (built, errs) = r.server.rounds.run_rounds().await.unwrap();
	assert!(errs.is_empty(), "{:?}", errs);
	let (hs, st) = (server_state(&r, &hp), server_state(&r, &ap));
	println!("CP16: {} round(s) built; H's refresh: {}; A's refresh of its own change: {} ({})", built.len(), hs["state"], st["state"],
		st["waiting"]);
	assert_ne!(hs["state"], "pending", "{}", hs);
	assert_eq!(st["state"], "pending", "the cap holds the refresh: {}", st);
	assert!(st["waiting"].as_str().unwrap_or("").contains("in flight"), "{}", st);
	let line = coin_line(&a, &change);
	println!("CP16: A's change given to the pending refresh: {}", line);
	assert_eq!((line["state"].as_str(), line["lineage"].as_str()), (Some("given"), Some("own")), "{}", line);
	assert_eq!(line["at_risk"], false, "an own coin given to a round is at risk to nobody: {}", line);
	let (held, marked) = risk_views(&a);
	println!("CP16: out_of_round {:?}; coin_places at_risk {:?}", held, marked);
	assert!(held.is_empty(), "nothing of A's counts out of round: {:?}", held);
	assert_eq!(held, marked);

	// A payment that fits the budget without the change is taken.
	let got = pay_named(&s, &a, x, 500_000);
	let line = coin_line(&a, &got);
	println!("CP16: S's payment to A, taken beside the pending refresh: {}", line);
	assert_eq!((line["lineage"].as_str(), line["at_risk"].as_bool()), (Some("received"), Some(true)), "{}", line);
	let (held, marked) = risk_views(&a);
	assert_eq!(held.get(&x.to_string()).copied(), Some(500_000), "{:?}", held);
	assert_eq!(held, marked);

	// The payment received, given to a refresh that waits too (no round is
	// built for it): counted at its whole value, as before.
	let rp = a.ok(&["participate", "--leaf", &got])["participations"][0]["participation"].as_str().unwrap().to_string();
	let st = server_state(&r, &rp);
	println!("CP16: A's refresh of the payment received: {} ({})", st["state"], st["waiting"]);
	assert_eq!(st["state"], "pending", "{}", st);
	let line = coin_line(&a, &got);
	println!("CP16: the payment received, given to the pending refresh: {}", line);
	assert_eq!((line["state"].as_str(), line["at_risk"].as_bool()), (Some("given"), Some(true)), "{}", line);
	let (held, marked) = risk_views(&a);
	println!("CP16: out_of_round {:?}; coin_places at_risk {:?}", held, marked);
	assert_eq!(held.get(&x.to_string()).copied(), Some(500_000), "{:?}", held);
	assert_eq!(held, marked);
	// 500,000 counted: 600,000 more passes the budget, 400,000 fits.
	let why = a.refused(&["receive", "--asset", &x.to_string(), "--amount", "600000"], "past its instant budget");
	println!("CP16: 600,000 more refused: {}", why);
	pay_named(&s, &a, x, 400_000);
	let (held, marked) = risk_views(&a);
	assert_eq!(held.get(&x.to_string()).copied(), Some(900_000), "{:?}", held);
	assert_eq!(held, marked);
	for w in [&s, &a, &c, &h] {
		let _ = std::fs::remove_dir_all(&w.dir);
	}
}
