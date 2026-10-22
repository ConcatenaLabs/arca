//! The supervised profile on a whole server: an asset Z issued under the
//! supervision descriptor (with the pause capability) on an anchored
//! proof-of-stake regtest chain, served under the profile because the node
//! lists it; boarded and refreshed into a supervised batch, every leaf
//! `landing-1`; paid out of round between two holders; a targeted freeze of
//! one holder's landing and a pause of the asset, each mirrored by the
//! operator; every path refused for the frozen holder with `frozen`
//! (transfer, swap, refresh, offboard, take, resting-order fill,
//! distribution, plan, Lightning payment), and by the signer on its own
//! reading; a lifting taken only once final, a freeze no request met while it
//! lasted included; a participation taken before a freeze voided when its
//! round is built.

mod common;

use std::str::FromStr;

use elements::encode::{deserialize, serialize};
use elements::hashes::{hash160, Hash};
use elements::hex::FromHex;
use elements::secp256k1_zkp::{Keypair, XOnlyPublicKey};
use elements::{AssetId, OutPoint, Script, Transaction, TxIn};
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::{BoardRecord, CoinRecord, Landing, LandingTerms, LeafId, NewLeaf, Template, ValidCoin};
use common::client::{
	auths_json, exit_delay, forfeit_sig, hex, participation_body, random32, resolve, take_body, transfer_body, try_rebuild, want_landing,
	want_leaf, Held,
};
use common::flow::{forfeit_for, held_by};
use common::keys::{keypair, xonly};
use common::node::{self, op_true};
use common::rounds::{created, round_final, status, validate_new_leaf};
use common::running::{Running, MIN_LEAF};
use server::server::{AssetSection, SupervisedSection};
use server::signer::{SignerClient, SignerError};

const VALUE: u64 = 1_000_000;

/// The issuer's two supervision keys.
struct Issuer {
	z: AssetId,
	op: Keypair,
}

fn tx_of(hex: &str) -> Transaction {
	deserialize(&Vec::<u8>::from_hex(hex).unwrap()).unwrap()
}

/// The node's address for `spk`.
fn address(r: &Running, spk: &Script) -> String {
	let d: Value = r.rt.client().call("decodescript", &[json!(hex(spk.as_bytes()))]).unwrap();
	d["address"].as_str().or_else(|| d["segwit"]["address"].as_str()).unwrap().to_string()
}

/// Issues Z supervised, with the pause capability, 10^10 atoms of it and its
/// reissuance token into the purse.
fn issue_supervised(r: &mut Running) -> Issuer {
	let op = keypair("Z operational");
	let rec = keypair("Z recovery");
	let coin = r.purse.take_coin(r.purse.policy);
	let tx = node::spend_op_true(&coin, vec![], 20_000);
	let to = address(r, &Script::new_v0_wpkh(&elements::WPubkeyHash::from_byte_array([1; 20])));
	let issued: Value = r.rt.client().call("rawissueasset", &[json!(hex(&serialize(&tx))), json!([{
		"asset_amount": 100, "asset_address": to, "token_amount": 1, "token_address": to, "blind": false,
		"supervision": {"operationalkey": hex(&xonly(&op).serialize()), "recoverykey": hex(&xonly(&rec).serialize()), "pause": true},
	}])]).unwrap();
	let mut tx = tx_of(issued[0]["hex"].as_str().unwrap());
	let z = AssetId::from_str(issued[0]["asset"].as_str().unwrap()).unwrap();
	// The issued coins to the purse's OP_TRUE: the declaration binds the
	// issuance, not where its outputs pay.
	for o in tx.output.iter_mut() {
		if o.script_pubkey == Script::new_v0_wpkh(&elements::WPubkeyHash::from_byte_array([1; 20])) {
			o.script_pubkey = op_true();
		}
	}
	let txid = r.rt.client().send_raw_transaction(&tx).unwrap();
	r.rt.produce_block().unwrap();
	for (j, o) in tx.output.iter().enumerate() {
		if o.script_pubkey == op_true() && !o.is_fee() {
			r.purse.put((OutPoint::new(txid, j as u32), o.clone()));
		}
	}
	let listed: Value = r.rt.client().call("getsupervisedassets", &[]).unwrap();
	assert!(listed.as_array().unwrap().iter().any(|a| a["asset"] == json!(z.to_string()) && a["pauseallowed"] == json!(true)));
	node::list_fee_asset(&r.rt, z, 100_000_000);
	println!("Z {} issued under the supervision descriptor, pause allowed; listed for fees at 1:1", z);
	Issuer { z, op }
}

impl Issuer {
	/// A record of `kind` (freeze naming `target`, or pause), signed by the
	/// operational key and mined: its outpoint and target hash.
	fn record(&self, r: &mut Running, kind: &str, target: Option<&Script>) -> (OutPoint, String) {
		let coin = r.purse.take_coin(r.purse.policy);
		let t = target.map(|s| json!(hex(s.as_bytes()))).unwrap_or(Value::Null);
		let h: Value = r.rt.client().call("getsupervisionrecordhash", &[json!(kind), json!(self.z.to_string()), t.clone(), Value::Null,
			json!(coin.0.txid.to_string()), json!(coin.0.vout)]).unwrap();
		let digest: [u8; 32] = Vec::<u8>::from_hex(h["sighash"].as_str().unwrap()).unwrap().try_into().unwrap();
		let sig = sign_digest(&self.op, &digest, &[0; 32]);
		let built: Value = r.rt.client().call("buildsupervisionrecord", &[json!(kind), json!(self.z.to_string()), t, Value::Null,
			json!(hex(sig.as_ref()))]).unwrap();
		let tx = node::spend_op_true(&coin, vec![], 20_000);
		let raw: Value = r.rt.client().call("addsupervisionrecordoutput", &[json!(hex(&serialize(&tx))), built["script"].clone(),
			json!(self.z.to_string())]).unwrap();
		let tx = tx_of(raw.as_str().unwrap());
		let txid = r.rt.client().send_raw_transaction(&tx).unwrap();
		r.rt.produce_block().unwrap();
		let script = Vec::<u8>::from_hex(built["script"].as_str().unwrap()).unwrap();
		let mut at = None;
		for (j, o) in tx.output.iter().enumerate() {
			if o.script_pubkey.as_bytes() == &script[..] {
				at = Some(OutPoint::new(txid, j as u32));
			} else if o.script_pubkey == op_true() {
				r.purse.put((OutPoint::new(txid, j as u32), o.clone()));
			}
		}
		(at.expect("the record's output"), built["targethash"].as_str().unwrap().to_string())
	}

	/// Spends the record at `at`, lifting what it froze, and mines it.
	fn lift(&self, r: &mut Running, at: OutPoint, target: &str) {
		let h: Value = r.rt.client().call("getsupervisionunfreezehash", &[json!(at.txid.to_string()), json!(at.vout),
			json!(self.z.to_string()), json!(target)]).unwrap();
		let digest: [u8; 32] = Vec::<u8>::from_hex(h.as_str().unwrap()).unwrap().try_into().unwrap();
		let sig = sign_digest(&self.op, &digest, &[0; 32]);
		let coin = r.purse.take_coin(r.purse.policy);
		let record_tx = r.rt.client().raw_transaction(&at.txid).unwrap();
		let mut tx = node::spend_op_true(&coin, vec![], 20_000);
		tx.input.insert(0, TxIn { previous_output: at, ..Default::default() });
		let _ = &record_tx;
		let raw: Value = r.rt.client().call("setsupervisionunfreezesig", &[json!(hex(&serialize(&tx))), json!(0), json!(hex(sig.as_ref()))])
			.unwrap();
		let tx = tx_of(raw.as_str().unwrap());
		let txid = r.rt.client().send_raw_transaction(&tx).unwrap();
		r.rt.produce_block().unwrap();
		for (j, o) in tx.output.iter().enumerate() {
			if o.script_pubkey == op_true() {
				r.purse.put((OutPoint::new(txid, j as u32), o.clone()));
			}
		}
	}

	fn status(&self, r: &Running, spk: &Script) -> Value {
		r.rt.client().call("isassetfrozen", &[json!(self.z.to_string()), json!(hex(spk.as_bytes()))]).unwrap()
	}
}

/// A holder: its leaf keys come and go, its landing key stays.
struct Holder {
	landing_key: Keypair,
}

impl Holder {
	fn new(name: &'static str) -> Holder {
		Holder { landing_key: keypair(&format!("{} landing", name)) }
	}

	fn program(&self) -> [u8; 20] {
		hash160::Hash::hash(&self.landing_key.public_key().serialize()).to_byte_array()
	}

	fn landing(&self, allowance: u64) -> Landing {
		Landing { program: self.program(), allowance }
	}

	fn script(&self) -> Script {
		self.landing(0).script_pubkey()
	}
}

/// The refusal `answer` gives, asserting its code, printed.
fn refused(what: &str, answer: common::client::Answer, code: &str) -> String {
	let (c, m) = answer.refusal();
	println!("REFUSED {:<60} {}: {}", what, c, m);
	assert_eq!(c, code, "{}: {}", what, m);
	m
}

/// A coin a holder holds, with the transactions its bases came from.
struct Coin {
	held: Held,
	bases: Vec<Transaction>,
}

impl Coin {
	fn valid(&self, r: &Running) -> ValidCoin {
		resolve(&self.held, &self.bases, &r.policy())
	}
}

/// A board of `value` of Z for `owner`, converting into a landing-1 leaf at
/// `landing` (none: a plain board, which the profile refuses).
fn board_z(r: &mut Running, z: AssetId, owner: &Keypair, value: u64, landing: Option<Landing>) -> (BoardRecord, Transaction, common::client::Answer) {
	let nonce = r.http.operator_nonce();
	let mut record = common::client::board_record(owner, nonce, z, value, r.chain, r.s.x_only_public_key().0);
	record.landing = landing;
	let coins = vec![r.purse.take_coin(z), r.purse.take_coin(r.x)];
	let tx = record.tx(&coins, r.x, 2_000, &op_true()).unwrap().tx;
	for (j, o) in tx.output.iter().enumerate().skip(1) {
		if !o.is_fee() {
			r.purse.put((OutPoint::new(tx.txid(), j as u32), o.clone()));
		}
	}
	r.rt.client().send_raw_transaction(&tx).unwrap();
	let answer = r.http.register_board(&record, &tx);
	(record, tx, answer)
}

/// A new leaf of Z for `key`, landing at `landing`, holding `value`.
fn landing_leaf(key: &Keypair, z: AssetId, value: u64, landing: &Landing) -> NewLeaf {
	NewLeaf {
		owner: xonly(key), owner_nonce: random32(), creator_nonce: random32(), exit_delay: exit_delay(), htlc: None,
		landing: Some(landing.terms(z, value).unwrap()), v2: false,
	}
}

/// Refreshes `coin` into a leaf of `key` landing at `landing`: one
/// participation, its round, the forfeit handed over. The new coin.
async fn refresh_landing(r: &mut Running, coin: &Coin, key: &Keypair, landing: Landing) -> (Coin, Transaction) {
	let v = coin.valid(r);
	let (w, nonce) = want_landing(key, v.asset, v.value, landing);
	let (body, id) = participation_body(&[&coin.held], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(r, &built.tx.txid()).await;
	let st = status(r, &id);
	let (new_valid, record, round) = validate_new_leaf(r, &id, 0, key, &nonce);
	assert_eq!(record.template, Template::Landing1);
	assert_eq!(record.landing, Some(landing));
	// The whole batch, as anyone reads it from the published tree: every
	// leaf landing-1; and every output of its round explicit.
	let published = r.http.post("tree", &json!({"txid": round.txid().to_string(), "vout": st["outputs"][0]["batch_vout"]})).ok();
	let tree = try_rebuild(&published).unwrap();
	assert!(tree.leaves().iter().all(|l| l.spec.template == Template::Landing1 && l.spec.landing.is_some()));
	for l in published["leaves"].as_array().unwrap() {
		assert_eq!(l["template"], "landing-1", "{}", l);
		assert!(l["landing"]["program"].is_string(), "{}", l);
	}
	arca_covenant::landing::check_explicit(&round).unwrap();
	let f = forfeit_for(&v, &new_valid, &round, &st);
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&id),
		"forfeits": [{"leaf_id": coin.held.id.to_string(), "signature": forfeit_sig(&f, &coin.held.key)}],
		"leaves": [auths_json(&new_valid, key, created(&record))]})).ok();
	assert_eq!(done["state"], "released", "{}", done);
	(Coin { held: held_by(r, key, nonce, new_valid.leaf_id), bases: vec![round.clone()] }, round)
}

/// A transfer of `coins` into `outputs`, as its owners sign it.
fn transfer(r: &Running, coins: &[&Coin], outputs: &[(AssetId, u64, NewLeaf)], margin: u64) -> common::client::Answer {
	let parts: Vec<(&Held, ValidCoin, u64)> = coins.iter().map(|c| {
		let v = c.valid(r);
		let keep = v.value - margin;
		(&c.held, v, keep)
	}).collect();
	let body = transfer_body(&parts, outputs, xonly(&r.s), r.chain);
	r.http.post("cosign_transfer", &body)
}

/// The coin a transfer co-signed made for `key`, from its answer.
fn coin_from(r: &Running, cosigned: &Value, j: usize, key: &Keypair, nonce: [u8; 32], bases: Vec<Transaction>) -> Coin {
	let id = LeafId::from_str(cosigned["outputs"][j]["leaf_id"].as_str().unwrap()).unwrap();
	Coin { held: held_by(r, key, nonce, id), bases }
}

/// The transfer's margin: four times the floor for a two-input, two-output
/// reassignment, with room.
const MARGIN: u64 = 1_000;

#[tokio::test(flavor = "multi_thread")]
async fn a_frozen_holder_cannot_move_or_escape() {
	let mut r = Running::start().await;
	let iss = tokio::task::block_in_place(|| issue_supervised(&mut r));
	let z = iss.z;
	// The operator's signer reads freezes from a node of its own: without
	// one it signs nothing for a landing-1 coin.
	let cookie = r.signer.dir.join("node.cookie");
	std::fs::write(&cookie, "arca:arca").unwrap();
	let genesis = r.chain.genesis_hash();
	let node_url = format!("http://127.0.0.1:{}/", r.rt.node.rpc_port());
	tokio::task::block_in_place(|| r.signer.restart_with(genesis, &["--supervision-node".into(), node_url.clone(),
		"--supervision-cookie".into(), cookie.to_str().unwrap().into()]));

	// ---- The profile, read from the node --------------------------------
	let mut config = r.config.clone();
	let mut named = AssetSection::new(r.x, MIN_LEAF);
	named.supervised = Some(SupervisedSection::default());
	config.assets = vec![named];
	let e = r.server.reload(&config).await.unwrap_err();
	println!("REFUSED reload naming X supervised: {}", e);
	assert!(e.to_string().contains("does not list it as supervised"), "{}", e);
	let mut config = r.config.clone();
	config.assets.push(AssetSection::new(z, MIN_LEAF));
	r.server.reload(&config).await.unwrap();
	r.config = config;
	let info = r.http.get("info").ok();
	let zi = info["assets"].as_array().unwrap().iter().find(|a| a["asset"] == json!(z.to_string())).unwrap().clone();
	let allowance: u64 = zi["supervised"]["landing_allowance"].as_str().unwrap().parse().unwrap();
	println!("info: Z is served supervised, landing allowance {}; X: {}", allowance,
		info["assets"][0].get("supervised").map(|v| v.to_string()).unwrap_or("not supervised".into()));
	assert!(allowance > 0 && info["assets"][0].get("supervised").is_none());
	assert!(info["templates"]["list"].as_array().unwrap().contains(&json!("landing-1")));
	r.fund_wallet_in(z, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;

	// ---- Boarded and refreshed into a supervised batch -------------------
	let (alice, bob) = (Holder::new("alice"), Holder::new("bob"));
	let a_board_key = keypair("alice board");
	let (_, _, plain) = board_z(&mut r, z, &a_board_key, VALUE, None);
	refused("a board of Z into a vtxo-1 leaf", plain, "out_of_bounds");
	let (_, _, other) = board_z(&mut r, z, &a_board_key, VALUE, Some(alice.landing(allowance + 1)));
	refused("a board of Z with another allowance", other, "out_of_bounds");
	let (record, board_tx, ok) = board_z(&mut r, z, &a_board_key, VALUE, Some(alice.landing(allowance)));
	ok.ok();
	r.produce().await;
	r.bury().await;
	let id = record.leaf_id();
	let http = r.http.clone();
	r.wait("alice's board to be credited", || http.board_status(&id).json["state"] == "credited").await;
	let a_board = Coin { held: Held { key: a_board_key, nonce: record.owner_nonce, id, record: CoinRecord::Board(record) }, bases: vec![board_tx] };
	assert_eq!(a_board.held.record.landing().map(|t| t.program), Some(alice.program()));
	// A vtxo-1 leaf of Z is refused, as is a landing-1 leaf of X.
	let (w, _) = want_leaf(&keypair("alice vtxo"), z, VALUE, );
	let (body, _) = participation_body(&[&a_board.held], &[w], &[], None, xonly(&r.s), r.chain);
	refused("a refresh of Z into a vtxo-1 leaf", r.http.post("submit_participation", &body), "out_of_bounds");
	let a1_key = keypair("alice leaf 1");
	let (a1, round) = refresh_landing(&mut r, &a_board, &a1_key, alice.landing(allowance)).await;
	println!("round {} of Z: its batch rebuilt from the published tree, every leaf landing-1, alice's at her landing; every output \
		explicit ({} outputs)", round.txid(), round.output.len());

	// ---- Paid out of round, both holders landing-1 -----------------------
	let b1_key = keypair("bob leaf 1");
	let a2_key = keypair("alice leaf 2");
	let v = a1.valid(&r).value;
	let pay = 300_000;
	let to_bob = landing_leaf(&b1_key, z, pay, &bob.landing(allowance));
	let change = landing_leaf(&a2_key, z, v - MARGIN - pay - MARGIN, &alice.landing(allowance));
	// The profile on a transfer's outputs: no vtxo-1 leaf of Z, no other allowance.
	let plain = NewLeaf { landing: None, ..to_bob };
	refused("a transfer of Z into a vtxo-1 leaf", transfer(&r, &[&a1], &[(z, pay, plain), (z, v - MARGIN - pay - MARGIN, change)], MARGIN),
		"out_of_bounds");
	let skewed = NewLeaf { landing: Some(LandingTerms { min_value: pay - allowance - 1, ..to_bob.landing.unwrap() }), ..to_bob };
	refused("a transfer of Z with another allowance", transfer(&r, &[&a1], &[(z, pay, skewed), (z, v - MARGIN - pay - MARGIN, change)], MARGIN),
		"out_of_bounds");
	let paid = transfer(&r, &[&a1], &[(z, pay, to_bob), (z, v - MARGIN - pay - MARGIN, change)], MARGIN).ok();
	let bob1 = coin_from(&r, &paid, 0, &b1_key, to_bob.owner_nonce, a1.bases.clone());
	let alice2 = coin_from(&r, &paid, 1, &a2_key, change.owner_nonce, a1.bases.clone());
	println!("alice paid bob {} of Z out of round; both coins land at their holders' own keys", pay);

	// ---- A targeted freeze of alice's landing, mirrored ------------------
	let (freeze_at, freeze_target) = tokio::task::block_in_place(|| iss.record(&mut r, "freeze", Some(&alice.script())));
	r.produce().await;
	r.synced().await;
	println!("freeze record {} names alice's landing: isassetfrozen {}", freeze_at, iss.status(&r, &alice.script()));
	// Every path that would move alice's coin.
	let to_bob2 = landing_leaf(&keypair("bob leaf 2"), z, 100_000, &bob.landing(allowance));
	let a3 = landing_leaf(&keypair("alice leaf 3"), z, alice2.valid(&r).value - MARGIN - 100_000 - MARGIN, &alice.landing(allowance));
	let m = refused("transfer by the frozen holder", transfer(&r, &[&alice2], &[(z, 100_000, to_bob2), (z, a3.landing.unwrap().min_value
		+ allowance, a3)], MARGIN), "frozen");
	assert!(m.contains("a freeze record of the asset's issuer names its landing"), "{}", m);
	let swap_a = landing_leaf(&keypair("swap to bob"), z, alice2.valid(&r).value - MARGIN, &bob.landing(allowance));
	let swap_b = landing_leaf(&keypair("swap to alice"), z, bob1.valid(&r).value - MARGIN, &alice.landing(allowance));
	refused("swap with the frozen holder", transfer(&r, &[&alice2, &bob1], &[(z, alice2.valid(&r).value - MARGIN, swap_a),
		(z, bob1.valid(&r).value - MARGIN, swap_b)], MARGIN), "frozen");
	let (w, _) = want_landing(&keypair("alice refresh"), z, alice2.valid(&r).value, alice.landing(allowance));
	let (body, _) = participation_body(&[&alice2.held], &[w], &[], None, xonly(&r.s), r.chain);
	refused("refresh by the frozen holder", r.http.post("submit_participation", &body), "frozen");
	let off = server::participations::OutputRequest::Offboard { asset: z, value: alice2.valid(&r).value, script: op_true() };
	let (body, _) = participation_body(&[&alice2.held], &[off], &[], None, xonly(&r.s), r.chain);
	refused("offboard by the frozen holder", r.http.post("submit_participation", &body), "frozen");
	let terms = arca_covenant::FillOrder {
		asset_a: r.x, asset_b: z, rate_num: 1, rate_den: 1, maker_prog: xonly(&keypair("maker payout")).serialize(), min_lot: 1_000,
		expiry_locktime: 2_000_000_000, maker_x: xonly(&keypair("maker")).serialize(),
	};
	let (leaf, _) = want_leaf(&keypair("alice take"), r.x, 50_000);
	let (body, _) = take_body(&[&alice2.held], OutPoint::new(round.txid(), 5), &terms, 100_000, 50_000, &leaf, (z, 0), xonly(&r.s), r.chain);
	refused("take of an on-chain order by the frozen holder", r.http.post("take_order", &body), "frozen");
	let fill_input = {
		let parts = vec![(&alice2.held, alice2.valid(&r), alice2.valid(&r).value - MARGIN)];
		transfer_body(&parts, &[(z, alice2.valid(&r).value - 2 * MARGIN, landing_leaf(&keypair("alice fill"), z,
			alice2.valid(&r).value - 2 * MARGIN, &alice.landing(allowance)))], xonly(&r.s), r.chain)
	};
	refused("resting-order fill by the frozen holder", r.http.post("order_fill", &json!({
		"order": LeafId([7; 32]).to_string(), "coin": LeafId([7; 32]).to_string(), "filled": "1000",
		"inputs": fill_input["inputs"], "outputs": fill_input["outputs"]})), "frozen");
	let att = |id: &[u8; 32]| hex(sign_digest(&alice2.held.key, id, &random32()).as_ref());
	let claims = vec![json!({"key": hex(&xonly(&keypair("claimer")).serialize()), "nonce": hex(&random32()), "value": "100000"})];
	refused("distribution by the frozen holder", r.http.post("distribute", &json!({
		"inputs": [{"leaf_id": alice2.held.id.to_string(), "attestation": att(&[0; 32])}], "asset": z.to_string(),
		"exit_delay_units": exit_delay().units(), "claims": claims, "return_script": hex(op_true().as_bytes()), "fees": []})), "frozen");
	refused("plan by the frozen holder", r.http.post("plan_quote", &json!({"coin": alice2.held.id.to_string(),
		"owner_nonces": [hex(&random32())], "exit_delay_units": exit_delay().units(), "attestation": att(&[0; 32])})), "frozen");
	let htlc = arca_covenant::HtlcTerms {
		direction: arca_covenant::HtlcDirection::Send, payment_hash: [9; 32],
		timeout: arca_covenant::MedianTime::from_consensus(2_000_000_000).unwrap(), operator_delay: arca_covenant::RelativeTime::from_units(36).unwrap(),
	};
	let ln = NewLeaf { owner: xonly(&keypair("alice ln")), owner_nonce: random32(), creator_nonce: random32(), exit_delay: exit_delay(),
		htlc: Some(htlc), landing: None, v2: false };
	let send = transfer_body(&[(&alice2.held, alice2.valid(&r), alice2.valid(&r).value - MARGIN)],
		&[(z, alice2.valid(&r).value - 2 * MARGIN, ln)], xonly(&r.s), r.chain);
	refused("Lightning payment by the frozen holder", r.http.post("lightning_send", &json!({"invoice": "lnbcrt1",
		"inputs": send["inputs"], "outputs": send["outputs"]})), "frozen");

	// The signer refuses on its own reading, through its own node.
	let v2 = alice2.valid(&r);
	let out = arca_covenant::ExplicitOutput::new(z, v2.value - MARGIN, op_true());
	let msg = v2.leaf.collab_message(z, v2.value, std::slice::from_ref(&out)).unwrap();
	let owner_sig = sign_digest(&alice2.held.key, &msg.digest, &[0; 32]);
	let client = SignerClient::new(&r.signer.socket);
	let e = client.rebind(&v2.leaf.owner, &owner_sig, &v2.leaf.salt, Some(alice.program()), z, v2.value, std::slice::from_ref(&out)).await
		.unwrap_err();
	println!("REFUSED by the signer, on its own node: {}", e);
	assert!(matches!(e, SignerError::Frozen(_)), "{}", e);
	// Naming no landing gets a signature over the plain constant, never over
	// a landing-1 leaf's: shown under a salt of no coin, as the signer
	// records what it signs under a salt (the covenant's test spends a
	// landing-1 leaf with such a pair and is refused in a block).
	let salt = random32();
	let throwaway = arca_covenant::LeafPolicy { salt, ..v2.leaf };
	let landing_msg = throwaway.collab_message(z, v2.value, std::slice::from_ref(&out)).unwrap();
	let plain_msg = arca_covenant::message::rebind_message(&r.chain.leaf_constant(&salt), z, v2.value, std::slice::from_ref(&out)).unwrap();
	assert_ne!(plain_msg.digest, landing_msg.digest);
	let plain_sig = client.rebind(&v2.leaf.owner, &sign_digest(&alice2.held.key, &plain_msg.digest, &[0; 32]), &salt, None, z, v2.value,
		std::slice::from_ref(&out)).await.unwrap();
	assert!(arca_covenant::sign::verify_digest(&plain_sig, &plain_msg.digest, &xonly(&r.s)));
	assert!(!arca_covenant::sign::verify_digest(&plain_sig, &landing_msg.digest, &xonly(&r.s)),
		"a signature over the plain constant is not one over landing-1's");
	println!("the signer, asked with no landing, signs the plain constant's message, which no landing-1 leaf's script checks");
	// A signer that reads no node signs nothing for a landing-1 coin.
	let lone = tokio::task::block_in_place(|| common::signer::SignerProcess::start(&keypair("a second operator"), genesis));
	let e = SignerClient::new(&lone.socket).rebind(&v2.leaf.owner, &owner_sig, &v2.leaf.salt, Some(alice.program()), z, v2.value,
		std::slice::from_ref(&out)).await.unwrap_err();
	println!("REFUSED by a signer that reads no node: {}", e);
	assert!(e.to_string().contains("reads freezes from no node"), "{}", e);

	// bob is not frozen: he moves, and may pay alice, whose coin arrives frozen.
	let b2_key = keypair("bob leaf 2b");
	let to_alice = landing_leaf(&keypair("alice leaf from bob"), z, 50_000, &alice.landing(allowance));
	let bob_change = landing_leaf(&b2_key, z, bob1.valid(&r).value - MARGIN - 50_000 - MARGIN, &bob.landing(allowance));
	let paid = transfer(&r, &[&bob1], &[(z, 50_000, to_alice), (z, bob1.valid(&r).value - MARGIN - 50_000 - MARGIN, bob_change)], MARGIN).ok();
	let bob2 = coin_from(&r, &paid, 1, &b2_key, bob_change.owner_nonce, bob1.bases.clone());
	println!("bob, not frozen, paid alice 50000 of Z: the payment to a frozen landing is co-signed, and arrives frozen");

	// ---- A pause of Z, mirrored; its lifting taken once final ------------
	let (pause_at, _) = tokio::task::block_in_place(|| iss.record(&mut r, "pause", None));
	r.produce().await;
	r.synced().await;
	let to_x = landing_leaf(&keypair("bob leaf 3"), z, bob2.valid(&r).value - 2 * MARGIN, &bob.landing(allowance));
	let m = refused("transfer by bob under the pause", transfer(&r, &[&bob2], &[(z, bob2.valid(&r).value - 2 * MARGIN, to_x)], MARGIN), "frozen");
	assert!(m.contains("paused"), "{}", m);
	tokio::task::block_in_place(|| iss.lift(&mut r, pause_at, &"00".repeat(32)));
	r.produce().await;
	r.synced().await;
	let m = refused("transfer by bob, the pause lifted on the chain but not final", transfer(&r, &[&bob2],
		&[(z, bob2.valid(&r).value - 2 * MARGIN, to_x)], MARGIN), "frozen");
	assert!(m.contains("takes the lifting only once that block is final"), "{}", m);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let paid = transfer(&r, &[&bob2], &[(z, bob2.valid(&r).value - 2 * MARGIN, to_x)], MARGIN).ok();
	println!("the pause's lifting final: bob's transfer co-signed ({} output)", paid["outputs"].as_array().unwrap().len());

	// ---- A freeze no request met while it lasted, held all the same -----
	// The operator reads every freeze after each pass over the chain: bob's
	// landing frozen for one block and lifted, no coin of his asked about
	// meanwhile, still binds until the lifting is final.
	let bob3 = coin_from(&r, &paid, 0, &keypair("bob leaf 3"), to_x.owner_nonce, bob2.bases.clone());
	let z_bytes = z.into_inner().to_byte_array();
	let holds = |r: &Running| {
		let store = r.server.store.clone();
		tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(store.supervision_holds_of(&z_bytes))).unwrap()
	};
	let (bob_at, bob_target) = tokio::task::block_in_place(|| iss.record(&mut r, "freeze", Some(&bob.script())));
	r.produce().await;
	r.synced().await;
	let bob_hash: [u8; 32] = Vec::<u8>::from_hex(iss.status(&r, &bob.script())["targethash"].as_str().unwrap()).unwrap().try_into().unwrap();
	let bobs = |r: &Running| holds(r).into_iter().find(|h| h.target == bob_hash);
	r.wait("the operator to hold bob's freeze", || bobs(&r).is_some_and(|h| h.lifted.is_none())).await;
	tokio::task::block_in_place(|| iss.lift(&mut r, bob_at, &bob_target));
	r.produce().await;
	r.synced().await;
	r.wait("the operator to count the lifting", || bobs(&r).is_some_and(|h| h.lifted.is_some())).await;
	println!("bob's freeze, never met by a request, held by the operator: {:?}", bobs(&r));
	let to_y = landing_leaf(&keypair("bob leaf 4"), z, bob3.valid(&r).value - 2 * MARGIN, &bob.landing(allowance));
	let m = refused("transfer by bob, a freeze no request met lifted but not final", transfer(&r, &[&bob3],
		&[(z, bob3.valid(&r).value - 2 * MARGIN, to_y)], MARGIN), "frozen");
	assert!(m.contains("takes the lifting only once that block is final"), "{}", m);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	transfer(&r, &[&bob3], &[(z, bob3.valid(&r).value - 2 * MARGIN, to_y)], MARGIN).ok();
	assert!(bobs(&r).is_none(), "the hold dropped once its lifting is final: {:?}", bobs(&r));
	println!("its lifting final: bob's transfer co-signed, the hold dropped");

	// ---- alice's freeze lifted, final: alice moves again -----------------
	tokio::task::block_in_place(|| iss.lift(&mut r, freeze_at, &freeze_target));
	r.produce().await;
	r.synced().await;
	refused("transfer by alice, her freeze lifted but not final", transfer(&r, &[&alice2], &[(z, 100_000, to_bob2),
		(z, a3.landing.unwrap().min_value + allowance, a3)], MARGIN), "frozen");
	r.produce().await;
	r.bury().await;
	r.synced().await;
	transfer(&r, &[&alice2], &[(z, 100_000, to_bob2), (z, a3.landing.unwrap().min_value + allowance, a3)], MARGIN).ok();
	println!("alice's freeze lifted and final: her transfer co-signed");

	// ---- A participation taken before a freeze, voided at its round ------
	let a_board_key2 = keypair("alice board 2");
	let (record, board_tx, ok) = board_z(&mut r, z, &a_board_key2, VALUE, Some(alice.landing(allowance)));
	ok.ok();
	r.produce().await;
	r.bury().await;
	let id = record.leaf_id();
	let http = r.http.clone();
	r.wait("alice's second board to be credited", || http.board_status(&id).json["state"] == "credited").await;
	let board2 = Coin { held: Held { key: a_board_key2, nonce: record.owner_nonce, id, record: CoinRecord::Board(record) }, bases: vec![board_tx] };
	let (w, _) = want_landing(&keypair("alice leaf 4"), z, VALUE, alice.landing(allowance));
	let (body, pid) = participation_body(&[&board2.held], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	let _ = tokio::task::block_in_place(|| iss.record(&mut r, "freeze", Some(&alice.script())));
	r.produce().await;
	r.synced().await;
	let built = r.server.rounds.run_round().await.unwrap();
	let st = status(&r, &pid);
	println!("alice frozen after her participation was taken: the round {} it; participation {}: {}",
		if built.is_some() { "ran without" } else { "was not built for" }, st["state"], st["void_reason"]);
	assert_eq!(st["state"], "void", "{}", st);
	assert!(st["void_reason"].as_str().unwrap_or("").contains("frozen"), "{}", st);
	let _: (Value, XOnlyPublicKey) = (Value::Null, xonly(&a1_key));
}
