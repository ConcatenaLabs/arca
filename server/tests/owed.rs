//! Swept coins are repaid, never kept, against a whole server on an anchored
//! proof-of-stake regtest chain. Asset X charges a refresh fee of 5,000 parts
//! per million and 200 atoms a coin. B refreshes its board into a round leaf
//! and stays away; A refreshes and pays its leaf out of round to C, who stays
//! away too; D refreshes and goes home on the chain (its own output on the
//! chain, nothing owed). After the batch's expiry, its release and the
//! notice, the operator sweeps it, in a block anchored to a parent block of
//! its own. Once the sweep is final the server owes B and C each its coin
//! less the late-refresh fee, exactly, and `info` shows X's owed total and a
//! fundable figure that leaves it out. Bitcoin then reorganises that parent
//! block away: the sweep leaves the chain, the entries are withdrawn (a claim
//! is refused, `info` owes nothing), and the coins are back in their batch,
//! its output unspent in the chain. The sweep returns, final again, and the
//! entries with it. A claim signed by another key, for another amount, and
//! a second claim are refused; C's claim is a participation of the server's
//! own making, which runs in X's next round and which C completes with no
//! forfeit, holding a new leaf of exactly what is owed. B's entry stays owed.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::{OutPoint, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::{LeafId, ValidOrigin};
use server::participations::OutputRequest;
use server::server::AssetSection;

use common::client::{auths_json, hex, new_leaf, output_json, random32, transfer_body, unhex, want_leaf, Answer};
use common::flow::{drive, forfeit_for, held_by, Coin, Refreshed};
use common::client::{forfeit_sig, participation_body};
use common::keys::{keypair, xonly};
use common::rounds::{advance_mtp, created, credited_board, mtp, round_final, status, validate_new_leaf};
use common::running::{Running, MIN_LEAF};

const HOUR: u32 = 3_600;
const PPM: u64 = 5_000;
const BASE: u64 = 200;

fn refused(a: Answer, code: &str, what: &str) -> String {
	let (c, m) = a.refusal();
	println!("refused, {}: {} {}: {}", what, a.status, c, m);
	assert_eq!(c, code, "{}: {}", what, a.json);
	m
}

/// The late-refresh fee the schedule sets for a coin of `value`: the refresh
/// fee at its full charge, rounded up.
fn late_fee(value: u64) -> u64 {
	(value as u128 * PPM as u128).div_ceil(1_000_000) as u64 + BASE
}

/// An `owed` lookup proven by each of `keys`.
fn lookup(r: &Running, keys: &[&Keypair]) -> Answer {
	let v = r.http.post("challenge", &json!({})).ok();
	let challenge: [u8; 32] = unhex(v["challenge"].as_str().unwrap()).try_into().unwrap();
	let proofs: Vec<Value> = keys.iter().map(|k| {
		let d = server::auth::auth_digest(&r.chain, "owed", &challenge, &xonly(k), &[]);
		json!({"key": hex(&xonly(k).serialize()), "signature": hex(sign_digest(k, &d, &random32()).as_ref())})
	}).collect();
	r.http.post("owed", &json!({"challenge": hex(&challenge), "keys": proofs}))
}

/// X as `info` shows it.
fn info_x(r: &Running) -> Value {
	let info = r.http.get("info").ok();
	info["assets"].as_array().unwrap().iter().find(|a| a["asset"] == r.x.to_string()).cloned().unwrap()
}

/// A claim of coin `coin`, signed by `signer`, wanting `leaf` (its key proven
/// by `leaf_key`); and the repayment participation's id.
fn claim_body(r: &Running, coin: &LeafId, signer: &Keypair, leaf: &OutputRequest, leaf_key: &Keypair) -> (Value, [u8; 32]) {
	let id = server::owed::repayment_id(&r.chain, &xonly(&r.s), leaf);
	let mut l = output_json(leaf)["leaf"].clone();
	l["key_proof"] = json!(hex(sign_digest(leaf_key, &server::participations::key_proof_digest(&id), &random32()).as_ref()));
	let digest = server::owed::claim_digest(&r.chain, &xonly(&r.s), coin, &id);
	(json!({"leaf_id": coin.to_string(), "leaf": l, "signature": hex(sign_digest(signer, &digest, &random32()).as_ref())}), id)
}

/// Lets the watcher pass, then a block, buried, and the server at the tip.
async fn settle(r: &Running) {
	r.server.watcher.pass().await.unwrap();
	common::flow::broadcast_all(r).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.server.nursery.pass().await.unwrap();
	r.server.watcher.pass().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_swept_coin_is_owed_withdrawn_by_a_reorg_and_repaid_once() {
	let mut r = Running::start_with(|c, y| {
		// What follows is the sweep of a live coin: the operator does not take
		// it on the chain at its batch's release first.
		c.watcher.unroll_at_release = false;
		let x = c.assets[0].asset.clone();
		c.assets = vec![
			toml::from_str(&format!("asset = \"{}\"\nmin_leaf = \"{}\"\nrefresh_ppm = {}\nrefresh_base = \"{}\"\n", x, MIN_LEAF, PPM, BASE))
				.unwrap(),
			AssetSection::new(y, MIN_LEAF),
		];
	}).await;
	let x = r.x;
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	assert_eq!(r.http.get("info").ok()["swept"], json!({"policy": "repaid", "late_fee": "refresh"}));

	// A, B and D board, and refresh into one round.
	let (a, b, d) = (keypair("O A"), keypair("O B"), keypair("O D"));
	let mut coins = vec![];
	for k in [&a, &b, &d] {
		let (held, tx) = credited_board(&mut r, k, x).await;
		coins.push(Coin { held, bases: vec![tx] });
	}
	let (a1, b1, d1) = (keypair("O A, round"), keypair("O B, round"), keypair("O D, round"));
	let done = refresh_paying(&mut r, &[(&coins[0], &a1), (&coins[1], &b1), (&coins[2], &d1)]).await;
	let (la, lb, ld) = (&done[0].new, &done[1].new, &done[2].new);
	let expiry = la.valid(&r).expiry.to_consensus_u32();

	// A pays its whole leaf out of round to C.
	let c = keypair("O C");
	let va = la.valid(&r);
	let (to_c, c_nonce) = new_leaf(&c);
	let kept = va.value - 2_000;
	let paid = r.http.post("cosign_transfer", &transfer_body(&[(&la.held, va.clone(), kept)], &[(x, kept - 2_000, to_c)], xonly(&r.s), r.chain)).ok();
	let lc: LeafId = paid["outputs"][0]["leaf_id"].as_str().unwrap().parse().unwrap();
	let vc = kept - 2_000;
	let _ = held_by(&r, &c, c_nonce, lc);
	let vb = lb.valid(&r).value;
	println!("B holds {} = {} of X; C holds {} = {} of X, paid by A out of round", lb.held.id, vb, lc, vc);

	// D goes home: its leaf's path unrolled, its own output on the chain.
	let leaf_out = unroll_to_leaf(&r, ld, "D's exit");
	r.produce().await;
	r.bury().await;
	r.synced().await;
	println!("D's leaf is on the chain at {}", leaf_out);

	// The expiry, the release, the notice; the sweep in a block anchored to a
	// parent block of its own.
	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, expiry.saturating_sub(now) + HOUR).await;
	let token = done[0].new_valid.branch.nodes[0].sweep.token.into_inner().to_byte_array().to_vec();
	drive(&r, "the release at the batch's expiry", 4, |l| common::flow::has(l, "release", &token)).await;
	settle(&r).await;
	advance_mtp(&r, 37 * HOUR).await;
	r.rt.mine_parent(1).unwrap();
	tokio::task::block_in_place(|| r.rt.anchor_to_parent_tip()).unwrap();
	let p = r.rt.parent.client().block_count().unwrap();
	drive(&r, "the sweep after the notice", 4, |l| common::flow::has(l, "sweep", &token)).await;
	settle(&r).await;
	settle(&r).await;
	let sweep = common::flow::of_kind(&r, "sweep").await.into_iter().find(|w| w.subject == token).unwrap();
	assert_eq!(sweep.state, server::store::NurseryState::Final, "the sweep is final");
	let sweep_txid = Txid::from_byte_array(sweep.txid);
	println!("the sweep {} is final", sweep_txid);

	// What is owed: B's coin and C's, each less the late-refresh fee; nothing
	// for A's coin (spent out of round) or D's (on the chain).
	let owed = lookup(&r, &[&b1, &c, &a1, &d1]).ok();
	println!("owed: {}", owed);
	let entries = owed["owed"].as_array().unwrap();
	assert_eq!(entries.len(), 2, "{}", owed);
	let entry = |leaf: &LeafId| entries.iter().find(|e| e["leaf_id"] == json!(leaf.to_string())).cloned().unwrap();
	for (leaf, key, nonce, value) in [(&lb.held.id, &b1, lb.held.nonce, vb), (&lc, &c, c_nonce, vc)] {
		let e = entry(leaf);
		assert_eq!(e["owner"], json!(hex(&xonly(key).serialize())));
		assert_eq!(e["owner_nonce"], json!(hex(&nonce)));
		assert_eq!(e["value"], json!(value.to_string()));
		assert_eq!(e["fee"], json!(late_fee(value).to_string()), "the fee is the refresh fee at its full charge");
		assert_eq!(e["owed"], json!((value - late_fee(value)).to_string()));
		assert_eq!(e["state"], "owed");
		assert_eq!(e["sweep_txid"], json!(sweep_txid.to_string()));
	}
	let total = (vb - late_fee(vb)) + (vc - late_fee(vc));
	let ix = info_x(&r);
	println!("info for X: owed {}, fundable {}", ix["owed"], ix["fundable"]);
	assert_eq!(ix["owed"], json!({"total": total.to_string(), "coins": 2}));
	let pool: u64 = r.server.rounds.fundable_now().await.unwrap()[&x];
	assert_eq!(ix["fundable"], json!((pool - total).to_string()), "the fundable figure leaves what is owed out of the pool, {}", pool);

	// Bitcoin reorganises the sweep's parent block away: the sweep leaves the
	// chain, its entries are withdrawn, the coins are back in their batch.
	let orphaned = tokio::task::block_in_place(|| r.rt.orphan_parent_from(p)).unwrap();
	println!("the parent orphaned {} block(s) from {}", orphaned.len(), p);
	assert!(r.rt.client().confirmations(&sweep_txid).map(|c| c == 0).unwrap_or(true), "the sweep left the chain");
	r.synced().await;
	r.server.nursery.pass().await.unwrap();
	r.server.watcher.pass().await.unwrap();
	// Every output the sweep took (here B's and C's entries, D's unroll having
	// spent the batch output) is unspent in the chain again.
	let sweep_tx: Transaction = elements::encode::deserialize(&sweep.tx).unwrap();
	for i in &sweep_tx.input {
		let op = i.previous_output;
		let v: Value = r.rt.client().call("gettxout", &[json!(op.txid.to_string()), json!(op.vout), json!(false)]).unwrap();
		assert!(!v.is_null(), "{} is unspent in the chain again", op);
		println!("after the reorganisation {} is unspent in the chain again: {} of {}", op, v["value"], v["asset"]);
	}
	let owed = lookup(&r, &[&b1, &c]).ok();
	assert!(owed["owed"].as_array().unwrap().iter().all(|e| e["state"] == "withdrawn"), "{}", owed);
	assert!(info_x(&r).get("owed").is_none(), "info owes nothing while the sweep is not final");
	assert_eq!(r.server.store.leaf(&lb.held.id.0).await.unwrap().unwrap().state, server::store::LeafState::Live, "B's coin is live");
	let (w, _) = want_leaf(&keypair("O C, early"), x, vc - late_fee(vc));
	let (body, _) = claim_body(&r, &lc, &c, &w, &keypair("O C, early"));
	refused(r.http.post("owed_claim", &body), "owed_withdrawn", "a claim while the sweep is out of the chain");

	// The sweep returns, final again, and its entries with it.
	for _ in 0..4 {
		settle(&r).await;
		if lookup(&r, &[&b1]).ok()["owed"][0]["state"] == "owed" {
			break;
		}
	}
	assert!(r.rt.client().confirmations(&sweep_txid).unwrap() >= 1, "the same sweep is back in the chain");
	let owed = lookup(&r, &[&b1, &c]).ok();
	assert!(owed["owed"].as_array().unwrap().iter().all(|e| e["state"] == "owed"), "{}", owed);
	assert_eq!(info_x(&r)["owed"], json!({"total": total.to_string(), "coins": 2}));

	// Claims: by another key, for another amount, then C's own.
	let c2 = keypair("O C, repaid");
	let owed_c = vc - late_fee(vc);
	let (w, nonce) = want_leaf(&c2, x, owed_c);
	let (forged, _) = claim_body(&r, &lc, &a1, &w, &c2);
	refused(r.http.post("owed_claim", &forged), "bad_signature", "a claim of C's coin signed by A's key");
	let (more, _) = want_leaf(&c2, x, owed_c + 1);
	let (body_more, _) = claim_body(&r, &lc, &c, &more, &c2);
	refused(r.http.post("owed_claim", &body_more), "out_of_bounds", "a claim of one atom more than is owed");
	let (body, pid) = claim_body(&r, &lc, &c, &w, &c2);
	let st = r.http.post("owed_claim", &body).ok();
	println!("C's claim: {}", st);
	assert_eq!(st["state"], "pending");
	assert_eq!(st["participation_id"], json!(hex(&pid)));
	assert!(st["inputs"].as_array().unwrap().is_empty(), "the repayment gives up no coin");
	assert_eq!(r.http.post("owed_claim", &body).ok()["participation_id"], json!(hex(&pid)), "the same claim again is the same");
	let c3 = keypair("O C, twice");
	let (w3, _) = want_leaf(&c3, x, owed_c);
	let (again, _) = claim_body(&r, &lc, &c, &w3, &c3);
	refused(r.http.post("owed_claim", &again), "owed_claimed", "a second claim of C's coin");
	assert_eq!(lookup(&r, &[&c]).ok()["owed"][0]["state"], "claimed");

	// The repayment runs in X's next round; C completes it with no forfeit.
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let (valid, record, _) = validate_new_leaf(&r, &pid, 0, &c2, &nonce);
	let fin = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&pid), "forfeits": [],
		"leaves": [auths_json(&valid, &c2, created(&record))]})).ok();
	assert_eq!(fin["state"], "released", "{}", fin);
	let row = r.server.store.leaf(&valid.leaf_id.0).await.unwrap().unwrap();
	assert_eq!((row.state, row.value), (server::store::LeafState::Live, owed_c), "C holds a new leaf of exactly what is owed");
	println!("C's new leaf {} holds {} of X ({} less the fee {}), in round {}", valid.leaf_id, row.value, vc, late_fee(vc), built.tx.txid());
	r.server.watcher.pass().await.unwrap();
	let owed = lookup(&r, &[&b1, &c]).ok();
	assert_eq!(entry_state(&owed, &lc), "repaid");
	assert_eq!(entry_state(&owed, &lb.held.id), "owed");
	assert_eq!(info_x(&r)["owed"], json!({"total": (vb - late_fee(vb)).to_string(), "coins": 1}), "only B's coin is owed now");
	refused(r.http.post("owed_claim", &again), "owed_claimed", "a claim of C's coin once repaid");
	let _ = status(&r, &pid);
}

/// [`common::flow::refresh`], each coin paying the refresh fee its asset's
/// schedule asks (read from the server's refusal of a participation paying
/// none).
async fn refresh_paying(r: &mut Running, coins: &[(&Coin, &Keypair)]) -> Vec<Refreshed> {
	let mut ids = vec![];
	for (coin, key) in coins {
		let v = coin.valid(r);
		let (w, _) = want_leaf(key, v.asset, v.value);
		let (body, _) = participation_body(&[&coin.held], &[w], &[], None, xonly(&r.s), r.chain);
		let m = refused(r.http.post("submit_participation", &body), "fee", "a refresh paying no fee");
		let fee: u64 = m.split("asks ").nth(1).unwrap().split(' ').next().unwrap().parse().unwrap();
		let (w, nonce) = want_leaf(key, v.asset, v.value - fee);
		let (body, id) = participation_body(&[&coin.held], &[w], &[(v.asset, fee)], None, xonly(&r.s), r.chain);
		assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
		ids.push((id, nonce));
	}
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(r, &built.tx.txid()).await;
	let mut out = vec![];
	for ((coin, key), (id, nonce)) in coins.iter().zip(ids) {
		let st = status(r, &id);
		let (new_valid, record, round) = validate_new_leaf(r, &id, 0, key, &nonce);
		let old = coin.valid(r);
		let f = forfeit_for(&old, &new_valid, &round, &st);
		let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&id),
			"forfeits": [{"leaf_id": coin.held.id.to_string(), "signature": forfeit_sig(&f, &coin.held.key)}],
			"leaves": [auths_json(&new_valid, key, created(&record))]})).ok();
		assert_eq!(done["state"], "released", "{}", done);
		let preimage: [u8; 32] = unhex(done["preimage"].as_str().unwrap()).try_into().unwrap();
		let held = held_by(r, key, nonce, new_valid.leaf_id);
		out.push(Refreshed { new: Coin { held, bases: vec![round.clone()] }, old_key: coin.held.key, id, preimage, old, new_valid,
			connector_vout: st["round"]["connector_vout"].as_u64().unwrap() as u32, round });
	}
	out
}

fn send(r: &Running, what: &str, tx: &Transaction) -> Txid {
	let txid = r.rt.client().send_raw_transaction(tx).unwrap_or_else(|e| panic!("{}: {}", what, e));
	println!("{}: {} ({} vB)", what, txid, tx.vsize());
	txid
}

/// The unroll of `coin`, a batch leaf, from its batch output down by its
/// owner's own authorisations, and its entry with its preimage: the leaf's
/// outpoint.
fn unroll_to_leaf(r: &Running, coin: &Coin, label: &str) -> OutPoint {
	let v = coin.valid(r);
	let (valid, preimage, auths) = match &v.origin {
		ValidOrigin::Leaf { valid, preimage, auths } => (valid, preimage, auths),
		_ => panic!("not a batch leaf"),
	};
	let txs = valid.branch.unroll(OutPoint::new(valid.round_txid, valid.batch_vout), auths, &vec![FeeSource::Reserve; auths.len()]).unwrap();
	for (level, u) in txs.iter().enumerate() {
		send(r, &format!("{}: unroll, level {}", label, level), &u.tx);
	}
	let entry = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), preimage, &FeeSource::Reserve).unwrap();
	OutPoint::new(send(r, &format!("{}: its entry, with its preimage", label), &entry.tx), 0)
}

fn entry_state(owed: &Value, leaf: &LeafId) -> String {
	owed["owed"].as_array().unwrap().iter().find(|e| e["leaf_id"] == json!(leaf.to_string())).unwrap()["state"].as_str().unwrap().into()
}
