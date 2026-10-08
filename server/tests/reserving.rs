//! Re-serving a wallet's leaves to the key it restores with: a leaf bound to
//! its owner's mailbox key is served, in every state, to whoever proves that
//! key, with what it rests on and every way it was given up, each with the
//! owner's own signature; a page at a time, each page's proof bound to its
//! cursor; nothing of another key; at a bounded rate.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::{Keypair, XOnlyPublicKey};
use elements::{AssetId, OutPoint, Transaction};
use serde_json::{json, Value};

use arca_covenant::sign::{sign_digest, verify_digest};
use arca_covenant::{BoardRecord, CoinRecord, LeafId, MedianTime, RelativeTime, Template, TransferPlan};
use common::client::{auths_json, forfeit_sig, hex, new_leaf, participation_body, random32, transfer_body, unhex, want_leaf, Held};
use common::flow::forfeit_for;
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{created, round_final, status, validate_new_leaf, VALUE};
use common::running::Running;
use server::participations::OutputRequest;

fn refused(a: common::client::Answer, status: i32, code: &str) -> String {
	let (c, m) = a.refusal();
	assert_eq!((a.status, c.as_str()), (status, code), "{}", a.json);
	println!("refused {} {}: {}", status, code, m);
	m
}

/// The cases here pay part of a coin, leaving margins above the default cap.
fn wide_margins(c: &mut server::server::Config, _: AssetId) {
	c.fees.max_margin_multiple = Some(1_000_000);
}

/// `owner`'s signature binding its leaf to `mailbox`.
fn proof(r: &Running, owner: &Keypair, mailbox: &XOnlyPublicKey) -> String {
	let d = server::auth::mailbox_binding_digest(&r.chain, &xonly(&r.s), &xonly(owner), mailbox);
	hex(sign_digest(owner, &d, &random32()).as_ref())
}

/// A board of `VALUE` of X for `owner`, registered with `body` changed by
/// `bind`; its record, transaction and the answer.
fn board(r: &mut Running, owner: &Keypair, bind: impl FnOnce(&mut Value)) -> (BoardRecord, Transaction, common::client::Answer) {
	let nonce = r.http.operator_nonce();
	let record = common::client::board_record(owner, nonce, r.x, VALUE, r.chain, xonly(&r.s));
	let coins = vec![r.purse.take_coin(r.x)];
	let tx = record.tx(&coins, r.x, 2_000, &node::op_true()).unwrap().tx;
	for (j, o) in tx.output.iter().enumerate().skip(1) {
		if !o.is_fee() {
			r.purse.put((OutPoint::new(tx.txid(), j as u32), o.clone()));
		}
	}
	r.rt.client().send_raw_transaction(&tx).unwrap();
	let mut body = json!({"record": hex(&record.to_bytes().unwrap()), "tx": hex(&elements::encode::serialize(&tx))});
	bind(&mut body);
	let a = r.http.post("register_board", &body);
	(record, tx, a)
}

/// Every leaf served to `key`, a page of `limit` at a time, each page's
/// proof bound to its cursor and size.
fn served(r: &Running, key: &Keypair, limit: u32) -> Vec<Value> {
	let mut out = vec![];
	let mut after = 0u64;
	loop {
		let request = server::auth::mailbox_read_request(after, limit);
		let page = r.http.post("leaf_data", &json!({"auth": r.http.auth_for("leaf_data", key, &r.chain, &request),
			"after": after.to_string(), "limit": limit})).ok();
		let leaves = page["leaves"].as_array().unwrap().clone();
		assert!(leaves.len() <= limit as usize);
		if leaves.is_empty() {
			assert!(page["next"].is_null());
			return out;
		}
		after = page["next"].as_str().unwrap().parse().unwrap();
		assert_eq!(page["next"], leaves.last().unwrap()["cursor"]);
		out.extend(leaves);
	}
}

fn entry<'a>(all: &'a [Value], id: &LeafId) -> &'a Value {
	all.iter().find(|l| l["leaf_id"] == json!(id.to_string())).unwrap_or_else(|| panic!("no leaf {} in {:?}", id, all))
}

fn sig(s: &Value) -> Signature {
	Signature::from_slice(&unhex(s.as_str().unwrap())).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallets_leaves_are_served_to_its_mailbox_key_with_how_each_was_given_up() {
	let mut r = Running::start_with(wide_margins).await;
	r.fund_wallet(50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let s = xonly(&r.s);
	let (a_mailbox, b_mailbox, stranger) = (keypair("A's mailbox"), keypair("B's mailbox"), keypair("a stranger"));
	let a_board = keypair("A's board");

	// A binding not signed by the leaf's own key is refused, and nothing is
	// registered.
	let c_board = keypair("C's board");
	let not_c = proof(&r, &stranger, &xonly(&stranger));
	let (c_record, _, a) = board(&mut r, &c_board, |b| {
		b["mailbox"] = json!(hex(&xonly(&stranger).serialize()));
		b["mailbox_proof"] = json!(not_c);
	});
	refused(a, 422, "bad_signature");
	refused(r.http.board_status(&c_record.leaf_id()), 404, "unknown_board");
	// A mailbox without its proof is malformed.
	let d_board = keypair("D's board");
	let (_, _, a) = board(&mut r, &d_board, |b| b["mailbox"] = json!(hex(&xonly(&stranger).serialize())));
	refused(a, 400, "malformed");

	// A's board, bound to A's mailbox key.
	let pa = proof(&r, &a_board, &xonly(&a_mailbox));
	let (record, board_tx, a) = board(&mut r, &a_board, |b| {
		b["mailbox"] = json!(hex(&xonly(&a_mailbox).serialize()));
		b["mailbox_proof"] = json!(pa);
	});
	assert_eq!(a.ok()["state"], "pending");
	let board_id = record.leaf_id();
	let all = served(&r, &a_mailbox, 100);
	assert_eq!(all.len(), 1, "{:?}", all);
	let e = entry(&all, &board_id);
	assert_eq!((e["kind"].as_str(), e["state"].as_str()), (Some("board"), Some("pending")));
	assert_eq!(e["owner"], hex(&xonly(&a_board).serialize()));
	assert_eq!(e["owner_nonce"], hex(&record.owner_nonce));
	assert_eq!(e["board"]["txid"], board_tx.txid().to_string());
	assert_eq!(CoinRecord::from_bytes(&unhex(e["record"].as_str().unwrap())).unwrap(), CoinRecord::Board(record));
	assert!(served(&r, &stranger, 100).is_empty(), "nothing of a key the request does not prove");
	r.produce().await;
	r.bury().await;
	let http = r.http.clone();
	r.wait("the board to be credited", || http.board_status(&board_id).json["state"] == "credited").await;
	let e = served(&r, &a_mailbox, 100)[0].clone();
	assert_eq!((e["state"].as_str(), e["board"]["state"].as_str()), (Some("live"), Some("credited")));

	// A pays B out of round, its change to its own mailbox.
	let held = Held { key: a_board, nonce: record.owner_nonce, id: board_id, record: CoinRecord::Board(record) };
	let policy = r.policy();
	let bases = vec![board_tx.clone()];
	let coin = held.record.resolve(&bases, &policy).unwrap();
	let (b_key, a_change) = (keypair("B's leaf"), keypair("A's change"));
	let (b_leaf, _) = new_leaf(&b_key);
	let (c_leaf, c_nonce) = new_leaf(&a_change);
	let kept = VALUE - 2_000;
	let mut body = transfer_body(&[(&held, coin.clone(), kept)], &[(r.x, 600_000, b_leaf), (r.x, kept - 600_000 - 2_000, c_leaf)], s, r.chain);
	body["outputs"][0]["mailbox"] = json!(hex(&xonly(&b_mailbox).serialize()));
	body["outputs"][1]["mailbox"] = json!(hex(&xonly(&a_mailbox).serialize()));
	let done = r.http.post("cosign_transfer", &body).ok();
	let change_id: LeafId = done["outputs"][1]["leaf_id"].as_str().unwrap().parse().unwrap();
	let all = served(&r, &a_mailbox, 100);
	assert_eq!(all.len(), 2);
	// The board, spent, with A's own checkpoint signature over it.
	let e = entry(&all, &board_id);
	assert_eq!(e["state"], "spent");
	let t = &e["given"][0]["transfer"];
	assert_eq!((t["transfer_id"].as_str(), t["state"].as_str()), (done["transfer_id"].as_str(), Some("signed")));
	let cp: u64 = t["checkpoint_value"].as_str().unwrap().parse().unwrap();
	let plan = TransferPlan { inputs: vec![(coin.clone(), cp)], outputs: vec![] };
	assert!(verify_digest(&sig(&t["checkpoint_sig"]), &plan.checkpoint_message(0).unwrap().digest, &xonly(&a_board)),
		"the checkpoint signature served is A's own over its board's move into its checkpoint");
	// The change, with the transfer and the head its signature was recorded at.
	let e = entry(&all, &change_id);
	assert_eq!((e["kind"].as_str(), e["state"].as_str(), e["owner_nonce"].as_str()), (Some("transfer"), Some("live"), Some(hex(&c_nonce).as_str())));
	assert_eq!(e["made_by"]["transfer_id"], done["transfer_id"]);
	assert_eq!(e["made_by"]["signer_record"], done["signer_record"], "the head the transfer was recorded at, as its answer gave it");
	// B's coin to B's mailbox, and nothing of A's.
	let b_all = served(&r, &b_mailbox, 100);
	assert_eq!(b_all.len(), 1);
	assert_eq!(b_all[0]["leaf_id"], done["outputs"][0]["leaf_id"]);

	// A refreshes its change, the new leaf bound to its mailbox key.
	let a_new = keypair("A's new leaf");
	let change = Held { key: a_change, nonce: c_nonce, id: change_id,
		record: CoinRecord::from_bytes(&unhex(done["outputs"][1]["record"].as_str().unwrap())).unwrap() };
	let change_value = change.record.resolve(&bases, &policy).unwrap().value;
	let (w, new_nonce) = want_leaf(&a_new, r.x, change_value);
	let (mut pbody, pid) = participation_body(&[&change], &[w.clone()], &[], None, s, r.chain);
	// A binding signed by another key than the leaf's is refused.
	pbody["outputs"][0]["leaf"]["mailbox"] = json!(hex(&xonly(&a_mailbox).serialize()));
	pbody["outputs"][0]["leaf"]["mailbox_proof"] = json!(proof(&r, &stranger, &xonly(&a_mailbox)));
	refused(r.http.post("submit_participation", &pbody), 422, "bad_signature");
	pbody["outputs"][0]["leaf"]["mailbox_proof"] = json!(proof(&r, &a_new, &xonly(&a_mailbox)));
	assert_eq!(r.http.post("submit_participation", &pbody).ok()["state"], "pending");
	let all = served(&r, &a_mailbox, 100);
	let e = entry(&all, &change_id);
	let p = &e["given"][0]["participation"];
	assert_eq!((p["participation_id"].as_str(), p["state"].as_str(), p["returned"].as_bool()), (Some(hex(&pid).as_str()), Some("pending"), Some(false)));
	// Every part of the id is served: the owner recomputes it and finds its
	// own attestation over it.
	let outs: Vec<OutputRequest> = p["outputs"].as_array().unwrap().iter().map(|o| {
		let l = &o["leaf"];
		OutputRequest::Leaf {
			asset: l["asset"].as_str().unwrap().parse().unwrap(), value: l["value"].as_str().unwrap().parse().unwrap(),
			template: l["template"].as_str().unwrap().parse::<Template>().unwrap(),
			owner: XOnlyPublicKey::from_slice(&unhex(l["owner"].as_str().unwrap())).unwrap(),
			owner_nonce: unhex(l["owner_nonce"].as_str().unwrap()).try_into().unwrap(),
			exit_delay: RelativeTime::from_units(l["exit_delay_units"].as_u64().unwrap() as u16).unwrap(),
		}
	}).collect();
	assert_eq!(outs, vec![w]);
	let ins: Vec<LeafId> = p["inputs"].as_array().unwrap().iter().map(|i| i.as_str().unwrap().parse().unwrap()).collect();
	let id = server::participations::participation_id(&r.chain, &s, &ins, &outs, &[], p["not_before"].as_u64().map(|t| MedianTime::from_consensus(t as u32).unwrap()));
	assert_eq!(id, pid);
	assert!(verify_digest(&sig(&p["attestation"]), &id, &xonly(&a_change)), "the attestation served is A's own over the id");
	assert_eq!(p["forfeits"], json!([]));

	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let (new_valid, new_record, round) = validate_new_leaf(&r, &pid, 0, &a_new, &new_nonce);
	let all = served(&r, &a_mailbox, 100);
	let e = entry(&all, &new_valid.leaf_id);
	assert_eq!(e["record"], "", "a round's leaf is served without its record until its participation's preimage went out");
	assert_eq!(e["owner_nonce"], hex(&new_nonce));
	assert_eq!((e["batch"]["round_txid"].as_str(), e["batch"]["participation_id"].as_str()), (Some(built.tx.txid().to_string().as_str()),
		Some(hex(&pid).as_str())));
	let st = status(&r, &pid);
	assert_eq!(e["batch"]["batch_vout"], st["outputs"][0]["batch_vout"]);
	assert_eq!(e["batch"]["leaf_index"], st["outputs"][0]["leaf_index"]);
	assert!(e["batch"]["signer_record"]["signature"].is_string(), "the head of the signer's record when the round was built: {}", e);

	// The forfeit handed over: served with the owner's half, which A checks
	// is its own; the new leaf's record served once the preimage went out.
	let old = change.record.resolve(&bases, &policy).unwrap();
	let f = forfeit_for(&old, &new_valid, &round, &st);
	let fdone = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&pid),
		"forfeits": [{"leaf_id": change_id.to_string(), "signature": forfeit_sig(&f, &a_change)}],
		"leaves": [auths_json(&new_valid, &a_new, created(&new_record))]})).ok();
	assert_eq!(fdone["state"], "released");
	let all = served(&r, &a_mailbox, 100);
	let e = entry(&all, &change_id);
	assert_eq!(e["state"], "spent");
	let p = &e["given"][0]["participation"];
	assert_eq!(p["state"], "released");
	let ff = &p["forfeits"][0];
	assert_eq!((ff["round_txid"].as_str(), ff["cosigned"].as_bool()), (Some(built.tx.txid().to_string().as_str()), Some(true)));
	assert_eq!(ff["connector_vout"], st["round"]["connector_vout"]);
	assert!(verify_digest(&sig(&ff["owner_sig"]), &f.message().digest, &xonly(&a_change)), "the forfeit's half served is A's own");
	let e = entry(&all, &new_valid.leaf_id);
	assert_eq!(e["state"], "live");
	match CoinRecord::from_bytes(&unhex(e["record"].as_str().unwrap())).unwrap() {
		CoinRecord::Leaf { record, preimage, .. } => {
			assert_eq!(record, new_record);
			assert_eq!(hex(&preimage), fdone["preimage"].as_str().unwrap());
		},
		other => panic!("a round's leaf served as {:?}", other),
	}

	// Paging: one leaf a page, the same leaves in the same order; a page's
	// proof is good for that page alone.
	let one = served(&r, &a_mailbox, 1);
	assert_eq!(one, all);
	assert_eq!(all.len(), 3);
	let request = server::auth::mailbox_read_request(0, 1);
	let good = r.http.auth_for("leaf_data", &a_mailbox, &r.chain, &request);
	for (after, limit) in [("1", 1), ("0", 2)] {
		refused(r.http.post("leaf_data", &json!({"auth": good, "after": after, "limit": limit})), 401, "unauthenticated");
	}
	// A request naming no page reads the first, its proof over nothing.
	let first = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", &a_mailbox, &r.chain)})).ok();
	assert_eq!(first["leaves"].as_array().unwrap().len(), 3);
	// A leaf's own key is served that leaf alone, as before.
	let own = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", &a_new, &r.chain)})).ok();
	assert_eq!(own["leaves"].as_array().unwrap().len(), 1);
	assert_eq!(own["leaves"][0]["leaf_id"], json!(new_valid.leaf_id.to_string()));

	// bind_mailbox: B's leaf, made without a binding, bound now to another
	// mailbox of B's; a key the server knows no leaf of binds nothing; a proof
	// by another key, and too many at once, are refused.
	let b2 = keypair("B's second mailbox");
	let bound = r.http.post("bind_mailbox", &json!({"bindings": [
		{"owner": hex(&xonly(&b_key).serialize()), "mailbox": hex(&xonly(&b2).serialize()), "proof": proof(&r, &b_key, &xonly(&b2))},
		{"owner": hex(&xonly(&stranger).serialize()), "mailbox": hex(&xonly(&b2).serialize()), "proof": proof(&r, &stranger, &xonly(&b2))},
	]})).ok();
	assert_eq!(bound["bound"][0]["mailbox"], hex(&xonly(&b2).serialize()));
	assert!(bound["bound"][1]["mailbox"].is_null(), "{}", bound);
	assert_eq!(served(&r, &b2, 100).len(), 1);
	// One owner key, one binding: an earlier one stands.
	let again = r.http.post("bind_mailbox", &json!({"bindings": [
		{"owner": hex(&xonly(&b_key).serialize()), "mailbox": hex(&xonly(&stranger).serialize()), "proof": proof(&r, &b_key, &xonly(&stranger))},
	]})).ok();
	assert_eq!(again["bound"][0]["mailbox"], hex(&xonly(&b2).serialize()));
	assert!(served(&r, &stranger, 100).is_empty());
	refused(r.http.post("bind_mailbox", &json!({"bindings": [
		{"owner": hex(&xonly(&b_key).serialize()), "mailbox": hex(&xonly(&b2).serialize()), "proof": proof(&r, &stranger, &xonly(&b2))},
	]})), 422, "bad_signature");
	let many: Vec<Value> = (0..65).map(|_| json!({"owner": hex(&xonly(&b_key).serialize()), "mailbox": hex(&xonly(&b2).serialize()),
		"proof": proof(&r, &b_key, &xonly(&b2))})).collect();
	refused(r.http.post("bind_mailbox", &json!({"bindings": many})), 400, "malformed");
	println!("A's mailbox key is served its board (spent), its change (spent) and its new leaf (live); B's, its leaf");
}

#[tokio::test(flavor = "multi_thread")]
async fn reads_are_answered_at_a_bounded_rate_for_each_source() {
	let r = Running::start_with(|c, _| {
		c.limits.read_source_per_second = 1;
		c.limits.read_source_burst = 3;
	}).await;
	let k = keypair("a reader");
	let mut statuses = vec![];
	for _ in 0..4 {
		statuses.push(r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", &k, &r.chain)})).status);
	}
	assert_eq!(statuses, vec![200, 200, 200, 429], "the fourth read in a second is refused");
	let a = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", &k, &r.chain)}));
	let m = refused(a, 429, "rate_limited");
	assert!(m.contains("try again in"), "{}", m);
	tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
	assert_eq!(r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", &k, &r.chain)})).status, 200, "one more a second later");
}
