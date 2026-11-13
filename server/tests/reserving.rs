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

/// The settled cursor of the first leaf served to `key`.
fn first_cursor(r: &Running, key: &Keypair) -> String {
	let request = server::auth::leaf_since_request("0", 1, &[], &[]);
	let page = r.http.post("leaf_data", &json!({"auth": r.http.auth_for("leaf_data", key, &r.chain, &request), "since": "0", "limit": 1})).ok();
	page["next"].as_str().unwrap().to_string()
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
	let plan = TransferPlan { checkpoint_exit: false, inputs: vec![(coin.clone(), cp)], outputs: vec![] };
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
			order: None,
			landing: None,
			channel: None,
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

	// Reads past a settled cursor: the same leaves, a page at a time, each
	// page's proof bound to its cursor, size, held coins and ids; the held
	// coins' states, with the whole entry of one given up for good; leaves
	// asked by id; nothing of a leaf not served to the key.
	let info = r.http.get("info").ok();
	assert_eq!((&info["leaf_data"]["page"], &info["leaf_data"]["held"], &info["leaf_data"]["leaf_ids"]), (&json!(100), &json!(400), &json!(100)));
	let settled = |since: &str, limit: u32, held: &[[u8; 32]], ids: &[[u8; 32]]| {
		let request = server::auth::leaf_since_request(since, limit, held, ids);
		r.http.post("leaf_data", &json!({"auth": r.http.auth_for("leaf_data", &a_mailbox, &r.chain, &request), "since": since, "limit": limit,
			"held": held.iter().map(|h| hex(h)).collect::<Vec<_>>(), "leaf_ids": ids.iter().map(|h| hex(h)).collect::<Vec<_>>()}))
	};
	// From "0", every leaf from the base tables, a page at a time, each
	// cursor a read from the first under way ("<epoch>:W…"), ending on a
	// settled cursor.
	let whole_on = |c: &str| c.split(':').nth(1).is_some_and(|c| c.starts_with('W'));
	let mut since = "0".to_string();
	let mut paged = vec![];
	loop {
		let page = settled(&since, 1, &[], &[]).ok();
		let leaves = page["leaves"].as_array().unwrap().clone();
		since = page["next"].as_str().unwrap().to_string();
		paged.extend(leaves.clone());
		if !whole_on(&since) {
			assert!(leaves.is_empty(), "a page of one, full, reads on: {}", page);
			break;
		}
		assert_eq!(leaves.len(), 1, "{}", page);
	}
	assert!(since.contains('.'), "a read from the first leaf ends on a settled cursor: {}", since);
	assert_eq!(paged, all, "the same leaves, in the same order, read from the first");
	let epoch = info["leaf_data"]["epoch"].as_str().unwrap().to_string();
	// Past the settled cursor of A's first leaf ("<epoch>:0.0"), from
	// `leaf_served`: the same leaves.
	let mut past = format!("{}:0.0", epoch);
	let mut paged = vec![];
	loop {
		let page = settled(&past, 1, &[], &[]).ok();
		let Some(l) = page["leaves"].as_array().unwrap().first().cloned() else {
			assert!(page["next"].is_null(), "{}", page);
			break;
		};
		past = page["next"].as_str().unwrap().to_string();
		assert!(past.contains('.') && !whole_on(&past), "a settled cursor names the making transaction and the seq: {}", past);
		paged.push(l);
	}
	assert_eq!(paged, all, "the same leaves, in the same order, past a settled cursor");
	let stranger_leaf = [0x5a; 32];
	let page = settled(&since, 100, &[change_id.0, new_valid.leaf_id.0, stranger_leaf], &[new_valid.leaf_id.0]).ok();
	assert!(page["leaves"].as_array().unwrap().is_empty(), "nothing past the end: {}", page);
	let held = page["held"].as_array().unwrap();
	assert_eq!(held.len(), 2, "a leaf not served to the key is not answered: {}", page);
	let of = |id: &LeafId| held.iter().find(|h| h["leaf_id"] == json!(id.to_string())).unwrap().clone();
	assert_eq!((of(&change_id)["state"].as_str(), of(&change_id)["given"].as_bool()), (Some("spent"), Some(true)));
	assert_eq!((of(&new_valid.leaf_id)["state"].as_str(), of(&new_valid.leaf_id)["given"].as_bool()), (Some("live"), Some(false)));
	let asked: Vec<&Value> = page["asked"].as_array().unwrap().iter().collect();
	assert_eq!(asked.len(), 2, "the coin given up for good and the leaf asked by id, whole: {}", page);
	assert_eq!(*asked.iter().find(|e| e["leaf_id"] == json!(change_id.to_string())).unwrap(), entry(&all, &change_id));
	assert_eq!(*asked.iter().find(|e| e["leaf_id"] == json!(new_valid.leaf_id.to_string())).unwrap(), entry(&all, &new_valid.leaf_id));
	// Neither list crowds out the other: a hundred leaves asked by id (the
	// most a read takes) and the coin given up for good are all answered.
	let mut hundred: Vec<[u8; 32]> = (0..99u8).map(|i| [i ^ 0xa5; 32]).collect();
	hundred.push(new_valid.leaf_id.0);
	let page = settled(&since, 100, &[change_id.0], &hundred).ok();
	let asked: Vec<&str> = page["asked"].as_array().unwrap().iter().filter_map(|e| e["leaf_id"].as_str()).collect();
	assert!(asked.contains(&change_id.to_string().as_str()) && asked.contains(&new_valid.leaf_id.to_string().as_str()),
		"the coin given up for good and the leaf by id, with a hundred ids asked: {:?}", asked);

	// The settled cursor orders and compares transaction ids as numbers: A's
	// leaves made by transactions 8, 9 and 10 (in that order; "10" sorts
	// before "8" as text) are each served once, in that order, a page of one
	// at a time.
	let since = {
		let (sql, conn) = tokio_postgres::connect(&r.db.url, tokio_postgres::NoTls).await.unwrap();
		tokio::spawn(conn);
		for (i, e) in all.iter().enumerate() {
			sql.execute("UPDATE leaf_served SET served_xid = $2::text::xid8 WHERE leaf_id = decode($1, 'hex') AND mailbox_key = $3",
				&[&e["leaf_id"].as_str().unwrap(), &(8 + i).to_string(), &&xonly(&a_mailbox).serialize()[..]]).await.unwrap();
		}
		let mut since = format!("{}:0.0", epoch);
		let mut read = vec![];
		loop {
			let page = settled(&since, 1, &[], &[]).ok();
			let Some(l) = page["leaves"].as_array().unwrap().first().cloned() else { break };
			since = page["next"].as_str().unwrap().to_string();
			read.push(l);
			assert!(read.len() <= all.len(), "a leaf served twice: {:?}", read);
		}
		assert_eq!(read, all, "every leaf once, in order, across 9 to 10");
		// The leaves' cursors as transactions 9 and 10 with their seq: past
		// 9, the leaf of 10 alone.
		assert_eq!(epoch.len(), 16, "{}", info["leaf_data"]);
		assert!(since.starts_with(&format!("{}:", epoch)), "a cursor names its epoch: {}", since);
		let past = settled(&format!("{}:9.{}", epoch, all[1]["cursor"].as_str().unwrap()), 100, &[], &[]).ok();
		assert_eq!(past["leaves"].as_array().unwrap().len(), 1, "{}", past);

		// A database restored from a dump starts its transaction counter
		// again: the server, starting on it, finds its counter behind the
		// transactions its leaves were served at, and starts a new epoch, its
		// leaves served at transaction 0. A cursor of the old epoch reads from
		// the first leaf.
		sql.execute("UPDATE leaf_served SET served_xid = '9000000000000'::xid8 WHERE mailbox_key = $1",
			&[&&xonly(&a_mailbox).serialize()[..]]).await.unwrap();
		let new_epoch = r.db.store.cursor_epoch_at_start().await.unwrap();
		assert_ne!(hex(&new_epoch), epoch, "a new epoch");
		assert_eq!(r.http.get("info").ok()["leaf_data"]["epoch"], json!(hex(&new_epoch)));
		let left: i64 = sql.query_one("SELECT count(*) FROM leaf_served WHERE served_xid <> '0'::xid8", &[]).await.unwrap().get(0);
		assert_eq!(left, 0, "every served transaction set to 0");
		let again = settled(&since, 100, &[], &[]).ok();
		assert_eq!(again["leaves"].as_array().unwrap().len(), all.len(), "a cursor of the old epoch reads from the first leaf: {}", again);
		assert!(again["next"].as_str().unwrap().starts_with(&hex(&new_epoch)), "{}", again);
		// The server starting again on it keeps the epoch.
		assert_eq!(r.db.store.cursor_epoch_at_start().await.unwrap(), new_epoch);

		// The database's identity (its cluster's system identifier and its
		// timeline) is kept beside the epoch: none kept yet (as the
		// migration leaves it) keeps the epoch and keeps the identity; another
		// one kept (a restore into another cluster, a recovery to an earlier
		// point, a standby promoted) starts a new epoch.
		let sqlr = &sql;
		let identity = move || async move {
			sqlr.query_one("SELECT identity FROM leaf_cursor_epoch", &[]).await.unwrap().get::<_, Option<String>>(0)
		};
		sql.execute("UPDATE leaf_cursor_epoch SET identity = NULL", &[]).await.unwrap();
		assert_eq!(r.db.store.cursor_epoch_at_start().await.unwrap(), new_epoch, "no identity kept: the epoch stands");
		let real = identity().await.expect("the identity is kept");
		assert!(real.contains('/'), "{}", real);
		sql.execute("UPDATE leaf_cursor_epoch SET identity = 'another cluster/00000001'", &[]).await.unwrap();
		let third = r.db.store.cursor_epoch_at_start().await.unwrap();
		assert_ne!(third, new_epoch, "another identity: a new epoch");
		assert_eq!(identity().await, Some(real.clone()), "the identity kept is the database's");
		assert_eq!(r.db.store.cursor_epoch_at_start().await.unwrap(), third, "and stands at the next start");
		let after_move = settled(again["next"].as_str().unwrap(), 100, &[], &[]).ok();
		assert_eq!(after_move["leaves"].as_array().unwrap().len(), all.len(), "a cursor of the epoch before reads from the first leaf");

		// The read from the first leaf comes from the base tables, never from
		// `leaf_served` alone: a row lost from it (deleted by hand) is served
		// at the next read from the first leaf, and kept again, at that read's
		// transaction, so a read past a cursor taken before serves it too.
		let whole = || {
			let mut c = "0".to_string();
			let mut ids = vec![];
			loop {
				let page = settled(&c, 100, &[], &[]).ok();
				ids.extend(page["leaves"].as_array().unwrap().iter().map(|l| l["leaf_id"].as_str().unwrap().to_string()));
				c = page["next"].as_str().unwrap().to_string();
				if !whole_on(&c) {
					return (ids, c);
				}
			}
		};
		let (_, before) = whole();
		let lost = all[0]["leaf_id"].as_str().unwrap().to_string();
		let mailbox = xonly(&a_mailbox).serialize();
		let (mailboxr, lostr) = (&mailbox, &lost);
		let rows = move || async move {
			sqlr.query_one("SELECT count(*) FROM leaf_served WHERE mailbox_key = $1 AND leaf_id = decode($2, 'hex')", &[&&mailboxr[..], lostr])
				.await.unwrap().get::<_, i64>(0)
		};
		sql.execute("DELETE FROM leaf_served WHERE mailbox_key = $1 AND leaf_id = decode($2, 'hex')", &[&&mailbox[..], &lost]).await.unwrap();
		assert_eq!(rows().await, 0);
		let past_lost = settled(&format!("{}:0.0", hex(&third)), 100, &[], &[]).ok();
		assert!(past_lost["leaves"].as_array().unwrap().iter().all(|l| l["leaf_id"] != json!(lost)), "the index lost it: {}", past_lost);
		let (ids, end) = whole();
		assert!(ids.contains(&lost), "the read from the first leaf serves the leaf the index lost: {:?}", ids);
		assert_eq!(ids.len(), all.len());
		assert_eq!(rows().await, 1, "and keeps it again");
		let repaired = settled(&before, 100, &[], &[]).ok();
		let repaired: Vec<&str> = repaired["leaves"].as_array().unwrap().iter().filter_map(|l| l["leaf_id"].as_str()).collect();
		assert_eq!(repaired, vec![lost.as_str()], "kept again past every cursor: a read past one taken before serves it");
		// A's end, in the latest epoch: what the late binding below reads past.
		end
	};

	// The proof binds every part of the read.
	let request = server::auth::leaf_since_request("0", 1, &[change_id.0], &[]);
	let good = r.http.auth_for("leaf_data", &a_mailbox, &r.chain, &request);
	for (since, limit, held, ids) in [("0", 2, vec![hex(&change_id.0)], vec![]), ("0", 1, vec![], vec![]), ("0", 1, vec![], vec![hex(&change_id.0)]),
		(first_cursor(&r, &a_mailbox).as_str(), 1, vec![hex(&change_id.0)], vec![])]
	{
		refused(r.http.post("leaf_data", &json!({"auth": good, "since": since, "limit": limit, "held": held, "leaf_ids": ids})), 401,
			"unauthenticated");
	}
	// A cursor and a settled cursor together, held coins without a settled
	// cursor, a cursor that does not read, too many held: refused.
	refused(r.http.post("leaf_data", &json!({"auth": good, "since": "0", "after": "0", "limit": 1})), 400, "malformed");
	refused(r.http.post("leaf_data", &json!({"auth": good, "after": "0", "limit": 1, "held": [hex(&change_id.0)]})), 400, "malformed");
	refused(r.http.post("leaf_data", &json!({"auth": good, "since": "seven", "limit": 1})), 400, "malformed");
	// A cursor longer than a cursor can be is refused, so no proof stands for
	// a cursor longer than it binds.
	let long = format!("{}:{}.1", "00".repeat(8), "0".repeat(60));
	refused(r.http.post("leaf_data", &json!({"auth": good, "since": long, "limit": 1})), 400, "malformed");
	let many: Vec<String> = (0..401u32).map(|i| hex(&[(i % 251) as u8; 32])).collect();
	refused(r.http.post("leaf_data", &json!({"auth": good, "since": "0", "limit": 1, "held": many})), 400, "malformed");

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
	// B's leaf came to be served to B's second mailbox with its binding, made
	// after every leaf of A's: a read past a settled cursor reached before the
	// binding (A's last, past B's leaf by when it was made) serves it.
	let request = server::auth::leaf_since_request(&since, 100, &[], &[]);
	let late = r.http.post("leaf_data", &json!({"auth": r.http.auth_for("leaf_data", &b2, &r.chain, &request), "since": since, "limit": 100})).ok();
	let late: Vec<&str> = late["leaves"].as_array().unwrap().iter().filter_map(|l| l["leaf_id"].as_str()).collect();
	assert_eq!(late.len(), 1, "a leaf bound after the cursor is read past it: {:?}", late);
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

#[tokio::test(flavor = "multi_thread")]
async fn the_published_tree_lists_every_node_and_each_preimage_once_it_went_out() {
	let mut r = common::rounds::start().await;
	let s = xonly(&r.s);
	let (a, b) = (keypair("A's board for the tree"), keypair("B's board for the tree"));
	let x = r.x;
	let (a_coin, a_tx) = common::rounds::credited_board(&mut r, &a, x).await;
	let (b_coin, b_tx) = common::rounds::credited_board(&mut r, &b, x).await;
	let (a_new, b_new) = (keypair("A's leaf in the tree"), keypair("B's leaf in the tree"));
	let (wa, na) = want_leaf(&a_new, r.x, VALUE);
	let (wb, nb) = want_leaf(&b_new, r.x, VALUE);
	let (pa, ida) = participation_body(&[&a_coin], &[wa], &[], None, s, r.chain);
	let (pb, idb) = participation_body(&[&b_coin], &[wb], &[], None, s, r.chain);
	r.http.post("submit_participation", &pa).ok();
	r.http.post("submit_participation", &pb).ok();
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;

	// rounds lists the round with its batch; a page of one, then nothing.
	let list = r.http.post("rounds", &json!({})).ok();
	let mine: Vec<&Value> = list["rounds"].as_array().unwrap().iter().filter(|x| x["txid"] == built.tx.txid().to_string()).collect();
	assert_eq!(mine.len(), 1, "{}", list);
	assert_eq!(mine[0]["state"], "final");
	let vout = mine[0]["batches"][0].as_u64().unwrap();
	let after = mine[0]["cursor"].as_str().unwrap().to_string();
	let rest = r.http.post("rounds", &json!({"after": after, "limit": 1})).ok();
	assert_eq!(rest["rounds"], json!([]));
	assert!(rest["next"].is_null());

	let published = r.http.post("tree", &json!({"txid": built.tx.txid().to_string(), "vout": vout})).ok();
	assert_eq!(published["round_state"], "final");
	let tree = common::client::rebuild(&published);
	// Every node as the tree builds it, level by level.
	let levels = published["nodes"].as_array().unwrap();
	assert_eq!(levels.len(), tree.levels().len());
	for (shown, built_level) in levels.iter().zip(tree.levels()) {
		for (n, b) in shown.as_array().unwrap().iter().zip(built_level) {
			assert_eq!(n["value"], b.value.to_string());
			assert_eq!(n["reserve"], b.reserve.to_string());
			assert_eq!(n["script_pubkey"], hex(b.output().script_pubkey.as_bytes()));
			assert_eq!(n["children"], json!([b.children.start, b.children.end]));
		}
	}
	assert_eq!(levels.last().unwrap()[0]["script_pubkey"], hex(built.tx.output[vout as usize].script_pubkey.as_bytes()),
		"the last level is the batch output the round pays");
	// Each leaf's id and script; no preimage before any went out.
	for (l, rec) in published["leaves"].as_array().unwrap().iter().zip(tree.records()) {
		assert_eq!(l["leaf_id"], rec.leaf_id().unwrap().to_string());
		assert!(l["preimage"].is_null(), "no preimage before its participation's went out: {}", l);
	}
	// A hands over its forfeit: its leaf's preimage is published, B's is not.
	let st = status(&r, &ida);
	let (va, ra, round) = validate_new_leaf(&r, &ida, 0, &a_new, &na);
	let old = a_coin.record.resolve(&[a_tx.clone()], &r.policy()).unwrap();
	let f = forfeit_for(&old, &va, &round, &st);
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&ida),
		"forfeits": [{"leaf_id": a_coin.id.to_string(), "signature": forfeit_sig(&f, &a)}],
		"leaves": [auths_json(&va, &a_new, created(&ra))]})).ok();
	assert_eq!(done["state"], "released");
	let published = r.http.post("tree", &json!({"txid": built.tx.txid().to_string(), "vout": vout})).ok();
	let ia = st["outputs"][0]["leaf_index"].as_u64().unwrap() as usize;
	let ib = status(&r, &idb)["outputs"][0]["leaf_index"].as_u64().unwrap() as usize;
	assert_eq!(published["leaves"][ia]["preimage"], done["preimage"]);
	assert!(published["leaves"][ib]["preimage"].is_null(), "B's forfeit has not come: its preimage stays the operator's");
	// From the published tree alone, A's leaf: the record the tree gives, the
	// preimage it publishes, A's own authorisations made again; it validates
	// against the round as the leaf A first took.
	let record = common::client::rebuild(&published).record(ia);
	let preimage: [u8; 32] = unhex(published["leaves"][ia]["preimage"].as_str().unwrap()).try_into().unwrap();
	let auths: Vec<_> = va.branch.nodes.iter().map(|n| (sign_digest(&a_new, &n.unroll_authorisation(created(&record)).digest, &random32()),
		created(&record))).collect();
	let coin = CoinRecord::Leaf { record, preimage, auths };
	let v = coin.validate(&[round.clone()], &r.policy(), &xonly(&a_new), &na).unwrap();
	assert_eq!(v.id, va.leaf_id);
	let _ = (b_tx, nb);
	println!("published tree of {}:{}: {} levels of nodes; A's preimage out, B's not", built.tx.txid(), vout, levels.len());
}

/// A leaf, and its owner key's binding to a mailbox, inserted by two
/// transactions open at once, kept for the mailbox (`leaf_served`) whichever
/// commits first: each trigger waits for the other's transaction on the
/// claim of the owner key, then reads its row.
#[tokio::test(flavor = "multi_thread")]
async fn a_leaf_and_its_binding_made_at_once_are_served_to_the_mailbox() {
	let db = common::db::TestDb::new().await;
	for (round, leaf_first_commit) in [(1u8, true), (2u8, false)] {
		let (owner, mailbox, leaf_id) = ([round; 32], [round ^ 0xf0; 32], [round ^ 0x0f; 32]);
		let connect = || async {
			let (c, conn) = tokio_postgres::connect(&db.url, tokio_postgres::NoTls).await.unwrap();
			tokio::spawn(conn);
			c
		};
		let (t1, t2) = (connect().await, connect().await);
		t1.batch_execute("BEGIN").await.unwrap();
		t1.execute("INSERT INTO arca_script (script_pubkey, kind, leaf_id) VALUES ($1, 'leaf', $2)", &[&&leaf_id[..], &&leaf_id[..]]).await.unwrap();
		t1.execute("INSERT INTO leaf (leaf_id, kind, asset, value, owner_key, script_pubkey, hops, record, state)
			VALUES ($1, 'batch', $2, 1000, $3, $1, 0, '\\x00', 'live')", &[&&leaf_id[..], &&[7u8; 32][..], &&owner[..]]).await.unwrap();
		t2.batch_execute("BEGIN").await.unwrap();
		// The binding's trigger waits on the claim of the owner key while the leaf's
		// transaction is open: insert it in a task of its own.
		let t2 = std::sync::Arc::new(t2);
		let t2b = t2.clone();
		let bind = tokio::spawn(async move {
			t2b.execute("INSERT INTO leaf_mailbox (owner_key, mailbox_key, proof) VALUES ($1, $2, $3)",
				&[&&owner[..], &&mailbox[..], &&[9u8; 64][..]]).await.unwrap();
		});
		tokio::time::sleep(std::time::Duration::from_millis(300)).await;
		if leaf_first_commit {
			t1.batch_execute("COMMIT").await.unwrap();
			bind.await.unwrap();
			t2.batch_execute("COMMIT").await.unwrap();
		} else {
			// The binding cannot commit before the leaf's lock is released:
			// the leaf's transaction commits, then the binding's.
			assert!(!bind.is_finished(), "the binding waits for the leaf's transaction");
			t1.batch_execute("COMMIT").await.unwrap();
			bind.await.unwrap();
			t2.batch_execute("COMMIT").await.unwrap();
		}
		let n: i64 = t1.query_one("SELECT count(*) FROM leaf_served WHERE mailbox_key = $1 AND leaf_id = $2", &[&&mailbox[..], &&leaf_id[..]])
			.await.unwrap().get(0);
		assert_eq!(n, 1, "round {}: the leaf is kept for the mailbox it was bound to meanwhile", round);
	}
	// The other order: the binding's transaction first, the leaf inserted
	// while it is open.
	let (owner, mailbox, leaf_id) = ([3u8; 32], [0xf3u8; 32], [0x0cu8; 32]);
	let (t1, c1) = tokio_postgres::connect(&db.url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(c1);
	let (t2, c2) = tokio_postgres::connect(&db.url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(c2);
	t2.batch_execute("BEGIN").await.unwrap();
	t2.execute("INSERT INTO leaf_mailbox (owner_key, mailbox_key, proof) VALUES ($1, $2, $3)", &[&&owner[..], &&mailbox[..], &&[9u8; 64][..]])
		.await.unwrap();
	t1.batch_execute("BEGIN").await.unwrap();
	t1.execute("INSERT INTO arca_script (script_pubkey, kind, leaf_id) VALUES ($1, 'leaf', $2)", &[&&leaf_id[..], &&leaf_id[..]]).await.unwrap();
	let t1 = std::sync::Arc::new(t1);
	let t1b = t1.clone();
	let make = tokio::spawn(async move {
		t1b.execute("INSERT INTO leaf (leaf_id, kind, asset, value, owner_key, script_pubkey, hops, record, state)
			VALUES ($1, 'batch', $2, 1000, $3, $1, 0, '\\x00', 'live')", &[&&leaf_id[..], &&[7u8; 32][..], &&owner[..]]).await.unwrap();
	});
	tokio::time::sleep(std::time::Duration::from_millis(300)).await;
	assert!(!make.is_finished(), "the leaf waits for the binding's transaction");
	t2.batch_execute("COMMIT").await.unwrap();
	make.await.unwrap();
	t1.batch_execute("COMMIT").await.unwrap();
	let n: i64 = t2.query_one("SELECT count(*) FROM leaf_served WHERE mailbox_key = $1 AND leaf_id = $2", &[&&mailbox[..], &&leaf_id[..]])
		.await.unwrap().get(0);
	assert_eq!(n, 1, "the leaf is kept for the mailbox its key was bound to meanwhile");
	// Keys that are not the same never wait on each other: a transaction
	// holding leaves open (a round's) and one binding other keys (a plan's)
	// each go on at once, in either order.
	t1.batch_execute("BEGIN").await.unwrap();
	t2.batch_execute("BEGIN").await.unwrap();
	let (asset, proof) = ([7u8; 32], [9u8; 64]);
	for (c, i) in [(&*t1, 0x40u8), (&t2, 0x41), (&*t1, 0x42), (&t2, 0x43)] {
		let id = [i; 32];
		let owner = [i ^ 0x80; 32];
		if i % 2 == 0 {
			c.execute("INSERT INTO arca_script (script_pubkey, kind, leaf_id) VALUES ($1, 'leaf', $1)", &[&&id[..]]).await.unwrap();
			c.execute("INSERT INTO leaf (leaf_id, kind, asset, value, owner_key, script_pubkey, hops, record, state)
				VALUES ($1, 'batch', $2, 1000, $3, $1, 0, '\\x00', 'live')", &[&&id[..], &&asset[..], &&owner[..]]).await.unwrap();
		} else {
			let (o, m, p) = (&owner[..], &mailbox[..], &proof[..]);
			let params: [&(dyn tokio_postgres::types::ToSql + Sync); 3] = [&o, &m, &p];
			let t = tokio::time::timeout(std::time::Duration::from_secs(5), c.execute(
				"INSERT INTO leaf_mailbox (owner_key, mailbox_key, proof) VALUES ($1, $2, $3)", &params));
			t.await.expect("a binding of another key does not wait").unwrap();
		}
	}
	t1.batch_execute("COMMIT").await.unwrap();
	t2.batch_execute("COMMIT").await.unwrap();
}

/// A transaction of 20,000 leaves and 20,000 bindings: each trigger claims
/// its owner key with a row (`leaf_served_claim`), not a lock, so the
/// transaction takes no slot of PostgreSQL's shared lock table for them (an
/// advisory lock a key filled it between 12,000 and 14,000 leaves, failing with "out of
/// shared memory"); and every leaf is kept for its key and its mailbox.
#[tokio::test(flavor = "multi_thread")]
async fn a_transaction_of_many_leaves_and_bindings_holds_a_bounded_number_of_locks() {
	let db = common::db::TestDb::new().await;
	let (c, conn) = tokio_postgres::connect(&db.url, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(conn);
	c.batch_execute("BEGIN;
		INSERT INTO arca_script (script_pubkey, kind, leaf_id)
		SELECT decode(lpad(to_hex(i), 64, '0'), 'hex'), 'leaf', decode(lpad(to_hex(i), 64, '0'), 'hex') FROM generate_series(1, 20000) i;
		INSERT INTO leaf (leaf_id, kind, asset, value, owner_key, script_pubkey, hops, record, state)
		SELECT decode(lpad(to_hex(i), 64, '0'), 'hex'), 'batch', decode(repeat('07', 32), 'hex'), 1000,
		       decode(lpad(to_hex(i + 1000000), 64, '0'), 'hex'), decode(lpad(to_hex(i), 64, '0'), 'hex'), 0, '\\x00', 'live'
		FROM generate_series(1, 20000) i;
		INSERT INTO leaf_mailbox (owner_key, mailbox_key, proof)
		SELECT decode(lpad(to_hex(i + 1000000), 64, '0'), 'hex'), decode(lpad(to_hex(i % 7 + 9000000), 64, '0'), 'hex'),
		       decode(repeat('09', 64), 'hex')
		FROM generate_series(1, 20000) i;").await.unwrap();
	let locks: i64 = c.query_one("SELECT count(*) FROM pg_locks WHERE pid = pg_backend_pid()", &[]).await.unwrap().get(0);
	assert!(locks < 100, "{} locks held", locks);
	let claims: i64 = c.query_one("SELECT count(*) FROM leaf_served_claim", &[]).await.unwrap().get(0);
	assert_eq!(claims, 20_000, "one claim a key");
	c.batch_execute("COMMIT").await.unwrap();
	let kept: i64 = c.query_one("SELECT count(*) FROM leaf_served", &[]).await.unwrap().get(0);
	assert_eq!(kept, 40_000, "each leaf kept for its key and for its mailbox");
	let left: i64 = c.query_one("SELECT count(*) FROM leaf_served_claim", &[]).await.unwrap().get(0);
	assert_eq!(left, 0, "each claim deleted when its transaction committed");
	println!("20,000 leaves and 20,000 bindings in one transaction: {} locks held, {} claims, {} rows kept", locks, claims, kept);
}

/// Two transactions claiming the same two owner keys in opposite orders. One
/// key at a time, as the triggers claim, they wait on each other and
/// PostgreSQL aborts one (a deadlock). Every path that claims several keys
/// claims them first, all at once in the keys' order
/// (`leaf_served_claim_all`): the second then waits for the first to end,
/// and both go through. A round's transaction (leaves of K2 then K1) and a
/// plan's (bindings of K1 then K2), each claiming its keys first, both
/// commit, and both leaves are kept for the mailbox. A thousand leaves made
/// leave no claim behind once their transactions end.
#[tokio::test(flavor = "multi_thread")]
async fn claims_of_several_keys_never_wait_on_each_other_in_a_cycle_and_end_with_their_transaction() {
	let db = common::db::TestDb::new().await;
	let connect = || async {
		let (c, conn) = tokio_postgres::connect(&db.url, tokio_postgres::NoTls).await.unwrap();
		tokio::spawn(conn);
		std::sync::Arc::new(c)
	};
	let (k1, k2) = ([0x71u8; 32], [0x72u8; 32]);
	let claim = |c: std::sync::Arc<tokio_postgres::Client>, keys: Vec<[u8; 32]>| tokio::spawn(async move {
		let keys: Vec<&[u8]> = keys.iter().map(|k| &k[..]).collect();
		c.execute("SELECT leaf_served_claim_all($1)", &[&keys]).await.map(|_| ())
	});
	let one = |c: std::sync::Arc<tokio_postgres::Client>, k: [u8; 32]| tokio::spawn(async move {
		c.execute("SELECT leaf_served_claim($1)", &[&&k[..]]).await.map(|_| ())
	});
	let wait = std::time::Duration::from_millis(300);

	// One key at a time, in opposite orders: a deadlock, one aborted.
	let (t1, t2) = (connect().await, connect().await);
	t1.batch_execute("BEGIN").await.unwrap();
	t2.batch_execute("BEGIN").await.unwrap();
	one(t1.clone(), k2).await.unwrap().unwrap();
	one(t2.clone(), k1).await.unwrap().unwrap();
	let a = one(t1.clone(), k1);
	tokio::time::sleep(wait).await;
	let b = one(t2.clone(), k2);
	let (a, b) = (a.await.unwrap(), b.await.unwrap());
	let aborted: Vec<String> = [&a, &b].iter().filter_map(|r| r.as_ref().err())
		.map(|e| e.as_db_error().map(|d| format!("{} {}", d.code().code(), d.message())).unwrap_or_default()).collect();
	assert_eq!(aborted.len(), 1, "one of the two aborted: {:?}", aborted);
	assert!(aborted[0].starts_with("40P01 deadlock detected"), "{:?}", aborted);
	println!("one key at a time, opposite orders: {}", aborted[0]);
	t1.batch_execute("ROLLBACK").await.unwrap();
	t2.batch_execute("ROLLBACK").await.unwrap();

	// All at once, in the keys' order: the second waits, then goes through.
	t1.batch_execute("BEGIN").await.unwrap();
	t2.batch_execute("BEGIN").await.unwrap();
	claim(t1.clone(), vec![k2, k1]).await.unwrap().unwrap();
	let b = claim(t2.clone(), vec![k1, k2]);
	tokio::time::sleep(wait).await;
	assert!(!b.is_finished(), "the second waits for the first");
	t1.batch_execute("COMMIT").await.unwrap();
	b.await.unwrap().expect("no deadlock: the second goes through once the first ends");
	t2.batch_execute("COMMIT").await.unwrap();

	// A round's transaction and a plan's, interleaved, each claiming its keys
	// first: the round inserts leaves of K2 then K1, the plan binds K1 then K2.
	let mailbox = [0x7fu8; 32];
	let (round, plan) = (connect().await, connect().await);
	round.batch_execute("BEGIN").await.unwrap();
	plan.batch_execute("BEGIN").await.unwrap();
	claim(round.clone(), vec![k2, k1]).await.unwrap().unwrap();
	let p = {
		let plan = plan.clone();
		tokio::spawn(async move {
			let keys: Vec<&[u8]> = vec![&k1[..], &k2[..]];
			plan.execute("SELECT leaf_served_claim_all($1)", &[&keys]).await?;
			for k in [k1, k2] {
				plan.execute("INSERT INTO leaf_mailbox (owner_key, mailbox_key, proof) VALUES ($1, $2, $3)",
					&[&&k[..], &&mailbox[..], &&[9u8; 64][..]]).await?;
			}
			Ok::<_, tokio_postgres::Error>(())
		})
	};
	for (i, k) in [(0x81u8, k2), (0x82, k1)] {
		let id = [i; 32];
		round.execute("INSERT INTO arca_script (script_pubkey, kind, leaf_id) VALUES ($1, 'leaf', $1)", &[&&id[..]]).await.unwrap();
		round.execute("INSERT INTO leaf (leaf_id, kind, asset, value, owner_key, script_pubkey, hops, record, state)
			VALUES ($1, 'batch', $2, 1000, $3, $1, 0, '\\x00', 'live')", &[&&id[..], &&[7u8; 32][..], &&k[..]]).await.unwrap();
	}
	tokio::time::sleep(wait).await;
	assert!(!p.is_finished(), "the plan waits for the round");
	round.batch_execute("COMMIT").await.unwrap();
	p.await.unwrap().expect("the plan's bindings go through once the round ends");
	plan.batch_execute("COMMIT").await.unwrap();
	let kept: i64 = round.query_one("SELECT count(*) FROM leaf_served WHERE mailbox_key = $1", &[&&mailbox[..]]).await.unwrap().get(0);
	assert_eq!(kept, 2, "both leaves kept for the mailbox");

	// A thousand leaves, each in its own transaction, and a thousand more in
	// one: no claim left once they end.
	let c = connect().await;
	for i in 0..1000u32 {
		c.batch_execute(&format!("INSERT INTO arca_script (script_pubkey, kind, leaf_id) VALUES (decode(lpad(to_hex({i} + 5000000), 64, '0'), 'hex'), 'leaf',
			decode(lpad(to_hex({i} + 5000000), 64, '0'), 'hex'));
			INSERT INTO leaf (leaf_id, kind, asset, value, owner_key, script_pubkey, hops, record, state)
			VALUES (decode(lpad(to_hex({i} + 5000000), 64, '0'), 'hex'), 'batch', decode(repeat('07', 32), 'hex'), 1000,
			decode(lpad(to_hex({i} + 6000000), 64, '0'), 'hex'), decode(lpad(to_hex({i} + 5000000), 64, '0'), 'hex'), 0, '\\x00', 'live')")).await.unwrap();
	}
	c.batch_execute("BEGIN;
		INSERT INTO arca_script (script_pubkey, kind, leaf_id)
		SELECT decode(lpad(to_hex(i + 7000000), 64, '0'), 'hex'), 'leaf', decode(lpad(to_hex(i + 7000000), 64, '0'), 'hex') FROM generate_series(1, 1000) i;
		INSERT INTO leaf (leaf_id, kind, asset, value, owner_key, script_pubkey, hops, record, state)
		SELECT decode(lpad(to_hex(i + 7000000), 64, '0'), 'hex'), 'batch', decode(repeat('07', 32), 'hex'), 1000,
		       decode(lpad(to_hex(i + 8000000), 64, '0'), 'hex'), decode(lpad(to_hex(i + 7000000), 64, '0'), 'hex'), 0, '\\x00', 'live'
		FROM generate_series(1, 1000) i;
		COMMIT;").await.unwrap();
	let made: i64 = c.query_one("SELECT count(*) FROM leaf", &[]).await.unwrap().get(0);
	let left: i64 = c.query_one("SELECT count(*) FROM leaf_served_claim", &[]).await.unwrap().get(0);
	assert_eq!((made, left), (2002, 0), "no claim outlives its transaction");
	println!("{} leaves made, {} claims left", made, left);
}
