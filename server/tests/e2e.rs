//! The server end to end, as an operator runs it (`arca-signer` in its own
//! process, `Server::start` with its tasks and HTTP listener) on an anchored
//! proof-of-stake regtest chain, driven by the minimal client over HTTP: a
//! board registered, final, credited; a transfer co-signed, delivered through
//! the mailbox, received and validated by the client; and each of the
//! server's rules exercised by a refusal with its reason.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::{OutPoint, Transaction};
use serde_json::{json, Value};

use arca_covenant::{CoinRecord, RelativeTime};
use common::client::{hex, new_leaf, random32, transfer_body, unhex, Held};
use common::keys::{keypair, xonly};
use common::running::{Running, MIN_LEAF};

const VALUE: u64 = 1_000_000;
const MARGIN: u64 = 2_000;

fn refused(a: common::client::Answer, status: i32, code: &str) {
	let (c, m) = a.refusal();
	assert_eq!((a.status, c.as_str()), (status, code), "{}", a.json);
	println!("refused {} {}: {}", status, code, m);
}

/// The cases here pay part of a coin with no change, leaving margins far
/// above the default cap; the bounds themselves are `tests/margins.rs`'s.
fn wide_margins(c: &mut server::server::Config, _: elements::AssetId) {
	c.fees.max_margin_multiple = Some(1_000_000);
}

/// A credited board for `owner`, held as a coin.
async fn credited_board(r: &mut Running, owner: &elements::secp256k1_zkp::Keypair) -> (Held, Transaction) {
	let (record, tx, _) = r.board(owner, VALUE);
	r.produce().await;
	r.bury().await;
	let id = record.leaf_id();
	let http = r.http.clone();
	r.wait("the board to be credited", || http.board_status(&id).json["state"] == "credited").await;
	(Held { key: *owner, nonce: record.owner_nonce, id, record: CoinRecord::Board(record) }, tx)
}

#[tokio::test(flavor = "multi_thread")]
async fn board_transfer_mailbox_and_rules() {
	let mut r = Running::start_with(wide_margins).await;
	let s = xonly(&r.s);

	// info
	let info = r.http.get("info").ok();
	assert_eq!(info["operator"], hex(&s.serialize()));
	assert_eq!(info["genesis_hash"], r.chain.genesis_hash().to_string());
	assert_eq!(info["assets"], json!([{"asset": r.x.to_string(), "min_leaf": MIN_LEAF.to_string(),
		"fees": {"refresh_ppm": 0, "refresh_base": "0", "offboard_ppm": 0, "offboard_base": "0", "lightning_ppm": 0,
			"lightning_base": "0"}}]));
	assert_eq!(info["depth_limit"], 5);
	assert_eq!(info["finality"], json!({"certification": "required", "anchor_depth": 2}));
	println!("info: {}", info);

	// A board, registered over HTTP: pending until final, then credited.
	let a = keypair("A");
	let (record, board_tx, answer) = r.board(&a, VALUE);
	assert_eq!(answer["state"], "pending");
	println!("board registered: {}", answer);
	let id = record.leaf_id();
	r.produce().await;
	r.synced().await;
	let st = r.http.board_status(&id).ok();
	assert_eq!((st["state"].as_str(), st["finality"].as_str()), (Some("pending"), Some("settled")), "{}", st);
	r.bury().await;
	let http = r.http.clone();
	r.wait("the board to be credited", || http.board_status(&id).json["state"] == "credited").await;
	println!("board credited: {}", r.http.board_status(&id).json);
	let a_coin = Held { key: a, nonce: record.owner_nonce, id, record: CoinRecord::Board(record) };

	// A board not yet final cannot be spent off-chain.
	let p = keypair("P");
	let (p_record, _, _) = r.board(&p, VALUE);
	let p_coin = Held { key: p, nonce: p_record.owner_nonce, id: p_record.leaf_id(), record: CoinRecord::Board(p_record) };
	let policy = r.policy();
	let pc = p_coin.record.resolve(&[], &policy).err();
	assert!(pc.is_some(), "its board transaction is not in a block a wallet can see yet");

	// A pays B 600,000 and keeps the rest in a new leaf of its own.
	let bases = vec![board_tx.clone()];
	let a_valid = a_coin.record.resolve(&bases, &policy).unwrap();
	let b = keypair("B");
	let a2 = keypair("A change");
	let (b_leaf, b_nonce) = new_leaf(&b);
	let (a2_leaf, a2_nonce) = new_leaf(&a2);
	let kept = VALUE - MARGIN;
	let outputs = vec![(r.x, 600_000, b_leaf), (r.x, kept - 600_000 - MARGIN, a2_leaf)];
	let body = transfer_body(&[(&a_coin, a_valid.clone(), kept)], &outputs, s, r.chain);
	let done = r.http.post("cosign_transfer", &body).ok();
	println!("co-signed: transfer {} into {} new leaves", done["transfer_id"], done["outputs"].as_array().unwrap().len());
	// The same request again: the same answer.
	let again = r.http.post("cosign_transfer", &body).ok();
	assert_eq!(again, done);

	// B collects it from its mailbox and validates it as a receiver.
	let mail = r.http.mailbox(&b, &r.chain, 0);
	assert_eq!(mail.len(), 1);
	let (cursor, b_id, b_record) = mail[0].clone();
	let b_valid = b_record.validate(&bases, &policy, &xonly(&b), &b_nonce).unwrap();
	assert_eq!(b_valid.id, b_id);
	assert_eq!((b_valid.asset, b_valid.value, b_valid.hops), (r.x, 600_000, 1));
	b_valid.check_boards(|op| r.unspent(op)).unwrap();
	assert!(r.http.mailbox(&b, &r.chain, cursor).is_empty(), "nothing after the cursor");
	println!("B received {} and validated it: {} atoms of X, {} hop, its board unspent", b_id, b_valid.value, b_valid.hops);
	// A's change, from the answer, validates for A too.
	let a2_record = CoinRecord::from_bytes(&unhex(done["outputs"][1]["record"].as_str().unwrap())).unwrap();
	a2_record.validate(&bases, &policy, &xonly(&a2), &a2_nonce).unwrap();
	let b_coin = Held { key: b, nonce: b_nonce, id: b_id, record: b_record };

	// leaf_data re-serves B's leaf to B.
	let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", &b, &r.chain)})).ok();
	assert_eq!(ld["leaves"].as_array().unwrap().len(), 1);
	assert_eq!(ld["leaves"][0]["leaf_id"], b_id.to_string());
	assert_eq!(ld["leaves"][0]["state"], "live");
	assert_eq!(CoinRecord::from_bytes(&unhex(ld["leaves"][0]["record"].as_str().unwrap())).unwrap(), b_coin.record);
	let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", &a, &r.chain)})).ok();
	assert_eq!(ld["leaves"][0]["state"], "spent");
	println!("leaf_data: B's leaf live, A's board spent");

	// --- Refusals ---

	// A second spend of A's board, to another receiver.
	let c = keypair("C");
	let (c_leaf, _) = new_leaf(&c);
	let body2 = transfer_body(&[(&a_coin, a_valid.clone(), kept)], &[(r.x, 500_000, c_leaf)], s, r.chain);
	refused(r.http.post("cosign_transfer", &body2), 409, "double_spend");

	// B's coin, to outputs outside the published bounds.
	let b_valid2 = b_coin.record.resolve(&bases, &policy).unwrap();
	let b_kept = 600_000 - MARGIN;
	let chain = r.chain;
	let spend_b = |outs: Vec<(elements::AssetId, u64, arca_covenant::NewLeaf)>| transfer_body(&[(&b_coin, b_valid2.clone(), b_kept)], &outs, s, chain);
	let d = keypair("D");
	let (mut d_leaf, d_nonce) = new_leaf(&d);
	d_leaf.exit_delay = RelativeTime::from_units(10).unwrap();
	refused(r.http.post("cosign_transfer", &spend_b(vec![(r.x, 500_000, d_leaf)])), 422, "out_of_bounds");
	d_leaf.exit_delay = RelativeTime::from_units(400).unwrap();
	refused(r.http.post("cosign_transfer", &spend_b(vec![(r.x, 500_000, d_leaf)])), 422, "out_of_bounds");
	d_leaf.exit_delay = common::client::exit_delay();
	refused(r.http.post("cosign_transfer", &spend_b(vec![(r.x, MIN_LEAF - 1, d_leaf)])), 422, "out_of_bounds");
	refused(r.http.post("cosign_transfer", &spend_b(vec![(r.y, 500_000, d_leaf)])), 422, "out_of_bounds");
	// More than the checkpoint keeps.
	refused(r.http.post("cosign_transfer", &spend_b(vec![(r.x, b_kept + 1, d_leaf)])), 422, "value");
	// A key that already owns a leaf (A's change key).
	let mut reused = d_leaf;
	reused.owner = xonly(&a2);
	refused(r.http.post("cosign_transfer", &spend_b(vec![(r.x, 500_000, reused)])), 409, "key_reused");
	// The owner's signature made by another key.
	let mut forged = spend_b(vec![(r.x, 500_000, d_leaf)]);
	let wrong = Held { key: keypair("not B"), ..b_coin.clone() };
	let wrong_body = transfer_body(&[(&wrong, b_valid2.clone(), b_kept)], &[(r.x, 500_000, d_leaf)], s, r.chain);
	forged["inputs"][0]["checkpoint_sig"] = wrong_body["inputs"][0]["checkpoint_sig"].clone();
	refused(r.http.post("cosign_transfer", &forged), 422, "bad_signature");
	// A leaf the server does not know, and a board not yet final.
	let mut unknown = spend_b(vec![(r.x, 500_000, d_leaf)]);
	unknown["inputs"][0]["leaf_id"] = json!(hex(&[7; 32]));
	refused(r.http.post("cosign_transfer", &unknown), 404, "unknown_leaf");
	let mut pending = spend_b(vec![(r.x, 500_000, d_leaf)]);
	pending["inputs"][0]["leaf_id"] = json!(p_coin.id.to_string());
	refused(r.http.post("cosign_transfer", &pending), 422, "not_live");
	// Every refusal above left nothing behind: B pays D now.
	let ok = r.http.post("cosign_transfer", &spend_b(vec![(r.x, 300_000, d_leaf)])).ok();
	let d_record = r.http.mailbox(&d, &r.chain, 0).remove(0).2;
	d_record.validate(&bases, &policy, &xonly(&d), &d_nonce).unwrap();
	println!("after the refusals, B paid D: transfer {}", ok["transfer_id"]);

	// A sender that repeats B's output for D, creator nonce and all: one
	// transaction could satisfy both reassignments and hand one side's value
	// to whoever broadcasts it. Refused for the same outputs, and for a set
	// whose first outputs are B's: the repeated output's salt is D's leaf's,
	// and a salt is unique on a server (the merge rule behind it refuses the
	// same, `mergeable_at_once`).
	let a2_valid = a2_record.resolve(&bases, &policy).unwrap();
	let a2_coin = Held { key: a2, nonce: a2_nonce, id: a2_valid.id, record: a2_record.clone() };
	let a2_kept = a2_valid.value - MARGIN;
	let spend_a2 = |outs: Vec<(elements::AssetId, u64, arca_covenant::NewLeaf)>| transfer_body(&[(&a2_coin, a2_valid.clone(), a2_kept)], &outs, s, chain);
	refused(r.http.post("cosign_transfer", &spend_a2(vec![(r.x, 300_000, d_leaf)])), 409, "salt");
	let (a3_leaf, _) = new_leaf(&keypair("A3"));
	refused(r.http.post("cosign_transfer", &spend_a2(vec![(r.x, 300_000, d_leaf), (r.x, 1_000, a3_leaf)])), 409, "salt");
	// The rule is kept in the database: a server started again still refuses.
	r.restart_server().await;
	refused(r.http.post("cosign_transfer", &spend_a2(vec![(r.x, 300_000, d_leaf)])), 409, "salt");
	// The same receive request paid again under a fresh creator nonce is a
	// second leaf for D's key, which the server refuses: a key owns one leaf.
	let mut again = d_leaf;
	again.creator_nonce = random32();
	refused(r.http.post("cosign_transfer", &spend_a2(vec![(r.x, 300_000, again)])), 409, "key_reused");

	// A release for a leaf with an open reassignment.
	let e = r.server.cosigner.check_release(&a_coin.id).await.unwrap_err();
	assert_eq!(e.code(), "open_reassignment");
	println!("refused release of {}: {}", a_coin.id, e);

	// The request size is bounded before parsing: 70 kB of anything is too
	// large, valid JSON or not.
	let junk = vec![b'{'; 70 * 1024];
	refused(r.http.post_bytes("cosign_transfer", junk), 413, "request_too_large");
	let mut padded = spend_b(vec![(r.x, 500_000, d_leaf)]);
	padded["inputs"][0]["leaf_id"] = json!("a".repeat(70 * 1024));
	refused(r.http.post("cosign_transfer", &padded), 413, "request_too_large");
	refused(r.http.post_bytes("cosign_transfer", b"{\"inputs\": [".to_vec()), 400, "malformed");
	let mut extra = spend_b(vec![(r.x, 500_000, d_leaf)]);
	extra["unexpected"] = json!(1);
	refused(r.http.post("cosign_transfer", &extra), 400, "malformed");

	// Authentication: B's mailbox needs B's key, and a challenge this server
	// issued; the same proof again within the challenge's lifetime only
	// repeats the very read B signed: another cursor or page size is refused.
	let first_page = server::auth::mailbox_read_request(0, 10);
	let mut auth = r.http.auth_for("mailbox_read", &a, &r.chain, &first_page);
	auth["key"] = json!(hex(&xonly(&b).serialize()));
	refused(r.http.post("mailbox_read", &json!({"auth": auth, "after": "0", "limit": 10})), 401, "unauthenticated");
	let good = r.http.auth_for("mailbox_read", &b, &r.chain, &first_page);
	let first = r.http.post("mailbox_read", &json!({"auth": good, "after": "0", "limit": 10})).ok();
	assert_eq!(r.http.post("mailbox_read", &json!({"auth": good, "after": "0", "limit": 10})).ok(), first);
	for (after, limit) in [("1", 10), ("0", 11), ("100", 100)] {
		let replayed = r.http.post("mailbox_read", &json!({"auth": good, "after": after, "limit": limit}));
		println!("B's proof for (0, 10) replayed with ({}, {}): {} {:?}", after, limit, replayed.status, replayed.refusal());
		refused(replayed, 401, "unauthenticated");
	}
	let mut other_call = r.http.auth("leaf_data", &b, &r.chain);
	other_call["key"] = json!(hex(&xonly(&b).serialize()));
	refused(r.http.post("mailbox_read", &json!({"auth": other_call, "after": "0", "limit": 10})), 401, "unauthenticated");
	let mut unknown_c = r.http.auth("mailbox_read", &b, &r.chain);
	unknown_c["challenge"] = json!(hex(&[1; 32]));
	refused(r.http.post("mailbox_read", &json!({"auth": unknown_c, "after": "0", "limit": 10})), 401, "unauthenticated");
}

#[tokio::test(flavor = "multi_thread")]
async fn depth_limit_five() {
	let mut r = Running::start().await;
	let s = xonly(&r.s);
	let (mut held, board_tx) = credited_board(&mut r, &keypair("hop 0")).await;
	let bases = vec![board_tx];
	let mut value = VALUE;
	for hop in 1..=6 {
		let policy = r.policy();
		let coin = held.record.resolve(&bases, &policy).unwrap();
		let next = keypair(&format!("hop {}", hop));
		let (leaf, nonce) = new_leaf(&next);
		let kept = value - MARGIN;
		let body = transfer_body(&[(&held, coin, kept)], &[(r.x, kept - MARGIN, leaf)], s, r.chain);
		let a = r.http.post("cosign_transfer", &body);
		if hop == 6 {
			refused(a, 422, "depth_limit");
			break;
		}
		let done = a.ok();
		let record = CoinRecord::from_bytes(&unhex(done["outputs"][0]["record"].as_str().unwrap())).unwrap();
		let valid = record.validate(&bases, &policy, &xonly(&next), &nonce).unwrap();
		assert_eq!(valid.hops, hop);
		println!("hop {}: co-signed, {} reassignments from the board", hop, valid.hops);
		held = Held { key: next, nonce, id: valid.id, record };
		value = kept - MARGIN;
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn no_offchain_spend_of_a_leaf_on_chain() {
	let mut r = Running::start().await;
	let s = xonly(&r.s);

	// A converted board: its owner alone takes it on-chain into its leaf.
	let (d_coin, d_tx) = credited_board(&mut r, &keypair("D")).await;
	let board = match &d_coin.record { CoinRecord::Board(b) => *b, _ => unreachable!() };
	let fee_coin = r.purse.take_coin(r.x);
	let at = OutPoint::new(d_tx.txid(), 0);
	let conv = board.policy().conversion(at, &arca_covenant::FeeSource::Coin {
		outpoint: fee_coin.0, coin: fee_coin.1.clone(), fee: 2_000, change: common::node::op_true(),
	}).unwrap();
	let digest = conv.sighash(r.chain.genesis_hash()).unwrap();
	let sig = arca_covenant::sign::sign_digest(&d_coin.key, &digest, &random32());
	let conversion = conv.finish(vec![sig.as_ref().to_vec()]).tx;
	r.rt.client().send_raw_transaction(&conversion).unwrap();
	let (vout, change) = conversion.output.iter().enumerate()
		.filter(|(_, o)| o.script_pubkey == common::node::op_true())
		.max_by_key(|(_, o)| o.value.explicit().unwrap()).unwrap();
	r.purse.put((OutPoint::new(conversion.txid(), vout as u32), change.clone()));
	println!("D converted its board on-chain: {}", conversion.txid());
	// Seen in the mempool, before any block: refused.
	let policy = r.policy();
	let dc = d_coin.record.resolve(std::slice::from_ref(&d_tx), &policy).unwrap();
	let e = keypair("E");
	let (e_leaf, _) = new_leaf(&e);
	let body = transfer_body(&[(&d_coin, dc, VALUE - MARGIN)], &[(r.x, VALUE - 2 * MARGIN, e_leaf)], s, r.chain);
	let server_store = r.server.store.clone();
	let leaf_script = board.policy().leaf.script_pubkey().to_bytes();
	let start = std::time::Instant::now();
	while server_store.sighted(std::slice::from_ref(&leaf_script)).await.unwrap().is_empty() {
		assert!(start.elapsed().as_secs() < 30, "the server did not see the conversion");
		tokio::time::sleep(std::time::Duration::from_millis(100)).await;
	}
	refused(r.http.post("cosign_transfer", &body), 422, "on_chain");

	// A transfer's output published on-chain by its receiver.
	let (f_coin, f_tx) = credited_board(&mut r, &keypair("F")).await;
	let bases = vec![f_tx];
	let policy = r.policy();
	let fc = f_coin.record.resolve(&bases, &policy).unwrap();
	let g = keypair("G");
	let (g_leaf, g_nonce) = new_leaf(&g);
	let kept = VALUE - MARGIN;
	r.http.post("cosign_transfer", &transfer_body(&[(&f_coin, fc, kept)], &[(r.x, kept - MARGIN, g_leaf)], s, r.chain)).ok();
	let g_record = r.http.mailbox(&g, &r.chain, 0).remove(0).2;
	let g_valid = g_record.validate(&bases, &policy, &xonly(&g), &g_nonce).unwrap();
	let input = match &g_valid.origin { arca_covenant::ValidOrigin::Transfer { inputs, .. } => inputs[0].clone(), _ => unreachable!() };
	let cp = input.board_checkpoint_tx(&arca_covenant::FeeSource::Reserve).unwrap().tx;
	r.rt.client().send_raw_transaction(&cp).unwrap();
	let re = g_valid.reassignment_tx(&[OutPoint::new(cp.txid(), 0)], &arca_covenant::FeeSource::Reserve).unwrap().tx;
	r.rt.client().send_raw_transaction(&re).unwrap();
	r.produce().await;
	r.synced().await;
	println!("G published the checkpoint {} and the reassignment {}", cp.txid(), re.txid());
	let h = keypair("H");
	let (h_leaf, _) = new_leaf(&h);
	let g_coin = Held { key: g, nonce: g_nonce, id: g_valid.id, record: g_record };
	let gc = g_coin.record.resolve(&bases, &policy).unwrap();
	let body = transfer_body(&[(&g_coin, gc, kept - 2 * MARGIN)], &[(r.x, kept - 3 * MARGIN, h_leaf)], s, r.chain);
	refused(r.http.post("cosign_transfer", &body), 422, "on_chain");
}

#[tokio::test(flavor = "multi_thread")]
async fn board_rolled_back_over_http() {
	let mut r = Running::start().await;
	let s = xonly(&r.s);
	let (coin, tx) = credited_board(&mut r, &keypair("R")).await;
	// R pays T before the rollback; T's coin rests on R's board.
	let bases = vec![tx.clone()];
	let policy = r.policy();
	let rc = coin.record.resolve(&bases, &policy).unwrap();
	let t = keypair("T");
	let (t_leaf, t_nonce) = new_leaf(&t);
	r.http.post("cosign_transfer", &transfer_body(&[(&coin, rc, VALUE - MARGIN)], &[(r.x, VALUE - 2 * MARGIN, t_leaf)], s, r.chain)).ok();
	let t_record = r.http.mailbox(&t, &r.chain, 0).remove(0).2;
	let t_valid = t_record.validate(&bases, &policy, &xonly(&t), &t_nonce).unwrap();
	let t_coin = Held { key: t, nonce: t_nonce, id: t_valid.id, record: t_record };
	let u = keypair("U");
	let (u_leaf, _) = new_leaf(&u);
	let t_spend = transfer_body(&[(&t_coin, t_valid.clone(), VALUE - 3 * MARGIN)], &[(r.x, VALUE - 4 * MARGIN, u_leaf)], s, r.chain);

	let block = r.server.store.tx_location(&tx.txid().to_byte_array()).await.unwrap().unwrap();
	common::node::invalidate(&r.rt, &elements::BlockHash::from_byte_array(block.hash));
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0"])).unwrap();
	let http = r.http.clone();
	let id = coin.id;
	r.wait("the board to be uncredited", || http.board_status(&id).json["state"] == "pending").await;
	println!("after the rollback: {}", r.http.board_status(&id).json);
	// A coin resting on the uncredited board is not co-signed.
	refused(r.http.post("cosign_transfer", &t_spend), 422, "board_not_final");
	let rt = &r.rt;
	let txid = tx.txid();
	r.wait("the server to broadcast it again", || common::node::in_mempool(rt, &txid)).await;
	r.produce().await;
	r.bury().await;
	r.wait("the board to be credited again", || http.board_status(&id).json["state"] == "credited").await;
	let b = r.server.store.board(&id.0).await.unwrap().unwrap();
	assert_eq!((b.credits, b.uncredits), (2, 1));
	println!("credited again: {}", r.http.board_status(&id).json);
	// Final again: T's coin is co-signed.
	r.http.post("cosign_transfer", &t_spend).ok();
	println!("T's coin, resting on the board, co-signed once the board is credited again");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_spends_at_once() {
	let mut r = Running::start().await;
	let s = xonly(&r.s);
	let (coin, tx) = credited_board(&mut r, &keypair("K")).await;
	let policy = r.policy();
	let kc = coin.record.resolve(&[tx], &policy).unwrap();
	// Two different spends of K's coin, sent together, many times over.
	let mut bodies = vec![];
	for i in 0..8 {
		let to = keypair(&format!("receiver {}", i));
		let (leaf, _) = new_leaf(&to);
		bodies.push(transfer_body(&[(&coin, kc.clone(), VALUE - MARGIN)], &[(r.x, VALUE - 2 * MARGIN, leaf)], s, r.chain));
	}
	let answers: Vec<common::client::Answer> = tokio::task::block_in_place(|| {
		std::thread::scope(|sc| {
			let hs: Vec<_> = bodies.iter().map(|b| { let h = r.http.clone(); sc.spawn(move || h.post("cosign_transfer", b)) }).collect();
			hs.into_iter().map(|h| h.join().unwrap()).collect()
		})
	});
	let ok = answers.iter().filter(|a| a.status == 200).count();
	let spent = answers.iter().filter(|a| a.status == 409 && a.refusal().0 == "double_spend").count();
	assert_eq!((ok, spent), (1, 7), "{:?}", answers.iter().map(|a| a.json.clone()).collect::<Vec<_>>());
	println!("eight spends of one leaf at once: {} co-signed, {} refused double_spend", ok, spent);
}

#[tokio::test(flavor = "multi_thread")]
async fn mergeable_at_once() {
	let mut r = Running::start_with(wide_margins).await;
	let s = xonly(&r.s);
	// Two coins of two owners, each sent at once to the same output set.
	let (k1, t1) = credited_board(&mut r, &keypair("M1")).await;
	let (k2, t2) = credited_board(&mut r, &keypair("M2")).await;
	let policy = r.policy();
	let c1 = k1.record.resolve(std::slice::from_ref(&t1), &policy).unwrap();
	let c2 = k2.record.resolve(std::slice::from_ref(&t2), &policy).unwrap();
	let (leaf, _) = new_leaf(&keypair("one request"));
	let outs = [(r.x, 500_000, leaf)];
	let bodies = [
		transfer_body(&[(&k1, c1, VALUE - MARGIN)], &outs, s, r.chain),
		transfer_body(&[(&k2, c2, VALUE - MARGIN)], &outs, s, r.chain),
	];
	let answers: Vec<common::client::Answer> = tokio::task::block_in_place(|| {
		std::thread::scope(|sc| {
			let hs: Vec<_> = bodies.iter().map(|b| { let h = r.http.clone(); sc.spawn(move || h.post("cosign_transfer", b)) }).collect();
			hs.into_iter().map(|h| h.join().unwrap()).collect()
		})
	});
	// One is co-signed. The other is refused by the merge rule, which runs
	// under a lock on the output set, when both passed the salt check before
	// either was recorded; or for its salt, when the first was recorded
	// before it got there. Which depends on timing alone.
	let codes: Vec<(i32, String)> = answers.iter().map(|a| (a.status, a.refusal().0)).collect();
	assert!(codes.contains(&(200, String::new()))
		&& (codes.contains(&(409, "merge".into())) || codes.contains(&(409, "salt".into()))), "{:?}", codes);
	println!("two coins sent to one output set at once: {:?}", codes);
}

#[tokio::test(flavor = "multi_thread")]
async fn signer_unreachable() {
	let mut r = Running::start().await;
	let s = xonly(&r.s);
	let (coin, tx) = credited_board(&mut r, &keypair("V")).await;
	let policy = r.policy();
	let vc = coin.record.resolve(&[tx], &policy).unwrap();
	let w = keypair("W");
	let (w_leaf, _) = new_leaf(&w);
	let body = transfer_body(&[(&coin, vc.clone(), VALUE - MARGIN)], &[(r.x, VALUE - 2 * MARGIN, w_leaf)], s, r.chain);
	r.signer.kill();
	refused(r.http.post("cosign_transfer", &body), 503, "signer_unavailable");
	// The spend was recorded before the server asked the signer: another
	// spend of the coin is refused even though nothing was signed.
	let z = keypair("Z");
	let (z_leaf, _) = new_leaf(&z);
	let other = transfer_body(&[(&coin, vc, VALUE - MARGIN)], &[(r.x, VALUE - 2 * MARGIN, z_leaf)], s, r.chain);
	refused(r.http.post("cosign_transfer", &other), 409, "double_spend");
	assert!(r.http.mailbox(&w, &r.chain, 0).is_empty(), "nothing delivered unsigned");
	// The signer back, the same request completes.
	let genesis = r.chain.genesis_hash();
	let key = r.s;
	tokio::task::block_in_place(|| r.signer.restart(&key, genesis));
	let done = r.http.post("cosign_transfer", &body).ok();
	assert_eq!(r.http.mailbox(&w, &r.chain, 0).len(), 1);
	println!("the signer back: the same request completed, transfer {}", done["transfer_id"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn no_policy_asset_cosigns_and_broadcasts() {
	let mut r = Running::start().await;
	let s = xonly(&r.s);
	r.fund_wallet(5_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let balance = r.server.wallet.balance().await.unwrap();
	assert_eq!(balance.keys().copied().collect::<Vec<_>>(), vec![r.x], "the wallet holds X alone");
	println!("the server's wallet: {:?}; policy asset {} none", balance, r.purse.policy);

	// It co-signs...
	let (coin, tx) = credited_board(&mut r, &keypair("Q")).await;
	let policy = r.policy();
	let qc = coin.record.resolve(&[tx], &policy).unwrap();
	let w = keypair("W");
	let (w_leaf, _) = new_leaf(&w);
	r.http.post("cosign_transfer", &transfer_body(&[(&coin, qc, VALUE - MARGIN)], &[(r.x, VALUE - 2 * MARGIN, w_leaf)], s, r.chain)).ok();
	println!("co-signed a transfer with no policy asset anywhere");

	// ...and builds, names X as the fee asset, and broadcasts.
	let built = r.server.wallet.build(&server::wallet::BuildRequest {
		outputs: vec![arca_covenant::ExplicitOutput::new(r.x, 1_000_000, common::node::op_true())],
		connector: Some(sequentia_ext::AssetAmount::new(r.x, 10_000)), fee_asset: r.x,
	}).await.unwrap();
	assert_eq!(built.fee.asset, r.x);
	let res = r.server.nursery.submit(&built.tx, server::nursery::NurseryKind::Round, Some(built.fee)).await.unwrap();
	assert_eq!(res, "accepted");
	r.produce().await;
	r.bury().await;
	let txid = built.tx.txid();
	let store = r.server.store.clone();
	let start = std::time::Instant::now();
	loop {
		let row = store.nursery_get(&txid.to_byte_array()).await.unwrap().unwrap();
		if row.state == server::store::NurseryState::Final {
			break;
		}
		assert!(start.elapsed().as_secs() < 60, "not final: {:?}", row);
		tokio::time::sleep(std::time::Duration::from_millis(100)).await;
	}
	let v: Value = r.rt.client().call("getrawtransaction", &[json!(txid.to_string()), json!(true)]).unwrap();
	println!("broadcast {} with its fee of {} atoms in X; final; {} confirmations", txid, built.fee.amount, v["confirmations"]);
}

/// The key of every challenge's check is kept in the database, drawn once: a
/// challenge issued before a restart is taken after it, and two servers on
/// one database take each other's (R7d F6).
#[tokio::test(flavor = "multi_thread")]
async fn a_challenge_is_taken_across_a_restart_and_by_another_server_on_the_database() {
	let mut r = Running::start().await;
	let b = keypair("B");
	let request = server::auth::mailbox_read_request(0, 10);
	let proof = r.http.auth_for("mailbox_read", &b, &r.chain, &request);
	let read = |http: &common::client::Http| http.post("mailbox_read", &json!({"auth": proof, "after": "0", "limit": 10}));
	let mut second = r.config.clone();
	second.listen = "127.0.0.1:0".into();
	let other = server::server::Server::start(&second).await.unwrap();
	let http2 = common::client::Http { base: format!("http://{}", other.addr) };
	let a = read(&http2);
	println!("a challenge of the first server, read through a second on the same database: {} {}", a.status, a.json);
	assert_eq!(a.status, 200, "{}", a.json);
	other.stop();
	r.restart_server().await;
	let a = read(&r.http);
	println!("the same proof after the first server restarted: {} {}", a.status, a.json);
	assert_eq!(a.status, 200, "{}", a.json);
	let c2 = r.http.post("challenge", &json!({})).ok();
	assert!(c2["challenge"].is_string());
}
