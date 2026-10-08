//! A leaf's salt is unique on a server (D44), and the signer's one-spend
//! rule is the salt's: its signature commits to the salt and not to the
//! owner key, so it never gives two spend signatures under one salt.
//!
//! A transfer's sender chooses both nonces of a new leaf's salt, and the
//! public `tree` call publishes every batch leaf's two nonces. So a holder
//! can name another holder's salt for a leaf under its own key. The server
//! refuses that leaf (`salt`), whether the salt is a batch leaf's, a board's,
//! a transfer output's, or one promised to a participation not yet in a
//! round; a board and a transfer naming one are refused alike. A database
//! that has forgotten a salt (restored from an older copy, or new) lets
//! such a leaf through; the first to spend under the salt then takes it, and
//! the other holder is refused by the signer and can exit. And the case the
//! rule guards: a holder that paid from its leaf, its database having
//! forgotten the salt, makes a second leaf under it and pays again: the
//! signer refuses that second spend, whose signature would also be valid on
//! the first coin.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use serde_json::json;

use arca_covenant::{CoinRecord, NewLeaf};
use common::client::{
	auths_json, board_record, exit_delay, forfeit_sig, hex, new_leaf, participation_body, random32, transfer_body, unhex, want_leaf,
	Answer, Held,
};
use common::flow::{forfeit_for, refresh, Coin};
use common::keys::{keypair, xonly};
use common::rounds::{created, credited_board, round_final, start, status, validate_new_leaf};

const MARGIN: u64 = 2_000;

fn refused_salt(a: &Answer, salt: &[u8; 32], what: &str) {
	println!("{}: {} {}", what, a.status, a.json);
	assert_eq!(a.status, 409, "{}: {}", what, a.json);
	let (code, message) = a.refusal();
	assert_eq!(code, "salt", "{}: {}", what, a.json);
	assert!(message.contains(&hex(salt)), "{}: the refusal names the salt: {}", what, message);
}

/// The salt of the batch leaf the participation `id` was given, read as
/// anyone reads it: from the public tree.
fn salt_from_tree(r: &common::running::Running, id: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
	let st = status(r, id);
	let o = &st["outputs"][0];
	let tree = r.http.post("tree", &json!({"txid": st["round"]["txid"], "vout": o["batch_vout"]})).ok();
	let l = &tree["leaves"][o["leaf_index"].as_u64().unwrap() as usize];
	let on: [u8; 32] = unhex(l["owner_nonce"].as_str().unwrap()).try_into().unwrap();
	let op: [u8; 32] = unhex(l["operator_nonce"].as_str().unwrap()).try_into().unwrap();
	(arca_covenant::leaf::leaf_salt(&on, &op), on, op)
}

#[tokio::test(flavor = "multi_thread")]
async fn no_leaf_takes_a_salt_the_server_has_seen() {
	let mut r = start().await;
	let s = xonly(&r.s);
	let x = r.x;

	// V, W and U each hold a live round leaf.
	let mut coins = vec![];
	for who in ["V", "W", "U"] {
		let (held, tx) = credited_board(&mut r, &keypair(&format!("{} board", who)), x).await;
		coins.push((Coin { held, bases: vec![tx] }, keypair(&format!("{} leaf", who))));
	}
	let done = refresh(&mut r, &coins.iter().map(|(c, k)| (c, k)).collect::<Vec<_>>()).await;
	let (v, w, u) = (&done[0], &done[1], &done[2]);
	println!("V's round leaf {}, W's {}, U's {}", v.new.held.id, w.new.held.id, u.new.held.id);

	// The attacker reads V's nonces from the public tree and asks for a leaf
	// of its own key under V's salt: refused, nothing recorded.
	let (v_salt, v_on, v_op) = salt_from_tree(&r, &v.id);
	let (a_held, a_tx) = credited_board(&mut r, &keypair("attacker board"), x).await;
	let a_valid = a_held.record.resolve(std::slice::from_ref(&a_tx), &r.policy()).unwrap();
	let kept = a_valid.value - MARGIN;
	let copy = NewLeaf { owner: xonly(&keypair("attacker copy")), owner_nonce: v_on, creator_nonce: v_op, exit_delay: exit_delay(), htlc: None };
	assert_eq!(copy.salt(), v_salt);
	let t = r.http.post("cosign_transfer", &transfer_body(&[(&a_held, a_valid.clone(), kept)], &[(x, kept - MARGIN, copy)], s, r.chain));
	refused_salt(&t, &v_salt, "a transfer to a leaf of the attacker's under V's salt (a batch leaf's)");
	assert_eq!(r.server.store.leaf(&a_held.id.0).await.unwrap().unwrap().state, server::store::LeafState::Live,
		"the attacker's coin is not spent by the refused transfer");

	// Two new leaves of one transfer under one salt.
	let (l1, _) = new_leaf(&keypair("twin one"));
	let l2 = NewLeaf { owner: xonly(&keypair("twin two")), ..l1 };
	let half = (kept - MARGIN) / 2;
	let t = r.http.post("cosign_transfer", &transfer_body(&[(&a_held, a_valid.clone(), kept)], &[(x, half, l1), (x, half, l2)], s, r.chain));
	refused_salt(&t, &l1.salt(), "a transfer to two new leaves under one salt");

	// A transfer output's salt: the attacker pays itself a leaf whose salt
	// takes a fresh operator nonce as its creator nonce, then boards under
	// that same pair. The board is refused for its salt, before its nonce
	// (which is unused) is looked at.
	let n = r.http.operator_nonce();
	let mine = NewLeaf { owner: xonly(&keypair("attacker own")), owner_nonce: random32(), creator_nonce: n, exit_delay: exit_delay(), htlc: None };
	let t = r.http.post("cosign_transfer", &transfer_body(&[(&a_held, a_valid.clone(), kept)], &[(x, kept - MARGIN, mine)], s, r.chain));
	assert_eq!(t.status, 200, "{}", t.json);
	let board_key = keypair("attacker board under a transfer's salt");
	let mut rec = board_record(&board_key, n, x, common::rounds::VALUE, r.chain, s);
	rec.owner_nonce = mine.owner_nonce;
	assert_eq!(rec.salt(), mine.salt());
	let coin = r.purse.take_coin(x);
	let tx = rec.tx(std::slice::from_ref(&coin), x, 2_000, &common::node::op_true()).unwrap().tx;
	let b = r.http.register_board(&rec, &tx);
	refused_salt(&b, &mine.salt(), "a board under a transfer output's salt, its operator nonce unused");
	assert!(r.server.store.board(&rec.leaf_id().0).await.unwrap().is_none());
	// The board transaction was never sent: its coin goes back to the purse.
	r.purse.put(coin);

	// A salt promised to a participation not yet in a round: U refreshes,
	// and the attacker, who learnt the participation's nonces, asks for a
	// leaf under that salt before the round is built.
	let uv = u.new.valid(&r);
	let u_next = keypair("U next");
	let (want, u_nonce) = want_leaf(&u_next, x, uv.value);
	let (body, pid) = participation_body(&[&u.new.held], &[want], &[], None, s, r.chain);
	let p = r.http.post("submit_participation", &body).ok();
	assert_eq!(p["state"], "pending", "{}", p);
	let op: [u8; 32] = unhex(p["outputs"][0]["operator_nonce"].as_str().unwrap()).try_into().unwrap();
	let promised = arca_covenant::leaf::leaf_salt(&u_nonce, &op);
	let (b2, b2_tx) = credited_board(&mut r, &keypair("attacker board 2"), x).await;
	let b2v = b2.record.resolve(std::slice::from_ref(&b2_tx), &r.policy()).unwrap();
	let k2 = b2v.value - MARGIN;
	let early = NewLeaf { owner: xonly(&keypair("attacker early")), owner_nonce: u_nonce, creator_nonce: op, exit_delay: exit_delay(), htlc: None };
	let t = r.http.post("cosign_transfer", &transfer_body(&[(&b2, b2v.clone(), k2)], &[(x, k2 - MARGIN, early)], s, r.chain));
	refused_salt(&t, &promised, "a transfer to a leaf under a salt promised to a participation");

	// V pays C, and U's round runs and takes its forfeit: both as if no one
	// had tried.
	let vv = v.new.valid(&r);
	let vk = vv.value - MARGIN;
	let (c_leaf, _) = new_leaf(&keypair("C"));
	let t = r.http.post("cosign_transfer", &transfer_body(&[(&v.new.held, vv, vk)], &[(x, vk - MARGIN, c_leaf)], s, r.chain));
	println!("V pays C: {} {}", t.status, t.json.get("error").cloned().unwrap_or(json!("co-signed")));
	assert_eq!(t.status, 200, "{}", t.json);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let st = status(&r, &pid);
	let (new_valid, record, round) = validate_new_leaf(&r, &pid, 0, &u_next, &u_nonce);
	assert_eq!(new_valid.branch.leaf.salt, promised, "U's new leaf takes the salt promised to it");
	let f = forfeit_for(&uv, &new_valid, &round, &st);
	let fl = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&pid),
		"forfeits": [{"leaf_id": u.new.held.id.to_string(), "signature": forfeit_sig(&f, &u.new.held.key)}],
		"leaves": [auths_json(&new_valid, &u_next, created(&record))]}));
	println!("U hands over its forfeit for round {}: {} {}", round.txid(), fl.status, fl.json);
	assert_eq!(fl.status, 200, "{}", fl.json);
	assert_eq!(fl.json["state"], "released");

	let (pg, conn) = tokio_postgres::connect(&r.config.database, tokio_postgres::NoTls).await.unwrap();
	tokio::spawn(conn);
	// R7c's case: the attacker pays a victim from its own leaf L1, its
	// database then forgets L1's salt, and it makes a second leaf L2 of its
	// own under that salt and pays itself from it. S's signature for L2's
	// spend would be valid on L1 as well, taking the victim's payment back:
	// the signer refuses it.
	let (b4, b4_tx) = credited_board(&mut r, &keypair("attacker board 4"), x).await;
	let b4v = b4.record.resolve(std::slice::from_ref(&b4_tx), &r.policy()).unwrap();
	let k4 = b4v.value - MARGIN;
	let a5 = keypair("attacker leaf L1");
	let l1_leaf = NewLeaf { owner: xonly(&a5), owner_nonce: random32(), creator_nonce: random32(), exit_delay: exit_delay(), htlc: None };
	let (l1_on, l1_op) = (l1_leaf.owner_nonce, l1_leaf.creator_nonce);
	let t = r.http.post("cosign_transfer", &transfer_body(&[(&b4, b4v, k4)], &[(x, k4 - MARGIN, l1_leaf)], s, r.chain)).ok();
	let rec = CoinRecord::from_bytes(&unhex(t["outputs"][0]["record"].as_str().unwrap())).unwrap();
	let l1 = Held { key: a5, nonce: l1_on, id: t["outputs"][0]["leaf_id"].as_str().unwrap().parse().unwrap(), record: rec };
	let l1v = l1.record.resolve(std::slice::from_ref(&b4_tx), &r.policy()).unwrap();
	let l1_salt = l1v.leaf.salt;
	let kl = l1v.value - MARGIN;
	let (victim, _) = new_leaf(&keypair("victim R"));
	let l1_value = l1v.value;
	let t = r.http.post("cosign_transfer", &transfer_body(&[(&l1, l1v, kl)], &[(x, kl - MARGIN, victim)], s, r.chain));
	println!("the attacker pays the victim from L1 (salt {}): {}", hex(&l1_salt), t.status);
	assert_eq!(t.status, 200, "{}", t.json);
	assert_eq!(pg.execute("DELETE FROM leaf_salt WHERE salt = $1", &[&&l1_salt[..]]).await.unwrap(), 1);
	let (b5, b5_tx) = credited_board(&mut r, &keypair("attacker board 5"), x).await;
	let b5v = b5.record.resolve(std::slice::from_ref(&b5_tx), &r.policy()).unwrap();
	let k5 = b5v.value - MARGIN;
	assert_eq!(k5 - MARGIN, l1_value, "L2 holds what L1 held: one message would spend either");
	let a6 = keypair("attacker leaf L2");
	let l2_leaf = NewLeaf { owner: xonly(&a6), owner_nonce: l1_on, creator_nonce: l1_op, exit_delay: exit_delay(), htlc: None };
	let t = r.http.post("cosign_transfer", &transfer_body(&[(&b5, b5v, k5)], &[(x, k5 - MARGIN, l2_leaf)], s, r.chain)).ok();
	let rec = CoinRecord::from_bytes(&unhex(t["outputs"][0]["record"].as_str().unwrap())).unwrap();
	let l2 = Held { key: a6, nonce: l1_on, id: t["outputs"][0]["leaf_id"].as_str().unwrap().parse().unwrap(), record: rec };
	let l2v = l2.record.resolve(std::slice::from_ref(&b5_tx), &r.policy()).unwrap();
	assert_eq!(l2v.leaf.salt, l1_salt);
	println!("with L1's salt forgotten, the attacker's second leaf L2 under it is co-signed");
	let (sink2, _) = new_leaf(&keypair("attacker sink 2"));
	let t = r.http.post("cosign_transfer", &transfer_body(&[(&l2, l2v, kl)], &[(x, kl - MARGIN, sink2)], s, r.chain));
	println!("the attacker pays itself from L2: {} {:?}", t.status, t.refusal());
	assert_eq!(t.refusal().0, "double_spend", "the signer refuses a second spend under the salt: {}", t.json);
	assert!(t.refusal().1.contains(&hex(&l1_salt)), "{}", t.json);

	// A database that has forgotten W's salt (restored from an older copy,
	// or a new one) lets the attacker's leaf under it through, and its spend
	// as well; the signer's rule is the salt's, so W's own payment is then
	// refused, and W can exit.
	let (w_salt, w_on, w_op) = salt_from_tree(&r, &w.id);
	assert_eq!(pg.execute("DELETE FROM leaf_salt WHERE salt = $1", &[&&w_salt[..]]).await.unwrap(), 1);
	let (b3, b3_tx) = credited_board(&mut r, &keypair("attacker board 3"), x).await;
	let b3v = b3.record.resolve(std::slice::from_ref(&b3_tx), &r.policy()).unwrap();
	let k3 = b3v.value - MARGIN;
	let a4 = keypair("attacker copy of W");
	let copy_w = NewLeaf { owner: xonly(&a4), owner_nonce: w_on, creator_nonce: w_op, exit_delay: exit_delay(), htlc: None };
	let t = r.http.post("cosign_transfer", &transfer_body(&[(&b3, b3v, k3)], &[(x, k3 - MARGIN, copy_w)], s, r.chain)).ok();
	println!("with W's salt forgotten by the database, the attacker's leaf under it is co-signed");
	let rec = CoinRecord::from_bytes(&unhex(t["outputs"][0]["record"].as_str().unwrap())).unwrap();
	let held = Held { key: a4, nonce: w_on, id: t["outputs"][0]["leaf_id"].as_str().unwrap().parse().unwrap(), record: rec };
	let hv = held.record.resolve(std::slice::from_ref(&b3_tx), &r.policy()).unwrap();
	assert_eq!(hv.leaf.salt, w_salt);
	let kh = hv.value - MARGIN;
	let (sink, _) = new_leaf(&keypair("attacker sink"));
	let t = r.http.post("cosign_transfer", &transfer_body(&[(&held, hv, kh)], &[(x, kh - MARGIN, sink)], s, r.chain));
	println!("the attacker spends its leaf under W's salt: {}", t.status);
	assert_eq!(t.status, 200, "{}", t.json);
	let wv = w.new.valid(&r);
	let wk = wv.value - MARGIN;
	let (d_leaf, _) = new_leaf(&keypair("D"));
	let t = r.http.post("cosign_transfer", &transfer_body(&[(&w.new.held, wv, wk)], &[(x, wk - MARGIN, d_leaf)], s, r.chain));
	println!("W pays D after the attacker spent a leaf under W's salt: {} {}", t.status,
		t.json.get("error").cloned().unwrap_or(json!("co-signed")));
	assert_eq!(t.refusal().0, "double_spend", "{}", t.json);
	assert!(t.refusal().1.contains(&hex(&w_salt)), "the signer names the salt: {}", t.json);
}
