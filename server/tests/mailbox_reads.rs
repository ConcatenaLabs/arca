//! Reading many mailboxes at once (`mailbox_reads`): the store's one
//! statement answers each key exactly as reading it alone does, whatever the
//! keys, their cursors, the page size and the bound on rows; and the call
//! takes each key's proof of a `mailbox_read`, refusing the whole batch on
//! one proof that does not hold, on a key named twice and on more keys than
//! it reads.
//!
//! Needs `ARCA_TEST_POSTGRES`; the call's test needs `SEQUENTIAD_EXEC` too.

mod common;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_json::{json, Value};

use common::client::{hex, random32};
use common::db::TestDb;
use common::keys::{keypair, xonly};
use common::running::Running;
use server::store::{LeafKind, LeafState, MailboxMessage, NewCoin, NewScript, ScriptKind};

/// A coin the store holds, for a message to name: leaf `i`.
fn coin(i: u32, nonce: [u8; 32]) -> NewCoin {
	let mut id = [0u8; 32];
	id[..4].copy_from_slice(&i.to_le_bytes());
	id[4] = 0xc0;
	let script = [&[0x51, 0x20][..], &id[..]].concat();
	NewCoin {
		leaf_id: id,
		kind: LeafKind::Board,
		asset: [0xaa; 32],
		value: 1_000,
		owner_key: id,
		script_pubkey: script.clone(),
		hops: 0,
		record: vec![1],
		state: LeafState::Pending,
		salt: id,
		promised_to: None,
		operator_nonce: Some(nonce),
		scripts: vec![NewScript { script_pubkey: script, kind: ScriptKind::Board }],
		maker_coin: false,
	}
}

fn same(a: &[MailboxMessage], b: &[MailboxMessage]) -> bool {
	a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.cursor == y.cursor && x.kind == y.kind && x.leaf_id == y.leaf_id
		&& x.payload == y.payload)
}

/// Random keys with random mailboxes, read in random batches after random
/// cursors: every key the batch answers holds what reading it alone after
/// its cursor holds (the last one answered possibly a shorter prefix of it,
/// where the bound on rows ran out), the keys answered are a prefix of those
/// asked, and reading on until every key is read to its end finds every
/// message of every key, each once.
#[tokio::test]
async fn a_batch_reads_each_key_as_reading_it_alone() {
	let db = TestDb::new().await;
	let s = &db.store;
	let mut rng = StdRng::seed_from_u64(691);
	let keys: Vec<[u8; 32]> = (0..60u8).map(|i| { let mut k = [0u8; 32]; k[0] = 0x6b; k[1] = i; k }).collect();
	let mut coins = vec![];
	for i in 0..400 {
		coins.push(coin(i, s.issue_nonce().await.unwrap()));
	}
	s.insert_coins(&coins).await.unwrap();
	// Most keys hold nothing, as most receive requests are never paid; a few
	// hold many messages.
	let mut posted: Vec<Vec<i64>> = vec![vec![]; keys.len()];
	for c in &coins {
		let k = if rng.gen_bool(0.5) { rng.gen_range(0..4) } else { rng.gen_range(0..keys.len() / 2) };
		if rng.gen_bool(0.3) {
			continue;
		}
		posted[k].push(s.mailbox_post(&keys[k], &c.leaf_id, &c.leaf_id).await.unwrap());
	}
	let empty = posted.iter().filter(|p| p.is_empty()).count();
	println!("{} keys, {} of them empty, {} messages", keys.len(), empty, posted.iter().map(|p| p.len()).sum::<usize>());
	assert!(empty > 10 && posted.iter().any(|p| p.len() > 40));

	for round in 0..200 {
		let n = rng.gen_range(1..=keys.len());
		let mut pick: Vec<usize> = (0..keys.len()).collect();
		for i in (1..pick.len()).rev() {
			pick.swap(i, rng.gen_range(0..=i));
		}
		pick.truncate(n);
		let reads: Vec<([u8; 32], i64)> = pick.iter().map(|&i| {
			let after = match rng.gen_range(0..3) {
				0 => 0,
				1 if !posted[i].is_empty() => posted[i][rng.gen_range(0..posted[i].len())],
				_ => rng.gen_range(0..2_000),
			};
			(keys[i], after)
		}).collect();
		let limit = [1, 3, 100][rng.gen_range(0..3)];
		let rows = [1, 5, 60, 10_000][rng.gen_range(0..4)];
		let got = s.mailbox_read_many(&reads, limit, true, rows).await.unwrap();
		assert!(!got.is_empty(), "round {}: at least one key is answered", round);
		assert!(got.len() <= reads.len());
		let mut used = 0;
		for (j, (k, msgs)) in got.iter().enumerate() {
			assert_eq!(*k, reads[j].0, "round {}: the keys answered are those asked, in order", round);
			let alone = s.mailbox_read(&reads[j].0, reads[j].1, limit, true).await.unwrap();
			if j + 1 < got.len() {
				assert!(same(msgs, &alone), "round {} key {}: answered as alone", round, j);
			} else {
				assert!(same(msgs, &alone[..msgs.len()]), "round {} key {}: the last one a prefix of its page", round, j);
				assert!(msgs.len() == alone.len() || used + msgs.len().max(1) as i64 == rows, "round {}: cut only by the bound", round);
			}
			used += msgs.len().max(1) as i64;
		}
		assert!(used <= rows.max(1), "round {}: {} rows read against a bound of {}", round, used, rows);
		if got.len() < reads.len() {
			assert_eq!(used, rows, "round {}: keys are left out only where the bound ran out", round);
		}
	}

	// Read on, as a wallet does, until every key is read to its end: every
	// message found, each once, in order.
	let mut cursors = vec![0i64; keys.len()];
	let mut found: Vec<Vec<i64>> = vec![vec![]; keys.len()];
	let mut todo: Vec<usize> = (0..keys.len()).collect();
	let mut calls = 0;
	while !todo.is_empty() {
		calls += 1;
		let reads: Vec<([u8; 32], i64)> = todo.iter().map(|&i| (keys[i], cursors[i])).collect();
		let got = s.mailbox_read_many(&reads, 100, true, 120).await.unwrap();
		let mut next = vec![];
		for (j, &i) in todo.iter().enumerate() {
			match got.get(j) {
				None => next.push(i),
				Some((_, msgs)) if msgs.is_empty() => {},
				Some((_, msgs)) => {
					found[i].extend(msgs.iter().map(|m| m.cursor));
					cursors[i] = msgs.last().unwrap().cursor;
					next.push(i);
				},
			}
		}
		todo = next;
	}
	assert_eq!(found, posted, "every message of every key, each once, in order");
	println!("read to the end in {} statements", calls);
}

fn proof(r: &Running, challenge: &[u8; 32], key: &elements::secp256k1_zkp::Keypair, after: i64, limit: u32) -> Value {
	let request = server::auth::mailbox_read_request(after as u64, limit);
	let digest = server::auth::auth_digest(&r.chain, "mailbox_read", challenge, &xonly(key), &request);
	let sig = arca_covenant::sign::sign_digest(key, &digest, &random32());
	json!({"key": hex(&xonly(key).serialize()), "after": after.to_string(), "signature": hex(sig.as_ref())})
}

fn challenge(r: &Running) -> [u8; 32] {
	let v = r.http.post("challenge", &json!({})).ok();
	common::client::unhex(v["challenge"].as_str().unwrap()).try_into().unwrap()
}

/// The call: `info` publishes how many keys it reads; a batch of proven keys
/// answers each as `mailbox_read` does; one proof over another cursor, the
/// page size or the call, a key named twice, no key or too many, are each
/// refused whole, and nothing is read.
#[tokio::test(flavor = "multi_thread")]
async fn the_call_takes_each_keys_proof_of_a_mailbox_read() {
	let r = Running::start().await;
	let info = r.http.get("info").ok();
	assert_eq!(info["mailbox_reads"], json!(server::http::MAX_MAILBOX_READS), "{}", info["mailbox_reads"]);
	let keys: Vec<_> = (0..150).map(|i| keypair(&format!("mailbox reads {}", i))).collect();
	let mut coins = vec![];
	for i in 0..20 {
		coins.push(coin(i, r.server.store.issue_nonce().await.unwrap()));
	}
	r.server.store.insert_coins(&coins).await.unwrap();
	for (i, c) in coins.iter().enumerate() {
		r.server.store.mailbox_post(&xonly(&keys[i % 3 * 50]).serialize(), &c.leaf_id, &c.leaf_id).await.unwrap();
	}
	let c = challenge(&r);
	let reads: Vec<Value> = keys.iter().map(|k| proof(&r, &c, k, 0, 100)).collect();
	let body = json!({"challenge": hex(&c), "limit": 100, "notices": true, "reads": reads});
	println!("a batch of {} keys: {} bytes", keys.len(), body.to_string().len());
	let t = std::time::Instant::now();
	let v = r.http.post("mailbox_reads", &body).ok();
	println!("answered in {:?}", t.elapsed());
	let boxes = v["mailboxes"].as_array().unwrap();
	assert_eq!(boxes.len(), keys.len(), "every key answered");
	for (i, k) in keys.iter().enumerate() {
		assert_eq!(boxes[i]["key"], hex(&xonly(k).serialize()));
		let alone = r.http.post("mailbox_read", &json!({"auth": r.http.auth_for("mailbox_read", k, &r.chain,
			&server::auth::mailbox_read_request(0, 100)), "after": "0", "limit": 100, "notices": true})).ok();
		assert_eq!(boxes[i]["messages"], alone["messages"], "key {} answered as mailbox_read answers it", i);
	}
	assert_eq!(boxes[0]["messages"].as_array().unwrap().len(), 7);
	assert_eq!(boxes[1]["messages"].as_array().unwrap().len(), 0);

	let refused = |body: Value, status: i32, code: &str, says: &str| {
		let a = r.http.post("mailbox_reads", &body);
		let (c2, m) = a.refusal();
		println!("REFUSED {} {}: {}", a.status, c2, m);
		assert_eq!((a.status, c2.as_str()), (status, code), "{}", m);
		assert!(m.contains(says), "{}", m);
	};
	let with = |reads: Vec<Value>| json!({"challenge": hex(&c), "limit": 100, "notices": true, "reads": reads});
	// One proof over another cursor than it reads after.
	let mut bad = reads[..10].to_vec();
	bad[7] = proof(&r, &c, &keys[7], 5, 100);
	bad[7]["after"] = json!("0");
	refused(with(bad), 401, "unauthenticated", &format!("does not prove key {}", hex(&xonly(&keys[7]).serialize())));
	// Over another page size than the batch asks.
	let mut bad = reads[..10].to_vec();
	bad[3] = proof(&r, &c, &keys[3], 0, 99);
	refused(with(bad), 401, "unauthenticated", "does not prove key");
	// Over another call: a `leaf_data` proof of the same key and request.
	let mut bad = reads[..10].to_vec();
	let digest = server::auth::auth_digest(&r.chain, "leaf_data", &c, &xonly(&keys[2]), &server::auth::mailbox_read_request(0, 100));
	bad[2]["signature"] = json!(hex(arca_covenant::sign::sign_digest(&keys[2], &digest, &random32()).as_ref()));
	refused(with(bad), 401, "unauthenticated", "does not prove key");
	// Another key's signature.
	let mut bad = reads[..10].to_vec();
	bad[4]["signature"] = reads[5]["signature"].clone();
	refused(with(bad), 401, "unauthenticated", "does not prove key");
	// Under another challenge than the batch names.
	let other = challenge(&r);
	let mut bad = reads[..10].to_vec();
	bad[1] = proof(&r, &other, &keys[1], 0, 100);
	refused(with(bad), 401, "unauthenticated", "does not prove key");
	// A challenge the server did not issue.
	let mut forged = c;
	forged[20] ^= 1;
	refused(json!({"challenge": hex(&forged), "limit": 100, "reads": reads[..2]}), 401, "unauthenticated", "not issued by this server");
	// A key named twice.
	let mut twice = reads[..10].to_vec();
	twice.push(reads[0].clone());
	refused(with(twice), 400, "malformed", "named twice");
	// None, and more than it reads.
	refused(with(vec![]), 400, "malformed", "a mailbox read names 1 to");
	let many: Vec<Value> = (0..server::http::MAX_MAILBOX_READS + 1).map(|i| proof(&r, &c, &keypair(&format!("many {}", i)), 0, 100)).collect();
	let a = r.http.post("mailbox_reads", &with(many));
	println!("REFUSED {} keys: {} {:?}", server::http::MAX_MAILBOX_READS + 1, a.status, a.refusal());
	assert!(a.status == 400 || a.status == 413, "{}", a.status);
}
