//! The server's database remembers the latest entry of the signer's record
//! it was given, and every rebind request names it: a signer whose record
//! has been cut back signs nothing, and the server does not start against
//! it.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use common::client::{new_leaf, transfer_body, Held};
use common::keys::{keypair, xonly};
use common::running::Running;

const VALUE: u64 = 1_000_000;
const MARGIN: u64 = 2_000;

async fn credited_board(r: &mut Running, owner: &elements::secp256k1_zkp::Keypair) -> (Held, elements::Transaction) {
	let (record, tx, _) = r.board(owner, VALUE);
	r.produce().await;
	r.bury().await;
	let id = record.leaf_id();
	let http = r.http.clone();
	r.wait("the board to be credited", || http.board_status(&id).json["state"] == "credited").await;
	(Held { key: *owner, nonce: record.owner_nonce, id, record: arca_covenant::CoinRecord::Board(record) }, tx)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_record_cut_back_signs_nothing_and_the_server_does_not_start_on_it() {
	let mut r = Running::start().await;
	let s = xonly(&r.s);
	let x = r.x;
	assert_eq!(r.server.store.signer_head().await.unwrap(), None, "nothing signed yet");
	let empty = std::fs::read(r.signer.record()).unwrap();

	// A pays B: two entries (the checkpoint and the reassignment), the
	// database told the latest.
	let (a, a_tx) = credited_board(&mut r, &keypair("A")).await;
	let av = a.record.resolve(std::slice::from_ref(&a_tx), &r.policy()).unwrap();
	let kept = av.value - MARGIN;
	let (b_leaf, _) = new_leaf(&keypair("B"));
	let t = r.http.post("cosign_transfer", &transfer_body(&[(&a, av, kept)], &[(x, kept - MARGIN, b_leaf)], s, r.chain));
	assert_eq!(t.status, 200, "{}", t.json);
	let head = r.server.store.signer_head().await.unwrap().expect("the database knows an entry");
	println!("A paid B; the database knows entry {} of the signer's record", head.0);
	assert_eq!(head.0, 2);

	// The record replaced by the copy taken before: the signer starts on it,
	// and refuses the next request, which names entry 2.
	let whole = std::fs::read(r.signer.record()).unwrap();
	let genesis = r.chain.genesis_hash();
	r.signer.kill();
	std::fs::write(r.signer.record(), &empty).unwrap();
	r.signer.restart(&r.s, genesis);
	let (c, c_tx) = credited_board(&mut r, &keypair("C")).await;
	let cv = c.record.resolve(std::slice::from_ref(&c_tx), &r.policy()).unwrap();
	let ck = cv.value - MARGIN;
	let (d_leaf, _) = new_leaf(&keypair("D"));
	let c_pays_d = transfer_body(&[(&c, cv, ck)], &[(x, ck - MARGIN, d_leaf)], s, r.chain);
	let t = r.http.post("cosign_transfer", &c_pays_d);
	println!("C pays D, the signer's record cut back: {} {}", t.status, t.json);
	assert_eq!(t.status, 503, "{}", t.json);
	let (code, message) = t.refusal();
	assert_eq!(code, "signer_unavailable");
	assert!(message.contains("record_behind"), "{}", message);

	// And the server does not start against it, naming both entries.
	r.server.stop();
	let e = server::server::Server::start(&r.config).await.err().expect("no start on a record cut back");
	println!("the server's start on it: {}", e);
	assert!(e.to_string().contains("ends at entry 0 and the database knows entry 2"), "{}", e);

	// The whole record back: the server starts, and C's payment completes.
	r.signer.kill();
	std::fs::write(r.signer.record(), &whole).unwrap();
	r.signer.restart(&r.s, genesis);
	r.server = server::server::Server::start(&r.config).await.unwrap();
	r.http = common::client::Http { base: format!("http://{}", r.server.addr) };
	// The same request again, byte for byte, as a wallet sends it again.
	let t = r.http.post("cosign_transfer", &c_pays_d);
	assert_eq!(t.status, 200, "{}", t.json);
	println!("the whole record back: the server starts, and C's payment, sent again, is co-signed: entry {}",
		r.server.store.signer_head().await.unwrap().unwrap().0);
}

/// The record compacted against the salts the server lists as expired: a
/// batch leaf paid on out of round, and the coin it paid, each past its
/// batch's last expiry, are listed with their checkpoints; a board's salt
/// never is. The signer's record compacted with that list goes on from its
/// latest entry, which the database knows, so the server starts on it.
#[tokio::test(flavor = "multi_thread")]
async fn the_record_compacted_against_the_expired_salts_still_starts_the_server() {
	use arca_covenant::transfer::checkpoint_salt;
	use arca_covenant::CoinRecord;
	use common::flow::{refresh, Coin};
	use common::rounds::{advance_mtp, mtp};
	let mut r = common::rounds::start().await;
	let (s, x, chain) = (xonly(&r.s), r.x, r.chain);

	// A's board refreshed into a batch leaf, which pays B out of round.
	let (ab, ab_tx) = common::rounds::credited_board(&mut r, &keypair("A"), x).await;
	let board_salt = match &ab.record { CoinRecord::Board(b) => b.salt(), _ => unreachable!() };
	let got = refresh(&mut r, &[(&Coin { held: ab, bases: vec![ab_tx] }, &keypair("A, batch"))]).await;
	let leaf = &got[0].new;
	let lv = leaf.valid(&r);
	let kept = lv.value - MARGIN;
	let (b_leaf, _) = new_leaf(&keypair("B"));
	let paid = r.http.post("cosign_transfer", &transfer_body(&[(&leaf.held, lv.clone(), kept)], &[(x, kept - MARGIN, b_leaf)], s, chain)).ok();
	let b_record = CoinRecord::from_bytes(&common::client::unhex(paid["outputs"][0]["record"].as_str().unwrap())).unwrap();
	let b_salt = b_record.resolve(&leaf.bases, &r.policy()).unwrap().leaf.salt;
	// C's board pays D out of round: entries under a board's salt.
	let (c, c_tx) = credited_board(&mut r, &keypair("C")).await;
	let cv = c.record.resolve(std::slice::from_ref(&c_tx), &r.policy()).unwrap();
	let c_salt = cv.leaf.salt;
	let ck = cv.value - MARGIN;
	let (d_leaf, _) = new_leaf(&keypair("D"));
	r.http.post("cosign_transfer", &transfer_body(&[(&c, cv, ck)], &[(x, ck - MARGIN, d_leaf)], s, chain)).ok();
	let head = r.server.store.signer_head().await.unwrap().unwrap();
	let lines_before = std::fs::read_to_string(r.signer.record()).unwrap().lines().count();
	println!("the record holds {} entries, the database knows entry {}", lines_before - 1, head.0);

	// Past the batch's last expiry.
	let last = match &leaf.held.record { CoinRecord::Leaf { record, .. } => record.schedule.expiries().last().unwrap().to_consensus_u32(),
		_ => unreachable!() };
	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, last - now + 3_600).await;
	r.synced().await;
	let salts = server::server::expired_salts(&r.config).await.unwrap();
	println!("expired salts: {}", salts.len());
	for want in [lv.leaf.salt, checkpoint_salt(&lv.leaf.salt), b_salt, checkpoint_salt(&b_salt)] {
		assert!(salts.contains(&want), "a salt of a coin resting on the expired batch is listed");
	}
	for never in [board_salt, c_salt, checkpoint_salt(&c_salt)] {
		assert!(!salts.contains(&never), "a board's salt is never listed");
	}

	// The record compacted with that list, put in place, the server started
	// on it.
	r.server.stop();
	r.signer.kill();
	let dir = r.signer.dir.clone();
	let list = dir.join("expired.salts");
	std::fs::write(&list, salts.iter().map(|s| server::signer::hex(s) + "\n").collect::<String>()).unwrap();
	let compacted = dir.join("compacted.record");
	let out = std::process::Command::new(env!("CARGO_BIN_EXE_arca-signer"))
		.args(["--key-file", dir.join("operator.key").to_str().unwrap(), "--genesis", &chain.genesis_hash().to_string(),
			"--record", r.signer.record().to_str().unwrap(), "--compact-into", compacted.to_str().unwrap(),
			"--drop-salts", list.to_str().unwrap()])
		.output().unwrap();
	println!("{}", String::from_utf8_lossy(&out.stderr).trim());
	assert!(out.status.success());
	std::fs::rename(&compacted, r.signer.record()).unwrap();
	let lines_after = std::fs::read_to_string(r.signer.record()).unwrap().lines().count();
	println!("the compacted record holds {} entries", lines_after - 1);
	assert!(lines_after < lines_before, "entries were dropped");
	r.signer.restart(&r.s, chain.genesis_hash());
	r.restart_server().await;
	assert_eq!(r.server.store.signer_head().await.unwrap(), Some(head), "the database's entry is the compacted record's latest");
	r.http.get("info").ok();
	println!("the server started on the compacted record");
}
