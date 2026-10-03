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
