//! Participations over HTTP, against a whole server on an anchored
//! proof-of-stake regtest chain: a participation accepted, its status, the
//! same participation submitted again, and each rule exercised by a refusal
//! with its code.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::Transaction;
use serde_json::json;

use arca_covenant::{CoinRecord, RelativeTime};
use common::client::{hex, participation_body, random32, want_leaf, Answer, Held};
use common::keys::{keypair, xonly};
use common::node;
use common::running::{Running, MIN_LEAF};
use server::participations::OutputRequest;

const VALUE: u64 = 1_000_000;
/// The refresh fee the test server charges, in parts per million.
const REFRESH_PPM: u64 = 1_000;
const OFFBOARD_PPM: u64 = 2_000;

fn refused(a: Answer, status: i32, code: &str) {
	let (c, m) = a.refusal();
	assert_eq!((a.status, c.as_str()), (status, code), "{}", a.json);
	println!("refused {} {}: {}", status, code, m);
}

async fn start() -> Running {
	Running::start_with(|c, _| {
		c.fees.refresh_ppm = REFRESH_PPM;
		c.fees.offboard_ppm = OFFBOARD_PPM;
	}).await
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
async fn participation_accepted_and_refused() {
	let mut r = start().await;
	let s = xonly(&r.s);
	let (x, chain) = (r.x, r.chain);

	let info = r.http.get("info").ok();
	assert_eq!(info["fees"]["refresh_ppm"], REFRESH_PPM);
	assert_eq!(info["fees"]["offboard_ppm"], OFFBOARD_PPM);

	let a = keypair("A");
	let (a_coin, _) = credited_board(&mut r, &a).await;
	let b = keypair("B");
	let (b_coin, b_tx) = credited_board(&mut r, &b).await;

	// A board just confirmed has its whole service ahead of it (28 days), so
	// its refresh pays the whole fee.
	let fee = VALUE * REFRESH_PPM / 1_000_000;
	let a2 = keypair("A, new leaf");
	let (want_a2, _) = want_leaf(&a2, x, VALUE - fee);
	let (body, id) = participation_body(&[&a_coin], std::slice::from_ref(&want_a2), &[(x, fee)], None, s, chain);
	let st = r.http.post("submit_participation", &body).ok();
	println!("participation accepted: {}", st);
	assert_eq!(st["participation_id"], hex(&id));
	assert_eq!(st["state"], "pending");
	assert_eq!(st["attempt"], 0);
	assert_eq!(st["inputs"][0]["leaf_id"], a_coin.id.to_string());
	assert!(st["inputs"][0]["margin"].as_str().unwrap().parse::<u64>().unwrap() > 1, "X is accepted for fees: a priced margin");
	assert_eq!(st["outputs"][0]["kind"], "leaf");
	assert_eq!(st["outputs"][0]["operator_nonce"].as_str().unwrap().len(), 64);
	assert!(st.get("round").is_none());
	// The same participation again: the same answer.
	assert_eq!(r.http.post("submit_participation", &body).ok(), st);
	assert_eq!(r.http.post("participation_status", &json!({"participation_id": hex(&id)})).ok(), st);
	// The coin given up is spent by the participation.
	let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", &a, &chain)})).ok();
	assert_eq!(ld["leaves"][0]["state"], "spent");

	// --- Refusals ---

	// A's board again, in another participation: in use.
	let (other, _) = want_leaf(&keypair("A, other"), x, VALUE - fee);
	let (body2, _) = participation_body(&[&a_coin], &[other], &[(x, fee)], None, s, chain);
	refused(r.http.post("submit_participation", &body2), 409, "in_use");
	// And in a transfer: given up, so a second spend.
	let (c_leaf, _) = common::client::new_leaf(&keypair("C"));
	let tbody = json!({"inputs": [{"leaf_id": a_coin.id.to_string(), "checkpoint_value": "990000",
		"checkpoint_sig": hex(&[1; 64]), "reassignment_sig": hex(&[1; 64])}],
		"outputs": [{"asset": x.to_string(), "value": "980000", "owner": hex(&c_leaf.owner.serialize()),
		"owner_nonce": hex(&c_leaf.owner_nonce), "creator_nonce": hex(&c_leaf.creator_nonce), "exit_delay_units": c_leaf.exit_delay.units()}]});
	refused(r.http.post("cosign_transfer", &tbody), 409, "double_spend");

	// B's board, attested by another key.
	let b2 = keypair("B, new leaf");
	let (want_b2, _) = want_leaf(&b2, x, VALUE - fee);
	let (mut bad, _) = participation_body(&[&b_coin], std::slice::from_ref(&want_b2), &[(x, fee)], None, s, chain);
	let forged = Held { key: keypair("not B"), ..b_coin.clone() };
	let (forged_body, _) = participation_body(&[&forged], std::slice::from_ref(&want_b2), &[(x, fee)], None, s, chain);
	bad["inputs"][0]["attestation"] = forged_body["inputs"][0]["attestation"].clone();
	refused(r.http.post("submit_participation", &bad), 422, "bad_attestation");
	// An attestation B made for another participation.
	let (want_b3, _) = want_leaf(&keypair("B, third leaf"), x, VALUE - fee);
	let (b3_body, _) = participation_body(&[&b_coin], &[want_b3], &[(x, fee)], None, s, chain);
	bad["inputs"][0]["attestation"] = b3_body["inputs"][0]["attestation"].clone();
	refused(r.http.post("submit_participation", &bad), 422, "bad_attestation");

	// Unbalanced: one atom too many out, one atom too few out, the fee in another asset.
	let (w, _) = want_leaf(&b2, x, VALUE - fee + 1);
	refused(r.http.post("submit_participation", &participation_body(&[&b_coin], &[w], &[(x, fee)], None, s, chain).0), 422, "unbalanced");
	let (w, _) = want_leaf(&b2, x, VALUE - fee - 1);
	refused(r.http.post("submit_participation", &participation_body(&[&b_coin], &[w], &[(x, fee)], None, s, chain).0), 422, "unbalanced");
	let (w, _) = want_leaf(&b2, x, VALUE - fee);
	refused(r.http.post("submit_participation", &participation_body(&[&b_coin], &[w], &[(r.y, fee)], None, s, chain).0), 422, "unbalanced");
	// The fee one atom short of the schedule, balanced.
	let (w, _) = want_leaf(&b2, x, VALUE - fee + 1);
	refused(r.http.post("submit_participation", &participation_body(&[&b_coin], &[w], &[(x, fee - 1)], None, s, chain).0), 422, "fee");

	// A key already wanted by A's participation, and one key twice.
	let (w, _) = want_leaf(&a2, x, VALUE - fee);
	refused(r.http.post("submit_participation", &participation_body(&[&b_coin], &[w], &[(x, fee)], None, s, chain).0), 409, "key_reused");
	let (w1, _) = want_leaf(&b2, x, 500_000);
	let (w2, _) = want_leaf(&b2, x, VALUE - fee - 500_000);
	refused(r.http.post("submit_participation", &participation_body(&[&b_coin], &[w1, w2], &[(x, fee)], None, s, chain).0), 409, "key_reused");
	// A key owning a board.
	let (w, _) = want_leaf(&a, x, VALUE - fee);
	refused(r.http.post("submit_participation", &participation_body(&[&b_coin], &[w], &[(x, fee)], None, s, chain).0), 409, "key_reused");

	// A template a round does not build.
	let mut t = participation_body(&[&b_coin], std::slice::from_ref(&want_b2), &[(x, fee)], None, s, chain).0;
	t["outputs"][0]["leaf"]["template"] = json!("board-1");
	refused(r.http.post("submit_participation", &t), 422, "template");
	t["outputs"][0]["leaf"]["template"] = json!("vtxo-2");
	refused(r.http.post("submit_participation", &t), 422, "template");

	// Outside the bounds: an exit delay, an asset not served, a leaf too small,
	// a round time too far ahead.
	let short = OutputRequest::Leaf { asset: x, value: VALUE - fee, template: arca_covenant::Template::Vtxo1, owner: xonly(&b2),
		owner_nonce: random32(), exit_delay: RelativeTime::from_units(10).unwrap() };
	refused(r.http.post("submit_participation", &participation_body(&[&b_coin], &[short], &[(x, fee)], None, s, chain).0), 422, "out_of_bounds");
	let (w, _) = want_leaf(&b2, r.y, VALUE - fee);
	refused(r.http.post("submit_participation", &participation_body(&[&b_coin], &[w], &[(x, fee)], None, s, chain).0), 422, "out_of_bounds");
	let (w1, _) = want_leaf(&b2, x, MIN_LEAF - 1);
	let (w2, _) = want_leaf(&keypair("B, rest"), x, VALUE - fee - MIN_LEAF + 1);
	refused(r.http.post("submit_participation", &participation_body(&[&b_coin], &[w1, w2], &[(x, fee)], None, s, chain).0), 422, "out_of_bounds");
	let mtp = r.rt.client().blockchain_info().unwrap().median_time as u32;
	refused(r.http.post("submit_participation",
		&participation_body(&[&b_coin], std::slice::from_ref(&want_b2), &[(x, fee)], Some(mtp + 8 * 86_400), s, chain).0), 422, "out_of_bounds");

	// An offboard to a script the server knows as an Arca script.
	let board_leaf = match &a_coin.record { CoinRecord::Board(b) => b.policy().leaf.script_pubkey(), _ => unreachable!() };
	let off = OutputRequest::Offboard { asset: x, value: 500_000, script: board_leaf };
	let (w, _) = want_leaf(&b2, x, VALUE - fee - 500_000 - 2_000);
	refused(r.http.post("submit_participation", &participation_body(&[&b_coin], &[off, w], &[(x, fee + 2_000)], None, s, chain).0), 409, "script_reused");

	// An unknown leaf, a board not yet final, a request with a stray field, a
	// coin given twice, an unknown participation.
	let ghost = Held { id: arca_covenant::LeafId([7; 32]), ..b_coin.clone() };
	refused(r.http.post("submit_participation", &participation_body(&[&ghost], std::slice::from_ref(&want_b2), &[(x, fee)], None, s, chain).0), 404, "unknown_leaf");
	let p = keypair("P");
	let (p_record, _, _) = r.board(&p, VALUE);
	let p_coin = Held { key: p, nonce: p_record.owner_nonce, id: p_record.leaf_id(), record: CoinRecord::Board(p_record) };
	let (w, _) = want_leaf(&keypair("P, new"), x, VALUE - fee);
	refused(r.http.post("submit_participation", &participation_body(&[&p_coin], &[w], &[(x, fee)], None, s, chain).0), 422, "not_live");
	let mut stray = participation_body(&[&b_coin], std::slice::from_ref(&want_b2), &[(x, fee)], None, s, chain).0;
	stray["unexpected"] = json!(1);
	refused(r.http.post("submit_participation", &stray), 400, "malformed");
	let mut stray = participation_body(&[&b_coin], std::slice::from_ref(&want_b2), &[(x, fee)], None, s, chain).0;
	stray["outputs"][0]["offboard"] = json!({"asset": x.to_string(), "value": "1", "script": "51"});
	refused(r.http.post("submit_participation", &stray), 400, "malformed");
	let (w, _) = want_leaf(&b2, x, 2 * VALUE - 2 * fee);
	refused(r.http.post("submit_participation", &participation_body(&[&b_coin, &b_coin], &[w], &[(x, 2 * fee)], None, s, chain).0), 400, "malformed");
	refused(r.http.post("participation_status", &json!({"participation_id": hex(&[9; 32])})), 404, "unknown_participation");

	// A transfer paying a key a participation wants: the key is promised.
	let b_valid = b_coin.record.resolve(std::slice::from_ref(&b_tx), &r.policy()).unwrap();
	let promised = arca_covenant::NewLeaf { owner: xonly(&a2), owner_nonce: random32(), creator_nonce: random32(), exit_delay: common::client::exit_delay() };
	let body = common::client::transfer_body(&[(&b_coin, b_valid, VALUE - 2_000)], &[(x, VALUE - 4_000, promised)], s, chain);
	refused(r.http.post("cosign_transfer", &body), 409, "key_reused");

	// B, honestly, half to a new leaf and half offboard to an address of its
	// own: the offboard pays its percentage and its output's margin.
	let addr = node::op_true();
	let (w, _) = want_leaf(&b2, x, 400_000);
	let off = OutputRequest::Offboard { asset: x, value: 500_000, script: addr };
	let (body, _) = participation_body(&[&b_coin], &[w, off], &[(x, VALUE - 900_000)], None, s, chain);
	let st = r.http.post("submit_participation", &body).ok();
	println!("participation with an offboard accepted: {}", st);
	let margin: u64 = st["outputs"][1]["margin"].as_str().unwrap().parse().unwrap();
	assert!(margin > 0, "X is accepted for fees: the offboard's output holds a margin for its unlock");
	assert!(VALUE - 900_000 >= fee + 500_000 * OFFBOARD_PPM / 1_000_000 + margin, "the fee covers the schedule");
	assert_eq!(st["outputs"][1]["reclaim_delay_units"], 2 * 338 + 338);
}
