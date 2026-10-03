//! Offboards, against a whole server on an anchored proof-of-stake regtest
//! chain, the watcher driven a pass at a time, a block between passes:
//!
//! 1. Offboards in X (listed for fees) and in Y (not listed): once each
//!    owner hands over its forfeit, the watcher unlocks each output to its
//!    destination with the preimage, the output's margin paying in X and a
//!    wallet coin of X paying for Y's; the boards given up come back to the
//!    operator, Y's claim paid by a coin of X too.
//! 2. An offboard whose owner never hands over its forfeit: the
//!    participation expires and the coin is the owner's again; the watcher
//!    does not unlock the output and does not reclaim it before its delay (a
//!    reclaim signed early is refused); after the delay it reclaims it.
//! 3. An owner offboards a batch leaf, is paid on-chain, and then brings the
//!    leaf it gave up back on-chain: the watcher answers with the forfeit and
//!    claims it, and the owner's exit is refused.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Script, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::{ExplicitOutput, Forfeit, OffboardPolicy, RelativeTime, ValidOrigin};
use common::client::{forfeit_sig, hex, participation_body, random32, unhex};
use common::flow::{claim_of, drive, exit_tx, final_of, has, log, of_kind, refresh, settle, txid, verdict, Coin};
use common::keys::{keypair, xonly};
use common::rounds::{advance_mtp, credited_board, round_final, start, status, VALUE};
use common::running::Running;
use server::participations::OutputRequest;

const HOUR: u32 = 3_600;
const PAID: u64 = 900_000;
const FEE: u64 = 100_000;

fn send(r: &Running, what: &str, tx: &Transaction) -> Txid {
	let txid = r.rt.client().send_raw_transaction(tx).unwrap_or_else(|e| panic!("{}: {}", what, e));
	println!("{}: {} ({} vB)", what, txid, tx.vsize());
	txid
}

/// A destination script of the owner's: a v0 key hash of `key`.
fn destination(key: &Keypair) -> Script {
	Script::new_v0_wpkh(&elements::WPubkeyHash::hash(&key.public_key().serialize()))
}

/// More coins of X for the wallet, final: each transaction a coin pays the
/// fee of takes one until its change is final.
async fn fund_x(r: &mut Running, n: usize) {
	let x = r.x;
	for _ in 0..n {
		r.fund_wallet_in(x, 5_000_000).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
}

async fn board_coin(r: &mut Running, key: &Keypair, asset: AssetId) -> Coin {
	let (held, tx) = credited_board(r, key, asset).await;
	Coin { held, bases: vec![tx] }
}

/// An offboard of all of `coin` but the fee, to `to`: the participation's id.
fn offboard(r: &Running, coin: &Coin, to: &Script) -> [u8; 32] {
	let v = coin.valid(r);
	let out = OutputRequest::Offboard { asset: v.asset, value: PAID, script: to.clone() };
	let (body, id) = participation_body(&[&coin.held], &[out], &[(v.asset, FEE)], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending", "{}", body);
	id
}

/// The offboard output's policy, from the participation's status, as its
/// owner rebuilds it.
fn policy_of(r: &Running, id: &[u8; 32], asset: AssetId, to: &Script) -> (OffboardPolicy, Value) {
	let st = status(r, id);
	let units = st["outputs"][0]["reclaim_delay_units"].as_u64().unwrap() as u16;
	(OffboardPolicy {
		unlock_hash: unhex(st["unlock_hash"].as_str().unwrap()).try_into().unwrap(),
		destination: ExplicitOutput::new(asset, PAID, to.clone()),
		operator: xonly(&r.s),
		reclaim_delay: RelativeTime::from_units(units).unwrap(),
	}, st)
}

/// The owner checks the round pays its offboard and hands over its forfeit:
/// the preimage.
fn complete(r: &Running, id: &[u8; 32], coin: &Coin, to: &Script) -> [u8; 32] {
	let v = coin.valid(r);
	let (policy, st) = policy_of(r, id, v.asset, to);
	let round = r.rt.client().raw_transaction(&common::client::txid(st["round"]["txid"].as_str().unwrap())).unwrap();
	let c = st["round"]["connector_vout"].as_u64().unwrap() as u32;
	let delay = RelativeTime::from_units(st["refund_delay_units"].as_u64().unwrap() as u16).unwrap();
	let margin: u64 = st["inputs"][0]["margin"].as_str().unwrap().parse().unwrap();
	let f = Forfeit::for_offboard(v.leaf, (v.asset, v.value), v.id, &policy, &round, c, delay, margin).unwrap();
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(id),
		"forfeits": [{"leaf_id": coin.held.id.to_string(), "signature": forfeit_sig(&f, &coin.held.key)}], "leaves": []})).ok();
	assert_eq!(done["state"], "released", "{}", done);
	unhex(done["preimage"].as_str().unwrap()).try_into().unwrap()
}

/// Where the round put the offboard of participation `id`.
fn offboard_at(r: &Running, id: &[u8; 32]) -> OutPoint {
	let st = status(r, id);
	OutPoint::new(common::client::txid(st["round"]["txid"].as_str().unwrap()), st["outputs"][0]["offboard_vout"].as_u64().unwrap() as u32)
}

fn subject(op: &OutPoint) -> Vec<u8> {
	[op.txid.to_byte_array().to_vec(), op.vout.to_le_bytes().to_vec()].concat()
}

#[tokio::test(flavor = "multi_thread")]
async fn offboards_in_either_asset_are_unlocked_by_the_watcher() {
	let mut r = start().await;
	let (x, y) = (r.x, r.y);
	fund_x(&mut r, 4).await;
	let (ox, oy) = (keypair("O1 X"), keypair("O1 Y"));
	let cx = board_coin(&mut r, &ox, x).await;
	let cy = board_coin(&mut r, &oy, y).await;
	let (dx, dy) = (destination(&keypair("O1 X, on-chain")), destination(&keypair("O1 Y, on-chain")));
	let (px, py) = (offboard(&r, &cx, &dx), offboard(&r, &cy, &dy));
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	println!("round {}: {} vB, {} offboard(s), {} batch(es)", built.tx.txid(), built.tx.vsize(), built.offboards, built.batches.len());
	assert_eq!(built.offboards, 2);
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let (ax, ay) = (offboard_at(&r, &px), offboard_at(&r, &py));
	println!("offboard outputs: X at {} holding {:?}, Y at {} holding {:?}", ax, built.tx.output[ax.vout as usize].value.explicit(),
		ay, built.tx.output[ay.vout as usize].value.explicit());
	assert_eq!(built.tx.output[ay.vout as usize].value.explicit(), Some(PAID), "Y is not listed: no margin, a fee coin pays its unlock");

	// Before the forfeits: nothing to unlock.
	r.server.watcher.pass().await.unwrap();
	assert!(of_kind(&r, "unlock").await.is_empty(), "no unlock before the owner's forfeit");
	complete(&r, &px, &cx, &dx);
	complete(&r, &py, &cy, &dy);
	drive(&r, "the unlocks and the boards", 12, |l| has(l, "unlock", &subject(&ax)) && has(l, "unlock", &subject(&ay))
		&& has(l, "claim", &cx.held.id.0) && has(l, "claim", &cy.held.id.0)).await;
	settle(&r).await;
	let l = log(&r).await;
	assert!(l.iter().all(|w| w.state == server::store::NurseryState::Final), "everything is final");
	for (who, at, to, asset) in [("X", ax, &dx, x), ("Y", ay, &dy, y)] {
		let w = l.iter().find(|w| w.kind == "unlock" && w.subject == subject(&at)).unwrap();
		let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
		assert_eq!(tx.input[0].previous_output, at);
		assert_eq!((&tx.output[0].script_pubkey, tx.output[0].asset.explicit(), tx.output[0].value.explicit()), (to, Some(asset), Some(PAID)),
			"{}'s destination is paid in full", who);
		let fee_asset = tx.output.iter().find(|o| o.is_fee()).and_then(|o| o.asset.explicit()).unwrap();
		println!("the offboard in {} unlocked by {} ({} vB, {} inputs), its fee in {}", who, txid(w), tx.vsize(), tx.input.len(),
			if fee_asset == x { "X" } else { "Y" });
		assert_eq!(fee_asset, x, "the fee is in X, which the node accepts");
	}
	// The Y board came back too: its forfeit and claim paid by coins of X.
	for kind in ["forfeit", "claim"] {
		let w = if kind == "claim" { claim_of(&l, &cy.held.id.0).unwrap() } else {
			l.iter().find(|w| w.kind == kind && w.subject == cy.held.id.0.to_vec()).unwrap()
		};
		let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
		let fee_asset = tx.output.iter().find(|o| o.is_fee()).and_then(|o| o.asset.explicit()).unwrap();
		println!("Y board's {} {} ({} vB): fee in {}", kind, txid(w), tx.vsize(), if fee_asset == x { "X" } else { "Y" });
		assert_eq!(fee_asset, x);
	}
	assert!(final_of(&l, "claim", &cx.held.id.0));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_offboard_never_forfeited_is_reclaimed_after_its_delay() {
	let mut r = start().await;
	let x = r.x;
	let q = keypair("O2 Q");
	let cq = board_coin(&mut r, &q, x).await;
	let dq = destination(&keypair("O2 Q, on-chain"));
	let pq = offboard(&r, &cq, &dq);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let at = offboard_at(&r, &pq);
	let (policy, _) = policy_of(&r, &pq, x, &dq);
	println!("Q's offboard at {}, reclaimable {} units after it confirmed", at, policy.reclaim_delay.units());

	// Q never hands over its forfeit: a day after the round is final the
	// participation expires, and the board is Q's again.
	advance_mtp(&r, 86_400 + 600).await;
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	assert_eq!(status(&r, &pq)["state"], "expired");
	let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", &q, &r.chain)})).ok();
	assert_eq!(ld["leaves"][0]["state"], "live", "Q's board is Q's again");
	r.server.watcher.pass().await.unwrap();
	assert!(of_kind(&r, "unlock").await.is_empty() && of_kind(&r, "offboard_reclaim").await.is_empty(),
		"neither unlocked, since its preimage never went out, nor reclaimed before its delay");
	// A reclaim signed now is refused: the delay has not passed.
	let held = built.tx.output[at.vout as usize].value.explicit().unwrap();
	let early = policy.reclaim(at, held, &[ExplicitOutput::new(x, held - 2_000, common::node::op_true())], &FeeSource::Reserve).unwrap();
	let sig = sign_digest(&r.s, &early.sighash(r.chain.genesis_hash()).unwrap(), &random32());
	let early = early.finish(vec![sig.as_ref().to_vec()]);
	let e = verdict(&r, &early.tx).unwrap_err();
	println!("the operator's reclaim before the delay: refused, {}", e);
	assert!(e.contains("non-BIP68-final"), "{}", e);

	let before = r.server.wallet.balance().await.unwrap().get(&x).copied().unwrap_or(0);
	advance_mtp(&r, policy.reclaim_delay.seconds() as u32 + HOUR).await;
	drive(&r, "the reclaim after the delay", 4, |l| has(l, "offboard_reclaim", &subject(&at))).await;
	settle(&r).await;
	let l = log(&r).await;
	assert!(final_of(&l, "offboard_reclaim", &subject(&at)));
	assert!(of_kind(&r, "unlock").await.is_empty(), "never unlocked");
	let after = r.server.wallet.balance().await.unwrap().get(&x).copied().unwrap_or(0);
	println!("the wallet holds {} more of X: the offboard output reclaimed", after as i64 - before as i64);
	assert!(after > before + PAID - 10_000);
	assert!(r.unspent(&cq.valid(&r).board().unwrap().1), "Q's board is untouched");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_offboarded_leaf_brought_back_on_chain_is_answered() {
	let mut r = start().await;
	let x = r.x;
	let (o0, p0) = (keypair("O3 O, board"), keypair("O3 P, board"));
	let co = board_coin(&mut r, &o0, x).await;
	let cp = board_coin(&mut r, &p0, x).await;
	let (o1, p1) = (keypair("O3 O"), keypair("O3 P"));
	let first = refresh(&mut r, &[(&co, &o1), (&cp, &p1)]).await;
	println!("round 1: O and P each hold a leaf of one batch");

	// O offboards its leaf and is paid on-chain.
	let dest = destination(&keypair("O3 O, on-chain"));
	let po = offboard(&r, &first[0].new, &dest);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	complete(&r, &po, &first[0].new, &dest);
	let at = offboard_at(&r, &po);
	drive(&r, "O's offboard", 6, |l| has(l, "unlock", &subject(&at))).await;
	settle(&r).await;
	println!("O is paid {} of X at its own script", PAID);

	// O then takes back the leaf it gave up.
	let v = first[0].new.valid(&r);
	let (valid, preimage, auths) = match &v.origin {
		ValidOrigin::Leaf { valid, preimage, auths } => (valid, preimage, auths),
		_ => unreachable!(),
	};
	let txs = valid.branch.unroll(OutPoint::new(valid.round_txid, valid.batch_vout), auths, &vec![FeeSource::Reserve; auths.len()]).unwrap();
	for u in &txs {
		send(&r, "O unrolls its old leaf's path", &u.tx);
	}
	let entry = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), preimage, &FeeSource::Reserve).unwrap();
	let leaf_at = OutPoint::new(send(&r, "O unlocks its old entry", &entry.tx), 0);
	let id = first[0].new.held.id.0.to_vec();
	drive(&r, "the answer to O", 6, |l| has(l, "claim", &id)).await;
	settle(&r).await;
	let l = log(&r).await;
	assert!(final_of(&l, "forfeit", &id) && final_of(&l, "claim", &id));
	let f = l.iter().find(|w| w.kind == "forfeit" && w.subject == id).unwrap();
	let ftx: Transaction = elements::encode::deserialize(&f.tx).unwrap();
	assert_eq!(ftx.input[0].previous_output, leaf_at);
	advance_mtp(&r, 37 * HOUR).await;
	let e = verdict(&r, &exit_tx(&r, &valid.branch.leaf, leaf_at, x, VALUE, &o1)).unwrap_err();
	println!("O's exit of the leaf it offboarded, after its delay: refused, {}", e);
	assert!(e.contains("missingorspent") || e.contains("missing-inputs"), "{}", e);
}
