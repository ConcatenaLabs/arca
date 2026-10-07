//! The watcher, against a whole server on an anchored proof-of-stake regtest
//! chain: `arca-signer` in its own process, PostgreSQL, the wallet paid in X
//! and Y and never the policy asset, the minimal client playing every owner.
//! Each test but the second drives the watcher a pass at a time, a block
//! between passes:
//!
//! 1. Boards given up in a round come back: the forfeit from the board
//!    output, the round's connector asset issued, the claim. A refreshed
//!    batch leaf brought back on-chain by its owner (a stale exit) is
//!    answered by its forfeit at once and claimed; the owner's exit is
//!    refused once the delay has passed.
//! 2. A board paid out of round and then converted by its sender is answered
//!    by its checkpoint and the reassignment, by the watcher running on its
//!    own as the server's task; the sender's exit is refused, and the
//!    receiver's leaf is on the chain.
//! 3. A batch past its expiry: nothing before `E`; the release at `E`; no
//!    sweep before the notice; then one sweep of everything of the batch
//!    still unspent (a lowest node and an entry an owner had unrolled), while
//!    the owner's own leaf, which it put on-chain, exits untouched.
//! 4. A batch every owner has refreshed and released, in two rounds, comes
//!    back before it expires: the batch output unrolled by an owner's
//!    authorisation, each lowest node reclaimed with an atom of each round's
//!    connector asset.
//! 6. A coin paid out of round from a board and then refreshed by its
//!    receiver rests on that board alone, which no batch sweeps: the board
//!    carries the dates of a batch made when it confirmed (`board_status`).
//!    While the sender's change rests live on the same lineage the watcher
//!    publishes nothing of it. Past the board's exit deadline the change is
//!    refused in a transfer and in a refresh, and the watcher still waits
//!    while it rests live on the lineage; from the board's expiry it
//!    publishes the board's checkpoint, the reassignment and B's forfeit, and
//!    claims it.
//! 5. An anchor-driven reorganisation: the parent orphans the block a round
//!    and the watcher's answer to a stale exit are anchored to; the node
//!    disconnects them, the nursery broadcasts them again unchanged, and they
//!    are final again with the same txids; the owner's exit is still refused.
//!
//! The refusals here are the mempool's: a proof-of-stake chain takes no block
//! its committee did not make. The covenant's regtest suite forces every
//! script's negatives into blocks on a chain that can.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::{OutPoint, Transaction, Txid};

use arca_covenant::sign::sign_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::witness::find_preimage;
use arca_covenant::ValidOrigin;
use common::client::{new_leaf, random32, transfer_body, unhex};
use common::flow::{claim_of, claimed, drive, exit_tx, final_of, has, log, of_kind, refresh, settle, txid, verdict, Coin};
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{advance_mtp, credited_board, start, VALUE};
use common::running::Running;

const HOUR: u32 = 3_600;

fn send(r: &Running, what: &str, tx: &Transaction) -> Txid {
	let txid = r.rt.client().send_raw_transaction(tx).unwrap_or_else(|e| panic!("{}: {}", what, e));
	println!("{}: {} ({} vB)", what, txid, tx.vsize());
	txid
}

/// A server as [`start`] gives one, with its watcher acting on its own as
/// it follows the chain.
async fn start_watching() -> Running {
	let mut r = Running::start_with(|c, y| {
		c.assets.push(server::server::AssetSection { asset: y.to_string(), min_leaf: common::running::MIN_LEAF.to_string() });
		c.watcher.enabled = true;
	}).await;
	let (x, y) = (r.x, r.y);
	for asset in [x, x, x, y] {
		r.fund_wallet_in(asset, 50_000_000).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r
}

/// Produces blocks, the watcher acting on its own, until its log satisfies
/// `done`.
async fn wait_for<F: FnMut(&[server::store::WatcherTxRow]) -> bool>(r: &Running, what: &str, blocks: usize, mut done: F) {
	for n in 0..blocks {
		for _ in 0..20 {
			if done(&log(r).await) {
				println!("{}: done by the watcher's own task after {} block(s)", what, n);
				for w in log(r).await {
					println!("  watcher: {} {}: {}", w.kind, txid(&w), w.detail);
				}
				return;
			}
			tokio::time::sleep(std::time::Duration::from_millis(250)).await;
		}
		r.produce().await;
	}
	panic!("{}: not done after {} blocks", what, blocks);
}

async fn board_coin(r: &mut Running, key: &Keypair) -> Coin {
	let (held, tx) = credited_board(r, key, r.x).await;
	Coin { held, bases: vec![tx] }
}

async fn x_balance(r: &Running) -> u64 {
	r.server.wallet.balance().await.unwrap().get(&r.x).copied().unwrap_or(0)
}

/// The unroll of `coin`, a batch leaf, from its batch output down by its
/// owner's own authorisations, and its entry with its preimage, each
/// broadcast and mined: the leaf's outpoint.
async fn unroll_to_leaf(r: &Running, coin: &Coin, label: &str) -> OutPoint {
	let v = coin.valid(r);
	let (valid, preimage, auths) = match &v.origin {
		ValidOrigin::Leaf { valid, preimage, auths } => (valid, preimage, auths),
		_ => panic!("not a batch leaf"),
	};
	let txs = valid.branch.unroll(OutPoint::new(valid.round_txid, valid.batch_vout), auths, &vec![FeeSource::Reserve; auths.len()]).unwrap();
	for (level, u) in txs.iter().enumerate() {
		send(r, &format!("{}: unroll, level {}, by the owner's authorisation", label, level), &u.tx);
	}
	let entry = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), preimage, &FeeSource::Reserve).unwrap();
	let at = send(r, &format!("{}: its entry, with its preimage", label), &entry.tx);
	OutPoint::new(at, 0)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_exit_is_answered_and_refreshed_boards_come_back() {
	let mut r = start().await;
	let x = r.x;
	let ca = board_coin(&mut r, &keypair("W1 A, board")).await;
	let cb = board_coin(&mut r, &keypair("W1 B, board")).await;
	let (a1, b1) = (keypair("W1 A, round 1"), keypair("W1 B, round 1"));
	let first = refresh(&mut r, &[(&ca, &a1), (&cb, &b1)]).await;
	println!("round 1: boards A and B refreshed into a batch of two leaves");

	// The boards given up come back to the operator: a board never expires.
	let before = x_balance(&r).await;
	let (ida, idb) = (ca.held.id.0.to_vec(), cb.held.id.0.to_vec());
	drive(&r, "the boards given up in round 1", 8, |l| has(l, "claim", &ida) && has(l, "claim", &idb)).await;
	settle(&r).await;
	let l = log(&r).await;
	for (who, id) in [("A", &ida), ("B", &idb)] {
		assert!(final_of(&l, "forfeit", id) && final_of(&l, "claim", id), "board {}'s forfeit and claim are final", who);
	}
	assert_eq!(of_kind(&r, "issue").await.len(), 1, "one atom of round 1's connector asset serves both claims");
	for c in [&ca, &cb] {
		let board = c.valid(&r).board().unwrap().1;
		assert!(!r.unspent(&board), "the board output {} is spent by its forfeit", board);
	}
	let after = x_balance(&r).await;
	println!("the wallet holds {} more of X, from two boards of {}", after as i64 - before as i64, VALUE);
	assert!(after > before + VALUE, "both boards' value, less the fees, is the operator's again");

	// A board owner who gave up its board cannot take it now.
	let (policy, at) = ca.valid(&r).board().unwrap();
	let fee_coin = r.purse.take_coin(x);
	let conv = policy.conversion(at, &FeeSource::Coin { outpoint: fee_coin.0, coin: fee_coin.1.clone(), fee: 3_000, change: node::op_true() }).unwrap();
	let sig = sign_digest(&ca.held.key, &conv.sighash(r.chain.genesis_hash()).unwrap(), &random32());
	let conv = conv.finish(vec![sig.as_ref().to_vec()]);
	let e = verdict(&r, &conv.tx).unwrap_err();
	println!("A's conversion of its board after the watcher's forfeit: refused, {}", e);
	assert!(e.contains("missingorspent") || e.contains("missing-inputs"), "{}", e);
	r.purse.put(fee_coin);

	// Round 2: A refreshes its leaf of round 1.
	let a2 = keypair("W1 A, round 2");
	let second = refresh(&mut r, &[(&first[0].new, &a2)]).await;
	println!("round 2: A's leaf of round 1 refreshed");

	// A goes back on its word: it brings the leaf it gave up on-chain.
	let leaf_at = unroll_to_leaf(&r, &first[0].new, "A's stale exit").await;
	let a_leaf = first[0].new_valid.branch.leaf;
	let early = exit_tx(&r, &a_leaf, leaf_at, x, VALUE, &a1);
	let e = verdict(&r, &early).unwrap_err();
	println!("A's exit before its delay: refused, {}", e);
	assert!(e.contains("non-BIP68-final"), "{}", e);

	// The watcher answers at once with the forfeit, and claims it.
	let id1 = first[0].new.held.id.0.to_vec();
	drive(&r, "the answer to A's stale exit", 6, |l| has(l, "claim", &id1)).await;
	settle(&r).await;
	let l = log(&r).await;
	let forfeit = l.iter().find(|w| w.kind == "forfeit" && w.subject == id1).unwrap();
	let ftx: Transaction = elements::encode::deserialize(&forfeit.tx).unwrap();
	assert_eq!(ftx.input[0].previous_output, leaf_at, "the forfeit spends A's leaf where A put it");
	assert!(final_of(&l, "forfeit", &id1) && final_of(&l, "claim", &id1), "the forfeit and its claim are final");
	let claim = claim_of(&l, &id1).unwrap();
	let ctx: Transaction = elements::encode::deserialize(&claim.tx).unwrap();
	let h = arca_covenant::script::sha256(&second[0].preimage);
	assert_eq!(find_preimage(&ctx.input[0].witness.script_witness, &h), Some(second[0].preimage),
		"the claim reveals the preimage of A's round-2 leaf, which A holds already");
	println!("A's leaf {} answered: forfeit {}, claim {}", leaf_at, txid(forfeit), txid(claim));

	// Past the delay, A's exit is refused: the forfeit spent the leaf.
	advance_mtp(&r, 37 * HOUR).await;
	let late = exit_tx(&r, &a_leaf, leaf_at, x, VALUE, &a1);
	let e = verdict(&r, &late).unwrap_err();
	println!("A's exit after its delay: refused, {}", e);
	assert!(e.contains("missingorspent") || e.contains("missing-inputs"), "{}", e);
	// And its refund of the forfeit: the claim spent the forfeit output.
	assert!(!r.unspent(&OutPoint::new(txid(forfeit), 0)), "the forfeit output is the operator's");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_board_paid_out_of_round_and_then_converted_is_answered() {
	let mut r = start_watching().await;
	let (x, s) = (r.x, xonly(&r.s));
	let a = keypair("W2 A");
	let ca = board_coin(&mut r, &a).await;
	let (b, a2) = (keypair("W2 B"), keypair("W2 A, change"));
	let (b_leaf, b_nonce) = new_leaf(&b);
	let (a2_leaf, _) = new_leaf(&a2);
	let kept = VALUE - 2_000;
	let outputs = vec![(x, 600_000, b_leaf), (x, kept - 600_000 - 2_000, a2_leaf)];
	let a_valid = ca.valid(&r);
	let done = r.http.post("cosign_transfer", &transfer_body(&[(&ca.held, a_valid.clone(), kept)], &outputs, s, r.chain)).ok();
	let transfer: Vec<u8> = unhex(done["transfer_id"].as_str().unwrap());
	let mail = r.http.mailbox(&b, &r.chain, 0);
	let (_, b_id, b_record) = mail[0].clone();
	let b_valid = b_record.validate(&ca.bases, &r.policy(), &xonly(&b), &b_nonce).unwrap();
	println!("A paid B 600000 of X out of round from its board: B's coin {}", b_id);

	// A takes its board back anyway: it converts it, its own coin paying.
	let (policy, at) = a_valid.board().unwrap();
	let fee_coin = r.purse.take_coin(x);
	let conv = policy.conversion(at, &FeeSource::Coin { outpoint: fee_coin.0, coin: fee_coin.1.clone(), fee: 3_000, change: node::op_true() }).unwrap();
	let sig = sign_digest(&a, &conv.sighash(r.chain.genesis_hash()).unwrap(), &random32());
	let conv = conv.finish(vec![sig.as_ref().to_vec()]);
	let leaf_at = OutPoint::new(send(&r, "A converts the board it paid away", &conv.tx), 0);

	// The watcher, running on its own, answers with A's checkpoint, then
	// the reassignment.
	wait_for(&r, "the answer to A's conversion", 6, |l| has(l, "reassignment", &transfer)).await;
	settle(&r).await;
	let l = log(&r).await;
	assert!(final_of(&l, "checkpoint", &ca.held.id.0) && final_of(&l, "reassignment", &transfer), "both are final");
	let cp = l.iter().find(|w| w.kind == "checkpoint").unwrap();
	let cptx: Transaction = elements::encode::deserialize(&cp.tx).unwrap();
	assert_eq!(cptx.input[0].previous_output, leaf_at, "the checkpoint spends the leaf A's conversion made");
	let re = l.iter().find(|w| w.kind == "reassignment").unwrap();
	let retx: Transaction = elements::encode::deserialize(&re.tx).unwrap();
	assert_eq!(retx.output[0].script_pubkey, b_valid.leaf.script_pubkey(), "B's leaf is on the chain");
	assert_eq!(retx.output[0].value.explicit(), Some(600_000));

	// A's exit is refused, past the delay; B's exit, past its own, confirms.
	advance_mtp(&r, 37 * HOUR).await;
	let e = verdict(&r, &exit_tx(&r, &policy.leaf, leaf_at, x, VALUE, &a)).unwrap_err();
	println!("A's exit of its converted board after the delay: refused, {}", e);
	assert!(e.contains("missingorspent") || e.contains("missing-inputs"), "{}", e);
	let b_exit = exit_tx(&r, &b_valid.leaf, OutPoint::new(txid(re), 0), x, 600_000, &b);
	send(&r, "B's exit of the leaf the watcher published", &b_exit);
	r.produce().await;
	assert!(r.rt.client().confirmations(&b_exit.txid()).unwrap() >= 1);
}

/// The unroll of node `level` of `coin`'s path, held at `at`, by the coin's
/// owner's authorisation: the transaction, broadcast.
fn unroll_level(r: &Running, coin: &Coin, level: usize, at: OutPoint, label: &str) -> Transaction {
	let v = coin.valid(r);
	let (valid, auths) = match &v.origin {
		ValidOrigin::Leaf { valid, auths, .. } => (valid, auths),
		_ => panic!("not a batch leaf"),
	};
	let u = valid.branch.nodes[level].unroll_tx(at, &auths[level], &FeeSource::Reserve).unwrap();
	send(r, label, &u.tx);
	u.tx
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_batch_is_released_then_swept() {
	let mut r = start().await;
	let x = r.x;
	let mut boards = vec![];
	let mut keys = vec![];
	for i in 0..5 {
		boards.push(board_coin(&mut r, &keypair(&format!("W3 U{}, board", i))).await);
		keys.push(keypair(&format!("W3 U{}", i)));
	}
	let pairs: Vec<(&Coin, &Keypair)> = boards.iter().zip(&keys).collect();
	let got = refresh(&mut r, &pairs).await;
	let round = got[0].round.clone();
	let schedule = got[0].new_valid.branch.nodes[0].sweep;
	let e0 = match &got[0].new.held.record {
		arca_covenant::CoinRecord::Leaf { record, .. } => record.schedule.expiries()[0].to_consensus_u32(),
		_ => unreachable!(),
	};
	println!("a batch of five leaves (lowest nodes of 3 and 2), expiring at {}", e0);
	// The boards given up come back first; then nothing more to do.
	drive(&r, "the five boards", 12, |l| claimed(l) == 5).await;
	settle(&r).await;

	// U0 unrolls the batch output and U3 its lowest node and its entry: an
	// owner taking its own leaf on-chain, as it may.
	let batch_at = OutPoint::new(round.txid(), got[0].new_valid.batch_vout);
	let root = unroll_level(&r, &got[0].new, 0, batch_at, "U0 unrolls the batch output");
	let low1 = unroll_level(&r, &got[3].new, 1, OutPoint::new(root.txid(), 1), "U3 unrolls lowest node 1");
	let v3 = got[3].new.valid(&r);
	let entry = match &v3.origin {
		ValidOrigin::Leaf { valid, preimage, .. } => valid.branch.entry_tx(OutPoint::new(low1.txid(), 0), preimage, &FeeSource::Reserve).unwrap(),
		_ => unreachable!(),
	};
	let u3_leaf = OutPoint::new(send(&r, "U3 unlocks its entry into its leaf", &entry.tx), 0);
	settle(&r).await;

	// Before the expiry: no release.
	r.server.watcher.pass().await.unwrap();
	assert!(of_kind(&r, "release").await.is_empty(), "nothing before the expiry");
	println!("before E: the watcher releases nothing");
	let now = common::rounds::mtp(&r).to_consensus_u32();
	advance_mtp(&r, e0.saturating_sub(now) + HOUR).await;
	let token_subject = schedule.token.into_inner().to_byte_array().to_vec();
	drive(&r, "the release at the expiry", 4, |l| has(l, "release", &token_subject)).await;
	settle(&r).await;
	// The notice: no sweep yet.
	r.server.watcher.pass().await.unwrap();
	assert!(of_kind(&r, "sweep").await.is_empty(), "no sweep before the token has waited W at R");
	println!("after the release: no sweep during the notice");
	let before = x_balance(&r).await;
	advance_mtp(&r, 37 * HOUR).await;
	drive(&r, "the sweep after the notice", 4, |l| has(l, "sweep", &token_subject)).await;
	settle(&r).await;
	let sw = of_kind(&r, "sweep").await.remove(0);
	let swtx: Transaction = elements::encode::deserialize(&sw.tx).unwrap();
	let swept: Vec<OutPoint> = swtx.input.iter().map(|i| i.previous_output).collect();
	println!("the sweep {} takes {:?}", txid(&sw), swept);
	assert!(swept.contains(&OutPoint::new(root.txid(), 0)), "lowest node 0, which U0 unrolled");
	assert!(swept.contains(&OutPoint::new(low1.txid(), 1)), "U4's entry, which U3 unrolled");
	assert_eq!(swtx.input.len(), 3, "the two, and the token at R");
	assert!(!swept.contains(&u3_leaf));
	let after = x_balance(&r).await;
	println!("the wallet holds {} more of X", after as i64 - before as i64);
	assert!(after > before + 4 * VALUE, "lowest node 0's three leaves and U4's leaf, less the fee");
	// U3's leaf is U3's: it exits.
	let u3 = exit_tx(&r, &v3.leaf, u3_leaf, x, VALUE, &keys[3]);
	send(&r, "U3's exit of its own leaf", &u3);
	r.produce().await;
	assert!(r.rt.client().confirmations(&u3.txid()).unwrap() >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_batch_every_owner_released_comes_back_before_it_expires() {
	let mut r = start().await;
	let mut boards = vec![];
	let mut keys = vec![];
	for i in 0..5 {
		boards.push(board_coin(&mut r, &keypair(&format!("W4 U{}, board", i))).await);
		keys.push(keypair(&format!("W4 U{}", i)));
	}
	let pairs: Vec<(&Coin, &Keypair)> = boards.iter().zip(&keys).collect();
	let first = refresh(&mut r, &pairs).await;
	let round1 = first[0].round.clone();
	drive(&r, "the five boards", 12, |l| claimed(l) == 5).await;
	settle(&r).await;

	// Owners 0, 1, 2 refresh in round 2 and release; owners 3 and 4 in round 3.
	let k2: Vec<Keypair> = (0..5).map(|i| keypair(&format!("W4 U{}, again", i))).collect();
	let second = refresh(&mut r, &[(&first[0].new, &k2[0]), (&first[1].new, &k2[1]), (&first[2].new, &k2[2])]).await;
	for x in &second {
		common::flow::release(&r, x);
	}
	r.server.watcher.pass().await.unwrap();
	assert!(of_kind(&r, "unroll").await.is_empty() && of_kind(&r, "reclaim").await.is_empty(),
		"owners 3 and 4 have not released: nothing is unrolled");
	println!("three of five owners released: the watcher waits");
	let third = refresh(&mut r, &[(&first[3].new, &k2[3]), (&first[4].new, &k2[4])]).await;
	for x in &third {
		common::flow::release(&r, x);
	}
	let before = x_balance(&r).await;
	drive(&r, "the unroll and the reclaims", 10, |l| l.iter().filter(|w| w.kind == "reclaim").count() == 2).await;
	settle(&r).await;
	let l = log(&r).await;
	let unrolls: Vec<_> = l.iter().filter(|w| w.kind == "unroll").collect();
	assert_eq!(unrolls.len(), 1, "the batch output, unrolled once");
	let utx: Transaction = elements::encode::deserialize(&unrolls[0].tx).unwrap();
	assert_eq!(utx.input[0].previous_output, OutPoint::new(round1.txid(), first[0].new_valid.batch_vout));
	let reclaims: Vec<Transaction> = l.iter().filter(|w| w.kind == "reclaim")
		.map(|w| elements::encode::deserialize(&w.tx).unwrap()).collect();
	let m2 = arca_covenant::connector_asset(second[0].round.txid(), second[0].connector_vout);
	let m3 = arca_covenant::connector_asset(third[0].round.txid(), third[0].connector_vout);
	for (k, tx) in reclaims.iter().enumerate() {
		let spends: Vec<_> = tx.input.iter().map(|i| i.previous_output).collect();
		println!("reclaim {}: {} ({} vB) spends {:?}", k, tx.txid(), tx.vsize(), spends);
		assert!(tx.output.iter().any(|o| o.asset.explicit() == Some(m2)) || tx.output.iter().any(|o| o.asset.explicit() == Some(m3)),
			"each reclaim pays an atom of the connector asset its releases name back to the wallet");
	}
	assert!(l.iter().all(|w| w.state == server::store::NurseryState::Final), "everything the watcher published is final");
	assert_eq!(of_kind(&r, "issue").await.len(), 3, "round 1's (for the boards), round 2's and round 3's connector assets");
	let after = x_balance(&r).await;
	println!("the wallet holds {} more of X, round 1's batch back before its expiry", after as i64 - before as i64);
	assert!(after > before + 4 * VALUE);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_anchor_driven_reorganisation_takes_out_a_round_and_the_answers() {
	let mut r = start().await;
	let x = r.x;
	let ca = board_coin(&mut r, &keypair("W5 A, board")).await;
	let cb = board_coin(&mut r, &keypair("W5 B, board")).await;
	let (a1, b1) = (keypair("W5 A, round 1"), keypair("W5 B, round 1"));
	let first = refresh(&mut r, &[(&ca, &a1), (&cb, &b1)]).await;
	drive(&r, "the two boards", 8, |l| claimed(l) == 2).await;
	settle(&r).await;

	// A parent block of their own for what follows: round 2, A's stale
	// exit, and the watcher's answer.
	r.rt.mine_parent(1).unwrap();
	tokio::task::block_in_place(|| r.rt.anchor_to_parent_tip()).unwrap();
	let p = r.rt.parent.client().block_count().unwrap();
	let a2 = keypair("W5 A, round 2");
	let second = refresh(&mut r, &[(&first[0].new, &a2)]).await;
	let round2 = second[0].round.txid();
	let leaf_at = unroll_to_leaf(&r, &first[0].new, "A's stale exit").await;
	let id1 = first[0].new.held.id.0.to_vec();
	drive(&r, "the answer to A's stale exit", 6, |l| has(l, "claim", &id1)).await;
	settle(&r).await;
	// What the watcher published after round 2: the forfeit, round 2's
	// connector asset, the claim.
	let m2 = arca_covenant::connector_asset(round2, second[0].connector_vout).into_inner().to_byte_array().to_vec();
	let answers: Vec<(String, Txid)> = log(&r).await.iter().filter(|w| w.subject == id1 || ((w.kind == "issue" || w.kind == "claim") && w.subject == m2))
		.map(|w| (w.kind.clone(), txid(w))).collect();
	assert_eq!(answers.len(), 3, "{:?}", answers);
	assert!(log(&r).await.iter().all(|w| w.state == server::store::NurseryState::Final));
	let block2 = r.rt.client().call::<serde_json::Value>("getrawtransaction", &[serde_json::json!(round2.to_string()), serde_json::json!(true)]).unwrap();
	let h2: elements::BlockHash = block2["blockhash"].as_str().unwrap().parse().unwrap();
	let anchored = r.rt.client().block_header(&h2).unwrap();
	use sequentia_ext::BlockHeaderExt;
	assert_eq!(anchored.bitcoin_anchor().height as u64, p, "round 2 is anchored to the parent block of its own");
	let tip_before = r.rt.client().block_count().unwrap();
	println!("round 2 {} and the answers {:?} are final; Sequentia tip {}, round 2 anchored at parent {}", round2, answers, tip_before, p);

	// Bitcoin reorganises: the parent orphans that block and every one above.
	let orphaned = tokio::task::block_in_place(|| r.rt.orphan_parent_from(p)).unwrap();
	let tip_after = r.rt.client().block_count().unwrap();
	println!("the parent orphaned {} block(s) from {}; the Sequentia tip went from {} to {}", orphaned.len(), p, tip_before, tip_after);
	assert!(r.rt.client().confirmations(&round2).is_err() || r.rt.client().confirmations(&round2).unwrap() == 0,
		"round 2 left the chain");
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
	assert_ne!(r.server.store.round_by_txid(&round2.to_byte_array()).await.unwrap().unwrap().state, server::store::RoundState::Final,
		"the server no longer calls round 2 final");
	r.server.nursery.pass().await.unwrap();
	for t in std::iter::once(&round2).chain(answers.iter().map(|(_, t)| t)) {
		let in_chain = r.rt.client().confirmations(t).map(|c| c > 0).unwrap_or(false);
		assert!(!in_chain && node::in_mempool(&r.rt, t), "{} left the chain and waits in the mempool", t);
		let row = r.server.store.nursery_get(&t.to_byte_array()).await.unwrap().unwrap();
		println!("{}: out of the chain, in the mempool; the nursery holds it {:?}, broadcast {} time(s)", t, row.state, row.broadcasts);
		assert_eq!(row.state, server::store::NurseryState::Pending);
	}

	// Everything returns, unchanged, and is final again.
	settle(&r).await;
	common::rounds::round_final(&r, &round2).await;
	settle(&r).await;
	let l = log(&r).await;
	for (kind, t) in &answers {
		let row = l.iter().find(|w| txid(w) == *t).unwrap();
		println!("{} {}: {:?} again", kind, t, row.state);
		assert_eq!(row.state, server::store::NurseryState::Final, "{} {} is final again, with the same txid", kind, t);
		assert!(r.rt.client().confirmations(t).unwrap() >= 1);
	}
	assert_eq!((l.iter().filter(|w| w.subject == id1).count(), l.iter().filter(|w| w.kind == "claim" && w.subject == m2).count()), (1, 1),
		"nothing built again: one forfeit and one claim");
	advance_mtp(&r, 37 * HOUR).await;
	let e = verdict(&r, &exit_tx(&r, &first[0].new_valid.branch.leaf, leaf_at, x, VALUE, &a1)).unwrap_err();
	println!("A's exit after the reorganisation and its delay: refused, {}", e);
	assert!(e.contains("missingorspent") || e.contains("missing-inputs"), "{}", e);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refreshed_coin_paid_from_a_board_waits_for_the_change_and_then_comes_back() {
	let mut r = start().await;
	let (x, s) = (r.x, xonly(&r.s));
	let a = keypair("W6 A");
	let ca = board_coin(&mut r, &a).await;
	let (b, a2) = (keypair("W6 B"), keypair("W6 A, change"));
	let (b_leaf, b_nonce) = new_leaf(&b);
	let (a2_leaf, a2_nonce) = new_leaf(&a2);
	let kept = VALUE - 2_000;
	let change = kept - 600_000 - 2_000;
	let outputs = vec![(x, 600_000, b_leaf), (x, change, a2_leaf)];
	let done = r.http.post("cosign_transfer", &transfer_body(&[(&ca.held, ca.valid(&r), kept)], &outputs, s, r.chain)).ok();
	let transfer: Vec<u8> = unhex(done["transfer_id"].as_str().unwrap());
	let (_, b_id, b_record) = r.http.mailbox(&b, &r.chain, 0)[0].clone();
	let cb = Coin { held: common::client::Held { key: b, nonce: b_nonce, id: b_id, record: b_record }, bases: ca.bases.clone() };
	let (_, a2_id, a2_record) = r.http.mailbox(&a2, &r.chain, 0)[0].clone();
	let ca2 = Coin { held: common::client::Held { key: a2, nonce: a2_nonce, id: a2_id, record: a2_record }, bases: ca.bases.clone() };
	println!("A paid B 600000 of X from its board and kept {} as change; both coins rest on A's board", change);

	// B refreshes its coin into a round: the operator now holds B's forfeit,
	// and funded B's new leaf. A's change still rests on the lineage, live:
	// the watcher publishes none of it, whatever B did.
	let b2 = keypair("W6 B, round");
	let got = refresh(&mut r, &[(&cb, &b2)]).await;
	println!("B's coin refreshed into round {}", got[0].round.txid());
	let bid = b_id.0.to_vec();
	for _ in 0..4 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		r.produce().await;
	}
	let l = log(&r).await;
	assert!(!has(&l, "checkpoint", &ca.held.id.0) && !has(&l, "reassignment", &transfer) && !has(&l, "forfeit", &bid),
		"nothing of the lineage is published while A's change rests on it: {:?}", l.iter().map(|w| (&w.kind, &w.detail)).collect::<Vec<_>>());
	println!("after four passes and four blocks the watcher has published nothing of the lineage: A's change is live on it");
	let ld = r.http.post("leaf_data", &serde_json::json!({"auth": r.http.auth("leaf_data", &b2, &r.chain)})).ok();
	assert_eq!(ld["leaves"][0]["state"], "live", "B's new leaf is live");

	// The board's dates: those of a batch made when it confirmed.
	let board_tx = ca.bases[0].txid();
	let block: serde_json::Value = r.rt.client().call("getrawtransaction", &[serde_json::json!(board_tx.to_string()), serde_json::json!(true)]).unwrap();
	let header: serde_json::Value = r.rt.client().call("getblockheader", &[block["blockhash"].clone()]).unwrap();
	let confirmed = header["mediantime"].as_u64().unwrap() as u32;
	let st = r.http.board_status(&ca.held.id).ok();
	println!("A's board: {}", st);
	assert_eq!(st["expiry"].as_u64(), Some((confirmed + 28 * 86_400) as u64), "28 days after the median time of its block");
	assert_eq!(st["exit_deadline"].as_u64(), Some((confirmed + 25 * 86_400) as u64), "three days before");
	let info = r.http.get("info").ok();
	assert_eq!(info["boards"], serde_json::json!({"lifetime_seconds": 2_419_200, "exit_deadline_seconds": 259_200, "refresh_until_seconds": 259_200}));
	let expiry = confirmed + 28 * 86_400;

	// Past the board's exit deadline: A's change is no longer co-signed into
	// a transfer, nor taken into a refresh: its owner takes it on the chain.
	let now = common::rounds::mtp(&r).to_consensus_u32();
	advance_mtp(&r, expiry - 3 * 86_400 + HOUR - now).await;
	r.synced().await;
	let now = common::rounds::mtp(&r).to_consensus_u32();
	assert!(now > expiry - 3 * 86_400 && now < expiry, "past the exit deadline, before the expiry: {}", now);
	let (a3_leaf, _) = new_leaf(&keypair("W6 A, change again"));
	let refused = r.http.post("cosign_transfer", &transfer_body(&[(&ca2.held, ca2.valid(&r), change - 2_000)],
		&[(x, change - 4_000, a3_leaf)], s, r.chain));
	println!("A's transfer of its change past the board's exit deadline: {} {:?}", refused.status, refused.refusal());
	assert_eq!(refused.refusal().0, "invalid_coin");
	assert!(refused.refusal().1.contains("exit deadline has passed"), "{:?}", refused.refusal());
	let a4 = keypair("W6 A, round");
	let (w, _) = common::client::want_leaf(&a4, x, change);
	let (body, _) = common::client::participation_body(&[&ca2.held], &[w], &[], None, s, r.chain);
	let refused = r.http.post("submit_participation", &body);
	println!("A's refresh of its change past the board's exit deadline: {} {:?}", refused.status, refused.refusal());
	assert_eq!(refused.status, 422, "{}", refused.json);
	assert!(refused.refusal().1.contains("rests on a board whose service ends"), "{:?}", refused.refusal());

	// A's change rests live on the lineage: the watcher publishes nothing of
	// it before the board's expiry.
	let now = common::rounds::mtp(&r).to_consensus_u32();
	advance_mtp(&r, expiry - HOUR - now).await;
	for _ in 0..3 {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		r.produce().await;
	}
	let l = log(&r).await;
	assert!(!has(&l, "checkpoint", &ca.held.id.0) && !has(&l, "forfeit", &bid), "nothing before the board's expiry: {:?}",
		l.iter().map(|w| (&w.kind, &w.detail)).collect::<Vec<_>>());
	println!("an hour before the board's expiry the watcher has published nothing of the lineage: A's change rests on it");

	// From the board's expiry the watcher brings the lineage on the chain
	// and claims B's forfeit; A's change comes on the chain as its leaf, A's
	// to claim.
	let before = x_balance(&r).await;
	advance_mtp(&r, 2 * HOUR).await;
	drive(&r, "the lineage of A's board past its expiry, B's coin given up", 12, |l| has(l, "claim", &bid)).await;
	settle(&r).await;
	let l = log(&r).await;
	assert!(final_of(&l, "checkpoint", &ca.held.id.0), "A's board checkpointed from the board output");
	assert!(final_of(&l, "reassignment", &transfer), "the reassignment published");
	assert!(final_of(&l, "forfeit", &bid) && final_of(&l, "claim", &bid), "B's forfeit published and claimed");
	let a2id = a2_id.0.to_vec();
	assert!(!has(&l, "forfeit", &a2id), "A gave nothing up: no forfeit of its change");
	let cp = l.iter().find(|w| w.kind == "checkpoint").unwrap();
	let cptx: Transaction = elements::encode::deserialize(&cp.tx).unwrap();
	assert_eq!(cptx.input[0].previous_output, ca.valid(&r).board().unwrap().1, "the checkpoint spends the board output itself");
	let after = x_balance(&r).await;
	println!("the wallet holds {} more of X: B's coin back, less the fees", after as i64 - before as i64);
	assert!(after > before + 590_000);
	// The coins whose forfeit's claim is final are scanned no more.
	let left: Vec<String> = r.server.store.forfeited_transfer_coins().await.unwrap().iter()
		.map(|(l, _)| common::client::hex(l)).collect();
	println!("forfeited transfer coins still scanned once B's claim is final: {:?}", left);
	assert!(!left.contains(&common::client::hex(&bid)), "{:?}", left);
}
