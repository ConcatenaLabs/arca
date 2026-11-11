//! A swap whose checkpoints carry their owners' exit, co-signed by the
//! operator, and the watcher's duty to it, against a node and PostgreSQL.
//!
//! A gives X from its board, C gives Y from its board, in one reassignment
//! whose two checkpoints each have their owner's exit. A then pulls out:
//! it publishes its own checkpoint from its record, so that its exit runs.
//!
//! 1. The watcher answers: it publishes C's checkpoint from C's board and
//!    the reassignment, inside A's exit delay; A's exit after the delay is
//!    refused, the swap's coins stand.
//! 2. C has refreshed the X the swap paid it, so the operator holds that
//!    coin's forfeit and funded C's new leaf. The watcher is stopped: A's
//!    exit goes through after the delay, the swap can never confirm, and
//!    the coin the forfeit takes can never exist. The test prints what the
//!    operator funded against it.
//!
//! Needs `ARCA_TEST_POSTGRES`, `SEQUENTIAD_EXEC` and the signer binary, as
//! every server test.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::{OutPoint, Transaction};

use arca_covenant::sign::sign_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::transfer::COIN_RECORD_VERSION_EXIT;
use arca_covenant::{ExplicitOutput, ValidCoin, ValidInput, ValidOrigin};
use common::client::{new_leaf, random32, transfer_body_with, unhex, Held};
use common::flow::{drive, has, log, refresh, settle, verdict, Coin};
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{advance_mtp, credited_board, start, VALUE};
use common::running::Running;

const HOUR: u32 = 3_600;

fn send(r: &Running, what: &str, tx: &Transaction) -> elements::Txid {
	let txid = r.rt.client().send_raw_transaction(tx).unwrap_or_else(|e| panic!("{}: {}", what, e));
	println!("{}: {} ({} vB)", what, txid, tx.vsize());
	txid
}

struct Swap {
	transfer: Vec<u8>,
	/// A's coin of Y and C's coin of X, as their mailboxes gave them.
	a_gets: Coin,
	c_gets: Coin,
	c_board: Coin,
	a: Keypair,
}

/// A's board of X and C's board of Y swapped in one reassignment, every
/// checkpoint with its owner's exit: A gets C's Y whole, C gets A's X less
/// the reassignment's margin.
async fn swap(r: &mut Running, tag: &str) -> Swap {
	let (x, y, s) = (r.x, r.y, xonly(&r.s));
	let (a, c) = (keypair(&format!("{} A", tag)), keypair(&format!("{} C", tag)));
	let (ha, ta) = credited_board(r, &a, x).await;
	let (hc, tc) = credited_board(r, &c, y).await;
	let a_board = Coin { held: ha, bases: vec![ta.clone()] };
	let c_board = Coin { held: hc, bases: vec![tc.clone()] };
	let (ka, kc) = (keypair(&format!("{} A gets Y", tag)), keypair(&format!("{} C gets X", tag)));
	let (a_leaf, a_nonce) = new_leaf(&ka);
	let (c_leaf, c_nonce) = new_leaf(&kc);
	// Each checkpoint's margin in its own asset, at the operator's rates
	// (Y is worth more: a few atoms pay its fee); the reassignment's in X.
	let kept = VALUE - 2_000;
	let kept_y = VALUE - 20;
	let outputs = vec![(y, kept_y, a_leaf), (x, kept - 2_000, c_leaf)];
	let body = transfer_body_with(&[(&a_board.held, a_board.valid(r), kept), (&c_board.held, c_board.valid(r), kept_y)], &outputs, s, r.chain,
		true);
	let done = r.http.post("cosign_transfer", &body).ok();
	let transfer: Vec<u8> = unhex(done["transfer_id"].as_str().unwrap());
	let bases = vec![ta, tc];
	let mail = |k: &Keypair, n: [u8; 32]| {
		let (_, id, record) = r.http.mailbox(k, &r.chain, 0)[0].clone();
		assert_eq!(record.to_bytes().unwrap()[0], COIN_RECORD_VERSION_EXIT, "a record with a checkpoint exit is version 2");
		Coin { held: Held { key: *k, nonce: n, id, record }, bases: bases.clone() }
	};
	let (a_gets, c_gets) = (mail(&ka, a_nonce), mail(&kc, c_nonce));
	println!("{}: A's {} of X and C's {} of Y swapped in transfer {}, each checkpoint with its owner's exit", tag, kept, kept_y,
		common::client::hex(&transfer));
	Swap { transfer, a_gets, c_gets, c_board, a }
}

fn inputs_of(v: &ValidCoin) -> Vec<ValidInput> {
	match &v.origin {
		ValidOrigin::Transfer { inputs, .. } => inputs.clone(),
		_ => unreachable!("a reassignment's coin"),
	}
}

/// A pulls out: its checkpoint, from its record, spending its board output.
fn pull_out(r: &Running, sw: &Swap, tag: &str) -> (ValidInput, OutPoint) {
	let ins = inputs_of(&sw.a_gets.valid(r));
	let a_in = ins[0].clone();
	assert!(a_in.checkpoint.exit.is_some(), "A's checkpoint has its owner's exit");
	let cp = a_in.board_checkpoint_tx(&FeeSource::Reserve).unwrap().tx;
	let at = send(r, &format!("{}: A publishes its own checkpoint from its board", tag), &cp);
	(a_in, OutPoint::new(at, 0))
}

/// A's exit of its checkpoint at `at`, by its own key alone.
fn a_exit(r: &Running, a: &Keypair, i: &ValidInput, at: OutPoint) -> Transaction {
	let asset = i.coin.asset;
	let ks = i.checkpoint.exit_tx(at, asset, i.checkpoint_value, &[ExplicitOutput::new(asset, i.checkpoint_value - 1_500, node::op_true())],
		&FeeSource::Reserve).unwrap();
	let sig = sign_digest(a, &ks.sighash(r.chain.genesis_hash()).unwrap(), &random32());
	ks.finish(vec![sig.as_ref().to_vec()]).tx
}

#[tokio::test(flavor = "multi_thread")]
async fn an_early_checkpoint_of_a_swap_is_answered_inside_the_delay() {
	let mut r = start().await;
	let info = r.http.get("info").ok();
	assert_eq!(info["checkpoint_exit"], true, "the operator offers checkpoints with their owners' exit");
	let sw = swap(&mut r, "CX1").await;
	let (a_in, a_cp) = pull_out(&r, &sw, "CX1");
	r.produce().await;
	assert!(verdict(&r, &a_exit(&r, &sw.a, &a_in, a_cp)).unwrap_err().contains("non-BIP68-final"), "A's exit waits its delay");

	// The watcher answers A's checkpoint: C's checkpoint from C's board,
	// then the reassignment.
	drive(&r, "the answer to A's early checkpoint", 8, |l| has(l, "reassignment", &sw.transfer)).await;
	settle(&r).await;
	let l = log(&r).await;
	assert!(has(&l, "checkpoint", &sw.c_board.held.id.0), "the watcher published C's checkpoint from C's board");
	for w in &l {
		println!("  watcher: {} {}", w.kind, w.detail);
	}
	let re = l.iter().find(|w| w.kind == "reassignment").unwrap();
	let retx: Transaction = elements::encode::deserialize(&re.tx).unwrap();
	assert_eq!(retx.output[0].script_pubkey, sw.a_gets.valid(&r).leaf.script_pubkey(), "A's coin of Y is on the chain");
	assert_eq!(retx.output[1].script_pubkey, sw.c_gets.valid(&r).leaf.script_pubkey(), "C's coin of X is on the chain");

	// Past the delay A cannot pull out.
	advance_mtp(&r, 37 * HOUR).await;
	let e = verdict(&r, &a_exit(&r, &sw.a, &a_in, a_cp)).unwrap_err();
	println!("CX1: A's exit of its checkpoint after the delay: refused, {}", e);
	assert!(e.contains("missingorspent") || e.contains("missing-inputs"), "{}", e);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_early_checkpoint_left_unanswered_voids_the_coin_the_operator_holds() {
	let mut r = start().await;
	let x = r.x;
	let sw = swap(&mut r, "CX2").await;
	// C refreshes the X the swap paid it: the operator holds that coin's
	// forfeit and funded C's new leaf.
	let c2 = keypair("CX2 C, round");
	let got = refresh(&mut r, &[(&sw.c_gets, &c2)]).await;
	let funded = got[0].new.valid(&r).value;
	println!("CX2: C refreshed its {} of X into round {}: the operator funded C's new leaf with {} of X and holds the forfeit of the \
		swap's coin", sw.c_gets.valid(&r).value, got[0].round.txid(), funded);
	let before = r.server.wallet.balance().await.unwrap().get(&x).copied().unwrap_or(0);

	// The watcher is stopped (no pass runs): A publishes its checkpoint and
	// waits out its delay.
	let (a_in, a_cp) = pull_out(&r, &sw, "CX2");
	r.produce().await;
	advance_mtp(&r, 37 * HOUR).await;
	let exit = a_exit(&r, &sw.a, &a_in, a_cp);
	send(&r, "CX2: A's own exit of its checkpoint after the delay, no operator, the watcher stopped", &exit);
	r.produce().await;
	assert!(r.rt.client().confirmations(&exit.txid()).unwrap() >= 1);

	// The swap can never confirm now: C's checkpoint goes on, and the
	// reassignment is refused for A's spent checkpoint.
	let c_in = inputs_of(&sw.c_gets.valid(&r))[1].clone();
	let fee = r.purse.take_coin(x);
	let ccp = send(&r, "CX2: C's checkpoint from its board", &c_in.board_checkpoint_tx(
		&FeeSource::Coin { outpoint: fee.0, coin: fee.1, fee: 3_000, change: node::op_true() }).unwrap().tx);
	r.produce().await;
	// Its fee from the margin the swap left in X.
	let re = sw.c_gets.valid(&r).reassignment_tx(&[a_cp, OutPoint::new(ccp, 0)], &FeeSource::Reserve).unwrap().tx;
	let e = verdict(&r, &re).unwrap_err();
	println!("CX2: the swap's reassignment after A's exit: refused, {}", e);
	assert!(e.contains("missingorspent") || e.contains("missing-inputs"), "{}", e);

	// What the operator holds against it is void: the coin its forfeit
	// takes can never reach the chain, and C's new leaf, which it funded,
	// is C's.
	let after = r.server.wallet.balance().await.unwrap().get(&x).copied().unwrap_or(0);
	println!("CX2: the operator funded {} of X against a coin that can never exist (its wallet holds {} of X before A's exit, {} after: \
		nothing comes back)", funded, before, after);
}

/// An operator that does not offer checkpoints with their owners' exit says
/// so in `info`, refuses a transfer that asks for them before anything is
/// recorded or signed, and co-signs the same swap signed without them, as
/// every operator co-signs a transfer from a wallet that never asks.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_that_does_not_offer_the_exit_refuses_it_and_serves_the_old_form() {
	let mut r = Running::start_with(|c, y| {
		c.assets.push(server::server::AssetSection::new(y, common::running::MIN_LEAF));
		c.checkpoint_exit = false;
	}).await;
	let (x, y, s) = (r.x, r.y, xonly(&r.s));
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(y, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	assert_eq!(r.http.get("info").ok()["checkpoint_exit"], false);
	let (a, c) = (keypair("CX3 A"), keypair("CX3 C"));
	let (ha, ta) = credited_board(&mut r, &a, x).await;
	let (hc, tc) = credited_board(&mut r, &c, y).await;
	let (ca, cc) = (Coin { held: ha, bases: vec![ta] }, Coin { held: hc, bases: vec![tc] });
	let (a_leaf, _) = new_leaf(&keypair("CX3 A gets Y"));
	let (c_leaf, _) = new_leaf(&keypair("CX3 C gets X"));
	let (kept, kept_y) = (VALUE - 2_000, VALUE - 20);
	let outputs = vec![(y, kept_y, a_leaf), (x, kept - 2_000, c_leaf)];
	let coins = [(&ca.held, ca.valid(&r), kept), (&cc.held, cc.valid(&r), kept_y)];
	let refused = r.http.post("cosign_transfer", &transfer_body_with(&coins, &outputs, s, r.chain, true));
	println!("CX3: a swap asking for checkpoints with their owners' exit: {} {:?}", refused.status, refused.refusal());
	assert_eq!(refused.status, 422, "{}", refused.json);
	assert!(refused.refusal().1.contains("info.checkpoint_exit is false"), "{:?}", refused.refusal());
	let done = r.http.post("cosign_transfer", &transfer_body_with(&coins, &outputs, s, r.chain, false)).ok();
	let (_, _, record) = r.http.mailbox(&keypair("CX3 A gets Y"), &r.chain, 0)[0].clone();
	assert_eq!(record.to_bytes().unwrap()[0], arca_covenant::transfer::COIN_RECORD_VERSION, "the old form: a version 1 record");
	println!("CX3: the same swap signed without them: co-signed, transfer {}, its records version 1", done["transfer_id"]);
}
