//! A lost round that returns: the re-run of its participations cannot stand
//! in the chain beside it. Each reorganisation here is driven through the
//! parent chain (`Regtest::orphan_parent_from`) on an anchored proof-of-stake
//! regtest chain: every Sequentia block anchored to an orphaned Bitcoin block
//! goes out of the chain with it, however deep. The watcher is driven a pass
//! at a time, as the scenario needs it.
//!
//! The round R is final and its participations released. Its block goes out
//! with its parent block; the node forgets its mempool and another
//! transaction X takes R's first input, buried: R is lost. Its
//! participations run again in Y, which spends a coin that keeps it apart
//! from R. Then a deeper reorganisation takes X out, R (sent by anyone who
//! holds it) confirms in its place, and the server restores R and retires Y.
//! Every transaction of the blocks that reorganisation disconnects is sent
//! again after R, in its order, as a node puts them back in its mempool:
//! those that conflict with R are refused, the rest confirm beside it.
//! After every restore an ordinary round is built for a fresh participant.
//!
//! 1. Y spends an input of R that was still unspent: after the deeper
//!    reorganisation R is in the chain and Y never can be (its input is
//!    spent by R); A holds one leaf, R's; the operator claims A's board with
//!    its forfeit for R; nothing of Y's was published.
//! 2. R had one input, which X took; X pays the operator: Y spends X's
//!    output, and once X is out, Y's input does not exist.
//! 3. X pays the operator nothing and R had no other input: the
//!    participation is voided, saying so, and its coin stays given up; when
//!    R returns the participation is restored as it stood in R, and the
//!    watcher claims its board with its forfeit for R.
//! 4. The participant whose forfeit for R the watcher published while R was
//!    final (barred from a re-run): with R back, the watcher claims that
//!    forfeit with R's connector asset; when the owner refunded it while R
//!    was out, the refund stands, and the server never credits that
//!    participant's leaf of R: it is its owner's to take on the chain (its
//!    first unroll is valid), and the loss is the operator's.
//! 5. A's board given up in Y has its forfeit for Y published and claimed
//!    before the deeper reorganisation: that forfeit spends the board alone,
//!    so it comes back with the disconnected blocks and confirms beside R,
//!    and Y's claim of it never can. The server leaves A's leaf of R
//!    uncredited, A's to take on the chain, the loss the operator's; A's
//!    refund of Y's forfeit opens after its delay.
//! 6. A voided while R is out exits the board it gave up before X: when R
//!    returns, the board is spent on the chain by A's exit, and the server
//!    leaves A's leaf of R uncredited, A's to take, the loss the operator's.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::{OutPoint, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::{ExplicitOutput, Forfeit, LeafRecord, RelativeTime, ValidLeaf};
use common::client::{auths_json, forfeit_sig, hex, participation_body, random32, unhex, want_leaf};
use common::flow::{drive, forfeit_for, has, log, settle, txid, verdict, Coin};
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{created, credited_board, round_final, round_state, spend_wallet_coin, start, status, validate_new_leaf};
use common::running::Running;
use server::store::{LeafState, RoundState, WatcherTxRow};

/// Whether a block of the active chain holds `txid`.
fn in_a_block(r: &Running, txid: &Txid) -> bool {
	r.rt.client().call::<Value>("getrawtransaction", &[json!(txid.to_string()), json!(true)]).ok()
		.and_then(|v| v["confirmations"].as_u64()).unwrap_or(0) > 0
}

/// A parent block of its own, and the Sequentia tip anchored to it: what is
/// mined next is anchored there, so orphaning it takes that out. Returns its
/// height.
async fn own_anchor(r: &Running) -> u64 {
	tokio::task::block_in_place(|| {
		r.rt.mine_parent(1).unwrap();
		r.rt.anchor_to_parent_tip().unwrap();
	});
	r.rt.parent.client().block_count().unwrap()
}

/// A server whose wallet holds one coin of X per value of `coins`, final.
async fn start_funded(coins: &[u64]) -> Running {
	let mut r = Running::start().await;
	let x = r.x;
	for v in coins {
		r.fund_wallet_in(x, *v).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r
}

/// The coin `c` given up for a new leaf under `key` of its whole value.
fn participate(r: &Running, c: &Coin, key: &Keypair) -> ([u8; 32], [u8; 32]) {
	let v = c.valid(r);
	let (w, nonce) = want_leaf(key, v.asset, v.value);
	let (body, id) = participation_body(&[&c.held], &[w], &[], None, xonly(&r.s), r.chain);
	assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
	(id, nonce)
}

/// What an owner holds once released: its forfeit, the preimage, its new
/// leaf as validated, its record and the round.
struct Released {
	forfeit: Forfeit,
	preimage: [u8; 32],
	leaf: ValidLeaf,
	record: LeafRecord,
	round: Transaction,
}

/// The owner of `c` hands over its forfeit for the round participation `p`
/// is in now, and is released.
fn hand_over(r: &Running, p: &[u8; 32], c: &Coin, key: &Keypair, nonce: &[u8; 32]) -> Released {
	let st = status(r, p);
	let (leaf, record, round) = validate_new_leaf(r, p, 0, key, nonce);
	let forfeit = forfeit_for(&c.valid(r), &leaf, &round, &st);
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(p),
		"forfeits": [{"leaf_id": c.held.id.to_string(), "signature": forfeit_sig(&forfeit, &c.held.key)}],
		"leaves": [auths_json(&leaf, key, created(&record))]})).ok();
	assert_eq!(done["state"], "released", "{}", done);
	let preimage: [u8; 32] = unhex(done["preimage"].as_str().unwrap()).try_into().unwrap();
	Released { forfeit, preimage, leaf, record, round }
}

/// The first transaction of the owner `key` bringing its leaf `x` onto the
/// chain: the unroll of the batch output's node, by its own authorisation.
fn first_unroll(x: &Released, key: &Keypair) -> Transaction {
	let t = created(&x.record);
	let auths: Vec<_> = x.leaf.branch.nodes.iter()
		.map(|n| n.owner_auth(sign_digest(key, &n.unroll_authorisation(t).digest, &random32()), t, xonly(key))).collect();
	let fees = vec![FeeSource::Reserve; auths.len()];
	let txs = x.leaf.branch.unroll(OutPoint::new(x.round.txid(), x.leaf.batch_vout), &auths, &fees).unwrap();
	txs[0].tx.clone()
}

/// Waits until participation `p` is `state`: a round found lost is retired
/// first, and each participation it ran is looked at after, by whichever
/// pass retired it.
async fn wait_state(r: &Running, p: &[u8; 32], state: &str) -> Value {
	r.wait(&format!("participation {} to be {}", hex(p), state), || status(r, p)["state"] == state).await;
	status(r, p)
}

/// Runs the watcher and the nursery, a block after each, `n` times.
async fn passes(r: &Running, n: usize) {
	for _ in 0..n {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		r.server.nursery.pass().await.unwrap();
		r.produce().await;
	}
}

/// The forfeit the watcher logged for coin `c` naming the round `round_id`.
fn forfeit_naming(l: &[WatcherTxRow], c: &Coin, round_id: i64) -> Option<WatcherTxRow> {
	l.iter().find(|w| w.kind == "forfeit" && w.subject == c.held.id.0.to_vec() && w.detail.ends_with(&format!("round {}", round_id)))
		.cloned()
}

/// The watcher's claim, in `l`, that spends the forfeit `f`.
fn claim_spending(l: &[WatcherTxRow], f: &Txid) -> Option<WatcherTxRow> {
	l.iter().filter(|w| w.kind == "claim").find(|w| {
		let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
		tx.input.iter().any(|i| i.previous_output == OutPoint::new(*f, 0))
	}).cloned()
}

/// How the transaction X that takes R's first input pays.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Taker {
	/// To a bare `OP_TRUE`: nothing to the operator.
	Elsewhere,
	/// Most of it back to a script of the operator's wallet.
	ToOperator,
}

/// R goes out of the chain with its parent block (`anchor`), the node
/// forgets its mempool, `meanwhile` runs, and X takes R's first input in a
/// block anchored to a parent block of its own, buried. The server holds R
/// lost. Returns X and the height of its parent block.
async fn lose<F: FnOnce(&Running)>(r: &mut Running, tag: &str, round: &Transaction, anchor: u64, taker: Taker, meanwhile: F)
	-> (Transaction, u64)
{
	r.server.stop();
	let orphaned = tokio::task::block_in_place(|| r.rt.orphan_parent_from(anchor)).unwrap();
	assert!(!in_a_block(r, &round.txid()), "R went out of the chain with its parent block");
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0"])).unwrap();
	println!("{} R {}: out of the chain with {} parent block(s) from height {}; the node restarted with an empty mempool", tag,
		round.txid(), orphaned.len(), anchor);
	meanwhile(r);
	let p_x = own_anchor(r).await;
	let wi = round.input[0].previous_output;
	let w_out = r.rt.client().raw_transaction(&wi.txid).unwrap().output[wi.vout as usize].clone();
	let outputs = match taker {
		Taker::Elsewhere => vec![],
		Taker::ToOperator => {
			let (_, to) = server::wallet::Wallet::hand_out_receive_script(&r.db.store, common::keys::MNEMONIC).await.unwrap();
			let a = w_out.asset.explicit().unwrap();
			vec![sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(a, w_out.value.explicit().unwrap() - 3_000), to)]
		},
	};
	let x = spend_wallet_coin(wi, &w_out, outputs, 2_000);
	r.rt.client().send_raw_transaction(&x).unwrap();
	r.produce().await;
	r.bury().await;
	println!("{} X {} takes R's input {}, in a block anchored at parent height {}, buried", tag, x.txid(), wi, p_x);
	r.restart_server().await;
	round_state(r, &round.txid(), RoundState::Lost).await;
	(x, p_x)
}

/// Every Sequentia block of the active chain, from height 1, with its
/// transactions after the coinbase: what a node puts back in its mempool
/// for the blocks a reorganisation disconnects.
fn blocks_now(r: &Running) -> Vec<(u64, String, Vec<Transaction>)> {
	let tip: u64 = r.rt.client().call("getblockcount", &[]).unwrap();
	(1..=tip).map(|h| {
		let hash: String = r.rt.client().call("getblockhash", &[json!(h)]).unwrap();
		let b: Value = r.rt.client().call("getblock", &[json!(hash), json!(2)]).unwrap();
		let txs = b["tx"].as_array().unwrap().iter().skip(1)
			.map(|t| elements::encode::deserialize(&unhex(t["hex"].as_str().unwrap())).unwrap()).collect();
		(h, hash, txs)
	}).collect()
}

/// Sends again, in their order, the transactions of the blocks of `before`
/// that are no longer in the active chain, as a node puts them back in its
/// mempool after a reorganisation: what conflicts with the chain now is
/// refused, the rest waits for a block. Returns each with the node's answer.
fn send_disconnected(r: &Running, before: &[(u64, String, Vec<Transaction>)]) -> Vec<(Txid, Result<(), String>)> {
	let tip: u64 = r.rt.client().call("getblockcount", &[]).unwrap();
	let mut out = vec![];
	for (h, hash, txs) in before {
		let now = (*h <= tip).then(|| r.rt.client().call::<String>("getblockhash", &[json!(h)]).unwrap());
		if now.as_deref() == Some(hash.as_str()) {
			continue;
		}
		for t in txs {
			out.push((t.txid(), r.rt.client().send_raw_transaction(t).map(|_| ()).map_err(|e| e.to_string().chars().take(60).collect::<String>())));
		}
	}
	out
}

/// The deeper reorganisation: everything anchored at parent height `p_x`
/// or above goes out (X, and what came after it), the node restarts,
/// `meanwhile` runs, R, sent by anyone who holds it, takes X's place, and
/// every other transaction of the disconnected blocks is sent again after
/// it, in its order, as a node holds them; the next blocks confirm what the
/// node took, buried. The server, started again, holds R final.
///
/// `mock`, when the test moved the node's clock on, is that clock, kept
/// across the node's restart.
async fn r_returns<F: FnOnce(&Running)>(r: &mut Running, tag: &str, round: &Transaction, x: &Transaction, p_x: u64, mock: Option<u64>,
	meanwhile: F)
{
	r.server.stop();
	let before = blocks_now(r);
	let orphaned = tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_x)).unwrap();
	assert!(!in_a_block(r, &x.txid()), "X went out of the chain with its parent block");
	let mock_arg = mock.map(|m| format!("-mocktime={}", m));
	let mut args = vec!["-persistmempool=0"];
	args.extend(mock_arg.as_deref());
	tokio::task::block_in_place(|| r.rt.node.restart(&args)).unwrap();
	println!("{} X {}: out of the chain with {} parent block(s) from height {}; the node restarted with an empty mempool", tag,
		x.txid(), orphaned.len(), p_x);
	meanwhile(r);
	println!("{} R sent again (anyone holding it can): {:?}", tag, r.rt.client().send_raw_transaction(round).map(|t| t.to_string())
		.map_err(|e| e.to_string()));
	let back = send_disconnected(r, &before);
	println!("{} the disconnected blocks' transactions sent again, as a node holds them: {} taken, {} refused ({:?})", tag,
		back.iter().filter(|b| b.1.is_ok()).count(), back.iter().filter(|b| b.1.is_err()).count(),
		back.iter().map(|(t, v)| format!("{}… {}", &t.to_string()[..8], match v { Ok(()) => "taken".to_string(), Err(e) => e.clone() }))
			.collect::<Vec<_>>());
	r.produce().await;
	r.produce().await;
	r.bury().await;
	assert!(in_a_block(r, &round.txid()));
	r.restart_server().await;
	round_state(r, &round.txid(), RoundState::Final).await;
}

/// The refusal of a transaction that spends what is spent or missing: the
/// node's consensus check of its inputs.
fn missing_or_spent(v: &Result<(), String>) -> bool {
	v.as_ref().err().is_some_and(|e| e.contains("missing") || e.contains("missingorspent"))
}

/// Follows a refresh of A's board through R, its loss, its re-run in Y, and
/// R's return, for the taker `taker`, with `funds` the operator's coins.
/// Returns what the test checks after.
async fn rerun_then_return(tag: &str, funds: Option<&[u64]>, taker: Taker) {
	let mut r = match funds {
		Some(c) => start_funded(c).await,
		None => start().await,
	};
	let x = r.x;
	let (a, c) = (keypair(&format!("{} A", tag)), keypair(&format!("{} C", tag)));
	let (ha, ta) = credited_board(&mut r, &a, x).await;
	let (hc, tc) = credited_board(&mut r, &c, x).await;
	let (ca, cc) = (Coin { held: ha, bases: vec![ta] }, Coin { held: hc, bases: vec![tc] });
	let (a2, c2) = (keypair(&format!("{} A2", tag)), keypair(&format!("{} C2", tag)));
	let (pa, a2n) = participate(&r, &ca, &a2);
	let (pc, c2n) = participate(&r, &cc, &c2);

	// Round R, alone in a parent block of its own; final; both released.
	let p_r = own_anchor(&r).await;
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let rtx = built.tx.clone();
	r.produce().await;
	r.bury().await;
	round_final(&r, &rtx.txid()).await;
	let a_r = hand_over(&r, &pa, &ca, &a2, &a2n);
	let _c_r = hand_over(&r, &pc, &cc, &c2, &c2n);
	println!("{} R = {} final, {} input(s); A released (leaf {}), C released", tag, rtx.txid(), rtx.input.len(), a_r.leaf.leaf_id);

	let (xtx, p_x) = lose(&mut r, tag, &rtx, p_r, taker, |_| {}).await;
	r.server.rounds.pass().await.unwrap();
	let sa = wait_state(&r, &pa, "pending").await;
	println!("{} after R is lost: A {} attempt {}", tag, sa["state"], sa["attempt"]);
	assert_eq!((sa["state"].as_str(), sa["attempt"].as_u64()), (Some("pending"), Some(1)), "{}", sa);

	// Y runs both again, and spends the coin that keeps it apart from R.
	let built_y = r.server.rounds.run_round().await.unwrap().unwrap();
	let ytx = built_y.tx.clone();
	let ties = r.server.store.replaced_by(built_y.round_id).await.unwrap();
	assert_eq!(ties.len(), 1, "Y records the round it replaces");
	assert_eq!(ties[0].replaces, built.round_id);
	let tie = OutPoint::new(Txid::from_byte_array(ties[0].tie.0), ties[0].tie.1);
	assert!(ytx.input.iter().any(|i| i.previous_output == tie), "Y spends its tie");
	match taker {
		Taker::Elsewhere => {
			assert!(rtx.input.iter().any(|i| i.previous_output == tie), "the tie is an input of R that was still unspent");
			assert_eq!(ties[0].via, None);
			println!("{} Y = {} spends {}, an input of R still unspent", tag, ytx.txid(), tie);
		},
		Taker::ToOperator => {
			assert_eq!(tie.txid, xtx.txid(), "the tie is X's output");
			assert_eq!(ties[0].via, Some(xtx.txid().to_byte_array()));
			println!("{} Y = {} spends {}, the operator's output of X, the transaction that took R's input", tag, ytx.txid(), tie);
		},
	}
	r.produce().await;
	r.bury().await;
	round_final(&r, &ytx.txid()).await;
	let a_y = hand_over(&r, &pa, &ca, &a2, &a2n);
	let _c_y = hand_over(&r, &pc, &cc, &c2, &c2n);
	println!("{} Y final; A released again (leaf {}); nothing of Y's published", tag, a_y.leaf.leaf_id);

	// The deeper reorganisation; R returns in X's place.
	r_returns(&mut r, tag, &rtx, &xtx, p_x, None, |_| {}).await;
	let (vy, vx) = (verdict(&r, &ytx), verdict(&r, &xtx));
	println!("{} with R in the chain, the node's verdict on Y: {:?}; on X: {:?}", tag, vy, vx);
	assert!(missing_or_spent(&vy) && missing_or_spent(&vx), "Y can never stand beside R: {:?}", vy);
	println!("{} in a block now: R {}, Y {}, X {}", tag, in_a_block(&r, &rtx.txid()), in_a_block(&r, &ytx.txid()), in_a_block(&r, &xtx.txid()));
	assert!(in_a_block(&r, &rtx.txid()) && !in_a_block(&r, &ytx.txid()) && !in_a_block(&r, &xtx.txid()));

	// The server: R restored, Y retired, A back as it stood in R.
	r.wait("Y retired", || tokio::runtime::Handle::current().block_on(r.server.store.round(built_y.round_id)).unwrap()
		.is_some_and(|y| y.state == RoundState::Lost)).await;
	let sa = status(&r, &pa);
	println!("{} A at the server: {} attempt {} in round {}", tag, sa["state"], sa["attempt"], sa["round"]["txid"]);
	assert_eq!((sa["state"].as_str(), sa["attempt"].as_u64(), sa["round"]["txid"].as_str()),
		(Some("released"), Some(0), Some(rtx.txid().to_string().as_str())));
	assert_eq!(sa["unlock_hash"].as_str().unwrap(), hex(&arca_covenant::script::sha256(&a_r.preimage)));
	let leaf_state = |id: &arca_covenant::LeafId| tokio::runtime::Handle::current().block_on(r.server.store.leaf(&id.0)).unwrap().unwrap().state;
	let (lr, ly) = tokio::task::block_in_place(|| (leaf_state(&a_r.leaf.leaf_id), leaf_state(&a_y.leaf.leaf_id)));
	println!("{} A's leaf of R {:?}, of Y {:?}", tag, lr, ly);
	assert_eq!((lr, ly), (LeafState::Live, LeafState::Lost));

	// A holds one leaf: its leaf of R comes onto the chain, its leaf of Y
	// never can.
	let (ur, uy) = (verdict(&r, &first_unroll(&a_r, &a2)), verdict(&r, &first_unroll(&a_y, &a2)));
	println!("{} the node's verdict on the first unroll of A's leaf of R: {:?}; of Y: {:?}", tag, ur, uy);
	assert_eq!(ur, Ok(()));
	assert!(missing_or_spent(&uy), "{:?}", uy);

	// The operator holds one forfeit that can be claimed: its forfeit for R
	// of A's board, claimed with R's connector asset.
	drive(&r, &format!("{} A's board claimed for R", tag), 12, |l| forfeit_naming(l, &ca, built.round_id)
		.is_some_and(|f| claim_spending(l, &txid(&f)).is_some())).await;
	settle(&r).await;
	let l = log(&r).await;
	let f_r = txid(&forfeit_naming(&l, &ca, built.round_id).unwrap());
	let claim = claim_spending(&l, &f_r).unwrap();
	assert!(in_a_block(&r, &txid(&claim)) && claim.detail.contains(&format!("round {}", built.round_id)));
	println!("{} the operator's forfeit for R {} claimed by {}; its forfeits for Y: {:?}", tag, f_r, txid(&claim),
		forfeit_naming(&l, &ca, built_y.round_id).map(|f| txid(&f)));
	assert!(forfeit_naming(&l, &ca, built_y.round_id).is_none(), "nothing of Y's is published");
	let _ = ordinary_round(&mut r, tag, "B").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_returning_round_beats_the_rerun_that_spent_its_unspent_input() {
	// Two boards of 1,000,000 and coins of 1,500,000: R spends two coins.
	rerun_then_return("Ra", Some(&[1_500_000, 1_500_000, 1_500_000, 1_500_000]), Taker::Elsewhere).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_returning_round_beats_the_rerun_that_spent_the_takers_output() {
	rerun_then_return("Rb", None, Taker::ToOperator).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rerun_nothing_keeps_apart_from_its_round_is_voided_and_restored_when_the_round_returns() {
	let tag = "Rc";
	let mut r = start().await;
	let x = r.x;
	let a = keypair("Rc A");
	let (ha, ta) = credited_board(&mut r, &a, x).await;
	let ca = Coin { held: ha, bases: vec![ta] };
	let a2 = keypair("Rc A2");
	let (pa, a2n) = participate(&r, &ca, &a2);
	let p_r = own_anchor(&r).await;
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let rtx = built.tx.clone();
	assert_eq!(rtx.input.len(), 1, "R spends one coin");
	r.produce().await;
	r.bury().await;
	round_final(&r, &rtx.txid()).await;
	let a_r = hand_over(&r, &pa, &ca, &a2, &a2n);

	// X takes R's only input and pays the operator nothing.
	let (xtx, p_x) = lose(&mut r, tag, &rtx, p_r, Taker::Elsewhere, |_| {}).await;
	let sa = wait_state(&r, &pa, "void").await;
	println!("{} after R is lost: A {}: {}", tag, sa["state"], sa["void_reason"]);
	assert_eq!(sa["state"], "void");
	let why = sa["void_reason"].as_str().unwrap();
	assert!(why.contains("no coin of the operator's can keep a re-run apart from round") && why.contains(&rtx.txid().to_string()), "{}", why);
	assert_eq!(sa["inputs"][0]["returned"], false, "its forfeit for R stays good should R return");
	assert!(r.server.rounds.run_round().await.unwrap().is_none(), "nothing runs again");

	// R returns: A is back as it stood in R, and the operator claims A's
	// board with its forfeit for R.
	r_returns(&mut r, tag, &rtx, &xtx, p_x, None, |_| {}).await;
	r.server.rounds.pass().await.unwrap();
	let sa = status(&r, &pa);
	println!("{} with R back: A {} attempt {}, void reason {}", tag, sa["state"], sa["attempt"], sa["void_reason"]);
	assert_eq!((sa["state"].as_str(), sa["attempt"].as_u64()), (Some("released"), Some(0)));
	assert_eq!(r.server.store.leaf(&a_r.leaf.leaf_id.0).await.unwrap().unwrap().state, LeafState::Live);
	drive(&r, "Rc A's board claimed for R", 12, |l| forfeit_naming(l, &ca, built.round_id)
		.is_some_and(|f| claim_spending(l, &txid(&f)).is_some())).await;
	settle(&r).await;
	let l = log(&r).await;
	let f_r = txid(&forfeit_naming(&l, &ca, built.round_id).unwrap());
	let claim = claim_spending(&l, &f_r).unwrap();
	println!("{} the forfeit for R of A's board {} claimed by {}", tag, f_r, txid(&claim));
	assert!(in_a_block(&r, &txid(&claim)));
	let _ = a_r.forfeit;
	let _ = ordinary_round(&mut r, tag, "B").await;
}

/// The participant P whose forfeit for R the watcher published while R was
/// final, and A, whose was not. R is lost with P's forfeit confirmed below
/// X; A runs again in Y; R returns. With `refund`, P refunds its forfeit
/// once its delay has run, while R is out, before X.
async fn barred(tag: &str, refund: bool) {
	let mut r = start().await;
	let x = r.x;
	let (p, a) = (keypair(&format!("{} P", tag)), keypair(&format!("{} A", tag)));
	let (hp, tp) = credited_board(&mut r, &p, x).await;
	let (ha, ta) = credited_board(&mut r, &a, x).await;
	let (cp, ca) = (Coin { held: hp, bases: vec![tp] }, Coin { held: ha, bases: vec![ta] });
	let (p2, a2) = (keypair(&format!("{} P2", tag)), keypair(&format!("{} A2", tag)));
	let (pp, p2n) = participate(&r, &cp, &p2);
	let (pa, a2n) = participate(&r, &ca, &a2);
	let p_r = own_anchor(&r).await;
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let rtx = built.tx.clone();
	r.produce().await;
	r.bury().await;
	round_final(&r, &rtx.txid()).await;
	// P hands over, and the watcher publishes P's board's forfeit for R; A
	// hands over after, and nothing of A's is published.
	let p_r_leaf = hand_over(&r, &pp, &cp, &p2, &p2n);
	drive(&r, &format!("{} P's forfeit for R", tag), 8, |l| has(l, "forfeit", &cp.held.id.0)).await;
	settle(&r).await;
	let fp = txid(&forfeit_naming(&log(&r).await, &cp, built.round_id).unwrap());
	let fp_tx: Transaction = r.rt.client().raw_transaction(&fp).unwrap();
	let _a_r = hand_over(&r, &pa, &ca, &a2, &a2n);
	println!("{} R = {} final; the watcher published P's forfeit for R {}; A released, nothing of it published", tag, rtx.txid(), fp);

	// R goes out; P's forfeit, as anyone who saw it holds it, confirms below
	// X; with `refund`, P refunds it once its delay has run.
	let refund_delay = RelativeTime::from_units(status(&r, &pp)["refund_delay_units"].as_u64().unwrap() as u16).unwrap();
	let fp_out = p_r_leaf.forfeit.output().txout();
	let vout = fp_tx.output.iter().position(|o| *o == fp_out).unwrap() as u32;
	let at = OutPoint::new(fp, vout);
	let refund_tx = {
		let value = p_r_leaf.forfeit.value - p_r_leaf.forfeit.margin;
		let ks = p_r_leaf.forfeit.refund(at, &[ExplicitOutput::new(x, value - 3_000, node::op_true())], &FeeSource::Reserve).unwrap();
		let sig = sign_digest(&p, &ks.sighash(r.chain.genesis_hash()).unwrap(), &random32());
		ks.finish(vec![sig.as_ref().to_vec()]).tx
	};
	let mock = refund.then(|| {
		let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
		let mtp = r.rt.client().blockchain_info().unwrap().median_time;
		now.max(mtp) + refund_delay.seconds() + 660
	});
	let (xtx, p_x) = lose(&mut r, tag, &rtx, p_r, Taker::ToOperator, |r| {
		r.rt.client().send_raw_transaction(&fp_tx).unwrap();
		tokio::task::block_in_place(|| r.rt.produce_block()).unwrap();
		if let Some(mock) = mock {
			let _: Value = r.rt.client().call("setmocktime", &[json!(mock)]).unwrap();
			for _ in 0..12 {
				tokio::task::block_in_place(|| r.rt.produce_block()).unwrap();
			}
			r.rt.client().send_raw_transaction(&refund_tx).unwrap();
			tokio::task::block_in_place(|| r.rt.produce_block()).unwrap();
		}
	}).await;
	println!("{} P's forfeit for R in a block: {}; P's refund of it in a block: {}", tag, in_a_block(&r, &fp), in_a_block(&r, &refund_tx.txid()));
	assert!(in_a_block(&r, &fp));
	assert_eq!(in_a_block(&r, &refund_tx.txid()), refund);
	let sp = wait_state(&r, &pp, "void").await;
	println!("{} after R is lost: P {}: {}", tag, sp["state"], sp["void_reason"]);
	assert_eq!(sp["state"], "void");
	assert!(sp["void_reason"].as_str().unwrap().contains(&fp.to_string()));

	// A runs again in Y.
	let built_y = r.server.rounds.run_round().await.unwrap().unwrap();
	assert_eq!(built_y.participations, 1, "P is not taken again");
	r.produce().await;
	r.bury().await;
	round_final(&r, &built_y.tx.txid()).await;
	let _a_y = hand_over(&r, &pa, &ca, &a2, &a2n);

	// R returns in X's place; P's forfeit, below X, stays.
	r_returns(&mut r, tag, &rtx, &xtx, p_x, mock, |_| {}).await;
	r.server.rounds.pass().await.unwrap();
	assert!(in_a_block(&r, &fp));
	let sp = status(&r, &pp);
	let sa = status(&r, &pa);
	println!("{} with R back: P {} attempt {} ({}); A {} attempt {}", tag, sp["state"], sp["attempt"], sp["void_reason"], sa["state"],
		sa["attempt"]);
	assert_eq!((sa["state"].as_str(), sa["attempt"].as_u64()), (Some("released"), Some(0)));
	let p_leaf = r.server.store.leaf(&p_r_leaf.leaf.leaf_id.0).await.unwrap().unwrap().state;
	if !refund {
		// The watcher claims P's forfeit for R with R's connector asset: P
		// holds its leaf of R, the operator P's board.
		assert_eq!((sp["state"].as_str(), sp["attempt"].as_u64()), (Some("released"), Some(0)));
		assert_eq!(p_leaf, LeafState::Live);
		drive(&r, &format!("{} P's forfeit for R claimed", tag), 12, |l| claim_spending(l, &fp).is_some()).await;
		settle(&r).await;
		let claim = claim_spending(&log(&r).await, &fp).unwrap();
		assert!(in_a_block(&r, &txid(&claim)));
		let tx: Transaction = elements::encode::deserialize(&claim.tx).unwrap();
		let m = arca_covenant::connector_asset(rtx.txid(), built.connector_vout);
		let k = tx.input.iter().position(|i| i.previous_output != at).unwrap();
		println!("{} the watcher's claim {} of P's forfeit for R, with an atom of R's connector asset {} (input {}); P's refund now: {:?}",
			tag, tx.txid(), m, k, verdict(&r, &refund_tx));
		assert!(missing_or_spent(&verdict(&r, &refund_tx)), "the refund can no longer be made");
	} else {
		// P's refund stands: P holds its board's value. The server never
		// credits P's leaf of R, so it co-signs nothing of it; P holds the
		// leaf's record, and the leaf is P's to take on the chain: the loss
		// is the operator's.
		assert_eq!(sp["state"], "void");
		let why = sp["void_reason"].as_str().unwrap();
		assert!(why.contains("refunded on the chain") && why.contains("its owner's to take on the chain") && why.contains("the loss is the \
			operator's"), "{}", why);
		assert_eq!(p_leaf, LeafState::Expired);
		passes(&r, 3).await;
		assert!(claim_spending(&log(&r).await, &fp).is_none(), "nothing can claim a refunded forfeit");
		let unroll = verdict(&r, &first_unroll(&p_r_leaf, &p2));
		println!("{} P's refund {} stands; P's leaf of R at the server: {:?}; its first unroll, the node's verdict: {:?}", tag,
			refund_tx.txid(), p_leaf, unroll);
		assert_eq!(unroll, Ok(()), "the leaf is P's to take on the chain");
	}
	let _ = ordinary_round(&mut r, tag, "B").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_barred_participants_forfeit_is_claimed_when_its_round_returns() {
	barred("Rd1", false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forfeit_refunded_while_its_round_was_out_leaves_the_returning_leaf_uncredited() {
	barred("Rd2", true).await;
}

/// A fresh participant `who`'s credited board, as a coin, and its key.
async fn fresh_board(r: &mut Running, tag: &str, who: &str) -> (Coin, Keypair) {
	let x = r.x;
	let b = keypair(&format!("{} {}", tag, who));
	let (hb, tb) = credited_board(r, &b, x).await;
	(Coin { held: hb, bases: vec![tb] }, b)
}

/// An ordinary round for a fresh participant `who`, built now: its board
/// credited, given up, the round built, confirmed in a parent block of its
/// own, final, and the participant released. The round, and what it issued
/// its token from.
async fn ordinary_round(r: &mut Running, tag: &str, who: &str) -> (Transaction, OutPoint) {
	let (cb, _) = fresh_board(r, tag, who).await;
	ordinary_round_of(r, tag, who, &cb).await
}

/// [`ordinary_round`] for the board `cb`, credited already.
async fn ordinary_round_of(r: &mut Running, tag: &str, who: &str, cb: &Coin) -> (Transaction, OutPoint) {
	let b2 = keypair(&format!("{} {} 2", tag, who));
	let (pb, b2n) = participate(r, cb, &b2);
	let _ = own_anchor(r).await;
	// The operator's round loop, a pass of the watcher and the nursery
	// between tries: a round the reorganisation took out is sent again, and
	// its change confirms, before the wallet has a coin to issue from.
	let mut built = None;
	for k in 0..6 {
		match r.server.rounds.run_round().await {
			Ok(Some(b)) => {
				built = Some(b);
				break;
			},
			other => {
				println!("{} {}'s round, try {}: {:?}", tag, who, k, other.map(|b| b.map(|b| b.tx.txid())).map_err(|e| e.to_string()));
				r.server.rounds.pass().await.unwrap();
				passes(r, 1).await;
				r.bury().await;
				r.synced().await;
			},
		}
	}
	let Some(built) = built else {
		for c in r.server.store.wallet_coins(None).await.unwrap() {
			println!("{} the wallet's coin {}:{} value {} in_chain {} spent {}", tag, Txid::from_byte_array(c.txid), c.vout, c.value, c.in_chain,
				c.spent_by.is_some());
		}
		panic!("{} {}'s round is not built", tag, who);
	};
	let tx = built.tx.clone();
	let issuer = tx.input[0].previous_output;
	r.produce().await;
	r.bury().await;
	round_final(r, &tx.txid()).await;
	let _ = hand_over(r, &pb, cb, &b2, &b2n);
	println!("{} {}'s round {} built and final; it issues from {}", tag, who, tx.txid(), issuer);
	(tx, issuer)
}

/// The batch tokens round `tx` issues: one atom of each, from its first
/// inputs.
fn tokens_of(tx: &Transaction) -> Vec<elements::AssetId> {
	tx.input.iter().filter(|i| i.has_issuance()).map(|i| i.issuance_ids().0).collect()
}

/// R7f F4, its Z1b turned around. A lost round returns and its re-run Y is
/// retired, which frees Y's coins, the coin Y issued its batch token from
/// among them. That coin's token is Y's batch's for good, so it never
/// issues again: the next ordinary round, for B, is built, issuing from
/// another coin, and its token is not Y's. (Before, the next round chose
/// Y's issuing coin again, and every build failed on the batch token's
/// uniqueness until a larger coin arrived.)
#[tokio::test(flavor = "multi_thread")]
async fn the_next_round_after_a_return_issues_from_another_coin() {
	let tag = "Z1b";
	let mut r = start().await;
	let x = r.x;
	let (a, a2) = (keypair("Z1b A"), keypair("Z1b A2"));
	let (ha, ta) = credited_board(&mut r, &a, x).await;
	let ca = Coin { held: ha, bases: vec![ta] };
	let (pa, a2n) = participate(&r, &ca, &a2);
	let p_r = own_anchor(&r).await;
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let rtx = built.tx.clone();
	r.produce().await;
	r.bury().await;
	round_final(&r, &rtx.txid()).await;
	let _a_r = hand_over(&r, &pa, &ca, &a2, &a2n);
	let (xtx, p_x) = lose(&mut r, tag, &rtx, p_r, Taker::ToOperator, |_| {}).await;
	r.server.rounds.pass().await.unwrap();
	wait_state(&r, &pa, "pending").await;
	let built_y = r.server.rounds.run_round().await.unwrap().unwrap();
	let ytx = built_y.tx.clone();
	r.produce().await;
	r.bury().await;
	round_final(&r, &ytx.txid()).await;
	let _a_y = hand_over(&r, &pa, &ca, &a2, &a2n);
	let (y_issuer, y_tokens) = (ytx.input[0].previous_output, tokens_of(&ytx));
	println!("{} Y = {} issues {:?} from {}", tag, ytx.txid(), y_tokens, y_issuer);
	r_returns(&mut r, tag, &rtx, &xtx, p_x, None, |_| {}).await;
	r.server.rounds.pass().await.unwrap();
	let (rs, ys) = (r.server.store.round(built.round_id).await.unwrap().map(|x| x.state),
		r.server.store.round(built_y.round_id).await.unwrap().map(|x| x.state));
	println!("{} R restored: R {:?}, Y {:?}", tag, rs, ys);
	assert_eq!((rs, ys), (Some(RoundState::Final), Some(RoundState::Lost)));
	let freed = r.server.store.wallet_coin_at(&y_issuer.txid.to_byte_array(), y_issuer.vout).await.unwrap();
	println!("{} Y's issuing coin, freed: spent_by {:?}", tag, freed.as_ref().map(|c| c.spent_by.is_some()));

	// B, a new participant: an ordinary round.
	let (btx, b_issuer) = ordinary_round(&mut r, tag, "B").await;
	assert_ne!(b_issuer, y_issuer, "the next round issues from another coin than Y's");
	assert!(tokens_of(&btx).iter().all(|t| !y_tokens.contains(t)), "its token is not Y's");
}

/// R7f Z1 with a round built after each of its four parent-chain
/// reorganisations, the operator's wallet funded once, at the start, and the
/// four fresh participants' boards made then, below every reorganisation: R lost
/// (X takes its input) and A run again in Y; R returns (X and Y out); R lost
/// again (X back) and A run again in Z; Y returns (Z out). After each, an
/// ordinary round for a fresh participant is built and final, and exactly
/// one of A's leaves can reach the chain, the one the server credits.
#[tokio::test(flavor = "multi_thread")]
async fn a_round_is_built_after_each_reorganisation() {
	let tag = "Z1";
	let mut r = start().await;
	let x = r.x;
	let (a, a2) = (keypair("Z1 A"), keypair("Z1 A2"));
	let (ha, ta) = credited_board(&mut r, &a, x).await;
	let ca = Coin { held: ha, bases: vec![ta] };
	let mut fresh = vec![];
	for k in 1..=4 {
		fresh.push(fresh_board(&mut r, tag, &format!("B{}", k)).await.0);
	}
	let (pa, a2n) = participate(&r, &ca, &a2);
	let p_r = own_anchor(&r).await;
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let rtx = built.tx.clone();
	r.produce().await;
	r.bury().await;
	round_final(&r, &rtx.txid()).await;
	let a_r = hand_over(&r, &pa, &ca, &a2, &a2n);
	let leaf = |r: &Running, x: &Released| {
		let id = x.leaf.leaf_id.0;
		tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(r.server.store.leaf(&id))).unwrap().map(|l| l.state)
	};
	// Exactly one of A's leaves comes onto the chain, the one credited.
	let one = |r: &Running, step: &str, leaves: &[(&str, &Released)], live: &str| {
		let mut seen = vec![];
		for (n, x) in leaves {
			let (st, v) = (leaf(r, x), verdict(r, &first_unroll(x, &a2)));
			seen.push(format!("leaf of {}: server {:?}, its unroll {:?}", n, st, v.as_ref().map_err(|e| e.chars().take(40).collect::<String>())));
			if *n == live {
				assert_eq!((st, v.is_ok()), (Some(LeafState::Live), true), "{} {}: the leaf of {}", tag, step, n);
			} else {
				assert!(st != Some(LeafState::Live) && missing_or_spent(&v), "{} {}: the leaf of {}: {:?} {:?}", tag, step, n, st, v);
			}
		}
		println!("{} {}: {}", tag, step, seen.join("; "));
	};

	// 1. R lost: X takes its input, paying the operator; A runs again in Y.
	let (xtx, p_x) = lose(&mut r, tag, &rtx, p_r, Taker::ToOperator, |_| {}).await;
	r.server.rounds.pass().await.unwrap();
	wait_state(&r, &pa, "pending").await;
	let built_y = r.server.rounds.run_round().await.unwrap().unwrap();
	let ytx = built_y.tx.clone();
	r.produce().await;
	r.bury().await;
	round_final(&r, &ytx.txid()).await;
	let a_y = hand_over(&r, &pa, &ca, &a2, &a2n);
	one(&r, "(1) R lost, Y final", &[("R", &a_r), ("Y", &a_y)], "Y");
	let (_, i1) = ordinary_round_of(&mut r, tag, "B1", &fresh[0]).await;

	// 2. R returns: X (and Y, and B1's round, with it) out, R confirmed in
	// a parent block of its own.
	r.server.stop();
	let orphaned = tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_x)).unwrap();
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0"])).unwrap();
	println!("{} (2) {} parent block(s) from height {} orphaned; the node restarted with an empty mempool", tag, orphaned.len(), p_x);
	let p_r2 = own_anchor(&r).await;
	println!("{} (2) R sent again: {:?}", tag, r.rt.client().send_raw_transaction(&rtx).map(|t| t.to_string()).map_err(|e| e.to_string()));
	r.produce().await;
	r.bury().await;
	r.restart_server().await;
	round_state(&r, &rtx.txid(), RoundState::Final).await;
	r.server.rounds.pass().await.unwrap();
	assert_eq!(r.server.store.round(built_y.round_id).await.unwrap().map(|x| x.state), Some(RoundState::Lost), "Y retired");
	one(&r, "(2) R returned", &[("R", &a_r), ("Y", &a_y)], "R");
	let (_, i2) = ordinary_round_of(&mut r, tag, "B2", &fresh[1]).await;
	assert_ne!(i2, ytx.input[0].previous_output, "not from Y's issuing coin");

	// 3. R lost again: R's block out, X sent again and confirmed; A runs
	// again in Z.
	let (_, p_x2) = {
		r.server.stop();
		let orphaned = tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_r2)).unwrap();
		tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0"])).unwrap();
		println!("{} (3) {} parent block(s) from height {} orphaned; the node restarted with an empty mempool", tag, orphaned.len(), p_r2);
		let p = own_anchor(&r).await;
		println!("{} (3) X sent again: {:?}", tag, r.rt.client().send_raw_transaction(&xtx).map(|t| t.to_string()).map_err(|e| e.to_string()));
		r.produce().await;
		r.bury().await;
		r.restart_server().await;
		round_state(&r, &rtx.txid(), RoundState::Lost).await;
		((), p)
	};
	r.server.rounds.pass().await.unwrap();
	let sa = wait_state(&r, &pa, "pending").await;
	println!("{} (3) A {} attempt {}", tag, sa["state"], sa["attempt"]);
	let p_z = own_anchor(&r).await;
	let built_z = r.server.rounds.run_round().await.unwrap().expect("Z is built, from the coins the wallet holds");
	let ztx = built_z.tx.clone();
	println!("{} (3) Z = {} ties: {:?}", tag, ztx.txid(), r.server.store.replaced_by(built_z.round_id).await.unwrap());
	r.produce().await;
	r.bury().await;
	round_final(&r, &ztx.txid()).await;
	let a_z = hand_over(&r, &pa, &ca, &a2, &a2n);
	one(&r, "(3) Z final", &[("R", &a_r), ("Y", &a_y), ("Z", &a_z)], "Z");
	let (_, i3) = ordinary_round_of(&mut r, tag, "B3", &fresh[2]).await;
	let _ = p_x2;

	// 4. Y returns: Z (and B3's round) out, Y sent by anyone who holds it.
	r.server.stop();
	let orphaned = tokio::task::block_in_place(|| r.rt.orphan_parent_from(p_z)).unwrap();
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0"])).unwrap();
	println!("{} (4) {} parent block(s) from height {} orphaned; X in a block {}", tag, orphaned.len(), p_z, in_a_block(&r, &xtx.txid()));
	println!("{} (4) Y sent again: {:?}", tag, r.rt.client().send_raw_transaction(&ytx).map(|t| t.to_string()).map_err(|e| e.to_string()));
	r.produce().await;
	r.bury().await;
	r.restart_server().await;
	round_state(&r, &ytx.txid(), RoundState::Final).await;
	r.server.rounds.pass().await.unwrap();
	one(&r, "(4) Y returned", &[("R", &a_r), ("Y", &a_y), ("Z", &a_z)], "Y");
	let (_, i4) = ordinary_round_of(&mut r, tag, "B4", &fresh[3]).await;
	println!("{} the four rounds after each reorganisation issued from {}, {}, {}, {}", tag, i1, i2, i3, i4);
	let issued = [ytx.input[0].previous_output, ztx.input[0].previous_output];
	assert!([i1, i2, i3, i4].iter().all(|i| !issued.contains(i)), "never a re-run's issuing coin");
}

/// R7f F5, its Z2 turned around. A's board, given up in R, is run again in
/// Y, and the watcher publishes and claims its forfeit for Y. The deeper
/// reorganisation brings R back, and the node puts the disconnected
/// transactions back in its mempool: Y's forfeit spends A's board alone, so
/// it confirms beside R, while Y's claim of it never can. The server leaves
/// A uncredited: void, saying that its leaf of R is its owner's to take and
/// the loss the operator's, the leaf `expired` at the server. On the chain:
/// A's first unroll of its leaf of R is valid, the operator has no forfeit
/// for R of A's board, and A's refund of Y's forfeit opens after its delay.
/// The next round is built.
#[tokio::test(flavor = "multi_thread")]
async fn a_reruns_forfeit_back_with_the_reorganisation_leaves_the_returning_leaf_uncredited() {
	let tag = "Z2";
	let mut r = start().await;
	let x = r.x;
	let (a, a2) = (keypair("Z2 A"), keypair("Z2 A2"));
	let (ha, ta) = credited_board(&mut r, &a, x).await;
	let ca = Coin { held: ha, bases: vec![ta] };
	let (pa, a2n) = participate(&r, &ca, &a2);
	let p_r = own_anchor(&r).await;
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let rtx = built.tx.clone();
	r.produce().await;
	r.bury().await;
	round_final(&r, &rtx.txid()).await;
	let a_r = hand_over(&r, &pa, &ca, &a2, &a2n);
	let (xtx, p_x) = lose(&mut r, tag, &rtx, p_r, Taker::ToOperator, |_| {}).await;
	r.server.rounds.pass().await.unwrap();
	wait_state(&r, &pa, "pending").await;
	let built_y = r.server.rounds.run_round().await.unwrap().unwrap();
	let ytx = built_y.tx.clone();
	r.produce().await;
	r.bury().await;
	round_final(&r, &ytx.txid()).await;
	let a_y = hand_over(&r, &pa, &ca, &a2, &a2n);
	drive(&r, "Z2 A's board claimed for Y", 10, |l| has(l, "claim", &ca.held.id.0)).await;
	settle(&r).await;
	let l = log(&r).await;
	let f_y = txid(&forfeit_naming(&l, &ca, built_y.round_id).expect("A's board's forfeit for Y"));
	let f_y_tx: Transaction = r.rt.client().raw_transaction(&f_y).unwrap();
	let c_y: Transaction = elements::encode::deserialize(&claim_spending(&l, &f_y).unwrap().tx).unwrap();
	println!("{} Y final; A's board's forfeit for Y {} and its claim {} in blocks", tag, f_y, c_y.txid());
	assert!(in_a_block(&r, &f_y) && in_a_block(&r, &c_y.txid()));

	r_returns(&mut r, tag, &rtx, &xtx, p_x, None, |_| {}).await;
	r.server.rounds.pass().await.unwrap();
	println!("{} in a block now: R {}, X {}, Y {}, Y's forfeit of A's board {}, its claim {}", tag, in_a_block(&r, &rtx.txid()),
		in_a_block(&r, &xtx.txid()), in_a_block(&r, &ytx.txid()), in_a_block(&r, &f_y), in_a_block(&r, &c_y.txid()));
	assert!(in_a_block(&r, &rtx.txid()) && in_a_block(&r, &f_y) && !in_a_block(&r, &ytx.txid()) && !in_a_block(&r, &c_y.txid()));
	assert!(missing_or_spent(&verdict(&r, &c_y)), "Y's claim can never confirm");
	let sa = status(&r, &pa);
	let leaf_r = r.server.store.leaf(&a_r.leaf.leaf_id.0).await.unwrap().unwrap().state;
	let unroll = verdict(&r, &first_unroll(&a_r, &a2));
	println!("{} A at the server: {} ({}); its leaf of R {:?}, its first unroll {:?}", tag, sa["state"], sa["void_reason"], leaf_r, unroll);
	assert_eq!(sa["state"], "void");
	let why = sa["void_reason"].as_str().unwrap();
	assert!(why.contains(&f_y.to_string()) && why.contains(&format!("a forfeit for round {}", built_y.round_id))
		&& why.contains("its owner's to take on the chain") && why.contains("the loss is the operator's"), "{}", why);
	assert_eq!(leaf_r, LeafState::Expired);
	assert_eq!(unroll, Ok(()), "the leaf is A's to take");
	assert_eq!(r.server.store.leaf(&a_y.leaf.leaf_id.0).await.unwrap().unwrap().state, LeafState::Lost);
	passes(&r, 4).await;
	let l = log(&r).await;
	let f_r = forfeit_naming(&l, &ca, built.round_id);
	println!("{} the operator's forfeit for R of A's board: {:?}", tag, f_r.as_ref().map(txid));
	if let Some(f) = &f_r {
		let t: Transaction = elements::encode::deserialize(&f.tx).unwrap();
		assert!(missing_or_spent(&verdict(&r, &t)) && !in_a_block(&r, &t.txid()), "no forfeit for R of A's board can confirm");
	}
	// A's refund of Y's forfeit: A's, once its delay has run.
	let fy_out = a_y.forfeit.output().txout();
	let vout = f_y_tx.output.iter().position(|o| *o == fy_out).unwrap() as u32;
	let value = a_y.forfeit.value - a_y.forfeit.margin;
	let ks = a_y.forfeit.refund(OutPoint::new(f_y, vout), &[ExplicitOutput::new(x, value - 3_000, node::op_true())], &FeeSource::Reserve).unwrap();
	let sig = sign_digest(&a, &ks.sighash(r.chain.genesis_hash()).unwrap(), &random32());
	let refund_tx = ks.finish(vec![sig.as_ref().to_vec()]).tx;
	let rv = verdict(&r, &refund_tx);
	println!("{} A's refund of Y's forfeit, the node's verdict now: {:?}", tag, rv);
	assert!(rv.as_ref().err().is_some_and(|e| e.contains("non-BIP68-final")), "{:?}", rv);
	let _ = ordinary_round(&mut r, tag, "B").await;
}

/// R7f F5's third case. A's participation is voided while R is out (X pays
/// the operator nothing, R had one input), and A, as its wallet does, takes
/// back the board it gave up: it converts it and exits it after its delay,
/// both in blocks below X. When R returns, A's board is spent on the chain
/// by A's own exit, otherwise than by its forfeit for R: the server leaves A
/// uncredited, its leaf of R its owner's to take (its first unroll valid),
/// the loss the operator's, and no forfeit for R of A's board can be built.
/// The next round is built.
#[tokio::test(flavor = "multi_thread")]
async fn a_board_exited_while_its_round_was_out_leaves_the_returning_leaf_uncredited() {
	let tag = "Re";
	let mut r = start().await;
	let x = r.x;
	let (a, a2) = (keypair("Re A"), keypair("Re A2"));
	let (ha, ta) = credited_board(&mut r, &a, x).await;
	let ca = Coin { held: ha, bases: vec![ta] };
	// B's board, for the round after the restore, made now, below every
	// reorganisation.
	let (cb, _) = fresh_board(&mut r, tag, "B").await;
	let (pa, a2n) = participate(&r, &ca, &a2);
	let p_r = own_anchor(&r).await;
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	let rtx = built.tx.clone();
	r.produce().await;
	r.bury().await;
	round_final(&r, &rtx.txid()).await;
	let a_r = hand_over(&r, &pa, &ca, &a2, &a2n);
	// A's conversion and exit, made while R is out, below X.
	let (policy, at) = ca.valid(&r).board().unwrap();
	let fee_coin = r.purse.take_coin(x);
	let conv = policy.conversion(at, &FeeSource::Coin { outpoint: fee_coin.0, coin: fee_coin.1.clone(), fee: 3_000, change: node::op_true() })
		.unwrap();
	let sig = sign_digest(&a, &conv.sighash(r.chain.genesis_hash()).unwrap(), &random32());
	let conv = conv.finish(vec![sig.as_ref().to_vec()]).tx;
	let leaf_at = OutPoint::new(conv.txid(), 0);
	let exit = common::flow::exit_tx(&r, &policy.leaf, leaf_at, x, policy.value, &a);
	let mock = {
		let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
		let mtp = r.rt.client().blockchain_info().unwrap().median_time;
		now.max(mtp) + policy.leaf.exit_delay.seconds() as u64 + 660
	};
	let (xtx, p_x) = lose(&mut r, tag, &rtx, p_r, Taker::Elsewhere, |r| {
		r.rt.client().send_raw_transaction(&conv).unwrap();
		tokio::task::block_in_place(|| r.rt.produce_block()).unwrap();
		let _: Value = r.rt.client().call("setmocktime", &[json!(mock)]).unwrap();
		for _ in 0..12 {
			tokio::task::block_in_place(|| r.rt.produce_block()).unwrap();
		}
		r.rt.client().send_raw_transaction(&exit).unwrap();
		tokio::task::block_in_place(|| r.rt.produce_block()).unwrap();
	}).await;
	println!("{} A's conversion {} and exit {} in blocks below X: {} {}", tag, conv.txid(), exit.txid(), in_a_block(&r, &conv.txid()),
		in_a_block(&r, &exit.txid()));
	assert!(in_a_block(&r, &conv.txid()) && in_a_block(&r, &exit.txid()));
	let sa = wait_state(&r, &pa, "void").await;
	println!("{} after R is lost: A {}: {}", tag, sa["state"], sa["void_reason"]);

	r_returns(&mut r, tag, &rtx, &xtx, p_x, Some(mock), |_| {}).await;
	r.server.rounds.pass().await.unwrap();
	let sa = status(&r, &pa);
	let leaf_r = r.server.store.leaf(&a_r.leaf.leaf_id.0).await.unwrap().unwrap().state;
	let unroll = verdict(&r, &first_unroll(&a_r, &a2));
	println!("{} with R back: A {} ({}); its leaf of R {:?}, its first unroll {:?}", tag, sa["state"], sa["void_reason"], leaf_r, unroll);
	assert_eq!(sa["state"], "void");
	let why = sa["void_reason"].as_str().unwrap();
	assert!(why.contains(&format!("{}:0", conv.txid())) && why.contains("its owner's to take on the chain")
		&& why.contains("the loss is the operator's"), "the leaf A's conversion made, which A's exit spent: {}", why);
	assert_eq!(leaf_r, LeafState::Expired);
	assert_eq!(unroll, Ok(()), "the leaf is A's to take");
	passes(&r, 4).await;
	let l = log(&r).await;
	let f_r = forfeit_naming(&l, &ca, built.round_id);
	println!("{} the operator's forfeit for R of A's board: {:?}", tag, f_r.as_ref().map(txid));
	if let Some(f) = &f_r {
		let t: Transaction = elements::encode::deserialize(&f.tx).unwrap();
		assert!(missing_or_spent(&verdict(&r, &t)) && !in_a_block(&r, &t.txid()), "no forfeit for R of A's board can confirm");
	}
	let _ = ordinary_round_of(&mut r, tag, "B", &cb).await;
}
