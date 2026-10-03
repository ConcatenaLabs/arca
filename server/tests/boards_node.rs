//! Board registration and crediting on an anchored proof-of-stake regtest
//! chain: a board registered, final, credited; uncredited by a rollback that
//! takes it out, broadcast again by the server alone and credited again; and
//! every board outside the operator's policy refused, for its reason, leaving
//! nothing behind.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::{BlockHash, Txid};

use arca_covenant::{BoardRecord, Chain, RelativeTime};
use common::client::{board_record, board_tx};
use common::keys::{keypair, xonly};
use common::node::{self, op_true};
use common::stack::{Stack, MIN_LEAF};
use server::boards::BoardError;
use server::chain::Finality;
use server::store::{BoardState, LeafState};

const VALUE: u64 = 2_000_000;

fn refused(e: BoardError, code: &str) {
	assert_eq!(e.code(), code, "{}", e);
	println!("refused, {}: {}", code, e);
}

#[tokio::test(flavor = "multi_thread")]
async fn boards_on_regtest() {
	let mut st = Stack::start().await;
	let s = xonly(&st.s);

	// A board: the owner gets the operator's nonce, pays its coins and
	// broadcasts, then registers.
	let owner = keypair("board owner 1");
	let nonce = st.db.store.issue_nonce().await.unwrap();
	let record = board_record(&owner, nonce, st.x, VALUE, st.chain, s);
	let coin = st.purse.take_coin(st.x);
	let tx = board_tx(&record, &coin, 2_000, op_true());
	st.rt.client().send_raw_transaction(&tx).unwrap();
	st.purse.put((elements::OutPoint::new(tx.txid(), 1), tx.output[1].clone()));
	let status = st.boards.register(&record, &tx).await.unwrap();
	assert_eq!(status.state, BoardState::Pending);
	assert_eq!(status.finality, Finality::NotInChain);
	let id = record.leaf_id();
	assert_eq!(status.leaf_id, id);
	assert_eq!(st.db.store.leaf(&id.0).await.unwrap().unwrap().state, LeafState::Pending);
	println!("registered {} paid by {}: {:?}, {}", id, tx.txid(), status.state, status.finality.name());

	st.produce().await;
	let status = st.boards.status(&id).await.unwrap().unwrap();
	assert_eq!(status.state, BoardState::Pending, "settled is not final: {:?}", status.finality);
	assert!(matches!(status.finality, Finality::Settled { depth: 0, .. }));
	st.bury().await;
	let status = st.boards.status(&id).await.unwrap().unwrap();
	assert_eq!(status.state, BoardState::Credited);
	assert!(status.finality.is_final());
	assert_eq!(st.db.store.leaf(&id.0).await.unwrap().unwrap().state, LeafState::Live);
	println!("credited once final: {:?}", status.finality);

	// Registering it again changes nothing.
	assert_eq!(st.boards.register(&record, &tx).await.unwrap().state, BoardState::Credited);

	// A rollback below it, and a node that forgot it: uncredited at once,
	// broadcast again by the server, credited again once final again.
	let block = st.db.store.tx_location(&tx.txid().to_byte_array()).await.unwrap().unwrap();
	node::invalidate(&st.rt, &BlockHash::from_byte_array(block.hash));
	tokio::task::block_in_place(|| st.rt.node.restart(&["-persistmempool=0"])).unwrap();
	assert!(!node::in_mempool(&st.rt, &tx.txid()));
	st.follow().await;
	let status = st.boards.status(&id).await.unwrap().unwrap();
	assert_eq!(status.state, BoardState::Pending);
	assert_eq!(st.db.store.leaf(&id.0).await.unwrap().unwrap().state, LeafState::Pending);
	assert!(node::in_mempool(&st.rt, &tx.txid()), "the server broadcast it again");
	let nursery = st.db.store.nursery_get(&tx.txid().to_byte_array()).await.unwrap().unwrap();
	println!("after the rollback: {:?}, {}; nursery broadcast it again: {}", status.state, status.finality.name(),
		nursery.last_result.unwrap());
	st.produce().await;
	assert_eq!(st.boards.status(&id).await.unwrap().unwrap().state, BoardState::Pending);
	st.bury().await;
	let b = st.db.store.board(&id.0).await.unwrap().unwrap();
	assert_eq!((b.state, b.credits, b.uncredits), (BoardState::Credited, 2, 1));
	assert_eq!(Txid::from_byte_array(b.txid), tx.txid(), "the same transaction");
	assert_eq!(st.db.store.leaf(&id.0).await.unwrap().unwrap().state, LeafState::Live);
	println!("credited again: credits {}, uncredits {}", b.credits, b.uncredits);

	// Refusals. Each builds the transaction the record asks for, from a coin
	// it does not spend.
	let coin2 = st.purse.take_coin(st.x);
	let try_board = |r: &BoardRecord| board_tx(r, &coin2, 2_000, op_true());

	let other = keypair("board owner 2");
	let n2 = st.db.store.issue_nonce().await.unwrap();
	let mut r = board_record(&other, n2, st.x, VALUE, st.chain, xonly(&keypair("another operator")));
	refused(st.boards.register(&r, &try_board(&r)).await.unwrap_err(), "wrong_operator");
	r = board_record(&other, n2, st.x, VALUE, Chain::new(BlockHash::from_byte_array([7; 32])), s);
	refused(st.boards.register(&r, &try_board(&r)).await.unwrap_err(), "wrong_chain");
	r = board_record(&other, n2, st.x, VALUE, st.chain, s);
	r.exit_delay = RelativeTime::from_units(1).unwrap();
	refused(st.boards.register(&r, &try_board(&r)).await.unwrap_err(), "out_of_bounds");
	r = board_record(&other, n2, st.y, VALUE, st.chain, s);
	refused(st.boards.register(&r, &board_tx(&r, &st.purse.take_coin(st.y), 0, op_true())).await.unwrap_err(), "out_of_bounds");
	r = board_record(&other, n2, st.x, MIN_LEAF - 1, st.chain, s);
	refused(st.boards.register(&r, &try_board(&r)).await.unwrap_err(), "out_of_bounds");
	r = board_record(&other, [9; 32], st.x, VALUE, st.chain, s);
	refused(st.boards.register(&r, &try_board(&r)).await.unwrap_err(), "nonce_unknown");
	r = board_record(&other, nonce, st.x, VALUE, st.chain, s);
	refused(st.boards.register(&r, &try_board(&r)).await.unwrap_err(), "nonce_used");
	// The transaction does not pay the board output, or pays it twice.
	r = board_record(&other, n2, st.x, VALUE, st.chain, s);
	let wrong = board_tx(&board_record(&keypair("someone else"), n2, st.x, VALUE, st.chain, s), &coin2, 2_000, op_true());
	refused(st.boards.register(&r, &wrong).await.unwrap_err(), "board_output");
	let mut twice = try_board(&r);
	twice.output.insert(1, twice.output[0].clone());
	refused(st.boards.register(&r, &twice).await.unwrap_err(), "board_output");
	// The key of a leaf the server already knows, with a fresh nonce.
	let n3 = st.db.store.issue_nonce().await.unwrap();
	r = board_record(&owner, n3, st.x, VALUE, st.chain, s);
	refused(st.boards.register(&r, &try_board(&r)).await.unwrap_err(), "key_reused");
	// Another transaction paying a board already registered.
	let other_tx = board_tx(&record, &coin2, 3_000, op_true());
	refused(st.boards.register(&record, &other_tx).await.unwrap_err(), "board_exists");

	// Nothing refused was kept: the nonces refused above are still free, and
	// a valid board takes one.
	r = board_record(&other, n2, st.x, VALUE, st.chain, s);
	let ok = try_board(&r);
	st.rt.client().send_raw_transaction(&ok).unwrap();
	assert_eq!(st.boards.register(&r, &ok).await.unwrap().state, BoardState::Pending);
	st.produce().await;
	st.bury().await;
	assert_eq!(st.boards.status(&r.leaf_id()).await.unwrap().unwrap().state, BoardState::Credited);
	println!("a valid board on the nonce the refusals were given: credited");
}
