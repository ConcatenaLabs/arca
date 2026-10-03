//! A transaction of the watcher's whose parent never comes back: review R7's
//! F9. A deep anchor-driven reorganisation takes out the round's atom
//! issuance, the forfeit of a board and its claim; another issuance of the
//! same connector output takes the first one's place. The forfeit returns;
//! the claim never can, since its atom is gone, and no final transaction
//! spends that atom's outpoint, which never exists. The nursery finds the
//! claim's parent in no block, no mempool and lost in the nursery, marks the
//! claim lost, and the watcher claims the forfeit again with the new atom.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::{OutPoint, Transaction, Txid};

use arca_covenant::sign::sign_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::{connector_asset, ConnectorPolicy, ExplicitOutput};
use common::client::random32;
use common::flow::{claim_of, log, refresh, Coin};
use common::keys::{keypair, xonly};
use common::rounds::{credited_board, start};
use server::store::NurseryState;

#[tokio::test(flavor = "multi_thread")]
async fn a_claim_whose_atom_never_returns_is_lost_and_claimed_again() {
	let mut r = start().await;
	let x = r.x;
	let (held, tx) = credited_board(&mut r, &keypair("A, board"), x).await;
	let coin = Coin { held, bases: vec![tx] };
	let refreshed = refresh(&mut r, &[(&coin, &keypair("A, new leaf"))]).await;
	let round = &refreshed[0].round;
	let c = refreshed[0].connector_vout;
	let leaf = coin.held.id.0.to_vec();

	// A parent block of their own for what follows, so the reorganisation
	// that orphans it takes out exactly that.
	r.rt.mine_parent(1).unwrap();
	r.rt.anchor_to_parent_tip().unwrap();
	let p = r.rt.parent.client().block_count().unwrap();
	r.synced().await;
	// The watcher publishes the board's forfeit and issues the round's atom;
	// a block; then it claims the forfeit with the atom; a block.
	r.server.watcher.pass().await.unwrap();
	r.produce().await;
	r.synced().await;
	r.server.watcher.pass().await.unwrap();
	for _ in 0..6 {
		r.produce().await;
	}
	r.synced().await;
	let l = log(&r).await;
	let forfeit = l.iter().find(|w| w.kind == "forfeit" && w.subject == leaf).unwrap().clone();
	let issue = l.iter().find(|w| w.kind == "issue").unwrap().clone();
	let claim = claim_of(&l, &leaf).expect("claimed").clone();
	let (f, i, cl) = (Txid::from_byte_array(forfeit.txid), Txid::from_byte_array(issue.txid), Txid::from_byte_array(claim.txid));
	for t in [i, f, cl] {
		assert!(r.rt.client().confirmations(&t).unwrap() >= 1, "{} is in a block", t);
	}
	println!("issue {}, forfeit {}, claim {}: in blocks anchored at parent {} or above", i, f, cl, p);

	// Bitcoin reorganises from that parent block: every block anchored there
	// or above is disconnected, however deep.
	let before = r.rt.client().block_count().unwrap();
	let orphaned = tokio::task::block_in_place(|| r.rt.orphan_parent_from(p)).unwrap();
	let after = r.rt.client().block_count().unwrap();
	println!("the parent orphaned {} block(s); the Sequentia tip went from {} to {}", orphaned.len(), before, after);
	for t in [i, f, cl] {
		assert!(r.rt.client().confirmations(&t).map(|n| n == 0).unwrap_or(true), "{} left the chain", t);
	}
	// The server stopped, the node restarted with its mempool empty, and
	// another issuance of the same connector output takes the first one's
	// place: the first can never return, nor can the claim on its atom.
	r.server.stop();
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0"])).unwrap();
	let conn = OutPoint::new(round.txid(), c);
	let held = ExplicitOutput::from_txout(&round.output[c as usize]).unwrap();
	let to = r.server.wallet.receive_script().await.unwrap();
	let ks = ConnectorPolicy { operator: xonly(&r.s) }.issuance(conn, (held.asset, held.value), to, &[], &FeeSource::Reserve).unwrap();
	let sig = sign_digest(&r.s, &ks.sighash(r.chain.genesis_hash()).unwrap(), &random32());
	let other: Transaction = ks.finish(vec![sig.as_ref().to_vec()]).tx;
	assert_ne!(other.txid(), i);
	r.rt.client().send_raw_transaction(&other).unwrap();
	r.produce().await;
	r.bury().await;
	println!("another issuance {} of the connector output, final", other.txid());

	r.restart_server().await;
	let m = connector_asset(round.txid(), c);
	let mut claimed_again = None;
	for n in 0..12 {
		r.synced().await;
		r.server.nursery.pass().await.unwrap();
		r.server.watcher.pass().await.unwrap();
		let l = log(&r).await;
		let state = |t: &Txid| l.iter().find(|w| w.txid == t.to_byte_array()).map(|w| w.state);
		let last = r.server.store.nursery_get(&cl.to_byte_array()).await.unwrap().and_then(|row| row.last_result);
		println!("pass {}: issue {:?}, forfeit {:?}, claim {:?} (last broadcast: {:?})", n, state(&i), state(&f), state(&cl), last);
		if let Some(again) = l.iter().find(|w| w.kind == "claim" && w.txid != claim.txid && w.state != NurseryState::Lost) {
			let t = Txid::from_byte_array(again.txid);
			if r.rt.client().confirmations(&t).is_ok_and(|n| n >= 1) {
				claimed_again = Some(t);
				break;
			}
		}
		r.produce().await;
		r.bury().await;
	}
	let l = log(&r).await;
	let row = |t: &Txid| l.iter().find(|w| w.txid == t.to_byte_array()).unwrap().clone();
	assert_eq!(row(&i).state, NurseryState::Lost, "the first issuance is lost: another spent its input and is final");
	assert_eq!(row(&cl).state, NurseryState::Lost, "the claim on its atom is lost");
	let again = claimed_again.expect("the forfeit claimed again, in a block");
	let tx: Transaction = elements::encode::deserialize(&row(&again).tx).unwrap();
	assert!(tx.input.iter().any(|x| x.previous_output == OutPoint::new(f, 0)), "it takes the forfeit");
	assert!(tx.input.iter().any(|x| x.previous_output == OutPoint::new(other.txid(), 0)), "with the other issuance's atom of {}", m);
	println!("the claim {} is lost; the forfeit {} is claimed again by {}, with the atom of {}", cl, f, again, other.txid());
}
