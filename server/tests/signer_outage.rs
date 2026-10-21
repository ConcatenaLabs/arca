//! A stopped signer holds none of the operator's coins, against a whole
//! server on an anchored proof-of-stake regtest chain. A batch reaches its
//! expiry while the signer is stopped: each watcher pass builds the token's
//! release, reserving a coin of the wallet's for its fee, and cannot sign
//! it. The coin is given back each time, so the wallet can spend what it
//! could before, and the operator's rounds are not left unfunded. Once the
//! signer is back, the release goes out.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;

use common::flow::{claimed, drive, has, log, refresh, settle, Coin};
use common::keys::keypair;
use common::rounds::{advance_mtp, credited_board, mtp};
use common::running::Running;

const HOUR: u32 = 3_600;

#[tokio::test(flavor = "multi_thread")]
async fn a_release_the_signer_cannot_sign_holds_no_coin_of_the_wallet() {
	let mut r = Running::start().await;
	let x = r.x;
	for _ in 0..2 {
		r.fund_wallet_in(x, 50_000_000).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	// A board refreshed into a batch; its forfeit claimed.
	let (held, tx) = credited_board(&mut r, &keypair("SO board"), x).await;
	let board = Coin { held, bases: vec![tx] };
	let key = keypair("SO");
	let got = refresh(&mut r, &[(&board, &key)]).await;
	let token = got[0].new_valid.branch.nodes[0].sweep.token.into_inner().to_byte_array().to_vec();
	drive(&r, "the board's forfeit claimed", 12, |l| claimed(l) == 1).await;
	settle(&r).await;
	let e0 = match &got[0].new.held.record {
		arca_covenant::CoinRecord::Leaf { record, .. } => record.schedule.expiries()[0].to_consensus_u32(),
		_ => unreachable!(),
	};

	// The signer stops; the batch reaches its expiry.
	let before = r.server.wallet.balance().await.unwrap().get(&x).copied().unwrap_or(0);
	r.signer.kill();
	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, e0.saturating_sub(now) + HOUR).await;
	for pass in 0..4 {
		r.synced().await;
		let res = r.server.watcher.pass().await;
		println!("watcher pass {} with the signer stopped: {:?}", pass, res.as_ref().err().map(|e| e.to_string()));
		r.produce().await;
		r.bury().await;
	}
	assert!(!has(&log(&r).await, "release", &token), "nothing is released without the operator's signature");
	let after = r.server.wallet.balance().await.unwrap().get(&x).copied().unwrap_or(0);
	println!("the wallet can spend {} of X before the signer stopped, {} after four passes", before, after);
	assert!(after >= before, "no coin of the wallet's is held by a release that was never published: {} -> {}", before, after);

	// The signer back: the release goes out.
	let genesis = r.rt.client().genesis_hash().unwrap();
	r.signer.restart(&r.s, genesis);
	drive(&r, "the release once the signer is back", 4, |l| has(l, "release", &token)).await;
}
