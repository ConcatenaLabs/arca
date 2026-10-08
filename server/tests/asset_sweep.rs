//! A batch's expiry worked in its own asset, against a whole server on an
//! anchored proof-of-stake regtest chain: X and Y both listed for fees, X the
//! first of the operator's fee assets. A batch of Y, at its expiry, has its
//! token released with the fee paid from Y's pool, and is swept after the
//! notice with the fee taken from the Y it sweeps: Y's work is paid in Y,
//! and X's pool is not touched for it.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::hashes::Hash;
use elements::{AssetId, Transaction};

use common::flow::{claimed, drive, of_kind, refresh, settle, txid, Coin};
use common::keys::keypair;
use common::rounds::{advance_mtp, credited_board, mtp};
use common::running::Running;

const HOUR: u32 = 3_600;

/// The asset of `tx`'s fee output.
fn fee_asset(tx: &Transaction) -> AssetId {
	tx.output.iter().find(|o| o.is_fee()).and_then(|o| o.asset.explicit()).expect("a fee output")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_batch_is_released_and_swept_in_its_own_asset() {
	let mut r = Running::start_with(|c, y| {
		c.assets.push(toml::from_str(&format!("asset = \"{}\"\nmin_leaf = \"1000\"\n", y)).unwrap());
	}).await;
	let (x, y) = (r.x, r.y);
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	for asset in [x, x, y, y] {
		r.fund_wallet_in(asset, 50_000_000).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	// The configuration names no fee assets: the served ones, X first.

	// Two boards of Y refreshed into a batch of Y; the boards come back.
	let mut boards = vec![];
	let mut keys = vec![];
	for i in 0..2 {
		let (held, tx) = credited_board(&mut r, &keypair(&format!("AS U{}, board", i)), y).await;
		boards.push(Coin { held, bases: vec![tx] });
		keys.push(keypair(&format!("AS U{}", i)));
	}
	let pairs: Vec<(&Coin, &elements::secp256k1_zkp::Keypair)> = boards.iter().zip(&keys).collect();
	let got = refresh(&mut r, &pairs).await;
	let round = got[0].round.clone();
	let schedule = got[0].new_valid.branch.nodes[0].sweep;
	assert_eq!(round.output[got[0].new_valid.batch_vout as usize].asset.explicit(), Some(y), "a batch of Y");
	drive(&r, "the two boards", 12, |l| claimed(l) == 2).await;
	settle(&r).await;
	let e0 = match &got[0].new.held.record {
		arca_covenant::CoinRecord::Leaf { record, .. } => record.schedule.expiries()[0].to_consensus_u32(),
		_ => unreachable!(),
	};

	// At the expiry: the token's release, its fee from Y's pool.
	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, e0.saturating_sub(now) + HOUR).await;
	let token_subject = schedule.token.into_inner().to_byte_array().to_vec();
	drive(&r, "the release at the expiry", 4, |l| common::flow::has(l, "release", &token_subject)).await;
	settle(&r).await;
	let rel = of_kind(&r, "release").await.remove(0);
	let rel_tx: Transaction = elements::encode::deserialize(&rel.tx).unwrap();
	println!("the release {} of the batch of Y: {} vB, its fee in {}", txid(&rel), rel_tx.vsize(), if fee_asset(&rel_tx) == y { "Y" } else { "X" });
	assert_eq!(fee_asset(&rel_tx), y, "the batch's own asset pays for its release");
	assert!(rel_tx.output.iter().all(|o| o.asset.explicit() != Some(x)), "nothing of X's pool moves for Y's batch");

	// After the notice: the sweep, its fee from the Y it sweeps.
	advance_mtp(&r, 37 * HOUR).await;
	drive(&r, "the sweep after the notice", 4, |l| common::flow::has(l, "sweep", &token_subject)).await;
	settle(&r).await;
	let sw = of_kind(&r, "sweep").await.remove(0);
	let sw_tx: Transaction = elements::encode::deserialize(&sw.tx).unwrap();
	println!("the sweep {} of the batch of Y: {} input(s), its fee in {}", txid(&sw), sw_tx.input.len(),
		if fee_asset(&sw_tx) == y { "Y" } else { "X" });
	assert_eq!(fee_asset(&sw_tx), y);
	assert!(sw_tx.output.iter().all(|o| o.asset.explicit() != Some(x)), "nothing of X's pool moves for Y's batch");
}
