//! What the round tests share: a server serving X (listed for fees) and Y
//! (not listed), its wallet funded and final; credited boards; a round
//! followed to final; a wallet's policies; and a new leaf validated from its
//! published tree alone.

use std::time::{Duration, Instant};

use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::{CoinRecord, LeafRecord, MedianTime, ValidLeaf, WalletPolicy};
use server::server::AssetSection;
use server::store::RoundState;

use super::client::{rebuild, Held};
use super::keys::xonly;
use super::running::{Running, MIN_LEAF};

pub const VALUE: u64 = 1_000_000;

/// A server serving X and Y, its wallet paid two coins of X and one of Y,
/// all final.
pub async fn start() -> Running {
	let mut r = Running::start_with(|c, y| {
		c.assets.push(AssetSection { asset: y.to_string(), min_leaf: MIN_LEAF.to_string() });
	}).await;
	let (x, y) = (r.x, r.y);
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(y, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r
}

/// A credited board for `owner` in `asset`, held as a coin, and its
/// transaction.
pub async fn credited_board(r: &mut Running, owner: &Keypair, asset: AssetId) -> (Held, Transaction) {
	let (record, tx, _) = r.board_in(owner, asset, VALUE);
	r.produce().await;
	r.bury().await;
	let id = record.leaf_id();
	let http = r.http.clone();
	r.wait("the board to be credited", || http.board_status(&id).json["state"] == "credited").await;
	(Held { key: *owner, nonce: record.owner_nonce, id, record: CoinRecord::Board(record) }, tx)
}

/// Waits until the server calls the round `round_txid` final.
pub async fn round_final(r: &Running, round_txid: &Txid) {
	round_state(r, round_txid, RoundState::Final).await
}

/// Waits until the server has the round `round_txid` in `state`.
pub async fn round_state(r: &Running, round_txid: &Txid, state: RoundState) {
	let store = r.server.store.clone();
	let t = round_txid.to_byte_array();
	let start = Instant::now();
	loop {
		r.server.rounds.pass().await.unwrap();
		if store.round_by_txid(&t).await.unwrap().map(|x| x.state) == Some(state) {
			return;
		}
		assert!(start.elapsed() < Duration::from_secs(60), "the round did not become {:?}", state);
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
}

/// The tip's median time.
pub fn mtp(r: &Running) -> MedianTime {
	MedianTime::from_consensus(r.rt.client().blockchain_info().unwrap().median_time as u32).unwrap()
}

/// A wallet's acceptance policy at the chain's tip.
pub fn accept_policy(r: &Running) -> WalletPolicy {
	WalletPolicy::new(r.chain, xonly(&r.s), mtp(r))
}

/// The status of participation `id`.
pub fn status(r: &Running, id: &[u8; 32]) -> Value {
	r.http.post("participation_status", &json!({"participation_id": super::client::hex(id)})).ok()
}

/// A new leaf of a participation, validated by its owner from the published
/// tree alone: output `output` of the participation `id`, owned by `key`
/// under `nonce`. Returns the valid leaf, its record and the round.
pub fn validate_new_leaf(r: &Running, id: &[u8; 32], output: usize, key: &Keypair, nonce: &[u8; 32])
	-> (ValidLeaf, LeafRecord, Transaction)
{
	let st = status(r, id);
	let o = &st["outputs"][output];
	let vout = o["batch_vout"].as_u64().unwrap() as u32;
	let index = o["leaf_index"].as_u64().unwrap() as usize;
	let txid = st["round"]["txid"].as_str().unwrap().to_string();
	let published = r.http.post("tree", &json!({"txid": txid, "vout": vout})).ok();
	let tree = rebuild(&published);
	let round = r.rt.client().raw_transaction(&super::client::txid(&txid)).unwrap();
	let record = tree.record(index);
	let valid = record.validate(&round, &accept_policy(r), &xonly(key), nonce).unwrap();
	assert_eq!(valid.leaf_id.to_string(), o["leaf_id"].as_str().unwrap());
	(valid, record, round)
}

/// The round's creation time, from a leaf's schedule: the time an owner signs
/// its own unroll authorisations with.
pub fn created(record: &LeafRecord) -> MedianTime {
	MedianTime::from_consensus(record.schedule.expiries()[0].to_consensus_u32() - 28 * 86_400).unwrap()
}
