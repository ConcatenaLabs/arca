//! Refreshes as wallets run them, and the watcher driven along the chain,
//! for the watcher's and the offboard's tests.

use std::time::Duration;

use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::{OutPoint, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::{CoinRecord, ExplicitOutput, Forfeit, LeafPolicy, Release, RelativeTime, ValidCoin, ValidLeaf, ValidOrigin};
use server::store::{NurseryState, WatcherTxRow};

use super::client::{auths_json, forfeit_sig, hex, participation_body, random32, unhex, want_leaf, Held};
use super::keys::xonly;
use super::node;
use super::rounds::{created, round_final, status, validate_new_leaf};
use super::running::Running;

/// A coin a wallet holds, with the transactions its bases came from.
#[derive(Clone)]
pub struct Coin {
	pub held: Held,
	pub bases: Vec<Transaction>,
}

impl Coin {
	pub fn valid(&self, r: &Running) -> ValidCoin {
		self.held.record.resolve(&self.bases, &r.policy()).unwrap()
	}
}

/// A coin refreshed: the new coin, its participation, its preimage, the old
/// coin and new leaf as validated, the round and its connector output.
pub struct Refreshed {
	pub new: Coin,
	/// The key of the coin given up.
	pub old_key: Keypair,
	pub id: [u8; 32],
	pub preimage: [u8; 32],
	pub old: ValidCoin,
	pub new_valid: ValidLeaf,
	pub round: Transaction,
	pub connector_vout: u32,
}

/// The forfeit a wallet signs for `old`, given up for `new` in `round`.
pub fn forfeit_for(old: &ValidCoin, new: &ValidLeaf, round: &Transaction, st: &Value) -> Forfeit {
	let c = st["round"]["connector_vout"].as_u64().unwrap() as u32;
	let delay = RelativeTime::from_units(st["refund_delay_units"].as_u64().unwrap() as u16).unwrap();
	let margin: u64 = st["inputs"][0]["margin"].as_str().unwrap().parse().unwrap();
	Forfeit::for_refresh(old.leaf, (old.asset, old.value), old.id, new, round, c, delay, margin).unwrap()
}

/// The coin `key` holds at the server, by `leaf_data`.
pub fn held_by(r: &Running, key: &Keypair, nonce: [u8; 32], id: arca_covenant::LeafId) -> Held {
	let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", key, &r.chain)})).ok();
	let entry = ld["leaves"].as_array().unwrap().iter().find(|l| l["leaf_id"] == json!(id.to_string())).unwrap().clone();
	Held { key: *key, nonce, id, record: CoinRecord::from_bytes(&unhex(entry["record"].as_str().unwrap())).unwrap() }
}

/// Each coin given up for a new leaf of its whole value under the key beside
/// it, each in its own participation, in one round, made final; every owner
/// validates its new leaf from the published tree and hands over its
/// forfeit.
pub async fn refresh(r: &mut Running, coins: &[(&Coin, &Keypair)]) -> Vec<Refreshed> {
	let mut ids = vec![];
	for (coin, key) in coins {
		let v = coin.valid(r);
		let (w, nonce) = want_leaf(key, v.asset, v.value);
		let (body, id) = participation_body(&[&coin.held], &[w], &[], None, xonly(&r.s), r.chain);
		assert_eq!(r.http.post("submit_participation", &body).ok()["state"], "pending");
		ids.push((id, nonce));
	}
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(r, &built.tx.txid()).await;
	let mut out = vec![];
	for ((coin, key), (id, nonce)) in coins.iter().zip(ids) {
		let st = status(r, &id);
		let (new_valid, record, round) = validate_new_leaf(r, &id, 0, key, &nonce);
		let old = coin.valid(r);
		let f = forfeit_for(&old, &new_valid, &round, &st);
		let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&id),
			"forfeits": [{"leaf_id": coin.held.id.to_string(), "signature": forfeit_sig(&f, &coin.held.key)}],
			"leaves": [auths_json(&new_valid, key, created(&record))]})).ok();
		assert_eq!(done["state"], "released", "{}", done);
		let preimage: [u8; 32] = unhex(done["preimage"].as_str().unwrap()).try_into().unwrap();
		let held = held_by(r, key, nonce, new_valid.leaf_id);
		out.push(Refreshed {
			new: Coin { held, bases: vec![round.clone()] }, old_key: coin.held.key, id, preimage, old, new_valid, connector_vout: st["round"]["connector_vout"].as_u64().unwrap() as u32,
			round,
		});
	}
	out
}

/// The owner of a refreshed batch leaf releases the lowest node above it.
pub fn release(r: &Running, x: &Refreshed) {
	let old = match &x.old.origin {
		ValidOrigin::Leaf { valid, .. } => valid,
		_ => panic!("only a batch leaf has a lowest node"),
	};
	let rel = Release::for_refresh(old, &x.new_valid, &x.round, x.connector_vout).unwrap();
	let sig = sign_digest(&x.old_key, &rel.message().digest, &random32());
	let a = r.http.post("release_leaves", &json!({"participation_id": hex(&x.id), "releases": [{
		"leaf_id": x.old.id.to_string(), "connector_asset": rel.connector.to_string(), "signature": hex(sig.as_ref())}]})).ok();
	assert_eq!(a["released"].as_array().unwrap().len(), 1, "{}", a);
}

/// The watcher's transactions, oldest first.
pub async fn log(r: &Running) -> Vec<WatcherTxRow> {
	r.server.store.watcher_log().await.unwrap()
}

/// The watcher's transactions of `kind`.
pub async fn of_kind(r: &Running, kind: &str) -> Vec<WatcherTxRow> {
	log(r).await.into_iter().filter(|w| w.kind == kind).collect()
}

pub fn txid(w: &WatcherTxRow) -> Txid {
	Txid::from_byte_array(w.txid)
}

/// Runs the watcher, then a block, until `done` holds, for at most `rounds`
/// blocks; prints what the watcher published. Returns the blocks it took.
pub async fn drive<F: FnMut(&[WatcherTxRow]) -> bool>(r: &Running, what: &str, rounds: usize, mut done: F) -> usize {
	let mut seen = log(r).await.len();
	for n in 0..rounds {
		r.synced().await;
		r.server.watcher.pass().await.unwrap();
		let now = log(r).await;
		for w in &now[seen..] {
			let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
			println!("  watcher: {} {} ({} vB): {}", w.kind, txid(w), tx.vsize(), w.detail);
		}
		seen = now.len();
		if done(&now) {
			println!("{}: done after {} block(s)", what, n);
			return n;
		}
		r.produce().await;
	}
	panic!("{}: not done after {} blocks; the watcher's log: {:?}", what, rounds,
		log(r).await.iter().map(|w| (w.kind.clone(), w.state)).collect::<Vec<_>>());
}

/// The watcher's claim, in `log`, of the forfeit it published for the coin
/// `leaf`: a claim acts for its round, and takes each forfeit as an input.
pub fn claim_of<'a>(log: &'a [WatcherTxRow], leaf: &[u8]) -> Option<&'a WatcherTxRow> {
	let forfeits: Vec<[u8; 32]> = log.iter().filter(|w| w.kind == "forfeit" && w.subject == leaf).map(|w| w.txid).collect();
	log.iter().filter(|w| w.kind == "claim").find(|w| {
		let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
		tx.input.iter().any(|i| i.previous_output.vout == 0 && forfeits.contains(&i.previous_output.txid.to_byte_array()))
	})
}

/// How many of the forfeits in `log` its claims take.
pub fn claimed(log: &[WatcherTxRow]) -> usize {
	let forfeits: std::collections::HashSet<[u8; 32]> = log.iter().filter(|w| w.kind == "forfeit").map(|w| w.txid).collect();
	log.iter().filter(|w| w.kind == "claim").map(|w| {
		let tx: Transaction = elements::encode::deserialize(&w.tx).unwrap();
		tx.input.iter().filter(|i| i.previous_output.vout == 0 && forfeits.contains(&i.previous_output.txid.to_byte_array())).count()
	}).sum()
}

/// Whether the watcher's transaction of `kind` for `subject` is final; for
/// a claim, the claim of the coin `subject`'s forfeit.
pub fn final_of(log: &[WatcherTxRow], kind: &str, subject: &[u8]) -> bool {
	if kind == "claim" {
		return claim_of(log, subject).is_some_and(|w| w.state == NurseryState::Final);
	}
	log.iter().any(|w| w.kind == kind && w.subject == subject && w.state == NurseryState::Final)
}

/// Whether the watcher has published one of `kind` for `subject`; for a
/// claim, the claim of the coin `subject`'s forfeit.
pub fn has(log: &[WatcherTxRow], kind: &str, subject: &[u8]) -> bool {
	if kind == "claim" {
		return claim_of(log, subject).is_some();
	}
	log.iter().any(|w| w.kind == kind && w.subject == subject)
}

/// Produces and buries blocks until the watcher's transactions are final.
pub async fn settle(r: &Running) {
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.server.nursery.pass().await.unwrap();
	tokio::time::sleep(Duration::from_millis(100)).await;
}

/// An exit claim of `leaf` on the chain at `at`, holding `value` of
/// `asset`, signed by `key`, paying to a bare `OP_TRUE`.
pub fn exit_tx(r: &Running, leaf: &LeafPolicy, at: OutPoint, asset: elements::AssetId, value: u64, key: &Keypair) -> Transaction {
	let ks = leaf.exit_tx(at, asset, value, &[ExplicitOutput::new(asset, value - 3_000, node::op_true())], &FeeSource::Reserve).unwrap();
	let sig = sign_digest(key, &ks.sighash(r.chain.genesis_hash()).unwrap(), &random32());
	ks.finish(vec![sig.as_ref().to_vec()]).tx
}

/// The node's verdict on `tx`: `Ok` if it would take it, else its reason.
pub fn verdict(r: &Running, tx: &Transaction) -> Result<(), String> {
	let a = r.rt.client().test_mempool_accept(&[tx]).unwrap().remove(0);
	if a.allowed { Ok(()) } else { Err(a.reject_reason.unwrap_or_default()) }
}
