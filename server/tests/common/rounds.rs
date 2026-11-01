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
	start_tuned(true).await
}

/// [`start`] with the operator's unroll at release off, for a test that
/// follows the sweep of a live coin.
pub async fn start_sweeping() -> Running {
	start_tuned(false).await
}

async fn start_tuned(unroll_at_release: bool) -> Running {
	let mut r = Running::start_with(|c, y| {
		c.assets.push(AssetSection::new(y, MIN_LEAF));
		c.watcher.unroll_at_release = unroll_at_release;
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

/// Waits until the server calls the round `round_txid` final. A round held
/// unbroadcast for its forfeits (one holding a batch without a sweep) first
/// has them handed over for every participation the tests made
/// ([`hand_over_held`]), then goes out and is mined and buried.
pub async fn round_final(r: &Running, round_txid: &Txid) {
	if send_held(r, round_txid).await {
		r.produce().await;
		r.bury().await;
	}
	round_state(r, round_txid, RoundState::Final).await
}

/// When the round `round_txid` is held unbroadcast for its forfeits, hands
/// them over ([`hand_over_held`]) and runs a pass over the rounds, which
/// broadcasts it. Returns whether it was held.
pub async fn send_held(r: &Running, round_txid: &Txid) -> bool {
	let row = r.server.store.round_by_txid(&round_txid.to_byte_array()).await.unwrap();
	if !row.as_ref().is_some_and(|x| x.state == RoundState::Built) {
		return false;
	}
	let n = hand_over_held(r, round_txid).await;
	r.server.rounds.pass().await.unwrap();
	println!("round {} held for its forfeits: {} participation(s) handed theirs over before it went out", round_txid, n);
	true
}

/// Hands over, for every participation the tests made that is issued in
/// the round `round_txid` (built, held unbroadcast), its forfeits as a
/// wallet hands them over: each new leaf rebuilt from the published tree and
/// validated against the transaction the status serves, each coin's forfeit
/// signed against it, the new leaves' unroll authorisations. Returns how
/// many were handed over.
pub async fn hand_over_held(r: &Running, round_txid: &Txid) -> usize {
	let row = r.server.store.round_by_txid(&round_txid.to_byte_array()).await.unwrap().expect("the round");
	let mut n = 0;
	for id in r.server.store.round_participations(row.round_id).await.unwrap() {
		let Some(m) = super::client::made(&id) else { continue };
		if m.coins.is_empty() {
			continue;
		}
		hand_over(r, &id, &m).await;
		n += 1;
	}
	n
}

/// [`hand_over_held`] for one participation `id`, made of `m`.
pub async fn hand_over(r: &Running, id: &[u8; 32], m: &super::client::Made) -> Value {
	use super::client::{auths_json, forfeit_sig, hex, unhex};
	let st = status(r, id);
	let round: Transaction = elements::encode::deserialize(&unhex(st["round"]["tx"].as_str().unwrap_or_else(|| panic!("the held round's transaction: {}", st)))).unwrap();
	assert_eq!(round.txid().to_string(), st["round"]["txid"].as_str().unwrap());
	let mut news = vec![];
	let mut acc_news = vec![];
	let mut leaves = vec![];
	for (j, l) in m.leaves.iter().enumerate() {
		let Some((owner, nonce)) = l else { continue };
		let o = &st["outputs"][j];
		let published = r.http.post("tree", &json!({"txid": st["round"]["txid"], "vout": o["batch_vout"]})).ok();
		let index = o["leaf_index"].as_u64().unwrap() as usize;
		match super::client::rebuild_batch(&published) {
			arca_covenant::Batch::Tree(tree) => {
				let record = tree.record(index);
				let valid = record.validate(&round, &accept_policy(r), owner, nonce).unwrap();
				if let Some(k) = super::client::key_of(owner) {
					leaves.push(auths_json(&valid, &k, created(&record)));
				}
				news.push(valid);
			},
			// A leaf of an accumulator batch: its one exit authorisation.
			arca_covenant::Batch::Accumulator(acc) => {
				let valid = acc.record(index).validate(&round, &accept_policy(r), owner, nonce).unwrap();
				if let Some(k) = super::client::key_of(owner) {
					leaves.push(super::client::exit_auth_json(&valid, &k, super::client::two_hours_ago()));
				}
				acc_news.push(valid);
			},
		}
	}
	let c = st["round"]["connector_vout"].as_u64().unwrap() as u32;
	let delay = arca_covenant::RelativeTime::from_units(st["refund_delay_units"].as_u64().unwrap() as u16).unwrap();
	let mut forfeits = vec![];
	for h in &m.coins {
		let mut bases = vec![];
		server::coins::bases(&r.server.store, &h.record, &mut bases).await.unwrap();
		let old = h.record.resolve(&bases, &r.policy()).unwrap();
		let input = st["inputs"].as_array().unwrap().iter().find(|i| i["leaf_id"] == json!(h.id.to_string())).unwrap();
		let margin: u64 = input["margin"].as_str().unwrap().parse().unwrap();
		// A participation with no leaf of its own (a distribution's payer)
		// signs against the unlock hash and connector its status names.
		let f = match (news.first(), acc_news.first()) {
			(Some(new), _) => arca_covenant::Forfeit::for_refresh(old.leaf, (old.asset, old.value), old.id, new, &round, c, delay, margin).unwrap(),
			(None, Some(new)) => new.forfeit_for(old.leaf, (old.asset, old.value), old.id, &round, c, delay, margin).unwrap(),
			(None, None) => {
				let unlock: [u8; 32] = unhex(st["unlock_hash"].as_str().unwrap()).try_into().unwrap();
				arca_covenant::Forfeit::new(old.leaf, (old.asset, old.value), old.id, unlock, arca_covenant::connector_asset(round.txid(), c),
					delay, margin).unwrap()
			},
		};
		forfeits.push(json!({"leaf_id": h.id.to_string(), "signature": forfeit_sig(&f, &h.key)}));
	}
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(id), "forfeits": forfeits, "leaves": leaves})).ok();
	assert!(done.get("preimage").is_none(), "no preimage before the round is broadcast: {}", done);
	done
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

/// Moves the chain's median time at least `seconds` on: the node's clock set
/// ahead, then enough blocks for the median of the last eleven to follow.
pub async fn advance_mtp(r: &Running, seconds: u32) {
	let start = mtp(r).to_consensus_u32();
	let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
	let mock = now.max(start as u64) + seconds as u64 + 60;
	let _: Value = r.rt.client().call("setmocktime", &[json!(mock)]).unwrap();
	for _ in 0..12 {
		r.produce().await;
	}
	assert!(mtp(r).to_consensus_u32() >= start + seconds, "the median time moved from {} to {}", start, mtp(r).to_consensus_u32());
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

/// The time an owner signs its own unroll authorisations with: an hour
/// before its round's creation, read from the leaf's schedule. An unroll is
/// final only once the tip's median time is past the authorisation's time,
/// and right after a round the median time may not yet be past the round's
/// own; an earlier time is usable at once.
///
/// A batch without a sweep carries no date: its owner signs with an hour
/// before now, as a wallet does.
pub fn created(record: &LeafRecord) -> MedianTime {
	if !record.schedule.expires() {
		let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
		return MedianTime::from_consensus(now - 2 * 3_600).unwrap();
	}
	MedianTime::from_consensus(record.schedule.expiries()[0].to_consensus_u32() - 28 * 86_400 - 3_600).unwrap()
}

/// A transaction spending the server wallet's coin at `coin` (whose output is
/// `txout`) into `outputs` and a fee of `fee` in the coin's asset, signed
/// outside the server with the wallet's mnemonic: the operator's coin spent
/// elsewhere, as when another tool uses the same wallet.
pub fn spend_wallet_coin(coin: elements::OutPoint, txout: &elements::TxOut, outputs: Vec<elements::TxOut>, fee: u64) -> Transaction {
	use elements::bitcoin::bip32::DerivationPath;
	use elements::pset::PartiallySignedTransaction;
	use lwk_common::Signer as _;
	use std::str::FromStr;
	let signer = lwk_signer::SwSigner::new(super::keys::MNEMONIC, false).unwrap();
	let secp = elements::bitcoin::secp256k1::Secp256k1::new();
	// Find the key: the wallet's scripts are m/84'/1'/0'/<chain>/<index>.
	let (path, pk) = (0..2).flat_map(|c| (0..200).map(move |i| (c, i))).find_map(|(c, i)| {
		let path = DerivationPath::from_str(&format!("m/84h/1h/0h/{}/{}", c, i)).unwrap();
		let pk = elements::bitcoin::PublicKey::new(signer.derive_xprv(&path).unwrap().private_key.public_key(&secp));
		(elements::Script::new_v0_wpkh(&elements::WPubkeyHash::hash(&pk.to_bytes())) == txout.script_pubkey).then_some((path, pk))
	}).expect("a key of the wallet's");
	let asset = txout.asset.explicit().unwrap();
	let value = txout.value.explicit().unwrap();
	let spent: u64 = outputs.iter().map(|o| o.value.explicit().unwrap()).sum();
	let mut output = outputs;
	output.push(sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(asset, value - spent - fee), super::node::op_true()));
	output.push(sequentia_ext::fee_txout(sequentia_ext::AssetAmount::new(asset, fee)));
	let mut tx = Transaction {
		version: 2, lock_time: elements::LockTime::ZERO,
		input: vec![elements::TxIn { previous_output: coin, sequence: elements::Sequence::MAX, ..Default::default() }],
		output,
	};
	let mut pset = PartiallySignedTransaction::from_tx(tx.clone());
	pset.inputs_mut()[0].witness_utxo = Some(txout.clone());
	pset.inputs_mut()[0].bip32_derivation.insert(pk, (signer.fingerprint(), path));
	assert_eq!(signer.sign(&mut pset).unwrap(), 1);
	let sig = pset.inputs()[0].partial_sigs.get(&pk).unwrap().clone();
	tx.input[0].witness.script_witness = vec![sig, pk.to_bytes()];
	tx
}

/// Moves the median time past participation `id`'s forfeit deadline, the
/// later of a day after its round was found final and its coins' exit
/// deadline, by ten minutes, and runs a pass over the rounds.
#[allow(dead_code)]
pub async fn past_forfeit_deadline(r: &Running, id: &[u8; 32]) {
	let p = r.server.store.participation(id).await.unwrap().expect("a participation");
	let round = r.server.store.round(p.round_id.expect("in a round")).await.unwrap().expect("its round");
	let final_at = round.final_mtp.expect("its round is final");
	let deadline = r.server.rounds.exit_deadline_of(id).await.unwrap().unwrap_or(0).max(final_at + server::params::Params::FORFEIT_DEADLINE);
	let now = mtp(r).to_consensus_u32();
	if deadline + 600 > now {
		advance_mtp(r, deadline + 600 - now).await;
	}
	r.synced().await;
	r.server.rounds.pass().await.unwrap();
}
