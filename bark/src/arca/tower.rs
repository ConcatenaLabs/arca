//! Watchtowers: a coin nobody refreshes is taken on the chain under its
//! owner's key before its batch can be swept.
//!
//! A leaf of a batch that its holder neither refreshes nor takes home is
//! swept by the operator once its batch is released and the notice `W` has
//! run. Anyone who holds the coin's record and its owner's unroll
//! authorisations can bring it on the chain first, where it is its owner's
//! alone: the unroll pins every child output and the entry's unlock pins the
//! leaf, so whoever broadcasts them chooses nothing but the fee. A wallet
//! therefore deposits, for every coin it holds that rests on a batch, its
//! record with timed authorisations, with each watchtower it names; the coin
//! is then safe while any one of them acts.
//!
//! **The holder's side** ([`Wallet::progress_deposits`], at every `sync`).
//! For each live coin resting on a batch, and each coin paid to it out of
//! round, the wallet builds one deposit: the
//! coin record, with the authorisations of each batch leaf of its own in it
//! signed again for a time an hour before that batch's first expiry
//! ([`DEPOSIT_LEAD`]), so no one can unroll it before the batch could be
//! released, and the transactions the coin rests on. It sends the deposit to
//! each watchtower once, and again to a watchtower added later. A coin that
//! is no longer the wallet's (given up in a round that is final, spent,
//! exited, lost) has its deposit withdrawn: the coin's owner key signs
//! [`withdraw_digest`] over the deposit's id, so the withdrawal removes that
//! deposit and nothing else. The watchtowers are a setting of the wallet's
//! ([`Wallet::set_watchtowers`]); while none is set, the wallet uses those
//! the operator's `info` lists under `watchtowers`.
//!
//! **Sealed.** A deposit is sealed ([`seal`]), so a watchtower learns
//! nothing of the coin until it has to act, as a Lightning watchtower learns
//! nothing until a breach. Its triggers ([`triggers`]) are what on the chain
//! calls for an answer: each batch's release (its token at `R`, the bytes
//! `"R" ‖ R's script ‖ token`) and, for a coin paid out of round, each leaf
//! and checkpoint it descends from (`"O" ‖ script`). The payload
//! (`{"record", "bases"}`, its length as 4 bytes little-endian first, padded
//! with zeros to a multiple of [`BLOB_PAD`]) is sealed with
//! ChaCha20-Poly1305 under a random content key; the content key is sealed
//! under each trigger's key, `SHA256(K ‖ K ‖ genesis ‖ trigger ‖ salt)`,
//! `K = SHA256("Arca/watchtower-key")`, and filed under the trigger's hint,
//! `SHA256(H ‖ H ‖ genesis ‖ trigger)`, `H = SHA256("Arca/watchtower-hint")`.
//! Every key seals one message, so the nonce is zero. The hints are padded
//! with random ones to a multiple of [`HINTS_PAD`] and sorted. A watchtower
//! hashes the two possible triggers of every output in each new block and
//! in the mempool and looks the hints up: a match gives it the trigger, the
//! trigger the key, the key the content key and the payload. A release's
//! trigger can be guessed by whoever follows the operator's batches, so a
//! deposit opened by it is private only against those who do not; a
//! lineage script cannot be guessed before it appears. A sealed deposit is
//! withdrawn with a key derived from the coin's key and its salt
//! ([`withdraw_key`]), so it names no key of the coin; its id is
//! `SHA256(withdrawal key ‖ salt ‖ blob)` ([`sealed_id`]). A watchtower
//! still takes a deposit in the clear (`{"genesis_hash", "record",
//! "bases"}`).
//!
//! **The watchtower's side.** A watchtower is a wallet of its own (its
//! mnemonic holds the coins it pays fees with) that takes deposits
//! ([`Wallet::tower_deposit`]) and withdrawals ([`Wallet::tower_withdraw`]),
//! and passes over them ([`Wallet::tower_pass`]). A pass leaves a coin alone
//! until a batch it rests on is released (the batch's token at `R`, in a
//! block or the mempool) or, for a coin paid out of round, until a sender
//! up its lineage takes an earlier coin home (a leaf or checkpoint the coin
//! descends from in a block or the mempool, which only the coin's checkpoint
//! and reassignment answer, within that leaf's exit delay); then it builds
//! whatever is still missing of the coin's path, from the lowest output the
//! chain holds unspent, exactly as an exit does, and broadcasts it. Each transaction pays its fee from the
//! reserve the output it spends holds for it, when the node accepts the
//! batch's asset for fees and the reserve covers the floor; otherwise from a
//! coin of the watchtower's own. Coins on one branch share its nodes: the
//! second finds them built and adds only its own part. Nothing a pass does
//! needs the operator, so a watchtower acts while the operator is down.
//!
//! A deposit cannot move a coin anywhere else: its signatures authorise the
//! unroll of the coin's own nodes into their pinned children, its preimage
//! opens the entry into the coin's own leaf, and the pairs a coin paid out of
//! round carries spend only into the outputs they commit to. Once on the
//! chain, the leaf is spent only by its owner's exit, or by owner and
//! operator together. A deposit left behind for a coin its holder gave up
//! brings only that old coin on the chain, where the operator answers it with
//! the forfeit the holder signed (see the server's watcher), and the holder's
//! new coin is untouched.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, OutPoint, Transaction};
use serde_json::{json, Value};

use arca_covenant::sign::verify_digest;
use arca_covenant::{Chain, ClockSchedule, CoinRecord, MedianTime, RelativeTime, ValidOrigin, WalletPolicy};

use super::chain::{hex, unhex, unhex32};
use super::client::ServerClient;
use super::exit::{Here, Payer};
use super::round::NewValid;
use super::wallet::{sign, Wallet};
use super::Error;

/// Where the wallet keeps the watchtowers it names: a JSON array of base
/// URLs. Absent, the wallet uses those the operator's `info` lists and the
/// program's defaults.
pub const WATCHTOWERS_META: &str = "watchtowers";

/// Where the wallet keeps the watchtowers the program that runs it names by
/// default ([`Wallet::set_default_watchtowers`]): a JSON array of base URLs,
/// used beside the operator's while the user names none. A wallet program
/// lists here watchtowers run by others than the operator, so its users do
/// not rely on the operator alone to name who watches for them.
pub const DEFAULT_WATCHTOWERS_META: &str = "watchtowers_default";

/// The tag of the digest a coin's owner key signs to withdraw its deposit.
pub const WITHDRAW_TAG: &[u8] = b"Arca/watchtower-withdraw";

/// How long before its batch's first expiry the authorisations a deposit
/// carries for the wallet's own batch leaf become usable: an hour, so the
/// coin can be unrolled from the moment its batch can be released (at that
/// expiry, by the release's own lock time) and not before.
pub const DEPOSIT_LEAD: u32 = 3_600;

/// The largest deposit a watchtower takes, in bytes of its JSON body.
pub const MAX_DEPOSIT_BYTES: usize = 512 * 1024;

/// The most deposits one watchtower holds.
pub const MAX_DEPOSITS: u64 = 100_000;

/// The coin states whose deposit is withdrawn: the coin is no longer the
/// wallet's off the chain.
const DONE: &[&str] = &["spent", "exited", "lost"];

/// A deposit's id: the SHA256 of its coin record's binary form.
pub fn deposit_id(record: &[u8]) -> [u8; 32] {
	sha256::Hash::hash(record).to_byte_array()
}

/// What a coin's owner key signs to withdraw its deposit `deposit` from a
/// watchtower: `SHA256(T ‖ T ‖ genesis ‖ owner ‖ deposit)`,
/// `T = SHA256("Arca/watchtower-withdraw")`.
pub fn withdraw_digest(chain: &Chain, owner: &XOnlyPublicKey, deposit: &[u8; 32]) -> [u8; 32] {
	let t = sha256::Hash::hash(WITHDRAW_TAG);
	let mut e = sha256::Hash::engine();
	e.input(t.as_byte_array());
	e.input(t.as_byte_array());
	e.input(&chain.genesis_bytes());
	e.input(&owner.serialize());
	e.input(deposit);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// The clock schedules of every batch `record` rests on.
fn schedules(record: &CoinRecord, out: &mut Vec<ClockSchedule>) {
	match record {
		CoinRecord::Leaf { record, .. } => out.push(record.schedule.clone()),
		CoinRecord::Accumulator { record, .. } => out.push(record.schedule.clone()),
		CoinRecord::Board(_) => {},
		CoinRecord::Transfer(_) | CoinRecord::Fill(_) => record.parents().into_iter().for_each(|p| schedules(p, out)),
	}
}

/// Whether `record` is a coin paid out of round (a transfer or a fill): one
/// with a lineage, whose senders can take an earlier coin home on the chain.
fn has_lineage(record: &CoinRecord) -> bool {
	matches!(record, CoinRecord::Transfer(_) | CoinRecord::Fill(_))
}

/// The latest time of any authorisation `record` carries.
fn latest_auth(record: &CoinRecord) -> u32 {
	match record {
		CoinRecord::Leaf { auths, .. } => auths.iter().map(|(_, t)| t.to_consensus_u32()).max().unwrap_or(0),
		CoinRecord::Accumulator { auth, .. } => auth.1.to_consensus_u32(),
		CoinRecord::Board(_) => 0,
		CoinRecord::Transfer(_) | CoinRecord::Fill(_) => record.parents().into_iter().map(latest_auth).max().unwrap_or(0),
	}
}

/// The tags of a sealed deposit's hashes: a hint the watchtower looks up, the
/// key a hint's wrap is sealed under, and the wallet's withdrawal key.
pub const HINT_TAG: &[u8] = b"Arca/watchtower-hint";
pub const KEY_TAG: &[u8] = b"Arca/watchtower-key";
pub const WITHDRAW_KEY_TAG: &[u8] = b"Arca/watchtower-withdraw-key";

/// A sealed deposit carries its hints in groups of this many, the rest
/// random, so their number says little of the coin's lineage.
pub const HINTS_PAD: usize = 8;

/// The most hints one sealed deposit carries.
pub const MAX_HINTS: usize = 64;

/// A sealed deposit's plaintext is padded to a multiple of this many bytes.
pub const BLOB_PAD: usize = 1_024;

/// The most blocks a pass reads back after a rollback of the last block it
/// read, or at its first look.
const SCAN_BACK: u64 = 100;

/// The meta key of the last block the watchtower read for sealed deposits:
/// `height:hash`.
const SCANNED_META: &str = "tower_scanned";

fn tagged(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
	let t = sha256::Hash::hash(tag);
	let mut e = sha256::Hash::engine();
	e.input(t.as_byte_array());
	e.input(t.as_byte_array());
	for p in parts {
		e.input(p);
	}
	sha256::Hash::from_engine(e).to_byte_array()
}

/// What on the chain opens a sealed deposit of `record`: the release of
/// each batch it rests on (its token at that batch's `R`, `"R" ‖ script ‖
/// token`), and, for a coin paid out of round, each leaf and checkpoint it
/// descends from (`"O" ‖ script`). Each appears on the chain only when the
/// watchtower has something to answer, and a script of the lineage cannot
/// be guessed before: it commits to keys and salts nobody else holds.
pub fn triggers(record: &CoinRecord, coin: &arca_covenant::ValidCoin) -> Vec<Vec<u8>> {
	let mut sch = vec![];
	schedules(record, &mut sch);
	let mut out: Vec<Vec<u8>> = sch.iter().map(|s| release_trigger(&s.r().script_pubkey(), &s.token)).collect();
	if has_lineage(record) {
		out.extend(coin.lineage().iter().map(|o| output_trigger(&o.output.script_pubkey)));
	}
	out.sort();
	out.dedup();
	out
}

fn release_trigger(script: &elements::Script, token: &AssetId) -> Vec<u8> {
	[b"R".as_slice(), script.as_bytes(), &token.into_inner().to_byte_array()[..]].concat()
}

fn output_trigger(script: &elements::Script) -> Vec<u8> {
	[b"O".as_slice(), script.as_bytes()].concat()
}

/// The hint under which a trigger is looked up: the same for every deposit
/// it opens, and no help in guessing the trigger.
pub fn hint_of(chain: &Chain, trigger: &[u8]) -> [u8; 32] {
	tagged(HINT_TAG, &[&chain.genesis_bytes(), trigger])
}

fn wrap_key(chain: &Chain, trigger: &[u8], salt: &[u8; 32]) -> [u8; 32] {
	tagged(KEY_TAG, &[&chain.genesis_bytes(), trigger, salt])
}

/// The key a wallet withdraws a sealed deposit with: derived from the
/// coin's key and the deposit's salt, so it names no key of the coin.
pub fn withdraw_key(coin: &elements::secp256k1_zkp::Keypair, salt: &[u8; 32]) -> Result<elements::secp256k1_zkp::Keypair, Error> {
	let sk = tagged(WITHDRAW_KEY_TAG, &[&coin.secret_bytes(), salt]);
	elements::secp256k1_zkp::Keypair::from_seckey_slice(elements::secp256k1_zkp::SECP256K1, &sk).map_err(|e| Error::Keys(e.to_string()))
}

fn aead(key: &[u8; 32], data: &[u8], open: bool) -> Result<Vec<u8>, Error> {
	use chacha20poly1305::aead::{Aead, KeyInit};
	let c = chacha20poly1305::ChaCha20Poly1305::new(key.into());
	// Every key here seals one message (a fresh content key, or a key bound
	// to a fresh salt), so a zero nonce is never used twice under one key.
	let nonce = chacha20poly1305::Nonce::default();
	if open {
		c.decrypt(&nonce, data).map_err(|_| Error::Refused("bad_seal: the deposit does not open under its trigger".into()))
	} else {
		c.encrypt(&nonce, data).map_err(|_| Error::Refused("bad_seal: the deposit could not be sealed".into()))
	}
}

/// A sealed deposit's id: `SHA256(withdraw ‖ salt ‖ blob)`.
pub fn sealed_id(withdraw: &XOnlyPublicKey, salt: &[u8; 32], blob: &[u8]) -> [u8; 32] {
	let mut e = sha256::Hash::engine();
	e.input(&withdraw.serialize());
	e.input(salt);
	e.input(blob);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// Seals `payload` (a deposit's `{"record", "bases"}`) so that it opens only
/// once one of `triggers` appears on the chain, as a Lightning watchtower's
/// blob opens only with the breach's txid: the payload, padded, under a
/// random content key; that key under each trigger's key; each trigger
/// named only by its hint. The hints are padded with random ones and sorted.
/// Answers the body's `sealed` object and the deposit's id.
pub fn seal(chain: &Chain, payload: &[u8], triggers: &[Vec<u8>], withdraw: &XOnlyPublicKey, salt: &[u8; 32]) -> Result<(Value, [u8; 32]), Error> {
	if triggers.is_empty() || triggers.len() > MAX_HINTS {
		return Err(Error::Refused(format!("the coin has {} triggers; a sealed deposit takes 1 to {}", triggers.len(), MAX_HINTS)));
	}
	let content = super::random32();
	let mut plain = (payload.len() as u32).to_le_bytes().to_vec();
	plain.extend_from_slice(payload);
	plain.resize(plain.len().div_ceil(BLOB_PAD) * BLOB_PAD, 0);
	let blob = aead(&content, &plain, false)?;
	let mut pairs: Vec<([u8; 32], Vec<u8>)> = vec![];
	for t in triggers {
		pairs.push((hint_of(chain, t), aead(&wrap_key(chain, t, salt), &content, false)?));
	}
	while pairs.len() % HINTS_PAD != 0 && pairs.len() < MAX_HINTS {
		let mut junk = super::random32().to_vec();
		junk.extend_from_slice(&super::random32()[..16]);
		pairs.push((super::random32(), junk));
	}
	pairs.sort();
	let id = sealed_id(withdraw, salt, &blob);
	Ok((json!({"v": 1, "salt": hex(salt), "withdraw": withdraw.to_string(), "hints": pairs.iter().map(|p| hex(&p.0)).collect::<Vec<_>>(),
		"wraps": pairs.iter().map(|p| hex(&p.1)).collect::<Vec<_>>(), "blob": hex(&blob)}), id))
}

/// Opens a sealed deposit `sealed` by `trigger`, seen on the chain, whose
/// hint is at index `k`: the payload it carries.
pub fn open(chain: &Chain, sealed: &Value, trigger: &[u8], k: usize) -> Result<Vec<u8>, Error> {
	let salt = unhex32(sealed["salt"].as_str().unwrap_or(""))?;
	let wrap = unhex(sealed["wraps"][k].as_str().unwrap_or(""))?;
	let content: [u8; 32] = aead(&wrap_key(chain, trigger, &salt), &wrap, true)?.try_into()
		.map_err(|_| Error::Refused("bad_seal: the content key is not 32 bytes".into()))?;
	let plain = aead(&content, &unhex(sealed["blob"].as_str().unwrap_or(""))?, true)?;
	let n = u32::from_le_bytes(plain.get(..4).and_then(|b| b.try_into().ok()).ok_or_else(|| Error::Refused("bad_seal: empty".into()))?) as usize;
	plain.get(4..4 + n).map(<[u8]>::to_vec).ok_or_else(|| Error::Refused("bad_seal: the length runs past the payload".into()))
}

fn txs_of(v: &Value) -> Result<Vec<Transaction>, Error> {
	v.as_array().cloned().unwrap_or_default().iter().map(|t| {
		let raw = unhex(t.as_str().unwrap_or(""))?;
		elements::encode::deserialize(&raw).map_err(|e| Error::Parse(format!("a base transaction: {}", e)))
	}).collect()
}

impl Wallet {
	// -----------------------------------------------------------------------
	// The holder's side
	// -----------------------------------------------------------------------

	/// The watchtowers the wallet deposits with, and where the list comes
	/// from: the wallet's own setting, or the operator's `info` and the
	/// program's defaults.
	pub fn watchtowers(&self) -> Result<Value, Error> {
		let (list, from) = self.tower_list()?;
		Ok(json!({"watchtowers": list, "from": from, "defaults": self.default_towers()?}))
	}

	/// Names the watchtowers the program running the wallet adds to the
	/// operator's by default (each a base URL, as for
	/// [`Self::set_watchtowers`]); an empty list adds none. A user's own
	/// setting still replaces both.
	pub fn set_default_watchtowers(&mut self, urls: &[String]) -> Result<Value, Error> {
		for u in urls {
			ServerClient::new(u)?;
		}
		if urls.is_empty() {
			self.store.delete_meta(DEFAULT_WATCHTOWERS_META)?;
		} else {
			self.store.set_meta(DEFAULT_WATCHTOWERS_META, &json!(urls).to_string())?;
		}
		self.watchtowers()
	}

	fn default_towers(&self) -> Result<Vec<String>, Error> {
		Ok(match self.store.meta(DEFAULT_WATCHTOWERS_META)? {
			Some(v) => serde_json::from_str(&v).map_err(|e| Error::Store(format!("the default watchtowers: {}", e)))?,
			None => vec![],
		})
	}

	/// Names the watchtowers the wallet deposits with (each a base URL,
	/// `https://`, or `http://` to this machine); an empty list deposits with
	/// none. `None` goes back to the operator's list. A deposit already sent
	/// stays with its watchtower until its coin is no longer the wallet's.
	pub fn set_watchtowers(&mut self, urls: Option<&[String]>) -> Result<Value, Error> {
		match urls {
			None => self.store.delete_meta(WATCHTOWERS_META)?,
			Some(list) => {
				for u in list {
					ServerClient::new(u)?;
				}
				self.store.set_meta(WATCHTOWERS_META, &json!(list).to_string())?;
			},
		}
		self.watchtowers()
	}

	fn tower_list(&self) -> Result<(Vec<String>, &'static str), Error> {
		if let Some(v) = self.store.meta(WATCHTOWERS_META)? {
			let list: Vec<String> = serde_json::from_str(&v).map_err(|e| Error::Store(format!("the watchtowers: {}", e)))?;
			return Ok((list, "setting"));
		}
		let info = self.server.info().unwrap_or(Value::Null);
		let mut list: Vec<String> = info["watchtowers"].as_array().cloned().unwrap_or_default().iter()
			.filter_map(|u| u.as_str().map(str::to_string)).filter(|u| ServerClient::new(u).is_ok()).collect();
		let defaults = self.default_towers()?;
		let from = if defaults.is_empty() { "operator" } else { "operator and defaults" };
		for d in defaults {
			if !list.iter().any(|u| u.trim_end_matches('/') == d.trim_end_matches('/')) {
				list.push(d);
			}
		}
		Ok((list, from))
	}

	/// Whether watchtower `url` can hold this wallet's deposits, from its
	/// `info`: it watches this chain, for this wallet's operator (a sealed
	/// deposit cannot be checked when it is taken, so one sent to a
	/// watchtower of another operator would be refused only once it must
	/// act), and takes sealed deposits. `Err` says why not.
	fn tower_usable(&self, url: &str) -> Result<(), String> {
		let info = ServerClient::new(url).and_then(|c| c.get("info")).map_err(|e| format!("its info does not answer: {}", e))?;
		if info["watchtower"] != json!(true) {
			return Err("it is not a watchtower".into());
		}
		if info["genesis_hash"].as_str() != Some(self.genesis.genesis_hash().to_string().as_str()) {
			return Err("it watches another chain".into());
		}
		if info["operator"].as_str() != Some(self.operator.to_string().as_str()) {
			return Err(format!("it watches for another operator ({})", info["operator"].as_str().unwrap_or("none named")));
		}
		if info["sealed"].as_u64().unwrap_or(0) < 1 {
			return Err("it takes no sealed deposit".into());
		}
		Ok(())
	}

	/// The deposit of the coin `row`: its record, with the authorisations of
	/// a batch leaf of the wallet's own signed again for an hour before its
	/// batch's first expiry, and the transactions it rests on. `None` for a
	/// coin that rests on no batch and has no lineage: no sweep takes it, and
	/// no sender up a lineage can take it back.
	fn deposit_of(&self, row: &super::store::CoinRow) -> Result<Option<(CoinRecord, Vec<Transaction>, Vec<Vec<u8>>)>, Error> {
		let record = Self::record_of(row)?;
		let mut sch = vec![];
		schedules(&record, &mut sch);
		if sch.is_empty() && !has_lineage(&record) {
			return Ok(None);
		}
		let bases = self.accepted_bases(&record)?;
		let now = self.now()?;
		let coin = self.resolve(&record, &bases, &self.followed_policy(row.expiry, now)).map_err(|e| Error::Refused(e.to_string()))?;
		let opens = triggers(&record, &coin);
		let at = |s: &ClockSchedule| -> Result<MedianTime, Error> {
			MedianTime::from_consensus(s.expiries()[0].to_consensus_u32().saturating_sub(DEPOSIT_LEAD)).map_err(|e| Error::Node(e.to_string()))
		};
		let record = match (record, &coin.origin) {
			(CoinRecord::Leaf { record, preimage, .. }, ValidOrigin::Leaf { valid, .. }) => {
				let key = self.coin_key(&row.owner_nonce)?;
				let auths = NewValid::Tree(valid.clone()).sign_auths(&key, at(&record.schedule)?);
				CoinRecord::Leaf { record, preimage, auths }
			},
			(CoinRecord::Accumulator { record, preimage, .. }, ValidOrigin::Accumulator { valid, .. }) => {
				let key = self.coin_key(&row.owner_nonce)?;
				let auth = NewValid::Accumulator(valid.clone()).sign_auths(&key, at(&record.schedule)?)[0];
				CoinRecord::Accumulator { record, preimage, auth }
			},
			(r, _) => r,
		};
		Ok(Some((record, bases, opens)))
	}

	/// Every live coin resting on a batch deposited with each watchtower the
	/// wallet names, once; every deposit of a coin no longer the wallet's
	/// withdrawn. What it did, a line a coin and watchtower; a watchtower
	/// that cannot be reached is tried again at the next `sync`.
	pub(crate) fn progress_deposits(&mut self) -> Result<Vec<Value>, Error> {
		let (named, _) = self.tower_list()?;
		let mut out = vec![];
		// Each watchtower's info is read once a sync, and only when a coin
		// has a deposit still to send it; one that cannot hold the wallet's
		// deposits is passed over, saying why.
		let mut towers = vec![];
		if !named.is_empty() {
			let mut wanted = BTreeSet::new();
			for row in self.store.coins_in_states(&["live"])? {
				let sent = self.store.deposit_sent_to(&row.leaf_id)?;
				wanted.extend(named.iter().filter(|t| !sent.contains(t)).cloned());
			}
			for t in named.iter().filter(|t| wanted.contains(*t)) {
				match self.tower_usable(t) {
					Ok(()) => towers.push(t.clone()),
					Err(why) => out.push(json!({"watchtower": t, "passed_over": why})),
				}
			}
		}
		if !towers.is_empty() {
			for row in self.store.coins_in_states(&["live"])? {
				let sent = self.store.deposit_sent_to(&row.leaf_id)?;
				let todo: Vec<&String> = towers.iter().filter(|t| !sent.contains(t)).collect();
				if todo.is_empty() {
					continue;
				}
				let body = match self.store.deposit(&row.leaf_id)? {
					Some((_, b)) => b,
					None => {
						let (record, bases, opens) = match self.deposit_of(&row) {
							Ok(Some(d)) => d,
							Ok(None) => continue,
							Err(e) => {
								out.push(json!({"leaf_id": row.leaf_id, "error": e.to_string()}));
								continue;
							},
						};
						// Sealed: no watchtower reads the coin before one of
						// the events it answers is on the chain.
						let bytes = record.to_bytes().map_err(|e| Error::Refused(e.to_string()))?;
						let payload = json!({"record": hex(&bytes),
							"bases": bases.iter().map(|t| hex(&elements::encode::serialize(t))).collect::<Vec<_>>()}).to_string();
						let salt = super::random32();
						let wkey = withdraw_key(&self.coin_key(&row.owner_nonce)?, &salt)?;
						let (sealed, id) = seal(&self.genesis, payload.as_bytes(), &opens, &wkey.x_only_public_key().0, &salt)?;
						let body = json!({"genesis_hash": self.genesis.genesis_hash().to_string(), "sealed": sealed}).to_string();
						self.store.put_deposit(&row.leaf_id, &hex(&id), &body)?;
						body
					},
				};
				let v: Value = serde_json::from_str(&body).map_err(|e| Error::Store(e.to_string()))?;
				for t in todo {
					match ServerClient::new(t).and_then(|c| c.post("deposit", &v)) {
						Ok(a) => {
							self.store.put_deposit_sent(&row.leaf_id, t)?;
							out.push(json!({"leaf_id": row.leaf_id, "watchtower": t, "deposited": a["deposit"]}));
						},
						Err(e) => out.push(json!({"leaf_id": row.leaf_id, "watchtower": t, "error": e.to_string()})),
					}
				}
			}
		}
		// Withdrawals: every deposit whose coin is no longer the wallet's.
		for (leaf, id) in self.store.deposits()? {
			let row = self.store.coin(&leaf)?;
			if row.as_ref().is_some_and(|r| !DONE.contains(&r.state.as_str())) {
				continue;
			}
			let mut left = 0;
			// A sealed deposit is withdrawn with the key derived for it, a
			// plain one with the coin's own.
			let salt = self.store.deposit(&leaf)?.and_then(|(_, b)| serde_json::from_str::<Value>(&b).ok())
				.and_then(|b| b["sealed"]["salt"].as_str().and_then(|s| unhex32(s).ok()));
			let key = match (&row, salt) {
				(Some(r), Some(salt)) => Some(withdraw_key(&self.coin_key(&r.owner_nonce)?, &salt)?),
				(Some(r), None) => Some(self.coin_key(&r.owner_nonce)?),
				(None, _) => None,
			};
			for t in self.store.deposit_sent_to(&leaf)? {
				let Some(key) = &key else {
					self.store.delete_deposit_sent(&leaf, &t)?;
					continue;
				};
				let owner = key.x_only_public_key().0;
				let did = unhex32(&id)?;
				let sig = sign(key, &withdraw_digest(&self.genesis, &owner, &did));
				let body = json!({"deposit": id, "owner": owner.to_string(), "signature": hex(sig.as_ref())});
				match ServerClient::new(&t).and_then(|c| c.post("withdraw", &body)) {
					Ok(_) | Err(Error::Server { .. }) => {
						self.store.delete_deposit_sent(&leaf, &t)?;
						out.push(json!({"leaf_id": leaf, "watchtower": t, "withdrawn": id}));
					},
					Err(e) => {
						left += 1;
						out.push(json!({"leaf_id": leaf, "watchtower": t, "error": e.to_string()}));
					},
				}
			}
			if left == 0 {
				self.store.delete_deposit(&leaf)?;
			}
		}
		Ok(out)
	}

	// -----------------------------------------------------------------------
	// The watchtower's side
	// -----------------------------------------------------------------------

	/// The policy a watchtower checks a deposit under: the wallet's receipt
	/// policy with no horizon and any exit delay, as of the latest
	/// authorisation time the record carries or now, whichever is later, and
	/// never past the coin's first expiry, so a deposit made long before its
	/// batch expires is checked as it will be used.
	fn tower_policy(&self, record: &CoinRecord) -> Result<WalletPolicy, Error> {
		let mut sch = vec![];
		schedules(record, &mut sch);
		let first = sch.iter().map(|s| s.expiries()[0].to_consensus_u32()).min().unwrap_or(u32::MAX);
		let now = self.now()?.to_consensus_u32();
		let as_of = now.max(latest_auth(record)).min(first);
		let as_of = MedianTime::from_consensus(as_of).map_err(|e| Error::Node(e.to_string()))?;
		Ok(WalletPolicy {
			horizon: 0,
			min_exit_delay: RelativeTime::from_units(1).expect("one unit"),
			max_exit_delay: RelativeTime::from_units(u16::MAX).expect("the most units"),
			..self.receipt_policy(as_of)
		})
	}

	/// The coin a deposit holds, checked: every check a receiver runs, but
	/// whose coin it is, against the transactions the deposit names.
	fn tower_coin(&self, record: &CoinRecord, bases: &[Transaction]) -> Result<arca_covenant::ValidCoin, Error> {
		let policy = self.tower_policy(record)?;
		self.resolve(record, bases, &policy).map_err(|e| Error::Refused(format!("the deposit's coin does not check: {}", e)))
	}

	/// Takes a deposit (`{"genesis_hash", "record", "bases"}`): a coin
	/// record, checked as a receiver checks one, resting on a batch, and the
	/// transactions it rests on. A later deposit for the same owner key
	/// replaces the earlier one. Answers its id.
	pub fn tower_deposit(&mut self, body: &Value) -> Result<Value, Error> {
		if body["genesis_hash"].as_str() != Some(self.genesis.genesis_hash().to_string().as_str()) {
			return Err(Error::Refused("wrong_chain: the deposit is for another chain".into()));
		}
		if !body["sealed"].is_null() {
			return self.tower_deposit_sealed(&body["sealed"]);
		}
		let bytes = unhex(body["record"].as_str().unwrap_or(""))?;
		let record = CoinRecord::from_bytes(&bytes).map_err(|e| Error::Refused(format!("invalid_record: {}", e)))?;
		let mut sch = vec![];
		schedules(&record, &mut sch);
		if sch.is_empty() && !has_lineage(&record) {
			return Err(Error::Refused("invalid_record: the coin rests on no batch and has no lineage: no sweep takes it, and no \
				sender can take it back".into()));
		}
		let (owner, _) = record.owner().ok_or_else(|| Error::Refused("invalid_record: the record names no owner".into()))?;
		let bases = txs_of(&body["bases"])?;
		let coin = self.tower_coin(&record, &bases).map_err(|e| Error::Refused(format!("invalid_record: {}", e)))?;
		if self.store.tower_count()? >= MAX_DEPOSITS {
			return Err(Error::Refused("request_too_large: the watchtower holds as many deposits as it takes".into()));
		}
		let id = hex(&deposit_id(&bytes));
		let bases_text = json!(body["bases"]).to_string();
		self.store.tower_put(&id, &owner.to_string(), &coin.id.to_string(), &bytes, &bases_text)?;
		Ok(json!({"deposit": id, "leaf_id": coin.id.to_string(), "state": "held"}))
	}

	/// Takes a sealed deposit (`{"genesis_hash", "sealed": {"v", "salt",
	/// "withdraw", "hints", "wraps", "blob"}}`, [`seal`]): kept as it is,
	/// unread, until a pass sees one of its hints' triggers on the chain
	/// ([`Self::tower_open`]). Only its shape can be checked now. Answers its
	/// id.
	fn tower_deposit_sealed(&mut self, sealed: &Value) -> Result<Value, Error> {
		let bad = |w: &str| Error::Refused(format!("invalid_seal: {}", w));
		if sealed["v"].as_u64() != Some(1) {
			return Err(bad("the version is not 1"));
		}
		let salt = unhex32(sealed["salt"].as_str().unwrap_or("")).map_err(|_| bad("the salt is not 32 bytes"))?;
		let withdraw = XOnlyPublicKey::from_str(sealed["withdraw"].as_str().unwrap_or("")).map_err(|_| bad("the withdrawal key"))?;
		let hints = sealed["hints"].as_array().cloned().unwrap_or_default();
		let wraps = sealed["wraps"].as_array().cloned().unwrap_or_default();
		if hints.is_empty() || hints.len() > MAX_HINTS || hints.len() != wraps.len() {
			return Err(bad(&format!("1 to {} hints, as many wraps", MAX_HINTS)));
		}
		let mut hs = vec![];
		for (h, w) in hints.iter().zip(&wraps) {
			let h = h.as_str().unwrap_or("");
			unhex32(h).map_err(|_| bad("a hint is not 32 bytes"))?;
			if unhex(w.as_str().unwrap_or("")).map_err(|_| bad("a wrap"))?.len() != 48 {
				return Err(bad("a wrap is not 48 bytes"));
			}
			hs.push(h.to_string());
		}
		let blob = unhex(sealed["blob"].as_str().unwrap_or("")).map_err(|_| bad("the blob"))?;
		if blob.is_empty() || blob.len() > MAX_DEPOSIT_BYTES / 2 {
			return Err(bad("the blob's size"));
		}
		if self.store.tower_count()? >= MAX_DEPOSITS {
			return Err(Error::Refused("request_too_large: the watchtower holds as many deposits as it takes".into()));
		}
		let id = hex(&sealed_id(&withdraw, &salt, &blob));
		self.store.tower_put_sealed(&id, &withdraw.to_string(), &sealed.to_string(), &hs)?;
		if self.store.meta(SCANNED_META)?.is_none() {
			let tip = self.chain.tip()?;
			self.store.set_meta(SCANNED_META, &format!("{}:{}", tip.height, tip.hash))?;
		}
		Ok(json!({"deposit": id, "state": "sealed"}))
	}

	/// Opens every sealed deposit whose trigger is on the chain: each
	/// output of the blocks since the last pass read, and of the mempool,
	/// looked up by the hints of its two possible triggers. An opened
	/// deposit is checked as a plain one is and held from then on; one that
	/// does not open or check is kept as `invalid`, with why.
	fn tower_open(&mut self) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		if self.store.tower_sealed_count()? == 0 {
			return Ok(out);
		}
		let tip = self.chain.tip()?;
		let from = match self.store.meta(SCANNED_META)?.and_then(|m| m.split_once(':').map(|(h, b)| (h.to_string(), b.to_string()))) {
			Some((h, b)) => {
				let h: u64 = h.parse().unwrap_or(tip.height);
				let same = self.chain.block_hash(h)?.is_some_and(|x| x.to_string() == b);
				if same { h + 1 } else { h.saturating_sub(SCAN_BACK) }
			},
			None => tip.height.saturating_sub(SCAN_BACK),
		};
		let mut seen: Vec<elements::TxOut> = vec![];
		self.chain.each_block_to(from, tip.height, |_, b| {
			seen.extend(b.txdata.into_iter().flat_map(|t| t.output));
			Ok(false)
		})?;
		seen.extend(self.chain.mempool_txs()?.into_iter().flat_map(|t| t.output));
		for o in seen {
			let mut ts = vec![output_trigger(&o.script_pubkey)];
			if let Some(a) = o.asset.explicit() {
				ts.push(release_trigger(&o.script_pubkey, &a));
			}
			for t in ts {
				for (id, k) in self.store.tower_hinted(&hex(&hint_of(&self.genesis, &t)))? {
					let Some(body) = self.store.tower_sealed_body(&id)? else { continue };
					let sealed: Value = serde_json::from_str(&body).map_err(|e| Error::Store(e.to_string()))?;
					let opened = open(&self.genesis, &sealed, &t, k).and_then(|p| {
						let v: Value = serde_json::from_slice(&p).map_err(|e| Error::Refused(format!("bad_seal: {}", e)))?;
						let bytes = unhex(v["record"].as_str().unwrap_or(""))?;
						let record = CoinRecord::from_bytes(&bytes).map_err(|e| Error::Refused(format!("invalid_record: {}", e)))?;
						let coin = self.tower_coin(&record, &txs_of(&v["bases"])?)?;
						Ok((coin.id.to_string(), bytes, json!(v["bases"]).to_string()))
					});
					match opened {
						Ok((leaf, bytes, bases)) => {
							let note = format!("opened: its trigger {} is on the chain", if t[0] == b'R' { "(a release)" } else { "(an output of its lineage)" });
							self.store.tower_opened(&id, &leaf, &bytes, &bases, &note)?;
							out.push(json!({"deposit": id, "leaf_id": leaf, "state": "held", "note": note}));
						},
						Err(e) => {
							self.store.tower_set(&id, "invalid", &e.to_string(), None)?;
							out.push(json!({"deposit": id, "state": "invalid", "error": e.to_string()}));
						},
					}
				}
			}
		}
		self.store.set_meta(SCANNED_META, &format!("{}:{}", tip.height, tip.hash))?;
		Ok(out)
	}

	/// Takes a withdrawal (`{"deposit", "owner", "signature"}`): the deposit
	/// removed when the signature is its owner key's over
	/// [`withdraw_digest`]. A deposit the watchtower does not hold is
	/// answered as withdrawn.
	pub fn tower_withdraw(&mut self, body: &Value) -> Result<Value, Error> {
		let id = body["deposit"].as_str().unwrap_or("").to_string();
		let did = unhex32(&id)?;
		let Some(row) = self.store.tower_get(&id)? else {
			return Ok(json!({"deposit": id, "withdrawn": true, "held": false}));
		};
		let owner = XOnlyPublicKey::from_str(&row.owner).map_err(|e| Error::Store(e.to_string()))?;
		let sig = Signature::from_slice(&unhex(body["signature"].as_str().unwrap_or(""))?)
			.map_err(|e| Error::Refused(format!("bad_signature: {}", e)))?;
		if !verify_digest(&sig, &withdraw_digest(&self.genesis, &owner, &did), &owner) {
			return Err(Error::Refused("bad_signature: the withdrawal is not signed by the deposit's owner key".into()));
		}
		self.store.tower_delete(&id)?;
		Ok(json!({"deposit": id, "withdrawn": true, "held": true}))
	}

	/// The deposits the watchtower holds, each with its state: `held`
	/// (waiting for a batch it rests on to be released), `brought` (its path
	/// broadcast, the leaf not in a block yet), `on_chain` (its leaf in a
	/// block, its owner's), `gone` (nothing of its path is unspent: its
	/// holder spent it, or a sweep took it; looked at again on every pass),
	/// with what it cost.
	pub fn tower_deposits(&self) -> Result<Value, Error> {
		let rows = self.store.tower_all()?;
		Ok(Value::Array(rows.into_iter().map(|r| json!({"deposit": r.id, "leaf_id": r.leaf_id, "owner": r.owner, "state": r.state,
			"note": r.note, "broadcast": serde_json::from_str::<Value>(&r.txs).unwrap_or(Value::Null)})).collect()))
	}

	/// Whether a batch of `schedules` is released: its token at `R`, unspent
	/// in a block or made by a transaction in the mempool.
	fn released(&self, sch: &[ClockSchedule], memo: &mut BTreeMap<Vec<u8>, bool>) -> Result<bool, Error> {
		for s in sch {
			let r = s.r().script_pubkey();
			let key = [r.as_bytes(), &s.token.into_inner().to_byte_array()[..]].concat();
			if let Some(b) = memo.get(&key) {
				if *b {
					return Ok(true);
				}
				continue;
			}
			let mut at_r = self.chain.coins_at(std::slice::from_ref(&r))?.iter().any(|(_, o, _)| o.asset.explicit() == Some(s.token));
			if !at_r {
				at_r = self.chain.mempool_txs()?.iter().any(|t| t.output.iter()
					.any(|o| o.script_pubkey == r && o.asset.explicit() == Some(s.token)));
			}
			memo.insert(key, at_r);
			if at_r {
				return Ok(true);
			}
		}
		Ok(false)
	}

	/// One pass over the deposits: each coin a batch it rests on has
	/// released brought on the chain, as far as the chain allows now. What it
	/// did, a line a deposit it acted on or found changed.
	pub fn tower_pass(&mut self) -> Result<Value, Error> {
		let mut memo = BTreeMap::new();
		let mut out = self.tower_open()?;
		for row in self.store.tower_all()? {
			// A coin read as gone is looked at again: the chain is read in two
			// steps (its set of unspent outputs, then the mempool), and a
			// transaction mined between them is seen in neither.
			if !matches!(row.state.as_str(), "held" | "brought" | "gone") {
				continue;
			}
			let r = self.tower_one(&row, &mut memo);
			match r {
				Ok(Some(v)) => out.push(v),
				Ok(None) => {},
				Err(e) => {
					let note = e.to_string();
					if note != row.note {
						self.store.tower_set(&row.id, &row.state, &note, None)?;
						out.push(json!({"deposit": row.id, "leaf_id": row.leaf_id, "state": row.state, "error": note}));
					}
				},
			}
		}
		Ok(json!({"acted": out}))
	}

	fn tower_one(&mut self, row: &super::store::TowerRow, memo: &mut BTreeMap<Vec<u8>, bool>) -> Result<Option<Value>, Error> {
		let record = CoinRecord::from_bytes(&row.record).map_err(|e| Error::Store(e.to_string()))?;
		let bases = txs_of(&serde_json::from_str::<Value>(&row.bases).map_err(|e| Error::Store(e.to_string()))?)?;
		let mut sch = vec![];
		schedules(&record, &mut sch);
		let released = row.state != "held" || self.released(&sch, memo)?;
		// A coin paid out of round is answered as soon as a sender up its
		// lineage takes an earlier coin on the chain, released or not; until
		// an output it descends from moves, nothing of its lineage can be
		// there, which one look at those outputs tells.
		if !released && (!has_lineage(&record) || !self.roots_moved(&record, &bases, memo)?) {
			return Ok(None);
		}
		let coin = self.tower_coin(&record, &bases)?;
		let mut path = vec![];
		Self::path_outputs(&coin, &mut path);
		let here = Here { outputs: path.clone(), at: self.chain.locate(&path)? };
		let leaf = coin.output().txout();
		let seen = if released { vec![] } else {
			let seen = self.lineage_seen(&coin, &here)?;
			if seen.is_empty() && here.at(&coin.output()).is_none() {
				return Ok(None);
			}
			seen
		};
		if let Some(at) = path.iter().zip(&here.at).find(|(o, _)| **o == leaf).and_then(|(_, a)| *a) {
			if self.chain.finality(&at.txid)?.in_chain() {
				let note = format!("its leaf is on the chain at {}, its owner's", at);
				self.store.tower_set(&row.id, "on_chain", &note, None)?;
				return Ok(Some(json!({"deposit": row.id, "leaf_id": row.leaf_id, "state": "on_chain", "leaf": at.to_string()})));
			}
			return Ok(None);
		}
		if here.at.iter().all(Option::is_none) {
			if row.state == "gone" {
				return Ok(None);
			}
			let note = "nothing of its path is unspent on the chain: its holder spent it, or a sweep took it".to_string();
			self.store.tower_set(&row.id, "gone", &note, None)?;
			return Ok(Some(json!({"deposit": row.id, "leaf_id": row.leaf_id, "state": "gone", "note": note})));
		}
		let mut payer = Payer::new(None);
		payer.moved = Some(coin.asset);
		let mut built = vec![];
		let at = self.bring(&coin, &mut payer, &mut built, &here)?;
		let mut steps = vec![];
		for u in &built {
			let txid = self.chain.broadcast(&u.tx)?;
			let fees: Vec<Value> = u.tx.output.iter().filter(|o| o.is_fee())
				.filter_map(|o| Some(json!({"asset": o.asset.explicit()?.to_string(), "amount": o.value.explicit()?.to_string()}))).collect();
			let by_coin = u.tx.input.len() > 1;
			steps.push(json!({"txid": txid.to_string(), "vsize": u.tx.vsize(), "fee": fees,
				"paid_by": if by_coin { "a coin of the watchtower's" } else { "its own reserve" }}));
		}
		let mut all: Vec<Value> = serde_json::from_str::<Value>(&row.txs).ok().and_then(|v| v.as_array().cloned()).unwrap_or_default();
		all.extend(steps.iter().cloned());
		let note = if seen.is_empty() {
			format!("its batch is released: its path broadcast, its leaf at {}", at)
		} else {
			format!("a sender up its lineage took an earlier coin on the chain ({}): its path broadcast, its leaf at {}", seen.join("; "), at)
		};
		self.store.tower_set(&row.id, "brought", &note, Some(&Value::Array(all).to_string()))?;
		Ok(Some(json!({"deposit": row.id, "leaf_id": row.leaf_id, "state": "brought", "leaf": at.to_string(), "broadcast": steps})))
	}

	/// Whether an output `record` descends from (a batch output or a board,
	/// read from the deposit's transactions) is spent, in a block or the
	/// mempool, or cannot be named: only then can anything of its lineage be
	/// on the chain.
	fn roots_moved(&self, record: &CoinRecord, bases: &[Transaction], memo: &mut BTreeMap<Vec<u8>, bool>) -> Result<bool, Error> {
		let mut outs = vec![];
		if super::wallet::base_outputs(record, &mut outs).is_err() {
			return Ok(true);
		}
		for o in outs {
			let Some(tx) = bases.iter().find(|t| t.output.contains(&o)) else { return Ok(true) };
			let txid = tx.txid();
			for (i, _) in tx.output.iter().enumerate().filter(|(_, x)| **x == o) {
				let op = OutPoint::new(txid, i as u32);
				let key = [b"root".as_slice(), &elements::encode::serialize(&op)].concat();
				let spent = match memo.get(&key) {
					Some(b) => *b,
					None => {
						let b = !self.chain.unspent(&op)?;
						memo.insert(key, b);
						b
					},
				};
				if spent {
					return Ok(true);
				}
			}
		}
		Ok(false)
	}

	/// What of `coin`'s lineage is on the chain (`here`): a leaf or
	/// checkpoint it descends from, unspent in a block or the mempool. Each
	/// means a sender has started to take an earlier coin home, which only
	/// the checkpoint and reassignment answer, within that leaf's exit delay.
	fn lineage_seen(&self, coin: &arca_covenant::ValidCoin, here: &Here) -> Result<Vec<String>, Error> {
		Ok(coin.lineage().into_iter().filter(|o| here.at(&o.output).is_some())
			.map(|o| format!("a {} it descends from", o.kind)).collect())
	}
}

impl Wallet {
	/// What a watchtower publishes of itself: the chain and the operator it
	/// watches for, and how many deposits it holds.
	pub fn tower_info(&self) -> Result<Value, Error> {
		Ok(json!({"watchtower": true, "genesis_hash": self.genesis.genesis_hash().to_string(), "operator": self.operator.to_string(),
			"deposits": self.store.tower_count()?, "sealed": 1}))
	}

	/// A watchtower's answer to `call` (`info`, `deposit`, `withdraw`) with
	/// `body`, for the program that serves it over HTTP.
	pub fn tower_call(&mut self, call: &str, body: &Value) -> Result<Value, Error> {
		match call {
			"info" => self.tower_info(),
			"deposit" => self.tower_deposit(body),
			"withdraw" => self.tower_withdraw(body),
			_ => Err(Error::Refused(format!("malformed: no call {}", call))),
		}
	}
}

/// The key of an exit's record that says its coin was kept safe: brought on
/// the chain by someone else (a watchtower, or the operator at its batch's
/// release) before the wallet started any exit of it.
pub const KEPT_SAFE: &str = "kept_safe";

/// What a wallet tells its user of such a coin, in plain words.
pub const KEPT_SAFE_NOTE: &str = "moved out of the Ark to keep it safe while you were away";

impl Wallet {
	/// Whether `leaf_id`'s exit is of a coin kept safe, and whether that coin
	/// is boarded back already.
	pub(crate) fn kept_safe(&self, leaf_id: &str) -> Result<(bool, bool), Error> {
		let Some((_, j, _)) = self.store.exit(leaf_id)? else { return Ok((false, false)) };
		let v: Value = serde_json::from_str(&j).map_err(|e| Error::Store(e.to_string()))?;
		Ok((v[KEPT_SAFE] == json!(true), !v["reboard"].is_null()))
	}

	/// Every coin kept safe whose claim is final, boarded back: a board of
	/// what the claim paid less the board's fee, in the coin's asset. Once
	/// a board is out, or refused for a reason a retry does not change, it
	/// is recorded and not tried again; a board that could not reach the
	/// operator is tried at the next `sync`.
	pub(crate) fn progress_reboards(&mut self) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		for c in self.store.coins_in("exited")? {
			let (kept, done) = self.kept_safe(&c.leaf_id)?;
			if !kept || done {
				continue;
			}
			let Some((st, j, claim)) = self.store.exit(&c.leaf_id)? else { continue };
			let mut v: Value = serde_json::from_str(&j).map_err(|e| Error::Store(e.to_string()))?;
			let Some(claim) = claim.as_deref().and_then(|t| elements::Txid::from_str(t).ok()) else { continue };
			let Some(tx) = self.chain.transaction(&claim)? else { continue };
			let asset = AssetId::from_str(&c.asset).map_err(|e| Error::Store(e.to_string()))?;
			let paid: u64 = tx.output.iter().filter(|o| o.asset.explicit() == Some(asset) && !o.is_fee())
				.filter_map(|o| o.value.explicit()).take(1).sum();
			let r = self.board_quote(asset, paid.saturating_sub(1), None).and_then(|q| {
				let fee: u64 = q["fee"]["amount"].as_str().and_then(|a| a.parse().ok()).unwrap_or(0);
				self.board(asset, paid.saturating_sub(fee), None)
			});
			match r {
				Ok(b) => {
					v["reboard"] = json!({"board": b.clone()});
					self.store.set_exit(&c.leaf_id, &st, &v.to_string(), Some(&claim.to_string()))?;
					out.push(json!({"leaf_id": c.leaf_id, "boarded": b, "note": format!("{}: boarded back", KEPT_SAFE_NOTE)}));
				},
				Err(e @ (Error::Unreachable(_) | Error::Node(_) | Error::Missing(_))) => {
					out.push(json!({"leaf_id": c.leaf_id, "error": e.to_string(), "note": "tried again at the next sync"}));
				},
				Err(e) => {
					v["reboard"] = json!({"refused": e.to_string()});
					self.store.set_exit(&c.leaf_id, &st, &v.to_string(), Some(&claim.to_string()))?;
					out.push(json!({"leaf_id": c.leaf_id, "error": e.to_string(), "note": "the coin stays on the chain, the wallet's to spend"}));
				},
			}
		}
		Ok(out)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use elements::hashes::Hash as _;

	fn chain(b: u8) -> Chain {
		Chain::new(elements::BlockHash::from_byte_array([b; 32]))
	}

	#[test]
	fn a_sealed_deposit_opens_under_each_trigger_and_nothing_else() {
		let c = chain(7);
		let key = elements::secp256k1_zkp::Keypair::from_seckey_slice(elements::secp256k1_zkp::SECP256K1, &[3; 32]).unwrap();
		let salt = [9; 32];
		let w = withdraw_key(&key, &salt).unwrap();
		assert_ne!(w.x_only_public_key(), key.x_only_public_key(), "the withdrawal key names no key of the coin");
		let payload = br#"{"record":"00","bases":[]}"#;
		let ts = vec![b"O\x51\x20leaf".to_vec(), b"O\x51\x20checkpoint".to_vec(), b"Rr-script-and-token".to_vec()];
		let (sealed, id) = seal(&c, payload, &ts, &w.x_only_public_key().0, &salt).unwrap();
		let hints: Vec<String> = sealed["hints"].as_array().unwrap().iter().map(|h| h.as_str().unwrap().to_string()).collect();
		assert_eq!(hints.len(), HINTS_PAD, "three hints padded to {}", HINTS_PAD);
		assert_eq!(unhex(sealed["blob"].as_str().unwrap()).unwrap().len(), BLOB_PAD + 16, "the payload padded, and its tag");
		assert_eq!(id, sealed_id(&w.x_only_public_key().0, &salt, &unhex(sealed["blob"].as_str().unwrap()).unwrap()));
		let text = sealed.to_string();
		assert!(!text.contains("leaf") && !text.contains("record"), "nothing of the payload or the triggers in the clear");
		for t in &ts {
			let h = hex(&hint_of(&c, t));
			let k = hints.iter().position(|x| *x == h).expect("each trigger's hint is among them");
			assert_eq!(open(&c, &sealed, t, k).unwrap(), payload.to_vec());
			// Another chain's hint differs, and the key with it.
			assert_ne!(hint_of(&chain(8), t), hint_of(&c, t));
			assert!(open(&chain(8), &sealed, t, k).is_err(), "another chain's key opens nothing");
		}
		// A trigger the deposit was not sealed under opens nothing, at any hint.
		for k in 0..hints.len() {
			assert!(open(&c, &sealed, b"Oanother output", k).is_err());
		}
		// A wrap or a blob changed by one bit opens nothing.
		let k = hints.iter().position(|x| *x == hex(&hint_of(&c, &ts[0]))).unwrap();
		let mut bad = sealed.clone();
		let mut wrap = unhex(bad["wraps"][k].as_str().unwrap()).unwrap();
		wrap[0] ^= 1;
		bad["wraps"][k] = json!(hex(&wrap));
		assert!(open(&c, &bad, &ts[0], k).is_err());
		let mut bad = sealed.clone();
		let mut blob = unhex(bad["blob"].as_str().unwrap()).unwrap();
		blob[5] ^= 1;
		bad["blob"] = json!(hex(&blob));
		assert!(open(&c, &bad, &ts[0], k).is_err());
		// Two seals of one payload share their hints and nothing else.
		let (again, id2) = seal(&c, payload, &ts, &w.x_only_public_key().0, &[10; 32]).unwrap();
		assert_ne!(id, id2);
		assert_ne!(again["blob"], sealed["blob"]);
	}
}
