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
//! For each live coin resting on a batch, the wallet builds one deposit: the
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
//! **The watchtower's side.** A watchtower is a wallet of its own (its
//! mnemonic holds the coins it pays fees with) that takes deposits
//! ([`Wallet::tower_deposit`]) and withdrawals ([`Wallet::tower_withdraw`]),
//! and passes over them ([`Wallet::tower_pass`]). A pass leaves a coin alone
//! until a batch it rests on is released (the batch's token at `R`, in a
//! block or the mempool); then it builds whatever is still missing of the
//! coin's path, from the lowest output the chain holds unspent, exactly as an
//! exit does, and broadcasts it. Each transaction pays its fee from the
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

use std::collections::BTreeMap;
use std::str::FromStr;

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Transaction};
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
/// URLs. Absent, the wallet uses those the operator's `info` lists.
pub const WATCHTOWERS_META: &str = "watchtowers";

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

/// The latest time of any authorisation `record` carries.
fn latest_auth(record: &CoinRecord) -> u32 {
	match record {
		CoinRecord::Leaf { auths, .. } => auths.iter().map(|(_, t)| t.to_consensus_u32()).max().unwrap_or(0),
		CoinRecord::Accumulator { auth, .. } => auth.1.to_consensus_u32(),
		CoinRecord::Board(_) => 0,
		CoinRecord::Transfer(_) | CoinRecord::Fill(_) => record.parents().into_iter().map(latest_auth).max().unwrap_or(0),
	}
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
	/// from: the wallet's own setting, or the operator's `info`.
	pub fn watchtowers(&self) -> Result<Value, Error> {
		let (list, from) = self.tower_list()?;
		Ok(json!({"watchtowers": list, "from": from}))
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
		let list = info["watchtowers"].as_array().cloned().unwrap_or_default().iter()
			.filter_map(|u| u.as_str().map(str::to_string)).filter(|u| ServerClient::new(u).is_ok()).collect();
		Ok((list, "operator"))
	}

	/// The deposit of the coin `row`: its record, with the authorisations of
	/// a batch leaf of the wallet's own signed again for an hour before its
	/// batch's first expiry, and the transactions it rests on. `None` for a
	/// coin that rests on no batch, which no sweep takes.
	fn deposit_of(&self, row: &super::store::CoinRow) -> Result<Option<(CoinRecord, Vec<Transaction>)>, Error> {
		let record = Self::record_of(row)?;
		let mut sch = vec![];
		schedules(&record, &mut sch);
		if sch.is_empty() {
			return Ok(None);
		}
		let bases = self.accepted_bases(&record)?;
		let now = self.now()?;
		let coin = self.resolve(&record, &bases, &self.followed_policy(row.expiry, now)).map_err(|e| Error::Refused(e.to_string()))?;
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
		Ok(Some((record, bases)))
	}

	/// Every live coin resting on a batch deposited with each watchtower the
	/// wallet names, once; every deposit of a coin no longer the wallet's
	/// withdrawn. What it did, a line a coin and watchtower; a watchtower
	/// that cannot be reached is tried again at the next `sync`.
	pub(crate) fn progress_deposits(&mut self) -> Result<Vec<Value>, Error> {
		let (towers, _) = self.tower_list()?;
		let mut out = vec![];
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
						let (record, bases) = match self.deposit_of(&row) {
							Ok(Some(d)) => d,
							Ok(None) => continue,
							Err(e) => {
								out.push(json!({"leaf_id": row.leaf_id, "error": e.to_string()}));
								continue;
							},
						};
						let bytes = record.to_bytes().map_err(|e| Error::Refused(e.to_string()))?;
						let id = deposit_id(&bytes);
						let body = json!({"genesis_hash": self.genesis.genesis_hash().to_string(), "record": hex(&bytes),
							"bases": bases.iter().map(|t| hex(&elements::encode::serialize(t))).collect::<Vec<_>>()}).to_string();
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
			let key = match &row {
				Some(r) => Some(self.coin_key(&r.owner_nonce)?),
				None => None,
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
		let bytes = unhex(body["record"].as_str().unwrap_or(""))?;
		let record = CoinRecord::from_bytes(&bytes).map_err(|e| Error::Refused(format!("invalid_record: {}", e)))?;
		let mut sch = vec![];
		schedules(&record, &mut sch);
		if sch.is_empty() {
			return Err(Error::Refused("invalid_record: the coin rests on no batch, and no sweep takes it".into()));
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
		let mut out = vec![];
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
		if row.state == "held" && !self.released(&sch, memo)? {
			return Ok(None);
		}
		let coin = self.tower_coin(&record, &bases)?;
		let mut path = vec![];
		Self::path_outputs(&coin, &mut path);
		let here = Here { outputs: path.clone(), at: self.chain.locate(&path)? };
		let leaf = coin.output().txout();
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
		let note = format!("its batch is released: its path broadcast, its leaf at {}", at);
		self.store.tower_set(&row.id, "brought", &note, Some(&Value::Array(all).to_string()))?;
		Ok(Some(json!({"deposit": row.id, "leaf_id": row.leaf_id, "state": "brought", "leaf": at.to_string(), "broadcast": steps})))
	}
}

impl Wallet {
	/// What a watchtower publishes of itself: the chain and the operator it
	/// watches for, and how many deposits it holds.
	pub fn tower_info(&self) -> Result<Value, Error> {
		Ok(json!({"watchtower": true, "genesis_hash": self.genesis.genesis_hash().to_string(), "operator": self.operator.to_string(),
			"deposits": self.store.tower_count()?}))
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
