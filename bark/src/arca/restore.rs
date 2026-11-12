//! Restoring a wallet from its mnemonic alone.
//!
//! A wallet keeps one key per leaf, from the mnemonic and the leaf's random
//! owner nonce, so a mnemonic alone names no leaf. It does name the wallet's
//! mailbox key ([`super::keys`]), and the wallet binds every leaf it makes to
//! it ([`Wallet::binding`]): the server then serves those leaves, every way
//! each was given up and every coin posted to the mailbox to whoever proves
//! the mailbox key (`leaf_data`). A restore reads them and takes the
//! operator's word for nothing it can check:
//!
//! - **the keepers**: the keeper set `info` names is pinned only when the
//!   operator's latest head comes with the acknowledgements of as many of
//!   them as must hold it, and no head it serves is acknowledged by a key the
//!   set does not hold; otherwise nothing is restored;
//! - **each coin**: its owner key must be the key the mnemonic derives from
//!   the owner nonce it names; its record is validated against the chain as a
//!   coin held is ([`Wallet::followed_policy`]: as of its expiry once that has
//!   passed, a coin past it kept only while the chain still holds its path);
//!   a round's leaf is rebuilt from the published tree, compared with the
//!   record served, and its unroll authorisations signed again; a coin made
//!   out of round is taken only on a head of the signer's record held outside
//!   the operator's machine ([`Wallet::held_outside`]);
//! - **how it was given up**: a coin is spent, given or forfeited only on its
//!   owner's own signature, which the wallet checks: the checkpoint signature
//!   of a transfer, the attestation over a participation's id (recomputed
//!   from every part of it), the owner's half of a forfeit. The server's
//!   `state` is never taken: a coin a record of the wallet's shows spent (an
//!   input of a coin the operator co-signed) is spent whatever the server says
//!   of it, and one whose forfeit the owner signed is never live;
//! - **what the chain says**: every base is read from the chain, and the
//!   restore ends with a `sync`, which re-checks every coin, follows every
//!   forfeit, completes every participation and takes home what is due.
//!
//! The coins that make the balance now are checked first; the coins the
//! server serves as given up for good, and every coin a record it serves
//! names as an input of a transfer, are the wallet's history, kept in the
//! store as served and checked with the same checks a step at each `sync`
//! after the restore ([`Wallet::restore_history`]), the coins whose records
//! spend a coin before the coin. None of them is counted until its step has
//! checked it.
//!
//! What cannot be recovered is said with its reason (`not_recovered`): a
//! record the server withholds and the published tree does not hold, a coin
//! failing a check, and receive requests handed out and never paid, which no
//! one but the lost store knew: the schedule holds at a day for as long as
//! such a request could last ([`super::wallet::REQUEST_HOLDS`] from the
//! restore), since a payment to one is read only by `sync`.
//!
//! Two live stores of one mnemonic draw their own owner nonces, and each
//! one's mailbox read refuses a coin made under a nonce it never drew; each
//! follows the other by catching up ([`Wallet::catch_up`], from `sync`),
//! which reads what the server serves as a restore does: it takes what the
//! store does not hold, and gives up what the other store gave up on the
//! owner's own signatures, so both show the same coins. A restore that stops
//! at an error keeps what it took before it, and a later restore takes the
//! rest. A take whose round is held for its takes' forfeits, unbroadcast, is
//! restored from the round its status serves (its txid the round's), as
//! `sync` reads it.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use elements::hashes::{sha256, Hash};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Txid};
use serde_json::{json, Value};

use arca_covenant::{connector_asset, Batch, CoinRecord, Forfeit, LeafId, MedianTime, RelativeTime, Template, TransferPlan, ValidCoin, ValidOrigin};

use super::chain::{hex, unhex, unhex32};
use super::client::{participation_id, Wanted, LEAF_DATA_PAGES, LEAF_PAGE};
use super::store::ForfeitRow;
use super::round::NewRecord;
use super::wallet::{amount, kind_of, owner_of, Wallet};
use super::Error;

/// Where the wallet keeps the median time until which its schedule holds at
/// a day after a restore: receive requests handed out before it are not
/// known, and one may still be paid until then.
pub(crate) const RESTORED_UNTIL: &str = "restored_until";

/// What the schedule says while it holds at a day after a restore.
pub(crate) const RESTORED_NOTE: &str = "the wallet was restored from its mnemonic: a receive request handed out before then cannot be \
	known (its key comes from a random nonce the lost store held), and a coin paid to one is read only by sync, so sync runs at least \
	once a day until the latest such a request could lapse (lapses_at). Forget it once no request was outstanding";

/// What a restore says of the history it leaves to `sync`.
pub(crate) const HISTORY_NOTE: &str = "the coins the server serves as given up for good (a transfer the operator co-signed, a \
	participation it released) are checked a few at a time by each sync after the restore, with every check a restore makes, until \
	left is 0: they make the wallet's history, and none is counted until it is checked. A coin the server serves as unspent that one of \
	the records it serves names as spent waits with them";

/// What a restore says of the watchtowers' deposits it leaves owed.
pub(crate) const DEPOSITS_NOTE: &str = "the coins restored are deposited with the watchtowers right after the restore returns (the \
	command deposits, which the program runs at once); until they are, a coin rests on this wallet alone to answer anything published \
	on the chain against it, and every sync makes them first while they are owed";

/// One coin the restore could not take, and why.
fn missed(leaf: &str, why: impl Into<String>) -> Value {
	json!({"leaf_id": leaf, "why": why.into()})
}

/// A signature from its hex, if it is one.
fn signature(v: &Value) -> Option<Signature> {
	v.as_str().and_then(|s| unhex(s).ok()).and_then(|b| Signature::from_slice(&b).ok())
}

/// When the unroll authorisations a restore signs again for a leaf of first
/// expiry `first` are dated: an hour before the time the leaf is checked as
/// of (now, or its expiry once that has passed, [`Wallet::followed_policy`]),
/// so they are usable at once whenever the wallet checks the leaf.
fn auth_time(first: u32, now: MedianTime) -> Result<MedianTime, String> {
	MedianTime::from_consensus(first.min(now.to_consensus_u32()).saturating_sub(3600)).map_err(|e| e.to_string())
}

/// A coin the restore took, with what it rests on and how it was given up,
/// for the passes after the first.
struct Taken {
	entry: Value,
	coin: ValidCoin,
}

/// What [`Wallet::take_served`] took and found.
struct TakenServed {
	restored: Vec<Value>,
	not_recovered: Vec<Value>,
	notes: Vec<Value>,
	given_elsewhere: Vec<Value>,
}

/// Where the wallet keeps the coins of a restore's history still to be
/// checked ([`Wallet::restore_history`]): what the server served, as it
/// served it, for coins it serves as given up for good.
pub(crate) const RESTORE_HISTORY: &str = "restore_history";

/// Where the wallet keeps the ids of the coins of [`RESTORE_HISTORY`], for
/// the mailbox read, which leaves each to its step.
pub(crate) const RESTORE_HISTORY_IDS: &str = "restore_history_ids";

/// The longest a coin of a restore's history waits for a transaction it
/// rests on, as the server names it, to be in a block of the active chain
/// again ([`Wallet::restore_history`]), in seconds of median time: six hours,
/// far past the time a transaction an anchor-driven reorganisation took out
/// of the chain needs to be mined again. Past it, the coin is checked as a
/// restore that takes everything at once checks it.
pub const HISTORY_WAIT_MOST: u32 = 6 * 3600;

/// The field of a listed coin that says since when (median time) it waits
/// for a transaction it rests on ([`HISTORY_WAIT_MOST`]).
pub(crate) const WAITING_SINCE: &str = "waiting_since";

/// The most coins of a restore's history one step checks
/// ([`Wallet::restore_history`]): a `sync` runs one step, so it holds the
/// wallet for a bounded time while the history lasts.
pub const HISTORY_STEP: usize = 20;

/// Where the wallet keeps the median time it last caught up with what the
/// server serves to its mailbox key ([`Wallet::catch_up`]).
pub(crate) const CAUGHT_UP: &str = "caught_up";

/// How often `sync` catches up, at most (median-time seconds).
pub(crate) const CATCH_UP_EVERY: u32 = 600;

/// Where the wallet keeps the coins held out as spent elsewhere
/// ([`Wallet::spent_elsewhere`]).
const SPENT_ELSEWHERE: &str = "spent_elsewhere";

impl Wallet {
	/// After the operator refused a spend of this store's because coin
	/// `leaf` of the wallet's own is spent already (`double_spend`), by
	/// nothing this store did: another store of the mnemonic (a second
	/// device) gave it to a round or paid with it. The wallet reads what the
	/// other stores did at once, so it stops counting the coin and holds
	/// what replaced it (arca #839). While that other store's round is not
	/// final its participation is not released and the catch-up finds
	/// nothing yet: the coin is then held out of every spend
	/// ([`Self::spent_elsewhere`]) until a catch-up settles it, so no quote
	/// or spend offers it again in the meantime.
	pub(crate) fn caught_up_after_spent(&mut self, leaf: &str) -> Result<(), Error> {
		if let Err(c) = self.catch_up() {
			self.store.refused("the catch-up after a coin spent elsewhere", &c.to_string())?;
		}
		let mut held = self.spent_elsewhere_listed()?;
		held.insert(leaf.to_string());
		self.keep_spent_elsewhere(held)
	}

	/// The coins of the wallet's own that the operator refused to spend as
	/// spent already, which a catch-up has not settled yet: still live or
	/// pending here, while the other store's round that spends them is not
	/// final. No spend takes them; a spend short without them waits for
	/// them ([`Error::SettleFirst`]), and `sync` and `settle_first` catch up
	/// until they are settled.
	pub(crate) fn spent_elsewhere(&self) -> Result<BTreeSet<String>, Error> {
		let mut out = BTreeSet::new();
		for l in self.spent_elsewhere_listed()? {
			if self.store.coin(&l)?.is_some_and(|c| matches!(c.state.as_str(), "live" | "pending")) {
				out.insert(l);
			}
		}
		Ok(out)
	}

	fn spent_elsewhere_listed(&self) -> Result<BTreeSet<String>, Error> {
		Ok(self.store.meta(SPENT_ELSEWHERE)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default())
	}

	/// Keeps of `held` those a catch-up has not settled.
	fn keep_spent_elsewhere(&mut self, held: BTreeSet<String>) -> Result<(), Error> {
		let mut keep = BTreeSet::new();
		for l in held {
			if self.store.coin(&l)?.is_some_and(|c| matches!(c.state.as_str(), "live" | "pending")) {
				keep.insert(l);
			}
		}
		self.store.set_meta(SPENT_ELSEWHERE, &json!(keep).to_string())
	}

	/// A catch-up while a coin is held out as spent elsewhere
	/// ([`Self::spent_elsewhere`]), whenever it is asked, not once every ten
	/// minutes; what it found, or `None` when no coin is held out.
	pub(crate) fn settle_spent_elsewhere(&mut self) -> Result<Option<Value>, Error> {
		let held = self.spent_elsewhere()?;
		if held.is_empty() {
			return Ok(None);
		}
		let v = self.catch_up()?;
		self.keep_spent_elsewhere(held)?;
		Ok(Some(v))
	}

	/// Restores the wallet from what its mnemonic names: every leaf the server
	/// serves to its mailbox key, each checked as the module documentation
	/// says, then the mailbox, then a `sync`. Run on a wallet created from a
	/// mnemonic; run again, it takes only what it does not hold. Refuses, and
	/// restores nothing, while the operator's keeper set is not acknowledged.
	pub fn restore(&mut self) -> Result<Value, Error> {
		self.restore_with(false)
	}

	/// [`Self::restore`]; with `at_once`, every coin served is checked
	/// before it returns, the wallet's history with the rest, and its `sync`
	/// makes the watchtowers' deposits: for a program that wants the whole
	/// history checked before anything else, at the cost of the time it
	/// takes.
	pub fn restore_with(&mut self, at_once: bool) -> Result<Value, Error> {
		let mut steps = super::exit::Steps::start(self);
		let info = self.server_info()?;
		let (entries, served_receives, read_note) = self.read_served()?;
		steps.lap(self, "read");
		// The coins that make the balance now first; the coins the server
		// serves as given up for good after, a step at each sync.
		// The keepers are checked over everything served, before anything is
		// taken: a head acknowledged by a key outside the set refuses the
		// whole restore, whichever coin it comes with.
		self.keepers_acknowledged(&info, &entries)?;
		self.no_foreign_acks(&info, &entries)?;
		let (now_entries, history) = if at_once { (entries.clone(), vec![]) } else { self.split_history(&entries)? };
		self.keep_history(&history)?;
		let TakenServed { mut restored, not_recovered, mut notes, given_elsewhere: _ } =
			self.take_served(&info, &now_entries, &served_receives, false, Some(&mut steps))?;
		let (history, settled) = self.settle_held_history(&history)?;
		notes.extend(settled);
		self.keep_history(&history)?;
		let now = self.now()?;

		// The mailbox, from its start: a coin held is held, one paid to a key
		// of the mnemonic and never read is taken.
		self.adopting.set(true);
		let mailbox_read = self.mailbox();
		self.adopting.set(false);
		let mailbox_read = mailbox_read.unwrap_or_else(|e| json!({"error": e.to_string()}));
		steps.lap(self, "mailbox");

		// The chain is read from the oldest base on, the history's included
		// (as the server names them; each step lowers it again from the
		// coins it checked); the schedule holds at a day while a request
		// handed out before may still be paid.
		let named: BTreeSet<Txid> = history.iter().flat_map(Self::served_bases).filter_map(|t| Txid::from_str(&t).ok()).collect();
		self.lower_birthday(&named.into_iter().collect::<Vec<_>>())?;
		let until = now.to_consensus_u32().saturating_add(super::wallet::REQUEST_HOLDS);
		let held_until: u32 = self.store.meta(RESTORED_UNTIL)?.and_then(|v| v.parse().ok()).unwrap_or(0);
		self.store.set_meta(RESTORED_UNTIL, &until.max(held_until).to_string())?;
		steps.lap(self, "birthday");

		// One line per coin not recovered, its reasons together.
		let mut merged: Vec<Value> = vec![];
		for m in not_recovered {
			match merged.iter_mut().find(|x| x["leaf_id"] == m["leaf_id"]) {
				Some(x) if x["why"] != m["why"] => x["why"] = json!(format!("{}; {}", x["why"].as_str().unwrap_or(""), m["why"].as_str().unwrap_or(""))),
				Some(_) => {},
				None => merged.push(m),
			}
		}
		let not_recovered = merged;
		// Each coin as the restore left it, how it was given up applied.
		for v in restored.iter_mut() {
			if let Some(c) = self.store.coin(v["leaf_id"].as_str().unwrap_or(""))? {
				v["state"] = json!(c.state);
			}
		}
		// Offline-refresh plans bound to the mailbox key: kept, their keys
		// checked against the mnemonic; `sync` takes up each step whose round
		// is final.
		let plans = self.restore_plans().map(Value::Array).unwrap_or_else(|e| json!({"error": e.to_string()}));
		steps.lap(self, "plans");
		// A restore has just read everything a catch-up would.
		self.store.set_meta(CAUGHT_UP, &now.to_consensus_u32().to_string())?;
		// The watchtowers' deposits are not waited for: they are noted as
		// owed, made at once after the restore returns (the command
		// `deposits`), and first by any `sync` while they are owed.
		if !at_once {
			self.store.set_meta(super::tower::DEPOSITS_OWED, &now.to_consensus_u32().to_string())?;
		}
		let sync = self.sync_with(true, at_once, false)?;
		steps.lap(self, "sync");
		let left = self.history_left()?;
		let mut out = json!({
			"served": entries.len(), "restored": restored, "not_recovered": not_recovered, "notes": notes, "mailbox": mailbox_read,
			"plans": plans, "history": {"left": left, "loading": left > 0, "note": self.spelling.say(HISTORY_NOTE)},
			"requests": {"lapses_at": until.max(held_until), "note": self.spelling.say(RESTORED_NOTE)},
			"sync": sync,
		});
		if !at_once {
			out["deposits"] = json!({"owed": true, "note": self.spelling.say(DEPOSITS_NOTE)});
		}
		if let Some(n) = read_note {
			out["note"] = json!(n);
		}
		out["cost_by_step"] = steps.done();
		Ok(out)
	}

	/// The keeper set the wallet pinned from `info` (when it was created) is
	/// acknowledged: a head of the operator's signer's record it shows (its
	/// latest, in `info`, or one a coin it serves rests on) comes with the
	/// acknowledgements of as many of them as must hold it. Refuses
	/// otherwise, and the wallet restores nothing: it pins no keeper set on the
	/// operator's word.
	fn keepers_acknowledged(&self, info: &Value, entries: &[Value]) -> Result<(), Error> {
		let (keys, required) = self.keepers()?;
		if keys.is_empty() {
			return Ok(());
		}
		let latest = match self.held_outside(&info["signer_record"]) {
			Ok(()) => return Ok(()),
			Err(why) => why,
		};
		for e in entries {
			for h in [&e["made_by"]["signer_record"], &e["batch"]["signer_record"]] {
				if !h.is_null() && self.held_outside(h).is_ok() {
					return Ok(());
				}
			}
		}
		Err(Error::Refused(format!("the operator names {} keeper(s), {} of them required, and no head of its signer's record it shows comes \
			with their acknowledgements ({}): the wallet pins no keeper set on the operator's word, and restores nothing", keys.len(), required,
			latest)))
	}

	/// No head the operator shows is acknowledged by a key outside the keeper
	/// set the wallet pinned: a keeper's acknowledgement over a head of this
	/// operator's record, by a key the operator does not name, shows the set
	/// it names is not its own. Refuses, and restores nothing.
	fn no_foreign_acks(&self, info: &Value, entries: &[Value]) -> Result<(), Error> {
		let (keys, _) = self.keepers()?;
		let mut heads = vec![info["signer_record"].clone()];
		for e in entries {
			heads.push(e["batch"]["signer_record"].clone());
			heads.push(e["made_by"]["signer_record"].clone());
		}
		for h in heads.iter().filter(|h| !h.is_null()) {
			let (Some(entry), Some(hash)) = (h["entry"].as_u64(), h["hash"].as_str().and_then(|x| unhex32(x).ok())) else { continue };
			for a in h["acks"].as_array().cloned().unwrap_or_default() {
				let Some(k) = a["key"].as_str().and_then(|k| XOnlyPublicKey::from_str(k).ok()) else { continue };
				if keys.contains(&k) {
					continue;
				}
				let (Some(n), Some(s)) = (a["nonce"].as_str().and_then(|n| unhex32(n).ok()), signature(&a["signature"])) else { continue };
				if arca_covenant::sign::verify_digest(&s, &super::client::keeper_ack_digest(&self.genesis, &self.operator, entry, &hash, &n), &k) {
					return Err(Error::Refused(format!("entry {} of the operator's signer's record is acknowledged by keeper {}, which the operator \
						does not name among its keepers ({} named): the keeper set it shows is not its own, so the wallet pins none and restores \
						nothing", entry, k, keys.len())));
				}
			}
		}
		Ok(())
	}

	/// The published batch at output `vout` of round `txid`, of either kind,
	/// fetched once, rebuilt from its parts and refused unless it lists what
	/// they build ([`super::round::rebuild_batch`]).
	fn published_tree<'a>(&self, trees: &'a mut BTreeMap<(String, u32), (Value, Batch)>, txid: &str, vout: u32)
		-> Result<&'a (Value, Batch), String>
	{
		let key = (txid.to_string(), vout);
		if !trees.contains_key(&key) {
			let t = self.server.post("tree", &json!({"txid": txid, "vout": vout})).map_err(|e| e.to_string())?;
			if t["round_txid"].as_str() != Some(txid) || t["batch_vout"].as_u64() != Some(vout as u64) {
				return Err(format!("the server published the tree of another batch than {}:{}", txid, vout));
			}
			let tree = super::round::rebuild_batch(&t).map_err(|e| e.to_string())?;
			trees.insert(key.clone(), (t, tree));
		}
		Ok(&trees[&key])
	}

	/// A round's leaf at `index` of the batch at `vout` of round `txid`,
	/// rebuilt from the published tree and checked against the round on the
	/// chain under the wallet's key of `nonce`, with `preimage` (checked to
	/// open it) and unroll authorisations the mnemonic signs again: what the
	/// wallet holds of the leaf, the server's copy of its record not needed.
	fn leaf_from_tree(&self, trees: &mut BTreeMap<(String, u32), (Value, Batch)>, txid: &str, vout: u32, index: usize, nonce: &[u8; 32],
		preimage: Option<[u8; 32]>, now: MedianTime) -> Result<(CoinRecord, NewRecord), String>
	{
		let (t, tree) = self.published_tree(trees, txid, vout)?;
		if index >= tree.len() {
			return Err(format!("the published tree of {}:{} has no leaf {}", txid, vout, index));
		}
		let record = NewRecord::of(tree, index);
		let published = t["leaves"][index]["preimage"].as_str().and_then(|p| unhex32(p).ok());
		let preimage = preimage.or(published).ok_or_else(|| format!("its preimage has not gone out: the published tree of {}:{} shows none \
			for leaf {}, and the server serves no record of it", txid, vout, index))?;
		if sha256::Hash::hash(&preimage).to_byte_array() != record.unlock_hash() {
			return Err(format!("the preimage of leaf {} of {}:{} does not open its unlock hash", index, txid, vout));
		}
		let owner = self.keys.leaf_xonly(nonce).map_err(|e| e.to_string())?;
		if record.owner() != owner || record.owner_nonce() != *nonce {
			return Err(format!("leaf {} of the published tree of {}:{} is not under the key this wallet derives from owner nonce {}", index, txid,
				vout, hex(nonce)));
		}
		let round_txid = Txid::from_str(txid).map_err(|e| e.to_string())?;
		let round = self.chain.transaction(&round_txid).map_err(|e| e.to_string())?
			.ok_or_else(|| format!("round {} is not on the chain the node holds", txid))?;
		let first = record.first_expiry();
		let valid = record.validate(&round, &self.followed_policy(first, now), &owner, nonce)
			.map_err(|e| format!("the leaf in round {} fails the wallet's checks: {}", txid, e))?;
		let key = self.keys.leaf(nonce).map_err(|e| e.to_string())?;
		let at = auth_time(first, now)?;
		let auths = valid.sign_auths(&key, at);
		Ok((record.coin(preimage, auths).map_err(|e| e.to_string())?, record))
	}

	/// Restores one coin the server serves (`e`), checked: its record, its
	/// owner key, the tree for a round's leaf, the chain, and for a coin made
	/// out of round the keepers' acknowledgements of its head. Kept `live` or
	/// `pending` as the chain stands; how it was given up is looked at next.
	/// `None` for a round's leaf served without its record (its participation
	/// is followed instead); `Err` with the reason it is not taken.
	fn restore_coin(&mut self, e: &Value, trees: &mut BTreeMap<(String, u32), (Value, Batch)>, now: MedianTime)
		-> Result<Option<(String, ValidCoin)>, String>
	{
		let id = e["leaf_id"].as_str().unwrap_or("").to_string();
		let kind = e["kind"].as_str().unwrap_or("");
		let bytes = unhex(e["record"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
		if bytes.is_empty() {
			return match kind {
				"batch" => Ok(None),
				"transfer" if e["state"] == "pending" => Err("the transfer that makes it is recorded at the server and not co-signed: there is no \
					coin yet, and the wallet restored from its mnemonic holds no request to post again".into()),
				_ => Err(format!("the server serves this {} without its record: withheld; nothing is credited for it", kind)),
			};
		}
		let served = CoinRecord::from_bytes(&bytes).map_err(|e| format!("the record does not decode: {}", e))?;
		let (owner, nonce) = owner_of(&served);
		if e["owner"].as_str().is_some_and(|o| o != hex(&owner.serialize())) || e["owner_nonce"].as_str().is_some_and(|n| n != hex(&nonce)) {
			return Err("the server names another owner key or nonce than the record does".into());
		}
		let mine = self.keys.leaf_xonly(&nonce).map_err(|e| e.to_string())?;
		if mine != owner {
			return Err(format!("a leaf of another key: the record's owner key {} is not the key this wallet derives from its owner nonce {} ({})",
				owner, hex(&nonce), mine));
		}
		if let Some(n) = self.store.nonce(&nonce).map_err(|e| e.to_string())? {
			if n.leaf_id.as_deref().is_some_and(|l| l != id) {
				return Err(format!("a second coin for the single-use key {} (the wallet holds {})", owner, n.leaf_id.unwrap_or_default()));
			}
		}
		if kind_of(&served) != kind {
			return Err(format!("the server names it a {}, its record a {}", kind, kind_of(&served)));
		}
		// A round's leaf: as the published tree builds it, with its
		// authorisations signed again.
		let record = match NewRecord::of_coin(&served) {
			Some((record, preimage, _)) => {
				let b = &e["batch"];
				let txid = b["round_txid"].as_str().ok_or("a round's leaf served without its round")?.to_string();
				let (vout, index) = (b["batch_vout"].as_u64().unwrap_or(u64::MAX) as u32, b["leaf_index"].as_u64().unwrap_or(u64::MAX) as usize);
				let (coin, built) = self.leaf_from_tree(trees, &txid, vout, index, &nonce, Some(preimage), now)?;
				if built != record {
					return Err(format!("the record served is not leaf {} of the published tree of {}:{}", index, txid, vout));
				}
				coin
			},
			None => served.clone(),
		};
		// A coin made out of round rests on the operator's machine until the
		// head of its signer's record is held outside it.
		if matches!(record, CoinRecord::Transfer(_)) {
			if let Err(why) = self.held_outside(&e["made_by"]["signer_record"]) {
				return Err(format!("{}: the coin is not taken (the mailbox read takes it once its head comes with them)", why));
			}
		}
		self.take_served_bases(e);
		let a = self.checked_as_held(&record, &owner, &nonce, now)?;
		let (state, note) = if a.all_final() { ("live", String::new()) } else { ("pending", format!("waiting: {}", a.waiting())) };
		let row = self.row(&record, &a, state, &note).map_err(|e| e.to_string())?;
		let coin = a.valid.clone();
		let entry_head = e["made_by"]["signer_record"].clone();
		self.store.atomically(|s| {
			if s.nonce(&nonce)?.is_none() {
				s.put_nonce(&nonce, &owner.serialize(), "restored")?;
			}
			s.put_coin(&row)?;
			s.use_nonce(&nonce, &id)
		}).map_err(|e| e.to_string())?;
		if matches!(record, CoinRecord::Transfer(_)) {
			if let Err(err) = self.keep_coin_head(&id, &entry_head) {
				let _ = self.store.refused(&format!("the head of restored coin {}", id), &err.to_string());
			}
		} else if !e["batch"]["signer_record"].is_null() {
			let _ = self.witness_record(&e["batch"]["signer_record"], false);
		}
		Ok(Some((state.to_string(), coin)))
	}

	/// Every leaf the server serves to the mailbox key, a page at a time, and
	/// the payments into the tree asked under it (D70); with a note when the
	/// read stopped short.
	fn read_served(&self) -> Result<(Vec<Value>, Vec<Value>, Option<String>), Error> {
		let mailbox = self.keys.mailbox()?;
		let mut entries: Vec<Value> = vec![];
		let mut served_receives: Vec<Value> = vec![];
		let mut after = 0i64;
		let mut read_note: Option<String> = None;
		let mut pages = 0;
		loop {
			if pages >= LEAF_DATA_PAGES {
				read_note = Some(format!("the server names more than {} pages of leaves: the restore reads no further, and takes what it read",
					LEAF_DATA_PAGES));
				break;
			}
			pages += 1;
			let page = self.server.leaf_data(&mailbox, &self.genesis, after, LEAF_PAGE)?;
			if after == 0 {
				served_receives = page["receives"].as_array().cloned().unwrap_or_default();
			}
			let leaves = page["leaves"].as_array().cloned().unwrap_or_default();
			if leaves.is_empty() {
				break;
			}
			// Every leaf of a page lies past the cursor asked, and the next
			// cursor past every one: a page that serves again what was read,
			// or names a next that does not advance past it, ends the read.
			let cursors: Vec<i64> = leaves.iter().filter_map(|l| l["cursor"].as_str().and_then(|c| c.parse::<i64>().ok())).collect();
			if cursors.iter().any(|c| *c <= after) {
				read_note = Some(format!("the server serves leaves at or before the cursor asked ({}) again: the restore reads no further, \
					and takes what it read", after));
				break;
			}
			entries.extend(leaves);
			let last = cursors.iter().copied().max().unwrap_or(after);
			match page["next"].as_str().and_then(|n| n.parse::<i64>().ok()) {
				Some(n) if n > after && n >= last => after = n,
				Some(n) => {
					read_note = Some(format!("the server names a next page at cursor {}, not past the page it served (to {}): the restore reads \
						no further, and takes what it read", n, last));
					break;
				},
				None => break,
			}
		}
		Ok((entries, served_receives, read_note))
	}

	/// The coin passes of a restore over what the server serves: each coin
	/// the store does not hold, checked and taken; how each was given up, on
	/// its owner's own signatures; what the wallet's own records say of the
	/// coins they spend; and the participations in their forfeit step.
	///
	/// `catching_up` ([`Self::catch_up`]): a store that holds coins already,
	/// another store of the mnemonic live beside it. A coin it holds as live
	/// or pending that the server serves as given up in a transfer the
	/// operator co-signed, or in a participation the operator released and
	/// this store never made, is given up as the restore gives
	/// it up (`given_elsewhere`); and a coin it could not take is said, not
	/// recorded as refused again, since it is looked at again next time; and
	/// a coin under a nonce this store drew is left to its mailbox read.
	fn take_served(&mut self, info: &Value, entries: &[Value], served_receives: &[Value], catching_up: bool,
		mut steps: Option<&mut super::exit::Steps>) -> Result<TakenServed, Error>
	{
		// A restore checks the keepers over everything served before it splits
		// it, and its history's steps take what that restore checked.
		if catching_up {
			self.keepers_acknowledged(info, entries)?;
			self.no_foreign_acks(info, entries)?;
		}
		let now = self.now()?;
		let mut not_recovered: Vec<Value> = vec![];
		let mut restored: Vec<Value> = vec![];
		let mut taken: BTreeMap<String, Taken> = BTreeMap::new();
		let mut trees: BTreeMap<(String, u32), (Value, Batch)> = BTreeMap::new();

		// The transactions the server names for every coin to be checked,
		// with where each is and its block's header, read together in a few
		// batches ahead of the checks, which then find them read: the checks
		// are the same, only the requests that make them fewer.
		// The published trees of their rounds are asked of the operator
		// first, each once, so that the chain is read after the last request
		// to the operator rather than looked at again after each one.
		let mut named: BTreeSet<Txid> = BTreeSet::new();
		let mut batches: BTreeSet<(String, u32)> = BTreeSet::new();
		for e in entries {
			if self.store.coin(e["leaf_id"].as_str().unwrap_or(""))?.is_none() && !(catching_up && self.drew_nonce_of(e)?) {
				named.extend(Self::served_bases(e).iter().filter_map(|t| Txid::from_str(t).ok()));
				for g in e["given"].as_array().into_iter().flatten() {
					for f in g["participation"]["forfeits"].as_array().into_iter().flatten() {
						named.extend(f["round_txid"].as_str().and_then(|t| Txid::from_str(t).ok()));
					}
				}
				let b = &e["batch"];
				if let (Some(t), Some(v), false) = (b["round_txid"].as_str(), b["batch_vout"].as_u64(), e["record"].as_str().unwrap_or("").is_empty()) {
					batches.insert((t.to_string(), v as u32));
				}
			}
		}
		for (t, v) in &batches {
			let _ = self.published_tree(&mut trees, t, *v);
		}
		self.chain.read_ahead_of(&named.into_iter().collect::<Vec<_>>(), &[]);

		// Every coin served with a record, checked; the same leaf served twice
		// is looked at once, its first copy.
		let mut seen = BTreeSet::new();
		// Coins this store holds that another store of the mnemonic gave up.
		let mut elsewhere: BTreeMap<String, Taken> = BTreeMap::new();
		for e in entries {
			let id = e["leaf_id"].as_str().unwrap_or("").to_string();
			if !seen.insert(id.clone()) {
				not_recovered.push(missed(&id, "the server serves this leaf twice: the wallet looked at its first copy alone"));
				continue;
			}
			if let Some(c) = self.store.coin(&id)? {
				if catching_up && matches!(c.state.as_str(), "live" | "pending") && self.given_elsewhere(e)? {
					if let Some(coin) = self.held_valid(&c, now) {
						elsewhere.insert(id, Taken { entry: e.clone(), coin });
					}
				}
				continue;
			}
			// A coin under a nonce this store drew is its own mailbox's to
			// take, with its arrival; a catch-up takes the other stores'.
			if catching_up && self.drew_nonce_of(e)? {
				continue;
			}
			match self.restore_coin(e, &mut trees, now) {
				Ok(Some((row_state, coin))) => {
					restored.push(json!({"leaf_id": id, "kind": e["kind"], "asset": coin.asset.to_string(), "value": coin.value.to_string(),
						"state": row_state}));
					taken.insert(id, Taken { entry: e.clone(), coin });
				},
				Ok(None) => {},
				Err(why) => {
					if !catching_up {
						self.store.refused(&format!("restore of coin {}", id), &why)?;
					}
					not_recovered.push(missed(&id, why));
				},
			}
		}

		if let Some(st) = steps.as_deref_mut() { st.lap(self, "coins"); }
		// The coins a coin taken spends, by the transfer that made it: a
		// received leaf is spent by its claim only once the wallet holds a coin
		// the claim made, checked.
		let mut spent_by_held: BTreeMap<String, Option<String>> = BTreeMap::new();
		for t in taken.values() {
			if let ValidOrigin::Transfer { inputs, .. } = &t.coin.origin {
				let tid = t.entry["made_by"]["transfer_id"].as_str().unwrap_or("").to_string();
				for i in inputs {
					spent_by_held.insert(i.coin.id.to_string(), Some(tid.clone()));
				}
			}
		}
		// And by a coin held before, which a restore's history step finds
		// held (the coin a claim made, taken at the restore or a step
		// before).
		if !catching_up && !taken.is_empty() {
			let mut wanted: BTreeSet<[u8; 32]> = BTreeSet::new();
			for id in taken.keys() {
				wanted.extend(self.store.coin(id)?.map(|c| c.owner_nonce));
			}
			let skip: BTreeSet<String> = taken.keys().cloned().collect();
			for (k, v) in self.held_spenders(&wanted, &skip, now)? {
				spent_by_held.entry(k).or_insert(v);
			}
		}

		// How each was given up, on its owner's own signatures.
		let mut notes: Vec<Value> = vec![];
		for (id, t) in &taken {
			notes.extend(self.restore_given(id, &t.entry, &t.coin, now, &spent_by_held)?);
		}
		let mut given_elsewhere: Vec<Value> = vec![];
		for (id, t) in &elsewhere {
			notes.extend(self.restore_given(id, &t.entry, &t.coin, now, &spent_by_held)?);
			if let Some(c) = self.store.coin(id)? {
				if c.state != "live" {
					given_elsewhere.push(json!({"leaf_id": id, "asset": t.coin.asset.to_string(), "value": t.coin.value.to_string(),
						"state": c.state}));
				}
			}
		}

		if let Some(st) = steps.as_deref_mut() { st.lap(self, "given"); }
		// A leaf the lost wallet took home: its own output on the chain, found
		// and followed as an exit would (its claim, a forfeit or a checkpoint
		// that took it, or the exit to go on), never held live.
		// The batch outputs and boards every coin rests on are read together,
		// in one request, and judged at once: a coin whose every one stands
		// has nothing of its lineage on the chain ([`Chain::descendants_from`]
		// answers the same), and only the others are looked at one by one.
		let mut roots: BTreeSet<elements::OutPoint> = BTreeSet::new();
		for (id, t) in &taken {
			if self.store.coin(id)?.is_some_and(|c| matches!(c.state.as_str(), "live" | "pending")) {
				roots.extend(t.coin.roots());
			}
		}
		let standing = self.chain.unspent_of(&roots.into_iter().collect::<Vec<_>>())?;
		// The others' own outputs are looked for together, in one pass over
		// the blocks from the lowest height any of them can be at: a wallet
		// with a long history has hundreds of coins resting on a batch
		// output reclaimed or a board converted since, and a pass each read
		// and decoded the same blocks once for every coin.
		let from = self.store.meta("birthday")?.and_then(|b| b.parse::<u64>().ok()).unwrap_or(0).saturating_sub(1000);
		let mut wanted: Vec<(&String, &ValidCoin, u64)> = vec![];
		for (id, t) in &taken {
			if t.coin.roots().iter().all(|r| standing.contains(r)) {
				continue;
			}
			if self.store.coin(id)?.is_some_and(|c| matches!(c.state.as_str(), "live" | "pending")) {
				if let Some(lowest) = self.chain.descendants_from(&t.coin.roots(), from)? {
					wanted.push((id, &t.coin, from.max(lowest)));
				}
			}
		}
		let outputs: Vec<(elements::TxOut, u64)> = wanted.iter().map(|(_, c, h)| (c.output().txout(), *h)).collect();
		let found = self.chain.find_payments(&outputs)?;
		for ((id, coin, _), paid) in wanted.into_iter().zip(found) {
			let Some((tx, h)) = paid else { continue };
			if self.store.coin(id)?.is_some_and(|c| matches!(c.state.as_str(), "live" | "pending")) {
				notes.push(self.restore_on_chain(id, coin, tx, h)?);
			}
		}

		if let Some(st) = steps.as_deref_mut() { st.lap(self, "on_chain"); }
		// A leaf that went over Lightning and is not given up on its owner's
		// signature: as the payment stands. A received leaf whose claim the
		// server recorded and has not co-signed (`sending`) is held as
		// handed over too, with its home date (D68): the transfer the lost
		// wallet posted is not the restored wallet's to post again, and the
		// leaf comes home by its claim unless the operator co-signs one.
		for (id, t) in &taken {
			let Some(h) = t.coin.leaf.htlc else { continue };
			let receive = h.direction == arca_covenant::HtlcDirection::Receive;
			if self.store.coin(id)?.is_some_and(|c| matches!(c.state.as_str(), "live" | "pending") || (receive && c.state == "sending")) {
				notes.push(self.restore_htlc(id, &t.coin, h, &info, now)?);
			}
		}

		if let Some(st) = steps.as_deref_mut() { st.lap(self, "htlc"); }
		// D70: the payments into the tree asked under the mailbox key and not
		// yet claimed, whose leaf is not held yet (held, wanted in a round, or
		// made and not yet released): each rebuilt from what the server serves,
		// checked against the mnemonic, and taken up by `sync`.
		for r in served_receives {
			match self.restore_receive(r, &info) {
				Ok(Some(n)) => notes.push(n),
				Ok(None) => {},
				Err(why) => {
					let hash = r["payment_hash"].as_str().unwrap_or("").to_string();
					if !catching_up {
						self.store.refused(&format!("restore of the payment received under hash {}", hash), &why)?;
					}
					not_recovered.push(json!({"payment_hash": hash, "why": why}));
				},
			}
		}

		if let Some(st) = steps.as_deref_mut() { st.lap(self, "receives"); }
		// What the wallet's own records say, whatever the server says of the
		// coins they rest on: every coin a held coin's record spends was
		// spent by the transfer that made it, which the operator co-signed.
		for t in taken.values() {
			let ValidOrigin::Transfer { inputs, .. } = &t.coin.origin else { continue };
			let tid = t.entry["made_by"]["transfer_id"].as_str().unwrap_or("").to_string();
			for i in inputs {
				let Some(c) = self.store.coin(&i.coin.id.to_string())? else { continue };
				if c.state == "spent" {
					continue;
				}
				let why = format!("the server serves coin {} as {}, an old copy: the record of coin {}, which the operator co-signed, shows it \
					spent by transfer {}", c.leaf_id, if c.state == "live" { "unspent" } else { &c.state }, t.coin.id, tid);
				self.store.set_coin_spent(&c.leaf_id, &format!("transfer {}", tid))?;
				if catching_up {
					// Held here, given up by another store of the mnemonic.
					given_elsewhere.push(json!({"leaf_id": c.leaf_id, "asset": c.asset, "value": c.value.to_string(), "state": "spent"}));
				} else {
					self.store.refused(&format!("restore of coin {}", c.leaf_id), &why)?;
				}
				notes.push(json!({"leaf_id": c.leaf_id, "note": why}));
			}
		}

		if let Some(st) = steps.as_deref_mut() { st.lap(self, "records"); }
		// Participations in their forfeit step: the new leaves validated as
		// before their forfeits were signed; and the new leaves of released
		// ones that the server does not serve, from the published tree.
		notes.extend(self.restore_participations(&mut trees, now, &mut restored, &mut not_recovered)?);
		if let Some(st) = steps.as_deref_mut() { st.lap(self, "participations"); }
		Ok(TakenServed { restored, not_recovered, notes, given_elsewhere })
	}

	/// Whether every output `wanted` names is an offboard and round `rtx` is
	/// final in the chain: a released participation that wanted no leaf has
	/// no preimage to wait for, its offboard output being the round's,
	/// unlocked into the address by the operator or, past its grace, by the
	/// wallet that made it.
	fn offboards_final(&self, wanted: &Value, rtx: &str) -> Result<bool, Error> {
		let Some(ws) = wanted.as_array().filter(|a| !a.is_empty()) else { return Ok(false) };
		if !ws.iter().all(|w| w.get("offboard").is_some_and(|o| o.is_object())) {
			return Ok(false);
		}
		let Ok(t) = Txid::from_str(rtx) else { return Ok(false) };
		Ok(self.chain.finality(&t)?.is_final())
	}

	/// Whether the server serves coin `e` as given up in a way that is final
	/// and not this store's own: a transfer the operator co-signed, or a
	/// participation the operator released that this store never made.
	/// Checked on the owner's signatures by [`Self::restore_given`].
	fn given_elsewhere(&self, e: &Value) -> Result<bool, Error> {
		for g in e["given"].as_array().cloned().unwrap_or_default() {
			if g["transfer"]["state"] == "signed" {
				return Ok(true);
			}
			let p = &g["participation"];
			if p["state"] == "released" && self.store.participation_state(p["participation_id"].as_str().unwrap_or(""))?.is_none() {
				return Ok(true);
			}
		}
		Ok(false)
	}

	/// Whether this store drew the owner nonce served coin `e` names.
	fn drew_nonce_of(&self, e: &Value) -> Result<bool, Error> {
		let Ok(nonce) = unhex32(e["owner_nonce"].as_str().unwrap_or("")) else { return Ok(false) };
		Ok(self.store.nonce(&nonce)?.is_some())
	}

	/// A coin the store holds, checked as held, if it still checks.
	fn held_valid(&self, c: &super::store::CoinRow, now: MedianTime) -> Option<ValidCoin> {
		let record = Self::record_of(c).ok()?;
		let bases = self.accepted_bases(&record).ok()?;
		self.resolve(&record, &bases, &self.followed_policy(c.expiry, now)).ok()
	}

	/// What other stores of the mnemonic did since this one last looked, from
	/// what the server serves to the mailbox key, checked as a restore checks
	/// it: every coin this store does not hold under a nonce it never drew
	/// (another store's; its own are its mailbox's), taken; and every coin it holds
	/// that another store gave up, on the owner's own signatures, given up
	/// here too (`given_elsewhere`), so every store of the mnemonic shows the
	/// same coins. `sync` runs it at most once every ten minutes; the coins
	/// held stay as they are while it runs.
	pub fn catch_up(&mut self) -> Result<Value, Error> {
		let info = self.server_info()?;
		let (entries, served_receives, read_note) = self.read_served()?;
		// The coins a restore left to its history steps are theirs: a catch-up
		// would otherwise check them all at once.
		let listed = self.history_ids()?;
		let entries: Vec<Value> = entries.into_iter().filter(|e| !listed.contains(e["leaf_id"].as_str().unwrap_or(""))).collect();
		let TakenServed { mut restored, not_recovered, notes, given_elsewhere } =
			self.take_served(&info, &entries, &served_receives, true, None)?;
		let now = self.now()?;
		self.store.set_meta(CAUGHT_UP, &now.to_consensus_u32().to_string())?;
		for v in restored.iter_mut() {
			if let Some(c) = self.store.coin(v["leaf_id"].as_str().unwrap_or(""))? {
				v["state"] = json!(c.state);
			}
		}
		let mut out = json!({"served": entries.len(), "restored": restored, "given_elsewhere": given_elsewhere,
			"not_taken": not_recovered, "notes": notes});
		if let Some(n) = read_note {
			out["note"] = json!(n);
		}
		Ok(out)
	}

	/// Whether the server serves coin `e` as given up for good: in a
	/// transfer the operator co-signed, or in a participation it released.
	/// Its word decides only when the coin is checked, never whether: the
	/// coin is checked with every other check later
	/// ([`Self::restore_history`]).
	fn given_for_good(e: &Value) -> bool {
		e["given"].as_array().into_iter().flatten()
			.any(|g| g["transfer"]["state"] == "signed" || g["participation"]["state"] == "released")
	}

	/// The coins served (`entries`) split in two: those a restore checks at
	/// once, and its history, checked a step at each `sync` after. The
	/// history is every coin the server serves as given up for good, and
	/// every coin a record it serves names as an input of a transfer (by
	/// the owner key and nonce of the input, which the wallet's keys use
	/// once; the coin's own record aside), whatever the server says of it:
	/// a coin that may be spent is counted only once the records that may
	/// spend it are checked. A leaf received over Lightning is checked at
	/// once whatever is served of it: its claim decides where it stands.
	fn split_history(&self, entries: &[Value]) -> Result<(Vec<Value>, Vec<Value>), Error> {
		let record = |e: &Value| unhex(e["record"].as_str().unwrap_or("")).ok().filter(|b| !b.is_empty())
			.and_then(|b| CoinRecord::from_bytes(&b).ok());
		// Each input key named, with the coins whose records name it.
		let mut named: BTreeMap<[u8; 32], BTreeSet<String>> = BTreeMap::new();
		for e in entries {
			if let Some(r @ CoinRecord::Transfer(_)) = record(e) {
				for p in r.parents() {
					named.entry(owner_of(p).1).or_default().insert(e["leaf_id"].as_str().unwrap_or("").to_string());
				}
			}
		}
		let (mut now, mut later) = (vec![], vec![]);
		// The coins of the history whose records name each coin.
		let mut namers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
		// A coin held already (a restore run again, after one cut short) is
		// split as any other: one of the history is settled by how it was
		// given up ([`Self::settle_held_history`]), never left counted.
		for e in entries {
			let id = e["leaf_id"].as_str().unwrap_or("");
			let by: BTreeSet<String> = record(e).and_then(|r| named.get(&owner_of(&r).1).cloned()).unwrap_or_default()
				.into_iter().filter(|b| b != id).collect();
			if !record(e).as_ref().is_some_and(Self::received_htlc) && (Self::given_for_good(e) || !by.is_empty()) {
				namers.insert(id.to_string(), by);
				later.push(e.clone());
			} else {
				now.push(e.clone());
			}
		}
		// A coin of the history that a record taken at once names as an input
		// (a transfer's, a fill's) is taken at once with it: a coin is judged
		// beside the coins it was made from (a trade that can never complete
		// starts the return of the coin given into it, a claim spends the
		// leaf it claims), as a restore that takes everything at once judges
		// it.
		let mut parents: BTreeSet<[u8; 32]> = BTreeSet::new();
		for e in &now {
			if let Some(r) = record(e) {
				parents.extend(r.parents().into_iter().map(|p| owner_of(p).1));
			}
		}
		// And a coin of the history whose record spends a leaf received over
		// Lightning that is taken at once: the leaf is spent by its claim only
		// once the wallet holds a coin the claim made (D68), so that coin is
		// judged with it, or the leaf would be counted until its step.
		let received: BTreeSet<[u8; 32]> = now.iter().filter_map(|e| record(e)).filter(Self::received_htlc)
			.map(|r| owner_of(&r).1).collect();
		let (mut moved, kept): (Vec<Value>, Vec<Value>) = later.into_iter()
			.partition(|e| record(e).is_some_and(|r| parents.contains(&owner_of(&r).1)
				|| r.parents().iter().any(|p| received.contains(&owner_of(p).1))));
		later = kept;
		// A coin taken at once is never named by a record left to the
		// history: the records that spend a moved coin move with it, and
		// theirs with them, as a restore that takes everything at once judges
		// a coin beside the records that spend it.
		let mut up: BTreeSet<[u8; 32]> = moved.iter().filter_map(|e| record(e)).map(|r| owner_of(&r).1).collect();
		loop {
			let (more, kept): (Vec<Value>, Vec<Value>) = later.into_iter()
				.partition(|e| record(e).is_some_and(|r| r.parents().iter().any(|p| up.contains(&owner_of(p).1))));
			later = kept;
			if more.is_empty() {
				break;
			}
			up.extend(more.iter().filter_map(|e| record(e)).map(|r| owner_of(&r).1));
			moved.extend(more);
		}
		for e in &moved {
			namers.remove(e["leaf_id"].as_str().unwrap_or(""));
		}
		now.append(&mut moved);
		// A coin of the history comes after every coin of the history whose
		// record names it, so the coin a claim or a transfer made is held
		// before the coin it spends is judged ([`Self::restore_given`]).
		let mut ordered = vec![];
		let mut placed: BTreeSet<String> = BTreeSet::new();
		let in_history: BTreeSet<String> = namers.keys().cloned().collect();
		while !later.is_empty() {
			let (mut ready, mut rest): (Vec<Value>, Vec<Value>) = later.into_iter().partition(|e| {
				namers.get(e["leaf_id"].as_str().unwrap_or("")).is_none_or(|by| by.iter().all(|b| placed.contains(b) || !in_history.contains(b)))
			});
			// Records naming each other in a ring cannot be: whatever is left
			// then goes last, in the order served.
			if ready.is_empty() {
				ready = std::mem::take(&mut rest);
			}
			for e in &ready {
				placed.insert(e["leaf_id"].as_str().unwrap_or("").to_string());
			}
			ordered.extend(ready);
			later = rest;
		}
		Ok((now, ordered))
	}

	/// Whether `record` is a leaf received over Lightning (`htlc-1`, received):
	/// its claim decides where it stands, which only the restore's checks of
	/// it at once can judge (D68), whatever the server serves of it.
	fn received_htlc(record: &CoinRecord) -> bool {
		let htlc = match record {
			CoinRecord::Leaf { record, .. } => record.leaf().htlc,
			CoinRecord::Accumulator { record, .. } => record.leaf().htlc,
			CoinRecord::Board(b) => b.leaf().htlc,
			CoinRecord::Transfer(t) => t.leaf.htlc,
			CoinRecord::Fill(_) => None,
		};
		htlc.is_some_and(|h| h.direction == arca_covenant::HtlcDirection::Receive)
	}

	/// Keeps `history` as the coins left to [`Self::restore_history`],
	/// those the store does not hold, in place of any list kept before.
	fn keep_history(&self, history: &[Value]) -> Result<(), Error> {
		let mut left = vec![];
		for e in history {
			if self.store.coin(e["leaf_id"].as_str().unwrap_or(""))?.is_none() {
				left.push(e.clone());
			}
		}
		if left.is_empty() {
			self.store.delete_meta(RESTORE_HISTORY)?;
			self.store.delete_meta(RESTORE_HISTORY_IDS)
		} else {
			let ids: Vec<Value> = left.iter().map(|e| e["leaf_id"].clone()).collect();
			self.store.set_metas(&[(RESTORE_HISTORY, Value::Array(left).to_string()), (RESTORE_HISTORY_IDS, Value::Array(ids).to_string())])
		}
	}

	fn history(&self) -> Result<Vec<Value>, Error> {
		Ok(self.store.meta(RESTORE_HISTORY)?.and_then(|v| serde_json::from_str::<Value>(&v).ok())
			.and_then(|v| v.as_array().cloned()).unwrap_or_default())
	}

	/// How many coins of a restore's history are left to check.
	/// Read from the ids alone, which are written with the list in one
	/// transaction: `balance` asks it at every read.
	pub(crate) fn history_left(&self) -> Result<usize, Error> {
		Ok(self.history_ids()?.len())
	}

	/// The ids of the coins a restore left to its history's steps.
	pub(crate) fn history_ids(&self) -> Result<BTreeSet<String>, Error> {
		Ok(self.store.meta(RESTORE_HISTORY_IDS)?.and_then(|v| serde_json::from_str::<Vec<String>>(&v).ok()).unwrap_or_default()
			.into_iter().collect())
	}

	/// One step of a restore's history: at most [`HISTORY_STEP`] of the
	/// coins it left, checked as the restore checks a coin (its record, its
	/// owner key, its tree, the chain, then how it was given up, on its
	/// owner's own signatures); then what the records of every coin held
	/// say of the coins they spend, and the birthday lowered to the oldest
	/// base. `None` when nothing is left. `sync` runs one step; a step that
	/// stops at an error keeps what it took, and the next takes the rest.
	pub fn restore_history(&mut self) -> Result<Option<Value>, Error> {
		let all = self.history()?;
		if all.is_empty() {
			return Ok(None);
		}
		let info = self.server_info()?;
		// A step cut short (the program closed, the link lost) may have taken
		// a coin and not yet applied how it was given up, and a participation
		// completed or a catch-up may have taken one of the list since: each
		// such coin is settled first, by its own served record, as a restore
		// that took everything at once settles it, so none is left counted.
		let (unheld, mut notes) = self.settle_held_history(&all)?;
		// The next coins of the list, those whose bases are in a block of the
		// active chain: a coin resting on a transaction an anchor-driven
		// reorganisation took out of the chain waits in the list until it is
		// mined again (or can never return), as it would have been taken
		// while it was in a block. Bitcoin anchoring decides, not the order.
		let ahead: Vec<Txid> = unheld.iter().take(2 * HISTORY_STEP).flat_map(Self::served_bases)
			.filter_map(|t| Txid::from_str(&t).ok()).collect();
		self.chain.read_ahead_of(&ahead, &[]);
		// The wait is bounded ([`HISTORY_WAIT_MOST`]): a transaction the
		// server names that never confirms (a lie, or one a reorganisation
		// left out for good) holds no coin in the list for ever; past the
		// bound the coin is taken as a restore that takes everything at once
		// takes it.
		let now = self.now()?.to_consensus_u32() as u64;
		let (mut step, mut waiting) = (vec![], 0usize);
		let mut later: Vec<Value> = vec![];
		for mut e in unheld {
			if step.len() >= HISTORY_STEP {
				later.push(e);
				continue;
			}
			if self.base_out_of_chain(&e)? {
				let since = e[WAITING_SINCE].as_u64().unwrap_or(now);
				if now.saturating_sub(since) < HISTORY_WAIT_MOST as u64 {
					e[WAITING_SINCE] = json!(since);
					waiting += 1;
					later.push(e);
					continue;
				}
			}
			step.push(e);
		}
		let TakenServed { mut restored, not_recovered, notes: taken_notes, given_elsewhere: _ } =
			self.take_served(&info, &step, &[], false, None)?;
		notes.extend(taken_notes);
		let (rest, settled) = self.settle_held_history(&later)?;
		notes.extend(settled);
		notes.extend(self.held_records_spend()?);
		self.lower_birthday(&[])?;
		self.keep_history(&rest)?;
		for v in restored.iter_mut() {
			if let Some(c) = self.store.coin(v["leaf_id"].as_str().unwrap_or(""))? {
				v["state"] = json!(c.state);
			}
		}
		let left = self.history_left()?;
		let mut out = json!({"checked": step.len(), "restored": restored, "not_recovered": not_recovered, "notes": notes,
			"left": left, "loading": left > 0});
		if waiting > 0 {
			out["waiting_for_the_chain"] = json!(waiting);
		}
		Ok(Some(out))
	}

	/// Whether a transaction coin `e` rests on, as the server names them, is
	/// in no block of the active chain and can still return to it (taken out
	/// by a reorganisation, back in the mempool or not): the coin waits. One
	/// the node does not know, or that can never return, does not wait: the
	/// coin's own check says what becomes of it.
	fn base_out_of_chain(&self, e: &Value) -> Result<bool, Error> {
		for t in Self::served_bases(e) {
			let Ok(txid) = Txid::from_str(&t) else { continue };
			if self.chain.tx_block(&txid)?.is_some() {
				continue;
			}
			if let Some(tx) = self.chain.transaction(&txid)? {
				if !self.chain.gone(&tx)? {
					return Ok(true);
				}
			}
		}
		Ok(false)
	}

	/// The coins that held coins' records spend in a transfer, among those
	/// of the owner nonces `wanted` (the held coins in `skip` aside): each
	/// record checked when its coin was taken, read as it stands now. Its
	/// record, which the operator co-signed, spends the coin whatever the
	/// server names the transfer (`None`).
	fn held_spenders(&self, wanted: &BTreeSet<[u8; 32]>, skip: &BTreeSet<String>, now: MedianTime)
		-> Result<BTreeMap<String, Option<String>>, Error>
	{
		let mut out = BTreeMap::new();
		for c in self.store.coins()? {
			if skip.contains(&c.leaf_id) {
				continue;
			}
			let Ok(record) = Self::record_of(&c) else { continue };
			if !matches!(record, CoinRecord::Transfer(_)) || !record.parents().iter().any(|p| wanted.contains(&owner_of(p).1)) {
				continue;
			}
			let Some(valid) = self.held_valid(&c, now) else { continue };
			let ValidOrigin::Transfer { inputs, .. } = &valid.origin else { continue };
			for i in inputs {
				out.entry(i.coin.id.to_string()).or_insert(None);
			}
		}
		Ok(out)
	}

	/// The coins of `list` (a restore's history) that the wallet holds now
	/// by another way than their own step (a participation completed takes
	/// its new leaves, a catch-up or the mailbox a coin): how each was given
	/// up, as the server serves it, applied at once on its owner's own
	/// signatures ([`Self::restore_given`]), so that a leaf a later transfer
	/// spent is never counted between two steps. Answers the coins still to
	/// check, and the notes.
	fn settle_held_history(&mut self, list: &[Value]) -> Result<(Vec<Value>, Vec<Value>), Error> {
		let now = self.now()?;
		let (mut held, mut rest) = (vec![], vec![]);
		for e in list {
			match self.store.coin(e["leaf_id"].as_str().unwrap_or(""))? {
				Some(c) => held.push((e.clone(), c)),
				None => rest.push(e.clone()),
			}
		}
		let mut notes = vec![];
		if held.is_empty() {
			return Ok((rest, notes));
		}
		let wanted: BTreeSet<[u8; 32]> = held.iter().map(|(_, c)| c.owner_nonce).collect();
		let spenders = self.held_spenders(&wanted, &BTreeSet::new(), now)?;
		for (e, c) in held {
			if !matches!(c.state.as_str(), "live" | "pending" | "sending") {
				continue;
			}
			let Some(coin) = self.held_valid(&c, now) else { continue };
			notes.extend(self.restore_given(&c.leaf_id, &e, &coin, now, &spenders)?);
		}
		Ok((rest, notes))
	}

	/// What the records of every coin the store holds say of the coins they
	/// spend, whatever the server says of those: each coin a held coin's
	/// record spends in a transfer, which the operator co-signed, is spent.
	/// A restore's own pass looks at the coins it took; the history steps
	/// take a record and the coin it spends in any order, so each looks at
	/// every coin held.
	fn held_records_spend(&mut self) -> Result<Vec<Value>, Error> {
		let coins = self.store.coins()?;
		let open: BTreeSet<[u8; 32]> = coins.iter().filter(|c| c.state != "spent").map(|c| c.owner_nonce).collect();
		let now = self.now()?;
		let mut notes = vec![];
		for c in &coins {
			let Ok(record) = Self::record_of(c) else { continue };
			if !matches!(record, CoinRecord::Transfer(_)) || !record.parents().iter().any(|p| open.contains(&owner_of(p).1)) {
				continue;
			}
			let Some(valid) = self.held_valid(c, now) else { continue };
			let ValidOrigin::Transfer { inputs, .. } = &valid.origin else { continue };
			for i in inputs {
				let Some(x) = self.store.coin(&i.coin.id.to_string())? else { continue };
				if x.state == "spent" {
					continue;
				}
				let why = format!("the server serves coin {} as {}, an old copy: the record of coin {}, which the operator co-signed, shows it \
					spent by the transfer that made it", x.leaf_id, if x.state == "live" { "unspent" } else { &x.state }, c.leaf_id);
				self.store.set_coin_spent(&x.leaf_id, &format!("the transfer that made coin {}", c.leaf_id))?;
				self.store.refused(&format!("restore of coin {}", x.leaf_id), &why)?;
				notes.push(json!({"leaf_id": x.leaf_id, "note": why}));
			}
		}
		Ok(notes)
	}

	/// Lowers the birthday to the block of the oldest base of a coin held,
	/// or of `more`: the chain is read from there on.
	fn lower_birthday(&self, more: &[Txid]) -> Result<(), Error> {
		let mut bases: BTreeSet<Txid> = self.store.coins()?.iter().flat_map(|c| c.bases.iter().filter_map(|b| Txid::from_str(b).ok()))
			.collect();
		bases.extend(more.iter().copied());
		let bases: Vec<Txid> = bases.into_iter().collect();
		self.chain.read_ahead_of(&bases, &[]);
		let mut lowest: Option<u64> = None;
		for t in &bases {
			if let Some((_, h)) = self.chain.tx_block(t)? {
				lowest = Some(lowest.map_or(h, |l| l.min(h)));
			}
		}
		if let Some(h) = lowest {
			let birthday: u64 = self.store.meta("birthday")?.and_then(|b| b.parse().ok()).unwrap_or(u64::MAX);
			if h < birthday {
				self.store.set_meta("birthday", &h.to_string())?;
			}
		}
		Ok(())
	}

	/// Whether `sync` catches up now ([`CATCH_UP_EVERY`]).
	pub(crate) fn catch_up_due(&self) -> Result<bool, Error> {
		let now = self.now()?.to_consensus_u32();
		let last: Option<u32> = self.store.meta(CAUGHT_UP)?.and_then(|v| v.parse().ok());
		Ok(last.map_or(true, |l| now.saturating_sub(l) >= CATCH_UP_EVERY || now < l))
	}

	/// The transactions the server names for coin `e` (`bases`: the batch
	/// outputs and boards a coin made out of round descends from; a round
	/// leaf's round; a board's own transaction), read by txid and taken as
	/// known bases. Without them a fresh store finds a base by the node's set
	/// of unspent outputs, and one spent since (a batch reclaimed after its
	/// leaves moved on) only by reading blocks. Hints only: each is taken
	/// only from the active chain, and used only where it pays an output the
	/// record names; one that does not read leaves the search as it was.
	fn take_served_bases(&mut self, e: &Value) {
		for t in Self::served_bases(e) {
			let Ok(txid) = Txid::from_str(&t) else { continue };
			match self.chain.transaction(&txid) {
				Ok(Some(tx)) => { let _ = self.hint_base(&tx); },
				_ => {},
			}
		}
	}

	/// The txids the server names for coin `e`: its bases, its round, its
	/// board's transaction.
	fn served_bases(e: &Value) -> Vec<String> {
		let mut named: Vec<String> = e["bases"].as_array().into_iter().flatten()
			.filter_map(|b| b["txid"].as_str().map(str::to_string)).collect();
		named.extend(e["batch"]["round_txid"].as_str().map(str::to_string));
		named.extend(e["board"]["txid"].as_str().map(str::to_string));
		named.sort();
		named.dedup();
		named
	}

	/// The coin `id` (`coin`), restored live, whose own output the chain
	/// holds: the lost wallet unrolled it. Its exit is taken up where the chain
	/// has it, the wallet's own claim recognised by the address it pays (one
	/// of the mnemonic's receive addresses): `exited` once that claim is
	/// final, `exiting` while it is not or the leaf waits for its claim, and
	/// as a forfeit or a co-signed checkpoint that took it says otherwise.
	/// `tx`, at height `h`, is the first transaction that pays the coin's
	/// output, found by the restore's pass over the blocks: the coin's output
	/// is made only by spends that start at the batch outputs and boards it
	/// rests on, so only coins with one of those spent are looked for, and
	/// from the lowest block holding one.
	fn restore_on_chain(&mut self, id: &str, coin: &ValidCoin, tx: elements::Transaction, h: u64) -> Result<Value, Error> {
		let out = coin.output().txout();
		let vout = tx.output.iter().position(|o| *o == out).expect("pays it") as u32;
		let leaf = elements::OutPoint::new(tx.txid(), vout);
		let mut prior = json!({"txs": [], "leaf": leaf.to_string()});
		let mut claim = None;
		if let Some((sp, _)) = self.chain.spender(&leaf, h)? {
			// The mnemonic's receive addresses, as far as the wallet has used
			// them and a gap beyond.
			let _ = self.onchain_coins()?;
			let end = self.store.indices(super::keys::RECEIVE)? + 20;
			for i in 0..end {
				let to = self.keys.onchain_script(super::keys::RECEIVE, i)?;
				if sp.output.iter().any(|o| o.script_pubkey == to) {
					prior["claim_index"] = json!(i);
					claim = Some(sp.txid().to_string());
					break;
				}
			}
		}
		self.store.set_exit(id, if claim.is_some() { "claimed" } else { "unrolling" }, &prior.to_string(), claim.as_deref())?;
		self.store.set_coin_state(id, "exiting", "its leaf is on the chain, taken home before the restore: the exit is followed where the \
			chain has it")?;
		let followed = self.exit(id, None).unwrap_or_else(|e| json!({"leaf_id": id, "error": e.to_string()}));
		let state = self.store.coin(id)?.map(|c| c.state).unwrap_or_default();
		Ok(json!({"leaf_id": id, "state": state, "note": format!("its leaf {} is on the chain: the lost wallet took it home; {}", leaf,
			followed)}))
	}

	/// D63: the `htlc-1` coin `id` (`coin`, of terms `h`), restored live, as its
	/// payment stands. A payment out of the tree the operator reports paid,
	/// with a preimage that opens the leaf's hash, is the operator's: the
	/// coin is spent by it. One it reports paying is followed (`paying`);
	/// one failed is taken back by the next `sync`, as the lost wallet would.
	/// A leaf received over Lightning is held `receiving` with its payment
	/// rebuilt from its terms and its nonce (the preimage derives from them):
	/// as the lost wallet may have handed its preimage over already, it is
	/// taken as handed over, so the payment is never called failed, `sync`
	/// claims it, and should the operator not co-sign it goes home by its
	/// claim at its home date. A restore never credits a leaf the operator
	/// may claim with a preimage it has. A restore past the received leaf's
	/// home date, or its timeout, cannot be sure to win the race with the
	/// operator's refund: it says so on the coin, and `sync` takes the leaf
	/// home at once.
	fn restore_htlc(&mut self, id: &str, coin: &ValidCoin, h: arca_covenant::HtlcTerms, info: &Value, now: MedianTime) -> Result<Value, Error> {
		let hash = hex(&h.payment_hash);
		match h.direction {
			arca_covenant::HtlcDirection::Send => {
				let p = self.server.post("lightning_send_status", &json!({"payment_hash": hash}));
				let state = p.as_ref().ok().and_then(|p| p["state"].as_str().map(str::to_string)).unwrap_or_default();
				let pre = p.as_ref().ok().and_then(|p| p["preimage"].as_str().and_then(|x| unhex32(x).ok()));
				let opens = pre.is_some_and(|x| arca_covenant::script::sha256(&x) == h.payment_hash);
				let mut rec = json!({"htlc_leaf_id": id, "asset": coin.asset.to_string(), "restored": true});
				if let Ok(p) = &p {
					for k in ["amount", "fee"] {
						rec[k] = p[k].clone();
					}
				}
				let note = match (state.as_str(), opens) {
					("paid", true) => {
						let pre = hex(&pre.expect("checked"));
						self.store.set_coin_spent(id, &format!("the payment over Lightning of hash {}, paid (preimage {})", hash, pre))?;
						rec["state"] = json!("paid");
						rec["preimage"] = json!(pre);
						"paid: the operator's, its preimage checked against the leaf's hash".to_string()
					},
					("failed", _) => {
						self.store.set_coin_state(id, "paying", &format!("the htlc-1 leaf of the payment of hash {}: failed, taken back by sync", hash))?;
						rec["state"] = json!("failed");
						rec["reason"] = p.as_ref().map(|p| p["reason"].clone()).unwrap_or(Value::Null);
						"failed: sync takes the leaf back".to_string()
					},
					(s, _) => {
						self.store.set_coin_state(id, "paying", &format!("the htlc-1 leaf of the payment of hash {}: the operator is paying the \
							invoice", hash))?;
						rec["state"] = json!("paying");
						match p {
							Err(e) => format!("the operator does not say how it stands ({}): followed as paying", e),
							Ok(_) if s == "paid" => "the operator says paid with a preimage that does not open the leaf's hash: followed as paying"
								.to_string(),
							Ok(_) => "paying: followed by sync".to_string(),
						}
					},
				};
				self.set_send(&hash, rec)?;
				Ok(json!({"leaf_id": id, "payment_hash": hash, "note": format!("a payment over Lightning out of the tree: {}", note)}))
			},
			arca_covenant::HtlcDirection::Receive => {
				let row = self.store.coin(id)?.ok_or_else(|| Error::Store(format!("no coin {}", id)))?;
				let nonce = row.owner_nonce;
				if hex(&arca_covenant::script::sha256(&self.receive_preimage(&nonce)?)) != hash {
					// A hash the wallet did not make (a swap's): held for its
					// preimage, which the operator serves once it knows it,
					// and counted nowhere until then.
					let note = format!("the leaf received over Lightning under hash {}, a hash this wallet did not make: held for its \
						preimage, which sync takes from the operator once it knows it, then claims the leaf", hash);
					self.store.set_coin_state(id, "receiving", &note)?;
					let rec = json!({"state": "issuing", "nonce": hex(&nonce), "asset": coin.asset.to_string(), "value": coin.value.to_string(),
						"participation": hex(&super::lightning::receive_participation_id(&h.payment_hash)), "timeout": h.timeout.to_consensus_u32(),
						"hash_given": true, "restored": true,
						"window": info["lightning"]["receive"]["window_seconds"].as_u64().unwrap_or(6 * 3600)});
					self.set_receive(&hash, rec)?;
					return Ok(json!({"leaf_id": id, "payment_hash": hash, "note": note}));
				}
				let block = info["lightning"]["receive"]["block_seconds"].as_u64().unwrap_or(60).max(1);
				let timeout = h.timeout.to_consensus_u32() as u64;
				let (_, a) = self.held(&row)?;
				let (home_at, margin) = self.receive_home(coin, &a.bases, timeout, block)?;
				let at = now.to_consensus_u32() as u64;
				let late = if at >= timeout {
					Some(format!("restored too late to win: past the leaf's timeout (median time {}), when the operator's refund opens; sync \
						takes it home by its claim at once, which the operator's refund may take first", timeout))
				} else if at >= home_at {
					Some(format!("restored too late to be sure to win: past the leaf's home date (median time {}), {} s before its timeout \
						(median time {}), when the operator's refund opens; sync takes it home by its claim at once, which may come after \
						the refund opens", home_at, timeout - at, timeout))
				} else {
					None
				};
				let note = match &late {
					Some(l) => format!("the leaf of the payment received over Lightning under hash {}, {}", hash, l),
					None => format!("the leaf of the payment received over Lightning under hash {}, restored: sync claims it, and takes it home \
						by its claim at its home date (median time {}) should the operator not co-sign", hash, home_at),
				};
				self.store.set_coin_state(id, "receiving", &note)?;
				let mut rec = json!({"state": "claiming", "nonce": hex(&nonce), "asset": coin.asset.to_string(),
					"value": coin.value.to_string(), "participation": hex(&super::lightning::receive_participation_id(&h.payment_hash)),
					"timeout": timeout, "home_at": home_at, "margin": margin, "restored": true,
					"window": info["lightning"]["receive"]["window_seconds"].as_u64().unwrap_or(6 * 3600)});
				if let Some(l) = &late {
					rec["late"] = json!(l);
				}
				self.set_receive(&hash, rec)?;
				Ok(json!({"leaf_id": id, "payment_hash": hash, "note": note}))
			},
		}
	}

	/// D70: a payment into the tree the server serves (`r`, from `leaf_data`)
	/// as asked under the mailbox key and not yet claimed, rebuilt so that
	/// `sync` takes its leaf up as the lost wallet would have: its key must be
	/// the one the mnemonic derives from the nonce it names, the preimage the
	/// wallet derives from them must open its hash, and its invoice must be
	/// for that hash, asset and amount, the operator's fee within the
	/// wallet's default bound. Kept `waiting`: the next `sync` asks the
	/// operator how it stands and follows the participation that wants its
	/// leaf as its own. `None` for one the wallet holds already.
	fn restore_receive(&mut self, r: &Value, info: &Value) -> Result<Option<Value>, String> {
		let hash = r["payment_hash"].as_str().unwrap_or("").to_string();
		if self.receives().map_err(|e| e.to_string())?.contains_key(&hash) {
			return Ok(None);
		}
		let nonce = unhex32(r["owner_nonce"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
		let owner = self.keys.leaf_xonly(&nonce).map_err(|e| e.to_string())?;
		if r["owner"].as_str() != Some(&hex(&owner.serialize())) {
			return Err(format!("the server serves a payment received under hash {} for a key this wallet does not derive from the nonce it \
				names", hash));
		}
		// A hash the wallet did not make (a swap's) is held for its preimage.
		let preimage = self.receive_preimage(&nonce).map_err(|e| e.to_string())?;
		let given = hex(&arca_covenant::script::sha256(&preimage)) != hash;
		let asset = AssetId::from_str(r["asset"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
		let asked = amount(&r["amount"], "an amount").map_err(|e| e.to_string())?;
		let fee = amount(&r["fee"], "a fee").map_err(|e| e.to_string())?;
		let invoice = r["invoice"].as_str().unwrap_or("").to_string();
		let inv = super::lightning::parse_invoice(&invoice).map_err(|e| e.to_string())?;
		if hex(&inv.payment_hash) != hash || inv.asset != Some(asset) || inv.amount_msat != Some(asked.saturating_mul(1000)) {
			return Err(format!("the invoice served for the payment received under hash {} is not for that hash, asset and amount", hash));
		}
		if fee >= asked || !super::round::fee_within(fee, asked, super::DEFAULT_MAX_FEE_PPM) {
			return Err(format!("the operator's fee of {} for the payment received under hash {} of {} is above the wallet's bound of {} ppm",
				fee, hash, asked, super::DEFAULT_MAX_FEE_PPM));
		}
		if self.store.nonce(&nonce).map_err(|e| e.to_string())?.is_none() {
			self.store.put_nonce(&nonce, &owner.serialize(), "lightning-receive").map_err(|e| e.to_string())?;
		}
		let window = info["lightning"]["receive"]["window_seconds"].as_u64().unwrap_or(6 * 3600);
		let mut rec = json!({"state": "waiting", "nonce": hex(&nonce), "asset": asset.to_string(), "amount": asked.to_string(),
			"fee": fee.to_string(), "value": (asked - fee).to_string(), "invoice": invoice, "max_fee_ppm": super::DEFAULT_MAX_FEE_PPM,
			"window": window, "restored": true});
		if given {
			rec["hash_given"] = json!(true);
			if let Some(p) = r["preimage"].as_str().filter(|p| unhex32(p).is_ok_and(|b| hex(&arca_covenant::script::sha256(&b)) == hash)) {
				rec["preimage"] = json!(p);
			}
		}
		self.set_receive(&hash, rec).map_err(|e| e.to_string())?;
		Ok(Some(json!({"payment_hash": hash, "state": r["state"], "note": "a payment received over Lightning and not yet claimed, restored \
			waiting: sync asks how it stands, takes up the participation that wants its leaf, and claims the leaf once held"})))
	}

	/// Coin `record` of the wallet's key `owner` of `nonce`, checked against
	/// the chain as a coin the wallet holds is: as of its expiry once that
	/// has passed, and refused once a sweep that cut its path is final; while
	/// the chain still holds its path it is the wallet's.
	fn checked_as_held(&self, record: &CoinRecord, owner: &XOnlyPublicKey, nonce: &[u8; 32], now: MedianTime)
		-> Result<super::wallet::Assessed, String>
	{
		let first = super::pay::first_expiry(record).unwrap_or(u32::MAX);
		let a = match self.assess(record, &self.followed_policy(first, now), Some((owner, nonce))) {
			Ok(a) => a,
			Err(Error::Missing(m)) => return Err(format!("not on the chain now: {}", m)),
			Err(e) => return Err(e.to_string()),
		};
		if a.valid.expiry < now {
			if let Some((why, by)) = self.swept(&a.valid).map_err(|e| e.to_string())? {
				if self.chain.finality(&by).map_err(|e| e.to_string())?.is_final() {
					return Err(format!("it is past its batch's expiry, and its path is gone: {}; that spend is final", why));
				}
			}
		}
		Ok(a)
	}

	/// How coin `id` (`coin`, as the wallet checked it) was given up, as the
	/// server serves it (`e["given"]`), on its owner's own signatures alone:
	/// each transfer's checkpoint signature, each participation's attestation
	/// over its id recomputed from every part, and each forfeit's owner half.
	/// Whatever carries no such signature is not taken, and said. The latest
	/// way decides the coin's state; every participation is kept, with its
	/// forfeits, as the wallet kept them.
	///
	/// A leaf received over Lightning is given up only to its claim, which
	/// carries its preimage: one whose claim the server recorded and has not
	/// co-signed is left to [`Self::restore_htlc`], held as handed over with
	/// its home date; and one whose claim the server says it co-signed is
	/// spent only when the wallet holds a coin that claim made, checked
	/// (`spent_by_held`, by the coins it spends), since the server may say
	/// so of a claim it never co-signed.
	fn restore_given(&mut self, id: &str, e: &Value, coin: &ValidCoin, now: MedianTime, spent_by_held: &BTreeMap<String, Option<String>>)
		-> Result<Vec<Value>, Error>
	{
		let mut notes = vec![];
		let owner = coin.leaf.owner;
		// Participations first, oldest first, then transfers: a coin given up
		// to a participation the operator voided or let expire may be paid on
		// after, and a co-signed transfer is final.
		let mut given = e["given"].as_array().cloned().unwrap_or_default();
		given.sort_by_key(|g| g.get("transfer").is_some());
		for g in given {
			if let Some(t) = g.get("transfer") {
				let tid = t["transfer_id"].as_str().unwrap_or("");
				let cpv = amount(&t["checkpoint_value"], "a checkpoint value").unwrap_or(0);
				// Into a checkpoint with or without its owner's exit: the pair
				// names the checkpoint's output, so one of the two verifies.
				let signed = [false, true].into_iter().any(|checkpoint_exit| {
					let plan = TransferPlan { checkpoint_exit, inputs: vec![(coin.clone(), cpv)], outputs: vec![] };
					plan.checkpoint_message(0).ok().zip(signature(&t["checkpoint_sig"]))
						.is_some_and(|(m, s)| arca_covenant::sign::verify_digest(&s, &m.digest, &owner))
				});
				if !signed {
					let why = format!("the server says coin {} was given up in transfer {}, with a checkpoint signature that is not its owner's: \
						the wallet holds the coin as its own", id, tid);
					self.store.refused(&format!("restore of coin {}", id), &why)?;
					notes.push(json!({"leaf_id": id, "note": why}));
					continue;
				}
				let received = coin.leaf.htlc.is_some_and(|h| h.direction == arca_covenant::HtlcDirection::Receive);
				if received {
					// D68: a received leaf's claim, held as handed over unless a
					// coin it made is held.
					if t["state"] == "signed" && spent_by_held.get(id).is_some_and(|h| h.as_deref().is_none_or(|h| h == tid)) {
						self.store.set_coin_spent(id, &format!("transfer {}", tid))?;
					} else {
						let why = if t["state"] == "signed" {
							format!("the server says the claim of received leaf {} (transfer {}) is co-signed, and serves no coin it made that \
								the wallet can check: the leaf is held as not spent, and taken home by its claim unless a claim of it is \
								co-signed", id, tid)
						} else {
							format!("the claim of received leaf {} (transfer {}) is recorded at the server and not co-signed: the leaf is held as \
								handed over, and taken home by its claim at its home date unless a claim of it is co-signed", id, tid)
						};
						self.store.set_coin_state(id, "sending", &why)?;
						notes.push(json!({"leaf_id": id, "note": why}));
					}
					continue;
				}
				if t["state"] == "signed" {
					self.store.set_coin_spent(id, &format!("transfer {}", tid))?;
				} else {
					self.store.set_coin_state(id, "sending", &format!("given up in transfer {}, which the operator recorded and has not co-signed: \
						the wallet restored from its mnemonic holds no request to post again; sync takes the coin home from home_from unless the \
						operator completes the transfer", tid))?;
				}
				continue;
			}
			let Some(p) = g.get("participation") else { continue };
			match self.restore_participation(id, coin, p, now) {
				Ok(Some(n)) => notes.push(n),
				Ok(None) => {},
				Err(why) => {
					self.store.refused(&format!("restore of coin {}", id), &why)?;
					notes.push(json!({"leaf_id": id, "note": why}));
				},
			}
		}
		Ok(notes)
	}

	/// One participation coin `id` was given up to, as served (`p`): its id
	/// recomputed from its parts, the coin's attestation over it, and each
	/// forfeit of the coin checked as its owner's; then the participation
	/// kept as the wallet kept it, and the coin's state set from it.
	fn restore_participation(&mut self, id: &str, coin: &ValidCoin, p: &Value, now: MedianTime) -> Result<Option<Value>, String> {
		let pid = p["participation_id"].as_str().unwrap_or("").to_string();
		let mut inputs = vec![];
		for i in p["inputs"].as_array().cloned().unwrap_or_default() {
			inputs.push(LeafId::from_str(i.as_str().unwrap_or("")).map_err(|e| format!("participation {}: an input: {}", pid, e))?);
		}
		let mut wanted = vec![];
		let mut nonces = vec![];
		// What the wallet keeps of each output wanted, in order: a leaf by its
		// nonce, an offboard by its destination (an order the wallet placed).
		let mut wanted_json = vec![];
		for o in p["outputs"].as_array().cloned().unwrap_or_default() {
			if let Some(off) = o.get("offboard") {
				let asset = AssetId::from_str(off["asset"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
				let value = amount(&off["value"], "an offboard's value").map_err(|e| e.to_string())?;
				let script = unhex(off["script"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
				wanted.push(Wanted::Offboard { asset, value, script: elements::Script::from(script.clone()) });
				wanted_json.push(json!({"offboard": {"asset": asset.to_string(), "value": value.to_string(), "script": hex(&script)}}));
				continue;
			}
			let Some(l) = o.get("leaf") else {
				return Err(format!("participation {} wants an output that is neither a leaf nor an offboard: the wallet makes none, and takes \
					the coin as not given up to it", pid));
			};
			let asset = AssetId::from_str(l["asset"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
			let value = amount(&l["value"], "a leaf's value").map_err(|e| e.to_string())?;
			let template: Template = l["template"].as_str().unwrap_or("").parse().map_err(|e: arca_covenant::RecordError| e.to_string())?;
			let owner = XOnlyPublicKey::from_str(l["owner"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
			let owner_nonce = unhex32(l["owner_nonce"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
			let exit_delay = RelativeTime::from_units(l["exit_delay_units"].as_u64().unwrap_or(0) as u16).map_err(|e| e.to_string())?;
			// A resting order's terms, as the participation wanted them: its id
			// covers them, and its leaf is checked against them.
			let order = match l.get("order").filter(|o| !o.is_null()) {
				Some(o) => Some(arca_covenant::record_json::order_terms_from_json(o, asset).map_err(|e| e.to_string())?),
				None => None,
			};
			// A landing leaf's landing, likewise covered by the id, as the
			// template names it: the wallet's own landing key, or the
			// participation is not its own.
			let landing = match l.get("landing").filter(|g| !g.is_null()) {
				Some(g) => Some(arca_covenant::Landing { own_index: template == Template::Landing2,
					..arca_covenant::record_json::landing_from_json(g).map_err(|e| e.to_string())? }),
				None => None,
			};
			if landing.is_some_and(|g| self.keys.landing_program().is_ok_and(|p| p != g.program)) {
				return Err(format!("participation {} wants a landing leaf landing at another key than this wallet's: the wallet takes the \
					coin as not given up to it", pid));
			}
			// A channel leaf's terms, likewise covered by the id.
			let channel = match l.get("channel").filter(|c| !c.is_null()) {
				Some(c) => Some(arca_covenant::record_json::channel_from_json(c).map_err(|e| e.to_string())?),
				None => None,
			};
			wanted.push(Wanted::Leaf { asset, value, template, owner, owner_nonce, exit_delay, order, landing, channel });
			nonces.push((owner_nonce, owner, asset, value));
			let mut w = json!({"nonce": hex(&owner_nonce), "asset": asset.to_string(), "value": value.to_string()});
			if let Some(c) = &channel {
				w["channel"] = arca_covenant::record_json::channel_json(c);
			}
			if let Some(o) = &order {
				w["order"] = arca_covenant::record_json::order_terms_json(o);
			}
			if let Some(g) = &landing {
				w["landing"] = arca_covenant::record_json::landing_json(g);
				if g.own_index {
					w["template"] = json!(arca_covenant::LANDING_2);
				}
			}
			wanted_json.push(w);
		}
		let mut fees = vec![];
		for f in p["fees"].as_array().cloned().unwrap_or_default() {
			fees.push((AssetId::from_str(f["asset"].as_str().unwrap_or("")).map_err(|e| e.to_string())?,
				amount(&f["amount"], "a fee").map_err(|e| e.to_string())?));
		}
		let not_before = p["not_before"].as_u64().map(|t| MedianTime::from_consensus(t as u32)).transpose().map_err(|e| e.to_string())?;
		// A take's id covers its order besides these parts.
		let fill = p.get("fill").filter(|f| f.is_object());
		let computed = match fill {
			None => participation_id(&self.genesis, &self.operator, &inputs, &wanted, &fees, not_before),
			Some(f) => {
				let (order, terms) = arca_covenant::FillOrder::from_relay(&f["order"]).map_err(|e| format!("take {}: {}", pid, e))?;
				let (Some(Wanted::Leaf { asset, value, template, owner, owner_nonce, exit_delay, .. }), Some(fee), 1, 1) =
					(wanted.first().cloned(), fees.first().copied(), wanted.len(), fees.len()) else {
					return Err(format!("take {} is served with {} leaves and {} fees: a take wants one leaf and pays one fee", pid,
						wanted.len(), fees.len()));
				};
				arca_covenant::Take {
					order, terms,
					locked: amount(&f["locked"], "what the order holds").map_err(|e| e.to_string())?,
					filled: amount(&f["filled"], "the fill").map_err(|e| e.to_string())?,
					inputs: inputs.clone(),
					leaf: arca_covenant::TakeLeaf { asset, value, template, owner, owner_nonce, exit_delay },
					fee, not_before,
				}.id(&self.genesis, &self.operator)
			},
		};
		if hex(&computed) != pid {
			return Err(format!("the server names participation {}, and the parts it serves make {}: the wallet takes coin {} as not given \
				up to it", pid, hex(&computed), id));
		}
		if !signature(&p["attestation"]).is_some_and(|s| arca_covenant::sign::verify_digest(&s, &computed, &coin.leaf.owner)) {
			return Err(format!("the attestation served for coin {} in participation {} is not its owner's: the wallet takes the coin as not \
				given up to it", id, pid));
		}
		// Each forfeit of the coin the owner signed, for one attempt's round.
		let mut forfeits: Vec<(ForfeitRow, bool)> = vec![];
		for f in p["forfeits"].as_array().cloned().unwrap_or_default() {
			let round = f["round_txid"].as_str().unwrap_or("").to_string();
			let (Ok(rtx), Ok(unlock)) = (Txid::from_str(&round), unhex32(f["unlock_hash"].as_str().unwrap_or(""))) else { continue };
			let vout = f["connector_vout"].as_u64().unwrap_or(0) as u32;
			let units = f["refund_delay_units"].as_u64().unwrap_or(0) as u16;
			let margin = amount(&f["margin"], "a forfeit's margin").unwrap_or(0);
			let Ok(refund) = RelativeTime::from_units(units) else { continue };
			let ok = Forfeit::new(coin.leaf, (coin.asset, coin.value), coin.id, unlock, connector_asset(rtx, vout), refund, margin).ok()
				.zip(signature(&f["owner_sig"])).is_some_and(|(ff, s)| arca_covenant::sign::verify_digest(&s, &ff.message().digest, &coin.leaf.owner));
			if !ok {
				continue;
			}
			let from_height = self.chain.tx_block(&rtx).ok().flatten().map_or(0, |(_, h)| h).saturating_sub(100);
			forfeits.push((ForfeitRow {
				leaf_id: id.to_string(), participation: pid.clone(), round, connector_vout: vout, unlock_hash: hex(&unlock), refund_units: units,
				margin, from_height, state: "signed".into(), note: String::new(),
			}, f["cosigned"] == json!(true)));
		}
		let state = p["state"].as_str().unwrap_or("");
		let unlock = p["unlock_hash"].as_str().unwrap_or("").to_string();
		let current: Vec<&(ForfeitRow, bool)> = forfeits.iter().filter(|(f, _)| f.unlock_hash == unlock).collect();
		let given: Vec<String> = inputs.iter().map(|l| l.to_string()).collect();
		let mut body = json!({"restored": true, "inputs": given, "outputs": p["outputs"], "fees": p["fees"], "not_before": p["not_before"]});
		if let Some(f) = fill {
			body["order"] = f["order"].clone();
			body["locked"] = f["locked"].clone();
			body["filled"] = f["filled"].clone();
			// A take that shares its order checks its round against the sum
			// of the takes of it, as the wallet that made it would.
			if f["shared"] == json!(true) {
				body["share"] = json!(true);
			}
		}
		let s = &self.store;
		let held = s.participations().map_err(|e| e.to_string())?.into_iter().any(|q| q.0 == pid);
		if !held {
			s.put_participation(&pid, &body.to_string(), &serde_json::to_string(&given).expect("strings"), &Value::Array(wanted_json).to_string())
				.map_err(|e| e.to_string())?;
			// The nonces of the leaves it wants, under the wallet's keys,
			// waited on until the leaves are held.
			for (n, o, _, _) in &nonces {
				if s.nonce(n).map_err(|e| e.to_string())?.is_none() && self.keys.leaf_xonly(n).map_err(|e| e.to_string())? == *o {
					s.put_nonce(n, &o.serialize(), "refresh").map_err(|e| e.to_string())?;
				}
			}
		}
		for (f, _) in &forfeits {
			s.put_forfeit(f).map_err(|e| e.to_string())?;
		}
		let round = current.first().map(|(f, _)| f.round.clone());
		let note = |what: &str| json!({"leaf_id": id, "participation": pid, "state": what});
		Ok(Some(match state {
			"pending" => {
				s.set_participation(&pid, "pending", None, None).map_err(|e| e.to_string())?;
				s.set_coin_state(id, "given", &format!("participation {}", pid)).map_err(|e| e.to_string())?;
				note("pending")
			},
			// Its forfeit signed: given up under it, followed on the chain,
			// until the preimage of the new leaves is in hand (a released
			// participation's is looked for next, [`Self::restore_participations`]).
			"issued" | "released" if !current.is_empty() => {
				s.set_participation(&pid, "forfeiting", None, round.as_deref()).map_err(|e| e.to_string())?;
				s.set_coin_state(id, "forfeited", &format!("participation {}: its forfeit for round {} is signed", pid, round.unwrap_or_default()))
					.map_err(|e| e.to_string())?;
				note(state)
			},
			"issued" | "released" => {
				s.set_participation(&pid, "issued", None, None).map_err(|e| e.to_string())?;
				s.set_coin_state(id, "given", &format!("participation {}", pid)).map_err(|e| e.to_string())?;
				note(state)
			},
			"void" | "expired" => {
				s.set_participation(&pid, state, None, None).map_err(|e| e.to_string())?;
				let returned = p["returned"] == json!(true);
				if !forfeits.is_empty() {
					// A coin whose forfeit its owner signed is never live: the
					// forfeit may be claimed, and is followed on the chain.
					let why = if returned {
						format!("the server says participation {} gave coin {} back, and serves the owner's own forfeit of it: an old copy; the \
							coin stays held under its forfeit, followed on the chain until its refund or the coin's exit", pid, id)
					} else {
						format!("the server will not run participation {}; the coin is held under its forfeit, and is the wallet's on the chain, \
							by that forfeit's refund or its exit", pid)
					};
					s.set_coin_state(id, "forfeited", &why).map_err(|e| e.to_string())?;
					json!({"leaf_id": id, "participation": pid, "state": state, "note": why})
				} else {
					s.set_coin_state(id, "live", "").map_err(|e| e.to_string())?;
					note(state)
				}
			},
			other => {
				let _ = now;
				return Err(format!("participation {} is {} at the server: not a state the wallet follows", pid, other));
			},
		}))
	}

	/// Every participation restored in its forfeit step gets the new leaves
	/// the wallet validated before signing its forfeits, rebuilt from the
	/// published tree. One the operator released is completed as the wallet
	/// completes one ([`Self::finish`]) once the preimage of its new leaves is
	/// in hand, from the record of a new leaf the server serves or from the
	/// published tree: its new leaves are kept (one the server does not serve,
	/// from the published tree, and said so), the coins it gave up spent.
	/// Without the preimage the coins stay given up under their forfeits,
	/// followed on the chain, and `sync` completes it once the preimage is out.
	fn restore_participations(&mut self, trees: &mut BTreeMap<(String, u32), (Value, Batch)>, now: MedianTime, restored: &mut Vec<Value>,
		not_recovered: &mut Vec<Value>) -> Result<Vec<Value>, Error>
	{
		let mut notes = vec![];
		let followed: Vec<_> = self.store.participations()?.into_iter()
			.filter(|p| p.4 == "forfeiting" && serde_json::from_str::<Value>(&p.1).is_ok_and(|b| b["restored"] == json!(true))).collect();
		// How each stands, asked of the operator first, then their rounds read
		// together: the chain is read after the last request to the operator,
		// rather than looked at again after each one.
		let mut statuses = BTreeMap::new();
		for p in &followed {
			statuses.insert(p.0.clone(), self.server.post("participation_status", &json!({"participation_id": p.0})));
		}
		let rounds: BTreeSet<Txid> = followed.iter().filter_map(|p| p.6.clone()
			.or_else(|| statuses.get(&p.0).and_then(|s| s.as_ref().ok()).and_then(|s| s["round"]["txid"].as_str().map(str::to_string))))
			.filter_map(|r| Txid::from_str(&r).ok()).collect();
		self.chain.read_ahead_of(&rounds.into_iter().collect::<Vec<_>>(), &[]);
		for (pid, _body, given_json, wanted, _state, _, round) in followed {
			let st = match statuses.remove(&pid).expect("asked for each") {
				Ok(st) => st,
				Err(e) => {
					notes.push(json!({"participation": pid, "error": e.to_string()}));
					continue;
				},
			};
			let rtx = round.clone().or(st["round"]["txid"].as_str().map(str::to_string)).unwrap_or_default();
			// The round as the node holds it, or, for a take whose round is
			// held unbroadcast for its takes' forfeits, as the take's status
			// serves it (without its witnesses, its txid the round's), as
			// `sync` reads it.
			let round_tx: Option<elements::Transaction> = match Txid::from_str(&rtx) {
				Ok(t) => match self.chain.transaction(&t)? {
					Some(tx) => Some(tx),
					None => st["round"]["tx"].as_str().and_then(|h| unhex(h).ok())
						.and_then(|b| elements::encode::deserialize::<elements::Transaction>(&b).ok()).filter(|tx| tx.txid() == t),
				},
				Err(_) => None,
			};
			let released = st["state"] == "released" && st["round"]["txid"].as_str() == Some(rtx.as_str());
			let wanted: Value = serde_json::from_str(&wanted).map_err(|e| Error::Store(e.to_string()))?;
			let mut news = vec![];
			let mut preimage = None;
			let mut withheld = vec![];
			for (o, w) in st["outputs"].as_array().cloned().unwrap_or_default().iter().zip(wanted.as_array().cloned().unwrap_or_default()) {
				let Ok(nonce) = unhex32(w["nonce"].as_str().unwrap_or("")) else { continue };
				let (Some(vout), Some(index)) = (o["batch_vout"].as_u64(), o["leaf_index"].as_u64()) else { continue };
				let leaf_id = o["leaf_id"].as_str().unwrap_or("").to_string();
				let held = self.store.coin(&leaf_id)?;
				let served_preimage = match &held {
					Some(c) => NewRecord::of_coin(&Self::record_of(c)?).map(|(_, p, _)| p),
					None => None,
				};
				// The leaf as the wallet validated it before signing: its
				// preimage, when one is in hand, is checked to open it.
				let built = match self.leaf_from_tree(trees, &rtx, vout as u32, index as usize, &nonce, served_preimage, now) {
					Ok(b) => Some(b),
					Err(why) if why.contains("its preimage has not gone out") => None,
					Err(why) => {
						if held.is_none() {
							not_recovered.push(missed(&leaf_id, format!("a new leaf of participation {}: {}", pid, why)));
						}
						notes.push(json!({"participation": pid, "leaf_id": leaf_id, "note": why}));
						continue;
					},
				};
				let (record, auths, p) = match built.as_ref().and_then(|(c, _)| NewRecord::of_coin(c)) {
					Some((record, preimage, auths)) => (record, auths, Some(preimage)),
					None => {
						// No preimage anywhere: the leaf as the tree builds it,
						// validated, its authorisations signed, to be opened
						// by a preimage the chain or the operator gives later.
						let (_, tree) = self.published_tree(trees, &rtx, vout as u32).map_err(Error::Refused)?;
						if index as usize >= tree.len() {
							return Err(Error::Refused(format!("the published batch of {}:{} has no leaf {}", rtx, vout, index)));
						}
						let record = NewRecord::of(tree, index as usize);
						let round_tx = round_tx.clone()
							.ok_or_else(|| Error::Missing(format!("round {} is not on the chain the node holds", rtx)))?;
						let owner = self.keys.leaf_xonly(&nonce)?;
						let first = record.first_expiry();
						let valid = record.validate(&round_tx, &self.followed_policy(first, now), &owner, &nonce)
							.map_err(|e| Error::Refused(format!("the new leaf in round {} fails the wallet's checks: {}", rtx, e)))?;
						let key = self.keys.leaf(&nonce)?;
						let at = auth_time(first, now).map_err(Error::Node)?;
						(record, valid.sign_auths(&key, at), None)
					},
				};
				if p.is_some() {
					preimage = p;
				}
				if held.is_none() {
					withheld.push(leaf_id.clone());
				}
				news.push((leaf_id.clone(), held.is_some(), nonce, record.clone(), auths.clone(),
					json!({"record": hex(&record.to_bytes()?), "nonce": hex(&nonce),
					"auths": auths.iter().map(|(s, t)| json!({"signature": hex(s.as_ref()), "time": t.to_consensus_u32()})).collect::<Vec<_>>()})));
			}
			if let Some(round_tx) = &round_tx {
				self.store.put_tx(&rtx, &elements::encode::serialize(round_tx), "round")?;
			}
			let all: Vec<Value> = news.iter().map(|n| n.5.clone()).collect();
			self.store.set_participation_news(&pid, &json!({"round": rtx, "leaves": all}).to_string())?;
			if !released {
				notes.push(json!({"participation": pid, "state": "forfeiting", "round": rtx}));
				continue;
			}
			match preimage {
				Some(p) => {
					// A new leaf the wallet does not hold yet is checked as any
					// coin restored is, as of its expiry once that has passed:
					// one whose path a final sweep cut is not taken. The
					// participation is completed with the others, its coins
					// given up spent.
					let mut kept_news = vec![];
					for (leaf_id, held, nonce, record, auths, entry) in &news {
						if !held {
							let coin = record.coin(p, auths.clone())?;
							if let Err(why) = self.checked_as_held(&coin, &record.owner(), nonce, now) {
								not_recovered.push(missed(leaf_id, format!("a new leaf of participation {}: {}", pid, why)));
								withheld.retain(|w| w != leaf_id);
								continue;
							}
						}
						kept_news.push(entry.clone());
					}
					self.store.set_participation_news(&pid, &json!({"round": rtx, "leaves": kept_news}).to_string())?;
					let kept = self.finish(&pid, p, "settled")?;
					for k in kept {
						let id = k["leaf_id"].as_str().unwrap_or("").to_string();
						if withheld.contains(&id) {
							notes.push(json!({"leaf_id": id, "note": format!("the server does not serve this leaf, which participation {} \
								released for the wallet: withheld; recovered from the published tree and the preimage, checked against the round", pid)}));
							restored.push(json!({"leaf_id": id, "kind": "batch", "asset": k["asset"], "value": k["value"], "state": "live",
								"from": "the published tree"}));
						}
					}
					notes.push(json!({"participation": pid, "state": "released", "round": rtx}));
				},
				// A participation that wanted only offboards has no new leaf
				// to give a preimage: released, its round final in the chain,
				// the coins it gave up are spent, as the wallet that made it
				// finds them.
				None if released && news.is_empty() && self.offboards_final(&wanted, &rtx)? => {
					let given: Vec<String> = serde_json::from_str(&given_json).map_err(|e| Error::Store(e.to_string()))?;
					self.store.atomically(|s| {
						for l in &given {
							s.set_coin_spent(l, &format!("participation {}", pid))?;
							s.set_forfeit_state(l, &rtx, "settled", "")?;
						}
						s.set_participation(&pid, "released", None, Some(&rtx))
					})?;
					notes.push(json!({"participation": pid, "state": "released", "round": rtx, "note": "it wanted offboards alone, and its \
						round is final in the chain: the coins given up for it are spent"}));
				},
				None => {
					for id in &withheld {
						not_recovered.push(missed(id, format!("the server does not serve this leaf, which participation {} released for the \
							wallet, and its preimage has not gone out: the published tree of round {} shows none, and the server serves no record of \
							it; the coin given up for it stays under its forfeit, followed on the chain, and sync completes the leaf once the \
							preimage is out", pid, rtx)));
					}
					notes.push(json!({"participation": pid, "state": "forfeiting", "round": rtx, "note": "released at the server, and the wallet \
						holds no preimage of its new leaves: the coins given up stay under their forfeits, followed on the chain"}));
				},
			}
		}
		Ok(notes)
	}
}
