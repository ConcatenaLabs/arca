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
//! What cannot be recovered is said with its reason (`not_recovered`): a
//! record the server withholds and the published tree does not hold, a coin
//! failing a check, and receive requests handed out and never paid, which no
//! one but the lost store knew: the schedule holds at a day for as long as
//! such a request could last ([`super::wallet::REQUEST_HOLDS`] from the
//! restore), since a payment to one is read only by `sync`.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use elements::hashes::{sha256, Hash};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Txid};
use serde_json::{json, Value};

use arca_covenant::tree::Tree;
use arca_covenant::{connector_asset, CoinRecord, Forfeit, LeafId, LeafRecord, MedianTime, RelativeTime, Template, TransferPlan, ValidCoin, ValidOrigin};

use super::chain::{hex, unhex, unhex32};
use super::client::{participation_id, Wanted, LEAF_PAGE};
use super::store::ForfeitRow;
use super::wallet::{amount, kind_of, owner_of, sign, Wallet};
use super::Error;

/// Where the wallet keeps the median time until which its schedule holds at
/// a day after a restore: receive requests handed out before it are not
/// known, and one may still be paid until then.
pub(crate) const RESTORED_UNTIL: &str = "restored_until";

/// What the schedule says while it holds at a day after a restore.
pub(crate) const RESTORED_NOTE: &str = "the wallet was restored from its mnemonic: a receive request handed out before then cannot be \
	known (its key comes from a random nonce the lost store held), and a coin paid to one is read only by sync, so sync runs at least \
	once a day until the latest such a request could lapse (lapses_at). Forget it once no request was outstanding";

/// One coin the restore could not take, and why.
fn missed(leaf: &str, why: impl Into<String>) -> Value {
	json!({"leaf_id": leaf, "why": why.into()})
}

/// A signature from its hex, if it is one.
fn signature(v: &Value) -> Option<Signature> {
	v.as_str().and_then(|s| unhex(s).ok()).and_then(|b| Signature::from_slice(&b).ok())
}

/// A coin the restore took, with what it rests on and how it was given up,
/// for the passes after the first.
struct Taken {
	entry: Value,
	coin: ValidCoin,
}

impl Wallet {
	/// Restores the wallet from what its mnemonic names: every leaf the server
	/// serves to its mailbox key, each checked as the module documentation
	/// says, then the mailbox, then a `sync`. Run on a wallet created from a
	/// mnemonic; run again, it takes only what it does not hold. Refuses, and
	/// restores nothing, while the operator's keeper set is not acknowledged.
	pub fn restore(&mut self) -> Result<Value, Error> {
		let info = self.server_info()?;
		let mailbox = self.keys.mailbox()?;
		let mut entries: Vec<Value> = vec![];
		let mut after = 0i64;
		loop {
			let page = self.server.leaf_data(&mailbox, &self.genesis, after, LEAF_PAGE)?;
			let leaves = page["leaves"].as_array().cloned().unwrap_or_default();
			if leaves.is_empty() {
				break;
			}
			entries.extend(leaves);
			match page["next"].as_str().and_then(|n| n.parse::<i64>().ok()) {
				Some(n) if n > after => after = n,
				_ => break,
			}
		}
		self.keepers_acknowledged(&info, &entries)?;
		self.no_foreign_acks(&info, &entries)?;
		let now = self.now()?;
		let mut not_recovered: Vec<Value> = vec![];
		let mut restored: Vec<Value> = vec![];
		let mut taken: BTreeMap<String, Taken> = BTreeMap::new();
		let mut trees: BTreeMap<(String, u32), (Value, Tree)> = BTreeMap::new();

		// Every coin served with a record, checked; the same leaf served twice
		// is looked at once, its first copy.
		let mut seen = BTreeSet::new();
		for e in &entries {
			let id = e["leaf_id"].as_str().unwrap_or("").to_string();
			if !seen.insert(id.clone()) {
				not_recovered.push(missed(&id, "the server serves this leaf twice: the wallet looked at its first copy alone"));
				continue;
			}
			if self.store.coin(&id)?.is_some() {
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
					self.store.refused(&format!("restore of coin {}", id), &why)?;
					not_recovered.push(missed(&id, why));
				},
			}
		}

		// How each was given up, on its owner's own signatures.
		let mut notes: Vec<Value> = vec![];
		for (id, t) in &taken {
			notes.extend(self.restore_given(id, &t.entry, &t.coin, now)?);
		}

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
				self.store.refused(&format!("restore of coin {}", c.leaf_id), &why)?;
				notes.push(json!({"leaf_id": c.leaf_id, "note": why}));
			}
		}

		// Participations in their forfeit step: the new leaves validated as
		// before their forfeits were signed; and the new leaves of released
		// ones that the server does not serve, from the published tree.
		notes.extend(self.restore_participations(&mut trees, now, &mut restored, &mut not_recovered)?);

		// The mailbox, from its start: a coin held is held, one paid to a key
		// of the mnemonic and never read is taken.
		self.adopting.set(true);
		let mailbox_read = self.mailbox();
		self.adopting.set(false);
		let mailbox_read = mailbox_read.unwrap_or_else(|e| json!({"error": e.to_string()}));

		// The chain is read from the oldest base on; the schedule holds at a
		// day while a request handed out before may still be paid.
		let mut lowest: Option<u64> = None;
		for c in self.store.coins()? {
			for b in &c.bases {
				if let Ok(t) = Txid::from_str(b) {
					if let Some(h) = self.chain.finality(&t)?.height() {
						lowest = Some(lowest.map_or(h, |l| l.min(h)));
					}
				}
			}
		}
		if let Some(h) = lowest {
			let birthday: u64 = self.store.meta("birthday")?.and_then(|b| b.parse().ok()).unwrap_or(u64::MAX);
			if h < birthday {
				self.store.set_meta("birthday", &h.to_string())?;
			}
		}
		let until = now.to_consensus_u32().saturating_add(super::wallet::REQUEST_HOLDS);
		let held_until: u32 = self.store.meta(RESTORED_UNTIL)?.and_then(|v| v.parse().ok()).unwrap_or(0);
		self.store.set_meta(RESTORED_UNTIL, &until.max(held_until).to_string())?;

		// Each coin as the restore left it, how it was given up applied.
		for v in restored.iter_mut() {
			if let Some(c) = self.store.coin(v["leaf_id"].as_str().unwrap_or(""))? {
				v["state"] = json!(c.state);
			}
		}
		let sync = self.sync()?;
		Ok(json!({
			"served": entries.len(), "restored": restored, "not_recovered": not_recovered, "notes": notes, "mailbox": mailbox_read,
			"requests": {"lapses_at": until.max(held_until), "note": self.spelling.say(RESTORED_NOTE)},
			"sync": sync,
		}))
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

	/// The published tree of the batch at output `vout` of round `txid`,
	/// fetched once, rebuilt from its parts and refused unless it lists what
	/// they build ([`super::round::rebuild`]).
	fn published_tree<'a>(&self, trees: &'a mut BTreeMap<(String, u32), (Value, Tree)>, txid: &str, vout: u32)
		-> Result<&'a (Value, Tree), String>
	{
		let key = (txid.to_string(), vout);
		if !trees.contains_key(&key) {
			let t = self.server.post("tree", &json!({"txid": txid, "vout": vout})).map_err(|e| e.to_string())?;
			if t["round_txid"].as_str() != Some(txid) || t["batch_vout"].as_u64() != Some(vout as u64) {
				return Err(format!("the server published the tree of another batch than {}:{}", txid, vout));
			}
			let tree = super::round::rebuild(&t).map_err(|e| e.to_string())?;
			trees.insert(key.clone(), (t, tree));
		}
		Ok(&trees[&key])
	}

	/// A round's leaf at `index` of the batch at `vout` of round `txid`,
	/// rebuilt from the published tree and checked against the round on the
	/// chain under the wallet's key of `nonce`, with `preimage` (checked to
	/// open it) and unroll authorisations the mnemonic signs again: what the
	/// wallet holds of the leaf, the server's copy of its record not needed.
	fn leaf_from_tree(&self, trees: &mut BTreeMap<(String, u32), (Value, Tree)>, txid: &str, vout: u32, index: usize, nonce: &[u8; 32],
		preimage: Option<[u8; 32]>, now: MedianTime) -> Result<(CoinRecord, LeafRecord), String>
	{
		let (t, tree) = self.published_tree(trees, txid, vout)?;
		if index >= tree.records().len() {
			return Err(format!("the published tree of {}:{} has no leaf {}", txid, vout, index));
		}
		let record = tree.record(index);
		let published = t["leaves"][index]["preimage"].as_str().and_then(|p| unhex32(p).ok());
		let preimage = preimage.or(published).ok_or_else(|| format!("its preimage has not gone out: the published tree of {}:{} shows none \
			for leaf {}, and the server serves no record of it", txid, vout, index))?;
		if sha256::Hash::hash(&preimage).to_byte_array() != record.unlock_hash {
			return Err(format!("the preimage of leaf {} of {}:{} does not open its unlock hash", index, txid, vout));
		}
		let owner = self.keys.leaf_xonly(nonce).map_err(|e| e.to_string())?;
		if record.owner != owner || record.owner_nonce != *nonce {
			return Err(format!("leaf {} of the published tree of {}:{} is not under the key this wallet derives from owner nonce {}", index, txid,
				vout, hex(nonce)));
		}
		let round_txid = Txid::from_str(txid).map_err(|e| e.to_string())?;
		let round = self.chain.transaction(&round_txid).map_err(|e| e.to_string())?
			.ok_or_else(|| format!("round {} is not on the chain the node holds", txid))?;
		let first = record.schedule.expiries()[0].to_consensus_u32();
		let valid = record.validate(&round, &self.followed_policy(first, now), &owner, nonce)
			.map_err(|e| format!("the leaf in round {} fails the wallet's checks: {}", txid, e))?;
		let key = self.keys.leaf(nonce).map_err(|e| e.to_string())?;
		// Unroll authorisations an hour before now: usable at once.
		let at = MedianTime::from_consensus(now.to_consensus_u32().saturating_sub(3600)).map_err(|e| e.to_string())?;
		let auths = valid.branch.nodes.iter().map(|n| (sign(&key, &n.unroll_authorisation(at).digest), at)).collect();
		Ok((CoinRecord::Leaf { record: record.clone(), preimage, auths }, record))
	}

	/// Restores one coin the server serves (`e`), checked: its record, its
	/// owner key, the tree for a round's leaf, the chain, and for a coin made
	/// out of round the keepers' acknowledgements of its head. Kept `live` or
	/// `pending` as the chain stands; how it was given up is looked at next.
	/// `None` for a round's leaf served without its record (its participation
	/// is followed instead); `Err` with the reason it is not taken.
	fn restore_coin(&mut self, e: &Value, trees: &mut BTreeMap<(String, u32), (Value, Tree)>, now: MedianTime)
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
		let record = match &served {
			CoinRecord::Leaf { record, preimage, .. } => {
				let b = &e["batch"];
				let txid = b["round_txid"].as_str().ok_or("a round's leaf served without its round")?.to_string();
				let (vout, index) = (b["batch_vout"].as_u64().unwrap_or(u64::MAX) as u32, b["leaf_index"].as_u64().unwrap_or(u64::MAX) as usize);
				let (coin, built) = self.leaf_from_tree(trees, &txid, vout, index, &nonce, Some(*preimage), now)?;
				if built != *record {
					return Err(format!("the record served is not leaf {} of the published tree of {}:{}", index, txid, vout));
				}
				coin
			},
			_ => served.clone(),
		};
		// A coin made out of round rests on the operator's machine until the
		// head of its signer's record is held outside it.
		if matches!(record, CoinRecord::Transfer(_)) {
			if let Err(why) = self.held_outside(&e["made_by"]["signer_record"]) {
				return Err(format!("{}: the coin is not taken (the mailbox read takes it once its head comes with them)", why));
			}
		}
		let first = super::pay::first_expiry(&record).unwrap_or(u32::MAX);
		let policy = self.followed_policy(first, now);
		let a = match self.assess(&record, &policy, Some((&owner, &nonce))) {
			Ok(a) => a,
			Err(Error::Missing(m)) => return Err(format!("not on the chain now: {}", m)),
			Err(e) => return Err(e.to_string()),
		};
		// Past its expiry it is the wallet's while the chain holds its path,
		// and lost once a sweep that cut it is final.
		if a.valid.expiry < now {
			if let Some((why, by)) = self.swept(&a.valid).map_err(|e| e.to_string())? {
				if self.chain.finality(&by).map_err(|e| e.to_string())?.is_final() {
					return Err(format!("it is past its batch's expiry, and its path is gone: {}; that spend is final", why));
				}
			}
		}
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

	/// How coin `id` (`coin`, as the wallet checked it) was given up, as the
	/// server serves it (`e["given"]`), on its owner's own signatures alone:
	/// each transfer's checkpoint signature, each participation's attestation
	/// over its id recomputed from every part, and each forfeit's owner half.
	/// Whatever carries no such signature is not taken, and said. The latest
	/// way decides the coin's state; every participation is kept, with its
	/// forfeits, as the wallet kept them.
	fn restore_given(&mut self, id: &str, e: &Value, coin: &ValidCoin, now: MedianTime) -> Result<Vec<Value>, Error> {
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
				let plan = TransferPlan { inputs: vec![(coin.clone(), cpv)], outputs: vec![] };
				let signed = plan.checkpoint_message(0).ok().zip(signature(&t["checkpoint_sig"]))
					.is_some_and(|(m, s)| arca_covenant::sign::verify_digest(&s, &m.digest, &owner));
				if !signed {
					let why = format!("the server says coin {} was given up in transfer {}, with a checkpoint signature that is not its owner's: \
						the wallet holds the coin as its own", id, tid);
					self.store.refused(&format!("restore of coin {}", id), &why)?;
					notes.push(json!({"leaf_id": id, "note": why}));
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
		for o in p["outputs"].as_array().cloned().unwrap_or_default() {
			let Some(l) = o.get("leaf") else {
				return Err(format!("participation {} wants an output that is no leaf: the wallet makes none, and takes the coin as not given up \
					to it", pid));
			};
			let asset = AssetId::from_str(l["asset"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
			let value = amount(&l["value"], "a leaf's value").map_err(|e| e.to_string())?;
			let template: Template = l["template"].as_str().unwrap_or("").parse().map_err(|e: arca_covenant::RecordError| e.to_string())?;
			let owner = XOnlyPublicKey::from_str(l["owner"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
			let owner_nonce = unhex32(l["owner_nonce"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
			let exit_delay = RelativeTime::from_units(l["exit_delay_units"].as_u64().unwrap_or(0) as u16).map_err(|e| e.to_string())?;
			wanted.push(Wanted::Leaf { asset, value, template, owner, owner_nonce, exit_delay });
			nonces.push((owner_nonce, owner, asset, value));
		}
		let mut fees = vec![];
		for f in p["fees"].as_array().cloned().unwrap_or_default() {
			fees.push((AssetId::from_str(f["asset"].as_str().unwrap_or("")).map_err(|e| e.to_string())?,
				amount(&f["amount"], "a fee").map_err(|e| e.to_string())?));
		}
		let not_before = p["not_before"].as_u64().map(|t| MedianTime::from_consensus(t as u32)).transpose().map_err(|e| e.to_string())?;
		let computed = participation_id(&self.genesis, &self.operator, &inputs, &wanted, &fees, not_before);
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
			let from_height = self.chain.finality(&rtx).ok().and_then(|x| x.height()).unwrap_or(0).saturating_sub(100);
			forfeits.push((ForfeitRow {
				leaf_id: id.to_string(), participation: pid.clone(), round, connector_vout: vout, unlock_hash: hex(&unlock), refund_units: units,
				margin, from_height, state: "signed".into(), note: String::new(),
			}, f["cosigned"] == json!(true)));
		}
		let state = p["state"].as_str().unwrap_or("");
		let unlock = p["unlock_hash"].as_str().unwrap_or("").to_string();
		let current: Vec<&(ForfeitRow, bool)> = forfeits.iter().filter(|(f, _)| f.unlock_hash == unlock).collect();
		let given: Vec<String> = inputs.iter().map(|l| l.to_string()).collect();
		let wanted_json: Vec<Value> = nonces.iter().map(|(n, _, a, v)| json!({"nonce": hex(n), "asset": a.to_string(), "value": v.to_string()}))
			.collect();
		let body = json!({"restored": true, "inputs": given, "outputs": p["outputs"], "fees": p["fees"], "not_before": p["not_before"]});
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
			"issued" if !current.is_empty() => {
				s.set_participation(&pid, "forfeiting", None, round.as_deref()).map_err(|e| e.to_string())?;
				s.set_coin_state(id, "forfeited", &format!("participation {}: its forfeit for round {} is signed", pid, round.unwrap_or_default()))
					.map_err(|e| e.to_string())?;
				note("forfeiting")
			},
			"issued" => {
				s.set_participation(&pid, "issued", None, None).map_err(|e| e.to_string())?;
				s.set_coin_state(id, "given", &format!("participation {}", pid)).map_err(|e| e.to_string())?;
				note("issued")
			},
			"released" => {
				// The preimage is set once the new leaves are held.
				for (f, _) in &current {
					s.set_forfeit_state(id, &f.round, "settled", "").map_err(|e| e.to_string())?;
				}
				s.set_participation(&pid, "issued", None, round.as_deref()).map_err(|e| e.to_string())?;
				s.set_coin_spent(id, &format!("participation {}", pid)).map_err(|e| e.to_string())?;
				note("released")
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
	/// published tree; every released one whose new leaves the wallet does not
	/// hold (the server did not serve them) gets them from the published tree,
	/// with its preimage; and every released one whose leaves it holds is
	/// released, with that preimage.
	fn restore_participations(&mut self, trees: &mut BTreeMap<(String, u32), (Value, Tree)>, now: MedianTime, restored: &mut Vec<Value>,
		not_recovered: &mut Vec<Value>) -> Result<Vec<Value>, Error>
	{
		let mut notes = vec![];
		for (pid, body, given, wanted, state, _, round) in self.store.participations()? {
			let restored_here = serde_json::from_str::<Value>(&body).is_ok_and(|b| b["restored"] == json!(true));
			if !restored_here || !matches!(state.as_str(), "forfeiting" | "issued") {
				continue;
			}
			let given: Vec<String> = serde_json::from_str(&given).map_err(|e| Error::Store(e.to_string()))?;
			// A released participation is held as `issued` with its round
			// until its leaves are held; one in its forfeit step as
			// `forfeiting`.
			let released = state == "issued" && given.iter().any(|l| self.store.coin(l).ok().flatten()
				.is_some_and(|c| c.spent_by.as_deref() == Some(&format!("participation {}", pid))));
			if state == "issued" && !released {
				continue;
			}
			let st = match self.server.post("participation_status", &json!({"participation_id": pid})) {
				Ok(st) => st,
				Err(e) => {
					notes.push(json!({"participation": pid, "error": e.to_string()}));
					continue;
				},
			};
			let rtx = st["round"]["txid"].as_str().map(str::to_string).or(round.clone()).unwrap_or_default();
			let wanted: Value = serde_json::from_str(&wanted).map_err(|e| Error::Store(e.to_string()))?;
			let outputs = st["outputs"].as_array().cloned().unwrap_or_default();
			let mut news = vec![];
			let mut preimage = None;
			for (o, w) in outputs.iter().zip(wanted.as_array().cloned().unwrap_or_default()) {
				let Ok(nonce) = unhex32(w["nonce"].as_str().unwrap_or("")) else { continue };
				let (Some(vout), Some(index)) = (o["batch_vout"].as_u64(), o["leaf_index"].as_u64()) else { continue };
				let leaf_id = o["leaf_id"].as_str().unwrap_or("").to_string();
				let held = self.store.coin(&leaf_id)?;
				let pre = match &held {
					Some(c) => match Self::record_of(c)? {
						CoinRecord::Leaf { preimage, .. } => Some(preimage),
						_ => None,
					},
					None => None,
				};
				match self.leaf_from_tree(trees, &rtx, vout as u32, index as usize, &nonce, pre, now) {
					Ok((coin, record)) => {
						let CoinRecord::Leaf { preimage: p, auths, .. } = &coin else { continue };
						news.push(json!({"record": hex(&record.to_bytes().map_err(|e| Error::Refused(e.to_string()))?), "nonce": hex(&nonce),
							"auths": auths.iter().map(|(s, t)| json!({"signature": hex(s.as_ref()), "time": t.to_consensus_u32()})).collect::<Vec<_>>()}));
						if released {
							preimage = Some(*p);
							if held.is_none() {
								// Withheld by `leaf_data`: taken from the published tree.
								match self.take_from_tree(&coin, &nonce, now) {
									Ok(v) => {
										notes.push(json!({"leaf_id": leaf_id, "note": "the server does not serve this leaf, which participation \
											released for the wallet: withheld; recovered from the published tree, its preimage published there, \
											checked against the round"}));
										restored.push(v);
									},
									Err(why) => not_recovered.push(missed(&leaf_id, why)),
								}
							}
						}
					},
					Err(why) if released && held.is_none() => not_recovered.push(missed(&leaf_id, format!("the server does not serve this leaf, \
						which participation {} released for the wallet, and {}", pid, why))),
					Err(why) => notes.push(json!({"participation": pid, "leaf_id": leaf_id, "note": why})),
				}
			}
			if let Ok(t) = Txid::from_str(&rtx) {
				if let Some(round_tx) = self.chain.transaction(&t)? {
					self.store.put_tx(&rtx, &elements::encode::serialize(&round_tx), "round")?;
				}
			}
			let news = json!({"round": rtx, "leaves": news});
			self.store.set_participation_news(&pid, &news.to_string())?;
			match (released, preimage) {
				(true, Some(p)) => {
					self.store.set_participation(&pid, "released", Some(&hex(&p)), Some(&rtx))?;
					notes.push(json!({"participation": pid, "state": "released", "round": rtx}));
				},
				(true, None) => notes.push(json!({"participation": pid, "state": "issued", "round": rtx, "note": "released at the server, and \
					the wallet holds none of its new leaves: sync completes it once their preimage is out"})),
				_ => {},
			}
		}
		Ok(notes)
	}

	/// Keeps a round's leaf rebuilt from the published tree (`coin`), checked
	/// against the chain as a coin held is.
	fn take_from_tree(&mut self, coin: &CoinRecord, nonce: &[u8; 32], now: MedianTime) -> Result<Value, String> {
		let (owner, _) = owner_of(coin);
		let first = super::pay::first_expiry(coin).unwrap_or(u32::MAX);
		let a = self.assess(coin, &self.followed_policy(first, now), Some((&owner, nonce))).map_err(|e| e.to_string())?;
		let (state, note) = if a.all_final() { ("live", String::new()) } else { ("pending", format!("waiting: {}", a.waiting())) };
		let row = self.row(coin, &a, state, &note).map_err(|e| e.to_string())?;
		let id = row.leaf_id.clone();
		self.store.atomically(|s| {
			if s.nonce(nonce)?.is_none() {
				s.put_nonce(nonce, &owner.serialize(), "restored")?;
			}
			s.put_coin(&row)?;
			s.use_nonce(nonce, &id)
		}).map_err(|e| e.to_string())?;
		Ok(json!({"leaf_id": id, "kind": kind_of(coin), "asset": a.valid.asset.to_string(), "value": a.valid.value.to_string(), "state": state,
			"from": "the published tree"}))
	}
}
