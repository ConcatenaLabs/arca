//! Swept coins are repaid: what the operator owes the wallet for coins its
//! sweeps took.
//!
//! A coin the wallet neither refreshed nor took home before its batch was
//! swept is owed to it by the operator, less the published late-refresh fee
//! (the server's `owed`). Each `sync` asks the operator what it owes the
//! wallet's mailbox key (`owed`) and claims every entry owed (`owed_claim`):
//! signed by the swept coin's owner key, for one new leaf of exactly what is
//! owed, under a key of the wallet's. The operator makes that leaf in the
//! asset's next round, as a participation of its own making that gives up no
//! coin, which the wallet then completes as any participation of its own
//! (no forfeit; its unroll authorisations for the new leaf).
//!
//! The new leaf's owner nonce follows from the swept coin and the attempt
//! ([`repayment_nonce`]), so a wallet restored from its mnemonic recognises a
//! claim made before it was restored and completes it; an attempt the
//! operator voided is followed by the next. Until the new leaf is held, what
//! is owed counts in the balance as `returning`, and the swept coin is shown
//! `lost`, its note saying it is being repaid. The wallet takes nothing on
//! the operator's word but what it is paid: the new leaf is validated against
//! the round as every leaf is.

use elements::hashes::{sha256, Hash, HashEngine};
use elements::AssetId;
use serde_json::{json, Value};
use std::str::FromStr;

use arca_covenant::{Chain, LeafId, Template};
use elements::secp256k1_zkp::XOnlyPublicKey;

use super::chain::{hex, unhex32};
use super::client::{auth_digest, key_proof_digest, participation_id, Wanted};
use super::wallet::{sign, Wallet};
use super::Error;

/// Where the wallet keeps the operator's last answer to `owed`.
pub(crate) const OWED_META: &str = "owed";

/// The tag of the digest a swept coin's owner key signs to claim it.
pub const OWED_CLAIM_TAG: &[u8] = b"Arca/owed-claim";

/// The tag of a repayment leaf's owner nonce.
const NONCE_TAG: &[u8] = b"Arca/owed-repayment-nonce";

/// The most attempts the wallet makes at one entry: one more each time the
/// operator voids a claim's participation (its round lost, or its forfeit
/// day passed before the wallet came back).
const ATTEMPTS: u8 = 16;

/// What a swept coin's owner key signs to claim it: `SHA256(T ‖ T ‖ genesis ‖
/// S ‖ coin ‖ participation id)`, `T = SHA256("Arca/owed-claim")`. The layout
/// is the server's (`server::owed::claim_digest`).
pub fn claim_digest(chain: &Chain, operator: &XOnlyPublicKey, coin: &LeafId, participation: &[u8; 32]) -> [u8; 32] {
	let t = sha256::Hash::hash(OWED_CLAIM_TAG);
	let mut e = sha256::Hash::engine();
	e.input(t.as_byte_array());
	e.input(t.as_byte_array());
	e.input(&chain.genesis_bytes());
	e.input(&operator.serialize());
	e.input(&coin.0);
	e.input(participation);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// The owner nonce of the leaf that repays `coin` at attempt `k`: public, and
/// the key it gives the wallet's alone, so a restored wallet finds it again.
pub fn repayment_nonce(coin: &LeafId, k: u8) -> [u8; 32] {
	let t = sha256::Hash::hash(NONCE_TAG);
	let mut e = sha256::Hash::engine();
	e.input(t.as_byte_array());
	e.input(t.as_byte_array());
	e.input(&coin.0);
	e.input(&[k]);
	sha256::Hash::from_engine(e).to_byte_array()
}

impl Wallet {
	/// What the operator owes the wallet for swept coins, as it answers the
	/// wallet's mailbox key now: each coin, its value, the late-refresh fee
	/// and what is owed, the sweep, and its state (`owed`, `claimed`,
	/// `repaid`, or `withdrawn` while a rollback holds its sweep out of
	/// finality). Kept for the balance. Signs nothing but the lookup's proof.
	pub fn owed(&mut self) -> Result<Value, Error> {
		let entries = self.owed_lookup()?;
		self.store.set_meta(OWED_META, &Value::Array(entries.clone()).to_string())?;
		Ok(Value::Array(entries))
	}

	fn owed_lookup(&self) -> Result<Vec<Value>, Error> {
		let mailbox = self.keys.mailbox()?;
		let x = mailbox.x_only_public_key().0;
		let v = self.server.post("challenge", &json!({}))?;
		let challenge = unhex32(v["challenge"].as_str().unwrap_or(""))?;
		let proof = sign(&mailbox, &auth_digest(&self.genesis, "owed", &challenge, &x, &[]));
		let answer = self.server.post("owed", &json!({"challenge": hex(&challenge),
			"keys": [{"key": hex(&x.serialize()), "signature": hex(proof.as_ref())}]}))?;
		// Only entries under a key the wallet holds are its own.
		let mut out = vec![];
		for e in answer["owed"].as_array().cloned().unwrap_or_default() {
			let Ok(nonce) = unhex32(e["owner_nonce"].as_str().unwrap_or("")) else { continue };
			if self.keys.leaf_xonly(&nonce).ok().map(|k| hex(&k.serialize())).as_deref() != e["owner"].as_str() {
				continue;
			}
			out.push(e);
		}
		Ok(out)
	}

	/// What is owed and not yet held, per asset: every entry owed or claimed
	/// whose repayment the wallet has not completed. The balance counts it as
	/// `returning`.
	pub(crate) fn returning(&self) -> Result<Vec<(String, u64)>, Error> {
		let Some(m) = self.store.meta(OWED_META)? else { return Ok(vec![]) };
		let entries: Vec<Value> = serde_json::from_str(&m).unwrap_or_default();
		let done: Vec<String> = self.store.participations()?.into_iter().filter(|p| p.4 == "released").map(|p| p.0).collect();
		let mut out = vec![];
		for e in entries {
			if !matches!(e["state"].as_str(), Some("owed") | Some("claimed")) {
				continue;
			}
			if e["participation_id"].as_str().is_some_and(|p| done.iter().any(|d| d == p)) {
				continue;
			}
			let (Some(a), Some(v)) = (e["asset"].as_str(), e["owed"].as_str().and_then(|v| v.parse::<u64>().ok())) else { continue };
			out.push((a.to_string(), v));
		}
		Ok(out)
	}

	/// The step of `sync`: asks what is owed, shows each swept coin the
	/// wallet holds as lost and being repaid, claims every entry owed, and
	/// takes up a claim made before a restore as the wallet's own
	/// participation, which `sync` then completes.
	pub(crate) fn progress_owed(&mut self) -> Result<Vec<Value>, Error> {
		let entries = self.owed_lookup()?;
		self.store.set_meta(OWED_META, &Value::Array(entries.clone()).to_string())?;
		let mut out = vec![];
		for e in &entries {
			let leaf = e["leaf_id"].as_str().unwrap_or("").to_string();
			let state = e["state"].as_str().unwrap_or("");
			if matches!(state, "owed" | "claimed" | "repaid") {
				if let Some(c) = self.store.coin(&leaf)? {
					if !matches!(c.state.as_str(), "spent" | "exited") && !c.note.starts_with("swept") {
						self.store.set_coin_state(&leaf, "lost", &format!("swept by {} after its expiry: the operator repays it as a new coin, \
							less the late-refresh fee of {}", e["sweep_txid"].as_str().unwrap_or(""), e["fee"].as_str().unwrap_or("")))?;
					}
				}
			}
			let step = match state {
				"owed" => self.claim_owed(e),
				"claimed" => self.adopt_owed(e),
				_ => continue,
			};
			out.push(step.unwrap_or_else(|err| json!({"leaf_id": leaf, "state": state, "error": err.to_string()})));
		}
		Ok(out)
	}

	/// The leaf wanted for entry `e` at attempt `k`, with its nonce.
	fn repayment_leaf(&self, info: &Value, e: &Value, k: u8) -> Result<(Wanted, [u8; 32], Value), Error> {
		let coin = LeafId::from_str(e["leaf_id"].as_str().unwrap_or("")).map_err(|e| Error::Parse(e.to_string()))?;
		let asset = AssetId::from_str(e["asset"].as_str().unwrap_or("")).map_err(|e| Error::Parse(e.to_string()))?;
		let value: u64 = e["owed"].as_str().unwrap_or("").parse().map_err(|_| Error::Parse("what is owed".into()))?;
		let nonce = repayment_nonce(&coin, k);
		let owner = self.keys.leaf_xonly(&nonce)?;
		let landing = self.landing_rule(info, asset)?;
		let template = if landing.is_some() { Template::Landing1 } else { Template::Vtxo1 };
		let wanted = Wanted::Leaf { asset, value, template, owner, owner_nonce: nonce, exit_delay: self.exit_delay(), order: None, landing,
			channel: None };
		let mut entry = json!({"nonce": hex(&nonce), "asset": asset.to_string(), "value": value.to_string()});
		if let Some(l) = &landing {
			entry["landing"] = arca_covenant::record_json::landing_json(l);
		}
		Ok((wanted, nonce, entry))
	}

	/// Claims entry `e`, owed: the first attempt the wallet has not made, and
	/// on to the next while the operator says its key or participation is
	/// taken (an attempt it voided).
	fn claim_owed(&mut self, e: &Value) -> Result<Value, Error> {
		let info = self.server_info()?;
		let coin = LeafId::from_str(e["leaf_id"].as_str().unwrap_or("")).map_err(|e| Error::Parse(e.to_string()))?;
		let owner_nonce = unhex32(e["owner_nonce"].as_str().unwrap_or(""))?;
		let coin_key = self.coin_key(&owner_nonce)?;
		for k in 0..ATTEMPTS {
			let (wanted, nonce, entry) = self.repayment_leaf(&info, e, k)?;
			let id = participation_id(&self.genesis, &self.operator, &[], std::slice::from_ref(&wanted), &[], None);
			let pid = hex(&id);
			if self.store.participations()?.iter().any(|p| p.0 == pid) {
				continue;
			}
			let key = self.keys.leaf(&nonce)?;
			let mut j = wanted.json();
			j["leaf"]["key_proof"] = json!(hex(sign(&key, &key_proof_digest(&id)).as_ref()));
			let (mailbox, proof) = self.binding(&key)?;
			j["leaf"]["mailbox"] = json!(mailbox);
			j["leaf"]["mailbox_proof"] = json!(proof);
			let signature = sign(&coin_key, &claim_digest(&self.genesis, &self.operator, &coin, &id));
			let body = json!({"leaf_id": coin.to_string(), "leaf": j["leaf"], "signature": hex(signature.as_ref())});
			match self.server.post("owed_claim", &body) {
				Ok(st) => {
					if st["participation_id"].as_str() != Some(pid.as_str()) {
						return Err(Error::Refused(format!("the operator answers the claim of coin {} with participation {}, not {}", coin,
							st["participation_id"], pid)));
					}
					self.take_up_repayment(&pid, &nonce, &key, &entry)?;
					return Ok(json!({"leaf_id": coin.to_string(), "state": "claimed", "participation": pid, "owed": e["owed"]}));
				},
				Err(Error::Server { code, .. }) if code == "key_reused" => continue,
				Err(err) => return Err(err),
			}
		}
		Err(Error::Refused(format!("coin {}: {} attempts at its repayment are taken", coin, ATTEMPTS)))
	}

	/// Entry `e` is claimed: by an attempt of the wallet's (made before a
	/// restore, or before the wallet's store lost it), taken up as its own
	/// participation; one the wallet holds already is followed by `sync`.
	fn adopt_owed(&mut self, e: &Value) -> Result<Value, Error> {
		let pid = e["participation_id"].as_str().unwrap_or("").to_string();
		if self.store.participations()?.iter().any(|p| p.0 == pid) {
			return Ok(json!({"leaf_id": e["leaf_id"], "state": "claimed", "participation": pid}));
		}
		let info = self.server_info()?;
		for k in 0..ATTEMPTS {
			let (wanted, nonce, entry) = self.repayment_leaf(&info, e, k)?;
			let id = participation_id(&self.genesis, &self.operator, &[], std::slice::from_ref(&wanted), &[], None);
			if hex(&id) == pid {
				let key = self.keys.leaf(&nonce)?;
				self.take_up_repayment(&pid, &nonce, &key, &entry)?;
				return Ok(json!({"leaf_id": e["leaf_id"], "state": "claimed", "participation": pid, "note": "a claim made before, taken up"}));
			}
		}
		Ok(json!({"leaf_id": e["leaf_id"], "state": "claimed", "participation": pid,
			"note": "claimed by a participation the wallet cannot recognise as its own; it takes nothing from it"}))
	}

	/// Records the repayment participation `pid` as the wallet's own: no
	/// coin given up, one leaf wanted under the nonce `nonce`.
	fn take_up_repayment(&mut self, pid: &str, nonce: &[u8; 32], key: &elements::secp256k1_zkp::Keypair, entry: &Value) -> Result<(), Error> {
		let owner = key.x_only_public_key().0.serialize();
		let held = self.store.nonce(nonce)?.is_some();
		let wanted = Value::Array(vec![entry.clone()]);
		self.store.atomically(|s| {
			if !held {
				s.put_nonce(nonce, &owner, "repayment")?;
			}
			s.put_participation(pid, "{}", "[]", &wanted.to_string())?;
			s.set_participation(pid, "pending", None, None)
		})
	}
}
