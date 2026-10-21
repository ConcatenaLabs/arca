//! Offline refresh: a plan the wallet pre-signs so that the operator
//! refreshes a coin in later rounds while the wallet stays closed
//! ([`arca_covenant::plan`]).
//!
//! A plan covers one coin of a round and 1 to [`MAX_STEPS`] steps, one per
//! expiry the wallet will be away for. For each step the wallet draws an owner
//! nonce, so the new leaf's key comes from the mnemonic, derives the preimage
//! its entry is locked to from that key and nonce (a restore derives it
//! again), names a fresh on-chain address of its own for the refund's output
//! 0, and signs: the coin's attestation over the plan's id, each new key's
//! proof, both halves of every refund (each pays the wallet the step's value at
//! that address whenever the operator uses it), and each new key's binding to
//! the mailbox key. The operator quotes the plan first: its operator nonces,
//! the fee of each step (the refresh fee in the coin's free window, where the
//! wallet pays nothing unless the user raises its bound for the command), the
//! refund's margin and the script its own share pays to.
//!
//! The wallet takes the operator's word for nothing it can check. At each
//! `sync` it reads each plan's status and takes up each step whose round is
//! final: it rebuilds the step's leaf from the record the status serves,
//! validates it against the round, checks it is the leaf the plan names, signs
//! its unroll authorisations, hands them over, keeps the leaf as a coin of its
//! own, and only then marks the coin the step gave up spent. A step not taken
//! up leaves that coin the wallet's (D41). A plan the operator stopped is
//! cancelled, so the coin's batch is released as any other; the coin is the
//! wallet's to refresh or take home.
//!
//! A coin a plan names is paid out of round by no wallet: its refund halves
//! are valid while its script is unspent, and with one the operator alone
//! could void a reassignment of it. The wallet refreshes it in a round first.
//!
//! The schedule names, for each plan, the date until which it covers the coin
//! at the earliest, if the operator applies it ([`covered_until`]): each step
//! runs no earlier than five days before its coin's first expiry, and each new
//! batch expires no sooner than the acceptance horizon after its round. The
//! wallet must sync before the last coin's refresh window, which is when
//! `next_sync_at` names for it. The operator applies the plan: one that applies
//! no step, applies one early, or sweeps a coin whose holder is away, takes
//! that coin, as it can take any coin whose holder stays away past its expiry.
//! What the wallet hands over gives it nothing more.

use std::collections::HashSet;
use std::str::FromStr;

use elements::hashes::{sha256, Hash, HashEngine};
use elements::{AssetId, Script, Txid};
use serde_json::{json, Value};

use arca_covenant::plan::{key_proof_digest, Plan, PlanStep, MAX_STEPS};
use arca_covenant::{CoinRecord, LeafId, LeafRecord, MedianTime, RelativeTime, WalletPolicy};

use super::chain::{hex, unhex, unhex32};
use super::client::mailbox_binding_digest;
use super::keys::{p2wpkh, RECEIVE};
use super::round::{fee_within, FREE_WINDOW};
use super::store::CoinRow;
use super::wallet::{amount, sign, Wallet};
use super::{random32, Error, DEFAULT_MAX_FEE_PPM};

/// The tag of the hash a step's preimage is: `SHA256(T ‖ secret(A) ‖ nonce)`.
pub const PREIMAGE_TAG: &[u8] = b"Arca/plan-preimage";
/// The tag of the digest a coin's owner signs to ask for a quote.
pub const QUOTE_TAG: &[u8] = b"Arca/plan-quote";
/// The tag of the digest the mailbox key signs to cancel a plan.
pub const CANCEL_TAG: &[u8] = b"Arca/plan-cancel";

/// How long before a coin's first expiry a step runs at the earliest: the
/// start of its free window.
pub const STEP_FROM: u32 = WalletPolicy::EXIT_DEADLINE + FREE_WINDOW;

/// The steps a plan holds unless the user names another number: two
/// expiries.
pub const DEFAULT_STEPS: usize = 2;

fn tagged(tag: &[u8]) -> sha256::HashEngine {
	let t = sha256::Hash::hash(tag);
	let mut e = sha256::Hash::engine();
	e.input(t.as_byte_array());
	e.input(t.as_byte_array());
	e
}

/// What a coin's owner signs to ask for a quote: the server's
/// (`server::plans::quote_digest`).
pub fn quote_digest(chain: &arca_covenant::Chain, operator: &elements::secp256k1_zkp::XOnlyPublicKey, coin: &LeafId,
	owner_nonces: &[[u8; 32]], exit_delay: RelativeTime) -> [u8; 32]
{
	let mut e = tagged(QUOTE_TAG);
	e.input(&chain.genesis_bytes());
	e.input(&operator.serialize());
	e.input(&coin.0);
	e.input(&[owner_nonces.len() as u8]);
	for n in owner_nonces {
		e.input(n);
	}
	e.input(&exit_delay.units().to_le_bytes());
	sha256::Hash::from_engine(e).to_byte_array()
}

/// What the plan's mailbox key signs to cancel it: the server's
/// (`server::plans::cancel_digest`).
pub fn cancel_digest(chain: &arca_covenant::Chain, operator: &elements::secp256k1_zkp::XOnlyPublicKey, plan: &[u8; 32]) -> [u8; 32] {
	let mut e = tagged(CANCEL_TAG);
	e.input(&chain.genesis_bytes());
	e.input(&operator.serialize());
	e.input(plan);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// The earliest a coin whose first expiry is `expiry` can still be covered
/// after `steps` steps: each step runs no earlier than [`STEP_FROM`] before
/// its coin's expiry, and each new batch expires no sooner than the
/// acceptance horizon after its round. The last coin's first expiry.
pub fn last_expiry(expiry: u32, steps: usize) -> u32 {
	let gain = WalletPolicy::DEFAULT_HORIZON.saturating_sub(STEP_FROM);
	expiry.saturating_add(gain.saturating_mul(steps as u32))
}

/// The date until which a plan of `steps` steps from a coin whose first
/// expiry is `expiry` covers it at the earliest: its last coin's exit
/// deadline.
pub fn covered_until(expiry: u32, steps: usize) -> u32 {
	last_expiry(expiry, steps).saturating_sub(WalletPolicy::EXIT_DEADLINE)
}

/// How near its step window a coin must be before `care` plans it: a coin
/// whose first step could run within this time of now. A younger coin stays
/// free to spend out of round (a coin a plan names is not), and is planned at
/// the first `care` once it comes this near. The gap this leaves, in plain
/// words: a wallet closed within a coin's first two weeks or so and kept
/// closed through that coin's step window can lose the coin to the
/// operator's sweep, as any holder who stays away past an expiry can.
pub const PLAN_WITHIN: u32 = 10 * 86_400;

/// The fee bound `care` plans under when the caller names none: 2,000
/// parts per million of a coin for each step. A step in its coin's free
/// window costs nothing; the bound only lets a plan through when the
/// operator asks a small fee there.
pub const CARE_MAX_FEE_PPM: u64 = 2_000;

/// The date by which the wallet must sync for a plan of `steps` steps from a
/// coin whose first expiry is `expiry`: the start of the last coin's refresh
/// window at the earliest.
pub fn sync_by(expiry: u32, steps: usize) -> u32 {
	last_expiry(expiry, steps).saturating_sub(STEP_FROM)
}

impl Wallet {
	/// The preimage of step `nonce`'s entry: `SHA256(T ‖ secret(A) ‖ nonce)`,
	/// `A` the key the mnemonic derives from the nonce: a restore derives it
	/// again.
	pub(crate) fn plan_preimage(&self, nonce: &[u8; 32]) -> Result<[u8; 32], Error> {
		let key = self.keys.leaf(nonce)?;
		let mut e = sha256::Hash::engine();
		e.input(PREIMAGE_TAG);
		e.input(&key.secret_bytes());
		e.input(nonce);
		Ok(sha256::Hash::from_engine(e).to_byte_array())
	}

	/// The plans the wallet holds, each `(id, coin, body, state, status)`.
	fn plan_rows(&self) -> Result<Vec<(String, String, Value, String, Value)>, Error> {
		let mut out = vec![];
		for (id, coin, body, state, status) in self.store.plans()? {
			let body: Value = serde_json::from_str(&body).map_err(|e| Error::Store(format!("plan {}: {}", id, e)))?;
			let status = status.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null);
			out.push((id, coin, body, state, status));
		}
		Ok(out)
	}

	/// Every coin a plan names (the coin it starts from, and each leaf a step
	/// made), whatever the plan's state: each carries refund halves the
	/// wallet signed, valid while its script is unspent.
	pub(crate) fn planned_coins(&self) -> Result<HashSet<String>, Error> {
		let mut out = HashSet::new();
		for (_, coin, body, _, _) in self.plan_rows()? {
			out.insert(coin);
			for s in body["steps"].as_array().into_iter().flatten() {
				if let Some(l) = s["leaf_id"].as_str() {
					out.insert(l.to_string());
				}
			}
		}
		Ok(out)
	}

	/// The current coin of each plan that is open: the coin its next step
	/// gives up, with the plan's id and the date the wallet must sync by.
	pub(crate) fn plan_currents(&self) -> Result<Vec<(String, String, u32)>, Error> {
		let mut out = vec![];
		for (id, coin, body, state, _) in self.plan_rows()? {
			if state != "open" {
				continue;
			}
			let current = Self::current_coin(&coin, &body);
			out.push((id, current, body["sync_by"].as_u64().unwrap_or(0) as u32));
		}
		Ok(out)
	}

	/// The coins a plan may start from: live leaves of a round, `vtxo-1`,
	/// named by no plan, all of them or those of `asset`.
	fn plannable(&self, asset: Option<AssetId>) -> Result<Vec<CoinRow>, Error> {
		let named = self.planned_coins()?;
		let mut out = vec![];
		for c in self.store.coins_in("live")? {
			if named.contains(&c.leaf_id) || asset.is_some_and(|a| c.asset != a.to_string()) {
				continue;
			}
			match CoinRecord::from_bytes(&c.record) {
				Ok(CoinRecord::Leaf { record, .. }) if record.htlc.is_none() => out.push(c),
				_ => {},
			}
		}
		Ok(out)
	}

	/// The coins `coins` names, or every coin a plan may start from.
	fn plan_coins(&self, coins: &[String]) -> Result<Vec<CoinRow>, Error> {
		if coins.is_empty() {
			let all = self.plannable(None)?;
			if all.is_empty() {
				return Err(Error::Refused("the wallet holds no live coin of a round that no plan names: a plan starts from a coin of a \
					round, so refresh a board or a received coin in a round first".into()));
			}
			return Ok(all);
		}
		let ok = self.plannable(None)?;
		coins.iter().map(|l| ok.iter().find(|c| &c.leaf_id == l).cloned().ok_or_else(|| Error::Refused(format!(
			"coin {} is no live coin of a round that no plan names: a plan starts from a coin of a round, so refresh a board or a received \
			coin in a round first", l)))).collect()
	}

	/// What the operator would charge for a plan of `steps` steps from each
	/// coin of `coins` (every coin a plan may start from when empty), and the
	/// dates it would cover each coin until at the earliest, checked against
	/// the wallet's bound; nothing is signed or kept. Each quote draws the
	/// operator's nonces, which a later `plan` does not reuse.
	pub fn plan_quote(&mut self, coins: &[String], steps: usize, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		let rows = self.plan_coins(coins)?;
		let mut out = vec![];
		for c in rows {
			let nonces: Vec<[u8; 32]> = (0..steps).map(|_| random32()).collect();
			let q = self.quote_plan(&c, &nonces)?;
			out.push(self.quote_json(&c, &q, steps, max_fee_ppm)?);
		}
		Ok(json!({"plans": out, "note": PLAN_NOTE}))
	}

	fn quote_plan(&mut self, c: &CoinRow, nonces: &[[u8; 32]]) -> Result<Value, Error> {
		if nonces.is_empty() || nonces.len() > MAX_STEPS {
			return Err(Error::Refused(format!("a plan holds 1 to {} steps, one per expiry the wallet will be away for", MAX_STEPS)));
		}
		self.server_info()?;
		let key = self.coin_key(&c.owner_nonce)?;
		let coin = LeafId::from_str(&c.leaf_id).map_err(|e| Error::Parse(e.to_string()))?;
		let digest = quote_digest(&self.genesis, &self.operator, &coin, nonces, self.exit_delay());
		let q = self.server.post("plan_quote", &json!({"coin": c.leaf_id, "owner_nonces": nonces.iter().map(|n| hex(n)).collect::<Vec<_>>(),
			"exit_delay_units": self.exit_delay().units(), "attestation": hex(sign(&key, &digest).as_ref())}))?;
		if q["coin"].as_str() != Some(c.leaf_id.as_str()) || q["asset"].as_str() != Some(c.asset.as_str())
			|| amount(&q["value"], "value")? != c.value || q["steps"].as_array().map(|s| s.len()) != Some(nonces.len())
		{
			return Err(Error::Refused(format!("the operator quotes another coin, value or number of steps than the wallet asked for: {}", q)));
		}
		Ok(q)
	}

	fn quote_json(&self, c: &CoinRow, q: &Value, steps: usize, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		let fees: Vec<u64> = q["steps"].as_array().into_iter().flatten().map(|s| amount(&s["fee"], "fee")).collect::<Result<_, _>>()?;
		let fee: u64 = fees.iter().sum();
		let bound = max_fee_ppm.unwrap_or(DEFAULT_MAX_FEE_PPM);
		let within = fees.iter().all(|f| *f == 0 || (max_fee_ppm.is_some() && fee_within(*f, c.value, bound)));
		Ok(json!({"coin": c.leaf_id, "asset": c.asset, "value": c.value.to_string(), "expiry": c.expiry, "steps": steps,
			"fees": fees.iter().map(|f| f.to_string()).collect::<Vec<_>>(), "fee": fee.to_string(), "within_bound": within,
			"covered_until": covered_until(c.expiry, steps), "sync_by": sync_by(c.expiry, steps), "earliest_step": q["earliest"]}))
	}

	/// Makes a plan of `steps` steps (1 to [`MAX_STEPS`]) from each coin of
	/// `coins`, every coin a plan may start from when empty: quoted, signed and
	/// handed to the operator, kept. A step's fee is refused above the
	/// wallet's bound, and any fee at all unless the user raises the bound
	/// for this command: a step runs in its coin's free window, where a
	/// refresh costs nothing.
	pub fn plan(&mut self, coins: &[String], steps: usize, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		let rows = self.plan_coins(coins)?;
		let mut out = vec![];
		for c in rows {
			out.push(match self.make_plan(&c, steps, max_fee_ppm) {
				Ok(v) => v,
				Err(e) => json!({"coin": c.leaf_id, "error": e.to_string()}),
			});
		}
		Ok(json!({"plans": out, "note": PLAN_NOTE}))
	}

	fn make_plan(&mut self, c: &CoinRow, steps: usize, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		let record = match CoinRecord::from_bytes(&c.record).map_err(|e| Error::Store(e.to_string()))? {
			CoinRecord::Leaf { record, .. } => record,
			_ => return Err(Error::Refused(format!("coin {} is not a leaf of a round", c.leaf_id))),
		};
		let key = self.coin_key(&c.owner_nonce)?;
		let mailbox = self.keys.mailbox()?;
		let nonces: Vec<[u8; 32]> = (0..steps).map(|_| random32()).collect();
		let keys: Vec<elements::secp256k1_zkp::Keypair> = nonces.iter().map(|n| self.keys.leaf(n)).collect::<Result<_, _>>()?;
		let q = self.quote_plan(c, &nonces)?;
		let shown = self.quote_json(c, &q, steps, max_fee_ppm)?;
		if shown["within_bound"] != json!(true) {
			return Err(Error::Refused(format!("the operator asks a fee of {} for the plan of coin {} ({:?} by step): a step runs in its \
				coin's free window, where a refresh costs nothing, so the wallet pays nothing unless the bound is raised for this command \
				(--max-fee-ppm), and never more than that bound", shown["fee"], c.leaf_id, shown["fees"])));
		}
		let op_script = Script::from(unhex(q["operator_script"].as_str().unwrap_or(""))?);
		let coin = LeafId::from_str(&c.leaf_id).map_err(|e| Error::Parse(e.to_string()))?;
		let asset = AssetId::from_str(&c.asset).map_err(|e| Error::Parse(e.to_string()))?;
		let mut plan_steps = Vec::with_capacity(steps);
		let mut indices = vec![];
		let mut preimages = vec![];
		let mut value = c.value;
		for (j, (n, k)) in nonces.iter().zip(&keys).enumerate() {
			let s = &q["steps"][j];
			let fee = amount(&s["fee"], "fee")?;
			value = value.checked_sub(fee).ok_or_else(|| Error::Refused("the operator's fees exceed the coin".into()))?;
			let index = self.store.take_index(RECEIVE)?;
			let holder = p2wpkh(&self.keys.onchain(RECEIVE, index)?);
			let preimage = self.plan_preimage(n)?;
			plan_steps.push(PlanStep {
				value, fee, owner: k.x_only_public_key().0, owner_nonce: *n,
				operator_nonce: unhex32(s["operator_nonce"].as_str().unwrap_or(""))?,
				exit_delay: self.exit_delay(), unlock_hash: sha256::Hash::hash(&preimage).to_byte_array(),
				holder_script: holder, operator_script: op_script.clone(), margin: amount(&s["margin"], "margin")?,
			});
			indices.push(index);
			preimages.push(preimage);
		}
		let plan = Plan { chain: self.genesis, operator: self.operator, coin, first: record.leaf(), asset, value: c.value, steps: plan_steps };
		plan.check().map_err(|e| Error::Refused(format!("the plan: {}", e)))?;
		let id = plan.id();
		let kd = key_proof_digest(&id);
		let mut body_steps = vec![];
		let mut kept_steps = vec![];
		for (j, s) in plan.steps.iter().enumerate() {
			let rf = plan.refund(j + 1).expect("checked");
			let old_key = if j == 0 { &key } else { &keys[j - 1] };
			let old = rf.old_message().map_err(|e| Error::Refused(e.to_string()))?;
			let new = rf.new_message().map_err(|e| Error::Refused(e.to_string()))?;
			let md = mailbox_binding_digest(&self.genesis, &self.operator, &s.owner, &mailbox.x_only_public_key().0);
			body_steps.push(json!({
				"value": s.value.to_string(), "fee": s.fee.to_string(), "owner": hex(&s.owner.serialize()), "owner_nonce": hex(&s.owner_nonce),
				"operator_nonce": hex(&s.operator_nonce), "exit_delay_units": s.exit_delay.units(), "unlock_hash": hex(&s.unlock_hash),
				"preimage": hex(&preimages[j]), "holder_script": hex(s.holder_script.as_bytes()),
				"operator_script": hex(s.operator_script.as_bytes()), "margin": s.margin.to_string(),
				"key_proof": hex(sign(&keys[j], &kd).as_ref()),
				"old_half": hex(sign(old_key, &old.digest).as_ref()), "new_half": hex(sign(&keys[j], &new.digest).as_ref()),
				"mailbox_proof": hex(sign(&keys[j], &md).as_ref()),
			}));
			kept_steps.push(json!({"idx": j + 1, "value": s.value.to_string(), "fee": s.fee.to_string(), "owner": hex(&s.owner.serialize()),
				"owner_nonce": hex(&s.owner_nonce), "operator_nonce": hex(&s.operator_nonce), "exit_delay_units": s.exit_delay.units(),
				"unlock_hash": hex(&s.unlock_hash), "holder_script": hex(s.holder_script.as_bytes()), "holder_index": indices[j]}));
		}
		// The keys and nonces are the wallet's before anything leaves it, so a
		// leaf a step makes is accepted under them.
		self.store.atomically(|s| {
			for (n, k) in nonces.iter().zip(&keys) {
				s.put_nonce(n, &k.x_only_public_key().0.serialize(), "plan")?;
			}
			Ok(())
		})?;
		let body = json!({"quote": q["quote"], "coin": c.leaf_id, "mailbox": hex(&mailbox.x_only_public_key().0.serialize()),
			"attestation": hex(sign(&key, &id).as_ref()), "steps": body_steps});
		let st = self.server.post("submit_plan", &body)?;
		if st["plan_id"].as_str() != Some(hex(&id).as_str()) {
			return Err(Error::Refused(format!("the operator answers for another plan than the wallet made: {}", st)));
		}
		let kept = json!({"plan_id": hex(&id), "coin": c.leaf_id, "asset": c.asset, "value": c.value.to_string(), "expiry": c.expiry,
			"first": {"owner": hex(&record.owner.serialize()), "salt": hex(&record.salt()), "exit_delay_units": record.exit_delay.units()},
			"steps": kept_steps, "covered_until": covered_until(c.expiry, steps), "sync_by": sync_by(c.expiry, steps),
			"made_at": self.now()?.to_consensus_u32()});
		let state = st["state"].as_str().unwrap_or("open").to_string();
		self.store.put_plan(&hex(&id), &c.leaf_id, &kept.to_string(), &state)?;
		self.store.set_plan(&hex(&id), &state, Some(&st.to_string()))?;
		Ok(json!({"plan_id": hex(&id), "coin": c.leaf_id, "state": state, "steps": steps, "covered_until": kept["covered_until"],
			"sync_by": kept["sync_by"], "fee": shown["fee"]}))
	}

	/// Every plan the wallet made or restored: its coin, its steps (each with
	/// the leaf it makes, its state and the leaf once taken up), its state, and
	/// the dates it covers the coin until at the earliest and the wallet must
	/// sync by.
	pub fn plans(&self) -> Result<Value, Error> {
		let mut out = vec![];
		for (id, coin, body, state, status) in self.plan_rows()? {
			let steps: Vec<Value> = body["steps"].as_array().cloned().unwrap_or_default().into_iter().enumerate().map(|(j, mut s)| {
				let st = &status["steps"][j];
				s["state"] = st["state"].clone();
				if !st["reason"].is_null() {
					s["reason"] = st["reason"].clone();
				}
				if !st["round_txid"].is_null() {
					s["round"] = st["round_txid"].clone();
				}
				s
			}).collect();
			let mut p = json!({"plan_id": id, "coin": coin, "asset": body["asset"], "value": body["value"], "state": state, "steps": steps,
				"covered_until": body["covered_until"], "sync_by": body["sync_by"]});
			if !status["reason"].is_null() {
				p["reason"] = status["reason"].clone();
			}
			out.push(p);
		}
		Ok(json!({"plans": out, "note": PLAN_NOTE}))
	}

	/// What a wallet does by itself at a sync, so that it needs no prompt:
	/// takes up every open claim under its on-chain receive keys (`scan`
	/// of them from the first, as [`Self::claim`]); cancels each open plan
	/// whose current coin has moved (spent, exited or lost, or gone from the
	/// store); and plans each live coin of a round that no plan names and
	/// whose first step could run within [`PLAN_WITHIN`], `steps` steps
	/// under the fee bound `max_fee_ppm` ([`CARE_MAX_FEE_PPM`] unless
	/// named). A plan's fee is the operator's, taken from the coin in the
	/// coin's own asset; a coin the operator will not plan stays unplanned,
	/// with the operator's reason, and `sync` refreshes it while the wallet
	/// is open. One part failing stops no other; each says what it did.
	pub fn care(&mut self, scan: Option<u32>, steps: usize, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		let claims = self.claim(&[], scan).unwrap_or_else(|e| json!({"error": e.to_string()}));
		let mut cancelled = vec![];
		for (id, coin, body, state, _) in self.plan_rows()? {
			if state != "open" {
				continue;
			}
			let current = Self::current_coin(&coin, &body);
			let moved = self.store.coin(&current)?.is_none_or(|c| matches!(c.state.as_str(), "spent" | "exited" | "lost"));
			if !moved {
				continue;
			}
			cancelled.push(match self.cancel_at_operator(&id) {
				Ok(st) => json!({"plan_id": id, "coin": current, "state": st["state"]}),
				Err(e) => json!({"plan_id": id, "coin": current, "error": e.to_string()}),
			});
		}
		let now = self.now()?.to_consensus_u32();
		let bound = Some(max_fee_ppm.unwrap_or(CARE_MAX_FEE_PPM));
		let mut planned = vec![];
		let mut later = 0usize;
		for c in self.plannable(None)? {
			if now.saturating_add(PLAN_WITHIN) < c.expiry.saturating_sub(STEP_FROM) {
				later += 1;
				continue;
			}
			planned.push(match self.make_plan(&c, steps, bound) {
				Ok(v) => v,
				Err(e) => json!({"coin": c.leaf_id, "asset": c.asset, "error": e.to_string()}),
			});
		}
		Ok(json!({"claims": claims, "cancelled": cancelled, "planned": planned, "not_yet_planned": later,
			"plan_within": PLAN_WITHIN, "max_fee_ppm": bound}))
	}

	/// Cancels the steps of plan `id` that have not started.
	pub fn plan_cancel(&mut self, id: &str) -> Result<Value, Error> {
		let row = self.plan_rows()?.into_iter().find(|p| p.0 == id).ok_or_else(|| Error::Refused(format!("no plan {}", id)))?;
		let st = self.cancel_at_operator(&row.0)?;
		Ok(json!({"plan_id": id, "state": st["state"], "note": "the steps that had not started will not run; every coin the plan \
			named stays out of out-of-round payments until it is refreshed in a round, its refund halves being valid while its script is \
			unspent"}))
	}

	fn cancel_at_operator(&mut self, id: &str) -> Result<Value, Error> {
		let pid = unhex32(id)?;
		let mailbox = self.keys.mailbox()?;
		let st = self.server.post("cancel_plan", &json!({"plan_id": id,
			"signature": hex(sign(&mailbox, &cancel_digest(&self.genesis, &self.operator, &pid)).as_ref())}))?;
		let state = st["state"].as_str().unwrap_or("cancelled").to_string();
		self.store.set_plan(id, &state, Some(&st.to_string()))?;
		Ok(st)
	}

	/// For `sync`: each plan's status read, and each step whose round is
	/// final taken up ([`Self::take_up_step`]); a plan the operator stopped is
	/// cancelled, its coin the wallet's to refresh or take home.
	pub(crate) fn progress_plans(&mut self) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		for (id, _, body, state, _) in self.plan_rows()? {
			if state == "cancelled" || (state == "done" && Self::all_taken(&body)) {
				continue;
			}
			let st = match self.server.post("plan_status", &json!({"plan_id": id})) {
				Ok(s) => s,
				Err(e) => {
					out.push(json!({"plan_id": id, "error": e.to_string()}));
					continue;
				},
			};
			self.store.set_plan(&id, st["state"].as_str().unwrap_or(&state), Some(&st.to_string()))?;
			let done: Vec<usize> = st["steps"].as_array().into_iter().flatten().enumerate()
				.filter(|(_, s)| s["state"] == "done").map(|(j, _)| j).collect();
			let mut body = body;
			body["status_steps_done"] = json!(done);
			let mut taken = vec![];
			for (j, s) in st["steps"].as_array().cloned().unwrap_or_default().into_iter().enumerate() {
				if s["state"] != "done" {
					continue;
				}
				if body["steps"][j]["leaf_id"].is_string() {
					continue;
				}
				match self.take_up_step(&id, j, &body, &s) {
					Ok(v) => {
						// The body as the take-up kept it, for the next step.
						if let Some((_, _, fresh, _, _)) = self.plan_rows()?.into_iter().find(|p| p.0 == id) {
							body = fresh;
							body["status_steps_done"] = json!(done);
						}
						taken.push(v);
					},
					Err(e) => {
						taken.push(json!({"step": j + 1, "error": e.to_string(), "note": "the coin it gave up stays the wallet's until the \
							step's leaf is taken up"}));
						break;
					},
				}
			}
			let mut v = json!({"plan_id": id, "state": st["state"], "taken_up": taken});
			if st["state"] == "stopped" {
				v["reason"] = st["reason"].clone();
				// The operator holds the batch of a stopped plan's coin until
				// the coin is on the chain. The wallet cancels the plan, which
				// lets that batch go as any other, only while the coin can
				// still be refreshed, or once it is no longer at stake: a coin
				// on its way home keeps the plan stopped until it is home.
				let current = self.plan_rows()?.into_iter().find(|p| p.0 == id).map(|p| Self::current_coin(&p.1, &p.2))
					.unwrap_or_default();
				let row = self.store.coin(&current)?;
				let now = self.now()?.to_consensus_u32();
				let refreshable = row.as_ref().is_some_and(|c| matches!(c.state.as_str(), "live" | "pending")
					&& super::wallet::CoinDates::of(c.expiry).is_some_and(|d| now < d.home_from));
				let settled = row.as_ref().is_none_or(|c| matches!(c.state.as_str(), "exited" | "spent" | "lost"));
				if refreshable || settled {
					match self.cancel_at_operator(&id) {
						Ok(_) => v["note"] = json!(self.spelling.say("the operator stopped the plan; the wallet cancelled it, so its coin's \
							batch is released as any other: the coin is the wallet's to refresh or take home, and {sync} does so by its dates")),
						Err(e) => v["cancel_error"] = json!(e.to_string()),
					}
				} else {
					v["note"] = json!(format!("the operator stopped the plan, and holds the batch of its coin {} until the coin is on the \
						chain; the wallet takes it home and cancels the plan once it is", current));
				}
			}
			out.push(v);
		}
		Ok(out)
	}

	/// For the re-check, whether or not the operator answers: a step the
	/// wallet took up whose round can never return, as the wallet's own node
	/// sees it (an input of the round spent by another transaction that is
	/// final), did not happen. The coin it gave up is the wallet's again,
	/// `live`, to refresh or take home by its dates, and the step is kept
	/// marked `lost`. The leaves of that step and of the steps after it are
	/// the re-check's to follow, as any coin's. Should the parent chain bring
	/// the round back, final, the step stands again and the coin it gave up
	/// is spent again, as a refresh's is ([`Self::recheck`]): the step's leaf
	/// holds its value. The operator's word decides nothing here: one that
	/// calls a step void while its round stands frees no coin.
	pub(crate) fn plan_rounds_gone(&mut self) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		for (id, coin, body, _, _) in self.plan_rows()? {
			let steps = body["steps"].as_array().cloned().unwrap_or_default();
			for (j, s) in steps.iter().enumerate() {
				let (Some(round), Some(leaf)) = (s["round"].as_str(), s["leaf_id"].as_str()) else { break };
				let Some(raw) = self.store.tx(round)? else { continue };
				let tx: elements::Transaction = elements::encode::deserialize(&raw).map_err(|e| Error::Store(e.to_string()))?;
				let gave_up = if j == 0 { coin.clone() } else { steps[j - 1]["leaf_id"].as_str().unwrap_or("").to_string() };
				let by = format!("plan {} step {}", id, j + 1);
				let lost = s["lost"].as_bool() == Some(true);
				if !lost && self.chain.gone(&tx)? {
					let why = format!("step {} of plan {} ran in round {}, which can never return: an input of it is spent by another \
						transaction, final. The step did not happen, and this coin is the wallet's again", j + 1, id, round);
					let mut kept = body.clone();
					kept["steps"][j]["lost"] = json!(true);
					let back = self.store.atomically(|st| {
						let back = st.unspend_coin(&gave_up, &by, &why)?;
						st.update_plan_body(&id, &kept.to_string())?;
						Ok(back)
					})?;
					out.push(json!({"leaf_id": gave_up, "plan": id, "step": j + 1, "round": round, "can_never_return": true,
						"from": if back { json!("spent") } else { Value::Null }, "to": if back { json!("live") } else { Value::Null },
						"why": why, "lost_leaf": leaf}));
					break;
				}
				// The round back, final: the step's leaf is the wallet's again
				// (a step's leaf has no participation to revive it, as a
				// refresh's has), and only then the coin it gave up is spent.
				if lost && self.chain.finality(&tx.txid())?.is_final() && self.revive_step_leaf(leaf, round)? {
					let mut kept = body.clone();
					kept["steps"][j]["lost"] = json!(false);
					let respent = self.store.atomically(|st| {
						let live = st.coin(&gave_up)?.is_some_and(|c| c.state == "live");
						if live {
							st.set_coin_spent(&gave_up, &by)?;
						}
						st.update_plan_body(&id, &kept.to_string())?;
						Ok(live)
					})?;
					out.push(json!({"leaf_id": gave_up, "plan": id, "step": j + 1, "round": round, "returned": true,
						"to": if respent { json!("spent") } else { Value::Null }, "kept_leaf": leaf}));
				}
				if lost {
					break;
				}
			}
		}
		Ok(out)
	}

	/// The leaf `leaf` a step made, lost while its round `round` was out of
	/// the chain, the wallet's again now that the round is final: checked
	/// against the chain as of its expiry, as any leaf read again, and left
	/// lost when a final sweep or another spend has cut its path. Whether the
	/// wallet holds it now.
	fn revive_step_leaf(&mut self, leaf: &str, round: &str) -> Result<bool, Error> {
		let Some(c) = self.store.coin(leaf)? else { return Ok(false) };
		if matches!(c.state.as_str(), "live" | "pending") {
			return Ok(true);
		}
		if c.state != "lost" {
			return Ok(false);
		}
		let record = Self::record_of(&c)?;
		let now = self.now()?;
		let Ok(bases) = self.accepted_bases(&record) else { return Ok(false) };
		let Ok(valid) = record.resolve(&bases, &self.followed_policy(c.expiry, now)) else { return Ok(false) };
		if self.cut_by_final_spend(&valid)? {
			return Ok(false);
		}
		let mut fin = true;
		for t in &bases {
			fin &= self.chain.finality(&t.txid())?.is_final();
		}
		let (to, why) = if fin { ("live", format!("round {} is final in the chain again", round)) } else {
			("pending", format!("round {} is in the chain again, not yet final", round)) };
		self.store.set_coin_state(&c.leaf_id, to, &why)?;
		Ok(true)
	}

	/// For a restore: every plan the operator serves to the mailbox key,
	/// kept as the lost store kept it, its keys checked against the mnemonic
	/// (each step's key must be the one its owner nonce derives); `sync` then
	/// takes up each step whose round is final, as for a plan the wallet made.
	pub(crate) fn restore_plans(&mut self) -> Result<Vec<Value>, Error> {
		let mailbox = self.keys.mailbox()?;
		let auth = self.server.auth("plans", &mailbox, &self.genesis, &[])?;
		let served = self.server.post("plans", &json!({"auth": auth}))?;
		let held: HashSet<String> = self.plan_rows()?.into_iter().map(|p| p.0).collect();
		let mut out = vec![];
		for st in served["plans"].as_array().cloned().unwrap_or_default() {
			let id = st["plan_id"].as_str().unwrap_or("").to_string();
			if held.contains(&id) {
				continue;
			}
			let coin = st["coin"].as_str().unwrap_or("").to_string();
			let expiry = self.store.coin(&coin)?.map(|c| c.expiry).unwrap_or(0);
			let mut steps = vec![];
			let mut nonces = vec![];
			for (j, s) in st["steps"].as_array().cloned().unwrap_or_default().into_iter().enumerate() {
				let nonce = unhex32(s["owner_nonce"].as_str().unwrap_or(""))?;
				let key = self.keys.leaf(&nonce)?;
				if Some(hex(&key.x_only_public_key().0.serialize())) != s["owner"].as_str().map(String::from) {
					return Err(Error::Refused(format!("plan {} step {}: its key is not the key this mnemonic derives from its owner nonce", id,
						j + 1)));
				}
				nonces.push((nonce, key));
				steps.push(json!({"idx": j + 1, "value": s["value"], "fee": s["fee"], "owner": s["owner"], "owner_nonce": s["owner_nonce"],
					"operator_nonce": s["operator_nonce"], "exit_delay_units": s["exit_delay_units"], "unlock_hash": s["unlock_hash"],
					"holder_script": s["holder_script"]}));
			}
			let n = steps.len();
			self.store.atomically(|s| {
				for (nonce, key) in &nonces {
					if s.nonce(nonce)?.is_none() {
						s.put_nonce(nonce, &key.x_only_public_key().0.serialize(), "plan")?;
					}
				}
				Ok(())
			})?;
			let body = json!({"plan_id": id, "coin": coin, "asset": st["asset"], "value": st["value"], "expiry": expiry, "steps": steps,
				"covered_until": covered_until(expiry, n), "sync_by": sync_by(expiry, n), "restored": true});
			let state = st["state"].as_str().unwrap_or("open").to_string();
			self.store.put_plan(&id, &coin, &body.to_string(), &state)?;
			self.store.set_plan(&id, &state, Some(&st.to_string()))?;
			out.push(json!({"plan_id": id, "coin": coin, "state": state, "steps": n}));
		}
		Ok(out)
	}

	/// The coin a plan stands on as the wallet holds it: the leaf of the last
	/// step it took up whose round is not lost, or the coin it started from.
	fn current_coin(coin: &str, body: &Value) -> String {
		let mut current = coin.to_string();
		for s in body["steps"].as_array().into_iter().flatten() {
			match s["leaf_id"].as_str() {
				Some(l) if s["lost"].as_bool() != Some(true) => current = l.to_string(),
				_ => break,
			}
		}
		current
	}

	fn all_taken(body: &Value) -> bool {
		body["steps"].as_array().is_some_and(|s| s.iter().all(|x| x["leaf_id"].is_string()))
	}

	/// Takes up step `j` (from 0) of plan `id`, whose round the status `s`
	/// calls final: the leaf rebuilt from the record served, validated against
	/// the round as of its expiry once that has passed, checked to be the leaf
	/// the plan names (key, owner nonce, operator nonce, exit delay, value,
	/// unlock hash), its unroll authorisations signed and handed over; kept
	/// as a coin of the wallet's, and only then the coin the step gave up
	/// marked spent.
	fn take_up_step(&mut self, id: &str, j: usize, body: &Value, s: &Value) -> Result<Value, Error> {
		let want = &body["steps"][j];
		let nonce = unhex32(want["owner_nonce"].as_str().unwrap_or(""))?;
		let key = self.keys.leaf(&nonce)?;
		let preimage = self.plan_preimage(&nonce)?;
		let record = LeafRecord::from_bytes(&unhex(s["record"].as_str().unwrap_or(""))?)
			.map_err(|e| Error::Refused(format!("the record the operator serves for step {}: {}", j + 1, e)))?;
		let round_txid = Txid::from_str(s["round_txid"].as_str().unwrap_or("")).map_err(|e| Error::Parse(e.to_string()))?;
		let finality = self.chain.finality(&round_txid)?;
		if !finality.is_final() {
			return Err(Error::Refused(format!("step {}'s round {} is {}: the wallet takes up nothing of a round that is not final", j + 1,
				round_txid, finality.word())));
		}
		let round = self.chain.transaction(&round_txid)?.ok_or_else(|| Error::Node(format!("the node does not have round {}", round_txid)))?;
		let now = self.now()?;
		let first = record.schedule.expiries()[0].to_consensus_u32();
		let policy = self.followed_policy(first, now);
		let valid = record.validate(&round, &policy, &key.x_only_public_key().0, &nonce)
			.map_err(|e| Error::Refused(format!("step {}'s leaf does not check out: {}", j + 1, e)))?;
		let named = |k: &str| want[k].as_str().map(|v| v.to_string());
		if Some(hex(&record.operator_nonce)) != named("operator_nonce") || Some(record.value.to_string()) != named("value")
			|| Some(hex(&record.unlock_hash)) != named("unlock_hash") || record.exit_delay.units() as u64 != want["exit_delay_units"].as_u64().unwrap_or(0)
			|| record.asset.to_string() != body["asset"].as_str().unwrap_or("") || record.htlc.is_some()
		{
			return Err(Error::Refused(format!("step {}'s leaf is not the leaf the plan names", j + 1)));
		}
		if sha256::Hash::hash(&preimage).to_byte_array() != record.unlock_hash {
			return Err(Error::Refused(format!("step {}'s preimage does not open its leaf's entry", j + 1)));
		}
		// When the step ran: no earlier than the start of the free window of
		// the coin it gave up, as the operator promised.
		let as_of = match finality.height() {
			Some(h) => self.chain.median_time_at(h)?.unwrap_or(now.to_consensus_u32()),
			None => now.to_consensus_u32(),
		};
		let before_expiry = if j == 0 { body["expiry"].as_u64().unwrap_or(0) as u32 } else { body["steps"][j - 1]["expiry"].as_u64().unwrap_or(0) as u32 };
		let early = before_expiry > 0 && as_of < before_expiry.saturating_sub(STEP_FROM);
		let t = MedianTime::from_consensus(as_of.min(now.to_consensus_u32())).map_err(|e| Error::Parse(e.to_string()))?;
		let auths: Vec<(elements::secp256k1_zkp::schnorr::Signature, MedianTime)> =
			valid.branch.nodes.iter().map(|n| (sign(&key, &n.unroll_authorisation(t).digest), t)).collect();
		// The operator holds the full record of the leaf the wallet keeps: the
		// last step done. A leaf a later step gave up again is the operator's
		// to answer with that step's refund, whose record it built itself.
		let kept_on = s_next_done(body, j);
		if !kept_on {
			self.server.post("plan_leaf", &json!({"leaf_id": valid.leaf_id.to_string(), "auths": auths.iter().map(|(sg, t)|
				json!({"signature": hex(sg.as_ref()), "time": t.to_consensus_u32()})).collect::<Vec<_>>()}))?;
		}
		let coin = CoinRecord::Leaf { record: record.clone(), preimage, auths };
		let a = self.assess(&coin, &policy, Some((&record.owner, &nonce)))?;
		let state = if a.all_final() { "live" } else { "pending" };
		let note = format!("made by step {} of plan {}: refreshed in a round before it is paid out of round", j + 1, id);
		let row = self.row(&coin, &a, state, &note)?;
		let leaf = row.leaf_id.clone();
		let gave_up = if j == 0 { body["coin"].as_str().unwrap_or("").to_string() }
			else { body["steps"][j - 1]["leaf_id"].as_str().unwrap_or("").to_string() };
		let mut kept = body.clone();
		kept["steps"][j]["leaf_id"] = json!(leaf);
		kept["steps"][j]["expiry"] = json!(first);
		kept["steps"][j]["round"] = json!(round_txid.to_string());
		self.store.atomically(|st| {
			if st.coin(&leaf)?.is_none() {
				st.put_coin_bound(&row, true)?;
				st.use_nonce(&nonce, &leaf)?;
			}
			if !gave_up.is_empty() && st.coin(&gave_up)?.is_some() {
				st.set_coin_spent(&gave_up, &format!("plan {} step {}", id, j + 1))?;
			}
			st.update_plan_body(id, &kept.to_string())
		})?;
		let mut v = json!({"step": j + 1, "leaf_id": leaf, "gave_up": gave_up, "round": round_txid.to_string(), "value": record.value.to_string(),
			"expiry": first});
		if early {
			v["note"] = json!(format!("the operator ran this step at median time {}, before the free window of the coin it gave up (from {}): \
				the plan covers the coin for less time than it promised", as_of, before_expiry.saturating_sub(STEP_FROM)));
		}
		Ok(v)
	}
}

/// Whether the step after step `j` (from 0) of the plan `body` is done, as
/// the status the wallet read last says: then step `j`'s leaf was given up
/// again.
fn s_next_done(body: &Value, j: usize) -> bool {
	body["status_steps_done"].as_array().is_some_and(|d| d.iter().any(|i| i.as_u64() == Some(j as u64 + 1)))
}

/// What the wallet says of every plan.
pub const PLAN_NOTE: &str = "a plan lets the operator refresh a coin while the wallet stays closed, until covered_until at the earliest; \
	the wallet must sync by sync_by. The operator applies it: one that applies no step, applies one early, or sweeps a coin whose holder \
	is away takes that coin, as it can take any coin whose holder stays away past its expiry. What the wallet hands over gives it nothing \
	more: every pre-signed refund pays the wallet the step's value. A coin a plan names is refreshed in a round before it is paid out of \
	round.";

#[cfg(test)]
mod test {
	use std::str::FromStr;

	use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey};
	use elements::BlockHash;
	use serde_json::json;

	use arca_covenant::{Chain, LeafId, RelativeTime, WalletPolicy};

	use super::super::wallet::Wallet;
	use super::{covered_until, last_expiry, quote_digest, sync_by, STEP_FROM};

	const DAY: u32 = 86_400;

	#[test]
	fn a_plan_covers_each_expiry_by_the_horizon_less_the_free_window() {
		assert_eq!(STEP_FROM, 5 * DAY, "a step runs from five days before its coin's expiry");
		let e = 1_800_000_000;
		let gain = WalletPolicy::DEFAULT_HORIZON - 5 * DAY;
		assert_eq!(last_expiry(e, 0), e);
		assert_eq!(last_expiry(e, 2), e + 2 * gain);
		assert_eq!(covered_until(e, 2), e + 2 * gain - WalletPolicy::EXIT_DEADLINE);
		assert_eq!(sync_by(e, 2), e + 2 * gain - 5 * DAY);
		for n in 1..=6 {
			assert!(sync_by(e, n) < covered_until(e, n), "the wallet syncs before the plan's cover ends");
			assert!(sync_by(e, n) > e, "a plan carries the wallet past its coin's expiry");
		}
		assert_eq!(last_expiry(u32::MAX - 1, 6), u32::MAX, "saturates");
	}

	#[test]
	fn a_quote_request_binds_its_coin_nonces_and_delay() {
		let chain = Chain::new(BlockHash::from_str("3ce8ab6c8f9836c0cebca304f3cbed3e824e6c53f4cacd2822f6f8441eed1a3e").unwrap());
		let s = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[3; 32]).unwrap()).x_only_public_key().0;
		let d = RelativeTime::from_units(253).unwrap();
		let base = quote_digest(&chain, &s, &LeafId([1; 32]), &[[4; 32], [5; 32]], d);
		assert_ne!(base, quote_digest(&chain, &s, &LeafId([2; 32]), &[[4; 32], [5; 32]], d), "the coin");
		assert_ne!(base, quote_digest(&chain, &s, &LeafId([1; 32]), &[[5; 32], [4; 32]], d), "the nonces' order");
		assert_ne!(base, quote_digest(&chain, &s, &LeafId([1; 32]), &[[4; 32]], d), "the number of steps");
		assert_ne!(base, quote_digest(&chain, &s, &LeafId([1; 32]), &[[4; 32], [5; 32]], RelativeTime::from_units(254).unwrap()), "the delay");
		let other = Chain::new(BlockHash::from_str("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206").unwrap());
		assert_ne!(base, quote_digest(&other, &s, &LeafId([1; 32]), &[[4; 32], [5; 32]], d), "the chain");
	}

	#[test]
	fn a_plan_stands_on_its_last_step_taken_up_whose_round_is_not_lost() {
		let body = |steps: serde_json::Value| json!({"steps": steps});
		assert_eq!(Wallet::current_coin("c0", &body(json!([{}, {}]))), "c0", "no step taken up");
		assert_eq!(Wallet::current_coin("c0", &body(json!([{"leaf_id": "l1"}, {}]))), "l1");
		assert_eq!(Wallet::current_coin("c0", &body(json!([{"leaf_id": "l1"}, {"leaf_id": "l2"}]))), "l2");
		assert_eq!(Wallet::current_coin("c0", &body(json!([{"leaf_id": "l1", "lost": true}, {"leaf_id": "l2"}]))), "c0",
			"a step whose round is lost did not happen, nor did any after it");
		assert_eq!(Wallet::current_coin("c0", &body(json!([{"leaf_id": "l1"}, {"leaf_id": "l2", "lost": true}]))), "l1");
		assert_eq!(Wallet::current_coin("c0", &body(json!([{"leaf_id": "l1", "lost": false}]))), "l1", "a round that came back");
	}
}
