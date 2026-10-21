//! Claim trees, from both sides: a payer's distribution, one round paying
//! many holders, each under a key the payer names; and a holder's claims,
//! found under the wallet's own address keys and taken up.
//!
//! **The payer.** [`Wallet::distribute`] gives up the wallet's coins of one
//! asset for one `vtxo-1` leaf per holder, each owned by the claim key of the
//! key the payer names and a nonce the wallet draws
//! ([`arca_covenant::claim_key`]). The coins must hold exactly the claims and
//! the operator's fee, so when no coin holds that much, the wallet first pays
//! itself, out of round, a coin of exactly that value and its change. The
//! distribution then runs as a refresh does: `sync` validates every claim
//! leaf against the round and the published tree once the round is final,
//! hands over the forfeit of each coin given up, with no authorisation for any
//! claim leaf (it holds no claim key), and the operator releases the
//! distribution. What no holder takes up by the deadline (the claim leaves'
//! exit deadline, three days before their batch's first expiry) is paid back
//! by the operator to the distribution's return script, by default an
//! on-chain address of the wallet's, once the sweep that took it is final.
//! That payment is the operator's, not a script's; [`Wallet::distributions`]
//! shows it and every claim's state.
//!
//! **The holder.** A wallet named by one of its on-chain receive keys, or by
//! its OpenAMP account key ([`super::keys::Keys::openamp`], the key a
//! SeqPal ID is), finds its claims by asking the operator
//! ([`Wallet::claims`]), proving each key it asks under: the OpenAMP key, and
//! the receive keys from the first index to [`super::wallet`]'s gap past the
//! last it handed out. [`Wallet::claim`] takes each open claim up: it checks the
//! leaf as a leaf of its own refresh is checked (rebuilt from the published
//! tree, validated against its round, final, under the claim key of its own
//! key and the claim's nonce, with the five checks and the wallet's bounds,
//! the preimage opening its entry), signs the leaf's unroll authorisations
//! with the claim key and hands them to the operator, keeps the leaf as a coin
//! of its own, and pays it out of round to a fresh leaf under a key of its
//! own nonce. A claim the operator does not take up is still the wallet's
//! coin: its exit, its refresh and every date of it run as any coin's.
//!
//! The claim key signs for the claim leaf alone: the key named itself (an
//! address key or the OpenAMP key) signs nothing of the tree, only the proofs
//! of the lookup, each a BIP340 signature over the tagged `Arca/auth` digest
//! of the call, the chain and the operator's challenge, which is no enclave
//! sighash, no OpenAMP statement and no freeze message.

use std::collections::BTreeSet;
use std::str::FromStr;

use elements::hashes::{sha256, Hash};
use elements::secp256k1_zkp::{Keypair, XOnlyPublicKey};
use elements::{AssetId, Script, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::{claim_key, claim_keypair, Claim, CoinRecord, Distribution, ExplicitOutput, LeafId, MedianTime};

use super::chain::{hex, unhex, unhex32};
use super::client::auth_digest;
use super::keys::RECEIVE;
use super::pay::Out;
use super::round::{fee_within, refresh_fee, rebuild, schedule_of};
use super::store::CoinRow;
use super::wallet::{amount, sign, Wallet};
use super::{random32, Error, DEFAULT_MAX_FEE_PPM};

/// The most claims one distribution names: the operator's bound, a batch.
pub const MAX_CLAIMS: usize = 1024;

/// The most keys one lookup names: the operator's bound.
pub const MAX_LOOKUP_KEYS: usize = 64;

/// How many on-chain receive keys past the last the wallet handed out a
/// lookup names: the same gap the wallet's on-chain scan keeps.
pub const CLAIM_GAP: u32 = 20;

/// Which of the wallet's keys a claim was named under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Named {
	/// The on-chain key at `chain/index`.
	Onchain(u32, u32),
	/// The OpenAMP account key, `m/5/0`.
	OpenAmp,
}

impl std::fmt::Display for Named {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			Named::Onchain(c, i) => write!(f, "on-chain key {}/{}", c, i),
			Named::OpenAmp => write!(f, "the OpenAMP account key"),
		}
	}
}

/// The purpose a claim leaf's nonce is recorded under: the key that was
/// named, `claim <chain>/<index>` for an on-chain key, `claim openamp` for
/// the OpenAMP account key.
fn claim_purpose(named: Named) -> String {
	match named {
		Named::Onchain(c, i) => format!("claim {}/{}", c, i),
		Named::OpenAmp => "claim openamp".to_string(),
	}
}

/// The key a claim nonce's purpose names.
fn parse_claim_purpose(p: &str) -> Option<Named> {
	let rest = p.strip_prefix("claim ")?;
	if rest == "openamp" {
		return Some(Named::OpenAmp);
	}
	let (c, i) = rest.split_once('/')?;
	Some(Named::Onchain(c.parse().ok()?, i.parse().ok()?))
}

/// A claim found under one of the wallet's keys, with that key.
struct Found {
	named: Named,
	claim: Value,
}

impl Wallet {
	/// The key that signs for the coin the wallet holds under `nonce`: the
	/// leaf key the mnemonic derives from the nonce, or, for a claim leaf, the
	/// claim key of the on-chain key that was named and the claim's nonce,
	/// checked against the key the wallet recorded.
	pub(crate) fn coin_key(&self, nonce: &[u8; 32]) -> Result<Keypair, Error> {
		if let Some(row) = self.store.nonce(nonce)? {
			if let Some(named) = parse_claim_purpose(&row.purpose) {
				let k = claim_keypair(&self.named_keypair(named)?, nonce).map_err(|e| Error::Keys(e.to_string()))?;
				if k.x_only_public_key().0.serialize() != row.owner_key {
					return Err(Error::Keys(format!("the claim key of {} and nonce {} is not the key the wallet recorded",
						named, hex(nonce))));
				}
				return Ok(k);
			}
		}
		self.keys.leaf(nonce)
	}

	/// The wallet's own key that `named` is.
	fn named_keypair(&self, named: Named) -> Result<Keypair, Error> {
		match named {
			Named::Onchain(c, i) => self.keys.onchain(c, i),
			Named::OpenAmp => self.keys.openamp(),
		}
	}

	/// The wallet's OpenAMP account key (`m/5/0`): the key a SeqPal ID is,
	/// and one a payer can name for this wallet.
	pub fn openamp_key(&self) -> Result<XOnlyPublicKey, Error> {
		Ok(self.keys.openamp()?.x_only_public_key().0)
	}

	/// The key a payer names for `s` ([`named_key`]), an address read by the
	/// wallet's node.
	pub fn named(&self, s: &str) -> Result<XOnlyPublicKey, Error> {
		named_key(s, &self.chain)
	}

	/// The script the wallet's node reads `address` as.
	pub fn script_of(&self, address: &str) -> Result<Script, Error> {
		self.chain.script_of(address)
	}

	// -----------------------------------------------------------------------
	// The payer
	// -----------------------------------------------------------------------

	/// What a distribution of `claims` (each a key named and what its leaf
	/// holds) in `asset` costs now, and the coins it gives up, signing and
	/// asking nothing of the operator but its `info`: what
	/// [`Wallet::distribute`] takes as `shown`.
	pub fn distribute_quote(&mut self, asset: AssetId, claims: &[(XOnlyPublicKey, u64)]) -> Result<Value, Error> {
		let info = self.server_info()?;
		let plan = self.distribution_plan(&info, asset, claims)?;
		Ok(json!({
			"asset": asset.to_string(), "claims": claims.len(), "total": plan.total.to_string(), "fee": plan.fee.to_string(),
			"coins": plan.coins.iter().map(|c| json!({"leaf_id": c.leaf_id, "value": c.value.to_string(), "expiry": c.expiry}))
				.collect::<Vec<_>>(),
			"split": plan.split,
			"note": "the fee is the operator's refresh fee of each coin given up, its fixed part for each claim leaf, and its offboard's \
				fixed part once, for the payment of what no holder takes up back to the return script; with `split`, the wallet first pays \
				itself a coin of exactly the claims and the fee, out of round",
		}))
	}

	/// Pays `claims` (each a key named and what its leaf holds) in `asset`
	/// in one round: see the [module documentation](self). What no holder
	/// takes up goes back to `return_to`, by default a new on-chain address
	/// of the wallet's. With `shown`, the distribution goes ahead only on
	/// that very fee, as [`Wallet::distribute_quote`] answered it.
	pub fn distribute(&mut self, asset: AssetId, claims: &[(XOnlyPublicKey, u64)], return_to: Option<Script>, shown: Option<u64>)
		-> Result<Value, Error>
	{
		self.witnessed_now()?;
		let info = self.server_info()?;
		let mut plan = self.distribution_plan(&info, asset, claims)?;
		if let Some(s) = shown {
			if s != plan.fee {
				return Err(Error::Refused(format!("the distribution's fee changed since it was shown; it is now {} of asset {}", plan.fee,
					asset)));
			}
		}
		let return_script = match return_to {
			Some(s) => s,
			None => self.new_script(RECEIVE)?,
		};
		if plan.split {
			plan.coins = vec![self.split_for(&info, asset, plan.total + plan.fee as u128)?];
		}
		let need = plan.total + plan.fee as u128;
		let held: u128 = plan.coins.iter().map(|c| c.value as u128).sum();
		if held != need {
			return Err(Error::Refused(format!("the coins given up hold {} of asset {}, and the claims and the fee take {}", held, asset, need)));
		}
		let claims: Vec<Claim> = claims.iter().map(|(k, v)| Claim { named: *k, nonce: random32(), value: *v }).collect();
		let fees: Vec<(AssetId, u64)> = if plan.fee > 0 { vec![(asset, plan.fee)] } else { vec![] };
		let d = Distribution {
			inputs: plan.coins.iter().map(|c| LeafId::from_str(&c.leaf_id).map_err(|e| Error::Store(e.to_string()))).collect::<Result<_, _>>()?,
			asset, exit_delay: self.exit_delay(), claims: claims.clone(), return_script: return_script.clone(), fees: fees.clone(),
			not_before: None,
		};
		d.check().map_err(|e| Error::Refused(e.to_string()))?;
		let id = d.id(&self.genesis, &self.operator);
		let mut inputs = vec![];
		for c in &plan.coins {
			let key = self.coin_key(&c.owner_nonce)?;
			inputs.push(json!({"leaf_id": c.leaf_id, "attestation": hex(sign(&key, &id).as_ref())}));
		}
		let body = json!({
			"inputs": inputs,
			"asset": asset.to_string(),
			"exit_delay_units": d.exit_delay.units(),
			"claims": claims.iter().map(|c| json!({"key": hex(&c.named.serialize()), "nonce": hex(&c.nonce), "value": c.value.to_string()}))
				.collect::<Vec<_>>(),
			"return_script": hex(return_script.as_bytes()),
			"fees": fees.iter().map(|(a, v)| json!({"asset": a.to_string(), "amount": v.to_string()})).collect::<Vec<_>>(),
		});
		// Each claim as the wallet's participation record keeps a leaf it
		// wants: its asset, value and nonce, and the key it was named under.
		let wanted: Vec<Value> = claims.iter().map(|c| json!({"asset": asset.to_string(), "value": c.value.to_string(),
			"nonce": hex(&c.nonce), "claim": hex(&c.named.serialize())})).collect();
		let pid = hex(&id);
		let given: Vec<String> = plan.coins.iter().map(|c| c.leaf_id.clone()).collect();
		self.store.atomically(|s| {
			s.put_participation(&pid, &body.to_string(), &serde_json::to_string(&given).expect("strings"), &Value::Array(wanted.clone()).to_string())?;
			for l in &given {
				s.set_coin_state(l, "given", &format!("distribution {}", pid))?;
			}
			Ok(())
		})?;
		let answer = match self.submit_participation_body(&pid, &body, &given) {
			Ok(a) => a,
			Err(Error::Unreachable(why)) => return Err(Error::Unreachable(format!("distribution {}: {}", pid, why))),
			Err(e) => return Err(e),
		};
		Ok(json!({
			"distribution": pid, "state": answer["state"], "asset": asset.to_string(), "total": plan.total.to_string(),
			"fee": plan.fee.to_string(), "gives": given, "return_script": hex(return_script.as_bytes()),
			"claims": claims.iter().map(|c| json!({"key": hex(&c.named.serialize()), "value": c.value.to_string(),
				"claim_key": c.owner().map(|k| hex(&k.serialize())).unwrap_or_default()})).collect::<Vec<_>>(),
			"note": self.spelling.say("{sync} hands over the forfeits once the round is final; the claims open then"),
		}))
	}

	/// Every distribution the wallet made, as the operator shows it now: its
	/// state, its deadline, each claim's state (`pending`, `open`,
	/// `claimed`, `returned`) and each payment of unclaimed leaves back to
	/// its return script. One the operator does not answer for is shown
	/// with the error.
	pub fn distributions(&self) -> Result<Value, Error> {
		let mut out = vec![];
		for (pid, body, _, _, state, _, round) in self.store.participations()? {
			let body: Value = serde_json::from_str(&body).map_err(|e| Error::Store(e.to_string()))?;
			if body.get("claims").is_none() {
				continue;
			}
			match self.server.post("distribution_status", &json!({"distribution_id": pid})) {
				Ok(mut st) => {
					st["wallet_state"] = json!(state);
					out.push(st);
				},
				Err(e) => out.push(json!({"distribution_id": pid, "wallet_state": state, "round": round, "error": e.to_string()})),
			}
		}
		Ok(Value::Array(out))
	}

	/// The coins a distribution of `claims` in `asset` gives up, and its fee.
	fn distribution_plan(&self, info: &Value, asset: AssetId, claims: &[(XOnlyPublicKey, u64)]) -> Result<Plan, Error> {
		if claims.is_empty() || claims.len() > MAX_CLAIMS {
			return Err(Error::Refused(format!("{} claims; a distribution names 1 to {}", claims.len(), MAX_CLAIMS)));
		}
		let min = Self::min_leaf(info, asset)?;
		let mut seen = BTreeSet::new();
		for (k, v) in claims {
			if !seen.insert(k.serialize()) {
				return Err(Error::Refused(format!("key {} is named twice: a distribution pays each key once; add its amounts up", k)));
			}
			if *v < min {
				return Err(Error::Refused(format!("a claim of {} for key {} is below the operator's smallest leaf in asset {}, {}", v, k,
					asset, min)));
			}
			if *k == self.operator {
				return Err(Error::Refused("a key named is the operator's own: a leaf has its holder's key, never the operator's".into()));
			}
		}
		let total: u128 = claims.iter().map(|(_, v)| *v as u128).sum();
		let schedule = schedule_of(info, asset);
		let base = schedule["refresh_base"].as_str().and_then(|b| b.parse::<u64>().ok()).unwrap_or(0) as u128;
		let off = schedule["offboard_base"].as_str().and_then(|b| b.parse::<u64>().ok()).unwrap_or(0) as u128;
		let fixed = base * claims.len() as u128 + off;
		let now = self.now()?.to_consensus_u32();
		let coins = self.spendable_coins(asset)?;
		if coins.is_empty() {
			return Err(Error::Refused(format!("the wallet holds no live coin of asset {} to distribute from", asset)));
		}
		let fee_of = |value: u128, expiry: u32| -> Result<u64, Error> {
			let f = fixed + refresh_fee(&schedule, value.min(u64::MAX as u128) as u64, expiry, now) as u128;
			u64::try_from(f).map_err(|_| Error::Refused("the fee is above 2^64 atoms".into()))
		};
		let bound = |fee: u64| -> Result<(), Error> {
			if !fee_within(fee, total.min(u64::MAX as u128) as u64, DEFAULT_MAX_FEE_PPM) {
				return Err(Error::Refused(format!("the operator's fee for this distribution is {} of asset {}, above the wallet's bound of \
					{} ppm of the {} it pays", fee, asset, DEFAULT_MAX_FEE_PPM, total)));
			}
			Ok(())
		};
		// One coin that holds exactly the claims and its own fee.
		for c in &coins {
			let fee = fee_of(c.coin.value as u128, c.row.expiry)?;
			if c.coin.value as u128 == total + fee as u128 {
				bound(fee)?;
				return Ok(Plan { coins: vec![c.row.clone()], total, fee, split: false });
			}
		}
		// Otherwise a coin of exactly that, paid to the wallet itself first:
		// it rests on the batches of the coins it comes from, the earliest of
		// whose expiries prices its refresh fee.
		let mut fee = fee_of(total, coins[0].row.expiry)?;
		for _ in 0..4 {
			let need = total + fee as u128;
			let mut held = 0u128;
			let mut expiry = u32::MAX;
			for c in &coins {
				held += c.coin.value as u128;
				expiry = expiry.min(c.row.expiry);
				if held >= need {
					break;
				}
			}
			let again = fee_of(need, expiry)?;
			if again == fee {
				break;
			}
			fee = again;
		}
		bound(fee)?;
		// Refused here, before a quote promises it or anything is signed: the
		// coin the wallet would pay itself comes out of its live coins.
		let held: u128 = coins.iter().map(|c| c.coin.value as u128).sum();
		if held < total + fee as u128 {
			return Err(Error::Refused(format!("the wallet's live coins of asset {} hold {}, and the claims and the fee take {}",
				asset, held, total + fee as u128)));
		}
		Ok(Plan { coins: vec![], total, fee, split: true })
	}

	/// Pays the wallet itself, out of round, a coin of exactly `need` of
	/// `asset` (and its change), and returns it.
	fn split_for(&mut self, info: &Value, asset: AssetId, need: u128) -> Result<CoinRow, Error> {
		let need = u64::try_from(need).map_err(|_| Error::Refused("a distribution above 2^64 atoms".into()))?;
		let min = Self::min_leaf(info, asset)?;
		let leaf = self.own_leaf_for("distribution")?;
		let mailbox = self.keys.mailbox()?.x_only_public_key().0;
		let probe = ExplicitOutput::new(asset, need, leaf.policy(self.operator, self.genesis).script_pubkey());
		let (inputs, _margin, change) = self.choose_coins(info, asset, need, &probe, min)?;
		let mut outs = vec![Out { asset, value: need, leaf: leaf.clone(), mailbox, until: None }];
		if change > 0 {
			outs.push(Out { asset, value: change, leaf: self.own_leaf_for("change")?, mailbox, until: None });
		}
		self.transfer_back(&inputs, &outs)?;
		let id = self.store.nonce(&leaf.owner_nonce)?.and_then(|n| n.leaf_id)
			.ok_or_else(|| Error::Unreachable("the coin the wallet paid itself for the distribution is not held yet; ask again".into()))?;
		let row = self.store.coin(&id)?.ok_or_else(|| Error::Store(format!("coin {} is gone", id)))?;
		if row.state != "live" || row.value != need {
			return Err(Error::Refused(format!("the coin the wallet paid itself for the distribution is {} and holds {}, not live and {}",
				row.state, row.value, need)));
		}
		Ok(row)
	}

	// -----------------------------------------------------------------------
	// The holder
	// -----------------------------------------------------------------------

	/// The keys a lookup names: the OpenAMP account key, then the on-chain
	/// receive keys, `scan` of them from the first, or every index handed out
	/// and [`CLAIM_GAP`] more.
	fn claim_keys(&self, scan: Option<u32>) -> Result<Vec<(Named, Keypair)>, Error> {
		let n = match scan {
			Some(n) => n,
			None => self.store.indices(RECEIVE)? + CLAIM_GAP,
		};
		let mut keys = vec![(Named::OpenAmp, self.keys.openamp()?)];
		for i in 0..n {
			keys.push((Named::Onchain(RECEIVE, i), self.keys.onchain(RECEIVE, i)?));
		}
		Ok(keys)
	}

	/// The claims the operator holds under `keys`, each with its key, proven
	/// under one challenge for each [`MAX_LOOKUP_KEYS`] keys.
	fn lookup(&self, keys: &[(Named, Keypair)]) -> Result<Vec<Found>, Error> {
		let mut out = vec![];
		for chunk in keys.chunks(MAX_LOOKUP_KEYS) {
			let v = self.server.post("challenge", &json!({}))?;
			let challenge = unhex32(v["challenge"].as_str().unwrap_or(""))?;
			let proofs: Vec<Value> = chunk.iter().map(|(_, k)| {
				let x = k.x_only_public_key().0;
				json!({"key": hex(&x.serialize()), "signature": hex(sign(k, &auth_digest(&self.genesis, "claims", &challenge, &x, &[])).as_ref())})
			}).collect();
			let answer = self.server.post("claims", &json!({"challenge": hex(&challenge), "keys": proofs}))?;
			for c in answer["claims"].as_array().cloned().unwrap_or_default() {
				let Some((named, _)) = chunk.iter().find(|(_, k)| c["key"].as_str() == Some(&hex(&k.x_only_public_key().0.serialize())))
				else { continue };
				out.push(Found { named: *named, claim: c });
			}
		}
		Ok(out)
	}

	/// The claims under the wallet's OpenAMP key and its on-chain receive
	/// keys, as the operator shows them: each claim's distribution, the key it
	/// was named under and its address (`null` for the OpenAMP key, with
	/// `named_as` saying which key it is), its value and state (`pending` until its distribution is
	/// released, `open`, `claimed`, `returned`), its deadline, and whether
	/// the wallet holds it. Asks the operator, proving each key; signs
	/// nothing else.
	pub fn claims(&self, scan: Option<u32>) -> Result<Value, Error> {
		let keys = self.claim_keys(scan)?;
		let found = self.lookup(&keys)?;
		let mut out = vec![];
		for f in found {
			let c = &f.claim;
			let nonce = unhex32(c["nonce"].as_str().unwrap_or(""))?;
			let held = self.store.nonce(&nonce)?.and_then(|n| n.leaf_id);
			let (address, named_as) = match f.named {
				Named::Onchain(chain, index) => (json!(self.chain.address(&self.keys.onchain_script(chain, index)?)?), json!("address")),
				Named::OpenAmp => (Value::Null, json!("openamp")),
			};
			out.push(json!({
				"distribution": c["distribution_id"], "index": c["index"], "key": c["key"], "address": address, "named_as": named_as,
				"asset": c["asset"], "value": c["value"], "state": c["state"], "leaf_id": c["leaf_id"], "deadline": c["deadline"],
				"expiry": c["expiry"], "held": held,
			}));
		}
		Ok(Value::Array(out))
	}

	/// Takes up every open claim under the wallet's OpenAMP key and its
	/// on-chain receive keys, or
	/// those of `which` (leaf ids, or `distribution:index`): see the [module
	/// documentation](self). Each is kept as a coin of the wallet's once
	/// checked, and paid out of round to a fresh leaf of its own; a claim the
	/// operator does not take up stays a coin of the wallet's, refreshed or
	/// taken home as any. One that fails says why and stops no other.
	pub fn claim(&mut self, which: &[String], scan: Option<u32>) -> Result<Value, Error> {
		self.witnessed_now()?;
		let keys = self.claim_keys(scan)?;
		let found = self.lookup(&keys)?;
		let mut out = vec![];
		for f in found {
			let c = &f.claim;
			let name = format!("{}:{}", c["distribution_id"].as_str().unwrap_or(""), c["index"]);
			let leaf = c["leaf_id"].as_str().unwrap_or("").to_string();
			if !which.is_empty() && !which.iter().any(|w| *w == name || *w == leaf) {
				continue;
			}
			if c["state"] != "open" {
				out.push(json!({"claim": name, "state": c["state"], "note": "not open: a claim is taken up once its distribution is \
					released, and until its holder has claimed it or it went back to its payer"}));
				continue;
			}
			let nonce = match unhex32(c["nonce"].as_str().unwrap_or("")) {
				Ok(n) => n,
				Err(e) => {
					out.push(json!({"claim": name, "refused": e.to_string()}));
					continue;
				},
			};
			// Held already: kept by an earlier run, and taken up unless that
			// failed; a held coin still live is paid on now.
			let row = match self.store.nonce(&nonce)?.and_then(|n| n.leaf_id) {
				Some(id) => self.store.coin(&id)?,
				None => match self.adopt_claim(f.named, c) {
					Ok(r) => Some(r),
					Err(e) => {
						self.store.refused(&format!("claim {}", name), &e.to_string())?;
						out.push(json!({"claim": name, "refused": e.to_string()}));
						continue;
					},
				},
			};
			let Some(row) = row else {
				out.push(json!({"claim": name, "error": "the coin the wallet kept for it is gone"}));
				continue;
			};
			if row.state != "live" {
				out.push(json!({"claim": name, "leaf_id": row.leaf_id, "state": row.state, "note": "held; not live, so not paid on now"}));
				continue;
			}
			match self.respend_to_self(vec![row.clone()]) {
				Ok(t) => out.push(json!({"claim": name, "leaf_id": row.leaf_id, "value": row.value.to_string(), "taken_up": t})),
				Err(e) => out.push(json!({"claim": name, "leaf_id": row.leaf_id, "held": true, "error": e.to_string(),
					"note": "the claim is the wallet's coin: it is paid on at a later run, refreshed or taken home as any coin"})),
			}
		}
		Ok(Value::Array(out))
	}

	/// Checks the claim `c`, found under the wallet's key `named`, hands its
	/// unroll authorisations to the operator, and keeps it.
	fn adopt_claim(&mut self, from: Named, c: &Value) -> Result<CoinRow, Error> {
		let named_pair = self.named_keypair(from)?;
		let named = named_pair.x_only_public_key().0;
		if c["key"].as_str() != Some(&hex(&named.serialize())) {
			return Err(Error::Refused("the operator answers for another key than the one asked under".into()));
		}
		let nonce = unhex32(c["nonce"].as_str().unwrap_or(""))?;
		let owner = claim_key(&named, &nonce).map_err(|e| Error::Refused(e.to_string()))?;
		if c["owner"].as_str() != Some(&hex(&owner.serialize())) {
			return Err(Error::Refused(format!("the operator names claim key {} for this claim, and the key named and its nonce make {}",
				c["owner"], owner)));
		}
		if self.store.nonce(&nonce)?.is_some() {
			return Err(Error::Refused(format!("the wallet holds a key under nonce {} already: a claim's nonce is one the wallet never held",
				hex(&nonce))));
		}
		// The round, final, and the leaf rebuilt from its published tree.
		let round_txid = Txid::from_str(c["round"].as_str().unwrap_or("")).map_err(|e| Error::Parse(format!("the claim's round: {}", e)))?;
		let finality = self.chain.finality(&round_txid)?;
		if !finality.is_final() {
			return Err(Error::Missing(format!("the claim's round {} is {}: a claim is taken once its round is final", round_txid,
				finality.word())));
		}
		let round: Transaction = self.chain.transaction(&round_txid)?
			.ok_or_else(|| Error::Node(format!("the node does not have round {}", round_txid)))?;
		let tree = self.server.post("tree", &json!({"txid": round_txid.to_string(), "vout": c["batch_vout"]}))?;
		if tree["round_txid"].as_str() != Some(&round_txid.to_string()) {
			return Err(Error::Refused("the server published the tree of another round".into()));
		}
		self.witness_record(&tree["signer_record"], false)?;
		let tree = rebuild(&tree)?;
		let at = c["leaf_index"].as_u64().ok_or_else(|| Error::Parse("the claim names no place in its tree".into()))? as usize;
		if at >= tree.records().len() {
			return Err(Error::Refused("the operator names a leaf the published tree does not have".into()));
		}
		let record = tree.record(at);
		if c["record"].as_str() != Some(&hex(&record.to_bytes().map_err(|e| Error::Refused(e.to_string()))?)) {
			return Err(Error::Refused("the record the operator serves for the claim is not the published tree's".into()));
		}
		// Checked as a leaf of the wallet's own refresh: its acceptance horizon
		// counted from the round's block.
		let now = self.now()?;
		let as_of = match finality.height() {
			Some(h) => self.chain.median_time_at(h)?.and_then(|t| MedianTime::from_consensus(t).ok()).map_or(now, |t| t.min(now)),
			None => now,
		};
		let (policy, _) = self.leaf_policy(record.asset, as_of)?;
		let valid = record.validate(&round, &policy, &owner, &nonce)
			.map_err(|e| Error::Refused(format!("the claim leaf in round {} fails the wallet's checks: {}", round_txid, e)))?;
		if Some(valid.leaf_id.to_string().as_str()) != c["leaf_id"].as_str() {
			return Err(Error::Refused("the operator names the claim leaf by another id than its record gives".into()));
		}
		if record.value.to_string() != c["value"].as_str().unwrap_or("") || record.asset.to_string() != c["asset"].as_str().unwrap_or("") {
			return Err(Error::Refused(format!("the claim leaf holds {} of {}; the operator says {} of {}", record.value, record.asset,
				c["value"], c["asset"])));
		}
		let preimage = unhex32(c["preimage"].as_str().unwrap_or(""))
			.map_err(|_| Error::Refused("the operator serves no preimage for the claim: its distribution is not released".into()))?;
		if sha256::Hash::hash(&preimage).to_byte_array() != record.unlock_hash {
			return Err(Error::Refused("the preimage the operator serves does not open the claim leaf's entry".into()));
		}
		// The claim key, and its unroll authorisations, usable at once.
		let key = claim_keypair(&named_pair, &nonce).map_err(|e| Error::Keys(e.to_string()))?;
		if key.x_only_public_key().0 != owner {
			return Err(Error::Keys("the wallet's claim key is not the leaf's".into()));
		}
		let t = MedianTime::from_consensus(now.to_consensus_u32().saturating_sub(3600)).map_err(|e| Error::Node(e.to_string()))?;
		let auths: Vec<_> = valid.branch.nodes.iter().map(|n| (sign(&key, &n.unroll_authorisation(t).digest), t)).collect();
		let answer = self.server.post("claim_leaf", &json!({"leaf_id": valid.leaf_id.to_string(),
			"auths": auths.iter().map(|(s, t)| json!({"signature": hex(s.as_ref()), "time": t.to_consensus_u32()})).collect::<Vec<_>>()}))?;
		let coin = CoinRecord::Leaf { record: record.clone(), preimage, auths };
		let first = record.schedule.expiries()[0].to_consensus_u32();
		let a = self.assess(&coin, &self.followed_policy(first, now), Some((&owner, &nonce)))?;
		let state = if a.all_final() { "live" } else { "pending" };
		let note = format!("claim {} of distribution {}, named under {}", c["index"], c["distribution_id"].as_str().unwrap_or(""), from);
		let row = self.row(&coin, &a, state, &note)?;
		let purpose = claim_purpose(from);
		self.store.atomically(|s| {
			s.put_nonce(&nonce, &owner.serialize(), &purpose)?;
			s.put_coin_bound(&row, false)?;
			s.use_nonce(&nonce, &row.leaf_id)
		})?;
		let _ = answer;
		Ok(row)
	}
}

/// What a distribution gives up and pays.
struct Plan {
	coins: Vec<CoinRow>,
	total: u128,
	fee: u64,
	/// Whether the wallet pays itself a coin of exactly the claims and the
	/// fee first.
	split: bool,
}

/// The x-only key a payer names for `s`: 64 hex digits (an x-only key), 66
/// (a compressed public key, whose x is taken), or a taproot address's
/// program.
pub fn named_key(s: &str, chain: &super::chain::ChainSource) -> Result<XOnlyPublicKey, Error> {
	let s = s.trim();
	if s.len() == 64 {
		return XOnlyPublicKey::from_str(s).map_err(|e| Error::Parse(format!("key {}: {}", s, e)));
	}
	if s.len() == 66 {
		let pk = elements::secp256k1_zkp::PublicKey::from_slice(&unhex(s)?).map_err(|e| Error::Parse(format!("key {}: {}", s, e)))?;
		return Ok(pk.x_only_public_key().0);
	}
	let script = chain.script_of(s)?;
	arca_covenant::claim::named_of_script(&script).ok_or_else(|| Error::Parse(format!("{} names no key: a taproot address names its \
		program, and any other address only its key's hash, so name the key itself (64 or 66 hex digits)", s)))
}

/// The amount `v`, from a list's text.
pub fn claim_amount(v: &str) -> Result<u64, Error> {
	amount(&json!(v.trim()), "an amount")
}

/// The asset of `s`.
pub fn claim_asset(s: &str) -> Result<AssetId, Error> {
	AssetId::from_str(s.trim()).map_err(|e| Error::Parse(format!("asset {}: {}", s, e)))
}
