//! Paying an address on the chain from the wallet's leaves: a cooperative
//! offboard.
//!
//! A participation gives up leaves of one asset and wants one offboard output
//! of exactly the amount, paying the address's script, and a change leaf
//! where the coins hold more. The operator's round pays the offboard output,
//! hash-locked to the participation's unlock hash; `sync` hands over the
//! forfeits once the round is final, and the operator then unlocks the output
//! with the preimage into the address: its output 0 pays exactly the amount
//! there. Should the operator not unlock it within [`UNLOCK_GRACE_SECONDS`] of
//! the wallet holding the preimage, the wallet unlocks it itself, the margin
//! the output holds paying the fee where the node accepts the asset for fees.
//! A participation the operator drops, voids or lets expire gives the coins
//! back, and nothing is paid.
//!
//! The fee is in the asset moved, as a participation carries one asset: each
//! coin's refresh fee, the offboard's fee by the asset's schedule, and the
//! margin the offboard output holds for its unlock. Where an offboard stands
//! is read from the chain each time it is asked for ([`Wallet::offboards`]).

use std::str::FromStr;

use elements::hashes::{sha256, Hash};
use elements::{AssetId, OutPoint, Script, Txid};
use serde_json::{json, Value};

use arca_covenant::spend::FeeSource;
use arca_covenant::{ExplicitOutput, LeafId, OffboardPolicy, RelativeTime, Template};

use super::chain::{hex, unhex, unhex32};
use super::client::{key_proof_digest, participation_id, Wanted};
use super::order::UNLOCK_GRACE_SECONDS;
use super::pay::{In, Margins};
use super::round::{fee_within, refresh_fee, schedule_of, DEFAULT_MAX_FEE_PPM};
use super::take::offboard_fee;
use super::wallet::{sign, Wallet};
use super::{random32, Error};

/// The wallet's offboards, each `{offboard, asset, amount, script, at?,
/// unlock_after?}`, kept beside its participations.
const OFFBOARDS: &str = "offboards";

/// An offboard, planned: the coins given up, the fee, the margin it holds,
/// and the change.
struct Plan {
	coins: Vec<In>,
	fee: u64,
	margin: u64,
	change: u64,
}

fn parse_outpoint(s: &str) -> Result<OutPoint, Error> {
	let (t, v) = s.split_once(':').ok_or_else(|| Error::Store(format!("an outpoint {:?}", s)))?;
	Ok(OutPoint::new(Txid::from_str(t).map_err(|e| Error::Store(e.to_string()))?,
		v.parse().map_err(|_| Error::Store(format!("an outpoint {:?}", s)))?))
}

impl Wallet {
	/// The script an offboard pays: `address`, an unconfidential address of
	/// the chain the node follows, or `script`, hex. Refused: neither or both,
	/// a confidential address (the offboard pays an explicit output), and a
	/// script the wallet holds as an Arca script (the operator refuses it too).
	pub fn offboard_script(&self, address: Option<&str>, script: Option<&str>) -> Result<Script, Error> {
		let spk = match (address, script) {
			(Some(a), None) => {
				if self.chain.is_confidential(a)? {
					return Err(Error::Refused(format!("{} is a confidential address: an offboard pays an explicit output, so name the \
						address's unconfidential form", a)));
				}
				self.chain.script_of(a)?
			},
			(None, Some(s)) => Script::from(unhex(s)?),
			_ => return Err(Error::Parse("an offboard pays an address or a script: name one of them".into())),
		};
		if spk.is_empty() || spk.len() > 10_000 {
			return Err(Error::Refused(format!("a script of {} bytes: an offboard pays 1 to 10,000", spk.len())));
		}
		Ok(spk)
	}

	/// What paying `amount` of `asset` to `script` on the chain would cost,
	/// before anything is signed, written or asked of the operator but its
	/// published fees: the coins given up, the fee (each coin's refresh fee,
	/// the offboard's fee by the asset's schedule, and the margin the output
	/// holds for its unlock) and the change. Refuses what [`Self::offboard`]
	/// refuses for the same reason.
	pub fn offboard_quote(&mut self, asset: AssetId, amount: u64, script: &Script, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		let _quote = self.quoting();
		let info = self.server_info()?;
		let q = self.offboard_plan(&info, asset, amount, script, max_fee_ppm).map(|(q, _)| q);
		self.quoted(q)
	}

	fn offboard_plan(&self, info: &Value, asset: AssetId, amount: u64, script: &Script, max_fee_ppm: Option<u64>)
		-> Result<(Value, Plan), Error>
	{
		if amount == 0 {
			return Err(Error::Refused("an offboard of nothing".into()));
		}
		let min = Self::min_leaf(info, asset)?;
		let schedule = schedule_of(info, asset);
		let m = Margins::of(info, asset)?;
		let probe = OffboardPolicy { unlock_hash: [0; 32], destination: ExplicitOutput::new(asset, amount, script.clone()),
			operator: self.operator, reclaim_delay: RelativeTime::from_units(1).map_err(|e| Error::Refused(e.to_string()))? };
		let margin = probe.unlock_margin(m.floor, m.multiple);
		let offboard = offboard_fee(&schedule, amount).saturating_add(margin);
		let now = self.now()?.to_consensus_u32();
		// The coins, furthest from their exit date first and the largest
		// first among one date, until they hold the amount and the fee, with
		// no change or change of at least the operator's smallest leaf.
		// A coin given up in a refresh that waits is taken back first when
		// the live coins fall short.
		self.free_when_short(asset, amount.saturating_add(offboard))?;
		let mut chosen: Vec<In> = vec![];
		let (mut total, mut refresh) = (0u64, 0u64);
		let mut done = None;
		for c in self.coins_to_give(asset)? {
			if chosen.len() == super::round::MAX_GIVEN {
				return Err(Self::too_many_coins(asset, total, amount.saturating_add(refresh).saturating_add(offboard)));
			}
			let (record, held) = self.held(&c.row)?;
			let expiry = self.service_expiry(&record, &held)?;
			refresh = refresh.saturating_add(refresh_fee(&schedule, c.coin.value, expiry, now));
			total = total.saturating_add(c.coin.value);
			chosen.push(c);
			let fee = refresh.saturating_add(offboard);
			if let Some(change) = total.checked_sub(amount.saturating_add(fee)).filter(|c| *c == 0 || *c >= min) {
				done = Some((fee, change));
				break;
			}
		}
		let Some((fee, change)) = done else {
			let need = amount.saturating_add(refresh).saturating_add(offboard);
			return Err(self.short_of(asset, need.saturating_sub(total).max(1), format!("the wallet's live coins of asset {} hold {} and \
				an offboard of {} and its fee need {} (refresh {}, offboard {}), with any change at least the operator's smallest leaf \
				of {}: board or receive more, or pay less", asset, total, amount, need, refresh, offboard, min))?);
		};
		let bound = max_fee_ppm.unwrap_or(DEFAULT_MAX_FEE_PPM);
		if !fee_within(fee, amount, bound) {
			return Err(Error::Refused(format!("paying {} of asset {} on the chain costs {}, above the wallet's bound of {} ppm of the \
				amount (raise it with max_fee_ppm)", amount, asset, fee, bound)));
		}
		let q = json!({
			"asset": asset.to_string(), "amount": amount.to_string(), "script": hex(script.as_bytes()),
			"address": self.chain.address(script)?,
			"fee": {"asset": asset.to_string(), "amount": fee.to_string(), "refresh": refresh.to_string(),
				"offboard": offboard_fee(&schedule, amount).to_string(), "unlock_margin": margin.to_string()},
			"gives": chosen.iter().map(|c| c.row.leaf_id.clone()).collect::<Vec<_>>(),
			"change": change.to_string(),
		});
		Ok((q, Plan { coins: chosen, fee, margin, change }))
	}

	/// Pays `amount` of `asset` to `script` on the chain through the next
	/// round (see the [module documentation](self)). The fee is in `asset`; a
	/// `fee_asset` other than it is refused, a participation carrying one
	/// asset. With `shown`, it goes ahead only on the fee and the coins the
	/// program showed (an [`Self::offboard_quote`]'s `fee` and `gives`).
	/// Answers the offboard, named by its participation; `sync` completes it,
	/// and [`Self::offboards`] says where it stands.
	pub fn offboard(&mut self, asset: AssetId, amount: u64, script: &Script, fee_asset: Option<AssetId>, max_fee_ppm: Option<u64>,
		shown: Option<&Value>) -> Result<Value, Error>
	{
		if let Some(f) = fee_asset.filter(|f| *f != asset) {
			return Err(Error::Refused(format!("an offboard's fee is paid in the asset it moves, {}, as the round that pays it carries that \
				one asset: asset {} cannot pay it", asset, f)));
		}
		self.witnessed_now()?;
		let info = self.server_info()?;
		let (quote, plan) = self.offboard_plan(&info, asset, amount, script, max_fee_ppm)?;
		if let Some(s) = shown {
			for k in ["fee", "gives"] {
				if s[k] != quote[k] {
					return Err(Error::Refused(format!("the offboard's {} changed since it was shown: it is now {}", k, quote[k])));
				}
			}
		}
		let mut wanted = vec![Wanted::Offboard { asset, value: amount, script: script.clone() }];
		let mut wanted_json = vec![json!({"offboard": {"asset": asset.to_string(), "value": amount.to_string(),
			"script": hex(script.as_bytes()), "margin": plan.margin.to_string()}})];
		if plan.change > 0 {
			let nonce = random32();
			let owner = self.keys.leaf_xonly(&nonce)?;
			self.store.put_nonce(&nonce, &owner.serialize(), "offboard change")?;
			wanted.push(Wanted::Leaf { asset, value: plan.change, template: Template::Vtxo1, owner, owner_nonce: nonce,
				exit_delay: self.exit_delay(), order: None, landing: None, channel: None });
			wanted_json.push(json!({"nonce": hex(&nonce), "asset": asset.to_string(), "value": plan.change.to_string()}));
		}
		let fees = vec![(asset, plan.fee)];
		let ids: Vec<LeafId> = plan.coins.iter().map(|c| c.coin.id).collect();
		let id = participation_id(&self.genesis, &self.operator, &ids, &wanted, &fees, None);
		let mut inputs = vec![];
		for c in &plan.coins {
			let k = self.coin_key(&c.row.owner_nonce)?;
			inputs.push(json!({"leaf_id": c.row.leaf_id, "attestation": hex(sign(&k, &id).as_ref())}));
		}
		let mut outputs = vec![];
		for w in &wanted {
			let mut j = w.json();
			if let Wanted::Leaf { owner_nonce, .. } = w {
				let k = self.keys.leaf(owner_nonce)?;
				j["leaf"]["key_proof"] = json!(hex(sign(&k, &key_proof_digest(&id)).as_ref()));
				let (mailbox, proof) = self.binding(&k)?;
				j["leaf"]["mailbox"] = json!(mailbox);
				j["leaf"]["mailbox_proof"] = json!(proof);
			}
			outputs.push(j);
		}
		let body = json!({"inputs": inputs, "outputs": outputs,
			"fees": fees.iter().map(|(a, v)| json!({"asset": a.to_string(), "amount": v.to_string()})).collect::<Vec<_>>()});
		let pid = hex(&id);
		let given: Vec<String> = plan.coins.iter().map(|c| c.row.leaf_id.clone()).collect();
		let entry = json!({"offboard": pid, "asset": asset.to_string(), "amount": amount.to_string(), "script": hex(script.as_bytes())});
		self.store.atomically(|s| {
			s.put_participation(&pid, &body.to_string(), &serde_json::to_string(&given).expect("strings"),
				&Value::Array(wanted_json.clone()).to_string())?;
			for l in &given {
				s.set_coin_state(l, "given", &format!("offboard {}", pid))?;
			}
			let mut list: Vec<Value> = s.meta(OFFBOARDS)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
			list.push(entry.clone());
			s.set_meta(OFFBOARDS, &Value::Array(list).to_string())
		})?;
		let answer = self.submit_participation_body(&pid, &body, &given)?;
		// When the round that pays it is due: within the operator's interval
		// between rounds while participations wait, when it publishes one.
		let within = info["fills"]["round_interval_seconds"].as_u64().filter(|s| *s > 0);
		Ok(json!({"offboard": pid, "state": answer["state"], "asset": asset.to_string(), "amount": amount.to_string(),
			"address": quote["address"], "script": quote["script"], "fee": quote["fee"], "gives": given,
			"change": plan.change.to_string(), "round_within_seconds": within,
			"note": self.spelling.say("asked: once the operator's round pays the offboard and is final, {sync} hands over the forfeits; \
				the operator then pays the address on the chain. {offboards} says where it stands")}))
	}

	/// Moves each offboard on as far as `sync` takes it: once its
	/// participation is released, the round's offboard output is recorded;
	/// once the wallet has held the preimage for [`UNLOCK_GRACE_SECONDS`] and
	/// the operator has not unlocked the output, the wallet unlocks it
	/// itself, its margin paying the fee where the node accepts the asset.
	pub(crate) fn progress_offboards(&mut self) -> Result<Vec<Value>, Error> {
		let mut list: Vec<Value> = self.store.meta(OFFBOARDS)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		if list.is_empty() {
			return Ok(vec![]);
		}
		let parts = self.store.participations()?;
		let now = self.now()?.to_consensus_u32();
		let mut out = vec![];
		let mut changed = false;
		for e in list.iter_mut() {
			let id = e["offboard"].as_str().unwrap_or("").to_string();
			let Some((_, _, _, _, state, preimage, _)) = parts.iter().find(|p| p.0 == id) else { continue };
			let Some(at) = e["at"].as_str().map(str::to_string) else {
				if state == "released" {
					let news: Value = serde_json::from_str(&self.store.participation_news(&id)?.unwrap_or_default())
						.map_err(|e| Error::Store(e.to_string()))?;
					let off = &news["offboards"][0];
					if let (Some(round), Some(vout)) = (news["round"].as_str(), off["vout"].as_u64()) {
						e["at"] = json!(format!("{}:{}", round, vout));
						e["reclaim_units"] = off["reclaim_units"].clone();
						e["unlock_after"] = json!(now.saturating_add(UNLOCK_GRACE_SECONDS));
						changed = true;
						out.push(json!({"offboard": id, "state": "unlocking", "output": e["at"]}));
					}
				}
				continue;
			};
			let off = parse_outpoint(&at)?;
			if !self.chain.unspent(&off)? || e["unlock_after"].as_u64().is_some_and(|t| (now as u64) < t) {
				continue;
			}
			// The operator has not unlocked it: the wallet does, with the
			// preimage it holds.
			let Some(pre) = preimage.as_deref() else { continue };
			match self.unlock_offboard(e, &off, &unhex32(pre)?) {
				Ok(txid) => out.push(json!({"offboard": id, "unlocked": txid.to_string(),
					"note": "the operator had not unlocked the offboard: the wallet did, with the preimage it holds"})),
				Err(err) => out.push(json!({"offboard": id, "unlock": err.to_string()})),
			}
		}
		if changed {
			self.store.set_meta(OFFBOARDS, &Value::Array(list).to_string())?;
		}
		Ok(out)
	}

	/// The unlock of offboard `e`'s output at `off` into its address, its
	/// margin the fee: where the node does not take the asset for fees the
	/// operator's watcher, which attaches a coin, unlocks it.
	fn unlock_offboard(&self, e: &Value, off: &OutPoint, preimage: &[u8; 32]) -> Result<Txid, Error> {
		let asset = AssetId::from_str(e["asset"].as_str().unwrap_or("")).map_err(|err| Error::Store(err.to_string()))?;
		let amount: u64 = e["amount"].as_str().unwrap_or("").parse().map_err(|_| Error::Store("an offboard's amount".into()))?;
		let script = Script::from(unhex(e["script"].as_str().unwrap_or(""))?);
		let tx = self.chain.transaction(&off.txid)?.ok_or_else(|| Error::Node(format!("the node does not have round {}", off.txid)))?;
		let held = tx.output.get(off.vout as usize).and_then(|o| o.value.explicit())
			.ok_or_else(|| Error::Refused(format!("round {} has no explicit output {}", off.txid, off.vout)))?;
		let policy = OffboardPolicy {
			unlock_hash: sha256::Hash::hash(preimage).to_byte_array(),
			destination: ExplicitOutput::new(asset, amount, script), operator: self.operator,
			reclaim_delay: RelativeTime::from_units(e["reclaim_units"].as_u64().unwrap_or(0) as u16)
				.map_err(|err| Error::Refused(err.to_string()))?,
		};
		if self.chain.floor_per_kvb(asset)?.is_none() {
			return Err(Error::Refused(format!("the node does not take asset {} for fees now: the operator's watcher unlocks the \
				offboard, attaching a coin of its own", asset)));
		}
		let u = policy.unlock_tx(*off, held, preimage, &FeeSource::Reserve).map_err(|err| Error::Refused(err.to_string()))?;
		self.chain.broadcast(&u.tx)
	}

	/// Every offboard the wallet asked for, and where it stands, read from
	/// the chain: `waiting` for the operator's round, `in_round` until `sync`
	/// hands over its forfeits, `unlocking` until the round's output is paid
	/// to the address, `paid` (the unlock's txid and whether it is final),
	/// `reclaimed` (the operator took the output back after its delay), or
	/// `not_made` (the participation ended without a round: the coins are the
	/// wallet's again).
	pub fn offboards(&self) -> Result<Value, Error> {
		let list: Vec<Value> = self.store.meta(OFFBOARDS)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		let parts = self.store.participations()?;
		let mut out = vec![];
		for e in &list {
			let id = e["offboard"].as_str().unwrap_or("");
			let state = parts.iter().find(|p| p.0 == id).map(|p| p.4.as_str()).unwrap_or("unknown");
			let script = Script::from(unhex(e["script"].as_str().unwrap_or(""))?);
			let mut v = json!({"offboard": id, "asset": e["asset"], "amount": e["amount"], "address": self.chain.address(&script)?,
				"script": e["script"]});
			match e["at"].as_str() {
				None => {
					v["state"] = json!(match state {
						"submitting" | "pending" => "waiting",
						"issued" | "forfeiting" => "in_round",
						"released" => "unlocking",
						_ => "not_made",
					});
				},
				Some(at) => {
					let off = parse_outpoint(at)?;
					v["output"] = json!(at);
					let from = self.chain.finality(&off.txid)?.height().unwrap_or(0).saturating_sub(1);
					match self.chain.spender(&off, from)? {
						None => v["state"] = json!("unlocking"),
						Some((tx, _)) => {
							let i = tx.input.iter().position(|x| x.previous_output == off).unwrap_or(0);
							let paid = tx.output.get(i).and_then(ExplicitOutput::from_txout)
								.is_some_and(|o| o.script_pubkey == script && Some(o.value) == e["amount"].as_str().and_then(|a| a.parse().ok()));
							v["state"] = json!(if paid { "paid" } else { "reclaimed" });
							v["txid"] = json!(tx.txid().to_string());
							v["final"] = json!(self.chain.finality(&tx.txid())?.is_final());
						},
					}
				},
			}
			out.push(v);
		}
		Ok(Value::Array(out))
	}
}
