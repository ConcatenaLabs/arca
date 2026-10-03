//! Taking part in a round: the refresh.
//!
//! One request, never interactive: the coins given up, each attested by its
//! key, the leaves wanted (one per asset, under a fresh key each) and the fee
//! the operator's schedule asks, in each coin's own asset. Then, once the
//! round holding the participation is final, the wallet rebuilds each new
//! leaf from the published tree, validates it against the round transaction
//! with the five checks on its sweep token and clock and every bound of its
//! policy, and only then signs the forfeit of each coin it gave up, built from
//! that validated leaf and round, and its unroll authorisations. The server
//! answers with the preimage that opens the new leaves; the wallet checks it
//! against their unlock hash, keeps them, and releases the lowest node of each
//! old batch leaf.

use std::collections::BTreeMap;
use std::str::FromStr;

use elements::hashes::{sha256, Hash};
use elements::{AssetId, Txid};
use serde_json::{json, Value};

use arca_covenant::encode::Encoding;
use arca_covenant::spend::margin_for;
use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeParams};
use arca_covenant::{Chain, ClockSchedule, CoinRecord, Forfeit, LeafRecord, MedianTime, Release, RelativeTime, Template, ValidLeaf, WalletPolicy};

use super::chain::{hex, unhex, unhex32};
use super::client::{participation_id, Wanted};
use super::pay::MARGIN_MULTIPLE;
use super::wallet::{amount, sign, Wallet};
use super::Error;

/// The operator's refresh fee for a coin of `value` whose earliest expiry is
/// `expiry`, at `now`, by the schedule `info` publishes.
pub fn refresh_fee(fees: &Value, value: u64, expiry: u32, now: u32) -> u64 {
	let ppm = fees["refresh_ppm"].as_u64().unwrap_or(0) as u128;
	let free = fees["free_window_seconds"].as_u64().unwrap_or(0) as u32;
	let full = fees["full_after_seconds"].as_u64().unwrap_or(1).max(1) as u32;
	let left = expiry.saturating_sub(now).saturating_sub(free);
	let charged = left.min(full) as u128;
	((value as u128 * ppm * charged).div_ceil(full as u128 * 1_000_000)).min(u64::MAX as u128) as u64
}

/// The tree a published batch describes, rebuilt by the wallet from the
/// published parts alone.
pub fn rebuild(t: &Value) -> Result<Tree, Error> {
	let s = |k: &str| t[k].as_str().map(|s| s.to_string()).ok_or_else(|| Error::Parse(format!("the published tree has no {}", k)));
	let reserve = if let Some(r) = t["reserve"].get("fee_rate") {
		ReserveRule::FeeRate { floor_per_kvb: amount(&r["floor_per_kvb"], "floor_per_kvb")?, multiple: amount(&r["multiple"], "multiple")? }
	} else {
		let r = &t["reserve"]["fixed"];
		ReserveRule::Fixed { node: amount(&r["node"], "node")?, entry: amount(&r["entry"], "entry")? }
	};
	let params = TreeParams {
		asset: AssetId::from_str(&s("asset")?).map_err(|e| Error::Parse(e.to_string()))?,
		chain: Chain::new(elements::BlockHash::from_str(&s("genesis_hash")?).map_err(|e| Error::Parse(e.to_string()))?),
		schedule: ClockSchedule::decode(&unhex(&s("schedule")?)?).map_err(|e| Error::Refused(format!("the published schedule: {}", e)))?,
		burn: t["burn"].as_bool().unwrap_or(false),
		radix: t["radix"].as_u64().unwrap_or(0) as usize,
		reserve,
		min_leaf: amount(&t["min_leaf"], "min_leaf")?,
	};
	let mut leaves = vec![];
	for l in t["leaves"].as_array().cloned().unwrap_or_default() {
		leaves.push(LeafSpec {
			template: l["template"].as_str().unwrap_or("").parse().map_err(|e: arca_covenant::RecordError| Error::Parse(e.to_string()))?,
			owner: elements::secp256k1_zkp::XOnlyPublicKey::from_slice(&unhex(l["owner"].as_str().unwrap_or(""))?)
				.map_err(|e| Error::Parse(e.to_string()))?,
			value: amount(&l["value"], "a leaf's value")?,
			owner_nonce: unhex32(l["owner_nonce"].as_str().unwrap_or(""))?,
			operator_nonce: unhex32(l["operator_nonce"].as_str().unwrap_or(""))?,
			exit_delay: RelativeTime::from_units(l["exit_delay_units"].as_u64().unwrap_or(0) as u16).map_err(|e| Error::Parse(e.to_string()))?,
			unlock_hash: unhex32(l["unlock_hash"].as_str().unwrap_or(""))?,
		});
	}
	Tree::build(params, &leaves).map_err(|e| Error::Refused(format!("the published tree does not build: {}", e)))
}

impl Wallet {
	/// Gives up `leaf_ids` (every live coin when empty) for one new leaf per
	/// asset in a round, paying the operator's schedule in each coin's own
	/// asset. Not before median time `not_before`, when given.
	pub fn participate(&mut self, leaf_ids: &[String], not_before: Option<u32>) -> Result<Value, Error> {
		let info = self.server_info()?;
		let now = self.now()?;
		let rows: Vec<_> = if leaf_ids.is_empty() {
			self.store.coins_in("live")?
		} else {
			leaf_ids.iter().map(|l| {
				let c = self.store.coin(l)?.ok_or_else(|| Error::Refused(format!("no coin {}", l)))?;
				if c.state != "live" {
					return Err(Error::Refused(format!("coin {} is {}, not live", l, c.state)));
				}
				Ok(c)
			}).collect::<Result<_, _>>()?
		};
		if rows.is_empty() {
			return Err(Error::Refused("no live coin to refresh".into()));
		}
		let mut per: BTreeMap<AssetId, (u64, u64)> = BTreeMap::new();
		let mut ids = vec![];
		for r in &rows {
			let (_, a) = self.held(r)?;
			if !a.all_final() {
				return Err(Error::Refused(format!("coin {} is not final: {}", r.leaf_id, a.waiting())));
			}
			let fee = refresh_fee(&info["fees"], a.valid.value, a.valid.expiry.to_consensus_u32(), now.to_consensus_u32());
			let e = per.entry(a.valid.asset).or_default();
			e.0 += a.valid.value;
			e.1 += fee;
			ids.push(a.valid.id);
		}
		let mut wanted = vec![];
		let mut nonces = vec![];
		let mut fees = vec![];
		for (asset, (total, fee)) in &per {
			let value = total - fee;
			let min = Self::min_leaf(&info, *asset)?;
			if value < min {
				return Err(Error::Refused(format!("the new leaf in asset {} would hold {}, below the operator's smallest leaf {}", asset, value, min)));
			}
			let nonce = super::random32();
			let owner = self.keys.leaf_xonly(&nonce)?;
			self.store.put_nonce(&nonce, &owner.serialize(), "refresh")?;
			wanted.push(Wanted::Leaf { asset: *asset, value, template: Template::Vtxo1, owner, owner_nonce: nonce, exit_delay: self.exit_delay() });
			nonces.push(json!({"nonce": hex(&nonce), "asset": asset.to_string(), "value": value.to_string()}));
			if *fee > 0 {
				fees.push((*asset, *fee));
			}
		}
		let nb = not_before.map(MedianTime::from_consensus).transpose().map_err(|e| Error::Refused(e.to_string()))?;
		let id = participation_id(&self.genesis, &self.operator, &ids, &wanted, &fees, nb);
		let mut inputs = vec![];
		for r in &rows {
			let key = self.keys.leaf(&r.owner_nonce)?;
			inputs.push(json!({"leaf_id": r.leaf_id, "attestation": hex(sign(&key, &id).as_ref())}));
		}
		let mut body = json!({
			"inputs": inputs, "outputs": wanted.iter().map(Wanted::json).collect::<Vec<_>>(),
			"fees": fees.iter().map(|(a, v)| json!({"asset": a.to_string(), "amount": v.to_string()})).collect::<Vec<_>>(),
		});
		if let Some(t) = not_before {
			body["not_before"] = json!(t);
		}
		let pid = hex(&id);
		let given: Vec<String> = rows.iter().map(|r| r.leaf_id.clone()).collect();
		self.store.atomically(|s| {
			s.put_participation(&pid, &body.to_string(), &serde_json::to_string(&given).expect("strings"), &Value::Array(nonces.clone()).to_string())?;
			for l in &given {
				s.set_coin_state(l, "given", &format!("participation {}", pid))?;
			}
			Ok(())
		})?;
		let answer = self.submit(&pid, &body, &given)?;
		Ok(json!({"participation": pid, "state": answer["state"], "gives": given, "wants": nonces,
			"fees": fees.iter().map(|(a, v)| json!({"asset": a.to_string(), "amount": v.to_string()})).collect::<Vec<_>>()}))
	}

	fn submit(&mut self, pid: &str, body: &Value, given: &[String]) -> Result<Value, Error> {
		match self.server.post("submit_participation", body) {
			Ok(a) => {
				self.store.set_participation(pid, a["state"].as_str().unwrap_or("pending"), None, None)?;
				Ok(a)
			},
			Err(e @ Error::Server { .. }) => {
				self.store.atomically(|s| {
					for l in given {
						s.set_coin_state(l, "live", "")?;
					}
					s.set_participation(pid, "refused", None, None)?;
					s.refused(&format!("participation {}", pid), &e.to_string())
				})?;
				Err(e)
			},
			Err(e) => Err(e),
		}
	}

	/// Moves every participation on as far as it can go now: submits one the
	/// server never answered, completes one whose round is final, and puts
	/// back the coins of one the server voided.
	pub(crate) fn progress_participations(&mut self) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		for (pid, body, given, wanted, state, _, _) in self.store.participations()? {
			let given: Vec<String> = serde_json::from_str(&given).map_err(|e| Error::Store(e.to_string()))?;
			if matches!(state.as_str(), "released" | "void" | "refused") {
				continue;
			}
			if state == "submitting" {
				let body: Value = serde_json::from_str(&body).map_err(|e| Error::Store(e.to_string()))?;
				match self.submit(&pid, &body, &given) {
					Ok(a) => out.push(json!({"participation": pid, "state": a["state"]})),
					Err(e) => out.push(json!({"participation": pid, "error": e.to_string()})),
				}
				continue;
			}
			let st = self.server.post("participation_status", &json!({"participation_id": pid}))?;
			match st["state"].as_str().unwrap_or("") {
				"pending" => out.push(json!({"participation": pid, "state": "pending", "note": "waiting for a round"})),
				"void" => {
					self.store.atomically(|s| {
						for l in &given {
							s.set_coin_state(l, "live", "")?;
						}
						s.set_participation(&pid, "void", None, None)
					})?;
					out.push(json!({"participation": pid, "state": "void", "note": "the server will not run it; its coins are live again"}));
				},
				"issued" | "released" => {
					let wanted: Value = serde_json::from_str(&wanted).map_err(|e| Error::Store(e.to_string()))?;
					match self.complete(&pid, &st, &given, &wanted) {
						Ok(v) => out.push(v),
						Err(e) => {
							self.store.refused(&format!("participation {}", pid), &e.to_string())?;
							out.push(json!({"participation": pid, "state": st["state"], "refused": e.to_string()}));
						},
					}
				},
				other => out.push(json!({"participation": pid, "state": other})),
			}
		}
		Ok(out)
	}

	/// The forfeit swap of an issued participation, once its round is final.
	fn complete(&mut self, pid: &str, st: &Value, given: &[String], wanted: &Value) -> Result<Value, Error> {
		let round_txid = Txid::from_str(st["round"]["txid"].as_str().unwrap_or("")).map_err(|e| Error::Parse(e.to_string()))?;
		let finality = self.chain.finality(&round_txid)?;
		if !finality.is_final() {
			return Ok(json!({"participation": pid, "state": "issued", "round": round_txid.to_string(),
				"note": format!("the round is {}; the wallet signs nothing for it before it is final", finality.word())}));
		}
		if st["forfeit_first"].as_bool() == Some(true) {
			return Ok(json!({"participation": pid, "state": st["state"], "note": "forfeit-first: the preimage comes only from the claim of the forfeit on-chain"}));
		}
		let round = self.chain.transaction(&round_txid)?.ok_or_else(|| Error::Node(format!("the node does not have round {}", round_txid)))?;
		let now = self.now()?;
		let accept = self.accept_policy(now);
		// Each new leaf, rebuilt from the published tree and validated
		// against the round before anything is signed for it.
		let mut news: Vec<(ValidLeaf, LeafRecord, [u8; 32])> = vec![];
		let wanted = wanted.as_array().cloned().unwrap_or_default();
		for (j, o) in st["outputs"].as_array().cloned().unwrap_or_default().iter().enumerate() {
			let w = wanted.get(j).ok_or_else(|| Error::Refused("the server reports more outputs than the wallet asked for".into()))?;
			let nonce = unhex32(w["nonce"].as_str().unwrap_or(""))?;
			let tree = self.server.post("tree", &json!({"txid": round_txid.to_string(), "vout": o["batch_vout"]}))?;
			if tree["round_txid"].as_str() != Some(&round_txid.to_string()) {
				return Err(Error::Refused("the server published the tree of another round".into()));
			}
			let tree = rebuild(&tree)?;
			let index = o["leaf_index"].as_u64().ok_or_else(|| Error::Parse("no leaf_index".into()))? as usize;
			if index >= tree.records().len() {
				return Err(Error::Refused("the server names a leaf the published tree does not have".into()));
			}
			let record = tree.record(index);
			let owner = self.keys.leaf_xonly(&nonce)?;
			let valid = record.validate(&round, &accept, &owner, &nonce)
				.map_err(|e| Error::Refused(format!("the new leaf in round {} fails the wallet's checks: {}", round_txid, e)))?;
			if record.asset.to_string() != w["asset"].as_str().unwrap_or("") || record.value.to_string() != w["value"].as_str().unwrap_or("") {
				return Err(Error::Refused(format!("the new leaf holds {} of {}; the wallet asked for {} of {}", record.value, record.asset,
					w["value"], w["asset"])));
			}
			if Some(valid.leaf_id.to_string().as_str()) != o["leaf_id"].as_str() {
				return Err(Error::Refused("the server names the new leaf by another id than its record gives".into()));
			}
			news.push((valid, record, nonce));
		}
		if news.is_empty() {
			return Err(Error::Refused("the participation has no new leaf".into()));
		}
		// Every forfeit's refund must run out before the new leaves' exit
		// deadline, or withholding the preimage strands the owner.
		let refund = RelativeTime::from_units(st["refund_delay_units"].as_u64().unwrap_or(0) as u16).map_err(|e| Error::Parse(e.to_string()))?;
		let deadline = news.iter().map(|(_, r, _)| r.schedule.expiries()[0].to_consensus_u32()).min().unwrap_or(0)
			.saturating_sub(WalletPolicy::EXIT_DEADLINE);
		if now.to_consensus_u32() as u64 + refund.seconds() >= deadline as u64 {
			return Err(Error::Refused(format!("the forfeits' refund delay of {} s would end after the new leaves' exit deadline", refund.seconds())));
		}
		let c = st["round"]["connector_vout"].as_u64().ok_or_else(|| Error::Parse("no connector_vout".into()))? as u32;
		let mut forfeits = vec![];
		let mut releases = vec![];
		for (k, l) in given.iter().enumerate() {
			let row = self.store.coin(l)?.ok_or_else(|| Error::Store(format!("coin {} is gone", l)))?;
			let (record, a) = self.held(&row)?;
			let old = &a.valid;
			let margin = amount(&st["inputs"][k]["margin"], "a forfeit's margin")?;
			// The margin is the fee of a forfeit someone broadcasts: a few
			// times the floor, or one atom where the node does not take the
			// asset for fees. More is value handed to the broadcaster.
			let ceiling = match self.chain.floor_per_kvb(old.asset)? {
				Some(f) => margin_for(1000, f, MARGIN_MULTIPLE),
				None => 1,
			};
			if margin > ceiling {
				return Err(Error::Refused(format!("the forfeit of {} would leave {} atoms uncommitted; the wallet leaves at most {}", l, margin, ceiling)));
			}
			let f = Forfeit::for_refresh(old.leaf, (old.asset, old.value), old.id, &news[0].0, &round, c, refund, margin)
				.map_err(|e| Error::Refused(format!("the forfeit of {}: {}", l, e)))?;
			let key = self.keys.leaf(&row.owner_nonce)?;
			forfeits.push(json!({"leaf_id": l, "signature": hex(sign(&key, &f.message().digest).as_ref())}));
			// A batch leaf's lowest node is released for this round alone: the
			// release names the round's connector asset, so it is void if the
			// round leaves the chain.
			if let (CoinRecord::Leaf { .. }, arca_covenant::ValidOrigin::Leaf { valid, .. }) = (&record, &old.origin) {
				if valid.branch.nodes.last().is_some_and(|n| n.reclaim.is_some()) {
					let rel = Release::for_refresh(valid, &news[0].0, &round, c)
						.map_err(|e| Error::Refused(format!("the release of {}: {}", l, e)))?;
					releases.push(json!({"leaf_id": l, "signature": hex(sign(&key, &rel.message().digest).as_ref())}));
				}
			}
		}
		// Unroll authorisations an hour before now: usable at once.
		let t = MedianTime::from_consensus(now.to_consensus_u32().saturating_sub(3600)).map_err(|e| Error::Node(e.to_string()))?;
		let mut leaves = vec![];
		let mut auths_of = vec![];
		for (valid, _, nonce) in &news {
			let key = self.keys.leaf(nonce)?;
			let sigs: Vec<_> = valid.branch.nodes.iter().map(|n| (sign(&key, &n.unroll_authorisation(t).digest), t)).collect();
			leaves.push(json!({"leaf_id": valid.leaf_id.to_string(),
				"auths": sigs.iter().map(|(s, t)| json!({"signature": hex(s.as_ref()), "time": t.to_consensus_u32()})).collect::<Vec<_>>()}));
			auths_of.push(sigs);
		}
		let done = self.server.post("forfeit_leaves", &json!({"participation_id": pid, "forfeits": forfeits, "leaves": leaves}))?;
		let Some(pre) = done["preimage"].as_str() else {
			return Ok(json!({"participation": pid, "state": done["state"], "note": "forfeits in; the preimage is not out yet"}));
		};
		let preimage = unhex32(pre)?;
		let mut kept = vec![];
		for ((valid, record, nonce), auths) in news.iter().zip(auths_of) {
			if sha256::Hash::hash(&preimage).to_byte_array() != record.unlock_hash {
				return Err(Error::Refused("the server's preimage does not open the new leaves".into()));
			}
			let coin = CoinRecord::Leaf { record: record.clone(), preimage, auths };
			let a = self.assess(&coin, &self.receipt_policy(now), Some((&record.owner, nonce)))?;
			let row = self.row(&coin, &a, if a.all_final() { "live" } else { "pending" }, "")?;
			if self.store.coin(&row.leaf_id)?.is_none() {
				let id = row.leaf_id.clone();
				self.store.atomically(|s| {
					s.put_coin(&row)?;
					s.use_nonce(nonce, &id)
				})?;
			}
			kept.push(json!({"leaf_id": valid.leaf_id.to_string(), "asset": record.asset.to_string(), "value": record.value.to_string(),
				"expiry": record.schedule.expiries()[0].to_consensus_u32()}));
		}
		self.store.atomically(|s| {
			for l in given {
				s.set_coin_spent(l, &format!("participation {}", pid))?;
			}
			s.set_participation(pid, "released", Some(pre), Some(&round_txid.to_string()))
		})?;
		// The release of each old batch leaf's lowest node, now that the
		// preimage is in hand, the new leaves validated and their round final.
		let released = if releases.is_empty() {
			Value::Array(vec![])
		} else {
			match self.server.post("release_leaves", &json!({"participation_id": pid, "releases": releases})) {
				Ok(v) => v["released"].clone(),
				Err(e) => json!({"error": e.to_string()}),
			}
		};
		Ok(json!({"participation": pid, "state": "released", "round": round_txid.to_string(), "new_leaves": kept, "released": released}))
	}
}
