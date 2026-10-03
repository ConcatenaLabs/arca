//! Taking part in a round: the refresh.
//!
//! One request, never interactive: the coins given up, each attested by its
//! key, the leaves wanted (one per asset, under a fresh key each) and the fee
//! the operator's schedule asks, in each coin's own asset. Then, once the
//! round holding the participation is final, the wallet rebuilds each new
//! leaf from the published tree, validates it against the round transaction
//! with the five checks on its sweep token and clock and every bound of its
//! policy, and requires the status to show exactly the leaves it asked for,
//! in order, all under the participation's one unlock hash, and exactly the
//! coins it gave up. Only then does it sign the forfeit of each coin it gave
//! up, built from the validated leaf of the coin's own asset and its round,
//! and its unroll authorisations. The server
//! answers with the preimage that opens the new leaves; the wallet checks it
//! against their unlock hash, keeps them, and releases the lowest node of each
//! old batch leaf.

use std::collections::BTreeMap;
use std::str::FromStr;

use elements::hashes::{sha256, Hash};
use elements::{AssetId, OutPoint, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::encode::Encoding;
use arca_covenant::spend::{margin_for, FeeSource};
use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeParams};
use arca_covenant::{connector_asset, Chain, ClockSchedule, CoinRecord, ExplicitOutput, Forfeit, LeafRecord, MedianTime, Release, RelativeTime, Template, ValidLeaf, WalletPolicy};

use super::chain::{hex, unhex, unhex32};
use super::store::ForfeitRow;
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

/// The most a refresh may cost, in millionths of a coin's value, unless the
/// user raises it for one command.
pub const DEFAULT_MAX_FEE_PPM: u64 = 10_000;

/// A refresh is free in the two days before a coin's exit deadline, three
/// days before its first expiry: the wallet pays nothing there unless the
/// user raises the bound for one command, whatever window the server
/// publishes.
pub const FREE_WINDOW: u32 = 2 * 86_400;

/// Whether a coin whose first expiry is `expiry` is in its free window at
/// `now`.
pub fn in_free_window(expiry: u32, now: u32) -> bool {
	(expiry as u64).saturating_sub(now as u64) <= (WalletPolicy::EXIT_DEADLINE + FREE_WINDOW) as u64
}

/// Whether `fee` is at most `ppm` millionths of `value`.
pub fn fee_within(fee: u64, value: u64, ppm: u64) -> bool {
	(fee as u128) * 1_000_000 <= (value as u128) * (ppm as u128)
}

fn ppm_of(fee: u64, value: u64) -> u64 {
	((fee as u128 * 1_000_000).div_ceil(value.max(1) as u128)).min(u64::MAX as u128) as u64
}

/// What the wallet says of a leaf in an asset the node does not accept for
/// fees, before it takes one.
const FEE_COIN_NOTE: &str = "the node does not accept these assets for fees, so the new leaves' reserves are one atom: every transaction \
	of an exit of them needs a fee coin of the wallet's in an asset the node accepts (exit --fee-asset)";

/// A refresh as [`Wallet::refresh_quote`] prices it: the coins it gives up
/// and what each costs, checked against the wallet's bound.
pub struct RefreshQuote {
	info: Value,
	rows: Vec<super::store::CoinRow>,
	ids: Vec<arca_covenant::LeafId>,
	per: BTreeMap<AssetId, (u64, u64)>,
	coins: Vec<Value>,
}

impl RefreshQuote {
	/// Each coin given up, its fee, that fee in millionths of the coin, and
	/// the bound it was checked against.
	pub fn coins(&self) -> &[Value] {
		&self.coins
	}
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
	/// What a refresh of `leaf_ids` (every live coin when empty) costs, coin by
	/// coin, by the schedule the server's `info` publishes, checked against
	/// the wallet's bound before anything is signed: a fee above
	/// `max_fee_ppm` of a coin (by default [`DEFAULT_MAX_FEE_PPM`]), or any fee
	/// for a coin in the free window (the [`FREE_WINDOW`] before its exit
	/// deadline) unless `max_fee_ppm` is given, is refused. The quote is what
	/// [`Wallet::participate`] submits.
	pub fn refresh_quote(&self, leaf_ids: &[String], max_fee_ppm: Option<u64>) -> Result<RefreshQuote, Error> {
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
		let mut coins = vec![];
		for r in &rows {
			let (record, a) = self.held(r)?;
			if !a.all_final() {
				return Err(Error::Refused(format!("coin {} is not final: {}", r.leaf_id, a.waiting())));
			}
			// A coin resting on a board counts from the board's dates, and is
			// taken into a refresh until a day before the board's expiry.
			let (value, expiry) = (a.valid.value, self.service_expiry(&record, &a)?);
			if let Some(b) = self.board_expiry(&record, &a.bases)? {
				if now.to_consensus_u32() as u64 + super::wallet::BOARD_REFRESH_UNTIL as u64 >= b as u64 {
					return Err(Error::Refused(format!("coin {} rests on a board whose service ends at median time {}: the operator takes \
						it into a refresh only until a day before; exit it", r.leaf_id, b)));
				}
			}
			let fee = refresh_fee(&info["fees"], value, expiry, now.to_consensus_u32());
			let free = in_free_window(expiry, now.to_consensus_u32());
			let bound = max_fee_ppm.unwrap_or(if free { 0 } else { DEFAULT_MAX_FEE_PPM });
			if !fee_within(fee, value, bound) {
				return Err(Error::Refused(format!("the operator asks a refresh fee of {} of asset {} for coin {}: {} ppm of its {}{}; \
					the wallet pays at most {} ppm{} unless the bound is raised for this command (--max-fee-ppm)",
					fee, a.valid.asset, r.leaf_id, ppm_of(fee, value), value,
					if free { ", inside its free window (the two days before its exit deadline), where a refresh is free" } else { "" },
					bound, if max_fee_ppm.is_none() && !free { ", and nothing in a coin's free window," } else { "" })));
			}
			let e = per.entry(a.valid.asset).or_default();
			e.0 = e.0.checked_add(value).ok_or_else(|| Error::Refused("the coins' values overflow".into()))?;
			e.1 = e.1.checked_add(fee).ok_or_else(|| Error::Refused("the fees overflow".into()))?;
			ids.push(a.valid.id);
			coins.push(json!({"leaf_id": r.leaf_id, "asset": a.valid.asset.to_string(), "value": value.to_string(), "fee": fee.to_string(),
				"ppm": ppm_of(fee, value), "free_window": free, "bound_ppm": bound}));
		}
		for (asset, (total, fee)) in &per {
			let value = total.checked_sub(*fee).ok_or_else(|| Error::Refused(format!("the refresh fee of {} in asset {} is more than the \
				coins hold, {}", fee, asset, total)))?;
			let min = Self::min_leaf(&info, *asset)?;
			if value < min {
				return Err(Error::Refused(format!("the new leaf in asset {} would hold {}, below the operator's smallest leaf {}", asset, value, min)));
			}
		}
		Ok(RefreshQuote { info, rows, ids, per, coins })
	}

	/// Gives up the coins of `quote` for one new leaf per asset in a round,
	/// paying the fees it states in each coin's own asset. Not before median
	/// time `not_before`, when given.
	pub fn participate(&mut self, quote: RefreshQuote, not_before: Option<u32>) -> Result<Value, Error> {
		let RefreshQuote { info, rows, ids, per, coins } = quote;
		let mut needs_fee_coin = vec![];
		for asset in per.keys() {
			if self.chain.floor_per_kvb(*asset)?.is_none() {
				needs_fee_coin.push(asset.to_string());
			}
		}
		let mut wanted = vec![];
		let mut nonces = vec![];
		let mut fees = vec![];
		for (asset, (total, fee)) in &per {
			let value = total.checked_sub(*fee).ok_or_else(|| Error::Refused("the refresh fee is more than the coins hold".into()))?;
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
		let mut out = json!({"participation": pid, "state": answer["state"], "gives": given, "wants": nonces,
			"fees": fees.iter().map(|(a, v)| json!({"asset": a.to_string(), "amount": v.to_string()})).collect::<Vec<_>>(), "quote": coins});
		if !needs_fee_coin.is_empty() {
			out["exit_needs_fee_coin"] = json!({"assets": needs_fee_coin, "note": FEE_COIN_NOTE});
		}
		Ok(out)
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
	/// server never answered, completes one whose round is final, and gives
	/// back the coins of one the server will not run (`void`, or `expired`
	/// after its forfeit day), except a coin under a forfeit the wallet
	/// signed that could still be claimed. One participation the server does
	/// not answer for stops no other.
	pub(crate) fn progress_participations(&mut self) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		for (pid, body, given, wanted, state, _, _) in self.store.participations()? {
			let given: Vec<String> = serde_json::from_str(&given).map_err(|e| Error::Store(e.to_string()))?;
			if matches!(state.as_str(), "released" | "void" | "expired" | "refused" | "lost") {
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
			let st = match self.server.post("participation_status", &json!({"participation_id": pid})) {
				Ok(st) => st,
				Err(e) => {
					out.push(json!({"participation": pid, "state": state, "error": e.to_string()}));
					continue;
				},
			};
			match st["state"].as_str().unwrap_or("") {
				// The server will not run it, or its forfeit day passed.
				s @ ("void" | "expired") => out.push(self.give_back(&pid, &given, s)?),
				_ if state == "withdrawn" => out.push(json!({"participation": pid, "state": "withdrawn",
					"note": "the wallet is taking a coin of it on-chain, and signs nothing for it"})),
				"pending" => out.push(json!({"participation": pid, "state": "pending", "note": "waiting for a round"})),
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

	/// The server will not run participation `pid` (`why` is `void` or
	/// `expired`): each coin it gave up is live again, unless the wallet
	/// signed a forfeit of it for a round that is not gone, which the
	/// operator could still claim. Such a coin stays given up, and the
	/// wallet follows its forfeit on the chain ([`Self::watch_forfeits`]); it
	/// can still be exited.
	fn give_back(&mut self, pid: &str, given: &[String], why: &str) -> Result<Value, Error> {
		let mut back = vec![];
		let mut held = vec![];
		for l in given {
			let Some(c) = self.store.coin(l)? else { continue };
			if !matches!(c.state.as_str(), "given" | "forfeited") {
				continue;
			}
			let open: Vec<String> = self.store.forfeits_of(l)?.into_iter().filter(|f| FOLLOWED.contains(&f.state.as_str()))
				.map(|f| f.round).collect();
			if open.is_empty() {
				back.push(l.clone());
			} else {
				held.push(json!({"leaf_id": l, "forfeit_for_round": open}));
			}
		}
		self.store.atomically(|s| {
			for l in &back {
				s.set_coin_state(l, "live", "")?;
			}
			s.set_participation(pid, why, None, None)
		})?;
		Ok(json!({"participation": pid, "state": why, "live_again": back, "held": held,
			"note": if held.is_empty() { "the server will not run it; its coins are live again".to_string() } else {
				"the server will not run it; a coin under a forfeit signed for a round still in the chain stays given up until that round \
				is gone or the forfeit is answered on the chain, and can be exited".to_string() }}))
	}

	/// The forfeit swap of an issued participation, once its round is final.
	///
	/// Nothing is signed until the status shows exactly the leaves the wallet
	/// asked for, in the order it asked for them, each rebuilt from the
	/// published tree and validated against the round, every one under the
	/// participation's one unlock hash, and the coins given up are exactly
	/// the participation's. Each coin's forfeit and release is then built
	/// against the new leaf of the coin's own asset.
	fn complete(&mut self, pid: &str, st: &Value, given: &[String], wanted: &Value) -> Result<Value, Error> {
		if st["participation_id"].as_str() != Some(pid) {
			return Err(Error::Refused(format!("the server answers for participation {}, not {}", st["participation_id"], pid)));
		}
		let round_txid = Txid::from_str(st["round"]["txid"].as_str().unwrap_or("")).map_err(|e| Error::Parse(e.to_string()))?;
		let finality = self.chain.finality(&round_txid)?;
		if !finality.is_final() {
			return Ok(json!({"participation": pid, "state": "issued", "round": round_txid.to_string(),
				"note": format!("the round is {}; the wallet signs nothing for it before it is final", finality.word())}));
		}
		let round = self.chain.transaction(&round_txid)?.ok_or_else(|| Error::Node(format!("the node does not have round {}", round_txid)))?;
		let now = self.now()?;
		let mut needs_fee_coin: Vec<String> = vec![];
		let unlock_hash = unhex32(st["unlock_hash"].as_str().unwrap_or(""))
			.map_err(|_| Error::Refused("the status names no unlock hash for the participation".into()))?;
		// The coins given up: exactly the participation's, each once.
		let inputs = st["inputs"].as_array().cloned().unwrap_or_default();
		if inputs.len() != given.len() || given.iter().any(|l| inputs.iter().filter(|i| i["leaf_id"].as_str() == Some(l.as_str())).count() != 1) {
			return Err(Error::Refused(format!("the status names {} coin(s) given up; the participation gives up exactly {}",
				inputs.len(), given.len())));
		}
		// Each new leaf, rebuilt from the published tree and validated
		// against the round before anything is signed for it: the leaves the
		// wallet asked for, all of them, in order, and nothing else.
		let mut news: Vec<(ValidLeaf, LeafRecord, [u8; 32])> = vec![];
		let wanted = wanted.as_array().cloned().unwrap_or_default();
		let outputs = st["outputs"].as_array().cloned().unwrap_or_default();
		if outputs.len() != wanted.len() {
			return Err(Error::Refused(format!("the status shows {} new leaf/leaves and the wallet asked for {}: it signs nothing \
				until every leaf it asked for is shown and checked", outputs.len(), wanted.len())));
		}
		for (j, (o, w)) in outputs.iter().zip(&wanted).enumerate() {
			if o["kind"].as_str() != Some("leaf") || o["asset"] != w["asset"] || o["value"] != w["value"] {
				return Err(Error::Refused(format!("the status's output {} is {} {} of {}; the wallet asked for a leaf of {} of {}", j,
					o["kind"], o["value"], o["asset"], w["value"], w["asset"])));
			}
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
			// The reserves, at four times the node's floor in the leaf's asset
			// when it accepts that asset for fees, one atom when it does not.
			let (accept, fee_coin) = self.leaf_policy(record.asset, now)?;
			if fee_coin {
				needs_fee_coin.push(record.asset.to_string());
			}
			let valid = record.validate(&round, &accept, &owner, &nonce)
				.map_err(|e| Error::Refused(format!("the new leaf in round {} fails the wallet's checks: {}", round_txid, e)))?;
			if record.asset.to_string() != w["asset"].as_str().unwrap_or("") || record.value.to_string() != w["value"].as_str().unwrap_or("") {
				return Err(Error::Refused(format!("the new leaf holds {} of {}; the wallet asked for {} of {}", record.value, record.asset,
					w["value"], w["asset"])));
			}
			if Some(valid.leaf_id.to_string().as_str()) != o["leaf_id"].as_str() {
				return Err(Error::Refused("the server names the new leaf by another id than its record gives".into()));
			}
			// One unlock hash opens every new leaf of the participation: a
			// forfeit can be claimed only by releasing all of them.
			if record.unlock_hash != unlock_hash {
				return Err(Error::Refused(format!("the new leaf in asset {} is locked to another unlock hash than the participation's \
					{}: a forfeit is claimable only by releasing every leaf the wallet asked for", record.asset, hex(&unlock_hash))));
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
		let mut signed = vec![];
		for l in given {
			let row = self.store.coin(l)?.ok_or_else(|| Error::Store(format!("coin {} is gone", l)))?;
			let (record, a) = self.held(&row)?;
			let old = &a.valid;
			let input = inputs.iter().find(|i| i["leaf_id"].as_str() == Some(l.as_str())).expect("checked above");
			let margin = amount(&input["margin"], "a forfeit's margin")?;
			// The new leaf of the coin's own asset.
			let new = &news.iter().find(|(_, r, _)| r.asset == old.asset)
				.ok_or_else(|| Error::Refused(format!("the participation has no new leaf in the asset of coin {}", l)))?.0;
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
			let f = Forfeit::for_refresh(old.leaf, (old.asset, old.value), old.id, new, &round, c, refund, margin)
				.map_err(|e| Error::Refused(format!("the forfeit of {}: {}", l, e)))?;
			let key = self.keys.leaf(&row.owner_nonce)?;
			forfeits.push(json!({"leaf_id": l, "signature": hex(sign(&key, &f.message().digest).as_ref())}));
			signed.push((l.clone(), margin));
			// A batch leaf's lowest node is released for this round alone: the
			// release names the round's connector asset, so it is void if the
			// round leaves the chain.
			if let (CoinRecord::Leaf { .. }, arca_covenant::ValidOrigin::Leaf { valid, .. }) = (&record, &old.origin) {
				if valid.branch.nodes.last().is_some_and(|n| n.reclaim.is_some()) {
					let rel = Release::for_refresh(valid, new, &round, c)
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
		// Before any forfeit leaves the wallet: each forfeit it signs, the
		// round it is bound to, and the new leaves it validated, so that it
		// can follow every forfeit on the chain and complete the leaves with a
		// preimage the chain publishes, whatever the server does next.
		let news_json = json!({"round": round_txid.to_string(), "leaves": news.iter().zip(&auths_of).map(|((_, record, nonce), auths)| {
			Ok(json!({"record": hex(&record.to_bytes().map_err(|e| Error::Refused(e.to_string()))?), "nonce": hex(nonce),
				"auths": auths.iter().map(|(s, t)| json!({"signature": hex(s.as_ref()), "time": t.to_consensus_u32()})).collect::<Vec<_>>()}))
		}).collect::<Result<Vec<_>, Error>>()?});
		let from_height = finality.height().unwrap_or(0).saturating_sub(100);
		self.store.put_tx(&round_txid.to_string(), &elements::encode::serialize(&round), "round")?;
		self.store.atomically(|s| {
			for (l, margin) in &signed {
				s.put_forfeit(&ForfeitRow {
					leaf_id: l.clone(), participation: pid.to_string(), round: round_txid.to_string(), connector_vout: c,
					unlock_hash: hex(&unlock_hash), refund_units: refund.units(), margin: *margin, from_height,
					state: "signed".into(), note: String::new(),
				})?;
				if s.coin(l)?.is_some_and(|c| c.state == "given") {
					s.set_coin_state(l, "forfeited", &format!("participation {}: its forfeit for round {} is signed", pid, round_txid))?;
				}
			}
			s.set_participation_news(pid, &news_json.to_string())?;
			s.set_participation(pid, "forfeiting", None, Some(&round_txid.to_string()))
		})?;
		let done = match self.server.post("forfeit_leaves", &json!({"participation_id": pid, "forfeits": forfeits, "leaves": leaves})) {
			Ok(d) => d,
			Err(e) => return Ok(json!({"participation": pid, "state": "forfeiting", "error": e.to_string(),
				"note": "the forfeits may have reached the server: the wallet follows each one's output on the chain"})),
		};
		let Some(pre) = done["preimage"].as_str() else {
			return Ok(json!({"participation": pid, "state": "forfeiting", "forfeit_first": done["forfeit_first"],
				"note": "forfeits in; the preimage is not out yet: the wallet follows each forfeit's output on the chain, takes the preimage \
				from a claim of it, and takes the refund when its delay passes with no claim"}));
		};
		let preimage = unhex32(pre)?;
		let kept = self.finish(pid, preimage, "settled")?;
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
		let mut out = json!({"participation": pid, "state": "released", "round": round_txid.to_string(), "new_leaves": kept, "released": released});
		if !needs_fee_coin.is_empty() {
			out["exit_needs_fee_coin"] = json!({"assets": needs_fee_coin, "note": FEE_COIN_NOTE});
		}
		Ok(out)
	}

	/// Completes participation `pid` with `preimage`: its new leaves, as the
	/// wallet validated them before signing its forfeits, opened and kept;
	/// the coins it gave up spent; its forfeits `how` (`settled` with the
	/// server's answer, `claimed` from a claim on the chain).
	pub(crate) fn finish(&mut self, pid: &str, preimage: [u8; 32], how: &str) -> Result<Vec<Value>, Error> {
		let news: Value = serde_json::from_str(&self.store.participation_news(pid)?
			.ok_or_else(|| Error::Store(format!("participation {} has no new leaves recorded", pid)))?)
			.map_err(|e| Error::Store(e.to_string()))?;
		let (given, round) = self.store.participations()?.into_iter().find(|p| p.0 == pid)
			.map(|p| (p.2, news["round"].as_str().unwrap_or("").to_string()))
			.ok_or_else(|| Error::Store(format!("no participation {}", pid)))?;
		let given: Vec<String> = serde_json::from_str(&given).map_err(|e| Error::Store(e.to_string()))?;
		let now = self.now()?;
		let mut kept = vec![];
		for n in news["leaves"].as_array().cloned().unwrap_or_default() {
			let record = LeafRecord::from_bytes(&unhex(n["record"].as_str().unwrap_or(""))?).map_err(|e| Error::Store(e.to_string()))?;
			let nonce = unhex32(n["nonce"].as_str().unwrap_or(""))?;
			if sha256::Hash::hash(&preimage).to_byte_array() != record.unlock_hash {
				return Err(Error::Refused("the preimage does not open the new leaves".into()));
			}
			let mut auths = vec![];
			for a in n["auths"].as_array().cloned().unwrap_or_default() {
				let sig = elements::secp256k1_zkp::schnorr::Signature::from_slice(&unhex(a["signature"].as_str().unwrap_or(""))?)
					.map_err(|e| Error::Store(e.to_string()))?;
				let t = MedianTime::from_consensus(a["time"].as_u64().unwrap_or(0) as u32).map_err(|e| Error::Store(e.to_string()))?;
				auths.push((sig, t));
			}
			let coin = CoinRecord::Leaf { record: record.clone(), preimage, auths };
			let a = self.assess(&coin, &self.receipt_policy(now), Some((&record.owner, &nonce)))?;
			let row = self.row(&coin, &a, if a.all_final() { "live" } else { "pending" }, "")?;
			if self.store.coin(&row.leaf_id)?.is_none() {
				let id = row.leaf_id.clone();
				self.store.atomically(|s| {
					s.put_coin(&row)?;
					s.use_nonce(&nonce, &id)
				})?;
			}
			kept.push(json!({"leaf_id": row.leaf_id, "asset": record.asset.to_string(), "value": record.value.to_string(),
				"expiry": record.schedule.expiries()[0].to_consensus_u32()}));
		}
		self.store.atomically(|s| {
			for l in &given {
				s.set_coin_spent(l, &format!("participation {}", pid))?;
				s.set_forfeit_state(l, &round, how, "")?;
			}
			s.set_participation(pid, "released", Some(&hex(&preimage)), Some(&round))
		})?;
		Ok(kept)
	}
}

impl Wallet {
	/// The forfeit the wallet signed, as `f` records it, of the coin `row`.
	pub(crate) fn forfeit_of(&self, row: &super::store::CoinRow, f: &ForfeitRow) -> Result<Forfeit, Error> {
		let record = Self::record_of(row)?;
		let policy = WalletPolicy { horizon: 0, ..self.receipt_policy(self.now()?) };
		let coin = record.resolve(&self.accepted_bases(&record)?, &policy).map_err(|e| Error::Refused(e.to_string()))?;
		let round = Txid::from_str(&f.round).map_err(|e| Error::Store(e.to_string()))?;
		let refund = RelativeTime::from_units(f.refund_units).map_err(|e| Error::Store(e.to_string()))?;
		Forfeit::new(coin.leaf, (coin.asset, coin.value), coin.id, unhex32(&f.unlock_hash)?, connector_asset(round, f.connector_vout), refund, f.margin)
			.map_err(|e| Error::Refused(e.to_string()))
	}

	/// Follows on the chain every forfeit the wallet signed whose output's
	/// fate is not yet decided, whatever the server says of it, until a spend
	/// of that output is final: a claim of the output publishes the preimage,
	/// which completes the new leaves at once, whatever the wallet broadcast
	/// itself; an output left unclaimed until the refund delay has run since
	/// it confirmed is the wallet's to refund, and the coin is the wallet's
	/// on the chain once that refund is final; a forfeit never published,
	/// whose round can never return, is void, and its coin is the wallet's
	/// again. A refund in the mempool, or a claim in a block not yet final,
	/// decides nothing: the other may still take the output.
	///
	/// A forfeit decided by a final spend is followed still, until the new
	/// leaves' batch has expired: Sequentia reorganises whenever its Bitcoin
	/// anchor does, with no depth limit, so a rollback can take a final
	/// refund or claim out, and the operator's claim can then confirm in
	/// place of the wallet's refund. When the spend that decided a forfeit is
	/// no longer final, the forfeit is undecided again and the chain decides
	/// it again ([`Self::recheck_decided`]).
	pub(crate) fn watch_forfeits(&mut self) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		for state in DECIDED {
			for f in self.store.forfeits_in(state)? {
				match self.recheck_decided(&f) {
					Ok(Some(v)) => out.push(v),
					Ok(None) => {},
					Err(e) => out.push(json!({"leaf_id": f.leaf_id, "round": f.round, "error": e.to_string()})),
				}
			}
		}
		let mut followed = vec![];
		for state in FOLLOWED {
			followed.extend(self.store.forfeits_in(state)?);
		}
		for f in followed {
			match self.watch_forfeit(&f) {
				Ok(Some(v)) => out.push(v),
				Ok(None) => {},
				Err(e) => out.push(json!({"leaf_id": f.leaf_id, "round": f.round, "error": e.to_string()})),
			}
		}
		Ok(out)
	}

	/// Whether the new leaves of participation `pid` have expired: the
	/// median time is past the last expiry of every batch they are in, after
	/// which no preimage opens anything. A participation with no new leaves
	/// recorded has not.
	fn new_leaves_expired(&self, pid: &str) -> Result<bool, Error> {
		let Some(news) = self.store.participation_news(pid)? else { return Ok(false) };
		let news: Value = serde_json::from_str(&news).map_err(|e| Error::Store(e.to_string()))?;
		let mut last = 0u32;
		for n in news["leaves"].as_array().cloned().unwrap_or_default() {
			let record = LeafRecord::from_bytes(&unhex(n["record"].as_str().unwrap_or(""))?).map_err(|e| Error::Store(e.to_string()))?;
			last = last.max(record.schedule.expiries().last().map(|e| e.to_consensus_u32()).unwrap_or(u32::MAX));
		}
		Ok(last != 0 && self.now()?.to_consensus_u32() > last)
	}

	/// A forfeit decided by a final spend of its output (`refunded`, or
	/// `claimed` with the claim's txid recorded), looked at again until the
	/// new leaves' batch has expired: when that spend is no longer final (a
	/// rollback took its block out, however deep, or left it uncertified or
	/// its anchor unburied), the forfeit goes back to undecided (`refunding`,
	/// `claiming`) and the coin of a refund back under its forfeit, so the
	/// chain decides again: a claim that confirms in the refund's place
	/// publishes the preimage, which completes the new leaves.
	pub(crate) fn recheck_decided(&mut self, f: &ForfeitRow) -> Result<Option<Value>, Error> {
		let Ok(spend) = Txid::from_str(&f.note) else { return Ok(None) };
		if self.new_leaves_expired(&f.participation)? {
			return Ok(None);
		}
		let finality = self.chain.finality(&spend)?;
		if finality.is_final() {
			return Ok(None);
		}
		let (what, back) = if f.state == "refunded" { ("refund", "refunding") } else { ("claim", "claiming") };
		let why = format!("the {} {} that decided its forfeit is {} now: a rollback took it out of the final chain, and the wallet \
			follows the forfeit's output until a spend of it is final again", what, spend, finality.word());
		self.store.atomically(|s| {
			s.set_forfeit_state(&f.leaf_id, &f.round, back, &spend.to_string())?;
			if f.state == "refunded" && s.coin(&f.leaf_id)?.is_some_and(|c| c.state == "exited") {
				s.set_coin_state(&f.leaf_id, "forfeited", &why)?;
			}
			Ok(())
		})?;
		Ok(Some(json!({"leaf_id": f.leaf_id, "round": f.round, "state": back, "was": f.state, "note": why})))
	}

	/// [`Self::watch_forfeits`] for one forfeit, its outcome for people.
	pub(crate) fn watch_forfeit_now(&mut self, f: &ForfeitRow) -> Value {
		match self.watch_forfeit(f) {
			Ok(Some(v)) => v,
			Ok(None) => json!({"leaf_id": f.leaf_id, "round": f.round, "state": "signed"}),
			Err(e) => json!({"leaf_id": f.leaf_id, "round": f.round, "error": e.to_string()}),
		}
	}

	fn watch_forfeit(&mut self, f: &ForfeitRow) -> Result<Option<Value>, Error> {
		let row = self.store.coin(&f.leaf_id)?.ok_or_else(|| Error::Store(format!("no coin {}", f.leaf_id)))?;
		let forfeit = self.forfeit_of(&row, f)?;
		let out = forfeit.output().txout();
		// Published and unspent: the refund, once its delay has run (again,
		// when a refund the wallet sent left the mempool or a block).
		if let Some(at) = self.chain.locate(std::slice::from_ref(&out))?[0] {
			return self.refund_forfeit(f, &forfeit, at, &row).map(Some);
		}
		// Published and spent: by a claim, which publishes the preimage, or by
		// the wallet's own refund. Only a final spend decides the coin.
		if let Some((ftx, h)) = self.chain.find_payment(&out, f.from_height)? {
			let vout = ftx.output.iter().position(|o| *o == out).expect("pays it") as u32;
			let at = OutPoint::new(ftx.txid(), vout);
			if let Some((spender, _)) = self.chain.spender(&at, h)? {
				let spent_by = spender.txid();
				let finality = self.chain.finality(&spent_by)?;
				let unlock = unhex32(&f.unlock_hash)?;
				let preimage = spender.input.iter().filter(|i| i.previous_output == at).flat_map(|i| i.witness.script_witness.iter())
					.find(|w| w.len() == 32 && sha256::Hash::hash(w).to_byte_array() == unlock)
					.map(|w| <[u8; 32]>::try_from(w.as_slice()).expect("32 bytes"));
				if let Some(pre) = preimage {
					// The preimage is the wallet's from the moment it is seen,
					// whatever becomes of the claim: the new leaves are kept.
					let state = if finality.is_final() { "claimed" } else { "claiming" };
					let kept = self.finish(&f.participation, pre, state)?;
					// The claim is what decided this forfeit: followed while its
					// new leaves' batch lives.
					self.store.set_forfeit_state(&f.leaf_id, &f.round, state, &spent_by.to_string())?;
					return Ok(Some(json!({"leaf_id": f.leaf_id, "round": f.round, "state": state, "claim": spent_by.to_string(),
						"finality": finality.word(),
						"note": "the operator claimed the forfeit on the chain, which publishes the preimage: the new leaves are the wallet's",
						"new_leaves": kept})));
				}
				if finality.is_final() {
					self.store.atomically(|s| {
						s.set_forfeit_state(&f.leaf_id, &f.round, "refunded", &spent_by.to_string())?;
						s.set_coin_state(&f.leaf_id, "exited", &format!("its forfeit's output refunded by {}, final", spent_by))
					})?;
					return Ok(Some(json!({"leaf_id": f.leaf_id, "round": f.round, "state": "refunded", "refund": spent_by.to_string()})));
				}
				let why = format!("its forfeit's output is spent by the refund {}, which is {}: the wallet follows the output until a \
					spend of it is final, the refund or the operator's claim", spent_by, finality.word());
				self.store.atomically(|s| {
					s.set_forfeit_state(&f.leaf_id, &f.round, "refunding", &spent_by.to_string())?;
					if s.coin(&f.leaf_id)?.is_some_and(|c| c.state != "spent") {
						s.set_coin_state(&f.leaf_id, "forfeited", &why)?;
					}
					Ok(())
				})?;
				return Ok(Some(json!({"leaf_id": f.leaf_id, "round": f.round, "state": "refunding", "refund": spent_by.to_string(),
					"finality": finality.word(), "note": why})));
			}
		}
		// Never published: void once its round can never return.
		if f.state != "signed" {
			return Ok(None);
		}
		if let Some(raw) = self.store.tx(&f.round)? {
			let round: Transaction = elements::encode::deserialize(&raw).map_err(|e| Error::Store(e.to_string()))?;
			if self.chain.gone(&round)? {
				let why = format!("round {} can never return, so its forfeit can never be claimed: the coin is the wallet's again", f.round);
				self.store.set_forfeit_state(&f.leaf_id, &f.round, "void", &why)?;
				let open = self.store.forfeits_of(&f.leaf_id)?.iter().any(|x| FOLLOWED.contains(&x.state.as_str()));
				if !open && matches!(row.state.as_str(), "forfeited" | "spent") {
					self.store.set_coin_state(&f.leaf_id, "live", &why)?;
				}
				return Ok(Some(json!({"leaf_id": f.leaf_id, "round": f.round, "state": "void", "note": why})));
			}
		}
		Ok(None)
	}

	/// The owner's refund of the forfeit output at `at`, once the refund
	/// delay has run from its confirmation, to an address of the wallet's.
	fn refund_forfeit(&mut self, f: &ForfeitRow, forfeit: &Forfeit, at: OutPoint, row: &super::store::CoinRow) -> Result<Value, Error> {
		let base = json!({"leaf_id": f.leaf_id, "round": f.round, "forfeit": at.to_string()});
		if !self.chain.finality(&at.txid)?.in_chain() {
			let mut v = base;
			v["state"] = json!("published");
			v["note"] = json!("the operator's forfeit of the coin is in the mempool: its refund delay runs once it is in a block");
			return Ok(v);
		}
		let key = self.keys.leaf(&row.owner_nonce)?;
		let index_key = format!("refund_index_{}_{}", f.leaf_id, f.round);
		let index = match self.store.meta(&index_key)?.and_then(|v| v.parse().ok()) {
			Some(i) => i,
			None => {
				let i = self.store.take_index(super::keys::RECEIVE)?;
				self.store.set_meta(&index_key, &i.to_string())?;
				i
			},
		};
		let to = self.keys.onchain_script(super::keys::RECEIVE, index)?;
		let (asset, value) = (forfeit.asset, forfeit.value - forfeit.margin);
		let mut payer = super::exit::Payer::new(None);
		let built = self.key_spend(&mut payer, &key, &|fs| {
			let out = match fs {
				FeeSource::Coin { .. } => ExplicitOutput::new(asset, value, to.clone()),
				_ => {
					let fee = self.fee_for(asset, 220)?;
					if fee >= value {
						return Err(Error::Refused(format!("the forfeit's {} atoms do not cover its refund's fee", value)));
					}
					ExplicitOutput::new(asset, value - fee, to.clone())
				},
			};
			forfeit.refund(at, &[out], fs).map_err(|e| Error::Refused(e.to_string()))
		});
		let mut v = base;
		match built.and_then(|u| self.chain.broadcast(&u.tx).map(|txid| (txid, u))) {
			Ok((txid, u)) => {
				// Sent, which decides nothing: the operator's claim may still
				// take the output. The wallet follows it until a spend is final.
				let why = format!("its forfeit's refund {} is sent: the wallet follows the forfeit's output until a spend of it is \
					final, the refund or the operator's claim", txid);
				self.store.atomically(|s| {
					s.set_forfeit_state(&f.leaf_id, &f.round, "refunding", &txid.to_string())?;
					if s.coin(&f.leaf_id)?.is_some_and(|c| c.state != "spent") {
						s.set_coin_state(&f.leaf_id, "forfeited", &why)?;
					}
					Ok(())
				})?;
				v["state"] = json!("refunding");
				v["refund"] = json!({"txid": txid.to_string(), "vsize": u.tx.vsize(), "pays": u.tx.output[0].value.explicit().map(|x| x.to_string())});
				v["note"] = json!(why);
			},
			Err(e) if e.to_string().contains("non-BIP68-final") => {
				v["state"] = json!("published");
				v["note"] = json!(format!("the operator published the coin's forfeit and has not claimed it; the wallet takes the refund once \
					{} s have run from its confirmation", forfeit.policy.refund_delay.seconds()));
			},
			Err(e) => {
				v["state"] = json!("published");
				v["error"] = json!(e.to_string());
			},
		}
		Ok(v)
	}
}

/// The states of a forfeit whose output's fate is not decided yet, which the
/// wallet follows on the chain: `signed` (its preimage not in hand, the
/// output unpublished or unspent), `refunding` (spent by the wallet's
/// refund, not yet final), `claiming` (spent by the operator's claim, not yet
/// final; the preimage is in hand).
pub(crate) const FOLLOWED: [&str; 3] = ["signed", "refunding", "claiming"];

/// The states of a forfeit decided by a final spend of its output, which the
/// wallet still looks at until its new leaves' batch has expired: `refunded`
/// (the wallet's refund final), `claimed` (the operator's claim final). A
/// rollback that leaves that spend not final makes it undecided again.
pub(crate) const DECIDED: [&str; 2] = ["refunded", "claimed"];

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_fee_is_bounded_in_millionths_of_its_coin() {
		assert!(fee_within(20_000, 2_000_000, DEFAULT_MAX_FEE_PPM));
		assert!(!fee_within(20_001, 2_000_000, DEFAULT_MAX_FEE_PPM));
		assert!(!fee_within(1_000_000, 2_000_000, DEFAULT_MAX_FEE_PPM));
		assert!(fee_within(1_000_000, 2_000_000, 500_000));
		// Nothing at all in the free window, unless raised.
		assert!(fee_within(0, 2_000_000, 0));
		assert!(!fee_within(1, 2_000_000, 0));
		// No overflow at the extremes.
		assert!(fee_within(u64::MAX, u64::MAX, 1_000_000));
		assert!(!fee_within(u64::MAX, 1, u64::MAX / 2));
		assert_eq!(ppm_of(1_000_000, 2_000_000), 500_000);
	}

	#[test]
	fn the_free_window_is_the_two_days_before_the_exit_deadline() {
		let e = 2_000_000_000u32;
		let deadline = WalletPolicy::EXIT_DEADLINE;
		assert!(!in_free_window(e, e - deadline - FREE_WINDOW - 1));
		assert!(in_free_window(e, e - deadline - FREE_WINDOW));
		assert!(in_free_window(e, e - deadline));
		// A coin with no expiry known yet: a board in no block.
		assert!(!in_free_window(u32::MAX, e));
	}

	#[test]
	fn a_published_fee_above_the_coin_is_capped_not_wrapped() {
		let fees = json!({"refresh_ppm": u64::MAX, "free_window_seconds": 0, "full_after_seconds": 1});
		let fee = refresh_fee(&fees, 2_000_000, u32::MAX, 0);
		assert!(fee > 2_000_000);
		assert!(!fee_within(fee, 2_000_000, DEFAULT_MAX_FEE_PPM));
		assert!(2_000_000u64.checked_sub(fee).is_none());
	}
}
