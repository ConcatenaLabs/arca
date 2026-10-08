//! Taking part in a round: the refresh.
//!
//! One request per asset, never interactive: a round carries one asset, so
//! the wallet refreshes each asset's coins in that asset's rounds. A request
//! names the coins given up, each attested by its key, the leaf wanted (under
//! a fresh key) and the fee the operator's schedule asks, in the coins' own
//! asset. Then, once the
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
use super::client::{key_proof_digest, participation_id, Wanted};
use super::pay::MARGIN_MULTIPLE;
use super::wallet::{amount, sign, Wallet};
use super::Error;

/// The operator's refresh fee for a coin of `value` whose earliest expiry is
/// `expiry`, at `now`, by the schedule `fees` ([`schedule_of`]): its parts
/// per million of the coin and its fixed part a coin, both falling to
/// nothing in the free window.
pub fn refresh_fee(fees: &Value, value: u64, expiry: u32, now: u32) -> u64 {
	let ppm = fees["refresh_ppm"].as_u64().unwrap_or(0) as u128;
	let base = fees["refresh_base"].as_str().and_then(|b| b.parse::<u64>().ok()).unwrap_or(0) as u128;
	let free = fees["free_window_seconds"].as_u64().unwrap_or(0) as u32;
	let full = fees["full_after_seconds"].as_u64().unwrap_or(1).max(1) as u32;
	let left = expiry.saturating_sub(now).saturating_sub(free);
	let charged = left.min(full) as u128;
	((value as u128 * ppm + base * 1_000_000) * charged).div_ceil(full as u128 * 1_000_000).min(u64::MAX as u128) as u64
}

/// The schedule the operator charges in `asset` by what `info` publishes:
/// the asset's own (`assets[].fees`), with the free window `fees` states,
/// or, from an operator that publishes none for the asset, the one at the
/// top of `fees`.
pub fn schedule_of(info: &Value, asset: AssetId) -> Value {
	let mut s = info["fees"].clone();
	let own = info["assets"].as_array().into_iter().flatten().find(|a| a["asset"].as_str() == Some(&asset.to_string()))
		.map(|a| a["fees"].clone()).unwrap_or(Value::Null);
	if let Some(o) = own.as_object() {
		for (k, v) in o {
			s[k] = v.clone();
		}
	}
	s
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
	/// The asset of each coin of `rows`.
	assets: Vec<AssetId>,
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
	let tree = Tree::build(params, &leaves).map_err(|e| Error::Refused(format!("the published tree does not build: {}", e)))?;
	check_published(t, &tree)?;
	Ok(tree)
}

/// What a published tree says beyond the parts it is built from, against
/// the tree the wallet built from those parts: every node it lists (its
/// value, reserve, script and children, level by level), each leaf's id and
/// script, and each preimage it publishes, which must open its leaf's
/// unlock hash. The wallet takes the operator's word for none of it: a tree
/// that says one thing and builds to another is refused.
fn check_published(t: &Value, tree: &Tree) -> Result<(), Error> {
	let wrong = |what: String| Error::Refused(format!("the published tree is not the tree its parts build: {}", what));
	if let Some(levels) = t["nodes"].as_array() {
		if levels.len() != tree.levels().len() {
			return Err(wrong(format!("it lists {} levels of nodes, its parts build {}", levels.len(), tree.levels().len())));
		}
		for (k, (shown, built)) in levels.iter().zip(tree.levels()).enumerate() {
			let shown = shown.as_array().cloned().unwrap_or_default();
			if shown.len() != built.len() {
				return Err(wrong(format!("level {} lists {} nodes, its parts build {}", k, shown.len(), built.len())));
			}
			for (j, (n, b)) in shown.iter().zip(built).enumerate() {
				let same = n["value"].as_str() == Some(&b.value.to_string()) && n["reserve"].as_str() == Some(&b.reserve.to_string())
					&& n["script_pubkey"].as_str() == Some(&hex(b.output().script_pubkey.as_bytes()))
					&& n["children"] == json!([b.children.start, b.children.end]);
				if !same {
					return Err(wrong(format!("node {} of level {} is listed as {}", j, k, n)));
				}
			}
		}
	}
	let shown = t["leaves"].as_array().cloned().unwrap_or_default();
	for (i, (l, r)) in shown.iter().zip(tree.records()).enumerate() {
		if let Some(id) = l["leaf_id"].as_str() {
			let built = r.leaf_id().map_err(|e| Error::Refused(e.to_string()))?;
			if id != built.to_string() {
				return Err(wrong(format!("leaf {} is named {}, its parts make it {}", i, id, built)));
			}
		}
		if let Some(spk) = l["script_pubkey"].as_str() {
			if spk != hex(tree.leaves()[i].leaf.script_pubkey().as_bytes()) {
				return Err(wrong(format!("leaf {}'s script is listed as {}", i, spk)));
			}
		}
		if let Some(p) = l["preimage"].as_str() {
			let p = unhex32(p)?;
			if sha256::Hash::hash(&p).to_byte_array() != r.unlock_hash {
				return Err(wrong(format!("the preimage published for leaf {} does not open its unlock hash", i)));
			}
		}
	}
	Ok(())
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
		let mut assets = vec![];
		let mut coins = vec![];
		for r in &rows {
			let (record, a) = self.held(r)?;
			if !a.all_final() {
				return Err(Error::Refused(format!("coin {} is not final: {}", r.leaf_id, a.waiting())));
			}
			// A coin resting on a board counts from the board's dates, and is
			// taken into a refresh until its exit deadline, three days before
			// the board's expiry.
			let (value, expiry) = (a.valid.value, self.service_expiry(&record, &a)?);
			if let Some(b) = self.board_expiry(&record, &a.bases)? {
				if now.to_consensus_u32() as u64 + WalletPolicy::EXIT_DEADLINE as u64 >= b as u64 {
					return Err(Error::Refused(format!("coin {} rests on a board whose service ends at median time {}: the operator takes \
						it into a refresh only until its exit deadline, three days before; exit it", r.leaf_id, b)));
				}
			}
			let schedule = schedule_of(&info, a.valid.asset);
			let fee = refresh_fee(&schedule, value, expiry, now.to_consensus_u32());
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
			assets.push(a.valid.asset);
			coins.push(json!({"leaf_id": r.leaf_id, "asset": a.valid.asset.to_string(), "value": value.to_string(), "fee": fee.to_string(),
				"ppm": ppm_of(fee, value), "free_window": free, "bound_ppm": bound,
				"schedule": {"refresh_ppm": schedule["refresh_ppm"], "refresh_base": schedule["refresh_base"]}}));
		}
		for (asset, (total, fee)) in &per {
			let value = total.checked_sub(*fee).ok_or_else(|| Error::Refused(format!("the refresh fee of {} in asset {} is more than the \
				coins hold, {}", fee, asset, total)))?;
			let min = Self::min_leaf(&info, *asset)?;
			if value < min {
				return Err(Error::Refused(format!("the new leaf in asset {} would hold {}, below the operator's smallest leaf {}", asset, value, min)));
			}
		}
		Ok(RefreshQuote { info, rows, ids, assets, per, coins })
	}

	/// Gives up the coins of `quote` for a new leaf in each asset, in one
	/// participation per asset: a round carries one asset, so each asset's
	/// coins are refreshed in that asset's rounds. Each pays the fee the quote
	/// states in its own asset. Not before median time `not_before`, when
	/// given. Answers each participation (`participations`), one the server
	/// refused or did not take now with its `error` (one not taken stands,
	/// and sync posts it again); it is an error only when none was taken.
	pub fn participate(&mut self, quote: RefreshQuote, not_before: Option<u32>) -> Result<Value, Error> {
		let RefreshQuote { info, rows, ids, assets, per, coins } = quote;
		let mut out = vec![];
		let mut first_error = None;
		for (asset, (total, fee)) in &per {
			let mine: Vec<usize> = (0..rows.len()).filter(|k| assets[*k] == *asset).collect();
			let rows: Vec<&super::store::CoinRow> = mine.iter().map(|k| &rows[*k]).collect();
			let ids: Vec<arca_covenant::LeafId> = mine.iter().map(|k| ids[*k]).collect();
			match self.participate_in(&info, *asset, *total, *fee, &rows, &ids, not_before) {
				Ok(v) => out.push(v),
				Err(e) => {
					let mut entry = json!({"asset": asset.to_string(), "gives": rows.iter().map(|r| r.leaf_id.clone()).collect::<Vec<_>>(),
						"error": e.to_string()});
					// Not taken now, and not refused: it stands, its coins
					// given, and sync posts it again. A refusal gives its
					// coins back. Every other asset's goes on either way.
					entry["note"] = json!(match e {
						Error::Unreachable(_) => self.spelling.say("not taken now: it stands, and {sync} posts it again"),
						_ => "refused: its coins are the wallet's again, live".into(),
					});
					out.push(entry);
					first_error.get_or_insert(e);
				},
			}
		}
		if let Some(e) = first_error {
			if out.iter().all(|p| p.get("error").is_some()) {
				return Err(e);
			}
		}
		Ok(json!({"participations": out, "quote": coins}))
	}

	/// Gives up `rows`, all of `asset` and worth `total`, for one new leaf of
	/// `asset` in a round, paying `fee` of it.
	#[allow(clippy::too_many_arguments)]
	fn participate_in(&mut self, info: &Value, asset: AssetId, total: u64, fee: u64, rows: &[&super::store::CoinRow],
		ids: &[arca_covenant::LeafId], not_before: Option<u32>) -> Result<Value, Error>
	{
		let needs_fee_coin = self.chain.floor_per_kvb(asset)?.is_none();
		let value = total.checked_sub(fee).ok_or_else(|| Error::Refused("the refresh fee is more than the coins hold".into()))?;
		let min = Self::min_leaf(info, asset)?;
		if value < min {
			return Err(Error::Refused(format!("the new leaf in asset {} would hold {}, below the operator's smallest leaf {}", asset, value, min)));
		}
		let nonce = super::random32();
		let owner = self.keys.leaf_xonly(&nonce)?;
		self.store.put_nonce(&nonce, &owner.serialize(), "refresh")?;
		let wanted = vec![Wanted::Leaf { asset, value, template: Template::Vtxo1, owner, owner_nonce: nonce, exit_delay: self.exit_delay() }];
		let nonces = vec![json!({"nonce": hex(&nonce), "asset": asset.to_string(), "value": value.to_string()})];
		let fees: Vec<(AssetId, u64)> = if fee > 0 { vec![(asset, fee)] } else { vec![] };
		let nb = not_before.map(MedianTime::from_consensus).transpose().map_err(|e| Error::Refused(e.to_string()))?;
		let id = participation_id(&self.genesis, &self.operator, ids, &wanted, &fees, nb);
		let mut inputs = vec![];
		for r in rows {
			let key = self.keys.leaf(&r.owner_nonce)?;
			inputs.push(json!({"leaf_id": r.leaf_id, "attestation": hex(sign(&key, &id).as_ref())}));
		}
		// Each leaf wanted under a key the wallet holds, and proves it holds.
		let mut outputs = vec![];
		for w in &wanted {
			let Wanted::Leaf { owner_nonce, .. } = w;
			let key = self.keys.leaf(owner_nonce)?;
			let mut j = w.json();
			j["leaf"]["key_proof"] = json!(hex(sign(&key, &key_proof_digest(&id)).as_ref()));
			// The new leaf is re-served to the wallet's mailbox key, which a
			// wallet restored from the mnemonic reads with; the binding is not
			// part of the participation's id.
			let (mailbox, proof) = self.binding(&key)?;
			j["leaf"]["mailbox"] = json!(mailbox);
			j["leaf"]["mailbox_proof"] = json!(proof);
			outputs.push(j);
		}
		let mut body = json!({
			"inputs": inputs, "outputs": outputs,
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
		let answer = match self.submit(&pid, &body, &given) {
			Ok(a) => a,
			// Not taken now and not refused (the server busy or unreachable,
			// or taking no new work in the asset while its rate is stale):
			// the participation stands, its coins given, and sync posts it
			// again.
			Err(Error::Unreachable(why)) => return Err(Error::Unreachable(format!("participation {}: {}", pid, why))),
			Err(e) => return Err(e),
		};
		let mut out = json!({"participation": pid, "asset": asset.to_string(), "state": answer["state"], "gives": given, "wants": nonces,
			"fees": fees.iter().map(|(a, v)| json!({"asset": a.to_string(), "amount": v.to_string()})).collect::<Vec<_>>()});
		if needs_fee_coin {
			out["exit_needs_fee_coin"] = json!({"assets": [asset.to_string()], "note": FEE_COIN_NOTE});
		}
		Ok(out)
	}

	/// Every participation the wallet made, from its own store, oldest
	/// first, asking nothing of the operator: its id, where it stands, the
	/// round it ran in (its transaction id, once known), whether it was
	/// released, each coin it gave up and each new leaf it wanted, with the
	/// state of each the wallet holds. `sync` reports a release once; a
	/// client that missed that report asks here, as often as it likes.
	pub fn participations(&self) -> Result<Value, Error> {
		let mut out = vec![];
		for (pid, _, given, wanted, state, preimage, round) in self.store.participations()? {
			let given: Vec<String> = serde_json::from_str(&given).map_err(|e| Error::Store(e.to_string()))?;
			let wanted: Value = serde_json::from_str(&wanted).map_err(|e| Error::Store(e.to_string()))?;
			let mut gives = vec![];
			for l in &given {
				let c = self.store.coin(l)?;
				gives.push(json!({"leaf_id": l, "state": c.map(|c| c.state)}));
			}
			let mut new_leaves = vec![];
			for w in wanted.as_array().cloned().unwrap_or_default() {
				let leaf = match w["nonce"].as_str().and_then(|n| unhex32(n).ok()) {
					Some(n) => self.store.nonce(&n)?.and_then(|r| r.leaf_id),
					None => None,
				};
				let coin = match &leaf {
					Some(l) => self.store.coin(l)?,
					None => None,
				};
				new_leaves.push(json!({"asset": w["asset"], "value": w["value"], "leaf_id": leaf, "state": coin.map(|c| c.state)}));
			}
			out.push(json!({"participation": pid, "state": state, "round": round, "released": preimage.is_some(), "gives": gives,
				"new_leaves": new_leaves}));
		}
		Ok(Value::Array(out))
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
				s @ ("void" | "expired") => out.push(self.give_back(&pid, &given, s, &st)?),
				_ if state == "withdrawn" => out.push(json!({"participation": pid, "state": "withdrawn",
					"note": "the wallet is taking a coin of it on-chain, and signs nothing for it"})),
				"pending" => out.push(json!({"participation": pid, "state": "pending", "note": "waiting for a round"})),
				// A coin of it on its way home on the chain: its forfeits are
				// not handed over again (the server would refuse them, the coin
				// being on the chain). Once the operator releases the
				// participation, which it does once it holds them whole or
				// claims one, the wallet takes the published preimage.
				"issued" if given.iter().any(|l| self.store.coin(l).ok().flatten().is_some_and(|c| c.state == "exiting")) => {
					out.push(json!({"participation": pid, "state": "issued", "note": "a coin of it is on its way home on the chain: the \
						wallet hands its forfeits over no more, and takes the new leaves once the operator releases the participation"}));
				},
				"issued" | "released" => {
					// Released by the server once it held the forfeits the wallet
					// handed over before: nothing is signed for it again.
					if st["state"] == "released" {
						match self.take_released(&pid, &st, &given) {
							Ok(Some(v)) => {
								out.push(v);
								continue;
							},
							Ok(None) => {},
							Err(e) => {
								self.store.refused(&format!("participation {}", pid), &e.to_string())?;
								out.push(json!({"participation": pid, "state": st["state"], "refused": e.to_string()}));
								continue;
							},
						}
					}
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
	/// `expired`), and `st` is its status: each coin it gave up that the
	/// operator gave back (`returned`) is live again. Any other is held
	/// under a forfeit the wallet signed: one for a round that is not gone,
	/// which the operator could still claim, or one the operator published,
	/// or handed to the node, for a round that is lost, which may
	/// still confirm (the status's `void_reason` says so). The coin stays
	/// given up, `forfeited`: the wallet follows its forfeit on the chain
	/// ([`Self::watch_forfeits`]) and refunds it once its delay has run, and
	/// a coin whose forfeit is for a lost round and is not
	/// on the chain is taken on the chain at once, by its exit, whichever of
	/// the two confirms first. An operator that does not say which coins it
	/// gave back is taken to give back every coin with no forfeit open.
	fn give_back(&mut self, pid: &str, given: &[String], why: &str, st: &Value) -> Result<Value, Error> {
		let reason = st["void_reason"].as_str().map(str::to_string);
		let mut back = vec![];
		let mut held = vec![];
		for l in given {
			let Some(c) = self.store.coin(l)? else { continue };
			if !matches!(c.state.as_str(), "given" | "forfeited") {
				continue;
			}
			let followed: Vec<ForfeitRow> = self.store.forfeits_of(l)?.into_iter().filter(|f| FOLLOWED.contains(&f.state.as_str())).collect();
			let returned = st["inputs"].as_array().and_then(|a| a.iter().find(|i| i["leaf_id"].as_str() == Some(l.as_str())))
				.and_then(|i| i["returned"].as_bool());
			// A forfeit the wallet found void (never published, its round
			// gone) is followed again for a coin the operator keeps given up:
			// the operator holds it whole, and it may still confirm.
			let mut open = followed.clone();
			if returned == Some(false) {
				for f in self.store.forfeits_of(l)? {
					if f.state == "void" && self.round_gone(&f)? {
						open.push(f);
					}
				}
			}
			if returned.unwrap_or(followed.is_empty()) {
				back.push(l.clone());
			} else {
				held.push((l.clone(), open));
			}
		}
		let note = match &reason {
			Some(r) => format!("the server will not run participation {}: {}", pid, r),
			None => format!("the server will not run participation {}", pid),
		};
		self.store.atomically(|s| {
			for l in &back {
				s.set_coin_state(l, "live", "")?;
			}
			for (l, open) in &held {
				s.set_coin_state(l, "forfeited", &format!("{}; the coin is held under its forfeit, and is the wallet's on the chain, \
					by that forfeit's refund or its exit", note))?;
				for f in open.iter().filter(|f| f.state == "void") {
					s.set_forfeit_state(l, &f.round, "signed", "the operator keeps the coin given up under this forfeit: followed until \
						the coin's exit or this forfeit's refund is final")?;
				}
			}
			s.set_participation(pid, why, None, None)
		})?;
		let mut out_held = vec![];
		for (l, open) in &held {
			let mut h = json!({"leaf_id": l, "forfeit_for_round": open.iter().map(|f| f.round.clone()).collect::<Vec<_>>()});
			// A forfeit for a lost round, not on the chain:
			// the coin goes on the chain at once by its exit.
			let mut exit = !open.is_empty();
			for f in open {
				let row = self.store.coin(l)?.ok_or_else(|| Error::Store(format!("no coin {}", l)))?;
				let on_chain = self.chain.locate(std::slice::from_ref(&self.forfeit_of(&row, f)?.output().txout()))?[0].is_some();
				exit &= !on_chain && self.round_gone(f)?;
			}
			if exit {
				h["exit"] = self.exit(l, None).unwrap_or_else(|e| json!({"error": e.to_string(),
					"note": "exit the coin, naming an asset the wallet holds on the chain for the fees (--fee-asset)"}));
			}
			out_held.push(h);
		}
		let mut out = json!({"participation": pid, "state": why, "live_again": back, "held": out_held,
			"note": if held.is_empty() { format!("{}; its coins are live again", note) } else {
				format!("{}; a coin under a forfeit that may still be claimed or confirm stays given up: its forfeit is followed on \
				the chain and refunded once its delay has run, and one whose forfeit is not on the chain is exited", note) }});
		if let Some(r) = reason {
			out["void_reason"] = json!(r);
		}
		Ok(out)
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
		// The acceptance horizon counts from the round's block, not from this
		// sync: the server takes the forfeits until the later of a day after
		// the round is final and the coins' exit date, and a leaf completed
		// then is as long-lived as one completed at once. The operator cannot
		// date the block.
		let as_of = match finality.height() {
			Some(h) => self.chain.median_time_at(h)?.and_then(|t| MedianTime::from_consensus(t).ok()).map_or(now, |t| t.min(now)),
			None => now,
		};
		let info = self.server_info()?;
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
			self.witness_record(&tree["signer_record"], false)?;
			let tree = rebuild(&tree)?;
			let index = o["leaf_index"].as_u64().ok_or_else(|| Error::Parse("no leaf_index".into()))? as usize;
			if index >= tree.records().len() {
				return Err(Error::Refused("the server names a leaf the published tree does not have".into()));
			}
			let record = tree.record(index);
			let owner = self.keys.leaf_xonly(&nonce)?;
			// The reserves, at four times the node's floor in the leaf's asset
			// when it accepts that asset for fees, one atom when it does not.
			let (accept, fee_coin) = self.leaf_policy(record.asset, as_of)?;
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
			// times the floor, or one atom where the operator's node does not
			// take the asset for fees, priced from the floor the operator
			// publishes, as a transfer's margins are, whatever the wallet's
			// own node makes of the asset. More is value handed to the
			// broadcaster.
			let ceiling = match super::pay::Margins::of(&info, old.asset)?.floor {
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
			return Ok(json!({"participation": pid, "state": "forfeiting",
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

	/// Participation `pid`, which the server answers `released` (status
	/// `st`), when the wallet already signed and recorded the forfeit of every
	/// coin it gave up (`given`) and the new leaves it validated before
	/// signing them: the server released it on those forfeits, so the wallet
	/// signs nothing for it again, and the checks it makes before signing,
	/// dated now, are not made again (they guard a forfeit about to leave the
	/// wallet, and these left it long ago). It takes the preimage from the
	/// published tree of the round it recorded, and completes the new leaves
	/// it validated then ([`Self::finish`], which checks the preimage opens
	/// them). `None` when the wallet holds no such forfeits, the server says
	/// it was released in another round, or the server publishes no
	/// preimage there: the participation is then completed as one not yet
	/// released.
	fn take_released(&mut self, pid: &str, st: &Value, given: &[String]) -> Result<Option<Value>, Error> {
		let Some(news) = self.store.participation_news(pid)? else { return Ok(None) };
		let news: Value = serde_json::from_str(&news).map_err(|e| Error::Store(e.to_string()))?;
		let round = news["round"].as_str().unwrap_or("").to_string();
		for l in given {
			if !self.store.forfeits_of(l)?.iter().any(|f| f.participation == pid && f.round == round) {
				return Ok(None);
			}
		}
		// Released in another round than the one the wallet signed for: the
		// participation is completed as one not yet released, every check
		// made.
		if st["round"]["txid"].as_str() != Some(round.as_str()) {
			return Ok(None);
		}
		// The unlock hash the wallet's new leaves carry, as it validated them.
		let mut unlock = None;
		for n in news["leaves"].as_array().cloned().unwrap_or_default() {
			let record = LeafRecord::from_bytes(&unhex(n["record"].as_str().unwrap_or(""))?).map_err(|e| Error::Store(e.to_string()))?;
			unlock = Some(record.unlock_hash);
		}
		let Some(unlock) = unlock else { return Ok(None) };
		let mut preimage = None;
		for o in st["outputs"].as_array().cloned().unwrap_or_default() {
			let tree = self.server.post("tree", &json!({"txid": round, "vout": o["batch_vout"]}))?;
			if tree["round_txid"].as_str() != Some(round.as_str()) {
				return Err(Error::Refused("the server published the tree of another round".into()));
			}
			for l in tree["leaves"].as_array().cloned().unwrap_or_default() {
				let Some(p) = l["preimage"].as_str().and_then(|p| unhex32(p).ok()) else { continue };
				if sha256::Hash::hash(&p).to_byte_array() == unlock {
					preimage = Some(p);
				}
			}
			if preimage.is_some() {
				break;
			}
		}
		let Some(preimage) = preimage else { return Ok(None) };
		let kept = self.finish(pid, preimage, "settled")?;
		Ok(Some(json!({"participation": pid, "state": "released", "round": round, "new_leaves": kept,
			"note": "released by the server on the forfeits the wallet handed over before: the preimage taken from the published tree, \
				nothing signed again"})))
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
			// The leaf was accepted before any forfeit left the wallet. A
			// claim publishes the preimage at any time the forfeit's output
			// lives, and the operator takes the forfeits until the coins' exit
			// deadline, so the leaf is completed when it is, in its last days
			// or past its expiry as well: as an exit checks a coin held.
			let first = record.schedule.expiries()[0].to_consensus_u32();
			let a = self.assess(&coin, &self.followed_policy(first, now), Some((&record.owner, &nonce)))?;
			let row = self.row(&coin, &a, if a.all_final() { "live" } else { "pending" }, "")?;
			if self.store.coin(&row.leaf_id)?.is_none() {
				let id = row.leaf_id.clone();
				self.store.atomically(|s| {
					s.put_coin(&row)?;
					s.use_nonce(&nonce, &id)
				})?;
			}
			let mut k = json!({"leaf_id": row.leaf_id, "asset": record.asset.to_string(), "value": record.value.to_string(),
				"expiry": record.schedule.expiries()[0].to_consensus_u32()});
			if let Some(f) = self.exit_fee(&row, &mut None)? {
				k["exit_fee"] = f;
			}
			kept.push(k);
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
	/// The coin is checked as of its expiry once that has passed, as an exit
	/// checks it: a forfeit is followed until a spend of its output is final,
	/// and the chain can decide it, or undo what it decided, at any time the
	/// output lives, past the coin's expiry as before it.
	pub(crate) fn forfeit_of(&self, row: &super::store::CoinRow, f: &ForfeitRow) -> Result<Forfeit, Error> {
		let record = Self::record_of(row)?;
		let policy = self.followed_policy(row.expiry, self.now()?);
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
	/// on the chain once that refund is final, unless the wallet holds the
	/// preimage of the new leaves the coin was given up for (read from a
	/// claim a rollback took out) and their round can return: the output is
	/// then the operator's to claim, and the wallet sends no refund and
	/// follows it, until the new leaves' batch has expired, sending the round
	/// again from its own copy whenever it is in no block and no mempool with
	/// its inputs unspent, so that its leaves are the wallet's in the chain
	/// whoever else is gone; a forfeit never published,
	/// whose round is lost, is void, and its coin is the wallet's
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
	pub(crate) fn new_leaves_expired(&self, pid: &str) -> Result<bool, Error> {
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
		// when a refund the wallet sent left the mempool or a block), unless
		// the wallet holds the preimage its round's new leaves open and that
		// round can return. Then the coin was exchanged for those leaves, and
		// the output is the operator's claim to make: the wallet only
		// follows it.
		if let Some(at) = self.chain.locate(std::slice::from_ref(&out))?[0] {
			// The participation stands in another of its rounds: the coin was
			// exchanged for that round's leaves, whatever becomes of this
			// forfeit's.
			if let Some(other) = self.stands_elsewhere(f)? {
				return Ok(Some(json!({"leaf_id": f.leaf_id, "round": f.round, "forfeit": at.to_string(), "state": f.state,
					"note": format!("the forfeit's output is unspent, and the participation stands in round {}, whose leaves the wallet \
					holds for this coin: the wallet sends no refund of it while that round is in the chain", other)})));
			}
			// Withheld only until the new leaves' batch has expired, after which
			// no preimage opens anything and the coin is the wallet's to take
			// back. Until then, a round in no block and no mempool, its inputs
			// unspent, is sent again from the wallet's own copy: its leaves are
			// the wallet's once it is in the chain, and the operator's claim
			// can follow.
			if self.holds_preimage(f)? && !self.round_gone(f)? && !self.new_leaves_expired(&f.participation)? {
				let mut v = json!({"leaf_id": f.leaf_id, "round": f.round, "forfeit": at.to_string(), "state": f.state,
					"note": "the forfeit's output is unspent, and the wallet holds the preimage of the new leaves it was given up for, \
					read from the operator's claim: the output is the operator's to claim while its round can return, so the wallet \
					sends no refund and follows it until the new leaves' batch has expired"});
				if let Some(sent) = self.send_round_again(&f.round)? {
					v["round_sent"] = sent;
				}
				return Ok(Some(v));
			}
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
		// Never published: void once its round is lost.
		if f.state != "signed" {
			return Ok(None);
		}
		if self.round_gone(f)? {
			let pstate = self.store.participations()?.into_iter().find(|p| p.0 == f.participation).map(|p| p.4).unwrap_or_default();
			// A coin the operator keeps given up under this forfeit (its
			// participation will never run) is still to be taken on the
			// chain: the forfeit may still confirm, from any mempool that
			// saw it, and is followed until the coin is exited.
			if matches!(pstate.as_str(), "void" | "expired") && matches!(row.state.as_str(), "forfeited" | "exiting") {
				return Ok(None);
			}
			// The coin follows its participation, which the operator runs
			// again: it is the wallet's again only once the operator says so.
			let why = format!("round {} is lost, so its forfeit cannot be claimed while it is", f.round);
			self.store.set_forfeit_state(&f.leaf_id, &f.round, "void", &why)?;
			return Ok(Some(json!({"leaf_id": f.leaf_id, "round": f.round, "state": "void", "note": why})));
		}
		Ok(None)
	}

	/// Follows each participation to the one of its rounds that stands. A
	/// participation can have been in several rounds: one that went out of
	/// the chain, and the round that ran it again, which spends a coin that
	/// cannot exist beside the first, so at most one of them is in the chain
	/// whatever the parent chain does. When one of them is final, and the
	/// wallet holds its new leaves (their preimage in their records), the
	/// participation is released in it: its leaves of that round are the
	/// wallet's again once their round is final, and its leaves of every
	/// other round are lost. Only a round whose forfeit of a coin given up
	/// the wallet refunded (that coin came back to it) or whose coin given up
	/// the wallet took on the chain itself is not followed: its leaves are
	/// the operator's, who sweeps them with their batch. Run by the re-check,
	/// so the wallet holds one leaf for each coin it gave up, whichever round
	/// stands. A coin paid to the wallet out of a leaf of a round that went
	/// out of the chain, lost with it, is the wallet's again once every round
	/// and board it rests on is final again. Returns what changed.
	pub(crate) fn follow_standing_rounds(&mut self) -> Result<Vec<Value>, Error> {
		let mut changes = vec![];
		let coins = self.store.coins()?;
		let opens = |c: &super::store::CoinRow, round: &str, h: &str| -> bool {
			c.kind == "batch" && c.bases.iter().any(|b| b == round) && matches!(Self::record_of(c),
				Ok(CoinRecord::Leaf { record, .. }) if hex(&record.unlock_hash) == h)
		};
		for (pid, _, given, _, state, _, pround) in self.store.participations()? {
			if matches!(state.as_str(), "submitting" | "withdrawn" | "refused") {
				continue;
			}
			let given: Vec<String> = serde_json::from_str(&given).map_err(|e| Error::Store(e.to_string()))?;
			// Its rounds, each with the unlock hash its forfeits name.
			let mut rounds: BTreeMap<String, String> = BTreeMap::new();
			let mut forfeits: Vec<ForfeitRow> = vec![];
			for l in &given {
				for f in self.store.forfeits_of(l)? {
					if f.participation == pid {
						rounds.insert(f.round.clone(), f.unlock_hash.clone());
						forfeits.push(f);
					}
				}
			}
			let held_of = |k: &str| -> Vec<&super::store::CoinRow> { coins.iter().filter(|c| opens(c, k, &rounds[k])).collect() };
			// One round, released in it, its leaves not lost: nothing to follow.
			if rounds.len() == 1 && state == "released" && pround.as_deref().is_some_and(|r| rounds.contains_key(r))
				&& held_of(pround.as_deref().unwrap_or("")).iter().all(|c| c.state != "lost")
			{
				continue;
			}
			let mut standing = vec![];
			for k in rounds.keys() {
				let txid = Txid::from_str(k).map_err(|e| Error::Store(e.to_string()))?;
				if !held_of(k).is_empty() && self.chain.finality(&txid)?.is_final() {
					standing.push(k.clone());
				}
			}
			let [k] = standing.as_slice() else { continue };
			let leaves = held_of(k);
			let already = state == "released" && pround.as_deref() == Some(k.as_str());
			if !already || leaves.iter().any(|c| c.state == "lost") {
				// A coin given up for this round that came back to the wallet on
				// the chain while the round was out leaves its leaves to the
				// operator.
				let refunded = forfeits.iter().any(|f| &f.round == k && matches!(f.state.as_str(), "refunded" | "refunding"));
				let exited = given.iter().any(|l| coins.iter().any(|c| &c.leaf_id == l && c.state == "exited"));
				if refunded || exited {
					let why = format!("round {} is in the chain again, but the coin given up for this leaf came back to the wallet on \
						the chain while it was out (by {}): the leaf is the operator's, who sweeps it with its batch", k,
						if refunded { "its forfeit's refund" } else { "its exit" });
					for c in leaves.iter().filter(|c| matches!(c.state.as_str(), "live" | "pending" | "lost") && c.note != why) {
						self.store.set_coin_state(&c.leaf_id, "lost", &why)?;
						changes.push(json!({"leaf_id": c.leaf_id, "from": c.state, "to": "lost", "why": why}));
					}
					continue;
				}
			}
			let CoinRecord::Leaf { preimage, .. } = Self::record_of(leaves[0])? else { continue };
			if !already {
				let mut news = vec![];
				for c in &leaves {
					let CoinRecord::Leaf { record, auths, .. } = Self::record_of(c)? else { continue };
					news.push(json!({"record": hex(&record.to_bytes().map_err(|e| Error::Store(e.to_string()))?), "nonce": hex(&c.owner_nonce),
						"auths": auths.iter().map(|(s, t)| json!({"signature": hex(s.as_ref()), "time": t.to_consensus_u32()})).collect::<Vec<_>>()}));
				}
				let news = json!({"round": k, "leaves": news});
				let why = format!("round {} of participation {} is final in the chain: the participation stands in it, and its leaves of \
					any other round it was in are out of the chain", k, pid);
				let given = given.clone();
				let leaves_ids: Vec<(String, [u8; 32])> = leaves.iter().map(|c| (c.leaf_id.clone(), c.owner_nonce)).collect();
				self.store.atomically(|s| {
					s.set_participation_news(&pid, &news.to_string())?;
					s.set_participation(&pid, "released", Some(&hex(&preimage)), Some(k))?;
					for l in &given {
						if s.coin(l)?.is_some_and(|c| matches!(c.state.as_str(), "given" | "forfeited")) {
							s.set_coin_spent(l, &format!("participation {}", pid))?;
						}
						for f in s.forfeits_of(l)? {
							if f.participation == pid && &f.round == k && f.state == "void" {
								s.set_forfeit_state(l, k, "signed", &why)?;
							}
						}
					}
					for (leaf, nonce) in &leaves_ids {
						s.wait_on_nonce(nonce)?;
						s.use_nonce(nonce, leaf)?;
					}
					Ok(())
				})?;
				changes.push(json!({"participation": pid, "from": state, "to": "released", "round": k, "why": why}));
			}
			// Its leaves of the round that stands, the wallet's again; of every
			// other round, out of the chain. A leaf read again past its expiry
			// is checked as of that expiry: the round that stands holds its
			// path, and its exit goes on until a sweep is final. One whose
			// path a final sweep, or another spend, has cut stays lost.
			let now = self.now()?;
			for c in leaves.iter().filter(|c| c.state == "lost") {
				let record = Self::record_of(c)?;
				let Ok(bases) = self.accepted_bases(&record) else { continue };
				let Ok(valid) = record.resolve(&bases, &self.followed_policy(c.expiry, now)) else { continue };
				if self.cut_by_final_spend(&valid)? {
					continue;
				}
				let mut fin = true;
				for t in &bases {
					fin &= self.chain.finality(&t.txid())?.is_final();
				}
				let (to, why) = if fin { ("live", format!("round {} is final in the chain again", k)) } else {
					("pending", format!("round {} is in the chain again, not yet final", k)) };
				self.store.set_coin_state(&c.leaf_id, to, &why)?;
				changes.push(json!({"leaf_id": c.leaf_id, "from": "lost", "to": to, "why": why}));
			}
			for (j, h) in rounds.iter().filter(|(j, _)| *j != k) {
				for c in coins.iter().filter(|c| opens(c, j, h) && matches!(c.state.as_str(), "live" | "pending")) {
					let why = format!("round {} is out of the chain: round {} of the same participation stands, and the wallet holds its \
						leaves in their place", j, k);
					self.store.set_coin_state(&c.leaf_id, "lost", &why)?;
					changes.push(json!({"leaf_id": c.leaf_id, "from": c.state, "to": "lost", "why": why}));
				}
			}
		}
		// A coin paid out of a leaf of a round that went out of the chain is
		// lost with it; once every round and board it rests on is final in the
		// chain again and its checks pass, it is the wallet's again, past its
		// expiry as before it (checked as of that expiry), unless a final
		// sweep, or another spend, has cut its path.
		let now = self.now()?;
		for c in self.store.coins_in("lost")?.into_iter().filter(|c| c.kind == "transfer") {
			let record = Self::record_of(&c)?;
			let Ok(bases) = self.accepted_bases(&record) else { continue };
			let Ok(valid) = record.resolve(&bases, &self.followed_policy(c.expiry, now)) else { continue };
			let mut fin = true;
			for t in &bases {
				fin &= self.chain.finality(&t.txid())?.is_final();
			}
			if !fin || valid.check_boards(|op| self.chain.unspent(op).unwrap_or(false)).is_err() || self.cut_by_final_spend(&valid)? {
				continue;
			}
			let why = "every round and board it rests on is final in the chain again".to_string();
			self.store.set_coin_state(&c.leaf_id, "live", &why)?;
			changes.push(json!({"leaf_id": c.leaf_id, "from": "lost", "to": "live", "why": why}));
		}
		Ok(changes)
	}

	/// The round, other than the one forfeit `f` was signed for, that the
	/// participation `f` belongs to stands in: released in it and in a
	/// block of the chain. The coin was exchanged for that round's leaves.
	fn stands_elsewhere(&self, f: &ForfeitRow) -> Result<Option<String>, Error> {
		let Some(p) = self.store.participations()?.into_iter().find(|p| p.0 == f.participation) else { return Ok(None) };
		let Some(round) = p.6.filter(|r| p.4 == "released" && *r != f.round) else { return Ok(None) };
		let txid = Txid::from_str(&round).map_err(|e| Error::Store(e.to_string()))?;
		Ok(self.chain.finality(&txid)?.in_chain().then_some(round))
	}

	/// Whether the wallet holds the preimage of the participation forfeit
	/// `f` was signed for: the one that opens the new leaves of its round
	/// (`f`'s unlock hash).
	fn holds_preimage(&self, f: &ForfeitRow) -> Result<bool, Error> {
		let unlock = unhex32(&f.unlock_hash)?;
		Ok(self.store.participations()?.into_iter().filter(|p| p.0 == f.participation).filter_map(|p| p.5)
			.filter_map(|pre| unhex32(&pre).ok()).any(|pre| sha256::Hash::hash(&pre).to_byte_array() == unlock))
	}

	/// Sends the round `round` again from the wallet's own copy when it is in
	/// no block and not in the mempool and every coin it spends is unspent:
	/// what the node answered, or `None` when there was nothing to send.
	fn send_round_again(&self, round: &str) -> Result<Option<Value>, Error> {
		let Some(raw) = self.store.tx(round)? else { return Ok(None) };
		let tx: Transaction = elements::encode::deserialize(&raw).map_err(|e| Error::Store(e.to_string()))?;
		if self.chain.whereabouts(&tx.txid())? != (false, false) {
			return Ok(None);
		}
		for i in &tx.input {
			if !self.chain.unspent(&i.previous_output)? {
				return Ok(None);
			}
		}
		Ok(Some(match self.chain.broadcast(&tx) {
			Ok(txid) => json!({"txid": txid.to_string(), "note": "the round was in no block and no mempool, its inputs unspent: the wallet \
				sent it again from its own copy"}),
			Err(e) => json!({"txid": tx.txid().to_string(), "error": e.to_string()}),
		}))
	}

	/// Whether the round forfeit `f` is bound to is lost: out of the chain,
	/// and an input of it spent by another transaction that is final. Its
	/// connector asset is then not issued, so no claim of the forfeit can be
	/// made while that stands.
	fn round_gone(&self, f: &ForfeitRow) -> Result<bool, Error> {
		let Some(raw) = self.store.tx(&f.round)? else { return Ok(false) };
		let round: Transaction = elements::encode::deserialize(&raw).map_err(|e| Error::Store(e.to_string()))?;
		self.chain.gone(&round)
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
