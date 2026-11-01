//! Taking part in a round: the refresh.
//!
//! One request per asset, never interactive: a round carries one asset, so
//! the wallet refreshes each asset's coins in that asset's rounds. A request
//! names the coins given up, each attested by its key, the leaf wanted (under
//! a fresh key) and the fee the operator's schedule asks, in the coins' own
//! asset. Then, once the
//! round holding the participation is final, the wallet rebuilds each new
//! leaf from the published batch (a tree, or an accumulator batch, as it
//! names its kind), validates it against the round transaction
//! with the five checks on its sweep token and clock and every bound of its
//! policy, and requires the status to show exactly the leaves it asked for,
//! in order, all under the participation's one unlock hash, and exactly the
//! coins it gave up. Only then does it sign the forfeit of each coin it gave
//! up, built from the validated leaf of the coin's own asset and its round,
//! and its authorisations to take the leaf out (one per node of a tree's
//! branch; one exit from an accumulator batch). The server
//! answers with the preimage that opens the new leaves; the wallet checks it
//! against their unlock hash, keeps them, and releases the lowest node of each
//! old batch leaf, or its slot of an accumulator batch without a sweep
//! (`AccumulatorRelease`): the releases are signed with the forfeits and kept with
//! the participation, and handed to the server once the participation is
//! completed, however it completes (the server's answer, the preimage read
//! from the published tree or from a claim on the chain), retried at each
//! `sync` until the server takes them.

use std::collections::BTreeMap;
use std::str::FromStr;

use elements::hashes::{sha256, Hash};
use elements::{AssetId, OutPoint, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::encode::Encoding;
use arca_covenant::spend::{margin_for, FeeSource};
use arca_covenant::tree::{LeafSpec, ReserveRule, TreeParams};
use arca_covenant::accumulator::{AccumulatorRelease, ACCUMULATOR_RECORD_VERSION, ACCUMULATOR_RECORD_VERSION_NO_SWEEP};
use arca_covenant::{connector_asset, AccumulatorRecord, Batch, BatchKind, Chain, ClockSchedule, CoinRecord, ExplicitOutput, Forfeit,
	HtlcTerms, Landing, LeafId, LeafPolicy, LeafRecord, MedianTime, OffboardPolicy, OrderLeafTerms, Release, RelativeTime, SpendError,
	Template, ValidAccumulatorLeaf, ValidLeaf, WalletPolicy};

use super::chain::{hex, unhex, unhex32};
use super::store::ForfeitRow;
use super::client::{key_proof_digest, participation_id, withdraw_digest, Wanted};
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

/// A quote under way ([`Wallet::quoting`]), until dropped.
pub(crate) struct Quoting {
	flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
	was: bool,
}

impl Drop for Quoting {
	fn drop(&mut self) {
		self.flag.store(self.was, std::sync::atomic::Ordering::Relaxed);
	}
}

/// The most a refresh may cost, in millionths of a coin's value, unless the
/// user raises it for one command.
pub const DEFAULT_MAX_FEE_PPM: u64 = 10_000;

/// A refresh is free in the two days before a coin's exit deadline, three
/// days before its first expiry: the wallet pays nothing there unless the
/// user raises the bound for one command, whatever window the server
/// publishes.
pub const FREE_WINDOW: u32 = 2 * 86_400;

/// A refresh quote's coins in the participations that give them up: one per
/// asset, or one per [`MAX_GIVEN`] coins of an asset that has more, each
/// with its coins' value and fee as quoted (`coins[k]`'s `value` and `fee`,
/// `assets[k]` its asset); a channel leaf is one participation whatever it
/// gives up. Each part is its asset, value, fee and the indices of its coins.
pub(crate) fn participation_parts(per: &BTreeMap<AssetId, (u64, u64)>, assets: &[AssetId], coins: &[Value], channel: bool)
	-> Vec<(AssetId, u64, u64, Vec<usize>)>
{
	let mut parts = vec![];
	for (asset, (total, fee)) in per {
		let mine: Vec<usize> = (0..assets.len()).filter(|k| assets[*k] == *asset).collect();
		if channel || mine.len() <= MAX_GIVEN {
			parts.push((*asset, *total, *fee, mine));
			continue;
		}
		let of = |k: &usize, key: &str| coins[*k][key].as_str().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
		for chunk in mine.chunks(MAX_GIVEN) {
			let t = chunk.iter().map(|k| of(k, "value")).sum::<u64>();
			let f = chunk.iter().map(|k| of(k, "fee")).sum::<u64>();
			parts.push((*asset, t, f, chunk.to_vec()));
		}
	}
	parts
}

/// The most coins one participation, take or distribution gives up: the
/// operator refuses more (`MAX_INPUTS` in its participations). A refresh of
/// more coins of an asset is made in as many participations as it needs;
/// every other selection stops at this many coins, the largest first when
/// the wallet holds more.
pub const MAX_GIVEN: usize = 16;

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
	/// The operator's side of a channel leaf wanted in place of a plain one
	/// ([`Wallet::channel_open`]); `None` for a refresh.
	pub(crate) channel: Option<u64>,
	/// With a channel: what the wallet keeps in a plain leaf of its own
	/// beside it, out of what the coins hold after the fee.
	pub(crate) keep: Option<u64>,
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

	/// What the coins of `asset` hold after the refresh fee.
	pub(crate) fn after(&self, asset: &AssetId) -> Option<u64> {
		self.per.get(asset).map(|(total, fee)| total.saturating_sub(*fee))
	}
}

/// A new leaf's batch against the profile the operator states for its asset
/// (`info`'s `assets[].issuer`): the batch of an asset served issuer-operated
/// is burn-only, its refresh liquidity minted for it and destroyed by its
/// sweep, and no other asset's batch is. A batch with an operator sweep in
/// an issuer-operated asset could hand minted units to the operator; a
/// burn-only batch in another is an operator whose statement and scripts
/// disagree. A round that mints the batch's asset is refused unless the
/// batch is burn-only whatever `info` says (check 5).
pub(crate) fn check_profile<R: LeafTerms>(info: &Value, record: &R) -> Result<(), String> {
	profile_agrees(info, record.asset(), record.burn())
}

/// The terms of a new leaf the wallet checks against what it asked for,
/// whichever kind of batch holds it.
pub(crate) trait LeafTerms {
	fn template(&self) -> Template;
	fn htlc(&self) -> Option<&HtlcTerms>;
	fn order(&self) -> Option<&OrderLeafTerms>;
	fn asset(&self) -> AssetId;
	fn burn(&self) -> bool;
	/// A `channel-1` leaf's terms; an accumulator batch takes none.
	fn channel(&self) -> Option<&arca_covenant::Channel>;
	/// A `claim-1` leaf's lapse; an accumulator batch takes none.
	fn lapse(&self) -> Option<&arca_covenant::Lapse>;
}

impl LeafTerms for LeafRecord {
	fn template(&self) -> Template { self.template }
	fn htlc(&self) -> Option<&HtlcTerms> { self.htlc.as_ref() }
	fn order(&self) -> Option<&OrderLeafTerms> { self.order.as_ref() }
	fn asset(&self) -> AssetId { self.asset }
	fn burn(&self) -> bool { self.burn }
	fn channel(&self) -> Option<&arca_covenant::Channel> { self.channel.as_ref() }
	fn lapse(&self) -> Option<&arca_covenant::Lapse> { self.claim.as_ref() }
}

/// A new leaf as the wallet rebuilds it from a published batch: a tree's
/// leaf record or an accumulator batch's. The two binary forms open with
/// different version bytes, so one reads back as the kind it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NewRecord {
	Tree(LeafRecord),
	Accumulator(AccumulatorRecord),
}

impl LeafTerms for NewRecord {
	fn template(&self) -> Template {
		match self { NewRecord::Tree(r) => r.template, NewRecord::Accumulator(r) => r.template }
	}
	fn htlc(&self) -> Option<&HtlcTerms> {
		match self { NewRecord::Tree(r) => r.htlc.as_ref(), NewRecord::Accumulator(r) => r.htlc.as_ref() }
	}
	fn order(&self) -> Option<&OrderLeafTerms> {
		match self { NewRecord::Tree(r) => r.order.as_ref(), NewRecord::Accumulator(r) => r.order.as_ref() }
	}
	fn asset(&self) -> AssetId {
		match self { NewRecord::Tree(r) => r.asset, NewRecord::Accumulator(r) => r.asset }
	}
	fn burn(&self) -> bool {
		match self { NewRecord::Tree(r) => r.burn, NewRecord::Accumulator(r) => r.burn }
	}
	fn channel(&self) -> Option<&arca_covenant::Channel> {
		match self { NewRecord::Tree(r) => r.channel.as_ref(), NewRecord::Accumulator(_) => None }
	}
	fn lapse(&self) -> Option<&arca_covenant::Lapse> {
		match self { NewRecord::Tree(r) => r.claim.as_ref(), NewRecord::Accumulator(_) => None }
	}
}

impl NewRecord {
	/// Leaf `i` of `batch`.
	pub(crate) fn of(batch: &Batch, i: usize) -> NewRecord {
		match batch {
			Batch::Tree(t) => NewRecord::Tree(t.record(i)),
			Batch::Accumulator(a) => NewRecord::Accumulator(a.record(i)),
		}
	}

	pub(crate) fn value(&self) -> u64 {
		match self { NewRecord::Tree(r) => r.value, NewRecord::Accumulator(r) => r.value }
	}

	pub(crate) fn unlock_hash(&self) -> [u8; 32] {
		match self { NewRecord::Tree(r) => r.unlock_hash, NewRecord::Accumulator(r) => r.unlock_hash }
	}

	pub(crate) fn landing(&self) -> Option<&Landing> {
		match self { NewRecord::Tree(r) => r.landing.as_ref(), NewRecord::Accumulator(r) => r.landing.as_ref() }
	}

	pub(crate) fn owner(&self) -> elements::secp256k1_zkp::XOnlyPublicKey {
		match self { NewRecord::Tree(r) => r.owner, NewRecord::Accumulator(r) => r.owner }
	}

	pub(crate) fn owner_nonce(&self) -> [u8; 32] {
		match self { NewRecord::Tree(r) => r.owner_nonce, NewRecord::Accumulator(r) => r.owner_nonce }
	}

	pub(crate) fn operator_nonce(&self) -> [u8; 32] {
		match self { NewRecord::Tree(r) => r.operator_nonce, NewRecord::Accumulator(r) => r.operator_nonce }
	}

	pub(crate) fn exit_delay(&self) -> RelativeTime {
		match self { NewRecord::Tree(r) => r.exit_delay, NewRecord::Accumulator(r) => r.exit_delay }
	}

	pub(crate) fn schedule(&self) -> &ClockSchedule {
		match self { NewRecord::Tree(r) => &r.schedule, NewRecord::Accumulator(r) => &r.schedule }
	}

	/// The batch's first expiry.
	pub(crate) fn first_expiry(&self) -> u32 {
		self.schedule().expiries()[0].to_consensus_u32()
	}

	pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, Error> {
		match self {
			NewRecord::Tree(r) => r.to_bytes().map_err(|e| Error::Refused(e.to_string())),
			NewRecord::Accumulator(r) => r.to_bytes().map_err(|e| Error::Refused(e.to_string())),
		}
	}

	/// Reads [`NewRecord::to_bytes`], of either kind.
	pub(crate) fn from_bytes(b: &[u8]) -> Result<NewRecord, String> {
		match b.first() {
			Some(&ACCUMULATOR_RECORD_VERSION) | Some(&ACCUMULATOR_RECORD_VERSION_NO_SWEEP) =>
				AccumulatorRecord::from_bytes(b).map(NewRecord::Accumulator).map_err(|e| e.to_string()),
			_ => LeafRecord::from_bytes(b).map(NewRecord::Tree).map_err(|e| e.to_string()),
		}
	}

	/// The wallet's check of the leaf against `round`, for `owner` and the
	/// nonce it picked, within `policy`.
	pub(crate) fn validate(&self, round: &Transaction, policy: &WalletPolicy, owner: &elements::secp256k1_zkp::XOnlyPublicKey,
		nonce: &[u8; 32]) -> Result<NewValid, String>
	{
		match self {
			NewRecord::Tree(r) => r.validate(round, policy, owner, nonce).map(NewValid::Tree).map_err(|e| e.to_string()),
			NewRecord::Accumulator(r) => r.validate(round, policy, owner, nonce).map(NewValid::Accumulator).map_err(|e| e.to_string()),
		}
	}

	/// The coin record of the leaf, opened by `preimage`, with the owner's
	/// authorisations to take it out (one per node of a tree's branch; one
	/// exit for an accumulator batch).
	pub(crate) fn coin(&self, preimage: [u8; 32], auths: Vec<(elements::secp256k1_zkp::schnorr::Signature, MedianTime)>)
		-> Result<CoinRecord, Error>
	{
		Ok(match self {
			NewRecord::Tree(record) => CoinRecord::Leaf { record: record.clone(), preimage, auths },
			NewRecord::Accumulator(record) => {
				let [auth] = auths[..] else {
					return Err(Error::Refused(format!("an accumulator leaf is taken out by one authorisation, and {} are given", auths.len())));
				};
				CoinRecord::Accumulator { record: record.clone(), preimage, auth }
			},
		})
	}

	/// The leaf a coin record of a batch's leaf holds, its preimage and its
	/// authorisations as [`NewRecord::coin`] takes them; `None` for a coin of
	/// another kind.
	#[allow(clippy::type_complexity)]
	pub(crate) fn of_coin(c: &CoinRecord) -> Option<(NewRecord, [u8; 32], Vec<(elements::secp256k1_zkp::schnorr::Signature, MedianTime)>)> {
		match c {
			CoinRecord::Leaf { record, preimage, auths } => Some((NewRecord::Tree(record.clone()), *preimage, auths.clone())),
			CoinRecord::Accumulator { record, preimage, auth } => Some((NewRecord::Accumulator(record.clone()), *preimage, vec![*auth])),
			_ => None,
		}
	}
}

/// A new leaf the wallet validated, of either kind of batch.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum NewValid {
	Tree(ValidLeaf),
	Accumulator(ValidAccumulatorLeaf),
}

impl NewValid {
	pub(crate) fn leaf_id(&self) -> LeafId {
		match self { NewValid::Tree(v) => v.leaf_id, NewValid::Accumulator(v) => v.leaf_id }
	}

	/// The owner's authorisations to take the leaf out from `t`, signed with
	/// `key`: one per node of a tree's branch, or the one exit from an
	/// accumulator batch.
	pub(crate) fn sign_auths(&self, key: &elements::secp256k1_zkp::Keypair, t: MedianTime)
		-> Vec<(elements::secp256k1_zkp::schnorr::Signature, MedianTime)>
	{
		match self {
			NewValid::Tree(v) => v.branch.nodes.iter().map(|n| (sign(key, &n.unroll_authorisation(t).digest), t)).collect(),
			NewValid::Accumulator(v) => vec![(sign(key, &v.exit_digest(t)), t)],
		}
	}

	/// The forfeit of `old`, given up for this leaf of `round`.
	#[allow(clippy::too_many_arguments)]
	pub(crate) fn forfeit_for(&self, old: LeafPolicy, held: (AssetId, u64), old_id: LeafId, round: &Transaction, c: u32,
		refund: RelativeTime, margin: u64) -> Result<Forfeit, SpendError>
	{
		match self {
			NewValid::Tree(v) => Forfeit::for_refresh(old, held, old_id, v, round, c, refund, margin),
			NewValid::Accumulator(v) => v.forfeit_for(old, held, old_id, round, c, refund, margin),
		}
	}

	/// The release of the lowest node above `old`, given up for this leaf.
	pub(crate) fn release(&self, old: &ValidLeaf, round: &Transaction, c: u32) -> Result<Release, SpendError> {
		match self {
			NewValid::Tree(v) => Release::for_refresh(old, v, round, c),
			NewValid::Accumulator(v) => Release::for_accumulator_refresh(old, v, round, c),
		}
	}
}

/// [`check_profile`] for a batch of `asset` whose sweep burns (`burn`) or
/// pays the operator.
fn profile_agrees(info: &Value, asset: AssetId, burn: bool) -> Result<(), String> {
	let asset = asset.to_string();
	let served = info["assets"].as_array().and_then(|a| a.iter().find(|x| x["asset"].as_str() == Some(asset.as_str())).cloned());
	let issuer_operated = served.is_some_and(|a| !a["issuer"].is_null());
	match (issuer_operated, burn) {
		(true, false) => Err(format!("the operator serves asset {} issuer-operated, and this batch's sweep pays the operator: units minted for \
			its refresh could be kept rather than burned, so the wallet takes no leaf of it", asset)),
		(false, true) => Err(format!("this batch's sweep is burn-only, and the operator serves asset {} as no issuer-operated asset: its \
			statement and its scripts disagree", asset)),
		_ => Ok(()),
	}
}

/// The batch a published batch describes, of the kind it names (a tree when
/// it names none), rebuilt by the wallet from the published parts alone and
/// refused unless it lists what they build ([`check_published`]).
pub fn rebuild_batch(t: &Value) -> Result<Batch, Error> {
	let kind = match t.get("kind").and_then(Value::as_str) {
		None => BatchKind::Tree,
		Some(k) => BatchKind::parse(k).ok_or_else(|| Error::Refused(format!("the published batch is of kind {}, which the wallet does not \
			know", k)))?,
	};
	let (params, leaves) = published_parts(t)?;
	let batch = Batch::build(kind, params, &leaves).map_err(|e| Error::Refused(format!("the published {} does not build: {}", kind, e)))?;
	check_published(t, &batch)?;
	Ok(batch)
}

/// What a published batch is built from: its parameters (the radix read by
/// a tree alone) and its leaves.
fn published_parts(t: &Value) -> Result<(TreeParams, Vec<LeafSpec>), Error> {
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
		burn: t["burn"].as_bool().unwrap_or(false), delegated_reclaim: t["delegated_reclaim"].as_bool().unwrap_or(false),
		radix: t["radix"].as_u64().unwrap_or(0) as usize,
		reserve,
		min_leaf: amount(&t["min_leaf"], "min_leaf")?,
	};
	let mut leaves = vec![];
	for l in t["leaves"].as_array().cloned().unwrap_or_default() {
		// A resting order's terms (`order-3`, or `order-2`), another holder's
		// or the wallet's own: the tree does not build without them.
		let order = match l.get("order").filter(|o| !o.is_null()) {
			Some(o) => Some(arca_covenant::record_json::order_terms_from_json(o, params.asset)
				.map_err(|e| Error::Parse(format!("a published leaf's order terms: {}", e)))?),
			None => None,
		};
		leaves.push(LeafSpec {
			claim: match l.get("claim").filter(|c| !c.is_null()) {
				Some(c) => Some(arca_covenant::record_json::claim_from_json(c)
					.map_err(|e| Error::Parse(format!("a published leaf's lapse: {}", e)))?),
				None => None,
			},
			template: l["template"].as_str().unwrap_or("").parse().map_err(|e: arca_covenant::RecordError| Error::Parse(e.to_string()))?,
			owner: elements::secp256k1_zkp::XOnlyPublicKey::from_slice(&unhex(l["owner"].as_str().unwrap_or(""))?)
				.map_err(|e| Error::Parse(e.to_string()))?,
			value: amount(&l["value"], "a leaf's value")?,
			owner_nonce: unhex32(l["owner_nonce"].as_str().unwrap_or(""))?,
			operator_nonce: unhex32(l["operator_nonce"].as_str().unwrap_or(""))?,
			exit_delay: RelativeTime::from_units(l["exit_delay_units"].as_u64().unwrap_or(0) as u16).map_err(|e| Error::Parse(e.to_string()))?,
			unlock_hash: unhex32(l["unlock_hash"].as_str().unwrap_or(""))?,
			htlc: super::lightning::htlc_terms_of(&l["htlc"])?,
			order,
			landing: match l.get("landing").filter(|g| !g.is_null()) {
				Some(g) => Some(arca_covenant::record_json::landing_from_json(g)
					.map_err(|e| Error::Parse(format!("a published leaf's landing: {}", e)))?),
				None => None,
			},
			// A channel leaf's terms, another holder's or the wallet's own:
			// its script, and so the tree, follow from them.
			channel: match l.get("channel").filter(|c| !c.is_null()) {
				Some(c) => Some(arca_covenant::record_json::channel_from_json(c)
					.map_err(|e| Error::Parse(format!("a published leaf's channel terms: {}", e)))?),
				None => None,
			},
		});
	}
	Ok((params, leaves))
}

/// Refuses a new leaf whose template is not the one the wallet asked for, or
/// whose terms are not the ones it asked for. The template is part of what
/// a leaf is: the same owner key, nonce, asset and value under another
/// template is another coin. An `htlc-1` leaf locked to a hash its operator
/// knows can be claimed out of the tree by the operator; an order leaf is
/// filled under the operator's signature alone. So a leaf is `vtxo-1` unless
/// the wallet asked for something else: `order-3` (or `order-2`, as the terms name) on the terms of a resting
/// order it asked for (`w["order"]`), `landing-1` for a supervised asset at
/// the landing it asked for (`w["landing"]`, which the caller compares with
/// the leaf's), or `htlc-1` in the one participation that names one, a
/// payment received over Lightning, locked to that payment's hash
/// (`receive`) in the receiving direction.
pub(crate) fn leaf_as_asked<R: LeafTerms>(w: &Value, record: &R, receive: Option<&[u8; 32]>) -> Result<(), String> {
	let asked_order = w.get("order").is_some_and(|o| !o.is_null());
	let asked_landing = w.get("landing").is_some_and(|l| !l.is_null());
	let asked_channel = w.get("channel").filter(|c| !c.is_null());
	let asked_v2 = w.get("template").and_then(|t| t.as_str()) == Some("vtxo-2");
	// A claim leaf that lapses, on exactly the terms its distribution named:
	// the deadline, the allowance and the return script.
	let asked_lapse = w.get("lapse").filter(|l| !l.is_null());
	let served_lapse = record.lapse().map(arca_covenant::record_json::claim_json);
	if asked_lapse != served_lapse.as_ref() {
		return Err(format!("its lapse is {}, and the wallet asked for {}", served_lapse.map_or("none".into(), |l| l.to_string()),
			asked_lapse.map_or("none".into(), |l| l.to_string())));
	}
	if asked_lapse.is_some() {
		// A lapse with a vest time is a vest-1 leaf's, any other a claim-1 leaf's.
		let want = if record.lapse().is_some_and(|l| l.vest.is_some()) { Template::Vest1 } else { Template::Claim1 };
		return if record.template() == want && record.htlc().is_none() && record.order().is_none() {
			Ok(())
		} else {
			Err(format!("it is a leaf of template {}, and the wallet asked for a {} leaf", record.template(), want))
		};
	}
	let want = match (receive, asked_order, asked_landing, asked_channel) {
		(Some(_), ..) => Template::Htlc1,
		// The terms name their version: order-3, or order-2 for a leaf from
		// before it, restored or taken up as it is.
		(None, true, ..) => w.get("order").and_then(|o| arca_covenant::record_json::order_terms_from_json(o, record.asset()).ok())
			.map_or(Template::Order3, |o| o.template()),
		(None, false, true, _) => Template::Landing1,
		(None, false, false, Some(_)) => Template::Channel1,
		(None, false, false, None) if asked_v2 => Template::Vtxo2,
		(None, false, false, None) => Template::Vtxo1,
	};
	// A channel leaf on exactly the terms asked: the operator's side and
	// the credit window; and no channel where none was asked.
	let served = record.channel().map(arca_covenant::record_json::channel_json);
	if asked_channel != served.as_ref() {
		return Err(format!("its channel terms are {}, and the wallet asked for {}", served.map_or("none".into(), |c| c.to_string()),
			asked_channel.map_or("none".into(), |c| c.to_string())));
	}
	if record.template() != want {
		return Err(format!("it is a leaf of template {}, and the wallet asked for one of template {}: the template is part of what a \
			coin is, and the wallet signs nothing for a leaf of another template than it asked", record.template(), want));
	}
	match want {
		Template::Htlc1 => {
			let hash = receive.expect("asked");
			match record.htlc() {
				Some(h) if h.direction == arca_covenant::HtlcDirection::Receive && &h.payment_hash == hash && record.order().is_none() => Ok(()),
				Some(h) => Err(format!("it is an htlc-1 leaf {} under hash {}, and the wallet asked for the leaf receiving payment hash {}",
					h.direction.name(), hex(&h.payment_hash), hex(hash))),
				None => Err("it is an htlc-1 leaf with no terms".into()),
			}
		},
		_ if record.htlc().is_some() => Err(format!("it carries htlc-1 terms, and the wallet asked for a leaf of template {}", want)),
		_ => order_as_asked(w, record.template(), record.order()),
	}
}

/// A landing as the wallet names it to its user: the program and the
/// allowance, or that there is none.
pub(crate) fn landing_text(l: Option<&arca_covenant::Landing>) -> String {
	match l {
		Some(l) => format!("P2WPKH {} (allowance {})", hex(&l.program), l.allowance),
		None => "no landing (a plain leaf)".into(),
	}
}

/// Refuses a new leaf that is a resting order where the wallet's wanted leaf
/// `w` asked for none, or one on other terms than it asked: an order leaf
/// is filled under the operator's signature alone, at the price and to
/// the credit keys its terms name.
fn order_as_asked(w: &Value, template: Template, order: Option<&arca_covenant::OrderLeafTerms>) -> Result<(), String> {
	let asked = w.get("order").filter(|o| !o.is_null());
	let served = order.map(arca_covenant::record_json::order_terms_json);
	if asked == served.as_ref() && matches!(template, Template::Order2 | Template::Order3) == asked.is_some() {
		return Ok(());
	}
	let say = |o: Option<&Value>| o.map_or("no resting order".to_string(), |o| format!("a resting order on terms {}", o));
	Err(format!("it is {}, and the wallet asked for {}: it signs nothing for a leaf of other terms than it asked", say(served.as_ref()),
		say(asked)))
}

/// What a published batch says beyond the parts it is built from, against
/// the batch the wallet built from those parts: every node a tree lists (its
/// value, reserve, script and children, level by level; an accumulator
/// batch lists none), each leaf's id and script, and each preimage it
/// publishes, which must open its leaf's unlock hash. The wallet takes the
/// operator's word for none of it: a batch that says one thing and builds to
/// another is refused.
fn check_published(t: &Value, batch: &Batch) -> Result<(), Error> {
	let kind = batch.kind();
	let name = if kind == BatchKind::Tree { "tree" } else { "batch" };
	let wrong = |what: String| Error::Refused(format!("the published {} is not the {} its parts build: {}", name, name, what));
	let records: Vec<(Result<LeafId, String>, [u8; 32])> = match batch {
		Batch::Tree(tree) => tree.records().iter().map(|r| (r.leaf_id().map_err(|e| e.to_string()), r.unlock_hash)).collect(),
		Batch::Accumulator(acc) => acc.records().iter().map(|r| (r.leaf_id().map_err(|e| e.to_string()), r.unlock_hash)).collect(),
	};
	let tree = match batch {
		Batch::Tree(tree) => Some(tree),
		Batch::Accumulator(_) => {
			if t["nodes"].as_array().is_some_and(|n| !n.is_empty()) {
				return Err(wrong("it lists nodes, and an accumulator batch has none".into()));
			}
			None
		},
	};
	if let (Some(levels), Some(tree)) = (t["nodes"].as_array(), tree) {
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
	for (i, (l, (id_built, unlock_hash))) in shown.iter().zip(records).enumerate() {
		if let Some(id) = l["leaf_id"].as_str() {
			let built = id_built.map_err(Error::Refused)?;
			if id != built.to_string() {
				return Err(wrong(format!("leaf {} is named {}, its parts make it {}", i, id, built)));
			}
		}
		if let Some(spk) = l["script_pubkey"].as_str() {
			if spk != hex(batch.leaves()[i].leaf.script_pubkey().as_bytes()) {
				return Err(wrong(format!("leaf {}'s script is listed as {}", i, spk)));
			}
		}
		if let Some(p) = l["preimage"].as_str() {
			let p = unhex32(p)?;
			if sha256::Hash::hash(&p).to_byte_array() != unlock_hash {
				return Err(wrong(format!("the preimage published for leaf {} does not open its unlock hash", i)));
			}
		}
	}
	Ok(())
}

/// What the wallet counts, beyond a coin's exit delay and its forfeit's
/// refund delay, for bringing a coin it gave up for an offboard on the
/// chain should the operator withhold the preimage: a day.
pub const OFFBOARD_UNROLL_SECONDS: u64 = 86_400;

impl Wallet {
	/// The offboard the status's output `j` (`o`) shows for the wallet's
	/// wanted offboard `w` (`{asset, value, script}`): its policy rebuilt with
	/// the participation's unlock hash and the reclaim delay the status names,
	/// and found in `round` exactly once, at the index the status names,
	/// holding at least the destination's value.
	fn offboard_shown(&self, j: usize, o: &Value, w: &Value, unlock_hash: &[u8; 32], round: &Transaction)
		-> Result<(OffboardPolicy, u32), Error>
	{
		if o["kind"].as_str() != Some("offboard") || o["asset"] != w["asset"] || o["value"] != w["value"] {
			return Err(Error::Refused(format!("the status's output {} is {} {} of {}; the wallet asked for an offboard of {} of {}", j,
				o["kind"], o["value"], o["asset"], w["value"], w["asset"])));
		}
		let asset = AssetId::from_str(w["asset"].as_str().unwrap_or("")).map_err(|e| Error::Store(e.to_string()))?;
		let value = amount(&w["value"], "an offboard's value")?;
		let script = elements::Script::from(unhex(w["script"].as_str().unwrap_or(""))?);
		let units = o["reclaim_delay_units"].as_u64().and_then(|u| u16::try_from(u).ok())
			.ok_or_else(|| Error::Refused(format!("the status's offboard {} names no reclaim delay", j)))?;
		let policy = OffboardPolicy { unlock_hash: *unlock_hash, destination: ExplicitOutput::new(asset, value, script), operator: self.operator,
			reclaim_delay: RelativeTime::from_units(units).map_err(|e| Error::Refused(e.to_string()))? };
		let vout = policy.find(round).map_err(|e| Error::Refused(format!("round {}: the offboard of {} of asset {}: {}", round.txid(), value,
			asset, e)))?;
		if o["offboard_vout"].as_u64() != Some(vout as u64) {
			return Err(Error::Refused(format!("the status names output {} of round {} for the offboard, which the round pays at {}",
				o["offboard_vout"], round.txid(), vout)));
		}
		Ok((policy, vout))
	}

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
			// Every live coin but a resting order's: refreshing one cancels
			// the order, which only naming it does.
			self.store.coins_in("live")?.into_iter().filter(|c| !super::resting::is_order_coin(c)).collect()
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
			// A channel coin gives up the wallet's side of it: its latest
			// balance and every credit not folded, read from the operator
			// first, as the operator counts it.
			let value = match self.channel_worth(r)? {
				Some(_) => {
					self.channel_sync(&r.leaf_id)?;
					self.channel_worth(r)?.expect("a channel")
				},
				None => a.valid.value,
			};
			let expiry = self.service_expiry(&record, &a)?;
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
		Ok(RefreshQuote { info, channel: None, keep: None, rows, ids, assets, per, coins })
	}

	/// What refreshing a coin of `value` of `asset` whose expiry is median
	/// time `expiry` into the operator's next round would cost now, priced as
	/// [`Self::refresh_quote`] prices a coin the wallet holds, before the
	/// wallet holds it: for a program that shows what a coin it is about to
	/// receive (a swap's, whose `swap_read` names its dates) costs to settle
	/// in a round. The fee only falls as time passes, so a quote of the coin
	/// once held is at most this one. Signs, asks and stores nothing but the
	/// operator's published schedule.
	pub fn settle_quote(&self, asset: AssetId, value: u64, expiry: u32) -> Result<Value, Error> {
		let info = self.server_info()?;
		let now = self.now()?.to_consensus_u32();
		let schedule = schedule_of(&info, asset);
		let fee = refresh_fee(&schedule, value, expiry, now);
		let after = value.checked_sub(fee).ok_or_else(|| Error::Refused(format!("the refresh fee of {} in asset {} is more than the \
			coin holds, {}", fee, asset, value)))?;
		let min = Self::min_leaf(&info, asset)?;
		if after < min {
			return Err(Error::Refused(format!("the new leaf in asset {} would hold {}, below the operator's smallest leaf {}", asset, after, min)));
		}
		Ok(json!({"asset": asset.to_string(), "value": value.to_string(), "expiry": expiry, "fee": fee.to_string(), "after": after.to_string(),
			"ppm": ppm_of(fee, value), "free_window": in_free_window(expiry, now),
			"schedule": {"refresh_ppm": schedule["refresh_ppm"], "refresh_base": schedule["refresh_base"]}}))
	}

	/// Gives up the coins of `quote` for a new leaf in each asset, in one
	/// participation per asset, or per [`MAX_GIVEN`] coins of an asset when
	/// it refreshes more: a round carries one asset, so each asset's coins
	/// are refreshed in that asset's rounds. Each pays the fee the quote
	/// states for its coins, in its own asset. Not before median time `not_before`, when
	/// given. Answers each participation (`participations`), one the server
	/// refused or did not take now with its `error` (one not taken stands,
	/// and sync posts it again); it is an error only when none was taken.
	pub fn participate(&mut self, quote: RefreshQuote, not_before: Option<u32>) -> Result<Value, Error> {
		let RefreshQuote { info, channel, keep, rows, ids, assets, per, coins } = quote;
		let mut out = vec![];
		let mut first_error = None;
		let parts = participation_parts(&per, &assets, &coins, channel.is_some());
		for (asset, total, fee, mine) in &parts {
			let rows: Vec<&super::store::CoinRow> = mine.iter().map(|k| &rows[*k]).collect();
			let ids: Vec<arca_covenant::LeafId> = mine.iter().map(|k| ids[*k]).collect();
			match self.participate_in(&info, *asset, *total, *fee, &rows, &ids, not_before, channel, keep) {
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
	/// `asset` in a round, paying `fee` of it: a channel leaf with `capacity`
	/// on the operator's side when given, and then, with `keep`, a plain leaf
	/// of `keep` beside it, the channel taking the rest.
	#[allow(clippy::too_many_arguments)]
	fn participate_in(&mut self, info: &Value, asset: AssetId, total: u64, fee: u64, rows: &[&super::store::CoinRow],
		ids: &[arca_covenant::LeafId], not_before: Option<u32>, capacity: Option<u64>, keep: Option<u64>) -> Result<Value, Error>
	{
		let needs_fee_coin = self.chain.floor_per_kvb(asset)?.is_none();
		let value = total.checked_sub(fee).ok_or_else(|| Error::Refused("the refresh fee is more than the coins hold".into()))?;
		let min = Self::min_leaf(info, asset)?;
		if value < min {
			return Err(Error::Refused(format!("the new leaf in asset {} would hold {}, below the operator's smallest leaf {}", asset, value, min)));
		}
		// A leaf of a supervised asset is landing-1, at the wallet's landing
		// key; the operator's statement is checked against the wallet's node.
		let landing = self.landing_rule(info, asset)?;
		let nonce = super::random32();
		let owner = self.keys.leaf_xonly(&nonce)?;
		self.store.put_nonce(&nonce, &owner.serialize(), "refresh")?;
		// A channel leaf: the operator's side on top of the wallet's, with
		// the operator's credit window.
		let channel = match capacity {
			Some(c) => Some(Self::channel_terms(info, asset, c)?),
			None => None,
		};
		let template = if channel.is_some() {
			Template::Channel1
		} else if landing.is_some() {
			Template::Landing1
		} else if self.asks_vtxo2() {
			Template::Vtxo2
		} else {
			Template::Vtxo1
		};
		// What stays in a plain leaf beside a channel: refused unless both
		// leaves hold at least the operator's smallest.
		let kept = match keep.filter(|_| channel.is_some()) {
			Some(k) if k >= min && value.saturating_sub(k) >= min => Some(k),
			Some(k) => return Err(Error::Refused(format!("keeping {} of {} beside the channel leaves a leaf below the operator's smallest, {}",
				k, value, min))),
			None => None,
		};
		let value = value - kept.unwrap_or(0);
		let value = value.checked_add(capacity.unwrap_or(0)).ok_or_else(|| Error::Refused("the channel's value overflows".into()))?;
		let mut wanted = vec![Wanted::Leaf { asset, value, template, owner, owner_nonce: nonce, exit_delay: self.exit_delay(),
			order: None, landing, channel }];
		let mut entry = json!({"nonce": hex(&nonce), "asset": asset.to_string(), "value": value.to_string()});
		if let Some(l) = &landing {
			entry["landing"] = arca_covenant::record_json::landing_json(l);
		}
		if let Some(c) = &channel {
			entry["channel"] = arca_covenant::record_json::channel_json(c);
		}
		if template == Template::Vtxo2 {
			entry["template"] = json!("vtxo-2");
		}
		let mut nonces = vec![entry];
		if let Some(k) = kept {
			let n2 = super::random32();
			let o2 = self.keys.leaf_xonly(&n2)?;
			self.store.put_nonce(&n2, &o2.serialize(), "refresh")?;
			let t2 = if self.asks_vtxo2() { Template::Vtxo2 } else { Template::Vtxo1 };
			wanted.push(Wanted::Leaf { asset, value: k, template: t2, owner: o2, owner_nonce: n2, exit_delay: self.exit_delay(),
				order: None, landing: None, channel: None });
			let mut e2 = json!({"nonce": hex(&n2), "asset": asset.to_string(), "value": k.to_string()});
			if t2 == Template::Vtxo2 {
				e2["template"] = json!("vtxo-2");
			}
			nonces.push(e2);
		}
		let fees: Vec<(AssetId, u64)> = if fee > 0 { vec![(asset, fee)] } else { vec![] };
		let nb = not_before.map(MedianTime::from_consensus).transpose().map_err(|e| Error::Refused(e.to_string()))?;
		let id = participation_id(&self.genesis, &self.operator, ids, &wanted, &fees, nb);
		let mut inputs = vec![];
		for r in rows {
			let key = self.coin_key(&r.owner_nonce)?;
			inputs.push(json!({"leaf_id": r.leaf_id, "attestation": hex(sign(&key, &id).as_ref())}));
		}
		// Each leaf wanted under a key the wallet holds, and proves it holds.
		let mut outputs = vec![];
		for w in &wanted {
			let Wanted::Leaf { owner_nonce, .. } = w else { continue };
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
				let mut e = json!({"asset": w["asset"], "value": w["value"], "leaf_id": leaf, "state": coin.map(|c| c.state)});
				// A distribution's claim: the key it was named under; its leaf
				// is its holder's, which `distributions` follows.
				if let Some(k) = w.get("claim") {
					e["claim"] = k.clone();
				}
				new_leaves.push(e);
			}
			out.push(json!({"participation": pid, "state": state, "round": round, "released": preimage.is_some(), "gives": gives,
				"new_leaves": new_leaves}));
		}
		Ok(Value::Array(out))
	}

	/// Whether the operator takes back a pending participation for the owners
	/// of its coins (`info` `participations.withdraw`).
	pub(crate) fn operator_withdraws(info: &Value) -> bool {
		info["participations"]["withdraw"].as_bool() == Some(true)
	}

	/// Takes back the wallet's participation `pid` while the operator has not
	/// put it in a round: each coin it gives up signs the withdrawal digest
	/// under its own key ([`withdraw_digest`]), and the operator voids it
	/// under the lock its round builder holds, so a round either took it
	/// first or never takes it. Each coin the operator gives back is live
	/// again. One a round took is answered `in_round`, its coins still given
	/// up there, and is completed as any other.
	pub fn withdraw_participation(&self, pid: &str) -> Result<Value, Error> {
		let Some((_, body, _, _, state, _, _)) = self.store.participations()?.into_iter().find(|p| p.0 == pid) else {
			return Err(Error::Refused(format!("the wallet made no participation {}", pid)));
		};
		if state != "pending" {
			return Err(Error::Refused(format!("participation {} is {}: only one the operator holds pending is withdrawn", pid, state)));
		}
		let body: Value = serde_json::from_str(&body).map_err(|e| Error::Store(e.to_string()))?;
		let id = unhex32(pid).map_err(|e| Error::Store(e.to_string()))?;
		let digest = withdraw_digest(&self.genesis, &self.operator, &id);
		let mut sigs = vec![];
		let mut leaves = vec![];
		for i in body["inputs"].as_array().into_iter().flatten() {
			let l = i["leaf_id"].as_str().ok_or_else(|| Error::Store(format!("participation {} names a coin without its id", pid)))?;
			let row = self.store.coin(l)?.ok_or_else(|| Error::Store(format!("no coin {}", l)))?;
			sigs.push(hex(sign(&self.coin_key(&row.owner_nonce)?, &digest).as_ref()));
			leaves.push(l.to_string());
		}
		let st = match self.server.post("withdraw_participation", &json!({"participation_id": pid, "signatures": sigs})) {
			Ok(st) => st,
			Err(Error::Server { code, message, .. }) if code == "in_round" => {
				return Ok(json!({"participation": pid, "state": "in_round", "note": message}));
			},
			Err(e) => return Err(e),
		};
		if st["state"] != "void" {
			return Err(Error::Refused(format!("the operator answers participation {} as {}, not void", pid, st["state"])));
		}
		let mut back = vec![];
		for l in &leaves {
			let returned = st["inputs"].as_array().and_then(|a| a.iter().find(|i| i["leaf_id"].as_str() == Some(l.as_str())))
				.and_then(|i| i["returned"].as_bool()).unwrap_or(true);
			if returned && self.store.coin(l)?.is_some_and(|c| c.state == "given") {
				back.push(l.clone());
			}
		}
		for l in &back {
			self.store.set_coin_state(l, "live", "")?;
		}
		self.store.set_participation(pid, "void", None, None)?;
		Ok(json!({"participation": pid, "state": "void", "live_again": back, "void_reason": st["void_reason"]}))
	}

	/// Whether participation `body` is a refresh: not a take, a distribution
	/// or an offboard, its every output a leaf. Only a refresh is taken back
	/// for the owner of its coins ([`Self::withdraw_refreshes`],
	/// [`Self::withdraw_waited`]).
	pub(crate) fn is_refresh(body: &Value) -> bool {
		!Self::is_take(body) && body.get("claims").is_none()
			&& body["outputs"].as_array().is_some_and(|o| !o.is_empty() && o.iter().all(|o| o.get("leaf").is_some()))
	}

	/// Each coin given up in a refresh the store holds pending, by its leaf
	/// id: that refresh's id.
	pub(crate) fn refresh_waiting_coins(&self) -> Result<std::collections::BTreeMap<String, String>, Error> {
		let mut out = std::collections::BTreeMap::new();
		for (pid, body, given, _, state, _, _) in self.store.participations()? {
			if state != "pending" {
				continue;
			}
			let body: Value = serde_json::from_str(&body).map_err(|e| Error::Store(e.to_string()))?;
			if !Self::is_refresh(&body) {
				continue;
			}
			let given: Vec<String> = serde_json::from_str(&given).map_err(|e| Error::Store(e.to_string()))?;
			for l in given {
				out.insert(l, pid.clone());
			}
		}
		Ok(out)
	}

	/// The wallet's refreshes the store holds pending that give up a coin of
	/// `asset`, oldest first: each one's id and the coins it gives up.
	fn pending_refreshes_of(&self, asset: AssetId) -> Result<Vec<(String, Vec<String>)>, Error> {
		let mut out = vec![];
		for (pid, body, given, _, state, _, _) in self.store.participations()? {
			if state != "pending" {
				continue;
			}
			let body: Value = serde_json::from_str(&body).map_err(|e| Error::Store(e.to_string()))?;
			if !Self::is_refresh(&body) {
				continue;
			}
			let given: Vec<String> = serde_json::from_str(&given).map_err(|e| Error::Store(e.to_string()))?;
			let mut of_asset = false;
			for l in &given {
				of_asset |= self.store.coin(l)?.is_some_and(|c| c.asset == asset.to_string());
			}
			if of_asset {
				out.push((pid, given));
			}
		}
		Ok(out)
	}

	/// Takes back every refresh of the wallet's in `asset` that the operator
	/// still holds pending (not a take, a distribution or an offboard), so a
	/// payment or a trade the live coins of `asset` cannot cover can use the
	/// coins it gave up. Answers what it took back; nothing when the operator
	/// takes no withdrawal, or while a quote runs.
	pub(crate) fn withdraw_refreshes(&self, asset: AssetId) -> Result<Vec<Value>, Error> {
		if self.quoting.load(std::sync::atomic::Ordering::Relaxed) || !Self::operator_withdraws(&self.server_info()?) {
			return Ok(vec![]);
		}
		let mut out = vec![];
		for (pid, _) in self.pending_refreshes_of(asset)? {
			match self.withdraw_participation(&pid) {
				Ok(v) => out.push(v),
				Err(e @ Error::Unreachable(_)) => return Err(e),
				Err(e) => out.push(json!({"participation": pid, "error": e.to_string()})),
			}
		}
		Ok(out)
	}

	/// What a payment or a trade the live coins of `asset` fall short for
	/// does first: it takes back every refresh of `asset` that waits
	/// ([`Self::withdraw_refreshes`]), answering whether any came back. While
	/// a quote runs it takes nothing back, and counts instead the coins of
	/// each such refresh the operator answers pending at its first attempt,
	/// which it always lets the wallet take back (a re-run only once its
	/// earlier round can never return, which its status does not say, so a
	/// quote does not count one), so the quote prices what the
	/// trade itself would pay with ([`Self::spendable_coins`]); the quote
	/// says which ([`Self::quoted`]).
	pub(crate) fn free_refreshes(&self, asset: AssetId) -> Result<bool, Error> {
		if !self.quoting.load(std::sync::atomic::Ordering::Relaxed) {
			return Ok(self.withdraw_refreshes(asset)?.iter().any(|v| v["state"] == "void"));
		}
		if !Self::operator_withdraws(&self.server_info()?) {
			return Ok(false);
		}
		let mut counted = false;
		for (pid, given) in self.pending_refreshes_of(asset)? {
			if self.quote_frees.borrow().iter().any(|(p, _)| *p == pid) {
				counted = true;
				continue;
			}
			let st = match self.server.post("participation_status", &json!({"participation_id": pid})) {
				Ok(st) => st,
				Err(e @ Error::Unreachable(_)) => return Err(e),
				Err(_) => continue,
			};
			if st["state"] == "pending" && st["attempt"].as_u64().unwrap_or(0) == 0 {
				self.quote_frees.borrow_mut().push((pid, given));
				counted = true;
			}
		}
		Ok(counted)
	}

	/// The coins of `asset` given up in refreshes the quote under way counts
	/// as the trade's to pay with ([`Self::free_refreshes`]); none outside a
	/// quote.
	pub(crate) fn counted_given(&self, asset: AssetId) -> Result<Vec<super::store::CoinRow>, Error> {
		if !self.quoting.load(std::sync::atomic::Ordering::Relaxed) {
			return Ok(vec![]);
		}
		let mut out = vec![];
		for (_, given) in self.quote_frees.borrow().iter() {
			for l in given {
				if let Some(c) = self.store.coin(l)?.filter(|c| c.state == "given" && c.asset == asset.to_string()) {
					out.push(c);
				}
			}
		}
		Ok(out)
	}

	/// Marks a quote under way until the guard is dropped: a quote takes back
	/// no refresh ([`Self::withdraw_refreshes`]); it counts the coins the
	/// trade would take back ([`Self::free_refreshes`]).
	pub(crate) fn quoting(&self) -> Quoting {
		let was = self.quoting.swap(true, std::sync::atomic::Ordering::Relaxed);
		if !was {
			self.quote_frees.borrow_mut().clear();
		}
		Quoting { flag: self.quoting.clone(), was }
	}

	/// A quote's answer `q`, saying which refreshes that wait the trade would
	/// take back first to pay with their coins (`takes_back`, each its
	/// participation and coins), when it counted any
	/// ([`Self::free_refreshes`]). The quote itself took nothing back.
	pub(crate) fn quoted(&self, q: Result<Value, Error>) -> Result<Value, Error> {
		let mut q = q?;
		let frees = self.quote_frees.borrow();
		if !frees.is_empty() && q.is_object() {
			q["takes_back"] = json!(frees.iter().map(|(p, g)| json!({"participation": p, "coins": g})).collect::<Vec<_>>());
			q["takes_back_note"] = json!("coins given up in a refresh that waits for a round count as the wallet's to pay with: the \
				trade takes that refresh back first, and is refused, the coins still given up, if a round has taken it meanwhile");
		}
		Ok(q)
	}

	/// [`Self::free_refreshes`] when the live coins of `asset` the wallet
	/// can pay with hold less than `need`: whether any came back (or, while
	/// a quote runs, were counted).
	pub(crate) fn free_when_short(&self, asset: AssetId, need: u64) -> Result<bool, Error> {
		let have: u64 = self.spendable_coins(asset)?.iter().map(|i| i.coin.value).sum();
		if have >= need {
			return Ok(false);
		}
		self.free_refreshes(asset)
	}

	/// Posts the participation `pid` of `body`, a take's to `take_order`.
	pub(crate) fn submit_participation_body(&mut self, pid: &str, body: &Value, given: &[String]) -> Result<Value, Error> {
		self.submit(pid, body, given)
	}

	fn submit(&mut self, pid: &str, body: &Value, given: &[String]) -> Result<Value, Error> {
		let call = if Self::is_take(body) {
			"take_order"
		} else if body.get("claims").is_some() {
			"distribute"
		} else {
			"submit_participation"
		};
		// The forfeit window and whether rounds are held for forfeits, so
		// that the wallet keeps in touch until its round is built.
		let info = self.server_info().ok();
		if let Some(info) = &info {
			self.remember_fills(info)?;
		}
		// The wallet hands over its forfeits against the served round before
		// it is broadcast, and says so to an operator that reads it (one
		// that builds batches without a sweep refuses a participation that
		// does not). An older operator refuses fields it does not know, so it
		// is told only when it asks. Not part of the participation's id.
		//
		// It also names the leaf record formats it reads to an operator that
		// asks (`info.participations.record_formats`), which then puts its
		// new leaves only into batches whose records it reads: a wallet that
		// names none is never given a slot of an accumulator batch without a
		// sweep. Not part of the participation's id either.
		let told;
		let reads = |key: &str| info.as_ref().is_some_and(|i| i["participations"][key].as_bool() == Some(true));
		let body = match (reads("forfeits_before_broadcast"), reads("record_formats")) {
			(before, formats) if (before || formats) && call != "take_order" && body.is_object() => {
				let mut b = body.clone();
				if before {
					b["forfeits_before_broadcast"] = json!(true);
				}
				if formats && call == "submit_participation" {
					b["record_formats"] = json!(arca_covenant::RECORD_FORMATS);
				}
				told = b;
				&told
			},
			_ => body,
		};
		match self.server.post(call, body) {
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
			// A participation completed with its releases not yet taken (the
			// server was not reached, or its round not final there yet).
			if state == "released" {
				if let Some(r) = self.send_releases(&pid)? {
					out.push(json!({"participation": pid, "state": "released", "released": r}));
				}
				continue;
			}
			if matches!(state.as_str(), "void" | "expired" | "refused" | "lost") {
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
				// A refresh of received coins that has waited too long for the
				// operator's funds or cap is taken back, its coins free to pay.
				"pending" => match self.withdraw_waited(&pid, &st) {
					Ok(Some(v)) => out.push(v),
					// Why the operator holds it back, in its words, when it says.
					Ok(None) => out.push(json!({"participation": pid, "state": "pending",
						"note": st["waiting"].as_str().map_or_else(|| "waiting for a round".to_string(), str::to_string)})),
					Err(e) => out.push(json!({"participation": pid, "state": "pending", "error": e.to_string()})),
				},
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
					let body: Value = serde_json::from_str(&body).map_err(|e| Error::Store(e.to_string()))?;
					match self.complete(&pid, &st, &given, &wanted, &body) {
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
	/// operator gave back (`returned`) is live again, unless the wallet
	/// signed a forfeit of it for a round that is not gone (D75: no input of
	/// that round spent by a final transaction of another), as a take signs
	/// its forfeits before its round is broadcast: such a forfeit could still
	/// be claimed, and the round still confirm, whatever the operator says, so
	/// the coin is held `forfeited` until the round is gone, and is live again
	/// then ([`Self::watch_forfeits`]). Any other is held
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
		// D75: given back, but under a forfeit for a round not gone.
		let mut until_gone: Vec<(String, Vec<ForfeitRow>)> = vec![];
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
				let mut standing = vec![];
				for f in &followed {
					if !self.round_gone(f)? {
						standing.push(f.clone());
					}
				}
				if standing.is_empty() {
					back.push(l.clone());
				} else {
					until_gone.push((l.clone(), standing));
				}
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
			for (l, standing) in &until_gone {
				s.set_coin_state(l, "forfeited", &format!("{}; the operator gave the coin back, but the wallet signed its forfeit for round \
					{}, which is not gone (no input of it is spent by a final transaction of another) and could still confirm: the coin is \
					held until that round is gone, and is live again then", note,
					standing.iter().map(|f| f.round.clone()).collect::<Vec<_>>().join(", ")))?;
				s.set_meta(&given_back_key(l), pid)?;
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
		let until: Vec<Value> = until_gone.iter().map(|(l, standing)| json!({"leaf_id": l,
			"forfeit_for_round": standing.iter().map(|f| f.round.clone()).collect::<Vec<_>>(),
			"note": "given back by the operator; held until the round its forfeit was signed for is gone"})).collect();
		let mut out = json!({"participation": pid, "state": why, "live_again": back, "held": out_held, "held_until_gone": until,
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
	fn complete(&mut self, pid: &str, st: &Value, given: &[String], wanted: &Value, body: &Value) -> Result<Value, Error> {
		if st["participation_id"].as_str() != Some(pid) {
			return Err(Error::Refused(format!("the server answers for participation {}, not {}", st["participation_id"], pid)));
		}
		let round_txid = Txid::from_str(st["round"]["txid"].as_str().unwrap_or("")).map_err(|e| Error::Parse(e.to_string()))?;
		let take = Self::is_take(body);
		// A round held for its forfeits (one that fills on-chain orders, or
		// holds a batch without a sweep) is broadcast only once every
		// participation in it has handed over its forfeits: until then its
		// status serves the transaction without its witnesses, its txid the
		// round's, which the wallet checks and validates its new leaves
		// against. A forfeit names the round's connector asset, which only
		// that transaction issues: signed for a round that never confirms, it
		// spends nothing, and a claim of it on the chain reveals the preimage
		// of the new leaves it was given up for.
		let unbroadcast = match st["round"]["tx"].as_str() {
			Some(t) if take || !given.is_empty() => {
				let tx: Transaction = elements::encode::deserialize(&unhex(t)?).map_err(|e| Error::Parse(format!("the round: {}", e)))?;
				if tx.txid() != round_txid {
					return Err(Error::Refused(format!("the server serves a transaction {} for round {}", tx.txid(), round_txid)));
				}
				Some(tx)
			},
			_ => None,
		};
		let now = self.now()?;
		let (round, as_of, finality) = match unbroadcast {
			Some(tx) => (tx, now, None),
			None => {
				let finality = self.chain.finality(&round_txid)?;
				if !finality.is_final() {
					return Ok(json!({"participation": pid, "state": "issued", "round": round_txid.to_string(),
						"note": format!("the round is {}; the wallet signs nothing for it before it is final", finality.word())}));
				}
				let round = self.chain.transaction(&round_txid)?
					.ok_or_else(|| Error::Node(format!("the node does not have round {}", round_txid)))?;
				// The acceptance horizon counts from the round's block, not from
				// this sync: the server takes the forfeits until the later of a
				// day after the round is final and the coins' exit date, and a
				// leaf completed then is as long-lived as one completed at once.
				// The operator cannot date the block.
				let as_of = match finality.height() {
					Some(h) => self.chain.median_time_at(h)?.and_then(|t| MedianTime::from_consensus(t).ok()).map_or(now, |t| t.min(now)),
					None => now,
				};
				(round, as_of, Some(finality))
			},
		};
		// A take signs for no round that does not fill its order as it asked.
		if take {
			self.check_take_round(body, st, &round)?;
		}
		let info = self.server_info()?;
		self.remember_fills(&info)?;
		// The one participation whose new leaf is `htlc-1`: a payment the
		// wallet receives over Lightning, whose participation id its hash
		// gives. Every other new leaf is the template the wallet asked for.
		let mut receive = None;
		for hash in self.receives()?.keys() {
			let h = unhex32(hash)?;
			if hex(&super::lightning::receive_participation_id(&h)) == pid {
				receive = Some(h);
			}
		}
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
		let mut news: Vec<(NewValid, NewRecord, [u8; 32])> = vec![];
		// Which of them are a distribution's claims, under keys the wallet
		// does not hold: it signs no authorisation for them and keeps none.
		let mut claim_leaf: Vec<bool> = vec![];
		let wanted = wanted.as_array().cloned().unwrap_or_default();
		let outputs = st["outputs"].as_array().cloned().unwrap_or_default();
		if outputs.len() != wanted.len() {
			return Err(Error::Refused(format!("the status shows {} new leaf/leaves and the wallet asked for {}: it signs nothing \
				until every leaf it asked for is shown and checked", outputs.len(), wanted.len())));
		}
		// Each offboard, found in the round where the status says, paying its
		// destination exactly under the participation's unlock hash.
		let mut offboards: Vec<(OffboardPolicy, u32)> = vec![];
		for (j, (o, w)) in outputs.iter().zip(&wanted).enumerate() {
			if let Some(ow) = w.get("offboard") {
				let policy = self.offboard_shown(j, o, ow, &unlock_hash, &round)?;
				offboards.push(policy);
				continue;
			}
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
			let batch = rebuild_batch(&tree)?;
			let index = o["leaf_index"].as_u64().ok_or_else(|| Error::Parse("no leaf_index".into()))? as usize;
			if index >= batch.len() {
				return Err(Error::Refused("the server names a leaf the published batch does not have".into()));
			}
			let record = NewRecord::of(&batch, index);
			// A distribution's leaves are its claims, owned by the claim key of
			// the key the wallet named and the nonce it drew; every other leaf
			// the wallet asks for is its own.
			let owner = match w["claim"].as_str() {
				Some(named) => {
					let named = elements::secp256k1_zkp::XOnlyPublicKey::from_slice(&unhex(named)?).map_err(|e| Error::Store(e.to_string()))?;
					arca_covenant::claim_key(&named, &nonce).map_err(|e| Error::Refused(e.to_string()))?
				},
				None => self.keys.leaf_xonly(&nonce)?,
			};
			// The reserves, at four times the node's floor in the leaf's asset
			// when it accepts that asset for fees, one atom when it does not.
			let (accept, fee_coin) = self.leaf_policy(record.asset(), as_of)?;
			if fee_coin {
				needs_fee_coin.push(record.asset().to_string());
			}
			let valid = record.validate(&round, &accept, &owner, &nonce)
				.map_err(|e| Error::Refused(format!("the new leaf in round {} fails the wallet's checks: {}", round_txid, e)))?;
			check_profile(&info, &record).map_err(|why| Error::Refused(format!("the new leaf in round {}: {}", round_txid, why)))?;
			// The supervised profile: a leaf of a supervised asset lands at the
			// wallet's own key, with the published allowance, and its round
			// keeps every output explicit; no other asset's leaf is landing-1.
			// A claim's leaf names no landing of the wallet's.
			leaf_as_asked(w, &record, receive.as_ref()).map_err(|why| Error::Refused(format!("the new leaf in round {}: {}", round_txid, why)))?;
			// The supervised profile: a leaf of a supervised asset is asked
			// for landing-1 at the wallet's own key, and lands where it was
			// asked; its round keeps every output explicit. No other asset's
			// leaf is landing-1, and a claim's leaf names no landing.
			let asked = match w.get("landing").filter(|l| !l.is_null()) {
				Some(l) => Some(arca_covenant::record_json::landing_from_json(l).map_err(|e| Error::Store(format!("a wanted landing: {}", e)))?),
				None => None,
			};
			let supervised = self.chain.supervised_assets()?.contains(&record.asset());
			if w.get("claim").is_none() && supervised != asked.is_some() {
				return Err(Error::Refused(format!("the new leaf in round {} is of asset {}, which the wallet's node {} supervised, and the \
					wallet asked for {}: it signs nothing for it", round_txid, record.asset(), if supervised { "lists as" } else { "does not list as" },
					landing_text(asked.as_ref()))));
			}
			if record.landing() != asked.as_ref() {
				return Err(Error::Refused(format!("the new leaf in round {} lands at {}, and the wallet asked for {}: a leaf of a supervised \
					asset lands only where its owner asked", round_txid, landing_text(record.landing()), landing_text(asked.as_ref()))));
			}
			if asked.is_some() {
				arca_covenant::landing::check_explicit(&round).map_err(|e| Error::Refused(format!("round {}: {}", round_txid, e)))?;
			}
			if record.asset().to_string() != w["asset"].as_str().unwrap_or("") || record.value().to_string() != w["value"].as_str().unwrap_or("") {
				return Err(Error::Refused(format!("the new leaf holds {} of {}; the wallet asked for {} of {}", record.value(), record.asset(),
					w["value"], w["asset"])));
			}
			if Some(valid.leaf_id().to_string().as_str()) != o["leaf_id"].as_str() {
				return Err(Error::Refused("the server names the new leaf by another id than its record gives".into()));
			}
			// One unlock hash opens every new leaf of the participation: a
			// forfeit can be claimed only by releasing all of them.
			if record.unlock_hash() != unlock_hash {
				return Err(Error::Refused(format!("the new leaf in asset {} is locked to another unlock hash than the participation's \
					{}: a forfeit is claimable only by releasing every leaf the wallet asked for", record.asset(), hex(&unlock_hash))));
			}
			news.push((valid, record, nonce));
			claim_leaf.push(w.get("claim").is_some());
		}
		if news.is_empty() && offboards.is_empty() {
			return Err(Error::Refused("the participation has no new leaf".into()));
		}
		// Every forfeit's refund must run out before the new leaves' exit
		// deadline, or withholding the preimage strands the owner.
		let refund = RelativeTime::from_units(st["refund_delay_units"].as_u64().unwrap_or(0) as u16).map_err(|e| Error::Parse(e.to_string()))?;
		if !news.is_empty() {
			let deadline = news.iter().map(|(_, r, _)| r.first_expiry()).min().unwrap_or(0)
				.saturating_sub(WalletPolicy::EXIT_DEADLINE);
			if now.to_consensus_u32() as u64 + refund.seconds() >= deadline as u64 {
				return Err(Error::Refused(format!("the forfeits' refund delay of {} s would end after the new leaves' exit deadline", refund.seconds())));
			}
		}
		// An offboard's reclaim must wait out what the owner needs if the
		// operator withholds the preimage: a day to bring the coin it gave up
		// on the chain, that coin's exit delay, and the forfeit's refund delay.
		// Otherwise the operator could reclaim the output and claim the
		// forfeit too.
		if !offboards.is_empty() {
			let mut longest = 0u64;
			for l in given {
				let row = self.store.coin(l)?.ok_or_else(|| Error::Store(format!("coin {} is gone", l)))?;
				longest = longest.max(self.held(&row)?.1.valid.leaf.exit_delay.seconds());
			}
			for (p, _) in &offboards {
				let need = longest + refund.seconds() + OFFBOARD_UNROLL_SECONDS;
				if p.reclaim_delay.seconds() < need {
					return Err(Error::Refused(format!("the operator may reclaim the offboard {} s after its round, and the wallet needs at 						least {} s (a day to bring the coin it gives up on the chain, its exit delay of {} s and the forfeit's refund delay of 						{} s) before a reclaim cannot take the output from under it", p.reclaim_delay.seconds(), need, longest, refund.seconds())));
				}
			}
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
			// The new leaf of the coin's own asset; a take's one leaf, in the
			// asset its order sells, for the coins it gives up in the asset the
			// order is paid in.
			let new = news.iter().find(|(_, r, _)| r.asset() == old.asset || take).map(|n| &n.0);
			let offboard = offboards.iter().find(|(p, _)| p.destination.asset == old.asset).map(|o| &o.0);
			if new.is_none() && offboard.is_none() {
				return Err(Error::Refused(format!("the participation has no new leaf and no offboard in the asset of coin {}", l)));
			}
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
			// Against the new leaf of the coin's asset, or its offboard: one
			// unlock hash opens both.
			let f = match (new, offboard) {
				(Some(new), _) => new.forfeit_for(old.leaf, (old.asset, old.value), old.id, &round, c, refund, margin),
				(None, Some(p)) => Forfeit::for_offboard(old.leaf, (old.asset, old.value), old.id, p, &round, c, refund, margin),
				(None, None) => unreachable!("refused above"),
			}.map_err(|e| Error::Refused(format!("the forfeit of {}: {}", l, e)))?;
			let key = self.coin_key(&row.owner_nonce)?;
			forfeits.push(json!({"leaf_id": l, "signature": hex(sign(&key, &f.message().digest).as_ref())}));
			signed.push((l.clone(), margin));
			// A batch leaf's lowest node is released for this round alone: the
			// release names the round's connector asset, so it is void if the
			// round leaves the chain.
			if let (CoinRecord::Leaf { .. }, arca_covenant::ValidOrigin::Leaf { valid, .. }) = (&record, &old.origin) {
				if valid.branch.nodes.last().is_some_and(|n| n.reclaim.is_some()) {
					let rel = match (new, offboard) {
						(Some(new), _) => new.release(valid, &round, c),
						(None, Some(p)) => Release::for_offboard(valid, p, &round, c),
						(None, None) => unreachable!("refused above"),
					}.map_err(|e| Error::Refused(format!("the release of {}: {}", l, e)))?;
					releases.push(json!({"leaf_id": l, "signature": hex(sign(&key, &rel.message().digest).as_ref())}));
				}
			} else if let (CoinRecord::Accumulator { .. }, arca_covenant::ValidOrigin::Accumulator { valid, .. }) = (&record, &old.origin) {
				// A slot of an accumulator batch without a sweep is released
				// itself, for this round alone, as a lowest node is. One with
				// a sweep has no release.
				if valid.policy.no_sweep() {
					let rel = match (new, offboard) {
						(Some(NewValid::Tree(v)), _) => AccumulatorRelease::for_refresh(valid, v, &round, c),
						(Some(NewValid::Accumulator(v)), _) => AccumulatorRelease::for_accumulator_refresh(valid, v, &round, c),
						(None, Some(p)) => AccumulatorRelease::for_offboard(valid, p, &round, c),
						(None, None) => unreachable!("refused above"),
					}.map_err(|e| Error::Refused(format!("the release of {}: {}", l, e)))?;
					releases.push(json!({"leaf_id": l, "signature": hex(sign(&key, &rel.digest()).as_ref())}));
				}
			} else if matches!(record, CoinRecord::Transfer(_) | CoinRecord::Fill(_)) && !old.release_nodes().is_empty()
				// The order resting again after a fill carries the order
				// coin's own key, which delegated into the fill: a release by
				// it would release the order's slot alone, for every coin the
				// fill made. It is never signed.
				&& !matches!(&record, CoinRecord::Fill(f) if matches!(f.leaf, arca_covenant::transfer::FillLeaf::Rest { .. })) {
				// A coin a reassignment made, resting on lowest nodes with
				// RECLAIM-D: its holder releases each of them for this round,
				// whether it refreshes the coin or offboards it, so that a node
				// whose coins moved out of round comes back once every coin it
				// became has left it.
				let rels = match (new, offboard) {
					(Some(NewValid::Tree(v)), _) => Release::for_holder(old, v, &round, c),
					(None, Some(p)) => Release::for_holder_offboard(old, p, &round, c),
					_ => Ok(vec![]),
				}.map_err(|e| Error::Refused(format!("the releases of {}: {}", l, e)))?;
				for rel in rels {
					releases.push(json!({"leaf_id": l, "node": hex(&rel.node_hash),
						"signature": hex(sign(&key, &rel.message().digest).as_ref())}));
				}
			}
		}
		// Unroll authorisations an hour before now: usable at once.
		let t = MedianTime::from_consensus(now.to_consensus_u32().saturating_sub(3600)).map_err(|e| Error::Node(e.to_string()))?;
		let mut leaves = vec![];
		let mut auths_of = vec![];
		for ((valid, _, nonce), _) in news.iter().zip(&claim_leaf).filter(|(_, c)| !**c) {
			let key = self.keys.leaf(nonce)?;
			let sigs = valid.sign_auths(&key, t);
			leaves.push(json!({"leaf_id": valid.leaf_id().to_string(),
				"auths": sigs.iter().map(|(s, t)| json!({"signature": hex(s.as_ref()), "time": t.to_consensus_u32()})).collect::<Vec<_>>()}));
			auths_of.push(sigs);
		}
		// Before any forfeit leaves the wallet: each forfeit it signs, the
		// round it is bound to, and the new leaves it validated, so that it
		// can follow every forfeit on the chain and complete the leaves with a
		// preimage the chain publishes, whatever the server does next.
		let mine: Vec<&(NewValid, NewRecord, [u8; 32])> = news.iter().zip(&claim_leaf).filter(|(_, c)| !**c).map(|(n, _)| n).collect();
		let mut news_json = json!({"round": round_txid.to_string(), "leaves": mine.iter().zip(&auths_of).map(|((_, record, nonce), auths)| {
			Ok(json!({"record": hex(&record.to_bytes()?), "nonce": hex(nonce),
				"auths": auths.iter().map(|(s, t)| json!({"signature": hex(s.as_ref()), "time": t.to_consensus_u32()})).collect::<Vec<_>>()}))
		}).collect::<Result<Vec<_>, Error>>()?});
		// A distribution's claim leaves, as validated: the preimage that comes
		// back must open them.
		let claims_json: Vec<Value> = news.iter().zip(&claim_leaf).filter(|(_, c)| **c).map(|((v, r, n), _)| {
			Ok(json!({"record": hex(&r.to_bytes()?), "nonce": hex(n), "leaf_id": v.leaf_id().to_string()}))
		}).collect::<Result<Vec<_>, Error>>()?;
		if !claims_json.is_empty() {
			news_json["claims"] = json!(claims_json);
		}
		// The releases of the old leaves' lowest nodes, kept until the server
		// takes them: they go to it once the preimage is in hand and the
		// round final, by whichever way the participation completes.
		if !releases.is_empty() {
			news_json["releases"] = json!(releases);
		}
		if !offboards.is_empty() {
			news_json["offboards"] = json!(offboards.iter().map(|(p, vout)| json!({
				"vout": vout, "asset": p.destination.asset.to_string(), "value": p.destination.value.to_string(),
				"script": hex(p.destination.script_pubkey.as_bytes()), "reclaim_units": p.reclaim_delay.units(),
			})).collect::<Vec<_>>());
		}
		let from_height = match &finality {
			Some(f) => f.height().unwrap_or(0).saturating_sub(100),
			None => self.chain.tip()?.height.saturating_sub(100),
		};
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
			if finality.is_none() {
				return Ok(json!({"participation": pid, "state": "forfeiting", "round": round_txid.to_string(),
					"note": "the forfeits are in before the round is broadcast: the round goes out once every participation in it has \
					handed over its own, and the preimage comes once it is final"}));
			}
			return Ok(json!({"participation": pid, "state": "forfeiting",
				"note": "forfeits in; the preimage is not out yet: the wallet follows each forfeit's output on the chain, takes the preimage \
				from a claim of it, and takes the refund when its delay passes with no claim"}));
		};
		let preimage = unhex32(pre)?;
		let kept = self.finish(pid, preimage, "settled")?;
		// The release of each old batch leaf's lowest node, now that the
		// preimage is in hand, the new leaves validated and their round final.
		let released = self.send_releases(pid)?.unwrap_or(Value::Array(vec![]));
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
		// The unlock hash the wallet's new leaves carry, as it validated them
		// (a distribution's claim leaves, for a distribution).
		let mut unlock = None;
		for n in news["leaves"].as_array().cloned().unwrap_or_default().into_iter().chain(news["claims"].as_array().cloned().unwrap_or_default()) {
			let record = NewRecord::from_bytes(&unhex(n["record"].as_str().unwrap_or(""))?).map_err(Error::Store)?;
			unlock = Some(record.unlock_hash());
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
		let released = self.send_releases(pid)?.unwrap_or(Value::Array(vec![]));
		Ok(Some(json!({"participation": pid, "state": "released", "round": round, "new_leaves": kept, "released": released,
			"note": "released by the server on the forfeits the wallet handed over before: the preimage taken from the published tree, \
				nothing signed again"})))
	}

	/// Hands the server the releases participation `pid` signed of the old
	/// leaves' lowest nodes, once it is completed (the preimage in hand), so
	/// the operator can reclaim a node every owner of which has moved on. They
	/// are kept with the participation until the server takes them or refuses
	/// them for good; a refusal for a round the server does not yet hold as
	/// final, or a server not reached, leaves them for the next `sync`. Each
	/// release names the round the participation completed in, so it is void
	/// should that round leave the chain. `None` when nothing waits to be
	/// sent; else what the server answered.
	pub(crate) fn send_releases(&mut self, pid: &str) -> Result<Option<Value>, Error> {
		let Some(news) = self.store.participation_news(pid)? else { return Ok(None) };
		// Most participations hold none, or sent them long ago: told apart
		// without reading the record.
		if !news.contains("\"releases\"") || news.contains("\"releases_sent\":true") {
			return Ok(None);
		}
		let mut news: Value = serde_json::from_str(&news).map_err(|e| Error::Store(e.to_string()))?;
		let pending = news["releases"].as_array().cloned().unwrap_or_default();
		if pending.is_empty() || news["releases_sent"].as_bool() == Some(true) {
			return Ok(None);
		}
		let later = |code: &str| matches!(code, "release_early" | "round_not_final" | "not_synced" | "internal");
		let answer = match self.server.post("release_leaves", &json!({"participation_id": pid, "releases": pending})) {
			Ok(v) => v["released"].clone(),
			Err(Error::Server { code, .. }) if later(&code) => return Ok(Some(json!({"waiting": code}))),
			// Refused for good as a set (one coin of it, say, now under an
			// open reassignment): each is handed over alone, so the others
			// are still taken.
			Err(Error::Server { .. }) => {
				let mut taken = vec![];
				for r in &pending {
					match self.server.post("release_leaves", &json!({"participation_id": pid, "releases": [r]})) {
						Ok(v) => taken.extend(v["released"].as_array().cloned().unwrap_or_default()),
						Err(Error::Server { code, .. }) if later(&code) => return Ok(Some(json!({"waiting": code}))),
						Err(e @ Error::Server { .. }) => taken.push(json!({"leaf_id": r["leaf_id"], "refused": e.to_string()})),
						Err(e) => return Ok(Some(json!({"error": e.to_string()}))),
					}
				}
				Value::Array(taken)
			},
			Err(e) => return Ok(Some(json!({"error": e.to_string()}))),
		};
		news["releases_sent"] = json!(true);
		self.store.set_participation_news(pid, &news.to_string())?;
		Ok(Some(answer))
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
		for n in news["claims"].as_array().cloned().unwrap_or_default() {
			let record = NewRecord::from_bytes(&unhex(n["record"].as_str().unwrap_or(""))?).map_err(Error::Store)?;
			if sha256::Hash::hash(&preimage).to_byte_array() != record.unlock_hash() {
				return Err(Error::Refused("the preimage does not open the distribution's claim leaves".into()));
			}
		}
		let mut kept = vec![];
		for n in news["leaves"].as_array().cloned().unwrap_or_default() {
			let record = NewRecord::from_bytes(&unhex(n["record"].as_str().unwrap_or(""))?).map_err(Error::Store)?;
			let nonce = unhex32(n["nonce"].as_str().unwrap_or(""))?;
			if sha256::Hash::hash(&preimage).to_byte_array() != record.unlock_hash() {
				return Err(Error::Refused("the preimage does not open the new leaves".into()));
			}
			let mut auths = vec![];
			for a in n["auths"].as_array().cloned().unwrap_or_default() {
				let sig = elements::secp256k1_zkp::schnorr::Signature::from_slice(&unhex(a["signature"].as_str().unwrap_or(""))?)
					.map_err(|e| Error::Store(e.to_string()))?;
				let t = MedianTime::from_consensus(a["time"].as_u64().unwrap_or(0) as u32).map_err(|e| Error::Store(e.to_string()))?;
				auths.push((sig, t));
			}
			let coin = record.coin(preimage, auths)?;
			// The leaf was accepted before any forfeit left the wallet. A
			// claim publishes the preimage at any time the forfeit's output
			// lives, and the operator takes the forfeits until the coins' exit
			// deadline, so the leaf is completed when it is, in its last days
			// or past its expiry as well: as an exit checks a coin held.
			let first = record.first_expiry();
			let a = self.assess(&coin, &self.followed_policy(first, now), Some((&record.owner(), &nonce)))?;
			// A leaf received over Lightning is held apart until its owner
			// claims it with the payment's preimage (`lightning`).
			let state = if record.htlc().is_some() { "receiving" } else if a.all_final() { "live" } else { "pending" };
			let row = self.row(&coin, &a, state, "")?;
			// Bound to the mailbox key when the act that wanted it named the
			// key: a refresh does; a receive over Lightning does when it was
			// asked for with the key.
			let bound = match record.htlc() {
				Some(t) => self.receives()?.get(&hex(&t.payment_hash)).is_some_and(|r| !r["request"]["mailbox"].is_null()),
				None => true,
			};
			if self.store.coin(&row.leaf_id)?.is_none() {
				let id = row.leaf_id.clone();
				self.store.atomically(|s| {
					s.put_coin_bound(&row, bound)?;
					s.use_nonce(&nonce, &id)
				})?;
			}
			let mut k = json!({"leaf_id": row.leaf_id, "asset": record.asset().to_string(), "value": record.value().to_string(),
				"expiry": first});
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
		let coin = self.resolve(&record, &self.accepted_bases(&record)?, &policy).map_err(|e| Error::Refused(e.to_string()))?;
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
			let record = NewRecord::from_bytes(&unhex(n["record"].as_str().unwrap_or(""))?).map_err(Error::Store)?;
			last = last.max(record.schedule().expiries().last().map(|e| e.to_consensus_u32()).unwrap_or(u32::MAX));
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
				let preimage = spender.input.iter().filter(|i| i.previous_output == at)
					.find_map(|i| arca_covenant::witness::find_preimage(&i.witness.script_witness, &unlock));
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
				// D75: a coin the operator gave back, held while this
				// forfeit's round could confirm, is live again once that round
				// and every other its forfeits were signed for are gone.
				if row.state == "forfeited" && self.store.meta(&given_back_key(&f.leaf_id))?.is_some() {
					let mut standing = false;
					for g in self.store.forfeits_of(&f.leaf_id)? {
						if g.round != f.round && FOLLOWED.contains(&g.state.as_str()) && !self.round_gone(&g)? {
							standing = true;
						}
					}
					let why = format!("round {} is gone: an input of it is spent by a final transaction of another, so its forfeit can \
						never be claimed", f.round);
					let key = given_back_key(&f.leaf_id);
					self.store.atomically(|s| {
						s.set_forfeit_state(&f.leaf_id, &f.round, "void", &why)?;
						if !standing {
							s.set_coin_state(&f.leaf_id, "live", "")?;
							s.delete_meta(&key)?;
						}
						Ok(())
					})?;
					return Ok(Some(json!({"leaf_id": f.leaf_id, "round": f.round, "state": "void", "coin": if standing { "forfeited" } else { "live" },
						"note": if standing { format!("{}; the coin waits for another round its forfeit was signed for", why) } else {
							format!("{}; the operator gave the coin back, so it is live again", why) }})));
				}
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
		// Each batch coin's unlock hash, read from its record once: a
		// participation's rounds are matched against every coin, and a wallet
		// that rests many orders holds hundreds of both.
		let unlocks: Vec<Option<String>> = coins.iter().map(|c| (c.kind == "batch").then(|| Self::record_of(c).ok()
			.and_then(|r| NewRecord::of_coin(&r)).map(|(record, _, _)| hex(&record.unlock_hash()))).flatten()).collect();
		let opens = |i: usize, round: &str, h: &str| -> bool {
			let c = &coins[i];
			c.kind == "batch" && c.bases.iter().any(|b| b == round) && unlocks[i].as_deref() == Some(h)
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
			let held_of = |k: &str| -> Vec<&super::store::CoinRow> { (0..coins.len()).filter(|i| opens(*i, k, &rounds[k])).map(|i| &coins[i]).collect() };
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
			let Some((_, preimage, _)) = NewRecord::of_coin(&Self::record_of(leaves[0])?) else { continue };
			if !already {
				let mut news = vec![];
				for c in &leaves {
					let Some((record, _, auths)) = NewRecord::of_coin(&Self::record_of(c)?) else { continue };
					news.push(json!({"record": hex(&record.to_bytes()?), "nonce": hex(&c.owner_nonce),
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
				let Ok(valid) = self.resolve(&record, &bases, &self.followed_policy(c.expiry, now)) else { continue };
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
				for c in (0..coins.len()).filter(|i| opens(*i, j, h)).map(|i| &coins[i]).filter(|c| matches!(c.state.as_str(), "live" | "pending")) {
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
			let Ok(valid) = self.resolve(&record, &bases, &self.followed_policy(c.expiry, now)) else { continue };
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
		let key = self.coin_key(&row.owner_nonce)?;
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

/// Where the wallet marks a coin the operator gave back while a forfeit the
/// wallet signed for it could still be claimed (D75): held `forfeited` until
/// the round of that forfeit is gone. The value is the participation.
pub(crate) fn given_back_key(leaf_id: &str) -> String {
	format!("given_back_{}", leaf_id)
}

/// The states of a forfeit decided by a final spend of its output, which the
/// wallet still looks at until its new leaves' batch has expired: `refunded`
/// (the wallet's refund final), `claimed` (the operator's claim final). A
/// rollback that leaves that spend not final makes it undecided again.
pub(crate) const DECIDED: [&str; 2] = ["refunded", "claimed"];

#[cfg(test)]
mod tests {
	use super::*;

	/// A record of a leaf the wallet takes, of each kind, read back by its
	/// first byte: an accumulator record of a batch with a sweep (version 1)
	/// and of one without (version 4), and a tree leaf record (version 2 or
	/// 3), none taken for another kind.
	#[test]
	fn records_of_every_kind_are_read_back_as_their_kind() {
		use arca_covenant::accumulator::{Accumulator, AccumulatorParams};
		use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeParams};
		let secp = elements::secp256k1_zkp::Secp256k1::new();
		let key = |n: u8| elements::secp256k1_zkp::Keypair::from_seckey_slice(&secp, &[n; 32]).unwrap().x_only_public_key().0;
		let chain = Chain::new(elements::BlockHash::from_byte_array([9; 32]));
		let asset = AssetId::from_slice(&[3; 32]).unwrap();
		let delay = RelativeTime::from_seconds_ceil(36 * 3600).unwrap();
		let leaves: Vec<LeafSpec> = (0..4u8).map(|i| LeafSpec {
			template: arca_covenant::Template::Vtxo1, owner: key(10 + i), value: 100_000, owner_nonce: [20 + i; 32],
			operator_nonce: [30 + i; 32], exit_delay: delay, unlock_hash: [40 + i; 32], htlc: None, order: None, landing: None,
			channel: None, claim: None,
		}).collect();
		let s = key(1);
		let swept = ClockSchedule::new(AssetId::from_slice(&[5; 32]).unwrap(), s, delay, vec![MedianTime::from_consensus(1_800_000_000).unwrap()])
			.unwrap();
		let reserve = ReserveRule::Fixed { node: 1_000, entry: 1_000 };
		for (schedule, version) in [(swept.clone(), 1u8), (ClockSchedule::never(s), 4u8)] {
			let acc = Accumulator::build(AccumulatorParams { asset, chain, schedule, burn: false, reserve, min_leaf: 1 }, &leaves).unwrap();
			let b = acc.record(1).to_bytes().unwrap();
			assert_eq!(b[0], version);
			assert!(matches!(NewRecord::from_bytes(&b), Ok(NewRecord::Accumulator(r)) if r == acc.record(1)), "accumulator, version {}", version);
		}
		for (schedule, version) in [(swept, 2u8), (ClockSchedule::never(s), 3u8)] {
			let tree = Tree::build(TreeParams { asset, chain, schedule, burn: false, delegated_reclaim: false, radix: 4, reserve, min_leaf: 1 },
				&leaves).unwrap();
			let b = tree.record(1).to_bytes().unwrap();
			assert_eq!(b[0], version);
			assert!(matches!(NewRecord::from_bytes(&b), Ok(NewRecord::Tree(r)) if r == tree.record(1)), "tree, version {}", version);
		}
	}

	#[test]
	fn a_refresh_of_more_coins_than_one_participation_takes_is_split() {
		let a = AssetId::from_slice(&[1; 32]).unwrap();
		let b = AssetId::from_slice(&[2; 32]).unwrap();
		// 40 coins of a (value 100 + k, fee 1 each) and 3 of b.
		let mut assets = vec![];
		let mut coins = vec![];
		let mut per: BTreeMap<AssetId, (u64, u64)> = BTreeMap::new();
		for k in 0..43u64 {
			let asset = if k < 40 { a } else { b };
			assets.push(asset);
			coins.push(json!({"value": (100 + k).to_string(), "fee": "1"}));
			let e = per.entry(asset).or_default();
			e.0 += 100 + k;
			e.1 += 1;
		}
		let parts = participation_parts(&per, &assets, &coins, false);
		let sizes: Vec<(AssetId, usize)> = parts.iter().map(|p| (p.0, p.3.len())).collect();
		assert_eq!(sizes, vec![(a, 16), (a, 16), (a, 8), (b, 3)], "at most {} coins a participation", MAX_GIVEN);
		for (asset, total, fee, idx) in &parts {
			assert!(idx.iter().all(|k| assets[*k] == *asset));
			assert_eq!(*total, idx.iter().map(|k| 100 + *k as u64).sum::<u64>());
			assert_eq!(*fee, idx.len() as u64);
		}
		assert_eq!(parts.iter().filter(|p| p.0 == a).map(|p| p.1).sum::<u64>(), per[&a].0, "every coin given up once");
		// A channel leaf is one participation, whatever it gives up.
		assert_eq!(participation_parts(&per, &assets, &coins, true).len(), 2);
	}

	#[test]
	fn a_batch_agrees_with_the_profile_its_operator_states() {
		let z = AssetId::from_slice(&[7; 32]).unwrap();
		let x = AssetId::from_slice(&[8; 32]).unwrap();
		let info = json!({"assets": [
			{"asset": z.to_string(), "issuer": {"limiter": "00"}},
			{"asset": x.to_string()},
		]});
		assert_eq!(profile_agrees(&info, z, true), Ok(()), "issuer-operated, burn-only");
		assert_eq!(profile_agrees(&info, x, false), Ok(()), "open, the operator's sweep");
		let e = profile_agrees(&info, z, false).unwrap_err();
		assert!(e.contains("issuer-operated") && e.contains("pays the operator"), "{}", e);
		let e = profile_agrees(&info, x, true).unwrap_err();
		assert!(e.contains("burn-only") && e.contains("no issuer-operated asset"), "{}", e);
		// An asset `info` does not list is served as no issuer-operated asset.
		let y = AssetId::from_slice(&[9; 32]).unwrap();
		assert_eq!(profile_agrees(&info, y, false), Ok(()));
		assert!(profile_agrees(&info, y, true).is_err());
		assert!(profile_agrees(&json!({}), z, true).is_err(), "no asset list at all");
		// `issuer: null` is no statement of the profile.
		let null = json!({"assets": [{"asset": z.to_string(), "issuer": null}]});
		assert!(profile_agrees(&null, z, true).is_err());
		assert_eq!(profile_agrees(&null, z, false), Ok(()));
	}

	#[test]
	fn a_new_leaf_is_a_resting_order_only_where_asked_and_on_its_terms() {
		use arca_covenant::order::{OrderLeafTerms, OrderTerms, SeqdexOrder};
		let key = |b: u8| elements::secp256k1_zkp::Keypair::from_seckey_slice(&elements::secp256k1_zkp::Secp256k1::new(), &[b; 32])
			.unwrap().x_only_public_key().0;
		let (a, b) = (AssetId::from_slice(&[1; 32]).unwrap(), AssetId::from_slice(&[2; 32]).unwrap());
		let terms = OrderLeafTerms {
			landed: SeqdexOrder { terms: OrderTerms { asset_a: a, asset_b: b, rate_num: 2, rate_den: 1, min_lot: 10 }, maker: [7; 32],
				expiry: 1_800_000_000, refund_key: key(3), version: arca_covenant::order::SeqdexVersion::V2 },
			credits: [key(4).serialize(), key(5).serialize(), key(6).serialize(), key(8).serialize()],
		};
		let plain = json!({"nonce": "00", "asset": a.to_string(), "value": "1"});
		let asked = json!({"nonce": "00", "asset": a.to_string(), "value": "1", "order": arca_covenant::record_json::order_terms_json(&terms)});
		assert!(order_as_asked(&plain, Template::Vtxo1, None).is_ok(), "a plain leaf where a plain leaf was asked for");
		assert!(order_as_asked(&asked, Template::Vtxo1, None).is_err(), "a plain leaf where an order was asked for");
		assert!(order_as_asked(&asked, Template::Order3, Some(&terms)).is_ok(), "the order asked for");
		let mut old = terms;
		old.landed.version = arca_covenant::order::SeqdexVersion::V1;
		assert!(order_as_asked(&asked, Template::Order2, Some(&old)).is_err(), "an order-2 leaf where order-3 was asked for");
		let e = order_as_asked(&plain, Template::Order3, Some(&terms)).unwrap_err();
		println!("an order the wallet did not ask for: {}", e);
		assert!(e.contains("a resting order on terms"), "{}", e);
		let mut other = terms;
		other.credits[0] = key(9).serialize();
		assert!(order_as_asked(&asked, Template::Order3, Some(&other)).is_err(), "an order with another credit key");
		other = terms;
		other.landed.terms.rate_num = 1;
		assert!(order_as_asked(&asked, Template::Order3, Some(&other)).is_err(), "an order at another price");
	}

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
