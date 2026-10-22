//! Issuer-operated assets: batches the asset's own issuer funds by reissuing
//! the asset in the round, through the mint limiter that holds its
//! reissuance token, and whose sweeps can only burn.
//!
//! An asset is served issuer-operated when its configuration names its mint
//! limiter (`[assets.issuer]`): the instance file the limiter's tool wrote,
//! the asset's issuance entropy, and the limiter's coin and state when the
//! operator set it up. Then:
//!
//! - every batch of the asset is burn-only, and the round that makes it
//!   reissues exactly what it pays in the asset (the batch output with its
//!   leaves and reserves, and each offboard output) at input 0, spending the
//!   limiter's coin, its successor at output 0. The signer signs the mint
//!   (the `reissue` request) after checking every unit of the asset the round
//!   pays goes to a burn-only batch or an offboard it rebuilds itself, and
//!   the limiter's own tool signs and satisfies the program;
//! - the operator keeps no unit of the asset: everything of it an operator
//!   transaction takes in (a forfeit's claim, a reclaim, a reclaimed
//!   offboard, a margin or reserve left over) is burned in that transaction,
//!   and every fee is paid in another asset ([`burns`]);
//! - takes of on-chain orders, distributions and Lightning legs in the asset
//!   are not served: each would make the operator hold or mint units outside
//!   a round's reissue.
//!
//! The limiter's state is carried by its coin. The server follows the coin
//! on the chain from the one its configuration names ([`limiter_now`]):
//! through its own rounds' mints, and through any other spend (the cold
//! key's brake, its release, its recovery), read against the instance. A
//! round mints only from a coin whose transaction is final.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use elements::encode::{deserialize, serialize};
use elements::hashes::Hash;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, BlockHash, OutPoint, Transaction, TxOut, Txid};
use serde::{Deserialize, Serialize};

use arca_covenant::clock::ClockSchedule;
use arca_covenant::encode::Encoding;
use arca_covenant::issuer;
use arca_covenant::limiter::{self, LimiterParams, LimiterSpend, LimiterState, MIN_AGE};
use arca_covenant::{Chain, ExplicitOutput, LeafSpec, OffboardPolicy, RelativeTime, ReserveRule, Template, Tree, TreeParams};

use crate::chain::FinalityService;
use crate::store::{Store, StoreError};

/// Why the limiter could not be read.
#[derive(Debug, thiserror::Error)]
pub enum IssuerError {
	#[error(transparent)]
	Store(#[from] StoreError),
	#[error("the chain: {0}")]
	Chain(String),
}

/// `[assets.issuer]`: the asset's mint limiter.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuerSection {
	/// The instance file the limiter's tool wrote (`mint-limiter instance`).
	pub limiter: PathBuf,
	/// The asset's issuance entropy, as `issueasset` prints it.
	pub entropy: String,
	/// The limiter's coin when the operator set the asset up, `txid:vout`.
	pub coin: String,
	/// That coin's state, `minted,elapsed,armed` (`0,0,0` when absent).
	#[serde(default)]
	pub state: Option<String>,
}

/// An issuer-operated asset as the server serves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuerAsset {
	pub limiter: LimiterParams,
	/// The chain the instance names.
	pub genesis: BlockHash,
	/// The asset's issuance entropy, as a reissuance carries it.
	pub entropy: [u8; 32],
	/// Where the server starts following the limiter's coin, and its state.
	pub start: OutPoint,
	pub start_state: LimiterState,
}

fn parse_state(s: &str) -> Result<LimiterState, String> {
	let p: Vec<&str> = s.split(',').map(str::trim).collect();
	let [m, e, a] = p.as_slice() else { return Err(format!("state {:?}: minted,elapsed,armed", s)) };
	let armed = match *a {
		"0" => false,
		"1" => true,
		_ => return Err(format!("state {:?}: armed is 0 or 1", s)),
	};
	Ok(LimiterState {
		minted: m.parse().map_err(|e| format!("state {:?}: minted: {}", s, e))?,
		elapsed: e.parse().map_err(|e| format!("state {:?}: elapsed: {}", s, e))?,
		armed,
	})
}

impl IssuerAsset {
	/// `asset`'s issuer section, read: the instance file must be a mint
	/// limiter of `asset` whose token is the asset's explicit reissuance
	/// token by `entropy`.
	pub fn from_section(asset: AssetId, s: &IssuerSection, relative_to: Option<&Path>) -> Result<IssuerAsset, String> {
		let path = match relative_to {
			Some(dir) if s.limiter.is_relative() => dir.join(&s.limiter),
			_ => s.limiter.clone(),
		};
		let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {}", path.display(), e))?;
		let (limiter, genesis) = LimiterParams::from_instance_json(&text).map_err(|e| format!("{}: {}", path.display(), e))?;
		let entropy = limiter::entropy_from_hex(&s.entropy).map_err(|e| e.to_string())?;
		if limiter.asset != asset {
			return Err(format!("{} is the mint limiter of asset {}, not {}", path.display(), limiter.asset, asset));
		}
		if limiter::asset_of_entropy(entropy) != asset {
			return Err(format!("entropy {} issues another asset than {}", s.entropy, asset));
		}
		if limiter::token_of_entropy(entropy) != limiter.token {
			return Err(format!("the limiter holds {}, not asset {}'s explicit reissuance token {}", limiter.token, asset,
				limiter::token_of_entropy(entropy)));
		}
		let start = parse_outpoint(&s.coin)?;
		let start_state = match &s.state {
			Some(st) => parse_state(st)?,
			None => LimiterState::default(),
		};
		Ok(IssuerAsset { limiter, genesis, entropy, start, start_state })
	}
}

fn parse_outpoint(s: &str) -> Result<OutPoint, String> {
	let (t, v) = s.split_once(':').ok_or_else(|| format!("coin {:?}: txid:vout", s))?;
	Ok(OutPoint::new(Txid::from_str(t).map_err(|e| format!("coin {:?}: {}", s, e))?, v.parse().map_err(|e| format!("coin {:?}: {}", s, e))?))
}

/// The limiter's coin now, as the chain has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimiterNow {
	pub coin: OutPoint,
	pub txout: TxOut,
	pub state: LimiterState,
	/// Its confirmations: the age, in blocks, a spend in the next block
	/// finds it.
	pub confirmations: u64,
	/// Whether the transaction that made it is final.
	pub is_final: bool,
}

/// Where the limiter stands: its coin, or why none can mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimiterAt {
	Ready(LimiterNow),
	Unavailable(String),
}

/// The most steps [`limiter_now`] follows the coin.
const MAX_STEPS: usize = 100_000;

/// Where `asset`'s mint limiter stands on the chain: its coin is followed
/// from the one the configuration names, through each spend the chain holds
/// (a mint of the server's own round, found by its record, or any spend of a
/// watched coin, read against the instance), to the one unspent.
pub async fn limiter_now(store: &Store, finality: &FinalityService, asset: AssetId, i: &IssuerAsset) -> Result<LimiterAt, IssuerError> {
	let (mut op, mut state) = (i.start, i.start_state);
	let chain = |e: crate::chain::ChainError| IssuerError::Chain(e.to_string());
	for _ in 0..MAX_STEPS {
		store.watch_outpoint(&op.txid.to_byte_array(), op.vout, "limiter", &asset.into_inner().to_byte_array()).await?;
		let at = op;
		if let Some(confirmations) = finality.call(move |n| n.unspent(&at, false)).await.map_err(chain)? {
			let made = finality.watch(op.txid, "limiter").await.map_err(|e| IssuerError::Chain(e.to_string()))?;
			let txid = op.txid;
			let tx = finality.call(move |n| n.transaction(&txid)).await.map_err(chain)?
				.ok_or_else(|| IssuerError::Chain(format!("the node does not hold {}", txid)))?;
			let txout = tx.output.get(op.vout as usize).cloned()
				.ok_or_else(|| IssuerError::Chain(format!("{} has no output {}", txid, op.vout)))?;
			if txout.script_pubkey != i.limiter.script_pubkey(state) {
				return Ok(LimiterAt::Unavailable(format!("the limiter's coin {} is not the instance in state {:?}: the configured coin \
					or state is wrong", op, state)));
			}
			if txout.asset.explicit() != Some(i.limiter.token) || txout.value.explicit().is_none() {
				return Ok(LimiterAt::Unavailable(format!("the limiter's coin {} does not hold the token {} explicitly", op, i.limiter.token)));
			}
			// A round of the server's that spends the coin and is in no
			// block yet holds it: a second round minting from it would
			// spend it twice, and one of the two would be lost.
			for r in store.round_mints_spending(&op.txid.to_byte_array(), op.vout).await? {
				if store.round_by_txid(&r).await?.is_some_and(|row| row.state != crate::store::RoundState::Lost) {
					return Ok(LimiterAt::Unavailable(format!("the limiter's coin {} is spent by the round {}, which is in no block yet",
						op, Txid::from_byte_array(r))));
				}
			}
			return Ok(LimiterAt::Ready(LimiterNow { coin: op, txout, state, confirmations, is_final: made.is_final() }));
		}
		let made = finality.watch(op.txid, "limiter").await.map_err(|e| IssuerError::Chain(e.to_string()))?;
		if !made.in_chain() {
			return Ok(LimiterAt::Unavailable(format!("the limiter's coin {} is in no block of the chain", op)));
		}
		// Spent: by a round of the server's in the chain, or by whatever the
		// finality service saw spend the watched coin.
		let mut spender = None;
		for r in store.round_mints_spending(&op.txid.to_byte_array(), op.vout).await? {
			let t = Txid::from_byte_array(r);
			if finality.watch(t, "limiter").await.map_err(|e| IssuerError::Chain(e.to_string()))?.in_chain() {
				spender = Some(t);
			}
		}
		if spender.is_none() {
			if let Some(t) = store.outpoint_spender(&op.txid.to_byte_array(), op.vout).await? {
				let t = Txid::from_byte_array(t);
				if finality.watch(t, "limiter").await.map_err(|e| IssuerError::Chain(e.to_string()))?.in_chain() {
					spender = Some(t);
				}
			}
		}
		let Some(by) = spender else {
			return Ok(LimiterAt::Unavailable(format!("the limiter's coin {} is spent by a transaction the server has not seen yet", op)));
		};
		let tx = finality.call(move |n| n.transaction(&by)).await.map_err(chain)?
			.ok_or_else(|| IssuerError::Chain(format!("the node does not hold {}", by)))?;
		let k = tx.input.iter().position(|x| x.previous_output == op)
			.ok_or_else(|| IssuerError::Chain(format!("{} does not spend {}", by, op)))?;
		match i.limiter.follow(state, &tx, k) {
			Some(LimiterSpend::Recover) => return Ok(LimiterAt::Unavailable(format!("the cold key took the token out of the limiter in {}: \
				the asset has no limiter coin to mint from", by))),
			Some(s) => {
				state = s.next().expect("every path but the recovery has a successor");
				op = OutPoint::new(by, 0);
			},
			None => return Ok(LimiterAt::Unavailable(format!("{} spends the limiter's coin {} by no path of the covenant", by, op))),
		}
	}
	Ok(LimiterAt::Unavailable("the limiter's coin was followed too far".into()))
}

/// A mint the limiter allows now, or why it allows none: its coin, final,
/// unbraked and two blocks old or more, and the most it can mint from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintRoom {
	pub now: LimiterNow,
	pub age: u16,
	pub room: u64,
}

impl MintRoom {
	pub fn of(at: &LimiterAt, l: &LimiterParams) -> Result<MintRoom, String> {
		let now = match at {
			LimiterAt::Ready(n) => n.clone(),
			LimiterAt::Unavailable(why) => return Err(why.clone()),
		};
		if now.state.armed {
			return Err("the asset's mint limiter is braked: its cold key stopped every mint".into());
		}
		if !now.is_final {
			return Err(format!("the mint limiter's coin {} is not final yet: a round mints only from a final coin", now.coin));
		}
		let age = now.confirmations.min(u16::MAX as u64) as u16;
		if age < MIN_AGE {
			return Err(format!("the mint limiter's coin {} is {} block(s) old; a mint spends a coin {} blocks old or more", now.coin, age,
				MIN_AGE));
		}
		let room = l.room(now.state, age);
		Ok(MintRoom { now, age, room })
	}

	/// Why a round that mints `need` waits, when it does.
	pub fn wait(&self, l: &LimiterParams, need: u64) -> Option<String> {
		(need > self.room).then(|| format!("the asset's mint limiter allows {} more in its window now, and the round would mint {}; the \
			window ends in {} block(s), when {} more is allowed", self.room, need, l.blocks_to_new_window(self.now.state, self.age),
			l.allowance))
	}
}

/// Whether the operator burns every unit of `asset` it takes in: the asset is
/// served issuer-operated now, or a batch of it was made burn-only (units
/// minted for a refresh may still come back from it, whatever the asset is
/// served as since).
pub async fn burns(params: &crate::params::Params, store: &Store, asset: AssetId) -> Result<bool, StoreError> {
	if params.assets.get(&asset).is_some_and(|a| a.issuer.is_some()) {
		return Ok(true);
	}
	store.has_burn_batches(&asset.into_inner().to_byte_array()).await
}

// ---------------------------------------------------------------------------
// The signer's `reissue` request
// ---------------------------------------------------------------------------

/// The limiter's state on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireState {
	pub minted: String,
	pub elapsed: u16,
	pub armed: bool,
}

impl From<LimiterState> for WireState {
	fn from(s: LimiterState) -> WireState {
		WireState { minted: s.minted.to_string(), elapsed: s.elapsed, armed: s.armed }
	}
}

impl WireState {
	pub fn state(&self) -> Result<LimiterState, String> {
		Ok(LimiterState { minted: self.minted.parse().map_err(|e| format!("state.minted: {}", e))?, elapsed: self.elapsed, armed: self.armed })
	}
}

/// A leaf of a batch a mint funds: a `vtxo-1` leaf, as the tree builder
/// takes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireLeaf {
	pub owner: String,
	pub owner_nonce: String,
	pub operator_nonce: String,
	pub exit_delay_units: u16,
	pub value: String,
	pub unlock_hash: String,
}

/// A batch a mint funds, at output `vout`: everything the tree builder takes
/// but the asset (the minted one), the chain (the signer's) and the burn
/// (always).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireBatch {
	pub vout: u32,
	/// The clock schedule, in arca-covenant's canonical encoding.
	pub schedule: String,
	pub radix: u32,
	/// `fee_rate` (`a` the floor per 1,000 vbytes, `b` the multiple) or
	/// `fixed` (`a` a node's reserve, `b` an entry's).
	pub reserve: String,
	pub reserve_a: String,
	pub reserve_b: String,
	pub min_leaf: String,
	pub leaves: Vec<WireLeaf>,
}

/// An offboard output a mint funds, at output `vout`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireOffboard {
	pub vout: u32,
	pub unlock_hash: String,
	pub value: String,
	pub script: String,
	pub reclaim_delay_units: u16,
	pub margin: String,
}

/// What the signer is asked to mint: the round, unsigned at input 0, with
/// the output each input spends; the asset and its entropy; the limiter's
/// state; and every output of the asset the round pays, with what the
/// signer rebuilds it from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireReissue {
	pub tx: String,
	pub prevouts: Vec<String>,
	pub asset: String,
	pub entropy: String,
	pub state: WireState,
	pub batches: Vec<WireBatch>,
	pub offboards: Vec<WireOffboard>,
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
	if s.len() % 2 != 0 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
		return Err(format!("{:.16}…: not hex", s));
	}
	Ok((0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digits")).collect())
}

fn unhex32(s: &str) -> Result<[u8; 32], String> {
	unhex(s)?.try_into().map_err(|_| format!("{:.16}…: not 32 bytes", s))
}

fn amount(s: &str, what: &str) -> Result<u64, String> {
	s.parse().map_err(|e| format!("{}: {}", what, e))
}

impl WireBatch {
	/// The batch's parts as the tree builder takes them; refused unless every
	/// leaf is `vtxo-1`.
	pub fn of(vout: u32, params: &TreeParams, leaves: &[LeafSpec]) -> Result<WireBatch, String> {
		let (reserve, a, b) = match params.reserve {
			ReserveRule::FeeRate { floor_per_kvb, multiple } => ("fee_rate", floor_per_kvb, multiple),
			ReserveRule::Fixed { node, entry } => ("fixed", node, entry),
		};
		let mut out = vec![];
		for l in leaves {
			if l.template != Template::Vtxo1 || l.htlc.is_some() || l.order.is_some() {
				return Err(format!("an issuer-operated batch holds vtxo-1 leaves only, not {}", l.template));
			}
			out.push(WireLeaf {
				owner: hex(&l.owner.serialize()), owner_nonce: hex(&l.owner_nonce), operator_nonce: hex(&l.operator_nonce),
				exit_delay_units: l.exit_delay.units(), value: l.value.to_string(), unlock_hash: hex(&l.unlock_hash),
			});
		}
		Ok(WireBatch {
			vout, schedule: hex(&params.schedule.encode()), radix: params.radix as u32, reserve: reserve.into(),
			reserve_a: a.to_string(), reserve_b: b.to_string(), min_leaf: params.min_leaf.to_string(), leaves: out,
		})
	}

	/// The tree it builds, minting `asset` on `chain`, burn-only.
	pub fn tree(&self, asset: AssetId, chain: Chain) -> Result<Tree, String> {
		let schedule = ClockSchedule::decode(&unhex(&self.schedule)?).map_err(|e| format!("the schedule: {}", e))?;
		let (a, b) = (amount(&self.reserve_a, "reserve_a")?, amount(&self.reserve_b, "reserve_b")?);
		let reserve = match self.reserve.as_str() {
			"fee_rate" => ReserveRule::FeeRate { floor_per_kvb: a, multiple: b },
			"fixed" => ReserveRule::Fixed { node: a, entry: b },
			other => return Err(format!("reserve {:?}: fee_rate or fixed", other)),
		};
		let mut leaves = vec![];
		for l in &self.leaves {
			leaves.push(LeafSpec {
				template: Template::Vtxo1,
				owner: XOnlyPublicKey::from_slice(&unhex(&l.owner)?).map_err(|e| format!("owner: {}", e))?,
				value: amount(&l.value, "value")?,
				owner_nonce: unhex32(&l.owner_nonce)?,
				operator_nonce: unhex32(&l.operator_nonce)?,
				exit_delay: RelativeTime::from_units(l.exit_delay_units).map_err(|e| e.to_string())?,
				unlock_hash: unhex32(&l.unlock_hash)?,
				htlc: None,
				order: None,
				landing: None,
				channel: None,
			});
		}
		let params = TreeParams {
			asset, chain, schedule, burn: true, radix: self.radix as usize, reserve, min_leaf: amount(&self.min_leaf, "min_leaf")?,
		};
		Tree::build(params, &leaves).map_err(|e| format!("the batch at output {} does not build: {}", self.vout, e))
	}
}

impl WireOffboard {
	pub fn of(vout: u32, policy: &OffboardPolicy, margin: u64) -> WireOffboard {
		WireOffboard {
			vout, unlock_hash: hex(&policy.unlock_hash), value: policy.destination.value.to_string(),
			script: hex(policy.destination.script_pubkey.as_bytes()), reclaim_delay_units: policy.reclaim_delay.units(),
			margin: margin.to_string(),
		}
	}

	/// The output it builds under `operator`, paying `asset`.
	pub fn output(&self, asset: AssetId, operator: XOnlyPublicKey) -> Result<ExplicitOutput, String> {
		let policy = OffboardPolicy {
			unlock_hash: unhex32(&self.unlock_hash)?,
			destination: ExplicitOutput::new(asset, amount(&self.value, "value")?, elements::Script::from(unhex(&self.script)?)),
			operator,
			reclaim_delay: RelativeTime::from_units(self.reclaim_delay_units).map_err(|e| e.to_string())?,
		};
		Ok(policy.output(amount(&self.margin, "margin")?))
	}
}

impl WireReissue {
	/// The request for minting into `tx`, whose inputs spend `prevouts`.
	pub fn new(tx: &Transaction, prevouts: &[TxOut], asset: AssetId, entropy: [u8; 32], state: LimiterState, batches: Vec<WireBatch>,
		offboards: Vec<WireOffboard>) -> WireReissue
	{
		WireReissue {
			tx: hex(&serialize(tx)),
			prevouts: prevouts.iter().map(|p| hex(&serialize(p))).collect(),
			asset: asset.to_string(),
			// As an RPC prints it, the form the limiter's tool reads.
			entropy: elements::hashes::sha256::Midstate::from_byte_array(entropy).to_string(),
			state: state.into(),
			batches,
			offboards,
		}
	}
}

/// A mint the signer's checks passed.
#[derive(Debug, Clone)]
pub struct CheckedReissue {
	pub tx: Transaction,
	pub prevouts: Vec<TxOut>,
	pub amount: u64,
	pub age: u16,
	pub next: LimiterState,
}

/// The signer's checks on a mint, before it asks the limiter's tool to sign:
/// input 0 spends the limiter's coin in the state given and reissues the
/// asset, and no other input reissues it or spends a coin of it; every
/// output of the asset is a burn-only batch under `operator` on `chain`, or
/// an offboard under `operator`, each rebuilt here from its parts, and
/// together they hold exactly the amount reissued, so no unit of the asset
/// goes to change or a fee; output 0 is the limiter's successor; and the
/// mint fits the limiter's allowance.
pub fn check_reissue(chain: Chain, operator: XOnlyPublicKey, l: &LimiterParams, req: &WireReissue) -> Result<CheckedReissue, String> {
	let asset = AssetId::from_str(&req.asset).map_err(|e| format!("asset: {}", e))?;
	if asset != l.asset {
		return Err(format!("asset {} is not the limiter's {}", asset, l.asset));
	}
	let tx: Transaction = deserialize(&unhex(&req.tx)?).map_err(|e| format!("tx: {}", e))?;
	let mut prevouts = vec![];
	for p in &req.prevouts {
		prevouts.push(deserialize::<TxOut>(&unhex(p)?).map_err(|e| format!("prevouts: {}", e))?);
	}
	if prevouts.len() != tx.input.len() || tx.input.is_empty() {
		return Err(format!("{} spent outputs for {} inputs", prevouts.len(), tx.input.len()));
	}
	let state = req.state.state()?;
	let entropy = limiter::entropy_from_hex(&req.entropy).map_err(|e| e.to_string())?;
	if limiter::asset_of_entropy(entropy) != asset {
		return Err("the entropy issues another asset".into());
	}
	// Input 0: the limiter's coin, reissuing the asset.
	if prevouts[0].script_pubkey != l.script_pubkey(state) || prevouts[0].asset.explicit() != Some(l.token) {
		return Err(format!("input 0 does not spend the limiter's coin in state {:?}", state));
	}
	let reissuing = issuer::reissuing_inputs(&tx, asset);
	if reissuing != [0] {
		return Err(format!("the asset is reissued at input(s) {:?}; a mint reissues it at input 0 alone", reissuing));
	}
	let x = match tx.input[0].asset_issuance.amount {
		elements::confidential::Value::Explicit(x) if x > 0 => x,
		_ => return Err("input 0's reissued amount is not explicit".into()),
	};
	if let Some(i) = prevouts.iter().position(|p| p.asset.explicit() == Some(asset) || p.asset.explicit().is_none()) {
		return Err(format!("input {} spends a coin of the asset, or one that hides its asset: a mint's round pays the asset from the mint \
			alone", i));
	}
	// Every output of the asset: a batch or an offboard rebuilt here.
	let mut claimed: Vec<(u32, ExplicitOutput)> = vec![];
	for b in &req.batches {
		let tree = b.tree(asset, chain)?;
		if tree.params().schedule.operator != operator {
			return Err(format!("the batch at output {} names another operator key", b.vout));
		}
		claimed.push((b.vout, tree.batch_output()));
	}
	for o in &req.offboards {
		claimed.push((o.vout, o.output(asset, operator)?));
	}
	let mut seen = std::collections::BTreeSet::new();
	let mut total = 0u64;
	for (vout, want) in &claimed {
		if !seen.insert(*vout) {
			return Err(format!("output {} is named twice", vout));
		}
		let got = tx.output.get(*vout as usize).and_then(ExplicitOutput::from_txout);
		if got.as_ref() != Some(want) {
			return Err(format!("output {} is not the batch or offboard its parts build", vout));
		}
		total = total.checked_add(want.value).ok_or("the outputs overflow")?;
	}
	for (i, o) in tx.output.iter().enumerate() {
		let of_asset = o.asset.explicit() == Some(asset) || o.asset.explicit().is_none();
		if of_asset && !seen.contains(&(i as u32)) {
			return Err(format!("output {} pays the asset (or hides its asset) and is no batch or offboard of the mint", i));
		}
	}
	if total != x {
		return Err(format!("the round reissues {} and its batches and offboards hold {}", x, total));
	}
	// Output 0: the successor, in the state the mint leads to.
	let seq = tx.input[0].sequence.to_consensus_u32();
	if seq & (1 << 31 | 1 << 22) != 0 {
		return Err("input 0's sequence declares no age in blocks".into());
	}
	let age = (seq & 0xffff) as u16;
	let next = l.mint(state, age, x).map_err(|e| e.to_string())?;
	let succ = ExplicitOutput::new(l.token, prevouts[0].value.explicit().unwrap_or(0), l.script_pubkey(next));
	if tx.output.first().and_then(ExplicitOutput::from_txout) != Some(succ) {
		return Err("output 0 is not the limiter's successor".into());
	}
	Ok(CheckedReissue { tx, prevouts, amount: x, age, next })
}

/// Why the signer refuses to sign a spend that pays a unit of one of
/// `assets` anywhere but a bare `OP_RETURN`: the operator keeps nothing of an
/// asset it reissues.
pub fn check_spend_burns(assets: &[AssetId], tx: &Transaction) -> Result<(), String> {
	for (i, o) in tx.output.iter().enumerate() {
		match o.asset.explicit() {
			Some(a) if assets.contains(&a) && !issuer::is_burn(&o.script_pubkey) => {
				return Err(format!("output {} pays asset {}, which this signer reissues, to a script other than a burn: the operator keeps \
					no unit of it and pays no fee in it", i, a));
			},
			None if !o.asset.is_null() && !assets.is_empty() => {
				return Err(format!("output {} hides its asset", i));
			},
			_ => {},
		}
	}
	Ok(())
}

// ---------------------------------------------------------------------------
// The supply report
// ---------------------------------------------------------------------------

/// What the operator minted and burned of the issuer-operated `asset`, and
/// what is live in its burn-only batches now ([`crate::api::IssuerSupply`]):
/// every round's mint and every burn of the watcher's that the active chain
/// holds, each with its finality, and the value under burn-only sweeps.
pub async fn supply(store: &Store, finality: &FinalityService, asset: AssetId, i: &IssuerAsset)
	-> Result<crate::api::IssuerSupply, IssuerError>
{
	use crate::api::{IssuerSupply, SupplyEntry};
	let chain_err = |e: crate::chain::finality::FinalityError| IssuerError::Chain(e.to_string());
	let a = asset.into_inner().to_byte_array();
	let mut out = IssuerSupply {
		asset: asset.to_string(), limiter_coin: None, limiter_minted: None, limiter_elapsed: None, limiter_armed: None,
		limiter_unavailable: None, mints: vec![], burns: vec![], minted: String::new(), minted_final: String::new(),
		burned: String::new(), burned_final: String::new(), in_batches: String::new(),
	};
	match limiter_now(store, finality, asset, i).await? {
		LimiterAt::Ready(n) => {
			out.limiter_coin = Some(n.coin.to_string());
			out.limiter_minted = Some(n.state.minted.to_string());
			out.limiter_elapsed = Some(n.state.elapsed);
			out.limiter_armed = Some(n.state.armed);
		},
		LimiterAt::Unavailable(why) => out.limiter_unavailable = Some(why),
	}
	let (mut minted, mut minted_final, mut burned, mut burned_final) = (0u64, 0u64, 0u64, 0u64);
	for m in store.round_mints(&a).await? {
		let Some(r) = store.round(m.round_id).await? else { continue };
		let txid = Txid::from_byte_array(r.txid);
		let f = finality.watch(txid, "round").await.map_err(chain_err)?;
		if !f.in_chain() {
			continue;
		}
		minted = minted.saturating_add(m.amount);
		if f.is_final() {
			minted_final = minted_final.saturating_add(m.amount);
		}
		out.mints.push(SupplyEntry { txid: txid.to_string(), kind: "round".into(), amount: m.amount.to_string(), state: f.name().into() });
	}
	for w in store.watcher_log().await? {
		let Ok(tx) = deserialize::<Transaction>(&w.tx) else { continue };
		let b = issuer::burned(&tx, asset);
		if b == 0 {
			continue;
		}
		let txid = Txid::from_byte_array(w.txid);
		let f = finality.watch(txid, "watcher").await.map_err(chain_err)?;
		if !f.in_chain() {
			continue;
		}
		burned = burned.saturating_add(b);
		if f.is_final() {
			burned_final = burned_final.saturating_add(b);
		}
		out.burns.push(SupplyEntry { txid: txid.to_string(), kind: w.kind.clone(), amount: b.to_string(), state: f.name().into() });
	}
	let mut live = 0u64;
	for b in store.burn_batches(&a).await? {
		let Some(r) = store.round(b.round_id).await? else { continue };
		if !finality.watch(Txid::from_byte_array(r.txid), "round").await.map_err(chain_err)?.in_chain() {
			continue;
		}
		let mut candidates = vec![(OutPoint::new(Txid::from_byte_array(r.txid), b.vout), b.value)];
		for s in store.tree_sightings(b.round_id, b.vout).await? {
			candidates.push((OutPoint::new(Txid::from_byte_array(s.txid), s.vout), s.value));
		}
		let mut seen = std::collections::HashSet::new();
		for (op, value) in candidates {
			if !seen.insert(op) {
				continue;
			}
			if finality.call(move |n| n.unspent(&op, false)).await.map_err(|e| IssuerError::Chain(e.to_string()))?.is_some() {
				live = live.saturating_add(value);
			}
		}
	}
	out.minted = minted.to_string();
	out.minted_final = minted_final.to_string();
	out.burned = burned.to_string();
	out.burned_final = burned_final.to_string();
	out.in_batches = live.to_string();
	Ok(out)
}
