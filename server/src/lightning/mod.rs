//! The Lightning gateway: the operator's Lightning nodes.
//!
//! The operator runs one SeqLN node for each asset it serves over Lightning,
//! named beside the asset's pool, rate and fees in its configuration
//! (`[assets.lightning]`), and one Lightning node on Bitcoin for native BTC
//! (`[lightning.bitcoin]`). A payment between a leaf and Lightning is a
//! hash-lock on both sides under one hash, and its two sides are in one asset:
//! the node a payment in asset X goes through holds channels in X, and a leaf
//! in X never funds an invoice in another asset. No asset is preferred: each
//! has its own node, and none falls back on another's.
//!
//! The gateway checks each node every [`GatewayConfig::poll`] and before it
//! is first used: the node answers, runs on a Sequentia network (Bitcoin for
//! the Bitcoin node), and holds at least one open channel in its asset; the
//! hold-invoice plugin, which receiving needs, is noted. `info` names each
//! asset's leg and its state. A request in an asset the operator does not
//! serve, in a served asset with no node, or in one whose node is down is
//! refused at every entry with the reason ([`LegRefusal`]).
//!
//! Each node's channels are shared by every holder's payments and by the
//! legs of swaps, so one payment may use only part of them: at most
//! [`PaymentLimit::share_ppm`] of what the node can send (for a payment out
//! of the tree) or receive (for one into it), less a reserve kept for swaps
//! ([`PaymentLimit::reserve`]). `info` publishes the figure per asset and
//! direction (`max_payment`), and a payment above it is refused at its entry:
//! a send out of the tree, an invoice to receive into it. The Bitcoin node's
//! figure is published too, for the wallets that pay native BTC over it.

pub mod bolt11;
pub mod cln;
pub mod receive;
pub mod send;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use elements::AssetId;
use serde_json::{json, Value};
use tokio::task::JoinHandle;

use cln::{Cln, ClnError};

/// How long a health check waits on a node.
const CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// The networks a SeqLN node of an asset may run on.
pub const SEQUENTIA_NETWORKS: &[&str] = &["sequentia", "sequentia-testnet", "sequentia-regtest"];

/// The networks the Bitcoin node may run on.
pub const BITCOIN_NETWORKS: &[&str] = &["bitcoin", "testnet4", "testnet", "signet", "regtest"];

/// How much of a node's channels one payment may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentLimit {
	/// The share of what the node can carry, in a direction, less the
	/// reserve, one payment may use: in parts per million.
	pub share_ppm: u32,
	/// What the node keeps for swaps' legs in each direction, in the asset's
	/// atoms (satoshis for the Bitcoin node): no payment uses it.
	pub reserve: u64,
}

/// The share one payment may use where the configuration names none: a
/// tenth.
pub const DEFAULT_PAYMENT_SHARE_PPM: u32 = 100_000;

impl Default for PaymentLimit {
	fn default() -> PaymentLimit {
		PaymentLimit { share_ppm: DEFAULT_PAYMENT_SHARE_PPM, reserve: 0 }
	}
}

impl PaymentLimit {
	/// The most one payment may move over `capacity`: (capacity − reserve) ×
	/// share, rounded down.
	pub fn of(&self, capacity: u64) -> u64 {
		(capacity.saturating_sub(self.reserve) as u128 * self.share_ppm as u128 / 1_000_000) as u64
	}
}

/// An asset's node as the gateway is configured with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegConfig {
	pub asset: AssetId,
	/// The path of its `lightning-rpc` socket.
	pub rpc: PathBuf,
	pub limit: PaymentLimit,
}

/// What the gateway is configured with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayConfig {
	/// Each asset's node.
	pub legs: Vec<LegConfig>,
	/// The Bitcoin node, by its socket, and the Bitcoin ark it serves, if any.
	pub bitcoin: Option<BitcoinLegConfig>,
	/// How often every node is checked.
	pub poll: Duration,
	/// The chain's policy asset: SeqLN names no asset on a channel in it.
	pub policy_asset: Option<AssetId>,
}

/// The Bitcoin side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinLegConfig {
	pub rpc: PathBuf,
	pub limit: PaymentLimit,
	/// The Bitcoin ark the operator runs for native BTC, which wallets join
	/// with Bark; none when the operator runs none.
	pub ark: Option<String>,
}

/// What the last check found of a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegState {
	/// Not checked yet.
	Unknown,
	Up(NodeView),
	/// The node cannot carry a payment, and why.
	Down(String),
}

/// A node that answered and holds channels in its asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeView {
	pub node_id: String,
	pub network: String,
	/// Its open channels in the leg's asset.
	pub channels: u32,
	/// What it can send and receive over them now, in the asset's atoms.
	pub spendable: u64,
	pub receivable: u64,
	/// Whether it runs the hold-invoice plugin (`holdinvoice`), which
	/// receiving needs.
	pub holds: bool,
}

/// One node: an asset's, or the Bitcoin node (`asset` none).
#[derive(Debug)]
pub struct Leg {
	pub asset: Option<AssetId>,
	pub cln: Arc<Cln>,
	state: RwLock<LegState>,
	limit: RwLock<PaymentLimit>,
}

/// The most one payment may move over a node now, each way, in its atoms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxPayment {
	/// A payment out of the tree: the node sends it.
	pub send: u64,
	/// A payment into the tree: the node receives it.
	pub receive: u64,
}

impl Leg {
	fn new(asset: Option<AssetId>, rpc: PathBuf, limit: PaymentLimit) -> Arc<Leg> {
		Arc::new(Leg { asset, cln: Arc::new(Cln::new(rpc)), state: RwLock::new(LegState::Unknown), limit: RwLock::new(limit) })
	}

	pub fn state(&self) -> LegState {
		self.state.read().unwrap_or_else(|e| e.into_inner()).clone()
	}

	pub fn limit(&self) -> PaymentLimit {
		*self.limit.read().unwrap_or_else(|e| e.into_inner())
	}

	fn set_limit(&self, l: PaymentLimit) {
		*self.limit.write().unwrap_or_else(|e| e.into_inner()) = l;
	}

	/// The most one payment may move over the node, each way, at its last
	/// check: none while it is down.
	pub fn max_payment(&self) -> MaxPayment {
		match self.state() {
			LegState::Up(v) => {
				let l = self.limit();
				MaxPayment { send: l.of(v.spendable), receive: l.of(v.receivable) }
			},
			_ => MaxPayment { send: 0, receive: 0 },
		}
	}

	fn set(&self, s: LegState) {
		let mut cur = self.state.write().unwrap_or_else(|e| e.into_inner());
		if *cur != s {
			match (&*cur, &s) {
				(_, LegState::Down(why)) => log::warn!("lightning: {} is down: {}", self.name(), why),
				(LegState::Down(_) | LegState::Unknown, LegState::Up(v)) => log::info!("lightning: {} is up: node {} on {}, \
					{} channel(s), {} to send, {} to receive{}", self.name(), v.node_id, v.network, v.channels, v.spendable, v.receivable,
					if v.holds { "" } else { ", no hold-invoice plugin" }),
				_ => {},
			}
			*cur = s;
		}
	}

	/// Its name in a message: the asset's node, or the Bitcoin node.
	pub fn name(&self) -> String {
		match &self.asset {
			Some(a) => format!("the node of asset {}", a),
			None => "the Bitcoin node".into(),
		}
	}

	/// Asks the node what the leg needs of it ([`Gateway::check`]).
	async fn check(&self, policy_asset: Option<AssetId>) {
		let s = match self.view(policy_asset).await {
			Ok(v) => LegState::Up(v),
			Err(why) => LegState::Down(why),
		};
		self.set(s);
	}

	async fn view(&self, policy_asset: Option<AssetId>) -> Result<NodeView, String> {
		let info = self.cln.call("getinfo", json!({}), CHECK_TIMEOUT).await.map_err(|e| e.to_string())?;
		let node_id = info["id"].as_str().unwrap_or("").to_string();
		let network = info["network"].as_str().unwrap_or("").to_string();
		let allowed = if self.asset.is_some() { SEQUENTIA_NETWORKS } else { BITCOIN_NETWORKS };
		if !allowed.contains(&network.as_str()) {
			return Err(format!("it runs on network {:?}; {} runs on {}", network, self.name(),
				if self.asset.is_some() { "a Sequentia network" } else { "a Bitcoin network" }));
		}
		let chans = self.cln.call("listpeerchannels", json!({}), CHECK_TIMEOUT).await.map_err(|e| e.to_string())?;
		let mut channels = 0;
		let (mut spendable, mut receivable) = (0u64, 0u64);
		let mut elsewhere: BTreeMap<String, u32> = BTreeMap::new();
		for c in chans["channels"].as_array().into_iter().flatten() {
			if c["state"].as_str() != Some("CHANNELD_NORMAL") {
				continue;
			}
			let asset = channel_asset(c, policy_asset);
			if self.asset.is_none() || asset == self.asset.map(|a| a.to_string()) {
				channels += 1;
				spendable += c["spendable_msat"].as_u64().unwrap_or(0) / 1000;
				receivable += c["receivable_msat"].as_u64().unwrap_or(0) / 1000;
			} else {
				*elsewhere.entry(asset.unwrap_or_else(|| "an unnamed asset".into())).or_insert(0) += 1;
			}
		}
		if channels == 0 {
			let rest = if elsewhere.is_empty() {
				"it has none open".to_string()
			} else {
				format!("its open channels are in {}", elsewhere.iter().map(|(a, n)| format!("asset {} ({})", a, n)).collect::<Vec<_>>()
					.join(", "))
			};
			return Err(format!("node {} holds no open channel in {}: {}", node_id,
				self.asset.map(|a| format!("asset {}", a)).unwrap_or_else(|| "bitcoin".into()), rest));
		}
		let holds = match self.cln.call("holdinvoicelookup", json!({ "payment_hash": "00".repeat(32) }), CHECK_TIMEOUT).await {
			Ok(_) => true,
			Err(e) if e.answered() => false,
			Err(e) => return Err(e.to_string()),
		};
		Ok(NodeView { node_id, network, channels, spendable, receivable, holds })
	}
}

/// The asset of a channel as `listpeerchannels` shows it, display order: its
/// `channel_asset`, or the policy asset where SeqLN names none.
fn channel_asset(c: &Value, policy_asset: Option<AssetId>) -> Option<String> {
	c["channel_asset"].as_str().map(|s| s.to_lowercase()).or_else(|| policy_asset.map(|a| a.to_string()))
}

/// Why a request cannot go over Lightning in an asset.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LegRefusal {
	#[error("asset {0} is not served by this operator")]
	NotServed(AssetId),
	#[error("asset {0} is served, but has no Lightning leg here: the operator runs no Lightning node for it")]
	NoLeg(AssetId),
	#[error("{leg} cannot carry a payment now: {reason}")]
	Down { leg: String, reason: String },
	#[error("{0} runs no hold-invoice plugin, which receiving over Lightning needs")]
	NoHold(String),
	#[error("the operator runs no Lightning node on Bitcoin")]
	NoBitcoinLeg,
}

impl LegRefusal {
	/// The refusal's code: `out_of_bounds` for an asset not served, as
	/// everywhere else; `no_lightning` for one without a leg; and
	/// `lightning_unavailable` (a 503: asked again later, it may be taken)
	/// while the node is down.
	pub fn code(&self) -> &'static str {
		match self {
			LegRefusal::NotServed(_) => "out_of_bounds",
			LegRefusal::NoLeg(_) | LegRefusal::NoHold(_) | LegRefusal::NoBitcoinLeg => "no_lightning",
			LegRefusal::Down { .. } => "lightning_unavailable",
		}
	}
}

/// See the [module documentation](self).
pub struct Gateway {
	legs: RwLock<BTreeMap<AssetId, Arc<Leg>>>,
	bitcoin: Option<Arc<Leg>>,
	ark: Option<String>,
	poll: Duration,
	policy_asset: Option<AssetId>,
}

impl Gateway {
	pub fn new(config: &GatewayConfig) -> Arc<Gateway> {
		let legs = config.legs.iter().map(|l| (l.asset, Leg::new(Some(l.asset), l.rpc.clone(), l.limit))).collect();
		Arc::new(Gateway {
			legs: RwLock::new(legs),
			bitcoin: config.bitcoin.as_ref().map(|b| Leg::new(None, b.rpc.clone(), b.limit)),
			ark: config.bitcoin.as_ref().and_then(|b| b.ark.clone()),
			poll: config.poll,
			policy_asset: config.policy_asset,
		})
	}

	/// Takes the assets' nodes anew: a leg whose socket is unchanged keeps its
	/// state and takes its new limit; a new or changed one is checked at once.
	pub async fn reconfigure(&self, legs: &[LegConfig]) {
		let fresh: Vec<Arc<Leg>> = {
			let mut cur = self.legs.write().unwrap_or_else(|e| e.into_inner());
			let mut next = BTreeMap::new();
			let mut fresh = vec![];
			for c in legs {
				match cur.get(&c.asset) {
					Some(l) if l.cln.path() == c.rpc.as_path() => {
						l.set_limit(c.limit);
						next.insert(c.asset, l.clone());
					},
					_ => {
						let l = Leg::new(Some(c.asset), c.rpc.clone(), c.limit);
						fresh.push(l.clone());
						next.insert(c.asset, l);
					},
				}
			}
			*cur = next;
			fresh
		};
		for l in fresh {
			l.check(self.policy_asset).await;
		}
	}

	fn all(&self) -> Vec<Arc<Leg>> {
		let mut v: Vec<Arc<Leg>> = self.legs.read().unwrap_or_else(|e| e.into_inner()).values().cloned().collect();
		v.extend(self.bitcoin.clone());
		v
	}

	/// Checks every node now.
	pub async fn check(&self) {
		for l in self.all() {
			l.check(self.policy_asset).await;
		}
	}

	/// Checks every node at the configured interval.
	pub fn spawn(self: &Arc<Self>) -> JoinHandle<()> {
		let g = self.clone();
		tokio::spawn(async move {
			loop {
				g.check().await;
				tokio::time::sleep(g.poll).await;
			}
		})
	}

	/// The leg of `asset`, for a request: refused unless `served`, with a
	/// node, and that node up when last checked. A node that went down since
	/// fails the call the request makes, which says so too.
	pub fn leg(&self, asset: &AssetId, served: bool) -> Result<Arc<Leg>, LegRefusal> {
		if !served {
			return Err(LegRefusal::NotServed(*asset));
		}
		let leg = self.legs.read().unwrap_or_else(|e| e.into_inner()).get(asset).cloned().ok_or(LegRefusal::NoLeg(*asset))?;
		match leg.state() {
			LegState::Up(_) => Ok(leg),
			LegState::Down(reason) => Err(LegRefusal::Down { leg: leg.name(), reason }),
			LegState::Unknown => Err(LegRefusal::Down { leg: leg.name(), reason: "it has not been checked yet".into() }),
		}
	}

	/// The leg of `asset`, whatever its state: to resolve what its node
	/// already holds.
	pub fn any_leg(&self, asset: &AssetId) -> Option<Arc<Leg>> {
		self.legs.read().unwrap_or_else(|e| e.into_inner()).get(asset).cloned()
	}

	/// The leg of `asset` for a receive: [`Gateway::leg`], and its node runs
	/// the hold-invoice plugin.
	pub fn receiving_leg(&self, asset: &AssetId, served: bool) -> Result<Arc<Leg>, LegRefusal> {
		let leg = self.leg(asset, served)?;
		match leg.state() {
			LegState::Up(v) if !v.holds => Err(LegRefusal::NoHold(leg.name())),
			_ => Ok(leg),
		}
	}

	/// The Bitcoin node, up.
	pub fn bitcoin_leg(&self) -> Result<Arc<Leg>, LegRefusal> {
		let leg = self.bitcoin.clone().ok_or(LegRefusal::NoBitcoinLeg)?;
		match leg.state() {
			LegState::Up(_) => Ok(leg),
			LegState::Down(reason) => Err(LegRefusal::Down { leg: leg.name(), reason }),
			LegState::Unknown => Err(LegRefusal::Down { leg: leg.name(), reason: "it has not been checked yet".into() }),
		}
	}

	/// The leg `info` shows for `asset`; none when it has no node.
	pub fn asset_info(&self, asset: &AssetId) -> Option<crate::api::LightningLegInfo> {
		let leg = self.legs.read().unwrap_or_else(|e| e.into_inner()).get(asset).cloned()?;
		Some(leg_info(&leg))
	}

	/// What `info` shows of the Bitcoin side.
	pub fn bitcoin_info(&self) -> Option<crate::api::BitcoinLightningInfo> {
		let leg = self.bitcoin.as_ref()?;
		Some(crate::api::BitcoinLightningInfo { node: leg_info(leg), ark: self.ark.clone() })
	}
}

fn leg_info(leg: &Leg) -> crate::api::LightningLegInfo {
	let m = leg.max_payment();
	let max_payment = crate::api::MaxPaymentInfo { send: m.send.to_string(), receive: m.receive.to_string() };
	let limit = leg.limit();
	let payment_limit = crate::api::PaymentLimitInfo { share_ppm: limit.share_ppm, reserve: limit.reserve.to_string() };
	match leg.state() {
		LegState::Up(v) => crate::api::LightningLegInfo {
			state: "up".into(), node: Some(v.node_id), network: Some(v.network), channels: v.channels,
			spendable: v.spendable.to_string(), receivable: v.receivable.to_string(), max_payment, payment_limit, receives: v.holds,
			reason: None,
		},
		LegState::Down(why) => crate::api::LightningLegInfo {
			state: "down".into(), node: None, network: None, channels: 0, spendable: "0".into(), receivable: "0".into(), max_payment,
			payment_limit, receives: false, reason: Some(why),
		},
		LegState::Unknown => crate::api::LightningLegInfo {
			state: "down".into(), node: None, network: None, channels: 0, spendable: "0".into(), receivable: "0".into(), max_payment,
			payment_limit, receives: false, reason: Some("not checked yet".into()),
		},
	}
}

/// What a refusal from a node says, for a request that reached it.
pub fn node_error(leg: &Leg, e: &ClnError) -> LegRefusal {
	LegRefusal::Down { leg: leg.name(), reason: e.to_string() }
}
