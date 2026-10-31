//! The server, assembled: configuration, components, tasks and the HTTP
//! listener.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use elements::AssetId;
use serde::Deserialize;
use tokio::task::JoinHandle;

use arca_covenant::{BoardRecord, Chain, ConnectorPolicy, RelativeTime};
use sequentia_ext::rpc::{Auth, Client};

use crate::boards::Boards;
use crate::chain::{Certification, ChainSource, FinalityConfig, FinalityService, NodeSource};
use crate::cosign::Cosigner;
use crate::http::{router, App, Limiter};
use crate::nursery::Nursery;
use crate::params::{Amount, AssetFees, AssetParams, FeeSchedule, Params};
use crate::rates::{RateConfig, RateSource};
use crate::participations::Participations;
use crate::forfeits::Forfeits;
use crate::lightning::{BitcoinLegConfig, Gateway, GatewayConfig};
use crate::rounds::{RoundConfig, Rounds};
use crate::signer::{parse_amount, SignerClient};
use crate::store::Store;
use crate::wallet::{SpendFrom, Wallet, WalletConfig};
use crate::watcher::{Watcher, WatcherConfig};

/// The server's configuration, as `arcad` reads it from a TOML file.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
	/// Where the HTTP interface listens, `127.0.0.1:3535`. A reverse proxy in
	/// front terminates TLS.
	pub listen: String,
	/// The PostgreSQL connection string.
	pub database: String,
	/// The signer's socket (`arca-signer --socket`).
	pub signer_socket: PathBuf,
	/// A file holding the on-chain wallet's BIP39 mnemonic.
	pub wallet_mnemonic_file: PathBuf,
	/// The multiple of the node's relay floor the wallet pays.
	#[serde(default = "default_fee_multiple")]
	pub fee_multiple: u64,
	/// How many coins the wallet keeps each asset's pool in: a change worth
	/// two shares of the pool or more is split into shares
	/// ([`crate::wallet::WalletConfig::pool_coins`]).
	#[serde(default = "default_pool_coins")]
	pub pool_coins: u32,
	/// The largest request body read, in bytes.
	#[serde(default = "default_max_request")]
	pub max_request_bytes: usize,
	/// How long a challenge is good for, in seconds.
	#[serde(default = "default_challenge_ttl")]
	pub challenge_ttl_seconds: u64,
	/// How often a round is built when participations wait, in seconds; 0
	/// builds none on a timer (a round is then built by `Rounds::run_round`).
	#[serde(default = "default_round_interval")]
	pub round_interval_seconds: u64,
	pub node: NodeConfig,
	#[serde(default)]
	pub finality: FinalitySection,
	/// The exit delay bounds, in 512-second units; the specification's 36 to
	/// 48 hours when absent.
	#[serde(default)]
	pub exit_delay_units: Option<(u16, u16)>,
	/// The assets served, in the order `info` lists them; taken anew,
	/// without a restart, by [`Server::reload`].
	pub assets: Vec<AssetSection>,
	/// The assets a round's fee is paid in, in order of preference (display
	/// order ids); the served assets, in the order listed, when absent. A
	/// round carries one asset and pays in it when the node accepts it for
	/// fees and it is listed here, else in the first of these the node
	/// accepts.
	#[serde(default)]
	pub fee_assets: Option<Vec<String>>,
	/// What the operator charges for a refresh and an offboard; nothing when
	/// absent.
	#[serde(default)]
	pub fees: FeesSection,
	/// How the watcher works; the defaults when absent.
	#[serde(default)]
	pub watcher: WatcherSection,
	/// What the unauthenticated calls may leave behind; the defaults when
	/// absent.
	#[serde(default)]
	pub limits: LimitsSection,
	/// Where the operator's metrics are served (`GET /metrics`, the text
	/// format Prometheus reads), for the operator alone: a loopback address.
	/// None are served when absent.
	#[serde(default)]
	pub metrics_listen: Option<String>,
	/// The Lightning gateway beyond each asset's own node
	/// (`[assets.lightning]`): its Bitcoin node and how often the nodes are
	/// checked ([`crate::lightning`]).
	#[serde(default)]
	pub lightning: LightningSection,
	/// How takes of on-chain orders are bounded; the defaults when absent.
	#[serde(default)]
	pub fills: FillsSection,
	/// The operator's equivocation bond ([`crate::bond`]); none when absent.
	#[serde(default)]
	pub bond: Option<crate::bond::BondSection>,
	/// How batches are built; trees alone when absent.
	#[serde(default)]
	pub batches: BatchesSection,
}

/// How batches are built.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BatchesSection {
	/// The share of a batch's leaves, in millionths, the operator expects to
	/// leave on the chain on their own. Set, a batch is built as an
	/// accumulator batch when that many exits cost less from one than through
	/// a tree (up to about 7.6 % of 1,024 leaves); absent, every batch is a
	/// tree.
	#[serde(default)]
	pub accumulator_exit_rate_ppm: Option<u32>,
	/// The most batches of their own a round builds for holders that move
	/// their coins soon after they get them, so that each empties together
	/// and comes back early ([`RoundConfig::holder_batches`]); 8 when absent,
	/// 0 for none.
	#[serde(default)]
	pub holder_batches: Option<usize>,
	/// How young, in seconds, a coin given up must be for its holder to
	/// count as one that moves its coins soon; three days when absent.
	#[serde(default)]
	pub holder_window_seconds: Option<u32>,
	/// Whether new batches carry RECLAIM-D on their lowest nodes
	/// ([`RoundConfig::delegated_reclaim`]); off when absent. Set it only
	/// once every wallet the operator's holders use reads the leaf record's
	/// RECLAIM-D flag: one that does not refuses such a batch's leaves.
	#[serde(default)]
	pub delegated_reclaim: bool,
}

/// How takes of on-chain orders are bounded.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FillsSection {
	/// No order is taken, or filled in a round, whose maker can refund it
	/// within this many seconds: 21,600 (six hours) when absent.
	#[serde(default = "default_order_margin")]
	pub order_margin_seconds: u32,
	/// The seconds a block is counted at for an order whose REFUND is locked
	/// to a height: 60 when absent.
	#[serde(default = "default_order_block")]
	pub block_seconds: u32,
	/// How long a round that fills orders waits, from when it was built, for
	/// every take in it to hand over its forfeits before it is broadcast:
	/// 600 (ten minutes) when absent.
	#[serde(default = "default_fill_forfeit_window")]
	pub forfeit_window_seconds: u32,
}

impl Default for FillsSection {
	fn default() -> FillsSection {
		FillsSection {
			order_margin_seconds: default_order_margin(), block_seconds: default_order_block(),
			forfeit_window_seconds: default_fill_forfeit_window(),
		}
	}
}

fn default_fill_forfeit_window() -> u32 {
	crate::params::FILL_FORFEIT_WINDOW_SECONDS
}

fn default_order_margin() -> u32 {
	crate::params::ORDER_MARGIN_SECONDS
}

fn default_order_block() -> u32 {
	crate::params::ORDER_BLOCK_SECONDS
}

/// The gateway's settings beside the assets' own nodes.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LightningSection {
	/// How often every Lightning node is checked, in seconds.
	#[serde(default = "default_lightning_poll")]
	pub poll_seconds: u64,
	/// The operator's Lightning node on Bitcoin, for native BTC; none when
	/// absent.
	#[serde(default)]
	pub bitcoin: Option<BitcoinLightningSection>,
	/// The delay on the operator's claim of an `htlc-1` leaf, in 512-second
	/// units: the owner's refund waits longer.
	#[serde(default = "default_operator_delay")]
	pub operator_delay_units: u16,
	/// The least exit delay an `htlc-1` leaf of a payment out of the tree
	/// takes: the owner's refund delay, the operator's time to claim first.
	#[serde(default = "default_owner_delay")]
	pub owner_delay_units: u16,
	/// How far past the chain's median time the leaf's timeout lies, at
	/// least (at most twice that): longer than any payment takes to resolve.
	#[serde(default = "default_send_timeout")]
	pub send_timeout_seconds: u32,
	/// The chain's block interval, in seconds, which bounds a payment's lock
	/// times.
	#[serde(default = "default_block_seconds")]
	pub block_seconds: u32,
	/// How long one payment attempt runs, in seconds.
	#[serde(default = "default_retry_seconds")]
	pub retry_seconds: u32,
	/// The longest stall of the chain a payment out of the tree is safe
	/// through, in seconds: its lock times end this long, and half the rest,
	/// before its leaf's timeout. Below `send_timeout_seconds`.
	#[serde(default = "default_send_stall_margin")]
	pub send_stall_margin_seconds: u32,
	/// The time a wallet has to claim a leaf received over Lightning, past
	/// the leaf's exit delay, once its round is final.
	#[serde(default = "default_receive_window")]
	pub receive_window_seconds: u32,
	/// How long an invoice to receive over Lightning is good for.
	#[serde(default = "default_invoice_expiry")]
	pub invoice_expiry_seconds: u32,
	/// The most the leaves of payments received over Lightning and not yet
	/// claimed may hold in an asset, as a share of the operator's pool in
	/// it, in parts per million: a request beyond it is refused.
	#[serde(default = "default_receive_cap_ppm")]
	pub receive_cap_ppm: u32,
}

impl Default for LightningSection {
	fn default() -> LightningSection {
		LightningSection {
			poll_seconds: default_lightning_poll(), bitcoin: None, operator_delay_units: default_operator_delay(),
			owner_delay_units: default_owner_delay(), send_timeout_seconds: default_send_timeout(), block_seconds: default_block_seconds(),
			send_stall_margin_seconds: default_send_stall_margin(),
			retry_seconds: default_retry_seconds(), receive_window_seconds: default_receive_window(),
			invoice_expiry_seconds: default_invoice_expiry(), receive_cap_ppm: default_receive_cap_ppm(),
		}
	}
}

fn default_operator_delay() -> u16 {
	36
}

fn default_owner_delay() -> u16 {
	72
}

fn default_send_timeout() -> u32 {
	86_400
}

fn default_send_stall_margin() -> u32 {
	6 * 3600
}

fn default_block_seconds() -> u32 {
	60
}

fn default_retry_seconds() -> u32 {
	60
}

fn default_receive_window() -> u32 {
	6 * 3600
}

fn default_receive_cap_ppm() -> u32 {
	100_000
}

fn default_invoice_expiry() -> u32 {
	3600
}

fn default_lightning_poll() -> u64 {
	10
}

/// A Lightning node, by its JSON-RPC socket.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LegSection {
	/// The node's `lightning-rpc` socket.
	pub rpc: PathBuf,
}

/// The Bitcoin side: the Lightning node on Bitcoin, and the Bitcoin ark the
/// operator runs for native BTC.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BitcoinLightningSection {
	/// The node's `lightning-rpc` socket.
	pub rpc: PathBuf,
	/// The URL of the Bitcoin ark wallets join with Bark; none when the
	/// operator runs none.
	#[serde(default)]
	pub ark: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
	/// Operator nonces handed out per second at most, over every source
	/// together, and how many at once before that rate holds: a high bound on
	/// the rows nonces hold (the rate times their lifetime), set far above
	/// what honest callers ask, so a few sources cannot use it up.
	#[serde(default = "default_issue_per_second")]
	pub issue_per_second: u32,
	#[serde(default = "default_issue_burst")]
	pub issue_burst: u32,
	/// Operator nonces handed out to each source (an IPv4 address, an IPv6
	/// /48) per second at most, and how many at once: what keeps one caller
	/// from using up what every caller needs.
	#[serde(default = "default_source_per_second")]
	pub source_per_second: u32,
	#[serde(default = "default_source_burst")]
	pub source_burst: u32,
	/// The addresses of the reverse proxies in front: a request from one is
	/// counted against the address its `X-Forwarded-For` names, any other
	/// against the address that connected. Loopback when absent, for a proxy
	/// on the same machine.
	#[serde(default = "default_trusted_proxies")]
	pub trusted_proxies: Vec<String>,
	/// How long an operator nonce is good for: one no board took in that
	/// time is deleted, and a board naming it is refused.
	#[serde(default = "default_nonce_ttl")]
	pub nonce_ttl_seconds: u64,
	/// How long a board never credited may stay out of every block after it
	/// was registered before it is dropped.
	#[serde(default = "default_board_unconfirmed")]
	pub board_unconfirmed_seconds: u64,
	/// How often expired nonces are deleted.
	#[serde(default = "default_cleanup_interval")]
	pub cleanup_interval_seconds: u64,
	/// Witnesses of the signer's record answered per second at most, over
	/// every source together, and how many at once: a budget of the
	/// witness's own, apart from the nonces', set well under what the
	/// signer answers (about 2,500 witnesses of 32 heads it never saw a
	/// second, on a record of 200,000 entries, measured on a release build),
	/// so that witnesses leave co-signing its time. Each witness reads up to
	/// 32 running hashes under the signer's record lock and carries up to 34
	/// of its signatures.
	#[serde(default = "default_witness_per_second")]
	pub witness_per_second: u32,
	#[serde(default = "default_witness_burst")]
	pub witness_burst: u32,
	/// Witnesses answered to each source per second at most, and how many at
	/// once: a wallet makes one each command.
	#[serde(default = "default_witness_source_per_second")]
	pub witness_source_per_second: u32,
	#[serde(default = "default_witness_source_burst")]
	pub witness_source_burst: u32,
	/// The reads that serve a wallet what the server holds for it and what
	/// it publishes (`leaf_data`, `mailbox_read`, `tree`, `rounds`,
	/// `bind_mailbox`) answered per second at most, over every source
	/// together, and how many at once: each reads the database and may carry
	/// a page of records.
	#[serde(default = "default_read_per_second")]
	pub read_per_second: u32,
	#[serde(default = "default_read_burst")]
	pub read_burst: u32,
	/// Those reads answered to each source per second at most, and how many
	/// at once: a restore reads a page of leaves, a page of its mailbox and
	/// a tree for each round its leaves rest on.
	#[serde(default = "default_read_source_per_second")]
	pub read_source_per_second: u32,
	#[serde(default = "default_read_source_burst")]
	pub read_source_burst: u32,
}

impl Default for LimitsSection {
	fn default() -> LimitsSection {
		LimitsSection {
			issue_per_second: default_issue_per_second(), issue_burst: default_issue_burst(),
			source_per_second: default_source_per_second(), source_burst: default_source_burst(),
			trusted_proxies: default_trusted_proxies(),
			nonce_ttl_seconds: default_nonce_ttl(), board_unconfirmed_seconds: default_board_unconfirmed(),
			cleanup_interval_seconds: default_cleanup_interval(),
			witness_per_second: default_witness_per_second(), witness_burst: default_witness_burst(),
			witness_source_per_second: default_witness_source_per_second(), witness_source_burst: default_witness_source_burst(),
			read_per_second: default_read_per_second(), read_burst: default_read_burst(),
			read_source_per_second: default_read_source_per_second(), read_source_burst: default_read_source_burst(),
		}
	}
}

fn default_read_per_second() -> u32 {
	500
}

fn default_read_burst() -> u32 {
	2_000
}

fn default_read_source_per_second() -> u32 {
	10
}

fn default_read_source_burst() -> u32 {
	200
}

fn default_witness_per_second() -> u32 {
	250
}

fn default_witness_burst() -> u32 {
	1_000
}

fn default_witness_source_per_second() -> u32 {
	5
}

fn default_witness_source_burst() -> u32 {
	60
}

fn default_issue_per_second() -> u32 {
	250
}

fn default_issue_burst() -> u32 {
	10_000
}

fn default_source_per_second() -> u32 {
	1
}

fn default_source_burst() -> u32 {
	10
}

fn default_trusted_proxies() -> Vec<String> {
	vec!["127.0.0.1".into(), "::1".into()]
}

fn default_nonce_ttl() -> u64 {
	3600
}

fn default_board_unconfirmed() -> u64 {
	6 * 3600
}

fn default_cleanup_interval() -> u64 {
	60
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WatcherSection {
	/// Whether the watcher acts on its own, following the chain. Off, it acts
	/// only when `Watcher::pass` is called.
	#[serde(default = "default_true")]
	pub enabled: bool,
	/// Unroll the nodes above each lowest node all of whose owners have
	/// released it, and reclaim it, before the batch expires.
	#[serde(default = "default_true")]
	pub reclaim_early: bool,
	/// The most outputs one sweep takes.
	#[serde(default = "default_sweep_inputs")]
	pub max_sweep_inputs: usize,
	/// How often the recovery work runs when no block arrives, in seconds.
	#[serde(default = "default_recovery_interval")]
	pub recovery_interval_seconds: u64,
	/// The most forfeits one claim takes.
	#[serde(default = "default_claim_inputs")]
	pub max_claim_inputs: usize,
	/// How many vbytes of the watcher's own transactions may wait for a
	/// block before it publishes no new forfeit of a board.
	#[serde(default = "default_block_share")]
	pub block_share_vbytes: u64,
	/// The chain's block interval, in seconds.
	#[serde(default = "default_block_interval")]
	pub block_interval_seconds: u64,
	/// Bring every live coin of a released batch on the chain under its
	/// holder's key before the sweep.
	#[serde(default = "default_true")]
	pub unroll_at_release: bool,
	/// The watchtowers `info` lists for holders who name none of their own:
	/// base URLs, each `https://`.
	#[serde(default)]
	pub watchtowers: Vec<String>,
}

impl Default for WatcherSection {
	fn default() -> WatcherSection {
		WatcherSection {
			enabled: true, reclaim_early: default_true(), max_sweep_inputs: default_sweep_inputs(),
			recovery_interval_seconds: default_recovery_interval(), max_claim_inputs: default_claim_inputs(),
			block_share_vbytes: default_block_share(), block_interval_seconds: default_block_interval(), unroll_at_release: true,
			watchtowers: vec![],
		}
	}
}

fn default_true() -> bool {
	true
}

fn default_sweep_inputs() -> usize {
	WatcherConfig::default().max_sweep_inputs
}

fn default_recovery_interval() -> u64 {
	WatcherConfig::default().recovery_interval.as_secs()
}

fn default_claim_inputs() -> usize {
	WatcherConfig::default().max_claim_inputs
}

fn default_block_share() -> u64 {
	WatcherConfig::default().block_share_vbytes
}

fn default_block_interval() -> u64 {
	WatcherConfig::default().block_interval.as_secs()
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FeesSection {
	/// The most a refresh costs, in parts per million of the coin's value.
	#[serde(default)]
	pub refresh_ppm: u64,
	/// What an offboard costs, in parts per million of what it pays out, on
	/// top of the margin of its output.
	#[serde(default)]
	pub offboard_ppm: u64,
	/// What a payment over Lightning costs, either way, in parts per million
	/// of what it moves.
	#[serde(default)]
	pub lightning_ppm: u64,
	/// The most margin a co-signed transfer may leave for a fee, as a
	/// multiple of the least (four times the node's floor in an asset it
	/// accepts for fees, one atom in one it does not); 25 when absent.
	#[serde(default)]
	pub max_margin_multiple: Option<u64>,
}

fn default_fee_multiple() -> u64 {
	2
}

fn default_pool_coins() -> u32 {
	crate::wallet::POOL_COINS
}

fn default_max_request() -> usize {
	64 * 1024
}

fn default_challenge_ttl() -> u64 {
	120
}

fn default_round_interval() -> u64 {
	60
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
	/// `http://host:port/`
	pub rpc_url: String,
	/// The node's cookie file, or a user and password.
	#[serde(default)]
	pub cookie_file: Option<PathBuf>,
	#[serde(default)]
	pub rpc_user: Option<String>,
	#[serde(default)]
	pub rpc_password: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FinalitySection {
	#[serde(default = "default_anchor_depth")]
	pub anchor_depth: u32,
	/// `required`, or `none` on a chain with no committee.
	#[serde(default = "default_certification")]
	pub certification: String,
	#[serde(default)]
	pub start_height: Option<u64>,
	#[serde(default = "default_poll_ms")]
	pub poll_interval_ms: u64,
}

impl Default for FinalitySection {
	fn default() -> FinalitySection {
		FinalitySection {
			anchor_depth: default_anchor_depth(), certification: default_certification(), start_height: None,
			poll_interval_ms: default_poll_ms(),
		}
	}
}

fn default_anchor_depth() -> u32 {
	2
}

fn default_certification() -> String {
	"required".into()
}

fn default_poll_ms() -> u64 {
	1000
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AssetSection {
	/// The asset id, display order.
	pub asset: String,
	/// What a refresh and an offboard cost in the asset, in parts per
	/// million; `[fees]`' when absent.
	#[serde(default)]
	pub refresh_ppm: Option<u64>,
	#[serde(default)]
	pub offboard_ppm: Option<u64>,
	/// The fixed part of a refresh, for each coin given up, and of an
	/// offboard: in the asset's atoms, or (`_value`) as a value in atoms of
	/// the reference unit, converted at the asset's rate, which `rate` must
	/// then name a source for; nothing when absent. Decimal strings.
	#[serde(default)]
	pub refresh_base: Option<String>,
	#[serde(default)]
	pub refresh_base_value: Option<String>,
	#[serde(default)]
	pub offboard_base: Option<String>,
	#[serde(default)]
	pub offboard_base_value: Option<String>,
	/// What a payment over Lightning costs in the asset, either way: parts
	/// per million of what it moves (`[fees]`' when absent), and a fixed part,
	/// in atoms or as a value, as the other fixed parts.
	#[serde(default)]
	pub lightning_ppm: Option<u64>,
	#[serde(default)]
	pub lightning_base: Option<String>,
	#[serde(default)]
	pub lightning_base_value: Option<String>,
	/// The smallest leaf, in the asset's atoms, as a decimal string.
	#[serde(default)]
	pub min_leaf: Option<String>,
	/// Or the smallest leaf as a value, in atoms of the reference unit, as a
	/// decimal string: converted at the asset's rate, which `rate` must then
	/// name a source for.
	#[serde(default)]
	pub min_leaf_value: Option<String>,
	/// Where the asset's rate comes from ([`crate::rates`]); none when
	/// absent.
	#[serde(default)]
	pub rate: Option<RateSection>,
	/// The operator's SeqLN node in the asset, its Lightning leg; none when
	/// absent, and then nothing in the asset goes over Lightning here.
	#[serde(default)]
	pub lightning: Option<LegSection>,
	/// The asset's mint limiter, when the operator serves it issuer-operated
	/// ([`crate::issuer`]); none for an asset whose batches the operator funds
	/// from its own coins.
	#[serde(default)]
	pub issuer: Option<crate::issuer::IssuerSection>,
	/// The supervised profile's settings ([`crate::supervision`]). An asset
	/// the node lists as supervised is served under the profile whether or
	/// not its section names one; one that names one and is not supervised
	/// on the chain is refused.
	#[serde(default)]
	pub supervised: Option<SupervisedSection>,
	/// The most the operator puts on its own side of a `channel-1` leaf in
	/// the asset ([`crate::channels`]), in its atoms, or (`_value`) as a
	/// value in atoms of the reference unit, converted at the asset's rate;
	/// decimal strings. No channel leaf of the asset is made when absent.
	#[serde(default)]
	pub channel_capacity: Option<String>,
	#[serde(default)]
	pub channel_capacity_value: Option<String>,
	/// The most of the asset the operator fronts for refreshes whose old
	/// coins have not come back yet, in its atoms, or (`_value`) as a value in
	/// atoms of the reference unit, converted at the asset's rate; decimal
	/// strings. A refresh beyond it waits for a later round. No cap when
	/// absent; `"0"` fronts nothing, for an asset whose pool is empty.
	#[serde(default)]
	pub in_flight_cap: Option<String>,
	#[serde(default)]
	pub in_flight_cap_value: Option<String>,
	/// The restricted profile ([`crate::restricted`]): the asset is a
	/// restricted asset its issuer serves in this tree, and its policy server
	/// co-signs beside the operator.
	#[serde(default)]
	pub restricted: Option<RestrictedSection>,
}

/// A restricted asset's policy server.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct RestrictedSection {
	/// The policy server's base URL, as `http://host:port`.
	pub policy_server: String,
	/// The file holding the issuer's token for the policy server's issuer
	/// calls, readable by the operator alone.
	pub token_file: String,
}

/// A supervised asset's settings.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct SupervisedSection {
	/// The fee allowance every `landing-1` leaf of the asset carries, in its
	/// atoms, as a decimal string: the most of a leaf's value its landing may
	/// leave out of the output it pays the owner. When absent, four times the
	/// node's fee floor in the asset for a landing when the server starts,
	/// or none where the node takes no fees in the asset (a landing then
	/// pays its fee from a coin of another asset).
	#[serde(default)]
	pub landing_allowance: Option<String>,
}

impl AssetSection {
	/// `asset`, its smallest leaf `min_leaf` atoms, and no rate.
	pub fn new(asset: impl ToString, min_leaf: u64) -> AssetSection {
		AssetSection {
			asset: asset.to_string(), refresh_ppm: None, offboard_ppm: None, refresh_base: None, refresh_base_value: None,
			offboard_base: None, offboard_base_value: None, min_leaf: Some(min_leaf.to_string()), min_leaf_value: None, rate: None,
			lightning: None, lightning_ppm: None, lightning_base: None, lightning_base_value: None, issuer: None, supervised: None,
			channel_capacity: None, channel_capacity_value: None, in_flight_cap: None, in_flight_cap_value: None, restricted: None,
		}
	}
}

/// An asset's rate source ([`crate::rates`]).
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RateSection {
	/// `node` (the node's own rate for the asset), `file` or `command`.
	pub source: String,
	/// The file a `file` source reads.
	#[serde(default)]
	pub path: Option<PathBuf>,
	/// The program and its arguments a `command` source runs.
	#[serde(default)]
	pub command: Option<Vec<String>>,
	/// How long a rate is good for, in seconds from its time; an hour when
	/// absent.
	#[serde(default = "default_rate_max_age")]
	pub max_age_seconds: u64,
}

fn default_rate_max_age() -> u64 {
	3_600
}

impl RateSection {
	/// The source this names, checked.
	fn config(&self) -> Result<RateConfig, String> {
		let source = match (self.source.as_str(), &self.path, &self.command) {
			("node", None, None) => RateSource::Node,
			("file", Some(p), None) => RateSource::File(p.clone()),
			("command", None, Some(c)) if !c.is_empty() => RateSource::Command(c.clone()),
			("node", ..) => return Err("source \"node\" takes neither path nor command".into()),
			("file", ..) => return Err("source \"file\" takes a path, and no command".into()),
			("command", ..) => return Err("source \"command\" takes a command, a program and its arguments, and no path".into()),
			(other, ..) => return Err(format!("source {:?}: node, file or command", other)),
		};
		if self.max_age_seconds == 0 {
			return Err("max_age_seconds is at least 1".into());
		}
		Ok(RateConfig { source, max_age: self.max_age_seconds })
	}
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct StartError(pub String);

fn err<E: std::fmt::Display>(what: &str) -> impl Fn(E) -> StartError + '_ {
	move |e| StartError(format!("{}: {}", what, e))
}

/// The node's RPC client, as the configuration names it.
fn node_client(config: &Config) -> Result<Client, StartError> {
	let auth = match (&config.node.cookie_file, &config.node.rpc_user, &config.node.rpc_password) {
		(Some(c), _, _) => Auth::CookieFile(c.clone()),
		(None, Some(u), Some(p)) => Auth::UserPass(u.clone(), p.clone()),
		_ => return Err(StartError("the node needs cookie_file, or rpc_user and rpc_password".into())),
	};
	Ok(Client::new(config.node.rpc_url.clone(), auth))
}

/// The salts the signer's record no longer needs: each leaf whose coin rests
/// on batches alone, every one of them past its last expiry at the tip the
/// database followed, and its checkpoint's. A batch past its last expiry is
/// swept, and the server serves none of its coins; a coin resting on a board
/// is never dropped. What `arca-signer --compact-into` drops; `arcad
/// <config> expired-salts` prints them, one hex salt a line. It needs the
/// database alone.
pub async fn expired_salts(config: &Config) -> Result<Vec<[u8; 32]>, StartError> {
	use arca_covenant::CoinRecord;
	fn last_expiry(r: &CoinRecord) -> Option<u32> {
		match r {
			CoinRecord::Board(_) => None,
			CoinRecord::Leaf { record, .. } => Some(record.schedule.expiries().last().map(|e| e.to_consensus_u32()).unwrap_or(u32::MAX)),
			CoinRecord::Accumulator { record, .. } => Some(record.schedule.expiries().last().map(|e| e.to_consensus_u32()).unwrap_or(u32::MAX)),
			CoinRecord::Transfer(_) | CoinRecord::Fill(_) => r.parents().into_iter().map(last_expiry).try_fold(0u32, |m, e| e.map(|e| m.max(e))),
		}
	}
	let store = Store::connect(&config.database).await.map_err(err("the database"))?;
	let now = store.tip_block().await.map_err(err("the database"))?
		.ok_or_else(|| StartError("the database has followed no block yet".into()))?.median_time;
	let mut out = vec![];
	for (salt, record) in store.leaf_salts().await.map_err(err("the database"))? {
		let Ok(record) = CoinRecord::from_bytes(&record) else { continue };
		if last_expiry(&record).is_some_and(|e| (e as u64) < now) {
			out.push(salt);
			out.push(arca_covenant::transfer::checkpoint_salt(&salt));
		}
	}
	Ok(out)
}

/// A receive address of the operator's on-chain wallet, handed out and
/// recorded in the database ([`Wallet::hand_out_receive_script`]): what the
/// operator pays to fund the wallet. Its index, its script, and its address
/// as the node writes it (unblinded). It needs the database, the mnemonic
/// file and the node, and neither the signer nor a running server, so
/// `arcad <config> address` may run beside the server or before its first
/// start. The server follows the chain from where it first started, so a
/// coin is found only in a block it connects after the address was handed
/// out and after that first start.
pub async fn receive_address(config: &Config) -> Result<(u32, elements::Script, String), StartError> {
	let store = Store::connect(&config.database).await.map_err(err("the database"))?;
	let mnemonic = std::fs::read_to_string(&config.wallet_mnemonic_file)
		.map_err(err("wallet_mnemonic_file"))?.trim().to_string();
	let (index, script) = Wallet::hand_out_receive_script(&store, &mnemonic).await.map_err(err("the wallet"))?;
	let client = node_client(config)?;
	let hex: String = script.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
	let decoded = tokio::task::spawn_blocking(move || client.call::<serde_json::Value>("decodescript", &[serde_json::json!(hex)]))
		.await.map_err(err("the node"))?.map_err(err("the node"))?;
	let address = decoded["address"].as_str().or_else(|| decoded["segwit"]["address"].as_str())
		.ok_or_else(|| StartError(format!("the node gave no address for the wallet's script: {}", decoded)))?;
	Ok((index, script, address.to_string()))
}

/// The bond the configuration names, for the operator key the signer holds,
/// on the node's chain: what the bond commands work on.
async fn configured_bond(config: &Config) -> Result<(crate::bond::Bond, Client), StartError> {
	let section = config.bond.as_ref().ok_or_else(|| StartError("the configuration has no [bond] section".into()))?;
	let client = node_client(config)?;
	let c = client.clone();
	let genesis = tokio::task::spawn_blocking(move || c.genesis_hash()).await.map_err(err("the node"))?.map_err(err("the node"))?;
	let operator = SignerClient::new(&config.signer_socket).pubkey().await.map_err(err("the signer"))?;
	let max_exit = match config.exit_delay_units {
		Some((_, max)) => RelativeTime::from_units(max).map_err(err("exit_delay_units"))?,
		None => Params::new(Chain::new(genesis), operator, BTreeMap::new()).max_exit_delay,
	};
	let bond = crate::bond::Bond::from_section(section, Chain::new(genesis), operator,
		RoundConfig::default().lifetime.max(Params::BOARD_LIFETIME), max_exit).map_err(|e| StartError(format!("bond: {}", e)))?;
	Ok((bond, client))
}

/// The address the node writes for `script` (unblinded).
async fn address_of(client: &Client, script: &elements::Script) -> Result<String, StartError> {
	let hex: String = script.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
	let c = client.clone();
	let decoded = tokio::task::spawn_blocking(move || c.call::<serde_json::Value>("decodescript", &[serde_json::json!(hex)]))
		.await.map_err(err("the node"))?.map_err(err("the node"))?;
	decoded["address"].as_str().or_else(|| decoded["segwit"]["address"].as_str()).map(str::to_string)
		.ok_or_else(|| StartError(format!("the node gave no address for the script: {}", decoded)))
}

/// `arcad <config> bond-address`: the bond's terms and the address that
/// posts it, as JSON. It needs the node and the signer (for `S`).
pub async fn bond_address(config: &Config) -> Result<serde_json::Value, StartError> {
	let (bond, client) = configured_bond(config).await?;
	let p = bond.policy;
	let hex = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
	Ok(serde_json::json!({
		"address": address_of(&client, &p.script_pubkey()).await?,
		"script_pubkey": hex(p.script_pubkey().as_bytes()),
		"notice_script_pubkey": hex(p.notice_script_pubkey().as_bytes()),
		"operator": hex(&p.operator.serialize()),
		"withdraw_key": hex(&p.withdraw.serialize()),
		"notice_units": p.notice.units(),
		"notice_seconds": p.notice.seconds(),
	}))
}

/// What shows the operator key has already signed two messages under one
/// salt, or that its signer would: the salts the signer's record holds two
/// different digests under, and the leaves the database holds
/// operator-signed forfeits of for more than one round (a signer that let a
/// lost round's participation run again with a second forfeit, before it
/// kept one message per salt, left both), each such pair burning any bond
/// under the key in the hands of whoever holds the database or a backup of
/// it; and a record an older signer compacted, which kept no salt it
/// dropped, so the signer would sign under one again. Empty when there is
/// none.
pub async fn signed_twice(config: &Config) -> Result<Vec<String>, StartError> {
	let mut out = vec![];
	let signer = SignerClient::new(&config.signer_socket);
	let record = signer.record().await.map_err(err("the signer"))?;
	if record.salts_lost {
		out.push(format!("the signer's record is a compaction of format {} by an older signer, which kept no salt it dropped, so the \
			signer would sign again under one: compact it again (arca-signer --compact-into, with arcad expired-salts), which keeps \
			them", record.format));
	}
	let mut seen: std::collections::HashMap<[u8; 32], [u8; 32]> = std::collections::HashMap::new();
	let mut twice: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
	let mut after = 0u64;
	loop {
		let page = signer.entries(after).await.map_err(err("the signer"))?;
		let Some(last) = page.last() else { break };
		after = last.n;
		for e in &page {
			match seen.get(&e.salt) {
				Some(d) if *d != e.digest => {
					twice.insert(e.salt);
				},
				Some(_) => {},
				None => {
					seen.insert(e.salt, e.digest);
				},
			}
		}
	}
	if let Some(first) = twice.iter().next() {
		out.push(format!("the signer's record holds two different messages under {} salt(s), {} the first",
			twice.len(), crate::signer::hex(first)));
	}
	let store = Store::connect(&config.database).await.map_err(err("the database"))?;
	let (leaves, total) = store.leaves_forfeited_twice(1).await.map_err(err("the database"))?;
	if let Some(first) = leaves.first() {
		out.push(format!("the database holds operator-signed forfeits for more than one round of {} leaf (leaves), {} the first",
			total, crate::signer::hex(first)));
	}
	Ok(out)
}

/// `arcad <config> bond-post <wallet> <asset> <atoms> [<fee asset>]`: pays
/// `atoms` of `asset` to the bond's address from the node wallet `wallet`,
/// explicitly, the fee in `fee_asset` (the bond's own asset when not named,
/// as a wallet pays: never a fall-back to another), and returns the bond
/// coin and the line that names it in `[bond]`. A treasury's, a reserve's,
/// a bridge's, an escrow's or another service's wallet is refused by name,
/// and nothing is paid while the operator key has already signed two
/// messages under one salt ([`signed_twice`]): such a bond is burned by
/// whoever holds them.
pub async fn bond_post(config: &Config, wallet: &str, asset: AssetId, atoms: u64, fee_asset: Option<AssetId>)
	-> Result<serde_json::Value, StartError>
{
	if let Some(why) = crate::bond::refused_wallet(wallet) {
		return Err(StartError(format!("{} is {} wallet: a bond is never posted from one; name an operating wallet", wallet, why)));
	}
	if atoms == 0 {
		return Err(StartError("a bond holds at least one atom".into()));
	}
	let (bond, client) = configured_bond(config).await?;
	let twice = signed_twice(config).await?;
	if !twice.is_empty() {
		return Err(StartError(format!("the operator key has already signed two messages under one salt, or its signer would: {}; \
			a bond under this key would be anyone's to burn who holds them, so none is posted", twice.join("; "))));
	}
	let spk = bond.policy.script_pubkey();
	let address = address_of(&client, &spk).await?;
	let auth = match (&config.node.cookie_file, &config.node.rpc_user, &config.node.rpc_password) {
		(Some(c), _, _) => Auth::CookieFile(c.clone()),
		(None, Some(u), Some(p)) => Auth::UserPass(u.clone(), p.clone()),
		_ => return Err(StartError("the node needs cookie_file, or rpc_user and rpc_password".into())),
	};
	let url = format!("{}/wallet/{}", config.node.rpc_url.trim_end_matches('/'), wallet);
	let w = Client::new(url, auth);
	let amount = format!("{}.{:08}", atoms / 100_000_000, atoms % 100_000_000);
	let fee = fee_asset.unwrap_or(asset).to_string();
	let params = vec![serde_json::json!(address), serde_json::json!(amount), serde_json::json!(""), serde_json::json!(""),
		serde_json::json!(false), serde_json::Value::Null, serde_json::Value::Null, serde_json::json!("unset"), serde_json::Value::Null,
		serde_json::json!(asset.to_string()), serde_json::json!(true), serde_json::Value::Null, serde_json::json!(fee)];
	let txid: String = tokio::task::spawn_blocking(move || w.call::<String>("sendtoaddress", &params))
		.await.map_err(err("the node"))?.map_err(err(&format!("the node wallet {}", wallet)))?;
	let txid = elements::Txid::from_str(&txid).map_err(err("the node's txid"))?;
	let c = client.clone();
	let tx = tokio::task::spawn_blocking(move || c.raw_transaction(&txid)).await.map_err(err("the node"))?.map_err(err("the node"))?;
	let vout = tx.output.iter().position(|o| o.script_pubkey == spk && o.asset.explicit() == Some(asset) && o.value.explicit() == Some(atoms))
		.ok_or_else(|| StartError(format!("{} pays no explicit {} of {} to the bond's script", txid, atoms, asset)))?;
	let outpoint = format!("{}:{}", txid, vout);
	Ok(serde_json::json!({"txid": txid.to_string(), "vout": vout, "outpoint": outpoint, "asset": asset.to_string(),
		"value": atoms.to_string(), "address": address, "wallet": wallet, "fee_asset": fee,
		"config": format!("outpoint = \"{}\"", outpoint)}))
}

/// What the notice and the withdrawal need: the store, the chain, the
/// operator's on-chain wallet (which pays their fees) and the bond.
async fn bond_spender(config: &Config) -> Result<(crate::bond::Bond, Arc<FinalityService>, Wallet), StartError> {
	let (bond, client) = configured_bond(config).await?;
	let store = Store::connect(&config.database).await.map_err(err("the database"))?;
	let source: Arc<dyn ChainSource> = Arc::new(NodeSource::new(client));
	let certification = match config.finality.certification.as_str() {
		"required" => Certification::Required,
		"none" => Certification::NotOnThisChain,
		other => return Err(StartError(format!("finality.certification {:?}: required or none", other))),
	};
	let finality = FinalityService::new(store.clone(), source, FinalityConfig {
		anchor_depth: config.finality.anchor_depth, certification, start_height: config.finality.start_height,
		poll_interval: Duration::from_millis(config.finality.poll_interval_ms), cert_lookback: 144,
	}).await.map_err(err("the finality service"))?;
	let mnemonic = std::fs::read_to_string(&config.wallet_mnemonic_file).map_err(err("wallet_mnemonic_file"))?.trim().to_string();
	// This process follows no chain of its own, so it reads the running
	// server's view from the database and takes a fee coin once its block is
	// in the chain: the operator's own transaction.
	let wallet = Wallet::new(store, finality.clone(), bond.policy.operator,
		WalletConfig { mnemonic, fee_multiple: config.fee_multiple, spend_from: SpendFrom::Confirmed, pool_coins: config.pool_coins }).map_err(err("the wallet"))?;
	Ok((bond, finality, wallet))
}

/// The fee assets the bond's spends pay in, in order: the bond's own asset,
/// then the configuration's fee assets, then the served assets.
fn bond_fee_assets(config: &Config, asset: AssetId) -> Vec<AssetId> {
	let mut out = vec![asset];
	let listed = config.fee_assets.clone().unwrap_or_default().into_iter().chain(config.assets.iter().map(|a| a.asset.clone()));
	for a in listed.filter_map(|a| AssetId::from_str(&a).ok()) {
		if !out.contains(&a) {
			out.push(a);
		}
	}
	out
}

/// Signs input 0 of `k` with `w`, gives input 1 a stand-in for the wallet's
/// signature, and returns the transaction, its id and its virtual size once
/// signed.
fn bond_spend_signed(k: arca_covenant::spend::KeySpend, w: &elements::secp256k1_zkp::Keypair, genesis: elements::BlockHash)
	-> Result<(elements::Transaction, elements::Txid, u64), String>
{
	let mut aux = [0u8; 32];
	rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut aux);
	let sig = arca_covenant::sign::sign_digest(w, &k.sighash(genesis).map_err(|e| e.to_string())?, &aux);
	let u = k.finish(vec![sig.as_ref().to_vec()]);
	let mut sized = u.tx.clone();
	if sized.input.len() > 1 {
		sized.input[1].witness.script_witness = vec![vec![0; 72], vec![0; 33]];
	}
	let vsize = (sized.weight() as u64).div_ceil(4);
	Ok((u.tx.clone(), u.tx.txid(), vsize))
}

/// Reads `W`'s key from its file, which only its owner may read, and checks
/// it is the bond's.
fn withdraw_key(path: &std::path::Path, bond: &crate::bond::Bond) -> Result<elements::secp256k1_zkp::Keypair, StartError> {
	use std::os::unix::fs::PermissionsExt;
	let meta = std::fs::metadata(path).map_err(err(&path.display().to_string()))?;
	if meta.permissions().mode() & 0o077 != 0 {
		return Err(StartError(format!("{} is readable by others than its owner; chmod 600 it", path.display())));
	}
	let text = std::fs::read_to_string(path).map_err(err(&path.display().to_string()))?;
	let secret = crate::signer::unhex32(text.trim()).map_err(err(&path.display().to_string()))?;
	let key = elements::secp256k1_zkp::Keypair::from_seckey_slice(&elements::secp256k1_zkp::Secp256k1::new(), &secret)
		.map_err(err(&path.display().to_string()))?;
	if key.x_only_public_key().0 != bond.policy.withdraw {
		return Err(StartError(format!("{} holds the key {}, and the bond's withdrawal key is {}", path.display(),
			key.x_only_public_key().0, bond.policy.withdraw)));
	}
	Ok(key)
}

/// Builds the spend `make` makes with a fee coin of the operator's wallet,
/// signs it and broadcasts it.
async fn bond_spend<F>(config: &Config, finality: &Arc<FinalityService>, wallet: &Wallet, asset: AssetId, w: &elements::secp256k1_zkp::Keypair,
	make: F) -> Result<elements::Transaction, StartError>
where
	F: Fn(&arca_covenant::FeeSource) -> Result<arca_covenant::spend::KeySpend, String>,
{
	let genesis = finality.call(|c| c.genesis()).await.map_err(err("the node"))?;
	let (mut tx, coin, _) = wallet.with_fee_coin(&bond_fee_assets(config, asset), |fee| bond_spend_signed(make(fee)?, w, genesis))
		.await.map_err(err("the operator's wallet"))?;
	wallet.sign_input(&mut tx, 1, &coin).map_err(err("the operator's wallet"))?;
	let t = tx.clone();
	if let Err(e) = finality.call(move |c| c.broadcast(&t)).await {
		let _ = wallet.release(&tx.txid()).await;
		return Err(StartError(format!("the node refused {}: {}", tx.txid(), e)));
	}
	Ok(tx)
}

/// `arcad <config> withdraw <asset> <atoms> <address> [<fee asset>]`: pays
/// `atoms` of `asset` from the operator's on-chain wallet to `address`, its
/// fee in `fee asset` (the asset itself when not named): what moves a pool
/// grown past its need back to the treasury that funded it. It spends final
/// coins only, as a round does, and never more than the wallet can spend now
/// less what it owes for swept coins (`fundable` in `/v1/info`), so no coin a
/// holder is owed leaves. The coins it takes are marked spent in the database
/// all or none, so it runs beside the server: a round never takes them, and
/// it never takes a round's. Needs the database, the mnemonic file, the node
/// and the signer.
pub async fn withdraw(config: &Config, asset: &str, atoms: &str, to: &str, fee_asset: Option<&str>) -> Result<serde_json::Value, StartError> {
	use crate::wallet::BuildRequest;
	let asset = AssetId::from_str(asset).map_err(err("the asset"))?;
	let fee_asset = match fee_asset {
		Some(f) => AssetId::from_str(f).map_err(err("the fee asset"))?,
		None => asset,
	};
	let atoms: u64 = atoms.parse().map_err(err("the atoms"))?;
	if atoms == 0 {
		return Err(StartError("nothing to withdraw: 0 atoms".into()));
	}
	let client = node_client(config)?;
	let addr = to.to_string();
	let c = client.clone();
	let info = tokio::task::spawn_blocking(move || c.call::<serde_json::Value>("validateaddress", &[serde_json::json!(addr)]))
		.await.map_err(err("the node"))?.map_err(err("the node"))?;
	if info["isvalid"] != serde_json::json!(true) {
		return Err(StartError(format!("{} is not an address of this chain", to)));
	}
	if info.get("confidential_key").and_then(|k| k.as_str()).is_some_and(|k| !k.is_empty()) {
		return Err(StartError(format!("{} is a confidential address; the wallet pays explicit outputs: give its unconfidential one", to)));
	}
	let spk = elements::Script::from(crate::signer::unhex(info["scriptPubKey"].as_str().unwrap_or_default()).map_err(err("the address's script"))?);
	let operator = SignerClient::new(&config.signer_socket).pubkey().await.map_err(err("the signer"))?;
	let store = Store::connect(&config.database).await.map_err(err("the database"))?;
	let source: Arc<dyn ChainSource> = Arc::new(NodeSource::new(client));
	let certification = match config.finality.certification.as_str() {
		"required" => Certification::Required,
		"none" => Certification::NotOnThisChain,
		other => return Err(StartError(format!("finality.certification {:?}: required or none", other))),
	};
	let finality = FinalityService::new(store.clone(), source, FinalityConfig {
		anchor_depth: config.finality.anchor_depth, certification, start_height: config.finality.start_height,
		poll_interval: Duration::from_millis(config.finality.poll_interval_ms), cert_lookback: 144,
	}).await.map_err(err("the finality service"))?;
	let mnemonic = std::fs::read_to_string(&config.wallet_mnemonic_file).map_err(err("wallet_mnemonic_file"))?.trim().to_string();
	let wallet = Wallet::new(store.clone(), finality.clone(), operator,
		WalletConfig { mnemonic, fee_multiple: config.fee_multiple, spend_from: SpendFrom::Final, pool_coins: config.pool_coins })
		.map_err(err("the wallet"))?;
	let can = wallet.balance().await.map_err(err("the operator's wallet"))?.get(&asset).copied().unwrap_or(0);
	let owed = store.owed_totals().await.map_err(err("the database"))?.get(&asset.into_inner().to_byte_array()).map_or(0, |o| o.0);
	let room = can.saturating_sub(owed);
	if atoms > room {
		return Err(StartError(format!("the wallet can pay {} atoms of {} now and owes {} for swept coins: {} at most may leave, not {}",
			can, asset, owed, room, atoms)));
	}
	let built = wallet.build(&BuildRequest { outputs: vec![arca_covenant::ExplicitOutput::new(asset, atoms, spk)], connector: None, fee_asset })
		.await.map_err(err("the operator's wallet"))?;
	let tx = built.tx.clone();
	let txid = tx.txid();
	if let Err(e) = finality.call(move |c| c.broadcast(&tx)).await {
		let _ = wallet.release(&txid).await;
		return Err(StartError(format!("the node refused {}: {}", txid, e)));
	}
	Ok(serde_json::json!({"txid": txid.to_string(), "to": to, "asset": asset.to_string(), "value": atoms.to_string(),
		"fee": built.fee.amount.to_string(), "fee_asset": built.fee.asset.to_string(), "could_pay": can.to_string(), "owed": owed.to_string()}))
}

/// `arcad <config> bond-notice <key file>`: the notice of the configured
/// bond coin, signed with `W`'s key from `key_file`, its fee from the
/// operator's wallet, broadcast. Returns its id, the notice output and the
/// line that names it in `[bond]`. From then on the bond reads as in notice
/// (once the configuration names it), and wallets take no payment out of
/// round from the operator.
pub async fn bond_notice(config: &Config, key_file: &std::path::Path) -> Result<serde_json::Value, StartError> {
	let (bond, finality, wallet) = bond_spender(config).await?;
	let w = withdraw_key(key_file, &bond)?;
	let b = bond.clone();
	let view = finality.call(move |c| crate::bond::read(c, &b)).await.map_err(err("the node"))?;
	if view.state != "bonded" {
		return Err(StartError(format!("the bond is {}, not bonded: {}", view.state, view.why)));
	}
	let (op, asset, value) = (bond.outpoint.expect("bonded"), view.asset.expect("bonded"), view.value.expect("bonded"));
	let p = bond.policy;
	let tx = bond_spend(config, &finality, &wallet, asset, &w, |fee| p.notice_tx(op, asset, value, fee).map_err(|e| e.to_string())).await?;
	let notice = format!("{}:0", tx.txid());
	Ok(serde_json::json!({"txid": tx.txid().to_string(), "notice": notice, "notice_seconds": p.notice.seconds(),
		"config": format!("notice = \"{}\"", notice)}))
}

/// `arcad <config> bond-withdraw <key file> <address>`: once the notice's
/// delay has run, the whole bond to `address`, signed with `W`'s key, its
/// fee from the operator's wallet, broadcast.
pub async fn bond_withdraw(config: &Config, key_file: &std::path::Path, to: &str) -> Result<serde_json::Value, StartError> {
	let (bond, finality, wallet) = bond_spender(config).await?;
	let w = withdraw_key(key_file, &bond)?;
	let b = bond.clone();
	let view = finality.call(move |c| crate::bond::read(c, &b)).await.map_err(err("the node"))?;
	if view.state != "noticed" {
		return Err(StartError(format!("the bond is {}, not in notice: {}", view.state, view.why)));
	}
	let client = node_client(config)?;
	let addr = to.to_string();
	let info = tokio::task::spawn_blocking(move || client.call::<serde_json::Value>("validateaddress", &[serde_json::json!(addr)]))
		.await.map_err(err("the node"))?.map_err(err("the node"))?;
	if info["isvalid"] != serde_json::json!(true) {
		return Err(StartError(format!("{} is not an address of this chain", to)));
	}
	let spk = elements::Script::from(crate::signer::unhex(info["scriptPubKey"].as_str().unwrap_or_default()).map_err(err("the address's script"))?);
	let (n, asset, value) = (bond.notice.expect("noticed"), view.asset.expect("noticed"), view.value.expect("noticed"));
	let p = bond.policy;
	let out = arca_covenant::ExplicitOutput::new(asset, value, spk);
	let tx = bond_spend(config, &finality, &wallet, asset, &w,
		|fee| p.withdraw_tx(n, asset, value, std::slice::from_ref(&out), fee).map_err(|e| e.to_string())).await?;
	Ok(serde_json::json!({"txid": tx.txid().to_string(), "to": to, "asset": asset.to_string(), "value": value.to_string()}))
}

/// Deletes, every `every`, the operator nonces no board took within
/// `nonce_ttl`.
fn housekeeping(store: Store, nonce_ttl: Duration, every: Duration) -> JoinHandle<()> {
	tokio::spawn(async move {
		loop {
			match store.delete_expired(nonce_ttl).await {
				Ok(0) => {},
				Ok(n) => log::info!("deleted {} expired operator nonce(s)", n),
				Err(e) => log::warn!("deleting expired nonces: {}", e),
			}
			tokio::time::sleep(every).await;
		}
	})
}

/// What the chain shows of the operator's that the database does not know:
/// a transaction paying the operator's connector script that is no round of
/// the database's, and a board output spent by its collaborative path, which
/// needs `S`, by a transaction the server neither built nor co-signed (the
/// checkpoint of the board's transfer). Each is named.
async fn unknown_to_the_database(store: &Store, finality: &Arc<FinalityService>, operator: elements::secp256k1_zkp::XOnlyPublicKey)
	-> Result<Vec<String>, StartError>
{
	use elements::hashes::Hash;
	let mut found = vec![];
	let connector = ConnectorPolicy { operator }.script_pubkey();
	for t in store.unknown_rounds(connector.as_bytes()).await.map_err(err("the database"))? {
		found.push(format!("transaction {} pays the operator's connector script and is no round the database knows",
			elements::Txid::from_byte_array(t)));
	}
	for (record, txid, vout, by, checkpoint) in store.board_spends_unbuilt().await.map_err(err("the database"))? {
		let record = BoardRecord::from_bytes(&record).map_err(err("a board's record"))?;
		let by = elements::Txid::from_byte_array(by);
		let spender = match finality.call(move |c| c.transaction(&by)).await.map_err(err("the node"))? {
			Some(t) => t,
			None => continue,
		};
		let at = elements::OutPoint::new(elements::Txid::from_byte_array(txid), vout);
		let script = spender.input.iter().find(|i| i.previous_output == at)
			.and_then(|i| arca_covenant::witness::without_annex(&i.witness.script_witness).iter().rev().nth(1).cloned());
		// The owner's conversion is its own; any other path needs S, and the
		// server co-signed it only as the checkpoint of the board's transfer.
		if script.as_deref() == Some(record.policy().convert_script().as_bytes())
			|| checkpoint.is_some_and(|c| spender.output.iter().any(|o| o.script_pubkey.as_bytes() == c.as_slice()))
		{
			continue;
		}
		found.push(format!("transaction {} spends board {} by its collaborative path, which the database has no record of co-signing",
			by, record.leaf_id()));
	}
	Ok(found)
}

/// Refuses to start when the signer's record is not the one the database
/// knows: it ends before the latest entry the database was given (cut back,
/// or replaced by an older copy), or holds another entry there (another
/// record, or one two signers wrote).
async fn check_signer_record(store: &Store, signer: &SignerClient) -> Result<(), StartError> {
	let known = match store.signer_head().await.map_err(err("the database"))? {
		Some(k) => k,
		None => return Ok(()),
	};
	let (held, _) = signer.head().await.map_err(err("the signer"))?;
	if known.0 > held {
		return Err(StartError(format!(
			"the signer's record ends at entry {} and the database knows entry {} ({}): the record has been cut back or \
			 replaced by an older copy, and a signer on it could sign again what it signed before; start the signer on its \
			 whole record (see the server's README)", held, known.0, crate::signer::hex(&known.1))));
	}
	let there = signer.entries(known.0 - 1).await.map_err(err("the signer"))?;
	match there.first() {
		Some(e) if e.n == known.0 && e.hash == known.1 => Ok(()),
		other => Err(StartError(format!(
			"entry {} of the signer's record is not the one the database knows: the record holds {}, the database {}; \
			 this is another record, or one two signers wrote (see the server's README)", known.0,
			other.map(|e| crate::signer::hex(&e.hash)).unwrap_or_else(|| "nothing".into()), crate::signer::hex(&known.1)))),
	}
}

/// Refuses to start when the signer's record holds an entry, after the
/// latest one the database was given, that the database never recorded
/// asking for: the database is older than what the signer has signed
/// (restored from an older copy, or a commit lost), and serving from it
/// could co-sign or build against what it forgot (a forfeit it would never
/// claim, a spend it would co-sign again). Names each such entry. Every
/// message the server asks for is recorded before it asks, with what the
/// signature is for, so a database restored to its latest commit always
/// knows them. Otherwise the database is told the record's latest entry.
async fn check_signer_entries(store: &Store, signer: &SignerClient) -> Result<(), StartError> {
	use crate::signer::{hex, Signed};
	let mut after = store.signer_head().await.map_err(err("the database"))?.map(|h| h.0).unwrap_or(0);
	let mut unknown = vec![];
	let mut last = None;
	loop {
		let page = signer.entries(after).await.map_err(err("the signer"))?;
		let Some(end) = page.last() else { break };
		after = end.n;
		last = Some((end.n, end.hash));
		let keys: Vec<([u8; 32], [u8; 32], [u8; 32])> = page.iter().map(|e| (e.owner, e.salt, e.digest)).collect();
		for i in store.unknown_messages(&keys).await.map_err(err("the database"))? {
			let e = &page[i];
			unknown.push(format!("entry {}, the {} {} of the leaf of {} under salt {}", e.n,
				match e.kind { Signed::Spend => "spend", Signed::Forfeit(_) => "forfeit" }, hex(&e.digest), hex(&e.owner), hex(&e.salt)));
		}
		// Enough to refuse, and to name: a database far older than a long
		// record is not read against all of it.
		if unknown.len() >= 10 {
			break;
		}
	}
	if !unknown.is_empty() {
		let more = unknown.len() > 10 || after < signer.head().await.map_err(err("the signer"))?.0;
		unknown.truncate(10);
		return Err(StartError(format!(
			"the signer's record holds what the database has no record of asking the signer for, so the database is older \
			 than what the signer has signed (restored from an older copy, or a commit lost) and serving from it could co-sign \
			 or build against what it forgot; restore the database to its latest state (see the server's README) before \
			 starting: {}{}", unknown.join("; "), if more { "; and maybe more" } else { "" })));
	}
	if let Some((n, hash)) = last {
		store.set_signer_head(n, &hash).await.map_err(err("the database"))?;
	}
	Ok(())
}

/// The schedule an asset takes where it sets none of its own: `[fees]`.
fn default_fees(config: &Config) -> FeeSchedule {
	FeeSchedule {
		refresh_ppm: config.fees.refresh_ppm, offboard_ppm: config.fees.offboard_ppm, lightning_ppm: config.fees.lightning_ppm,
		..Default::default()
	}
}

/// The top-level settings of `a` and `b` that differ, by name.
fn restart_only(a: &Config, b: &Config) -> Vec<String> {
	let mut out = vec![];
	let mut differ = |name: &str, same: bool| if !same { out.push(name.to_string()) };
	differ("listen", a.listen == b.listen);
	differ("database", a.database == b.database);
	differ("signer_socket", a.signer_socket == b.signer_socket);
	differ("wallet_mnemonic_file", a.wallet_mnemonic_file == b.wallet_mnemonic_file);
	differ("fee_multiple", a.fee_multiple == b.fee_multiple);
	differ("max_request_bytes", a.max_request_bytes == b.max_request_bytes);
	differ("challenge_ttl_seconds", a.challenge_ttl_seconds == b.challenge_ttl_seconds);
	differ("round_interval_seconds", a.round_interval_seconds == b.round_interval_seconds);
	differ("node", a.node == b.node);
	differ("finality", a.finality == b.finality);
	differ("exit_delay_units", a.exit_delay_units == b.exit_delay_units);
	differ("fees.max_margin_multiple", a.fees.max_margin_multiple == b.fees.max_margin_multiple);
	differ("watcher", a.watcher == b.watcher);
	differ("limits", a.limits == b.limits);
	differ("metrics_listen", a.metrics_listen == b.metrics_listen);
	differ("lightning", a.lightning == b.lightning);
	differ("fills", a.fills == b.fills);
	out
}

/// A running server.
pub struct Server {
	pub addr: SocketAddr,
	/// Where the metrics are served, when they are.
	pub metrics_addr: Option<SocketAddr>,
	pub store: Store,
	pub params: Arc<Params>,
	pub finality: Arc<FinalityService>,
	pub nursery: Arc<Nursery>,
	pub boards: Arc<Boards>,
	pub wallet: Arc<Wallet>,
	pub cosigner: Arc<Cosigner>,
	pub participations: Arc<Participations>,
	pub plans: Arc<crate::plans::Plans>,
	pub orders: Arc<crate::orders::Orders>,
	pub rounds: Arc<Rounds>,
	pub forfeits: Arc<Forfeits>,
	pub watcher: Arc<Watcher>,
	pub gateway: Arc<Gateway>,
	pub sends: Arc<crate::lightning::send::Sends>,
	pub receives: Arc<crate::lightning::receive::Receives>,
	/// The configuration the server runs with, as last loaded.
	config: std::sync::Mutex<Config>,
	tasks: Vec<JoinHandle<()>>,
}

/// What a reload of the configuration changed ([`Server::reload`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reloaded {
	/// Assets served from now on that were not served before.
	pub added: Vec<AssetId>,
	/// Assets served before whose settings changed.
	pub changed: Vec<AssetId>,
	/// Whether the assets a round's fee is paid in changed.
	pub fee_assets: bool,
	/// The settings that changed and take a restart, which the reload left
	/// as they were.
	pub needs_restart: Vec<String>,
}

/// The assets `config` serves, in its order, each once, and the assets a
/// round's fee is paid in when it names them.
fn assets_of(config: &Config) -> Result<(Vec<(AssetId, AssetParams)>, Option<Vec<AssetId>>), StartError> {
	let mut list: Vec<(AssetId, AssetParams)> = vec![];
	for a in &config.assets {
		let id = AssetId::from_str(&a.asset).map_err(err("assets.asset"))?;
		if list.iter().any(|(b, _)| *b == id) {
			return Err(StartError(format!("assets: asset {} is listed twice", id)));
		}
		let rate = a.rate.as_ref().map(|r| r.config()).transpose().map_err(|e| StartError(format!("asset {}: rate: {}", id, e)))?;
		let (min_leaf, min_leaf_value) = match (&a.min_leaf, &a.min_leaf_value) {
			(Some(m), None) => (parse_amount(m).map_err(err("assets.min_leaf"))?, None),
			(None, Some(v)) if rate.is_some() => (0, Some(parse_amount(v).map_err(err("assets.min_leaf_value"))?)),
			(None, Some(_)) => return Err(StartError(format!("asset {}: min_leaf_value is converted at the asset's rate, and the asset \
				names no rate source", id))),
			_ => return Err(StartError(format!("asset {}: min_leaf, in atoms, or min_leaf_value, in the reference unit: one of them", id))),
		};
		let amount = |what: &str, atoms: &Option<String>, value: &Option<String>| -> Result<Amount, StartError> {
			match (atoms, value) {
				(None, None) => Ok(Amount::Atoms(0)),
				(Some(a), None) => Ok(Amount::Atoms(parse_amount(a).map_err(|e| StartError(format!("asset {}: {}: {}", id, what, e)))?)),
				(None, Some(v)) if rate.is_some() => Ok(Amount::Value(parse_amount(v)
					.map_err(|e| StartError(format!("asset {}: {}_value: {}", id, what, e)))?)),
				(None, Some(_)) => Err(StartError(format!("asset {}: {}_value is converted at the asset's rate, and the asset names no \
					rate source", id, what))),
				(Some(_), Some(_)) => Err(StartError(format!("asset {}: {}, in atoms, or {}_value, in the reference unit: not both", id, what,
					what))),
			}
		};
		let fees = AssetFees {
			refresh_ppm: a.refresh_ppm.unwrap_or(config.fees.refresh_ppm),
			offboard_ppm: a.offboard_ppm.unwrap_or(config.fees.offboard_ppm),
			refresh_base: amount("refresh_base", &a.refresh_base, &a.refresh_base_value)?,
			offboard_base: amount("offboard_base", &a.offboard_base, &a.offboard_base_value)?,
			lightning_ppm: a.lightning_ppm.unwrap_or(config.fees.lightning_ppm),
			lightning_base: amount("lightning_base", &a.lightning_base, &a.lightning_base_value)?,
		};
		let issuer = match &a.issuer {
			None => None,
			Some(s) => {
				if a.lightning.is_some() {
					return Err(StartError(format!("asset {}: an issuer-operated asset has no Lightning leg here: the operator would pay out \
						of and be paid into channels in the asset, units it keeps none of and mints only in a round", id)));
				}
				Some(crate::issuer::IssuerAsset::from_section(id, s, None).map_err(|e| StartError(format!("asset {}: issuer: {}", id, e)))?)
			},
		};
		let channel_capacity = amount("channel_capacity", &a.channel_capacity, &a.channel_capacity_value)?;
		let in_flight_cap = match (&a.in_flight_cap, &a.in_flight_cap_value) {
			(None, None) => None,
			_ => Some(amount("in_flight_cap", &a.in_flight_cap, &a.in_flight_cap_value)?),
		};
		list.push((id, AssetParams { min_leaf, min_leaf_value, rate, fees, issuer, supervised: None, channel_capacity, restricted: None,
			in_flight_cap }));
	}
	if list.is_empty() {
		return Err(StartError("assets: the server serves at least one asset".into()));
	}
	let fee_assets = match &config.fee_assets {
		Some(l) => Some(l.iter().map(|a| AssetId::from_str(a)).collect::<Result<Vec<_>, _>>().map_err(err("fee_assets"))?),
		None => None,
	};
	Ok((list, fee_assets))
}

/// The size a landing's transaction is priced at for its default fee
/// allowance: the claim measured 227 vbytes, with room for a fee output.
pub const LANDING_VSIZE: u64 = 250;

/// Serves every asset of `list` that the node lists as supervised under the
/// supervised profile ([`crate::supervision`]), with its fee allowance; and
/// refuses a configuration that names the profile for an asset the chain does
/// not supervise, or serves a supervised asset issuer-operated or over
/// Lightning, neither of which keeps it in `landing-1` leaves.
async fn supervise(list: &mut [(AssetId, AssetParams)], config: &Config, finality: &FinalityService) -> Result<(), StartError> {
	let listed = finality.call(|c| c.supervised_assets()).await.map_err(err("the node's supervised assets"))?;
	for (id, p) in list.iter_mut() {
		let section = config.assets.iter().find(|s| AssetId::from_str(&s.asset).ok() == Some(*id));
		let named = section.and_then(|s| s.supervised.clone());
		if !listed.iter().any(|s| s.asset == *id) {
			if named.is_some() {
				return Err(StartError(format!("asset {}: supervised: the node does not list it as supervised; an asset is supervised \
					only if it was issued so, with the descriptor in its id", id)));
			}
			p.supervised = None;
			continue;
		}
		if p.issuer.is_some() {
			return Err(StartError(format!("asset {}: supervised on the chain, and configured issuer-operated: the two profiles are \
				not served together", id)));
		}
		if section.is_some_and(|s| s.lightning.is_some()) {
			return Err(StartError(format!("asset {}: supervised on the chain: no Lightning leg serves it here, as an htlc-1 leaf's \
				paths pay a key a freeze cannot follow", id)));
		}
		let landing_allowance = match named.and_then(|s| s.landing_allowance) {
			Some(a) => parse_amount(&a).map_err(|e| StartError(format!("asset {}: supervised.landing_allowance: {}", id, e)))?,
			None => match crate::fees::floor_per_kvb(finality, *id).await.map_err(err("the node's fee floor"))? {
				Some(floor) => crate::fees::atoms_for(floor, LANDING_VSIZE, crate::fees::MULTIPLE),
				None => 0,
			},
		};
		if landing_allowance > 0 && landing_allowance >= p.min_leaf.max(1) && p.min_leaf_value.is_none() {
			return Err(StartError(format!("asset {}: a landing allowance of {} is not below the smallest leaf, {}", id,
				landing_allowance, p.min_leaf)));
		}
		log::info!("asset {} is supervised: served under the supervised profile, landing allowance {}", id, landing_allowance);
		p.supervised = Some(crate::params::Supervised { landing_allowance });
	}
	Ok(())
}

/// Serves every asset whose section names a policy server under the
/// restricted profile ([`crate::restricted`]): the asset's tree terms read
/// from its policy server, which must name `operator` as the tree's operator.
/// Refuses a restricted asset that is also supervised, issuer-operated or
/// served over Lightning, none of which keeps it in `enclave-1` leaves.
async fn restrict(list: &mut [(AssetId, AssetParams)], config: &Config, operator: elements::secp256k1_zkp::XOnlyPublicKey) -> Result<(), StartError> {
	for (id, p) in list.iter_mut() {
		let section = config.assets.iter().find(|s| AssetId::from_str(&s.asset).ok() == Some(*id));
		let Some(r) = section.and_then(|s| s.restricted.clone()) else {
			p.restricted = None;
			continue;
		};
		if p.supervised.is_some() || p.issuer.is_some() || section.is_some_and(|s| s.lightning.is_some())
			|| p.channel_capacity != crate::params::Amount::Atoms(0) {
			return Err(StartError(format!("asset {}: restricted: a restricted asset is held in enclave-1 leaves alone, so it is not also \
				supervised, issuer-operated, served over Lightning or in channel-1 leaves here", id)));
		}
		let token = std::fs::read_to_string(&r.token_file)
			.map_err(|e| StartError(format!("asset {}: restricted.token_file {}: {}", id, r.token_file, e)))?.trim().to_string();
		let terms = crate::restricted::tree_terms(&r.policy_server, *id).await
			.map_err(|e| StartError(format!("asset {}: restricted: {}", id, e)))?;
		if terms.operator != operator {
			return Err(StartError(format!("asset {}: restricted: the policy server names {} as the operator of the asset's tree, and this \
				operator's key is {}: it serves the asset only in a tree its issuer names it the operator of", id,
				crate::signer::hex(&terms.operator.serialize()), crate::signer::hex(&operator.serialize()))));
		}
		log::info!("asset {} is restricted: served in its issuer's tree, every leaf enclave-1, policy key {}, clawback {}, policy server {}",
			id, crate::signer::hex(&terms.policy.serialize()),
			terms.clawback.map_or("none".to_string(), |k| crate::signer::hex(&k.serialize())), r.policy_server);
		p.restricted = Some(crate::restricted::Restricted { policy: terms.policy, clawback: terms.clawback, server: r.policy_server, token });
	}
	Ok(())
}

/// Refuses an issuer-operated asset whose mint limiter is an instance on
/// another chain than `genesis`, and issuer-operated assets that leave no
/// fee asset: a round that mints an asset, and a sweep that burns it, pay
/// their fees in another (`fee_assets`, the served assets when `None`).
fn issuers_on(list: &[(AssetId, AssetParams)], fee_assets: &Option<Vec<AssetId>>, genesis: elements::BlockHash) -> Result<(), StartError> {
	for (a, p) in list {
		if let Some(i) = &p.issuer {
			if i.genesis != genesis {
				return Err(StartError(format!("asset {}: issuer: the mint limiter is an instance on chain {}, and the server runs on {}", a,
					i.genesis, genesis)));
			}
		}
	}
	let issuer = |a: &AssetId| list.iter().any(|(b, p)| b == a && p.issuer.is_some());
	if list.iter().any(|(a, _)| issuer(a)) {
		let payable = match fee_assets {
			Some(f) => f.iter().any(|a| !issuer(a)),
			None => list.iter().any(|(a, _)| !issuer(a)),
		};
		if !payable {
			return Err(StartError("every fee asset is issuer-operated: a round that mints an asset, and a sweep that burns it, pay their \
				fees in another asset, so list one in fee_assets (or serve one) that is not issuer-operated".into()));
		}
	}
	Ok(())
}

/// Each served asset's Lightning node, as `config` names it.
fn legs_of(config: &Config) -> Result<Vec<(AssetId, PathBuf)>, StartError> {
	let mut out = vec![];
	for a in &config.assets {
		if let Some(l) = &a.lightning {
			out.push((AssetId::from_str(&a.asset).map_err(err("assets.asset"))?, l.rpc.clone()));
		}
	}
	Ok(out)
}

impl Server {
	/// Starts every component from `config`: the store, the finality service
	/// following the node, the signer's key, the wallet, the nursery, the
	/// boards, the co-signer, the rounds, the watcher, their tasks, and the
	/// HTTP listener.
	pub async fn start(config: &Config) -> Result<Server, StartError> {
		let store = Store::connect(&config.database).await.map_err(err("the database"))?;
		let source: Arc<dyn ChainSource> = Arc::new(NodeSource::new(node_client(config)?));
		let certification = match config.finality.certification.as_str() {
			"required" => Certification::Required,
			"none" => Certification::NotOnThisChain,
			other => return Err(StartError(format!("finality.certification {:?}: required or none", other))),
		};
		let fconfig = FinalityConfig {
			anchor_depth: config.finality.anchor_depth,
			certification,
			start_height: config.finality.start_height,
			poll_interval: Duration::from_millis(config.finality.poll_interval_ms),
			cert_lookback: 144,
		};
		let finality = FinalityService::new(store.clone(), source.clone(), fconfig).await.map_err(err("the finality service"))?;
		let genesis = finality.call(|c| c.genesis()).await.map_err(err("the node"))?;
		let signer = SignerClient::new(&config.signer_socket).with_store(store.clone());
		let operator = signer.pubkey().await.map_err(err("the signer"))?;
		let (keeper_keys, keepers_required) = signer.keepers().await.map_err(err("the signer"))?;
		let keepers = crate::api::KeepersInfo {
			keys: keeper_keys.iter().map(|k| crate::signer::hex(&k.serialize())).collect(), required: keepers_required,
		};
		// The keepers are part of the operator's identity: pinned the first
		// time the server reads them, as a wallet pins them, and a signer
		// naming another set (its record replaced, or edited, a compacted
		// record's first line included) is not this operator's.
		let pinned = store.pin_keepers(&keepers.keys, keepers.required as usize).await.map_err(err("the database"))?;
		if (pinned.0.as_slice(), pinned.1) != (keepers.keys.as_slice(), keepers.required as usize) {
			return Err(StartError(format!("the signer's record names the keepers [{}], {} required; this server pinned [{}], {} required, \
				the first time it read them: the keepers are part of the operator's identity, fixed in its record when it was made, so \
				this signer runs on another record than this operator's (replaced, or its first line edited). Start the signer on the \
				operator's own record", keepers.keys.join(", "), keepers.required, pinned.0.join(", "), pinned.1)));
		}
		if keepers.keys.is_empty() {
			log::warn!("the signer has no keeper: its record rests on this machine alone, so a restore of the machine can let a coin \
				paid out of round be spent twice; this operator is for its own coins");
		}
		// A signer stopped by a proven rollback of its record signs nothing
		// the record governs; the server still starts, so every wallet's
		// witness learns it and its holders exit, and serves no co-signature.
		match signer.witness(&[], None).await.map_err(err("the signer"))?.stopped {
			Some(why) => log::error!("the signer is stopped: {}; the server co-signs nothing, and answers each wallet's witness with \
				it so that holders exit", why),
			None => {
				check_signer_record(&store, &signer).await?;
				check_signer_entries(&store, &signer).await?;
				// The record's latest entry, signed, so a round built before
				// the next co-signature publishes a head wallets keep.
				let h = signer.signed_head().await.map_err(err("the signer"))?;
				if h.entry > 0 {
					store.set_signer_head_signed(h.entry, &h.hash, h.signature.as_ref()).await.map_err(err("the database"))?;
				}
			},
		}

		let (mut list, fee_assets) = assets_of(config)?;
		issuers_on(&list, &fee_assets, genesis)?;
		supervise(&mut list, config, &finality).await?;
		restrict(&mut list, config, operator).await?;
		let mut params = Params::new(Chain::new(genesis), operator, BTreeMap::new());
		params.assets.set_default_fees(default_fees(config));
		params.serve(list, fee_assets);
		// Every rate source read before anything is served.
		params.rates.read_all(&finality).await;
		if let Some(m) = config.fees.max_margin_multiple {
			if m < 1 {
				return Err(StartError("fees.max_margin_multiple is at least 1".into()));
			}
			params.max_margin_multiple = m;
		}
		if config.fills.block_seconds == 0 {
			return Err(StartError("fills.block_seconds is at least 1".into()));
		}
		params.order_margin_seconds = config.fills.order_margin_seconds;
		params.order_block_seconds = config.fills.block_seconds;
		params.fill_forfeit_window_seconds = config.fills.forfeit_window_seconds;
		params.round_interval_seconds = config.round_interval_seconds;
		params.watchtowers = config.watcher.watchtowers.clone();
		if let Some((min, max)) = config.exit_delay_units {
			params.min_exit_delay = RelativeTime::from_units(min).map_err(err("exit_delay_units"))?;
			params.max_exit_delay = RelativeTime::from_units(max).map_err(err("exit_delay_units"))?;
			params.set_delays();
		}
		let params = Arc::new(params);
		// The bond binds S; its notice outlasts every coin paid out of round
		// before it.
		let bond = match &config.bond {
			Some(b) => Some(crate::bond::Bond::from_section(b, params.chain, operator, RoundConfig::default().lifetime.max(Params::BOARD_LIFETIME),
				params.max_exit_delay).map_err(|e| StartError(format!("bond: {}", e)))?),
			None => None,
		};

		let mnemonic = std::fs::read_to_string(&config.wallet_mnemonic_file)
			.map_err(err("wallet_mnemonic_file"))?.trim().to_string();
		let wallet = Arc::new(Wallet::new(store.clone(), finality.clone(), operator,
			WalletConfig { mnemonic, fee_multiple: config.fee_multiple, spend_from: SpendFrom::Final, pool_coins: config.pool_coins })
			.map_err(err("the wallet"))?);
		let nursery = Nursery::new(store.clone(), finality.clone(), Some(wallet.clone()), Duration::from_secs(30));
		let boards = Boards::new(store.clone(), finality.clone(), nursery.clone(), params.clone(),
			Duration::from_secs(config.limits.board_unconfirmed_seconds));
		let cosigner = Cosigner::new(store.clone(), finality.clone(), params.clone(), signer.clone());
		let channels = crate::channels::Channels::new(store.clone(), params.clone(), signer.clone());
		let participations = Participations::new(store.clone(), finality.clone(), params.clone(), signer.clone());
		let plans = crate::plans::Plans::new(store.clone(), finality.clone(), params.clone(), signer.clone(), wallet.clone());
		let orders = crate::orders::Orders::new(store.clone(), finality.clone(), params.clone(), signer.clone());
		let rounds = Rounds::new(store.clone(), finality.clone(), params.clone(), wallet.clone(), nursery.clone(), signer.clone(),
			RoundConfig {
				accumulator_exit_rate_ppm: config.batches.accumulator_exit_rate_ppm,
				holder_batches: config.batches.holder_batches.unwrap_or(RoundConfig::default().holder_batches),
				holder_window: config.batches.holder_window_seconds.unwrap_or(RoundConfig::default().holder_window),
				delegated_reclaim: config.batches.delegated_reclaim,
				..RoundConfig::default()
			});
		let forfeits = Forfeits::new(store.clone(), finality.clone(), params.clone(), signer.clone(), cosigner.clone());
		let watcher = Watcher::new(store.clone(), finality.clone(), params.clone(), wallet.clone(), nursery.clone(), signer,
			rounds.clone(), WatcherConfig {
				reclaim_early: config.watcher.reclaim_early,
				max_sweep_inputs: config.watcher.max_sweep_inputs.max(1),
				recovery_interval: Duration::from_secs(config.watcher.recovery_interval_seconds.max(1)),
				max_claim_inputs: config.watcher.max_claim_inputs.max(1),
				block_share_vbytes: config.watcher.block_share_vbytes.max(1),
				block_interval: Duration::from_secs(config.watcher.block_interval_seconds.max(1)),
				unroll_at_release: config.watcher.unroll_at_release,
			});

		// The first pass before anything is answered, so the chain is known,
		// watching for the operator's connector script, which every round
		// pays; then nothing is served from a database that does not know
		// what the chain shows of the operator's.
		store.watch_connector(ConnectorPolicy { operator }.script_pubkey().as_bytes()).await.map_err(err("the database"))?;
		finality.sync().await.map_err(err("the first pass over the chain"))?;
		let unknown = unknown_to_the_database(&store, &finality, operator).await?;
		if !unknown.is_empty() {
			return Err(StartError(format!(
				"the chain shows what the database does not know, so the database is older than the chain (restored from an \
				 older copy, or a commit lost) and serving from it could co-sign or build against what it forgot; restore the \
				 database to its latest state (see the server's README) before starting: {}", unknown.join("; "))));
		}
		// A forfeit recorded and never given the operator's half is completed
		// now, and every minute after (the signer may come back later).
		match forfeits.fill_unsigned().await {
			Ok(0) => {},
			Ok(n) => log::info!("{} forfeit(s) given the operator's half at start", n),
			Err(e) => log::warn!("forfeits without the operator's half: {}", e),
		}
		// So is a fill of a resting order the signer left half done.
		match orders.finish_unsigned().await {
			Ok(0) => {},
			Ok(n) => log::info!("{} fill(s) of resting orders completed at start", n),
			Err(e) => log::warn!("fills of resting orders left unsigned: {}", e),
		}
		// D61 for a transfer recorded before this server posted notices (an
		// operator moved from an older version with one in flight): each of
		// its outputs posted as pending, once, before anything is served.
		match cosigner.post_missing_notices().await {
			Ok(0) => {},
			Ok(n) => log::info!("{} pending notice(s) posted at start for transfers recorded before notices were posted", n),
			Err(e) => log::warn!("the pending notices of transfers recorded before notices were posted: {}", e),
		}
		// The Lightning gateway's nodes, checked before anything is served.
		let policy_asset = {
			let client = node_client(config)?;
			tokio::task::spawn_blocking(move || client.call::<serde_json::Value>("getsidechaininfo", &[])).await
				.map_err(err("the node"))?.ok()
				.and_then(|v| v["pegged_asset"].as_str().and_then(|a| AssetId::from_str(a).ok()))
		};
		let gateway = Gateway::new(&GatewayConfig {
			legs: legs_of(config)?,
			bitcoin: config.lightning.bitcoin.as_ref().map(|b| BitcoinLegConfig { rpc: b.rpc.clone(), ark: b.ark.clone() }),
			poll: Duration::from_secs(config.lightning.poll_seconds.max(1)),
			policy_asset,
		});
		gateway.check().await;
		let l = &config.lightning;
		if l.operator_delay_units == 0 || l.owner_delay_units <= l.operator_delay_units {
			return Err(StartError("lightning: operator_delay_units is at least 1 and below owner_delay_units".into()));
		}
		if l.send_stall_margin_seconds >= l.send_timeout_seconds.max(60) {
			return Err(StartError("lightning: send_stall_margin_seconds is below send_timeout_seconds, which leaves a payment's lock \
				times the rest".into()));
		}
		let sends = crate::lightning::send::Sends::new(store.clone(), params.clone(), gateway.clone(), cosigner.clone(),
			crate::lightning::send::SendConfig {
				operator_delay: RelativeTime::from_units(l.operator_delay_units).map_err(err("lightning.operator_delay_units"))?,
				owner_delay: RelativeTime::from_units(l.owner_delay_units).map_err(err("lightning.owner_delay_units"))?,
				timeout_seconds: l.send_timeout_seconds.max(60),
				block_seconds: l.block_seconds.max(1),
				retry_seconds: l.retry_seconds.max(5),
				stall_margin_seconds: l.send_stall_margin_seconds,
			});
		let receives = crate::lightning::receive::Receives::new(store.clone(), params.clone(), gateway.clone(), cosigner.clone(),
			finality.clone(), wallet.clone(), crate::lightning::receive::ReceiveConfig {
				operator_delay: RelativeTime::from_units(l.operator_delay_units).map_err(err("lightning.operator_delay_units"))?,
				window_seconds: l.receive_window_seconds.max(60),
				invoice_expiry_seconds: l.invoice_expiry_seconds.max(60),
				block_seconds: l.block_seconds.max(1),
				cap_ppm: l.receive_cap_ppm.min(1_000_000),
				stall_seconds: l.send_stall_margin_seconds,
			});
		sends.set_receives(receives.clone());
		let interval = (config.round_interval_seconds > 0).then(|| Duration::from_secs(config.round_interval_seconds));
		rounds.pass().await.map_err(err("the first pass over the rounds"))?;
		let mut tasks = vec![nursery.spawn(), boards.spawn(), rounds.spawn(interval), params.rates.spawn(finality.clone()), gateway.spawn(), sends.spawn(),
			receives.spawn()];
		if config.watcher.enabled {
			tasks.push(watcher.spawn());
		}
		tasks.push(finality.spawn());
		// The supervised profile's watch on the node: after each pass over
		// the chain, every freeze and pause of a supervised asset the server
		// serves is held, and each lifting counted from there.
		tasks.push({
			let (store, finality, params) = (store.clone(), finality.clone(), params.clone());
			let mut rx = finality.subscribe();
			tokio::spawn(async move {
				loop {
					match rx.recv().await {
						Ok(crate::chain::ChainEvent::Synced { .. }) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {},
						Ok(_) => continue,
						Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
					}
					let assets: Vec<AssetId> = params.assets.ids().into_iter().filter(|a| params.supervised(a).is_some()).collect();
					if let Err(e) = crate::supervision::observe(&store, &finality, &assets).await {
						log::warn!("supervision: reading the node's freezes: {}", e);
					}
				}
			})
		});
		tasks.push(housekeeping(store.clone(), Duration::from_secs(config.limits.nonce_ttl_seconds),
			Duration::from_secs(config.limits.cleanup_interval_seconds.max(1))));
		// Once a minute: the forfeits without the operator's half, the fills
		// of resting orders left unsigned, and the keepers the signer names,
		// against the pinned set.
		let replaced: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
		let pinned_keepers = Arc::new(std::sync::Mutex::new(keepers.clone()));
		tasks.push({
			let (forfeits, orders) = (forfeits.clone(), orders.clone());
			let (signer, pinned, replaced) = (cosigner.signer().clone(), pinned_keepers.clone(), replaced.clone());
			tokio::spawn(async move {
				loop {
					tokio::time::sleep(Duration::from_secs(60)).await;
					if crate::http::keepers_replaced(&signer, &pinned, &replaced).await {
						continue;
					}
					match forfeits.fill_unsigned().await {
						Ok(0) => {},
						Ok(n) => log::info!("{} forfeit(s) given the operator's half", n),
						Err(e) => log::warn!("forfeits without the operator's half: {}", e),
					}
					match orders.finish_unsigned().await {
						Ok(0) => {},
						Ok(n) => log::info!("{} fill(s) of resting orders completed", n),
						Err(e) => log::warn!("fills of resting orders left unsigned: {}", e),
					}
				}
			})
		});

		let app = Arc::new(App {
			store: store.clone(), params: params.clone(), boards: boards.clone(), cosigner: cosigner.clone(),
			participations: participations.clone(), plans: plans.clone(), orders: orders.clone(), rounds: rounds.clone(), forfeits: forfeits.clone(),
			channels, certification, anchor_depth: config.finality.anchor_depth, max_request: config.max_request_bytes,
			challenge_ttl: Duration::from_secs(config.challenge_ttl_seconds),
			nonces: Limiter::new(config.limits.issue_per_second, config.limits.issue_burst, config.limits.source_per_second,
				config.limits.source_burst),
			witnesses: Limiter::new(config.limits.witness_per_second, config.limits.witness_burst, config.limits.witness_source_per_second,
				config.limits.witness_source_burst),
			reads: Limiter::new(config.limits.read_per_second, config.limits.read_burst, config.limits.read_source_per_second,
				config.limits.read_source_burst),
			challenge_key: store.challenge_key().await.map_err(err("the database"))?,
			trusted_proxies: config.limits.trusted_proxies.iter().map(|a| a.parse())
				.collect::<Result<_, _>>().map_err(err("limits.trusted_proxies"))?,
			floors: tokio::sync::Mutex::new(None),
			record_head: tokio::sync::Mutex::new(None),
			bond,
			bond_view: tokio::sync::Mutex::new(None),
			keepers: std::sync::Mutex::new(keepers),
			replaced,
			gateway: gateway.clone(),
			sends: sends.clone(),
			receives: receives.clone(),
		});
		let mut metrics_addr = None;
		if let Some(at) = &config.metrics_listen {
			let w = watcher.clone();
			let routes = axum::Router::new().route("/metrics", axum::routing::get(move || {
				let w = w.clone();
				async move { w.fee_status().metrics() }
			}));
			let listener = tokio::net::TcpListener::bind(at).await.map_err(err("metrics_listen"))?;
			metrics_addr = Some(listener.local_addr().map_err(err("metrics_listen"))?);
			log::info!("metrics on {}", metrics_addr.expect("set"));
			tasks.push(tokio::spawn(async move {
				if let Err(e) = axum::serve(listener, routes).await {
					log::error!("the metrics listener stopped: {}", e);
				}
			}));
		}
		let listener = tokio::net::TcpListener::bind(&config.listen).await.map_err(err("listen"))?;
		let addr = listener.local_addr().map_err(err("listen"))?;
		let routes = router(app).into_make_service_with_connect_info::<SocketAddr>();
		tasks.push(tokio::spawn(async move {
			if let Err(e) = axum::serve(listener, routes).await {
				log::error!("the HTTP listener stopped: {}", e);
			}
		}));
		log::info!("arca server on {}: operator {}, genesis {}, assets {}", addr, crate::signer::hex(&operator.serialize()), genesis,
			params.assets.ids().iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "));
		Ok(Server { addr, metrics_addr, store, params, finality, nursery, boards, wallet, cosigner, participations, plans, orders, rounds,
			forfeits, watcher, gateway, sends, receives, config: std::sync::Mutex::new(config.clone()), tasks })
	}

	/// Takes the assets `config` serves, each with its smallest leaf, its
	/// fee schedule, its rate source and its Lightning node, the schedule an asset takes where it
	/// sets none (`[fees]`' refresh and offboard parts), and the assets a
	/// round's fee is paid in, without a
	/// restart, and reads every rate source: an asset added is served by every entry,
	/// every round and the watcher from now on (its pool is the wallet's
	/// coins of it, so it is funded by paying the wallet), and an asset whose
	/// settings changed is served under its new ones. Nothing is taken when
	/// `config` does not read, or leaves out an asset served now: an asset
	/// stops being served only at a restart, after which the server takes no
	/// new work in it and its holders take their coins on the chain. Any
	/// other setting that changed takes a restart; the reload leaves it as
	/// it was and says so.
	pub async fn reload(&self, config: &Config) -> Result<Reloaded, StartError> {
		let (mut list, fee_assets) = assets_of(config)?;
		issuers_on(&list, &fee_assets, self.params.chain.genesis_hash())?;
		supervise(&mut list, config, &self.finality).await?;
		restrict(&mut list, config, self.params.operator).await?;
		let legs = legs_of(config)?;
		let before = self.params.assets.all();
		let removed: Vec<String> = before.iter().filter(|(a, _)| !list.iter().any(|(b, _)| b == a)).map(|(a, _)| a.to_string()).collect();
		if !removed.is_empty() {
			return Err(StartError(format!("the configuration leaves out asset(s) {} that the server serves: an asset stops being \
				served only at a restart (its holders then take their coins on the chain), so nothing was reloaded", removed.join(", "))));
		}
		let out = {
			let mut current = self.config.lock().unwrap_or_else(|e| e.into_inner());
			let mut out = Reloaded::default();
			for (a, p) in &list {
				let section = |c: &Config| c.assets.iter().find(|s| AssetId::from_str(&s.asset).ok() == Some(*a)).and_then(|s| s.lightning.clone());
				match before.iter().find(|(b, _)| b == a) {
					None => out.added.push(*a),
					Some((_, q)) if q != p || section(&current) != section(config) => out.changed.push(*a),
					Some(_) => {},
				}
			}
			out.fee_assets = self.params.assets.fee_assets() != fee_assets.clone().unwrap_or_else(|| list.iter().map(|(a, _)| *a).collect());
			// What a reload takes, laid over the configuration the server
			// runs with: whatever else differs takes a restart.
			let mut taken = current.clone();
			taken.assets = config.assets.clone();
			taken.fee_assets = config.fee_assets.clone();
			taken.fees.refresh_ppm = config.fees.refresh_ppm;
			taken.fees.offboard_ppm = config.fees.offboard_ppm;
			taken.fees.lightning_ppm = config.fees.lightning_ppm;
			if taken != *config {
				out.needs_restart = restart_only(&taken, config);
				log::warn!("reload: {} changed and take(s) a restart; left as they were", out.needs_restart.join(", "));
			}
			self.params.assets.set_default_fees(default_fees(config));
			self.params.serve(list, fee_assets);
			*current = taken;
			out
		};
		self.params.rates.read_all(&self.finality).await;
		self.gateway.reconfigure(&legs).await;
		log::info!("reload: the server serves {}; added {:?}, changed {:?}{}",
			self.params.assets.ids().iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "),
			out.added.iter().map(|a| a.to_string()).collect::<Vec<_>>(), out.changed.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
			if out.fee_assets { "; the fee assets changed" } else { "" });
		Ok(out)
	}

	/// The configuration the server runs with, as last loaded.
	pub fn config(&self) -> Config {
		self.config.lock().unwrap_or_else(|e| e.into_inner()).clone()
	}

	/// Stops every task.
	pub fn stop(&self) {
		for t in &self.tasks {
			t.abort();
		}
	}
}

impl Drop for Server {
	fn drop(&mut self) {
		self.stop();
	}
}

#[cfg(test)]
mod tests {
	use super::Config;

	/// The example configuration names every setting, and parses.
	#[test]
	fn example_config_parses() {
		let c: Config = toml::from_str(include_str!("../arcad.example.toml")).expect("the example parses");
		assert_eq!(c.assets.len(), 1);
		assert_eq!(c.fees.refresh_ppm, 0);
		assert!(c.watcher.reclaim_early);
		assert_eq!(c.watcher.max_sweep_inputs, 50);
		assert_eq!(c.limits.issue_per_second, 250);
		assert_eq!(c.limits.issue_per_second, super::LimitsSection::default().issue_per_second, "the example names the defaults");
		assert_eq!(c.limits.issue_burst, super::LimitsSection::default().issue_burst);
		assert_eq!(c.limits.nonce_ttl_seconds, 3600);
		let d = super::LimitsSection::default();
		assert_eq!((c.limits.witness_per_second, c.limits.witness_burst, c.limits.witness_source_per_second, c.limits.witness_source_burst),
			(d.witness_per_second, d.witness_burst, d.witness_source_per_second, d.witness_source_burst), "the example names the defaults");
	}
}
