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
use crate::params::{AssetParams, FeeSchedule, Params};
use crate::participations::Participations;
use crate::forfeits::Forfeits;
use crate::rounds::{RoundConfig, Rounds};
use crate::signer::{parse_amount, SignerClient};
use crate::store::Store;
use crate::wallet::{SpendFrom, Wallet, WalletConfig};
use crate::watcher::{Watcher, WatcherConfig};

/// The server's configuration, as `arcad` reads it from a TOML file.
#[derive(Debug, Clone, Deserialize)]
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
	/// The assets served.
	pub assets: Vec<AssetSection>,
	/// The assets a round's fee is paid in, in order of preference (display
	/// order ids); the served assets, in the order listed, when absent. A
	/// round pays in the first of its own batches' assets the node accepts
	/// for fees, else in the first of these it accepts.
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
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
	/// Operator nonces handed out per second at most, and the same for
	/// authentication challenges, each counted on its own.
	#[serde(default = "default_issue_per_second")]
	pub issue_per_second: u32,
	/// How many of either may be handed out at once before the rate holds.
	#[serde(default = "default_issue_burst")]
	pub issue_burst: u32,
	/// How long an operator nonce is good for: one no board took in that
	/// time is deleted, and a board naming it is refused.
	#[serde(default = "default_nonce_ttl")]
	pub nonce_ttl_seconds: u64,
	/// How long a board never credited may stay out of every block after it
	/// was registered before it is dropped.
	#[serde(default = "default_board_unconfirmed")]
	pub board_unconfirmed_seconds: u64,
	/// How often expired nonces and challenges are deleted.
	#[serde(default = "default_cleanup_interval")]
	pub cleanup_interval_seconds: u64,
}

impl Default for LimitsSection {
	fn default() -> LimitsSection {
		LimitsSection {
			issue_per_second: default_issue_per_second(), issue_burst: default_issue_burst(),
			nonce_ttl_seconds: default_nonce_ttl(), board_unconfirmed_seconds: default_board_unconfirmed(),
			cleanup_interval_seconds: default_cleanup_interval(),
		}
	}
}

fn default_issue_per_second() -> u32 {
	5
}

fn default_issue_burst() -> u32 {
	50
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatcherSection {
	/// Whether the watcher acts on its own, following the chain. Off, it acts
	/// only when `Watcher::pass` is called.
	#[serde(default = "default_true")]
	pub enabled: bool,
	/// Unroll a node all of whose owners have released their lowest nodes,
	/// and reclaim those, before the batch expires.
	#[serde(default = "default_true")]
	pub reclaim_early: bool,
	/// The most outputs one sweep takes.
	#[serde(default = "default_sweep_inputs")]
	pub max_sweep_inputs: usize,
	/// How often the recovery work runs when no block arrives, in seconds.
	#[serde(default = "default_recovery_interval")]
	pub recovery_interval_seconds: u64,
}

impl Default for WatcherSection {
	fn default() -> WatcherSection {
		WatcherSection {
			enabled: true, reclaim_early: default_true(), max_sweep_inputs: default_sweep_inputs(),
			recovery_interval_seconds: default_recovery_interval(),
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

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeesSection {
	/// The most a refresh costs, in parts per million of the coin's value.
	#[serde(default)]
	pub refresh_ppm: u64,
	/// What an offboard costs, in parts per million of what it pays out, on
	/// top of the margin of its output.
	#[serde(default)]
	pub offboard_ppm: u64,
	/// The most margin a co-signed transfer may leave for a fee, as a
	/// multiple of the least (four times the node's floor in an asset it
	/// accepts for fees, one atom in one it does not); 25 when absent.
	#[serde(default)]
	pub max_margin_multiple: Option<u64>,
}

fn default_fee_multiple() -> u64 {
	2
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetSection {
	/// The asset id, display order.
	pub asset: String,
	/// The smallest leaf, in the asset's atoms, as a decimal string.
	pub min_leaf: String,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct StartError(pub String);

fn err<E: std::fmt::Display>(what: &str) -> impl Fn(E) -> StartError + '_ {
	move |e| StartError(format!("{}: {}", what, e))
}

/// Deletes, every `every`, the operator nonces no board took within
/// `nonce_ttl` and the challenges used or expired.
fn housekeeping(store: Store, nonce_ttl: Duration, every: Duration) -> JoinHandle<()> {
	tokio::spawn(async move {
		loop {
			match store.delete_expired(nonce_ttl).await {
				Ok((0, 0)) => {},
				Ok((n, c)) => log::info!("deleted {} expired operator nonce(s) and {} used or expired challenge(s)", n, c),
				Err(e) => log::warn!("deleting expired nonces and challenges: {}", e),
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
			.and_then(|i| i.witness.script_witness.iter().rev().nth(1).cloned());
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

/// A running server.
pub struct Server {
	pub addr: SocketAddr,
	pub store: Store,
	pub params: Arc<Params>,
	pub finality: Arc<FinalityService>,
	pub nursery: Arc<Nursery>,
	pub boards: Arc<Boards>,
	pub wallet: Arc<Wallet>,
	pub cosigner: Arc<Cosigner>,
	pub participations: Arc<Participations>,
	pub rounds: Arc<Rounds>,
	pub forfeits: Arc<Forfeits>,
	pub watcher: Arc<Watcher>,
	tasks: Vec<JoinHandle<()>>,
}

impl Server {
	/// Starts every component from `config`: the store, the finality service
	/// following the node, the signer's key, the wallet, the nursery, the
	/// boards, the co-signer, the rounds, the watcher, their tasks, and the
	/// HTTP listener.
	pub async fn start(config: &Config) -> Result<Server, StartError> {
		let store = Store::connect(&config.database).await.map_err(err("the database"))?;
		let auth = match (&config.node.cookie_file, &config.node.rpc_user, &config.node.rpc_password) {
			(Some(c), _, _) => Auth::CookieFile(c.clone()),
			(None, Some(u), Some(p)) => Auth::UserPass(u.clone(), p.clone()),
			_ => return Err(StartError("the node needs cookie_file, or rpc_user and rpc_password".into())),
		};
		let source: Arc<dyn ChainSource> = Arc::new(NodeSource::new(Client::new(config.node.rpc_url.clone(), auth)));
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
		let signer = SignerClient::new(&config.signer_socket);
		let operator = signer.pubkey().await.map_err(err("the signer"))?;

		let mut assets = BTreeMap::new();
		let mut order = vec![];
		for a in &config.assets {
			let id = AssetId::from_str(&a.asset).map_err(err("assets.asset"))?;
			assets.insert(id, AssetParams { min_leaf: parse_amount(&a.min_leaf).map_err(err("assets.min_leaf"))? });
			order.push(id);
		}
		let mut params = Params::new(Chain::new(genesis), operator, assets);
		params.fee_assets = match &config.fee_assets {
			Some(list) => list.iter().map(|a| AssetId::from_str(a)).collect::<Result<_, _>>().map_err(err("fee_assets"))?,
			None => order,
		};
		params.fees = FeeSchedule { refresh_ppm: config.fees.refresh_ppm, offboard_ppm: config.fees.offboard_ppm };
		if let Some(m) = config.fees.max_margin_multiple {
			if m < 1 {
				return Err(StartError("fees.max_margin_multiple is at least 1".into()));
			}
			params.max_margin_multiple = m;
		}
		if let Some((min, max)) = config.exit_delay_units {
			params.min_exit_delay = RelativeTime::from_units(min).map_err(err("exit_delay_units"))?;
			params.max_exit_delay = RelativeTime::from_units(max).map_err(err("exit_delay_units"))?;
			params.set_delays();
		}
		let params = Arc::new(params);

		let mnemonic = std::fs::read_to_string(&config.wallet_mnemonic_file)
			.map_err(err("wallet_mnemonic_file"))?.trim().to_string();
		let wallet = Arc::new(Wallet::new(store.clone(), finality.clone(), operator,
			WalletConfig { mnemonic, fee_multiple: config.fee_multiple, spend_from: SpendFrom::Final })
			.map_err(err("the wallet"))?);
		let nursery = Nursery::new(store.clone(), finality.clone(), Some(wallet.clone()), Duration::from_secs(30));
		let boards = Boards::new(store.clone(), finality.clone(), nursery.clone(), params.clone(),
			Duration::from_secs(config.limits.board_unconfirmed_seconds));
		let cosigner = Cosigner::new(store.clone(), finality.clone(), params.clone(), signer.clone());
		let participations = Participations::new(store.clone(), finality.clone(), params.clone());
		let rounds = Rounds::new(store.clone(), finality.clone(), params.clone(), wallet.clone(), nursery.clone(), RoundConfig::default());
		let forfeits = Forfeits::new(store.clone(), params.clone(), signer.clone(), cosigner.clone());
		let watcher = Watcher::new(store.clone(), finality.clone(), params.clone(), wallet.clone(), nursery.clone(), signer,
			rounds.clone(), WatcherConfig {
				reclaim_early: config.watcher.reclaim_early,
				max_sweep_inputs: config.watcher.max_sweep_inputs.max(1),
				recovery_interval: Duration::from_secs(config.watcher.recovery_interval_seconds.max(1)),
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
		let interval = (config.round_interval_seconds > 0).then(|| Duration::from_secs(config.round_interval_seconds));
		rounds.pass().await.map_err(err("the first pass over the rounds"))?;
		let mut tasks = vec![nursery.spawn(), boards.spawn(), rounds.spawn(interval)];
		if config.watcher.enabled {
			tasks.push(watcher.spawn());
		}
		tasks.push(finality.spawn());
		tasks.push(housekeeping(store.clone(), Duration::from_secs(config.limits.nonce_ttl_seconds),
			Duration::from_secs(config.limits.cleanup_interval_seconds.max(1))));

		let app = Arc::new(App {
			store: store.clone(), params: params.clone(), boards: boards.clone(), cosigner: cosigner.clone(),
			participations: participations.clone(), rounds: rounds.clone(), forfeits: forfeits.clone(), certification, anchor_depth: config.finality.anchor_depth, max_request: config.max_request_bytes,
			challenge_ttl: Duration::from_secs(config.challenge_ttl_seconds),
			nonces: Limiter::new(config.limits.issue_per_second, config.limits.issue_burst),
			challenges: Limiter::new(config.limits.issue_per_second, config.limits.issue_burst),
		});
		let listener = tokio::net::TcpListener::bind(&config.listen).await.map_err(err("listen"))?;
		let addr = listener.local_addr().map_err(err("listen"))?;
		let routes = router(app);
		tasks.push(tokio::spawn(async move {
			if let Err(e) = axum::serve(listener, routes).await {
				log::error!("the HTTP listener stopped: {}", e);
			}
		}));
		log::info!("arca server on {}: operator {}, genesis {}", addr, crate::signer::hex(&operator.serialize()), genesis);
		Ok(Server { addr, store, params, finality, nursery, boards, wallet, cosigner, participations, rounds, forfeits, watcher, tasks })
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
		assert_eq!(c.limits.issue_per_second, 5);
		assert_eq!(c.limits.nonce_ttl_seconds, 3600);
	}
}
