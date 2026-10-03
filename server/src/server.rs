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

use arca_covenant::{Chain, RelativeTime};
use sequentia_ext::rpc::{Auth, Client};

use crate::boards::Boards;
use crate::chain::{Certification, ChainSource, FinalityConfig, FinalityService, NodeSource};
use crate::cosign::Cosigner;
use crate::http::{router, App};
use crate::nursery::Nursery;
use crate::params::{AssetParams, FeeSchedule, Params};
use crate::participations::Participations;
use crate::rounds::{RoundConfig, Rounds};
use crate::signer::{parse_amount, SignerClient};
use crate::store::Store;
use crate::wallet::{SpendFrom, Wallet, WalletConfig};

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
	tasks: Vec<JoinHandle<()>>,
}

impl Server {
	/// Starts every component from `config`: the store, the finality service
	/// following the node, the signer's key, the wallet, the nursery, the
	/// boards, the co-signer, their tasks, and the HTTP listener.
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
		let boards = Boards::new(store.clone(), finality.clone(), nursery.clone(), params.clone());
		let cosigner = Cosigner::new(store.clone(), finality.clone(), params.clone(), signer);
		let participations = Participations::new(store.clone(), finality.clone(), params.clone());
		let rounds = Rounds::new(store.clone(), finality.clone(), params.clone(), wallet.clone(), nursery.clone(), RoundConfig::default());

		// The first pass before anything is answered, so the chain is known.
		finality.sync().await.map_err(err("the first pass over the chain"))?;
		let interval = (config.round_interval_seconds > 0).then(|| Duration::from_secs(config.round_interval_seconds));
		rounds.pass().await.map_err(err("the first pass over the rounds"))?;
		let mut tasks = vec![nursery.spawn(), boards.spawn(), rounds.spawn(interval)];
		tasks.push(finality.spawn());

		let app = Arc::new(App {
			store: store.clone(), params: params.clone(), boards: boards.clone(), cosigner: cosigner.clone(),
			participations: participations.clone(), rounds: rounds.clone(), certification, anchor_depth: config.finality.anchor_depth, max_request: config.max_request_bytes,
			challenge_ttl: Duration::from_secs(config.challenge_ttl_seconds),
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
		Ok(Server { addr, store, params, finality, nursery, boards, wallet, cosigner, participations, rounds, tasks })
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
	}
}
