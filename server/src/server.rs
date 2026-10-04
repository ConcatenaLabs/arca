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
	/// Where the operator's metrics are served (`GET /metrics`, the text
	/// format Prometheus reads), for the operator alone: a loopback address.
	/// None are served when absent.
	#[serde(default)]
	pub metrics_listen: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
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
	/// witness's own, apart from the nonces'. Each witness takes the
	/// signer's record lock and up to 34 of its signatures.
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
		}
	}
}

fn default_witness_per_second() -> u32 {
	500
}

fn default_witness_burst() -> u32 {
	5_000
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
}

impl Default for WatcherSection {
	fn default() -> WatcherSection {
		WatcherSection {
			enabled: true, reclaim_early: default_true(), max_sweep_inputs: default_sweep_inputs(),
			recovery_interval_seconds: default_recovery_interval(), max_claim_inputs: default_claim_inputs(),
			block_share_vbytes: default_block_share(), block_interval_seconds: default_block_interval(),
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
			CoinRecord::Transfer(t) => t.inputs.iter().map(|i| last_expiry(&i.coin)).try_fold(0u32, |m, e| e.map(|e| m.max(e))),
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
				max_claim_inputs: config.watcher.max_claim_inputs.max(1),
				block_share_vbytes: config.watcher.block_share_vbytes.max(1),
				block_interval: Duration::from_secs(config.watcher.block_interval_seconds.max(1)),
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
		let interval = (config.round_interval_seconds > 0).then(|| Duration::from_secs(config.round_interval_seconds));
		rounds.pass().await.map_err(err("the first pass over the rounds"))?;
		let mut tasks = vec![nursery.spawn(), boards.spawn(), rounds.spawn(interval)];
		if config.watcher.enabled {
			tasks.push(watcher.spawn());
		}
		tasks.push(finality.spawn());
		tasks.push(housekeeping(store.clone(), Duration::from_secs(config.limits.nonce_ttl_seconds),
			Duration::from_secs(config.limits.cleanup_interval_seconds.max(1))));
		tasks.push({
			let forfeits = forfeits.clone();
			tokio::spawn(async move {
				loop {
					tokio::time::sleep(Duration::from_secs(60)).await;
					match forfeits.fill_unsigned().await {
						Ok(0) => {},
						Ok(n) => log::info!("{} forfeit(s) given the operator's half", n),
						Err(e) => log::warn!("forfeits without the operator's half: {}", e),
					}
				}
			})
		});

		let app = Arc::new(App {
			store: store.clone(), params: params.clone(), boards: boards.clone(), cosigner: cosigner.clone(),
			participations: participations.clone(), rounds: rounds.clone(), forfeits: forfeits.clone(), certification, anchor_depth: config.finality.anchor_depth, max_request: config.max_request_bytes,
			challenge_ttl: Duration::from_secs(config.challenge_ttl_seconds),
			nonces: Limiter::new(config.limits.issue_per_second, config.limits.issue_burst, config.limits.source_per_second,
				config.limits.source_burst),
			witnesses: Limiter::new(config.limits.witness_per_second, config.limits.witness_burst, config.limits.witness_source_per_second,
				config.limits.witness_source_burst),
			challenge_key: store.challenge_key().await.map_err(err("the database"))?,
			trusted_proxies: config.limits.trusted_proxies.iter().map(|a| a.parse())
				.collect::<Result<_, _>>().map_err(err("limits.trusted_proxies"))?,
			floors: tokio::sync::Mutex::new(None),
			record_head: tokio::sync::Mutex::new(None),
			keepers: std::sync::Mutex::new(keepers),
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
		log::info!("arca server on {}: operator {}, genesis {}", addr, crate::signer::hex(&operator.serialize()), genesis);
		Ok(Server { addr, metrics_addr, store, params, finality, nursery, boards, wallet, cosigner, participations, rounds, forfeits, watcher, tasks })
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
