//! A whole Arca server as an operator runs it: `arca-signer` in its own
//! process, `Server::start` with its tasks and its HTTP listener, on an
//! anchored proof-of-stake regtest chain. It serves asset X (listed for fees
//! on the node) and asset Y (not listed), and its wallet holds no policy asset.

use std::time::{Duration, Instant};

use elements::hashes::{sha256, Hash};
use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey};
use elements::{AssetId, Transaction, Txid};

use sequentia_ext::regtest::Regtest;
use sequentia_ext::{explicit_txout, AssetAmount};
use server::server::{AssetSection, Config, FinalitySection, LimitsSection, NodeConfig, Server, WatcherSection};
use server::store::RoundState;

use super::db::TestDb;
use super::node::{self, Purse};
use super::keeper::KeeperProcess;
use super::signer::SignerProcess;

pub const MIN_LEAF: u64 = 1_000;

/// The BIP39 test mnemonic every wallet library knows: the operator's
/// on-chain wallet, on regtest only.
pub const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// A test key derived from a label, for regtest only.
pub fn keypair(label: &str) -> Keypair {
	let secret = sha256::Hash::hash(format!("Arca CLI test key/{}", label).as_bytes());
	Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(secret.as_byte_array()).unwrap())
}

pub struct Running {
	pub server: Server,
	pub config: Config,
	pub rt: Regtest,
	pub purse: Purse,
	pub x: AssetId,
	pub y: AssetId,
	pub signer: SignerProcess,
	pub db: TestDb,
	/// The keepers of the signer's record, each on a port of its own, as on
	/// other machines; none unless the test starts some.
	pub keepers: Vec<KeeperProcess>,
}

impl Running {
	/// The server, its wallet funded in X and Y and final. Leaves take exit
	/// delays from one 512-second unit, so a test can wait one out.
	pub async fn start() -> Running {
		Self::start_kept(0, None).await
	}

	/// The server, its signer handing every head to `keepers` keepers of its
	/// own, `required` of them (all, unless named) to hold each.
	pub async fn start_kept(keepers: usize, required: Option<usize>) -> Running {
		let db = TestDb::new().await;
		let rt = tokio::task::block_in_place(node::start);
		let mut purse = tokio::task::block_in_place(|| Purse::new(&rt));
		let x = tokio::task::block_in_place(|| purse.issue(&rt, "asset X", 100_000_000_000));
		let y = tokio::task::block_in_place(|| purse.issue(&rt, "asset Y", 100_000_000_000));
		node::list_fee_asset(&rt, x, 100_000_000);
		let s = keypair("operator");
		let genesis = rt.client().genesis_hash().unwrap();
		let keepers: Vec<KeeperProcess> = (0..keepers).map(|i| tokio::task::block_in_place(||
			KeeperProcess::start(&keypair(&format!("keeper {}", i)), s.x_only_public_key().0, genesis))).collect();
		let mut extra = vec![];
		for k in &keepers {
			extra.push("--keeper".to_string());
			extra.push(k.arg());
		}
		if let Some(r) = required {
			extra.push("--keepers-required".into());
			extra.push(r.to_string());
		}
		extra.push("--keeper-timeout-ms".into());
		extra.push("2000".into());
		let signer = tokio::task::block_in_place(|| SignerProcess::start_with(&s, genesis, extra));
		let mnemonic = signer.dir.join("wallet.mnemonic");
		std::fs::write(&mnemonic, MNEMONIC).unwrap();
		let config = Config {
			listen: "127.0.0.1:0".into(),
			database: db.url.clone(),
			signer_socket: signer.socket.clone(),
			wallet_mnemonic_file: mnemonic,
			fee_multiple: 2,
			max_request_bytes: 64 * 1024,
			challenge_ttl_seconds: 120,
			// The test builds each round when it wants one.
			round_interval_seconds: 0,
			node: NodeConfig {
				rpc_url: format!("http://127.0.0.1:{}/", rt.node.rpc_port()),
				cookie_file: None, rpc_user: Some("arca".into()), rpc_password: Some("arca".into()),
			},
			finality: FinalitySection { poll_interval_ms: 200, ..Default::default() },
			exit_delay_units: Some((1, 338)),
			assets: vec![
				AssetSection { asset: x.to_string(), min_leaf: MIN_LEAF.to_string() },
				AssetSection { asset: y.to_string(), min_leaf: MIN_LEAF.to_string() },
			],
			fee_assets: None,
			fees: Default::default(),
			// The watcher acts on the chain for the operator, as it does on a
			// server in use: the wallet must hold its coins with it on.
			watcher: WatcherSection::default(),
			// The scenarios ask for nonces, challenges and witnesses faster
			// than one wallet does.
			limits: LimitsSection {
				issue_per_second: 10_000, issue_burst: 10_000, source_per_second: 10_000, source_burst: 10_000,
				witness_per_second: 10_000, witness_burst: 10_000, witness_source_per_second: 10_000, witness_source_burst: 10_000,
				..Default::default()
			},
			metrics_listen: None,
		};
		let server = Server::start(&config).await.unwrap();
		let mut r = Running { server, config, rt, purse, x, y, signer, db, keepers };
		r.fund_server(x, 50_000_000).await;
		r.fund_server(x, 50_000_000).await;
		r.fund_server(y, 50_000_000).await;
		r.produce().await;
		r.bury().await;
		r.synced().await;
		r
	}

	pub fn url(&self) -> String {
		format!("http://{}", self.server.addr)
	}

	/// Stops the server and starts a new one on the same database, at the
	/// same address, so every wallet reaches it as before.
	pub async fn restart_server(&mut self) {
		let addr = self.server.addr;
		self.server.stop();
		self.config.listen = addr.to_string();
		let start = Instant::now();
		loop {
			match Server::start(&self.config).await {
				Ok(s) => {
					self.server = s;
					return;
				},
				Err(e) => {
					assert!(start.elapsed() < Duration::from_secs(20), "the server did not start again at {}: {}", addr, e);
					tokio::time::sleep(Duration::from_millis(200)).await;
				},
			}
		}
	}

	pub fn node_url(&self) -> String {
		format!("http://127.0.0.1:{}/", self.rt.node.rpc_port())
	}

	async fn fund_server(&mut self, asset: AssetId, amount: u64) -> Transaction {
		let to = self.server.wallet.receive_script().await.unwrap();
		tokio::task::block_in_place(|| self.purse.pay(&self.rt, vec![explicit_txout(AssetAmount::new(asset, amount), to)]))
	}

	/// Pays `amount` of `asset` to `script` from the purse, broadcast.
	pub fn pay_to(&mut self, script: elements::Script, asset: AssetId, amount: u64) -> Transaction {
		tokio::task::block_in_place(|| self.purse.pay(&self.rt, vec![explicit_txout(AssetAmount::new(asset, amount), script)]))
	}

	pub async fn produce(&self) {
		tokio::task::block_in_place(|| self.rt.produce_block()).unwrap();
	}

	pub async fn bury(&self) {
		tokio::task::block_in_place(|| node::bury(&self.rt));
	}

	/// Waits until the server has followed the chain to the node's tip.
	pub async fn synced(&self) {
		let tip = self.rt.client().best_block_hash().unwrap();
		let start = Instant::now();
		loop {
			if self.server.store.tip_block().await.unwrap().map(|b| b.hash) == Some(tip.to_byte_array()) {
				return;
			}
			assert!(start.elapsed() < Duration::from_secs(60), "the server did not reach the tip");
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}

	/// Waits until the server has the round `txid` in `state`.
	pub async fn round_state(&self, txid: &Txid, state: RoundState) {
		let start = Instant::now();
		loop {
			self.server.rounds.pass().await.unwrap();
			if self.server.store.round_by_txid(&txid.to_byte_array()).await.unwrap().map(|x| x.state) == Some(state) {
				return;
			}
			assert!(start.elapsed() < Duration::from_secs(60), "the round did not become {:?}", state);
			tokio::time::sleep(Duration::from_millis(200)).await;
		}
	}

	/// Waits until `f` holds.
	pub async fn wait<F: FnMut() -> bool>(&self, what: &str, mut f: F) {
		let start = Instant::now();
		loop {
			if tokio::task::block_in_place(&mut f) {
				return;
			}
			assert!(start.elapsed() < Duration::from_secs(60), "timed out waiting for {}", what);
			tokio::time::sleep(Duration::from_millis(200)).await;
		}
	}
}

