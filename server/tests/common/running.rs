//! A whole server running as an operator runs it: `arca-signer` in its own
//! process holding `S`, `Server::start` with its tasks and its HTTP listener,
//! on an anchored proof-of-stake regtest chain, its wallet paid in asset X
//! only, never the policy asset.

use std::time::{Duration, Instant};

use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Transaction};
use serde_json::{json, Value};

use arca_covenant::{Chain, MedianTime, WalletPolicy};
use sequentia_ext::regtest::Regtest;
use sequentia_ext::{explicit_txout, AssetAmount};
use server::server::{AssetSection, Config, FinalitySection, LimitsSection, NodeConfig, Server, WatcherSection};

use super::client::Http;
use super::db::TestDb;
use super::keys::{keypair, MNEMONIC};
use super::node::{self, Purse};
use super::signer::SignerProcess;

pub const MIN_LEAF: u64 = 1_000;

pub struct Running {
	pub server: Server,
	pub config: Config,
	pub http: Http,
	pub rt: Regtest,
	pub purse: Purse,
	pub x: AssetId,
	pub y: AssetId,
	pub s: Keypair,
	pub chain: Chain,
	pub signer: SignerProcess,
	pub db: TestDb,
}

impl Running {
	pub async fn start() -> Running {
		Running::start_with(|_, _| {}).await
	}

	/// [`Running::start`], with the server's configuration changed by `tune`
	/// first. `tune` is given the configuration and asset Y.
	pub async fn start_with<F: FnOnce(&mut Config, AssetId)>(tune: F) -> Running {
		Running::start_on(&[], tune).await
	}

	/// [`Running::start_with`] on a node given `node_args` as well.
	pub async fn start_on<F: FnOnce(&mut Config, AssetId)>(node_args: &[&str], tune: F) -> Running {
		// The server's log, at the level RUST_LOG names.
		let _ = env_logger::builder().is_test(true).try_init();
		let db = TestDb::new().await;
		let rt = tokio::task::block_in_place(|| node::start_with(node_args));
		let mut purse = tokio::task::block_in_place(|| Purse::new(&rt));
		let x = tokio::task::block_in_place(|| purse.issue(&rt, "asset X", 100_000_000_000));
		let y = tokio::task::block_in_place(|| purse.issue(&rt, "asset Y", 100_000_000_000));
		node::list_fee_asset(&rt, x, 100_000_000);
		let s = keypair("operator");
		let genesis = rt.client().genesis_hash().unwrap();
		let signer = tokio::task::block_in_place(|| SignerProcess::start(&s, genesis));
		let mnemonic = signer.dir.join("wallet.mnemonic");
		std::fs::write(&mnemonic, MNEMONIC).unwrap();
		let mut config = Config {
			listen: "127.0.0.1:0".into(),
			database: db.url.clone(),
			signer_socket: signer.socket.clone(),
			wallet_mnemonic_file: mnemonic,
			fee_multiple: 2,
			max_request_bytes: 64 * 1024,
			challenge_ttl_seconds: 120,
			// The tests build each round by hand.
			round_interval_seconds: 0,
			node: NodeConfig {
				rpc_url: format!("http://127.0.0.1:{}/", rt.node.rpc_port()),
				cookie_file: None, rpc_user: Some("arca".into()), rpc_password: Some("arca".into()),
			},
			finality: FinalitySection { poll_interval_ms: 200, ..Default::default() },
			exit_delay_units: None,
			assets: vec![AssetSection { asset: x.to_string(), min_leaf: MIN_LEAF.to_string() }],
			fee_assets: None,
			fees: Default::default(),
			// The tests before the watcher's drive every step by hand; a test
			// of the watcher turns it on, or calls its pass.
			watcher: WatcherSection { enabled: false, ..Default::default() },
			// The tests ask for nonces, challenges and witnesses faster than
			// a wallet does; the test of the limits sets them itself.
			limits: LimitsSection {
				issue_per_second: 10_000, issue_burst: 10_000, source_per_second: 10_000, source_burst: 10_000,
				witness_per_second: 10_000, witness_burst: 10_000, witness_source_per_second: 10_000, witness_source_burst: 10_000,
				read_per_second: 10_000, read_burst: 10_000, read_source_per_second: 10_000, read_source_burst: 10_000,
				..Default::default()
			},
			metrics_listen: None,
		};
		tune(&mut config, y);
		let server = Server::start(&config).await.unwrap();
		let http = Http { base: format!("http://{}", server.addr) };
		Running { server, config, http, rt, purse, x, y, s, chain: Chain::new(genesis), signer, db }
	}

	/// Stops the server and starts a new one on the same database: what it
	/// knows must survive.
	pub async fn restart_server(&mut self) {
		self.server.stop();
		self.server = Server::start(&self.config).await.unwrap();
		self.http = Http { base: format!("http://{}", self.server.addr) };
	}

	/// Every entry of the signer's record.
	pub async fn signer_entries(&self) -> Vec<server::signer::Entry> {
		let client = server::signer::SignerClient::new(&self.signer.socket);
		let mut all = vec![];
		loop {
			let page = client.entries(all.len() as u64).await.unwrap();
			if page.is_empty() {
				return all;
			}
			all.extend(page);
		}
	}

	/// Waits until `f` holds, polling.
	pub async fn wait<F: FnMut() -> bool>(&self, what: &str, mut f: F) {
		let start = Instant::now();
		loop {
			if tokio::task::block_in_place(&mut f) {
				return;
			}
			assert!(start.elapsed() < Duration::from_secs(60), "timed out waiting for {}", what);
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
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
		let store = self.server.store.clone();
		let start = Instant::now();
		loop {
			if store.tip_block().await.unwrap().map(|b| b.hash) == Some(elements::hashes::Hash::to_byte_array(tip)) {
				return;
			}
			assert!(start.elapsed() < Duration::from_secs(60), "the server did not reach the tip");
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}

	/// A wallet's policy at the chain's tip.
	pub fn policy(&self) -> WalletPolicy {
		let mtp = self.rt.client().blockchain_info().unwrap().median_time as u32;
		WalletPolicy::new(self.chain, self.s.x_only_public_key().0, MedianTime::from_consensus(mtp).unwrap()).receipt()
	}

	/// A board of `value` of X for `owner`, paid and registered over HTTP;
	/// its transaction, and the answer.
	pub fn board(&mut self, owner: &Keypair, value: u64) -> (arca_covenant::BoardRecord, Transaction, Value) {
		self.board_in(owner, self.x, value)
	}

	/// [`Running::board`] in `asset`.
	pub fn board_in(&mut self, owner: &Keypair, asset: AssetId, value: u64) -> (arca_covenant::BoardRecord, Transaction, Value) {
		let nonce = self.http.operator_nonce();
		let record = super::client::board_record(owner, nonce, asset, value, self.chain, self.s.x_only_public_key().0);
		// The fee in X, which the node accepts: a board in another asset
		// takes an X coin as well.
		let mut coins = vec![self.purse.take_coin(asset)];
		if asset != self.x {
			coins.push(self.purse.take_coin(self.x));
		}
		let tx = record.tx(&coins, self.x, 2_000, &node::op_true()).unwrap().tx;
		for (j, o) in tx.output.iter().enumerate().skip(1) {
			if !o.is_fee() {
				self.purse.put((OutPoint::new(tx.txid(), j as u32), o.clone()));
			}
		}
		self.rt.client().send_raw_transaction(&tx).unwrap();
		let answer = self.http.register_board(&record, &tx).ok();
		(record, tx, answer)
	}

	/// Pays the server's wallet `amount` of X.
	pub async fn fund_wallet(&mut self, amount: u64) {
		let x = self.x;
		self.fund_wallet_in(x, amount).await;
	}

	/// Pays the server's wallet `amount` of `asset`, in one coin.
	pub async fn fund_wallet_in(&mut self, asset: AssetId, amount: u64) -> Transaction {
		let to = self.server.wallet.receive_script().await.unwrap();
		tokio::task::block_in_place(|| self.purse.pay(&self.rt, vec![explicit_txout(AssetAmount::new(asset, amount), to)]))
	}

	/// Whether the node holds `txid`'s output `vout` unspent.
	pub fn unspent(&self, op: &OutPoint) -> bool {
		let v: Value = self.rt.client().call("gettxout", &[json!(op.txid.to_string()), json!(op.vout), json!(true)]).unwrap();
		!v.is_null()
	}
}
