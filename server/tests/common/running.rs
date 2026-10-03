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
use server::server::{AssetSection, Config, FinalitySection, NodeConfig, Server};

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
		let db = TestDb::new().await;
		let rt = tokio::task::block_in_place(node::start);
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
			node: NodeConfig {
				rpc_url: format!("http://127.0.0.1:{}/", rt.node.rpc_port()),
				cookie_file: None, rpc_user: Some("arca".into()), rpc_password: Some("arca".into()),
			},
			finality: FinalitySection { poll_interval_ms: 200, ..Default::default() },
			exit_delay_units: None,
			assets: vec![AssetSection { asset: x.to_string(), min_leaf: MIN_LEAF.to_string() }],
			fee_assets: None,
			fees: Default::default(),
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
		let nonce = self.http.operator_nonce();
		let record = super::client::board_record(owner, nonce, self.x, value, self.chain, self.s.x_only_public_key().0);
		let coin = self.purse.take_coin(self.x);
		let tx = super::client::board_tx(&record, &coin, 2_000, node::op_true());
		self.purse.put((OutPoint::new(tx.txid(), 1), tx.output[1].clone()));
		self.rt.client().send_raw_transaction(&tx).unwrap();
		let answer = self.http.register_board(&record, &tx).ok();
		(record, tx, answer)
	}

	/// Pays the server's wallet `amount` of X.
	pub async fn fund_wallet(&mut self, amount: u64) {
		let to = self.server.wallet.receive_script().await.unwrap();
		tokio::task::block_in_place(|| self.purse.pay(&self.rt, vec![explicit_txout(AssetAmount::new(self.x, amount), to)]));
	}

	/// Whether the node holds `txid`'s output `vout` unspent.
	pub fn unspent(&self, op: &OutPoint) -> bool {
		let v: Value = self.rt.client().call("gettxout", &[json!(op.txid.to_string()), json!(op.vout), json!(true)]).unwrap();
		!v.is_null()
	}
}
