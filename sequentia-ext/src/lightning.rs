//! SeqLN Lightning nodes on a regtest chain, for tests.
//!
//! [`LightningNode::start`] runs SeqLN's `lightningd` on a chain started with
//! [`Regtest::start_seqln`], whose name, arguments and genesis block are the
//! ones SeqLN's `sequentia-regtest` network assumes. The node reaches the
//! chain through `sequentia-cli`, found beside the `sequentiad` the chain
//! runs, and is spoken to over its JSON-RPC socket, as an operator's server
//! speaks to it. It is stopped, and its directory deleted, on drop.
//!
//! The tests that need nodes read `LIGHTNINGD_EXEC`, the path of a SeqLN
//! `lightningd` (`make all-programs` in a SeqLN checkout): the hold-invoice
//! plugin is taken from the same checkout (`contrib/holdinvoice-seq`).
//!
//! The Bitcoin side runs the same `lightningd` on a Bitcoin Core regtest
//! chain ([`BitcoinRegtest`], `BITCOIND_EXEC`, with `bitcoin-cli` beside it):
//! native BTC, on Bitcoin.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::regtest::Regtest;
use crate::{AssetId, Script};

/// The `lightningd` named by `LIGHTNINGD_EXEC`, when it is set.
pub fn lightningd_from_env() -> Option<PathBuf> {
	std::env::var_os("LIGHTNINGD_EXEC").map(PathBuf::from)
}

/// The hold-invoice plugin of the SeqLN checkout `lightningd` was built in.
pub fn hold_plugin(lightningd: &Path) -> PathBuf {
	lightningd.parent().and_then(|d| d.parent()).map(|root| root.join("contrib/holdinvoice-seq/holdinvoice.py"))
		.unwrap_or_else(|| PathBuf::from("holdinvoice.py"))
}

fn free_port() -> u16 {
	std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).expect("a free port")
}

/// A Bitcoin Core regtest node, for a Lightning node on Bitcoin. It is
/// stopped, and its data deleted, on drop.
pub struct BitcoinRegtest {
	child: Child,
	dir: PathBuf,
	exe: PathBuf,
	pub rpc_port: u16,
}

impl BitcoinRegtest {
	/// The `bitcoind` named by `BITCOIND_EXEC`, when it is set.
	pub fn exe_from_env() -> Option<PathBuf> {
		std::env::var_os("BITCOIND_EXEC").map(PathBuf::from)
	}

	/// Starts `bitcoind` on regtest under `dir`, with a wallet, and waits
	/// until it answers.
	pub fn start(exe: &Path, dir: &Path) -> Result<BitcoinRegtest, String> {
		let _ = std::fs::remove_dir_all(dir);
		std::fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
		let rpc_port = free_port();
		let child = Command::new(exe).args([
			"-regtest".to_string(), format!("-datadir={}", dir.display()), format!("-rpcport={}", rpc_port),
			format!("-port={}", free_port()), "-listen=0".into(), "-server".into(), "-printtoconsole=0".into(),
			"-rpcuser=arca".into(), "-rpcpassword=arca".into(), "-fallbackfee=0.00001".into(), "-txindex=1".into(),
		]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e| format!("cannot start {}: {}", exe.display(), e))?;
		let b = BitcoinRegtest { child, dir: dir.to_path_buf(), exe: exe.to_path_buf(), rpc_port };
		let start = Instant::now();
		while b.cli(&["getblockcount"]).is_err() {
			if start.elapsed() > Duration::from_secs(60) {
				return Err("bitcoind did not answer within 60 s".into());
			}
			std::thread::sleep(Duration::from_millis(200));
		}
		b.cli(&["createwallet", "arca"])?;
		Ok(b)
	}

	/// `bitcoin-cli`, found beside `bitcoind`.
	pub fn cli_path(&self) -> PathBuf {
		self.exe.parent().map(|d| d.join("bitcoin-cli")).unwrap_or_else(|| PathBuf::from("bitcoin-cli"))
	}

	/// Runs `bitcoin-cli` with `args`; its output, trimmed.
	pub fn cli(&self, args: &[&str]) -> Result<String, String> {
		let out = Command::new(self.cli_path()).args(["-regtest".to_string(), format!("-datadir={}", self.dir.display()),
			format!("-rpcport={}", self.rpc_port), "-rpcuser=arca".into(), "-rpcpassword=arca".into()]).args(args)
			.output().map_err(|e| e.to_string())?;
		if !out.status.success() {
			return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
		}
		Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
	}

	/// Mines `n` blocks to its wallet.
	pub fn mine(&self, n: u32) {
		let to = self.cli(&["getnewaddress"]).expect("an address");
		self.cli(&["generatetoaddress", &n.to_string(), &to]).expect("blocks");
	}

	pub fn dir(&self) -> &Path {
		&self.dir
	}
}

impl Drop for BitcoinRegtest {
	fn drop(&mut self) {
		let _ = self.cli(&["stop"]);
		let start = Instant::now();
		while start.elapsed() < Duration::from_secs(30) {
			if let Ok(Some(_)) = self.child.try_wait() {
				break;
			}
			std::thread::sleep(Duration::from_millis(100));
		}
		let _ = self.child.kill();
		let _ = self.child.wait();
		let _ = std::fs::remove_dir_all(&self.dir);
	}
}

/// One running `lightningd`.
pub struct LightningNode {
	child: Child,
	dir: PathBuf,
	/// Its node id.
	pub id: String,
	/// The port it listens on, on 127.0.0.1.
	pub port: u16,
	network: String,
}

impl LightningNode {
	/// Starts `lightningd` under `dir` on `rt`'s chain, with `plugins`, and
	/// waits until it answers.
	pub fn start(rt: &Regtest, lightningd: &Path, dir: &Path, plugins: &[PathBuf]) -> Result<LightningNode, String> {
		let cli = std::env::var_os("SEQUENTIAD_EXEC").map(PathBuf::from)
			.and_then(|d| d.parent().map(|p| p.join("sequentia-cli")))
			.ok_or("SEQUENTIAD_EXEC names the sequentiad the chain runs; sequentia-cli is taken beside it")?;
		LightningNode::start_with(&rt.chain_name(), &cli, rt.node.datadir(), rt.node.rpc_port(), lightningd, dir, plugins)
	}

	/// Starts `lightningd` under `dir` on the Bitcoin regtest chain `btc`.
	pub fn start_on_bitcoin(btc: &BitcoinRegtest, lightningd: &Path, dir: &Path, plugins: &[PathBuf]) -> Result<LightningNode, String> {
		LightningNode::start_with("regtest", &btc.cli_path(), btc.dir(), btc.rpc_port, lightningd, dir, plugins)
	}

	fn start_with(network: &str, cli: &Path, datadir: &Path, rpc_port: u16, lightningd: &Path, dir: &Path, plugins: &[PathBuf])
		-> Result<LightningNode, String>
	{
		let _ = std::fs::remove_dir_all(dir);
		std::fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
		let network = network.to_string();
		let port = free_port();
		let mut args = vec![
			"--developer".to_string(),
			format!("--network={}", network),
			format!("--lightning-dir={}", dir.display()),
			format!("--bitcoin-cli={}", cli.display()),
			format!("--bitcoin-datadir={}", datadir.display()),
			"--bitcoin-rpcuser=arca".into(), "--bitcoin-rpcpassword=arca".into(),
			"--bitcoin-rpcconnect=127.0.0.1".into(),
			format!("--bitcoin-rpcport={}", rpc_port),
			format!("--addr=127.0.0.1:{}", port),
			format!("--log-file={}", dir.join("log").display()),
			"--log-level=debug".into(),
			"--dev-bitcoind-poll=1".into(),
			"--dev-fast-gossip".into(),
			"--disable-dns".into(),
		];
		for p in plugins {
			args.push(format!("--plugin={}", p.display()));
		}
		let child = Command::new(lightningd).args(&args).stdout(Stdio::null()).stderr(Stdio::null())
			.spawn().map_err(|e| format!("cannot start {}: {}", lightningd.display(), e))?;
		let mut n = LightningNode { child, dir: dir.to_path_buf(), id: String::new(), port, network };
		let start = Instant::now();
		loop {
			match n.call("getinfo", json!({})) {
				Ok(info) => {
					n.id = info["id"].as_str().unwrap_or("").to_string();
					return Ok(n);
				},
				Err(e) => {
					if let Ok(Some(status)) = n.child.try_wait() {
						return Err(format!("lightningd exited ({}) before answering; see {}", status, dir.join("log").display()));
					}
					if start.elapsed() > Duration::from_secs(60) {
						return Err(format!("lightningd did not answer within 60 s: {}", e));
					}
					std::thread::sleep(Duration::from_millis(250));
				},
			}
		}
	}

	/// Its JSON-RPC socket.
	pub fn rpc_path(&self) -> PathBuf {
		self.dir.join(&self.network).join("lightning-rpc")
	}

	/// Its directory.
	pub fn dir(&self) -> &Path {
		&self.dir
	}

	/// Calls `method` with `params` (an object).
	pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
		call_at(&self.rpc_path(), method, params)
	}

	/// [`LightningNode::call`], which must succeed.
	pub fn ok(&self, method: &str, params: Value) -> Value {
		self.call(method, params).unwrap_or_else(|e| panic!("{}", e))
	}
}

/// Calls `method` with `params` (an object) on the node whose JSON-RPC
/// socket is `rpc`: a call that blocks (a `pay` the payee holds) can run on a
/// thread of its own with the path alone.
pub fn call_at(rpc: &Path, method: &str, params: Value) -> Result<Value, String> {
	{
		let mut s = UnixStream::connect(rpc).map_err(|e| e.to_string())?;
		s.set_read_timeout(Some(Duration::from_secs(300))).map_err(|e| e.to_string())?;
		let req = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
		s.write_all(&serde_json::to_vec(&req).expect("JSON")).map_err(|e| e.to_string())?;
		let mut buf = vec![];
		let mut chunk = [0u8; 16 * 1024];
		loop {
			let n = s.read(&mut chunk).map_err(|e| e.to_string())?;
			if n == 0 {
				return Err(format!("{}: the connection closed", method));
			}
			buf.extend_from_slice(&chunk[..n]);
			let mut it = serde_json::Deserializer::from_slice(&buf).into_iter::<Value>();
			match it.next() {
				Some(Ok(v)) => {
					if let Some(e) = v.get("error") {
						return Err(format!("{}: {}", method, e));
					}
					return Ok(v["result"].clone());
				},
				Some(Err(e)) if e.is_eof() => continue,
				Some(Err(e)) => return Err(e.to_string()),
				None => continue,
			}
		}
	}
}

impl LightningNode {

	/// A fresh on-chain address of its wallet, as the script it pays.
	pub fn receive_script(&self, rt: &Regtest) -> Script {
		let addr = self.ok("newaddr", json!({ "addresstype": "bech32" }))["bech32"].as_str().expect("an address").to_string();
		let info: Value = rt.client().call("validateaddress", &[json!(addr)]).expect("the node reads the address");
		let hex = info["scriptPubKey"].as_str().expect("a script");
		Script::from(<Vec<u8> as elements::hex::FromHex>::from_hex(hex).expect("hex"))
	}

	/// Waits until its wallet holds at least `n` confirmed outputs.
	pub fn wait_funds(&self, n: usize) {
		self.wait("its funds", |me| me.ok("listfunds", json!({}))["outputs"].as_array()
			.map(|o| o.iter().filter(|x| x["status"] == "confirmed").count() >= n).unwrap_or(false));
	}

	/// Waits until `f` holds, at most a minute.
	pub fn wait<F: Fn(&LightningNode) -> bool>(&self, what: &str, f: F) {
		let start = Instant::now();
		while !f(self) {
			assert!(start.elapsed() < Duration::from_secs(60), "{}: timed out waiting for {}", self.dir.display(), what);
			std::thread::sleep(Duration::from_millis(250));
		}
	}

	/// Connects to `peer`.
	pub fn connect(&self, peer: &LightningNode) {
		self.ok("connect", json!({ "id": peer.id, "host": "127.0.0.1", "port": peer.port }));
	}

	/// Opens a channel to `peer` of `atoms` of `asset`, pushing `push` atoms
	/// to it, and produces blocks until both sides see it open. Returns the
	/// funding txid.
	pub fn open_channel(&self, rt: &Regtest, peer: &LightningNode, asset: AssetId, atoms: u64, push: u64) -> String {
		self.open(peer, Some(asset), atoms, push, &|| { rt.produce_block().expect("a block"); })
	}

	/// Opens a channel in bitcoin to `peer`, on the Bitcoin chain `btc`.
	pub fn open_bitcoin_channel(&self, btc: &BitcoinRegtest, peer: &LightningNode, sats: u64, push: u64) -> String {
		self.open(peer, None, sats, push, &|| btc.mine(1))
	}

	fn open(&self, peer: &LightningNode, asset: Option<AssetId>, atoms: u64, push: u64, block: &dyn Fn()) -> String {
		self.connect(peer);
		let mut params = json!({ "id": peer.id, "amount": atoms });
		if let Some(a) = asset {
			params["asset"] = json!(a.to_string());
		}
		if push > 0 {
			params["push_msat"] = json!(push * 1000);
		}
		let r = self.ok("fundchannel", params);
		let txid = r["txid"].as_str().expect("a funding txid").to_string();
		let start = Instant::now();
		loop {
			block();
			let both = [self, peer].iter().all(|n| {
				let other = if std::ptr::eq(*n, self) { &peer.id } else { &self.id };
				n.ok("listpeerchannels", json!({ "id": other }))["channels"].as_array().into_iter().flatten()
					.any(|c| c["funding_txid"].as_str() == Some(&txid) && c["state"] == "CHANNELD_NORMAL")
			});
			if both {
				return txid;
			}
			assert!(start.elapsed() < Duration::from_secs(90), "the channel {} did not open", txid);
			std::thread::sleep(Duration::from_millis(500));
		}
	}

	/// Stops it and waits for it to exit.
	pub fn stop(&mut self) {
		let _ = self.call("stop", json!({}));
		let start = Instant::now();
		while start.elapsed() < Duration::from_secs(30) {
			if let Ok(Some(_)) = self.child.try_wait() {
				return;
			}
			std::thread::sleep(Duration::from_millis(100));
		}
		let _ = self.child.kill();
		let _ = self.child.wait();
	}

	/// Whether it still runs.
	pub fn running(&mut self) -> bool {
		matches!(self.child.try_wait(), Ok(None))
	}
}

impl Drop for LightningNode {
	fn drop(&mut self) {
		self.stop();
		if std::env::var_os("ARCA_KEEP_LIGHTNING").is_none() {
			let _ = std::fs::remove_dir_all(&self.dir);
		}
	}
}
