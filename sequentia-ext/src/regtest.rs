//! A throwaway anchored Sequentia chain for tests.
//!
//! [`Regtest::start`] runs two `sequentiad` processes from the same binary: a
//! Bitcoin-mode regtest node as the parent chain, and a Sequentia custom chain
//! (`elementsregtest`) whose block headers carry a Bitcoin anchor taken from
//! that parent, as on every live Sequentia chain. Both are stopped, and their
//! data directories deleted, on drop.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::rpc::{Auth, Client};

/// The descriptor the harness mines to: a bare `OP_TRUE`, spendable by anyone.
pub const OP_TRUE_DESCRIPTOR: &str = "raw(51)";

/// Arguments that give the Sequentia node the prototype's chain: the initial
/// free coins at an `OP_TRUE` output of the genesis block, transparent
/// addresses, fees in any accepted asset, and Simplicity active from genesis.
pub const CHAIN_ARGS: &[&str] = &[
	"-initialfreecoins=2100000000000000",
	"-con_default_blinded_addresses=0",
	"-validatepegin=0",
	"-con_parent_chain_signblockscript=51",
	"-con_any_asset_fees=1",
	"-evbparams=simplicity:-1:::",
];

/// One running `sequentiad`.
pub struct Daemon {
	child: Child,
	datadir: PathBuf,
	rpc_port: u16,
	client: Client,
}

impl Daemon {
	pub fn client(&self) -> &Client {
		&self.client
	}

	pub fn rpc_port(&self) -> u16 {
		self.rpc_port
	}

	pub fn datadir(&self) -> &Path {
		&self.datadir
	}

	fn start(exe: &Path, datadir: PathBuf, args: &[String]) -> Result<Daemon, String> {
		let _ = std::fs::remove_dir_all(&datadir);
		std::fs::create_dir_all(&datadir).map_err(|e| format!("{}: {}", datadir.display(), e))?;
		let rpc_port = free_port();
		let mut all = vec![
			format!("-datadir={}", datadir.display()),
			format!("-rpcport={}", rpc_port),
			format!("-port={}", free_port()),
			"-listen=0".into(), "-server".into(), "-printtoconsole=0".into(),
			"-rpcuser=arca".into(), "-rpcpassword=arca".into(),
			"-disablewallet".into(), "-txindex=1".into(),
		];
		all.extend(args.iter().cloned());
		let child = Command::new(exe).args(&all)
			.stdout(Stdio::null()).stderr(Stdio::null())
			.spawn().map_err(|e| format!("cannot start {}: {}", exe.display(), e))?;
		let client = Client::new(format!("http://127.0.0.1:{}/", rpc_port),
			Auth::UserPass("arca".into(), "arca".into()));
		let mut daemon = Daemon { child, datadir, rpc_port, client };
		let start = Instant::now();
		loop {
			match daemon.client.block_count() {
				Ok(_) => return Ok(daemon),
				Err(e) => {
					if let Ok(Some(status)) = daemon.child.try_wait() {
						return Err(format!("sequentiad exited ({}) before answering; see {}",
							status, daemon.datadir.display()));
					}
					if start.elapsed() > Duration::from_secs(60) {
						return Err(format!("sequentiad did not answer within 60 s: {}", e));
					}
					std::thread::sleep(Duration::from_millis(200));
				},
			}
		}
	}
}

impl Drop for Daemon {
	fn drop(&mut self) {
		let _ = self.client.call::<serde_json::Value>("stop", &[]);
		let start = Instant::now();
		while start.elapsed() < Duration::from_secs(30) {
			if let Ok(Some(_)) = self.child.try_wait() {
				break;
			}
			std::thread::sleep(Duration::from_millis(100));
		}
		let _ = self.child.kill();
		let _ = self.child.wait();
		let _ = std::fs::remove_dir_all(&self.datadir);
	}
}

fn free_port() -> u16 {
	TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A Sequentia regtest chain anchored to a Bitcoin regtest parent.
pub struct Regtest {
	/// The Sequentia node. Declared first so it stops before its parent.
	pub node: Daemon,
	/// The Bitcoin-mode parent chain the node anchors to.
	pub parent: Daemon,
	/// Deletes the work directory once both nodes have stopped.
	_workdir: WorkDir,
}

/// Fields drop in declaration order, so this goes after both nodes.
struct WorkDir(PathBuf);

impl Drop for WorkDir {
	fn drop(&mut self) {
		let _ = std::fs::remove_dir_all(&self.0);
	}
}

impl Regtest {
	/// Starts both nodes from `exe` with data directories under `workdir`,
	/// which is deleted on drop; `extra` goes to the Sequentia node after
	/// [`CHAIN_ARGS`].
	pub fn start(exe: &Path, workdir: &Path, extra: &[&str]) -> Result<Regtest, String> {
		let parent = Daemon::start(exe, workdir.join("parent"), &["-chain=regtest".to_string()])?;
		// An anchor is a parent block: give the parent a few.
		parent.client.generate_to_descriptor(10, OP_TRUE_DESCRIPTOR).map_err(|e| e.to_string())?;
		let parent_genesis = parent.client.genesis_hash().map_err(|e| e.to_string())?;
		let mut args: Vec<String> = vec![
			"-chain=elementsregtest".into(),
			"-con_bitcoin_anchor=1".into(),
			"-validateanchor=1".into(),
			"-mainchainrpchost=127.0.0.1".into(),
			format!("-mainchainrpcport={}", parent.rpc_port),
			"-mainchainrpcuser=arca".into(),
			"-mainchainrpcpassword=arca".into(),
			format!("-parentgenesisblockhash={}", parent_genesis),
		];
		args.extend(CHAIN_ARGS.iter().map(|s| s.to_string()));
		args.extend(extra.iter().map(|s| s.to_string()));
		let node = Daemon::start(exe, workdir.join("sequentia"), &args)?;
		Ok(Regtest { node, parent, _workdir: WorkDir(workdir.to_path_buf()) })
	}

	/// Starts the chain with the binary named by `SEQUENTIAD_EXEC`.
	pub fn from_env(workdir: &Path, extra: &[&str]) -> Regtest {
		let exe = std::env::var_os("SEQUENTIAD_EXEC").expect(
			"SEQUENTIAD_EXEC must name a sequentiad binary; these tests run against a regtest chain",
		);
		Regtest::start(Path::new(&exe), workdir, extra).unwrap_or_else(|e| panic!("{}", e))
	}

	/// The Sequentia node's client.
	pub fn client(&self) -> &Client {
		&self.node.client
	}
}
