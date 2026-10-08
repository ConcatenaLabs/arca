//! A throwaway anchored Sequentia chain for tests.
//!
//! [`Regtest::start`] runs two `sequentiad` processes from the same binary: a
//! Bitcoin-mode regtest node as the parent chain, and a Sequentia custom chain
//! (`elementsregtest`) whose block headers carry a Bitcoin anchor taken from
//! that parent, as on every live Sequentia chain. Both are stopped, and their
//! data directories deleted, on drop.
//!
//! [`Regtest::start_pos`] runs the same chain under proof of stake, as the live
//! chains run: a committee of three test stakers certifies every block, which
//! [`Regtest::produce_block`] builds from the mempool. A proof-of-stake chain
//! takes no block from `generateblock` or `generatetodescriptor`.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::rpc::{Auth, Client};
use crate::BlockHash;

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

/// What SeqLN's `sequentia-regtest` network assumes of the chain besides its
/// name: addresses that share the Bitcoin regtest prefixes, the genesis
/// block's coins counted by a node wallet, and no block subsidy. With
/// [`CHAIN_ARGS`] and a committee they make the genesis block
/// [`SEQLN_GENESIS`], which SeqLN's chain parameters carry.
pub const SEQLN_CHAIN_ARGS: &[&str] = &[
	"-anyonecanspendaremine=1",
	"-con_blocksubsidy=0",
	"-bech32_hrp=bcrt",
	"-pubkeyprefix=111",
	"-scriptprefix=196",
];

/// The genesis block of SeqLN's `sequentia-regtest` network, display order.
pub const SEQLN_GENESIS: &str = "48471cda14077e1e1a530e3ae6e90a1cd8b1ae4fa2d2ee326687f2e479972505";

/// One running `sequentiad`.
pub struct Daemon {
	child: Child,
	datadir: PathBuf,
	rpc_port: u16,
	client: Client,
	exe: PathBuf,
	/// Every argument it was started with.
	args: Vec<String>,
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
		let child = Daemon::spawn(exe, &all)?;
		let client = Client::new(format!("http://127.0.0.1:{}/", rpc_port),
			Auth::UserPass("arca".into(), "arca".into()));
		let mut daemon = Daemon { child, datadir, rpc_port, client, exe: exe.to_path_buf(), args: all };
		daemon.wait_ready()?;
		Ok(daemon)
	}

	fn spawn(exe: &Path, args: &[String]) -> Result<Child, String> {
		Command::new(exe).args(args)
			.stdout(Stdio::null()).stderr(Stdio::null())
			.spawn().map_err(|e| format!("cannot start {}: {}", exe.display(), e))
	}

	fn wait_ready(&mut self) -> Result<(), String> {
		let start = Instant::now();
		loop {
			match self.client.block_count() {
				Ok(_) => return Ok(()),
				Err(e) => {
					if let Ok(Some(status)) = self.child.try_wait() {
						return Err(format!("sequentiad exited ({}) before answering; see {}",
							status, self.datadir.display()));
					}
					if start.elapsed() > Duration::from_secs(60) {
						return Err(format!("sequentiad did not answer within 60 s: {}", e));
					}
					std::thread::sleep(Duration::from_millis(200));
				},
			}
		}
	}

	/// Stops the node and waits for it to exit, keeping its data.
	fn stop(&mut self) {
		let _ = self.client.call::<serde_json::Value>("stop", &[]);
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

	/// Stops the node and starts it again on the same data directory and
	/// ports, with its arguments and then `extra`. With `-persistmempool=0`
	/// it comes back with an empty mempool, as a node that never saw the
	/// transactions it held.
	pub fn restart(&mut self, extra: &[&str]) -> Result<(), String> {
		self.stop();
		let mut args = self.args.clone();
		args.extend(extra.iter().map(|s| s.to_string()));
		self.child = Daemon::spawn(&self.exe, &args)?;
		self.wait_ready()
	}
}

impl Drop for Daemon {
	fn drop(&mut self) {
		self.stop();
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
	/// The stakers of a proof-of-stake chain, each of whom may lead and all of
	/// whom countersign.
	committee: Option<Committee>,
	/// Deletes the work directory once both nodes have stopped.
	_workdir: WorkDir,
}

/// Arguments that put the Sequentia node under proof of stake with a
/// committee of three, a one-second slot, and anchors taken from the parent's
/// tip as soon as the node sees it. `-acceptnonstdtxn` lets the genesis block's
/// free coins, at a bare `OP_TRUE`, be spent through the mempool, since a
/// proof-of-stake chain takes no block that skips it.
pub const POS_ARGS: &[&str] = &[
	"-con_pos=1",
	"-posvrf=1",
	"-posaggcommittee=1",
	"-poscommitteesize=3",
	"-posslotinterval=1",
	"-anchorpollinterval=1",
	"-anchorminconf=1",
	"-acceptnonstdtxn=1",
];

/// The test stakers of a proof-of-stake chain: keys anyone can derive, for
/// regtest only.
struct Committee {
	/// Each staker's key, in WIF.
	wifs: Vec<String>,
}

impl Committee {
	fn new() -> Committee {
		use elements::bitcoin::hashes::{sha256, Hash};
		use elements::bitcoin::secp256k1::SecretKey;
		let wifs = (0..3).map(|i| {
			let seed = sha256::Hash::hash(format!("sequentia-ext regtest staker {}", i).as_bytes());
			let key = SecretKey::from_slice(seed.as_byte_array()).expect("a hash is a key");
			elements::bitcoin::PrivateKey::new(key, elements::bitcoin::NetworkKind::Test).to_wif()
		}).collect();
		Committee { wifs }
	}

	/// `-staker=<key>:1` for each staker.
	fn args(&self) -> Vec<String> {
		let secp = elements::bitcoin::secp256k1::Secp256k1::new();
		self.wifs.iter().map(|w| {
			let key = elements::bitcoin::PrivateKey::from_wif(w).expect("our own WIF");
			format!("-staker={}:1", key.public_key(&secp))
		}).collect()
	}
}

fn exe_from_env() -> PathBuf {
	PathBuf::from(std::env::var_os("SEQUENTIAD_EXEC").expect(
		"SEQUENTIAD_EXEC must name a sequentiad binary; these tests run against a regtest chain",
	))
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
		Regtest::start_with(exe, workdir, extra, None, "elementsregtest", &[])
	}

	/// Starts the chain under proof of stake ([`POS_ARGS`]), certified by a
	/// committee of three test stakers. Blocks come from
	/// [`Regtest::produce_block`].
	pub fn start_pos(exe: &Path, workdir: &Path, extra: &[&str]) -> Result<Regtest, String> {
		Regtest::start_with(exe, workdir, extra, Some(Committee::new()), "elementsregtest", &[])
	}

	/// The proof-of-stake chain under the name and the arguments SeqLN's
	/// `sequentia-regtest` network assumes ([`SEQLN_CHAIN_ARGS`]), so that
	/// SeqLN nodes run on it ([`crate::lightning`]). Refuses to go on when the
	/// genesis block is not the one SeqLN expects.
	pub fn start_seqln(exe: &Path, workdir: &Path, extra: &[&str]) -> Result<Regtest, String> {
		let rt = Regtest::start_with(exe, workdir, extra, Some(Committee::new()), "sequentia-regtest", SEQLN_CHAIN_ARGS)?;
		let genesis = rt.client().genesis_hash().map_err(|e| e.to_string())?.to_string();
		if genesis != SEQLN_GENESIS {
			return Err(format!("the chain's genesis block is {}, and SeqLN's sequentia-regtest expects {}", genesis, SEQLN_GENESIS));
		}
		Ok(rt)
	}

	/// [`Regtest::start_seqln`] with the binary named by `SEQUENTIAD_EXEC`.
	pub fn seqln_from_env(workdir: &Path, extra: &[&str]) -> Regtest {
		Regtest::start_seqln(&exe_from_env(), workdir, extra).unwrap_or_else(|e| panic!("{}", e))
	}

	fn start_with(exe: &Path, workdir: &Path, extra: &[&str], committee: Option<Committee>, chain: &str, chain_args: &[&str])
		-> Result<Regtest, String>
	{
		let parent = Daemon::start(exe, workdir.join("parent"), &["-chain=regtest".to_string()])?;
		// An anchor is a parent block: give the parent a few.
		parent.client.generate_to_descriptor(10, OP_TRUE_DESCRIPTOR).map_err(|e| e.to_string())?;
		let parent_genesis = parent.client.genesis_hash().map_err(|e| e.to_string())?;
		let mut args: Vec<String> = vec![
			format!("-chain={}", chain),
			"-con_bitcoin_anchor=1".into(),
			"-validateanchor=1".into(),
			"-mainchainrpchost=127.0.0.1".into(),
			format!("-mainchainrpcport={}", parent.rpc_port),
			"-mainchainrpcuser=arca".into(),
			"-mainchainrpcpassword=arca".into(),
			format!("-parentgenesisblockhash={}", parent_genesis),
		];
		args.extend(CHAIN_ARGS.iter().map(|s| s.to_string()));
		args.extend(chain_args.iter().map(|s| s.to_string()));
		if let Some(c) = &committee {
			args.extend(POS_ARGS.iter().map(|s| s.to_string()));
			args.extend(c.args());
		}
		args.extend(extra.iter().map(|s| s.to_string()));
		let node = Daemon::start(exe, workdir.join("sequentia"), &args)?;
		Ok(Regtest { node, parent, committee, _workdir: WorkDir(workdir.to_path_buf()) })
	}

	/// Starts the chain with the binary named by `SEQUENTIAD_EXEC`.
	pub fn from_env(workdir: &Path, extra: &[&str]) -> Regtest {
		Regtest::start(&exe_from_env(), workdir, extra).unwrap_or_else(|e| panic!("{}", e))
	}

	/// Starts the proof-of-stake chain with the binary named by
	/// `SEQUENTIAD_EXEC`.
	pub fn pos_from_env(workdir: &Path, extra: &[&str]) -> Regtest {
		Regtest::start_pos(&exe_from_env(), workdir, extra).unwrap_or_else(|e| panic!("{}", e))
	}

	/// Builds one block from the mempool on a proof-of-stake chain, certified
	/// by the whole committee, and returns its hash. Each staker is tried as
	/// the leader in turn until one is eligible for the current slot.
	pub fn produce_block(&self) -> Result<BlockHash, String> {
		let committee = self.committee.as_ref().ok_or("not a proof-of-stake chain")?;
		let all = serde_json::json!(committee.wifs);
		let start = Instant::now();
		loop {
			let mut last = String::new();
			for leader in &committee.wifs {
				match self.client().call::<serde_json::Value>("generateposblock", &[serde_json::json!(leader), all.clone()]) {
					Ok(v) => return serde_json::from_value(v["hash"].clone()).map_err(|e| e.to_string()),
					Err(e) => last = e.to_string(),
				}
			}
			if start.elapsed() > Duration::from_secs(30) {
				return Err(format!("no staker could produce a block: {}", last));
			}
			std::thread::sleep(Duration::from_millis(250));
		}
	}

	/// Mines `n` blocks on the parent chain.
	pub fn mine_parent(&self, n: u64) -> Result<(), String> {
		self.parent.client().generate_to_descriptor(n, OP_TRUE_DESCRIPTOR).map(|_| ()).map_err(|e| e.to_string())
	}

	/// Produces blocks until the Sequentia tip is anchored to the parent's
	/// tip, so a block anchored earlier counts every parent block since as
	/// burying it. Returns the blocks produced.
	pub fn anchor_to_parent_tip(&self) -> Result<Vec<BlockHash>, String> {
		let target = self.parent.client().block_count().map_err(|e| e.to_string())?;
		let start = Instant::now();
		let mut made = vec![];
		loop {
			made.push(self.produce_block()?);
			let tip = self.client().best_block_hash().map_err(|e| e.to_string())?;
			let header = self.client().block_header(&tip).map_err(|e| e.to_string())?;
			if crate::BlockHeaderExt::bitcoin_anchor(&header).height as u64 >= target {
				return Ok(made);
			}
			if start.elapsed() > Duration::from_secs(60) {
				return Err(format!("the tip did not anchor to parent height {} within 60 s", target));
			}
			std::thread::sleep(Duration::from_millis(500));
		}
	}

	/// Reorganises the parent chain from `height`: the parent block at that
	/// height and every block above it are invalidated, and the parent mines
	/// a longer branch in their place. Every Sequentia block anchored to one
	/// of the orphaned blocks is then invalid: the node's anchor watcher finds
	/// it, disconnects it and every block above it, and returns their
	/// transactions to the mempool, as on the live chain when Bitcoin
	/// reorganises. Waits until the node's tip is anchored in the parent's
	/// new chain, and returns the orphaned parent blocks, lowest first.
	pub fn orphan_parent_from(&self, height: u64) -> Result<Vec<BlockHash>, String> {
		let parent = self.parent.client();
		let tip = parent.block_count().map_err(|e| e.to_string())?;
		if height == 0 || height > tip {
			return Err(format!("parent height {} is not between 1 and the tip, {}", height, tip));
		}
		let orphaned = (height..=tip).map(|h| parent.block_hash(h)).collect::<Result<Vec<_>, _>>()
			.map_err(|e| e.to_string())?;
		let _: serde_json::Value = parent.call("invalidateblock", &[serde_json::json!(orphaned[0].to_string())])
			.map_err(|e| e.to_string())?;
		// Another output script, so no block of the new branch can be one
		// of the invalidated blocks again.
		parent.generate_to_descriptor(tip - height + 2, "raw(52)").map_err(|e| e.to_string())?;
		let start = Instant::now();
		loop {
			let t = self.client().best_block_hash().map_err(|e| e.to_string())?;
			let anchor = crate::BlockHeaderExt::bitcoin_anchor(&self.client().block_header(&t).map_err(|e| e.to_string())?);
			let at: serde_json::Value = parent.call("getblockheader", &[serde_json::json!(anchor.block_hash.to_string())])
				.map_err(|e| e.to_string())?;
			if at["confirmations"].as_i64().unwrap_or(-1) >= 0 {
				return Ok(orphaned);
			}
			if start.elapsed() > Duration::from_secs(60) {
				return Err(format!("the tip is still anchored to an orphaned parent block {} after 60 s", anchor.block_hash));
			}
			std::thread::sleep(Duration::from_millis(250));
		}
	}

	/// The Sequentia node's client.
	pub fn client(&self) -> &Client {
		&self.node.client
	}

	/// The `-chain` the Sequentia node runs.
	pub fn chain_name(&self) -> String {
		self.node.args.iter().find_map(|a| a.strip_prefix("-chain=")).unwrap_or("elementsregtest").to_string()
	}
}
