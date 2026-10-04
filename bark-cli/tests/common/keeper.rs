//! `arca-keeper` in its own process, on a port of its own, as on another
//! machine than the signer: it holds the heads of the signer's record.

use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use elements::secp256k1_zkp::{Keypair, XOnlyPublicKey};
use elements::BlockHash;

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// The keeper binary: `ARCA_KEEPER_EXEC`, or `arca-keeper` beside `arca`.
pub fn keeper_exe() -> PathBuf {
	if let Some(p) = std::env::var_os("ARCA_KEEPER_EXEC") {
		return PathBuf::from(p);
	}
	let p = PathBuf::from(env!("CARGO_BIN_EXE_arca")).parent().unwrap().join("arca-keeper");
	assert!(p.exists(), "{} is missing: build it with `cargo build -p arca-server --bin arca-keeper`, or name it with ARCA_KEEPER_EXEC",
		p.display());
	p
}

pub struct KeeperProcess {
	child: Option<Child>,
	pub dir: PathBuf,
	pub addr: String,
	pub key: Keypair,
	operator: XOnlyPublicKey,
	genesis: BlockHash,
}

impl KeeperProcess {
	/// A new keeper with key `key`, its heads file made once, serving on a
	/// port of its own.
	pub fn start(key: &Keypair, operator: XOnlyPublicKey, genesis: BlockHash) -> KeeperProcess {
		static N: AtomicUsize = AtomicUsize::new(0);
		let dir = PathBuf::from(format!("/tmp/arca-cli-keeper-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
		let file = dir.join("keeper.key");
		std::fs::write(&file, hex(&key.secret_bytes())).unwrap();
		std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
		let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
		let mut k = KeeperProcess { child: None, dir, addr: format!("127.0.0.1:{}", port), key: *key, operator, genesis };
		let made = k.command().arg("--create").output().unwrap();
		assert!(made.status.success(), "the keeper's heads file: {}", String::from_utf8_lossy(&made.stderr));
		k.resume();
		k
	}

	fn command(&self) -> Command {
		let mut c = Command::new(keeper_exe());
		c.args(["--key-file", self.dir.join("keeper.key").to_str().unwrap(), "--operator", &hex(&self.operator.serialize()),
			"--genesis", &self.genesis.to_string(), "--heads", self.dir.join("heads").to_str().unwrap()]);
		c
	}

	/// What the signer is told of it: `<host:port>=<key>`.
	pub fn arg(&self) -> String {
		format!("{}={}", self.addr, hex(&self.key.x_only_public_key().0.serialize()))
	}

	/// The keeper's own key.
	pub fn xonly(&self) -> XOnlyPublicKey {
		self.key.x_only_public_key().0
	}

	/// Stops the keeper; its heads file stays.
	pub fn halt(&mut self) {
		if let Some(mut c) = self.child.take() {
			let _ = c.kill();
			let _ = c.wait();
		}
	}

	/// Starts the keeper again on its heads file, at the same address.
	pub fn resume(&mut self) {
		self.halt();
		self.child = Some(self.command().args(["--listen", &self.addr]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
		let start = Instant::now();
		while TcpStream::connect(&self.addr).is_err() {
			assert!(start.elapsed() < Duration::from_secs(20), "the keeper did not listen");
			std::thread::sleep(Duration::from_millis(50));
		}
	}

	/// The latest entry its heads file holds.
	pub fn latest(&self) -> Option<u64> {
		std::fs::read_to_string(self.dir.join("heads")).unwrap().lines().skip(1).last()
			.and_then(|l| l.split(' ').next()).and_then(|n| n.parse().ok())
	}
}

impl Drop for KeeperProcess {
	fn drop(&mut self) {
		self.halt();
		let _ = std::fs::remove_dir_all(&self.dir);
	}
}
