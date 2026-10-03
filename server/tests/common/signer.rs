//! `arca-signer` run as its own process for a test, with a key file it alone
//! reads and a socket in a directory of the test's.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use elements::secp256k1_zkp::Keypair;
use elements::BlockHash;

pub struct SignerProcess {
	child: Child,
	pub dir: PathBuf,
	pub socket: PathBuf,
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// A fresh directory for one signer.
pub fn signer_dir() -> PathBuf {
	static N: AtomicUsize = AtomicUsize::new(0);
	// Short: a Unix socket path is limited to about 100 bytes.
	let dir = PathBuf::from(format!("/tmp/arca-signer-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
	dir
}

/// Writes `key`'s secret to a file of mode `mode` in `dir`.
pub fn key_file(dir: &std::path::Path, key: &Keypair, mode: u32) -> PathBuf {
	let path = dir.join("operator.key");
	std::fs::write(&path, hex(&key.secret_bytes())).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
	path
}

impl SignerProcess {
	pub fn start(key: &Keypair, genesis: BlockHash) -> SignerProcess {
		let dir = signer_dir();
		let file = key_file(&dir, key, 0o600);
		let socket = dir.join("signer.sock");
		let child = Command::new(env!("CARGO_BIN_EXE_arca-signer"))
			.args(["--key-file", file.to_str().unwrap(), "--genesis", &genesis.to_string(), "--socket", socket.to_str().unwrap(),
				"--record", dir.join("signer.record").to_str().unwrap()])
			.stdout(Stdio::null()).stderr(Stdio::null())
			.spawn().unwrap();
		let start = Instant::now();
		while !socket.exists() {
			assert!(start.elapsed() < Duration::from_secs(20), "the signer did not open its socket");
			std::thread::sleep(Duration::from_millis(50));
		}
		SignerProcess { child, dir, socket }
	}

	/// The signer's one-spend record.
	pub fn record(&self) -> PathBuf {
		self.dir.join("signer.record")
	}

	pub fn pid(&self) -> u32 {
		self.child.id()
	}

	/// Stops the signer: the server can no longer reach `S`.
	pub fn kill(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
		let _ = std::fs::remove_file(&self.socket);
	}

	/// Starts it again on the same key and socket.
	pub fn restart(&mut self, key: &Keypair, genesis: BlockHash) {
		self.kill();
		let file = self.dir.join("operator.key");
		let _ = key;
		self.child = Command::new(env!("CARGO_BIN_EXE_arca-signer"))
			.args(["--key-file", file.to_str().unwrap(), "--genesis", &genesis.to_string(), "--socket", self.socket.to_str().unwrap(),
				"--record", self.record().to_str().unwrap()])
			.stdout(Stdio::null()).stderr(Stdio::null())
			.spawn().unwrap();
		let start = Instant::now();
		while !self.socket.exists() {
			assert!(start.elapsed() < Duration::from_secs(20), "the signer did not open its socket");
			std::thread::sleep(Duration::from_millis(50));
		}
	}
}

impl Drop for SignerProcess {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
		let _ = std::fs::remove_dir_all(&self.dir);
	}
}
