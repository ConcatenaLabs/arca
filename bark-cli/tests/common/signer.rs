//! `arca-signer` in its own process, holding the operator key.

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
	/// What every start passes besides the key, chain, socket and record.
	extra: Vec<String>,
}

/// The signer binary: `ARCA_SIGNER_EXEC`, or `arca-signer` beside `arca`.
pub fn signer_exe() -> PathBuf {
	if let Some(p) = std::env::var_os("ARCA_SIGNER_EXEC") {
		return PathBuf::from(p);
	}
	let p = PathBuf::from(env!("CARGO_BIN_EXE_arca")).parent().unwrap().join("arca-signer");
	assert!(p.exists(), "{} is missing: build it with `cargo build -p arca-server --bin arca-signer`, or name it with ARCA_SIGNER_EXEC",
		p.display());
	p
}

impl SignerProcess {
	pub fn start(key: &Keypair, genesis: BlockHash) -> SignerProcess {
		Self::start_with(key, genesis, vec![])
	}

	/// The signer, started with `extra` arguments (its keepers): every start
	/// and resume passes them.
	pub fn start_with(key: &Keypair, genesis: BlockHash, extra: Vec<String>) -> SignerProcess {
		static N: AtomicUsize = AtomicUsize::new(0);
		// Short: a Unix socket path is limited to about 100 bytes.
		let dir = PathBuf::from(format!("/tmp/arca-cli-signer-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
		let file = dir.join("operator.key");
		std::fs::write(&file, key.secret_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>()).unwrap();
		std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
		let socket = dir.join("signer.sock");
		// A new operator key's record, made once, on purpose.
		let made = Command::new(signer_exe())
			.args(["--key-file", file.to_str().unwrap(), "--genesis", &genesis.to_string(),
				"--record", dir.join("signer.record").to_str().unwrap(), "--create-record"])
			.output().unwrap();
		assert!(made.status.success(), "the signer's record: {}", String::from_utf8_lossy(&made.stderr));
		let child = Command::new(signer_exe())
			.args(["--key-file", file.to_str().unwrap(), "--genesis", &genesis.to_string(), "--socket", socket.to_str().unwrap(),
				"--record", dir.join("signer.record").to_str().unwrap()])
			.args(&extra)
			.stdout(Stdio::null()).stderr(Stdio::null())
			.spawn().unwrap();
		let start = Instant::now();
		while !socket.exists() {
			assert!(start.elapsed() < Duration::from_secs(20), "the signer did not open its socket");
			std::thread::sleep(Duration::from_millis(50));
		}
		SignerProcess { child, dir, socket, extra }
	}

	/// The signer's process id.
	pub fn pid(&self) -> u32 {
		self.child.id()
	}

	/// The signer's record.
	pub fn record(&self) -> PathBuf {
		self.dir.join("signer.record")
	}

	/// Stops the signer; its record stays.
	pub fn halt(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
		let _ = std::fs::remove_file(&self.socket);
	}

	/// Starts the signer again on its record.
	pub fn resume(&mut self, genesis: BlockHash) {
		let file = self.dir.join("operator.key");
		self.child = Command::new(signer_exe())
			.args(["--key-file", file.to_str().unwrap(), "--genesis", &genesis.to_string(), "--socket", self.socket.to_str().unwrap(),
				"--record", self.record().to_str().unwrap()])
			.args(&self.extra)
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
