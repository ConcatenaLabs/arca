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
	/// What every start passes besides the key, chain, socket and record:
	/// where each of the record's keepers is reached.
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
	/// The signer on a record made without keepers.
	pub fn start(key: &Keypair, genesis: BlockHash) -> SignerProcess {
		Self::start_with(key, genesis, vec!["--no-keepers".into()], vec![])
	}

	/// The signer on a record made with `create` (the record's keepers, or
	/// `--no-keepers`), started with `extra` arguments (where each keeper is
	/// reached): every start and resume passes them.
	pub fn start_with(key: &Keypair, genesis: BlockHash, create: Vec<String>, extra: Vec<String>) -> SignerProcess {
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
			.args(&create)
			.output().unwrap();
		assert!(made.status.success(), "the signer's record: {}", String::from_utf8_lossy(&made.stderr));
		let mut s = SignerProcess { child: Self::spawn(&dir, &file, genesis, &socket, &extra), dir, socket, extra };
		s.wait_for_socket().unwrap_or_else(|e| panic!("the signer did not start: {}", e));
		s
	}

	/// `arca-signer` on the record in `dir`, its log appended to
	/// `signer.log` there.
	fn spawn(dir: &std::path::Path, file: &std::path::Path, genesis: BlockHash, socket: &std::path::Path, extra: &[String]) -> Child {
		let log = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("signer.log")).unwrap();
		Command::new(signer_exe())
			.args(["--key-file", file.to_str().unwrap(), "--genesis", &genesis.to_string(), "--socket", socket.to_str().unwrap(),
				"--record", dir.join("signer.record").to_str().unwrap()])
			.args(extra)
			.stdout(Stdio::null()).stderr(log)
			.spawn().unwrap()
	}

	/// Waits for the signer's socket; its exit status and log when it exits
	/// first.
	fn wait_for_socket(&mut self) -> Result<(), String> {
		let start = Instant::now();
		while !self.socket.exists() {
			if let Some(status) = self.child.try_wait().unwrap() {
				return Err(format!("exit {:?}: {}", status.code(), self.log().trim()));
			}
			assert!(start.elapsed() < Duration::from_secs(20), "the signer did not open its socket: {}", self.log());
			std::thread::sleep(Duration::from_millis(50));
		}
		Ok(())
	}

	/// Everything the signer wrote to its log, every start.
	pub fn log(&self) -> String {
		std::fs::read_to_string(self.dir.join("signer.log")).unwrap_or_default()
	}

	/// What every later start passes: where the keepers are reached, as a
	/// start script restored from another time would say.
	pub fn set_extra(&mut self, extra: Vec<String>) {
		self.extra = extra;
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
		self.try_resume(genesis).unwrap_or_else(|e| panic!("the signer did not start again: {}", e));
	}

	/// [`Self::resume`], or the signer's exit status and log when it refuses
	/// to start.
	pub fn try_resume(&mut self, genesis: BlockHash) -> Result<(), String> {
		let file = self.dir.join("operator.key");
		self.child = Self::spawn(&self.dir, &file, genesis, &self.socket, &self.extra);
		self.wait_for_socket()
	}
}

impl Drop for SignerProcess {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
		let _ = std::fs::remove_dir_all(&self.dir);
	}
}

/// A tap on a signer's socket that changes one character of every owner's
/// signature the server's requests carry, checks included: the signer then
/// declines each such request (`declined`), on its own key, chain and record,
/// as it declines any request whose owner did not sign it, and answers
/// everything else as it is. Dropping the tap puts the signer's own socket
/// back. The signer is not restarted while a tap is on it.
pub struct GarblingTap {
	at: PathBuf,
	real: PathBuf,
	stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
	thread: Option<std::thread::JoinHandle<()>>,
}

impl GarblingTap {
	pub fn on(signer: &SignerProcess) -> GarblingTap {
		use std::io::{BufRead, BufReader, Write};
		use std::os::unix::net::{UnixListener, UnixStream};
		let at = signer.socket.clone();
		let real = signer.dir.join("signer.real.sock");
		std::fs::rename(&at, &real).unwrap();
		let listener = UnixListener::bind(&at).unwrap();
		listener.set_nonblocking(true).unwrap();
		let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
		let (s, r) = (stop.clone(), real.clone());
		let thread = std::thread::spawn(move || {
			while !s.load(Ordering::SeqCst) {
				let (client, _) = match listener.accept() {
					Ok(x) => x,
					Err(_) => {
						std::thread::sleep(Duration::from_millis(10));
						continue;
					},
				};
				let r = r.clone();
				std::thread::spawn(move || {
					client.set_nonblocking(false).unwrap();
					let mut reader = BufReader::new(client.try_clone().unwrap());
					let mut line = String::new();
					if reader.read_line(&mut line).unwrap_or(0) == 0 {
						return;
					}
					if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&line) {
						if garble_owner_sigs(&mut v) {
							println!("signer tap: request {} carries an owner's signature changed", v["op"]);
							line = format!("{}\n", v);
						}
					}
					let Ok(mut up) = UnixStream::connect(&r) else { return };
					if up.write_all(line.as_bytes()).is_err() {
						return;
					}
					let mut answer = String::new();
					let _ = BufReader::new(up).read_line(&mut answer);
					let mut client = client;
					let _ = client.write_all(answer.as_bytes());
				});
			}
		});
		GarblingTap { at, real, stop, thread: Some(thread) }
	}
}

impl Drop for GarblingTap {
	fn drop(&mut self) {
		self.stop.store(true, Ordering::SeqCst);
		if let Some(t) = self.thread.take() {
			let _ = t.join();
		}
		let _ = std::fs::remove_file(&self.at);
		let _ = std::fs::rename(&self.real, &self.at);
	}
}

/// Changes the first hex digit of every `owner_sig` in a request, wherever it
/// sits; true when there was one.
fn garble_owner_sigs(v: &mut serde_json::Value) -> bool {
	match v {
		serde_json::Value::Object(m) => {
			let mut any = false;
			for (k, x) in m.iter_mut() {
				if k == "owner_sig" {
					if let Some(sig) = x.as_str().filter(|s| !s.is_empty()) {
						let first = if sig.starts_with('0') { '1' } else { '0' };
						*x = serde_json::Value::String(format!("{}{}", first, &sig[1..]));
						any = true;
					}
				} else {
					any |= garble_owner_sigs(x);
				}
			}
			any
		},
		serde_json::Value::Array(a) => a.iter_mut().fold(false, |any, x| garble_owner_sigs(x) | any),
		_ => false,
	}
}
