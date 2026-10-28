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

/// Makes a new record at `record` for the key in `key_file`, without
/// keepers, as an operator does once for a new key: the signer's output.
pub fn create_record(key_file: &std::path::Path, genesis: BlockHash, record: &std::path::Path) -> std::process::Output {
	create_record_with(key_file, genesis, record, &["--no-keepers".to_string()])
}

/// Makes a new record at `record` naming the keepers `keys`, `required` of
/// them to hold every head: the signer's output.
pub fn create_record_kept(key_file: &std::path::Path, genesis: BlockHash, record: &std::path::Path,
	keys: &[elements::secp256k1_zkp::XOnlyPublicKey], required: usize) -> std::process::Output
{
	let mut a = vec![];
	for k in keys {
		a.push("--keeper-key".to_string());
		a.push(hex(&k.serialize()));
	}
	a.push("--keepers-required".into());
	a.push(required.to_string());
	create_record_with(key_file, genesis, record, &a)
}

/// `arca-signer --create-record` with `args` (the record's keepers).
pub fn create_record_with(key_file: &std::path::Path, genesis: BlockHash, record: &std::path::Path, args: &[String])
	-> std::process::Output
{
	Command::new(env!("CARGO_BIN_EXE_arca-signer"))
		.args(["--key-file", key_file.to_str().unwrap(), "--genesis", &genesis.to_string(), "--record", record.to_str().unwrap(),
			"--create-record"])
		.args(args)
		.output().unwrap()
}

impl SignerProcess {
	pub fn start(key: &Keypair, genesis: BlockHash) -> SignerProcess {
		let dir = signer_dir();
		let file = key_file(&dir, key, 0o600);
		let socket = dir.join("signer.sock");
		let made = create_record(&file, genesis, &dir.join("signer.record"));
		assert!(made.status.success(), "the signer's record: {}", String::from_utf8_lossy(&made.stderr));
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

	/// Starts it again on the same key, record and socket, with `extra`
	/// arguments (an issuer-operated asset's `--issuer`, say); its log to
	/// `signer.log` in its directory.
	pub fn restart_with(&mut self, genesis: BlockHash, extra: &[String]) {
		self.kill();
		let file = self.dir.join("operator.key");
		let log = std::fs::File::create(self.dir.join("signer.log")).unwrap();
		self.child = Command::new(env!("CARGO_BIN_EXE_arca-signer"))
			.args(["--key-file", file.to_str().unwrap(), "--genesis", &genesis.to_string(), "--socket", self.socket.to_str().unwrap(),
				"--record", self.record().to_str().unwrap()])
			.args(extra)
			.stdout(Stdio::null()).stderr(log)
			.spawn().unwrap();
		let start = Instant::now();
		while !self.socket.exists() {
			assert!(start.elapsed() < Duration::from_secs(20), "the signer did not open its socket: {}",
				std::fs::read_to_string(self.dir.join("signer.log")).unwrap_or_default());
			std::thread::sleep(Duration::from_millis(50));
		}
	}

	/// The signer's log since [`SignerProcess::restart_with`].
	pub fn log(&self) -> String {
		std::fs::read_to_string(self.dir.join("signer.log")).unwrap_or_default()
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

/// A tap on a signer's socket: the server's requests pass through it to the
/// signer, one request and one answer a connection, as the server asks. While
/// [`SignerTap::cut`] names an operation, a request of it is dropped
/// unanswered, as when the signer goes away in the middle of a call; the
/// requests before it in the same piece of work have been signed and
/// recorded. Dropping the tap puts the signer's own socket back.
pub struct SignerTap {
	at: PathBuf,
	real: PathBuf,
	cut: std::sync::Arc<std::sync::Mutex<Option<String>>>,
	stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
	thread: Option<std::thread::JoinHandle<()>>,
}

impl SignerTap {
	pub fn on(signer: &SignerProcess) -> SignerTap {
		use std::io::{BufRead, BufReader, Write};
		use std::os::unix::net::{UnixListener, UnixStream};
		let at = signer.socket.clone();
		let real = signer.dir.join("signer.real.sock");
		std::fs::rename(&at, &real).unwrap();
		let listener = UnixListener::bind(&at).unwrap();
		listener.set_nonblocking(true).unwrap();
		let cut = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
		let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
		let (c, s, r) = (cut.clone(), stop.clone(), real.clone());
		let thread = std::thread::spawn(move || {
			while !s.load(Ordering::SeqCst) {
				let (client, _) = match listener.accept() {
					Ok(x) => x,
					Err(_) => {
						std::thread::sleep(Duration::from_millis(10));
						continue;
					},
				};
				let (c, r) = (c.clone(), r.clone());
				std::thread::spawn(move || {
					client.set_nonblocking(false).unwrap();
					let mut reader = BufReader::new(client.try_clone().unwrap());
					let mut line = String::new();
					if reader.read_line(&mut line).unwrap_or(0) == 0 {
						return;
					}
					let v = serde_json::from_str::<serde_json::Value>(&line).unwrap_or_default();
					let op = v["op"].as_str().map(String::from).unwrap_or_default();
					// A check signs nothing: it passes, so what is cut is the
					// request that would sign.
					let check = v["check"].as_bool().unwrap_or(false);
					if !check && c.lock().unwrap().as_deref() == Some(op.as_str()) {
						println!("signer tap: request {} dropped unanswered", op);
						return;
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
		SignerTap { at, real, cut, stop, thread: Some(thread) }
	}

	/// Drops every request of operation `op` unanswered from now, but a
	/// check (which signs nothing); `None` passes everything again.
	pub fn cut(&self, op: Option<&str>) {
		*self.cut.lock().unwrap() = op.map(String::from);
	}
}

impl Drop for SignerTap {
	fn drop(&mut self) {
		self.stop.store(true, Ordering::SeqCst);
		if let Some(t) = self.thread.take() {
			let _ = t.join();
		}
		let _ = std::fs::remove_file(&self.at);
		let _ = std::fs::rename(&self.real, &self.at);
	}
}
