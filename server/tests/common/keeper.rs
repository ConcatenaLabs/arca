//! `arca-keeper` run as its own process for a test, on a port of its own, as
//! on another machine; and a proxy in front of a keeper that can rewrite its
//! answers or delay every byte.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use elements::secp256k1_zkp::{Keypair, XOnlyPublicKey};
use elements::BlockHash;
use serde_json::Value;

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// A free port on this machine.
pub fn free_port() -> u16 {
	TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
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
	/// A new keeper with a key of its own, its heads file made once, serving
	/// on a port of its own.
	pub fn start(key: &Keypair, operator: XOnlyPublicKey, genesis: BlockHash) -> KeeperProcess {
		static N: AtomicUsize = AtomicUsize::new(0);
		let dir = PathBuf::from(format!("/tmp/arca-keeper-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
		let file = dir.join("keeper.key");
		std::fs::write(&file, hex(&key.secret_bytes())).unwrap();
		std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
		let mut k = KeeperProcess { child: None, dir, addr: format!("127.0.0.1:{}", free_port()), key: *key, operator, genesis };
		let made = k.command().arg("--create").output().unwrap();
		assert!(made.status.success(), "the keeper's heads file: {}", String::from_utf8_lossy(&made.stderr));
		k.resume();
		k
	}

	fn command(&self) -> Command {
		let mut c = Command::new(env!("CARGO_BIN_EXE_arca-keeper"));
		c.args(["--key-file", self.dir.join("keeper.key").to_str().unwrap(), "--operator", &hex(&self.operator.serialize()),
			"--genesis", &self.genesis.to_string(), "--heads", self.heads().to_str().unwrap()]);
		c
	}

	/// The keeper's heads file.
	pub fn heads(&self) -> PathBuf {
		self.dir.join("heads")
	}

	/// What the signer is told of it: `<host:port>=<key>`.
	pub fn arg(&self) -> String {
		format!("{}={}", self.addr, hex(&self.key.x_only_public_key().0.serialize()))
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
		let log = std::fs::File::create(self.dir.join("keeper.log")).unwrap();
		self.child = Some(self.command().args(["--listen", &self.addr]).stdout(Stdio::null()).stderr(log).spawn().unwrap());
		let start = Instant::now();
		while TcpStream::connect(&self.addr).is_err() {
			assert!(start.elapsed() < Duration::from_secs(20), "the keeper did not listen: {}", self.log());
			std::thread::sleep(Duration::from_millis(50));
		}
	}

	pub fn log(&self) -> String {
		std::fs::read_to_string(self.dir.join("keeper.log")).unwrap_or_default()
	}

	/// How many heads its file holds, and the latest entry.
	pub fn held(&self) -> (usize, Option<u64>) {
		let text = std::fs::read_to_string(self.heads()).unwrap();
		let lines: Vec<&str> = text.lines().skip(1).collect();
		(lines.len(), lines.last().and_then(|l| l.split(' ').next()).and_then(|n| n.parse().ok()))
	}
}

impl Drop for KeeperProcess {
	fn drop(&mut self) {
		self.halt();
		let _ = std::fs::remove_dir_all(&self.dir);
	}
}

/// Rewrites one answer line of a keeper (the request it answers given).
pub type LineRewrite = Arc<dyn Fn(&Value, &mut Value) + Send + Sync>;

/// A proxy in front of a keeper, on a port of its own: it passes every
/// request line on and every answer line back, rewritten when a rewrite is
/// set, and delays every byte each way by `delay`.
#[derive(Clone)]
pub struct LineProxy {
	pub addr: String,
	rewrite: Arc<Mutex<Option<LineRewrite>>>,
}

impl LineProxy {
	pub fn start(target: &str, delay: Duration) -> LineProxy {
		let l = TcpListener::bind("127.0.0.1:0").unwrap();
		let p = LineProxy { addr: l.local_addr().unwrap().to_string(), rewrite: Arc::new(Mutex::new(None)) };
		let (q, target) = (p.clone(), target.to_string());
		std::thread::spawn(move || {
			for client in l.incoming().flatten() {
				let (q, target) = (q.clone(), target.clone());
				std::thread::spawn(move || {
					let Ok(upstream) = TcpStream::connect(&target) else { return };
					let _ = client.set_nodelay(true);
					let _ = upstream.set_nodelay(true);
					let mut up_w = upstream.try_clone().unwrap();
					let mut cl_w = client.try_clone().unwrap();
					let mut cl_r = BufReader::new(client);
					let mut up_r = BufReader::new(upstream);
					let last_request = Arc::new(Mutex::new(Value::Null));
					let lr = last_request.clone();
					// Requests: client to keeper.
					std::thread::spawn(move || loop {
						let mut line = String::new();
						match cl_r.read_line(&mut line) {
							Ok(0) | Err(_) => return,
							Ok(_) => {},
						}
						*lr.lock().unwrap() = serde_json::from_str(&line).unwrap_or(Value::Null);
						std::thread::sleep(delay);
						if up_w.write_all(line.as_bytes()).is_err() {
							return;
						}
					});
					// Answers: keeper to client.
					loop {
						let mut line = String::new();
						match up_r.read_line(&mut line) {
							Ok(0) | Err(_) => return,
							Ok(_) => {},
						}
						let f = q.rewrite.lock().unwrap().clone();
						if let Some(f) = f {
							let mut v: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
							f(&last_request.lock().unwrap().clone(), &mut v);
							line = format!("{}\n", v);
						}
						std::thread::sleep(delay);
						if cl_w.write_all(line.as_bytes()).is_err() {
							return;
						}
					}
				});
			}
		});
		p
	}

	pub fn rewrite(&self, f: Option<LineRewrite>) {
		*self.rewrite.lock().unwrap() = f;
	}

	/// What the signer is told of it: `<host:port>=<key>`, the key the
	/// keeper behind it signs with.
	pub fn arg(&self, key: &XOnlyPublicKey) -> String {
		format!("{}={}", self.addr, hex(&key.serialize()))
	}
}
