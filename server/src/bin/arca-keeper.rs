//! `arca-keeper`: holds the heads of the operator's signer's record on
//! another machine than the signer, so that the signer answers an entry only
//! once its signed head is held outside the signer's machine. See
//! `server::keeper` for what it takes and how it answers.
//!
//!     arca-keeper --key-file <file> --pubkey
//!     arca-keeper --key-file <file> --operator <S> --genesis <hash> --heads <file> --create
//!     arca-keeper --key-file <file> --operator <S> --genesis <hash> --heads <file> --listen <host:port> \
//!         --allow <ip> … [--max-connections <n>] [--idle-timeout-ms <ms>]
//!
//! The key file holds the keeper's own 32-byte secret key as 64 hex
//! characters, and must not be readable by anyone but its owner, and is
//! backed up as the operator key is, for a key file lost while its heads
//! file survives: the signer's record names the keeper's key for good, so a
//! keeper whose key is lost cannot be replaced. A keeper whose heads file is
//! lost, or would come back from an older copy, no longer holds what it
//! acknowledged: it is a lost keeper, never started again under its key, on
//! a new heads file or an old one. `--pubkey`
//! prints the key's public half, which the operator names when it makes the
//! signer's record (`arca-signer --create-record --keeper-key <key>`), and
//! again, with where the keeper listens, when it starts the signer
//! (`arca-signer --keeper <host:port>=<key>`). The
//! operator key `S` is the signer's public key, as `info` shows it; the
//! genesis hash is in display order. `--create` makes a new, empty heads
//! file, once, for a new keeper, and exits: a heads file is never made in
//! passing, so one that is lost is not silently replaced. The keeper locks its file while it
//! runs and syncs every head it takes before it answers.
//!
//! A keeper is reached from the signer alone: it admits a connection only
//! from an address named with `--allow` (the signer's machine; one for
//! each address it may come from), holds at most `--max-connections` open
//! (16 by default; the signer keeps one), closes one idle for
//! `--idle-timeout-ms` (60 s by default; the signer opens a new one when it
//! next needs it), and waits before accepting again after an accept fails
//! (out of descriptors, say), saying so once in a while rather than once a
//! try. A connection from an address `--allow` does not name gets one
//! answer before it is closed, to its first line, within a second: why
//! (`{"error": "refused: …"}`), so a signer that moved, or reaches the
//! keeper through NAT or another address family, says why its keeper does
//! not answer. At most a few such answers are given at once; beyond that,
//! and past the most connections it holds, a connection is closed with
//! nothing said.

use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use elements::BlockHash;
use rand::RngCore;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use arca_covenant::sign::sign_digest;
use server::keeper::{ack_digest, held_digest, latest_digest, HeadsFile, Taken, MAX_LINE};
use server::signer::{hex, unhex, unhex32, WireEntryRef};

struct Args {
	key_file: PathBuf,
	operator: Option<XOnlyPublicKey>,
	genesis: Option<BlockHash>,
	heads: Option<PathBuf>,
	listen: Option<String>,
	create: bool,
	pubkey: bool,
	/// The addresses a connection is admitted from.
	allow: Vec<IpAddr>,
	max_connections: usize,
	idle_timeout: Duration,
}

fn args() -> Result<Args, String> {
	let mut a = Args { key_file: PathBuf::new(), operator: None, genesis: None, heads: None, listen: None, create: false, pubkey: false,
		allow: vec![], max_connections: 16, idle_timeout: Duration::from_secs(60) };
	let mut key_file = None;
	let mut it = std::env::args().skip(1);
	while let Some(x) = it.next() {
		let mut value = || it.next().ok_or_else(|| format!("{} needs a value", x));
		match x.as_str() {
			"--key-file" => key_file = Some(PathBuf::from(value()?)),
			"--operator" => a.operator = Some(XOnlyPublicKey::from_slice(&unhex(&value()?)?).map_err(|e| format!("--operator: {}", e))?),
			"--genesis" => a.genesis = Some(BlockHash::from_str(&value()?).map_err(|e| format!("--genesis: {}", e))?),
			"--heads" => a.heads = Some(PathBuf::from(value()?)),
			"--listen" => a.listen = Some(value()?),
			"--create" => a.create = true,
			"--pubkey" => a.pubkey = true,
			"--allow" => a.allow.push(value()?.parse::<IpAddr>().map_err(|e| format!("--allow: {}", e))?.to_canonical()),
			"--max-connections" => a.max_connections = value()?.parse::<usize>().ok().filter(|n| *n > 0)
				.ok_or("--max-connections: a number from 1")?,
			"--idle-timeout-ms" => a.idle_timeout = Duration::from_millis(value()?.parse::<u64>().ok().filter(|n| *n > 0)
				.ok_or("--idle-timeout-ms: a number of milliseconds from 1")?),
			other => return Err(format!("unknown argument {}", other)),
		}
	}
	a.key_file = key_file.ok_or("--key-file is required")?;
	if !a.pubkey {
		if a.operator.is_none() || a.genesis.is_none() || a.heads.is_none() {
			return Err("--operator, --genesis and --heads are required".into());
		}
		if !a.create && a.listen.is_none() {
			return Err("--listen is required".into());
		}
		if a.listen.is_some() && a.allow.is_empty() {
			return Err("--allow is required with --listen: the addresses the signer connects from (a keeper is reached from the \
				signer alone)".into());
		}
	}
	Ok(a)
}

/// The most refusals answered at once ([`refuse`]).
const REFUSING: usize = 8;

/// Answers a connection the keeper does not admit with `why`, then closes
/// it: reads the peer's first line (within a second; nothing it asks is
/// done), so that the peer is not reset before it reads the answer, and
/// writes `{"error": why}`. At most [`REFUSING`] at once; beyond that the
/// connection is closed with nothing said.
fn refuse(stream: tokio::net::TcpStream, refusing: &Arc<AtomicUsize>, why: String) {
	if refusing.fetch_add(1, Ordering::SeqCst) >= REFUSING {
		refusing.fetch_sub(1, Ordering::SeqCst);
		drop(stream);
		return;
	}
	let refusing = refusing.clone();
	tokio::spawn(async move {
		let _ = tokio::time::timeout(Duration::from_secs(1), async {
			let (read, mut write) = stream.into_split();
			let mut line = String::new();
			let _ = BufReader::new(read).take(MAX_LINE as u64 + 1).read_line(&mut line).await;
			let mut out = json!({"error": why}).to_string();
			out.push('\n');
			let _ = write.write_all(out.as_bytes()).await;
			let _ = write.shutdown().await;
		}).await;
		refusing.fetch_sub(1, Ordering::SeqCst);
	});
}

fn load_key(path: &PathBuf) -> Result<Keypair, String> {
	let meta = std::fs::metadata(path).map_err(|e| format!("{}: {}", path.display(), e))?;
	if meta.permissions().mode() & 0o077 != 0 {
		return Err(format!("{} is readable by others than its owner; chmod 600 it", path.display()));
	}
	let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path.display(), e))?;
	let secret = unhex32(text.trim()).map_err(|e| format!("{}: {}", path.display(), e))?;
	let key = SecretKey::from_slice(&secret).map_err(|e| format!("{}: {}", path.display(), e))?;
	Ok(Keypair::from_secret_key(&Secp256k1::new(), &key))
}

fn sign(key: &Keypair, digest: &[u8; 32]) -> String {
	let mut aux = [0u8; 32];
	rand::rngs::OsRng.fill_bytes(&mut aux);
	hex(sign_digest(key, digest, &aux).as_ref())
}

/// Answers one request line.
fn answer(key: &Keypair, operator: &XOnlyPublicKey, genesis: &BlockHash, heads: &Mutex<HeadsFile>, line: &str) -> Value {
	let req: Value = match serde_json::from_str(line) {
		Ok(v) => v,
		Err(e) => return json!({"error": format!("not a request: {}", e)}),
	};
	let nonce = || unhex32(req["nonce"].as_str().unwrap_or(""));
	let head_json = |h: &WireEntryRef| json!({"entry": h.entry, "hash": h.hash, "signature": h.signature});
	match req["op"].as_str() {
		Some("key") => json!({"key": hex(&key.x_only_public_key().0.serialize())}),
		Some("latest") => {
			let nonce = match nonce() {
				Ok(n) => n,
				Err(e) => return json!({"error": format!("nonce: {}", e)}),
			};
			let h = heads.lock().unwrap_or_else(|e| e.into_inner());
			match h.latest() {
				Ok(Some(l)) => {
					let hash = unhex32(&l.hash).expect("held");
					json!({"head": head_json(&l), "signature": sign(key, &latest_digest(genesis, operator, &nonce, Some((l.entry, &hash))))})
				},
				Ok(None) => json!({"head": null, "signature": sign(key, &latest_digest(genesis, operator, &nonce, None))}),
				Err(e) => json!({"error": format!("the heads file could not be read: {}", e)}),
			}
		},
		Some("hold") => {
			let nonce = match nonce() {
				Ok(n) => n,
				Err(e) => return json!({"error": format!("nonce: {}", e)}),
			};
			let head: WireEntryRef = match serde_json::from_value(req["head"].clone()) {
				Ok(h) => h,
				Err(e) => return json!({"error": format!("head: {}", e)}),
			};
			let mut h = heads.lock().unwrap_or_else(|e| e.into_inner());
			// The latest head it held when asked, which a head past it is
			// taken on top of: named, signed, with the acknowledgement.
			let before = match h.latest() {
				Ok(l) => l,
				Err(e) => return json!({"error": format!("the heads file could not be read: {}", e)}),
			};
			match h.take(&head) {
				Ok(Taken::Holds) => {
					let hash = unhex32(&head.hash).expect("taken");
					let held = before.as_ref().map(|l| (l.entry, unhex32(&l.hash).expect("held")));
					json!({"ack": {"key": hex(&key.x_only_public_key().0.serialize()), "nonce": hex(&nonce),
						"signature": sign(key, &ack_digest(genesis, operator, head.entry, &hash, &nonce))},
						"latest": before.as_ref().map(head_json),
						"latest_signature": sign(key, &held_digest(genesis, operator, head.entry, &hash, &nonce,
							held.as_ref().map(|(n, x)| (*n, x))))})
				},
				Ok(Taken::Contradicts(held)) => {
					let hash = unhex32(&held.hash).expect("held");
					eprintln!("arca-keeper: refused entry {} ({}): it holds entry {} ({})", head.entry, head.hash, held.entry, held.hash);
					json!({"refused": format!("entry {} with the running hash {} contradicts what the keeper holds: entry {} with the \
						running hash {}", head.entry, head.hash, held.entry, held.hash),
						"holds": head_json(&held), "signature": sign(key, &latest_digest(genesis, operator, &nonce, Some((held.entry, &hash))))})
				},
				Err(e) => json!({"error": e}),
			}
		},
		_ => json!({"error": "unknown op: key, hold or latest"}),
	}
}

/// One open connection, counted while it lives.
struct Held(Arc<AtomicUsize>);

impl Held {
	fn new(n: Arc<AtomicUsize>) -> Held {
		n.fetch_add(1, Ordering::SeqCst);
		Held(n)
	}
}

impl Drop for Held {
	fn drop(&mut self) {
		self.0.fetch_sub(1, Ordering::SeqCst);
	}
}

/// What the keeper says of connections it refuses and accepts that fail:
/// the first of each kind at once, then how many more at most once every
/// ten seconds, so a flood cannot fill its log.
#[derive(Default)]
struct Said {
	kinds: std::collections::HashMap<&'static str, (Instant, u64)>,
}

impl Said {
	fn say(&mut self, kind: &'static str, what: String) {
		let now = Instant::now();
		match self.kinds.get_mut(kind) {
			None => {
				eprintln!("arca-keeper: {}", what);
				self.kinds.insert(kind, (now, 0));
			},
			Some((at, more)) => {
				*more += 1;
				if now.duration_since(*at) >= Duration::from_secs(10) {
					eprintln!("arca-keeper: {} ({} more like it in the last {} s)", what, more, now.duration_since(*at).as_secs());
					*at = now;
					*more = 0;
				}
			},
		}
	}
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
	let fail = |e: String| -> ! {
		eprintln!("arca-keeper: {}", e);
		std::process::exit(2);
	};
	let a = args().unwrap_or_else(|e| fail(e));
	let key = load_key(&a.key_file).unwrap_or_else(|e| fail(e));
	if a.pubkey {
		println!("{}", hex(&key.x_only_public_key().0.serialize()));
		return;
	}
	let (operator, genesis, path) = (a.operator.expect("checked"), a.genesis.expect("checked"), a.heads.clone().expect("checked"));
	if a.create {
		match HeadsFile::create(&path, &operator, &genesis) {
			Ok(()) => {
				eprintln!("arca-keeper: created the heads file {} for S = {} on {}: for a new keeper only; a keeper whose heads file was \
					lost is a lost keeper, never started again under its key", path.display(), hex(&operator.serialize()), genesis);
				return;
			},
			Err(e) => fail(e),
		}
	}
	let heads = match HeadsFile::open(&path, &operator, &genesis) {
		Ok((h, note)) => {
			if let Some(n) = note {
				eprintln!("arca-keeper: {}", n);
			}
			Arc::new(Mutex::new(h))
		},
		Err(e) => fail(e),
	};
	let listen = a.listen.clone().expect("checked");
	let listener = TcpListener::bind(&listen).await.unwrap_or_else(|e| fail(format!("{}: {}", listen, e)));
	{
		let h = heads.lock().unwrap_or_else(|e| e.into_inner());
		eprintln!("arca-keeper: K = {} keeps the heads of S = {} on {} in {}: {} held, the latest {}; on {}, admitting {} alone, at most {} \
			connection(s), each closed after {} ms idle", hex(&key.x_only_public_key().0.serialize()), hex(&operator.serialize()), genesis,
			path.display(), h.len(), h.latest().ok().flatten().map(|l| l.entry.to_string()).unwrap_or_else(|| "none".into()),
			listener.local_addr().map(|a| a.to_string()).unwrap_or_default(),
			a.allow.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", "), a.max_connections, a.idle_timeout.as_millis());
	}
	let open = Arc::new(AtomicUsize::new(0));
	let refusing = Arc::new(AtomicUsize::new(0));
	let mut said = Said::default();
	let mut wait = Duration::ZERO;
	loop {
		let (stream, peer) = match listener.accept().await {
			Ok(s) => s,
			Err(e) => {
				// Out of descriptors, say: wait before trying again, longer
				// each time, and say so once in a while.
				wait = (wait * 2).clamp(Duration::from_millis(10), Duration::from_secs(1));
				said.say("accept", format!("accept: {}; waiting {} ms before accepting again", e, wait.as_millis()));
				tokio::time::sleep(wait).await;
				continue;
			},
		};
		wait = Duration::ZERO;
		// Holding its most connections, the keeper closes the next at once
		// with nothing said, whoever it comes from: a stranger is told why
		// only while the keeper has room.
		if open.load(Ordering::SeqCst) >= a.max_connections {
			said.say("full", format!("refused a connection from {}: {} are open, the most it holds", peer, a.max_connections));
			drop(stream);
			continue;
		}
		let from = peer.ip().to_canonical();
		if !a.allow.contains(&from) {
			said.say("refused", format!("refused a connection from {}, which --allow does not name", peer));
			refuse(stream, &refusing, format!("refused: this keeper admits connections only from the addresses its --allow names, and \
				{} is not one: name it with --allow on the keeper (and in its firewall)", from));
			continue;
		}
		let held = Held::new(open.clone());
		let (heads, idle) = (heads.clone(), a.idle_timeout);
		tokio::spawn(async move {
			let _held = held;
			let _ = stream.set_nodelay(true);
			let (read, mut write) = stream.into_split();
			let mut reader = BufReader::new(read);
			loop {
				let mut line = String::new();
				// A connection idle this long is closed: the signer opens a
				// new one when it next needs it.
				let got = match tokio::time::timeout(idle, (&mut reader).take(MAX_LINE as u64 + 1).read_line(&mut line)).await {
					Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
					Ok(Ok(n)) => n,
				};
				let reply = if got > MAX_LINE || !line.ends_with('\n') {
					json!({"error": "request too long"})
				} else {
					answer(&key, &operator, &genesis, &heads, line.trim_end())
				};
				let mut out = reply.to_string();
				out.push('\n');
				if write.write_all(out.as_bytes()).await.is_err() || got > MAX_LINE {
					return;
				}
			}
		});
	}
}
