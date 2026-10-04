//! `arca-keeper`: holds the heads of the operator's signer's record on
//! another machine than the signer, so that the signer answers an entry only
//! once its signed head is held outside the signer's machine. See
//! `server::keeper` for what it takes and how it answers.
//!
//!     arca-keeper --key-file <file> --pubkey
//!     arca-keeper --key-file <file> --operator <S> --genesis <hash> --heads <file> --create
//!     arca-keeper --key-file <file> --operator <S> --genesis <hash> --heads <file> --listen <host:port>
//!
//! The key file holds the keeper's own 32-byte secret key as 64 hex
//! characters, and must not be readable by anyone but its owner; `--pubkey`
//! prints the key's public half, which the signer's operator names in the
//! signer's configuration (`arca-signer --keeper <host:port>=<key>`). The
//! operator key `S` is the signer's public key, as `info` shows it; the
//! genesis hash is in display order. `--create` makes a new, empty heads
//! file, once, and exits: a heads file is never made in passing, so one that
//! is lost is not silently replaced. The keeper locks its file while it
//! runs and syncs every head it takes before it answers.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use elements::BlockHash;
use rand::RngCore;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use arca_covenant::sign::sign_digest;
use server::keeper::{ack_digest, latest_digest, HeadsFile, Taken, MAX_LINE};
use server::signer::{hex, unhex, unhex32, WireEntryRef};

struct Args {
	key_file: PathBuf,
	operator: Option<XOnlyPublicKey>,
	genesis: Option<BlockHash>,
	heads: Option<PathBuf>,
	listen: Option<String>,
	create: bool,
	pubkey: bool,
}

fn args() -> Result<Args, String> {
	let mut a = Args { key_file: PathBuf::new(), operator: None, genesis: None, heads: None, listen: None, create: false, pubkey: false };
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
	}
	Ok(a)
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
			match h.take(&head) {
				Ok(Taken::Holds) => {
					let hash = unhex32(&head.hash).expect("taken");
					json!({"ack": {"key": hex(&key.x_only_public_key().0.serialize()), "nonce": hex(&nonce),
						"signature": sign(key, &ack_digest(genesis, operator, head.entry, &hash, &nonce))}})
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
				eprintln!("arca-keeper: created the heads file {} for S = {} on {}", path.display(), hex(&operator.serialize()), genesis);
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
		eprintln!("arca-keeper: K = {} keeps the heads of S = {} on {} in {}: {} held, the latest {}; on {}",
			hex(&key.x_only_public_key().0.serialize()), hex(&operator.serialize()), genesis, path.display(), h.len(),
			h.latest().ok().flatten().map(|l| l.entry.to_string()).unwrap_or_else(|| "none".into()),
			listener.local_addr().map(|a| a.to_string()).unwrap_or_default());
	}
	loop {
		let (stream, _) = match listener.accept().await {
			Ok(s) => s,
			Err(e) => {
				eprintln!("arca-keeper: accept: {}", e);
				continue;
			},
		};
		let heads = heads.clone();
		tokio::spawn(async move {
			let _ = stream.set_nodelay(true);
			let (read, mut write) = stream.into_split();
			let mut reader = BufReader::new(read);
			loop {
				let mut line = String::new();
				let got = match (&mut reader).take(MAX_LINE as u64 + 1).read_line(&mut line).await {
					Ok(0) | Err(_) => return,
					Ok(n) => n,
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
