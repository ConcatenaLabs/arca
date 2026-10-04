//! The keeper: a holder of the signer's signed heads on another machine than
//! the signer, so that a snapshot of the signer's machine, restored over its
//! record and the server's database together, cannot take back an entry the
//! signer has answered.
//!
//! `arca-keeper` holds the operator key `S` (public), the chain's genesis
//! hash and a key of its own, `K`, and keeps an append-only file of the
//! heads of `S`'s record it was given ([`HeadsFile`]), each line synced to
//! disk before it answers. It takes a head only with `S`'s valid signature
//! ([`crate::signer::record_head_digest`]), and only when it extends what it
//! holds: an entry after its latest, or an entry it holds with the same
//! running hash. Any other head contradicts what it holds, and is refused
//! with the head it holds at that entry (another hash), or, at an entry it
//! never held before its latest, with its latest: each signed by `S`, which
//! is the signer's own proof that its record was rolled back (D49).
//!
//! The keeper speaks TCP, one JSON object a line each way, any number of
//! requests on one connection:
//!
//! - `{"op":"key"}`: `{"key": K}`;
//! - `{"op":"hold","head":{"entry":…,"hash":…,"signature":…},"nonce":…}`:
//!   `{"ack":{"key":K,"nonce":…,"signature":…}}`, `K`'s signature over
//!   [`ack_digest`]: the keeper holds that head, now; or
//!   `{"refused":…,"holds":{…},"signature":…}`, the head it holds at that
//!   entry or its latest, with `K`'s signature over [`latest_digest`];
//! - `{"op":"latest","nonce":…}`: `{"head":{…}|null,"signature":…}`, the
//!   latest head it holds and `K`'s signature over [`latest_digest`].
//!
//! Every answer is signed by `K` over the asker's nonce, fresh for each
//! request, so nobody on the path can make an acknowledgement or replay an
//! older latest. The acknowledgement travels on with the head, to every
//! wallet that is shown it: a wallet that pinned the keeper's key checks it
//! as the signer does.

use std::path::Path;

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use serde::{Deserialize, Serialize};

use crate::signer::{hex, record_head_digest, unhex, unhex32, WireEntryRef};

/// The tag of a keeper's acknowledgement of a head.
pub const ACK_TAG: &[u8] = b"Arca/keeper-ack";
/// The tag of a keeper's answer naming the latest head it holds.
pub const LATEST_TAG: &[u8] = b"Arca/keeper-latest";
/// The first word of a heads file's first line.
pub const HEADS_MAGIC: &str = "arca-keeper-heads";
/// The heads file's format.
pub const HEADS_VERSION: u32 = 1;
/// The longest request line a keeper reads.
pub const MAX_LINE: usize = 4096;

fn tagged(tag: &[u8]) -> sha256::HashEngine {
	let t = sha256::Hash::hash(tag);
	let mut e = sha256::Hash::engine();
	e.input(t.as_byte_array());
	e.input(t.as_byte_array());
	e
}

/// What keeper `K` signs to acknowledge that it holds head `entry`, `hash`
/// of `S`'s record on the chain of `genesis`, answering a request that
/// carried `nonce`: `SHA256(T ‖ T ‖ genesis ‖ S ‖ entry ‖ hash ‖ nonce)`,
/// `T = SHA256("Arca/keeper-ack")`, the genesis hash in internal byte
/// order, the entry eight bytes little-endian.
pub fn ack_digest(genesis: &elements::BlockHash, operator: &XOnlyPublicKey, entry: u64, hash: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
	let mut e = tagged(ACK_TAG);
	e.input(&arca_covenant::Chain::new(*genesis).genesis_bytes());
	e.input(&operator.serialize());
	e.input(&entry.to_le_bytes());
	e.input(hash);
	e.input(nonce);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// What keeper `K` signs to name the latest head of `S`'s record it holds,
/// `head` (`None` when it holds none), answering a request that carried
/// `nonce`: `SHA256(T ‖ T ‖ genesis ‖ S ‖ nonce ‖ 0x00)` when it holds none,
/// `SHA256(T ‖ T ‖ genesis ‖ S ‖ nonce ‖ 0x01 ‖ entry ‖ hash)` otherwise,
/// `T = SHA256("Arca/keeper-latest")`.
pub fn latest_digest(genesis: &elements::BlockHash, operator: &XOnlyPublicKey, nonce: &[u8; 32], head: Option<(u64, &[u8; 32])>)
	-> [u8; 32]
{
	let mut e = tagged(LATEST_TAG);
	e.input(&arca_covenant::Chain::new(*genesis).genesis_bytes());
	e.input(&operator.serialize());
	e.input(nonce);
	match head {
		None => e.input(&[0]),
		Some((n, h)) => {
			e.input(&[1]);
			e.input(&n.to_le_bytes());
			e.input(h);
		},
	}
	sha256::Hash::from_engine(e).to_byte_array()
}

/// A keeper's acknowledgement of a head, as it travels with the head: the
/// keeper's key, the nonce of the request it answered, and its signature
/// over [`ack_digest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireAck {
	pub key: String,
	pub nonce: String,
	pub signature: String,
}

impl WireAck {
	/// Whether this is `keeper`'s acknowledgement of head `entry`, `hash` of
	/// `operator`'s record on `genesis`'s chain.
	pub fn verify(&self, genesis: &elements::BlockHash, operator: &XOnlyPublicKey, keeper: &XOnlyPublicKey, entry: u64, hash: &[u8; 32])
		-> bool
	{
		let ok = || -> Option<bool> {
			if unhex32(&self.key).ok()? != keeper.serialize() {
				return Some(false);
			}
			let nonce = unhex32(&self.nonce).ok()?;
			let sig = Signature::from_slice(&unhex(&self.signature).ok()?).ok()?;
			Some(arca_covenant::sign::verify_digest(&sig, &ack_digest(genesis, operator, entry, hash, &nonce), keeper))
		};
		ok().unwrap_or(false)
	}
}

/// Whether `head` carries `operator`'s signature over it as a head of its
/// record on `genesis`'s chain.
pub fn signed_by(genesis: &elements::BlockHash, operator: &XOnlyPublicKey, head: &WireEntryRef) -> bool {
	let ok = || -> Option<bool> {
		let hash = unhex32(&head.hash).ok()?;
		let sig = Signature::from_slice(&unhex(head.signature.as_deref()?).ok()?).ok()?;
		Some(arca_covenant::sign::verify_digest(&sig, &record_head_digest(genesis, head.entry, &hash), operator))
	};
	ok().unwrap_or(false)
}

/// What [`HeadsFile::take`] does with a head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Taken {
	/// It holds the head now: written and synced, or held before.
	Holds,
	/// The head contradicts what it holds: the head it holds at that entry
	/// (another hash), or its latest, past the entry, which it never held.
	Contradicts(WireEntryRef),
}

/// The header of a heads file kept for `operator` on the chain of `genesis`.
pub fn heads_header(operator: &XOnlyPublicKey, genesis: &elements::BlockHash) -> String {
	format!("{} {} {} {}", HEADS_MAGIC, HEADS_VERSION, hex(&operator.serialize()), genesis)
}

/// A keeper's append-only file of the heads of `S`'s record it was given:
/// a header naming the format, `S` and the chain, then one line a head,
/// `<entry> <hash> <S's signature>`, entries strictly increasing, each
/// appended and synced before the keeper answers. It is made once, on
/// purpose ([`HeadsFile::create`]), never in passing, so a lost file is not
/// silently replaced; the keeper locks it while it runs; a write that fails
/// is undone at once, and a last line cut short by a crash, never answered,
/// is removed when the file is opened, which says so; and the file is
/// synced when it is opened, before the keeper answers anything. Every
/// line's signature is checked when the file is opened.
pub struct HeadsFile {
	file: std::fs::File,
	size: u64,
	/// Every head held: its entry, running hash, and where its line starts.
	held: Vec<(u64, [u8; 32], u64)>,
	operator: XOnlyPublicKey,
	genesis: elements::BlockHash,
}

impl HeadsFile {
	/// Makes a new, empty heads file at `path` (mode 0600), and syncs it and
	/// its directory. It never replaces a file already there.
	pub fn create(path: &Path, operator: &XOnlyPublicKey, genesis: &elements::BlockHash) -> Result<(), String> {
		use std::io::Write;
		use std::os::unix::fs::OpenOptionsExt;
		let fail = |e: std::io::Error| format!("{}: {}", path.display(), e);
		let mut file = match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) {
			Ok(f) => f,
			Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
				return Err(format!("{}: a heads file is there already; one is made once, and never replaced", path.display()));
			},
			Err(e) => return Err(fail(e)),
		};
		file.write_all(format!("{}\n", heads_header(operator, genesis)).as_bytes()).map_err(fail)?;
		file.sync_all().map_err(fail)?;
		if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
			std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(fail)?;
		}
		Ok(())
	}

	/// Opens the heads file at `path`, kept for `operator` on the chain of
	/// `genesis`, and locks it for this process. Returns it, and a note when
	/// a last line cut short was removed.
	pub fn open(path: &Path, operator: &XOnlyPublicKey, genesis: &elements::BlockHash) -> Result<(HeadsFile, Option<String>), String> {
		use std::io::{BufRead, Seek};
		let fail = |e: std::io::Error| format!("{}: {}", path.display(), e);
		let mut file = match std::fs::OpenOptions::new().read(true).append(true).open(path) {
			Ok(f) => f,
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(format!(
				"{}: there is no heads file here. A keeper starts only on its file, whole: one that is lost is not replaced by an \
				 empty one in passing. A new keeper starts with a file made once, on purpose: arca-keeper --create", path.display())),
			Err(e) => return Err(fail(e)),
		};
		match file.try_lock() {
			Ok(()) => {},
			Err(std::fs::TryLockError::WouldBlock) => return Err(format!(
				"{}: the heads file is held by another keeper that is running", path.display())),
			Err(std::fs::TryLockError::Error(e)) => return Err(fail(e)),
		}
		file.seek(std::io::SeekFrom::Start(0)).map_err(fail)?;
		let mut reader = std::io::BufReader::new(file.try_clone().map_err(fail)?);
		let mut line = String::new();
		let got = reader.read_line(&mut line).map_err(fail)?;
		if got == 0 || !line.ends_with('\n') {
			return Err(format!("{}: the heads file has no header line", path.display()));
		}
		let header = line.trim_end_matches('\n').to_string();
		if header != heads_header(operator, genesis) {
			return Err(format!("{}: the heads file is not one kept for {} on {} in format {} ({:?})", path.display(),
				hex(&operator.serialize()), genesis, HEADS_VERSION, header.chars().take(160).collect::<String>()));
		}
		let mut at = got as u64;
		let mut held: Vec<(u64, [u8; 32], u64)> = vec![];
		let mut repaired = None;
		let mut k = 1u64;
		loop {
			k += 1;
			line.clear();
			let got = reader.read_line(&mut line).map_err(fail)?;
			if got == 0 {
				break;
			}
			if !line.ends_with('\n') {
				repaired = Some(format!("the heads file's last line was cut short, by a write that failed or a crash, and was never \
					answered: removed ({} bytes)", got));
				file.set_len(at).map_err(fail)?;
				break;
			}
			let bad = |what: &str| format!("{} line {}: {}: {:?}", path.display(), k, what, line.trim_end().chars().take(200).collect::<String>());
			let head = parse_head(line.trim_end_matches('\n')).map_err(|e| bad(&e))?;
			if held.last().is_some_and(|l| l.0 >= head.entry) {
				return Err(bad("an entry not after the one before it: the file has been changed"));
			}
			if !signed_by(genesis, operator, &head) {
				return Err(bad("a head without S's signature: the file has been changed"));
			}
			held.push((head.entry, unhex32(&head.hash).expect("parsed"), at));
			at += got as u64;
		}
		// A whole line a crash left unsynced is on disk before anything is
		// answered.
		file.sync_all().map_err(fail)?;
		Ok((HeadsFile { file, size: at, held, operator: *operator, genesis: *genesis }, repaired))
	}

	/// How many heads it holds.
	pub fn len(&self) -> usize {
		self.held.len()
	}

	pub fn is_empty(&self) -> bool {
		self.held.is_empty()
	}

	/// The head held at line `at`, read back with its signature.
	fn head_at(&self, at: u64) -> Result<WireEntryRef, String> {
		use std::os::unix::fs::FileExt;
		let mut buf = vec![0u8; 256];
		let n = self.file.read_at(&mut buf, at).map_err(|e| e.to_string())?;
		let text = std::str::from_utf8(&buf[..n]).map_err(|e| e.to_string())?;
		parse_head(text.split('\n').next().unwrap_or(""))
	}

	/// The latest head it holds, with `S`'s signature.
	pub fn latest(&self) -> Result<Option<WireEntryRef>, String> {
		self.held.last().map(|l| self.head_at(l.2)).transpose()
	}

	/// The head it holds at `entry`, with `S`'s signature.
	pub fn at(&self, entry: u64) -> Result<Option<WireEntryRef>, String> {
		match self.held.binary_search_by_key(&entry, |l| l.0) {
			Ok(i) => self.head_at(self.held[i].2).map(Some),
			Err(_) => Ok(None),
		}
	}

	/// Takes `head`: refused without `S`'s signature; held when it is after
	/// the latest held (appended and synced) or held already with the same
	/// hash; otherwise it contradicts what the file holds.
	pub fn take(&mut self, head: &WireEntryRef) -> Result<Taken, String> {
		use std::io::Write;
		if !signed_by(&self.genesis, &self.operator, head) {
			return Err(format!("entry {} with the running hash {} is not signed by S as a head of its record on this chain", head.entry,
				head.hash));
		}
		let hash = unhex32(&head.hash)?;
		match self.held.last() {
			Some(l) if head.entry <= l.0 => {
				return match self.held.binary_search_by_key(&head.entry, |x| x.0) {
					Ok(i) if self.held[i].1 == hash => Ok(Taken::Holds),
					Ok(i) => Ok(Taken::Contradicts(self.head_at(self.held[i].2)?)),
					Err(_) => Ok(Taken::Contradicts(self.head_at(l.2)?)),
				};
			},
			_ => {},
		}
		let line = format!("{} {} {}\n", head.entry, head.hash, head.signature.as_deref().unwrap_or(""));
		if let Err(error) = self.file.write_all(line.as_bytes()).and_then(|_| self.file.sync_data()) {
			let undone = self.file.set_len(self.size).and_then(|_| self.file.sync_data());
			return Err(format!("the heads file could not be written ({}){}", error,
				if undone.is_ok() { "; the line cut short was removed" } else { "; nor the line cut short removed" }));
		}
		self.held.push((head.entry, hash, self.size));
		self.size += line.len() as u64;
		Ok(Taken::Holds)
	}
}

/// One line of a heads file, `<entry> <hash> <signature>`.
fn parse_head(line: &str) -> Result<WireEntryRef, String> {
	let f: Vec<&str> = line.split(' ').collect();
	match f.as_slice() {
		[n, h, s] if !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()) => {
			unhex32(h)?;
			unhex(s)?;
			Ok(WireEntryRef { entry: n.parse().map_err(|_| "not a head line".to_string())?, hash: h.to_string(), signature: Some(s.to_string()) })
		},
		_ => Err("not a head line".into()),
	}
}

/// A keeper the signer is configured with: where it listens, and its key.
#[derive(Debug, Clone)]
pub struct KeeperAddr {
	pub addr: String,
	pub key: XOnlyPublicKey,
}

impl std::str::FromStr for KeeperAddr {
	type Err = String;

	/// `<host:port>=<key>`, the key 64 hex characters, as `arca-keeper
	/// --pubkey` prints it.
	fn from_str(s: &str) -> Result<KeeperAddr, String> {
		let (addr, key) = s.rsplit_once('=').ok_or_else(|| format!("a keeper is <host:port>=<key>, not {:?}", s))?;
		let key = XOnlyPublicKey::from_slice(&unhex(key)?).map_err(|e| format!("the keeper's key: {}", e))?;
		Ok(KeeperAddr { addr: addr.to_string(), key })
	}
}

/// How many of `n` keepers must answer for their latest, at a start, when
/// `required` of them must hold every head: enough that any `required` of
/// them include one that answered (`n - required + 1`), so the latest head
/// any acknowledged set holds is seen.
pub fn start_quorum(n: usize, required: usize) -> usize {
	n.saturating_sub(required) + 1
}

/// The refusal code of a signer that cannot sign now for want of its
/// keepers: too few answered for their latest since it started, or too few
/// acknowledged the head an entry needs. The entry stays; the same request
/// again completes once they do.
pub const KEEPERS_UNAVAILABLE: &str = "keepers_unavailable";

/// What a keeper answered to a head handed to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Held {
	/// It holds the head: its acknowledgement, checked.
	Ack(WireAck),
	/// The head contradicts what it holds: the head it holds there, or its
	/// latest, signed by `S` (checked).
	Contradicts(WireEntryRef),
}

type Conn = (tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>, tokio::net::tcp::OwnedWriteHalf);

/// The signer's end of one keeper: one connection, kept open and asked one
/// request at a time, opened again after any failure. Every answer is
/// checked against the keeper's key and the request's nonce, fresh for each
/// request, so an answer someone on the path made, or replayed, is no
/// answer.
pub struct KeeperClient {
	pub addr: KeeperAddr,
	conn: tokio::sync::Mutex<Option<Conn>>,
	timeout: std::time::Duration,
}

impl KeeperClient {
	pub fn new(addr: KeeperAddr, timeout: std::time::Duration) -> KeeperClient {
		KeeperClient { addr, conn: tokio::sync::Mutex::new(None), timeout }
	}

	async fn ask(&self, req: &serde_json::Value) -> Result<serde_json::Value, String> {
		use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
		let mut line = req.to_string();
		line.push('\n');
		let mut c = self.conn.lock().await;
		let mut last = String::new();
		for _ in 0..2 {
			if c.is_none() {
				match tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(&self.addr.addr)).await {
					Ok(Ok(s)) => {
						let _ = s.set_nodelay(true);
						let (r, w) = s.into_split();
						*c = Some((tokio::io::BufReader::new(r), w));
					},
					Ok(Err(e)) => return Err(format!("{}: {}", self.addr.addr, e)),
					Err(_) => return Err(format!("{}: no connection within {} ms", self.addr.addr, self.timeout.as_millis())),
				}
			}
			let (r, w) = c.as_mut().expect("connected");
			let got = tokio::time::timeout(self.timeout, async {
				w.write_all(line.as_bytes()).await?;
				let mut out = String::new();
				match r.read_line(&mut out).await? {
					0 => Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "the keeper closed the connection")),
					_ => Ok(out),
				}
			}).await;
			match got {
				Ok(Ok(out)) => return serde_json::from_str(&out).map_err(|e| format!("{}: its answer is not understood: {}", self.addr.addr, e)),
				Ok(Err(e)) => last = format!("{}: {}", self.addr.addr, e),
				Err(_) => last = format!("{}: no answer within {} ms", self.addr.addr, self.timeout.as_millis()),
			}
			*c = None;
		}
		Err(last)
	}

	/// The latest head the keeper holds, as it names it signed with its key
	/// over a fresh nonce; `None` when it holds none.
	pub async fn latest(&self, genesis: &elements::BlockHash, operator: &XOnlyPublicKey) -> Result<Option<WireEntryRef>, String> {
		let nonce = random_nonce();
		let v = self.ask(&serde_json::json!({"op": "latest", "nonce": hex(&nonce)})).await?;
		if let Some(e) = v["error"].as_str() {
			return Err(format!("{}: {}", self.addr.addr, e));
		}
		let head: Option<WireEntryRef> = match &v["head"] {
			serde_json::Value::Null => None,
			h => Some(serde_json::from_value(h.clone()).map_err(|e| format!("{}: the head it names: {}", self.addr.addr, e))?),
		};
		let hash = head.as_ref().map(|h| unhex32(&h.hash)).transpose()?;
		let digest = latest_digest(genesis, operator, &nonce, head.as_ref().zip(hash.as_ref()).map(|(h, x)| (h.entry, x)));
		if !self.signed(&v["signature"], &digest) {
			return Err(format!("{}: its answer is not signed by its key over this request's nonce: made or replayed by someone else",
				self.addr.addr));
		}
		if let Some(h) = &head {
			if !signed_by(genesis, operator, h) {
				return Err(format!("{}: the head it names, entry {}, is not signed by S", self.addr.addr, h.entry));
			}
		}
		Ok(head)
	}

	/// Hands the keeper `head`, signed by `S`: its acknowledgement, or the
	/// head it holds that `head` contradicts, each checked.
	pub async fn hold(&self, genesis: &elements::BlockHash, operator: &XOnlyPublicKey, head: &WireEntryRef) -> Result<Held, String> {
		let nonce = random_nonce();
		let v = self.ask(&serde_json::json!({"op": "hold", "head": head, "nonce": hex(&nonce)})).await?;
		if !v["ack"].is_null() {
			let ack: WireAck = serde_json::from_value(v["ack"].clone()).map_err(|e| format!("{}: its acknowledgement: {}", self.addr.addr, e))?;
			let hash = unhex32(&head.hash)?;
			if ack.nonce != hex(&nonce) || !ack.verify(genesis, operator, &self.addr.key, head.entry, &hash) {
				return Err(format!("{}: an acknowledgement not signed by its key over this head and this request's nonce: made or \
					replayed by someone else", self.addr.addr));
			}
			return Ok(Held::Ack(ack));
		}
		if let Some(why) = v["refused"].as_str() {
			let holds: WireEntryRef = serde_json::from_value(v["holds"].clone()).map_err(|e| format!("{}: the head it holds: {}", self.addr.addr, e))?;
			let hash = unhex32(&holds.hash)?;
			if !self.signed(&v["signature"], &latest_digest(genesis, operator, &nonce, Some((holds.entry, &hash)))) || !signed_by(genesis, operator, &holds) {
				return Err(format!("{}: a refusal ({}) not signed by its key over this request's nonce, or naming a head S did not sign",
					self.addr.addr, why));
			}
			return Ok(Held::Contradicts(holds));
		}
		Err(format!("{}: {}", self.addr.addr, v["error"].as_str().unwrap_or("no acknowledgement")))
	}

	fn signed(&self, sig: &serde_json::Value, digest: &[u8; 32]) -> bool {
		sig.as_str().and_then(|s| unhex(s).ok()).and_then(|b| Signature::from_slice(&b).ok())
			.is_some_and(|s| arca_covenant::sign::verify_digest(&s, digest, &self.addr.key))
	}
}

/// 32 random bytes from the system's source: each request's nonce.
pub fn random_nonce() -> [u8; 32] {
	use rand::RngCore;
	let mut n = [0u8; 32];
	rand::rngs::OsRng.fill_bytes(&mut n);
	n
}
