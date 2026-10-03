//! The operator key `S`, behind a narrow interface in a process of its own.
//!
//! The server never holds `S`. The signer (`arca-signer`) loads it, listens on
//! a Unix socket, and answers these requests, one JSON object per line:
//!
//! - `{"op":"pubkey"}`: the x-only key `S`;
//! - `{"op":"rebind","owner":…,"owner_sig":…,"salt":…,"asset_in":…,"value_in":…,"outputs":[…],"known":…}`:
//!   `S`'s signature over the rebindable message of a collaborative path,
//!   which the signer builds itself from the parts, on its own chain:
//!   `SHA256(K ‖ asset_in ‖ 0x01 ‖ 0x01 ‖ value_in ‖ m ‖ SHA256(record 0) ‖ …)`
//!   with `K = SHA256(SHA256("ArcaRbd1" ‖ genesis) ‖ salt)`, for 1 to 4
//!   committed outputs; with the entry of the record it was recorded as.
//!   `known` names the latest entry of the record the server's database
//!   knows (`{"entry":…,"hash":…}`);
//! - `{"op":"head"}` and `{"op":"entries","after":…,"limit":…}`: the record's
//!   latest entry, and its entries after one, for the server to check its
//!   database against at start;
//! - `{"op":"spend","tx":…,"prevouts":[…],"input":…,"leaf":…}`: `S`'s signature
//!   over the spend of input `input` of the transaction by the tapscript leaf
//!   `leaf`, whose signature hash (Elements taproot, `SIGHASH_DEFAULT`, its
//!   own chain's genesis hash) the signer computes itself from the
//!   transaction and the outputs every input spends. It signs only for a leaf
//!   that names `S` with `OP_CHECKSIG` or `OP_CHECKSIGVERIFY` (one of the
//!   operator's own paths: a clock's release or roll, `R`, a sweep, a reclaim,
//!   a forfeit's claim, the connector's issuance, an offboard's reclaim), and
//!   only for an input that spends a taproot output.
//!
//! It signs nothing else: no digest handed to it, no unroll authorisation, no
//! release, and no spend by a path that checks `S` with
//! `OP_CHECKSIGFROMSTACK`, which only the rebindable message reaches. The
//! socket sits in a directory only the operator's user can enter, and the
//! server checks every rule before it asks.
//!
//! # The one-spend record
//!
//! The signer, not the database, is the authority on what `S` has co-signed.
//! Before it returns a rebindable signature it appends `(owner, salt, kind,
//! digest)` to its record, a file it alone writes, and syncs it to disk
//! ([`SpendRecord`]); it reads the record line by line when it starts. Each entry
//! names its leaf: its owner's key together with its salt (a leaf's, a
//! board's or a checkpoint's, whose owner is its coin's). The rule, though, is
//! kept per salt: `S`'s signature commits to the salt (`K` above) and not to
//! the owner key, so a signature given for one leaf is valid on every coin of
//! the same salt, asset and value. Under each salt it signs:
//!
//! - one **spend**: a message into anything but a forfeit output (a leaf
//!   into its checkpoint, a checkpoint into its reassignment). A spend
//!   message is refused (`already_signed`) when any entry under the salt,
//!   whatever its owner, carries another message, whatever the database
//!   says; the same message again is signed again, so a request repeated
//!   after a signer outage completes;
//! - or any number of **forfeits**, one for each round's connector asset `M`:
//!   a leaf given up in a round, and again forfeit-first in a later round
//!   after the first could never return. A forfeit is a rebind request that
//!   names the forfeit's parts (`forfeit`), from which the signer rebuilds
//!   the forfeit output and checks it is the one output committed to; it is
//!   refused once the salt has a spend, and a second forfeit message for the
//!   same `M` under the salt is refused. A spend is refused once the salt
//!   has a forfeit.
//!
//! Every rebind request names the leaf's owner key and carries the owner's
//! own signature over the very message `S` is to sign (the checkpoint, the
//! reassignment or the forfeit each needs both), and the signer checks it
//! before it records anything: an entry under a key is always the holder of
//! that key's doing. The server refuses a second leaf under a salt it knows,
//! so two leaves share a salt only where its database has forgotten one
//! (restored from an older copy, or new). There the first leaf to spend
//! under the salt takes it, and the other's holder is refused, and can still
//! exit; a second signature under one salt, which would be valid on the first
//! coin as well, is never given.
//!
//! So a database restored from an older copy, which no longer knows a
//! transfer it co-signed, cannot have `S` co-sign a second spend of the same
//! coin: the record outlives it.
//!
//! The record cannot be lost, cut back, torn or shared without the signer
//! noticing ([`SpendRecord`]): it is made once, on purpose, never in passing;
//! every entry carries its number and a running hash, and the server's
//! database remembers the latest it was given, which every request names, so
//! a record cut back or replaced stops the signer signing; a write that fails
//! is undone, and a line cut short by a crash removed at start; and the
//! signer locks the record while it runs.
//!
//! Amounts are decimal strings, asset ids in display order, everything else
//! hex.

use std::path::{Path, PathBuf};

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Script};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use arca_covenant::{ExplicitOutput, ForfeitPolicy, LeafId, RelativeTime};

/// The longest request line the signer reads: a claim of 200 forfeits, its
/// spent outputs with it, fits several times over.
pub const MAX_REQUEST: usize = 1024 * 1024;

/// An output a rebindable signature commits to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireOutput {
	pub asset: String,
	pub value: String,
	pub script: String,
}

impl WireOutput {
	pub fn from_output(o: &ExplicitOutput) -> WireOutput {
		WireOutput { asset: o.asset.to_string(), value: o.value.to_string(), script: hex(o.script_pubkey.as_bytes()) }
	}

	pub fn to_output(&self) -> Result<ExplicitOutput, String> {
		let asset: AssetId = self.asset.parse().map_err(|e| format!("asset: {}", e))?;
		let value = parse_amount(&self.value)?;
		let script = Script::from(unhex(&self.script)?);
		Ok(ExplicitOutput::new(asset, value, script))
	}
}

/// The parts of a forfeit output, from which the signer rebuilds it: the
/// owner's key, the unlock hash, the connector asset (display order), the
/// refund delay in 512-second units and the id of the leaf given up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireForfeit {
	pub owner: String,
	pub unlock_hash: String,
	pub connector: String,
	pub refund_delay_units: u16,
	pub leaf_id: String,
}

impl WireForfeit {
	pub fn from_policy(p: &ForfeitPolicy) -> WireForfeit {
		WireForfeit {
			owner: hex(&p.owner.serialize()), unlock_hash: hex(&p.unlock_hash), connector: p.connector.to_string(),
			refund_delay_units: p.refund_delay.units(), leaf_id: hex(&p.leaf_id.0),
		}
	}

	/// The forfeit policy these parts name under `operator`.
	pub fn to_policy(&self, operator: XOnlyPublicKey) -> Result<ForfeitPolicy, String> {
		Ok(ForfeitPolicy {
			unlock_hash: unhex32(&self.unlock_hash)?,
			owner: XOnlyPublicKey::from_slice(&unhex(&self.owner)?).map_err(|e| format!("owner: {}", e))?,
			operator,
			refund_delay: RelativeTime::from_units(self.refund_delay_units).map_err(|e| format!("refund_delay_units: {}", e))?,
			leaf_id: LeafId(unhex32(&self.leaf_id)?),
			connector: self.connector.parse().map_err(|e| format!("connector: {}", e))?,
		})
	}
}

/// A request to the signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
	/// A struct variant, so a stray field is refused as for `rebind` (serde
	/// lets a unit variant of a tagged enum through with any fields).
	Pubkey {},
	/// A rebindable message for the leaf of `owner` (an x-only key) under
	/// `salt`, with `owner_sig`, the owner's BIP340 signature over that same
	/// message; a forfeit's names its parts.
	Rebind {
		owner: String, owner_sig: String, salt: String, asset_in: String, value_in: String, outputs: Vec<WireOutput>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		forfeit: Option<WireForfeit>,
		/// The latest entry of the signer's record the server's database
		/// knows; absent when it knows none.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		known: Option<WireEntryRef>,
	},
	/// The latest entry of the record: its number and running hash.
	Head {},
	/// The entries after entry `after`, at most `limit` of them.
	Entries { after: u64, limit: u32 },
	/// The transaction and each output its inputs spend, in Sequentia's
	/// encoding as hex; the input signed; the leaf it spends by, as hex.
	Spend { tx: String, prevouts: Vec<String>, input: u32, leaf: String },
}

/// Why the signer will not sign a spend: `Ok` when `leaf` names `operator`
/// with `OP_CHECKSIG` or `OP_CHECKSIGVERIFY`, the input exists, every input's
/// spent output is given, and the input spends a taproot output.
pub fn check_spend(operator: &XOnlyPublicKey, tx: &elements::Transaction, prevouts: &[elements::TxOut], input: usize, leaf: &Script)
	-> Result<(), String>
{
	use elements::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY};
	use elements::script::Instruction;
	if prevouts.len() != tx.input.len() {
		return Err(format!("{} spent outputs for {} inputs", prevouts.len(), tx.input.len()));
	}
	let spent = prevouts.get(input).ok_or_else(|| format!("input {} of {}", input, tx.input.len()))?;
	if !spent.script_pubkey.is_v1_p2tr() {
		return Err(format!("input {} spends no taproot output", input));
	}
	let key = operator.serialize();
	let ins: Vec<Instruction> = leaf.instructions().collect::<Result<_, _>>().map_err(|e| format!("the leaf does not parse: {}", e))?;
	let names_key = ins.windows(2).any(|w| matches!((&w[0], &w[1]),
		(Instruction::PushBytes(k), Instruction::Op(op)) if *k == key && (*op == OP_CHECKSIG || *op == OP_CHECKSIGVERIFY)));
	if !names_key {
		return Err("the leaf is not one of the operator's paths: it names no S with OP_CHECKSIG or OP_CHECKSIGVERIFY".into());
	}
	Ok(())
}

/// An entry of the record, by its number and running hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireEntryRef {
	pub entry: u64,
	pub hash: String,
}

/// An entry of the record, whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireEntry {
	pub entry: u64,
	pub kind: String,
	pub owner: String,
	pub salt: String,
	pub digest: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub connector: Option<String>,
	pub hash: String,
}

/// The most entries one `entries` request returns.
pub const MAX_ENTRIES: u32 = 1000;

/// The signer's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Response {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub pubkey: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub signature: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
	/// `already_signed` when the record holds another message for the leaf;
	/// `record_behind` or `record_differs` when the database knows a later
	/// entry, or another.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub code: Option<String>,
	/// The entry a rebindable signature was recorded as, or the record's
	/// latest.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub entry: Option<WireEntryRef>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub entries: Option<Vec<WireEntry>>,
}

/// The refusal code of a message the one-spend record does not admit.
pub const ALREADY_SIGNED: &str = "already_signed";

/// What a rebindable message the signer signed is, for its record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signed {
	/// Into anything but a forfeit output: one per salt.
	Spend,
	/// Into a forfeit output for the round whose connector asset is this.
	Forfeit([u8; 32]),
}

/// A leaf, as each entry of the record names it: its owner's key and its salt.
pub type LeafKey = ([u8; 32], [u8; 32]);

/// The first word of a record's first line.
pub const RECORD_MAGIC: &str = "arca-signer-record";
/// The record's format.
pub const RECORD_VERSION: u32 = 1;
/// The tag of the record's running hash.
pub const RECORD_TAG: &[u8] = b"Arca/signer-record";
/// The refusal code when the database knows a later entry than the record
/// holds: the record has been cut back or replaced by an older copy.
pub const RECORD_BEHIND: &str = "record_behind";
/// The refusal code when the database knows an entry the record holds
/// otherwise: another record, or one two signers wrote.
pub const RECORD_DIFFERS: &str = "record_differs";

/// `SHA256("Arca/signer-record" ‖ prev ‖ text)`: the running hash after a
/// line of the record whose text, before its own hash, is `text`; `prev` is
/// the hash before it, all zeros before the first line.
pub fn chain_hash(prev: &[u8; 32], text: &str) -> [u8; 32] {
	let mut b = RECORD_TAG.to_vec();
	b.extend(prev);
	b.extend(text.as_bytes());
	arca_covenant::script::sha256(&b)
}

/// The header of a record kept for `operator` on the chain of `genesis`.
pub fn record_header(operator: &XOnlyPublicKey, genesis: &elements::BlockHash) -> String {
	format!("{} {} {} {}", RECORD_MAGIC, RECORD_VERSION, hex(&operator.serialize()), genesis)
}

/// One message in the record: its number (from 1), what it is, the leaf it
/// is for, its digest, and the running hash after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
	pub n: u64,
	pub kind: Signed,
	pub owner: [u8; 32],
	pub salt: [u8; 32],
	pub digest: [u8; 32],
	pub hash: [u8; 32],
}

impl Entry {
	/// The line's text before its hash.
	fn text(&self) -> String {
		match self.kind {
			Signed::Spend => format!("{} spend {} {} {}", self.n, hex(&self.owner), hex(&self.salt), hex(&self.digest)),
			Signed::Forfeit(m) => format!("{} forfeit {} {} {} {}", self.n, hex(&self.owner), hex(&self.salt), hex(&self.digest), hex(&m)),
		}
	}

	pub fn to_wire(&self) -> WireEntry {
		WireEntry {
			entry: self.n,
			kind: match self.kind { Signed::Spend => "spend", Signed::Forfeit(_) => "forfeit" }.into(),
			owner: hex(&self.owner), salt: hex(&self.salt), digest: hex(&self.digest),
			connector: match self.kind { Signed::Forfeit(m) => Some(hex(&m)), Signed::Spend => None },
			hash: hex(&self.hash),
		}
	}

	pub fn from_wire(w: &WireEntry) -> Result<Entry, String> {
		Ok(Entry {
			n: w.entry,
			kind: match (w.kind.as_str(), &w.connector) {
				("spend", None) => Signed::Spend,
				("forfeit", Some(m)) => Signed::Forfeit(unhex32(m)?),
				_ => return Err(format!("an entry of kind {:?}", w.kind)),
			},
			owner: unhex32(&w.owner)?, salt: unhex32(&w.salt)?, digest: unhex32(&w.digest)?, hash: unhex32(&w.hash)?,
		})
	}
}

/// The format of a record compacted from another
/// ([`SpendRecord::compact`]): its first line also names the record it was
/// compacted from, by that record's latest entry and running hash, and how
/// many of its entries it carries over, with a hash over their lines.
pub const RECORD_VERSION_COMPACTED: u32 = 2;
/// The tag of the hash over a compacted record's carried lines.
pub const RECORD_CARRIED_TAG: &[u8] = b"Arca/signer-record-carried";

/// How many entries apart the record remembers where a line starts, to read
/// entries back from the file.
const MARK_EVERY: u64 = 1024;
/// How many of the latest entries' running hashes the record keeps at hand:
/// the entry the database knows, which every request names, is nearly always
/// one of them.
const RECENT: usize = 4096;

/// One entry as the record keeps it at hand: the first eight bytes of its
/// salt, and where its line starts in the file. Everything else is read back
/// from the line when a request needs it: the entries under a salt are few,
/// so a lookup reads one or two lines, and keeping only this lets a record of
/// millions of entries open in a few tens of megabytes. Two salts sharing
/// their first eight bytes (salts are hashes) only make a lookup read one
/// more line, which its full salt then sets apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Kept {
	salt: u64,
	at: u64,
}

fn salt_key(salt: &[u8; 32]) -> u64 {
	u64::from_le_bytes(salt[..8].try_into().expect("8 bytes"))
}

/// Whether `b` is 64 lower-case hex digits.
fn is_hex32(b: &[u8]) -> bool {
	b.len() == 64 && b.iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

/// One entry line, checked as the record is opened without decoding more
/// than it needs: its fields, its number and salt, and its running hash,
/// which must follow `prev` over the line's text as written. Returns the
/// entry's number, salt and running hash.
fn check_line(line: &[u8], prev: Option<&[u8; 32]>) -> Result<(u64, [u8; 32], [u8; 32]), String> {
	let f: Vec<&[u8]> = line.split(|b| *b == b' ').collect();
	let ok = match f.as_slice() {
		[n, kind, rest @ ..] => {
			n.iter().all(u8::is_ascii_digit) && !n.is_empty()
				&& ((*kind == b"spend" && rest.len() == 4) || (*kind == b"forfeit" && rest.len() == 5))
				&& rest.iter().all(|x| is_hex32(x))
		},
		_ => false,
	};
	if !ok {
		return Err("not a record line".into());
	}
	let n: u64 = std::str::from_utf8(f[0]).ok().and_then(|n| n.parse().ok()).ok_or("not a record line")?;
	let salt = unhex32(std::str::from_utf8(f[3]).expect("hex"))?;
	let hash = unhex32(std::str::from_utf8(f[f.len() - 1]).expect("hex"))?;
	if let Some(prev) = prev {
		let text = &line[..line.len() - 65];
		let mut e = sha256::Hash::engine();
		e.input(RECORD_TAG);
		e.input(prev);
		e.input(text);
		if sha256::Hash::from_engine(e).to_byte_array() != hash {
			return Err("its running hash does not follow from the lines before it: the record has been changed".into());
		}
	}
	Ok((n, salt, hash))
}

/// One entry line, its running hash included.
fn parse_entry(line: &str) -> Result<Entry, String> {
	let f: Vec<&str> = line.split(' ').collect();
	let n: u64 = f.first().and_then(|n| n.parse().ok()).ok_or("not a record line")?;
	let (kind, owner, salt, digest, hash) = match f.as_slice() {
		[_, "spend", o, s, d, h] => (Signed::Spend, *o, *s, *d, *h),
		[_, "forfeit", o, s, d, m, h] => (Signed::Forfeit(unhex32(m)?), *o, *s, *d, *h),
		_ => return Err("not a record line".into()),
	};
	Ok(Entry { n, kind, owner: unhex32(owner)?, salt: unhex32(salt)?, digest: unhex32(digest)?, hash: unhex32(hash)? })
}

/// Reads the line that starts at `at` in `file`, without its newline.
fn line_at(file: &std::fs::File, at: u64) -> Result<String, String> {
	use std::os::unix::fs::FileExt;
	let mut buf = vec![0u8; 512];
	let mut got = 0;
	loop {
		let n = file.read_at(&mut buf[got..], at + got as u64).map_err(|e| e.to_string())?;
		if n == 0 {
			return Err(format!("no whole line at offset {}", at));
		}
		got += n;
		if let Some(end) = buf[..got].iter().position(|b| *b == b'\n') {
			return String::from_utf8(buf[..end].to_vec()).map_err(|e| e.to_string());
		}
		if got == buf.len() {
			buf.resize(buf.len() * 2, 0);
		}
	}
}

/// The signer's append-only record of every rebindable message it signed:
/// see the [module documentation](self).
///
/// The first line names the format, the operator key and the chain:
/// `arca-signer-record 1 <S> <genesis>`. Then one line per message,
/// `<n> spend <owner> <salt> <digest> <hash>` or
/// `<n> forfeit <owner> <salt> <digest> <connector> <hash>`, numbered from 1,
/// each ending with the running hash ([`chain_hash`]) over the header and
/// every line before it, appended and synced to disk before the signature is
/// returned.
///
/// The record is read line by line when it is opened, every line checked,
/// and kept at hand only as far as a lookup needs: for each entry, the first
/// eight bytes of its salt and where its line starts, sorted; with where
/// every 1,024th line starts, and the running hashes of the latest 4,096
/// entries. The entries under a salt, and anything a request repeated or the
/// database's start check asks, are read back from the file.
///
/// A record can be compacted into a new one ([`SpendRecord::compact`]),
/// dropping the entries under salts the server no longer serves (leaves
/// whose batches have expired): the new record's first line,
/// `arca-signer-record 2 <S> <genesis> <n> <hash> <carried> <carried hash>`,
/// names the old record's latest entry and running hash, from which its own
/// entries go on, and how many lines it carries over from it, verbatim, with
/// a hash over them (`SHA256("Arca/signer-record-carried" ‖ lines)`).
///
/// The record is never made in passing: [`SpendRecord::create`] makes a new
/// one, once, and [`SpendRecord::open`] refuses a path where there is none,
/// so a lost record is not silently replaced by an empty one. The signer
/// holds an exclusive lock on the file while it runs, so two signers never
/// write one record. A write that fails is undone at once, so a torn line is
/// never followed by another; a last line left cut short by a crash was never
/// answered, and is removed when the record is opened, which says so. Any
/// other line that does not read, or whose number or running hash does not
/// follow, stops the signer from starting.
///
/// The server's database remembers the latest entry it was given; each
/// request names it ([`SpendRecord::check_known`]). A record that ends
/// before that entry has been cut back, and one whose entry there is another
/// is another record: from then on the signer signs nothing until it is
/// started again on its whole record.
pub struct SpendRecord {
	file: std::fs::File,
	/// The file's length, every line in it whole.
	size: u64,
	/// Where the first entry line starts.
	first: u64,
	/// The entry the record's own entries follow, and its running hash: 0
	/// and the header's hash, or for a compacted record the latest of the
	/// record it was compacted from.
	base: (u64, [u8; 32]),
	head: (u64, [u8; 32]),
	/// How many entries the record holds.
	count: u64,
	/// Every entry read when the record was opened, by salt.
	kept: Vec<Kept>,
	/// Every entry added since, by salt.
	added: std::collections::HashMap<u64, Vec<u64>>,
	/// `(entry, offset)` of every [`MARK_EVERY`]th entry line, from the first.
	marks: Vec<(u64, u64)>,
	/// `(entry, running hash)` of the latest entries.
	recent: std::collections::VecDeque<(u64, [u8; 32])>,
	/// Why the signer signs nothing more until it is started again.
	refusing: Option<String>,
}

impl SpendRecord {
	/// Makes a new, empty record at `path` (mode 0600) for `operator` on the
	/// chain of `genesis`, and syncs it and its directory: an act of its own,
	/// for a new operator key. It never replaces a record already there.
	pub fn create(path: &Path, operator: &XOnlyPublicKey, genesis: &elements::BlockHash) -> Result<(), String> {
		Self::write_new(path, &format!("{}\n", record_header(operator, genesis)), |_| Ok(()))
	}

	/// Writes a new file at `path` (mode 0600, refused where one is) with
	/// `header` and whatever `rest` writes, and syncs it and its directory.
	fn write_new(path: &Path, header: &str, rest: impl FnOnce(&mut std::io::BufWriter<&std::fs::File>) -> Result<(), String>)
		-> Result<(), String>
	{
		use std::io::Write;
		use std::os::unix::fs::OpenOptionsExt;
		let fail = |e: std::io::Error| format!("{}: {}", path.display(), e);
		let file = match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) {
			Ok(f) => f,
			Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
				return Err(format!("{}: a record is there already; a record is made once, and never replaced", path.display()));
			},
			Err(e) => return Err(fail(e)),
		};
		{
			let mut w = std::io::BufWriter::new(&file);
			w.write_all(header.as_bytes()).map_err(fail)?;
			rest(&mut w)?;
			w.flush().map_err(fail)?;
		}
		file.sync_all().map_err(fail)?;
		if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
			std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(fail)?;
		}
		Ok(())
	}

	/// Opens the record at `path`, kept for `operator` on the chain of
	/// `genesis`, and locks it for this process, reading it line by line.
	/// Returns it, and a note when a last line cut short was removed.
	pub fn open(path: &Path, operator: &XOnlyPublicKey, genesis: &elements::BlockHash) -> Result<(SpendRecord, Option<String>), String> {
		use std::io::{BufRead, Seek};
		let fail = |e: std::io::Error| format!("{}: {}", path.display(), e);
		let mut file = match std::fs::OpenOptions::new().read(true).append(true).open(path) {
			Ok(f) => f,
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(format!(
				"{}: there is no record here. The signer starts only on its record, whole: a record that is lost is not \
				 replaced by an empty one, since S would then sign again what it signed before. A new operator key starts \
				 with a record made once, on purpose: arca-signer --create-record", path.display())),
			Err(e) => return Err(fail(e)),
		};
		match file.try_lock() {
			Ok(()) => {},
			Err(std::fs::TryLockError::WouldBlock) => return Err(format!(
				"{}: the record is held by another signer that is running; two signers never write one record", path.display())),
			Err(std::fs::TryLockError::Error(e)) => return Err(fail(e)),
		}
		file.seek(std::io::SeekFrom::Start(0)).map_err(fail)?;
		let mut reader = std::io::BufReader::with_capacity(1 << 20, file.try_clone().map_err(fail)?);
		let mut line: Vec<u8> = Vec::with_capacity(512);
		let read = |reader: &mut std::io::BufReader<std::fs::File>, line: &mut Vec<u8>| -> Result<usize, String> {
			line.clear();
			reader.read_until(b'\n', line).map_err(fail)
		};
		let got = read(&mut reader, &mut line)?;
		if got == 0 || !line.ends_with(b"\n") {
			return Err(format!("{}: the record has no header line", path.display()));
		}
		let header = std::str::from_utf8(&line[..got - 1]).map_err(|e| format!("{}: the header: {}", path.display(), e))?.to_string();
		let f: Vec<&str> = header.split(' ').collect();
		if f.first() != Some(&RECORD_MAGIC) {
			return Err(format!("{}: the first line is not a record's header ({:?}): a record kept without one, by salt \
				alone, cannot be read by this signer", path.display(), header.chars().take(80).collect::<String>()));
		}
		let ours = record_header(operator, genesis);
		let ours: Vec<&str> = ours.split(' ').collect();
		let (base, carried) = match f.get(1).and_then(|v| v.parse::<u32>().ok()) {
			Some(RECORD_VERSION) => (None, None),
			Some(RECORD_VERSION_COMPACTED) if f.len() == 8 => {
				let n: u64 = f[4].parse().map_err(|_| format!("{}: the header's latest entry {:?}", path.display(), f[4]))?;
				let carried: u64 = f[6].parse().map_err(|_| format!("{}: the header's carried count {:?}", path.display(), f[6]))?;
				(Some((n, unhex32(f[5]).map_err(|e| format!("{}: the header: {}", path.display(), e))?)),
					Some((carried, unhex32(f[7]).map_err(|e| format!("{}: the header: {}", path.display(), e))?)))
			},
			_ => return Err(format!("{}: the record is of format {:?}; this signer reads formats {} and {}", path.display(), f.get(1),
				RECORD_VERSION, RECORD_VERSION_COMPACTED)),
		};
		if f.get(2..4) != ours.get(2..4) || (base.is_none() && f.len() != 4) {
			return Err(format!("{}: the record is kept for another operator key or another chain ({:?}); this signer holds \
				{} on {}", path.display(), header, hex(&operator.serialize()), genesis));
		}
		let base = base.unwrap_or((0, chain_hash(&[0; 32], &header)));
		let first = got as u64;
		// About 300 bytes a line: room for every entry at once.
		let lines = file.metadata().map(|m| m.len()).unwrap_or(0) / 280 + 16;
		let mut record = SpendRecord {
			file, size: first, first, base, head: base, count: 0, kept: Vec::with_capacity(lines as usize), added: Default::default(),
			marks: vec![], recent: Default::default(), refusing: None,
		};
		let mut at = first;
		let mut k = 1u64;
		// The carried lines of a compacted record: whole, numbered upwards to
		// the entry it was compacted at, their hash the header's.
		if let Some((carried, want)) = carried {
			let mut e = sha256::Hash::engine();
			e.input(RECORD_CARRIED_TAG);
			let mut last = 0u64;
			for _ in 0..carried {
				k += 1;
				let got = read(&mut reader, &mut line)?;
				let text = std::str::from_utf8(&line[..got.saturating_sub(1)]).unwrap_or("");
				let bad = |what: &str| format!("{} line {}: {}: {:?}", path.display(), k, what, text.chars().take(200).collect::<String>());
				if got == 0 || !line.ends_with(b"\n") {
					return Err(bad("a carried line is missing or cut short: the record has been changed"));
				}
				e.input(&line[..got]);
				let (n, salt, hash) = check_line(&line[..got - 1], None).map_err(|w| bad(&w))?;
				if n <= last || n > base.0 {
					return Err(bad("a carried entry out of order"));
				}
				last = n;
				record.keep(n, &salt, hash, at, false);
				at += got as u64;
			}
			if sha256::Hash::from_engine(e).to_byte_array() != want {
				return Err(format!("{}: the carried lines do not hash to the header's: the record has been changed", path.display()));
			}
		}
		let mut repaired = None;
		loop {
			k += 1;
			let got = read(&mut reader, &mut line)?;
			if got == 0 {
				break;
			}
			if !line.ends_with(b"\n") {
				// A line cut short, by a write that failed or a crash: never
				// answered, and never to be followed by another.
				let cut = String::from_utf8_lossy(&line[..got]).to_string();
				repaired = Some(format!("the record's last line was cut short, by a write that failed or a crash, and was never \
					answered: removed ({} bytes: {:?})", got, cut.chars().take(80).collect::<String>()));
				record.file.set_len(at).map_err(fail)?;
				record.file.sync_all().map_err(fail)?;
				break;
			}
			let body = &line[..got - 1];
			let bad = |what: &str| format!("{} line {}: {}: {:?}", path.display(), k, what,
				String::from_utf8_lossy(body).chars().take(200).collect::<String>());
			let (n, salt, hash) = check_line(body, Some(&record.head.1)).map_err(|w| bad(&w))?;
			if n != record.head.0 + 1 {
				return Err(bad(&format!("entry {} where entry {} follows", n, record.head.0 + 1)));
			}
			record.head = (n, hash);
			record.keep(n, &salt, hash, at, false);
			at += got as u64;
		}
		record.size = at;
		record.kept.sort_unstable();
		record.kept.shrink_to_fit();
		Ok((record, repaired))
	}

	/// Keeps entry `n` under `salt`, its running hash `hash` and its line at
	/// `at`, at hand: in the sorted entries read at opening, or among those
	/// `added` since.
	fn keep(&mut self, n: u64, salt: &[u8; 32], hash: [u8; 32], at: u64, added: bool) {
		if added {
			self.added.entry(salt_key(salt)).or_default().push(at);
		} else {
			self.kept.push(Kept { salt: salt_key(salt), at });
		}
		if self.count % MARK_EVERY == 0 {
			self.marks.push((n, at));
		}
		self.count += 1;
		self.recent.push_back((n, hash));
		if self.recent.len() > RECENT {
			self.recent.pop_front();
		}
	}

	/// Every entry under `salt`, read back from the file.
	fn under(&self, salt: &[u8; 32]) -> Result<Vec<Entry>, String> {
		let key = salt_key(salt);
		let from = self.kept.partition_point(|k| k.salt < key);
		let mut at: Vec<u64> = self.kept[from..].iter().take_while(|k| k.salt == key).map(|k| k.at).collect();
		at.extend(self.added.get(&key).into_iter().flatten());
		let mut out = vec![];
		for a in at {
			let e = self.entry_at(a)?;
			if e.salt == *salt {
				out.push(e);
			}
		}
		Ok(out)
	}

	/// The entry whose line starts at `at`.
	fn entry_at(&self, at: u64) -> Result<Entry, String> {
		parse_entry(&line_at(&self.file, at)?)
	}

	/// Calls `f` with each entry line from `from` on (its text, its entry and
	/// where it starts) until `f` says stop.
	fn each_from(&self, from: u64, mut f: impl FnMut(&str, Entry, u64) -> Result<bool, String>) -> Result<(), String> {
		use std::io::{BufRead, Seek};
		let mut file = self.file.try_clone().map_err(|e| e.to_string())?;
		file.seek(std::io::SeekFrom::Start(from)).map_err(|e| e.to_string())?;
		let mut reader = std::io::BufReader::with_capacity(1 << 20, file);
		let mut line = String::with_capacity(512);
		let mut at = from;
		while at < self.size {
			line.clear();
			let got = reader.read_line(&mut line).map_err(|e| e.to_string())?;
			if got == 0 {
				break;
			}
			let text = line.trim_end_matches('\n');
			if !f(text, parse_entry(text)?, at)? {
				break;
			}
			at += got as u64;
		}
		Ok(())
	}

	/// How many messages the record holds.
	pub fn len(&self) -> usize {
		self.count as usize
	}

	pub fn is_empty(&self) -> bool {
		self.count == 0
	}

	/// The latest entry's number and running hash: 0 and the header's hash
	/// for a record that holds none, and for a compacted record that has
	/// added none, the latest of the record it was compacted from.
	pub fn head(&self) -> (u64, [u8; 32]) {
		self.head
	}

	/// The entries after entry `after`, at most `limit` of them, read back
	/// from the file.
	pub fn entries_after(&self, after: u64, limit: usize) -> Result<Vec<Entry>, String> {
		let mut out = vec![];
		if limit == 0 || after >= self.head.0 {
			return Ok(out);
		}
		let i = self.marks.partition_point(|(n, _)| *n <= after);
		let from = if i == 0 { self.first } else { self.marks[i - 1].1 };
		self.each_from(from, |_, e, _| {
			if e.n > after {
				out.push(e);
			}
			Ok(out.len() < limit)
		})?;
		Ok(out)
	}

	/// The running hash of entry `n`, when the record holds it.
	fn hash_of(&self, n: u64) -> Result<Option<[u8; 32]>, String> {
		if n == self.base.0 {
			return Ok(Some(self.base.1));
		}
		if let Ok(i) = self.recent.binary_search_by_key(&n, |(m, _)| *m) {
			return Ok(Some(self.recent[i].1));
		}
		let i = self.marks.partition_point(|(m, _)| *m <= n);
		if i == 0 {
			return Ok(None);
		}
		let mut found = None;
		self.each_from(self.marks[i - 1].1, |_, e, _| {
			if e.n == n {
				found = Some(e.hash);
			}
			Ok(e.n < n)
		})?;
		Ok(found)
	}

	/// Why the signer signs nothing more, if it does not.
	pub fn refusing(&self) -> Option<&str> {
		self.refusing.as_deref()
	}

	/// Checks the latest entry the server's database knows, entry `n` with
	/// running hash `hash` (`n` 0 when it knows none): the record must hold
	/// it, the same. When it does not, the signer signs nothing more until it
	/// is started again.
	pub fn check_known(&mut self, n: u64, hash: &[u8; 32]) -> Result<(), String> {
		if let Some(why) = &self.refusing {
			return Err(why.clone());
		}
		if n == 0 {
			return Ok(());
		}
		let held = self.head.0;
		if n > held {
			self.refusing = Some(format!(
				"{}: the database knows entry {} of the signer's record, and the record ends at entry {}: it has been cut \
				 back or replaced by an older copy; nothing is signed until the signer runs on its whole record", RECORD_BEHIND, n, held));
		} else {
			match self.hash_of(n) {
				Ok(Some(h)) if h == *hash => {},
				Ok(Some(h)) => self.refusing = Some(format!(
					"{}: entry {} of the signer's record is not the one the database knows (its running hash is {}, the database's \
					 {}): this is another record, or one two signers wrote; nothing is signed", RECORD_DIFFERS, n, hex(&h), hex(hash))),
				Ok(None) => self.refusing = Some(format!(
					"{}: the database knows entry {} of the signer's record, which this record does not hold: compacted away, \
					 so the database is older than the compaction, or this is another record; nothing is signed", RECORD_DIFFERS, n)),
				Err(e) => return Err(format!("the record could not be read: {}", e)),
			}
		}
		match &self.refusing {
			Some(why) => Err(why.clone()),
			None => Ok(()),
		}
	}

	/// Whether `S` may sign `digest`, a message of `kind` for the leaf of
	/// `owner` under `salt`: when it may, the message is in the record, on
	/// disk, before this returns, and its entry is returned. The rule is the
	/// salt's: `S`'s signature commits to the salt and not to the owner, so
	/// what was signed for another leaf under the same salt counts here. The
	/// same message again under the salt is the entry already recorded; a
	/// spend is refused when any entry under the salt carries another
	/// message; a forfeit when the salt has a spend, or a forfeit for the
	/// same round with another message.
	pub fn admit(&mut self, owner: &[u8; 32], salt: &[u8; 32], kind: Signed, digest: &[u8; 32]) -> Result<Entry, String> {
		use std::io::Write;
		if let Some(why) = &self.refusing {
			return Err(why.clone());
		}
		let had = self.under(salt).map_err(|e| format!("the record could not be read: {}", e))?;
		if let Some(e) = had.iter().find(|e| e.kind == kind && e.digest == *digest) {
			return Ok(*e);
		}
		for e in &had {
			let clash = match (kind, e.kind) {
				(Signed::Spend, _) => e.digest != *digest,
				(Signed::Forfeit(_), Signed::Spend) => true,
				(Signed::Forfeit(m), Signed::Forfeit(n)) => m == n && e.digest != *digest,
			};
			if clash {
				return Err(format!(
					"{}: S has already co-signed {} {} under salt {} (entry {}, for the leaf of {}); the signer co-signs one \
					 spend under a salt, or its forfeits, one for each round, since its signature commits to the salt and \
					 not to the owner",
					ALREADY_SIGNED, match e.kind { Signed::Spend => "the spend", Signed::Forfeit(_) => "the forfeit" }, hex(&e.digest),
					hex(salt), e.n, hex(&e.owner),
				));
			}
		}
		let (n, prev) = self.head;
		let mut e = Entry { n: n + 1, kind, owner: *owner, salt: *salt, digest: *digest, hash: [0; 32] };
		e.hash = chain_hash(&prev, &e.text());
		let line = format!("{} {}\n", e.text(), hex(&e.hash));
		if let Err(error) = self.file.write_all(line.as_bytes()).and_then(|_| self.file.sync_data()) {
			// Undone at once: a line cut short is never followed by another.
			return match self.file.set_len(self.size).and_then(|_| self.file.sync_data()) {
				Ok(()) => Err(format!("the record could not be written, so nothing is signed: {}; the line cut short was removed", error)),
				Err(again) => {
					let why = format!("the record could not be written ({}), nor the line cut short removed ({}): nothing is \
						signed until the signer is started again, which removes it", error, again);
					self.refusing = Some(why.clone());
					Err(why)
				},
			};
		}
		let at = self.size;
		self.size += line.len() as u64;
		self.head = (e.n, e.hash);
		self.keep(e.n, &e.salt, e.hash, at, true);
		Ok(e)
	}

	/// Compacts the record at `from` (kept for `operator` on the chain of
	/// `genesis`, and locked while this runs, so its signer is stopped) into a
	/// new record at `into`, dropping every entry under a salt of `drop`: the
	/// salts of leaves whose batches have expired, which the server no longer
	/// serves (`arcad <config> expired-salts`). The new record's first line
	/// names the old record's latest entry and running hash, from which its
	/// own entries go on, so the server's database, which knows that entry,
	/// knows the new record; it carries every other entry's line over
	/// verbatim. Returns how many entries it carried and dropped, and the
	/// entry the new record goes on from.
	pub fn compact(from: &Path, into: &Path, operator: &XOnlyPublicKey, genesis: &elements::BlockHash,
		drop: &std::collections::HashSet<[u8; 32]>) -> Result<(u64, u64, (u64, [u8; 32])), String>
	{
		use std::io::Write;
		let (old, repaired) = Self::open(from, operator, genesis)?;
		if let Some(note) = repaired {
			return Err(format!("{}: {}; open it with the signer first", from.display(), note));
		}
		let (mut carried, mut dropped) = (0u64, 0u64);
		let mut e = sha256::Hash::engine();
		e.input(RECORD_CARRIED_TAG);
		old.each_from(old.first, |text, entry, _| {
			if drop.contains(&entry.salt) {
				dropped += 1;
			} else {
				carried += 1;
				e.input(text.as_bytes());
				e.input(b"\n");
			}
			Ok(true)
		})?;
		let carried_hash = sha256::Hash::from_engine(e).to_byte_array();
		let base = old.head();
		let header = format!("{} {} {} {} {} {} {} {}\n", RECORD_MAGIC, RECORD_VERSION_COMPACTED, hex(&operator.serialize()), genesis,
			base.0, hex(&base.1), carried, hex(&carried_hash));
		Self::write_new(into, &header, |w| {
			old.each_from(old.first, |text, entry, _| {
				if !drop.contains(&entry.salt) {
					w.write_all(text.as_bytes()).and_then(|_| w.write_all(b"\n")).map_err(|e| format!("{}: {}", into.display(), e))?;
				}
				Ok(true)
			})
		})?;
		Ok((carried, dropped, base))
	}
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum SignerError {
	#[error("cannot reach the signer at {path}: {error}")]
	Unreachable { path: String, error: String },
	#[error("the signer refused: {0}")]
	Refused(String),
	/// The one-spend record holds another message for the leaf.
	#[error("the signer refused: {0}")]
	AlreadySigned(String),
	/// The database knows a later entry of the signer's record than the
	/// record holds, or another: the signer signs nothing until it runs on
	/// its whole record.
	#[error("the signer refused: {0}")]
	Record(String),
	/// The server's database, asked for the latest entry it knows or told a
	/// new one.
	#[error("the database, about the signer's record: {0}")]
	Database(String),
	#[error("the signer's answer is not understood: {0}")]
	Answer(String),
}

pub fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
	if !s.len().is_multiple_of(2) || !s.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
		return Err(format!("not lower-case hex: {:?}", s.chars().take(80).collect::<String>()));
	}
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string())).collect()
}

pub fn unhex32(s: &str) -> Result<[u8; 32], String> {
	unhex(s)?.try_into().map_err(|v: Vec<u8>| format!("{} bytes where 32 are needed", v.len()))
}

/// A decimal amount: digits only, no sign, no leading zero, fitting in u64.
pub fn parse_amount(s: &str) -> Result<u64, String> {
	if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
		return Err(format!("not a decimal amount: {:?}", s.chars().take(40).collect::<String>()));
	}
	s.parse().map_err(|e| format!("amount {}: {}", s, e))
}

/// The server's end of the signer's socket. With the server's database
/// beside it ([`SignerClient::with_store`]), every rebind request names the
/// latest entry of the signer's record the database knows, and the entry
/// each signature was recorded as is remembered there.
#[derive(Clone)]
pub struct SignerClient {
	path: PathBuf,
	store: Option<crate::store::Store>,
}

impl std::fmt::Debug for SignerClient {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SignerClient").field("path", &self.path).finish()
	}
}

impl SignerClient {
	pub fn new(path: impl AsRef<Path>) -> SignerClient {
		SignerClient { path: path.as_ref().to_path_buf(), store: None }
	}

	/// The same signer, with the server's database remembering its record's
	/// latest entry.
	pub fn with_store(mut self, store: crate::store::Store) -> SignerClient {
		self.store = Some(store);
		self
	}

	async fn ask(&self, req: &Request) -> Result<Response, SignerError> {
		let unreachable = |e: std::io::Error| SignerError::Unreachable { path: self.path.display().to_string(), error: e.to_string() };
		let mut stream = UnixStream::connect(&self.path).await.map_err(unreachable)?;
		let mut line = serde_json::to_string(req).map_err(|e| SignerError::Answer(e.to_string()))?;
		line.push('\n');
		stream.write_all(line.as_bytes()).await.map_err(unreachable)?;
		let mut reader = BufReader::new(stream);
		let mut answer = String::new();
		reader.read_line(&mut answer).await.map_err(unreachable)?;
		let r: Response = serde_json::from_str(&answer).map_err(|e| SignerError::Answer(format!("{}: {:?}", e, answer)))?;
		if let Some(e) = r.error {
			return Err(match r.code.as_deref() {
				Some(ALREADY_SIGNED) => SignerError::AlreadySigned(e),
				Some(RECORD_BEHIND) | Some(RECORD_DIFFERS) => SignerError::Record(e),
				_ => SignerError::Refused(e),
			});
		}
		Ok(r)
	}

	/// The latest entry of the signer's record: its number and running hash.
	pub async fn head(&self) -> Result<(u64, [u8; 32]), SignerError> {
		let r = self.ask(&Request::Head {}).await?;
		let e = r.entry.ok_or_else(|| SignerError::Answer("no entry".into()))?;
		Ok((e.entry, unhex32(&e.hash).map_err(SignerError::Answer)?))
	}

	/// The entries of the signer's record after entry `after`, at most
	/// [`MAX_ENTRIES`].
	pub async fn entries(&self, after: u64) -> Result<Vec<Entry>, SignerError> {
		let r = self.ask(&Request::Entries { after, limit: MAX_ENTRIES }).await?;
		r.entries.unwrap_or_default().iter().map(Entry::from_wire).collect::<Result<_, _>>().map_err(SignerError::Answer)
	}

	/// The operator key `S`.
	pub async fn pubkey(&self) -> Result<XOnlyPublicKey, SignerError> {
		let r = self.ask(&Request::Pubkey {}).await?;
		let k = r.pubkey.ok_or_else(|| SignerError::Answer("no key".into()))?;
		XOnlyPublicKey::from_slice(&unhex(&k).map_err(SignerError::Answer)?).map_err(|e| SignerError::Answer(e.to_string()))
	}

	/// `S`'s signature over the rebindable message of the leaf of `owner`
	/// under `salt`, spending a coin of `value_in` of `asset_in` into
	/// `outputs`; `owner_sig` is the owner's signature over that message.
	pub async fn rebind(&self, owner: &XOnlyPublicKey, owner_sig: &Signature, salt: &[u8; 32], asset_in: AssetId, value_in: u64,
		outputs: &[ExplicitOutput]) -> Result<Signature, SignerError>
	{
		self.rebind_as(owner, owner_sig, salt, asset_in, value_in, outputs, None).await
	}

	/// `S`'s signature over the rebindable message of the leaf of `owner`
	/// under `salt`, spending a coin of `value_in` of `asset_in` into
	/// `output`, the forfeit output of `forfeit`: the signer records it as a
	/// forfeit for its round. `owner_sig` is the owner's forfeit signature.
	#[allow(clippy::too_many_arguments)]
	pub async fn rebind_forfeit(&self, owner: &XOnlyPublicKey, owner_sig: &Signature, salt: &[u8; 32], asset_in: AssetId, value_in: u64,
		forfeit: &ForfeitPolicy, output: &ExplicitOutput) -> Result<Signature, SignerError>
	{
		self.rebind_as(owner, owner_sig, salt, asset_in, value_in, std::slice::from_ref(output), Some(WireForfeit::from_policy(forfeit))).await
	}

	#[allow(clippy::too_many_arguments)]
	async fn rebind_as(&self, owner: &XOnlyPublicKey, owner_sig: &Signature, salt: &[u8; 32], asset_in: AssetId, value_in: u64,
		outputs: &[ExplicitOutput], forfeit: Option<WireForfeit>) -> Result<Signature, SignerError>
	{
		let known = match &self.store {
			Some(store) => store.signer_head().await.map_err(|e| SignerError::Database(e.to_string()))?
				.map(|(entry, hash)| WireEntryRef { entry, hash: hex(&hash) }),
			None => None,
		};
		let r = self.ask(&Request::Rebind {
			owner: hex(&owner.serialize()), owner_sig: hex(owner_sig.as_ref()), salt: hex(salt), asset_in: asset_in.to_string(),
			value_in: value_in.to_string(), outputs: outputs.iter().map(WireOutput::from_output).collect(), forfeit, known,
		}).await?;
		if let (Some(store), Some(e)) = (&self.store, &r.entry) {
			let hash = unhex32(&e.hash).map_err(SignerError::Answer)?;
			store.set_signer_head(e.entry, &hash).await.map_err(|e| SignerError::Database(e.to_string()))?;
		}
		let s = r.signature.ok_or_else(|| SignerError::Answer("no signature".into()))?;
		Signature::from_slice(&unhex(&s).map_err(SignerError::Answer)?).map_err(|e| SignerError::Answer(e.to_string()))
	}

	/// `S`'s signature over the spend of input `input` of `tx` by `leaf`,
	/// `prevouts` the outputs every input spends. The transaction goes without
	/// its witnesses, which the signature hash does not cover.
	pub async fn spend(&self, tx: &elements::Transaction, prevouts: &[elements::TxOut], input: usize, leaf: &Script)
		-> Result<Signature, SignerError>
	{
		let mut bare = tx.clone();
		for i in &mut bare.input {
			i.witness = Default::default();
		}
		let r = self.ask(&Request::Spend {
			tx: hex(&elements::encode::serialize(&bare)),
			prevouts: prevouts.iter().map(|p| hex(&elements::encode::serialize(p))).collect(),
			input: input as u32,
			leaf: hex(leaf.as_bytes()),
		}).await?;
		let s = r.signature.ok_or_else(|| SignerError::Answer("no signature".into()))?;
		Signature::from_slice(&unhex(&s).map_err(SignerError::Answer)?).map_err(|e| SignerError::Answer(e.to_string()))
	}
}
