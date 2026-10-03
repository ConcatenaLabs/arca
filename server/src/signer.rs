//! The operator key `S`, behind a narrow interface in a process of its own.
//!
//! The server never holds `S`. The signer (`arca-signer`) loads it, listens on
//! a Unix socket, and answers three requests, one JSON object per line:
//!
//! - `{"op":"pubkey"}`: the x-only key `S`;
//! - `{"op":"rebind","owner":…,"owner_sig":…,"salt":…,"asset_in":…,"value_in":…,"outputs":[…]}`:
//!   `S`'s signature over the rebindable message of a collaborative path,
//!   which the signer builds itself from the parts, on its own chain:
//!   `SHA256(K ‖ asset_in ‖ 0x01 ‖ 0x01 ‖ value_in ‖ m ‖ SHA256(record 0) ‖ …)`
//!   with `K = SHA256(SHA256("ArcaRbd1" ‖ genesis) ‖ salt)`, for 1 to 4
//!   committed outputs;
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
//! ([`SpendRecord`]); it reads the whole record when it starts. The record is
//! kept per leaf: a leaf is its owner's key together with its salt (a leaf's,
//! a board's or a checkpoint's, whose owner is its coin's). For each leaf it
//! then signs:
//!
//! - one **spend**: a message into anything but a forfeit output (a leaf
//!   into its checkpoint, a checkpoint into its reassignment). A second spend
//!   message for the leaf is refused (`already_signed`), whatever the
//!   database says; the same message again is signed again, so a request
//!   repeated after a signer outage completes;
//! - or any number of **forfeits**, one for each round's connector asset `M`:
//!   a leaf given up in a round, and again forfeit-first in a later round
//!   after the first could never return. A forfeit is a rebind request that
//!   names the forfeit's parts (`forfeit`), from which the signer rebuilds
//!   the forfeit output and checks it is the one output committed to; it is
//!   refused once the leaf has a spend, and a second forfeit message for the
//!   same `M` is refused. A spend is refused once the leaf has a forfeit.
//!
//! Every rebind request names the leaf's owner key and carries the owner's
//! own signature over the very message `S` is to sign (the checkpoint, the
//! reassignment or the forfeit each needs both), and the signer checks it
//! before it records anything: an entry under a key is always the holder of
//! that key's doing. So nothing one holder sends changes what `S` will sign
//! for another holder's leaf, even under a salt the two leaves share (the
//! server refuses a second leaf under a salt it knows, but a database
//! restored from an older copy, or a new one, has forgotten which salts it
//! saw).
//!
//! So a database restored from an older copy, which no longer knows a
//! transfer it co-signed, cannot have `S` co-sign a second spend of the same
//! coin: the record outlives it.
//!
//! Amounts are decimal strings, asset ids in display order, everything else
//! hex.

use std::path::{Path, PathBuf};

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
	},
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
	/// `already_signed` when the record holds another message for the leaf.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub code: Option<String>,
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

/// A leaf, as the record keys it: its owner's key and its salt.
pub type LeafKey = ([u8; 32], [u8; 32]);

/// The signer's append-only record of every rebindable message it signed:
/// see the [module documentation](self).
///
/// One line per message, `spend <owner> <salt> <digest>` or
/// `forfeit <owner> <salt> <digest> <connector>`, hex, appended and synced to
/// disk before the signature is returned. A last line cut short by a crash
/// was never answered, and is dropped when the record is opened; any other
/// line that does not read stops the signer from starting.
pub struct SpendRecord {
	file: std::fs::File,
	by_leaf: std::collections::HashMap<LeafKey, Vec<(Signed, [u8; 32])>>,
}

impl SpendRecord {
	/// Opens the record at `path`, creating it (mode 0600) when absent.
	pub fn open(path: &Path) -> Result<SpendRecord, String> {
		use std::io::{Read, Seek, Write};
		use std::os::unix::fs::OpenOptionsExt;
		let fail = |e: std::io::Error| format!("{}: {}", path.display(), e);
		let created = !path.exists();
		let mut file = std::fs::OpenOptions::new().read(true).append(true).create(true).mode(0o600).open(path).map_err(fail)?;
		if created {
			if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
				std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(fail)?;
			}
		}
		let mut text = String::new();
		file.seek(std::io::SeekFrom::Start(0)).map_err(fail)?;
		file.read_to_string(&mut text).map_err(fail)?;
		let whole = match text.rfind('\n') {
			Some(i) => i + 1,
			None => 0,
		};
		if whole < text.len() {
			// A line cut short: never answered.
			file.set_len(whole as u64).map_err(fail)?;
			file.sync_all().map_err(fail)?;
		}
		let mut by_leaf: std::collections::HashMap<LeafKey, Vec<(Signed, [u8; 32])>> = Default::default();
		for (n, line) in text[..whole].lines().enumerate() {
			let bad = |what: &str| format!("{} line {}: {}: {:?}", path.display(), n + 1, what, line);
			let f: Vec<&str> = line.split(' ').collect();
			let (kind, owner, salt, digest) = match f.as_slice() {
				["spend", o, s, d] => (Signed::Spend, *o, *s, *d),
				["forfeit", o, s, d, m] => (Signed::Forfeit(unhex32(m).map_err(|e| bad(&e))?), *o, *s, *d),
				["spend", _, _] | ["forfeit", _, _, _] => return Err(bad(
					"a line of a record kept by salt alone, which names no owner key: this signer keeps its record per leaf \
					 and cannot read it")),
				_ => return Err(bad("not a record line")),
			};
			let leaf = (unhex32(owner).map_err(|e| bad(&e))?, unhex32(salt).map_err(|e| bad(&e))?);
			by_leaf.entry(leaf).or_default().push((kind, unhex32(digest).map_err(|e| bad(&e))?));
		}
		let _ = file.flush();
		Ok(SpendRecord { file, by_leaf })
	}

	/// How many messages the record holds.
	pub fn len(&self) -> usize {
		self.by_leaf.values().map(|v| v.len()).sum()
	}

	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Whether `S` may sign `digest`, a message of `kind` for the leaf of
	/// `owner` under `salt`: when it may, the message is in the record, on
	/// disk, before this returns. Another leaf under the same salt is
	/// another leaf: what was signed for it does not count here.
	pub fn admit(&mut self, owner: &[u8; 32], salt: &[u8; 32], kind: Signed, digest: &[u8; 32]) -> Result<(), String> {
		use std::io::Write;
		let leaf = (*owner, *salt);
		let had = self.by_leaf.get(&leaf).map(|v| v.as_slice()).unwrap_or(&[]);
		if had.iter().any(|(k, d)| *k == kind && d == digest) {
			return Ok(());
		}
		for (k, d) in had {
			let clash = match (kind, k) {
				(Signed::Spend, _) | (Signed::Forfeit(_), Signed::Spend) => true,
				(Signed::Forfeit(m), Signed::Forfeit(n)) => m == *n,
			};
			if clash {
				return Err(format!(
					"{}: S has already co-signed {} {} for the leaf of {} under salt {}; the signer co-signs one spend of an \
					 output, or its forfeits, one for each round",
					ALREADY_SIGNED, match k { Signed::Spend => "the spend", Signed::Forfeit(_) => "the forfeit" }, hex(d),
					hex(owner), hex(salt),
				));
			}
		}
		let line = match kind {
			Signed::Spend => format!("spend {} {} {}\n", hex(owner), hex(salt), hex(digest)),
			Signed::Forfeit(m) => format!("forfeit {} {} {} {}\n", hex(owner), hex(salt), hex(digest), hex(&m)),
		};
		self.file.write_all(line.as_bytes()).and_then(|_| self.file.sync_data())
			.map_err(|e| format!("the record could not be written, so nothing is signed: {}", e))?;
		self.by_leaf.entry(leaf).or_default().push((kind, *digest));
		Ok(())
	}
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum SignerError {
	#[error("cannot reach the signer at {path}: {error}")]
	Unreachable { path: String, error: String },
	#[error("the signer refused: {0}")]
	Refused(String),
	/// The one-spend record holds another message for the salt.
	#[error("the signer refused: {0}")]
	AlreadySigned(String),
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

/// The server's end of the signer's socket.
#[derive(Debug, Clone)]
pub struct SignerClient {
	path: PathBuf,
}

impl SignerClient {
	pub fn new(path: impl AsRef<Path>) -> SignerClient {
		SignerClient { path: path.as_ref().to_path_buf() }
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
			if r.code.as_deref() == Some(ALREADY_SIGNED) {
				return Err(SignerError::AlreadySigned(e));
			}
			return Err(SignerError::Refused(e));
		}
		Ok(r)
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
		let r = self.ask(&Request::Rebind {
			owner: hex(&owner.serialize()), owner_sig: hex(owner_sig.as_ref()), salt: hex(salt), asset_in: asset_in.to_string(),
			value_in: value_in.to_string(), outputs: outputs.iter().map(WireOutput::from_output).collect(), forfeit,
		}).await?;
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
