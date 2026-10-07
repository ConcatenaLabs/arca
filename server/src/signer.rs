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
//!   latest entry, signed ([`record_head_digest`]), and its entries after
//!   one, for the server to check its database against at start;
//! - `{"op":"under","salt":…}`: the record's entries under a salt, for the
//!   server to refuse a coin to a refresh whose forfeit the signer could not
//!   co-sign, or would co-sign beside one it holds already;
//! - `{"op":"witness","heads":[{"entry":…,"hash":…,"signature":…},…],"nonce":…}`:
//!   the running hash at each entry named, each signed as a head
//!   ([`record_head_digest`]); the record's latest entry, signed as a head
//!   (none once stopped); and, when the request carries a nonce (32 bytes,
//!   fresh for each call), the record's latest entry signed together with it
//!   ([`record_end_digest`]), so an older head replayed cannot pass for the
//!   record's end. A head among them that carries `S`'s signature and that
//!   the record does not hold (an entry past its end, or another hash at
//!   that entry) is proof the record was rolled back or replaced: the signer
//!   writes it beside the record and signs nothing the record governs from
//!   then on ([`SpendRecord::witness`]); a stopped signer answers with that
//!   proof and the head its record holds at the proof's entry, signed;
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
//!   a leaf given up in a round, and again in a later round after the first
//!   could never return. A forfeit is a rebind request that
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
//! # The signed head, witnessed
//!
//! Every head of the record the signer hands out, `(entry, running hash)`, is
//! signed with `S` over `SHA256(T ‖ T ‖ genesis ‖ entry ‖ hash)`,
//! `T = SHA256("Arca/record-head")`, the entry eight bytes little-endian
//! ([`record_head_digest`]), and only for an entry on disk: the latest, after
//! a message is recorded and synced, or an earlier one the record holds.
//! Wallets keep these heads and hand them back on every contact (`witness`).
//! A signed head the record does not hold can only come from a record that
//! was rolled back or replaced, since the signer signed it: the signer then
//! writes the head and why beside its record (`<record>.stopped`) and refuses
//! every rebindable message and every signed head from then on, across
//! restarts, until the operator removes that file by an explicit command
//! (`arca-signer --clear-stopped`). It still signs the spends of the
//! operator's own paths (a claim, a sweep), which the record does not
//! govern and which hold no holder's coin. A head without `S`'s valid
//! signature, of another chain, or that the record holds, stops nothing; so
//! does a head the record knows only by its number, from before a
//! compaction that kept no hash for it.
//!
//! The record cannot be lost, cut back, torn or shared without the signer
//! noticing ([`SpendRecord`]): it is made once, on purpose, never in passing;
//! every entry carries its number and a running hash, and the server's
//! database remembers the latest it was given, which every request names, so
//! a record cut back or replaced stops the signer signing; a write that fails
//! is undone, and a line cut short by a crash removed at start; and the
//! signer locks the record while it runs.
//!
//! # The record's keepers
//!
//! The keepers ([`crate::keeper`]) are part of the operator's identity: the
//! record names them in its first line when it is made, their keys and how
//! many must hold a head ([`RecordKeepers`]), or says it has none, and that
//! set is the record's for its whole life. The signer serves only with it:
//! its command line says only where each keeper is reached. A changed set,
//! or keepers for an operator that had none, is a new operator: a new key
//! and a new record. A record of format 1 to 3, made before records named
//! their keepers, is a record without keepers.
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
	/// The latest entry of the record: its number and running hash, signed.
	Head {},
	/// Heads a wallet holds, each with the signature it was handed out with:
	/// the running hash at each entry, signed, and the latest entry, signed
	/// as a head and, with the wallet's fresh `nonce` (32 bytes, hex), as the
	/// record's end.
	Witness {
		heads: Vec<WireEntryRef>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		nonce: Option<String>,
	},
	/// The entries after entry `after`, at most `limit` of them.
	Entries { after: u64, limit: u32 },
	/// The entries under `salt` (32 bytes, hex), whatever their owner: what
	/// the record holds of a leaf of that salt, a spend or forfeits.
	Under { salt: String },
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

/// An entry of the record, by its number and running hash; with `S`'s
/// signature over it ([`record_head_digest`]) when the signer hands it out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireEntryRef {
	pub entry: u64,
	pub hash: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub signature: Option<String>,
}

/// The running hash the record holds at an entry: `None` past its end, or for
/// an entry a compaction kept no hash of; with `S`'s signature over it as a
/// head ([`record_head_digest`]) when there is one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireEntryHash {
	pub entry: u64,
	pub hash: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub signature: Option<String>,
}

/// What a stopped signer shows of why it stopped: the head it was handed
/// that its record does not hold, with `S`'s signature as it was handed
/// over, and the head its record holds at that entry, signed, when it holds
/// one there (another hash). When it holds none there (the head lies past
/// the record's end), the record's end signed with the asker's nonce shows
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireStopProof {
	pub head: WireEntryRef,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub held: Option<WireEntryRef>,
}

/// The most heads one `witness` request names.
pub const MAX_WITNESS: usize = 32;

/// The most heads without `S`'s valid signature one `witness` request
/// names: each is looked up all the same (a wallet may hold one from before
/// heads were signed), and none can prove anything.
pub const MAX_UNSIGNED_WITNESS: usize = 4;

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
	/// The running hash at each entry a `witness` request named, in order.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub hashes: Option<Vec<WireEntryHash>>,
	/// Why the signer signs nothing the record governs: a proven rollback.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub stopped: Option<String>,
	/// The record's latest entry, signed with the nonce a witness carried
	/// ([`record_end_digest`]).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub end: Option<WireEntryRef>,
	/// The proof a stopped signer stopped on.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub proof: Option<WireStopProof>,
	/// The keepers' acknowledgements of `entry`, the head handed out: each
	/// keeper's signature over it ([`crate::keeper::ack_digest`]).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub acks: Option<Vec<crate::keeper::WireAck>>,
	/// The keepers the signer hands every head to, and how many must hold
	/// one before it is answered (`pubkey`'s answer).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub keepers: Option<WireKeepers>,
}

/// The keepers a signer hands every head to before it answers an entry
/// ([`crate::keeper`]): their keys, and how many must acknowledge a head.
/// None and 0 for a signer with no keeper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct WireKeepers {
	pub keys: Vec<String>,
	pub required: u32,
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
/// The record's first format, which names no keepers: a record of it is a
/// record without keepers. Read, never written.
pub const RECORD_VERSION: u32 = 1;
/// The record's format: its first line names its keepers
/// ([`RecordKeepers`]), and a compacted record's first line goes on as
/// [`RECORD_VERSION_HASHES`]'s.
pub const RECORD_VERSION_KEEPERS: u32 = 4;

/// The keepers a record names in its first line, fixed when it is made: each
/// keeper's own key and how many of them must hold a head before the signer
/// answers an entry. No keys and 0 for a record without keepers, which never
/// gains any.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecordKeepers {
	pub keys: Vec<XOnlyPublicKey>,
	pub required: usize,
}

impl RecordKeepers {
	/// The keepers `keys`, `required` of them to hold every head: at least
	/// one keeper, no key twice, from 1 to all of them required.
	pub fn new(keys: Vec<XOnlyPublicKey>, required: usize) -> Result<RecordKeepers, String> {
		if keys.is_empty() {
			return Err("a record with keepers names at least one".into());
		}
		if keys.iter().enumerate().any(|(i, k)| keys[..i].contains(k)) {
			return Err("a keeper's key named twice".into());
		}
		if required == 0 || required > keys.len() {
			return Err(format!("{} keepers required: from 1 to the {} keepers named", required, keys.len()));
		}
		Ok(RecordKeepers { keys, required })
	}

	/// Whether the record has no keepers.
	pub fn is_none(&self) -> bool {
		self.keys.is_empty()
	}

	/// The field of the record's first line that names them:
	/// `keepers=none`, or `keepers=<required>:<key>,<key>,…`.
	pub fn field(&self) -> String {
		if self.keys.is_empty() {
			return "keepers=none".into();
		}
		format!("keepers={}:{}", self.required, self.keys.iter().map(|k| hex(&k.serialize())).collect::<Vec<_>>().join(","))
	}

	/// Reads [`Self::field`] back.
	pub fn from_field(field: &str) -> Result<RecordKeepers, String> {
		let v = field.strip_prefix("keepers=").ok_or_else(|| format!("{:?} does not name the record's keepers", field))?;
		if v == "none" {
			return Ok(RecordKeepers::default());
		}
		let (required, keys) = v.split_once(':').ok_or_else(|| format!("keepers {:?}: <required>:<key>,…", v))?;
		let required: usize = required.parse().map_err(|_| format!("keepers {:?}: the number required", v))?;
		let keys = keys.split(',').map(|k| unhex32(k).and_then(|b| XOnlyPublicKey::from_slice(&b).map_err(|e| format!("{}: {}", k, e))))
			.collect::<Result<Vec<_>, _>>().map_err(|e| format!("keepers: a key {}", e))?;
		RecordKeepers::new(keys, required)
	}

	/// For people: `none`, or `<required> of <key>, <key>, …`.
	pub fn describe(&self) -> String {
		if self.keys.is_empty() {
			return "none".into();
		}
		format!("{} of {}", self.required, self.keys.iter().map(|k| hex(&k.serialize())).collect::<Vec<_>>().join(", "))
	}
}
/// The tag of the record's running hash.
pub const RECORD_TAG: &[u8] = b"Arca/signer-record";
/// The refusal code when the database knows a later entry than the record
/// holds: the record has been cut back or replaced by an older copy.
pub const RECORD_BEHIND: &str = "record_behind";
/// The refusal code when the database knows an entry the record holds
/// otherwise: another record, or one two signers wrote.
pub const RECORD_DIFFERS: &str = "record_differs";
/// The refusal code of a signer stopped by a proven rollback of its record.
pub const STOPPED: &str = "stopped";
/// The tag of a signed head of the record.
pub const RECORD_HEAD_TAG: &[u8] = b"Arca/record-head";

/// What `S` signs to hand out entry `entry` of its record, whose running
/// hash is `hash`, on the chain of `genesis`:
/// `SHA256(T ‖ T ‖ genesis ‖ entry ‖ hash)`, `T = SHA256("Arca/record-head")`,
/// the genesis hash in internal byte order, the entry eight bytes
/// little-endian. The tag keeps it apart from every other message `S` signs.
pub fn record_head_digest(genesis: &elements::BlockHash, entry: u64, hash: &[u8; 32]) -> [u8; 32] {
	let tag = sha256::Hash::hash(RECORD_HEAD_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&arca_covenant::Chain::new(*genesis).genesis_bytes());
	e.input(&entry.to_le_bytes());
	e.input(hash);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// The tag of the record's end signed together with a witness's nonce.
pub const RECORD_END_TAG: &[u8] = b"Arca/record-end";

/// What `S` signs to answer a witness that carried `nonce`: its record ends
/// at entry `entry`, whose running hash is `hash`, on the chain of
/// `genesis`: `SHA256(T ‖ T ‖ genesis ‖ entry ‖ hash ‖ nonce)`,
/// `T = SHA256("Arca/record-end")`, the genesis hash in internal byte order,
/// the entry eight bytes little-endian. The nonce is the asker's, fresh for
/// each call, so the answer cannot be an older end replayed: a record that
/// ends, after a wallet was handed a head, before that head's entry has been
/// rolled back.
pub fn record_end_digest(genesis: &elements::BlockHash, entry: u64, hash: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
	let tag = sha256::Hash::hash(RECORD_END_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&arca_covenant::Chain::new(*genesis).genesis_bytes());
	e.input(&entry.to_le_bytes());
	e.input(hash);
	e.input(nonce);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// Where the proof of a rollback is kept beside the record at `record`.
pub fn stopped_path(record: &Path) -> PathBuf {
	let mut p = record.as_os_str().to_owned();
	p.push(".stopped");
	PathBuf::from(p)
}

/// Where the signer notes, beside the record at `record`, that a head of the
/// record has been acknowledged by as many keepers as it requires: from
/// then on a keeper that holds no head has lost its heads file, and is no
/// answer ([`mark_acknowledged`]).
pub fn acknowledged_path(record: &Path) -> PathBuf {
	let mut p = record.as_os_str().to_owned();
	p.push(".acknowledged");
	PathBuf::from(p)
}

/// Notes beside the record at `record` that its head `entry`, `hash` has
/// been acknowledged by as many keepers as it requires, once: the file is
/// made and synced, with its directory, the first time, and left as it is
/// after. The record's keepers held nothing before the first such head; from
/// then on a keeper that holds none has lost its heads file.
pub fn mark_acknowledged(record: &Path, entry: u64, hash: &[u8; 32]) -> Result<(), String> {
	use std::io::Write;
	use std::os::unix::fs::OpenOptionsExt;
	let path = acknowledged_path(record);
	let fail = |e: std::io::Error| format!("{}: {}", path.display(), e);
	let mut f = match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
		Ok(f) => f,
		Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
		Err(e) => return Err(fail(e)),
	};
	f.write_all(format!("entry {} {}: the first head of the record its keepers acknowledged; a keeper that holds no head from \
		now on has lost its heads file\n", entry, hex(hash)).as_bytes()).and_then(|_| f.sync_all()).map_err(fail)?;
	if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
		std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(fail)?;
	}
	Ok(())
}

/// Where the signer keeps, beside the record at `record`, what it has seen
/// each of the record's keepers hold: the highest entry each named or
/// acknowledged, and whether it is a lost keeper, and why
/// ([`write_keepers_seen`]). It is read at every start, so a keeper that
/// answers below what it held, after a restart of the signer, is a lost
/// keeper, as it is within one run, and a lost keeper stays one.
pub fn keepers_seen_path(record: &Path) -> PathBuf {
	let mut p = record.as_os_str().to_owned();
	p.push(".keepers-seen");
	PathBuf::from(p)
}

/// The first line of [`keepers_seen_path`]'s file.
const KEEPERS_SEEN_MAGIC: &str = "arca-keepers-seen 1";

/// What the signer has seen one keeper hold: the highest entry it named or
/// acknowledged, and why it is a lost keeper, once it is one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeeperSeen {
	pub held: Option<u64>,
	pub lost: Option<String>,
}

/// What the signer has seen each keeper hold, by the keeper's key, as kept
/// beside the record at `record`: empty when nothing is kept there yet. A
/// file that does not read is an error, never taken for empty.
pub fn read_keepers_seen(record: &Path) -> Result<std::collections::BTreeMap<[u8; 32], KeeperSeen>, String> {
	let path = keepers_seen_path(record);
	let text = match std::fs::read_to_string(&path) {
		Ok(t) => t,
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
		Err(e) => return Err(format!("{}: {}", path.display(), e)),
	};
	let bad = |l: &str| format!("{}: not a line of what the signer saw its keepers hold: {:?}", path.display(), l);
	let mut lines = text.lines();
	if lines.next() != Some(KEEPERS_SEEN_MAGIC) {
		return Err(format!("{}: it does not start with {:?}", path.display(), KEEPERS_SEEN_MAGIC));
	}
	let mut out = std::collections::BTreeMap::new();
	for l in lines.filter(|l| !l.is_empty()) {
		let mut f = l.splitn(3, ' ');
		let (Some(key), Some(held)) = (f.next(), f.next()) else { return Err(bad(l)) };
		let key = unhex32(key).map_err(|_| bad(l))?;
		let held = match held {
			"none" => None,
			n => Some(n.parse::<u64>().map_err(|_| bad(l))?),
		};
		let lost = match f.next() {
			None => None,
			Some(rest) => Some(rest.strip_prefix("lost ").ok_or_else(|| bad(l))?.to_string()),
		};
		out.insert(key, KeeperSeen { held, lost });
	}
	Ok(out)
}

/// Writes what the signer has seen each keeper hold beside the record at
/// `record`, whole or not at all: to a new file, synced, then renamed over
/// the old one, with the directory synced. The signer writes it before it
/// releases anything that taught it more, and releases nothing it cannot
/// write it for.
pub fn write_keepers_seen(record: &Path, seen: &[([u8; 32], KeeperSeen)]) -> Result<(), String> {
	use std::io::Write;
	use std::os::unix::fs::OpenOptionsExt;
	let path = keepers_seen_path(record);
	let mut tmp = path.as_os_str().to_owned();
	tmp.push(".new");
	let tmp = PathBuf::from(tmp);
	let fail = |p: &Path, e: std::io::Error| format!("{}: {}", p.display(), e);
	let mut text = format!("{}\n", KEEPERS_SEEN_MAGIC);
	for (key, s) in seen {
		text.push_str(&format!("{} {}", hex(key), s.held.map(|n| n.to_string()).unwrap_or_else(|| "none".into())));
		if let Some(why) = &s.lost {
			text.push_str(&format!(" lost {}", why.replace('\n', " ")));
		}
		text.push('\n');
	}
	let _ = std::fs::remove_file(&tmp);
	let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| fail(&tmp, e))?;
	f.write_all(text.as_bytes()).and_then(|_| f.sync_all()).map_err(|e| fail(&tmp, e))?;
	drop(f);
	std::fs::rename(&tmp, &path).map_err(|e| fail(&path, e))?;
	if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
		std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(|e| fail(dir, e))?;
	}
	Ok(())
}

/// The head a proof of a rollback kept beside the record names, from its
/// `head <entry> <hash> <signature>` line.
fn stop_head_of(text: &str) -> Option<WireEntryRef> {
	let l = text.lines().find(|l| l.starts_with("head "))?;
	let f: Vec<&str> = l.split(' ').collect();
	match f.as_slice() {
		["head", n, h, sig] => Some(WireEntryRef {
			entry: n.parse().ok()?, hash: h.to_string(), signature: (!sig.is_empty()).then(|| sig.to_string()),
		}),
		_ => None,
	}
}

/// `SHA256("Arca/signer-record" ‖ prev ‖ text)`: the running hash after a
/// line of the record whose text, before its own hash, is `text`; `prev` is
/// the hash before it, all zeros before the first line.
pub fn chain_hash(prev: &[u8; 32], text: &str) -> [u8; 32] {
	let mut b = RECORD_TAG.to_vec();
	b.extend(prev);
	b.extend(text.as_bytes());
	arca_covenant::script::sha256(&b)
}

/// The header of a record of the first format ([`RECORD_VERSION`]), without
/// keepers, kept for `operator` on the chain of `genesis`.
pub fn record_header(operator: &XOnlyPublicKey, genesis: &elements::BlockHash) -> String {
	format!("{} {} {} {}", RECORD_MAGIC, RECORD_VERSION, hex(&operator.serialize()), genesis)
}

/// The header of a record kept for `operator` on the chain of `genesis`,
/// naming its keepers: `arca-signer-record 4 <S> <genesis> keepers=…`. It is
/// the first line the running hash goes over, so every head the signer
/// signs commits to the keepers.
pub fn kept_record_header(operator: &XOnlyPublicKey, genesis: &elements::BlockHash, keepers: &RecordKeepers) -> String {
	format!("{} {} {} {} {}", RECORD_MAGIC, RECORD_VERSION_KEEPERS, hex(&operator.serialize()), genesis, keepers.field())
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

/// The format of a record compacted from another without the running hash
/// of each entry it dropped: its first line also names the record it was
/// compacted from, by that record's latest entry and running hash, and how
/// many of its entries it carries over, with a hash over their lines. Read,
/// never written.
pub const RECORD_VERSION_COMPACTED: u32 = 2;
/// The format of a record compacted from another
/// ([`SpendRecord::compact`]): as [`RECORD_VERSION_COMPACTED`], with a hash
/// line `<n> <hash>` in place of every entry it dropped, so the record
/// answers the running hash at every entry for its whole life.
pub const RECORD_VERSION_HASHES: u32 = 3;
/// The tag of the hash over a compacted record's carried lines.
pub const RECORD_CARRIED_TAG: &[u8] = b"Arca/signer-record-carried";

/// How many lines apart the record remembers where a line starts, to read
/// entries and running hashes back from the file: a lookup reads at most
/// this many lines.
const MARK_EVERY: u64 = 64;
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

/// A hash line of a compacted record, `<n> <hash>`: the running hash of an
/// entry the compaction dropped.
fn check_hash_line(line: &[u8]) -> Option<(u64, [u8; 32])> {
	let f: Vec<&[u8]> = line.split(|b| *b == b' ').collect();
	match f.as_slice() {
		[n, h] if !n.is_empty() && n.iter().all(u8::is_ascii_digit) && is_hex32(h) => {
			let n: u64 = std::str::from_utf8(n).ok()?.parse().ok()?;
			Some((n, unhex32(std::str::from_utf8(h).ok()?).ok()?))
		},
		_ => None,
	}
}

/// One line of the record after its header: an entry, or the running hash of
/// an entry a compaction dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Line {
	Entry(Entry),
	Hash(u64, [u8; 32]),
}

impl Line {
	fn n(&self) -> u64 {
		match self {
			Line::Entry(e) => e.n,
			Line::Hash(n, _) => *n,
		}
	}

	fn hash(&self) -> [u8; 32] {
		match self {
			Line::Entry(e) => e.hash,
			Line::Hash(_, h) => *h,
		}
	}
}

fn parse_line(text: &str) -> Result<Line, String> {
	match check_hash_line(text.as_bytes()) {
		Some((n, h)) => Ok(Line::Hash(n, h)),
		None => parse_entry(text).map(Line::Entry),
	}
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
/// The first line names the format, the operator key, the chain and the
/// record's keepers ([`RecordKeepers`]):
/// `arca-signer-record 4 <S> <genesis> keepers=<required>:<key>,…`, or
/// `keepers=none`; a record of format 1, `arca-signer-record 1 <S> <genesis>`,
/// has no keepers. Then one line per message,
/// `<n> spend <owner> <salt> <digest> <hash>` or
/// `<n> forfeit <owner> <salt> <digest> <connector> <hash>`, numbered from 1,
/// each ending with the running hash ([`chain_hash`]) over the header and
/// every line before it, appended and synced to disk before the signature is
/// returned.
///
/// The record is read line by line when it is opened, every line checked,
/// and kept at hand only as far as a lookup needs: for each entry, the first
/// eight bytes of its salt and where its line starts, sorted; with where
/// every 64th line starts, and the running hashes of the latest 4,096
/// entries. The entries under a salt, the running hash at an entry, and
/// anything a request repeated or the database's start check asks, are read
/// back from the file.
///
/// A record can be compacted into a new one ([`SpendRecord::compact`]),
/// dropping the entries under salts the server no longer serves (leaves
/// whose batches have expired): the new record's first line,
/// `arca-signer-record 4 <S> <genesis> keepers=… <n> <hash> <carried> <carried hash>`,
/// names the old record's keepers, its latest entry and running hash, from
/// which its own entries go on, and how many lines it carries over from it,
/// with a hash over the keepers field and them
/// (`SHA256("Arca/signer-record-carried" ‖ keepers=… ‖ 0x0a ‖ lines)`;
/// format 3, `arca-signer-record 3 <S> <genesis> <n> <hash> <carried> <carried hash>`,
/// names no keepers and hashes the lines alone): every entry
/// it keeps, verbatim, and for every entry it drops a hash line
/// `<n> <hash>`, its running hash, so the record answers the running hash
/// at any of its entries for its whole life. A record of format 2, compacted
/// without those lines, is read too.
///
/// The record is never made in passing: [`SpendRecord::create`] makes a new
/// one, once, and [`SpendRecord::open`] refuses a path where there is none,
/// so a lost record is not silently replaced by an empty one. The signer
/// holds an exclusive lock on the file while it runs, so two signers never
/// write one record. A write that fails is undone at once, so a torn line is
/// never followed by another; a last line left cut short by a crash was never
/// answered, and is removed when the record is opened, which says so; and the
/// record is synced when it is opened, before it answers anything, so a whole
/// line a crash left in the page cache alone is on disk before its head is
/// signed. Any
/// other line that does not read, or whose number or running hash does not
/// follow, stops the signer from starting.
///
/// The server's database remembers the latest entry it was given; each
/// request names it ([`SpendRecord::check_known`]). A record that ends
/// before that entry has been cut back, and one whose entry there is another
/// is another record: from then on the signer signs nothing until it is
/// started again on its whole record. A head the signer signed that the
/// record does not hold, handed back by a wallet, stops it for good
/// ([`SpendRecord::witness`]).
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
	/// How many lines, entries and hash lines, the record holds.
	lines: u64,
	/// `(entry, offset)` of every [`MARK_EVERY`]th line, from the first.
	marks: Vec<(u64, u64)>,
	/// `(entry, running hash)` of the latest entries.
	recent: std::collections::VecDeque<(u64, [u8; 32])>,
	/// Why the signer signs nothing more until it is started again.
	refusing: Option<String>,
	/// Why the signer signs nothing the record governs, for good: a proven
	/// rollback, kept beside the record ([`stopped_path`]).
	stopped: Option<String>,
	/// Where that proof is kept.
	stop_path: PathBuf,
	/// The head that proved it, as it was handed over.
	stop_head: Option<WireEntryRef>,
	/// The operator key and the chain the record is kept for, which every
	/// head it hands out is signed under.
	operator: XOnlyPublicKey,
	genesis: elements::BlockHash,
	/// The keepers its first line names: none for a record of format 1 to 3.
	keepers: RecordKeepers,
}

impl SpendRecord {
	/// Makes a new, empty record at `path` (mode 0600) for `operator` on the
	/// chain of `genesis`, naming `keepers` (none, for a record without
	/// keepers) for its whole life, and syncs it and its directory: an act of
	/// its own, for a new operator key. It never replaces a record already
	/// there.
	pub fn create(path: &Path, operator: &XOnlyPublicKey, genesis: &elements::BlockHash, keepers: &RecordKeepers) -> Result<(), String> {
		Self::write_new(path, &format!("{}\n", kept_record_header(operator, genesis, keepers)), |_| Ok(()))
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
		let mut hash_lines = false;
		// The fields after the operator key and the chain: the keepers in
		// format 4, then, in a compacted record, where it was compacted from.
		let version = f.get(1).and_then(|v| v.parse::<u32>().ok());
		let (keepers, rest) = match version {
			Some(RECORD_VERSION_KEEPERS) if f.len() == 5 || f.len() == 9 => (
				RecordKeepers::from_field(f[4]).map_err(|e| format!("{}: the header: {}", path.display(), e))?, &f[5..]),
			Some(RECORD_VERSION_KEEPERS) => return Err(format!("{}: a header of format 4 with {} fields", path.display(), f.len())),
			_ => (RecordKeepers::default(), f.get(4..).unwrap_or(&[])),
		};
		let compacted = |rest: &[&str]| -> Result<_, String> {
			let n: u64 = rest[0].parse().map_err(|_| format!("{}: the header's latest entry {:?}", path.display(), rest[0]))?;
			let carried: u64 = rest[2].parse().map_err(|_| format!("{}: the header's carried count {:?}", path.display(), rest[2]))?;
			Ok((Some((n, unhex32(rest[1]).map_err(|e| format!("{}: the header: {}", path.display(), e))?)),
				Some((carried, unhex32(rest[3]).map_err(|e| format!("{}: the header: {}", path.display(), e))?))))
		};
		let (base, carried) = match version {
			Some(RECORD_VERSION) if f.len() == 4 => (None, None),
			Some(RECORD_VERSION_KEEPERS) if rest.is_empty() => (None, None),
			Some(RECORD_VERSION_KEEPERS) => {
				hash_lines = true;
				compacted(rest)?
			},
			Some(v @ (RECORD_VERSION_COMPACTED | RECORD_VERSION_HASHES)) if f.len() == 8 => {
				hash_lines = v == RECORD_VERSION_HASHES;
				compacted(rest)?
			},
			_ => return Err(format!("{}: the record is of format {:?}; this signer reads formats {}, {}, {} and {}", path.display(), f.get(1),
				RECORD_VERSION, RECORD_VERSION_COMPACTED, RECORD_VERSION_HASHES, RECORD_VERSION_KEEPERS)),
		};
		if f.get(2..4) != ours.get(2..4) {
			return Err(format!("{}: the record is kept for another operator key or another chain ({:?}); this signer holds \
				{} on {}", path.display(), header, hex(&operator.serialize()), genesis));
		}
		let base = base.unwrap_or((0, chain_hash(&[0; 32], &header)));
		let first = got as u64;
		// About 300 bytes a line: room for every entry at once.
		let lines = file.metadata().map(|m| m.len()).unwrap_or(0) / 280 + 16;
		let stop_path = stopped_path(path);
		let (stopped, stop_head) = match std::fs::read_to_string(&stop_path) {
			Ok(text) => (Some(format!("{}: {} (the proof is kept in {}; the operator clears it with arca-signer --clear-stopped)", STOPPED,
				text.lines().next().unwrap_or("the record was rolled back or replaced"), stop_path.display())), stop_head_of(&text)),
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, None),
			Err(e) => return Err(format!("{}: {}", stop_path.display(), e)),
		};
		let mut record = SpendRecord {
			file, size: first, first, base, head: base, count: 0, kept: Vec::with_capacity(lines as usize), added: Default::default(),
			lines: 0, marks: vec![], recent: Default::default(), refusing: None, stopped, stop_path, stop_head, operator: *operator,
			genesis: *genesis, keepers,
		};
		let mut at = first;
		let mut k = 1u64;
		// The carried lines of a compacted record: whole, numbered upwards to
		// the entry it was compacted at, their hash the header's.
		if let Some((carried, want)) = carried {
			let mut e = sha256::Hash::engine();
			e.input(RECORD_CARRIED_TAG);
			if version == Some(RECORD_VERSION_KEEPERS) {
				e.input(record.keepers.field().as_bytes());
				e.input(b"\n");
			}
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
				if let Some((n, _)) = check_hash_line(&line[..got - 1]).filter(|_| hash_lines) {
					if n <= last || n > base.0 {
						return Err(bad("a carried hash line out of order"));
					}
					last = n;
					record.mark(n, at);
					at += got as u64;
					continue;
				}
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
		// A signer that crashed between writing a line and syncing it leaves
		// a whole line that may be in the page cache alone: synced now,
		// before the record answers anything, so its latest entry is on disk
		// before its head is signed.
		record.file.sync_all().map_err(fail)?;
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
		self.mark(n, at);
		self.count += 1;
		self.recent.push_back((n, hash));
		if self.recent.len() > RECENT {
			self.recent.pop_front();
		}
	}

	/// Counts the line of entry `n` at `at`, remembering where every
	/// [`MARK_EVERY`]th line starts.
	fn mark(&mut self, n: u64, at: u64) {
		if self.lines % MARK_EVERY == 0 {
			self.marks.push((n, at));
		}
		self.lines += 1;
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

	/// Calls `f` with each line from `from` on (its text, what it holds and
	/// where it starts) until `f` says stop.
	fn each_from(&self, from: u64, f: impl FnMut(&str, Line, u64) -> Result<bool, String>) -> Result<(), String> {
		self.each_from_by(from, 1 << 20, f)
	}

	/// [`Self::each_from`], reading the file `chunk` bytes at a time: a
	/// look-up that reads a few lines reads a few kilobytes, not a megabyte.
	fn each_from_by(&self, from: u64, chunk: usize, mut f: impl FnMut(&str, Line, u64) -> Result<bool, String>) -> Result<(), String> {
		use std::io::{BufRead, Seek};
		let mut file = self.file.try_clone().map_err(|e| e.to_string())?;
		file.seek(std::io::SeekFrom::Start(from)).map_err(|e| e.to_string())?;
		let mut reader = std::io::BufReader::with_capacity(chunk, file);
		let mut line = String::with_capacity(512);
		let mut at = from;
		while at < self.size {
			line.clear();
			let got = reader.read_line(&mut line).map_err(|e| e.to_string())?;
			if got == 0 {
				break;
			}
			let text = line.trim_end_matches('\n');
			if !f(text, parse_line(text)?, at)? {
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

	/// The keepers the record's first line names: none for a record of
	/// format 1 to 3, made before records named them.
	pub fn keepers(&self) -> &RecordKeepers {
		&self.keepers
	}

	/// The latest entry's number and running hash: 0 and the header's hash
	/// for a record that holds none, and for a compacted record that has
	/// added none, the latest of the record it was compacted from.
	pub fn head(&self) -> (u64, [u8; 32]) {
		self.head
	}

	/// The entries under `salt`, whatever their owner, read back from the
	/// file.
	pub fn entries_under(&self, salt: &[u8; 32]) -> Result<Vec<Entry>, String> {
		self.under(salt)
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
		self.each_from(from, |_, l, _| {
			if let Line::Entry(e) = l {
				if e.n > after {
					out.push(e);
				}
			}
			Ok(out.len() < limit)
		})?;
		Ok(out)
	}

	/// The running hash of entry `n`, when the record holds it: an entry of
	/// its own, one it carries, or one a compaction dropped and kept the hash
	/// of. `None` past its end, and for an entry a compaction of format 2
	/// dropped.
	pub fn hash_of(&self, n: u64) -> Result<Option<[u8; 32]>, String> {
		if n == self.base.0 {
			return Ok(Some(self.base.1));
		}
		if n > self.head.0 {
			return Ok(None);
		}
		if let Ok(i) = self.recent.binary_search_by_key(&n, |(m, _)| *m) {
			return Ok(Some(self.recent[i].1));
		}
		let i = self.marks.partition_point(|(m, _)| *m <= n);
		if i == 0 {
			return Ok(None);
		}
		let from = self.marks[i - 1].1;
		if let Some(found) = self.scan_hash(from, n)? {
			return Ok(found);
		}
		let mut found = None;
		self.each_from_by(from, 16 << 10, |_, l, _| {
			if l.n() == n {
				found = Some(l.hash());
			}
			Ok(l.n() < n)
		})?;
		Ok(found)
	}

	/// The running hash of entry `n` read from the whole lines of one read
	/// of 32 KiB at `from`, a mark at or before it, taking of each line only
	/// its number and its last field (every line was checked when the record
	/// was opened, or written by this signer): `Some(None)` when the lines
	/// pass `n` without it, `None` when the read ends before them.
	fn scan_hash(&self, from: u64, n: u64) -> Result<Option<Option<[u8; 32]>>, String> {
		use std::os::unix::fs::FileExt;
		let len = (self.size.saturating_sub(from) as usize).min(32 << 10);
		let mut buf = vec![0u8; len];
		let mut got = 0;
		while got < len {
			let k = self.file.read_at(&mut buf[got..], from + got as u64).map_err(|e| e.to_string())?;
			if k == 0 {
				break;
			}
			got += k;
		}
		let mut rest = &buf[..got];
		while let Some(end) = rest.iter().position(|b| *b == b'\n') {
			let line = &rest[..end];
			rest = &rest[end + 1..];
			let at = line.iter().position(|b| *b == b' ').ok_or("a line without fields")?;
			let m: u64 = std::str::from_utf8(&line[..at]).ok().and_then(|x| x.parse().ok()).ok_or("a line without its number")?;
			if m > n {
				return Ok(Some(None));
			}
			if m == n {
				let last = line.iter().rposition(|b| *b == b' ').expect("a field");
				return Ok(Some(Some(unhex32(std::str::from_utf8(&line[last + 1..]).map_err(|e| e.to_string())?)?)));
			}
		}
		Ok(None)
	}

	/// Why the signer signs nothing more, if it does not.
	pub fn refusing(&self) -> Option<&str> {
		self.stopped.as_deref().or(self.refusing.as_deref())
	}

	/// Why the signer signs nothing the record governs, for good: a proven
	/// rollback, if one was handed to it.
	pub fn stopped(&self) -> Option<&str> {
		self.stopped.as_deref()
	}

	/// The head that stopped the signer, as it was handed over, with `S`'s
	/// signature: a head the record does not hold.
	pub fn stop_head(&self) -> Option<&WireEntryRef> {
		self.stop_head.as_ref()
	}

	/// Checks the heads a wallet holds, each `(entry, running hash)` with the
	/// signature it was handed out with, against the record, and returns the
	/// running hash the record holds at each entry (`None` past its end, or
	/// for an entry a compaction of format 2 dropped). A head that carries
	/// `S`'s valid signature on this chain and that the record does not hold
	/// (an entry past its end, or another hash at its entry) is proof that
	/// the record was rolled back or replaced, since the signer signed it:
	/// the proof is written beside the record ([`stopped_path`]) and synced,
	/// and the signer signs nothing the record governs from then on, across
	/// restarts. A head without that signature stops nothing, nor does one
	/// the record holds, or one at an entry whose hash a compaction did not
	/// keep. Every signature is checked before anything is looked up, and a
	/// call naming more than [`MAX_UNSIGNED_WITNESS`] heads without a valid
	/// one is refused.
	pub fn witness(&mut self, heads: &[WireEntryRef]) -> Result<Vec<WireEntryHash>, String> {
		// Every signature is checked before anything is looked up, and the
		// heads without one that holds are few: only `S`'s heads cost a read
		// of the record beyond that bound.
		let signed: Vec<Option<[u8; 32]>> = heads.iter().map(|h| self.signed_head(h)).collect();
		self.witness_checked(heads, &signed)
	}

	/// [`Self::witness`], each head's signature checked already by the
	/// caller, outside the lock the record is held under: `signed[i]` is
	/// the running hash `heads[i]` names when it carries `S`'s valid
	/// signature over it on this chain, `None` otherwise.
	pub fn witness_checked(&mut self, heads: &[WireEntryRef], signed: &[Option<[u8; 32]>]) -> Result<Vec<WireEntryHash>, String> {
		if signed.len() != heads.len() {
			return Err("a signature check for every head".into());
		}
		let unsigned = signed.iter().filter(|s| s.is_none()).count();
		if unsigned > MAX_UNSIGNED_WITNESS {
			return Err(format!("{} heads without the signer's valid signature; a witness names at most {}", unsigned, MAX_UNSIGNED_WITNESS));
		}
		let mut out = Vec::with_capacity(heads.len());
		let mut proof = None;
		for (h, signed) in heads.iter().zip(signed.iter().copied()) {
			let held = self.hash_of(h.entry).map_err(|e| format!("the record could not be read: {}", e))?;
			out.push(WireEntryHash { entry: h.entry, hash: held.map(|x| hex(&x)), signature: None });
			if proof.is_some() || self.stopped.is_some() {
				continue;
			}
			let Some(hash) = signed else { continue };
			let why = if h.entry > self.head.0 {
				Some(format!("a head the signer signed, entry {} with the running hash {}, lies past the record's end at entry {}",
					h.entry, h.hash, self.head.0))
			} else {
				held.filter(|x| *x != hash).map(|x| format!("a head the signer signed, entry {} with the running hash {}, is not the \
					record's: it holds {} at that entry", h.entry, h.hash, hex(&x)))
			};
			if let Some(why) = why {
				proof = Some((h.clone(), why));
			}
		}
		if let Some((h, why)) = proof {
			self.stop(&h, &why);
		}
		Ok(out)
	}

	/// The running hash `head` names, when it carries `S`'s valid signature
	/// over it on this chain ([`record_head_digest`]).
	fn signed_head(&self, head: &WireEntryRef) -> Option<[u8; 32]> {
		let hash = unhex32(&head.hash).ok()?;
		let sig = Signature::from_slice(&unhex(head.signature.as_deref()?).ok()?).ok()?;
		arca_covenant::sign::verify_digest(&sig, &record_head_digest(&self.genesis, head.entry, &hash), &self.operator).then_some(hash)
	}

	/// Stops the signer for good on the proof `head`, a head it signed that
	/// the record does not hold: written beside the record and synced, so a
	/// restart keeps it. Should the write fail, the signer is stopped still,
	/// until it is started again.
	fn stop(&mut self, head: &WireEntryRef, why: &str) {
		use std::io::Write;
		use std::os::unix::fs::OpenOptionsExt;
		let text = format!("the signer's record was rolled back or replaced: {}\nhead {} {} {}\nrecord head {} {}\n", why, head.entry, head.hash,
			head.signature.as_deref().unwrap_or(""), self.head.0, hex(&self.head.1));
		let written = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&self.stop_path)
			.and_then(|mut f| f.write_all(text.as_bytes()).and_then(|_| f.sync_all()))
			.and_then(|_| match self.stop_path.parent().filter(|d| !d.as_os_str().is_empty()) {
				Some(dir) => std::fs::File::open(dir).and_then(|d| d.sync_all()),
				None => Ok(()),
			});
		let kept = match written {
			Ok(()) => format!("the proof is kept in {}; the operator clears it with arca-signer --clear-stopped", self.stop_path.display()),
			Err(e) => format!("the proof could not be written to {} ({}): the signer is stopped until it is started again", self.stop_path.display(), e),
		};
		self.stopped = Some(format!("{}: the signer's record was rolled back or replaced: {}; it signs nothing the record governs ({})",
			STOPPED, why, kept));
		self.stop_head = Some(head.clone());
	}

	/// Removes the proof of a rollback kept beside the record at `record`,
	/// returning what it said: the operator's explicit act, with the signer
	/// stopped. `None` when there is none.
	pub fn clear_stopped(record: &Path) -> Result<Option<String>, String> {
		let path = stopped_path(record);
		let text = match std::fs::read_to_string(&path) {
			Ok(t) => t,
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
			Err(e) => return Err(format!("{}: {}", path.display(), e)),
		};
		std::fs::remove_file(&path).map_err(|e| format!("{}: {}", path.display(), e))?;
		if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
			std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(|e| format!("{}: {}", dir.display(), e))?;
		}
		Ok(Some(text))
	}

	/// Checks the latest entry the server's database knows, entry `n` with
	/// running hash `hash` (`n` 0 when it knows none): the record must hold
	/// it, the same. When it does not, the signer signs nothing more until it
	/// is started again.
	pub fn check_known(&mut self, n: u64, hash: &[u8; 32]) -> Result<(), String> {
		if let Some(why) = self.refusing() {
			return Err(why.to_string());
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
		if let Some(why) = self.refusing() {
			return Err(why.to_string());
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
	/// names the old record's keepers (none for a record of format 1 to 3),
	/// and its latest entry and running hash, from which its
	/// own entries go on, so the server's database, which knows that entry,
	/// knows the new record; it carries every other entry's line over
	/// verbatim, and for each entry it drops a hash line with its running
	/// hash. Returns how many entries it carried and dropped, and the entry
	/// the new record goes on from.
	pub fn compact(from: &Path, into: &Path, operator: &XOnlyPublicKey, genesis: &elements::BlockHash,
		drop: &std::collections::HashSet<[u8; 32]>) -> Result<(u64, u64, (u64, [u8; 32])), String>
	{
		use std::io::Write;
		let (old, repaired) = Self::open(from, operator, genesis)?;
		if let Some(note) = repaired {
			return Err(format!("{}: {}; open it with the signer first", from.display(), note));
		}
		// Every line the new record carries: an entry kept, verbatim, or the
		// hash line of an entry dropped (or of one dropped before).
		let carry = |text: &str, l: Line| -> String {
			match l {
				Line::Entry(e) if drop.contains(&e.salt) => format!("{} {}", e.n, hex(&e.hash)),
				_ => text.to_string(),
			}
		};
		let (mut carried, mut dropped, mut lines) = (0u64, 0u64, 0u64);
		let mut e = sha256::Hash::engine();
		e.input(RECORD_CARRIED_TAG);
		// The keepers go over to the new record with the rest: a record never
		// gains keepers, nor loses them.
		let keepers = old.keepers.field();
		e.input(keepers.as_bytes());
		e.input(b"\n");
		old.each_from(old.first, |text, l, _| {
			match l {
				Line::Entry(x) if drop.contains(&x.salt) => dropped += 1,
				Line::Entry(_) => carried += 1,
				Line::Hash(..) => {},
			}
			lines += 1;
			e.input(carry(text, l).as_bytes());
			e.input(b"\n");
			Ok(true)
		})?;
		let carried_hash = sha256::Hash::from_engine(e).to_byte_array();
		let base = old.head();
		let header = format!("{} {} {} {} {} {} {} {} {}\n", RECORD_MAGIC, RECORD_VERSION_KEEPERS, hex(&operator.serialize()), genesis,
			keepers, base.0, hex(&base.1), lines, hex(&carried_hash));
		Self::write_new(into, &header, |w| {
			old.each_from(old.first, |text, l, _| {
				w.write_all(carry(text, l).as_bytes()).and_then(|_| w.write_all(b"\n")).map_err(|e| format!("{}: {}", into.display(), e))?;
				Ok(true)
			})
		})?;
		// What the keepers have acknowledged goes over too: the new record's
		// keepers are the old one's, and hold its heads.
		if let Ok(text) = std::fs::read_to_string(acknowledged_path(from)) {
			let (entry, hash) = text.split(' ').nth(1).zip(text.split(' ').nth(2))
				.and_then(|(n, h)| Some((n.parse::<u64>().ok()?, unhex32(h.trim_end_matches(':')).ok()?)))
				.unwrap_or((base.0, base.1));
			mark_acknowledged(into, entry, &hash)?;
		}
		// And what the signer saw each keeper hold, its lost keepers with it.
		let seen = read_keepers_seen(from)?;
		if !seen.is_empty() {
			write_keepers_seen(into, &seen.into_iter().collect::<Vec<_>>())?;
		}
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
	/// A head the signer signed that its record does not hold was handed
	/// back: its record was rolled back or replaced, and it signs nothing the
	/// record governs.
	#[error("the signer refused: {0}")]
	Stopped(String),
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

/// A head of the signer's record as the signer hands it out: an entry, its
/// running hash and `S`'s signature over them ([`record_head_digest`]), with
/// the keepers' acknowledgements of it when it has keepers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHead {
	pub entry: u64,
	pub hash: [u8; 32],
	pub signature: Option<Signature>,
	pub acks: Vec<crate::keeper::WireAck>,
}

impl SignedHead {
	pub fn from_wire(w: &WireEntryRef) -> Result<SignedHead, String> {
		let signature = w.signature.as_deref().map(|s| Signature::from_slice(&unhex(s)?).map_err(|e| e.to_string())).transpose()?;
		Ok(SignedHead { entry: w.entry, hash: unhex32(&w.hash)?, signature, acks: vec![] })
	}

	fn from_answer(r: &Response) -> Result<Option<SignedHead>, SignerError> {
		let Some(e) = &r.entry else { return Ok(None) };
		let mut h = SignedHead::from_wire(e).map_err(SignerError::Answer)?;
		h.acks = r.acks.clone().unwrap_or_default();
		Ok(Some(h))
	}

	pub fn to_wire(&self) -> WireEntryRef {
		WireEntryRef { entry: self.entry, hash: hex(&self.hash), signature: self.signature.map(|s| hex(s.as_ref())) }
	}
}

/// The signer's answer to a witness of its record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witnessed {
	pub head: Option<SignedHead>,
	pub hashes: Vec<WireEntryHash>,
	pub stopped: Option<String>,
	/// The record's latest entry signed with the witness's nonce.
	pub end: Option<WireEntryRef>,
	pub proof: Option<WireStopProof>,
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
				Some(STOPPED) => SignerError::Stopped(e),
				_ => SignerError::Refused(e),
			});
		}
		Ok(r)
	}

	/// The latest entry of the signer's record: its number and running hash.
	pub async fn head(&self) -> Result<(u64, [u8; 32]), SignerError> {
		self.signed_head().await.map(|h| (h.entry, h.hash))
	}

	/// The latest entry of the signer's record, with the signer's signature
	/// over it, and its keepers' acknowledgements when they hold it (kept in
	/// the server's database, which hands them on with the head).
	pub async fn signed_head(&self) -> Result<SignedHead, SignerError> {
		let r = self.ask(&Request::Head {}).await?;
		let h = SignedHead::from_answer(&r)?.ok_or_else(|| SignerError::Answer("no entry".into()))?;
		self.keep_acks(&h).await?;
		Ok(h)
	}

	/// The keepers the signer hands every head to, and how many must hold
	/// one before it answers an entry.
	pub async fn keepers(&self) -> Result<(Vec<XOnlyPublicKey>, u32), SignerError> {
		let r = self.ask(&Request::Pubkey {}).await?;
		let k = r.keepers.unwrap_or_default();
		let keys = k.keys.iter().map(|x| XOnlyPublicKey::from_slice(&unhex(x).map_err(SignerError::Answer)?)
			.map_err(|e| SignerError::Answer(e.to_string()))).collect::<Result<Vec<_>, _>>()?;
		Ok((keys, k.required))
	}

	/// Keeps the keepers' acknowledgements of `h` in the server's database.
	async fn keep_acks(&self, h: &SignedHead) -> Result<(), SignerError> {
		if let (Some(store), false) = (&self.store, h.acks.is_empty()) {
			store.put_head_acks(h.entry, &h.hash, &h.acks).await.map_err(|e| SignerError::Database(e.to_string()))?;
		}
		Ok(())
	}

	/// What the signer's record holds at each of `heads`, heads of it a
	/// wallet was handed: the running hash at each entry, signed, the
	/// record's latest entry, signed (none while the signer is stopped) and,
	/// with the wallet's `nonce`, signed together with it, and why it is
	/// stopped, if it is, with the proof. A head the signer signed that the
	/// record does not hold stops it ([`SpendRecord::witness`]).
	pub async fn witness(&self, heads: &[WireEntryRef], nonce: Option<&[u8; 32]>) -> Result<Witnessed, SignerError> {
		let r = self.ask(&Request::Witness { heads: heads.to_vec(), nonce: nonce.map(|n| hex(n)) }).await?;
		let head = SignedHead::from_answer(&r)?;
		if let Some(h) = &head {
			self.keep_acks(h).await?;
		}
		Ok(Witnessed { head, hashes: r.hashes.unwrap_or_default(), stopped: r.stopped, end: r.end, proof: r.proof })
	}

	/// The entries of the signer's record after entry `after`, at most
	/// [`MAX_ENTRIES`].
	pub async fn entries(&self, after: u64) -> Result<Vec<Entry>, SignerError> {
		let r = self.ask(&Request::Entries { after, limit: MAX_ENTRIES }).await?;
		r.entries.unwrap_or_default().iter().map(Entry::from_wire).collect::<Result<_, _>>().map_err(SignerError::Answer)
	}

	/// The entries of the signer's record under `salt`: what `S` has
	/// co-signed for a leaf of that salt, a spend or forfeits.
	pub async fn under(&self, salt: &[u8; 32]) -> Result<Vec<Entry>, SignerError> {
		let r = self.ask(&Request::Under { salt: hex(salt) }).await?;
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
		self.rebind_as(owner, owner_sig, salt, asset_in, value_in, outputs, None).await.map(|(s, _)| s)
	}

	/// [`Self::rebind`], with the entry of the record the signature was
	/// recorded as, signed.
	pub async fn rebind_recorded(&self, owner: &XOnlyPublicKey, owner_sig: &Signature, salt: &[u8; 32], asset_in: AssetId, value_in: u64,
		outputs: &[ExplicitOutput]) -> Result<(Signature, Option<SignedHead>), SignerError>
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
			.map(|(s, _)| s)
	}

	#[allow(clippy::too_many_arguments)]
	async fn rebind_as(&self, owner: &XOnlyPublicKey, owner_sig: &Signature, salt: &[u8; 32], asset_in: AssetId, value_in: u64,
		outputs: &[ExplicitOutput], forfeit: Option<WireForfeit>) -> Result<(Signature, Option<SignedHead>), SignerError>
	{
		let known = match &self.store {
			Some(store) => store.signer_head().await.map_err(|e| SignerError::Database(e.to_string()))?
				.map(|(entry, hash)| WireEntryRef { entry, hash: hex(&hash), signature: None }),
			None => None,
		};
		let r = self.ask(&Request::Rebind {
			owner: hex(&owner.serialize()), owner_sig: hex(owner_sig.as_ref()), salt: hex(salt), asset_in: asset_in.to_string(),
			value_in: value_in.to_string(), outputs: outputs.iter().map(WireOutput::from_output).collect(), forfeit, known,
		}).await?;
		let head = SignedHead::from_answer(&r)?;
		if let (Some(store), Some(h)) = (&self.store, &head) {
			self.keep_acks(h).await?;
			store.set_signer_head_signed(h.entry, &h.hash, h.signature.as_ref()).await.map_err(|e| SignerError::Database(e.to_string()))?;
		}
		let s = r.signature.ok_or_else(|| SignerError::Answer("no signature".into()))?;
		let sig = Signature::from_slice(&unhex(&s).map_err(SignerError::Answer)?).map_err(|e| SignerError::Answer(e.to_string()))?;
		Ok((sig, head))
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
