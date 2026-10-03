//! The operator key `S`, behind a narrow interface in a process of its own.
//!
//! The server never holds `S`. The signer (`arca-signer`) loads it, listens on
//! a Unix socket, and answers three requests, one JSON object per line:
//!
//! - `{"op":"pubkey"}`: the x-only key `S`;
//! - `{"op":"rebind","salt":…,"asset_in":…,"value_in":…,"outputs":[…]}`: `S`'s
//!   signature over the rebindable message of a collaborative path, which the
//!   signer builds itself from the parts, on its own chain:
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
//! `OP_CHECKSIGFROMSTACK`, which only the rebindable message reaches. Whoever
//! reaches the socket can have it sign a rebindable message for any salt,
//! which is what co-signing is, and spend any output on the operator's own
//! paths; the socket sits in a directory only the operator's user can enter,
//! and the server checks every rule before it asks.
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

use arca_covenant::ExplicitOutput;

/// The longest request line the signer reads.
pub const MAX_REQUEST: usize = 64 * 1024;

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

/// A request to the signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
	/// A struct variant, so a stray field is refused as for `rebind` (serde
	/// lets a unit variant of a tagged enum through with any fields).
	Pubkey {},
	Rebind { salt: String, asset_in: String, value_in: String, outputs: Vec<WireOutput> },
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub pubkey: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub signature: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum SignerError {
	#[error("cannot reach the signer at {path}: {error}")]
	Unreachable { path: String, error: String },
	#[error("the signer refused: {0}")]
	Refused(String),
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

	/// `S`'s signature over the rebindable message of the output with `salt`,
	/// spending a coin of `value_in` of `asset_in` into `outputs`.
	pub async fn rebind(&self, salt: &[u8; 32], asset_in: AssetId, value_in: u64, outputs: &[ExplicitOutput])
		-> Result<Signature, SignerError>
	{
		let r = self.ask(&Request::Rebind {
			salt: hex(salt), asset_in: asset_in.to_string(), value_in: value_in.to_string(),
			outputs: outputs.iter().map(WireOutput::from_output).collect(),
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
