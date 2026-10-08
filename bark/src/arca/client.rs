//! The wallet's client of the Arca server: JSON over HTTPS, every call under
//! `/v1/`. Plain HTTP is spoken only to this machine (a loopback address or
//! `localhost`), as to a server behind a local TLS proxy or in a test.
//!
//! The calls that read a key's mailbox or leaves are authenticated with a
//! challenge from the server, signed with the key (BIP340) over the tagged
//! hash `SHA256(T ‖ T ‖ genesis_hash ‖ len(call) ‖ call ‖ challenge ‖ key ‖
//! SHA256(request))`, `T = SHA256("Arca/auth")`, `request` what the read asks
//! besides its proof ([`mailbox_read_request`]), so a proof seen by anyone on
//! the way repeats only that very read. A transfer is authenticated by its owners'
//! signatures over the transfer itself, a participation by each owner's
//! attestation over the participation's id, and by each key it wants a leaf
//! under, signing its key-proof digest. There is no bearer token.
//!
//! Every refusal the server makes comes back as [`Error::Server`], with its
//! HTTP status, its stable code and its sentence; any other failure, a 5xx or
//! a timeout among them, is [`Error::Unreachable`], and leaves the request
//! standing.

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::{Keypair, XOnlyPublicKey};
use elements::AssetId;
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::{Chain, LeafId, MedianTime, RelativeTime, Template};

use super::chain::{hex, unhex32};
use super::{random32, Error};

/// The tag of the hash a key signs to authenticate a call.
pub const AUTH_TAG: &[u8] = b"Arca/auth";

/// The tag of a participation's id.
pub const PARTICIPATION_TAG: &[u8] = b"Arca/participation";

/// The tag of a key proof, the signature by a key a participation wants a
/// leaf under.
pub const KEY_PROOF_TAG: &[u8] = b"Arca/participation-key";

/// The digest each key a participation wants a leaf under signs, to prove the
/// participation holds it: `SHA256(T ‖ T ‖ id)`,
/// `T = SHA256("Arca/participation-key")`. The server's
/// (`server::participations::key_proof_digest`).
pub fn key_proof_digest(id: &[u8; 32]) -> [u8; 32] {
	let tag = sha256::Hash::hash(KEY_PROOF_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(id);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// The tag of a signed head of the operator's signer's record.
pub const RECORD_HEAD_TAG: &[u8] = b"Arca/record-head";

/// What the operator key signs to hand out entry `entry` of its signer's
/// record, whose running hash is `hash`: `SHA256(T ‖ T ‖ genesis ‖ entry ‖
/// hash)`, `T = SHA256("Arca/record-head")`, the entry eight bytes
/// little-endian. The server's (`server::signer::record_head_digest`).
pub fn record_head_digest(chain: &Chain, entry: u64, hash: &[u8; 32]) -> [u8; 32] {
	let tag = sha256::Hash::hash(RECORD_HEAD_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&chain.genesis_bytes());
	e.input(&entry.to_le_bytes());
	e.input(hash);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// The tag of the signer's record's end, signed with a witness's nonce.
pub const RECORD_END_TAG: &[u8] = b"Arca/record-end";

/// What the operator key signs to answer a witness that carried `nonce`: its
/// signer's record ends at entry `entry`, whose running hash is `hash`:
/// `SHA256(T ‖ T ‖ genesis ‖ entry ‖ hash ‖ nonce)`,
/// `T = SHA256("Arca/record-end")`. The server's
/// (`server::signer::record_end_digest`).
pub fn record_end_digest(chain: &Chain, entry: u64, hash: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
	let tag = sha256::Hash::hash(RECORD_END_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&chain.genesis_bytes());
	e.input(&entry.to_le_bytes());
	e.input(hash);
	e.input(nonce);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// The tag of a keeper's acknowledgement of a head of the operator's signer's
/// record.
pub const KEEPER_ACK_TAG: &[u8] = b"Arca/keeper-ack";

/// What a keeper signs to acknowledge that it holds head `entry`, `hash` of
/// the record of `operator`'s signer, answering a request that carried
/// `nonce`: `SHA256(T ‖ T ‖ genesis ‖ operator ‖ entry ‖ hash ‖ nonce)`,
/// `T = SHA256("Arca/keeper-ack")`. The server's (`server::keeper::ack_digest`).
pub fn keeper_ack_digest(chain: &Chain, operator: &XOnlyPublicKey, entry: u64, hash: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
	let tag = sha256::Hash::hash(KEEPER_ACK_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&chain.genesis_bytes());
	e.input(&operator.serialize());
	e.input(&entry.to_le_bytes());
	e.input(hash);
	e.input(nonce);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// What a `mailbox_read` asks besides its proof, as the proof binds it: the
/// cursor (eight bytes) and the page size (four), little-endian; a
/// `leaf_data` asks nothing more. The server's
/// (`server::auth::mailbox_read_request`).
pub fn mailbox_read_request(after: u64, limit: u32) -> Vec<u8> {
	let mut b = after.to_le_bytes().to_vec();
	b.extend(limit.to_le_bytes());
	b
}

/// The digest `key` signs to authenticate `call` with `challenge`, asking
/// `request` ([`mailbox_read_request`]): `SHA256(T ‖ T ‖ genesis_hash ‖
/// len(call) ‖ call ‖ challenge ‖ key ‖ SHA256(request))`.
pub fn auth_digest(chain: &Chain, call: &str, challenge: &[u8; 32], key: &XOnlyPublicKey, request: &[u8]) -> [u8; 32] {
	let tag = sha256::Hash::hash(AUTH_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&chain.genesis_bytes());
	e.input(&[call.len() as u8]);
	e.input(call.as_bytes());
	e.input(challenge);
	e.input(&key.serialize());
	e.input(sha256::Hash::hash(request).as_byte_array());
	sha256::Hash::from_engine(e).to_byte_array()
}

/// The tag of a leaf's binding to its owner's mailbox key.
pub const MAILBOX_BINDING_TAG: &[u8] = b"Arca/mailbox-of";

/// What a leaf's owner key signs to have the server re-serve the leaf, and
/// how it was given up, to `mailbox` (`leaf_data`), the key a wallet
/// restored from its mnemonic reads with: `SHA256(T ‖ T ‖ genesis_hash ‖ S ‖
/// owner ‖ mailbox)`, `T = SHA256("Arca/mailbox-of")`. The server's
/// (`server::auth::mailbox_binding_digest`).
pub fn mailbox_binding_digest(chain: &Chain, operator: &XOnlyPublicKey, owner: &XOnlyPublicKey, mailbox: &XOnlyPublicKey) -> [u8; 32] {
	let tag = sha256::Hash::hash(MAILBOX_BINDING_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&chain.genesis_bytes());
	e.input(&operator.serialize());
	e.input(&owner.serialize());
	e.input(&mailbox.serialize());
	sha256::Hash::from_engine(e).to_byte_array()
}

/// An output a participation wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wanted {
	Leaf { asset: AssetId, value: u64, template: Template, owner: XOnlyPublicKey, owner_nonce: [u8; 32], exit_delay: RelativeTime },
}

impl Wanted {
	pub fn json(&self) -> Value {
		match self {
			Wanted::Leaf { asset, value, template, owner, owner_nonce, exit_delay } => json!({"leaf": {
				"asset": asset.to_string(), "value": value.to_string(), "template": template.to_string(),
				"owner": hex(&owner.serialize()), "owner_nonce": hex(owner_nonce), "exit_delay_units": exit_delay.units(),
			}}),
		}
	}
}

/// The id of a participation of these parts: what each owner giving up a coin
/// signs. The layout is the server's (`server::participations`).
pub fn participation_id(chain: &Chain, operator: &XOnlyPublicKey, inputs: &[LeafId], outputs: &[Wanted],
	fees: &[(AssetId, u64)], not_before: Option<MedianTime>) -> [u8; 32]
{
	let tag = sha256::Hash::hash(PARTICIPATION_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&chain.genesis_bytes());
	e.input(&operator.serialize());
	e.input(&[inputs.len() as u8]);
	for i in inputs {
		e.input(&i.0);
	}
	e.input(&[outputs.len() as u8]);
	for o in outputs {
		match o {
			Wanted::Leaf { asset, value, template, owner, owner_nonce, exit_delay } => {
				e.input(&[0]);
				e.input(&asset.into_inner().to_byte_array());
				e.input(&value.to_le_bytes());
				e.input(&[template.id(), template.version()]);
				e.input(&owner.serialize());
				e.input(owner_nonce);
				e.input(&exit_delay.units().to_le_bytes());
			},
		}
	}
	e.input(&[fees.len() as u8]);
	for (a, v) in fees {
		e.input(&a.into_inner().to_byte_array());
		e.input(&v.to_le_bytes());
	}
	match not_before {
		Some(t) => {
			e.input(&[1]);
			e.input(&t.to_consensus_u32().to_le_bytes());
		},
		None => e.input(&[0]),
	}
	sha256::Hash::from_engine(e).to_byte_array()
}

/// Whether `base` is a server URL the wallet will speak to: `https://`, or
/// `http://` to this machine alone (a loopback address or `localhost`).
/// Plain HTTP across a network lets anyone on the path answer as the
/// operator: change a status, a fee or a tree, or name another operator
/// key when the wallet is created.
pub fn check_server_url(base: &str) -> Result<(), Error> {
	let lower = base.trim().to_ascii_lowercase();
	if lower.starts_with("https://") {
		return Ok(());
	}
	let Some(rest) = lower.strip_prefix("http://") else {
		return Err(Error::Refused(format!("the server URL {:?} is neither https:// nor http://", base)));
	};
	let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
	let authority = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
	let host = if let Some(v6) = authority.strip_prefix('[') {
		v6.split(']').next().unwrap_or("")
	} else {
		authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority)
	};
	let loopback = host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
	if loopback {
		return Ok(());
	}
	Err(Error::Refused(format!("the server URL {} is plain http to {}, which is not this machine: anyone on the path could answer \
		as the operator; use https://", base, host)))
}

/// The codes with which the server refuses a request outright, with a 4xx
/// status: the request was not taken. A busy server's `rate_limited`, and
/// `not_synced`, `signer_unavailable`, `signer_replaced` and `internal`
/// (5xx), are not among them: the request may be taken later, or may have
/// been.
///
/// They are the server's codes (`server::api::REFUSAL_CODES`) answered with a
/// 4xx, but `rate_limited`: a request to slow down is sent again later. A
/// test compares the two lists.
pub const REFUSALS: &[&str] = &[
	"bad_attestation", "bad_forfeit", "bad_signature", "board_exists", "board_not_final", "board_output", "depth_limit",
	"double_spend", "fee", "forfeit_set", "htlc", "in_use", "invalid_coin", "invalid_leaf", "invalid_record", "invalid_transaction", "invoice",
	"key_reused", "leaf_set", "malformed", "margin", "merge", "no_lightning", "no_lowest_node", "nonce_unknown", "nonce_used", "not_accepted",
	"not_in_round", "not_live", "not_participating", "on_chain", "open_reassignment", "operator_key", "out_of_bounds",
	"release_early", "request_lapsed", "request_too_large", "round_not_final", "salt", "script_reused", "template", "unauthenticated", "unbalanced",
	"unknown_batch", "unknown_board", "unknown_leaf", "unknown_participation", "unknown_payment", "value", "wrong_chain", "wrong_operator",
	"wrong_round",
];

/// The most bindings one `bind_mailbox` takes: the server's bound.
pub const MAX_BINDINGS: usize = 64;

/// The most leaves one `leaf_data` page holds: the server's bound.
pub const LEAF_PAGE: u32 = 100;

/// The server, at its base URL.
#[derive(Debug, Clone)]
pub struct ServerClient {
	base: String,
	timeout: u64,
}

impl ServerClient {
	/// The server at `base`, which must be `https://`, or `http://` to this
	/// machine ([`check_server_url`]).
	pub fn new(base: &str) -> Result<ServerClient, Error> {
		check_server_url(base)?;
		// rustls picks no crypto provider by itself when the build enables
		// more than one; one already installed is kept.
		#[cfg(feature = "arca")]
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		Ok(ServerClient { base: base.trim_end_matches('/').to_string(), timeout: 60 })
	}

	pub fn base(&self) -> &str {
		&self.base
	}

	/// The server's answer to `call`. Only a 4xx carrying one of the
	/// server's refusal codes ([`REFUSALS`]) is a refusal, [`Error::Server`]:
	/// the request was not taken, and nothing it asked for was done. Anything
	/// else (no answer, a timeout, a 5xx, a gateway's page, a code the wallet
	/// does not know, a request to slow down) says nothing of what the server
	/// did, and is [`Error::Unreachable`]: a request that changes something
	/// stays standing, to be posted again byte for byte.
	fn answer(call: &str, r: Result<(i32, String), String>) -> Result<Value, Error> {
		let (status, text) = r.map_err(|e| Error::Unreachable(format!("{}: {}", call, e)))?;
		let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
		if status == 200 {
			return Ok(json);
		}
		let code = json["error"]["code"].as_str().unwrap_or("").to_string();
		let message = json["error"]["message"].as_str().map(|s| s.to_string()).unwrap_or_else(|| text.to_string());
		if (400..500).contains(&status) && REFUSALS.contains(&code.as_str()) {
			return Err(Error::Server { call: call.to_string(), status, code, message });
		}
		Err(Error::Unreachable(format!("{}: the server answered {} {}: {}", call, status, code, message)))
	}

	/// The status and text of one request, over `minreq`.
	#[cfg(feature = "arca")]
	fn send(&self, _method: &str, call: &str, body: Option<&Value>) -> Result<(i32, String), String> {
		let url = format!("{}/v1/{}", self.base, call);
		let request = match body {
			None => minreq::get(url),
			Some(b) => minreq::post(url).with_header("Content-Type", "application/json").with_body(b.to_string()),
		};
		let r = request.with_timeout(self.timeout).send().map_err(|e| e.to_string())?;
		Ok((i32::from(r.status_code), r.as_str().unwrap_or("").to_string()))
	}

	/// The status and text of one request, through the transport the program
	/// registered (`sequentia_ext::platform`).
	#[cfg(not(feature = "arca"))]
	fn send(&self, method: &str, call: &str, body: Option<&Value>) -> Result<(i32, String), String> {
		let url = format!("{}/v1/{}", self.base, call);
		let text = body.map(|b| b.to_string());
		let request = sequentia_ext::platform::Request {
			method,
			url: &url,
			headers: if text.is_some() { vec![("Content-Type", "application/json".into())] } else { vec![] },
			body: text.as_deref(),
			timeout_secs: self.timeout,
		};
		let r = sequentia_ext::platform::http(&request)?;
		Ok((r.status, r.body))
	}

	pub fn get(&self, call: &str) -> Result<Value, Error> {
		Self::answer(call, self.send("GET", call, None))
	}

	pub fn post(&self, call: &str, body: &Value) -> Result<Value, Error> {
		Self::answer(call, self.send("POST", call, Some(body)))
	}

	pub fn info(&self) -> Result<Value, Error> {
		self.get("info")
	}

	pub fn operator_nonce(&self) -> Result<[u8; 32], Error> {
		let v = self.post("operator_nonce", &json!({}))?;
		unhex32(v["operator_nonce"].as_str().unwrap_or(""))
	}

	/// A proof of `key` for `call`, asking `request`.
	pub fn auth(&self, call: &str, key: &Keypair, chain: &Chain, request: &[u8]) -> Result<Value, Error> {
		let v = self.post("challenge", &json!({}))?;
		let challenge = unhex32(v["challenge"].as_str().unwrap_or(""))?;
		let xonly = key.x_only_public_key().0;
		let sig = sign_digest(key, &auth_digest(chain, call, &challenge, &xonly, request), &random32());
		Ok(json!({"key": hex(&xonly.serialize()), "challenge": hex(&challenge), "signature": hex(sig.as_ref())}))
	}

	/// Hands the server the heads of its signer's record the wallet holds
	/// (`{"entry", "hash", "signature"}` each) with a fresh `nonce`, and gets
	/// back the running hash the record holds at each entry and its latest
	/// entry, each signed by the signer, the record's end signed with the
	/// nonce, and whether the signer is stopped, with its proof.
	pub fn witness(&self, heads: &[Value], nonce: &[u8; 32]) -> Result<Value, Error> {
		self.post("witness", &json!({"heads": heads, "nonce": hex(nonce)}))
	}

	/// The coin records in `key`'s mailbox after `after`.
	pub fn mailbox_read(&self, key: &Keypair, chain: &Chain, after: i64, limit: u32) -> Result<Value, Error> {
		let auth = self.auth("mailbox_read", key, chain, &mailbox_read_request(after.max(0) as u64, limit))?;
		self.post("mailbox_read", &json!({"auth": auth, "after": after.to_string(), "limit": limit}))
	}

	/// A page of the leaves the server serves to `key`, after cursor `after`,
	/// up to `limit`: those it owns, those whose owner keys bound them to it,
	/// and the transfer outputs posted to it; `next` names the cursor to read
	/// on from.
	pub fn leaf_data(&self, key: &Keypair, chain: &Chain, after: i64, limit: u32) -> Result<Value, Error> {
		let auth = self.auth("leaf_data", key, chain, &mailbox_read_request(after.max(0) as u64, limit))?;
		self.post("leaf_data", &json!({"auth": auth, "after": after.max(0).to_string(), "limit": limit}))
	}

	/// Binds each leaf of `bindings` (`{owner, mailbox, proof}`, at most
	/// [`MAX_BINDINGS`]) to the mailbox key its owner key signed it to: the
	/// server answers the mailbox each key is bound to.
	pub fn bind_mailbox(&self, bindings: &[Value]) -> Result<Value, Error> {
		self.post("bind_mailbox", &json!({"bindings": bindings}))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn plain_http_only_to_this_machine() {
		for ok in ["https://example.org/arca", "HTTPS://example.org", "http://127.0.0.1:3535", "http://localhost/arca",
			"http://[::1]:80/", "http://127.0.0.5", "http://user@127.0.0.1:1/x"]
		{
			assert!(check_server_url(ok).is_ok(), "{}", ok);
		}
		for bad in ["http://example.org/arca", "http://192.0.2.1:3535", "http://[2001:db8::1]/", "http://127.0.0.1.example.org/",
			"http://localhost.example.org", "ftp://127.0.0.1", "example.org"]
		{
			assert!(check_server_url(bad).is_err(), "{}", bad);
		}
	}
}
