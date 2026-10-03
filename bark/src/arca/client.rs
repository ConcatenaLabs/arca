//! The wallet's client of the Arca server: JSON over HTTPS, every call under
//! `/v1/`. Plain HTTP is spoken only to this machine (a loopback address or
//! `localhost`), as to a server behind a local TLS proxy or in a test.
//!
//! The calls that read a key's mailbox or leaves are authenticated with a
//! challenge from the server, signed with the key (BIP340) over the tagged
//! hash `SHA256(T ‖ T ‖ genesis_hash ‖ len(call) ‖ call ‖ challenge ‖ key)`,
//! `T = SHA256("Arca/auth")`. A transfer is authenticated by its owners'
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

/// The digest `key` signs to authenticate `call` with `challenge`.
pub fn auth_digest(chain: &Chain, call: &str, challenge: &[u8; 32], key: &XOnlyPublicKey) -> [u8; 32] {
	let tag = sha256::Hash::hash(AUTH_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&chain.genesis_bytes());
	e.input(&[call.len() as u8]);
	e.input(call.as_bytes());
	e.input(challenge);
	e.input(&key.serialize());
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
/// `not_synced`, `signer_unavailable` and `internal` (5xx), are not among
/// them: the request may be taken later, or may have been.
///
/// They are the server's codes (`server::api::REFUSAL_CODES`) answered with a
/// 4xx, but `rate_limited`: a request to slow down is sent again later. A
/// test compares the two lists.
pub const REFUSALS: &[&str] = &[
	"bad_attestation", "bad_forfeit", "bad_signature", "board_exists", "board_not_final", "board_output", "depth_limit",
	"double_spend", "fee", "forfeit_set", "in_use", "invalid_coin", "invalid_leaf", "invalid_record", "invalid_transaction",
	"key_reused", "leaf_set", "malformed", "margin", "merge", "no_lowest_node", "nonce_unknown", "nonce_used", "not_accepted",
	"not_in_round", "not_live", "not_participating", "on_chain", "open_reassignment", "operator_key", "out_of_bounds",
	"release_early", "request_too_large", "round_not_final", "salt", "script_reused", "template", "unauthenticated", "unbalanced",
	"unknown_batch", "unknown_board", "unknown_leaf", "unknown_participation", "value", "wrong_chain", "wrong_operator",
	"wrong_round",
];

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
	fn answer(call: &str, r: Result<minreq::Response, minreq::Error>) -> Result<Value, Error> {
		let r = r.map_err(|e| Error::Unreachable(format!("{}: {}", call, e)))?;
		let text = r.as_str().unwrap_or("");
		let json: Value = serde_json::from_str(text).unwrap_or(Value::Null);
		if r.status_code == 200 {
			return Ok(json);
		}
		let code = json["error"]["code"].as_str().unwrap_or("").to_string();
		let message = json["error"]["message"].as_str().map(|s| s.to_string()).unwrap_or_else(|| text.to_string());
		if (400..500).contains(&r.status_code) && REFUSALS.contains(&code.as_str()) {
			return Err(Error::Server { call: call.to_string(), status: r.status_code as i32, code, message });
		}
		Err(Error::Unreachable(format!("{}: the server answered {} {}: {}", call, r.status_code, code, message)))
	}

	pub fn get(&self, call: &str) -> Result<Value, Error> {
		Self::answer(call, minreq::get(format!("{}/v1/{}", self.base, call)).with_timeout(self.timeout).send())
	}

	pub fn post(&self, call: &str, body: &Value) -> Result<Value, Error> {
		Self::answer(call, minreq::post(format!("{}/v1/{}", self.base, call))
			.with_header("Content-Type", "application/json")
			.with_body(body.to_string()).with_timeout(self.timeout).send())
	}

	pub fn info(&self) -> Result<Value, Error> {
		self.get("info")
	}

	pub fn operator_nonce(&self) -> Result<[u8; 32], Error> {
		let v = self.post("operator_nonce", &json!({}))?;
		unhex32(v["operator_nonce"].as_str().unwrap_or(""))
	}

	/// A proof of `key` for `call`.
	pub fn auth(&self, call: &str, key: &Keypair, chain: &Chain) -> Result<Value, Error> {
		let v = self.post("challenge", &json!({}))?;
		let challenge = unhex32(v["challenge"].as_str().unwrap_or(""))?;
		let xonly = key.x_only_public_key().0;
		let sig = sign_digest(key, &auth_digest(chain, call, &challenge, &xonly), &random32());
		Ok(json!({"key": hex(&xonly.serialize()), "challenge": hex(&challenge), "signature": hex(sig.as_ref())}))
	}

	/// The coin records in `key`'s mailbox after `after`.
	pub fn mailbox_read(&self, key: &Keypair, chain: &Chain, after: i64, limit: u32) -> Result<Value, Error> {
		let auth = self.auth("mailbox_read", key, chain)?;
		self.post("mailbox_read", &json!({"auth": auth, "after": after.to_string(), "limit": limit}))
	}

	/// The leaves `key` owns, as the server holds them.
	pub fn leaf_data(&self, key: &Keypair, chain: &Chain) -> Result<Value, Error> {
		let auth = self.auth("leaf_data", key, chain)?;
		self.post("leaf_data", &json!({"auth": auth}))
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
