//! The wallet's client of the Arca server: JSON over HTTPS, every call under
//! `/v1/`. Plain HTTP is spoken only to this machine (a loopback address or
//! `localhost`), as to a server behind a local TLS proxy or in a test.
//!
//! The calls that read a key's mailbox or leaves are authenticated with a
//! challenge from the server, signed with the key (BIP340) over the tagged
//! hash `SHA256(T ‖ T ‖ genesis_hash ‖ len(call) ‖ call ‖ challenge ‖ key)`,
//! `T = SHA256("Arca/auth")`. A transfer is authenticated by its owners'
//! signatures over the transfer itself, a participation by each owner's
//! attestation over the participation's id. There is no bearer token.
//!
//! Every refusal the server makes comes back as [`Error::Server`], with its
//! HTTP status, its stable code and its sentence.

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

	fn answer(call: &str, r: Result<minreq::Response, minreq::Error>) -> Result<Value, Error> {
		let r = r.map_err(|e| Error::Unreachable(format!("{}: {}", call, e)))?;
		let text = r.as_str().unwrap_or("");
		let json: Value = serde_json::from_str(text).unwrap_or(Value::Null);
		if r.status_code == 200 {
			return Ok(json);
		}
		let code = json["error"]["code"].as_str().unwrap_or("").to_string();
		let message = json["error"]["message"].as_str().map(|s| s.to_string()).unwrap_or_else(|| text.to_string());
		Err(Error::Server { call: call.to_string(), status: r.status_code as i32, code, message })
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
