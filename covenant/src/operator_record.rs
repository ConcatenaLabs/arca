//! The operator record: what an Arca operator publishes about itself in the
//! Sequentia registry, signed with its operator key `S`.
//!
//! The registry (`ConcatenaLabs/sequentia-registry`, `operators.js`) defines
//! the record and checks every field of it against the operator's live
//! `info`; a wallet reads the record to find an operator and to know, before
//! it trusts a server, which key, chain and keepers that server must show.
//! This module holds the part both sides of the signature need:
//!
//! - the record's canonical form ([`canonical`]): its JSON with every
//!   object's keys sorted, no white space, strings of printable ASCII only
//!   and numbers that are whole and at most 2^53 - 1, so that the
//!   registry's JavaScript and this code write the same bytes;
//! - what the key signs ([`digest`]): the BIP340 tagged hash, tag
//!   [`OPERATOR_RECORD_TAG`], of those bytes;
//! - the checks a signer makes before it signs one, and a reader before it
//!   believes one ([`check`], [`sign`], [`verify`]).
//!
//! The tag is used by nothing else the operator key signs: every other
//! digest it signs is a sighash or carries an `Arca/` tag, so a record's
//! signature authorises nothing but the record, and the record names the
//! key and the chain it is for, so it is good for that operator on that
//! chain alone. A record carries the time it was made (`issued_at`); the
//! registry keeps the latest a key has signed and refuses an older one, so
//! an old record cannot be played back over a newer.

use std::fmt::Write as _;

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::{Keypair, XOnlyPublicKey};
use serde_json::Value;

use crate::sign::{sign_digest, verify_digest};

/// The tag of the hash the operator key signs over its record.
pub const OPERATOR_RECORD_TAG: &[u8] = b"sequentia-registry/arca-operator/v1";

/// The record's version, in its `arca_operator` field.
pub const VERSION: u64 = 1;

/// Every field of a record of [`VERSION`]: a record with any other is
/// refused, and one without any of these.
pub const FIELDS: &[&str] = &[
	"api", "arca_operator", "assets", "contact", "exit_delay_units", "expiry", "genesis_hash", "issued_at", "keepers", "operator",
	"templates",
];

/// The largest number a record holds: JavaScript's largest exact integer.
pub const MAX_NUMBER: u64 = (1 << 53) - 1;

/// Why a record is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OperatorRecordError {
	#[error("the record is not in canonical form: {0}")]
	NotCanonical(String),
	#[error("the record: {0}")]
	Field(String),
	#[error("the record is for operator {record}, not {key}")]
	OtherOperator { record: String, key: String },
	#[error("the record is for the chain of genesis {record}, not {genesis}")]
	OtherChain { record: String, genesis: String },
	#[error("the signature is not the operator key's over the record (BIP340, tag {})", String::from_utf8_lossy(OPERATOR_RECORD_TAG))]
	BadSignature,
}

/// The canonical form of `v`: keys sorted by their bytes, no white space,
/// strings of printable ASCII (0x20 to 0x7e) with only `"` and `\` escaped,
/// whole numbers from 0 to [`MAX_NUMBER`], `true` and `false`; no `null`.
pub fn canonical(v: &Value) -> Result<String, OperatorRecordError> {
	let mut out = String::new();
	write_canonical(v, &mut out, "the record")?;
	Ok(out)
}

fn write_string(s: &str, out: &mut String, at: &str) -> Result<(), OperatorRecordError> {
	if !s.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
		return Err(OperatorRecordError::NotCanonical(format!("{}: text other than printable ASCII", at)));
	}
	out.push('"');
	for c in s.chars() {
		if c == '"' || c == '\\' {
			out.push('\\');
		}
		out.push(c);
	}
	out.push('"');
	Ok(())
}

fn write_canonical(v: &Value, out: &mut String, at: &str) -> Result<(), OperatorRecordError> {
	match v {
		Value::Null => return Err(OperatorRecordError::NotCanonical(format!("{}: null", at))),
		Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
		Value::Number(n) => match n.as_u64() {
			Some(u) if u <= MAX_NUMBER => {
				let _ = write!(out, "{}", u);
			},
			_ => return Err(OperatorRecordError::NotCanonical(format!("{}: {} is not a whole number from 0 to 2^53 - 1", at, n))),
		},
		Value::String(s) => write_string(s, out, at)?,
		Value::Array(a) => {
			out.push('[');
			for (i, e) in a.iter().enumerate() {
				if i > 0 {
					out.push(',');
				}
				write_canonical(e, out, &format!("{}[{}]", at, i))?;
			}
			out.push(']');
		},
		Value::Object(m) => {
			let mut keys: Vec<&String> = m.keys().collect();
			keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
			out.push('{');
			for (i, k) in keys.into_iter().enumerate() {
				if i > 0 {
					out.push(',');
				}
				write_string(k, out, at)?;
				out.push(':');
				write_canonical(&m[k], out, &format!("{}.{}", at, k))?;
			}
			out.push('}');
		},
	}
	Ok(())
}

/// What the operator key signs: `SHA256(T ‖ T ‖ canonical(record))`,
/// `T = SHA256(`[`OPERATOR_RECORD_TAG`]`)`.
pub fn digest(record: &Value) -> Result<[u8; 32], OperatorRecordError> {
	let bytes = canonical(record)?;
	let tag = sha256::Hash::hash(OPERATOR_RECORD_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(bytes.as_bytes());
	Ok(sha256::Hash::from_engine(e).to_byte_array())
}

fn hex64(v: &Value, what: &str) -> Result<String, OperatorRecordError> {
	match v.as_str() {
		Some(s) if s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) => Ok(s.to_string()),
		_ => Err(OperatorRecordError::Field(format!("{}: 64 lower-case hex characters", what))),
	}
}

/// Checks the record's frame: an object of exactly [`FIELDS`], version
/// [`VERSION`], an operator key, a genesis hash, the API's address, the
/// time it was made, and a canonical form. Returns the operator key and the
/// genesis hash (display order) it names. The fields inside (assets, fees,
/// keepers, delays, contact) are the registry's to check against `info`.
pub fn check(record: &Value) -> Result<(XOnlyPublicKey, String), OperatorRecordError> {
	let m = record.as_object().ok_or_else(|| OperatorRecordError::Field("not an object".into()))?;
	for k in m.keys() {
		if !FIELDS.contains(&k.as_str()) {
			return Err(OperatorRecordError::Field(format!("unknown field {}", k)));
		}
	}
	for k in FIELDS {
		if !m.contains_key(*k) {
			return Err(OperatorRecordError::Field(format!("{} is missing", k)));
		}
	}
	if record["arca_operator"].as_u64() != Some(VERSION) {
		return Err(OperatorRecordError::Field(format!("arca_operator: {}", VERSION)));
	}
	let key = hex64(&record["operator"], "operator")?;
	let key = XOnlyPublicKey::from_slice(&unhex(&key)).map_err(|e| OperatorRecordError::Field(format!("operator: {}", e)))?;
	let genesis = hex64(&record["genesis_hash"], "genesis_hash")?;
	if !record["api"].as_str().is_some_and(|a| a.starts_with("https://") || a.starts_with("http://")) {
		return Err(OperatorRecordError::Field("api: the server's https:// address".into()));
	}
	if record["issued_at"].as_u64().is_none() {
		return Err(OperatorRecordError::Field("issued_at: unix seconds".into()));
	}
	canonical(record)?;
	Ok((key, genesis))
}

/// Signs `record` with `keypair`, the operator key, after [`check`]: the
/// record must name this key and the chain of `genesis` (display order).
pub fn sign(keypair: &Keypair, record: &Value, genesis: &str, aux: &[u8; 32]) -> Result<Signature, OperatorRecordError> {
	let (key, at) = check(record)?;
	let own = keypair.x_only_public_key().0;
	if key != own {
		return Err(OperatorRecordError::OtherOperator { record: key.to_string(), key: own.to_string() });
	}
	if at != genesis {
		return Err(OperatorRecordError::OtherChain { record: at, genesis: genesis.to_string() });
	}
	Ok(sign_digest(keypair, &digest(record)?, aux))
}

/// Checks `record` ([`check`]) and that `signature` (hex) is its operator
/// key's over it. Returns the key and the genesis hash it names.
pub fn verify(record: &Value, signature: &str) -> Result<(XOnlyPublicKey, String), OperatorRecordError> {
	let (key, genesis) = check(record)?;
	let bytes = unhex(signature);
	let sig = (signature.len() == 128).then(|| Signature::from_slice(&bytes).ok()).flatten().ok_or(OperatorRecordError::BadSignature)?;
	if !verify_digest(&sig, &digest(record)?, &key) {
		return Err(OperatorRecordError::BadSignature);
	}
	Ok((key, genesis))
}

/// Lower-case hex of what was checked to be hex; anything else gives no
/// bytes, which every caller refuses.
fn unhex(s: &str) -> Vec<u8> {
	if s.len() % 2 != 0 {
		return vec![];
	}
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16)).collect::<Result<Vec<u8>, _>>().unwrap_or_default()
}

#[cfg(test)]
mod tests {
	use super::*;
	use elements::secp256k1_zkp::{Secp256k1, SecretKey};
	use serde_json::json;

	fn key() -> Keypair {
		let sk = SecretKey::from_slice(&sha256::Hash::hash(b"Arca test vector key/S").to_byte_array()).unwrap();
		Keypair::from_secret_key(&Secp256k1::new(), &sk)
	}

	const GENESIS: &str = "16af270696dbd3a65ed61a2f48459c8d8e9110c0c9937938109e7d7c87e8e42c";

	fn record() -> Value {
		json!({
			"arca_operator": 1,
			"operator": key().x_only_public_key().0.to_string(),
			"genesis_hash": GENESIS,
			"api": "https://example.org/arca",
			"assets": [{"asset": "e39685e7c2e1ad7dd3e2b4b12ae2a1a3c0b1a7b3b3a1b2c3d4e5f60718293a4b", "min_leaf": "1000",
				"rate": {"source": "node", "max_age_seconds": 600},
				"fees": {"refresh_ppm": 5000, "refresh_base": "200", "offboard_ppm": 1000, "offboard_base_value": "100", "lightning_ppm": 0,
					"lightning_base": "0"}}],
			"keepers": {"keys": [], "required": 0},
			"exit_delay_units": {"min": 253, "max": 338},
			"expiry": {"batch_lifetime_seconds": 2419200, "exit_deadline_seconds": 259200},
			"templates": {"version": 1, "list": ["vtxo-1", "board-1", "htlc-1"]},
			"contact": {"name": "Example \"Ops\" \\ test", "domain": "example.org"},
			"issued_at": 1800000000u64,
		})
	}

	#[test]
	fn the_canonical_form_sorts_keys_and_refuses_what_javascript_writes_otherwise() {
		assert_eq!(canonical(&json!({"b": [1, true, "x\"\\/"], "a": {"d": 0, "c": false}})).unwrap(),
			r#"{"a":{"c":false,"d":0},"b":[1,true,"x\"\\/"]}"#);
		for bad in [json!({"a": null}), json!({"a": 1.5}), json!({"a": -1}), json!({"a": 9007199254740992u64}), json!({"a": "é"}),
			json!({"a": "\n"}), json!({"é": 1})]
		{
			assert!(matches!(canonical(&bad), Err(OperatorRecordError::NotCanonical(_))), "{}", bad);
		}
		assert!(canonical(&json!({"a": 9007199254740991u64})).is_ok());
	}

	/// The digest the registry's JavaScript computes for the same record
	/// (`test/operators.test.js` in sequentia-registry holds this value and
	/// verifies a signature this module made over it).
	#[test]
	fn the_digest_is_the_tagged_hash_of_the_canonical_form() {
		let r = record();
		let d: String = digest(&r).unwrap().iter().map(|b| format!("{:02x}", b)).collect();
		assert_eq!(d, "6f1188f5ef76f91831bbffe2910fd0b5cb38b0f889d91c2f8d7be2deda9c58dc");
		let tag = sha256::Hash::hash(OPERATOR_RECORD_TAG);
		let mut pre = tag.to_byte_array().to_vec();
		pre.extend(tag.to_byte_array());
		pre.extend(canonical(&r).unwrap().as_bytes());
		assert_eq!(digest(&r).unwrap(), sha256::Hash::hash(&pre).to_byte_array());
	}

	#[test]
	fn a_signed_record_verifies_and_an_edited_one_does_not() {
		let r = record();
		let sig = sign(&key(), &r, GENESIS, &[0; 32]).unwrap();
		let hex: String = sig.as_ref().iter().map(|b| format!("{:02x}", b)).collect();
		assert_eq!(verify(&r, &hex).unwrap().0, key().x_only_public_key().0);
		let mut edited = r.clone();
		edited["api"] = json!("https://thief.example/arca");
		assert_eq!(verify(&edited, &hex).unwrap_err(), OperatorRecordError::BadSignature);
		assert_eq!(verify(&r, &hex[..126]).unwrap_err(), OperatorRecordError::BadSignature);
		assert_eq!(verify(&r, "zz").unwrap_err(), OperatorRecordError::BadSignature);
	}

	#[test]
	fn the_signer_signs_only_its_own_key_on_its_own_chain() {
		let mut r = record();
		let other = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[7; 32]).unwrap());
		assert!(matches!(sign(&other, &r, GENESIS, &[0; 32]), Err(OperatorRecordError::OtherOperator { .. })));
		assert!(matches!(sign(&key(), &r, &"00".repeat(32), &[0; 32]), Err(OperatorRecordError::OtherChain { .. })));
		r["extra"] = json!(1);
		assert_eq!(sign(&key(), &r, GENESIS, &[0; 32]).unwrap_err(), OperatorRecordError::Field("unknown field extra".into()));
		let mut r = record();
		r.as_object_mut().unwrap().remove("contact");
		assert_eq!(check(&r).unwrap_err(), OperatorRecordError::Field("contact is missing".into()));
		let mut r = record();
		r["arca_operator"] = json!(2);
		assert!(check(&r).is_err());
	}
}
