//! Finding an operator in the Sequentia registry.
//!
//! An operator publishes a record of itself in the registry
//! (`ConcatenaLabs/sequentia-registry`): its operator key, the chain's
//! genesis, its API's address, the assets it serves with their fee
//! schedules, its keepers, its exit delays and expiry, and a contact, signed
//! with the operator key ([`arca_covenant::operator_record`]). The registry
//! checks the record against the operator's live `info` when it is listed
//! and on a schedule, and says so beside it (`status`: `ok`, `stale` when
//! the operator has not answered for a while, `mismatched` with the
//! differences when its `info` no longer says what the record does).
//!
//! The wallet trusts the registry for none of that: it checks every
//! record's signature itself and refuses one that does not verify, so a
//! registry can withhold an operator but cannot put words in its mouth. A
//! wallet joined from a record ([`Expected`]) is created only when the
//! server at the record's address shows the record's operator key, chain
//! and keepers, which the wallet then pins as it pins them for a server
//! named by address.

use elements::secp256k1_zkp::XOnlyPublicKey;
use serde_json::{json, Value};

use arca_covenant::operator_record;

use super::client::check_server_url;
use super::Error;

/// What a server joined from a registry record must show before the wallet
/// pins it: the record's operator key, chain and keepers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
	pub operator: XOnlyPublicKey,
	/// The genesis hash, in display order.
	pub genesis: String,
	/// The keepers' keys, sorted, and how many are required.
	pub keepers: (Vec<String>, u64),
}

impl Expected {
	/// What `record`, already verified, says the server must show.
	pub fn of(record: &Value) -> Result<Expected, Error> {
		let (operator, genesis) = operator_record::check(record).map_err(|e| Error::Refused(e.to_string()))?;
		Ok(Expected { operator, genesis, keepers: keepers(&record["keepers"])? })
	}

	/// Refuses a server whose `info` shows another operator key, chain or
	/// set of keepers than the record.
	pub fn check(&self, info: &Value) -> Result<(), Error> {
		let key = info["operator"].as_str().unwrap_or("");
		if key != self.operator.to_string() {
			return Err(Error::Refused(format!("the server at the record's address shows operator key {:?}, not the record's {}: it is \
				not the operator the registry lists", key, self.operator)));
		}
		let genesis = info["genesis_hash"].as_str().unwrap_or("");
		if genesis != self.genesis {
			return Err(Error::Refused(format!("the server shows the chain of genesis {:?}; the record names {}", genesis, self.genesis)));
		}
		let shown = keepers(&info["keepers"])?;
		if shown != self.keepers {
			return Err(Error::Refused(format!("the server shows keepers {:?}, {} required; the record names {:?}, {} required", shown.0,
				shown.1, self.keepers.0, self.keepers.1)));
		}
		Ok(())
	}
}

fn keepers(k: &Value) -> Result<(Vec<String>, u64), Error> {
	let mut keys = k["keys"].as_array().ok_or_else(|| Error::Parse("the keepers: no list of keys".into()))?
		.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| Error::Parse("a keeper's key is not text".into())))
		.collect::<Result<Vec<String>, Error>>()?;
	keys.sort();
	let required = k["required"].as_u64().ok_or_else(|| Error::Parse("the keepers: no number required".into()))?;
	Ok((keys, required))
}

/// The registry, at its base URL.
#[derive(Debug, Clone)]
pub struct RegistryClient {
	base: String,
	timeout: u64,
}

impl RegistryClient {
	/// The registry at `base`, which must be `https://`, or `http://` to this
	/// machine, as for a server.
	pub fn new(base: &str) -> Result<RegistryClient, Error> {
		check_server_url(base)?;
		#[cfg(feature = "arca")]
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
		Ok(RegistryClient { base: base.trim_end_matches('/').to_string(), timeout: 30 })
	}

	pub fn base(&self) -> &str {
		&self.base
	}

	#[cfg(feature = "arca")]
	fn fetch(&self, path: &str) -> Result<(i32, String), String> {
		let r = minreq::get(format!("{}{}", self.base, path)).with_timeout(self.timeout).send().map_err(|e| e.to_string())?;
		Ok((i32::from(r.status_code), r.as_str().unwrap_or("").to_string()))
	}

	#[cfg(not(feature = "arca"))]
	fn fetch(&self, path: &str) -> Result<(i32, String), String> {
		let url = format!("{}{}", self.base, path);
		let request = sequentia_ext::platform::Request { method: "GET", url: &url, headers: vec![], body: None, timeout_secs: self.timeout };
		let r = sequentia_ext::platform::http(&request)?;
		Ok((r.status, r.body))
	}

	fn get(&self, path: &str) -> Result<Value, Error> {
		let (status, text) = self.fetch(path).map_err(|e| Error::Unreachable(format!("the registry {}: {}", self.base, e)))?;
		let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
		match status {
			200 => Ok(v),
			404 => Err(Error::Refused(format!("the registry {} lists no {}", self.base, path.trim_start_matches('/')))),
			s => Err(Error::Unreachable(format!("the registry {} answered {} to {}: {}", self.base, s, path,
				v["error"].as_str().unwrap_or(&text)))),
		}
	}

	/// The operators the registry lists, each record's signature checked
	/// here: those that verify, with what the registry says of each, and
	/// those refused, with the reason. With `genesis`, only the operators
	/// of that chain.
	pub fn operators(&self, genesis: Option<&str>) -> Result<Value, Error> {
		let list = self.get("/operators")?;
		let entries = list.as_array().ok_or_else(|| Error::Parse("the registry's list of operators is not a list".into()))?;
		let mut listed = vec![];
		let mut refused = vec![];
		for e in entries {
			match listing(e) {
				Ok(v) if genesis.is_some_and(|g| v["genesis_hash"] != g) => {},
				Ok(v) => listed.push(v),
				Err(why) => refused.push(json!({"operator": e["record"]["operator"], "reason": why.to_string()})),
			}
		}
		Ok(json!({"registry": self.base, "operators": listed, "refused": refused}))
	}

	/// The record of operator `key`, its signature checked here, and what the
	/// registry says of it. Refused when it does not verify, when it is the
	/// record of another key, and when the registry finds that the
	/// operator's `info` no longer matches it.
	pub fn operator(&self, key: &str) -> Result<(Value, Value), Error> {
		let key = key.trim().to_lowercase();
		if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
			return Err(Error::Parse(format!("the operator key {:?}: 64 hex characters", key)));
		}
		let e = self.get(&format!("/operators/{}", key))?;
		let v = listing(&e)?;
		if v["operator"] != key.as_str() {
			return Err(Error::Refused(format!("the registry answered for operator {} the record of {}", key, v["operator"])));
		}
		if v["status"] == "mismatched" {
			return Err(Error::Refused(format!("the registry finds that the operator's info no longer matches its signed record ({}): \
				the operator has changed what it published without signing a new record; nothing is joined", v["differences"])));
		}
		Ok((e["record"].clone(), v))
	}
}

/// One entry of the registry's list, its signature checked: what a wallet
/// shows of it.
fn listing(e: &Value) -> Result<Value, Error> {
	let record = &e["record"];
	let sig = e["signature"].as_str().unwrap_or("");
	let (key, genesis) = operator_record::verify(record, sig).map_err(|err| Error::Refused(err.to_string()))?;
	let assets: Vec<Value> = record["assets"].as_array().cloned().unwrap_or_default().iter().map(|a| a["asset"].clone()).collect();
	Ok(json!({
		"operator": key.to_string(), "genesis_hash": genesis, "api": record["api"], "assets": assets, "keepers": record["keepers"],
		"exit_delay_units": record["exit_delay_units"], "expiry": record["expiry"], "contact": record["contact"],
		"issued_at": record["issued_at"], "signature": "verified",
		"status": e["status"], "checked_at": e["checked_at"], "differences": e["differences"],
	}))
}

#[cfg(test)]
mod tests {
	use super::*;
	use elements::hashes::{sha256, Hash};
	use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey};

	fn key() -> Keypair {
		let sk = SecretKey::from_slice(&sha256::Hash::hash(b"Arca test vector key/S").to_byte_array()).unwrap();
		Keypair::from_secret_key(&Secp256k1::new(), &sk)
	}

	const GENESIS: &str = "16af270696dbd3a65ed61a2f48459c8d8e9110c0c9937938109e7d7c87e8e42c";

	fn record(keepers: Value) -> Value {
		json!({
			"arca_operator": 1, "operator": key().x_only_public_key().0.to_string(), "genesis_hash": GENESIS,
			"api": "https://example.org/arca", "assets": [], "keepers": keepers, "exit_delay_units": {"min": 1, "max": 2},
			"expiry": {"batch_lifetime_seconds": 2419200, "exit_deadline_seconds": 259200},
			"templates": {"version": 1, "list": ["vtxo-1"]}, "contact": {"name": "x", "domain": "example.org"}, "issued_at": 1,
		})
	}

	fn entry(r: &Value, status: &str) -> Value {
		let sig = operator_record::sign(&key(), r, GENESIS, &[0; 32]).unwrap();
		let hex: String = sig.as_ref().iter().map(|b| format!("{:02x}", b)).collect();
		json!({"record": r, "signature": hex, "status": status, "checked_at": 5})
	}

	#[test]
	fn a_listing_is_shown_only_when_its_signature_verifies() {
		let r = record(json!({"keys": [], "required": 0}));
		let v = listing(&entry(&r, "ok")).unwrap();
		assert_eq!(v["operator"], key().x_only_public_key().0.to_string());
		assert_eq!(v["status"], "ok");
		let mut tampered = entry(&r, "ok");
		tampered["record"]["api"] = json!("https://thief.example/arca");
		assert!(listing(&tampered).unwrap_err().to_string().contains("not the operator key's over the record"));
	}

	#[test]
	fn a_server_must_show_the_records_key_chain_and_keepers() {
		let a = "1111111111111111111111111111111111111111111111111111111111111111";
		let b = "2222222222222222222222222222222222222222222222222222222222222222";
		let r = record(json!({"keys": [b, a], "required": 1}));
		let e = Expected::of(&r).unwrap();
		let info = json!({"operator": key().x_only_public_key().0.to_string(), "genesis_hash": GENESIS,
			"keepers": {"keys": [a, b], "required": 1}});
		e.check(&info).unwrap();
		for (k, v, why) in [("operator", json!(a), "shows operator key"), ("genesis_hash", json!(b), "chain of genesis"),
			("keepers", json!({"keys": [a], "required": 1}), "shows keepers")]
		{
			let mut i = info.clone();
			i[k] = v;
			assert!(e.check(&i).unwrap_err().to_string().contains(why), "{}", k);
		}
	}
}
