//! The leaf record's JSON form, for the server interface.
//!
//! The fields are the binary form's ([`crate::record`]), named:
//!
//! ```text
//! version            2
//! template           "vtxo-1"
//! owner              hex
//! owner_nonce        hex
//! operator_nonce     hex
//! exit_delay_units   512-second units
//! asset              hex, display order
//! value              decimal string
//! unlock_hash        hex
//! entry_reserve      decimal string
//! genesis_hash       hex, display order
//! operator           hex
//! token              hex, display order
//! notice_units       512-second units
//! burn               true or false
//! expiries           [median times]
//! path               [levels, from the batch output down]
//!   index            the index on the leaf's path
//!   reserve          decimal string
//!   siblings         [{"value": decimal string, "program": hex}]
//!   member_index     above the lowest level: the owner's index in the member list
//!   member_path      above the lowest level: [hex], bottom level first
//!   owners           at the lowest level only: [hex]
//! ```
//!
//! Asset ids, the token and the genesis hash are hex in display order, the
//! order the node's RPCs print; every other byte string is hex in its own
//! order. Hex is lower case. Amounts are decimal strings without leading zeros,
//! so no reader rounds them; every other number is a JSON integer.
//!
//! The reader is strict: it refuses a missing, unknown or misplaced field, a
//! repeated key, a value of the wrong type, and anything the binary reader
//! refuses. The canonical text ([`canonical_text`]) has its keys sorted by
//! byte and no whitespace, so one record has exactly one text.

use std::fmt;

use elements::hashes::Hash;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, BlockHash};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::clock::{ClockSchedule, MAX_STEPS};
use crate::gate::{MemberProof, MAX_DEPTH};
use crate::message::Chain;
use crate::node::MAX_CHILDREN;
use crate::record::{
	hex32, LeafRecord, LowestLevel, RecordError, Sibling, Template, UpperLevel, MAX_LEVELS, RECORD_VERSION,
};
use crate::script::asset_bytes;
use crate::time::{MedianTime, RelativeTime};

pub(crate) fn hex(b: &[u8]) -> String {
	let mut s = String::with_capacity(2 * b.len());
	for x in b {
		s.push_str(&format!("{:02x}", x));
	}
	s
}

pub(crate) fn display(b: [u8; 32]) -> String {
	let mut r = b;
	r.reverse();
	hex(&r)
}

fn siblings_json(s: &[Sibling]) -> Value {
	Value::Array(s.iter().map(|s| {
		let mut o = Map::new();
		o.insert("value".into(), Value::String(s.value.to_string()));
		o.insert("program".into(), Value::String(hex(&s.program)));
		Value::Object(o)
	}).collect())
}

impl LeafRecord {
	/// The JSON form. Refuses a record that [`LeafRecord::check`] refuses.
	pub fn to_json(&self) -> Result<Value, RecordError> {
		self.check()?;
		let mut path = vec![];
		for u in &self.upper {
			let mut o = Map::new();
			o.insert("index".into(), u.index.into());
			o.insert("reserve".into(), Value::String(u.reserve.to_string()));
			o.insert("siblings".into(), siblings_json(&u.siblings));
			o.insert("member_index".into(), u.member.index.into());
			o.insert("member_path".into(), Value::Array(u.member.siblings.iter().map(|s| Value::String(hex(s))).collect()));
			path.push(Value::Object(o));
		}
		let l = &self.lowest;
		let mut o = Map::new();
		o.insert("index".into(), l.index.into());
		o.insert("reserve".into(), Value::String(l.reserve.to_string()));
		o.insert("siblings".into(), siblings_json(&l.siblings));
		o.insert("owners".into(), Value::Array(l.owners.iter().map(|k| Value::String(hex(&k.serialize()))).collect()));
		path.push(Value::Object(o));

		let mut m = Map::new();
		m.insert("version".into(), RECORD_VERSION.into());
		m.insert("template".into(), Value::String(self.template.to_string()));
		m.insert("owner".into(), Value::String(hex(&self.owner.serialize())));
		m.insert("owner_nonce".into(), Value::String(hex(&self.owner_nonce)));
		m.insert("operator_nonce".into(), Value::String(hex(&self.operator_nonce)));
		m.insert("exit_delay_units".into(), self.exit_delay.units().into());
		m.insert("asset".into(), Value::String(display(asset_bytes(self.asset))));
		m.insert("value".into(), Value::String(self.value.to_string()));
		m.insert("unlock_hash".into(), Value::String(hex(&self.unlock_hash)));
		m.insert("entry_reserve".into(), Value::String(self.entry_reserve.to_string()));
		m.insert("genesis_hash".into(), Value::String(display(self.chain.genesis_bytes())));
		m.insert("operator".into(), Value::String(hex(&self.schedule.operator.serialize())));
		m.insert("token".into(), Value::String(display(asset_bytes(self.schedule.token))));
		m.insert("notice_units".into(), self.schedule.notice.units().into());
		m.insert("burn".into(), Value::Bool(self.burn));
		m.insert("expiries".into(), Value::Array(self.schedule.expiries().iter().map(|e| e.to_consensus_u32().into()).collect()));
		m.insert("path".into(), Value::Array(path));
		Ok(Value::Object(m))
	}

	/// The canonical JSON text.
	pub fn to_json_string(&self) -> Result<String, RecordError> {
		Ok(canonical_text(&self.to_json()?))
	}

	/// Reads the JSON text of a record. Refuses a repeated key and trailing
	/// characters as well as everything [`LeafRecord::from_json`] refuses.
	pub fn from_json_str(text: &str) -> Result<LeafRecord, RecordError> {
		LeafRecord::from_json(&strict(text)?)
	}

	/// Reads the JSON form.
	pub fn from_json(v: &Value) -> Result<LeafRecord, RecordError> {
		let m = object(v, "record", &[
			"version", "template", "owner", "owner_nonce", "operator_nonce", "exit_delay_units", "asset", "value",
			"unlock_hash", "entry_reserve", "genesis_hash", "operator", "token", "notice_units", "burn", "expiries", "path",
		])?;
		let version = int(m, "version", u64::MAX)?;
		if version != RECORD_VERSION as u64 {
			return Err(RecordError::Version(version));
		}
		let template: Template = string(m, "template")?.parse()?;
		let owner = key(m, "owner")?;
		let owner_nonce = bytes32(m, "owner_nonce")?;
		let operator_nonce = bytes32(m, "operator_nonce")?;
		let exit_delay = units(m, "exit_delay_units")?;
		let asset = AssetId::from_byte_array(display32(m, "asset")?);
		let value = amount(m, "value")?;
		let unlock_hash = bytes32(m, "unlock_hash")?;
		let entry_reserve = amount(m, "entry_reserve")?;
		let chain = Chain::new(BlockHash::from_byte_array(display32(m, "genesis_hash")?));
		let operator = key(m, "operator")?;
		let token = AssetId::from_byte_array(display32(m, "token")?);
		let notice = units(m, "notice_units")?;
		let burn = m["burn"].as_bool().ok_or_else(|| RecordError::Type("burn".into()))?;
		let expiries = array(m, "expiries", MAX_STEPS)?;
		let mut times = Vec::with_capacity(expiries.len());
		for e in expiries {
			let t = e.as_u64().filter(|t| *t <= u32::MAX as u64).ok_or_else(|| RecordError::Type("expiries".into()))?;
			times.push(MedianTime::from_consensus(t as u32).map_err(crate::encode::DecodeError::from)?);
		}
		let schedule = ClockSchedule::new_unchecked(token, operator, notice, times).map_err(RecordError::Schedule)?;

		let path = array(m, "path", MAX_LEVELS)?;
		if path.is_empty() {
			return Err(RecordError::Levels(0));
		}
		let mut upper = Vec::with_capacity(path.len() - 1);
		for (level, p) in path[..path.len() - 1].iter().enumerate() {
			let ctx = format!("path[{}]", level);
			let o = object(p, &ctx, &["index", "reserve", "siblings", "member_index", "member_path"])?;
			let (index, reserve, siblings) = level_common(o, &ctx)?;
			let member_index = int(o, "member_index", u32::MAX as u64)? as u32;
			let mp = array(o, "member_path", MAX_DEPTH)?;
			let mut path = Vec::with_capacity(mp.len());
			for s in mp {
				path.push(s.as_str().and_then(hex32).ok_or_else(|| RecordError::Hex(format!("{}.member_path", ctx)))?);
			}
			upper.push(UpperLevel { index, reserve, siblings, member: MemberProof { index: member_index, siblings: path } });
		}
		let ctx = format!("path[{}]", path.len() - 1);
		let o = object(&path[path.len() - 1], &ctx, &["index", "reserve", "siblings", "owners"])?;
		let (index, reserve, siblings) = level_common(o, &ctx)?;
		let mut owners = vec![];
		for k in array(o, "owners", MAX_CHILDREN)? {
			let b = k.as_str().and_then(hex32).ok_or_else(|| RecordError::Hex(format!("{}.owners", ctx)))?;
			owners.push(XOnlyPublicKey::from_slice(&b).map_err(|_| RecordError::Key(format!("{}.owners", ctx)))?);
		}
		let record = LeafRecord {
			template, owner, owner_nonce, operator_nonce, exit_delay, asset, value, unlock_hash, entry_reserve, chain,
			schedule, burn,
			upper, lowest: LowestLevel { index, reserve, siblings, owners },
		};
		record.check()?;
		Ok(record)
	}
}

/// `v` as an object with exactly the keys `keys`.
pub(crate) fn object<'a>(v: &'a Value, ctx: &str, keys: &[&str]) -> Result<&'a Map<String, Value>, RecordError> {
	let m = v.as_object().ok_or_else(|| RecordError::Type(ctx.into()))?;
	for k in keys {
		if !m.contains_key(*k) {
			return Err(RecordError::Field(format!("{}.{}", ctx, k)));
		}
	}
	if let Some(k) = m.keys().find(|k| !keys.contains(&k.as_str())) {
		return Err(RecordError::Field(format!("{}.{}", ctx, k)));
	}
	Ok(m)
}

pub(crate) fn int(m: &Map<String, Value>, k: &str, max: u64) -> Result<u64, RecordError> {
	m[k].as_u64().filter(|v| *v <= max).ok_or_else(|| RecordError::Type(k.into()))
}

pub(crate) fn string<'a>(m: &'a Map<String, Value>, k: &str) -> Result<&'a str, RecordError> {
	m[k].as_str().ok_or_else(|| RecordError::Type(k.into()))
}

pub(crate) fn array<'a>(m: &'a Map<String, Value>, k: &str, max: usize) -> Result<&'a Vec<Value>, RecordError> {
	m[k].as_array().filter(|a| a.len() <= max).ok_or_else(|| RecordError::Type(k.into()))
}

pub(crate) fn bytes32(m: &Map<String, Value>, k: &str) -> Result<[u8; 32], RecordError> {
	hex32(string(m, k)?).ok_or_else(|| RecordError::Hex(k.into()))
}

pub(crate) fn display32(m: &Map<String, Value>, k: &str) -> Result<[u8; 32], RecordError> {
	let mut b = bytes32(m, k)?;
	b.reverse();
	Ok(b)
}

pub(crate) fn key(m: &Map<String, Value>, k: &str) -> Result<XOnlyPublicKey, RecordError> {
	XOnlyPublicKey::from_slice(&bytes32(m, k)?).map_err(|_| RecordError::Key(k.into()))
}

pub(crate) fn units(m: &Map<String, Value>, k: &str) -> Result<RelativeTime, RecordError> {
	let u = int(m, k, u16::MAX as u64)?;
	Ok(RelativeTime::from_units(u as u16).map_err(crate::encode::DecodeError::from)?)
}

/// A canonical decimal amount: digits only, no leading zero, at most `u64`.
fn parse_amount(s: &str) -> Option<u64> {
	if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
		return None;
	}
	s.parse().ok()
}

pub(crate) fn amount(m: &Map<String, Value>, k: &str) -> Result<u64, RecordError> {
	parse_amount(string(m, k)?).ok_or_else(|| RecordError::Amount(k.into()))
}

fn level_common(o: &Map<String, Value>, ctx: &str) -> Result<(u8, u64, Vec<Sibling>), RecordError> {
	let index = int(o, "index", u8::MAX as u64).map_err(|_| RecordError::Type(format!("{}.index", ctx)))? as u8;
	let reserve = amount(o, "reserve").map_err(|_| RecordError::Amount(format!("{}.reserve", ctx)))?;
	let mut siblings = vec![];
	let list = array(o, "siblings", MAX_CHILDREN).map_err(|_| RecordError::Type(format!("{}.siblings", ctx)))?;
	for (i, s) in list.iter().enumerate() {
		let sctx = format!("{}.siblings[{}]", ctx, i);
		let so = object(s, &sctx, &["value", "program"])?;
		let value = amount(so, "value").map_err(|_| RecordError::Amount(format!("{}.value", sctx)))?;
		let program = bytes32(so, "program").map_err(|_| RecordError::Hex(format!("{}.program", sctx)))?;
		siblings.push(Sibling { value, program });
	}
	Ok((index, reserve, siblings))
}

/// The canonical text of a JSON value: object keys sorted by byte, no
/// whitespace. It does not depend on how `serde_json` orders a map.
pub fn canonical_text(v: &Value) -> String {
	let mut out = String::new();
	write_canonical(&mut out, v);
	out
}

fn write_canonical(out: &mut String, v: &Value) {
	match v {
		Value::Object(m) => {
			let mut keys: Vec<&String> = m.keys().collect();
			keys.sort();
			out.push('{');
			for (i, k) in keys.iter().enumerate() {
				if i > 0 {
					out.push(',');
				}
				out.push_str(&serde_json::to_string(k).expect("a string serialises"));
				out.push(':');
				write_canonical(out, &m[k.as_str()]);
			}
			out.push('}');
		},
		Value::Array(a) => {
			out.push('[');
			for (i, x) in a.iter().enumerate() {
				if i > 0 {
					out.push(',');
				}
				write_canonical(out, x);
			}
			out.push(']');
		},
		other => out.push_str(&serde_json::to_string(other).expect("a scalar serialises")),
	}
}

/// Reads JSON text with every object's keys distinct and nothing after it.
pub(crate) fn strict(text: &str) -> Result<Value, RecordError> {
	let mut de = serde_json::Deserializer::from_str(text);
	let v = Strict::deserialize(&mut de).map_err(|e| RecordError::Json(e.to_string()))?;
	de.end().map_err(|e| RecordError::Json(e.to_string()))?;
	Ok(v.0)
}

/// A JSON value read with every object's keys distinct: two readers that keep
/// a different one of two repeated keys would read two different records.
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Strict, D::Error> {
		d.deserialize_any(StrictVisitor)
	}
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
	type Value = Strict;

	fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str("a JSON value")
	}

	fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
		Ok(Strict(Value::Bool(v)))
	}

	fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
		Ok(Strict(Value::from(v)))
	}

	fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
		Ok(Strict(Value::from(v)))
	}

	fn visit_f64<E>(self, v: f64) -> Result<Strict, E> {
		Ok(Strict(Value::from(v)))
	}

	fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
		Ok(Strict(Value::String(v.to_owned())))
	}

	fn visit_string<E>(self, v: String) -> Result<Strict, E> {
		Ok(Strict(Value::String(v)))
	}

	fn visit_unit<E>(self) -> Result<Strict, E> {
		Ok(Strict(Value::Null))
	}

	fn visit_none<E>(self) -> Result<Strict, E> {
		Ok(Strict(Value::Null))
	}

	fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
		let mut v = vec![];
		while let Some(Strict(x)) = seq.next_element()? {
			v.push(x);
		}
		Ok(Strict(Value::Array(v)))
	}

	fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
		let mut m = Map::new();
		while let Some(k) = map.next_key::<String>()? {
			if m.contains_key(&k) {
				return Err(de::Error::custom(format!("the key {:?} is repeated", k)));
			}
			let Strict(v) = map.next_value()?;
			m.insert(k, v);
		}
		Ok(Strict(Value::Object(m)))
	}
}
