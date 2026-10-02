//! Fuzz bodies for `arca-covenant`'s decoders and readers.
//!
//! Each function takes untrusted bytes, as a client gets them from a server or
//! a watcher from the chain. Any panic inside the library is a bug: these
//! bodies are run bare under libFuzzer (`libfuzzer/covenant.rs`) and behind
//! [`crate::harness::guard`] under honggfuzz (`src/bin/covenant_*.rs`).
//! The oracles check that what decodes re-encodes to the same bytes, that
//! every decoded policy builds its scripts, and that a decoded leaf record
//! reads the same in both of its forms and rebuilds its path.

use arca_covenant::elements;
use arca_covenant::encode::{Encoding, Policy};
use arca_covenant::record::{LeafRecord, RecordError};
use arca_covenant::script::sha256;
use arca_covenant::witness::{find_preimage, ScriptPath, UnrollWitness};
use arca_covenant::{check_round, ClockSchedule, MedianTime, RelativeTime};
use elements::secp256k1_zkp::XOnlyPublicKey;

use crate::{oracle_assert, oracle_assert_eq, oracle_unreachable};

/// A policy or a published clock schedule: decode, re-encode, build.
pub fn policy_decode(data: &[u8]) {
	if let Ok(p) = Policy::decode(data) {
		oracle_assert_eq!(p.encode(), data.to_vec(), "a decoded policy re-encodes to its bytes");
		let spk = p.script_pubkey();
		oracle_assert!(spk.is_v1_p2tr(), "every policy is a taproot output");
	}
	if let Ok(s) = ClockSchedule::decode(data) {
		oracle_assert_eq!(s.encode(), data.to_vec(), "a decoded schedule re-encodes to its bytes");
		let clocks = s.clocks();
		oracle_assert_eq!(clocks.len(), s.expiries().len());
		let _ = s.r().script_pubkey();
	}
}

/// Splits `data` into witness items: each item is one length byte, then
/// that many bytes (fewer at the end).
fn items(data: &[u8]) -> Vec<Vec<u8>> {
	let mut out = vec![];
	let mut rest = data;
	while let Some((&len, tail)) = rest.split_first() {
		let n = (len as usize).min(tail.len());
		out.push(tail[..n].to_vec());
		rest = &tail[n..];
	}
	out
}

/// A witness stack: split it as a script-path spend, read it as an unroll,
/// and look for a preimage of the first item's hash.
pub fn witness_parse(data: &[u8]) {
	let stack = items(data);
	if let Ok(sp) = ScriptPath::parse(&stack) {
		oracle_assert!(sp.items.len() + 2 <= stack.len());
		if let Ok(u) = UnrollWitness::parse(sp.items) {
			oracle_assert_eq!(sp.items.len(), 3 + 2 * u.path.len());
			oracle_assert!(u.time.to_consensus_u32() >= 500_000_000);
		}
	}
	let _ = UnrollWitness::parse(&stack);
	if let Some(first) = stack.first() {
		let h = sha256(first);
		if first.len() == 32 {
			oracle_assert_eq!(find_preimage(&stack, &h).map(|p| p.to_vec()), Some(first.clone()));
		} else {
			let _ = find_preimage(&stack, &h);
		}
	}
}

/// A round transaction from the server: decode it and run the five checks
/// against a fixed schedule.
pub fn round_check(data: &[u8]) {
	let tx: elements::Transaction = match elements::encode::deserialize(data) {
		Ok(tx) => tx,
		Err(_) => return,
	};
	let key = XOnlyPublicKey::from_slice(&[
		0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
		0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
	]).unwrap();
	// The token the first input would issue, so the checks get past check 1.
	let token = match tx.input.first() {
		Some(i) if i.has_issuance() => i.issuance_ids().0,
		_ => elements::AssetId::from_byte_array([7; 32]),
	};
	let schedule = ClockSchedule::new(token, key, RelativeTime::from_units(254).unwrap(),
		vec![MedianTime::from_consensus(1_800_000_000).unwrap()]).unwrap();
	let sweeps = [schedule.sweep(false, false), schedule.sweep(true, false)];
	if let Err(e) = check_round(&tx, &schedule, &sweeps) {
		oracle_assert!((1..=5).contains(&e.check()));
	}
}

/// What any decoded record must do: give the same record from its binary
/// form and from its canonical JSON text, and rebuild its path unless its
/// sums overflow or a child repeats the path's script.
fn record_oracles(r: &LeafRecord) {
	let bytes = r.to_bytes().expect("a decoded record encodes");
	oracle_assert_eq!(&LeafRecord::from_bytes(&bytes).expect("its bytes decode"), r);
	let text = r.to_json_string().expect("a decoded record has a JSON form");
	oracle_assert_eq!(&LeafRecord::from_json_str(&text).expect("its JSON text decodes"), r);
	match r.branch() {
		Ok(b) => {
			oracle_assert_eq!(b.nodes.len(), r.levels());
			oracle_assert_eq!(b.position(), r.position());
			let _ = b.leaf_id();
			let _ = b.batch_output();
		},
		Err(RecordError::ValueSum) | Err(RecordError::DuplicateChild { .. }) => {},
		Err(e) => oracle_unreachable!("a decoded record's path fails with {:?}", e),
	}
}

/// A leaf record in its binary form: decode, re-encode, read it again from
/// its JSON text, rebuild its path.
pub fn record_decode(data: &[u8]) {
	if let Ok(r) = LeafRecord::from_bytes(data) {
		oracle_assert_eq!(r.to_bytes().unwrap(), data.to_vec(), "a decoded record re-encodes to its bytes");
		record_oracles(&r);
	}
}

/// A leaf record in its JSON form: the bytes as UTF-8 text.
pub fn record_json(data: &[u8]) {
	let Ok(text) = std::str::from_utf8(data) else { return };
	if let Ok(r) = LeafRecord::from_json_str(text) {
		record_oracles(&r);
	}
}
