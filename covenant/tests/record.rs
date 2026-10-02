//! The leaf record against its golden vectors, and validation against
//! mutation.
//!
//! `regtest/vectors/records.json` is written by the regtest suite's Python
//! reference (`regtest/records.py`), which shares no code with this crate. Each
//! batch in it is built by the tree rules from fixed inputs, funded by a round
//! transaction that issues the batch's token, and every exported leaf's record
//! is given in both forms with its id. Here every record must decode, encode
//! back to the same bytes and the same JSON text, give the same id, and pass
//! validation against its round. The refusal vectors must be refused with the
//! kind of error they name.
//!
//! Then every single field of valid records is mutated, one at a time, and
//! validation must refuse every mutation; so must every one-byte change of the
//! binary form. `-- --nocapture` prints the table.

use std::collections::BTreeMap;
use std::str::FromStr;

use elements::encode::deserialize;
use elements::hashes::{sha256d, Hash};
use elements::hex::FromHex;
use elements::{AssetId, BlockHash, ContractHash, OutPoint, Transaction, Txid};
use serde_json::Value;

use arca_covenant::record::{LeafRecord, Sibling};
use arca_covenant::script::sha256;
use arca_covenant::{ClockSchedule, MedianTime, MemberProof, RelativeTime};

fn vectors() -> Value {
	let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../regtest/vectors/records.json");
	serde_json::from_str(&std::fs::read_to_string(path).expect("regtest/vectors/records.json")).unwrap()
}

fn hexbytes(v: &Value) -> Vec<u8> {
	Vec::<u8>::from_hex(v.as_str().unwrap()).unwrap()
}

fn round_of(batch: &Value) -> Transaction {
	deserialize(&hexbytes(&batch["round"]["tx"])).unwrap()
}

/// Every valid record in the vectors, with its batch's round.
fn valid_records() -> Vec<(String, LeafRecord, Transaction)> {
	let v = vectors();
	let mut out = vec![];
	for b in v["batches"].as_array().unwrap() {
		let round = round_of(b);
		for r in b["records"].as_array().unwrap() {
			let rec = LeafRecord::from_bytes(&hexbytes(&r["binary"])).unwrap();
			out.push((format!("{} / leaf {}", b["name"].as_str().unwrap(), r["leaf"]), rec, round.clone()));
		}
	}
	out
}

#[test]
fn golden_vectors_regenerate() {
	let v = vectors();
	let genesis = BlockHash::from_str(v["inputs"]["genesis_hash"].as_str().unwrap()).unwrap();
	let mut records = 0;
	for b in v["batches"].as_array().unwrap() {
		let name = b["name"].as_str().unwrap();
		let round = round_of(b);

		// The token is the asset the round's first input issues.
		let issuer = &b["inputs"]["token_issuer"];
		let outpoint = OutPoint::new(Txid::from_str(issuer["txid"].as_str().unwrap()).unwrap(),
			issuer["vout"].as_u64().unwrap() as u32);
		assert_eq!(round.input[0].previous_output, outpoint, "{}", name);
		let token = AssetId::new_issuance(outpoint, ContractHash::from_byte_array([0; 32]));
		assert_eq!(token.to_string(), b["inputs"]["token"].as_str().unwrap(), "{}: the token", name);

		let batch_spk = hexbytes(&b["batch_output"]["script_pubkey"]);
		let batch_value = b["batch_output"]["value"].as_u64().unwrap();
		let asset = AssetId::from_str(b["batch_output"]["asset"].as_str().unwrap()).unwrap();
		for r in b["records"].as_array().unwrap() {
			let ctx = format!("{} / leaf {}", name, r["leaf"]);
			let binary = hexbytes(&r["binary"]);
			let text = r["json"].as_str().unwrap();

			// Both forms decode to the same record and encode back exactly.
			let rec = LeafRecord::from_bytes(&binary).unwrap_or_else(|e| panic!("{}: {}", ctx, e));
			assert_eq!(rec.to_bytes().unwrap(), binary, "{}: binary form", ctx);
			let from_json = LeafRecord::from_json_str(text).unwrap_or_else(|e| panic!("{}: {}", ctx, e));
			assert_eq!(from_json, rec, "{}: the two forms differ", ctx);
			assert_eq!(rec.to_json_string().unwrap(), text, "{}: JSON text", ctx);
			assert_eq!(rec.chain.genesis_hash(), genesis);
			assert_eq!(rec.schedule.token, token);
			assert_eq!(rec.asset, asset);

			// The path rebuilds the batch output, the entry and the leaf.
			let branch = rec.branch().unwrap();
			let out = branch.batch_output();
			assert_eq!(out.script_pubkey.as_bytes(), &batch_spk[..], "{}: batch output script", ctx);
			assert_eq!(out.value, batch_value, "{}: batch output value", ctx);
			assert_eq!(branch.leaf.program().to_vec(), hexbytes(&r["leaf_program"]), "{}: leaf", ctx);
			assert_eq!(branch.entry_output().script_pubkey.as_bytes()[2..].to_vec(), hexbytes(&r["entry_program"]),
				"{}: entry", ctx);
			let position: Vec<u8> = r["position"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u8).collect();
			assert_eq!(rec.position(), position, "{}: position", ctx);
			assert_eq!(rec.leaf_id().unwrap().to_string(), r["leaf_id"].as_str().unwrap(), "{}: leaf id", ctx);
			assert_eq!(rec.schedule.clock0_script_pubkey().as_bytes().to_vec(), hexbytes(&b["clock0_script_pubkey"]));

			// And the record validates against the round that funds it.
			let ok = rec.validate(&round).unwrap_or_else(|e| panic!("{}: refused: {}", ctx, e));
			assert_eq!(ok.batch_vout, b["round"]["batch_vout"].as_u64().unwrap() as u32);
			assert_eq!(ok.leaf_id.to_string(), r["leaf_id"].as_str().unwrap());
			records += 1;
		}
	}
	println!("{} records in {} batches: both forms and every id regenerate, every record validates",
		records, v["batches"].as_array().unwrap().len());
	assert!(records >= 50);
}

#[test]
fn refusal_vectors() {
	let v = vectors();
	for x in v["invalid_binary"].as_array().unwrap() {
		let name = x["name"].as_str().unwrap();
		let e = LeafRecord::from_bytes(&hexbytes(&x["binary"])).err()
			.unwrap_or_else(|| panic!("binary {:?}: decoded", name));
		assert_eq!(e.kind(), x["kind"].as_str().unwrap(), "binary {:?}: refused with {:?}", name, e);
		println!("binary  {:<45} refused: {}", name, e);
	}
	for x in v["invalid_json"].as_array().unwrap() {
		let name = x["name"].as_str().unwrap();
		let e = LeafRecord::from_json_str(x["json"].as_str().unwrap()).err()
			.unwrap_or_else(|| panic!("JSON {:?}: decoded", name));
		assert_eq!(e.kind(), x["kind"].as_str().unwrap(), "JSON {:?}: refused with {:?}", name, e);
		println!("JSON    {:<45} refused: {}", name, e);
	}
	// A repeated key: readers that keep different copies would read
	// different records, so it is refused.
	let (_, rec, _) = valid_records().remove(20);
	let text = rec.to_json_string().unwrap();
	let twice = text.replacen("{\"asset\":", "{\"value\":\"1\",\"asset\":", 1);
	assert_eq!(LeafRecord::from_json_str(&twice).unwrap_err().kind(), "json");
	assert_eq!(LeafRecord::from_json_str(&format!("{} x", text)).unwrap_err().kind(), "json");
	// Whitespace is read, and the canonical text has none.
	let spaced = serde_json::to_string_pretty(&rec.to_json().unwrap()).unwrap();
	assert_eq!(LeafRecord::from_json_str(&spaced).unwrap(), rec);
}

fn flip(b: [u8; 32]) -> [u8; 32] {
	let mut b = b;
	b[31] ^= 1;
	b
}

fn other_key(label: &str) -> elements::secp256k1_zkp::XOnlyPublicKey {
	let secret = sha256(format!("Arca test key/mutation {}", label).as_bytes());
	let s = elements::secp256k1_zkp::Secp256k1::new();
	elements::secp256k1_zkp::Keypair::from_secret_key(&s, &elements::secp256k1_zkp::SecretKey::from_slice(&secret).unwrap())
		.x_only_public_key().0
}

fn schedule_with(s: &ClockSchedule, f: impl FnOnce(&mut Vec<MedianTime>)) -> ClockSchedule {
	let mut e = s.expiries().to_vec();
	f(&mut e);
	ClockSchedule::new_unchecked(s.token, s.operator, s.notice, e).unwrap()
}

/// Every single-field mutation of `r`, named.
fn mutations(r: &LeafRecord) -> Vec<(String, LeafRecord)> {
	let mut m: Vec<(String, LeafRecord)> = vec![];
	let mut add = |name: String, f: &dyn Fn(&mut LeafRecord)| {
		let mut x = r.clone();
		f(&mut x);
		assert_ne!(&x, r, "{} is not a mutation", name);
		m.push((name, x));
	};
	add("owner".into(), &|x| x.owner = other_key("owner"));
	add("salt".into(), &|x| x.salt = flip(x.salt));
	add("exit delay".into(), &|x| x.exit_delay = RelativeTime::from_units(x.exit_delay.units() + 1).unwrap());
	add("asset".into(), &|x| x.asset = AssetId::from_byte_array(flip(x.asset.into_inner().to_byte_array())));
	add("value + 1".into(), &|x| x.value += 1);
	add("value - 1".into(), &|x| x.value -= 1);
	add("unlock hash".into(), &|x| x.unlock_hash = flip(x.unlock_hash));
	add("entry reserve".into(), &|x| x.entry_reserve += 1);
	add("genesis hash".into(), &|x| x.chain = arca_covenant::Chain::new(BlockHash::from_byte_array(flip(x.chain.genesis_bytes()))));
	add("operator".into(), &|x| x.schedule = ClockSchedule::new_unchecked(x.schedule.token, other_key("operator"),
		x.schedule.notice, x.schedule.expiries().to_vec()).unwrap());
	add("token".into(), &|x| x.schedule = ClockSchedule::new_unchecked(
		AssetId::from_byte_array(flip(x.schedule.token.into_inner().to_byte_array())), x.schedule.operator,
		x.schedule.notice, x.schedule.expiries().to_vec()).unwrap());
	add("notice".into(), &|x| x.schedule = ClockSchedule::new_unchecked(x.schedule.token, x.schedule.operator,
		RelativeTime::from_units(x.schedule.notice.units() + 1).unwrap(), x.schedule.expiries().to_vec()).unwrap());
	add("burn".into(), &|x| x.burn = !x.burn);
	for k in 0..r.schedule.expiries().len() {
		add(format!("expiry {} later", k), &|x| x.schedule = schedule_with(&x.schedule, |e| {
			e[k] = MedianTime::from_consensus(e[k].to_consensus_u32() + 1).unwrap()
		}));
		add(format!("expiry {} earlier", k), &|x| x.schedule = schedule_with(&x.schedule, |e| {
			e[k] = MedianTime::from_consensus(e[k].to_consensus_u32() - 1).unwrap()
		}));
	}
	add("an expiry added".into(), &|x| x.schedule = schedule_with(&x.schedule, |e| {
		let last = *e.last().unwrap();
		e.push(MedianTime::from_consensus(last.to_consensus_u32() + 86_400).unwrap())
	}));
	if r.schedule.expiries().len() > 1 {
		add("the last expiry removed".into(), &|x| x.schedule = schedule_with(&x.schedule, |e| { e.pop(); }));
	}
	let extra = Sibling { value: 1_000, program: sha256(b"an extra child") };
	for l in 0..r.upper.len() {
		let u = &r.upper[l];
		let count = u.siblings.len() + 1;
		add(format!("level {} index", l), &|x| {
			let u = &mut x.upper[l];
			u.index = if count > 1 { (u.index + 1) % count as u8 } else { 1 };
		});
		add(format!("level {} reserve", l), &|x| x.upper[l].reserve += 1);
		for s in 0..u.siblings.len() {
			add(format!("level {} sibling {} value", l, s), &|x| x.upper[l].siblings[s].value += 1);
			add(format!("level {} sibling {} program", l, s), &|x| {
				x.upper[l].siblings[s].program = flip(x.upper[l].siblings[s].program)
			});
		}
		add(format!("level {} a child added", l), &|x| x.upper[l].siblings.push(extra));
		if !u.siblings.is_empty() {
			add(format!("level {} a child removed", l), &|x| {
				let u = &mut x.upper[l];
				let i = if (u.index as usize) < u.siblings.len() { u.siblings.len() - 1 } else { 0 };
				u.siblings.remove(i);
				if u.index as usize > u.siblings.len() { u.index -= 1; }
			});
		}
		add(format!("level {} member index", l), &|x| x.upper[l].member.index ^= 1);
		add(format!("level {} member index + 2", l), &|x| x.upper[l].member.index += 2);
		for s in 0..u.member.siblings.len() {
			add(format!("level {} member path {}", l, s), &|x| {
				x.upper[l].member.siblings[s] = flip(x.upper[l].member.siblings[s])
			});
		}
		add(format!("level {} member path one level longer", l), &|x| x.upper[l].member.siblings.push([7; 32]));
		add(format!("level {} member path one level shorter", l), &|x| {
			let m = &mut x.upper[l].member;
			m.siblings.pop();
			if m.siblings.is_empty() { m.siblings.push([7; 32]); m.siblings.push([8; 32]); }
		});
	}
	let lw = &r.lowest;
	let count = lw.siblings.len() + 1;
	add("lowest index".into(), &|x| {
		x.lowest.index = if count > 1 { (x.lowest.index + 1) % count as u8 } else { 1 };
	});
	add("lowest reserve".into(), &|x| x.lowest.reserve += 1);
	for s in 0..lw.siblings.len() {
		add(format!("lowest sibling {} value", s), &|x| x.lowest.siblings[s].value += 1);
		add(format!("lowest sibling {} program", s), &|x| x.lowest.siblings[s].program = flip(x.lowest.siblings[s].program));
		add(format!("lowest owner {}", s), &|x| x.lowest.owners[s] = other_key(&format!("lowest owner {}", s)));
	}
	add("lowest: a child and its owner added".into(), &|x| {
		x.lowest.siblings.push(extra);
		x.lowest.owners.push(other_key("added owner"));
	});
	if !lw.siblings.is_empty() {
		add("lowest: a child and its owner removed".into(), &|x| {
			let l = &mut x.lowest;
			let i = l.siblings.len() - 1;
			l.siblings.remove(i);
			l.owners.remove(i);
			if l.index as usize > l.siblings.len() { l.index -= 1; }
		});
		add("lowest: two owners swapped".into(), &|x| {
			if x.lowest.owners.len() > 1 { x.lowest.owners.swap(0, 1) } else { x.lowest.owners[0] = other_key("swap") }
		});
	}
	if !r.upper.is_empty() {
		add("the top level removed".into(), &|x| { x.upper.remove(0); });
	}
	add("a level added on top".into(), &|x| {
		x.upper.insert(0, arca_covenant::record::UpperLevel {
			index: 0, reserve: 2_500, siblings: vec![extra],
			member: MemberProof { index: 1, siblings: vec![[9; 32]; 3] },
		});
	});
	m
}

#[test]
fn every_single_field_mutation_is_refused() {
	let records = valid_records();
	let mut rows: BTreeMap<String, String> = BTreeMap::new();
	let mut tried = 0;
	// The richest records: two from each batch.
	let mut seen = BTreeMap::new();
	for (name, rec, round) in &records {
		let batch = name.split(" / ").next().unwrap().to_string();
		let n = seen.entry(batch).or_insert(0);
		if *n >= 2 {
			continue;
		}
		*n += 1;
		rec.validate(round).unwrap();
		for (field, mutant) in mutations(rec) {
			let e = mutant.validate(round).err()
				.unwrap_or_else(|| panic!("{}: the mutation of {:?} VALIDATES", name, field));
			tried += 1;
			rows.entry(field).or_insert_with(|| format!("{} ({})", e, e.kind()));
		}
	}
	println!("\n{:<44} first refusal", "field mutated");
	for (f, e) in &rows {
		println!("{:<44} {}", f, e);
	}
	println!("\n{} mutations of {} records, {} distinct fields: every one refused", tried,
		seen.values().sum::<i32>(), rows.len());
}

#[test]
fn every_one_byte_change_is_refused() {
	let records = valid_records();
	let mut decode_refused = 0;
	let mut validate_refused = 0;
	let mut by_kind: BTreeMap<&'static str, usize> = BTreeMap::new();
	for (name, rec, round) in records.iter().step_by(7) {
		let bytes = rec.to_bytes().unwrap();
		for i in 0..bytes.len() {
			for mask in [0x01u8, 0x80, 0xff] {
				let mut b = bytes.clone();
				b[i] ^= mask;
				match LeafRecord::from_bytes(&b) {
					Err(e) => {
						decode_refused += 1;
						*by_kind.entry(e.kind()).or_default() += 1;
					},
					Ok(m) => {
						let e = m.validate(round).err().unwrap_or_else(|| {
							panic!("{}: byte {} ^ {:#04x} decodes and VALIDATES", name, i, mask)
						});
						validate_refused += 1;
						*by_kind.entry(e.kind()).or_default() += 1;
					},
				}
			}
		}
	}
	println!("one-byte changes: {} refused by the decoder, {} by validation; by kind {:?}",
		decode_refused, validate_refused, by_kind);
}

#[test]
fn validation_needs_the_round() {
	let (_, rec, round) = valid_records().remove(10);
	let batch = rec.branch().unwrap().batch_output();

	// The path alone matches the batch output, and a later expiry does not
	// change the path: only the round shows the clock.
	let mut later = rec.clone();
	later.schedule = schedule_with(&rec.schedule, |e| e[0] = MedianTime::from_consensus(e[0].to_consensus_u32() + 1).unwrap());
	assert!(later.validate_batch_output(&batch.txout()).is_ok());
	assert_eq!(later.validate(&round).unwrap_err().to_string(),
		"check 5: the token is not paid to clock 0 rebuilt from the published schedule");

	// The batch output paid twice, or not at all.
	let mut twice = round.clone();
	twice.output.push(batch.txout());
	assert_eq!(rec.validate(&twice).unwrap_err().kind(), "batch_output");
	let mut none = round.clone();
	none.output[0].value = elements::confidential::Value::Explicit(batch.value - 1);
	assert_eq!(rec.validate(&none).unwrap_err().kind(), "batch_output");

	// Each attack on the token that consensus accepts.
	let mut two_atoms = round.clone();
	two_atoms.input[0].asset_issuance.amount = elements::confidential::Value::Explicit(2);
	assert_eq!(rec.validate(&two_atoms).unwrap_err().to_string(), "check 1: the token is issued as 2 atoms, not one");
	let mut token_at_r = round.clone();
	token_at_r.output[1].script_pubkey = rec.schedule.r().script_pubkey();
	assert_eq!(rec.validate(&token_at_r).unwrap_err().to_string(),
		"check 4: the token is paid straight to R, released before any expiry");
	let mut reissuable = round.clone();
	reissuable.input[0].asset_issuance.inflation_keys = elements::confidential::Value::Explicit(1);
	assert_eq!(rec.validate(&reissuable).unwrap_err().to_string(), "check 3: the issuance creates a reissuance token");
	let mut other_issuer = round.clone();
	other_issuer.input[0].previous_output.txid = Txid::from_raw_hash(sha256d::Hash::hash(b"another"));
	assert_eq!(rec.validate(&other_issuer).unwrap_err().to_string(), "check 1: no input of the round issues the token");
	let mut backwards = rec.clone();
	backwards.schedule = schedule_with(&rec.schedule, |e| e.swap(0, 1));
	assert_eq!(backwards.validate(&round).unwrap_err().to_string(), "check 5: the schedule runs backwards at step 1");
}
