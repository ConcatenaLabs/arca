//! `arca-enclave`: what a policy server checks of an `enclave-1` board or
//! transfer, computed by the code that builds them.
//!
//! A restricted asset's policy server (OpenAMP's `openampd`) co-signs beside
//! the operator: it signs the very messages the operator's key signs, once it
//! has applied the asset's rules. It runs this tool to learn what those
//! messages are and what they move, so the scripts and digests it approves
//! are Arca's own. One request on stdin, one JSON answer on stdout, exit 0;
//! a refusal is `{"error": "..."}` on stdout and exit 1.
//!
//! ```text
//! arca-enclave board      {"record": "<board record hex>"}
//! arca-enclave transfer   {"genesis", "operator", "policy", "clawback",
//!                          "inputs": [{"coin": "<coin record hex>", "checkpoint_value"}],
//!                          "outputs": [{"asset", "value", "holder", "owner_nonce", "creator_nonce", "exit_delay_units"}]}
//! ```
//!
//! `board` answers the board output's script, the leaf it converts into, its
//! holder, policy key, clawback key, operator, chain, salt and value, and the
//! control blocks of its claw leaf in the board and in the leaf. `transfer`
//! answers, for each input, the coin's leaf salt, holder and value with the
//! two digests its owner and the operator sign (the coin into its checkpoint,
//! the checkpoint into the outputs), and for each output its leaf's salt,
//! holder, value, script and claw control block. Every input must be an
//! `enclave-1` coin of the operator, chain, policy key and clawback named,
//! resting on a board (a coin of a batch or a fill has no place in a
//! restricted asset's tree), and every output an `enclave-1` leaf of theirs.
//! Asset ids and the genesis hash are in display order, as the node prints
//! them; keys, salts, digests and scripts are lower-case hex; amounts are
//! decimal strings.

use std::io::Read;
use std::str::FromStr;

use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, BlockHash};
use serde_json::{json, Value};

use arca_covenant::board::BoardRecord;
use arca_covenant::checkpoint::CheckpointPolicy;
use arca_covenant::spend::Rebindable;
use arca_covenant::sweep::Sweep;
use arca_covenant::transfer::{board_sweep, checkpoint_salt, CoinRecord, NewLeaf};
use arca_covenant::{enclave_key, Chain, Enclave, ExplicitOutput, LeafPolicy, RelativeTime};

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str, what: &str) -> Result<Vec<u8>, String> {
	if s.len() % 2 != 0 || !s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
		return Err(format!("{} is not lower-case hex", what));
	}
	Ok((0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect())
}

fn field<'a>(v: &'a Value, k: &str) -> Result<&'a Value, String> {
	v.get(k).ok_or_else(|| format!("the request has no {}", k))
}

fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
	field(v, k)?.as_str().ok_or_else(|| format!("{} is not a string", k))
}

fn key(v: &Value, k: &str) -> Result<XOnlyPublicKey, String> {
	XOnlyPublicKey::from_slice(&unhex(text(v, k)?, k)?).map_err(|_| format!("{} is not an x-only key", k))
}

fn bytes32(v: &Value, k: &str) -> Result<[u8; 32], String> {
	unhex(text(v, k)?, k)?.try_into().map_err(|_| format!("{} is not 32 bytes", k))
}

fn amount(v: &Value, k: &str) -> Result<u64, String> {
	let s = text(v, k)?;
	if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
		return Err(format!("{} is not a decimal amount", k));
	}
	s.parse().map_err(|_| format!("{} is out of range", k))
}

fn asset(v: &Value, k: &str) -> Result<AssetId, String> {
	AssetId::from_str(text(v, k)?).map_err(|_| format!("{} is not an asset id", k))
}

fn display(bytes: [u8; 32]) -> String {
	let mut b = bytes;
	b.reverse();
	hex(&b)
}

fn claw_control(tap: &arca_covenant::TapOutput, leaf: &LeafPolicy) -> Value {
	leaf.claw_script().ok().and_then(|s| tap.control_block(&s)).map_or(Value::Null, |c| Value::String(hex(&c)))
}

fn enclave_json(e: &Enclave) -> Value {
	json!({
		"holder": hex(&e.holder.serialize()),
		"policy": hex(&e.policy.serialize()),
		"clawback": e.clawback.map_or(Value::Null, |k| Value::String(hex(&k.serialize()))),
	})
}

fn board(req: &Value) -> Result<Value, String> {
	let record = BoardRecord::from_bytes(&unhex(text(req, "record")?, "record")?).map_err(|e| format!("the board record: {}", e))?;
	let e = record.enclave.ok_or("the board converts into no enclave-1 leaf: it is not a board of a restricted asset")?;
	let policy = record.policy();
	let leaf = record.leaf();
	let mut out = enclave_json(&e);
	let o = out.as_object_mut().expect("an object");
	o.insert("template".into(), json!(leaf.template().to_string()));
	o.insert("script_pubkey".into(), json!(hex(policy.script_pubkey().as_bytes())));
	o.insert("leaf_script_pubkey".into(), json!(hex(leaf.script_pubkey().as_bytes())));
	o.insert("asset".into(), json!(record.asset.to_string()));
	o.insert("value".into(), json!(record.value.to_string()));
	o.insert("operator".into(), json!(hex(&record.operator.serialize())));
	o.insert("genesis".into(), json!(display(record.chain.genesis_bytes())));
	o.insert("salt".into(), json!(hex(&record.salt())));
	o.insert("exit_delay_units".into(), json!(record.exit_delay.units()));
	o.insert("claw_control".into(), claw_control(&policy.taproot(), &leaf));
	o.insert("leaf_claw_control".into(), claw_control(&leaf.taproot(), &leaf));
	Ok(out)
}

/// A restricted coin's leaf, the sweep its checkpoint takes, its asset and
/// its value, from its record alone: a board, or a reassignment's output
/// whose first input leads down to one.
fn coin_leaf(c: &CoinRecord) -> Result<(LeafPolicy, Sweep, AssetId, u64), String> {
	match c {
		CoinRecord::Board(b) => Ok((b.leaf(), board_sweep(b.operator, b.exit_delay), b.asset, b.value)),
		CoinRecord::Transfer(t) => {
			let first = t.inputs.first().ok_or("a reassignment with no input")?;
			let (l0, sweep, _, _) = coin_leaf(&first.coin)?;
			let o = t.outputs.get(t.index as usize).ok_or("a coin index past the reassignment's outputs")?;
			Ok((t.leaf.policy(l0.operator, l0.chain), sweep, o.asset, o.value))
		},
		CoinRecord::Leaf { .. } | CoinRecord::Accumulator { .. } => Err("a coin of a batch: a restricted asset's coins rest on boards".into()),
		CoinRecord::Fill(_) => Err("a coin of a fill: a restricted asset is not filled in the tree".into()),
	}
}

fn transfer(req: &Value) -> Result<Value, String> {
	let chain = Chain::new(BlockHash::from_str(text(req, "genesis")?).map_err(|_| "genesis is not a block hash")?);
	let operator = key(req, "operator")?;
	let policy = key(req, "policy")?;
	let clawback = match field(req, "clawback")? {
		Value::Null => None,
		_ => Some(key(req, "clawback")?),
	};
	let inputs = field(req, "inputs")?.as_array().ok_or("inputs is not a list")?;
	let outputs = field(req, "outputs")?.as_array().ok_or("outputs is not a list")?;
	if inputs.is_empty() || inputs.len() > 16 {
		return Err(format!("{} inputs: a transfer gives up 1 to 16 coins", inputs.len()));
	}
	if outputs.is_empty() || outputs.len() > arca_covenant::leaf::MAX_OUTPUTS as usize {
		return Err(format!("{} outputs: a reassignment commits to 1 to {}", outputs.len(), arca_covenant::leaf::MAX_OUTPUTS));
	}
	let mut new = vec![];
	let mut answer_out = vec![];
	for (j, o) in outputs.iter().enumerate() {
		let a = asset(o, "asset")?;
		let value = amount(o, "value")?;
		if value == 0 {
			return Err(format!("output {} holds nothing", j));
		}
		let holder = key(o, "holder")?;
		let owner_nonce = bytes32(o, "owner_nonce")?;
		let units = field(o, "exit_delay_units")?.as_u64().filter(|u| *u <= u16::MAX as u64).ok_or("exit_delay_units is out of range")?;
		let exit_delay = RelativeTime::from_units(units as u16).map_err(|e| format!("output {}'s exit delay: {}", j, e))?;
		let enclave = Enclave { holder, policy, clawback };
		let leaf = NewLeaf {
			owner: enclave_key(&holder, &owner_nonce).map_err(|e| e.to_string())?, owner_nonce,
			creator_nonce: bytes32(o, "creator_nonce")?, exit_delay, htlc: None, landing: None,
			enclave: Some(enclave.terms(a, value)),
		};
		let p = leaf.policy(operator, chain);
		new.push(ExplicitOutput::new(a, value, p.script_pubkey()));
		answer_out.push(json!({
			"salt": hex(&leaf.salt()), "holder": hex(&holder.serialize()), "value": value.to_string(),
			"script_pubkey": hex(p.script_pubkey().as_bytes()), "claw_control": claw_control(&p.taproot(), &p),
		}));
	}
	let mut answer_in = vec![];
	let mut moved: Option<AssetId> = None;
	for (i, input) in inputs.iter().enumerate() {
		let coin = CoinRecord::from_bytes(&unhex(text(input, "coin")?, "coin")?).map_err(|e| format!("input {}'s coin record: {}", i, e))?;
		let (leaf, sweep, a, value) = coin_leaf(&coin).map_err(|e| format!("input {}: {}", i, e))?;
		let terms = leaf.enclave.ok_or_else(|| format!("input {} is a coin of template {}, not enclave-1", i, leaf.template()))?;
		if leaf.operator != operator || leaf.chain != chain {
			return Err(format!("input {} is a coin of another operator or chain", i));
		}
		if terms.enclave.policy != policy || terms.enclave.clawback != clawback {
			return Err(format!("input {}'s leaf names another policy key or clawback than the asset's", i));
		}
		terms.enclave.check_owner(&leaf.owner, &match &coin {
			CoinRecord::Board(b) => b.owner_nonce,
			CoinRecord::Transfer(t) => t.leaf.owner_nonce,
			_ => unreachable!("coin_leaf refused it"),
		}).map_err(|e| format!("input {}: {}", i, e))?;
		if *moved.get_or_insert(a) != a {
			return Err("the inputs are of two assets: a restricted asset's transfer moves one".into());
		}
		let checkpoint_value = amount(input, "checkpoint_value")?;
		let ckpt = CheckpointPolicy { owner: leaf.owner, operator, salt: checkpoint_salt(&leaf.salt), chain, sweep };
		let ckpt_out = ExplicitOutput::new(a, checkpoint_value, ckpt.script_pubkey());
		let cm = leaf.message(a, value, &[ckpt_out]).map_err(|e| e.to_string())?;
		let rm = ckpt.message(a, checkpoint_value, &new).map_err(|e| e.to_string())?;
		answer_in.push(json!({
			"salt": hex(&leaf.salt), "holder": hex(&terms.enclave.holder.serialize()), "value": value.to_string(),
			"checkpoint_value": checkpoint_value.to_string(), "checkpoint_digest": hex(&cm.digest),
			"reassignment_digest": hex(&rm.digest),
		}));
	}
	let a = moved.expect("one input");
	if new.iter().any(|o| o.asset != a) {
		return Err("an output is in another asset than the inputs".into());
	}
	Ok(json!({"asset": a.to_string(), "inputs": answer_in, "outputs": answer_out}))
}

fn main() {
	let cmd = std::env::args().nth(1).unwrap_or_default();
	let mut body = String::new();
	let answer = std::io::stdin().read_to_string(&mut body).map_err(|e| e.to_string())
		.and_then(|_| serde_json::from_str::<Value>(&body).map_err(|e| format!("the request is not JSON: {}", e)))
		.and_then(|req| match cmd.as_str() {
			"board" => board(&req),
			"transfer" => transfer(&req),
			other => Err(format!("unknown command {:?}: arca-enclave board | transfer", other)),
		});
	match answer {
		Ok(v) => println!("{}", v),
		Err(e) => {
			println!("{}", json!({"error": e}));
			std::process::exit(1);
		},
	}
}
