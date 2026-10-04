//! The minimal client: what a wallet does against the server, built on
//! `arca-covenant` directly.

use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Script, Transaction, TxOut};
use rand::RngCore;

use arca_covenant::{BoardRecord, Chain, RelativeTime, Template};

use super::keys::xonly;

/// A random 32-byte nonce: a wallet never takes its nonces from a counter.
pub fn random32() -> [u8; 32] {
	let mut b = [0u8; 32];
	rand::rngs::OsRng.fill_bytes(&mut b);
	b
}

/// The specification's exit delay, 36 hours.
pub fn exit_delay() -> RelativeTime {
	RelativeTime::from_seconds_ceil(36 * 3600).unwrap()
}

/// A board record for `owner`'s new key, with a nonce of the owner's and the
/// one the operator gave.
pub fn board_record(owner: &Keypair, operator_nonce: [u8; 32], asset: AssetId, value: u64, chain: Chain,
	operator: elements::secp256k1_zkp::XOnlyPublicKey) -> BoardRecord
{
	BoardRecord {
		template: Template::Board1,
		owner: xonly(owner),
		owner_nonce: random32(),
		operator_nonce,
		exit_delay: exit_delay(),
		asset, value, chain, operator,
	}
}

/// The board transaction paying `record` from `coin`, a coin at a bare
/// `OP_TRUE` (whose spend needs no witness), the fee in the board's own
/// asset, change to `change`.
pub fn board_tx(record: &BoardRecord, coin: &(OutPoint, TxOut), fee: u64, change: Script) -> Transaction {
	record.tx(std::slice::from_ref(coin), record.asset, fee, &change).unwrap().tx
}

// ---------------------------------------------------------------------------
// The client over HTTP
// ---------------------------------------------------------------------------

use std::str::FromStr;

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::Txid;
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::{CoinRecord, ExplicitOutput, LeafId, NewLeaf, TransferPlan, ValidCoin, WalletPolicy};

pub fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn unhex(s: &str) -> Vec<u8> {
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// An answer: its HTTP status and its JSON.
#[derive(Debug, Clone)]
pub struct Answer {
	pub status: i32,
	pub json: Value,
}

impl Answer {
	/// The refusal's code and message.
	pub fn refusal(&self) -> (String, String) {
		(self.json["error"]["code"].as_str().unwrap_or("").into(), self.json["error"]["message"].as_str().unwrap_or("").into())
	}

	pub fn ok(self) -> Value {
		assert_eq!(self.status, 200, "{}", self.json);
		self.json
	}
}

/// The server's HTTP interface, as a wallet reaches it.
#[derive(Debug, Clone)]
pub struct Http {
	pub base: String,
}

impl Http {
	pub fn get(&self, call: &str) -> Answer {
		let r = minreq::get(format!("{}/v1/{}", self.base, call)).with_timeout(60).send().unwrap();
		Answer { status: r.status_code, json: serde_json::from_str(r.as_str().unwrap()).unwrap_or(Value::Null) }
	}

	pub fn post_bytes(&self, call: &str, body: Vec<u8>) -> Answer {
		let r = minreq::post(format!("{}/v1/{}", self.base, call))
			.with_header("Content-Type", "application/json").with_body(body).with_timeout(60).send().unwrap();
		Answer { status: r.status_code, json: serde_json::from_str(r.as_str().unwrap()).unwrap_or(Value::Null) }
	}

	pub fn post(&self, call: &str, body: &Value) -> Answer {
		self.post_bytes(call, body.to_string().into_bytes())
	}

	pub fn operator_nonce(&self) -> [u8; 32] {
		let v = self.post("operator_nonce", &json!({})).ok();
		unhex(v["operator_nonce"].as_str().unwrap()).try_into().unwrap()
	}

	/// A proof of `key` for `call` asking nothing more (`leaf_data`).
	pub fn auth(&self, call: &str, key: &Keypair, chain: &Chain) -> Value {
		self.auth_for(call, key, chain, &[])
	}

	/// A proof of `key` for `call` asking `request`
	/// (`server::auth::mailbox_read_request`).
	pub fn auth_for(&self, call: &str, key: &Keypair, chain: &Chain, request: &[u8]) -> Value {
		let v = self.post("challenge", &json!({})).ok();
		let challenge: [u8; 32] = unhex(v["challenge"].as_str().unwrap()).try_into().unwrap();
		let digest = server::auth::auth_digest(chain, call, &challenge, &xonly(key), request);
		let sig = sign_digest(key, &digest, &random32());
		json!({"key": hex(&xonly(key).serialize()), "challenge": hex(&challenge), "signature": hex(sig.as_ref())})
	}

	pub fn register_board(&self, record: &BoardRecord, tx: &Transaction) -> Answer {
		self.post("register_board", &json!({
			"record": hex(&record.to_bytes().unwrap()),
			"tx": hex(&elements::encode::serialize(tx)),
		}))
	}

	pub fn board_status(&self, id: &LeafId) -> Answer {
		self.post("board_status", &json!({"leaf_id": id.to_string()}))
	}

	/// The coin records in `key`'s mailbox after `after`.
	pub fn mailbox(&self, key: &Keypair, chain: &Chain, after: i64) -> Vec<(i64, LeafId, CoinRecord)> {
		let request = server::auth::mailbox_read_request(after as u64, 100);
		let v = self.post("mailbox_read", &json!({"auth": self.auth_for("mailbox_read", key, chain, &request), "after": after.to_string(),
			"limit": 100})).ok();
		v["messages"].as_array().unwrap().iter().map(|m| (
			m["cursor"].as_str().unwrap().parse().unwrap(),
			LeafId::from_str(m["leaf_id"].as_str().unwrap()).unwrap(),
			CoinRecord::from_bytes(&unhex(m["record"].as_str().unwrap())).unwrap(),
		)).collect()
	}
}

/// A coin a client holds: its key, its nonce and its record.
#[derive(Clone)]
pub struct Held {
	pub key: Keypair,
	pub nonce: [u8; 32],
	pub id: LeafId,
	pub record: CoinRecord,
}

/// A leaf a sender creates for a receiver: the receiver's key and nonce, as
/// its receive request publishes them, and a creator nonce the sender draws
/// fresh for this leaf.
pub fn new_leaf(key: &Keypair) -> (NewLeaf, [u8; 32]) {
	let nonce = random32();
	(NewLeaf { owner: xonly(key), owner_nonce: nonce, creator_nonce: random32(), exit_delay: exit_delay() }, nonce)
}

/// Resolves `held` under `policy` against `bases`, as its owner would before
/// spending it.
pub fn resolve(held: &Held, bases: &[Transaction], policy: &WalletPolicy) -> ValidCoin {
	held.record.resolve(bases, policy).unwrap()
}

/// A transfer's request body: `coins` (each with what its checkpoint keeps)
/// into `outputs`, each owner signing both messages.
pub fn transfer_body(coins: &[(&Held, ValidCoin, u64)], outputs: &[(AssetId, u64, NewLeaf)], operator: XOnlyPublicKey, chain: Chain)
	-> Value
{
	let plan = TransferPlan {
		inputs: coins.iter().map(|(_, c, v)| (c.clone(), *v)).collect(),
		outputs: outputs.iter().map(|(a, v, l)| ExplicitOutput::new(*a, *v, l.policy(operator, chain).script_pubkey())).collect(),
	};
	let inputs: Vec<Value> = coins.iter().enumerate().map(|(k, (h, _, v))| {
		let cp: Signature = sign_digest(&h.key, &plan.checkpoint_message(k).unwrap().digest, &random32());
		let re: Signature = sign_digest(&h.key, &plan.reassignment_message(k).unwrap().digest, &random32());
		json!({"leaf_id": h.id.to_string(), "checkpoint_value": v.to_string(), "checkpoint_sig": hex(cp.as_ref()), "reassignment_sig": hex(re.as_ref())})
	}).collect();
	let outs: Vec<Value> = outputs.iter().map(|(a, v, l)| json!({
		"asset": a.to_string(), "value": v.to_string(), "owner": hex(&l.owner.serialize()),
		"owner_nonce": hex(&l.owner_nonce), "creator_nonce": hex(&l.creator_nonce), "exit_delay_units": l.exit_delay.units(),
	})).collect();
	json!({"inputs": inputs, "outputs": outs})
}

/// The txid a hex string names.
pub fn txid(s: &str) -> Txid {
	Txid::from_str(s).unwrap()
}

// ---------------------------------------------------------------------------
// Participations
// ---------------------------------------------------------------------------

use server::participations::{participation_id, OutputRequest};

/// The keys the tests' wallets want leaves under, by their x-only key, so
/// that [`participation_body`] can prove each one, as a wallet does.
static WANTED_KEYS: std::sync::Mutex<Vec<Keypair>> = std::sync::Mutex::new(Vec::new());

/// Holds `key` as one the tests' wallets want leaves under.
pub fn hold_key(key: &Keypair) {
	let mut k = WANTED_KEYS.lock().unwrap();
	if !k.iter().any(|h| h.x_only_public_key().0 == key.x_only_public_key().0) {
		k.push(*key);
	}
}

fn held_key(owner: &XOnlyPublicKey) -> Option<Keypair> {
	WANTED_KEYS.lock().unwrap().iter().find(|k| k.x_only_public_key().0 == *owner).copied()
}

/// A leaf a participation wants for `key`: a fresh owner nonce of the
/// wallet's, the specification's exit delay. The key is held, so the
/// participation proves it.
pub fn want_leaf(key: &Keypair, asset: AssetId, value: u64) -> (OutputRequest, [u8; 32]) {
	hold_key(key);
	let nonce = random32();
	(OutputRequest::Leaf {
		asset, value, template: arca_covenant::Template::Vtxo1, owner: xonly(key), owner_nonce: nonce, exit_delay: exit_delay(),
	}, nonce)
}

/// The JSON of one output wanted.
pub fn output_json(o: &OutputRequest) -> Value {
	match o {
		OutputRequest::Leaf { asset, value, template, owner, owner_nonce, exit_delay } => json!({"leaf": {
			"asset": asset.to_string(), "value": value.to_string(), "template": template.to_string(),
			"owner": hex(&owner.serialize()), "owner_nonce": hex(owner_nonce), "exit_delay_units": exit_delay.units(),
		}}),
		OutputRequest::Offboard { asset, value, script } => json!({"offboard": {
			"asset": asset.to_string(), "value": value.to_string(), "script": hex(script.as_bytes()),
		}}),
	}
}

/// A participation's request body and its id: `coins` given up, each
/// attested by its owner's key, for `outputs`, each leaf's key proved when
/// the tests hold it ([`hold_key`]), paying `fees`.
pub fn participation_body(coins: &[&Held], outputs: &[OutputRequest], fees: &[(AssetId, u64)], not_before: Option<u32>,
	operator: XOnlyPublicKey, chain: Chain) -> (Value, [u8; 32])
{
	let ids: Vec<LeafId> = coins.iter().map(|h| h.id).collect();
	let nb = not_before.map(|t| arca_covenant::MedianTime::from_consensus(t).unwrap());
	let id = participation_id(&chain, &operator, &ids, outputs, fees, nb);
	let inputs: Vec<Value> = coins.iter().map(|h| json!({
		"leaf_id": h.id.to_string(), "attestation": hex(sign_digest(&h.key, &id, &random32()).as_ref()),
	})).collect();
	let proof = server::participations::key_proof_digest(&id);
	let outputs: Vec<Value> = outputs.iter().map(|o| {
		let mut j = output_json(o);
		if let OutputRequest::Leaf { owner, .. } = o {
			if let Some(k) = held_key(owner) {
				j["leaf"]["key_proof"] = json!(hex(sign_digest(&k, &proof, &random32()).as_ref()));
			}
		}
		j
	}).collect();
	let mut body = json!({
		"inputs": inputs,
		"outputs": outputs,
		"fees": fees.iter().map(|(a, v)| json!({"asset": a.to_string(), "amount": v.to_string()})).collect::<Vec<_>>(),
	});
	if let Some(t) = not_before {
		body["not_before"] = json!(t);
	}
	(body, id)
}

// ---------------------------------------------------------------------------
// Published trees
// ---------------------------------------------------------------------------

use arca_covenant::encode::Encoding;
use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeParams};
use arca_covenant::ClockSchedule;

/// The tree a published batch describes, rebuilt by the wallet from the
/// published parts alone with `arca-covenant`'s builder.
pub fn rebuild(t: &Value) -> Tree {
	try_rebuild(t).unwrap()
}

/// [`rebuild`], or why the builder refuses the parts.
pub fn try_rebuild(t: &Value) -> Result<Tree, String> {
	let s = |k: &str| t[k].as_str().unwrap_or_else(|| panic!("{} in {}", k, t)).to_string();
	let num = |v: &Value| v.as_str().unwrap().parse::<u64>().unwrap();
	let reserve = if let Some(r) = t["reserve"].get("fee_rate") {
		ReserveRule::FeeRate { floor_per_kvb: num(&r["floor_per_kvb"]), multiple: num(&r["multiple"]) }
	} else {
		let r = &t["reserve"]["fixed"];
		ReserveRule::Fixed { node: num(&r["node"]), entry: num(&r["entry"]) }
	};
	let params = TreeParams {
		asset: s("asset").parse().unwrap(),
		chain: Chain::new(s("genesis_hash").parse().unwrap()),
		schedule: ClockSchedule::decode(&unhex(&s("schedule"))).map_err(|e| e.to_string())?,
		burn: t["burn"].as_bool().unwrap(),
		radix: t["radix"].as_u64().unwrap() as usize,
		reserve,
		min_leaf: num(&t["min_leaf"]),
	};
	let leaves: Vec<LeafSpec> = t["leaves"].as_array().unwrap().iter().map(|l| LeafSpec {
		template: l["template"].as_str().unwrap().parse().unwrap(),
		owner: XOnlyPublicKey::from_slice(&unhex(l["owner"].as_str().unwrap())).unwrap(),
		value: num(&l["value"]),
		owner_nonce: unhex(l["owner_nonce"].as_str().unwrap()).try_into().unwrap(),
		operator_nonce: unhex(l["operator_nonce"].as_str().unwrap()).try_into().unwrap(),
		exit_delay: RelativeTime::from_units(l["exit_delay_units"].as_u64().unwrap() as u16).unwrap(),
		unlock_hash: unhex(l["unlock_hash"].as_str().unwrap()).try_into().unwrap(),
	}).collect();
	Tree::build(params, &leaves).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// The forfeit swap
// ---------------------------------------------------------------------------

use arca_covenant::{Forfeit, ValidLeaf};

/// The owner's unroll authorisations for every node above `valid`, at `t`,
/// as `forfeit_leaves` takes them.
pub fn auths_json(valid: &ValidLeaf, key: &Keypair, t: arca_covenant::MedianTime) -> Value {
	json!({
		"leaf_id": valid.leaf_id.to_string(),
		"auths": valid.branch.nodes.iter().map(|n| json!({
			"signature": hex(sign_digest(key, &n.unroll_authorisation(t).digest, &random32()).as_ref()),
			"time": t.to_consensus_u32(),
		})).collect::<Vec<_>>(),
	})
}

/// The owner's signature over forfeit `f`.
pub fn forfeit_sig(f: &Forfeit, key: &Keypair) -> String {
	hex(sign_digest(key, &f.message().digest, &random32()).as_ref())
}
