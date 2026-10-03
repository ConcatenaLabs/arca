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

	/// A proof of `key` for `call`.
	pub fn auth(&self, call: &str, key: &Keypair, chain: &Chain) -> Value {
		let v = self.post("challenge", &json!({})).ok();
		let challenge: [u8; 32] = unhex(v["challenge"].as_str().unwrap()).try_into().unwrap();
		let digest = server::auth::auth_digest(chain, call, &challenge, &xonly(key));
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
		let v = self.post("mailbox_read", &json!({"auth": self.auth("mailbox_read", key, chain), "after": after.to_string(), "limit": 100})).ok();
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
