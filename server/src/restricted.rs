//! The restricted profile: a restricted asset (an OpenAMP asset, whose every
//! move needs its issuer's policy key) held in `enclave-1` leaves
//! (`arca_covenant::enclave`), the issuer running this operator, and its
//! policy server co-signing beside it.
//!
//! - Every leaf of the asset, on a board or from a reassignment, is
//!   `enclave-1`, for the asset's policy key and clawback key, its owner key
//!   the holder's enclave key for its owner nonce: its exit pays only the
//!   holder's enclave, in full. No other template holds it, and no other
//!   asset's leaf is `enclave-1`.
//! - The policy server is the asset's: the operator reads the asset's tree
//!   terms from it (`GET /v1/assets/{id}`: the policy key, the clawback key,
//!   the tree's operator) when it loads the asset, and serves the asset only
//!   when the tree's operator is its own key `S`.
//! - Before its signer signs anything of a transfer of the asset, the
//!   operator asks the policy server to co-sign it
//!   (`POST /v1/issuer/tree/transfer`), which applies the asset's rules
//!   (freeze, categories, lock-in, velocity, holder caps, vesting) and records
//!   the move in its register; its answer is a signature by the policy key
//!   over each message `S` is to sign, which the signer checks itself
//!   (`--restricted`) before it signs. A refusal is the policy server's own
//!   words (`policy`).
//! - Margins are zero: a checkpoint keeps the whole coin and the
//!   reassignment commits every atom, since a remainder of the asset could go
//!   anywhere, a fee output included. Whoever brings a coin on the chain pays
//!   its fees with a coin of another asset; the watcher does so from the
//!   operator's own.
//! - Served: the board, the transfer between holders the policy server
//!   knows, and the exit. Not served, refused before anything else
//!   ([`gate`]): a refresh or an offboard, a swap, a payment over Lightning,
//!   an order or a take, a distribution, a plan. A coin rests on its board,
//!   whose service dates bind it, and its holder takes it home before them.

use std::collections::HashMap;
use std::time::Duration;

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::AssetId;
use serde_json::{json, Value};

use arca_covenant::{CoinRecord, Enclave, EnclaveTerms, LeafId, NewLeaf};

use crate::params::Params;
use crate::store::{Store, StoreError};

/// The refusal code of a move the policy server refused.
pub const POLICY: &str = "policy";

/// The refusal code of a path not served for a restricted asset.
pub const RESTRICTED: &str = "restricted";

/// How long a call to the policy server may take.
const TIMEOUT: Duration = Duration::from_secs(20);

/// What the operator serves of a restricted asset: the terms its leaves
/// carry and the policy server that co-signs beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restricted {
	/// The asset's policy key `Kp`.
	pub policy: XOnlyPublicKey,
	/// The issuer's key `Ki`, when the asset elected clawback.
	pub clawback: Option<XOnlyPublicKey>,
	/// The policy server's base URL.
	pub server: String,
	/// The issuer's token for the policy server, read from its file.
	pub token: String,
}

impl Restricted {
	/// The enclave of `holder` for this asset.
	pub fn enclave(&self, holder: XOnlyPublicKey) -> Enclave {
		Enclave { holder, policy: self.policy, clawback: self.clawback }
	}
}

/// The tree terms a policy server publishes for an asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeTerms {
	pub operator: XOnlyPublicKey,
	pub policy: XOnlyPublicKey,
	pub clawback: Option<XOnlyPublicKey>,
}

/// Why the restricted profile refuses.
#[derive(Debug, thiserror::Error)]
pub enum RestrictedError {
	#[error("{}asset {asset} is served as a restricted asset in its issuer's tree: {what} is not served for it. A holder transfers it to \
		another registered holder, or takes it home to its own enclave by its exit", coin.map(|c| format!("coin {} is of asset {}: ", c, asset)).unwrap_or_default())]
	NotServed { asset: AssetId, coin: Option<LeafId>, what: String },
	#[error("the policy server refused: {0}")]
	Policy(String),
	#[error("the policy server did not answer: {0}")]
	Unavailable(String),
	#[error(transparent)]
	Store(#[from] StoreError),
}

impl RestrictedError {
	pub fn code(&self) -> &'static str {
		match self {
			RestrictedError::NotServed { .. } => RESTRICTED,
			RestrictedError::Policy(_) => POLICY,
			RestrictedError::Unavailable(_) => "policy_unavailable",
			RestrictedError::Store(_) => "internal",
		}
	}
}

/// Refuses `what`, a path not served for a restricted asset, for any coin
/// `leaves` names that is of one: before anything else about the request. A
/// coin the server does not know passes here and meets the rest of the
/// request's checks.
pub async fn gate(store: &Store, params: &Params, leaves: &[LeafId], what: &str) -> Result<(), RestrictedError> {
	for id in leaves {
		let Some(row) = store.leaf(&id.0).await? else { continue };
		let asset = AssetId::from_byte_array(row.asset);
		if params.restricted(&asset).is_some() {
			return Err(RestrictedError::NotServed { asset, coin: Some(*id), what: what.into() });
		}
	}
	Ok(())
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
	(s.len() % 2 == 0).then(|| (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect()).flatten()
}

fn xonly(v: &Value) -> Option<XOnlyPublicKey> {
	v.as_str().and_then(unhex).and_then(|b| XOnlyPublicKey::from_slice(&b).ok())
}

async fn call(method: &'static str, url: String, token: Option<String>, body: Option<Value>) -> Result<(i32, Value), String> {
	tokio::task::spawn_blocking(move || {
		let mut r = match method {
			"GET" => minreq::get(&url),
			_ => minreq::post(&url),
		}.with_timeout(TIMEOUT.as_secs());
		if let Some(t) = token {
			r = r.with_header("Authorization", format!("Bearer {}", t));
		}
		if let Some(b) = body {
			r = r.with_header("Content-Type", "application/json").with_body(b.to_string());
		}
		let resp = r.send().map_err(|e| format!("{} {}: {}", method, url, e))?;
		let v: Value = serde_json::from_slice(resp.as_bytes()).unwrap_or(Value::Null);
		Ok((resp.status_code, v))
	}).await.map_err(|e| e.to_string())?
}

/// The asset's tree terms, as its policy server publishes them.
pub async fn tree_terms(server: &str, asset: AssetId) -> Result<TreeTerms, String> {
	let url = format!("{}/v1/assets/{}", server.trim_end_matches('/'), asset);
	let (status, v) = call("GET", url.clone(), None, None).await?;
	if status != 200 {
		return Err(format!("{} answered {}: {}", url, status, v));
	}
	let t = &v["tree"];
	if t.is_null() {
		return Err(format!("the policy server keeps no tree for asset {}: its issuer enables one (POST /v1/issuer/tree)", asset));
	}
	let bad = |k: &str| format!("the policy server's tree terms for asset {} name no valid {}", asset, k);
	Ok(TreeTerms {
		operator: xonly(&t["operator"]).ok_or_else(|| bad("operator"))?,
		policy: xonly(&t["policy"]).ok_or_else(|| bad("policy key"))?,
		clawback: match &t["clawback"] {
			Value::Null => None,
			c => Some(xonly(c).ok_or_else(|| bad("clawback key"))?),
		},
	})
}

/// The policy server's co-signature of a transfer: its id there, and the
/// policy key's signature over each message the operator is to sign.
#[derive(Debug, Clone)]
pub struct Approval {
	pub id: String,
	pub signatures: HashMap<[u8; 32], Signature>,
}

impl Approval {
	/// The policy key's signature over `digest`.
	pub fn over(&self, digest: &[u8; 32]) -> Result<Signature, RestrictedError> {
		self.signatures.get(digest).copied().ok_or_else(|| RestrictedError::Policy(format!(
			"the policy server's answer carries no signature over message {}", hex(digest))))
	}
}

/// Asks the policy server of `r` to co-sign a transfer of `asset`: each input
/// coin with what its checkpoint keeps, each new leaf with its asset and
/// value. Its signatures are checked against `r.policy` here, as the signer
/// will check them.
pub async fn approve(r: &Restricted, asset: AssetId, inputs: &[(&CoinRecord, u64)], outputs: &[(AssetId, u64, NewLeaf)])
	-> Result<Approval, RestrictedError>
{
	let mut ins = vec![];
	for (coin, v) in inputs {
		let bytes = coin.to_bytes().map_err(|e| RestrictedError::Policy(e.to_string()))?;
		ins.push(json!({"coin": hex(&bytes), "checkpoint_value": v.to_string()}));
	}
	let mut outs = vec![];
	for (a, v, leaf) in outputs {
		let terms: EnclaveTerms = leaf.enclave.ok_or_else(|| RestrictedError::Policy("an output is not an enclave-1 leaf".into()))?;
		outs.push(json!({
			"asset": a.to_string(), "value": v.to_string(), "holder": hex(&terms.enclave.holder.serialize()),
			"owner_nonce": hex(&leaf.owner_nonce), "creator_nonce": hex(&leaf.creator_nonce),
			"exit_delay_units": leaf.exit_delay.units(),
		}));
	}
	let body = json!({"asset": asset.to_string(), "transfer": {"inputs": ins, "outputs": outs}});
	let url = format!("{}/v1/issuer/tree/transfer", r.server.trim_end_matches('/'));
	let (status, v) = call("POST", url, Some(r.token.clone()), Some(body)).await.map_err(RestrictedError::Unavailable)?;
	match status {
		200 => {},
		400 | 403 | 404 | 409 => return Err(RestrictedError::Policy(v["error"].as_str().unwrap_or("no reason given").to_string())),
		s => return Err(RestrictedError::Unavailable(format!("answered {}: {}", s, v))),
	}
	let id = v["id"].as_str().unwrap_or_default().to_string();
	let mut signatures = HashMap::new();
	for s in v["signatures"].as_array().into_iter().flatten() {
		let digest: [u8; 32] = s["digest"].as_str().and_then(unhex).and_then(|b| b.try_into().ok())
			.ok_or_else(|| RestrictedError::Policy("a signature names no digest".into()))?;
		let sig = s["signature"].as_str().and_then(unhex).and_then(|b| Signature::from_slice(&b).ok())
			.ok_or_else(|| RestrictedError::Policy("a signature is malformed".into()))?;
		if !arca_covenant::sign::verify_digest(&sig, &arca_covenant::enclave::policy_cosign_digest(&digest), &r.policy) {
			return Err(RestrictedError::Policy(format!("the signature over {} does not verify under the asset's policy key", hex(&digest))));
		}
		signatures.insert(digest, sig);
	}
	Ok(Approval { id, signatures })
}

/// Tells the policy server a transfer it co-signed will not be completed:
/// its inputs are its holders' again there.
pub async fn drop(r: &Restricted, id: &str) {
	let url = format!("{}/v1/issuer/tree/transfer/{}/drop", r.server.trim_end_matches('/'), id);
	match call("POST", url, Some(r.token.clone()), Some(json!({}))).await {
		Ok((200, _)) => {},
		Ok((s, v)) => log::warn!("restricted: the policy server answered {} to dropping transfer {}: {}", s, id, v),
		Err(e) => log::warn!("restricted: dropping transfer {} at the policy server: {}", id, e),
	}
}

