//! The JSON the server speaks: every request and answer of its interface.
//!
//! Conventions, as in the leaf record's JSON form: amounts are decimal
//! strings, asset ids and the genesis hash are in display order, keys,
//! nonces, signatures, leaf ids and records are lower-case hex. Records travel
//! in their binary form, which is canonical. Every object refuses a field it
//! does not know and a field given twice.

use serde::{Deserialize, Serialize};

/// An error: a stable code and a sentence for people.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
	pub error: ErrorDetail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorDetail {
	pub code: String,
	pub message: String,
}

/// `GET /v1/info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
	/// The operator key `S`.
	pub operator: String,
	pub genesis_hash: String,
	pub assets: Vec<AssetInfo>,
	pub exit_delay_units: Bounds,
	/// The most reassignments a coin may be from a round or a board.
	pub depth_limit: u32,
	pub finality: FinalityInfo,
	pub templates: TemplatesInfo,
	pub fees: FeesInfo,
	/// The largest request body the server reads.
	pub max_request_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetInfo {
	pub asset: String,
	pub min_leaf: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bounds {
	pub min: u32,
	pub max: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalityInfo {
	/// `required` on a chain with a committee.
	pub certification: String,
	/// The Bitcoin blocks that bury a final block's anchor.
	pub anchor_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplatesInfo {
	pub version: u32,
	pub list: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeesInfo {
	/// What the operator charges for an out-of-round transfer, in the asset
	/// moved.
	pub transfer: String,
}

/// `POST /v1/operator_nonce`: a fresh operator nonce for one leaf the
/// operator creates, a board's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceResponse {
	pub operator_nonce: String,
}

/// `POST /v1/challenge`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeResponse {
	pub challenge: String,
	pub expires_in_seconds: u64,
}

/// Proof of a key, for the calls that need one: the key, a challenge the
/// server issued, and the key's signature over [`crate::auth::auth_digest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
	pub key: String,
	pub challenge: String,
	pub signature: String,
}

/// An empty request body, `{}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

/// `POST /v1/register_board`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterBoard {
	/// The board record, binary form.
	pub record: String,
	/// The board transaction.
	pub tx: String,
}

/// `POST /v1/board_status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardStatusRequest {
	pub leaf_id: String,
}

/// A board's state: `pending`, `credited` or `lost`, and its transaction's
/// finality: `not_in_chain`, `unsettled`, `settled` or `final`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardStatus {
	pub leaf_id: String,
	pub txid: String,
	pub vout: u32,
	pub state: String,
	pub finality: String,
}

/// `POST /v1/cosign_transfer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CosignTransfer {
	pub inputs: Vec<TransferInput>,
	pub outputs: Vec<TransferOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferInput {
	pub leaf_id: String,
	pub checkpoint_value: String,
	/// The owner's signatures over the checkpoint and the reassignment.
	pub checkpoint_sig: String,
	pub reassignment_sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferOutput {
	pub asset: String,
	pub value: String,
	/// The new leaf's owner key and nonce, as its receiver published them.
	pub owner: String,
	pub owner_nonce: String,
	/// The second nonce of the new leaf's salt: the sender draws it, fresh
	/// and at random, for every leaf it creates.
	pub creator_nonce: String,
	pub exit_delay_units: u16,
	/// The mailbox the new coin goes to; the owner key when absent.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub mailbox: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cosigned {
	pub transfer_id: String,
	/// The operator's signatures for each input.
	pub signatures: Vec<OperatorSignatures>,
	/// Each new coin, with its record as its receiver gets it.
	pub outputs: Vec<Coin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorSignatures {
	pub checkpoint: String,
	pub reassignment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coin {
	pub leaf_id: String,
	/// The coin record, binary form.
	pub record: String,
}

/// `POST /v1/mailbox_read`: messages after `after` (a cursor, decimal), up
/// to `limit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxRead {
	pub auth: Auth,
	pub after: String,
	pub limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mailbox {
	pub messages: Vec<MailboxMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxMessage {
	pub cursor: String,
	pub kind: String,
	pub leaf_id: String,
	pub record: String,
}

/// `POST /v1/leaf_data`: the leaves the authenticated key owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafDataRequest {
	pub auth: Auth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafData {
	pub leaves: Vec<LeafEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafEntry {
	pub leaf_id: String,
	/// `board`, `batch` or `transfer`.
	pub kind: String,
	/// `pending`, `live`, `spent` or `lost`.
	pub state: String,
	pub asset: String,
	pub value: String,
	/// The coin record, binary form; empty while a transfer's output waits
	/// for its signatures.
	pub record: String,
}
