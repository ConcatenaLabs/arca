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

/// Every code a refusal carries (`ErrorDetail::code`), each answered with
/// the status `crate::http::status_of` gives it: a 4xx says the request was
/// not taken, and nothing it asked for was done; a 5xx (`internal`,
/// `signer_unavailable`, `not_synced`) and 429 (`rate_limited`) say nothing of
/// what was done, and the request is sent again as it was. A test reads the
/// codes out of the source and compares them with this list, and the wallet's
/// own test compares it with the codes the wallet knows.
pub const REFUSAL_CODES: &[&str] = &[
	"bad_attestation", "bad_forfeit", "bad_signature", "board_exists", "board_not_final", "board_output", "depth_limit",
	"double_spend", "fee", "forfeit_set", "in_use", "internal", "invalid_coin", "invalid_leaf", "invalid_record",
	"invalid_transaction", "key_reused", "leaf_set", "malformed", "margin", "merge", "no_lowest_node", "nonce_unknown",
	"nonce_used", "not_accepted", "not_in_round", "not_live", "not_participating", "not_synced", "on_chain", "open_reassignment",
	"operator_key", "out_of_bounds", "rate_limited", "release_early", "request_too_large", "round_not_final", "salt",
	"script_reused", "signer_replaced", "signer_unavailable", "template", "unauthenticated", "unbalanced", "unknown_batch", "unknown_board",
	"unknown_leaf", "unknown_participation", "value", "wrong_chain", "wrong_operator", "wrong_round",
];

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
	pub participations: ParticipationsInfo,
	pub boards: BoardsInfo,
	/// The signer's record's latest entry and running hash; absent while the
	/// signer does not answer.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub signer_record: Option<RecordHead>,
	/// The keepers the signer hands every head of its record to, on other
	/// machines, and how many must hold a head before the signer answers an
	/// entry: a wallet pins them when it is created, as it pins the operator
	/// key. No keys and 0 for an operator with no keeper, whose record rests
	/// on its own machine alone.
	pub keepers: KeepersInfo,
	/// The largest request body the server reads.
	pub max_request_bytes: u64,
}

/// The keepers of the signer's record ([`crate::keeper`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeepersInfo {
	/// Each keeper's own key (x-only, hex), which signs its acknowledgements.
	pub keys: Vec<String>,
	/// How many of them acknowledge every head the signer answers an entry
	/// with.
	pub required: u32,
}

/// The times a participation keeps to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipationsInfo {
	/// A coin is given up only while its first expiry lies at least this far
	/// ahead, and a later round time asked for must lie before that point:
	/// the exit deadline, three days.
	pub exit_deadline_seconds: u32,
	/// A participation's forfeits are taken until the later of this long
	/// after its round was found final, one day, and the exit deadline of
	/// the coins it gave up; otherwise it expires, its coins are the owner's
	/// again and its new leaves never are.
	pub forfeit_deadline_seconds: u32,
}

/// The dates a board, and every coin resting on it, carries: those of a batch
/// made when the board confirmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardsInfo {
	/// A board's service expiry lies this long after the median time of the
	/// block that confirms it: 28 days, a batch's lifetime.
	pub lifetime_seconds: u32,
	/// Its exit deadline lies this long before the expiry, three days: up to
	/// it the operator co-signs spends of a coin resting on the board and
	/// takes it into a refresh; after it, the coin's owner takes it on the
	/// chain.
	pub exit_deadline_seconds: u32,
	/// A refresh takes the coin until this long before the expiry: the exit
	/// deadline, three days.
	pub refresh_until_seconds: u32,
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
	/// The refresh fee, in parts per million of a coin's value, for a coin
	/// whose expiry is `full_after_seconds` or more beyond the free window; it
	/// falls in proportion to the time left beyond the window, to nothing
	/// within it. A coin resting on a board counts from the board's service
	/// expiry when that comes first.
	pub refresh_ppm: u64,
	/// A refresh is free for a coin whose first expiry is at most this far
	/// ahead, five days: the window is the two days before the exit deadline.
	pub free_window_seconds: u32,
	pub full_after_seconds: u32,
	/// The offboard fee, in parts per million of what it pays out, on top of
	/// the margin the round's output holds for its unlock.
	pub offboard_ppm: u64,
	/// The least margin a transfer's checkpoint and reassignment leave for
	/// their fee, as a multiple of the node's floor in an asset it accepts
	/// for fees (one atom in one it does not), and the most, as a multiple of
	/// that least.
	pub margin_multiple: u64,
	pub max_margin_multiple: u64,
	/// The operator's node's relay floor in each asset served, now: what the
	/// operator prices every margin it bounds from. Absent when the node did
	/// not answer.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub floors: Option<Vec<FloorInfo>>,
}

/// The relay floor of the operator's node in one asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FloorInfo {
	pub asset: String,
	/// In the asset's own atoms per 1,000 vbytes; `null` when the node does
	/// not accept the asset for fees now (a margin is then one atom).
	pub floor_per_kvb: Option<String>,
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
	/// The key the board is re-served to besides its own: its owner's
	/// mailbox key, which a wallet restored from its mnemonic derives
	/// (`leaf_data`), with the board's owner key's signature over the
	/// binding (`auth::mailbox_binding_digest`). Both or neither.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub mailbox: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub mailbox_proof: Option<String>,
}

/// `POST /v1/board_status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardStatusRequest {
	pub leaf_id: String,
}

/// A board's state: `pending`, `credited` or `lost`, its transaction's
/// finality: `not_in_chain`, `unsettled`, `settled` or `final`, and, once its
/// transaction is in a block, its dates (median times): the exit deadline and
/// the service expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardStatus {
	pub leaf_id: String,
	pub txid: String,
	pub vout: u32,
	pub state: String,
	pub finality: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub exit_deadline: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub expiry: Option<u32>,
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
	/// The entry of the signer's record the transfer's last signature was
	/// recorded as, signed: what the coins it makes rest on.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub signer_record: Option<RecordHead>,
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
	/// For a coin a transfer made, the entry of the signer's record that
	/// transfer's last signature was recorded as, signed.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub signer_record: Option<RecordHead>,
}

/// `POST /v1/leaf_data`: the leaves served to the authenticated key, after
/// cursor `after` (decimal), up to `limit`: those it owns, those whose owner
/// key bound them to it, and the transfer outputs posted to it as a mailbox.
/// The proof binds the cursor and the page size as a `mailbox_read`'s does;
/// a request without them reads the first page, its proof over nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafDataRequest {
	pub auth: Auth,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub after: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafData {
	pub leaves: Vec<LeafEntry>,
	/// The cursor of the last leaf served, to ask for the next page after;
	/// absent when this page holds nothing.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub next: Option<String>,
}

/// A leaf as the server re-serves it: its record, what it rests on, and
/// every way it was given up, each with the owner's own signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafEntry {
	pub leaf_id: String,
	/// `board`, `batch` or `transfer`.
	pub kind: String,
	/// `pending`, `live`, `spent`, `lost` or `expired`.
	pub state: String,
	pub asset: String,
	pub value: String,
	/// The coin record, binary form; empty while a transfer's output waits
	/// for its signatures, and for a round's leaf until its participation's
	/// preimage went out.
	pub record: String,
	/// Where the leaf lies in the order the server learned of leaves: the
	/// cursor of a next page.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cursor: Option<String>,
	/// Its owner key, and the owner nonce it was derived from (absent for a
	/// transfer's output whose record is empty).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub owner: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub owner_nonce: Option<String>,
	/// A round's leaf: its round, its batch and its index in the published
	/// tree, the participation it was made for, and the head of the signer's
	/// record when the round was built, with the keepers' acknowledgements.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub batch: Option<LeafBatch>,
	/// A board: its transaction output and its state there.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub board: Option<LeafBoard>,
	/// A transfer's output: the transfer, and the head of the signer's
	/// record its last signature was recorded at, with the keepers'
	/// acknowledgements.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub made_by: Option<LeafMadeBy>,
	/// Every way the coin was given up, oldest first.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub given: Vec<LeafGiven>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafBatch {
	pub round_txid: String,
	/// `built`, `broadcast`, `final` or `lost`.
	pub round_state: String,
	pub batch_vout: u32,
	pub leaf_index: u32,
	pub participation_id: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub signer_record: Option<RecordHead>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafBoard {
	pub txid: String,
	pub vout: u32,
	/// `pending`, `credited` or `lost`.
	pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafMadeBy {
	pub transfer_id: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub signer_record: Option<RecordHead>,
}

/// One way a coin was given up: `{"transfer": …}` or `{"participation": …}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LeafGiven {
	Transfer(GivenTransfer),
	Participation(GivenParticipation),
}

/// A transfer the coin is an input of: whether the operator signed it, the
/// coin's checkpoint value, and the owner's signature over the coin's move
/// into its checkpoint, which the owner checks is its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GivenTransfer {
	pub transfer_id: String,
	/// `recorded` or `signed`.
	pub state: String,
	pub checkpoint_value: String,
	pub checkpoint_sig: String,
}

/// A participation the coin was given up to: its state, every part its id
/// is a hash of, so the owner recomputes the id and checks the coin's
/// attestation over it is its own, whether the coin was given back, and
/// every forfeit of the coin recorded for it, each with the owner's half.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GivenParticipation {
	pub participation_id: String,
	pub state: String,
	pub attestation: String,
	pub returned: bool,
	pub inputs: Vec<String>,
	pub outputs: Vec<ServedOutput>,
	pub fees: Vec<FeeAmount>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub not_before: Option<u32>,
	pub unlock_hash: String,
	pub refund_delay_units: u16,
	pub forfeits: Vec<GivenForfeit>,
}

/// An output a participation wants, as its id covers it, with the leaf the
/// current attempt's round made of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ServedOutput {
	Leaf(ServedWantedLeaf),
	Offboard(WantedOffboard),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServedWantedLeaf {
	pub asset: String,
	pub value: String,
	pub template: String,
	pub owner: String,
	pub owner_nonce: String,
	pub exit_delay_units: u16,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub leaf_id: Option<String>,
}

/// A forfeit of the coin, for the round of one attempt: what its output
/// names and the owner's signature over the coin's move into it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GivenForfeit {
	pub participation_id: String,
	pub round_txid: String,
	pub connector_vout: u32,
	pub unlock_hash: String,
	pub refund_delay_units: u16,
	pub margin: String,
	pub owner_sig: String,
	/// Whether the operator's half is recorded too.
	pub cosigned: bool,
}

/// `POST /v1/bind_mailbox`: binds leaves to their owner's mailbox key, each
/// with its owner key's signature over the binding: for leaves made before
/// their wallet named the key when it asked for them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindMailbox {
	pub bindings: Vec<MailboxBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxBinding {
	pub owner: String,
	pub mailbox: String,
	pub proof: String,
}

/// What each binding came to: the mailbox the key is bound to (an earlier
/// binding stands), or none for a key the server knows no leaf of.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxBound {
	pub bound: Vec<BoundKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundKey {
	pub owner: String,
	pub mailbox: Option<String>,
}

/// `POST /v1/submit_participation`: the coins given up, each with its
/// owner's attestation, the outputs wanted, the fee per asset, and the
/// earliest median time of a round it may run in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitParticipation {
	pub inputs: Vec<ParticipationInput>,
	pub outputs: Vec<WantedOutput>,
	pub fees: Vec<FeeAmount>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub not_before: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipationInput {
	pub leaf_id: String,
	/// The coin's owner key's signature over the participation's id.
	pub attestation: String,
}

/// An output wanted: `{"leaf": …}` or `{"offboard": …}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum WantedOutput {
	Leaf(WantedLeaf),
	Offboard(WantedOffboard),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WantedLeaf {
	pub asset: String,
	pub value: String,
	/// `vtxo-1`.
	pub template: String,
	pub owner: String,
	pub owner_nonce: String,
	pub exit_delay_units: u16,
	/// The owner key's BIP340 signature over the participation's key-proof
	/// digest (`participations::key_proof_digest`): a participation wants a
	/// leaf only under a key it holds. Required of a participation the
	/// server does not hold yet; one it holds is answered with its status
	/// whatever its body lacks (the id does not cover the proofs).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub key_proof: Option<String>,
	/// The key the leaf is re-served to besides its own: its owner's
	/// mailbox key, with the owner key's signature over the binding
	/// (`auth::mailbox_binding_digest`). Both or neither; not covered by the
	/// participation's id.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub mailbox: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub mailbox_proof: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WantedOffboard {
	pub asset: String,
	pub value: String,
	/// The destination's scriptPubKey.
	pub script: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeAmount {
	pub asset: String,
	pub amount: String,
}

/// `POST /v1/participation_status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipationStatusRequest {
	pub participation_id: String,
}

/// A participation: `pending` until a round takes it, `issued` once it is in
/// a round, `released` once its forfeits are in and its preimage handed over,
/// `void` if it will not run, `expired` if its forfeits did not come within a
/// day of its round being final (its coins are the owner's again).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipationStatus {
	pub participation_id: String,
	pub state: String,
	/// How often a round it was in could not return and it ran again.
	pub attempt: u32,
	pub unlock_hash: String,
	/// The refund delay every forfeit of it carries.
	pub refund_delay_units: u16,
	/// Its round, once issued.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub round: Option<RoundRef>,
	pub inputs: Vec<ParticipationInputStatus>,
	pub outputs: Vec<ParticipationOutputStatus>,
	pub fees: Vec<FeeAmount>,
	/// While pending: why the last round that could have taken it did not
	/// (the operator's wallet could not fund its outputs, say).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub waiting: Option<String>,
	/// Once void: why it will never run (a coin of it whose forfeit for a
	/// round that could not return the operator published, say).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub void_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoundRef {
	pub txid: String,
	/// The round's connector output, whose asset every forfeit of the round names.
	pub connector_vout: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipationInputStatus {
	pub leaf_id: String,
	pub asset: String,
	pub value: String,
	/// What the forfeit of this coin leaves uncommitted for its own fee.
	pub margin: String,
	/// Once the participation is void or expired: whether the coin is its
	/// owner's again off the chain. A coin not given back has a forfeit
	/// signed, and is its owner's on the chain, by that forfeit's refund or by
	/// its exit.
	#[serde(default)]
	pub returned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipationOutputStatus {
	/// `leaf` or `offboard`.
	pub kind: String,
	pub asset: String,
	pub value: String,
	/// A leaf: the operator nonce of its salt, and once in a round its id, its
	/// batch output's index in the round and its index among that batch's
	/// leaves.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub operator_nonce: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub leaf_id: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub batch_vout: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub leaf_index: Option<u32>,
	/// An offboard: what the round's output holds beyond the destination for
	/// its unlock, the operator's reclaim delay, and once in a round the
	/// output's index.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub margin: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub reclaim_delay_units: Option<u16>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub offboard_vout: Option<u32>,
}

/// `POST /v1/tree`: the published tree of the batch paid by output `vout` of
/// the round `txid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRequest {
	pub txid: String,
	pub vout: u32,
}

/// A batch as the operator publishes it: everything the tree builder takes,
/// so anyone rebuilds every script of the tree, and where the round put it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedTree {
	pub round_txid: String,
	pub batch_vout: u32,
	/// The output holding the batch's sweep token, at its first clock.
	pub token_vout: u32,
	/// The round's connector output.
	pub connector_vout: u32,
	pub asset: String,
	pub genesis_hash: String,
	/// The clock schedule `(T, S, W, E_0 … E_K)`, in arca-covenant's
	/// canonical encoding.
	pub schedule: String,
	pub burn: bool,
	pub radix: u32,
	pub reserve: TreeReserve,
	pub min_leaf: String,
	/// Every leaf, in the tree's order.
	pub leaves: Vec<TreeLeaf>,
	/// The latest entry of the signer's record when the round was built.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub signer_record: Option<RecordHead>,
	/// Where the round stands: `built`, `broadcast`, `final` or `lost`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub round_state: Option<String>,
	/// Every node of the tree as the server built it, level by level, the
	/// lowest nodes first; the last level holds the batch output alone. A
	/// reader rebuilds the tree from the leaves and the parameters and
	/// refuses one whose nodes differ from what it rebuilt.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub nodes: Vec<Vec<PublishedNode>>,
}

/// A node of a published tree: its output (its value, the reserve in it,
/// its script) and its children, `[start, end)` in the level below (the
/// leaves' entries, for a lowest node).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedNode {
	pub value: String,
	pub reserve: String,
	pub script_pubkey: String,
	pub children: [u32; 2],
}

/// `POST /v1/rounds`: the rounds after `after` (a round's number,
/// decimal), up to `limit`, oldest first: what a mirror copies every
/// published tree by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoundsRequest {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub after: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rounds {
	pub rounds: Vec<RoundEntry>,
	/// The cursor of the last round listed, to ask for the next page after;
	/// absent when this page holds nothing.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub next: Option<String>,
}

/// A round: its number (the cursor), its transaction, where it stands, and
/// the outputs of its batches, each a published tree (`tree`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoundEntry {
	pub cursor: String,
	pub txid: String,
	pub state: String,
	pub batches: Vec<u32>,
}

/// An entry of the signer's record: its number and running hash, with `S`'s
/// signature over them, and the keepers' acknowledgements of it. A wallet
/// keeps every one it is shown that carries that signature and, where the
/// operator has keepers, the acknowledgements the wallet requires, and hands
/// them back on every contact (`witness`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordHead {
	pub entry: u64,
	pub hash: String,
	/// `S`'s signature over the entry and its running hash
	/// (`signer::record_head_digest`); absent only for a round built before
	/// heads were signed.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub signature: Option<String>,
	/// Each keeper's acknowledgement that it holds this head
	/// (`keeper::ack_digest`): its key, the nonce of the request it
	/// answered, and its signature.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub acks: Vec<crate::keeper::WireAck>,
}

/// `POST /v1/witness`: the heads of the signer's record a wallet holds, each
/// with the signature it was handed out with, at most
/// [`crate::signer::MAX_WITNESS`], and a nonce the wallet draws fresh for the
/// call (32 bytes), which the signer signs the record's end together with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessRequest {
	pub heads: Vec<RecordHead>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub nonce: Option<String>,
}

/// The running hash the record holds at an entry a wallet named: `None` past
/// its end, or where a compaction kept no hash; with `S`'s signature over it
/// as a head when there is one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryHash {
	pub entry: u64,
	pub hash: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub signature: Option<String>,
}

/// What a stopped signer shows of why it stopped: the head it was handed that
/// its record does not hold, signed by `S`, and the head the record holds at
/// that entry, signed, when it holds another there; when it holds none
/// there, the witness's `end` lies before it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopProof {
	pub head: RecordHead,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub held: Option<RecordHead>,
}

/// The answer to a witness: the record's latest entry, signed (none while the
/// signer is stopped), the running hash at each entry named, in order, each
/// signed, the record's latest entry signed together with the request's
/// nonce (`signer::record_end_digest`; absent when the request carried
/// none), and why the signer is stopped, if it is, with its proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Witness {
	pub head: Option<RecordHead>,
	pub hashes: Vec<EntryHash>,
	pub stopped: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub end: Option<RecordHead>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub proof: Option<StopProof>,
}

/// The tree's reserve rule: `{"fee_rate": …}` or `{"fixed": …}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeReserve {
	FeeRate(FeeRateReserve),
	Fixed(FixedReserve),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeRateReserve {
	/// The floor per 1,000 vbytes, in the batch asset's atoms.
	pub floor_per_kvb: String,
	pub multiple: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedReserve {
	pub node: String,
	pub entry: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeLeaf {
	pub template: String,
	pub owner: String,
	pub owner_nonce: String,
	pub operator_nonce: String,
	pub exit_delay_units: u16,
	pub value: String,
	pub unlock_hash: String,
	/// The leaf's id, and its output's script, as the tree gives them.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub leaf_id: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub script_pubkey: Option<String>,
	/// The preimage of the leaf's unlock hash, once its participation's
	/// preimage went out: it opens the leaf's entry, which pays the leaf's
	/// own script and nothing else, so it moves nothing but into the
	/// leaf, and lets an owner whose record is gone take the leaf on the
	/// chain from the published tree, its mnemonic and the chain.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub preimage: Option<String>,
}

/// `POST /v1/forfeit_leaves`: the owner's signature over the forfeit of each
/// coin the participation gave up, and its unroll authorisations for every
/// node above each new leaf, from the batch output down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForfeitLeaves {
	pub participation_id: String,
	pub forfeits: Vec<ForfeitSignature>,
	pub leaves: Vec<LeafAuths>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForfeitSignature {
	pub leaf_id: String,
	pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafAuths {
	pub leaf_id: String,
	pub auths: Vec<UnrollAuth>,
}

/// An unroll authorisation: the signature over
/// `SHA256("Arca/unroll" ‖ H ‖ t)` and its time `t`, a median time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnrollAuth {
	pub signature: String,
	pub time: u32,
}

/// What `forfeit_leaves` returns: the participation, released, and its
/// preimage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Forfeited {
	pub participation_id: String,
	pub state: String,
	pub preimage: String,
}

/// `POST /v1/release_leaves`: the owner's release of the lowest node of each
/// coin given up, signed with that coin's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseLeaves {
	pub participation_id: String,
	pub releases: Vec<ReleaseSignature>,
}

/// One coin's release: the signature over
/// `SHA256("Arca/release" ‖ genesis_hash ‖ H ‖ M)`, `M` the connector asset of
/// the participation's round, and, if the wallet names it, that `M` (display
/// order). A named `M` that is not the round's is refused (`wrong_round`); an
/// unnamed one is the round's, and the signature is checked over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSignature {
	pub leaf_id: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub connector_asset: Option<String>,
	pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Released {
	pub participation_id: String,
	/// The coins whose release is recorded.
	pub released: Vec<String>,
}
