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
	"script_reused", "signer_unavailable", "template", "unauthenticated", "unbalanced", "unknown_batch", "unknown_board",
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
	/// The largest request body the server reads.
	pub max_request_bytes: u64,
}

/// The times a participation keeps to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipationsInfo {
	/// A coin is given up only while its first expiry lies at least this far
	/// ahead, and a later round time asked for must lie before that point:
	/// the exit deadline, three days.
	pub exit_deadline_seconds: u32,
	/// A participation's forfeits must come within this long of its round
	/// being found final, one day; otherwise it expires, its coins are the
	/// owner's again and its new leaves never are.
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
	/// it the operator co-signs spends of a coin resting on the board; after
	/// it, it takes the coin only into a refresh.
	pub exit_deadline_seconds: u32,
	/// A refresh takes the coin until this long before the expiry, one day.
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
	/// leaf only under a key it holds.
	pub key_proof: String,
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
	/// Set after a round it was released in could not return: the next
	/// preimage goes out only once its forfeit is published and claimed.
	pub forfeit_first: bool,
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
}

/// An entry of the signer's record: its number and running hash. A wallet
/// keeps every one it is shown, and refuses an operator that later shows a
/// lower latest entry, or another hash at an entry it has seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordHead {
	pub entry: u64,
	pub hash: String,
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

/// What `forfeit_leaves` returns: the participation's state, and its
/// preimage once released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Forfeited {
	pub participation_id: String,
	pub state: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub preimage: Option<String>,
	pub forfeit_first: bool,
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
