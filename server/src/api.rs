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
	"bad_attestation", "bad_forfeit", "bad_signature", "board_exists", "board_not_final", "board_output", "conflict", "depth_limit",
	"double_spend", "fee", "forfeit_set", "frozen", "hash_reused", "htlc", "in_use", "internal", "invalid_coin", "invalid_leaf", "invalid_record", "invoice",
	"invalid_transaction", "key_reused", "leaf_set", "lightning_unavailable", "malformed", "margin", "merge", "no_lightning",
	"no_lowest_node", "nonce_unknown",
	"nonce_used", "not_accepted", "not_an_order", "not_in_round", "not_live", "not_participating", "not_synced", "on_chain", "open_reassignment",
	"operator_key", "order", "order_expiring", "order_moved", "order_not_final", "order_spent", "order_taken", "out_of_bounds", "planned", "rate_limited", "rate_stale", "receive_cap", "release_early", "request_lapsed", "request_too_large",
	"round_not_final", "salt",
	"script_reused", "signer_replaced", "signer_unavailable", "template", "unauthenticated", "unbalanced", "unknown_batch", "unknown_board",
	"unknown_leaf", "unknown_order", "unknown_participation", "unknown_payment", "unknown_plan", "value", "wrong_chain", "wrong_operator", "wrong_round",
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
	/// The Lightning side beyond the assets' own legs (`assets[].lightning`).
	pub lightning: LightningInfo,
	/// How takes of on-chain orders are bounded (`take_order`).
	pub fills: FillsInfo,
	/// The operator's equivocation bond, as the server's node shows it now
	/// ([`crate::bond`]); absent when the operator configures none. A wallet
	/// checks it on its own node before it takes a payment out of round.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub bond: Option<BondInfo>,
}

/// The operator's equivocation bond ([`crate::bond`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BondInfo {
	/// `unposted`, `missing`, `unconfirmed`, `bonded`, `noticed` or `spent`.
	pub state: String,
	/// The bond coin, `txid:vout`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub outpoint: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub asset: Option<String>,
	/// In the asset's atoms.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub value: Option<String>,
	/// The value in atoms of the reference unit, at the operator's rate for
	/// the asset; absent without one.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub reference_value: Option<String>,
	/// The key it binds: the operator key `S`.
	pub operator: String,
	/// `W`, the only key that gives the notice and withdraws.
	pub withdraw_key: String,
	/// `D`, how long after the notice confirmed the bond can be withdrawn,
	/// in 512-second units.
	pub notice_units: u16,
	pub script_pubkey: String,
	pub notice_script_pubkey: String,
	/// In notice: the notice output, `txid:vout`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub notice: Option<String>,
	/// In notice: the median time from which a withdrawal can confirm.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub withdrawable_at: Option<u64>,
	/// Whether the coin that stands is final: certified, its anchor buried.
	#[serde(rename = "final")]
	pub final_: bool,
	/// What the state rests on.
	pub why: String,
}

/// How takes of on-chain orders are bounded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FillsInfo {
	/// No order is taken, or filled in a round, whose maker can refund it
	/// within this many seconds.
	pub order_margin_seconds: u32,
	/// The seconds a block is counted at for an order whose REFUND is locked
	/// to a height.
	pub block_seconds: u32,
	/// A round that fills orders goes out once every take in it has handed
	/// over its forfeits; one whose forfeits do not come within this many
	/// seconds of the round being built (by the chain's median time) is
	/// voided, and the round is built again without it.
	pub forfeit_window_seconds: u32,
	/// The seconds between the operator's rounds while participations wait,
	/// a fill round among them; 0 when it builds rounds only when asked. A
	/// wallet with a take pending wakes within this and within half the
	/// forfeit window, so it hands its forfeits over in time.
	#[serde(default)]
	pub round_interval_seconds: u64,
	/// Whether the server takes a take that shares its order
	/// (`take_order`'s `share`): several such takes of one order stand
	/// together, and one round fills their sum and pays each its own leaf.
	#[serde(default)]
	pub shared: bool,
}

/// An asset's Lightning leg: the operator's SeqLN node in that asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightningLegInfo {
	/// `up`: the node answered at the last check, on a network of the right
	/// chain, with at least one open channel in the asset; `down` otherwise,
	/// with the reason. A request over a leg that is down is refused
	/// `lightning_unavailable`.
	pub state: String,
	/// The node's id, while up.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub node: Option<String>,
	/// Its network, while up.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub network: Option<String>,
	/// Its open channels in the asset.
	pub channels: u32,
	/// What it can send and receive over them, in the asset's atoms.
	pub spendable: String,
	pub receivable: String,
	/// Whether it can take a payment into a leaf: it runs the hold-invoice
	/// plugin.
	pub receives: bool,
	/// Why it is down.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub reason: Option<String>,
}

/// The Lightning side `info` shows beside the assets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightningInfo {
	/// The operator's Lightning node on Bitcoin, for native BTC; absent
	/// when it runs none.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub bitcoin: Option<BitcoinLightningInfo>,
	/// The terms of the `htlc-1` leaf a payment out of the tree gives its
	/// coins up into.
	pub send: LightningSendInfo,
	/// The terms of the `htlc-1` leaf a payment into the tree is received
	/// in.
	pub receive: LightningReceiveInfo,
}

/// The operator's terms for a payment into the tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightningReceiveInfo {
	/// The delay on the operator's refund of the leaf, in 512-second units.
	pub operator_delay_units: u16,
	/// The time a wallet has, past its leaf's exit delay, to claim it once
	/// its round is final: the leaf's timeout leaves at least its exit delay
	/// and this.
	pub window_seconds: u32,
	/// How long an invoice is good for.
	pub invoice_expiry_seconds: u32,
	/// The chain's block interval, which turns the payment's lock times
	/// into time.
	pub block_seconds: u32,
	/// How long before the timeout of a payer's send leaf the leaf of a
	/// payment settled inside the operator times out: a payment out of the
	/// tree that pays this operator's own invoice.
	pub internal_gap_seconds: u64,
}

/// The operator's terms for a payment out of the tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightningSendInfo {
	/// The delay on the operator's claim, in 512-second units.
	pub operator_delay_units: u16,
	/// The least exit delay the leaf takes, the owner's refund delay.
	pub owner_delay_units: u16,
	/// The leaf's timeout lies at least this far past the chain's median
	/// time, and at most twice as far.
	pub timeout_seconds: u32,
}

/// The Bitcoin side: native BTC, on Bitcoin, never in a Sequentia leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinLightningInfo {
	pub node: LightningLegInfo,
	/// The Bitcoin ark the operator runs, which wallets join with Bark for
	/// native BTC; absent when it runs none.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub ark: Option<String>,
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
	/// The smallest leaf taken now, in the asset's atoms; absent while it is
	/// a value the operator has no rate to convert yet.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub min_leaf: Option<String>,
	/// The smallest leaf as the operator sets it when it sets it as a value,
	/// in atoms of the reference unit: `min_leaf` is that at `rate`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub min_leaf_value: Option<String>,
	/// The operator's rate for the asset, when it names a source for one.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rate: Option<RateInfo>,
	/// What the operator charges in the asset, in its atoms now; absent while
	/// a part set as a value has no rate to convert it at.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub fees: Option<AssetFeesInfo>,
	/// The asset's Lightning leg; absent when the operator runs no Lightning
	/// node in it.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub lightning: Option<LightningLegInfo>,
	/// Present when the operator serves the asset issuer-operated: every
	/// batch of it is funded by a reissue in its round, through the asset's
	/// mint limiter, and its sweep can only burn. A wallet refuses a batch
	/// of the asset whose sweep is not burn-only, and one of another asset
	/// whose sweep is.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub issuer: Option<IssuerInfo>,
	/// Present when the asset is supervised on the chain (its issuer can
	/// freeze holdings by consensus rule) and the operator serves it under
	/// the supervised profile: every leaf of it is `landing-1`, landing in
	/// its owner's own key with the allowance here; the operator co-signs
	/// nothing that spends a coin whose holder is frozen.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub supervised: Option<SupervisedInfo>,
}

/// What the operator serves of a supervised asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisedInfo {
	/// The fee allowance every `landing-1` leaf of the asset carries, in its
	/// atoms: the most of a leaf's value its landing may leave out of the
	/// output it pays its owner.
	pub landing_allowance: String,
}

/// An issuer-operated asset's mint limiter (sequentia-contracts
/// `templates/mint_limiter`), as its instance names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerInfo {
	/// The limiter's template hash.
	pub limiter: String,
	/// The asset's explicit reissuance token, which the limiter holds.
	pub token: String,
	/// The key that signs mints and the key that brakes them.
	pub operator_key: String,
	pub cold_key: String,
	/// The most minted in a window, in the asset's atoms, and the window in
	/// blocks.
	pub allowance: String,
	pub window_blocks: u16,
	pub recovery_delay_units: u16,
}

/// `POST /v1/issuer_supply`: what the operator mints and burns of an
/// issuer-operated asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerSupplyRequest {
	pub asset: String,
}

/// What the operator minted and burned of an issuer-operated asset, each
/// transaction named so a reader checks it against the chain, and what is
/// live in its batches now. Only transactions of the active chain count;
/// `state` says which are final.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerSupply {
	pub asset: String,
	/// The limiter's coin now, its state, and why it mints nothing now when
	/// it does not.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub limiter_coin: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub limiter_minted: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub limiter_elapsed: Option<u16>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub limiter_armed: Option<bool>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub limiter_unavailable: Option<String>,
	/// Every round's mint in the chain.
	pub mints: Vec<SupplyEntry>,
	/// Every burn of the operator's in the chain: a sweep, a claim, a
	/// reclaim, a refund, a margin.
	pub burns: Vec<SupplyEntry>,
	/// The sums of `mints` and `burns`, and of their final ones.
	pub minted: String,
	pub minted_final: String,
	pub burned: String,
	pub burned_final: String,
	/// The value under burn-only sweeps now: every unspent output of a
	/// burn-only batch of the asset (its batch output, a node or an entry on
	/// the chain) whose round is in the chain.
	pub in_batches: String,
	/// Each output `in_batches` counts, so a reader checks each against the
	/// chain and against its batch's published tree (`tree`).
	#[serde(default)]
	pub in_batches_outputs: Vec<BatchOutputEntry>,
}

/// An unspent output under a burn-only sweep: where it is, what it holds,
/// and where it sits in its batch's published tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchOutputEntry {
	/// `txid:vout`.
	pub outpoint: String,
	pub value: String,
	/// The batch's round and its output there, as `tree` takes them.
	pub round_txid: String,
	pub batch_vout: u32,
	/// `batch` (the round's batch output, the top level's one node), `node`
	/// (a node below it, on the chain once unrolled) or `entry` (a leaf's
	/// entry, below a lowest node).
	pub kind: String,
	/// A node's level in the published tree's `nodes`, the lowest nodes 0,
	/// and its index in that level; for an entry, -1 and its leaf's index.
	/// Absent for the batch output.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub level: Option<i16>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub index: Option<u32>,
}

/// A transaction that minted or burned an issuer-operated asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyEntry {
	pub txid: String,
	/// `round`, or the watcher's kind of transaction (`sweep`, `claim`,
	/// `reclaim`, …).
	pub kind: String,
	pub amount: String,
	/// `final`, `settled` or `unsettled`.
	pub state: String,
}

/// What the operator charges in one asset: a refresh, falling to nothing in
/// the free window (`fees.free_window_seconds`, `fees.full_after_seconds`),
/// `refresh_ppm` of each coin given up plus `refresh_base` atoms a coin at
/// most; an offboard, `offboard_ppm` of what it pays out plus
/// `offboard_base` atoms and its output's margin. A fixed part the operator
/// sets as a value in the reference unit is shown as such beside it
/// (`refresh_base_value`, `offboard_base_value`), taken in atoms at the
/// asset's `rate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetFeesInfo {
	pub refresh_ppm: u64,
	pub refresh_base: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub refresh_base_value: Option<String>,
	pub offboard_ppm: u64,
	pub offboard_base: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub offboard_base_value: Option<String>,
	/// A payment over Lightning, either way: `lightning_ppm` of what it moves,
	/// rounded up, plus `lightning_base` atoms.
	pub lightning_ppm: u64,
	pub lightning_base: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub lightning_base_value: Option<String>,
}

/// The operator's rate for an asset ([`crate::rates`]): what 10^8 atoms of
/// the asset are worth in atoms of the reference unit, where it comes from,
/// and how old it is. While it is `stale` the server takes no new work in
/// the asset (`rate_stale`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateInfo {
	/// `node`, `file` or `command`.
	pub source: String,
	/// The last rate read; absent before the first.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rate: Option<String>,
	/// When its price was taken, in unix seconds, and how long ago.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub time: Option<u64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub age_seconds: Option<u64>,
	/// How long a rate is good for.
	pub max_age_seconds: u64,
	pub stale: bool,
	/// Why the last read of the source failed, when it did.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub failed: Option<String>,
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
	/// The refresh fee an asset takes where it sets none of its own (each
	/// asset's own is `assets[].fees`), in parts per million of a coin's value, for a coin
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
	/// What a payment over Lightning costs, either way, where an asset sets
	/// none of its own (`assets[].fees.lightning_ppm`).
	pub lightning_ppm: u64,
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
	/// When the receive request this output pays lapses, as the request
	/// carries it (`until`, a median time): its receiver waits for a payment
	/// to it until then. The server records no transfer once the chain's
	/// median time has reached it (`request_lapsed`); a transfer it recorded
	/// before completes. Absent for the sender's own change, and from a
	/// sender that does not name it.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub until: Option<u32>,
	/// The terms of an `htlc-1` leaf: only in a payment over Lightning
	/// (`lightning_send`).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub htlc: Option<HtlcTermsJson>,
	/// The landing of a `landing-1` leaf, for a leaf of a supervised asset,
	/// in the leaf record's JSON form (`{"program", "allowance"}`): the
	/// program of the receiver's landing key, as its receive request names
	/// it, and the operator's published allowance.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub landing: Option<serde_json::Value>,
}

/// An `htlc-1` leaf's terms beside its owner's key, nonces and exit delay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HtlcTermsJson {
	/// `send`: the operator claims with the preimage, the owner refunds.
	pub direction: String,
	pub payment_hash: String,
	/// The median time from which the refund opens.
	pub timeout: u32,
	pub operator_delay_units: u16,
}

impl HtlcTermsJson {
	pub fn of(t: &arca_covenant::HtlcTerms) -> HtlcTermsJson {
		HtlcTermsJson {
			direction: t.direction.name().into(),
			payment_hash: crate::signer::hex(&t.payment_hash),
			timeout: t.timeout.to_consensus_u32(),
			operator_delay_units: t.operator_delay.units(),
		}
	}
}

/// `POST /v1/lightning_send`: pay `invoice` with the transfer, whose outputs
/// make one `htlc-1` leaf of the payment and the change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightningSend {
	pub invoice: String,
	pub inputs: Vec<TransferInput>,
	pub outputs: Vec<TransferOutput>,
}

/// The answer to `lightning_send`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightningSent {
	pub cosigned: Cosigned,
	pub payment: LightningPayment,
}

/// A payment out of the tree, as `lightning_send` and `lightning_send_status`
/// answer it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightningPayment {
	pub payment_hash: String,
	pub asset: String,
	/// What the invoice asks, and the operator's fee, in the asset's atoms.
	pub amount: String,
	pub fee: String,
	/// The `htlc-1` coin the payment gave up.
	pub htlc_leaf_id: String,
	/// `paying`, `paid` (with the preimage) or `failed` (with the reason):
	/// once failed, the operator co-signs the coin back to its owner.
	pub state: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub preimage: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub reason: Option<String>,
}

/// `POST /v1/lightning_receive`: an invoice paid into the tree, under the
/// wallet's own payment hash, into an `htlc-1` leaf of `owner` in a round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightningReceive {
	pub asset: String,
	/// What the invoice asks, in the asset's atoms; the leaf holds it less
	/// the operator's fee.
	pub amount: String,
	pub payment_hash: String,
	/// The key the leaf is asked under, its nonce, and its exit delay.
	pub owner: String,
	pub owner_nonce: String,
	pub exit_delay_units: u16,
	#[serde(default)]
	pub description: Option<String>,
	/// The owner key's BIP340 signature over the request:
	/// `SHA256(T ‖ T ‖ genesis_hash ‖ S ‖ asset ‖ amount ‖ payment_hash ‖
	/// owner ‖ owner_nonce ‖ exit_delay_units)`, `T =
	/// SHA256("Arca/lightning-receive")`.
	pub owner_sig: String,
	/// The mailbox key the leaf is bound to when it is made, and the owner
	/// key's signature over the binding (as a refresh's wanted leaves name
	/// it), both or neither: a restore from the mnemonic is then served the
	/// leaf before it is claimed.
	#[serde(default)]
	pub mailbox: Option<String>,
	#[serde(default)]
	pub mailbox_proof: Option<String>,
}

/// A payment into the tree, as `lightning_receive` and its status answer
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightningReceived {
	pub payment_hash: String,
	pub asset: String,
	pub amount: String,
	pub fee: String,
	/// What the leaf holds: the amount less the fee.
	pub value: String,
	pub invoice: String,
	/// When the invoice expires (Unix time).
	pub expires_at: u64,
	/// `open`, `accepted` (held, the leaf wanted by `participation_id`),
	/// `claimed` (the preimage handed over) or `cancelled` (failed back).
	pub state: String,
	/// Whether the node has settled the payment.
	pub settled: bool,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub participation_id: Option<String>,
	/// The leaf's timeout, a median time.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub timeout: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub reason: Option<String>,
	/// The exit delay of the leaf asked for, in 512-second units.
	#[serde(default)]
	pub exit_delay_units: u16,
	/// What holds the payment once it is held: `node`, a Lightning payment
	/// held at the operator's node, or `send`, a payment out of the tree at
	/// this operator that pays the invoice, settled inside the operator.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub held_by: Option<String>,
	/// For a payment held by a send: that send leaf's timeout, a median time.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub send_timeout: Option<u32>,
	/// The preimage, once the operator knows it.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub preimage: Option<String>,
}

/// `POST /v1/lightning_preimage`: the preimage of a payment into the tree,
/// from anyone who has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightningPreimage {
	pub payment_hash: String,
	pub preimage: String,
}

/// `POST /v1/lightning_receive_status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightningReceiveStatus {
	pub payment_hash: String,
}

/// `POST /v1/lightning_receive_claim`: the payment's preimage, and the
/// transfer of its leaf to a leaf of the owner's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightningReceiveClaim {
	pub payment_hash: String,
	pub preimage: String,
	pub inputs: Vec<TransferInput>,
	pub outputs: Vec<TransferOutput>,
}

/// The answer to `lightning_receive_claim`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightningClaimed {
	pub cosigned: Cosigned,
	pub receive: LightningReceived,
}

/// `POST /v1/lightning_send_status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightningSendStatus {
	pub payment_hash: String,
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

/// `POST /v1/order_publish`: a maker publishes the resting order a round
/// made it, so that takers fill it while the maker is away.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderPublish {
	/// The record of the coin a round made of the order, binary form, as
	/// the maker holds it: with its entry's preimage and the maker's unroll
	/// authorisations.
	pub record: String,
	/// The nonces of the order's four credit keys, the first credit's first.
	pub credit_nonces: Vec<String>,
	/// The mailbox the order's credits and remainders go to.
	pub mailbox: String,
	/// The order's leaf key's signature over the publication.
	pub signature: String,
}

/// `POST /v1/order_fill`: a taker fills a resting order in the tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderFill {
	/// The order: the leaf id of the coin a round made of it.
	pub order: String,
	/// The coin it rests at, as `order_state` showed it.
	pub coin: String,
	/// What the taker takes of the order's asset, in atoms.
	pub filled: String,
	/// The taker's coins, in the asset the order is paid in, each with its
	/// owner's signatures over its checkpoint and over the fill's outputs.
	pub inputs: Vec<TransferInput>,
	/// The taker's leaves: of what it fills, then its change.
	pub outputs: Vec<TransferOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderFilled {
	pub transfer_id: String,
	/// The operator's signature over the fill.
	pub fill_signature: String,
	/// The operator's signatures for each of the taker's coins.
	pub signatures: Vec<OperatorSignatures>,
	/// Each coin the fill makes, in output order: the maker's credit, the
	/// order resting again after a partial fill, then the taker's leaves.
	pub outputs: Vec<Coin>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub signer_record: Option<RecordHead>,
}

/// `POST /v1/order_state`: how resting orders stand, by their ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderStateRequest {
	pub orders: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderStates {
	/// Each order asked for that is published here; one that is not is left
	/// out.
	pub orders: Vec<OrderState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderState {
	pub order: String,
	/// `resting` (a taker can fill it), `exhausted` (it rests, and fills no
	/// more: its credit keys are used), `filling` (a fill of the coin it
	/// rests at is recorded and not yet signed: it takes no other fill, and
	/// the fill is either signed or dropped), `filled` (filled whole, the fill
	/// signed), `cancelled` (its maker gave its coin up otherwise), `landed`
	/// (the coin it rests at is on the chain, brought there by its maker or
	/// by the operator at its exit deadline, and moves whole into SeqDEX's
	/// order for the same terms: it takes no fill in the tree), `pending`, or
	/// `unknown`.
	pub state: String,
	/// The coin it rests at now, and what of the asset it sells it holds.
	pub coin: String,
	pub asset: String,
	pub value: String,
	/// What a taker builds a fill from: the coin's leaf key, salt, exit delay
	/// and order terms (the leaf record's `order`, its credit keys the next
	/// first).
	pub owner: String,
	pub salt: String,
	pub exit_delay_units: u16,
	pub terms: serde_json::Value,
	pub fills_left: u8,
	/// The earliest first expiry of the batches the coin rests on.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub expiry: Option<u32>,
	/// The coin's record, binary form, while it rests: a taker checks the
	/// coin is in the tree before it signs a fill of it.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub record: Option<String>,
	pub fills: Vec<OrderFillState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderFillState {
	pub transfer_id: String,
	/// The order coin it spent.
	pub coin: String,
	pub filled: String,
	pub credited: String,
	pub partial: bool,
	pub signed: bool,
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
/// to `limit`: coins, and with `notices` the notices of coins pending and
/// withdrawn too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxRead {
	pub auth: Auth,
	pub after: String,
	pub limit: u32,
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub notices: bool,
}

/// A notice in a mailbox (D61): a transfer the server recorded and has not
/// signed yet will make the coin `leaf_id` of the mailbox's (`pending`:
/// its asset, value, owner key and nonce, and `until`, the median time from
/// which it can no longer complete, its earliest batch's expiry, absent for
/// coins resting on boards alone), or that transfer was dropped and the coin
/// will never come (`withdrawn`, with the reason).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxNotice {
	pub transfer_id: String,
	pub leaf_id: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub asset: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub value: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub owner: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub owner_nonce: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub until: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub reason: Option<String>,
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
	/// For a notice (`kind` `pending` or `withdrawn`), what it says; its
	/// `record` is then empty.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub notice: Option<MailboxNotice>,
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
	/// On the first page: every payment into the tree asked under a key
	/// bound to the authenticated key and not yet claimed or failed back
	/// (`open` or `accepted`), with the operator's participation for its
	/// leaf once held, so a wallet restored from its mnemonic takes the leaf
	/// up (D70).
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub receives: Vec<ServedReceive>,
}

/// A payment into the tree as `leaf_data` serves it to the mailbox key its
/// leaf's key is bound to: what was asked, the invoice, and how it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServedReceive {
	pub payment_hash: String,
	pub asset: String,
	pub amount: String,
	pub fee: String,
	pub invoice: String,
	pub owner: String,
	pub owner_nonce: String,
	pub exit_delay_units: u16,
	/// `open` or `accepted`.
	pub state: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub participation_id: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub timeout: Option<u32>,
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

/// One way a coin was given up: `{"transfer": …}`, `{"participation": …}`,
/// or, for the `htlc-1` leaf of a payment out of the tree that is paid,
/// `{"payment": …}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LeafGiven {
	Transfer(GivenTransfer),
	Participation(GivenParticipation),
	Payment(GivenPayment),
}

/// A payment over Lightning out of the tree that paid with the coin, its
/// `htlc-1` leaf: its hash and the preimage that proves it paid, which its
/// owner checks opens the leaf's hash. The leaf is then the operator's,
/// which claims it with that preimage should it come on the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GivenPayment {
	pub payment_hash: String,
	pub state: String,
	pub preimage: String,
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
	/// For a take, the order its id covers besides these parts:
	/// `arca_covenant::Take::id` is recomputed from them.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub fill: Option<GivenFill>,
}

/// The order a take that gave a coin up takes, as its id covers it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GivenFill {
	/// The order's terms in the relay's form, its outpoint among them.
	pub order: serde_json::Value,
	pub locked: String,
	pub filled: String,
	/// Whether the take shares its order with other takes of it.
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub shared: bool,
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
	/// An `htlc-1` leaf's terms (a payment received over Lightning).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub htlc: Option<HtlcTermsJson>,
	/// An `order-2` leaf's terms, a resting order.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub order: Option<serde_json::Value>,
	/// A `landing-1` leaf's landing, a leaf of a supervised asset.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub landing: Option<serde_json::Value>,
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
	/// `order-2`'s terms, for a resting order (template `order-2`), in the
	/// leaf record's JSON form of them (`arca_covenant::record_json::order_terms_json`):
	/// covered by the participation's id.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub order: Option<serde_json::Value>,
	/// `landing-1`'s landing, for a leaf of a supervised asset (template
	/// `landing-1`), in the leaf record's JSON form (`{"program", "allowance"}`,
	/// `arca_covenant::record_json::landing_json`): the program of the
	/// owner's landing key its exit pays, and the operator's published
	/// allowance. Covered by the participation's id.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub landing: Option<serde_json::Value>,
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

/// `POST /v1/take_order`: a take of the on-chain order the relay serves as
/// `order`, by `filled` atoms of the asset it sells, giving up `inputs` in
/// the asset it is paid in for the one leaf `leaf`, and paying `fee` in that
/// asset. Its id is `arca_covenant::Take::id`, which each input's
/// attestation signs and the leaf's key proof covers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TakeOrder {
	/// The order's `CovenantTerms`, in the relay's JSON form, or an offer
	/// whose settlement is one.
	pub order: serde_json::Value,
	/// What the order holds at its outpoint, in atoms, as the taker read it.
	pub locked: String,
	pub filled: String,
	pub inputs: Vec<ParticipationInput>,
	pub leaf: WantedLeaf,
	pub fee: FeeAmount,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub not_before: Option<u32>,
	/// Whether the take accepts a round that fills its order together with
	/// other takes of it, each paid a leaf of its own fill (a server whose
	/// `info.fills.shared` is true takes it). Absent or false: the take takes
	/// the order alone.
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub share: bool,
}

/// The order a take takes, in its status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FillStatus {
	/// `txid:vout`.
	pub order: String,
	/// The asset it sells, and the one it is paid in.
	pub asset_a: String,
	pub asset_b: String,
	pub locked: String,
	pub filled: String,
	/// What rests again after the fill; 0 for a full fill.
	pub remainder: String,
	/// The maker's credit: the price of the fill, in `asset_b`.
	pub price: String,
	/// The maker's program, which the credit pays (`OP_1 <program>`).
	pub maker_script: String,
	/// The order's scriptPubKey.
	pub script: String,
	/// Once in a round: the order's input `k`, the maker's credit at `2k`,
	/// and at `2k+1` the order resting again, or, filled whole, an output of
	/// another asset.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub input: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub credit_vout: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub remainder_vout: Option<u32>,
	/// Once in a round: what the round fills of the order, every take of it
	/// together (this one's `filled` among them), what rests again after
	/// that, the maker's credit at `2k` for it, and how many takes share it.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub round_filled: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub round_remainder: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub round_credit: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub round_takes: Option<u32>,
}

/// `POST /v1/transfer_status`: how the transfer `transfer_id` stands, and
/// the output `leaf_id` of it, when it has one: what a wallet holding a
/// notice that the coin is pending for it (D61) checks the notice by (D69).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferStatusRequest {
	pub transfer_id: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub leaf_id: Option<String>,
}

/// A transfer: `recorded` (not yet co-signed), `signed`, or `unknown` (never
/// recorded, or dropped), and the output asked for when it is one of its
/// outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferStatus {
	pub transfer_id: String,
	pub state: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub output: Option<TransferOutputStatus>,
}

/// An output of a transfer, as the server holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferOutputStatus {
	pub leaf_id: String,
	pub owner: String,
	pub asset: String,
	pub value: String,
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
	/// For a take, the order it takes.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub fill: Option<FillStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoundRef {
	pub txid: String,
	/// The round's connector output, whose asset every forfeit of the round names.
	pub connector_vout: u32,
	/// For a round that fills on-chain orders and is not broadcast yet: the
	/// transaction without its witnesses (its txid the round's), which a
	/// take validates its new leaf against before it hands over its forfeits;
	/// nobody but the operator can broadcast it.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub tx: Option<String>,
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
	/// An `htlc-1` leaf's terms (a payment received over Lightning).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub htlc: Option<HtlcTermsJson>,
	/// An `order-2` leaf's terms, a resting order.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub order: Option<serde_json::Value>,
	/// A `landing-1` leaf's landing (`{"program", "allowance"}`): where its
	/// owner's exit pays, the leaf of a supervised asset. Anyone, its issuer
	/// included, reads from it where each leaf of a batch lands.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub landing: Option<serde_json::Value>,
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
	/// Absent for a take whose forfeits came before its round was
	/// broadcast: it goes out once the round is final.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub preimage: Option<String>,
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

/// `POST /v1/distribute`: a distribution, one round paying many holders
/// (a claim tree). Each coin given up is attested over the distribution's id
/// ([`arca_covenant::Distribution::id`]); each claim names a key, the nonce
/// the payer drew for it and what its leaf holds, and the leaf is owned by
/// the claim key of the two ([`arca_covenant::claim_key`]). Answered as
/// `participation_status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Distribute {
	pub inputs: Vec<ParticipationInput>,
	pub asset: String,
	pub exit_delay_units: u16,
	pub claims: Vec<ClaimWanted>,
	/// The script the unclaimed sum is paid to, hex.
	pub return_script: String,
	pub fees: Vec<FeeAmount>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub not_before: Option<u32>,
}

/// One claim of a distribution: the named key (x-only, hex), the payer's
/// nonce for it, and the leaf's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimWanted {
	pub key: String,
	pub nonce: String,
	pub value: String,
}

/// `POST /v1/distribution_status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistributionStatusRequest {
	pub distribution_id: String,
}

/// A distribution as its payer sees it: its participation's state, where
/// its leaves are, the deadline by which a holder takes a claim up through
/// the operator (the claim leaves' exit deadline, three days before their
/// batch's first expiry), each claim, and each payment of unclaimed leaves
/// back to the return script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistributionStatus {
	pub distribution_id: String,
	pub state: String,
	pub asset: String,
	pub return_script: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub round: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub expiry: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub deadline: Option<u32>,
	pub claims: Vec<ClaimStatus>,
	pub returns: Vec<ClaimReturn>,
	/// What the returns pay together.
	pub returned: String,
}

/// One claim's state: `pending` (its distribution not released), `open`
/// (its leaf live, not taken up), `claimed` (its leaf spent, by its holder's
/// take-up or refresh), `returned` (paid back to the payer after a final
/// sweep took it), or the state of a distribution that never released
/// (`void`, `expired`), or of a leaf lost with its round (`lost`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimStatus {
	pub index: u16,
	pub key: String,
	pub owner: String,
	pub value: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub leaf_id: Option<String>,
	pub state: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub returned_in: Option<String>,
}

/// A payment of unclaimed leaves to the payer: its transaction, what it
/// pays, and where it stands in the nursery (`pending`, `final`, `lost`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimReturn {
	pub txid: String,
	pub value: String,
	pub state: String,
}

/// `POST /v1/claims`: the claims under each key, each key proven by its
/// signature over the authentication digest of the call `claims`, the
/// challenge and the key, with an empty request ([`crate::auth`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimsRequest {
	pub challenge: String,
	pub keys: Vec<KeyProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyProof {
	pub key: String,
	pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
	pub claims: Vec<ClaimFound>,
}

/// A claim found under a key: what its holder needs to check its leaf and
/// take it up. The record (the leaf's record in its tree, hex) and the
/// preimage come once the distribution is released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimFound {
	pub distribution_id: String,
	pub index: u16,
	pub key: String,
	pub nonce: String,
	pub owner: String,
	pub asset: String,
	pub value: String,
	pub exit_delay_units: u16,
	pub state: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub leaf_id: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub round: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub batch_vout: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub leaf_index: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub record: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub preimage: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub expiry: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub deadline: Option<u32>,
}

/// `POST /v1/claim_leaf`: a holder's unroll authorisations for a claim leaf,
/// one per node above it from the batch output down, signed by its claim key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimLeaf {
	pub leaf_id: String,
	pub auths: Vec<UnrollAuth>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimLeafAnswer {
	pub leaf_id: String,
	pub state: String,
}

/// `POST /v1/plan_quote`: a quote for an offline-refresh plan from the coin
/// `coin`, one step per owner nonce, its leaves under the exit delay given,
/// asked by the coin's owner (its signature over the quote digest,
/// [`crate::plans::quote_digest`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanQuoteRequest {
	pub coin: String,
	pub owner_nonces: Vec<String>,
	pub exit_delay_units: u16,
	pub attestation: String,
}

/// What `plan_quote` answers: the quote's id, the coin's asset, value and
/// first expiry, the earliest median time of step 1's round, the script the
/// operator's share of every refund pays to, and per step its operator
/// nonce, its fee and its refund's margin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanQuote {
	pub quote: String,
	pub coin: String,
	pub asset: String,
	pub value: String,
	pub expiry: u32,
	pub earliest: u32,
	pub operator_script: String,
	pub steps: Vec<PlanQuoteStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanQuoteStep {
	pub operator_nonce: String,
	pub fee: String,
	pub margin: String,
}

/// `POST /v1/submit_plan`: an offline-refresh plan, everything its holder
/// hands over with it ([`crate::plans`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitPlan {
	pub quote: String,
	pub coin: String,
	/// The mailbox key every leaf of the plan is bound to.
	pub mailbox: String,
	/// The coin's owner's signature over the plan's id.
	pub attestation: String,
	pub steps: Vec<SubmitPlanStep>,
}

/// One step of a plan: the leaf it makes, its refund, and what its key
/// signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitPlanStep {
	pub value: String,
	pub fee: String,
	pub owner: String,
	pub owner_nonce: String,
	pub operator_nonce: String,
	pub exit_delay_units: u16,
	pub unlock_hash: String,
	pub preimage: String,
	pub holder_script: String,
	pub operator_script: String,
	pub margin: String,
	pub key_proof: String,
	pub old_half: String,
	pub new_half: String,
	pub mailbox_proof: String,
}

/// `POST /v1/plan_status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanStatusRequest {
	pub plan_id: String,
}

/// A plan as its holder sees it: `open`, `done`, `cancelled` or `stopped`
/// (with the reason), and each step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanStatus {
	pub plan_id: String,
	pub coin: String,
	pub asset: String,
	pub value: String,
	pub state: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub reason: Option<String>,
	pub steps: Vec<PlanStepStatus>,
}

/// A step: `waiting`, `running`, `done` or `void` (with the reason); the leaf
/// it makes as the plan names it; the coin it gives up once known; its round
/// once in one; and its leaf, with the leaf's record in the tree once its
/// round is final.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanStepStatus {
	pub idx: u16,
	pub state: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub reason: Option<String>,
	/// The leaf the step makes, as the plan names it: what a wallet restored
	/// from its mnemonic derives the leaf's key and preimage from, and
	/// recognises the refund's output by.
	pub value: String,
	pub fee: String,
	pub owner: String,
	pub owner_nonce: String,
	pub operator_nonce: String,
	pub exit_delay_units: u16,
	pub unlock_hash: String,
	pub holder_script: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub participation_id: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub gives_up: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub round_txid: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub round_state: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub leaf_id: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub batch_vout: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub leaf_index: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub record: Option<String>,
}

/// `POST /v1/plans`: every plan whose leaves are bound to the authenticated
/// key (a wallet's mailbox key), the newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlansRequest {
	pub auth: Auth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanList {
	pub plans: Vec<PlanStatus>,
}

/// `POST /v1/cancel_plan`: the plan's mailbox key's signature over its
/// cancel digest ([`crate::plans::cancel_digest`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelPlan {
	pub plan_id: String,
	pub signature: String,
}

/// `POST /v1/plan_leaf`: the holder's unroll authorisations for a leaf a
/// step of a plan made, signed by the leaf's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanLeaf {
	pub leaf_id: String,
	pub auths: Vec<UnrollAuth>,
}
