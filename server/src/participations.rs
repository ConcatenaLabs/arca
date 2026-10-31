//! Participations: what an owner submits, once, to take part in a round.
//!
//! Every participation is non-interactive. The owner names the coins it gives
//! up, each with an attestation (its owner key's signature over the
//! participation's id), the outputs it wants for them (leaves, each with its
//! template, owner key, owner nonce and exit delay, or offboards to an
//! on-chain script), the fee it pays per asset, and optionally the earliest
//! time of a round it may run in. Then the round runs it without the owner
//! online.
//!
//! The server accepts a participation only when:
//!
//! - it carries one asset, as the round it runs in does: every coin it gives
//!   up, every output it wants and every fee it pays is in that asset
//!   (`out_of_bounds` otherwise, naming the assets);
//! - every coin given up passes the check of [`crate::coins`]: known, live,
//!   held by nothing else, its record valid, its boards credited and unspent,
//!   nothing of its lineage on-chain, and its first expiry (or the service
//!   expiry of a board it rests on, whichever comes first) still past its
//!   exit deadline, three days ahead ([`Params::participation_policy`]); its
//!   attestation verifies; and the earliest round time asked for, if any,
//!   lies before every coin's exit deadline;
//! - no coin given up is of a supervised asset whose holder is frozen
//!   ([`crate::supervision`]), checked before anything else about the
//!   request;
//! - every leaf wanted is a template the round builds (`vtxo-1`; `landing-1`
//!   with the published allowance for a supervised asset, whose leaves are
//!   all `landing-1`; `order-3` for a resting order, never `order-2`, whose
//!   fill takes an annex nothing signs), within the
//!   published bounds (an asset served, a value within its bounds, an exit
//!   delay within the bounds), under a key that owns no leaf, is wanted by no
//!   other participation and is not the operator's `S`; every offboard pays a served asset within its
//!   bounds to a script that is not an Arca script the server knows;
//! - the coins given up hold exactly what the outputs take plus the fee,
//!   and the fee covers the published schedule
//!   ([`crate::params::FeeSchedule`]);
//! - the operator's signer holds nothing under any coin's salt: no forfeit
//!   (a coin an older server gave back while its forfeit stood in the
//!   signer's record, which stays given up, its owner's way home its exit)
//!   and no spend (one the database lost). Either would leave a forfeit of
//!   this round beside another, or refused for good, and the participation
//!   could then be neither released nor expired. The refusal is
//!   `double_spend`, naming the coin and what the signer holds.
//!
//! It then chooses the participation's unlock hash, draws its own operator
//! nonce for every leaf wanted (taken by this participation at once, so never
//! handed out again), takes each leaf's owner nonce as given, promises the
//! participation the salt the two make (drawing again in the unlikely case
//! the server has seen it: a salt is unique on a server, so no transfer can
//! take it before the round makes the leaf), prices each
//! forfeit's margin, and records it all, the coins given up becoming spent by
//! the participation, in one database transaction. A participation submitted
//! again is the same participation and gets its status, whatever key proofs
//! it carries: the id does not cover them, and they were checked when it was
//! taken, so a request repeated without them is answered too.
//!
//! The participation's id is a tagged hash of the whole request but the
//! attestations and key proofs, which sign it:
//!
//! ```text
//! SHA256(T ‖ T ‖ genesis_hash ‖ S ‖ body),   T = SHA256("Arca/participation")
//! body = n, each leaf id given up
//!      ‖ m, each output: kind (0 leaf, 1 offboard), asset, value (u64),
//!          then for a leaf: template id, template version, owner key, owner nonce, exit delay units (u16),
//!          and for an order-3 (or order-2) leaf its terms (the leaf record's binary form of them, 252 bytes)
//!          and for a landing-1 leaf its landing (the program, 20 bytes, and the allowance, u64)
//!          and for an offboard: script length (u16), script
//!      ‖ f, each fee: asset, amount (u64)
//!      ‖ 0, or 1 and the earliest round time (u32)
//! ```
//!
//! counts as one byte, integers little-endian, asset ids in internal byte
//! order. The tag keeps the attestation apart from everything else a leaf key
//! signs; the genesis hash and `S` keep it to one chain and one operator.
//!
//! A take ([`Participations::take`]) is a participation that asks the round
//! to fill an on-chain order for its owner: it gives up coins in the asset the
//! order is paid in and wants one leaf of what it fills, in the asset the
//! order sells, so it carries those two assets and runs in no refresh round.
//! Its id is [`arca_covenant::Take::id`], under its own tag. Several takes of
//! one order that each say they share it run in one round, which fills their
//! sum and pays each its own leaf.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, OutPoint, Script};
use rand::RngCore;

use arca_covenant::offboard::MAX_DESTINATION;
use arca_covenant::script::sha256 as sha256_bytes;
use arca_covenant::sign::verify_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::{
	connector_asset, Chain, ExplicitOutput, FillError, FillOrder, Forfeit, LeafId, MedianTime, OffboardPolicy, Pair, RefundLock,
	RelativeTime, Take, TakeLeaf, Template, ValidCoin,
};

#[path = "distributions.rs"]
pub mod distributions;

use crate::chain::FinalityService;
use crate::coins::{self, CoinError};
use crate::fees;
use crate::params::Params;
use crate::signer::{hex, Signed, SignerClient, SignerError};
use crate::store::{
	FillRow, NewParticipation, ParticipationInput, ParticipationOutput, ParticipationRow, Store, StoreError, WantedKind,
};

/// The most coins one participation gives up.
pub const MAX_INPUTS: usize = 16;
/// The most outputs one participation wants.
pub const MAX_OUTPUTS: usize = 16;
/// How far ahead of now a participation may name the earliest round it runs
/// in, in seconds.
pub const MAX_DEFER: u32 = 7 * 86_400;
/// The tag of a participation's id.
pub const PARTICIPATION_TAG: &[u8] = b"Arca/participation";

/// The tag of a key proof: the signature, by the key a leaf is wanted under,
/// that the participation's author holds that key.
pub const KEY_PROOF_TAG: &[u8] = b"Arca/participation-key";

/// The digest each key a participation wants a leaf under signs:
/// `SHA256(T ‖ T ‖ id)`, `T = SHA256("Arca/participation-key")`. The tag keeps
/// it apart from the attestation over the id itself, which gives up a coin.
pub fn key_proof_digest(id: &[u8; 32]) -> [u8; 32] {
	let tag = sha256::Hash::hash(KEY_PROOF_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(id);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// A coin given up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRequest {
	pub leaf_id: LeafId,
	/// The coin's owner key's signature over the participation's id.
	pub attestation: Signature,
}

/// An output wanted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputRequest {
	Leaf {
		asset: AssetId, value: u64, template: Template, owner: XOnlyPublicKey, owner_nonce: [u8; 32], exit_delay: RelativeTime,
		/// An order's terms, for a resting order (`order-3`).
		order: Option<arca_covenant::OrderLeafTerms>,
		/// `landing-1`'s landing, for a leaf of a supervised asset.
		landing: Option<arca_covenant::Landing>,
		/// `channel-1`'s terms, for a channel leaf: the operator's side of
		/// `value` and the credit window.
		channel: Option<arca_covenant::Channel>,
	},
	Offboard { asset: AssetId, value: u64, script: Script },
}

impl OutputRequest {
	pub fn asset(&self) -> AssetId {
		match self {
			OutputRequest::Leaf { asset, .. } | OutputRequest::Offboard { asset, .. } => *asset,
		}
	}

	pub fn value(&self) -> u64 {
		match self {
			OutputRequest::Leaf { value, .. } | OutputRequest::Offboard { value, .. } => *value,
		}
	}

	/// What the output takes of the participation's coins: its value, less
	/// the operator's side of a channel leaf, which the operator funds.
	pub fn owner_value(&self) -> u64 {
		match self {
			OutputRequest::Leaf { value, channel: Some(c), .. } => value.saturating_sub(c.capacity),
			o => o.value(),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipationRequest {
	pub inputs: Vec<InputRequest>,
	pub outputs: Vec<OutputRequest>,
	/// For each output, in order, the proof of its key ([`key_proof_digest`],
	/// signed by the key a leaf is wanted under); `None` for an offboard, and
	/// for a leaf of a request that brings none, which is refused unless the
	/// server holds the participation already.
	pub key_proofs: Vec<Option<Signature>>,
	/// The fee paid, per asset, in that asset.
	pub fees: Vec<(AssetId, u64)>,
	/// The earliest median time of a round it may run in.
	pub not_before: Option<MedianTime>,
}

impl ParticipationRequest {
	/// The participation's id: see the [module documentation](self).
	pub fn id(&self, chain: &Chain, operator: &XOnlyPublicKey) -> [u8; 32] {
		participation_id(chain, operator, &self.inputs.iter().map(|i| i.leaf_id).collect::<Vec<_>>(), &self.outputs, &self.fees, self.not_before)
	}
}

/// A take: a holder asks the round to fill the on-chain order at `order`,
/// whose terms are `terms`, by `filled` atoms, giving up `inputs` (coins in
/// the asset the order is paid in, worth its price and the fee) for one leaf
/// of `filled` in the asset it sells. Its id is [`Take::id`], which every
/// coin's owner attests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TakeRequest {
	pub order: OutPoint,
	pub terms: FillOrder,
	/// What the order holds on the chain, as the taker read it.
	pub locked: u64,
	pub filled: u64,
	pub inputs: Vec<InputRequest>,
	/// The leaf wanted ([`OutputRequest::Leaf`]).
	pub leaf: OutputRequest,
	/// The proof of the leaf's key ([`key_proof_digest`] of the take's id).
	pub key_proof: Option<Signature>,
	/// The operator's fee, in the asset the order is paid in.
	pub fee: (AssetId, u64),
	pub not_before: Option<MedianTime>,
	/// Whether the take accepts a round that fills its order together with
	/// other takes of it: the round then fills their sum, and each is paid a
	/// leaf of its own fill. Not covered by the id: it changes which takes a
	/// round runs together, never what any take gives or gets.
	pub share: bool,
}

impl TakeRequest {
	/// The take its id covers; `None` when the leaf wanted is not a leaf.
	pub fn take(&self) -> Option<Take> {
		let OutputRequest::Leaf { asset, value, template, owner, owner_nonce, exit_delay, .. } = &self.leaf else { return None };
		Some(Take {
			order: self.order,
			terms: self.terms.clone(),
			locked: self.locked,
			filled: self.filled,
			inputs: self.inputs.iter().map(|i| i.leaf_id).collect(),
			leaf: TakeLeaf { asset: *asset, value: *value, template: *template, owner: *owner, owner_nonce: *owner_nonce,
				exit_delay: *exit_delay },
			fee: self.fee,
			not_before: self.not_before,
		})
	}
}

/// The id of a participation of these parts: what each owner giving up a
/// coin signs.
pub fn participation_id(chain: &Chain, operator: &XOnlyPublicKey, inputs: &[LeafId], outputs: &[OutputRequest],
	fees: &[(AssetId, u64)], not_before: Option<MedianTime>) -> [u8; 32]
{
	let tag = sha256::Hash::hash(PARTICIPATION_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&chain.genesis_bytes());
	e.input(&operator.serialize());
	e.input(&[inputs.len() as u8]);
	for i in inputs {
		e.input(&i.0);
	}
	e.input(&[outputs.len() as u8]);
	for o in outputs {
		match o {
			OutputRequest::Leaf { asset, value, template, owner, owner_nonce, exit_delay, order, landing, channel } => {
				e.input(&[0]);
				e.input(&asset.into_inner().to_byte_array());
				e.input(&value.to_le_bytes());
				e.input(&[template.id(), template.version()]);
				e.input(&owner.serialize());
				e.input(owner_nonce);
				e.input(&exit_delay.units().to_le_bytes());
				if let Some(o) = order {
					let mut b = vec![];
					o.encode_to(&mut b);
					e.input(&b);
				}
				if let Some(l) = landing {
					e.input(&l.program);
					e.input(&l.allowance.to_le_bytes());
				}
				if let Some(c) = channel {
					e.input(&c.capacity.to_le_bytes());
					e.input(&c.window.units().to_le_bytes());
				}
			},
			OutputRequest::Offboard { asset, value, script } => {
				e.input(&[1]);
				e.input(&asset.into_inner().to_byte_array());
				e.input(&value.to_le_bytes());
				e.input(&(script.len() as u16).to_le_bytes());
				e.input(script.as_bytes());
			},
		}
	}
	e.input(&[fees.len() as u8]);
	for (a, v) in fees {
		e.input(&a.into_inner().to_byte_array());
		e.input(&v.to_le_bytes());
	}
	match not_before {
		Some(t) => {
			e.input(&[1]);
			e.input(&t.to_consensus_u32().to_le_bytes());
		},
		None => e.input(&[0]),
	}
	sha256::Hash::from_engine(e).to_byte_array()
}

/// Why a participation was refused, or could not be handled.
#[derive(Debug, thiserror::Error)]
pub enum ParticipationError {
	#[error("the request is malformed: {0}")]
	Malformed(String),
	#[error(transparent)]
	Coin(CoinError),
	#[error("input {0}: the attestation is not the coin's owner's signature over the participation")]
	BadAttestation(usize),
	#[error("output {0}: the key proof is not the wanted key's signature over the participation: a participation wants a leaf only \
		under a key it holds")]
	BadKeyProof(usize),
	#[error("output {0}: template {1} is not one a round builds")]
	Template(usize, String),
	#[error("input {0}: coin {1} is an htlc-1 leaf, which no refresh takes: it is claimed, refunded, or spent back by its \
		collaborative path once its payment over Lightning is decided")]
	HtlcInput(usize, LeafId),
	#[error("an output is outside the operator's published bounds: {0}")]
	OutOfBounds(String),
	/// It carries several assets, or pays a fee in one the operator does not
	/// serve.
	#[error("{0}")]
	Assets(String),
	#[error("an output's key already owns a leaf or is wanted by another participation: every leaf has a key of its own")]
	KeyReused,
	#[error("output {0}: the leaf's key is the operator's own key S: a leaf has its owner's key, never the operator's")]
	OperatorKey(usize),
	#[error("an offboard pays a script the server knows as an Arca script: a leaf script is never funded twice")]
	ScriptReused,
	#[error("the amounts do not balance: {0}")]
	Unbalanced(String),
	#[error("the fee does not cover the schedule: {0}")]
	Fee(String),
	#[error("no participation {0} is known")]
	Unknown(String),
	#[error("leaf {0} is no claim of a distribution this server knows")]
	UnknownClaim(LeafId),
	#[error("claim leaf {0} is not open yet: its distribution is not released, so no preimage opens its entry; it is taken up once \
		its payer has handed over its forfeits")]
	ClaimNotReleased(LeafId),
	#[error("claim leaf {0} has lapsed: its distribution's deadline {1} has passed, and what its holder did not take up by then goes \
		back to its payer")]
	ClaimLapsed(LeafId, u32),
	#[error("the return script is a script the server knows as an Arca script: what no holder takes up is paid to an address of the \
		payer's, never into the tree")]
	ReturnScriptReused,
	/// A coin an offline-refresh plan names, or a coin a step made whose
	/// predecessor can still come home.
	#[error("{0}")]
	Planned(String),
	#[error("the server has not followed the chain yet")]
	NotSynced,
	/// The operator's signer holds a forfeit or a spend under a coin's salt.
	#[error("{0}")]
	SignedAlready(String),
	#[error(transparent)]
	Supervision(#[from] crate::supervision::SupervisionError),
	#[error(transparent)]
	Restricted(#[from] crate::restricted::RestrictedError),
	#[error("the signer: {0}")]
	Signer(SignerError),
	/// The operator's rate for the participation's asset is stale, or
	/// missing: no new work in the asset.
	#[error(transparent)]
	Rate(crate::rates::RateError),
	/// A take's order: its terms, the fill asked of it, or what the chain
	/// holds at its outpoint.
	#[error("{0}")]
	Order(String),
	/// A take's order is spent, on the chain or in the node's mempool.
	#[error("{0}")]
	OrderSpent(String),
	/// A take's order is on the chain, not yet final.
	#[error("{0}")]
	OrderNotFinal(String),
	/// Another participation takes the same order.
	#[error("{0}")]
	OrderTaken(String),
	/// A take's order can be refunded by its maker too soon.
	#[error("{0}")]
	OrderExpiring(String),
	#[error(transparent)]
	Store(StoreError),
	#[error("{0}")]
	Internal(String),
}

impl ParticipationError {
	/// A stable name for the refusal.
	pub fn code(&self) -> &'static str {
		use ParticipationError::*;
		match self {
			Malformed(_) => "malformed",
			Coin(CoinError::UnknownLeaf(_)) => "unknown_leaf",
			Coin(CoinError::NotLive(..)) => "not_live",
			Coin(CoinError::Spent(_)) => "in_use",
			Coin(CoinError::BoardNotFinal(_)) => "board_not_final",
			Coin(CoinError::RoundNotFinal(_)) => "round_not_final",
			Coin(CoinError::OnChain { .. }) => "on_chain",
			Coin(CoinError::InvalidCoin { .. }) | Coin(CoinError::PastBoardDate { .. }) => "invalid_coin",
			Coin(CoinError::Channel(_)) => "template",
			Coin(CoinError::Lapsed { .. }) => "lapsed",
			Coin(CoinError::Store(_)) | Coin(CoinError::Internal(_)) => "internal",
			BadAttestation(_) | BadKeyProof(_) => "bad_attestation",
			Template(..) | HtlcInput(..) => "template",
			OutOfBounds(_) | Assets(_) => "out_of_bounds",
			KeyReused => "key_reused",
			OperatorKey(_) => "operator_key",
			ScriptReused => "script_reused",
			Unbalanced(_) => "unbalanced",
			Fee(_) => "fee",
			Unknown(_) => "unknown_participation",
			UnknownClaim(_) => "unknown_leaf",
			ClaimNotReleased(_) => "not_live",
			ClaimLapsed(..) => "lapsed",
			ReturnScriptReused => "script_reused",
			NotSynced => "not_synced",
			Planned(_) => "planned",
			SignedAlready(_) => "double_spend",
			Signer(SignerError::Frozen(_)) => crate::supervision::FROZEN,
			Signer(SignerError::Declined(_)) => "declined",
			Signer(_) => "signer_unavailable",
			Supervision(e) => e.code(),
			Restricted(e) => e.code(),
			Rate(_) => "rate_stale",
			Order(_) => "order",
			OrderSpent(_) => "order_spent",
			OrderNotFinal(_) => "order_not_final",
			OrderTaken(_) => "order_taken",
			OrderExpiring(_) => "order_expiring",
			Store(_) | Internal(_) => "internal",
		}
	}
}

impl From<StoreError> for ParticipationError {
	fn from(e: StoreError) -> ParticipationError {
		match e {
			StoreError::KeyReused => ParticipationError::KeyReused,
			StoreError::ScriptReused => ParticipationError::ScriptReused,
			StoreError::OrderTaken(order, by) => ParticipationError::OrderTaken(format!("order {} is taken by participation {}, \
				which is pending or in a round, and one of the two takes it alone: an order is taken by one such participation at a time \
				(takes that both share it may stand together), and a take of it waits until that one is done", order, by)),
			StoreError::OrderFull(order, why) => ParticipationError::OrderTaken(format!("order {}: {}", order, why)),
			other => ParticipationError::Store(other),
		}
	}
}

impl From<CoinError> for ParticipationError {
	fn from(e: CoinError) -> ParticipationError {
		match e {
			CoinError::Store(s) => s.into(),
			other => ParticipationError::Coin(other),
		}
	}
}

/// Where a participation's round, and each output in it, stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundRef {
	pub txid: elements::Txid,
	/// The round's connector output, whose asset every forfeit names.
	pub connector_vout: u32,
	/// For a round that fills on-chain orders and is not broadcast yet, the
	/// transaction without its witnesses.
	pub unbroadcast: Option<elements::Transaction>,
}

/// Where one output wanted stands in the participation's round.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Placed {
	/// For a leaf: its id, its batch output's index in the round and its
	/// index among the batch's leaves.
	pub leaf_id: Option<LeafId>,
	pub batch_vout: Option<u32>,
	pub leaf_index: Option<u32>,
	/// For an offboard: the index of its output in the round.
	pub offboard_vout: Option<u32>,
}

/// A participation as its owner sees it.
#[derive(Debug, Clone)]
pub struct Status {
	pub row: ParticipationRow,
	pub round: Option<RoundRef>,
	/// For each output wanted, in order.
	pub placed: Vec<Placed>,
	/// For a take in a round: the input its order is at, `k`, credited at
	/// `2k` and resting again, or holding another asset, at `2k+1`.
	pub fill_at: Option<u32>,
	/// For a take in a round: what the round fills of its order, every take
	/// of it together, and the maker's credit for that ([`RoundFill`]).
	pub round_fill: Option<RoundFill>,
}

/// What a round fills of one order, all its takes together: the sum of
/// their fills, what rests again, and the maker's credit at `2k`, the
/// order's price for the sum (rounded up once, so at most the sum of the
/// takes' own prices).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundFill {
	pub filled: u64,
	pub remainder: u64,
	pub credit: u64,
	pub takes: u32,
}

/// See the [module documentation](self).
pub struct Participations {
	store: Store,
	finality: Arc<FinalityService>,
	params: Arc<Params>,
	signer: SignerClient,
}

/// A signature of the right length for sizing a transaction.
fn dummy_sig() -> Signature {
	Signature::from_slice(&[1u8; 64]).expect("64 bytes")
}

/// The margin a forfeit of `coin` leaves for its own fee: the multiple of the
/// floor, in the coin's asset, for the forfeit transaction with the margin as
/// its fee; one atom when the node does not accept the asset for fees. At
/// most the coin's value less one atom.
pub fn forfeit_margin(coin: &ValidCoin, refund_delay: RelativeTime, floor_per_kvb: Option<u64>) -> u64 {
	let floor = match floor_per_kvb {
		Some(f) => f,
		None => return 1,
	};
	let margin = Forfeit::new(coin.leaf, (coin.asset, coin.value), coin.id, [0; 32], connector_asset(elements::Txid::all_zeros(), 0), refund_delay, 1)
		.and_then(|f| f.tx(OutPoint::default(), &Pair { operator: dummy_sig(), owner: dummy_sig() }, &FeeSource::Reserve))
		.map(|u| fees::atoms_for(floor, u.tx.vsize() as u64, fees::MULTIPLE))
		.unwrap_or(1);
	margin.clamp(1, coin.value.saturating_sub(1).max(1))
}

/// The margin the round's offboard output holds for its unlock into
/// `destination`: the multiple of the floor, in the destination's asset, for
/// the unlock with the margin as its fee; nothing when the node does not
/// accept the asset for fees (whoever unlocks attaches a coin).
pub fn offboard_margin(destination: &ExplicitOutput, operator: XOnlyPublicKey, reclaim_delay: RelativeTime, floor_per_kvb: Option<u64>) -> u64 {
	let policy = OffboardPolicy { unlock_hash: [0; 32], destination: destination.clone(), operator, reclaim_delay };
	policy.unlock_margin(floor_per_kvb, fees::MULTIPLE)
}

/// Why a participation that carries `asset` and `others` too is refused.
fn one_asset(asset: AssetId, others: &BTreeSet<AssetId>) -> String {
	format!("a participation carries one asset, as the round it runs in does, and this one carries asset {} and {}: submit one \
		participation per asset", asset, others.iter().map(|a| format!("asset {}", a)).collect::<Vec<_>>().join(" and "))
}

/// An outpoint as `txid:vout`.
pub fn outpoint_text(op: &OutPoint) -> String {
	format!("{}:{}", op.txid, op.vout)
}

/// Why the REFUND of `terms` opens too soon for a round to fill the order
/// now, at a tip of `height` and median time `mtp`: within
/// [`Params::order_margin_seconds`], a height counted at
/// [`Params::order_block_seconds`] a block. `None` when it does not.
pub fn refund_too_soon(terms: &FillOrder, p: &Params, height: u64, mtp: u32) -> Option<String> {
	let margin = p.order_margin_seconds;
	match terms.refund_lock() {
		RefundLock::Height(h) => {
			let blocks = margin.div_ceil(p.order_block_seconds.max(1)) as u64;
			(h as u64 <= height + blocks).then(|| format!("its maker can refund it from height {}, and the chain is at {}: a round fills \
				only an order its maker cannot take back for {} more blocks ({} s at {} s a block)", h, height, blocks, margin,
				p.order_block_seconds))
		},
		RefundLock::Time(t) => (t as u64 <= mtp as u64 + margin as u64).then(|| format!("its maker can refund it from median time {}, \
			and the chain is at {}: a round fills only an order its maker cannot take back for {} s more", t, mtp, margin)),
	}
}

/// [`Participations::order_on_chain`], for the round builder as well.
pub async fn order_on_chain(finality: &FinalityService, order: &OutPoint, terms: &FillOrder, locked: u64) -> Result<(), ParticipationError> {
	let op = *order;
	let at = outpoint_text(order);
	let tx = finality.call(move |n| n.transaction(&op.txid)).await.map_err(|e| ParticipationError::Internal(e.to_string()))?
		.ok_or_else(|| ParticipationError::Order(format!("the operator's node knows no transaction {}", order.txid)))?;
	let out = tx.output.get(order.vout as usize)
		.ok_or_else(|| ParticipationError::Order(format!("transaction {} has no output {}", order.txid, order.vout)))?;
	let shown = ExplicitOutput::from_txout(out)
		.ok_or_else(|| ParticipationError::Order(format!("output {} hides its asset or value: an order rests explicitly", at)))?;
	if shown.script_pubkey != terms.script_pubkey() {
		return Err(ParticipationError::Order(format!("the terms do not make the script at {}: they are not that order's terms", at)));
	}
	if shown.asset != terms.asset_a || shown.value != locked {
		return Err(ParticipationError::Order(format!("output {} holds {} of asset {}, and the take names {} of asset {}", at,
			shown.value, shown.asset, locked, terms.asset_a)));
	}
	let unspent = finality.call(move |n| n.unspent(&op, true)).await.map_err(|e| ParticipationError::Internal(e.to_string()))?;
	if unspent.is_none() {
		return Err(ParticipationError::OrderSpent(format!("order {} is spent, in a block or in the node's mempool: it was filled or \
			refunded before this take", at)));
	}
	let finality_of = finality.watch(order.txid, "order").await.map_err(|e| ParticipationError::Internal(e.to_string()))?;
	if !finality_of.is_final() {
		return Err(ParticipationError::OrderNotFinal(format!("order {} is {}: a round spends only what a rollback cannot take away, so \
			it takes the order once its block is certified and its anchor buried", at, finality_of.name())));
	}
	Ok(())
}

impl Participations {
	pub fn new(store: Store, finality: Arc<FinalityService>, params: Arc<Params>, signer: SignerClient) -> Arc<Participations> {
		Arc::new(Participations { store, finality, params, signer })
	}

	async fn now(&self) -> Result<MedianTime, ParticipationError> {
		let tip = self.store.tip_block().await?.ok_or(ParticipationError::NotSynced)?;
		MedianTime::from_consensus(tip.median_time as u32).map_err(|e| ParticipationError::Internal(e.to_string()))
	}

	async fn floor(&self, asset: AssetId) -> Result<Option<u64>, ParticipationError> {
		fees::floor_per_kvb(&self.finality, asset).await.map_err(|e| ParticipationError::Internal(e.to_string()))
	}

	/// The terms of an `order-3` leaf wanted at output `j`, of `asset` under
	/// `owner`: terms a leaf may carry ([`arca_covenant::OrderLeafTerms::check`]),
	/// all four credit keys present, each owning no leaf now (a fill makes a
	/// leaf under each), paid in an asset the operator serves (each credit is
	/// a leaf of it), and a REFUND time past the order margin, before which
	/// the operator co-signs fills.
	async fn check_order_terms(&self, j: usize, o: &arca_covenant::OrderLeafTerms, asset: AssetId, owner: &XOnlyPublicKey,
		now: MedianTime) -> Result<(), ParticipationError>
	{
		let p = &self.params;
		o.check(asset, owner, &p.operator).map_err(|e| ParticipationError::Order(format!("output {}: {}", j, e)))?;
		if o.credits.contains(&[0u8; 32]) {
			return Err(ParticipationError::Order(format!("output {}: a resting order starts with all four of its credit keys", j)));
		}
		let paid_in = o.landed.terms.asset_b;
		if p.supervised(&paid_in).is_some() {
			return Err(ParticipationError::OutOfBounds(format!("output {}: an order paid in asset {}, which is supervised: each credit \
				is a vtxo-1 leaf, out of a freeze's reach", j, paid_in)));
		}
		if !p.assets.contains(&paid_in) {
			return Err(ParticipationError::Assets(format!("output {}: an order paid in asset {}, which is not served by this operator: \
				each credit is a leaf of it", j, paid_in)));
		}
		let least = now.to_consensus_u32().saturating_add(p.order_margin_seconds);
		if o.landed.expiry <= least {
			return Err(ParticipationError::Order(format!("output {}: an order whose REFUND time {} is within the operator's order \
				margin of {} s: it would take no fill", j, o.landed.expiry, p.order_margin_seconds)));
		}
		for c in &o.credits {
			if self.store.key_owns_leaf(c).await? {
				return Err(ParticipationError::KeyReused);
			}
		}
		Ok(())
	}

	/// Accepts `req`: see the [module documentation](self). A participation
	/// submitted again gets its status, whatever key proofs it carries: the
	/// id does not cover them, and they were checked when it was taken.
	pub async fn submit(&self, req: &ParticipationRequest) -> Result<Status, ParticipationError> {
		let n = req.inputs.len();
		if n == 0 || n > MAX_INPUTS {
			return Err(ParticipationError::Malformed(format!("{} coins given up; a participation gives up 1 to {}", n, MAX_INPUTS)));
		}
		let m = req.outputs.len();
		if m == 0 || m > MAX_OUTPUTS {
			return Err(ParticipationError::Malformed(format!("{} outputs; a participation wants 1 to {}", m, MAX_OUTPUTS)));
		}
		if req.inputs.iter().map(|i| i.leaf_id).collect::<HashSet<_>>().len() != n {
			return Err(ParticipationError::Malformed("a coin is given up twice".into()));
		}
		if req.fees.len() > MAX_INPUTS || req.fees.iter().map(|f| f.0).collect::<HashSet<_>>().len() != req.fees.len() {
			return Err(ParticipationError::Malformed("the fees name an asset twice, or too many assets".into()));
		}
		let p = &self.params;
		let id = req.id(&p.chain, &p.operator);
		if self.store.participation(&id).await?.is_some() {
			return self.status(&id).await;
		}
		// A coin whose holder is frozen is refused before anything else.
		let given: Vec<LeafId> = req.inputs.iter().map(|i| i.leaf_id).collect();
		crate::supervision::gate(&self.store, &self.finality, p, &given).await?;
		crate::restricted::gate(&self.store, p, &given, "a refresh or an offboard").await?;
		if let Some(a) = req.outputs.iter().map(|o| o.asset()).find(|a| p.restricted(a).is_some()) {
			return Err(crate::restricted::RestrictedError::NotServed { asset: a, coin: None, what: "a round".into() }.into());
		}
		let now = self.now().await?;
		if let Some(t) = req.not_before {
			if t.to_consensus_u32() > now.to_consensus_u32().saturating_add(MAX_DEFER) {
				return Err(ParticipationError::OutOfBounds(format!(
					"the earliest round time is more than {} days ahead", MAX_DEFER / 86_400)));
			}
		}

		// The outputs, within the published bounds, each leaf under a key the
		// participation proves it holds.
		if req.key_proofs.len() != m {
			return Err(ParticipationError::Malformed(format!("{} key proofs for {} outputs", req.key_proofs.len(), m)));
		}
		let proof_digest = key_proof_digest(&id);
		let mut keys = HashSet::new();
		for (j, o) in req.outputs.iter().enumerate() {
			p.check_value(o.asset(), o.value()).map_err(ParticipationError::OutOfBounds)?;
			match o {
				OutputRequest::Leaf { template, owner, exit_delay, order, asset, value, landing, channel, .. } => {
					match (template, order, landing, channel) {
						(Template::Vtxo1 | Template::Vtxo2, None, None, None) | (Template::Landing1, None, Some(_), None) => {},
						(Template::Order3, Some(o), None, None) if o.template() == Template::Order3 =>
							self.check_order_terms(j, o, *asset, owner, now).await?,
						// order-2's fill takes an annex nobody signs, so a relay
						// could pin it at the floor fee rate. Leaves already
						// resting as order-2 are still filled; new ones are not
						// made.
						(Template::Order2, Some(_), None, None) => return Err(ParticipationError::Order(format!(
							"output {}: an order-2 leaf, whose fill takes an annex that nothing signs: the operator rests new orders as \
							order-3", j))),
						(Template::Channel1, None, None, Some(c)) => p.check_channel(*asset, *value, c)
							.map_err(|e| ParticipationError::OutOfBounds(format!("output {}: {}", j, e)))?,
						_ => return Err(ParticipationError::Template(j, template.to_string())),
					}
					p.check_landing(*asset, *value, landing.as_ref())
						.map_err(|e| ParticipationError::OutOfBounds(format!("output {}: {}", j, e)))?;
					if !p.exit_delay_ok(*exit_delay) {
						return Err(ParticipationError::OutOfBounds(format!(
							"an exit delay of {} units; the operator takes {} to {}", exit_delay.units(),
							p.min_exit_delay.units(), p.max_exit_delay.units(),
						)));
					}
					if *owner == p.operator {
						return Err(ParticipationError::OperatorKey(j));
					}
					if !keys.insert(*owner) {
						return Err(ParticipationError::KeyReused);
					}
					match &req.key_proofs[j] {
						Some(proof) if verify_digest(proof, &proof_digest, owner) => {},
						_ => return Err(ParticipationError::BadKeyProof(j)),
					}
				},
				OutputRequest::Offboard { script, .. } => {
					if script.is_empty() || script.len() > MAX_DESTINATION {
						return Err(ParticipationError::OutOfBounds(format!(
							"an offboard script of {} bytes; it takes 1 to {}", script.len(), MAX_DESTINATION)));
					}
					if self.store.arca_script(script.as_bytes()).await?.is_some() {
						return Err(ParticipationError::ScriptReused);
					}
				},
			}
		}

		for (a, _) in &req.fees {
			if !p.assets.contains(a) {
				return Err(ParticipationError::Assets(format!("a fee in asset {}, which is not served by this operator", a)));
			}
		}
		// One asset: a round carries one, and the participation runs whole in
		// one round. Every asset it names is served, checked above.
		let asset = req.outputs[0].asset();
		let others: BTreeSet<AssetId> = req.outputs.iter().map(|o| o.asset()).chain(req.fees.iter().map(|f| f.0))
			.filter(|a| *a != asset).collect();
		if !others.is_empty() {
			return Err(ParticipationError::Assets(one_asset(asset, &others)));
		}
		// New work in the asset: its rate, if the operator prices the asset
		// from one, must be fresh. A participation taken before is answered
		// above whatever the rate.
		p.fresh_rate(&asset).map_err(ParticipationError::Rate)?;

		// The coins given up, each checked, each attested by its owner, up to
		// its exit deadline: three days before its first expiry, or before the
		// service expiry of a board it rests on, whichever comes first.
		let mut coins = Vec::with_capacity(n);
		let mut expiries = Vec::with_capacity(n);
		let mut last_times = Vec::with_capacity(n);
		let policy = p.participation_policy(now);
		for (k, i) in req.inputs.iter().enumerate() {
			let c = coins::check(&self.store, &policy, &i.leaf_id, &id, coins::BoardDates::Within(Params::PARTICIPATION_HORIZON)).await?;
			if c.coin.leaf.htlc.is_some() {
				return Err(ParticipationError::HtlcInput(k, i.leaf_id));
			}
			if let Some(why) = crate::plans::blocks_participation(&self.store, &i.leaf_id.0, &id).await? {
				return Err(ParticipationError::Planned(why));
			}
			if c.coin.asset != asset {
				return Err(ParticipationError::Assets(one_asset(asset, &BTreeSet::from([c.coin.asset]))));
			}
			if !verify_digest(&i.attestation, &id, &c.coin.leaf.owner) {
				return Err(ParticipationError::BadAttestation(k));
			}
			let mut last = c.coin.expiry.to_consensus_u32().saturating_sub(Params::PARTICIPATION_HORIZON);
			if let Some(b) = c.board_expiry {
				last = last.min(b.saturating_sub(Params::PARTICIPATION_HORIZON));
			}
			expiries.push(c.expiry());
			last_times.push(last);
			coins.push(c.coin);
		}
		// Nothing of any coin in the signer's record: a coin under a forfeit
		// the signer holds stays given up, and one under a spend was paid on;
		// either would leave this participation's forfeit beside another, or
		// refused for good, and the participation stuck.
		for (c, i) in coins.iter().zip(&req.inputs) {
			let held = self.signer.under(&c.leaf.salt).await.map_err(ParticipationError::Signer)?;
			if let Some(e) = held.first() {
				let (what, why) = match e.kind {
					Signed::Forfeit(_) => ("the forfeit", "a coin under a forfeit the signer holds stays given up"),
					Signed::Spend => ("the spend", "the coin was paid on"),
				};
				return Err(ParticipationError::SignedAlready(format!(
					"coin {}: the operator's signer has already co-signed {} {} under salt {} (entry {}): {}, and is refreshed in no \
					round; its owner's way home is its exit", i.leaf_id, what, hex(&e.digest), hex(&c.leaf.salt), e.n, why)));
			}
		}
		// A coin is taken only up to its exit deadline, and so is a round
		// asked for later.
		if let Some(t) = req.not_before {
			for (last, i) in last_times.iter().zip(&req.inputs) {
				if t.to_consensus_u32() > *last {
					return Err(ParticipationError::OutOfBounds(format!(
						"the earliest round time {} lies past the last time coin {} is taken, {}", t.to_consensus_u32(), i.leaf_id, last)));
				}
			}
		}

		// A channel coin gives up its owner's side: the latest state's
		// balance and every credit not folded, read with the state and note
		// they come from, which must still be the latest when it is given up.
		let mut seen = vec![];
		let mut shares = Vec::with_capacity(n);
		for (c, i) in coins.iter().zip(&req.inputs) {
			match crate::channels::owner_share(&self.store, &i.leaf_id, &c.leaf).await? {
				Some((share, s)) => {
					shares.push(share);
					seen.push(s);
				},
				None => shares.push(c.value),
			}
		}
		// The amounts, per asset: in = out + fee, exactly.
		let mut held: BTreeMap<AssetId, u128> = BTreeMap::new();
		for (c, share) in coins.iter().zip(&shares) {
			*held.entry(c.asset).or_default() += *share as u128;
		}
		let mut taken: BTreeMap<AssetId, u128> = BTreeMap::new();
		for o in &req.outputs {
			*taken.entry(o.asset()).or_default() += o.owner_value() as u128;
		}
		let paid: BTreeMap<AssetId, u64> = req.fees.iter().copied().collect();
		for (a, v) in &paid {
			*taken.entry(*a).or_default() += *v as u128;
		}
		for a in held.keys().chain(taken.keys()) {
			let (h, t) = (held.get(a).copied().unwrap_or(0), taken.get(a).copied().unwrap_or(0));
			if h != t {
				return Err(ParticipationError::Unbalanced(format!(
					"the coins given up hold {} of asset {}; the outputs and the fee take {}", h, a, t)));
			}
		}

		// The margins, and the fee the asset's schedule asks.
		let schedule = p.fees(&asset).map_err(ParticipationError::Assets)?;
		let refund_delay = p.refund_delay;
		let mut margins = Vec::with_capacity(n);
		let mut due: BTreeMap<AssetId, u64> = BTreeMap::new();
		for ((c, expiry), share) in coins.iter().zip(&expiries).zip(&shares) {
			margins.push(forfeit_margin(c, refund_delay, self.floor(c.asset).await?));
			*due.entry(c.asset).or_default() += schedule.refresh(*share, *expiry, now);
		}
		let mut wanted = Vec::with_capacity(m);
		for o in &req.outputs {
			let kind = match o {
				OutputRequest::Leaf { template, owner, owner_nonce, exit_delay, order, landing, channel, .. } => WantedKind::Leaf {
					template: template.to_string(),
					owner_key: owner.serialize(),
					owner_nonce: *owner_nonce,
					exit_delay_units: exit_delay.units(),
					operator_nonce: [0; 32],
					htlc: None,
					order: *order,
					landing: *landing,
					channel: *channel,
					claim: None,
				},
				OutputRequest::Offboard { asset, value, script } => {
					let destination = ExplicitOutput::new(*asset, *value, script.clone());
					let margin = offboard_margin(&destination, p.operator, p.offboard_reclaim_delay, self.floor(*asset).await?);
					*due.entry(*asset).or_default() += schedule.offboard(*value, margin);
					WantedKind::Offboard { script: script.to_bytes(), margin, reclaim_delay_units: p.offboard_reclaim_delay.units() }
				},
			};
			wanted.push(ParticipationOutput {
				asset: o.asset().into_inner().to_byte_array(), value: o.value(), kind, leaf_id: None,
			});
		}
		for (a, d) in &due {
			let f = paid.get(a).copied().unwrap_or(0);
			if f < *d {
				return Err(ParticipationError::Fee(format!("a fee of {} in asset {}; the asset's schedule asks {} (refresh {} ppm and {} \
					a coin, offboard {} ppm and {})", f, a, d, schedule.refresh_ppm, schedule.refresh_base, schedule.offboard_ppm,
					schedule.offboard_base)));
			}
		}

		// The unlock hash, and the record.
		let mut preimage = [0u8; 32];
		rand::rngs::OsRng.fill_bytes(&mut preimage);
		let new = NewParticipation {
			id,
			unlock_hash: sha256_bytes(&preimage),
			preimage,
			not_before: req.not_before.map(|t| t.to_consensus_u32()),
			refund_delay_units: refund_delay.units(),
			inputs: req.inputs.iter().zip(&coins).zip(&margins).map(|((i, c), margin)| ParticipationInput {
				leaf_id: i.leaf_id.0,
				asset: c.asset.into_inner().to_byte_array(),
				value: c.value,
				margin: *margin,
				attestation: *i.attestation.as_ref(),
				returned: false,
			}).collect(),
			outputs: wanted,
			fees: req.fees.iter().map(|(a, v)| (a.into_inner().to_byte_array(), *v)).collect(),
			fill: None,
			distribution: None,
		};
		match self.store.insert_participation_seen(&new, &seen).await {
			Ok(()) => {},
			Err(StoreError::ParticipationExists) => return self.status(&id).await,
			Err(StoreError::LeafSpent(l)) => return Err(CoinError::Spent(l.parse().unwrap_or(req.inputs[0].leaf_id)).into()),
			Err(StoreError::LeafNotLive(l, s)) => return Err(CoinError::NotLive(l.parse().unwrap_or(req.inputs[0].leaf_id), s).into()),
			Err(StoreError::ChannelBusy(l)) => return Err(ParticipationError::OutOfBounds(format!(
				"channel {} has a state or a payment in flight, or moved since its share was read: submit again", l))),
			Err(e) => return Err(e.into()),
		}
		log::info!("participation {} accepted: {} coin(s) given up for {} output(s)", crate::signer::hex(&id), n, m);
		self.status(&id).await
	}

	/// Takes the on-chain order `req` names, for a leaf of what it fills:
	/// see [`crate::participations`]. The take is a participation of its
	/// own, carrying two assets: the coins it gives up and its fee are in the
	/// asset the order is paid in, `asset_b`, and the leaf it wants is in the
	/// asset the order sells, `asset_a`, in whose round it runs. It is
	/// accepted only when:
	///
	/// - the order's terms are ones a resting order can have, and the fill
	///   asked of them is one its FILL leaf takes ([`FillOrder::plan`]);
	/// - the node holds, at the order's outpoint and unspent (in its mempool
	///   too), an explicit output of `locked` atoms of `asset_a` paying the
	///   script the terms make; its transaction is final, so no rollback can
	///   take the order out from under a round; and the order's REFUND does not
	///   open within [`Params::order_margin_seconds`] (a height counted at
	///   [`Params::order_block_seconds`] a block);
	/// - the leaf wanted holds exactly `filled` of `asset_a`, as a refresh's
	///   leaf is bounded, under a key the take proves it holds;
	/// - both assets are served, their rates fresh;
	/// - every coin given up is in `asset_b` and passes what a refresh's
	///   coins pass, attested over the take's id;
	/// - the coins hold exactly the order's price for the fill and the fee,
	///   and the fee covers `asset_b`'s schedule for an offboard of the price
	///   (the maker's credit is an on-chain output the operator pays in
	///   `asset_b`, as it pays an offboard);
	/// - no other pending or issued participation takes the order, unless
	///   this take and every one standing share it ([`TakeRequest::share`]):
	///   then they stand together while all of them together take no more
	///   than the order holds and leave nothing resting below its min_lot,
	///   so any of them a round runs together fill a whole its FILL leaf
	///   takes.
	///
	/// Each take's own fill is at least the order's min_lot, as a fill alone
	/// must be: a round that fills an order for several takes is judged by
	/// the leaf on their sum, so the minimum lot of each buyer is the
	/// operator's rule, here and again when the round is built.
	///
	/// A take submitted again is answered with its status.
	pub async fn take(&self, req: &TakeRequest) -> Result<Status, ParticipationError> {
		let n = req.inputs.len();
		if n == 0 || n > MAX_INPUTS {
			return Err(ParticipationError::Malformed(format!("{} coins given up; a take gives up 1 to {}", n, MAX_INPUTS)));
		}
		if req.inputs.iter().map(|i| i.leaf_id).collect::<HashSet<_>>().len() != n {
			return Err(ParticipationError::Malformed("a coin is given up twice".into()));
		}
		let take = req.take().ok_or_else(|| ParticipationError::Malformed("a take wants one leaf, and no offboard".into()))?;
		let p = &self.params;
		let id = take.id(&p.chain, &p.operator);
		if self.store.participation(&id).await?.is_some() {
			return self.status(&id).await;
		}
		// A coin whose holder is frozen is refused before anything else.
		let given: Vec<LeafId> = req.inputs.iter().map(|i| i.leaf_id).collect();
		crate::supervision::gate(&self.store, &self.finality, p, &given).await?;
		crate::restricted::gate(&self.store, p, &given, "a take of an order").await?;
		let now = self.now().await?;
		if let Some(t) = req.not_before {
			if t.to_consensus_u32() > now.to_consensus_u32().saturating_add(MAX_DEFER) {
				return Err(ParticipationError::OutOfBounds(format!(
					"the earliest round time is more than {} days ahead", MAX_DEFER / 86_400)));
			}
		}

		// The order's terms, and the fill asked of them.
		let terms = &req.terms;
		let order_text = outpoint_text(&req.order);
		let fill_error = |e: FillError| ParticipationError::Order(format!("order {}: {}", order_text, e));
		let plan = terms.plan(req.locked, req.filled).map_err(fill_error)?;
		let (asset_a, asset_b) = (terms.asset_a, terms.asset_b);
		let price = plan.credit.value;
		// An issuer-operated asset is not filled in a round: the orders hold
		// the round's low inputs, where its mint limiter must be input 0, and
		// the credit would come from coins the operator keeps none of.
		for a in [asset_a, asset_b] {
			if p.assets.get(&a).is_some_and(|x| x.issuer.is_some()) {
				return Err(ParticipationError::OutOfBounds(format!("asset {} is issuer-operated here: its batches are funded by a mint in \
					their round, and a round that fills an on-chain order mints nothing", a)));
			}
			// A supervised asset is not taken through a round: the taker's
			// leaf is vtxo-1 by the take's own id, and the order's covenant
			// pays its maker by a script path a freeze cannot follow.
			if p.supervised(&a).is_some() {
				return Err(ParticipationError::OutOfBounds(format!("asset {} is supervised: a take of an on-chain order is not served in \
					it, as its leaf would be vtxo-1, out of a freeze's reach", a)));
			}
		}

		// The leaf: what the take fills, in the asset the order sells, under
		// a key the take proves it holds.
		let leaf = &take.leaf;
		if leaf.asset != asset_a || leaf.value != req.filled {
			return Err(ParticipationError::Order(format!("order {}: the leaf a take wants holds what it fills, {} of asset {}, and this \
				one asks {} of asset {}", order_text, req.filled, asset_a, leaf.value, leaf.asset)));
		}
		if leaf.template != Template::Vtxo1 {
			return Err(ParticipationError::Template(0, leaf.template.to_string()));
		}
		if !p.exit_delay_ok(leaf.exit_delay) {
			return Err(ParticipationError::OutOfBounds(format!(
				"an exit delay of {} units; the operator takes {} to {}", leaf.exit_delay.units(), p.min_exit_delay.units(),
				p.max_exit_delay.units())));
		}
		if leaf.owner == p.operator {
			return Err(ParticipationError::OperatorKey(0));
		}
		match &req.key_proof {
			Some(proof) if verify_digest(proof, &key_proof_digest(&id), &leaf.owner) => {},
			_ => return Err(ParticipationError::BadKeyProof(0)),
		}
		for a in [asset_a, asset_b] {
			if !p.assets.contains(&a) {
				return Err(ParticipationError::Assets(format!("the order {} asset {}, which is not served by this operator", if a == asset_a {
					"sells" } else { "is paid in" }, a)));
			}
		}
		if req.fee.0 != asset_b {
			return Err(ParticipationError::Assets(format!("a take pays its fee in the asset the order is paid in, {}, not in {}", asset_b,
				req.fee.0)));
		}
		p.check_value(asset_a, req.filled).map_err(ParticipationError::OutOfBounds)?;
		p.fresh_rate(&asset_a).map_err(ParticipationError::Rate)?;
		p.fresh_rate(&asset_b).map_err(ParticipationError::Rate)?;

		// The order on the chain: what its outpoint holds, unspent, final, and
		// not about to be refunded.
		self.order_on_chain(&req.order, terms, req.locked).await?;
		let tip = self.store.tip_block().await?.ok_or(ParticipationError::NotSynced)?;
		if let Some(why) = refund_too_soon(terms, &p, tip.height, tip.median_time as u32) {
			return Err(ParticipationError::OrderExpiring(format!("order {}: {}", order_text, why)));
		}

		// The coins given up, each checked as a refresh's are, all in the
		// asset the order is paid in.
		let (coins, _) = self.coins_given_up(&req.inputs, &id, now, &|c: &ValidCoin, k: usize| (c.asset != asset_b).then(|| {
			ParticipationError::Assets(format!("a take gives up coins in the asset the order is paid in, {}, and coin {} (input {}) is \
				in asset {}", asset_b, req.inputs[k].leaf_id, k, c.asset))
		})).await?;

		// The amounts: the coins hold the price and the fee, exactly, and the
		// fee covers the schedule for an offboard of the price.
		let held: u128 = coins.iter().map(|c| c.value as u128).sum();
		if held != price as u128 + req.fee.1 as u128 {
			return Err(ParticipationError::Unbalanced(format!("the coins given up hold {} of asset {}; the order's price for {} atoms is \
				{} and the fee {}, which take {}", held, asset_b, req.filled, price, req.fee.1, price as u128 + req.fee.1 as u128)));
		}
		let schedule = p.fees(&asset_b).map_err(ParticipationError::Assets)?;
		let due = schedule.offboard(price, 0);
		if req.fee.1 < due {
			return Err(ParticipationError::Fee(format!("a fee of {} in asset {}; a take pays the asset's schedule for an offboard of \
				the order's price, {}: {} (offboard {} ppm and {})", req.fee.1, asset_b, price, due, schedule.offboard_ppm,
				schedule.offboard_base)));
		}
		let mut margins = Vec::with_capacity(n);
		for c in &coins {
			margins.push(forfeit_margin(c, p.refund_delay, self.floor(c.asset).await?));
		}

		// The unlock hash, and the record.
		let mut preimage = [0u8; 32];
		rand::rngs::OsRng.fill_bytes(&mut preimage);
		let new = NewParticipation {
			id,
			unlock_hash: sha256_bytes(&preimage),
			preimage,
			not_before: req.not_before.map(|t| t.to_consensus_u32()),
			refund_delay_units: p.refund_delay.units(),
			inputs: req.inputs.iter().zip(&coins).zip(&margins).map(|((i, c), margin)| ParticipationInput {
				leaf_id: i.leaf_id.0,
				asset: c.asset.into_inner().to_byte_array(),
				value: c.value,
				margin: *margin,
				attestation: *i.attestation.as_ref(),
				returned: false,
			}).collect(),
			outputs: vec![ParticipationOutput {
				asset: asset_a.into_inner().to_byte_array(),
				value: req.filled,
				kind: WantedKind::Leaf {
					template: leaf.template.to_string(),
					owner_key: leaf.owner.serialize(),
					owner_nonce: leaf.owner_nonce,
					exit_delay_units: leaf.exit_delay.units(),
					operator_nonce: [0; 32],
					htlc: None,
					order: None,
					landing: None,
					channel: None,
					claim: None,
				},
				leaf_id: None,
			}],
			fees: vec![(asset_b.into_inner().to_byte_array(), req.fee.1)],
			fill: Some(FillRow {
				order_txid: req.order.txid.to_byte_array(),
				order_vout: req.order.vout,
				terms: terms.to_relay(&req.order).to_string(),
				script_pubkey: terms.script_pubkey().to_bytes(),
				locked: req.locked,
				filled: req.filled,
				price,
				shared: req.share,
			}),
			distribution: None,
		};
		match self.store.insert_participation(&new).await {
			Ok(()) => {},
			Err(StoreError::ParticipationExists) => return self.status(&id).await,
			Err(StoreError::LeafSpent(l)) => return Err(CoinError::Spent(l.parse().unwrap_or(req.inputs[0].leaf_id)).into()),
			Err(StoreError::LeafNotLive(l, s)) => return Err(CoinError::NotLive(l.parse().unwrap_or(req.inputs[0].leaf_id), s).into()),
			Err(e) => return Err(e.into()),
		}
		log::info!("take {} accepted: order {} filled by {} of asset {} for {} of asset {}, {} coin(s) given up", crate::signer::hex(&id),
			order_text, req.filled, asset_a, price, asset_b, n);
		self.status(&id).await
	}

	/// Checks the order a take names against the node: an explicit output of
	/// `locked` of the order's asset at `order`, paying the script its terms
	/// make, unspent in the chain and the mempool, in a transaction that is
	/// final.
	pub async fn order_on_chain(&self, order: &OutPoint, terms: &FillOrder, locked: u64) -> Result<(), ParticipationError> {
		order_on_chain(&self.finality, order, terms, locked).await
	}

	/// The coins of `inputs`, given up for the participation `id`: each
	/// passes the coin check up to its exit deadline, is no `htlc-1` leaf,
	/// is attested by its owner over `id`, and has nothing under its salt in
	/// the signer's record; `other` refuses a coin of an asset the
	/// participation does not give up. Returns the coins, and the last time a
	/// round takes each.
	async fn coins_given_up(&self, inputs: &[InputRequest], id: &[u8; 32], now: MedianTime,
		other: &(dyn Fn(&ValidCoin, usize) -> Option<ParticipationError> + Sync)) -> Result<(Vec<ValidCoin>, Vec<u32>), ParticipationError>
	{
		let mut coins = Vec::with_capacity(inputs.len());
		let mut last_times = Vec::with_capacity(inputs.len());
		let policy = self.params.participation_policy(now);
		for (k, i) in inputs.iter().enumerate() {
			let c = coins::check_plain(&self.store, &policy, &i.leaf_id, id, coins::BoardDates::Within(Params::PARTICIPATION_HORIZON)).await?;
			if c.coin.leaf.htlc.is_some() {
				return Err(ParticipationError::HtlcInput(k, i.leaf_id));
			}
			if let Some(e) = other(&c.coin, k) {
				return Err(e);
			}
			if !verify_digest(&i.attestation, id, &c.coin.leaf.owner) {
				return Err(ParticipationError::BadAttestation(k));
			}
			let mut last = c.coin.expiry.to_consensus_u32().saturating_sub(Params::PARTICIPATION_HORIZON);
			if let Some(b) = c.board_expiry {
				last = last.min(b.saturating_sub(Params::PARTICIPATION_HORIZON));
			}
			last_times.push(last);
			coins.push(c.coin);
		}
		for (c, i) in coins.iter().zip(inputs) {
			let held = self.signer.under(&c.leaf.salt).await.map_err(ParticipationError::Signer)?;
			if let Some(e) = held.first() {
				let (what, why) = match e.kind {
					Signed::Forfeit(_) => ("the forfeit", "a coin under a forfeit the signer holds stays given up"),
					Signed::Spend => ("the spend", "the coin was paid on"),
				};
				return Err(ParticipationError::SignedAlready(format!(
					"coin {}: the operator's signer has already co-signed {} {} under salt {} (entry {}): {}, and is refreshed in no \
					round; its owner's way home is its exit", i.leaf_id, what, hex(&e.digest), hex(&c.leaf.salt), e.n, why)));
			}
		}
		Ok((coins, last_times))
	}

	/// The participation `id` and where it stands.
	pub async fn status(&self, id: &[u8; 32]) -> Result<Status, ParticipationError> {
		let row = self.store.participation(id).await?.ok_or_else(|| ParticipationError::Unknown(crate::signer::hex(id)))?;
		let mut placed = vec![Placed::default(); row.outputs.len()];
		let round = match row.round_id {
			Some(round_id) => {
				let r = self.store.round(round_id).await?
					.ok_or_else(|| ParticipationError::Internal(format!("round {} is not recorded", round_id)))?;
				let at = self.store.placement(id, row.attempt).await?;
				for (j, leaf, vout, idx) in at.leaves {
					if let Some(p) = placed.get_mut(j as usize) {
						*p = Placed { leaf_id: Some(LeafId(leaf)), batch_vout: Some(vout), leaf_index: Some(idx), offboard_vout: None };
					}
				}
				for (j, vout) in at.offboards {
					if let Some(p) = placed.get_mut(j as usize) {
						p.offboard_vout = Some(vout);
					}
				}
				// A held round, before it is broadcast: the transaction a
				// participation validates its new leaves against before it
				// hands over its forfeits.
				let unbroadcast = if r.state == crate::store::RoundState::Built && !row.inputs.is_empty()
					&& self.store.round_held(round_id).await? {
					let mut tx: elements::Transaction = elements::encode::deserialize(&r.tx).map_err(|e| ParticipationError::Internal(e.to_string()))?;
					for i in &mut tx.input {
						i.witness = Default::default();
					}
					Some(tx)
				} else {
					None
				};
				Some(RoundRef { txid: elements::Txid::from_byte_array(r.txid), connector_vout: r.connector_vout, unbroadcast })
			},
			None => None,
		};
		let fill_at = match (&row.fill, row.round_id) {
			(Some(_), Some(round_id)) => self.store.fill_in_round(id, row.attempt).await?.filter(|(r, _)| *r == round_id).map(|(_, k)| k),
			_ => None,
		};
		let round_fill = match (&row.fill, row.round_id, fill_at) {
			(Some(f), Some(round_id), Some(k)) => Some(self.round_fill(round_id, k, f).await?),
			_ => None,
		};
		Ok(Status { row, round, placed, fill_at, round_fill })
	}

	/// What the round `round_id` fills of the order at its input `k`, whose
	/// take `f` is one of the takes of it the round runs.
	async fn round_fill(&self, round_id: i64, k: u32, f: &FillRow) -> Result<RoundFill, ParticipationError> {
		let mut filled: u64 = 0;
		let mut takes = 0;
		for x in self.store.round_fills(round_id).await?.into_iter().filter(|x| x.k == k) {
			let p = self.store.participation(&x.participation_id).await?
				.ok_or_else(|| ParticipationError::Internal(format!("take {} of round {} is not recorded", hex(&x.participation_id), round_id)))?;
			let g = p.fill.ok_or_else(|| ParticipationError::Internal(format!("participation {} is not a take", hex(&p.id))))?;
			filled = filled.checked_add(g.filled).ok_or_else(|| ParticipationError::Internal("a round's fill overflows".into()))?;
			takes += 1;
		}
		let terms = f.order()?;
		let credit = terms.price(filled).ok_or_else(|| ParticipationError::Internal(format!("order {}: no price for {}", outpoint_text(&f.outpoint()),
			filled)))?;
		Ok(RoundFill { filled, remainder: f.locked.saturating_sub(filled), credit, takes })
	}
}

