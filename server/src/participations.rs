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
//! - every coin given up passes the check of [`crate::coins`]: known, live,
//!   held by nothing else, its record valid, its boards credited and unspent,
//!   nothing of its lineage on-chain, and its first expiry still past its exit
//!   deadline, three days ahead ([`Params::participation_policy`]); its
//!   attestation verifies; and the earliest round time asked for, if any,
//!   lies before every coin's exit deadline;
//! - every leaf wanted is a template the round builds (`vtxo-1`), within the
//!   published bounds (an asset served, a value within its bounds, an exit
//!   delay within the bounds), under a key that owns no leaf, is wanted by no
//!   other participation and is not the operator's `S`; every offboard pays a served asset within its
//!   bounds to a script that is not an Arca script the server knows;
//! - per asset, the coins given up hold exactly what the outputs take plus
//!   the fee, and the fee covers the published schedule
//!   ([`crate::params::FeeSchedule`]).
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
//!          then for a leaf: template id, template version, owner key, owner nonce, exit delay units (u16)
//!          and for an offboard: script length (u16), script
//!      ‖ f, each fee: asset, amount (u64)
//!      ‖ 0, or 1 and the earliest round time (u32)
//! ```
//!
//! counts as one byte, integers little-endian, asset ids in internal byte
//! order. The tag keeps the attestation apart from everything else a leaf key
//! signs; the genesis hash and `S` keep it to one chain and one operator.

use std::collections::{BTreeMap, HashSet};
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
	connector_asset, Chain, ExplicitOutput, Forfeit, LeafId, MedianTime, OffboardPolicy, Pair, RelativeTime, Template, ValidCoin,
};

use crate::chain::FinalityService;
use crate::coins::{self, CoinError};
use crate::fees;
use crate::params::Params;
use crate::store::{
	NewParticipation, ParticipationInput, ParticipationOutput, ParticipationRow, Store, StoreError, WantedKind,
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
	Leaf { asset: AssetId, value: u64, template: Template, owner: XOnlyPublicKey, owner_nonce: [u8; 32], exit_delay: RelativeTime },
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
			OutputRequest::Leaf { asset, value, template, owner, owner_nonce, exit_delay } => {
				e.input(&[0]);
				e.input(&asset.into_inner().to_byte_array());
				e.input(&value.to_le_bytes());
				e.input(&[template.id(), template.version()]);
				e.input(&owner.serialize());
				e.input(owner_nonce);
				e.input(&exit_delay.units().to_le_bytes());
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
	#[error("an output is outside the operator's published bounds: {0}")]
	OutOfBounds(String),
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
	#[error("the server has not followed the chain yet")]
	NotSynced,
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
			Coin(CoinError::Store(_)) | Coin(CoinError::Internal(_)) => "internal",
			BadAttestation(_) | BadKeyProof(_) => "bad_attestation",
			Template(..) => "template",
			OutOfBounds(_) => "out_of_bounds",
			KeyReused => "key_reused",
			OperatorKey(_) => "operator_key",
			ScriptReused => "script_reused",
			Unbalanced(_) => "unbalanced",
			Fee(_) => "fee",
			Unknown(_) => "unknown_participation",
			NotSynced => "not_synced",
			Store(_) | Internal(_) => "internal",
		}
	}
}

impl From<StoreError> for ParticipationError {
	fn from(e: StoreError) -> ParticipationError {
		match e {
			StoreError::KeyReused => ParticipationError::KeyReused,
			StoreError::ScriptReused => ParticipationError::ScriptReused,
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
}

/// See the [module documentation](self).
pub struct Participations {
	store: Store,
	finality: Arc<FinalityService>,
	params: Arc<Params>,
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
	let floor = match floor_per_kvb {
		Some(f) => f,
		None => return 0,
	};
	let policy = OffboardPolicy { unlock_hash: [0; 32], destination: destination.clone(), operator, reclaim_delay };
	policy.unlock_tx(OutPoint::default(), destination.value.saturating_add(1), &[0; 32], &FeeSource::Reserve)
		.map(|u| fees::atoms_for(floor, u.tx.vsize() as u64, fees::MULTIPLE))
		.unwrap_or(0)
}

impl Participations {
	pub fn new(store: Store, finality: Arc<FinalityService>, params: Arc<Params>) -> Arc<Participations> {
		Arc::new(Participations { store, finality, params })
	}

	async fn now(&self) -> Result<MedianTime, ParticipationError> {
		let tip = self.store.tip_block().await?.ok_or(ParticipationError::NotSynced)?;
		MedianTime::from_consensus(tip.median_time as u32).map_err(|e| ParticipationError::Internal(e.to_string()))
	}

	async fn floor(&self, asset: AssetId) -> Result<Option<u64>, ParticipationError> {
		fees::floor_per_kvb(&self.finality, asset).await.map_err(|e| ParticipationError::Internal(e.to_string()))
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
				OutputRequest::Leaf { template, owner, exit_delay, .. } => {
					if *template != Template::Vtxo1 {
						return Err(ParticipationError::Template(j, template.to_string()));
					}
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

		// The coins given up, each checked, each attested by its owner. A coin
		// resting on a board is taken past its exit deadline, into a refresh,
		// up to a day before the board's service expiry.
		let mut coins = Vec::with_capacity(n);
		let mut expiries = Vec::with_capacity(n);
		let mut last_times = Vec::with_capacity(n);
		let policy = p.participation_policy(now);
		for (k, i) in req.inputs.iter().enumerate() {
			let c = coins::check(&self.store, &policy, &i.leaf_id, &id, coins::BoardDates::Within(Params::ROUND_HORIZON)).await?;
			if !verify_digest(&i.attestation, &id, &c.coin.leaf.owner) {
				return Err(ParticipationError::BadAttestation(k));
			}
			let mut last = c.coin.expiry.to_consensus_u32().saturating_sub(Params::PARTICIPATION_HORIZON);
			if let Some(b) = c.board_expiry {
				last = last.min(b.saturating_sub(Params::ROUND_HORIZON));
			}
			expiries.push(c.expiry());
			last_times.push(last);
			coins.push(c.coin);
		}
		// A coin is taken only up to its exit deadline (a coin resting on a
		// board, up to a day before the board's expiry), and so is a round
		// asked for later.
		if let Some(t) = req.not_before {
			for (last, i) in last_times.iter().zip(&req.inputs) {
				if t.to_consensus_u32() > *last {
					return Err(ParticipationError::OutOfBounds(format!(
						"the earliest round time {} lies past the last time coin {} is taken, {}", t.to_consensus_u32(), i.leaf_id, last)));
				}
			}
		}

		// The amounts, per asset: in = out + fee, exactly.
		let mut held: BTreeMap<AssetId, u128> = BTreeMap::new();
		for c in &coins {
			*held.entry(c.asset).or_default() += c.value as u128;
		}
		let mut taken: BTreeMap<AssetId, u128> = BTreeMap::new();
		for o in &req.outputs {
			*taken.entry(o.asset()).or_default() += o.value() as u128;
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

		// The margins, and the fee the schedule asks.
		let refund_delay = p.refund_delay;
		let mut margins = Vec::with_capacity(n);
		let mut due: BTreeMap<AssetId, u64> = BTreeMap::new();
		for (c, expiry) in coins.iter().zip(&expiries) {
			margins.push(forfeit_margin(c, refund_delay, self.floor(c.asset).await?));
			*due.entry(c.asset).or_default() += p.fees.refresh(c.value, *expiry, now);
		}
		let mut wanted = Vec::with_capacity(m);
		for o in &req.outputs {
			let kind = match o {
				OutputRequest::Leaf { template, owner, owner_nonce, exit_delay, .. } => WantedKind::Leaf {
					template: template.to_string(),
					owner_key: owner.serialize(),
					owner_nonce: *owner_nonce,
					exit_delay_units: exit_delay.units(),
					operator_nonce: [0; 32],
				},
				OutputRequest::Offboard { asset, value, script } => {
					let destination = ExplicitOutput::new(*asset, *value, script.clone());
					let margin = offboard_margin(&destination, p.operator, p.offboard_reclaim_delay, self.floor(*asset).await?);
					*due.entry(*asset).or_default() += p.fees.offboard(*value, margin);
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
				return Err(ParticipationError::Fee(format!("a fee of {} in asset {}; the schedule asks {}", f, a, d)));
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
			}).collect(),
			outputs: wanted,
			fees: req.fees.iter().map(|(a, v)| (a.into_inner().to_byte_array(), *v)).collect(),
		};
		match self.store.insert_participation(&new).await {
			Ok(()) => {},
			Err(StoreError::ParticipationExists) => return self.status(&id).await,
			Err(StoreError::LeafSpent(l)) => return Err(CoinError::Spent(l.parse().unwrap_or(req.inputs[0].leaf_id)).into()),
			Err(StoreError::LeafNotLive(l, s)) => return Err(CoinError::NotLive(l.parse().unwrap_or(req.inputs[0].leaf_id), s).into()),
			Err(e) => return Err(e.into()),
		}
		log::info!("participation {} accepted: {} coin(s) given up for {} output(s)", crate::signer::hex(&id), n, m);
		self.status(&id).await
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
				Some(RoundRef { txid: elements::Txid::from_byte_array(r.txid), connector_vout: r.connector_vout })
			},
			None => None,
		};
		Ok(Status { row, round, placed })
	}
}

