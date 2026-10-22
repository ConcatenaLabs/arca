//! Offline refresh: a holder who will stay away past a coin's expiry
//! pre-signs a plan, and the operator refreshes the coin in later rounds
//! without it ([`arca_covenant::plan`]).
//!
//! Step `i` gives up the holder's coin `L(i-1)` for a new leaf `L(i)`: a
//! participation of the server's own making, wanting `L(i)` exactly as the
//! plan names it (owner key, owner nonce, the operator nonce the quote drew,
//! exit delay, value) under the plan's unlock hash, whose preimage the holder
//! handed over and can derive again. It runs in the asset's ordinary round,
//! created no earlier than the start of `L(i-1)`'s free window (five days
//! before its first expiry), and may run after `L(i-1)`'s exit deadline
//! while `L(i-1)`'s batch is not released. Once its round is final the
//! server releases it without forfeits, credits `L(i)` (whose record waits for
//! the holder's unroll authorisations, [`Plans::hand_over`]), and the next
//! step is due. In place of the forfeit the holder could not sign before the
//! round existed, the operator holds the step's refund: the holder's halves
//! over `L(i-1)`'s and `L(i)`'s collaborative paths, both committing to `v(i)`
//! at the holder's address and the rest less a margin at the operator's
//! script. Every use of either half pays the holder `v(i)`.
//!
//! The server takes a plan ([`Plans::submit`]) only when:
//!
//! - its coin passes what a refresh's coins pass, is a leaf of a round, is
//!   named by no other plan that is open or stopped, and its owner attested
//!   the plan's id;
//! - every step's operator nonce is one the quote drew ([`Plans::quote`]),
//!   its key owns no leaf and is wanted by nothing else, its salt is new to
//!   the server (now promised to the step), its key proof, both refund halves
//!   and its binding to the plan's mailbox key verify, and its preimage
//!   opens its unlock hash;
//! - the plan is well formed ([`arca_covenant::Plan::check`]), every value
//!   and exit delay is within the operator's bounds, every fee covers the
//!   asset's schedule at the step's earliest time, every operator script is
//!   the quote's, and no holder's address is a script the server knows as
//!   an Arca script.
//!
//! Its rules once taken:
//!
//! - A step whose coin is spent elsewhere, on the chain, or lost, or whose
//!   round is lost, is void and the plan stopped: the coin it would have
//!   given up is its holder's again ([`apply`], [`void_rerun`]).
//! - The watcher releases no batch that holds the current coin of a plan
//!   that is open or stopped ([`holds_batch`]): a holder away on a plan
//!   finds its coin unswept, refreshed or not.
//! - A coin a plan names carries its holder's refund halves while its script
//!   is unspent, so the operator co-signs no transfer of it
//!   ([`blocks_transfer`]); a holder gives it up in a round first, by a
//!   participation of its own, which the operator takes for the current coin
//!   of an open or stopped plan unless a step of it is in a round
//!   ([`blocks_participation`]). While that participation holds the coin no
//!   step runs from it ([`apply`]); once it is released the plan ends
//!   ([`release_given_up`]); should it never complete, the plan stands. A
//!   coin a step made is taken into no participation until the coin it
//!   replaced is swept, the sweep final: the refund that answers that coin
//!   needs the signer's one spend under the new coin's salt.
//! - A coin a step gave up that comes on the chain is answered by the
//!   step's refund ([`crate::watcher`]).

use std::sync::Arc;

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Script, Txid};

use arca_covenant::plan::{key_proof_digest, Plan, PlanStep, MAX_STEPS};
use arca_covenant::sign::verify_digest;
use arca_covenant::spend::{FeeSource, Pair};
use arca_covenant::{Chain, CoinRecord, LeafId, LeafPolicy, MedianTime, RelativeTime, Template};

use crate::chain::FinalityService;
use crate::coins::{self, CoinError};
use crate::fees;
use crate::params::{FeeSchedule, Params};
use crate::signer::{hex, Signed, SignerClient};
use crate::store::{
	LeafRow, LeafState, NewParticipation, NewPlan, NewPlanStep, ParticipationInput, ParticipationOutput, ParticipationRow, ParticipationState,
	PlanRow, PlanState,
	StepState, Store, StoreError, WantedKind,
};
use crate::wallet::Wallet;

/// The tag of the digest a coin's owner signs to ask for a plan's quote.
pub const QUOTE_TAG: &[u8] = b"Arca/plan-quote";
/// The tag of a step's participation id.
pub const STEP_TAG: &[u8] = b"Arca/plan-step";
/// The tag of the digest the plan's mailbox key signs to cancel it.
pub const CANCEL_TAG: &[u8] = b"Arca/plan-cancel";

fn tagged(tag: &[u8]) -> sha256::HashEngine {
	let t = sha256::Hash::hash(tag);
	let mut e = sha256::Hash::engine();
	e.input(t.as_byte_array());
	e.input(t.as_byte_array());
	e
}

/// What a coin's owner signs to ask for a quote: `SHA256(T ‖ T ‖ genesis ‖ S
/// ‖ coin ‖ n ‖ owner nonces ‖ exit delay units (u16))`,
/// `T = SHA256("Arca/plan-quote")`.
pub fn quote_digest(chain: &Chain, operator: &XOnlyPublicKey, coin: &LeafId, owner_nonces: &[[u8; 32]], exit_delay: RelativeTime)
	-> [u8; 32]
{
	let mut e = tagged(QUOTE_TAG);
	e.input(&chain.genesis_bytes());
	e.input(&operator.serialize());
	e.input(&coin.0);
	e.input(&[owner_nonces.len() as u8]);
	for n in owner_nonces {
		e.input(n);
	}
	e.input(&exit_delay.units().to_le_bytes());
	sha256::Hash::from_engine(e).to_byte_array()
}

/// The id of step `idx`'s participation: `SHA256(T ‖ T ‖ plan id ‖ idx (u16))`,
/// `T = SHA256("Arca/plan-step")`.
pub fn step_participation_id(plan: &[u8; 32], idx: u16) -> [u8; 32] {
	let mut e = tagged(STEP_TAG);
	e.input(plan);
	e.input(&idx.to_le_bytes());
	sha256::Hash::from_engine(e).to_byte_array()
}

/// What the plan's mailbox key signs to cancel it: `SHA256(T ‖ T ‖ genesis ‖
/// S ‖ plan id)`, `T = SHA256("Arca/plan-cancel")`.
pub fn cancel_digest(chain: &Chain, operator: &XOnlyPublicKey, plan: &[u8; 32]) -> [u8; 32] {
	let mut e = tagged(CANCEL_TAG);
	e.input(&chain.genesis_bytes());
	e.input(&operator.serialize());
	e.input(plan);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// Why a plan request was refused, or could not be handled.
#[derive(Debug, thiserror::Error)]
pub enum PlanError {
	#[error("the request is malformed: {0}")]
	Malformed(String),
	#[error(transparent)]
	Supervision(#[from] crate::supervision::SupervisionError),
	#[error(transparent)]
	Restricted(#[from] crate::restricted::RestrictedError),
	#[error(transparent)]
	Coin(CoinError),
	#[error("{0}")]
	BadSignature(String),
	#[error("{0}")]
	OutOfBounds(String),
	#[error("the plan: {0}")]
	Plan(arca_covenant::PlanError),
	#[error("{0}")]
	Planned(String),
	#[error("no plan {0} is known")]
	Unknown(String),
	#[error("{0}")]
	Conflict(String),
	#[error("the server has not followed the chain yet")]
	NotSynced,
	#[error(transparent)]
	Rate(crate::rates::RateError),
	#[error("the signer: {0}")]
	Signer(String),
	#[error(transparent)]
	Store(StoreError),
	#[error("{0}")]
	Internal(String),
}

impl PlanError {
	/// A stable name for the refusal.
	pub fn code(&self) -> &'static str {
		use PlanError::*;
		match self {
			Malformed(_) => "malformed",
			Coin(CoinError::UnknownLeaf(_)) => "unknown_leaf",
			Coin(CoinError::NotLive(..)) => "not_live",
			Coin(CoinError::Spent(_)) => "in_use",
			Coin(CoinError::OnChain { .. }) => "on_chain",
			Coin(CoinError::RoundNotFinal(_)) => "round_not_final",
			Coin(_) => "invalid_coin",
			BadSignature(_) => "bad_attestation",
			OutOfBounds(_) | Plan(_) => "out_of_bounds",
			Planned(_) => "planned",
			Unknown(_) => "unknown_plan",
			Conflict(_) => "conflict",
			NotSynced => "not_synced",
			Rate(_) => "rate_stale",
			Signer(_) => "signer_unavailable",
			Supervision(e) => e.code(),
			Restricted(e) => e.code(),
			Store(StoreError::KeyReused) => "key_reused",
			Store(StoreError::SaltReused(_)) => "salt",
			Store(StoreError::NonceUnknown) => "nonce_unknown",
			Store(StoreError::NonceUsed) => "nonce_used",
			Store(StoreError::CoinPlanned(_)) => "planned",
			Store(StoreError::UnlockHashReused) => "hash_reused",
			Store(StoreError::LeafSpent(_)) => "in_use",
			Store(StoreError::LeafNotLive(..)) => "not_live",
			Store(_) | Internal(_) => "internal",
		}
	}
}

impl From<StoreError> for PlanError {
	fn from(e: StoreError) -> PlanError {
		PlanError::Store(e)
	}
}

impl From<CoinError> for PlanError {
	fn from(e: CoinError) -> PlanError {
		match e {
			CoinError::Store(s) => PlanError::Store(s),
			other => PlanError::Coin(other),
		}
	}
}

/// A request for a plan's quote: the coin it starts from, an owner nonce of
/// the wallet's for each step, the exit delay its leaves want, and the coin's
/// owner's signature over [`quote_digest`].
#[derive(Debug, Clone)]
pub struct QuoteRequest {
	pub coin: LeafId,
	pub owner_nonces: Vec<[u8; 32]>,
	pub exit_delay: RelativeTime,
	pub attestation: Signature,
}

/// What the operator quotes for one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteStep {
	pub operator_nonce: [u8; 32],
	pub fee: u64,
	pub margin: u64,
}

/// A plan's quote.
#[derive(Debug, Clone)]
pub struct Quote {
	/// The quote's id: what the operator nonces were drawn under.
	pub quote: [u8; 32],
	pub coin: LeafId,
	pub asset: AssetId,
	pub value: u64,
	/// The coin's first expiry.
	pub expiry: MedianTime,
	/// The script the operator's share of every refund pays to.
	pub operator_script: Script,
	pub steps: Vec<QuoteStep>,
	/// The earliest median time of step 1's round: the start of the coin's
	/// free window.
	pub earliest: u32,
}

/// A plan as the holder submits it: the quote it answers, the steps it
/// signed, and everything it hands over.
#[derive(Debug, Clone)]
pub struct SubmitRequest {
	pub quote: [u8; 32],
	pub coin: LeafId,
	pub steps: Vec<PlanStep>,
	pub mailbox: XOnlyPublicKey,
	/// `L(0)`'s owner's signature over the plan's id.
	pub attestation: Signature,
	/// For each step: `A(i)`'s signature over [`key_proof_digest`] of the id,
	/// the holder's two refund halves, the preimage of its unlock hash, and
	/// `A(i)`'s binding to the mailbox key.
	pub key_proofs: Vec<Signature>,
	pub halves: Vec<(Signature, Signature)>,
	pub preimages: Vec<[u8; 32]>,
	pub mailbox_proofs: Vec<Signature>,
}

/// Where one step stands, as the holder sees it.
#[derive(Debug, Clone)]
pub struct StepStatus {
	pub idx: u16,
	pub state: StepState,
	pub reason: Option<String>,
	pub participation: Option<[u8; 32]>,
	/// The coin it gives up, once known.
	pub gives_up: Option<[u8; 32]>,
	/// Its round and the round's state, once it is in one.
	pub round: Option<(Txid, String)>,
	/// Its leaf: id, batch output and index in the batch, and its record in
	/// the tree, once its round is final.
	pub leaf_id: Option<[u8; 32]>,
	pub batch_vout: Option<u32>,
	pub leaf_index: Option<u32>,
	pub record: Option<Vec<u8>>,
}

/// A plan as the holder sees it.
#[derive(Debug, Clone)]
pub struct PlanStatus {
	pub row: PlanRow,
	pub steps: Vec<StepStatus>,
}

/// See the [module documentation](self).
pub struct Plans {
	store: Store,
	finality: Arc<FinalityService>,
	params: Arc<Params>,
	signer: SignerClient,
	wallet: Arc<Wallet>,
}

/// A signature of the right length for sizing a transaction.
fn dummy_sig() -> Signature {
	Signature::from_slice(&[1u8; 64]).expect("64 bytes")
}

/// The margin a refund of a coin of `value` in `asset` leaves for its own
/// fee: the multiple of the floor for the refund with the margin as its fee
/// (two collaborative inputs, two outputs); one atom when the node does not
/// accept the asset for fees. At most the coin's value less one atom.
pub fn refund_margin(params: &Params, leaf: &LeafPolicy, asset: AssetId, value: u64, floor_per_kvb: Option<u64>) -> u64 {
	let Some(floor) = floor_per_kvb else { return 1 };
	let script = Script::from(vec![0x00; 22]);
	let r = arca_covenant::Refund {
		old: *leaf, old_value: value, new: *leaf, new_value: value, asset,
		holder: arca_covenant::ExplicitOutput::new(asset, value, script.clone()),
		operator: arca_covenant::ExplicitOutput::new(asset, value.saturating_sub(1), script),
	};
	let pair = Pair { operator: dummy_sig(), owner: dummy_sig() };
	let _ = params;
	let margin = r.tx(elements::OutPoint::default(), elements::OutPoint::default(), &pair, &pair, &FeeSource::Reserve)
		.map(|u| fees::atoms_for(floor, u.tx.vsize() as u64 + 10, fees::MULTIPLE))
		.unwrap_or(1);
	margin.clamp(1, value.saturating_sub(1).max(1))
}

impl Plans {
	pub fn new(store: Store, finality: Arc<FinalityService>, params: Arc<Params>, signer: SignerClient, wallet: Arc<Wallet>) -> Arc<Plans> {
		Arc::new(Plans { store, finality, params, signer, wallet })
	}

	async fn now(&self) -> Result<MedianTime, PlanError> {
		let tip = self.store.tip_block().await?.ok_or(PlanError::NotSynced)?;
		MedianTime::from_consensus(tip.median_time as u32).map_err(|e| PlanError::Internal(e.to_string()))
	}

	/// The coin a plan may start from: it passes what a refresh's coins pass
	/// now, is a `vtxo-1` leaf of a round (of a tree or an accumulator
	/// batch), and the signer holds nothing under its salt; with its first
	/// expiry.
	async fn first_coin(&self, coin: &LeafId, holder: &[u8; 32], now: MedianTime) -> Result<coins::Checked, PlanError> {
		let policy = self.params.participation_policy(now);
		let c = coins::check_plain(&self.store, &policy, coin, holder, coins::BoardDates::Within(Params::PARTICIPATION_HORIZON)).await?;
		if !matches!(c.record, CoinRecord::Leaf { .. } | CoinRecord::Accumulator { .. }) || c.coin.leaf.htlc.is_some() {
			return Err(PlanError::OutOfBounds(format!("coin {} is not a vtxo-1 leaf of a round: a plan starts from a coin of a round, \
				so refresh a board or a received coin in a round first", coin)));
		}
		if let Some((plan, _)) = self.open_plan_naming(&coin.0).await? {
			return Err(PlanError::Planned(format!("coin {} is named by plan {}, which is open or stopped: cancel it first", coin, hex(&plan))));
		}
		let held = self.signer.under(&c.coin.leaf.salt).await.map_err(|e| PlanError::Signer(e.to_string()))?;
		if let Some(e) = held.first() {
			return Err(PlanError::Conflict(format!("coin {}: the operator's signer has already co-signed {} under its salt (entry {}): \
				it is refreshed in no round, its owner's way home is its exit", coin, match e.kind { Signed::Forfeit(_) => "a forfeit",
				Signed::Spend => "a spend" }, e.n)));
		}
		Ok(c)
	}

	/// The open or stopped plan naming the coin `leaf`, and how.
	async fn open_plan_naming(&self, leaf: &[u8; 32]) -> Result<Option<([u8; 32], &'static str)>, PlanError> {
		for (id, how) in self.store.plans_naming(leaf).await? {
			if let Some(p) = self.store.plan(&id).await? {
				if matches!(p.state, PlanState::Open | PlanState::Stopped) {
					return Ok(Some((id, how)));
				}
			}
		}
		Ok(None)
	}

	/// Quotes a plan of one step per owner nonce, 1 to [`MAX_STEPS`], from
	/// the coin `req.coin`: for each step an operator nonce drawn now, the
	/// step's fee by the asset's schedule at its earliest time, and the
	/// refund's margin; and the script the operator's share of every refund
	/// pays to.
	pub async fn quote(&self, req: &QuoteRequest) -> Result<Quote, PlanError> {
		self.supervised_coin(&req.coin).await?;
		let n = req.owner_nonces.len();
		if n == 0 || n > MAX_STEPS {
			return Err(PlanError::Malformed(format!("{} steps; a plan holds 1 to {}", n, MAX_STEPS)));
		}
		for (i, a) in req.owner_nonces.iter().enumerate() {
			if req.owner_nonces[..i].contains(a) {
				return Err(PlanError::Malformed("an owner nonce is named twice".into()));
			}
		}
		if !self.params.exit_delay_ok(req.exit_delay) {
			return Err(PlanError::OutOfBounds(format!("an exit delay of {} units; the operator takes {} to {}", req.exit_delay.units(),
				self.params.min_exit_delay.units(), self.params.max_exit_delay.units())));
		}
		let now = self.now().await?;
		let digest = quote_digest(&self.params.chain, &self.params.operator, &req.coin, &req.owner_nonces, req.exit_delay);
		let c = self.first_coin(&req.coin, &digest, now).await?;
		if !verify_digest(&req.attestation, &digest, &c.coin.leaf.owner) {
			return Err(PlanError::BadSignature("the attestation is not the coin's owner's signature over the quote request".into()));
		}
		let asset = c.coin.asset;
		if !self.params.assets.contains(&asset) {
			return Err(PlanError::OutOfBounds(format!("asset {} is not served by this operator", asset)));
		}
		self.params.fresh_rate(&asset).map_err(PlanError::Rate)?;
		let schedule = self.params.fees(&asset).map_err(PlanError::OutOfBounds)?;
		let expiry = c.coin.expiry;
		let earliest = expiry.to_consensus_u32().saturating_sub(FeeSchedule::FREE_FROM);
		let floor = fees::floor_per_kvb(&self.finality, asset).await.map_err(|e| PlanError::Internal(e.to_string()))?;
		let margin = refund_margin(&self.params, &c.coin.leaf, asset, c.coin.value, floor);
		let quote_id = digest;
		let nonces = self.store.draw_quote_nonces(&quote_id, n).await?;
		// The operator's share of a step's refund: a burn when the asset is
		// issuer-operated, whose operator keeps no unit of it.
		let fresh = if self.params.assets.get(&asset).is_some_and(|a| a.issuer.is_some()) {
			arca_covenant::issuer::burn_script()
		} else {
			self.wallet.receive_script().await.map_err(|e| PlanError::Internal(e.to_string()))?
		};
		let operator_script = Script::from(self.store.quote_script_or(&quote_id, fresh.as_bytes()).await?);
		let steps = nonces.into_iter().map(|operator_nonce| {
			// Each step runs in the free window of the coin it gives up,
			// where the schedule asks nothing.
			let fee = schedule.refresh(c.coin.value, expiry, MedianTime::from_consensus(earliest.max(500_000_000)).unwrap_or(expiry));
			QuoteStep { operator_nonce, fee, margin }
		}).collect();
		Ok(Quote { quote: quote_id, coin: req.coin, asset, value: c.coin.value, expiry, operator_script, steps, earliest })
	}

	/// The supervised profile, before anything else about a plan: a coin
	/// whose holder is frozen is refused for the freeze
	/// ([`crate::supervision::gate`]), and a plan is not served in a
	/// supervised asset at all, as a step's refund pays the holder a fresh
	/// on-chain script, not its landing.
	async fn supervised_coin(&self, coin: &LeafId) -> Result<(), PlanError> {
		crate::supervision::gate(&self.store, &self.finality, &self.params, std::slice::from_ref(coin)).await?;
		crate::restricted::gate(&self.store, &self.params, std::slice::from_ref(coin), "a plan of offline refresh").await?;
		if let Some(row) = self.store.leaf(&coin.0).await? {
			let asset = AssetId::from_byte_array(row.asset);
			if self.params.supervised(&asset).is_some() {
				return Err(PlanError::OutOfBounds(format!("asset {} is supervised: offline refresh is not served in it, as a step's \
					refund pays the holder a script a freeze does not follow", asset)));
			}
		}
		Ok(())
	}

	/// Takes a plan: see the [module documentation](self). A plan taken
	/// before is answered with its status.
	pub async fn submit(&self, req: &SubmitRequest) -> Result<PlanStatus, PlanError> {
		self.supervised_coin(&req.coin).await?;
		let n = req.steps.len();
		if n == 0 || n > MAX_STEPS {
			return Err(PlanError::Malformed(format!("{} steps; a plan holds 1 to {}", n, MAX_STEPS)));
		}
		if req.key_proofs.len() != n || req.halves.len() != n || req.preimages.len() != n || req.mailbox_proofs.len() != n {
			return Err(PlanError::Malformed(format!("{} steps, and {} key proofs, {} pairs of halves, {} preimages and {} mailbox proofs: \
				one of each per step", n, req.key_proofs.len(), req.halves.len(), req.preimages.len(), req.mailbox_proofs.len())));
		}
		let now = self.now().await?;
		let p = &self.params;
		// The coin, resolved as a refresh resolves it; the plan built on it.
		let row = self.store.leaf(&req.coin.0).await?.ok_or(PlanError::Coin(CoinError::UnknownLeaf(req.coin)))?;
		let first_record = CoinRecord::from_bytes(&row.record).map_err(|e| PlanError::Coin(CoinError::InvalidCoin { leaf: req.coin, error: e }))?;
		let first = match &first_record {
			CoinRecord::Leaf { record, .. } => record.leaf(),
			CoinRecord::Accumulator { record, .. } => record.leaf(),
			_ => return Err(PlanError::OutOfBounds(format!("coin {} is not a vtxo-1 leaf of a round", req.coin))),
		};
		let plan = Plan {
			chain: p.chain, operator: p.operator, coin: req.coin, first, asset: AssetId::from_byte_array(row.asset), value: row.value,
			steps: req.steps.clone(),
		};
		let id = plan.id();
		if let Some(existing) = self.store.plan(&id).await? {
			return self.status_of(existing).await;
		}
		plan.check().map_err(PlanError::Plan)?;
		let c = self.first_coin(&req.coin, &id, now).await?;
		if c.coin.leaf != first {
			return Err(PlanError::Internal("the coin's record gives another leaf".into()));
		}
		if !verify_digest(&req.attestation, &id, &first.owner) {
			return Err(PlanError::BadSignature("the attestation is not the coin's owner's signature over the plan's id".into()));
		}
		let asset = plan.asset;
		if !p.assets.contains(&asset) {
			return Err(PlanError::OutOfBounds(format!("asset {} is not served by this operator", asset)));
		}
		p.fresh_rate(&asset).map_err(PlanError::Rate)?;
		let schedule = p.fees(&asset).map_err(PlanError::OutOfBounds)?;
		let quoted_script = self.quote_script(&req.quote).await?;
		let key_digest = key_proof_digest(&id);
		let mut steps = Vec::with_capacity(n);
		for (j, s) in req.steps.iter().enumerate() {
			let i = j + 1;
			p.check_value(asset, s.value).map_err(PlanError::OutOfBounds)?;
			if !p.exit_delay_ok(s.exit_delay) {
				return Err(PlanError::OutOfBounds(format!("step {}: an exit delay of {} units; the operator takes {} to {}", i,
					s.exit_delay.units(), p.min_exit_delay.units(), p.max_exit_delay.units())));
			}
			if s.owner == p.operator {
				return Err(PlanError::OutOfBounds(format!("step {}: the leaf's key is the operator's own key S", i)));
			}
			let before = plan.value(i - 1).expect("checked");
			let due = schedule.refresh(before, c.coin.expiry, MedianTime::from_consensus(
				c.coin.expiry.to_consensus_u32().saturating_sub(FeeSchedule::FREE_FROM).max(500_000_000)).unwrap_or(c.coin.expiry));
			if s.fee < due {
				return Err(PlanError::OutOfBounds(format!("step {}: a fee of {}; the asset's schedule asks {} in the step's free window", i,
					s.fee, due)));
			}
			if Some(&s.operator_script) != quoted_script.as_ref() {
				return Err(PlanError::OutOfBounds(format!("step {}: the operator's script is not the one the quote named", i)));
			}
			if self.store.arca_script(s.holder_script.as_bytes()).await?.is_some() {
				return Err(PlanError::OutOfBounds(format!("step {}: the holder's address is a script the server knows as an Arca script: a \
					refund pays the holder at an address of its own, never into the tree", i)));
			}
			if !verify_digest(&req.key_proofs[j], &key_digest, &s.owner) {
				return Err(PlanError::BadSignature(format!("step {}: the key proof is not the leaf's key's signature over the plan", i)));
			}
			if arca_covenant::script::sha256(&req.preimages[j]) != s.unlock_hash {
				return Err(PlanError::BadSignature(format!("step {}: the preimage does not open the unlock hash", i)));
			}
			let refund = plan.refund(i).expect("checked");
			let (old_half, new_half) = req.halves[j];
			let old = refund.old_message().map_err(|e| PlanError::Internal(e.to_string()))?;
			let new = refund.new_message().map_err(|e| PlanError::Internal(e.to_string()))?;
			if !verify_digest(&old_half, &old.digest, &refund.old.owner) || !verify_digest(&new_half, &new.digest, &refund.new.owner) {
				return Err(PlanError::BadSignature(format!("step {}: a refund half is not its leaf's owner's signature over the refund", i)));
			}
			if !crate::auth::verify_binding(&p.chain, &p.operator, &s.owner, &req.mailbox, &req.mailbox_proofs[j]) {
				return Err(PlanError::BadSignature(format!("step {}: the mailbox proof is not the leaf's key's binding to the mailbox key", i)));
			}
			steps.push(NewPlanStep {
				idx: i as u16, value: s.value, fee: s.fee, owner_key: s.owner.serialize(), owner_nonce: s.owner_nonce,
				operator_nonce: s.operator_nonce, exit_delay_units: s.exit_delay.units(), unlock_hash: s.unlock_hash,
				preimage: req.preimages[j], holder_script: s.holder_script.to_bytes(), operator_script: s.operator_script.to_bytes(),
				margin: s.margin, old_half: *old_half.as_ref(), new_half: *new_half.as_ref(), key_proof: *req.key_proofs[j].as_ref(),
				mailbox_proof: *req.mailbox_proofs[j].as_ref(), participation_id: step_participation_id(&id, i as u16),
			});
		}
		let new = NewPlan {
			plan_id: id, coin: req.coin.0, asset: asset.into_inner().to_byte_array(), value: plan.value, first_owner: first.owner.serialize(),
			first_salt: first.salt, first_delay: first.exit_delay.units(), mailbox_key: req.mailbox.serialize(),
			attestation: *req.attestation.as_ref(), quote: req.quote, steps,
		};
		match self.store.insert_plan(&new).await {
			Ok(()) => {},
			Err(StoreError::PlanExists) => {},
			Err(e) => return Err(e.into()),
		}
		log::info!("plan {} accepted: coin {} refreshed by {} step(s) without its holder", hex(&id), req.coin, n);
		self.status(&id).await
	}

	/// The script a quote named for the operator's share of every refund.
	/// `None` when there is no such quote.
	async fn quote_script(&self, quote: &[u8; 32]) -> Result<Option<Script>, PlanError> {
		Ok(self.store.quote_script(quote).await?.map(Script::from))
	}

	/// The plan `id` as its holder sees it.
	pub async fn status(&self, id: &[u8; 32]) -> Result<PlanStatus, PlanError> {
		let row = self.store.plan(id).await?.ok_or_else(|| PlanError::Unknown(hex(id)))?;
		self.status_of(row).await
	}

	async fn status_of(&self, row: PlanRow) -> Result<PlanStatus, PlanError> {
		let mut steps = Vec::with_capacity(row.steps.len());
		let mut gives_up = Some(row.coin);
		for s in &row.steps {
			let mut st = StepStatus {
				idx: s.step.idx, state: s.state, reason: s.reason.clone(), participation: s.participation, gives_up,
				round: None, leaf_id: s.leaf_id, batch_vout: None, leaf_index: None, record: None,
			};
			if let Some(l) = s.leaf_id {
				if let Some(b) = self.store.batch_leaf(&l).await? {
					if let Some(r) = self.store.round(b.round_id).await? {
						st.round = Some((Txid::from_byte_array(r.txid), r.state.as_str().to_string()));
					}
					st.batch_vout = Some(b.vout);
					st.leaf_index = Some(b.idx);
					if s.state == StepState::Done {
						st.record = Some(b.record.clone());
					}
				}
			}
			gives_up = s.leaf_id;
			steps.push(st);
		}
		Ok(PlanStatus { row, steps })
	}

	/// The plans whose leaves are bound to the mailbox `key`, the newest
	/// first.
	pub async fn of_mailbox(&self, key: &XOnlyPublicKey) -> Result<Vec<PlanStatus>, PlanError> {
		let mut out = vec![];
		for id in self.store.plans_of_mailbox(&key.serialize()).await? {
			out.push(self.status(&id).await?);
		}
		Ok(out)
	}

	/// Cancels the steps of plan `id` that have not started, on the plan's
	/// mailbox key's signature over [`cancel_digest`]. A plan whose step is
	/// in a round waits for the round first; a plan over already is answered
	/// as it stands.
	pub async fn cancel(&self, id: &[u8; 32], signature: &Signature) -> Result<PlanStatus, PlanError> {
		let row = self.store.plan(id).await?.ok_or_else(|| PlanError::Unknown(hex(id)))?;
		let mailbox = XOnlyPublicKey::from_slice(&row.mailbox_key).map_err(|e| PlanError::Internal(e.to_string()))?;
		if !verify_digest(signature, &cancel_digest(&self.params.chain, &self.params.operator, id), &mailbox) {
			return Err(PlanError::BadSignature("the signature is not the plan's mailbox key's over its cancel digest".into()));
		}
		if matches!(row.state, PlanState::Open | PlanState::Stopped) && !self.store.cancel_plan(id, "cancelled by its holder").await? {
			return Err(PlanError::Conflict(format!("plan {} has a step in a round: it is cancelled once that round decides it", hex(id))));
		}
		log::info!("plan {} cancelled by its holder", hex(id));
		self.status(id).await
	}

	/// Takes the holder's unroll authorisations for `leaf`, a leaf a step of
	/// a plan made, one per node above it from the batch output down, each
	/// signed by the leaf's key: the server keeps the leaf's full record (its
	/// record in the tree, the step's preimage, the authorisations), which it
	/// resolves a spend of the leaf from. A leaf whose record the server holds
	/// already is answered as it stands.
	pub async fn hand_over(&self, leaf: &LeafId, auths: Vec<(Signature, MedianTime)>) -> Result<(), PlanError> {
		let row = self.store.leaf(&leaf.0).await?.ok_or(PlanError::Coin(CoinError::UnknownLeaf(*leaf)))?;
		if !row.record.is_empty() {
			return Ok(());
		}
		let mut step = None;
		for (id, how) in self.store.plans_naming(&leaf.0).await? {
			if how != "made" {
				continue;
			}
			let plan = self.store.plan(&id).await?.ok_or_else(|| PlanError::Internal("a plan is gone".into()))?;
			step = plan.steps.into_iter().find(|s| s.leaf_id == Some(leaf.0) && s.state == StepState::Done);
			if step.is_some() {
				break;
			}
		}
		let step = step.ok_or_else(|| PlanError::Unknown(format!("leaf {} is no leaf a done step of a plan made", leaf)))?;
		let b = self.store.batch_leaf(&leaf.0).await?.ok_or_else(|| PlanError::Internal(format!("leaf {} is in no batch", leaf)))?;
		let round = self.store.round(b.round_id).await?.ok_or_else(|| PlanError::Internal(format!("round {} is not recorded", b.round_id)))?;
		let round_tx: elements::Transaction = elements::encode::deserialize(&round.tx).map_err(|e| PlanError::Internal(e.to_string()))?;
		// As of now, or of its first expiry once that has passed: a holder back
		// after the leaf's expiry hands its authorisations over all the same.
		let now = self.now().await?;
		let first = crate::coins::batch_leaf_expiry(&b).ok_or_else(|| PlanError::Internal(format!("leaf {}'s record", leaf)))?;
		let as_of = if first < now.to_consensus_u32() { MedianTime::from_consensus(first).map_err(|e| PlanError::Internal(e.to_string()))? } else { now };
		let coin = crate::coins::batch_coin(&b, step.step.preimage, auths).map_err(|e| PlanError::Internal(format!("leaf {}: {}", leaf, e)))?;
		let policy = arca_covenant::WalletPolicy { horizon: 0, ..self.params.taken_policy(as_of) };
		let valid = coin.resolve(std::slice::from_ref(&round_tx), &policy)
			.map_err(|e| PlanError::Coin(CoinError::InvalidCoin { leaf: *leaf, error: e }))?;
		if valid.id != *leaf {
			return Err(PlanError::Internal(format!("the record of leaf {} gives the id {}", leaf, valid.id)));
		}
		let bytes = coin.to_bytes().map_err(|e| PlanError::Internal(e.to_string()))?;
		self.store.set_plan_leaf_record(&leaf.0, &bytes).await?;
		log::info!("leaf {} of a plan's step: its holder's unroll authorisations are in", leaf);
		Ok(())
	}
}

/// The first expiry of the coin `leaf`: from its coin record, or from its
/// record in the tree for a leaf a step made whose holder has not handed
/// over its authorisations yet.
pub async fn coin_expiry(store: &Store, leaf: &[u8; 32]) -> Result<Option<u32>, StoreError> {
	let Some(row) = store.leaf(leaf).await? else { return Ok(None) };
	if !row.record.is_empty() {
		if let Ok(c) = CoinRecord::from_bytes(&row.record) {
			match c {
				CoinRecord::Leaf { record, .. } => return Ok(Some(record.schedule.expiries()[0].to_consensus_u32())),
				CoinRecord::Accumulator { record, .. } => return Ok(Some(record.schedule.expiries()[0].to_consensus_u32())),
				_ => {},
			}
		}
	}
	let Some(b) = store.batch_leaf(leaf).await? else { return Ok(None) };
	Ok(crate::coins::batch_leaf_expiry(&b))
}

/// Starts every step whose turn it is and whose time has come (`now` at or
/// past the start of its coin's free window): its participation, recorded
/// pending, runs in the asset's next round. A step whose coin is spent
/// otherwise, lost, or on the chain is void, and its plan stopped. Returns
/// how many started.
pub async fn apply(store: &Store, params: &Params, now: MedianTime) -> Result<usize, StoreError> {
	let mut started = 0;
	for id in store.open_plans().await? {
		let Some(plan) = store.plan(&id).await? else { continue };
		let Some(next) = plan.next().cloned() else { continue };
		if next.state != StepState::Waiting {
			continue;
		}
		let Some(coin) = plan.current_coin() else { continue };
		let Some(row) = store.leaf(&coin).await? else { continue };
		let void = |why: String| async move {
			if store.void_step(&id, next.step.idx, &why).await? {
				log::warn!("plan {}: step {} is void and the plan stopped: {}", hex(&id), next.step.idx, why);
			}
			Ok::<_, StoreError>(())
		};
		match row.state {
			LeafState::Live => {},
			// Its holder's own participation holds it: no step runs from it,
			// and the plan ends once that participation is released.
			LeafState::Spent if holders_participation(store, &row).await?.is_some() => continue,
			LeafState::Spent => {
				void(format!("coin {} is spent by {}", LeafId(coin), row.spent_by.as_deref().map(hex).unwrap_or_default())).await?;
				continue;
			},
			other => {
				void(format!("coin {} is {}", LeafId(coin), other.as_str())).await?;
				continue;
			},
		}
		if !store.sightings_of(&row.script_pubkey).await?.is_empty() {
			void(format!("coin {} is on the chain: its holder took it home", LeafId(coin))).await?;
			continue;
		}
		let Some(expiry) = coin_expiry(store, &coin).await? else { continue };
		if now.to_consensus_u32() < expiry.saturating_sub(FeeSchedule::FREE_FROM) {
			continue;
		}
		let s = &next.step;
		let attestation = if s.idx == 1 {
			plan.attestation
		} else {
			plan.steps[s.idx as usize - 2].step.key_proof
		};
		let before = if s.idx == 1 { plan.value } else { plan.steps[s.idx as usize - 2].step.value };
		let pid = step_participation_id(&id, s.idx);
		let np = NewParticipation {
			id: pid,
			unlock_hash: s.unlock_hash,
			preimage: s.preimage,
			not_before: None,
			refund_delay_units: params.refund_delay.units(),
			inputs: vec![ParticipationInput {
				leaf_id: coin, asset: plan.asset, value: before, margin: s.margin, attestation, returned: false,
			}],
			outputs: vec![ParticipationOutput {
				asset: plan.asset, value: s.value,
				kind: WantedKind::Leaf {
					template: Template::Vtxo1.to_string(), owner_key: s.owner_key, owner_nonce: s.owner_nonce,
					exit_delay_units: s.exit_delay_units, operator_nonce: s.operator_nonce, htlc: None, order: None,
					landing: None,
					channel: None,
				},
				leaf_id: None,
			}],
			fees: vec![(plan.asset, s.fee)],
			fill: None,
			distribution: None,
		};
		match store.start_step(&id, s.idx, &np).await {
			Ok(true) => {
				started += 1;
				log::info!("plan {}: step {} runs as participation {}, giving up coin {}", hex(&id), s.idx, hex(&pid), LeafId(coin));
			},
			Ok(false) => {},
			Err(e @ (StoreError::LeafSpent(_) | StoreError::LeafNotLive(..) | StoreError::KeyReused | StoreError::SaltReused(_))) => {
				// Taken meanwhile by its holder's own participation: that
				// holds the plan, as above.
				let held = match store.leaf(&coin).await? {
					Some(r) => holders_participation(store, &r).await?.is_some(),
					None => false,
				};
				if !held {
					void(e.to_string()).await?;
				}
			},
			Err(e) => return Err(e),
		}
	}
	Ok(started)
}

/// Completes every running step whose participation is issued in a final
/// round: released without forfeits, its leaf credited. Returns how many.
pub async fn finish(store: &Store) -> Result<usize, StoreError> {
	let mut done = 0;
	for id in store.open_plans().await? {
		let Some(plan) = store.plan(&id).await? else { continue };
		for s in plan.steps.iter().filter(|s| s.state == StepState::Running) {
			if store.finish_step(&id, s.step.idx).await? {
				done += 1;
				log::info!("plan {}: step {} is done, its round final: leaf {} credited", hex(&id), s.step.idx,
					s.leaf_id.map(|l| LeafId(l).to_string()).unwrap_or_default());
			}
		}
	}
	Ok(done)
}

/// For the participation `p` of a plan's step, why its coin is not one the
/// round can take now, or `None` when it is: the coin spent by the step,
/// and nothing of it on the chain. A step runs late, past the coin's exit
/// deadline, as long as the coin's batch is not released.
pub async fn step_coin_waits(store: &Store, p: &ParticipationRow) -> Result<Option<String>, StoreError> {
	for i in p.inputs.iter().filter(|i| !i.returned) {
		let Some(row) = store.leaf(&i.leaf_id).await? else {
			return Ok(Some(format!("coin {} is not known", LeafId(i.leaf_id))));
		};
		if row.state != LeafState::Spent || row.spent_by.as_deref() != Some(&p.id[..]) {
			return Ok(Some(format!("coin {} is {}, not given up to the step", LeafId(i.leaf_id), row.state.as_str())));
		}
		if !store.sightings_of(&row.script_pubkey).await?.is_empty() {
			return Ok(Some(format!("coin {} is on the chain", LeafId(i.leaf_id))));
		}
	}
	Ok(None)
}

/// Each participation of `again` that is a plan's step, run again after its
/// round was lost: a step runs only under the leaf its plan names, so it is
/// not run again. Its participation is voided (its coin, for which no
/// forfeit was ever signed, is its holder's again), the step void and the
/// plan stopped; the batch guard keeps that coin unswept. Returns the ids it
/// voided.
pub async fn void_rerun(store: &Store, again: &[[u8; 32]], round: &Txid) -> Result<Vec<[u8; 32]>, StoreError> {
	let mut out = vec![];
	for id in again {
		let Some((plan, idx)) = store.plan_step_of(id).await? else { continue };
		let why = format!("its round {} is lost, and a step runs only under the leaf its plan names", round);
		store.void_participation(id, &why).await?;
		store.void_step(&plan, idx, &why).await?;
		log::warn!("plan {}: step {} is void and the plan stopped: {}", hex(&plan), idx, why);
		out.push(*id);
	}
	Ok(out)
}

/// Why the batch at output `vout` of the round `round_id` must not be
/// released now, or `None`: it holds the current coin of a plan that is
/// open or stopped, which is not on the chain. A holder away on a plan
/// finds that coin unswept, whether the step that gives it up has run or
/// not.
pub async fn holds_batch(store: &Store, round_id: i64, vout: u32) -> Result<Option<String>, StoreError> {
	for id in store.unfinished_plans().await? {
		let Some(plan) = store.plan(&id).await? else { continue };
		let Some(coin) = plan.current_coin() else { continue };
		let Some(b) = store.batch_leaf(&coin).await? else { continue };
		if b.round_id != round_id || b.vout != vout {
			continue;
		}
		let Some(row) = store.leaf(&coin).await? else { continue };
		if matches!(row.state, LeafState::Lost | LeafState::Expired) || !store.sightings_of(&row.script_pubkey).await?.is_empty() {
			continue;
		}
		return Ok(Some(format!("it holds coin {}, the current coin of plan {} ({})", LeafId(coin), hex(&id), plan.state.as_str())));
	}
	Ok(None)
}

/// Why the operator co-signs no transfer of the coin `leaf`, or `None`: a
/// plan names it, and its holder's refund halves are valid while its script
/// is unspent, so the operator alone could void a reassignment of it.
pub async fn blocks_transfer(store: &Store, leaf: &[u8; 32]) -> Result<Option<String>, StoreError> {
	Ok(store.plans_naming(leaf).await?.first().map(|(id, _)| format!(
		"coin {} is named by offline-refresh plan {}, and its holder's refund halves stay valid while its script is unspent: its \
		holder gives it up in a round, for a leaf no plan names, before paying out of round", LeafId(*leaf), hex(id))))
}

/// Why no participation takes the coin `leaf` now, or `None`. A holder's
/// participation may give up the current coin of a plan that is open or
/// stopped: it holds the plan, no step runs from the coin while it does, and
/// the plan ends once that participation is released ([`release_given_up`]);
/// should it never complete, the plan stands. It is refused while the plan's
/// next step is in a round (that step gives the coin up), for a coin a plan
/// names that is not its current coin, and for a coin a step made whose
/// predecessor is not yet swept with the sweep final (the step's refund, which
/// answers that coin, needs this coin's one co-signed spend).
pub async fn blocks_participation(store: &Store, leaf: &[u8; 32], participation: &[u8; 32]) -> Result<Option<String>, StoreError> {
	for (id, how) in store.plans_naming(leaf).await? {
		let Some(plan) = store.plan(&id).await? else { continue };
		if plan.steps.iter().any(|s| s.participation == Some(*participation)) {
			return Ok(None);
		}
		if matches!(plan.state, PlanState::Open | PlanState::Stopped) {
			if plan.current_coin() != Some(*leaf) {
				return Ok(Some(format!("coin {} is named by offline-refresh plan {}, which is {}, and is not its current coin",
					LeafId(*leaf), hex(&id), plan.state.as_str())));
			}
			if let Some(s) = plan.next().filter(|s| s.state == StepState::Running) {
				return Ok(Some(format!("coin {} is being given up by step {} of offline-refresh plan {}, in a round now: its new leaf is \
					the holder's at its next sync", LeafId(*leaf), s.step.idx, hex(&id))));
			}
		}
		if how == "made" {
			let Some(s) = plan.steps.iter().find(|s| s.leaf_id == Some(*leaf)) else { continue };
			let Some(pid) = s.participation else { continue };
			let Some(p) = store.participation(&pid).await? else { continue };
			for i in &p.inputs {
				if !store.batch_swept_final(&i.leaf_id).await? {
					return Ok(Some(format!("coin {} was made by step {} of offline-refresh plan {}, and the coin it replaced, {}, is not yet \
						swept with its batch: the step's refund, which answers that coin, needs this coin's one co-signed spend; it is taken \
						into a round once that sweep is final", LeafId(*leaf), s.step.idx, hex(&id), LeafId(i.leaf_id))));
				}
			}
		}
	}
	Ok(None)
}

/// The participation of its holder's that holds the coin `row`, when it is
/// spent by one that is no plan's step: the coin is then the holder's to give
/// up in that participation's round, and no step runs from it.
async fn holders_participation(store: &Store, row: &LeafRow) -> Result<Option<ParticipationRow>, StoreError> {
	let Some(by) = row.spent_by.as_deref().and_then(|b| <[u8; 32]>::try_from(b).ok()) else { return Ok(None) };
	if store.plan_step_of(&by).await?.is_some() {
		return Ok(None);
	}
	store.participation(&by).await
}

/// Ends every plan, open or stopped, whose current coin its holder gave up
/// in a participation of its own that is now released: its round final and
/// its forfeits handed over, the coin is given up for good, and the new
/// leaf is the holder's, named by no plan. A participation that never
/// completes leaves the plan as it was. Returns how many plans ended.
pub async fn release_given_up(store: &Store) -> Result<usize, StoreError> {
	let mut ended = 0;
	for id in store.unfinished_plans().await? {
		let Some(plan) = store.plan(&id).await? else { continue };
		let Some(coin) = plan.current_coin() else { continue };
		let Some(row) = store.leaf(&coin).await? else { continue };
		if row.state != LeafState::Spent {
			continue;
		}
		let Some(p) = holders_participation(store, &row).await? else { continue };
		if p.state != ParticipationState::Released {
			continue;
		}
		let round = match p.round_id {
			Some(r) => store.round(r).await?.map(|r| Txid::from_byte_array(r.txid).to_string()).unwrap_or_default(),
			None => String::new(),
		};
		let why = format!("released: its holder gave its coin {} up in participation {}, round {}", LeafId(coin), hex(&p.id), round);
		if store.cancel_plan(&id, &why).await? {
			ended += 1;
			log::info!("plan {}: {}", hex(&id), why);
		}
	}
	Ok(ended)
}

/// The covenant plan a stored plan is, rebuilt from what the server keeps.
pub fn plan_of(row: &PlanRow, params: &Params) -> Result<Plan, String> {
	let key = |b: &[u8; 32]| XOnlyPublicKey::from_slice(b).map_err(|e| e.to_string());
	let first = LeafPolicy { enclave: None,
		owner: key(&row.first_owner)?, operator: params.operator, salt: row.first_salt, chain: params.chain,
		exit_delay: RelativeTime::from_units(row.first_delay).map_err(|e| e.to_string())?, htlc: None,
		order: None,
		landing: None,
		channel: None, v2: false,
	};
	let mut steps = Vec::with_capacity(row.steps.len());
	for s in &row.steps {
		let st = &s.step;
		steps.push(PlanStep {
			value: st.value, fee: st.fee, owner: key(&st.owner_key)?, owner_nonce: st.owner_nonce, operator_nonce: st.operator_nonce,
			exit_delay: RelativeTime::from_units(st.exit_delay_units).map_err(|e| e.to_string())?, unlock_hash: st.unlock_hash,
			holder_script: Script::from(st.holder_script.clone()), operator_script: Script::from(st.operator_script.clone()), margin: st.margin,
		});
	}
	Ok(Plan {
		chain: params.chain, operator: params.operator, coin: LeafId(row.coin), first, asset: AssetId::from_byte_array(row.asset),
		value: row.value, steps,
	})
}

/// A step's refund, ready for the operator's two signatures.
#[derive(Debug, Clone)]
pub struct PlanRefund {
	pub plan: [u8; 32],
	pub idx: u16,
	pub refund: arca_covenant::Refund,
	pub old_half: Signature,
	pub new_half: Signature,
	/// The leaf the step's round made for it, and the preimage of its entry.
	pub new_leaf: [u8; 32],
	pub preimage: [u8; 32],
}

/// The refund of the step that gave up the coin `leaf` for a leaf of a round,
/// if a step did: what the watcher answers that coin with when it comes on
/// the chain.
pub async fn refund_for(store: &Store, params: &Params, leaf: &[u8; 32]) -> Result<Option<PlanRefund>, StoreError> {
	for (id, _) in store.plans_naming(leaf).await? {
		let Some(row) = store.plan(&id).await? else { continue };
		let mut gives_up = Some(row.coin);
		for s in &row.steps {
			if gives_up == Some(*leaf) && s.participation.is_some() {
				let Some(new_leaf) = s.leaf_id else { break };
				let plan = match plan_of(&row, params) {
					Ok(p) => p,
					Err(e) => {
						log::error!("plan {}: cannot be rebuilt: {}", hex(&id), e);
						break;
					},
				};
				let Some(refund) = plan.refund(s.step.idx as usize) else { break };
				let (Ok(old_half), Ok(new_half)) = (Signature::from_slice(&s.step.old_half), Signature::from_slice(&s.step.new_half)) else {
					break;
				};
				return Ok(Some(PlanRefund { plan: id, idx: s.step.idx, refund, old_half, new_half, new_leaf, preimage: s.step.preimage }));
			}
			gives_up = s.leaf_id;
		}
	}
	Ok(None)
}
