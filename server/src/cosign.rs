//! Co-signing out-of-round transfers.
//!
//! A sender gives up one or more coins the server knows, by leaf id, each
//! with the value its checkpoint keeps and the owner's two signatures (over
//! the checkpoint and over the reassignment), for one to four new leaves,
//! each named by its owner's key and nonce, a creator nonce the sender drew
//! fresh for it, an exit delay, an asset and a value. The server co-signs
//! only when every rule holds:
//!
//! - each input is a coin the server knows, live (a board is live only once
//!   credited, that is final), spent by nothing else: a second spend of a leaf
//!   is refused, and that refusal is the whole of the double-spend protection
//!   before a round;
//! - no output of the coin's lineage is on-chain, in a block or in the
//!   mempool, and no board it rests on is spent or uncredited: an Arca leaf on
//!   the chain past its exit delay can be exited by its owner at once, so the
//!   server co-signs no off-chain spend of it, a converted board included;
//! - the new coins are at most [`Params::depth_limit`] reassignments from a
//!   round or a board;
//! - each new leaf is within the published bounds: an asset served, a value
//!   within that asset's bounds, an exit delay within the bounds, a key that
//!   owns no other leaf and is not the operator's `S`, a script never seen;
//! - no transaction could satisfy both this reassignment and one the server
//!   co-signed before: their committed outputs do not agree at every index
//!   both commit to (`arca_covenant::TransferPlan::admit`, run against every
//!   reassignment recorded with the same output 0, under a lock on it), since
//!   such a transaction would hand one side's value to whoever broadcast it;
//! - every checkpoint keeps between one atom and the whole coin, the outputs
//!   take no more of any asset than the checkpoints keep, and every owner
//!   signature verifies;
//! - the margins are bounded: each checkpoint leaves, and the reassignment
//!   leaves in at least one asset, the least margin that pays its fee (four
//!   times the node's floor for the transaction, in an asset the node
//!   accepts for fees now; one atom in one it does not), and no margin is
//!   more than [`Params::max_margin_multiple`] times its least. A transfer
//!   whose answer would need a coin of the operator's for every fee, or
//!   whose margin would be a fee the node refuses, is not co-signed.
//!
//! Then the transfer is recorded, inputs spent, before `S` signs anything
//! (the signer runs in its own process: [`crate::signer`]). The signer keeps
//! its own record and co-signs one spend of each output whatever the
//! database says, so a database restored from an older copy cannot co-sign a
//! second spend: the signer refuses it, and so does the server
//! (`double_spend`). Each new coin's
//! record is checked by the server as a receiver would check it, stored, and
//! posted to the receiver's mailbox. A request repeated byte for byte gets the
//! same answer.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Transaction};

use arca_covenant::script::sha256;
use arca_covenant::sign::verify_digest;
use arca_covenant::transfer::SeenReassignments;
use arca_covenant::transfer::{transfer_id, Transfer, TransferInput, MAX_INPUTS};
use arca_covenant::spend::{margin_for, FeeSource};
use arca_covenant::{CoinRecord, ExplicitOutput, LeafId, MedianTime, NewLeaf, Pair, TransferError, TransferPlan, ValidInput};
use elements::OutPoint;

use crate::chain::FinalityService;
use crate::coins::{self, Checked, CoinError};
use crate::fees;
use crate::params::Params;
use crate::signer::{SignerClient, SignerError};
use crate::store::{
	LeafKind, LeafState, NewCoin, NewReassignment, NewScript, NewTransferInput, NewTransferOutput, ScriptKind, Store,
	StoreError,
};

/// One coin given up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRequest {
	pub leaf_id: LeafId,
	/// What the checkpoint keeps; the rest of the coin is the checkpoint's fee
	/// margin.
	pub checkpoint_value: u64,
	/// The owner's signature over the checkpoint.
	pub checkpoint_sig: Signature,
	/// The owner's signature over the reassignment.
	pub reassignment_sig: Signature,
}

/// One new leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputRequest {
	pub asset: AssetId,
	pub value: u64,
	pub leaf: NewLeaf,
	/// The mailbox the new coin's record goes to; the leaf's owner key when
	/// `None`.
	pub mailbox: Option<XOnlyPublicKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRequest {
	pub inputs: Vec<InputRequest>,
	pub outputs: Vec<OutputRequest>,
}

/// What the server returns for a co-signed transfer.
#[derive(Debug, Clone)]
pub struct Cosigned {
	pub transfer_id: [u8; 32],
	/// The operator's signatures for each input, `operator` filled in each
	/// pair: over the checkpoint, and over the reassignment.
	pub signatures: Vec<(Signature, Signature)>,
	/// Each new coin: its id and its record, as its receiver gets it.
	pub outputs: Vec<(LeafId, CoinRecord)>,
}

/// Why a transfer was refused, or could not be co-signed.
#[derive(Debug, thiserror::Error)]
pub enum CosignError {
	#[error("the request is malformed: {0}")]
	Malformed(String),
	#[error("leaf {0} is not known to this server")]
	UnknownLeaf(LeafId),
	#[error("leaf {0} is {1}, not live: a board is live once its transaction is final")]
	NotLive(LeafId, &'static str),
	#[error("leaf {0} is already spent: the server co-signs one spend of a leaf")]
	DoubleSpend(LeafId),
	#[error("leaf {0} rests on a board that is not credited: its transaction is not final")]
	BoardNotFinal(LeafId),
	#[error("leaf {0} rests on a leaf of a round that is not final")]
	RoundNotFinal(LeafId),
	#[error("leaf {leaf}: {what} is on-chain, so its owner could take it under the receiver; the server co-signs no off-chain spend of it")]
	OnChain { leaf: LeafId, what: String },
	#[error("the new coins would be {hops} reassignments from a round or a board; the limit is {limit}: refresh in a round first")]
	DepthLimit { hops: usize, limit: usize },
	#[error("an output is outside the operator's published bounds: {0}")]
	OutOfBounds(String),
	#[error("the values do not add up: {0}")]
	Value(String),
	#[error("a margin is outside the bounds: {0}")]
	Margin(String),
	#[error("input {input}: the owner's {which} signature does not verify")]
	BadSignature { input: usize, which: &'static str },
	#[error("leaf {leaf}'s coin does not check out: {error}")]
	InvalidCoin { leaf: LeafId, error: TransferError },
	#[error("an output's key already owns a leaf: every leaf has a key of its own")]
	KeyReused,
	#[error("an output's key is the operator's own key S: a leaf has its owner's key, never the operator's")]
	OperatorKey,
	#[error("an output's script is already known: a leaf script is never funded twice")]
	ScriptReused,
	#[error("an output's salt {0} is already known to the server: every leaf has a salt of its own, never one another leaf has had")]
	SaltReused(String),
	#[error("leaf {0} has an open out-of-round reassignment: no release is accepted for it")]
	OpenReassignment(LeafId),
	#[error("one transaction could satisfy this reassignment and one already co-signed, and give one side's value to whoever broadcast it: {0}")]
	Mergeable(String),
	#[error("the signer: {0}")]
	Signer(#[from] SignerError),
	#[error("the server has not followed the chain yet")]
	NotSynced,
	#[error(transparent)]
	Store(StoreError),
	#[error("{0}")]
	Internal(String),
}

impl CosignError {
	/// A stable name for the refusal.
	pub fn code(&self) -> &'static str {
		use CosignError::*;
		match self {
			Malformed(_) => "malformed",
			UnknownLeaf(_) => "unknown_leaf",
			NotLive(..) => "not_live",
			DoubleSpend(_) => "double_spend",
			BoardNotFinal(_) => "board_not_final",
			RoundNotFinal(_) => "round_not_final",
			OnChain { .. } => "on_chain",
			DepthLimit { .. } => "depth_limit",
			OutOfBounds(_) => "out_of_bounds",
			Value(_) => "value",
			Margin(_) => "margin",
			BadSignature { .. } => "bad_signature",
			InvalidCoin { .. } => "invalid_coin",
			KeyReused => "key_reused",
			OperatorKey => "operator_key",
			ScriptReused => "script_reused",
			SaltReused(_) => "salt",
			OpenReassignment(_) => "open_reassignment",
			Mergeable(_) => "merge",
			Signer(SignerError::AlreadySigned(_)) => "double_spend",
			Signer(_) => "signer_unavailable",
			NotSynced => "not_synced",
			Store(_) | Internal(_) => "internal",
		}
	}
}

impl From<StoreError> for CosignError {
	fn from(e: StoreError) -> CosignError {
		match e {
			StoreError::KeyReused => CosignError::KeyReused,
			StoreError::ScriptReused => CosignError::ScriptReused,
			StoreError::SaltReused(h) => CosignError::SaltReused(h),
			StoreError::Mergeable(m) => CosignError::Mergeable(m),
			other => CosignError::Store(other),
		}
	}
}

impl From<CoinError> for CosignError {
	fn from(e: CoinError) -> CosignError {
		match e {
			CoinError::UnknownLeaf(id) => CosignError::UnknownLeaf(id),
			CoinError::NotLive(id, state) => CosignError::NotLive(id, state),
			CoinError::Spent(id) => CosignError::DoubleSpend(id),
			CoinError::BoardNotFinal(id) => CosignError::BoardNotFinal(id),
			CoinError::RoundNotFinal(id) => CosignError::RoundNotFinal(id),
			CoinError::OnChain { leaf, what } => CosignError::OnChain { leaf, what },
			CoinError::InvalidCoin { leaf, error } => CosignError::InvalidCoin { leaf, error },
			CoinError::Store(e) => e.into(),
			CoinError::Internal(m) => CosignError::Internal(m),
		}
	}
}

/// The tag of a transfer request's hash, which is the transfer's id.
pub const REQUEST_TAG: &[u8] = b"Arca/transfer-request";

impl TransferRequest {
	/// The request's hash: every field, in order. A repeated request has the
	/// same hash and gets the same answer.
	pub fn hash(&self) -> [u8; 32] {
		let mut e = sha256::Hash::engine();
		e.input(REQUEST_TAG);
		e.input(&[self.inputs.len() as u8]);
		for i in &self.inputs {
			e.input(&i.leaf_id.0);
			e.input(&i.checkpoint_value.to_le_bytes());
			e.input(i.checkpoint_sig.as_ref());
			e.input(i.reassignment_sig.as_ref());
		}
		e.input(&[self.outputs.len() as u8]);
		for o in &self.outputs {
			e.input(&o.asset.into_inner().to_byte_array());
			e.input(&o.value.to_le_bytes());
			e.input(&o.leaf.owner.serialize());
			e.input(&o.leaf.owner_nonce);
			e.input(&o.leaf.creator_nonce);
			e.input(&o.leaf.exit_delay.units().to_le_bytes());
			e.input(&o.mailbox.unwrap_or(o.leaf.owner).serialize());
		}
		sha256::Hash::from_engine(e).to_byte_array()
	}
}

/// See the [module documentation](self).
pub struct Cosigner {
	store: Store,
	finality: Arc<FinalityService>,
	params: Arc<Params>,
	signer: SignerClient,
}

impl Cosigner {
	pub fn new(store: Store, finality: Arc<FinalityService>, params: Arc<Params>, signer: SignerClient) -> Arc<Cosigner> {
		Arc::new(Cosigner { store, finality, params, signer })
	}

	async fn now(&self) -> Result<MedianTime, CosignError> {
		let tip = self.store.tip_block().await?.ok_or(CosignError::NotSynced)?;
		MedianTime::from_consensus(tip.median_time as u32).map_err(|e| CosignError::Internal(e.to_string()))
	}

	/// Checks a coin given up: known, live, its record valid under the
	/// server's policy, its boards credited and unspent, nothing of its
	/// lineage on-chain ([`crate::coins::check`]).
	async fn check_input(&self, id: &LeafId, transfer: &[u8; 32], now: MedianTime) -> Result<Checked, CosignError> {
		Ok(coins::check(&self.store, &self.params.policy(now), id, transfer).await?)
	}

	/// Co-signs `req`: see the [module documentation](self).
	pub async fn cosign(&self, req: &TransferRequest) -> Result<Cosigned, CosignError> {
		let n = req.inputs.len();
		if n == 0 || n > MAX_INPUTS {
			return Err(CosignError::Malformed(format!("{} inputs; a transfer takes 1 to {}", n, MAX_INPUTS)));
		}
		let m = req.outputs.len();
		if m == 0 || m > arca_covenant::leaf::MAX_OUTPUTS as usize {
			return Err(CosignError::Malformed(format!("{} outputs; a transfer makes 1 to 4", m)));
		}
		let ids: HashSet<LeafId> = req.inputs.iter().map(|i| i.leaf_id).collect();
		if ids.len() != n {
			return Err(CosignError::Malformed("a leaf is given twice".into()));
		}
		let transfer = req.hash();
		// A request repeated byte for byte gets the answer it got.
		if self.store.transfer(&transfer).await?.is_some_and(|t| t.signed) {
			return self.answer(&transfer).await;
		}
		let now = self.now().await?;
		let s = self.params.operator;
		let chain = self.params.chain;

		// The outputs, within the published bounds.
		let mut outputs = Vec::with_capacity(m);
		let mut keys = HashSet::new();
		for o in &req.outputs {
			if !self.params.exit_delay_ok(o.leaf.exit_delay) {
				return Err(CosignError::OutOfBounds(format!(
					"an exit delay of {} units; the operator takes {} to {}", o.leaf.exit_delay.units(),
					self.params.min_exit_delay.units(), self.params.max_exit_delay.units(),
				)));
			}
			self.params.check_value(o.asset, o.value).map_err(CosignError::OutOfBounds)?;
			if o.leaf.owner == s {
				return Err(CosignError::OperatorKey);
			}
			if !keys.insert(o.leaf.owner) {
				return Err(CosignError::KeyReused);
			}
			outputs.push(ExplicitOutput::new(o.asset, o.value, o.leaf.policy(s, chain).script_pubkey()));
		}
		// Each new leaf's salt is its own: never another output's, never one
		// the server has seen on a leaf or promised to one (D44). The sender
		// chooses both nonces of a new leaf's salt. A transfer recorded and
		// not yet signed holds its outputs' salts itself, so the check
		// against the server's is made only for a transfer not yet recorded.
		let mut salts = Vec::with_capacity(m);
		for o in &req.outputs {
			let salt = o.leaf.salt();
			if salts.contains(&salt) {
				return Err(CosignError::SaltReused(crate::signer::hex(&salt)));
			}
			salts.push(salt);
		}
		let recorded = self.store.transfer(&transfer).await?.is_some();
		if !recorded {
			if let Some(known) = self.store.known_salts(&salts).await?.first() {
				return Err(CosignError::SaltReused(crate::signer::hex(known)));
			}
		}

		// The inputs, each checked.
		let mut checked = Vec::with_capacity(n);
		for i in &req.inputs {
			checked.push(self.check_input(&i.leaf_id, &transfer, now).await?);
		}
		let hops = 1 + checked.iter().map(|c| c.coin.hops).max().expect("an input");
		if hops > self.params.depth_limit {
			return Err(CosignError::DepthLimit { hops, limit: self.params.depth_limit });
		}

		// The values.
		let mut kept: BTreeMap<AssetId, u64> = BTreeMap::new();
		for (i, c) in req.inputs.iter().zip(&checked) {
			if i.checkpoint_value == 0 || i.checkpoint_value > c.coin.value {
				return Err(CosignError::Value(format!(
					"a checkpoint keeps {} of a coin of {}", i.checkpoint_value, c.coin.value)));
			}
			*kept.entry(c.coin.asset).or_insert(0) += i.checkpoint_value;
		}
		let mut paid: BTreeMap<AssetId, u64> = BTreeMap::new();
		for o in &outputs {
			*paid.entry(o.asset).or_insert(0) += o.value;
		}
		for (a, v) in &paid {
			let have = kept.get(a).copied().unwrap_or(0);
			if *v > have {
				return Err(CosignError::Value(format!("the outputs take {} of asset {}; the checkpoints keep {}", v, a, have)));
			}
		}

		self.check_margins(req, &checked, &outputs).await?;

		// The owners' signatures.
		let plan = TransferPlan {
			inputs: checked.iter().zip(&req.inputs).map(|(c, i)| (c.coin.clone(), i.checkpoint_value)).collect(),
			outputs: outputs.clone(),
		};
		let mut messages = Vec::with_capacity(n);
		for (k, (c, i)) in checked.iter().zip(&req.inputs).enumerate() {
			let cp = plan.checkpoint_message(k).map_err(|e| CosignError::Internal(e.to_string()))?.digest;
			let re = plan.reassignment_message(k).map_err(|e| CosignError::Internal(e.to_string()))?.digest;
			if !verify_digest(&i.checkpoint_sig, &cp, &c.coin.leaf.owner) {
				return Err(CosignError::BadSignature { input: k, which: "checkpoint" });
			}
			if !verify_digest(&i.reassignment_sig, &re, &c.coin.leaf.owner) {
				return Err(CosignError::BadSignature { input: k, which: "reassignment" });
			}
			messages.push((cp, re));
		}

		// The new coins' ids, from the reassignment.
		let parts: Vec<(LeafId, [u8; 32])> = checked.iter().enumerate()
			.map(|(k, c)| (c.coin.id, plan.checkpoint(k).taproot().program())).collect();
		let new_ids: Vec<LeafId> = req.outputs.iter().enumerate()
			.map(|(j, o)| transfer_id(&parts, &outputs, j as u8, &o.leaf.policy(s, chain).program())).collect();

		// Recorded before anything is signed; a repeated request finds it.
		match self.store.transfer(&transfer).await? {
			Some(t) if t.signed => return self.answer(&transfer).await,
			// Recorded, not yet signed: the signer was not reached last time.
			Some(_) => {},
			None => {
				let ins: Vec<NewTransferInput> = req.inputs.iter().enumerate().map(|(k, i)| NewTransferInput {
					leaf_id: i.leaf_id.0,
					checkpoint_value: i.checkpoint_value,
					checkpoint_owner_sig: sig_bytes(&i.checkpoint_sig),
					reassignment_owner_sig: sig_bytes(&i.reassignment_sig),
					checkpoint_script: plan.checkpoint(k).script_pubkey().to_bytes(),
				}).collect();
				let outs: Vec<NewTransferOutput> = req.outputs.iter().zip(&outputs).zip(&new_ids).map(|((o, out), id)| NewTransferOutput {
					coin: NewCoin {
						leaf_id: id.0,
						kind: LeafKind::Transfer,
						asset: o.asset.into_inner().to_byte_array(),
						value: o.value,
						owner_key: o.leaf.owner.serialize(),
						script_pubkey: out.script_pubkey.to_bytes(),
						hops: hops as u16,
						record: vec![],
						state: LeafState::Pending,
						salt: o.leaf.salt(),
						promised_to: None,
						// The sender's creator nonce, not one the operator issued.
						operator_nonce: None,
						scripts: vec![NewScript { script_pubkey: out.script_pubkey.to_bytes(), kind: ScriptKind::Leaf }],
					},
					mailbox_key: o.mailbox.unwrap_or(o.leaf.owner).serialize(),
				}).collect();
				let spent: Vec<(LeafId, u64)> = plan.inputs.iter().map(|(c, v)| (c.id, *v)).collect();
				let reassignment = NewReassignment {
					first_output: sha256(&outputs[0].record()),
					inputs: encode_inputs(&spent),
					outputs: encode_outputs(&outputs),
				};
				let admit = |seen: &[(Vec<u8>, Vec<u8>)]| -> Result<(), String> {
					let mut known = SeenReassignments::new();
					for (i, o) in seen {
						known.admit(&decode_inputs(i)?, &decode_outputs(o)?).map_err(|e| e.to_string())?;
					}
					plan.admit(&mut known).map_err(|e| e.to_string())
				};
				self.store.record_transfer(&transfer, &reassignment, admit, &ins, &outs).await.map_err(|e| match e {
					StoreError::LeafSpent(id) => CosignError::DoubleSpend(id.parse().unwrap_or(req.inputs[0].leaf_id)),
					StoreError::LeafNotLive(id, state) => CosignError::NotLive(id.parse().unwrap_or(req.inputs[0].leaf_id), state),
					other => other.into(),
				})?;
			},
		}

		// Now S signs, in its own process; each signature is checked against
		// the message the server built.
		let mut sigs = Vec::with_capacity(n);
		for (k, (c, i)) in checked.iter().zip(&req.inputs).enumerate() {
			let cp_out = plan.checkpoint_output(k);
			let owner = c.coin.leaf.owner;
			let cp = self.signer.rebind(&owner, &i.checkpoint_sig, &c.coin.leaf.salt, c.coin.asset, c.coin.value,
				std::slice::from_ref(&cp_out)).await.map_err(|e| lost_spend(e, &c.coin.id))?;
			let checkpoint = plan.checkpoint(k);
			let re = self.signer.rebind(&checkpoint.owner, &i.reassignment_sig, &checkpoint.salt, c.coin.asset, plan.inputs[k].1,
				&outputs).await.map_err(|e| lost_spend(e, &c.coin.id))?;
			if !verify_digest(&cp, &messages[k].0, &s) || !verify_digest(&re, &messages[k].1, &s) {
				return Err(CosignError::Internal("the signer signed another message than the server built".into()));
			}
			sigs.push((cp, re));
		}

		// Each new coin's record, checked as its receiver will check it.
		let mut bases: Vec<Transaction> = checked.iter().flat_map(|c| c.bases.clone()).collect();
		bases.dedup_by_key(|t| t.txid());
		let policy = self.params.policy(now);
		let mut records = Vec::with_capacity(m);
		for (j, o) in req.outputs.iter().enumerate() {
			let record = CoinRecord::Transfer(Box::new(Transfer {
				inputs: checked.iter().zip(&req.inputs).zip(&sigs).map(|((c, i), (cp, re))| TransferInput {
					coin: c.record.clone(),
					checkpoint_value: i.checkpoint_value,
					checkpoint: Pair { operator: *cp, owner: i.checkpoint_sig },
					reassignment: Pair { operator: *re, owner: i.reassignment_sig },
				}).collect(),
				outputs: outputs.clone(),
				index: j as u8,
				leaf: o.leaf,
			}));
			let valid = record.validate(&bases, &policy, &o.leaf.owner, &o.leaf.owner_nonce)
				.map_err(|error| CosignError::InvalidCoin { leaf: new_ids[j], error })?;
			if valid.id != new_ids[j] {
				return Err(CosignError::Internal("a new coin's record gives another id".into()));
			}
			records.push((new_ids[j].0, record.to_bytes().map_err(|e| CosignError::Internal(e.to_string()))?));
		}
		let sig_bytes_list: Vec<([u8; 64], [u8; 64])> = sigs.iter().map(|(a, b)| (sig_bytes(a), sig_bytes(b))).collect();
		self.store.complete_transfer(&transfer, &sig_bytes_list, &records).await?;
		log::info!("co-signed transfer {} of {} input(s) into {} new leaf/leaves",
			crate::signer::hex(&transfer), n, m);
		self.answer(&transfer).await
	}

	/// The least margin of a transaction of `vsize` vbytes in `asset`: four
	/// times the node's floor when it accepts the asset for fees now, one
	/// atom when it does not.
	async fn least_margin(&self, asset: AssetId, vsize: usize) -> Result<u64, CosignError> {
		match fees::floor_per_kvb(&self.finality, asset).await.map_err(|e| CosignError::Internal(e.to_string()))? {
			Some(f) => Ok(margin_for(vsize, f, fees::MULTIPLE).max(1)),
			None => Ok(1),
		}
	}

	/// Each checkpoint's margin, and the reassignment's, within the bounds:
	/// see the [module documentation](self). Each transaction is sized as a
	/// wallet sizes it: the checkpoint keeping the whole coin, and the
	/// reassignment with every input and output in the first input's asset
	/// (an explicit output's size does not depend on its asset or value).
	async fn check_margins(&self, req: &TransferRequest, checked: &[Checked], outputs: &[ExplicitOutput]) -> Result<(), CosignError> {
		let cap = self.params.max_margin_multiple;
		fn internal<E: std::fmt::Display>(e: E) -> CosignError {
			CosignError::Internal(e.to_string())
		}
		let dummy = Signature::from_slice(&[1; 64]).expect("64 bytes");
		let pair = Pair { operator: dummy, owner: dummy };
		let first = checked[0].coin.asset;
		let mut sized = Vec::with_capacity(checked.len());
		for (k, (i, c)) in req.inputs.iter().zip(checked).enumerate() {
			let vi = ValidInput {
				coin: c.coin.clone(), checkpoint: c.coin.checkpoint(), checkpoint_value: c.coin.value,
				checkpoint_pair: pair, reassignment_pair: pair,
			};
			let vsize = vi.checkpoint_tx(OutPoint::default(), &FeeSource::Reserve).map_err(internal)?.tx.vsize();
			let least = self.least_margin(c.coin.asset, vsize).await?;
			let margin = c.coin.value - i.checkpoint_value;
			if margin < least || margin > least.saturating_mul(cap) {
				return Err(CosignError::Margin(format!(
					"input {}'s checkpoint leaves {} of asset {} for its fee; the operator takes {} to {}",
					k, margin, c.coin.asset, least, least.saturating_mul(cap))));
			}
			let mut same = vi;
			same.coin.asset = first;
			sized.push(same);
		}
		let small: Vec<ExplicitOutput> = outputs.iter().map(|o| ExplicitOutput::new(first, 1, o.script_pubkey.clone())).collect();
		let cps: Vec<OutPoint> = (0..sized.len()).map(|i| OutPoint::new(elements::Txid::all_zeros(), i as u32)).collect();
		let vsize = arca_covenant::transfer::reassignment_tx(&sized, &small, &cps, &FeeSource::Reserve).map_err(internal)?.tx.vsize();
		let mut margins: BTreeMap<AssetId, u64> = BTreeMap::new();
		for (i, c) in req.inputs.iter().zip(checked) {
			*margins.entry(c.coin.asset).or_default() += i.checkpoint_value;
		}
		for o in outputs {
			let m = margins.entry(o.asset).or_default();
			*m = m.saturating_sub(o.value);
		}
		let mut pays = None;
		let mut least_any = vec![];
		for (a, m) in &margins {
			let least = self.least_margin(*a, vsize).await?;
			least_any.push(format!("{} of asset {}", least, a));
			if *m > least.saturating_mul(cap) {
				return Err(CosignError::Margin(format!(
					"the reassignment leaves {} of asset {} for its fee; the operator takes at most {}", m, a, least.saturating_mul(cap))));
			}
			if *m >= least {
				pays.get_or_insert(*a);
			}
		}
		if pays.is_none() {
			return Err(CosignError::Margin(format!(
				"the reassignment leaves no margin that pays its fee: at least {}", least_any.join(", or "))));
		}
		Ok(())
	}

	/// The stored answer to the transfer `transfer`.
	async fn answer(&self, transfer: &[u8; 32]) -> Result<Cosigned, CosignError> {
		let t = self.store.transfer(transfer).await?.ok_or_else(|| CosignError::Internal("a transfer vanished".into()))?;
		let mut signatures = vec![];
		for (_, _, s) in &t.inputs {
			let (cp, re) = s.ok_or_else(|| CosignError::Internal("a signed transfer without signatures".into()))?;
			signatures.push((sig_from(&cp)?, sig_from(&re)?));
		}
		let mut outputs = vec![];
		for (id, _) in &t.outputs {
			let row = self.store.leaf(id).await?.ok_or_else(|| CosignError::Internal("an output vanished".into()))?;
			let record = CoinRecord::from_bytes(&row.record).map_err(|e| CosignError::Internal(e.to_string()))?;
			outputs.push((LeafId(*id), record));
		}
		Ok(Cosigned { transfer_id: *transfer, signatures, outputs })
	}

	/// The check a round makes before it accepts an owner's release of a
	/// leaf's lowest node: the leaf must have no open out-of-round
	/// reassignment, or the sender could void the receiver's chain together
	/// with the operator.
	pub async fn check_release(&self, leaf_id: &LeafId) -> Result<(), CosignError> {
		self.store.leaf(&leaf_id.0).await?.ok_or(CosignError::UnknownLeaf(*leaf_id))?;
		if self.store.spent_by_transfer(&leaf_id.0).await?.is_some() {
			return Err(CosignError::OpenReassignment(*leaf_id));
		}
		Ok(())
	}

	pub fn finality(&self) -> &Arc<FinalityService> {
		&self.finality
	}
}

/// The signer's refusal, logged loudly when its record holds another spend
/// of the coin: the database let through a second spend, so it has lost one
/// the signer co-signed.
fn lost_spend(e: SignerError, leaf: &LeafId) -> CosignError {
	if let SignerError::AlreadySigned(m) = &e {
		log::error!("the signer refused a second spend of leaf {} that the database allowed: the database has lost a spend \
			the signer co-signed ({})", leaf, m);
	}
	CosignError::Signer(e)
}

fn sig_bytes(s: &Signature) -> [u8; 64] {
	let mut b = [0u8; 64];
	b.copy_from_slice(s.as_ref());
	b
}

fn sig_from(b: &[u8; 64]) -> Result<Signature, CosignError> {
	Signature::from_slice(b).map_err(|e| CosignError::Internal(e.to_string()))
}

/// A reassignment's inputs, as the store keeps them: each coin's id and its
/// checkpoint's value.
fn encode_inputs(inputs: &[(LeafId, u64)]) -> Vec<u8> {
	let mut w = vec![inputs.len() as u8];
	for (id, v) in inputs {
		w.extend(id.0);
		w.extend(v.to_le_bytes());
	}
	w
}

fn decode_inputs(b: &[u8]) -> Result<Vec<(LeafId, u64)>, String> {
	let bad = || "a stored reassignment's inputs do not decode".to_string();
	let n = *b.first().ok_or_else(bad)? as usize;
	if b.len() != 1 + n * 40 {
		return Err(bad());
	}
	Ok((0..n).map(|i| {
		let at = 1 + i * 40;
		(LeafId(b[at..at + 32].try_into().expect("32")), u64::from_le_bytes(b[at + 32..at + 40].try_into().expect("8")))
	}).collect())
}

/// A reassignment's committed outputs, as the store keeps them.
fn encode_outputs(outputs: &[ExplicitOutput]) -> Vec<u8> {
	let mut w = vec![outputs.len() as u8];
	for o in outputs {
		w.extend(o.asset.into_inner().to_byte_array());
		w.extend(o.value.to_le_bytes());
		let spk = o.script_pubkey.as_bytes();
		w.extend((spk.len() as u16).to_le_bytes());
		w.extend(spk);
	}
	w
}

fn decode_outputs(b: &[u8]) -> Result<Vec<ExplicitOutput>, String> {
	let bad = || "a stored reassignment's outputs do not decode".to_string();
	let mut at = 1;
	let n = *b.first().ok_or_else(bad)? as usize;
	let mut out = Vec::with_capacity(n);
	for _ in 0..n {
		let take = |at: &mut usize, len: usize| -> Result<&[u8], String> {
			let s = b.get(*at..*at + len).ok_or_else(bad)?;
			*at += len;
			Ok(s)
		};
		let asset = AssetId::from_byte_array(take(&mut at, 32)?.try_into().expect("32"));
		let value = u64::from_le_bytes(take(&mut at, 8)?.try_into().expect("8"));
		let len = u16::from_le_bytes(take(&mut at, 2)?.try_into().expect("2")) as usize;
		let spk = elements::Script::from(take(&mut at, len)?.to_vec());
		out.push(ExplicitOutput::new(asset, value, spk));
	}
	if at != b.len() {
		return Err(bad());
	}
	Ok(out)
}
