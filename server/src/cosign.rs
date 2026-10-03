//! Co-signing out-of-round transfers.
//!
//! A sender gives up one or more coins the server knows, by leaf id, each
//! with the value its checkpoint keeps and the owner's two signatures (over
//! the checkpoint and over the reassignment), for one to four new leaves,
//! each named by its owner's key and nonce, an operator nonce the server
//! issued, an exit delay, an asset and a value. The server co-signs only when
//! every rule holds:
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
//!   within that asset's bounds, an exit delay within the bounds, an operator
//!   nonce the server issued and never gave another leaf, a key that owns no
//!   other leaf, a script never seen;
//! - every checkpoint keeps between one atom and the whole coin, the outputs
//!   take no more of any asset than the checkpoints keep, and every owner
//!   signature verifies.
//!
//! Then the transfer is recorded, inputs spent, before `S` signs anything
//! (the signer runs in its own process: [`crate::signer`]). Each new coin's
//! record is checked by the server as a receiver would check it, stored, and
//! posted to the receiver's mailbox. A request repeated byte for byte gets the
//! same answer.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Transaction};

use arca_covenant::sign::verify_digest;
use arca_covenant::transfer::{transfer_id, Transfer, TransferInput, MAX_INPUTS};
use arca_covenant::{CoinRecord, ExplicitOutput, LeafId, MedianTime, NewLeaf, Pair, TransferError, TransferPlan, ValidCoin};

use crate::chain::FinalityService;
use crate::params::Params;
use crate::signer::{SignerClient, SignerError};
use crate::store::{BoardState, LeafKind, LeafState, NewCoin, NewScript, NewTransferInput, NewTransferOutput, ScriptKind, Store, StoreError};

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
	#[error("leaf {leaf}: {what} is on-chain, so its owner could take it under the receiver; the server co-signs no off-chain spend of it")]
	OnChain { leaf: LeafId, what: String },
	#[error("the new coins would be {hops} reassignments from a round or a board; the limit is {limit}: refresh in a round first")]
	DepthLimit { hops: usize, limit: usize },
	#[error("an output is outside the operator's published bounds: {0}")]
	OutOfBounds(String),
	#[error("the values do not add up: {0}")]
	Value(String),
	#[error("input {input}: the owner's {which} signature does not verify")]
	BadSignature { input: usize, which: &'static str },
	#[error("leaf {leaf}'s coin does not check out: {error}")]
	InvalidCoin { leaf: LeafId, error: TransferError },
	#[error("the operator nonce of an output was not issued by this server")]
	NonceUnknown,
	#[error("the operator nonce of an output has already been used")]
	NonceUsed,
	#[error("an output's key already owns a leaf: every leaf has a key of its own")]
	KeyReused,
	#[error("an output's script is already known: a leaf script is never funded twice")]
	ScriptReused,
	#[error("leaf {0} has an open out-of-round reassignment: no release is accepted for it")]
	OpenReassignment(LeafId),
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
			OnChain { .. } => "on_chain",
			DepthLimit { .. } => "depth_limit",
			OutOfBounds(_) => "out_of_bounds",
			Value(_) => "value",
			BadSignature { .. } => "bad_signature",
			InvalidCoin { .. } => "invalid_coin",
			NonceUnknown => "nonce_unknown",
			NonceUsed => "nonce_used",
			KeyReused => "key_reused",
			ScriptReused => "script_reused",
			OpenReassignment(_) => "open_reassignment",
			Signer(_) => "signer_unavailable",
			NotSynced => "not_synced",
			Store(_) | Internal(_) => "internal",
		}
	}
}

impl From<StoreError> for CosignError {
	fn from(e: StoreError) -> CosignError {
		match e {
			StoreError::NonceUnknown => CosignError::NonceUnknown,
			StoreError::NonceUsed => CosignError::NonceUsed,
			StoreError::KeyReused => CosignError::KeyReused,
			StoreError::ScriptReused => CosignError::ScriptReused,
			other => CosignError::Store(other),
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
			e.input(&o.leaf.operator_nonce);
			e.input(&o.leaf.exit_delay.units().to_le_bytes());
			e.input(&o.mailbox.unwrap_or(o.leaf.owner).serialize());
		}
		sha256::Hash::from_engine(e).to_byte_array()
	}
}

/// A coin given up, checked.
struct Checked {
	record: CoinRecord,
	coin: ValidCoin,
	bases: Vec<Transaction>,
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

	/// The transactions a coin record's bases came from: each board's, as
	/// registered. A leaf of a batch rests on its round.
	async fn bases(&self, record: &CoinRecord, out: &mut Vec<Transaction>) -> Result<(), CosignError> {
		match record {
			CoinRecord::Board(b) => {
				let row = self.store.board(&b.leaf_id().0).await?
					.ok_or_else(|| CosignError::Internal(format!("board {} of a known coin is not registered", b.leaf_id())))?;
				let tx: Transaction = elements::encode::deserialize(&row.tx).map_err(|e| CosignError::Internal(e.to_string()))?;
				out.push(tx);
			},
			CoinRecord::Transfer(t) => {
				for i in &t.inputs {
					Box::pin(self.bases(&i.coin, out)).await?;
				}
			},
			CoinRecord::Leaf { .. } => {},
		}
		Ok(())
	}

	/// Checks a coin given up: known, live, its record valid under the
	/// server's policy, its boards credited and unspent, nothing of its
	/// lineage on-chain.
	async fn check_input(&self, id: &LeafId, transfer: &[u8; 32], now: MedianTime) -> Result<Checked, CosignError> {
		let row = self.store.leaf(&id.0).await?.ok_or(CosignError::UnknownLeaf(*id))?;
		match row.state {
			LeafState::Live => {},
			LeafState::Spent if row.spent_by.as_deref() == Some(&transfer[..]) => {},
			LeafState::Spent => return Err(CosignError::DoubleSpend(*id)),
			LeafState::Pending => return Err(CosignError::NotLive(*id, "pending")),
			LeafState::Lost => return Err(CosignError::NotLive(*id, "lost")),
		}
		let record = CoinRecord::from_bytes(&row.record).map_err(|error| CosignError::InvalidCoin { leaf: *id, error })?;
		let mut bases = vec![];
		self.bases(&record, &mut bases).await?;
		let coin = record.resolve(&bases, &self.params.policy(now)).map_err(|error| CosignError::InvalidCoin { leaf: *id, error })?;
		if coin.id != *id {
			return Err(CosignError::Internal(format!("the record of leaf {} gives the id {}", id, coin.id)));
		}
		// Its own leaf and every leaf and checkpoint it descends from.
		let mut scripts = vec![coin.output().script_pubkey.to_bytes()];
		scripts.extend(coin.lineage().iter().map(|o| o.output.script_pubkey.to_bytes()));
		let seen = self.store.sighted(&scripts).await?;
		if seen.contains(&scripts[0]) {
			return Err(CosignError::OnChain { leaf: *id, what: "its own leaf".into() });
		}
		coin.check_lineage(|s| seen.contains(&s.to_bytes()))
			.map_err(|e| CosignError::OnChain { leaf: *id, what: e.to_string() })?;
		// Every board it rests on: credited, and its output unspent.
		for b in coin.boards() {
			let txid = b.txid.to_byte_array();
			let board = self.store.boards_by_txid(&txid).await?.into_iter().find(|r| r.vout == b.vout)
				.ok_or_else(|| CosignError::Internal(format!("board output {} is not registered", b)))?;
			if board.state != BoardState::Credited {
				return Err(CosignError::BoardNotFinal(*id));
			}
			if let Some(by) = self.store.outpoint_spender(&txid, b.vout).await? {
				return Err(CosignError::OnChain {
					leaf: *id,
					what: format!("the board output {} is spent by {}", b, elements::Txid::from_byte_array(by)),
				});
			}
		}
		Ok(Checked { record, coin, bases })
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
			if !keys.insert(o.leaf.owner) {
				return Err(CosignError::KeyReused);
			}
			outputs.push(ExplicitOutput::new(o.asset, o.value, o.leaf.policy(s, chain).script_pubkey()));
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
						operator_nonce: Some(o.leaf.operator_nonce),
						scripts: vec![NewScript { script_pubkey: out.script_pubkey.to_bytes(), kind: ScriptKind::Leaf }],
					},
					mailbox_key: o.mailbox.unwrap_or(o.leaf.owner).serialize(),
				}).collect();
				self.store.record_transfer(&transfer, &ins, &outs).await.map_err(|e| match e {
					StoreError::LeafSpent(id) => CosignError::DoubleSpend(id.parse().unwrap_or(req.inputs[0].leaf_id)),
					StoreError::LeafNotLive(id, state) => CosignError::NotLive(id.parse().unwrap_or(req.inputs[0].leaf_id), state),
					other => other.into(),
				})?;
			},
		}

		// Now S signs, in its own process; each signature is checked against
		// the message the server built.
		let mut sigs = Vec::with_capacity(n);
		for (k, c) in checked.iter().enumerate() {
			let cp_out = plan.checkpoint_output(k);
			let cp = self.signer.rebind(&c.coin.leaf.salt, c.coin.asset, c.coin.value, std::slice::from_ref(&cp_out)).await?;
			let re = self.signer.rebind(&plan.checkpoint(k).salt, c.coin.asset, plan.inputs[k].1, &outputs).await?;
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

fn sig_bytes(s: &Signature) -> [u8; 64] {
	let mut b = [0u8; 64];
	b.copy_from_slice(s.as_ref());
	b
}

fn sig_from(b: &[u8; 64]) -> Result<Signature, CosignError> {
	Signature::from_slice(b).map_err(|e| CosignError::Internal(e.to_string()))
}
