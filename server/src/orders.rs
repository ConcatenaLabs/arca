//! Resting orders in the tree: an `order-2` leaf ([`arca_covenant::order`])
//! that its maker rests and leaves, and that takers fill out of round with
//! the maker offline.
//!
//! **Resting.** A maker asks a round for an `order-2` leaf as for any leaf
//! (a participation whose wanted leaf names the template and carries the
//! order's terms; [`crate::participations`] checks them), completes the
//! participation, then publishes the order ([`Orders::publish`]): the coin's
//! record as it holds it (with its entry's preimage and its own unroll
//! authorisations, which every coin a fill makes carries in its lineage, so
//! a taker can bring its coin on the chain alone), the nonces its four
//! credit keys come from, and its mailbox, signed by the order's leaf key.
//! The maker can then stop its process.
//!
//! **A fill.** A taker gives up coins of the asset the order is paid in, each
//! through a checkpoint as in a transfer, for a leaf of what it fills and its
//! change ([`Orders::fill`]). The fill spends the order's coin by its fill
//! path under the operator's signature over its outputs, which the program
//! enforces: the maker's credit at output 0, for a partial fill the order
//! resting again at output 1, then the taker's leaves. The operator co-signs
//! one only when:
//!
//! - the order coin is the coin the order rests at now, live, its lineage off
//!   the chain and its first expiry past its exit deadline
//!   ([`crate::coins::check`]), and the signer holds nothing under its salt
//!   (no other fill, no cancel, no forfeit);
//! - it is before the order's REFUND time less the order margin;
//! - each taker coin passes the same checks as a transfer's input, is of the
//!   asset the order is paid in, and expires no earlier than the order coin,
//!   so every coin of the fill ages with the order's lineage and no batch a
//!   taker's coin rests on is swept while the order's lineage needs it;
//! - the coins it makes are within the depth limit (an order fills at most
//!   four times along one lineage, which its credit keys hold in consensus
//!   too);
//! - the fill holds by the program's rules (`OrderPolicy::plan`, then
//!   `judge` by the signer itself), the taker's leaves are within the
//!   published bounds, and every owner signature verifies; the fill's margin
//!   (what the checkpoints keep beyond the outputs, in the asset paid) pays
//!   its fee as a transfer's does.
//!
//! The fill is recorded (a transfer of the taker's coins, the order coin spent
//! by it, its row and the request) before anything is signed; the signer co-signs each
//! taker coin's checkpoint and the fill's reassignment pair, and the fill
//! itself, recorded as the one spend under the order coin's salt. Each coin it
//! makes has a `CoinRecord::Fill`, checked as its receiver checks it: the
//! taker's leaves go to the taker's mailbox, the credit and the remainder to
//! the maker's, and the order then rests at the remainder. A fill whose call
//! ends before the signer has signed all of it (the server stopped, the
//! signer gone after the taker's pairs) is completed by the server from the
//! request it kept, at start and every minute ([`Orders::finish_unsigned`]),
//! as it is when its taker sends it again.
//!
//! **Cancel.** The maker gives up the order coin as any coin, by its
//! collaborative path: a transfer into a leaf of its own (or a forfeit in a
//! refresh). The signer's one spend per salt keeps a cancel and a fill of one
//! coin apart.
//!
//! **The state view** ([`Orders::state`]) says, per order, where it rests,
//! what it has filled and what is left, and the terms a taker builds a fill
//! from; anyone may read it. A fill recorded and not yet signed is not a
//! fill: the order reads `filling` until it is signed or dropped, and the
//! fill is listed with `signed` false.

use std::collections::HashSet;
use std::sync::Arc;

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Transaction};

use arca_covenant::order::OrderPolicy;
use arca_covenant::sign::verify_digest;
use arca_covenant::spend::margin_for;
use arca_covenant::transfer::{fill_hash, FillCoin, FillLeaf, OrderFill, SeenReassignments, TransferInput, MAX_INPUTS};
use arca_covenant::{CoinRecord, ExplicitOutput, LeafId, MedianTime, Pair, TransferPlan, ValidCoin, ValidInput, WalletPolicy};

use crate::chain::FinalityService;
use crate::coins::{self, BoardDates, Checked, CoinError};
use crate::cosign::{self, CosignError, InputRequest, OutputRequest};
use crate::fees;
use crate::params::Params;
use crate::signer::{hex, SignerClient, SignerError};
use crate::store::{
	LeafKind, LeafState, NewCoin, NewOrderFill, NewReassignment, NewScript, NewTransferInput, NewTransferOutput, OrderFillRow,
	RestingOrderRow, ScriptKind, SignerMessage, Store, StoreError,
};

pub use arca_covenant::order::{publish_digest, PUBLISH_TAG};

/// The tag of a fill request's hash, which is its transfer's id.
pub const FILL_REQUEST_TAG: &[u8] = b"Arca/order-fill-request";

/// A maker's publication of its order.
#[derive(Debug, Clone)]
pub struct PublishRequest {
	/// The record of the coin a round made of the order.
	pub record: CoinRecord,
	pub credit_nonces: [[u8; 32]; 4],
	pub mailbox: XOnlyPublicKey,
	/// The order's leaf key's signature over [`publish_digest`].
	pub signature: Signature,
}

/// A taker's fill of a resting order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FillRequest {
	pub order: LeafId,
	/// The coin it rests at, as the taker read it.
	pub coin: LeafId,
	pub filled: u64,
	/// The taker's coins, each with its checkpoint's value and its owner's
	/// signatures over the checkpoint and over the fill's outputs.
	pub inputs: Vec<InputRequest>,
	/// The taker's leaves: first the one of what it fills, then its change.
	pub outputs: Vec<OutputRequest>,
}

impl FillRequest {
	/// The request's hash, the fill's transfer id.
	pub fn hash(&self) -> [u8; 32] {
		let mut e = sha256::Hash::engine();
		e.input(FILL_REQUEST_TAG);
		e.input(&self.order.0);
		e.input(&self.coin.0);
		e.input(&self.filled.to_le_bytes());
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
			e.input(&o.until.unwrap_or(0).to_le_bytes());
		}
		sha256::Hash::from_engine(e).to_byte_array()
	}

	/// The request in the form the server keeps it with its fill, so that a
	/// fill the signer left half done is completed from it
	/// ([`Orders::finish_unsigned`]): a version byte (1), the order, the
	/// coin and the amount filled, then each taker coin (its id, its
	/// checkpoint's value and its owner's two signatures) and each taker leaf
	/// (asset, value, owner, owner nonce, creator nonce, exit delay units,
	/// its mailbox and lapse when named), integers little-endian. A taker
	/// leaf of a fill is `vtxo-1`, so no `htlc-1` terms are kept.
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut b = vec![1u8];
		b.extend_from_slice(&self.order.0);
		b.extend_from_slice(&self.coin.0);
		b.extend_from_slice(&self.filled.to_le_bytes());
		b.push(self.inputs.len() as u8);
		for i in &self.inputs {
			b.extend_from_slice(&i.leaf_id.0);
			b.extend_from_slice(&i.checkpoint_value.to_le_bytes());
			b.extend_from_slice(i.checkpoint_sig.as_ref());
			b.extend_from_slice(i.reassignment_sig.as_ref());
		}
		b.push(self.outputs.len() as u8);
		for o in &self.outputs {
			b.extend_from_slice(&o.asset.into_inner().to_byte_array());
			b.extend_from_slice(&o.value.to_le_bytes());
			b.extend_from_slice(&o.leaf.owner.serialize());
			b.extend_from_slice(&o.leaf.owner_nonce);
			b.extend_from_slice(&o.leaf.creator_nonce);
			b.extend_from_slice(&o.leaf.exit_delay.units().to_le_bytes());
			match o.mailbox {
				Some(m) => {
					b.push(1);
					b.extend_from_slice(&m.serialize());
				},
				None => b.push(0),
			}
			match o.until {
				Some(u) => {
					b.push(1);
					b.extend_from_slice(&u.to_le_bytes());
				},
				None => b.push(0),
			}
		}
		b
	}

	/// The request [`FillRequest::to_bytes`] kept.
	pub fn from_bytes(b: &[u8]) -> Result<FillRequest, String> {
		let mut at = 0usize;
		let mut take = |n: usize| -> Result<&[u8], String> {
			let s = b.get(at..at + n).ok_or_else(|| "a fill request cut short".to_string())?;
			at += n;
			Ok(s)
		};
		let a32 = |s: &[u8]| -> [u8; 32] { s.try_into().expect("32 bytes") };
		let u64_of = |s: &[u8]| u64::from_le_bytes(s.try_into().expect("8 bytes"));
		if take(1)?[0] != 1 {
			return Err("a fill request of an unknown version".into());
		}
		let order = LeafId(a32(take(32)?));
		let coin = LeafId(a32(take(32)?));
		let filled = u64_of(take(8)?);
		let n = take(1)?[0] as usize;
		let mut inputs = Vec::with_capacity(n);
		for _ in 0..n {
			let leaf_id = LeafId(a32(take(32)?));
			let checkpoint_value = u64_of(take(8)?);
			let checkpoint_sig = Signature::from_slice(take(64)?).map_err(|e| e.to_string())?;
			let reassignment_sig = Signature::from_slice(take(64)?).map_err(|e| e.to_string())?;
			inputs.push(InputRequest { leaf_id, checkpoint_value, checkpoint_sig, reassignment_sig });
		}
		let m = take(1)?[0] as usize;
		let mut outputs = Vec::with_capacity(m);
		for _ in 0..m {
			let asset = AssetId::from_slice(take(32)?).map_err(|e| e.to_string())?;
			let value = u64_of(take(8)?);
			let owner = XOnlyPublicKey::from_slice(take(32)?).map_err(|e| e.to_string())?;
			let owner_nonce = a32(take(32)?);
			let creator_nonce = a32(take(32)?);
			let units = u16::from_le_bytes(take(2)?.try_into().expect("2 bytes"));
			let exit_delay = arca_covenant::RelativeTime::from_units(units).map_err(|e| e.to_string())?;
			let mailbox = match take(1)?[0] {
				0 => None,
				_ => Some(XOnlyPublicKey::from_slice(take(32)?).map_err(|e| e.to_string())?),
			};
			let until = match take(1)?[0] {
				0 => None,
				_ => Some(u32::from_le_bytes(take(4)?.try_into().expect("4 bytes"))),
			};
			outputs.push(OutputRequest {
				asset, value, leaf: arca_covenant::NewLeaf { owner, owner_nonce, creator_nonce, exit_delay, htlc: None, landing: None, v2: false },
				mailbox, until,
			});
		}
		if at != b.len() {
			return Err("a fill request with bytes after its end".into());
		}
		Ok(FillRequest { order, coin, filled, inputs, outputs })
	}
}

/// What the operator answers for a fill it co-signed.
#[derive(Debug, Clone)]
pub struct Filled {
	pub transfer_id: [u8; 32],
	/// The operator's fill signature.
	pub fill_signature: Signature,
	/// The operator's signatures for each taker coin: over its checkpoint,
	/// and over the fill's outputs.
	pub signatures: Vec<(Signature, Signature)>,
	/// Each coin the fill makes, in output order: its id and its record.
	pub outputs: Vec<(LeafId, CoinRecord)>,
	/// The entry of the signer's record the fill's last signature was
	/// recorded as, signed.
	pub signer_head: Option<crate::store::RecordHeadRow>,
}

/// An order as the state view shows it.
#[derive(Debug, Clone)]
pub struct OrderView {
	pub order: RestingOrderRow,
	/// The policy of the coin it rests at now.
	pub policy: OrderPolicy,
	/// That coin's value, and its state.
	pub value: u64,
	pub coin_state: LeafState,
	pub fills: Vec<OrderFillRow>,
	/// The earliest first expiry of the batches the coin rests on.
	pub expiry: Option<u32>,
	/// Whether a spend of the coin other than a fill (a cancel, a forfeit)
	/// is recorded.
	pub given_up: bool,
	/// Whether a fill of the coin is recorded and not yet signed: it is
	/// either signed (the order then rests at its remainder, or is filled
	/// whole) or dropped (the order rests where it was).
	pub filling: bool,
	/// Whether the coin it rests at, live, is on the chain: brought there to
	/// land, by its maker or by the operator at its exit deadline.
	pub landed: bool,
}

impl OrderView {
	/// `resting`, `filling`, `filled`, `cancelled`, `exhausted`, `landed`,
	/// `pending` or `unknown`. `filled` is said only of a fill the operator
	/// signed.
	pub fn state(&self) -> &'static str {
		match self.coin_state {
			LeafState::Live if self.landed => "landed",
			LeafState::Live if self.policy.fills_left() == 0 => "exhausted",
			LeafState::Live => "resting",
			LeafState::Spent if self.given_up => "cancelled",
			LeafState::Spent if self.filling => "filling",
			LeafState::Spent => "filled",
			LeafState::Pending => "pending",
			_ => "unknown",
		}
	}
}

/// Why an order could not be published or filled.
#[derive(Debug, thiserror::Error)]
pub enum OrderError {
	#[error("the request is malformed: {0}")]
	Malformed(String),
	#[error("no resting order {0} is published here")]
	UnknownOrder(String),
	#[error("{0}")]
	NotAnOrder(String),
	#[error("{0}")]
	Moved(String),
	#[error("{0}")]
	Terms(String),
	#[error(transparent)]
	Cosign(#[from] CosignError),
	#[error("the server has not followed the chain yet")]
	NotSynced,
	#[error("{0}")]
	Internal(String),
}

impl OrderError {
	pub fn code(&self) -> &'static str {
		match self {
			OrderError::Malformed(_) => "malformed",
			OrderError::UnknownOrder(_) => "unknown_order",
			OrderError::NotAnOrder(_) => "not_an_order",
			OrderError::Moved(_) => "order_moved",
			OrderError::Terms(_) => "order",
			OrderError::Cosign(e) => e.code(),
			OrderError::NotSynced => "not_synced",
			OrderError::Internal(_) => "internal",
		}
	}
}

impl From<StoreError> for OrderError {
	fn from(e: StoreError) -> OrderError {
		OrderError::Cosign(e.into())
	}
}

impl From<CoinError> for OrderError {
	fn from(e: CoinError) -> OrderError {
		OrderError::Cosign(e.into())
	}
}

impl From<SignerError> for OrderError {
	fn from(e: SignerError) -> OrderError {
		OrderError::Cosign(e.into())
	}
}

fn internal<E: std::fmt::Display>(e: E) -> OrderError {
	OrderError::Internal(e.to_string())
}

/// See the [module documentation](self).
pub struct Orders {
	store: Store,
	finality: Arc<FinalityService>,
	params: Arc<Params>,
	signer: SignerClient,
}

impl Orders {
	pub fn new(store: Store, finality: Arc<FinalityService>, params: Arc<Params>, signer: SignerClient) -> Arc<Orders> {
		Arc::new(Orders { store, finality, params, signer })
	}

	async fn now(&self) -> Result<MedianTime, OrderError> {
		let tip = self.store.tip_block().await?.ok_or(OrderError::NotSynced)?;
		MedianTime::from_consensus(tip.median_time as u32).map_err(internal)
	}

	/// Publishes a resting order: see the [module documentation](self). The
	/// same publication again gets the order's state.
	pub async fn publish(&self, req: &PublishRequest) -> Result<OrderView, OrderError> {
		let CoinRecord::Leaf { record, .. } = &req.record else {
			return Err(OrderError::NotAnOrder("a resting order is published by the record of the coin a round made of it".into()));
		};
		if record.order.is_none() {
			return Err(OrderError::NotAnOrder(format!("the coin's template is {}, not order-2", record.template)));
		}
		let id = record.leaf_id().map_err(|e| OrderError::Malformed(e.to_string()))?;
		if self.store.resting_order(&id.0).await?.is_some() {
			return self.view(&id).await?.ok_or_else(|| internal("a published order is gone"));
		}
		let p = &self.params;
		let digest = publish_digest(&p.chain, &p.operator, &id, &req.credit_nonces, &req.mailbox);
		if !verify_digest(&req.signature, &digest, &record.owner) {
			return Err(OrderError::Malformed("the publication is not signed by the order's leaf key".into()));
		}
		let now = self.now().await?;
		// The coin the round made, live, as the server holds it; and the
		// maker's record of it, with its preimage and authorisations, valid
		// under the server's policy and naming the same coin.
		let checked = coins::check(&self.store, &p.policy(now), &id, &[0; 32], BoardDates::Within(WalletPolicy::EXIT_DEADLINE)).await?;
		let coin = req.record.resolve(&checked.bases, &p.policy(now))
			.map_err(|e| OrderError::Cosign(CosignError::InvalidCoin { leaf: id, error: e }))?;
		if coin.id != id || coin.output() != checked.coin.output() {
			return Err(OrderError::NotAnOrder("the record published is not the record of the coin the server holds".into()));
		}
		let bytes = req.record.to_bytes().map_err(internal)?;
		self.store.insert_resting_order(&id.0, &record.owner.serialize(), &req.mailbox.serialize(), &bytes, &req.credit_nonces).await?;
		log::info!("resting order {} published, {} of {} resting", id, coin.value, coin.asset);
		self.view(&id).await?.ok_or_else(|| internal("a published order is gone"))
	}

	/// The order whose first coin is `id`, as the state view shows it.
	pub async fn view(&self, id: &LeafId) -> Result<Option<OrderView>, OrderError> {
		let Some(order) = self.store.resting_order(&id.0).await? else { return Ok(None) };
		let row = self.store.leaf(&order.current_leaf).await?.ok_or_else(|| internal("an order's coin is not known"))?;
		let record = CoinRecord::from_bytes(&row.record).map_err(internal)?;
		let policy = record.order_policy().ok_or_else(|| internal("an order's coin is not an order"))?;
		let fills = self.store.order_fills(&id.0).await?;
		let whole = fills.iter().any(|f| f.order_leaf == order.current_leaf);
		let filling = fills.iter().any(|f| f.order_leaf == order.current_leaf && f.signature.is_none());
		let landed = row.state == LeafState::Live && !self.store.sightings_of(&row.script_pubkey).await?.is_empty();
		Ok(Some(OrderView {
			value: row.value, coin_state: row.state, expiry: cosign::first_expiry(&record),
			given_up: row.state == LeafState::Spent && !whole, filling, landed,
			order, policy, fills,
		}))
	}

	/// The views of `ids`; an order not published is left out.
	pub async fn state(&self, ids: &[LeafId]) -> Result<Vec<OrderView>, OrderError> {
		let mut out = vec![];
		for id in ids {
			if let Some(v) = self.view(id).await? {
				out.push(v);
			}
		}
		Ok(out)
	}

	/// The answer to a fill already signed.
	async fn answer(&self, transfer: &[u8; 32], fill: &OrderFillRow) -> Result<Filled, OrderError> {
		let t = self.store.transfer(transfer).await?.ok_or_else(|| internal("a signed fill's transfer is gone"))?;
		let sig = fill.signature.ok_or_else(|| internal("a fill answered before it was signed"))?;
		let mut signatures = vec![];
		for (_, _, s) in &t.inputs {
			let (cp, re) = s.ok_or_else(|| internal("a signed fill's taker input is not signed"))?;
			signatures.push((Signature::from_slice(&cp).map_err(internal)?, Signature::from_slice(&re).map_err(internal)?));
		}
		let mut outputs = vec![];
		for (leaf, _) in &t.outputs {
			let row = self.store.leaf(leaf).await?.ok_or_else(|| internal("a fill's coin is gone"))?;
			outputs.push((LeafId(*leaf), CoinRecord::from_bytes(&row.record).map_err(internal)?));
		}
		Ok(Filled {
			transfer_id: *transfer, fill_signature: Signature::from_slice(&sig).map_err(internal)?, signatures, outputs,
			signer_head: t.signer_head,
		})
	}

	/// Completes every fill recorded and not signed whose request the server
	/// kept: one whose call ended before the signer's answer to the fill
	/// itself (the server stopped, or the signer went away after it signed
	/// the taker's pairs). Each is co-signed as [`Orders::fill`] co-signs a
	/// fill sent again, judged as it was when recorded; its coins are posted
	/// to their mailboxes, and the order rests at its remainder. The taker
	/// signed its pairs over exactly these outputs, so completing the fill
	/// takes nothing from anyone, and the order's coin is no longer held
	/// until its taker comes back. A fill the signer refuses (its record
	/// holds another spend of a coin) is dropped there, its coins live
	/// again; one that fails otherwise stays recorded, and is tried again
	/// at the next pass. Returns how many were completed.
	pub async fn finish_unsigned(&self) -> Result<usize, OrderError> {
		let mut done = 0;
		for (transfer, request) in self.store.unsigned_order_fills().await? {
			let Some(bytes) = request else {
				log::info!("fill {} is recorded and not signed, and was recorded with no request kept: it waits for its taker", hex(&transfer));
				continue;
			};
			let req = match FillRequest::from_bytes(&bytes) {
				Ok(r) if r.hash() == transfer => r,
				Ok(_) => {
					log::error!("fill {}: the request kept with it is not the fill's", hex(&transfer));
					continue;
				},
				Err(e) => {
					log::error!("fill {}: the request kept with it does not read: {}", hex(&transfer), e);
					continue;
				},
			};
			match self.fill(&req).await {
				Ok(_) => {
					done += 1;
					log::info!("fill {} of order {}, left unsigned, completed by the server", hex(&transfer), req.order);
				},
				Err(e) => log::warn!("fill {} of order {} stays unsigned for now: {}", hex(&transfer), req.order, e),
			}
		}
		Ok(done)
	}

	/// The least margin of a transaction of `vsize` vbytes in `asset`: four
	/// times the node's floor where it takes the asset for fees now, one atom
	/// where it does not.
	async fn least_margin(&self, asset: AssetId, vsize: usize) -> Result<u64, OrderError> {
		match fees::floor_per_kvb(&self.finality, asset).await.map_err(internal)? {
			Some(f) => Ok(margin_for(vsize, f, fees::MULTIPLE).max(1)),
			None => Ok(1),
		}
	}

	/// Co-signs a fill: see the [module documentation](self).
	pub async fn fill(&self, req: &FillRequest) -> Result<Filled, OrderError> {
		let n = req.inputs.len();
		if n == 0 || n > MAX_INPUTS {
			return Err(OrderError::Malformed(format!("{} taker coins; a fill takes 1 to {}", n, MAX_INPUTS)));
		}
		if req.outputs.is_empty() || req.outputs.len() > 2 {
			return Err(OrderError::Malformed(format!("{} taker leaves; a fill makes the taker's leaf and at most its change",
				req.outputs.len())));
		}
		let ids: HashSet<LeafId> = req.inputs.iter().map(|i| i.leaf_id).collect();
		if ids.len() != n || ids.contains(&req.coin) {
			return Err(OrderError::Malformed("a coin is given twice".into()));
		}
		let transfer = req.hash();
		if let Some(f) = self.store.order_fill_by_transfer(&transfer).await? {
			if f.signature.is_some() {
				return self.answer(&transfer, &f).await;
			}
		}
		// A coin whose holder is frozen is refused before anything else.
		let given: Vec<LeafId> = req.inputs.iter().map(|i| i.leaf_id).collect();
		crate::supervision::gate(&self.store, &self.finality, &self.params, &given).await.map_err(CosignError::from)?;
		let order = self.store.resting_order(&req.order.0).await?.ok_or_else(|| OrderError::UnknownOrder(req.order.to_string()))?;
		let recorded = self.store.order_fill_by_transfer(&transfer).await?.is_some();
		if !recorded && order.current_leaf != req.coin.0 {
			return Err(OrderError::Moved(format!("order {} rests at coin {} now, not {}: fill the coin it rests at",
				req.order, LeafId(order.current_leaf), req.coin)));
		}
		let now = self.now().await?;
		let p = &self.params;
		let s = p.operator;
		let policy = p.policy(now);
		let dates = BoardDates::WithinUnlessRecorded(WalletPolicy::EXIT_DEADLINE);

		// The order coin.
		let oc = coins::check(&self.store, &policy, &req.coin, &transfer, dates).await?;
		let op = oc.coin.leaf.order_policy().ok_or_else(|| OrderError::NotAnOrder(format!("coin {} is not a resting order's", req.coin)))?;
		let t = op.terms();
		let refund_time = op.landed.expiry;
		if !recorded && now.to_consensus_u32().saturating_add(p.order_margin_seconds) >= refund_time {
			return Err(OrderError::Terms(format!("order {} can be refunded from median time {} once it lands, within the operator's \
				order margin of {} s: the operator co-signs no fill of it from now", req.order, refund_time, p.order_margin_seconds)));
		}
		let plan = op.plan(oc.coin.value, req.filled).map_err(|e| OrderError::Terms(format!("order {}: {}", req.order, e)))?;
		let price = plan.credit.value;

		// The taker's leaves: what it fills, in the asset the order sells,
		// then its change, in the asset it pays.
		let mut outputs = vec![plan.credit.clone()];
		if let Some(r) = &plan.rest {
			outputs.push(r.clone());
		}
		let mut keys = HashSet::new();
		for (j, o) in req.outputs.iter().enumerate() {
			let want = if j == 0 { t.asset_a } else { t.asset_b };
			if o.asset != want || (j == 0 && o.value != req.filled) {
				return Err(OrderError::Terms(format!("the taker's leaf {} holds {} of {}; a fill's first taker leaf holds what it fills \
					({} of {}), and the second the change in {}", j, o.value, o.asset, req.filled, t.asset_a, t.asset_b)));
			}
			if o.leaf.htlc.is_some() {
				return Err(OrderError::Malformed("a taker's leaf from a fill is vtxo-1".into()));
			}
			if let Some(until) = o.until {
				if !recorded && now.to_consensus_u32() >= until {
					return Err(OrderError::Cosign(CosignError::RequestLapsed { output: j, until, now: now.to_consensus_u32() }));
				}
			}
			if !p.exit_delay_ok(o.leaf.exit_delay) {
				return Err(OrderError::Cosign(CosignError::OutOfBounds(format!("an exit delay of {} units; the operator takes {} to {}",
					o.leaf.exit_delay.units(), p.min_exit_delay.units(), p.max_exit_delay.units()))));
			}
			p.check_value(o.asset, o.value).map_err(|e| OrderError::Cosign(CosignError::OutOfBounds(e)))?;
			if o.leaf.owner == s {
				return Err(OrderError::Cosign(CosignError::OperatorKey));
			}
			if !keys.insert(o.leaf.owner) {
				return Err(OrderError::Cosign(CosignError::KeyReused));
			}
			outputs.push(ExplicitOutput::new(o.asset, o.value, o.leaf.policy(s, p.chain).script_pubkey()));
		}
		let m = outputs.len();
		if !(2..=arca_covenant::order::MAX_FILL_OUTPUTS as usize).contains(&m) {
			return Err(OrderError::Malformed(format!("a fill of {} outputs; it commits to 2 to 4", m)));
		}
		let salts: Vec<[u8; 32]> = req.outputs.iter().map(|o| o.leaf.salt()).collect();
		if !recorded {
			if let Some(known) = self.store.known_salts(&salts).await?.first() {
				return Err(OrderError::Cosign(CosignError::SaltReused(hex(known))));
			}
		}

		// The taker's coins, each checked as a transfer's input, of the asset
		// the order is paid in, expiring no earlier than the order coin.
		let mut checked: Vec<Checked> = Vec::with_capacity(n);
		for i in &req.inputs {
			let c = coins::check(&self.store, &policy, &i.leaf_id, &transfer, dates).await?;
			if c.coin.asset != t.asset_b {
				return Err(OrderError::Terms(format!("coin {} is of asset {}; a fill of this order is paid in {}", i.leaf_id, c.coin.asset,
					t.asset_b)));
			}
			if c.expiry().to_consensus_u32() < oc.expiry().to_consensus_u32() {
				return Err(OrderError::Terms(format!("coin {} expires at median time {}, before the order's coin ({}): a fill is paid with \
					coins that expire no earlier than the order, so every coin it makes ages with the order; refresh it first", i.leaf_id,
					c.expiry().to_consensus_u32(), oc.expiry().to_consensus_u32())));
			}
			checked.push(c);
		}
		let hops = 1 + checked.iter().map(|c| c.coin.hops).chain(std::iter::once(oc.coin.hops)).max().expect("the order");
		if hops > p.depth_limit {
			return Err(OrderError::Cosign(CosignError::DepthLimit { hops, limit: p.depth_limit }));
		}

		// The values: the checkpoints keep at least what the outputs take in
		// the asset paid, and what is left is the fill's margin.
		let kept: u64 = req.inputs.iter().map(|i| i.checkpoint_value).sum();
		for (i, c) in req.inputs.iter().zip(&checked) {
			if i.checkpoint_value == 0 || i.checkpoint_value > c.coin.value {
				return Err(OrderError::Cosign(CosignError::Value(format!("a checkpoint keeps {} of a coin of {}", i.checkpoint_value,
					c.coin.value))));
			}
		}
		let paid: u64 = outputs.iter().filter(|o| o.asset == t.asset_b).map(|o| o.value).sum();
		if paid > kept {
			return Err(OrderError::Cosign(CosignError::Value(format!("the fill pays {} of asset {}; the checkpoints keep {}", paid,
				t.asset_b, kept))));
		}
		let dummy = Signature::from_slice(&[1; 64]).expect("64 bytes");
		let pair = Pair { operator: dummy, owner: dummy };
		let sized: Vec<ValidInput> = checked.iter().zip(&req.inputs).map(|(c, i)| ValidInput {
			coin: c.coin.clone(), checkpoint: c.coin.checkpoint(), checkpoint_value: i.checkpoint_value, checkpoint_pair: pair,
			reassignment_pair: pair,
		}).collect();
		if !recorded {
			let at = elements::OutPoint::default();
			let u = arca_covenant::transfer::fill_tx(&oc.coin, &dummy, plan.rest.is_some(), &sized, &outputs, at, &vec![at; n],
				&arca_covenant::spend::FeeSource::Reserve).map_err(|e| OrderError::Cosign(CosignError::Margin(e.to_string())))?;
			let least = self.least_margin(t.asset_b, u.tx.vsize()).await?;
			let margin = kept - paid;
			if margin < least || margin > least.saturating_mul(p.max_margin_multiple) {
				return Err(OrderError::Cosign(CosignError::Margin(format!("the fill leaves a margin of {} of asset {}; it pays its fee \
					from {} to {}", margin, t.asset_b, least, least.saturating_mul(p.max_margin_multiple)))));
			}
			for (k, v) in sized.iter().enumerate() {
				let u = v.checkpoint_tx(at, &arca_covenant::spend::FeeSource::Reserve)
					.map_err(|e| OrderError::Cosign(CosignError::Margin(e.to_string())))?;
				let least = self.least_margin(v.coin.asset, u.tx.vsize()).await?;
				let margin = v.coin.value - v.checkpoint_value;
				if margin < least || margin > least.saturating_mul(p.max_margin_multiple) {
					return Err(OrderError::Cosign(CosignError::Margin(format!("taker coin {}'s checkpoint leaves a margin of {}; it pays \
						its fee from {} to {}", k, margin, least, least.saturating_mul(p.max_margin_multiple)))));
				}
			}
		}

		// The taker's signatures.
		let tplan = TransferPlan {
			inputs: checked.iter().zip(&req.inputs).map(|(c, i)| (c.coin.clone(), i.checkpoint_value)).collect(),
			outputs: outputs.clone(),
		};
		let mut messages = Vec::with_capacity(n);
		for (k, (c, i)) in checked.iter().zip(&req.inputs).enumerate() {
			let cp = tplan.checkpoint_message(k).map_err(internal)?.digest;
			let re = tplan.reassignment_message(k).map_err(internal)?.digest;
			if !verify_digest(&i.checkpoint_sig, &cp, &c.coin.leaf.owner) {
				return Err(OrderError::Cosign(CosignError::BadSignature { input: k, which: "checkpoint" }));
			}
			if !verify_digest(&i.reassignment_sig, &re, &c.coin.leaf.owner) {
				return Err(OrderError::Cosign(CosignError::BadSignature { input: k, which: "reassignment" }));
			}
			messages.push((cp, re));
		}
		let txouts: Vec<_> = outputs.iter().map(|o| o.txout()).collect();
		let fill_digest = op.fill_digest(oc.coin.value, &txouts).map_err(internal)?;

		// The new coins' ids.
		let parts: Vec<(LeafId, [u8; 32])> = checked.iter().map(|c| (c.coin.id, c.coin.checkpoint().taproot().program())).collect();
		let hash = fill_hash((oc.coin.id, oc.coin.leaf.program()), &parts, &outputs);
		let credit_leaf = op.credit_leaf().expect("the plan holds a credit key");
		let rest_leaf = op.next().leaf();
		let mut leaves = vec![credit_leaf];
		if plan.rest.is_some() {
			leaves.push(rest_leaf);
		}
		leaves.extend(req.outputs.iter().map(|o| o.leaf.policy(s, p.chain)));
		let new_ids: Vec<LeafId> = leaves.iter().enumerate().map(|(j, l)| LeafId::compute(&hash, &[j as u8], &l.program())).collect();
		// The fill's place along the order's lineage: its own row's when it is
		// recorded already, the next otherwise.
		let seq = match self.store.order_fill_by_transfer(&transfer).await? {
			Some(f) => f.seq,
			None => self.store.order_fills(&order.order_id).await?.len() as u32,
		};
		if seq >= 4 {
			return Err(OrderError::Terms(format!("order {} has filled {} times; an order fills at most four times", req.order, seq)));
		}
		let maker_nonce = match CoinRecord::from_bytes(&order.record).map_err(internal)? {
			CoinRecord::Leaf { record, .. } => record.owner_nonce,
			_ => return Err(internal("a resting order's first record is not a round's leaf")),
		};

		if !recorded {
			let ins: Vec<NewTransferInput> = req.inputs.iter().enumerate().map(|(k, i)| NewTransferInput {
				leaf_id: i.leaf_id.0, checkpoint_value: i.checkpoint_value, checkpoint_owner_sig: cosign::sig_bytes(&i.checkpoint_sig),
				reassignment_owner_sig: cosign::sig_bytes(&i.reassignment_sig), checkpoint_script: tplan.checkpoint(k).script_pubkey().to_bytes(),
			}).collect();
			let until = std::iter::once(&oc).chain(&checked).filter_map(|c| cosign::first_expiry(&c.record)).min();
			let mut outs = Vec::with_capacity(m);
			for (j, (out, id)) in outputs.iter().zip(&new_ids).enumerate() {
				let (owner, nonce, mailbox, salt, rest) = match j {
					0 => (credit_leaf.owner, order.credit_nonces[seq as usize], order.mailbox_key, credit_leaf.salt, true),
					1 if plan.rest.is_some() => (op.owner, maker_nonce, order.mailbox_key, rest_leaf.salt, true),
					_ => {
						let o = &req.outputs[j + req.outputs.len() - m];
						(o.leaf.owner, o.leaf.owner_nonce, o.mailbox.unwrap_or(o.leaf.owner).serialize(), o.leaf.salt(), false)
					},
				};
				outs.push(NewTransferOutput {
					coin: NewCoin {
						leaf_id: id.0, kind: LeafKind::Transfer, asset: out.asset.into_inner().to_byte_array(), value: out.value,
						owner_key: owner.serialize(), script_pubkey: out.script_pubkey.to_bytes(), hops: hops as u16, record: vec![],
						state: LeafState::Pending, salt, promised_to: None, operator_nonce: None,
						scripts: vec![NewScript { script_pubkey: out.script_pubkey.to_bytes(), kind: ScriptKind::Leaf }],
						maker_coin: rest,
					},
					mailbox_key: mailbox,
					notice: serde_json::to_vec(&crate::api::MailboxNotice {
						transfer_id: hex(&transfer), leaf_id: id.to_string(), asset: Some(out.asset.to_string()),
						value: Some(out.value.to_string()), owner: Some(hex(&owner.serialize())), owner_nonce: Some(hex(&nonce)), until,
						reason: None,
					}).expect("a notice"),
				});
			}
			let spent: Vec<(LeafId, u64)> = tplan.inputs.iter().map(|(c, v)| (c.id, *v)).collect();
			let reassignment = NewReassignment {
				first_output: arca_covenant::script::sha256(&outputs[0].record()),
				inputs: cosign::encode_inputs(&spent),
				outputs: cosign::encode_outputs(&outputs),
			};
			let admit = |seen: &[(Vec<u8>, Vec<u8>)]| -> Result<(), String> {
				let mut known = SeenReassignments::new();
				for (i, o) in seen {
					known.admit(&cosign::decode_inputs(i)?, &cosign::decode_outputs(o)?).map_err(|e| e.to_string())?;
				}
				tplan.admit(&mut known).map_err(|e| e.to_string())
			};
			let mut signer_messages = vec![SignerMessage { owner: op.owner.serialize(), salt: op.salt, digest: fill_digest, forfeit: false }];
			for (k, c) in checked.iter().enumerate() {
				let cp = tplan.checkpoint(k);
				signer_messages.push(SignerMessage { owner: c.coin.leaf.owner.serialize(), salt: c.coin.leaf.salt, digest: messages[k].0,
					forfeit: false });
				signer_messages.push(SignerMessage { owner: cp.owner.serialize(), salt: cp.salt, digest: messages[k].1, forfeit: false });
			}
			let new_fill = NewOrderFill {
				order_id: order.order_id, order_leaf: req.coin.0, seq, filled: req.filled, credited: price, partial: plan.rest.is_some(),
				m: m as u8, request: req.to_bytes(),
			};
			self.store.record_order_fill(&transfer, &reassignment, admit, &ins, &outs, &signer_messages, &new_fill).await
				.map_err(|e| match e {
					StoreError::LeafSpent(id) => OrderError::Cosign(CosignError::DoubleSpend(id.parse().unwrap_or(req.coin))),
					other => other.into(),
				})?;
		}

		// Nothing is signed while the signer holds anything else under the
		// order coin's salt or a taker coin's.
		for e in self.signer.under(&op.salt).await? {
			if e.digest != fill_digest {
				let _ = self.store.drop_order_fill(&transfer, "the signer holds another spend of the order's coin").await;
				return Err(OrderError::Cosign(CosignError::Signer(SignerError::AlreadySigned(format!("{}: the order's coin {} has \
					another spend co-signed (entry {}): a fill, a cancel or a forfeit; the signer co-signs one", crate::signer::ALREADY_SIGNED,
					req.coin, e.n)))));
			}
		}
		for (k, c) in checked.iter().enumerate() {
			for e in self.signer.under(&c.coin.leaf.salt).await? {
				if !(e.kind == crate::signer::Signed::Spend && e.digest == messages[k].0) {
					let _ = self.store.drop_order_fill(&transfer, "the signer holds another spend of a taker's coin").await;
					return Err(OrderError::Cosign(cosign::lost_spend(SignerError::AlreadySigned(format!("{}: coin {} has another spend \
						co-signed (entry {})", crate::signer::ALREADY_SIGNED, c.coin.id, e.n)), &c.coin.id)));
				}
			}
		}

		// S signs: the taker's two pairs, then the fill.
		let mut head: Option<crate::store::RecordHeadRow> = None;
		let mut latest = |h: Option<crate::signer::SignedHead>| {
			if let Some(h) = h {
				if let Some(sg) = h.signature {
					if head.is_none_or(|x| x.0 < h.entry) {
						head = Some((h.entry, h.hash, cosign::sig_bytes(&sg)));
					}
				}
			}
		};
		let mut sigs = Vec::with_capacity(n);
		for (k, (c, i)) in checked.iter().zip(&req.inputs).enumerate() {
			let cp_out = tplan.checkpoint_output(k);
			let (cp, h) = self.signer.rebind_recorded(&c.coin.leaf.owner, &i.checkpoint_sig, &c.coin.leaf.salt, c.coin.leaf.landing.map(|l| l.program),
				c.coin.asset, c.coin.value,
				std::slice::from_ref(&cp_out)).await.map_err(|e| OrderError::Cosign(cosign::lost_spend(e, &c.coin.id)))?;
			latest(h);
			let checkpoint = tplan.checkpoint(k);
			let (re, h) = self.signer.rebind_recorded(&checkpoint.owner, &i.reassignment_sig, &checkpoint.salt, None, c.coin.asset,
				i.checkpoint_value, &outputs).await.map_err(|e| OrderError::Cosign(cosign::lost_spend(e, &c.coin.id)))?;
			latest(h);
			if !verify_digest(&cp, &messages[k].0, &s) || !verify_digest(&re, &messages[k].1, &s) {
				return Err(internal("the signer signed another message than the server built"));
			}
			sigs.push((cp, re));
		}
		let (fill_sig, h) = self.signer.order_fill(&op, oc.coin.value, plan.rest.is_some(), &outputs).await
			.map_err(|e| OrderError::Cosign(cosign::lost_spend(e, &oc.coin.id)))?;
		latest(h);
		if !verify_digest(&fill_sig, &fill_digest, &s) {
			return Err(internal("the signer signed another fill than the server built"));
		}

		// Each new coin's record, checked as its holder will check it.
		let fill = OrderFill {
			order: oc.record.clone(),
			signature: fill_sig,
			partial: plan.rest.is_some(),
			inputs: checked.iter().zip(&req.inputs).zip(&sigs).map(|((c, i), (cp, re))| TransferInput {
				coin: c.record.clone(), checkpoint_value: i.checkpoint_value,
				checkpoint: Pair { operator: *cp, owner: i.checkpoint_sig },
				reassignment: Pair { operator: *re, owner: i.reassignment_sig },
			}).collect(),
			outputs: outputs.clone(),
		};
		// The order coin's record as the maker published it carries its
		// preimage and authorisations; a remainder's record is the server's own.
		let fill = match self.store.resting_order(&order.order_id).await? {
			Some(o) if o.order_id == req.coin.0 => OrderFill { order: CoinRecord::from_bytes(&o.record).map_err(internal)?, ..fill },
			_ => fill,
		};
		let mut bases: Vec<Transaction> = std::iter::once(&oc).chain(&checked).flat_map(|c| c.bases.clone()).collect();
		bases.sort_by_key(|t| t.txid());
		bases.dedup_by_key(|t| t.txid());
		let vpolicy = WalletPolicy { horizon: 0, ..policy };
		let mut records = Vec::with_capacity(m);
		for (j, id) in new_ids.iter().enumerate() {
			let (leaf, owner, nonce) = match j {
				0 => (FillLeaf::Credit { owner_nonce: order.credit_nonces[seq as usize] }, credit_leaf.owner,
					order.credit_nonces[seq as usize]),
				1 if plan.rest.is_some() => (FillLeaf::Rest { owner_nonce: maker_nonce }, op.owner, maker_nonce),
				_ => {
					let o = &req.outputs[j + req.outputs.len() - m];
					(FillLeaf::New(o.leaf), o.leaf.owner, o.leaf.owner_nonce)
				},
			};
			let record = CoinRecord::Fill(Box::new(FillCoin { fill: fill.clone(), index: j as u8, leaf }));
			let valid = record.validate(&bases, &vpolicy, &owner, &nonce)
				.map_err(|error| OrderError::Cosign(CosignError::InvalidCoin { leaf: *id, error }))?;
			if valid.id != *id {
				return Err(internal("a fill's coin's record gives another id"));
			}
			records.push((id.0, record.to_bytes().map_err(internal)?));
		}
		let sig_list: Vec<([u8; 64], [u8; 64])> = sigs.iter().map(|(a, b)| (cosign::sig_bytes(a), cosign::sig_bytes(b))).collect();
		self.store.complete_transfer(&transfer, &sig_list, &records, head).await?;
		self.store.sign_order_fill(&transfer, &cosign::sig_bytes(&fill_sig), plan.rest.as_ref().map(|_| new_ids[1].0)).await?;
		log::info!("co-signed fill {} of order {}: {} of {} for {} of {}{}", hex(&transfer), req.order, req.filled, t.asset_a, price,
			t.asset_b, if plan.rest.is_some() { format!(", {} resting at {}", plan.remainder, new_ids[1]) } else { String::new() });
		let row = self.store.order_fill_by_transfer(&transfer).await?.ok_or_else(|| internal("a fill just signed is gone"))?;
		self.answer(&transfer, &row).await
	}
}

/// The coin of a fill's taker, as its owner rebuilds its record from the
/// answer: the fill, the coin's index and its leaf.
pub fn coin_of(fill: &OrderFill, index: u8, leaf: FillLeaf) -> CoinRecord {
	CoinRecord::Fill(Box::new(FillCoin { fill: fill.clone(), index, leaf }))
}

/// Whether `coin` is a coin of a resting order (an `order-2` leaf).
pub fn is_order(coin: &ValidCoin) -> bool {
	coin.leaf.order.is_some()
}
