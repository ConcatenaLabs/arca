//! Paying an invoice out of the tree (`lightning_send`).
//!
//! A wallet pays a BOLT11 invoice in asset A out of its coins in A. It gives
//! the coins up, through checkpoints and a reassignment as in any transfer,
//! into an `htlc-1` leaf ([`arca_covenant::htlc`]) of its own key, locked to
//! the invoice's payment hash (direction `send`: the operator claims with the
//! preimage after its delay, the owner refunds after the timeout and the
//! leaf's exit delay), and change. The operator co-signs only when:
//!
//! - the invoice names asset A (SeqLN's `a` field), the asset of every coin
//!   given up and of every output: a coin in one asset never pays an invoice
//!   in another, and the payment goes through A's node and no other;
//! - A's node is up, decodes the invoice as valid and unexpired, for an
//!   amount, and the payment hash is the leaf's; the hash is no unlock hash of
//!   a participation, whose preimage the operator hands out, and no other
//!   payment's;
//! - the leaf holds exactly the invoice's amount and the operator's fee for
//!   it in A (`lightning_ppm`, `lightning_base`), its operator delay is the
//!   one the operator publishes, its exit delay at least the owner's least,
//!   and its timeout lies between `send_timeout_seconds` and twice that past
//!   the chain's median time;
//! - and every rule of a transfer holds ([`crate::cosign`]).
//!
//! It then records the payment, `paying`, and pays the invoice through A's
//! node, spending on routing at most its fee, and resolving before the
//! leaf's timeout. The node's answer decides it: `paid` with the preimage,
//! which proves the payment and makes the leaf the operator's (it co-signs
//! no spend of it back, and claims it with the preimage should it come
//! on-chain); or `failed` once no part of the payment is pending on the
//! node, after which the operator co-signs the leaf back to its owner, a new
//! leaf through its collaborative path. A payment whose answer is not known
//! is asked about again, and paid again only when the node never started it;
//! one whose every part failed before this run is called failed only once a
//! `pay` an earlier run started can no longer try another route. The leaf's
//! refund path is the owner's when the operator does neither.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use elements::AssetId;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use arca_covenant::{HtlcDirection, MedianTime, RelativeTime};

use crate::cosign::{CosignError, Cosigned, Cosigner, TransferRequest};
use crate::lightning::cln::ClnError;
use crate::lightning::{Gateway, Leg, LegRefusal};
use crate::params::Params;
use crate::store::{SendRow, SendState, Store, StoreError};

/// The operator's terms for an `htlc-1` leaf of a payment out of the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendConfig {
	/// The relative delay on the operator's claim.
	pub operator_delay: RelativeTime,
	/// The least exit delay the leaf takes: the owner's refund waits this long
	/// after the leaf is on-chain, the operator's time to claim first.
	pub owner_delay: RelativeTime,
	/// How far past the chain's median time the leaf's timeout lies, at
	/// least; at most twice that.
	pub timeout_seconds: u32,
	/// The chain's block interval, to bound the payment's lock times.
	pub block_seconds: u32,
	/// How long one payment attempt runs.
	pub retry_seconds: u32,
}

/// A request to pay `invoice` with `transfer`, whose outputs make the
/// `htlc-1` leaf and the change.
#[derive(Debug, Clone)]
pub struct SendRequest {
	pub invoice: String,
	pub transfer: TransferRequest,
}

/// What the operator answers: the co-signed transfer and the payment.
#[derive(Debug, Clone)]
pub struct Sent {
	pub cosigned: Cosigned,
	pub payment: SendRow,
}

/// Why a payment was refused.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
	#[error("{0}")]
	Malformed(String),
	#[error(transparent)]
	Leg(#[from] LegRefusal),
	/// The invoice does not decode, is expired, names no amount or another
	/// asset than the coins'.
	#[error("{0}")]
	Invoice(String),
	/// The `htlc-1` leaf's terms are not the operator's.
	#[error("{0}")]
	Htlc(String),
	#[error("{0}")]
	Fee(String),
	#[error("{0}")]
	InUse(String),
	#[error(transparent)]
	Cosign(#[from] CosignError),
	#[error(transparent)]
	Store(#[from] StoreError),
	#[error("the server has not followed the chain yet")]
	NotSynced,
}

impl SendError {
	pub fn code(&self) -> &'static str {
		match self {
			SendError::Malformed(_) => "malformed",
			SendError::Leg(l) => l.code(),
			SendError::Invoice(_) => "invoice",
			SendError::Htlc(_) => "htlc",
			SendError::Fee(_) => "fee",
			SendError::InUse(_) => "in_use",
			SendError::Cosign(c) => c.code(),
			SendError::Store(_) => "internal",
			SendError::NotSynced => "not_synced",
		}
	}
}

/// What A's node says of an invoice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
	pub payment_hash: [u8; 32],
	pub amount_msat: u64,
	pub asset: Option<String>,
	pub created_at: u64,
	pub expiry: u64,
	/// The lock time, in blocks, the payee takes on the last hop at least.
	pub min_final_cltv: u64,
}

/// Asks `leg`'s node to decode `invoice`, and refuses one it does not take
/// as a valid BOLT11 invoice.
pub async fn decode(leg: &Leg, invoice: &str) -> Result<Decoded, SendError> {
	let d = leg.cln.call("decode", json!({ "string": invoice }), Duration::from_secs(10)).await.map_err(|e| match e {
		ClnError::Rpc { message, .. } => SendError::Invoice(format!("the invoice does not decode: {}", message)),
		other => SendError::Leg(crate::lightning::node_error(leg, &other)),
	})?;
	if d["valid"].as_bool() != Some(true) || d["type"].as_str() != Some("bolt11 invoice") {
		return Err(SendError::Invoice(format!("{} does not take the invoice as a valid BOLT11 invoice", leg.name())));
	}
	let payment_hash = d["payment_hash"].as_str().and_then(|h| crate::signer::unhex32(h).ok())
		.ok_or_else(|| SendError::Invoice("the invoice names no payment hash".into()))?;
	let amount_msat = d["amount_msat"].as_u64().ok_or_else(|| SendError::Invoice("the invoice names no amount: an invoice paid \
		out of the tree names what it asks".into()))?;
	Ok(Decoded {
		payment_hash, amount_msat, asset: d["asset"].as_str().map(|a| a.to_lowercase()),
		created_at: d["created_at"].as_u64().unwrap_or(0), expiry: d["expiry"].as_u64().unwrap_or(3600),
		min_final_cltv: d["min_final_cltv_expiry"].as_u64().unwrap_or(18),
	})
}

/// See the [module documentation](self).
pub struct Sends {
	store: Store,
	params: Arc<Params>,
	gateway: Arc<Gateway>,
	cosigner: Arc<Cosigner>,
	config: SendConfig,
	/// The payments a task is paying now.
	running: Mutex<HashSet<[u8; 32]>>,
	/// Held from the look for a payment of a hash to its record, so two
	/// transfers locked to one hash are never both co-signed.
	gate: Mutex<()>,
}

fn unix_now() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Sends {
	pub fn new(store: Store, params: Arc<Params>, gateway: Arc<Gateway>, cosigner: Arc<Cosigner>, config: SendConfig) -> Arc<Sends> {
		Arc::new(Sends { store, params, gateway, cosigner, config, running: Mutex::new(HashSet::new()), gate: Mutex::new(()) })
	}

	pub fn config(&self) -> &SendConfig {
		&self.config
	}

	async fn now(&self) -> Result<MedianTime, SendError> {
		let tip = self.store.tip_block().await?.ok_or(SendError::NotSynced)?;
		MedianTime::from_consensus(tip.median_time as u32).map_err(|e| SendError::Malformed(e.to_string()))
	}

	/// Takes `req`: see the [module documentation](self). A request repeated
	/// byte for byte is answered as it was.
	pub async fn send(self: &Arc<Self>, req: &SendRequest) -> Result<Sent, SendError> {
		let outs = &req.transfer.outputs;
		let htlcs: Vec<usize> = (0..outs.len()).filter(|j| outs[*j].leaf.htlc.is_some()).collect();
		let [j] = htlcs[..] else {
			return Err(SendError::Malformed(format!("a payment over Lightning makes one htlc-1 leaf; this makes {}", htlcs.len())));
		};
		let out = &outs[j];
		let terms = out.leaf.htlc.expect("an htlc output");
		// A request repeated byte for byte gets the answer it got, whatever
		// has changed since (the invoice expired, the fees, the node): the
		// operator co-signed it already, and a wallet whose answer was lost
		// asks again.
		let transfer_id = req.transfer.hash();
		if let Some(r) = self.store.send(&terms.payment_hash).await? {
			if r.transfer_id == transfer_id {
				let cosigned = self.cosigner.cosign_htlc(&req.transfer).await?;
				return Ok(Sent { cosigned, payment: r });
			}
		}
		if terms.direction != HtlcDirection::Send {
			return Err(SendError::Htlc("the htlc-1 leaf of a payment out of the tree is one the operator claims (direction send)".into()));
		}
		let asset = out.asset;
		// One asset: every output, and every coin given up.
		if let Some(o) = outs.iter().find(|o| o.asset != asset) {
			return Err(SendError::Invoice(format!("an output is in asset {}, and the htlc-1 leaf in asset {}: a payment over Lightning \
				moves one asset", o.asset, asset)));
		}
		for i in &req.transfer.inputs {
			if let Some(row) = self.store.leaf(&i.leaf_id.0).await? {
				let a = AssetId::from_byte_array(row.asset);
				if a != asset {
					return Err(SendError::Invoice(format!("coin {} is in asset {}, and the payment in asset {}: a coin in one asset \
						never pays an invoice in another", i.leaf_id, a, asset)));
				}
			}
		}
		let leg = self.gateway.leg(&asset, self.params.assets.contains(&asset))?;
		let inv = decode(&leg, &req.invoice).await?;
		match &inv.asset {
			Some(a) if *a == asset.to_string() => {},
			Some(a) => return Err(SendError::Invoice(format!("the invoice is to be paid in asset {}, and the coins given up are in asset \
				{}: a coin in one asset never pays an invoice in another", a, asset))),
			None => return Err(SendError::Invoice("the invoice names no asset: on Sequentia an invoice names the asset it is paid in".into())),
		}
		if inv.created_at.saturating_add(inv.expiry) <= unix_now() + 60 {
			return Err(SendError::Invoice("the invoice has expired, or expires within a minute".into()));
		}
		if inv.payment_hash != terms.payment_hash {
			return Err(SendError::Htlc("the htlc-1 leaf is locked to another hash than the invoice's payment hash".into()));
		}
		if inv.amount_msat % 1000 != 0 {
			return Err(SendError::Invoice(format!("the invoice asks {} msat, which is not a whole number of atoms", inv.amount_msat)));
		}
		let amount = inv.amount_msat / 1000;
		let fee = self.params.fees(&asset).map_err(SendError::Fee)?.lightning(amount);
		if out.value != amount.saturating_add(fee) {
			return Err(SendError::Fee(format!("the htlc-1 leaf holds {} of asset {}; the invoice asks {} and the operator's fee for it \
				is {} (its schedule in the asset), so the leaf holds {}", out.value, asset, amount, fee, amount + fee)));
		}
		if terms.operator_delay != self.config.operator_delay {
			return Err(SendError::Htlc(format!("the htlc-1 leaf's operator delay is {} units; the operator's is {}",
				terms.operator_delay.units(), self.config.operator_delay.units())));
		}
		if out.leaf.exit_delay < self.config.owner_delay {
			return Err(SendError::Htlc(format!("the htlc-1 leaf's exit delay is {} units; the operator takes {} at least, its time to \
				claim before the owner's refund", out.leaf.exit_delay.units(), self.config.owner_delay.units())));
		}
		let now = self.now().await?.to_consensus_u32();
		let t = terms.timeout.to_consensus_u32();
		let (lo, hi) = (now.saturating_add(self.config.timeout_seconds), now.saturating_add(2 * self.config.timeout_seconds));
		let _gate = self.gate.lock().await;
		let recorded = self.store.send(&terms.payment_hash).await?;
		match &recorded {
			Some(r) if r.transfer_id != transfer_id => return Err(SendError::InUse(format!("a payment for hash {} is {} already, by \
				another transfer: an invoice is paid once", crate::signer::hex(&terms.payment_hash), r.state.name()))),
			Some(_) => {},
			None => {
				if t < lo || t > hi {
					return Err(SendError::Htlc(format!("the htlc-1 leaf's timeout {} is not between {} and {} (median times)", t, lo, hi)));
				}
				let room = self.max_delay(t, now);
				if inv.min_final_cltv > room as u64 {
					return Err(SendError::Invoice(format!("the invoice takes a final lock time of {} blocks; a payment whose leaf times out at \
						{} locks for at most {} blocks", inv.min_final_cltv, t, room)));
				}
				if self.store.is_unlock_hash(&terms.payment_hash).await? {
					return Err(SendError::Htlc("the payment hash is an unlock hash of the operator's: a payment never takes one".into()));
				}
			},
		}
		let cosigned = self.cosigner.cosign_htlc(&req.transfer).await?;
		let leaf_id = cosigned.outputs[j].0;
		let payment = self.store.record_send(&SendRow {
			payment_hash: terms.payment_hash, asset: asset.into_inner().to_byte_array(), invoice: req.invoice.clone(), amount, fee,
			transfer_id, htlc_leaf_id: leaf_id.0, state: SendState::Paying, preimage: None, reason: None,
		}).await?;
		if payment.state == SendState::Paying {
			self.start(payment.clone()).await;
		}
		Ok(Sent { cosigned, payment })
	}

	/// The payment for `hash`.
	pub async fn status(&self, hash: &[u8; 32]) -> Result<Option<SendRow>, StoreError> {
		self.store.send(hash).await
	}

	/// Pays every payment still `paying` that no task pays, every few
	/// seconds: at a start, those an earlier run left.
	pub fn spawn(self: &Arc<Self>) -> JoinHandle<()> {
		let me = self.clone();
		tokio::spawn(async move {
			loop {
				match me.store.sends_paying().await {
					Ok(rows) => {
						for r in rows {
							me.start(r).await;
						}
					},
					Err(e) => log::warn!("lightning: the payments being paid: {}", e),
				}
				tokio::time::sleep(Duration::from_secs(5)).await;
			}
		})
	}

	async fn start(self: &Arc<Self>, row: SendRow) {
		if !self.running.lock().await.insert(row.payment_hash) {
			return;
		}
		let me = self.clone();
		tokio::spawn(async move {
			let hash = row.payment_hash;
			if let Err(e) = me.pay(&row).await {
				log::warn!("lightning: payment {}: {}", crate::signer::hex(&hash), e);
			}
			me.running.lock().await.remove(&hash);
		});
	}

	/// What A's node holds of the payment for `hash`: complete with its
	/// preimage, pending, failed in every part (with when the first part
	/// started), or never started.
	async fn on_node(&self, leg: &Leg, hash: &[u8; 32]) -> Result<NodeView, ClnError> {
		let r = leg.cln.call("listsendpays", json!({ "payment_hash": crate::signer::hex(hash) }), Duration::from_secs(30)).await?;
		let parts = r["payments"].as_array().cloned().unwrap_or_default();
		if let Some(p) = parts.iter().find(|p| p["status"] == "complete") {
			if let Some(pre) = p["payment_preimage"].as_str().and_then(|h| crate::signer::unhex32(h).ok()) {
				return Ok(NodeView::Complete(pre));
			}
		}
		if parts.iter().any(|p| p["status"] == "pending") {
			return Ok(NodeView::Pending);
		}
		let started = parts.iter().filter_map(|p| p["created_at"].as_u64()).min().unwrap_or(0);
		Ok(if parts.is_empty() { NodeView::Never } else { NodeView::Failed(started) })
	}

	/// Pays `row` through its asset's node, or learns how the payment it
	/// started before went, and decides it.
	async fn pay(&self, row: &SendRow) -> Result<(), String> {
		let asset = AssetId::from_byte_array(row.asset);
		let leg = self.gateway.leg(&asset, true).map_err(|e| e.to_string())?;
		let hash = row.payment_hash;
		match self.on_node(&leg, &hash).await.map_err(|e| e.to_string())? {
			NodeView::Complete(pre) => return self.decide(&hash, Some(&pre), None).await,
			NodeView::Pending => return Ok(()),
			// A `pay` an earlier run started may still try another route
			// until its time runs out: failed only once it has.
			NodeView::Failed(started) if unix_now() < started + self.config.retry_seconds as u64 + 120 => return Ok(()),
			NodeView::Failed(_) => return self.decide(&hash, None, Some("the node failed every part of the payment")).await,
			NodeView::Never => {},
		}
		// The leaf's timeout bounds the payment's lock times: it resolves,
		// one way or the other, well before the owner's refund could open.
		let t = self.store.leaf(&row.htlc_leaf_id).await.map_err(|e| e.to_string())?
			.and_then(|l| arca_covenant::CoinRecord::from_bytes(&l.record).ok())
			.and_then(|r| match r { arca_covenant::CoinRecord::Transfer(t) => t.leaf.htlc.map(|h| h.timeout.to_consensus_u32()), _ => None })
			.ok_or("the htlc-1 coin of the payment is not known")?;
		let now = self.now().await.map_err(|e| e.to_string())?.to_consensus_u32();
		let maxdelay = self.max_delay(t, now).max(1);
		let params = json!({
			"bolt11": row.invoice,
			"maxfee": row.fee.saturating_mul(1000),
			"maxdelay": maxdelay,
			"retry_for": self.config.retry_seconds,
		});
		log::info!("lightning: paying {} atoms of asset {} for hash {} through {} (routing at most {} atoms, lock times within {} \
			blocks)", row.amount, asset, crate::signer::hex(&hash), leg.name(), row.fee, maxdelay);
		let wait = Duration::from_secs(self.config.retry_seconds as u64 + 120);
		match leg.cln.call("pay", params, wait).await {
			Ok(r) if r["status"] == "complete" => {
				let pre = r["payment_preimage"].as_str().and_then(|h| crate::signer::unhex32(h).ok())
					.ok_or("the node said complete with no preimage")?;
				self.decide(&hash, Some(&pre), None).await
			},
			Ok(r) => Err(format!("the node answered {}", r)),
			Err(e) => {
				// Decided only by what the node holds: a part still pending
				// may complete yet.
				match self.on_node(&leg, &hash).await.map_err(|e| e.to_string())? {
					NodeView::Complete(pre) => self.decide(&hash, Some(&pre), None).await,
					NodeView::Pending => Ok(()),
					NodeView::Failed(_) | NodeView::Never if e.answered() => self.decide(&hash, None, Some(&e.to_string())).await,
					_ => Err(e.to_string()),
				}
			},
		}
	}

	/// The most blocks a payment's lock times may add up to when its leaf
	/// times out at `t` and the chain's median time is `now`: half the time
	/// left, in blocks at the chain's interval, so that the payment resolves
	/// well before the owner's refund could open, at half the chain's pace.
	fn max_delay(&self, t: u32, now: u32) -> u32 {
		t.saturating_sub(now) / 2 / self.config.block_seconds.max(1)
	}

	async fn decide(&self, hash: &[u8; 32], preimage: Option<&[u8; 32]>, reason: Option<&str>) -> Result<(), String> {
		if let Some(p) = preimage {
			if arca_covenant::script::sha256(p) != *hash {
				return Err("the node gave a preimage of another hash".into());
			}
		}
		if self.store.decide_send(hash, preimage, reason).await.map_err(|e| e.to_string())? {
			match preimage {
				Some(_) => log::info!("lightning: payment {} paid", crate::signer::hex(hash)),
				None => log::info!("lightning: payment {} failed: {}", crate::signer::hex(hash), reason.unwrap_or("")),
			}
		}
		Ok(())
	}
}

enum NodeView {
	Complete([u8; 32]),
	Pending,
	Failed(u64),
	Never,
}

/// The JSON of a payment, as `lightning_send` and `lightning_send_status`
/// answer it.
pub fn payment_json(r: &SendRow) -> Value {
	let mut v = json!({
		"payment_hash": crate::signer::hex(&r.payment_hash),
		"asset": AssetId::from_byte_array(r.asset).to_string(),
		"amount": r.amount.to_string(),
		"fee": r.fee.to_string(),
		"htlc_leaf_id": crate::signer::hex(&r.htlc_leaf_id),
		"state": r.state.name(),
	});
	if let Some(p) = &r.preimage {
		v["preimage"] = json!(crate::signer::hex(p));
	}
	if let Some(why) = &r.reason {
		v["reason"] = json!(why);
	}
	v
}
