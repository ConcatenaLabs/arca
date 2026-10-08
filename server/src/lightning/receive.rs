//! Receiving over Lightning into the tree (`lightning_receive`).
//!
//! A wallet asks to receive `amount` of asset A under a payment hash of its
//! own choosing, whose preimage only it knows, into an `htlc-1` leaf of a key
//! of its own (signing the request with that key). The operator's node in A
//! makes the invoice: the server has it make one for the payment under a
//! preimage of the node's, swaps in the wallet's hash ([`super::bolt11`]),
//! has the node sign the result (`signinvoice`), and registers the hash with
//! the node's hold-invoice plugin, which holds the payment when it arrives
//! instead of settling it. The invoice's final lock time is long enough for
//! the leaf's timeout to leave the wallet its exit delay and a window
//! (`receive_window_seconds`) past it.
//!
//! Once the payment is held in full, in A, its parts locked long enough, the
//! operator wants the leaf in the next round of A: a participation that gives
//! up no coin and wants one output, the `htlc-1` leaf (direction `receive`:
//! its owner claims it with the preimage once its exit delay has run, the
//! operator refunds it once its timeout has passed and then the operator's
//! delay), of the amount less the operator's fee, funded by the operator's
//! pool against the payment its node holds. Its timeout is half the time the
//! held parts are locked for, so the payment outlives every claim the owner
//! can make. The wallet completes the participation as any other, handing
//! over its unroll authorisations for the leaf (`forfeit_leaves`, with no
//! forfeit), and receives the leaf's record and its entry's preimage.
//!
//! Only then does the wallet hand over the payment's preimage
//! (`lightning_receive_claim`), with a transfer of the leaf to a leaf of its
//! own, which the operator co-signs once the preimage opens the hash; its
//! node settles the payment with it. So the payment is never settled before
//! the wallet holds its leaf. A wallet that claims on the chain instead
//! reveals the preimage there; the server reads it from the claim and
//! settles the payment the same way.
//!
//! A payment is failed back when the invoice expires unpaid, when what is
//! held is locked for too short a time, when its leaf never comes (the
//! participation void, expired, or not built in time), and once the time to
//! claim has passed with no preimage: the leaf's timeout and the operator's
//! delay, while the leaf is not on the chain unspent, where its owner could
//! still claim it. A leaf of such a payment that reaches the chain is the
//! operator's to refund (the watcher's `htlc_refund`).

use std::sync::Arc;
use std::time::Duration;

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, OutPoint, Txid};
use rand::RngCore;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use arca_covenant::sign::verify_digest;
use arca_covenant::{HtlcDirection, HtlcTerms, MedianTime, RelativeTime, Template};

use crate::chain::finality::FinalityService;
use crate::cosign::{CosignError, Cosigned, Cosigner, TransferRequest};
use crate::lightning::cln::ClnError;
use crate::lightning::{Gateway, Leg, LegRefusal};
use crate::params::Params;
use crate::store::{
	NewParticipation, NewReceive, ParticipationOutput, ParticipationState, ReceiveRow, ReceiveState, Store, StoreError, WantedKind,
};

/// The blocks an invoice's final lock time adds to what the leaf needs, for
/// the blocks found between the payment and its check.
const CLTV_SLACK: u32 = 12;

/// The operator's terms for a payment into the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiveConfig {
	/// The relative delay on the operator's refund of the leaf.
	pub operator_delay: RelativeTime,
	/// The time the wallet has, past the leaf's exit delay, to claim it
	/// once its round is final.
	pub window_seconds: u32,
	/// How long an invoice is good for.
	pub invoice_expiry_seconds: u32,
	/// The chain's block interval, to turn lock times into time.
	pub block_seconds: u32,
}

impl ReceiveConfig {
	/// The blocks the held payment must stay locked for a leaf of exit delay
	/// `exit`: twice its exit delay and the window, in blocks, so that the
	/// leaf's timeout, half that time, leaves both.
	pub fn needed_blocks(&self, exit: RelativeTime) -> u32 {
		let seconds = exit.seconds() + self.window_seconds as u64;
		(2 * seconds).div_ceil(self.block_seconds.max(1) as u64).min(u32::MAX as u64) as u32
	}
}

/// A request to receive: see the [module documentation](self).
#[derive(Debug, Clone)]
pub struct ReceiveRequest {
	pub asset: AssetId,
	pub amount: u64,
	pub payment_hash: [u8; 32],
	pub owner: XOnlyPublicKey,
	pub owner_nonce: [u8; 32],
	pub exit_delay: RelativeTime,
	pub description: String,
	/// The owner key's signature over the request
	/// ([`crate::auth::lightning_receive_digest`]).
	pub owner_sig: Signature,
}

/// Why a request to receive, or a claim, was refused.
#[derive(Debug, thiserror::Error)]
pub enum ReceiveError {
	#[error("{0}")]
	Malformed(String),
	#[error("the request is not signed by the key the leaf is asked under")]
	BadSignature,
	#[error(transparent)]
	Leg(#[from] LegRefusal),
	#[error("{0}")]
	OutOfBounds(String),
	#[error("the key is the operator's own")]
	OperatorKey,
	#[error("the key owns a leaf, or another payment into the tree asks for one under it")]
	KeyReused,
	#[error("{0}")]
	InUse(String),
	/// The node did not make the invoice as asked.
	#[error("{0}")]
	Invoice(String),
	/// A claim the leaf's terms do not take.
	#[error("{0}")]
	Htlc(String),
	#[error("no payment into the tree is known for hash {0}")]
	Unknown(String),
	#[error(transparent)]
	Cosign(#[from] CosignError),
	#[error(transparent)]
	Store(#[from] StoreError),
	#[error("the server has not followed the chain yet")]
	NotSynced,
}

impl ReceiveError {
	pub fn code(&self) -> &'static str {
		match self {
			ReceiveError::Malformed(_) => "malformed",
			ReceiveError::BadSignature => "bad_signature",
			ReceiveError::Leg(l) => l.code(),
			ReceiveError::OutOfBounds(_) => "out_of_bounds",
			ReceiveError::OperatorKey => "operator_key",
			ReceiveError::KeyReused => "key_reused",
			ReceiveError::InUse(_) => "in_use",
			ReceiveError::Invoice(_) => "invoice",
			ReceiveError::Htlc(_) => "htlc",
			ReceiveError::Unknown(_) => "unknown_payment",
			ReceiveError::Cosign(c) => c.code(),
			ReceiveError::Store(_) => "internal",
			ReceiveError::NotSynced => "not_synced",
		}
	}
}

/// What a claim answers: the co-signed transfer of the leaf, and the payment.
#[derive(Debug, Clone)]
pub struct Claimed {
	pub cosigned: Cosigned,
	pub receive: ReceiveRow,
}

/// The id of the participation that wants the leaf of the payment of `hash`.
pub fn participation_id(hash: &[u8; 32]) -> [u8; 32] {
	let mut e = sha256::Hash::engine();
	e.input(crate::auth::LIGHTNING_RECEIVE_TAG);
	e.input(hash);
	sha256::Hash::from_engine(e).to_byte_array()
}

fn unix_now() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn hex(b: &[u8]) -> String {
	crate::signer::hex(b)
}

/// See the [module documentation](self).
pub struct Receives {
	store: Store,
	params: Arc<Params>,
	gateway: Arc<Gateway>,
	cosigner: Arc<Cosigner>,
	finality: Arc<FinalityService>,
	config: ReceiveConfig,
	/// Held by every step that decides a payment: a request, a pass, a
	/// claim. A preimage is never recorded while the payment is being failed
	/// back, nor the other way round.
	gate: Mutex<()>,
}

impl Receives {
	pub fn new(store: Store, params: Arc<Params>, gateway: Arc<Gateway>, cosigner: Arc<Cosigner>, finality: Arc<FinalityService>,
		config: ReceiveConfig) -> Arc<Receives>
	{
		Arc::new(Receives { store, params, gateway, cosigner, finality, config, gate: Mutex::new(()) })
	}

	pub fn config(&self) -> &ReceiveConfig {
		&self.config
	}

	async fn now(&self) -> Result<MedianTime, ReceiveError> {
		let tip = self.store.tip_block().await?.ok_or(ReceiveError::NotSynced)?;
		MedianTime::from_consensus(tip.median_time as u32).map_err(|e| ReceiveError::Malformed(e.to_string()))
	}

	/// The payment for `hash`.
	pub async fn status(&self, hash: &[u8; 32]) -> Result<Option<ReceiveRow>, StoreError> {
		self.store.receive(hash).await
	}

	/// Takes `req`: see the [module documentation](self). A request repeated
	/// is answered with the payment it made.
	pub async fn receive(&self, req: &ReceiveRequest) -> Result<ReceiveRow, ReceiveError> {
		let p = &self.params;
		let digest = crate::auth::lightning_receive_digest(&p.chain, &p.operator, &req.asset, req.amount, &req.payment_hash, &req.owner,
			&req.owner_nonce, req.exit_delay.units());
		if !verify_digest(&req.owner_sig, &digest, &req.owner) {
			return Err(ReceiveError::BadSignature);
		}
		let _gate = self.gate.lock().await;
		if let Some(r) = self.store.receive(&req.payment_hash).await? {
			let n = &r.new;
			if n.asset == req.asset.into_inner().to_byte_array() && n.amount == req.amount && n.owner_key == req.owner.serialize()
				&& n.owner_nonce == req.owner_nonce && n.exit_delay_units == req.exit_delay.units()
			{
				return Ok(r);
			}
			return Err(ReceiveError::InUse(format!("a payment into the tree under hash {} is asked for already", hex(&req.payment_hash))));
		}
		let leg = self.gateway.receiving_leg(&req.asset, p.assets.contains(&req.asset))?;
		if req.owner == p.operator {
			return Err(ReceiveError::OperatorKey);
		}
		let key = req.owner.serialize();
		if self.store.key_owns_leaf(&key).await? || self.store.receive_key(&key).await? {
			return Err(ReceiveError::KeyReused);
		}
		if !p.exit_delay_ok(req.exit_delay) {
			return Err(ReceiveError::OutOfBounds(format!("an exit delay of {} units; the operator takes {} to {}", req.exit_delay.units(),
				p.min_exit_delay.units(), p.max_exit_delay.units())));
		}
		if req.exit_delay <= self.config.operator_delay {
			return Err(ReceiveError::OutOfBounds(format!("an exit delay of {} units; the leaf's must be longer than the operator's delay \
				of {}", req.exit_delay.units(), self.config.operator_delay.units())));
		}
		if self.store.is_unlock_hash(&req.payment_hash).await? || self.store.send(&req.payment_hash).await?.is_some() {
			return Err(ReceiveError::InUse(format!("hash {} is in use here already", hex(&req.payment_hash))));
		}
		let fee = p.fees(&req.asset).map_err(ReceiveError::OutOfBounds)?.lightning(req.amount);
		let value = req.amount.checked_sub(fee).filter(|v| *v > 0).ok_or_else(|| ReceiveError::OutOfBounds(format!(
			"the operator's fee of {} takes the whole {} asked", fee, req.amount)))?;
		p.check_value(req.asset, value).map_err(|e| ReceiveError::OutOfBounds(format!("the leaf of {} (the {} asked, less the \
			operator's fee of {}): {}", value, req.amount, fee, e)))?;
		if req.description.len() > 256 {
			return Err(ReceiveError::Malformed("a description of more than 256 bytes".into()));
		}
		let invoice = self.make_invoice(&leg, req).await?;
		let row = self.store.insert_receive(&NewReceive {
			payment_hash: req.payment_hash, asset: req.asset.into_inner().to_byte_array(), amount: req.amount, fee, invoice,
			expires_at: unix_now() + self.config.invoice_expiry_seconds as u64, owner_key: key, owner_nonce: req.owner_nonce,
			exit_delay_units: req.exit_delay.units(),
		}).await.map_err(|e| match e {
			StoreError::KeyReused => ReceiveError::KeyReused,
			other => ReceiveError::Store(other),
		})?;
		log::info!("lightning: receiving {} of asset {} under hash {} into a leaf of {} (fee {})", req.amount, req.asset,
			hex(&req.payment_hash), value, fee);
		Ok(row)
	}

	/// The invoice of `req`: the node's, under the wallet's hash, signed by
	/// the node, and the hash registered to be held.
	async fn make_invoice(&self, leg: &Leg, req: &ReceiveRequest) -> Result<String, ReceiveError> {
		let node = |e: ClnError| ReceiveError::Leg(crate::lightning::node_error(leg, &e));
		let t = Duration::from_secs(30);
		let cltv = self.config.needed_blocks(req.exit_delay) + CLTV_SLACK;
		let label = format!("arca-receive-{}", hex(&req.payment_hash));
		let mut other = [0u8; 32];
		rand::rngs::OsRng.fill_bytes(&mut other);
		// The node's own invoice for the payment, under a preimage of its
		// own: never to be paid, and deleted at once.
		let made = leg.cln.call("invoice", json!({
			"amount_msat": req.amount.saturating_mul(1000), "label": label, "description": req.description,
			"expiry": self.config.invoice_expiry_seconds, "preimage": hex(&other), "cltv": cltv, "asset": req.asset.to_string(),
		}), t).await.map_err(node)?;
		let template = made["bolt11"].as_str().ok_or_else(|| ReceiveError::Invoice("the node made no invoice".into()))?.to_string();
		leg.cln.call("delinvoice", json!({ "label": label, "status": "unpaid" }), t).await.map_err(node)?;
		let swapped = super::bolt11::with_payment_hash(&template, &req.payment_hash)
			.map_err(|e| ReceiveError::Invoice(format!("the node's invoice: {}", e)))?;
		let signed = leg.cln.call("signinvoice", json!({ "invstring": swapped }), t).await.map_err(node)?;
		let invoice = signed["bolt11"].as_str().ok_or_else(|| ReceiveError::Invoice("the node signed no invoice".into()))?.to_string();
		// Read back as a payer's node reads it.
		let d = super::send::decode(leg, &invoice).await.map_err(|e| ReceiveError::Invoice(format!("the invoice made: {}", e)))?;
		if d.payment_hash != req.payment_hash || d.asset.as_deref() != Some(&req.asset.to_string()) || d.amount_msat != req.amount * 1000
			|| d.min_final_cltv < cltv as u64
		{
			return Err(ReceiveError::Invoice("the invoice the node signed is not the one asked for".into()));
		}
		leg.cln.call("holdinvoice", json!({
			"payment_hash": hex(&req.payment_hash), "amount_msat": req.amount.saturating_mul(1000), "label": label,
			"description": req.description, "cltv": cltv, "asset": req.asset.to_string(),
		}), t).await.map_err(node)?;
		Ok(invoice)
	}

	/// Moves every payment on, every two seconds: see the [module
	/// documentation](self).
	pub fn spawn(self: &Arc<Self>) -> JoinHandle<()> {
		let me = self.clone();
		tokio::spawn(async move {
			loop {
				if let Err(e) = me.pass().await {
					log::warn!("lightning: receiving: {}", e);
				}
				tokio::time::sleep(Duration::from_secs(2)).await;
			}
		})
	}

	/// One pass over every payment not done with.
	pub async fn pass(&self) -> Result<(), ReceiveError> {
		let _gate = self.gate.lock().await;
		for r in self.store.receives_in(ReceiveState::Open).await? {
			if let Err(e) = self.on_open(&r).await {
				log::warn!("lightning: the payment of hash {}: {}", hex(&r.new.payment_hash), e);
			}
		}
		for r in self.store.receives_in(ReceiveState::Accepted).await? {
			if let Err(e) = self.on_accepted(&r).await {
				log::warn!("lightning: the payment of hash {}: {}", hex(&r.new.payment_hash), e);
			}
		}
		for r in self.store.receives_unresolved().await? {
			if let Err(e) = self.resolve(&r).await {
				log::warn!("lightning: the payment of hash {}: {}", hex(&r.new.payment_hash), e);
			}
		}
		Ok(())
	}

	fn leg_of(&self, r: &ReceiveRow) -> Option<Arc<Leg>> {
		self.gateway.any_leg(&AssetId::from_byte_array(r.new.asset))
	}

	async fn cancel(&self, r: &ReceiveRow, why: &str) -> Result<(), ReceiveError> {
		if self.store.cancel_receive(&r.new.payment_hash, why).await? {
			log::info!("lightning: the payment of hash {} is failed back: {}", hex(&r.new.payment_hash), why);
		}
		Ok(())
	}

	async fn on_open(&self, r: &ReceiveRow) -> Result<(), ReceiveError> {
		let hash = r.new.payment_hash;
		let Some(leg) = self.leg_of(r) else {
			if unix_now() > r.new.expires_at {
				return self.cancel(r, "the invoice expired unpaid").await;
			}
			return Ok(());
		};
		let t = Duration::from_secs(10);
		let node = |e: ClnError| ReceiveError::Leg(crate::lightning::node_error(&leg, &e));
		let h = leg.cln.call("holdinvoicelookup", json!({ "payment_hash": hex(&hash) }), t).await.map_err(node)?;
		let received = h["received_msat"].as_u64().unwrap_or(0) / 1000;
		match h["state"].as_str() {
			Some("accepted") if received >= r.new.amount => {},
			Some("accepted") | Some("waiting") => {
				if unix_now() > r.new.expires_at {
					return self.cancel(r, if received > 0 { "the invoice expired, part of it paid" } else { "the invoice expired unpaid" })
						.await;
				}
				return Ok(());
			},
			Some("unknown") => {
				return self.cancel(r, "the node holds nothing under the hash").await;
			},
			other => return self.cancel(r, &format!("the node's hold is {}", other.unwrap_or("?"))).await,
		}
		// Held in full: is it locked for long enough?
		let exit = RelativeTime::from_units(r.new.exit_delay_units).map_err(|e| ReceiveError::Malformed(e.to_string()))?;
		let (expiry, height) = (h["cltv_expiry"].as_u64().unwrap_or(0), h["blockheight"].as_u64().unwrap_or(u64::MAX));
		let left = expiry.saturating_sub(height);
		let needed = self.config.needed_blocks(exit) as u64;
		if left < needed {
			return self.cancel(r, &format!("the payment is locked for {} blocks; its leaf needs {}", left, needed)).await;
		}
		// The leaf times out at half the time the payment is locked for.
		let now = self.now().await?.to_consensus_u32() as u64;
		let timeout = now + left * self.config.block_seconds as u64 / 2;
		let timeout = u32::try_from(timeout).map_err(|_| ReceiveError::Malformed("a timeout past 2106".into()))?;
		let terms = HtlcTerms {
			direction: HtlcDirection::Receive,
			payment_hash: hash,
			timeout: MedianTime::from_consensus(timeout).map_err(|e| ReceiveError::Malformed(e.to_string()))?,
			operator_delay: self.config.operator_delay,
		};
		terms.check(exit).map_err(|e| ReceiveError::Htlc(e.to_string()))?;
		let id = participation_id(&hash);
		let mut preimage = [0u8; 32];
		rand::rngs::OsRng.fill_bytes(&mut preimage);
		let unlock_hash = arca_covenant::script::sha256(&preimage);
		let p = NewParticipation {
			id, unlock_hash, preimage, not_before: None, refund_delay_units: 1, inputs: vec![], fees: vec![],
			outputs: vec![ParticipationOutput {
				asset: r.new.asset,
				value: r.new.amount - r.new.fee,
				kind: WantedKind::Leaf {
					template: Template::Htlc1.to_string(), owner_key: r.new.owner_key, owner_nonce: r.new.owner_nonce,
					exit_delay_units: r.new.exit_delay_units, operator_nonce: [0; 32], htlc: Some(terms),
				},
				leaf_id: None,
			}],
		};
		match self.store.insert_participation(&p).await {
			Ok(()) | Err(StoreError::ParticipationExists) => {},
			Err(StoreError::KeyReused) => return self.cancel(r, "the key the leaf is asked under owns a leaf now").await,
			Err(e) => return Err(e.into()),
		}
		if self.store.accept_receive(&hash, &id, timeout, expiry as u32).await? {
			log::info!("lightning: the payment of hash {} is held ({} atoms, locked {} blocks): its leaf, timing out at {}, is wanted \
				in the next round (participation {})", hex(&hash), received, left, timeout, hex(&id));
		}
		Ok(())
	}

	/// The leaf of the payment `r`, once its round made it.
	async fn leaf_of(&self, r: &ReceiveRow) -> Result<Option<[u8; 32]>, ReceiveError> {
		let Some(id) = r.participation_id else { return Ok(None) };
		Ok(self.store.participation(&id).await?.and_then(|p| p.outputs.first().and_then(|o| o.leaf_id)))
	}

	async fn on_accepted(&self, r: &ReceiveRow) -> Result<(), ReceiveError> {
		let hash = r.new.payment_hash;
		let id = r.participation_id.ok_or_else(|| ReceiveError::Malformed("an accepted payment without its participation".into()))?;
		let p = self.store.participation(&id).await?.ok_or_else(|| ReceiveError::Malformed("its participation is gone".into()))?;
		let now = self.now().await?.to_consensus_u32() as u64;
		let timeout = r.timeout.unwrap_or(0) as u64;
		let exit = RelativeTime::from_units(r.new.exit_delay_units).map_err(|e| ReceiveError::Malformed(e.to_string()))?;
		match p.state {
			ParticipationState::Void | ParticipationState::Expired => {
				let why = p.void_reason.clone().unwrap_or_else(|| "its leaf was never handed over".into());
				return self.cancel(r, &format!("its leaf never came: {}", why)).await;
			},
			// Built too late, the leaf would leave its owner less than its
			// exit delay and half its window to claim.
			// A round that took it meanwhile issues its leaf: then it is not
			// void, and the payment stands.
			ParticipationState::Pending if now + exit.seconds() + self.config.window_seconds as u64 / 2 > timeout => {
				let why = "no round took its leaf in time";
				if self.store.void_participation(&id, why).await? {
					return self.cancel(r, why).await;
				}
				return Ok(());
			},
			_ => {},
		}
		// A claim on the chain reveals the preimage there.
		if let Some(leaf) = self.leaf_of(r).await? {
			if let Some(pre) = self.preimage_on_chain(&leaf, &hash).await? {
				if self.store.claim_receive(&hash, &pre).await? {
					log::info!("lightning: the payment of hash {}: its leaf was claimed on the chain, the preimage read there", hex(&hash));
				}
				return Ok(());
			}
		}
		// The time to claim is over: the leaf is the operator's to refund.
		// One on the chain and still unspent could yet be claimed there, so
		// the payment stands until the watcher's refund takes it, or until
		// the held parts are a dozen blocks from their expiry.
		if now > timeout + self.config.operator_delay.seconds() + 3600 {
			let height = self.store.tip_block().await?.map(|b| b.height).unwrap_or(0);
			let near = height + 12 >= r.htlc_expiry.unwrap_or(0) as u64;
			if !near {
				if let Some(leaf) = self.leaf_of(r).await? {
					if self.unspent_on_chain(&leaf).await? {
						return Ok(());
					}
				}
			}
			return self.cancel(r, "its leaf was not claimed in time").await;
		}
		Ok(())
	}

	/// Whether an output of the leaf `leaf` is on the chain, unspent.
	async fn unspent_on_chain(&self, leaf: &[u8; 32]) -> Result<bool, ReceiveError> {
		let Some(row) = self.store.leaf(leaf).await? else { return Ok(false) };
		for (txid, vout) in self.store.sightings_of(&row.script_pubkey).await? {
			let at = OutPoint::new(Txid::from_byte_array(txid), vout);
			let unspent = self.finality.call(move |c| c.unspent(&at, true)).await
				.map_err(|e| ReceiveError::Malformed(format!("the chain: {}", e)))?;
			if unspent.is_some() {
				return Ok(true);
			}
		}
		Ok(false)
	}

	/// The preimage the claim of the leaf `leaf` on the chain revealed, if
	/// it has been claimed there: each output of the leaf seen on the chain
	/// is watched for its spend, and one spent before it was watched (its
	/// claim right behind it) is looked for on the chain itself.
	async fn preimage_on_chain(&self, leaf: &[u8; 32], hash: &[u8; 32]) -> Result<Option<[u8; 32]>, ReceiveError> {
		let Some(row) = self.store.leaf(leaf).await? else { return Ok(None) };
		let chain = |e: crate::chain::ChainError| ReceiveError::Malformed(format!("the chain: {}", e));
		for (txid, vout) in self.store.sightings_of(&row.script_pubkey).await? {
			self.store.watch_outpoint(&txid, vout, "receive", leaf).await?;
			let at = OutPoint::new(Txid::from_byte_array(txid), vout);
			let tx = match self.store.outpoint_spender(&txid, vout).await? {
				Some(by) => {
					let by = Txid::from_byte_array(by);
					self.finality.call(move |c| c.transaction(&by)).await.map_err(chain)?
				},
				None => {
					if self.finality.call(move |c| c.unspent(&at, true)).await.map_err(chain)?.is_some() {
						continue;
					}
					let found = self.finality.call(move |c| find_spender(c, &at)).await.map_err(chain)?;
					if let Some(tx) = &found {
						self.store.set_outpoint_spender(&txid, vout, &tx.txid().to_byte_array()).await?;
					}
					found
				},
			};
			let Some(tx) = tx else { continue };
			for i in tx.input.iter().filter(|i| i.previous_output == at) {
				for w in &i.witness.script_witness {
					if let Ok(p) = <[u8; 32]>::try_from(&w[..]) {
						if arca_covenant::script::sha256(&p) == *hash {
							return Ok(Some(p));
						}
					}
				}
			}
		}
		Ok(None)
	}

	/// Settles a claimed payment with its preimage, or fails a cancelled one
	/// back.
	async fn resolve(&self, r: &ReceiveRow) -> Result<(), ReceiveError> {
		let hash = r.new.payment_hash;
		let Some(leg) = self.leg_of(r) else { return Ok(()) };
		let t = Duration::from_secs(30);
		let node = |e: ClnError| ReceiveError::Leg(crate::lightning::node_error(&leg, &e));
		match (r.state, r.preimage) {
			(ReceiveState::Claimed, Some(pre)) => {
				let h = leg.cln.call("holdinvoicelookup", json!({ "payment_hash": hex(&hash) }), t).await.map_err(node)?;
				if h["state"] != "settled" {
					leg.cln.call("holdinvoicesettle", json!({ "payment_hash": hex(&hash), "preimage": hex(&pre) }), t).await.map_err(node)?;
				}
				self.store.set_receive_settled(&hash).await?;
				log::info!("lightning: the payment of hash {} is settled", hex(&hash));
			},
			(ReceiveState::Cancelled, _) => {
				let h = leg.cln.call("holdinvoicelookup", json!({ "payment_hash": hex(&hash) }), t).await.map_err(node)?;
				if !matches!(h["state"].as_str(), Some("cancelled") | Some("unknown")) {
					leg.cln.call("holdinvoicecancel", json!({ "payment_hash": hex(&hash) }), t).await.map_err(node)?;
				}
				self.store.set_receive_failed_back(&hash).await?;
			},
			_ => {},
		}
		Ok(())
	}

	/// Takes the preimage of the payment `hash` with the transfer of its
	/// leaf: see the [module documentation](self).
	pub async fn claim(&self, hash: &[u8; 32], preimage: &[u8; 32], transfer: &TransferRequest) -> Result<Claimed, ReceiveError> {
		if arca_covenant::script::sha256(preimage) != *hash {
			return Err(ReceiveError::Htlc("the preimage does not open the payment hash".into()));
		}
		let _gate = self.gate.lock().await;
		let r = self.store.receive(hash).await?.ok_or_else(|| ReceiveError::Unknown(hex(hash)))?;
		match r.state {
			ReceiveState::Accepted | ReceiveState::Claimed => {},
			ReceiveState::Open => return Err(ReceiveError::Htlc("the payment is not held yet: there is no leaf to claim".into())),
			ReceiveState::Cancelled => return Err(ReceiveError::Htlc(format!("the payment was failed back: {}",
				r.reason.as_deref().unwrap_or("")))),
		}
		let id = r.participation_id.ok_or_else(|| ReceiveError::Malformed("an accepted payment without its participation".into()))?;
		let p = self.store.participation(&id).await?.ok_or_else(|| ReceiveError::Malformed("its participation is gone".into()))?;
		if p.state != ParticipationState::Released {
			return Err(ReceiveError::Htlc(format!("the leaf is not the owner's yet (its participation is {}): it is claimed once its \
				round is final and the owner has completed the participation (forfeit_leaves)", p.state.as_str())));
		}
		if r.state == ReceiveState::Accepted {
			let now = self.now().await?.to_consensus_u32() as u64;
			if now >= r.timeout.unwrap_or(0) as u64 + self.config.operator_delay.seconds() {
				return Err(ReceiveError::Htlc("the time to claim the leaf is over".into()));
			}
			self.store.claim_receive(hash, preimage).await?;
			log::info!("lightning: the payment of hash {}: its owner handed over the preimage", hex(hash));
		}
		drop(_gate);
		// Settled at once if the node answers; a pass settles it otherwise.
		if let Some(r) = self.store.receive(hash).await? {
			if let Err(e) = self.resolve(&r).await {
				log::warn!("lightning: settling the payment of hash {}: {}", hex(hash), e);
			}
		}
		let cosigned = self.cosigner.cosign(transfer).await?;
		let receive = self.store.receive(hash).await?.ok_or_else(|| ReceiveError::Unknown(hex(hash)))?;
		Ok(Claimed { cosigned, receive })
	}
}

/// How many blocks back from the tip a spend of a received leaf's output is
/// looked for, when it came before the output was watched.
const SPEND_LOOKBACK: usize = 10_000;

/// The transaction spending `at`, in the mempool or in a block from the tip
/// down to the one holding `at`, at most [`SPEND_LOOKBACK`] of them.
fn find_spender(c: &dyn crate::chain::ChainSource, at: &OutPoint) -> Result<Option<elements::Transaction>, crate::chain::ChainError> {
	let spends = |tx: &elements::Transaction| tx.input.iter().any(|i| i.previous_output == *at);
	for t in c.mempool()? {
		if let Some(tx) = c.transaction(&t)? {
			if spends(&tx) {
				return Ok(Some(tx));
			}
		}
	}
	let Some(from) = c.tx_block(&at.txid)? else { return Ok(None) };
	let mut h = c.tip()?;
	for _ in 0..SPEND_LOOKBACK {
		if let Some(tx) = c.block_txs(&h)?.into_iter().find(|tx| spends(tx)) {
			return Ok(Some(tx));
		}
		if h == from {
			break;
		}
		match c.header(&h)?.prev {
			Some(p) => h = p,
			None => break,
		}
	}
	Ok(None)
}

/// The JSON of a payment into the tree, as `lightning_receive` and its
/// status answer it.
pub fn receive_json(r: &ReceiveRow) -> Value {
	let n = &r.new;
	let mut v = json!({
		"payment_hash": hex(&n.payment_hash),
		"asset": AssetId::from_byte_array(n.asset).to_string(),
		"amount": n.amount.to_string(),
		"fee": n.fee.to_string(),
		"value": (n.amount - n.fee).to_string(),
		"invoice": n.invoice,
		"expires_at": n.expires_at,
		"state": r.state.name(),
		"settled": r.settled,
	});
	if let Some(p) = &r.participation_id {
		v["participation_id"] = json!(hex(p));
	}
	if let Some(t) = r.timeout {
		v["timeout"] = json!(t);
	}
	if let Some(why) = &r.reason {
		v["reason"] = json!(why);
	}
	v
}
