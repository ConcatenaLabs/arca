//! Distributions: one round paying many holders, each under a key its payer
//! names (a claim tree).
//!
//! A distribution is a participation of the payer's. It gives up the payer's
//! coins, all in one asset, each attested by its owner key over the
//! distribution's id ([`arca_covenant::Distribution::id`]), and wants one
//! `vtxo-1` leaf per claim, owned by the claim key of the key the payer names
//! and the nonce it draws ([`arca_covenant::claim_key`]), which the server
//! derives itself: a distribution names keys, never claim keys, so it can take
//! no key a wallet uses for its own leaves. It runs in the asset's ordinary
//! round and completes as a refresh does: the payer hands over the forfeit of
//! every coin it gave up once the round is final, with no unroll
//! authorisation for any claim leaf (it holds no claim key), and the
//! distribution's one preimage goes out; then every claim leaf is credited.
//!
//! The server accepts a distribution only when:
//!
//! - it keeps the bounds every distribution keeps (1 to 16 coins, 1 to
//!   [`MAX_CLAIMS`] claims, each holding something, no key named twice, a
//!   return script, no fee asset twice) and its asset is served;
//! - each claim's value is within the asset's published bounds, its exit
//!   delay within the operator's, and its claim key is not the operator's `S`
//!   and owns no leaf;
//! - the return script is a standard address (P2PKH, P2SH, P2WPKH, P2WSH or
//!   P2TR), so the payment of the unclaimed leaves relays, and no Arca script
//!   the server knows;
//! - every coin given up passes what a refresh's coins pass, attested over
//!   the distribution's id, with nothing of it in the signer's record;
//! - the coins hold exactly the claims and the fee, all in the asset, and the
//!   fee covers the schedule: the refresh fee of each coin given up, the
//!   refresh's fixed part for each claim leaf, and the offboard's fixed part
//!   once, for the payment of the unclaimed leaves back to the payer.
//!
//! A holder takes a claim leaf up out of round, as any coin is spent. First it
//! hands over its unroll authorisations for the leaf ([`Participations::claim_leaf`]),
//! signed by the claim key: the server keeps them with the leaf's record, so
//! it can resolve the coin, co-sign its spend and pass it on inside the
//! transfer, as it does with every round leaf. Signatures that verify under
//! the claim key are the proof that whoever hands them over holds it.
//!
//! The leaves no holder took up are paid back to the payer's return script by
//! the watcher once the sweep that took them is final ([`crate::watcher`]).

use std::collections::{BTreeMap, BTreeSet};

use elements::secp256k1_zkp::schnorr::Signature;
use elements::AssetId;
use rand::RngCore;

use arca_covenant::script::sha256 as sha256_bytes;
use arca_covenant::sign::verify_digest;
use arca_covenant::{Distribution, LeafId, MedianTime, Template};

use super::{forfeit_margin, ParticipationError, Participations, Status, MAX_DEFER};
use crate::coins::{self, CoinError};
use crate::params::Params;
use crate::signer::{hex, Signed};
use crate::store::{
	ClaimRow, NewDistribution, NewParticipation, ParticipationInput, ParticipationOutput, ParticipationState, StoreError, WantedKind,
};

/// The most claims one distribution names: the specification's batch of
/// 1,024 leaves, which its claims share with nothing else they could not fit
/// beside.
pub const MAX_CLAIMS: usize = 1024;

/// What a payer submits: the distribution, and for each coin it gives up, in
/// order, its owner's signature over the distribution's id.
#[derive(Debug, Clone)]
pub struct DistributionRequest {
	pub distribution: Distribution,
	pub attestations: Vec<Signature>,
}

/// What the operator asks for a distribution under `schedule`: the refresh
/// fee of each coin given up (its value and expiry, at `now`), the refresh's
/// fixed part for each of `claims` claim leaves, and the offboard's fixed
/// part once, for the payment of what no holder takes up.
pub fn distribution_fee(schedule: &crate::params::FeeSchedule, coins: &[(u64, MedianTime)], claims: usize, now: MedianTime) -> u64 {
	let mut fee: u128 = coins.iter().map(|(v, e)| schedule.refresh(*v, *e, now) as u128).sum();
	fee += schedule.refresh_base as u128 * claims as u128;
	fee += schedule.offboard_base as u128;
	fee.min(u64::MAX as u128) as u64
}

impl From<arca_covenant::ClaimError> for ParticipationError {
	fn from(e: arca_covenant::ClaimError) -> ParticipationError {
		ParticipationError::Malformed(e.to_string())
	}
}

impl Participations {
	/// Accepts the distribution `req`: see the [module documentation](self).
	/// A distribution submitted again is answered with its status.
	pub async fn distribute(&self, req: &DistributionRequest) -> Result<Status, ParticipationError> {
		let d = &req.distribution;
		d.check()?;
		if d.claims.len() > MAX_CLAIMS {
			return Err(ParticipationError::Malformed(format!("{} claims; a distribution names 1 to {}, a batch's leaves",
				d.claims.len(), MAX_CLAIMS)));
		}
		if req.attestations.len() != d.inputs.len() {
			return Err(ParticipationError::Malformed(format!("{} attestations for {} coins", req.attestations.len(), d.inputs.len())));
		}
		if d.inputs.iter().collect::<BTreeSet<_>>().len() != d.inputs.len() {
			return Err(ParticipationError::Malformed("a coin is given up twice".into()));
		}
		let p = &self.params;
		let id = d.id(&p.chain, &p.operator);
		if self.store.participation(&id).await?.is_some() {
			return self.status(&id).await;
		}
		// A coin whose holder is frozen is refused before anything else.
		crate::supervision::gate(&self.store, &self.finality, p, &d.inputs).await?;
		let now = self.now().await?;
		if let Some(t) = d.not_before {
			if t.to_consensus_u32() > now.to_consensus_u32().saturating_add(MAX_DEFER) {
				return Err(ParticipationError::OutOfBounds(format!(
					"the earliest round time is more than {} days ahead", MAX_DEFER / 86_400)));
			}
		}

		// The asset, served, its rate fresh, and every fee in it.
		let asset = d.asset;
		if !p.assets.contains(&asset) {
			return Err(ParticipationError::Assets(format!("asset {} is not served by this operator", asset)));
		}
		// An issuer-operated asset's operator keeps none of it, so it could
		// pay no unclaimed value back to the payer.
		if p.assets.get(&asset).is_some_and(|x| x.issuer.is_some()) {
			return Err(ParticipationError::OutOfBounds(format!("asset {} is issuer-operated here: the operator keeps no unit of it, and a \
				distribution's unclaimed value is paid back from the operator's coins", asset)));
		}
		// A claim leaf is vtxo-1, owned by a key derived from the one the
		// payer names, which names no landing: out of a freeze's reach.
		if p.supervised(&asset).is_some() {
			return Err(ParticipationError::OutOfBounds(format!("asset {} is supervised: a distribution is not served in it, as its \
				claim leaves would be vtxo-1, out of a freeze's reach", asset)));
		}
		if let Some((a, _)) = d.fees.iter().find(|(a, _)| *a != asset) {
			return Err(ParticipationError::Assets(format!("a fee in asset {}: a distribution pays its fee in its own asset, {}", a, asset)));
		}
		p.fresh_rate(&asset).map_err(ParticipationError::Rate)?;

		// Each claim: its value within the bounds, its exit delay within the
		// operator's, its claim key derived here, not the operator's, owning
		// no leaf.
		if !p.exit_delay_ok(d.exit_delay) {
			return Err(ParticipationError::OutOfBounds(format!(
				"an exit delay of {} units; the operator takes {} to {}", d.exit_delay.units(), p.min_exit_delay.units(),
				p.max_exit_delay.units())));
		}
		let mut owners = Vec::with_capacity(d.claims.len());
		let mut seen = BTreeSet::new();
		for (j, c) in d.claims.iter().enumerate() {
			p.check_value(asset, c.value).map_err(|e| ParticipationError::OutOfBounds(format!("claim {}: {}", j, e)))?;
			let owner = c.owner()?;
			if owner == p.operator {
				return Err(ParticipationError::OperatorKey(j));
			}
			if !seen.insert(owner.serialize()) || self.store.key_owns_leaf(&owner.serialize()).await? {
				return Err(ParticipationError::KeyReused);
			}
			owners.push(owner);
		}

		// The return script: an explicit destination, no Arca script.
		let ret = &d.return_script;
		if ret.is_empty() || ret.len() > arca_covenant::offboard::MAX_DESTINATION {
			return Err(ParticipationError::OutOfBounds(format!("a return script of {} bytes; it takes 1 to {}", ret.len(),
				arca_covenant::offboard::MAX_DESTINATION)));
		}
		if !(ret.is_p2pkh() || ret.is_p2sh() || ret.is_v0_p2wpkh() || ret.is_v0_p2wsh() || ret.is_v1_p2tr()) {
			return Err(ParticipationError::OutOfBounds("the return script is no standard address (P2PKH, P2SH, P2WPKH, P2WSH or P2TR): \
				what no holder takes up is paid back on the chain, and a payment the node does not relay is never made".into()));
		}
		if self.store.arca_script(ret.as_bytes()).await?.is_some() {
			return Err(ParticipationError::ReturnScriptReused);
		}

		// The coins given up, each checked and attested over the id.
		let policy = p.participation_policy(now);
		let mut coins = Vec::with_capacity(d.inputs.len());
		let mut dated = Vec::with_capacity(d.inputs.len());
		let mut last_times = Vec::with_capacity(d.inputs.len());
		for (k, (leaf, att)) in d.inputs.iter().zip(&req.attestations).enumerate() {
			let c = coins::check(&self.store, &policy, leaf, &id, coins::BoardDates::Within(Params::PARTICIPATION_HORIZON)).await?;
			if c.coin.leaf.htlc.is_some() {
				return Err(ParticipationError::HtlcInput(k, *leaf));
			}
			if c.coin.asset != asset {
				return Err(ParticipationError::Assets(format!("coin {} is in asset {}, and the distribution pays asset {}: a \
					distribution gives up coins of its own asset alone", leaf, c.coin.asset, asset)));
			}
			if !verify_digest(att, &id, &c.coin.leaf.owner) {
				return Err(ParticipationError::BadAttestation(k));
			}
			let mut last = c.coin.expiry.to_consensus_u32().saturating_sub(Params::PARTICIPATION_HORIZON);
			if let Some(b) = c.board_expiry {
				last = last.min(b.saturating_sub(Params::PARTICIPATION_HORIZON));
			}
			last_times.push(last);
			dated.push((c.coin.value, c.expiry()));
			coins.push(c.coin);
		}
		for (c, leaf) in coins.iter().zip(&d.inputs) {
			let held = self.signer.under(&c.leaf.salt).await.map_err(ParticipationError::Signer)?;
			if let Some(e) = held.first() {
				let (what, why) = match e.kind {
					Signed::Forfeit(_) => ("the forfeit", "a coin under a forfeit the signer holds stays given up"),
					Signed::Spend => ("the spend", "the coin was paid on"),
				};
				return Err(ParticipationError::SignedAlready(format!(
					"coin {}: the operator's signer has already co-signed {} {} under salt {} (entry {}): {}, and is taken in no round; \
					its owner's way home is its exit", leaf, what, hex(&e.digest), hex(&c.leaf.salt), e.n, why)));
			}
		}
		if let Some(t) = d.not_before {
			for (last, leaf) in last_times.iter().zip(&d.inputs) {
				if t.to_consensus_u32() > *last {
					return Err(ParticipationError::OutOfBounds(format!(
						"the earliest round time {} lies past the last time coin {} is taken, {}", t.to_consensus_u32(), leaf, last)));
				}
			}
		}

		// The amounts: the coins hold the claims and the fee, exactly.
		let held: u128 = coins.iter().map(|c| c.value as u128).sum();
		let paid: u64 = d.fees.iter().map(|(_, v)| *v).sum();
		let taken = d.total() + paid as u128;
		if held != taken {
			return Err(ParticipationError::Unbalanced(format!(
				"the coins given up hold {} of asset {}; the claims and the fee take {}", held, asset, taken)));
		}
		let schedule = p.fees(&asset).map_err(ParticipationError::Assets)?;
		let due = distribution_fee(&schedule, &dated, d.claims.len(), now);
		if paid < due {
			return Err(ParticipationError::Fee(format!("a fee of {} in asset {}; the asset's schedule asks {} for a distribution of {} \
				claim(s) from {} coin(s) (each coin's refresh: {} ppm and {} a coin falling to nothing in its free window; {} a claim leaf; \
				{} once, for the return)", paid, asset, due, d.claims.len(), coins.len(), schedule.refresh_ppm, schedule.refresh_base,
				schedule.refresh_base, schedule.offboard_base)));
		}

		// The record: an ordinary participation whose outputs are the claim
		// leaves, and the distribution beside it.
		let refund_delay = p.refund_delay;
		let mut margins = Vec::with_capacity(coins.len());
		for c in &coins {
			margins.push(forfeit_margin(c, refund_delay, self.floor(c.asset).await?));
		}
		let mut preimage = [0u8; 32];
		rand::rngs::OsRng.fill_bytes(&mut preimage);
		let new = NewParticipation {
			id,
			unlock_hash: sha256_bytes(&preimage),
			preimage,
			not_before: d.not_before.map(|t| t.to_consensus_u32()),
			refund_delay_units: refund_delay.units(),
			inputs: d.inputs.iter().zip(&coins).zip(&margins).zip(&req.attestations).map(|(((l, c), margin), att)| ParticipationInput {
				leaf_id: l.0,
				asset: c.asset.into_inner().to_byte_array(),
				value: c.value,
				margin: *margin,
				attestation: *att.as_ref(),
				returned: false,
			}).collect(),
			outputs: d.claims.iter().zip(&owners).map(|(c, owner)| ParticipationOutput {
				asset: asset.into_inner().to_byte_array(),
				value: c.value,
				kind: WantedKind::Leaf {
					template: Template::Vtxo1.to_string(),
					owner_key: owner.serialize(),
					owner_nonce: c.nonce,
					exit_delay_units: d.exit_delay.units(),
					operator_nonce: [0; 32],
					htlc: None,
					order: None,
					landing: None,
				},
				leaf_id: None,
			}).collect(),
			fees: d.fees.iter().map(|(a, v)| (a.into_inner().to_byte_array(), *v)).collect(),
			fill: None,
			distribution: Some(NewDistribution {
				return_script: ret.to_bytes(),
				named: d.claims.iter().map(|c| c.named.serialize()).collect(),
			}),
		};
		match self.store.insert_participation(&new).await {
			Ok(()) => {},
			Err(StoreError::ParticipationExists) => return self.status(&id).await,
			Err(StoreError::LeafSpent(l)) => return Err(CoinError::Spent(l.parse().unwrap_or(d.inputs[0])).into()),
			Err(StoreError::LeafNotLive(l, s)) => return Err(CoinError::NotLive(l.parse().unwrap_or(d.inputs[0]), s).into()),
			Err(e) => return Err(e.into()),
		}
		log::info!("distribution {} accepted: {} coin(s) given up for {} claim(s) of asset {}", hex(&id), coins.len(), d.claims.len(),
			asset);
		self.status(&id).await
	}

	/// Takes a holder's unroll authorisations for the claim leaf `leaf`, one
	/// per node above it from the batch output down, each signed by the
	/// leaf's claim key: the server keeps the leaf's full record (its record
	/// in the tree, the distribution's preimage, the authorisations), which it
	/// resolves a spend of the leaf from. Taken only for a leaf whose
	/// distribution is released, with authorisations the record validates
	/// against the round. A leaf whose record the server holds already is
	/// answered as it stands.
	pub async fn claim_leaf(&self, leaf: &LeafId, auths: Vec<(Signature, MedianTime)>) -> Result<ClaimRow, ParticipationError> {
		let claim = self.store.claim_of_leaf(&leaf.0).await?
			.ok_or(ParticipationError::UnknownClaim(*leaf))?;
		if claim.authorised {
			return Ok(claim);
		}
		if claim.participation_state != ParticipationState::Released {
			return Err(ParticipationError::ClaimNotReleased(*leaf));
		}
		let p = self.store.participation(&claim.participation_id).await?
			.ok_or_else(|| ParticipationError::Internal("a claim's participation is not recorded".into()))?;
		let row = self.store.batch_leaf(&leaf.0).await?
			.ok_or_else(|| ParticipationError::Internal(format!("claim leaf {} is in no batch", leaf)))?;
		let round = self.store.round(row.round_id).await?
			.ok_or_else(|| ParticipationError::Internal(format!("the round of claim leaf {} is not recorded", leaf)))?;
		let round_tx: elements::Transaction = elements::encode::deserialize(&round.tx)
			.map_err(|e| ParticipationError::Internal(e.to_string()))?;
		let coin = crate::coins::batch_coin(&row, p.preimage, auths)
			.map_err(|e| ParticipationError::Internal(format!("claim leaf {}: {}", leaf, e)))?;
		let policy = self.params.taken_policy(self.now().await?);
		let valid = coin.resolve(std::slice::from_ref(&round_tx), &policy)
			.map_err(|e| ParticipationError::Coin(CoinError::InvalidCoin { leaf: *leaf, error: e }))?;
		if valid.id != *leaf {
			return Err(ParticipationError::Internal(format!("the record of leaf {} gives the id {}", leaf, valid.id)));
		}
		let bytes = coin.to_bytes().map_err(|e| ParticipationError::Internal(e.to_string()))?;
		self.store.set_claim_record(&leaf.0, row.round_id, &bytes).await?;
		log::info!("claim leaf {} of distribution {}: its holder's unroll authorisations are in", leaf, hex(&claim.participation_id));
		self.store.claim_of_leaf(&leaf.0).await?.ok_or_else(|| ParticipationError::Internal("the claim is gone".into()))
	}
}

/// The claims of `rows` by distribution, each distribution's in order.
pub fn by_distribution(rows: Vec<ClaimRow>) -> BTreeMap<[u8; 32], Vec<ClaimRow>> {
	let mut out: BTreeMap<[u8; 32], Vec<ClaimRow>> = BTreeMap::new();
	for r in rows {
		out.entry(r.participation_id).or_default().push(r);
	}
	out
}

/// The asset of `row`.
pub fn claim_asset(row: &ClaimRow) -> AssetId {
	AssetId::from_byte_array(row.asset)
}
