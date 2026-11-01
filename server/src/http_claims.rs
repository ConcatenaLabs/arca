//! The routes of claim trees: `distribute`, `distribution_status`, `claims`
//! and `claim_leaf` ([`crate::participations::distributions`]).

use super::*;

use arca_covenant::{Claim, Distribution};

use crate::participations::distributions::DistributionRequest;
use crate::store::{BatchLeafRow, ClaimRow, NurseryState, ParticipationState};

/// The most keys one `claims` lookup names.
pub const MAX_CLAIM_KEYS: usize = 64;

/// The most claims one `claims` answer carries, the newest first.
pub const CLAIMS_PAGE: i64 = 1_000;

/// A claim's state, as `distribution_status` and `claims` name it
/// ([`api::ClaimStatus`]).
pub fn claim_state(c: &ClaimRow) -> &'static str {
	if c.returned_in.is_some() {
		return "returned";
	}
	if c.lapsed_in.is_some() {
		return "lapsed";
	}
	match c.participation_state {
		ParticipationState::Pending | ParticipationState::Issued => return "pending",
		ParticipationState::Released => {},
		other => return other.as_str(),
	}
	// A claim leaf of a released distribution is open whether its holder has
	// handed over its authorisations (live) or not yet (pending).
	match c.leaf_state {
		Some(LeafState::Live) | Some(LeafState::Pending) => "open",
		Some(LeafState::Spent) => "claimed",
		Some(LeafState::Lost) => "lost",
		Some(LeafState::Expired) => "expired",
		None => "pending",
	}
}

/// A claim leaf's state now: [`claim_state`], `lapsing` for an open claim-1
/// leaf whose deadline has passed at `now`, `vesting` for an open vest-1
/// leaf before its vest time.
pub fn claim_state_at(c: &ClaimRow, now: u32) -> &'static str {
	match claim_state(c) {
		"open" if c.lapse.as_ref().is_some_and(|l| now >= l.deadline.to_consensus_u32()) => "lapsing",
		"open" if c.lapse.as_ref().and_then(|l| l.vest).is_some_and(|v| now < v.to_consensus_u32()) => "vesting",
		s => s,
	}
}

/// The take-up deadline of a claim placed in a batch whose first expiry is
/// `expiry` (none without a sweep), lapsing at `lapse`: the earlier.
fn take_up_deadline(expiry: Option<u32>, lapse: Option<u32>) -> Option<u32> {
	match (expiry.map(deadline_of), lapse) {
		(Some(a), Some(b)) => Some(a.min(b)),
		(a, b) => a.or(b),
	}
}

/// The round of `leaf` and the first expiry of its batch (`None` for a
/// batch without a sweep, which never expires).
async fn placed(app: &App, leaf: &BatchLeafRow) -> Result<(String, Option<u32>), Refusal> {
	let round = app.store.round(leaf.round_id).await?
		.ok_or_else(|| Refusal::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("round {} is not recorded", leaf.round_id)))?;
	let batch = app.store.batches(leaf.round_id).await?.into_iter().find(|b| b.vout == leaf.vout)
		.ok_or_else(|| Refusal::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("round {} has no batch at {}", leaf.round_id,
			leaf.vout)))?;
	let schedule = <arca_covenant::ClockSchedule as arca_covenant::encode::Encoding>::decode(&batch.schedule)
		.map_err(|e| Refusal::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()))?;
	Ok((txid_hex(&round.txid), schedule.expiries().first().map(|e| e.to_consensus_u32())))
}

/// The claim leaves' exit deadline, by which the operator takes a claim up:
/// three days before their batch's first expiry.
fn deadline_of(expiry: u32) -> u32 {
	expiry.saturating_sub(arca_covenant::WalletPolicy::EXIT_DEADLINE)
}

pub(super) async fn distribute(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>)
	-> Result<Json<api::ParticipationStatus>, Refusal>
{
	let req: api::Distribute = parse(body, app.max_request)?;
	let mut inputs = Vec::with_capacity(req.inputs.len());
	let mut attestations = Vec::with_capacity(req.inputs.len());
	for i in &req.inputs {
		inputs.push(leaf_id(&i.leaf_id)?);
		attestations.push(sig(&i.attestation)?);
	}
	let mut claims = Vec::with_capacity(req.claims.len());
	for c in &req.claims {
		claims.push(Claim { named: key(&c.key)?, nonce: unhex32(&c.nonce).map_err(Refusal::malformed)?, value: amount(&c.value)? });
	}
	let mut fees = Vec::with_capacity(req.fees.len());
	for f in &req.fees {
		fees.push((asset(&f.asset)?, amount(&f.amount)?));
	}
	let distribution = Distribution {
		inputs,
		asset: asset(&req.asset)?,
		exit_delay: RelativeTime::from_units(req.exit_delay_units).map_err(|e| Refusal::malformed(format!("exit delay: {}", e)))?,
		claims,
		return_script: elements::Script::from(unhex(&req.return_script).map_err(Refusal::malformed)?),
		fees,
		not_before: req.not_before.map(|t| MedianTime::from_consensus(t).map_err(|e| Refusal::malformed(format!("not_before: {}", e))))
			.transpose()?,
		lapse: match (req.deadline, &req.lapse_allowance) {
			(Some(t), Some(a)) => Some(arca_covenant::DistributionLapse {
				deadline: MedianTime::from_consensus(t).map_err(|e| Refusal::malformed(format!("deadline: {}", e)))?,
				allowance: amount(a)?,
				vest: req.vest.map(|v| MedianTime::from_consensus(v).map_err(|e| Refusal::malformed(format!("vest: {}", e)))).transpose()?,
			}),
			(None, None) if req.vest.is_some() => return Err(Refusal::malformed("a vest time comes with a deadline")),
			(None, None) => None,
			_ => return Err(Refusal::malformed("a deadline and a lapse allowance come together")),
		},
	};
	let status = app.participations.distribute(&DistributionRequest { distribution, attestations }).await?;
	Ok(Json(participation_status(&status)))
}

pub(super) async fn distribution_status(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>)
	-> Result<Json<api::DistributionStatus>, Refusal>
{
	let req: api::DistributionStatusRequest = parse(body, app.max_request)?;
	let id = unhex32(&req.distribution_id).map_err(Refusal::malformed)?;
	let d = app.store.distribution(&id).await?.ok_or_else(|| Refusal::new(StatusCode::NOT_FOUND, "unknown_participation",
		format!("no distribution {} is known", hex(&id))))?;
	let p = app.store.participation(&id).await?.ok_or_else(|| Refusal::new(StatusCode::NOT_FOUND, "unknown_participation",
		format!("no distribution {} is known", hex(&id))))?;
	let now = app.store.tip_block().await?.map(|b| b.median_time as u32).unwrap_or(0);
	let lapse = d.claims.first().and_then(|c| c.lapse.clone());
	let mut at = None;
	for c in &d.claims {
		if let Some(l) = c.leaf_id {
			if let Some(row) = app.store.batch_leaf(&l).await? {
				at = Some(placed(&app, &row).await?);
				break;
			}
		}
	}
	let mut returns = Vec::with_capacity(d.returns.len());
	let mut returned: u128 = 0;
	for r in &d.returns {
		let state = match app.store.nursery_get(&r.txid).await? {
			Some(n) => match n.state {
				NurseryState::Pending => "pending",
				NurseryState::Final => "final",
				NurseryState::Lost => "lost",
			},
			None => "recorded",
		};
		returned += r.value as u128;
		returns.push(api::ClaimReturn { txid: txid_hex(&r.txid), value: r.value.to_string(), state: state.into() });
	}
	Ok(Json(api::DistributionStatus {
		distribution_id: hex(&id),
		state: p.state.as_str().into(),
		asset: AssetId::from_byte_array(d.claims.first().map(|c| c.asset).unwrap_or_default()).to_string(),
		return_script: hex(&d.return_script),
		round: at.as_ref().map(|(r, _)| r.clone()),
		expiry: at.as_ref().and_then(|(_, e)| *e),
		deadline: take_up_deadline(at.as_ref().and_then(|(_, e)| *e), lapse.as_ref().map(|l| l.deadline.to_consensus_u32())),
		lapse_deadline: lapse.as_ref().map(|l| l.deadline.to_consensus_u32()),
		lapse_allowance: lapse.as_ref().map(|l| l.allowance.to_string()),
		vest: lapse.as_ref().and_then(|l| l.vest).map(|v| v.to_consensus_u32()),
		claims: d.claims.iter().map(|c| api::ClaimStatus {
			index: c.idx,
			key: hex(&c.named_key),
			owner: hex(&c.owner_key),
			value: c.value.to_string(),
			leaf_id: c.leaf_id.map(|l| LeafId(l).to_string()),
			state: claim_state_at(c, now).into(),
			returned_in: c.returned_in.map(|t| txid_hex(&t)),
			lapsed_in: c.lapsed_in.map(|t| txid_hex(&t)),
		}).collect(),
		returns,
		returned: returned.to_string(),
	}))
}

pub(super) async fn claims(State(app): State<Arc<App>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap,
	body: Result<Bytes, BytesRejection>) -> Result<Json<api::Claims>, Refusal>
{
	let req: api::ClaimsRequest = parse(body, app.max_request)?;
	app.reads.refusal("a claims lookup", app.source(peer.ip(), &headers))?;
	if req.keys.is_empty() || req.keys.len() > MAX_CLAIM_KEYS {
		return Err(Refusal::malformed(format!("{} keys; a claims lookup names 1 to {}", req.keys.len(), MAX_CLAIM_KEYS)));
	}
	let mut keys = Vec::with_capacity(req.keys.len());
	for k in &req.keys {
		let a = api::Auth { key: k.key.clone(), challenge: req.challenge.clone(), signature: k.signature.clone() };
		keys.push(authenticate(&app, "claims", &a, &[]).await?.serialize());
	}
	let rows = app.store.claims_named(&keys, CLAIMS_PAGE).await?;
	let now = app.store.tip_block().await?.map(|b| b.median_time as u32).unwrap_or(0);
	let mut out = Vec::with_capacity(rows.len());
	for c in rows {
		let mut found = api::ClaimFound {
			distribution_id: hex(&c.participation_id),
			index: c.idx,
			key: hex(&c.named_key),
			nonce: hex(&c.owner_nonce),
			owner: hex(&c.owner_key),
			asset: AssetId::from_byte_array(c.asset).to_string(),
			value: c.value.to_string(),
			exit_delay_units: c.exit_delay_units,
			state: claim_state_at(&c, now).into(),
			leaf_id: None, round: None, batch_vout: None, leaf_index: None, record: None, preimage: None, expiry: None, deadline: None,
			lapse_deadline: c.lapse.as_ref().map(|l| l.deadline.to_consensus_u32()),
			vest: c.lapse.as_ref().and_then(|l| l.vest).map(|v| v.to_consensus_u32()),
		};
		// Where the leaf is, its record and the preimage that opens its entry,
		// once the distribution is released: until then the leaf is not
		// credited, and the preimage has not gone out.
		if c.participation_state == ParticipationState::Released {
			if let Some(row) = match c.leaf_id {
				Some(l) => app.store.batch_leaf(&l).await?,
				None => None,
			} {
				let (round, expiry) = placed(&app, &row).await?;
				let p = app.store.participation(&c.participation_id).await?;
				found.leaf_id = Some(LeafId(row.leaf_id).to_string());
				found.round = Some(round);
				found.batch_vout = Some(row.vout);
				found.leaf_index = Some(row.idx);
				found.record = Some(hex(&row.record));
				found.preimage = p.map(|p| hex(&p.preimage));
				found.expiry = expiry;
				found.deadline = take_up_deadline(expiry, c.lapse.as_ref().map(|l| l.deadline.to_consensus_u32()));
			}
		}
		out.push(found);
	}
	Ok(Json(api::Claims { claims: out }))
}

pub(super) async fn claim_leaf(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>)
	-> Result<Json<api::ClaimLeafAnswer>, Refusal>
{
	let req: api::ClaimLeaf = parse(body, app.max_request)?;
	let leaf = leaf_id(&req.leaf_id)?;
	let mut auths = Vec::with_capacity(req.auths.len());
	for a in &req.auths {
		auths.push((sig(&a.signature)?, MedianTime::from_consensus(a.time).map_err(|e| Refusal::malformed(format!("time: {}", e)))?));
	}
	let row = app.participations.claim_leaf(&leaf, auths).await?;
	Ok(Json(api::ClaimLeafAnswer { leaf_id: leaf.to_string(), state: claim_state(&row).into() }))
}
