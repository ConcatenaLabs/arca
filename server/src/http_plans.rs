//! The routes of offline refresh: `plan_quote`, `submit_plan`,
//! `plan_status`, `plans`, `cancel_plan` and `plan_leaf` ([`crate::plans`]).

use super::*;

use arca_covenant::plan::PlanStep;

use crate::plans::{PlanError, PlanStatus, QuoteRequest, SubmitRequest};

impl From<PlanError> for Refusal {
	fn from(e: PlanError) -> Refusal {
		let code = e.code();
		if code == "internal" {
			log::error!("plans: {}", e);
		}
		Refusal::new(status_of(code), code, e.to_string())
	}
}

fn plan_json(s: &PlanStatus) -> api::PlanStatus {
	api::PlanStatus {
		plan_id: hex(&s.row.plan_id),
		coin: hex(&s.row.coin),
		asset: AssetId::from_byte_array(s.row.asset).to_string(),
		value: s.row.value.to_string(),
		state: s.row.state.as_str().into(),
		reason: s.row.reason.clone(),
		steps: s.steps.iter().zip(&s.row.steps).map(|(st, row)| api::PlanStepStatus {
			idx: st.idx,
			state: st.state.as_str().into(),
			reason: st.reason.clone(),
			value: row.step.value.to_string(),
			fee: row.step.fee.to_string(),
			owner: hex(&row.step.owner_key),
			owner_nonce: hex(&row.step.owner_nonce),
			operator_nonce: hex(&row.step.operator_nonce),
			exit_delay_units: row.step.exit_delay_units,
			unlock_hash: hex(&row.step.unlock_hash),
			holder_script: hex(&row.step.holder_script),
			participation_id: st.participation.map(|p| hex(&p)),
			gives_up: st.gives_up.map(|l| hex(&l)),
			round_txid: st.round.as_ref().map(|(t, _)| t.to_string()),
			round_state: st.round.as_ref().map(|(_, s)| s.clone()),
			leaf_id: st.leaf_id.map(|l| hex(&l)),
			batch_vout: st.batch_vout,
			leaf_index: st.leaf_index,
			record: st.record.as_ref().map(|r| hex(r)),
		}).collect(),
	}
}

fn script(s: &str) -> Result<elements::Script, Refusal> {
	Ok(elements::Script::from(unhex(s).map_err(Refusal::malformed)?))
}

pub(super) async fn plan_quote(State(app): State<Arc<App>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap,
	body: Result<Bytes, BytesRejection>) -> Result<Json<api::PlanQuote>, Refusal>
{
	let req: api::PlanQuoteRequest = parse(body, app.max_request)?;
	app.nonces.refusal("a plan quote", app.source(peer.ip(), &headers))?;
	let mut owner_nonces = Vec::with_capacity(req.owner_nonces.len());
	for n in &req.owner_nonces {
		owner_nonces.push(unhex32(n).map_err(Refusal::malformed)?);
	}
	let q = app.plans.quote(&QuoteRequest {
		coin: leaf_id(&req.coin)?,
		owner_nonces,
		exit_delay: RelativeTime::from_units(req.exit_delay_units).map_err(|e| Refusal::malformed(format!("exit delay: {}", e)))?,
		attestation: sig(&req.attestation)?,
	}).await?;
	Ok(Json(api::PlanQuote {
		quote: hex(&q.quote),
		coin: q.coin.to_string(),
		asset: q.asset.to_string(),
		value: q.value.to_string(),
		expiry: q.expiry.to_consensus_u32(),
		earliest: q.earliest,
		operator_script: hex(q.operator_script.as_bytes()),
		steps: q.steps.iter().map(|s| api::PlanQuoteStep {
			operator_nonce: hex(&s.operator_nonce), fee: s.fee.to_string(), margin: s.margin.to_string(),
		}).collect(),
	}))
}

pub(super) async fn submit_plan(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Result<Json<api::PlanStatus>, Refusal> {
	let req: api::SubmitPlan = parse(body, app.max_request)?;
	let mut steps = Vec::with_capacity(req.steps.len());
	let (mut key_proofs, mut halves, mut preimages, mut mailbox_proofs) = (vec![], vec![], vec![], vec![]);
	for s in &req.steps {
		steps.push(PlanStep {
			value: amount(&s.value)?,
			fee: amount(&s.fee)?,
			owner: key(&s.owner)?,
			owner_nonce: unhex32(&s.owner_nonce).map_err(Refusal::malformed)?,
			operator_nonce: unhex32(&s.operator_nonce).map_err(Refusal::malformed)?,
			exit_delay: RelativeTime::from_units(s.exit_delay_units).map_err(|e| Refusal::malformed(format!("exit delay: {}", e)))?,
			unlock_hash: unhex32(&s.unlock_hash).map_err(Refusal::malformed)?,
			holder_script: script(&s.holder_script)?,
			operator_script: script(&s.operator_script)?,
			margin: amount(&s.margin)?,
		});
		key_proofs.push(sig(&s.key_proof)?);
		halves.push((sig(&s.old_half)?, sig(&s.new_half)?));
		preimages.push(unhex32(&s.preimage).map_err(Refusal::malformed)?);
		mailbox_proofs.push(sig(&s.mailbox_proof)?);
	}
	let status = app.plans.submit(&SubmitRequest {
		quote: unhex32(&req.quote).map_err(Refusal::malformed)?,
		coin: leaf_id(&req.coin)?,
		steps,
		mailbox: key(&req.mailbox)?,
		attestation: sig(&req.attestation)?,
		key_proofs, halves, preimages, mailbox_proofs,
	}).await?;
	Ok(Json(plan_json(&status)))
}

pub(super) async fn plan_status(State(app): State<Arc<App>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap,
	body: Result<Bytes, BytesRejection>) -> Result<Json<api::PlanStatus>, Refusal>
{
	let req: api::PlanStatusRequest = parse(body, app.max_request)?;
	app.reads.refusal("a plan's status", app.source(peer.ip(), &headers))?;
	let id = unhex32(&req.plan_id).map_err(Refusal::malformed)?;
	Ok(Json(plan_json(&app.plans.status(&id).await?)))
}

pub(super) async fn plans(State(app): State<Arc<App>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap,
	body: Result<Bytes, BytesRejection>) -> Result<Json<api::PlanList>, Refusal>
{
	let req: api::PlansRequest = parse(body, app.max_request)?;
	app.reads.refusal("a read of a key's plans", app.source(peer.ip(), &headers))?;
	let k = authenticate(&app, "plans", &req.auth, &[]).await?;
	let list = app.plans.of_mailbox(&k).await?;
	Ok(Json(api::PlanList { plans: list.iter().map(plan_json).collect() }))
}

pub(super) async fn cancel_plan(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Result<Json<api::PlanStatus>, Refusal> {
	let req: api::CancelPlan = parse(body, app.max_request)?;
	let id = unhex32(&req.plan_id).map_err(Refusal::malformed)?;
	Ok(Json(plan_json(&app.plans.cancel(&id, &sig(&req.signature)?).await?)))
}

pub(super) async fn plan_leaf(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Result<Json<api::Empty>, Refusal> {
	let req: api::PlanLeaf = parse(body, app.max_request)?;
	let mut auths = Vec::with_capacity(req.auths.len());
	for a in &req.auths {
		auths.push((sig(&a.signature)?, MedianTime::from_consensus(a.time).map_err(|e| Refusal::malformed(format!("time: {}", e)))?));
	}
	app.plans.hand_over(&leaf_id(&req.leaf_id)?, auths).await?;
	Ok(Json(api::Empty {}))
}
