//! The routes of swept coins: `owed` and `owed_claim` ([`crate::owed`]).

use super::*;

use crate::owed::{ClaimRequest, OwedError};

/// The most keys one `owed` lookup names.
pub const MAX_OWED_KEYS: usize = 64;

impl From<OwedError> for Refusal {
	fn from(e: OwedError) -> Refusal {
		let code = e.code();
		if code == "internal" {
			log::error!("owed: {}", e);
		}
		Refusal::new(status_of(code), code, e.to_string())
	}
}

/// Every coin a final sweep took from the holders of the keys named, each
/// key proven over a fresh challenge: a mailbox key finds every coin bound
/// or posted to it, an owner key its own coin.
pub(super) async fn owed(State(app): State<Arc<App>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap,
	body: Result<Bytes, BytesRejection>) -> Result<Json<api::Owed>, Refusal>
{
	let req: api::OwedRequest = parse(body, app.max_request)?;
	app.reads.refusal("an owed lookup", app.source(peer.ip(), &headers))?;
	if req.keys.is_empty() || req.keys.len() > MAX_OWED_KEYS {
		return Err(Refusal::malformed(format!("{} keys; an owed lookup names 1 to {}", req.keys.len(), MAX_OWED_KEYS)));
	}
	let mut keys = Vec::with_capacity(req.keys.len());
	for k in &req.keys {
		let a = api::Auth { key: k.key.clone(), challenge: req.challenge.clone(), signature: k.signature.clone() };
		keys.push(authenticate(&app, "owed", &a, &[]).await?.serialize());
	}
	let rows = app.store.owed_of(&keys, &keys).await?;
	Ok(Json(api::Owed { owed: rows.iter().map(|o| api::OwedFound {
		leaf_id: LeafId(o.leaf_id).to_string(),
		owner: hex(&o.owner_key),
		owner_nonce: hex(&o.owner_nonce),
		asset: AssetId::from_byte_array(o.asset).to_string(),
		value: o.value.to_string(),
		fee: o.fee.to_string(),
		owed: o.owed().to_string(),
		sweep_txid: txid_hex(&o.sweep_txid),
		state: o.state.as_str().into(),
		participation_id: o.participation_id.map(|p| hex(&p)),
	}).collect() }))
}

/// Claims what is owed for a swept coin as one new leaf, signed by the coin's
/// owner key; answered with the repayment participation's status, which the
/// wallet then follows as any participation of its own.
pub(super) async fn owed_claim(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>)
	-> Result<Json<api::ParticipationStatus>, Refusal>
{
	let req: api::OwedClaim = parse(body, app.max_request)?;
	let l = &req.leaf;
	let owner = key(&l.owner)?;
	let leaf = part::OutputRequest::Leaf {
		asset: asset(&l.asset)?,
		value: amount(&l.value)?,
		template: l.template.parse().map_err(|e| Refusal::new(StatusCode::UNPROCESSABLE_ENTITY, "template",
			format!("template {:?}: {}", l.template, e)))?,
		owner,
		owner_nonce: unhex32(&l.owner_nonce).map_err(Refusal::malformed)?,
		exit_delay: RelativeTime::from_units(l.exit_delay_units).map_err(|e| Refusal::malformed(format!("exit delay: {}", e)))?,
		order: None,
		landing: landing_of(&l.landing)?,
		channel: None,
	};
	if l.order.is_some() || l.channel.is_some() {
		return Err(OwedError::Template(l.template.clone()).into());
	}
	let key_proof = sig(l.key_proof.as_deref().ok_or_else(|| Refusal::malformed("the leaf wanted carries no key proof"))?)?;
	let binding = binding(&app, &owner, l.mailbox.as_deref(), l.mailbox_proof.as_deref())?;
	let id = crate::owed::claim(&app.store, &app.params, &ClaimRequest { coin: leaf_id(&req.leaf_id)?, leaf, key_proof,
		signature: sig(&req.signature)? }).await?;
	if let Some((mailbox, proof)) = binding {
		app.store.bind_mailbox(&owner.serialize(), &mailbox.serialize(), proof.as_ref()).await?;
	}
	Ok(Json(participation_status(&app.participations.status(&id).await?)))
}
