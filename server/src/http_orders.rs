//! The routes of resting orders: `order_publish`, `order_fill` and
//! `order_state` ([`crate::orders`]).

use super::*;

use arca_covenant::CoinRecord;

use crate::orders::{FillRequest, OrderError, OrderView, PublishRequest};

impl From<OrderError> for Refusal {
	fn from(e: OrderError) -> Refusal {
		let code = e.code();
		if code == "internal" {
			log::error!("orders: {}", e);
		}
		Refusal::new(status_of(code), code, e.to_string())
	}
}

fn internal<E: std::fmt::Display>(e: E) -> Refusal {
	Refusal::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string())
}

/// An order as `order_state` shows it.
async fn order_json(app: &App, v: &OrderView) -> Result<api::OrderState, Refusal> {
	let p = &v.policy;
	let resting = matches!(v.state(), "resting" | "exhausted");
	let record = if resting {
		// The record a fill carries: the maker's for the order's first coin.
		if v.order.current_leaf == v.order.order_id {
			Some(hex(&v.order.record))
		} else {
			app.store.leaf(&v.order.current_leaf).await?.map(|r| hex(&r.record))
		}
	} else {
		None
	};
	Ok(api::OrderState {
		order: hex(&v.order.order_id),
		state: v.state().into(),
		coin: hex(&v.order.current_leaf),
		asset: p.terms().asset_a.to_string(),
		value: v.value.to_string(),
		owner: hex(&p.owner.serialize()),
		salt: hex(&p.salt),
		exit_delay_units: p.exit_delay.units(),
		terms: arca_covenant::record_json::order_terms_json(&p.leaf_terms()),
		fills_left: p.fills_left() as u8,
		expiry: v.expiry,
		record,
		fills: v.fills.iter().map(|f| api::OrderFillState {
			transfer_id: hex(&f.transfer_id),
			coin: hex(&f.order_leaf),
			filled: f.filled.to_string(),
			credited: f.credited.to_string(),
			partial: f.partial,
			signed: f.signature.is_some(),
		}).collect(),
	})
}

pub(super) async fn order_publish(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Result<Json<api::OrderState>, Refusal> {
	let req: api::OrderPublish = parse(body, app.max_request)?;
	let record = CoinRecord::from_bytes(&unhex(&req.record).map_err(Refusal::malformed)?)
		.map_err(|e| Refusal::malformed(format!("record: {}", e)))?;
	if req.credit_nonces.len() != 4 {
		return Err(Refusal::malformed(format!("{} credit nonces; an order names four", req.credit_nonces.len())));
	}
	let mut credit_nonces = [[0u8; 32]; 4];
	for (i, n) in req.credit_nonces.iter().enumerate() {
		credit_nonces[i] = unhex32(n).map_err(Refusal::malformed)?;
	}
	let v = app.orders.publish(&PublishRequest { record, credit_nonces, mailbox: key(&req.mailbox)?, signature: sig(&req.signature)? }).await?;
	Ok(Json(order_json(&app, &v).await?))
}

pub(super) async fn order_fill(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Result<Json<api::OrderFilled>, Refusal> {
	let req: api::OrderFill = parse(body, app.max_request)?;
	let t = transfer_request(&req.inputs, &req.outputs)?;
	let done = app.orders.fill(&FillRequest {
		order: leaf_id(&req.order)?, coin: leaf_id(&req.coin)?, filled: amount(&req.filled)?, inputs: t.inputs, outputs: t.outputs,
	}).await?;
	Ok(Json(api::OrderFilled {
		transfer_id: hex(&done.transfer_id),
		fill_signature: hex(done.fill_signature.as_ref()),
		signatures: done.signatures.iter().map(|(cp, re)| api::OperatorSignatures {
			checkpoint: hex(cp.as_ref()), reassignment: hex(re.as_ref()),
		}).collect(),
		outputs: done.outputs.iter().map(|(id, r)| Ok(api::Coin { leaf_id: id.to_string(), record: hex(&r.to_bytes().map_err(internal)?) }))
			.collect::<Result<_, Refusal>>()?,
		signer_record: match done.signer_head {
			Some((entry, h, s)) => Some(head_with_acks(&app, entry, &h, Some(&s)).await?),
			None => None,
		},
	}))
}

/// The transfer id of the fill a request names, by its transfer id or by the
/// order coin it spent.
async fn fill_named(app: &App, transfer_id: &Option<String>, order_coin: &Option<String>) -> Result<[u8; 32], Refusal> {
	match (transfer_id, order_coin) {
		(Some(t), None) => unhex32(t).map_err(Refusal::malformed),
		(None, Some(o)) => {
			let id = leaf_id(o)?;
			match app.store.order_fill_of(&id.0).await.map_err(internal)? {
				Some(f) => Ok(f.transfer_id),
				None => Err(OrderError::UnknownFill(format!("of order coin {}", id)).into()),
			}
		},
		_ => Err(Refusal::malformed("a fill is named by its transfer_id or its order_coin, one of the two")),
	}
}

/// What the maker of a filled order signs its order coin's delegation into
/// the fill over ([`crate::orders::Orders::delegation_terms`]).
pub(super) async fn order_fill_delegation_terms(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>)
	-> Result<Json<api::FillDelegationTerms>, Refusal>
{
	let req: api::FillRef = parse(body, app.max_request)?;
	let transfer = fill_named(&app, &req.transfer_id, &req.order_coin).await?;
	let t = app.orders.delegation_terms(&transfer).await?;
	Ok(Json(api::FillDelegationTerms {
		transfer_id: hex(&t.transfer_id),
		order_coin: t.order_coin.to_string(),
		takers: t.takers.iter().map(|l| api::FillTakerLeaf {
			owner: hex(&l.owner.serialize()), owner_nonce: hex(&l.owner_nonce), creator_nonce: hex(&l.creator_nonce),
			exit_delay_units: l.exit_delay.units(),
		}).collect(),
		delegated: t.delegated,
	}))
}

/// Takes a maker's delegation of its order coin into a fill
/// ([`crate::orders::Orders::delegate`]).
pub(super) async fn order_fill_delegation(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>)
	-> Result<Json<api::FillDelegated>, Refusal>
{
	let req: api::FillDelegation = parse(body, app.max_request)?;
	let transfer = fill_named(&app, &req.transfer_id, &req.order_coin).await?;
	let kept = app.orders.delegate(&transfer, &sig(&req.signature)?).await?;
	Ok(Json(api::FillDelegated { transfer_id: hex(&transfer), kept }))
}

/// How resting orders stand: anyone may read it, a relay included.
pub(super) async fn order_state(State(app): State<Arc<App>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap,
	body: Result<Bytes, BytesRejection>) -> Result<Json<api::OrderStates>, Refusal>
{
	let req: api::OrderStateRequest = parse(body, app.max_request)?;
	app.reads.refusal("a read of resting orders", app.source(peer.ip(), &headers))?;
	if req.orders.len() > ORDERS_PER_READ {
		return Err(Refusal::malformed(format!("{} orders; a read names at most {}", req.orders.len(), ORDERS_PER_READ)));
	}
	let ids = req.orders.iter().map(|o| leaf_id(o)).collect::<Result<Vec<_>, _>>()?;
	let mut orders = vec![];
	for v in app.orders.state(&ids).await? {
		orders.push(order_json(&app, &v).await?);
	}
	Ok(Json(api::OrderStates { orders }))
}

/// The most orders one `order_state` read names.
pub const ORDERS_PER_READ: usize = 100;
