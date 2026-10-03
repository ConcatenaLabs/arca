//! JSON over HTTP: the interface a wallet speaks.
//!
//! Every call is under `/v1/`, so the server can sit behind one same-origin
//! path of a reverse proxy, which terminates TLS. Every request body is
//! bounded before it is read, let alone parsed: a body over the limit is
//! refused with 413 whatever it holds. Every refusal is a JSON object with a
//! stable code and a sentence (`api::ErrorBody`).
//!
//! | Call | Method | Authenticated |
//! |---|---|---|
//! | `info` | GET | no |
//! | `operator_nonce` | POST | no |
//! | `challenge` | POST | no |
//! | `register_board`, `board_status` | POST | no |
//! | `cosign_transfer` | POST | by the owners' signatures over the transfer itself |
//! | `mailbox_read`, `leaf_data` | POST | by a challenge signed with the key ([`crate::auth`]) |

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use elements::encode::deserialize;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Transaction};
use serde::de::DeserializeOwned;

use arca_covenant::{BoardRecord, LeafId, NewLeaf, RelativeTime};

use crate::api;
use crate::auth;
use crate::boards::{BoardError, BoardStatus, Boards};
use crate::chain::{Certification, Finality};
use crate::cosign::{CosignError, Cosigner, InputRequest, OutputRequest, TransferRequest};
use crate::params::Params;
use crate::signer::{hex, parse_amount, unhex, unhex32};
use crate::store::{ChallengeError, LeafKind, LeafState, Store};

/// What the HTTP handlers reach.
pub struct App {
	pub store: Store,
	pub params: Arc<Params>,
	pub boards: Arc<Boards>,
	pub cosigner: Arc<Cosigner>,
	pub certification: Certification,
	pub anchor_depth: u32,
	pub max_request: usize,
	pub challenge_ttl: Duration,
}

/// A refusal, as the client sees it.
#[derive(Debug)]
pub struct Refusal {
	pub status: StatusCode,
	pub code: String,
	pub message: String,
}

impl Refusal {
	fn new(status: StatusCode, code: &str, message: impl Into<String>) -> Refusal {
		Refusal { status, code: code.into(), message: message.into() }
	}

	fn malformed(message: impl Into<String>) -> Refusal {
		Refusal::new(StatusCode::BAD_REQUEST, "malformed", message)
	}
}

impl IntoResponse for Refusal {
	fn into_response(self) -> Response {
		let body = api::ErrorBody { error: api::ErrorDetail { code: self.code, message: self.message } };
		(self.status, Json(body)).into_response()
	}
}

/// The status a refusal code is answered with.
fn status_of(code: &str) -> StatusCode {
	match code {
		"malformed" | "invalid_record" | "invalid_transaction" => StatusCode::BAD_REQUEST,
		"unauthenticated" => StatusCode::UNAUTHORIZED,
		"unknown_leaf" | "unknown_board" => StatusCode::NOT_FOUND,
		"double_spend" | "nonce_used" | "key_reused" | "script_reused" | "board_exists" => StatusCode::CONFLICT,
		"request_too_large" => StatusCode::PAYLOAD_TOO_LARGE,
		"signer_unavailable" | "not_synced" => StatusCode::SERVICE_UNAVAILABLE,
		"internal" => StatusCode::INTERNAL_SERVER_ERROR,
		_ => StatusCode::UNPROCESSABLE_ENTITY,
	}
}

impl From<BoardError> for Refusal {
	fn from(e: BoardError) -> Refusal {
		let code = e.code();
		if code == "internal" {
			log::error!("register_board: {}", e);
		}
		Refusal::new(status_of(code), code, e.to_string())
	}
}

impl From<CosignError> for Refusal {
	fn from(e: CosignError) -> Refusal {
		let code = e.code();
		if code == "internal" {
			log::error!("cosign_transfer: {}", e);
		}
		Refusal::new(status_of(code), code, e.to_string())
	}
}

impl From<crate::store::StoreError> for Refusal {
	fn from(e: crate::store::StoreError) -> Refusal {
		log::error!("store: {}", e);
		Refusal::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "the server's database failed")
	}
}

/// Parses a body that came through the size bound: a body over it never
/// reaches this point.
fn parse<T: DeserializeOwned>(body: Result<Bytes, BytesRejection>, limit: usize) -> Result<T, Refusal> {
	let body = match body {
		Ok(b) => b,
		Err(e) if e.status() == StatusCode::PAYLOAD_TOO_LARGE => {
			return Err(Refusal::new(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large",
				format!("the request body is over {} bytes and was not read", limit)));
		},
		Err(e) => return Err(Refusal::malformed(e.body_text())),
	};
	serde_json::from_slice(&body).map_err(|e| Refusal::malformed(format!("the request is not the expected JSON: {}", e)))
}

fn key(s: &str) -> Result<XOnlyPublicKey, Refusal> {
	XOnlyPublicKey::from_slice(&unhex(s).map_err(Refusal::malformed)?).map_err(|e| Refusal::malformed(format!("key: {}", e)))
}

fn sig(s: &str) -> Result<Signature, Refusal> {
	Signature::from_slice(&unhex(s).map_err(Refusal::malformed)?).map_err(|e| Refusal::malformed(format!("signature: {}", e)))
}

fn leaf_id(s: &str) -> Result<LeafId, Refusal> {
	Ok(LeafId(unhex32(s).map_err(Refusal::malformed)?))
}

fn asset(s: &str) -> Result<AssetId, Refusal> {
	AssetId::from_str(s).map_err(|e| Refusal::malformed(format!("asset: {}", e)))
}

fn amount(s: &str) -> Result<u64, Refusal> {
	parse_amount(s).map_err(Refusal::malformed)
}

/// Checks a proof of `auth.key` for `call` and uses up its challenge.
async fn authenticate(app: &App, call: &str, a: &api::Auth) -> Result<XOnlyPublicKey, Refusal> {
	let k = key(&a.key)?;
	let challenge = unhex32(&a.challenge).map_err(Refusal::malformed)?;
	let signature = sig(&a.signature)?;
	let unauthenticated = |m: String| Refusal::new(StatusCode::UNAUTHORIZED, "unauthenticated", m);
	match app.store.use_challenge(&challenge).await? {
		Ok(()) => {},
		Err(ChallengeError::Unknown) => return Err(unauthenticated("the challenge was not issued by this server".into())),
		Err(ChallengeError::Used) => return Err(unauthenticated("the challenge has already been used".into())),
		Err(ChallengeError::Expired) => return Err(unauthenticated("the challenge has expired".into())),
	}
	if !auth::verify(&app.params.chain, call, &challenge, &k, &signature) {
		return Err(unauthenticated(format!("the signature does not prove the key for {}", call)));
	}
	Ok(k)
}

fn finality_name(f: &Finality) -> String {
	f.name().to_string()
}

fn board_status(s: &BoardStatus) -> api::BoardStatus {
	api::BoardStatus {
		leaf_id: s.leaf_id.to_string(),
		txid: s.txid.to_string(),
		vout: s.vout,
		state: match s.state {
			crate::store::BoardState::Pending => "pending",
			crate::store::BoardState::Credited => "credited",
			crate::store::BoardState::Lost => "lost",
		}.into(),
		finality: finality_name(&s.finality),
	}
}

async fn info(State(app): State<Arc<App>>) -> Json<api::Info> {
	let p = &app.params;
	Json(api::Info {
		operator: hex(&p.operator.serialize()),
		genesis_hash: p.chain.genesis_hash().to_string(),
		assets: p.assets.iter().map(|(a, ap)| api::AssetInfo { asset: a.to_string(), min_leaf: ap.min_leaf.to_string() }).collect(),
		exit_delay_units: api::Bounds { min: p.min_exit_delay.units() as u32, max: p.max_exit_delay.units() as u32 },
		depth_limit: p.depth_limit as u32,
		finality: api::FinalityInfo {
			certification: match app.certification {
				Certification::Required => "required",
				Certification::NotOnThisChain => "none",
			}.into(),
			anchor_depth: app.anchor_depth,
		},
		templates: api::TemplatesInfo { version: 1, list: vec!["vtxo-1".into(), "board-1".into()] },
		fees: api::FeesInfo { transfer: "0".into() },
		max_request_bytes: app.max_request as u64,
	})
}

async fn operator_nonce(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Result<Json<api::NonceResponse>, Refusal> {
	let _: api::Empty = parse(body, app.max_request)?;
	let n = app.store.issue_nonce().await?;
	Ok(Json(api::NonceResponse { operator_nonce: hex(&n) }))
}

async fn challenge(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Result<Json<api::ChallengeResponse>, Refusal> {
	let _: api::Empty = parse(body, app.max_request)?;
	let c = app.store.issue_challenge(app.challenge_ttl).await?;
	Ok(Json(api::ChallengeResponse { challenge: hex(&c), expires_in_seconds: app.challenge_ttl.as_secs() }))
}

async fn register_board(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Result<Json<api::BoardStatus>, Refusal> {
	let req: api::RegisterBoard = parse(body, app.max_request)?;
	let record = BoardRecord::from_bytes(&unhex(&req.record).map_err(Refusal::malformed)?)
		.map_err(|e| Refusal::new(StatusCode::BAD_REQUEST, "invalid_record", format!("the board record: {}", e)))?;
	let tx: Transaction = deserialize(&unhex(&req.tx).map_err(Refusal::malformed)?)
		.map_err(|e| Refusal::new(StatusCode::BAD_REQUEST, "invalid_transaction", format!("the board transaction: {}", e)))?;
	let status = app.boards.register(&record, &tx).await?;
	Ok(Json(board_status(&status)))
}

async fn board_status_call(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Result<Json<api::BoardStatus>, Refusal> {
	let req: api::BoardStatusRequest = parse(body, app.max_request)?;
	let id = leaf_id(&req.leaf_id)?;
	match app.boards.status(&id).await? {
		Some(s) => Ok(Json(board_status(&s))),
		None => Err(Refusal::new(StatusCode::NOT_FOUND, "unknown_board", format!("no board {} is registered", id))),
	}
}

async fn cosign_transfer(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Result<Json<api::Cosigned>, Refusal> {
	let req: api::CosignTransfer = parse(body, app.max_request)?;
	let mut inputs = Vec::with_capacity(req.inputs.len());
	for i in &req.inputs {
		inputs.push(InputRequest {
			leaf_id: leaf_id(&i.leaf_id)?,
			checkpoint_value: amount(&i.checkpoint_value)?,
			checkpoint_sig: sig(&i.checkpoint_sig)?,
			reassignment_sig: sig(&i.reassignment_sig)?,
		});
	}
	let mut outputs = Vec::with_capacity(req.outputs.len());
	for o in &req.outputs {
		outputs.push(OutputRequest {
			asset: asset(&o.asset)?,
			value: amount(&o.value)?,
			leaf: NewLeaf {
				owner: key(&o.owner)?,
				owner_nonce: unhex32(&o.owner_nonce).map_err(Refusal::malformed)?,
				operator_nonce: unhex32(&o.operator_nonce).map_err(Refusal::malformed)?,
				exit_delay: RelativeTime::from_units(o.exit_delay_units)
					.map_err(|e| Refusal::malformed(format!("exit delay: {}", e)))?,
			},
			mailbox: o.mailbox.as_deref().map(key).transpose()?,
		});
	}
	let done = app.cosigner.cosign(&TransferRequest { inputs, outputs }).await?;
	Ok(Json(api::Cosigned {
		transfer_id: hex(&done.transfer_id),
		signatures: done.signatures.iter().map(|(cp, re)| api::OperatorSignatures {
			checkpoint: hex(cp.as_ref()), reassignment: hex(re.as_ref()),
		}).collect(),
		outputs: done.outputs.iter().map(|(id, r)| Ok(api::Coin {
			leaf_id: id.to_string(),
			record: hex(&r.to_bytes().map_err(|e| Refusal::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()))?),
		})).collect::<Result<_, Refusal>>()?,
	}))
}

/// The most messages one read returns.
pub const MAILBOX_PAGE: u32 = 100;

async fn mailbox_read(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Result<Json<api::Mailbox>, Refusal> {
	let req: api::MailboxRead = parse(body, app.max_request)?;
	let after: i64 = if req.after == "0" { 0 } else {
		i64::try_from(amount(&req.after)?).map_err(|_| Refusal::malformed("cursor out of range"))?
	};
	let k = authenticate(&app, "mailbox_read", &req.auth).await?;
	let limit = req.limit.clamp(1, MAILBOX_PAGE) as i64;
	let msgs = app.store.mailbox_read(&k.serialize(), after, limit).await?;
	Ok(Json(api::Mailbox {
		messages: msgs.into_iter().map(|m| api::MailboxMessage {
			cursor: m.cursor.to_string(),
			kind: m.kind,
			leaf_id: m.leaf_id.map(|l| hex(&l)).unwrap_or_default(),
			record: hex(&m.payload),
		}).collect(),
	}))
}

async fn leaf_data(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Result<Json<api::LeafData>, Refusal> {
	let req: api::LeafDataRequest = parse(body, app.max_request)?;
	let k = authenticate(&app, "leaf_data", &req.auth).await?;
	let rows = app.store.leaves_by_owner(&k.serialize()).await?;
	Ok(Json(api::LeafData {
		leaves: rows.into_iter().map(|r| api::LeafEntry {
			leaf_id: hex(&r.leaf_id),
			kind: match r.kind {
				LeafKind::Board => "board",
				LeafKind::Batch => "batch",
				LeafKind::Transfer => "transfer",
			}.into(),
			state: match r.state {
				LeafState::Pending => "pending",
				LeafState::Live => "live",
				LeafState::Spent => "spent",
				LeafState::Lost => "lost",
			}.into(),
			asset: AssetId::from_byte_array(r.asset).to_string(),
			value: r.value.to_string(),
			record: hex(&r.record),
		}).collect(),
	}))
}

/// The server's routes, every body bounded to `app.max_request` bytes.
pub fn router(app: Arc<App>) -> Router {
	let limit = app.max_request;
	Router::new()
		.route("/v1/info", get(info))
		.route("/v1/operator_nonce", post(operator_nonce))
		.route("/v1/challenge", post(challenge))
		.route("/v1/register_board", post(register_board))
		.route("/v1/board_status", post(board_status_call))
		.route("/v1/cosign_transfer", post(cosign_transfer))
		.route("/v1/mailbox_read", post(mailbox_read))
		.route("/v1/leaf_data", post(leaf_data))
		.layer(DefaultBodyLimit::max(limit))
		.with_state(app)
}
