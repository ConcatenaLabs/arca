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
//! | `operator_nonce` | POST | no: issued at a bounded rate, overall and for each source ([`Limiter`]) |
//! | `challenge` | POST | no: issued at a bounded rate, overall and for each source ([`Limiter`]) |
//! | `register_board`, `board_status` | POST | no |
//! | `cosign_transfer` | POST | by the owners' signatures over the transfer itself |
//! | `submit_participation` | POST | by each owner's attestation over the participation |
//! | `participation_status` | POST | no: the id is the hash of the request |
//! | `tree` | POST | no: the operator publishes every tree |
//! | `forfeit_leaves` | POST | by each owner's signatures over the forfeits themselves |
//! | `release_leaves` | POST | by each owner's signature over the release itself |
//! | `mailbox_read`, `leaf_data` | POST | by a challenge signed with the key ([`crate::auth`]) |

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use elements::encode::deserialize;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Transaction};
use serde::de::DeserializeOwned;

use arca_covenant::{BoardRecord, LeafId, MedianTime, NewLeaf, RelativeTime};

use crate::api;
use crate::auth;
use crate::boards::{BoardError, BoardStatus, Boards};
use crate::chain::{Certification, Finality};
use crate::cosign::{CosignError, Cosigner, InputRequest, OutputRequest, TransferRequest};
use crate::params::{FeeSchedule, Params};
use crate::forfeits::{AuthsRequest, ForfeitError, ForfeitLeaves, ForfeitRequest, Forfeits, ReleaseRequest};
use crate::rounds::{RoundError, Rounds};
use crate::participations::{self as part, ParticipationError, ParticipationRequest, Participations, Status};
use crate::signer::{hex, parse_amount, unhex, unhex32};
use crate::auth::ChallengeError;
use crate::store::{LeafKind, LeafState, Store, WantedKind};

/// What the HTTP handlers reach.
pub struct App {
	pub store: Store,
	pub params: Arc<Params>,
	pub boards: Arc<Boards>,
	pub cosigner: Arc<Cosigner>,
	pub participations: Arc<Participations>,
	pub rounds: Arc<Rounds>,
	pub forfeits: Arc<Forfeits>,
	pub certification: Certification,
	pub anchor_depth: u32,
	pub max_request: usize,
	pub challenge_ttl: Duration,
	/// Bounds the operator nonces handed out.
	pub nonces: Limiter,
	/// The key of every challenge's check ([`crate::auth`]), drawn when the
	/// server starts.
	pub challenge_key: [u8; 32],
	/// The addresses of the reverse proxies whose forwarded address names a
	/// request's source.
	pub trusted_proxies: Vec<IpAddr>,
	/// The floors `info` last published, and when: asked of the node at most
	/// once every [`FLOORS_FOR`].
	pub floors: tokio::sync::Mutex<Option<(Instant, Vec<api::FloorInfo>)>>,
	/// The signer's record head `info` last published, and when.
	pub record_head: tokio::sync::Mutex<Option<(Instant, (u64, [u8; 32]))>>,
}

/// How long `info` publishes the floors it read from the node before it reads
/// them again.
pub const FLOORS_FOR: Duration = Duration::from_secs(5);

/// The operator's node's floor in every asset served, as `info` publishes
/// it; `None` when the node does not answer.
async fn floors(app: &App) -> Option<Vec<api::FloorInfo>> {
	let mut cached = app.floors.lock().await;
	if let Some((at, f)) = cached.as_ref() {
		if at.elapsed() < FLOORS_FOR {
			return Some(f.clone());
		}
	}
	let mut out = vec![];
	for asset in app.params.assets.keys() {
		match crate::fees::floor_per_kvb(app.cosigner.finality(), *asset).await {
			Ok(f) => out.push(api::FloorInfo { asset: asset.to_string(), floor_per_kvb: f.map(|f| f.to_string()) }),
			Err(e) => {
				log::warn!("info: the node's floor in asset {}: {}", asset, e);
				return None;
			},
		}
	}
	*cached = Some((Instant::now(), out.clone()));
	Some(out)
}

impl App {
	/// Where a request comes from, as the limits count it ([`source_of`]).
	pub fn source(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
		source_of(peer, headers, &self.trusted_proxies)
	}
}

/// One entry of an `X-Forwarded-For`: an address, with or without a port
/// (`203.0.113.5:4711`, `[2001:db8::1]:4711`); `None` for anything else
/// (`unknown`, an obfuscated name).
fn forwarded_entry(s: &str) -> Option<IpAddr> {
	let s = s.trim();
	s.parse::<IpAddr>().ok()
		.or_else(|| s.parse::<SocketAddr>().ok().map(|a| a.ip()))
		.or_else(|| s.strip_prefix('[').and_then(|r| r.strip_suffix(']')).and_then(|a| a.parse::<IpAddr>().ok()))
}

/// Where a request from `peer` comes from, as the limits count it: `peer`,
/// unless it is one of the `trusted` proxies, in which case the nearest
/// address in its `X-Forwarded-For` that is not a trusted proxy (a proxy
/// appends the address that connected to it; anything before that, a
/// client may have written itself). Each entry is read on its own, a port
/// after an address allowed, so one that does not read costs nothing to the
/// rest. But the walk stops at the first entry that is not a trusted proxy:
/// when that one does not read, the source is unknown, and the request is
/// counted against `peer` rather than against what a client wrote before it.
/// A request that does not come from a trusted proxy names its own source,
/// whatever header it carries.
pub fn source_of(peer: IpAddr, headers: &HeaderMap, trusted: &[IpAddr]) -> IpAddr {
	if !trusted.contains(&peer) {
		return peer;
	}
	let entries: Vec<Option<IpAddr>> = headers.get_all("x-forwarded-for").iter()
		.flat_map(|v| v.to_str().ok().map(|v| v.split(',').map(forwarded_entry).collect::<Vec<_>>()).unwrap_or_else(|| vec![None]))
		.collect();
	for e in entries.into_iter().rev() {
		match e {
			Some(a) if trusted.contains(&a) => continue,
			Some(a) => return a,
			None => return peer,
		}
	}
	peer
}

/// A token bucket: at most `burst` tokens, refilled at `per_second`.
#[derive(Debug, Clone, Copy)]
struct Bucket {
	tokens: f64,
	at: Instant,
}

impl Bucket {
	fn refill(&mut self, per_second: f64, burst: f64, now: Instant) {
		self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * per_second).min(burst);
		self.at = now;
	}

	fn wait(&self, per_second: f64) -> Duration {
		if per_second <= 0.0 {
			return Duration::from_secs(60);
		}
		Duration::from_secs_f64((1.0 - self.tokens).max(0.0) / per_second)
	}
}

/// The most sources a [`Limiter`] keeps a bucket for at once. One whose
/// bucket is full again is forgotten first; while every one is in use, a new
/// source waits.
pub const MAX_SOURCES: usize = 65_536;

/// Where a request comes from, as a [`Limiter`] counts it: an IPv4 address,
/// or the /48 an IPv6 address is in (a site is commonly handed a /48, so a
/// caller holding one is one source, however many /64s it carves out).
pub fn source_key(ip: IpAddr) -> IpAddr {
	match ip {
		IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
			Some(v4) => IpAddr::V4(v4),
			None => {
				let s = v6.segments();
				IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0))
			},
		},
		v4 => v4,
	}
}

/// Bounds the one unauthenticated call that writes a row, the operator
/// nonce: a token bucket for each source (`source_burst`, refilled at
/// `source_per_second`), so that one caller cannot use up what every caller
/// needs, and one over every caller together (at most `burst` at once,
/// refilled at `per_second`), set far above what honest callers ask: a high
/// bound on the rows, each deleted once expired (`Store::delete_expired`), so
/// what the call can hold in the database is at most the overall rate times
/// the row's lifetime, without a budget a few sources could use up.
#[derive(Debug)]
pub struct Limiter {
	per_second: f64,
	burst: f64,
	source_per_second: f64,
	source_burst: f64,
	state: std::sync::Mutex<(Bucket, HashMap<IpAddr, Bucket>)>,
}

impl Limiter {
	pub fn new(per_second: u32, burst: u32, source_per_second: u32, source_burst: u32) -> Limiter {
		let burst = f64::from(burst.max(1));
		let all = Bucket { tokens: burst, at: Instant::now() };
		Limiter {
			per_second: f64::from(per_second), burst, source_per_second: f64::from(source_per_second),
			source_burst: f64::from(source_burst.max(1)), state: std::sync::Mutex::new((all, HashMap::new())),
		}
	}

	/// Takes one token for a request from `source`, from its own bucket and
	/// from everyone's, or says how long until both have one.
	pub fn take(&self, source: IpAddr) -> Result<(), Duration> {
		let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
		let now = Instant::now();
		let (all, sources) = &mut *s;
		all.refill(self.per_second, self.burst, now);
		let key = source_key(source);
		if !sources.contains_key(&key) && sources.len() >= MAX_SOURCES {
			let (rate, cap) = (self.source_per_second, self.source_burst);
			sources.retain(|_, b| {
				b.refill(rate, cap, now);
				b.tokens < cap
			});
			if sources.len() >= MAX_SOURCES {
				return Err(Duration::from_secs(1));
			}
		}
		let mine = sources.entry(key).or_insert(Bucket { tokens: self.source_burst, at: now });
		mine.refill(self.source_per_second, self.source_burst, now);
		if mine.tokens < 1.0 {
			return Err(mine.wait(self.source_per_second));
		}
		if all.tokens < 1.0 {
			return Err(all.wait(self.per_second));
		}
		mine.tokens -= 1.0;
		all.tokens -= 1.0;
		Ok(())
	}

	fn refusal(&self, call: &str, source: IpAddr) -> Result<(), Refusal> {
		self.take(source).map_err(|wait| Refusal::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited",
			format!("{} is handed out at a bounded rate to each source, within a high bound overall; try again in {} ms", call,
				wait.as_millis().max(1))))
	}
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
pub fn status_of(code: &str) -> StatusCode {
	match code {
		"malformed" | "invalid_record" | "invalid_transaction" => StatusCode::BAD_REQUEST,
		"unauthenticated" => StatusCode::UNAUTHORIZED,
		"unknown_leaf" | "unknown_board" => StatusCode::NOT_FOUND,
		"unknown_participation" | "unknown_batch" => StatusCode::NOT_FOUND,
		"double_spend" | "in_use" | "nonce_used" | "key_reused" | "script_reused" | "salt" | "board_exists" | "merge" => StatusCode::CONFLICT,
		"request_too_large" => StatusCode::PAYLOAD_TOO_LARGE,
		"rate_limited" => StatusCode::TOO_MANY_REQUESTS,
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

impl From<ParticipationError> for Refusal {
	fn from(e: ParticipationError) -> Refusal {
		let code = e.code();
		if code == "internal" {
			log::error!("participation: {}", e);
		}
		Refusal::new(status_of(code), code, e.to_string())
	}
}

impl From<ForfeitError> for Refusal {
	fn from(e: ForfeitError) -> Refusal {
		let code = e.code();
		if code == "internal" {
			log::error!("forfeits: {}", e);
		}
		Refusal::new(status_of(code), code, e.to_string())
	}
}

impl From<RoundError> for Refusal {
	fn from(e: RoundError) -> Refusal {
		log::error!("rounds: {}", e);
		Refusal::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string())
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

/// The server's clock, in seconds: what a challenge's time is.
fn unix_now() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Checks a proof of `auth.key` for `call`: its challenge issued by this
/// server within its lifetime, and the key's signature.
async fn authenticate(app: &App, call: &str, a: &api::Auth) -> Result<XOnlyPublicKey, Refusal> {
	let k = key(&a.key)?;
	let challenge = unhex32(&a.challenge).map_err(Refusal::malformed)?;
	let signature = sig(&a.signature)?;
	let unauthenticated = |m: String| Refusal::new(StatusCode::UNAUTHORIZED, "unauthenticated", m);
	match auth::check_challenge(&app.challenge_key, &challenge, unix_now(), app.challenge_ttl.as_secs()) {
		Ok(()) => {},
		Err(e @ ChallengeError::Unknown) | Err(e @ ChallengeError::Expired) => return Err(unauthenticated(e.to_string())),
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
		exit_deadline: s.expiry.map(|e| e.saturating_sub(arca_covenant::WalletPolicy::EXIT_DEADLINE)),
		expiry: s.expiry,
	}
}

/// How long `info` publishes the signer's record head it read before it asks
/// again.
pub const RECORD_HEAD_FOR: Duration = Duration::from_secs(2);

/// The signer's record's latest entry and running hash, as `info` publishes
/// it: asked of the signer at most once every [`RECORD_HEAD_FOR`], and again
/// at once when the database has been given a later entry since; `None`
/// while the signer does not answer (the database's latest may lag the
/// record by an entry after a crash, and would read as a rollback).
async fn record_head(app: &App) -> Option<api::RecordHead> {
	let known = app.store.signer_head().await.ok().flatten().map(|h| h.0).unwrap_or(0);
	let mut cached = app.record_head.lock().await;
	if let Some((at, h)) = cached.as_ref() {
		if at.elapsed() < RECORD_HEAD_FOR && known <= h.0 {
			return Some(api::RecordHead { entry: h.0, hash: hex(&h.1) });
		}
	}
	let head = match app.cosigner.signer().head().await {
		Ok(h) => Some(h),
		Err(e) => {
			log::warn!("info: the signer's record head: {}", e);
			None
		},
	};
	if let Some(h) = head {
		*cached = Some((Instant::now(), h));
	}
	head.map(|(entry, h)| api::RecordHead { entry, hash: hex(&h) })
}

async fn info(State(app): State<Arc<App>>) -> Json<api::Info> {
	let floors = floors(&app).await;
	let signer_record = record_head(&app).await;
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
		fees: api::FeesInfo {
			transfer: "0".into(),
			refresh_ppm: p.fees.refresh_ppm,
			free_window_seconds: FeeSchedule::FREE_FROM,
			full_after_seconds: FeeSchedule::FULL_AFTER,
			offboard_ppm: p.fees.offboard_ppm,
			margin_multiple: crate::fees::MULTIPLE,
			max_margin_multiple: p.max_margin_multiple,
			floors,
		},
		participations: api::ParticipationsInfo {
			exit_deadline_seconds: Params::PARTICIPATION_HORIZON,
			forfeit_deadline_seconds: Params::FORFEIT_DEADLINE,
		},
		boards: api::BoardsInfo {
			lifetime_seconds: Params::BOARD_LIFETIME,
			exit_deadline_seconds: arca_covenant::WalletPolicy::EXIT_DEADLINE,
			refresh_until_seconds: Params::ROUND_HORIZON,
		},
		signer_record,
		max_request_bytes: app.max_request as u64,
	})
}

async fn operator_nonce(State(app): State<Arc<App>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap,
	body: Result<Bytes, BytesRejection>) -> Result<Json<api::NonceResponse>, Refusal>
{
	let _: api::Empty = parse(body, app.max_request)?;
	app.nonces.refusal("an operator nonce", app.source(peer.ip(), &headers))?;
	let n = app.store.issue_nonce().await?;
	Ok(Json(api::NonceResponse { operator_nonce: hex(&n) }))
}

async fn challenge(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Result<Json<api::ChallengeResponse>, Refusal> {
	let _: api::Empty = parse(body, app.max_request)?;
	let mut random = [0u8; 12];
	rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut random);
	let c = auth::issue_challenge(&app.challenge_key, unix_now(), random);
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
				creator_nonce: unhex32(&o.creator_nonce).map_err(Refusal::malformed)?,
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

fn participation_status(s: &Status) -> api::ParticipationStatus {
	let r = &s.row;
	api::ParticipationStatus {
		participation_id: hex(&r.id),
		state: r.state.as_str().into(),
		attempt: r.attempt,
		unlock_hash: hex(&r.unlock_hash),
		forfeit_first: r.forfeit_first,
		refund_delay_units: r.refund_delay_units,
		round: s.round.as_ref().map(|rr| api::RoundRef { txid: rr.txid.to_string(), connector_vout: rr.connector_vout }),
		inputs: r.inputs.iter().map(|i| api::ParticipationInputStatus {
			leaf_id: hex(&i.leaf_id),
			asset: AssetId::from_byte_array(i.asset).to_string(),
			value: i.value.to_string(),
			margin: i.margin.to_string(),
		}).collect(),
		outputs: r.outputs.iter().zip(&s.placed).map(|(o, at)| {
			let mut out = api::ParticipationOutputStatus {
				kind: String::new(),
				asset: AssetId::from_byte_array(o.asset).to_string(),
				value: o.value.to_string(),
				operator_nonce: None,
				leaf_id: at.leaf_id.map(|l| l.to_string()),
				batch_vout: at.batch_vout,
				leaf_index: at.leaf_index,
				margin: None,
				reclaim_delay_units: None,
				offboard_vout: at.offboard_vout,
			};
			match &o.kind {
				WantedKind::Leaf { operator_nonce, .. } => {
					out.kind = "leaf".into();
					out.operator_nonce = Some(hex(operator_nonce));
				},
				WantedKind::Offboard { margin, reclaim_delay_units, .. } => {
					out.kind = "offboard".into();
					out.margin = Some(margin.to_string());
					out.reclaim_delay_units = Some(*reclaim_delay_units);
				},
			}
			out
		}).collect(),
		fees: r.fees.iter().map(|(a, v)| api::FeeAmount { asset: AssetId::from_byte_array(*a).to_string(), amount: v.to_string() }).collect(),
		waiting: r.waiting.clone().filter(|_| r.state == crate::store::ParticipationState::Pending),
	}
}

async fn submit_participation(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>)
	-> Result<Json<api::ParticipationStatus>, Refusal>
{
	let req: api::SubmitParticipation = parse(body, app.max_request)?;
	let mut inputs = Vec::with_capacity(req.inputs.len());
	for i in &req.inputs {
		inputs.push(part::InputRequest { leaf_id: leaf_id(&i.leaf_id)?, attestation: sig(&i.attestation)? });
	}
	let mut outputs = Vec::with_capacity(req.outputs.len());
	let mut key_proofs = Vec::with_capacity(req.outputs.len());
	for o in &req.outputs {
		key_proofs.push(match o {
			api::WantedOutput::Leaf(l) => l.key_proof.as_deref().map(sig).transpose()?,
			api::WantedOutput::Offboard(_) => None,
		});
		outputs.push(match o {
			api::WantedOutput::Leaf(l) => part::OutputRequest::Leaf {
				asset: asset(&l.asset)?,
				value: amount(&l.value)?,
				template: l.template.parse().map_err(|e| Refusal::new(StatusCode::UNPROCESSABLE_ENTITY, "template",
					format!("template {:?}: {}", l.template, e)))?,
				owner: key(&l.owner)?,
				owner_nonce: unhex32(&l.owner_nonce).map_err(Refusal::malformed)?,
				exit_delay: RelativeTime::from_units(l.exit_delay_units).map_err(|e| Refusal::malformed(format!("exit delay: {}", e)))?,
			},
			api::WantedOutput::Offboard(b) => part::OutputRequest::Offboard {
				asset: asset(&b.asset)?,
				value: amount(&b.value)?,
				script: elements::Script::from(unhex(&b.script).map_err(Refusal::malformed)?),
			},
		});
	}
	let mut fees = Vec::with_capacity(req.fees.len());
	for f in &req.fees {
		fees.push((asset(&f.asset)?, amount(&f.amount)?));
	}
	let not_before = req.not_before.map(|t| MedianTime::from_consensus(t).map_err(|e| Refusal::malformed(format!("not_before: {}", e))))
		.transpose()?;
	let status = app.participations.submit(&ParticipationRequest { inputs, outputs, key_proofs, fees, not_before }).await?;
	Ok(Json(participation_status(&status)))
}

async fn participation_status_call(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>)
	-> Result<Json<api::ParticipationStatus>, Refusal>
{
	let req: api::ParticipationStatusRequest = parse(body, app.max_request)?;
	let id = unhex32(&req.participation_id).map_err(Refusal::malformed)?;
	Ok(Json(participation_status(&app.participations.status(&id).await?)))
}

async fn tree(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Result<Json<api::PublishedTree>, Refusal> {
	let req: api::TreeRequest = parse(body, app.max_request)?;
	let txid = elements::Txid::from_str(&req.txid).map_err(|e| Refusal::malformed(format!("txid: {}", e)))?;
	let t = app.rounds.tree(&txid, req.vout).await?
		.ok_or_else(|| Refusal::new(StatusCode::NOT_FOUND, "unknown_batch", format!("no batch is paid by {}:{}", txid, req.vout)))?;
	use arca_covenant::encode::Encoding;
	Ok(Json(api::PublishedTree {
		round_txid: t.round_txid.to_string(),
		batch_vout: t.batch_vout,
		token_vout: t.token_vout,
		connector_vout: t.connector_vout,
		asset: t.params.asset.to_string(),
		genesis_hash: t.params.chain.genesis_hash().to_string(),
		schedule: hex(&t.params.schedule.encode()),
		burn: t.params.burn,
		radix: t.params.radix as u32,
		reserve: match t.params.reserve {
			arca_covenant::ReserveRule::FeeRate { floor_per_kvb, multiple } => api::TreeReserve::FeeRate(api::FeeRateReserve {
				floor_per_kvb: floor_per_kvb.to_string(), multiple: multiple.to_string(),
			}),
			arca_covenant::ReserveRule::Fixed { node, entry } => api::TreeReserve::Fixed(api::FixedReserve {
				node: node.to_string(), entry: entry.to_string(),
			}),
		},
		min_leaf: t.params.min_leaf.to_string(),
		signer_record: t.signer_head.map(|(entry, h)| api::RecordHead { entry, hash: hex(&h) }),
		leaves: t.leaves.iter().map(|l| api::TreeLeaf {
			template: l.template.to_string(),
			owner: hex(&l.owner.serialize()),
			owner_nonce: hex(&l.owner_nonce),
			operator_nonce: hex(&l.operator_nonce),
			exit_delay_units: l.exit_delay.units(),
			value: l.value.to_string(),
			unlock_hash: hex(&l.unlock_hash),
		}).collect(),
	}))
}

async fn forfeit_leaves(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Result<Json<api::Forfeited>, Refusal> {
	let req: api::ForfeitLeaves = parse(body, app.max_request)?;
	let participation_id = unhex32(&req.participation_id).map_err(Refusal::malformed)?;
	let mut forfeits = Vec::with_capacity(req.forfeits.len());
	for f in &req.forfeits {
		forfeits.push(ForfeitRequest { leaf_id: leaf_id(&f.leaf_id)?, signature: sig(&f.signature)? });
	}
	let mut leaves = Vec::with_capacity(req.leaves.len());
	for l in &req.leaves {
		let mut auths = Vec::with_capacity(l.auths.len());
		for a in &l.auths {
			auths.push((sig(&a.signature)?, MedianTime::from_consensus(a.time).map_err(|e| Refusal::malformed(format!("time: {}", e)))?));
		}
		leaves.push(AuthsRequest { leaf_id: leaf_id(&l.leaf_id)?, auths });
	}
	let done = app.forfeits.forfeit_leaves(&ForfeitLeaves { participation_id, forfeits, leaves }).await?;
	Ok(Json(api::Forfeited {
		participation_id: hex(&done.participation_id),
		state: done.state.as_str().into(),
		preimage: done.preimage.map(|p| hex(&p)),
		forfeit_first: done.forfeit_first,
	}))
}

async fn release_leaves(State(app): State<Arc<App>>, body: Result<Bytes, BytesRejection>) -> Result<Json<api::Released>, Refusal> {
	let req: api::ReleaseLeaves = parse(body, app.max_request)?;
	let id = unhex32(&req.participation_id).map_err(Refusal::malformed)?;
	let mut releases = Vec::with_capacity(req.releases.len());
	for r in &req.releases {
		let connector = r.connector_asset.as_deref().map(asset).transpose()?;
		releases.push(ReleaseRequest { leaf_id: leaf_id(&r.leaf_id)?, connector, signature: sig(&r.signature)? });
	}
	let done = app.forfeits.release_leaves(&id, &releases).await?;
	Ok(Json(api::Released { participation_id: hex(&id), released: done.iter().map(|l| l.to_string()).collect() }))
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
				LeafState::Expired => "expired",
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
		.route("/v1/submit_participation", post(submit_participation))
		.route("/v1/participation_status", post(participation_status_call))
		.route("/v1/tree", post(tree))
		.route("/v1/forfeit_leaves", post(forfeit_leaves))
		.route("/v1/release_leaves", post(release_leaves))
		.route("/v1/mailbox_read", post(mailbox_read))
		.route("/v1/leaf_data", post(leaf_data))
		.layer(DefaultBodyLimit::max(limit))
		.with_state(app)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn ip(s: &str) -> IpAddr {
		s.parse().unwrap()
	}

	fn forwarded(v: &str) -> HeaderMap {
		let mut h = HeaderMap::new();
		h.insert("x-forwarded-for", v.parse().unwrap());
		h
	}

	/// The source is the proxy's forwarded address only when the request
	/// comes from the proxy, and then the nearest one not a proxy.
	#[test]
	fn the_source_is_forwarded_only_by_a_trusted_proxy() {
		let trusted = [ip("127.0.0.1"), ip("::1")];
		assert_eq!(source_of(ip("203.0.113.7"), &forwarded("198.51.100.9"), &trusted), ip("203.0.113.7"),
			"a request from elsewhere names its own source, whatever it carries");
		assert_eq!(source_of(ip("127.0.0.1"), &HeaderMap::new(), &trusted), ip("127.0.0.1"));
		assert_eq!(source_of(ip("127.0.0.1"), &forwarded("198.51.100.9"), &trusted), ip("198.51.100.9"));
		assert_eq!(source_of(ip("127.0.0.1"), &forwarded("10.9.9.9, 198.51.100.9"), &trusted), ip("198.51.100.9"),
			"what a client wrote before the proxy's own entry is not taken");
		assert_eq!(source_of(ip("127.0.0.1"), &forwarded("198.51.100.9, ::1"), &trusted), ip("198.51.100.9"),
			"a chain of trusted proxies is walked back");
		assert_eq!(source_of(ip("127.0.0.1"), &forwarded("not an address"), &trusted), ip("127.0.0.1"));
		// An entry that does not read costs the others nothing; a port is read
		// past; the nearest entry not a proxy unreadable names no source.
		assert_eq!(source_of(ip("127.0.0.1"), &forwarded("unknown, 203.0.113.5"), &trusted), ip("203.0.113.5"));
		assert_eq!(source_of(ip("127.0.0.1"), &forwarded("203.0.113.5:4711"), &trusted), ip("203.0.113.5"));
		assert_eq!(source_of(ip("127.0.0.1"), &forwarded("[2001:db8::7]:4711"), &trusted), ip("2001:db8::7"));
		assert_eq!(source_of(ip("127.0.0.1"), &forwarded("198.51.100.9, unknown"), &trusted), ip("127.0.0.1"),
			"what a client wrote before an entry that does not read is not taken");
	}

	/// One source's bucket is its own: a caller that used up its own leaves
	/// another its share, while the overall bound still holds.
	#[test]
	fn one_source_cannot_use_up_another_s() {
		let l = Limiter::new(0, 5, 0, 2);
		let (a, b) = (ip("203.0.113.7"), ip("198.51.100.9"));
		assert!(l.take(a).is_ok() && l.take(a).is_ok());
		assert!(l.take(a).is_err(), "a's own burst is used up");
		assert!(l.take(b).is_ok() && l.take(b).is_ok(), "b's is whole");
		assert!(l.take(ip("192.0.2.1")).is_ok());
		assert!(l.take(ip("192.0.2.2")).is_err(), "the overall burst of 5 is used up");
		// The addresses of one IPv6 /48 are one source, its /64s included.
		let l = Limiter::new(0, 10, 0, 1);
		assert!(l.take(ip("2001:db8:1:2::1")).is_ok());
		assert!(l.take(ip("2001:db8:1:2::ffff")).is_err());
		assert!(l.take(ip("2001:db8:1:3::1")).is_err(), "another /64 of the same /48");
		assert!(l.take(ip("2001:db8:2::1")).is_ok(), "another /48");
	}
}
