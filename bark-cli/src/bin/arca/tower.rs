//! `arca watchtower serve`: a watchtower over HTTP.
//!
//! The wallet in the data directory is the watchtower's: its on-chain coins
//! pay the fees no reserve covers. It answers `GET /v1/info`, `POST
//! /v1/deposit` and `POST /v1/withdraw` (the last segment after `/v1/`
//! names the call, so it serves under any path prefix a proxy adds), one
//! request a connection, and passes over its deposits every `interval`
//! seconds ([`bark::arca::Wallet::tower_pass`]). Requests wait while a pass
//! runs: the wallet is one, and the store is its.
//!
//! Every answer allows any origin (`Access-Control-Allow-Origin: *`), and a
//! preflight (`OPTIONS`) is answered at once: wallets in browsers deposit
//! with watchtowers on other origins than the page's, their operator's and
//! other operators'. Nothing it takes or answers is private: a deposit is
//! sealed, and a withdrawal is signed.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use bark::arca::client::REFUSALS;
use bark::arca::tower::MAX_DEPOSIT_BYTES;
use bark::arca::{Error, Wallet};
use serde_json::{json, Value};

struct Request {
	call: String,
	body: Value,
	reply: mpsc::Sender<(u16, Value)>,
}

/// The status and JSON body of an error: a refusal whose message starts
/// with one of the server's refusal codes carries that code, so a wallet
/// reads it as a refusal; anything else says nothing of what was done.
fn refusal(e: &Error) -> (u16, Value) {
	let msg = e.to_string();
	match e {
		Error::Refused(m) | Error::Parse(m) => {
			let code = m.split(':').next().unwrap_or("").trim();
			let code = if REFUSALS.contains(&code) { code } else { "malformed" };
			(422, json!({"error": {"code": code, "message": msg}}))
		},
		_ => (503, json!({"error": {"code": "unavailable", "message": msg}})),
	}
}

/// The headers that let a page on any origin call the watchtower.
const CORS: &str = "Access-Control-Allow-Origin: *\r\n";

/// The answer to a preflight: the calls a page may make, for ten minutes.
fn preflight(s: &mut TcpStream) {
	let head = format!("HTTP/1.1 204 No Content\r\n{}Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
		Access-Control-Allow-Headers: Content-Type\r\nAccess-Control-Max-Age: 600\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", CORS);
	let _ = s.write_all(head.as_bytes()).and_then(|_| s.flush());
}

fn respond(s: &mut TcpStream, status: u16, body: &Value) {
	let text = body.to_string();
	let reason = match status { 200 => "OK", 404 => "Not Found", 413 => "Payload Too Large", 422 => "Unprocessable Entity", _ => "Error" };
	let head = format!("HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n", status, reason,
		text.len(), CORS);
	let _ = s.write_all(head.as_bytes()).and_then(|_| s.write_all(text.as_bytes())).and_then(|_| s.flush());
}

/// Reads one request from `s` (its head, then exactly its body), hands it to
/// the wallet's loop and writes the answer.
fn handle(mut s: TcpStream, tx: mpsc::Sender<Request>) {
	let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
	let mut buf = Vec::new();
	let mut chunk = [0u8; 4096];
	let head_end = loop {
		if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
			break i + 4;
		}
		if buf.len() > 16 * 1024 {
			return respond(&mut s, 413, &json!({"error": {"code": "request_too_large", "message": "the request's head is too long"}}));
		}
		match s.read(&mut chunk) {
			Ok(0) | Err(_) => return,
			Ok(n) => buf.extend_from_slice(&chunk[..n]),
		}
	};
	let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
	let mut lines = head.split("\r\n");
	let first: Vec<&str> = lines.next().unwrap_or("").split_whitespace().collect();
	let path = first.get(1).copied().unwrap_or("").split('?').next().unwrap_or("").to_string();
	if first.first().is_some_and(|m| m.eq_ignore_ascii_case("OPTIONS")) {
		return preflight(&mut s);
	}
	let length: usize = lines.filter_map(|l| l.split_once(':')).find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
		.and_then(|(_, v)| v.trim().parse().ok()).unwrap_or(0);
	if length > MAX_DEPOSIT_BYTES {
		return respond(&mut s, 413, &json!({"error": {"code": "request_too_large", "message": "the request's body is too large"}}));
	}
	let mut body = buf[head_end..].to_vec();
	while body.len() < length {
		match s.read(&mut chunk) {
			Ok(0) | Err(_) => return,
			Ok(n) => body.extend_from_slice(&chunk[..n]),
		}
	}
	body.truncate(length);
	let Some(call) = path.rsplit_once("/v1/").map(|(_, c)| c.trim_end_matches('/').to_string()) else {
		return respond(&mut s, 404, &json!({"error": {"code": "malformed", "message": format!("no call at {}", path)}}));
	};
	let body: Value = if body.is_empty() { Value::Null } else {
		match serde_json::from_slice(&body) {
			Ok(v) => v,
			Err(e) => return respond(&mut s, 422, &json!({"error": {"code": "malformed", "message": format!("the body: {}", e)}})),
		}
	};
	let (reply, answer) = mpsc::channel();
	if tx.send(Request { call, body, reply }).is_err() {
		return;
	}
	if let Ok((status, v)) = answer.recv_timeout(Duration::from_secs(600)) {
		respond(&mut s, status, &v);
	}
}

/// Serves the watchtower on `listen` until the process is stopped.
pub fn serve(w: &mut Wallet, listen: &str, interval: u64) -> Result<Value, Error> {
	let listener = TcpListener::bind(listen).map_err(|e| Error::Io(format!("{}: {}", listen, e)))?;
	let at = listener.local_addr().map_err(|e| Error::Io(e.to_string()))?;
	eprintln!("arca watchtower: listening on {}, a pass every {} s", at, interval);
	let (tx, rx) = mpsc::channel::<Request>();
	std::thread::spawn(move || {
		for s in listener.incoming().flatten() {
			let tx = tx.clone();
			std::thread::spawn(move || handle(s, tx));
		}
	});
	let mut next = Instant::now();
	loop {
		match rx.recv_timeout(next.saturating_duration_since(Instant::now())) {
			Ok(r) => {
				let a = match w.tower_call(&r.call, &r.body) {
					Ok(v) => (200, v),
					Err(e) => refusal(&e),
				};
				let _ = r.reply.send(a);
			},
			Err(mpsc::RecvTimeoutError::Timeout) => {
				match w.tower_pass() {
					Ok(v) if v["acted"].as_array().is_some_and(|a| !a.is_empty()) => eprintln!("arca watchtower: {}", v),
					Ok(_) => {},
					Err(e) => eprintln!("arca watchtower: the pass stopped: {}", e),
				}
				next = Instant::now() + Duration::from_secs(interval.max(1));
			},
			Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(json!({"stopped": true})),
		}
	}
}
