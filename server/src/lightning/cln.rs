//! A client of a Core Lightning node's JSON-RPC, over its Unix socket.
//!
//! SeqLN is a Core Lightning fork, and the gateway speaks to it as Core
//! Lightning's own `lightning-cli` does: one JSON-RPC 2.0 request on the
//! node's `lightning-rpc` socket, answered by one JSON object. Each call opens
//! its own connection, so a call that waits (a payment) holds up no other,
//! and a node that restarted is reached again by the next call. The fork's
//! gRPC bindings carry no asset, so the gateway does not use them.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// The largest answer read from a node: a `listpeerchannels` of a busy node
/// stays far below it.
const MAX_ANSWER: usize = 64 * 1024 * 1024;

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClnError {
	/// The node could not be reached at all: its socket is missing, refuses,
	/// or closed before answering.
	#[error("the node at {path} could not be reached: {why}")]
	Unreachable { path: String, why: String },
	/// The node did not answer in time.
	#[error("the node at {path} did not answer {method} within {seconds} s")]
	Timeout { path: String, method: String, seconds: u64 },
	/// The node answered with an error.
	#[error("{method}: the node refused it ({code}): {message}")]
	Rpc { method: String, code: i64, message: String, data: Option<Value> },
	/// The node answered with something that is not a JSON-RPC answer.
	#[error("{method}: the node's answer is not a JSON-RPC answer: {why}")]
	Malformed { method: String, why: String },
}

impl ClnError {
	/// Whether the node was reached and answered: a refusal says something
	/// about the request, the others only about the node.
	pub fn answered(&self) -> bool {
		matches!(self, ClnError::Rpc { .. })
	}
}

/// A node's JSON-RPC, at its socket.
#[derive(Debug)]
pub struct Cln {
	path: PathBuf,
	next_id: AtomicU64,
}

impl Cln {
	/// The node whose `lightning-rpc` socket is `path`.
	pub fn new(path: impl Into<PathBuf>) -> Cln {
		Cln { path: path.into(), next_id: AtomicU64::new(1) }
	}

	pub fn path(&self) -> &Path {
		&self.path
	}

	/// Calls `method` with `params` (an object), waiting at most `timeout`.
	pub async fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, ClnError> {
		let path = self.path.display().to_string();
		match tokio::time::timeout(timeout, self.call_inner(method, params)).await {
			Ok(r) => r,
			Err(_) => Err(ClnError::Timeout { path, method: method.into(), seconds: timeout.as_secs() }),
		}
	}

	async fn call_inner(&self, method: &str, params: Value) -> Result<Value, ClnError> {
		let path = self.path.display().to_string();
		let unreachable = |why: String| ClnError::Unreachable { path: path.clone(), why };
		let mut stream = UnixStream::connect(&self.path).await.map_err(|e| unreachable(e.to_string()))?;
		let id = self.next_id.fetch_add(1, Ordering::Relaxed);
		let request = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
		let bytes = serde_json::to_vec(&request).expect("a JSON value serialises");
		stream.write_all(&bytes).await.map_err(|e| unreachable(e.to_string()))?;
		let mut buf = Vec::with_capacity(4096);
		let mut chunk = [0u8; 16 * 1024];
		loop {
			let n = stream.read(&mut chunk).await.map_err(|e| unreachable(e.to_string()))?;
			if n == 0 {
				return Err(unreachable(format!("the connection closed before {} was answered", method)));
			}
			buf.extend_from_slice(&chunk[..n]);
			if buf.len() > MAX_ANSWER {
				return Err(ClnError::Malformed { method: method.into(), why: format!("an answer over {} bytes", MAX_ANSWER) });
			}
			// The node writes one object per answer and keeps the
			// connection open: an object is whole once it parses.
			let mut it = serde_json::Deserializer::from_slice(&buf).into_iter::<Value>();
			match it.next() {
				Some(Ok(v)) => return answer(method, id, v),
				Some(Err(e)) if e.is_eof() => continue,
				Some(Err(e)) => return Err(ClnError::Malformed { method: method.into(), why: e.to_string() }),
				None => continue,
			}
		}
	}
}

/// The result of a JSON-RPC answer to request `id`.
fn answer(method: &str, id: u64, v: Value) -> Result<Value, ClnError> {
	if v.get("id").and_then(|i| i.as_u64()) != Some(id) {
		return Err(ClnError::Malformed { method: method.into(), why: format!("an answer to another request: {}", v) });
	}
	if let Some(e) = v.get("error") {
		return Err(ClnError::Rpc {
			method: method.into(),
			code: e.get("code").and_then(|c| c.as_i64()).unwrap_or(0),
			message: e.get("message").and_then(|m| m.as_str()).unwrap_or("").to_string(),
			data: e.get("data").cloned(),
		});
	}
	v.get("result").cloned().ok_or_else(|| ClnError::Malformed { method: method.into(), why: "no result and no error".into() })
}

#[cfg(test)]
mod test {
	use super::*;

	/// A stand-in node: answers each request on its socket with `reply`,
	/// given the request, written in pieces to exercise the reader.
	async fn fake(path: &Path, reply: fn(&Value) -> Value) {
		let listener = tokio::net::UnixListener::bind(path).unwrap();
		tokio::spawn(async move {
			loop {
				let (mut s, _) = listener.accept().await.unwrap();
				tokio::spawn(async move {
					let mut buf = vec![];
					let mut chunk = [0u8; 1024];
					let req = loop {
						let n = s.read(&mut chunk).await.unwrap();
						buf.extend_from_slice(&chunk[..n]);
						if let Ok(v) = serde_json::from_slice::<Value>(&buf) {
							break v;
						}
					};
					let out = serde_json::to_vec(&reply(&req)).unwrap();
					for piece in out.chunks(7) {
						s.write_all(piece).await.unwrap();
						s.flush().await.unwrap();
					}
					s.write_all(b"\n\n").await.unwrap();
					// The node keeps the connection open after it answers.
					tokio::time::sleep(Duration::from_secs(5)).await;
				});
			}
		});
	}

	fn dir(name: &str) -> PathBuf {
		let d = std::env::temp_dir().join(format!("arca-cln-test-{}-{}", std::process::id(), name));
		let _ = std::fs::remove_dir_all(&d);
		std::fs::create_dir_all(&d).unwrap();
		d
	}

	#[tokio::test]
	async fn a_call_is_answered_with_its_result_or_its_error() {
		let d = dir("answers");
		let sock = d.join("lightning-rpc");
		fake(&sock, |req| match req["method"].as_str().unwrap() {
			"getinfo" => json!({ "jsonrpc": "2.0", "id": req["id"], "result": { "id": "02ab", "network": "sequentia-regtest" } }),
			"stray" => json!({ "jsonrpc": "2.0", "id": 999_999, "result": {} }),
			_ => json!({ "jsonrpc": "2.0", "id": req["id"], "error": { "code": -32601, "message": "Unknown command" } }),
		}).await;
		let c = Cln::new(&sock);
		let info = c.call("getinfo", json!({}), Duration::from_secs(5)).await.unwrap();
		assert_eq!(info["network"], "sequentia-regtest");
		let e = c.call("nosuch", json!({}), Duration::from_secs(5)).await.unwrap_err();
		assert!(matches!(e, ClnError::Rpc { code: -32601, .. }) && e.answered(), "{}", e);
		let e = c.call("stray", json!({}), Duration::from_secs(5)).await.unwrap_err();
		assert!(matches!(e, ClnError::Malformed { .. }), "{}", e);
		let gone = Cln::new(d.join("no-such-socket"));
		let e = gone.call("getinfo", json!({}), Duration::from_secs(5)).await.unwrap_err();
		assert!(matches!(e, ClnError::Unreachable { .. }) && !e.answered(), "{}", e);
		let _ = std::fs::remove_dir_all(&d);
	}
}
