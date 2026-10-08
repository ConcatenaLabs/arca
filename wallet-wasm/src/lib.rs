//! The Arca wallet (`bark::arca`) for a browser's dedicated worker.
//!
//! The wallet library is the one the `arca` command line runs, compiled for
//! `wasm32` with nothing of its own rewritten: every script, record, check,
//! store write and refusal is that library's. This crate adds only what a
//! browser lacks:
//!
//! - **HTTP**: every request to the node and to the server is a synchronous
//!   `XMLHttpRequest`, which a dedicated worker may block on, so the
//!   library's blocking calls run as they do natively
//!   ([`sequentia_ext::platform`]);
//! - **a pause**, for the library's back-off while it tries an operator again;
//! - **the store**: SQLite's OPFS storage (`opfs-sahpool`), installed with
//!   [`install_store`] before a wallet is opened. Every write SQLite commits
//!   is on disk before the next statement runs, as with the native file, so
//!   what the library writes before it broadcasts or hands anything over is
//!   kept across a closed tab.
//!
//! A command's answer is the library's JSON. A refusal is thrown as the
//! JSON the command line prints, `{"error": {"kind", "message"}}`, with the
//! server's `code` and `status` when the server refused, so a page shows it
//! in the library's own words.

use std::time::Duration;

use bark::arca::command;
use bark::arca::store::Store;
use bark::arca::{Error, Wallet};
use serde_json::{json, Value};
use sequentia_ext::platform::{self, Platform, Request, Response};
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// The platform
// ---------------------------------------------------------------------------

/// A synchronous `XMLHttpRequest` per request, and a pause that waits on the
/// clock.
struct Worker;

fn js_text(v: JsValue) -> String {
	v.as_string()
		.or_else(|| js_sys::Reflect::get(&v, &"message".into()).ok().and_then(|m| m.as_string()))
		.unwrap_or_else(|| format!("{:?}", v))
}

impl Platform for Worker {
	fn http(&self, r: &Request) -> Result<Response, String> {
		let x = web_sys::XmlHttpRequest::new().map_err(js_text)?;
		x.open_with_async(r.method, r.url, false).map_err(js_text)?;
		for (k, v) in &r.headers {
			x.set_request_header(k, v).map_err(js_text)?;
		}
		// A worker may bound a synchronous request; a page may not.
		x.set_timeout(u32::try_from(r.timeout_secs.saturating_mul(1000)).unwrap_or(u32::MAX));
		match r.body {
			Some(b) => x.send_with_opt_str(Some(b)),
			None => x.send(),
		}
		.map_err(|e| format!("{} {}: {}", r.method, r.url, js_text(e)))?;
		let status = x.status().map_err(js_text)?;
		if status == 0 {
			return Err(format!("{} {}: no answer", r.method, r.url));
		}
		Ok(Response { status: i32::from(status), body: x.response_text().map_err(js_text)?.unwrap_or_default() })
	}

	/// Waits on the clock. A worker blocked in the library has nothing else
	/// to do, and `Atomics.wait` needs a cross-origin-isolated page.
	fn sleep(&self, d: Duration) {
		let until = js_sys::Date::now() + d.as_millis() as f64;
		while js_sys::Date::now() < until {}
	}
}

/// Installs SQLite's OPFS storage in `directory` as the default, and
/// registers the worker's HTTP and pause. Call once, in a dedicated worker,
/// before anything else. A second tab's worker fails here while the first
/// holds the storage, so one wallet runs at a time.
#[wasm_bindgen(js_name = installStore)]
pub async fn install_store(directory: String) -> Result<(), JsValue> {
	let cfg = sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg { directory, ..Default::default() };
	sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(&cfg, true)
		.await
		.map_err(|e| JsValue::from_str(&format!("the wallet's storage cannot be opened: {}", e)))?;
	let _ = platform::set_platform(Box::new(Worker));
	Ok(())
}

// ---------------------------------------------------------------------------
// Answers
// ---------------------------------------------------------------------------

/// A refusal as the command line prints it ([`command::refusal`]).
fn refusal(e: Error) -> JsValue {
	JsValue::from_str(&command::refusal(&e).to_string())
}

fn open_store(mnemonic: &str) -> Result<Store, Error> {
	let conn = rusqlite::Connection::open(command::store_name(mnemonic)?).map_err(|e| Error::Store(e.to_string()))?;
	Store::open_connection(conn)
}

// ---------------------------------------------------------------------------
// The wallet
// ---------------------------------------------------------------------------

/// One Arca wallet, open in this worker.
#[wasm_bindgen]
pub struct ArcaWallet {
	w: Wallet,
}

/// Whether this browser's storage holds the wallet of `mnemonic`.
#[wasm_bindgen(js_name = arcaWalletExists)]
pub fn wallet_exists(mnemonic: &str) -> Result<bool, JsValue> {
	let store = open_store(mnemonic).map_err(refusal)?;
	Ok(store.meta("genesis").map_err(refusal)?.is_some())
}

#[wasm_bindgen]
impl ArcaWallet {
	/// Creates the wallet of `mnemonic` against the server and node `config`
	/// names (`{"server", "node_url", "node_user"?, "node_password"?,
	/// "exit_delay_units"?, "min_exit_delay_units"?, "max_exit_delay_units"?}`),
	/// pinning the node's chain and the server's operator key, as `arca
	/// create` does. Its answer is `info`, with `operator_key_check`.
	pub fn create(mnemonic: &str, config: &str) -> Result<ArcaWallet, JsValue> {
		let c: Value = serde_json::from_str(config).map_err(|e| refusal(Error::Parse(format!("the configuration: {}", e))))?;
		let cfg = command::config(&c).map_err(refusal)?;
		let store = open_store(mnemonic).map_err(refusal)?;
		let w = Wallet::create_in(store, mnemonic, cfg).map_err(refusal)?;
		Ok(ArcaWallet { w })
	}

	/// Opens the wallet of `mnemonic` this browser holds; the node's password
	/// is handed over again on each open and never stored.
	pub fn open(mnemonic: &str, node_password: Option<String>) -> Result<ArcaWallet, JsValue> {
		let store = open_store(mnemonic).map_err(refusal)?;
		let w = Wallet::open_in(store, mnemonic, node_password).map_err(refusal)?;
		Ok(ArcaWallet { w })
	}

	/// Runs one command, as `arca <command>` does, `args` a JSON object of its
	/// arguments: the library's [`command::run`], whose answer is `{"result",
	/// "start"}` and whose commands are [`command::COMMANDS`].
	pub fn run(&mut self, command: &str, args: &str) -> Result<String, JsValue> {
		let a: Value = if args.trim().is_empty() { json!({}) } else {
			serde_json::from_str(args).map_err(|e| refusal(Error::Parse(format!("the arguments: {}", e))))?
		};
		command::run(&mut self.w, command, &a).map(|v| v.to_string()).map_err(refusal)
	}
}
