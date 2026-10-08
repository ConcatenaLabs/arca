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

use std::str::FromStr;
use std::time::Duration;

use bark::arca::elements::hashes::{sha256, Hash};
use bark::arca::elements::AssetId;
use bark::arca::keys::Keys;
use bark::arca::store::Store;
use bark::arca::{Config, Error, Wallet};
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

/// A refusal as the command line prints it.
fn refusal(e: Error) -> JsValue {
	let mut out = json!({"error": {"kind": e.kind(), "message": e.to_string()}});
	if let Error::Server { code, status, .. } = &e {
		out["error"]["code"] = json!(code);
		out["error"]["status"] = json!(status);
	}
	JsValue::from_str(&out.to_string())
}

fn refused(message: impl Into<String>) -> JsValue {
	refusal(Error::Refused(message.into()))
}

/// The store's file for `mnemonic`: one per wallet, named after its mailbox
/// key, so two mnemonics never meet in one store.
fn store_name(mnemonic: &str) -> Result<String, Error> {
	let keys = Keys::new(mnemonic.trim(), 0, 1)?;
	let k = keys.mailbox()?.x_only_public_key().0.serialize();
	let h = sha256::Hash::hash(&k).to_byte_array();
	Ok(format!("arca-{}.sqlite", h[..8].iter().map(|b| format!("{:02x}", b)).collect::<String>()))
}

fn open_store(mnemonic: &str) -> Result<Store, Error> {
	let conn = rusqlite::Connection::open(store_name(mnemonic)?).map_err(|e| Error::Store(e.to_string()))?;
	Store::open_connection(conn)
}

fn asset(s: &str) -> Result<AssetId, Error> {
	AssetId::from_str(s).map_err(|e| Error::Parse(format!("the asset {}: {}", s, e)))
}

fn opt_asset(v: &Value) -> Result<Option<AssetId>, Error> {
	match v.as_str().filter(|s| !s.is_empty()) {
		Some(s) => asset(s).map(Some),
		None => Ok(None),
	}
}

fn opt_u64(v: &Value, what: &str) -> Result<Option<u64>, Error> {
	match v {
		Value::Null => Ok(None),
		Value::String(s) if s.is_empty() => Ok(None),
		Value::String(s) => s.parse().map(Some).map_err(|_| Error::Parse(format!("{}: {}", what, s))),
		Value::Number(n) => n.as_u64().map(Some).ok_or_else(|| Error::Parse(format!("{}: {}", what, n))),
		_ => Err(Error::Parse(format!("{}: {}", what, v))),
	}
}

fn req_str<'a>(v: &'a Value, what: &str) -> Result<&'a str, Error> {
	v.as_str().filter(|s| !s.is_empty()).ok_or_else(|| Error::Parse(format!("{} is missing", what)))
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
		let mut cfg = Config::spec_delays(req_str(&c["server"], "the server").map_err(refusal)?, req_str(&c["node_url"], "the node").map_err(refusal)?);
		cfg.node_user = c["node_user"].as_str().map(String::from);
		cfg.node_password = c["node_password"].as_str().map(String::from);
		for (k, slot) in [("exit_delay_units", &mut cfg.exit_delay_units), ("min_exit_delay_units", &mut cfg.min_exit_delay_units),
			("max_exit_delay_units", &mut cfg.max_exit_delay_units)]
		{
			if let Some(v) = opt_u64(&c[k], k).map_err(refusal)? {
				*slot = u16::try_from(v).map_err(|_| refused(format!("{} is out of range", k)))?;
			}
		}
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
	/// arguments. The answer is `{"result", "start"}`: the command's JSON,
	/// and what the start of the command found (the witness of the
	/// operator's signer's record, and the re-check of every coin against the
	/// chain), which the command line runs on every start and prints when
	/// it changed something.
	///
	/// Commands: `info`, `address`, `balance`, `coins`, `record {leaf_id}`,
	/// `board {asset, amount, fee_asset?}`, `boards`, `receive {asset?,
	/// amount?}`, `send {request, amount?, asset?}`, `mailbox`, `quote
	/// {leaves?, max_fee_ppm?}`, `participate {leaves?, not_before?,
	/// max_fee_ppm?, shown}`, `participations`, `sync`, `schedule`,
	/// `recheck`, `exit {leaf_id, fee_asset?}`, `refusals`.
	pub fn run(&mut self, command: &str, args: &str) -> Result<String, JsValue> {
		let a: Value = if args.trim().is_empty() { json!({}) } else {
			serde_json::from_str(args).map_err(|e| refusal(Error::Parse(format!("the arguments: {}", e))))?
		};
		let start = self.start(command);
		let result = self.command(command, &a).map_err(refusal)?;
		Ok(json!({"result": result, "start": start}).to_string())
	}

	/// What `arca` runs before a command: the witness (unless the command
	/// stays on this machine and the node), then the re-check (unless the
	/// command is itself `recheck` or `sync`).
	fn start(&mut self, command: &str) -> Value {
		let local = matches!(command, "address" | "balance" | "coins" | "record" | "refusals" | "participations" | "exit" | "schedule");
		let mut out = json!({});
		if !local {
			out["witness"] = match self.w.witness() {
				Ok(v) => v,
				Err(e) => json!({"error": {"kind": e.kind(), "message": format!("the witness on start could not run ({}): the wallet takes \
					no coin and signs no spend through the operator until a witness succeeds", e)}}),
			};
		}
		if !matches!(command, "recheck" | "sync" | "schedule") {
			out["recheck"] = match self.w.recheck() {
				Ok(v) => v,
				Err(e) => json!({"error": {"kind": e.kind(), "message": format!("the re-check on start could not run: {}", e)}}),
			};
		}
		out
	}

	fn command(&mut self, command: &str, a: &Value) -> Result<Value, Error> {
		let w = &mut self.w;
		match command {
			"info" => w.info(),
			"address" => w.address(),
			"balance" => w.balance(),
			"coins" => w.coins(),
			"record" => w.record(req_str(&a["leaf_id"], "the coin")?),
			"board" => {
				let amount = opt_u64(&a["amount"], "the amount")?.ok_or_else(|| Error::Parse("the amount is missing".into()))?;
				w.board(asset(req_str(&a["asset"], "the asset")?)?, amount, opt_asset(&a["fee_asset"])?)
			},
			"boards" => w.boards(),
			"receive" => w.receive(opt_asset(&a["asset"])?, opt_u64(&a["amount"], "the amount")?),
			"send" => w.send(req_str(&a["request"], "the receive request")?, opt_u64(&a["amount"], "the amount")?, opt_asset(&a["asset"])?),
			"mailbox" => w.mailbox(),
			"quote" => {
				let quote = w.refresh_quote(&leaves(a)?, opt_u64(&a["max_fee_ppm"], "the fee bound")?)?;
				Ok(json!({"coins": quote.coins()}))
			},
			"participate" => {
				// The fee is shown before anything is signed: the page shows
				// the quote, and the participation goes ahead only on the
				// very fees it showed.
				let quote = w.refresh_quote(&leaves(a)?, opt_u64(&a["max_fee_ppm"], "the fee bound")?)?;
				let now = json!(quote.coins());
				if a["shown"] != now {
					return Err(Error::Refused(format!("the refresh fees changed since they were shown; they are now {}", now)));
				}
				let not_before = opt_u64(&a["not_before"], "not before")?
					.map(|t| u32::try_from(t).map_err(|_| Error::Parse("not before is out of range".into()))).transpose()?;
				w.participate(quote, not_before)
			},
			"participations" => w.participations(),
			"sync" => w.sync(),
			"schedule" => w.sync_schedule(),
			"recheck" => w.recheck(),
			"exit" => w.exit(req_str(&a["leaf_id"], "the coin")?, opt_asset(&a["fee_asset"])?),
			"refusals" => w.refusals(),
			other => Err(Error::Refused(format!("no command {}", other))),
		}
	}
}

fn leaves(a: &Value) -> Result<Vec<String>, Error> {
	match &a["leaves"] {
		Value::Null => Ok(vec![]),
		Value::Array(v) => v.iter().map(|l| l.as_str().map(String::from).ok_or_else(|| Error::Parse("a coin is not text".into()))).collect(),
		other => Err(Error::Parse(format!("the coins: {}", other))),
	}
}
