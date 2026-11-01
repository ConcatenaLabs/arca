//! The Bitcoin ark wallet for a browser.
//!
//! [command] holds the wallet's commands by name, in plain Rust: a program
//! that links the wallet natively opens it with [open] and calls
//! [command::run]. On `wasm32`, [BtcArk] exports the same to a dedicated
//! worker, with the wallet's store in IndexedDB, its server reached over
//! gRPC-web and its chain read from an Esplora server.

pub mod command;
pub mod exit;
pub mod tower;

use std::sync::Arc;

pub use command::run;

/// Opens the wallet of a phrase, creating it on its first open. A wallet made
/// anew from a phrase that held coins in the ark before takes back what the
/// server's recovery mailbox kept for it.
///
/// The wallet's daemon runs from here on: it claims Lightning payments the
/// server holds for it, takes in payments sent to it in the ark, follows its
/// boards and refreshes its coins in the server's rounds.
pub async fn open(
	network: &str,
	mnemonic: &str,
	server: &str,
	esplora: &str,
	persister: Option<Arc<dyn bark::persist::BarkPersister>>,
) -> anyhow::Result<bark::Wallet> {
	let net = command::network(network)?;
	let seed = command::seed(net, mnemonic)?;
	let config = command::config(net, server, esplora);
	let mut args = bark::OpenWalletArgs::default();
	args.persister = persister;
	exit::attach_funding(&mut args, net, mnemonic).await?;
	bark::Wallet::open(net, seed, config, args).await
}

#[cfg(target_arch = "wasm32")]
mod web {
	use wasm_bindgen::prelude::*;

	fn err(e: anyhow::Error) -> JsValue {
		JsValue::from_str(&format!("{:#}", e))
	}

	/// Logs to the console at `level` (error, warn, info, debug, trace).
	#[wasm_bindgen(js_name = setLogLevel)]
	pub fn set_log_level(level: &str) {
		console_error_panic_hook::set_once();
		let l = level.parse().unwrap_or(log::Level::Warn);
		let _ = console_log::init_with_level(l);
		log::set_max_level(l.to_level_filter());
	}

	/// The commands [BtcArk::run] answers to.
	#[wasm_bindgen]
	pub fn commands() -> Vec<String> {
		crate::command::COMMANDS.iter().map(|s| s.to_string()).collect()
	}

	/// One phrase's Bitcoin ark wallet.
	#[wasm_bindgen]
	pub struct BtcArk {
		wallet: bark::Wallet,
	}

	#[wasm_bindgen]
	impl BtcArk {
		/// Opens (or creates) the wallet of `mnemonic` on `network`, against the ark
		/// server at `server` (gRPC-web) and the Esplora server at `esplora`.
		pub async fn open(network: String, mnemonic: String, server: String, esplora: String) -> Result<BtcArk, JsValue> {
			console_error_panic_hook::set_once();
			let wallet = crate::open(&network, &mnemonic, &server, &esplora, None).await.map_err(err)?;
			Ok(BtcArk { wallet })
		}

		/// Runs one command: `args` and the answer are JSON text.
		pub fn run(&self, cmd: String, args: String) -> js_sys::Promise {
			let wallet = self.wallet.clone();
			wasm_bindgen_futures::future_to_promise(async move {
				let args: serde_json::Value = if args.trim().is_empty() {
					serde_json::Value::Object(Default::default())
				} else {
					serde_json::from_str(&args).map_err(|e| JsValue::from_str(&format!("the arguments are not JSON: {}", e)))?
				};
				let out = crate::command::run(&wallet, &cmd, &args).await.map_err(err)?;
				Ok(JsValue::from_str(&out.to_string()))
			})
		}

		/// Stops the wallet's daemon.
		pub fn close(&self) {
			self.wallet.stop_daemon();
		}
	}
}
