//! `arcad`: the Arca operator's server.
//!
//!     arcad <config.toml>
//!     arcad <config.toml> address
//!     arcad <config.toml> expired-salts
//!
//! The configuration is `server::server::Config`; `server/arcad.example.toml`
//! shows every setting. The operator key lives in `arca-signer`, which must be
//! running first.
//!
//! With `address`, it hands out a receive address of the operator's on-chain
//! wallet, records it in the database and prints it as JSON
//! (`{"address", "script_pubkey", "index"}`), then exits: what the operator
//! pays to fund the wallet. It needs the database, the mnemonic file and the
//! node, not the signer, and may run beside the server.
//!
//! With `expired-salts`, it prints the salts the signer's record no longer
//! needs, one hex salt a line (`server::server::expired_salts`): what
//! `arca-signer --compact-into … --drop-salts` drops. It needs the database
//! alone.
//!
//! Running, it reads its configuration again on SIGHUP and takes the assets
//! it serves, with their smallest leaves and rate sources, and the assets a
//! round's fee is paid in, without a restart
//! (`server::server::Server::reload`): an asset added is served from then
//! on. A configuration that does not read, or that leaves out an asset
//! served now, is refused whole and the server runs on as it was; any other
//! setting that changed takes a restart, and the log says which.

use server::server::{expired_salts, receive_address, Config, Server};

#[tokio::main]
async fn main() {
	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
	let path = match std::env::args().nth(1) {
		Some(p) => p,
		None => {
			eprintln!("usage: arcad <config.toml> [address | expired-salts]");
			std::process::exit(2);
		},
	};
	let text = match std::fs::read_to_string(&path) {
		Ok(t) => t,
		Err(e) => {
			eprintln!("arcad: {}: {}", path, e);
			std::process::exit(2);
		},
	};
	let config: Config = match toml::from_str(&text) {
		Ok(c) => c,
		Err(e) => {
			eprintln!("arcad: {}: {}", path, e);
			std::process::exit(2);
		},
	};
	match std::env::args().nth(2).as_deref() {
		None => {},
		Some("address") => match receive_address(&config).await {
			Ok((index, script, address)) => {
				let hex: String = script.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
				println!("{}", serde_json::json!({"address": address, "script_pubkey": hex, "index": index}));
				return;
			},
			Err(e) => {
				eprintln!("arcad: {}", e);
				std::process::exit(1);
			},
		},
		Some("expired-salts") => match expired_salts(&config).await {
			Ok(salts) => {
				for s in salts {
					println!("{}", s.iter().map(|b| format!("{:02x}", b)).collect::<String>());
				}
				return;
			},
			Err(e) => {
				eprintln!("arcad: {}", e);
				std::process::exit(1);
			},
		},
		Some(other) => {
			eprintln!("arcad: unknown command {:?}; usage: arcad <config.toml> [address | expired-salts]", other);
			std::process::exit(2);
		},
	}
	let server = match Server::start(&config).await {
		Ok(s) => s,
		Err(e) => {
			eprintln!("arcad: {}", e);
			std::process::exit(1);
		},
	};
	println!("arcad listening on {}", server.addr);
	let mut hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
		Ok(h) => h,
		Err(e) => {
			eprintln!("arcad: SIGHUP: {}", e);
			std::process::exit(1);
		},
	};
	loop {
		tokio::select! {
			_ = tokio::signal::ctrl_c() => break,
			_ = hangup.recv() => reload(&server, &path).await,
		}
	}
	server.stop();
}

/// Reads the configuration at `path` again and hands it to the running
/// server, logging what it took.
async fn reload(server: &Server, path: &str) {
	let config: Config = match std::fs::read_to_string(path).map_err(|e| e.to_string()).and_then(|t| toml::from_str(&t).map_err(|e| e.to_string())) {
		Ok(c) => c,
		Err(e) => {
			log::error!("reload: {}: {}; the server runs on as it was", path, e);
			return;
		},
	};
	match server.reload(&config).await {
		Ok(r) => log::info!("reload: {}: {} asset(s) added, {} changed{}", path, r.added.len(), r.changed.len(),
			if r.needs_restart.is_empty() { String::new() } else { format!("; take a restart: {}", r.needs_restart.join(", ")) }),
		Err(e) => log::error!("reload: {}: {}", path, e),
	}
}
