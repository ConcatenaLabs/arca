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
	let _ = tokio::signal::ctrl_c().await;
	server.stop();
}
