//! `arcad`: the Arca operator's server.
//!
//!     arcad <config.toml>
//!
//! The configuration is `server::server::Config`; `server/arcad.example.toml`
//! shows every setting. The operator key lives in `arca-signer`, which must be
//! running first.

use server::server::{Config, Server};

#[tokio::main]
async fn main() {
	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
	let path = match std::env::args().nth(1) {
		Some(p) => p,
		None => {
			eprintln!("usage: arcad <config.toml>");
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
