//! `arcad`: the Arca operator's server.
//!
//!     arcad <config.toml>
//!     arcad <config.toml> address
//!     arcad <config.toml> expired-salts
//!     arcad bond-key <file>
//!     arcad <config.toml> bond-address
//!     arcad <config.toml> bond-post <node wallet> <asset> <atoms> [<fee asset>]
//!     arcad <config.toml> bond-notice <withdrawal key file>
//!     arcad <config.toml> bond-withdraw <withdrawal key file> <address>
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
//! The `bond-` commands work the operator's equivocation bond
//! (`server::bond`, the `[bond]` section; the server's README, "The
//! equivocation bond"), each printing JSON. `bond-key` draws the withdrawal
//! key `W` into a new file only its owner can read and prints its public key,
//! which `[bond] withdraw_key` names. `bond-address` prints the bond's
//! address and terms; it needs the node and the signer, for `S`. `bond-post`
//! pays the bond from a node wallet the operator names, never a treasury's, a
//! reserve's, a bridge's, an escrow's or another service's, and prints the
//! `outpoint` line for `[bond]`. `bond-notice` gives the notice and prints the
//! `notice` line; `bond-withdraw` takes the bond to an address once the
//! notice's delay has run. Those two sign with `W`'s key from its file and
//! pay their fee from the operator's on-chain wallet; they need the
//! database, the mnemonic file, the node and the signer.
//!
//! Running, it reads its configuration again on SIGHUP and takes the assets
//! it serves, with their smallest leaves and rate sources, and the assets a
//! round's fee is paid in, without a restart
//! (`server::server::Server::reload`): an asset added is served from then
//! on. A configuration that does not read, or that leaves out an asset
//! served now, is refused whole and the server runs on as it was; any other
//! setting that changed takes a restart, and the log says which.

use std::str::FromStr;

use server::server::{bond_address, bond_notice, bond_post, bond_withdraw, expired_salts, receive_address, Config, Server};

const USAGE: &str = "usage: arcad <config.toml> [address | expired-salts | bond-address | bond-post <node wallet> <asset> <atoms> \
	[<fee asset>] | bond-notice <key file> | bond-withdraw <key file> <address>], or arcad bond-key <file>";

/// Prints `r` as JSON, or the error, and exits.
fn done(r: Result<serde_json::Value, String>) -> ! {
	match r {
		Ok(v) => {
			println!("{}", v);
			std::process::exit(0);
		},
		Err(e) => {
			eprintln!("arcad: {}", e);
			std::process::exit(1);
		},
	}
}

#[tokio::main]
async fn main() {
	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
	let args: Vec<String> = std::env::args().collect();
	if args.get(1).map(String::as_str) == Some("bond-key") {
		match args.get(2) {
			Some(f) => done(server::bond::new_key(std::path::Path::new(f)).map(|k| serde_json::json!({"withdraw_key": k.to_string(), "file": f}))),
			None => {
				eprintln!("{}", USAGE);
				std::process::exit(2);
			},
		}
	}
	let path = match std::env::args().nth(1) {
		Some(p) => p,
		None => {
			eprintln!("{}", USAGE);
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
		Some("bond-address") => done(bond_address(&config).await.map_err(|e| e.to_string())),
		Some("bond-post") => {
			let (Some(wallet), Some(asset), Some(atoms)) = (args.get(3), args.get(4), args.get(5)) else {
				eprintln!("{}", USAGE);
				std::process::exit(2);
			};
			let parsed = (|| -> Result<_, String> {
				let asset = elements::AssetId::from_str(asset).map_err(|e| format!("asset {:?}: {}", asset, e))?;
				let atoms: u64 = atoms.parse().map_err(|e| format!("atoms {:?}: {}", atoms, e))?;
				let fee = args.get(6).map(|f| elements::AssetId::from_str(f).map_err(|e| format!("fee asset {:?}: {}", f, e))).transpose()?;
				Ok((asset, atoms, fee))
			})();
			match parsed {
				Ok((asset, atoms, fee)) => done(bond_post(&config, wallet, asset, atoms, fee).await.map_err(|e| e.to_string())),
				Err(e) => done(Err(e)),
			}
		},
		Some("bond-notice") => match args.get(3) {
			Some(k) => done(bond_notice(&config, std::path::Path::new(k)).await.map_err(|e| e.to_string())),
			None => {
				eprintln!("{}", USAGE);
				std::process::exit(2);
			},
		},
		Some("bond-withdraw") => match (args.get(3), args.get(4)) {
			(Some(k), Some(to)) => done(bond_withdraw(&config, std::path::Path::new(k), to).await.map_err(|e| e.to_string())),
			_ => {
				eprintln!("{}", USAGE);
				std::process::exit(2);
			},
		},
		Some(other) => {
			eprintln!("arcad: unknown command {:?}; {}", other, USAGE);
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
