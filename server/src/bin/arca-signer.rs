//! `arca-signer`: holds the operator key `S` and signs the rebindable messages
//! of collaborative paths and the spends of the operator's own paths, each
//! built by the signer itself, and nothing else, for the server on a Unix
//! socket. See `server::signer` for the protocol.
//!
//!     arca-signer --key-file <file> --genesis <hash> --socket <path>
//!
//! The key file holds the 32-byte secret key as 64 hex characters, and must
//! not be readable by anyone but its owner. The genesis hash is in display
//! order, as `getblockhash 0` prints it. The socket is created with mode 0600.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::str::FromStr;

use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey};
use elements::BlockHash;
use rand::RngCore;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use arca_covenant::message::rebind_message;
use arca_covenant::sign::{script_spend_sighash, sign_digest};
use arca_covenant::Chain;
use server::signer::{check_spend, hex, parse_amount, unhex, unhex32, Request, Response, MAX_REQUEST};

struct Args {
	key_file: PathBuf,
	genesis: BlockHash,
	socket: PathBuf,
}

fn args() -> Result<Args, String> {
	let mut key_file = None;
	let mut genesis = None;
	let mut socket = None;
	let mut it = std::env::args().skip(1);
	while let Some(a) = it.next() {
		let mut value = || it.next().ok_or_else(|| format!("{} needs a value", a));
		match a.as_str() {
			"--key-file" => key_file = Some(PathBuf::from(value()?)),
			"--genesis" => genesis = Some(BlockHash::from_str(&value()?).map_err(|e| format!("--genesis: {}", e))?),
			"--socket" => socket = Some(PathBuf::from(value()?)),
			other => return Err(format!("unknown argument {}", other)),
		}
	}
	Ok(Args {
		key_file: key_file.ok_or("--key-file is required")?,
		genesis: genesis.ok_or("--genesis is required")?,
		socket: socket.ok_or("--socket is required")?,
	})
}

fn load_key(path: &PathBuf) -> Result<Keypair, String> {
	let meta = std::fs::metadata(path).map_err(|e| format!("{}: {}", path.display(), e))?;
	if meta.permissions().mode() & 0o077 != 0 {
		return Err(format!("{} is readable by others than its owner; chmod 600 it", path.display()));
	}
	let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path.display(), e))?;
	let secret = unhex32(text.trim()).map_err(|e| format!("{}: {}", path.display(), e))?;
	let key = SecretKey::from_slice(&secret).map_err(|e| format!("{}: {}", path.display(), e))?;
	Ok(Keypair::from_secret_key(&Secp256k1::new(), &key))
}

/// Answers one request line.
fn answer(key: &Keypair, chain: &Chain, genesis: BlockHash, line: &str) -> Response {
	let none = Response { pubkey: None, signature: None, error: None };
	let req: Request = match serde_json::from_str(line) {
		Ok(r) => r,
		Err(e) => return Response { error: Some(format!("not a request: {}", e)), ..none },
	};
	match req {
		Request::Pubkey {} => Response { pubkey: Some(hex(&key.x_only_public_key().0.serialize())), ..none },
		Request::Rebind { salt, asset_in, value_in, outputs } => {
			let parsed = (|| -> Result<_, String> {
				let salt = unhex32(&salt)?;
				let asset_in = elements::AssetId::from_str(&asset_in).map_err(|e| format!("asset_in: {}", e))?;
				let value_in = parse_amount(&value_in)?;
				if outputs.is_empty() || outputs.len() > arca_covenant::leaf::MAX_OUTPUTS as usize {
					return Err(format!("{} committed outputs; a collaborative path commits to 1 to 4", outputs.len()));
				}
				let outputs = outputs.iter().map(|o| o.to_output()).collect::<Result<Vec<_>, _>>()?;
				Ok((salt, asset_in, value_in, outputs))
			})();
			let (salt, asset_in, value_in, outputs) = match parsed {
				Ok(p) => p,
				Err(e) => return Response { error: Some(e), ..none },
			};
			let message = match rebind_message(&chain.leaf_constant(&salt), asset_in, value_in, &outputs) {
				Ok(m) => m,
				Err(e) => return Response { error: Some(e.to_string()), ..none },
			};
			let mut aux = [0u8; 32];
			rand::rngs::OsRng.fill_bytes(&mut aux);
			let sig = sign_digest(key, &message.digest, &aux);
			eprintln!("arca-signer: signed rebind {} for salt {}", hex(&message.digest), hex(&salt));
			Response { signature: Some(hex(sig.as_ref())), ..none }
		},
		Request::Spend { tx, prevouts, input, leaf } => {
			let parsed = (|| -> Result<_, String> {
				let tx: elements::Transaction = elements::encode::deserialize(&unhex(&tx)?).map_err(|e| format!("tx: {}", e))?;
				let prevouts = prevouts.iter()
					.map(|p| elements::encode::deserialize::<elements::TxOut>(&unhex(p)?).map_err(|e| format!("prevout: {}", e)))
					.collect::<Result<Vec<_>, String>>()?;
				let leaf = elements::Script::from(unhex(&leaf)?);
				check_spend(&key.x_only_public_key().0, &tx, &prevouts, input as usize, &leaf)?;
				let digest = script_spend_sighash(&tx, input as usize, &prevouts, &leaf, genesis).map_err(|e| e.to_string())?;
				Ok((tx.txid(), digest))
			})();
			let (txid, digest) = match parsed {
				Ok(p) => p,
				Err(e) => return Response { error: Some(e), ..none },
			};
			let mut aux = [0u8; 32];
			rand::rngs::OsRng.fill_bytes(&mut aux);
			let sig = sign_digest(key, &digest, &aux);
			eprintln!("arca-signer: signed spend of input {} of {}", input, txid);
			Response { signature: Some(hex(sig.as_ref())), ..none }
		},
	}
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
	let args = match args() {
		Ok(a) => a,
		Err(e) => {
			eprintln!("arca-signer: {}", e);
			std::process::exit(2);
		},
	};
	let key = match load_key(&args.key_file) {
		Ok(k) => k,
		Err(e) => {
			eprintln!("arca-signer: {}", e);
			std::process::exit(2);
		},
	};
	let chain = Chain::new(args.genesis);
	let genesis = args.genesis;
	let _ = std::fs::remove_file(&args.socket);
	let listener = match UnixListener::bind(&args.socket) {
		Ok(l) => l,
		Err(e) => {
			eprintln!("arca-signer: {}: {}", args.socket.display(), e);
			std::process::exit(2);
		},
	};
	if let Err(e) = std::fs::set_permissions(&args.socket, std::fs::Permissions::from_mode(0o600)) {
		eprintln!("arca-signer: {}: {}", args.socket.display(), e);
		std::process::exit(2);
	}
	eprintln!("arca-signer: S = {} on {}", hex(&key.x_only_public_key().0.serialize()), args.socket.display());
	loop {
		let (stream, _) = match listener.accept().await {
			Ok(s) => s,
			Err(e) => {
				eprintln!("arca-signer: accept: {}", e);
				continue;
			},
		};
		tokio::spawn(async move {
			let (read, mut write) = stream.into_split();
			let mut reader = BufReader::new(read).take(MAX_REQUEST as u64 + 1);
			let mut line = String::new();
			let reply = match reader.read_line(&mut line).await {
				Ok(n) if n > MAX_REQUEST => Response { pubkey: None, signature: None, error: Some("request too long".into()) },
				Ok(_) => answer(&key, &chain, genesis, line.trim_end()),
				Err(e) => Response { pubkey: None, signature: None, error: Some(e.to_string()) },
			};
			let mut out = serde_json::to_string(&reply).unwrap_or_else(|_| "{\"error\":\"internal\"}".into());
			out.push('\n');
			let _ = write.write_all(out.as_bytes()).await;
		});
	}
}
