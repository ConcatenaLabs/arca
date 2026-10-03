//! `arca-signer`: holds the operator key `S` and signs the rebindable messages
//! of collaborative paths and the spends of the operator's own paths, each
//! built by the signer itself, and nothing else, for the server on a Unix
//! socket. See `server::signer` for the protocol.
//!
//!     arca-signer --key-file <file> --genesis <hash> --socket <path> --record <file>
//!
//! The key file holds the 32-byte secret key as 64 hex characters, and must
//! not be readable by anyone but its owner. The genesis hash is in display
//! order, as `getblockhash 0` prints it. The socket is created with mode 0600.
//! The record is the signer's append-only record of every rebindable message
//! it signed (`server::signer::SpendRecord`), created when absent: it is what
//! makes the signer the one-spend authority, so it is kept on durable storage
//! and never rolled back, whatever is done to the server's database.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use elements::BlockHash;
use rand::RngCore;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use arca_covenant::message::rebind_message;
use arca_covenant::sign::{script_spend_sighash, sign_digest, verify_digest};
use arca_covenant::Chain;
use server::signer::{
	check_spend, hex, parse_amount, unhex, unhex32, Request, Response, Signed, SpendRecord, ALREADY_SIGNED, MAX_REQUEST,
};

struct Args {
	key_file: PathBuf,
	genesis: BlockHash,
	socket: PathBuf,
	record: PathBuf,
}

fn args() -> Result<Args, String> {
	let mut key_file = None;
	let mut genesis = None;
	let mut socket = None;
	let mut record = None;
	let mut it = std::env::args().skip(1);
	while let Some(a) = it.next() {
		let mut value = || it.next().ok_or_else(|| format!("{} needs a value", a));
		match a.as_str() {
			"--key-file" => key_file = Some(PathBuf::from(value()?)),
			"--genesis" => genesis = Some(BlockHash::from_str(&value()?).map_err(|e| format!("--genesis: {}", e))?),
			"--socket" => socket = Some(PathBuf::from(value()?)),
			"--record" => record = Some(PathBuf::from(value()?)),
			other => return Err(format!("unknown argument {}", other)),
		}
	}
	Ok(Args {
		key_file: key_file.ok_or("--key-file is required")?,
		genesis: genesis.ok_or("--genesis is required")?,
		socket: socket.ok_or("--socket is required")?,
		record: record.ok_or("--record is required: the signer keeps a record of every spend it co-signs")?,
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
fn answer(key: &Keypair, chain: &Chain, genesis: BlockHash, record: &Mutex<SpendRecord>, line: &str) -> Response {
	let none = Response::default();
	let req: Request = match serde_json::from_str(line) {
		Ok(r) => r,
		Err(e) => return Response { error: Some(format!("not a request: {}", e)), ..none },
	};
	match req {
		Request::Pubkey {} => Response { pubkey: Some(hex(&key.x_only_public_key().0.serialize())), ..none },
		Request::Rebind { owner, owner_sig, salt, asset_in, value_in, outputs, forfeit } => {
			let parsed = (|| -> Result<_, String> {
				let owner = XOnlyPublicKey::from_slice(&unhex(&owner)?).map_err(|e| format!("owner: {}", e))?;
				let owner_sig = Signature::from_slice(&unhex(&owner_sig)?).map_err(|e| format!("owner_sig: {}", e))?;
				let salt = unhex32(&salt)?;
				let asset_in = elements::AssetId::from_str(&asset_in).map_err(|e| format!("asset_in: {}", e))?;
				let value_in = parse_amount(&value_in)?;
				if outputs.is_empty() || outputs.len() > arca_covenant::leaf::MAX_OUTPUTS as usize {
					return Err(format!("{} committed outputs; a collaborative path commits to 1 to 4", outputs.len()));
				}
				let outputs = outputs.iter().map(|o| o.to_output()).collect::<Result<Vec<_>, _>>()?;
				// A forfeit is a forfeit only if its one output is the forfeit
				// output its parts make, of the coin's asset and less than it.
				let kind = match &forfeit {
					None => Signed::Spend,
					Some(f) => {
						let policy = f.to_policy(key.x_only_public_key().0)?;
						match outputs.as_slice() {
							[o] if o.script_pubkey == policy.script_pubkey() && o.asset == asset_in && o.value < value_in => {},
							_ => return Err("the forfeit's parts do not make the one output committed to".into()),
						}
						Signed::Forfeit(policy.connector.into_inner().to_byte_array())
					},
				};
				Ok((owner, owner_sig, salt, asset_in, value_in, outputs, kind))
			})();
			let (owner, owner_sig, salt, asset_in, value_in, outputs, kind) = match parsed {
				Ok(p) => p,
				Err(e) => return Response { error: Some(e), ..none },
			};
			let message = match rebind_message(&chain.leaf_constant(&salt), asset_in, value_in, &outputs) {
				Ok(m) => m,
				Err(e) => return Response { error: Some(e.to_string()), ..none },
			};
			// The owner signed this very message: an entry under its key is
			// its own doing, never another holder's.
			if !verify_digest(&owner_sig, &message.digest, &owner) {
				return Response {
					error: Some(format!("the owner's signature over {} does not verify under the key {}: the signer records a message \
						only under the key of the owner who signed it", hex(&message.digest), hex(&owner.serialize()))),
					..none
				};
			}
			// On disk before anything is signed.
			let admitted = record.lock().unwrap_or_else(|e| e.into_inner()).admit(&owner.serialize(), &salt, kind, &message.digest);
			if let Err(e) = admitted {
				eprintln!("arca-signer: refused rebind {} for the leaf of {} under salt {}: {}", hex(&message.digest),
					hex(&owner.serialize()), hex(&salt), e);
				let code = e.starts_with(ALREADY_SIGNED).then(|| ALREADY_SIGNED.to_string());
				return Response { error: Some(e), code, ..none };
			}
			let mut aux = [0u8; 32];
			rand::rngs::OsRng.fill_bytes(&mut aux);
			let sig = sign_digest(key, &message.digest, &aux);
			eprintln!("arca-signer: signed rebind {} ({}) for the leaf of {} under salt {}", hex(&message.digest),
				match kind { Signed::Spend => "spend", Signed::Forfeit(_) => "forfeit" }, hex(&owner.serialize()), hex(&salt));
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
	let record = match SpendRecord::open(&args.record) {
		Ok(r) => Arc::new(Mutex::new(r)),
		Err(e) => {
			eprintln!("arca-signer: the record: {}", e);
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
	eprintln!("arca-signer: S = {} on {}; {} message(s) in the record {}", hex(&key.x_only_public_key().0.serialize()),
		args.socket.display(), record.lock().unwrap_or_else(|e| e.into_inner()).len(), args.record.display());
	loop {
		let (stream, _) = match listener.accept().await {
			Ok(s) => s,
			Err(e) => {
				eprintln!("arca-signer: accept: {}", e);
				continue;
			},
		};
		let record = record.clone();
		tokio::spawn(async move {
			let (read, mut write) = stream.into_split();
			let mut reader = BufReader::new(read).take(MAX_REQUEST as u64 + 1);
			let mut line = String::new();
			let reply = match reader.read_line(&mut line).await {
				Ok(n) if n > MAX_REQUEST => Response { error: Some("request too long".into()), ..Response::default() },
				Ok(_) => answer(&key, &chain, genesis, &record, line.trim_end()),
				Err(e) => Response { error: Some(e.to_string()), ..Response::default() },
			};
			let mut out = serde_json::to_string(&reply).unwrap_or_else(|_| "{\"error\":\"internal\"}".into());
			out.push('\n');
			let _ = write.write_all(out.as_bytes()).await;
		});
	}
}
