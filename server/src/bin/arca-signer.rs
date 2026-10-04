//! `arca-signer`: holds the operator key `S` and signs the rebindable messages
//! of collaborative paths and the spends of the operator's own paths, each
//! built by the signer itself, and nothing else, for the server on a Unix
//! socket. See `server::signer` for the protocol.
//!
//!     arca-signer --key-file <file> --genesis <hash> --socket <path> --record <file> \
//!         [--keeper <host:port>=<key> …] [--keepers-required <n>] [--keeper-timeout-ms <ms>]
//!     arca-signer --key-file <file> --genesis <hash> --record <file> --create-record
//!     arca-signer --key-file <file> --genesis <hash> --record <file> --compact-into <new file> --drop-salts <file>
//!     arca-signer --key-file <file> --genesis <hash> --record <file> --clear-stopped
//!
//! The key file holds the 32-byte secret key as 64 hex characters, and must
//! not be readable by anyone but its owner. The genesis hash is in display
//! order, as `getblockhash 0` prints it. The socket is created with mode 0600.
//! The record is the signer's append-only record of every rebindable message
//! it signed (`server::signer::SpendRecord`): it is what makes the signer the
//! one-spend authority, so it is kept on durable storage and never rolled
//! back, whatever is done to the server's database. The signer starts only on
//! its record and locks it while it runs. `--create-record` makes a new,
//! empty record for this key and chain, once, and exits: a record is never
//! made in passing, so one that is lost is never silently replaced.
//!
//! `--compact-into` writes a compacted copy of the record to a new file and
//! exits (`server::signer::SpendRecord::compact`): every entry under a salt
//! listed in the `--drop-salts` file (one hex salt a line, as
//! `arcad <config> expired-salts` prints them) is dropped, every other entry
//! carried over, and the new record goes on from the old one's latest entry.
//! It locks the record, so it runs with the signer stopped; the operator then
//! puts the new file in the record's place and starts the signer on it. The
//! new record keeps the running hash of every entry it drops.
//!
//! Every head of the record the signer hands out is signed with `S`, and so
//! is every running hash a witness is answered with, and the record's end
//! together with the nonce the witness carried. A head it signed that its
//! record does not hold, handed back by a wallet, proves the record was
//! rolled back or replaced: the signer writes the proof to
//! `<record>.stopped` and signs no rebindable message and no head from then
//! on, across restarts (`server::signer::SpendRecord::witness`), and answers
//! every witness with that proof. Only `--clear-stopped`, run with the
//! signer stopped, removes that file, after printing it.
//!
//! With keepers (`--keeper`, one for each, on other machines: `server::keeper`),
//! the signer answers an entry of its record only once its signed head is
//! held outside this machine: after it has written and synced an entry and
//! signed its head, it hands the record's latest head to every keeper and
//! releases the co-signature only when `--keepers-required` of them (all, by
//! default) have acknowledged it; otherwise it answers that it cannot sign
//! now (`keepers_unavailable`), the entry stays, and the same request again
//! completes. At start, and before the first signature after a start, it asks
//! the keepers for the latest head each holds: one past the record's end, or
//! with another hash at an entry the record holds, is proof the record was
//! rolled back, and stops the signer; and until enough keepers have answered
//! (enough that any set of `--keepers-required` of them includes one) it
//! signs nothing the record governs. Every head it hands out carries the
//! acknowledgements it has of it.

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
use server::keeper::{start_quorum, Held, KeeperAddr, KeeperClient, WireAck, KEEPERS_UNAVAILABLE};
use server::signer::{
	check_spend, hex, parse_amount, record_end_digest, record_head_digest, unhex, unhex32, Request, Response, Signed, SpendRecord,
	WireEntryRef, WireKeepers, WireStopProof, ALREADY_SIGNED, MAX_ENTRIES, MAX_REQUEST, MAX_WITNESS, RECORD_BEHIND, RECORD_DIFFERS,
	STOPPED,
};

struct Args {
	key_file: PathBuf,
	genesis: BlockHash,
	/// `None` with `--create-record`, which serves nothing.
	socket: Option<PathBuf>,
	record: PathBuf,
	create_record: bool,
	/// `--compact-into` and `--drop-salts`.
	compact: Option<(PathBuf, PathBuf)>,
	clear_stopped: bool,
	keepers: Vec<KeeperAddr>,
	/// How many keepers must hold a head; all of them by default.
	keepers_required: Option<usize>,
	keeper_timeout: std::time::Duration,
}

fn args() -> Result<Args, String> {
	let mut key_file = None;
	let mut genesis = None;
	let mut socket = None;
	let mut record = None;
	let mut create_record = false;
	let mut compact_into = None;
	let mut drop_salts = None;
	let mut clear_stopped = false;
	let mut keepers: Vec<KeeperAddr> = vec![];
	let mut keepers_required = None;
	let mut keeper_timeout = std::time::Duration::from_secs(5);
	let mut it = std::env::args().skip(1);
	while let Some(a) = it.next() {
		let mut value = || it.next().ok_or_else(|| format!("{} needs a value", a));
		match a.as_str() {
			"--key-file" => key_file = Some(PathBuf::from(value()?)),
			"--genesis" => genesis = Some(BlockHash::from_str(&value()?).map_err(|e| format!("--genesis: {}", e))?),
			"--socket" => socket = Some(PathBuf::from(value()?)),
			"--record" => record = Some(PathBuf::from(value()?)),
			"--create-record" => create_record = true,
			"--compact-into" => compact_into = Some(PathBuf::from(value()?)),
			"--drop-salts" => drop_salts = Some(PathBuf::from(value()?)),
			"--clear-stopped" => clear_stopped = true,
			"--keeper" => keepers.push(value()?.parse().map_err(|e| format!("--keeper: {}", e))?),
			"--keepers-required" => keepers_required = Some(value()?.parse::<usize>().map_err(|e| format!("--keepers-required: {}", e))?),
			"--keeper-timeout-ms" => keeper_timeout = std::time::Duration::from_millis(value()?.parse::<u64>()
				.map_err(|e| format!("--keeper-timeout-ms: {}", e))?),
			other => return Err(format!("unknown argument {}", other)),
		}
	}
	let compact = match (compact_into, drop_salts) {
		(Some(i), Some(d)) => Some((i, d)),
		(None, None) => None,
		_ => return Err("--compact-into and --drop-salts go together".into()),
	};
	if !create_record && !clear_stopped && compact.is_none() && socket.is_none() {
		return Err("--socket is required".into());
	}
	match keepers_required {
		Some(_) if keepers.is_empty() => return Err("--keepers-required needs a --keeper".into()),
		Some(k) if k == 0 || k > keepers.len() => return Err(format!("--keepers-required {}: from 1 to the {} keepers named", k, keepers.len())),
		_ => {},
	}
	if keepers.iter().enumerate().any(|(i, k)| keepers[..i].iter().any(|o| o.key == k.key)) {
		return Err("--keeper: two keepers with one key".into());
	}
	Ok(Args {
		key_file: key_file.ok_or("--key-file is required")?,
		genesis: genesis.ok_or("--genesis is required")?,
		socket,
		record: record.ok_or("--record is required: the signer keeps a record of every spend it co-signs")?,
		create_record,
		compact,
		clear_stopped,
		keepers,
		keepers_required,
		keeper_timeout,
	})
}

/// The signer's keepers: their clients, how many must hold a head, whether
/// enough of them answered for their latest since the signer started, and
/// the latest head they acknowledged, with the acknowledgements.
struct Keepers {
	list: Vec<KeeperClient>,
	required: usize,
	checked: tokio::sync::Mutex<bool>,
	/// Also what one hand-over at a time holds: requests that wait for it
	/// are answered by the head it gets acknowledged when that head covers
	/// their entry.
	acked: tokio::sync::Mutex<Option<(WireEntryRef, Vec<WireAck>)>>,
}

/// What every request is answered from.
struct State {
	key: Keypair,
	chain: Chain,
	genesis: BlockHash,
	record: Mutex<SpendRecord>,
	keepers: Option<Keepers>,
}

impl State {
	fn operator(&self) -> XOnlyPublicKey {
		self.key.x_only_public_key().0
	}

	/// Why the signer is stopped, if it is.
	fn stopped(&self) -> Option<String> {
		self.record.lock().unwrap_or_else(|e| e.into_inner()).stopped().map(str::to_string)
	}

	/// Hands `head`, a head some keeper holds, to the record: one the record
	/// does not hold (past its end, or another hash at its entry) stops the
	/// signer. Returns why it is stopped, if it is.
	fn against_record(&self, head: &WireEntryRef) -> Result<Option<String>, String> {
		let mut r = self.record.lock().unwrap_or_else(|e| e.into_inner());
		let was = r.stopped().is_some();
		r.witness(std::slice::from_ref(head))?;
		let stopped = r.stopped().map(str::to_string);
		if let (false, Some(why)) = (was, &stopped) {
			eprintln!("arca-signer: STOPPED by a keeper's head: {}", why);
		}
		Ok(stopped)
	}

	/// Asks the keepers for the latest head each holds, unless enough of them
	/// answered since the signer started. A keeper's head the record does not
	/// hold stops the signer; too few answers leave it signing nothing the
	/// record governs, until enough answer.
	async fn check_keepers(&self) -> Result<(), String> {
		let Some(k) = &self.keepers else { return Ok(()) };
		let mut checked = k.checked.lock().await;
		if *checked {
			return Ok(());
		}
		let (genesis, operator) = (self.genesis, self.operator());
		let answers = futures_join(k.list.iter().map(|c| c.latest(&genesis, &operator))).await;
		let mut answered = 0;
		let mut notes = vec![];
		for (c, a) in k.list.iter().zip(answers) {
			match a {
				Ok(head) => {
					answered += 1;
					if let Some(h) = head {
						if let Some(why) = self.against_record(&h)? {
							return Err(why);
						}
						notes.push(format!("{} holds entry {}", c.addr.addr, h.entry));
					} else {
						notes.push(format!("{} holds no head", c.addr.addr));
					}
				},
				Err(e) => notes.push(e),
			}
		}
		let need = start_quorum(k.list.len(), k.required);
		if answered < need {
			return Err(format!("{}: {} of the {} keepers answered for the latest head each holds, and {} must before the signer signs \
				anything its record governs after a start, so that it sees the latest head any {} of them hold ({})", KEEPERS_UNAVAILABLE,
				answered, k.list.len(), need, k.required, notes.join("; ")));
		}
		eprintln!("arca-signer: the keepers agree with the record ({})", notes.join("; "));
		*checked = true;
		Ok(())
	}

	/// The record's latest head, at or after entry `at_least`, acknowledged by
	/// as many keepers as must hold a head, with their acknowledgements: the
	/// head acknowledged last when it covers `at_least`, or the record's
	/// latest, handed to every keeper now. A keeper's answer that the head
	/// contradicts what it holds hands the head it holds to the record, which
	/// stops the signer on it.
	async fn held_outside(&self, at_least: u64) -> Result<(WireEntryRef, Vec<WireAck>), String> {
		let k = self.keepers.as_ref().expect("keepers");
		let mut acked = k.acked.lock().await;
		if let Some((h, a)) = acked.as_ref().filter(|(h, _)| h.entry >= at_least) {
			return Ok((h.clone(), a.clone()));
		}
		let head = {
			let r = self.record.lock().unwrap_or_else(|e| e.into_inner());
			if let Some(why) = r.stopped() {
				return Err(why.to_string());
			}
			let (n, hash) = r.head();
			signed_head(&self.key, &self.genesis, n, &hash)
		};
		let (genesis, operator) = (self.genesis, self.operator());
		let answers = futures_join(k.list.iter().map(|c| c.hold(&genesis, &operator, &head))).await;
		let mut acks = vec![];
		let mut notes = vec![];
		for (c, a) in k.list.iter().zip(answers) {
			match a {
				Ok(Held::Ack(ack)) => acks.push(ack),
				Ok(Held::Contradicts(held)) => {
					if let Some(why) = self.against_record(&held)? {
						return Err(why);
					}
					notes.push(format!("{} refused entry {}, holding entry {}", c.addr.addr, head.entry, held.entry));
				},
				Err(e) => notes.push(e),
			}
		}
		if acks.len() < k.required {
			return Err(format!("{}: {} of the {} keepers acknowledged entry {}, and {} must before the signer answers it; the entry \
				stays, and the same request again completes once they do ({})", KEEPERS_UNAVAILABLE, acks.len(), k.list.len(), head.entry,
				k.required, notes.join("; ")));
		}
		*acked = Some((head.clone(), acks.clone()));
		Ok((head, acks))
	}
}

/// Runs every future at once, and returns their outputs in order.
async fn futures_join<F: std::future::Future>(fs: impl Iterator<Item = F>) -> Vec<F::Output> {
	let mut set = Vec::new();
	for f in fs {
		set.push(Box::pin(f));
	}
	let mut out: Vec<Option<F::Output>> = set.iter().map(|_| None).collect();
	std::future::poll_fn(|cx| {
		let mut pending = false;
		for (i, f) in set.iter_mut().enumerate() {
			if out[i].is_none() {
				match f.as_mut().poll(cx) {
					std::task::Poll::Ready(v) => out[i] = Some(v),
					std::task::Poll::Pending => pending = true,
				}
			}
		}
		if pending { std::task::Poll::Pending } else { std::task::Poll::Ready(()) }
	}).await;
	out.into_iter().map(|o| o.expect("ready")).collect()
}

/// The refusal code of a signer error: the code it starts with.
fn code_of(e: &str) -> Option<String> {
	[ALREADY_SIGNED, RECORD_BEHIND, RECORD_DIFFERS, STOPPED, KEEPERS_UNAVAILABLE].into_iter()
		.find(|c| e.starts_with(&format!("{}:", c))).map(str::to_string)
}

/// `S`'s signature over entry `n` of the record, whose running hash is
/// `hash`: how every head the signer hands out is signed.
fn signed_head(key: &Keypair, genesis: &BlockHash, n: u64, hash: &[u8; 32]) -> WireEntryRef {
	let mut aux = [0u8; 32];
	rand::rngs::OsRng.fill_bytes(&mut aux);
	let sig = sign_digest(key, &record_head_digest(genesis, n, hash), &aux);
	WireEntryRef { entry: n, hash: hex(hash), signature: Some(hex(sig.as_ref())) }
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
async fn answer(state: &State, line: &str) -> Response {
	let (key, chain, genesis, record) = (&state.key, &state.chain, state.genesis, &state.record);
	let none = Response::default();
	let req: Request = match serde_json::from_str(line) {
		Ok(r) => r,
		Err(e) => return Response { error: Some(format!("not a request: {}", e)), ..none },
	};
	match req {
		Request::Pubkey {} => Response {
			pubkey: Some(hex(&key.x_only_public_key().0.serialize())),
			keepers: Some(match &state.keepers {
				Some(k) => WireKeepers { keys: k.list.iter().map(|c| hex(&c.addr.key.serialize())).collect(), required: k.required as u32 },
				None => WireKeepers::default(),
			}),
			..none
		},
		Request::Head {} => {
			let stopped = |why: String| Response { error: Some(why.clone()), code: Some(STOPPED.into()), stopped: Some(why), ..none.clone() };
			let (n, hash) = {
				let r = record.lock().unwrap_or_else(|e| e.into_inner());
				if let Some(why) = r.stopped() {
					return stopped(why.to_string());
				}
				r.head()
			};
			// With keepers, the head is handed out with their
			// acknowledgements once they hold it; without them (too few
			// answer) it goes out alone, and a wallet that pinned them keeps
			// no head of it.
			if state.keepers.is_some() {
				let held = async { state.check_keepers().await?; state.held_outside(n).await }.await;
				match held {
					Ok((h, acks)) => return Response { entry: Some(h), acks: Some(acks), ..none },
					Err(e) => {
						if let Some(why) = state.stopped() {
							return stopped(why);
						}
						eprintln!("arca-signer: the head, entry {}, goes out without the keepers' acknowledgements: {}", n, e);
					},
				}
			}
			Response { entry: Some(signed_head(key, &genesis, n, &hash)), ..none }
		},
		Request::Witness { heads, nonce } => {
			if heads.len() > MAX_WITNESS {
				return Response { error: Some(format!("{} heads; a witness names at most {}", heads.len(), MAX_WITNESS)), ..none };
			}
			let nonce = match nonce.as_deref().map(unhex32).transpose() {
				Ok(n) => n,
				Err(e) => return Response { error: Some(format!("nonce: {}", e)), ..none },
			};
			let mut r = record.lock().unwrap_or_else(|e| e.into_inner());
			let was = r.stopped().is_some();
			let mut hashes = match r.witness(&heads) {
				Ok(h) => h,
				Err(e) => return Response { error: Some(e), ..none },
			};
			// Every running hash answered is signed as a head: another hash
			// at an entry a wallet holds is then two heads `S` signed at one
			// entry, which nobody without `S` can make.
			for h in &mut hashes {
				if let Some(x) = h.hash.as_deref().and_then(|x| unhex32(x).ok()) {
					h.signature = signed_head(key, &genesis, h.entry, &x).signature;
				}
			}
			let stopped = r.stopped().map(str::to_string);
			if let (false, Some(why)) = (was, &stopped) {
				eprintln!("arca-signer: STOPPED: {}", why);
			}
			let (n, hash) = r.head();
			// The record's end with the asker's nonce: not an older head
			// replayed. A stopped signer signs it too, as part of its proof.
			let end = nonce.map(|nonce| {
				let mut aux = [0u8; 32];
				rand::rngs::OsRng.fill_bytes(&mut aux);
				let sig = sign_digest(key, &record_end_digest(&genesis, n, &hash, &nonce), &aux);
				WireEntryRef { entry: n, hash: hex(&hash), signature: Some(hex(sig.as_ref())) }
			});
			let proof = match (&stopped, r.stop_head()) {
				(Some(_), Some(p)) => {
					let held = match r.hash_of(p.entry) {
						Ok(Some(x)) if hex(&x) != p.hash => Some(signed_head(key, &genesis, p.entry, &x)),
						Ok(_) => None,
						Err(e) => return Response { error: Some(format!("the record could not be read: {}", e)), ..none },
					};
					Some(WireStopProof { head: p.clone(), held })
				},
				_ => None,
			};
			drop(r);
			// The latest head goes with the keepers' acknowledgements when
			// they acknowledged it last.
			let acks = match &state.keepers {
				Some(k) => k.acked.try_lock().ok().and_then(|a| a.as_ref().filter(|(h, _)| h.entry == n && h.hash == hex(&hash))
					.map(|(_, a)| a.clone())),
				None => None,
			};
			Response {
				entry: stopped.is_none().then(|| signed_head(key, &genesis, n, &hash)),
				acks: acks.filter(|_| stopped.is_none()),
				hashes: Some(hashes),
				stopped,
				end,
				proof,
				..none
			}
		},
		Request::Entries { after, limit } => {
			let r = record.lock().unwrap_or_else(|e| e.into_inner());
			match r.entries_after(after, limit.min(MAX_ENTRIES) as usize) {
				Ok(list) => Response { entries: Some(list.iter().map(|e| e.to_wire()).collect()), ..none },
				Err(e) => Response { error: Some(format!("the record could not be read: {}", e)), ..none },
			}
		},
		Request::Rebind { owner, owner_sig, salt, asset_in, value_in, outputs, forfeit, known } => {
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
				let known = match &known {
					Some(k) => (k.entry, unhex32(&k.hash)?),
					None => (0, [0; 32]),
				};
				Ok((owner, owner_sig, salt, asset_in, value_in, outputs, kind, known))
			})();
			let (owner, owner_sig, salt, asset_in, value_in, outputs, kind, known) = match parsed {
				Ok(p) => p,
				Err(e) => return Response { error: Some(e), ..none },
			};
			// After a start, nothing the record governs is signed before
			// enough keepers have answered for their latest.
			if let Err(e) = state.check_keepers().await {
				eprintln!("arca-signer: refused rebind for the leaf of {} under salt {}: {}", hex(&owner.serialize()), hex(&salt), e);
				return Response { code: code_of(&e), error: Some(e), ..none };
			}
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
			// The record holds what the database knows, the same; then the
			// message is on disk before anything is signed.
			let admitted = {
				let mut r = record.lock().unwrap_or_else(|e| e.into_inner());
				r.check_known(known.0, &known.1).and_then(|_| r.admit(&owner.serialize(), &salt, kind, &message.digest))
			};
			let entry = match admitted {
				Ok(e) => e,
				Err(e) => {
					eprintln!("arca-signer: refused rebind {} for the leaf of {} under salt {}: {}", hex(&message.digest),
						hex(&owner.serialize()), hex(&salt), e);
					return Response { code: code_of(&e), error: Some(e), ..none };
				},
			};
			// The entry is on disk; with keepers, it is answered only once
			// the required number hold a head at or after it.
			let (head, acks) = match &state.keepers {
				Some(_) => match state.held_outside(entry.n).await {
					Ok((h, a)) => (h, Some(a)),
					Err(e) => {
						eprintln!("arca-signer: rebind {} recorded as entry {}, not answered: {}", hex(&message.digest), entry.n, e);
						return Response { code: code_of(&e), error: Some(e), ..none };
					},
				},
				None => (signed_head(key, &genesis, entry.n, &entry.hash), None),
			};
			let mut aux = [0u8; 32];
			rand::rngs::OsRng.fill_bytes(&mut aux);
			let sig = sign_digest(key, &message.digest, &aux);
			eprintln!("arca-signer: signed rebind {} ({}) for the leaf of {} under salt {}: entry {}", hex(&message.digest),
				match kind { Signed::Spend => "spend", Signed::Forfeit(_) => "forfeit" }, hex(&owner.serialize()), hex(&salt), entry.n);
			Response { signature: Some(hex(sig.as_ref())), entry: Some(head), acks, ..none }
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
	let operator = key.x_only_public_key().0;
	if args.create_record {
		match SpendRecord::create(&args.record, &operator, &args.genesis) {
			Ok(()) => {
				eprintln!("arca-signer: created the record {} for S = {} on {}", args.record.display(), hex(&operator.serialize()),
					args.genesis);
				std::process::exit(0);
			},
			Err(e) => {
				eprintln!("arca-signer: the record: {}", e);
				std::process::exit(2);
			},
		}
	}
	if args.clear_stopped {
		match SpendRecord::clear_stopped(&args.record) {
			Ok(Some(text)) => {
				eprintln!("arca-signer: removed the proof of a rollback kept beside {}; it said:\n{}", args.record.display(), text.trim_end());
				std::process::exit(0);
			},
			Ok(None) => {
				eprintln!("arca-signer: there is no proof of a rollback beside {}", args.record.display());
				std::process::exit(0);
			},
			Err(e) => {
				eprintln!("arca-signer: {}", e);
				std::process::exit(2);
			},
		}
	}
	if let Some((into, drop_file)) = &args.compact {
		let drop = match std::fs::read_to_string(drop_file).map_err(|e| format!("{}: {}", drop_file.display(), e)).and_then(|text| {
			text.lines().map(str::trim).filter(|l| !l.is_empty()).map(unhex32).collect::<Result<std::collections::HashSet<_>, _>>()
				.map_err(|e| format!("{}: {}", drop_file.display(), e))
		}) {
			Ok(d) => d,
			Err(e) => {
				eprintln!("arca-signer: {}", e);
				std::process::exit(2);
			},
		};
		match SpendRecord::compact(&args.record, into, &operator, &args.genesis, &drop) {
			Ok((carried, dropped, (n, hash))) => {
				eprintln!("arca-signer: compacted {} into {}: {} entries carried over, {} dropped; it goes on from entry {} ({})",
					args.record.display(), into.display(), carried, dropped, n, hex(&hash));
				std::process::exit(0);
			},
			Err(e) => {
				eprintln!("arca-signer: compacting the record: {}", e);
				std::process::exit(2);
			},
		}
	}
	let record = match SpendRecord::open(&args.record, &operator, &args.genesis) {
		Ok((r, repaired)) => {
			if let Some(note) = repaired {
				eprintln!("arca-signer: {}", note);
			}
			Mutex::new(r)
		},
		Err(e) => {
			eprintln!("arca-signer: the record: {}", e);
			std::process::exit(2);
		},
	};
	let keepers = (!args.keepers.is_empty()).then(|| Keepers {
		required: args.keepers_required.unwrap_or(args.keepers.len()),
		list: args.keepers.iter().map(|k| KeeperClient::new(k.clone(), args.keeper_timeout)).collect(),
		checked: tokio::sync::Mutex::new(false),
		acked: tokio::sync::Mutex::new(None),
	});
	let state = Arc::new(State { key, chain: Chain::new(args.genesis), genesis: args.genesis, record, keepers });
	match &state.keepers {
		// At start, before anything is served: the keepers' latest heads
		// against the record. One the record does not hold stops the signer
		// now; with too few answers, it serves, and signs nothing the record
		// governs until enough answer.
		Some(k) => {
			eprintln!("arca-signer: {} keeper(s), {} of them to hold every head: {}", k.list.len(), k.required,
				k.list.iter().map(|c| format!("{} ({})", c.addr.addr, hex(&c.addr.key.serialize()))).collect::<Vec<_>>().join(", "));
			if let Err(e) = state.check_keepers().await {
				eprintln!("arca-signer: at start: {}", e);
			}
		},
		None => eprintln!("arca-signer: no keeper: the record rests on this machine alone, and a restore of the machine can let a coin \
			paid out of round be spent twice"),
	}
	let socket = args.socket.clone().expect("a socket when serving");
	let _ = std::fs::remove_file(&socket);
	let listener = match UnixListener::bind(&socket) {
		Ok(l) => l,
		Err(e) => {
			eprintln!("arca-signer: {}: {}", socket.display(), e);
			std::process::exit(2);
		},
	};
	if let Err(e) = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)) {
		eprintln!("arca-signer: {}: {}", socket.display(), e);
		std::process::exit(2);
	}
	{
		let r = state.record.lock().unwrap_or_else(|e| e.into_inner());
		eprintln!("arca-signer: S = {} on {}; {} message(s) in the record {}, its latest entry {}", hex(&operator.serialize()),
			socket.display(), r.len(), args.record.display(), r.head().0);
		if let Some(why) = r.stopped() {
			eprintln!("arca-signer: STOPPED: {}", why);
		}
	}
	loop {
		let (stream, _) = match listener.accept().await {
			Ok(s) => s,
			Err(e) => {
				eprintln!("arca-signer: accept: {}", e);
				continue;
			},
		};
		let state = state.clone();
		tokio::spawn(async move {
			let (read, mut write) = stream.into_split();
			let mut reader = BufReader::new(read).take(MAX_REQUEST as u64 + 1);
			let mut line = String::new();
			let reply = match reader.read_line(&mut line).await {
				Ok(n) if n > MAX_REQUEST => Response { error: Some("request too long".into()), ..Response::default() },
				Ok(_) => answer(&state, line.trim_end()).await,
				Err(e) => Response { error: Some(e.to_string()), ..Response::default() },
			};
			let mut out = serde_json::to_string(&reply).unwrap_or_else(|_| "{\"error\":\"internal\"}".into());
			out.push('\n');
			let _ = write.write_all(out.as_bytes()).await;
		});
	}
}
