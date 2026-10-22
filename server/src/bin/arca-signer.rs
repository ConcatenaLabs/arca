//! `arca-signer`: holds the operator key `S` and signs the rebindable messages
//! of collaborative paths, the spends of the operator's own paths and the
//! operator's unroll and accumulator exit authorisations, each built by the signer itself, and
//! nothing else, for the server on a Unix socket. See `server::signer` for
//! the protocol.
//!
//!     arca-signer --key-file <file> --pubkey
//!     arca-signer --key-file <file> --genesis <hash> --sign-operator-record <record.json>
//!     arca-signer --key-file <file> --genesis <hash> --socket <path> --record <file> \
//!         [--keeper <host:port>=<key> …] [--keeper-timeout-ms <ms>] [--start-keepers-seen] \
//!         [--issuer <instance file>=<mnemonic file> …] [--mint-limiter <path>] \
//!         [--supervision-node <url> --supervision-cookie <file>] \
//!         [--restricted <asset>=<policy key>[:<clawback key>] …]
//!     arca-signer --key-file <file> --genesis <hash> --record <file> --create-record \
//!         (--keeper-key <key> … --keepers-required <k> | --no-keepers)
//!     arca-signer --key-file <file> --genesis <hash> --record <file> --compact-into <new file> --drop-salts <file>
//!     arca-signer --key-file <file> --genesis <hash> --record <file> --clear-stopped
//!
//! With `--issuer`, the signer mints an issuer-operated asset through its mint
//! limiter: the instance file the limiter's tool wrote, and the mnemonic file
//! of the limiter's operator key, which only the tool reads (`--mint-limiter`
//! names it, `mint-limiter` on the `PATH` by default). It checks a round's
//! mint itself before the tool signs it (`server::issuer::check_reissue`),
//! and signs no spend that pays a unit of such an asset anywhere but a burn.
//!
//! With `--supervision-node`, the signer reads freezes of supervised assets
//! from that node itself (`isassetfrozen`, over JSON-RPC, authenticated by
//! the cookie file or a file holding `user:password`), independently of the
//! server: it signs a rebindable message for a `landing-1` coin, the leaf of
//! a supervised asset, only while its node shows the coin's landing free and
//! the asset not paused, and builds the message with that landing after `K`,
//! as the coin's script does, so a request naming another landing gets a
//! signature that spends nothing (`server::supervision`). Without one it signs no message
//! for a `landing-1` coin at all.
//!
//! With `--restricted`, the signer serves a restricted asset (an OpenAMP
//! asset) held in `enclave-1` leaves, whose policy server co-signs beside the
//! operator (`server::restricted`): it signs a rebindable message of that
//! asset only beside the policy key's signature over that very message
//! (`arca_covenant::enclave::policy_cosign_digest`), and for an `enclave-1`
//! coin it builds the message with the digest of the holder's enclave after
//! `K`, from the holder the request names and the asset's keys given here, as
//! the coin's script does. So no database and no server gets `S`'s signature
//! for a move of the asset the policy server did not approve, and a request
//! naming another holder gets a signature that spends nothing. It signs no
//! forfeit of such an asset, and no `enclave-1` message of any other asset.
//!
//! The key file holds the 32-byte secret key as 64 hex characters, and must
//! not be readable by anyone but its owner. `--pubkey` prints the operator
//! key `S` it holds, and exits: a new operator's keepers are made with it
//! (`arca-keeper --operator <S> … --create`) before its record exists.
//! `--sign-operator-record` signs the operator's record for the Sequentia
//! registry (`arca_covenant::operator_record`) and prints
//! `{"record", "signature"}`, the body the registry takes, and exits: it
//! signs only a record that names this key and the chain of `--genesis`,
//! under the record's own tag, which nothing else the key signs uses. It
//! reads the key file and the record and nothing else, so it runs beside a
//! signer that is serving. The genesis hash is in display
//! order, as `getblockhash 0` prints it. The socket is created with mode 0600.
//! The record is the signer's append-only record of every rebindable message
//! it signed (`server::signer::SpendRecord`): it is what makes the signer the
//! one-spend authority, so it is kept on durable storage and never rolled
//! back, whatever is done to the server's database. The signer starts only on
//! its record and locks it while it runs. `--create-record` makes a new,
//! empty record for this key and chain, once, and exits: a record is never
//! made in passing, so one that is lost is never silently replaced.
//!
//! The record names its keepers in its first line, fixed when it is made:
//! `--create-record` takes each keeper's key (`--keeper-key`, as
//! `arca-keeper --pubkey` prints it) and how many of them must hold every
//! head (`--keepers-required`), or `--no-keepers` for an operator without
//! keepers, for its own coins. From then on the signer serves only with
//! that set: `--keeper <host:port>=<key>` says only where each of the
//! record's keepers is reached, one for every key the record names and for
//! no other, and the signer refuses to start otherwise, saying which key has
//! no address or which is not the record's. A record made without keepers
//! (and every record of format 1 to 3) refuses `--keeper`: it never gains
//! any. A changed set is a new operator, with a new key and a new record.
//!
//! `--compact-into` writes a compacted copy of the record to a new file and
//! exits (`server::signer::SpendRecord::compact`): every entry under a salt
//! listed in the `--drop-salts` file (one hex salt a line, as
//! `arcad <config> expired-salts` prints them) is dropped, every other entry
//! carried over, and the new record goes on from the old one's latest entry.
//! It locks the record, so it runs with the signer stopped; the operator then
//! puts the new file in the record's place and starts the signer on it. The
//! new record keeps the running hash of every entry it drops, and its salt:
//! the signer refuses any message under a kept salt, as it refuses a second
//! under any other. A record an older signer compacted kept no salt; the
//! signer says so at start, and compacted again it keeps every salt listed.
//!
//! Every head of the record the signer hands out is signed with `S`, and so
//! is every running hash a witness is answered with, and the record's end
//! together with the nonce the witness carried. A head's signature never
//! changes, so the signer keeps each one it made or checked, by entry and
//! running hash, and hands that one out again; a witness copies what it
//! needs from the record under the record's lock and signs after releasing
//! it, so witnesses never hold up a co-signature for longer than the
//! lookups take. A head it signed that its
//! record does not hold, handed back by a wallet, proves the record was
//! rolled back or replaced: the signer writes the proof to
//! `<record>.stopped` and signs no rebindable message and no head from then
//! on, across restarts (`server::signer::SpendRecord::witness`), and answers
//! every witness with that proof. Only `--clear-stopped`, run with the
//! signer stopped, removes that file, after printing it.
//!
//! With keepers (on other machines: `server::keeper`), the signer answers an
//! entry of its record only once its signed head is held outside this
//! machine: after it has written and synced an entry and signed its head, it
//! hands the record's latest head to every keeper and releases the
//! co-signature only when as many of them as the record requires have
//! acknowledged it, each acknowledgement naming the latest head the keeper
//! held when asked, which the record must hold with the same hash (a latest
//! it does not hold stops the signer, so a signer restored with its memory
//! cannot pass a keeper's latest with a head past it); otherwise it answers
//! that it cannot sign now (`keepers_unavailable`), the entry stays, and the
//! same request again completes. At start, and before the first signature after a start, it asks
//! the keepers for the latest head each holds: one past the record's end, or
//! with another hash at an entry the record holds, is proof the record was
//! rolled back, and stops the signer; and until enough keepers have answered
//! (enough that any set of as many as the record requires includes one) it
//! signs nothing the record governs. Once a head of the record has been
//! acknowledged by as many keepers as it requires, which the signer notes
//! beside the record (`server::signer::acknowledged_path`), a keeper that
//! holds no head has lost its heads file and is no answer. A keeper seen to
//! go back, naming no head or a latest below one it held, is a lost keeper:
//! the signer counts it no more, and says so. What it saw each keeper hold,
//! lost keepers included, it writes beside the record
//! (`server::signer::keepers_seen_path`) before it releases anything that
//! taught it more, and reads at every start, so a restart changes nothing of
//! it; it releases nothing it cannot note there, nor before it has noted the
//! first acknowledged head. So a record with `<record>.acknowledged` beside
//! it has `<record>.keepers-seen` too, and the signer refuses to start on
//! one that has the first and not the second, naming both: the file was
//! lost, or left beside another name. A record whose signer kept no
//! `<record>.keepers-seen` (one made before the signer kept it) is started
//! once with `--start-keepers-seen`, which writes that file, nothing seen of
//! any keeper yet, and is refused for a record that has the file or no
//! `<record>.acknowledged`. Every head it
//! hands out carries the acknowledgements it has of it, and `pubkey` names
//! the record's keepers.

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
use server::keeper::{reached, start_quorum, Held, KeeperAddr, KeeperClient, WireAck, KEEPERS_UNAVAILABLE};
use server::signer::{
	check_spend, hex, parse_amount, record_end_digest, record_head_digest, unhex, unhex32, RecordKeepers, Request, Response, Signed,
	SpendRecord, WireChannel, WireState,
	WireEntryRef, WireKeepers, WireStopProof, ALREADY_SIGNED, MAX_ENTRIES, MAX_REQUEST, MAX_WITNESS, RECORD_BEHIND, RECORD_DIFFERS,
	STOPPED,
};

struct Args {
	key_file: PathBuf,
	/// `--pubkey`: print `S` and exit; nothing else is read.
	pubkey: bool,
	/// `--sign-operator-record`: sign the operator record in this file and
	/// exit; nothing else is read.
	sign_record: Option<PathBuf>,
	genesis: BlockHash,
	/// `None` with `--create-record`, which serves nothing.
	socket: Option<PathBuf>,
	record: PathBuf,
	/// `--compact-into` and `--drop-salts`.
	compact: Option<(PathBuf, PathBuf)>,
	clear_stopped: bool,
	/// Where each of the record's keepers is reached.
	keepers: Vec<KeeperAddr>,
	/// With `--create-record`: the keepers the new record names.
	record_keepers: Option<RecordKeepers>,
	keeper_timeout: std::time::Duration,
	/// `--start-keepers-seen`: write `<record>.keepers-seen` at this start,
	/// for a record whose signer kept none.
	start_keepers_seen: bool,
	/// `--issuer <instance>=<mnemonic>`: each issuer-operated asset's mint
	/// limiter, and the mnemonic of its operator key.
	issuers: Vec<(PathBuf, PathBuf)>,
	/// `--mint-limiter <path>`: the limiter's tool, which signs a mint.
	mint_tool: PathBuf,
	/// `--supervision-node <url>` and `--supervision-cookie <file>`: the node
	/// the signer reads freezes from.
	supervision: Option<(String, PathBuf)>,
	/// `--restricted <asset>=<policy key>[:<clawback key>]`: each restricted
	/// asset's policy key, and its issuer's clawback key where it elected one.
	restricted: Vec<(elements::AssetId, XOnlyPublicKey, Option<XOnlyPublicKey>)>,
}

/// Reads `--restricted`'s value: `<asset>=<policy key>[:<clawback key>]`,
/// the keys x-only, in hex.
fn restricted_arg(v: &str) -> Result<(elements::AssetId, XOnlyPublicKey, Option<XOnlyPublicKey>), String> {
	let (a, keys) = v.split_once('=').ok_or("--restricted <asset>=<policy key>[:<clawback key>]")?;
	let asset = elements::AssetId::from_str(a).map_err(|e| format!("--restricted: the asset: {}", e))?;
	let key = |k: &str| XOnlyPublicKey::from_slice(&unhex(k)?).map_err(|e| format!("--restricted: a key: {}", e));
	let (policy, clawback) = match keys.split_once(':') {
		Some((p, c)) => (key(p)?, Some(key(c)?)),
		None => (key(keys)?, None),
	};
	Ok((asset, policy, clawback))
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
	let mut keeper_keys: Vec<XOnlyPublicKey> = vec![];
	let mut no_keepers = false;
	let mut keepers_required = None;
	let mut keeper_timeout = std::time::Duration::from_secs(5);
	let mut pubkey = false;
	let mut start_keepers_seen = false;
	let mut restricted = vec![];
	let mut sign_record = None;
	let mut issuers: Vec<(PathBuf, PathBuf)> = vec![];
	let mut mint_tool = PathBuf::from("mint-limiter");
	let mut supervision_node = None;
	let mut supervision_cookie = None;
	let mut it = std::env::args().skip(1);
	while let Some(a) = it.next() {
		let mut value = || it.next().ok_or_else(|| format!("{} needs a value", a));
		match a.as_str() {
			"--key-file" => key_file = Some(PathBuf::from(value()?)),
			"--pubkey" => pubkey = true,
			"--sign-operator-record" => sign_record = Some(PathBuf::from(value()?)),
			"--genesis" => genesis = Some(BlockHash::from_str(&value()?).map_err(|e| format!("--genesis: {}", e))?),
			"--socket" => socket = Some(PathBuf::from(value()?)),
			"--record" => record = Some(PathBuf::from(value()?)),
			"--create-record" => create_record = true,
			"--compact-into" => compact_into = Some(PathBuf::from(value()?)),
			"--drop-salts" => drop_salts = Some(PathBuf::from(value()?)),
			"--clear-stopped" => clear_stopped = true,
			"--keeper" => keepers.push(value()?.parse().map_err(|e| format!("--keeper: {}", e))?),
			"--keeper-key" => keeper_keys.push(XOnlyPublicKey::from_slice(&unhex(&value()?).map_err(|e| format!("--keeper-key: {}", e))?)
				.map_err(|e| format!("--keeper-key: {}", e))?),
			"--no-keepers" => no_keepers = true,
			"--start-keepers-seen" => start_keepers_seen = true,
			"--keepers-required" => keepers_required = Some(value()?.parse::<usize>().map_err(|e| format!("--keepers-required: {}", e))?),
			"--keeper-timeout-ms" => keeper_timeout = std::time::Duration::from_millis(value()?.parse::<u64>()
				.map_err(|e| format!("--keeper-timeout-ms: {}", e))?),
			"--issuer" => {
				let v = value()?;
				let (i, m) = v.split_once('=').ok_or("--issuer <instance file>=<mnemonic file>")?;
				issuers.push((PathBuf::from(i), PathBuf::from(m)));
			},
			"--mint-limiter" => mint_tool = PathBuf::from(value()?),
			"--supervision-node" => supervision_node = Some(value()?),
			"--supervision-cookie" => supervision_cookie = Some(PathBuf::from(value()?)),
			"--restricted" => restricted.push(restricted_arg(&value()?)?),
			other => return Err(format!("unknown argument {}", other)),
		}
	}
	if let Some(file) = sign_record {
		if pubkey || socket.is_some() || record.is_some() || create_record || clear_stopped || compact_into.is_some() || drop_salts.is_some()
			|| !keepers.is_empty() || !keeper_keys.is_empty() || no_keepers || keepers_required.is_some() || start_keepers_seen
		{
			return Err("--sign-operator-record takes --key-file and --genesis alone: it signs the record and exits".into());
		}
		return Ok(Args {
			key_file: key_file.ok_or("--key-file is required")?, pubkey: false, sign_record: Some(file),
			genesis: genesis.ok_or("--genesis is required: the record is signed only for the chain it names")?, socket: None,
			record: PathBuf::new(), compact: None, clear_stopped: false, keepers: vec![], record_keepers: None, keeper_timeout,
			start_keepers_seen: false, issuers: vec![], mint_tool, supervision: None, restricted: vec![],
		});
	}
	if pubkey {
		if genesis.is_some() || socket.is_some() || record.is_some() || create_record || clear_stopped || compact_into.is_some()
			|| drop_salts.is_some() || !keepers.is_empty() || !keeper_keys.is_empty() || no_keepers || keepers_required.is_some()
		{
			return Err("--pubkey takes --key-file alone: it prints the operator key S and exits".into());
		}
		return Ok(Args {
			key_file: key_file.ok_or("--key-file is required")?, pubkey, sign_record: None, genesis: <BlockHash as elements::hashes::Hash>::all_zeros(), socket: None,
			record: PathBuf::new(), compact: None, clear_stopped: false, keepers: vec![], record_keepers: None, keeper_timeout,
			start_keepers_seen: false, issuers: vec![], mint_tool, supervision: None, restricted: vec![],
		});
	}
	let compact = match (compact_into, drop_salts) {
		(Some(i), Some(d)) => Some((i, d)),
		(None, None) => None,
		_ => return Err("--compact-into and --drop-salts go together".into()),
	};
	if !create_record && !clear_stopped && compact.is_none() && socket.is_none() {
		return Err("--socket is required".into());
	}
	if start_keepers_seen && socket.is_none() {
		return Err("--start-keepers-seen goes with a start that serves (--socket): it writes <record>.keepers-seen at that start".into());
	}
	// The keepers are the record's, named once, when it is made; a start
	// says only where each is reached.
	let record_keepers = if create_record {
		if !keepers.is_empty() {
			return Err("--create-record takes each keeper's key (--keeper-key <key>); where a keeper is reached is given when the \
				signer starts (--keeper <host:port>=<key>)".into());
		}
		match (keeper_keys.is_empty(), no_keepers, keepers_required) {
			(true, true, None) => Some(RecordKeepers::default()),
			(false, false, Some(k)) => Some(RecordKeepers::new(keeper_keys, k).map_err(|e| format!("the record's keepers: {}", e))?),
			(false, false, None) => return Err("--keeper-key needs --keepers-required <k>: how many of the keepers must hold every head \
				(fewer than all, such as two of three, so that one keeper lost does not end the operator)".into()),
			(_, true, _) => return Err("--no-keepers names no keeper and no number required".into()),
			(true, false, _) => return Err("--create-record needs the record's keepers, fixed for its whole life: --keeper-key <key> \
				for each (as arca-keeper --pubkey prints it) and --keepers-required <k>, or --no-keepers for an operator without \
				keepers, for its own coins".into()),
		}
	} else {
		if !keeper_keys.is_empty() || no_keepers {
			return Err("--keeper-key and --no-keepers go with --create-record: the record names its keepers when it is made".into());
		}
		if keepers_required.is_some() {
			return Err("--keepers-required is the record's, named when it is made (--create-record), and read from its first line".into());
		}
		None
	};
	if keepers.iter().enumerate().any(|(i, k)| keepers[..i].iter().any(|o| o.key == k.key)) {
		return Err("--keeper: two keepers with one key".into());
	}
	Ok(Args {
		key_file: key_file.ok_or("--key-file is required")?,
		pubkey: false,
		sign_record: None,
		genesis: genesis.ok_or("--genesis is required")?,
		socket,
		record: record.ok_or("--record is required: the signer keeps a record of every spend it co-signs")?,
		compact,
		clear_stopped,
		keepers,
		record_keepers,
		keeper_timeout,
		start_keepers_seen,
		issuers,
		mint_tool,
		supervision: match (supervision_node, supervision_cookie) {
			(Some(n), Some(c)) => Some((n, c)),
			(None, None) => None,
			_ => return Err("--supervision-node and --supervision-cookie go together".into()),
		},
		restricted,
	})
}

/// The witness of the limiter's coin at input 0 of a checked mint, from the
/// limiter's own tool (`mint-limiter sign`), which signs the program's
/// signature hash over the whole transaction with the mnemonic's key and
/// satisfies the program; the transaction it gives back must be the one
/// checked, its input 0's witness aside.
async fn mint_witness(state: &State, i: &Issuer, req: &server::issuer::WireReissue, checked: &server::issuer::CheckedReissue)
	-> Result<Vec<Vec<u8>>, String>
{
	use tokio::process::Command;
	let body = serde_json::json!({
		"tx": req.tx, "prevouts": req.prevouts, "entropy": req.entropy,
		"state": {"minted": req.state.minted, "elapsed": req.state.elapsed, "armed": req.state.armed as u8},
	});
	let mut child = Command::new(&state.mint_tool)
		.args(["sign", "--instance"]).arg(&i.instance).arg("--mnemonic-file").arg(&i.mnemonic)
		.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
		.kill_on_drop(true)
		.spawn().map_err(|e| format!("the limiter's tool {}: {}", state.mint_tool.display(), e))?;
	let mut stdin = child.stdin.take().ok_or("the tool's input")?;
	stdin.write_all(body.to_string().as_bytes()).await.map_err(|e| e.to_string())?;
	drop(stdin);
	let out = tokio::time::timeout(std::time::Duration::from_secs(120), child.wait_with_output()).await
		.map_err(|_| "the limiter's tool did not answer in two minutes".to_string())?.map_err(|e| e.to_string())?;
	if !out.status.success() {
		return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
	}
	let v: serde_json::Value = serde_json::from_slice(&out.stdout).map_err(|e| format!("the tool's answer: {}", e))?;
	let signed: elements::Transaction = elements::encode::deserialize(&unhex(v["hex"].as_str().unwrap_or(""))?)
		.map_err(|e| format!("the tool's transaction: {}", e))?;
	let mut bare = signed.clone();
	bare.input[0].witness = checked.tx.input[0].witness.clone();
	if elements::encode::serialize(&bare) != elements::encode::serialize(&checked.tx) {
		return Err("the limiter's tool gave back another transaction than the one checked".into());
	}
	if v["next_state"]["minted"].as_str() != Some(&checked.next.minted.to_string())
		|| v["next_state"]["elapsed"].as_u64() != Some(checked.next.elapsed as u64)
	{
		return Err(format!("the limiter's tool computes the next state {}, the signer {:?}", v["next_state"], checked.next));
	}
	Ok(signed.input[0].witness.script_witness.clone())
}

/// Stops the signer at start, saying why.
fn fail(m: &str) -> ! {
	eprintln!("arca-signer: {}", m);
	std::process::exit(2)
}

/// An issuer-operated asset's mint limiter, as the signer mints through it:
/// the instance, its file and the mnemonic file of its operator key, which
/// only the limiter's tool reads.
struct Issuer {
	limiter: arca_covenant::LimiterParams,
	instance: PathBuf,
	mnemonic: PathBuf,
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
	/// What each keeper was seen to hold, in the list's order: read from
	/// beside the record at start (`<record>.keepers-seen`), and written there
	/// again before anything that taught the signer more is released.
	seen: Mutex<Vec<Seen>>,
	/// What was last written beside the record of `seen`.
	saved: Mutex<Vec<Seen>>,
	/// Whether a head of the record has been acknowledged by as many keepers
	/// as it requires (`<record>.acknowledged`): from then on a keeper that
	/// holds no head has lost its heads file, and is no answer.
	acknowledged: std::sync::atomic::AtomicBool,
	record: PathBuf,
}

/// What one keeper was seen to hold: the highest entry it named or
/// acknowledged, and why it is a lost keeper, once it is one.
type Seen = server::signer::KeeperSeen;

impl Keepers {
	/// Takes `latest`, the entry keeper `i` names as the latest it holds (in
	/// an answer for its latest, or with an acknowledgement), and says why it
	/// is no answer when it is a lost keeper: its heads file no longer holds
	/// what it held. A keeper that holds no head once a head of the record has
	/// been acknowledged, or less than it was seen to hold, before a restart
	/// of the signer as well as after, is one, and stays one, across restarts
	/// ([`Self::save`]). Its contradictions still stop the signer; its
	/// answers count for nothing.
	fn note(&self, i: usize, latest: Option<u64>) -> Option<String> {
		let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
		let s = &mut seen[i];
		if let Some(why) = &s.lost {
			return Some(why.clone());
		}
		let addr = &self.list[i].addr.addr;
		let why = match (latest, s.held) {
			(None, Some(was)) => Some(format!("{} holds no head, where it held entry {}", addr, was)),
			(None, None) if self.acknowledged.load(std::sync::atomic::Ordering::SeqCst) => Some(format!("{} holds no head, though a \
				head of the record has been acknowledged by as many keepers as it requires", addr)),
			(Some(n), Some(was)) if n < was => Some(format!("{} holds entry {}, below entry {} it held", addr, n, was)),
			_ => None,
		};
		match why {
			Some(w) => {
				let why = format!("{}: a lost keeper, whose heads file was lost or restored from an older copy, so it no longer holds \
					what it acknowledged; the signer counts it no more (noted beside its record), and it is never started again under its key", w);
				eprintln!("arca-signer: {}", why);
				s.lost = Some(why.clone());
				Some(why)
			},
			None => {
				s.held = s.held.max(latest);
				None
			},
		}
	}

	/// Notes that keeper `i` acknowledged `entry`.
	fn holds(&self, i: usize, entry: u64) {
		let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
		seen[i].held = seen[i].held.max(Some(entry));
	}

	/// What each keeper was seen to hold, from beside the record at `record`
	/// (`<record>.keepers-seen`), for the keepers `list` in order: nothing
	/// seen of a keeper the file does not name.
	fn read_seen(record: &std::path::Path, list: &[KeeperAddr]) -> Result<Vec<Seen>, String> {
		let kept = server::signer::read_keepers_seen(record)?;
		Ok(list.iter().map(|k| kept.get(&k.key.serialize()).cloned().unwrap_or_default()).collect())
	}

	/// Writes what each keeper was seen to hold beside the record, when it
	/// changed since it was last written: synced before anything that taught
	/// the signer more is released, which nothing is when it cannot be.
	fn save(&self) -> Result<(), String> {
		let now = self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
		let mut saved = self.saved.lock().unwrap_or_else(|e| e.into_inner());
		if *saved == now {
			return Ok(());
		}
		let by_key: Vec<([u8; 32], Seen)> = self.list.iter().zip(&now).map(|(c, s)| (c.addr.key.serialize(), s.clone())).collect();
		server::signer::write_keepers_seen(&self.record, &by_key)?;
		*saved = now;
		Ok(())
	}
}

/// What every request is answered from.
struct State {
	key: Keypair,
	chain: Chain,
	genesis: BlockHash,
	record: Mutex<SpendRecord>,
	keepers: Option<Keepers>,
	/// `S`'s signature over each head, by entry and running hash, that the
	/// signer made or checked: handed out again rather than made again, and
	/// a head handed back with it needs no check. At most [`MAX_KEPT_SIGS`].
	sigs: Mutex<std::collections::HashMap<(u64, [u8; 32]), [u8; 64]>>,
	/// The issuer-operated assets whose mints this signer signs.
	issuers: Vec<Issuer>,
	mint_tool: PathBuf,
	/// The node the signer reads freezes of supervised assets from.
	supervision: Option<sequentia_ext::rpc::Client>,
	/// Each restricted asset's policy key and clawback key.
	restricted: std::collections::HashMap<elements::AssetId, (XOnlyPublicKey, Option<XOnlyPublicKey>)>,
}

/// Whether `landing`, a `landing-1` coin's landing program, is free for
/// `asset` as the signer's own node shows it: `Err` naming why not. Without a
/// node, nothing that names a landing is signed.
async fn landing_free(state: &State, asset: elements::AssetId, landing: [u8; 20]) -> Result<(), String> {
	let client = state.supervision.clone().ok_or_else(|| format!("{}: this signer reads freezes from no node (--supervision-node), so it \
		signs no spend of a landing-1 coin, the leaf of a supervised asset", server::supervision::FROZEN))?;
	let script = format!("0014{}", hex(&landing));
	let answer = tokio::task::spawn_blocking(move || {
		client.call::<serde_json::Value>("isassetfrozen", &[serde_json::json!(asset.to_string()), serde_json::json!(script)])
	}).await.map_err(|e| format!("{}: the node call did not finish: {}", server::supervision::FROZEN, e))?;
	let v = answer.map_err(|e| format!("{}: the signer's node did not say whether landing {} is frozen for asset {}: {}",
		server::supervision::FROZEN, hex(&landing), asset, e))?;
	match (v["frozen"].as_bool(), v["paused"].as_bool()) {
		(Some(false), Some(false)) | (Some(false), None) => Ok(()),
		(_, Some(true)) => Err(format!("{}: asset {} is paused, as the signer's node shows it: no landing-1 coin of it is spent \
			off the chain", server::supervision::FROZEN, asset)),
		_ => Err(format!("{}: landing {} is frozen for asset {}, as the signer's node shows it: the coin is spent only by its \
			landing", server::supervision::FROZEN, hex(&landing), asset)),
	}
}

/// How many heads' signatures the signer keeps at hand: about 15 MB. Past
/// that it forgets them all and makes or checks each again as it is asked.
const MAX_KEPT_SIGS: usize = 100_000;

impl State {
	fn operator(&self) -> XOnlyPublicKey {
		self.key.x_only_public_key().0
	}

	fn keep_sig(&self, n: u64, hash: &[u8; 32], sig: [u8; 64]) {
		let mut k = self.sigs.lock().unwrap_or_else(|e| e.into_inner());
		if k.len() >= MAX_KEPT_SIGS {
			k.clear();
		}
		k.insert((n, *hash), sig);
	}

	/// `S`'s signature over entry `n` of the record, whose running hash is
	/// `hash`: the one kept, or a new one, kept. How every head the signer
	/// hands out is signed.
	fn signed_head(&self, n: u64, hash: &[u8; 32]) -> WireEntryRef {
		let kept = self.sigs.lock().unwrap_or_else(|e| e.into_inner()).get(&(n, *hash)).copied();
		let sig = match kept {
			Some(s) => s,
			None => {
				let mut aux = [0u8; 32];
				rand::rngs::OsRng.fill_bytes(&mut aux);
				let s: [u8; 64] = *sign_digest(&self.key, &record_head_digest(&self.genesis, n, hash), &aux).as_ref();
				self.keep_sig(n, hash, s);
				s
			},
		};
		WireEntryRef { entry: n, hash: hex(hash), signature: Some(hex(&sig)) }
	}

	/// The running hash `head` names when it carries `S`'s valid signature
	/// over it on this chain: the signature kept for that head needs no
	/// check, and another valid one is kept in its place.
	fn check_head(&self, head: &WireEntryRef) -> Option<[u8; 32]> {
		let hash = unhex32(&head.hash).ok()?;
		let sig: [u8; 64] = unhex(head.signature.as_deref()?).ok()?.try_into().ok()?;
		if self.sigs.lock().unwrap_or_else(|e| e.into_inner()).get(&(head.entry, hash)) == Some(&sig) {
			return Some(hash);
		}
		let parsed = Signature::from_slice(&sig).ok()?;
		if !verify_digest(&parsed, &record_head_digest(&self.genesis, head.entry, &hash), &self.operator()) {
			return None;
		}
		self.keep_sig(head.entry, &hash, sig);
		Some(hash)
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
		for (i, (c, a)) in k.list.iter().zip(answers).enumerate() {
			match a {
				Ok(head) => {
					if let Some(h) = &head {
						if let Some(why) = self.against_record(h)? {
							return Err(why);
						}
					}
					// A keeper that holds nothing, once a head has been
					// acknowledged, has lost its heads file: no answer.
					if let Some(why) = k.note(i, head.as_ref().map(|h| h.entry)) {
						notes.push(why);
						continue;
					}
					answered += 1;
					notes.push(match &head {
						Some(h) => format!("{} holds entry {}", c.addr.addr, h.entry),
						None => format!("{} holds no head", c.addr.addr),
					});
				},
				Err(e) => notes.push(e),
			}
		}
		// A lost keeper stays lost across restarts: noted beside the record
		// before anything is signed.
		let saved = k.save();
		let need = start_quorum(k.list.len(), k.required);
		if answered < need {
			return Err(format!("{}: {} of the {} keepers answered for the latest head each holds, and {} must before the signer signs \
				anything its record governs after a start, so that it sees the latest head any {} of them hold ({})", KEEPERS_UNAVAILABLE,
				answered, k.list.len(), need, k.required, notes.join("; ")));
		}
		if let Err(e) = saved {
			return Err(format!("{}: the signer cannot note beside its record what its keepers hold ({}), and signs nothing its record \
				governs until it can", KEEPERS_UNAVAILABLE, e));
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
	/// stops the signer on it; so does the latest head an acknowledgement
	/// says the keeper held when it was asked. A keeper takes a head past its
	/// latest on its number alone, so a signer restored with its memory, past
	/// its start check, whose first hand-overs a keeper missed, or which took
	/// several requests at once before the first hand-over, hands over a head
	/// past the keeper's latest: nothing is released until the record holds
	/// that latest, with that hash, and a latest it does not hold stops the
	/// signer, as at a start.
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
			r.head()
		};
		let head = self.signed_head(head.0, &head.1);
		let (genesis, operator) = (self.genesis, self.operator());
		let answers = futures_join(k.list.iter().map(|c| c.hold(&genesis, &operator, &head))).await;
		let mut acks = vec![];
		let mut notes = vec![];
		for (i, (c, a)) in k.list.iter().zip(answers).enumerate() {
			match a {
				Ok(Held::Ack(ack, latest)) => {
					if let Some(l) = &latest {
						if let Some(why) = self.against_record(l)? {
							return Err(why);
						}
					}
					// A lost keeper's acknowledgement counts for nothing, and
					// goes to nobody.
					if let Some(why) = k.note(i, latest.as_ref().map(|l| l.entry)) {
						notes.push(why);
						continue;
					}
					k.holds(i, head.entry);
					acks.push(ack);
				},
				Ok(Held::Contradicts(held)) => {
					if let Some(why) = self.against_record(&held)? {
						return Err(why);
					}
					notes.push(format!("{} refused entry {}, holding entry {}", c.addr.addr, head.entry, held.entry));
				},
				Err(e) => notes.push(e),
			}
		}
		// What the keepers were seen to hold, lost keepers included, goes
		// beside the record before anything it taught is released.
		let saved = k.save();
		if acks.len() < k.required {
			return Err(format!("{}: {} of the {} keepers acknowledged entry {}, and {} must before the signer answers it; the entry \
				stays, and the same request again completes once they do ({})", KEEPERS_UNAVAILABLE, acks.len(), k.list.len(), head.entry,
				k.required, notes.join("; ")));
		}
		let cannot = |what: &str, e: String| {
			eprintln!("arca-signer: noting beside the record {}: {}; nothing is released until it is noted", what, e);
			format!("{}: {} of the {} keepers acknowledged entry {}, but the signer cannot note beside its record {} ({}): it releases \
				nothing until it can; the entry stays, and the same request again completes once it can", KEEPERS_UNAVAILABLE, acks.len(),
				k.list.len(), head.entry, what, e)
		};
		if let Err(e) = saved {
			return Err(cannot("what its keepers hold", e));
		}
		// The first head the keepers acknowledged: from now on, one that holds
		// none has lost its heads file. Noted before it is released.
		if !k.acknowledged.load(std::sync::atomic::Ordering::SeqCst) {
			if let Err(e) = server::signer::mark_acknowledged(&k.record, head.entry, &unhex32(&head.hash)?) {
				return Err(cannot("that a head was acknowledged", e));
			}
			k.acknowledged.store(true, std::sync::atomic::Ordering::SeqCst);
		}
		*acked = Some((head.clone(), acks.clone()));
		Ok((head, acks))
	}
}

/// The rule at start between the two files the signer keeps beside its
/// record at `record`: a record noted acknowledged (`<record>.acknowledged`)
/// has what the signer saw its keepers hold (`<record>.keepers-seen`), or
/// the signer does not start. `start` (`--start-keepers-seen`) writes that
/// file for a record whose signer kept none, nothing seen of any of the
/// record's keepers (`named`, reached at `addrs`), once: it is refused where
/// the file is already there, or where no head was noted acknowledged, or
/// where the record names no keeper.
fn keepers_seen_at_start(record: &std::path::Path, named: &RecordKeepers, addrs: &[KeeperAddr], start: bool) -> Result<(), String> {
	let acknowledged = server::signer::acknowledged_path(record);
	let seen = server::signer::keepers_seen_path(record);
	match (acknowledged.exists(), seen.exists(), start) {
		(true, false, false) => Err(format!("{} says a head of the record was acknowledged by as many keepers as it requires, and {} \
			is missing: the signer writes what it saw each keeper hold there before it notes the first acknowledged head, so the file \
			was lost, or left beside another name (a compacted record's files go with it: <new file>.acknowledged and \
			<new file>.keepers-seen). Put the file back from where it lies; never start without it, which forgets every lost keeper and \
			every head a keeper was seen to hold. A record whose signer kept no such file (one made before the signer kept it) is started \
			once with --start-keepers-seen", acknowledged.display(), seen.display())),
		(_, _, false) => Ok(()),
		_ if named.is_none() => Err("--start-keepers-seen: the record names no keeper".into()),
		(_, true, true) => Err(format!("--start-keepers-seen writes {} for a record whose signer kept none, and it is there: it is \
			never written over", seen.display())),
		(false, false, true) => Err(format!("--start-keepers-seen writes {} for a record noted acknowledged ({}) whose signer kept \
			none, and {} is not there: this record starts without it", seen.display(), acknowledged.display(), acknowledged.display())),
		(true, false, true) => {
			let none: Vec<([u8; 32], Seen)> = addrs.iter().map(|k| (k.key.serialize(), Seen::default())).collect();
			server::signer::write_keepers_seen(record, &none)?;
			eprintln!("arca-signer: wrote {}, nothing seen of any of the record's {} keeper(s) yet, for a record whose signer kept none; \
				from now on it is kept, and --start-keepers-seen is refused", seen.display(), none.len());
			Ok(())
		},
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
	[ALREADY_SIGNED, RECORD_BEHIND, RECORD_DIFFERS, STOPPED, KEEPERS_UNAVAILABLE, server::supervision::FROZEN, server::restricted::POLICY,
		server::restricted::RESTRICTED].into_iter()
		.find(|c| e.starts_with(&format!("{}:", c))).map(str::to_string)
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
			Response { entry: Some(state.signed_head(n, &hash)), ..none }
		},
		Request::Witness { heads, nonce } => {
			if heads.len() > MAX_WITNESS {
				return Response { error: Some(format!("{} heads; a witness names at most {}", heads.len(), MAX_WITNESS)), ..none };
			}
			let nonce = match nonce.as_deref().map(unhex32).transpose() {
				Ok(n) => n,
				Err(e) => return Response { error: Some(format!("nonce: {}", e)), ..none },
			};
			// Every signature is checked before the record is locked, the
			// ones the signer made or checked before by a look-up alone.
			let signed: Vec<Option<[u8; 32]>> = heads.iter().map(|h| state.check_head(h)).collect();
			// Under the record's lock, only what the answer needs from it:
			// the running hashes, whether it is stopped, its end, and the
			// proof's parts. Everything is signed after the lock is
			// released, so a witness holds no co-signature up for longer.
			let (mut hashes, stopped, (n, hash), stop_parts) = {
				let mut r = record.lock().unwrap_or_else(|e| e.into_inner());
				let was = r.stopped().is_some();
				let hashes = match r.witness_checked(&heads, &signed) {
					Ok(h) => h,
					Err(e) => return Response { error: Some(e), ..none },
				};
				let stopped = r.stopped().map(str::to_string);
				if let (false, Some(why)) = (was, &stopped) {
					eprintln!("arca-signer: STOPPED: {}", why);
				}
				let parts = match (&stopped, r.stop_head()) {
					(Some(_), Some(p)) => match r.hash_of(p.entry) {
						Ok(Some(x)) if hex(&x) != p.hash => Some((p.clone(), Some(x))),
						Ok(_) => Some((p.clone(), None)),
						Err(e) => return Response { error: Some(format!("the record could not be read: {}", e)), ..none },
					},
					_ => None,
				};
				(hashes, stopped, r.head(), parts)
			};
			// Every running hash answered is signed as a head: another hash
			// at an entry a wallet holds is then two heads `S` signed at one
			// entry, which nobody without `S` can make.
			for h in &mut hashes {
				if let Some(x) = h.hash.as_deref().and_then(|x| unhex32(x).ok()) {
					h.signature = state.signed_head(h.entry, &x).signature;
				}
			}
			// The record's end with the asker's nonce: not an older head
			// replayed. A stopped signer signs it too, as part of its proof.
			let end = nonce.map(|nonce| {
				let mut aux = [0u8; 32];
				rand::rngs::OsRng.fill_bytes(&mut aux);
				let sig = sign_digest(key, &record_end_digest(&genesis, n, &hash, &nonce), &aux);
				WireEntryRef { entry: n, hash: hex(&hash), signature: Some(hex(sig.as_ref())) }
			});
			let proof = stop_parts.map(|(head, held)| {
				let held = held.map(|x| state.signed_head(head.entry, &x));
				WireStopProof { head, held }
			});
			// The latest head goes with the keepers' acknowledgements when
			// they acknowledged it last.
			let acks = match &state.keepers {
				Some(k) => k.acked.try_lock().ok().and_then(|a| a.as_ref().filter(|(h, _)| h.entry == n && h.hash == hex(&hash))
					.map(|(_, a)| a.clone())),
				None => None,
			};
			Response {
				entry: stopped.is_none().then(|| state.signed_head(n, &hash)),
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
		Request::Record {} => {
			let r = record.lock().unwrap_or_else(|e| e.into_inner());
			Response { record: Some(r.info()), ..none }
		},
		Request::Under { salt } => {
			let salt = match unhex32(&salt) {
				Ok(s) => s,
				Err(e) => return Response { error: Some(format!("salt: {}", e)), ..none },
			};
			let r = record.lock().unwrap_or_else(|e| e.into_inner());
			match r.entries_under(&salt) {
				Ok(list) => Response { entries: Some(list.iter().map(|e| e.to_wire()).collect()), ..none },
				Err(e) => Response { error: Some(format!("the record could not be read: {}", e)), ..none },
			}
		},
		Request::Rebind { owner, owner_sig, salt, asset_in, value_in, outputs, forfeit, known, landing, enclave, policy_sig } => {
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
				let landing = match &landing {
					Some(l) => Some(<[u8; 20]>::try_from(unhex(l)?.as_slice()).map_err(|_| "landing: 20 bytes".to_string())?),
					None => None,
				};
				let enclave = match &enclave {
					Some(h) => Some(XOnlyPublicKey::from_slice(&unhex(h)?).map_err(|e| format!("enclave: {}", e))?),
					None => None,
				};
				let policy_sig = match &policy_sig {
					Some(s) => Some(Signature::from_slice(&unhex(s)?).map_err(|e| format!("policy_sig: {}", e))?),
					None => None,
				};
				// A restricted asset's coin: the asset's keys, as given at
				// start; a coin of no restricted asset is never enclave-1.
				let restricted = state.restricted.get(&asset_in).copied();
				match (&restricted, &enclave, &landing, &forfeit) {
					(None, Some(_), _, _) => return Err(format!("{}: asset {} is not served restricted here: no enclave-1 coin of it is \
						co-signed", server::restricted::RESTRICTED, asset_in)),
					(_, Some(_), Some(_), _) => return Err("a coin is enclave-1 or landing-1, not both".into()),
					(Some(_), _, _, Some(_)) => return Err(format!("{}: asset {} is restricted: it is not refreshed in the tree, so no \
						forfeit of it is signed", server::restricted::RESTRICTED, asset_in)),
					_ => {},
				}
				let enclave = match (enclave, restricted) {
					(Some(holder), Some((policy, clawback))) => Some(arca_covenant::Enclave { holder, policy, clawback }),
					_ => None,
				};
				Ok((owner, owner_sig, salt, asset_in, value_in, outputs, kind, known, landing, enclave, restricted, policy_sig))
			})();
			let (owner, owner_sig, salt, asset_in, value_in, outputs, kind, known, landing, enclave, restricted, policy_sig) = match parsed {
				Ok(p) => p,
				Err(e) => return Response { error: Some(e), ..none },
			};
			// After a start, nothing the record governs is signed before
			// enough keepers have answered for their latest.
			if let Err(e) = state.check_keepers().await {
				eprintln!("arca-signer: refused rebind for the leaf of {} under salt {}: {}", hex(&owner.serialize()), hex(&salt), e);
				return Response { code: code_of(&e), error: Some(e), ..none };
			}
			// A landing-1 coin's freeze, read from the signer's own node,
			// before anything is recorded; its message carries its landing
			// program after `K`.
			if let Some(l) = landing {
				if let Err(e) = landing_free(state, asset_in, l).await {
					eprintln!("arca-signer: refused rebind for the leaf of {} under salt {}: {}", hex(&owner.serialize()), hex(&salt), e);
					return Response { code: code_of(&e), error: Some(e), ..none };
				}
			}
			let k = match (&landing, &enclave) {
				(Some(l), _) => chain.landing_prefix(&salt, l),
				(None, Some(e)) => chain.enclave_prefix(&salt, &e.digest()),
				(None, None) => chain.leaf_constant(&salt).to_vec(),
			};
			let message = match rebind_message(&k, asset_in, value_in, &outputs) {
				Ok(m) => m,
				Err(e) => return Response { error: Some(e.to_string()), ..none },
			};
			// A restricted asset's message is signed only beside its policy
			// key's approval of that very message.
			if let Some((policy, _)) = restricted {
				let approved = policy_sig.is_some_and(|s| verify_digest(&s,
					&arca_covenant::enclave::policy_cosign_digest(&message.digest), &policy));
				if !approved {
					let e = format!("{}: message {} of restricted asset {} carries no valid approval by its policy key {}: the signer \
						co-signs a move of the asset only beside its policy server's", server::restricted::POLICY, hex(&message.digest),
						asset_in, hex(&policy.serialize()));
					eprintln!("arca-signer: refused rebind for the leaf of {} under salt {}: {}", hex(&owner.serialize()), hex(&salt), e);
					return Response { code: Some(server::restricted::POLICY.into()), error: Some(e), ..none };
				}
			}
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
				None => (state.signed_head(entry.n, &entry.hash), None),
			};
			let mut aux = [0u8; 32];
			rand::rngs::OsRng.fill_bytes(&mut aux);
			let sig = sign_digest(key, &message.digest, &aux);
			eprintln!("arca-signer: signed rebind {} ({}) for the leaf of {} under salt {}: entry {}", hex(&message.digest),
				match kind { Signed::Spend => "spend", Signed::Forfeit(_) => "forfeit" }, hex(&owner.serialize()), hex(&salt), entry.n);
			Response { signature: Some(hex(sig.as_ref())), entry: Some(head), acks, ..none }
		},
		Request::OrderFill { owner, salt, asset_in, exit_delay_units, order, value_in, partial, outputs, known } => {
			let parsed = (|| -> Result<_, String> {
				let owner = XOnlyPublicKey::from_slice(&unhex(&owner)?).map_err(|e| format!("owner: {}", e))?;
				let salt = unhex32(&salt)?;
				let asset_in = elements::AssetId::from_str(&asset_in).map_err(|e| format!("asset_in: {}", e))?;
				let terms = arca_covenant::record_json::order_terms_from_json(&order, asset_in).map_err(|e| format!("order: {}", e))?;
				let exit_delay = arca_covenant::RelativeTime::from_units(exit_delay_units).map_err(|e| format!("exit delay: {}", e))?;
				let value_in = parse_amount(&value_in)?;
				if !(2..=arca_covenant::order::MAX_FILL_OUTPUTS as usize).contains(&outputs.len()) {
					return Err(format!("{} committed outputs; a fill commits to 2 to 4", outputs.len()));
				}
				let outputs = outputs.iter().map(|o| o.to_output().map(|o| o.txout())).collect::<Result<Vec<_>, _>>()?;
				let policy = terms.policy(owner, key.x_only_public_key().0, salt, *chain, exit_delay);
				// The order's terms are its maker's consent: the signer signs a
				// fill only as the program would take it.
				policy.judge(&outputs, 0, value_in, partial).map_err(|e| format!("the fill does not hold: {}", e))?;
				let digest = policy.fill_digest(value_in, &outputs).map_err(|e| e.to_string())?;
				let known = match &known {
					Some(k) => (k.entry, unhex32(&k.hash)?),
					None => (0, [0; 32]),
				};
				Ok((owner, salt, digest, known))
			})();
			let (owner, salt, digest, known) = match parsed {
				Ok(p) => p,
				Err(e) => return Response { error: Some(e), ..none },
			};
			if let Err(e) = state.check_keepers().await {
				eprintln!("arca-signer: refused order fill for the order of {} under salt {}: {}", hex(&owner.serialize()), hex(&salt), e);
				return Response { code: code_of(&e), error: Some(e), ..none };
			}
			let admitted = {
				let mut r = record.lock().unwrap_or_else(|e| e.into_inner());
				r.check_known(known.0, &known.1).and_then(|_| r.admit(&owner.serialize(), &salt, Signed::Spend, &digest))
			};
			let entry = match admitted {
				Ok(e) => e,
				Err(e) => {
					eprintln!("arca-signer: refused order fill {} for the order of {} under salt {}: {}", hex(&digest),
						hex(&owner.serialize()), hex(&salt), e);
					return Response { code: code_of(&e), error: Some(e), ..none };
				},
			};
			let (head, acks) = match &state.keepers {
				Some(_) => match state.held_outside(entry.n).await {
					Ok((h, a)) => (h, Some(a)),
					Err(e) => {
						eprintln!("arca-signer: order fill {} recorded as entry {}, not answered: {}", hex(&digest), entry.n, e);
						return Response { code: code_of(&e), error: Some(e), ..none };
					},
				},
				None => (state.signed_head(entry.n, &entry.hash), None),
			};
			let mut aux = [0u8; 32];
			rand::rngs::OsRng.fill_bytes(&mut aux);
			let sig = sign_digest(key, &digest, &aux);
			eprintln!("arca-signer: signed order fill {} for the order of {} under salt {}: entry {}", hex(&digest),
				hex(&owner.serialize()), hex(&salt), entry.n);
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
				// The operator keeps no unit of an asset this signer mints.
				let minted: Vec<elements::AssetId> = state.issuers.iter().map(|i| i.limiter.asset).collect();
				server::issuer::check_spend_burns(&minted, &tx)?;
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
		Request::Reissue { reissue } => {
			let issuer = match elements::AssetId::from_str(&reissue.asset).ok().and_then(|a| state.issuers.iter().find(|i| i.limiter.asset == a)) {
				Some(i) => i,
				None => return Response { error: Some(format!("asset {} is minted by no limiter this signer holds", reissue.asset)), ..none },
			};
			let checked = match server::issuer::check_reissue(state.chain, state.operator(), &issuer.limiter, &reissue) {
				Ok(c) => c,
				Err(e) => return Response { error: Some(format!("the mint: {}", e)), ..none },
			};
			match mint_witness(state, issuer, &reissue, &checked).await {
				Ok(w) => {
					eprintln!("arca-signer: signed a mint of {} of asset {} in {}, the limiter's count to {} ({} blocks behind)", checked.amount,
						issuer.limiter.asset, checked.tx.txid(), checked.next.minted, checked.next.elapsed);
					Response { witness: Some(w.iter().map(|x| hex(x)).collect()), ..none }
				},
				Err(e) => Response { error: Some(format!("the mint: {}", e)), ..none },
			}
		},
		Request::ChannelState { channel, state: wire_state, owner_sig } => {
			match channel_digest(state, &channel, &wire_state, Some(&owner_sig), None) {
				Ok((digest, what)) => {
					let mut aux = [0u8; 32];
					rand::rngs::OsRng.fill_bytes(&mut aux);
					let sig = sign_digest(key, &digest, &aux);
					eprintln!("arca-signer: signed {}", what);
					Response { signature: Some(hex(sig.as_ref())), ..none }
				},
				Err(e) => {
					eprintln!("arca-signer: refused a channel state: {}", e);
					Response { error: Some(e), ..none }
				},
			}
		},
		Request::ChannelNote { channel, state: wire_state, owner_sig, credit } => {
			let credit = match parse_amount(&credit) {
				Ok(c) => c,
				Err(e) => return Response { error: Some(format!("credit: {}", e)), ..none },
			};
			match channel_digest(state, &channel, &wire_state, owner_sig.as_deref(), Some(credit)) {
				Ok((digest, what)) => {
					let mut aux = [0u8; 32];
					rand::rngs::OsRng.fill_bytes(&mut aux);
					let sig = sign_digest(key, &digest, &aux);
					eprintln!("arca-signer: signed {}", what);
					Response { signature: Some(hex(sig.as_ref())), ..none }
				},
				Err(e) => {
					eprintln!("arca-signer: refused a channel note: {}", e);
					Response { error: Some(e), ..none }
				},
			}
		},
		Request::Unroll { children_hash, time } => {
			let parsed = (|| -> Result<_, String> {
				let h = unhex32(&children_hash).map_err(|e| format!("children_hash: {}", e))?;
				let t = arca_covenant::MedianTime::from_consensus(time).map_err(|e| format!("time: {}", e))?;
				Ok((h, t))
			})();
			let (h, t) = match parsed {
				Ok(p) => p,
				Err(e) => return Response { error: Some(e), ..none },
			};
			let message = arca_covenant::message::unroll_authorisation(&h, t);
			let mut aux = [0u8; 32];
			rand::rngs::OsRng.fill_bytes(&mut aux);
			let sig = sign_digest(key, &message.digest, &aux);
			eprintln!("arca-signer: signed the unroll authorisation of the node with children hash {} from {}", hex(&h), time);
			Response { signature: Some(hex(sig.as_ref())), ..none }
		},
		Request::AccumulatorExit { root, record: slot_record, time } => {
			let parsed = (|| -> Result<_, String> {
				let root = unhex32(&root).map_err(|e| format!("root: {}", e))?;
				let rec = unhex32(&slot_record).map_err(|e| format!("record: {}", e))?;
				let t = arca_covenant::MedianTime::from_consensus(time).map_err(|e| format!("time: {}", e))?;
				Ok((root, rec, t))
			})();
			let (root, rec, t) = match parsed {
				Ok(p) => p,
				Err(e) => return Response { error: Some(e), ..none },
			};
			let digest = arca_covenant::accumulator::exit_digest(chain, &root, &rec, t);
			let mut aux = [0u8; 32];
			rand::rngs::OsRng.fill_bytes(&mut aux);
			let sig = sign_digest(key, &digest, &aux);
			eprintln!("arca-signer: signed the exit authorisation of slot record {} of the accumulator batch {} from {}", hex(&rec),
				hex(&root), time);
			Response { signature: Some(hex(sig.as_ref())), ..none }
		},
	}
}

/// What the signer signs for a `channel-1` coin: the state message of
/// `wire_state`, or with `credit` the note of that cumulative credit, each
/// rebuilt from the channel's terms under the signer's own key and chain,
/// with what it is in words. Refused unless the owner signed the state, the
/// state's balances add up to the channel's value, a note keeps within the
/// state's cap, the signer is not stopped, and its record holds nothing under
/// the coin's salt (a coin given up or paid on takes no new state).
fn channel_digest(state: &State, channel: &WireChannel, wire_state: &WireState, owner_sig: Option<&str>, credit: Option<u64>)
	-> Result<([u8; 32], String), String>
{
	let policy = channel.to_policy(state.key.x_only_public_key().0, state.chain)?;
	let st = wire_state.to_state()?;
	let message = policy.state_message(&st).map_err(|e| e.to_string())?;
	// A state is the owner's own doing; a note may stand on the channel's
	// opening, which its leaf's script carries and nobody signs.
	match (owner_sig, credit) {
		(None, Some(_)) if st == policy.opening() => {},
		(None, _) => return Err(format!("state {} of the channel under salt {} comes without its owner's signature", st.number,
			hex(&policy.salt))),
		(Some(s), _) => {
			let owner_sig = Signature::from_slice(&unhex(s)?).map_err(|e| format!("owner_sig: {}", e))?;
			if st.number == 0 || !verify_digest(&owner_sig, &message.digest, &policy.owner) {
				return Err(format!("the owner's signature over state {} of the channel under salt {} does not verify under the key {}",
					st.number, hex(&policy.salt), hex(&policy.owner.serialize())));
			}
		},
	}
	{
		let r = state.record.lock().unwrap_or_else(|e| e.into_inner());
		if let Some(why) = r.stopped() {
			return Err(format!("the signer is stopped: {}", why));
		}
		let under = r.entries_under(&policy.salt).map_err(|e| format!("the record could not be read: {}", e))?;
		if let Some(e) = under.first() {
			return Err(format!("the record holds entry {} under salt {}: the coin was given up or paid on, and takes no new state \
				or note", e.n, hex(&policy.salt)));
		}
	}
	match credit {
		None => Ok((message.digest, format!("state {} of the channel under salt {} ({} to the owner, {} to the operator)", st.number,
			hex(&policy.salt), st.owner, st.operator))),
		Some(c) => {
			if c == 0 || c > st.credit_cap() {
				return Err(format!("a note of {} for state {}, whose cap is {}: the operator's balance covers no more", c, st.number,
					st.credit_cap()));
			}
			let note = policy.note_message(c).map_err(|e| e.to_string())?;
			Ok((note.digest, format!("a credit note of {} for the channel under salt {} (state {}, cap {})", c, hex(&policy.salt),
				st.number, st.credit_cap())))
		},
	}
}

/// The operator record in `file`, signed with `key` for the chain of
/// `genesis`, as the registry takes it: `{"record", "signature"}`.
fn sign_operator_record(key: &Keypair, file: &std::path::Path, genesis: &str) -> Result<serde_json::Value, String> {
	let text = std::fs::read_to_string(file).map_err(|e| e.to_string())?;
	let record: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("not JSON: {}", e))?;
	let mut aux = [0u8; 32];
	rand::rngs::OsRng.fill_bytes(&mut aux);
	let sig = arca_covenant::operator_record::sign(key, &record, genesis, &aux).map_err(|e| e.to_string())?;
	Ok(serde_json::json!({"record": record, "signature": hex(sig.as_ref())}))
}

// Requests are answered on several threads at once: a witness's signing
// runs beside a co-signature, which waits only for the record's lock.
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
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
	if args.pubkey {
		println!("{}", hex(&operator.serialize()));
		return;
	}
	if let Some(file) = &args.sign_record {
		match sign_operator_record(&key, file, &args.genesis.to_string()) {
			Ok(v) => {
				println!("{}", v);
				return;
			},
			Err(e) => {
				eprintln!("arca-signer: {}: {}", file.display(), e);
				std::process::exit(1);
			},
		}
	}
	if let Some(keepers) = &args.record_keepers {
		match SpendRecord::create(&args.record, &operator, &args.genesis, keepers) {
			Ok(()) => {
				eprintln!("arca-signer: created the record {} for S = {} on {}, its keepers {}", args.record.display(),
					hex(&operator.serialize()), args.genesis, keepers.describe());
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
			Ok((carried, dropped, kept, (n, hash))) => {
				eprintln!("arca-signer: compacted {} into {}: {} entries carried over, {} dropped; it goes on from entry {} ({}); \
					{} salt(s) kept, under which it signs nothing", args.record.display(), into.display(), carried, dropped, n, hex(&hash), kept);
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
			r
		},
		Err(e) => {
			eprintln!("arca-signer: the record: {}", e);
			std::process::exit(2);
		},
	};
	// The keepers are the record's: the command line says only where each
	// is reached, and the signer serves with all of them or not at all.
	let named = record.keepers().clone();
	let addrs = match reached(&named, &args.keepers) {
		Ok(a) => a,
		Err(e) => {
			eprintln!("arca-signer: the record {} names its keepers ({}): {}", args.record.display(), named.describe(), e);
			std::process::exit(2);
		},
	};
	// What the signer saw each keeper hold is written before the first
	// acknowledged head is noted, so a record noted acknowledged has it: one
	// missing was lost, or left beside another name, and taken for empty it
	// would forget a lost keeper and every head a keeper was seen to hold.
	if let Err(e) = keepers_seen_at_start(&args.record, &named, &addrs, args.start_keepers_seen) {
		eprintln!("arca-signer: {}", e);
		std::process::exit(2);
	}
	let record = Mutex::new(record);
	// What the signer saw each keeper hold, before this start as well.
	let seen = match Keepers::read_seen(&args.record, &addrs) {
		Ok(s) => s,
		Err(e) => {
			eprintln!("arca-signer: what the signer saw its keepers hold, kept beside its record: {}", e);
			std::process::exit(2);
		},
	};
	for (c, s) in addrs.iter().zip(&seen) {
		if let Some(why) = &s.lost {
			eprintln!("arca-signer: keeper {} is a lost keeper, as noted beside the record: {}", hex(&c.key.serialize()), why);
		}
	}
	let keepers = (!named.is_none()).then(|| Keepers {
		required: named.required,
		list: addrs.iter().map(|k| KeeperClient::new(k.clone(), args.keeper_timeout)).collect(),
		checked: tokio::sync::Mutex::new(false),
		acked: tokio::sync::Mutex::new(None),
		saved: Mutex::new(seen.clone()),
		seen: Mutex::new(seen),
		acknowledged: std::sync::atomic::AtomicBool::new(server::signer::acknowledged_path(&args.record).exists()),
		record: args.record.clone(),
	});
	// Each issuer-operated asset's limiter: an instance on this chain, whose
	// mnemonic file only its owner reads.
	let mut issuers = vec![];
	for (instance, mnemonic) in &args.issuers {
		let text = match std::fs::read_to_string(instance) {
			Ok(t) => t,
			Err(e) => fail(&format!("--issuer: {}: {}", instance.display(), e)),
		};
		let (limiter, genesis) = match arca_covenant::LimiterParams::from_instance_json(&text) {
			Ok(x) => x,
			Err(e) => fail(&format!("--issuer: {}: {}", instance.display(), e)),
		};
		if genesis != args.genesis {
			fail(&format!("--issuer: {} is a mint limiter on chain {}, not {}", instance.display(), genesis, args.genesis));
		}
		match std::fs::metadata(mnemonic) {
			Ok(m) if m.permissions().mode() & 0o077 != 0 => fail(&format!("--issuer: {} is readable by others than its owner", mnemonic.display())),
			Ok(_) => {},
			Err(e) => fail(&format!("--issuer: {}: {}", mnemonic.display(), e)),
		}
		if limiter.operator == key.x_only_public_key().0 {
			fail("--issuer: the limiter's operator key is S: a mint is signed by the issuer's own key, never by S");
		}
		eprintln!("arca-signer: mints asset {} through its limiter {} (allowance {} a window of {} blocks)", limiter.asset,
			instance.display(), limiter.allowance, limiter.window);
		issuers.push(Issuer { limiter, instance: instance.clone(), mnemonic: mnemonic.clone() });
	}
	let supervision = args.supervision.as_ref().map(|(url, cookie)| {
		eprintln!("arca-signer: reads freezes of supervised assets from the node at {}", url);
		sequentia_ext::rpc::Client::new(url.clone(), sequentia_ext::rpc::Auth::CookieFile(cookie.clone())).with_timeout(30)
	});
	for (a, p, c) in &args.restricted {
		eprintln!("arca-signer: serves restricted asset {}: its messages co-signed only beside policy key {}, clawback {}", a,
			hex(&p.serialize()), c.map_or("none".to_string(), |k| hex(&k.serialize())));
	}
	let restricted = args.restricted.iter().map(|(a, p, c)| (*a, (*p, *c))).collect();
	let state = Arc::new(State { key, chain: Chain::new(args.genesis), genesis: args.genesis, record, keepers, sigs: Default::default(),
		issuers, mint_tool: args.mint_tool.clone(), supervision, restricted });
	match &state.keepers {
		// At start, before anything is served: the keepers' latest heads
		// against the record. One the record does not hold stops the signer
		// now; with too few answers, it serves, and signs nothing the record
		// governs until enough answer.
		Some(k) => {
			eprintln!("arca-signer: the record's {} keeper(s), {} of them to hold every head: {}", k.list.len(), k.required,
				k.list.iter().map(|c| format!("{} ({})", c.addr.addr, hex(&c.addr.key.serialize()))).collect::<Vec<_>>().join(", "));
			if let Err(e) = state.check_keepers().await {
				eprintln!("arca-signer: at start: {}", e);
			}
		},
		None => eprintln!("arca-signer: the record names no keeper: it rests on this machine alone, and a restore of the machine can let \
			a coin paid out of round be spent twice; this operator is for its own coins"),
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
		let info = r.info();
		if info.dropped_salts > 0 {
			eprintln!("arca-signer: {} salt(s) kept from compactions, under which it signs nothing", info.dropped_salts);
		}
		if info.salts_lost {
			eprintln!("arca-signer: the record is a compaction of format {} by an older signer, which kept no salt it dropped: it \
				would sign again under one. Compact it again (--compact-into, with arcad expired-salts) before posting a bond", info.format);
		}
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
