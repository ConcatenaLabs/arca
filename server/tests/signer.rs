//! `arca-signer` as its own process: it holds `S`, answers its key, signs the
//! rebindable message it builds itself for this chain, and nothing else.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use elements::hashes::{sha256d, Hash};
use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, BlockHash, Script};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use arca_covenant::message::rebind_message;
use arca_covenant::sign::{sign_digest, verify_digest};
use arca_covenant::{Chain, ExplicitOutput, LeafPolicy};
use common::keys::{keypair, xonly};
use common::signer::{key_file, signer_dir, SignerProcess};
use server::signer::{SignerClient, SignerError};

async fn raw(socket: &std::path::Path, line: &str) -> String {
	let mut s = UnixStream::connect(socket).await.unwrap();
	// A line over the limit is answered, and the socket closed, before the
	// signer has read it all: the rest cannot be written.
	let _ = s.write_all(line.as_bytes()).await;
	let _ = s.write_all(b"\n").await;
	let mut r = BufReader::new(s);
	let mut out = String::new();
	r.read_line(&mut out).await.unwrap();
	out
}

#[tokio::test]
async fn the_signer_process() {
	let s = keypair("operator");
	let genesis = BlockHash::from_raw_hash(sha256d::Hash::hash(b"a chain"));
	let p = SignerProcess::start(&s, genesis);
	let mode = std::fs::metadata(&p.socket).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o600, "the socket is the operator's alone");
	let client = SignerClient::new(&p.socket);
	assert_eq!(client.pubkey().await.unwrap(), xonly(&s));

	// A rebindable message for a leaf on this chain: the signature verifies
	// against the message arca-covenant builds.
	let leaf = LeafPolicy {
		owner: xonly(&keypair("owner")), operator: xonly(&s), salt: [5; 32], chain: Chain::new(genesis),
		exit_delay: arca_covenant::RelativeTime::from_units(254).unwrap(),
	};
	let asset = AssetId::from_slice(&[3; 32]).unwrap();
	let outs = vec![ExplicitOutput::new(asset, 9_000, Script::from(vec![0x51]))];
	let owner = keypair("owner");
	let msg = leaf.collab_message(asset, 10_000, &outs).unwrap();
	let sig = client.rebind(&xonly(&owner), &sign_digest(&owner, &msg.digest, &[0; 32]), &leaf.salt, asset, 10_000, &outs).await.unwrap();
	assert!(verify_digest(&sig, &msg.digest, &xonly(&s)));
	// The same parts on another chain give another message: this signature
	// means nothing there.
	let other = LeafPolicy { chain: Chain::new(BlockHash::all_zeros()), ..leaf };
	assert!(!verify_digest(&sig, &other.collab_message(asset, 10_000, &outs).unwrap().digest, &xonly(&s)));
	println!("rebind signed for pid {}; verifies on its chain only", p.pid());

	// Nothing but its key and rebindable messages.
	for (what, line) in [
		("a raw digest", format!(r#"{{"op":"sign","digest":"{}"}}"#, "00".repeat(32))),
		("no outputs", format!(r#"{{"op":"rebind","salt":"{}","asset_in":"{}","value_in":"1","outputs":[]}}"#, "00".repeat(32), asset)),
		("five outputs", format!(r#"{{"op":"rebind","salt":"{}","asset_in":"{}","value_in":"1","outputs":[{}]}}"#,
			"00".repeat(32), asset, vec![format!(r#"{{"asset":"{}","value":"1","script":"51"}}"#, asset); 5].join(","))),
		("an unknown field", format!(r#"{{"op":"pubkey","digest":"{}"}}"#, "00".repeat(32))),
		("a value with a sign", format!(r#"{{"op":"rebind","salt":"{}","asset_in":"{}","value_in":"-1","outputs":[{{"asset":"{}","value":"1","script":"51"}}]}}"#, "00".repeat(32), asset, asset)),
		("a line over the limit", format!(r#"{{"op":"pubkey","x":"{}"}}"#, "a".repeat(1_100_000))),
	] {
		let answer = raw(&p.socket, &line).await;
		let v: serde_json::Value = serde_json::from_str(&answer).unwrap();
		assert!(v["error"].is_string() && v["signature"].is_null(), "{}: {}", what, answer);
		println!("refused, {}: {}", what, v["error"].as_str().unwrap());
	}
	let e = client.rebind(&xonly(&owner), &sign_digest(&owner, &[0; 32], &[0; 32]), &[0; 32], asset, 1, &[]).await.unwrap_err();
	assert!(matches!(e, SignerError::Refused(_)), "{}", e);

	// The spend of one of the operator's own paths: a clock's release. The
	// signer computes the signature hash itself, on its own chain.
	let schedule = arca_covenant::ClockSchedule::new(asset, xonly(&s), arca_covenant::RelativeTime::from_units(254).unwrap(),
		vec![arca_covenant::MedianTime::from_consensus(1_800_000_000).unwrap()]).unwrap();
	let fee_coin = sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(asset, 9_000), Script::from(vec![0x51]));
	let fee = arca_covenant::spend::FeeSource::Coin {
		outpoint: elements::OutPoint::new(elements::Txid::from_raw_hash(sha256d::Hash::hash(b"fee coin")), 0),
		coin: fee_coin, fee: 1_000, change: Script::from(vec![0x51]),
	};
	let token = elements::OutPoint::new(elements::Txid::from_raw_hash(sha256d::Hash::hash(b"token")), 1);
	let release = schedule.release_tx(0, token, &fee).unwrap();
	let sig = client.spend(&release.tx, &release.prevouts, 0, &release.script).await.unwrap();
	assert!(verify_digest(&sig, &release.sighash(genesis).unwrap(), &xonly(&s)), "the release's signature verifies");
	println!("signed the release of clock 0: it verifies over the signature hash arca-covenant builds");

	// A path that is not the operator's: refused, whatever the transaction.
	let collab = leaf.collab_script();
	let exit = leaf.exit_script();
	let cases: Vec<(&str, Vec<elements::TxOut>, usize, Script)> = vec![
		("the leaf's collaborative path (S under OP_CHECKSIGFROMSTACK)", release.prevouts.clone(), 0, collab),
		("the owner's exit path", release.prevouts.clone(), 0, exit),
		("an input past the last", release.prevouts.clone(), 2, release.script.clone()),
		("one spent output for two inputs", release.prevouts[..1].to_vec(), 0, release.script.clone()),
		("an input spending a bare OP_TRUE", vec![release.prevouts[1].clone(), release.prevouts[1].clone()], 0, release.script.clone()),
	];
	for (what, prevouts, input, script) in cases {
		let e = client.spend(&release.tx, &prevouts, input, &script).await.unwrap_err();
		assert!(matches!(e, SignerError::Refused(_)), "{}: {}", what, e);
		println!("refused, {}: {}", what, e);
	}
	let line = format!(r#"{{"op":"spend","tx":"00","prevouts":[],"input":0,"leaf":"51","digest":"{}"}}"#, "00".repeat(32));
	let v: serde_json::Value = serde_json::from_str(&raw(&p.socket, &line).await).unwrap();
	assert!(v["error"].is_string() && v["signature"].is_null(), "a stray digest: {}", v);
	println!("refused, a spend request carrying a digest: {}", v["error"].as_str().unwrap());

	// A key file others can read is refused at start.
	let dir = signer_dir();
	let file = key_file(&dir, &s, 0o644);
	let out = Command::new(env!("CARGO_BIN_EXE_arca-signer"))
		.args(["--key-file", file.to_str().unwrap(), "--genesis", &genesis.to_string(), "--socket", dir.join("s").to_str().unwrap(),
			"--record", dir.join("r").to_str().unwrap()])
		.output().unwrap();
	assert_eq!(out.status.code(), Some(2));
	let msg = String::from_utf8_lossy(&out.stderr);
	assert!(msg.contains("readable by others"), "{}", msg);
	println!("a key file of mode 644: {}", msg.trim());
	std::fs::remove_dir_all(&dir).unwrap();
}

/// The owner's signature over the rebindable message of its leaf under
/// `salt` on `genesis`'s chain: what the server forwards with every rebind.
fn owner_sig(owner: &Keypair, genesis: BlockHash, salt: &[u8; 32], asset: AssetId, value_in: u64, outputs: &[ExplicitOutput])
	-> elements::secp256k1_zkp::schnorr::Signature
{
	let m = rebind_message(&Chain::new(genesis).leaf_constant(salt), asset, value_in, outputs).unwrap();
	sign_digest(owner, &m.digest, &[0; 32])
}

/// The one-spend record: one spend under a salt, or forfeits one per round,
/// kept on disk across restarts, whatever asks; an entry names its leaf (its
/// owner key and its salt) and is always the owner's doing, but the rule is
/// the salt's, since `S`'s signature commits to the salt and not to the
/// owner: another leaf under the same salt is refused another message.
#[tokio::test]
async fn the_signers_record() {
	use arca_covenant::{ForfeitPolicy, LeafId, RelativeTime};
	let s = keypair("operator");
	let genesis = BlockHash::from_raw_hash(sha256d::Hash::hash(b"a chain"));
	let mut p = SignerProcess::start(&s, genesis);
	let client = SignerClient::new(&p.socket);
	let asset = AssetId::from_slice(&[3; 32]).unwrap();
	let out = |v: u64, b: u8| ExplicitOutput::new(asset, v, Script::from(vec![0x51, b]));
	let refused_twice = |e: SignerError| assert!(matches!(e, SignerError::AlreadySigned(_)), "{}", e);
	let (a, b) = (keypair("owner"), keypair("another holder"));
	let spend = |k: &Keypair, salt: [u8; 32], o: ExplicitOutput| {
		let client = client.clone();
		let k = *k;
		async move { client.rebind(&xonly(&k), &owner_sig(&k, genesis, &salt, asset, 10_000, &[o.clone()]), &salt, asset, 10_000, &[o]).await }
	};

	// A spend of A's leaf under salt 1, the same again, and a second spend
	// refused.
	let first = spend(&a, [1; 32], out(9_000, 1)).await.unwrap();
	let again = spend(&a, [1; 32], out(9_000, 1)).await.unwrap();
	println!("A's leaf under salt 1: spend signed, and signed again when asked again ({} and {})", hex32(&first), hex32(&again));
	let e = spend(&a, [1; 32], out(9_000, 2)).await.unwrap_err();
	println!("A's leaf under salt 1: a second spend: {}", e);
	refused_twice(e);

	// B's leaf under the same salt: S's signature for A's spend is valid on
	// B's coin too, so a spend of B's into another message would be a second
	// signature under the salt, valid on A's coin as well: refused. The same
	// message, B's own signature over it, is no second spend.
	let e = spend(&b, [1; 32], out(9_000, 2)).await.unwrap_err();
	println!("B's leaf under salt 1 (A's salt), another message: {}", e);
	refused_twice(e);
	spend(&b, [1; 32], out(9_000, 1)).await.unwrap();
	println!("B's leaf under salt 1, the message A's spend was signed for: signed, no second spend");
	refused_twice(spend(&b, [1; 32], out(9_000, 3)).await.unwrap_err());
	refused_twice(spend(&a, [1; 32], out(9_000, 3)).await.unwrap_err());
	println!("any other message under salt 1, by either owner: refused");

	// An owner signature that is not the named key's over this message:
	// refused, and nothing recorded under that key.
	let o = out(9_000, 5);
	let wrong_key = owner_sig(&b, genesis, &[5; 32], asset, 10_000, &[o.clone()]);
	let e = client.rebind(&xonly(&a), &wrong_key, &[5; 32], asset, 10_000, &[o.clone()]).await.unwrap_err();
	assert!(matches!(e, SignerError::Refused(_)), "{}", e);
	println!("A named, B's signature: {}", e);
	let wrong_message = owner_sig(&a, genesis, &[5; 32], asset, 10_000, &[out(9_000, 6)]);
	let e = client.rebind(&xonly(&a), &wrong_message, &[5; 32], asset, 10_000, &[o.clone()]).await.unwrap_err();
	assert!(matches!(e, SignerError::Refused(_)), "{}", e);
	println!("A's signature over another message: {}", e);
	let wrong_salt = owner_sig(&a, genesis, &[6; 32], asset, 10_000, &[o.clone()]);
	let e = client.rebind(&xonly(&a), &wrong_salt, &[5; 32], asset, 10_000, &[o.clone()]).await.unwrap_err();
	assert!(matches!(e, SignerError::Refused(_)), "{}", e);
	println!("A's signature for another salt: {}", e);

	// Forfeits of A's leaf under salt 2: one per connector asset.
	let forfeit = |m: u8, h: u8| ForfeitPolicy {
		unlock_hash: [h; 32], owner: xonly(&a), operator: xonly(&s),
		refund_delay: RelativeTime::from_units(338).unwrap(), leaf_id: LeafId([2; 32]), connector: AssetId::from_slice(&[m; 32]).unwrap(),
	};
	let fout = |f: &ForfeitPolicy| ExplicitOutput::new(asset, 9_000, f.script_pubkey());
	let give = |salt: [u8; 32], f: ForfeitPolicy, o: ExplicitOutput| {
		let client = client.clone();
		async move {
			let sig = owner_sig(&a, genesis, &salt, asset, 10_000, &[o.clone()]);
			client.rebind_forfeit(&xonly(&a), &sig, &salt, asset, 10_000, &f, &o).await
		}
	};
	let (f1, f1b, f2) = (forfeit(7, 1), forfeit(7, 2), forfeit(8, 1));
	give([2; 32], f1, fout(&f1)).await.unwrap();
	give([2; 32], f1, fout(&f1)).await.unwrap();
	let e = give([2; 32], f1b, fout(&f1b)).await.unwrap_err();
	println!("salt 2: a second forfeit for the same round: {}", e);
	refused_twice(e);
	give([2; 32], f2, fout(&f2)).await.unwrap();
	println!("salt 2: a forfeit for another round's connector is signed");
	let e = spend(&a, [2; 32], out(9_000, 1)).await.unwrap_err();
	println!("salt 2: a spend after its forfeits: {}", e);
	refused_twice(e);
	// Another owner's forfeit under salt 2 for a round already forfeited
	// there, and its spend: refused, the rule being the salt's.
	let fb = ForfeitPolicy { owner: xonly(&b), ..forfeit(7, 3) };
	let ob = fout(&fb);
	let sig = owner_sig(&b, genesis, &[2; 32], asset, 10_000, &[ob.clone()]);
	let e = client.rebind_forfeit(&xonly(&b), &sig, &[2; 32], asset, 10_000, &fb, &ob).await.unwrap_err();
	println!("salt 2: B's forfeit for the round A's forfeit was signed for: {}", e);
	refused_twice(e);
	refused_twice(spend(&b, [2; 32], out(9_000, 1)).await.unwrap_err());
	// A spend's leaf takes no forfeit.
	let f3 = forfeit(9, 1);
	let e = give([1; 32], f3, fout(&f3)).await.unwrap_err();
	println!("salt 1: a forfeit after its spend: {}", e);
	refused_twice(e);
	// Parts that do not make the output committed to: refused, not recorded.
	let e = give([3; 32], f3, out(9_000, 1)).await.unwrap_err();
	assert!(matches!(e, SignerError::Refused(_)), "{}", e);
	println!("salt 3: forfeit parts that do not make the output: {}", e);
	spend(&a, [3; 32], out(9_000, 3)).await.unwrap();

	// The record outlives the process: after a restart, the same refusals.
	let lines = std::fs::read_to_string(p.record()).unwrap();
	println!("the record, {} line(s):\n{}", lines.lines().count(), lines.trim_end());
	assert_eq!(lines.lines().count(), 1 + 4,
		"the header, the one message under salt 1, two forfeits of salt 2, a spend of salt 3");
	p.restart(&s, genesis);
	refused_twice(spend(&a, [1; 32], out(9_000, 2)).await.unwrap_err());
	refused_twice(spend(&b, [1; 32], out(9_000, 2)).await.unwrap_err());
	spend(&b, [1; 32], out(9_000, 1)).await.unwrap();
	refused_twice(give([2; 32], f1b, fout(&f1b)).await.unwrap_err());
	spend(&a, [1; 32], out(9_000, 1)).await.unwrap();
	println!("after a restart: the same second spends and second forfeit refused; the first spend signed again");

	// A last line cut short by a crash was never answered: it is dropped.
	p.kill();
	let mut f = std::fs::OpenOptions::new().append(true).open(p.record()).unwrap();
	std::io::Write::write_all(&mut f, b"6 spend 0404").unwrap();
	drop(f);
	p.restart(&s, genesis);
	spend(&a, [4; 32], out(9_000, 4)).await.unwrap();
	let lines = std::fs::read_to_string(p.record()).unwrap();
	assert_eq!(lines.lines().count(), 1 + 5, "the cut line dropped, the new one whole: {}", lines);
	// Any other line that does not read stops the signer from starting, and
	// so does a record kept by salt alone, which has no header.
	let start = |p: &SignerProcess| Command::new(env!("CARGO_BIN_EXE_arca-signer"))
		.args(["--key-file", p.dir.join("operator.key").to_str().unwrap(), "--genesis", &genesis.to_string(),
			"--socket", p.socket.to_str().unwrap(), "--record", p.record().to_str().unwrap()])
		.output().unwrap();
	p.kill();
	std::fs::write(p.record(), format!("{}nonsense\n{}", lines, lines)).unwrap();
	let out = start(&p);
	assert_eq!(out.status.code(), Some(2));
	println!("a record with a line that does not read: {}", String::from_utf8_lossy(&out.stderr).trim());
	std::fs::write(p.record(), format!("spend {} {}\n", "01".repeat(32), "02".repeat(32))).unwrap();
	let out = start(&p);
	assert_eq!(out.status.code(), Some(2));
	let msg = String::from_utf8_lossy(&out.stderr);
	assert!(msg.contains("by salt alone"), "{}", msg);
	println!("a record kept by salt alone: {}", msg.trim());
}

fn hex32(s: &elements::secp256k1_zkp::schnorr::Signature) -> String {
	s.as_ref()[..8].iter().map(|b| format!("{:02x}", b)).collect::<String>() + "…"
}

/// A rebind request line for `owner`'s leaf under `salt`, spending 10,000 of
/// `asset` into one output of 9,000 to a script ending in `b`, naming
/// `known` as the latest entry the database knows.
fn rebind_line(owner: &Keypair, genesis: BlockHash, salt: [u8; 32], asset: AssetId, b: u8, known: Option<(u64, [u8; 32])>) -> String {
	use server::signer::{hex, WireOutput};
	let o = ExplicitOutput::new(asset, 9_000, Script::from(vec![0x51, b]));
	let sig = owner_sig(owner, genesis, &salt, asset, 10_000, std::slice::from_ref(&o));
	let mut r = serde_json::json!({
		"op": "rebind", "owner": hex(&xonly(owner).serialize()), "owner_sig": hex(sig.as_ref()), "salt": hex(&salt),
		"asset_in": asset.to_string(), "value_in": "10000", "outputs": [WireOutput::from_output(&o)],
	});
	if let Some((entry, hash)) = known {
		r["known"] = serde_json::json!({"entry": entry, "hash": hex(&hash)});
	}
	r.to_string()
}

/// `S`'s signature over entry `n` of the record with running hash `hash`.
fn head_sig(s: &Keypair, genesis: BlockHash, n: u64, hash: &[u8; 32]) -> elements::secp256k1_zkp::schnorr::Signature {
	sign_digest(s, &server::signer::record_head_digest(&genesis, n, hash), &[7; 32])
}

/// The signer's answer to a witness of `heads`.
async fn witness(socket: &std::path::Path, heads: &[(u64, [u8; 32], Option<elements::secp256k1_zkp::schnorr::Signature>)]) -> serde_json::Value {
	use server::signer::hex;
	let heads: Vec<serde_json::Value> = heads.iter().map(|(n, h, s)| {
		let mut v = serde_json::json!({"entry": n, "hash": hex(h)});
		if let Some(s) = s {
			v["signature"] = serde_json::json!(hex(s.as_ref()));
		}
		v
	}).collect();
	serde_json::from_str(&raw(socket, &serde_json::json!({"op": "witness", "heads": heads}).to_string()).await).unwrap()
}

/// The answer to a rebind request: the entry recorded, or the refusal's
/// code and sentence.
async fn ask(socket: &std::path::Path, line: &str) -> Result<(u64, [u8; 32]), (String, String)> {
	let v: serde_json::Value = serde_json::from_str(&raw(socket, line).await).unwrap();
	match v["error"].as_str() {
		Some(e) => Err((v["code"].as_str().unwrap_or("").to_string(), e.to_string())),
		None => {
			assert!(v["signature"].is_string(), "{}", v);
			let h: [u8; 32] = server::signer::unhex32(v["entry"]["hash"].as_str().unwrap_or("")).unwrap_or([0; 32]);
			Ok((v["entry"]["entry"].as_u64().unwrap_or(0), h))
		},
	}
}

/// A signer run by hand: its process, its socket, and its log.
struct Run {
	child: std::process::Child,
	socket: std::path::PathBuf,
	log: std::path::PathBuf,
}

impl Run {
	/// Starts `arca-signer` on `record` through `prefix` (a shell prefix that
	/// ends in an `exec`, so the signer keeps the shell's pid), its log to a
	/// file beside the socket. Waits for
	/// its socket, or for it to exit; `None` when it exited.
	fn start(dir: &std::path::Path, name: &str, genesis: BlockHash, record: &std::path::Path, prefix: &str) -> Result<Run, String> {
		Self::start_of(env!("CARGO_BIN_EXE_arca-signer"), dir, name, genesis, record, prefix)
	}

	/// `start`, of the signer binary at `bin`.
	fn start_of(bin: &str, dir: &std::path::Path, name: &str, genesis: BlockHash, record: &std::path::Path, prefix: &str)
		-> Result<Run, String>
	{
		let socket = dir.join(format!("{}.sock", name));
		let log = dir.join(format!("{}.log", name));
		let _ = std::fs::remove_file(&socket);
		let cmd = format!("{}{} --key-file {} --genesis {} --socket {} --record {} 2> {}", prefix, bin,
			dir.join("operator.key").display(), genesis, socket.display(), record.display(), log.display());
		let mut child = Command::new("bash").args(["-c", &cmd]).spawn().unwrap();
		let start = std::time::Instant::now();
		loop {
			if socket.exists() {
				std::thread::sleep(std::time::Duration::from_millis(50));
				return Ok(Run { child, socket, log });
			}
			if let Some(st) = child.try_wait().unwrap() {
				return Err(format!("exit {:?}: {}", st.code(), std::fs::read_to_string(&log).unwrap_or_default().trim()));
			}
			assert!(start.elapsed() < std::time::Duration::from_secs(20), "the signer neither served nor exited");
			std::thread::sleep(std::time::Duration::from_millis(50));
		}
	}

	fn log(&self) -> String {
		std::fs::read_to_string(&self.log).unwrap_or_default()
	}

	fn stop(self) -> String {
		self.log()
	}
}

impl Drop for Run {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

/// The signer's record cannot be lost, cut back, torn or shared without the
/// signer noticing: a missing record is never replaced by an empty one (one
/// is made on purpose, once); a record cut back at a line boundary, or
/// another record, is caught by the entry the database knows, and the signer
/// then signs nothing; a write that fails is undone at once, and a line cut
/// short by a crash is removed at start with a log line; an edited line, or
/// a record of another key, stops the start; two signers never write one
/// record.
#[tokio::test(flavor = "multi_thread")]
async fn the_record_cannot_be_lost_cut_torn_or_shared() {
	let s = keypair("operator");
	let genesis = BlockHash::from_raw_hash(sha256d::Hash::hash(b"a chain"));
	let dir = signer_dir();
	let key = key_file(&dir, &s, 0o600);
	let record = dir.join("signer.record");
	let asset = AssetId::from_slice(&[3; 32]).unwrap();
	let (a, b) = (keypair("owner"), keypair("another holder"));

	// Lost: no record, no start; one is made on purpose, once.
	let e = Run::start(&dir, "lost", genesis, &record, "exec ").err().expect("no start without a record");
	println!("(a) no record: {}", e);
	assert!(e.contains("exit Some(2)") && e.contains("there is no record here"), "{}", e);
	assert!(!record.exists(), "nothing was made in passing");
	let made = common::signer::create_record(&key, genesis, &record);
	assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
	println!("(a) --create-record: {}", String::from_utf8_lossy(&made.stderr).trim());
	let again = common::signer::create_record(&key, genesis, &record);
	assert_eq!(again.status.code(), Some(2));
	println!("(a) --create-record again: {}", String::from_utf8_lossy(&again.stderr).trim());
	assert_eq!(std::fs::metadata(&record).unwrap().permissions().mode() & 0o777, 0o600);

	// Entries 1 and 2, the database told each.
	let run = Run::start(&dir, "one", genesis, &record, "exec ").unwrap();
	let e1 = ask(&run.socket, &rebind_line(&a, genesis, [1; 32], asset, 1, None)).await.unwrap();
	assert_eq!(e1.0, 1);
	let at_one = std::fs::read(&record).unwrap();
	let e2 = ask(&run.socket, &rebind_line(&a, genesis, [2; 32], asset, 1, Some(e1))).await.unwrap();
	assert_eq!(e2.0, 2);
	println!("entries 1 and 2 recorded; the database knows entry 2");

	// Shared: a second signer on the same record does not start.
	let e = Run::start(&dir, "two", genesis, &record, "exec ").err().expect("a second signer on one record does not start");
	println!("(d) a second signer on the same record: {}", e);
	assert!(e.contains("exit Some(2)") && e.contains("held by another signer"), "{}", e);
	run.stop();

	// Cut back: the record as it was after entry 1. The signer starts (it
	// cannot know), but the first request naming entry 2 is refused, and
	// from then on it signs nothing: not the second spend of the leaf under
	// salt 2 it would otherwise sign again, nor anything else.
	std::fs::write(dir.join("whole.record"), std::fs::read(&record).unwrap()).unwrap();
	std::fs::write(&record, &at_one).unwrap();
	let run = Run::start(&dir, "cut", genesis, &record, "exec ").unwrap();
	let e = ask(&run.socket, &rebind_line(&a, genesis, [2; 32], asset, 2, Some(e2))).await.unwrap_err();
	println!("(b) the record cut back to entry 1, the database knowing entry 2: {} {}", e.0, e.1);
	assert_eq!(e.0, "record_behind", "{}", e.1);
	let e = ask(&run.socket, &rebind_line(&b, genesis, [9; 32], asset, 1, None)).await.unwrap_err();
	println!("(b) then anything else: {} {}", e.0, e.1);
	assert_eq!(e.0, "record_behind");
	run.stop();
	std::fs::write(&record, std::fs::read(dir.join("whole.record")).unwrap()).unwrap();

	// Another record: a copy taken after entry 1 and written on by another
	// signer has another entry 2.
	let copy = dir.join("copy.record");
	std::fs::write(&copy, &at_one).unwrap();
	let other = Run::start(&dir, "copy", genesis, &copy, "exec ").unwrap();
	let c2 = ask(&other.socket, &rebind_line(&b, genesis, [7; 32], asset, 1, Some(e1))).await.unwrap();
	assert_eq!(c2.0, 2);
	let e = ask(&other.socket, &rebind_line(&b, genesis, [8; 32], asset, 1, Some(e2))).await.unwrap_err();
	println!("(d) a copy written by another signer, asked with the database's entry 2: {} {}", e.0, e.1);
	assert_eq!(e.0, "record_differs", "{}", e.1);
	other.stop();

	// A write that fails (the disk full: a file size limit just past the
	// record) is undone at once; with room again the next entry is whole.
	let size = std::fs::metadata(&record).unwrap().len();
	let limited = Run::start(&dir, "full", genesis, &record, &format!("trap '' XFSZ; exec prlimit --fsize={}:unlimited ", size + 100))
		.unwrap();
	let pid = limited.child.id().to_string();
	let e = ask(&limited.socket, &rebind_line(&a, genesis, [3; 32], asset, 1, Some(e2))).await.unwrap_err();
	println!("(c) a write past the limit: {}", e.1);
	assert!(e.1.contains("could not be written") && e.1.contains("removed"), "{}", e.1);
	let bytes = std::fs::read(&record).unwrap();
	assert_eq!(bytes.len() as u64, size, "the line cut short is gone at once");
	assert!(bytes.ends_with(b"\n"));
	let raised = Command::new("prlimit").args(["--pid", &pid, "--fsize=unlimited:unlimited"]).status().unwrap();
	assert!(raised.success());
	let e3 = ask(&limited.socket, &rebind_line(&a, genesis, [3; 32], asset, 1, Some(e2))).await.unwrap();
	assert_eq!(e3.0, 3, "the next entry follows entry 2");
	limited.stop();
	let run = Run::start(&dir, "after", genesis, &record, "exec ").unwrap();
	println!("(c) room again: entry 3 written whole, and the signer starts on the record: {}", run.log().trim());
	run.stop();

	// A line cut short by a crash is removed at start, which says so, and
	// the next entry follows the last whole one.
	let mut f = std::fs::OpenOptions::new().append(true).open(&record).unwrap();
	std::io::Write::write_all(&mut f, format!("4 spend {}", "05".repeat(20)).as_bytes()).unwrap();
	drop(f);
	let run = Run::start(&dir, "crash", genesis, &record, "exec ").unwrap();
	let log = run.log();
	println!("(c) a line cut short by a crash, at start: {}", log.lines().next().unwrap_or(""));
	assert!(log.contains("cut short") && log.contains("removed"), "{}", log);
	let e4 = ask(&run.socket, &rebind_line(&a, genesis, [4; 32], asset, 1, Some(e3))).await.unwrap();
	assert_eq!(e4.0, 4);
	run.stop();

	// An edited line stops the start: its running hash no longer follows.
	let text = std::fs::read_to_string(&record).unwrap();
	let edited = text.replacen(&"02".repeat(32), &"0a".repeat(32), 1);
	assert_ne!(edited, text);
	std::fs::write(&record, edited).unwrap();
	let e = Run::start(&dir, "edited", genesis, &record, "exec ").err().expect("no start on an edited record");
	println!("(b) an edited line: {}", e);
	assert!(e.contains("running hash does not follow"), "{}", e);
	std::fs::write(&record, text).unwrap();

	// A record of another key does not start under this one.
	let other_key = keypair("another operator");
	std::fs::write(&key, other_key.secret_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>()).unwrap();
	let e = Run::start(&dir, "key", genesis, &record, "exec ").err().expect("no start on another key's record");
	println!("a record of another key: {}", e);
	assert!(e.contains("another operator key"), "{}", e);
	std::fs::remove_dir_all(&dir).unwrap();
}

/// The record compacted into a new one: the entries under the salts the
/// server lists as expired dropped, every other carried over verbatim, the
/// new record going on from the old one's latest entry, so the entry the
/// database knows is still the record's. The signer starts on it and keeps
/// the rule for every salt carried over; a dropped salt is free again; the
/// carried lines are checked against the header's hash; and a compaction
/// never runs while a signer holds the record, nor over a file that is there.
#[tokio::test(flavor = "multi_thread")]
async fn the_record_is_compacted_and_goes_on_from_its_latest_entry() {
	use server::signer::hex;
	let s = keypair("operator");
	let genesis = BlockHash::from_raw_hash(sha256d::Hash::hash(b"a chain"));
	let dir = signer_dir();
	let key = key_file(&dir, &s, 0o600);
	let record = dir.join("signer.record");
	let asset = AssetId::from_slice(&[3; 32]).unwrap();
	let a = keypair("owner");
	assert!(common::signer::create_record(&key, genesis, &record).status.success());

	// Seven entries, under salts 1 to 7, the database told each.
	let run = Run::start(&dir, "first", genesis, &record, "exec ").unwrap();
	let mut known = None;
	let mut entries = vec![];
	for k in 1..=7u8 {
		let e = ask(&run.socket, &rebind_line(&a, genesis, [k; 32], asset, 1, known)).await.unwrap();
		assert_eq!(e.0, k as u64);
		entries.push(e);
		known = Some(e);
	}
	let compact = |into: &std::path::Path, drop: &std::path::Path| Command::new(env!("CARGO_BIN_EXE_arca-signer"))
		.args(["--key-file", key.to_str().unwrap(), "--genesis", &genesis.to_string(), "--record", record.to_str().unwrap(),
			"--compact-into", into.to_str().unwrap(), "--drop-salts", drop.to_str().unwrap()])
		.output().unwrap();
	let drop = dir.join("expired.salts");
	std::fs::write(&drop, format!("{}\n{}\n{}\n{}\n", hex(&[1; 32]), hex(&[2; 32]), hex(&[3; 32]), hex(&[9; 32]))).unwrap();
	let new = dir.join("signer.record.new");
	let out = compact(&new, &drop);
	assert_eq!(out.status.code(), Some(2), "no compaction while a signer holds the record");
	println!("compacting while the signer runs: {}", String::from_utf8_lossy(&out.stderr).trim());
	assert!(!new.exists());
	run.stop();

	let out = compact(&new, &drop);
	let said = String::from_utf8_lossy(&out.stderr).to_string();
	println!("compacted: {}", said.trim());
	assert!(out.status.success(), "{}", said);
	assert!(said.contains("4 entries carried over, 3 dropped; it goes on from entry 7"), "{}", said);
	assert_eq!(compact(&new, &drop).status.code(), Some(2), "never over a file that is there");
	let text = std::fs::read_to_string(&new).unwrap();
	let header: Vec<&str> = text.lines().next().unwrap().split(' ').collect();
	assert_eq!(header[..2], ["arca-signer-record", "3"]);
	assert_eq!((header[4], header[5], header[6]), ("7", hex(&entries[6].1).as_str(), "7"));
	let old = std::fs::read_to_string(&record).unwrap();
	for (k, line) in text.lines().skip(1).enumerate() {
		if k < 3 {
			assert_eq!(line, format!("{} {}", k + 1, hex(&entries[k].1)), "a dropped entry keeps its running hash");
		} else {
			assert_eq!(line, old.lines().nth(1 + k).unwrap(), "carried over verbatim");
		}
	}
	assert_eq!(std::fs::metadata(&new).unwrap().permissions().mode() & 0o777, 0o600);
	std::fs::rename(&new, &record).unwrap();

	// The signer on the compacted record: the database's entry 7 is its
	// own; the rule holds for every salt carried over, and a dropped one is
	// free again.
	let run = Run::start(&dir, "compacted", genesis, &record, "exec ").unwrap();
	assert!(run.log().contains("4 message(s) in the record") && run.log().contains("its latest entry 7"), "{}", run.log());
	let e = ask(&run.socket, &rebind_line(&a, genesis, [4; 32], asset, 2, known)).await.unwrap_err();
	println!("salt 4, carried over, another message: {:?}", e);
	assert_eq!(e.0, "already_signed");
	assert_eq!(ask(&run.socket, &rebind_line(&a, genesis, [4; 32], asset, 1, known)).await.unwrap(), entries[3],
		"the same message again: its entry, read back from the file");
	let e8 = ask(&run.socket, &rebind_line(&a, genesis, [1; 32], asset, 2, known)).await.unwrap();
	println!("salt 1, dropped, another message: signed as entry {}", e8.0);
	assert_eq!(e8.0, 8);
	ask(&run.socket, &rebind_line(&a, genesis, [5; 32], asset, 1, Some(entries[4]))).await
		.expect("the database knowing a carried entry");
	let listed: serde_json::Value = serde_json::from_str(&raw(&run.socket, r#"{"op":"entries","after":0,"limit":100}"#).await).unwrap();
	let ns: Vec<u64> = listed["entries"].as_array().unwrap().iter().map(|e| e["entry"].as_u64().unwrap()).collect();
	assert_eq!(ns, vec![4, 5, 6, 7, 8]);
	let listed: serde_json::Value = serde_json::from_str(&raw(&run.socket, r#"{"op":"entries","after":6,"limit":100}"#).await).unwrap();
	assert_eq!(listed["entries"].as_array().unwrap().len(), 2);
	// The record answers the running hash at a dropped entry, and a head of
	// it signed before the compaction stops nothing.
	let w = witness(&run.socket, &[(2, entries[1].1, Some(head_sig(&s, genesis, 2, &entries[1].1)))]).await;
	println!("a head from before the compaction, entry 2: {}", w);
	assert_eq!(w["hashes"][0]["hash"], serde_json::json!(hex(&entries[1].1)), "the hash at a dropped entry");
	assert!(w["stopped"].is_null());
	ask(&run.socket, &rebind_line(&a, genesis, [6; 32], asset, 1, Some(entries[1]))).await
		.expect("the database knowing entry 2, compacted away, whose hash the record kept");
	let e = ask(&run.socket, &rebind_line(&a, genesis, [6; 32], asset, 1, Some((2, [0x22; 32])))).await.unwrap_err();
	println!("the database knowing another hash at entry 2: {:?}", e);
	assert_eq!(e.0, "record_differs");
	run.stop();

	// Started again, it reads the carried lines and the new one; a carried
	// line changed stops the start.
	let run = Run::start(&dir, "again", genesis, &record, "exec ").unwrap();
	assert!(run.log().contains("5 message(s) in the record") && run.log().contains("its latest entry 8"), "{}", run.log());
	run.stop();
	let whole = std::fs::read_to_string(&record).unwrap();
	std::fs::write(&record, whole.replacen(&hex(&[5; 32]), &hex(&[0x55; 32]), 1)).unwrap();
	let e = Run::start(&dir, "edited", genesis, &record, "exec ").err().expect("an edited carried line stops the start");
	println!("a carried line changed: {}", e);
	assert!(e.contains("do not hash to the header"), "{}", e);
	std::fs::write(&record, &whole).unwrap();

	// A compacted record compacted again goes on from its own latest entry.
	std::fs::write(&drop, format!("{}\n", hex(&[4; 32]))).unwrap();
	let out = compact(&new, &drop);
	assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
	assert!(String::from_utf8_lossy(&out.stderr).contains("4 entries carried over, 1 dropped; it goes on from entry 8"),
		"{}", String::from_utf8_lossy(&out.stderr));
	let _ = std::fs::remove_dir_all(&dir);
}

/// D49. Every head the signer hands out is signed with `S`; a head it signed
/// that its record does not hold, handed back, proves the record rolled back
/// or replaced, and stops the signer for good: it writes the proof beside
/// its record and refuses every rebindable message and every signed head,
/// across restarts, while it still signs the operator's own spends; only
/// `--clear-stopped` removes the proof. A head without `S`'s valid
/// signature, altered, of another chain, or that the record holds, stops
/// nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_head_the_signer_signed_that_its_record_does_not_hold_stops_it() {
	use server::signer::hex;
	let s = keypair("operator");
	let genesis = BlockHash::from_raw_hash(sha256d::Hash::hash(b"a chain"));
	let dir = signer_dir();
	let key = key_file(&dir, &s, 0o600);
	let record = dir.join("signer.record");
	let asset = AssetId::from_slice(&[3; 32]).unwrap();
	let a = keypair("owner");
	assert!(common::signer::create_record(&key, genesis, &record).status.success());
	let run = Run::start(&dir, "first", genesis, &record, "exec ").unwrap();

	// Every head handed out is signed: a rebind's entry, and `head`.
	let mut known = None;
	let mut entries = vec![];
	let mut snapshot = vec![];
	for k in 1..=4u8 {
		let v: serde_json::Value = serde_json::from_str(&raw(&run.socket, &rebind_line(&a, genesis, [k; 32], asset, 1, known)).await).unwrap();
		let e = (v["entry"]["entry"].as_u64().unwrap(), server::signer::unhex32(v["entry"]["hash"].as_str().unwrap()).unwrap());
		let sig = elements::secp256k1_zkp::schnorr::Signature::from_slice(&server::signer::unhex(v["entry"]["signature"].as_str().unwrap()).unwrap()).unwrap();
		assert!(verify_digest(&sig, &server::signer::record_head_digest(&genesis, e.0, &e.1), &xonly(&s)), "entry {} is signed by S", e.0);
		entries.push((e.0, e.1, sig));
		known = Some(e);
		if k == 2 {
			snapshot = std::fs::read(&record).unwrap();
		}
	}
	let head: serde_json::Value = serde_json::from_str(&raw(&run.socket, r#"{"op":"head"}"#).await).unwrap();
	println!("the head, signed: {}", head);
	assert_eq!(head["entry"]["entry"], 4);
	assert!(head["entry"]["signature"].is_string());

	// Heads that stop nothing.
	let other = keypair("not the operator");
	let other_chain = BlockHash::from_raw_hash(sha256d::Hash::hash(b"another chain"));
	let (n4, h4, sig4) = entries[3];
	let cases = [
		("unsigned, past the end", (9, [9; 32], None)),
		("signed by another key, past the end", (9, [9; 32], Some(head_sig(&other, genesis, 9, &[9; 32])))),
		("S's signature over another chain's head, past the end", (9, [9; 32], Some(head_sig(&s, other_chain, 9, &[9; 32])))),
		("entry 4's signature over another hash", (n4, [0x44; 32], Some(sig4))),
		("entry 4's signature moved to entry 9", (9, h4, Some(sig4))),
		("garbage for a signature", (9, [9; 32], Some(elements::secp256k1_zkp::schnorr::Signature::from_slice(&[1; 64]).unwrap()))),
		("entry 3, held, signed", (entries[2].0, entries[2].1, Some(entries[2].2))),
	];
	for (what, h) in cases {
		let w = witness(&run.socket, &[h]).await;
		println!("{}: hash at entry {} {} | stopped {}", what, h.0, w["hashes"][0]["hash"], w["stopped"]);
		assert!(w["stopped"].is_null(), "{} stops nothing: {}", what, w);
		assert!(w["entry"]["signature"].is_string(), "{}", w);
	}
	assert_eq!(witness(&run.socket, &[(3, [0; 32], None)]).await["hashes"][0]["hash"], serde_json::json!(hex(&entries[2].1)));
	let e5 = ask(&run.socket, &rebind_line(&a, genesis, [5; 32], asset, 1, known)).await.expect("still signing");
	known = Some(e5);
	let e5_sig = head_sig(&s, genesis, e5.0, &e5.1);
	run.stop();

	// The record rolled back to its copy at entry 2, then two entries of
	// another branch: a head of the lost branch, handed back, stops it.
	std::fs::write(&record, &snapshot).unwrap();
	let run = Run::start(&dir, "rolledback", genesis, &record, "exec ").unwrap();
	let b = keypair("another owner");
	for k in 13..=15u8 {
		ask(&run.socket, &rebind_line(&b, genesis, [k; 32], asset, 1, None)).await.unwrap();
	}
	let w = witness(&run.socket, &[(1, entries[0].1, Some(entries[0].2)), (n4, h4, Some(sig4))]).await;
	println!("the rolled-back record past entry 4 again, handed the head of entry 4 it lost: {}", w);
	assert!(w["stopped"].as_str().unwrap().contains("is not the record's"), "{}", w);
	assert!(w["entry"].is_null(), "no signed head from a stopped signer");
	assert_eq!(w["hashes"][0]["hash"], serde_json::json!(hex(&entries[0].1)));
	assert_ne!(w["hashes"][1]["hash"], serde_json::json!(hex(&h4)));
	let proof = std::fs::read_to_string(server::signer::stopped_path(&record)).expect("the proof beside the record");
	println!("the proof kept: {}", proof.trim());
	let e = ask(&run.socket, &rebind_line(&b, genesis, [16; 32], asset, 1, None)).await.unwrap_err();
	println!("a rebind after the stop: {:?}", e);
	assert_eq!(e.0, "stopped");
	let h: serde_json::Value = serde_json::from_str(&raw(&run.socket, r#"{"op":"head"}"#).await).unwrap();
	assert_eq!(h["code"], "stopped", "{}", h);
	run.stop();

	// Across a restart; the operator's own spends are still signed.
	let run = Run::start(&dir, "restarted", genesis, &record, "exec ").unwrap();
	assert!(run.log().contains("STOPPED"), "{}", run.log());
	assert_eq!(ask(&run.socket, &rebind_line(&b, genesis, [16; 32], asset, 1, None)).await.unwrap_err().0, "stopped");
	let client = SignerClient::new(&run.socket);
	let (tx, prevouts, leaf) = own_spend(&s);
	let sig = client.spend(&tx, &prevouts, 0, &leaf).await.expect("a spend of the operator's own path is still signed");
	println!("the operator's own spend, signed after the stop: {}", hex32(&sig));
	run.stop();

	// Only an explicit command removes the proof.
	let out = Command::new(env!("CARGO_BIN_EXE_arca-signer")).args(["--key-file", key.to_str().unwrap(), "--genesis", &genesis.to_string(),
		"--record", record.to_str().unwrap(), "--clear-stopped"]).output().unwrap();
	println!("--clear-stopped: {}", String::from_utf8_lossy(&out.stderr).trim());
	assert!(out.status.success());
	assert!(!server::signer::stopped_path(&record).exists());
	let run = Run::start(&dir, "cleared", genesis, &record, "exec ").unwrap();
	ask(&run.socket, &rebind_line(&b, genesis, [16; 32], asset, 1, None)).await.expect("signing again once the operator cleared it");

	// A head past the record's end, signed: a record cut back stops too.
	let w = witness(&run.socket, &[(e5.0 + 10, e5.1, Some(head_sig(&s, genesis, e5.0 + 10, &e5.1)))]).await;
	println!("a signed head past the end: stopped {}", w["stopped"]);
	assert!(w["stopped"].as_str().unwrap().contains("past the record's end"), "{}", w);
	let _ = (known, e5_sig);
	run.stop();
	let _ = std::fs::remove_dir_all(&dir);
}

/// A spend of one of the operator's own paths: a coin at a taproot output
/// whose one leaf is `<S> OP_CHECKSIG`, spent to a bare `OP_TRUE`.
fn own_spend(s: &Keypair) -> (elements::Transaction, Vec<elements::TxOut>, Script) {
	use elements::opcodes::all::OP_CHECKSIG;
	let leaf = elements::script::Builder::new().push_slice(&xonly(s).serialize()).push_opcode(OP_CHECKSIG).into_script();
	let tap = arca_covenant::TapOutput::new(vec![(0, leaf.clone())]);
	let asset = AssetId::from_slice(&[3; 32]).unwrap();
	let prev = sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(asset, 10_000), tap.script_pubkey());
	let tx = elements::Transaction {
		version: 2, lock_time: elements::LockTime::ZERO,
		input: vec![elements::TxIn { previous_output: elements::OutPoint::new(elements::Txid::all_zeros(), 0), ..Default::default() }],
		output: vec![sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(asset, 9_000), Script::from(vec![0x51])),
			sequentia_ext::fee_txout(sequentia_ext::AssetAmount::new(asset, 1_000))],
	};
	(tx, vec![prev], leaf)
}

/// A record compacted in format 2, which kept no hash for the entries it
/// dropped, is opened by this signer: it signs on from the record's latest
/// entry, refuses another message under a carried salt, answers the hash at
/// a carried entry and none at a dropped one, so a signed head of a dropped
/// entry stops nothing; a database knowing a dropped entry is refused
/// (`record_differs`, compacted away). Compacted again, it becomes format 3
/// and keeps what it had. With `ARCA_FORMAT2_SIGNER` naming a signer binary
/// that compacts in format 2, that signer makes the record and compacts it;
/// without it, this signer's compaction is written back as format 2 wrote
/// it: the carried entry lines alone, counted and hashed in the header.
#[tokio::test(flavor = "multi_thread")]
async fn a_record_compacted_in_format_2_is_read() {
	use elements::hashes::{sha256, HashEngine};
	use server::signer::hex;
	let s = keypair("operator");
	let genesis = BlockHash::from_raw_hash(sha256d::Hash::hash(b"a chain"));
	let dir = signer_dir();
	let key = key_file(&dir, &s, 0o600);
	let record = dir.join("signer.record");
	let asset = AssetId::from_slice(&[3; 32]).unwrap();
	let a = keypair("owner");
	let old = std::env::var("ARCA_FORMAT2_SIGNER").ok();
	let maker = old.clone().unwrap_or_else(|| env!("CARGO_BIN_EXE_arca-signer").to_string());
	println!("the record made and compacted by {}", maker);
	let made = Command::new(&maker)
		.args(["--key-file", key.to_str().unwrap(), "--genesis", &genesis.to_string(), "--record", record.to_str().unwrap(), "--create-record"])
		.output().unwrap();
	assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
	let run = Run::start_of(&maker, &dir, "first", genesis, &record, "exec ").unwrap();
	let mut known = None;
	let mut entries = vec![];
	for k in 1..=5u8 {
		let e = ask(&run.socket, &rebind_line(&a, genesis, [k; 32], asset, 1, known)).await.unwrap();
		entries.push(e);
		known = Some(e);
	}
	run.stop();
	let compact = |bin: &str, drop: &std::path::Path, into: &std::path::Path| Command::new(bin)
		.args(["--key-file", key.to_str().unwrap(), "--genesis", &genesis.to_string(), "--record", record.to_str().unwrap(),
			"--compact-into", into.to_str().unwrap(), "--drop-salts", drop.to_str().unwrap()])
		.output().unwrap();
	let drop = dir.join("expired.salts");
	std::fs::write(&drop, format!("{}\n{}\n", hex(&[1; 32]), hex(&[2; 32]))).unwrap();
	let new = dir.join("signer.record.new");
	let out = compact(&maker, &drop, &new);
	assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
	let text = std::fs::read_to_string(&new).unwrap();
	let v2 = match old {
		Some(_) => text,
		None => {
			let header: Vec<&str> = text.lines().next().unwrap().split(' ').collect();
			let carried: Vec<&str> = text.lines().skip(1).filter(|l| l.split(' ').count() > 2).collect();
			let mut e = sha256::Hash::engine();
			e.input(server::signer::RECORD_CARRIED_TAG);
			for l in &carried {
				e.input(l.as_bytes());
				e.input(b"\n");
			}
			format!("{} 2 {} {} {} {} {} {}\n{}\n", header[0], header[2], header[3], header[4], header[5], carried.len(),
				hex(&sha256::Hash::from_engine(e).to_byte_array()), carried.join("\n"))
		},
	};
	println!("the format-2 record:\n{}", v2.trim());
	assert!(v2.starts_with("arca-signer-record 2 ") && v2.lines().count() == 4, "{}", v2);
	std::fs::remove_file(&new).unwrap();
	std::fs::write(&record, &v2).unwrap();

	let run = Run::start(&dir, "format2", genesis, &record, "exec ").unwrap();
	println!("this signer on it: {}", run.log().trim());
	assert!(run.log().contains("3 message(s) in the record") && run.log().contains("its latest entry 5"), "{}", run.log());
	let e = ask(&run.socket, &rebind_line(&a, genesis, [4; 32], asset, 2, known)).await.unwrap_err();
	println!("salt 4, carried, another message: {:?}", e);
	assert_eq!(e.0, "already_signed");
	let w = witness(&run.socket, &[
		(4, entries[3].1, Some(head_sig(&s, genesis, 4, &entries[3].1))),
		(1, entries[0].1, Some(head_sig(&s, genesis, 1, &entries[0].1))),
	]).await;
	println!("signed heads of carried entry 4 and dropped entry 1: {}", w);
	assert_eq!(w["hashes"][0]["hash"], serde_json::json!(hex(&entries[3].1)));
	assert!(w["hashes"][1]["hash"].is_null(), "format 2 kept no hash for a dropped entry");
	assert!(w["stopped"].is_null(), "a head the record cannot tell stops nothing");
	let e6 = ask(&run.socket, &rebind_line(&a, genesis, [1; 32], asset, 2, known)).await.expect("signs on, a dropped salt free again");
	assert_eq!(e6.0, 6);
	let e = ask(&run.socket, &rebind_line(&a, genesis, [7; 32], asset, 1, Some(entries[1]))).await.unwrap_err();
	println!("the database knowing dropped entry 2: {:?}", e);
	assert_eq!(e.0, "record_differs");
	assert!(e.1.contains("compacted away"), "{}", e.1);
	run.stop();

	// Compacted again by this signer: format 3, the hash of the entry it
	// drops kept, the entries format 2 dropped still without one.
	std::fs::write(&drop, format!("{}\n", hex(&[3; 32]))).unwrap();
	let out = compact(env!("CARGO_BIN_EXE_arca-signer"), &drop, &new);
	let said = String::from_utf8_lossy(&out.stderr).to_string();
	println!("compacted again: {}", said.trim());
	assert!(said.contains("3 entries carried over, 1 dropped; it goes on from entry 6"), "{}", said);
	std::fs::rename(&new, &record).unwrap();
	let run = Run::start(&dir, "format3", genesis, &record, "exec ").unwrap();
	assert!(run.log().contains("3 message(s) in the record") && run.log().contains("its latest entry 6"), "{}", run.log());
	let w = witness(&run.socket, &[(3, entries[2].1, None), (2, entries[1].1, None), (6, e6.1, Some(head_sig(&s, genesis, 6, &e6.1)))]).await;
	println!("format 3 from format 2, entries 3, 2 and 6: {}", w);
	assert_eq!(w["hashes"][0]["hash"], serde_json::json!(hex(&entries[2].1)));
	assert!(w["hashes"][1]["hash"].is_null() && w["stopped"].is_null());
	assert_eq!(w["hashes"][2]["hash"], serde_json::json!(hex(&e6.1)));
	assert_eq!(ask(&run.socket, &rebind_line(&a, genesis, [5; 32], asset, 1, Some(e6))).await.unwrap(), entries[4]);
	run.stop();
	let _ = std::fs::remove_dir_all(&dir);
}
