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
		let socket = dir.join(format!("{}.sock", name));
		let log = dir.join(format!("{}.log", name));
		let _ = std::fs::remove_file(&socket);
		let cmd = format!("{}{} --key-file {} --genesis {} --socket {} --record {} 2> {}", prefix, env!("CARGO_BIN_EXE_arca-signer"),
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
	assert_eq!(header[..2], ["arca-signer-record", "2"]);
	assert_eq!((header[4], header[5], header[6]), ("7", hex(&entries[6].1).as_str(), "4"));
	let old = std::fs::read_to_string(&record).unwrap();
	for (k, line) in text.lines().skip(1).enumerate() {
		assert_eq!(line, old.lines().nth(4 + k).unwrap(), "carried over verbatim");
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
	let e = ask(&run.socket, &rebind_line(&a, genesis, [6; 32], asset, 1, Some(entries[1]))).await.unwrap_err();
	println!("the database knowing entry 2, compacted away: {:?}", e);
	assert_eq!(e.0, "record_differs");
	assert!(e.1.contains("compacted away"), "{}", e.1);
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
