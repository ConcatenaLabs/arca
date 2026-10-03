//! `arca-signer` as its own process: it holds `S`, answers its key, signs the
//! rebindable message it builds itself for this chain, and nothing else.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use elements::hashes::{sha256d, Hash};
use elements::{AssetId, BlockHash, Script};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use arca_covenant::sign::verify_digest;
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
	let sig = client.rebind(&leaf.salt, asset, 10_000, &outs).await.unwrap();
	let msg = leaf.collab_message(asset, 10_000, &outs).unwrap();
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
	let e = client.rebind(&[0; 32], asset, 1, &[]).await.unwrap_err();
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

/// The one-spend record: one spend per salt, or forfeits one per round,
/// kept on disk across restarts, whatever asks.
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

	// A spend of salt 1, the same again, and a second spend refused.
	let first = client.rebind(&[1; 32], asset, 10_000, &[out(9_000, 1)]).await.unwrap();
	let again = client.rebind(&[1; 32], asset, 10_000, &[out(9_000, 1)]).await.unwrap();
	println!("salt 1: spend signed, and signed again when asked again ({} and {})", hex32(&first), hex32(&again));
	let e = client.rebind(&[1; 32], asset, 10_000, &[out(9_000, 2)]).await.unwrap_err();
	println!("salt 1: a second spend: {}", e);
	refused_twice(e);

	// Forfeits of salt 2: one per connector asset.
	let forfeit = |m: u8, h: u8| ForfeitPolicy {
		unlock_hash: [h; 32], owner: xonly(&keypair("owner")), operator: xonly(&s),
		refund_delay: RelativeTime::from_units(338).unwrap(), leaf_id: LeafId([2; 32]), connector: AssetId::from_slice(&[m; 32]).unwrap(),
	};
	let fout = |f: &ForfeitPolicy| ExplicitOutput::new(asset, 9_000, f.script_pubkey());
	let (f1, f1b, f2) = (forfeit(7, 1), forfeit(7, 2), forfeit(8, 1));
	client.rebind_forfeit(&[2; 32], asset, 10_000, &f1, &fout(&f1)).await.unwrap();
	client.rebind_forfeit(&[2; 32], asset, 10_000, &f1, &fout(&f1)).await.unwrap();
	let e = client.rebind_forfeit(&[2; 32], asset, 10_000, &f1b, &fout(&f1b)).await.unwrap_err();
	println!("salt 2: a second forfeit for the same round: {}", e);
	refused_twice(e);
	client.rebind_forfeit(&[2; 32], asset, 10_000, &f2, &fout(&f2)).await.unwrap();
	println!("salt 2: a forfeit for another round's connector is signed");
	let e = client.rebind(&[2; 32], asset, 10_000, &[out(9_000, 1)]).await.unwrap_err();
	println!("salt 2: a spend after its forfeits: {}", e);
	refused_twice(e);
	// A spend's salt takes no forfeit.
	let f3 = forfeit(9, 1);
	let e = client.rebind_forfeit(&[1; 32], asset, 10_000, &f3, &fout(&f3)).await.unwrap_err();
	println!("salt 1: a forfeit after its spend: {}", e);
	refused_twice(e);
	// Parts that do not make the output committed to: refused, not recorded.
	let e = client.rebind_forfeit(&[3; 32], asset, 10_000, &f3, &out(9_000, 1)).await.unwrap_err();
	assert!(matches!(e, SignerError::Refused(_)), "{}", e);
	println!("salt 3: forfeit parts that do not make the output: {}", e);
	client.rebind(&[3; 32], asset, 10_000, &[out(9_000, 3)]).await.unwrap();

	// The record outlives the process: after a restart, the same refusals.
	let lines = std::fs::read_to_string(p.record()).unwrap();
	println!("the record, {} line(s):\n{}", lines.lines().count(), lines.trim_end());
	assert_eq!(lines.lines().count(), 4, "a spend of salt 1, two forfeits of salt 2, a spend of salt 3");
	p.restart(&s, genesis);
	refused_twice(client.rebind(&[1; 32], asset, 10_000, &[out(9_000, 2)]).await.unwrap_err());
	refused_twice(client.rebind_forfeit(&[2; 32], asset, 10_000, &f1b, &fout(&f1b)).await.unwrap_err());
	client.rebind(&[1; 32], asset, 10_000, &[out(9_000, 1)]).await.unwrap();
	println!("after a restart: the same second spend and second forfeit refused; the first spend signed again");

	// A last line cut short by a crash was never answered: it is dropped.
	p.kill();
	let mut f = std::fs::OpenOptions::new().append(true).open(p.record()).unwrap();
	std::io::Write::write_all(&mut f, b"spend 0404").unwrap();
	drop(f);
	p.restart(&s, genesis);
	client.rebind(&[4; 32], asset, 10_000, &[out(9_000, 4)]).await.unwrap();
	let lines = std::fs::read_to_string(p.record()).unwrap();
	assert_eq!(lines.lines().count(), 5, "the cut line dropped, the new one whole: {}", lines);
	// Any other line that does not read stops the signer from starting.
	p.kill();
	std::fs::write(p.record(), format!("{}nonsense\n{}", lines, lines)).unwrap();
	let out = Command::new(env!("CARGO_BIN_EXE_arca-signer"))
		.args(["--key-file", p.dir.join("operator.key").to_str().unwrap(), "--genesis", &genesis.to_string(),
			"--socket", p.socket.to_str().unwrap(), "--record", p.record().to_str().unwrap()])
		.output().unwrap();
	assert_eq!(out.status.code(), Some(2));
	println!("a record with a line that does not read: {}", String::from_utf8_lossy(&out.stderr).trim());
}

fn hex32(s: &elements::secp256k1_zkp::schnorr::Signature) -> String {
	s.as_ref()[..8].iter().map(|b| format!("{:02x}", b)).collect::<String>() + "…"
}
