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
	s.write_all(line.as_bytes()).await.unwrap();
	s.write_all(b"\n").await.unwrap();
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
		("a line over the limit", format!(r#"{{"op":"pubkey","x":"{}"}}"#, "a".repeat(20_000))),
	] {
		let answer = raw(&p.socket, &line).await;
		let v: serde_json::Value = serde_json::from_str(&answer).unwrap();
		assert!(v["error"].is_string() && v["signature"].is_null(), "{}: {}", what, answer);
		println!("refused, {}: {}", what, v["error"].as_str().unwrap());
	}
	let e = client.rebind(&[0; 32], asset, 1, &[]).await.unwrap_err();
	assert!(matches!(e, SignerError::Refused(_)), "{}", e);

	// A key file others can read is refused at start.
	let dir = signer_dir();
	let file = key_file(&dir, &s, 0o644);
	let out = Command::new(env!("CARGO_BIN_EXE_arca-signer"))
		.args(["--key-file", file.to_str().unwrap(), "--genesis", &genesis.to_string(), "--socket", dir.join("s").to_str().unwrap()])
		.output().unwrap();
	assert_eq!(out.status.code(), Some(2));
	let msg = String::from_utf8_lossy(&out.stderr);
	assert!(msg.contains("readable by others"), "{}", msg);
	println!("a key file of mode 644: {}", msg.trim());
	std::fs::remove_dir_all(&dir).unwrap();
}
