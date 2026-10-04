//! D52. The signer answers an entry of its record only once its signed head
//! is held outside its machine, by `arca-keeper` processes, each on a port of
//! its own as on another machine: a keeper down holds up the answer and the
//! same request completes when it is back; a restored signer is stopped at
//! start by a keeper's head; a keeper that lies is no keeper; a keeper
//! restored from an older copy catches up; with one of two keepers required,
//! one down holds nothing up, but a start needs both; and what a keeper adds
//! to a co-signature, on this machine and at 50 ms each way.

mod common;

use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use elements::hashes::{sha256d, Hash};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, BlockHash, Script};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use arca_covenant::message::rebind_message;
use arca_covenant::sign::{sign_digest, verify_digest};
use arca_covenant::{Chain, ExplicitOutput};
use common::keeper::{KeeperProcess, LineProxy};
use common::keys::{keypair, xonly};
use common::signer::{key_file, signer_dir};
use server::keeper::{ack_digest, WireAck};
use server::signer::{hex, record_head_digest, unhex, unhex32};

async fn raw(socket: &std::path::Path, line: &str) -> Value {
	let mut s = UnixStream::connect(socket).await.unwrap();
	s.write_all(line.as_bytes()).await.unwrap();
	s.write_all(b"\n").await.unwrap();
	let mut r = BufReader::new(s);
	let mut out = String::new();
	r.read_line(&mut out).await.unwrap();
	serde_json::from_str(&out).unwrap()
}

/// A rebind request line for `owner`'s leaf under `salt`, spending 10,000 of
/// `asset` into one output of 9,000.
fn rebind_line(owner: &Keypair, genesis: BlockHash, salt: [u8; 32], asset: AssetId) -> String {
	let o = ExplicitOutput::new(asset, 9_000, Script::from(vec![0x51, 1]));
	let m = rebind_message(&Chain::new(genesis).leaf_constant(&salt), asset, 10_000, std::slice::from_ref(&o)).unwrap();
	let sig = sign_digest(owner, &m.digest, &[1; 32]);
	json!({
		"op": "rebind", "owner": hex(&xonly(owner).serialize()), "owner_sig": hex(sig.as_ref()), "salt": hex(&salt),
		"asset_in": asset.to_string(), "value_in": "10000", "outputs": [server::signer::WireOutput::from_output(&o)],
	}).to_string()
}

/// A signer run by hand with keepers: its process, socket and log.
struct Signer {
	child: std::process::Child,
	dir: std::path::PathBuf,
	socket: std::path::PathBuf,
	log: std::path::PathBuf,
}

impl Signer {
	/// Starts `arca-signer` on the record in `dir` with `extra` arguments
	/// (the keepers), and waits for its socket.
	fn start(dir: &std::path::Path, name: &str, genesis: BlockHash, extra: &[String]) -> Signer {
		let socket = dir.join(format!("{}.sock", name));
		let log = dir.join(format!("{}.log", name));
		let _ = std::fs::remove_file(&socket);
		let child = Command::new(env!("CARGO_BIN_EXE_arca-signer"))
			.args(["--key-file", dir.join("operator.key").to_str().unwrap(), "--genesis", &genesis.to_string(), "--socket",
				socket.to_str().unwrap(), "--record", dir.join("signer.record").to_str().unwrap()])
			.args(extra).stderr(std::fs::File::create(&log).unwrap()).spawn().unwrap();
		let start = Instant::now();
		while !socket.exists() {
			assert!(start.elapsed() < Duration::from_secs(30), "the signer did not open its socket: {}", std::fs::read_to_string(&log).unwrap_or_default());
			std::thread::sleep(Duration::from_millis(50));
		}
		Signer { child, dir: dir.to_path_buf(), socket, log }
	}

	fn log(&self) -> String {
		std::fs::read_to_string(&self.log).unwrap_or_default()
	}

	fn stopped(&self) -> bool {
		server::signer::stopped_path(&self.dir.join("signer.record")).exists()
	}
}

impl Drop for Signer {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

fn keepers_args(list: &[String], required: Option<usize>) -> Vec<String> {
	let mut a = vec![];
	for k in list {
		a.push("--keeper".to_string());
		a.push(k.clone());
	}
	if let Some(r) = required {
		a.push("--keepers-required".into());
		a.push(r.to_string());
	}
	a.push("--keeper-timeout-ms".into());
	a.push("2000".into());
	a
}

/// Whether `v`'s `acks` hold an acknowledgement by each of `keepers` of the
/// head `v["entry"]`, under operator `s` on `genesis`.
fn acked_by(v: &Value, s: &Keypair, genesis: BlockHash, keepers: &[&Keypair]) -> bool {
	let head = &v["entry"];
	let (Some(n), Some(h)) = (head["entry"].as_u64(), head["hash"].as_str()) else { return false };
	let hash = unhex32(h).unwrap();
	let acks: Vec<WireAck> = serde_json::from_value(v["acks"].clone()).unwrap_or_default();
	keepers.iter().all(|k| acks.iter().any(|a| a.verify(&genesis, &xonly(s), &xonly(k), n, &hash)))
}

/// Whether `v`'s head is signed by `s`.
fn head_signed(v: &Value, s: &Keypair, genesis: BlockHash) -> bool {
	let head = &v["entry"];
	let (Some(n), Some(h), Some(sig)) = (head["entry"].as_u64(), head["hash"].as_str(), head["signature"].as_str()) else { return false };
	let sig = Signature::from_slice(&unhex(sig).unwrap()).unwrap();
	verify_digest(&sig, &record_head_digest(&genesis, n, &unhex32(h).unwrap()), &xonly(s))
}

struct Setup {
	s: Keypair,
	genesis: BlockHash,
	dir: std::path::PathBuf,
	asset: AssetId,
	owner: Keypair,
}

fn setup() -> Setup {
	let s = keypair("operator");
	let genesis = BlockHash::from_raw_hash(sha256d::Hash::hash(b"a chain"));
	let dir = signer_dir();
	let key = key_file(&dir, &s, 0o600);
	assert!(common::signer::create_record(&key, genesis, &dir.join("signer.record")).status.success());
	Setup { s, genesis, dir, asset: AssetId::from_slice(&[3; 32]).unwrap(), owner: keypair("owner") }
}

/// D52.1 and D52.2. With one keeper, every rebind is answered only once the
/// keeper holds its head: the answer's head carries the keeper's
/// acknowledgement, which verifies under the keeper's key, and the keeper's
/// file holds the head. With the keeper down, the signer records the entry
/// and answers `keepers_unavailable`, signing nothing; the same request again
/// completes once the keeper is back, as the same entry. `info`'s source,
/// `head`, carries the acknowledgement too, and `pubkey` names the keeper.
#[tokio::test(flavor = "multi_thread")]
async fn a_keeper_holds_every_head_before_the_signer_answers_and_one_down_holds_it_up() {
	let t = setup();
	let k = keypair("keeper one");
	let mut keeper = KeeperProcess::start(&k, xonly(&t.s), t.genesis);
	let signer = Signer::start(&t.dir, "one", t.genesis, &keepers_args(&[keeper.arg()], None));
	println!("the signer at start: {}", signer.log().trim());
	let p = raw(&signer.socket, r#"{"op":"pubkey"}"#).await;
	assert_eq!(p["keepers"], json!({"keys": [hex(&xonly(&k).serialize())], "required": 1}), "{}", p);

	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [1; 32], t.asset)).await;
	println!("a rebind with the keeper up: entry {} acks {}", v["entry"], v["acks"]);
	assert!(v["signature"].is_string() && head_signed(&v, &t.s, t.genesis));
	assert!(acked_by(&v, &t.s, t.genesis, &[&k]), "the keeper's acknowledgement of the head: {}", v);
	assert_eq!(keeper.held(), (1, Some(1)), "the keeper holds entry 1");
	// Another key's acknowledgement does not verify as the keeper's.
	assert!(!acked_by(&v, &t.s, t.genesis, &[&keypair("not the keeper")]));
	let h = raw(&signer.socket, r#"{"op":"head"}"#).await;
	assert!(acked_by(&h, &t.s, t.genesis, &[&k]), "the head handed out carries the acknowledgement: {}", h);

	// The keeper down: recorded, not answered.
	keeper.halt();
	let line = rebind_line(&t.owner, t.genesis, [2; 32], t.asset);
	let v = raw(&signer.socket, &line).await;
	println!("a rebind with the keeper down: {} | {}", v["code"], v["error"]);
	assert_eq!(v["code"], "keepers_unavailable", "{}", v);
	assert!(v["signature"].is_null(), "nothing signed");
	let record = std::fs::read_to_string(t.dir.join("signer.record")).unwrap();
	assert_eq!(record.lines().count(), 3, "the entry stays in the record");
	let h = raw(&signer.socket, r#"{"op":"head"}"#).await;
	assert!(h["acks"].is_null() && h["entry"]["entry"] == 2, "the head goes out without acknowledgements: {}", h);

	// Back: the same request completes, as the same entry.
	keeper.resume();
	let v = raw(&signer.socket, &line).await;
	println!("the same request with the keeper back: entry {} acks {:?}", v["entry"]["entry"], v["acks"].as_array().map(|a| a.len()));
	assert!(v["signature"].is_string() && acked_by(&v, &t.s, t.genesis, &[&k]), "{}", v);
	assert_eq!(v["entry"]["entry"], 2);
	assert_eq!(std::fs::read_to_string(t.dir.join("signer.record")).unwrap().lines().count(), 3, "no second entry for it");
	assert_eq!(keeper.held().1, Some(2));
	drop(signer);
	let _ = std::fs::remove_dir_all(&t.dir);
}

/// D52.2 and R7e F1 at the signer. The signer's machine is restored from a
/// snapshot: its record goes back to entry 2, while the keeper, on another
/// machine, holds entry 4. The signer started on the restored record asks
/// the keeper for its latest before it serves: entry 4, past the record's
/// end, stops it at once, the proof kept beside the record; every rebind is
/// refused `stopped`, the second spend of the lost entries included, and its
/// witness carries the keeper's head as the proof.
#[tokio::test(flavor = "multi_thread")]
async fn a_restored_signer_is_stopped_at_start_by_its_keeper() {
	let t = setup();
	let k = keypair("keeper one");
	let keeper = KeeperProcess::start(&k, xonly(&t.s), t.genesis);
	let args = keepers_args(&[keeper.arg()], None);
	let signer = Signer::start(&t.dir, "first", t.genesis, &args);
	let mut snapshot = vec![];
	for i in 1..=4u8 {
		let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [i; 32], t.asset)).await;
		assert!(v["signature"].is_string(), "{}", v);
		if i == 2 {
			snapshot = std::fs::read(t.dir.join("signer.record")).unwrap();
		}
	}
	drop(signer);
	println!("the keeper holds {:?} (heads, latest entry)", keeper.held());
	std::fs::write(t.dir.join("signer.record"), &snapshot).unwrap();
	let signer = Signer::start(&t.dir, "restored", t.genesis, &args);
	println!("the restored signer's log: {}", signer.log().trim());
	assert!(signer.stopped(), "stopped at start: {}", signer.log());
	assert!(signer.log().contains("STOPPED by a keeper's head") && signer.log().contains("past the record's end at entry 2"), "{}", signer.log());
	// The second spend of entry 3's leaf, and anything else, is refused.
	for salt in [[3u8; 32], [9u8; 32]] {
		let v = raw(&signer.socket, &rebind_line(&keypair("another owner"), t.genesis, salt, t.asset)).await;
		println!("a rebind on the restored record: {} | {}", v["code"], v["error"]);
		assert_eq!(v["code"], "stopped");
		assert!(v["signature"].is_null());
	}
	let nonce = [7u8; 32];
	let w = raw(&signer.socket, &json!({"op": "witness", "heads": [], "nonce": hex(&nonce)}).to_string()).await;
	println!("its witness: stopped {} | proof {} | end {}", w["stopped"], w["proof"]["head"]["entry"], w["end"]["entry"]);
	assert_eq!(w["proof"]["head"]["entry"], 4);
	assert_eq!(w["end"]["entry"], 2);
	drop(signer);
	let _ = std::fs::remove_dir_all(&t.dir);
}

/// D52.1. A keeper that lies is no keeper. Behind a proxy that rewrites its
/// answers: an acknowledgement signed by another key, an acknowledgement
/// replayed from an earlier request, and a latest replayed from an earlier
/// request are each refused, so the signer signs nothing. Straight to the
/// keeper, the same requests complete.
#[tokio::test(flavor = "multi_thread")]
async fn a_keeper_that_lies_is_no_keeper() {
	let t = setup();
	let k = keypair("keeper one");
	let keeper = KeeperProcess::start(&k, xonly(&t.s), t.genesis);
	let proxy = LineProxy::start(&keeper.addr, Duration::ZERO);
	let args = keepers_args(&[proxy.arg(&xonly(&k))], None);
	let signer = Signer::start(&t.dir, "through", t.genesis, &args);
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [1; 32], t.asset)).await;
	assert!(v["signature"].is_string() && acked_by(&v, &t.s, t.genesis, &[&k]), "honest through the proxy: {}", v);
	let first_ack = v["acks"][0].clone();

	// (a) An acknowledgement signed by another key.
	let other = keypair("not the keeper");
	let (s_key, genesis) = (xonly(&t.s), t.genesis);
	proxy.rewrite(Some(Arc::new(move |req: &Value, v: &mut Value| {
		if req["op"] == "hold" && !v["ack"].is_null() {
			let (n, h) = (req["head"]["entry"].as_u64().unwrap(), unhex32(req["head"]["hash"].as_str().unwrap()).unwrap());
			let nonce = unhex32(req["nonce"].as_str().unwrap()).unwrap();
			let sig = sign_digest(&other, &ack_digest(&genesis, &s_key, n, &h, &nonce), &[3; 32]);
			v["ack"]["signature"] = json!(hex(sig.as_ref()));
		}
	})));
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [2; 32], t.asset)).await;
	println!("(a) an acknowledgement signed by another key: {} | {}", v["code"], v["error"]);
	assert_eq!(v["code"], "keepers_unavailable");
	assert!(v["signature"].is_null() && v["error"].as_str().unwrap().contains("made or replayed by someone else"), "{}", v);

	// (b) The first acknowledgement replayed.
	let replay = first_ack.clone();
	proxy.rewrite(Some(Arc::new(move |req: &Value, v: &mut Value| {
		if req["op"] == "hold" && !v["ack"].is_null() {
			v["ack"] = replay.clone();
		}
	})));
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [2; 32], t.asset)).await;
	println!("(b) an earlier acknowledgement replayed: {} | {}", v["code"], v["error"]);
	assert_eq!(v["code"], "keepers_unavailable");
	assert!(v["signature"].is_null());
	drop(signer);

	// (c) An earlier latest replayed, at a start: the start check counts no
	// keeper, and the signer signs nothing.
	let latest = std::sync::Arc::new(std::sync::Mutex::new(Value::Null));
	let l2 = latest.clone();
	proxy.rewrite(Some(Arc::new(move |req: &Value, v: &mut Value| {
		if req["op"] == "latest" {
			let mut kept = l2.lock().unwrap();
			if kept.is_null() {
				*kept = v.clone();
			} else {
				*v = kept.clone();
			}
		}
	})));
	drop(Signer::start(&t.dir, "learn", t.genesis, &args));
	let signer = Signer::start(&t.dir, "replayed", t.genesis, &args);
	println!("(c) the signer's start with an earlier latest replayed: {}", signer.log().lines().filter(|l| l.contains("at start")).collect::<Vec<_>>().join(" "));
	assert!(signer.log().contains("made or replayed by someone else"), "{}", signer.log());
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [3; 32], t.asset)).await;
	println!("(c) a rebind after it: {} | {}", v["code"], v["error"]);
	assert_eq!(v["code"], "keepers_unavailable");
	assert!(v["signature"].is_null());
	assert!(!latest.lock().unwrap().is_null());
	drop(signer);

	// Straight to the keeper, the request completes.
	let signer = Signer::start(&t.dir, "straight", t.genesis, &keepers_args(&[keeper.arg()], None));
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [2; 32], t.asset)).await;
	assert!(v["signature"].is_string() && acked_by(&v, &t.s, t.genesis, &[&k]), "{}", v);
	drop(signer);
	let _ = std::fs::remove_dir_all(&t.dir);
}

/// D52.1. A keeper restored from an older copy of its heads file, while the
/// signer's record was not restored: its latest (entry 2) is a head the
/// record still holds, so it proves nothing and stops nothing, at a start or
/// in a hand-over. It takes the record's latest head, past its own, and is
/// whole again: the record never went back, and it is the record, not the
/// keeper, that refuses a second spend; the keeper only lost, for a moment,
/// heads the record still holds.
#[tokio::test(flavor = "multi_thread")]
async fn a_keeper_restored_from_an_older_copy_catches_up() {
	let t = setup();
	let k = keypair("keeper one");
	let mut keeper = KeeperProcess::start(&k, xonly(&t.s), t.genesis);
	let args = keepers_args(&[keeper.arg()], None);
	let signer = Signer::start(&t.dir, "first", t.genesis, &args);
	let mut copy = vec![];
	for i in 1..=4u8 {
		assert!(raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [i; 32], t.asset)).await["signature"].is_string());
		if i == 2 {
			copy = std::fs::read(keeper.heads()).unwrap();
		}
	}
	keeper.halt();
	std::fs::write(keeper.heads(), &copy).unwrap();
	keeper.resume();
	println!("the keeper restored from its copy holds {:?}", keeper.held());
	assert_eq!(keeper.held().1, Some(2));
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [5; 32], t.asset)).await;
	println!("the next rebind: entry {} acks {:?} | the keeper now holds {:?}", v["entry"]["entry"], v["acks"].as_array().map(|a| a.len()),
		keeper.held());
	assert!(v["signature"].is_string() && acked_by(&v, &t.s, t.genesis, &[&k]));
	assert_eq!(keeper.held().1, Some(5), "the keeper took the record's latest, past its own");
	drop(signer);
	// And a signer started while the keeper is still behind is not stopped.
	keeper.halt();
	std::fs::write(keeper.heads(), &copy).unwrap();
	keeper.resume();
	let signer = Signer::start(&t.dir, "again", t.genesis, &args);
	assert!(!signer.stopped(), "{}", signer.log());
	assert!(signer.log().contains("the keepers agree with the record"), "{}", signer.log());
	assert!(raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [6; 32], t.asset)).await["signature"].is_string());
	drop(signer);
	let _ = std::fs::remove_dir_all(&t.dir);
}

/// D52.2. Two keepers, one of them required. With both up, both
/// acknowledge; with one down, the other's acknowledgement is enough and the
/// signer answers. A start needs answers from both (any one keeper that
/// acknowledges must be among those that answered, or a signer restored
/// together with a lagging keeper would miss the other's latest), so with one
/// down at a start it signs nothing until it is back.
#[tokio::test(flavor = "multi_thread")]
async fn two_keepers_with_one_required() {
	let t = setup();
	let (k1, k2) = (keypair("keeper one"), keypair("keeper two"));
	let keeper1 = KeeperProcess::start(&k1, xonly(&t.s), t.genesis);
	let mut keeper2 = KeeperProcess::start(&k2, xonly(&t.s), t.genesis);
	let args = keepers_args(&[keeper1.arg(), keeper2.arg()], Some(1));
	let signer = Signer::start(&t.dir, "both", t.genesis, &args);
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [1; 32], t.asset)).await;
	assert!(acked_by(&v, &t.s, t.genesis, &[&k1, &k2]), "both acknowledge: {}", v);
	keeper2.halt();
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [2; 32], t.asset)).await;
	println!("one of two down, one required: signed {} | acks {}", v["signature"].is_string(), v["acks"].as_array().map(|a| a.len()).unwrap_or(0));
	assert!(v["signature"].is_string() && acked_by(&v, &t.s, t.genesis, &[&k1]) && !acked_by(&v, &t.s, t.genesis, &[&k2]));
	drop(signer);

	let signer = Signer::start(&t.dir, "restart", t.genesis, &args);
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [3; 32], t.asset)).await;
	println!("a start with one of two down: {} | {}", v["code"], v["error"]);
	assert_eq!(v["code"], "keepers_unavailable");
	assert!(v["error"].as_str().unwrap().contains("1 of the 2 keepers answered for the latest head each holds, and 2 must"), "{}", v);
	keeper2.resume();
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [3; 32], t.asset)).await;
	println!("with it back: signed {} | acks {}", v["signature"].is_string(), v["acks"].as_array().map(|a| a.len()).unwrap_or(0));
	assert!(v["signature"].is_string() && acked_by(&v, &t.s, t.genesis, &[&k1, &k2]));
	drop(signer);
	let _ = std::fs::remove_dir_all(&t.dir);
}

/// D52.2, measured. What a keeper adds to a co-signature: 40 rebinds, one
/// at a time, without a keeper, with one on this machine, and with one 50 ms
/// away each way (a proxy delaying every byte). Prints the median and the
/// slowest; asserts only that each completes.
#[tokio::test(flavor = "multi_thread")]
async fn what_a_keeper_adds_to_a_cosignature() {
	let t = setup();
	let k = keypair("keeper one");
	let keeper = KeeperProcess::start(&k, xonly(&t.s), t.genesis);
	let far = LineProxy::start(&keeper.addr, Duration::from_millis(50));
	let mut salt = 0u32;
	let mut runs = vec![];
	for (what, args) in [
		("no keeper", vec![]),
		("a keeper on this machine", keepers_args(&[keeper.arg()], None)),
		("a keeper 50 ms away each way", keepers_args(&[far.arg(&xonly(&k))], None)),
	] {
		let signer = Signer::start(&t.dir, &format!("m{}", runs.len()), t.genesis, &args);
		let mut times = vec![];
		for _ in 0..40 {
			salt += 1;
			let mut s = [0u8; 32];
			s[..4].copy_from_slice(&salt.to_le_bytes());
			let line = rebind_line(&t.owner, t.genesis, s, t.asset);
			let at = Instant::now();
			let v = raw(&signer.socket, &line).await;
			times.push(at.elapsed());
			assert!(v["signature"].is_string(), "{}: {}", what, v);
		}
		times.sort();
		println!("MEASURE {}: median {:.1} ms, slowest {:.1} ms, over {} rebinds", what, times[times.len() / 2].as_secs_f64() * 1000.0,
			times[times.len() - 1].as_secs_f64() * 1000.0, times.len());
		runs.push((what, times[times.len() / 2]));
		drop(signer);
	}
	let _ = std::fs::remove_dir_all(&t.dir);
}
