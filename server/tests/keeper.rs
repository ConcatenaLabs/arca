//! D52. The signer answers an entry of its record only once its signed head
//! is held outside its machine, by `arca-keeper` processes, each on a port of
//! its own as on another machine: a keeper down holds up the answer and the
//! same request completes when it is back; a restored signer is stopped at
//! start by a keeper's head, and one restored with its memory by the latest
//! head a keeper's acknowledgement names, whether its first hand-overs were
//! missed or its requests came at once; a keeper that lies is no keeper; a keeper
//! restored from an older copy, or started again empty, is a lost keeper and
//! no answer, while keepers that never held a head answer until one is
//! acknowledged; with one of two keepers required,
//! one down holds nothing up, but a start needs both; a keeper at its
//! connection bound says nothing to anyone, and tells a stranger why only
//! while it has room; and what a keeper adds to a co-signature, on this
//! machine and at 50 ms each way.

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
		Self::try_start(dir, name, genesis, extra).unwrap_or_else(|e| panic!("the signer did not start: {}", e))
	}

	/// [`Self::start`], or the signer's exit status and log when it exits
	/// before it opens its socket.
	fn try_start(dir: &std::path::Path, name: &str, genesis: BlockHash, extra: &[String]) -> Result<Signer, String> {
		let socket = dir.join(format!("{}.sock", name));
		let log = dir.join(format!("{}.log", name));
		let _ = std::fs::remove_file(&socket);
		let mut child = Command::new(env!("CARGO_BIN_EXE_arca-signer"))
			.args(["--key-file", dir.join("operator.key").to_str().unwrap(), "--genesis", &genesis.to_string(), "--socket",
				socket.to_str().unwrap(), "--record", dir.join("signer.record").to_str().unwrap()])
			.args(extra).stderr(std::fs::File::create(&log).unwrap()).spawn().unwrap();
		let start = Instant::now();
		while !socket.exists() {
			if let Some(status) = child.try_wait().unwrap() {
				return Err(format!("exit {:?}: {}", status.code(), std::fs::read_to_string(&log).unwrap_or_default().trim()));
			}
			assert!(start.elapsed() < Duration::from_secs(30), "the signer did not open its socket: {}", std::fs::read_to_string(&log).unwrap_or_default());
			std::thread::sleep(Duration::from_millis(50));
		}
		Ok(Signer { child, dir: dir.to_path_buf(), socket, log })
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

/// Where each keeper is reached, as the signer's command line says it: the
/// record names the keepers and how many are required.
fn keepers_args(list: &[String]) -> Vec<String> {
	let mut a = vec![];
	for k in list {
		a.push("--keeper".to_string());
		a.push(k.clone());
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

/// An operator whose record names the keepers `keepers`, `required` of them
/// to hold every head (none: a record without keepers).
fn setup(keepers: &[&Keypair], required: usize) -> Setup {
	let s = keypair("operator");
	let genesis = BlockHash::from_raw_hash(sha256d::Hash::hash(b"a chain"));
	let dir = signer_dir();
	let key = key_file(&dir, &s, 0o600);
	let made = match keepers {
		[] => common::signer::create_record(&key, genesis, &dir.join("signer.record")),
		k => common::signer::create_record_kept(&key, genesis, &dir.join("signer.record"), &k.iter().map(|k| xonly(k)).collect::<Vec<_>>(),
			required),
	};
	assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
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
	let k = keypair("keeper one");
	let t = setup(&[&k], 1);
	let mut keeper = KeeperProcess::start(&k, xonly(&t.s), t.genesis);
	let signer = Signer::start(&t.dir, "one", t.genesis, &keepers_args(&[keeper.arg()]));
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
	let k = keypair("keeper one");
	let t = setup(&[&k], 1);
	let keeper = KeeperProcess::start(&k, xonly(&t.s), t.genesis);
	let args = keepers_args(&[keeper.arg()]);
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
/// replayed from an earlier request, an acknowledgement that does not say
/// the latest head the keeper held or hides it, and a latest replayed from
/// an earlier request are each refused, so the signer signs nothing.
/// Straight to the keeper, the same requests complete.
#[tokio::test(flavor = "multi_thread")]
async fn a_keeper_that_lies_is_no_keeper() {
	let k = keypair("keeper one");
	let t = setup(&[&k], 1);
	let keeper = KeeperProcess::start(&k, xonly(&t.s), t.genesis);
	let proxy = LineProxy::start(&keeper.addr, Duration::ZERO);
	let args = keepers_args(&[proxy.arg(&xonly(&k))]);
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

	// (d) An acknowledgement that does not say the latest head the keeper
	// held (as from a keeper older than the signer), and (e) one whose
	// latest is hidden (`null`, "it held none"): neither counts.
	proxy.rewrite(Some(Arc::new(|req: &Value, v: &mut Value| {
		if req["op"] == "hold" && !v["ack"].is_null() {
			v.as_object_mut().unwrap().remove("latest");
		}
	})));
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [2; 32], t.asset)).await;
	println!("(d) an acknowledgement without the keeper's latest: {} | {}", v["code"], v["error"]);
	assert_eq!(v["code"], "keepers_unavailable");
	assert!(v["signature"].is_null() && v["error"].as_str().unwrap().contains("does not say the latest head the keeper held"), "{}", v);
	proxy.rewrite(Some(Arc::new(|req: &Value, v: &mut Value| {
		if req["op"] == "hold" && !v["ack"].is_null() {
			v["latest"] = Value::Null;
		}
	})));
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [2; 32], t.asset)).await;
	println!("(e) an acknowledgement whose latest is hidden: {} | {}", v["code"], v["error"]);
	assert_eq!(v["code"], "keepers_unavailable");
	assert!(v["signature"].is_null() && v["error"].as_str().unwrap().contains("made or replayed by someone else"), "{}", v);
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
	let signer = Signer::start(&t.dir, "straight", t.genesis, &keepers_args(&[keeper.arg()]));
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [2; 32], t.asset)).await;
	assert!(v["signature"].is_string() && acked_by(&v, &t.s, t.genesis, &[&k]), "{}", v);
	drop(signer);
	let _ = std::fs::remove_dir_all(&t.dir);
}

/// R7g F3. A keeper whose heads file is restored from an older copy, or made
/// again empty under its key, while the signer runs, is a lost keeper: it no
/// longer holds what it acknowledged, so it is no longer part of what makes a
/// head held outside the signer's machine. The signer saw it hold entry 4;
/// when it names a latest below that (entry 2), or none, the signer counts it
/// no more while it runs and says why, and with it the record's only keeper,
/// signs nothing. Nothing stops: the record is whole. The keeper still takes
/// the heads it is handed.
#[tokio::test(flavor = "multi_thread")]
async fn a_keeper_restored_from_an_older_copy_or_emptied_is_a_lost_keeper() {
	for emptied in [false, true] {
		let k = keypair("keeper one");
		let t = setup(&[&k], 1);
		let mut keeper = KeeperProcess::start(&k, xonly(&t.s), t.genesis);
		let args = keepers_args(&[keeper.arg()]);
		let signer = Signer::start(&t.dir, "first", t.genesis, &args);
		let mut copy = vec![];
		for i in 1..=4u8 {
			assert!(raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [i; 32], t.asset)).await["signature"].is_string());
			if i == 2 {
				copy = std::fs::read(keeper.heads()).unwrap();
			}
		}
		keeper.halt();
		if emptied {
			std::fs::remove_file(keeper.heads()).unwrap();
			let made = Command::new(env!("CARGO_BIN_EXE_arca-keeper"))
				.args(["--key-file", keeper.dir.join("keeper.key").to_str().unwrap(), "--operator", &hex(&xonly(&t.s).serialize()),
					"--genesis", &t.genesis.to_string(), "--heads", keeper.heads().to_str().unwrap(), "--create"]).output().unwrap();
			assert!(made.status.success());
		} else {
			std::fs::write(keeper.heads(), &copy).unwrap();
		}
		keeper.resume();
		let what = if emptied { "made again empty" } else { "restored from its copy at entry 2" };
		println!("the keeper's heads file {}: it holds {:?}", what, keeper.held());
		for salt in [5u8, 6] {
			let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [salt; 32], t.asset)).await;
			println!("a rebind after it ({}): signed {} | {} | {}", what, v["signature"].is_string(), v["code"],
				v["error"].as_str().unwrap_or(""));
			assert_eq!(v["code"], "keepers_unavailable", "{}", v);
			assert!(v["signature"].is_null());
			let e = v["error"].as_str().unwrap();
			assert!(e.contains("0 of the 1 keepers acknowledged") && e.contains("a lost keeper"), "{}", e);
			assert!(e.contains(if emptied { "holds no head" } else { "entry 2, below entry" }), "{}", e);
		}
		assert!(!signer.stopped(), "the record is whole: nothing stops");
		assert!(signer.log().contains("a lost keeper"), "{}", signer.log());
		println!("the keeper took the heads all the same: {:?}", keeper.held());
		drop(signer);
		let _ = std::fs::remove_dir_all(&t.dir);
	}
}

/// R7g F3, KB turned around. Two of three keepers. Entry 1 is held by all
/// three; a copy of the record is taken; keeper 2 is down while entries 2
/// and 3 are signed (keepers 0 and 1 hold 3). Then the signer's machine is
/// restored from the copy, keeper 0's heads file is made again empty under
/// its key (its machine lost, its key kept), keeper 1 is unreachable and
/// keeper 2 is back at entry 1. A keeper that holds nothing, once a head of
/// the record has been acknowledged, has not answered: the start check has
/// one answer of the two it needs, the restored signer signs nothing, and
/// the second spend of entry 2's leaf is refused. Once keeper 1 answers, its
/// entry 3, past the record's end, stops the signer.
#[tokio::test(flavor = "multi_thread")]
async fn a_keeper_started_empty_under_its_key_is_no_answer() {
	let (k0, k1, k2) = (keypair("keeper zero"), keypair("keeper one"), keypair("keeper two"));
	let t = setup(&[&k0, &k1, &k2], 2);
	let mut keeper0 = KeeperProcess::start(&k0, xonly(&t.s), t.genesis);
	let mut keeper1 = KeeperProcess::start(&k1, xonly(&t.s), t.genesis);
	let mut keeper2 = KeeperProcess::start(&k2, xonly(&t.s), t.genesis);
	let args = keepers_args(&[keeper0.arg(), keeper1.arg(), keeper2.arg()]);
	let record = t.dir.join("signer.record");
	let signer = Signer::start(&t.dir, "first", t.genesis, &args);
	let v = raw(&signer.socket, &rebind_into(&t.owner, t.genesis, [1; 32], t.asset, 9_000)).await;
	assert!(acked_by(&v, &t.s, t.genesis, &[&k0, &k1, &k2]), "{}", v);
	let snapshot = std::fs::read(&record).unwrap();
	keeper2.halt();
	for i in 2..=3u8 {
		let v = raw(&signer.socket, &rebind_into(&t.owner, t.genesis, [i; 32], t.asset, 9_000)).await;
		assert!(v["signature"].is_string() && acked_by(&v, &t.s, t.genesis, &[&k0, &k1]), "{}", v);
	}
	drop(signer);
	println!("before: keeper 0 holds {:?}, keeper 1 {:?}, keeper 2 {:?}", keeper0.held(), keeper1.held(), keeper2.held());
	// The restore, with whatever beside the record the copy holds.
	std::fs::write(&record, &snapshot).unwrap();
	keeper0.halt();
	std::fs::remove_file(keeper0.heads()).unwrap();
	let made = Command::new(env!("CARGO_BIN_EXE_arca-keeper"))
		.args(["--key-file", keeper0.dir.join("keeper.key").to_str().unwrap(), "--operator", &hex(&xonly(&t.s).serialize()),
			"--genesis", &t.genesis.to_string(), "--heads", keeper0.heads().to_str().unwrap(), "--create"]).output().unwrap();
	assert!(made.status.success());
	keeper0.resume();
	keeper1.halt();
	keeper2.resume();
	println!("at the restore: keeper 0 holds {:?} (made again empty), keeper 1 down, keeper 2 holds {:?}", keeper0.held(), keeper2.held());
	let signer = Signer::start(&t.dir, "restored", t.genesis, &args);
	let start = signer.log().lines().filter(|l| l.contains("at start")).collect::<Vec<_>>().join(" / ");
	println!("the restored signer at start: {}", start);
	assert!(!signer.log().contains("the keepers agree with the record"), "{}", signer.log());
	assert!(start.contains("1 of the 3 keepers answered") && start.contains("holds no head") && start.contains("a lost keeper"), "{}", start);
	for salt in [2u8, 9] {
		let v = raw(&signer.socket, &rebind_into(&t.owner, t.genesis, [salt; 32], t.asset, 8_000)).await;
		println!("a rebind under salt {} on the restored record: signed {} | {} | {}", salt, v["signature"].is_string(), v["code"],
			v["error"].as_str().unwrap_or(""));
		assert_eq!(v["code"], "keepers_unavailable", "{}", v);
		assert!(v["signature"].is_null());
	}
	assert_eq!(keeper0.held().1, None, "nothing was handed to the keeper made again empty");
	keeper1.resume();
	let v = raw(&signer.socket, &rebind_into(&t.owner, t.genesis, [2; 32], t.asset, 8_000)).await;
	println!("with keeper 1 back: signed {} | {} | stopped {}", v["signature"].is_string(), v["code"], signer.stopped());
	assert_eq!(v["code"], "stopped", "{}", v);
	assert!(signer.stopped());
	drop(signer);
	let _ = std::fs::remove_dir_all(&t.dir);
}

/// R7g F3, the other side. Before any head of the record has been
/// acknowledged by as many keepers as it requires, a keeper's "no head" is
/// an answer: the keepers of a new operator have never held one. Two of
/// three keepers: the first request is recorded while two keepers are down
/// (keeper 0 alone takes the head, which is not enough), and the signer is
/// started again with every keeper up. Keepers 1 and 2 hold nothing and
/// count, the start check passes and the same request completes. Once a
/// head has been acknowledged, a keeper with no head no longer counts at a
/// start: the record says so beside it (`<record>.acknowledged`), and the
/// next start with keeper 2 emptied needs keepers 0 and 1.
#[tokio::test(flavor = "multi_thread")]
async fn keepers_that_never_held_a_head_answer_until_one_is_acknowledged() {
	let (k0, k1, k2) = (keypair("keeper zero"), keypair("keeper one"), keypair("keeper two"));
	let t = setup(&[&k0, &k1, &k2], 2);
	let keeper0 = KeeperProcess::start(&k0, xonly(&t.s), t.genesis);
	let mut keeper1 = KeeperProcess::start(&k1, xonly(&t.s), t.genesis);
	let mut keeper2 = KeeperProcess::start(&k2, xonly(&t.s), t.genesis);
	let args = keepers_args(&[keeper0.arg(), keeper1.arg(), keeper2.arg()]);
	let marker = server::signer::acknowledged_path(&t.dir.join("signer.record"));
	let signer = Signer::start(&t.dir, "new", t.genesis, &args);
	keeper1.halt();
	keeper2.halt();
	let line = rebind_into(&t.owner, t.genesis, [1; 32], t.asset, 9_000);
	let v = raw(&signer.socket, &line).await;
	println!("the first request, keepers 1 and 2 down: {} | {}", v["code"], v["error"]);
	assert_eq!(v["code"], "keepers_unavailable");
	assert_eq!(keeper0.held().1, Some(1));
	assert!(!marker.exists(), "no head acknowledged yet");
	drop(signer);
	keeper1.resume();
	keeper2.resume();
	let signer = Signer::start(&t.dir, "again", t.genesis, &args);
	println!("started again: {}", signer.log().lines().filter(|l| l.contains("keepers agree") || l.contains("at start")).collect::<Vec<_>>()
		.join(" / "));
	assert!(signer.log().contains("the keepers agree with the record"), "{}", signer.log());
	let v = raw(&signer.socket, &line).await;
	println!("the same request: signed {} | entry {} | acked by all three {}", v["signature"].is_string(), v["entry"]["entry"],
		acked_by(&v, &t.s, t.genesis, &[&k0, &k1, &k2]));
	assert!(v["signature"].is_string() && v["entry"]["entry"] == 1 && acked_by(&v, &t.s, t.genesis, &[&k0, &k1, &k2]), "{}", v);
	let said = std::fs::read_to_string(&marker).unwrap_or_default();
	println!("beside the record: {}", said.trim());
	assert!(said.starts_with("entry 1 "), "{}", said);
	drop(signer);
	// Keeper 2 made again empty: no answer now. With keeper 1 down too, the
	// start waits; with keeper 1 back, keepers 0 and 1 are enough.
	keeper2.halt();
	std::fs::remove_file(keeper2.heads()).unwrap();
	let made = Command::new(env!("CARGO_BIN_EXE_arca-keeper"))
		.args(["--key-file", keeper2.dir.join("keeper.key").to_str().unwrap(), "--operator", &hex(&xonly(&t.s).serialize()),
			"--genesis", &t.genesis.to_string(), "--heads", keeper2.heads().to_str().unwrap(), "--create"]).output().unwrap();
	assert!(made.status.success());
	keeper2.resume();
	keeper1.halt();
	let signer = Signer::start(&t.dir, "emptied", t.genesis, &args);
	let v = raw(&signer.socket, &rebind_into(&t.owner, t.genesis, [2; 32], t.asset, 9_000)).await;
	println!("keeper 2 emptied, keeper 1 down: {} | {}", v["code"], v["error"]);
	assert_eq!(v["code"], "keepers_unavailable");
	assert!(v["error"].as_str().unwrap().contains("1 of the 3 keepers answered"), "{}", v);
	keeper1.resume();
	let v = raw(&signer.socket, &rebind_into(&t.owner, t.genesis, [2; 32], t.asset, 9_000)).await;
	println!("keeper 1 back: signed {} | acked by keepers 0 and 1 {}", v["signature"].is_string(), acked_by(&v, &t.s, t.genesis, &[&k0, &k1]));
	assert!(v["signature"].is_string() && acked_by(&v, &t.s, t.genesis, &[&k0, &k1]) && !acked_by(&v, &t.s, t.genesis, &[&k2]), "{}", v);
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
	let (k1, k2) = (keypair("keeper one"), keypair("keeper two"));
	let t = setup(&[&k1, &k2], 1);
	let keeper1 = KeeperProcess::start(&k1, xonly(&t.s), t.genesis);
	let mut keeper2 = KeeperProcess::start(&k2, xonly(&t.s), t.genesis);
	let args = keepers_args(&[keeper1.arg(), keeper2.arg()]);
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
	let k = keypair("keeper one");
	let t = setup(&[&k], 1);
	let keeper = KeeperProcess::start(&k, xonly(&t.s), t.genesis);
	let far = LineProxy::start(&keeper.addr, Duration::from_millis(50));
	let mut salt = 0u32;
	let mut runs = vec![];
	// The record names its keepers for good: the run without one is on a
	// record of its own.
	let alone = setup(&[], 0);
	for (what, dir, args) in [
		("no keeper", &alone.dir, vec![]),
		("a keeper on this machine", &t.dir, keepers_args(&[keeper.arg()])),
		("a keeper 50 ms away each way", &t.dir, keepers_args(&[far.arg(&xonly(&k))])),
	] {
		let signer = Signer::start(dir, &format!("m{}", runs.len()), t.genesis, &args);
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
	let _ = std::fs::remove_dir_all(&alone.dir);
}

/// D55 (R7f F1 to F3 at the signer). The keepers are part of the operator's
/// identity, fixed when its record is made: the record's first line names
/// them and how many must hold a head, and the signer serves only with that
/// set. The command line says only where each keeper is reached: with no
/// address for a keeper the record names (a start that lost `--keeper`, as a
/// restored start script would), with a keeper the record does not name (a
/// keeper replaced, R7f's K2 and K2b), or with `--keepers-required` of its
/// own, the signer refuses to start and says why. A record made without
/// keepers, or of format 1, refuses `--keeper`: it never gains any. The
/// first line is under the running hash, so a hand-edited set does not
/// open; a compacted record carries the set over, under its carried hash.
/// The command that makes a record takes the set, or `--no-keepers`, and
/// nothing less.
#[tokio::test(flavor = "multi_thread")]
async fn the_record_names_its_keepers_and_the_signer_serves_only_with_them() {
	use server::signer::record_header;
	let (k1, k2, k3) = (keypair("keeper one"), keypair("keeper two"), keypair("keeper three"));
	let t = setup(&[&k1, &k2], 2);
	let record = t.dir.join("signer.record");
	let first = std::fs::read_to_string(&record).unwrap();
	println!("the record's first line: {}", first.trim());
	assert_eq!(first.trim(), format!("arca-signer-record 4 {} {} keepers=2:{},{}", hex(&xonly(&t.s).serialize()), t.genesis,
		hex(&xonly(&k1).serialize()), hex(&xonly(&k2).serialize())));
	let keeper1 = KeeperProcess::start(&k1, xonly(&t.s), t.genesis);
	let keeper2 = KeeperProcess::start(&k2, xonly(&t.s), t.genesis);
	let keeper3 = KeeperProcess::start(&k3, xonly(&t.s), t.genesis);
	let (h1, h2, h3) = (hex(&xonly(&k1).serialize()), hex(&xonly(&k2).serialize()), hex(&xonly(&k3).serialize()));

	let refused = |name: &str, args: &[String]| -> String {
		let e = Signer::try_start(&t.dir, name, t.genesis, args).err().unwrap_or_else(|| panic!("{}: the signer started", name));
		println!("{}: {}", name, e.lines().last().unwrap_or(""));
		assert!(e.starts_with("exit Some(2)"), "{}", e);
		e
	};
	// A start that lost --keeper: every key without an address is named.
	let e = refused("no --keeper", &keepers_args(&[]));
	assert!(e.contains(&format!("the record's keeper {} has no address", h1)) && e.contains(&format!("the record's keeper {} has no address", h2)), "{}", e);
	let e = refused("one of the two", &keepers_args(&[keeper1.arg()]));
	assert!(e.contains(&format!("the record's keeper {} has no address", h2)) && !e.contains(&format!("keeper {} has no address", h1)), "{}", e);
	// K2 and K2b: a keeper replaced by another key.
	let e = refused("keeper two replaced by three", &keepers_args(&[keeper1.arg(), keeper3.arg()]));
	assert!(e.contains(&format!("={}: that key is not one of the record's keepers", h3)), "{}", e);
	assert!(e.contains(&format!("the record's keeper {} has no address", h2)), "{}", e);
	let e = refused("a third keeper beside the two", &keepers_args(&[keeper1.arg(), keeper2.arg(), keeper3.arg()]));
	assert!(e.contains(&format!("={}: that key is not one of the record's keepers", h3)) && !e.contains("has no address"), "{}", e);
	let mut fewer = keepers_args(&[keeper1.arg(), keeper2.arg()]);
	fewer.extend(["--keepers-required".to_string(), "1".to_string()]);
	let e = refused("fewer required than the record", &fewer);
	assert!(e.contains("--keepers-required is the record's"), "{}", e);
	assert!(!server::signer::stopped_path(&record).exists());

	// With every keeper the record names, it serves, and names them.
	let signer = Signer::start(&t.dir, "both", t.genesis, &keepers_args(&[keeper2.arg(), keeper1.arg()]));
	let p = raw(&signer.socket, r#"{"op":"pubkey"}"#).await;
	println!("with both: pubkey's keepers {}", p["keepers"]);
	assert_eq!(p["keepers"], json!({"keys": [h1, h2], "required": 2}));
	for i in 1..=3u8 {
		let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [i; 32], t.asset)).await;
		assert!(v["signature"].is_string() && acked_by(&v, &t.s, t.genesis, &[&k1, &k2]), "{}", v);
	}
	drop(signer);

	// The first line is under the running hash: the set edited out of a
	// record with entries does not open.
	let whole = std::fs::read_to_string(&record).unwrap();
	let edited = whole.replacen(&format!("keepers=2:{},{}", h1, h2), "keepers=none", 1);
	std::fs::write(&record, &edited).unwrap();
	let e = refused("the keepers edited out of the first line", &keepers_args(&[]));
	assert!(e.contains("line 2"), "{}", e);
	std::fs::write(&record, &whole).unwrap();

	// Compacted, the set goes over, and stays the record's.
	let key = t.dir.join("operator.key");
	let drop_file = t.dir.join("expired.salts");
	std::fs::write(&drop_file, format!("{}\n", hex(&[1; 32]))).unwrap();
	let compacted = t.dir.join("signer.record.new");
	let out = Command::new(env!("CARGO_BIN_EXE_arca-signer"))
		.args(["--key-file", key.to_str().unwrap(), "--genesis", &t.genesis.to_string(), "--record", record.to_str().unwrap(),
			"--compact-into", compacted.to_str().unwrap(), "--drop-salts", drop_file.to_str().unwrap()])
		.output().unwrap();
	assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
	let text = std::fs::read_to_string(&compacted).unwrap();
	let header = text.lines().next().unwrap().to_string();
	println!("the compacted record's first line: {}", header);
	// What the keepers acknowledged goes over with it.
	let said = std::fs::read_to_string(server::signer::acknowledged_path(&compacted)).unwrap();
	assert_eq!(said, std::fs::read_to_string(server::signer::acknowledged_path(&record)).unwrap());
	// So does what the signer saw each keeper hold.
	let seen = server::signer::read_keepers_seen(&compacted).unwrap();
	println!("what the signer saw its keepers hold, carried over: {:?}", seen);
	assert!(seen.len() == 2 && seen == server::signer::read_keepers_seen(&record).unwrap(), "{:?}", seen);
	assert!(header.starts_with(&format!("arca-signer-record 4 {} {} keepers=2:{},{} 3 ", hex(&xonly(&t.s).serialize()), t.genesis, h1, h2)),
		"{}", header);
	std::fs::write(&record, text.replacen(&format!("keepers=2:{},{}", h1, h2), &format!("keepers=1:{}", h1), 1)).unwrap();
	let e = refused("a compacted record's keepers edited", &keepers_args(&[keeper1.arg()]));
	assert!(e.contains("the carried lines do not hash to the header's"), "{}", e);
	std::fs::rename(&compacted, &record).unwrap();
	let e = refused("the compacted record started without --keeper", &keepers_args(&[]));
	assert!(e.contains("has no address"), "{}", e);
	let signer = Signer::start(&t.dir, "compacted", t.genesis, &keepers_args(&[keeper1.arg(), keeper2.arg()]));
	assert_eq!(raw(&signer.socket, r#"{"op":"pubkey"}"#).await["keepers"], json!({"keys": [h1, h2], "required": 2}));
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [4; 32], t.asset)).await;
	assert!(v["signature"].is_string() && v["entry"]["entry"] == 4 && acked_by(&v, &t.s, t.genesis, &[&k1, &k2]), "{}", v);
	drop(signer);

	// A record made without keepers never gains any.
	let none = setup(&[], 0);
	let line = std::fs::read_to_string(none.dir.join("signer.record")).unwrap();
	println!("a record without keepers: {}", line.trim());
	assert!(line.trim().ends_with(" keepers=none"), "{}", line);
	let e = Signer::try_start(&none.dir, "gains one", none.genesis, &keepers_args(&[keeper1.arg()])).err().expect("refused");
	println!("--keeper on a record without keepers: {}", e.lines().last().unwrap_or(""));
	assert!(e.starts_with("exit Some(2)") && e.contains("the record was made without keepers, as its first line says, and never gains any"), "{}", e);
	let signer = Signer::start(&none.dir, "alone", none.genesis, &[]);
	assert_eq!(raw(&signer.socket, r#"{"op":"pubkey"}"#).await["keepers"], json!({"keys": [], "required": 0}));
	assert!(signer.log().contains("the record names no keeper"), "{}", signer.log());
	drop(signer);
	// A record of format 1, made before records named keepers, is one
	// without keepers.
	std::fs::write(none.dir.join("signer.record"), format!("{}\n", record_header(&xonly(&none.s), &none.genesis))).unwrap();
	let e = Signer::try_start(&none.dir, "format 1 gains one", none.genesis, &keepers_args(&[keeper1.arg()])).err().expect("refused");
	println!("--keeper on a record of format 1: {}", e.lines().last().unwrap_or(""));
	assert!(e.contains("never gains any"), "{}", e);
	drop(Signer::start(&none.dir, "format 1", none.genesis, &[]));

	// The command that makes a record takes the set, or --no-keepers.
	let make = |args: &[&str]| {
		let fresh = signer_dir();
		let key = key_file(&fresh, &t.s, 0o600);
		let out = common::signer::create_record_with(&key, t.genesis, &fresh.join("signer.record"),
			&args.iter().map(|a| a.to_string()).collect::<Vec<_>>());
		let made = fresh.join("signer.record").exists();
		let _ = std::fs::remove_dir_all(&fresh);
		(out.status.code(), String::from_utf8_lossy(&out.stderr).trim().to_string(), made)
	};
	for (args, want) in [
		(vec![], "--create-record needs the record's keepers"),
		(vec!["--keeper-key", &h1], "--keeper-key needs --keepers-required"),
		(vec!["--keeper-key", &h1, "--keepers-required", "2"], "2 keepers required: from 1 to the 1 keepers named"),
		(vec!["--keeper-key", &h1, "--keeper-key", &h1, "--keepers-required", "1"], "a keeper's key named twice"),
		(vec!["--no-keepers", "--keeper-key", &h1], "--no-keepers names no keeper"),
		(vec!["--keeper", &keeper1.arg(), "--keepers-required", "1"], "--create-record takes each keeper's key"),
	] {
		let (code, said, made) = make(&args);
		println!("--create-record {:?}: {}", args, said);
		assert_eq!(code, Some(2), "{}", said);
		assert!(said.contains(want) && !made, "{}", said);
	}
	let (code, said, made) = make(&["--keeper-key", &h1, "--keeper-key", &h2, "--keeper-key", &h3, "--keepers-required", "2"]);
	println!("--create-record two of three: {}", said);
	assert!(code == Some(0) && made && said.contains(&format!("its keepers 2 of {}, {}, {}", h1, h2, h3)), "{}", said);
	let _ = std::fs::remove_dir_all(&t.dir);
	let _ = std::fs::remove_dir_all(&none.dir);
}

/// Asks the keeper at `addr` for its latest head on a fresh connection,
/// within `wait`: its answer, or `None`.
async fn ask_latest(addr: &str, wait: Duration) -> Option<Value> {
	tokio::time::timeout(wait, async {
		let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
		s.write_all(format!("{{\"op\":\"latest\",\"nonce\":\"{}\"}}\n", hex(&[9; 32])).as_bytes()).await.ok()?;
		let mut r = BufReader::new(s);
		let mut out = String::new();
		r.read_line(&mut out).await.ok()?;
		serde_json::from_str(&out).ok()
	}).await.ok().flatten()
}

/// Whether the keeper closed connection `s` within `wait`.
async fn closed(s: &mut tokio::net::TcpStream, wait: Duration) -> bool {
	use tokio::io::AsyncReadExt;
	let mut b = [0u8; 64];
	matches!(tokio::time::timeout(wait, s.read(&mut b)).await, Ok(Ok(0)) | Ok(Err(_)))
}

/// The keeper process's CPU time, user and system, in clock ticks.
fn cpu_ticks(pid: u32) -> u64 {
	let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).unwrap();
	let f: Vec<&str> = stat.rsplit_once(") ").unwrap().1.split(' ').collect();
	f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
}

/// R7f F8 turned around. A keeper is reached from the signer alone, and a
/// flood of connections neither stops it nor fills its log. With its open
/// descriptors limited to 32: (a) 300 connections from an address `--allow`
/// does not name are each closed at once, one line in its log says so, and
/// the signer's co-signature goes through meanwhile; (b) 40 idle
/// connections from the signer's own address: at most `--max-connections`
/// (8) stay open, the rest closed at once, and once they have been idle for
/// `--idle-timeout-ms` they are closed too and the next co-signature goes
/// through; (c) a keeper allowed more connections than it has descriptors,
/// 100 opened to it: its accept fails, it waits before trying again and
/// says so a few times rather than in a loop, and answers again once the
/// idle ones are closed.
#[tokio::test(flavor = "multi_thread")]
async fn a_keeper_admits_its_signer_alone_and_holds_up_under_a_flood() {
	let k = keypair("keeper one");
	let t = setup(&[&k], 1);
	let listen = |max: &str| ["--allow", "127.0.0.1", "--max-connections", max, "--idle-timeout-ms", "1500"].iter().map(|a| a.to_string())
		.collect::<Vec<_>>();
	let keeper = KeeperProcess::start_with(&k, xonly(&t.s), t.genesis, listen("8"), Some(32));
	let signer = Signer::start(&t.dir, "flooded", t.genesis, &keepers_args(&[keeper.arg()]));
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [1; 32], t.asset)).await;
	assert!(v["signature"].is_string() && acked_by(&v, &t.s, t.genesis, &[&k]), "{}", v);

	// (a) From an address --allow does not name.
	let addr: std::net::SocketAddr = keeper.addr.parse().unwrap();
	let mut outsiders = vec![];
	for _ in 0..300 {
		let sock = tokio::net::TcpSocket::new_v4().unwrap();
		sock.bind("127.0.0.2:0".parse().unwrap()).unwrap();
		if let Ok(s) = sock.connect(addr).await {
			outsiders.push(s);
		}
	}
	let mut shut = 0;
	for s in &mut outsiders {
		shut += closed(s, Duration::from_secs(2)).await as usize;
	}
	let refused_lines = keeper.log().lines().filter(|l| l.contains("refused a connection from 127.0.0.2")).count();
	println!("(a) {} connections from 127.0.0.2, {} closed at once by the keeper; {} line(s) in its log", outsiders.len(), shut, refused_lines);
	assert_eq!((outsiders.len(), shut), (300, 300));
	assert!(refused_lines <= 2, "{}", keeper.log());
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [2; 32], t.asset)).await;
	println!("(a) a co-signature meanwhile: signed {} | acks {}", v["signature"].is_string(), v["acks"].as_array().map(|a| a.len()).unwrap_or(0));
	assert!(v["signature"].is_string() && acked_by(&v, &t.s, t.genesis, &[&k]), "{}", v);
	drop(outsiders);

	// (b) Idle connections from the signer's own address.
	let mut idle = vec![];
	for _ in 0..40 {
		idle.push(tokio::net::TcpStream::connect(addr).await.unwrap());
	}
	// Every connection looked at together, for 300 ms.
	let mut looked = tokio::task::JoinSet::new();
	for mut s in idle {
		looked.spawn(async move {
			let c = closed(&mut s, Duration::from_millis(300)).await;
			(s, c)
		});
	}
	let mut idle = vec![];
	let mut shut = 0;
	while let Some(Ok((s, c))) = looked.join_next().await {
		shut += c as usize;
		idle.push(s);
	}
	println!("(b) 40 idle connections from 127.0.0.1: {} closed at once, {} held (the signer's own included in the bound of 8)", shut, 40 - shut);
	assert!(shut >= 32, "{} closed", shut);
	tokio::time::sleep(Duration::from_millis(2500)).await;
	let mut later = 0;
	for s in &mut idle {
		later += closed(s, Duration::from_millis(100)).await as usize;
	}
	println!("(b) after 1.5 s idle: {} of 40 closed", later);
	assert_eq!(later, 40);
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [3; 32], t.asset)).await;
	println!("(b) the next co-signature: signed {} | acks {}", v["signature"].is_string(), v["acks"].as_array().map(|a| a.len()).unwrap_or(0));
	assert!(v["signature"].is_string() && acked_by(&v, &t.s, t.genesis, &[&k]), "{}", v);
	drop(idle);
	drop(signer);

	// (c) More connections than descriptors.
	let k2 = keypair("keeper two");
	let keeper2 = KeeperProcess::start_with(&k2, xonly(&t.s), t.genesis, listen("1000"), Some(32));
	let pid = keeper2.pid().unwrap();
	let ticks = cpu_ticks(pid);
	let at = Instant::now();
	let mut many = vec![];
	for _ in 0..100 {
		many.push(tokio::net::TcpStream::connect(&keeper2.addr).await.unwrap());
	}
	tokio::time::sleep(Duration::from_millis(1200)).await;
	let used = cpu_ticks(pid) - ticks;
	let log = keeper2.log();
	let accept_lines = log.lines().filter(|l| l.contains("accept:")).count();
	println!("(c) 100 connections to a keeper with 32 descriptors: {} accept line(s) in its log ({} bytes), {} CPU tick(s) in {} ms; {}",
		accept_lines, log.len(), used, at.elapsed().as_millis(), log.lines().find(|l| l.contains("accept:")).unwrap_or("no accept failure"));
	assert!(accept_lines >= 1 && accept_lines <= 3, "{}", log);
	assert!(used < 50, "the keeper waits rather than spinning: {} ticks", used);
	drop(many);
	tokio::time::sleep(Duration::from_millis(2000)).await;
	let answer = ask_latest(&keeper2.addr, Duration::from_secs(3)).await;
	println!("(c) a fresh request once the idle ones are closed: {}", answer.as_ref().map(|a| a.to_string()).unwrap_or_else(|| "none".into()));
	assert!(answer.is_some_and(|a| a["signature"].is_string()));
	let _ = std::fs::remove_dir_all(&t.dir);
}

/// A rebind request line for `owner`'s leaf under `salt`, spending 10,000 of
/// `asset` into one output of `out`: with another `out` than a request
/// before it under the salt, a second spend of the leaf.
fn rebind_into(owner: &Keypair, genesis: BlockHash, salt: [u8; 32], asset: AssetId, out: u64) -> String {
	let o = ExplicitOutput::new(asset, out, Script::from(vec![0x51, 1]));
	let m = rebind_message(&Chain::new(genesis).leaf_constant(&salt), asset, 10_000, std::slice::from_ref(&o)).unwrap();
	let sig = sign_digest(owner, &m.digest, &[1; 32]);
	json!({
		"op": "rebind", "owner": hex(&xonly(owner).serialize()), "owner_sig": hex(sig.as_ref()), "salt": hex(&salt),
		"asset_in": asset.to_string(), "value_in": "10000", "outputs": [server::signer::WireOutput::from_output(&o)],
	}).to_string()
}

/// Hands `head` to the keeper at `addr` as a signer would (`hold`), on a
/// fresh connection: its answer.
async fn hold_at(addr: &str, head: &Value) -> Value {
	let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
	let line = json!({"op": "hold", "head": head, "nonce": hex(&[0x5a; 32])}).to_string();
	s.write_all(line.as_bytes()).await.unwrap();
	s.write_all(b"\n").await.unwrap();
	let mut r = BufReader::new(s);
	let mut out = String::new();
	r.read_line(&mut out).await.unwrap();
	serde_json::from_str(&out).unwrap()
}

/// What the signer signed before its machine was restored: entries 3 and 4
/// of its record, after the two `t`'s record holds, each a spend of 9,000
/// under salts 3 and 4, made on a copy of the record under the same key
/// (beside a scratch keeper of `k`'s key) and handed to `keeper` as that
/// signer would. The keeper then holds entry 4.
async fn the_lost_window(t: &Setup, k: &Keypair, keeper: &KeeperProcess) {
	let copy = signer_dir();
	std::fs::copy(t.dir.join("operator.key"), copy.join("operator.key")).unwrap();
	std::fs::copy(t.dir.join("signer.record"), copy.join("signer.record")).unwrap();
	let scratch = KeeperProcess::start(k, xonly(&t.s), t.genesis);
	let before = Signer::start(&copy, "before", t.genesis, &keepers_args(&[scratch.arg()]));
	for i in 3..=4u8 {
		let v = raw(&before.socket, &rebind_into(&t.owner, t.genesis, [i; 32], t.asset, 9_000)).await;
		assert!(v["signature"].is_string(), "{}", v);
		assert!(!hold_at(&keeper.addr, &v["entry"]).await["ack"].is_null(), "the keeper takes entry {}", i);
	}
	drop(before);
	let _ = std::fs::remove_dir_all(&copy);
	assert_eq!(keeper.held().1, Some(4));
}

/// R7g F1, KD turned around. A signer restored with its memory (a snapshot of
/// its machine taken with its RAM): its process passed its start check
/// already, so it asks the keeper nothing at start, and its record ends at
/// entry 2, while the keeper holds entries 3 and 4 the signer signed before
/// the restore. Its keeper is unreachable for its first requests (second
/// spends of the leaves of entries 3 and 4, and a third request): each is
/// recorded, as entries 3 to 5, and answered `keepers_unavailable`. Once the
/// keeper is back, the next hand-over is of entry 5, past the keeper's
/// latest: the keeper takes it, and its acknowledgement names the latest
/// head it held, entry 4, which the record does not hold. The signer
/// releases nothing and is stopped on that head, the proof kept. And with
/// the keeper up throughout, the first hand-over (entry 3, which the keeper
/// holds with another hash) stops it, as before.
#[tokio::test(flavor = "multi_thread")]
async fn a_signer_restored_with_its_memory_is_stopped_by_the_keepers_latest() {
	for keeper_down in [true, false] {
		let k = keypair("keeper one");
		let t = setup(&[&k], 1);
		let mut keeper = KeeperProcess::start(&k, xonly(&t.s), t.genesis);
		let args = keepers_args(&[keeper.arg()]);
		let tag = if keeper_down { "the keeper unreachable for the first requests" } else { "the keeper up" };
		// The restored signer: its process past its start check, its record
		// at entry 2.
		let a = Signer::start(&t.dir, "restored", t.genesis, &args);
		for i in 1..=2u8 {
			let v = raw(&a.socket, &rebind_into(&t.owner, t.genesis, [i; 32], t.asset, 9_000)).await;
			assert!(v["signature"].is_string() && acked_by(&v, &t.s, t.genesis, &[&k]), "{}", v);
		}
		the_lost_window(&t, &k, &keeper).await;
		if keeper_down {
			keeper.halt();
		}
		let mut signed = vec![];
		for i in [3u8, 4, 5] {
			let v = raw(&a.socket, &rebind_into(&t.owner, t.genesis, [i; 32], t.asset, 8_000)).await;
			println!("{}: the second spend of salt {} (8,000 where 9,000 was signed): signed {} | {} | {}", tag, i, v["signature"].is_string(),
				v["code"], v["error"].as_str().map(|e| &e[..e.len().min(160)]).unwrap_or(""));
			if v["signature"].is_string() {
				signed.push(i);
			}
		}
		if keeper_down {
			keeper.resume();
			for i in [5u8, 3, 4] {
				let v = raw(&a.socket, &rebind_into(&t.owner, t.genesis, [i; 32], t.asset, 8_000)).await;
				println!("{}: with the keeper back, salt {} again: signed {} | {} | {}", tag, i, v["signature"].is_string(), v["code"],
					v["error"].as_str().map(|e| &e[..e.len().min(160)]).unwrap_or(""));
				if v["signature"].is_string() {
					signed.push(i);
				}
				assert_eq!(v["code"], "stopped", "{}", v);
			}
		}
		let proof = std::fs::read_to_string(server::signer::stopped_path(&t.dir.join("signer.record"))).unwrap_or_default();
		println!("{}: signed {:?} | stopped {} | the proof: {} | the keeper holds {:?}", tag, signed, a.stopped(),
			proof.lines().next().unwrap_or(""), keeper.held());
		assert!(signed.is_empty(), "{}: second spends co-signed under salts {:?}", tag, signed);
		assert!(a.stopped(), "{}: the signer is stopped: {}", tag, a.log());
		if keeper_down {
			// Stopped on the keeper's latest, which its acknowledgement of
			// entry 5 named: entry 4, another hash than the record's.
			assert!(proof.contains("head 4 ") && proof.contains("entry 4 with the running hash"), "{}", proof);
		}
		drop(a);
		let _ = std::fs::remove_dir_all(&t.dir);
	}
}

/// R7g F1, KE turned around: requests at once to a signer restored with its
/// memory. Its record ends at entry 2, the keeper holds entries 3 and 4 the
/// signer signed before the restore. A hand-over is held in flight (a `head`
/// request, through a proxy that delays every line 300 ms each way) while
/// eight rebinds arrive, the second spends of salts 3 and 4 among them: each
/// is recorded and waits for the hand-over, so the next hand-over is of the
/// record's latest, entry 10, past the keeper's latest. Nothing is co-signed
/// and the signer is stopped. Then the same eight requests at once without
/// the hand-over held, twenty times. A test that fails if the route ever
/// opens.
#[tokio::test(flavor = "multi_thread")]
async fn requests_at_once_to_a_signer_restored_with_its_memory_release_nothing() {
	for run in 0..21 {
		let held_in_flight = run == 0;
		let k = keypair("keeper one");
		let t = setup(&[&k], 1);
		let keeper = KeeperProcess::start(&k, xonly(&t.s), t.genesis);
		let slow = LineProxy::start(&keeper.addr, Duration::from_millis(if held_in_flight { 300 } else { 0 }));
		let args = keepers_args(&[slow.arg(&xonly(&k))]);
		// Entries 1 and 2, then the signer started again on them: its start
		// check passes (the keeper holds entry 2), and it has handed nothing
		// over since.
		{
			let first = Signer::start(&t.dir, "first", t.genesis, &keepers_args(&[keeper.arg()]));
			for i in 1..=2u8 {
				assert!(raw(&first.socket, &rebind_into(&t.owner, t.genesis, [i; 32], t.asset, 9_000)).await["signature"].is_string());
			}
		}
		let a = Signer::start(&t.dir, "restored", t.genesis, &args);
		assert!(!a.stopped() && a.log().contains("the keepers agree with the record"), "{}", a.log());
		the_lost_window(&t, &k, &keeper).await;
		let mut tasks = vec![];
		if held_in_flight {
			let socket = a.socket.clone();
			tasks.push(tokio::spawn(async move { (0u8, raw(&socket, r#"{"op":"head"}"#).await) }));
			tokio::time::sleep(Duration::from_millis(150)).await;
		}
		for i in 3u8..=10 {
			let (socket, owner, genesis, asset) = (a.socket.clone(), t.owner, t.genesis, t.asset);
			tasks.push(tokio::spawn(async move { (i, raw(&socket, &rebind_into(&owner, genesis, [i; 32], asset, 8_000)).await) }));
		}
		let mut signed = vec![];
		let mut codes = std::collections::BTreeMap::new();
		for h in tasks {
			let (i, v) = h.await.unwrap();
			if i > 0 && v["signature"].is_string() {
				signed.push((i, v["entry"]["entry"].as_u64().unwrap_or(0)));
			}
			*codes.entry(v["code"].as_str().unwrap_or("-").to_string()).or_insert(0) += 1;
		}
		let entries = std::fs::read_to_string(t.dir.join("signer.record")).unwrap().lines().count() - 1;
		println!("run {}{}: signed (salt, head entry) {:?} | codes {:?} | the record holds {} entries | stopped {} | the keeper holds {:?}", run,
			if held_in_flight { ", a hand-over held in flight" } else { "" }, signed, codes, entries, a.stopped(), keeper.held());
		assert!(signed.is_empty(), "run {}: co-signed {:?}", run, signed);
		assert!(a.stopped(), "run {}: the signer is stopped: {}", run, a.log());
		drop(a);
		let _ = std::fs::remove_dir_all(&t.dir);
	}
}

/// R7g's KC turned around (F6). A signer whose address the keeper's
/// `--allow` does not name (a signer that moved, or reaches the keeper
/// through NAT or another address family) is told why by the keeper before
/// it closes the connection, and says so: at its start, and in its answer
/// to a request it cannot release.
#[tokio::test(flavor = "multi_thread")]
async fn a_keeper_tells_a_signer_it_does_not_admit_why() {
	let k = keypair("keeper one");
	let t = setup(&[&k], 1);
	let keeper = KeeperProcess::start_with(&k, xonly(&t.s), t.genesis, vec!["--allow".into(), "10.20.30.40".into()], None);
	let signer = Signer::start(&t.dir, "moved", t.genesis, &keepers_args(&[keeper.arg()]));
	let at_start: Vec<String> = signer.log().lines().filter(|l| l.contains("at start")).map(str::to_string).collect();
	println!("KC the signer's log at start: {}", at_start.join(" / "));
	let why = "refused: this keeper admits connections only from the addresses its --allow names, and 127.0.0.1 is not one";
	assert!(at_start.iter().any(|l| l.contains(why)), "{}", signer.log());
	let v = raw(&signer.socket, &rebind_line(&t.owner, t.genesis, [1; 32], t.asset)).await;
	println!("KC a rebind: code {} | {}", v["code"], v["error"]);
	assert_eq!(v["code"], "keepers_unavailable", "{}", v);
	assert!(v["error"].as_str().unwrap_or("").contains(why), "{}", v);
	assert!(keeper.log().contains("refused a connection from 127.0.0.1"), "{}", keeper.log());
	drop(signer);
	let _ = std::fs::remove_dir_all(&t.dir);
}

/// R7g's F6: the README's order for a new operator with keepers, followed as
/// written, with its own commands: each key made (the test writes 32 random
/// bytes in hex, as `openssl rand -hex 32` does, mode 0600); `S` read with
/// `arca-signer --pubkey` before any record exists, and each keeper's key
/// with `arca-keeper --pubkey`; the record made naming the three keepers,
/// two required; each keeper's heads file made under `S` and the keeper
/// started; the signer started with the three. It co-signs, two keepers or
/// more acknowledging, and the record's first line names the three keys.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_operator_with_keepers_is_made_in_the_readmes_order() {
	use std::os::unix::fs::PermissionsExt;
	let dir = signer_dir();
	let genesis = BlockHash::from_raw_hash(sha256d::Hash::hash(b"a new operator"));
	let write_key = |name: &str| {
		let path = dir.join(name);
		let mut b = [0u8; 32];
		rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
		std::fs::write(&path, format!("{}\n", hex(&b))).unwrap();
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
		path
	};
	let pubkey = |exe: &str, key: &std::path::Path| {
		let out = Command::new(exe).args(["--key-file", key.to_str().unwrap(), "--pubkey"]).output().unwrap();
		assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
		String::from_utf8(out.stdout).unwrap().trim().to_string()
	};
	// 1. The operator key, and S, before any record exists.
	let op_key = write_key("operator.key");
	let s = pubkey(env!("CARGO_BIN_EXE_arca-signer"), &op_key);
	println!("S = {} (arca-signer --pubkey)", s);
	assert_eq!(s.len(), 64);
	// 2. Each keeper's key, and its public half.
	let kkeys: Vec<std::path::PathBuf> = (0..3).map(|i| write_key(&format!("keeper{}.key", i))).collect();
	let kpubs: Vec<String> = kkeys.iter().map(|k| pubkey(env!("CARGO_BIN_EXE_arca-keeper"), k)).collect();
	println!("the keepers' keys (arca-keeper --pubkey): {:?}", kpubs);
	// 3. The record, naming the three, two required.
	let record = dir.join("signer.record");
	let mut create = Command::new(env!("CARGO_BIN_EXE_arca-signer"));
	create.args(["--key-file", op_key.to_str().unwrap(), "--genesis", &genesis.to_string(), "--record", record.to_str().unwrap(),
		"--create-record"]);
	for k in &kpubs {
		create.args(["--keeper-key", k]);
	}
	let made = create.args(["--keepers-required", "2"]).output().unwrap();
	println!("{}", String::from_utf8_lossy(&made.stderr).trim());
	assert!(made.status.success());
	assert!(String::from_utf8_lossy(&made.stderr).contains(&s), "the record is made for S");
	// 4. Each keeper: its heads file under S, then serving the signer's address.
	let mut keepers = vec![];
	for (i, k) in kkeys.iter().enumerate() {
		let heads = dir.join(format!("keeper{}.heads", i));
		let base = |c: &mut Command| {
			c.args(["--key-file", k.to_str().unwrap(), "--operator", &s, "--genesis", &genesis.to_string(), "--heads",
				heads.to_str().unwrap()]);
		};
		let mut c = Command::new(env!("CARGO_BIN_EXE_arca-keeper"));
		base(&mut c);
		assert!(c.arg("--create").output().unwrap().status.success());
		let port = common::keeper::free_port();
		let mut c = Command::new(env!("CARGO_BIN_EXE_arca-keeper"));
		base(&mut c);
		let child = c.args(["--listen", &format!("127.0.0.1:{}", port), "--allow", "127.0.0.1"])
			.stderr(std::process::Stdio::null()).spawn().unwrap();
		keepers.push((child, format!("127.0.0.1:{}={}", port, kpubs[i])));
	}
	std::thread::sleep(Duration::from_millis(500));
	// 5. The signer, with where each keeper is reached.
	let signer = Signer::start(&dir, "new", genesis, &keepers_args(&keepers.iter().map(|(_, a)| a.clone()).collect::<Vec<_>>()));
	let first = std::fs::read_to_string(&record).unwrap().lines().next().unwrap().to_string();
	println!("the record's first line: {}", first);
	assert!(kpubs.iter().all(|k| first.contains(k.as_str())) && first.contains("keepers=2:"), "{}", first);
	let owner = keypair("owner");
	let v = raw(&signer.socket, &rebind_line(&owner, genesis, [1; 32], AssetId::from_slice(&[3; 32]).unwrap())).await;
	let acks = v["acks"].as_array().map(|a| a.len()).unwrap_or(0);
	println!("a rebind: signed {} | {} acknowledgement(s)", v["signature"].is_string(), acks);
	assert!(v["signature"].is_string() && acks >= 2, "{}", v);
	drop(signer);
	for (mut c, _) in keepers {
		let _ = c.kill();
		let _ = c.wait();
	}
	let _ = std::fs::remove_dir_all(&dir);
}

/// R7h F4, KL turned around. Two of three keepers. Entries 1 and 2 are held
/// by all three; keeper 2 is down while the signer signs entries 3 and 4
/// (spends of salts 3 and 4 into 9,000), which keepers 0 and 1 acknowledge,
/// and the signer writes what it saw each keeper hold beside its record
/// (`<record>.keepers-seen`). Then keeper 0's heads file comes back from its
/// copy at entry 2, keeper 1 is unreachable, and keeper 2 is back at entry
/// 2. The signer restarted: keeper 0 names entry 2, below entry 4 the signer
/// saw it hold before the restart, so it is a lost keeper and no answer; the
/// start check has one answer of the two it needs, and nothing is released.
/// Started again, keeper 0 is still lost. The record itself then put back to
/// a copy taken at entry 2, its side file as the signer wrote it: the second
/// spends of salts 3 and 4 are released to no one, and once keeper 1
/// answers, its entry 4, past the record's end, stops the signer.
#[tokio::test(flavor = "multi_thread")]
async fn a_keeper_gone_back_is_lost_across_a_restart_of_the_signer() {
	let (k0, k1, k2) = (keypair("keeper zero"), keypair("keeper one"), keypair("keeper two"));
	let t = setup(&[&k0, &k1, &k2], 2);
	let mut keeper0 = KeeperProcess::start(&k0, xonly(&t.s), t.genesis);
	let mut keeper1 = KeeperProcess::start(&k1, xonly(&t.s), t.genesis);
	let mut keeper2 = KeeperProcess::start(&k2, xonly(&t.s), t.genesis);
	let args = keepers_args(&[keeper0.arg(), keeper1.arg(), keeper2.arg()]);
	let record = t.dir.join("signer.record");
	let first = Signer::start(&t.dir, "first", t.genesis, &args);
	for i in 1..=2u8 {
		let v = raw(&first.socket, &rebind_into(&t.owner, t.genesis, [i; 32], t.asset, 9_000)).await;
		assert!(v["signature"].is_string() && acked_by(&v, &t.s, t.genesis, &[&k0, &k1, &k2]), "{}", v);
	}
	let record_at_2 = std::fs::read(&record).unwrap();
	let keeper0_at_2 = std::fs::read(keeper0.heads()).unwrap();
	keeper2.halt();
	for i in 3..=4u8 {
		let v = raw(&first.socket, &rebind_into(&t.owner, t.genesis, [i; 32], t.asset, 9_000)).await;
		assert!(v["signature"].is_string() && acked_by(&v, &t.s, t.genesis, &[&k0, &k1]), "{}", v);
	}
	let seen = std::fs::read_to_string(keepers_seen_path(&record)).unwrap_or_default();
	println!("KL what the signer saw, beside its record:\n{}", seen.trim_end());
	drop(first);
	// Keeper 0 back from its copy at entry 2; keeper 1 unreachable; keeper 2
	// back, at entry 2.
	keeper0.halt();
	std::fs::write(keeper0.heads(), &keeper0_at_2).unwrap();
	keeper0.resume();
	keeper1.halt();
	keeper2.resume();
	println!("KL keeper 0 holds {:?} (gone back), keeper 1 down, keeper 2 holds {:?}", keeper0.held(), keeper2.held());
	for run in ["restarted", "started again"] {
		let s = Signer::start(&t.dir, run, t.genesis, &args);
		let v = raw(&s.socket, &rebind_into(&t.owner, t.genesis, [5; 32], t.asset, 9_000)).await;
		println!("KL the signer {}: a new spend: signed {} | {} | {}", run, v["signature"].is_string(), v["code"],
			v["error"].as_str().map(|e| &e[..e.len().min(240)]).unwrap_or(""));
		assert!(v["signature"].is_null(), "{}: released with keepers 0 and 2: {}", run, v);
		assert_eq!(v["code"], "keepers_unavailable", "{}", v);
		let e = v["error"].as_str().unwrap();
		assert!(e.contains("1 of the 3 keepers answered") && e.contains("a lost keeper"), "{}", e);
		assert!(e.contains(if run == "restarted" { "holds entry 2, below entry 4 it held" } else { "a lost keeper" }), "{}", e);
		assert!(!s.stopped(), "{}", s.log());
	}
	// The record alone back at entry 2, its side file as the signer wrote it.
	std::fs::write(&record, &record_at_2).unwrap();
	let s = Signer::start(&t.dir, "record back", t.genesis, &args);
	for i in 3..=4u8 {
		let v = raw(&s.socket, &rebind_into(&t.owner, t.genesis, [i; 32], t.asset, 8_000)).await;
		println!("KL the record back at entry 2: the second spend of salt {} (8,000 where 9,000 was signed): signed {} | {} | {}", i,
			v["signature"].is_string(), v["code"], v["error"].as_str().map(|e| &e[..e.len().min(160)]).unwrap_or(""));
		assert!(v["signature"].is_null(), "a second spend released: {}", v);
		assert_eq!(v["code"], "keepers_unavailable", "{}", v);
	}
	keeper1.resume();
	let v = raw(&s.socket, &rebind_into(&t.owner, t.genesis, [3; 32], t.asset, 8_000)).await;
	println!("KL keeper 1 back: salt 3 again: signed {} | {} | stopped {}", v["signature"].is_string(), v["code"], s.stopped());
	assert!(v["signature"].is_null(), "{}", v);
	assert!(s.stopped(), "keeper 1's entry 4, past the record's end, stops the signer: {}", s.log());
	for (k, n) in [(&k0, 4), (&k1, 4), (&k2, 2)] {
		assert!(seen.lines().any(|l| l == format!("{} {}", hex(&xonly(k).serialize()), n)), "{}", seen);
	}
	drop(s);
	let _ = std::fs::remove_dir_all(&t.dir);
}

/// Where the signer keeps what it saw its keepers hold, beside `record`.
fn keepers_seen_path(record: &std::path::Path) -> std::path::PathBuf {
	std::path::PathBuf::from(format!("{}.keepers-seen", record.display()))
}

/// R7h F4. What the signer saw its keepers hold, and the first head they
/// acknowledged, are noted beside the record before anything is released:
/// a signer that cannot write beside its record (its directory made
/// read-only) records the entry, gets the keeper's acknowledgement, and
/// releases nothing; once it can write again, the same request completes,
/// as the same entry.
#[tokio::test(flavor = "multi_thread")]
async fn a_signer_that_cannot_note_what_its_keepers_hold_releases_nothing() {
	use std::os::unix::fs::PermissionsExt;
	for first_head in [true, false] {
		let k = keypair("keeper one");
		let t = setup(&[&k], 1);
		let keeper = KeeperProcess::start(&k, xonly(&t.s), t.genesis);
		let s = Signer::start(&t.dir, "signer", t.genesis, &keepers_args(&[keeper.arg()]));
		if !first_head {
			let v = raw(&s.socket, &rebind_into(&t.owner, t.genesis, [1; 32], t.asset, 9_000)).await;
			assert!(v["signature"].is_string(), "{}", v);
		}
		let salt = [7u8; 32];
		std::fs::set_permissions(&t.dir, std::fs::Permissions::from_mode(0o500)).unwrap();
		let v = raw(&s.socket, &rebind_into(&t.owner, t.genesis, salt, t.asset, 9_000)).await;
		std::fs::set_permissions(&t.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
		let tag = if first_head { "the first head" } else { "a later head" };
		println!("{}, the record's directory read-only: signed {} | {} | {}", tag, v["signature"].is_string(), v["code"],
			v["error"].as_str().map(|e| &e[..e.len().min(240)]).unwrap_or(""));
		assert!(v["signature"].is_null(), "{}: released though nothing could be noted: {}", tag, v);
		assert_eq!(v["code"], "keepers_unavailable", "{}", v);
		assert!(v["error"].as_str().unwrap().contains("cannot note beside its record"), "{}", v);
		let again = raw(&s.socket, &rebind_into(&t.owner, t.genesis, salt, t.asset, 9_000)).await;
		println!("{}, writable again: signed {} | entry {}", tag, again["signature"].is_string(), again["entry"]["entry"]);
		assert!(again["signature"].is_string(), "{}", again);
		assert_eq!(again["entry"]["entry"], if first_head { 1 } else { 2 }, "the same entry: {}", again);
		assert!(server::signer::acknowledged_path(&t.dir.join("signer.record")).exists());
		assert!(keepers_seen_path(&t.dir.join("signer.record")).exists());
		drop(s);
		let _ = std::fs::remove_dir_all(&t.dir);
	}
}

/// What the keeper at `addr` says to a connection from `from` that sends
/// it a request line: every byte it writes before it closes the
/// connection, within two seconds.
async fn said_to(addr: &str, from: &str) -> String {
	use tokio::io::AsyncReadExt;
	let sock = tokio::net::TcpSocket::new_v4().unwrap();
	sock.bind(format!("{}:0", from).parse().unwrap()).unwrap();
	let mut s = sock.connect(addr.parse().unwrap()).await.unwrap();
	let _ = s.write_all(format!("{{\"op\":\"latest\",\"nonce\":\"{}\"}}\n", hex(&[7; 32])).as_bytes()).await;
	let mut out = vec![];
	let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut out)).await;
	String::from_utf8_lossy(&out).trim().to_string()
}

/// R7h's second review, H3 turned around. A keeper holding its most
/// connections (`--max-connections` 2, both from the signer's address)
/// closes the next at once with nothing said, whoever it comes from: an
/// address `--allow` does not name included. With room again, a stranger
/// is told why before the keeper closes it, and the signer's address is
/// answered.
#[tokio::test(flavor = "multi_thread")]
async fn a_keeper_at_its_bound_says_nothing_to_anyone() {
	let k = keypair("keeper one");
	let t = setup(&[&k], 1);
	let listen = ["--allow", "127.0.0.1", "--max-connections", "2", "--idle-timeout-ms", "60000"].iter().map(|a| a.to_string()).collect();
	let keeper = KeeperProcess::start_with(&k, xonly(&t.s), t.genesis, listen, None);
	// The connection its start was checked over closed first.
	tokio::time::sleep(Duration::from_millis(500)).await;
	let mut held = vec![];
	for _ in 0..2 {
		held.push(tokio::net::TcpStream::connect(&keeper.addr).await.unwrap());
	}
	for s in &mut held {
		assert!(!closed(s, Duration::from_millis(300)).await, "both connections are held: {}", keeper.log());
	}
	let stranger = said_to(&keeper.addr, "127.0.0.2").await;
	let signer = said_to(&keeper.addr, "127.0.0.1").await;
	println!("H3 two connections held, the most it holds: a stranger is answered {:?}; the signer's address {:?}", stranger, signer);
	// Room again: the two closed, and the keeper finds them closed.
	drop(held);
	tokio::time::sleep(Duration::from_millis(500)).await;
	let stranger_after = said_to(&keeper.addr, "127.0.0.2").await;
	let signer_after = ask_latest(&keeper.addr, Duration::from_secs(3)).await;
	println!("H3 with room again: a stranger is answered {:?}; the signer's address {}", stranger_after,
		signer_after.as_ref().map(|v| v.to_string()).unwrap_or_else(|| "none".into()));
	println!("H3 the keeper's log: {}", keeper.log().lines().filter(|l| l.contains("refused")).collect::<Vec<_>>().join(" / "));
	assert_eq!(stranger, "", "at its bound the keeper says nothing to a stranger");
	assert_eq!(signer, "", "nor to the signer's address");
	assert!(stranger_after.contains("refused: this keeper admits connections only from the addresses its --allow names, and 127.0.0.2 is not one"),
		"with room, a stranger is told why: {}", stranger_after);
	assert!(signer_after.is_some_and(|v| v["signature"].is_string()), "with room, the signer's address is answered");
	let _ = std::fs::remove_dir_all(&t.dir);
}
