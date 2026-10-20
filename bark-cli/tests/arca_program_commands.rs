//! The commands a program running `arca` for its user needs, run against a
//! whole Arca server on an anchored proof-of-stake regtest chain, as the
//! scenarios run it: a mnemonic restored from the standard input (`-`), a
//! socket as Node.js gives it, never the command line; the refresh fees shown before anything is signed
//! (`quote`), and the participation taken only on the very fees shown
//! (`participate --shown`), refused before anything is signed when they
//! changed; and `schedule`, the time `sync` must next run, which asks
//! nothing of the operator.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

use elements::Script;
use serde_json::{json, Value};

use common::cli::Arca;
use common::running::Running;
use server::store::RoundState;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

/// `arca create … --mnemonic-file -`, the mnemonic written to its standard
/// input, which is one end of a socket pair, as Node.js gives a child its
/// input (a path such as /dev/stdin cannot be opened on a socket): whether
/// it succeeded, and its JSON.
fn create_from_stdin(w: &Arca, args: &[&str], mnemonic: &str) -> (bool, Value) {
	let (ours, theirs) = UnixStream::pair().unwrap();
	let child = Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&w.dir).args(args)
		.args(["--mnemonic-file", "-"]).env("ARCA_NODE_PASSWORD", "arca")
		.stdin(Stdio::from(OwnedFd::from(theirs))).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("run arca");
	let mut ours = ours;
	ours.write_all(mnemonic.as_bytes()).unwrap();
	ours.shutdown(std::net::Shutdown::Write).unwrap();
	let out = tokio::task::block_in_place(|| child.wait_with_output()).unwrap();
	(out.status.success(), serde_json::from_slice(&out.stdout).expect("JSON"))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_program_restores_from_a_file_shows_fees_before_signing_and_reads_the_schedule() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"];

	// A wallet with a board, live.
	let a = Arca::new("A");
	a.ok(&create);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, r.x, 5_000_000);
	r.produce().await;
	let board = a.ok(&["board", &x, "2000000"])["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the server to credit the board", || a.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	a.ok(&["sync"]);

	// `schedule` answers without the operator: the board's dates, and when
	// `sync` must next run.
	let sch = a.ok(&["schedule"]);
	assert_eq!(sch["coins"][0]["leaf_id"], board.as_str(), "{}", sch);
	assert!(sch["next_sync_at"].as_u64().unwrap() > sch["now"].as_u64().unwrap(), "nothing is due yet: {}", sch);
	assert_eq!(sch["due"], false);
	assert_eq!(sch["next_sync_at"], sch["coins"][0]["refresh_from"], "the board's free window is the next date: {}", sch);

	// The same wallet restored from its mnemonic, read from the standard
	// input, a socket: the mnemonic is the one written, and the board is
	// served back.
	let words = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap();
	let a2 = Arca::new("A2");
	let (ok, v) = create_from_stdin(&a2, &create, &format!("  {}\n", words.split_whitespace().collect::<Vec<_>>().join("  ")));
	assert!(ok, "{}", v);
	assert_eq!(v["mailbox_key"], a.ok(&["info"])["mailbox_key"], "one mnemonic, one mailbox key");
	assert_eq!(std::fs::read_to_string(a2.dir.join("mnemonic")).unwrap().split_whitespace().collect::<Vec<_>>(),
		words.split_whitespace().collect::<Vec<_>>());
	assert_eq!(v["restore"]["not_recovered"], json!([]), "{}", v);
	a2.ok(&["sync"]);
	assert!(a2.ok(&["coins"]).as_array().unwrap().iter().any(|c| c["leaf_id"] == board.as_str() && c["state"] == "live"),
		"the board is restored");
	// A file that cannot be read restores nothing, and makes no wallet.
	let a3 = Arca::new("A3");
	let mut args = create.to_vec();
	args.extend(["--mnemonic-file", "/nonexistent/mnemonic"]);
	a3.refused(&args, "/nonexistent/mnemonic");
	assert!(!a3.dir.join("arca.sqlite").exists());
	// The mnemonic is given one way only.
	let both = tokio::task::block_in_place(|| Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&a3.dir).args(create)
		.args(["--mnemonic", "abandon", "--mnemonic-file", "/dev/null"]).output()).unwrap();
	assert!(!both.status.success() && String::from_utf8_lossy(&both.stderr).contains("cannot be used with"),
		"--mnemonic and --mnemonic-file together are refused: {}", String::from_utf8_lossy(&both.stderr));

	// `quote` shows each coin's refresh fee and signs nothing.
	let q = a.ok(&["quote"]);
	let shown = q["coins"].clone();
	assert_eq!(shown.as_array().unwrap().len(), 1, "{}", q);
	assert_eq!(shown[0]["leaf_id"], board.as_str());
	assert!(shown[0]["fee"].is_string() && shown[0]["schedule"].is_object(), "{}", q);
	assert!(a.ok(&["participations"]).as_array().unwrap().is_empty(), "a quote hands nothing over");

	// Fees other than those shown: refused before anything is signed.
	let mut stale = shown.clone();
	stale[0]["fee"] = json!("1");
	let msg = a.refused(&["participate", "--shown", &stale.to_string()], "the refresh fees changed since they were shown");
	assert!(msg.contains(&shown.to_string()), "the refusal shows the fees as they are now: {}", msg);
	assert!(a.ok(&["participations"]).as_array().unwrap().is_empty(), "nothing was handed over");
	assert_eq!(a.ok(&["coins"])[0]["state"], "live", "the coin is not given");
	a.refused(&["participate", "--shown", "not json"], "the fees shown");

	// The very fees shown: the participation goes ahead, and completes.
	let p = a.ok(&["participate", "--shown", &shown.to_string()]);
	assert_eq!(p["participations"][0]["state"], "pending", "{}", p);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	let s = a.ok(&["sync"]);
	assert_eq!(s["participations"][0]["state"], "released", "{}", s);
	let coins = a.ok(&["coins"]);
	assert!(coins.as_array().unwrap().iter().any(|c| c["kind"] == "batch" && c["state"] == "live"), "{}", coins);
}
