//! The wallet's Bitcoin side against a real Bitcoin ark on regtest: Bark's
//! server, captaind, at the release the wallet bundles, its Lightning
//! gateway (upstream Core Lightning with Boltz's hold plugin), and a peer
//! Core Lightning node as the outside payer and payee
//! (`contrib/bitcoin-ark-regtest/`). The wallet runs Bark's own client and
//! daemon, `bark` and `barkd`, built with the testnet4 patch.
//!
//! One wallet, its Bitcoin ark wallet made from its own mnemonic: it boards,
//! pays an invoice of the peer over Lightning and reads the outcome back,
//! receives over Lightning with the claim run as the payer pays, gets a fresh
//! invoice when a payment can no longer be claimed, refreshes, and exits
//! alone. A second wallet restored from the same mnemonic finds the same
//! coins.
//!
//! Needs `ARCA_TEST_BITCOIN_ARK`, the harness script with its environment
//! (`regtest.sh`, after `regtest.sh up`), and `ARCA_BARK_EXEC` and
//! `ARCA_BARKD_EXEC`, the patched `bark` and `barkd`. Skipped otherwise.

mod common;

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use bitcoin::hashes::{sha256, Hash};
use serde_json::Value;

use common::cli::Arca;

fn harness() -> Option<PathBuf> {
	std::env::var_os("ARCA_TEST_BITCOIN_ARK").map(PathBuf::from)
}

/// The harness script, run with `args`: its standard output.
fn ark(args: &[&str]) -> String {
	let out = Command::new(harness().unwrap()).args(args).output().expect("run the harness");
	assert!(out.status.success(), "regtest.sh {:?}: {}{}", args, String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
	String::from_utf8_lossy(&out.stdout).trim().to_string()
}
fn ark_json(args: &[&str]) -> Value {
	let s = ark(args);
	// lightning-cli `pay` prints a progress line before its JSON.
	let s = s.find('{').map(|i| &s[i..]).unwrap_or(&s);
	serde_json::from_str(s).unwrap_or_else(|e| panic!("regtest.sh {:?}: not JSON ({}): {}", args, e, s))
}
fn mine(n: u32) {
	ark(&["mine", &n.to_string()]);
}
fn height() -> u64 {
	ark(&["btc", "getblockcount"]).parse().unwrap()
}

/// A mnemonic no earlier run of this test used, so the ark holds nothing
/// of it.
fn fresh_mnemonic() -> String {
	let seed = format!("{}-{:?}", std::process::id(), std::time::SystemTime::now());
	let entropy = sha256::Hash::hash(seed.as_bytes()).to_byte_array();
	bip39::Mnemonic::from_entropy(&entropy[..16]).unwrap().to_string()
}

fn write_mnemonic(a: &Arca, m: &str) {
	std::fs::create_dir_all(&a.dir).unwrap();
	std::fs::write(a.dir.join("mnemonic"), m).unwrap();
}

/// Bark's own JSON, through `arca bitcoin`.
fn bark(a: &Arca, args: &[&str]) -> Value {
	let out = tokio::task::block_in_place(|| Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&a.dir)
		.arg("bitcoin").arg("--quiet").args(args).output().unwrap());
	assert!(out.status.success(), "arca bitcoin {:?}: {}", args, String::from_utf8_lossy(&out.stderr));
	serde_json::from_slice(&out.stdout).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&out.stdout).trim().to_string()))
}
fn spendable(a: &Arca) -> u64 {
	bark(a, &["balance"])["spendable_sat"].as_u64().unwrap()
}

/// Waits up to `secs`, mining a block and letting the wallet catch up each
/// time, until `done`.
fn until(a: &Arca, secs: u64, what: &str, mut done: impl FnMut() -> bool) {
	let t0 = Instant::now();
	while !done() {
		assert!(t0.elapsed() < Duration::from_secs(secs), "{}: not within {} s (height {})", what, secs, height());
		mine(1);
		let _ = tokio::task::block_in_place(|| Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&a.dir)
			.args(["bitcoin", "--quiet", "maintain"]).output());
		std::thread::sleep(Duration::from_secs(1));
	}
}

/// Waits until the gateway holds an incoming HTLC: the payer's payment has
/// reached Bark's server.
fn until_held() {
	let t0 = Instant::now();
	loop {
		let ch = ark_json(&["gw", "listpeerchannels"]);
		if ch["channels"].as_array().unwrap().iter().any(|c| c["htlcs"].as_array().is_some_and(|h| !h.is_empty())) {
			return;
		}
		assert!(t0.elapsed() < Duration::from_secs(30), "the payment did not reach the gateway");
		std::thread::sleep(Duration::from_millis(200));
	}
}

/// The peer pays `invoice` in the background; its answer.
fn peer_pays(invoice: &str) -> std::thread::JoinHandle<Value> {
	let inv = invoice.to_string();
	std::thread::spawn(move || {
		let out = Command::new(harness().unwrap()).args(["peer", "pay", &inv]).output().unwrap();
		let s = String::from_utf8_lossy(&out.stdout).to_string();
		let s = s.find('{').map(|i| s[i..].to_string()).unwrap_or(s);
		serde_json::from_str(&s).unwrap_or(Value::String(s))
	})
}

#[tokio::test(flavor = "multi_thread")]
async fn btc_boards_pays_receives_refreshes_and_exits_in_a_bitcoin_ark() {
	if harness().is_none() || std::env::var_os("ARCA_BARK_EXEC").is_none() || std::env::var_os("ARCA_BARKD_EXEC").is_none() {
		println!("skipped: ARCA_TEST_BITCOIN_ARK, ARCA_BARK_EXEC and ARCA_BARKD_EXEC name no Bitcoin ark and no Bark");
		return;
	}
	let info = ark_json(&["info"]);
	let (url, bitcoind, cookie) = (info["ark"].as_str().unwrap(), info["bitcoind"].as_str().unwrap(), info["cookie"].as_str().unwrap());
	let create = ["bitcoin", "create", "--regtest", "--ark", url, "--bitcoind", bitcoind, "--bitcoind-cookie", cookie];

	// No Arca wallet: no mnemonic to make the Bitcoin ark wallet from.
	let a = Arca::new("BTCA");
	a.refused(&create, "create it first");
	a.refused(&["lightning", "receive", "btc", "1000"], "has no Bitcoin ark wallet");

	// The Bitcoin ark wallet, from the wallet's own mnemonic; no second one.
	let m = fresh_mnemonic();
	write_mnemonic(&a, &m);
	let tip = height();
	let c = a.ok(&create);
	let c_info = bark(&a, &["ark-info"]);
	assert_eq!((c["network"].as_str(), c["ark_info"]["network"].as_str()), (Some("regtest"), Some("regtest")));
	assert!(c["birthday_height"].as_u64().unwrap() >= tip, "a new wallet scans Bitcoin from now");
	assert_eq!(std::fs::read_to_string(a.dir.join("bitcoin/mnemonic")).unwrap().trim(), m, "the same mnemonic");
	assert!(!a.dir.join("bitcoin/auth_token").exists(), "barkd's token is gone");
	a.refused(&create, "has a Bitcoin ark wallet already");
	let without = ["bitcoin", "create", "--regtest", "--ark", url];
	a.refused(&without, "--bitcoind");

	// On-chain BTC, then a board.
	let addr = bark(&a, &["onchain", "address"])["address"].as_str().unwrap().to_string();
	ark(&["btc", "-rpcwallet=miner", "sendtoaddress", &addr, "0.01"]);
	mine(1);
	until(&a, 60, "the on-chain funding", || bark(&a, &["onchain", "balance"])["confirmed_sat"].as_u64().unwrap() >= 1_000_000);
	let board = bark(&a, &["board", "300000 sats"]);
	println!("board: {}", board);
	until(&a, 120, "the board", || spendable(&a) > 0);
	let boarded = spendable(&a);
	println!("spendable after the board: {}", boarded);

	// Lightning out: `pay invoice … --wait` prints nothing; the wallet reads
	// the payment back with `pay status`, preimage and all.
	let pi = ark_json(&["peer", "invoice", "20000000", &format!("w-out-{}", std::process::id()), "out"]);
	let inv = pi["bolt11"].as_str().unwrap();
	let paid = a.ok(&["lightning", "pay", inv]);
	assert_eq!((paid["side"].as_str(), paid["payment"]["state"].as_str()), (Some("bitcoin"), Some("paid")));
	let li = ark_json(&["peer", "listinvoices", &format!("w-out-{}", std::process::id())]);
	assert_eq!(li["invoices"][0]["status"], "paid");
	assert_eq!(paid["payment"]["preimage"], li["invoices"][0]["payment_preimage"], "the preimage the peer revealed");
	// A Bitcoin invoice is never paid from a Sequentia asset.
	let pi2 = ark_json(&["peer", "invoice", "1000000", &format!("w-out2-{}", std::process::id()), "out"]);
	a.refused(&["lightning", "pay", pi2["bolt11"].as_str().unwrap(), "--asset", &"ab".repeat(32)], "paid in native BTC");
	assert_eq!(ark_json(&["peer", "listinvoices", &format!("w-out2-{}", std::process::id())])["invoices"][0]["status"], "unpaid");

	// Lightning in: the invoice, then the claim run while the payer pays.
	let before = spendable(&a);
	let r = a.ok(&["lightning", "receive", "btc", "30000", "--description", "in"]);
	let inv = r["invoice"].as_str().unwrap().to_string();
	assert!(r["next"].as_str().unwrap().contains("arca lightning claim"));
	let pay = peer_pays(&inv);
	let got = a.ok(&["lightning", "claim", &inv, "--wait", "60"]);
	assert_eq!(got["state"], "claimed");
	assert_eq!(got["receive"]["state"], "settled");
	assert_eq!(pay.join().unwrap()["status"], "complete");
	let after = spendable(&a);
	println!("received: {} -> {} (+{})", before, after, after - before);
	assert!(after > before && after <= before + 30_000);

	// No payment within the wait: `waiting`, nothing lost; a claim later.
	let r = a.ok(&["lightning", "receive", "btc", "11000"]);
	let inv = r["invoice"].as_str().unwrap().to_string();
	let w = a.ok(&["lightning", "claim", &inv, "--wait", "3"]);
	assert_eq!(w["state"], "waiting");
	let pay = peer_pays(&inv);
	assert_eq!(a.ok(&["lightning", "claim", &inv, "--wait", "60"])["state"], "claimed");
	assert_eq!(pay.join().unwrap()["status"], "complete");

	// Blocks between the payment's arrival and the claim, as many as leave
	// the held payment's lock time too close: the claim asks for an HTLC
	// expiring at the tip plus the invoice's final CLTV delta less the
	// server's htlc_expiry_delta, and the server wants that delta again
	// below the incoming payment's expiry; so the claim is refused once the
	// tip passes the expiry less the final delta (the payer adds a random
	// offset to the expiry, so the count is read from the held HTLC). The
	// claim cannot succeed; the wallet asks for a fresh invoice of the same
	// amount, which the payer then pays.
	let r = a.ok(&["lightning", "receive", "btc", "12000", "--description", "again"]);
	let inv = r["invoice"].as_str().unwrap().to_string();
	let pay = peer_pays(&inv);
	until_held();
	let held = ark_json(&["gw", "listpeerchannels"])["channels"].as_array().unwrap().iter()
		.flat_map(|c| c["htlcs"].as_array().unwrap().clone()).find(|h| h["direction"] == "in").unwrap();
	let expiry = held["expiry"].as_u64().unwrap();
	let final_delta = inv.parse::<lightning_invoice::Bolt11Invoice>().unwrap().min_final_cltv_expiry_delta();
	let server_delta = c_info["htlc_expiry_delta"].as_u64().unwrap();
	let tip = height();
	let blocks = (expiry + 1 - final_delta).saturating_sub(tip);
	assert!(blocks > 0);
	println!("held HTLC expiry {}, tip {}, final delta {}, server delta {}: {} blocks before the claim", expiry, tip, final_delta,
		server_delta, blocks);
	mine(blocks as u32);
	let re = a.ok(&["lightning", "claim", &inv, "--wait", "60"]);
	assert_eq!(re["state"], "reissued");
	assert_eq!(re["replaces"], inv.as_str());
	println!("why: {}", re["why"]);
	let t0 = Instant::now();
	while !pay.is_finished() {
		assert!(t0.elapsed() < Duration::from_secs(90), "the first payment was never failed back to the payer");
		std::thread::sleep(Duration::from_millis(500));
	}
	let first = pay.join().unwrap();
	println!("the first payment: {}", first);
	assert_ne!(first["status"], "complete", "the first payment went back to the payer: {}", first);
	let fresh = re["invoice"].as_str().unwrap().to_string();
	assert_ne!(fresh, inv);
	let fi = bark::arca::lightning::parse_invoice(&fresh).unwrap();
	assert_eq!((fi.amount_msat, fi.description.as_deref()), (Some(12_000_000), Some("again")));
	let before = spendable(&a);
	let pay = peer_pays(&fresh);
	assert_eq!(a.ok(&["lightning", "claim", &fresh, "--wait", "60"])["state"], "claimed");
	assert_eq!(pay.join().unwrap()["status"], "complete");
	assert!(spendable(&a) > before);

	// Restored from the same mnemonic: the same coins.
	let b = Arca::new("BTCB");
	write_mnemonic(&b, &m);
	let mut restore = create.to_vec();
	let from = c["birthday_height"].as_u64().unwrap().to_string();
	restore.extend(["--birthday-height", &from]);
	b.ok(&restore);
	until(&b, 60, "the restored wallet's coins", || spendable(&b) == spendable(&a));
	println!("restored: {} spendable, as the first wallet", spendable(&b));
	let _ = std::fs::remove_dir_all(&b.dir);

	// A refresh: every leaf replaced by one from a round.
	let old: Vec<Value> = bark(&a, &["vtxos"]).as_array().unwrap().iter().map(|v| v["id"].clone()).collect();
	println!("refresh: {}", bark(&a, &["refresh", "--all"]));
	until(&a, 180, "the refresh", || {
		let now = bark(&a, &["vtxos"]);
		let live: Vec<&Value> = now.as_array().unwrap().iter().filter(|v| v["state"]["type"] == "spendable").collect();
		!live.is_empty() && live.iter().all(|v| !old.contains(&v["id"]))
	});

	// The exit, alone: every leaf on chain, then claimed to the on-chain
	// wallet.
	let leaving = spendable(&a);
	let onchain_before = bark(&a, &["onchain", "balance"])["total_sat"].as_u64().unwrap();
	println!("exit start: {}", bark(&a, &["exit", "start", "--all"]));
	let t0 = Instant::now();
	loop {
		let _ = bark(&a, &["exit", "progress"]);
		let l = bark(&a, &["exit", "list"]);
		if l.as_array().is_some_and(|x| !x.is_empty() && x.iter().all(|e| e["state"]["type"] == "claimable")) {
			break;
		}
		assert!(t0.elapsed() < Duration::from_secs(600), "the exit did not become claimable: {}", l);
		mine(1);
		std::thread::sleep(Duration::from_millis(500));
	}
	let to = bark(&a, &["onchain", "address"])["address"].as_str().unwrap().to_string();
	println!("exit claim: {}", bark(&a, &["exit", "claim", &to, "--all"]));
	until(&a, 120, "the claim", || {
		bark(&a, &["onchain", "balance"])["confirmed_sat"].as_u64().unwrap() > onchain_before + leaving - 5_000
	});
	let ob = bark(&a, &["onchain", "balance"]);
	println!("exited {} sat: on-chain {} -> {}", leaving, onchain_before, ob["total_sat"]);
	assert_eq!(spendable(&a), 0);
	let _ = std::fs::remove_dir_all(&a.dir);
}
