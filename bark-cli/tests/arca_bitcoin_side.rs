//! The Bitcoin side of Lightning, at its boundary. Native BTC goes over
//! Lightning through Bark's own Lightning leg, on the wallet's Bitcoin ark
//! wallet (`<datadir>/bitcoin`), never through a Sequentia leaf. Here `bark`
//! is a stand-in that records what it is asked and answers as Bark does, so
//! the test checks the exact calls the wallet makes of Bark: a payment is
//! made, then read back with `pay status` (`pay invoice … --wait` prints
//! nothing); a receive is an invoice, then a claim run while the payer pays,
//! then the receive read back. None is made while the wallet has no Bitcoin
//! ark wallet, a Bitcoin invoice is never paid from a Sequentia leaf, and the
//! Bitcoin side needs nothing of the Arca operator. `tests/arca_bitcoin_ark.rs`
//! runs the same calls against a real Bitcoin ark.
//!
//! Needs what the other scenarios need.

mod common;

use std::path::PathBuf;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};

use server::server::BitcoinLightningSection;

use common::cli::Arca;
use common::running::Running;

/// A Bitcoin regtest invoice for 1,000 satoshis, signed.
fn bitcoin_invoice() -> String {
	let key = SecretKey::from_slice(&[0x31; 32]).unwrap();
	InvoiceBuilder::new(Currency::Regtest)
		.description("a coffee".into())
		.payment_hash(sha256::Hash::hash(b"a preimage"))
		.payment_secret(PaymentSecret([0x42; 32]))
		.current_timestamp()
		.min_final_cltv_expiry_delta(144)
		.amount_milli_satoshis(1_000_000)
		.build_signed(|h| Secp256k1::new().sign_ecdsa_recoverable(h, &key))
		.unwrap()
		.to_string()
}

/// What the stand-in for Bark was asked since the last look, one argument a
/// line and `--` after each call, and clears it; `None` when it was not run.
fn asked(log: &PathBuf) -> Option<Vec<String>> {
	let s = std::fs::read_to_string(log).ok()?;
	std::fs::remove_file(log).unwrap();
	Some(s.lines().map(|l| l.to_string()).collect())
}

#[tokio::test(flavor = "multi_thread")]
async fn native_btc_goes_through_barks_leg_on_the_wallets_bitcoin_ark() {
	// The stand-in for Bark: it writes each call down, one argument a line
	// and `--` after it, and answers as Bark does.
	let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("bark-standin-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let (exe, log) = (dir.join("bark"), dir.join("asked"));
	std::fs::write(&exe, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" -- >> '{}'\ncase \"$*\" in\n\
		*'pay status'*) echo '{{\"state\": \"paid\", \"preimage\": \"00\"}}' ;;\n\
		*'pay invoice'*) ;;\n\
		*'lightning invoice'*) echo '{{\"invoice\": \"lnbcrt1standin\"}}' ;;\n\
		*'receive status'*) echo '{{\"state\": \"settled\"}}' ;;\n\
		*'lightning claim'*) ;;\n\
		*'onchain balance'*) echo '{{\"total_sat\": 300}}' ;;\n\
		*balance*) echo '{{\"spendable_sat\": 1000, \"pending_exit_sat\": 20}}' ;;\n\
		*) echo '{{\"stand_in\": true}}' ;;\nesac\n", log.display())).unwrap();
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
	// SAFETY: this test binary runs this one test, and sets the variable
	// before it runs anything that reads the environment on another thread.
	unsafe { std::env::set_var("ARCA_BARK_EXEC", &exe) };

	// An operator naming its Bitcoin ark and its Lightning node on Bitcoin.
	let ark = "https://ark.example.org";
	let mut r = Running::start_with(|c, _, _| {
		c.lightning.bitcoin = Some(BitcoinLightningSection { rpc: dir.join("no-node"), ark: Some(ark.into()) });
	}).await;
	let x = r.x.to_string();
	let (url, nurl) = (r.url(), r.node_url());
	let a = Arca::new("BTC1");
	a.ok(&["create", "--server", &url, "--node-url", &nurl, "--node-user", "arca", "--exit-delay-units", "1",
		"--min-exit-delay-units", "1"]);
	let info = a.ok(&["info"]);
	println!("info.lightning.bitcoin: {}", info["server_info"]["lightning"]["bitcoin"]);
	assert_eq!(info["server_info"]["lightning"]["bitcoin"]["ark"], ark);
	let inv = bitcoin_invoice();
	println!("a Bitcoin invoice: {}", inv);

	// No Bitcoin ark wallet yet: refused, Bark not run.
	a.refused(&["lightning", "pay", &inv], "has no Bitcoin ark wallet");
	a.refused(&["lightning", "receive", "btc", "1000"], "has no Bitcoin ark wallet");
	a.refused(&["lightning", "claim", &inv], "has no Bitcoin ark wallet");
	assert_eq!(asked(&log), None);
	let b = a.ok(&["balance"]);
	assert_eq!((&b["rows"][0]["asset"], &b["rows"][0]["total"]), (&serde_json::json!("BTC"), &serde_json::json!("0")));
	assert_eq!(asked(&log), None);

	// With one: a payment, then its status.
	let bitcoin = a.dir.join("bitcoin");
	std::fs::create_dir_all(&bitcoin).unwrap();
	std::fs::write(bitcoin.join("mnemonic"), "stand-in").unwrap();
	let d = bitcoin.display().to_string();
	let calls = |c: &[&[&str]]| -> Vec<String> {
		c.iter().flat_map(|c| ["--datadir", &d, "--quiet"].into_iter().chain(c.iter().copied()).chain(["--"]))
			.map(|s| s.to_string()).collect()
	};
	let paid = a.ok(&["lightning", "pay", &inv]);
	assert_eq!((paid["side"].as_str(), paid["payment"]["state"].as_str()), (Some("bitcoin"), Some("paid")));
	assert_eq!(asked(&log).unwrap(), calls(&[&["lightning", "pay", "invoice", &inv, "--wait"],
		&["lightning", "pay", "status", &inv, "--no-sync"]]));
	let paid = a.ok(&["lightning", "pay", &inv, "--asset", "BTC"]);
	assert_eq!(paid["side"], "bitcoin");
	assert_eq!(asked(&log).unwrap(), calls(&[&["lightning", "pay", "invoice", &inv, "--wait"],
		&["lightning", "pay", "status", &inv, "--no-sync"]]));
	// A receive: the invoice, then the claim, then the receive read back.
	let got = a.ok(&["lightning", "receive", "btc", "1000", "--description", "a coffee"]);
	assert_eq!((got["side"].as_str(), got["invoice"].as_str()), (Some("bitcoin"), Some("lnbcrt1standin")));
	assert!(got["next"].as_str().unwrap().contains("arca lightning claim lnbcrt1standin"));
	assert_eq!(asked(&log).unwrap(), calls(&[&["lightning", "invoice", "1000 sats", "--description", "a coffee"]]));
	let claimed = a.ok(&["lightning", "claim", &inv, "--wait", "5"]);
	assert_eq!((claimed["state"].as_str(), claimed["receive"]["state"].as_str()), (Some("claimed"), Some("settled")));
	assert_eq!(asked(&log).unwrap(), calls(&[&["lightning", "claim", &inv, "--wait"],
		&["lightning", "receive", "status", &inv, "--no-sync"]]));
	// The BTC row counts the ark balance and the on-chain wallet.
	let b = a.ok(&["balance"]);
	assert_eq!(b["rows"][0]["total"], "1320");
	assert_eq!(asked(&log).unwrap(), calls(&[&["balance"], &["onchain", "balance"]]));

	// A Bitcoin invoice is never paid from a Sequentia leaf: asked to, the
	// wallet refuses before anything is signed, and Bark is not run.
	a.refused(&["lightning", "pay", &inv, "--asset", &x], "paid in native BTC");
	assert_eq!(asked(&log), None);
	assert!(a.ok(&["lightning", "payments"]).as_object().unwrap().is_empty(), "nothing paid on the Sequentia side");
	assert!(a.ok(&["lightning", "receives"]).as_object().unwrap().is_empty(), "nothing asked on the Sequentia side");

	// The Bitcoin side is the wallet's own Bitcoin ark wallet, joined to any
	// Bark ark: an operator that names none (its [lightning] section, which
	// takes a restart) changes nothing of it.
	r.config.lightning.bitcoin = None;
	r.restart_server().await;
	assert!(a.ok(&["info"])["server_info"]["lightning"]["bitcoin"].is_null());
	assert_eq!(a.ok(&["lightning", "pay", &inv])["payment"]["state"], "paid");
	assert_eq!(asked(&log).unwrap(), calls(&[&["lightning", "pay", "invoice", &inv, "--wait"],
		&["lightning", "pay", "status", &inv, "--no-sync"]]));
	let _ = std::fs::remove_dir_all(&a.dir);
	let _ = std::fs::remove_dir_all(&dir);
}
