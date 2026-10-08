//! The Bitcoin side of Lightning, at its boundary. Native BTC goes over
//! Lightning through Bark's own Lightning leg, on the wallet's Bitcoin ark
//! wallet, against the Bitcoin ark the operator names (`info`'s
//! `lightning.bitcoin.ark`); never through a Sequentia leaf. That ark, Bark's
//! server on the Bitcoin network the chain anchors to, does not run yet, so
//! `bark` here is a stand-in that records what it is asked and answers as
//! Bark does. The test checks the exact calls the wallet makes of Bark, that
//! it makes none while the operator names no ark or the wallet has no
//! Bitcoin ark wallet, and that a Bitcoin invoice is never paid from a
//! Sequentia leaf.
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

/// What the stand-in for Bark was asked last, one argument a line, and
/// clears it; `None` when it was not run.
fn asked(log: &PathBuf) -> Option<Vec<String>> {
	let s = std::fs::read_to_string(log).ok()?;
	std::fs::remove_file(log).unwrap();
	Some(s.lines().map(|l| l.to_string()).collect())
}

#[tokio::test(flavor = "multi_thread")]
async fn native_btc_goes_through_barks_leg_on_the_operators_bitcoin_ark() {
	// The stand-in for Bark: it writes its arguments down and answers JSON.
	let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("bark-standin-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let (exe, log) = (dir.join("bark"), dir.join("asked"));
	std::fs::write(&exe, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\necho '{{\"stand_in\": true}}'\n", log.display())).unwrap();
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
	assert_eq!(asked(&log), None);

	// With one, each flow is exactly one call of Bark's Lightning leg.
	let bitcoin = a.dir.join("bitcoin");
	std::fs::create_dir_all(&bitcoin).unwrap();
	let d = bitcoin.display().to_string();
	let paid = a.ok(&["lightning", "pay", &inv]);
	assert_eq!((paid["side"].as_str(), paid["ark"].as_str(), &paid["bark"]["stand_in"]), (Some("bitcoin"), Some(ark), &serde_json::json!(true)));
	assert_eq!(asked(&log).unwrap(), vec!["--datadir", &d, "--quiet", "lightning", "pay", "invoice", &inv, "--wait"]);
	let paid = a.ok(&["lightning", "pay", &inv, "--asset", "BTC"]);
	assert_eq!(paid["side"], "bitcoin");
	assert_eq!(asked(&log).unwrap(), vec!["--datadir", &d, "--quiet", "lightning", "pay", "invoice", &inv, "--wait"]);
	let got = a.ok(&["lightning", "receive", "btc", "1000", "--description", "a coffee"]);
	assert_eq!(got["side"], "bitcoin");
	assert_eq!(asked(&log).unwrap(), vec!["--datadir", &d, "--quiet", "lightning", "invoice", "1000 sats", "--description", "a coffee"]);

	// A Bitcoin invoice is never paid from a Sequentia leaf: asked to, the
	// wallet refuses before anything is signed, and Bark is not run.
	a.refused(&["lightning", "pay", &inv, "--asset", &x], "paid in native BTC");
	assert_eq!(asked(&log), None);
	assert!(a.ok(&["lightning", "payments"]).as_object().unwrap().is_empty(), "nothing paid on the Sequentia side");
	assert!(a.ok(&["lightning", "receives"]).as_object().unwrap().is_empty(), "nothing asked on the Sequentia side");

	// An operator that names no Bitcoin ark (its [lightning] section, which
	// takes a restart): refused, with the reason.
	r.config.lightning.bitcoin = None;
	r.restart_server().await;
	assert!(a.ok(&["info"])["server_info"]["lightning"]["bitcoin"].is_null());
	a.refused(&["lightning", "pay", &inv], "names no Bitcoin ark");
	a.refused(&["lightning", "receive", "btc", "1000"], "names no Bitcoin ark");
	assert_eq!(asked(&log), None);
	let _ = std::fs::remove_dir_all(&a.dir);
	let _ = std::fs::remove_dir_all(&dir);
}
