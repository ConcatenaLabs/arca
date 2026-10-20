//! The wallet's Bitcoin side: Bark's own wallet for Bitcoin arks, in
//! `<datadir>/bitcoin`, run as Bark ships it. BTC there is native bitcoin in
//! a Bitcoin ark (Bark's server, on the Bitcoin network the chain anchors to),
//! never a Sequentia leaf.
//!
//! The wallet runs Bark's `bark` once per call, as a user would, and `barkd`
//! once, for the create: Bark's command line takes a mnemonic to restore only
//! as an argument, which other users of the machine can read, while `barkd`
//! takes it in a request body. So `create` starts `barkd` on a loopback port
//! with the Bitcoin ark wallet's directory, sends it the Arca wallet's own
//! mnemonic under the token `barkd` wrote there, and stops it.
//!
//! The three Lightning calls follow what Bark does, not what it prints:
//! - `bark lightning pay invoice INVOICE --wait` prints nothing; the payment's
//!   outcome is read back with `bark lightning pay status INVOICE`.
//! - A received payment is held by Bark's server only until the wallet claims
//!   it (`bark lightning claim INVOICE --wait`, run while the payer pays), and
//!   failed back to the payer otherwise.
//! - A claim the server refuses because the payment's lock time is too close
//!   ("too close to inbound HTLC expiry"), or one whose receive Bark no longer
//!   holds because the server failed the payment back when blocks came before
//!   the claim, cannot succeed later. The wallet then asks for a fresh invoice
//!   of the same amount and description for the payer to pay instead.

use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bark::arca::Error;
use serde_json::{json, Value};

/// Bark's binary: the one `ARCA_BARK_EXEC` names, else the one beside this
/// one.
pub fn bark_exe() -> PathBuf {
	if let Some(p) = std::env::var_os("ARCA_BARK_EXEC") {
		return PathBuf::from(p);
	}
	beside("bark")
}

/// Bark's daemon: the one `ARCA_BARKD_EXEC` names, else the one beside
/// `bark`.
pub fn barkd_exe() -> PathBuf {
	if let Some(p) = std::env::var_os("ARCA_BARKD_EXEC") {
		return PathBuf::from(p);
	}
	let bark = bark_exe();
	let name = if cfg!(windows) { "barkd.exe" } else { "barkd" };
	bark.parent().map(|d| d.join(name)).unwrap_or_else(|| PathBuf::from(name))
}

fn beside(name: &str) -> PathBuf {
	let name = if cfg!(windows) { format!("{}.exe", name) } else { name.to_string() };
	std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join(&name))).unwrap_or_else(|| PathBuf::from(name))
}

/// The Bitcoin ark wallet's directory.
pub fn dir(datadir: &Path) -> PathBuf {
	datadir.join("bitcoin")
}

/// Whether the wallet has a Bitcoin ark wallet.
pub fn has_wallet(datadir: &Path) -> bool {
	dir(datadir).join("mnemonic").exists()
}

fn no_wallet() -> Error {
	Error::Refused("the wallet has no Bitcoin ark wallet: create one with `arca bitcoin create`, which joins a Bitcoin ark from \
		this wallet's own mnemonic; nothing is signed".into())
}

/// Bark's words when it refused: its standard error, without its log
/// prefixes, or what it printed.
fn barks_words(out: &std::process::Output) -> String {
	let err = String::from_utf8_lossy(&out.stderr);
	let text = err.trim();
	let text = if text.is_empty() { String::from_utf8_lossy(&out.stdout).trim().to_string() } else { text.to_string() };
	text.strip_prefix("Error: ").unwrap_or(&text).to_string()
}

/// One quiet run of `bark` on the Bitcoin ark wallet: what it printed, or
/// its refusal in its own words.
fn bark(datadir: &Path, args: &[&str]) -> Result<Vec<u8>, Error> {
	let out = Command::new(bark_exe()).arg("--datadir").arg(dir(datadir)).arg("--quiet").args(args)
		.stdin(Stdio::null()).output()
		.map_err(|e| Error::Io(format!("cannot run Bark ({}): {}", bark_exe().display(), e)))?;
	if !out.status.success() {
		return Err(Error::Refused(format!("Bark refused it: {}", barks_words(&out))));
	}
	Ok(out.stdout)
}

/// The same, its JSON; a bare string (as `bark address` prints) as a string.
fn bark_json(datadir: &Path, args: &[&str]) -> Result<Value, Error> {
	let out = bark(datadir, args)?;
	Ok(serde_json::from_slice(&out).unwrap_or_else(|_| json!(String::from_utf8_lossy(&out).trim())))
}

/// The Bitcoin side's balance: Bark's ark balance and its on-chain wallet's,
/// or why there is none.
pub fn balance(datadir: &Path) -> Value {
	if !has_wallet(datadir) {
		return json!({"wallet": null, "note": "no Bitcoin ark wallet yet: create one with `arca bitcoin create`"});
	}
	let ark = bark_json(datadir, &["balance"]);
	let onchain = bark_json(datadir, &["onchain", "balance"]);
	match (ark, onchain) {
		(Ok(ark), Ok(onchain)) => json!({"wallet": dir(datadir).display().to_string(), "ark": ark, "onchain": onchain}),
		(a, o) => {
			let why = [a.err(), o.err()].into_iter().flatten().map(|e| e.to_string()).collect::<Vec<_>>().join("; ");
			json!({"wallet": dir(datadir).display().to_string(), "error": why})
		},
	}
}

/// What the Bitcoin side holds, in satoshis: every amount of the ark balance
/// (spendable, pending in a round, a board, an exit, a Lightning payment
/// either way) and the on-chain wallet's total. `None` when it could not be
/// read.
pub fn total_sat(b: &Value) -> Option<u64> {
	if b["left_out"] == json!(true) {
		return None;
	}
	if b["wallet"].is_null() && b["error"].is_null() {
		return Some(0);
	}
	let ark = b["ark"].as_object()?;
	let sum: u64 = ark.iter().filter(|(k, _)| k.ends_with("_sat")).filter_map(|(_, v)| v.as_u64()).sum();
	Some(sum + b["onchain"]["total_sat"].as_u64()?)
}

/// Pays a BOLT11 invoice in native BTC from the Bitcoin ark wallet, and reads
/// back how the payment stands: `pay invoice … --wait` prints nothing.
pub fn pay(datadir: &Path, invoice: &str) -> Result<Value, Error> {
	if !has_wallet(datadir) {
		return Err(no_wallet());
	}
	let paid = bark(datadir, &["lightning", "pay", "invoice", invoice, "--wait"]);
	let status = bark_json(datadir, &["lightning", "pay", "status", invoice, "--no-sync"]);
	match (paid, status) {
		(Ok(_), Ok(status)) => Ok(json!({"side": "bitcoin", "invoice": invoice, "payment": status})),
		(Ok(_), Err(e)) => Ok(json!({"side": "bitcoin", "invoice": invoice, "payment": null, "note": format!(
			"Bark paid without an error, and its status could not be read: {}", e)})),
		(Err(e), Ok(status)) => Err(Error::Refused(format!("{}; the payment stands: {}", e, status))),
		(Err(e), Err(_)) => Err(e),
	}
}

/// An invoice for `sats` satoshis on the Bitcoin ark wallet.
pub fn invoice(datadir: &Path, sats: u64, description: Option<&str>) -> Result<Value, Error> {
	if !has_wallet(datadir) {
		return Err(no_wallet());
	}
	let amount = format!("{} sats", sats);
	let mut args = vec!["lightning", "invoice", amount.as_str()];
	if let Some(d) = description {
		args.extend(["--description", d]);
	}
	let v = bark_json(datadir, &args)?;
	let inv = v["invoice"].as_str().ok_or_else(|| Error::Refused(format!("Bark made no invoice: {}", v)))?.to_string();
	Ok(json!({"side": "bitcoin", "invoice": inv, "amount_sat": sats,
		"next": format!("claim it while the payer pays: `arca lightning claim {}`. Bark's server holds a payment only until the \
			wallet claims it, and fails it back to the payer otherwise", inv)}))
}

/// Asks Bark to stop the process, and makes sure it has.
fn stop(child: &mut Child) {
	#[cfg(unix)]
	{
		let _ = Command::new("kill").arg("-TERM").arg(child.id().to_string()).stdin(Stdio::null())
			.stdout(Stdio::null()).stderr(Stdio::null()).status();
		let until = Instant::now() + Duration::from_secs(10);
		while Instant::now() < until {
			if let Ok(Some(_)) = child.try_wait() {
				return;
			}
			std::thread::sleep(Duration::from_millis(100));
		}
	}
	let _ = child.kill();
	let _ = child.wait();
}

/// Claims a payment to the Bitcoin ark wallet's invoice: waits up to `wait`
/// for the payer's payment and claims it at once. Answers its state:
/// `claimed`; `waiting` (no payment came: claim again while the payer may
/// still pay); or `reissued`, with a fresh invoice of the same amount and
/// description, when the payment can no longer be claimed: the server
/// refused the claim as too close to the payment's expiry, or failed the
/// payment back to the payer already.
pub fn claim(datadir: &Path, invoice: &str, wait: Duration) -> Result<Value, Error> {
	if !has_wallet(datadir) {
		return Err(no_wallet());
	}
	let parsed = bark::arca::lightning::parse_invoice(invoice)?;
	let mut child = Command::new(bark_exe()).arg("--datadir").arg(dir(datadir)).arg("--quiet")
		.args(["lightning", "claim", invoice, "--wait"])
		.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
		.map_err(|e| Error::Io(format!("cannot run Bark ({}): {}", bark_exe().display(), e)))?;
	let mut err = child.stderr.take().expect("piped");
	let errs = std::thread::spawn(move || { let mut s = String::new(); let _ = err.read_to_string(&mut s); s });
	let mut out = child.stdout.take().expect("piped");
	let outs = std::thread::spawn(move || { let mut s = String::new(); let _ = out.read_to_string(&mut s); s });
	let until = Instant::now() + wait;
	let status = loop {
		match child.try_wait() {
			Ok(Some(s)) => break Some(s),
			Ok(None) if Instant::now() >= until => { stop(&mut child); break None },
			Ok(None) => std::thread::sleep(Duration::from_millis(200)),
			Err(e) => return Err(Error::Io(format!("waiting for Bark's claim: {}", e))),
		}
	};
	let stderr = errs.join().unwrap_or_default();
	let stdout = outs.join().unwrap_or_default();
	let receive = || bark_json(datadir, &["lightning", "receive", "status", invoice, "--no-sync"]).ok();
	match status {
		None => Ok(json!({"side": "bitcoin", "state": "waiting", "invoice": invoice, "receive": receive(),
			"note": format!("no payment was claimed within {} s: claim again while the payer may still pay", wait.as_secs())})),
		Some(s) if s.success() => Ok(json!({"side": "bitcoin", "state": "claimed", "invoice": invoice, "receive": receive()})),
		Some(_) => {
			let words = { let t = stderr.trim(); let t = if t.is_empty() { stdout.trim() } else { t }; t.strip_prefix("Error: ").unwrap_or(t).to_string() };
			// Refused as too close to the payment's expiry, or the receive
			// gone from the wallet because the server failed the payment
			// back already: either way it is not claimable any more.
			if !(words.contains("too close") || words.contains("no pending lightning receive")) {
				return Err(Error::Refused(format!("Bark refused the claim: {}", words)));
			}
			if let Some(r) = receive().filter(|r| r["state"] == "settled") {
				return Ok(json!({"side": "bitcoin", "state": "claimed", "invoice": invoice, "receive": r}));
			}
			// The payment cannot be claimed any more and goes back to the
			// payer. A fresh invoice of the same amount and description.
			let sats = parsed.amount_msat.map(|m| m / 1000)
				.ok_or_else(|| Error::Refused(format!("Bark refused the claim: {}; the invoice names no amount to ask again", words)))?;
			// The old receive is over; Bark is told so, which may fail when
			// it knows it already.
			let _ = bark(datadir, &["lightning", "receive", "cancel", invoice]);
			let mut fresh = crate::bitcoin::invoice(datadir, sats, parsed.description.as_deref())?;
			fresh["state"] = json!("reissued");
			fresh["replaces"] = json!(invoice);
			fresh["why"] = json!(format!("Bark refused the claim: {}. That payment cannot be claimed any more and goes back to the payer; this is a fresh \
				invoice of the same amount for the payer to pay instead", words));
			Ok(fresh)
		},
	}
}

/// The options of `arca bitcoin create`.
pub struct CreateOpts {
	pub network: String,
	pub ark: String,
	pub bitcoind: Option<String>,
	pub bitcoind_cookie: Option<String>,
	pub bitcoind_user: Option<String>,
	pub bitcoind_password: Option<String>,
	pub esplora: Option<String>,
	pub birthday_height: Option<u32>,
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
fn base64(data: &[u8]) -> String {
	let mut s = String::new();
	for c in data.chunks(3) {
		let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
		let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
		for i in 0..4 {
			if i <= c.len() { s.push(BASE64[(n >> (18 - 6 * i) & 63) as usize] as char) } else { s.push('=') }
		}
	}
	s
}

/// The least Bitcoin Core Bark's client takes as its chain source.
pub const MIN_BITCOIND_VERSION: u64 = 29_00_00;

/// One call of the Bitcoin Core node's JSON-RPC: its result.
fn bitcoind_call(o: &CreateOpts, method: &str) -> Result<Value, Error> {
	let url = o.bitcoind.as_deref().unwrap_or("");
	let auth = match (&o.bitcoind_cookie, &o.bitcoind_user, &o.bitcoind_password) {
		(Some(c), _, _) => std::fs::read_to_string(c).map_err(|e| Error::Io(format!("{}: {}", c, e)))?.trim().to_string(),
		(None, Some(u), Some(p)) => format!("{}:{}", u, p),
		_ => return Err(Error::Parse("name the Bitcoin Core node's cookie (--bitcoind-cookie) or its user (--bitcoind-user) and \
			password (ARCA_BITCOIND_PASSWORD)".into())),
	};
	let body = json!({"jsonrpc": "1.0", "id": "arca", "method": method, "params": []}).to_string();
	let r = minreq::post(url).with_header("Authorization", format!("Basic {}", base64(auth.as_bytes())))
		.with_header("Content-Type", "application/json").with_body(body).with_timeout(30).send()
		.map_err(|e| Error::Io(format!("the Bitcoin Core node at {}: {}", url, e)))?;
	let v: Value = serde_json::from_slice(r.as_bytes())
		.map_err(|_| Error::Io(format!("the Bitcoin Core node at {} answered {} {}", url, r.status_code, r.as_str().unwrap_or(""))))?;
	if !v["error"].is_null() || v["result"].is_null() {
		return Err(Error::Io(format!("the Bitcoin Core node at {} answered {}", url, v)));
	}
	Ok(v["result"].clone())
}

/// The Bitcoin Core node is one Bark's client can use, and its tip: a
/// wallet made from a mnemonic scans its chain from a birthday, and a wallet
/// with no history on Bitcoin has none before now.
fn bitcoind_check(o: &CreateOpts) -> Result<u32, Error> {
	let net = bitcoind_call(o, "getnetworkinfo")?;
	let version = net["version"].as_u64().unwrap_or(0);
	if version < MIN_BITCOIND_VERSION {
		return Err(Error::Refused(format!("the Bitcoin Core node at {} is {} (version {}): Bark's client needs Bitcoin Core 29 or \
			later as its chain source, or an Esplora server; nothing was created", o.bitcoind.as_deref().unwrap_or(""),
			net["subversion"].as_str().unwrap_or("?"), version)));
	}
	let tip = bitcoind_call(o, "getblockcount")?;
	tip.as_u64().map(|h| h as u32).ok_or_else(|| Error::Io(format!("getblockcount answered {}", tip)))
}

/// A loopback port nothing listens on, outside Linux's ephemeral range.
fn free_port() -> Result<u16, Error> {
	let seed = std::process::id() as u16 ^ (Instant::now().elapsed().subsec_nanos() as u16);
	for i in 0..2000u16 {
		let p = 21000 + (seed.wrapping_add(i * 7)) % 9000;
		if TcpListener::bind(("127.0.0.1", p)).is_ok() {
			return Ok(p);
		}
	}
	Err(Error::Io("no free loopback port for barkd".into()))
}

/// Creates the Bitcoin ark wallet from the Arca wallet's own mnemonic: a new
/// wallet scans Bitcoin from now (or `birthday_height`); a restored one
/// recovers its ark coins from the server's recovery mailbox and its
/// on-chain coins from its birthday.
pub fn create(datadir: &Path, o: CreateOpts) -> Result<Value, Error> {
	let d = dir(datadir);
	if has_wallet(datadir) {
		return Err(Error::Refused(format!("the wallet has a Bitcoin ark wallet already, in {}", d.display())));
	}
	let mnemonic = std::fs::read_to_string(datadir.join("mnemonic")).map_err(|_| Error::Refused(format!(
		"no Arca wallet in {}: create it first (`arca create`); the Bitcoin ark wallet is made from its mnemonic", datadir.display())))?;
	let mnemonic = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
	let chain_source = match (&o.bitcoind, &o.esplora) {
		(Some(url), None) => {
			let auth = match (&o.bitcoind_cookie, &o.bitcoind_user, &o.bitcoind_password) {
				(Some(c), _, _) => json!({"cookie": {"cookie": c}}),
				(None, Some(u), Some(p)) => json!({"user-pass": {"user": u, "pass": p}}),
				_ => return Err(Error::Parse("name the Bitcoin Core node's cookie (--bitcoind-cookie) or its user (--bitcoind-user) \
					and password (ARCA_BITCOIND_PASSWORD)".into())),
			};
			json!({"bitcoind": {"bitcoind": url, "bitcoind_auth": auth}})
		},
		(None, Some(url)) => json!({"esplora": {"url": url}}),
		_ => return Err(Error::Parse("name one chain source: a Bitcoin Core node (--bitcoind, version 29 or later) or an Esplora \
			server (--esplora)".into())),
	};
	let birthday = match (o.birthday_height, &o.bitcoind) {
		(given, Some(_)) => { let tip = bitcoind_check(&o)?; Some(given.unwrap_or(tip)) },
		(given, None) => given,
	};
	std::fs::create_dir_all(&d).map_err(|e| Error::Io(format!("{}: {}", d.display(), e)))?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
	}
	let port = free_port()?;
	let mut cmd = Command::new(barkd_exe());
	cmd.arg("--datadir").arg(&d).arg("--port").arg(port.to_string()).arg("--quiet")
		.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
	for (k, _) in std::env::vars_os() {
		if k.to_string_lossy().starts_with("BARKD_") {
			cmd.env_remove(k);
		}
	}
	let mut barkd = cmd.spawn().map_err(|e| Error::Io(format!("cannot run Bark's daemon ({}): {}", barkd_exe().display(), e)))?;
	let token_file = d.join("auth_token");
	let result = (|| {
		let addr = SocketAddr::from(([127, 0, 0, 1], port));
		let until = Instant::now() + Duration::from_secs(60);
		loop {
			if let Ok(Some(s)) = barkd.try_wait() {
				return Err(Error::Io(format!("Bark's daemon stopped ({}) before the wallet was made", s)));
			}
			if token_file.exists() && TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
				break;
			}
			if Instant::now() >= until {
				return Err(Error::Io("Bark's daemon did not start within 60 s".into()));
			}
			std::thread::sleep(Duration::from_millis(200));
		}
		let token = std::fs::read_to_string(&token_file).map_err(|e| Error::Io(format!("{}: {}", token_file.display(), e)))?;
		let body = json!({"ark_server": o.ark, "chain_source": chain_source, "mnemonic": mnemonic, "network": o.network,
			"birthday_height": birthday});
		let r = minreq::post(format!("http://127.0.0.1:{}/api/v1/wallet/create", port))
			.with_header("Authorization", format!("Bearer {}", token.trim())).with_header("Content-Type", "application/json")
			.with_body(body.to_string()).with_timeout(600).send()
			.map_err(|e| Error::Io(format!("Bark's daemon: {}", e)))?;
		if r.status_code != 200 {
			let v: Value = serde_json::from_slice(r.as_bytes()).unwrap_or_else(|_| json!(r.as_str().unwrap_or("")));
			let why = v["message"].as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string());
			return Err(Error::Refused(format!("Bark refused it: {}", why)));
		}
		let v: Value = serde_json::from_slice(r.as_bytes()).unwrap_or(Value::Null);
		Ok(v["fingerprint"].clone())
	})();
	stop(&mut barkd);
	// The token served this one create; nothing needs it after.
	let _ = std::fs::remove_file(&token_file);
	let fingerprint = result?;
	let info = bark_json(datadir, &["ark-info"])?;
	let mut source = chain_source;
	if let Some(a) = source["bitcoind"]["bitcoind_auth"].get_mut("user-pass") {
		a["pass"] = json!("(withheld)");
	}
	Ok(json!({"side": "bitcoin", "wallet": d.display().to_string(), "network": o.network, "ark": o.ark, "chain_source": source,
		"birthday_height": birthday, "fingerprint": fingerprint,
		"ark_info": {"network": info["network"], "server_pubkey": info["server_pubkey"], "round_interval": info["round_interval"],
			"vtxo_exit_delta": info["vtxo_exit_delta"], "vtxo_lifetime": info["vtxo_lifetime"]},
		"note": "the Bitcoin ark wallet is made from this wallet's own mnemonic: restoring the mnemonic restores both sides"}))
}

#[cfg(test)]
mod test {
	#[test]
	fn base64_of_cookie() {
		assert_eq!(super::base64(b"__cookie__:abc"), "X19jb29raWVfXzphYmM=");
		assert_eq!(super::base64(b"ab"), "YWI=");
		assert_eq!(super::base64(b"abc"), "YWJj");
	}
}
