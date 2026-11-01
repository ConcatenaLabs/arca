//! A whole Arca server on an anchored proof-of-stake regtest chain, kept
//! running for a wallet driven from outside this process: a browser wallet
//! built on the wallet library's wasm package (`wallet-wasm/`), or anything
//! else that speaks the server's HTTP and the node's JSON-RPC.
//!
//! It is the scenarios' server (`tests/common/running.rs`): asset X listed
//! for fees on the node, asset Y not, rounds built only when asked, leaves
//! with exit delays from one 512-second unit. It is ignored by default and
//! runs until it is told to stop:
//!
//! ```sh
//! ARCA_OPERATOR_CONTROL=127.0.0.1:18640 \
//!   cargo test -p arca-cli --test arca_operator_for_browsers -- --ignored --nocapture
//! ```
//!
//! with `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` as for the
//! scenarios (`tests/common/mod.rs`). It writes nothing a browser must read:
//! `GET /state` on the control address answers with the server's URL, the
//! node's RPC URL and credentials, the two assets, the chain's genesis hash,
//! and the file of the test operator key (for `arca-signer
//! --sign-operator-record`). The control address
//! takes, each a `POST` whose body is a JSON object:
//!
//! | Path | Does |
//! |---|---|
//! | `/fund {script, asset, amount}` | Pays `amount` of `asset` to the script (hex) from the test's coins, broadcast |
//! | `/fund_server {asset, amount}` | Pays `amount` of `asset` to the operator's own wallet, which funds its rounds, from the test's coins, broadcast |
//! | `/produce` | Produces one block |
//! | `/bury` | Buries the chain two Bitcoin blocks deep and waits for the server to follow |
//! | `/round` | Builds a round of whatever participations stand, mines it, buries it and waits for it to be final; its txid, or `null` when none stood |
//! | `/advance {seconds}` | Moves the chain's median time at least that far on |
//! | `/rpc {method, params}` | One call to the node, its result |
//! | `/fees {asset, refresh_ppm?, offboard_base?}` | Sets the asset's refresh fee, or the fixed part of its offboard fee (what a take pays), and reloads the server's configuration, as an operator's SIGHUP does |
//! | `/build` | Builds the rounds of whatever participations stand, and broadcasts none that waits on a take's forfeits: their txids, sizes and the orders each fills |
//! | `/pass` | One pass over the rounds: a round held for takes' forfeits goes out once every one is in |
//! | `/settle` | One pass of the watcher (releases, notices, sweeps, the return of unclaimed claims), a block buried two Bitcoin blocks deep, one pass of the nursery and another of the watcher, as an operator's timers do between them; the chain's tip |
//! | `/round_state {txid}` | Where the server says the round stands: built, broadcast, final or lost |
//! | `/orphan {height}` | Reorganises the parent chain from that height (an anchor rollback): every block anchored there or above leaves the chain |
//! | `/restart` | Stops the server and starts it again on the same database, at the same address, as an operator's restart does; the chain and the signer keep running |
//! | `/freeze {script}` | A freeze record of the supervised asset naming the script (hex), signed by its issuer and mined |
//! | `/lift {script}` | Spends that record, lifting the freeze, and mines it |
//! | `/bond_post {amount?}` | Posts the operator's equivocation bond in X (5,000,000 unless named), names it in the configuration, and starts the server again |
//! | `/bond_notice` | Gives the bond's notice, names it, and starts the server again: the bond reads `noticed` |
//! | `/bond_drop` | Names no bond in the configuration, and starts the server again: a wallet that saw one reads it `missing` |
//! | `/quit` | Stops the server, the signer and the chain, and ends the test |
//!
//! A browser wallet that bonds a stake on this chain (a stake carries no
//! committee key) needs the committee to outweigh it, or sortition picks no
//! committee member and no block is made: set
//! `SEQUENTIA_REGTEST_COMMITTEE_STAKE` to each committee staker's weight in
//! atoms, well above the stakes the wallet bonds (one atom when unset).
//!
//! With `ARCA_OPERATOR_SUPERVISED` set, the chain issues an asset Z under
//! the supervision descriptor (pause allowed, listed for fees at 1:1), and
//! the operator serves it under the supervised profile, its signer reading
//! freezes from the chain's node; `/state` names it `supervised`. Set to a
//! count `n`, it issues `n` such assets (Z, Z1, …), all named in
//! `supervised_all`; `/freeze` and `/lift` act on Z. With
//! `ARCA_OPERATOR_MORE_ASSETS` set to a count `n`, the chain issues `n`
//! plain assets beyond X and Y (listed for fees at 1:1) and the operator
//! serves them; `/state` names them `more`, and every asset served in
//! `assets`. With `ARCA_OPERATOR_LIGHTNING` as well, each of them gets a
//! Lightning leg as X has (a channel of 10^12 atoms between the same two
//! nodes). With
//! `ARCA_OPERATOR_ISSUER` set (and `MINT_LIMITER`, the mint limiter's tool
//! of `sequentia-contracts` with `sign`), the chain runs Simplicity and the
//! operator serves an asset I issuer-operated, its reissuance token in a
//! mint limiter the signer mints through; `/state` names it `issuer`.
//!
//! With `ARCA_OPERATOR_NO_SWEEP` set to a number of seconds, the operator
//! builds every batch without a sweep (`[batches] no_sweep`), each collected
//! on the chain that long after its round (`collect_after_seconds`): every
//! refresh round is held until its forfeits are in, so drive it with
//! `/build`, the wallets' syncs, `/pass`, then `/produce` and `/bury`, and
//! the collection with `/advance` and `/settle`. It applies without
//! `ARCA_OPERATOR_LIGHTNING` and `ARCA_OPERATOR_ISSUER` only.
//!
//! With `ARCA_OPERATOR_CHANNELS` set to a capacity in atoms, the operator
//! makes channel leaves (`channel-1`) of every plain asset it serves, with up
//! to that much on its side of each.
//!
//! With `ARCA_OPERATOR_LIGHTNING` set (and `LIGHTNINGD_EXEC`, a SeqLN
//! `lightningd`), the chain is the one SeqLN's `sequentia-regtest` network
//! assumes and the operator runs a SeqLN node in X that receives, with a
//! channel to a node of its own, as the Lightning scenarios do; its payments
//! out of the tree time out four to eight days out, which a swap of BTC for
//! an asset (`arca btc-swap`) needs between wallets with the specification's
//! 36-hour exit delays against a Bitcoin ark's 88-hour HTLC delays. `/state`
//! then says `lightning: true`, and names the two nodes (`x_lightning:
//! {operator, peer}`, each its socket `rpc`, its `id` and `addr`), so that a
//! second operator's SeqLN node can open a channel to them. `/state` names
//! the chain (`chain`) and the node's data directory (`node_datadir`) in
//! every mode.
//!
//! With `ARCA_OPERATOR_BTC_LIGHTNING` set to a count `n` as well (and
//! `BITCOIND_EXEC`, a Bitcoin Core `bitcoind` with `bitcoin-cli` beside it),
//! a Bitcoin regtest chain runs beside it with `n + 1` Lightning nodes on
//! Bitcoin: a hub, for a maker of BTC, with a channel of 10,000,000 sat to
//! each of the other `n`, half of it pushed to them, one for each wallet
//! that trades BTC for an asset under one hash. `/state` then names their
//! sockets (`btc_lightning: {hub, wallets}`), and `/btc_mine` (`{blocks}`)
//! mines blocks on Bitcoin.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;
use std::time::Duration;

use elements::{AssetId, Script};
use serde_json::{json, Value};

use arca_covenant::bond::BondPolicy;
use arca_covenant::limiter::{self, LimiterParams, LimiterState};
use arca_covenant::RelativeTime;
use common::node::{self, op_true};
use common::running::{keypair, Running};
use elements::encode::{deserialize, serialize};
use elements::hashes::Hash;
use elements::secp256k1_zkp::Keypair;
use elements::{AssetIssuance, ContractHash, OutPoint, Transaction, TxIn};
use sequentia_ext::{explicit_txout, AssetAmount};
use server::bond::BondSection;
use server::issuer::IssuerSection;
use server::server::AssetSection;
use sequentia_ext::lightning::{BitcoinRegtest, LightningNode};
use server::store::RoundState;

/// One request: its path and its JSON body.
fn read_request(s: &mut TcpStream) -> Option<(String, String, Value)> {
	s.set_nonblocking(false).ok()?;
	s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
	let mut buf = vec![];
	let mut chunk = [0u8; 4096];
	let head_end = loop {
		let n = s.read(&mut chunk).ok()?;
		if n == 0 {
			return None;
		}
		buf.extend_from_slice(&chunk[..n]);
		if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
			break i + 4;
		}
	};
	let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
	let mut lines = head.lines();
	let mut first = lines.next()?.split_whitespace();
	let (method, path) = (first.next()?.to_string(), first.next()?.to_string());
	let len: usize = lines.filter_map(|l| l.split_once(':')).find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
		.and_then(|(_, v)| v.trim().parse().ok()).unwrap_or(0);
	while buf.len() < head_end + len {
		let n = s.read(&mut chunk).ok()?;
		if n == 0 {
			break;
		}
		buf.extend_from_slice(&chunk[..n]);
	}
	let body = &buf[head_end..(head_end + len).min(buf.len())];
	let json = if body.is_empty() { json!({}) } else { serde_json::from_slice(body).unwrap_or(Value::Null) };
	Some((method, path, json))
}

fn answer(s: &mut TcpStream, status: u16, v: &Value) {
	let body = v.to_string();
	let _ = write!(s, "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
		status, if status == 200 { "OK" } else { "Error" }, body.len(), body);
}

fn script(h: &str) -> Result<Script, String> {
	if h.len() % 2 != 0 {
		return Err("the script is not hex".into());
	}
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).map_err(|e| e.to_string()))
		.collect::<Result<Vec<u8>, _>>().map(Script::from)
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(h: &str) -> Result<Vec<u8>, String> {
	script(h).map(|s| s.into_bytes())
}

/// What the operator serves beyond X and Y: supervised assets and the first
/// one's freeze records, an issuer-operated asset, plain assets, and its bond.
#[derive(Default)]
struct Profiles {
	/// The (first) supervised asset and its issuer's operational key.
	supervised: Option<(AssetId, Keypair)>,
	/// Every supervised asset, the first one included.
	supervised_all: Vec<AssetId>,
	/// The plain assets served beyond X and Y.
	more: Vec<AssetId>,
	/// Each standing freeze record, by the script it names.
	freezes: std::collections::HashMap<String, (OutPoint, String)>,
	/// The issuer-operated asset.
	issuer: Option<AssetId>,
	/// The bond's notice key and outpoint, once posted.
	bond: Option<(Keypair, OutPoint)>,
}

/// Z (the `i`th supervised asset; the first is named Z), 1,000,000 units, issued under the
/// supervision descriptor with the pause capability into the purse, and
/// listed for fees at 1:1.
fn issue_supervised(r: &mut Running, i: usize) -> (AssetId, Keypair) {
	let name = if i == 0 { "Z".to_string() } else { format!("Z{}", i) };
	let op = keypair(&format!("{} operational", name));
	let rec = keypair(&format!("{} recovery", name));
	let coin = r.purse.take_coin(r.purse.policy);
	let tx = node::spend_op_true(&coin, vec![], 20_000);
	let parked = Script::new_v0_wpkh(&elements::WPubkeyHash::from_byte_array([1; 20]));
	let d: Value = r.rt.client().call("decodescript", &[json!(hex(parked.as_bytes()))]).unwrap();
	let to = d["address"].as_str().or_else(|| d["segwit"]["address"].as_str()).unwrap().to_string();
	let issued: Value = r.rt.client().call("rawissueasset", &[json!(hex(&serialize(&tx))), json!([{
		"asset_amount": 1_000_000, "asset_address": to, "token_amount": 1, "token_address": to, "blind": false,
		"supervision": {"operationalkey": hex(&op.x_only_public_key().0.serialize()),
			"recoverykey": hex(&rec.x_only_public_key().0.serialize()), "pause": true},
	}])]).unwrap();
	let mut tx: Transaction = deserialize(&unhex(issued[0]["hex"].as_str().unwrap()).unwrap()).unwrap();
	let z = AssetId::from_str(issued[0]["asset"].as_str().unwrap()).unwrap();
	for o in tx.output.iter_mut() {
		if o.script_pubkey == parked {
			o.script_pubkey = op_true();
		}
	}
	let txid = r.rt.client().send_raw_transaction(&tx).unwrap();
	r.rt.produce_block().unwrap();
	for (j, o) in tx.output.iter().enumerate() {
		if o.script_pubkey == op_true() && !o.is_fee() {
			r.purse.put((OutPoint::new(txid, j as u32), o.clone()));
		}
	}
	node::list_fee_asset(&r.rt, z, 100_000_000);
	(z, op)
}

/// A BIP340 signature by `key` over `digest`.
fn sign(key: &Keypair, digest: &[u8]) -> Result<String, String> {
	let d: [u8; 32] = digest.try_into().map_err(|_| "a digest of 32 bytes".to_string())?;
	Ok(hex(arca_covenant::sign::sign_digest(key, &d, &[0; 32]).as_ref()))
}

/// A freeze record of `z` naming `target`, signed and mined: its outpoint
/// and the target's hash.
fn freeze(r: &mut Running, z: AssetId, op: &Keypair, target: &Script) -> Result<(OutPoint, String), String> {
	let coin = r.purse.take_coin(r.purse.policy);
	let t = json!(hex(target.as_bytes()));
	let c = r.rt.client();
	let h: Value = c.call("getsupervisionrecordhash", &[json!("freeze"), json!(z.to_string()), t.clone(), Value::Null,
		json!(coin.0.txid.to_string()), json!(coin.0.vout)]).map_err(|e| e.to_string())?;
	let built: Value = c.call("buildsupervisionrecord", &[json!("freeze"), json!(z.to_string()), t, Value::Null,
		json!(sign(op, &unhex(h["sighash"].as_str().ok_or("no sighash")?)?)?)]).map_err(|e| e.to_string())?;
	let tx = node::spend_op_true(&coin, vec![], 20_000);
	let raw: Value = c.call("addsupervisionrecordoutput", &[json!(hex(&serialize(&tx))), built["script"].clone(), json!(z.to_string())])
		.map_err(|e| e.to_string())?;
	let tx: Transaction = deserialize(&unhex(raw.as_str().ok_or("no transaction")?)?).map_err(|e| e.to_string())?;
	let txid = c.send_raw_transaction(&tx).map_err(|e| e.to_string())?;
	r.rt.produce_block().map_err(|e| e.to_string())?;
	let record = unhex(built["script"].as_str().ok_or("no record")?)?;
	let mut at = None;
	for (j, o) in tx.output.iter().enumerate() {
		if o.script_pubkey.as_bytes() == &record[..] {
			at = Some(OutPoint::new(txid, j as u32));
		} else if o.script_pubkey == op_true() {
			r.purse.put((OutPoint::new(txid, j as u32), o.clone()));
		}
	}
	let at = at.ok_or("no record output")?;
	Ok((at, built["targethash"].as_str().ok_or("no target hash")?.to_string()))
}

/// Spends the freeze record at `at`, whose target hashes to `target`, and
/// mines it.
fn lift(r: &mut Running, z: AssetId, op: &Keypair, at: OutPoint, target: &str) -> Result<String, String> {
	let c = r.rt.client();
	let h: Value = c.call("getsupervisionunfreezehash", &[json!(at.txid.to_string()), json!(at.vout), json!(z.to_string()),
		json!(target)]).map_err(|e| e.to_string())?;
	let coin = r.purse.take_coin(r.purse.policy);
	let mut tx = node::spend_op_true(&coin, vec![], 20_000);
	tx.input.insert(0, TxIn { previous_output: at, ..Default::default() });
	let raw: Value = c.call("setsupervisionunfreezesig", &[json!(hex(&serialize(&tx))), json!(0),
		json!(sign(op, &unhex(h.as_str().ok_or("no digest")?)?)?)]).map_err(|e| e.to_string())?;
	let tx: Transaction = deserialize(&unhex(raw.as_str().ok_or("no transaction")?)?).map_err(|e| e.to_string())?;
	let txid = c.send_raw_transaction(&tx).map_err(|e| e.to_string())?;
	r.rt.produce_block().map_err(|e| e.to_string())?;
	for (j, o) in tx.output.iter().enumerate() {
		if o.script_pubkey == op_true() {
			r.purse.put((OutPoint::new(txid, j as u32), o.clone()));
		}
	}
	Ok(txid.to_string())
}

fn limiter_tool() -> std::path::PathBuf {
	std::path::PathBuf::from(std::env::var("MINT_LIMITER").expect("ARCA_OPERATOR_ISSUER needs MINT_LIMITER, the mint limiter's tool \
		(sequentia-contracts tools/mint-limiter, with `sign`)"))
}

fn limiter_json(args: &[&str]) -> Value {
	let out = std::process::Command::new(limiter_tool()).args(args).output().unwrap();
	assert!(out.status.success(), "mint-limiter {:?}: {}", args, String::from_utf8_lossy(&out.stderr));
	serde_json::from_slice(&out.stdout).unwrap()
}

/// I, issued with one explicit atom of reissuance token straight into a new
/// mint limiter: the limiter's instance, its words and the coin's outpoint.
fn issue_issuer_operated(r: &mut Running, dir: &std::path::Path) -> (AssetId, IssuerSection, std::path::PathBuf) {
	let words = dir.join("mint.words");
	let op = limiter_json(&["key", "--new", "--mnemonic-file", words.to_str().unwrap()])["key"].as_str().unwrap().to_string();
	let cold = keypair("I's cold key").x_only_public_key().0.to_string();
	let coin = r.purse.take_coin(r.purse.policy);
	let contract = arca_covenant::script::sha256(b"asset I, issuer-operated, for browser wallets");
	let i = AssetId::new_issuance(coin.0, ContractHash::from_byte_array(contract));
	let entropy = AssetId::generate_asset_entropy(coin.0, ContractHash::from_byte_array(contract)).to_byte_array();
	let entropy_hex = elements::hashes::sha256::Midstate::from_byte_array(entropy).to_string();
	let genesis = r.rt.client().genesis_hash().unwrap();
	let inst = limiter_json(&["instance", "--asset", &i.to_string(), "--token", &limiter::token_of_entropy(entropy).to_string(),
		"--entropy", &entropy_hex, "--operator-key", &op, "--cold-key", &cold, "--window", "1000", "--allowance", "100000000",
		"--recovery-delay", "10", "--genesis", &genesis.to_string()]);
	let mut file = inst.clone();
	file.as_object_mut().unwrap().remove("address");
	let instance = dir.join("limiter.json");
	std::fs::write(&instance, file.to_string()).unwrap();
	let (l, _) = LimiterParams::from_instance_json(&file.to_string()).unwrap();
	let mut tx = node::spend_op_true(&coin, vec![
		explicit_txout(AssetAmount::new(i, 10_000_000_000), op_true()),
		explicit_txout(AssetAmount::new(l.token, 1), l.script_pubkey(LimiterState::default())),
	], 10_000);
	tx.input[0].asset_issuance = AssetIssuance {
		asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: contract,
		amount: elements::confidential::Value::Explicit(10_000_000_000), inflation_keys: elements::confidential::Value::Explicit(1),
		denomination: 8,
	};
	let txid = r.rt.client().send_raw_transaction(&tx).unwrap();
	r.rt.produce_block().unwrap();
	r.purse.put((OutPoint::new(txid, 0), tx.output[0].clone()));
	r.purse.put((OutPoint::new(txid, 2), tx.output[2].clone()));
	node::list_fee_asset(&r.rt, i, 100_000_000);
	(i, IssuerSection { limiter: instance.clone(), entropy: entropy_hex, coin: format!("{}:1", txid), state: None }, words)
}

/// A count from the environment: unset is 0, set to anything but a number 1.
fn env_count(name: &str) -> usize {
	std::env::var(name).ok().map(|v| v.trim().parse::<usize>().unwrap_or(1)).unwrap_or(0)
}

/// The server with what `ARCA_OPERATOR_SUPERVISED`, `ARCA_OPERATOR_ISSUER`
/// and `ARCA_OPERATOR_MORE_ASSETS` ask: the assets issued, the signer started
/// again reading freezes from the chain's node and minting through the
/// limiter, the assets served.
async fn serve_profiles(r: &mut Running, p: &mut Profiles) {
	let supervised = env_count("ARCA_OPERATOR_SUPERVISED");
	let issuer = std::env::var_os("ARCA_OPERATOR_ISSUER").is_some();
	let more = env_count("ARCA_OPERATOR_MORE_ASSETS");
	if supervised == 0 && !issuer && more == 0 {
		return;
	}
	let genesis = r.rt.client().genesis_hash().unwrap();
	let mut extra = vec!["--keeper-timeout-ms".to_string(), "2000".into()];
	let mut sections = vec![];
	if supervised > 0 {
		let cookie = r.signer.dir.join("node.cookie");
		std::fs::write(&cookie, "arca:arca").unwrap();
		extra.extend(["--supervision-node".to_string(), r.node_url(), "--supervision-cookie".into(), cookie.display().to_string()]);
		for i in 0..supervised {
			let (z, op) = tokio::task::block_in_place(|| issue_supervised(r, i));
			sections.push(AssetSection::new(z, common::running::MIN_LEAF));
			if i == 0 {
				p.supervised = Some((z, op));
			}
			p.supervised_all.push(z);
		}
	}
	for i in 0..more {
		let m = tokio::task::block_in_place(|| r.purse.issue(&r.rt, &format!("asset M{}", i), 100_000_000_000_000));
		node::list_fee_asset(&r.rt, m, 100_000_000);
		sections.push(AssetSection::new(m, common::running::MIN_LEAF));
		p.more.push(m);
	}
	if issuer {
		let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("browsers-issuer{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		let (i, section, words) = tokio::task::block_in_place(|| issue_issuer_operated(r, &dir));
		extra.extend(["--issuer".to_string(), format!("{}={}", section.limiter.display(), words.display()), "--mint-limiter".into(),
			limiter_tool().display().to_string()]);
		let mut a = AssetSection::new(i, 1_000);
		a.issuer = Some(section);
		sections.push(a);
		p.issuer = Some(i);
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	tokio::task::block_in_place(|| {
		r.signer.halt();
		r.signer.set_extra(extra);
		r.signer.resume(genesis);
	});
	let mut config = r.config.clone();
	config.assets.extend(sections);
	r.server.reload(&config).await.unwrap();
	r.config = config;
	for z in p.supervised_all.clone() {
		r.fund_server(z, 50_000_000).await;
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
}

/// The least notice delay at the default exit-delay bounds, in units.
fn notice_units() -> u16 {
	server::bond::min_notice_seconds(server::bond::LIFETIME, RelativeTime::from_units(338).unwrap()).div_ceil(512) as u16
}

/// The paths of the supervised asset and the bond.
async fn profile_handle(r: &mut Running, p: &mut Profiles, path: &str, b: &Value) -> Option<Result<Value, String>> {
	Some(match path {
		"/freeze" | "/lift" => {
			let Some((z, op)) = p.supervised.clone() else { return Some(Err("the operator serves no supervised asset".into())) };
			let target = match script(b["script"].as_str().unwrap_or("")) {
				Ok(t) if !t.is_empty() => t,
				_ => return Some(Err("name the script (hex)".into())),
			};
			let key = hex(target.as_bytes());
			let out = if path == "/freeze" {
				tokio::task::block_in_place(|| freeze(r, z, &op, &target)).map(|(at, th)| {
					p.freezes.insert(key.clone(), (at, th));
					json!({"record": format!("{}:{}", at.txid, at.vout)})
				})
			} else {
				match p.freezes.remove(&key) {
					Some((at, th)) => tokio::task::block_in_place(|| lift(r, z, &op, at, &th)).map(|t| json!({"lifted": t})),
					None => Err("no freeze stands for that script".into()),
				}
			};
			r.synced().await;
			out.and_then(|mut v| {
				v["status"] = r.rt.client().call::<Value>("isassetfrozen", &[json!(z.to_string()), json!(key)]).map_err(|e| e.to_string())?;
				Ok(v)
			})
		},
		"/bond_post" => {
			let amount = b["amount"].as_u64().unwrap_or(5_000_000);
			let w = keypair("browsers bond W");
			let chain = arca_covenant::Chain::new(r.rt.client().genesis_hash().unwrap());
			let policy = match BondPolicy::new(chain, keypair("operator").x_only_public_key().0, w.x_only_public_key().0,
				RelativeTime::from_units(notice_units()).unwrap()) {
				Ok(p) => p,
				Err(e) => return Some(Err(e.to_string())),
			};
			let x = r.x;
			let tx = r.pay_to(policy.script_pubkey(), x, amount);
			r.produce().await;
			r.bury().await;
			let vout = tx.output.iter().position(|o| o.script_pubkey == policy.script_pubkey()).unwrap() as u32;
			let op = OutPoint::new(tx.txid(), vout);
			r.config.bond = Some(BondSection { withdraw_key: w.x_only_public_key().0.to_string(), notice_units: notice_units(),
				outpoint: Some(format!("{}:{}", op.txid, op.vout)), notice: None });
			r.restart_server().await;
			r.synced().await;
			p.bond = Some((w, op));
			Ok(json!({"bond": format!("{}:{}", op.txid, op.vout), "asset": x.to_string(), "amount": amount}))
		},
		"/bond_notice" => {
			let Some((w, _)) = p.bond.clone() else { return Some(Err("no bond posted".into())) };
			let x = r.x;
			r.fund_server(x, 50_000_000).await;
			r.produce().await;
			r.bury().await;
			r.synced().await;
			let key_file = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("browsers-bond-w{}.key", std::process::id()));
			let _ = std::fs::remove_file(&key_file);
			{
				use std::os::unix::fs::OpenOptionsExt;
				let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&key_file).unwrap();
				std::io::Write::write_all(&mut f, hex(&w.secret_bytes()).as_bytes()).unwrap();
			}
			let noticed = server::server::bond_notice(&r.config, &key_file).await;
			let _ = std::fs::remove_file(&key_file);
			let noticed = match noticed {
				Ok(n) => n,
				Err(e) => return Some(Err(e.to_string())),
			};
			r.produce().await;
			r.bury().await;
			r.config.bond.as_mut().unwrap().notice = noticed["notice"].as_str().map(String::from);
			r.restart_server().await;
			r.synced().await;
			Ok(json!({"notice": noticed["notice"]}))
		},
		"/bond_drop" => {
			r.config.bond = None;
			r.restart_server().await;
			r.synced().await;
			Ok(json!({"bond": null}))
		},
		_ => return None,
	})
}

async fn handle(r: &mut Running, path: &str, b: &Value) -> Result<Value, String> {
	match path {
		"/state" => Ok(json!({
			"server": r.url(), "node_url": r.node_url(), "node_user": "arca", "node_password": "arca",
			"lightning": r.config.assets.iter().any(|a| a.lightning.is_some()),
			"x": r.x.to_string(), "y": r.y.to_string(),
			// The test operator key's file, for `arca-signer --key-file …
			// --sign-operator-record`, and the chain it signs for.
			"signer_key_file": r.signer.dir.join("operator.key").display().to_string(),
			"genesis_hash": r.rt.client().call::<String>("getblockhash", &[json!(0)]).map_err(|e| e.to_string())?,
			"tip": r.rt.client().blockchain_info().map_err(|e| e.to_string())?.blocks,
		})),
		"/fund" => {
			let s = script(b["script"].as_str().ok_or("no script")?)?;
			// The purse pays whatever it is given: an empty script or more than
			// it holds would end the test, and the chain with it.
			if s.is_empty() {
				return Err("an empty script".into());
			}
			let asset = AssetId::from_str(b["asset"].as_str().ok_or("no asset")?).map_err(|e| e.to_string())?;
			let amount = b["amount"].as_u64().or_else(|| b["amount"].as_str().and_then(|a| a.parse().ok())).ok_or("no amount")?;
			let tx = r.pay_to(s, asset, amount);
			Ok(json!({"txid": tx.txid().to_string()}))
		},
		"/fund_server" => {
			let asset = AssetId::from_str(b["asset"].as_str().ok_or("no asset")?).map_err(|e| e.to_string())?;
			let amount = b["amount"].as_u64().ok_or("no amount")?;
			let tx = r.fund_server(asset, amount).await;
			Ok(json!({"txid": tx.txid().to_string()}))
		},
		"/produce" => {
			r.produce().await;
			Ok(json!({"tip": r.rt.client().blockchain_info().map_err(|e| e.to_string())?.blocks}))
		},
		"/bury" => {
			r.bury().await;
			r.synced().await;
			Ok(json!({"tip": r.rt.client().blockchain_info().map_err(|e| e.to_string())?.blocks}))
		},
		"/round" => {
			let built = r.server.rounds.run_round().await.map_err(|e| e.to_string())?;
			let Some(built) = built else { return Ok(json!({"round": null})) };
			let txid = built.tx.txid();
			r.produce().await;
			r.bury().await;
			r.round_state(&txid, RoundState::Final).await;
			r.synced().await;
			Ok(json!({"round": txid.to_string(), "vsize": built.tx.vsize()}))
		},
		"/advance" => {
			let seconds = b["seconds"].as_u64().ok_or("no seconds")? as u32;
			tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, seconds));
			r.synced().await;
			Ok(json!({"median_time": common::node::median_time(&r.rt)}))
		},
		"/rpc" => {
			let method = b["method"].as_str().ok_or("no method")?;
			let params: Vec<Value> = b["params"].as_array().cloned().unwrap_or_default();
			r.rt.client().call::<Value>(method, &params).map_err(|e| e.to_string())
		},
		"/build" => {
			let (built, failed) = r.server.rounds.run_rounds().await.map_err(|e| e.to_string())?;
			Ok(json!({
				"rounds": built.iter().map(|b| json!({"txid": b.tx.txid().to_string(), "vsize": b.tx.vsize(),
					"fills": b.fills.iter().map(|o| format!("{}:{}", o.txid, o.vout)).collect::<Vec<_>>()})).collect::<Vec<_>>(),
				"failed": failed.iter().map(|(a, e)| json!({"asset": a.to_string(), "error": e.to_string()})).collect::<Vec<_>>(),
			}))
		},
		"/pass" => {
			r.server.rounds.pass().await.map_err(|e| e.to_string())?;
			Ok(json!({"passed": true}))
		},
		"/settle" => {
			r.server.watcher.pass().await.map_err(|e| e.to_string())?;
			tokio::time::sleep(Duration::from_millis(300)).await;
			r.produce().await;
			r.bury().await;
			r.synced().await;
			r.server.nursery.pass().await.map_err(|e| e.to_string())?;
			r.server.watcher.pass().await.map_err(|e| e.to_string())?;
			tokio::time::sleep(Duration::from_millis(300)).await;
			Ok(json!({"tip": r.rt.client().blockchain_info().map_err(|e| e.to_string())?.blocks}))
		},
		"/round_state" => {
			use elements::hashes::Hash;
			let txid = elements::Txid::from_str(b["txid"].as_str().ok_or("no txid")?).map_err(|e| e.to_string())?;
			let st = r.server.store.round_by_txid(&txid.to_byte_array()).await.map_err(|e| e.to_string())?;
			Ok(json!({"state": st.map(|x| x.state.as_str())}))
		},
		"/orphan" => {
			let height = b["height"].as_u64().ok_or("no height")?;
			let gone = tokio::task::block_in_place(|| r.rt.orphan_parent_from(height))?;
			Ok(json!({"orphaned": gone.len()}))
		},
		"/restart" => {
			r.restart_server().await;
			r.synced().await;
			Ok(json!({"server": r.url()}))
		},
		"/fees" => {
			let asset = b["asset"].as_str().ok_or("no asset")?;
			let ppm = b["refresh_ppm"].as_u64();
			let offboard_base = b["offboard_base"].as_u64();
			if ppm.is_none() && offboard_base.is_none() {
				return Err("name refresh_ppm or offboard_base".into());
			}
			let mut config = r.config.clone();
			let a = config.assets.iter_mut().find(|a| a.asset == asset).ok_or("the server does not serve that asset")?;
			if let Some(p) = ppm {
				a.refresh_ppm = Some(p);
			}
			if let Some(base) = offboard_base {
				a.offboard_base = Some(base.to_string());
			}
			let reloaded = r.server.reload(&config).await.map_err(|e| e.to_string())?;
			r.config = config;
			Ok(json!({"changed": reloaded.changed.iter().map(|a| a.to_string()).collect::<Vec<_>>()}))
		},
		other => Err(format!("no path {}", other)),
	}
}

/// The server on SeqLN's chain, with its SeqLN node in X that receives and
/// a channel to a node of its own; its Lightning terms short except a
/// payment's timeout, four to eight days out.
async fn with_lightning() -> (Running, Vec<sequentia_ext::lightning::LightningNode>) {
	let lnd = common::lightning::lightningd("operator_for_browsers").expect("ARCA_OPERATOR_LIGHTNING needs LIGHTNINGD_EXEC");
	let mut r = Running::start_seqln(|c, _, _| {
		c.fees.lightning_ppm = 1_000;
		c.lightning.operator_delay_units = 1;
		c.lightning.owner_delay_units = 2;
		c.lightning.send_timeout_seconds = 4 * 86_400;
		c.lightning.send_stall_margin_seconds = 3600;
		c.lightning.poll_seconds = 1;
		c.lightning.retry_seconds = 10;
		c.lightning.receive_window_seconds = 600;
	}).await;
	let x = r.x;
	let (ox, px) = tokio::task::block_in_place(|| {
		let ox = common::lightning::node(&r.rt, &mut r.purse, &lnd, "browsers-o", true, x, 2_000_000_000);
		let px = common::lightning::node(&r.rt, &mut r.purse, &lnd, "browsers-p", true, x, 1_000_000_000);
		ox.open_channel(&r.rt, &px, x, 1_000_000_000, 300_000_000);
		(ox, px)
	});
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let mut config = r.config.clone();
	for a in config.assets.iter_mut() {
		if a.asset == x.to_string() {
			a.lightning = Some(server::server::LegSection { rpc: ox.rpc_path() });
		}
	}
	r.server.reload(&config).await.unwrap();
	r.config = config;
	let g = r.server.gateway.clone();
	r.wait("X's leg up", || g.leg(&x, true).is_ok()).await;
	(r, vec![ox, px])
}

/// The operator's Lightning leg in each of `more` too, on the same two
/// nodes as X's: a channel of 10^12 atoms of the asset from its node to the
/// other, 3·10^11 of it pushed, so that it both receives and pays in it.
async fn legs_in(r: &mut Running, nodes: &[LightningNode], more: &[AssetId]) {
	let [ox, px] = nodes else { return };
	for m in more {
		let to = ox.receive_script(&r.rt);
		r.pay_to(to, *m, 2_000_000_000_000);
		r.produce().await;
		tokio::task::block_in_place(|| {
			ox.wait("its funds in the asset", |n| n.ok("listfunds", json!({}))["outputs"].as_array().map(|o| o.iter()
				.any(|x| x["status"] == "confirmed" && x["asset"].as_str() == Some(&m.to_string()))).unwrap_or(false));
			ox.open_channel(&r.rt, px, *m, 1_000_000_000_000, 300_000_000_000);
		});
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let mut config = r.config.clone();
	for a in config.assets.iter_mut() {
		if more.iter().any(|m| a.asset == m.to_string()) {
			a.lightning = Some(server::server::LegSection { rpc: ox.rpc_path() });
		}
	}
	r.server.reload(&config).await.unwrap();
	r.config = config;
	for m in more {
		let g = r.server.gateway.clone();
		let m = *m;
		r.wait("the asset's leg up", || g.leg(&m, true).is_ok()).await;
	}
}

/// The Bitcoin side of a trade of BTC over Lightning: a Bitcoin regtest
/// chain, a hub node and a node for each wallet, each with a channel from
/// the hub. Stopped, and their directories deleted, on drop.
struct BitcoinSide {
	btc: BitcoinRegtest,
	hub: LightningNode,
	wallets: Vec<LightningNode>,
}

/// The hub and `n` nodes on a new Bitcoin regtest chain, each node with a
/// channel of 10,000,000 sat from the hub, 5,000,000 of it pushed to it.
fn bitcoin_side(n: usize) -> BitcoinSide {
	let lnd = common::lightning::lightningd("operator_for_browsers").expect("ARCA_OPERATOR_BTC_LIGHTNING needs LIGHTNINGD_EXEC");
	let exe = BitcoinRegtest::exe_from_env().expect("ARCA_OPERATOR_BTC_LIGHTNING needs BITCOIND_EXEC");
	let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("browsers-btc{}", std::process::id()));
	let btc = BitcoinRegtest::start(&exe, &dir).expect("a Bitcoin regtest chain");
	btc.mine(101);
	let hub = LightningNode::start_on_bitcoin(&btc, &lnd, &dir.with_extension("hub"), &[]).expect("the hub node");
	let addr = hub.ok("newaddr", json!({ "addresstype": "bech32" }))["bech32"].as_str().expect("an address").to_string();
	for _ in 0..n {
		btc.cli(&["sendtoaddress", &addr, "0.2"]).expect("a payment to the hub");
	}
	btc.mine(1);
	hub.wait_funds(n);
	let mut wallets = vec![];
	for i in 0..n {
		let w = LightningNode::start_on_bitcoin(&btc, &lnd, &dir.with_extension(format!("w{}", i)), &[]).expect("a wallet's node");
		hub.open_bitcoin_channel(&btc, &w, 10_000_000, 5_000_000);
		wallets.push(w);
	}
	// Six blocks, so that every channel is announced and every node routes.
	btc.mine(6);
	BitcoinSide { btc, hub, wallets }
}

/// The Bitcoin side's paths: its sockets in `/state`, and `/btc_mine`.
fn bitcoin_handle(side: &Option<BitcoinSide>, path: &str, b: &Value) -> Option<Result<Value, String>> {
	let side = side.as_ref()?;
	match path {
		"/btc_mine" => {
			let n = b["blocks"].as_u64().unwrap_or(1).min(1000) as u32;
			side.btc.mine(n);
			Some(side.btc.cli(&["getblockcount"]).map(|c| json!({"blocks": c.trim().parse::<u64>().unwrap_or(0)})))
		},
		_ => None,
	}
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "a server kept running for a wallet outside this process; run by hand"]
async fn operator_for_browsers() {
	let addr = std::env::var("ARCA_OPERATOR_CONTROL").unwrap_or_else(|_| "127.0.0.1:18640".into());
	let (mut r, _nodes) = match std::env::var_os("ARCA_OPERATOR_LIGHTNING") {
		Some(_) => with_lightning().await,
		None if std::env::var_os("ARCA_OPERATOR_ISSUER").is_some() => (Running::start_on(&["-evbparams=simplicity:-1:::"], |_, _, _| {}).await, vec![]),
		// Batches without a sweep, collected at the horizon named (seconds).
		None => match std::env::var("ARCA_OPERATOR_NO_SWEEP") {
			Ok(h) => {
				let h: u32 = h.trim().parse().expect("ARCA_OPERATOR_NO_SWEEP is a service horizon in seconds");
				(Running::start_with(|c, _, _| {
					c.batches.no_sweep = true;
					c.batches.holder_batches = Some(0);
					c.batches.collect_after_seconds = Some(h);
				}).await, vec![])
			},
			Err(_) => (Running::start().await, vec![]),
		},
	};
	let mut profiles = Profiles::default();
	serve_profiles(&mut r, &mut profiles).await;
	// Channel leaves in every plain asset, up to the capacity asked.
	if let Ok(c) = std::env::var("ARCA_OPERATOR_CHANNELS") {
		let c: u64 = c.trim().parse().expect("ARCA_OPERATOR_CHANNELS is a capacity in atoms");
		let mut config = r.config.clone();
		for a in config.assets.iter_mut() {
			let id = AssetId::from_str(&a.asset).unwrap();
			if !profiles.supervised_all.contains(&id) && Some(id) != profiles.issuer {
				a.channel_capacity = Some(c.to_string());
			}
		}
		r.server.reload(&config).await.unwrap();
		r.config = config;
	}
	// With Lightning, the plain assets beyond X and Y get legs of their own.
	if !_nodes.is_empty() && !profiles.more.is_empty() {
		let more = profiles.more.clone();
		legs_in(&mut r, &_nodes, &more).await;
	}
	let btc = std::env::var("ARCA_OPERATOR_BTC_LIGHTNING").ok().map(|n| {
		let n = n.parse::<usize>().expect("ARCA_OPERATOR_BTC_LIGHTNING is a count of wallets' nodes");
		tokio::task::block_in_place(|| bitcoin_side(n))
	});
	let listener = TcpListener::bind(&addr).expect("bind the control address");
	listener.set_nonblocking(true).unwrap();
	println!("operator for browsers: control {}, server {}, node {}, X {}, Y {}", addr, r.url(), r.node_url(), r.x, r.y);
	loop {
		let mut s = match listener.accept() {
			Ok((s, _)) => s,
			Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
				tokio::time::sleep(Duration::from_millis(50)).await;
				continue;
			},
			Err(e) => panic!("accept: {}", e),
		};
		let Some((method, path, body)) = read_request(&mut s) else { continue };
		if method == "OPTIONS" {
			answer(&mut s, 200, &json!({}));
			continue;
		}
		if path == "/quit" {
			answer(&mut s, 200, &json!({"quit": true}));
			break;
		}
		let profiled = match bitcoin_handle(&btc, &path, &body) {
			Some(out) => Some(out),
			None => profile_handle(&mut r, &mut profiles, &path, &body).await,
		};
		let out = match profiled {
			Some(out) => out,
			None => handle(&mut r, &path, &body).await.map(|mut v| {
				if path == "/state" {
					v["supervised"] = json!(profiles.supervised.as_ref().map(|(z, _)| z.to_string()));
					v["supervised_all"] = json!(profiles.supervised_all.iter().map(|z| z.to_string()).collect::<Vec<_>>());
					v["more"] = json!(profiles.more.iter().map(|m| m.to_string()).collect::<Vec<_>>());
					v["assets"] = json!(r.config.assets.iter().map(|a| a.asset.to_string()).collect::<Vec<_>>());
					v["issuer"] = json!(profiles.issuer.map(|i| i.to_string()));
					v["bond"] = json!(profiles.bond.as_ref().map(|(_, o)| format!("{}:{}", o.txid, o.vout)));
					// The chain's name, the node's data directory and the
					// operator's own SeqLN nodes in X: what a second
					// operator's SeqLN node needs to run beside them.
					v["chain"] = json!(r.rt.chain_name());
					v["node_datadir"] = json!(r.rt.node.datadir().display().to_string());
					if let [ox, px] = &_nodes[..] {
						let n = |l: &LightningNode| json!({"rpc": l.rpc_path().display().to_string(), "id": l.id,
							"addr": format!("127.0.0.1:{}", l.port)});
						v["x_lightning"] = json!({"operator": n(ox), "peer": n(px)});
					}
				}
				if let (Some(side), "/state") = (&btc, path.as_str()) {
					v["btc_lightning"] = json!({"hub": side.hub.rpc_path().display().to_string(),
						"wallets": side.wallets.iter().map(|w| w.rpc_path().display().to_string()).collect::<Vec<_>>()});
				}
				v
			}),
		};
		println!("operator for browsers: {} {} -> {}", path, body, match &out { Ok(v) => v.to_string(), Err(e) => format!("error: {}", e) });
		match out {
			Ok(v) => answer(&mut s, 200, &v),
			Err(e) => answer(&mut s, 400, &json!({"error": e})),
		}
	}
	r.server.stop();
}
