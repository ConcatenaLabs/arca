//! A restricted asset in its issuer's tree, end to end, with the real policy
//! server: `openampd` (built from the openamp repository) and the
//! `arca-enclave` tool it runs, beside this server and `arca-signer`, on an
//! anchored proof-of-stake regtest chain.
//!
//! openampd issues a restricted asset R with clawback, minted to holder H1's
//! enclave, and names this operator the operator of R's tree. H1 boards its
//! enclave coin into an `enclave-1` board: openampd admits the board output
//! and co-signs the enclave input, H1's wallet checking the signature hash
//! itself before it signs. The operator credits the board, then co-signs a
//! transfer from H1 to H2 out of round beside openampd's approval: settled at
//! once, no transaction. One transfer is refused for each of the asset's
//! rules (category, lock-in, velocity, holder cap, vesting), each with
//! openampd's own words. H2 takes its coin home: the board's checkpoint and
//! the reassignment brought on the chain, then H2's exit into H2's enclave,
//! which openampd closes in its register on H2's report. H1's change, on the
//! chain with H2's coin, is clawed back by its claw leaf into the issuer's
//! enclave, openampd signing the policy half (and, as `-demoissuer` holds it,
//! the issuer's).
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES`, `OPENAMPD_EXEC` (the
//! openampd binary), `ARCA_ENCLAVE_EXEC` (this repository's `arca-enclave`)
//! and `TOKEN_COVENANTS_EXEC` (sequentia-contracts' `token-covenants`, which
//! openampd issues through); without the last three it says so and passes.

mod common;

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use elements::encode::{deserialize, serialize};
use elements::hex::FromHex;
use elements::secp256k1_zkp::{Keypair, XOnlyPublicKey};
use elements::{AssetId, OutPoint, Transaction, TxOut};
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::{enclave_key, enclave_keypair, BoardRecord, CoinRecord, Enclave, NewLeaf, Template};
use common::client::{hex, random32, transfer_body, unhex, Held};
use common::flow::Coin;
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::advance_mtp;
use common::running::{Running, MIN_LEAF};
use server::server::{AssetSection, RestrictedSection};

const TOKEN: &str = "e2e issuer token";
const ISSUED: u64 = 10_000_000;
const HOUR: u32 = 3_600;

struct Openampd {
	child: Child,
	url: String,
	dir: PathBuf,
}

impl Drop for Openampd {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

impl Openampd {
	fn call(&self, method: &str, path: &str, body: Option<&Value>, issuer: bool) -> (i32, Value) {
		let url = format!("{}{}", self.url, path);
		let mut r = if method == "GET" { minreq::get(&url) } else { minreq::post(&url) }.with_timeout(60);
		if issuer {
			r = r.with_header("Authorization", format!("Bearer {}", TOKEN));
		}
		if let Some(b) = body {
			r = r.with_header("Content-Type", "application/json").with_body(b.to_string());
		}
		let resp = r.send().unwrap_or_else(|e| panic!("{} {}: {}", method, path, e));
		(resp.status_code, serde_json::from_slice(resp.as_bytes()).unwrap_or(Value::Null))
	}

	fn ok(&self, method: &str, path: &str, body: Option<&Value>, issuer: bool) -> Value {
		let (s, v) = self.call(method, path, body, issuer);
		assert_eq!(s, 200, "{} {}: {} {}", method, path, s, v);
		v
	}
}

fn free_port() -> u16 {
	std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn tools() -> Option<(String, String, String)> {
	Some((std::env::var("OPENAMPD_EXEC").ok()?, std::env::var("ARCA_ENCLAVE_EXEC").ok()?, std::env::var("TOKEN_COVENANTS_EXEC").ok()?))
}

fn tx_of(h: &str) -> Transaction {
	deserialize(&Vec::<u8>::from_hex(h).unwrap()).unwrap()
}

fn send(r: &Running, what: &str, tx: &Transaction) -> elements::Txid {
	let txid = r.rt.client().send_raw_transaction(tx).unwrap_or_else(|e| panic!("{}: {}", what, e));
	println!("{}: {} ({} vB)", what, txid, tx.vsize());
	txid
}

/// Starts openampd on `r`'s node, its wallet funded from the purse.
fn start_openampd(r: &mut Running, exe: &str, tool: &str, tokens: &str) -> Openampd {
	let c = r.rt.client();
	let _: Value = c.call("createwallet", &[json!("openampd")]).unwrap();
	let wallet = sequentia_ext::rpc::Client::new(format!("http://127.0.0.1:{}/wallet/openampd", r.rt.node.rpc_port()),
		sequentia_ext::rpc::Auth::UserPass("arca".into(), "arca".into()));
	let addr: Value = wallet.call("getnewaddress", &[json!(""), json!("bech32")]).unwrap();
	let info: Value = wallet.call("getaddressinfo", &[addr.clone()]).unwrap();
	let spk = elements::Script::from(Vec::<u8>::from_hex(info["scriptPubKey"].as_str().unwrap()).unwrap());
	let policy_asset: Value = c.call("getsidechaininfo", &[]).unwrap();
	let pa = AssetId::from_str_display(policy_asset["pegged_asset"].as_str().unwrap());
	r.purse.pay(&r.rt, vec![
		sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(r.x, 2_000_000_000), spk.clone()),
		sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(pa, 2_000_000_000), spk),
	]);
	r.rt.produce_block().unwrap();
	let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("openampd-{}-{}", std::process::id(), random32()[0]));
	std::fs::create_dir_all(&dir).unwrap();
	let port = free_port();
	let log = std::fs::File::create(dir.join("openampd.log")).unwrap();
	let child = Command::new(exe)
		.args(["-listen", &format!("127.0.0.1:{}", port), "-datadir", dir.to_str().unwrap(),
			"-rpc", &format!("http://127.0.0.1:{}", r.rt.node.rpc_port()), "-rpcauth", "arca:arca", "-rpcwallet", "openampd",
			"-issuertoken", TOKEN, "-demoissuer", "-tokentool", tokens, "-arcaenclave", tool, "-follow", "500ms",
			"-electrs", "http://127.0.0.1:1"])
		.stdout(Stdio::null()).stderr(log).spawn().unwrap();
	let o = Openampd { child, url: format!("http://127.0.0.1:{}", port), dir };
	let start = Instant::now();
	while minreq::get(format!("{}/v1/assets", o.url)).with_timeout(2).send().is_err() {
		assert!(start.elapsed() < Duration::from_secs(30), "openampd did not start: {}",
			std::fs::read_to_string(o.dir.join("openampd.log")).unwrap_or_default());
		std::thread::sleep(Duration::from_millis(200));
	}
	o
}

trait FromStrDisplay {
	fn from_str_display(s: &str) -> Self;
}

impl FromStrDisplay for AssetId {
	fn from_str_display(s: &str) -> AssetId {
		s.parse().unwrap()
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restricted_asset_settles_in_its_issuers_tree_under_its_rules() {
	let Some((exe, tool, tokens)) = tools() else {
		println!("OPENAMPD_EXEC, ARCA_ENCLAVE_EXEC and TOKEN_COVENANTS_EXEC are not all set: this end-to-end test needs the real \
			policy server, and does nothing without it");
		return;
	};
	let mut r = Running::start_on(&["-disablewallet=0"], |c, _| c.watcher.enabled = true).await;
	let x = r.x;
	for _ in 0..3 {
		r.fund_wallet_in(x, 50_000_000).await;
	}
	// Coins of X for the fees the tests' own transactions pay.
	let outs = (0..8).map(|_| sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(x, 1_000_000), node::op_true())).collect();
	let paid = tokio::task::block_in_place(|| r.purse.pay(&r.rt, outs));
	for j in 0..8 {
		r.purse.put((OutPoint::new(paid.txid(), j), paid.output[j as usize].clone()));
	}
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let genesis = r.chain.genesis_hash();
	let s = xonly(&r.s);
	let o = tokio::task::block_in_place(|| start_openampd(&mut r, &exe, &tool, &tokens));

	// ---- the asset, its holders, its tree ---------------------------------
	let keys: Vec<Keypair> = ["issuer account", "H1", "H2", "H3 (no category)", "H4", "H5"].iter()
		.map(|l| keypair(&format!("e2e {}", l))).collect();
	let aid: Vec<String> = keys.iter().map(|k| o.ok("POST", "/v1/users", Some(&json!({"pubkeys": [hex(&xonly(k).serialize())]})), false)
		["aid"].as_str().unwrap().to_string()).collect();
	for a in [&aid[1], &aid[2], &aid[4], &aid[5]] {
		o.ok("POST", "/v1/issuer/categories", Some(&json!({"aid": a, "categories": ["qualified"]})), true);
	}
	let issued = tokio::task::block_in_place(|| o.ok("POST", "/v1/issuer/assets", Some(&json!({
		"name": "Restricted R", "ticker": "RRR", "precision": 0, "atoms": ISSUED, "holder_aid": aid[1], "issuer_aid": aid[0],
		"clawback": true, "rules": {"allowed_categories": ["qualified"]},
		"cap_cold_key": hex(&xonly(&keypair("e2e supply cap cold key")).serialize()),
	})), true));
	let rr: AssetId = issued["asset"].as_str().unwrap().parse().unwrap();
	let issue_txid = issued["txid"].as_str().unwrap().to_string();
	r.produce().await;
	o.ok("POST", "/v1/issuer/tree", Some(&json!({"asset": rr.to_string(), "operator": hex(&s.serialize())})), true);
	let asset = o.ok("GET", &format!("/v1/assets/{}", rr), None, false);
	let policy = XOnlyPublicKey::from_slice(&unhex(asset["tree"]["policy"].as_str().unwrap())).unwrap();
	let claw = XOnlyPublicKey::from_slice(&unhex(asset["tree"]["clawback"].as_str().unwrap())).unwrap();
	println!("openampd issued R {} ({} atoms to H1's enclave, clawback elected) and names {} the operator of its tree", rr, ISSUED,
		hex(&s.serialize()));
	let enclave = |k: &Keypair| Enclave { holder: xonly(k), policy, clawback: Some(claw) };

	// ---- served restricted ----------------------------------------------
	let token_file = r.signer.dir.join("policy.token");
	std::fs::write(&token_file, TOKEN).unwrap();
	let mut config = r.config.clone();
	let mut sec = AssetSection::new(rr, MIN_LEAF);
	sec.restricted = Some(RestrictedSection { policy_server: o.url.clone(), token_file: token_file.to_str().unwrap().into() });
	config.assets.push(sec);
	r.server.reload(&config).await.unwrap();
	tokio::task::block_in_place(|| r.signer.restart_with(genesis, &["--restricted".into(),
		format!("{}={}:{}", rr, hex(&policy.serialize()), hex(&claw.serialize()))]));

	// ---- H1 boards its enclave coin -------------------------------------
	let issue_tx = tx_of(r.rt.client().call::<Value>("getrawtransaction", &[json!(issue_txid)]).unwrap().as_str().unwrap());
	let h1_spk = enclave(&keys[1]).script_pubkey();
	let vout = issue_tx.output.iter().position(|t| t.script_pubkey == h1_spk).expect("the mint pays H1's enclave");
	let coin: (OutPoint, TxOut) = (OutPoint::new(issue_tx.txid(), vout as u32), issue_tx.output[vout].clone());
	let nonce = random32();
	let record = BoardRecord {
		template: Template::Board1, owner: enclave_key(&xonly(&keys[1]), &nonce).unwrap(), owner_nonce: nonce,
		operator_nonce: r.http.operator_nonce(), exit_delay: common::client::exit_delay(), asset: rr, value: ISSUED, chain: r.chain,
		operator: s, landing: None, enclave: Some(enclave(&keys[1])),
	};
	let fee = r.purse.take_coin(x);
	let mut btx = record.tx(&[coin.clone(), fee.clone()], x, 3_000, &node::op_true()).unwrap().tx;
	let cosigned = o.ok("POST", "/v1/cosign", Some(&json!({
		"tx": hex(&serialize(&btx)), "asset": rr.to_string(), "sender_aid": aid[1], "inputs": [0],
		"tree_outputs": [{"output": 0, "record": hex(&record.to_bytes().unwrap())}],
	})), false);
	let sig = &cosigned["sigs"][0];
	// H1's wallet signs no digest it was handed: it computes the signature
	// hash of its enclave input itself and checks the server's against it.
	let transfer_leaf = enclave(&keys[1]).transfer_script();
	let mine = arca_covenant::sign::script_spend_sighash(&btx, 0, &[coin.1.clone(), fee.1.clone()], &transfer_leaf, genesis).unwrap();
	assert_eq!(sig["sighash"].as_str().unwrap(), hex(&mine), "the policy server's signature hash is the one H1 computes");
	let h1_sig = sign_digest(&keys[1], &mine, &random32());
	btx.input[0].witness.script_witness = vec![unhex(sig["policy_sig"].as_str().unwrap()), h1_sig.as_ref().to_vec(),
		transfer_leaf.to_bytes(), unhex(sig["control"].as_str().unwrap())];
	btx.input[1].witness.script_witness = vec![];
	send(&r, "H1's board of R from its enclave, co-signed by openampd", &btx);
	for (j, out) in btx.output.iter().enumerate().skip(1) {
		if !out.is_fee() && out.asset.explicit() == Some(x) {
			r.purse.put((OutPoint::new(btx.txid(), j as u32), out.clone()));
		}
	}
	let board_answer = r.http.register_board(&record, &btx);
	println!("board registered: {}", board_answer.json);
	r.produce().await;
	r.bury().await;
	let id = record.leaf_id();
	let http = r.http.clone();
	r.wait("the board to be credited", || http.board_status(&id).json["state"] == "credited").await;
	let a1 = enclave_keypair(&keys[1], &nonce).unwrap();
	let c1 = Coin { held: Held { key: a1, nonce, id, record: CoinRecord::Board(record) }, bases: vec![btx.clone()] };
	println!("H1's enclave-1 board of {} R credited: {}", ISSUED, id);

	// ---- reassignments under the policy -------------------------------------
	let new = |k: &Keypair, value: u64| {
		let n = random32();
		(rr, value, NewLeaf {
			owner: enclave_key(&xonly(k), &n).unwrap(), owner_nonce: n, creator_nonce: random32(),
			exit_delay: common::client::exit_delay(), htlc: None, landing: None, enclave: Some(enclave(k).terms(rr, value)), v2: false,
		})
	};
	let v1 = c1.valid(&r);
	let try_send = |r: &Running, _what: &str, to: &Keypair, value: u64| {
		let (_, _, change) = new(&keys[1], ISSUED - value);
		let out = new(to, value);
		let body = transfer_body(&[(&c1.held, v1.clone(), ISSUED)], &[out.clone(), (rr, ISSUED - value, change)], s, r.chain);
		let a = r.http.post("cosign_transfer", &body);
		(a, out, change)
	};
	let refuse = |r: &Running, what: &str, to: &Keypair, value: u64, expect: &str| {
		let (a, _, _) = try_send(r, what, to, value);
		let (code, why) = a.refusal();
		println!("REFUSED {}: {} {}", what, code, why);
		assert_eq!(code, "policy", "{}", why);
		assert!(why.contains(expect), "{}: {}", what, why);
	};
	let rules = |v: Value| { o.ok("POST", "/v1/issuer/rules", Some(&json!({"asset": rr.to_string(), "rules": v})), true); };
	refuse(&r, "category: to H3, who holds no permitted category", &keys[3], 100_000, "lacks a permitted category");
	let height = r.rt.client().blockchain_info().unwrap().blocks as i64;
	rules(json!({"allowed_categories": ["qualified"], "lockin_until_height": height + 1000}));
	refuse(&r, "lock-in: the asset is locked in", &keys[2], 100_000, "locked in until height");
	rules(json!({"allowed_categories": ["qualified"], "velocity_window_blocks": 1000, "velocity_max_atoms": 50_000}));
	refuse(&r, "velocity: 100000 over a 50000 window", &keys[2], 100_000, "velocity limit");
	rules(json!({"allowed_categories": ["qualified"], "holder_cap": 1}));
	refuse(&r, "holder cap: a second holder over a cap of 1", &keys[2], 100_000, "holder cap");
	rules(json!({"allowed_categories": ["qualified"], "vesting": [{"aid": aid[1], "atoms": ISSUED - 50_000, "until_height": height + 1000}]}));
	refuse(&r, "vesting: H1's atoms locked", &keys[2], 100_000, "vesting");
	rules(json!({"allowed_categories": ["qualified"]}));
	let t0 = Instant::now();
	let (a, (_, _, leaf2), change1) = try_send(&r, "H1 to H2", &keys[2], 700_000);
	let done = a.ok();
	let took = t0.elapsed();
	println!("H1 paid H2 700000 R out of round, co-signed by the operator beside openampd, in {} ms; no transaction", took.as_millis());
	let transfer: Vec<u8> = unhex(done["transfer_id"].as_str().unwrap());
	let a2 = enclave_keypair(&keys[2], &leaf2.owner_nonce).unwrap();
	let (_, b_id, b_record) = r.http.mailbox(&a2, &r.chain, 0)[0].clone();
	let b_valid = b_record.validate(&c1.bases, &r.policy(), &xonly(&a2), &leaf2.owner_nonce).unwrap();
	println!("H2's coin {} validated: enclave-1, its exit paying H2's enclave", b_id);
	let holders = o.ok("GET", &format!("/v1/issuer/holders?asset={}", rr), None, true);
	println!("openampd's holders of R now: {}", holders);

	// ---- H2 takes its coin home ------------------------------------------
	let inputs = match &b_valid.origin { arca_covenant::ValidOrigin::Transfer { inputs, .. } => inputs.clone(), _ => unreachable!() };
	let fc = r.purse.take_coin(x);
	let mut cp = inputs[0].board_checkpoint_tx(&FeeSource::Coin { outpoint: fc.0, coin: fc.1.clone(), fee: 3_000, change: node::op_true() })
		.unwrap().tx;
	cp.input[1].witness.script_witness = vec![];
	let cp_txid = send(&r, "the board's checkpoint, the fee in X", &cp);
	r.produce().await;
	let fc = r.purse.take_coin(x);
	let mut re = b_valid.reassignment_tx(&[OutPoint::new(cp_txid, 0)],
		&FeeSource::Coin { outpoint: fc.0, coin: fc.1.clone(), fee: 3_000, change: node::op_true() }).unwrap().tx;
	re.input[1].witness.script_witness = vec![];
	let re_txid = send(&r, "the reassignment: H2's leaf and H1's change, the fee in X", &re);
	r.produce().await;
	advance_mtp(&r, 37 * HOUR).await;
	let fc = r.purse.take_coin(x);
	let ks = b_valid.leaf.enclave_exit_tx(OutPoint::new(re_txid, 0),
		&FeeSource::Coin { outpoint: fc.0, coin: fc.1.clone(), fee: 3_000, change: node::op_true() }).unwrap();
	let sig = sign_digest(&a2, &ks.sighash(genesis).unwrap(), &random32());
	let mut exit = ks.finish(vec![sig.as_ref().to_vec()]).tx;
	exit.input[1].witness.script_witness = vec![];
	let exit_txid = send(&r, "H2's exit into its enclave", &exit);
	r.produce().await;
	r.bury().await;
	let salt2 = hex(&b_valid.leaf.salt);
	o.ok("POST", &format!("/v1/tree/leaves/{}/exited", salt2), Some(&json!({"txid": exit_txid.to_string()})), false);
	let bal = o.ok("GET", &format!("/v1/users/{}/balance?asset={}", aid[2], rr), None, false);
	println!("H2's enclave balance at openampd: {}", bal);
	assert_eq!(bal["atoms"].as_u64(), Some(700_000));

	// ---- the clawback of H1's change, on the chain ---------------------------
	let change_at = OutPoint::new(re_txid, 1);
	let change_leaf = change1.policy(s, r.chain);
	let issuer_enclave = enclave(&keys[0]);
	let fc = r.purse.take_coin(x);
	let ks = change_leaf.claw_tx(change_at, &[arca_covenant::ExplicitOutput::new(rr, ISSUED - 700_000, issuer_enclave.script_pubkey())],
		&FeeSource::Coin { outpoint: fc.0, coin: fc.1.clone(), fee: 3_000, change: node::op_true() }).unwrap();
	let mut claw_tx = ks.tx.clone();
	let answer = o.ok("POST", "/v1/issuer/tree/clawback", Some(&json!({
		"asset": rr.to_string(), "salt": hex(&change_leaf.salt), "tx": hex(&serialize(&claw_tx)), "input": 0,
		"reason": "e2e: a court order",
	})), true);
	assert_eq!(answer["sighash"].as_str().unwrap(), hex(&ks.sighash(genesis).unwrap()), "openampd's claw hash is the one built here");
	claw_tx.input[0].witness.script_witness = answer["witness"].as_array().unwrap().iter().map(|w| unhex(w.as_str().unwrap())).collect();
	claw_tx.input[1].witness.script_witness = vec![];
	send(&r, "the clawback of H1's change by its claw leaf into the issuer's enclave", &claw_tx);
	r.produce().await;
	assert!(r.rt.client().confirmations(&claw_tx.txid()).unwrap() >= 1);
	let _ = transfer;
}
