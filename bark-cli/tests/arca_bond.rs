//! The operator's equivocation bond, from the wallet's side, with the `arca`
//! binary against a whole Arca server on an anchored proof-of-stake regtest
//! chain. A wallet whose operator posts no bond says so and takes a payment
//! out of round; once the operator posts one, the wallet checks it on its
//! own node and requires it: a payment worth more than the bond is refused,
//! one under it taken. Then the sender and a signer that breaks the
//! once-per-salt rule spend the sender's board, the coin the receiver was
//! paid out of, a second time on the chain: the receiver's `watch-bond`
//! reads the operator's signature from that spend, finds it beside the one
//! the receiver's coin carries under the same salt, and burns the bond in a
//! block. That second spend ends its witness with an annex (BIP341), which
//! the operator's signature does not cover: relay policy refuses it, a block
//! producer that takes non-standard transactions (this chain's node, started
//! with `-acceptnonstdtxn=1`) mines it, and the watcher reads it as the plain
//! spend. With the bond gone, and with a second bond in notice, the wallet
//! takes no payment out of round.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::str::FromStr;

use elements::{AssetId, OutPoint, Script, Transaction};
use serde_json::Value;

use arca_covenant::bond::{self, BondPolicy};
use arca_covenant::spend::collab_tx;
use arca_covenant::{CoinRecord, ExplicitOutput, FeeSource, Pair, Rebindable, RelativeTime};
use bark::arca::keys::Keys;
use common::cli::Arca;
use common::running::{keypair, Running};
use server::bond::BondSection;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from(unhex(h))
}

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// The height of the block that holds `txid`.
fn height_of(r: &Running, txid: &str) -> u64 {
	let tx: Value = r.rt.client().call("getrawtransaction", &[Value::from(txid), Value::from(true)]).unwrap();
	let header: Value = r.rt.client().call("getblockheader", &[tx["blockhash"].clone()]).unwrap();
	header["height"].as_u64().unwrap()
}

const BOND: u64 = 5_000_000;

/// The least notice delay at the default exit-delay bounds, in units.
fn notice_units() -> u16 {
	server::bond::min_notice_seconds(server::bond::LIFETIME, RelativeTime::from_units(338).unwrap()).div_ceil(512) as u16
}

/// Posts a bond of `BOND` of X under `w`, and names it in the server's
/// configuration (with `notice`, once given), the server started again.
async fn post(r: &mut Running, policy: &BondPolicy, w: &elements::secp256k1_zkp::Keypair) -> OutPoint {
	let x = r.x;
	let tx = r.pay_to(policy.script_pubkey(), x, BOND);
	r.produce().await;
	r.bury().await;
	let vout = tx.output.iter().position(|o| o.script_pubkey == policy.script_pubkey()).unwrap() as u32;
	let op = OutPoint::new(tx.txid(), vout);
	r.config.bond = Some(BondSection { withdraw_key: w.x_only_public_key().0.to_string(), notice_units: notice_units(),
		outpoint: Some(format!("{}:{}", op.txid, op.vout)), notice: None });
	r.restart_server().await;
	r.synced().await;
	op
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bond_covers_payments_out_of_round_and_a_double_spend_burns_it() {
	// A block producer that takes non-standard transactions: the annexed
	// double spend below reaches a block through its mempool.
	let mut r = Running::start_on(&["-acceptnonstdtxn=1"], |_, _, _| {}).await;
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("bond A");
	let b = Arca::new("bond B");
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1",
		"--min-exit-delay-units", "1"];
	a.ok(&create);
	b.ok(&create);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, r.x, 10_000_000);
	let s = script(&b.ok(&["address"]));
	r.pay_to(s, r.x, 2_000_000);
	r.produce().await;
	let ab = a.ok(&["board", &x, "2000000"]);
	let a_board = ab["leaf_id"].as_str().unwrap().to_string();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the server to credit A's board", || a.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	a.ok(&["sync"]);

	// --- An operator with no bond: said, and taken ---
	let req = b.ok(&["receive"]);
	println!("B's request from an operator with no bond: bond note {}", req["bond"]);
	assert!(req["bond"].as_str().unwrap().contains("posts no bond"), "{}", req);
	assert_eq!(b.ok(&["bond"])["state"], "none");
	b.ok(&["forget-request", req["details"]["owner"].as_str().unwrap()]);

	// --- The operator posts a bond ---
	let w = keypair("bond W");
	let s_key = keypair("operator");
	let chain = arca_covenant::Chain::new(r.rt.client().genesis_hash().unwrap());
	let policy = BondPolicy::new(chain, s_key.x_only_public_key().0, w.x_only_public_key().0,
		RelativeTime::from_units(notice_units()).unwrap()).unwrap();
	let bond_at = post(&mut r, &policy, &w).await;
	let bb = b.ok(&["bond"]);
	println!("B's check of the bond: {}", bb);
	assert_eq!((bb["state"].as_str(), bb["required"].as_bool()), (Some("bonded"), Some(true)));
	assert_eq!(bb["coin"], format!("{}:{}", bond_at.txid, bond_at.vout));

	// More out of round than the bond is worth: refused. Under it: taken.
	b.refused(&["receive", "--asset", &x, "--amount", "6000000"], "more than the bond's");
	let req = b.ok(&["receive", "--asset", &x, "--amount", "600000"]);
	assert!(req["bond"].is_null(), "a bonded operator: no note: {}", req);
	let request = req["request"].as_str().unwrap().to_string();
	a.ok(&["send", &request, "--amount", "600000", "--asset", &x]);
	let mb = b.ok(&["mailbox"]);
	let got = &mb["accepted"][0];
	assert_eq!((got["value"].as_str(), got["state"].as_str()), (Some("600000"), Some("live")), "{}", mb);
	assert!(mb["uncovered"].is_null(), "the bond covers it: {}", mb);
	let bb = b.ok(&["bond"]);
	assert_eq!(bb["covers"], true, "{}", bb);
	println!("B holds out of round {}", bb["out_of_round"]);

	// The operator's signatures B's coin carries, as evidence lines.
	let lines = b.ok(&["bond-evidence"])["lines"].as_array().unwrap().clone();
	println!("B's evidence: {} line(s)", lines.len());
	assert!(!lines.is_empty());

	// BEFORE: the board B's coin rests on stands, so nothing can spend under
	// its salt yet: the watcher reads no block, and finds nothing.
	let quiet = b.ok(&["watch-bond"]);
	println!("B's watch-bond while the board stands: {}", quiet["scanned"]);
	assert_eq!(quiet["scanned"]["blocks"], 0, "no block read while the board stands: {}", quiet["scanned"]);
	assert!(quiet["scanned"]["from"].is_null(), "{}", quiet["scanned"]);
	assert_eq!(quiet["conflicts"], serde_json::json!([]), "{}", quiet);
	// What that run noted as read is set aside, so the run after the theft
	// starts as a wallet's first does: from the block of the spent board.
	let db = rusqlite::Connection::open(b.dir.join("arca.sqlite")).unwrap();
	db.execute("DELETE FROM meta WHERE key IN ('bond_scanned', 'bond_salts')", []).unwrap();
	drop(db);

	// --- A and a signer that breaks the rule spend A's board again ---
	let rec = CoinRecord::from_bytes(&unhex(a.ok(&["record", &a_board])["record"].as_str().unwrap())).unwrap();
	let CoinRecord::Board(board) = rec else { panic!("A's coin is a board") };
	let bp = board.policy();
	let board_tx: Transaction = r.rt.client().raw_transaction(&elements::Txid::from_str(ab["txid"].as_str().unwrap()).unwrap()).unwrap();
	let vout = board_tx.output.iter().position(|o| o.script_pubkey == bp.script_pubkey()).unwrap() as u32;
	let board_at = OutPoint::new(board_tx.txid(), vout);
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap();
	let a_key = Keys::new(mnemonic.trim(), 0, 1).unwrap().leaf(&board.owner_nonce).unwrap();
	assert_eq!(a_key.x_only_public_key().0, board.owner);
	let back = ExplicitOutput::new(board.asset, board.value - 5_000, script(&a.ok(&["address"])));
	let m = bp.message(board.asset, board.value, std::slice::from_ref(&back)).unwrap();
	let sign = |k: &elements::secp256k1_zkp::Keypair| arca_covenant::sign::sign_digest(k, &m.digest, &[3; 32]);
	let pair = Pair { operator: sign(&s_key), owner: sign(&a_key) };
	let mut theft = collab_tx(&bp, board_at, board.asset, board.value, std::slice::from_ref(&back), &pair, &FeeSource::Reserve).unwrap();
	// An annex on the witness: the signatures commit to no annex, so it
	// changes nothing the covenant checks, and not the txid.
	let plain_txid = theft.tx.txid();
	theft.tx.input[0].witness.script_witness.push(vec![0x50, 0xb0, 0x4d]);
	assert_eq!(theft.tx.txid(), plain_txid);
	let stolen = r.rt.client().send_raw_transaction(&theft.tx).unwrap();
	r.produce().await;
	r.bury().await;
	let mined: Transaction = r.rt.client().raw_transaction(&stolen).unwrap();
	let w = &mined.input[0].witness.script_witness;
	assert_eq!((w.len(), w[w.len() - 1].clone()), (6, vec![0x50, 0xb0, 0x4d]), "the block carries the annex");
	println!("A and the rule-breaking signer spend A's board again, an annex on its witness ({} items): {}", w.len(), stolen);
	assert!(lines.iter().any(|l| l["salt"] == hex(&board.salt())), "B's evidence names the board's salt");

	// --- B's watcher burns the bond ---
	let watched = b.ok(&["watch-bond"]);
	println!("B's watch-bond: {}", watched);
	// B's coin rests on A's board: no spend of it is older, so B reads the
	// chain from the board's block, not from as far back as a first scan
	// may go.
	let board_height = height_of(&r, ab["txid"].as_str().unwrap());
	let tip = r.rt.client().block_count().unwrap();
	assert_eq!(watched["scanned"]["from"], board_height, "read from the block of the board B's coin rests on: {}", watched["scanned"]);
	assert_eq!(watched["scanned"]["blocks"], tip - board_height + 1, "{}", watched["scanned"]);
	assert!(board_height > 1, "a chain older than the board, unread");
	assert_eq!(watched["evidence"]["from_chain"], 1, "the operator's second signature, read from the chain");
	assert_eq!(watched["conflicts"].as_array().unwrap().len(), 1);
	assert_eq!(watched["conflicts"][0]["salt"], hex(&board.salt()));
	let slash = elements::Txid::from_str(watched["slashed"][0]["txid"].as_str().unwrap()).unwrap();
	// Run again before the slash's block: the signature read from the chain
	// is kept, so the conflict stands, and the slash is sent again, never a
	// second one; the chain is read on from where the first run stopped.
	let waiting = b.ok(&["watch-bond"]);
	println!("B's watch-bond while the slash waits: {}", waiting);
	assert_eq!(waiting["conflicts"].as_array().unwrap().len(), 1, "{}", waiting);
	assert_eq!(waiting["slashed"], serde_json::json!([]), "no second slash of the one bond: {}", waiting);
	assert_eq!(waiting["resent"][0]["txid"], slash.to_string(), "{}", waiting);
	assert_eq!(waiting["evidence"]["from_chain"], 0, "nothing new on the chain: {}", waiting);
	assert!(waiting["scanned"]["blocks"].as_u64().unwrap() <= 1, "read on, not again: {}", waiting["scanned"]);
	r.produce().await;
	r.bury().await;
	let tx: Transaction = r.rt.client().raw_transaction(&slash).unwrap();
	assert!(tx.input.iter().any(|i| i.previous_output == bond_at), "the slash spends the bond");
	assert_eq!(arca_covenant::issuer::burned(&tx, AssetId::from_str(&x).unwrap()), BOND, "the whole bond burned");
	let fee_asset = tx.output.iter().find(|o| o.is_fee()).and_then(|o| o.asset.explicit());
	println!("the slash {}: {} vB, burns {} of X, its fee in {:?}", slash, tx.vsize(), BOND, fee_asset);
	assert_eq!(fee_asset.map(|a| a.to_string()), Some(x.clone()), "the fee in the bond's own asset, from B's coin");
	let again = b.ok(&["watch-bond"]);
	assert_eq!(again["slashed"], serde_json::json!([]), "the bond is gone: nothing to slash again: {}", again);

	// --- With the bond gone, nothing out of round ---
	r.synced().await;
	let bb = b.ok(&["bond"]);
	println!("B's check once the bond is burned: {} ({})", bb["state"], bb["why"]);
	assert_eq!(bb["state"], "missing");
	b.refused(&["receive", "--asset", &x, "--amount", "600000"], "bond is missing");

	// The operator's own server, started again, sees the second signature
	// too: a collaborative spend of a board its database never co-signed.
	r.server.stop();
	let e = server::server::Server::start(&r.config).await.err().expect("refused");
	println!("the operator's server started again: {}", e);
	assert!(e.to_string().contains("which the database has no record of co-signing"), "{}", e);
}

/// A bond in notice: the wallet takes no payment out of round from its
/// operator, and names when the bond can be withdrawn.
#[tokio::test(flavor = "multi_thread")]
async fn a_bond_in_notice_takes_no_payment_out_of_round() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let b = Arca::new("notice B");
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1",
		"--min-exit-delay-units", "1"];
	b.ok(&create);
	let w = keypair("notice W");
	let chain = arca_covenant::Chain::new(r.rt.client().genesis_hash().unwrap());
	let policy = BondPolicy::new(chain, keypair("operator").x_only_public_key().0, w.x_only_public_key().0,
		RelativeTime::from_units(notice_units()).unwrap()).unwrap();
	post(&mut r, &policy, &w).await;
	assert_eq!(b.ok(&["bond"])["state"], "bonded");
	// B holds no coin that rests on a signature of the operator: its watcher
	// has no salt to look for, and reads no block.
	let watched = b.ok(&["watch-bond"]);
	println!("B's watch-bond with nothing to watch: {}", watched);
	assert_eq!(watched["scanned"]["blocks"], 0, "{}", watched);
	assert!(watched["scanned"]["from"].is_null(), "{}", watched);
	assert_eq!(watched["evidence"]["salts"], 0, "{}", watched);
	b.ok(&["receive", "--asset", &x, "--amount", "600000"]);
	// The operator gives the notice, its fee from its on-chain wallet.
	r.fund_server(r.x, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let key_file = b.dir.join("bond-w.key");
	{
		use std::os::unix::fs::OpenOptionsExt;
		let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&key_file).unwrap();
		std::io::Write::write_all(&mut f, hex(&w.secret_bytes()).as_bytes()).unwrap();
	}
	let noticed = server::server::bond_notice(&r.config, &key_file).await.unwrap();
	println!("the notice: {}", noticed);
	r.produce().await;
	r.bury().await;
	// Before the configuration names it, the bond reads as spent: missing.
	r.restart_server().await;
	r.synced().await;
	let bb = b.ok(&["bond"]);
	println!("B's check, the notice not yet named: {} ({})", bb["state"], bb["why"]);
	assert_eq!(bb["state"], "missing");
	b.refused(&["receive", "--asset", &x, "--amount", "600000"], "bond is missing");
	r.config.bond.as_mut().unwrap().notice = Some(noticed["notice"].as_str().unwrap().into());
	r.restart_server().await;
	r.synced().await;
	let bb = b.ok(&["bond"]);
	println!("B's check of the bond in notice: {} withdrawable at {}", bb["state"], bb["withdrawable_at"]);
	assert_eq!(bb["state"], "noticed");
	assert!(bb["withdrawable_at"].as_u64().is_some());
	b.refused(&["receive", "--asset", &x, "--amount", "600000"], "bond is noticed");
	b.refused(&["swap", "offer", "--give-asset", &x, "--give", "300000", "--want-asset", &r.y.to_string(), "--want", "400000"],
		"bond is noticed");
}
