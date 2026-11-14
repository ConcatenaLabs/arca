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
		outpoint: Some(format!("{}:{}", op.txid, op.vout)), notice: None, instant_budget_fraction: None, instant_limit_value: None });
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
	let noticed = server::server::bond_notice(&r.config, &key_file, None).await.unwrap();
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

/// Pays `amount` of `asset` to the bond's script, buried; the configuration
/// is left as it is.
async fn pay_bond(r: &mut Running, policy: &BondPolicy, asset: AssetId, amount: u64) -> OutPoint {
	let tx = r.pay_to(policy.script_pubkey(), asset, amount);
	r.produce().await;
	r.bury().await;
	let vout = tx.output.iter().position(|o| o.script_pubkey == policy.script_pubkey()).unwrap() as u32;
	OutPoint::new(tx.txid(), vout)
}

/// What `arca bond` says of the instant budget, as numbers.
fn budget_of(v: &Value) -> (u64, u64, u64, u64) {
	let b = &v["instant_budget"];
	let n = |k: &str| b[k].as_str().unwrap_or_else(|| panic!("instant_budget.{}: {}", k, v)).parse::<u64>().unwrap();
	(b["ppm"].as_u64().unwrap(), n("bond_value"), n("value"), n("room"))
}

/// The bond counts at its value at the wallet's node's rate, whatever its
/// asset: a bond in X (listed at one reference unit an atom, a stable
/// asset) at its atoms, a bond in Y (listed at a quarter) at a quarter of
/// them. A counterparty's instant budget, a share of that value, bounds what
/// it holds out of round at once, for a receive request and for a swap it
/// offers; the per-wallet refusal follows the same value; a lower price of
/// the bond's asset lowers both at once; the operator's suggested share,
/// when lower, is the one taken. The bond moves from X to Y with the
/// operator bonded throughout: the Y coin posted to the same script, the
/// configuration pointed at it, then the X coin given its notice by name.
#[tokio::test(flavor = "multi_thread")]
async fn an_instant_budget_follows_the_bonds_market_value() {
	let mut r = Running::start().await;
	let (x, y) = (r.x.to_string(), r.y.to_string());
	common::node::list_fee_asset(&r.rt, r.y, 25_000_000);
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("budget A");
	let b = Arca::new("budget B");
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1",
		"--min-exit-delay-units", "1"];
	a.ok(&create);
	b.ok(&create);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, r.x, 10_000_000);
	r.produce().await;
	a.ok(&["board", &x, "2000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the server to credit A's board", || a.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	a.ok(&["sync"]);

	// --- A bond of 5,000,000 X: X at one reference unit an atom ---
	let w = keypair("budget W");
	let chain = arca_covenant::Chain::new(r.rt.client().genesis_hash().unwrap());
	let policy = BondPolicy::new(chain, keypair("operator").x_only_public_key().0, w.x_only_public_key().0,
		RelativeTime::from_units(notice_units()).unwrap()).unwrap();
	let x_bond = post(&mut r, &policy, &w).await;
	b.refused(&["instant-budget", "1.5"], "at most 1");
	b.ok(&["instant-budget", "0.1"]);
	let bb = b.ok(&["bond"]);
	assert_eq!(budget_of(&bb), (100_000, BOND, BOND / 10, BOND / 10), "X counts at its atoms: {}", bb["instant_budget"]);
	b.refused(&["receive", "--asset", &x, "--amount", "600000"], "past its instant budget of 500000");
	let req = b.ok(&["receive", "--asset", &x, "--amount", "400000"]);
	a.ok(&["send", req["request"].as_str().unwrap(), "--amount", "400000", "--asset", &x]);
	let mb = b.ok(&["mailbox"]);
	assert_eq!(mb["accepted"][0]["value"], "400000", "{}", mb);
	let bb = b.ok(&["bond"]);
	assert_eq!(budget_of(&bb).3, 100_000, "500,000 less the 400,000 held out of round: {}", bb["instant_budget"]);

	// --- The bond moves to 40,000,000 Y, with the operator bonded throughout ---
	let ya = r.y;
	let y_bond = pay_bond(&mut r, &policy, ya, 40_000_000).await;
	assert_eq!(b.ok(&["bond"])["coin"], format!("{}:{}", x_bond.txid, x_bond.vout), "the X coin stands while Y is posted");
	r.config.bond.as_mut().unwrap().outpoint = Some(format!("{}:{}", y_bond.txid, y_bond.vout));
	r.restart_server().await;
	r.synced().await;
	let bb = b.ok(&["bond"]);
	println!("B's check of the Y bond: {}", bb);
	assert_eq!((bb["state"].as_str(), bb["asset"].as_str()), (Some("bonded"), Some(y.as_str())));
	// Y at a quarter of a reference unit: 40,000,000 Y are worth 10,000,000.
	assert_eq!(budget_of(&bb), (100_000, 10_000_000, 1_000_000, 600_000), "{}", bb["instant_budget"]);
	// The room in each priced asset's own atoms: 600,000 of X, 2,400,000 of Y.
	assert_eq!(bb["instant_budget"]["room_atoms"][&x], "600000", "{}", bb["instant_budget"]);
	assert_eq!(bb["instant_budget"]["room_atoms"][&y], "2400000", "{}", bb["instant_budget"]);

	// The per-wallet refusal, at the same value, with no budget set.
	b.ok(&["instant-budget", "off"]);
	assert!(b.ok(&["bond"])["instant_budget"].is_null());
	b.refused(&["receive", "--asset", &x, "--amount", "10500000"], "more than the bond's 10000000");
	let req = b.ok(&["receive", "--asset", &x, "--amount", "9000000"]);
	b.ok(&["forget-request", req["details"]["owner"].as_str().unwrap()]);

	// The budget, for a receive request and for a swap offered as a maker.
	b.ok(&["instant-budget", "0.1"]);
	b.refused(&["receive", "--asset", &x, "--amount", "700000"], "past its instant budget of 1000000");
	let req = b.ok(&["receive", "--asset", &x, "--amount", "500000"]);
	b.ok(&["forget-request", req["details"]["owner"].as_str().unwrap()]);
	b.refused(&["swap", "offer", "--give-asset", &x, "--give", "300000", "--want-asset", &y, "--want", "4000000"],
		"after the next round");
	let offer = b.ok(&["swap", "offer", "--give-asset", &x, "--give", "300000", "--want-asset", &y, "--want", "2000000"]);
	b.ok(&["swap", "cancel", offer["swap"].as_str().unwrap()]);

	// --- Y's price falls to 0.15: the budget falls with it, at once ---
	common::node::list_fee_asset(&r.rt, r.y, 15_000_000);
	let bb = b.ok(&["bond"]);
	assert_eq!(budget_of(&bb), (100_000, 6_000_000, 600_000, 200_000), "{}", bb["instant_budget"]);
	b.refused(&["receive", "--asset", &x, "--amount", "500000"], "past its instant budget of 600000");
	b.refused(&["receive", "--asset", &x, "--amount", "6000000"], "more than the bond's 6000000");

	// --- The operator suggests a twentieth: the lower share is taken ---
	r.config.bond.as_mut().unwrap().instant_budget_fraction = Some(0.05);
	r.restart_server().await;
	r.synced().await;
	let info = b.ok(&["info"])["server_info"].clone();
	println!("info.bond with a suggested share: {}", info["bond"]);
	assert_eq!(info["bond"]["instant_budget_ppm"], 50_000);
	match info["bond"]["reference_value"].as_str() {
		Some(v) => assert_eq!(info["bond"]["instant_budget"], (v.parse::<u64>().unwrap() / 20).to_string(), "a twentieth, at the operator's rate"),
		None => assert!(info["bond"]["instant_budget"].is_null(), "no rate of the operator's, no figure: {}", info["bond"]),
	}
	let bb = b.ok(&["bond"]);
	assert_eq!(budget_of(&bb), (50_000, 6_000_000, 300_000, 0), "{}", bb["instant_budget"]);
	assert_eq!(bb["instant_budget"]["own_ppm"], 100_000);
	b.refused(&["receive", "--asset", &x, "--amount", "1000"], "past its instant budget of 300000");
	// Past its budget, B asks for the refresh of what it holds at once.
	let sync = b.ok(&["sync"]);
	println!("B's sync past its budget: {}", sync);

	// --- The X coin retired: its notice, by name, leaves the Y bond standing ---
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
	let old = format!("{}:{}", x_bond.txid, x_bond.vout);
	let noticed = server::server::bond_notice(&r.config, &key_file, Some(&old)).await.unwrap();
	println!("the notice of the retired X coin: {}", noticed);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let notice_tx: Transaction = r.rt.client().raw_transaction(&elements::Txid::from_str(noticed["txid"].as_str().unwrap()).unwrap()).unwrap();
	assert!(notice_tx.input.iter().any(|i| i.previous_output == x_bond), "the notice spends the X coin");
	let bb = b.ok(&["bond"]);
	assert_eq!((bb["state"].as_str(), bb["coin"].as_str()), (Some("bonded"), Some(format!("{}:{}", y_bond.txid, y_bond.vout).as_str())),
		"the Y bond stands: {}", bb);
	let e = server::server::bond_notice(&r.config, &key_file, Some(&old)).await.unwrap_err();
	assert!(e.to_string().contains("not bonded"), "{}", e);
	let to = a.ok(&["address"])["address"].as_str().unwrap().to_string();
	let e = server::server::bond_withdraw(&r.config, &key_file, &to, Some((&old, noticed["notice"].as_str().unwrap()))).await.unwrap_err();
	println!("the retired coin's withdrawal before its delay: {}", e);
	assert!(e.to_string().contains("non-BIP68-final"), "{}", e);
}

/// What counts against an instant budget is what someone other than the
/// wallet could take with the operator: a coin whose lineage holds an input
/// the wallet does not own, at its whole value. A wallet's own change from
/// a plain payment out of its board is its key's alone, and counts nothing;
/// the coin its receiver holds counts whole.
#[tokio::test(flavor = "multi_thread")]
async fn own_change_counts_nothing_and_a_received_coin_counts_whole() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("own change A");
	let b = Arca::new("own change B");
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca", "--exit-delay-units", "1",
		"--min-exit-delay-units", "1"];
	a.ok(&create);
	b.ok(&create);
	let s = script(&a.ok(&["address"]));
	r.pay_to(s, r.x, 10_000_000);
	r.produce().await;
	a.ok(&["board", &x, "2000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the server to credit A's board", || a.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	a.ok(&["sync"]);
	let w = keypair("own change W");
	let chain = arca_covenant::Chain::new(r.rt.client().genesis_hash().unwrap());
	let policy = BondPolicy::new(chain, keypair("operator").x_only_public_key().0, w.x_only_public_key().0,
		RelativeTime::from_units(notice_units()).unwrap()).unwrap();
	post(&mut r, &policy, &w).await;
	for k in [&a, &b] {
		k.ok(&["instant-budget", "0.1"]);
	}
	// A pays B 300,000 out of its board: B holds 300,000 received, A about
	// 1,700,000 of its own change, both out of round.
	let req = b.ok(&["receive", "--asset", &x, "--amount", "300000"]);
	a.ok(&["send", req["request"].as_str().unwrap(), "--amount", "300000", "--asset", &x]);
	b.ok(&["mailbox"]);
	let change: u64 = a.ok(&["coins"]).as_array().unwrap().iter()
		.filter(|c| c["state"] == "live" && c["kind"] == "transfer").map(|c| c["value"].as_str().unwrap().parse::<u64>().unwrap()).sum();
	println!("OC: A's own change out of round: {}", change);
	assert!(change > 1_600_000, "A holds its change out of round");
	let (ab, bb) = (a.ok(&["bond"]), b.ok(&["bond"]));
	println!("OC: A's budget: {} | B's budget: {}", ab["instant_budget"], bb["instant_budget"]);
	assert_eq!(budget_of(&ab).3, BOND / 10, "A's own change counts nothing: its whole budget is room");
	assert_eq!(budget_of(&bb).3, BOND / 10 - 300_000, "B's received coin counts whole");
	a.ok(&["receive", "--asset", &x, "--amount", "400000"]);
	b.refused(&["receive", "--asset", &x, "--amount", "400000"], "past its instant budget of 500000");
	for k in [&a, &b] {
		let _ = std::fs::remove_dir_all(&k.dir);
	}
}

/// The hostile seller with the operator, against a lock between two holders
/// (`htlc-2`): seller A locks its board to buyer B out of round, and B
/// holds the lock at once. Then A and a signer that breaks the once-per-salt
/// rule spend A's board, the lock's input, a second time on the chain: B's
/// lock is void, and B, which holds the operator's signature under the
/// board's salt from the lock's record, reads the second one from that spend
/// and burns the bond in a block. The loss is the received-payment trust a
/// coin out of round carries, bounded by the bond.
#[tokio::test(flavor = "multi_thread")]
async fn a_seller_and_the_operator_spending_a_locks_input_again_burn_the_bond() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let a = Arca::new("bond lock A");
	let b = Arca::new("bond lock B");
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
	let w = keypair("bond W");
	let s_key = keypair("operator");
	let chain = arca_covenant::Chain::new(r.rt.client().genesis_hash().unwrap());
	let policy = BondPolicy::new(chain, s_key.x_only_public_key().0, w.x_only_public_key().0,
		RelativeTime::from_units(notice_units()).unwrap()).unwrap();
	let bond_at = post(&mut r, &policy, &w).await;
	assert_eq!(b.ok(&["bond"])["state"], "bonded");

	// --- A locks its board to B; B holds it at once ---
	let preimage = [0x61u8; 32];
	use bitcoin::hashes::Hash as _;
	let hash = hex(bitcoin::hashes::sha256::Hash::hash(&preimage).as_ref());
	let req = b.ok(&["lock", "request", "--asset", &x, "--amount", "600000", "--hash", &hash]);
	let locked = a.ok(&["lock", "to", &req.to_string(), "--timeout-in", "20000"]);
	println!("A locks to B: leaf {} timeout {}", locked["leaf_id"], locked["timeout"]);
	b.ok(&["sync"]);
	let ready = b.ok(&["lock", "ready", &hash]);
	assert_eq!(ready["ready"], true, "{}", ready);
	let lines = b.ok(&["bond-evidence"])["lines"].as_array().unwrap().clone();
	println!("B's evidence from the lock: {} line(s)", lines.len());
	let rec = CoinRecord::from_bytes(&unhex(a.ok(&["record", &a_board])["record"].as_str().unwrap())).unwrap();
	let CoinRecord::Board(board) = rec else { panic!("A's coin is a board") };
	assert!(lines.iter().any(|l| l["salt"] == hex(&board.salt())), "B holds the operator's signature under the board's salt: {:?}", lines);

	// --- A and the rule-breaking signer spend A's board again ---
	let bp = board.policy();
	let board_tx: Transaction = r.rt.client().raw_transaction(&elements::Txid::from_str(ab["txid"].as_str().unwrap()).unwrap()).unwrap();
	let vout = board_tx.output.iter().position(|o| o.script_pubkey == bp.script_pubkey()).unwrap() as u32;
	let board_at = OutPoint::new(board_tx.txid(), vout);
	let mnemonic = std::fs::read_to_string(a.dir.join("mnemonic")).unwrap();
	let a_key = Keys::new(mnemonic.trim(), 0, 1).unwrap().leaf(&board.owner_nonce).unwrap();
	let back = ExplicitOutput::new(board.asset, board.value - 5_000, script(&a.ok(&["address"])));
	let m = bp.message(board.asset, board.value, std::slice::from_ref(&back)).unwrap();
	let sign = |k: &elements::secp256k1_zkp::Keypair| arca_covenant::sign::sign_digest(k, &m.digest, &[3; 32]);
	let pair = Pair { operator: sign(&s_key), owner: sign(&a_key) };
	let theft = collab_tx(&bp, board_at, board.asset, board.value, std::slice::from_ref(&back), &pair, &FeeSource::Reserve).unwrap();
	let stolen = r.rt.client().send_raw_transaction(&theft.tx).unwrap();
	r.produce().await;
	r.bury().await;
	assert!(height_of(&r, &stolen.to_string()) > 0, "the second spend is in a block");
	println!("A and the signer spend the lock's input again: {}", stolen);

	// B's lock can no longer come on the chain: its input is spent elsewhere.
	let why = b.refused(&["lock", "ready", &hash], "spent elsewhere on the chain");
	println!("B's lock after the theft: {}", why);

	// --- B's watcher burns the bond ---
	let watched = b.ok(&["watch-bond"]);
	println!("B's watch-bond: evidence {} conflicts {} slashed {}", watched["evidence"], watched["conflicts"], watched["slashed"]);
	assert_eq!(watched["evidence"]["from_chain"], 1, "the operator's second signature, read from the chain");
	assert_eq!(watched["conflicts"][0]["salt"], hex(&board.salt()));
	let slash = elements::Txid::from_str(watched["slashed"][0]["txid"].as_str().unwrap()).unwrap();
	r.produce().await;
	r.bury().await;
	let tx: Transaction = r.rt.client().raw_transaction(&slash).unwrap();
	assert!(tx.input.iter().any(|i| i.previous_output == bond_at), "the slash spends the bond");
	assert_eq!(arca_covenant::issuer::burned(&tx, AssetId::from_str(&x).unwrap()), BOND, "the whole bond burned");
	println!("the slash {} is in block {}: it burns {} of X", slash, height_of(&r, &slash.to_string()), BOND);
}
