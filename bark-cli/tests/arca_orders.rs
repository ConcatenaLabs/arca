//! An order placed on the chain by a maker holding only leaves, as the `arca`
//! wallet places it, against a whole Arca server on an anchored
//! proof-of-stake regtest chain.
//!
//! The maker boards all of its X and holds no coin on the chain. It places
//! an order selling 1,000,000 X for Y at 3/2 with `arca order place`: the
//! fee is quoted and shown, the refusals are printed as the wallet words
//! them, and the placement waits while the test runs the operator's round:
//! the wallet hands over its forfeit once the round is final, the operator's
//! watcher unlocks the offboard into the order's address, and the command
//! answers where the order rests, final, with its terms as SeqDEX's relay
//! serves them. The maker's process is then stopped. Two takers holding Y
//! fill the order in part, one after the other, through the operator's fill
//! rounds (`arca take`), each round crediting the maker at `2k` and resting
//! the rest at `2k+1` under the identical script. A wallet made from the
//! maker's mnemonic alone finds the credits at the order's key and the coin
//! it gave up as spent. The maker comes back: `arca orders` reads both fills
//! from the chain, and the maker boards its credits from the order's key. Its
//! REFUND is refused by the wallet and by the node before the order's expiry,
//! and mined after it, taking the rest home.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::time::{Duration, Instant};

use elements::{AssetId, OutPoint, Script, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::fill::FillOrder;
use arca_covenant::spend::FeeSource;
use arca_covenant::{CoinRecord, ExplicitOutput};
use common::cli::Arca;
use common::running::Running;
use server::server::AssetSection;
use server::store::RoundState;

fn unhex(h: &str) -> Vec<u8> {
	(0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn create_args<'a>(server: &'a str, node: &'a str) -> Vec<&'a str> {
	vec!["create", "--server", server, "--node-url", node, "--node-user", "arca",
		"--exit-delay-units", "1", "--min-exit-delay-units", "1"]
}

fn script(v: &Value) -> Script {
	Script::from(unhex(v["script_pubkey"].as_str().unwrap()))
}

/// A wallet whose only holding of `asset` is one coin boarded whole: it
/// pays itself `paid` on the chain and boards all of it but the board's fee,
/// so nothing of `asset` is left on the chain.
async fn leaves_only(r: &mut Running, name: &str, asset: AssetId, paid: u64) -> Arca {
	let (url, node) = (r.url(), r.node_url());
	let w = Arca::new(name);
	w.ok(&create_args(&url, &node));
	let s = script(&w.ok(&["address"]));
	r.pay_to(s, asset, paid);
	r.produce().await;
	board_all(&w, asset, paid);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
	let b = w.ok(&["balance", "--without-bitcoin"]);
	assert!(b["sequentia_onchain"].get(asset.to_string()).is_none(), "{} holds nothing of the asset on the chain: {}", name, b);
	w
}

/// Boards all of the wallet's `held` of `asset` on the chain but the board's
/// own fee: the amount whose board, at its fee, leaves no change.
fn board_all(w: &Arca, asset: AssetId, held: u64) -> u64 {
	let mut amount = held / 2;
	for _ in 0..4 {
		let q = w.ok(&["board", &asset.to_string(), &amount.to_string(), "--quote"]);
		let fee: u64 = q["fee"]["amount"].as_str().unwrap().parse().unwrap();
		if amount + fee == held {
			break;
		}
		amount = held - fee;
	}
	w.ok(&["board", &asset.to_string(), &amount.to_string()]);
	amount
}

fn live_of(w: &Arca, asset: AssetId) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == json!(asset.to_string())).cloned().collect()
}

fn print_round(tx: &Transaction) {
	println!("round {} ({} vB):", tx.txid(), tx.vsize());
	for (i, inp) in tx.input.iter().enumerate() {
		println!("  input {}: {}:{}{}", i, inp.previous_output.txid, inp.previous_output.vout, if inp.has_issuance() { " (issues the token)" } else { "" });
	}
	for (j, o) in tx.output.iter().enumerate() {
		println!("  output {}: {} of {}{}", j, o.value.explicit().unwrap(), o.asset.explicit().unwrap(), if o.is_fee() { " (fee)" } else { "" });
	}
}

/// The order as a relay serves it, in a file for `arca take @FILE`.
fn served(name: &str, relay: &Value) -> String {
	let path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("order-{}-{}.json", std::process::id(), name));
	std::fs::write(&path, json!({"offer_id": name, "covenant": relay}).to_string()).unwrap();
	format!("@{}", path.display())
}

/// Runs `arca` with `args` in a thread of its own, as a user's process that
/// waits: its success and JSON when it ends.
fn spawn(w: &Arca, args: Vec<String>) -> std::thread::JoinHandle<(bool, Value)> {
	let dir = w.dir.clone();
	std::thread::spawn(move || {
		let out = std::process::Command::new(env!("CARGO_BIN_EXE_arca")).arg("--datadir").arg(&dir).arg("--witness-patience").arg("3")
			.args(&args).env("ARCA_NODE_PASSWORD", "arca").output().expect("run arca");
		let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("not JSON ({}): {}\n{}", e,
			String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)));
		(out.status.success(), v)
	})
}

/// One fill round of the operator's, its takes' forfeits handed over by
/// `takers`' syncs, broadcast, final, and each taker's leaf taken.
async fn fill_round(r: &mut Running, takers: &[&Arca]) -> Transaction {
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	assert_eq!(built.len(), 1, "one fill round");
	let tx = built[0].tx.clone();
	print_round(&tx);
	for t in takers {
		t.ok(&["sync"]);
	}
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.round_state(&tx.txid(), RoundState::Final).await;
	for t in takers {
		t.ok(&["sync"]);
	}
	tx
}

#[tokio::test(flavor = "multi_thread")]
async fn a_maker_holding_only_leaves_places_an_order_two_takers_fill() {
	// X carries an offboard fee of 1,000 atoms. Both X and Y are taken for
	// fees, each paying its own.
	let mut r = Running::start_with(|c, x, _| {
		c.assets[0] = AssetSection::new(x, 1_000);
		c.assets[0].offboard_base = Some("1000".into());
	}).await;
	let (x, y) = (r.x, r.y);
	common::node::list_fee_asset(&r.rt, y, 100_000_000);
	let maker = leaves_only(&mut r, "OM", x, 1_500_000).await;
	let coin = live_of(&maker, x).remove(0);
	let coin_id = coin["leaf_id"].as_str().unwrap().to_string();
	println!("the maker holds one coin of X, {}, and nothing of X on the chain", coin["value"]);

	// What the wallet refuses before it signs anything.
	let base = |extra: &[&str]| -> Vec<String> {
		let mut v: Vec<String> = ["order", "place", "--sell", &x.to_string(), "--amount", "1000000", "--for", &y.to_string(),
			"--rate-num", "3", "--rate-den", "2", "--min-lot", "100000", "--wait", "0"].iter().map(|s| s.to_string()).collect();
		v.extend(extra.iter().map(|s| s.to_string()));
		v
	};
	fn run(args: &[String]) -> Vec<&str> {
		args.iter().map(|s| s.as_str()).collect()
	}
	// Its own coin's script as the maker program: an Arca script.
	let rec = maker.ok(&["record", &coin_id]);
	let (board, leaf) = match CoinRecord::from_bytes(&unhex(rec["record"].as_str().unwrap())).unwrap() {
		CoinRecord::Board(b) => (b.output().script_pubkey, b.leaf().script_pubkey()),
		other => panic!("a board coin: {:?}", other),
	};
	for (what, s) in [("board", &board), ("leaf", &leaf)] {
		let a = base(&["--expires-in-hours", "48", "--maker-prog", &hex(&s.as_bytes()[2..])]);
		maker.refused(&run(&a), &format!("is the {} script of the wallet's coin", what));
	}
	let a = base(&["--expires", "1000"]);
	maker.refused(&run(&a), "is a height");
	let a = base(&["--expires-in-hours", "2"]);
	maker.refused(&run(&a), "the operator takes no take of an order refundable within");
	let mut a = base(&["--expires-in-hours", "48"]);
	assert_eq!(a[10], "--rate-den");
	a[11] = "7".into();
	maker.refused(&run(&a), "SeqDEX's relay lists an order only when");
	let a = base(&["--expires-in-hours", "48", "--max-fee-ppm", "1"]);
	maker.refused(&run(&a), "above the wallet's bound");
	let a = base(&["--expires-in-hours", "48", "--amount", "2000000"]);
	let mut a2 = a.clone();
	a2.drain(4..6);
	maker.refused(&run(&a2), "the wallet's live coins of asset");

	// The quote, then the placement, which waits while the operator runs
	// its round.
	let a = base(&["--expires-in-hours", "48"]);
	let mut q_args = a.clone();
	q_args.push("--quote".into());
	let q = maker.ok(&run(&q_args));
	println!("the quote: fee {} (refresh {}, offboard {}, unlock margin {}), change {}", q["fee"]["amount"], q["fee"]["refresh"],
		q["fee"]["offboard"], q["fee"]["unlock_margin"], q["change"]);
	assert_eq!(q["gives"], json!([coin_id]));
	let mut p_args = a.clone();
	p_args.retain(|s| s != "--wait" && s != "0");
	p_args.extend(["--shown".into(), q.to_string(), "--wait".into(), "300".into()]);
	let placing = spawn(&maker, p_args);
	let start = Instant::now();
	let round = loop {
		let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
		assert!(failed.is_empty(), "{:?}", failed);
		if let Some(b) = built.into_iter().find(|b| b.offboards > 0) {
			break b;
		}
		assert!(start.elapsed() < Duration::from_secs(60), "the order's participation never reached a round");
		tokio::time::sleep(Duration::from_millis(500)).await;
	};
	print_round(&round.tx);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.round_state(&round.tx.txid(), RoundState::Final).await;
	// The maker's process hands over its forfeit; the watcher unlocks the
	// offboard into the order's address; the order is buried.
	let start = Instant::now();
	while !placing.is_finished() {
		r.server.watcher.pass().await.unwrap();
		r.produce().await;
		r.bury().await;
		r.synced().await;
		assert!(start.elapsed() < Duration::from_secs(240), "the placement did not complete");
		tokio::time::sleep(Duration::from_millis(500)).await;
	}
	let (ok, placed) = placing.join().unwrap();
	assert!(ok, "{}", placed);
	println!("OM $ arca order place … --shown … --wait 300\n{}", serde_json::to_string(&placed).unwrap());
	let order = placed["order"].as_str().unwrap().to_string();
	let rests = &placed["placed"];
	assert_eq!((rests["state"].as_str(), rests["final"].as_bool(), rests["holds"].as_str()), (Some("resting"), Some(true), Some("1000000")));
	let relay = rests["relay"].clone();
	let (at, terms) = FillOrder::from_relay(&relay).unwrap();
	let unlock = r.rt.client().raw_transaction(&at.txid).unwrap();
	assert_eq!(at.vout, 0, "the unlock pays the order at its output 0");
	assert_eq!(unlock.input[0].previous_output.txid, round.tx.txid(), "the unlock spends the round's offboard output");
	assert_eq!(ExplicitOutput::from_txout(&unlock.output[0]).unwrap(), ExplicitOutput::new(x, 1_000_000, terms.script_pubkey()),
		"the order rests under SeqDEX's own two-leaf script, holding exactly its amount");
	assert!(maker.ok(&["coins"]).as_array().unwrap().iter().any(|c| c["leaf_id"] == json!(coin_id) && c["state"] == "spent"));
	println!("the order rests at {} under {}; the maker's process stops here", at, terms.script_pubkey());

	// Two takers holding Y fill it in part, one after the other.
	let t1 = leaves_only(&mut r, "OT1", y, 900_000).await;
	let t2 = leaves_only(&mut r, "OT2", y, 700_000).await;
	let k1 = t1.ok(&["take", &served("o-1", &relay), "--amount", "400000"]);
	assert_eq!((k1["price"].as_str(), k1["remainder"].as_str()), (Some("600000"), Some("600000")));
	let r1 = fill_round(&mut r, &[&t1]).await;
	assert_eq!(r1.input[0].previous_output, at, "the order at input 0");
	assert_eq!(ExplicitOutput::from_txout(&r1.output[0]).unwrap(), ExplicitOutput::new(y, 600_000, terms.maker_script_pubkey()),
		"the maker's credit at 0, to its key");
	assert_eq!(ExplicitOutput::from_txout(&r1.output[1]).unwrap(), ExplicitOutput::new(x, 600_000, terms.script_pubkey()),
		"the rest at 1, under the identical script");
	let again = OutPoint::new(r1.txid(), 1);
	let k2 = t2.ok(&["take", &served("o-2", &terms.to_relay(&again)), "--amount", "300000"]);
	assert_eq!(k2["price"].as_str(), Some("450000"));
	let r2 = fill_round(&mut r, &[&t2]).await;
	assert_eq!(r2.input[0].previous_output, again);
	assert_eq!(ExplicitOutput::from_txout(&r2.output[0]).unwrap(), ExplicitOutput::new(y, 450_000, terms.maker_script_pubkey()));
	assert_eq!(ExplicitOutput::from_txout(&r2.output[1]).unwrap(), ExplicitOutput::new(x, 300_000, terms.script_pubkey()));
	assert_eq!(live_of(&t1, x).iter().map(|c| c["value"].clone()).collect::<Vec<_>>(), vec![json!("400000")]);
	assert_eq!(live_of(&t2, x).iter().map(|c| c["value"].clone()).collect::<Vec<_>>(), vec![json!("300000")]);

	// A wallet made from the maker's mnemonic alone: the coin given up is
	// spent, and the credits at the order's key are on the chain.
	let mnemonic = std::fs::read_to_string(maker.dir.join("mnemonic")).unwrap();
	let mr = Arca::new("OMR");
	let (url, node) = (r.url(), r.node_url());
	let mut args = create_args(&url, &node);
	args.extend(["--mnemonic", mnemonic.trim()]);
	let made = mr.ok(&args);
	println!("the maker restored: {}", made["restore"]);
	mr.ok(&["sync"]);
	assert!(mr.ok(&["coins"]).as_array().unwrap().iter().any(|c| c["leaf_id"] == json!(coin_id) && c["state"] == "spent"),
		"the coin given up for the order is spent in the restored wallet");
	assert_eq!(mr.ok(&["balance", "--without-bitcoin"])["sequentia_onchain"][y.to_string()], json!("1050000"),
		"the credits at the order's key");

	// The maker comes back.
	let os = maker.ok(&["orders"]);
	let o = &os[0];
	assert_eq!((o["state"].as_str(), o["rests_at"].as_str(), o["holds"].as_str()), (Some("resting"), Some(format!("{}:1", r2.txid()).as_str()),
		Some("300000")));
	assert_eq!(o["fills"].as_array().unwrap().iter().map(|f| (f["filled"].clone(), f["credited"].clone(), f["k"].clone()))
		.collect::<Vec<_>>(), vec![(json!("400000"), json!("600000"), json!(0)), (json!("300000"), json!("450000"), json!(0))]);
	assert_eq!(o["credits"].as_array().unwrap().len(), 2);
	assert_eq!(o["relay"], terms.to_relay(&OutPoint::new(r2.txid(), 1)), "the relay's form at its new outpoint");
	assert_eq!(maker.ok(&["balance", "--without-bitcoin"])["sequentia_onchain"][y.to_string()], json!("1050000"));
	let boarded = board_all(&maker, y, 1_050_000);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the credits boarded", || maker.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	maker.ok(&["sync"]);
	assert_eq!(live_of(&maker, y).iter().map(|c| c["value"].clone()).collect::<Vec<_>>(), vec![json!(boarded.to_string())],
		"the credits boarded from the order's key");
	assert!(maker.ok(&["balance", "--without-bitcoin"])["sequentia_onchain"].get(y.to_string()).is_none());

	// The REFUND: refused before the expiry, by the wallet and by the node.
	maker.refused(&["order", "refund", &order], "REFUND opens once the chain's median time passes");
	let keys = bark::arca::keys::Keys::new(mnemonic.trim(), 0, 1).unwrap();
	let early = terms.refund_tx(OutPoint::new(r2.txid(), 1), 300_000, &[ExplicitOutput::new(x, 297_000, common::node::op_true())],
		&FeeSource::Reserve).unwrap();
	assert_eq!(xonly_bytes(&keys.order(0).unwrap()), terms.maker_x, "the order's REFUND key is its order key");
	let sg = arca_covenant::sign::sign_digest(&keys.order(0).unwrap(), &early.sighash(r.rt.client().genesis_hash().unwrap()).unwrap(), &[0; 32]);
	let early = early.finish(vec![sg.as_ref().to_vec()]).tx;
	let e = r.rt.client().send_raw_transaction(&early).unwrap_err().to_string();
	println!("the REFUND before the expiry, sent to the node: refused, {}", e);
	assert!(e.contains("non-final"), "{}", e);
	common::node::advance_mtp(&r.rt, 49 * 3600);
	r.synced().await;
	let back = maker.ok(&["order", "refund", &order]);
	r.produce().await;
	let txid: Txid = back["refund"].as_str().unwrap().parse().unwrap();
	assert!(r.rt.client().confirmations(&txid).unwrap() >= 1, "the REFUND at its time is mined");
	let os = maker.ok(&["orders"]);
	assert_eq!(os[0]["state"], "refunded", "{}", os[0]);
	let b = maker.ok(&["balance", "--without-bitcoin"]);
	println!("the maker's X on the chain after the REFUND: {}", b["sequentia_onchain"][x.to_string()]);
	assert_eq!(b["sequentia_onchain"][x.to_string()], back["value"]);
}

fn xonly_bytes(k: &elements::secp256k1_zkp::Keypair) -> [u8; 32] {
	k.x_only_public_key().0.serialize()
}

/// An operator whose watcher never unlocks the order's offboard: the maker's
/// wallet, holding the preimage, unlocks it into the order's address itself
/// once the grace has passed, its margin paying the fee.
#[tokio::test(flavor = "multi_thread")]
async fn the_wallet_unlocks_its_order_when_the_operator_does_not() {
	let mut r = Running::start_with(|c, x, _| {
		c.assets[0] = AssetSection::new(x, 1_000);
		c.watcher.enabled = false;
	}).await;
	let (x, y) = (r.x, r.y);
	let maker = leaves_only(&mut r, "OU", x, 600_000).await;
	let placed = maker.ok(&["order", "place", "--sell", &x.to_string(), "--amount", "500000", "--for", &y.to_string(), "--rate-num", "1",
		"--rate-den", "1", "--expires-in-hours", "48", "--wait", "0"]);
	let order = placed["order"].as_str().unwrap().to_string();
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	assert_eq!(built[0].offboards, 1);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.round_state(&built[0].tx.txid(), RoundState::Final).await;
	let s = maker.ok(&["sync"]);
	println!("the maker's sync once the round is final: participations {}, orders {}", s["participations"], s["orders"]);
	assert_eq!(maker.ok(&["orders"])[0]["state"], "unlocking", "released, and the operator does not unlock it");
	// Within the grace the wallet leaves it to the operator.
	let s = maker.ok(&["sync"]);
	assert!(s["orders"].as_array().is_none_or(|o| o.iter().all(|e| e.get("unlocked").is_none())), "{}", s["orders"]);
	common::node::advance_mtp(&r.rt, 900);
	r.synced().await;
	let s = maker.ok(&["sync"]);
	let unlocked = s["orders"].as_array().unwrap().iter().find_map(|e| e["unlocked"].as_str()).map(str::to_string)
		.unwrap_or_else(|| panic!("the wallet did not unlock its order: {}", s["orders"]));
	println!("the wallet unlocked its order's offboard itself: {}", unlocked);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let o = &maker.ok(&["orders"])[0];
	assert_eq!((o["order"].as_str(), o["state"].as_str(), o["rests_at"].as_str(), o["holds"].as_str(), o["final"].as_bool()),
		(Some(order.as_str()), Some("resting"), Some(format!("{}:0", unlocked).as_str()), Some("500000"), Some(true)));
}
