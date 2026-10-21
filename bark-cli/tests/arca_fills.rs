//! Taking on-chain orders, as the `arca` wallet does it, against a whole
//! Arca server on an anchored proof-of-stake regtest chain: two orders made
//! with SeqDEX's fill covenant sell Y for X (their scripts derived by SeqDEX's
//! own `seqob-covenant` when `SEQOB_COVENANT_EXEC` names it); two wallets
//! holding X take them with `arca take`, hand over their forfeits at `sync`
//! once the operator's round is built, and hold leaves of Y once it is final;
//! the makers are credited on the chain at `2k`, and the part of the first
//! order left resting is taken again from its new outpoint. Every refusal is
//! printed as the wallet words it.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::process::Command;

use elements::{AssetId, OutPoint, Script, Transaction};
use serde_json::{json, Value};

use arca_covenant::{ExplicitOutput, FillOrder};
use common::cli::Arca;
use common::running::{keypair, Running};
use sequentia_ext::{explicit_txout, AssetAmount};
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

/// An order selling Y for X at `num`/`den`, refundable from far ahead.
fn terms(r: &Running, maker: &str, num: u64, den: u64, min_lot: u64) -> FillOrder {
	let height = r.rt.client().blockchain_info().unwrap().blocks as u32;
	FillOrder {
		asset_a: r.y, asset_b: r.x, rate_num: num, rate_den: den, min_lot,
		maker_prog: keypair(&format!("{} payout", maker)).x_only_public_key().0.serialize(),
		expiry_locktime: height + 50_000,
		maker_x: keypair(maker).x_only_public_key().0.serialize(),
	}
}

/// Rests `locked` of Y under `terms`, at the script SeqDEX's own tool derives
/// when it is named (checked to be arca-covenant's), as a maker does.
fn rest(r: &mut Running, t: &FillOrder, locked: u64) -> OutPoint {
	let spk = match std::env::var("SEQOB_COVENANT_EXEC") {
		Ok(exec) => {
			let a = |x: AssetId| hex(&arca_covenant::script::asset_bytes(x));
			let out = Command::new(exec).args(["derive", "-a", &a(t.asset_a), "-b", &a(t.asset_b), "-num", &t.rate_num.to_string(),
				"-den", &t.rate_den.to_string(), "-minlot", &t.min_lot.to_string(), "-prog", &hex(&t.maker_prog), "-expiry",
				&t.expiry_locktime.to_string(), "-makerx", &hex(&t.maker_x)]).output().unwrap();
			assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
			let d: Value = serde_json::from_slice(&out.stdout).unwrap();
			let spk = Script::from(unhex(d["scriptpubkey"].as_str().unwrap()));
			assert_eq!(spk, t.script_pubkey());
			println!("order made with SeqDEX's seqob-covenant: {}", d["scriptpubkey"]);
			spk
		},
		Err(_) => {
			println!("order made with arca-covenant's builder (SEQOB_COVENANT_EXEC names no seqob-covenant)");
			t.script_pubkey()
		},
	};
	let tx = r.pay_to(spk, r.y, locked);
	OutPoint::new(tx.txid(), 0)
}

/// The order as a relay serves it: an offer whose settlement is the order's
/// `CovenantTerms`, written to a file for `arca take @FILE`.
fn served(name: &str, t: &FillOrder, at: &OutPoint) -> String {
	let path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("order-{}-{}.json", std::process::id(), name));
	let offer = json!({"offer_id": name, "give_asset": t.asset_a.to_string(), "want_asset": t.asset_b.to_string(),
		"covenant": t.to_relay(at)});
	std::fs::write(&path, offer.to_string()).unwrap();
	format!("@{}", path.display())
}

/// A wallet holding one live coin of `value` of X, boarded and credited.
async fn holder(r: &mut Running, name: &str, value: u64) -> Arca {
	let (url, node) = (r.url(), r.node_url());
	let w = Arca::new(name);
	w.ok(&create_args(&url, &node));
	let s = script(&w.ok(&["address"]));
	r.pay_to(s, r.x, value + 100_000);
	r.produce().await;
	w.ok(&["board", &r.x.to_string(), &value.to_string()]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the board credited", || w.ok(&["boards"]).as_array().unwrap().iter().all(|b| b["server"]["state"] == "credited")).await;
	w.ok(&["sync"]);
	w
}

fn live_of(w: &Arca, asset: AssetId) -> Vec<Value> {
	w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == json!(asset.to_string())).cloned().collect()
}

/// The round's inputs and outputs, by index.
fn print_round(tx: &Transaction) {
	println!("round {} ({} vB):", tx.txid(), tx.vsize());
	for (i, inp) in tx.input.iter().enumerate() {
		println!("  input {}: {}:{}{}", i, inp.previous_output.txid, inp.previous_output.vout, if inp.has_issuance() { " (issues the token)" } else { "" });
	}
	for (j, o) in tx.output.iter().enumerate() {
		println!("  output {}: {} of {}{}", j, o.value.explicit().unwrap(), o.asset.explicit().unwrap(), if o.is_fee() { " (fee)" } else { "" });
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn two_wallets_take_two_orders_and_hold_leaves() {
	// X carries an offboard fee of 1,000 atoms: a take pays it on the price.
	let mut r = Running::start_with(|c, x, _| {
		c.assets[0] = AssetSection::new(x, 1_000);
		c.assets[0].offboard_base = Some("1000".into());
	}).await;
	let (x, y) = (r.x, r.y);
	// Taker 1 holds 2,000,000 X, more than its take; taker 2 exactly its
	// take's price and fee.
	let t1 = holder(&mut r, "FT1", 2_000_000).await;
	let t2 = holder(&mut r, "FT2", 601_000).await;
	// Order 1 sells 1,000,000 Y at 1.5 X each, by lots of 10,000; order 2
	// sells 300,000 Y at 2 X each.
	let o1 = terms(&r, "maker 1", 3, 2, 10_000);
	let o2 = terms(&r, "maker 2", 2, 1, 1_000);
	let at1 = rest(&mut r, &o1, 1_000_000);
	let at2 = rest(&mut r, &o2, 300_000);
	r.produce().await;
	let (f1, f2) = (served("order-1", &o1, &at1), served("order-2", &o2, &at2));

	// Not final yet: the wallet refuses.
	r.synced().await;
	t1.refused(&["take", &f1, "--amount", "600000"], "a round takes an order once its transaction is final");
	r.bury().await;
	r.synced().await;

	// What the wallet refuses before it asks the operator anything.
	t1.refused(&["take", &f1, "--amount", "995000"], "leaves 5000 resting, below the order's min_lot of 10000");
	t1.refused(&["take", &f1, "--amount", "600000", "--max-fee-ppm", "1"], "above the wallet's bound of 1 ppm of the price");
	let mut keyed = o1.to_relay(&at1);
	keyed["internal_key"] = json!(arca_covenant::fill::base64(&keypair("maker 1").x_only_public_key().0.serialize()));
	t1.refused(&["take", &keyed.to_string()], "not the NUMS point");
	let other = FillOrder { rate_num: 1, ..o1.clone() };
	t1.refused(&["take", &other.to_relay(&at1).to_string()], "the terms do not make the script on the chain there");

	// The quote, then the takes.
	let q1 = t1.ok(&["take", &f1, "--amount", "600000", "--quote"]);
	assert_eq!((q1["price"].as_str(), q1["fee"].as_str(), q1["gives"].as_str(), q1["pays_itself_first"].as_bool()),
		(Some("900000"), Some("1000"), Some("901000"), Some(true)));
	let k1 = t1.ok(&["take", &f1, "--amount", "600000", "--shown", &q1.to_string()]);
	assert_eq!(k1["state"], "pending", "{}", k1);
	assert!(k1["paid_itself"].is_object(), "taker 1 paid itself a coin of the price and the fee first: {}", k1);
	let k2 = t2.ok(&["take", &f2]);
	assert_eq!((k2["state"].as_str(), k2["price"].as_str(), k2["remainder"].as_str()), (Some("pending"), Some("600000"), Some("0")));
	assert!(k2.get("paid_itself").is_none(), "taker 2 gave up its coin as it was: {}", k2);
	let (p1, p2) = (k1["take"].as_str().unwrap().to_string(), k2["take"].as_str().unwrap().to_string());

	// The round: built, held until every take's forfeits are in.
	let (built, failed) = r.server.rounds.run_rounds().await.unwrap();
	assert!(failed.is_empty(), "{:?}", failed);
	assert_eq!(built.len(), 1, "one fill round of Y");
	let b = &built[0];
	let tx = b.tx.clone();
	print_round(&tx);
	assert_eq!(b.fills, vec![at1, at2], "order 1 at input 0, order 2 at input 1");
	assert_eq!(b.batches, vec![(y, 4, 2)], "the batch of Y after the orders' four outputs");
	let rest1 = o1.plan(1_000_000, 600_000).unwrap();
	assert_eq!(ExplicitOutput::from_txout(&tx.output[0]).unwrap(), rest1.credit, "maker 1's credit at 0");
	assert_eq!(ExplicitOutput::from_txout(&tx.output[1]).unwrap(), rest1.rest.clone().unwrap(), "order 1 rests again at 1");
	assert_eq!(ExplicitOutput::from_txout(&tx.output[2]).unwrap(), o2.plan(300_000, 300_000).unwrap().credit, "maker 2's credit at 2");
	assert_ne!(tx.output[3].asset.explicit(), Some(y), "order 2 filled whole: no Y at its 2k+1");
	r.server.rounds.pass().await.unwrap();
	assert_eq!(r.server.store.round_by_txid(&elements::hashes::Hash::to_byte_array(tx.txid())).await.unwrap().unwrap().state,
		RoundState::Built, "held");

	// One more holder and one more order: taken by taker 4 first, so taker
	// 3's take of it is refused by the server, as the wallet prints it.
	let t3 = holder(&mut r, "FT3", 100_000).await;
	let t4 = holder(&mut r, "FT4", 41_000).await;
	let o3 = terms(&r, "maker 3", 2, 1, 1_000);
	let at3 = rest(&mut r, &o3, 20_000);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let f3 = served("order-3", &o3, &at3);
	// A fee of 1,000 on a price of 40,000 is 25,000 ppm: each raises its bound.
	t4.ok(&["take", &f3, "--max-fee-ppm", "30000"]);
	t3.refused(&["take", &f3, "--max-fee-ppm", "30000"], "the server refused take_order (409 order_taken)");


	// Each taker's sync hands its forfeits over; then the round goes out.
	for w in [&t1, &t2] {
		let s = w.ok(&["sync"]);
		println!("{} sync: {}", "a taker", s["participations"]);
	}
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.round_state(&tx.txid(), RoundState::Final).await;
	println!("round {} final: maker 1 credited 900000 X at output 0, maker 2 600000 X at output 2", tx.txid());

	// The takers take their leaves.
	for w in [&t1, &t2] {
		w.ok(&["sync"]);
	}
	let l1 = live_of(&t1, y);
	let l2 = live_of(&t2, y);
	println!("taker 1 holds {:?} of Y, taker 2 {:?}", l1.iter().map(|c| c["value"].clone()).collect::<Vec<_>>(),
		l2.iter().map(|c| c["value"].clone()).collect::<Vec<_>>());
	assert_eq!(l1.len(), 1);
	assert_eq!(l1[0]["value"], json!("600000"));
	assert_eq!(l2.len(), 1);
	assert_eq!(l2[0]["value"], json!("300000"));
	let parts = t1.ok(&["participations"]);
	assert!(parts.as_array().unwrap().iter().any(|p| p["participation"] == json!(p1) && p["released"] == json!(true)), "{}", parts);
	assert!(t2.ok(&["participations"]).as_array().unwrap().iter().any(|p| p["participation"] == json!(p2) && p["released"] == json!(true)));

	// Taker 2's device is lost: a wallet made from its mnemonic alone
	// restores the leaf of Y, and the coin of X it gave up in the take as
	// given up, the take's id recomputed from what the server serves.
	let t2r = Arca::new("FT2R");
	let mnemonic = std::fs::read_to_string(t2.dir.join("mnemonic")).unwrap();
	let (url, node) = (r.url(), r.node_url());
	let mut args = create_args(&url, &node);
	args.extend(["--mnemonic", mnemonic.trim()]);
	let made = t2r.ok(&args);
	println!("taker 2 restored: served {} | restored {} | not recovered {} | notes {}", made["restore"]["served"], made["restore"]["restored"],
		made["restore"]["not_recovered"], made["restore"]["notes"]);
	assert!(made["restore"]["error"].is_null(), "{}", made["restore"]);
	assert_eq!(made["restore"]["not_recovered"], json!([]), "{}", made["restore"]);
	t2r.ok(&["sync"]);
	let states = |w: &Arca| -> Vec<(String, String)> {
		let mut v: Vec<(String, String)> = w.ok(&["coins"]).as_array().unwrap().iter()
			.map(|c| (c["leaf_id"].as_str().unwrap().to_string(), c["state"].as_str().unwrap().to_string())).collect();
		v.sort();
		v
	};
	assert_eq!(states(&t2r), states(&t2), "the restored wallet holds every coin as the lost one did");
	assert_eq!(live_of(&t2r, y).iter().map(|c| c["value"].clone()).collect::<Vec<_>>(), vec![json!("300000")]);
	let parts = t2r.ok(&["participations"]);
	assert!(parts.as_array().unwrap().iter().any(|p| p["participation"] == json!(p2)), "the take restored: {}", parts);

	// Order 2 is spent; order 1 rests again at the round's output 1, and a
	// relay serving it there has it taken again.
	t3.refused(&["take", &f2], "is spent");
	let again_at = OutPoint::new(tx.txid(), 1);
	let f1b = served("order-1-again", &o1, &again_at);
	let k3 = t3.ok(&["take", &f1b, "--amount", "26666", "--max-fee-ppm", "30000"]);
	assert_eq!((k3["price"].as_str(), k3["fee"].as_str()), (Some("39999"), Some("1000")));
	// One round fills taker 4's order 3 and taker 3's rest of order 1.
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	assert_eq!(built.len(), 1);
	let again = built[0].tx.clone();
	print_round(&again);
	let k_rest = built[0].fills.iter().position(|o| *o == again_at).expect("the rest of order 1 is filled");
	let k_three = built[0].fills.iter().position(|o| *o == at3).expect("order 3 is filled");
	println!("order 3 at input {}, the rest of order 1 at input {}", k_three, k_rest);
	assert_eq!(built[0].fills.len(), 2);
	assert_eq!(o1.check(&again, k_rest, 400_000).unwrap().credited, 39_999);
	assert_eq!(o3.check(&again, k_three, 20_000).unwrap().remainder, 0);
	assert_eq!(again.output[2 * k_rest + 1].script_pubkey, o1.script_pubkey(), "order 1 rests again at its 2k+1");
	assert_eq!(built[0].batches[0].1, 4, "the batch after both orders' outputs");
	t3.ok(&["sync"]);
	t4.ok(&["sync"]);
	r.server.rounds.pass().await.unwrap();
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.round_state(&again.txid(), RoundState::Final).await;
	t3.ok(&["sync"]);
	t4.ok(&["sync"]);
	assert_eq!(live_of(&t3, y).iter().map(|c| c["value"].clone()).collect::<Vec<_>>(), vec![json!("26666")]);
	assert_eq!(live_of(&t4, y).iter().map(|c| c["value"].clone()).collect::<Vec<_>>(), vec![json!("20000")]);
	println!("order 1 rests again with {} of Y at {}:{}", 400_000 - 26_666, again.txid(), 2 * k_rest + 1);
}

/// R7l's F3 probe, turned around (D74): a take by a wallet that syncs only
/// when its schedule says it is due, as a program built on the library wakes
/// on `sync_schedule`. The fill round is built at once; the chain then moves
/// a minute at a time (twelve blocks, the parent chain burying them), the
/// server passing its rounds after each step. The schedule names a wake
/// within half the forfeit window while the take waits, saying why; the
/// wallet hands its forfeits over in time, the round goes out, and the take
/// completes: the wallet holds its leaf of Y, on the schedule alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_take_completes_on_the_schedule_alone() {
	let mut r = Running::start_with(|c, x, _| {
		c.assets[0] = AssetSection::new(x, 1_000);
		c.assets[0].offboard_base = Some("1000".into());
	}).await;
	let y = r.y;
	let t = holder(&mut r, "SCHED", 601_000).await;
	let o = terms(&r, "maker s", 2, 1, 1_000);
	let at = rest(&mut r, &o, 300_000);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	let k = t.ok(&["take", &served("sched", &o, &at)]);
	let pid = k["take"].as_str().unwrap().to_string();
	let sch = t.ok(&["schedule"]);
	println!("take {} {} | schedule: due {} next_sync_at {} (now {}) why {}", pid, k["state"], sch["due"], sch["next_sync_at"], sch["now"],
		sch["why"]);
	assert!(sch["why"].as_str().unwrap_or("").contains("a take of an on-chain order waits on its round"), "{}", sch);
	let wake = sch["next_sync_at"].as_u64().unwrap();
	assert!(wake <= sch["now"].as_u64().unwrap() + 300, "a wake within half the forfeit window: {}", sch);
	let (built, _) = r.server.rounds.run_rounds().await.unwrap();
	println!("the fill round built: {:?}", built.iter().map(|b| (b.tx.txid(), b.broadcast.clone())).collect::<Vec<_>>());
	assert_eq!(built.len(), 1);
	let mut syncs = 0;
	let mut released = false;
	for minute in 0..30 {
		let sch = t.ok(&["schedule"]);
		if sch["due"] == true {
			let s = t.ok(&["sync"]);
			syncs += 1;
			let p = s["participations"].as_array().cloned().unwrap_or_default();
			let mine = p.iter().find(|p| p["participation"] == json!(pid)).cloned().unwrap_or(Value::Null);
			println!("minute {}: due ({}); sync -> the take {} {}", minute, sch["why"], mine["state"], mine["note"]);
		}
		let parts = t.ok(&["participations"]);
		if parts.as_array().unwrap().iter().any(|p| p["participation"] == json!(pid) && p["state"] == "released") {
			released = true;
			println!("minute {}: the take is released", minute);
			break;
		}
		tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 60));
		r.bury().await;
		r.synced().await;
		r.server.rounds.pass().await.unwrap();
	}
	let row = r.server.store.round_by_txid(&elements::hashes::Hash::to_byte_array(built[0].tx.txid())).await.unwrap().unwrap();
	let held: Vec<Value> = live_of(&t, y).iter().map(|c| c["value"].clone()).collect();
	println!("{} syncs on the schedule; the round {:?}; the take released {}; the wallet holds Y {:?}", syncs, row.state, released, held);
	assert!(released, "the take completed on the schedule alone");
	assert_eq!(row.state, RoundState::Final);
	assert_eq!(held, vec![json!("300000")]);
	let after = t.ok(&["schedule"]);
	assert!(!after["why"].as_str().unwrap_or("").contains("a take of an on-chain order"), "no take wake once it is released: {}", after);
	let _ = std::fs::remove_dir_all(&t.dir);
}
