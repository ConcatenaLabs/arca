//! A claim tree, run with the `arca` binary against a whole Arca server on an
//! anchored proof-of-stake regtest chain. A payer boards its X and pays 20
//! holders in one round (`arca distribute`): eight are wallets that exist and
//! handed out an address (`arca address`, whose key the payer names), and
//! twelve exist only as mnemonics, named by an address key derived from them
//! (as an x-only key, a compressed public key, or the taproot address of the
//! key). Fourteen holders find and take up their leaves (`arca claims`, `arca
//! claim`), the twelve mnemonic ones by wallets created after the round,
//! never online before; six never do. In the claimed coins' free window
//! every claimed holder's `sync` refreshes its coin. At the claim batch's
//! expiry the operator releases and, after the notice, sweeps the batch, and
//! pays the six unclaimed claims back to the payer's return address, exactly;
//! every holder that claimed still holds its coin. Every refusal is asserted
//! by its reason.
//!
//! Needs `SEQUENTIAD_EXEC`, `ARCA_TEST_POSTGRES` and `arca-signer` (see
//! `tests/common/mod.rs`).

mod common;

use std::io::Write;

use elements::Script;
use serde_json::{json, Value};

use bark::arca::keys::{compressed, Keys, RECEIVE};
use common::cli::Arca;
use common::running::Running;
use server::store::RoundState;

const HOUR: u32 = 3_600;
const DAY: u32 = 86_400;

fn script(v: &Value) -> Script {
	let h = v["script_pubkey"].as_str().unwrap();
	Script::from((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect::<Vec<u8>>())
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn atoms(v: &Value) -> u64 {
	v.as_str().unwrap().parse().unwrap()
}

/// The live coins of `asset` a wallet holds, and what they hold together.
fn live(w: &Arca, asset: &str) -> (Vec<Value>, u64) {
	let c: Vec<Value> = w.ok(&["coins"]).as_array().unwrap().iter().filter(|c| c["state"] == "live" && c["asset"] == asset).cloned().collect();
	let total = c.iter().map(|c| atoms(&c["value"])).sum();
	(c, total)
}

/// The distribution as the payer sees it.
fn shown(p: &Arca) -> Value {
	p.ok(&["distributions"])[0].clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_payer_pays_twenty_holders_in_one_round_and_gets_back_what_nobody_took_up() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca"];

	// --- The payer boards its X ---
	let payer = Arca::new("payer");
	payer.ok(&create);
	r.pay_to(script(&payer.ok(&["address"])), r.x, 30_000_000);
	r.produce().await;
	payer.ok(&["board", &x, "22000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the payer's board to be credited", || payer.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	payer.ok(&["sync"]);

	// --- Twenty holders ---
	// Eight wallets that exist: each hands out an address, whose key the payer
	// names; one also holds an on-chain coin there.
	let existing: Vec<Arca> = (0..8).map(|i| Arca::new(&format!("existing {}", i))).collect();
	let mut keys: Vec<String> = vec![];
	for (i, w) in existing.iter().enumerate() {
		w.ok(&create);
		let a = w.ok(&["address"]);
		if i == 0 {
			r.pay_to(script(&a), r.x, 50_000);
		}
		keys.push(a["key"].as_str().unwrap().to_string());
	}
	// Twelve that exist only as mnemonics: the key of each one's first
	// receive address, named as an x-only key (six), a compressed public key
	// (three) or the key's taproot address (three).
	let mnemonics: Vec<String> = (0..12u8).map(|i| bip39::Mnemonic::from_entropy(&[i + 1; 16]).unwrap().to_string()).collect();
	for (i, m) in mnemonics.iter().enumerate() {
		let k = Keys::new(m, 0, 1).unwrap().onchain(RECEIVE, 0).unwrap();
		let xonly = hex(&k.x_only_public_key().0.serialize());
		keys.push(match i {
			0..=5 => xonly,
			6..=8 => hex(&compressed(&k)),
			_ => {
				let d: Value = r.rt.client().call("decodescript", &[json!(format!("5120{}", xonly))]).unwrap();
				d["address"].as_str().or_else(|| d["segwit"]["address"].as_str()).unwrap().to_string()
			},
		});
	}
	let value = |i: usize| 1_000_000 + 1_000 * i as u64;
	let list = |pairs: &[(String, u64)]| -> String {
		let path = payer.dir.join(format!("claims-{}.txt", pairs.len()));
		let mut f = std::fs::File::create(&path).unwrap();
		writeln!(f, "# key amount").unwrap();
		for (k, v) in pairs {
			writeln!(f, "{} {}", k, v).unwrap();
		}
		path.to_string_lossy().to_string()
	};
	let pairs: Vec<(String, u64)> = keys.iter().enumerate().map(|(i, k)| (k.clone(), value(i))).collect();
	let total: u64 = pairs.iter().map(|(_, v)| v).sum();
	let file = list(&pairs);

	// Refused before anything is signed.
	let twice = list(&[(keys[0].clone(), 1_000_000), (keys[0].clone(), 1_000_000)]);
	payer.refused(&["distribute", &twice, "--asset", &x], "is named twice");
	let small = list(&[(keys[0].clone(), 10)]);
	payer.refused(&["distribute", &small, "--asset", &x], "below the operator's smallest leaf");
	let wpkh = payer.ok(&["address"])["address"].as_str().unwrap().to_string();
	let by_hash = list(&[(wpkh, 1_000_000)]);
	payer.refused(&["distribute", &by_hash, "--asset", &x], "names no key");
	let beyond = list(&[(keys[0].clone(), 900_000_000)]);
	payer.refused(&["distribute", &beyond, "--asset", &x, "--quote"], "and the claims and the fee take");
	payer.refused(&["distribute", &beyond, "--asset", &x], "and the claims and the fee take");
	let quote = payer.ok(&["distribute", &file, "--asset", &x, "--quote"]);
	assert_eq!(quote["total"], json!(total.to_string()));
	assert_eq!(quote["split"], json!(true), "no coin holds exactly the claims: the wallet pays itself one first");
	let fee = atoms(&quote["fee"]);
	payer.refused(&["distribute", &file, "--asset", &x, "--shown", &(fee + 1).to_string()], "fee changed since it was shown");

	// --- One round pays them all ---
	let before = payer.ok(&["balance"])["sequentia_onchain"][&x].as_str().unwrap_or("0").parse::<u64>().unwrap();
	let d = payer.ok(&["distribute", &file, "--asset", &x, "--shown", &fee.to_string()]);
	assert_eq!(d["state"], "pending");
	assert_eq!(d["claims"].as_array().unwrap().len(), 20);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	println!("the round {}: {} vB, {} outputs", built.tx.txid(), built.tx.vsize(), built.tx.output.len());
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	payer.ok(&["sync"]);
	let st = shown(&payer);
	assert_eq!(st["state"], "released", "{}", st);
	assert!(st["claims"].as_array().unwrap().iter().all(|c| c["state"] == "open"), "{}", st);
	let expiry = st["expiry"].as_u64().unwrap() as u32;
	println!("the claims open until {} (expiry {})", st["deadline"], expiry);

	// --- Fourteen holders take their claims up ---
	let mut claimed: Vec<Arca> = vec![];
	for w in existing.iter().take(6) {
		let found = w.ok(&["claims"]);
		assert_eq!(found.as_array().unwrap().len(), 1, "{}", found);
		assert_eq!(found[0]["state"], "open");
		let taken = w.ok(&["claim"]);
		assert!(taken[0]["taken_up"]["transfer_id"].is_string(), "{}", taken);
		claimed.push(Arca { name: w.name.clone(), dir: w.dir.clone(), patience: w.patience.clone() });
	}
	for (i, m) in mnemonics.iter().take(8).enumerate() {
		let w = Arca::new(&format!("mnemonic {}", i));
		let mut args = create.to_vec();
		args.extend(["--mnemonic", m.as_str()]);
		w.ok(&args);
		let found = w.ok(&["claims"]);
		assert_eq!(found.as_array().unwrap().len(), 1, "holder {} finds its claim: {}", i, found);
		let taken = w.ok(&["claim"]);
		assert!(taken[0]["taken_up"]["transfer_id"].is_string(), "{}", taken);
		claimed.push(w);
	}
	for w in &claimed {
		let (coins, held) = live(w, &x);
		assert_eq!(coins.len(), 1, "{}: one live coin, the claim taken up: {:?}", w.name, coins);
		assert!(held > 990_000, "{} holds {}", w.name, held);
		// Taken up already: nothing more to take.
		assert_eq!(w.ok(&["claims"])[0]["state"], "claimed");
		assert_eq!(w.ok(&["claim"])[0]["state"], "claimed");
	}
	let st = shown(&payer);
	let states: Vec<&str> = st["claims"].as_array().unwrap().iter().map(|c| c["state"].as_str().unwrap()).collect();
	assert_eq!(states.iter().filter(|s| **s == "claimed").count(), 14, "{:?}", states);
	assert_eq!(states.iter().filter(|s| **s == "open").count(), 6, "{:?}", states);

	// --- The claimed coins' free window: every claimed holder refreshes ---
	// Half a day before a sync would take the coins home (a day before their
	// exit date), in the window where it asks for their refresh.
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, expiry - 4 * DAY - 12 * HOUR - now));
	r.synced().await;
	for w in &claimed {
		w.ok(&["sync"]);
	}
	payer.ok(&["sync"]);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	for w in &claimed {
		w.ok(&["sync"]);
		let (coins, _) = live(w, &x);
		assert_eq!(coins.len(), 1, "{}: refreshed: {:?}", w.name, coins);
		assert!(coins[0]["expiry"].as_u64().unwrap() as u32 > expiry + 20 * DAY, "{}: its new batch outlives the claim batch", w.name);
	}

	// --- The deadline: the release, the notice, the sweep, the return ---
	let now = common::node::median_time(&r.rt);
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, expiry.saturating_sub(now) + HOUR));
	settle(&r).await;
	tokio::task::block_in_place(|| common::node::advance_mtp(&r.rt, 37 * HOUR));
	settle(&r).await;
	let mut st = Value::Null;
	for _ in 0..10 {
		settle(&r).await;
		st = shown(&payer);
		if st["returns"].as_array().is_some_and(|a| a.first().is_some_and(|x| x["state"] == "final")) {
			break;
		}
	}
	println!("after the sweep: {}", st);
	let unclaimed: u64 = [6usize, 7, 16, 17, 18, 19].iter().map(|i| value(*i)).sum();
	assert_eq!(st["returned"], json!(unclaimed.to_string()), "the six claims nobody took up, exactly");
	assert_eq!(st["returns"][0]["state"], "final");
	let states: Vec<&str> = st["claims"].as_array().unwrap().iter().map(|c| c["state"].as_str().unwrap()).collect();
	assert_eq!(states.iter().filter(|s| **s == "claimed").count(), 14, "{:?}", states);
	assert_eq!(states.iter().filter(|s| **s == "returned").count(), 6, "{:?}", states);
	let ret_txid = st["returns"][0]["txid"].as_str().unwrap();
	let ret_tx = r.rt.client().raw_transaction(&ret_txid.parse().unwrap()).unwrap();
	let ret_script = st["return_script"].as_str().unwrap();
	let paid: u64 = ret_tx.output.iter().filter(|o| hex(o.script_pubkey.as_bytes()) == ret_script && o.asset.explicit() == Some(r.x))
		.map(|o| o.value.explicit().unwrap()).sum();
	assert_eq!(paid, unclaimed, "the return pays the payer's return address the unclaimed sum in X");
	println!("the return {}: {} vB, {} of X to the payer", ret_txid, ret_tx.vsize(), paid);
	let after = payer.ok(&["balance"])["sequentia_onchain"][&x].as_str().unwrap_or("0").parse::<u64>().unwrap();
	assert!(after >= before + unclaimed, "the payer's on-chain X grew by the return: {} then {}", before, after);
	// Every holder that claimed still holds its coin.
	for w in &claimed {
		let (coins, held) = live(w, &x);
		assert_eq!(coins.len(), 1, "{} still holds its coin: {:?}", w.name, coins);
		assert!(held > 990_000);
	}
	// The six that never claimed find their claims returned, and take nothing.
	let late = Arca::new("mnemonic 8, late");
	let mut args = create.to_vec();
	args.extend(["--mnemonic", mnemonics[8].as_str()]);
	late.ok(&args);
	assert_eq!(late.ok(&["claims"])[0]["state"], "returned");
	assert_eq!(late.ok(&["claim"])[0]["state"], "returned");
	assert_eq!(existing[6].ok(&["claims"])[0]["state"], "returned");
}

/// Produces and buries a block, lets the watcher pass and the nursery
/// follow, and waits for the server to be at the tip.
async fn settle(r: &Running) {
	r.server.watcher.pass().await.unwrap();
	tokio::time::sleep(std::time::Duration::from_millis(300)).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.server.nursery.pass().await.unwrap();
	r.server.watcher.pass().await.unwrap();
	tokio::time::sleep(std::time::Duration::from_millis(300)).await;
}

/// Two holders named by their OpenAMP account key (`m/5/0`), as SeqPal names
/// a security's holders: one a wallet that exists and shows its key
/// (`arca openamp-key`), one that exists only as a mnemonic until after the
/// round. Each finds its claim under that key (`named_as: openamp`) and takes
/// it up, signing for the claim leaf with the claim key of its OpenAMP key.
#[tokio::test(flavor = "multi_thread")]
async fn holders_named_by_their_openamp_key_take_their_claims_up() {
	let mut r = Running::start().await;
	let x = r.x.to_string();
	let (url, node) = (r.url(), r.node_url());
	let create = ["create", "--server", &url, "--node-url", &node, "--node-user", "arca"];

	let payer = Arca::new("openamp payer");
	payer.ok(&create);
	r.pay_to(script(&payer.ok(&["address"])), r.x, 5_000_000);
	r.produce().await;
	payer.ok(&["board", &x, "4000000"]);
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.wait("the payer's board to be credited", || payer.ok(&["boards"])[0]["server"]["state"] == "credited").await;
	payer.ok(&["sync"]);

	let shown_key = Arca::new("shows its key");
	shown_key.ok(&create);
	let k0 = shown_key.ok(&["openamp-key"]);
	assert_eq!(k0["path"], "m/5/0");
	let k0 = k0["key"].as_str().unwrap().to_string();
	let mnemonic = bip39::Mnemonic::from_entropy(&[42u8; 16]).unwrap().to_string();
	let k1 = hex(&Keys::new(&mnemonic, 0, 1).unwrap().openamp().unwrap().x_only_public_key().0.serialize());
	assert_ne!(k0, k1);
	let path = payer.dir.join("openamp-claims.txt");
	std::fs::write(&path, format!("{} 1000000\n{} 1200000\n", k0, k1)).unwrap();
	let file = path.to_string_lossy().to_string();
	let fee = atoms(&payer.ok(&["distribute", &file, "--asset", &x, "--quote"])["fee"]);
	payer.ok(&["distribute", &file, "--asset", &x, "--shown", &fee.to_string()]);
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	r.round_state(&built.tx.txid(), RoundState::Final).await;
	payer.ok(&["sync"]);
	assert_eq!(shown(&payer)["state"], "released");

	let late = Arca::new("mnemonic, after the round");
	let mut args = create.to_vec();
	args.extend(["--mnemonic", mnemonic.as_str()]);
	late.ok(&args);
	for (w, key, value) in [(&shown_key, &k0, 1_000_000u64), (&late, &k1, 1_200_000)] {
		let found = w.ok(&["claims"]);
		assert_eq!(found.as_array().unwrap().len(), 1, "{}: {}", w.name, found);
		assert_eq!(found[0]["named_as"], "openamp", "{}", found);
		assert_eq!(found[0]["key"], json!(key));
		assert!(found[0]["address"].is_null());
		let taken = w.ok(&["claim"]);
		assert!(taken[0]["taken_up"]["transfer_id"].is_string(), "{}", taken);
		let (coins, held) = live(w, &x);
		assert_eq!(coins.len(), 1, "{}: {:?}", w.name, coins);
		assert!(held > value - 10_000 && held <= value, "{} holds {}", w.name, held);
		assert_eq!(w.ok(&["claims"])[0]["state"], "claimed");
	}
	let st = shown(&payer);
	assert!(st["claims"].as_array().unwrap().iter().all(|c| c["state"] == "claimed"), "{}", st);
	println!("two holders named by their OpenAMP keys took their claims up: {}", st);
}
