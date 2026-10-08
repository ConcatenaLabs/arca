//! Several assets, each served on its own, against a whole server on an
//! anchored proof-of-stake regtest chain: a round carries one asset, so
//! participations in X (listed for fees) and in Y (not listed) run in
//! rounds of their own, each funded from its asset's pool of the operator's
//! wallet, the round in Y paying its fee from the pool of X; a participation
//! that carries two assets is refused; an asset the operator does not serve
//! is refused at every entry, its id named; and an asset added to `arcad`'s
//! configuration is served once it reloads it on SIGHUP, without a restart.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use elements::hashes::Hash;
use elements::{AssetId, Transaction};
use serde_json::json;

use arca_covenant::NewLeaf;
use common::client::{board_record, hex, new_leaf, participation_body, resolve, transfer_body, want_leaf, Http};
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{credited_board, round_final, start, status, validate_new_leaf, VALUE};
use common::running::{Running, MIN_LEAF};
use server::participations::OutputRequest;

/// The transaction paying `record`'s board from the purse (the fee in X),
/// and the purse coins it spends, to be put back if it is never broadcast.
fn board_paid(r: &mut Running, record: &arca_covenant::BoardRecord) -> (Transaction, Vec<(elements::OutPoint, elements::TxOut)>) {
	let coins = vec![r.purse.take_coin(record.asset), r.purse.take_coin(r.x)];
	(record.tx(&coins, r.x, 2_000, &node::op_true()).unwrap().tx, coins)
}

/// Broadcasts a board's transaction, its change back in the purse.
fn broadcast_board(r: &mut Running, tx: &Transaction) {
	for (j, o) in tx.output.iter().enumerate().skip(1) {
		if !o.is_fee() {
			r.purse.put((elements::OutPoint::new(tx.txid(), j as u32), o.clone()));
		}
	}
	r.rt.client().send_raw_transaction(tx).unwrap();
}

/// The assets of `tx`'s outputs that are neither a batch's sweep token nor
/// the connector's issue: what the round pays and takes change in.
fn assets_paid(tx: &Transaction, built: &server::rounds::Built) -> BTreeSet<AssetId> {
	let tokens: Vec<u32> = built.batches.iter().map(|(_, vout, _)| vout + 1).collect();
	tx.output.iter().enumerate()
		.filter(|(i, o)| !tokens.contains(&(*i as u32)) && *i as u32 != built.connector_vout && !o.is_fee())
		.filter_map(|(_, o)| o.asset.explicit()).collect()
}

/// The asset of each wallet coin `tx` spends.
async fn assets_spent(r: &Running, tx: &Transaction) -> Vec<AssetId> {
	let mut out = vec![];
	for i in &tx.input {
		let c = r.server.store.wallet_coin_at(&i.previous_output.txid.to_byte_array(), i.previous_output.vout).await.unwrap()
			.expect("a round spends the operator's coins only");
		out.push(AssetId::from_byte_array(c.asset));
	}
	out
}

#[tokio::test(flavor = "multi_thread")]
async fn each_asset_runs_in_rounds_of_its_own() {
	let mut r = start().await;
	let (x, y, s, chain) = (r.x, r.y, xonly(&r.s), r.chain);
	println!("asset X {} (listed for fees), asset Y {} (not listed); the wallet: {:?}", x, y, r.server.wallet.balance().await.unwrap());

	// A refreshes into X, B into Y, C into X with an offboard.
	let (a, b, c) = (keypair("A"), keypair("B"), keypair("C"));
	let (a_coin, _) = credited_board(&mut r, &a, x).await;
	let (b_coin, _) = credited_board(&mut r, &b, y).await;
	let (c_coin, _) = credited_board(&mut r, &c, x).await;
	let (a2, b2, c2) = (keypair("A, new"), keypair("B, new"), keypair("C, new"));
	let (wa, a2_nonce) = want_leaf(&a2, x, VALUE);
	let (wb, b2_nonce) = want_leaf(&b2, y, VALUE);
	let (wc, _) = want_leaf(&c2, x, 600_000);
	let off = OutputRequest::Offboard { asset: x, value: 300_000, script: node::op_true() };
	let (pa, ida) = participation_body(&[&a_coin], &[wa], &[], None, s, chain);
	let (pb, idb) = participation_body(&[&b_coin], &[wb], &[], None, s, chain);
	let (pc, idc) = participation_body(&[&c_coin], &[wc, off], &[(x, 100_000)], None, s, chain);
	for p in [&pa, &pb, &pc] {
		assert_eq!(r.http.post("submit_participation", p).ok()["state"], "pending");
	}

	// The first round: X's, from X's pool alone.
	let first = r.server.rounds.run_round().await.unwrap().expect("a round");
	let tx1 = first.tx.clone();
	let spent1 = assets_spent(&r, &tx1).await;
	println!("round 1 {}: {} vB, batches {:?}, offboards {}, participations {}, inputs in {:?}, outputs in {:?}", tx1.txid(),
		tx1.vsize(), first.batches, first.offboards, first.participations, spent1, assets_paid(&tx1, &first));
	assert_eq!(first.batches.len(), 1, "a round carries one asset: {:?}", first.batches);
	assert_eq!(first.batches[0].0, x);
	assert_eq!((first.offboards, first.participations), (1, 2));
	assert_eq!(assets_paid(&tx1, &first), BTreeSet::from([x]), "X's round pays X alone");
	assert!(spent1.iter().all(|a| *a == x), "X's round spends X's pool alone: {:?}", spent1);
	let fees: Vec<_> = tx1.output.iter().filter(|o| o.is_fee()).collect();
	assert_eq!(fees[0].asset.explicit(), Some(x), "its fee in its own asset, which the node accepts");
	assert_eq!(status(&r, &idb)["state"], "pending", "B's participation, in Y, is not in X's round");

	// The second: Y's. Y is not accepted for fees, so its fee and connector
	// come from the pool of X, the first fee asset the node accepts.
	let second = r.server.rounds.run_round().await.unwrap().expect("a round of Y");
	let tx2 = second.tx.clone();
	let spent2 = assets_spent(&r, &tx2).await;
	println!("round 2 {}: {} vB, batches {:?}, participations {}, inputs in {:?}, outputs in {:?}", tx2.txid(), tx2.vsize(),
		second.batches, second.participations, spent2, assets_paid(&tx2, &second));
	assert_eq!(second.batches, vec![(y, 0, 1)]);
	assert_eq!(assets_paid(&tx2, &second), BTreeSet::from([x, y]), "Y's batch and change, X's change");
	assert!(spent2.contains(&y) && spent2.iter().all(|a| *a == x || *a == y), "{:?}", spent2);
	let fees: Vec<_> = tx2.output.iter().filter(|o| o.is_fee()).collect();
	assert_eq!(fees[0].asset.explicit(), Some(x));
	assert!(r.server.rounds.run_round().await.unwrap().is_none(), "nothing waits");

	// Both final; each owner validates its new leaf from its round's tree.
	r.produce().await;
	r.bury().await;
	round_final(&r, &tx1.txid()).await;
	round_final(&r, &tx2.txid()).await;
	let (va, la, ra) = validate_new_leaf(&r, &ida, 0, &a2, &a2_nonce);
	let (vb, lb, rb) = validate_new_leaf(&r, &idb, 0, &b2, &b2_nonce);
	assert_eq!((ra.txid(), la.asset), (tx1.txid(), x));
	assert_eq!((rb.txid(), lb.asset), (tx2.txid(), y));
	assert_eq!(status(&r, &idc)["round"]["txid"], tx1.txid().to_string());
	println!("A's new leaf {} rests on round {}, B's {} on round {}", va.leaf_id, ra.txid(), vb.leaf_id, rb.txid());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_participation_carries_one_asset() {
	let mut r = start().await;
	let (x, y, s, chain) = (r.x, r.y, xonly(&r.s), r.chain);
	let (a, b) = (keypair("one asset: A"), keypair("one asset: B"));
	let (a_coin, _) = credited_board(&mut r, &a, x).await;
	let (b_coin, _) = credited_board(&mut r, &b, y).await;

	// An X coin and a Y coin, for an X leaf and a Y leaf.
	let (wx, _) = want_leaf(&keypair("one asset: X leaf"), x, VALUE);
	let (wy, _) = want_leaf(&keypair("one asset: Y leaf"), y, VALUE);
	let (both, _) = participation_body(&[&a_coin, &b_coin], &[wx, wy], &[], None, s, chain);
	let answer = r.http.post("submit_participation", &both);
	println!("two assets: {} {}", answer.status, answer.json);
	assert_eq!(answer.status, 422, "{}", answer.json);
	let (code, message) = answer.refusal();
	assert_eq!(code, "out_of_bounds");
	assert!(message.contains("carries one asset") && message.contains(&x.to_string()) && message.contains(&y.to_string()), "{}", message);

	// A Y coin for an X leaf.
	let (wx, _) = want_leaf(&keypair("one asset: X leaf for Y"), x, VALUE);
	let (cross, _) = participation_body(&[&b_coin], &[wx], &[], None, s, chain);
	let answer = r.http.post("submit_participation", &cross);
	println!("a Y coin for an X leaf: {} {}", answer.status, answer.json);
	let (code, message) = answer.refusal();
	assert_eq!(code, "out_of_bounds");
	assert!(message.contains("carries one asset"), "{}", message);

	// Each alone is taken.
	let (wx, _) = want_leaf(&keypair("one asset: X alone"), x, VALUE);
	let (wy, _) = want_leaf(&keypair("one asset: Y alone"), y, VALUE);
	let (px, _) = participation_body(&[&a_coin], &[wx], &[], None, s, chain);
	let (py, _) = participation_body(&[&b_coin], &[wy], &[], None, s, chain);
	assert_eq!(r.http.post("submit_participation", &px).ok()["state"], "pending");
	assert_eq!(r.http.post("submit_participation", &py).ok()["state"], "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_asset_not_served_is_refused_at_every_entry() {
	let mut r = start().await;
	let (x, s, chain) = (r.x, xonly(&r.s), r.chain);
	let z = tokio::task::block_in_place(|| r.purse.issue(&r.rt, "asset Z", 100_000_000_000));
	println!("asset Z {} is issued on the chain and not served", z);
	let refused = |what: &str, a: common::client::Answer| {
		println!("{}: {} {}", what, a.status, a.json);
		assert!((400..500).contains(&a.status), "{}: {}", what, a.json);
		let (code, message) = a.refusal();
		assert_eq!(code, "out_of_bounds", "{}: {}", what, message);
		assert!(message.contains(&z.to_string()), "{} names the asset: {}", what, message);
	};

	// A board of Z: refused before anything is registered.
	let owner = keypair("not served: board");
	let nonce = r.http.operator_nonce();
	let record = board_record(&owner, nonce, z, VALUE, chain, s);
	let (tx, coins) = board_paid(&mut r, &record);
	refused("a board of Z", r.http.register_board(&record, &tx));
	for c in coins {
		r.purse.put(c);
	}

	// A transfer paying Z, out of an X coin.
	let a = keypair("not served: A");
	let (coin, board_tx) = credited_board(&mut r, &a, x).await;
	let valid = resolve(&coin, &[board_tx], &r.policy());
	let (leaf, _): (NewLeaf, _) = new_leaf(&keypair("not served: receiver"));
	let body = transfer_body(&[(&coin, valid, VALUE)], &[(z, 500_000, leaf)], s, chain);
	refused("a transfer paying Z", r.http.post("cosign_transfer", &body));

	// A participation wanting a leaf of Z, offboarding Z, or paying its fee
	// in Z.
	let (wz, _) = want_leaf(&keypair("not served: Z leaf"), z, VALUE);
	let (p, _) = participation_body(&[&coin], &[wz], &[], None, s, chain);
	refused("a participation wanting a leaf of Z", r.http.post("submit_participation", &p));
	let off = OutputRequest::Offboard { asset: z, value: VALUE, script: node::op_true() };
	let (p, _) = participation_body(&[&coin], &[off], &[], None, s, chain);
	refused("a participation offboarding Z", r.http.post("submit_participation", &p));
	let (wx, _) = want_leaf(&keypair("not served: X leaf, fee in Z"), x, VALUE);
	let (p, _) = participation_body(&[&coin], &[wx], &[(z, 1)], None, s, chain);
	refused("a participation paying its fee in Z", r.http.post("submit_participation", &p));

	// `info` lists the assets served, and Z is not among them.
	let info = r.http.get("info").ok();
	let listed: Vec<&str> = info["assets"].as_array().unwrap().iter().map(|a| a["asset"].as_str().unwrap()).collect();
	assert!(!listed.contains(&z.to_string().as_str()), "{:?}", listed);
}

/// A configuration file for `arcad` on `r`'s database, signer and node,
/// serving `assets`, building a round every second.
fn config_file(r: &Running, assets: &[AssetId]) -> std::path::PathBuf {
	let c = &r.config;
	let mut text = format!(
		"listen = \"127.0.0.1:0\"\ndatabase = {:?}\nsigner_socket = {:?}\nwallet_mnemonic_file = {:?}\nround_interval_seconds = 1\n\
		 [node]\nrpc_url = {:?}\nrpc_user = \"arca\"\nrpc_password = \"arca\"\n\
		 [finality]\npoll_interval_ms = 200\n[watcher]\nenabled = false\n\
		 [limits]\nissue_per_second = 10000\nissue_burst = 10000\nsource_per_second = 10000\nsource_burst = 10000\n",
		c.database, c.signer_socket.display().to_string(), c.wallet_mnemonic_file.display().to_string(), c.node.rpc_url,
	);
	for a in assets {
		text.push_str(&format!("[[assets]]\nasset = \"{}\"\nmin_leaf = \"{}\"\n", a, MIN_LEAF));
	}
	let path = r.signer.dir.join("arcad-assets.toml");
	std::fs::write(&path, text).unwrap();
	path
}

/// `arcad` run by a test, stopped when the test ends, however it ends.
struct Arcad(std::process::Child);

impl Drop for Arcad {
	fn drop(&mut self) {
		if self.0.try_wait().ok().flatten().is_none() {
			let _ = self.0.kill();
			let _ = self.0.wait();
		}
	}
}

/// The assets `info` lists.
fn served(http: &Http) -> Vec<String> {
	http.get("info").ok()["assets"].as_array().unwrap().iter().map(|a| a["asset"].as_str().unwrap().to_string()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_asset_added_to_the_configuration_is_served_on_sighup() {
	// The in-process server serving X makes the database and funds the
	// wallet; then `arcad` runs on them as an operator runs it.
	let mut r = Running::start().await;
	let (x, y, s, chain) = (r.x, r.y, xonly(&r.s), r.chain);
	r.fund_wallet_in(x, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r.server.stop();
	let config = config_file(&r, &[x]);
	let log = r.signer.dir.join("arcad-assets.log");
	let mut arcad = Arcad(Command::new(env!("CARGO_BIN_EXE_arcad")).arg(&config).stdout(Stdio::piped())
		.stderr(std::fs::File::create(&log).unwrap()).spawn().unwrap());
	let pid = arcad.0.id();
	let mut line = String::new();
	tokio::task::block_in_place(|| BufReader::new(arcad.0.stdout.take().unwrap()).read_line(&mut line)).unwrap();
	let addr = line.trim().strip_prefix("arcad listening on ").unwrap_or_else(|| panic!("arcad said {:?}; its log: {}", line,
		std::fs::read_to_string(&log).unwrap_or_default())).to_string();
	println!("arcad (pid {}) on {}, serving X", pid, addr);
	r.http = Http { base: format!("http://{}", addr) };
	assert_eq!(served(&r.http), vec![x.to_string()]);

	// Y is refused, naming it.
	let owner = keypair("added: board of Y");
	let nonce = r.http.operator_nonce();
	let record = board_record(&owner, nonce, y, VALUE, chain, s);
	let (tx, coins) = board_paid(&mut r, &record);
	let answer = r.http.register_board(&record, &tx);
	println!("a board of Y before the reload: {} {}", answer.status, answer.json);
	assert_eq!(answer.refusal().0, "out_of_bounds");
	assert!(answer.refusal().1.contains(&y.to_string()));
	for c in coins {
		r.purse.put(c);
	}

	// Y added to the configuration, its pool funded, and SIGHUP: no restart.
	config_file(&r, &[x, y]);
	r.fund_wallet_in(y, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	tokio::task::block_in_place(|| Command::new("kill").arg("-HUP").arg(pid.to_string()).status()).unwrap();
	tokio::time::sleep(Duration::from_secs(1)).await;
	let start = Instant::now();
	loop {
		assert!(arcad.0.try_wait().unwrap().is_none(), "arcad exited on SIGHUP; its log: {}", std::fs::read_to_string(&log).unwrap_or_default());
		if served(&r.http).contains(&y.to_string()) {
			break;
		}
		assert!(start.elapsed() < Duration::from_secs(20), "Y is not served after SIGHUP; the log: {}",
			std::fs::read_to_string(&log).unwrap_or_default());
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
	assert_eq!(served(&r.http), vec![x.to_string(), y.to_string()], "in the configuration's order");
	println!("after SIGHUP, arcad (pid {}, the same process) serves {:?}", pid, served(&r.http));

	// The same board of Y is taken now, credited once final, and refreshed
	// in a round of Y the timer builds from Y's pool.
	let (tx, _) = board_paid(&mut r, &record);
	broadcast_board(&mut r, &tx);
	let answer = r.http.register_board(&record, &tx);
	println!("the board of Y after the reload: {} {}", answer.status, answer.json);
	assert_eq!(answer.status, 200, "{}", answer.json);
	r.produce().await;
	r.bury().await;
	let id = record.leaf_id();
	let http = r.http.clone();
	r.wait("the board of Y to be credited", || http.board_status(&id).json["state"] == "credited").await;
	let held = common::client::Held { key: owner, nonce: record.owner_nonce, id, record: arca_covenant::CoinRecord::Board(record) };
	let (wy, _) = want_leaf(&keypair("added: Y leaf"), y, VALUE);
	let (p, pid_y) = participation_body(&[&held], &[wy], &[], None, s, chain);
	assert_eq!(r.http.post("submit_participation", &p).ok()["state"], "pending");
	let http = r.http.clone();
	r.wait("the participation in Y to be issued", || {
		http.post("participation_status", &json!({"participation_id": hex(&pid_y)})).json["state"] == "issued"
	}).await;
	let st = r.http.post("participation_status", &json!({"participation_id": hex(&pid_y)})).ok();
	let round = st["round"]["txid"].as_str().unwrap().to_string();
	let tree = r.http.post("tree", &json!({"txid": round, "vout": 0})).ok();
	assert_eq!(tree["asset"], y.to_string(), "{}", tree);
	println!("Y's participation runs in round {}, its batch in Y", round);

	// A reload that leaves out a served asset is refused whole.
	config_file(&r, &[y]);
	tokio::task::block_in_place(|| Command::new("kill").arg("-HUP").arg(pid.to_string()).status()).unwrap();
	tokio::time::sleep(Duration::from_secs(1)).await;
	assert!(arcad.0.try_wait().unwrap().is_none());
	assert_eq!(served(&r.http), vec![x.to_string(), y.to_string()], "nothing was taken");
	let text = std::fs::read_to_string(&log).unwrap();
	let refusal = text.lines().find(|l| l.contains("leaves out asset")).unwrap_or_else(|| panic!("the log: {}", text));
	println!("the log: {}", refusal);

	tokio::task::block_in_place(|| Command::new("kill").arg("-INT").arg(pid.to_string()).status()).unwrap();
	let _ = tokio::task::block_in_place(|| arcad.0.wait());
}
