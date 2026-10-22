//! The restricted profile on a whole server: a restricted asset R (asset Y,
//! which the node does not take for fees) served in its issuer's tree, its
//! policy server a stub that publishes the asset's tree terms and co-signs a
//! transfer the way openampd does: it computes each message the operator is
//! to sign from the coin records and new leaves, by arca-covenant's own code,
//! and signs it with the policy key, unless a new leaf's holder is one it
//! refuses. On an anchored proof-of-stake regtest chain, `arca-signer` in its
//! own process with `--restricted`, PostgreSQL, the watcher on:
//!
//! - the operator refuses to serve R when the policy server names another
//!   operator of its tree, and serves it under the profile, published in
//!   `info`, when it names `S`;
//! - a board of R that is not `enclave-1`, one for another policy key, and
//!   one whose owner key is not its holder's are refused; an `enclave-1`
//!   board is credited;
//! - a transfer of the board's coin to another holder is co-signed beside
//!   the policy server, every atom committed; a transfer leaving a margin, one
//!   paying a `vtxo-1` leaf of R, one with another clawback key and one to a
//!   holder the policy server refuses are not (the last with the policy
//!   server's own words, `policy`);
//! - a refresh of R's coin and a round paying R are refused (`restricted`);
//! - the signer, asked directly, signs no message of R without the policy
//!   key's approval of that very message, and none beside an approval of
//!   another;
//! - the sender converts its board after paying it away: the watcher answers
//!   with the checkpoint and the reassignment, its own coins of X paying every
//!   fee as no margin of R is left; the sender's exit is refused; the
//!   receiver's exit pays its enclave the whole value.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use elements::hashes::{sha256, Hash};
use elements::secp256k1_zkp::{Keypair, XOnlyPublicKey};
use elements::{AssetId, OutPoint, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::checkpoint::CheckpointPolicy;
use arca_covenant::enclave::policy_cosign_digest;
use arca_covenant::sign::sign_digest;
use arca_covenant::spend::{FeeSource, Rebindable};
use arca_covenant::sweep::Sweep;
use arca_covenant::transfer::{board_sweep, checkpoint_salt};
use arca_covenant::{enclave_key, enclave_keypair, BoardRecord, CoinRecord, Enclave, ExplicitOutput, LeafPolicy, NewLeaf, Template};
use common::client::{hex, random32, transfer_body, unhex, Held};
use common::flow::{final_of, has, log, settle, txid, Coin};
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::advance_mtp;
use common::running::{Running, MIN_LEAF};
use server::server::{AssetSection, RestrictedSection};

const VALUE: u64 = 2_000_000;
const HOUR: u32 = 3_600;
const TOKEN: &str = "stub issuer token";

/// The stub's state.
struct Stub {
	asset: AssetId,
	operator: XOnlyPublicKey,
	policy: Keypair,
	clawback: Option<XOnlyPublicKey>,
	genesis: elements::BlockHash,
	refused: Mutex<Vec<XOnlyPublicKey>>,
	cosigned: AtomicUsize,
	dropped: AtomicUsize,
}

/// A restricted coin's leaf, its checkpoint's sweep, asset and value, as the
/// policy server's tool reads them from its record.
fn coin_leaf(c: &CoinRecord) -> (LeafPolicy, Sweep, AssetId, u64) {
	match c {
		CoinRecord::Board(b) => (b.leaf(), board_sweep(b.operator, b.exit_delay), b.asset, b.value),
		CoinRecord::Transfer(t) => {
			let (l0, sweep, _, _) = coin_leaf(&t.inputs[0].coin);
			let o = &t.outputs[t.index as usize];
			(t.leaf.policy(l0.operator, l0.chain), sweep, o.asset, o.value)
		},
		_ => panic!("a restricted coin rests on a board"),
	}
}

fn xonly_of(v: &Value) -> XOnlyPublicKey {
	XOnlyPublicKey::from_slice(&unhex(v.as_str().unwrap())).unwrap()
}

async fn terms(State(s): State<Arc<Stub>>, Path(id): Path<String>) -> (StatusCode, Json<Value>) {
	if id != s.asset.to_string() {
		return (StatusCode::NOT_FOUND, Json(json!({"error": "unknown asset"})));
	}
	(StatusCode::OK, Json(json!({"id": id, "tree": {
		"operator": hex(&s.operator.serialize()), "policy": hex(&xonly(&s.policy).serialize()),
		"clawback": s.clawback.map(|k| hex(&k.serialize())),
	}})))
}

async fn cosign(State(s): State<Arc<Stub>>, headers: HeaderMap, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
	if headers.get("authorization").and_then(|h| h.to_str().ok()) != Some(&format!("Bearer {}", TOKEN)) {
		return (StatusCode::UNAUTHORIZED, Json(json!({"error": "issuer token required"})));
	}
	let chain = arca_covenant::Chain::new(s.genesis);
	let t = &body["transfer"];
	let mut outs = vec![];
	for o in t["outputs"].as_array().unwrap() {
		let holder = xonly_of(&o["holder"]);
		if s.refused.lock().unwrap().contains(&holder) {
			return (StatusCode::FORBIDDEN, Json(json!({"error": format!("recipient {} lacks a permitted category", hex(&holder.serialize()))})));
		}
		let asset: AssetId = o["asset"].as_str().unwrap().parse().unwrap();
		let value: u64 = o["value"].as_str().unwrap().parse().unwrap();
		let n: [u8; 32] = unhex(o["owner_nonce"].as_str().unwrap()).try_into().unwrap();
		let leaf = NewLeaf {
			owner: enclave_key(&holder, &n).unwrap(), owner_nonce: n,
			creator_nonce: unhex(o["creator_nonce"].as_str().unwrap()).try_into().unwrap(),
			exit_delay: arca_covenant::RelativeTime::from_units(o["exit_delay_units"].as_u64().unwrap() as u16).unwrap(),
			htlc: None, landing: None,
			enclave: Some(Enclave { holder, policy: xonly(&s.policy), clawback: s.clawback }.terms(asset, value)),
		};
		outs.push(ExplicitOutput::new(asset, value, leaf.policy(s.operator, chain).script_pubkey()));
	}
	let mut sigs = vec![];
	for i in t["inputs"].as_array().unwrap() {
		let coin = CoinRecord::from_bytes(&unhex(i["coin"].as_str().unwrap())).unwrap();
		let v: u64 = i["checkpoint_value"].as_str().unwrap().parse().unwrap();
		let (leaf, sweep, asset, value) = coin_leaf(&coin);
		let cp = CheckpointPolicy { owner: leaf.owner, operator: s.operator, salt: checkpoint_salt(&leaf.salt), chain, sweep };
		let cm = leaf.message(asset, value, &[ExplicitOutput::new(asset, v, cp.script_pubkey())]).unwrap().digest;
		let rm = cp.message(asset, v, &outs).unwrap().digest;
		for d in [cm, rm] {
			let sig = sign_digest(&s.policy, &policy_cosign_digest(&d), &random32());
			sigs.push(json!({"digest": hex(&d), "signature": hex(sig.as_ref())}));
		}
	}
	s.cosigned.fetch_add(1, Ordering::SeqCst);
	let id = hex(&sha256::Hash::hash(body.to_string().as_bytes()).to_byte_array());
	(StatusCode::OK, Json(json!({"id": id, "policy": hex(&xonly(&s.policy).serialize()), "signatures": sigs})))
}

async fn drop_transfer(State(s): State<Arc<Stub>>, Path(_id): Path<String>) -> Json<Value> {
	s.dropped.fetch_add(1, Ordering::SeqCst);
	Json(json!({}))
}

/// Starts the stub on a free port: its URL.
async fn stub(s: Arc<Stub>) -> String {
	let app = Router::new()
		.route("/v1/assets/{id}", get(terms))
		.route("/v1/issuer/tree/transfer", post(cosign))
		.route("/v1/issuer/tree/transfer/{id}/drop", post(drop_transfer))
		.with_state(s);
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let url = format!("http://{}", listener.local_addr().unwrap());
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	url
}

/// Produces blocks, the watcher acting on its own, until its log satisfies
/// `done`.
async fn wait_watcher<F: FnMut(&[server::store::WatcherTxRow]) -> bool>(r: &Running, what: &str, blocks: usize, mut done: F) {
	for n in 0..blocks {
		for _ in 0..20 {
			if done(&log(r).await) {
				println!("{}: done by the watcher's own task after {} block(s)", what, n);
				for w in log(r).await {
					println!("  watcher: {} {}: {}", w.kind, txid(&w), w.detail);
				}
				return;
			}
			tokio::time::sleep(std::time::Duration::from_millis(250)).await;
		}
		r.produce().await;
	}
	panic!("{}: not done after {} blocks", what, blocks);
}

fn send(r: &Running, what: &str, tx: &Transaction) -> Txid {
	let txid = r.rt.client().send_raw_transaction(tx).unwrap_or_else(|e| panic!("{}: {}", what, e));
	println!("{}: {} ({} vB)", what, txid, tx.vsize());
	txid
}

/// A board of R for holder `h`, `enclave-1` when `enclave` names it, paid
/// from the purse and registered; its record, transaction and the server's
/// answer.
fn board(r: &mut Running, h: &Keypair, enclave: Option<Enclave>, owner: Option<XOnlyPublicKey>) -> (BoardRecord, Transaction, common::client::Answer) {
	let rr = r.y;
	let nonce = random32();
	let default_owner = match enclave {
		Some(_) => enclave_key(&xonly(h), &nonce).unwrap(),
		None => xonly(h),
	};
	let record = BoardRecord {
		template: Template::Board1, owner: owner.unwrap_or(default_owner), owner_nonce: nonce,
		operator_nonce: r.http.operator_nonce(), exit_delay: common::client::exit_delay(), asset: rr, value: VALUE, chain: r.chain,
		operator: xonly(&r.s), landing: None, enclave,
	};
	let coins = vec![r.purse.take_coin(rr), r.purse.take_coin(r.x)];
	let tx = record.tx(&coins, r.x, 2_000, &node::op_true()).unwrap().tx;
	for (j, o) in tx.output.iter().enumerate().skip(1) {
		if !o.is_fee() {
			r.purse.put((OutPoint::new(tx.txid(), j as u32), o.clone()));
		}
	}
	r.rt.client().send_raw_transaction(&tx).unwrap();
	let answer = r.http.register_board(&record, &tx);
	(record, tx, answer)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restricted_asset_moves_in_its_issuers_tree_under_its_policy() {
	let mut r = Running::start_with(|c, _| c.watcher.enabled = true).await;
	let (x, rr, s) = (r.x, r.y, xonly(&r.s));
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
	let (policy, issuer) = (keypair("R policy key"), keypair("R issuer key"));
	let state = Arc::new(Stub {
		asset: rr, operator: s, policy, clawback: Some(xonly(&issuer)), genesis, refused: Mutex::new(vec![]),
		cosigned: AtomicUsize::new(0), dropped: AtomicUsize::new(0),
	});
	let url = stub(state.clone()).await;
	let token_file = r.signer.dir.join("policy.token");
	std::fs::write(&token_file, TOKEN).unwrap();

	// ---- served only in a tree its issuer names this operator of ----------
	let elsewhere = Arc::new(Stub {
		asset: rr, operator: xonly(&keypair("another operator")), policy, clawback: None, genesis, refused: Mutex::new(vec![]),
		cosigned: AtomicUsize::new(0), dropped: AtomicUsize::new(0),
	});
	let elsewhere_url = stub(elsewhere).await;
	let section = |u: &str| {
		let mut a = AssetSection::new(rr, MIN_LEAF);
		a.restricted = Some(RestrictedSection { policy_server: u.into(), token_file: token_file.to_str().unwrap().into() });
		a
	};
	let mut config = r.config.clone();
	config.assets.push(section(&elsewhere_url));
	let e = r.server.reload(&config).await.unwrap_err();
	println!("REFUSED reload, the policy server naming another operator: {}", e);
	assert!(e.to_string().contains("as the operator of the asset's tree"), "{}", e);
	let mut config = r.config.clone();
	config.assets.push(section(&url));
	r.server.reload(&config).await.unwrap();
	tokio::task::block_in_place(|| r.signer.restart_with(genesis, &["--restricted".into(),
		format!("{}={}:{}", rr, hex(&xonly(&policy).serialize()), hex(&xonly(&issuer).serialize()))]));
	let info = r.http.get("info").ok();
	let served = info["assets"].as_array().unwrap().iter().find(|a| a["asset"] == rr.to_string()).unwrap().clone();
	println!("info, asset R: {}", served);
	assert_eq!(served["restricted"]["policy"], hex(&xonly(&policy).serialize()));
	assert_eq!(served["restricted"]["clawback"], hex(&xonly(&issuer).serialize()));

	// ---- boards: enclave-1 for the asset's keys and the holder's key --------
	let (h1, h2, h3) = (keypair("R holder 1"), keypair("R holder 2"), keypair("R holder 3"));
	let enclave = |h: &Keypair| Enclave { holder: xonly(h), policy: xonly(&policy), clawback: Some(xonly(&issuer)) };
	let (_, _, a) = board(&mut r, &keypair("R plain board"), None, None);
	let plain = a.refusal();
	println!("REFUSED a vtxo-1 board of R: {:?}", plain);
	assert!(plain.1.contains("is restricted: every leaf of it is enclave-1"), "{:?}", plain);
	let (_, _, a) = board(&mut r, &h1, Some(Enclave { policy: xonly(&keypair("other policy")), ..enclave(&h1) }), None);
	println!("REFUSED a board of R for another policy key: {:?}", a.refusal());
	assert!(a.refusal().1.contains("carries the asset's policy key"), "{:?}", a.refusal());
	// A board whose owner key is the holder's registered key itself, not its
	// enclave key for the nonce: no such record is written at all.
	let n = random32();
	let own = BoardRecord {
		template: Template::Board1, owner: xonly(&h1), owner_nonce: n, operator_nonce: r.http.operator_nonce(),
		exit_delay: common::client::exit_delay(), asset: rr, value: VALUE, chain: r.chain, operator: s, landing: None,
		enclave: Some(enclave(&h1)),
	};
	let e = own.to_bytes().unwrap_err();
	println!("REFUSED a board record of R whose owner key is the holder's own: {}", e);
	assert_eq!(e.kind(), "enclave");
	let (record, board_tx, a) = board(&mut r, &h1, Some(enclave(&h1)), None);
	a.ok();
	r.produce().await;
	r.bury().await;
	let id = record.leaf_id();
	let http = r.http.clone();
	r.wait("the board to be credited", || http.board_status(&id).json["state"] == "credited").await;
	let a1 = enclave_keypair(&h1, &record.owner_nonce).unwrap();
	let c1 = Coin { held: Held { key: a1, nonce: record.owner_nonce, id, record: CoinRecord::Board(record) }, bases: vec![board_tx] };
	println!("H1's enclave-1 board of {} R credited: {}", VALUE, id);

	// ---- transfers --------------------------------------------------------
	let new = |h: &Keypair, clawback: Option<XOnlyPublicKey>, value: u64| {
		let n = random32();
		let leaf = NewLeaf {
			owner: enclave_key(&xonly(h), &n).unwrap(), owner_nonce: n, creator_nonce: random32(),
			exit_delay: common::client::exit_delay(), htlc: None, landing: None,
			enclave: Some(Enclave { clawback, ..enclave(h) }.terms(rr, value)),
		};
		(rr, value, leaf)
	};
	let v1 = c1.valid(&r);
	let refused = |r: &Running, what: &str, body: Value| {
		let (code, why) = r.http.post("cosign_transfer", &body).refusal();
		println!("REFUSED {}: {} {}", what, code, why);
		(code, why)
	};
	let (code, why) = refused(&r, "a transfer of R leaving a margin of 2000",
		transfer_body(&[(&c1.held, v1.clone(), VALUE - 2_000)], &[new(&h2, Some(xonly(&issuer)), VALUE - 4_000)], s, r.chain));
	assert!(why.contains("keeps the whole coin"), "{} {}", code, why);
	let (_, _, mut plain_leaf) = new(&h2, None, VALUE);
	plain_leaf.enclave = None;
	let (_, why) = refused(&r, "a transfer of R into a vtxo-1 leaf",
		transfer_body(&[(&c1.held, v1.clone(), VALUE)], &[(rr, VALUE, plain_leaf)], s, r.chain));
	assert!(why.contains("every leaf of it is enclave-1"), "{}", why);
	let (_, why) = refused(&r, "a transfer of R into a leaf without the asset's clawback",
		transfer_body(&[(&c1.held, v1.clone(), VALUE)], &[new(&h2, None, VALUE)], s, r.chain));
	assert!(why.contains("clawback"), "{}", why);
	state.refused.lock().unwrap().push(xonly(&h3));
	let (code, why) = refused(&r, "a transfer of R to a holder the policy server refuses",
		transfer_body(&[(&c1.held, v1.clone(), VALUE)], &[new(&h3, Some(xonly(&issuer)), VALUE)], s, r.chain));
	assert_eq!(code, "policy");
	assert!(why.contains("lacks a permitted category"), "{}", why);
	assert_eq!(state.cosigned.load(Ordering::SeqCst), 0);
	let (_, _, leaf2) = new(&h2, Some(xonly(&issuer)), 700_000);
	let (_, _, change) = new(&h1, Some(xonly(&issuer)), VALUE - 700_000);
	let body = transfer_body(&[(&c1.held, v1.clone(), VALUE)], &[(rr, 700_000, leaf2), (rr, VALUE - 700_000, change)], s, r.chain);
	let done = r.http.post("cosign_transfer", &body).ok();
	println!("H1 paid H2 700000 R out of round, co-signed beside the policy server ({} co-signature(s) asked)",
		state.cosigned.load(Ordering::SeqCst));
	let transfer: Vec<u8> = unhex(done["transfer_id"].as_str().unwrap());
	let a2 = enclave_keypair(&h2, &leaf2.owner_nonce).unwrap();
	let mail = r.http.mailbox(&a2, &r.chain, 0);
	let (_, b_id, b_record) = mail[0].clone();
	let b_valid = b_record.validate(&c1.bases, &r.policy(), &xonly(&a2), &leaf2.owner_nonce).unwrap();
	assert_eq!(b_valid.leaf.template(), Template::Enclave1);
	println!("H2's coin {}: enclave-1, its exit paying H2's enclave", b_id);

	// ---- paths not served ---------------------------------------------------
	let b_coin = Coin { held: Held { key: a2, nonce: leaf2.owner_nonce, id: b_id, record: b_record.clone() }, bases: c1.bases.clone() };
	let (refresh, _) = common::client::participation_body(&[&b_coin.held], &[common::client::want_leaf(&keypair("R refresh"), rr, 700_000 - 10_000).0],
		&[(x, 10_000)], None, s, r.chain);
	let (code, why) = r.http.post("submit_participation", &refresh).refusal();
	println!("REFUSED a refresh of R's coin: {} {}", code, why);
	assert_eq!(code, "restricted");

	// ---- the signer, asked directly --------------------------------------
	let client = server::signer::SignerClient::new(&r.signer.socket);
	let out = [ExplicitOutput::new(rr, 700_000, node::op_true())];
	let m = b_valid.leaf.message(rr, 700_000, &out).unwrap();
	let owner_sig = sign_digest(&a2, &m.digest, &random32());
	let e = client.rebind_recorded(&xonly(&a2), &owner_sig, &b_valid.leaf.salt, None, rr, 700_000, &out).await.unwrap_err();
	println!("REFUSED by the signer, a message of R without the policy key's approval: {}", e);
	assert!(e.to_string().contains("no valid approval by its policy key"), "{}", e);
	let other = sign_digest(&policy, &policy_cosign_digest(&[7; 32]), &random32());
	let e = client.rebind_cosigned(&xonly(&a2), &owner_sig, &b_valid.leaf.salt, Some(xonly(&h2)), &other, rr, 700_000, &out).await.unwrap_err();
	println!("REFUSED by the signer, beside an approval of another message: {}", e);
	assert!(e.to_string().contains("no valid approval by its policy key"), "{}", e);

	// ---- the sender converts its board: the watcher answers ---------------
	let (bp, at) = v1.board().unwrap();
	let fee_coin = r.purse.take_coin(x);
	let conv = bp.conversion(at, &FeeSource::Coin { outpoint: fee_coin.0, coin: fee_coin.1.clone(), fee: 3_000, change: node::op_true() }).unwrap();
	let sig = sign_digest(&a1, &conv.sighash(genesis).unwrap(), &random32());
	let conv = conv.finish(vec![sig.as_ref().to_vec()]);
	let leaf_at = OutPoint::new(send(&r, "H1 converts the board it paid away", &conv.tx), 0);
	wait_watcher(&r, "the answer to H1's conversion", 6, |l| has(l, "reassignment", &transfer)).await;
	settle(&r).await;
	let l = log(&r).await;
	assert!(final_of(&l, "checkpoint", &c1.held.id.0) && final_of(&l, "reassignment", &transfer), "both are final");
	let re = l.iter().find(|w| w.kind == "reassignment").unwrap();
	let retx: Transaction = elements::encode::deserialize(&re.tx).unwrap();
	assert_eq!(retx.output[0].value.explicit(), Some(700_000));
	assert!(retx.output.iter().all(|o| o.asset.explicit() != Some(rr) || !o.is_fee()), "no fee in R");
	println!("the watcher published H1's checkpoint and the reassignment, paying every fee in X");
	advance_mtp(&r, 37 * HOUR).await;
	let fc = r.purse.take_coin(x);
	let ks = bp.leaf.enclave_exit_tx(leaf_at, &FeeSource::Coin { outpoint: fc.0, coin: fc.1.clone(), fee: 3_000, change: node::op_true() }).unwrap();
	let sig = sign_digest(&a1, &ks.sighash(genesis).unwrap(), &random32());
	let mut a_exit = ks.finish(vec![sig.as_ref().to_vec()]).tx;
	a_exit.input[1].witness.script_witness = vec![];
	let e = common::flow::verdict(&r, &a_exit).unwrap_err();
	println!("REFUSED H1's exit of its converted board after the delay: {}", e);
	assert!(e.contains("missingorspent") || e.contains("missing-inputs"), "{}", e);
	let fc = r.purse.take_coin(x);
	let ks = b_valid.leaf.enclave_exit_tx(OutPoint::new(txid(re), 0),
		&FeeSource::Coin { outpoint: fc.0, coin: fc.1.clone(), fee: 3_000, change: node::op_true() }).unwrap();
	let sig = sign_digest(&a2, &ks.sighash(genesis).unwrap(), &random32());
	let mut b_exit = ks.finish(vec![sig.as_ref().to_vec()]).tx;
	b_exit.input[1].witness.script_witness = vec![];
	send(&r, "H2's exit into its enclave", &b_exit);
	r.produce().await;
	assert!(r.rt.client().confirmations(&b_exit.txid()).unwrap() >= 1);
	assert_eq!(b_exit.output[0].script_pubkey, enclave(&h2).script_pubkey());
	assert_eq!(b_exit.output[0].value.explicit(), Some(700_000));
	println!("H2's coin is in H2's enclave: 700000 R at {}", hex(enclave(&h2).script_pubkey().as_bytes()));
}
