//! Rounds end to end, against a whole server on an anchored proof-of-stake
//! regtest chain, with the minimal client:
//!
//! 1. Several participants in two assets, X (listed for fees) and Y (not),
//!    one giving up coins of both for leaves of both, one leaving half on-chain
//!    by an offboard: one round, every forfeit in, every preimage out, every
//!    new leaf live, and the offboard's output unlocked to its owner's script
//!    with the preimage alone. The server's wallet holds no policy asset.
//! 2. A leaf unrolled from the published tree and exited by its owner alone:
//!    each node by the owner's own unroll authorisation with its reserve as the
//!    fee, the entry with the preimage, the exit after the exit delay with the
//!    owner's signature. No signature of the operator's is made or needed.
//!    Once the leaf is on the chain the server co-signs no off-chain spend of
//!    it.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::sign::sign_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::{
	CoinRecord, ExplicitOutput, Forfeit, OffboardPolicy, RelativeTime, Template, ValidCoin, ValidLeaf, WalletPolicy,
};
use common::client::{auths_json, forfeit_sig, hex, new_leaf, participation_body, random32, rebuild, transfer_body, unhex, Answer, Held};
use common::keys::{keypair, xonly};
use common::node;
use common::rounds::{created, credited_board, mtp, round_final, status, VALUE};
use common::running::{Running, MIN_LEAF};
use server::participations::OutputRequest;
use server::server::AssetSection;

fn refused(a: Answer, status: i32, code: &str) {
	let (c, m) = a.refusal();
	assert_eq!((a.status, c.as_str()), (status, code), "{}", a.json);
	println!("refused {} {}: {}", status, code, m);
}

/// The exit delay of the leaves of these tests: one 512-second unit, inside
/// the bounds this server publishes, so a test can wait it out.
fn short_delay() -> RelativeTime {
	RelativeTime::from_units(1).unwrap()
}

/// A server serving X and Y, taking exit delays from one unit, its wallet
/// funded and final.
async fn start() -> Running {
	let mut r = Running::start_with(|c, y| {
		c.assets.push(AssetSection { asset: y.to_string(), min_leaf: MIN_LEAF.to_string() });
		c.exit_delay_units = Some((1, 338));
	}).await;
	let (x, y) = (r.x, r.y);
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(x, 50_000_000).await;
	r.fund_wallet_in(y, 50_000_000).await;
	r.produce().await;
	r.bury().await;
	r.synced().await;
	r
}

/// A wallet's acceptance policy at the tip, with the exit-delay bounds this
/// server publishes.
fn policy(r: &Running) -> WalletPolicy {
	WalletPolicy { min_exit_delay: short_delay(), ..WalletPolicy::new(r.chain, xonly(&r.s), mtp(r)) }
}

/// A leaf wanted for `key`, with the short exit delay.
fn want(key: &Keypair, asset: AssetId, value: u64) -> (OutputRequest, [u8; 32]) {
	let nonce = random32();
	(OutputRequest::Leaf { asset, value, template: Template::Vtxo1, owner: xonly(key), owner_nonce: nonce, exit_delay: short_delay() }, nonce)
}

/// A participant: the coins it gives up (key, coin, the transaction its
/// board came from) and the leaves it wants (key, nonce, output index).
struct Participant {
	label: String,
	given: Vec<(Keypair, Held, Transaction)>,
	wanted: Vec<(Keypair, [u8; 32], usize)>,
	id: [u8; 32],
}

/// Validates every leaf `p` wants from the published trees, signs the forfeit
/// of every coin it gave up and hands them over. Returns the preimage and
/// each new leaf, validated.
fn complete(r: &Running, p: &Participant) -> ([u8; 32], Vec<(ValidLeaf, arca_covenant::LeafRecord, Transaction)>) {
	let st = status(r, &p.id);
	let mut news = vec![];
	for (key, nonce, j) in &p.wanted {
		let o = &st["outputs"][*j];
		let txid = st["round"]["txid"].as_str().unwrap().to_string();
		let published = r.http.post("tree", &json!({"txid": txid, "vout": o["batch_vout"]})).ok();
		let round = r.rt.client().raw_transaction(&common::client::txid(&txid)).unwrap();
		let record = rebuild(&published).record(o["leaf_index"].as_u64().unwrap() as usize);
		let valid = record.validate(&round, &policy(r), &xonly(key), nonce).unwrap();
		assert_eq!(valid.leaf_id.to_string(), o["leaf_id"].as_str().unwrap());
		news.push((valid, record, round));
	}
	let c = st["round"]["connector_vout"].as_u64().unwrap() as u32;
	let delay = RelativeTime::from_units(st["refund_delay_units"].as_u64().unwrap() as u16).unwrap();
	let mut forfeits = vec![];
	for (k, (key, held, tx)) in p.given.iter().enumerate() {
		let old: ValidCoin = held.record.resolve(std::slice::from_ref(tx), &r.policy()).unwrap();
		let margin: u64 = st["inputs"][k]["margin"].as_str().unwrap().parse().unwrap();
		// The new leaves share the participation's unlock hash: any of them
		// names it.
		let f = Forfeit::for_refresh(old.leaf, (old.asset, old.value), old.id, &news[0].0, &news[0].2, c, delay, margin).unwrap();
		forfeits.push(json!({"leaf_id": held.id.to_string(), "signature": forfeit_sig(&f, key)}));
	}
	let leaves: Vec<Value> = p.wanted.iter().zip(&news).map(|((key, _, _), (v, rec, _))| auths_json(v, key, created(rec))).collect();
	let done = r.http.post("forfeit_leaves", &json!({"participation_id": hex(&p.id), "forfeits": forfeits, "leaves": leaves})).ok();
	assert_eq!(done["state"], "released", "{}: {}", p.label, done);
	(unhex(done["preimage"].as_str().unwrap()).try_into().unwrap(), news)
}

/// Moves the chain's median time at least `seconds` on: the node's clock set
/// ahead, then enough blocks for the median of the last eleven to follow.
async fn advance_mtp(r: &Running, seconds: u32) {
	let start = mtp(r).to_consensus_u32();
	let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
	let mock = now.max(start as u64) + seconds as u64 + 60;
	let _: Value = r.rt.client().call("setmocktime", &[json!(mock)]).unwrap();
	for _ in 0..12 {
		r.produce().await;
	}
	assert!(mtp(r).to_consensus_u32() >= start + seconds, "the median time moved from {} to {}", start, mtp(r).to_consensus_u32());
}

fn send(r: &Running, what: &str, tx: &Transaction) -> Txid {
	let txid = r.rt.client().send_raw_transaction(tx).unwrap_or_else(|e| panic!("{}: {}", what, e));
	println!("{}: {} ({} vB)", what, txid, tx.vsize());
	txid
}

#[tokio::test(flavor = "multi_thread")]
async fn several_participants_in_two_assets() {
	let mut r = start().await;
	let (x, y, s, chain) = (r.x, r.y, xonly(&r.s), r.chain);
	let policy_asset = r.purse.policy;
	assert!(!r.server.wallet.balance().await.unwrap().contains_key(&policy_asset));

	// Four refresh in X, two in Y, one gives up X and Y for X and Y, one
	// leaves half on-chain.
	let mut ps: Vec<Participant> = vec![];
	for (i, asset) in [x, x, x, x, y, y].iter().enumerate() {
		let k = keypair(&format!("P{}", i));
		let (held, tx) = credited_board(&mut r, &k, *asset).await;
		let n = keypair(&format!("P{}, new", i));
		let (w, nonce) = want(&n, *asset, VALUE);
		let (body, id) = participation_body(&[&held], &[w], &[], None, s, chain);
		r.http.post("submit_participation", &body).ok();
		ps.push(Participant { label: format!("P{}", i), given: vec![(k, held, tx)], wanted: vec![(n, nonce, 0)], id });
	}
	let (m, mx, my) = (keypair("M"), keypair("M, X"), keypair("M, Y"));
	let (hx, tx_x) = credited_board(&mut r, &m, x).await;
	let m2 = keypair("M, Y board");
	let (hy, tx_y) = credited_board(&mut r, &m2, y).await;
	let (wx, nx) = want(&mx, x, VALUE);
	let (wy, ny) = want(&my, y, VALUE);
	let (body, id) = participation_body(&[&hx, &hy], &[wx, wy], &[], None, s, chain);
	r.http.post("submit_participation", &body).ok();
	ps.push(Participant { label: "M".into(), given: vec![(m, hx, tx_x), (m2, hy, tx_y)], wanted: vec![(mx, nx, 0), (my, ny, 1)], id });
	let (o, o2) = (keypair("O"), keypair("O, new"));
	let (ho, tx_o) = credited_board(&mut r, &o, x).await;
	let (wo, no) = want(&o2, x, 500_000);
	let dest = node::op_true();
	let off = OutputRequest::Offboard { asset: x, value: 400_000, script: dest.clone() };
	let (body, id) = participation_body(&[&ho], &[wo, off], &[(x, 100_000)], None, s, chain);
	let st_o = r.http.post("submit_participation", &body).ok();
	ps.push(Participant { label: "O".into(), given: vec![(o, ho, tx_o)], wanted: vec![(o2, no, 0)], id });

	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	println!("round {}: {} vB, batches {:?}, {} offboard(s), {} participations", built.tx.txid(), built.tx.vsize(), built.batches,
		built.offboards, built.participations);
	assert_eq!(built.participations, 8);
	let leaves: usize = built.batches.iter().map(|b| b.2).sum();
	assert_eq!(leaves, 9);
	assert!(built.tx.output.iter().all(|o| o.asset.explicit() != Some(policy_asset)));
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;

	// Every participant completes; every new leaf is live.
	let mut preimages = vec![];
	for p in &ps {
		let (pre, news) = complete(&r, p);
		for ((key, _, _), (v, _, _)) in p.wanted.iter().zip(&news) {
			let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", key, &r.chain)})).ok();
			assert_eq!(ld["leaves"][0]["state"], "live", "{}'s leaf {}", p.label, v.leaf_id);
		}
		println!("{} released: {} coin(s) given up, {} new leaf/leaves live", p.label, p.given.len(), news.len());
		preimages.push(pre);
	}

	// O unlocks its offboard with the preimage alone, to its own script.
	let st = status(&r, &ps[7].id);
	let vout = st["outputs"][1]["offboard_vout"].as_u64().unwrap() as u32;
	let reclaim = RelativeTime::from_units(st_o["outputs"][1]["reclaim_delay_units"].as_u64().unwrap() as u16).unwrap();
	let policy = OffboardPolicy {
		unlock_hash: unhex(st["unlock_hash"].as_str().unwrap()).try_into().unwrap(),
		destination: ExplicitOutput::new(x, 400_000, dest.clone()),
		operator: s,
		reclaim_delay: reclaim,
	};
	assert_eq!(policy.find(&built.tx).unwrap(), vout);
	let held = built.tx.output[vout as usize].value.explicit().unwrap();
	let unlock = policy.unlock_tx(OutPoint::new(built.tx.txid(), vout), held, &preimages[7], &FeeSource::Reserve).unwrap();
	let u = send(&r, "O's offboard unlocked with the preimage", &unlock.tx);
	r.produce().await;
	let got = r.rt.client().raw_transaction(&u).unwrap();
	assert_eq!((got.output[0].script_pubkey.clone(), got.output[0].value.explicit()), (dest, Some(400_000)));
	println!("O holds 400000 atoms of X on-chain, at its own script");
}

#[tokio::test(flavor = "multi_thread")]
async fn unroll_and_exit_from_the_published_tree() {
	let mut r = start().await;
	let (x, s, chain) = (r.x, xonly(&r.s), r.chain);
	// Five leaves in X: two lowest nodes under the batch output.
	let mut ps: Vec<Participant> = vec![];
	for i in 0..5 {
		let k = keypair(&format!("U{}", i));
		let (held, tx) = credited_board(&mut r, &k, x).await;
		let n = keypair(&format!("U{}, new", i));
		let (w, nonce) = want(&n, x, VALUE);
		let (body, id) = participation_body(&[&held], &[w], &[], None, s, chain);
		r.http.post("submit_participation", &body).ok();
		ps.push(Participant { label: format!("U{}", i), given: vec![(k, held, tx)], wanted: vec![(n, nonce, 0)], id });
	}
	let built = r.server.rounds.run_round().await.unwrap().unwrap();
	r.produce().await;
	r.bury().await;
	round_final(&r, &built.tx.txid()).await;
	let mut done = vec![];
	for p in &ps {
		done.push(complete(&r, p));
	}

	// U3 leaves alone, from what the operator published and its own key.
	let (preimage, news) = &done[3];
	let (valid, record, round) = &news[0];
	let owner = &ps[3].wanted[0].0;
	assert_eq!(valid.branch.nodes.len(), 2, "the batch output, then U3's lowest node");
	let t = created(record);
	let auths: Vec<_> = valid.branch.nodes.iter().map(|n| n.owner_auth(sign_digest(owner, &n.unroll_authorisation(t).digest, &random32()), t, xonly(owner))).collect();
	let fees = vec![FeeSource::Reserve; auths.len()];
	let txs = valid.branch.unroll(OutPoint::new(round.txid(), valid.batch_vout), &auths, &fees).unwrap();
	for (level, u) in txs.iter().enumerate() {
		send(&r, &format!("U3's unroll, level {}, its own authorisation, the reserve as the fee", level), &u.tx);
		r.produce().await;
	}
	let entry = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), preimage, &FeeSource::Reserve).unwrap();
	let at = send(&r, "U3's entry into its leaf, with the preimage", &entry.tx);
	r.produce().await;

	// On the chain now: the server co-signs no off-chain spend of it.
	r.synced().await;
	let ld = r.http.post("leaf_data", &json!({"auth": r.http.auth("leaf_data", owner, &r.chain)})).ok();
	let held = Held { key: *owner, nonce: ps[3].wanted[0].1, id: valid.leaf_id,
		record: CoinRecord::from_bytes(&unhex(ld["leaves"][0]["record"].as_str().unwrap())).unwrap() };
	let coin = held.record.resolve(std::slice::from_ref(round), &WalletPolicy { min_exit_delay: short_delay(), ..r.policy() }).unwrap();
	let (to, _) = new_leaf(&keypair("V"));
	refused(r.http.post("cosign_transfer", &transfer_body(&[(&held, coin, VALUE - 2_000)], &[(x, VALUE - 4_000, to)], s, chain)), 422, "on_chain");

	// The exit, by the owner's signature alone, once the delay has passed.
	let leaf = &valid.branch.leaf;
	let exit = |key: &Keypair| {
		let ks = leaf.exit_tx(OutPoint::new(at, 0), x, VALUE, &[ExplicitOutput::new(x, VALUE - 1_500, node::op_true())], &FeeSource::Reserve).unwrap();
		let sig = sign_digest(key, &ks.sighash(chain.genesis_hash()).unwrap(), &random32());
		ks.finish(vec![sig.as_ref().to_vec()]).tx
	};
	let early_tx = exit(owner);
	let early = r.rt.client().send_raw_transaction(&early_tx);
	let e = early.unwrap_err().to_string();
	println!("U3's exit before the delay: refused by the mempool, {}", e);
	assert!(e.contains("non-BIP68-final"), "{}", e);
	// A proof-of-stake chain takes no block that skips the committee, so the
	// same spend cannot be forced into a block here; the covenant's own
	// regtest suite does that on a chain that can.
	let forced = r.rt.client().generate_block("raw(51)", &[&early_tx]);
	println!("U3's exit before the delay, forced into a block: {:?}", forced.as_ref().map(|_| "mined").map_err(|e| e.to_string()));
	assert!(forced.is_err());
	// The operator's key in the owner's place.
	advance_mtp(&r, short_delay().units() as u32 * 512).await;
	let by_operator = r.rt.client().send_raw_transaction(&exit(&r.s));
	let e = by_operator.unwrap_err().to_string();
	println!("the exit signed by the operator's key: refused, {}", e);
	assert!(e.contains("Invalid Schnorr signature") || e.contains("script-verify"), "{}", e);
	let out = send(&r, "U3's exit, its own signature after the delay", &exit(owner));
	r.produce().await;
	let got = r.rt.client().raw_transaction(&out).unwrap();
	assert_eq!(got.output[0].value.explicit(), Some(VALUE - 1_500));
	println!("U3 left with {} atoms of X: {} node transactions, the entry and the exit, none signed by the operator", VALUE - 1_500, txs.len());
}
