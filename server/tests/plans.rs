//! Offline refresh against a whole server on an anchored proof-of-stake
//! regtest chain ([`server::plans`]).
//!
//! 1. A holder's plan of two steps from a coin of a round, quoted, signed
//!    and handed over before any step's round exists. Nothing runs before the
//!    coin's free window; then each step runs in the asset's ordinary round,
//!    is released without forfeits once final, and the plan is done. The
//!    holder, back, validates its last leaf from the published record alone
//!    and hands over its unroll authorisations. A transfer of a coin the plan
//!    names is refused, and so is a participation of the last leaf while the
//!    coin step 2 gave up is unswept. The holder then brings home that coin
//!    (a leaf step 1 made) with its own keys and preimage; the watcher answers
//!    with step 2's refund, the step's leaf brought on the chain by the
//!    operator's own authorisations: output 0 pays the holder the leaf's
//!    whole value.
//! 2. The batch guard: the current coin of a plan whose step can never run
//!    (stopped) is not released at its batch's expiry; once the holder
//!    cancels the plan, it is.
//! 3. Every refusal of a quote and of a plan, printed verbatim.
//! 4. A step whose round is lost: void, the plan stopped, the coin it gave up
//!    its holder's again, unreleased past its expiry, and taken home.
//!
//! Needs `SEQUENTIAD_EXEC` and `ARCA_TEST_POSTGRES`.

mod common;

use elements::secp256k1_zkp::Keypair;
use elements::{OutPoint, Script, Txid};
use serde_json::{json, Value};

use arca_covenant::plan::{key_proof_digest, Plan, PlanStep};
use arca_covenant::sign::sign_digest;
use arca_covenant::spend::FeeSource;
use arca_covenant::{CoinRecord, LeafId, LeafRecord, MedianTime, ValidLeaf};

use common::client::{exit_delay, hex, new_leaf, participation_body, random32, transfer_body, unhex, want_leaf};
use common::flow::{drive, has, refresh, settle, Coin};
use common::keys::{keypair, xonly};
use common::rounds::{accept_policy, advance_mtp, credited_board, mtp, round_final};
use common::running::Running;

const HOUR: u32 = 3_600;
const DAY: u32 = 86_400;

/// A script standing for an address of the holder's.
fn address(label: &str) -> Script {
	Script::from([vec![0x00, 0x14], arca_covenant::script::sha256(label.as_bytes())[..20].to_vec()].concat())
}

/// A plan as a wallet makes it: the plan, the keys and preimages of its
/// leaves, its mailbox key, the body it submits and its id.
struct Made {
	plan: Plan,
	keys: Vec<Keypair>,
	nonces: Vec<[u8; 32]>,
	preimages: Vec<[u8; 32]>,
	mailbox: Keypair,
	body: Value,
	id: [u8; 32],
}

/// The quote for a plan of `steps` steps from `coin`.
fn quote(r: &Running, coin: &Coin, nonces: &[[u8; 32]]) -> common::client::Answer {
	let qd = server::plans::quote_digest(&r.server.params.chain, &r.server.params.operator, &coin.held.id, nonces, exit_delay());
	r.http.post("plan_quote", &json!({"coin": coin.held.id.to_string(), "owner_nonces": nonces.iter().map(|n| hex(n)).collect::<Vec<_>>(),
		"exit_delay_units": exit_delay().units(), "attestation": hex(sign_digest(&coin.held.key, &qd, &random32()).as_ref())}))
}

/// A plan of `steps` steps from `coin`, quoted, built and signed as a wallet
/// would, every leaf holding the coin's value.
fn make_plan(r: &Running, coin: &Coin, label: &str, steps: usize) -> Made {
	let v = coin.valid(r);
	let keys: Vec<Keypair> = (1..=steps).map(|i| keypair(&format!("{} key {}", label, i))).collect();
	let nonces: Vec<[u8; 32]> = (0..steps).map(|_| random32()).collect();
	let preimages: Vec<[u8; 32]> = (0..steps).map(|_| random32()).collect();
	let q = quote(r, coin, &nonces).ok();
	let opscript = Script::from(unhex(q["operator_script"].as_str().unwrap()));
	let first = match &coin.held.record {
		CoinRecord::Leaf { record, .. } => record.leaf(),
		_ => panic!("a leaf of a round"),
	};
	let plan = Plan {
		chain: r.chain, operator: xonly(&r.s), coin: coin.held.id, first, asset: v.asset, value: v.value,
		steps: (0..steps).map(|j| PlanStep {
			value: v.value, fee: 0, owner: xonly(&keys[j]), owner_nonce: nonces[j],
			operator_nonce: unhex(q["steps"][j]["operator_nonce"].as_str().unwrap()).try_into().unwrap(),
			exit_delay: exit_delay(), unlock_hash: arca_covenant::script::sha256(&preimages[j]),
			holder_script: address(&format!("{} holder address {}", label, j + 1)), operator_script: opscript.clone(),
			margin: q["steps"][j]["margin"].as_str().unwrap().parse().unwrap(),
		}).collect(),
	};
	plan.check().unwrap();
	let id = plan.id();
	let mailbox = keypair(&format!("{} mailbox", label));
	let kd = key_proof_digest(&id);
	let body = json!({
		"quote": q["quote"], "coin": coin.held.id.to_string(), "mailbox": hex(&xonly(&mailbox).serialize()),
		"attestation": hex(sign_digest(&coin.held.key, &id, &random32()).as_ref()),
		"steps": (0..steps).map(|j| {
			let s = &plan.steps[j];
			let rf = plan.refund(j + 1).unwrap();
			let old_key = if j == 0 { &coin.held.key } else { &keys[j - 1] };
			let md = server::auth::mailbox_binding_digest(&r.chain, &xonly(&r.s), &s.owner, &xonly(&mailbox));
			json!({
				"value": s.value.to_string(), "fee": s.fee.to_string(), "owner": hex(&s.owner.serialize()), "owner_nonce": hex(&s.owner_nonce),
				"operator_nonce": hex(&s.operator_nonce), "exit_delay_units": s.exit_delay.units(), "unlock_hash": hex(&s.unlock_hash),
				"preimage": hex(&preimages[j]), "holder_script": hex(s.holder_script.as_bytes()),
				"operator_script": hex(s.operator_script.as_bytes()), "margin": s.margin.to_string(),
				"key_proof": hex(sign_digest(&keys[j], &kd, &random32()).as_ref()),
				"old_half": hex(sign_digest(old_key, &rf.old_message().unwrap().digest, &random32()).as_ref()),
				"new_half": hex(sign_digest(&keys[j], &rf.new_message().unwrap().digest, &random32()).as_ref()),
				"mailbox_proof": hex(sign_digest(&keys[j], &md, &random32()).as_ref()),
			})
		}).collect::<Vec<_>>(),
	});
	Made { plan, keys, nonces, preimages, mailbox, body, id }
}

fn plan_status(r: &Running, id: &[u8; 32]) -> Value {
	r.http.post("plan_status", &json!({"plan_id": hex(id)})).ok()
}

fn refused(a: common::client::Answer, code: &str, what: &str) -> String {
	let (c, m) = a.refusal();
	println!("refused, {}: {} {}: {}", what, a.status, c, m);
	assert_eq!(c, code, "{}: {}", what, a.json);
	m
}

/// Runs a round with whatever waits, follows it to final, and passes over
/// the rounds once more, which completes a plan's step in it.
async fn round(r: &mut Running) -> Txid {
	let built = r.server.rounds.run_round().await.unwrap().expect("a round");
	r.produce().await;
	r.bury().await;
	round_final(r, &built.tx.txid()).await;
	r.server.rounds.pass().await.unwrap();
	built.tx.txid()
}

/// A coin of a round, its own: a board refreshed once.
async fn round_coin(r: &mut Running, label: &str) -> Coin {
	let owner = keypair(&format!("{} owner", label));
	let x = r.x;
	let (board, tx) = credited_board(r, &owner, x).await;
	let coin = Coin { held: board, bases: vec![tx] };
	let k = keypair(&format!("{} coin 0", label));
	refresh(r, &[(&coin, &k)]).await.remove(0).new
}

/// The first expiry of `coin`.
fn expiry_of(coin: &Coin) -> u32 {
	match &coin.held.record {
		CoinRecord::Leaf { record, .. } => record.schedule.expiries()[0].to_consensus_u32(),
		_ => unreachable!(),
	}
}

/// Step `idx`'s leaf as the holder checks it from the plan's status alone:
/// its record, validated against its round under the plan's key and nonce.
fn step_leaf(r: &Running, st: &Value, m: &Made, idx: usize) -> (ValidLeaf, LeafRecord, elements::Transaction) {
	let s = &st["steps"][idx - 1];
	assert_eq!(s["state"], "done", "step {}: {}", idx, st);
	let record = LeafRecord::from_bytes(&unhex(s["record"].as_str().unwrap())).unwrap();
	let round = r.rt.client().raw_transaction(&common::client::txid(s["round_txid"].as_str().unwrap())).unwrap();
	let valid = record.validate(&round, &accept_policy(r), &xonly(&m.keys[idx - 1]), &m.nonces[idx - 1]).unwrap();
	assert_eq!(record.unlock_hash, arca_covenant::script::sha256(&m.preimages[idx - 1]));
	assert_eq!(valid.leaf_id.to_string(), s["leaf_id"].as_str().unwrap());
	(valid, record, round)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plan_refreshes_a_coin_twice_without_its_holder_and_answers_a_coin_it_gave_up() {
	let mut r = common::rounds::start().await;
	let x = r.x;
	let c0 = round_coin(&mut r, "P").await;
	let e0 = expiry_of(&c0);
	let m = make_plan(&r, &c0, "P", 2);
	let st = r.http.post("submit_plan", &m.body).ok();
	println!("plan {} taken: {}", hex(&m.id), st);
	assert_eq!(st["state"], "open");
	assert!(st["steps"].as_array().unwrap().iter().all(|s| s["state"] == "waiting"));
	// The same plan again: its status.
	assert_eq!(r.http.post("submit_plan", &m.body).ok()["plan_id"], json!(hex(&m.id)));

	// The coin the plan starts from is paid out of round by nobody, and taken
	// into no refresh while the plan stands.
	let v0 = c0.valid(&r);
	let (to, _) = new_leaf(&keypair("P someone"));
	refused(r.http.post("cosign_transfer", &transfer_body(&[(&c0.held, v0.clone(), v0.value - 2_000)], &[(x, v0.value - 4_000, to)],
		xonly(&r.s), r.chain)), "planned", "a transfer of the coin a plan starts from");
	let (w, _) = want_leaf(&keypair("P a refresh of its own"), x, v0.value);
	let (body, _) = participation_body(&[&c0.held], &[w], &[], None, xonly(&r.s), r.chain);
	refused(r.http.post("submit_participation", &body), "planned", "a refresh of the coin a plan starts from");

	// Nothing runs before the coin's free window.
	assert!(r.server.rounds.run_round().await.unwrap().is_none(), "no step before the free window");
	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, e0 - 5 * DAY + HOUR - now).await;
	r.synced().await;
	let round1 = round(&mut r).await;
	let st = plan_status(&r, &m.id);
	println!("after step 1's round {}: {}", round1, st);
	assert_eq!(st["steps"][0]["state"], "done");
	assert_eq!(st["steps"][0]["round_txid"], json!(round1.to_string()));
	assert_eq!(st["steps"][0]["gives_up"], json!(c0.held.id.to_string()));
	let (v1, rec1, round1_tx) = step_leaf(&r, &st, &m, 1);
	let e1 = rec1.schedule.expiries()[0].to_consensus_u32();

	// Step 2 in L(1)'s free window.
	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, e1 - 5 * DAY + HOUR - now).await;
	r.synced().await;
	let round2 = round(&mut r).await;
	let st = plan_status(&r, &m.id);
	println!("after step 2's round {}: {}", round2, st);
	assert_eq!(st["state"], "done");
	assert_eq!(st["steps"][1]["gives_up"], json!(v1.leaf_id.to_string()));
	let (v2, _, _) = step_leaf(&r, &st, &m, 2);

	// The holder, back, hands over its authorisations for L(2): the server
	// holds its full record.
	let t = MedianTime::from_consensus(mtp(&r).to_consensus_u32() - HOUR).unwrap();
	let auths = common::client::auths_json(&v2, &m.keys[1], t);
	r.http.post("plan_leaf", &auths).ok();
	let row = r.server.store.leaf(&v2.leaf_id.0).await.unwrap().unwrap();
	assert!(!row.record.is_empty() && row.state == server::store::LeafState::Live, "L(2) live with its full record");
	let pre2 = m.preimages[1];
	let held2 = common::client::Held { key: m.keys[1], nonce: m.nonces[1], id: v2.leaf_id,
		record: CoinRecord::from_bytes(&row.record).unwrap() };
	assert!(matches!(&held2.record, CoinRecord::Leaf { preimage, .. } if *preimage == pre2));
	let c2 = held2.record.resolve(&[r.rt.client().raw_transaction(&round2).unwrap()], &r.policy()).unwrap();
	let (to, _) = new_leaf(&keypair("P someone else"));
	refused(r.http.post("cosign_transfer", &transfer_body(&[(&held2, c2.clone(), c2.value - 2_000)], &[(x, c2.value - 4_000, to)],
		xonly(&r.s), r.chain)), "planned", "a transfer of a leaf a step made");
	let (w, _) = want_leaf(&keypair("P L(2) refreshed"), x, c2.value);
	let (body, _) = participation_body(&[&held2], &[w], &[], None, xonly(&r.s), r.chain);
	refused(r.http.post("submit_participation", &body), "planned", "a refresh of L(2) while the coin step 2 gave up is unswept");

	// The holder brings home L(1), which it gave up in step 2: its own
	// authorisations and preimage. The watcher answers with step 2's refund.
	let branch = &v1.branch;
	let auths1: Vec<arca_covenant::UnrollAuth> = branch.nodes.iter().map(|n|
		n.owner_auth(sign_digest(&m.keys[0], &n.unroll_authorisation(t).digest, &random32()), t, xonly(&m.keys[0]))).collect();
	let txs = branch.unroll(OutPoint::new(round1_tx.txid(), v1.batch_vout), &auths1, &vec![FeeSource::Reserve; auths1.len()]).unwrap();
	for u in &txs {
		r.rt.client().send_raw_transaction(&u.tx).unwrap();
	}
	let e = branch.entry_tx(branch.entry_outpoint(&txs).unwrap(), &m.preimages[0], &FeeSource::Reserve).unwrap();
	let l1_txid = r.rt.client().send_raw_transaction(&e.tx).unwrap();
	r.produce().await;
	r.synced().await;
	println!("the holder brought L(1) home: {}:0", l1_txid);
	drive(&r, "the refund of step 2", 12, |l| has(l, "refund", &v1.leaf_id.0)).await;
	settle(&r).await;
	let log = common::flow::of_kind(&r, "refund").await;
	let refund = r.rt.client().raw_transaction(&common::flow::txid(&log[0])).unwrap();
	println!("the refund {} ({} vB): inputs {:?}", refund.txid(), refund.vsize(),
		refund.input.iter().map(|i| i.previous_output.to_string()).collect::<Vec<_>>());
	assert_eq!(refund.input[0].previous_output, OutPoint::new(l1_txid, 0), "the refund spends L(1)");
	assert_eq!(refund.output[0].script_pubkey, m.plan.steps[1].holder_script, "output 0 is the holder's address");
	assert_eq!(refund.output[0].value.explicit(), Some(m.plan.steps[1].value), "and pays it L(2)'s whole value");
	for w in common::flow::log(&r).await {
		println!("watcher: {} {} {}", w.kind, common::flow::txid(&w), w.detail);
	}
	assert!(!r.unspent(&OutPoint::new(l1_txid, 0)), "L(1) can no longer exit");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_current_coin_of_a_stopped_plan_is_not_released_until_its_holder_cancels_the_plan() {
	let mut r = common::rounds::start().await;
	let c0 = round_coin(&mut r, "G").await;
	let e0 = expiry_of(&c0);
	let m = make_plan(&r, &c0, "G", 1);
	assert_eq!(r.http.post("submit_plan", &m.body).ok()["state"], "open");
	// The step can never run (as when its round is lost): the plan stops.
	assert!(r.server.store.void_step(&m.id, 1, "its round is lost, for this test").await.unwrap());
	let st = plan_status(&r, &m.id);
	assert_eq!(st["state"], "stopped", "{}", st);
	let token = match &c0.held.record {
		CoinRecord::Leaf { record, .. } => record.schedule.token.into_inner().to_byte_array().to_vec(),
		_ => unreachable!(),
	};
	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, e0 + HOUR - now).await;
	r.synced().await;
	for _ in 0..3 {
		r.server.watcher.pass().await.unwrap();
		settle(&r).await;
	}
	assert!(!has(&common::flow::log(&r).await, "release", &token), "the batch holding a stopped plan's coin is not released");
	println!("past the expiry {}: the batch is not released while the plan is stopped", e0);
	// A cancel signed by another key: refused; by the plan's mailbox key: done.
	let cd = server::plans::cancel_digest(&r.server.params.chain, &r.server.params.operator, &m.id);
	refused(r.http.post("cancel_plan", &json!({"plan_id": hex(&m.id), "signature": hex(sign_digest(&m.keys[0], &cd, &random32()).as_ref())})),
		"bad_attestation", "a cancel signed by another key than the plan's mailbox key");
	let st = r.http.post("cancel_plan", &json!({"plan_id": hex(&m.id), "signature": hex(sign_digest(&m.mailbox, &cd, &random32()).as_ref())})).ok();
	assert_eq!(st["state"], "cancelled", "{}", st);
	drive(&r, "the release once the plan is cancelled", 4, |l| has(l, "release", &token)).await;
	println!("the plan cancelled: the batch is released");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plan_is_refused_for_what_it_breaks() {
	let mut r = common::rounds::start().await;
	let c0 = round_coin(&mut r, "R").await;
	let try_ = |r: &Running, m: &Made, edit: &dyn Fn(&mut Value), code: &str, what: &str| {
		let mut b = m.body.clone();
		edit(&mut b);
		refused(r.http.post("submit_plan", &b), code, what)
	};
	let m = make_plan(&r, &c0, "R", 2);
	let other = keypair("R someone else");
	try_(&r, &m, &|b| b["attestation"] = json!(hex(sign_digest(&other, &m.id, &random32()).as_ref())), "bad_attestation",
		"an attestation by another key than the coin's");
	try_(&r, &m, &|b| b["steps"][1]["key_proof"] = json!(hex(sign_digest(&other, &[1; 32], &random32()).as_ref())), "bad_attestation",
		"a key proof by another key");
	try_(&r, &m, &|b| b["steps"][0]["old_half"] = b["steps"][0]["new_half"].clone(), "bad_attestation",
		"a refund half over the other leaf's message");
	try_(&r, &m, &|b| b["steps"][0]["preimage"] = json!(hex(&[3; 32])), "bad_attestation", "a preimage that does not open the unlock hash");
	try_(&r, &m, &|b| b["steps"][0]["mailbox_proof"] = json!(hex(sign_digest(&other, &[1; 32], &random32()).as_ref())), "bad_attestation",
		"a mailbox proof by another key");
	// Edits that change the plan's id: rebuilt and re-signed by the holder.
	let resign = |edit: &dyn Fn(&mut Plan)| -> Value {
		let mut p = m.plan.clone();
		edit(&mut p);
		let id = p.id();
		let kd = key_proof_digest(&id);
		let mut b = m.body.clone();
		b["attestation"] = json!(hex(sign_digest(&c0.held.key, &id, &random32()).as_ref()));
		for (j, s) in p.steps.iter().enumerate() {
			let rf = p.refund(j + 1).unwrap();
			let old_key = if j == 0 { &c0.held.key } else { &m.keys[j - 1] };
			b["steps"][j]["value"] = json!(s.value.to_string());
			b["steps"][j]["fee"] = json!(s.fee.to_string());
			b["steps"][j]["holder_script"] = json!(hex(s.holder_script.as_bytes()));
			b["steps"][j]["operator_script"] = json!(hex(s.operator_script.as_bytes()));
			b["steps"][j]["operator_nonce"] = json!(hex(&s.operator_nonce));
			b["steps"][j]["margin"] = json!(s.margin.to_string());
			b["steps"][j]["exit_delay_units"] = json!(s.exit_delay.units());
			b["steps"][j]["key_proof"] = json!(hex(sign_digest(&m.keys[j], &kd, &random32()).as_ref()));
			b["steps"][j]["old_half"] = json!(hex(sign_digest(old_key, &rf.old_message().unwrap().digest, &random32()).as_ref()));
			b["steps"][j]["new_half"] = json!(hex(sign_digest(&m.keys[j], &rf.new_message().unwrap().digest, &random32()).as_ref()));
		}
		b
	};
	refused(r.http.post("submit_plan", &resign(&|p| p.steps[0].operator_script = address("R not the operator's"))), "out_of_bounds",
		"an operator script other than the quote's");
	let own = c0.valid(&r).leaf.script_pubkey();
	refused(r.http.post("submit_plan", &resign(&|p| p.steps[1].holder_script = own.clone())), "out_of_bounds",
		"a holder's address that is an Arca script");
	refused(r.http.post("submit_plan", &resign(&|p| p.steps[1].operator_nonce = [7; 32])), "nonce_unknown", "an operator nonce the quote did not draw");
	refused(r.http.post("submit_plan", &resign(&|p| p.steps[1].value -= 1)),
		"out_of_bounds", "a plan whose last step is unbalanced");
	refused(r.http.post("submit_plan", &resign(&|p| p.steps[1].exit_delay = arca_covenant::RelativeTime::from_units(400).unwrap())),
		"out_of_bounds", "an exit delay above the operator's");
	// The plan as made: taken; a second plan of the same coin, and a quote for
	// it, refused while the first is open.
	assert_eq!(r.http.post("submit_plan", &m.body).ok()["state"], "open");
	let n2 = [random32()];
	refused(quote(&r, &c0, &n2), "planned", "a quote for a coin an open plan names");
	// A quote: steps out of bounds, an attestation by another key, a board.
	refused(quote(&r, &c0, &[[1; 32]; 7].map(|_| random32())), "malformed", "a quote for seven steps");
	let c1 = round_coin(&mut r, "R2").await;
	let qd = server::plans::quote_digest(&r.server.params.chain, &r.server.params.operator, &c1.held.id, &n2, exit_delay());
	refused(r.http.post("plan_quote", &json!({"coin": c1.held.id.to_string(), "owner_nonces": [hex(&n2[0])],
		"exit_delay_units": exit_delay().units(), "attestation": hex(sign_digest(&other, &qd, &random32()).as_ref())})), "bad_attestation",
		"a quote asked by another key than the coin's");
	let x = r.x;
	let (board, _) = credited_board(&mut r, &keypair("R3 owner"), x).await;
	let qd = server::plans::quote_digest(&r.server.params.chain, &r.server.params.operator, &board.id, &n2, exit_delay());
	refused(r.http.post("plan_quote", &json!({"coin": board.id.to_string(), "owner_nonces": [hex(&n2[0])],
		"exit_delay_units": exit_delay().units(), "attestation": hex(sign_digest(&board.key, &qd, &random32()).as_ref())})), "out_of_bounds",
		"a quote for a board");
	// A second coin's plan naming a key the first plan's step holds.
	let mut m2 = make_plan(&r, &c1, "R2", 1);
	m2.body["steps"][0]["owner"] = m.body["steps"][0]["owner"].clone();
	refused(r.http.post("submit_plan", &m2.body), "bad_attestation", "a plan naming another plan's key, signed by its own");
	let _ = LeafId([0; 32]);
}

/// 4. A step whose round is lost (its block disconnected, the operator's coin
///    it spent taken by another transaction, final): the step is void, the
///    plan stopped, the coin it gave up is its holder's again, the watcher
///    holds no refund for it, its batch is not released past its expiry, and
///    the holder takes it home.
#[tokio::test(flavor = "multi_thread")]
async fn a_step_whose_round_is_lost_is_void_and_the_coin_it_gave_up_stays_its_holders() {
	let mut r = common::rounds::start().await;
	let c0 = round_coin(&mut r, "L").await;
	let e0 = expiry_of(&c0);
	let m = make_plan(&r, &c0, "L", 1);
	assert_eq!(r.http.post("submit_plan", &m.body).ok()["state"], "open");
	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, e0 - 5 * DAY + HOUR - now).await;
	r.synced().await;
	let lost = round(&mut r).await;
	assert_eq!(plan_status(&r, &m.id)["steps"][0]["state"], "done");
	// The rollback, the server stopped meanwhile: the round's block
	// disconnected, and the operator's coin it spent taken by another
	// transaction, final.
	let tx = r.rt.client().raw_transaction(&lost).unwrap();
	r.server.stop();
	let w = tx.input[0].previous_output;
	let w_out = r.rt.client().raw_transaction(&w.txid).unwrap().output[w.vout as usize].clone();
	let v: Value = r.rt.client().call("getrawtransaction", &[json!(lost.to_string()), json!(true)]).unwrap();
	let tip_time = { let h = r.rt.client().best_block_hash().unwrap(); let hdr: Value = r.rt.client().call("getblockheader", &[json!(h.to_string())]).unwrap(); hdr["time"].as_u64().unwrap() };
	common::node::invalidate(&r.rt, &v["blockhash"].as_str().unwrap().parse().unwrap());
	// The chain's clock runs weeks ahead of this machine's: the node starts
	// again at the chain's time.
	let mock = format!("-mocktime={}", tip_time + 60);
	tokio::task::block_in_place(|| r.rt.node.restart(&["-persistmempool=0", &mock])).unwrap();
	let (_, to) = server::wallet::Wallet::hand_out_receive_script(&r.db.store, common::keys::MNEMONIC).await.unwrap();
	let back = sequentia_ext::explicit_txout(sequentia_ext::AssetAmount::new(w_out.asset.explicit().unwrap(),
		w_out.value.explicit().unwrap() - 3_000), to);
	let elsewhere = common::rounds::spend_wallet_coin(w, &w_out, vec![back], 2_000);
	r.rt.client().send_raw_transaction(&elsewhere).unwrap();
	r.produce().await;
	r.bury().await;
	r.restart_server().await;
	common::rounds::round_state(&r, &lost, server::store::RoundState::Lost).await;
	// The round marked lost and the step voided are two writes: the server's
	// own loop may have made the first when the round is seen lost.
	let start = std::time::Instant::now();
	while plan_status(&r, &m.id)["state"] == "done" && start.elapsed() < std::time::Duration::from_secs(60) {
		r.server.rounds.pass().await.unwrap();
		tokio::time::sleep(std::time::Duration::from_millis(200)).await;
	}
	let st = plan_status(&r, &m.id);
	println!("step 1's round {} lost: {}", lost, st);
	assert_eq!(st["state"], "stopped");
	assert_eq!(st["steps"][0]["state"], "void");
	let row = r.server.store.leaf(&c0.held.id.0).await.unwrap().unwrap();
	assert_eq!(row.state, server::store::LeafState::Live, "the coin the step gave up is its holder's again");
	assert!(server::plans::refund_for(&r.server.store, &r.server.params, &c0.held.id.0).await.unwrap().is_none(),
		"the watcher holds no refund for it: the step's leaf does not exist");
	// The coin as its holder validated it, before its expiry.
	let v0 = c0.valid(&r);
	// Its batch is not released past its expiry while the plan is stopped.
	let token = match &c0.held.record {
		CoinRecord::Leaf { record, .. } => record.schedule.token.into_inner().to_byte_array().to_vec(),
		_ => unreachable!(),
	};
	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, e0 + HOUR - now).await;
	r.synced().await;
	for _ in 0..3 {
		r.server.watcher.pass().await.unwrap();
		settle(&r).await;
	}
	assert!(!has(&common::flow::log(&r).await, "release", &token), "the batch of a stopped plan's coin is not released");
	// The holder takes the coin home: its own authorisations, its preimage,
	// its exit after the delay; nothing answers it.
	let (valid, preimage, auths) = match &v0.origin {
		arca_covenant::ValidOrigin::Leaf { valid, preimage, auths } => (valid.clone(), *preimage, auths.clone()),
		_ => unreachable!(),
	};
	let txs = valid.branch.unroll(OutPoint::new(valid.round_txid, valid.batch_vout), &auths, &vec![FeeSource::Reserve; auths.len()]).unwrap();
	for u in &txs {
		r.rt.client().send_raw_transaction(&u.tx).unwrap();
	}
	let e = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), &preimage, &FeeSource::Reserve).unwrap();
	let at = OutPoint::new(r.rt.client().send_raw_transaction(&e.tx).unwrap(), 0);
	r.produce().await;
	r.synced().await;
	for _ in 0..3 {
		r.server.watcher.pass().await.unwrap();
		r.produce().await;
	}
	assert!(r.unspent(&at), "nothing answers the holder's coin");
	let now = mtp(&r).to_consensus_u32();
	advance_mtp(&r, 37 * HOUR).await;
	let _ = now;
	let exit = common::flow::exit_tx(&r, &v0.leaf, at, v0.asset, v0.value, &c0.held.key);
	let txid = r.rt.client().send_raw_transaction(&exit).unwrap();
	r.produce().await;
	assert!(r.rt.client().confirmations(&txid).unwrap() >= 1, "the holder's exit confirms");
	println!("the holder took its coin home: {} ({} vB)", txid, exit.vsize());
}
