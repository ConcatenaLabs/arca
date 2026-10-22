//! `channel-1`'s scripts: the builders against `regtest/vectors/channel.json`,
//! which `regtest/channel.py` derives independently, and every transaction
//! the builders make spent on an anchored regtest chain whose node checks
//! scripts inline (`-par=1`): an update to a newer state, the settle of the
//! latest after the exit delay, the claim of an unfolded note, the provider's
//! spend after the window, and a stale state settled while the owner's
//! latest note takes the operator's whole balance. Beside them, each refused
//! by the mempool and again in a block, for the script's reason: an update to
//! an older state, an older state's settle on the newer output, a settle
//! before its delay, a claim above the signed cumulative amount, and a claim
//! of a note already paid.

mod common;

use elements::hashes::Hash;
use elements::hex::FromHex;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{BlockHash, OutPoint, Transaction};
use serde_json::Value;

use arca_covenant::channel::{owner_script_pubkey, ChannelPolicy, ChannelTerms, State};
use arca_covenant::spend::{FeeSource, Pair, UnrollTx};
use arca_covenant::*;
use common::net::*;
use common::*;

const VECTORS: &str = include_str!("../../regtest/vectors/channel.json");

fn hex(v: &Value) -> Vec<u8> {
	Vec::<u8>::from_hex(v.as_str().unwrap_or_else(|| panic!("not a hex string: {}", v))).unwrap()
}

fn same(name: &str, got: &[u8], want: &Value) {
	assert_eq!(got.to_vec(), hex(want), "{}", name);
}

#[test]
fn the_channel_matches_the_regtest_suites_vectors() {
	let v: Value = serde_json::from_str(VECTORS).unwrap();
	let chain = Chain::new(BlockHash::from_byte_array(hex(&v["genesis"]).try_into().unwrap()));
	let key = |k: &str| XOnlyPublicKey::from_slice(&hex(&v["keys"][k])).unwrap();
	let seq = |k: &str| RelativeTime::from_sequence(v[k].as_u64().unwrap() as u32).unwrap();
	let p = ChannelPolicy {
		owner: key("A"), operator: key("S"), salt: hex(&v["salt"]).try_into().unwrap(), chain,
		exit_delay: seq("exit_delay_sequence"),
		terms: ChannelTerms { value: v["value"].as_u64().unwrap(), capacity: v["capacity"].as_u64().unwrap(),
			window: seq("window_sequence") },
	};
	same("state constant", &p.state_constant(), &v["state_constant"]);
	same("credit constant", &p.credit_constant(), &v["credit_constant"]);
	same("owner scriptPubKey", owner_script_pubkey(&p.owner).as_bytes(), &v["owner_script_pubkey"]);
	for s in v["states"].as_array().unwrap() {
		let st = State { number: s["number"].as_u64().unwrap(), owner: s["owner"].as_u64().unwrap(),
			operator: s["operator"].as_u64().unwrap(), folded: s["folded"].as_u64().unwrap() };
		let n = st.number;
		if n == 0 {
			assert_eq!(st, p.opening());
		}
		let (tap, ctap) = (p.taproot(&st), p.credit_taproot(&st));
		let o = &s["output"];
		same(&format!("state {} collab", n), p.collab_script().as_bytes(), &o["leaves"]["collab"]);
		same(&format!("state {} update", n), p.update_script(n).as_bytes(), &o["leaves"]["update"]);
		same(&format!("state {} settle", n), p.settle_script(&st).as_bytes(), &o["leaves"]["settle"]);
		same(&format!("state {} scriptPubKey", n), p.script_pubkey(&st).as_bytes(), &o["script_pubkey"]);
		same(&format!("state {} root", n), &tap.merkle_root().unwrap(), &o["merkle_root"]);
		for (leaf, script) in [("collab", p.collab_script()), ("update", p.update_script(n)), ("settle", p.settle_script(&st))] {
			same(&format!("state {} {} control block", n, leaf), &tap.control_block(&script).unwrap(), &o["control_blocks"][leaf]);
		}
		let c = &s["credit_output"];
		same(&format!("state {} claim", n), p.claim_script(&st).as_bytes(), &c["leaves"]["claim"]);
		same(&format!("state {} provider", n), p.provider_script().as_bytes(), &c["leaves"]["provider"]);
		same(&format!("state {} credit scriptPubKey", n), ctap.script_pubkey().as_bytes(), &c["script_pubkey"]);
		same(&format!("state {} credit root", n), &ctap.merkle_root().unwrap(), &c["merkle_root"]);
		same(&format!("state {} claim control block", n), &ctap.control_block(&p.claim_script(&st)).unwrap(),
			&c["control_blocks"]["claim"]);
		let d = p.state_message(&st).unwrap().digest;
		same(&format!("state {} digest", n), &d, &s["digest"]);
		for (k, who) in [("A", "channel A"), ("S", "channel S")] {
			let sig = Signature::from_slice(&hex(&s["signatures"][k])).unwrap();
			assert!(sign::verify_digest(&sig, &d, &key(k)), "state {}: {}'s signature", n, who);
		}
	}
	for note in v["notes"].as_array().unwrap() {
		let d = p.note_message(note["cumulative"].as_u64().unwrap()).unwrap().digest;
		same("note digest", &d, &note["digest"]);
		assert!(sign::verify_digest(&Signature::from_slice(&hex(&note["signature"])).unwrap(), &d, &p.operator));
	}
}

struct Run {
	net: Net,
	a: elements::secp256k1_zkp::Keypair,
	s: elements::secp256k1_zkp::Keypair,
}

impl Run {
	fn policy(&self, label: &str) -> ChannelPolicy {
		ChannelPolicy {
			owner: xonly(&self.a), operator: xonly(&self.s), salt: label32(label), chain: self.net.chain,
			exit_delay: RelativeTime::from_seconds_ceil(4 * H as u64).unwrap(),
			terms: ChannelTerms { value: 100_000_000, capacity: 40_000_000,
				window: RelativeTime::from_seconds_ceil(6 * H as u64).unwrap() },
		}
	}

	fn fee(&mut self) -> FeeSource {
		let c = self.net.fee_coin();
		FeeSource::Coin { outpoint: c.outpoint, coin: c.txout, fee: 2_000, change: op_true_spk() }
	}

	/// The fee coin's witness, input 1.
	fn done(u: UnrollTx) -> Transaction {
		let mut tx = u.tx;
		tx.input[1].witness.script_witness = op_true_witness();
		tx
	}

	fn state_sigs(&self, p: &ChannelPolicy, st: &State) -> (Signature, Signature) {
		let d = p.state_message(st).unwrap().digest;
		(sig(&self.s, &d), sig(&self.a, &d))
	}

	fn update(&mut self, p: &ChannelPolicy, at: OutPoint, from: &State, to: &State) -> Transaction {
		let (so, ao) = self.state_sigs(p, to);
		let fee = self.fee();
		Run::done(p.update_tx(at, self.net.x, from, to, &so, &ao, &fee).unwrap())
	}

	fn note(&self, p: &ChannelPolicy, c: u64) -> Signature {
		sig(&self.s, &p.note_message(c).unwrap().digest)
	}
}

#[test]
fn a_channel_on_the_node() {
	let net = Net::start();
	let mut r = Run { net, a: keypair("channel owner"), s: keypair("channel operator") };
	let x = r.net.x;
	let p = r.policy("channel one");
	let (s0, s2) = (p.opening(), State { number: 2, owner: 45_000_000, operator: 55_000_000, folded: 0 });
	let s3 = State { number: 3, owner: 65_000_000, operator: 35_000_000, folded: 20_000_000 };
	let coin = r.net.fund(vec![explicit(x, p.terms.value, p.script_pubkey(&s0))]).remove(0);

	// The owner publishes state 2; the operator answers at once with state 3.
	let tx = r.update(&p, coin.outpoint, &s0, &s2);
	let t2 = r.net.pass("update 0 -> 2, fee coin attached", &tx);
	let at2 = OutPoint::new(t2, 0);
	// state 1, signed by both, forced onto the state-2 output (the builder refuses it)
	let s1 = State { number: 1, owner: 50_000_000, operator: 50_000_000, folded: 0 };
	let mut old = r.update(&p, at2, &s2, &s3);
	let (so, ao) = r.state_sigs(&p, &s1);
	old.output[0].script_pubkey = p.script_pubkey(&s1);
	old.input[0].witness.script_witness = p.update_witness(&s2, &s1, &so, &ao);
	r.net.refuse("update to an older state (1 on 2)", &old, "Script failed an OP_VERIFY operation");
	let tx = r.update(&p, at2, &s2, &s3);
	let t3 = r.net.pass("update 2 -> 3, the latest", &tx);
	let at3 = OutPoint::new(t3, 0);

	// The settle waits the exit delay, then pays the latest state.
	let fee = r.fee();
	let early = Run::done(p.settle_tx(at3, x, &s3, &fee).unwrap());
	r.net.refuse("settle(3) before its delay", &early, "non-BIP68-final");
	r.net.wait_csv(&t3, p.exit_delay);
	let fee = r.fee();
	let mut stale = p.settle_tx(at3, x, &s2, &fee).unwrap();
	// state 2's settle leaf forced onto the state-3 output
	stale.tx.input[0].witness.script_witness = p.settle_witness(&s2);
	stale.prevouts[0] = explicit(x, p.terms.value, p.script_pubkey(&s3));
	r.net.refuse("settle(2) on the state-3 output", &Run::done(stale), "Witness program hash mismatch");
	let fee = r.fee();
	let settle = Run::done(p.settle_tx(at3, x, &s3, &fee).unwrap());
	let ts = r.net.pass("settle(3)", &settle);
	assert_eq!(settle.output[0].script_pubkey, owner_script_pubkey(&p.owner));
	assert_eq!(settle.output[0].value.explicit(), Some(s3.owner));

	// The credit output: B = 55M, it holds 35M, 20M folded already.
	let credit = OutPoint::new(ts, 1);
	let fee = r.fee();
	let mut over = p.claim_tx(credit, x, &s3, s3.operator, 30_000_000, &r.note(&p, 30_000_000), &fee).unwrap();
	// the operator signed 30M; the witness says 40M and the outputs follow it
	let (d40, rest40) = p.claim_amounts(&s3, 40_000_000, s3.operator).unwrap();
	over.tx.output[0].value = elements::confidential::Value::Explicit(d40);
	over.tx.output[1].value = elements::confidential::Value::Explicit(rest40);
	over.tx.input[0].witness.script_witness = p.claim_witness(&s3, &r.note(&p, 30_000_000), 40_000_000);
	r.net.refuse("claim of 40M with the note for 30M", &Run::done(over), "Invalid Schnorr signature");
	let fee = r.fee();
	let claim = Run::done(p.claim_tx(credit, x, &s3, s3.operator, 30_000_000, &r.note(&p, 30_000_000), &fee).unwrap());
	let tc = r.net.pass("claim of the unfolded 10M", &claim);
	assert_eq!(claim.output[0].value.explicit(), Some(10_000_000));
	let rest = OutPoint::new(tc, 1);
	let fee = r.fee();
	let mut again = p.claim_tx(rest, x, &s3, 25_000_000, 31_000_000, &r.note(&p, 30_000_000), &fee).unwrap();
	again.tx.input[0].witness.script_witness = p.claim_witness(&s3, &r.note(&p, 30_000_000), 30_000_000);
	r.net.refuse("the same note again", &Run::done(again), "Script failed an OP_VERIFY operation");
	r.net.wait_csv(&tc, p.terms.window);
	let fee = r.fee();
	let ks = p.provider_tx(rest, x, &s3, 25_000_000, &[ExplicitOutput::new(x, 25_000_000, op_true_spk())], &fee).unwrap();
	let sighash = ks.sighash(r.net.genesis).unwrap();
	let prov = Run::done(ks.finish(vec![sig(&r.s, &sighash).as_ref().to_vec()]));
	r.net.pass("provider takes the rest after the window", &prov);

	// A stale state 0 settled after the owner had paid 30M: the latest note
	// (50M, signed against state 1's cap of 70M) takes all of state 0's 40M.
	let q = r.policy("channel two");
	let coin = r.net.fund(vec![explicit(x, q.terms.value, q.script_pubkey(&s0))]).remove(0);
	r.net.wait_csv(&coin.outpoint.txid, q.exit_delay);
	let fee = r.fee();
	let ts = r.net.pass("settle(0), stale", &Run::done(q.settle_tx(coin.outpoint, x, &s0, &fee).unwrap()));
	let fee = r.fee();
	let capped = Run::done(q.claim_tx(OutPoint::new(ts, 1), x, &s0, s0.operator, 50_000_000, &r.note(&q, 50_000_000), &fee)
		.unwrap());
	assert_eq!(capped.output[0].value.explicit(), Some(40_000_000));
	assert_eq!(capped.output[1].script_pubkey, op_true_spk(), "no rest output: the fee coin's change follows");
	r.net.pass("claim capped at B: the whole 40M, no rest", &capped);
	r.net.print();
}

/// Two `channel-1` leaves and a `vtxo-1` leaf in one batch of a real round:
/// each channel leaf's record validates against the round, survives both
/// forms, and its leaf is the channel's state-0 output. One channel is
/// brought on-chain, updated to state 1 and then spent by the coin's
/// collaborative pair, as a forfeit answers a coin given up in a round; the
/// other is brought on-chain, updated, settled after the exit delay, and its
/// unfolded credit claimed.
#[test]
fn channel_leaves_from_a_round() {
	use common::round::*;
	let mut a = Arca::start();
	let s = keypair("round operator");
	let (issuer, sched) = a.schedule(&s);
	let owners = [keypair("vtxo owner"), keypair("channel owner one"), keypair("channel owner two")];
	let preimages: Vec<[u8; 32]> = (0..3).map(|i| label32(&format!("entry preimage {}", i))).collect();
	let window = RelativeTime::from_units(delay().units() * 2).unwrap();
	let leaves: Vec<_> = (0..3).map(|i| {
		let mut sp = spec(&owners[i], &format!("round leaf {}", i), 20_000_000, hash(&preimages[i]));
		if i > 0 {
			sp.template = Template::Channel1;
			sp.channel = Some(Channel { capacity: 8_000_000, window });
		}
		sp
	}).collect();
	let tree = a.tree(&sched, &leaves);
	let (round, _) = round_tx(&a.net, &issuer, &[], &tree.batch_output(), &sched);
	a.net.pass("round with two channel-1 leaves", &round);
	let x = a.net.x;
	let policy = a.policy(&s);
	let t = mt(a.net.mtp() - 60);
	let mut coins = vec![];
	for i in 1..3 {
		let record = tree.record(i);
		assert_eq!(record.template, Template::Channel1);
		assert_eq!(LeafRecord::from_bytes(&record.to_bytes().unwrap()).unwrap(), record);
		assert_eq!(LeafRecord::from_json_str(&record.to_json_string().unwrap()).unwrap(), record);
		let valid = record.validate(&round, &policy, &xonly(&owners[i]), &record.owner_nonce).unwrap();
		let cp = record.leaf().channel_policy().unwrap();
		assert_eq!(cp.program(&cp.opening()), record.leaf().program());
		assert_eq!(cp.opening(), State { number: 0, owner: 12_000_000, operator: 8_000_000, folded: 0 });
		let auths = owner_auths(&valid, &owners[i], t);
		let at = if i == 1 {
			a.bring_leaf("channel 1", &valid, &auths, &preimages[i])
		} else {
			// the one node above both leaves is on-chain already: only the entry
			let txs = valid.branch.unroll(OutPoint::new(valid.round_txid, valid.batch_vout), &auths,
				&vec![FeeSource::Reserve; auths.len()]).unwrap();
			let e = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), &preimages[i], &FeeSource::Reserve).unwrap();
			OutPoint::new(a.net.pass("channel 2: entry into the leaf", &e.tx), 0)
		};
		coins.push((cp, at));
	}
	let fee = |a: &mut Arca| {
		let c = a.net.fee_coin();
		FeeSource::Coin { outpoint: c.outpoint, coin: c.txout, fee: 2_000, change: op_true_spk() }
	};
	let done = |u: UnrollTx| { let mut tx = u.tx; tx.input[1].witness.script_witness = op_true_witness(); tx };
	let state_pair = |cp: &ChannelPolicy, st: &State, owner: &elements::secp256k1_zkp::Keypair| {
		let d = cp.state_message(st).unwrap().digest;
		(sig(&s, &d), sig(owner, &d))
	};

	// Channel one: updated to state 1, then answered by the coin's pair.
	let (cp, at) = coins[0];
	let s1 = cp.opening().pay(2_000_000, 0).unwrap();
	let (so, ao) = state_pair(&cp, &s1, &owners[1]);
	let f = fee(&mut a);
	let t1 = a.net.pass("channel one: update 0 -> 1", &done(cp.update_tx(at, x, &cp.opening(), &s1, &so, &ao, &f).unwrap()));
	let leaf = tree.record(1).leaf();
	let outs = [ExplicitOutput::new(x, 20_000_000 - 1_000, op_true_spk())];
	let d = leaf.collab_message(x, 20_000_000, &outs).unwrap().digest;
	let pair = Pair { operator: sig(&s, &d), owner: sig(&owners[1], &d) };
	let f = fee(&mut a);
	let answer = done(cp.collab_tx(OutPoint::new(t1, 0), x, &s1, &outs, &pair, &f).unwrap());
	// the channel's 1,000-atom margin is the fee coin's change's to take
	assert!(answer.output.len() >= 2);
	a.net.pass("channel one: the coin's pair spends its state-1 output", &answer);

	// Channel two: updated, settled after the exit delay, credit claimed.
	let (cp, at) = coins[1];
	let s1 = cp.opening().pay(3_000_000, 0).unwrap();
	let s2 = s1.pay(0, 5_000_000).unwrap();
	assert_eq!(s2, State { number: 2, owner: 14_000_000, operator: 6_000_000, folded: 5_000_000 });
	let (so, ao) = state_pair(&cp, &s2, &owners[2]);
	let f = fee(&mut a);
	let t2 = a.net.pass("channel two: update 0 -> 2", &done(cp.update_tx(at, x, &cp.opening(), &s2, &so, &ao, &f).unwrap()));
	a.net.wait_csv(&t2, cp.exit_delay);
	let f = fee(&mut a);
	let ts = a.net.pass("channel two: settle(2)", &done(cp.settle_tx(OutPoint::new(t2, 0), x, &s2, &f).unwrap()));
	let note = sig(&s, &cp.note_message(7_000_000).unwrap().digest);
	let f = fee(&mut a);
	let claim = done(cp.claim_tx(OutPoint::new(ts, 1), x, &s2, s2.operator, 7_000_000, &note, &f).unwrap());
	assert_eq!(claim.output[0].value.explicit(), Some(2_000_000));
	a.net.pass("channel two: claim of 2M unfolded credit (note 7M, 5M folded)", &claim);
	a.net.print();
}
