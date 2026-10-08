//! The out-of-round transfer through the verifier: a chain three hops deep,
//! one of them a swap of two owners' coins in two assets, received and
//! validated from the last receiver's record alone; every transaction that
//! brings the coin on-chain built from that record and verified under the
//! block rules and the mempool's checks; each kind of bad record refused; and
//! the operator's rule that no two reassignments it co-signs can be satisfied
//! by one transaction.

mod common;

use std::str::FromStr;

use elements::hashes::{sha256d, Hash};
use elements::{AssetId, AssetIssuance, BlockHash, ContractHash, OutPoint, Transaction, Txid};

use arca_consensus::Verifier;
use arca_covenant::spend::{FeeSource, UnrollTx};
use arca_covenant::tree::ReserveRule;
use arca_covenant::*;

use common::chain::*;
use common::*;

const CREATED: u32 = 1_791_000_000;

struct Fx {
	consensus: Verifier,
	standard: Verifier,
	policy: WalletPolicy,
	rounds: Vec<Transaction>,
	b: Batches,
	hops: Hops,
}

fn issuer(label: &str) -> OutPoint {
	OutPoint::new(Txid::from_raw_hash(sha256d::Hash::hash(label.as_bytes())), 0)
}

fn schedule(s: &elements::secp256k1_zkp::Keypair, issuer: OutPoint, delay: RelativeTime) -> ClockSchedule {
	let token = AssetId::new_issuance(issuer, ContractHash::from_byte_array([0; 32]));
	let e = |d: u32| MedianTime::from_consensus(CREATED + d * 86_400).unwrap();
	ClockSchedule::new(token, xonly(s), delay, vec![e(28), e(56)]).unwrap()
}

fn round(tree: &arca_covenant::Tree, issuer: OutPoint) -> Transaction {
	let x = tree.params().asset;
	let mut r = Spend::new(0).input(issuer, explicit(x, 10_000_000_000, op_true().script_pubkey()), 0xffff_ffff)
		.outputs(vec![tree.batch_output().txout(), explicit(tree.params().schedule.token, 1, tree.clock0_script_pubkey()), fee(x, 2_000)]).tx;
	r.input[0].asset_issuance = AssetIssuance {
		asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: [0; 32],
		amount: elements::confidential::Value::Explicit(1), inflation_keys: elements::confidential::Value::Null, denomination: 0,
	};
	r
}

fn fx() -> Fx {
	let genesis = BlockHash::from_str("16af270696dbd3a65ed61a2f48459c8d8e9110c0c9937938109e7d7c87e8e42c").unwrap();
	let chain = Chain::new(genesis);
	let s = keypair("transfer operator");
	let delay = RelativeTime::from_seconds_ceil(36 * 3600).unwrap();
	let (i1, i2) = (issuer("transfer batch 1"), issuer("transfer batch 2"));
	let b = batches(chain, asset("transfer X"), asset("transfer Y"), s, schedule(&s, i1, delay), schedule(&s, i2, delay),
		delay, ReserveRule::FeeRate { floor_per_kvb: 100, multiple: 4 });
	let rounds = vec![round(&b.batch1, i1), round(&b.batch2, i2)];
	let now = MedianTime::from_consensus(CREATED).unwrap();
	let policy = WalletPolicy::new(chain, xonly(&s), now);
	let hops = hops(&b, &rounds, &policy, now, delay);
	Fx { consensus: Verifier::consensus(genesis), standard: Verifier::standard(genesis), policy, rounds, b, hops }
}

/// Builds every transaction that brings `coin` on-chain, each fee paid from
/// its own margin, appends them to `out` and returns where the coin lands.
fn bring(coin: &ValidCoin, out: &mut Vec<(String, UnrollTx)>) -> OutPoint {
	match &coin.origin {
		ValidOrigin::Leaf { valid, preimage, auths } => {
			let txs = valid.branch.unroll(OutPoint::new(valid.round_txid, valid.batch_vout), auths,
				&vec![FeeSource::Reserve; auths.len()]).unwrap();
			let e = valid.branch.entry_tx(valid.branch.entry_outpoint(&txs).unwrap(), preimage, &FeeSource::Reserve).unwrap();
			for (i, u) in txs.into_iter().enumerate() {
				out.push((format!("unroll of leaf {}, node {}", coin.id, i), u));
			}
			let at = OutPoint::new(e.tx.txid(), 0);
			out.push((format!("entry of leaf {}", coin.id), e));
			at
		},
		ValidOrigin::Transfer { inputs, index, .. } => {
			let mut cps = vec![];
			for (k, i) in inputs.iter().enumerate() {
				let at = bring(&i.coin, out);
				let cp = i.checkpoint_tx(at, &FeeSource::Reserve).unwrap();
				cps.push(OutPoint::new(cp.tx.txid(), 0));
				out.push((format!("checkpoint {} of coin {}", k, coin.id), cp));
			}
			let re = coin.reassignment_tx(&cps, &FeeSource::Reserve).unwrap();
			let at = OutPoint::new(re.tx.txid(), *index as u32);
			out.push((format!("reassignment creating coin {}", coin.id), re));
			at
		},
		ValidOrigin::Board { .. } => unreachable!("the chain has no board"),
	}
}

#[test]
fn a_chain_three_hops_deep_is_received_and_brought_on_chain() {
	let f = fx();
	let d = &f.hops.d;
	// D holds the record alone, as bytes from its mailbox.
	let bytes = f.hops.d_record.to_bytes().unwrap();
	let rec = CoinRecord::from_bytes(&bytes).unwrap();
	assert_eq!(rec.to_bytes().unwrap(), bytes);
	let coin = rec.validate(&f.rounds, &f.policy, &d.leaf.owner, &d.leaf.owner_nonce).unwrap();
	assert_eq!((coin.hops, coin.asset, coin.value), (3, f.b.batch2.params().asset, 5_000_000 - 3 * MARGIN));
	assert_eq!(coin.leaf.script_pubkey(), d.leaf.policy(xonly(&f.b.s), f.policy.chain).script_pubkey());
	println!("D's record: {} bytes, coin {} of {} atoms, {} hops, expiry {}", bytes.len(), coin.id, coin.value, coin.hops,
		coin.expiry.to_consensus_u32());

	// Everything that brings the coin on-chain, built from the record.
	let mut txs = vec![];
	let at = bring(&coin, &mut txs);
	for (name, u) in &txs {
		f.consensus.verify_tx(&u.prevouts, &u.tx).unwrap_or_else(|(i, e)| panic!("{}: input {}: {}", name, i, e));
		f.standard.verify_tx(&u.prevouts, &u.tx).unwrap_or_else(|(i, e)| panic!("{}: input {} (standard): {}", name, i, e));
		println!("{:<90} {:>4} vB, verifies", name, u.tx.vsize());
	}
	assert_eq!(txs.len(), 2 + 1 + 2 + 1 + 1 + 1 + 1 + 1 + 1 + 1);
	// D's leaf, at the end, exits under D's key alone.
	let ks = coin.leaf.exit_tx(at, coin.asset, coin.value,
		&[ExplicitOutput::new(coin.asset, coin.value - 1_500, op_true().script_pubkey())], &FeeSource::Reserve).unwrap();
	let sg = arca_covenant::sign::sign_digest(&d.key, &ks.sighash(f.policy.chain.genesis_hash()).unwrap(), &ZERO_AUX);
	let exit = ks.finish(vec![sg.as_ref().to_vec()]);
	f.consensus.verify_tx(&exit.prevouts, &exit.tx).unwrap();
	println!("D's exit: {} vB, verifies", exit.tx.vsize());

	// The other receivers' records validate for them too.
	let h = &f.hops;
	for (r, p) in [(&h.b1_record, &h.b1), (&h.a_change_record, &h.a_change), (&h.b2_record, &h.b2), (&h.c2_record, &h.c2)] {
		r.validate(&f.rounds, &f.policy, &p.leaf.owner, &p.leaf.owner_nonce).unwrap();
	}
}

/// Where an output `out` built earlier lands, if one of `out`'s
/// transactions pays it.
fn built_at(out: &[(String, UnrollTx)], o: &ExplicitOutput) -> Option<OutPoint> {
	let o = o.txout();
	out.iter().find_map(|(_, u)| u.tx.output.iter().position(|x| *x == o).map(|j| OutPoint::new(u.tx.txid(), j as u32)))
}

/// `bring`, building each transaction once however often the lineage
/// reaches it: two coins of one reassignment carry its spends both.
fn bring_once(coin: &ValidCoin, out: &mut Vec<(String, UnrollTx)>) -> OutPoint {
	if let Some(at) = built_at(out, &coin.output()) {
		return at;
	}
	match &coin.origin {
		ValidOrigin::Transfer { inputs, index, .. } => {
			let mut cps = vec![];
			for (k, i) in inputs.iter().enumerate() {
				let at = bring_once(&i.coin, out);
				let cp = i.checkpoint_tx(at, &FeeSource::Reserve).unwrap();
				cps.push(OutPoint::new(cp.tx.txid(), 0));
				out.push((format!("checkpoint {} of coin {}", k, coin.id), cp));
			}
			let re = coin.reassignment_tx(&cps, &FeeSource::Reserve).unwrap();
			let at = OutPoint::new(re.tx.txid(), *index as u32);
			out.push((format!("reassignment creating coin {}", coin.id), re));
			at
		},
		_ => bring(coin, out),
	}
}

/// Two coins of one reassignment, B's and A's change from hop 1, spent
/// together: each carries hop 1's spend of A's leaf, which is one spend met
/// twice, and the record is good; one transaction of hop 1 brings both on
/// the chain. A's leaf spent by two reassignments, or one coin at both
/// inputs, is still refused.
#[test]
fn two_coins_of_one_reassignment_are_spent_together() {
	let f = fx();
	let h = &f.hops;
	let p = &f.policy;
	let s = &f.b.s;
	let (b1, ch) = (h.b1_record.resolve(&f.rounds, p).unwrap(), h.a_change_record.resolve(&f.rounds, p).unwrap());
	let e = Party::new("E, paid both", h.d.leaf.exit_delay);
	let pay_both = |records: [&CoinRecord; 2], coins: [&ValidCoin; 2], keys: [&elements::secp256k1_zkp::Keypair; 2], to: &Party| {
		let plan = TransferPlan {
			inputs: coins.iter().map(|c| ((*c).clone(), c.value - MARGIN)).collect(),
			outputs: vec![ExplicitOutput::new(coins[0].asset, coins[0].value + coins[1].value - 3 * MARGIN,
				to.leaf.policy(xonly(s), p.chain).script_pubkey())],
		};
		CoinRecord::Transfer(Box::new(Transfer {
			inputs: (0..2).map(|i| {
				let (cp, re) = (plan.checkpoint_message(i).unwrap().digest, plan.reassignment_message(i).unwrap().digest);
				TransferInput { coin: records[i].clone(), checkpoint_value: plan.inputs[i].1,
					checkpoint: Pair { operator: sig(s, &cp), owner: sig(keys[i], &cp) },
					reassignment: Pair { operator: sig(s, &re), owner: sig(keys[i], &re) } }
			}).collect(),
			outputs: plan.outputs.clone(), index: 0, leaf: to.leaf,
		}))
	};
	let rec = pay_both([&h.b1_record, &h.a_change_record], [&b1, &ch], [&h.b1.key, &h.a_change.key], &e);
	let coin = rec.validate(&f.rounds, p, &e.leaf.owner, &e.leaf.owner_nonce)
		.unwrap_or_else(|err| panic!("two coins of hop 1 spent together: {} ({})", err, err.kind()));
	assert_eq!(coin.value, b1.value + ch.value - 3 * MARGIN);
	println!("B's coin and A's change of hop 1 spent together: coin {} of {} atoms, {} hops", coin.id, coin.value, coin.hops);
	let mut txs = vec![];
	bring_once(&coin, &mut txs);
	for (name, u) in &txs {
		f.consensus.verify_tx(&u.prevouts, &u.tx).unwrap_or_else(|(i, e)| panic!("{}: input {}: {}", name, i, e));
		f.standard.verify_tx(&u.prevouts, &u.tx).unwrap_or_else(|(i, e)| panic!("{}: input {} (standard): {}", name, i, e));
		println!("{:<90} {:>4} vB, verifies", name, u.tx.vsize());
	}
	let hop1: Vec<&String> = txs.iter().map(|(n, _)| n).filter(|n| n.contains(&format!("coin {}", b1.id)) || n.contains(&format!("coin {}", ch.id))).collect();
	assert_eq!(txs.iter().filter(|(n, _)| n.starts_with("reassignment")).count(), 2, "hop 1's reassignment once, then E's: {:?}", hop1);
	// The two inputs' checkpoints both spend outputs of hop 1's one reassignment.
	let re1 = txs.iter().find(|(n, _)| n == &format!("reassignment creating coin {}", b1.id)).expect("hop 1's reassignment").1.tx.txid();
	assert_eq!(txs.iter().filter(|(n, u)| n.starts_with("checkpoint") && u.tx.input[0].previous_output.txid == re1).count(), 2);

	// Refused still: A's leaf spent by a second reassignment, paying F, and
	// F's coin spent beside B's.
	let a_coin = h.a_base.resolve(&f.rounds, p).unwrap();
	let fp = Party::new("F, A's second spend", h.d.leaf.exit_delay);
	let f_rec = pay(&h.a_base, &a_coin, &f.b.a, s, fp.leaf, p.chain);
	let f_coin = f_rec.resolve(&f.rounds, p).unwrap();
	let m = pay_both([&h.b1_record, &f_rec], [&b1, &f_coin], [&h.b1.key, &fp.key], &e);
	let err = m.validate(&f.rounds, p, &e.leaf.owner, &e.leaf.owner_nonce).unwrap_err();
	println!("{:<64} {} ({})", "A's leaf spent by two reassignments, both coins spent", err, err.kind());
	assert!(matches!(err, TransferError::DoubleSpend(id) if id == a_coin.id), "{}", err);
	// One coin at both inputs, reached through one spend.
	let m = pay_both([&h.b1_record, &h.b1_record], [&b1, &b1], [&h.b1.key, &h.b1.key], &e);
	let err = m.validate(&f.rounds, p, &e.leaf.owner, &e.leaf.owner_nonce).unwrap_err();
	println!("{:<64} {} ({})", "B's coin at both inputs", err, err.kind());
	assert!(matches!(err, TransferError::DoubleSpend(id) if id == b1.id), "{}", err);
}

fn transfer(r: &CoinRecord) -> &Transfer {
	match r {
		CoinRecord::Transfer(t) => t,
		_ => panic!("a transfer"),
	}
}

fn transfer_mut(r: &mut CoinRecord) -> &mut Transfer {
	match r {
		CoinRecord::Transfer(t) => t,
		_ => panic!("a transfer"),
	}
}

#[test]
fn each_bad_record_is_refused() {
	let f = fx();
	let d = &f.hops.d;
	let rec = &f.hops.d_record;
	let refuse = |name: &str, r: &CoinRecord, policy: &WalletPolicy, owner: &elements::secp256k1_zkp::XOnlyPublicKey, nonce: &[u8; 32]| {
		let e = r.validate(&f.rounds, policy, owner, nonce).err().unwrap_or_else(|| panic!("{}: ACCEPTED", name));
		println!("{:<64} {} ({})", name, e, e.kind());
		e
	};
	let (key, nonce) = (d.leaf.owner, d.leaf.owner_nonce);
	let p = &f.policy;

	assert_eq!(refuse("another receiver's key", rec, p, &xonly(&f.b.a), &nonce).kind(), "owner");
	assert_eq!(refuse("not the nonce D published", rec, p, &key, &[9; 32]).kind(), "owner");
	let e = rec.validate(&f.rounds[..1], p, &key, &nonce).unwrap_err();
	assert_eq!(e.kind(), "round", "batch 2's round missing: {}", e);

	// The committed output changed: the pairs sign other outputs.
	let mut m = rec.clone();
	transfer_mut(&mut m).outputs[0].value -= 1;
	transfer_mut(&mut m).leaf = d.leaf;
	assert!(matches!(refuse("D's output one atom less", &m, p, &key, &nonce), TransferError::Pair { pair: "reassignment", .. }));
	// The two pairs swapped: a checkpoint's pair does not fit the leaf.
	let mut m = rec.clone();
	let i = &mut transfer_mut(&mut m).inputs[0];
	std::mem::swap(&mut i.checkpoint, &mut i.reassignment);
	assert!(matches!(refuse("the checkpoint and reassignment pairs swapped", &m, p, &key, &nonce), TransferError::Pair { pair: "checkpoint", .. }));
	// An operator signature from another key.
	let mut m = rec.clone();
	transfer_mut(&mut m).inputs[0].reassignment.operator = transfer(rec).inputs[0].reassignment.owner;
	assert_eq!(refuse("the owner's signature in the operator's place", &m, p, &key, &nonce).kind(), "signature");
	// A checkpoint worth more than the coin.
	let mut m = rec.clone();
	transfer_mut(&mut m).inputs[0].checkpoint_value = 10_000_000;
	assert_eq!(refuse("a checkpoint worth more than its coin", &m, p, &key, &nonce).kind(), "value");
	// The index pointing at a leaf that is not D's.
	let mut m = f.hops.b2_record.clone();
	transfer_mut(&mut m).leaf = d.leaf;
	assert_eq!(refuse("B's output claimed as D's leaf", &m, p, &key, &nonce).kind(), "output");
	// One coin spent twice in the lineage: hop 2's B input replaced by A's
	// base leaf, which hop 1 already spends... built as a new swap where both
	// inputs are the same coin.
	let mut m = f.hops.b2_record.clone();
	let first = transfer(&m).inputs[0].clone();
	transfer_mut(&mut m).inputs[1] = first;
	assert_eq!(refuse("one coin at both inputs of a swap", &m, p, &f.hops.b2.leaf.owner, &f.hops.b2.leaf.owner_nonce).kind(),
		"double_spend");
	// One leaf promised by two reassignments: A and a bystander of batch 1
	// each pay one output, the same leaf (a sender repeating another's
	// creator nonce), and its owner pays both coins on. One transaction can
	// satisfy both reassignments and create the leaf once.
	let s = &f.b.s;
	let t = MedianTime::from_consensus(CREATED).unwrap();
	let by = keypair("chain batch 1 bystander 0");
	let by_base = base(&f.b.batch1, 0, &by, f.b.preimages1[0], t);
	let by_coin = by_base.resolve(&f.rounds, p).unwrap();
	let a_coin = f.hops.a_base.resolve(&f.rounds, p).unwrap();
	assert_eq!((a_coin.asset, a_coin.value), (by_coin.asset, by_coin.value));
	let twice = Party::new("promised twice", d.leaf.exit_delay);
	let x1 = pay(&f.hops.a_base, &a_coin, &f.b.a, s, twice.leaf, p.chain);
	let x2 = pay(&by_base, &by_coin, &by, s, twice.leaf, p.chain);
	let (k1, k2) = (x1.resolve(&f.rounds, p).unwrap(), x2.resolve(&f.rounds, p).unwrap());
	assert_eq!(k1.output(), k2.output());
	let next = Party::new("after the promised leaf", d.leaf.exit_delay);
	let plan = TransferPlan {
		inputs: vec![(k1.clone(), k1.value - MARGIN), (k2.clone(), k2.value - MARGIN)],
		outputs: vec![ExplicitOutput::new(k1.asset, k1.value + k2.value - 3 * MARGIN, next.leaf.policy(xonly(s), p.chain).script_pubkey())],
	};
	let m = CoinRecord::Transfer(Box::new(Transfer {
		inputs: [&x1, &x2].iter().enumerate().map(|(i, r)| {
			let (cp, re) = (plan.checkpoint_message(i).unwrap().digest, plan.reassignment_message(i).unwrap().digest);
			TransferInput { coin: (*r).clone(), checkpoint_value: plan.inputs[i].1,
				checkpoint: Pair { operator: sig(s, &cp), owner: sig(&twice.key, &cp) },
				reassignment: Pair { operator: sig(s, &re), owner: sig(&twice.key, &re) } }
		}).collect(),
		outputs: plan.outputs.clone(), index: 0, leaf: next.leaf,
	}));
	let e = refuse("one leaf promised by two reassignments, both spent", &m, p, &next.leaf.owner, &next.leaf.owner_nonce);
	assert!(matches!(e, TransferError::SaltTwice { .. }), "{}", e);
	assert_eq!(e.kind(), "salt");
	// The coin's own leaf made again from a salt up its lineage.
	let m = pay(&f.hops.d_record, &coin_of(&f, rec), &d.key, s, d.leaf, p.chain);
	assert!(matches!(refuse("a coin paid into the leaf it came from", &m, p, &key, &nonce), TransferError::SaltTwice { .. }));
	// An unroll authorisation by another key, or not yet usable.
	let mut m = f.hops.a_base.clone();
	if let CoinRecord::Leaf { auths, .. } = &mut m {
		auths[0].0 = sig(&f.b.c, &[0; 32]);
	}
	assert_eq!(m.resolve(&f.rounds, p).unwrap_err().kind(), "unroll");
	let mut m = f.hops.a_base.clone();
	if let CoinRecord::Leaf { preimage, .. } = &mut m {
		preimage[0] ^= 1;
	}
	assert_eq!(m.resolve(&f.rounds, p).unwrap_err().to_string(), "a leaf's preimage does not open its entry");
	let early = WalletPolicy { now: MedianTime::from_consensus(CREATED - 1).unwrap(), ..*p };
	assert!(matches!(f.hops.a_base.resolve(&f.rounds, &early).unwrap_err(), TransferError::AuthTime(0)));
	// The receiver's policy: a coin past its horizon, or another operator.
	let later = WalletPolicy { now: MedianTime::from_consensus(CREATED + 2 * 86_400).unwrap(), ..*p };
	assert_eq!(refuse("a coin whose earliest batch expires inside the horizon", rec, &later, &key, &nonce).kind(), "policy");
	// Every leaf of the chain is the operator's: a wallet told another
	// operator refuses the batch leaves the chain starts from.
	let other = WalletPolicy { operator: xonly(&f.b.a), ..*p };
	assert!(matches!(refuse("a chain whose batch leaves are another operator's", rec, &other, &key, &nonce),
		TransferError::Record(RecordError::WrongOperator)));
	// The receipt policy asks only for the exit deadline: the coin that the
	// acceptance horizon refuses two days after its rounds is good until
	// three days before the earliest first expiry in its lineage.
	let coin = rec.validate(&f.rounds, &later.receipt(), &key, &nonce).unwrap();
	let e0 = coin.expiry.to_consensus_u32();
	let last = WalletPolicy { now: MedianTime::from_consensus(e0 - 3 * 86_400).unwrap(), ..*p };
	rec.validate(&f.rounds, &last.receipt(), &key, &nonce).unwrap();
	let past = WalletPolicy { now: MedianTime::from_consensus(e0 - 3 * 86_400 + 1).unwrap(), ..*p };
	assert!(matches!(refuse("a coin past the exit deadline of its earliest batch", rec, &past.receipt(), &key, &nonce),
		TransferError::Record(RecordError::ExpiryTooSoon { .. })));

	// Deeper than the depth limit: D pays itself three more times.
	let s = &f.b.s;
	let mut r = rec.clone();
	let mut owner = d.clone();
	for h in 0..3 {
		let coin = r.resolve(&f.rounds, p).unwrap();
		let next = Party::new(&format!("self payment {}", h), d.leaf.exit_delay);
		let plan = TransferPlan {
			inputs: vec![(coin.clone(), coin.value - MARGIN)],
			outputs: vec![ExplicitOutput::new(coin.asset, coin.value - 2 * MARGIN, next.leaf.policy(xonly(s), p.chain).script_pubkey())],
		};
		let (cp, re) = (plan.checkpoint_message(0).unwrap().digest, plan.reassignment_message(0).unwrap().digest);
		r = CoinRecord::Transfer(Box::new(Transfer {
			inputs: vec![TransferInput { coin: r, checkpoint_value: coin.value - MARGIN,
				checkpoint: Pair { operator: sig(s, &cp), owner: sig(&owner.key, &cp) },
				reassignment: Pair { operator: sig(s, &re), owner: sig(&owner.key, &re) } }],
			outputs: plan.outputs.clone(), index: 0, leaf: next.leaf,
		}));
		owner = next;
	}
	assert_eq!(r.resolve(&f.rounds, p).unwrap().hops, 6);
	assert_eq!(refuse("six reassignments from a round", &r, p, &owner.leaf.owner, &owner.leaf.owner_nonce).to_string(),
		"6 reassignments since a round; a coin is refreshed into a round after 5");
}

fn coin_of(f: &Fx, rec: &CoinRecord) -> ValidCoin {
	rec.resolve(&f.rounds, &f.policy).unwrap()
}

/// What the operator records of the reassignment that created `coin`.
fn reassignment(coin: &ValidCoin) -> (Vec<(LeafId, u64)>, Vec<ExplicitOutput>) {
	match &coin.origin {
		ValidOrigin::Transfer { inputs, outputs, .. } =>
			(inputs.iter().map(|i| (i.coin.id, i.checkpoint_value)).collect(), outputs.clone()),
		_ => panic!("a reassignment's output"),
	}
}

#[test]
fn the_operator_cosigns_no_two_reassignments_one_transaction_could_satisfy() {
	let f = fx();
	let h = &f.hops;
	// The chain's three reassignments, each seen once per output it creates:
	// none refused, and an output's second sight is the same reassignment.
	let mut seen = SeenReassignments::new();
	for r in [&h.b1_record, &h.a_change_record, &h.b2_record, &h.c2_record, &h.d_record] {
		let (ins, outs) = reassignment(&coin_of(&f, r));
		seen.admit(&ins, &outs).unwrap();
	}
	assert_eq!(seen.len(), 3);

	// Against hop 1's outputs [B1, A's change]: another reassignment with
	// the same outputs, with only the first, with one more after them, all
	// refused; the first alone, then the full set, refused in that order too.
	let (ins1, outs1) = reassignment(&coin_of(&f, &h.b1_record));
	let other = vec![(h.d_record.resolve(&f.rounds, &f.policy).unwrap().id, 1_000)];
	let more = {
		let mut o = outs1.clone();
		o.push(ExplicitOutput::new(o[0].asset, 1, op_true().script_pubkey()));
		o
	};
	for (name, outs) in [("the same outputs", outs1.clone()), ("its first output alone", outs1[..1].to_vec()),
		("its outputs and one more", more)]
	{
		let e = seen.check(&other, &outs).unwrap_err();
		println!("against hop 1 {:<28} {} ({})", name, e, e.kind());
		assert!(matches!(e, TransferError::Mergeable));
		assert!(arca_covenant::transfer::mergeable(&outs1, &outs));
	}
	let mut alone = SeenReassignments::new();
	alone.admit(&other, &outs1[..1]).unwrap();
	assert!(matches!(alone.admit(&ins1, &outs1).unwrap_err(), TransferError::Mergeable));
	// The same first output and another second: no transaction satisfies
	// both, since both commit to output 1; not refused.
	let mut diverge = outs1.clone();
	diverge[1].value -= 1;
	assert!(!arca_covenant::transfer::mergeable(&outs1, &diverge));
	seen.check(&other, &diverge).unwrap();
	// The same reassignment again is not another one.
	seen.check(&ins1, &outs1).unwrap();
	// Its inputs with another checkpoint value is another reassignment.
	let mut ins_other = ins1.clone();
	ins_other[0].1 -= 1;
	assert!(matches!(seen.check(&ins_other, &outs1).unwrap_err(), TransferError::Mergeable));
	assert!(matches!(seen.check(&ins1, &[]).unwrap_err(), TransferError::Outputs(0)));

	// The plan the sender builds is what the operator admits.
	let plan = TransferPlan { inputs: vec![(coin_of(&f, &h.a_base), 1_000)], outputs: outs1.clone() };
	assert!(matches!(plan.admit(&mut seen).unwrap_err(), TransferError::Mergeable));
	let mut fresh = Party::new("B1", f.hops.b1.leaf.exit_delay).leaf;
	fresh.creator_nonce = label32("another creator nonce");
	let fresh_out = vec![ExplicitOutput::new(outs1[0].asset, outs1[0].value, fresh.policy(xonly(&f.b.s), f.policy.chain).script_pubkey())];
	let plan = TransferPlan { inputs: vec![(coin_of(&f, &h.a_base), 1_000)], outputs: fresh_out };
	plan.admit(&mut seen).unwrap();
	println!("the same receiver, key and nonce, with another creator nonce: admitted");
}

#[test]
fn every_one_byte_change_of_a_record_is_refused() {
	let f = fx();
	let d = &f.hops.d;
	let bytes = f.hops.d_record.to_bytes().unwrap();
	let (mut decode, mut validate) = (0, 0);
	let mut kinds = std::collections::BTreeMap::new();
	for i in 0..bytes.len() {
		for mask in [0x01u8, 0x80] {
			let mut b = bytes.clone();
			b[i] ^= mask;
			match CoinRecord::from_bytes(&b) {
				Err(e) => {
					decode += 1;
					*kinds.entry(e.kind()).or_insert(0) += 1;
				},
				Ok(r) => {
					let e = r.validate(&f.rounds, &f.policy, &d.leaf.owner, &d.leaf.owner_nonce).err()
						.unwrap_or_else(|| panic!("byte {} ^ {:#04x} decodes and VALIDATES", i, mask));
					validate += 1;
					*kinds.entry(e.kind()).or_insert(0) += 1;
				},
			}
		}
	}
	println!("{}-byte record: {} one-byte changes refused by the decoder, {} by validation; by kind {:?}",
		bytes.len(), decode, validate, kinds);
	for cut in [0, 1, bytes.len() / 2, bytes.len() - 1] {
		assert!(CoinRecord::from_bytes(&bytes[..cut]).is_err());
	}
	let mut long = bytes.clone();
	long.push(0);
	assert!(CoinRecord::from_bytes(&long).is_err());
}

/// One hop of `coin` (held under `prev`) to `to`, signed by `owner` and the
/// operator, each step leaving the chain's margin.
fn pay(prev: &CoinRecord, coin: &ValidCoin, owner: &elements::secp256k1_zkp::Keypair, s: &elements::secp256k1_zkp::Keypair,
	to: NewLeaf, chain: Chain) -> CoinRecord
{
	let plan = TransferPlan {
		inputs: vec![(coin.clone(), coin.value - MARGIN)],
		outputs: vec![ExplicitOutput::new(coin.asset, coin.value - 2 * MARGIN, to.policy(xonly(s), chain).script_pubkey())],
	};
	let (cp, re) = (plan.checkpoint_message(0).unwrap().digest, plan.reassignment_message(0).unwrap().digest);
	CoinRecord::Transfer(Box::new(Transfer {
		inputs: vec![TransferInput { coin: prev.clone(), checkpoint_value: coin.value - MARGIN,
			checkpoint: Pair { operator: sig(s, &cp), owner: sig(owner, &cp) },
			reassignment: Pair { operator: sig(s, &re), owner: sig(owner, &re) } }],
		outputs: plan.outputs.clone(), index: 0, leaf: to,
	}))
}

#[test]
fn every_leaf_of_the_lineage_meets_the_policy() {
	let f = fx();
	let p = &f.policy;
	let s = &f.b.s;
	let a_coin = f.hops.a_base.resolve(&f.rounds, p).unwrap();

	// A pays B, whose leaf has an exit delay of one unit (512 s); B pays D,
	// whose own leaf is within the policy. B alone could exit 512 s after
	// its leaf reached the chain, before D could answer, so D refuses the
	// coin for B's leaf.
	let short = Party::new("short delay B", RelativeTime::from_units(1).unwrap());
	let b = pay(&f.hops.a_base, &a_coin, &f.b.a, s, short.leaf, p.chain);
	let b_coin = b.resolve(&f.rounds, &WalletPolicy { min_exit_delay: RelativeTime::from_units(1).unwrap(), ..*p }).unwrap();
	let d = Party::new("short delay D", RelativeTime::from_seconds_ceil(36 * 3600).unwrap());
	let d_rec = pay(&b, &b_coin, &short.key, s, d.leaf, p.chain);
	let e = d_rec.validate(&f.rounds, p, &d.leaf.owner, &d.leaf.owner_nonce).unwrap_err();
	println!("D receives a coin through a leaf of 512 s: {} ({})", e, e.kind());
	assert!(matches!(e, TransferError::LineageExitDelay { hops: 1, delay: 1, .. }), "{}", e);
	assert_eq!(e.kind(), "policy");
	// B's leaf as the receiver's own is refused as before; a delay too long
	// anywhere in the lineage is refused the same way.
	assert!(matches!(b.validate(&f.rounds, p, &short.leaf.owner, &short.leaf.owner_nonce).unwrap_err(), TransferError::ExitDelay));
	let long = Party::new("long delay B", RelativeTime::from_units(p.max_exit_delay.units() + 1).unwrap());
	let b = pay(&f.hops.a_base, &a_coin, &f.b.a, s, long.leaf, p.chain);
	let b_coin = b.resolve(&f.rounds, &WalletPolicy { max_exit_delay: long.leaf.exit_delay, ..*p }).unwrap();
	let d_rec = pay(&b, &b_coin, &long.key, s, d.leaf, p.chain);
	assert!(matches!(d_rec.validate(&f.rounds, p, &d.leaf.owner, &d.leaf.owner_nonce).unwrap_err(),
		TransferError::LineageExitDelay { hops: 1, .. }));
}

#[test]
fn the_lineage_lists_every_leaf_and_checkpoint() {
	let f = fx();
	let d = &f.hops.d;
	let coin = f.hops.d_record.validate(&f.rounds, &f.policy, &d.leaf.owner, &d.leaf.owner_nonce).unwrap();
	let lineage = coin.lineage();
	// Hop 3 spends B's Y; hop 2 (the swap) spends B's X and C's Y; hop 1
	// spends A's leaf: four leaves, each with its checkpoint.
	let kinds: Vec<LineageKind> = lineage.iter().map(|o| o.kind).collect();
	assert_eq!(kinds.iter().filter(|k| **k == LineageKind::Leaf).count(), 4);
	assert_eq!(kinds.iter().filter(|k| **k == LineageKind::Checkpoint).count(), 4);
	assert!(lineage.iter().all(|o| o.output.script_pubkey != coin.output().script_pubkey), "the coin's own leaf is not listed");
	let a_leaf = f.hops.a_base.resolve(&f.rounds, &f.policy).unwrap().output();
	assert_eq!(lineage[0], LineageOutput { kind: LineageKind::Leaf, output: a_leaf.clone() }, "the batches first");
	for o in &lineage {
		println!("lineage {:<10} {} atoms of {}", o.kind, o.output.value, o.output.asset);
	}
	// Nothing on-chain: the coin is accepted. A's leaf on-chain: refused.
	coin.check_lineage(|_| false).unwrap();
	let e = coin.check_lineage(|spk| *spk == a_leaf.script_pubkey).unwrap_err();
	println!("A's leaf on-chain: {} ({})", e, e.kind());
	assert!(matches!(e, TransferError::OnChain { kind: LineageKind::Leaf, .. }));
	let cp = lineage.iter().find(|o| o.kind == LineageKind::Checkpoint).unwrap().output.script_pubkey.clone();
	assert!(matches!(coin.check_lineage(|spk| *spk == cp).unwrap_err(), TransferError::OnChain { kind: LineageKind::Checkpoint, .. }));
	// A batch leaf received as it is has no lineage before it.
	assert!(f.hops.a_base.resolve(&f.rounds, &f.policy).unwrap().lineage().is_empty());
}

/// A payment out of the tree: A's leaf into an `htlc-1` coin the operator
/// claims with the preimage, beside A's change. The coin's record carries the
/// terms (tag 3), round-trips, and validates for the key A gave the payment;
/// every transaction that brings it on-chain verifies, and so do the
/// operator's claim and A's refund from there. The payment failing, the
/// operator and A return the coin into a new leaf of A's by the coin's own
/// collaborative path, through a checkpoint and a reassignment, and that
/// coin is brought on-chain too. Terms whose operator delay is not shorter
/// than the owner's are refused.
#[test]
fn an_htlc_1_coin_paid_out_and_returned() {
	let f = fx();
	let s = &f.b.s;
	let chain = f.policy.chain;
	let genesis = chain.genesis_hash();
	let delay = RelativeTime::from_seconds_ceil(36 * 3600).unwrap();
	let a_coin = f.hops.a_base.resolve(&f.rounds, &f.policy).unwrap();
	let x = a_coin.asset;
	let preimage = label32("htlc payment");
	let terms = HtlcTerms {
		direction: HtlcDirection::Send, payment_hash: arca_covenant::script::sha256(&preimage),
		timeout: MedianTime::from_consensus(CREATED + 2 * 86_400).unwrap(),
		operator_delay: RelativeTime::from_units(delay.units() / 3).unwrap(),
	};
	let htlc_key = keypair("htlc payer key");
	let htlc = NewLeaf {
		owner: xonly(&htlc_key), owner_nonce: label32("htlc owner nonce"), creator_nonce: label32("htlc creator nonce"),
		exit_delay: delay, htlc: Some(terms),
	};
	let change = Party::new("htlc change", delay);
	let pay = 3_000_000;
	let outputs = vec![
		ExplicitOutput::new(x, pay, htlc.policy(xonly(s), chain).script_pubkey()),
		ExplicitOutput::new(x, a_coin.value - pay - 2 * MARGIN, change.leaf.policy(xonly(s), chain).script_pubkey()),
	];
	let plan = TransferPlan { inputs: vec![(a_coin.clone(), a_coin.value - MARGIN)], outputs };
	let pairs = sign_plan(&plan, &[&f.b.a], s);
	let rec = record_for(&plan, &[&f.hops.a_base], &pairs, 0, htlc);
	let bytes = rec.to_bytes().unwrap();
	assert_eq!(bytes[1], 3, "a coin whose leaf is htlc-1 has tag 3");
	assert_eq!(CoinRecord::from_bytes(&bytes).unwrap(), rec);
	let coin = rec.validate(&f.rounds, &f.policy, &htlc.owner, &htlc.owner_nonce).unwrap();
	assert_eq!(coin.leaf.htlc, Some(terms));
	assert_eq!(coin.leaf.template(), Template::Htlc1);
	let mut txs = vec![];
	let at = bring(&coin, &mut txs);
	for (name, u) in &txs {
		f.consensus.verify_tx(&u.prevouts, &u.tx).unwrap_or_else(|(i, e)| panic!("{}: input {}: {}", name, i, e));
		println!("{:<90} {:>4} vB, verifies", name, u.tx.vsize());
	}
	let to_s = [ExplicitOutput::new(x, pay - 1_500, op_true().script_pubkey())];
	let ks = coin.leaf.claim_tx(at, x, pay, &to_s, &FeeSource::Reserve).unwrap();
	assert_eq!(ks.tx.input[0].sequence.0, terms.operator_delay.to_sequence());
	let sg = sig(s, &ks.sighash(genesis).unwrap());
	let claim = ks.finish(HtlcTerms::claim_items(&sg, &preimage));
	f.consensus.verify_tx(&claim.prevouts, &claim.tx).unwrap();
	println!("the operator's claim with the preimage: {} vB, verifies", claim.tx.vsize());
	let ks = coin.leaf.refund_tx(at, x, pay, &to_s, &FeeSource::Reserve).unwrap();
	assert_eq!(ks.tx.lock_time.to_consensus_u32(), terms.timeout.to_consensus_u32());
	assert_eq!(ks.tx.input[0].sequence.0, delay.to_sequence());
	let sg = sig(&htlc_key, &ks.sighash(genesis).unwrap());
	let refund = ks.finish(vec![sg.as_ref().to_vec()]);
	f.consensus.verify_tx(&refund.prevouts, &refund.tx).unwrap();
	println!("the owner's refund: {} vB, verifies", refund.tx.vsize());
	assert!(coin.leaf.exit_tx(at, x, pay, &to_s, &FeeSource::Reserve).is_err(), "htlc-1 has no exit");

	// The payment failed: back into a new leaf of A's, by both.
	let back = Party::new("htlc returned", delay);
	let plan = TransferPlan {
		inputs: vec![(coin.clone(), coin.value - MARGIN)],
		outputs: vec![ExplicitOutput::new(x, coin.value - 2 * MARGIN, back.leaf.policy(xonly(s), chain).script_pubkey())],
	};
	let pairs = sign_plan(&plan, &[&htlc_key], s);
	let returned = record_for(&plan, &[&rec], &pairs, 0, back.leaf);
	let coin2 = CoinRecord::from_bytes(&returned.to_bytes().unwrap()).unwrap()
		.validate(&f.rounds, &f.policy, &back.leaf.owner, &back.leaf.owner_nonce).unwrap();
	assert_eq!((coin2.hops, coin2.value, coin2.leaf.htlc), (2, pay - 2 * MARGIN, None));
	let mut txs = vec![];
	bring(&coin2, &mut txs);
	for (name, u) in &txs {
		f.consensus.verify_tx(&u.prevouts, &u.tx).unwrap_or_else(|(i, e)| panic!("{}: input {}: {}", name, i, e));
	}
	let (name, u) = txs.iter().rev().nth(1).unwrap();
	println!("{}: {} vB; the returned coin is brought on-chain in {} transactions, each verifies", name, u.tx.vsize(), txs.len());

	// Terms the leaf cannot carry.
	let bad = NewLeaf { htlc: Some(HtlcTerms { operator_delay: delay, ..terms }), ..htlc };
	let plan = TransferPlan {
		inputs: vec![(a_coin.clone(), a_coin.value - MARGIN)],
		outputs: vec![ExplicitOutput::new(x, a_coin.value - 2 * MARGIN, bad.policy(xonly(s), chain).script_pubkey())],
	};
	let pairs = sign_plan(&plan, &[&f.b.a], s);
	let rec = record_for(&plan, &[&f.hops.a_base], &pairs, 0, bad);
	let e = rec.validate(&f.rounds, &f.policy, &bad.owner, &bad.owner_nonce).unwrap_err();
	assert!(matches!(e, TransferError::Spend(SpendError::Policy(arca_covenant::Error::HtlcDelays { .. }))), "{}", e);
	assert!(matches!(CoinRecord::from_bytes(&rec.to_bytes().unwrap()), Err(TransferError::Decode(_))));
}
