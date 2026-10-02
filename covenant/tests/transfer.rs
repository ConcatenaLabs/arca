//! The out-of-round transfer through the verifier: a chain three hops deep,
//! one of them a swap of two owners' coins in two assets, received and
//! validated from the last receiver's record alone; every transaction that
//! brings the coin on-chain built from that record and verified under the
//! block rules and the mempool's checks; and each kind of bad record refused.

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
	let other = WalletPolicy { operator: xonly(&f.b.a), ..*p };
	assert_eq!(refuse("a chain under another operator", rec, &other, &key, &nonce).kind(), "policy");

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
