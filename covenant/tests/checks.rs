//! The five client checks against the attacks consensus accepts.
//!
//! Each round below is what an operator could broadcast and get confirmed:
//! the regtest prototype confirmed the first four attacks and swept a batch
//! early with each. The wallet's check must refuse every one, naming the check
//! that catches it, and accept the honest round.

mod common;

use elements::confidential::{Asset, AssetBlindingFactor, Value, ValueBlindingFactor};
use elements::secp256k1_zkp::{Generator, Secp256k1, Tag, Tweak, ZERO_TWEAK};
use elements::{AssetId, AssetIssuance, ContractHash, OutPoint, Transaction, TxIn, TxOut};
use elements::hashes::Hash;

use arca_covenant::*;
use common::*;

struct Round {
	issuing: OutPoint,
	contract: [u8; 32],
	token: AssetId,
}

impl Round {
	fn new() -> Round {
		let issuing = OutPoint::new(elements::Txid::from_byte_array(label32("operator coin")), 1);
		let contract = label32("contract");
		let token = AssetId::new_issuance(issuing, ContractHash::from_byte_array(contract));
		Round { issuing, contract, token }
	}

	fn issuance(&self, amount: Value, keys: Value) -> TxIn {
		TxIn {
			previous_output: self.issuing,
			asset_issuance: AssetIssuance {
				asset_blinding_nonce: ZERO_TWEAK,
				asset_entropy: self.contract,
				amount,
				inflation_keys: keys,
				denomination: 0,
			},
			..Default::default()
		}
	}

	fn tx(&self, input: Vec<TxIn>, output: Vec<TxOut>) -> Transaction {
		Transaction { version: 2, lock_time: elements::LockTime::ZERO, input, output }
	}
}

fn schedule(token: AssetId, expiries: &[u32]) -> ClockSchedule {
	let s = xonly(&keypair("S"));
	let w = RelativeTime::from_seconds_ceil(36 * 3600).unwrap();
	let e = expiries.iter().map(|t| MedianTime::from_consensus(*t).unwrap()).collect();
	ClockSchedule::new_unchecked(token, s, w, e).unwrap()
}

#[test]
fn honest_round_passes_and_each_attack_names_its_check() {
	let r = Round::new();
	let x = asset("X");
	let sched = schedule(r.token, &[1_793_419_200, 1_795_838_400, 1_798_257_600]);
	let clock0 = sched.clock0_script_pubkey();
	let r_spk = sched.r().script_pubkey();
	let batch = explicit(x, 50_000_000, op_true().script_pubkey());
	let t_at = |spk: &elements::Script, n: u64| explicit(r.token, n, spk.clone());
	let sweeps = vec![sched.sweep(false, false), sched.sweep(true, false)];
	let one = Value::Explicit(1);

	// The honest round: one explicit atom, no token, into clock 0.
	let honest = r.tx(vec![r.issuance(one, Value::Null)], vec![batch.clone(), t_at(&clock0, 1), fee(x, 1_000)]);
	assert_eq!(check_round(&honest, &sched, &sweeps[0], &sweeps[1..]), Ok(()));
	// Several batches in one round: one issuing input each; this batch's token is found.
	let other = OutPoint::new(elements::Txid::from_byte_array(label32("second operator coin")), 0);
	let mut second = r.issuance(one, Value::Null);
	second.previous_output = other;
	let other_t = AssetId::new_issuance(other, ContractHash::from_byte_array(r.contract));
	let two_batches = r.tx(vec![second, r.issuance(one, Value::Null)],
		vec![batch.clone(), t_at(&clock0, 1), explicit(other_t, 1, op_true().script_pubkey()), fee(x, 1_000)]);
	assert_eq!(check_round(&two_batches, &sched, &sweeps[0], &sweeps[1..]), Ok(()));

	let check = |tx: &Transaction, s: &ClockSchedule, sw: &[Sweep]| check_round(tx, s, &sw[0], &sw[1..]).unwrap_err();

	// K1: two atoms, the second straight to R.
	let k1 = r.tx(vec![r.issuance(Value::Explicit(2), Value::Null)], vec![batch.clone(), t_at(&clock0, 1), t_at(&r_spk, 1), fee(x, 1_000)]);
	let e = check(&k1, &sched, &sweeps);
	assert_eq!((e.check(), &e), (1, &RoundCheckFailure::NotOneAtom(2)));
	// No input issues the token at all.
	let mut none = honest.clone();
	none.input[0].previous_output.vout = 9;
	assert_eq!(check(&none, &sched, &sweeps), RoundCheckFailure::NotIssued);

	// A confidential issued amount.
	let secp = Secp256k1::new();
	let blinded_amount = Value::new_confidential_from_assetid(&secp, 1, r.token,
		ValueBlindingFactor::from_slice(&[3; 32]).unwrap(), AssetBlindingFactor::from_slice(&[4; 32]).unwrap());
	let k = r.tx(vec![r.issuance(blinded_amount, Value::Null)], vec![batch.clone(), t_at(&clock0, 1), fee(x, 1_000)]);
	assert_eq!(check(&k, &sched, &sweeps).check(), 2);

	// K2: a reissuance token, which could reissue T to R.
	let k2 = r.tx(vec![r.issuance(one, Value::Explicit(1))], vec![batch.clone(), t_at(&clock0, 1), fee(x, 1_000)]);
	assert_eq!(check(&k2, &sched, &sweeps), RoundCheckFailure::ReissuanceToken);
	// An input reissuing T.
	let mut reissue = r.issuance(one, Value::Null);
	reissue.previous_output.vout = 5;
	reissue.asset_issuance.asset_blinding_nonce = Tweak::from_inner([1; 32]).unwrap();
	reissue.asset_issuance.asset_entropy =
		AssetId::generate_asset_entropy(r.issuing, ContractHash::from_byte_array(r.contract)).to_byte_array();
	let k = r.tx(vec![r.issuance(one, Value::Null), reissue], vec![batch.clone(), t_at(&clock0, 1), fee(x, 1_000)]);
	assert_eq!(check(&k, &sched, &sweeps), RoundCheckFailure::Reissued(1));

	// K3: the only atom straight to R.
	let k3 = r.tx(vec![r.issuance(one, Value::Null)], vec![batch.clone(), t_at(&r_spk, 1), fee(x, 1_000)]);
	assert_eq!(check(&k3, &sched, &sweeps), RoundCheckFailure::TokenAtR);
	// The atom nowhere, or a blinded output that could hold it.
	let k = r.tx(vec![r.issuance(one, Value::Null)], vec![batch.clone(), fee(x, 1_000)]);
	assert_eq!(check(&k, &sched, &sweeps), RoundCheckFailure::TokenOutputs(0));
	let mut blinded = t_at(&clock0, 1);
	blinded.asset = Asset::Confidential(Generator::new_unblinded(&secp, Tag::from(label32("tag"))));
	let k = r.tx(vec![r.issuance(one, Value::Null)], vec![batch.clone(), t_at(&clock0, 1), blinded, fee(x, 1_000)]);
	assert_eq!(check(&k, &sched, &sweeps), RoundCheckFailure::BlindedOutput(2));

	// K4: a chain whose second step expires before the first. Published as it
	// is, the schedule runs backwards; published as an honest one, it does not
	// rebuild the clock the round pays.
	let backwards = schedule(r.token, &[1_793_419_200, 1_790_000_000]);
	let k4 = r.tx(vec![r.issuance(one, Value::Null)], vec![batch.clone(), t_at(&backwards.clock0_script_pubkey(), 1), fee(x, 1_000)]);
	assert_eq!(check(&k4, &backwards, &sweeps), RoundCheckFailure::ScheduleBackwards(1));
	let advertised = schedule(r.token, &[1_793_419_200, 1_795_838_400]);
	let e = check(&k4, &advertised, &sweeps);
	assert_eq!((e.check(), e), (5, RoundCheckFailure::NotClockZero));

	// The sweep paths above the leaf must name this schedule's T, S, R and W.
	let mut bad = sched.sweep(true, false);
	bad.r_program = [9; 32];
	assert_eq!(check(&honest, &sched, &[sweeps[0], bad]), RoundCheckFailure::SweepMismatch(1));
	let mut bad = sched.sweep(true, false);
	bad.notice = Some(RelativeTime::from_units(1).unwrap());
	assert_eq!(check(&honest, &sched, &[bad]), RoundCheckFailure::SweepMismatch(0));
	let mut bad = sched.sweep(false, false);
	bad.operator = xonly(&keypair("stranger"));
	assert_eq!(check(&honest, &sched, &[bad]), RoundCheckFailure::SweepMismatch(0));

	// Below the batch output every sweep waits the notice: one without it
	// (an inner node, a lowest node, an entry) is refused at its position,
	// while the batch output's may have none.
	let none = sched.sweep(false, false);
	let with = sched.sweep(true, false);
	assert_eq!(check_round(&honest, &sched, &none, &[with, with, with]), Ok(()));
	assert_eq!(check_round(&honest, &sched, &with, &[with]), Ok(()));
	for i in 0..3 {
		let mut below = [with, with, with];
		below[i] = none;
		let e = check(&honest, &sched, &[&[none][..], &below[..]].concat());
		assert_eq!((e.check(), &e), (5, &RoundCheckFailure::NoNotice(i + 1)), "{}", e);
	}
	assert_eq!(check(&honest, &sched, &[none, none, none, none]), RoundCheckFailure::NoNotice(1));
}
