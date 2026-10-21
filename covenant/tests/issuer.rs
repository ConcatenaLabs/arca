//! An issuer-operated asset's burns and supply, read from transactions; and a
//! fee coin that burns the margin it leaves (`FeeSource::Burning`).

mod common;

use elements::confidential::Value;
use elements::hashes::Hash;
use elements::{AssetIssuance, OutPoint, Script, Transaction, TxIn, Txid};

use arca_covenant::issuer::{burn, burn_script, burned, is_burn, issued, reissuing_inputs};
use arca_covenant::{limiter, ExplicitOutput, FeeSource, OffboardPolicy, RelativeTime};
use common::*;

fn op(label: &str) -> OutPoint {
	OutPoint::new(Txid::from_byte_array(label32(label)), 0)
}

#[test]
fn a_fee_coin_that_burns_pays_the_fee_and_burns_the_margin() {
	let x = asset("X");
	let y = asset("Y");
	let s = xonly(&keypair("S"));
	let destination = ExplicitOutput::new(x, 90_000, op_true().script_pubkey());
	let policy = OffboardPolicy { unlock_hash: [1; 32], destination: destination.clone(), operator: s,
		reclaim_delay: RelativeTime::from_units(300).unwrap() };
	let change = Script::from(vec![0x51]);
	let coin = explicit(y, 10_000, op_true().script_pubkey());
	let u = policy.unlock_tx(op("offboard"), 90_700, &[0; 32],
		&FeeSource::Burning { outpoint: op("fee coin"), coin: coin.clone(), fee: 400, change: change.clone() }).unwrap();
	let outs: Vec<(Option<elements::AssetId>, Option<u64>, Script)> =
		u.tx.output.iter().map(|o| (o.asset.explicit(), o.value.explicit(), o.script_pubkey.clone())).collect();
	assert_eq!(outs, vec![
		(Some(x), Some(90_000), destination.script_pubkey.clone()),
		(Some(x), Some(700), burn_script()),
		(Some(y), Some(9_600), change.clone()),
		(Some(y), Some(400), Script::new()),
	]);
	assert_eq!(burned(&u.tx, x), 700);
	assert_eq!(burned(&u.tx, y), 0);
	// The same with an ordinary fee coin: the margin goes to the change.
	let c = policy.unlock_tx(op("offboard"), 90_700, &[0; 32],
		&FeeSource::Coin { outpoint: op("fee coin"), coin, fee: 400, change: change.clone() }).unwrap();
	assert_eq!(c.tx.output[1].script_pubkey, change);
	assert_eq!(burned(&c.tx, x), 0);
}

#[test]
fn what_a_transaction_issues_and_burns_of_an_asset() {
	let entropy = label32("Z");
	let z = limiter::asset_of_entropy(entropy);
	let new_issue = TxIn {
		previous_output: op("issuer"),
		asset_issuance: AssetIssuance {
			asset_blinding_nonce: elements::secp256k1_zkp::ZERO_TWEAK, asset_entropy: [0; 32], amount: Value::Explicit(1),
			inflation_keys: Value::Null, denomination: 8,
		},
		..Default::default()
	};
	let t = new_issue.issuance_ids().0;
	let reissue = TxIn { previous_output: op("token"), asset_issuance: limiter::reissuance(entropy, 5_000), ..Default::default() };
	let tx = Transaction {
		version: 2, lock_time: elements::LockTime::ZERO, input: vec![reissue, new_issue],
		output: vec![burn(z, 1_200).txout(), explicit(z, 3_800, op_true().script_pubkey()), burn(t, 1).txout(),
			explicit(z, 9, Script::from(vec![0x6a, 0x01, 0x00]))],
	};
	assert_eq!(issued(&tx, z), Some(5_000));
	assert_eq!(issued(&tx, t), Some(1));
	assert_eq!(reissuing_inputs(&tx, z), vec![0]);
	assert!(reissuing_inputs(&tx, t).is_empty(), "a new issuance is no reissuance");
	// Only a bare OP_RETURN is a burn: one carrying data is not counted.
	assert_eq!(burned(&tx, z), 1_200);
	assert_eq!(burned(&tx, t), 1);
	assert!(is_burn(&burn_script()) && !is_burn(&Script::from(vec![0x6a, 0x01, 0x00])));
}
