//! Issuer-operated batches: the burn they end in, and the supply a
//! transaction moves.
//!
//! A batch run by its asset's own issuer is funded by reissuing the asset in
//! the round that makes it ([`crate::limiter`]), and every sweep path of it is
//! burn-only ([`crate::Sweep::burn`]): its value can only be destroyed, by a
//! bare `OP_RETURN` of the input's whole amount at the input's index. The
//! batch is marked by that flag alone, which the leaf record carries and every
//! sweep script above the leaf is built from, so a wallet rebuilding the
//! scripts reads the mark from the chain.
//!
//! A wallet refuses a leaf of a batch that a reissuance of the batch's asset
//! in its own round funds, unless every sweep path above the leaf is
//! burn-only (check 5, [`crate::checks::check_reissue`]): units minted for a
//! refresh that a sweep could hand to the operator are inflation.
//!
//! The supply of an asset is read from the chain: what each transaction
//! issues of it ([`issued`]) and burns of it ([`burned`]).

use elements::confidential::Value;
use elements::opcodes::all::OP_RETURN;
use elements::secp256k1_zkp::ZERO_TWEAK;
use elements::{AssetId, Script, Transaction};

use crate::script::ExplicitOutput;

/// The script of a burn: a bare `OP_RETURN`, which a burn-only sweep pins
/// and which never enters the UTXO set.
pub fn burn_script() -> Script {
	Script::from(vec![OP_RETURN.into_u8()])
}

/// A burn of `value` of `asset`: an explicit output to a bare `OP_RETURN`.
pub fn burn(asset: AssetId, value: u64) -> ExplicitOutput {
	ExplicitOutput::new(asset, value, burn_script())
}

/// Whether `spk` is a burn: a bare `OP_RETURN`.
pub fn is_burn(spk: &Script) -> bool {
	spk.as_bytes() == [OP_RETURN.into_u8()]
}

/// What `tx` burns of `asset`: the explicit value of its outputs of `asset`
/// to a bare `OP_RETURN`.
pub fn burned(tx: &Transaction, asset: AssetId) -> u64 {
	tx.output.iter()
		.filter(|o| o.asset.explicit() == Some(asset) && is_burn(&o.script_pubkey))
		.filter_map(|o| o.value.explicit())
		.fold(0u64, |a, v| a.saturating_add(v))
}

/// What `tx` issues of `asset`, new issuance and reissuance alike: the
/// explicit amounts of its inputs' issuances of `asset`. An amount that is
/// not explicit counts as `None`: a confidential issuance hides its amount.
pub fn issued(tx: &Transaction, asset: AssetId) -> Option<u64> {
	let mut total = 0u64;
	for input in tx.input.iter().filter(|i| i.has_issuance() && i.issuance_ids().0 == asset) {
		match input.asset_issuance.amount {
			Value::Explicit(v) => total = total.saturating_add(v),
			Value::Null => {},
			Value::Confidential(_) => return None,
		}
	}
	Some(total)
}

/// The inputs of `tx` that reissue `asset`: an issuance of it whose blinding
/// nonce is not zero, which marks a reissuance against its token.
pub fn reissuing_inputs(tx: &Transaction, asset: AssetId) -> Vec<usize> {
	tx.input.iter().enumerate()
		.filter(|(_, i)| i.has_issuance() && i.asset_issuance.asset_blinding_nonce != ZERO_TWEAK && i.issuance_ids().0 == asset)
		.map(|(k, _)| k)
		.collect()
}
