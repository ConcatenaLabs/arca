//! The minimal client: what a wallet does against the server, built on
//! `arca-covenant` directly.

use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Script, Transaction, TxOut};
use rand::RngCore;

use arca_covenant::{BoardRecord, Chain, RelativeTime, Template};

use super::keys::xonly;

/// A random 32-byte nonce: a wallet never takes its nonces from a counter.
pub fn random32() -> [u8; 32] {
	let mut b = [0u8; 32];
	rand::rngs::OsRng.fill_bytes(&mut b);
	b
}

/// The specification's exit delay, 36 hours.
pub fn exit_delay() -> RelativeTime {
	RelativeTime::from_seconds_ceil(36 * 3600).unwrap()
}

/// A board record for `owner`'s new key, with a nonce of the owner's and the
/// one the operator gave.
pub fn board_record(owner: &Keypair, operator_nonce: [u8; 32], asset: AssetId, value: u64, chain: Chain,
	operator: elements::secp256k1_zkp::XOnlyPublicKey) -> BoardRecord
{
	BoardRecord {
		template: Template::Board1,
		owner: xonly(owner),
		owner_nonce: random32(),
		operator_nonce,
		exit_delay: exit_delay(),
		asset, value, chain, operator,
	}
}

/// The board transaction paying `record` from `coin`, a coin at a bare
/// `OP_TRUE` (whose spend needs no witness), the fee in the board's own
/// asset, change to `change`.
pub fn board_tx(record: &BoardRecord, coin: &(OutPoint, TxOut), fee: u64, change: Script) -> Transaction {
	record.tx(std::slice::from_ref(coin), record.asset, fee, &change).unwrap().tx
}
