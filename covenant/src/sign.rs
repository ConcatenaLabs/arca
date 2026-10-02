//! Signature hashes and signing.
//!
//! Two kinds of signature appear in Arca's scripts. A path that ends in
//! `<key> OP_CHECKSIG` (an exit, a sweep, a roll or release, a forfeit claim
//! or refund, a reclaim, a plain HTLC refund) is signed over the Elements
//! taproot signature hash of the spending transaction, which commits to the
//! chain's genesis hash, every spent output and the leaf, with
//! `SIGHASH_DEFAULT`. A path that uses `OP_CHECKSIGFROMSTACK` (the rebindable
//! paths, the unroll authorisation, the release) is signed over the 32-byte
//! digest of a [`crate::CsfsMessage`].
//!
//! Both are BIP340 signatures. `aux` is the auxiliary randomness BIP340 mixes
//! into the nonce: give fresh random bytes when signing for real; the tests and
//! the golden vectors use 32 zero bytes, which keeps signatures reproducible.

use elements::hashes::Hash;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::{Keypair, Message, XOnlyPublicKey};
use elements::sighash::{Prevouts, SighashCache};
use elements::{BlockHash, SchnorrSighashType, Script, Transaction, TxOut};

use crate::taptree::{leaf_hash, secp};
use crate::Error;

/// The Elements taproot signature hash, `SIGHASH_DEFAULT`, of input
/// `input_index` of `tx` spending by the tapscript leaf `leaf`. `prevouts`
/// are the outputs every input spends, in input order.
pub fn script_spend_sighash(
	tx: &Transaction,
	input_index: usize,
	prevouts: &[TxOut],
	leaf: &Script,
	genesis_hash: BlockHash,
) -> Result<[u8; 32], Error> {
	if input_index >= tx.input.len() {
		return Err(Error::InputIndex(input_index));
	}
	let h = SighashCache::new(tx)
		.taproot_script_spend_signature_hash(
			input_index, &Prevouts::All(prevouts), leaf_hash(leaf), SchnorrSighashType::Default, genesis_hash,
		)
		.map_err(|e| Error::Sighash(e.to_string()))?;
	Ok(h.to_byte_array())
}

/// A BIP340 signature over `digest`.
pub fn sign_digest(keypair: &Keypair, digest: &[u8; 32], aux: &[u8; 32]) -> Signature {
	secp().sign_schnorr_with_aux_rand(&Message::from_digest(*digest), keypair, aux)
}

/// Whether `sig` is `key`'s BIP340 signature over `digest`.
pub fn verify_digest(sig: &Signature, digest: &[u8; 32], key: &XOnlyPublicKey) -> bool {
	secp().verify_schnorr(sig, &Message::from_digest(*digest), key).is_ok()
}

/// Signs input `input_index` of `tx` by the `<key> OP_CHECKSIG` leaf `leaf`.
pub fn sign_script_spend(
	keypair: &Keypair,
	tx: &Transaction,
	input_index: usize,
	prevouts: &[TxOut],
	leaf: &Script,
	genesis_hash: BlockHash,
	aux: &[u8; 32],
) -> Result<Signature, Error> {
	let digest = script_spend_sighash(tx, input_index, prevouts, leaf, genesis_hash)?;
	Ok(sign_digest(keypair, &digest, aux))
}
