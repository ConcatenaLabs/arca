//! Authentication by a challenge signed with a leaf key.
//!
//! A client asks for a challenge and proves it holds a key by signing, with
//! BIP340, the tagged hash
//!
//! ```text
//! SHA256(T ‖ T ‖ genesis_hash ‖ len(call) ‖ call ‖ challenge ‖ key ‖ SHA256(request)),   T = SHA256("Arca/auth")
//! ```
//!
//! where `call` names the request it authenticates (`mailbox_read`,
//! `leaf_data`) and `request` is what that request asks besides its proof
//! ([`mailbox_read_request`]: the cursor and page size; nothing for a
//! `leaf_data` that names neither). The tag keeps the signature apart from everything else a leaf
//! key signs (rebindable messages, unroll authorisations, releases, exit
//! claims), whose preimages never begin with `T ‖ T`; the genesis hash keeps
//! it to one chain, the call and the request to one read, the challenge to a
//! short while, the key to one signer. No shared bearer token exists.
//!
//! A challenge is stored nowhere: it is the time it was issued (4 bytes, the
//! server's clock in seconds, little-endian), 12 random bytes, and a keyed
//! check over both (the first 16 bytes of HMAC-SHA256, over
//! `"Arca/challenge" ‖ time ‖ random`, under a key drawn once and kept in the
//! database, so every server on it takes the challenges of every other, and
//! of itself before a restart). The server takes one it issued, by the check,
//! within its lifetime. So handing one out costs a hash and leaves no row, and
//! needs no budget shared by every caller; a proof used again within the
//! challenge's lifetime only repeats the very read it was signed for, since
//! the signature binds the call, the key and the request.

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;

use arca_covenant::sign::verify_digest;
use arca_covenant::Chain;

/// The tag of the signed message.
pub const AUTH_TAG: &[u8] = b"Arca/auth";

/// What a `mailbox_read` asks besides its proof, as the proof binds it: the
/// cursor (eight bytes) and the page size (four), little-endian. A paged
/// `leaf_data` asks the same of its cursor and page size; one that names
/// neither asks nothing more, and its request is empty.
pub fn mailbox_read_request(after: u64, limit: u32) -> Vec<u8> {
	let mut b = after.to_le_bytes().to_vec();
	b.extend(limit.to_le_bytes());
	b
}

/// The digest a client signs to authenticate `call` with `key`, asking
/// `request` ([`mailbox_read_request`]).
pub fn auth_digest(chain: &Chain, call: &str, challenge: &[u8; 32], key: &XOnlyPublicKey, request: &[u8]) -> [u8; 32] {
	let tag = sha256::Hash::hash(AUTH_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&chain.genesis_bytes());
	e.input(&[call.len() as u8]);
	e.input(call.as_bytes());
	e.input(challenge);
	e.input(&key.serialize());
	e.input(sha256::Hash::hash(request).as_byte_array());
	sha256::Hash::from_engine(e).to_byte_array()
}

/// The tag of a leaf's binding to its owner's mailbox key.
pub const MAILBOX_BINDING_TAG: &[u8] = b"Arca/mailbox-of";

/// What a leaf's owner key signs to have the leaf re-served to `mailbox`, its
/// wallet's mailbox key, besides itself (`leaf_data`):
/// `SHA256(T ‖ T ‖ genesis_hash ‖ S ‖ owner ‖ mailbox)`,
/// `T = SHA256("Arca/mailbox-of")`. The tag keeps it apart from everything
/// else a leaf key signs; the genesis hash and `S` keep it to one chain and
/// one operator. It authorises one thing: that the server serves the leaf's
/// record, and how it was given up, to whoever proves `mailbox`.
pub fn mailbox_binding_digest(chain: &Chain, operator: &XOnlyPublicKey, owner: &XOnlyPublicKey, mailbox: &XOnlyPublicKey) -> [u8; 32] {
	let tag = sha256::Hash::hash(MAILBOX_BINDING_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&chain.genesis_bytes());
	e.input(&operator.serialize());
	e.input(&owner.serialize());
	e.input(&mailbox.serialize());
	sha256::Hash::from_engine(e).to_byte_array()
}

/// Whether `proof` is `owner`'s signature over its leaf's binding to
/// `mailbox` ([`mailbox_binding_digest`]).
pub fn verify_binding(chain: &Chain, operator: &XOnlyPublicKey, owner: &XOnlyPublicKey, mailbox: &XOnlyPublicKey, proof: &Signature) -> bool {
	verify_digest(proof, &mailbox_binding_digest(chain, operator, owner, mailbox), owner)
}

/// Whether `sig` authenticates `call` with `key` for `challenge`, asking
/// `request`.
pub fn verify(chain: &Chain, call: &str, challenge: &[u8; 32], key: &XOnlyPublicKey, request: &[u8], sig: &Signature) -> bool {
	verify_digest(sig, &auth_digest(chain, call, challenge, key, request), key)
}

/// The tag of a challenge's keyed check.
pub const CHALLENGE_TAG: &[u8] = b"Arca/challenge";

/// How far ahead of the server's clock a challenge's time may lie: none was
/// issued later than now, but the clock may have stepped back a little.
pub const CHALLENGE_SKEW: u64 = 5;

fn challenge_check(key: &[u8; 32], time: &[u8], random: &[u8]) -> [u8; 16] {
	use elements::hashes::hmac::{Hmac, HmacEngine};
	let mut e = HmacEngine::<sha256::Hash>::new(key);
	e.input(CHALLENGE_TAG);
	e.input(time);
	e.input(random);
	let mac = Hmac::<sha256::Hash>::from_engine(e).to_byte_array();
	let mut out = [0u8; 16];
	out.copy_from_slice(&mac[..16]);
	out
}

/// A challenge issued at `now` (seconds) under `key`, with `random` bytes.
pub fn issue_challenge(key: &[u8; 32], now: u64, random: [u8; 12]) -> [u8; 32] {
	let mut c = [0u8; 32];
	c[..4].copy_from_slice(&(now.min(u32::MAX as u64) as u32).to_le_bytes());
	c[4..16].copy_from_slice(&random);
	let check = challenge_check(key, &c[..4], &c[4..16]);
	c[16..].copy_from_slice(&check);
	c
}

/// Why a challenge was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChallengeError {
	#[error("the challenge was not issued by this server")]
	Unknown,
	#[error("the challenge has expired")]
	Expired,
}

/// Whether `challenge` was issued under `key` at most `ttl` seconds before
/// `now`.
pub fn check_challenge(key: &[u8; 32], challenge: &[u8; 32], now: u64, ttl: u64) -> Result<(), ChallengeError> {
	let check = challenge_check(key, &challenge[..4], &challenge[4..16]);
	// Compared whole, whatever byte differs first.
	if check.iter().zip(&challenge[16..]).fold(0u8, |d, (a, b)| d | (a ^ b)) != 0 {
		return Err(ChallengeError::Unknown);
	}
	let issued = u64::from(u32::from_le_bytes(challenge[..4].try_into().expect("4 bytes")));
	if issued > now + CHALLENGE_SKEW || now.saturating_sub(issued) > ttl {
		return Err(ChallengeError::Expired);
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_challenge_is_checked_not_stored() {
		let (key, other) = ([7u8; 32], [8u8; 32]);
		let c = issue_challenge(&key, 1_800_000_000, [1; 12]);
		assert_eq!(check_challenge(&key, &c, 1_800_000_000, 120), Ok(()));
		assert_eq!(check_challenge(&key, &c, 1_800_000_120, 120), Ok(()), "within its lifetime, again");
		assert_eq!(check_challenge(&key, &c, 1_800_000_121, 120), Err(ChallengeError::Expired));
		assert_eq!(check_challenge(&key, &c, 1_799_999_000, 120), Err(ChallengeError::Expired), "issued in the future");
		assert_eq!(check_challenge(&other, &c, 1_800_000_000, 120), Err(ChallengeError::Unknown), "another server's");
		for i in 0..32 {
			let mut bad = c;
			bad[i] ^= 1;
			assert!(check_challenge(&key, &bad, 1_800_000_000, 120).is_err(), "byte {} changed", i);
		}
		assert_ne!(issue_challenge(&key, 1_800_000_000, [2; 12]), c, "the random part makes each one its own");
	}
}

/// The tag of a request to receive over Lightning.
pub const LIGHTNING_RECEIVE_TAG: &[u8] = b"Arca/lightning-receive";

/// What the key a wallet wants its received leaf under signs to ask for it
/// (`lightning_receive`): `SHA256(T ‖ T ‖ genesis_hash ‖ S ‖ asset ‖ amount
/// ‖ payment_hash ‖ owner ‖ owner_nonce ‖ exit_delay_units)`, amount eight
/// bytes and the exit delay two, little-endian, `T =
/// SHA256("Arca/lightning-receive")`. It proves the leaf's key is the
/// requester's, so no one asks for a leaf under a key that is not theirs.
#[allow(clippy::too_many_arguments)]
pub fn lightning_receive_digest(chain: &Chain, operator: &XOnlyPublicKey, asset: &elements::AssetId, amount: u64, payment_hash: &[u8; 32],
	owner: &XOnlyPublicKey, owner_nonce: &[u8; 32], exit_delay_units: u16) -> [u8; 32]
{
	let tag = sha256::Hash::hash(LIGHTNING_RECEIVE_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&chain.genesis_bytes());
	e.input(&operator.serialize());
	e.input(&asset.into_inner().to_byte_array());
	e.input(&amount.to_le_bytes());
	e.input(payment_hash);
	e.input(&owner.serialize());
	e.input(owner_nonce);
	e.input(&exit_delay_units.to_le_bytes());
	sha256::Hash::from_engine(e).to_byte_array()
}
