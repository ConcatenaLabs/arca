//! Authentication by a challenge signed with a leaf key.
//!
//! A client asks for a challenge (32 random bytes the server records, usable
//! once, for a short while) and proves it holds a key by signing, with BIP340,
//! the tagged hash
//!
//! ```text
//! SHA256(T ‖ T ‖ genesis_hash ‖ len(call) ‖ call ‖ challenge ‖ key),   T = SHA256("Arca/auth")
//! ```
//!
//! where `call` names the request it authenticates (`mailbox_read`,
//! `leaf_data`). The tag keeps the signature apart from everything else a leaf
//! key signs (rebindable messages, unroll authorisations, releases, exit
//! claims), whose preimages never begin with `T ‖ T`; the genesis hash keeps
//! it to one chain, the call to one request, the challenge to one use, the key
//! to one signer. No shared bearer token exists.

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;

use arca_covenant::sign::verify_digest;
use arca_covenant::Chain;

/// The tag of the signed message.
pub const AUTH_TAG: &[u8] = b"Arca/auth";

/// The digest a client signs to authenticate `call` with `key`.
pub fn auth_digest(chain: &Chain, call: &str, challenge: &[u8; 32], key: &XOnlyPublicKey) -> [u8; 32] {
	let tag = sha256::Hash::hash(AUTH_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&chain.genesis_bytes());
	e.input(&[call.len() as u8]);
	e.input(call.as_bytes());
	e.input(challenge);
	e.input(&key.serialize());
	sha256::Hash::from_engine(e).to_byte_array()
}

/// Whether `sig` authenticates `call` with `key` for `challenge`.
pub fn verify(chain: &Chain, call: &str, challenge: &[u8; 32], key: &XOnlyPublicKey, sig: &Signature) -> bool {
	verify_digest(sig, &auth_digest(chain, call, challenge, key), key)
}
