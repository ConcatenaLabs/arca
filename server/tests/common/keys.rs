//! Test keys anyone can derive, for regtest only.

use elements::hashes::{sha256, Hash};
use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

/// A test key derived from a label.
pub fn keypair(label: &str) -> Keypair {
	let secret = sha256::Hash::hash(format!("Arca server test key/{}", label).as_bytes());
	Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(secret.as_byte_array()).unwrap())
}

pub fn xonly(k: &Keypair) -> XOnlyPublicKey {
	k.x_only_public_key().0
}

/// The BIP39 test mnemonic every wallet library knows.
pub const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
