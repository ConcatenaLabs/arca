//! The wallet's keys, all from one BIP39 mnemonic, derived as the Sequentia
//! Wallet Kit derives them, so the same mnemonic serves the kit and this
//! wallet alike.
//!
//! - **Leaf keys**, one per leaf instance: `m/6'/account'/c1'/c2'/c3'/c4'`,
//!   where `c1` to `c4` are the first four 31-bit chunks, most significant bit
//!   first, of `SHA256("Arca/key" ‖ owner_nonce)`. The owner nonce is 32
//!   random bytes the wallet draws for every leaf it asks for, and goes into
//!   the leaf's salt and its record, so a record names its own key and a
//!   restore needs no index scan. A key never comes from a counter, which a
//!   restore would repeat.
//! - **The mailbox key**: the key the kit's own leaf derivation gives for the
//!   fixed nonce [`MAILBOX_NONCE`], `SHA256("Arca/mailbox")`, at
//!   `m/6'/account'/c1'/c2'/c3'/c4'`. Any wallet on the kit derives it from
//!   the mnemonic with the kit's `leaf_key`, as it derives a leaf's key from
//!   its record. The wallet names it in every receive request and reads its
//!   mailbox with it, so one challenge collects every coin paid to the
//!   wallet. It signs only the tagged authentication digest of a call, never
//!   a leaf's message, and no coin is accepted for its nonce, which the
//!   wallet never draws.
//! - **On-chain keys**, `m/84'/coin'/0'/<chain>/<index>` (`coin` is 0 on the
//!   main chain and 1 elsewhere), each an unblinded P2WPKH script: the same
//!   key is a Bitcoin address and a Sequentia address, as on every Sequentia
//!   wallet.

use elements::bitcoin::bip32::{ChildNumber, DerivationPath};
use elements::hashes::{hash160, sha256, Hash};
use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use elements::Script;
use lwk_signer::SwSigner;

use super::Error;

/// The kit's BIP32 purpose for Arca leaf keys, hardened.
pub const ARK_PURPOSE: u32 = 6;

/// The tag that begins the hash a leaf key's path is read from.
pub const KEY_TAG: &[u8] = b"Arca/key";

/// The tag whose hash is the mailbox key's nonce.
pub const MAILBOX_TAG: &[u8] = b"Arca/mailbox";

/// The nonce of the mailbox key: `SHA256("Arca/mailbox")`, the same for
/// every wallet, so the key follows from the mnemonic and the account alone.
pub fn mailbox_nonce() -> [u8; 32] {
	sha256::Hash::hash(MAILBOX_TAG).to_byte_array()
}

/// The on-chain chains: scripts handed out to be paid, and change.
pub const RECEIVE: u32 = 0;
pub const CHANGE: u32 = 1;

/// The four 31-bit chunks of `SHA256("Arca/key" ‖ owner_nonce)` that name a
/// leaf key's path, most significant bit first.
pub fn path_chunks(owner_nonce: &[u8; 32]) -> [u32; 4] {
	let mut data = KEY_TAG.to_vec();
	data.extend_from_slice(owner_nonce);
	let hash = sha256::Hash::hash(&data).to_byte_array();
	let mut first = [0u8; 16];
	first.copy_from_slice(&hash[..16]);
	let x = u128::from_be_bytes(first);
	let chunk = |shift: u32| ((x >> shift) & 0x7fff_ffff) as u32;
	[chunk(97), chunk(66), chunk(35), chunk(4)]
}

fn hardened(i: u32) -> Result<ChildNumber, Error> {
	ChildNumber::from_hardened_idx(i).map_err(|_| Error::Keys(format!("{} is not a hardened index", i)))
}

/// `m/6'/account'/c1'/c2'/c3'/c4'`, the path of the key for the leaf whose
/// owner nonce is `owner_nonce`.
pub fn leaf_key_path(account: u32, owner_nonce: &[u8; 32]) -> Result<DerivationPath, Error> {
	let mut path = vec![hardened(ARK_PURPOSE)?, hardened(account)?];
	for c in path_chunks(owner_nonce) {
		path.push(hardened(c)?);
	}
	Ok(DerivationPath::from(path))
}

/// The wallet's keys.
pub struct Keys {
	signer: SwSigner,
	account: u32,
	coin_type: u32,
	secp: Secp256k1<elements::secp256k1_zkp::All>,
}

impl Keys {
	/// The keys of `mnemonic`, under leaf account `account`, with on-chain
	/// coin type `coin_type` (0 on the main chain, 1 elsewhere).
	pub fn new(mnemonic: &str, account: u32, coin_type: u32) -> Result<Keys, Error> {
		let signer = SwSigner::new(mnemonic, false).map_err(|e| Error::Keys(e.to_string()))?;
		Ok(Keys { signer, account, coin_type, secp: Secp256k1::new() })
	}

	fn keypair_at(&self, path: &DerivationPath) -> Result<Keypair, Error> {
		let xprv = self.signer.derive_xprv(path).map_err(|e| Error::Keys(e.to_string()))?;
		let secret = SecretKey::from_slice(&xprv.private_key.secret_bytes()).map_err(|e| Error::Keys(e.to_string()))?;
		Ok(Keypair::from_secret_key(&self.secp, &secret))
	}

	/// The key of the leaf whose owner nonce is `owner_nonce`.
	pub fn leaf(&self, owner_nonce: &[u8; 32]) -> Result<Keypair, Error> {
		self.keypair_at(&leaf_key_path(self.account, owner_nonce)?)
	}

	/// The x-only key of the leaf whose owner nonce is `owner_nonce`.
	pub fn leaf_xonly(&self, owner_nonce: &[u8; 32]) -> Result<XOnlyPublicKey, Error> {
		Ok(self.leaf(owner_nonce)?.x_only_public_key().0)
	}

	/// The mailbox key: the leaf key of [`mailbox_nonce`].
	pub fn mailbox(&self) -> Result<Keypair, Error> {
		self.leaf(&mailbox_nonce())
	}

	/// The on-chain key at `m/84'/coin'/0'/chain/index`.
	pub fn onchain(&self, chain: u32, index: u32) -> Result<Keypair, Error> {
		let normal = |i: u32| ChildNumber::from_normal_idx(i).map_err(|_| Error::Keys(format!("{} is not a normal index", i)));
		let path = DerivationPath::from(vec![hardened(84)?, hardened(self.coin_type)?, hardened(0)?, normal(chain)?, normal(index)?]);
		self.keypair_at(&path)
	}

	/// The unblinded P2WPKH script of the on-chain key at `chain/index`.
	pub fn onchain_script(&self, chain: u32, index: u32) -> Result<Script, Error> {
		Ok(p2wpkh(&self.onchain(chain, index)?))
	}
}

/// The compressed public key of `key`.
pub fn compressed(key: &Keypair) -> [u8; 33] {
	key.public_key().serialize()
}

/// The P2WPKH script of `key`.
pub fn p2wpkh(key: &Keypair) -> Script {
	let h = hash160::Hash::hash(&compressed(key));
	Script::new_v0_wpkh(&elements::WPubkeyHash::from_byte_array(h.to_byte_array()))
}

#[cfg(test)]
mod tests {
	use super::*;

	const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

	#[test]
	fn the_path_follows_the_nonce_as_the_kit_derives_it() {
		// The kit's own vectors (lwk_wollet::ark::keys, `the_path_follows_the_nonce`).
		let nonce: [u8; 32] = core::array::from_fn(|i| i as u8);
		assert_eq!(path_chunks(&nonce), [330116911, 809309685, 1623618847, 382661522]);
		assert_eq!(leaf_key_path(0, &nonce).unwrap().to_string(), "6'/0'/330116911'/809309685'/1623618847'/382661522'");
		assert_eq!(path_chunks(&[0xff; 32]), [420927215, 1717579787, 356525174, 1629183434]);
		assert_eq!(leaf_key_path(7, &[0xff; 32]).unwrap().to_string(), "6'/7'/420927215'/1717579787'/356525174'/1629183434'");
		assert!(leaf_key_path(1 << 31, &nonce).is_err());
	}

	#[test]
	fn the_leaf_key_is_the_kits() {
		use lwk_common::Signer as _;
		let keys = Keys::new(MNEMONIC, 0, 1).unwrap();
		let signer = SwSigner::new(MNEMONIC, false).unwrap();
		for nonce in [[0u8; 32], [7; 32], [0xff; 32]] {
			let path = leaf_key_path(0, &nonce).unwrap();
			let kit = signer.derive_xpub(&path).unwrap().public_key.x_only_public_key().0;
			assert_eq!(keys.leaf_xonly(&nonce).unwrap().serialize(), kit.serialize());
		}
		// Another nonce, another key; another account, another key.
		assert_ne!(keys.leaf_xonly(&[1; 32]).unwrap(), keys.leaf_xonly(&[2; 32]).unwrap());
		assert_ne!(Keys::new(MNEMONIC, 1, 1).unwrap().leaf_xonly(&[1; 32]).unwrap(), keys.leaf_xonly(&[1; 32]).unwrap());
		// The mailbox key is none of the leaf keys a drawn nonce gives.
		assert_ne!(keys.mailbox().unwrap().x_only_public_key().0, keys.leaf_xonly(&[0; 32]).unwrap());
	}

	#[test]
	fn the_mailbox_key_is_the_kits_leaf_key_of_its_nonce() {
		use lwk_common::Signer as _;
		let keys = Keys::new(MNEMONIC, 0, 1).unwrap();
		let signer = SwSigner::new(MNEMONIC, false).unwrap();
		let nonce: [u8; 32] = sha256::Hash::hash(b"Arca/mailbox").to_byte_array();
		let path = leaf_key_path(0, &nonce).unwrap();
		let kit = signer.derive_xpub(&path).unwrap().public_key.x_only_public_key().0;
		assert_eq!(keys.mailbox().unwrap().x_only_public_key().0.serialize(), kit.serialize());
		assert_eq!(path.to_string().matches('/').count(), 5, "six hardened steps, as every Arca key of the kit: {}", path);
		assert_ne!(Keys::new(MNEMONIC, 1, 1).unwrap().mailbox().unwrap().x_only_public_key().0, kit, "per account");
	}

	#[test]
	fn the_onchain_key_is_bip84() {
		// BIP84's test vector for this mnemonic, first receive address on
		// testnet: tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl.
		let keys = Keys::new(MNEMONIC, 0, 1).unwrap();
		use std::str::FromStr;
		let s = keys.onchain_script(RECEIVE, 0).unwrap();
		let a = bitcoin::Address::from_str("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl").unwrap().assume_checked();
		assert_eq!(s.as_bytes(), a.script_pubkey().as_bytes());
	}
}
