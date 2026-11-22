//! The wallet's keys, all from one BIP39 mnemonic, derived as the Sequentia
//! Wallet Kit derives them, so the same mnemonic serves the kit and this
//! wallet alike.
//!
//! - **Leaf keys**, one per leaf instance: `m/6'/account'/c1'/c2'/c3'/c4'`,
//!   where `c1` to `c4` are the first four 31-bit chunks, most significant bit
//!   first, of `SHA256("Arca/key" ‖ owner_nonce)`. The owner nonce is drawn
//!   for every leaf the wallet asks for ([`Keys::owner_nonce`]), and goes into
//!   the leaf's salt and its record, so a record names its own key and a
//!   restore needs no index scan. A key never comes from a counter, which a
//!   restore would repeat: a leaf's pair of signatures is rebindable to any
//!   output of the same script, asset and amount, so no two leaves of the
//!   wallet may share a script, whatever the leaf's creator does.
//! - **Tagged owner nonces.** An owner nonce is 16 random bytes `r` and the
//!   first 16 bytes of `HMAC-SHA256(scan key, "Arca/nonce-tag" ‖ r)`, so a
//!   restore that holds only the mnemonic and published trees tells its own
//!   leaves from every other leaf with one HMAC each ([`Keys::drew`]), and a
//!   nonce stays as unique as 128 random bits make it. The scan key is
//!   `HMAC-SHA256(k, "Arca/scan-key")`, `k` the secret of the kit's leaf key
//!   for the fixed nonce `SHA256("Arca/scan")`: it finds the wallet's leaves
//!   and spends none of them, so a wallet may hand it to a service that scans
//!   for it. Without it a tag reads as random bytes, and no leaf names its
//!   wallet.
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
//! - **The landing key**, the first on-chain key, `m/84'/coin'/0'/0/0`: every
//!   leaf the wallet holds of a supervised asset is a landing leaf, whose exit
//!   pays only P2WPKH of this key, where a freeze of the asset binds. One key
//!   for every such leaf, so that a freeze of the holder's address reaches
//!   every coin it holds, and a landed coin is an ordinary coin of the
//!   wallet's on either chain.
//! - **The OpenAMP account key**, `m/5/0` (unhardened), as the kit and
//!   Ambra derive it: the key an OpenAMP account and a SeqPal ID are. The
//!   wallet looks for claims under it ([`super::claim`]), so a payer that
//!   knows only that account, as SeqPal knows its holders, can pay the wallet;
//!   here it signs nothing but the proof of a claims lookup.
//! - **The staking key**, `m/2/0` (unhardened), as the kit derives it: the
//!   key a stake is bonded to, and the key a site's sign-in names when the
//!   wallet signs it as a staker (Levo's). The wallet looks for claims under
//!   it too, so a vesting sale's lot paid to the key its buyer signed in with
//!   is found; here it signs nothing but the proof of a claims lookup and,
//!   for such a claim, the claim key derived from it.
//! - **Order keys**, `m/86'/coin'/0'/0/<index>`, one for each order the
//!   wallet places on the chain: the key itself is the order's REFUND key
//!   (`maker_x`), and its key-path output, tweaked with no script tree (the
//!   Elements tags), is the plain program every fill pays the maker's credit
//!   to (`maker_prog`). A credit there is spent by an ordinary signature over
//!   its own outpoint, never by a pair of rebindable signatures, so no
//!   signature made for one credit spends another of the same value.

use std::collections::HashMap;
use std::sync::Mutex;

use elements::bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use elements::hashes::hmac::{Hmac, HmacEngine};
use elements::hashes::{hash160, sha256, Hash, HashEngine};
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

/// The tag whose hash is the nonce of the leaf key the scan key comes from.
pub const SCAN_TAG: &[u8] = b"Arca/scan";

/// What the scan key is the HMAC of, under that leaf key's secret.
pub const SCAN_KEY_TAG: &[u8] = b"Arca/scan-key";

/// What begins the message a nonce's tag is the HMAC of.
pub const NONCE_TAG: &[u8] = b"Arca/nonce-tag";

/// The bytes of an owner nonce that are random; the rest is their tag.
pub const NONCE_RANDOM: usize = 16;

/// The nonce of the leaf key the scan key comes from: `SHA256("Arca/scan")`.
pub fn scan_nonce() -> [u8; 32] {
	sha256::Hash::hash(SCAN_TAG).to_byte_array()
}

/// The tag of the random bytes `r` of an owner nonce, under `scan_key`: the
/// first [`NONCE_RANDOM`] bytes of `HMAC-SHA256(scan_key, "Arca/nonce-tag" ‖ r)`.
pub fn nonce_tag(scan_key: &[u8; 32], r: &[u8]) -> [u8; NONCE_RANDOM] {
	let mut e = HmacEngine::<sha256::Hash>::new(scan_key);
	e.input(NONCE_TAG);
	e.input(r);
	let mac = Hmac::<sha256::Hash>::from_engine(e).to_byte_array();
	let mut tag = [0u8; NONCE_RANDOM];
	tag.copy_from_slice(&mac[..NONCE_RANDOM]);
	tag
}

/// Whether `nonce` carries the tag of its own random bytes under `scan_key`:
/// a nonce the wallet of that scan key drew.
pub fn tagged(scan_key: &[u8; 32], nonce: &[u8; 32]) -> bool {
	let tag = nonce_tag(scan_key, &nonce[..NONCE_RANDOM]);
	// Compared in full, whatever byte differs first: the tag is a MAC.
	tag.iter().zip(&nonce[NONCE_RANDOM..]).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0
}

/// The on-chain chains: scripts handed out to be paid, and change.
pub const RECEIVE: u32 = 0;
pub const CHANGE: u32 = 1;
/// The order keys' counter in the store ([`Keys::order`]).
pub const ORDERS: u32 = 86;

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
	/// The on-chain and order keys derived so far, by purpose, branch and
	/// index, and the extended key of each branch they were derived under
	/// (`m/purpose'/coin'/0'/branch`). The wallet reads its on-chain coins by
	/// every script up to the last index in use, and a wallet that boards or
	/// pays often uses thousands: derived from the root each time, as five
	/// steps of BIP32, those keys cost seconds of every command that reads
	/// them. A key is what its path names, so keeping it changes nothing but
	/// that cost; the branch's key gives a new one in one step.
	derived: Mutex<HashMap<(u32, u32, u32), Keypair>>,
	branches: Mutex<HashMap<(u32, u32), Xpriv>>,
	/// The scan key, derived once ([`Keys::scan_key`]): every owner nonce
	/// the wallet draws and every leaf a restore looks at needs it.
	scan: Mutex<Option<[u8; 32]>>,
}

impl Keys {
	/// The keys of `mnemonic`, under leaf account `account`, with on-chain
	/// coin type `coin_type` (0 on the main chain, 1 elsewhere).
	pub fn new(mnemonic: &str, account: u32, coin_type: u32) -> Result<Keys, Error> {
		let signer = SwSigner::new(mnemonic, false).map_err(|e| Error::Keys(e.to_string()))?;
		Ok(Keys { signer, account, coin_type, secp: Secp256k1::new(), derived: Mutex::default(), branches: Mutex::default(),
			scan: Mutex::default() })
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

	/// The scan key: `HMAC-SHA256(k, "Arca/scan-key")`, `k` the secret of
	/// the leaf key of [`scan_nonce`]. It tells the wallet's owner nonces
	/// from any other ([`Keys::drew`]) and signs nothing.
	pub fn scan_key(&self) -> Result<[u8; 32], Error> {
		if let Some(k) = *self.scan.lock().expect("the scan key") {
			return Ok(k);
		}
		let secret = self.leaf(&scan_nonce())?.secret_bytes();
		let mut e = HmacEngine::<sha256::Hash>::new(&secret);
		e.input(SCAN_KEY_TAG);
		let k = Hmac::<sha256::Hash>::from_engine(e).to_byte_array();
		*self.scan.lock().expect("the scan key") = Some(k);
		Ok(k)
	}

	/// A fresh owner nonce: [`NONCE_RANDOM`] bytes from the system's source
	/// and their tag under the scan key ([`nonce_tag`]).
	pub fn owner_nonce(&self) -> Result<[u8; 32], Error> {
		let mut nonce = super::random32();
		let tag = nonce_tag(&self.scan_key()?, &nonce[..NONCE_RANDOM]);
		nonce[NONCE_RANDOM..].copy_from_slice(&tag);
		Ok(nonce)
	}

	/// Whether this wallet drew `nonce` ([`Keys::owner_nonce`]). A nonce
	/// drawn before nonces were tagged reads as not drawn; its leaf is still
	/// the wallet's when its owner key is the key the nonce derives.
	pub fn drew(&self, nonce: &[u8; 32]) -> Result<bool, Error> {
		Ok(tagged(&self.scan_key()?, nonce))
	}

	/// The key at `m/purpose'/coin'/0'/branch/index`, derived once
	/// ([`Keys::derived`]).
	fn branch_key(&self, purpose: u32, branch: u32, index: u32) -> Result<Keypair, Error> {
		if let Some(k) = self.derived.lock().expect("the keys memo").get(&(purpose, branch, index)) {
			return Ok(*k);
		}
		let normal = |i: u32| ChildNumber::from_normal_idx(i).map_err(|_| Error::Keys(format!("{} is not a normal index", i)));
		let parent = {
			let mut b = self.branches.lock().expect("the keys memo");
			match b.get(&(purpose, branch)) {
				Some(x) => *x,
				None => {
					let path = DerivationPath::from(vec![hardened(purpose)?, hardened(self.coin_type)?, hardened(0)?, normal(branch)?]);
					let x = self.signer.derive_xprv(&path).map_err(|e| Error::Keys(e.to_string()))?;
					b.insert((purpose, branch), x);
					x
				},
			}
		};
		let xprv = parent.derive_priv(&self.secp, &[normal(index)?]).map_err(|e| Error::Keys(e.to_string()))?;
		let secret = SecretKey::from_slice(&xprv.private_key.secret_bytes()).map_err(|e| Error::Keys(e.to_string()))?;
		let k = Keypair::from_secret_key(&self.secp, &secret);
		self.derived.lock().expect("the keys memo").insert((purpose, branch, index), k);
		Ok(k)
	}

	/// The on-chain key at `m/84'/coin'/0'/chain/index`.
	pub fn onchain(&self, chain: u32, index: u32) -> Result<Keypair, Error> {
		self.branch_key(84, chain, index)
	}

	/// The landing key: the first on-chain key, `m/84'/coin'/0'/0/0`.
	pub fn landing(&self) -> Result<Keypair, Error> {
		self.onchain(RECEIVE, 0)
	}

	/// The landing program: `hash160` of the landing key.
	pub fn landing_program(&self) -> Result<[u8; 20], Error> {
		Ok(hash160::Hash::hash(&compressed(&self.landing()?)).to_byte_array())
	}

	/// The OpenAMP account key, `m/5/0`.
	pub fn openamp(&self) -> Result<Keypair, Error> {
		let normal = |i: u32| ChildNumber::from_normal_idx(i).map_err(|_| Error::Keys(format!("{} is not a normal index", i)));
		self.keypair_at(&DerivationPath::from(vec![normal(5)?, normal(0)?]))
	}

	/// The staking key, `m/2/0` (unhardened), as the kit derives it.
	pub fn staker(&self) -> Result<Keypair, Error> {
		let normal = |i: u32| ChildNumber::from_normal_idx(i).map_err(|_| Error::Keys(format!("{} is not a normal index", i)));
		self.keypair_at(&DerivationPath::from(vec![normal(2)?, normal(0)?]))
	}

	/// The unblinded P2WPKH script of the on-chain key at `chain/index`.
	pub fn onchain_script(&self, chain: u32, index: u32) -> Result<Script, Error> {
		Ok(p2wpkh(&self.onchain(chain, index)?))
	}

	/// The order key at `index`, `m/86'/coin'/0'/0/index`: an order's REFUND
	/// key, untweaked.
	pub fn order(&self, index: u32) -> Result<Keypair, Error> {
		self.branch_key(86, 0, index)
	}

	/// The key that signs a key-path spend of the order key's output: the
	/// order key tweaked with no script tree.
	pub fn order_spend_key(&self, index: u32) -> Result<Keypair, Error> {
		use elements::schnorr::TapTweak;
		Ok(self.order(index)?.tap_tweak(&self.secp, None).to_inner())
	}

	/// The program an order's credits are paid to: the order key's key-path
	/// output, `OP_1 <program>`.
	pub fn order_program(&self, index: u32) -> Result<[u8; 32], Error> {
		Ok(self.order_spend_key(index)?.x_only_public_key().0.serialize())
	}

	/// `OP_1 <program>` of the order key at `index`.
	pub fn order_script(&self, index: u32) -> Result<Script, Error> {
		Ok(elements::script::Builder::new().push_int(1).push_slice(&self.order_program(index)?).into_script())
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
	fn the_openamp_key_is_the_kits_m_5_0() {
		// The kit's `openampXonlyPubkey` for this mnemonic (lwk_wasm, run under
		// node), and an independent BIP32 derivation of m/5/0 in Python.
		let keys = Keys::new(MNEMONIC, 0, 1).unwrap();
		let x = keys.openamp().unwrap().x_only_public_key().0.serialize();
		let want = "1bec09aada7cdc3c9544fb44d9d01aa8d32e391f5c35346c3f3354d5f8c509dd";
		assert_eq!(x.iter().map(|b| format!("{:02x}", b)).collect::<String>(), want);
		// The same on every chain and every leaf account: an OpenAMP account is
		// one key per mnemonic.
		assert_eq!(Keys::new(MNEMONIC, 3, 0).unwrap().openamp().unwrap().x_only_public_key().0.serialize(), x);
		assert_ne!(keys.onchain(RECEIVE, 0).unwrap().x_only_public_key().0.serialize(), x);
	}

	#[test]
	fn the_order_key_is_bip86s_tweaked_by_the_elements_tags() {
		// BIP86's test vector for this mnemonic, m/86'/0'/0'/0/0: the internal
		// key. The output key is Elements' tweak of it, which the node checks
		// a key-path spend against, and is another than Bitcoin's.
		let keys = Keys::new(MNEMONIC, 0, 0).unwrap();
		let internal = keys.order(0).unwrap().x_only_public_key().0;
		assert_eq!(internal.to_string(), "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115");
		let secp = Secp256k1::verification_only();
		let elements_spk = Script::new_v1_p2tr(&secp, internal, None);
		assert_eq!(keys.order_script(0).unwrap(), elements_spk);
		assert_ne!(keys.order_program(0).unwrap().iter().map(|b| format!("{:02x}", b)).collect::<String>(), "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
			"Bitcoin's BIP86 output key: Elements tags its tweak otherwise");
		assert_ne!(keys.order(1).unwrap().x_only_public_key().0, internal);
		assert_ne!(Keys::new(MNEMONIC, 0, 1).unwrap().order(0).unwrap().x_only_public_key().0, internal, "per coin type");
	}

	#[test]
	fn a_kept_key_is_the_key_its_path_names() {
		// Derived from the branch's key and kept: the same as derived from the
		// root by the whole path, the first time and every time after.
		let keys = Keys::new(MNEMONIC, 0, 1).unwrap();
		let normal = |i: u32| ChildNumber::from_normal_idx(i).unwrap();
		let h = |i: u32| ChildNumber::from_hardened_idx(i).unwrap();
		for _ in 0..2 {
			for (chain, index) in [(RECEIVE, 0), (RECEIVE, 7), (CHANGE, 0), (CHANGE, 3000)] {
				let path = DerivationPath::from(vec![h(84), h(1), h(0), normal(chain), normal(index)]);
				assert_eq!(keys.onchain(chain, index).unwrap().secret_bytes(), keys.keypair_at(&path).unwrap().secret_bytes());
			}
			for index in [0, 1, 500] {
				let path = DerivationPath::from(vec![h(86), h(1), h(0), normal(0), normal(index)]);
				assert_eq!(keys.order(index).unwrap().secret_bytes(), keys.keypair_at(&path).unwrap().secret_bytes());
			}
		}
		assert_ne!(keys.onchain(RECEIVE, 1).unwrap().secret_bytes(), keys.onchain(CHANGE, 1).unwrap().secret_bytes());
		assert_ne!(keys.onchain(RECEIVE, 1).unwrap().secret_bytes(), keys.order(1).unwrap().secret_bytes());
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

	#[test]
	fn the_scan_key_is_the_hmac_of_the_leaf_key_of_its_nonce() {
		let keys = Keys::new(MNEMONIC, 0, 1).unwrap();
		let secret = keys.leaf(&sha256::Hash::hash(b"Arca/scan").to_byte_array()).unwrap().secret_bytes();
		let mut e = HmacEngine::<sha256::Hash>::new(&secret);
		e.input(b"Arca/scan-key");
		assert_eq!(keys.scan_key().unwrap(), Hmac::<sha256::Hash>::from_engine(e).to_byte_array());
		// Kept, and the same on every call; per account; not the secret itself.
		assert_eq!(keys.scan_key().unwrap(), keys.scan_key().unwrap());
		assert_ne!(Keys::new(MNEMONIC, 1, 1).unwrap().scan_key().unwrap(), keys.scan_key().unwrap());
		assert_ne!(keys.scan_key().unwrap(), secret);
		// Its nonce is neither the mailbox's nor one a draw gives.
		assert_ne!(scan_nonce(), mailbox_nonce());
		assert!(!keys.drew(&scan_nonce()).unwrap());
	}

	#[test]
	fn a_drawn_nonce_carries_the_tag_of_its_random_half() {
		let keys = Keys::new(MNEMONIC, 0, 1).unwrap();
		let other = Keys::new("legal winner thank year wave sausage worth useful legal winner thank yellow", 0, 1).unwrap();
		let k = keys.scan_key().unwrap();
		let mut seen = std::collections::BTreeSet::new();
		for _ in 0..64 {
			let n = keys.owner_nonce().unwrap();
			assert_eq!(n[NONCE_RANDOM..], nonce_tag(&k, &n[..NONCE_RANDOM]));
			assert!(keys.drew(&n).unwrap(), "the wallet that drew it");
			assert!(!other.drew(&n).unwrap(), "another mnemonic's wallet");
			assert!(!Keys::new(MNEMONIC, 1, 1).unwrap().drew(&n).unwrap(), "another account");
			// Any byte changed, in either half, and the tag fails.
			for i in [0, NONCE_RANDOM - 1, NONCE_RANDOM, 31] {
				let mut m = n;
				m[i] ^= 1;
				assert!(!keys.drew(&m).unwrap(), "byte {} changed", i);
			}
			assert!(seen.insert(n), "a fresh nonce each draw");
		}
		// A nonce drawn wholly at random, as before tags, reads as not drawn.
		assert!(!keys.drew(&[7; 32]).unwrap());
		// The tag is the HMAC's first half, by its definition.
		let r = [0xab; NONCE_RANDOM];
		let mut e = HmacEngine::<sha256::Hash>::new(&k);
		e.input(b"Arca/nonce-tag");
		e.input(&r);
		assert_eq!(nonce_tag(&k, &r)[..], Hmac::<sha256::Hash>::from_engine(e).to_byte_array()[..NONCE_RANDOM]);
	}
}
