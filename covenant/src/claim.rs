//! Claim trees: one round paying many holders, each under a key a payer
//! names.
//!
//! A payer names each holder by a 32-byte x-only key `A`: an address key the
//! holder already has (the x coordinate of a P2WPKH address's public key, or a
//! taproot address's output key, which is its program), or any key the holder
//! hands it. For each holder the payer draws a fresh 32-byte nonce `n`, and the
//! holder's leaf, an ordinary `vtxo-1` leaf, is owned by the claim key
//!
//! ```text
//! A' = lift_x(A) + t·G,   t = SHA256(T ‖ T ‖ A ‖ n),   T = SHA256("Arca/claim-key")
//! ```
//!
//! which the holder signs for with its secret for `A` plus `t`, as a taproot
//! output key is signed for, its parity handled as BIP340 handles it
//! ([`claim_key`], [`claim_keypair`]). `n` is the leaf's owner nonce too, so it
//! goes into the leaf's salt with the operator's nonce, as every leaf's does.
//!
//! The claim key is a key of its own for every claim: the same address can be
//! paid by any number of distributions while a leaf key never signs for
//! another leaf, the holder's address key itself signs nothing of the tree,
//! and since the server derives `A'` from `A` and `n` itself, naming a key
//! takes no key a wallet uses for its own leaves. The tweak hides nothing: the
//! published tree carries each leaf's owner key and owner nonce, so anyone who
//! knows an address key can test whether a claim was paid to it, as anyone can
//! see an on-chain payment to that address.
//!
//! A distribution ([`Distribution`]) is what the payer submits: the coins it
//! gives up, the asset, the claims, the script the unclaimed sum goes back to,
//! and the fee. Its id ([`Distribution::id`]) is what each coin's owner
//! attests.

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::{Keypair, Scalar, XOnlyPublicKey};
use elements::{AssetId, Script};

use crate::message::Chain;
use crate::record::LeafId;
use crate::taptree::secp;
use crate::time::{MedianTime, RelativeTime};

/// The tag of a claim key's tweak.
pub const CLAIM_KEY_TAG: &[u8] = b"Arca/claim-key";

/// The tag of a distribution's id.
pub const DISTRIBUTION_TAG: &[u8] = b"Arca/distribution";

/// The most claims one distribution names: what its id counts in two bytes.
/// A server takes no more than one batch holds.
pub const MAX_CLAIMS: usize = u16::MAX as usize;

/// The most coins one distribution gives up.
pub const MAX_INPUTS: usize = 16;

/// The most bytes of a distribution's return script.
pub const MAX_RETURN_SCRIPT: usize = 10_000;

/// Why a claim key or a distribution cannot be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClaimError {
	#[error("the tweak of key {0} by its nonce is no scalar, or makes no key: draw another nonce")]
	Tweak(XOnlyPublicKey),
	#[error("the key pair given is for {given}, not the named key {named}")]
	NotTheNamedKey { named: XOnlyPublicKey, given: XOnlyPublicKey },
	#[error("a distribution names {0} claims; it names 1 to {max}", max = MAX_CLAIMS)]
	ClaimCount(usize),
	#[error("a distribution gives up {0} coins; it gives up 1 to {max}", max = MAX_INPUTS)]
	InputCount(usize),
	#[error("key {0} is named twice: a distribution pays each named key once")]
	NamedTwice(XOnlyPublicKey),
	#[error("claim {0} holds nothing")]
	Empty(usize),
	#[error("the return script has {0} bytes; it has 1 to {max}", max = MAX_RETURN_SCRIPT)]
	ReturnScript(usize),
	#[error("the fees name {0} assets, or one twice")]
	Fees(usize),
}

/// `t = SHA256(T ‖ T ‖ A ‖ n)`, `T = SHA256("Arca/claim-key")`, as 32 bytes.
pub fn claim_tweak(named: &XOnlyPublicKey, nonce: &[u8; 32]) -> [u8; 32] {
	let tag = sha256::Hash::hash(CLAIM_KEY_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&named.serialize());
	e.input(nonce);
	sha256::Hash::from_engine(e).to_byte_array()
}

fn tweak_scalar(named: &XOnlyPublicKey, nonce: &[u8; 32]) -> Result<Scalar, ClaimError> {
	Scalar::from_be_bytes(claim_tweak(named, nonce)).map_err(|_| ClaimError::Tweak(*named))
}

/// The claim key `A'` of the key `named` and the nonce `nonce`.
pub fn claim_key(named: &XOnlyPublicKey, nonce: &[u8; 32]) -> Result<XOnlyPublicKey, ClaimError> {
	let t = tweak_scalar(named, nonce)?;
	named.add_tweak(secp(), &t).map(|(k, _)| k).map_err(|_| ClaimError::Tweak(*named))
}

/// The key pair that signs for the claim key of `named`'s x-only key and
/// `nonce`: `named` plus the tweak, the parity of each handled as BIP340
/// handles it. `named` may be any key pair whose x-only key the payer named,
/// whatever the parity of its own point: an on-chain address key, or a
/// taproot output key already tweaked.
pub fn claim_keypair(named: &Keypair, nonce: &[u8; 32]) -> Result<Keypair, ClaimError> {
	let a = named.x_only_public_key().0;
	let t = tweak_scalar(&a, nonce)?;
	named.add_xonly_tweak(secp(), &t).map_err(|_| ClaimError::Tweak(a))
}

/// Whether `pair` signs for the claim key `owner` of `named` and `nonce`: the
/// check a wallet makes before it takes a claim leaf as its own.
pub fn is_claim_key(owner: &XOnlyPublicKey, named: &XOnlyPublicKey, nonce: &[u8; 32]) -> bool {
	claim_key(named, nonce).is_ok_and(|k| k == *owner)
}

/// The key a taproot script names: its 32-byte program, `OP_1 <program>`.
/// `None` for any other script: a P2WPKH script names only its key's hash,
/// so a payer names the key itself.
pub fn named_of_script(script_pubkey: &Script) -> Option<XOnlyPublicKey> {
	let b = script_pubkey.as_bytes();
	if b.len() == 34 && b[0] == 0x51 && b[1] == 0x20 {
		XOnlyPublicKey::from_slice(&b[2..]).ok()
	} else {
		None
	}
}

/// One holder of a distribution: the key the payer names, the nonce it draws
/// for the holder, and what the holder's leaf holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Claim {
	pub named: XOnlyPublicKey,
	pub nonce: [u8; 32],
	pub value: u64,
}

impl Claim {
	/// The claim leaf's owner key ([`claim_key`]).
	pub fn owner(&self) -> Result<XOnlyPublicKey, ClaimError> {
		claim_key(&self.named, &self.nonce)
	}
}

/// What a payer submits: the coins it gives up, all in `asset`, for one
/// `vtxo-1` leaf per claim, each with `exit_delay`, in the asset's next round;
/// `return_script`, where the operator pays what no holder takes up; the fee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distribution {
	pub inputs: Vec<LeafId>,
	pub asset: AssetId,
	pub exit_delay: RelativeTime,
	pub claims: Vec<Claim>,
	pub return_script: Script,
	pub fees: Vec<(AssetId, u64)>,
	/// The earliest median time of a round it may run in.
	pub not_before: Option<MedianTime>,
}

fn asset_bytes(a: AssetId) -> [u8; 32] {
	a.into_inner().to_byte_array()
}

impl Distribution {
	/// The bounds every distribution keeps, before any server's: 1 to
	/// [`MAX_INPUTS`] coins, 1 to [`MAX_CLAIMS`] claims, each holding
	/// something, no key named twice, a return script of 1 to
	/// [`MAX_RETURN_SCRIPT`] bytes, and no asset twice among the fees.
	pub fn check(&self) -> Result<(), ClaimError> {
		if self.inputs.is_empty() || self.inputs.len() > MAX_INPUTS {
			return Err(ClaimError::InputCount(self.inputs.len()));
		}
		if self.claims.is_empty() || self.claims.len() > MAX_CLAIMS {
			return Err(ClaimError::ClaimCount(self.claims.len()));
		}
		let mut named = std::collections::BTreeSet::new();
		for (i, c) in self.claims.iter().enumerate() {
			if c.value == 0 {
				return Err(ClaimError::Empty(i));
			}
			if !named.insert(c.named.serialize()) {
				return Err(ClaimError::NamedTwice(c.named));
			}
		}
		if self.return_script.is_empty() || self.return_script.len() > MAX_RETURN_SCRIPT {
			return Err(ClaimError::ReturnScript(self.return_script.len()));
		}
		let fee_assets: std::collections::BTreeSet<[u8; 32]> = self.fees.iter().map(|f| asset_bytes(f.0)).collect();
		if self.fees.len() > u8::MAX as usize || fee_assets.len() != self.fees.len() {
			return Err(ClaimError::Fees(self.fees.len()));
		}
		Ok(())
	}

	/// What the claims hold together.
	pub fn total(&self) -> u128 {
		self.claims.iter().map(|c| c.value as u128).sum()
	}

	/// The id each coin's owner attests:
	///
	/// ```text
	/// SHA256(T ‖ T ‖ genesis_hash ‖ S ‖ body),   T = SHA256("Arca/distribution")
	/// body = n_in (u16), each leaf id given up
	///      ‖ asset ‖ exit delay units (u16)
	///      ‖ n_claims (u16), each claim: named key ‖ nonce ‖ value (u64)
	///      ‖ return script length (u16) ‖ return script
	///      ‖ n_fees (u8), each fee: asset ‖ amount (u64)
	///      ‖ 0, or 1 and the earliest round time (u32)
	/// ```
	///
	/// Integers little-endian, asset ids in internal byte order. Its tag is its
	/// own, so no attestation of a distribution is one of a participation or a
	/// take; the genesis hash and `S` keep it to one chain and one operator. A
	/// distribution that fails [`Distribution::check`] has no id a server
	/// takes, whatever this returns.
	pub fn id(&self, chain: &Chain, operator: &XOnlyPublicKey) -> [u8; 32] {
		let tag = sha256::Hash::hash(DISTRIBUTION_TAG);
		let mut e = sha256::Hash::engine();
		e.input(tag.as_byte_array());
		e.input(tag.as_byte_array());
		e.input(&chain.genesis_bytes());
		e.input(&operator.serialize());
		e.input(&(self.inputs.len() as u16).to_le_bytes());
		for i in &self.inputs {
			e.input(&i.0);
		}
		e.input(&asset_bytes(self.asset));
		e.input(&self.exit_delay.units().to_le_bytes());
		e.input(&(self.claims.len() as u16).to_le_bytes());
		for c in &self.claims {
			e.input(&c.named.serialize());
			e.input(&c.nonce);
			e.input(&c.value.to_le_bytes());
		}
		e.input(&(self.return_script.len() as u16).to_le_bytes());
		e.input(self.return_script.as_bytes());
		e.input(&[self.fees.len() as u8]);
		for (a, v) in &self.fees {
			e.input(&asset_bytes(*a));
			e.input(&v.to_le_bytes());
		}
		match self.not_before {
			Some(t) => {
				e.input(&[1]);
				e.input(&t.to_consensus_u32().to_le_bytes());
			},
			None => e.input(&[0]),
		}
		sha256::Hash::from_engine(e).to_byte_array()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::sign::{sign_digest, verify_digest};
	use elements::secp256k1_zkp::{Parity, SecretKey};

	fn pair(label: &str) -> Keypair {
		let s = SecretKey::from_slice(&sha256::Hash::hash(label.as_bytes()).to_byte_array()).unwrap();
		Keypair::from_secret_key(secp(), &s)
	}

	/// Key pairs whose own point has odd y and even y, as an address key may.
	fn of_parity(want: Parity) -> Keypair {
		(0..).map(|i| pair(&format!("address key {}", i))).find(|k| k.x_only_public_key().1 == want).unwrap()
	}

	#[test]
	fn the_claim_key_signs_with_the_named_key_plus_the_tweak_whatever_the_parity() {
		for parity in [Parity::Even, Parity::Odd] {
			let a = of_parity(parity);
			let named = a.x_only_public_key().0;
			for nonce in [[0u8; 32], [7; 32], [0xff; 32]] {
				let owner = claim_key(&named, &nonce).unwrap();
				let k = claim_keypair(&a, &nonce).unwrap();
				assert_eq!(k.x_only_public_key().0, owner, "the key pair signs for the published key");
				assert!(is_claim_key(&owner, &named, &nonce));
				let d = [0x5a; 32];
				let s = sign_digest(&k, &d, &[0; 32]);
				assert!(verify_digest(&s, &d, &owner));
				// The named key's own signature is not the claim key's.
				let wrong = sign_digest(&a, &d, &[0; 32]);
				assert!(!verify_digest(&wrong, &d, &owner));
				assert_ne!(owner, named);
			}
		}
	}

	#[test]
	fn the_claim_key_is_lift_x_of_the_named_key_plus_t_g() {
		// Independently of add_tweak: lift_x(A) is the even-y point, so a
		// secret for it is a or n - a; adding t gives the claim key's secret.
		let a = of_parity(Parity::Odd);
		let named = a.x_only_public_key().0;
		let nonce = [3u8; 32];
		let mut even_secret = a.secret_key();
		if a.x_only_public_key().1 == Parity::Odd {
			even_secret = even_secret.negate();
		}
		let t = Scalar::from_be_bytes(claim_tweak(&named, &nonce)).unwrap();
		let claim_secret = even_secret.add_tweak(&t).unwrap();
		let expect = Keypair::from_secret_key(secp(), &claim_secret).x_only_public_key().0;
		assert_eq!(claim_key(&named, &nonce).unwrap(), expect);
	}

	#[test]
	fn each_nonce_and_each_named_key_gives_a_key_of_its_own() {
		let a = pair("holder").x_only_public_key().0;
		let b = pair("another holder").x_only_public_key().0;
		let k = |named: &XOnlyPublicKey, n: u8| claim_key(named, &[n; 32]).unwrap();
		assert_ne!(k(&a, 1), k(&a, 2));
		assert_ne!(k(&a, 1), k(&b, 1));
		assert_eq!(k(&a, 1), k(&a, 1));
		assert!(!is_claim_key(&k(&a, 1), &a, &[2; 32]));
		assert!(!is_claim_key(&k(&a, 1), &b, &[1; 32]));
	}

	#[test]
	fn a_key_pair_for_another_key_signs_for_another_claim_key() {
		let a = pair("holder");
		let b = pair("payer");
		let named = a.x_only_public_key().0;
		let nonce = [9u8; 32];
		assert_ne!(claim_keypair(&b, &nonce).unwrap().x_only_public_key().0, claim_key(&named, &nonce).unwrap());
	}

	#[test]
	fn a_taproot_script_names_its_program_and_no_other_script_names_a_key() {
		let k = pair("taproot holder").x_only_public_key().0;
		let mut spk = vec![0x51, 0x20];
		spk.extend(k.serialize());
		assert_eq!(named_of_script(&Script::from(spk.clone())), Some(k));
		let mut wpkh = vec![0x00, 0x14];
		wpkh.extend([1u8; 20]);
		assert_eq!(named_of_script(&Script::from(wpkh)), None);
		spk[0] = 0x52;
		assert_eq!(named_of_script(&Script::from(spk)), None);
	}

	fn distribution() -> Distribution {
		Distribution {
			inputs: vec![LeafId([1; 32]), LeafId([2; 32])],
			asset: AssetId::from_slice(&[5; 32]).unwrap(),
			exit_delay: RelativeTime::from_units(254).unwrap(),
			claims: vec![
				Claim { named: pair("h1").x_only_public_key().0, nonce: [1; 32], value: 1_000 },
				Claim { named: pair("h2").x_only_public_key().0, nonce: [2; 32], value: 2_000 },
			],
			return_script: Script::from(vec![0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
			fees: vec![(AssetId::from_slice(&[5; 32]).unwrap(), 30)],
			not_before: None,
		}
	}

	#[test]
	fn the_id_commits_to_every_part() {
		let chain = Chain::new(elements::BlockHash::from_byte_array([0x11; 32]));
		let s = pair("operator").x_only_public_key().0;
		let d = distribution();
		assert!(d.check().is_ok());
		let id = d.id(&chain, &s);
		let mut seen = std::collections::BTreeSet::from([id]);
		let mut changed = |f: &dyn Fn(&mut Distribution)| {
			let mut x = distribution();
			f(&mut x);
			assert!(seen.insert(x.id(&chain, &s)), "a change left the id as it was");
		};
		changed(&|x| x.inputs.pop().map(|_| ()).unwrap());
		changed(&|x| x.inputs[0] = LeafId([3; 32]));
		changed(&|x| x.asset = AssetId::from_slice(&[6; 32]).unwrap());
		changed(&|x| x.exit_delay = RelativeTime::from_units(255).unwrap());
		changed(&|x| x.claims[0].value += 1);
		changed(&|x| x.claims[1].nonce = [3; 32]);
		changed(&|x| x.claims[1].named = pair("h3").x_only_public_key().0);
		changed(&|x| x.claims.swap(0, 1));
		changed(&|x| x.claims.pop().map(|_| ()).unwrap());
		changed(&|x| x.return_script = Script::from(vec![0x6a]));
		changed(&|x| x.fees[0].1 = 31);
		changed(&|x| x.fees.clear());
		changed(&|x| x.not_before = Some(MedianTime::from_consensus(1_800_000_000).unwrap()));
		assert_ne!(d.id(&Chain::new(elements::BlockHash::from_byte_array([0x12; 32])), &s), id, "another chain");
		assert_ne!(d.id(&chain, &pair("another operator").x_only_public_key().0), id, "another operator");
	}

	#[test]
	fn a_distribution_keeps_its_bounds() {
		let mut d = distribution();
		d.claims[1].named = d.claims[0].named;
		assert_eq!(d.check(), Err(ClaimError::NamedTwice(d.claims[0].named)));
		let mut d = distribution();
		d.claims[0].value = 0;
		assert_eq!(d.check(), Err(ClaimError::Empty(0)));
		let mut d = distribution();
		d.inputs.clear();
		assert_eq!(d.check(), Err(ClaimError::InputCount(0)));
		let mut d = distribution();
		d.claims.clear();
		assert_eq!(d.check(), Err(ClaimError::ClaimCount(0)));
		let mut d = distribution();
		d.return_script = Script::new();
		assert_eq!(d.check(), Err(ClaimError::ReturnScript(0)));
		let mut d = distribution();
		d.fees.push(d.fees[0]);
		assert_eq!(d.check(), Err(ClaimError::Fees(2)));
	}
}
