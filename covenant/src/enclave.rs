//! `enclave-1`: the leaf of a restricted asset, whose exit pays its holder's
//! on-chain enclave.
//!
//! A restricted asset (an OpenAMP asset) lives on the chain only in
//! enclaves: `P2TR(NUMS, [transfer, claw])`, the transfer leaf
//! `<H> OP_CHECKSIGVERIFY <Kp> OP_CHECKSIG` for the holder's registered key
//! `H` and the asset's policy key `Kp`, and the claw leaf
//! `<Ki> OP_CHECKSIGVERIFY <Kp> OP_CHECKSIG` for the issuer's key `Ki` only
//! where the asset elected clawback; with no clawback the transfer leaf is
//! the whole tree. Every move of such a coin needs the policy key, so the
//! issuer's rules travel with it. `enclave-1` keeps that true in the tree:
//!
//! ```text
//! collab:  the leaf's collaborative path, pushing K ‖ D, D = HASH160(Q)
//! exit:    <delay> OP_CHECKSEQUENCEVERIFY OP_DROP
//!          OP_0 OP_INSPECTOUTPUTSCRIPTPUBKEY OP_1 OP_EQUALVERIFY <Q> OP_EQUALVERIFY
//!          OP_0 OP_INSPECTOUTPUTASSET OP_1 OP_EQUALVERIFY <asset> OP_EQUALVERIFY
//!          OP_0 OP_INSPECTOUTPUTVALUE OP_1 OP_EQUALVERIFY <value, u64 LE> OP_EQUALVERIFY
//!          <A> OP_CHECKSIG
//! claw:    <Ki> OP_CHECKSIGVERIFY <Kp> OP_CHECKSIG          only where the asset elected clawback
//! ```
//!
//! The tree is `[collab, exit]`, or `[collab, [exit, claw]]` with clawback.
//!
//! - `Q` is the output key of the holder's enclave ([`Enclave::program`]),
//!   built as the policy server builds it. The exit pays output 0 `OP_1 <Q>`
//!   explicitly, in the leaf's asset, holding exactly the leaf's value: there
//!   is no fee allowance in the asset, since an uncommitted remainder of a
//!   restricted asset could go anywhere, a fee output included. The exit's
//!   fee is a coin attached in an asset the node takes.
//! - `A`, the owner key, is the holder's enclave key for the leaf
//!   ([`enclave_key`]): `A = lift_x(H) + t·G`, `t = SHA256(T ‖ T ‖ H ‖ n)`,
//!   `T = SHA256("Arca/enclave-key")`, `n` the owner nonce. Only the holder of
//!   `H`'s private key signs for the leaf, and anyone checks from the record
//!   that a leaf is `H`'s. Otherwise a wallet could hold a leaf whose exit
//!   pays another holder's enclave and spend it under that holder's rules.
//! - `D` after `K` binds the operator's pair to the enclave the coin exits to,
//!   as a `landing-1` leaf's `P` binds its landing: a signer told the wrong
//!   holder signs a message no real leaf checks. `D` is 20 bytes, so the
//!   message has a `landing-1` message's length, 95 + 32m bytes, and `K` is
//!   the salt's own, as the equivocation bond reads it.
//! - The claw leaf is the enclave's own, byte for byte. Its signatures are
//!   signature hashes over the spending transaction, so they move one coin,
//!   by one path, on one chain. With it the issuer and the policy server move
//!   a coin of the leaf, once it is on the chain, wherever they sign for: the
//!   power they hold over the enclave the leaf exits to. A leaf of an asset
//!   that elected no clawback has no such path.
//!
//! A record keeps the leaf's enclave as [`Enclave`]: `H`, `Kp` and the
//! issuer's key when the asset elected clawback. The exit's script needs the
//! asset and the value, which follow from the record's ([`Enclave::terms`]).

use elements::hashes::{hash160, sha256, Hash, HashEngine};
use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::{Keypair, Scalar, XOnlyPublicKey};
use elements::{AssetId, Script};

use crate::script::{asset_bytes, BuilderExt, ExplicitOutput};
use crate::taptree::{secp, TapOutput};
use crate::time::RelativeTime;

/// The tag of an enclave key's tweak.
pub const ENCLAVE_KEY_TAG: &[u8] = b"Arca/enclave-key";

/// The length of `D`, the enclave's digest in the collaborative constant.
pub const DIGEST_BYTES: usize = 20;

/// Why an `enclave-1` leaf cannot be built or spent as asked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnclaveError {
	#[error("the tweak of holder key {0} by the owner nonce is no scalar, or makes no key: draw another nonce")]
	Tweak(XOnlyPublicKey),
	#[error("the leaf's owner key {owner} is not the enclave key of holder {holder} for its owner nonce")]
	NotTheHoldersKey { owner: XOnlyPublicKey, holder: XOnlyPublicKey },
	#[error("an enclave-1 leaf's terms name asset {terms}, and the leaf holds {leaf}")]
	Asset { terms: AssetId, leaf: AssetId },
	#[error("an enclave-1 leaf's terms name a value of {terms}, and the leaf holds {leaf}")]
	Value { terms: u64, leaf: u64 },
	#[error("the exit's output 0 is not the holder's enclave, explicitly in the leaf's asset, holding exactly {value}")]
	Output { value: u64 },
	#[error("the asset elected no clawback: an enclave-1 leaf of it has no claw path")]
	NoClawback,
}

/// The tag of a policy server's co-signature beside the operator.
pub const POLICY_COSIGN_TAG: &[u8] = b"OpenAMP/tree-cosign";

/// What a restricted asset's policy key signs to approve a message the
/// operator's key is to sign: `SHA256(T ‖ T ‖ digest)`,
/// `T = SHA256("OpenAMP/tree-cosign")`, `digest` the rebindable message's
/// SHA256. The tag keeps the approval apart from every signature hash the
/// policy key signs on the chain, and the digest names one coin's salt, its
/// value, the outputs it commits to and the chain, so the approval moves
/// nothing else. The operator's signer signs a message of a restricted asset
/// only beside a valid approval of it.
pub fn policy_cosign_digest(digest: &[u8; 32]) -> [u8; 32] {
	let tag = sha256::Hash::hash(POLICY_COSIGN_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(digest);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// `t = SHA256(T ‖ T ‖ H ‖ n)`, `T = SHA256("Arca/enclave-key")`.
pub fn enclave_tweak(holder: &XOnlyPublicKey, nonce: &[u8; 32]) -> [u8; 32] {
	let tag = sha256::Hash::hash(ENCLAVE_KEY_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&holder.serialize());
	e.input(nonce);
	sha256::Hash::from_engine(e).to_byte_array()
}

fn tweak_scalar(holder: &XOnlyPublicKey, nonce: &[u8; 32]) -> Result<Scalar, EnclaveError> {
	Scalar::from_be_bytes(enclave_tweak(holder, nonce)).map_err(|_| EnclaveError::Tweak(*holder))
}

/// The leaf key of holder `holder` for owner nonce `nonce`.
pub fn enclave_key(holder: &XOnlyPublicKey, nonce: &[u8; 32]) -> Result<XOnlyPublicKey, EnclaveError> {
	let t = tweak_scalar(holder, nonce)?;
	holder.add_tweak(secp(), &t).map(|(k, _)| k).map_err(|_| EnclaveError::Tweak(*holder))
}

/// The key pair that signs for [`enclave_key`] of `holder`'s x-only key: the
/// holder's key plus the tweak, each parity handled as BIP340 handles it.
pub fn enclave_keypair(holder: &Keypair, nonce: &[u8; 32]) -> Result<Keypair, EnclaveError> {
	let h = holder.x_only_public_key().0;
	let t = tweak_scalar(&h, nonce)?;
	holder.add_xonly_tweak(secp(), &t).map_err(|_| EnclaveError::Tweak(h))
}

/// `<a> OP_CHECKSIGVERIFY <b> OP_CHECKSIG`, the enclave's leaf shape.
pub fn check_sig_pair(a: &XOnlyPublicKey, b: &XOnlyPublicKey) -> Script {
	Builder::new().push_slice(&a.serialize()).push_opcode(OP_CHECKSIGVERIFY)
		.push_slice(&b.serialize()).push_opcode(OP_CHECKSIG).into_script()
}

/// The holder's enclave for one asset, as an `enclave-1` record keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Enclave {
	/// `H`, the holder's registered key.
	pub holder: XOnlyPublicKey,
	/// `Kp`, the asset's policy key.
	pub policy: XOnlyPublicKey,
	/// `Ki`, the issuer's key, when the asset elected clawback.
	pub clawback: Option<XOnlyPublicKey>,
}

impl Enclave {
	/// The enclave's transfer leaf: `<H> OP_CHECKSIGVERIFY <Kp> OP_CHECKSIG`.
	pub fn transfer_script(&self) -> Script {
		check_sig_pair(&self.holder, &self.policy)
	}

	/// The claw leaf, `<Ki> OP_CHECKSIGVERIFY <Kp> OP_CHECKSIG`, where the
	/// asset elected clawback: the enclave's and the `enclave-1` leaf's alike.
	pub fn claw_script(&self) -> Option<Script> {
		self.clawback.map(|ki| check_sig_pair(&ki, &self.policy))
	}

	/// The enclave output: the transfer leaf alone, or the transfer and claw
	/// leaves at depth 1, under the NUMS key.
	pub fn taproot(&self) -> TapOutput {
		match self.claw_script() {
			None => TapOutput::new(vec![(0, self.transfer_script())]),
			Some(claw) => TapOutput::new(vec![(1, self.transfer_script()), (1, claw)]),
		}
	}

	/// `Q`, the enclave's witness v1 program.
	pub fn program(&self) -> [u8; 32] {
		self.taproot().program()
	}

	/// `OP_1 <Q>`.
	pub fn script_pubkey(&self) -> Script {
		self.taproot().script_pubkey()
	}

	/// `D = HASH160(Q)`, what the collaborative constant carries after `K`.
	pub fn digest(&self) -> [u8; DIGEST_BYTES] {
		hash160::Hash::hash(&self.program()).to_byte_array()
	}

	/// The terms a leaf of `value` of `asset` exits by.
	pub fn terms(&self, asset: AssetId, value: u64) -> EnclaveTerms {
		EnclaveTerms { enclave: *self, asset, value }
	}

	/// Whether `owner` is the holder's leaf key for `owner_nonce`.
	pub fn check_owner(&self, owner: &XOnlyPublicKey, owner_nonce: &[u8; 32]) -> Result<(), EnclaveError> {
		match enclave_key(&self.holder, owner_nonce) {
			Ok(k) if k == *owner => Ok(()),
			Ok(_) => Err(EnclaveError::NotTheHoldersKey { owner: *owner, holder: self.holder }),
			Err(e) => Err(e),
		}
	}

	/// The record's form: `H`, `Kp`, a clawback byte (0 or 1), and `Ki` when 1.
	pub fn write(&self, w: &mut Vec<u8>) {
		w.extend(self.holder.serialize());
		w.extend(self.policy.serialize());
		match &self.clawback {
			None => w.push(0),
			Some(k) => {
				w.push(1);
				w.extend(k.serialize());
			},
		}
	}
}

/// What an `enclave-1` leaf's scripts check: its enclave, its asset and its
/// value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnclaveTerms {
	pub enclave: Enclave,
	pub asset: AssetId,
	pub value: u64,
}

impl EnclaveTerms {
	/// Checks the terms against the output the leaf is paid.
	pub fn check_leaf(&self, asset: AssetId, value: u64) -> Result<(), EnclaveError> {
		if asset != self.asset {
			return Err(EnclaveError::Asset { terms: self.asset, leaf: asset });
		}
		if value != self.value {
			return Err(EnclaveError::Value { terms: self.value, leaf: value });
		}
		Ok(())
	}

	/// The exit for owner `A` and the exit delay.
	pub fn exit_script(&self, owner: &XOnlyPublicKey, delay: RelativeTime) -> Script {
		Builder::new().push_int(delay.to_sequence() as i64).ops(&[OP_CSV, OP_DROP])
			.push_int(0).push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.enclave.program()).push_opcode(OP_EQUALVERIFY)
			.push_int(0).push_opcode(OP_INSPECTOUTPUTASSET).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&asset_bytes(self.asset)).push_opcode(OP_EQUALVERIFY)
			.push_int(0).push_opcode(OP_INSPECTOUTPUTVALUE).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.value.to_le_bytes()).push_opcode(OP_EQUALVERIFY)
			.push_slice(&owner.serialize()).push_opcode(OP_CHECKSIG)
			.into_script()
	}

	/// The exit's output 0: the whole value at the holder's enclave.
	pub fn output(&self) -> ExplicitOutput {
		ExplicitOutput::new(self.asset, self.value, self.enclave.script_pubkey())
	}

	/// Checks `output` as the exit script will.
	pub fn check_output(&self, output: &ExplicitOutput) -> Result<(), EnclaveError> {
		if *output != self.output() {
			return Err(EnclaveError::Output { value: self.value });
		}
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use elements::secp256k1_zkp::SecretKey;

	fn key(b: u8) -> Keypair {
		Keypair::from_secret_key(secp(), &SecretKey::from_slice(&[b; 32]).unwrap())
	}

	#[test]
	fn the_leaf_key_is_the_holders() {
		let h = key(3);
		let n = [9u8; 32];
		let a = enclave_key(&h.x_only_public_key().0, &n).unwrap();
		assert_eq!(enclave_keypair(&h, &n).unwrap().x_only_public_key().0, a);
		let e = Enclave { holder: h.x_only_public_key().0, policy: key(4).x_only_public_key().0, clawback: None };
		assert!(e.check_owner(&a, &n).is_ok());
		assert!(e.check_owner(&a, &[8u8; 32]).is_err());
		assert!(e.check_owner(&h.x_only_public_key().0, &n).is_err());
	}

	#[test]
	fn the_policy_approval_is_tagged() {
		// SHA256(T ‖ T ‖ 0^32), T = SHA256("OpenAMP/tree-cosign"): pinned for
		// the policy server, which computes the same.
		let d = policy_cosign_digest(&[0u8; 32]);
		let t = sha256::Hash::hash(POLICY_COSIGN_TAG).to_byte_array();
		let mut b = t.to_vec();
		b.extend(t);
		b.extend([0u8; 32]);
		assert_eq!(d, sha256::Hash::hash(&b).to_byte_array());
		println!("policy_cosign_digest(0^32) = {}", d.iter().map(|x| format!("{:02x}", x)).collect::<String>());
	}

	#[test]
	fn the_exit_pays_the_whole_value() {
		let e = Enclave { holder: key(3).x_only_public_key().0, policy: key(4).x_only_public_key().0, clawback: Some(key(5).x_only_public_key().0) };
		let a = AssetId::from_slice(&[7; 32]).unwrap();
		let t = e.terms(a, 10_000);
		assert!(t.check_output(&t.output()).is_ok());
		assert!(t.check_output(&ExplicitOutput::new(a, 9_999, e.script_pubkey())).is_err());
		assert_eq!(e.script_pubkey().len(), 34);
		assert_ne!(e.program(), Enclave { clawback: None, ..e }.program());
		assert_eq!(e.claw_script().unwrap().len(), 68);
	}
}
