//! `landing-1`: the leaf of a supervised asset, with the forced landing.
//!
//! A supervised asset is one whose issuer can freeze holdings by consensus
//! rule (the node's supervision descriptor, committed in the asset id). A
//! freeze binds only single-owner spends (P2WPKH, a taproot key path): every
//! Arca output is spent by a script path, so no freeze ever reaches the tree
//! itself. `landing-1` brings the freeze back to the holder: its unilateral
//! path pays only a single-owner output of the owner's own key, where the
//! freeze binds. Both script leaves are at depth 1:
//!
//! ```text
//! collab:   the leaf's collaborative path, pushing K ‖ P, K = SHA256(SHA256("ArcaRbd1" ‖ genesis) ‖ salt)
//! landing:  <delay> OP_CHECKSEQUENCEVERIFY OP_DROP
//!           OP_0 OP_INSPECTOUTPUTSCRIPTPUBKEY OP_0 OP_EQUALVERIFY <P> OP_EQUALVERIFY
//!           OP_0 OP_INSPECTOUTPUTASSET OP_1 OP_EQUALVERIFY <asset> OP_EQUALVERIFY
//!           OP_0 OP_INSPECTOUTPUTVALUE OP_1 OP_EQUALVERIFY <min, u64 LE> OP_GREATERTHANOREQUAL64 OP_VERIFY
//!           <A> OP_CHECKSIG
//! ```
//!
//! `P` is the landing program, `hash160(L)` of the owner's landing key `L`, a
//! compressed key the owner names when the leaf is built: the landing pays
//! `P2WPKH(L)` (witness version 0, `P`), explicitly in the leaf's asset,
//! holding at least `min`, the leaf's value less the fee allowance; the rest
//! pays the fee, or anything up to the allowance. The landing's witness is the
//! owner's signature over the claim, a version 2 transaction whose input
//! sequence is the exit delay. With a 512-second delay the script is 119
//! bytes.
//!
//! The collaborative script pushes `K ‖ P` where another leaf's pushes `K`
//! ([`crate::Chain::landing_prefix`]), so its rebindable message is
//! `SHA256(K ‖ P ‖ …)`. A rebindable signature binds that message, not the
//! leaf's script, so a pair made for one landing spends only a leaf that
//! lands there: an operator's signer, given `P`, checks the freeze of the key
//! the coin truly lands in, and a request that names another landing gets a
//! signature that spends nothing. `K` is the salt's own, so two messages the
//! operator signs under the leaf's salt are evidence to its equivocation bond
//! as for any coin ([`crate::bond`]).
//!
//! A record keeps the landing as [`Landing`]: `P` and the allowance. The
//! script needs the minimum and the asset, which follow from the record's
//! asset and value ([`Landing::terms`]).
//!
//! A batch of a supervised asset holds `landing-1` leaves only, and every
//! output of every transaction that moves the asset is explicit, as consensus
//! requires ([`check_explicit`]).

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Script};

use crate::script::{asset_bytes, BuilderExt, ExplicitOutput};
use crate::time::RelativeTime;

/// The length of a landing program: `hash160` of a compressed key.
pub const PROGRAM_BYTES: usize = 20;

/// Why a landing cannot be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LandingError {
	#[error("a landing-1 leaf's allowance of {allowance} is not below its value of {value}: its landing would hold nothing")]
	Allowance { allowance: u64, value: u64 },
	#[error("a landing-1 leaf's terms name asset {terms}, and the leaf holds {leaf}")]
	Asset { terms: AssetId, leaf: AssetId },
	#[error("a landing-1 leaf's minimum of {min} is above its value of {value}")]
	Minimum { min: u64, value: u64 },
	#[error("the landing's output 0 is not P2WPKH of the landing program, explicitly in the leaf's asset, holding at least {min}")]
	Output { min: u64 },
	#[error("output {output} of a transaction moving a supervised asset is blinded: consensus keeps every output of one explicit")]
	Blinded { output: usize },
}

/// A `landing-1` leaf's landing, as its record keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Landing {
	/// `P = hash160(L)`.
	pub program: [u8; PROGRAM_BYTES],
	/// How much of the leaf's value the landing may leave out of its output 0:
	/// below the value.
	pub allowance: u64,
}

impl Landing {
	/// The script the landing pays, `OP_0 <P>`: P2WPKH of the landing key.
	pub fn script_pubkey(&self) -> Script {
		landing_script_pubkey(&self.program)
	}

	/// The terms a leaf of `value` of `asset` lands by.
	pub fn terms(&self, asset: AssetId, value: u64) -> Result<LandingTerms, LandingError> {
		if self.allowance >= value {
			return Err(LandingError::Allowance { allowance: self.allowance, value });
		}
		Ok(LandingTerms { program: self.program, asset, min_value: value - self.allowance })
	}
}

/// `OP_0 <program>`.
pub fn landing_script_pubkey(program: &[u8; PROGRAM_BYTES]) -> Script {
	Builder::new().push_int(0).push_slice(program).into_script()
}

/// What a `landing-1` leaf's landing script checks: where output 0 pays, in
/// what, and at least how much.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LandingTerms {
	/// `P = hash160(L)`.
	pub program: [u8; PROGRAM_BYTES],
	/// The leaf's asset.
	pub asset: AssetId,
	/// The least output 0 holds: the leaf's value less the allowance.
	pub min_value: u64,
}

impl LandingTerms {
	/// The record's form of these terms for a leaf of `asset` and `value`.
	pub fn landing(&self, asset: AssetId, value: u64) -> Result<Landing, LandingError> {
		if asset != self.asset {
			return Err(LandingError::Asset { terms: self.asset, leaf: asset });
		}
		if self.min_value > value || self.min_value == 0 {
			return Err(LandingError::Minimum { min: self.min_value, value });
		}
		Ok(Landing { program: self.program, allowance: value - self.min_value })
	}

	/// The landing script for owner `A` and the exit delay.
	pub fn script(&self, owner: &XOnlyPublicKey, delay: RelativeTime) -> Script {
		Builder::new().push_int(delay.to_sequence() as i64).ops(&[OP_CSV, OP_DROP])
			.push_int(0).push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY).push_int(0).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.program).push_opcode(OP_EQUALVERIFY)
			.push_int(0).push_opcode(OP_INSPECTOUTPUTASSET).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&asset_bytes(self.asset)).push_opcode(OP_EQUALVERIFY)
			.push_int(0).push_opcode(OP_INSPECTOUTPUTVALUE).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.min_value.to_le_bytes()).push_opcode(OP_GREATERTHANOREQUAL64).push_opcode(OP_VERIFY)
			.push_slice(&owner.serialize()).push_opcode(OP_CHECKSIG)
			.into_script()
	}

	/// The script the landing pays.
	pub fn script_pubkey(&self) -> Script {
		landing_script_pubkey(&self.program)
	}

	/// The landing's output 0, holding `value`.
	pub fn output(&self, value: u64) -> ExplicitOutput {
		ExplicitOutput::new(self.asset, value, self.script_pubkey())
	}

	/// Checks `output` as the landing script will: P2WPKH of `P`, in the
	/// asset, holding at least the minimum.
	pub fn check_output(&self, output: &ExplicitOutput) -> Result<(), LandingError> {
		if output.script_pubkey != self.script_pubkey() || output.asset != self.asset || output.value < self.min_value {
			return Err(LandingError::Output { min: self.min_value });
		}
		Ok(())
	}
}

/// The supervised profile's rule for a round of a supervised asset, or any
/// transaction that moves one: every output explicit in asset and value.
/// Consensus refuses such a transaction otherwise
/// (`bad-txns-supervised-blinded`): it cannot read a blinded output's asset,
/// so a supervised asset inside one could never be frozen. A wallet runs
/// this before it gives anything up for a round of a supervised asset.
pub fn check_explicit(tx: &elements::Transaction) -> Result<(), LandingError> {
	match tx.output.iter().position(|o| o.asset.explicit().is_none() || o.value.explicit().is_none()) {
		Some(output) => Err(LandingError::Blinded { output }),
		None => Ok(()),
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn the_allowance_is_below_the_value() {
		let a = AssetId::from_slice(&[7; 32]).unwrap();
		let l = Landing { program: [1; 20], allowance: 2_000 };
		assert_eq!(l.terms(a, 10_000).unwrap().min_value, 8_000);
		assert!(matches!(l.terms(a, 2_000), Err(LandingError::Allowance { .. })));
		let t = l.terms(a, 10_000).unwrap();
		assert_eq!(t.landing(a, 10_000).unwrap(), l);
		assert!(t.landing(AssetId::from_slice(&[8; 32]).unwrap(), 10_000).is_err());
		assert!(t.check_output(&t.output(8_000)).is_ok());
		assert!(t.check_output(&t.output(7_999)).is_err());
		assert_eq!(t.script_pubkey().len(), 22);
	}
}
