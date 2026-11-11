//! `landing-1` and `landing-2`: the leaf of a supervised asset, with the
//! forced landing.
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
//! # `landing-2`: the landing at the coin's own position
//!
//! `landing-1`'s landing inspects output 0, whatever input the coin is. Two
//! `landing-1` coins of one holder, spent together, are both satisfied by one
//! output 0 that holds one coin's worth, and the other coin's value leaves
//! past the landing key, where the issuer's freeze binds. `landing-2` is the
//! same leaf whose landing inspects the output at the spending input's own
//! index (`OP_PUSHCURRENTINPUTINDEX` where `landing-1` pushes 0), so two
//! landings spent together each need an output of their own:
//!
//! ```text
//! landing:  <delay> OP_CHECKSEQUENCEVERIFY OP_DROP
//!           OP_PUSHCURRENTINPUTINDEX OP_INSPECTOUTPUTSCRIPTPUBKEY OP_0 OP_EQUALVERIFY <P> OP_EQUALVERIFY
//!           OP_PUSHCURRENTINPUTINDEX OP_INSPECTOUTPUTASSET OP_1 OP_EQUALVERIFY <asset> OP_EQUALVERIFY
//!           OP_PUSHCURRENTINPUTINDEX OP_INSPECTOUTPUTVALUE OP_1 OP_EQUALVERIFY <min, u64 LE> OP_GREATERTHANOREQUAL64 OP_VERIFY
//!           <A> OP_CHECKSIG
//! ```
//!
//! It is the same 119 bytes with a 512-second delay, the same script as a
//! checkpoint's landing ([`LandingTerms::script_at_own_index`]), and
//! everything else about the leaf is `landing-1`'s: the collaborative path,
//! its prefix `K ‖ P`, the record's fields. [`Landing::own_index`] and
//! [`LandingTerms::own_index`] say which of the two a landing is.
//!
//! A `landing-1` coin keeps its script: it is committed in the tree, so it
//! lands at output 0 until it leaves, and a holder whose coins include one can
//! still spend it beside any other spend that pays its landing at output 0
//! (another `landing-1` coin, a `landing-2` coin or a checkpoint's landing at
//! input 0). Only refreshing it into a `landing-2` leaf ends that.
//!
//! A batch of a supervised asset holds landing leaves only, and every output
//! of every transaction that moves the asset is explicit, as consensus
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
	#[error("the landing's output is not P2WPKH of the landing program, explicitly in the leaf's asset, holding at least {min}")]
	Output { min: u64 },
	#[error("output {output} of a transaction moving a supervised asset is blinded: consensus keeps every output of one explicit")]
	Blinded { output: usize },
}

/// A landing leaf's landing, as its record keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Landing {
	/// `P = hash160(L)`.
	pub program: [u8; PROGRAM_BYTES],
	/// How much of the leaf's value the landing may leave out of its output:
	/// below the value.
	pub allowance: u64,
	/// `landing-2`: the landing inspects the output at the spending input's
	/// own index. `false` for `landing-1`, whose landing inspects output 0.
	pub own_index: bool,
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
		Ok(LandingTerms { program: self.program, asset, min_value: value - self.allowance, own_index: self.own_index })
	}

	/// The template of a leaf with this landing: `landing-2` when it lands at
	/// its own index, else `landing-1`.
	pub fn template(&self) -> crate::Template {
		if self.own_index { crate::Template::Landing2 } else { crate::Template::Landing1 }
	}
}

/// `OP_0 <program>`.
pub fn landing_script_pubkey(program: &[u8; PROGRAM_BYTES]) -> Script {
	Builder::new().push_int(0).push_slice(program).into_script()
}

/// What a landing script checks: where its output pays, in what, and at
/// least how much.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LandingTerms {
	/// `P = hash160(L)`.
	pub program: [u8; PROGRAM_BYTES],
	/// The leaf's asset.
	pub asset: AssetId,
	/// The least the landing's output holds: the leaf's value less the
	/// allowance.
	pub min_value: u64,
	/// The output inspected is the one at the spending input's own index
	/// (`landing-2`, and every checkpoint's landing); output 0 when `false`
	/// (`landing-1`).
	pub own_index: bool,
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
		Ok(Landing { program: self.program, allowance: value - self.min_value, own_index: self.own_index })
	}

	/// The leaf's landing script for owner `A` and the exit delay: at the
	/// spending input's own index for `landing-2`
	/// ([`Self::script_at_own_index`]), at output 0 for `landing-1`
	/// ([`Self::script_at_zero`]).
	pub fn script(&self, owner: &XOnlyPublicKey, delay: RelativeTime) -> Script {
		if self.own_index { self.script_at_own_index(owner, delay) } else { self.script_at_zero(owner, delay) }
	}

	/// `landing-1`'s landing script for owner `A` and the exit delay: it
	/// inspects output 0, whatever input the coin is.
	pub fn script_at_zero(&self, owner: &XOnlyPublicKey, delay: RelativeTime) -> Script {
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

	/// The landing script of a `landing-2` leaf, and of a checkpoint's exit
	/// ([`crate::checkpoint`]) for either landing leaf, for owner `A` and the
	/// exit delay: [`Self::script_at_zero`] with each output it inspects the
	/// one at the spending input's own index (`OP_PUSHCURRENTINPUTINDEX`
	/// where `landing-1` pushes 0), so two landings spent together can never
	/// share one output and carry the other coin's value past the landing
	/// key, where the issuer's freeze binds. The same 119 bytes with a
	/// 512-second delay.
	pub fn script_at_own_index(&self, owner: &XOnlyPublicKey, delay: RelativeTime) -> Script {
		Builder::new().push_int(delay.to_sequence() as i64).ops(&[OP_CSV, OP_DROP])
			.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTSCRIPTPUBKEY]).push_int(0).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.program).push_opcode(OP_EQUALVERIFY)
			.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTASSET]).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&asset_bytes(self.asset)).push_opcode(OP_EQUALVERIFY)
			.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTVALUE]).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.min_value.to_le_bytes()).push_opcode(OP_GREATERTHANOREQUAL64).push_opcode(OP_VERIFY)
			.push_slice(&owner.serialize()).push_opcode(OP_CHECKSIG)
			.into_script()
	}

	/// The script the landing pays.
	pub fn script_pubkey(&self) -> Script {
		landing_script_pubkey(&self.program)
	}

	/// The landing's output, holding `value`.
	pub fn output(&self, value: u64) -> ExplicitOutput {
		ExplicitOutput::new(self.asset, value, self.script_pubkey())
	}

	/// The index of the output the landing of a coin spent at input `input`
	/// inspects: `input` for `landing-2`, 0 for `landing-1`.
	pub fn output_index(&self, input: usize) -> usize {
		if self.own_index { input } else { 0 }
	}

	/// Checks the output the landing of a coin spent at input `input`
	/// inspects among `outputs`, as the landing script will.
	pub fn check_outputs(&self, input: usize, outputs: &[ExplicitOutput]) -> Result<(), LandingError> {
		let o = outputs.get(self.output_index(input)).ok_or(LandingError::Output { min: self.min_value })?;
		self.check_output(o)
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
		let l = Landing { program: [1; 20], allowance: 2_000, own_index: false };
		assert_eq!(l.terms(a, 10_000).unwrap().min_value, 8_000);
		assert!(matches!(l.terms(a, 2_000), Err(LandingError::Allowance { .. })));
		let t = l.terms(a, 10_000).unwrap();
		assert_eq!(t.landing(a, 10_000).unwrap(), l);
		assert!(t.landing(AssetId::from_slice(&[8; 32]).unwrap(), 10_000).is_err());
		assert!(t.check_output(&t.output(8_000)).is_ok());
		assert!(t.check_output(&t.output(7_999)).is_err());
		assert_eq!(t.script_pubkey().len(), 22);
	}

	#[test]
	fn landing_2_inspects_its_own_index_in_the_same_bytes() {
		let a = AssetId::from_slice(&[7; 32]).unwrap();
		let owner = XOnlyPublicKey::from_slice(&[
			0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
			0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98]).unwrap();
		let delay = RelativeTime::from_units(1).unwrap();
		let one = Landing { program: [1; 20], allowance: 2_000, own_index: false }.terms(a, 10_000).unwrap();
		let two = LandingTerms { own_index: true, ..one };
		assert_eq!(one.script(&owner, delay), one.script_at_zero(&owner, delay));
		assert_eq!(two.script(&owner, delay), two.script_at_own_index(&owner, delay));
		assert_eq!(one.script(&owner, delay).len(), 119);
		assert_eq!(two.script(&owner, delay).len(), 119);
		assert_ne!(one.script(&owner, delay), two.script(&owner, delay));
		assert_eq!(two.landing(a, 10_000).unwrap().template(), crate::Template::Landing2);
		assert_eq!(one.landing(a, 10_000).unwrap().template(), crate::Template::Landing1);
		let outs = [ExplicitOutput::new(a, 1, Script::new()), two.output(8_000)];
		assert!(two.check_outputs(1, &outs).is_ok());
		assert!(two.check_outputs(0, &outs).is_err());
		assert!(one.check_outputs(1, &outs).is_err());
		assert!(two.check_outputs(2, &outs).is_err());
	}
}
