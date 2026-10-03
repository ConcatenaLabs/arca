//! The sweep, behind the token.
//!
//! The right to sweep a batch is one atom of an asset `T`, issued by the round
//! into the batch's first clock. A sweep path holds no time lock of its own: it
//! requires, as another input of the same transaction, the atom resting at the
//! script `R`, where it arrives only through a clock's RELEASE. It checks the
//! script that holds the atom, not merely the asset, because a roll also spends
//! the atom.
//!
//! ```text
//! # witness, bottom to top: <sig_S> <k>, k the index of the input that carries T
//! OP_DUP OP_INSPECTINPUTASSET OP_1 OP_EQUALVERIFY <T> OP_EQUALVERIFY
//! OP_INSPECTINPUTSCRIPTPUBKEY OP_1 OP_EQUALVERIFY <R> OP_EQUALVERIFY
//! [<W> OP_CHECKSEQUENCEVERIFY OP_DROP]          # with notice
//! [burn body]                                   # issuer-operated batches
//! <S> OP_CHECKSIG
//! ```
//!
//! The batch output's sweep has no notice of its own: the token's wait at `R`
//! is the notice. Every other output above a leaf (inner and lowest nodes,
//! entries, checkpoints) adds `<W> OP_CHECKSEQUENCEVERIFY`, so an output that
//! first appears during or after the notice still gets `W` from its own
//! confirmation.
//!
//! The burn body lets the operator spend only into a bare `OP_RETURN` at the
//! input's own index, carrying the input's full amount of the input's asset.
//!
//! # The sweep transaction
//!
//! [`sweep_tx`] builds one wave of a batch's sweep: every output it takes
//! ([`Sweepable`]: the batch output, a node, an entry or a checkpoint) by its
//! sweep leaf, at inputs `0..n`, and the token resting at `R`, at input `n`,
//! which each sweep's `k` names. The token goes back to `R` after the outputs
//! the operator pays, where it waits `W` again before the next wave. Each
//! swept input carries its own notice as its sequence (none on the batch
//! output), so an output that went on-chain late is swept only `W` after its
//! own confirmation. A burn-only sweep pays the burns itself: an `OP_RETURN`
//! of each input's whole amount at the input's own index, its fee from a
//! coin attached. The operator signs every input ([`SweepTx::sighash`]); the
//! signatures commit to the whole transaction.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxOut};

use crate::checkpoint::CheckpointPolicy;
use crate::clock::ClockSchedule;
use crate::entry::EntryPolicy;
use crate::node::NodePolicy;
use crate::record::BranchNode;
use crate::script::{asset_bytes, scriptnum, sha256, BuilderExt, ExplicitOutput};
use crate::sign::script_spend_sighash;
use crate::spend::{assemble, explicit_txout, FeeSource, SpendError, UnrollTx, FEE_COIN_SEQUENCE};
use crate::taptree::TapOutput;
use crate::time::RelativeTime;
use crate::Error;

/// A sweep path of one output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sweep {
	/// The sweep token's asset.
	pub token: AssetId,
	/// The witness program of `R`.
	pub r_program: [u8; 32],
	/// The operator's key `S`.
	pub operator: XOnlyPublicKey,
	/// The notice `W` this output waits after its own confirmation; `None`
	/// for the batch output.
	pub notice: Option<RelativeTime>,
	/// Burn-only: the swept value can only be destroyed.
	pub burn: bool,
}

impl Sweep {
	/// The script leaf.
	pub fn script(&self) -> Script {
		let mut b = Builder::new()
			.ops(&[OP_DUP, OP_INSPECTINPUTASSET]).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&asset_bytes(self.token)).push_opcode(OP_EQUALVERIFY)
			.push_opcode(OP_INSPECTINPUTSCRIPTPUBKEY).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.r_program).push_opcode(OP_EQUALVERIFY);
		if let Some(w) = self.notice {
			b = b.push_int(w.to_sequence() as i64).ops(&[OP_CSV, OP_DROP]);
		}
		if self.burn {
			b = b
				.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTVALUE]).push_int(1).push_opcode(OP_EQUALVERIFY)
				.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTVALUE]).push_int(1)
				.ops(&[OP_EQUALVERIFY, OP_EQUALVERIFY])
				.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTASSET]).push_int(1).push_opcode(OP_EQUALVERIFY)
				.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTASSET]).push_int(1)
				.ops(&[OP_EQUALVERIFY, OP_EQUALVERIFY])
				.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTSCRIPTPUBKEY]).push_int(-1)
				.push_opcode(OP_EQUALVERIFY)
				.push_slice(&sha256(&[OP_RETURN.into_u8()])).push_opcode(OP_EQUALVERIFY);
		}
		b.push_slice(&self.operator.serialize()).push_opcode(OP_CHECKSIG).into_script()
	}

	/// The witness items below the script: the operator's signature over the
	/// sweep transaction, and `k`, the index of the input holding the token.
	pub fn witness_items(sig: &Signature, k: u32) -> Vec<Vec<u8>> {
		vec![sig.as_ref().to_vec(), scriptnum(k as i64)]
	}

	/// The sequence this output's input must carry: the notice, or a
	/// non-final sequence when there is none.
	pub fn sequence(&self) -> u32 {
		self.notice.map(|w| w.to_sequence()).unwrap_or(0xffff_fffe)
	}
}

/// An output a sweep takes: where it is, its asset and value, the taproot it
/// was built as and the sweep leaf it carries.
#[derive(Debug, Clone)]
pub struct Sweepable {
	pub outpoint: OutPoint,
	pub asset: AssetId,
	pub value: u64,
	pub tap: TapOutput,
	pub sweep: Sweep,
}

impl Sweepable {
	pub fn new(outpoint: OutPoint, (asset, value): (AssetId, u64), tap: TapOutput, sweep: Sweep) -> Sweepable {
		Sweepable { outpoint, asset, value, tap, sweep }
	}

	/// The output, as the transaction that created it pays it.
	pub fn txout(&self) -> TxOut {
		explicit_txout(self.asset, self.value, self.tap.script_pubkey())
	}
}

impl NodePolicy {
	/// This node, held at `outpoint` with `value`, as a sweep takes it.
	pub fn sweepable(&self, outpoint: OutPoint, value: u64) -> Sweepable {
		Sweepable::new(outpoint, (self.children()[0].asset, value), self.taproot(), *self.sweep())
	}
}

impl BranchNode {
	/// This node, held at `outpoint`, as a sweep takes it.
	pub fn sweepable(&self, outpoint: OutPoint) -> Sweepable {
		Sweepable::new(outpoint, (self.children[0].asset, self.value), self.taproot().clone(), self.sweep)
	}
}

impl EntryPolicy {
	/// This entry, held at `outpoint` with `value` (the leaf's value and the
	/// entry's reserve), as a sweep takes it.
	pub fn sweepable(&self, outpoint: OutPoint, value: u64) -> Sweepable {
		Sweepable::new(outpoint, (self.asset, value), self.taproot(), self.sweep)
	}
}

impl CheckpointPolicy {
	/// This checkpoint, held at `outpoint` with `value` of `asset`, as a
	/// sweep takes it.
	pub fn sweepable(&self, outpoint: OutPoint, asset: AssetId, value: u64) -> Sweepable {
		Sweepable::new(outpoint, (asset, value), self.taproot(), self.sweep)
	}
}

/// A sweep, built and waiting for the operator's signatures: one for each
/// swept output, then one for the token at `R`.
#[derive(Debug, Clone)]
pub struct SweepTx {
	pub tx: Transaction,
	/// The outputs the inputs spend, in input order.
	pub prevouts: Vec<TxOut>,
	/// The leaf each Arca input spends by, in input order: the swept
	/// outputs' sweeps, then `R`'s leaf for the token.
	pub leaves: Vec<Script>,
	taps: Vec<TapOutput>,
}

impl SweepTx {
	/// The input that holds the token, which every sweep's `k` names.
	pub fn token_input(&self) -> u32 {
		(self.leaves.len() - 1) as u32
	}

	/// The Elements taproot signature hash of input `input`, one of the
	/// swept outputs or the token, which the operator signs.
	pub fn sighash(&self, input: usize, genesis_hash: BlockHash) -> Result<[u8; 32], Error> {
		let leaf = self.leaves.get(input).ok_or(Error::InputIndex(input))?;
		script_spend_sighash(&self.tx, input, &self.prevouts, leaf, genesis_hash)
	}

	/// Puts the operator's signatures, one per entry of
	/// [`SweepTx::leaves`], on their inputs. A fee coin's witness is the
	/// operator's wallet's to add.
	pub fn finish(mut self, sigs: &[Signature]) -> Result<UnrollTx, SpendError> {
		if sigs.len() != self.leaves.len() {
			return Err(SpendError::SweepSignatures { given: sigs.len(), needed: self.leaves.len() });
		}
		let k = self.token_input();
		for (i, sig) in sigs.iter().enumerate() {
			let below = if i as u32 == k { ClockSchedule::r_witness_items(sig) } else { Sweep::witness_items(sig, k) };
			self.tx.input[i].witness.script_witness = self.taps[i].witness(&self.leaves[i], below);
		}
		Ok(UnrollTx { tx: self.tx, prevouts: self.prevouts })
	}
}

/// The script of an `OP_RETURN` a burn-only sweep pays.
fn burn_script() -> Script {
	Script::from(vec![OP_RETURN.into_u8()])
}

/// One wave of a batch's sweep: see the [module documentation](self).
/// `swept` are the outputs taken, each under `schedule`'s token, `R` and
/// operator, at inputs `0..n`; `token` is the token at `R`, at input `n`;
/// `outputs` are what the operator pays itself, then the token goes back to
/// `R`, and what the swept outputs hold beyond `outputs` pays the fee as `fee`
/// says. A burn-only sweep takes no `outputs`: it pays each input's whole
/// amount to an `OP_RETURN` at the input's index, and `fee` must be a coin.
pub fn sweep_tx(
	schedule: &ClockSchedule,
	token: OutPoint,
	swept: &[Sweepable],
	outputs: &[ExplicitOutput],
	fee: &FeeSource,
) -> Result<SweepTx, SpendError> {
	if swept.is_empty() {
		return Err(SpendError::NothingToSweep);
	}
	let r = schedule.r();
	for (i, s) in swept.iter().enumerate() {
		let w = &s.sweep;
		if w.token != schedule.token || w.r_program != r.program() || w.operator != schedule.operator
			|| w.notice.is_some_and(|n| n != schedule.notice)
		{
			return Err(SpendError::OtherBatch(i));
		}
		if s.tap.control_block(&w.script()).is_none() {
			return Err(SpendError::NotSweepable(i));
		}
	}
	let burn = swept[0].sweep.burn;
	if swept.iter().any(|s| s.sweep.burn != burn) {
		return Err(SpendError::MixedBurn);
	}
	let mut all: Vec<ExplicitOutput> = if burn {
		if !outputs.is_empty() {
			return Err(SpendError::BurnOutputs);
		}
		if !matches!(fee, FeeSource::Coin { .. }) {
			return Err(SpendError::NeedsFeeCoin("a burn-only sweep"));
		}
		swept.iter().map(|s| ExplicitOutput::new(s.asset, s.value, burn_script())).collect()
	} else {
		outputs.to_vec()
	};
	all.push(ExplicitOutput::new(schedule.token, 1, r.script_pubkey()));
	let w = Sequence(schedule.notice.to_sequence());
	let mut inputs: Vec<(OutPoint, TxOut, Sequence)> =
		swept.iter().map(|s| (s.outpoint, s.txout(), Sequence(s.sweep.sequence()))).collect();
	inputs.push((token, ExplicitOutput::new(schedule.token, 1, r.script_pubkey()).txout(), w));
	let u = assemble(LockTime::ZERO, inputs, &all, fee, FEE_COIN_SEQUENCE)?;
	let mut leaves: Vec<Script> = swept.iter().map(|s| s.sweep.script()).collect();
	leaves.push(schedule.r_script());
	let mut taps: Vec<TapOutput> = swept.iter().map(|s| s.tap.clone()).collect();
	taps.push(r);
	Ok(SweepTx { tx: u.tx, prevouts: u.prevouts, leaves, taps })
}
