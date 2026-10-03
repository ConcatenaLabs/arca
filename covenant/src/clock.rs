//! The expiry clock.
//!
//! The sweep token `T` moves through a chain of clock outputs, each a taproot
//! output with the NUMS internal key. Clock `j` holds two leaves; the last
//! clock holds RELEASE only:
//!
//! ```text
//! ROLL(j):    <S> OP_CHECKSIGVERIFY <pin: the output at this input's index is (T, 1 atom, clock j+1)>
//! RELEASE(j): <E_j> OP_CHECKLOCKTIMEVERIFY OP_DROP <S> OP_CHECKSIGVERIFY <pin: (T, 1 atom, R)>
//! R:          <W> OP_CHECKSEQUENCEVERIFY OP_DROP <S> OP_CHECKSIG
//! ```
//!
//! where a pin hashes the record of the output at the spending input's own
//! index and compares it with one constant, so the clocks of several batches
//! can move in one transaction. The chain is built in advance for a fixed
//! number of steps, last clock first, so it needs no state. The current expiry
//! is the `E` of whichever clock holds `T`; a release starts the notice `W` at
//! `R`, and every sweep spends `T` from `R`.
//!
//! The operator moves the token with [`ClockSchedule::release_tx`] at a
//! clock's expiry, or [`ClockSchedule::roll_tx`] to extend the batch, and reads
//! where it rests from the script of the output holding it
//! ([`ClockSchedule::place`]). The token holds one atom and nothing for a fee,
//! so a fee coin is attached to every move.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, LockTime, OutPoint, Script};

use crate::script::{record, sha256, BuilderExt, ExplicitOutput};
use crate::spend::{assemble, FeeSource, KeySpend, SpendError, FEE_COIN_SEQUENCE};
use crate::sweep::Sweep;
use crate::taptree::TapOutput;
use crate::time::{MedianTime, RelativeTime};
use crate::Error;

/// The most steps a schedule may have.
pub const MAX_STEPS: usize = 64;

/// The published schedule of a batch's clock: `(T, S, W, E_0 … E_K)`, from
/// which `R` and every clock are rebuilt.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClockSchedule {
	pub token: AssetId,
	pub operator: XOnlyPublicKey,
	pub notice: RelativeTime,
	expiries: Vec<MedianTime>,
}

/// Where a batch's token rests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenPlace {
	/// At clock `step`: the batch expires at that clock's `E`.
	Clock(usize),
	/// At `R`: released, so every sweep of the batch spends it from here.
	Released,
}

/// One clock output.
#[derive(Debug, Clone)]
pub struct Clock {
	pub step: usize,
	pub expiry: MedianTime,
	/// ROLL into the next clock; `None` for the last clock.
	pub roll: Option<Script>,
	pub release: Script,
	pub output: TapOutput,
}

impl ClockSchedule {
	/// A schedule whose expiries never move earlier, as an honest operator
	/// publishes it.
	pub fn new(
		token: AssetId,
		operator: XOnlyPublicKey,
		notice: RelativeTime,
		expiries: Vec<MedianTime>,
	) -> Result<ClockSchedule, Error> {
		let s = ClockSchedule::new_unchecked(token, operator, notice, expiries)?;
		if let Some(i) = s.backwards_at() {
			return Err(Error::ScheduleBackwards { index: i });
		}
		Ok(s)
	}

	/// A schedule in any order. Consensus accepts a clock chain that runs
	/// backwards, and a wallet must refuse one ([`crate::checks`]); this builds
	/// it, for that check and its tests.
	pub fn new_unchecked(
		token: AssetId,
		operator: XOnlyPublicKey,
		notice: RelativeTime,
		expiries: Vec<MedianTime>,
	) -> Result<ClockSchedule, Error> {
		if expiries.is_empty() {
			return Err(Error::EmptySchedule);
		}
		if expiries.len() > MAX_STEPS {
			return Err(Error::TooManySteps);
		}
		Ok(ClockSchedule { token, operator, notice, expiries })
	}

	pub fn expiries(&self) -> &[MedianTime] {
		&self.expiries
	}

	/// The index of the first expiry earlier than the one before it.
	pub fn backwards_at(&self) -> Option<usize> {
		self.expiries.windows(2).position(|w| w[1] < w[0]).map(|i| i + 1)
	}

	/// `R`'s only leaf: `<W> OP_CHECKSEQUENCEVERIFY OP_DROP <S> OP_CHECKSIG`.
	pub fn r_script(&self) -> Script {
		Builder::new().push_int(self.notice.to_sequence() as i64).ops(&[OP_CSV, OP_DROP])
			.push_slice(&self.operator.serialize()).push_opcode(OP_CHECKSIG).into_script()
	}

	/// `R`: where the token rests once released.
	pub fn r(&self) -> TapOutput {
		TapOutput::new(vec![(0, self.r_script())])
	}

	/// The witness items below `R`'s script: the operator's signature.
	pub fn r_witness_items(sig: &Signature) -> Vec<Vec<u8>> {
		vec![sig.as_ref().to_vec()]
	}

	/// Every clock, from the first; built from the last one back.
	pub fn clocks(&self) -> Vec<Clock> {
		let r_spk = self.r().script_pubkey();
		let mut out: Vec<Clock> = Vec::with_capacity(self.expiries.len());
		let mut next: Option<Script> = None;
		for (j, e) in self.expiries.iter().enumerate().rev() {
			let release = self.pinned(Some(*e), &r_spk);
			let (roll, output) = match next {
				Some(ref next_spk) => {
					let roll = self.pinned(None, next_spk);
					let output = TapOutput::new(vec![(1, roll.clone()), (1, release.clone())]);
					(Some(roll), output)
				},
				None => (None, TapOutput::new(vec![(0, release.clone())])),
			};
			next = Some(output.script_pubkey());
			out.push(Clock { step: j, expiry: *e, roll, release, output });
		}
		out.reverse();
		out
	}

	/// The first clock's scriptPubKey: where the round pays the token.
	pub fn clock0_script_pubkey(&self) -> Script {
		self.clocks().swap_remove(0).output.script_pubkey()
	}

	/// The sweep path every output of this batch carries: with the notice for
	/// every output but the batch output, burn-only for an issuer-operated
	/// batch.
	pub fn sweep(&self, with_notice: bool, burn: bool) -> Sweep {
		Sweep {
			token: self.token,
			r_program: self.r().program(),
			operator: self.operator,
			notice: if with_notice { Some(self.notice) } else { None },
			burn,
		}
	}

	/// Where an output paying `script_pubkey` would hold the token: at one of
	/// the clocks, at `R`, or at neither (`None`).
	pub fn place(&self, script_pubkey: &Script) -> Option<TokenPlace> {
		if *script_pubkey == self.r().script_pubkey() {
			return Some(TokenPlace::Released);
		}
		self.clocks().iter().position(|c| c.output.script_pubkey() == *script_pubkey).map(TokenPlace::Clock)
	}

	/// The operator's release of clock `step`, which holds the token at
	/// `token`: the token moves to `R` at output 0, where the notice `W`
	/// begins. The lock time is the clock's expiry `E` and the token's input
	/// non-final, as RELEASE's `OP_CHECKLOCKTIMEVERIFY` needs, so the release
	/// confirms only once the chain's median time has passed `E`. `fee` must
	/// be a fee coin. The operator signs [`KeySpend::sighash`] and finishes
	/// it with [`Clock::witness_items`].
	pub fn release_tx(&self, step: usize, token: OutPoint, fee: &FeeSource) -> Result<KeySpend, SpendError> {
		self.move_tx(step, token, false, fee)
	}

	/// The operator's roll of clock `step`, which holds the token at `token`,
	/// into clock `step + 1`, at output 0: the batch's expiry moves to that
	/// clock's `E`, and no script of the tree changes. `fee` must be a fee
	/// coin. Signed and finished as [`ClockSchedule::release_tx`].
	pub fn roll_tx(&self, step: usize, token: OutPoint, fee: &FeeSource) -> Result<KeySpend, SpendError> {
		self.move_tx(step, token, true, fee)
	}

	fn move_tx(&self, step: usize, token: OutPoint, roll: bool, fee: &FeeSource) -> Result<KeySpend, SpendError> {
		if matches!(fee, FeeSource::Reserve) {
			return Err(SpendError::NeedsFeeCoin("the token"));
		}
		let clocks = self.clocks();
		let c = clocks.get(step).ok_or(SpendError::ClockStep { step, steps: clocks.len() })?;
		let (script, to, lock) = if roll {
			let script = c.roll.clone().ok_or(SpendError::LastClock(step))?;
			(script, clocks[step + 1].output.script_pubkey(), LockTime::ZERO)
		} else {
			(c.release.clone(), self.r().script_pubkey(), LockTime::from_consensus(c.expiry.to_consensus_u32()))
		};
		let spent = ExplicitOutput::new(self.token, 1, c.output.script_pubkey()).txout();
		let u = assemble(lock, vec![(token, spent, FEE_COIN_SEQUENCE)], &[ExplicitOutput::new(self.token, 1, to)], fee, FEE_COIN_SEQUENCE)?;
		Ok(KeySpend::from_parts(u.tx, u.prevouts, c.output.clone(), script))
	}

	/// `[<E> CLTV DROP] <S> CHECKSIGVERIFY <pin (T, 1, to_spk)>`.
	fn pinned(&self, expiry: Option<MedianTime>, to_spk: &Script) -> Script {
		let mut b = Builder::new();
		if let Some(e) = expiry {
			b = b.push_int(e.to_consensus_u32() as i64).ops(&[OP_CLTV, OP_DROP]);
		}
		b.push_slice(&self.operator.serialize()).push_opcode(OP_CHECKSIGVERIFY)
			.current_output_record().push_opcode(OP_SHA256)
			.push_slice(&sha256(&record(self.token, 1, to_spk))).push_opcode(OP_EQUAL)
			.into_script()
	}
}

impl Clock {
	/// The witness items below ROLL's or RELEASE's script: the operator's
	/// signature. A release transaction sets `nLockTime` to at least the
	/// clock's expiry and a non-final sequence on this input.
	pub fn witness_items(sig: &Signature) -> Vec<Vec<u8>> {
		vec![sig.as_ref().to_vec()]
	}
}
