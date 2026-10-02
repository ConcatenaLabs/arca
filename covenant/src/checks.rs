//! The five checks a wallet runs before it accepts a leaf.
//!
//! Consensus does not stop an operator from building a dishonest clock. Each
//! of these answers an attack that consensus accepts and that swept a batch
//! before its advertised expiry on regtest: a second atom issued straight to
//! `R`, the only atom issued to `R`, an atom reissued to `R`, and a clock chain
//! whose second step expires earlier than its first. Given the round
//! transaction and the published schedule `(T, R, S, W, E_0 … E_K)`:
//!
//! 1. `T` is issued as exactly one atom.
//! 2. The issuance is explicit.
//! 3. The issuance creates no reissuance token, and nothing reissues `T`.
//! 4. The atom is paid to one output, not at `R`, and no other output carries
//!    `T` or an asset the wallet cannot see.
//! 5. That output's script is clock 0 rebuilt from the published schedule;
//!    every sweep path above the leaf names that `T`, `S` and `R` rebuilt from
//!    `W` and `S`, and a notice that is `W` or, on the batch output, none; and
//!    `E_0 ≤ E_1 ≤ … ≤ E_K`.
//!
//! The fifth matters most: the later clocks are hidden inside the first
//! clock's taproot commitment, and nothing in the round transaction shows them.

use elements::confidential::Value;
use elements::secp256k1_zkp::ZERO_TWEAK;
use elements::Transaction;

use crate::clock::ClockSchedule;
use crate::sweep::Sweep;

/// The check a round failed, and why.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoundCheckFailure {
	#[error("check 1: no input of the round issues the token")]
	NotIssued,
	#[error("check 1: the token is issued as {0} atoms, not one")]
	NotOneAtom(u64),
	#[error("check 2: the token's issued amount is not explicit")]
	NotExplicit,
	#[error("check 3: the issuance creates a reissuance token")]
	ReissuanceToken,
	#[error("check 3: input {0} reissues the token")]
	Reissued(usize),
	#[error("check 4: the token is in {0} outputs, not one")]
	TokenOutputs(usize),
	#[error("check 4: the token's output does not hold one explicit atom")]
	TokenOutputNotOneAtom,
	#[error("check 4: output {0} has a blinded asset, which could hold the token")]
	BlindedOutput(usize),
	#[error("check 4: the token is paid straight to R, released before any expiry")]
	TokenAtR,
	#[error("check 5: the token is not paid to clock 0 rebuilt from the published schedule")]
	NotClockZero,
	#[error("check 5: sweep path {0} does not name the schedule's token, operator, R and notice")]
	SweepMismatch(usize),
	#[error("check 5: the schedule runs backwards at step {0}")]
	ScheduleBackwards(usize),
}

impl RoundCheckFailure {
	/// The number of the check, 1 to 5.
	pub fn check(&self) -> u8 {
		use RoundCheckFailure::*;
		match self {
			NotIssued | NotOneAtom(_) => 1,
			NotExplicit => 2,
			ReissuanceToken | Reissued(_) => 3,
			TokenOutputs(_) | TokenOutputNotOneAtom | BlindedOutput(_) | TokenAtR => 4,
			NotClockZero | SweepMismatch(_) | ScheduleBackwards(_) => 5,
		}
	}
}

/// Runs the five checks on `round` against the published `schedule` and the
/// sweep paths of every output above the leaf (`sweeps`). Returns the first
/// check that fails, in order.
pub fn check_round(round: &Transaction, schedule: &ClockSchedule, sweeps: &[Sweep]) -> Result<(), RoundCheckFailure> {
	let token = schedule.token;

	// Checks 1 to 3: the input that issues T, and no other that reissues it.
	let mut issuance = None;
	for (i, input) in round.input.iter().enumerate() {
		if !input.has_issuance() || input.issuance_ids().0 != token {
			continue;
		}
		if input.asset_issuance.asset_blinding_nonce == ZERO_TWEAK {
			issuance = Some(input.asset_issuance);
		} else {
			return Err(RoundCheckFailure::Reissued(i));
		}
	}
	let issuance = issuance.ok_or(RoundCheckFailure::NotIssued)?;
	match issuance.amount {
		Value::Explicit(1) => {},
		Value::Explicit(n) => return Err(RoundCheckFailure::NotOneAtom(n)),
		_ => return Err(RoundCheckFailure::NotExplicit),
	}
	match issuance.inflation_keys {
		Value::Null | Value::Explicit(0) => {},
		_ => return Err(RoundCheckFailure::ReissuanceToken),
	}

	// Check 4: one output holds T, as one explicit atom, and no output hides it.
	let mut holding = vec![];
	for (i, out) in round.output.iter().enumerate() {
		match out.asset.explicit() {
			Some(a) if a == token => holding.push(i),
			Some(_) => {},
			None => if !out.asset.is_null() {
				return Err(RoundCheckFailure::BlindedOutput(i));
			},
		}
	}
	if holding.len() != 1 {
		return Err(RoundCheckFailure::TokenOutputs(holding.len()));
	}
	let out = &round.output[holding[0]];
	if out.value != Value::Explicit(1) {
		return Err(RoundCheckFailure::TokenOutputNotOneAtom);
	}
	let r = schedule.r();
	if out.script_pubkey == r.script_pubkey() {
		return Err(RoundCheckFailure::TokenAtR);
	}

	// Check 5: the schedule, rebuilt.
	if let Some(i) = schedule.backwards_at() {
		return Err(RoundCheckFailure::ScheduleBackwards(i));
	}
	if out.script_pubkey != schedule.clock0_script_pubkey() {
		return Err(RoundCheckFailure::NotClockZero);
	}
	let r_program = r.program();
	for (i, s) in sweeps.iter().enumerate() {
		let notice_ok = s.notice.is_none() || s.notice == Some(schedule.notice);
		if s.token != token || s.r_program != r_program || s.operator != schedule.operator || !notice_ok {
			return Err(RoundCheckFailure::SweepMismatch(i));
		}
	}
	Ok(())
}
