//! The operator's rules for `htlc-2` locks between two holders
//! ([`arca_covenant::lock`]), which [`crate::cosign`] applies.
//!
//! A payer `P` locks a coin to a payee `Q` by an ordinary transfer whose
//! output is an `htlc-2` leaf; the payee holds it at once, as any coin
//! received out of round. The operator co-signs the lock when:
//!
//! - payee, payer and operator are three keys, and the payer's key owns no
//!   leaf and refunds no other lock (a key the payer draws for this lock);
//! - the leaf is no other template's too, and its asset is not supervised
//!   (its paths pay keys a freeze cannot follow);
//! - both delays lie within the exit-delay bounds;
//! - the timeout `T` lies at least the payee's delay and an unroll
//!   ([`UNROLL_SECONDS`]) out, so that the payee can still take the coin on
//!   the chain and claim it before `T`, and at most [`LOCK_MAX_SECONDS`]
//!   out; and `T`, the payer's delay and an unroll fit before the earliest
//!   expiry of the batches the lock rests on, so that a sweep never cuts the
//!   refund;
//! - its depth leaves room for an ending: the lock is at most `depth_limit −
//!   1` reassignments from a round, so that its claim and its refund can each
//!   still follow it.
//!
//! It keeps each lock ([`crate::store::LockRow`]) and posts its record to the
//! payee's mailbox and to the payer's, under the payer's key for it, so that
//! a restore of either holder finds it. It co-signs one ending of a lock:
//!
//! - the claim (CLAIM-C), into a checkpoint of the payee's, only with a
//!   preimage that opens the hash and while the chain's median time is below
//!   `T` less [`CLAIM_MARGIN_SECONDS`];
//! - the refund (REFUND-C), into a checkpoint of the payer's, only once the
//!   chain's median time has reached `T`.
//!
//! The two windows never meet, and the lock is ended once: as the transfer
//! ending it is recorded, the lock is marked ended by it (a transfer dropped
//! before it is signed opens it again), and the signer co-signs one spend of
//! the lock's salt whatever the database says. A claim's preimage is kept
//! and served to both holders (`lock_status`), and anyone may hand the
//! preimage over first (`lock_preimage`): the payer once it claimed what the
//! payee paid, the payee's wallet once its payment settled.

use arca_covenant::{LockSpend, MedianTime, NewLeaf, ValidCoin};

use crate::cosign::CosignError;
use crate::params::Params;
use crate::store::{LockRow, LockState, Store};

/// The furthest a lock's timeout may lie: fourteen days.
pub const LOCK_MAX_SECONDS: u32 = 14 * 86_400;
/// How long before a lock's timeout the operator stops co-signing its claim:
/// ten minutes, ten of Sequentia's blocks, so that the claim's window and
/// the refund's never meet.
pub const CLAIM_MARGIN_SECONDS: u32 = 600;
/// What the operator allows for a holder to unroll a lock's lineage on the
/// chain: an hour.
pub const UNROLL_SECONDS: u32 = 3_600;

fn refuse(m: String) -> CosignError {
	CosignError::Lock(m)
}

/// The rules on an `htlc-2` output that need nothing but the output.
pub fn check_output(params: &Params, leaf: &NewLeaf, asset: &elements::AssetId) -> Result<(), CosignError> {
	let Some(terms) = leaf.lock else { return Ok(()) };
	if leaf.htlc.is_some() || leaf.landing.is_some() || leaf.v2 {
		return Err(refuse("an htlc-2 leaf carries no other template's terms".into()));
	}
	if params.supervised(asset).is_some() {
		return Err(CosignError::OutOfBounds(format!("asset {} is supervised: no htlc-2 leaf holds it, as its paths pay keys a freeze \
			cannot follow", asset)));
	}
	leaf.policy(params.operator, params.chain).lock_policy().expect("a lock").check()
		.map_err(|e| refuse(e.to_string()))?;
	if !params.exit_delay_ok(terms.refund_delay) {
		return Err(CosignError::OutOfBounds(format!("a payer's delay of {} units; the operator takes {} to {}",
			terms.refund_delay.units(), params.min_exit_delay.units(), params.max_exit_delay.units())));
	}
	Ok(())
}

/// The rules on an `htlc-2` output that need the inputs: its timeout against
/// now and the earliest expiry of the coins it rests on, its depth (`hops`,
/// the reassignments from a round the lock will be), and its payer's key.
pub async fn check_output_in(store: &Store, params: &Params, leaf: &NewLeaf, now: MedianTime, hops: usize, inputs: &[&ValidCoin])
	-> Result<(), CosignError>
{
	let Some(terms) = leaf.lock else { return Ok(()) };
	if hops + 1 > params.depth_limit {
		return Err(CosignError::DepthLimit { hops: hops + 1, limit: params.depth_limit });
	}
	let now = now.to_consensus_u32() as u64;
	let t = terms.timeout.to_consensus_u32() as u64;
	let least = now + leaf.exit_delay.seconds() + UNROLL_SECONDS as u64;
	if t < least {
		return Err(refuse(format!("a lock's timeout {} is too soon: its payee needs its delay and an hour to take it on the chain and \
			claim it first, so it lies at {} or later", t, least)));
	}
	if t > now + LOCK_MAX_SECONDS as u64 {
		return Err(refuse(format!("a lock's timeout {} is more than {} s out", t, LOCK_MAX_SECONDS)));
	}
	let expiry = inputs.iter().map(|c| c.expiry.to_consensus_u32() as u64).min().unwrap_or(u64::MAX);
	if expiry != arca_covenant::transfer::NEVER.to_consensus_u32() as u64
		&& t + terms.refund_delay.seconds() + UNROLL_SECONDS as u64 > expiry
	{
		return Err(refuse(format!("a lock's timeout {} with its payer's delay and an hour runs past {}, the earliest expiry of the \
			batches it rests on: a sweep would cut its refund", t, expiry)));
	}
	if store.key_owns_or_refunds(&terms.refunder.serialize()).await? {
		return Err(CosignError::KeyReused);
	}
	Ok(())
}

/// The rules on an input that is an `htlc-2` lock, before the transfer
/// ending it is recorded (`recorded` false) or when it is asked again:
/// the path the input names, against the lock as the operator keeps it and
/// the chain's median time `now`.
pub async fn check_input(store: &Store, coin: &ValidCoin, spend: Option<LockSpend>, now: MedianTime, recorded: bool, transfer: &[u8; 32])
	-> Result<Option<LockRow>, CosignError>
{
	let (policy, spend) = match (coin.leaf.lock_policy(), spend) {
		(None, None) => return Ok(None),
		(None, Some(_)) => return Err(refuse(format!("coin {} is no htlc-2 lock: its input names no claim or refund", coin.id))),
		(Some(_), None) => return Err(refuse(format!("coin {} is an htlc-2 lock: its input names its claim, with the preimage, or its \
			refund", coin.id))),
		(Some(p), Some(s)) => (p, s),
	};
	let row = store.lock(&coin.id.0).await?
		.ok_or_else(|| refuse(format!("coin {} is an htlc-2 lock this operator does not keep", coin.id)))?;
	spend.check(&policy).map_err(|e| refuse(e.to_string()))?;
	let state = match spend {
		LockSpend::Claim { .. } => LockState::Claimed,
		LockSpend::Refund => LockState::Refunded,
	};
	match (row.state, row.ended_by) {
		(LockState::Open, _) => {},
		(s, Some(by)) if s == state && by == *transfer => {},
		(s, _) => return Err(refuse(format!("the lock {} is {} already: the operator co-signs one ending of a lock", coin.id, s.as_str()))),
	}
	// A transfer recorded was judged when it was; asked again it completes.
	if !recorded && row.state == LockState::Open {
		let now = now.to_consensus_u32();
		let t = row.timeout;
		match spend {
			LockSpend::Claim { .. } if now >= t.saturating_sub(CLAIM_MARGIN_SECONDS) => return Err(refuse(format!(
				"the lock {}'s claim is co-signed only before {} ({} s before its timeout {}); the chain's median time is {}: its payee \
				claims on the chain, or its payer is refunded from the timeout", coin.id, t.saturating_sub(CLAIM_MARGIN_SECONDS),
				CLAIM_MARGIN_SECONDS, t, now))),
			LockSpend::Refund if now < t => return Err(refuse(format!(
				"the lock {}'s refund is co-signed only from its timeout {}; the chain's median time is {}", coin.id, t, now))),
			_ => {},
		}
	}
	Ok(Some(row))
}

/// The state an ending leaves a lock in, and the preimage it carries.
pub fn ending(spend: LockSpend) -> (LockState, Option<[u8; 32]>) {
	match spend {
		LockSpend::Claim { preimage } => (LockState::Claimed, Some(preimage)),
		LockSpend::Refund => (LockState::Refunded, None),
	}
}
