//! Offline refresh: a plan of refresh steps the operator applies without
//! the holder, and the refund that stands in for each step's forfeit.
//!
//! A holder who will be away past a coin's expiry pre-signs a plan. Step `i`
//! gives up the holder's coin `L(i-1)` for a new leaf `L(i)` that the operator
//! puts in a round near `L(i-1)`'s exit deadline; `L(0)` is the coin the plan
//! starts from. A forfeit cannot be signed before the round exists (it names
//! the round's connector asset), so each step's forfeit is replaced by a
//! **refund**: a spend of `L(i-1)` and `L(i)` together, each by the frozen
//! `vtxo-1` collaborative path with two committed outputs,
//!
//! ```text
//! output 0: v(i) of the asset to Q(i), an address of the holder's
//! output 1: v(i-1) - margin(i) of the asset to P(i), the operator's
//! ```
//!
//! The holder signs both halves when it makes the plan, `A(i-1)` over
//! `L(i-1)`'s rebindable message and `A(i)` over `L(i)`'s, both committing to
//! the same two outputs; the operator adds `S`'s two when it uses the refund.
//! Nothing here is a new script: [`Refund::tx`] spends two leaves through the
//! path every leaf has.
//!
//! What a half is bound to is what the collaborative message binds: the chain
//! (its genesis hash, in `K`), the leaf instance (its salt, in `K`), the coin's
//! asset and amount, and the two outputs. It names no outpoint, no round and no
//! time. So the refund is valid on whichever coins carry the two leaves'
//! scripts, and every use of either half creates output 0: whatever the
//! operator does with a refund, the holder ends holding `v(i)` at its own
//! address in place of what it consumed. Taking `L(i-1)` needs a coin with
//! `L(i)`'s script beside it, so while `L(i)`'s round is out of the chain the
//! refund cannot be mined, and a copy of `L(i)` the operator funds itself pays
//! the holder.
//!
//! A plan's id ([`Plan::id`]) is a tagged hash of everything the operator
//! does with it:
//!
//! ```text
//! SHA256(T ‖ T ‖ genesis_hash ‖ S ‖ leaf id of L(0) ‖ asset ‖ v(0) ‖ n ‖ step 1 ‖ … ‖ step n)
//! step = v(i) ‖ fee(i) ‖ A(i) ‖ owner nonce ‖ operator nonce ‖ exit delay units (u16)
//!      ‖ unlock hash ‖ |Q(i)| (u16) ‖ Q(i) ‖ |P(i)| (u16) ‖ P(i) ‖ margin(i)
//! T = SHA256("Arca/plan")
//! ```
//!
//! amounts eight bytes little-endian, `n` one byte, asset ids in internal byte
//! order. `L(0)`'s owner signs the id, giving `L(0)` up for the plan; each
//! `A(i)` signs [`key_proof_digest`] of it, proving the holder holds the key and
//! giving `L(i)` up in step `i+1`.

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, LockTime, OutPoint, Script};

use crate::leaf::{leaf_salt, LeafPolicy};
use crate::message::{Chain, CsfsMessage};
use crate::record::LeafId;
use crate::script::ExplicitOutput;
use crate::spend::{assemble, explicit_txout, Pair, Rebindable, SpendError, FINAL};
use crate::time::RelativeTime;
use crate::unroll::{FeeSource, UnrollTx};

/// The tag of a plan's id.
pub const PLAN_TAG: &[u8] = b"Arca/plan";
/// The tag of the digest each new leaf's key signs.
pub const PLAN_KEY_TAG: &[u8] = b"Arca/plan-key";
/// The most steps one plan holds.
pub const MAX_STEPS: usize = 6;
/// The longest script a refund pays to.
pub const MAX_SCRIPT: usize = 128;

/// One step of a plan: the leaf `L(i)` it gives the holder and the refund
/// that stands in for its forfeit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStep {
	/// `v(i)`, what `L(i)` holds.
	pub value: u64,
	/// What the step costs the holder: `v(i-1) - v(i)`.
	pub fee: u64,
	/// `A(i)`.
	pub owner: XOnlyPublicKey,
	pub owner_nonce: [u8; 32],
	/// The operator's nonce for `L(i)`, drawn when the plan was quoted.
	pub operator_nonce: [u8; 32],
	pub exit_delay: RelativeTime,
	/// The hash `L(i)`'s entry is locked to; its preimage is the holder's.
	pub unlock_hash: [u8; 32],
	/// `Q(i)`: the holder's address that a refund pays `v(i)` to.
	pub holder_script: Script,
	/// `P(i)`: the operator's script a refund pays the rest to.
	pub operator_script: Script,
	/// What the refund leaves of `L(i-1)`'s value for its own fee.
	pub margin: u64,
}

/// A plan: see the [module documentation](self).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
	pub chain: Chain,
	/// The operator's key `S`.
	pub operator: XOnlyPublicKey,
	/// `L(0)`'s id.
	pub coin: LeafId,
	/// `L(0)`'s policy.
	pub first: LeafPolicy,
	pub asset: AssetId,
	/// `v(0)`.
	pub value: u64,
	pub steps: Vec<PlanStep>,
}

/// Why a plan is malformed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
	#[error("a plan holds 1 to {max} steps; this one holds {0}", max = MAX_STEPS)]
	StepCount(usize),
	#[error("step {step}: the leaf holds {value} and the fee is {fee}, which is not what the coin before it holds, {before}")]
	Unbalanced { step: usize, before: u64, value: u64, fee: u64 },
	#[error("step {0}: a leaf holds at least one atom")]
	Empty(usize),
	#[error("step {step}: a margin of {margin} leaves nothing of the {before} the coin given up holds")]
	Margin { step: usize, margin: u64, before: u64 },
	#[error("step {0}: the leaf's key is the operator's key S, or a key another leaf of the plan has: every leaf has a key of its own")]
	Key(usize),
	#[error("step {0}: an owner nonce is used twice in the plan")]
	Nonce(usize),
	#[error("step {0}: the holder's address is the operator's script, or another step's: each refund pays the holder at an address of its own")]
	HolderScript(usize),
	#[error("step {0}: a script a refund pays is empty or longer than {max} bytes", max = MAX_SCRIPT)]
	Script(usize),
	#[error("the coin the plan starts from is not a vtxo-1 leaf of the plan's chain and operator")]
	First,
}

fn put_script(e: &mut sha256::HashEngine, s: &Script) {
	e.input(&(s.len() as u16).to_le_bytes());
	e.input(s.as_bytes());
}

fn tagged(tag: &[u8]) -> sha256::HashEngine {
	let t = sha256::Hash::hash(tag);
	let mut e = sha256::Hash::engine();
	e.input(t.as_byte_array());
	e.input(t.as_byte_array());
	e
}

/// The digest each new leaf's key `A(i)` signs over a plan's id:
/// `SHA256(T ‖ T ‖ id)`, `T = SHA256("Arca/plan-key")`. The tag keeps it apart
/// from `L(0)`'s attestation over the id itself and from everything else a
/// leaf key signs.
pub fn key_proof_digest(id: &[u8; 32]) -> [u8; 32] {
	let mut e = tagged(PLAN_KEY_TAG);
	e.input(id);
	sha256::Hash::from_engine(e).to_byte_array()
}

impl Plan {
	/// Checks the plan is well formed: 1 to [`MAX_STEPS`] steps, each leaf
	/// holding what the coin before it holds less its fee, a margin that
	/// leaves something, a key and an owner nonce of its own for every leaf, a
	/// holder's address of its own for every refund, and `L(0)` a `vtxo-1`
	/// leaf of the plan's chain and operator.
	pub fn check(&self) -> Result<(), PlanError> {
		let n = self.steps.len();
		if n == 0 || n > MAX_STEPS {
			return Err(PlanError::StepCount(n));
		}
		if self.first.htlc.is_some() || self.first.chain != self.chain || self.first.operator != self.operator {
			return Err(PlanError::First);
		}
		let mut before = self.value;
		let mut keys = vec![self.first.owner, self.operator];
		let mut nonces: Vec<[u8; 32]> = vec![];
		let mut holder_scripts: Vec<&Script> = vec![];
		for (j, s) in self.steps.iter().enumerate() {
			let i = j + 1;
			if s.value == 0 {
				return Err(PlanError::Empty(i));
			}
			if s.value.checked_add(s.fee) != Some(before) {
				return Err(PlanError::Unbalanced { step: i, before, value: s.value, fee: s.fee });
			}
			if s.margin >= before {
				return Err(PlanError::Margin { step: i, margin: s.margin, before });
			}
			if keys.contains(&s.owner) {
				return Err(PlanError::Key(i));
			}
			keys.push(s.owner);
			if nonces.contains(&s.owner_nonce) {
				return Err(PlanError::Nonce(i));
			}
			nonces.push(s.owner_nonce);
			for script in [&s.holder_script, &s.operator_script] {
				if script.is_empty() || script.len() > MAX_SCRIPT {
					return Err(PlanError::Script(i));
				}
			}
			if s.holder_script == s.operator_script || holder_scripts.contains(&&s.holder_script) {
				return Err(PlanError::HolderScript(i));
			}
			holder_scripts.push(&s.holder_script);
			before = s.value;
		}
		// A holder's address is never the operator's script of any step.
		for s in &self.steps {
			if let Some(j) = self.steps.iter().position(|t| t.operator_script == s.holder_script) {
				return Err(PlanError::HolderScript(j + 1));
			}
		}
		Ok(())
	}

	/// The plan's id: see the [module documentation](self).
	pub fn id(&self) -> [u8; 32] {
		let mut e = tagged(PLAN_TAG);
		e.input(&self.chain.genesis_bytes());
		e.input(&self.operator.serialize());
		e.input(&self.coin.0);
		e.input(&self.asset.into_inner().to_byte_array());
		e.input(&self.value.to_le_bytes());
		e.input(&[self.steps.len() as u8]);
		for s in &self.steps {
			e.input(&s.value.to_le_bytes());
			e.input(&s.fee.to_le_bytes());
			e.input(&s.owner.serialize());
			e.input(&s.owner_nonce);
			e.input(&s.operator_nonce);
			e.input(&s.exit_delay.units().to_le_bytes());
			e.input(&s.unlock_hash);
			put_script(&mut e, &s.holder_script);
			put_script(&mut e, &s.operator_script);
			e.input(&s.margin.to_le_bytes());
		}
		sha256::Hash::from_engine(e).to_byte_array()
	}

	/// `L(i)`'s policy, for `i` from 0 (the coin the plan starts from) to the
	/// number of steps.
	pub fn leaf(&self, i: usize) -> Option<LeafPolicy> {
		if i == 0 {
			return Some(self.first);
		}
		let s = self.steps.get(i - 1)?;
		Some(LeafPolicy {
			owner: s.owner,
			operator: self.operator,
			salt: leaf_salt(&s.owner_nonce, &s.operator_nonce),
			chain: self.chain,
			exit_delay: s.exit_delay,
			htlc: None,
			order: None,
			landing: None,
		})
	}

	/// What `L(i)` holds.
	pub fn value(&self, i: usize) -> Option<u64> {
		if i == 0 {
			return Some(self.value);
		}
		self.steps.get(i - 1).map(|s| s.value)
	}

	/// Step `i`'s refund, for `i` from 1 to the number of steps.
	pub fn refund(&self, i: usize) -> Option<Refund> {
		if i == 0 {
			return None;
		}
		let s = self.steps.get(i - 1)?;
		let old_value = self.value(i - 1)?;
		Some(Refund {
			old: self.leaf(i - 1)?,
			old_value,
			new: self.leaf(i)?,
			new_value: s.value,
			asset: self.asset,
			holder: ExplicitOutput::new(self.asset, s.value, s.holder_script.clone()),
			operator: ExplicitOutput::new(self.asset, old_value.saturating_sub(s.margin), s.operator_script.clone()),
		})
	}
}

/// A step's refund: `L(i-1)` (`old`) and `L(i)` (`new`) spent together, each by
/// its collaborative path, into the holder's output 0 and the operator's
/// output 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refund {
	pub old: LeafPolicy,
	pub old_value: u64,
	pub new: LeafPolicy,
	pub new_value: u64,
	pub asset: AssetId,
	/// Output 0: `v(i)` to the holder.
	pub holder: ExplicitOutput,
	/// Output 1: `v(i-1) - margin(i)` to the operator.
	pub operator: ExplicitOutput,
}

impl Refund {
	/// The two outputs both halves commit to, in order.
	pub fn outputs(&self) -> Vec<ExplicitOutput> {
		vec![self.holder.clone(), self.operator.clone()]
	}

	/// The message `L(i-1)`'s owner and the operator sign.
	pub fn old_message(&self) -> Result<CsfsMessage, crate::Error> {
		self.old.message(self.asset, self.old_value, &self.outputs())
	}

	/// The message `L(i)`'s owner and the operator sign.
	pub fn new_message(&self) -> Result<CsfsMessage, crate::Error> {
		self.new.message(self.asset, self.new_value, &self.outputs())
	}

	/// The refund spending `old_coin` (holding `L(i-1)`) at input 0 and
	/// `new_coin` (holding `L(i)`) at input 1, signed by `old_pair` and
	/// `new_pair`. The margin the two coins hold beyond the outputs pays the
	/// fee as `fee` says. The pairs are not checked here:
	/// [`Rebindable::verify`] does that.
	pub fn tx(&self, old_coin: OutPoint, new_coin: OutPoint, old_pair: &Pair, new_pair: &Pair, fee: &FeeSource)
		-> Result<UnrollTx, SpendError>
	{
		let old_out = explicit_txout(self.asset, self.old_value, self.old.script_pubkey());
		let new_out = explicit_txout(self.asset, self.new_value, self.new.script_pubkey());
		let mut u = assemble(LockTime::ZERO, vec![(old_coin, old_out, FINAL), (new_coin, new_out, FINAL)], &self.outputs(), fee, FINAL)?;
		u.tx.input[0].witness.script_witness = self.old.witness(old_pair, 2);
		u.tx.input[1].witness.script_witness = self.new.witness(new_pair, 2);
		Ok(u)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use elements::hashes::sha256d;
	use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey};
	use elements::BlockHash;

	fn key(label: &str) -> XOnlyPublicKey {
		let secret = crate::script::sha256(label.as_bytes());
		Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&secret).unwrap()).x_only_public_key().0
	}

	fn n(label: &str) -> [u8; 32] {
		crate::script::sha256(label.as_bytes())
	}

	fn script(label: &str) -> Script {
		let mut b = vec![0x00, 0x14];
		b.extend_from_slice(&n(label)[..20]);
		Script::from(b)
	}

	fn plan(steps: usize) -> Plan {
		let chain = Chain::new(BlockHash::from_raw_hash(sha256d::Hash::hash(b"genesis")));
		let operator = key("S");
		let first = LeafPolicy { owner: key("A0"), operator, salt: n("salt 0"), chain, exit_delay: RelativeTime::from_units(254).unwrap(),
			htlc: None, order: None, landing: None };
		Plan {
			chain, operator, coin: LeafId(n("coin")), first, asset: AssetId::from_slice(&n("asset")).unwrap(), value: 1_000_000,
			steps: (1..=steps).map(|i| PlanStep {
				value: 1_000_000, fee: 0, owner: key(&format!("A{}", i)), owner_nonce: n(&format!("owner nonce {}", i)),
				operator_nonce: n(&format!("operator nonce {}", i)), exit_delay: RelativeTime::from_units(254).unwrap(),
				unlock_hash: n(&format!("hash {}", i)), holder_script: script(&format!("Q{}", i)),
				operator_script: script(&format!("P{}", i)), margin: 1_000,
			}).collect(),
		}
	}

	#[test]
	fn a_well_formed_plan_checks_and_its_refunds_pay_the_holder_first() {
		let p = plan(2);
		p.check().unwrap();
		for i in 1..=2 {
			let r = p.refund(i).unwrap();
			assert_eq!(r.outputs()[0], ExplicitOutput::new(p.asset, 1_000_000, script(&format!("Q{}", i))));
			assert_eq!(r.outputs()[1], ExplicitOutput::new(p.asset, 999_000, script(&format!("P{}", i))));
			assert_eq!(r.old, p.leaf(i - 1).unwrap());
			assert_eq!(r.new, p.leaf(i).unwrap());
			assert_ne!(r.old_message().unwrap().digest, r.new_message().unwrap().digest);
		}
		assert!(p.refund(0).is_none() && p.refund(3).is_none());
		assert_eq!(p.leaf(1).unwrap().salt, leaf_salt(&n("owner nonce 1"), &n("operator nonce 1")));
	}

	#[test]
	fn the_id_covers_every_field() {
		let p = plan(2);
		let id = p.id();
		let mut changes: Vec<Plan> = vec![];
		let mut q = p.clone(); q.coin = LeafId(n("other coin")); changes.push(q);
		let mut q = p.clone(); q.value += 1; q.steps[0].fee += 1; changes.push(q);
		let mut q = p.clone(); q.steps[1].owner = key("other"); changes.push(q);
		let mut q = p.clone(); q.steps[1].owner_nonce = n("other"); changes.push(q);
		let mut q = p.clone(); q.steps[1].operator_nonce = n("other"); changes.push(q);
		let mut q = p.clone(); q.steps[0].exit_delay = RelativeTime::from_units(300).unwrap(); changes.push(q);
		let mut q = p.clone(); q.steps[0].unlock_hash = n("other"); changes.push(q);
		let mut q = p.clone(); q.steps[0].holder_script = script("other"); changes.push(q);
		let mut q = p.clone(); q.steps[0].operator_script = script("other"); changes.push(q);
		let mut q = p.clone(); q.steps[0].margin += 1; changes.push(q);
		let mut q = p.clone(); q.steps.pop(); changes.push(q);
		let mut q = p.clone(); q.operator = key("other"); changes.push(q);
		for q in &changes {
			assert_ne!(q.id(), id);
		}
		assert_ne!(key_proof_digest(&id), id);
	}

	#[test]
	fn malformed_plans_are_refused() {
		assert_eq!(plan(0).check(), Err(PlanError::StepCount(0)));
		assert_eq!(plan(MAX_STEPS + 1).check(), Err(PlanError::StepCount(MAX_STEPS + 1)));
		let mut p = plan(2); p.steps[1].value -= 1;
		assert!(matches!(p.check(), Err(PlanError::Unbalanced { step: 2, .. })));
		let mut p = plan(2); p.steps[0].margin = 1_000_000;
		assert!(matches!(p.check(), Err(PlanError::Margin { step: 1, .. })));
		let mut p = plan(2); p.steps[1].owner = p.steps[0].owner;
		assert_eq!(p.check(), Err(PlanError::Key(2)));
		let mut p = plan(2); p.steps[0].owner = p.operator;
		assert_eq!(p.check(), Err(PlanError::Key(1)));
		let mut p = plan(2); p.steps[0].owner = p.first.owner;
		assert_eq!(p.check(), Err(PlanError::Key(1)));
		let mut p = plan(2); p.steps[1].owner_nonce = p.steps[0].owner_nonce;
		assert_eq!(p.check(), Err(PlanError::Nonce(2)));
		let mut p = plan(2); p.steps[1].holder_script = p.steps[0].holder_script.clone();
		assert_eq!(p.check(), Err(PlanError::HolderScript(2)));
		let mut p = plan(2); p.steps[0].holder_script = p.steps[1].operator_script.clone();
		assert!(matches!(p.check(), Err(PlanError::HolderScript(_))));
		let mut p = plan(1); p.steps[0].operator_script = Script::new();
		assert_eq!(p.check(), Err(PlanError::Script(1)));
		let mut p = plan(1); p.first.operator = key("other");
		assert_eq!(p.check(), Err(PlanError::First));
		let mut p = plan(1); p.steps[0].value = 0; p.steps[0].fee = 1_000_000;
		assert_eq!(p.check(), Err(PlanError::Empty(1)));
	}
}
