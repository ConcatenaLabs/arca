//! A batch of either kind: a tree ([`crate::tree`]) or an accumulator
//! batch ([`crate::accumulator`]).
//!
//! Both hold the leaves of one asset, each behind the same hash-locked
//! entry, under the same token, clock and notice, and the round pays each the
//! same way: the batch output, then the token's atom to the first clock. They
//! differ in what is above the entries: a tree's node levels, or one
//! accumulator output from which each leaf leaves in one transaction. An
//! operator chooses the kind per batch ([`BatchKind::choose`]).

use elements::Script;

use crate::accumulator::{prefer_accumulator, Accumulator, AccumulatorParams, SLOTS};
use crate::record::Template;
use crate::script::ExplicitOutput;
use crate::tree::{LeafSpec, Tree, TreeError, TreeLeaf, TreeParams};

/// Which kind a batch is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BatchKind {
	Tree,
	Accumulator,
}

impl BatchKind {
	/// The name a published batch and a stored one carry.
	pub fn as_str(self) -> &'static str {
		match self {
			BatchKind::Tree => "tree",
			BatchKind::Accumulator => "accumulator",
		}
	}

	/// Reads [`BatchKind::as_str`]'s names.
	pub fn parse(s: &str) -> Option<BatchKind> {
		match s {
			"tree" => Some(BatchKind::Tree),
			"accumulator" => Some(BatchKind::Accumulator),
			_ => None,
		}
	}

	/// The kind an operator builds `leaves` as, at `radix`, when it expects
	/// `exit_rate_ppm` millionths of leaves to leave on the chain (`None`:
	/// the operator builds trees alone): an accumulator when
	/// [`prefer_accumulator`] says it is cheaper for that many exits, it holds
	/// them all, and every leaf is one an accumulator record carries (no
	/// `channel-1` or `claim-1`) and one the operator never brings on the chain by a path
	/// of its own (no `order-3` or `order-2`, which it lands for an absent maker), and the
	/// batch's sweep is not burn-only (an issuer-operated asset's batches are
	/// rebuilt by the mint's signer, which builds trees). Otherwise a tree.
	/// `no_sweep` prices the exits of a batch without a sweep
	/// (`arca/accumulator-2`), which are larger.
	pub fn choose(leaves: &[LeafSpec], radix: usize, exit_rate_ppm: Option<u32>, burn: bool, no_sweep: bool) -> BatchKind {
		let Some(ppm) = exit_rate_ppm else { return BatchKind::Tree };
		let n = leaves.len();
		if burn || n > SLOTS || leaves.iter().any(|l| matches!(l.template, Template::Order2 | Template::Order3 | Template::Channel1 | Template::Claim1
			| Template::Vest1) || l.channel.is_some() || l.claim.is_some()) {
			return BatchKind::Tree;
		}
		let exits = n as f64 * ppm as f64 / 1_000_000.0;
		if prefer_accumulator(n, radix, exits, no_sweep) { BatchKind::Accumulator } else { BatchKind::Tree }
	}

	/// The record format of a leaf of a batch of this kind, with a sweep or
	/// without one (`no_sweep`), by the names of [`RECORD_FORMATS`].
	pub fn record_format(self, no_sweep: bool) -> &'static str {
		match (self, no_sweep) {
			(BatchKind::Tree, false) => "leaf-2",
			(BatchKind::Tree, true) => "leaf-3",
			(BatchKind::Accumulator, false) => "accumulator-1",
			(BatchKind::Accumulator, true) => "accumulator-4",
		}
	}
}

/// The leaf record formats this library reads, each named by its kind and its
/// version byte: `leaf-2` and `leaf-3`, a tree's leaf with a sweep and without
/// ([`crate::record::RECORD_VERSION`], [`crate::record::RECORD_VERSION_NO_SWEEP`]), and
/// `accumulator-1` and `accumulator-4`, an accumulator batch's
/// ([`crate::accumulator::ACCUMULATOR_RECORD_VERSION`],
/// [`crate::accumulator::ACCUMULATOR_RECORD_VERSION_NO_SWEEP`]). A wallet names
/// them in each participation it submits, so that an operator puts its leaves
/// only in a batch whose record it reads ([`BatchKind::record_format`]).
pub const RECORD_FORMATS: &[&str] = &["leaf-2", "leaf-3", "accumulator-1", "accumulator-4"];

/// The leaf record formats an operator takes every participation to read,
/// named or not: those of every wallet that ever took part in a round, before
/// wallets named any. Every other format goes only to a participation that
/// names it.
pub const FORMATS_EVERY_WALLET_READS: &[&str] = &["leaf-2", "leaf-3", "accumulator-1"];

/// Whether a participation naming `named` reads `format`
/// ([`FORMATS_EVERY_WALLET_READS`], else one of `named`).
pub fn reads_format(named: &[String], format: &str) -> bool {
	FORMATS_EVERY_WALLET_READS.contains(&format) || named.iter().any(|n| n == format)
}

impl std::fmt::Display for BatchKind {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		f.write_str(self.as_str())
	}
}

impl From<&TreeParams> for AccumulatorParams {
	/// A tree's parameters but for the radix.
	fn from(p: &TreeParams) -> AccumulatorParams {
		AccumulatorParams {
			asset: p.asset, chain: p.chain, schedule: p.schedule.clone(), burn: p.burn, reserve: p.reserve, min_leaf: p.min_leaf,
		}
	}
}

/// A built batch of either kind.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Batch {
	Tree(Tree),
	Accumulator(Accumulator),
}

impl Batch {
	/// Builds `leaves` as `kind` under `params` (whose radix only a tree
	/// reads).
	pub fn build(kind: BatchKind, params: TreeParams, leaves: &[LeafSpec]) -> Result<Batch, TreeError> {
		Ok(match kind {
			BatchKind::Tree => Batch::Tree(Tree::build(params, leaves)?),
			BatchKind::Accumulator => Batch::Accumulator(Accumulator::build(AccumulatorParams::from(&params), leaves)?),
		})
	}

	pub fn kind(&self) -> BatchKind {
		match self {
			Batch::Tree(_) => BatchKind::Tree,
			Batch::Accumulator(_) => BatchKind::Accumulator,
		}
	}

	/// The output the round pays.
	pub fn batch_output(&self) -> ExplicitOutput {
		match self {
			Batch::Tree(t) => t.batch_output(),
			Batch::Accumulator(a) => a.batch_output(),
		}
	}

	/// The script the round pays the token's atom to: the first clock;
	/// `None` for a batch without a sweep, whose round pays no token.
	pub fn clock0_script_pubkey(&self) -> Option<Script> {
		match self {
			Batch::Tree(t) => t.clock0_script_pubkey(),
			Batch::Accumulator(a) => a.clock0_script_pubkey(),
		}
	}

	/// The leaves and their entries, in order (slot order for an
	/// accumulator batch).
	pub fn leaves(&self) -> &[TreeLeaf] {
		match self {
			Batch::Tree(t) => t.leaves(),
			Batch::Accumulator(a) => a.leaves(),
		}
	}

	pub fn len(&self) -> usize {
		self.leaves().len()
	}

	pub fn is_empty(&self) -> bool {
		self.leaves().is_empty()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn kinds_round_trip_their_names() {
		for k in [BatchKind::Tree, BatchKind::Accumulator] {
			assert_eq!(BatchKind::parse(k.as_str()), Some(k));
		}
		assert_eq!(BatchKind::parse("node"), None);
	}

	/// Each format's name carries the version byte its record starts with.
	#[test]
	fn record_formats_name_their_version_bytes() {
		use crate::accumulator::{ACCUMULATOR_RECORD_VERSION, ACCUMULATOR_RECORD_VERSION_NO_SWEEP};
		use crate::record::{RECORD_VERSION, RECORD_VERSION_NO_SWEEP};
		assert_eq!(BatchKind::Tree.record_format(false), format!("leaf-{}", RECORD_VERSION));
		assert_eq!(BatchKind::Tree.record_format(true), format!("leaf-{}", RECORD_VERSION_NO_SWEEP));
		assert_eq!(BatchKind::Accumulator.record_format(false), format!("accumulator-{}", ACCUMULATOR_RECORD_VERSION));
		assert_eq!(BatchKind::Accumulator.record_format(true), format!("accumulator-{}", ACCUMULATOR_RECORD_VERSION_NO_SWEEP));
		for k in [BatchKind::Tree, BatchKind::Accumulator] {
			for s in [false, true] {
				assert!(RECORD_FORMATS.contains(&k.record_format(s)), "this library reads every format it builds");
			}
		}
		assert!(FORMATS_EVERY_WALLET_READS.iter().all(|f| RECORD_FORMATS.contains(f)));
		assert!(reads_format(&[], "leaf-3") && reads_format(&[], "accumulator-1"));
		assert!(!reads_format(&[], "accumulator-4"), "a participation naming nothing never gets a slot without a sweep");
		assert!(reads_format(&["accumulator-4".into()], "accumulator-4"));
	}
}
