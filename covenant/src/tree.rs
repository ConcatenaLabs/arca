//! The covenant tree: a batch built from the leaves of one asset.
//!
//! [`Tree::build`] takes the leaves, the batch's parameters (the asset, the
//! chain, the token and clock schedule, whose `S` is the operator's key, the
//! radix and the reserve rule) and follows the specification's rules for
//! building a tree:
//!
//! 1. Leaves are laid left to right. Each sits behind its hash-locked entry,
//!    whose value is the leaf's value plus the entry's reserve.
//! 2. The entries are grouped into lowest nodes, the lowest nodes into the
//!    level above, and so on until one node is left: the batch output. At
//!    every level the children are spread as evenly as possible over the
//!    fewest nodes that hold them: `n` children at radix `r` go to
//!    `k = ⌈n / r⌉` nodes, the first `n mod k` of them holding `⌊n / k⌋ + 1`
//!    children and the rest `⌊n / k⌋`. Every node therefore holds 2 to `r`
//!    children, so owners in one batch pay about the same to exit; the one
//!    node with a single child is the batch output of a batch of one leaf.
//!    At radix 4, five leaves make lowest nodes of 3 and 2 under the batch
//!    output; seventeen make lowest nodes of 4, 4, 3, 3 and 3, those make
//!    nodes of 3 and 2, and those the batch output. Each node's script is
//!    built for its own child count. The radix is 3 to 6: at radix 2 an odd
//!    number of children on a level would need a node of one child.
//! 3. Scripts are computed bottom-up, since a node pins its children's
//!    scripts; `T` and `R` come first, since every sweep names them.
//! 4. Every node holds its reserve on top of its children's values.
//! 5. A node's members are the operator and the owners of every leaf under
//!    it, in leaf order, padded to a power of two with the operator's key; the
//!    list admits only 32-byte keys, by its type.
//! 6. The batch output's sweep has no notice (the token's wait at `R` is the
//!    notice); every other node's and every entry's waits `W` from its own
//!    confirmation. The lowest nodes carry RECLAIM.
//! 7. No leaf script appears twice, so no node or leaf script is funded twice.
//!    Each leaf's salt is `SHA256("Arca/salt" ‖ owner_nonce ‖ operator_nonce)`
//!    ([`crate::leaf::leaf_salt`]): the owner's wallet picks its nonce fresh
//!    for every leaf it asks for, the operator adds its own, and a batch with
//!    an operator nonce twice is refused.
//!
//! The tree gives the batch output the round pays, every node, and each leaf's
//! [`LeafRecord`]. A leaf's unroll is built from its record
//! ([`crate::unroll`]), by the owner as by anyone else.

use std::ops::Range;

use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxOut};

use crate::clock::ClockSchedule;
use crate::gate::{Members, MAX_OWNERS};
use crate::leaf::leaf_salt;
use crate::message::Chain;
use crate::node::MAX_CHILDREN;
use crate::record::{LeafRecord, LowestLevel, Sibling, Template, UpperLevel, MAX_LEVELS, MAX_VALUE};
use crate::script::{Child, ExplicitOutput};
use crate::time::RelativeTime;
use crate::{EntryPolicy, LeafPolicy, NodePolicy};

/// The smallest radix the builder takes. At radix 2 a level with an odd
/// number of children would need a node of one child.
pub const MIN_RADIX: usize = 3;

/// How `n` children are grouped into the nodes above them at radix `r`: the
/// fewest nodes that hold them (`k = ⌈n / r⌉`), the first `n mod k` holding
/// `⌊n / k⌋ + 1` children and the rest `⌊n / k⌋`. Each range is the children
/// of one node, in order.
pub fn spread(n: usize, r: usize) -> Vec<Range<usize>> {
	if n == 0 || r == 0 {
		return vec![];
	}
	let k = n.div_ceil(r);
	let (q, rem) = (n / k, n % k);
	let mut out = Vec::with_capacity(k);
	let mut at = 0;
	for j in 0..k {
		let len = q + usize::from(j < rem);
		out.push(at..at + len);
		at += len;
	}
	out
}

/// How much each output in the tree holds back for the fee of the
/// transaction that spends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReserveRule {
	/// The same reserve on every node and on every entry.
	Fixed { node: u64, entry: u64 },
	/// `multiple` times the relay floor, in the batch asset's atoms, for the
	/// transaction that spends the output with its reserve as the fee:
	/// `multiple × ⌈vsize × floor_per_kvb / 1000⌉`. The size is that
	/// transaction's, built with a dummy witness of full length (the
	/// authorisation's time counted at five bytes). The specification sets
	/// `multiple` to 4, to cover a fourfold rise in the fee floor.
	FeeRate { floor_per_kvb: u64, multiple: u64 },
}

/// A batch's parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeParams {
	/// The batch's one asset.
	pub asset: AssetId,
	pub chain: Chain,
	/// `(T, S, W, E_0 … E_K)`; `S` is the operator's key in every script.
	pub schedule: ClockSchedule,
	/// Burn-only sweeps, for a batch its asset's issuer runs.
	pub burn: bool,
	/// The most children a node has: [`MIN_RADIX`] to 6.
	pub radix: usize,
	pub reserve: ReserveRule,
	/// The smallest leaf value the builder accepts. The specification sets it
	/// at 1,000 times the relay floor per vbyte, so a leaf is worth more than
	/// its own exit.
	pub min_leaf: u64,
}

/// A leaf a batch is to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeafSpec {
	pub template: Template,
	/// The owner's key `A`.
	pub owner: XOnlyPublicKey,
	pub value: u64,
	/// The owner's contribution to the salt, fresh for every leaf it asks for.
	pub owner_nonce: [u8; 32],
	/// The operator's contribution to the salt, fresh for every leaf.
	pub operator_nonce: [u8; 32],
	pub exit_delay: RelativeTime,
	/// The entry's unlock hash `h`.
	pub unlock_hash: [u8; 32],
}

impl LeafSpec {
	/// The leaf's salt: `SHA256("Arca/salt" ‖ owner_nonce ‖ operator_nonce)`.
	pub fn salt(&self) -> [u8; 32] {
		leaf_salt(&self.owner_nonce, &self.operator_nonce)
	}
}

/// A leaf and the entry in front of it.
#[derive(Debug, Clone)]
pub struct TreeLeaf {
	pub spec: LeafSpec,
	pub leaf: LeafPolicy,
	pub entry: EntryPolicy,
	/// The entry's value: the leaf's value and the entry's reserve.
	pub entry_value: u64,
	pub entry_reserve: u64,
	entry_program: [u8; 32],
}

impl TreeLeaf {
	/// The entry's output, which its lowest node pins.
	pub fn entry_child(&self) -> Child {
		Child::new(self.entry.asset, self.entry_value, self.entry_program)
	}
}

/// A node of the tree.
#[derive(Debug, Clone)]
pub struct TreeNode {
	pub policy: NodePolicy,
	/// Its children's values and its reserve.
	pub value: u64,
	pub reserve: u64,
	/// The leaves under it.
	pub leaves: Range<usize>,
	/// Its children: their indices in the level below (the leaves' entries
	/// for a lowest node).
	pub children: Range<usize>,
	members: Members,
	program: [u8; 32],
}

impl TreeNode {
	/// Its member tree: the operator, then the owners under it in leaf order,
	/// padded with the operator.
	pub fn members(&self) -> &Members {
		&self.members
	}

	/// The node's output, as its parent pins it.
	pub fn child(&self) -> Child {
		Child::new(self.policy.children()[0].asset, self.value, self.program)
	}

	pub fn output(&self) -> ExplicitOutput {
		self.child().output()
	}
}

/// Why a tree cannot be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TreeError {
	#[error("a batch needs at least one leaf")]
	NoLeaves,
	#[error("{0} leaves; a batch holds at most {max}", max = MAX_OWNERS)]
	TooManyLeaves(usize),
	#[error("a radix of {0}; it must be {min} to {max}", min = MIN_RADIX, max = MAX_CHILDREN)]
	Radix(usize),
	#[error("leaf {leaf} holds {value}, outside {min} to {max}", max = MAX_VALUE)]
	LeafValue { leaf: usize, value: u64, min: u64 },
	#[error("leaf {leaf} has a template this builder does not build")]
	Template { leaf: usize },
	/// Two leaves with one script. With distinct operator nonces this takes a
	/// SHA256 collision; the check stays as a guard.
	#[error("leaves {first} and {second} have the same script")]
	DuplicateLeaf { first: usize, second: usize },
	#[error("leaves {first} and {second} have the same operator nonce")]
	DuplicateOperatorNonce { first: usize, second: usize },
	#[error("the batch would hold more than {max}", max = MAX_VALUE)]
	ValueSum,
	#[error("the tree would be {0} levels deep; a record holds {max}", max = MAX_LEVELS)]
	TooDeep(usize),
	#[error("the clock schedule runs backwards at step {0}")]
	ScheduleBackwards(usize),
	#[error(transparent)]
	Policy(#[from] crate::Error),
}

/// A batch's tree.
#[derive(Debug, Clone)]
pub struct Tree {
	params: TreeParams,
	leaves: Vec<TreeLeaf>,
	/// The lowest nodes first; the last level holds the batch output alone.
	levels: Vec<Vec<TreeNode>>,
}

fn sum(a: u64, b: u64) -> Result<u64, TreeError> {
	a.checked_add(b).filter(|v| *v <= MAX_VALUE).ok_or(TreeError::ValueSum)
}

/// `⌈vsize × floor_per_kvb / 1000⌉ × multiple` for a transaction with one input,
/// whose witness is `witness`, and `outputs`, plus a fee output.
fn fee_rate_reserve(floor_per_kvb: u64, multiple: u64, witness: Vec<Vec<u8>>, mut outputs: Vec<TxOut>, asset: AssetId) -> u64 {
	outputs.push(TxOut::new_fee(1, asset));
	let mut tx = Transaction {
		version: 2,
		lock_time: LockTime::ZERO,
		input: vec![TxIn { previous_output: OutPoint::default(), sequence: Sequence(0xffff_fffe), ..Default::default() }],
		output: outputs,
	};
	tx.input[0].witness.script_witness = witness;
	let vsize = tx.vsize() as u64;
	vsize.saturating_mul(floor_per_kvb).div_ceil(1000).saturating_mul(multiple)
}

impl Tree {
	/// Builds the tree over `leaves`, in order.
	pub fn build(params: TreeParams, leaves: &[LeafSpec]) -> Result<Tree, TreeError> {
		let n = leaves.len();
		if n == 0 {
			return Err(TreeError::NoLeaves);
		}
		if n > MAX_OWNERS {
			return Err(TreeError::TooManyLeaves(n));
		}
		if !(MIN_RADIX..=MAX_CHILDREN).contains(&params.radix) {
			return Err(TreeError::Radix(params.radix));
		}
		if let Some(i) = params.schedule.backwards_at() {
			return Err(TreeError::ScheduleBackwards(i));
		}
		let r = params.radix;
		let mut depth = 0;
		let mut width = n;
		loop {
			width = width.div_ceil(r);
			depth += 1;
			if width == 1 {
				break;
			}
		}
		if depth > MAX_LEVELS {
			return Err(TreeError::TooDeep(depth));
		}
		let operator = params.schedule.operator;
		let min = params.min_leaf.max(1);

		// The leaves and their entries.
		let entry_sweep = params.schedule.sweep(true, params.burn);
		let mut tree_leaves: Vec<TreeLeaf> = Vec::with_capacity(n);
		let mut seen = std::collections::HashMap::with_capacity(n);
		let mut nonces = std::collections::HashMap::with_capacity(n);
		for (i, spec) in leaves.iter().enumerate() {
			if let Some(first) = nonces.insert(spec.operator_nonce, i) {
				return Err(TreeError::DuplicateOperatorNonce { first, second: i });
			}
			if spec.template != Template::Vtxo1 {
				return Err(TreeError::Template { leaf: i });
			}
			if spec.value < min || spec.value > MAX_VALUE {
				return Err(TreeError::LeafValue { leaf: i, value: spec.value, min });
			}
			let leaf = LeafPolicy {
				owner: spec.owner, operator, salt: spec.salt(), chain: params.chain, exit_delay: spec.exit_delay,
			};
			let program = leaf.program();
			if let Some(first) = seen.insert(program, i) {
				return Err(TreeError::DuplicateLeaf { first, second: i });
			}
			let entry = EntryPolicy {
				unlock_hash: spec.unlock_hash, asset: params.asset, value: spec.value, leaf_program: program,
				sweep: entry_sweep,
			};
			let entry_tap = entry.taproot();
			let entry_reserve = match params.reserve {
				ReserveRule::Fixed { entry, .. } => entry,
				ReserveRule::FeeRate { floor_per_kvb, multiple } => {
					let w = entry_tap.witness(&entry.unlock_script(), vec![vec![0; 32]]);
					let leaf_out = ExplicitOutput::new(params.asset, spec.value, leaf.script_pubkey()).txout();
					fee_rate_reserve(floor_per_kvb, multiple, w, vec![leaf_out], params.asset)
				},
			};
			let entry_value = sum(spec.value, entry_reserve)?;
			tree_leaves.push(TreeLeaf {
				spec: *spec, leaf, entry, entry_value, entry_reserve, entry_program: entry_tap.program(),
			});
		}

		// The nodes, bottom-up.
		let mut below: Vec<(Child, Range<usize>)> =
			tree_leaves.iter().enumerate().map(|(i, l)| (l.entry_child(), i..i + 1)).collect();
		let mut levels: Vec<Vec<TreeNode>> = Vec::with_capacity(depth);
		for level in 0..depth {
			let lowest = level == 0;
			let is_root = level + 1 == depth;
			let sweep = params.schedule.sweep(!is_root, params.burn);
			let groups = spread(below.len(), r);
			let mut nodes = Vec::with_capacity(groups.len());
			for range in groups {
				let group = &below[range.clone()];
				let children: Vec<Child> = group.iter().map(|(c, _)| *c).collect();
				let leaf_range = group[0].1.start..group[group.len() - 1].1.end;
				let owners: Vec<XOnlyPublicKey> = tree_leaves[leaf_range.clone()].iter().map(|l| l.spec.owner).collect();
				let policy = NodePolicy::new(children, operator, owners, sweep, lowest.then_some(params.chain))?;
				let taproot = policy.taproot();
				let members = policy.members();
				let reserve = match params.reserve {
					ReserveRule::Fixed { node, .. } => node,
					ReserveRule::FeeRate { floor_per_kvb, multiple } => {
						let mut below = vec![vec![0; 64], vec![0; 5]];
						below.extend(members.proof(0).witness_items(&operator));
						let w = taproot.witness(&policy.unroll_script(), below);
						fee_rate_reserve(floor_per_kvb, multiple, w, policy.child_outputs(), params.asset)
					},
				};
				let value = policy.children().iter().try_fold(reserve, |acc, c| sum(acc, c.value))?;
				nodes.push(TreeNode {
					program: taproot.program(), policy, value, reserve, leaves: leaf_range, children: range, members,
				});
			}
			below = nodes.iter().map(|nd| (nd.child(), nd.leaves.clone())).collect();
			levels.push(nodes);
		}
		debug_assert_eq!(levels[depth - 1].len(), 1);
		Ok(Tree { params, leaves: tree_leaves, levels })
	}

	pub fn params(&self) -> &TreeParams {
		&self.params
	}

	/// The number of leaves.
	pub fn len(&self) -> usize {
		self.leaves.len()
	}

	pub fn is_empty(&self) -> bool {
		self.leaves.is_empty()
	}

	/// The leaves and their entries, in order.
	pub fn leaves(&self) -> &[TreeLeaf] {
		&self.leaves
	}

	/// The levels of nodes, the lowest first; the last holds the batch output.
	pub fn levels(&self) -> &[Vec<TreeNode>] {
		&self.levels
	}

	/// Every node, the lowest level first.
	pub fn nodes(&self) -> impl Iterator<Item = &TreeNode> {
		self.levels.iter().flatten()
	}

	/// The node whose output is the batch output.
	pub fn root(&self) -> &TreeNode {
		&self.levels[self.levels.len() - 1][0]
	}

	/// The output the round pays.
	pub fn batch_output(&self) -> ExplicitOutput {
		self.root().output()
	}

	/// The script the round pays the token's atom to: the first clock.
	pub fn clock0_script_pubkey(&self) -> Script {
		self.params.schedule.clock0_script_pubkey()
	}

	/// The nodes on leaf `leaf`'s path, from the batch output down, each with
	/// the index of the child on the path.
	pub fn path(&self, leaf: usize) -> Vec<(&TreeNode, usize)> {
		let mut out = Vec::with_capacity(self.levels.len());
		let mut i = leaf;
		for level in &self.levels {
			let j = level.partition_point(|nd| nd.children.end <= i);
			let node = &level[j];
			out.push((node, i - node.children.start));
			i = j;
		}
		out.reverse();
		out
	}

	/// Leaf `leaf`'s record. Panics if there is no such leaf.
	pub fn record(&self, leaf: usize) -> LeafRecord {
		let l = &self.leaves[leaf];
		let siblings = |node: &TreeNode, index: usize| -> Vec<Sibling> {
			node.policy.children().iter().enumerate().filter(|(j, _)| *j != index)
				.map(|(_, c)| Sibling { value: c.value, program: c.program }).collect()
		};
		let path = self.path(leaf);
		let (lowest_node, lowest_index) = path[path.len() - 1];
		let upper = path[..path.len() - 1].iter().map(|(node, index)| UpperLevel {
			index: *index as u8,
			reserve: node.reserve,
			siblings: siblings(node, *index),
			member: node.members.proof(1 + leaf - node.leaves.start),
		}).collect();
		let owners = lowest_node.policy.owners().iter().enumerate().filter(|(j, _)| *j != lowest_index)
			.map(|(_, k)| *k).collect();
		LeafRecord {
			template: l.spec.template,
			owner: l.spec.owner,
			owner_nonce: l.spec.owner_nonce,
			operator_nonce: l.spec.operator_nonce,
			exit_delay: l.spec.exit_delay,
			asset: self.params.asset,
			value: l.spec.value,
			unlock_hash: l.spec.unlock_hash,
			entry_reserve: l.entry_reserve,
			chain: self.params.chain,
			schedule: self.params.schedule.clone(),
			burn: self.params.burn,
			upper,
			lowest: LowestLevel {
				index: lowest_index as u8,
				reserve: lowest_node.reserve,
				siblings: siblings(lowest_node, lowest_index),
				owners,
			},
		}
	}

	/// Every leaf's record, in leaf order.
	pub fn records(&self) -> Vec<LeafRecord> {
		(0..self.len()).map(|i| self.record(i)).collect()
	}
}
