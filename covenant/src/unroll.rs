//! Unrolling a leaf: the transactions from the batch output down to the leaf.
//!
//! Each node on a leaf's path is spent by its UNROLL into its children, behind
//! one member's unroll authorisation; the leaf's entry is then spent into the
//! leaf with the unlock preimage. A [`Branch`], rebuilt from the leaf's
//! record, builds every one of these transactions:
//!
//! - with the output's own reserve as the fee ([`FeeSource::Reserve`]): one
//!   fee output in the batch asset; or part of it as the fee and the rest to
//!   the broadcaster's change ([`FeeSource::Split`]);
//! - or with a coin of the broadcaster's attached as a second input
//!   ([`FeeSource::Coin`]), in any asset a producer accepts: the coin pays the
//!   fee in its own asset, and the reserve goes to an ordinary output, since a
//!   transaction with fee outputs in two assets is refused.
//!
//! Neither the unroll nor the unlock commits to the transaction's other inputs
//! or to outputs past the ones it pins, so either shape satisfies the same
//! witness. A coin attached for the fee changes each transaction's id, so each
//! transaction is built on the id of the one before it. The fee coin's own
//! witness is the broadcaster's to add.

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxOut};

use crate::gate::MemberProof;
use crate::record::{Branch, BranchNode};
use crate::time::MedianTime;

/// Who pays the fee of a transaction in an unroll.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum FeeSource {
	/// The spent output's reserve is the fee, in the batch asset.
	Reserve,
	/// A coin of the broadcaster's, spent as the second input. It pays `fee`
	/// in its own asset; its change, and the spent output's reserve, go to
	/// `change`.
	Coin {
		outpoint: OutPoint,
		/// The coin: an explicit asset and value.
		coin: TxOut,
		fee: u64,
		change: Script,
	},
	/// The spent output's reserve, or the margin its signers left, in one
	/// asset, pays `fee` of itself, and the rest goes to `change`: a margin
	/// larger than the fee the transaction needs is not given away whole.
	Split {
		fee: u64,
		change: Script,
	},
}

/// One member's unroll authorisation for one node: its signature over
/// `SHA256("Arca/unroll" ‖ H ‖ t)`, the time `t`, its key and its proof in the
/// node's member tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnrollAuth {
	pub signature: Signature,
	pub time: MedianTime,
	pub key: XOnlyPublicKey,
	pub proof: MemberProof,
}

/// A transaction of an unroll, and the outputs its inputs spend, in input
/// order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnrollTx {
	pub tx: Transaction,
	pub prevouts: Vec<TxOut>,
}

/// Why an unroll cannot be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnrollError {
	#[error("{given} authorisations for a path of {needed} nodes")]
	Authorisations { given: usize, needed: usize },
	#[error("{given} fee sources for {needed} transactions")]
	FeeSources { given: usize, needed: usize },
	#[error("the fee coin's asset or value is not explicit")]
	FeeCoinNotExplicit,
	#[error("the fee coin holds {value}, less than the fee of {fee}")]
	FeeCoinTooSmall { value: u64, fee: u64 },
	#[error("margins in {0} assets: one pays the fee, and the others need a fee coin's change to go to")]
	SeveralMarginAssets(usize),
	#[error("a fee of {fee} out of a margin of {margin}: the fee is at least one atom and at most the margin")]
	SplitFee { fee: u64, margin: u64 },
}

/// Adds the fee to a transaction that spends an output holding `reserve` of
/// `asset` beyond what its pinned outputs take.
fn pay_fee(tx: &mut Transaction, prevouts: &mut Vec<TxOut>, asset: elements::AssetId, reserve: u64, fee: &FeeSource, sequence: Sequence)
	-> Result<(), UnrollError>
{
	let margins: Vec<(elements::AssetId, u64)> = if reserve > 0 { vec![(asset, reserve)] } else { vec![] };
	crate::spend::pay_fee(tx, prevouts, &margins, fee, sequence)
}

impl BranchNode {
	/// The owner's authorisation, from its signature over
	/// [`BranchNode::unroll_authorisation`] for `time`.
	pub fn owner_auth(&self, signature: Signature, time: MedianTime, owner: XOnlyPublicKey) -> UnrollAuth {
		UnrollAuth { signature, time, key: owner, proof: self.proof.clone() }
	}

	/// The unroll of this node held at `outpoint`: its children at outputs
	/// `0..r-1`, then the fee. The lock time is the authorisation's time and
	/// every input's sequence is non-final, as the authorisation's
	/// `OP_CHECKLOCKTIMEVERIFY` needs.
	pub fn unroll_tx(&self, outpoint: OutPoint, auth: &UnrollAuth, fee: &FeeSource) -> Result<UnrollTx, UnrollError> {
		let sequence = Sequence(0xffff_fffe);
		let mut tx = Transaction {
			version: 2,
			lock_time: LockTime::from_consensus(auth.time.to_consensus_u32()),
			input: vec![TxIn { previous_output: outpoint, sequence, ..Default::default() }],
			output: self.children.iter().map(|c| c.output().txout()).collect(),
		};
		let mut prevouts = vec![self.output().txout()];
		pay_fee(&mut tx, &mut prevouts, self.children[0].asset, self.reserve, fee, sequence)?;
		tx.input[0].witness.script_witness = self.member_unroll_witness(&auth.signature, auth.time, &auth.key, &auth.proof);
		Ok(UnrollTx { tx, prevouts })
	}
}

impl Branch {
	/// Every node transaction from the batch output, held at `batch`, down to
	/// the lowest node: `auths[i]` and `fees[i]` are for the `i`th node from
	/// the top. Each transaction spends the child its parent created on the
	/// leaf's path.
	pub fn unroll(&self, batch: OutPoint, auths: &[UnrollAuth], fees: &[FeeSource]) -> Result<Vec<UnrollTx>, UnrollError> {
		let needed = self.nodes.len();
		if auths.len() != needed {
			return Err(UnrollError::Authorisations { given: auths.len(), needed });
		}
		if fees.len() != needed {
			return Err(UnrollError::FeeSources { given: fees.len(), needed });
		}
		let mut out = Vec::with_capacity(needed);
		let mut at = batch;
		for ((node, auth), fee) in self.nodes.iter().zip(auths).zip(fees) {
			let u = node.unroll_tx(at, auth, fee)?;
			at = OutPoint::new(u.tx.txid(), node.index as u32);
			out.push(u);
		}
		Ok(out)
	}

	/// Where the leaf's entry is once [`Branch::unroll`] has made `txs`.
	pub fn entry_outpoint(&self, txs: &[UnrollTx]) -> Option<OutPoint> {
		let last = txs.last()?;
		Some(OutPoint::new(last.tx.txid(), self.nodes.last()?.index as u32))
	}

	/// The unlock of the entry held at `outpoint` into the leaf, with the
	/// preimage of the entry's unlock hash: the leaf at output 0, then the
	/// fee.
	pub fn entry_tx(&self, outpoint: OutPoint, preimage: &[u8; 32], fee: &FeeSource) -> Result<UnrollTx, UnrollError> {
		let sequence = Sequence(0xffff_ffff);
		let mut tx = Transaction {
			version: 2,
			lock_time: LockTime::ZERO,
			input: vec![TxIn { previous_output: outpoint, sequence, ..Default::default() }],
			output: vec![self.leaf_output().txout()],
		};
		let mut prevouts = vec![self.entry_output().txout()];
		pay_fee(&mut tx, &mut prevouts, self.entry.asset, self.entry_value - self.entry.value, fee, sequence)?;
		tx.input[0].witness.script_witness = self.entry.unlock_witness(preimage);
		Ok(UnrollTx { tx, prevouts })
	}
}
