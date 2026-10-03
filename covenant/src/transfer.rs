//! An out-of-round transfer, and the record a receiver validates back to the
//! batches it came from.
//!
//! A transfer is two linked transactions. Each input coin is first spent, by
//! its collaborative path, into a checkpoint output ([`CheckpointPolicy`]),
//! and the reassignment then spends the checkpoints into the new leaves. Both
//! are signed in advance by the coin's owner and the operator: the checkpoint
//! pair over the checkpoint output, the reassignment pair over the
//! reassignment's committed outputs (1 to 4). Neither commits to an outpoint,
//! so both survive any unroll. Each signer leaves a margin uncommitted for the
//! fee, in the coin's asset; whoever broadcasts may attach a coin of its own
//! instead and take the margin as change.
//!
//! A reassignment may spend several coins from several owners, in several
//! assets: that is the in-tree swap. Every owner signs the same output set, so
//! each is certain its coin moves only into a transaction that creates every
//! output it signed for; no signature names the other inputs.
//!
//! # Outputs unique to the reassignment
//!
//! Because no pair names an input, two reassignments whose committed outputs
//! agree at every index both commit to (the same outputs, or one set the
//! first outputs of the other) are satisfied by one transaction: it spends
//! the checkpoints of both, creates the outputs once, and the value of one
//! reassignment's inputs goes to whoever broadcasts it. Each pair is sound
//! on its own, so no signer can see this. Two payments to one receive
//! request, with no change, would commit to exactly one output set if the
//! receiver's leaf were built from the request alone.
//!
//! So every output a pair commits to carries something unique to the inputs
//! it spends. A leaf's salt is built from two nonces
//! ([`crate::leaf::leaf_salt`]): its owner's, and its creator's. For a leaf a
//! reassignment creates, the creator is the sender: its wallet draws a fresh
//! random nonce for every leaf it creates, the receiver's and its own change
//! alike ([`NewLeaf::creator_nonce`]), so two reassignments never commit to
//! the same output. The receiver checks its own key and nonce, as for any
//! leaf; the record carries the creator nonce, and the leaf is rebuilt from
//! both.
//!
//! Two more checks hold the rule where a sender breaks it. The operator
//! co-signs a reassignment only if its outputs cannot be merged with those of
//! any other reassignment it has co-signed ([`TransferPlan::admit`],
//! [`SeenReassignments`]). And [`CoinRecord::validate`] refuses a record in
//! which two coins share a salt: one leaf promised by two reassignments may
//! exist on-chain only once. The record cannot show the coins a wallet holds
//! or has held, so the wallet keeps every salt it has held a coin under and
//! refuses a coin at one of them: two records at one leaf are one coin, and
//! a leaf rebuilt at a salt its owner has signed under is spent by the
//! owner's old pairs, at the same asset and value. The sender chooses the
//! creator nonce, so it could rebuild such a leaf; a second honest payment,
//! under another creator nonce, never meets the refusal.
//!
//! # The checkpoint's salt
//!
//! A checkpoint's collaborative path is the leaf's script under another salt,
//! so a reassignment's pair never fits the leaf and a checkpoint's never fits
//! the checkpoint, and the two steps can be neither skipped nor reordered. The
//! salt is `SHA256("Arca/checkpoint" ‖ the coin's leaf salt)`
//! ([`checkpoint_salt`]): one leaf is spent once, so it has one checkpoint
//! script, and the tag keeps that salt apart from every leaf's. The checkpoint
//! sweeps with the notice of the batch the coin descends from (for a coin from
//! a reassignment of several, the first input's, recursively).
//!
//! # The coin record
//!
//! A [`CoinRecord`] is what the holder of a coin keeps: for a leaf of a batch,
//! its [`LeafRecord`] with the preimage of its entry and its owner's unroll
//! authorisations for every node on its path, so that anyone holding the record
//! can bring it on-chain; for a board, its [`BoardRecord`] (the board is
//! on-chain already); for a coin a reassignment created, the reassignment's
//! inputs (each a coin record in turn, with its checkpoint's value and both
//! pairs), the committed outputs, the coin's index among them, and the coin's
//! leaf: its owner's key, the two nonces of its salt (the owner's and the
//! sender's) and its exit delay. The second nonce of a leaf's salt is always
//! its creator's: the operator's in a leaf record (a round) and a board
//! record, the sender's in a coin a reassignment created.
//!
//! A receiver accepts a coin only after [`CoinRecord::validate`]: every batch
//! leaf in the record validates against the round that funds it, and every
//! board against its board transaction, under the receiver's [`WalletPolicy`]
//! (its receipt form, [`WalletPolicy::receipt`]);
//! every preimage opens its entry and every authorisation is the leaf owner's,
//! usable now; every pair verifies; no reassignment creates more of an asset
//! than its checkpoints hold; every leaf a reassignment creates along the
//! coin's lineage, whoever owns it, has an exit delay within the policy's
//! bounds; the coin's output is the leaf its record names, for the receiver's
//! key and the nonce it published, and the sender's creator nonce; no coin is
//! spent twice anywhere in the record, and no two coins in it share a salt;
//! and the chain is no deeper than [`DEPTH_LIMIT`] reassignments. A
//! coin from a reassignment is safe only until the earliest expiry among the
//! batches it descends from ([`ValidCoin::expiry`]), since a sweep of any of
//! them cuts its path; the receipt policy asks that each lie past the exit
//! deadline.
//!
//! The record cannot show what is on-chain, and an Arca leaf that is on-chain
//! is never spent off-chain: past its exit delay its owner can exit it at once.
//! [`ValidCoin::lineage`] lists every leaf and checkpoint the coin descends
//! from, and a receiver that can ask an index of the chain refuses the coin
//! when any is on-chain ([`ValidCoin::check_lineage`]); one that cannot relies
//! on the operator, which refuses to co-sign a spend of a leaf that is
//! on-chain. A board is on-chain from the start and must still be there,
//! unspent: [`ValidCoin::boards`] lists them and [`ValidCoin::check_boards`]
//! refuses the coin when one is spent.
//!
//! # A coin from a board
//!
//! A board has no batch and no expiry. Its leaf is the coin; a checkpoint of
//! it carries a sweep whose token no issuance can create
//! ([`board_sweep`]), so only the checkpoint's collaborative path spends it.
//! Every pair over the coin spends it as the board output or as the leaf a
//! conversion made of it ([`crate::board`]):
//! [`ValidInput::board_checkpoint_tx`] spends the board output itself.
//!
//! What the receiver relies on is the trust the specification names
//! "operator-confirmed": the sender and the operator could still sign another
//! spend of an input. Against the sender alone the receiver is safe once those
//! checks pass: it holds a co-signed spend of each coin, which needs no delay,
//! every leaf it descends from is off-chain with an exit delay the receiver
//! accepts, and it answers a stale exit at once by publishing the checkpoint
//! and the reassignment within that delay.
//!
//! # The binary form, version 1
//!
//! ```text
//! u8    format version, 1
//! coin:
//!   u8  0, a leaf of a batch:
//!         u16  length L, then L bytes: its LeafRecord, binary form
//!         [32] the preimage of its entry's unlock hash
//!         u8   n, the levels of its path, then n × ([64] signature, u32 time):
//!              its owner's unroll authorisation for each node, from the batch output down
//!   u8  2, a board:
//!         u16  length L, then L bytes: its BoardRecord, binary form
//!   u8  1, an output of a reassignment:
//!         u8   input count, 1 to 16, then per input:
//!                coin (recursively), u64 the checkpoint's value,
//!                [64] [64] the checkpoint pair (operator, owner),
//!                [64] [64] the reassignment pair (operator, owner)
//!         u8   output count m, 1 to 4, then per output:
//!                [32] asset, u64 value, compact size and the scriptPubKey (at most 10,000 bytes)
//!         u8   the coin's index, below m
//!         [32] owner key, [32] owner nonce, [32] creator nonce (the sender's), u16 exit delay units
//! ```
//!
//! Reassignments nest at most [`MAX_HOPS`] deep along any path of the record.
//! A reader refuses an unknown version or tag and anything that does not encode
//! back to the same bytes.
//!
//! The id of a coin a reassignment created is the leaf id, tag `Arca/leaf-id`,
//! of `R ‖ 0x01 ‖ index ‖ the leaf's program`, where `R` is the BIP340 tagged
//! hash, tag `Arca/reassignment`, of the input count, each input's coin id and
//! checkpoint program, the output count and each output's record hash
//! ([`reassignment_hash`]).

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, LockTime, OutPoint, Script, Transaction, TxOut};

use crate::board::{BoardPolicy, BoardRecord, ValidBoard};
use crate::checkpoint::CheckpointPolicy;
use crate::clock::ClockSchedule;
use crate::encode::{write_compact_size, DecodeError, Reader};
use crate::leaf::{leaf_salt, LeafPolicy, MAX_OUTPUTS};
use crate::message::{Chain, CsfsMessage};
use crate::offboard::MAX_DESTINATION;
use crate::record::{LeafId, LeafRecord, RecordError, ValidLeaf, WalletPolicy, MAX_VALUE};
use crate::script::{asset_bytes, sha256, ExplicitOutput};
use crate::sign::verify_digest;
use crate::spend::{assemble, collab_tx, FeeSource, Pair, Rebindable, SpendError, UnrollTx, FINAL};
use crate::sweep::Sweep;
use crate::time::{MedianTime, RelativeTime};
use crate::unroll::UnrollAuth;

/// The coin record format this crate writes and reads.
pub const COIN_RECORD_VERSION: u8 = 1;
/// The most reassignments a record nests along any path.
pub const MAX_HOPS: usize = 16;
/// The most inputs a reassignment in a record has.
pub const MAX_INPUTS: usize = 16;
/// The specification's reassignment depth limit: a coin more than this many
/// reassignments from a round is refused; it is refreshed into a round first.
pub const DEPTH_LIMIT: usize = 5;
/// The prefix of a checkpoint's salt.
pub const CHECKPOINT_SALT_TAG: &[u8; 15] = b"Arca/checkpoint";
/// The tag of a reassignment's hash, from which its outputs' ids follow.
pub const REASSIGNMENT_TAG: &[u8] = b"Arca/reassignment";

/// The tag whose hash is the sweep token of a coin from a board: an asset id
/// no issuance creates, so a sweep that needs it can never be taken.
pub const BOARD_TOKEN_TAG: &[u8] = b"Arca/board-token";

/// The expiry of a coin that descends from boards alone: a board never
/// expires.
pub const NEVER: MedianTime = MedianTime::MAX;

/// The sweep a checkpoint of a coin from a board carries: the frozen sweep
/// with notice, for a token no issuance creates (`SHA256(BOARD_TOKEN_TAG)`)
/// and `R` under the operator with the leaf's exit delay as its notice. Only
/// the checkpoint's collaborative path can spend it.
pub fn board_sweep(operator: XOnlyPublicKey, notice: RelativeTime) -> Sweep {
	let token = AssetId::from_byte_array(sha256(BOARD_TOKEN_TAG));
	ClockSchedule::new_unchecked(token, operator, notice, vec![NEVER]).expect("one step").sweep(true, false)
}

/// The salt of the checkpoint of a coin whose leaf salt is `leaf_salt`.
pub fn checkpoint_salt(leaf_salt: &[u8; 32]) -> [u8; 32] {
	let mut b = CHECKPOINT_SALT_TAG.to_vec();
	b.extend(leaf_salt);
	sha256(&b)
}

/// A new leaf a reassignment creates: its owner's key and nonce, as the
/// receiver publishes them, the creator nonce the sender draws for it, and
/// the exit delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NewLeaf {
	pub owner: XOnlyPublicKey,
	pub owner_nonce: [u8; 32],
	/// The second nonce of the leaf's salt, the creator's: the sender's
	/// wallet draws it at random for every leaf a reassignment creates, never
	/// from a counter or from the receive request, so that two reassignments
	/// never commit to the same output (see the [module documentation](self)).
	pub creator_nonce: [u8; 32],
	pub exit_delay: RelativeTime,
}

impl NewLeaf {
	/// The leaf, for `operator` on `chain`.
	pub fn policy(&self, operator: XOnlyPublicKey, chain: Chain) -> LeafPolicy {
		LeafPolicy {
			owner: self.owner, operator, salt: self.salt(), chain, exit_delay: self.exit_delay,
		}
	}

	/// The leaf's salt: `SHA256("Arca/salt" ‖ owner_nonce ‖ creator_nonce)`.
	pub fn salt(&self) -> [u8; 32] {
		leaf_salt(&self.owner_nonce, &self.creator_nonce)
	}
}

/// What the holder of a coin keeps. See the [module documentation](self).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum CoinRecord {
	/// A leaf of a batch.
	Leaf {
		record: LeafRecord,
		/// The preimage of the entry's unlock hash.
		preimage: [u8; 32],
		/// The owner's unroll authorisation for each node on the path, from the
		/// batch output down: the signature and its time.
		auths: Vec<(Signature, MedianTime)>,
	},
	/// An output of a reassignment.
	Transfer(Box<Transfer>),
	/// A board, on-chain.
	Board(BoardRecord),
}

/// A reassignment, and the coin's place in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
	pub inputs: Vec<TransferInput>,
	/// The committed outputs, at indices `0..m`.
	pub outputs: Vec<ExplicitOutput>,
	/// The coin's index among them.
	pub index: u8,
	/// The coin's leaf.
	pub leaf: NewLeaf,
}

/// One input of a reassignment: the coin, its checkpoint's value, the pair
/// that spends the coin into the checkpoint and the pair that spends the
/// checkpoint into the outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferInput {
	pub coin: CoinRecord,
	pub checkpoint_value: u64,
	pub checkpoint: Pair,
	pub reassignment: Pair,
}

/// Why a coin record does not decode or is not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransferError {
	#[error(transparent)]
	Decode(#[from] DecodeError),
	#[error(transparent)]
	Record(#[from] RecordError),
	#[error(transparent)]
	Spend(#[from] SpendError),
	#[error("unknown coin record format version {0}")]
	Version(u8),
	#[error("unknown coin tag {0}")]
	Tag(u8),
	#[error("reassignments nest more than {max} deep", max = MAX_HOPS)]
	TooDeep,
	#[error("{hops} reassignments since a round; a coin is refreshed into a round after {limit}")]
	DepthLimit { hops: usize, limit: usize },
	#[error("a reassignment with {0} inputs; it has 1 to {max}", max = MAX_INPUTS)]
	Inputs(usize),
	#[error("a reassignment with {0} outputs; it commits to 1 to {max}", max = MAX_OUTPUTS)]
	Outputs(usize),
	#[error("index {index} is past the reassignment's {count} outputs")]
	Index { index: usize, count: usize },
	#[error("no transaction given pays the batch output or the board output of a base in the record")]
	RoundMissing,
	#[error("the board at {0} is spent")]
	BoardSpent(OutPoint),
	#[error("a leaf's preimage does not open its entry")]
	Preimage,
	#[error("{given} unroll authorisations for a path of {needed} nodes")]
	Auths { given: usize, needed: usize },
	#[error("the unroll authorisation for level {0} is not the leaf owner's")]
	AuthSignature(usize),
	#[error("the unroll authorisation for level {0} is not usable until later than now")]
	AuthTime(usize),
	#[error("a checkpoint's value of {value} is not within the coin's {coin}")]
	CheckpointValue { value: u64, coin: u64 },
	#[error("input {input}: the {pair} pair does not verify: {error}")]
	Pair { input: usize, pair: &'static str, error: SpendError },
	#[error("the outputs take more of asset {0} than the checkpoints hold")]
	Overspend(AssetId),
	#[error("the output at the coin's index is not the leaf the record names")]
	LeafMismatch,
	#[error("two committed outputs carry the same script")]
	DuplicateOutput,
	#[error("coin {0} is spent twice in the record")]
	DoubleSpend(LeafId),
	#[error("coins {first} and {second} in the record share a salt: one leaf promised twice exists on-chain at most once")]
	SaltTwice { first: LeafId, second: LeafId },
	#[error("the outputs agree, at every index both commit to, with those of another reassignment: one transaction would satisfy both")]
	Mergeable,
	#[error("the coin is for another owner's key")]
	NotOwner,
	#[error("the coin's owner nonce is not the one the wallet published")]
	OwnerNonce,
	#[error("the coin's exit delay is outside the wallet's bounds")]
	ExitDelay,
	#[error("a leaf {hops} reassignments up the coin's lineage has an exit delay of {delay} units; the wallet accepts {min} to {max}")]
	LineageExitDelay { hops: usize, delay: u16, min: u16, max: u16 },
	#[error("a {kind} in the coin's lineage is on-chain: its owner could spend it under the receiver")]
	OnChain { kind: LineageKind, script: Script },
	#[error("this is not an output of a reassignment")]
	NotATransfer,
	#[error("this coin is not a board")]
	NotABoard,
	#[error("{given} checkpoints for a reassignment of {needed} inputs")]
	Checkpoints { given: usize, needed: usize },
}

impl TransferError {
	/// A short name for the kind of error.
	pub fn kind(&self) -> &'static str {
		use TransferError::*;
		match self {
			Decode(_) | Version(_) | Tag(_) | TooDeep | Inputs(_) | Outputs(_) | Index { .. } => "decode",
			Record(e) => e.kind(),
			Spend(_) => "spend",
			DepthLimit { .. } => "depth",
			RoundMissing => "round",
			Preimage | Auths { .. } | AuthSignature(_) | AuthTime(_) => "unroll",
			CheckpointValue { .. } | Overspend(_) => "value",
			Pair { .. } => "signature",
			LeafMismatch | DuplicateOutput => "output",
			DoubleSpend(_) => "double_spend",
			SaltTwice { .. } => "salt",
			Mergeable => "merge",
			NotOwner | OwnerNonce | ExitDelay => "owner",
			LineageExitDelay { .. } => "policy",
			OnChain { .. } | BoardSpent(_) => "on_chain",
			NotATransfer | NotABoard | Checkpoints { .. } => "use",
		}
	}
}

/// A coin a receiver accepted: what it is, and everything needed to bring it
/// on-chain.
#[derive(Debug, Clone)]
pub struct ValidCoin {
	pub id: LeafId,
	/// The coin's leaf.
	pub leaf: LeafPolicy,
	pub asset: AssetId,
	pub value: u64,
	/// The sweep its checkpoint takes: that of the batch it descends from.
	pub sweep: Sweep,
	/// The earliest first expiry among the batches it descends from.
	pub expiry: MedianTime,
	/// Reassignments since a round, along the longest path.
	pub hops: usize,
	pub origin: ValidOrigin,
}

/// How a valid coin came to be.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ValidOrigin {
	/// A leaf of a batch, checked against its round.
	Leaf {
		valid: ValidLeaf,
		preimage: [u8; 32],
		/// Its owner's unroll authorisations, ready for [`crate::Branch::unroll`].
		auths: Vec<UnrollAuth>,
	},
	/// An output of a reassignment.
	Transfer { inputs: Vec<ValidInput>, outputs: Vec<ExplicitOutput>, index: usize },
	/// A board, checked against its board transaction.
	Board { valid: ValidBoard, record: BoardRecord },
}

/// One checked input of a reassignment.
#[derive(Debug, Clone)]
pub struct ValidInput {
	pub coin: ValidCoin,
	pub checkpoint: CheckpointPolicy,
	pub checkpoint_value: u64,
	pub checkpoint_pair: Pair,
	pub reassignment_pair: Pair,
}

/// What an output in a coin's lineage is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LineageKind {
	/// A leaf: of a batch, or an output of a reassignment.
	Leaf,
	/// A checkpoint between a leaf and the reassignment that spends it.
	Checkpoint,
}

impl std::fmt::Display for LineageKind {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		f.write_str(match self {
			LineageKind::Leaf => "leaf",
			LineageKind::Checkpoint => "checkpoint",
		})
	}
}

/// An output a coin descends from ([`ValidCoin::lineage`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageOutput {
	pub kind: LineageKind,
	pub output: ExplicitOutput,
}

impl ValidCoin {
	/// Every leaf and checkpoint the coin descends from, from the batches
	/// down, in the order the record nests them; the coin's own leaf
	/// ([`ValidCoin::output`]) is not among them.
	///
	/// None of them may be on-chain when the coin is received. A leaf on-chain
	/// past its exit delay can be exited by its owner at once, and one on-chain
	/// within it leaves the receiver only the rest of the delay to answer, so
	/// an Arca leaf that is on-chain is never spent off-chain. A wallet that
	/// can ask an index of the chain checks every script here with
	/// [`ValidCoin::check_lineage`] and refuses the coin if any is on-chain;
	/// one that cannot relies on the operator, which refuses to co-sign a
	/// spend of a leaf that is on-chain.
	pub fn lineage(&self) -> Vec<LineageOutput> {
		let mut out = vec![];
		self.lineage_into(&mut out);
		out
	}

	fn lineage_into(&self, out: &mut Vec<LineageOutput>) {
		if let ValidOrigin::Transfer { inputs, .. } = &self.origin {
			for i in inputs {
				i.coin.lineage_into(out);
				out.push(LineageOutput { kind: LineageKind::Leaf, output: i.coin.output() });
				out.push(LineageOutput { kind: LineageKind::Checkpoint, output: i.checkpoint_output() });
			}
		}
	}

	/// Every board the coin descends from, its own included: each must still
	/// be unspent when the coin is received, since a board spent by its
	/// conversion or by a forfeit no longer backs the coin.
	pub fn boards(&self) -> Vec<OutPoint> {
		match &self.origin {
			ValidOrigin::Board { valid, .. } => vec![valid.outpoint()],
			ValidOrigin::Transfer { inputs, .. } => inputs.iter().flat_map(|i| i.coin.boards()).collect(),
			ValidOrigin::Leaf { .. } => vec![],
		}
	}

	/// Refuses the coin if any board it descends from is spent, as `unspent`
	/// reports it (the chain's set of unspent outputs).
	pub fn check_boards(&self, mut unspent: impl FnMut(&OutPoint) -> bool) -> Result<(), TransferError> {
		match self.boards().into_iter().find(|b| !unspent(b)) {
			Some(b) => Err(TransferError::BoardSpent(b)),
			None => Ok(()),
		}
	}

	/// The board output and where it is, for a coin that is a board.
	pub fn board(&self) -> Option<(BoardPolicy, OutPoint)> {
		match &self.origin {
			ValidOrigin::Board { valid, record } => Some((record.policy(), valid.outpoint())),
			_ => None,
		}
	}

	/// Refuses the coin if any script in its lineage is on-chain, as
	/// `on_chain` reports it (an address index: has any transaction paid this
	/// scriptPubKey).
	pub fn check_lineage(&self, mut on_chain: impl FnMut(&Script) -> bool) -> Result<(), TransferError> {
		for o in self.lineage() {
			if on_chain(&o.output.script_pubkey) {
				return Err(TransferError::OnChain { kind: o.kind, script: o.output.script_pubkey });
			}
		}
		Ok(())
	}

	/// The checkpoint this coin moves into when transferred: its own salt,
	/// the sweep of the batch it descends from.
	pub fn checkpoint(&self) -> CheckpointPolicy {
		CheckpointPolicy {
			owner: self.leaf.owner, operator: self.leaf.operator, salt: checkpoint_salt(&self.leaf.salt),
			chain: self.leaf.chain, sweep: self.sweep,
		}
	}

	/// The coin's output.
	pub fn output(&self) -> ExplicitOutput {
		ExplicitOutput::new(self.asset, self.value, self.leaf.script_pubkey())
	}

	/// The reassignment that created this coin, spending the checkpoints at
	/// `checkpoints` (one per input, in order). Each input's pair is on its
	/// checkpoint; what the checkpoints hold beyond the committed outputs pays
	/// the fee as `fee` says.
	pub fn reassignment_tx(&self, checkpoints: &[OutPoint], fee: &FeeSource) -> Result<UnrollTx, TransferError> {
		let (inputs, outputs) = match &self.origin {
			ValidOrigin::Transfer { inputs, outputs, .. } => (inputs, outputs),
			ValidOrigin::Leaf { .. } | ValidOrigin::Board { .. } => return Err(TransferError::NotATransfer),
		};
		reassignment_tx(inputs, outputs, checkpoints, fee)
	}
}

impl ValidInput {
	/// The checkpoint output.
	pub fn checkpoint_output(&self) -> ExplicitOutput {
		ExplicitOutput::new(self.coin.asset, self.checkpoint_value, self.checkpoint.script_pubkey())
	}

	/// The checkpoint transaction, spending the coin's leaf at `coin`.
	pub fn checkpoint_tx(&self, coin: OutPoint, fee: &FeeSource) -> Result<UnrollTx, TransferError> {
		Ok(collab_tx(&self.coin.leaf, coin, self.coin.asset, self.coin.value, &[self.checkpoint_output()],
			&self.checkpoint_pair, fee)?)
	}

	/// The checkpoint transaction of a coin that is a board, spending the
	/// board output itself with the same pair.
	pub fn board_checkpoint_tx(&self, fee: &FeeSource) -> Result<UnrollTx, TransferError> {
		let (board, at) = self.coin.board().ok_or(TransferError::NotABoard)?;
		Ok(collab_tx(&board, at, self.coin.asset, self.coin.value, &[self.checkpoint_output()], &self.checkpoint_pair, fee)?)
	}
}

/// The reassignment of `inputs` into `outputs`, the checkpoints held at
/// `checkpoints`.
pub fn reassignment_tx(inputs: &[ValidInput], outputs: &[ExplicitOutput], checkpoints: &[OutPoint], fee: &FeeSource)
	-> Result<UnrollTx, TransferError>
{
	if checkpoints.len() != inputs.len() {
		return Err(TransferError::Checkpoints { given: checkpoints.len(), needed: inputs.len() });
	}
	let ins: Vec<(OutPoint, TxOut, elements::Sequence)> = inputs.iter().zip(checkpoints)
		.map(|(i, at)| (*at, i.checkpoint_output().txout(), FINAL)).collect();
	let mut u = assemble(LockTime::ZERO, ins, outputs, fee, FINAL)?;
	for (k, i) in inputs.iter().enumerate() {
		u.tx.input[k].witness.script_witness = i.checkpoint.witness(&i.reassignment_pair, outputs.len() as u8);
	}
	Ok(u)
}

/// The id of output `index` of the reassignment of `inputs` (each a coin's
/// id and its checkpoint's program) into `outputs`, whose leaf program is
/// `program`.
pub fn transfer_id(inputs: &[(LeafId, [u8; 32])], outputs: &[ExplicitOutput], index: u8, program: &[u8; 32]) -> LeafId {
	LeafId::compute(&reassignment_hash(inputs, outputs), &[index], program)
}

/// The reassignment's hash, `R`: the BIP340 tagged hash, tag
/// `Arca/reassignment`, of the input count, each input's coin id and
/// checkpoint program, the output count and each output's record hash.
pub fn reassignment_hash(inputs: &[(LeafId, [u8; 32])], outputs: &[ExplicitOutput]) -> [u8; 32] {
	let tag = sha256(REASSIGNMENT_TAG);
	let mut b = Vec::with_capacity(64 + 1 + 64 * inputs.len() + 1 + 32 * outputs.len());
	b.extend(tag);
	b.extend(tag);
	b.push(inputs.len() as u8);
	for (id, cp) in inputs {
		b.extend(id.0);
		b.extend(cp);
	}
	b.push(outputs.len() as u8);
	for o in outputs {
		b.extend(sha256(&o.record()));
	}
	sha256(&b)
}

/// Whether one transaction can satisfy a pair over `a` and a pair over `b`:
/// every rebindable pair commits to the outputs at indices `0..m`, so two
/// pairs fit one transaction when their outputs agree at every index both
/// commit to, that is when one set is the first outputs of the other.
pub fn mergeable(a: &[ExplicitOutput], b: &[ExplicitOutput]) -> bool {
	let n = a.len().min(b.len());
	n > 0 && a[..n] == b[..n]
}

/// The reassignments an operator has co-signed, as the rule that keeps any
/// two from being merged needs them ([`TransferPlan::admit`]).
///
/// A transaction that satisfies two reassignments' pairs spends the
/// checkpoints of both and creates the outputs once; what one of them was to
/// pay goes to whoever broadcasts it. Two such reassignments always agree at
/// output 0, so they are kept by the hash of output 0's record. A wallet that
/// draws the creator nonce of every leaf it creates never meets this rule;
/// it holds where a wallet does not.
#[derive(Debug, Clone, Default)]
pub struct SeenReassignments {
	by_first: std::collections::HashMap<[u8; 32], Vec<SeenReassignment>>,
	count: usize,
}

#[derive(Debug, Clone)]
struct SeenReassignment {
	/// The coins spent, each with its checkpoint's value.
	inputs: Vec<(LeafId, u64)>,
	outputs: Vec<ExplicitOutput>,
}

impl SeenReassignments {
	pub fn new() -> SeenReassignments {
		SeenReassignments::default()
	}

	/// The number of reassignments recorded.
	pub fn len(&self) -> usize {
		self.count
	}

	pub fn is_empty(&self) -> bool {
		self.count == 0
	}

	/// Refuses the reassignment of `inputs` (each coin's id and its
	/// checkpoint's value) into `outputs` when a transaction could satisfy
	/// both it and one recorded here. The same reassignment again (the same
	/// coins, checkpoint values and outputs) is not refused: its checkpoints
	/// are the same outputs, each spent once.
	pub fn check(&self, inputs: &[(LeafId, u64)], outputs: &[ExplicitOutput]) -> Result<(), TransferError> {
		let first = match outputs.first() {
			Some(o) => sha256(&o.record()),
			None => return Err(TransferError::Outputs(0)),
		};
		for seen in self.by_first.get(&first).into_iter().flatten() {
			if seen.inputs == inputs && seen.outputs == outputs {
				continue;
			}
			if mergeable(&seen.outputs, outputs) {
				return Err(TransferError::Mergeable);
			}
		}
		Ok(())
	}

	/// [`SeenReassignments::check`], then records the reassignment.
	pub fn admit(&mut self, inputs: &[(LeafId, u64)], outputs: &[ExplicitOutput]) -> Result<(), TransferError> {
		self.check(inputs, outputs)?;
		let first = sha256(&outputs[0].record());
		let list = self.by_first.entry(first).or_default();
		if !list.iter().any(|s| s.inputs == inputs && s.outputs == outputs) {
			list.push(SeenReassignment { inputs: inputs.to_vec(), outputs: outputs.to_vec() });
			self.count += 1;
		}
		Ok(())
	}
}

/// A transfer being made: what each input's owner and the operator sign.
#[derive(Debug, Clone)]
pub struct TransferPlan {
	/// The coins given, each with its checkpoint's value.
	pub inputs: Vec<(ValidCoin, u64)>,
	/// The committed outputs.
	pub outputs: Vec<ExplicitOutput>,
}

impl TransferPlan {
	/// The checkpoint of input `i`.
	pub fn checkpoint(&self, i: usize) -> CheckpointPolicy {
		self.inputs[i].0.checkpoint()
	}

	/// The checkpoint output of input `i`.
	pub fn checkpoint_output(&self, i: usize) -> ExplicitOutput {
		let (coin, v) = &self.inputs[i];
		ExplicitOutput::new(coin.asset, *v, self.checkpoint(i).script_pubkey())
	}

	/// What input `i`'s owner and the operator sign to spend its coin into
	/// its checkpoint.
	pub fn checkpoint_message(&self, i: usize) -> Result<CsfsMessage, SpendError> {
		let (coin, _) = &self.inputs[i];
		Ok(coin.leaf.message(coin.asset, coin.value, &[self.checkpoint_output(i)])?)
	}

	/// What input `i`'s owner and the operator sign to spend its checkpoint
	/// into the outputs.
	pub fn reassignment_message(&self, i: usize) -> Result<CsfsMessage, SpendError> {
		let (coin, v) = &self.inputs[i];
		Ok(self.checkpoint(i).message(coin.asset, *v, &self.outputs)?)
	}

	/// The operator's rule before it co-signs: refuses the plan when one
	/// transaction could satisfy both its pairs and those of a reassignment in
	/// `seen` (its outputs agree with the other's at every index both commit
	/// to), and otherwise records it in `seen`. See the
	/// [module documentation](self).
	pub fn admit(&self, seen: &mut SeenReassignments) -> Result<(), TransferError> {
		let m = self.outputs.len();
		if m == 0 || m > MAX_OUTPUTS as usize {
			return Err(TransferError::Outputs(m));
		}
		let inputs: Vec<(LeafId, u64)> = self.inputs.iter().map(|(c, v)| (c.id, *v)).collect();
		seen.admit(&inputs, &self.outputs)
	}
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Every coin a record's lineage spends, by its id and its leaf's salt: to
/// refuse one spent twice, and one leaf promised by two reassignments.
struct Spent(Vec<(LeafId, [u8; 32])>);

impl Spent {
	fn add(&mut self, coin: &ValidCoin) -> Result<(), TransferError> {
		if self.0.iter().any(|(id, _)| *id == coin.id) {
			return Err(TransferError::DoubleSpend(coin.id));
		}
		self.check_salt(coin)?;
		self.0.push((coin.id, coin.leaf.salt));
		Ok(())
	}

	fn check_salt(&self, coin: &ValidCoin) -> Result<(), TransferError> {
		match self.0.iter().find(|(_, salt)| *salt == coin.leaf.salt) {
			Some((first, _)) => Err(TransferError::SaltTwice { first: *first, second: coin.id }),
			None => Ok(()),
		}
	}
}

impl CoinRecord {
	/// The check a wallet runs before it accepts a coin it receives: every
	/// check of [`CoinRecord::resolve`], then that the coin is for `owner`
	/// with the nonce the wallet published, its exit delay within the
	/// policy, and no deeper than [`DEPTH_LIMIT`] reassignments from a round.
	pub fn validate(&self, rounds: &[Transaction], policy: &WalletPolicy, owner: &XOnlyPublicKey, owner_nonce: &[u8; 32])
		-> Result<ValidCoin, TransferError>
	{
		let (key, nonce, delay) = match self {
			CoinRecord::Leaf { record, .. } => (record.owner, record.owner_nonce, record.exit_delay),
			CoinRecord::Transfer(t) => (t.leaf.owner, t.leaf.owner_nonce, t.leaf.exit_delay),
			CoinRecord::Board(b) => (b.owner, b.owner_nonce, b.exit_delay),
		};
		if key != *owner {
			return Err(TransferError::NotOwner);
		}
		if nonce != *owner_nonce {
			return Err(TransferError::OwnerNonce);
		}
		if !policy.exit_delay_ok(delay) {
			return Err(TransferError::ExitDelay);
		}
		let coin = self.resolve(rounds, policy)?;
		if coin.hops > DEPTH_LIMIT {
			return Err(TransferError::DepthLimit { hops: coin.hops, limit: DEPTH_LIMIT });
		}
		Ok(coin)
	}

	/// Checks the record from the batches up, against `rounds` (the round
	/// transactions the record's batch leaves came from, in any order) and
	/// under `policy`: see the [module documentation](self). This does not
	/// check whose coin it is; [`CoinRecord::validate`] does.
	pub fn resolve(&self, rounds: &[Transaction], policy: &WalletPolicy) -> Result<ValidCoin, TransferError> {
		let mut spent = Spent(vec![]);
		let coin = self.resolve_in(rounds, policy, &mut spent, 0)?;
		spent.check_salt(&coin)?;
		Ok(coin)
	}

	fn resolve_in(&self, rounds: &[Transaction], policy: &WalletPolicy, spent: &mut Spent, depth: usize)
		-> Result<ValidCoin, TransferError>
	{
		if depth > MAX_HOPS {
			return Err(TransferError::TooDeep);
		}
		match self {
			CoinRecord::Leaf { record, preimage, auths } => {
				let out = record.branch()?.batch_output();
				let round = rounds.iter()
					.find(|r| r.output.iter().any(|o| ExplicitOutput::from_txout(o).as_ref() == Some(&out)))
					.ok_or(TransferError::RoundMissing)?;
				let valid = record.validate_round(round, policy)?;
				if sha256(preimage) != record.unlock_hash {
					return Err(TransferError::Preimage);
				}
				let nodes = &valid.branch.nodes;
				if auths.len() != nodes.len() {
					return Err(TransferError::Auths { given: auths.len(), needed: nodes.len() });
				}
				let mut unroll = Vec::with_capacity(auths.len());
				for (level, ((sig, t), node)) in auths.iter().zip(nodes).enumerate() {
					if !verify_digest(sig, &node.unroll_authorisation(*t).digest, &record.owner) {
						return Err(TransferError::AuthSignature(level));
					}
					if t.to_consensus_u32() > policy.now.to_consensus_u32() {
						return Err(TransferError::AuthTime(level));
					}
					unroll.push(node.owner_auth(*sig, *t, record.owner));
				}
				let leaf = record.leaf();
				let id = valid.leaf_id;
				Ok(ValidCoin {
					id, leaf, asset: record.asset, value: record.value, sweep: record.schedule.sweep(true, record.burn),
					expiry: record.schedule.expiries()[0], hops: 0,
					origin: ValidOrigin::Leaf { valid, preimage: *preimage, auths: unroll },
				})
			},
			CoinRecord::Board(record) => {
				let out = record.output();
				let tx = rounds.iter()
					.find(|r| r.output.iter().any(|o| ExplicitOutput::from_txout(o).as_ref() == Some(&out)))
					.ok_or(TransferError::RoundMissing)?;
				let valid = record.validate(tx, policy)?;
				Ok(ValidCoin {
					id: valid.leaf_id, leaf: record.leaf(), asset: record.asset, value: record.value,
					sweep: board_sweep(record.operator, record.exit_delay), expiry: NEVER, hops: 0,
					origin: ValidOrigin::Board { valid, record: *record },
				})
			},
			CoinRecord::Transfer(t) => {
				let n = t.inputs.len();
				if n == 0 || n > MAX_INPUTS {
					return Err(TransferError::Inputs(n));
				}
				let m = t.outputs.len();
				if m == 0 || m > MAX_OUTPUTS as usize {
					return Err(TransferError::Outputs(m));
				}
				if t.index as usize >= m {
					return Err(TransferError::Index { index: t.index as usize, count: m });
				}
				for (j, o) in t.outputs.iter().enumerate() {
					if o.value == 0 || o.value > MAX_VALUE {
						return Err(RecordError::Value(o.value).into());
					}
					if t.outputs[..j].iter().any(|p| p.script_pubkey == o.script_pubkey) {
						return Err(TransferError::DuplicateOutput);
					}
				}
				let mut inputs = Vec::with_capacity(n);
				let mut held: Vec<(AssetId, u64)> = vec![];
				for (k, input) in t.inputs.iter().enumerate() {
					// Every input resolves under the receiver's policy, so its
					// leaf is the policy's operator's, on the policy's chain.
					let coin = input.coin.resolve_in(rounds, policy, spent, depth + 1)?;
					spent.add(&coin)?;
					if input.checkpoint_value == 0 || input.checkpoint_value > coin.value {
						return Err(TransferError::CheckpointValue { value: input.checkpoint_value, coin: coin.value });
					}
					let checkpoint = coin.checkpoint();
					let cp_out = ExplicitOutput::new(coin.asset, input.checkpoint_value, checkpoint.script_pubkey());
					coin.leaf.verify(coin.asset, coin.value, &[cp_out], &input.checkpoint)
						.map_err(|error| TransferError::Pair { input: k, pair: "checkpoint", error })?;
					checkpoint.verify(coin.asset, input.checkpoint_value, &t.outputs, &input.reassignment)
						.map_err(|error| TransferError::Pair { input: k, pair: "reassignment", error })?;
					match held.iter_mut().find(|(a, _)| *a == coin.asset) {
						Some((_, v)) => *v = v.checked_add(input.checkpoint_value).ok_or(SpendError::Overflow)?,
						None => held.push((coin.asset, input.checkpoint_value)),
					}
					inputs.push(ValidInput {
						checkpoint, checkpoint_value: input.checkpoint_value, checkpoint_pair: input.checkpoint,
						reassignment_pair: input.reassignment, coin,
					});
				}
				for (asset, _) in t.outputs.iter().map(|o| (o.asset, o.value)) {
					let out: u64 = t.outputs.iter().filter(|o| o.asset == asset).map(|o| o.value).sum();
					let have = held.iter().find(|(a, _)| *a == asset).map(|(_, v)| *v).unwrap_or(0);
					if out > have {
						return Err(TransferError::Overspend(asset));
					}
				}
				// The new leaf is in the receiver's lineage whoever owns it: a
				// short exit delay anywhere lets its owner exit before the
				// receiver can answer.
				if !policy.exit_delay_ok(t.leaf.exit_delay) {
					return Err(TransferError::LineageExitDelay {
						hops: depth, delay: t.leaf.exit_delay.units(), min: policy.min_exit_delay.units(),
						max: policy.max_exit_delay.units(),
					});
				}
				let first = &inputs[0].coin;
				let leaf = t.leaf.policy(first.leaf.operator, first.leaf.chain);
				let mine = &t.outputs[t.index as usize];
				if mine.script_pubkey != leaf.script_pubkey() {
					return Err(TransferError::LeafMismatch);
				}
				let parts: Vec<(LeafId, [u8; 32])> = inputs.iter().map(|i| (i.coin.id, i.checkpoint.taproot().program())).collect();
				let id = transfer_id(&parts, &t.outputs, t.index, &leaf.program());
				Ok(ValidCoin {
					id, leaf, asset: mine.asset, value: mine.value, sweep: first.sweep,
					expiry: inputs.iter().map(|i| i.coin.expiry).min_by_key(|e| e.to_consensus_u32()).expect("one input"),
					hops: 1 + inputs.iter().map(|i| i.coin.hops).max().expect("one input"),
					origin: ValidOrigin::Transfer { inputs, outputs: t.outputs.clone(), index: t.index as usize },
				})
			},
		}
	}

	// -----------------------------------------------------------------------
	// The binary form
	// -----------------------------------------------------------------------

	/// The binary form.
	pub fn to_bytes(&self) -> Result<Vec<u8>, TransferError> {
		let mut w = vec![COIN_RECORD_VERSION];
		self.write(&mut w, 0)?;
		Ok(w)
	}

	fn write(&self, w: &mut Vec<u8>, depth: usize) -> Result<(), TransferError> {
		if depth > MAX_HOPS {
			return Err(TransferError::TooDeep);
		}
		match self {
			CoinRecord::Leaf { record, preimage, auths } => {
				w.push(0);
				let b = record.to_bytes()?;
				let len = u16::try_from(b.len()).map_err(|_| DecodeError::Count(b.len() as u64))?;
				w.extend(len.to_le_bytes());
				w.extend(b);
				w.extend(preimage);
				w.push(auths.len() as u8);
				for (s, t) in auths {
					w.extend(s.as_ref());
					w.extend(t.to_consensus_u32().to_le_bytes());
				}
			},
			CoinRecord::Board(record) => {
				w.push(2);
				let b = record.to_bytes()?;
				w.extend((b.len() as u16).to_le_bytes());
				w.extend(b);
			},
			CoinRecord::Transfer(t) => {
				if t.inputs.is_empty() || t.inputs.len() > MAX_INPUTS {
					return Err(TransferError::Inputs(t.inputs.len()));
				}
				if t.outputs.is_empty() || t.outputs.len() > MAX_OUTPUTS as usize {
					return Err(TransferError::Outputs(t.outputs.len()));
				}
				w.push(1);
				w.push(t.inputs.len() as u8);
				for i in &t.inputs {
					i.coin.write(w, depth + 1)?;
					w.extend(i.checkpoint_value.to_le_bytes());
					for s in [&i.checkpoint.operator, &i.checkpoint.owner, &i.reassignment.operator, &i.reassignment.owner] {
						w.extend(s.as_ref());
					}
				}
				w.push(t.outputs.len() as u8);
				for o in &t.outputs {
					w.extend(asset_bytes(o.asset));
					w.extend(o.value.to_le_bytes());
					let spk = o.script_pubkey.as_bytes();
					if spk.len() > MAX_DESTINATION {
						return Err(DecodeError::Count(spk.len() as u64).into());
					}
					write_compact_size(w, spk.len() as u64);
					w.extend(spk);
				}
				w.push(t.index);
				w.extend(t.leaf.owner.serialize());
				w.extend(t.leaf.owner_nonce);
				w.extend(t.leaf.creator_nonce);
				w.extend(t.leaf.exit_delay.units().to_le_bytes());
			},
		}
		Ok(())
	}

	/// Reads the binary form, which must hold exactly one record.
	pub fn from_bytes(data: &[u8]) -> Result<CoinRecord, TransferError> {
		let mut r = Reader::new(data);
		let v = r.u8()?;
		if v != COIN_RECORD_VERSION {
			return Err(TransferError::Version(v));
		}
		let c = CoinRecord::read(&mut r, 0)?;
		if r.remaining() != 0 {
			return Err(DecodeError::TrailingBytes(r.remaining()).into());
		}
		Ok(c)
	}

	fn read(r: &mut Reader, depth: usize) -> Result<CoinRecord, TransferError> {
		if depth > MAX_HOPS {
			return Err(TransferError::TooDeep);
		}
		match r.u8()? {
			0 => {
				let len = r.u16()? as usize;
				let record = LeafRecord::from_bytes(r.bytes(len)?)?;
				let preimage = r.array32()?;
				let n = r.u8()? as usize;
				let mut auths = Vec::with_capacity(n);
				for _ in 0..n {
					let s = Signature::from_slice(r.bytes(64)?).map_err(|_| DecodeError::Key)?;
					auths.push((s, r.median_time()?));
				}
				Ok(CoinRecord::Leaf { record, preimage, auths })
			},
			1 => {
				let n = r.u8()? as usize;
				if n == 0 || n > MAX_INPUTS {
					return Err(TransferError::Inputs(n));
				}
				let mut inputs = Vec::with_capacity(n);
				for _ in 0..n {
					let coin = CoinRecord::read(r, depth + 1)?;
					let checkpoint_value = r.u64()?;
					let mut sigs = [None; 4];
					for s in sigs.iter_mut() {
						*s = Some(Signature::from_slice(r.bytes(64)?).map_err(|_| DecodeError::Key)?);
					}
					let [a, b, c, d] = sigs.map(|s| s.expect("read"));
					inputs.push(TransferInput {
						coin, checkpoint_value, checkpoint: Pair { operator: a, owner: b }, reassignment: Pair { operator: c, owner: d },
					});
				}
				let m = r.u8()? as usize;
				if m == 0 || m > MAX_OUTPUTS as usize {
					return Err(TransferError::Outputs(m));
				}
				let mut outputs = Vec::with_capacity(m);
				for _ in 0..m {
					let asset = r.asset()?;
					let value = r.u64()?;
					let len = r.compact_size()?;
					if len > MAX_DESTINATION as u64 {
						return Err(DecodeError::Count(len).into());
					}
					outputs.push(ExplicitOutput::new(asset, value, Script::from(r.bytes(len as usize)?.to_vec())));
				}
				let index = r.u8()?;
				if index as usize >= m {
					return Err(TransferError::Index { index: index as usize, count: m });
				}
				let leaf = NewLeaf { owner: r.key()?, owner_nonce: r.array32()?, creator_nonce: r.array32()?, exit_delay: r.relative_time()? };
				Ok(CoinRecord::Transfer(Box::new(Transfer { inputs, outputs, index, leaf })))
			},
			2 => {
				let len = r.u16()? as usize;
				Ok(CoinRecord::Board(BoardRecord::from_bytes(r.bytes(len)?)?))
			},
			t => Err(TransferError::Tag(t)),
		}
	}
}
