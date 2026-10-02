//! Arca's covenant scripts on Sequentia.
//!
//! Every output in an Arca batch is a taproot output with the BIP341 NUMS
//! point as its internal key, so it has no key path, and tapscript leaves at
//! leaf version `0xc4` hashed with the Elements tags. This crate builds those
//! leaves, the outputs that carry them, the messages their signatures cover and
//! the witnesses that spend them:
//!
//! - the tree ([`node`]): the gated UNROLL with its timed authorisation, the
//!   sweep behind the token ([`sweep`]), and the RECLAIM of a lowest node;
//! - the expiry clock ([`clock`]): ROLL, RELEASE, the script `R` the token
//!   rests at once released, and the chain of clocks built last one first;
//! - the leaf ([`leaf`]): the rebindable collaborative path and the exit;
//! - the outputs around it: the hash-locked entry ([`entry`]), the forfeit
//!   bound to the leaf it gives up and to its round ([`forfeit`]), the
//!   checkpoint ([`checkpoint`]), `htlc-1` ([`htlc`]) and the offboard output
//!   ([`offboard`]);
//! - the five checks a wallet runs on a round transaction and its published
//!   clock schedule ([`checks`]);
//! - the leaf record ([`record`]): what a holder keeps, its id, its binary
//!   and JSON forms ([`record_json`]), and its validation against the round;
//! - the tree builder ([`tree`]), which turns the leaves of one asset into a
//!   batch and gives each owner its record, and the unroll ([`unroll`]): the
//!   transactions from the batch output down to a leaf, with the reserve or a
//!   fee coin paying;
//! - the out-of-round transfer ([`transfer`]): the checkpoint and the
//!   reassignment, for one or several coins and owners, and the coin record a
//!   receiver validates back to the batches it came from;
//! - the board and its record ([`board`]), and the transactions that spend a
//!   leaf outside the unroll ([`spend`]): its exit, its forfeit with the claim
//!   and the refund, the offboard's unlock and reclaim, the margin or a fee
//!   coin paying;
//! - signature hashes and signing ([`sign`]), the binary encodings of every
//!   policy ([`encode`]) and the reading of witnesses found on-chain
//!   ([`witness`]).
//!
//! The scripts are frozen. Each one equals, byte for byte, the golden vector the
//! regtest suite exports (`regtest/vectors/arca.json`), and the tests spend
//! every path through the node's own interpreter.
//!
//! Amounts are explicit and carry their asset: Sequentia is transparent by
//! default and has no privileged asset, so nothing here assumes one. Every lock
//! is time based: absolute times are median-time values ([`MedianTime`]) and
//! delays are 512-second units ([`RelativeTime`]).

pub extern crate elements;

pub mod board;
pub mod checkpoint;
pub mod checks;
pub mod clock;
pub mod encode;
pub mod entry;
pub mod forfeit;
pub mod gate;
pub mod htlc;
pub mod leaf;
pub mod message;
pub mod node;
pub mod offboard;
pub mod record;
#[cfg(feature = "json")]
pub mod record_json;
pub mod script;
pub mod sign;
pub mod spend;
pub mod sweep;
pub mod taptree;
pub mod time;
pub mod transfer;
pub mod tree;
pub mod unroll;
pub mod witness;

pub use board::{BoardRecord, ValidBoard};
pub use checkpoint::CheckpointPolicy;
pub use checks::{check_round, RoundCheckFailure};
pub use clock::{Clock, ClockSchedule};
pub use entry::EntryPolicy;
pub use forfeit::{connector_asset, connector_issuance, Forfeit, ForfeitPolicy};
pub use gate::{GateCommitment, MemberProof, Members};
pub use htlc::{HtlcDirection, HtlcPolicy, HtlcSalts};
pub use leaf::LeafPolicy;
pub use message::{Chain, CsfsMessage};
pub use node::NodePolicy;
pub use offboard::OffboardPolicy;
pub use record::{Branch, BranchNode, LeafId, LeafRecord, RecordError, Template, ValidLeaf, WalletPolicy};
pub use script::{Child, ExplicitOutput};
pub use spend::{collab_tx, KeySpend, Pair, Rebindable, SpendError};
pub use sweep::Sweep;
pub use taptree::TapOutput;
pub use time::{MedianTime, RelativeTime};
pub use transfer::{CoinRecord, NewLeaf, Transfer, TransferError, TransferInput, TransferPlan, ValidCoin, ValidInput, ValidOrigin};
pub use tree::{LeafSpec, ReserveRule, Tree, TreeError, TreeParams};
pub use unroll::{FeeSource, UnrollAuth, UnrollTx};

/// Why a policy cannot be built or a spend cannot be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
	#[error("a node has {0} children; it must have 1 to 6")]
	ChildCount(usize),
	#[error("a rebindable spend commits to {0} outputs; it must commit to 1 to {max}", max = leaf::MAX_OUTPUTS)]
	OutputCount(usize),
	#[error("a lowest node needs at least one owner for its reclaim")]
	NoOwners,
	#[error("{0} owners under one node is more than the {max} a node takes", max = gate::MAX_OWNERS)]
	TooManyOwners(usize),
	#[error("the key is not a member of this node")]
	NotAMember,
	#[error("{given} owner signatures given for a reclaim that needs {needed}")]
	ReclaimSignatures { given: usize, needed: usize },
	#[error("the clock schedule is empty")]
	EmptySchedule,
	#[error("the clock schedule runs backwards: expiry {index} is earlier than the one before it")]
	ScheduleBackwards { index: usize },
	#[error("a clock schedule has at most {max} steps", max = clock::MAX_STEPS)]
	TooManySteps,
	#[error("the input index {0} is out of range")]
	InputIndex(usize),
	#[error("cannot compute the signature hash: {0}")]
	Sighash(String),
	#[error(transparent)]
	Time(#[from] time::TimeError),
}
