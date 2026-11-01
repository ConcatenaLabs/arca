//! Arca's covenant scripts on Sequentia.
//!
//! Every output in an Arca batch is a taproot output with the BIP341 NUMS
//! point as its internal key, so it has no key path, and tapscript leaves at
//! leaf version `0xc4` hashed with the Elements tags. This crate builds those
//! leaves, the outputs that carry them, the messages their signatures cover and
//! the witnesses that spend them:
//!
//! - the tree ([`node`]): the gated UNROLL with its timed authorisation, the
//!   sweep behind the token ([`sweep`]), and the RECLAIM of a lowest node,
//!   with the release each owner signs for it, bound to the round of its new
//!   leaf ([`release`]);
//! - the expiry clock ([`clock`]): ROLL, RELEASE, the script `R` the token
//!   rests at once released, the chain of clocks built last one first, and the
//!   operator's release and roll of the token; and the sweep transaction
//!   ([`sweep::sweep_tx`]) that takes a batch's outputs behind the token;
//! - the leaf ([`leaf`]): the rebindable collaborative path and the exit,
//!   or, for `htlc-1` ([`htlc`]), a claim with a preimage and a refund after a
//!   timeout in place of the exit; for `vtxo-2` ([`collab`]) the
//!   collaborative path is the Simplicity program `arca/collab-2`, which also
//!   binds the coin's index and the inputs its signers name;
//! - the outputs around it: the hash-locked entry ([`entry`]), the forfeit
//!   bound to the leaf it gives up and to its round ([`forfeit`]), the
//!   checkpoint ([`checkpoint`]), the offboard output with the margin its
//!   unlock takes ([`offboard`]) and the round's connector output, which only the issuance
//!   of the round's connector asset spends ([`forfeit::ConnectorPolicy`]);
//! - the five checks a wallet runs on a round transaction and its published
//!   clock schedule ([`checks`]), the fifth refusing a batch that its round
//!   funds by reissuing its asset unless every sweep above the leaf is
//!   burn-only;
//! - issuer-operated batches ([`issuer`]): the burn their sweeps end in, and
//!   what a transaction issues and burns of an asset; and the mint limiter
//!   their asset's reissuance token rests in ([`limiter`]): its coin's script
//!   in each state, the state a mint leads to, and what a spend of the coin
//!   did;
//! - the leaf record ([`record`]): what a holder keeps, its id, its binary
//!   and JSON forms ([`record_json`]), and its validation against the round;
//! - the tree builder ([`tree`]), which turns the leaves of one asset into a
//!   batch and gives each owner its record, and the unroll ([`unroll`]): the
//!   transactions from the batch output down to a leaf, with the reserve or a
//!   fee coin paying;
//! - the out-of-round transfer ([`transfer`]): the checkpoint and the
//!   reassignment, for one or several coins and owners, and the coin record a
//!   receiver validates back to the batches and boards it came from;
//! - an on-chain order a round fills ([`fill`]): SeqDEX's fill covenant, its
//!   terms as the relay serves them, the credit at `2k` and remainder at
//!   `2k+1` its FILL leaf reads, that leaf's judgement of a transaction, the
//!   maker's REFUND once its lock has passed, and the id a holder's take of
//!   an order is attested by;
//! - the board (`board-1`: the leaf's collaborative path and the owner's
//!   conversion into the leaf) and its record ([`board`]), and the
//!   transactions that spend a leaf outside the unroll ([`spend`]): its exit,
//!   its forfeit with the claim and the refund, the offboard's unlock and
//!   reclaim, the margin or a fee coin paying;
//! - signature hashes and signing ([`sign`]), the binary encodings of every
//!   policy ([`encode`]) and the reading of witnesses found on-chain
//!   ([`witness`]);
//! - claim trees ([`claim`]): the claim key a holder's leaf is owned by,
//!   derived from the key a payer names and a nonce, the distribution a
//!   payer submits to pay many holders in one round, and `claim-1`, the
//!   claim leaf whose LAPSE pays the payer back what nobody took up by the
//!   distribution's deadline;
//! - a resting order in the tree ([`order`]): the `order-2` leaf, which the
//!   operator fills with the maker offline under a Simplicity program, which
//!   pays each credit to a leaf of its own, and which lands, one exit delay
//!   after it reaches the chain, as SeqDEX's own order for the same terms;
//! - the leaf of a supervised asset ([`landing`]): `landing-1`, whose exit
//!   pays only P2WPKH of the owner's landing key, where a freeze of the asset
//!   binds, and whose collaborative constant commits to that key too; and
//!   the check that a round of a supervised asset keeps every output
//!   explicit;
//! - the leaf of a restricted asset ([`enclave`]): `enclave-1`, whose exit
//!   pays only its holder's enclave, in full, whose owner key is derived from
//!   the holder's registered key, and which carries the asset's claw leaf
//!   where the asset elected clawback;
//! - offline refresh ([`plan`]): a plan of refresh steps the operator applies
//!   without the holder, and each step's refund, which spends the coin given
//!   up and the new leaf together by their collaborative paths and pays the
//!   holder first;
//! - `channel-1` ([`channel`]): a leaf with a balance for each of owner and
//!   operator, replaced at once by a newer state both sign, settled after the
//!   exit delay, the operator's balance landing in a credit output from which
//!   the owner claims what the operator's cumulative note credits;
//! - the operator's equivocation bond ([`bond`]): a coin anyone burns with
//!   two different messages the operator key signed under one coin's salt,
//!   and which the operator withdraws only a delay after a public notice;
//! - the operator record ([`operator_record`]): what an operator publishes
//!   about itself in the Sequentia registry, its canonical form and the
//!   signature of the operator key over it.
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

pub mod accumulator;
pub mod accumulator_programs;
pub mod batch;
pub mod board;
pub mod bond;
pub mod channel;
pub mod checkpoint;
pub mod checks;
pub mod collab;
pub mod claim;
pub mod clock;
pub mod encode;
pub mod entry;
pub mod fill;
pub mod forfeit;
pub mod gate;
pub mod htlc;
pub mod issuer;
pub mod enclave;
pub mod landing;
pub mod leaf;
pub mod limiter;
pub mod message;
pub mod node;
pub mod offboard;
#[cfg(feature = "json")]
pub mod operator_record;
pub mod order;
pub mod order_programs;
pub mod plan;
pub mod record;
pub mod release;
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

pub use accumulator::{
	Accumulator, AccumulatorError, AccumulatorParams, AccumulatorPolicy, AccumulatorRecord, AccumulatorRelease, Bitmap, Exit, ExitAuth,
	ReleaseSpend, Released, SeenExit, SeenRelease, SeenSpend, Slot, ValidAccumulatorLeaf,
};
pub use batch::{Batch, BatchKind};
pub use board::{BoardPolicy, BoardRecord, ValidBoard};
pub use bond::{BondError, BondPolicy, BondState, Cosigned, Evidence, Form, Signed};
pub use channel::{Channel, ChannelError, ChannelPolicy, ChannelSpend, ChannelTerms, State};
pub use checkpoint::CheckpointPolicy;
pub use checks::{check_reissue, check_round, RoundCheckFailure};
pub use claim::{claim_key, claim_keypair, script_pin, Claim, ClaimError, Distribution, DistributionLapse, Lapse, LapseError, LapseTerms};
pub use clock::{no_sweep_token, Clock, ClockSchedule, TokenPlace};
pub use entry::EntryPolicy;
pub use fill::{FillError, FillOrder, FillPlan, Filled, RefundLock, Take, TakeLeaf};
pub use forfeit::{batch_claim_tx, connector_asset, ClaimTx, ConnectorPolicy, Forfeit, ForfeitPolicy};
pub use gate::{GateCommitment, MemberProof, Members};
pub use htlc::{HtlcDirection, HtlcPath, HtlcTerms};
pub use enclave::{enclave_key, enclave_keypair, Enclave, EnclaveError, EnclaveTerms};
pub use landing::{Landing, LandingError, LandingTerms};
pub use leaf::LeafPolicy;
pub use limiter::{LimiterError, LimiterParams, LimiterSpend, LimiterState};
pub use message::{Chain, CsfsMessage};
pub use node::{NodePolicy, ReleaseTree};
pub use offboard::OffboardPolicy;
pub use order::{OrderError, OrderFillPlan, OrderFilled, OrderLeafTerms, OrderPath, OrderPolicy, OrderTerms, SeqdexOrder};
pub use plan::{Plan, PlanError, PlanStep, Refund};
pub use record::{Branch, BranchNode, LeafId, LeafRecord, Recheck, RecordError, ReserveFloor, Template, ValidLeaf, WalletPolicy};
pub use release::{Delegation, Release};
pub use script::{Child, ExplicitOutput};
pub use spend::{collab_tx, KeySpend, Pair, Rebindable, SpendError};
pub use sweep::{sweep_tx, Sweep, SweepTx, Sweepable};
pub use taptree::TapOutput;
pub use time::{MedianTime, RelativeTime};
pub use transfer::{
	CoinRecord, LineageKind, LineageOutput, NewLeaf, SeenReassignments, Transfer, TransferError, TransferInput, TransferPlan,
	ValidCoin, ValidInput, ValidOrigin,
};
pub use tree::{LeafSpec, ReserveRule, Tree, TreeError, TreeParams};
pub use unroll::{FeeSource, UnrollAuth, UnrollTx};

/// Why a policy cannot be built or a spend cannot be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
	#[error("order-2's terms: {0}")]
	OrderTerms(String),
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
	#[error("the releases need {0} steps of RECLAIM-D, which has 32")]
	ReclaimSteps(usize),
	#[error("the clock schedule is empty")]
	EmptySchedule,
	#[error("a schedule naming the no-sweep token is the never schedule, with nothing else in it")]
	NoSweepSchedule,
	#[error("a batch without a sweep has no token, clock or sweep")]
	NoSweep,
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
	#[error("an htlc-1 leaf's operator delay of {operator} units is not shorter than its owner's delay of {owner}")]
	HtlcDelays { operator: u16, owner: u16 },
	#[error("an htlc-1 leaf has no exit: it is spent by its claim, its refund or its collaborative path")]
	HtlcHasNoExit,
	#[error("a vtxo-1 leaf has no {0} path")]
	NotAnHtlc(&'static str),
	#[error("a vtxo-2 pair names {0} inputs; it names 1 to {max}", max = collab::MAX_NAMED)]
	NamedCount(usize),
	#[error("named input {0}'s asset or amount is not explicit")]
	NamedNotExplicit(usize),
}
