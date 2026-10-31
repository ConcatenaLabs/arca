//! The round: what turns pending participations into batches on-chain.
//!
//! A round carries one asset. Each asset the operator serves has rounds of
//! its own and a pool of its own, the operator's wallet's coins of that
//! asset, which fund its batches; a participation carries one asset too
//! (every coin it gives up, every output it wants and every fee it pays),
//! so the round builder never mixes assets, and one asset's round that
//! cannot be built (its pool short, the node refusing it) holds back no
//! other's. At each round interval the runner builds a round for every asset
//! whose participations wait ([`Rounds::run_rounds`]): it gathers that
//! asset's pending participations whose earliest round time has come,
//! checks their coins again, takes those the operator's wallet can fund
//! (what the round pays for them, the batch output with its reserves and
//! offboard outputs, then its own fee and connector; one that does not fit
//! waits, saying why, and delays no other), and builds the asset's tree
//! with `arca-covenant`'s builder ([`arca_covenant::Tree::build`]): balanced
//! at radix 4, every node gated, RECLAIM on the lowest nodes, each leaf
//! behind its participation's hash-locked entry, the reserve at four times the
//! node's floor in the batch asset (one atom where the node does not accept
//! the asset for fees, so whoever unrolls attaches a fee coin). With
//! [`RoundConfig::accumulator_exit_rate_ppm`] set, a batch whose expected
//! exits cost less from one output is built as an accumulator batch instead
//! ([`BatchKind::choose`]): the same entries under one output, from which each
//! leaf leaves in one transaction. Each batch has
//! a sweep token of its own, issued as one explicit atom with no reissuance
//! token by one of the operator's coins, and a clock schedule of three steps
//! (28, 56 and 84 days after the round) with a notice of 36 hours.
//!
//! The round transaction pays, in order (after the orders' outputs in a round
//! that fills on-chain orders, below): each batch output followed by its
//! token's atom to the batch's first clock, then every offboard output, then
//! the connector output (`arca_covenant::ConnectorPolicy`), whose only spend
//! issues the round's connector asset, then change per asset and the one fee
//! output. A round of refreshes spends the operator's own coins and nothing
//! else: it takes no input of a third party, which could be spent elsewhere
//! and keep the round from returning after a rollback. Only a round of its
//! own that fills on-chain orders (below) spends one. A round has
//! `nLockTime` 0 and final inputs, and is kept byte for byte, so the nursery
//! broadcasts it again unchanged after a rollback and it returns with its
//! txid, every forfeit signed for it still good.
//!
//! The fee is paid in one asset: the round's own, when the node accepts it
//! for fees now and it is among the operator's fee assets, else the first of
//! those the node accepts. Never another. A round in an asset the node does
//! not accept for fees therefore draws its fee, and its connector, from the
//! pool of the first fee asset the node accepts.
//!
//! Before anything is recorded the runner checks its own work as a wallet
//! would: every leaf's record validates against the transaction under the
//! acceptance policy (the five checks on the token and its clock among them),
//! the connector output is the operator's, each offboard output is paid once,
//! and the node would accept the transaction now. Then the round, its
//! batches, every leaf (a pending coin until its owner hands over its
//! forfeits) and every participation's move to issued are recorded in one
//! database transaction, and the round goes to the nursery.
//!
//! A participation's coins are checked again when a round is built, and at
//! every pass over the rounds, under the horizon they were accepted under,
//! their exit deadline ([`Params::round_policy`]): a pending participation
//! with a coin past its exit deadline can never run and is voided, its coins
//! given back, whether a round is being built or not. From that deadline the
//! coin's owner takes it on the chain.
//!
//! The owner of each participation in a round hands over its forfeits once
//! the round is final, and the signer co-signs them, until the later of a
//! day after the round was found final ([`Params::FORFEIT_DEADLINE`]) and
//! the exit deadline of the coins it gave up. A forfeit the operator can
//! claim ends in a release ([`Rounds::release_held`]): a participation one
//! of whose forfeits the watcher claimed, or every forfeit of which is whole
//! while every coin it gave up is off the chain, is released by the server
//! itself and its new leaves credited. Otherwise a participation not
//! released by its deadline expires, whether its forfeits never came or
//! came and were never co-signed (the signer away, or its keepers), but for
//! one with some forfeits whole and the rest waiting for the operator's
//! half, which waits for the signer. Each forfeit of an expired
//! participation without the operator's half is dropped, never to be asked
//! of the signer again; each coin it gave up for which no forfeit was ever
//! recorded is the owner's again, live (a coin whose forfeit was recorded,
//! every coin of a participation with a whole forfeit, and one under a
//! forfeit signed for an earlier, lost round stay given up, their owners'
//! on the chain); and its new leaves are never credited: their preimage
//! never goes out, and the operator sweeps them with their batch at expiry.
//!
//! After a rollback the nursery broadcasts a round again unchanged; while it
//! is out of the chain its new leaves are uncredited, and they are credited
//! again once it is final again. A round out of the chain whose input another
//! transaction took, final, is lost: its new leaves are lost, the releases
//! given for it retired, and its participations run again in a later round
//! under new unlock hashes and operator nonces. A lost round can still
//! return: the parent chain can take out the transaction that took its
//! input, however deep, and anyone holding the round can send it again.
//!
//! So a round that runs a lost round's participations again cannot stand in
//! the chain beside it. It spends a coin of the operator's that cannot exist
//! while the lost round is in the chain: an input of the lost round that is
//! still unspent, or, where there is none, an output of a transaction that
//! took one (or of one of the operator's descending from it). Whatever the
//! parent chain does, at most one of the two is in the chain. A re-run runs
//! only with such a coin for every lost round of its participation's; where
//! none of the operator's exists, the participation is voided, saying why,
//! and its coins are its owner's on the chain. The round that spends it
//! records the lost round it replaces and the coin.
//!
//! A round held as lost that is final in the chain again is restored: the
//! round is final, each participation it ran is back as it stood in it
//! (under its unlock hash and operator nonces, its new leaves credited, its
//! releases and its forfeits for the round good again), and each round that
//! ran them again, which can now never confirm beside it, is retired with it;
//! nothing runs a third time for a participation whose first round stands.
//! A participation one of whose coins' salts holds another message the
//! signer co-signed (a forfeit for the round that ran it again, given before
//! its forfeit for this one came) is not brought back: the signer co-signs
//! one message under a salt, ever, so its forfeit for this round can never be
//! signed; its leaves of the round are never credited and their preimage
//! never goes out, and the coin is its owner's on the chain.
//! A participation one of whose coins was spent on the chain otherwise than
//! by its forfeit for the round (that forfeit refunded while the round was
//! out, the coin exited by its owner, or taken by another round's forfeit
//! that came back with the reorganisation) is not brought back: its leaves
//! of the round are never credited, and the server serves them nothing. Their
//! owner holds their records, so they are its to take on the chain, and the
//! loss, one coin's worth, is the operator's; whatever the owner leaves of
//! them the operator sweeps with their batch.
//!
//! A coin with a forfeit for an earlier round in the watcher's log, or whose
//! output the server has seen spent, is never taken into a re-run: such a
//! forfeit may still confirm, from any mempool that saw it, and is its
//! owner's to refund once its delay has run, since no claim of a round out of
//! the chain can be made. The participation is voided, saying why; its coins
//! stay given up, as every coin with a forfeit signed does, and are their
//! owners' on the chain, by that forfeit's refund or by their exit, unless
//! the round returns first and the forfeit is claimed. Every forfeit of the
//! lost round's coins in the watcher's log is given up by the nursery while
//! the round is out, and the log refuses a new one naming it, so the server
//! publishes no forfeit naming a lost round, by any path, a restart
//! included. Nor is a coin under whose salt the signer has co-signed a
//! message, the lost round's forfeit among them: the signer co-signs one
//! message under a salt, ever, since two burn the operator's bond, so such a
//! participation is voided and its coins are their owners' on the chain, by
//! their exits, unless the round returns. Any other re-run (one whose forfeits
//! the signer never co-signed: the round lost before they were whole)
//! completes as an ordinary participation: its forfeit for the new round is
//! taken and checked, the preimage released
//! against it, and the coin left like any forfeited coin (a board lineage to
//! the board's dates, a batch leaf to its batch's expiry, either answered at
//! once if its owner exits). Nothing goes on the chain for a re-run that an
//! ordinary participation would not put there.
//!
//! # Rounds that fill on-chain orders
//!
//! A take ([`crate::participations::Participations::take`]) runs in a round
//! of its own kind, beside the refresh rounds: a fill round of the asset its
//! orders sell ([`Rounds::run_fill_round_of`]), which carries takes and
//! nothing else, so that an input a third party can spend first (an order
//! anyone may fill) never stands in a round that carries refreshes. It is
//! built under the rule every SeqDEX fill covenant reads: the order at input
//! `k`, its maker's credit at output `2k` (the price, in the asset the order
//! is paid in, to the maker's program, paid from the operator's coins of that
//! asset) and at `2k+1` the order resting again with its identical script, or,
//! for a full fill, an output to the operator in the asset the order is paid
//! in ([`gap_value`]); the orders at inputs `0..n-1`, so outputs `0..2n-1` are
//! theirs, and the batch, its token, the connector, change and the fee after
//! them. The orders' own value pays the takers' leaves; the operator's pool of
//! the asset pays the batch's reserves. Before anything is recorded the
//! builder follows each order's FILL leaf over the transaction
//! ([`arca_covenant::FillOrder::check`]), and the node is asked whether it
//! would take it.
//!
//! Each take's order is checked again when its round is built: one spent by
//! another transaction (in a block or the node's mempool), or whose maker can
//! refund it too soon, drops out, its take voided with the reason, and the
//! round is built without it; so is one the node finds spent when the round is
//! put to it. A round that goes out of the chain because an order of it was
//! taken by another transaction that is final is lost like any round: its
//! takes run again, each order checked again, the one taken voided.
//!
//! A fill round pays its makers on the chain from the operator's coins, and
//! what the operator gets for that is each take's forfeits. So it is held,
//! built and unbroadcast, until every take in it has handed over its forfeits
//! (the owner's half of each, which is all the operator needs to complete
//! them), and only then broadcast ([`Rounds::pass`]). A take sees its round,
//! the transaction without its witnesses, in its status, validates its new
//! leaf against it, and signs. A take whose forfeits have not come
//! [`Params::fill_forfeit_window_seconds`] after its round was built (by the
//! chain's median time) is voided, the round dropped unbroadcast and its
//! coins freed, and the takes that did hand theirs over run again in the
//! round built after it. Its preimage goes out once the round is final, as
//! any participation's.
//!
//! A held round goes out only with its orders unspent. At every pass, and
//! before it is handed to the nursery, each of its orders is checked again at
//! the node: one spent meanwhile (anyone may fill an order on the chain while
//! its round waits) drops the round unbroadcast, voids that take with the
//! reason, and runs the others again. When the node refuses a fill round
//! (an order taken between that check and its answer, or a round an older
//! server put to the node regardless), its order inputs are looked up at the
//! node, not in the store's index, which never saw a spend made before the
//! round was handed over: a round whose order another transaction took is
//! retired as lost, like any round another transaction took an input of
//! ([`Rounds::retire`]). The signer is asked for its half of a take's
//! forfeit only once the node holds the round, in its mempool or a block
//! ([`crate::forfeits::Forfeits::fill_unsigned`]), so a forfeit for a round
//! that never reached the chain is never whole. And a round dropped
//! unbroadcast dies on the chain: one of its own coins is spent at once in a
//! transaction of the wallet's ([`Rounds::void_on_chain`]), done again at
//! each pass until one is under way, so the round can never confirm, whoever
//! holds it, and every wallet that signed a forfeit for it sees it gone.
//!
//! Each batch is published ([`Rounds::tree`]): its round, its output, its
//! token's output, the round's connector output, its asset, schedule, radix,
//! reserve rule and smallest leaf, and every leaf as the builder took it, so
//! a wallet, or a mirror, rebuilds every script of the tree and checks it
//! against the round transaction from that alone.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use std::time::Duration;

use elements::encode::{deserialize, serialize};
use elements::hashes::Hash;
use elements::{AssetId, OutPoint, Transaction, Txid};
use tokio::sync::{broadcast, Mutex};

use arca_covenant::encode::Encoding;
use arca_covenant::spend::FeeSource;
use arca_covenant::tree::{LeafSpec, ReserveRule, TreeParams};
use arca_covenant::{
	connector_asset, AccumulatorRecord, Batch, BatchKind, ClockSchedule, CoinRecord, ConnectorPolicy, ExplicitOutput, FillOrder, FillPlan, LeafId,
	MedianTime, OffboardPolicy, RelativeTime, Template, WalletPolicy,
};
use elements::Script;
use sequentia_ext::AssetAmount;

use crate::chain::{ChainEvent, FinalityService};

/// Whether `what` is new for participation `id` under `topic`: a reason a
/// participation is held is logged when it starts or changes, not on every
/// pass of the loop that finds it again (one held across a day of rounds
/// wrote thousands of identical lines).
fn said_anew(id: &[u8; 32], topic: &'static str, what: &str) -> bool {
	static SAID: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<([u8; 32], &'static str), String>>> = std::sync::OnceLock::new();
	let mut said = SAID.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
	if said.len() > 10_000 {
		said.clear();
	}
	match said.get(&(*id, topic)) {
		Some(w) if w == what => false,
		_ => {
			said.insert((*id, topic), what.to_string());
			true
		},
	}
}
use crate::coins;
use crate::fees;
use crate::nursery::{Nursery, NurseryKind};
use crate::params::Params;
use crate::store::{
	BatchRow, FillRow, LeafKind, LeafState, MintRow, NewBatch, NewBatchLeaf, NewCoin, NewOffboard, NewRerun, NewRound, NewRoundFill, NewScript, NewTreeScript,
	ParticipationRow, NurseryState, ParticipationState, RoundRow, RoundState, ScriptKind, Store, StoreError, StoredReserve, TreeScriptKind,
	WalletCoin, WantedKind,
};
use crate::participations::{order_on_chain, outpoint_text, refund_too_soon, ParticipationError};
use crate::signer::SignerClient;
use crate::wallet::{Foreign, Wallet, WalletError};

/// How the runner builds its trees and clocks.
#[derive(Debug, Clone)]
pub struct RoundConfig {
	/// The most children a node has.
	pub radix: usize,
	/// The notice `W` the token waits at `R` before any sweep.
	pub notice: RelativeTime,
	/// The time from a round to its batches' first expiry, and between
	/// steps of the clock, in seconds.
	pub lifetime: u32,
	/// The clock's steps.
	pub steps: usize,
	/// The most leaves one batch holds.
	pub max_batch_leaves: usize,
	/// The share of a batch's leaves, in millionths, the operator expects to
	/// leave on the chain on their own. When it is set, a batch whose
	/// expected exits cost less as an accumulator batch than as a tree is
	/// built as one ([`BatchKind::choose`]); when it is not, every batch is a
	/// tree.
	pub accumulator_exit_rate_ppm: Option<u32>,
	/// The most batches of their own a round builds, one for each holder
	/// that moves its coins soon after it gets them ([`Rounds::holder_of`]),
	/// the largest by value first; 0 puts every leaf of an asset in one
	/// batch. Such a batch empties together: once its holder refreshes again
	/// and releases, the watcher unrolls and reclaims it, and its value is
	/// back in the pool long before it expires.
	pub holder_batches: usize,
	/// How young a coin given up must be, in seconds since its batch's round,
	/// for its holder to count as one that moves its coins soon.
	pub holder_window: u32,
	/// Whether a tree's lowest nodes carry RECLAIM-D beside RECLAIM, so that
	/// a node whose coins were paid on out of round comes back once their
	/// current holders refresh and release it ([`crate::delegations`]). A
	/// wallet that does not read the leaf record's flag refuses such a
	/// batch's leaves, so it is set only once every wallet its holders use
	/// reads it.
	pub delegated_reclaim: bool,
}

/// The lowest nodes of the batch leaves a coin rests on: its own, or each up
/// its lineage of reassignments; `None` when it rests on an accumulator
/// batch, which has none (so no refresh of it completes a node).
fn lowest_nodes(record: &CoinRecord) -> Option<Vec<[u8; 32]>> {
	match record {
		CoinRecord::Leaf { record, .. } => Some(record.branch().ok().and_then(|b| b.nodes.last().map(|n| n.children_hash())).into_iter().collect()),
		CoinRecord::Accumulator { .. } => None,
		CoinRecord::Board(_) => Some(vec![]),
		_ => {
			let mut out = vec![];
			for p in record.parents() {
				out.extend(lowest_nodes(p)?);
			}
			Some(out)
		},
	}
}

/// The children hash of the lowest node above a batch leaf, from its leaf
/// record; `None` for an accumulator batch's leaf.
fn lowest_of(record: &[u8]) -> Option<[u8; 32]> {
	arca_covenant::LeafRecord::from_bytes(record).ok().and_then(|r| r.branch().ok()).and_then(|b| b.nodes.last().map(|n| n.children_hash()))
}

/// How close to its first expiry a coin given up must be for its refresh to
/// run whatever the in-flight cap ([`Rounds::within_cap`]): six days, a day
/// beyond the five before expiry from which a wallet asks for a refresh by
/// itself and the four from which it takes the coin on the chain instead.
pub const CAP_EXEMPT: u32 = 6 * 86_400;

impl Default for RoundConfig {
	/// The specification's: radix 4, a 36-hour notice, three steps of 28
	/// days, at most 1,024 leaves a batch.
	fn default() -> RoundConfig {
		RoundConfig {
			radix: 4,
			notice: RelativeTime::from_seconds_ceil(36 * 3600).expect("36 hours"),
			lifetime: 28 * 86_400,
			steps: 3,
			max_batch_leaves: 1024,
			accumulator_exit_rate_ppm: None,
			holder_batches: 8,
			holder_window: 3 * 86_400,
			delegated_reclaim: false,
		}
	}
}

/// Why a round could not be built or followed.
#[derive(Debug, thiserror::Error)]
pub enum RoundError {
	#[error(transparent)]
	Store(#[from] StoreError),
	#[error("the wallet: {0}")]
	Wallet(#[from] WalletError),
	#[error("the chain: {0}")]
	Chain(String),
	#[error("no asset of the round, and none of the operator's fee assets, is accepted for fees by the node now: {0}")]
	NoFeeAsset(String),
	#[error("the round does not check out as a wallet would check it: {0}")]
	Check(String),
	#[error("the node would not accept the round: {0}")]
	Refused(String),
	#[error("the server has not followed the chain yet")]
	NotSynced,
	/// An issuer-operated asset's mint limiter allows no mint of what the
	/// round would pay now, and why.
	#[error("the round's mint waits: {0}")]
	MintWaits(String),
	#[error("the signer did not sign the round's mint: {0}")]
	Mint(String),
	#[error("{0}")]
	Internal(String),
}

/// The witness a mint limiter's spend carries, for sizing a round's fee
/// before the limiter's tool makes it: the program's witness, its pruned
/// program (1,339 bytes for a mint within a window, 1,296 for one opening a
/// window), its commitment root and its control block, a little over.
const MINT_WITNESS: [usize; 4] = [240, 1_400, 32, 65];

/// A round the runner built and handed to the nursery.
#[derive(Debug, Clone)]
pub struct Built {
	pub round_id: i64,
	pub tx: Transaction,
	/// Each batch: its asset, its output's index and its leaf count.
	pub batches: Vec<(AssetId, u32, usize)>,
	pub offboards: usize,
	pub participations: usize,
	pub connector_vout: u32,
	/// Each on-chain order the round fills: its outpoint, at input `k`, in
	/// input order.
	pub fills: Vec<OutPoint>,
	/// What the nursery heard from the node.
	pub broadcast: String,
}

/// A batch as the operator publishes it: its kind and everything
/// [`Batch::build`] takes, and where the round put it.
#[derive(Debug, Clone)]
pub struct PublishedTree {
	pub round_txid: Txid,
	pub batch_vout: u32,
	pub token_vout: u32,
	pub connector_vout: u32,
	/// A tree, or an accumulator batch (whose `params.radix` is 0).
	pub kind: BatchKind,
	pub params: TreeParams,
	pub leaves: Vec<LeafSpec>,
	/// The latest entry of the signer's record, its running hash and the
	/// signer's signature over them, when the round was built: a witness of
	/// the record every wallet reading the tree keeps.
	pub signer_head: Option<(u64, [u8; 32], Option<[u8; 64]>)>,
	/// Where the round stands.
	pub round_state: RoundState,
	/// Each leaf's preimage, in tree order, once its participation's
	/// preimage went out: it opens the leaf's entry, which pays the leaf's
	/// own script and nothing else, so it lets an owner whose record is gone
	/// take the leaf on the chain from the published tree alone.
	pub preimages: Vec<Option<[u8; 32]>>,
}

/// One leaf the round builds: the participation, the output, the spec.
struct Planned {
	participation: usize,
	output: u16,
	spec: LeafSpec,
}

/// One offboard the round pays.
struct PlannedOffboard {
	participation: usize,
	output: u16,
	policy: OffboardPolicy,
	margin: u64,
}

/// An on-chain order a fill round fills: the takes that ask for it (their
/// indices among the round's participations, one or several), the order's
/// outpoint, terms and what it holds, and the fill, of all of them together.
struct PlannedFill {
	participations: Vec<usize>,
	order: OutPoint,
	terms: FillOrder,
	locked: u64,
	plan: FillPlan,
}

/// The most orders one round fills.
pub const MAX_FILLS: usize = 16;

/// The most takes one round runs, of all its orders together.
pub const MAX_TAKES: usize = 64;

/// The value of the output a full fill puts at its `2k+1`, which the FILL
/// leaf reads only for its asset, an explicit one other than the order's:
/// one atom of the asset the order is paid in, to the operator, or, where
/// that asset pays the round's fee, a value well above the node's dust
/// threshold for such an output in its fee asset (399 atoms at the default
/// dust relay fee).
pub fn gap_value(asset: AssetId, fee_asset: AssetId) -> u64 {
	if asset == fee_asset { 1_000 } else { 1 }
}

/// A coin a round spends to keep it apart from a lost round whose
/// participations it runs again: an input of the lost round, or an output of
/// a transaction descending from one that took an input of it (`via`, the
/// transaction that took it).
#[derive(Debug, Clone)]
struct Tie {
	replaces: i64,
	coin: WalletCoin,
	via: Option<Txid>,
}

/// The coins of the operator's that can keep a re-run apart from a lost
/// round: those spendable now, and whether any is unspent but not yet.
struct TieCoins {
	now: Vec<(WalletCoin, Option<Txid>)>,
	later: bool,
}

/// Why a participation run again after `round` is not taken when no coin of
/// the operator's can keep its re-run apart from that round.
fn no_tie(round: &Txid) -> String {
	format!("no coin of the operator's can keep a re-run apart from round {}, which went out of the chain: no input of it is \
		unspent and the operator's, and no transaction that took one paid the operator. That round can still return with the parent \
		chain, so the participation is not run again; its coins are its owner's on the chain, and if the round returns the server \
		restores it, and the participation as it stood in it", round)
}

/// See the [module documentation](self).
pub struct Rounds {
	store: Store,
	finality: Arc<FinalityService>,
	params: Arc<Params>,
	wallet: Arc<Wallet>,
	nursery: Arc<Nursery>,
	/// The signer, which signs an issuer-operated asset's mint
	/// ([`crate::issuer`]).
	signer: SignerClient,
	config: RoundConfig,
	/// One round at a time.
	running: Mutex<()>,
	/// One spend at a time of a dropped round's own coin
	/// ([`Rounds::void_on_chain`]), so a round is voided by one transaction.
	voiding: Mutex<()>,
	/// One pass at a time over the rounds built and not yet broadcast, so a
	/// round one pass hands to the node is never dropped by another.
	going_out: Mutex<()>,
	/// What [`Rounds::fundable_now`] last answered, and when.
	fundable_seen: Mutex<Option<(std::time::Instant, BTreeMap<AssetId, u64>)>>,
	/// Each participation's holder, once read ([`Rounds::holder_of`]).
	holders: Mutex<std::collections::HashMap<[u8; 32], Option<[u8; 32]>>>,
}

/// A batch a round builds: its asset, its leaves (each a participation's
/// index among the round's and an output's index in it), and whether it is
/// a holder's own, built as a tree whatever the batch kind rule says.
#[derive(Debug, Clone)]
pub struct BatchPlan {
	pub asset: AssetId,
	pub leaves: Vec<(usize, usize)>,
	pub own: bool,
}

/// The batches of a round, in order: per asset in asset order, a batch of
/// its own for each holder named in `holders` (the largest by value first,
/// at most `own_max` across the round), then one for every other leaf of the
/// asset, a holder's leaves side by side so that a lowest node's owners tend
/// to move together. `leaves` lists each leaf wanted as (asset, holder or
/// none, value, participation index, output index), in the round's order.
pub fn plan_batches(leaves: &[(AssetId, Option<[u8; 32]>, u64, usize, usize)], own_max: usize) -> Vec<BatchPlan> {
	let mut by_holder: BTreeMap<[u8; 32], (u64, usize)> = BTreeMap::new();
	for (k, (_, h, v, _, _)) in leaves.iter().enumerate() {
		if let Some(h) = h {
			let e = by_holder.entry(*h).or_insert((0, k));
			e.0 = e.0.saturating_add(*v);
		}
	}
	// The holders that get a batch of their own: the most value first, then
	// the first seen.
	let mut ranked: Vec<([u8; 32], (u64, usize))> = by_holder.into_iter().collect();
	ranked.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.1 .1.cmp(&b.1 .1)));
	let own: BTreeSet<[u8; 32]> = ranked.iter().take(own_max).map(|(h, _)| *h).collect();
	let mut out = vec![];
	let assets: BTreeSet<AssetId> = leaves.iter().map(|l| l.0).collect();
	for asset in assets {
		let of_asset: Vec<&(AssetId, Option<[u8; 32]>, u64, usize, usize)> = leaves.iter().filter(|l| l.0 == asset).collect();
		let mut seen: Vec<[u8; 32]> = vec![];
		for l in &of_asset {
			if let Some(h) = l.1.filter(|h| own.contains(h)) {
				if !seen.contains(&h) {
					seen.push(h);
				}
			}
		}
		for h in &seen {
			out.push(BatchPlan { asset, own: true,
				leaves: of_asset.iter().filter(|l| l.1 == Some(*h)).map(|l| (l.3, l.4)).collect() });
		}
		// The rest, a holder's leaves side by side in the order its first
		// leaf came.
		let rest: Vec<&&(AssetId, Option<[u8; 32]>, u64, usize, usize)> = of_asset.iter().filter(|l| !l.1.is_some_and(|h| own.contains(&h))).collect();
		let mut order: Vec<Option<[u8; 32]>> = vec![];
		for l in &rest {
			let key = l.1.or(Some(participation_key(l.3)));
			if !order.contains(&key) {
				order.push(key);
			}
		}
		let mut shared = vec![];
		for key in order {
			shared.extend(rest.iter().filter(|l| l.1.or(Some(participation_key(l.3))) == key).map(|l| (l.3, l.4)));
		}
		if !shared.is_empty() {
			out.push(BatchPlan { asset, leaves: shared, own: false });
		}
	}
	out
}

/// A stand-in holder for the leaves of a participation whose holder is not
/// known, which keeps them side by side and apart from every other's.
fn participation_key(k: usize) -> [u8; 32] {
	let mut b = [0xffu8; 32];
	b[..8].copy_from_slice(&(k as u64).to_le_bytes());
	b
}

/// How long [`Rounds::fundable_now`] serves what it last read.
pub const FUNDABLE_FOR: Duration = Duration::from_secs(10);

/// How the orders of a fill round not yet broadcast stand at the node, each
/// checked again ([`Rounds::orders_now`]).
enum OrdersNow {
	/// Every one rests, unspent and final, its maker unable to refund it
	/// within the margin.
	Rest,
	/// One is out of finality after a rollback: the round waits.
	Wait(String),
	/// These takes' orders can no longer be filled (spent by another
	/// transaction, or refundable too soon), and why.
	Taken(Vec<([u8; 32], String)>),
}

/// The size of the operator's issuance of a round's connector asset, with
/// the connector's own value as its fee: what the connector output holds the
/// fee for.
pub fn issuance_vsize(operator: elements::secp256k1_zkp::XOnlyPublicKey, asset: AssetId) -> u64 {
	let c = ConnectorPolicy { operator };
	c.issuance(OutPoint::default(), (asset, 1_000_000), c.script_pubkey(), &[], &FeeSource::Reserve)
		.map(|ks| ks.finish(vec![vec![0; 64]]).tx.vsize() as u64)
		.unwrap_or(400)
}

impl Rounds {
	pub fn new(store: Store, finality: Arc<FinalityService>, params: Arc<Params>, wallet: Arc<Wallet>, nursery: Arc<Nursery>,
		signer: SignerClient, config: RoundConfig) -> Arc<Rounds>
	{
		Arc::new(Rounds { store, finality, params, wallet, nursery, signer, config, running: Mutex::new(()), voiding: Mutex::new(()),
			going_out: Mutex::new(()), fundable_seen: Mutex::new(None), holders: Mutex::new(Default::default()) })
	}

	/// The finality service this operator follows the chain with.
	pub fn finality(&self) -> &Arc<FinalityService> {
		&self.finality
	}

	/// The rounds broadcast and not yet final, oldest first, each with where
	/// the finality service has it: what an operator reads to see whether
	/// finality keeps up.
	/// What the operator's wallet holds of each asset, final or not: every unspent coin in a
	/// block of the active chain. A round's change is held from the block it is in; `fundable`
	/// counts it only once it is final.
	pub async fn holdings(&self) -> Result<BTreeMap<AssetId, u64>, RoundError> {
		self.wallet.holdings().await.map_err(|e| RoundError::Chain(e.to_string()))
	}

	pub async fn waiting(&self) -> Result<Vec<(Txid, crate::chain::Finality)>, RoundError> {
		let mut out = vec![];
		for r in self.store.rounds_in(RoundState::Broadcast).await? {
			let txid = Txid::from_byte_array(r.txid);
			out.push((txid, self.finality.status(&txid).await.map_err(|e| RoundError::Chain(e.to_string()))?));
		}
		Ok(out)
	}

	/// What a round can pay now of each asset the operator serves, as a
	/// round's own check counts it ([`Self::fundable`]): what the wallet can
	/// spend of the asset, or, for an issuer-operated asset, what its mint
	/// limiter allows (0 while it allows none). A round that would pay more
	/// of an asset waits until it can; what other participations already
	/// wait for is not taken off. Read again at most every [`FUNDABLE_FOR`].
	pub async fn fundable_now(&self) -> Result<BTreeMap<AssetId, u64>, RoundError> {
		let mut seen = self.fundable_seen.lock().await;
		if let Some((at, m)) = seen.as_ref() {
			if at.elapsed() < FUNDABLE_FOR {
				return Ok(m.clone());
			}
		}
		let balance = self.wallet.balance().await?;
		let mut out = BTreeMap::new();
		for (asset, _) in self.params.assets.all() {
			let v = match self.mint_room(asset).await? {
				Some(Ok(m)) => m.room,
				Some(Err(_)) => 0,
				None => balance.get(&asset).copied().unwrap_or(0),
			};
			out.insert(asset, v);
		}
		*seen = Some((std::time::Instant::now(), out.clone()));
		Ok(out)
	}

	/// What the operator minted and burned of the issuer-operated `asset`,
	/// and what is live in its batches ([`crate::issuer::supply`]); `None`
	/// for an asset not served issuer-operated.
	pub async fn issuer_supply(&self, asset: AssetId) -> Result<Option<crate::api::IssuerSupply>, RoundError> {
		let Some(i) = self.params.assets.get(&asset).and_then(|a| a.issuer) else { return Ok(None) };
		crate::issuer::supply(&self.store, &self.finality, asset, &i).await.map(Some).map_err(|e| RoundError::Chain(e.to_string()))
	}

	/// Where `asset`'s mint limiter stands, and what it allows a round to
	/// mint now, when the asset is served issuer-operated: `None` for an
	/// asset the operator funds from its own coins; `Some(Err(why))` when it
	/// allows no mint now.
	async fn mint_room(&self, asset: AssetId) -> Result<Option<Result<crate::issuer::MintRoom, String>>, RoundError> {
		let Some(issuer) = self.params.assets.get(&asset).and_then(|a| a.issuer) else { return Ok(None) };
		let at = crate::issuer::limiter_now(&self.store, &self.finality, asset, &issuer).await
			.map_err(|e| RoundError::Chain(e.to_string()))?;
		Ok(Some(crate::issuer::MintRoom::of(&at, &issuer.limiter)))
	}

	pub fn config(&self) -> &RoundConfig {
		&self.config
	}

	/// The kind of batch the runner builds `specs` of `asset` as: an
	/// accumulator batch when the operator expects few enough of them to
	/// leave on their own ([`BatchKind::choose`]); a tree for an
	/// issuer-operated asset, whose batches the mint's signer rebuilds as
	/// trees.
	/// The holder of participation `row` when it moves its coins soon after
	/// it gets them: a coin it gives up rests on a batch made within
	/// [`RoundConfig::holder_window`] of now. The holder is the mailbox key
	/// its new leaves are bound to (a wallet binds every leaf it asks for to
	/// one key), else the participation itself. `None` for any other: its
	/// leaves go to the asset's shared batch. Read once a participation.
	async fn holder_of(&self, row: &ParticipationRow, now: MedianTime) -> Result<Option<[u8; 32]>, RoundError> {
		if self.config.holder_batches == 0 {
			return Ok(None);
		}
		if let Some(h) = self.holders.lock().await.get(&row.id) {
			return Ok(*h);
		}
		// A coin whose first expiry lies this late came from a batch made
		// within the window.
		let soon = (now.to_consensus_u32() + self.config.lifetime).saturating_sub(self.config.holder_window);
		let mut young = false;
		for i in &row.inputs {
			let Some(l) = self.store.leaf(&i.leaf_id).await? else { continue };
			let Ok(record) = CoinRecord::from_bytes(&l.record) else { continue };
			if crate::cosign::first_expiry(&record).is_some_and(|e| e >= soon) {
				young = true;
				break;
			}
		}
		let mut holder = None;
		if young {
			holder = Some(row.id);
			for o in &row.outputs {
				if let WantedKind::Leaf { owner_key, .. } = &o.kind {
					if let Some(m) = self.store.mailbox_of(owner_key).await? {
						holder = Some(m);
						break;
					}
				}
			}
		}
		let mut seen = self.holders.lock().await;
		if seen.len() > 100_000 {
			seen.clear();
		}
		seen.insert(row.id, holder);
		Ok(holder)
	}

	/// The batches a round of `rows` builds ([`plan_batches`]): no batch of
	/// its own in an asset the operator mints, whose batches are burn-only,
	/// and no more than the wallet's coins can issue tokens for besides the
	/// shared batches.
	async fn batches_of(&self, rows: &[&ParticipationRow], now: MedianTime, reserved: usize) -> Result<Vec<BatchPlan>, RoundError> {
		let mut leaves = vec![];
		for (k, row) in rows.iter().enumerate() {
			let mut holder = None;
			for (j, o) in row.outputs.iter().enumerate() {
				if let WantedKind::Leaf { .. } = &o.kind {
					let asset = AssetId::from_byte_array(o.asset);
					if holder.is_none() && self.params.assets.get(&asset).is_some_and(|a| a.issuer.is_none()) {
						holder = Some(self.holder_of(row, now).await?);
					}
					leaves.push((asset, holder.flatten(), o.value, k, j));
				}
			}
		}
		let assets: BTreeSet<AssetId> = leaves.iter().map(|l| l.0).collect();
		let room = self.config.holder_batches.min(self.wallet.issuing_coins(None).await?.saturating_sub(assets.len() + reserved));
		Ok(plan_batches(&leaves, room))
	}

	fn kind_of(&self, asset: &AssetId, specs: &[LeafSpec]) -> BatchKind {
		let issuer = self.params.assets.get(asset).is_some_and(|a| a.issuer.is_some());
		BatchKind::choose(specs, self.config.radix, self.config.accumulator_exit_rate_ppm, issuer)
	}

	async fn now(&self) -> Result<MedianTime, RoundError> {
		let tip = self.store.tip_block().await?.ok_or(RoundError::NotSynced)?;
		MedianTime::from_consensus(tip.median_time as u32).map_err(|e| RoundError::Internal(e.to_string()))
	}

	async fn floor(&self, asset: AssetId) -> Result<Option<u64>, RoundError> {
		fees::floor_per_kvb(&self.finality, asset).await.map_err(|e| RoundError::Chain(e.to_string()))
	}

	/// Whether every coin `p` gives up still passes the check it passed when
	/// it was accepted, under the round's horizon. A participation with a
	/// coin past that horizon can never run: it is voided, its coins given
	/// back. So is one that wants a leaf, or gives up a coin, outside the
	/// exit-delay bounds the operator takes now (they changed at a restart
	/// since it was accepted): no round of this operator makes that leaf or
	/// takes that coin.
	async fn still_good(&self, p: &ParticipationRow, now: MedianTime) -> Result<bool, RoundError> {
		// A coin of a supervised asset whose holder was frozen since the
		// participation was taken: nothing has moved, as no forfeit was
		// taken, and none is (`crate::supervision`). Its coins are given back.
		let given: Vec<LeafId> = p.inputs.iter().map(|i| LeafId(i.leaf_id)).collect();
		match crate::supervision::gate(&self.store, &self.finality, &self.params, &given).await {
			Ok(()) => {},
			Err(e @ (crate::supervision::SupervisionError::Frozen { .. } | crate::supervision::SupervisionError::NotLanding { .. })) => {
				let why = e.to_string();
				let voided = self.store.void_participation(&p.id, &why).await?;
				log::warn!("participation {} is voided (voided: {}): {}", crate::signer::hex(&p.id), voided, why);
				return Ok(false);
			},
			Err(crate::supervision::SupervisionError::Store(e)) => return Err(e.into()),
			Err(e) => {
				log::warn!("participation {} waits: {}", crate::signer::hex(&p.id), e);
				self.store.set_waiting(&p.id, Some(&format!("the freeze of its coins could not be read: {}", e))).await?;
				return Ok(false);
			},
		}
		if p.attempt > 0 {
			if let Some(why) = self.barred(p).await? {
				let voided = self.store.void_participation(&p.id, &why).await?;
				log::warn!("participation {} is never taken again (voided: {}): {}", crate::signer::hex(&p.id), voided, why);
				return Ok(false);
			}
		}
		let (min, max) = (self.params.min_exit_delay.units(), self.params.max_exit_delay.units());
		for o in &p.outputs {
			if let WantedKind::Leaf { exit_delay_units, .. } = &o.kind {
				if !(min..=max).contains(exit_delay_units) {
					let why = format!("it wants a leaf with an exit delay of {} units, and the operator takes {} to {} now",
						exit_delay_units, min, max);
					let voided = self.store.void_participation(&p.id, &why).await?;
					log::warn!("participation {} can never run: {} (voided: {})", crate::signer::hex(&p.id), why, voided);
					return Ok(false);
				}
			}
		}
		// A step of an offline-refresh plan gives up a coin whose holder is
		// away, a leaf a step made among them, whose record waits for that
		// holder's authorisations: it is taken while it is given up to the
		// step and nothing of it is on the chain, late as well, its batch
		// held unreleased meanwhile (`plans::holds_batch`).
		if self.store.plan_step_of(&p.id).await?.is_some() {
			if let Some(why) = crate::plans::step_coin_waits(&self.store, p).await? {
				log::warn!("participation {} (a plan's step) waits: {}", crate::signer::hex(&p.id), why);
				self.store.set_waiting(&p.id, Some(&why)).await?;
				return Ok(false);
			}
			return Ok(true);
		}
		let policy = self.params.round_policy(now);
		for i in &p.inputs {
			match coins::check(&self.store, &policy, &LeafId(i.leaf_id), &p.id, coins::BoardDates::Within(Params::PARTICIPATION_HORIZON)).await {
				Ok(_) => {},
				Err(coins::CoinError::Store(e)) => return Err(e.into()),
				Err(coins::CoinError::InvalidCoin {
					error: arca_covenant::TransferError::Record(arca_covenant::RecordError::ExpiryTooSoon { .. }), ..
				}) | Err(coins::CoinError::PastBoardDate { .. }) => {
					let why = format!("coin {} is past its exit deadline, the last time a round takes it", LeafId(i.leaf_id));
					let voided = self.store.void_participation(&p.id, &why).await?;
					log::warn!("participation {} can never run: {} (voided: {})", crate::signer::hex(&p.id), why, voided);
					return Ok(false);
				},
				Err(coins::CoinError::InvalidCoin {
					error: e @ (arca_covenant::TransferError::Record(arca_covenant::RecordError::ExitDelay { .. })
						| arca_covenant::TransferError::LineageExitDelay { .. }), ..
				}) => {
					let why = format!("coin {} lies outside the exit-delay bounds the operator takes now ({})", LeafId(i.leaf_id), e);
					let voided = self.store.void_participation(&p.id, &why).await?;
					log::warn!("participation {} can never run: {} (voided: {})", crate::signer::hex(&p.id), why, voided);
					return Ok(false);
				},
				Err(e) => {
					log::warn!("participation {} waits: {}", crate::signer::hex(&p.id), e);
					self.store.set_waiting(&p.id, Some(&format!("coin {} does not pass the check a round makes now: {}", LeafId(i.leaf_id), e)))
						.await?;
					return Ok(false);
				},
			}
		}
		Ok(true)
	}

	/// The one asset `row` carries: that of every coin it gives up, every
	/// output it wants and every fee it pays. `None` for a participation that
	/// carries several, which only a server from before a round carried one
	/// asset took.
	pub fn asset_of(row: &ParticipationRow) -> Option<AssetId> {
		let mut all = row.inputs.iter().map(|i| i.asset).chain(row.outputs.iter().map(|o| o.asset)).chain(row.fees.iter().map(|f| f.0));
		let first = all.next()?;
		all.all(|a| a == first).then(|| AssetId::from_byte_array(first))
	}

	/// The assets with a pending participation, in the order the operator
	/// serves them. A pending participation that carries several assets
	/// (taken by a server from before a round carried one asset) can never
	/// run and is voided, its coins given back; one in an asset the operator
	/// no longer serves waits, saying why.
	async fn assets_waiting(&self) -> Result<Vec<AssetId>, RoundError> {
		let served = self.params.assets.ids();
		let mut waiting: BTreeSet<AssetId> = BTreeSet::new();
		for id in self.store.participations_in(ParticipationState::Pending).await? {
			let row = match self.store.participation(&id).await? {
				Some(r) => r,
				None => continue,
			};
			// A take carries two assets by its nature, and runs in a round
			// of its own.
			if row.fill.is_some() {
				continue;
			}
			match Self::asset_of(&row) {
				Some(a) if served.contains(&a) => {
					waiting.insert(a);
				},
				Some(a) => {
					let why = format!("asset {} is not served by this operator now; it runs once it is", a);
					if row.waiting.as_deref() != Some(why.as_str()) {
						log::warn!("participation {} waits: {}", crate::signer::hex(&row.id), why);
						self.store.set_waiting(&row.id, Some(&why)).await?;
					}
				},
				None => {
					let why = "it carries several assets, and a round carries one: its coins are given back, to be refreshed one asset \
						at a time";
					let voided = self.store.void_participation(&row.id, why).await?;
					log::warn!("participation {} can never run: {} (voided: {})", crate::signer::hex(&row.id), why, voided);
				},
			}
		}
		Ok(served.into_iter().filter(|a| waiting.contains(a)).collect())
	}

	/// Builds a round for each asset whose participations wait, each its
	/// own: see the [module documentation](self). One asset's round that
	/// cannot be built (its pool short, no fee asset accepted, the node
	/// refusing it) holds back no other's; its error is logged and returned
	/// beside the rounds built.
	pub async fn run_rounds(&self) -> Result<(Vec<Built>, Vec<(AssetId, RoundError)>), RoundError> {
		let mut built = vec![];
		let mut failed = vec![];
		self.plans_due().await?;
		for asset in self.assets_waiting().await? {
			match self.run_round_of(asset).await {
				Ok(Some(b)) => built.push(b),
				Ok(None) => {},
				Err(e) => {
					log::warn!("rounds: the round of asset {}: {}", asset, e);
					failed.push((asset, e));
				},
			}
		}
		for asset in self.takes_waiting().await? {
			match self.run_fill_round_of(asset).await {
				Ok(Some(b)) => built.push(b),
				Ok(None) => {},
				Err(e) => {
					log::warn!("rounds: the fill round of asset {}: {}", asset, e);
					failed.push((asset, e));
				},
			}
		}
		Ok((built, failed))
	}

	/// The assets with a pending take, by the asset of the leaf it wants (the
	/// asset its order sells), in the order the operator serves them. A take
	/// of an asset the operator no longer serves waits, saying why.
	async fn takes_waiting(&self) -> Result<Vec<AssetId>, RoundError> {
		let served = self.params.assets.ids();
		let mut waiting: BTreeSet<AssetId> = BTreeSet::new();
		for id in self.store.participations_in(ParticipationState::Pending).await? {
			let Some(row) = self.store.participation(&id).await? else { continue };
			if row.fill.is_none() {
				continue;
			}
			let Some(a) = row.outputs.first().map(|o| AssetId::from_byte_array(o.asset)) else { continue };
			if served.contains(&a) {
				waiting.insert(a);
			} else {
				let why = format!("asset {} is not served by this operator now; the take runs once it is", a);
				if row.waiting.as_deref() != Some(why.as_str()) {
					self.store.set_waiting(&row.id, Some(&why)).await?;
				}
			}
		}
		Ok(served.into_iter().filter(|a| waiting.contains(a)).collect())
	}

	/// Why the take `row`'s order cannot be filled by a round now, if it
	/// cannot: `Some((true, why))` when it never can (the order spent, its
	/// refund too near), and the take is voided; `Some((false, why))` when
	/// it waits (the order's transaction out of finality after a rollback).
	async fn order_unfit(&self, row: &ParticipationRow) -> Result<Option<(bool, String)>, RoundError> {
		let Some(f) = &row.fill else { return Ok(None) };
		let terms = f.order().map_err(RoundError::Store)?;
		let op = f.outpoint();
		match order_on_chain(&self.finality, &op, &terms, f.locked).await {
			Ok(()) => {},
			Err(ParticipationError::OrderSpent(m)) => return Ok(Some((true, format!("{}; a round fills an order only while it rests \
				unspent, so the take is void", m)))),
			Err(ParticipationError::OrderNotFinal(m)) => return Ok(Some((false, m))),
			Err(ParticipationError::Order(m)) => return Ok(Some((true, m))),
			Err(e) => return Err(RoundError::Chain(e.to_string())),
		}
		let tip = self.store.tip_block().await?.ok_or(RoundError::NotSynced)?;
		if let Some(why) = refund_too_soon(&terms, &self.params, tip.height, tip.median_time as u32) {
			return Ok(Some((true, format!("order {}: {}; the take is void", outpoint_text(&op), why))));
		}
		Ok(None)
	}

	/// Builds the next fill round of `asset`: a round of its own that fills
	/// the on-chain orders pending takes ask for, every one selling `asset`,
	/// and pays each take its leaf in a batch of `asset` (see the [module
	/// documentation](self)). Each take's order is checked again first: one
	/// spent by another transaction, or whose maker can refund it too soon,
	/// is voided, saying why, and the round is built without it; so is one
	/// the node finds spent when the round is put to it. Returns `None` when
	/// nothing of it waits.
	pub async fn run_fill_round_of(&self, asset: AssetId) -> Result<Option<Built>, RoundError> {
		let _one = self.running.lock().await;
		let now = self.now().await?;
		if !self.params.assets.contains(&asset) {
			return Ok(None);
		}
		let mut chosen: Vec<ParticipationRow> = vec![];
		for id in self.store.participations_in(ParticipationState::Pending).await? {
			let Some(row) = self.store.participation(&id).await? else { continue };
			if row.fill.is_none() || row.outputs.first().map(|o| AssetId::from_byte_array(o.asset)) != Some(asset) {
				continue;
			}
			if row.not_before.is_some_and(|t| t > now.to_consensus_u32()) {
				continue;
			}
			if chosen.len() >= MAX_TAKES.min(self.config.max_batch_leaves) {
				continue;
			}
			// A new order needs an input of its own; a take of an order the
			// round fills already shares that order's.
			let orders: BTreeSet<OutPoint> = chosen.iter().filter_map(|c| c.fill.as_ref().map(|f| f.outpoint())).collect();
			if row.fill.as_ref().is_some_and(|f| !orders.contains(&f.outpoint())) && orders.len() >= MAX_FILLS {
				continue;
			}
			// Each buyer's own fill is at least the order's minimum lot: the
			// FILL leaf judges the round's fill of an order, every take of it
			// together, so a share below the lot is the round's to refuse.
			if let Some(why) = Self::below_min_lot(&row)? {
				let voided = self.store.void_participation(&row.id, &why).await?;
				log::warn!("take {} cannot run (voided: {}): {}", crate::signer::hex(&row.id), voided, why);
				continue;
			}
			// Takes of one order that run together all share it, and fill
			// no more of it than its FILL leaf takes; one that does not fit
			// beside those chosen before it waits for a later round.
			if let Some(why) = Self::does_not_fit(&chosen, &row)? {
				if row.waiting.as_deref() != Some(why.as_str()) {
					self.store.set_waiting(&row.id, Some(&why)).await?;
				}
				log::warn!("take {} waits: {}", crate::signer::hex(&row.id), why);
				continue;
			}
			if !self.still_good(&row, now).await? {
				continue;
			}
			let mut taken = false;
			for o in &row.outputs {
				if let WantedKind::Leaf { owner_key, .. } = &o.kind {
					taken |= self.store.key_owns_leaf(owner_key).await?;
				}
			}
			if taken {
				let why = self.paid_on(&row.id).await?.unwrap_or_else(|| "a key it wants a leaf under owns a leaf already".into());
				let voided = self.store.void_participation(&row.id, &why).await?;
				log::warn!("take {} cannot run: a key it wants owns a leaf (voided: {})", crate::signer::hex(&row.id), voided);
				continue;
			}
			match self.order_unfit(&row).await? {
				None => chosen.push(row),
				Some((true, why)) => {
					let voided = self.store.void_participation(&row.id, &why).await?;
					log::warn!("take {} drops out of the fill round (voided: {}): {}", crate::signer::hex(&row.id), voided, why);
				},
				Some((false, why)) => {
					log::warn!("take {} waits: {}", crate::signer::hex(&row.id), why);
					self.store.set_waiting(&row.id, Some(&why)).await?;
				},
			}
		}
		let chosen = self.within_cap(chosen, now).await?;
		let chosen = self.fundable_fills(chosen, now).await?;
		let (mut chosen, ties) = self.tie_reruns(chosen).await?;
		loop {
			if chosen.is_empty() {
				return Ok(None);
			}
			let fills = Self::plan_fills(&chosen)?;
			match self.build_from(&chosen, &fills, now, &ties).await {
				Err(RoundError::Wallet(WalletError::Insufficient { asset: short, need, have })) => {
					let row = chosen.pop().expect("not empty");
					self.wait(&row, short, need, have).await?;
				},
				// The node refused the round: an order spent since it was
				// checked drops out, and the round is built without it.
				Err(RoundError::Refused(reason)) => {
					let mut dropped = 0;
					let mut kept = vec![];
					for row in chosen {
						match self.order_unfit(&row).await? {
							Some((true, why)) => {
								self.store.void_participation(&row.id, &why).await?;
								log::warn!("take {} drops out of the fill round the node refused ({}): {}", crate::signer::hex(&row.id),
									reason, why);
								dropped += 1;
							},
							Some((false, why)) => {
								self.store.set_waiting(&row.id, Some(&why)).await?;
								dropped += 1;
							},
							None => kept.push(row),
						}
					}
					if dropped == 0 {
						return Err(RoundError::Refused(reason));
					}
					chosen = kept;
				},
				other => return other,
			}
		}
	}

	/// Why the take `row`'s own fill is one no round runs, if it is: below
	/// its order's minimum lot. A take is refused that at its submission;
	/// the round builder holds the same rule, since the order's FILL leaf
	/// reads only what a round fills of the order, every take of it together.
	fn below_min_lot(row: &ParticipationRow) -> Result<Option<String>, RoundError> {
		let Some(f) = &row.fill else { return Ok(None) };
		let terms = f.order()?;
		Ok((f.filled < terms.min_lot).then(|| format!("order {}: the take fills {} atoms, below the order's min_lot of {}: the covenant \
			judges a round's whole fill of an order, so the operator holds each buyer's share to the minimum lot, and the take is void",
			outpoint_text(&f.outpoint()), f.filled, terms.min_lot)))
	}

	/// Why the take `row` cannot run in the round beside the takes of
	/// `chosen`, if it cannot: another take of its order is chosen and one of
	/// the two takes it alone, or they read different amounts resting there,
	/// or all of them together would fill more of the order than its FILL
	/// leaf takes.
	fn does_not_fit(chosen: &[ParticipationRow], row: &ParticipationRow) -> Result<Option<String>, RoundError> {
		let Some(f) = &row.fill else { return Ok(None) };
		let op = f.outpoint();
		let same: Vec<&FillRow> = chosen.iter().filter_map(|c| c.fill.as_ref()).filter(|g| g.outpoint() == op).collect();
		if same.is_empty() {
			return Ok(None);
		}
		if !f.shared || same.iter().any(|g| !g.shared) {
			return Ok(Some(format!("order {} is filled in this round for another take, and one of the two takes it alone: it runs in a \
				later round", outpoint_text(&op))));
		}
		if same.iter().any(|g| g.locked != f.locked) {
			return Ok(Some(format!("order {}: the takes of it read different amounts resting there", outpoint_text(&op))));
		}
		let total: u128 = same.iter().map(|g| g.filled as u128).sum::<u128>() + f.filled as u128;
		let terms = f.order()?;
		match u64::try_from(total).ok().map(|t| terms.plan(f.locked, t)) {
			Some(Ok(_)) => Ok(None),
			Some(Err(e)) => Ok(Some(format!("order {}: with the takes before it the round would fill {} of it: {}; it runs in a later round",
				outpoint_text(&op), total, e))),
			None => Ok(Some(format!("order {}: the takes of it fill more than it holds", outpoint_text(&op)))),
		}
	}

	/// The fills of `chosen`, a fill round's takes, in order: each order
	/// once, at the input of its first take, its fill the sum of every
	/// chosen take of it; the order at input `k` is the `k`-th order met.
	/// Each take's own price is its fill's, rounded up; the order's credit is
	/// the price of the sum, rounded up once, so the operator pays the maker
	/// at most what the takes pay it.
	fn plan_fills(chosen: &[ParticipationRow]) -> Result<Vec<PlannedFill>, RoundError> {
		let mut fills: Vec<(OutPoint, Vec<usize>)> = vec![];
		for (j, row) in chosen.iter().enumerate() {
			let f = row.fill.as_ref().ok_or_else(|| RoundError::Internal("a fill round runs takes only".into()))?;
			let terms = f.order()?;
			let own = terms.plan(f.locked, f.filled).map_err(|e| RoundError::Internal(format!("take {}: {}", crate::signer::hex(&row.id), e)))?;
			if own.credit.value != f.price {
				return Err(RoundError::Internal(format!("take {}: its order prices the fill at {}, the take at {}", crate::signer::hex(&row.id),
					own.credit.value, f.price)));
			}
			match fills.iter_mut().find(|(op, _)| *op == f.outpoint()) {
				Some((_, takes)) => takes.push(j),
				None => fills.push((f.outpoint(), vec![j])),
			}
		}
		fills.into_iter().map(|(order, takes)| {
			let first = chosen[takes[0]].fill.as_ref().expect("a take");
			let terms = first.order()?;
			let mut total: u64 = 0;
			for j in &takes {
				let f = chosen[*j].fill.as_ref().expect("a take");
				if f.locked != first.locked || f.order()? != terms {
					return Err(RoundError::Internal(format!("order {}: its takes read it differently", outpoint_text(&order))));
				}
				total = total.checked_add(f.filled).ok_or_else(|| RoundError::Internal("a fill overflows".into()))?;
			}
			let plan = terms.plan(first.locked, total)
				.map_err(|e| RoundError::Internal(format!("order {}, {} take(s): {}", outpoint_text(&order), takes.len(), e)))?;
			Ok(PlannedFill { participations: takes, order, terms, locked: first.locked, plan })
		}).collect()
	}

	/// What a fill round with `rows` pays of each asset from the operator's
	/// pool: the batch less what the orders fill (their own value pays the
	/// leaves), and in each asset an order is paid in, its credit and the
	/// output a full fill puts at its `2k+1`.
	async fn fill_pays(&self, rows: &[&ParticipationRow], now: MedianTime) -> Result<BTreeMap<AssetId, u64>, RoundError> {
		let mut pays = self.pays(rows, now).await?;
		let mut orders: BTreeMap<OutPoint, (FillOrder, u64, u64)> = BTreeMap::new();
		for row in rows {
			let Some(f) = &row.fill else { continue };
			let e = orders.entry(f.outpoint()).or_insert((f.order()?, f.locked, 0));
			e.2 = e.2.saturating_add(f.filled);
		}
		for (terms, locked, filled) in orders.values() {
			if let Some(a) = pays.get_mut(&terms.asset_a) {
				*a = a.saturating_sub(*filled);
			}
			let credit = terms.price(*filled).unwrap_or(u64::MAX);
			let gap = if filled == locked { gap_value(terms.asset_b, terms.asset_b) } else { 0 };
			*pays.entry(terms.asset_b).or_default() += credit.saturating_add(gap);
		}
		Ok(pays)
	}

	/// The takes of `chosen` the wallet can fund now, in order, as
	/// [`Self::fundable`] takes participations.
	async fn fundable_fills(&self, chosen: Vec<ParticipationRow>, now: MedianTime) -> Result<Vec<ParticipationRow>, RoundError> {
		let balance = self.wallet.balance().await?;
		let have = |a: &AssetId| balance.get(a).copied().unwrap_or(0);
		let mut taken: Vec<ParticipationRow> = vec![];
		for row in chosen {
			let mut with: Vec<&ParticipationRow> = taken.iter().collect();
			with.push(&row);
			let pays = self.fill_pays(&with, now).await?;
			match pays.iter().find(|(a, v)| **v > have(a)) {
				Some((a, v)) => self.wait(&row, *a, *v, have(a)).await?,
				None => taken.push(row),
			}
		}
		Ok(taken)
	}

	/// The steps of offline-refresh plans whose time has come join the
	/// participations waiting, each its own participation
	/// ([`crate::plans::apply`]).
	async fn plans_due(&self) -> Result<usize, RoundError> {
		let now = self.now().await?;
		Ok(crate::plans::apply(&self.store, &self.params, now).await?)
	}

	/// Builds the next round: that of the first asset, in the order the
	/// operator serves them, whose participations wait and can run. Returns
	/// `None` when nothing waits.
	pub async fn run_round(&self) -> Result<Option<Built>, RoundError> {
		self.plans_due().await?;
		for asset in self.assets_waiting().await? {
			if let Some(b) = self.run_round_of(asset).await? {
				return Ok(Some(b));
			}
		}
		Ok(None)
	}

	/// Builds the next round of `asset` from its pending participations, if
	/// any: see the [module documentation](self). The round carries `asset`
	/// alone. Returns `None` when nothing of it waits.
	pub async fn run_round_of(&self, asset: AssetId) -> Result<Option<Built>, RoundError> {
		let _one = self.running.lock().await;
		let now = self.now().await?;
		if !self.params.assets.contains(&asset) {
			return Ok(None);
		}

		// The participations of the asset, whole, within the batch size.
		let mut chosen: Vec<ParticipationRow> = vec![];
		let mut count = 0usize;
		for id in self.store.participations_in(ParticipationState::Pending).await? {
			let row = match self.store.participation(&id).await? {
				Some(r) => r,
				None => continue,
			};
			if row.fill.is_some() || Self::asset_of(&row) != Some(asset) {
				continue;
			}
			if row.not_before.is_some_and(|t| t > now.to_consensus_u32()) {
				continue;
			}
			let adds = row.outputs.iter().filter(|o| matches!(o.kind, WantedKind::Leaf { .. })).count();
			if count + adds > self.config.max_batch_leaves {
				continue;
			}
			if !self.still_good(&row, now).await? {
				continue;
			}
			// A key a leaf of it wants that has come to own a leaf meanwhile
			// (which the store refuses, short of a race) would make the
			// round's record fail: the participation cannot run.
			let mut taken = false;
			for o in &row.outputs {
				if let WantedKind::Leaf { owner_key, .. } = &o.kind {
					taken |= self.store.key_owns_leaf(owner_key).await?;
				}
			}
			if taken {
				let why = self.paid_on(&row.id).await?.unwrap_or_else(|| "a key it wants a leaf under owns a leaf already".into());
				let voided = self.store.void_participation(&row.id, &why).await?;
				log::warn!("participation {} cannot run: a key it wants owns a leaf (voided: {})", crate::signer::hex(&row.id), voided);
				continue;
			}
			count += adds;
			chosen.push(row);
		}
		// What the wallet can fund: a participation whose outputs do not fit
		// waits, saying why, and delays no other.
		let chosen = self.within_cap(chosen, now).await?;
		let chosen = self.fundable(chosen, now).await?;
		// A re-run spends a coin that keeps it apart from every lost round of
		// its participation's; one with no such coin is never taken.
		let (mut chosen, ties) = self.tie_reruns(chosen).await?;
		loop {
			if chosen.is_empty() {
				return Ok(None);
			}
			match self.build_from(&chosen, &[], now, &ties).await {
				// Short of an asset once the round's own fee and connector are
				// counted: the last participation wanting that asset waits.
				// The fee asset may be another than the round's: then every
				// participation of the round waits on it, the last first.
				Err(RoundError::Wallet(WalletError::Insufficient { asset: short, need, have })) => {
					let a = short.into_inner().to_byte_array();
					let i = chosen.iter().rposition(|r| r.outputs.iter().any(|o| o.asset == a)).unwrap_or(chosen.len() - 1);
					let row = chosen.remove(i);
					self.wait(&row, short, need, have).await?;
				},
				// The limiter allows no such mint now (it moved since the
				// participations were taken): they wait, saying why.
				Err(RoundError::MintWaits(why)) => {
					for row in &chosen {
						self.wait_for(row, &format!("a round of asset {} mints what it pays of it, and {}", asset, why)).await?;
					}
					return Ok(None);
				},
				other => return other,
			}
		}
	}

	/// The lost rounds participation `id` was in before: every one its
	/// re-run must be kept apart from.
	async fn lost_rounds(&self, id: &[u8; 32]) -> Result<BTreeSet<i64>, RoundError> {
		Ok(self.store.attempts(id).await?.into_iter().filter(|a| a.round_lost).map(|a| a.round_id).collect())
	}

	/// The coins of the operator's that keep a round apart from the lost
	/// round `l`: an input of it that is unspent, and, for an input another
	/// transaction took, every unspent coin of the operator's that
	/// transaction pays, or that a transaction of the operator's resting on
	/// one of those pays, and so on. None of them can exist while `l` is in
	/// the chain, so a round that spends one cannot stand beside it.
	async fn tie_coins(&self, l: &RoundRow) -> Result<TieCoins, RoundError> {
		let tx: Transaction = deserialize(&l.tx).map_err(|e| RoundError::Internal(e.to_string()))?;
		let mut frontier: Vec<(OutPoint, Option<Txid>)> = tx.input.iter().map(|i| (i.previous_output, None)).collect();
		let mut seen: HashSet<OutPoint> = HashSet::new();
		let mut out = TieCoins { now: vec![], later: false };
		for _ in 0..8 {
			let mut next = vec![];
			for (op, via) in frontier {
				if !seen.insert(op) {
					continue;
				}
				let Some(c) = self.store.wallet_coin_at(&op.txid.to_byte_array(), op.vout).await? else { continue };
				let by = c.spent_by.filter(|b| *b != l.txid).or(self.store.outpoint_spender(&op.txid.to_byte_array(), op.vout).await?
					.filter(|b| *b != l.txid));
				let unspent = self.finality.call(move |n| n.unspent(&op, true)).await.map_err(|e| RoundError::Chain(e.to_string()))?.is_some();
				if unspent && c.spent_by.is_none_or(|b| b == l.txid) {
					if c.spent_by.is_none() && self.wallet.spendable_now(&c).await? {
						out.now.push((c, via));
					} else {
						out.later = true;
					}
					continue;
				}
				let Some(by) = by else { continue };
				for o in self.store.wallet_coins_of_tx(&by).await? {
					next.push((OutPoint::new(Txid::from_byte_array(o.txid), o.vout), via.or(Some(Txid::from_byte_array(by)))));
				}
			}
			if next.is_empty() {
				break;
			}
			frontier = next;
		}
		Ok(out)
	}

	/// The participations of `chosen` with the coins that keep each re-run
	/// among them apart from every lost round of its participation's, one
	/// coin per lost round (one coin may serve several). A re-run whose lost
	/// round has no such coin is voided, saying why, or waits while one is
	/// unspent but not yet the wallet's to spend.
	async fn tie_reruns(&self, chosen: Vec<ParticipationRow>) -> Result<(Vec<ParticipationRow>, Vec<Tie>), RoundError> {
		let mut need: BTreeMap<i64, Vec<usize>> = BTreeMap::new();
		for (k, p) in chosen.iter().enumerate() {
			if p.attempt == 0 {
				continue;
			}
			for l in self.lost_rounds(&p.id).await? {
				need.entry(l).or_default().push(k);
			}
		}
		let mut ties: Vec<Tie> = vec![];
		let mut cut: BTreeMap<usize, Option<String>> = BTreeMap::new();
		for (l, users) in &need {
			let round = self.store.round(*l).await?.ok_or_else(|| RoundError::Internal(format!("round {} is not recorded", l)))?;
			let coins = self.tie_coins(&round).await?;
			let held = coins.now.iter().find(|(c, _)| ties.iter().any(|t| (t.coin.txid, t.coin.vout) == (c.txid, c.vout))).cloned();
			match held.or_else(|| coins.now.first().cloned()) {
				Some((coin, via)) => ties.push(Tie { replaces: *l, coin, via }),
				None => {
					let why = (!coins.later).then(|| no_tie(&Txid::from_byte_array(round.txid)));
					for u in users {
						cut.entry(*u).or_insert(why.clone());
					}
				},
			}
		}
		let mut out = vec![];
		for (k, p) in chosen.into_iter().enumerate() {
			match cut.get(&k) {
				None => out.push(p),
				Some(Some(why)) => {
					let voided = self.store.void_participation(&p.id, why).await?;
					log::warn!("participation {} is never taken again (voided: {}): {}", crate::signer::hex(&p.id), voided, why);
				},
				Some(None) => {
					self.store.set_waiting(&p.id, Some("a coin that keeps its re-run apart from the round it was in is not yet the \
						operator's to spend; it runs once it is")).await?;
				},
			}
		}
		ties.retain(|t| need[&t.replaces].iter().any(|u| !cut.contains_key(u)));
		Ok((out, ties))
	}

	/// Records why `row` waits: a round with it would pay `need` of `asset`,
	/// and the wallet can spend `have`.
	async fn wait(&self, row: &ParticipationRow, asset: AssetId, need: u64, have: u64) -> Result<(), RoundError> {
		let why = format!("This refresh waits for a later round: the operator has too little of this asset free to refresh it with \
			right now. Nothing is lost meanwhile. (The operator's wallet cannot fund it in a round now: the round would pay {} of asset \
			{}, and the wallet can spend {} of it; it runs once the wallet can.)", need, asset, have);
		if row.waiting.as_deref() != Some(why.as_str()) {
			log::warn!("participation {} waits: {}", crate::signer::hex(&row.id), why);
		}
		self.store.set_waiting(&row.id, Some(&why)).await?;
		Ok(())
	}

	/// What a round with `rows` pays of each asset on their behalf: each
	/// batch output, its leaves and its reserves as the builder makes them,
	/// and each offboard output.
	async fn pays(&self, rows: &[&ParticipationRow], now: MedianTime) -> Result<BTreeMap<AssetId, u64>, RoundError> {
		let mut pays: BTreeMap<AssetId, u64> = BTreeMap::new();
		for row in rows {
			for o in &row.outputs {
				if let WantedKind::Offboard { margin, .. } = &o.kind {
					*pays.entry(AssetId::from_byte_array(o.asset)).or_default() += o.value + margin;
				}
			}
		}
		let expiries = self.expiries(now)?;
		for plan in self.batches_of(rows, now, 0).await? {
			let asset = plan.asset;
			let specs = plan.leaves.iter().map(|(k, j)| Self::spec(rows[*k], &rows[*k].outputs[*j])).collect::<Result<Vec<_>, _>>()?;
			let reserve = match self.floor(asset).await? {
				Some(f) => ReserveRule::FeeRate { floor_per_kvb: f, multiple: fees::MULTIPLE },
				None => ReserveRule::Fixed { node: 1, entry: 1 },
			};
			// The token's id changes no value: any asset stands in for it.
			let schedule = ClockSchedule::new(AssetId::from_byte_array([0xee; 32]), self.params.operator, self.config.notice, expiries.clone())
				.map_err(|e| RoundError::Internal(e.to_string()))?;
			let params = TreeParams {
				asset, chain: self.params.chain, schedule, burn: false, delegated_reclaim: self.config.delegated_reclaim, radix: self.config.radix, reserve,
				min_leaf: Self::tree_min_leaf(&self.params, &asset, &specs),
			};
			let kind = if plan.own { BatchKind::Tree } else { self.kind_of(&asset, &specs) };
			let batch = Batch::build(kind, params, &specs)
				.map_err(|e| RoundError::Internal(format!("the batch of asset {}: {}", asset, e)))?;
			*pays.entry(asset).or_default() += batch.batch_output().value;
		}
		Ok(pays)
	}

	/// The participations of `chosen` the wallet can fund now, in order: per
	/// asset, what a round with them pays must fit in what the wallet can
	/// spend of that asset. One that does not fit waits, saying why, and the
	/// ones after it are taken if they fit.
	async fn fundable(&self, chosen: Vec<ParticipationRow>, now: MedianTime) -> Result<Vec<ParticipationRow>, RoundError> {
		let balance = self.wallet.balance().await?;
		// A round of an issuer-operated asset mints what it pays of it: what
		// it may pay is what the asset's mint limiter allows now.
		let mut minting: BTreeMap<AssetId, Result<crate::issuer::MintRoom, String>> = BTreeMap::new();
		for row in &chosen {
			if let Some(a) = Self::asset_of(row) {
				if !minting.contains_key(&a) {
					if let Some(r) = self.mint_room(a).await? {
						minting.insert(a, r);
					}
				}
			}
		}
		let have = |a: &AssetId| match minting.get(a) {
			Some(Ok(m)) => m.room,
			Some(Err(_)) => 0,
			None => balance.get(a).copied().unwrap_or(0),
		};
		let all: Vec<&ParticipationRow> = chosen.iter().collect();
		let whole = self.pays(&all, now).await?;
		if whole.iter().all(|(a, v)| *v <= have(a)) {
			return Ok(chosen);
		}
		let mut taken: Vec<ParticipationRow> = vec![];
		for row in chosen {
			let mut with: Vec<&ParticipationRow> = taken.iter().collect();
			with.push(&row);
			let pays = self.pays(&with, now).await?;
			let mine: Vec<AssetId> = row.outputs.iter().map(|o| AssetId::from_byte_array(o.asset)).collect();
			match pays.iter().find(|(a, v)| mine.contains(a) && **v > have(a)) {
				Some((a, v)) => match minting.get(a) {
					Some(m) => {
						let why = match m {
							Ok(room) => room.wait(&self.params.assets.get(a).and_then(|x| x.issuer).expect("minting").limiter, *v)
								.unwrap_or_default(),
							Err(why) => why.clone(),
						};
						self.wait_for(&row, &format!("a round of asset {} mints what it pays of it, and {}; it runs once the limiter allows \
							it", a, why)).await?;
					},
					None => self.wait(&row, *a, *v, have(a)).await?,
				},
				None => taken.push(row),
			}
		}
		Ok(taken)
	}

	/// The participations of `chosen` within each asset's in-flight cap
	/// ([`crate::params::AssetParams::in_flight_cap`]), in order: what the
	/// operator has fronted for refreshes whose old coins have not come back
	/// ([`Store::in_flight`]), with what the ones taken before it give up, plus
	/// what it gives up, must stay within the cap of every asset it gives up
	/// coins in. One that would not waits for a later round, saying so in
	/// plain words, and delays no other, whatever asset that is: a cap of 0
	/// (an asset whose pool is empty) holds up none of a round's other
	/// assets. Coins resting on boards alone count for nothing, as the
	/// operator's forfeit of them pays it back at once. A participation with a
	/// coin within [`CAP_EXEMPT`] of its first expiry is never held by the
	/// cap: its holder would otherwise take it on the chain. Nor is an
	/// offboard (a holder moving coins out of the Ark), which the float the
	/// cap keeps is for, though what it gives up counts in flight. Nor is one whose
	/// coins rest only on lowest nodes that already hold fronted value and
	/// can still come back ([`crate::delegations::can_complete`]): it opens
	/// nothing new, and those nodes come back only once it runs, so holding it
	/// would keep the cap full for ever. One larger than a cap above 0 runs
	/// once nothing of the asset is in flight. Coins on accumulator batches
	/// count like any others, and never complete a node.
	async fn within_cap(&self, chosen: Vec<ParticipationRow>, now: MedianTime) -> Result<Vec<ParticipationRow>, RoundError> {
		let caps: BTreeMap<AssetId, u64> = self.params.assets.ids().into_iter()
			.filter_map(|a| self.params.in_flight_cap(&a).map(|c| (a, c))).collect();
		if caps.is_empty() || chosen.is_empty() {
			return Ok(chosen);
		}
		let mut flight: BTreeMap<AssetId, u64> = self.store.in_flight().await?.into_iter()
			.map(|(a, v)| (AssetId::from_byte_array(a), v)).collect();
		// The lowest nodes already holding fronted value that can still come
		// back by their holders' releases: a refresh of a coin resting on them
		// alone opens nothing new, and the node comes back only once it runs.
		// A node that cannot come back (a coin on it moved without a
		// delegation, say) holds its value until expiry whatever runs, so a
		// refresh on it is held by the cap like any other.
		let mut open: HashSet<[u8; 32]> = HashSet::new();
		let mut batches: BTreeSet<(i64, u32)> = BTreeSet::new();
		for (_, round_id, vout, rec) in self.store.in_flight_slots().await? {
			if let Some(h) = lowest_of(&rec) {
				open.insert(h);
				batches.insert((round_id, vout));
			}
		}
		let mut slots: BTreeMap<[u8; 32], Vec<[u8; 32]>> = BTreeMap::new();
		for (round_id, vout) in batches {
			let Some(round) = self.store.round(round_id).await? else { continue };
			let Some((_, leaves)) = self.store.batch(&round.txid, vout).await? else { continue };
			for l in leaves {
				if let Some(h) = lowest_of(&l.record).filter(|h| open.contains(h)) {
					slots.entry(h).or_default().push(l.leaf_id);
				}
			}
		}
		let mut completable: HashSet<[u8; 32]> = HashSet::new();
		for (h, ids) in &slots {
			if crate::delegations::can_complete(&self.store, ids, *h).await? {
				completable.insert(*h);
			}
		}
		let mut out = Vec::with_capacity(chosen.len());
		for row in chosen {
			let mut adds: BTreeMap<AssetId, u64> = BTreeMap::new();
			let mut near = false;
			let mut completes = true;
			for i in row.inputs.iter().filter(|i| !i.returned) {
				let asset = AssetId::from_byte_array(i.asset);
				if !caps.contains_key(&asset) {
					continue;
				}
				let Some(l) = self.store.leaf(&i.leaf_id).await? else { continue };
				let Ok(record) = CoinRecord::from_bytes(&l.record) else { continue };
				let Some(expiry) = crate::cosign::first_expiry(&record) else { continue };
				near |= expiry < now.to_consensus_u32().saturating_add(CAP_EXEMPT);
				completes &= lowest_nodes(&record).is_some_and(|ns| !ns.is_empty() && ns.iter().all(|h| completable.contains(h)));
				*adds.entry(asset).or_default() += i.value;
			}
			let completes = completes && !adds.is_empty();
			// A holder moving coins out of the Ark (an offboard: a stake, a
			// withdrawal) is never held by the cap: the cap holds refreshes
			// back so that the pool keeps what such moves need, and holding
			// them too would leave that float unused. What it gives up still
			// counts in flight.
			let leaves_the_ark = row.outputs.iter().any(|o| matches!(o.kind, WantedKind::Offboard { .. }));
			// One refresh larger than a cap above 0 runs when nothing else is
			// in flight, or it would wait for ever.
			let over = adds.iter().find(|(a, v)| {
				let f = flight.get(*a).copied().unwrap_or(0);
				f.saturating_add(**v) > caps[*a] && !(f == 0 && caps[*a] > 0)
			}).map(|(a, _)| *a);
			if let Some(a) = over.filter(|_| !near && !completes && !leaves_the_ark) {
				let why = format!("This refresh waits for a later round: the operator is refreshing as much of this asset as it takes on \
					at once, and takes more as earlier refreshes come back. Nothing is lost meanwhile. (Asset {}: {} of a cap of {} \
					in flight.)", a, flight.get(&a).copied().unwrap_or(0), caps[&a]);
				self.wait_for(&row, &why).await?;
				continue;
			}
			for (a, v) in adds {
				*flight.entry(a).or_default() += v;
			}
			out.push(row);
		}
		Ok(out)
	}

	/// Records why `row` waits.
	async fn wait_for(&self, row: &ParticipationRow, why: &str) -> Result<(), RoundError> {
		if row.waiting.as_deref() != Some(why) {
			log::warn!("participation {} waits: {}", crate::signer::hex(&row.id), why);
		}
		self.store.set_waiting(&row.id, Some(why)).await?;
		Ok(())
	}

	/// The smallest leaf a batch of `asset` holding `specs` publishes: the
	/// operator's smallest leaf now, or the smallest of `specs` when that is
	/// less. Each leaf was within the bounds when its participation was
	/// taken; a smallest leaf set as a value moves with the asset's rate
	/// since, and the builder refuses a leaf below the batch's smallest.
	fn tree_min_leaf(params: &Params, asset: &AssetId, specs: &[LeafSpec]) -> u64 {
		let least = specs.iter().map(|l| l.value).min().unwrap_or(1);
		params.min_leaf(asset).unwrap_or(1).min(least).max(1)
	}

	/// The leaf `o` of `row` wants, as the tree builder takes it.
	fn spec(row: &ParticipationRow, o: &crate::store::ParticipationOutput) -> Result<LeafSpec, RoundError> {
		match &o.kind {
			WantedKind::Leaf { template, owner_key, owner_nonce, exit_delay_units, operator_nonce, htlc, order, landing, channel } => Ok(LeafSpec {
				template: template.parse::<Template>().map_err(|e| RoundError::Internal(e.to_string()))?,
				owner: elements::secp256k1_zkp::XOnlyPublicKey::from_slice(owner_key).map_err(|e| RoundError::Internal(e.to_string()))?,
				value: o.value,
				owner_nonce: *owner_nonce,
				operator_nonce: *operator_nonce,
				exit_delay: RelativeTime::from_units(*exit_delay_units).map_err(|e| RoundError::Internal(e.to_string()))?,
				unlock_hash: row.unlock_hash,
				htlc: *htlc,
				order: *order,
				landing: *landing,
				channel: *channel,
			}),
			WantedKind::Offboard { .. } => Err(RoundError::Internal("an offboard is not a leaf".into())),
		}
	}

	/// The expiries of a round built at `now`.
	fn expiries(&self, now: MedianTime) -> Result<Vec<MedianTime>, RoundError> {
		(1..=self.config.steps as u32)
			.map(|k| MedianTime::from_consensus(now.to_consensus_u32() + k * self.config.lifetime))
			.collect::<Result<_, _>>().map_err(|e| RoundError::Internal(e.to_string()))
	}

	/// Builds, checks, records and broadcasts the round of `chosen`, spending
	/// every coin of `ties` a participation of `chosen` needs, and filling
	/// `fills`: the order at input `k` credited at output `2k` and resting
	/// again at `2k+1` (or, filled whole, an output of another asset there),
	/// the batches after them.
	async fn build_from(&self, chosen: &[ParticipationRow], fills: &[PlannedFill], now: MedianTime, ties: &[Tie])
		-> Result<Option<Built>, RoundError>
	{
		let p = self.params.clone();
		let s = p.operator;

		// The leaves of each batch ([`Rounds::batches_of`]), and the offboards.
		let rows: Vec<&ParticipationRow> = chosen.iter().collect();
		let plan = self.batches_of(&rows, now, ties.len()).await?;
		let mut groups: Vec<(AssetId, Vec<Planned>)> = Vec::with_capacity(plan.len());
		for b in &plan {
			let mut leaves = Vec::with_capacity(b.leaves.len());
			for (k, j) in &b.leaves {
				leaves.push(Planned { participation: *k, output: *j as u16, spec: Self::spec(&chosen[*k], &chosen[*k].outputs[*j])? });
			}
			groups.push((b.asset, leaves));
		}
		let mut offboards: Vec<PlannedOffboard> = vec![];
		for (k, row) in chosen.iter().enumerate() {
			for (j, o) in row.outputs.iter().enumerate() {
				let asset = AssetId::from_byte_array(o.asset);
				match &o.kind {
					WantedKind::Leaf { .. } => {},
					WantedKind::Offboard { script, margin, reclaim_delay_units } => {
						let policy = OffboardPolicy {
							unlock_hash: row.unlock_hash,
							destination: ExplicitOutput::new(asset, o.value, elements::Script::from(script.clone())),
							operator: s,
							reclaim_delay: RelativeTime::from_units(*reclaim_delay_units).map_err(|e| RoundError::Internal(e.to_string()))?,
						};
						offboards.push(PlannedOffboard { participation: k, output: j as u16, policy, margin: *margin });
					},
				}
			}
		}

		// A round of an issuer-operated asset mints what it pays in the asset
		// ([`crate::issuer`]): the limiter's coin at input 0, its successor at
		// output 0. It fills no order: the orders would hold the low inputs.
		let round_asset = groups.first().map(|g| g.0).or_else(|| offboards.first().map(|o| o.policy.destination.asset));
		let issuer = round_asset.and_then(|a| p.assets.get(&a).and_then(|x| x.issuer).map(|i| (a, i)));
		if issuer.is_some() && !fills.is_empty() {
			return Err(RoundError::Internal("an issuer-operated asset's round fills no on-chain order".into()));
		}
		let minted = issuer.map(|(a, _)| a);
		// Outputs 0..2n-1 are the orders', or output 0 the limiter's
		// successor; the batches start after them.
		let base = 2 * fills.len() as u32 + minted.is_some() as u32;

		// The fee asset: the round's own, when the node accepts it and it is
		// one of the operator's fee assets, else the first of those the node
		// accepts; never an asset the round mints, of which the operator
		// keeps nothing.
		let fee_assets: Vec<AssetId> = p.fee_assets().into_iter().filter(|a| Some(*a) != minted).collect();
		let mut floors: BTreeMap<AssetId, Option<u64>> = BTreeMap::new();
		let round_assets: Vec<AssetId> = groups.iter().map(|g| g.0).chain(offboards.iter().map(|o| o.policy.destination.asset)).collect();
		for a in round_assets.iter().chain(fee_assets.iter()) {
			if !floors.contains_key(a) {
				let f = self.floor(*a).await?;
				floors.insert(*a, f);
			}
		}
		let accepted = |a: &AssetId| floors.get(a).copied().flatten().is_some();
		let fee_asset = fee_assets.iter().find(|a| round_assets.contains(a) && accepted(a))
			.or_else(|| fee_assets.iter().find(|a| accepted(a)))
			.copied()
			.ok_or_else(|| RoundError::NoFeeAsset(format!("asset(s) {:?}, fee assets {:?}", round_assets, fee_assets)))?;
		let fee_floor = floors[&fee_asset].expect("accepted");
		let connector = AssetAmount::new(fee_asset, fees::atoms_for(fee_floor, issuance_vsize(s, fee_asset), fees::MULTIPLE).max(1));

		// The schedule's times and each batch's reserve rule.
		let expiries = self.expiries(now)?;
		let reserves: BTreeMap<AssetId, ReserveRule> = groups.iter().map(|g| &g.0).map(|a| (*a, match floors[a] {
			Some(f) => ReserveRule::FeeRate { floor_per_kvb: f, multiple: fees::MULTIPLE },
			None => ReserveRule::Fixed { node: 1, entry: 1 },
		})).collect();
		let (radix, notice, chain, delegated_reclaim) = (self.config.radix, self.config.notice, p.chain, self.config.delegated_reclaim);

		// The transaction: the wallet issues the tokens, the trees are built
		// on them.
		// The coins that keep this round apart from every lost round of a
		// participation it runs again.
		let mut lost = BTreeSet::new();
		for row in chosen.iter().filter(|r| r.attempt > 0) {
			lost.extend(self.lost_rounds(&row.id).await?);
		}
		let ties: Vec<&Tie> = ties.iter().filter(|t| lost.contains(&t.replaces)).collect();
		let mut forced: Vec<WalletCoin> = vec![];
		for t in &ties {
			if !forced.iter().any(|c| (c.txid, c.vout) == (t.coin.txid, t.coin.vout)) {
				forced.push(t.coin.clone());
			}
		}
		if let Some(l) = lost.iter().find(|l| !ties.iter().any(|t| t.replaces == **l)) {
			return Err(RoundError::Internal(format!("no coin keeps the round apart from lost round {}", l)));
		}
		// The mint: exactly what the round pays in the asset, from the
		// limiter's coin, which must allow it.
		let mut foreign = vec![];
		let mut successor = None;
		let mut mint = None;
		if let Some((asset, i)) = &issuer {
			let rows: Vec<&ParticipationRow> = chosen.iter().collect();
			let amount = self.pays(&rows, now).await?.get(asset).copied().unwrap_or(0);
			let room = match self.mint_room(*asset).await? {
				Some(Ok(r)) => r,
				Some(Err(why)) => return Err(RoundError::MintWaits(why)),
				None => return Err(RoundError::Internal("an issuer-operated asset with no limiter".into())),
			};
			if let Some(why) = room.wait(&i.limiter, amount) {
				return Err(RoundError::MintWaits(why));
			}
			let next = i.limiter.mint(room.now.state, room.age, amount).map_err(|e| RoundError::MintWaits(e.to_string()))?;
			let token_amount = room.now.txout.value.explicit().ok_or_else(|| RoundError::Internal("the limiter's coin hides its value".into()))?;
			foreign.push(Foreign {
				outpoint: room.now.coin,
				txout: room.now.txout.clone(),
				witness: MINT_WITNESS.iter().map(|n| vec![0; *n]).collect(),
				sequence: arca_covenant::limiter::age_sequence(room.age),
				issuance: Some(arca_covenant::limiter::reissuance(i.entropy, amount)),
			});
			successor = Some(ExplicitOutput::new(i.limiter.token, token_amount, i.limiter.script_pubkey(next)));
			mint = Some((*asset, *i, room, amount, next));
		}
		// Each order's input, first, and the outputs its FILL leaf reads: the
		// credit at 2k, and at 2k+1 the order resting again or, for a full
		// fill, an output to the operator in the asset the order is paid in.
		let mut fill_outputs = vec![];
		for f in fills {
			foreign.push(Foreign::spent_by_script(f.order, ExplicitOutput::new(f.terms.asset_a, f.locked, f.terms.script_pubkey()).txout(),
				f.terms.witness()));
			fill_outputs.push(f.plan.credit.clone());
			fill_outputs.push(match &f.plan.rest {
				Some(rest) => rest.clone(),
				None => ExplicitOutput::new(f.terms.asset_b, gap_value(f.terms.asset_b, fee_asset), self.wallet.change_script().await?),
			});
		}
		// Each batch's kind, chosen before the tokens: a tree or an
		// accumulator batch.
		// A holder's own batch is a tree, so that it can be reclaimed.
		let kinds: Vec<BatchKind> = groups.iter().zip(&plan)
			.map(|((a, leaves), b)| if b.own { BatchKind::Tree } else { self.kind_of(a, &leaves.iter().map(|l| l.spec).collect::<Vec<_>>()) })
			.collect();
		let (built, trees) = self.wallet.build_round(groups.len(), fee_asset, connector, &forced, &foreign, minted, |tokens| {
			let mut outputs: Vec<ExplicitOutput> = successor.iter().cloned().collect();
			outputs.extend(fill_outputs.iter().cloned());
			let mut trees = vec![];
			for (bi, ((asset, leaves), token)) in groups.iter().zip(tokens).enumerate() {
				let schedule = ClockSchedule::new(*token, s, notice, expiries.clone()).map_err(|e| e.to_string())?;
				let specs: Vec<LeafSpec> = leaves.iter().map(|l| l.spec).collect();
				// An issuer-operated asset's batch is burn-only.
				let params = TreeParams {
					asset: *asset, chain, schedule, burn: Some(*asset) == minted, delegated_reclaim, radix, reserve: reserves[asset],
					min_leaf: Self::tree_min_leaf(&p, asset, &specs),
				};
				let tree = Batch::build(kinds[bi], params.clone(), &specs).map_err(|e| format!("the batch of asset {}: {}", asset, e))?;
				outputs.push(tree.batch_output());
				outputs.push(ExplicitOutput::new(*token, 1, tree.clock0_script_pubkey()));
				trees.push((tree, params));
			}
			for o in &offboards {
				outputs.push(o.policy.output(o.margin));
			}
			Ok((outputs, trees))
		}).await?;
		let mut tx = built.tx.clone();
		let txid = tx.txid();
		let c = built.connector_vout.expect("a round has a connector");
		let release = |e: RoundError| async move {
			if let Err(w) = self.wallet.release(&txid).await {
				log::error!("round {}: its coins could not be freed: {}", txid, w);
			}
			Err::<Option<Built>, RoundError>(e)
		};
		// The mint, signed by the signer once the round is whole: it checks
		// every unit of the asset goes to a burn-only batch or an offboard it
		// rebuilds, and the limiter's tool signs over the whole transaction.
		// The wallet's signatures are made already; neither covers the
		// other's witness.
		if let Some((asset, i, room, amount, _)) = &mint {
			let mut batches = vec![];
			for (k, ((tree, params), (_, leaves))) in trees.iter().zip(&groups).enumerate() {
				let specs: Vec<LeafSpec> = leaves.iter().map(|l| l.spec).collect();
				if tree.kind() != BatchKind::Tree {
					return release(RoundError::Internal("an issuer-operated asset's batch is a tree".into())).await;
				}
				match crate::issuer::WireBatch::of(base + 2 * k as u32, params, &specs) {
					Ok(b) => batches.push(b),
					Err(e) => return release(RoundError::Internal(e)).await,
				}
			}
			let offs = offboards.iter().enumerate()
				.map(|(k, o)| crate::issuer::WireOffboard::of(base + 2 * trees.len() as u32 + k as u32, &o.policy, o.margin)).collect();
			let req = crate::issuer::WireReissue::new(&tx, &built.prevouts, *asset, i.entropy, room.now.state, batches, offs);
			match self.signer.reissue(&req).await {
				Ok(w) => tx.input[0].witness.script_witness = w,
				Err(e) => return release(RoundError::Mint(e.to_string())).await,
			}
			let paid: u64 = tx.output.iter().filter(|o| o.asset.explicit() == Some(*asset)).filter_map(|o| o.value.explicit()).sum();
			if paid != *amount {
				return release(RoundError::Check(format!("the round mints {} of asset {} and pays {} of it", amount, asset, paid))).await;
			}
		}

		// Checked as a wallet would check it.
		let accept = WalletPolicy {
			min_exit_delay: p.min_exit_delay,
			max_exit_delay: p.max_exit_delay,
			..WalletPolicy::new(chain, s, now)
		};
		let mut new_batches = vec![];
		for (i, ((batch, tp), (asset, leaves))) in trees.iter().zip(&groups).enumerate() {
			let vout = base + 2 * i as u32;
			// Each leaf's id, script and record, as its owner's wallet checks
			// it: a tree leaf's path, or an accumulator leaf's slot.
			let mut checked: Vec<(LeafId, Script, Result<Vec<u8>, String>)> = Vec::with_capacity(leaves.len());
			let mut failed = None;
			match batch {
				Batch::Tree(tree) => for (j, record) in tree.records().into_iter().enumerate() {
					match record.validate_round(&tx, &accept) {
						Ok(v) if v.batch_vout == vout =>
							checked.push((v.leaf_id, v.branch.leaf.script_pubkey(), record.to_bytes().map_err(|e| e.to_string()))),
						Ok(v) => failed = failed.or(Some(format!("batch {} is at output {}, not {}", i, v.batch_vout, vout))),
						Err(e) => failed = failed.or(Some(format!("leaf {} of batch {}: {}", j, i, e))),
					}
				},
				Batch::Accumulator(acc) => for (j, record) in acc.records().into_iter().enumerate() {
					match record.validate_round(&tx, &accept) {
						Ok(v) if v.batch_vout == vout =>
							checked.push((v.leaf_id, v.leaf.script_pubkey(), record.to_bytes().map_err(|e| e.to_string()))),
						Ok(v) => failed = failed.or(Some(format!("batch {} is at output {}, not {}", i, v.batch_vout, vout))),
						Err(e) => failed = failed.or(Some(format!("leaf {} of batch {}: {}", j, i, e))),
					}
				},
			}
			if let Some(why) = failed {
				return release(RoundError::Check(why)).await;
			}
			let mut new_leaves = vec![];
			for (j, ((leaf_id, leaf_spk, record), l)) in checked.into_iter().zip(leaves).enumerate() {
				let row = &chosen[l.participation];
				let record = match record {
					Ok(b) => b,
					Err(e) => return release(RoundError::Internal(e)).await,
				};
				new_leaves.push(NewBatchLeaf {
					coin: NewCoin {
						leaf_id: leaf_id.0,
						kind: LeafKind::Batch,
						asset: asset.into_inner().to_byte_array(),
						value: l.spec.value,
						owner_key: l.spec.owner.serialize(),
						script_pubkey: leaf_spk.to_bytes(),
						hops: 0,
						record: vec![],
						state: LeafState::Pending,
						// Promised to the participation when it took its
						// operator nonce.
						salt: arca_covenant::leaf::leaf_salt(&l.spec.owner_nonce, &l.spec.operator_nonce),
						promised_to: Some(row.id),
						// Taken when the participation was accepted.
						operator_nonce: None,
						scripts: vec![NewScript { script_pubkey: leaf_spk.to_bytes(), kind: ScriptKind::Leaf }],
						maker_coin: false,
					},
					idx: j as u32,
					participation_id: row.id,
					output_idx: l.output,
					attempt: row.attempt,
					template: l.spec.template.to_string(),
					owner_key: l.spec.owner.serialize(),
					owner_nonce: l.spec.owner_nonce,
					operator_nonce: l.spec.operator_nonce,
					exit_delay_units: l.spec.exit_delay.units(),
					value: l.spec.value,
					unlock_hash: l.spec.unlock_hash,
					record,
				});
			}
			// Every node and entry, so their outputs are seen once unrolled:
			// an accumulator batch has no nodes, and each exit pays an entry.
			let mut scripts = vec![];
			if let Batch::Tree(tree) = batch {
				for (level, nodes) in tree.levels().iter().enumerate() {
					for (k, nd) in nodes.iter().enumerate() {
						scripts.push(NewTreeScript {
							script_pubkey: nd.output().script_pubkey.to_bytes(), kind: TreeScriptKind::Node,
							level: level as i16, idx: k as u32, value: nd.value,
						});
					}
				}
			}
			for (k, l) in batch.leaves().iter().enumerate() {
				scripts.push(NewTreeScript {
					script_pubkey: l.entry.script_pubkey().to_bytes(), kind: TreeScriptKind::Entry,
					level: -1, idx: k as u32, value: l.entry_value,
				});
			}
			new_batches.push(NewBatch {
				batch: BatchRow {
					round_id: 0,
					vout,
					asset: asset.into_inner().to_byte_array(),
					value: batch.batch_output().value,
					token: tp.schedule.token.into_inner().to_byte_array(),
					token_vout: vout + 1,
					issuer: (tx.input[foreign.len() + i].previous_output.txid.to_byte_array(),
						tx.input[foreign.len() + i].previous_output.vout),
					schedule: tp.schedule.encode(),
					burn: tp.burn,
					radix: if batch.kind() == BatchKind::Tree { tp.radix as u16 } else { 0 },
					reserve: match tp.reserve {
						ReserveRule::FeeRate { floor_per_kvb, multiple } => StoredReserve::FeeRate { floor_per_kvb, multiple },
						ReserveRule::Fixed { node, entry } => StoredReserve::Fixed { node, entry },
					},
					min_leaf: tp.min_leaf,
					kind: batch.kind(),
					delegated_reclaim: tp.delegated_reclaim,
				},
				leaves: new_leaves,
				scripts,
			});
		}
		if let Err(e) = (ConnectorPolicy { operator: s }).check(&tx, c) {
			return release(RoundError::Check(e.to_string())).await;
		}
		// Each order as its FILL leaf reads the round: at input k, its credit
		// at 2k, at 2k+1 what was planned, the fill and the credit the take
		// was accepted for; and no batch output at an index any order reads.
		for (k, f) in fills.iter().enumerate() {
			if tx.input[k].previous_output != f.order || tx.input[k].witness.script_witness != f.terms.witness() {
				return release(RoundError::Check(format!("input {} is not order {} with its FILL witness", k, outpoint_text(&f.order)))).await;
			}
			let got = match f.terms.check(&tx, k, f.locked) {
				Ok(g) => g,
				Err(e) => return release(RoundError::Check(e.to_string())).await,
			};
			if (got.filled, got.remainder, got.credited) != (f.plan.filled, f.plan.remainder, f.plan.credit.value) {
				return release(RoundError::Check(format!("order {} at input {} fills {} and rests {} with a credit of {}; the take asked {}, {} \
					and {}", outpoint_text(&f.order), k, got.filled, got.remainder, got.credited, f.plan.filled, f.plan.remainder,
					f.plan.credit.value))).await;
			}
			let at = |i: u32| ExplicitOutput::from_txout(&tx.output[i as usize]);
			if at(2 * k as u32).as_ref() != Some(&f.plan.credit) || at(2 * k as u32 + 1).as_ref() != Some(&fill_outputs[2 * k + 1]) {
				return release(RoundError::Check(format!("outputs {} and {} are not order {}'s credit and what it planned at its 2k+1",
					2 * k, 2 * k + 1, outpoint_text(&f.order)))).await;
			}
		}
		for b in &new_batches {
			if b.batch.vout < base {
				return release(RoundError::Check(format!("a batch output at {}, among the outputs the orders read", b.batch.vout))).await;
			}
		}
		let mut new_offboards = vec![];
		for (k, o) in offboards.iter().enumerate() {
			let vout = base + 2 * trees.len() as u32 + k as u32;
			match o.policy.find(&tx) {
				Ok(v) if v == vout => {},
				Ok(v) => return release(RoundError::Check(format!("offboard {} is at output {}, not {}", k, v, vout))).await,
				Err(e) => return release(RoundError::Check(format!("offboard {}: {}", k, e))).await,
			}
			let row = &chosen[o.participation];
			new_offboards.push(NewOffboard {
				vout, participation_id: row.id, output_idx: o.output, attempt: row.attempt, value: tx.output[vout as usize].value.explicit().unwrap_or(0),
			});
		}
		if tx.lock_time != elements::LockTime::ZERO {
			return release(RoundError::Check("the lock time is not 0".into())).await;
		}
		let probe = tx.clone();
		match self.finality.call(move |src| src.test_accept(&probe)).await {
			Ok((true, _, _)) => {},
			Ok((false, reason, _)) => return release(RoundError::Refused(reason.unwrap_or_default())).await,
			Err(e) => return release(RoundError::Chain(e.to_string())).await,
		}

		// Recorded, then broadcast.
		let new = NewRound {
			txid: txid.to_byte_array(),
			tx: serialize(&tx),
			fee_asset: fee_asset.into_inner().to_byte_array(),
			fee: built.fee.amount,
			created_mtp: now.to_consensus_u32(),
			connector: (c, connector.asset.into_inner().to_byte_array(), connector.amount,
				connector_asset(txid, c).into_inner().to_byte_array()),
			batches: new_batches,
			offboards: new_offboards,
			participations: chosen.iter().map(|r| (r.id, r.attempt)).collect(),
			signer_head: self.store.signer_head_signed().await?,
			reruns: ties.iter().map(|t| NewRerun {
				replaces: t.replaces, tie: (t.coin.txid, t.coin.vout), via: t.via.map(|v| v.to_byte_array()),
			}).collect(),
			fills: fills.iter().enumerate().flat_map(|(k, f)| f.participations.iter().map(move |j| NewRoundFill {
				k: k as u32, participation_id: chosen[*j].id, attempt: chosen[*j].attempt,
			})).collect(),
			mint: mint.as_ref().map(|(asset, _, room, amount, next)| MintRow {
				round_id: 0,
				asset: asset.into_inner().to_byte_array(),
				coin: (room.now.coin.txid.to_byte_array(), room.now.coin.vout),
				minted: room.now.state.minted,
				elapsed: room.now.state.elapsed,
				age: room.age,
				amount: *amount,
				next_minted: next.minted,
				next_elapsed: next.elapsed,
			}),
		};
		let round_id = match self.store.insert_round(&new).await {
			Ok(id) => id,
			Err(e) => return release(e.into()).await,
		};
		// A round that fills orders waits, built, for its takes' forfeits
		// ([`Self::takes_ready`]); any other goes out at once.
		let broadcast = if fills.is_empty() {
			self.submit(round_id, &tx, built.fee).await?
		} else {
			"held: it is broadcast once every take in it has handed over its forfeits".to_string()
		};
		let batches: Vec<(AssetId, u32, usize)> = groups.iter().enumerate().map(|(i, (a, l))| (*a, base + 2 * i as u32, l.len())).collect();
		log::info!("round {} ({}): {} batch(es), {} offboard(s), {} participation(s), {} order(s) filled, {} vB, fee {} of {}: {}",
			round_id, txid, batches.len(), offboards.len(), chosen.len(), fills.len(), tx.vsize(), built.fee.amount, fee_asset, broadcast);
		for (k, f) in fills.iter().enumerate() {
			log::info!("round {}: order {} at input {}, filled by {} for {} take(s), its credit of {} at output {}, {} at output {}", round_id,
				outpoint_text(&f.order), k, f.plan.filled, f.participations.len(), f.plan.credit.value, 2 * k,
				if f.plan.rest.is_some() { "the order resting again" } else { "an output of another asset" }, 2 * k + 1);
		}
		for row in chosen {
			self.store.set_waiting(&row.id, None).await?;
		}
		Ok(Some(Built {
			round_id, tx, batches, offboards: offboards.len(), participations: chosen.len(), connector_vout: c,
			fills: fills.iter().map(|f| f.order).collect(), broadcast,
		}))
	}

	/// Hands the recorded round `round_id` to the nursery.
	async fn submit(&self, round_id: i64, tx: &Transaction, fee: AssetAmount) -> Result<String, RoundError> {
		let result = self.nursery.submit(tx, NurseryKind::Round, Some(fee)).await
			.map_err(|e| RoundError::Internal(format!("the nursery: {}", e)))?;
		self.store.set_round_state(round_id, RoundState::Built, RoundState::Broadcast).await?;
		Ok(result)
	}

	/// One pass: a round recorded but never handed to the nursery goes to
	/// it; a round held as lost that is final in the chain again is restored
	/// ([`Self::restore`]); one the nursery found lost is retired; one the
	/// finality service calls final is marked final, and the new leaves of
	/// its released participations are credited; one no longer final goes
	/// back to broadcast, its leaves uncredited. Then every participation
	/// whose forfeits are overdue expires, and every pending participation
	/// with a coin past its exit deadline is voided.
	pub async fn pass(&self) -> Result<(), RoundError> {
		let going_out = self.going_out.lock().await;
		for r in self.store.rounds_in(RoundState::Built).await? {
			let fills = !self.store.round_fills(r.round_id).await?.is_empty();
			if fills {
				// A round that fills orders goes out only with every order of
				// it unspent: each is checked again at the node first, and
				// one taken meanwhile drops the round unbroadcast.
				match self.orders_now(&r).await? {
					OrdersNow::Rest => {},
					OrdersNow::Wait(why) => {
						log::warn!("round {} ({}) waits before it goes out: {}", r.round_id, Txid::from_byte_array(r.txid), why);
						continue;
					},
					// An order spent by the round itself: the node holds the
					// round, handed to it before it was recorded as broadcast
					// (the server stopped in between). It is broadcast, and
					// goes on as any broadcast round.
					OrdersNow::Taken(_) if self.node_holds(&r).await? => {
						self.store.set_round_state(r.round_id, RoundState::Built, RoundState::Broadcast).await?;
						log::warn!("round {} ({}) is held by the node: recorded as broadcast", r.round_id, Txid::from_byte_array(r.txid));
						continue;
					},
					OrdersNow::Taken(voids) => {
						self.drop_fill_round(&r, &voids).await?;
						continue;
					},
				}
				// It goes out once every take in it has handed over its
				// forfeits, and is dropped, unbroadcast, when one has not
				// within the window.
				if !self.takes_ready(&r).await? {
					continue;
				}
			}
			let tx: Transaction = deserialize(&r.tx).map_err(|e| RoundError::Internal(e.to_string()))?;
			let fee = AssetAmount::new(AssetId::from_byte_array(r.fee_asset), r.fee);
			let answer = self.submit(r.round_id, &tx, fee).await?;
			// An order taken between that check and the node's answer: the
			// node refused the round, and it is resolved from the node's view
			// of its orders at once.
			if fills && answer != "accepted" {
				if let Some(r) = self.store.round(r.round_id).await? {
					self.refused_fill_round(&r).await?;
				}
			}
		}
		drop(going_out);
		// A round held as lost that is final again, before anything is
		// retired: the parent chain decides which round stands.
		for r in self.store.rounds_in(RoundState::Lost).await? {
			if self.finality.status(&Txid::from_byte_array(r.txid)).await.map_err(|e| RoundError::Chain(e.to_string()))?.is_final() {
				self.restore(&r).await?;
				continue;
			}
			// A fill round dropped unbroadcast (one the nursery was never
			// handed) dies on the chain: one of its own coins spent in a
			// transaction of the wallet's, done again at each pass until one
			// is under way (after a restart, or when the wallet could not do
			// it at once).
			if !self.store.round_fills(r.round_id).await?.is_empty() && self.store.nursery_get(&r.txid).await?.is_none() {
				if let Err(e) = self.void_on_chain(&r).await {
					log::warn!("round {} ({}), dropped unbroadcast: its own coin could not be spent now: {}", r.round_id,
						Txid::from_byte_array(r.txid), e);
				}
			}
		}
		let mut rows = self.store.rounds_in(RoundState::Broadcast).await?;
		rows.extend(self.store.rounds_in(RoundState::Final).await?);
		for r in rows {
			// A fill round the node refused, because another transaction
			// took an order of it, is resolved from the node's view of its
			// orders, not the store's index, which never saw that spend.
			if r.state == RoundState::Broadcast && self.refused_fill_round(&r).await? {
				continue;
			}
			if self.nursery_lost(&r).await? {
				self.retire(&r).await?;
				continue;
			}
			self.check_round(&r).await?;
		}
		// A step of an offline-refresh plan in a final round is done: released
		// without forfeits (its refund stands in their place), its leaf credited.
		crate::plans::finish(&self.store).await?;
		self.release_held().await?;
		// A plan whose coin its holder gave up in a participation of its own,
		// now released, ends.
		crate::plans::release_given_up(&self.store).await?;
		self.expire().await?;
		self.void_overdue().await?;
		Ok(())
	}

	/// Whether the round `r`, built to fill on-chain orders and not yet
	/// broadcast, may go out: every take in it has handed over its forfeits
	/// (the owner's half of each, which is all the operator needs to complete
	/// it). Its takes' forfeits are what the operator gets for paying their
	/// orders' makers on the chain: a round broadcast without them would pay a
	/// maker for a take that could then walk away with its coins. When the
	/// window ([`Params::fill_forfeit_window_seconds`], by the chain's median
	/// time from when the round was built) has passed without them, the round
	/// is dropped unbroadcast: its coins are freed, each take whose forfeits
	/// did not come is voided, saying why, and the others run again.
	async fn takes_ready(&self, r: &RoundRow) -> Result<bool, RoundError> {
		let mut missing = vec![];
		for f in self.store.round_fills(r.round_id).await? {
			let (n, whole, unsigned) = self.store.forfeit_count(&f.participation_id, r.round_id).await?;
			if whole + unsigned < n {
				missing.push(f.participation_id);
			}
		}
		if missing.is_empty() {
			return Ok(true);
		}
		let now = self.now().await?.to_consensus_u32() as u64;
		if now < r.created_mtp as u64 + self.params.fill_forfeit_window_seconds as u64 {
			return Ok(false);
		}
		let why = format!("its forfeits did not come within {} s of its round being built: a round that fills orders pays their makers \
			on the chain, so it goes out only once every take in it has handed over its forfeits", self.params.fill_forfeit_window_seconds);
		let voids: Vec<([u8; 32], String)> = missing.into_iter().map(|id| (id, why.clone())).collect();
		self.drop_fill_round(r, &voids).await?;
		Ok(false)
	}

	/// Each order of `r`, a fill round not yet broadcast, checked again at
	/// the node as when the round was built ([`Self::order_unfit`]): spent
	/// by another transaction, in a block or the node's mempool, or
	/// refundable by its maker within the margin, it can no longer be filled.
	async fn orders_now(&self, r: &RoundRow) -> Result<OrdersNow, RoundError> {
		let mut taken = vec![];
		let mut wait = None;
		for f in self.store.round_fills(r.round_id).await? {
			let Some(p) = self.store.participation(&f.participation_id).await? else { continue };
			match self.order_unfit(&p).await? {
				None => {},
				Some((true, why)) => taken.push((p.id, why)),
				Some((false, why)) => wait = Some(why),
			}
		}
		Ok(match (taken.is_empty(), wait) {
			(false, _) => OrdersNow::Taken(taken),
			(true, Some(why)) => OrdersNow::Wait(why),
			(true, None) => OrdersNow::Rest,
		})
	}

	/// Drops `r`, a fill round built and never broadcast, whole or not at all
	/// ([`Store::drop_unbroadcast_round`]): every forfeit recorded for it
	/// deleted, its coins freed, each take of `voids` voided with its reason,
	/// and every other take of it run again in the round built after it. One
	/// of its own coins is then spent at once ([`Self::void_on_chain`]), so it
	/// can never confirm. Returns whether it was dropped: not when it is no
	/// longer built.
	async fn drop_fill_round(&self, r: &RoundRow, voids: &[([u8; 32], String)]) -> Result<bool, RoundError> {
		let txid = Txid::from_byte_array(r.txid);
		let Some(again) = self.store.drop_unbroadcast_round(r.round_id).await? else { return Ok(false) };
		self.wallet.release(&txid).await?;
		let mut voided = 0;
		for (id, why) in voids {
			let why = format!("{}; its round {} was dropped unbroadcast, the take is void and the coins it gave up are its owner's again",
				why, txid);
			if self.store.void_participation(id, &why).await? {
				voided += 1;
			}
		}
		log::warn!("round {} ({}), which fills on-chain orders, dropped unbroadcast: {} take(s) void, {} run again", r.round_id, txid,
			voided, again.len().saturating_sub(voided));
		let dropped = self.store.round(r.round_id).await?.unwrap_or_else(|| r.clone());
		if let Err(e) = self.void_on_chain(&dropped).await {
			log::warn!("round {} ({}), dropped unbroadcast: its own coin could not be spent now ({}); the next pass tries again", r.round_id,
				txid, e);
		}
		Ok(true)
	}

	/// Spends one of the operator's own coins among the inputs of `r`, a fill
	/// round dropped unbroadcast, back to the wallet in a transaction of its
	/// own, handed to the nursery: once that is final the round can never
	/// confirm, whoever holds it, and every wallet whose take signed a
	/// forfeit for it finds it gone. Its fee is in the round's fee asset when
	/// the node still accepts it, else in another the node accepts. Nothing
	/// is done when a coin of the round is spent already by another
	/// transaction of the wallet's (that one voids it, or frees the coin
	/// again if it is dropped too), or when an order of it is spent by a
	/// transaction that is final (it is void already). Returns the spend.
	async fn void_on_chain(&self, r: &RoundRow) -> Result<Option<Txid>, RoundError> {
		let _one = self.voiding.lock().await;
		let round_txid = Txid::from_byte_array(r.txid);
		let tx: Transaction = deserialize(&r.tx).map_err(|e| RoundError::Internal(e.to_string()))?;
		let orders = self.store.round_orders(r.round_id).await?;
		for i in tx.input.iter().take(orders) {
			let op = i.previous_output;
			if let Some(by) = self.store.outpoint_spender(&op.txid.to_byte_array(), op.vout).await? {
				if by != r.txid && self.finality.status(&Txid::from_byte_array(by)).await.map_err(|e| RoundError::Chain(e.to_string()))?.is_final() {
					return Ok(None);
				}
			}
		}
		let mut coins = vec![];
		for i in tx.input.iter().skip(orders) {
			let op = i.previous_output;
			let Some(c) = self.store.wallet_coin_at(&op.txid.to_byte_array(), op.vout).await? else { continue };
			match c.spent_by {
				Some(by) if by != r.txid => return Ok(None),
				_ => coins.push(c),
			}
		}
		let fee_asset = AssetId::from_byte_array(r.fee_asset);
		coins.sort_by_key(|c| (AssetId::from_byte_array(c.asset) != fee_asset, c.value));
		let rates = self.finality.call(|c| c.fee_rates()).await.map_err(|e| RoundError::Chain(e.to_string()))?;
		let mut fee_assets = vec![fee_asset];
		fee_assets.extend(coins.iter().map(|c| AssetId::from_byte_array(c.asset)));
		fee_assets.extend(rates.keys().copied());
		let mut seen = HashSet::new();
		fee_assets.retain(|a| rates.get(a).is_some_and(|r| *r > 0) && seen.insert(*a));
		let mut last = String::from("no coin of the operator's among its inputs");
		for coin in &coins {
			for a in &fee_assets {
				match self.wallet.spend_back(coin, *a).await {
					Ok(built) => {
						let txid = built.tx.txid();
						let answer = self.nursery.submit(&built.tx, NurseryKind::Wallet, Some(built.fee)).await
							.map_err(|e| RoundError::Internal(format!("the nursery: {}", e)))?;
						log::warn!("round {} ({}), dropped unbroadcast: its coin {}:{} spent back to the wallet by {} (fee {} of {}): {}; once \
							that is final the round can never confirm", r.round_id, round_txid, Txid::from_byte_array(coin.txid), coin.vout, txid,
							built.fee.amount, built.fee.asset, answer);
						return Ok(Some(txid));
					},
					Err(e @ (WalletError::FeeAssetNotAccepted(_) | WalletError::Insufficient { .. })) => last = e.to_string(),
					Err(e @ WalletError::Raced) => {
						last = e.to_string();
						break;
					},
					Err(e) => return Err(e.into()),
				}
			}
		}
		Err(RoundError::Internal(format!("no coin of round {} could be spent back now: {}", round_txid, last)))
	}

	/// Whether the node holds the round `r` now: in a block of the chain the
	/// server follows, or in its mempool. (Not `getrawtransaction`, whose
	/// index can lag a block just connected.)
	async fn node_holds(&self, r: &RoundRow) -> Result<bool, RoundError> {
		let txid = Txid::from_byte_array(r.txid);
		Ok(self.finality.status(&txid).await.map_err(|e| RoundError::Chain(e.to_string()))?.in_chain()
			|| self.finality.call(|c| c.mempool()).await.map_err(|e| RoundError::Chain(e.to_string()))?.contains(&txid))
	}

	/// Retires `r`, a broadcast fill round, as lost when the node does not
	/// hold it (it refused it, or it left the mempool) because another
	/// transaction took an order of it: each order input is looked up at the
	/// node, not in the store's index of spends, which never saw a spend made
	/// before the round was handed over. The nursery gives the round up, the
	/// wallet's coins of it are freed, and it is retired like any round
	/// another transaction took an input of ([`Self::retire`]): its takes run
	/// again, each order checked again, and the take whose order was taken is
	/// voided then; a coin a take gave up whose forfeit it handed over stays
	/// given up, its owner's on the chain. The transaction that took the order
	/// is recorded where the nursery's check reads spends, so the round's
	/// loss is the chain's as for any round. It acts only once that
	/// transaction is found, in the mempool or a block the server follows,
	/// and is not the round itself: a round just mined, which the node's
	/// transaction index may not show yet, is left as it is. Returns whether
	/// it was retired.
	async fn refused_fill_round(&self, r: &RoundRow) -> Result<bool, RoundError> {
		let fills = self.store.round_fills(r.round_id).await?;
		if fills.is_empty() {
			return Ok(false);
		}
		let txid = Txid::from_byte_array(r.txid);
		let chain = |e: crate::chain::ChainError| RoundError::Chain(e.to_string());
		if self.node_holds(r).await? {
			return Ok(false);
		}
		let tx: Transaction = deserialize(&r.tx).map_err(|e| RoundError::Internal(e.to_string()))?;
		let mut taken = vec![];
		let ks: BTreeSet<u32> = fills.iter().map(|f| f.k).collect();
		for k in ks {
			let Some(op) = tx.input.get(k as usize).map(|i| i.previous_output) else { continue };
			if self.finality.call(move |c| c.unspent(&op, true)).await.map_err(chain)?.is_some() {
				continue;
			}
			match self.order_spender(&op).await? {
				// The round itself spends it, in a block the server has not
				// followed yet: the node holds the round.
				Some(by) if by == txid => return Ok(false),
				Some(by) => taken.push((op, by)),
				// Spent, by a transaction neither in the mempool nor in a
				// block the server has followed: looked up again at the next
				// pass.
				None => return Ok(false),
			}
		}
		if taken.is_empty() {
			return Ok(false);
		}
		// Read again: a pass that read the round before it was found final
		// leaves it as it stands.
		if self.store.round(r.round_id).await?.map(|x| x.state) != Some(RoundState::Broadcast) {
			return Ok(false);
		}
		for (op, by) in &taken {
			self.store.watch_outpoint(&op.txid.to_byte_array(), op.vout, "nursery", &r.txid).await?;
			self.store.set_outpoint_spender(&op.txid.to_byte_array(), op.vout, &by.to_byte_array()).await?;
			self.finality.watch(*by, "spend").await.map_err(|e| RoundError::Chain(e.to_string()))?;
			log::warn!("round {} ({}): the node does not hold it, and its order {} is spent by {}: retired as lost", r.round_id, txid,
				outpoint_text(op), by);
		}
		if self.store.nursery_get(&r.txid).await?.is_some_and(|n| n.state != NurseryState::Lost) {
			self.store.nursery_set_state(&r.txid, NurseryState::Lost).await?;
		}
		self.wallet.release(&txid).await?;
		self.retire(r).await?;
		Ok(true)
	}

	/// The transaction that spends `op` at the node: in its mempool, or in a
	/// block of the chain the server follows from the block of `op`'s own
	/// transaction up.
	async fn order_spender(&self, op: &OutPoint) -> Result<Option<Txid>, RoundError> {
		let chain = |e: crate::chain::ChainError| RoundError::Chain(e.to_string());
		let spends = |tx: &Transaction| tx.input.iter().any(|i| i.previous_output == *op);
		for t in self.finality.call(|c| c.mempool()).await.map_err(chain)? {
			if let Some(tx) = self.finality.call(move |c| c.transaction(&t)).await.map_err(chain)? {
				if spends(&tx) {
					return Ok(Some(t));
				}
			}
		}
		let Some(from) = self.store.tx_location(&op.txid.to_byte_array()).await?.map(|b| b.height) else { return Ok(None) };
		let tip = self.store.tip_block().await?.ok_or(RoundError::NotSynced)?.height;
		for h in from..=tip {
			let Some(b) = self.store.block_at(h).await? else { continue };
			let hash = elements::BlockHash::from_byte_array(b.hash);
			for tx in self.finality.call(move |c| c.block_txs(&hash)).await.map_err(chain)? {
				if spends(&tx) {
					return Ok(Some(tx.txid()));
				}
			}
		}
		Ok(None)
	}

	/// Releases every participation issued in a final round whose preimage
	/// is out, or which the operator can put out at will: one of its
	/// forfeits claimed by the watcher (whose claim reveals the preimage), or
	/// every forfeit of it whole while every coin it gave up is off the
	/// chain. Its new leaves are its owner's either way, so it is released
	/// and they are credited, as when the owner completes it itself; a
	/// forfeit step its owner can no longer finish (its coin on its way home
	/// on the chain, say) leaves nothing stranded. A coin given up whose own
	/// output is on the chain waits for the watcher's answer: until its
	/// forfeit is claimed, its owner may still take it by its exit once the
	/// exit delay has run, and a preimage handed out then would pay for the
	/// coin twice. Returns them.
	pub async fn release_held(&self) -> Result<Vec<[u8; 32]>, RoundError> {
		let mut released = vec![];
		for id in self.store.issued_in_final_rounds().await? {
			let Some(p) = self.store.participation(&id).await? else { continue };
			let Some(round_id) = p.round_id else { continue };
			let (n, whole, _) = self.store.forfeit_count(&id, round_id).await?;
			if whole == 0 {
				continue;
			}
			let why = if self.claimed(&p, round_id).await? {
				"the watcher claimed one of its forfeits, which put its preimage out".to_string()
			} else if whole == n {
				match self.coin_on_chain(&p).await? {
					None => "every forfeit of it is whole and every coin it gave up off the chain, so the operator can put its \
						preimage out at will".to_string(),
					Some(at) => {
						// Said when it starts or its reason changes, not every pass.
						if said_anew(&id, "held", &at) {
							log::info!("participation {}: every forfeit of it is whole, but {}: it is released once the watcher has \
								claimed that coin's forfeit", crate::signer::hex(&id), at);
						}
						continue;
					},
				}
			} else {
				continue;
			};
			if self.store.release_participation(&id, p.attempt, round_id).await? {
				log::info!("participation {} released by the server: {}; its new leaves are credited", crate::signer::hex(&id), why);
				released.push(id);
			}
		}
		Ok(released)
	}

	/// Whether the watcher has claimed a forfeit of participation `p` for the
	/// round `round_id`: a claim in its log, of that round, spending one.
	async fn claimed(&self, p: &ParticipationRow, round_id: i64) -> Result<bool, RoundError> {
		let round = self.store.round(round_id).await?.ok_or_else(|| RoundError::Internal(format!("round {} is not recorded", round_id)))?;
		let m = connector_asset(Txid::from_byte_array(round.txid), round.connector_vout);
		let claims = self.store.watcher_txs("claim", &m.into_inner().to_byte_array()).await?;
		if claims.is_empty() {
			return Ok(false);
		}
		let mut forfeits: HashSet<Txid> = HashSet::new();
		for i in &p.inputs {
			for w in self.store.watcher_txs("forfeit", &i.leaf_id).await? {
				forfeits.insert(Txid::from_byte_array(w.txid));
			}
		}
		for c in claims {
			let tx: Transaction = deserialize(&c.tx).map_err(|e| RoundError::Internal(e.to_string()))?;
			if tx.input.iter().any(|i| forfeits.contains(&i.previous_output.txid)) {
				return Ok(true);
			}
		}
		Ok(false)
	}

	/// The first coin participation `p` gave up whose own output the chain
	/// has shown (in a block or a mempool: its owner's exit brought it there,
	/// or another step of its lineage), and where. `None` while every coin it
	/// gave up is off the chain.
	async fn coin_on_chain(&self, p: &ParticipationRow) -> Result<Option<String>, RoundError> {
		for i in p.inputs.iter().filter(|i| !i.returned) {
			let leaf = LeafId(i.leaf_id);
			let c = match coins::resolve_any_time(&self.store, |t| self.params.taken_policy(t), &leaf).await {
				Ok(c) => c,
				Err(coins::CoinError::Store(e)) => return Err(e.into()),
				Err(e) => return Ok(Some(format!("coin {} given up cannot be read ({})", leaf, e))),
			};
			let script = c.coin.output().script_pubkey.to_bytes();
			if let Some((t, v)) = self.store.sightings_of(&script).await?.first() {
				return Ok(Some(format!("coin {}'s own output is on the chain at {}:{}", leaf, Txid::from_byte_array(*t), v)));
			}
		}
		Ok(None)
	}

	/// Expires every participation that is not released by the later of
	/// [`Params::FORFEIT_DEADLINE`] after its round was found final and its
	/// coins' exit deadline ([`Self::exit_deadline_of`]): its forfeits never
	/// came, or came and were never co-signed. So a wallet that asked for a
	/// refresh in its coin's free window completes it at any sync before the
	/// coin's exit date. Returns them.
	pub async fn expire(&self) -> Result<Vec<[u8; 32]>, RoundError> {
		let now = self.now().await?.to_consensus_u32();
		let cutoff = now.saturating_sub(Params::FORFEIT_DEADLINE);
		let mut expired = vec![];
		for id in self.store.overdue_participations(cutoff).await? {
			// A plan's step waits for no forfeit: it is released once its
			// round is final (`plans::finish`).
			if self.store.plan_step_of(&id).await?.is_some() {
				continue;
			}
			if self.exit_deadline_of(&id).await?.is_some_and(|d| now < d) {
				continue;
			}
			// Some forfeits whole and the rest recorded without the operator's
			// half: the signer may still sign the rest (`fill_unsigned`), and
			// the whole ones can reveal the preimage, so it waits.
			if let Some(round_id) = self.store.participation(&id).await?.and_then(|p| p.round_id) {
				let (_, whole, unsigned) = self.store.forfeit_count(&id, round_id).await?;
				if whole > 0 && unsigned > 0 {
					log::warn!("participation {} is past its forfeit deadline with {} forfeit(s) whole and {} waiting for the operator's \
						half: it waits for the signer, and gives back no coin", crate::signer::hex(&id), whole, unsigned);
					continue;
				}
			}
			if self.store.expire_participation(&id, cutoff).await? {
				log::warn!("participation {} expired: it was not released by the later of a day after its round was found final \
					and its coins' exit deadline (its forfeits did not come, or were not co-signed); each coin for which no forfeit was \
					recorded is given back, the others stay given up, and its new leaves are never credited", crate::signer::hex(&id));
				expired.push(id);
			}
		}
		Ok(expired)
	}

	/// The exit deadline of the coins participation `id` gave up: the
	/// earliest of their exit deadlines, [`Params::PARTICIPATION_HORIZON`]
	/// before each coin's first expiry, or before the service expiry of a
	/// board it rests on. `None` when no coin of it has a date, or one cannot
	/// be resolved (said in the log).
	pub async fn exit_deadline_of(&self, id: &[u8; 32]) -> Result<Option<u32>, RoundError> {
		let Some(p) = self.store.participation(id).await? else { return Ok(None) };
		// Whatever the time: only the coins' dates are asked for.
		let mut earliest: Option<u32> = None;
		for i in &p.inputs {
			let c = match coins::resolve_any_time(&self.store, |t| self.params.taken_policy(t), &LeafId(i.leaf_id)).await {
				Ok(c) => c,
				Err(coins::CoinError::Store(e)) => return Err(e.into()),
				Err(e) => {
					let why = format!("coin {} has no date the server can read: {}", LeafId(i.leaf_id), e);
					if said_anew(id, "date", &why) {
						log::error!("participation {}: {} (said once while it stands)", crate::signer::hex(id), why);
					}
					return Ok(None);
				},
			};
			let batch = c.coin.expiry.to_consensus_u32();
			let e = c.board_expiry.map_or(batch, |b| b.min(batch));
			if e != u32::MAX {
				let d = e.saturating_sub(Params::PARTICIPATION_HORIZON);
				earliest = Some(earliest.map_or(d, |x| x.min(d)));
			}
		}
		Ok(earliest)
	}

	/// Voids every pending participation with a coin past its exit deadline
	/// ([`Self::still_good`]), whether or not a round is being built: its
	/// coins are given back, and their owners take them on the chain. Holds
	/// the round builder's lock, so no round takes a participation this voids.
	/// Returns how many it voided.
	pub async fn void_overdue(&self) -> Result<usize, RoundError> {
		let _one = self.running.lock().await;
		let now = self.now().await?;
		let mut voided = 0;
		for id in self.store.participations_in(ParticipationState::Pending).await? {
			let Some(row) = self.store.participation(&id).await? else { continue };
			if !self.still_good(&row, now).await? && self.store.participation(&id).await?.is_some_and(|r| r.state == ParticipationState::Void) {
				voided += 1;
			}
		}
		Ok(voided)
	}

	/// Whether the nursery has found the round lost: out of the chain, and a
	/// final transaction of another txid spent one of its inputs.
	async fn nursery_lost(&self, r: &RoundRow) -> Result<bool, RoundError> {
		Ok(self.store.nursery_get(&r.txid).await?.is_some_and(|n| n.state == NurseryState::Lost))
	}

	/// Retires a round that went out of the chain and cannot return while
	/// another transaction that took one of its inputs stands
	/// ([`Store::retire_round`]): its unspent new leaves are lost, and its
	/// participations run again as ordinary ones. Every forfeit in the
	/// watcher's log of a coin they gave up names this round or an earlier
	/// one that went out of the chain: the nursery gives each up, never to
	/// broadcast it again while its round is out, and the wallet's coins of
	/// one not in the chain are freed. A participation with a coin
	/// [`Self::barred`], or whose re-run no coin of the operator's can keep
	/// apart from a round it was in ([`Self::tie_coins`]), is voided, saying
	/// why.
	async fn retire(&self, r: &RoundRow) -> Result<(), RoundError> {
		let mut again = self.store.retire_round(r.round_id).await?;
		// A step of an offline-refresh plan runs only under the leaf its plan
		// names: it is not run again, and its coin is its holder's.
		let voided = crate::plans::void_rerun(&self.store, &again, &Txid::from_byte_array(r.txid)).await?;
		again.retain(|id| !voided.contains(id));
		let never = self.rerun(r.round_id, &again).await?;
		log::warn!("round {} ({}) is out of the chain and another transaction that took one of its inputs is final: retired; \
			{} participation(s) run again, {} never taken", r.round_id, Txid::from_byte_array(r.txid), again.len() - never, never);
		Ok(())
	}

	/// Each participation of `again`, run again after the round `round_id`
	/// went out of the chain: every forfeit of a coin it gave up in the
	/// watcher's log given up, and the participation voided, saying why, when
	/// a coin of it is [`Self::barred`] or no coin of the operator's can keep
	/// its re-run apart from a lost round it was in. Returns how many were
	/// voided.
	async fn rerun(&self, round_id: i64, again: &[[u8; 32]]) -> Result<usize, RoundError> {
		let mut never = 0;
		let mut ties: BTreeMap<i64, bool> = BTreeMap::new();
		for id in again {
			for (txid, leaf) in self.store.logged_forfeits_of(id).await? {
				let t = Txid::from_byte_array(txid);
				let in_chain = self.finality.status(&t).await.map_err(|e| RoundError::Chain(e.to_string()))?.in_chain();
				self.store.nursery_set_state(&txid, NurseryState::Lost).await?;
				if !in_chain {
					self.wallet.release(&t).await?;
				}
				log::warn!("round {}: the forfeit {} of coin {} names a round out of the chain; it is not broadcast again while that \
					round is out", round_id, t, LeafId(leaf));
			}
			let Some(p) = self.store.participation(id).await? else { continue };
			let mut why = match self.paid_on(id).await? { Some(w) => Some(w), None => self.barred(&p).await? };
			if why.is_none() {
				for l in self.lost_rounds(id).await? {
					if !ties.contains_key(&l) {
						let round = self.store.round(l).await?.ok_or_else(|| RoundError::Internal(format!("round {} is not recorded", l)))?;
						let coins = self.tie_coins(&round).await?;
						ties.insert(l, !coins.now.is_empty() || coins.later);
					}
					if !ties[&l] {
						let round = self.store.round(l).await?.ok_or_else(|| RoundError::Internal(format!("round {} is not recorded", l)))?;
						why = Some(no_tie(&Txid::from_byte_array(round.txid)));
						break;
					}
				}
			}
			if let Some(why) = why {
				if self.store.void_participation(id, &why).await? {
					never += 1;
				}
				log::warn!("participation {} is never taken again: {}", crate::signer::hex(id), why);
			}
		}
		Ok(never)
	}

	/// Restores the round `r`, held as lost, which is final in the chain
	/// again ([`Store::restore_round`]): every round that ran its
	/// participations again and is not in the chain can now never confirm
	/// beside it, and is retired with it; each participation it ran is back
	/// as it stood in it, its leaves credited, its forfeits for it good
	/// again; what a retired round ran that was never in this one runs again
	/// as after any lost round. A round that ran its participations again and
	/// is in the chain too stays, and its participations with it.
	async fn restore(&self, r: &RoundRow) -> Result<(), RoundError> {
		let txid = Txid::from_byte_array(r.txid);
		let mut candidates: BTreeSet<i64> = self.store.reruns_of(r.round_id).await?.into_iter().collect();
		for (_, now_in) in self.store.earlier_in(r.round_id).await? {
			candidates.extend(now_in.filter(|c| *c != r.round_id));
		}
		let mut retire = vec![];
		for y in candidates {
			let Some(row) = self.store.round(y).await? else { continue };
			if row.state == RoundState::Lost {
				continue;
			}
			let yt = Txid::from_byte_array(row.txid);
			if self.finality.status(&yt).await.map_err(|e| RoundError::Chain(e.to_string()))?.in_chain() {
				log::error!("round {} ({}) ran participations of round {} ({}) again, and both are in the chain: each participation \
					stays in the round it is in now", y, yt, r.round_id, txid);
				continue;
			}
			retire.push(y);
		}
		// A participation one of whose coins' salts holds another message the
		// signer co-signed (a re-run's forfeit) can never be given its
		// forfeit for this round; one whose coin was spent on the chain
		// otherwise than by its forfeit for the round is its owner's again.
		// The leaves of the round of either are never credited.
		let mut uncredited = self.cosigned_elsewhere(r).await?;
		for (p, why) in self.spent_otherwise(r.round_id).await? {
			if !uncredited.iter().any(|(q, _)| *q == p) {
				uncredited.push((p, why));
			}
		}
		let now = self.now().await?.to_consensus_u32();
		let Some(done) = self.store.restore_round(r.round_id, &retire, now, &uncredited).await? else { return Ok(()) };
		for y in &done.retired {
			if let Some(row) = self.store.round(*y).await? {
				self.store.nursery_set_state(&row.txid, NurseryState::Lost).await?;
				self.wallet.release(&Txid::from_byte_array(row.txid)).await?;
				log::warn!("round {} ({}) can never confirm beside round {} ({}), which is final again: retired", y,
					Txid::from_byte_array(row.txid), r.round_id, txid);
			}
		}
		for (id, why) in &done.left {
			log::warn!("participation {} is not brought back to round {}: {}", crate::signer::hex(id), r.round_id, why);
		}
		if !uncredited.is_empty() {
			log::error!("round {} ({}) is final again with {} participation(s) whose new leaves are their owners' to take on the chain \
				while the coins they gave up went otherwise: the operator's loss, one coin each", r.round_id, txid, uncredited.len());
		}
		let never = self.rerun(r.round_id, &done.rerun).await?;
		log::warn!("round {} ({}) is final again: restored; {} participation(s) back as they stood in it, {} leaf/leaves credited, \
			{} coin(s) paid out of its leaves live again, {} round(s) retired, {} participation(s) of those run again, {} never taken",
			r.round_id, txid, done.restored.len(), done.credited, done.revived, done.retired.len(), done.rerun.len() - never, never);
		Ok(())
	}

	/// The participations of round `round_id`, final in the chain again, one
	/// of whose coins was spent on the chain otherwise than by its forfeit for
	/// that round, and why: that forfeit refunded while the round was out;
	/// or the coin's last output on the chain (its board output, or a leaf
	/// output of its script the chain shows) spent, in a block or a mempool,
	/// by anything but its forfeit for the round (its owner's exit, another
	/// round's forfeit that came back with the reorganisation). Their leaves
	/// of the round are never credited: their owners hold the records, so the
	/// leaves are theirs to take on the chain, and the loss is the operator's.
	/// The participations of round `r`, final in the chain again, one of
	/// whose coins' salts holds a message the signer co-signed other than
	/// its forfeit for `r` (a forfeit for a round that ran it again while `r`
	/// was out), each with why it is not brought back. The signer co-signs
	/// one message under a salt, ever, so that coin's forfeit for `r` can
	/// never be signed: the participation's new leaves of `r` are never
	/// credited and no preimage of them goes out, and the coin is its owner's
	/// on the chain, by its exit or by that other forfeit's refund.
	async fn cosigned_elsewhere(&self, r: &RoundRow) -> Result<Vec<([u8; 32], String)>, RoundError> {
		let m = arca_covenant::connector_asset(Txid::from_byte_array(r.txid), r.connector_vout).into_inner().to_byte_array();
		let mut out = vec![];
		'participation: for (pid, _) in self.store.earlier_in(r.round_id).await? {
			let Some(p) = self.store.participation(&pid).await? else { continue };
			for i in &p.inputs {
				let Some(salt) = self.store.salt_of_leaf(&i.leaf_id).await? else { continue };
				let held = self.signer.under(&salt).await.map_err(|e| RoundError::Internal(format!("the signer's record: {}", e)))?;
				if let Some(e) = held.iter().find(|e| !matches!(e.kind, crate::signer::Signed::Forfeit(c) if c == m)) {
					out.push((pid, format!("coin {} it gave up is under {} {} the signer co-signed (entry {}) while round {} was out of the \
						chain, and the signer co-signs one message under a salt, ever: its forfeit for round {} can never be signed, so its \
						new leaves of the round are never credited and their preimage never goes out; the coin is its owner's on the chain, \
						by its exit or by that forfeit's refund", LeafId(i.leaf_id),
						match e.kind { crate::signer::Signed::Spend => "a spend", crate::signer::Signed::Forfeit(_) => "a forfeit" },
						crate::signer::hex(&e.digest), e.n, r.round_id, r.round_id)));
					continue 'participation;
				}
			}
		}
		Ok(out)
	}

	async fn spent_otherwise(&self, round_id: i64) -> Result<Vec<([u8; 32], String)>, RoundError> {
		let chain = |e: crate::chain::ChainError| RoundError::Chain(e.to_string());
		let forfeits = self.store.forfeits_naming(round_id).await?;
		let mempool: std::collections::HashSet<Txid> = self.finality.call(|c| c.mempool()).await.map_err(chain)?.into_iter().collect();
		let mut out: Vec<([u8; 32], String)> = vec![];
		let owners = "its new leaves of the round are never credited: they are its owner's to take on the chain, who holds their \
			records, and the loss is the operator's";
		// A forfeit for the round refunded while the round was out.
		for (f, leaf) in &forfeits {
			let at = OutPoint::new(Txid::from_byte_array(*f), 0);
			if !self.finality.status(&at.txid).await.map_err(|e| RoundError::Chain(e.to_string()))?.in_chain() {
				continue;
			}
			let unspent = self.finality.call(move |c| c.unspent(&at, true)).await.map_err(chain)?.is_some();
			if unspent || self.store.watcher_spend(f, 0).await?.is_some() {
				continue;
			}
			if let Some(p) = self.store.forfeit_participation(leaf, round_id).await? {
				if !out.iter().any(|(q, _)| *q == p) {
					out.push((p, format!("its forfeit {} for round {} of coin {} it gave up was refunded on the chain while that round was out \
						of it: {}", at.txid, round_id, LeafId(*leaf), owners)));
				}
			}
		}
		// A coin whose last output on the chain went otherwise.
		for (pid, _) in self.store.earlier_in(round_id).await? {
			if out.iter().any(|(q, _)| *q == pid) {
				continue;
			}
			let Some(p) = self.store.participation(&pid).await? else { continue };
			for i in &p.inputs {
				let mine: Vec<Txid> = forfeits.iter().filter(|(_, l)| *l == i.leaf_id).map(|(f, _)| Txid::from_byte_array(*f)).collect();
				if let Some(how) = self.taken_otherwise(&i.leaf_id, &mine, &mempool).await? {
					out.push((pid, format!("coin {} it gave up was spent on the chain {}, otherwise than by its forfeit for round {}, while \
						that round was out of it: {}", LeafId(i.leaf_id), how, round_id, owners)));
					break;
				}
			}
		}
		Ok(out)
	}

	/// How the coin `leaf_id` was spent on the chain otherwise than by one of
	/// `forfeits` (its forfeits for a round): its board output, or every
	/// leaf output of its script the chain shows, spent in a block or a
	/// mempool, and none of `forfeits` in a block or in `mempool`. `None`
	/// while any of those outputs is unspent (the coin is still to be
	/// claimed, or exited, a conversion or an unroll on its way included), or
	/// the chain shows none of them (it is still off the chain).
	async fn taken_otherwise(&self, leaf_id: &[u8; 32], forfeits: &[Txid], mempool: &std::collections::HashSet<Txid>)
		-> Result<Option<String>, RoundError>
	{
		let chain = |e: crate::chain::ChainError| RoundError::Chain(e.to_string());
		let Some(row) = self.store.leaf(leaf_id).await? else { return Ok(None) };
		// Its board output and the leaf its conversion makes, for a board;
		// every output of its script the chain shows, for a leaf.
		let mut outs: Vec<OutPoint> = vec![];
		let mut scripts = vec![row.script_pubkey.clone()];
		if row.kind == LeafKind::Board {
			if let Some(b) = self.store.board(leaf_id).await? {
				outs.push(OutPoint::new(Txid::from_byte_array(b.txid), b.vout));
				if let Ok(record) = arca_covenant::BoardRecord::from_bytes(&b.record) {
					scripts.push(record.policy().leaf.script_pubkey().to_bytes());
				}
			}
		}
		for s in &scripts {
			outs.extend(self.store.sightings_of(s).await?.into_iter().map(|(t, v)| OutPoint::new(Txid::from_byte_array(t), v)));
		}
		// The last of them the chain shows spent, and what spent it when the
		// server saw that.
		let mut last: Option<(OutPoint, Option<Txid>)> = None;
		for op in outs {
			let txid = op.txid;
			let exists = mempool.contains(&txid) || self.finality.call(move |c| c.tx_block(&txid)).await.map_err(chain)?.is_some();
			if !exists {
				continue;
			}
			if self.finality.call(move |c| c.unspent(&op, true)).await.map_err(chain)?.is_some() {
				return Ok(None);
			}
			let by = self.store.outpoint_spender(&op.txid.to_byte_array(), op.vout).await?.map(Txid::from_byte_array);
			last = Some((op, by));
		}
		let Some((op, spent_by)) = last else { return Ok(None) };
		for f in forfeits {
			let f = *f;
			if mempool.contains(&f) || self.finality.call(move |c| c.tx_block(&f)).await.map_err(chain)?.is_some() {
				return Ok(None);
			}
		}
		let what = match spent_by {
			Some(t) => match self.store.forfeit_round_id(&t.to_byte_array()).await? {
				Some(n) => format!("(its output {}:{}) by {}, a forfeit for round {}", op.txid, op.vout, t, n),
				None => format!("(its output {}:{}) by {}", op.txid, op.vout, t),
			},
			None => format!("(its output {}:{})", op.txid, op.vout),
		};
		Ok(Some(what))
	}

	/// Why the participation `id`, run again after a lost round, is not run
	/// again when its new leaf of a lost round was spent before the round was
	/// lost: paid on out of round, or given up in another participation. What
	/// that spend made rests on the round, and is lost while the round is out;
	/// a second leaf would leave its owner what it spent.
	async fn paid_on(&self, id: &[u8; 32]) -> Result<Option<String>, RoundError> {
		let Some((leaf, round, by)) = self.store.spent_leaf_of_lost_round(id).await? else { return Ok(None) };
		let how = if self.store.transfer(&by).await?.is_some() {
			format!("paid on out of round (transfer {})", crate::signer::hex(&by))
		} else {
			format!("given up in participation {}", crate::signer::hex(&by))
		};
		Ok(Some(format!("its new leaf {} of round {}, which went out of the chain, was {} before the round was lost: what that \
			spend made rests on the round, and is lost while the round is out of the chain. The participation is not run again, since \
			a second leaf would leave its owner what it spent; its coins are its owner's on the chain, and if the round returns the \
			participation is restored as it stood in it, and what the spend made with it", LeafId(leaf), Txid::from_byte_array(round), how)))
	}

	/// Why the participation `p`, run again after a round that could not
	/// return, is never taken: a coin it gave up with a forfeit in the
	/// watcher's log (one for an earlier round of it, which may still
	/// confirm, and is its owner's to refund once its delay has run), or
	/// whose output the server has seen spent on the chain. `None` when it
	/// runs as an ordinary participation.
	async fn barred(&self, p: &ParticipationRow) -> Result<Option<String>, RoundError> {
		for i in &p.inputs {
			let id = LeafId(i.leaf_id);
			if let Some(w) = self.store.watcher_txs("forfeit", &i.leaf_id).await?.first() {
				return Ok(Some(format!("coin {} has a forfeit for an earlier round of this participation, which went out of the \
					chain, in the operator's log ({}): that forfeit may confirm, and is its owner's to refund once its refund delay has \
					run while that round is out; the coin is not taken into a round again, and if the round returns the participation \
					is restored as it stood in it", id, Txid::from_byte_array(w.txid))));
			}
			if let Some(at) = self.spent_on_chain(&i.leaf_id).await? {
				return Ok(Some(format!("coin {}'s output {} is spent on the chain: the coin is not taken into a round again", id, at)));
			}
			// S signs one message under a salt, ever: a forfeit it signed for
			// a round that went out of the chain is that message, and a
			// forfeit for this re-run would be a second, which burns the
			// operator's bond whoever holds the two.
			if let Some(salt) = self.store.salt_of_leaf(&i.leaf_id).await? {
				let held = self.signer.under(&salt).await.map_err(|e| RoundError::Internal(format!("the signer's record: {}", e)))?;
				if let Some(e) = held.first() {
					return Ok(Some(format!("coin {}: the operator's signer has co-signed {} {} under its salt (entry {}), and co-signs \
						one message under a salt, ever: the coin is not given up again in a re-run; its owner's way home is its exit, \
						and if the round returns the participation is restored as it stood in it", id,
						match e.kind { crate::signer::Signed::Spend => "a spend", crate::signer::Signed::Forfeit(_) => "a forfeit" },
						crate::signer::hex(&e.digest), e.n)));
				}
			}
		}
		Ok(None)
	}

	/// The output of the coin `leaf_id` (its board output, for a board; its
	/// leaf, wherever the chain shows it) when the server has seen it spent
	/// on the chain.
	async fn spent_on_chain(&self, leaf_id: &[u8; 32]) -> Result<Option<OutPoint>, RoundError> {
		let Some(row) = self.store.leaf(leaf_id).await? else { return Ok(None) };
		let outs: Vec<OutPoint> = if row.kind == LeafKind::Board {
			match self.store.board(leaf_id).await? {
				Some(b) => vec![OutPoint::new(Txid::from_byte_array(b.txid), b.vout)],
				None => vec![],
			}
		} else {
			self.store.sightings_of(&row.script_pubkey).await?.into_iter().map(|(t, v)| OutPoint::new(Txid::from_byte_array(t), v)).collect()
		};
		for op in outs {
			if self.store.outpoint_spender(&op.txid.to_byte_array(), op.vout).await?.is_some() {
				return Ok(Some(op));
			}
			let in_chain = self.finality.status(&op.txid).await.map_err(|e| RoundError::Chain(e.to_string()))?.in_chain();
			let unspent = self.finality.call(move |c| c.unspent(&op, true)).await.map_err(|e| RoundError::Chain(e.to_string()))?;
			if in_chain && unspent.is_none() {
				return Ok(Some(op));
			}
		}
		Ok(None)
	}

	/// A round that was final and no longer is: back to broadcast, its live
	/// new leaves uncredited until it is final again.
	async fn unfinal(&self, round_id: i64, txid: &Txid) -> Result<(), RoundError> {
		if self.store.set_round_state(round_id, RoundState::Final, RoundState::Broadcast).await? {
			let n = self.store.uncredit_round(round_id).await?;
			log::warn!("round {} ({}) is no longer final: {} leaf/leaves uncredited", round_id, txid, n);
		}
		Ok(())
	}

	/// Handles a change to the chain: a disconnection that takes a round out
	/// uncredits its leaves at once (the nursery broadcasts it again).
	pub async fn on_chain_event(&self, event: &ChainEvent) -> Result<(), RoundError> {
		if let ChainEvent::Disconnected { watched, .. } = event {
			for (txid, kind) in watched {
				if kind != NurseryKind::Round.as_str() {
					continue;
				}
				if let Some(r) = self.store.round_by_txid(&txid.to_byte_array()).await? {
					self.unfinal(r.round_id, txid).await?;
				}
			}
		}
		Ok(())
	}

	/// Follows one round's finality.
	async fn check_round(&self, r: &RoundRow) -> Result<(), RoundError> {
		let txid = Txid::from_byte_array(r.txid);
		let fin = self.finality.status(&txid).await.map_err(|e| RoundError::Chain(e.to_string()))?;
		match (r.state, fin.is_final()) {
			(RoundState::Broadcast, true) if self.store.mark_round_final(r.round_id, self.now().await?.to_consensus_u32()).await? => {
				let credited = self.store.credit_round(r.round_id).await?;
				log::info!("round {} ({}) is final; {} leaf/leaves credited", r.round_id, txid, credited);
			},
			(RoundState::Final, false) => self.unfinal(r.round_id, &txid).await?,
			_ => {},
		}
		Ok(())
	}

	/// The published tree of the batch paid by output `vout` of the round
	/// whose transaction is `txid`.
	pub async fn tree(&self, txid: &Txid, vout: u32) -> Result<Option<PublishedTree>, RoundError> {
		let (b, leaves) = match self.store.batch(&txid.to_byte_array(), vout).await? {
			Some(x) => x,
			None => return Ok(None),
		};
		let round = self.store.round(b.round_id).await?.ok_or_else(|| RoundError::Internal("a batch without its round".into()))?;
		let schedule = ClockSchedule::decode(&b.schedule).map_err(|e| RoundError::Internal(e.to_string()))?;
		let params = TreeParams {
			asset: AssetId::from_byte_array(b.asset),
			chain: self.params.chain,
			schedule,
			burn: b.burn, delegated_reclaim: b.delegated_reclaim,
			radix: b.radix as usize,
			reserve: match b.reserve {
				StoredReserve::FeeRate { floor_per_kvb, multiple } => ReserveRule::FeeRate { floor_per_kvb, multiple },
				StoredReserve::Fixed { node, entry } => ReserveRule::Fixed { node, entry },
			},
			min_leaf: b.min_leaf,
		};
		let mut specs = Vec::with_capacity(leaves.len());
		for l in &leaves {
			// An htlc-1, order-2, landing-1 or channel-1 leaf's terms, from the
			// record the builder gave it: a tree leaf record, or an
			// accumulator record (which carries no channel).
			let (htlc, order, landing, channel) = match b.kind {
				BatchKind::Tree => {
					let r = arca_covenant::LeafRecord::from_bytes(&l.record).map_err(|e| RoundError::Internal(e.to_string()))?;
					(r.htlc, r.order, r.landing, r.channel)
				},
				BatchKind::Accumulator => {
					let r = AccumulatorRecord::from_bytes(&l.record).map_err(|e| RoundError::Internal(e.to_string()))?;
					(r.htlc, r.order, r.landing, None)
				},
			};
			specs.push(LeafSpec {
				template: l.template.parse::<Template>().map_err(|e| RoundError::Internal(e.to_string()))?,
				owner: elements::secp256k1_zkp::XOnlyPublicKey::from_slice(&l.owner_key).map_err(|e| RoundError::Internal(e.to_string()))?,
				value: l.value,
				owner_nonce: l.owner_nonce,
				operator_nonce: l.operator_nonce,
				exit_delay: RelativeTime::from_units(l.exit_delay_units).map_err(|e| RoundError::Internal(e.to_string()))?,
				unlock_hash: l.unlock_hash,
				htlc,
				order,
				landing,
				channel,
			});
		}
		let signer_head = self.store.round_signer_head(b.round_id).await?;
		let preimages = self.store.released_preimages(b.round_id, b.vout).await?;
		Ok(Some(PublishedTree {
			round_txid: *txid, batch_vout: b.vout, token_vout: b.token_vout, connector_vout: round.connector_vout, kind: b.kind, params,
			leaves: specs, signer_head, round_state: round.state, preimages,
		}))
	}

	/// Follows the finality service's events, and builds a round every
	/// `interval` when one is given, until the task is dropped.
	pub fn spawn(self: &Arc<Self>, interval: Option<Duration>) -> tokio::task::JoinHandle<()> {
		let me = self.clone();
		let mut rx = self.finality.subscribe();
		tokio::spawn(async move {
			let mut tick = interval.map(tokio::time::interval);
			loop {
				let r = tokio::select! {
					e = rx.recv() => match e {
						Ok(ChainEvent::Synced { .. }) | Err(broadcast::error::RecvError::Lagged(_)) => me.pass().await,
						Ok(e @ ChainEvent::Disconnected { .. }) => me.on_chain_event(&e).await,
						Ok(_) => Ok(()),
						Err(broadcast::error::RecvError::Closed) => return,
					},
					_ = async { match tick.as_mut() { Some(t) => { t.tick().await; }, None => std::future::pending::<()>().await } } => {
						match me.run_rounds().await {
							Ok(_) => me.pass().await,
							Err(e) => Err(e),
						}
					},
				};
				if let Err(e) = r {
					log::warn!("rounds: {}", e);
				}
			}
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_holder_that_moves_soon_has_a_batch_of_its_own() {
		let a = AssetId::from_slice(&[1; 32]).unwrap();
		let b = AssetId::from_slice(&[2; 32]).unwrap();
		let (m, n) = (Some([7u8; 32]), Some([8u8; 32]));
		// A maker's four leaves over two participations, a smaller holder's
		// one, two leaves of nobody's, and one of another asset.
		let leaves = vec![(a, None, 10, 0, 0), (a, m, 100, 1, 0), (a, m, 100, 1, 1), (a, n, 5, 2, 0), (a, m, 100, 3, 0),
			(a, m, 100, 3, 1), (a, None, 10, 4, 0), (b, m, 50, 5, 0)];
		let p = plan_batches(&leaves, 8);
		let shape: Vec<(AssetId, bool, Vec<(usize, usize)>)> = p.iter().map(|b| (b.asset, b.own, b.leaves.clone())).collect();
		assert_eq!(shape, vec![
			(a, true, vec![(1, 0), (1, 1), (3, 0), (3, 1)]),
			(a, true, vec![(2, 0)]),
			(a, false, vec![(0, 0), (4, 0)]),
			(b, true, vec![(5, 0)]),
		]);
		// One batch of its own a round: the holder with the most value.
		let p = plan_batches(&leaves, 1);
		assert_eq!(p.iter().filter(|b| b.own).count(), 2, "the maker's, in both its assets");
		assert_eq!(p.iter().find(|b| b.asset == a && !b.own).unwrap().leaves, vec![(0, 0), (2, 0), (4, 0)]);
		// None: one batch an asset, every leaf in it, a holder's side by side.
		let p = plan_batches(&leaves, 0);
		assert_eq!(p.len(), 2);
		assert_eq!(p[0].leaves, vec![(0, 0), (1, 0), (1, 1), (3, 0), (3, 1), (2, 0), (4, 0)]);
	}

	fn order() -> FillOrder {
		let key = |b: u8| {
			let sk = elements::secp256k1_zkp::SecretKey::from_slice(&[b; 32]).unwrap();
			elements::secp256k1_zkp::Keypair::from_secret_key(elements::secp256k1_zkp::SECP256K1, &sk).x_only_public_key().0.serialize()
		};
		FillOrder {
			asset_a: AssetId::from_byte_array([1; 32]), asset_b: AssetId::from_byte_array([2; 32]), rate_num: 3, rate_den: 2,
			min_lot: 10_000, maker_prog: key(3), expiry_locktime: 1_800_000_000, maker_x: key(4),
		}
	}

	fn take(n: u8, at: OutPoint, terms: &FillOrder, locked: u64, filled: u64, shared: bool) -> ParticipationRow {
		ParticipationRow {
			id: [n; 32], unlock_hash: [0; 32], preimage: [0; 32], attempt: 0, round_id: None, state: ParticipationState::Pending,
			not_before: None, refund_delay_units: 1, inputs: vec![], outputs: vec![], fees: vec![], waiting: None, void_reason: None,
			fill: Some(FillRow {
				order_txid: at.txid.to_byte_array(), order_vout: at.vout, terms: terms.to_relay(&at).to_string(),
				script_pubkey: terms.script_pubkey().to_bytes(), locked, filled, price: terms.price(filled).unwrap(), shared,
			}),
		}
	}

	/// Ten takes of one order and one of another: one fill each order, at
	/// the input of its first take; the shared order's fill is the sum of its
	/// takes and its credit the order's price of that sum, rounded up once.
	#[test]
	fn takes_of_one_order_are_one_fill_of_their_sum() {
		let t = order();
		let sale = OutPoint::new(Txid::from_byte_array([7; 32]), 0);
		let other = OutPoint::new(Txid::from_byte_array([8; 32]), 1);
		let mut rows = vec![take(100, other, &t, 50_000, 50_000, true)];
		let shares: Vec<u64> = (0..10).map(|i| 100_001 + 10_000 * i).collect();
		for (i, f) in shares.iter().enumerate() {
			rows.push(take(i as u8, sale, &t, 2_000_000, *f, true));
		}
		let fills = Rounds::plan_fills(&rows).unwrap();
		assert_eq!(fills.len(), 2);
		assert_eq!((fills[0].order, fills[0].participations.clone()), (other, vec![0]));
		assert_eq!(fills[1].order, sale);
		assert_eq!(fills[1].participations, (1..=10).collect::<Vec<_>>());
		let sum: u64 = shares.iter().sum();
		assert_eq!((fills[1].plan.filled, fills[1].plan.remainder), (sum, 2_000_000 - sum));
		let own: u64 = shares.iter().map(|f| t.price(*f).unwrap()).sum();
		assert_eq!(fills[1].plan.credit.value, t.price(sum).unwrap());
		// Each odd share's own price rounds up half an atom; the sum's once.
		assert_eq!(own - fills[1].plan.credit.value, 5, "the takes pay {}, the maker is credited {}", own, fills[1].plan.credit.value);
	}

	/// The round builder's rules for a take of an order another chosen take
	/// fills: below the minimum lot, void; beside a take that takes it alone,
	/// or past what the FILL leaf lets one round take, a later round.
	#[test]
	fn the_round_builder_holds_each_share_to_the_order() {
		let t = order();
		let sale = OutPoint::new(Txid::from_byte_array([7; 32]), 0);
		let small = take(1, sale, &t, 2_000_000, 9_999, true);
		let why = Rounds::below_min_lot(&small).unwrap().expect("below the lot");
		assert!(why.contains("below the order's min_lot of 10000"), "{}", why);
		assert_eq!(Rounds::below_min_lot(&take(2, sale, &t, 2_000_000, 10_000, true)).unwrap(), None);

		let chosen = vec![take(3, sale, &t, 2_000_000, 1_000_000, true), take(4, sale, &t, 2_000_000, 900_000, true)];
		assert_eq!(Rounds::does_not_fit(&chosen, &take(5, sale, &t, 2_000_000, 100_000, true)).unwrap(), None, "fills it whole");
		let why = Rounds::does_not_fit(&chosen, &take(6, sale, &t, 2_000_000, 95_000, true)).unwrap().expect("leaves 5000");
		assert!(why.contains("below the order's min_lot of 10000"), "{}", why);
		let why = Rounds::does_not_fit(&chosen, &take(7, sale, &t, 2_000_000, 200_000, true)).unwrap().expect("more than it holds");
		assert!(why.contains("later round"), "{}", why);
		let why = Rounds::does_not_fit(&chosen, &take(8, sale, &t, 2_000_000, 50_000, false)).unwrap().expect("takes it alone");
		assert!(why.contains("takes it alone"), "{}", why);
		let alone = vec![take(9, sale, &t, 2_000_000, 50_000, false)];
		assert!(Rounds::does_not_fit(&alone, &take(10, sale, &t, 2_000_000, 50_000, true)).unwrap().is_some());
		let other = OutPoint::new(Txid::from_byte_array([8; 32]), 0);
		assert_eq!(Rounds::does_not_fit(&alone, &take(11, other, &t, 2_000_000, 50_000, false)).unwrap(), None, "another order");
	}
}
