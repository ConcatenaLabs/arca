//! The watcher: everything the operator does on the chain after a round.
//!
//! A round leaves the operator holding signatures and rights it must use on
//! the chain, and a holder who breaks its word must be answered there within
//! a delay. The watcher acts on each pass in the order of the deadlines
//! (answers to stale exits, then claims, then new forfeits and the rest), and
//! never builds a second spend of an outpoint while a spend of its own is in
//! the nursery and not lost:
//!
//! 1. **Stale exits.** A coin the server holds as given up (by a
//!    participation whose forfeit it stored, or by a co-signed transfer) whose
//!    leaf is seen on the chain unspent, in a block or the mempool, is
//!    answered at once: by its forfeit for the round its participation is in
//!    now (never one for a lost round), or by its
//!    checkpoint; and a
//!    reassignment is published once every checkpoint it spends is on the
//!    chain. The answer confirms before the leaf's exit delay runs out, so
//!    the leaf's owner can no longer exit it. A board given up and then
//!    converted is the same case: its leaf appears. A resting order's coin
//!    that a co-signed fill spent ([`crate::orders`]) is answered by the
//!    fill: each taker's coin is brought on and checkpointed, then the fill
//!    spends the order's coin by its fill path before its landing delay
//!    runs out, so its maker cannot land it.
//! 2. **Boards given up in a round.** Once the round is final, the forfeit of
//!    a board is published from the board output: no batch sweeps a board, so
//!    this is how its value comes back to the operator. Every forfeit's
//!    refund clock starts when it confirms, so these go out no faster than
//!    they can be claimed: a new one is published only while the watcher's
//!    own transactions waiting for a block stay within `block_share_vbytes`,
//!    and only if its claim can follow within its refund delay. A coin of a
//!    transfer given up in a round whose lineage rests on boards alone is
//!    swept by no batch either: the watcher publishes each board's
//!    checkpoint, and 1 carries it through each reassignment to the coin's
//!    forfeit. That lineage is shared with every coin its reassignments
//!    made, so it is published at once only when none of those is a coin
//!    another holder may still hold; otherwise not before the latest board
//!    service expiry among them ([`Params::BOARD_LIFETIME`]).
//! 3. **Claims.** The forfeits the watcher published that are in a block are
//!    claimed, every one of a round in one transaction (up to
//!    `max_claim_inputs`), each with the preimage of its unlock hash, against
//!    one atom of the round's connector asset `M`, which every claim names
//!    and which goes back to the wallet for the next. The atom is issued
//!    from the round's connector output when the first board forfeit of the
//!    round is published, so it is held by the time the forfeits confirm.
//! 4. **Offboards.** A released participation's offboard output is unlocked
//!    to its destination with the preimage, which the owner already holds. One
//!    whose participation expired or was voided (its preimage never went out)
//!    is reclaimed once its reclaim delay has passed since it confirmed. An
//!    offboard whose preimage went out is never reclaimed.
//! 5. **Expiry.** At the expiry `E` of the clock that holds a batch's token,
//!    the release moves the token to `R`; once it has waited the notice `W`
//!    there, each sweep takes every unspent output of the batch whose own
//!    notice has passed (the batch output, a node or entry someone unrolled, a
//!    checkpoint of a coin from the batch) and returns the token to `R`.
//!    Once the token is at `R`, before any sweep, every live coin of the
//!    batch (a leaf of it, or a coin resting on one through transfers) that
//!    no participation is giving up is brought on the chain under its
//!    holder's key, one step a pass, paid from its path's reserves, as a
//!    watchtower brings a deposited coin (`unroll_at_release`); so a sweep
//!    takes only what no one could unroll.
//! 6. **Reclaim.** A lowest node every owner of which has released it is
//!    reclaimed with an atom of each `M` the releases name. With
//!    `reclaim_early`, a node all of whose lowest nodes are released is
//!    unrolled first, by a released owner's authorisation from the server's
//!    records, so a fully refreshed batch comes back before it expires; a
//!    node with an owner who has not released is never unrolled by the
//!    watcher.
//! 7. **Absent makers' orders.** A resting order whose coin is live at its
//!    exit deadline (three days before the earliest expiry in its lineage),
//!    its maker not back to refresh or take it home, is landed by the
//!    operator: the coin is brought on the chain (its path unrolled by the
//!    authorisations of its record, and, for a coin a fill made, the fills
//!    published as their stale exits are answered), and once it has waited
//!    its exit delay in a block, the landing moves it whole into SeqDEX's
//!    order for the same terms, the fee from a coin of the wallet's. The
//!    order then rests on the chain, its maker's to refund, and is not swept
//!    with its batch. A coin the signer holds a spend of (a fill, a cancel,
//!    a forfeit) is left alone.
//! 8. **Returns.** A claim leaf of a distribution that a final sweep took
//!    with no spend of it recorded (its holder never took it up) is paid back
//!    to the distribution's return script, with every other such leaf of the
//!    distribution, from the operator's own coins (`returns.rs`).
//!
//! A fee is paid from the value a transaction takes, or from the margin its
//! signers left, when the node accepts that asset for fees now (the fee the
//! transaction needs, the rest of a large margin back to the wallet);
//! otherwise by a coin of the wallet's: of the asset the transaction works in
//! (a batch's, for its token's release) when the node accepts it and the
//! wallet holds one, else in the first asset of the operator's `fee_assets`
//! the node accepts. No asset is assumed, the policy asset included. Every
//! transaction goes to the nursery, which broadcasts it again unchanged after
//! a rollback, however deep: an anchor-driven reorganisation that takes out a
//! round and the watcher's answers puts them back in the order they were
//! made, and the watcher answers again whatever does not return. A forfeit
//! naming a lost round is the exception: the log refuses one
//! ([`StoreError::RoundLost`]), and the nursery gives up every forfeit of the
//! round's coins when the round is retired ([`crate::rounds`]), so no path, a
//! restart included, publishes one while the round is lost. A lost round
//! that is final again is restored, and its forfeits are the operator's to
//! publish and claim again.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use elements::encode::{deserialize, serialize};
use elements::hashes::Hash;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::{AssetId, OutPoint, Script, Transaction, Txid};
use tokio::sync::{broadcast, Mutex};

use arca_covenant::encode::Encoding;
use arca_covenant::node::{connector_index, reclaim_items};
use arca_covenant::sign::{script_spend_sighash, verify_digest};
use arca_covenant::spend::{FeeSource, KeySpend, Rebindable};
use arca_covenant::accumulator::{read_exit, Accumulator, AccumulatorParams, AccumulatorPolicy, ExitAuth};
use arca_covenant::tree::Tree;
use arca_covenant::{
	connector_asset, sweep_tx, ClaimTx, Clock, ClockSchedule, CoinRecord, ConnectorPolicy, ExplicitOutput, Forfeit, LeafId, MedianTime,
	OffboardPolicy, Pair, RelativeTime, Sweepable, TokenPlace, ValidCoin, ValidOrigin, WalletPolicy,
};
use sequentia_ext::AssetAmount;

use crate::chain::{ChainEvent, FinalityService};
use crate::coins;
use crate::fees;
use crate::nursery::Nursery;
use crate::params::Params;
use crate::rounds::Rounds;
use crate::signer::{hex, SignerClient, SignerError};
use crate::store::{
	BoardState, ForfeitRow, LeafState, NewWatcherTx, ParticipationState, RoundRow, RoundState, ScriptKind, Store,
	StoreError, TreeScriptKind, WalletCoin, WantedKind,
};
use crate::wallet::{Wallet, WalletError};

#[path = "returns.rs"]
mod returns;
#[path = "swept.rs"]
mod swept;

/// How the watcher works.
#[derive(Debug, Clone)]
pub struct WatcherConfig {
	/// Unroll a subtree whose every owner has released it and reclaim its
	/// lowest nodes before the batch expires.
	pub reclaim_early: bool,
	/// The most outputs one sweep takes.
	pub max_sweep_inputs: usize,
	/// How often the recovery steps (claims of boards, offboards, expiry,
	/// reclaims) run when no block arrives; stale exits are answered on every
	/// pass of the finality service.
	pub recovery_interval: Duration,
	/// The most forfeits one claim takes.
	pub max_claim_inputs: usize,
	/// How many vbytes of the watcher's own transactions may wait for a
	/// block before it publishes no new forfeit of a board: the share of a
	/// block it takes, so every forfeit it publishes is claimed a block or two
	/// after it confirms.
	pub block_share_vbytes: u64,
	/// The chain's block interval, to tell whether a forfeit published now
	/// can be claimed within its refund delay.
	pub block_interval: Duration,
	/// Whether every live coin of a released batch is brought on the chain
	/// under its holder's key before the sweep.
	pub unroll_at_release: bool,
}

impl Default for WatcherConfig {
	fn default() -> WatcherConfig {
		WatcherConfig {
			reclaim_early: true, max_sweep_inputs: 50, recovery_interval: Duration::from_secs(30),
			max_claim_inputs: 200, block_share_vbytes: 45_000, block_interval: Duration::from_secs(60), unroll_at_release: true,
		}
	}
}

/// What one more forfeit adds to its round's claim, in vbytes: a claim input
/// with its witness (the operator's signature, the preimage, `k`, the claim
/// script and its control block), measured at about 130 (`tests/claims.rs`).
pub const CLAIM_INPUT_VSIZE: u64 = 140;

/// A forfeit the watcher published, in a block, ready to be claimed.
struct Claimable {
	round_id: i64,
	forfeit: Forfeit,
	at: OutPoint,
	preimage: [u8; 32],
}

/// Why the watcher could not act.
#[derive(Debug, thiserror::Error)]
pub enum WatcherError {
	#[error(transparent)]
	Store(#[from] StoreError),
	#[error("the chain: {0}")]
	Chain(String),
	#[error("the wallet: {0}")]
	Wallet(#[from] WalletError),
	#[error("the signer: {0}")]
	Signer(#[from] SignerError),
	#[error("the nursery: {0}")]
	Nursery(String),
	#[error("{0}")]
	Build(String),
	#[error("the server has not followed the chain yet")]
	NotSynced,
}

fn build<E: std::fmt::Display>(what: &str) -> impl Fn(E) -> WatcherError + '_ {
	move |e| WatcherError::Build(format!("{}: {}", what, e))
}

/// A signature of the right length for sizing a transaction before it is
/// signed.
fn dummy_sig() -> Signature {
	Signature::from_slice(&[1; 64]).expect("64 bytes")
}

/// The virtual size of `tx` once the wallet's inputs at `wallet_inputs`
/// carry a P2WPKH witness; every other input already carries its witness or
/// one of the same size.
fn sized(mut tx: Transaction, wallet_inputs: &[usize]) -> u64 {
	for i in wallet_inputs {
		tx.input[*i].witness.script_witness = vec![vec![0; 72], vec![0; 33]];
	}
	tx.vsize() as u64
}

/// A burn of `value` of `asset`.
fn crate_burn(asset: AssetId, value: u64) -> ExplicitOutput {
	arca_covenant::issuer::burn(asset, value)
}

/// `src`, a fee coin, as one that burns the margin it leaves.
fn burning(src: &FeeSource) -> FeeSource {
	match src {
		FeeSource::Coin { outpoint, coin, fee, change } => FeeSource::Burning { outpoint: *outpoint, coin: coin.clone(), fee: *fee, change: change.clone() },
		other => other.clone(),
	}
}

/// The input of `tx` that a fee coin from `fee` holds.
fn fee_input(tx: &Transaction, fee: &FeeSource) -> Option<usize> {
	match fee {
		FeeSource::Coin { outpoint, .. } | FeeSource::Burning { outpoint, .. } => tx.input.iter().position(|i| i.previous_output == *outpoint),
		FeeSource::Reserve | FeeSource::Split { .. } => None,
	}
}

fn txid_of(b: &[u8; 32]) -> Txid {
	Txid::from_byte_array(*b)
}

/// A transaction built, every input but the wallet's signed.
struct Ready {
	tx: Transaction,
	/// The wallet's inputs: their index and coin.
	wallet: Vec<(usize, WalletCoin)>,
	fee: Option<AssetAmount>,
}

/// What a spend that pays out the value it takes was built with.
struct Payout<T> {
	made: T,
	fee_coin: Option<WalletCoin>,
	fee: AssetAmount,
}

/// What the watcher's fee pool stood at after its last pass over the boards:
/// its metric. Forfeits whose claim a coin of the wallet's must pay (their
/// asset not accepted for fees) are published only while the pool covers
/// what is outstanding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeeStatus {
	/// Per fee asset: what the pool holds, and what the forfeits waiting for
	/// their claim, and those published this pass, take of it.
	pub pools: BTreeMap<AssetId, (u64, u64)>,
	/// Board forfeits held back for block space, and for the fee pool.
	pub held_for_space: usize,
	pub held_for_fees: usize,
}

impl FeeStatus {
	/// The metric in the text format Prometheus reads.
	pub fn metrics(&self) -> String {
		let mut out = String::new();
		out.push_str("# HELP arca_watcher_fee_pool What the watcher can pay fees with, in the asset's atoms.\n");
		out.push_str("# TYPE arca_watcher_fee_pool gauge\n");
		for (a, (pool, _)) in &self.pools {
			out.push_str(&format!("arca_watcher_fee_pool{{asset=\"{}\"}} {}\n", a, pool));
		}
		out.push_str("# HELP arca_watcher_fee_outstanding The fees the forfeits waiting for their claim will take, in the asset's atoms.\n");
		out.push_str("# TYPE arca_watcher_fee_outstanding gauge\n");
		for (a, (_, owed)) in &self.pools {
			out.push_str(&format!("arca_watcher_fee_outstanding{{asset=\"{}\"}} {}\n", a, owed));
		}
		out.push_str("# HELP arca_watcher_forfeits_held Board forfeits not published in the last pass, and why.\n");
		out.push_str("# TYPE arca_watcher_forfeits_held gauge\n");
		out.push_str(&format!("arca_watcher_forfeits_held{{reason=\"block_space\"}} {}\n", self.held_for_space));
		out.push_str(&format!("arca_watcher_forfeits_held{{reason=\"fee_pool\"}} {}\n", self.held_for_fees));
		out
	}
}

/// See the [module documentation](self).
pub struct Watcher {
	store: Store,
	finality: Arc<FinalityService>,
	params: Arc<Params>,
	wallet: Arc<Wallet>,
	nursery: Arc<Nursery>,
	signer: SignerClient,
	rounds: Arc<Rounds>,
	config: WatcherConfig,
	/// One pass at a time.
	running: Mutex<()>,
	/// Each batch's tree, rebuilt once from its published form.
	trees: Mutex<HashMap<(i64, u32), Arc<Tree>>>,
	/// Each accumulator batch, rebuilt once from its published form.
	accumulators: Mutex<HashMap<(i64, u32), Arc<Accumulator>>>,
	/// The wallet's script everything the watcher takes for the operator
	/// is paid to, handed out once: a step the node refuses, and takes again
	/// on a later pass, hands out no new script each time.
	pay_to: Mutex<Option<Script>>,
	status: std::sync::Mutex<FeeStatus>,
}

impl Watcher {
	#[allow(clippy::too_many_arguments)]
	pub fn new(store: Store, finality: Arc<FinalityService>, params: Arc<Params>, wallet: Arc<Wallet>, nursery: Arc<Nursery>,
		signer: SignerClient, rounds: Arc<Rounds>, config: WatcherConfig) -> Arc<Watcher>
	{
		Arc::new(Watcher {
			store, finality, params, wallet, nursery, signer, rounds, config,
			running: Mutex::new(()), trees: Mutex::new(HashMap::new()), accumulators: Mutex::new(HashMap::new()), pay_to: Mutex::new(None),
			status: std::sync::Mutex::new(FeeStatus::default()),
		})
	}

	/// The fee pool and what waits on it, after the last pass.
	pub fn fee_status(&self) -> FeeStatus {
		self.status.lock().unwrap_or_else(|e| e.into_inner()).clone()
	}

	pub fn config(&self) -> &WatcherConfig {
		&self.config
	}

	// -----------------------------------------------------------------------
	// Passes
	// -----------------------------------------------------------------------

	/// One whole pass, in the order of the deadlines: the stale exits (the
	/// exit delay), then the claims (the refund delay), then new forfeits
	/// and the rest, which have none.
	pub async fn pass(&self) -> Result<(), WatcherError> {
		self.answer_stale_channel_states().await?;
		let _one = self.running.lock().await;
		let now = self.now().await?;
		self.answer_stale_exits().await?;
		self.claim_paid_htlcs().await?;
		self.refund_unclaimed_receives(now).await?;
		self.claim_forfeits().await?;
		self.recover_boards(now).await?;
		self.recover_board_transfers(now).await?;
		self.answer_stale_exits().await?;
		self.offboards().await?;
		self.land_orders(now).await?;
		self.expiries(now).await?;
		self.reclaims(now).await?;
		self.returns().await?;
		self.owed().await?;
		Ok(())
	}

	/// The urgent part of a pass alone: the stale exits, and the claims.
	pub async fn urgent(&self) -> Result<(), WatcherError> {
		let _one = self.running.lock().await;
		self.answer_stale_exits().await?;
		self.claim_paid_htlcs().await?;
		self.claim_forfeits().await
	}

	/// Follows the finality service: the urgent part after each of its
	/// passes, and a whole pass after each new block and at least every
	/// `recovery_interval`, until the task is dropped.
	pub fn spawn(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
		let me = self.clone();
		let mut rx = self.finality.subscribe();
		tokio::spawn(async move {
			let mut last_whole = Instant::now() - me.config.recovery_interval;
			let mut block = false;
			loop {
				let r = match rx.recv().await {
					Ok(ChainEvent::Connected { .. }) | Ok(ChainEvent::Disconnected { .. }) => {
						block = true;
						Ok(())
					},
					Ok(ChainEvent::Synced { .. }) | Err(broadcast::error::RecvError::Lagged(_)) => {
						if block || last_whole.elapsed() >= me.config.recovery_interval {
							block = false;
							last_whole = Instant::now();
							me.pass().await
						} else {
							me.urgent().await
						}
					},
					Err(broadcast::error::RecvError::Closed) => return,
				};
				if let Err(e) = r {
					log::warn!("watcher: {}", e);
				}
			}
		})
	}

	// -----------------------------------------------------------------------
	// The chain, the fee, the signer, publishing
	// -----------------------------------------------------------------------

	async fn now(&self) -> Result<MedianTime, WatcherError> {
		let tip = self.store.tip_block().await?.ok_or(WatcherError::NotSynced)?;
		MedianTime::from_consensus(tip.median_time as u32).map_err(build("the tip's median time"))
	}

	/// Whether `op` is unspent, in the chain or the mempool: its
	/// confirmations.
	async fn unspent(&self, op: OutPoint) -> Result<Option<u64>, WatcherError> {
		self.finality.call(move |c| c.unspent(&op, true)).await.map_err(|e| WatcherError::Chain(e.to_string()))
	}

	/// Whether `op` is unspent in a block of the chain.
	async fn confirmed(&self, op: OutPoint) -> Result<bool, WatcherError> {
		Ok(self.unspent(op).await?.is_some_and(|c| c > 0))
	}

	/// Whether the watcher already has a spend of `op` in the nursery that is
	/// not lost.
	async fn spending(&self, op: &OutPoint) -> Result<bool, WatcherError> {
		Ok(self.store.watcher_spend(&op.txid.to_byte_array(), op.vout).await?.is_some())
	}

	/// Whether an output of `txid`, in a block, has waited `delay` since: the
	/// tip's median time is at least `delay` past that of the block before
	/// the one holding it (BIP68's time-based relative lock).
	async fn waited(&self, txid: Txid, delay: RelativeTime) -> Result<bool, WatcherError> {
		let at = self.finality.call(move |c| c.tx_block(&txid)).await.map_err(|e| WatcherError::Chain(e.to_string()))?;
		let b = match at {
			Some(b) => b,
			None => return Ok(false),
		};
		let h = self.finality.call(move |c| c.header(&b)).await.map_err(|e| WatcherError::Chain(e.to_string()))?;
		let base = match h.prev {
			Some(p) => self.finality.call(move |c| c.header(&p)).await.map_err(|e| WatcherError::Chain(e.to_string()))?.median_time,
			None => 0,
		};
		let tip = self.finality.call(|c| c.tip()).await.map_err(|e| WatcherError::Chain(e.to_string()))?;
		let tip_mtp = self.finality.call(move |c| c.header(&tip)).await.map_err(|e| WatcherError::Chain(e.to_string()))?.median_time;
		Ok(tip_mtp >= base + delay.seconds())
	}

	/// The wallet's script the watcher pays what it takes to.
	async fn to_wallet(&self) -> Result<Script, WatcherError> {
		let mut s = self.pay_to.lock().await;
		if let Some(script) = &*s {
			return Ok(script.clone());
		}
		let script = self.wallet.receive_script().await?;
		*s = Some(script.clone());
		Ok(script)
	}

	async fn accepted(&self, asset: AssetId) -> Result<Option<u64>, WatcherError> {
		fees::floor_per_kvb(&self.finality, asset).await.map_err(|e| WatcherError::Chain(e.to_string()))
	}

	/// The assets a wallet coin may pay a fee in: `prefer` first, then the
	/// operator's fee assets.
	fn fee_assets(&self, prefer: AssetId) -> Vec<AssetId> {
		let mut v = vec![prefer];
		v.extend(self.params.fee_assets().into_iter().filter(|a| *a != prefer));
		v
	}

	/// Whether the operator burns every unit of `asset` it takes in, and pays
	/// no fee in it: an issuer-operated asset ([`crate::issuer::burns`]).
	async fn burns(&self, asset: AssetId) -> Result<bool, WatcherError> {
		Ok(crate::issuer::burns(&self.params, &self.store, asset).await?)
	}

	/// The assets a wallet coin may pay a fee in for a transaction that takes
	/// in `asset`, which the operator burns: the operator's fee assets but
	/// `asset`.
	fn fee_assets_but(&self, asset: AssetId) -> Vec<AssetId> {
		self.params.fee_assets().into_iter().filter(|a| *a != asset).collect()
	}

	/// `S`'s signature over input `input` of `tx` by `leaf`, checked against
	/// the signature hash the server computes itself. Every caller has
	/// reserved the wallet coins `tx` spends, and publishes it only once it
	/// is signed: when the signer gives no good signature (it is stopped,
	/// say), those coins are given back. A transaction never published would
	/// otherwise hold them from every later transaction and round, and each
	/// pass would reserve more.
	async fn operator_sig(&self, tx: &Transaction, prevouts: &[elements::TxOut], input: usize, leaf: &Script)
		-> Result<Signature, WatcherError>
	{
		let signed = self.checked_operator_sig(tx, prevouts, input, leaf).await;
		if signed.is_err() {
			self.wallet.release(&tx.txid()).await?;
		}
		signed
	}

	async fn checked_operator_sig(&self, tx: &Transaction, prevouts: &[elements::TxOut], input: usize, leaf: &Script)
		-> Result<Signature, WatcherError>
	{
		let sig = self.signer.spend(tx, prevouts, input, leaf).await?;
		let digest = script_spend_sighash(tx, input, prevouts, leaf, self.params.chain.genesis_hash()).map_err(build("the signature hash"))?;
		if !verify_digest(&sig, &digest, &self.params.operator) {
			return Err(WatcherError::Build("the signer signed another signature hash than the server computed".into()));
		}
		Ok(sig)
	}

	/// Signs the wallet's inputs and publishes: the node must take the
	/// transaction now, or nothing is recorded and the wallet's coins are
	/// given back. Returns its txid, or `None` when the node refused it.
	async fn publish(&self, r: Ready, kind: &'static str, subject: Vec<u8>, detail: String) -> Result<Option<Txid>, WatcherError> {
		self.publish_naming(r, kind, subject, detail, None).await
	}

	/// [`Self::publish`] for the forfeit of the coin `subject` for the round
	/// `round_id`, which the log refuses, and the wallet's coins with it,
	/// while that round is lost or cannot confirm as the chain stands.
	async fn publish_forfeit(&self, r: Ready, round_id: i64, subject: Vec<u8>, detail: String) -> Result<Option<Txid>, WatcherError> {
		// A round the server has not found lost yet whose transaction cannot
		// confirm as the chain stands is lost all the same.
		let round = self.store.round(round_id).await?.ok_or_else(|| WatcherError::Build(format!("no round {}", round_id)))?;
		let gone = self.nursery.can_never_return(&txid_of(&round.txid)).await.map_err(|e| WatcherError::Nursery(e.to_string()))?;
		if gone {
			self.wallet.release(&r.tx.txid()).await?;
			log::info!("watcher: the forfeit of {} not published: round {} cannot confirm as the chain stands", hex(&subject), round_id);
			return Ok(None);
		}
		self.publish_naming(r, "forfeit", subject, detail, Some(round_id)).await
	}

	async fn publish_naming(&self, mut r: Ready, kind: &'static str, subject: Vec<u8>, detail: String, round: Option<i64>)
		-> Result<Option<Txid>, WatcherError>
	{
		let txid = r.tx.txid();
		for (i, c) in &r.wallet {
			self.wallet.sign_input(&mut r.tx, *i, c)?;
		}
		let probe = r.tx.clone();
		let (ok, reason, vsize) = self.finality.call(move |c| c.test_accept(&probe)).await.map_err(|e| WatcherError::Chain(e.to_string()))?;
		if !ok {
			self.wallet.release(&txid).await?;
			log::info!("watcher: {} for {} not taken by the node yet: {}", kind, hex(&subject), reason.unwrap_or_default());
			return Ok(None);
		}
		let w = NewWatcherTx {
			txid: txid.to_byte_array(),
			tx: serialize(&r.tx),
			fee: r.fee.map(|f| (f.asset.into_inner().to_byte_array(), f.amount)),
			kind,
			subject,
			detail: detail.clone(),
			inputs: r.tx.input.iter().map(|i| (i.previous_output.txid.to_byte_array(), i.previous_output.vout)).collect(),
			round,
		};
		let result = match self.nursery.submit_watcher(&w).await {
			Ok(result) => result,
			Err(crate::nursery::NurseryError::Store(StoreError::RoundLost(round))) => {
				self.wallet.release(&txid).await?;
				log::info!("watcher: {} for {} not published: round {} is lost", kind, hex(&w.subject), round);
				return Ok(None);
			},
			// Whatever kept the transaction out of the nursery, the wallet's
			// coins it reserved are free again: kept, every such failure
			// would take a fee coin out of the wallet for good.
			Err(e) => {
				self.wallet.release(&txid).await?;
				return Err(WatcherError::Nursery(e.to_string()));
			},
		};
		// Its change, for the watcher's next transaction.
		self.store.record_pending_outputs(&r.tx).await?;
		log::info!("watcher: {} {} ({} vB): {}; {}", kind, txid, vsize.unwrap_or(0), detail, result);
		Ok(Some(txid))
	}

	/// Builds a spend of the operator's that pays what it takes of `asset`
	/// (`value`) to the wallet, less its fee: from that value when the node
	/// accepts the asset for fees now, else a wallet coin pays. `make` builds
	/// the spend for the outputs and fee source given, and returns it with a
	/// copy whose every input but the fee coin carries a witness of its final
	/// size (the wallet's inputs `wallet_inputs` aside).
	async fn payout<T, F>(&self, asset: AssetId, value: u64, wallet_inputs: &[usize], mut make: F) -> Result<Payout<T>, WatcherError>
	where
		F: FnMut(&[ExplicitOutput], &FeeSource) -> Result<(T, Transaction), String>,
	{
		// An issuer-operated asset: what the operator takes is burned whole,
		// and a coin of another asset pays the fee.
		if self.burns(asset).await? {
			let outs = [crate_burn(asset, value)];
			let (made, coin, fee) = self.wallet.with_fee_coin(&self.fee_assets_but(asset), |src| {
				let (made, dummy) = make(&outs, src)?;
				let mut w = wallet_inputs.to_vec();
				w.extend(fee_input(&dummy, src));
				let txid = dummy.txid();
				Ok((made, txid, sized(dummy, &w)))
			}).await?;
			return Ok(Payout { made, fee_coin: Some(coin), fee });
		}
		let to = self.to_wallet().await?;
		if self.accepted(asset).await?.is_some() {
			let (_, dummy) = make(&[ExplicitOutput::new(asset, value, to.clone())], &FeeSource::Reserve).map_err(WatcherError::Build)?;
			// The fee output is not there yet: allow for it.
			let fee = self.wallet.fee_in(asset, sized(dummy, wallet_inputs) + 50).await?;
			if value > fee.saturating_mul(2) {
				let (made, _) = make(&[ExplicitOutput::new(asset, value - fee, to)], &FeeSource::Reserve).map_err(WatcherError::Build)?;
				return Ok(Payout { made, fee_coin: None, fee: AssetAmount::new(asset, fee) });
			}
		}
		let outs = [ExplicitOutput::new(asset, value, to)];
		let (made, coin, fee) = self.wallet.with_fee_coin(&self.fee_assets(asset), |src| {
			let (made, dummy) = make(&outs, src)?;
			let mut w = wallet_inputs.to_vec();
			w.extend(fee_input(&dummy, src));
			let txid = dummy.txid();
			Ok((made, txid, sized(dummy, &w)))
		}).await?;
		Ok(Payout { made, fee_coin: Some(coin), fee })
	}

	/// [`Watcher::payout`] for what a spend takes in several assets
	/// (`held`): each asset's value goes to the wallet, the fee from the
	/// first of them the node accepts for fees now whose value covers it
	/// twice over; otherwise a wallet coin pays.
	async fn payout_all<T, F>(&self, held: &BTreeMap<AssetId, u64>, wallet_inputs: &[usize], mut make: F) -> Result<Payout<T>, WatcherError>
	where
		F: FnMut(&[ExplicitOutput], &FeeSource) -> Result<(T, Transaction), String>,
	{
		// Any asset of them issuer-operated: each such asset's value is
		// burned whole, the others go to the wallet, and a coin of an asset
		// none of them burns pays the fee.
		let mut burned = vec![];
		for a in held.keys() {
			if self.burns(*a).await? {
				burned.push(*a);
			}
		}
		if !burned.is_empty() {
			let to = self.to_wallet().await?;
			let outs: Vec<ExplicitOutput> = held.iter().map(|(a, v)| if burned.contains(a) { crate_burn(*a, *v) } else {
				ExplicitOutput::new(*a, *v, to.clone())
			}).collect();
			let assets: Vec<AssetId> = self.params.fee_assets().into_iter().filter(|a| !burned.contains(a)).collect();
			let (made, coin, fee) = self.wallet.with_fee_coin(&assets, |src| {
				let (made, dummy) = make(&outs, src)?;
				let mut w = wallet_inputs.to_vec();
				w.extend(fee_input(&dummy, src));
				let txid = dummy.txid();
				Ok((made, txid, sized(dummy, &w)))
			}).await?;
			return Ok(Payout { made, fee_coin: Some(coin), fee });
		}
		let to = self.to_wallet().await?;
		let outs = |less: Option<(AssetId, u64)>| -> Vec<ExplicitOutput> {
			held.iter().map(|(a, v)| {
				let fee = less.filter(|(b, _)| b == a).map(|(_, f)| f).unwrap_or(0);
				ExplicitOutput::new(*a, v - fee, to.clone())
			}).collect()
		};
		for (asset, value) in held {
			if self.accepted(*asset).await?.is_none() {
				continue;
			}
			let (_, dummy) = make(&outs(None), &FeeSource::Reserve).map_err(WatcherError::Build)?;
			// The fee output is not there yet: allow for it.
			let fee = self.wallet.fee_in(*asset, sized(dummy, wallet_inputs) + 50).await?;
			if *value > fee.saturating_mul(2) {
				let (made, _) = make(&outs(Some((*asset, fee))), &FeeSource::Reserve).map_err(WatcherError::Build)?;
				return Ok(Payout { made, fee_coin: None, fee: AssetAmount::new(*asset, fee) });
			}
		}
		let first = *held.keys().next().ok_or_else(|| WatcherError::Build("nothing to pay out".into()))?;
		let all = outs(None);
		let (made, coin, fee) = self.wallet.with_fee_coin(&self.fee_assets(first), |src| {
			let (made, dummy) = make(&all, src)?;
			let mut w = wallet_inputs.to_vec();
			w.extend(fee_input(&dummy, src));
			let txid = dummy.txid();
			Ok((made, txid, sized(dummy, &w)))
		}).await?;
		Ok(Payout { made, fee_coin: Some(coin), fee })
	}

	/// Builds a spend whose outputs its signers committed to: the margin they
	/// left pays the fee when the node accepts its asset now and the margin
	/// covers the node's floor; otherwise a wallet coin pays, the margin
	/// going to the wallet's change. A margin of more than twice the fee the
	/// wallet pays for the transaction pays that fee, and the rest goes to
	/// the wallet: paid whole, a large margin would be a fee the node refuses
	/// (`max-fee-exceeded`). `make` is as for [`Watcher::payout`].
	async fn margin_or_coin<T, F>(&self, asset: AssetId, margin: u64, mut make: F) -> Result<(T, Option<WalletCoin>, Option<AssetAmount>), WatcherError>
	where
		F: FnMut(&FeeSource) -> Result<(T, Transaction), String>,
	{
		// An issuer-operated asset: a coin of another asset pays, and the
		// margin is burned, never paid as a fee nor kept.
		if self.burns(asset).await? {
			let (made, coin, fee) = self.wallet.with_fee_coin(&self.fee_assets_but(asset), |src| {
				let src = burning(src);
				let (made, dummy) = make(&src)?;
				let w: Vec<usize> = fee_input(&dummy, &src).into_iter().collect();
				let txid = dummy.txid();
				Ok((made, txid, sized(dummy, &w)))
			}).await?;
			return Ok((made, Some(coin), Some(fee)));
		}
		if let Some(floor) = self.accepted(asset).await? {
			let (made, dummy) = make(&FeeSource::Reserve).map_err(WatcherError::Build)?;
			if margin >= fees::atoms_for(floor, dummy.vsize() as u64, 1) {
				let to = self.to_wallet().await?;
				// Sized with the change output it would have.
				if let Ok((_, sized)) = make(&FeeSource::Split { fee: 1, change: to.clone() }) {
					let fee = self.wallet.fee_in(asset, sized.vsize() as u64).await?;
					if margin > fee.saturating_mul(2) {
						let (made, _) = make(&FeeSource::Split { fee, change: to }).map_err(WatcherError::Build)?;
						return Ok((made, None, Some(AssetAmount::new(asset, fee))));
					}
				}
				return Ok((made, None, Some(AssetAmount::new(asset, margin))));
			}
		}
		let (made, coin, fee) = self.wallet.with_fee_coin(&self.fee_assets(asset), |src| {
			let (made, dummy) = make(src)?;
			let w: Vec<usize> = fee_input(&dummy, src).into_iter().collect();
			let txid = dummy.txid();
			Ok((made, txid, sized(dummy, &w)))
		}).await?;
		Ok((made, Some(coin), Some(fee)))
	}

	/// A coin record resolved for building its transactions, at any time
	/// after it was taken: under the server's policy as at the latest unroll
	/// authorisation in the record (every honest record was usable then, and
	/// every batch in it unexpired), with no horizon, and with any exit delay
	/// ([`Params::taken_policy`]): a coin taken under bounds the operator has
	/// changed since is answered all the same.
	fn resolve(&self, record: &CoinRecord, bases: &[Transaction]) -> Result<ValidCoin, WatcherError> {
		fn latest(r: &CoinRecord) -> u32 {
			match r {
				CoinRecord::Leaf { auths, .. } => auths.iter().map(|(_, t)| t.to_consensus_u32()).max().unwrap_or(0),
				CoinRecord::Accumulator { auth, .. } => auth.1.to_consensus_u32(),
				CoinRecord::Board(_) => 0,
				CoinRecord::Transfer(_) | CoinRecord::Fill(_) => r.parents().into_iter().map(latest).max().unwrap_or(0),
			}
		}
		let at = MedianTime::from_consensus(latest(record).max(arca_covenant::time::LOCKTIME_THRESHOLD)).map_err(build("a time"))?;
		let policy = WalletPolicy { horizon: 0, now: at, ..self.params.taken_policy(at) };
		record.resolve(bases, &policy).map_err(build("the coin record"))
	}

	/// The coin `leaf_id` the server holds, resolved.
	async fn coin(&self, leaf_id: &[u8; 32]) -> Result<ValidCoin, WatcherError> {
		let row = self.store.leaf(leaf_id).await?.ok_or_else(|| WatcherError::Build(format!("leaf {} is not known", hex(leaf_id))))?;
		let record = CoinRecord::from_bytes(&row.record).map_err(build("the coin record"))?;
		let mut bases = vec![];
		coins::bases(&self.store, &record, &mut bases).await.map_err(build("the coin's bases"))?;
		self.resolve(&record, &bases)
	}

	/// The batch's tree, rebuilt from its published form.
	async fn tree(&self, round: &RoundRow, vout: u32) -> Result<Arc<Tree>, WatcherError> {
		if let Some(t) = self.trees.lock().await.get(&(round.round_id, vout)) {
			return Ok(t.clone());
		}
		let p = self.rounds.tree(&txid_of(&round.txid), vout).await.map_err(build("the published tree"))?
			.ok_or_else(|| WatcherError::Build(format!("round {} has no batch at {}", round.round_id, vout)))?;
		if p.kind != arca_covenant::BatchKind::Tree {
			return Err(WatcherError::Build(format!("the batch at output {} of round {} is an accumulator batch, not a tree", vout,
				round.round_id)));
		}
		let t = Arc::new(Tree::build(p.params, &p.leaves).map_err(build("the tree"))?);
		self.trees.lock().await.insert((round.round_id, vout), t.clone());
		Ok(t)
	}

	/// The accumulator batch, rebuilt from its published form.
	async fn accumulator(&self, round: &RoundRow, vout: u32) -> Result<Arc<Accumulator>, WatcherError> {
		if let Some(a) = self.accumulators.lock().await.get(&(round.round_id, vout)) {
			return Ok(a.clone());
		}
		let p = self.rounds.tree(&txid_of(&round.txid), vout).await.map_err(build("the published batch"))?
			.ok_or_else(|| WatcherError::Build(format!("round {} has no batch at {}", round.round_id, vout)))?;
		if p.kind != arca_covenant::BatchKind::Accumulator {
			return Err(WatcherError::Build(format!("the batch at output {} of round {} is a tree", vout, round.round_id)));
		}
		let a = Arc::new(Accumulator::build(AccumulatorParams::from(&p.params), &p.leaves).map_err(build("the accumulator batch"))?);
		self.accumulators.lock().await.insert((round.round_id, vout), a.clone());
		Ok(a)
	}

	/// Where an accumulator batch is now: its output, the state it holds and
	/// its value, after every exit the chain (a block or the mempool) holds,
	/// followed from the round's output through each exit's rest. Every
	/// exit pays a slot's entry, whose script the watcher sees, so the exits
	/// are the transactions that paid an entry of the batch. `None` once an
	/// exit took the last of it.
	async fn accumulator_now(&self, round: &RoundRow, vout: u32, acc: &Accumulator)
		-> Result<Option<(OutPoint, AccumulatorPolicy, u64)>, WatcherError>
	{
		let mut txids: Vec<Txid> = vec![];
		for s in self.store.tree_sightings(round.round_id, vout).await? {
			if s.kind == TreeScriptKind::Entry {
				let t = txid_of(&s.txid);
				if !txids.contains(&t) {
					txids.push(t);
				}
			}
		}
		let mut exits: Vec<Transaction> = Vec::with_capacity(txids.len());
		for t in txids {
			let tx = self.finality.call(move |c| c.transaction(&t)).await.map_err(|e| WatcherError::Chain(e.to_string()))?;
			exits.extend(tx);
		}
		let mut at = OutPoint::new(txid_of(&round.txid), vout);
		let mut state = *acc.policy();
		let mut value = acc.total();
		loop {
			let next = exits.iter().find_map(|t| t.input.iter().position(|i| i.previous_output == at).map(|k| (t, k)));
			let Some((t, k)) = next else { break };
			let seen = read_exit(&t.input[k].witness.script_witness)
				.ok_or_else(|| WatcherError::Build(format!("{} spends the batch at {} and is no exit", t.txid(), at)))?;
			if seen.root != state.root || seen.bitmap != state.bitmap {
				return Err(WatcherError::Build(format!("{} spends the batch at {} from another state", t.txid(), at)));
			}
			if seen.last {
				return Ok(None);
			}
			state = state.after(seen.slot);
			let rest = 2 * k as u32 + 1;
			value = t.output.get(rest as usize).and_then(|o| o.value.explicit())
				.ok_or_else(|| WatcherError::Build(format!("exit {} has no rest at {}", t.txid(), rest)))?;
			at = OutPoint::new(t.txid(), rest);
		}
		Ok(Some((at, state, value)))
	}

	/// Logs an item's failure and carries on with the next.
	fn item<T>(what: &str, r: Result<T, WatcherError>) -> Result<Option<T>, WatcherError> {
		match r {
			Ok(v) => Ok(Some(v)),
			Err(WatcherError::Store(e)) => Err(WatcherError::Store(e)),
			Err(e) => {
				log::warn!("watcher: {}: {}", what, e);
				Ok(None)
			},
		}
	}

	// -----------------------------------------------------------------------
	// 1. Stale exits
	// -----------------------------------------------------------------------

	/// The state of the channel coin `leaf_id` (of `policy`) whose output is
	/// at `op`: its opening, or a state recorded for it, matched by the
	/// script the chain's output at `op` pays.
	async fn channel_state_at(&self, leaf_id: &[u8; 32], policy: &arca_covenant::ChannelPolicy, op: OutPoint)
		-> Result<arca_covenant::State, WatcherError>
	{
		let mut states = vec![policy.opening()];
		states.extend(self.store.channel_states(leaf_id).await?.into_iter().map(|r| r.state));
		for s in states {
			let spk = policy.script_pubkey(&s);
			let at = self.store.sightings_of(spk.as_bytes()).await?;
			if at.iter().any(|(t, v)| txid_of(t) == op.txid && *v == op.vout) {
				return Ok(s);
			}
		}
		Err(WatcherError::Build(format!("output {} of channel coin {} pays no state the operator knows", op, hex(leaf_id))))
	}

	/// Answers every live channel coin on the chain unspent at a state older
	/// than its latest, both sides signed: the latest published over it at
	/// once, the fee from the operator's wallet. An older state's settle pays
	/// the owner what it paid out since; the latest's waits the exit delay
	/// from its own block.
	async fn answer_stale_channel_states(&self) -> Result<(), WatcherError> {
		for (leaf_id, txid, vout) in self.store.live_channel_sightings().await? {
			let op = OutPoint::new(txid_of(&txid), vout);
			if self.spending(&op).await? || self.unspent(op).await?.is_none() {
				continue;
			}
			let r = self.answer_channel_state(&leaf_id, op).await;
			Self::item(&format!("the channel coin {} at {}", hex(&leaf_id), op), r)?;
		}
		Ok(())
	}

	async fn answer_channel_state(&self, leaf_id: &[u8; 32], op: OutPoint) -> Result<(), WatcherError> {
		let coin = self.coin(leaf_id).await?;
		let Some(policy) = coin.leaf.channel_policy() else { return Ok(()) };
		let Some(latest) = self.store.channel_latest_signed(leaf_id).await? else { return Ok(()) };
		let at = self.channel_state_at(leaf_id, &policy, op).await?;
		if at.number >= latest.state.number {
			return Ok(());
		}
		let operator_sig = Signature::from_slice(&latest.operator_sig.expect("signed")).map_err(build("a signature"))?;
		let owner_sig = Signature::from_slice(&latest.owner_sig).map_err(build("a signature"))?;
		let (u, fee_coin, fee) = self.margin_or_coin(coin.asset, 0, |fee| {
			let u = policy.update_tx(op, coin.asset, &at, &latest.state, &operator_sig, &owner_sig, fee).map_err(|e| e.to_string())?;
			let t = u.tx.clone();
			Ok((u, t))
		}).await?;
		let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
		self.publish(Ready { tx: u.tx, wallet, fee }, "channel_update", leaf_id.to_vec(),
			format!("state {} of channel coin {} over state {} on the chain at {}", latest.state.number, hex(leaf_id), at.number, op)).await?;
		Ok(())
	}

	/// Answers every coin given up whose leaf, or whose checkpoint, is on
	/// the chain unspent.
	async fn answer_stale_exits(&self) -> Result<(), WatcherError> {
		for (kind, leaf_id, txid, vout) in self.store.spent_coin_sightings().await? {
			let op = OutPoint::new(txid_of(&txid), vout);
			if self.spending(&op).await? || self.unspent(op).await?.is_none() {
				continue;
			}
			let r = match kind {
				ScriptKind::Leaf => self.answer_leaf(&leaf_id, op).await,
				ScriptKind::Checkpoint => self.publish_reassignment(&leaf_id).await,
				ScriptKind::Board | ScriptKind::Connector => Ok(()),
			};
			Self::item(&format!("the {:?} of coin {} at {}", kind, hex(&leaf_id), op), r)?;
		}
		Ok(())
	}

	/// The `htlc-1` coin of every payment over Lightning the operator paid,
	/// on the chain unspent: claimed with the preimage once the operator's
	/// delay has run since it confirmed, which is before the owner's refund
	/// can open (the coin's exit delay, longer). The coin comes on-chain
	/// when its owner takes the coin it gave up home: the stale exit is
	/// answered by its checkpoint and reassignment, which make it.
	async fn claim_paid_htlcs(&self) -> Result<(), WatcherError> {
		for s in self.store.sends_paid().await? {
			let r = self.claim_htlc(&s).await;
			Self::item(&format!("the htlc-1 coin {} of a paid payment", hex(&s.htlc_leaf_id)), r)?;
		}
		Ok(())
	}

	/// Refunds each received `htlc-1` leaf on the chain whose owner never
	/// handed over or revealed the preimage: once its timeout has passed and
	/// the operator's delay has run since the leaf confirmed. The payment it
	/// was issued against is failed back, or is to be.
	async fn refund_unclaimed_receives(&self, now: MedianTime) -> Result<(), WatcherError> {
		let mut rows = self.store.receives_in(crate::store::ReceiveState::Accepted).await?;
		rows.extend(self.store.receives_in(crate::store::ReceiveState::Cancelled).await?);
		for r in rows {
			let Some(id) = r.participation_id else { continue };
			let Some(leaf) = self.store.participation(&id).await?.and_then(|p| p.outputs.first().and_then(|o| o.leaf_id)) else { continue };
			let ready = self.store.leaf(&leaf).await?.is_some_and(|l| !l.record.is_empty());
			if !ready {
				continue;
			}
			let res = self.refund_receive(&leaf, now).await;
			Self::item(&format!("the received htlc-1 coin {}", hex(&leaf)), res)?;
		}
		Ok(())
	}

	async fn refund_receive(&self, leaf_id: &[u8; 32], now: MedianTime) -> Result<(), WatcherError> {
		let coin = self.coin(leaf_id).await?;
		let Some(terms) = coin.leaf.htlc else { return Ok(()) };
		if terms.direction != arca_covenant::HtlcDirection::Receive || now <= terms.timeout {
			return Ok(());
		}
		let spk = coin.leaf.script_pubkey();
		for (txid, vout) in self.store.sightings_of(spk.as_bytes()).await? {
			let op = OutPoint::new(txid_of(&txid), vout);
			if self.spending(&op).await? || self.unspent(op).await?.is_none() {
				continue;
			}
			if !self.waited(op.txid, terms.refund_delay(coin.leaf.exit_delay)).await? {
				continue;
			}
			let (leaf, asset, value) = (coin.leaf, coin.asset, coin.value);
			let pay = self.payout(asset, value, &[], |outs, fee| {
				let ks = leaf.refund_tx(op, asset, value, outs, fee).map_err(|e| e.to_string())?;
				let t = ks.clone().finish(vec![dummy_sig().as_ref().to_vec()]).tx;
				Ok((ks, t))
			}).await?;
			let ks = pay.made;
			let sig = self.operator_sig(&ks.tx, &ks.prevouts, 0, &ks.script).await?;
			let n = ks.tx.input.len();
			let u = ks.finish(vec![sig.as_ref().to_vec()]);
			let wallet = pay.fee_coin.map(|c| (n - 1, c)).into_iter().collect();
			self.publish(Ready { tx: u.tx, wallet, fee: Some(pay.fee) }, "htlc_refund", leaf_id.to_vec(),
				format!("the htlc-1 coin {} received under hash {}, never claimed, refunded at {}", hex(leaf_id),
					hex(&terms.payment_hash), op)).await?;
		}
		Ok(())
	}

	async fn claim_htlc(&self, s: &crate::store::SendRow) -> Result<(), WatcherError> {
		let preimage = s.preimage.ok_or_else(|| WatcherError::Build("a paid payment without its preimage".into()))?;
		let coin = self.coin(&s.htlc_leaf_id).await?;
		let Some(terms) = coin.leaf.htlc else { return Ok(()) };
		let spk = coin.leaf.script_pubkey();
		for (txid, vout) in self.store.sightings_of(spk.as_bytes()).await? {
			let op = OutPoint::new(txid_of(&txid), vout);
			if self.spending(&op).await? || self.unspent(op).await?.is_none() {
				continue;
			}
			if !self.waited(op.txid, terms.claim_delay(coin.leaf.exit_delay)).await? {
				continue;
			}
			let (leaf, asset, value) = (coin.leaf, coin.asset, coin.value);
			let pay = self.payout(asset, value, &[], |outs, fee| {
				let ks = leaf.claim_tx(op, asset, value, outs, fee).map_err(|e| e.to_string())?;
				let t = ks.clone().finish(arca_covenant::HtlcTerms::claim_items(&dummy_sig(), &preimage)).tx;
				Ok((ks, t))
			}).await?;
			let ks = pay.made;
			let sig = self.operator_sig(&ks.tx, &ks.prevouts, 0, &ks.script).await?;
			let n = ks.tx.input.len();
			let u = ks.finish(arca_covenant::HtlcTerms::claim_items(&sig, &preimage));
			let wallet = pay.fee_coin.map(|c| (n - 1, c)).into_iter().collect();
			self.publish(Ready { tx: u.tx, wallet, fee: Some(pay.fee) }, "htlc_claim", s.htlc_leaf_id.to_vec(),
				format!("the htlc-1 coin {} of the payment of hash {}, paid, claimed with its preimage at {}", hex(&s.htlc_leaf_id),
					hex(&s.payment_hash), op)).await?;
		}
		Ok(())
	}

	/// The forfeit of `leaf_id` the operator can claim: for the round of its
	/// participation's current attempt, that round not lost.
	async fn live_forfeit(&self, leaf_id: &[u8; 32]) -> Result<Option<ForfeitRow>, WatcherError> {
		for f in self.store.forfeits_of(leaf_id).await?.into_iter().rev() {
			let p = match self.store.participation(&f.participation_id).await? {
				Some(p) => p,
				None => continue,
			};
			if p.round_id != Some(f.round_id) || p.attempt != f.attempt {
				continue;
			}
			match self.store.round(f.round_id).await? {
				Some(r) if r.state != RoundState::Lost => return Ok(Some(f)),
				_ => continue,
			}
		}
		Ok(None)
	}

	/// The forfeit `f` of `coin`, rebuilt from what the server chose.
	fn forfeit(&self, coin: &ValidCoin, f: &ForfeitRow) -> Result<(Forfeit, Pair), WatcherError> {
		let refund = RelativeTime::from_units(f.forfeit.refund_delay_units).map_err(build("the refund delay"))?;
		let forfeit = Forfeit::new(coin.leaf, (coin.asset, coin.value), coin.id, f.forfeit.unlock_hash,
			AssetId::from_byte_array(f.forfeit.connector_asset), refund, f.forfeit.margin).map_err(build("the forfeit"))?;
		let pair = Pair {
			operator: Signature::from_slice(&f.forfeit.operator_sig).map_err(build("a signature"))?,
			owner: Signature::from_slice(&f.forfeit.owner_sig).map_err(build("a signature"))?,
		};
		forfeit.verify(&pair).map_err(build("the stored forfeit"))?;
		Ok((forfeit, pair))
	}

	/// Answers the leaf of the coin `leaf_id`, given up and on the chain
	/// unspent at `op`: its forfeit, or its checkpoint.
	async fn answer_leaf(&self, leaf_id: &[u8; 32], op: OutPoint) -> Result<(), WatcherError> {
		if self.answer_plan_coin(leaf_id, op).await? {
			return Ok(());
		}
		if let Some(f) = self.store.order_fill_of(leaf_id).await? {
			if f.signature.is_some() {
				return self.answer_fill(&f.transfer_id, true).await;
			}
		}
		let coin = self.coin(leaf_id).await?;
		if let Some(f) = self.live_forfeit(leaf_id).await? {
			let (forfeit, pair) = self.forfeit(&coin, &f)?;
			// A channel coin answered at whatever state output it reached: its
			// forfeit's pair spends any of them by the same collaborative leaf.
			let channel = match coin.leaf.channel_policy() {
				Some(p) => Some((p, self.channel_state_at(leaf_id, &p, op).await?)),
				None => None,
			};
			let (u, fee_coin, fee) = self.margin_or_coin(coin.asset, forfeit.margin, |fee| {
				let u = match &channel {
					Some((p, state)) => p.collab_tx(op, coin.asset, state, &[forfeit.output()], &pair, fee),
					None => forfeit.tx(op, &pair, fee),
				}.map_err(|e| e.to_string())?;
				let t = u.tx.clone();
				Ok((u, t))
			}).await?;
			let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
			self.publish_forfeit(Ready { tx: u.tx, wallet, fee }, f.round_id, leaf_id.to_vec(),
				format!("the forfeit of coin {} for round {}, on the chain at {}", hex(leaf_id), f.round_id, op)).await?;
			return Ok(());
		}
		if let Some(t) = self.store.spent_by_transfer(leaf_id).await? {
			let (inputs, _) = self.transfer_parts(&t).await?;
			let input = inputs.iter().find(|i| i.coin.id.0 == *leaf_id)
				.ok_or_else(|| WatcherError::Build(format!("transfer {} does not spend coin {}", hex(&t), hex(leaf_id))))?;
			let margin = coin.value - input.checkpoint_value;
			let (u, fee_coin, fee) = self.margin_or_coin(coin.asset, margin, |fee| {
				let u = input.checkpoint_tx(op, fee).map_err(|e| e.to_string())?;
				let t = u.tx.clone();
				Ok((u, t))
			}).await?;
			let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
			self.publish(Ready { tx: u.tx, wallet, fee }, "checkpoint", leaf_id.to_vec(),
				format!("the checkpoint of coin {}, paid on in transfer {}, its leaf on the chain at {}", hex(leaf_id), hex(&t), op)).await?;
		}
		Ok(())
	}

	/// Answers the coin `leaf_id`, given up by a step of an offline-refresh
	/// plan and on the chain unspent at `op`, with the step's refund: the
	/// step's leaf brought on the chain first, one transaction a pass (its path
	/// unrolled by the operator's own authorisations, its entry opened with
	/// the plan's preimage), then both spent into the holder's `v(i)` and the
	/// operator's share. `false` when no step gave the coin up.
	async fn answer_plan_coin(&self, leaf_id: &[u8; 32], op: OutPoint) -> Result<bool, WatcherError> {
		let Some(r) = crate::plans::refund_for(&self.store, &self.params, leaf_id).await? else { return Ok(false) };
		let new_spk = r.refund.new.script_pubkey();
		let mut new_at = None;
		for (txid, vout) in self.store.sightings_of(new_spk.as_bytes()).await? {
			let at = OutPoint::new(txid_of(&txid), vout);
			if self.unspent(at).await?.is_some() {
				new_at = Some(at);
				break;
			}
		}
		let Some(new_at) = new_at else {
			let coin = self.plan_leaf_coin(&r.new_leaf, r.preimage).await?;
			let now = self.now().await?;
			self.bring_on_chain(&coin, now).await?;
			return Ok(true);
		};
		if self.spending(&op).await? || self.spending(&new_at).await? {
			return Ok(true);
		}
		let outs = r.refund.outputs();
		// A plan holds vtxo-1 coins alone (`Plans` refuses a vtxo-2 coin), so
		// neither pair names inputs.
		let s_old = self.signer.rebind(&r.refund.old.owner, &r.old_half, &r.refund.old.salt, r.refund.old.landing.map(|l| l.program), r.refund.asset,
			r.refund.old_value, &outs, None).await?;
		let s_new = self.signer.rebind(&r.refund.new.owner, &r.new_half, &r.refund.new.salt, r.refund.new.landing.map(|l| l.program), r.refund.asset,
			r.refund.new_value, &outs, None).await?;
		let old_pair = Pair { operator: s_old, owner: r.old_half };
		let new_pair = Pair { operator: s_new, owner: r.new_half };
		r.refund.old.verify(r.refund.asset, r.refund.old_value, &outs, &old_pair).map_err(build("the refund's first pair"))?;
		r.refund.new.verify(r.refund.asset, r.refund.new_value, &outs, &new_pair).map_err(build("the refund's second pair"))?;
		let margin = (r.refund.old_value + r.refund.new_value).saturating_sub(outs.iter().map(|o| o.value).sum::<u64>());
		let (u, fee_coin, fee) = self.margin_or_coin(r.refund.asset, margin, |fee| {
			let u = r.refund.tx(op, new_at, &old_pair, &new_pair, fee).map_err(|e| e.to_string())?;
			let t = u.tx.clone();
			Ok((u, t))
		}).await?;
		let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
		self.publish(Ready { tx: u.tx, wallet, fee }, "refund", leaf_id.to_vec(),
			format!("the refund of step {} of plan {}: coin {}, on the chain at {}, and the step's leaf at {}, the holder paid {}",
				r.idx, hex(&r.plan), hex(leaf_id), op, new_at, r.refund.new_value)).await?;
		Ok(true)
	}

	/// The leaf a step of a plan made, as a coin the watcher can bring on the
	/// chain: its record in the tree, validated against its round as of any
	/// time, the step's preimage, and the operator's own unroll authorisation
	/// for every node above it (the operator is member 0 of every node).
	async fn plan_leaf_coin(&self, leaf: &[u8; 32], preimage: [u8; 32]) -> Result<ValidCoin, WatcherError> {
		let b = self.store.batch_leaf(leaf).await?.ok_or_else(|| WatcherError::Build(format!("leaf {} is in no batch", hex(leaf))))?;
		let round = self.store.round(b.round_id).await?.ok_or_else(|| WatcherError::Build(format!("round {} is not recorded", b.round_id)))?;
		let round_tx: Transaction = deserialize(&round.tx).map_err(build("the round"))?;
		if b.kind == arca_covenant::BatchKind::Accumulator {
			// The operator's own exit authorisation: the operator's path out
			// of an accumulator batch.
			let record = arca_covenant::AccumulatorRecord::from_bytes(&b.record).map_err(build("the leaf's record"))?;
			let any_time = MedianTime::from_consensus(500_000_000).map_err(build("a time"))?;
			let policy = WalletPolicy { horizon: 0, ..self.params.taken_policy(any_time) };
			let valid = record.validate_round(&round_tx, &policy).map_err(build("the leaf's record"))?;
			let now = self.now().await?;
			let t = MedianTime::from_consensus(now.to_consensus_u32().saturating_sub(1)).map_err(build("a time"))?;
			let signature = self.signer.accumulator_exit(&valid.policy.root, &valid.exit.record.record(valid.exit.slot), t).await?;
			if !verify_digest(&signature, &valid.exit_digest(t), &self.params.operator) {
				return Err(WatcherError::Build("the signer signed another exit authorisation than the server built".into()));
			}
			return Ok(ValidCoin {
				id: valid.leaf_id, leaf: record.leaf(), asset: record.asset, value: record.value,
				sweep: record.schedule.sweep(true, record.burn), expiry: record.schedule.expiries()[0], hops: 0,
				origin: ValidOrigin::Accumulator { valid, preimage, auth: ExitAuth { by_operator: true, time: t, signature } },
			});
		}
		let record = arca_covenant::LeafRecord::from_bytes(&b.record).map_err(build("the leaf's record"))?;
		let any_time = MedianTime::from_consensus(500_000_000).map_err(build("a time"))?;
		let policy = WalletPolicy { horizon: 0, ..self.params.taken_policy(any_time) };
		let valid = record.validate_round(&round_tx, &policy).map_err(build("the leaf's record"))?;
		let tree = self.tree(&round, b.vout).await?;
		let now = self.now().await?;
		let t = MedianTime::from_consensus(now.to_consensus_u32().saturating_sub(1)).map_err(build("a time"))?;
		let mut auths = Vec::with_capacity(valid.branch.nodes.len());
		for ((node, _), bn) in tree.path(b.idx as usize).iter().zip(&valid.branch.nodes) {
			let signature = self.signer.unroll(&bn.children_hash(), t).await?;
			if !verify_digest(&signature, &bn.unroll_authorisation(t).digest, &self.params.operator) {
				return Err(WatcherError::Build("the signer signed another unroll authorisation than the server built".into()));
			}
			auths.push(arca_covenant::UnrollAuth { signature, time: t, key: self.params.operator, proof: node.members().proof(0) });
		}
		Ok(ValidCoin {
			id: valid.leaf_id, leaf: record.leaf(), asset: record.asset, value: record.value, sweep: record.schedule.sweep(true, record.burn),
			expiry: record.schedule.expiries()[0], hops: 0, origin: ValidOrigin::Leaf { valid, preimage, auths },
		})
	}

	/// Takes the next step that brings a leaf of an accumulator batch onto
	/// the chain: its entry's unlock with the preimage, once an exit has paid
	/// the entry; otherwise the exit of its slot from where the batch is now,
	/// by `auth` (its owner's, or the operator's own).
	async fn bring_accumulator_leaf(&self, coin: &ValidCoin, valid: &arca_covenant::ValidAccumulatorLeaf, preimage: &[u8; 32],
		auth: &ExitAuth, now: MedianTime) -> Result<(), WatcherError>
	{
		for (txid, vout) in self.store.sightings_of(valid.leaf.script_pubkey().as_bytes()).await? {
			if self.unspent(OutPoint::new(txid_of(&txid), vout)).await?.is_some() {
				return Ok(());
			}
		}
		let round = self.store.round_by_txid(&valid.round_txid.to_byte_array()).await?
			.ok_or_else(|| WatcherError::Build("a leaf of a round the server did not build".into()))?;
		let entry = valid.entry_output();
		for s in self.store.tree_sightings(round.round_id, valid.batch_vout).await? {
			if s.script_pubkey != entry.script_pubkey.as_bytes() {
				continue;
			}
			let op = OutPoint::new(txid_of(&s.txid), s.vout);
			if self.unspent(op).await?.is_none() {
				continue;
			}
			if self.spending(&op).await? {
				return Ok(());
			}
			let (u, fee_coin, fee) = self.margin_or_coin(entry.asset, valid.entry_value - valid.entry.value, |fee| {
				let u = valid.entry_tx(op, preimage, fee).map_err(|e| e.to_string())?;
				let t = u.tx.clone();
				Ok((u, t))
			}).await?;
			let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
			self.publish(Ready { tx: u.tx, wallet, fee }, "entry", coin.id.0.to_vec(),
				format!("the entry of coin {} unlocked into its leaf", coin.id)).await?;
			return Ok(());
		}
		if auth.time.to_consensus_u32() > now.to_consensus_u32() {
			return Err(WatcherError::Build("the exit authorisation is not usable yet".into()));
		}
		let acc = self.accumulator(&round, valid.batch_vout).await?;
		let Some((at, state, held)) = self.accumulator_now(&round, valid.batch_vout, &acc).await? else {
			return Err(WatcherError::Build(format!("the accumulator batch of coin {} has no output left", coin.id)));
		};
		if state.bitmap.is_left(valid.exit.slot) || self.spending(&at).await? || self.unspent(at).await?.is_none() {
			return Ok(());
		}
		let (u, fee_coin, fee) = self.margin_or_coin(entry.asset, valid.exit.record.reserve, |fee| {
			let u = valid.exit_tx(&state, at, held, auth, fee).map_err(|e| e.to_string())?;
			let t = u.tx.clone();
			Ok((u, t))
		}).await?;
		let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
		self.publish(Ready { tx: u.tx, wallet, fee }, "unroll", state.root.to_vec(),
			format!("slot {} of coin {} out of its accumulator batch, by {}'s authorisation", valid.exit.slot, coin.id,
				if auth.by_operator { "the operator" } else { "its owner" })).await?;
		Ok(())
	}

	/// The inputs and committed outputs of the transfer `transfer_id`, from
	/// the record of a coin it made.
	async fn transfer_parts(&self, transfer_id: &[u8; 32]) -> Result<(Vec<arca_covenant::ValidInput>, Vec<ExplicitOutput>), WatcherError> {
		let t = self.store.transfer(transfer_id).await?.ok_or_else(|| WatcherError::Build(format!("transfer {} is not known", hex(transfer_id))))?;
		let first = t.outputs.first().ok_or_else(|| WatcherError::Build("a transfer with no outputs".into()))?;
		let coin = self.coin(&first.0).await?;
		match coin.origin {
			ValidOrigin::Transfer { inputs, outputs, .. } | ValidOrigin::Fill { inputs, outputs, .. } => Ok((inputs, outputs)),
			_ => Err(WatcherError::Build(format!("coin {} is not an output of a transfer", hex(&first.0)))),
		}
	}

	/// The first coin the fill `transfer_id` of a resting order made,
	/// resolved: its origin holds the order coin, the taker's inputs and the
	/// fill's outputs.
	async fn fill_coin(&self, transfer_id: &[u8; 32]) -> Result<ValidCoin, WatcherError> {
		let t = self.store.transfer(transfer_id).await?.ok_or_else(|| WatcherError::Build(format!("fill {} is not known", hex(transfer_id))))?;
		let first = t.outputs.first().ok_or_else(|| WatcherError::Build("a fill with no outputs".into()))?;
		let coin = self.coin(&first.0).await?;
		if !matches!(coin.origin, ValidOrigin::Fill { .. }) {
			return Err(WatcherError::Build(format!("coin {} is not an output of a fill", hex(&first.0))));
		}
		Ok(coin)
	}

	/// The first output paying `script` the chain holds unspent.
	async fn unspent_at(&self, script: &Script) -> Result<Option<OutPoint>, WatcherError> {
		for (txid, vout) in self.store.sightings_of(script.as_bytes()).await? {
			let op = OutPoint::new(txid_of(&txid), vout);
			if self.unspent(op).await?.is_some() {
				return Ok(Some(op));
			}
		}
		Ok(None)
	}

	/// Answers a resting order's coin that a fill the operator co-signed
	/// spent, on the chain: the fill is published once the order's coin and
	/// every taker's checkpoint are on the chain unspent, so the coin is
	/// spent by its fill path before its landing delay runs out and its maker
	/// cannot land it. Until then each taker coin is brought on (one step a
	/// pass; once its leaf is there, the answers to stale exits publish its
	/// checkpoint). `bring` is false when the answer is to a taker's
	/// checkpoint: the order's coin is then the maker's to bring, as each
	/// input of a transfer is its own holder's.
	async fn answer_fill(&self, transfer_id: &[u8; 32], bring: bool) -> Result<(), WatcherError> {
		let coin = self.fill_coin(transfer_id).await?;
		let ValidOrigin::Fill { order, inputs, outputs, .. } = &coin.origin else { unreachable!("a fill's coin") };
		let Some(order_at) = self.unspent_at(&order.leaf.script_pubkey()).await? else { return Ok(()) };
		if self.spending(&order_at).await? {
			return Ok(());
		}
		let now = self.now().await?;
		let mut at = vec![];
		let mut missing = false;
		for i in inputs {
			match self.unspent_at(&i.checkpoint_output().script_pubkey).await? {
				Some(op) if !self.spending(&op).await? => at.push(op),
				Some(_) => return Ok(()),
				None => {
					missing = true;
					if bring && self.unspent_at(&i.coin.leaf.script_pubkey()).await?.is_none() {
						Box::pin(self.bring_on_chain(&i.coin, now)).await?;
					}
				},
			}
		}
		if missing {
			return Ok(());
		}
		// What the inputs hold beyond the outputs, per asset: the fill's
		// margin is in the asset the order is paid in.
		let mut margins: BTreeMap<AssetId, u64> = BTreeMap::new();
		*margins.entry(order.asset).or_default() += order.value;
		for i in inputs {
			*margins.entry(i.coin.asset).or_default() += i.checkpoint_value;
		}
		for o in outputs {
			let m = margins.entry(o.asset).or_default();
			*m = m.saturating_sub(o.value);
		}
		margins.retain(|_, v| *v > 0);
		let (asset, margin) = match margins.iter().next() {
			Some((a, m)) if margins.len() == 1 => (*a, *m),
			_ => (outputs[0].asset, 0),
		};
		let (u, fee_coin, fee) = self.margin_or_coin(asset, margin, |fee| {
			let u = coin.fill_tx(order_at, &at, fee).map_err(|e| e.to_string())?;
			let tx = u.tx.clone();
			Ok((u, tx))
		}).await?;
		let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
		self.publish(Ready { tx: u.tx, wallet, fee }, "fill", transfer_id.to_vec(),
			format!("the fill {} of resting order coin {}, on the chain at {}, every checkpoint on the chain", hex(transfer_id),
				order.id, order_at)).await?;
		Ok(())
	}

	/// Publishes the reassignment of the transfer that spent the coin
	/// `input_leaf`, once every checkpoint it spends is on the chain unspent.
	async fn publish_reassignment(&self, input_leaf: &[u8; 32]) -> Result<(), WatcherError> {
		let t = match self.store.spent_by_transfer(input_leaf).await? {
			Some(t) => t,
			None => return Ok(()),
		};
		if self.store.order_fill_by_transfer(&t).await?.is_some_and(|f| f.signature.is_some()) {
			return self.answer_fill(&t, false).await;
		}
		let (inputs, outputs) = self.transfer_parts(&t).await?;
		let mut at = vec![];
		for i in &inputs {
			let script = i.checkpoint_output().script_pubkey;
			let mut found = None;
			for (txid, vout) in self.store.sightings_of(script.as_bytes()).await? {
				let op = OutPoint::new(txid_of(&txid), vout);
				if self.unspent(op).await?.is_some() {
					found = Some(op);
				}
			}
			match found {
				Some(op) if !self.spending(&op).await? => at.push(op),
				_ => return Ok(()),
			}
		}
		// The margins of every input, per asset: one pays the fee, or a
		// wallet coin pays and they go to its change.
		let mut margins: BTreeMap<AssetId, u64> = BTreeMap::new();
		for i in &inputs {
			*margins.entry(i.coin.asset).or_default() += i.checkpoint_value;
		}
		for o in &outputs {
			let m = margins.entry(o.asset).or_default();
			*m = m.saturating_sub(o.value);
		}
		margins.retain(|_, v| *v > 0);
		let (asset, margin) = match margins.iter().next() {
			Some((a, m)) if margins.len() == 1 => (*a, *m),
			_ => (outputs[0].asset, 0),
		};
		let (u, fee_coin, fee) = self.margin_or_coin(asset, margin, |fee| {
			let u = arca_covenant::transfer::reassignment_tx(&inputs, &outputs, &at, fee).map_err(|e| e.to_string())?;
			let tx = u.tx.clone();
			Ok((u, tx))
		}).await?;
		let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
		self.publish(Ready { tx: u.tx, wallet, fee }, "reassignment", t.to_vec(),
			format!("the reassignment of transfer {}, every checkpoint on the chain", hex(&t))).await?;
		Ok(())
	}

	// -----------------------------------------------------------------------
	// 2. Boards given up in a round
	// -----------------------------------------------------------------------

	/// The vbytes of the watcher's own transactions the nursery holds that
	/// no block holds yet.
	async fn waiting_vbytes(&self) -> Result<u64, WatcherError> {
		let mut v = 0;
		for tx in self.store.watcher_unconfirmed().await? {
			let t: Transaction = deserialize(&tx).map_err(build("a watcher transaction"))?;
			v += t.vsize() as u64;
		}
		Ok(v)
	}

	/// Whether a forfeit published now, with `waiting` vbytes of the
	/// watcher's ahead of it, is claimed before its refund opens: it
	/// confirms once those are in blocks, and its claim a block or two
	/// after, each block about `block_interval` apart, while its refund
	/// opens `refund_delay` after the block that holds it.
	fn claimed_in_time(&self, waiting: u64, refund_delay_units: u16) -> bool {
		let share = self.config.block_share_vbytes.max(1);
		let blocks = waiting.div_ceil(share) + 2;
		let needed = blocks.saturating_mul(self.config.block_interval.as_secs());
		needed < u64::from(refund_delay_units) * 512
	}

	/// Publishes the forfeit of every credited board given up in a round
	/// that is final, from the board output, no faster than the forfeits can
	/// be claimed: see the [module documentation](self).
	async fn recover_boards(&self, _now: MedianTime) -> Result<(), WatcherError> {
		let mut waiting = self.waiting_vbytes().await?;
		let mut held_back = 0usize;
		let mut held_for_fees = 0usize;
		let mut atoms: HashSet<i64> = HashSet::new();
		let mut pools = self.fee_pools().await?;
		for id in self.store.boards_to_recover().await? {
			let b = match self.store.board(&id).await? {
				Some(b) if b.state == BoardState::Credited => b,
				_ => continue,
			};
			let leaf = match self.store.leaf(&b.leaf_id).await? {
				Some(l) if l.state == LeafState::Spent => l,
				_ => continue,
			};
			let f = match self.live_forfeit(&leaf.leaf_id).await? {
				Some(f) => f,
				None => continue,
			};
			let p = match self.store.participation(&f.participation_id).await? {
				Some(p) => p,
				None => continue,
			};
			let round_final = self.store.round(f.round_id).await?.is_some_and(|r| r.state == RoundState::Final);
			if p.state != ParticipationState::Released || !round_final {
				continue;
			}
			let op = OutPoint::new(txid_of(&b.txid), b.vout);
			if self.spending(&op).await? || self.unspent(op).await?.is_none() {
				continue;
			}
			// Paced: within the block share, and claimable in time.
			if waiting >= self.config.block_share_vbytes || !self.claimed_in_time(waiting, f.forfeit.refund_delay_units) {
				held_back += 1;
				continue;
			}
			// Funded: a forfeit whose claim a wallet coin must pay goes out
			// only while the pool covers it and its claim beside what is
			// outstanding, twice over, since a coin pays a fee of at most
			// half its value.
			let asset = AssetId::from_byte_array(leaf.asset);
			if let Some((fa, cost)) = self.coin_cost(asset).await? {
				let (pool, owed) = pools.entry(fa).or_insert((0, 0));
				if owed.saturating_add(cost).saturating_mul(2) > *pool {
					held_for_fees += 1;
					continue;
				}
				*owed += cost;
			}
			let r = async {
				let coin = self.coin(&b.leaf_id).await?;
				let (board, _) = coin.board().ok_or_else(|| WatcherError::Build("a board's coin is not a board".into()))?;
				let (forfeit, pair) = self.forfeit(&coin, &f)?;
				let (u, fee_coin, fee) = self.margin_or_coin(coin.asset, forfeit.margin, |fee| {
					let u = forfeit.board_tx(&board, op, &pair, fee).map_err(|e| e.to_string())?;
					let t = u.tx.clone();
					Ok((u, t))
				}).await?;
				let vsize = u.tx.vsize() as u64;
				let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
				let done = self.publish_forfeit(Ready { tx: u.tx, wallet, fee }, f.round_id, b.leaf_id.to_vec(),
					format!("the forfeit of board {}, given up in round {}", hex(&b.leaf_id), f.round_id)).await?;
				Ok::<_, WatcherError>(done.map(|_| vsize))
			}.await;
			if let Some(Some(vsize)) = Self::item(&format!("the board {}", hex(&b.leaf_id)), r)? {
				waiting += vsize + CLAIM_INPUT_VSIZE;
				// The round's atom of `M`, so the claim need not wait for it.
				if atoms.insert(f.round_id) {
					let r = self.connector_atom(f.round_id).await;
					Self::item(&format!("the connector atom of round {}", f.round_id), r)?;
				}
			}
		}
		if held_back > 0 {
			log::info!("watcher: {} board forfeit(s) wait for block space: {} vB of the watcher's wait for a block (share {})",
				held_back, waiting, self.config.block_share_vbytes);
		}
		for (fa, (pool, owed)) in &pools {
			if held_for_fees > 0 || owed.saturating_mul(2) > *pool {
				log::warn!("watcher: the fee pool cannot cover what is outstanding: it holds {} of {} and the claims of the forfeits \
					waiting take {}; {} board forfeit(s) are held back until the wallet is paid more of it", pool, fa, owed, held_for_fees);
			}
		}
		*self.status.lock().unwrap_or_else(|e| e.into_inner()) = FeeStatus { pools, held_for_space: held_back, held_for_fees };
		Ok(())
	}

	/// The fee asset a wallet coin pays in for a forfeit of `asset` and its
	/// claim, and what the two take of it, when the node does not accept
	/// `asset` for fees now; `None` when it does (the margin pays the forfeit
	/// and the forfeited value its claim).
	async fn coin_cost(&self, asset: AssetId) -> Result<Option<(AssetId, u64)>, WatcherError> {
		if self.accepted(asset).await?.is_some() {
			return Ok(None);
		}
		for fa in self.fee_assets(asset) {
			if self.accepted(fa).await?.is_none() {
				continue;
			}
			// A forfeit with a fee coin, and its share of a claim with one.
			let forfeit = self.wallet.fee_in(fa, 450).await?;
			let claim = self.wallet.fee_in(fa, CLAIM_INPUT_VSIZE + 150).await?;
			return Ok(Some((fa, forfeit + claim)));
		}
		Err(WatcherError::Wallet(WalletError::NoFeeCoin(format!("no asset of {:?} is accepted for fees", self.fee_assets(asset)))))
	}

	/// Each fee asset's pool, and what the forfeits published and not yet
	/// claimed will take of it for their claims.
	async fn fee_pools(&self) -> Result<BTreeMap<AssetId, (u64, u64)>, WatcherError> {
		let mut pools: BTreeMap<AssetId, (u64, u64)> = BTreeMap::new();
		for (txid, subject) in self.store.unclaimed_forfeits().await? {
			let op = OutPoint::new(txid_of(&txid), 0);
			if self.spending(&op).await? {
				continue;
			}
			let leaf: [u8; 32] = match subject.try_into() {
				Ok(l) => l,
				Err(_) => continue,
			};
			let row = match self.store.leaf(&leaf).await? {
				Some(r) => r,
				None => continue,
			};
			if let Some((fa, _)) = self.coin_cost(AssetId::from_byte_array(row.asset)).await? {
				let claim = self.wallet.fee_in(fa, CLAIM_INPUT_VSIZE + 150).await?;
				pools.entry(fa).or_insert((0, 0)).1 += claim;
			}
		}
		for fa in self.params.fee_assets() {
			if self.accepted(fa).await?.is_some() {
				let pool = self.wallet.fee_pool(fa).await?;
				pools.entry(fa).or_insert((0, 0)).0 = pool;
			}
		}
		Ok(pools)
	}

	/// Brings onto the chain every coin of a transfer given up in a round
	/// that is final, whose lineage rests on boards alone: no batch sweeps
	/// it, so the operator gets its value back only by publishing the lineage
	/// (each board's checkpoint; the answers to stale exits publish each
	/// reassignment, then the coin's forfeit) and claiming the forfeit. A coin
	/// resting on a batch leaf is left to that batch's sweep.
	///
	/// The lineage is shared: the reassignments it publishes make other coins
	/// too, which land on the chain with it, and so do the coins those were
	/// spent into, carried on by the answers to stale exits. So the lineage
	/// is published at once only when none of them is a coin another holder
	/// may still hold off-chain ([`Self::shared_until`]); otherwise not
	/// before the latest service expiry among those coins, a date each of
	/// their holders knew ([`Params::BOARD_LIFETIME`]). Before then only an
	/// exit puts it on the chain, and the answers to stale exits take it on.
	async fn recover_board_transfers(&self, now: MedianTime) -> Result<(), WatcherError> {
		/// Whether every base of the coin is a board.
		fn boards_alone(r: &CoinRecord) -> bool {
			match r {
				CoinRecord::Board(_) => true,
				CoinRecord::Leaf { .. } | CoinRecord::Accumulator { .. } => false,
				CoinRecord::Transfer(_) | CoinRecord::Fill(_) => r.parents().into_iter().all(boards_alone),
			}
		}
		for (leaf_id, record) in self.store.forfeited_transfer_coins().await? {
			if !CoinRecord::from_bytes(&record).is_ok_and(|r| boards_alone(&r)) {
				continue;
			}
			let f = match self.live_forfeit(&leaf_id).await? {
				Some(f) => f,
				None => continue,
			};
			let p = match self.store.participation(&f.participation_id).await? {
				Some(p) => p,
				None => continue,
			};
			let round_final = self.store.round(f.round_id).await?.is_some_and(|r| r.state == RoundState::Final);
			if p.state != ParticipationState::Released || !round_final {
				continue;
			}
			let r = async {
				let coin = self.coin(&leaf_id).await?;
				if coin.expiry != arca_covenant::transfer::NEVER {
					return Ok(());
				}
				if let Some(until) = self.shared_until(&leaf_id).await? {
					if now.to_consensus_u32() < until {
						log::info!("watcher: the lineage of coin {} waits until median time {}: another holder's coin rests on it",
							hex(&leaf_id), until);
						return Ok(());
					}
				}
				self.bring_on_chain(&coin, now).await
			}.await;
			Self::item(&format!("the coin {} resting on boards", hex(&leaf_id)), r)?;
		}
		Ok(())
	}

	/// Whether publishing the lineage of the forfeited coin `leaf` would put
	/// on the chain a coin another holder may still hold off-chain, and if
	/// so the latest service expiry among such coins (`u32::MAX` when one of
	/// them has none known). The lineage publishes the transfer that made
	/// the coin, and for each of its inputs the transfers that made that
	/// input, down to the boards; every coin those transfers make lands on
	/// the chain. A coin spent by another transfer passes it on (counted as
	/// published, its own coins with it); one live or pending, or given up
	/// in a participation that holds no forfeit of it the operator can
	/// claim, is a coin someone may still hold. A coin under such a forfeit
	/// is the operator's.
	async fn shared_until(&self, leaf: &[u8; 32]) -> Result<Option<u32>, WatcherError> {
		let mut path: HashSet<[u8; 32]> = HashSet::new();
		let mut path_coins: HashSet<[u8; 32]> = HashSet::new();
		let mut todo = vec![*leaf];
		while let Some(c) = todo.pop() {
			if !path_coins.insert(c) {
				continue;
			}
			if let Some(t) = self.store.made_by_transfer(&c).await? {
				if path.insert(t) {
					let row = self.store.transfer(&t).await?
						.ok_or_else(|| WatcherError::Build(format!("transfer {} is not known", hex(&t))))?;
					todo.extend(row.inputs.iter().map(|i| i.0));
				}
			}
		}
		let mut transfers: Vec<[u8; 32]> = path.iter().copied().collect();
		let mut seen: HashSet<[u8; 32]> = path.clone();
		let mut until: Option<u32> = None;
		while let Some(t) = transfers.pop() {
			let row = self.store.transfer(&t).await?.ok_or_else(|| WatcherError::Build(format!("transfer {} is not known", hex(&t))))?;
			for (out, _) in row.outputs {
				if path_coins.contains(&out) {
					continue;
				}
				let Some(l) = self.store.leaf(&out).await? else { continue };
				let held = match l.state {
					LeafState::Live | LeafState::Pending => true,
					LeafState::Lost | LeafState::Expired => false,
					LeafState::Spent => match self.store.spent_by_transfer(&out).await? {
						Some(next) => {
							if seen.insert(next) {
								transfers.push(next);
							}
							false
						},
						None => self.live_forfeit(&out).await?.is_none(),
					},
				};
				if held {
					let record = CoinRecord::from_bytes(&l.record).map_err(build("a coin record"))?;
					let date = Self::service_expiry(&self.store, &record).await?.unwrap_or(u32::MAX);
					until = Some(until.map_or(date, |u| u.max(date)));
				}
			}
		}
		Ok(until)
	}

	/// When the coin of `record` expires as the operator serves it: the
	/// earliest first expiry of the batches it rests on, or service expiry
	/// of the boards ([`coins::board_expiry`]); `None` when none is known.
	async fn service_expiry(store: &Store, record: &CoinRecord) -> Result<Option<u32>, WatcherError> {
		fn batches(r: &CoinRecord, out: &mut Vec<u32>) {
			match r {
				CoinRecord::Leaf { record, .. } => out.extend(record.schedule.expiries().first().map(|e| e.to_consensus_u32())),
				CoinRecord::Accumulator { record, .. } => out.extend(record.schedule.expiries().first().map(|e| e.to_consensus_u32())),
				CoinRecord::Board(_) => {},
				CoinRecord::Transfer(_) | CoinRecord::Fill(_) => r.parents().into_iter().for_each(|p| batches(p, out)),
			}
		}
		let mut dates = vec![];
		batches(record, &mut dates);
		if let Some(b) = coins::board_expiry(store, record).await.map_err(|e| WatcherError::Build(e.to_string()))? {
			dates.push(b);
		}
		Ok(dates.into_iter().min())
	}

	/// Takes the next step that brings `coin` onto the chain: a node of a
	/// batch leaf's path by its owner's authorisation, or its entry with its
	/// preimage; the checkpoint of a board its lineage spent; the same for
	/// each coin a transfer in its lineage spent. A board itself is on the
	/// chain already; once a given-up leaf or a checkpoint is there, the
	/// answers to stale exits take it on.
	async fn bring_on_chain(&self, coin: &ValidCoin, now: MedianTime) -> Result<(), WatcherError> {
		match &coin.origin {
			ValidOrigin::Board { .. } => Ok(()),
			ValidOrigin::Accumulator { valid, preimage, auth } => self.bring_accumulator_leaf(coin, valid, preimage, auth, now).await,
			ValidOrigin::Leaf { valid, preimage, auths } => {
				let branch = &valid.branch;
				// The leaf itself on the chain: the rest is the answer's.
				for (txid, vout) in self.store.sightings_of(branch.leaf.script_pubkey().as_bytes()).await? {
					if self.unspent(OutPoint::new(txid_of(&txid), vout)).await?.is_some() {
						return Ok(());
					}
				}
				let round = self.store.round_by_txid(&valid.round_txid.to_byte_array()).await?
					.ok_or_else(|| WatcherError::Build("a leaf of a round the server did not build".into()))?;
				let seen = self.store.tree_sightings(round.round_id, valid.batch_vout).await?;
				let on_chain = |script: &Script| -> Vec<OutPoint> {
					seen.iter().filter(|s| s.script_pubkey == script.as_bytes())
						.map(|s| OutPoint::new(txid_of(&s.txid), s.vout)).collect()
				};
				let entry = branch.entry_output();
				for op in on_chain(&entry.script_pubkey) {
					if self.unspent(op).await?.is_some() {
						if self.spending(&op).await? {
							return Ok(());
						}
						let (u, fee_coin, fee) = self.margin_or_coin(entry.asset, branch.entry_value - branch.entry.value, |fee| {
							let u = branch.entry_tx(op, preimage, fee).map_err(|e| e.to_string())?;
							let t = u.tx.clone();
							Ok((u, t))
						}).await?;
						let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
						self.publish(Ready { tx: u.tx, wallet, fee }, "entry", coin.id.0.to_vec(),
							format!("the entry of coin {} unlocked into its leaf", coin.id)).await?;
						return Ok(());
					}
				}
				for (k, node) in branch.nodes.iter().enumerate().rev() {
					let out = node.output();
					// The batch output is the round's own output.
					let mut candidates = on_chain(&out.script_pubkey);
					if k == 0 {
						candidates.push(OutPoint::new(valid.round_txid, valid.batch_vout));
					}
					for op in candidates {
						if self.unspent(op).await?.is_none() {
							continue;
						}
						if self.spending(&op).await? {
							return Ok(());
						}
						let auth = &auths[k];
						if auth.time.to_consensus_u32() > now.to_consensus_u32() {
							return Err(WatcherError::Build(format!("the authorisation for level {} is not usable yet", k)));
						}
						let (u, fee_coin, fee) = self.margin_or_coin(out.asset, node.reserve, |fee| {
							let u = node.unroll_tx(op, auth, fee).map_err(|e| e.to_string())?;
							let t = u.tx.clone();
							Ok((u, t))
						}).await?;
						let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
						self.publish(Ready { tx: u.tx, wallet, fee }, "unroll", node.children_hash().to_vec(),
							format!("level {} of coin {}'s path, by its owner's authorisation", k, coin.id)).await?;
						return Ok(());
					}
				}
				Ok(())
			},
			ValidOrigin::Transfer { inputs, .. } => {
				for i in inputs {
					if let Some((board, at)) = i.coin.board() {
						if self.unspent(at).await?.is_none() || self.spending(&at).await? {
							continue;
						}
						let margin = i.coin.value - i.checkpoint_value;
						let (u, fee_coin, fee) = self.margin_or_coin(i.coin.asset, margin, |fee| {
							let u = i.board_checkpoint_tx(fee).map_err(|e| e.to_string())?;
							let t = u.tx.clone();
							Ok((u, t))
						}).await?;
						let _ = board;
						let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
						self.publish(Ready { tx: u.tx, wallet, fee }, "checkpoint", i.coin.id.0.to_vec(),
							format!("the checkpoint of board {}, from the board output", i.coin.id)).await?;
					} else {
						Box::pin(self.bring_on_chain(&i.coin, now)).await?;
					}
				}
				Ok(())
			},
			// A fill's coins: the order coin and each taker's coin it spends,
			// each brought on the chain as its own coin; once they are there,
			// the answers to stale exits take the checkpoints and the fill on.
			ValidOrigin::Fill { order, inputs, .. } => {
				Box::pin(self.bring_on_chain(order, now)).await?;
				for i in inputs {
					Box::pin(self.bring_on_chain(&i.coin, now)).await?;
				}
				Ok(())
			},
		}
	}

	// -----------------------------------------------------------------------
	// Absent makers' orders
	// -----------------------------------------------------------------------

	/// Lands every resting order whose maker is not back by its coin's exit
	/// deadline: see the [module documentation](self).
	async fn land_orders(&self, now: MedianTime) -> Result<(), WatcherError> {
		for order in self.store.live_resting_orders().await? {
			let r = self.land_order(&order, now).await;
			Self::item(&format!("the landing of resting order {}", hex(&order.order_id)), r)?;
		}
		Ok(())
	}

	/// One step of [`Watcher::land_orders`] for `order`: the coin it rests at
	/// brought a step nearer the chain, or, on the chain and its exit delay
	/// waited, landed.
	async fn land_order(&self, order: &crate::store::RestingOrderRow, now: MedianTime) -> Result<(), WatcherError> {
		let Some(row) = self.store.leaf(&order.current_leaf).await? else { return Ok(()) };
		if row.state != LeafState::Live {
			return Ok(());
		}
		let record = CoinRecord::from_bytes(&row.record).map_err(build("the coin record"))?;
		let Some(expiry) = crate::cosign::first_expiry(&record) else { return Ok(()) };
		if now.to_consensus_u32() < expiry.saturating_sub(WalletPolicy::EXIT_DEADLINE) {
			return Ok(());
		}
		let coin = self.coin(&order.current_leaf).await?;
		let policy = coin.leaf.order_policy().ok_or_else(|| WatcherError::Build(format!("coin {} is not an order's", coin.id)))?;
		// A spend of the coin co-signed (a fill, a cancel, a forfeit) is its
		// own way on, answered as a stale exit should the coin come on.
		if !self.signer.under(&policy.salt).await?.is_empty() {
			return Ok(());
		}
		let script = coin.leaf.script_pubkey();
		let Some(at) = self.unspent_at(&script).await? else {
			// On the chain and spent (landed, or filled there): nothing more.
			if !self.store.sightings_of(script.as_bytes()).await?.is_empty() {
				return Ok(());
			}
			log::info!("resting order {}: its coin {} is live at its exit deadline, its maker away: brought on the chain to land",
				hex(&order.order_id), coin.id);
			return self.bring_on_chain(&coin, now).await;
		};
		if self.spending(&at).await? || !self.confirmed(at).await? || !self.waited(at.txid, policy.exit_delay).await? {
			return Ok(());
		}
		let (u, fee_coin, fee) = self.margin_or_coin(coin.asset, 0, |fee| {
			let u = policy.landing_tx(at, coin.value, fee).map_err(|e| e.to_string())?;
			let t = u.tx.clone();
			Ok((u, t))
		}).await?;
		let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
		self.publish(Ready { tx: u.tx, wallet, fee }, "landing", order.order_id.to_vec(),
			format!("resting order {}, its maker away at its exit deadline: its coin {} at {} landed whole as SeqDEX's order", hex(&order.order_id),
				coin.id, at)).await?;
		Ok(())
	}

	// -----------------------------------------------------------------------
	// 4. Claims
	// -----------------------------------------------------------------------

	/// An atom of the connector asset of the round `round_id` the wallet
	/// holds in the chain and has not spent; when there is none, its issuance
	/// is published (once) and `None` returned.
	async fn connector_atom(&self, round_id: i64) -> Result<Option<WalletCoin>, WatcherError> {
		let round = self.store.round(round_id).await?.ok_or_else(|| WatcherError::Build(format!("round {} is not recorded", round_id)))?;
		let m = AssetId::from_byte_array(round.connector_asset);
		if let Some(c) = self.wallet.coins_in_chain(m).await?.into_iter().next() {
			return Ok(Some(c));
		}
		let op = OutPoint::new(txid_of(&round.txid), round.connector_vout);
		if self.spending(&op).await? || self.unspent(op).await?.is_none() {
			return Ok(None);
		}
		let tx: Transaction = deserialize(&round.tx).map_err(build("the round"))?;
		let held = ExplicitOutput::from_txout(&tx.output[round.connector_vout as usize])
			.ok_or_else(|| WatcherError::Build("the connector output is not explicit".into()))?;
		let to = self.to_wallet().await?;
		let c = ConnectorPolicy { operator: self.params.operator };
		let (ks, fee_coin, fee) = self.margin_or_coin(held.asset, held.value, |fee| {
			let ks = c.issuance(op, (held.asset, held.value), to.clone(), &[], fee).map_err(|e| e.to_string())?;
			let t = ks.clone().finish(vec![dummy_sig().as_ref().to_vec()]).tx;
			Ok((ks, t))
		}).await?;
		let sig = self.operator_sig(&ks.tx, &ks.prevouts, 0, &ks.script).await?;
		let n = ks.tx.input.len();
		let u = ks.finish(vec![sig.as_ref().to_vec()]);
		let wallet = fee_coin.map(|c| (n - 1, c)).into_iter().collect();
		self.publish(Ready { tx: u.tx, wallet, fee }, "issue", m.into_inner().to_byte_array().to_vec(),
			format!("one atom of round {}'s connector asset {}", round_id, m)).await?;
		Ok(None)
	}

	/// Claims the forfeits the watcher published that are in a block and
	/// unspent: every one of a round in one transaction, up to
	/// `max_claim_inputs`, against one atom of the round's connector asset.
	async fn claim_forfeits(&self) -> Result<(), WatcherError> {
		let mut by_round: BTreeMap<i64, Vec<Claimable>> = BTreeMap::new();
		for (txid, subject) in self.store.unclaimed_forfeits().await? {
			let leaf_id: [u8; 32] = match subject.try_into() {
				Ok(l) => l,
				Err(_) => continue,
			};
			let op = OutPoint::new(txid_of(&txid), 0);
			if self.spending(&op).await? || !self.confirmed(op).await? {
				continue;
			}
			let r = self.claimable(&leaf_id, op).await;
			if let Some(Some(c)) = Self::item(&format!("the claim of coin {}'s forfeit", hex(&leaf_id)), r)? {
				by_round.entry(c.round_id).or_default().push(c);
			}
		}
		for (round_id, list) in by_round {
			let n = list.len().min(self.config.max_claim_inputs.max(1));
			let r = self.claim(round_id, &list[..n]).await;
			Self::item(&format!("the claim of {} forfeit(s) of round {}", n, round_id), r)?;
			if list.len() > n {
				log::info!("watcher: {} more forfeit(s) of round {} wait for the next claim", list.len() - n, round_id);
			}
		}
		Ok(())
	}

	/// The forfeit of `leaf_id` at `op`, if it is the coin's live forfeit and
	/// may be claimed now.
	async fn claimable(&self, leaf_id: &[u8; 32], op: OutPoint) -> Result<Option<Claimable>, WatcherError> {
		let f = match self.live_forfeit(leaf_id).await? {
			Some(f) => f,
			None => return Ok(None),
		};
		let coin = self.coin(leaf_id).await?;
		let (forfeit, _) = self.forfeit(&coin, &f)?;
		let held = forfeit.output();
		let spent = self.finality.call(move |c| c.transaction(&op.txid)).await.map_err(|e| WatcherError::Chain(e.to_string()))?
			.ok_or_else(|| WatcherError::Chain(format!("{} is not known to the node", op.txid)))?;
		if spent.output.get(op.vout as usize).map(|o| &o.script_pubkey) != Some(&held.script_pubkey) {
			return Err(WatcherError::Build(format!("{} is not the forfeit output of coin {}'s live forfeit", op, hex(leaf_id))));
		}
		let preimage = self.store.attempt_preimage(&f.participation_id, f.attempt).await?
			.ok_or_else(|| WatcherError::Build("no preimage for the forfeit's attempt".into()))?;
		Ok(Some(Claimable { round_id: f.round_id, forfeit, at: op, preimage }))
	}

	/// Claims `list`, forfeits of the round `round_id`, in one transaction
	/// against one atom of its connector asset, paying what they hold to the
	/// wallet less the fee.
	async fn claim(&self, round_id: i64, list: &[Claimable]) -> Result<(), WatcherError> {
		let atom = match self.connector_atom(round_id).await? {
			Some(a) => a,
			None => return Ok(()),
		};
		let m_op = OutPoint::new(txid_of(&atom.txid), atom.vout);
		let m_out = sequentia_ext::explicit_txout(AssetAmount::new(AssetId::from_byte_array(atom.asset), atom.value),
			Script::from(atom.script_pubkey.clone()));
		let back = self.to_wallet().await?;
		let set: Vec<(&Forfeit, OutPoint)> = list.iter().map(|c| (&c.forfeit, c.at)).collect();
		let preimages: Vec<[u8; 32]> = list.iter().map(|c| c.preimage).collect();
		let mut held: BTreeMap<AssetId, u64> = BTreeMap::new();
		for c in list {
			let o = c.forfeit.output();
			*held.entry(o.asset).or_default() += o.value;
		}
		let n = list.len();
		let dummies = vec![dummy_sig(); n];
		let pay = self.payout_all(&held, &[n], |outs, fee| {
			let ct = arca_covenant::batch_claim_tx(&set, (m_op, m_out.clone()), outs, back.clone(), fee).map_err(|e| e.to_string())?;
			let t = ct.clone().finish(&dummies, &preimages).map_err(|e| e.to_string())?.tx;
			Ok((ct, t))
		}).await?;
		let ct: ClaimTx = pay.made;
		let txid = ct.tx.txid();
		self.wallet.take(&[&atom], &txid).await?;
		let mut sigs = Vec::with_capacity(n);
		for i in 0..n {
			sigs.push(self.operator_sig(&ct.tx, &ct.prevouts, i, &ct.leaves[i]).await?);
		}
		let k = ct.connector_input() as usize;
		let tx = ct.finish(&sigs, &preimages).map_err(build("the claim"))?.tx;
		// What it acts for is the round, by its connector asset, as for the
		// atom's issuance; each forfeit it claims is an input of it.
		let subject = AssetId::from_byte_array(atom.asset).into_inner().to_byte_array().to_vec();
		let mut wallet = vec![(k, atom)];
		wallet.extend(pay.fee_coin.map(|c| (tx.input.len() - 1, c)));
		self.publish(Ready { tx, wallet, fee: Some(pay.fee) }, "claim", subject,
			format!("the claim of {} forfeit(s) of round {}, revealing their preimages", n, round_id)).await?;
		Ok(())
	}

	// -----------------------------------------------------------------------
	// 5. Offboards
	// -----------------------------------------------------------------------

	/// Unlocks every offboard output of a released participation, and
	/// reclaims every one whose participation expired or was voided once its
	/// delay has passed.
	async fn offboards(&self) -> Result<(), WatcherError> {
		for o in self.store.offboards_pending().await? {
			let r = self.offboard(&o).await;
			Self::item(&format!("the offboard at output {} of round {}", o.vout, o.round_id), r)?;
		}
		Ok(())
	}

	async fn offboard(&self, o: &crate::store::OffboardRow) -> Result<(), WatcherError> {
		let p = self.store.participation(&o.participation_id).await?
			.ok_or_else(|| WatcherError::Build("an offboard of no participation".into()))?;
		let round = self.store.round(o.round_id).await?.ok_or_else(|| WatcherError::Build("an offboard of no round".into()))?;
		let op = OutPoint::new(txid_of(&round.txid), o.vout);
		if self.spending(&op).await? || self.unspent(op).await?.is_none() {
			return Ok(());
		}
		let wanted = p.outputs.get(o.output_idx as usize).ok_or_else(|| WatcherError::Build("no such offboard output".into()))?;
		let (script, units) = match &wanted.kind {
			WantedKind::Offboard { script, reclaim_delay_units, .. } => (Script::from(script.clone()), *reclaim_delay_units),
			WantedKind::Leaf { .. } => return Err(WatcherError::Build("the output wanted is a leaf".into())),
		};
		let asset = AssetId::from_byte_array(wanted.asset);
		let unlock_hash = match self.store.attempt_preimage(&o.participation_id, o.attempt).await? {
			Some(pre) => (arca_covenant::script::sha256(&pre), pre),
			None => return Err(WatcherError::Build("no preimage for the offboard's attempt".into())),
		};
		let policy = OffboardPolicy {
			unlock_hash: unlock_hash.0,
			destination: ExplicitOutput::new(asset, wanted.value, script),
			operator: self.params.operator,
			reclaim_delay: RelativeTime::from_units(units).map_err(build("the reclaim delay"))?,
		};
		let current = p.attempt == o.attempt && p.round_id == Some(o.round_id);
		let subject = [round.txid.to_vec(), o.vout.to_le_bytes().to_vec()].concat();
		match p.state {
			ParticipationState::Released if current => {
				let preimage = unlock_hash.1;
				let (u, fee_coin, fee) = self.margin_or_coin(asset, o.value.saturating_sub(wanted.value), |fee| {
					let u = policy.unlock_tx(op, o.value, &preimage, fee).map_err(|e| e.to_string())?;
					let t = u.tx.clone();
					Ok((u, t))
				}).await?;
				let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
				self.publish(Ready { tx: u.tx, wallet, fee }, "unlock", subject,
					format!("the offboard of participation {} unlocked to its destination", hex(&o.participation_id))).await?;
			},
			ParticipationState::Expired | ParticipationState::Void if current || p.state == ParticipationState::Void => {
				if !self.waited(op.txid, policy.reclaim_delay).await? {
					return Ok(());
				}
				let pay = self.payout(asset, o.value, &[], |outs, fee| {
					let ks = policy.reclaim(op, o.value, outs, fee).map_err(|e| e.to_string())?;
					let t = ks.clone().finish(vec![dummy_sig().as_ref().to_vec()]).tx;
					Ok((ks, t))
				}).await?;
				let ks = pay.made;
				let sig = self.operator_sig(&ks.tx, &ks.prevouts, 0, &ks.script).await?;
				let n = ks.tx.input.len();
				let u = ks.finish(vec![sig.as_ref().to_vec()]);
				let wallet = pay.fee_coin.map(|c| (n - 1, c)).into_iter().collect();
				self.publish(Ready { tx: u.tx, wallet, fee: Some(pay.fee) }, "offboard_reclaim", subject,
					format!("the offboard of participation {}, which never released its preimage, reclaimed after its delay",
						hex(&o.participation_id))).await?;
			},
			_ => {},
		}
		Ok(())
	}

	// -----------------------------------------------------------------------
	// 6. Expiry
	// -----------------------------------------------------------------------

	/// Releases each batch's token at its expiry and sweeps the batch after
	/// the notice.
	async fn expiries(&self, now: MedianTime) -> Result<(), WatcherError> {
		let mut rounds = self.store.rounds_in(RoundState::Final).await?;
		rounds.extend(self.store.rounds_in(RoundState::Broadcast).await?);
		for round in rounds {
			for b in self.store.batches(round.round_id).await? {
				let r = self.expire(&round, &b, now).await;
				Self::item(&format!("the expiry of the batch at output {} of round {}", b.vout, round.round_id), r)?;
			}
		}
		Ok(())
	}

	/// Where the batch's token is: the outpoint, and the script holding it,
	/// following the watcher's own moves from the round's token output.
	async fn token(&self, round: &RoundRow, b: &crate::store::BatchRow, token: AssetId) -> Result<(OutPoint, Script), WatcherError> {
		let tx: Transaction = deserialize(&round.tx).map_err(build("the round"))?;
		let mut op = OutPoint::new(txid_of(&round.txid), b.token_vout);
		let mut spk = tx.output[b.token_vout as usize].script_pubkey.clone();
		while let Some(w) = self.store.watcher_spend(&op.txid.to_byte_array(), op.vout).await? {
			let t: Transaction = deserialize(&w.tx).map_err(build("a watcher transaction"))?;
			let i = match t.output.iter().position(|o| o.asset.explicit() == Some(token)) {
				Some(i) => i,
				None => break,
			};
			op = OutPoint::new(t.txid(), i as u32);
			spk = t.output[i].script_pubkey.clone();
		}
		Ok((op, spk))
	}

	async fn expire(&self, round: &RoundRow, b: &crate::store::BatchRow, now: MedianTime) -> Result<(), WatcherError> {
		let schedule = ClockSchedule::decode(&b.schedule).map_err(build("the schedule"))?;
		// Nothing moves the token before the first expiry: every clock's is
		// at least that.
		if now.to_consensus_u32() < schedule.expiries()[0].to_consensus_u32() {
			return Ok(());
		}
		let (at, spk) = self.token(round, b, schedule.token).await?;
		let place = match schedule.place(&spk) {
			Some(p) => p,
			None => return Ok(()),
		};
		let subject = schedule.token.into_inner().to_byte_array().to_vec();
		match place {
			TokenPlace::Clock(j) => {
				let e = schedule.expiries()[j];
				if now.to_consensus_u32() < e.to_consensus_u32() || self.unspent(at).await?.is_none() || self.spending(&at).await? {
					return Ok(());
				}
				// A holder away on an offline-refresh plan finds its coin
				// unswept: the batch holding a plan's current coin waits.
				if let Some(why) = crate::plans::holds_batch(&self.store, round.round_id, b.vout).await? {
					log::info!("watcher: the batch at output {} of round {} is not released at clock {}'s expiry: {}", b.vout, round.round_id,
						j, why);
					return Ok(());
				}
				let asset = AssetId::from_byte_array(b.asset);
				let fee_assets = if self.burns(asset).await? { self.fee_assets_but(asset) } else { self.fee_assets(asset) };
				let (ks, coin, fee) = self.wallet.with_fee_coin(&fee_assets, |src| {
					let ks = schedule.release_tx(j, at, src).map_err(|e| e.to_string())?;
					let t = ks.clone().finish(Clock::witness_items(&dummy_sig())).tx;
					let w: Vec<usize> = fee_input(&t, src).into_iter().collect();
					Ok((ks, t.txid(), sized(t, &w)))
				}).await?;
				let sig = self.operator_sig(&ks.tx, &ks.prevouts, 0, &ks.script).await?;
				let n = ks.tx.input.len();
				let u = ks.finish(Clock::witness_items(&sig));
				self.publish(Ready { tx: u.tx, wallet: vec![(n - 1, coin)], fee: Some(fee) }, "release", subject,
					format!("the token of the batch at output {} of round {}, at clock {}'s expiry {}", b.vout, round.round_id, j,
						e.to_consensus_u32())).await?;
			},
			TokenPlace::Released => {
				if self.config.unroll_at_release {
					self.unroll_live(round, b, now).await?;
				}
				if !self.confirmed(at).await? || self.spending(&at).await?
					|| !self.waited(at.txid, schedule.notice).await?
				{
					return Ok(());
				}
				let swept = self.sweepable(round, b, &schedule).await?;
				if swept.is_empty() {
					return Ok(());
				}
				let asset = AssetId::from_byte_array(b.asset);
				let total: u64 = swept.iter().map(|s| s.value).sum();
				// A burn-only batch: each swept output is burned whole at its
				// own index, and a coin of another asset pays the fee.
				if b.burn {
					let (sw, coin, fee) = self.wallet.with_fee_coin(&self.fee_assets_but(asset), |src| {
						let sw = sweep_tx(&schedule, at, &swept, &[], src).map_err(|e| e.to_string())?;
						let t = sw.clone().finish(&vec![dummy_sig(); sw.leaves.len()]).map_err(|e| e.to_string())?.tx;
						let w: Vec<usize> = fee_input(&t, src).into_iter().collect();
						Ok((sw, t.txid(), sized(t, &w)))
					}).await?;
					let mut sigs = Vec::with_capacity(sw.leaves.len());
					for i in 0..sw.leaves.len() {
						sigs.push(self.operator_sig(&sw.tx, &sw.prevouts, i, &sw.leaves[i]).await?);
					}
					let n = sw.tx.input.len();
					let u = sw.finish(&sigs).map_err(build("the burn"))?;
					self.publish(Ready { tx: u.tx, wallet: vec![(n - 1, coin)], fee: Some(fee) }, "sweep", subject,
						format!("{} output(s) of the burn-only batch at output {} of round {}, {} of {} burned", swept.len(), b.vout,
							round.round_id, total, asset)).await?;
					return Ok(());
				}
				let pay = self.payout(asset, total, &[], |outs, fee| {
					let sw = sweep_tx(&schedule, at, &swept, outs, fee).map_err(|e| e.to_string())?;
					let t = sw.clone().finish(&vec![dummy_sig(); sw.leaves.len()]).map_err(|e| e.to_string())?.tx;
					Ok((sw, t))
				}).await?;
				let sw = pay.made;
				let mut sigs = Vec::with_capacity(sw.leaves.len());
				for i in 0..sw.leaves.len() {
					sigs.push(self.operator_sig(&sw.tx, &sw.prevouts, i, &sw.leaves[i]).await?);
				}
				let n = sw.tx.input.len();
				let u = sw.finish(&sigs).map_err(build("the sweep"))?;
				let wallet = pay.fee_coin.map(|c| (n - 1, c)).into_iter().collect();
				self.publish(Ready { tx: u.tx, wallet, fee: Some(pay.fee) }, "sweep", subject,
					format!("{} output(s) of the batch at output {} of round {}, {} of {}", swept.len(), b.vout, round.round_id, total, asset)).await?;
			},
		}
		Ok(())
	}

	/// Brings every live coin of the released batch on the chain under its
	/// holder's key, one step a coin a pass: each leaf of the batch, and each
	/// coin resting on one through transfers, that is live, not on the chain,
	/// not given up to a participation (its forfeit stored), not an `htlc-1`
	/// leaf (its payment's own paths settle it) and not a claim leaf of a
	/// distribution (which goes back to its payer). Paid from each output's
	/// reserve where the node accepts the batch's asset, else from a wallet
	/// coin.
	async fn unroll_live(&self, round: &RoundRow, b: &crate::store::BatchRow, now: MedianTime) -> Result<(), WatcherError> {
		let Some((_, leaves)) = self.store.batch(&round.txid, b.vout).await? else { return Ok(()) };
		let mut stack = vec![];
		for bl in leaves {
			if !self.store.is_distribution(&bl.participation_id).await? {
				stack.push(bl.leaf_id);
			}
		}
		let mut visited = HashSet::new();
		let mut brought = 0usize;
		while let Some(leaf) = stack.pop() {
			if !visited.insert(leaf) {
				continue;
			}
			let Some(row) = self.store.leaf(&leaf).await? else { continue };
			match row.state {
				LeafState::Live => {},
				LeafState::Spent => {
					stack.extend(self.store.transfer_outputs_of(&leaf).await?);
					continue;
				},
				_ => continue,
			}
			if !self.store.sightings_of(&row.script_pubkey).await?.is_empty() || self.live_forfeit(&leaf).await?.is_some() {
				continue;
			}
			let r = async {
				let coin = self.coin(&leaf).await?;
				if coin.leaf.htlc.is_some() {
					return Ok(false);
				}
				self.bring_on_chain(&coin, now).await.map(|_| true)
			}.await;
			if Self::item(&format!("the unroll of coin {} of the released batch at output {} of round {}", hex(&leaf), b.vout,
				round.round_id), r)? == Some(true)
			{
				brought += 1;
			}
		}
		if brought > 0 {
			log::info!("watcher: the batch at output {} of round {} is released: {} live coin(s) brought a step nearer the chain, \
				each under its holder's key", b.vout, round.round_id, brought);
		}
		Ok(())
	}

	/// The outputs of the batch a sweep can take now: the batch output, and
	/// every node, entry and checkpoint of it on the chain, unspent, past its
	/// own notice, that no transaction of the watcher's spends.
	async fn sweepable(&self, round: &RoundRow, b: &crate::store::BatchRow, schedule: &ClockSchedule) -> Result<Vec<Sweepable>, WatcherError> {
		if b.kind == arca_covenant::BatchKind::Accumulator {
			return self.accumulator_sweepable(round, b, schedule).await;
		}
		let tree = self.tree(round, b.vout).await?;
		let mut out: Vec<Sweepable> = vec![];
		let mut seen: HashSet<OutPoint> = HashSet::new();
		let root = tree.root();
		let batch = OutPoint::new(txid_of(&round.txid), b.vout);
		if self.confirmed(batch).await? && !self.spending(&batch).await? {
			out.push(root.policy.sweepable(batch, root.value));
		}
		seen.insert(batch);
		for s in self.store.tree_sightings(round.round_id, b.vout).await? {
			let op = OutPoint::new(txid_of(&s.txid), s.vout);
			if out.len() >= self.config.max_sweep_inputs || !seen.insert(op) {
				continue;
			}
			if !self.confirmed(op).await? || self.spending(&op).await? || !self.waited(op.txid, schedule.notice).await? {
				continue;
			}
			let item = match s.kind {
				TreeScriptKind::Node => tree.levels().get(s.level as usize).and_then(|l| l.get(s.idx as usize))
					.map(|n| n.policy.sweepable(op, n.value)),
				TreeScriptKind::Entry => tree.leaves().get(s.idx as usize).map(|l| l.entry.sweepable(op, l.entry_value)),
			};
			out.extend(item);
		}
		self.checkpoints_sweepable(schedule, &mut out, &mut seen).await?;
		Ok(out)
	}

	/// The outputs of an accumulator batch a sweep can take now: the batch
	/// output where its exits have left it, and every entry an exit paid,
	/// unspent, past its own notice, and the checkpoints of its coins; none
	/// that a transaction of the watcher's spends.
	async fn accumulator_sweepable(&self, round: &RoundRow, b: &crate::store::BatchRow, schedule: &ClockSchedule)
		-> Result<Vec<Sweepable>, WatcherError>
	{
		let acc = self.accumulator(round, b.vout).await?;
		let mut out: Vec<Sweepable> = vec![];
		let mut seen: HashSet<OutPoint> = HashSet::new();
		if let Some((at, state, value)) = self.accumulator_now(round, b.vout, &acc).await? {
			if self.confirmed(at).await? && !self.spending(&at).await? {
				out.push(state.sweepable(at, (acc.params().asset, value)));
			}
			seen.insert(at);
		}
		for s in self.store.tree_sightings(round.round_id, b.vout).await? {
			let op = OutPoint::new(txid_of(&s.txid), s.vout);
			if out.len() >= self.config.max_sweep_inputs || s.kind != TreeScriptKind::Entry || !seen.insert(op) {
				continue;
			}
			if !self.confirmed(op).await? || self.spending(&op).await? || !self.waited(op.txid, schedule.notice).await? {
				continue;
			}
			out.extend(acc.leaves().get(s.idx as usize).map(|l| l.entry.sweepable(op, l.entry_value)));
		}
		self.checkpoints_sweepable(schedule, &mut out, &mut seen).await?;
		Ok(out)
	}

	/// Adds to `out` every checkpoint of a coin from the batch of
	/// `schedule`'s token that a sweep can take now.
	async fn checkpoints_sweepable(&self, schedule: &ClockSchedule, out: &mut Vec<Sweepable>, seen: &mut HashSet<OutPoint>)
		-> Result<(), WatcherError>
	{
		// Checkpoints of coins from this batch.
		for (kind, leaf_id, txid, vout) in self.store.spent_coin_sightings().await? {
			if kind != ScriptKind::Checkpoint || out.len() >= self.config.max_sweep_inputs {
				continue;
			}
			let op = OutPoint::new(txid_of(&txid), vout);
			if !seen.insert(op) || !self.confirmed(op).await? || self.spending(&op).await? {
				continue;
			}
			let coin = match self.coin(&leaf_id).await {
				Ok(c) => c,
				Err(_) => continue,
			};
			let cp = coin.checkpoint();
			if cp.sweep.token != schedule.token || !self.waited(op.txid, schedule.notice).await? {
				continue;
			}
			let t = self.finality.call(move |c| c.transaction(&op.txid)).await.map_err(|e| WatcherError::Chain(e.to_string()))?;
			if let Some(v) = t.and_then(|t| t.output.get(op.vout as usize).and_then(|o| o.value.explicit())) {
				out.push(cp.sweepable(op, coin.asset, v));
			}
		}
		Ok(())
	}

	// -----------------------------------------------------------------------
	// 7. Reclaim
	// -----------------------------------------------------------------------

	/// Reclaims every lowest node on the chain whose owners have all
	/// released it, and with `reclaim_early` unrolls toward them through
	/// nodes all of whose owners have.
	async fn reclaims(&self, now: MedianTime) -> Result<(), WatcherError> {
		let mut batches = self.store.batches_with_releases().await?;
		for b in self.store.batches_with_delegations().await? {
			if !batches.contains(&b) {
				batches.push(b);
			}
		}
		for (round_id, vout) in batches {
			let round = match self.store.round(round_id).await? {
				Some(r) if r.state == RoundState::Final => r,
				_ => continue,
			};
			for b in self.store.batches(round_id).await?.into_iter().filter(|b| b.vout == vout) {
				let r = self.reclaim_batch(&round, &b, now).await;
				Self::item(&format!("the reclaim of the batch at output {} of round {}", b.vout, round.round_id), r)?;
			}
		}
		Ok(())
	}

	async fn reclaim_batch(&self, round: &RoundRow, b: &crate::store::BatchRow, now: MedianTime) -> Result<(), WatcherError> {
		let schedule = ClockSchedule::decode(&b.schedule).map_err(build("the schedule"))?;
		let (_, spk) = self.token(round, b, schedule.token).await?;
		let expired = match schedule.place(&spk) {
			Some(TokenPlace::Clock(j)) => now.to_consensus_u32() >= schedule.expiries()[j].to_consensus_u32(),
			_ => true,
		};
		let tree = self.tree(round, b.vout).await?;
		let leaves = match self.store.batch(&round.txid, b.vout).await? {
			Some((_, l)) => l,
			None => return Ok(()),
		};
		// Each leaf's release of its lowest node, by leaf index.
		let mut released: HashMap<usize, crate::store::ReleaseRow> = HashMap::new();
		// On a node with RECLAIM-D one of whose leaves moved out of round:
		// every slot's consent, by leaf index, once each has one.
		let mut consents: HashMap<usize, crate::delegations::Consent> = HashMap::new();
		for node in &tree.levels()[0] {
			let rows = self.store.releases(&node.policy.children_hash()).await?;
			for i in node.leaves.clone() {
				if let Some(r) = rows.iter().find(|r| leaves.get(i).is_some_and(|l| l.leaf_id == r.leaf_id)) {
					released.insert(i, r.clone());
				}
			}
			if b.delegated_reclaim && node.policy.delegated() && !node.leaves.clone().all(|i| released.contains_key(&i)) {
				let start = node.leaves.start;
				let slots: Option<Vec<([u8; 32], elements::secp256k1_zkp::XOnlyPublicKey)>> = node.leaves.clone()
					.map(|i| Some((leaves.get(i)?.leaf_id, *node.policy.owners().get(i - start)?))).collect();
				let Some(slots) = slots else { continue };
				if let Some(cs) = crate::delegations::node_consents(&self.store, &slots, node.policy.children_hash()).await? {
					for (i, c) in node.leaves.clone().zip(cs) {
						consents.insert(i, c);
					}
				}
			}
		}
		if released.is_empty() && consents.is_empty() {
			return Ok(());
		}
		let leaf_ids: Vec<[u8; 32]> = leaves.iter().map(|l| l.leaf_id).collect();
		let seen = self.store.tree_sightings(round.round_id, b.vout).await?;
		let depth = tree.levels().len();
		for level in (0..depth).rev() {
			for (k, node) in tree.levels()[level].iter().enumerate() {
				if !node.leaves.clone().all(|i| released.contains_key(&i) || consents.contains_key(&i)) {
					continue;
				}
				let mut candidates: Vec<OutPoint> = seen.iter().filter(|s| s.kind == TreeScriptKind::Node && s.level as usize == level && s.idx as usize == k)
					.map(|s| OutPoint::new(txid_of(&s.txid), s.vout)).collect();
				if level + 1 == depth {
					candidates.push(OutPoint::new(txid_of(&round.txid), b.vout));
				}
				for op in candidates {
					if self.spending(&op).await? || self.unspent(op).await?.is_none() {
						continue;
					}
					if level == 0 {
						let ids = &leaf_ids[node.leaves.clone()];
						if node.leaves.clone().all(|i| released.contains_key(&i)) {
							self.reclaim_node(node, op, &released, ids).await?;
						} else {
							let cs: Vec<&crate::delegations::Consent> = node.leaves.clone().map(|i| &consents[&i]).collect();
							self.reclaim_node_delegated(node, op, &cs, ids).await?;
						}
					} else if self.config.reclaim_early && !expired {
						self.unroll_released(node, level, depth, op, &leaves, &released).await?;
					}
					break;
				}
			}
		}
		Ok(())
	}

	/// Unrolls `node`, on the chain at `op`, all of whose owners have
	/// released their lowest nodes, by the first such owner's authorisation.
	#[allow(clippy::too_many_arguments)]
	async fn unroll_released(&self, node: &arca_covenant::tree::TreeNode, level: usize, depth: usize, op: OutPoint,
		leaves: &[crate::store::BatchLeafRow], released: &HashMap<usize, crate::store::ReleaseRow>) -> Result<(), WatcherError>
	{
		let i = node.leaves.start;
		let leaf = leaves.get(i).ok_or_else(|| WatcherError::Build("a leaf the tree has and the store does not".into()))?;
		let _ = released;
		let coin = self.coin(&leaf.leaf_id).await?;
		let (branch, auths) = match &coin.origin {
			ValidOrigin::Leaf { valid, auths, .. } => (&valid.branch, auths),
			_ => return Err(WatcherError::Build("a batch leaf's coin is not a leaf".into())),
		};
		let k = depth - 1 - level;
		let bn = &branch.nodes[k];
		if bn.children_hash() != node.policy.children_hash() {
			return Err(WatcherError::Build("the leaf's path does not pass the node".into()));
		}
		let asset = bn.children[0].asset;
		let (u, fee_coin, fee) = self.margin_or_coin(asset, bn.reserve, |fee| {
			let u = bn.unroll_tx(op, &auths[k], fee).map_err(|e| e.to_string())?;
			let t = u.tx.clone();
			Ok((u, t))
		}).await?;
		let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
		self.publish(Ready { tx: u.tx, wallet, fee }, "unroll", node.policy.children_hash().to_vec(),
			format!("a node at level {} all of whose owners released it, by coin {}'s authorisation", level, hex(&leaf.leaf_id))).await?;
		Ok(())
	}

	/// Reclaims the lowest node `node`, on the chain at `op`, with every
	/// owner's release and an atom of each connector asset they name.
	async fn reclaim_node(&self, node: &arca_covenant::tree::TreeNode, op: OutPoint,
		released: &HashMap<usize, crate::store::ReleaseRow>, leaf_ids: &[[u8; 32]]) -> Result<(), WatcherError>
	{
		// The releases in owner order: the node's owners are its leaves'.
		let rows: Vec<&crate::store::ReleaseRow> = node.leaves.clone().map(|i| &released[&i]).collect();
		let mut atoms: Vec<WalletCoin> = vec![];
		let mut rounds_named: Vec<i64> = rows.iter().map(|r| r.round_id).collect();
		rounds_named.dedup();
		let mut by_round: BTreeMap<i64, ()> = BTreeMap::new();
		for r in rounds_named {
			if by_round.insert(r, ()).is_some() {
				continue;
			}
			match self.connector_atom(r).await? {
				Some(a) => atoms.push(a),
				None => return Ok(()),
			}
		}
		let conns: Vec<(OutPoint, elements::TxOut)> = atoms.iter().map(|a| (
			OutPoint::new(txid_of(&a.txid), a.vout),
			sequentia_ext::explicit_txout(AssetAmount::new(AssetId::from_byte_array(a.asset), a.value), Script::from(a.script_pubkey.clone())),
		)).collect();
		let back = self.to_wallet().await?;
		let owners = node.policy.owners().len();
		let asset = node.policy.children()[0].asset;
		let wallet_inputs: Vec<usize> = (1..=conns.len()).collect();
		let sig_k = |ks: &KeySpend, sig: Signature| -> Result<Vec<Vec<u8>>, String> {
			let mut with_k = Vec::with_capacity(rows.len());
			for r in &rows {
				let k = connector_index(&ks.prevouts, AssetId::from_byte_array(r.connector_asset))
					.ok_or_else(|| "a release names a connector asset no input holds".to_string())?;
				with_k.push((Signature::from_slice(&r.signature).map_err(|e| e.to_string())?, k));
			}
			reclaim_items(&sig, &with_k, owners).map_err(|e| e.to_string())
		};
		let pay = self.payout(asset, node.value, &wallet_inputs, |outs, fee| {
			let ks = node.policy.reclaim_tx(op, node.value, &conns, outs, back.clone(), fee).map_err(|e| e.to_string())?;
			let t = ks.clone().finish(sig_k(&ks, dummy_sig())?).tx;
			Ok((ks, t))
		}).await?;
		let ks = pay.made;
		let txid = ks.tx.txid();
		self.wallet.take(&atoms.iter().collect::<Vec<_>>(), &txid).await?;
		let sig = self.operator_sig(&ks.tx, &ks.prevouts, 0, &ks.script).await?;
		let below = sig_k(&ks, sig).map_err(WatcherError::Build)?;
		let n = ks.tx.input.len();
		let u = ks.finish(below);
		let mut wallet: Vec<(usize, WalletCoin)> = atoms.into_iter().enumerate().map(|(i, a)| (i + 1, a)).collect();
		wallet.extend(pay.fee_coin.map(|c| (n - 1, c)));
		self.store.insert_reclaimed_leaves(&txid.to_byte_array(), leaf_ids).await?;
		self.publish(Ready { tx: u.tx, wallet, fee: Some(pay.fee) }, "reclaim", node.policy.children_hash().to_vec(),
			format!("a lowest node of {} owner(s), every one of whom released it", owners)).await?;
		Ok(())
	}

	/// Reclaims the lowest node `node`, on the chain at `op`, by RECLAIM-D:
	/// `consents` holds each owner's, in owner order, and the reclaim takes an
	/// atom of each connector asset their releases name.
	async fn reclaim_node_delegated(&self, node: &arca_covenant::tree::TreeNode, op: OutPoint,
		consents: &[&crate::delegations::Consent], leaf_ids: &[[u8; 32]]) -> Result<(), WatcherError>
	{
		let mut rounds = vec![];
		for c in consents {
			c.rounds(&mut rounds);
		}
		let mut atoms: Vec<WalletCoin> = vec![];
		for r in rounds {
			match self.connector_atom(r).await? {
				Some(a) => atoms.push(a),
				None => return Ok(()),
			}
		}
		let conns: Vec<(OutPoint, elements::TxOut)> = atoms.iter().map(|a| (
			OutPoint::new(txid_of(&a.txid), a.vout),
			sequentia_ext::explicit_txout(AssetAmount::new(AssetId::from_byte_array(a.asset), a.value), Script::from(a.script_pubkey.clone())),
		)).collect();
		let back = self.to_wallet().await?;
		let owners = node.policy.owners().len();
		let steps: usize = consents.iter().map(|c| c.steps()).sum();
		let asset = node.policy.children()[0].asset;
		let chain = self.params.chain;
		let wallet_inputs: Vec<usize> = (1..=conns.len()).collect();
		let items = |ks: &KeySpend, sig: Signature| -> Result<Vec<Vec<u8>>, String> {
			let trees = consents.iter().map(|c| c.tree(&ks.prevouts)).collect::<Result<Vec<_>, _>>()?;
			let prefix = node.policy.release_prefix().ok_or("a node without RECLAIM")?;
			arca_covenant::node::reclaim_delegated_items(&sig, &prefix, &chain.delegation_prefix(), &trees).map_err(|e| e.to_string())
		};
		let pay = self.payout(asset, node.value, &wallet_inputs, |outs, fee| {
			let ks = node.policy.reclaim_delegated_tx(op, node.value, &conns, outs, back.clone(), fee).map_err(|e| e.to_string())?;
			let t = ks.clone().finish(items(&ks, dummy_sig())?).tx;
			Ok((ks, t))
		}).await?;
		let ks = pay.made;
		let txid = ks.tx.txid();
		self.wallet.take(&atoms.iter().collect::<Vec<_>>(), &txid).await?;
		let sig = self.operator_sig(&ks.tx, &ks.prevouts, 0, &ks.script).await?;
		let below = items(&ks, sig).map_err(WatcherError::Build)?;
		let n = ks.tx.input.len();
		let u = ks.finish(below);
		let mut wallet: Vec<(usize, WalletCoin)> = atoms.into_iter().enumerate().map(|(i, a)| (i + 1, a)).collect();
		wallet.extend(pay.fee_coin.map(|c| (n - 1, c)));
		self.store.insert_reclaimed_leaves(&txid.to_byte_array(), leaf_ids).await?;
		self.publish(Ready { tx: u.tx, wallet, fee: Some(pay.fee) }, "reclaim", node.policy.children_hash().to_vec(),
			format!("a lowest node of {} owner(s) by RECLAIM-D, released by the current holders of its coins in {} step(s)", owners, steps))
			.await?;
		Ok(())
	}
}

/// The connector asset of a round, for reports.
pub fn round_connector(round: &RoundRow) -> AssetId {
	connector_asset(txid_of(&round.txid), round.connector_vout)
}

/// The leaf id of a 32-byte subject.
pub fn subject_leaf(subject: &[u8]) -> Option<LeafId> {
	subject.try_into().ok().map(LeafId)
}
