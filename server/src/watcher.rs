//! The watcher: everything the operator does on the chain after a round.
//!
//! A round leaves the operator holding signatures and rights it must use on
//! the chain, and a holder who breaks its word must be answered there within
//! a delay. The watcher acts on each pass, in this order, and never builds a
//! second spend of an outpoint while a spend of its own is in the nursery and
//! not lost:
//!
//! 1. **Stale exits.** A coin the server holds as given up (by a
//!    participation whose forfeit it stored, or by a co-signed transfer) whose
//!    leaf is seen on the chain unspent, in a block or the mempool, is
//!    answered at once: by its forfeit, or by its checkpoint; and a
//!    reassignment is published once every checkpoint it spends is on the
//!    chain. The answer confirms before the leaf's exit delay runs out, so
//!    the leaf's owner can no longer exit it. A board given up and then
//!    converted is the same case: its leaf appears.
//! 2. **Boards given up in a round.** Once the round is final, the forfeit of
//!    a board is published from the board output: a board never expires, so
//!    this is how its value comes back to the operator. A coin of a transfer
//!    given up in a round whose lineage rests on boards alone never expires
//!    either: the watcher publishes each board's checkpoint, and 1 carries it
//!    through each reassignment to the coin's forfeit.
//! 3. **Forfeit-first.** A participation run again after a round it was in
//!    could not return has its forfeits stored and its preimage withheld. The
//!    watcher brings each coin it gave up onto the chain from the coin's own
//!    record (each node of a batch leaf's path by its owner's authorisation,
//!    then its entry with its preimage; the checkpoint of a board in its
//!    lineage), so 1 publishes the forfeit; once every forfeit is final, the
//!    claims reveal the preimage, and once the claims are final the
//!    participation is released.
//! 4. **Claims.** Each forfeit the watcher published is claimed with the
//!    preimage of its unlock hash and an atom of its round's connector asset
//!    `M`, issued from the round's connector output when no atom is held,
//!    and paid back to the wallet by every claim for the next.
//! 5. **Offboards.** A released participation's offboard output is unlocked
//!    to its destination with the preimage, which the owner already holds. One
//!    whose participation expired or was voided (its preimage never went out)
//!    is reclaimed once its reclaim delay has passed since it confirmed. An
//!    offboard whose preimage went out is never reclaimed.
//! 6. **Expiry.** At the expiry `E` of the clock that holds a batch's token,
//!    the release moves the token to `R`; once it has waited the notice `W`
//!    there, each sweep takes every unspent output of the batch whose own
//!    notice has passed (the batch output, a node or entry someone unrolled, a
//!    checkpoint of a coin from the batch) and returns the token to `R`.
//! 7. **Reclaim.** A lowest node every owner of which has released it is
//!    reclaimed with an atom of each `M` the releases name. With
//!    `reclaim_early`, a node all of whose lowest nodes are released is
//!    unrolled first, by a released owner's authorisation from the server's
//!    records, so a fully refreshed batch comes back before it expires; a
//!    node with an owner who has not released is never unrolled by the
//!    watcher.
//!
//! A fee is paid from the value a transaction takes, or from the margin its
//! signers left, when the node accepts that asset for fees now (the fee the
//! transaction needs, the rest of a large margin back to the wallet);
//! otherwise by a coin of the wallet's in the first asset of the operator's
//! `fee_assets` the node accepts. No asset is assumed, the policy asset included. Every
//! transaction goes to the nursery, which broadcasts it again unchanged after
//! a rollback, however deep: an anchor-driven reorganisation that takes out a
//! round and the watcher's answers puts them back in the order they were
//! made, and the watcher answers again whatever does not return.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use elements::encode::{deserialize, serialize};
use elements::hashes::Hash;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::{AssetId, OutPoint, Script, Transaction, Txid};
use tokio::sync::{broadcast, Mutex};

use arca_covenant::encode::Encoding;
use arca_covenant::forfeit::ForfeitPolicy;
use arca_covenant::node::{connector_index, reclaim_items};
use arca_covenant::sign::{script_spend_sighash, verify_digest};
use arca_covenant::spend::{FeeSource, KeySpend};
use arca_covenant::tree::Tree;
use arca_covenant::{
	connector_asset, sweep_tx, Clock, ClockSchedule, CoinRecord, ConnectorPolicy, ExplicitOutput, Forfeit, LeafId, MedianTime,
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
	BoardState, ForfeitRow, LeafState, NewWatcherTx, NurseryState, ParticipationState, RoundRow, RoundState, ScriptKind, Store,
	StoreError, TreeScriptKind, WalletCoin, WantedKind,
};
use crate::wallet::{Wallet, WalletError};

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
}

impl Default for WatcherConfig {
	fn default() -> WatcherConfig {
		WatcherConfig { reclaim_early: true, max_sweep_inputs: 50, recovery_interval: Duration::from_secs(30) }
	}
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

/// The input of `tx` that a fee coin from `fee` holds.
fn fee_input(tx: &Transaction, fee: &FeeSource) -> Option<usize> {
	match fee {
		FeeSource::Coin { outpoint, .. } => tx.input.iter().position(|i| i.previous_output == *outpoint),
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
	/// The wallet's script everything the watcher takes for the operator
	/// is paid to, handed out once: a step the node refuses, and takes again
	/// on a later pass, hands out no new script each time.
	pay_to: Mutex<Option<Script>>,
}

impl Watcher {
	#[allow(clippy::too_many_arguments)]
	pub fn new(store: Store, finality: Arc<FinalityService>, params: Arc<Params>, wallet: Arc<Wallet>, nursery: Arc<Nursery>,
		signer: SignerClient, rounds: Arc<Rounds>, config: WatcherConfig) -> Arc<Watcher>
	{
		Arc::new(Watcher {
			store, finality, params, wallet, nursery, signer, rounds, config,
			running: Mutex::new(()), trees: Mutex::new(HashMap::new()), pay_to: Mutex::new(None),
		})
	}

	pub fn config(&self) -> &WatcherConfig {
		&self.config
	}

	// -----------------------------------------------------------------------
	// Passes
	// -----------------------------------------------------------------------

	/// One whole pass: the stale exits, then every recovery step.
	pub async fn pass(&self) -> Result<(), WatcherError> {
		let _one = self.running.lock().await;
		let now = self.now().await?;
		self.answer_stale_exits().await?;
		self.recover_boards(now).await?;
		self.recover_board_transfers(now).await?;
		self.forfeit_first(now).await?;
		self.claim_forfeits().await?;
		self.answer_stale_exits().await?;
		self.offboards().await?;
		self.expiries(now).await?;
		self.reclaims(now).await?;
		Ok(())
	}

	/// The urgent part of a pass alone: the stale exits, and the claims.
	pub async fn urgent(&self) -> Result<(), WatcherError> {
		let _one = self.running.lock().await;
		self.answer_stale_exits().await?;
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
		v.extend(self.params.fee_assets.iter().copied().filter(|a| *a != prefer));
		v
	}

	/// `S`'s signature over input `input` of `tx` by `leaf`, checked against
	/// the signature hash the server computes itself.
	async fn operator_sig(&self, tx: &Transaction, prevouts: &[elements::TxOut], input: usize, leaf: &Script)
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
	async fn publish(&self, mut r: Ready, kind: &'static str, subject: Vec<u8>, detail: String) -> Result<Option<Txid>, WatcherError> {
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
		};
		let result = self.nursery.submit_watcher(&w).await.map_err(|e| WatcherError::Nursery(e.to_string()))?;
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
	/// every batch in it unexpired), with no horizon.
	fn resolve(&self, record: &CoinRecord, bases: &[Transaction]) -> Result<ValidCoin, WatcherError> {
		fn latest(r: &CoinRecord) -> u32 {
			match r {
				CoinRecord::Leaf { auths, .. } => auths.iter().map(|(_, t)| t.to_consensus_u32()).max().unwrap_or(0),
				CoinRecord::Board(_) => 0,
				CoinRecord::Transfer(t) => t.inputs.iter().map(|i| latest(&i.coin)).max().unwrap_or(0),
			}
		}
		let at = MedianTime::from_consensus(latest(record).max(arca_covenant::time::LOCKTIME_THRESHOLD)).map_err(build("a time"))?;
		let policy = WalletPolicy { horizon: 0, now: at, ..self.params.policy(at) };
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
		let t = Arc::new(Tree::build(p.params, &p.leaves).map_err(build("the tree"))?);
		self.trees.lock().await.insert((round.round_id, vout), t.clone());
		Ok(t)
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
		let coin = self.coin(leaf_id).await?;
		if let Some(f) = self.live_forfeit(leaf_id).await? {
			let (forfeit, pair) = self.forfeit(&coin, &f)?;
			let (u, fee_coin, fee) = self.margin_or_coin(coin.asset, forfeit.margin, |fee| {
				let u = forfeit.tx(op, &pair, fee).map_err(|e| e.to_string())?;
				let t = u.tx.clone();
				Ok((u, t))
			}).await?;
			let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
			self.publish(Ready { tx: u.tx, wallet, fee }, "forfeit", leaf_id.to_vec(),
				format!("the forfeit of coin {}, on the chain at {}", hex(leaf_id), op)).await?;
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

	/// The inputs and committed outputs of the transfer `transfer_id`, from
	/// the record of a coin it made.
	async fn transfer_parts(&self, transfer_id: &[u8; 32]) -> Result<(Vec<arca_covenant::ValidInput>, Vec<ExplicitOutput>), WatcherError> {
		let t = self.store.transfer(transfer_id).await?.ok_or_else(|| WatcherError::Build(format!("transfer {} is not known", hex(transfer_id))))?;
		let first = t.outputs.first().ok_or_else(|| WatcherError::Build("a transfer with no outputs".into()))?;
		let coin = self.coin(&first.0).await?;
		match coin.origin {
			ValidOrigin::Transfer { inputs, outputs, .. } => Ok((inputs, outputs)),
			_ => Err(WatcherError::Build(format!("coin {} is not an output of a transfer", hex(&first.0)))),
		}
	}

	/// Publishes the reassignment of the transfer that spent the coin
	/// `input_leaf`, once every checkpoint it spends is on the chain unspent.
	async fn publish_reassignment(&self, input_leaf: &[u8; 32]) -> Result<(), WatcherError> {
		let t = match self.store.spent_by_transfer(input_leaf).await? {
			Some(t) => t,
			None => return Ok(()),
		};
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

	/// Publishes the forfeit of every credited board given up in a round
	/// that is final, from the board output.
	async fn recover_boards(&self, _now: MedianTime) -> Result<(), WatcherError> {
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
			let ready = p.state == ParticipationState::Released || (p.forfeit_first && p.state == ParticipationState::Issued);
			let round_final = self.store.round(f.round_id).await?.is_some_and(|r| r.state == RoundState::Final);
			if !ready || !round_final {
				continue;
			}
			let op = OutPoint::new(txid_of(&b.txid), b.vout);
			if self.spending(&op).await? || self.unspent(op).await?.is_none() {
				continue;
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
				let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
				self.publish(Ready { tx: u.tx, wallet, fee }, "forfeit", b.leaf_id.to_vec(),
					format!("the forfeit of board {}, given up in round {}", hex(&b.leaf_id), f.round_id)).await
			}.await;
			Self::item(&format!("the board {}", hex(&b.leaf_id)), r)?;
		}
		Ok(())
	}

	/// Brings onto the chain every coin of a transfer given up in a round
	/// that is final, whose lineage rests on boards alone: it never expires,
	/// so the operator gets its value back only by publishing the lineage
	/// (each board's checkpoint; the answers to stale exits publish each
	/// reassignment, then the coin's forfeit) and claiming the forfeit. A coin
	/// resting on a batch leaf is left to that batch's sweep.
	async fn recover_board_transfers(&self, now: MedianTime) -> Result<(), WatcherError> {
		/// Whether every base of the coin is a board.
		fn boards_alone(r: &CoinRecord) -> bool {
			match r {
				CoinRecord::Board(_) => true,
				CoinRecord::Leaf { .. } => false,
				CoinRecord::Transfer(t) => t.inputs.iter().all(|i| boards_alone(&i.coin)),
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
				self.bring_on_chain(&coin, now).await
			}.await;
			Self::item(&format!("the coin {} resting on boards", hex(&leaf_id)), r)?;
		}
		Ok(())
	}

	// -----------------------------------------------------------------------
	// 3. Forfeit-first
	// -----------------------------------------------------------------------

	/// Brings onto the chain each coin a forfeit-first participation gave
	/// up, and releases the participation once every claim of its forfeits
	/// is final.
	async fn forfeit_first(&self, now: MedianTime) -> Result<(), WatcherError> {
		for id in self.store.forfeit_first_waiting().await? {
			let p = match self.store.participation(&id).await? {
				Some(p) => p,
				None => continue,
			};
			let round_id = p.round_id.unwrap_or_default();
			if !self.store.round(round_id).await?.is_some_and(|r| r.state == RoundState::Final) {
				continue;
			}
			let mut claimed = 0;
			for i in &p.inputs {
				if self.store.watcher_txs("claim", &i.leaf_id).await?.iter().any(|w| w.state == NurseryState::Final) {
					claimed += 1;
					continue;
				}
				let r = async {
					let coin = self.coin(&i.leaf_id).await?;
					self.bring_on_chain(&coin, now).await
				}.await;
				Self::item(&format!("forfeit-first coin {}", hex(&i.leaf_id)), r)?;
			}
			if claimed == p.inputs.len() {
				let released = self.store.complete_participation(&id, p.attempt, round_id, &[], &[], true).await?;
				log::info!("watcher: participation {} ran forfeit-first; every forfeit claimed and final, so it is released ({})",
					hex(&id), released);
			}
		}
		Ok(())
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
		}
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

	/// Claims every forfeit the watcher published whose output is unspent,
	/// with the preimage and an atom of its round's connector asset. A
	/// forfeit-first participation's are claimed only once all its
	/// forfeits are final, since the claim reveals the preimage.
	async fn claim_forfeits(&self) -> Result<(), WatcherError> {
		for (txid, subject) in self.store.unclaimed_forfeits().await? {
			let leaf_id: [u8; 32] = match subject.try_into() {
				Ok(l) => l,
				Err(_) => continue,
			};
			let op = OutPoint::new(txid_of(&txid), 0);
			if self.spending(&op).await? || self.unspent(op).await?.is_none() {
				continue;
			}
			let r = self.claim(&leaf_id, op).await;
			Self::item(&format!("the claim of coin {}'s forfeit", hex(&leaf_id)), r)?;
		}
		Ok(())
	}

	async fn claim(&self, leaf_id: &[u8; 32], op: OutPoint) -> Result<(), WatcherError> {
		let f = match self.live_forfeit(leaf_id).await? {
			Some(f) => f,
			None => return Ok(()),
		};
		let p = self.store.participation(&f.participation_id).await?
			.ok_or_else(|| WatcherError::Build("a forfeit of no participation".into()))?;
		if p.forfeit_first && p.state == ParticipationState::Issued {
			// Every forfeit of it final before the preimage goes out.
			for i in &p.inputs {
				let done = self.store.watcher_txs("forfeit", &i.leaf_id).await?.iter().any(|w| w.state == NurseryState::Final);
				if !done {
					return Ok(());
				}
			}
		}
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
		let atom = match self.connector_atom(f.round_id).await? {
			Some(a) => a,
			None => return Ok(()),
		};
		let m_op = OutPoint::new(txid_of(&atom.txid), atom.vout);
		let m_out = sequentia_ext::explicit_txout(AssetAmount::new(AssetId::from_byte_array(atom.asset), atom.value),
			Script::from(atom.script_pubkey.clone()));
		let back = self.to_wallet().await?;
		let pay = self.payout(held.asset, held.value, &[Forfeit::CONNECTOR_INPUT as usize], |outs, fee| {
			let ks = forfeit.claim(op, (m_op, m_out.clone()), outs, back.clone(), fee).map_err(|e| e.to_string())?;
			let t = ks.clone().finish(ForfeitPolicy::claim_items(&dummy_sig(), &preimage, Forfeit::CONNECTOR_INPUT)).tx;
			Ok((ks, t))
		}).await?;
		let ks: KeySpend = pay.made;
		let txid = ks.tx.txid();
		self.wallet.take(&[&atom], &txid).await?;
		let sig = self.operator_sig(&ks.tx, &ks.prevouts, 0, &ks.script).await?;
		let n = ks.tx.input.len();
		let u = ks.finish(ForfeitPolicy::claim_items(&sig, &preimage, Forfeit::CONNECTOR_INPUT));
		let mut wallet = vec![(Forfeit::CONNECTOR_INPUT as usize, atom)];
		wallet.extend(pay.fee_coin.map(|c| (n - 1, c)));
		self.publish(Ready { tx: u.tx, wallet, fee: Some(pay.fee) }, "claim", leaf_id.to_vec(),
			format!("the claim of coin {}'s forfeit for round {}, revealing its preimage", hex(leaf_id), f.round_id)).await?;
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
				let (ks, coin, fee) = self.wallet.with_fee_coin(&self.params.fee_assets, |src| {
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
				if b.burn {
					log::warn!("watcher: the batch at output {} of round {} is burn-only; this server sweeps none", b.vout, round.round_id);
					return Ok(());
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

	/// The outputs of the batch a sweep can take now: the batch output, and
	/// every node, entry and checkpoint of it on the chain, unspent, past its
	/// own notice, that no transaction of the watcher's spends.
	async fn sweepable(&self, round: &RoundRow, b: &crate::store::BatchRow, schedule: &ClockSchedule) -> Result<Vec<Sweepable>, WatcherError> {
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
		Ok(out)
	}

	// -----------------------------------------------------------------------
	// 7. Reclaim
	// -----------------------------------------------------------------------

	/// Reclaims every lowest node on the chain whose owners have all
	/// released it, and with `reclaim_early` unrolls toward them through
	/// nodes all of whose owners have.
	async fn reclaims(&self, now: MedianTime) -> Result<(), WatcherError> {
		for (round_id, vout) in self.store.batches_with_releases().await? {
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
		for node in &tree.levels()[0] {
			let rows = self.store.releases(&node.policy.children_hash()).await?;
			for i in node.leaves.clone() {
				if let Some(r) = rows.iter().find(|r| leaves.get(i).is_some_and(|l| l.leaf_id == r.leaf_id)) {
					released.insert(i, r.clone());
				}
			}
		}
		if released.is_empty() {
			return Ok(());
		}
		let seen = self.store.tree_sightings(round.round_id, b.vout).await?;
		let depth = tree.levels().len();
		for level in (0..depth).rev() {
			for (k, node) in tree.levels()[level].iter().enumerate() {
				if !node.leaves.clone().all(|i| released.contains_key(&i)) {
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
						self.reclaim_node(node, op, &released).await?;
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
		released: &HashMap<usize, crate::store::ReleaseRow>) -> Result<(), WatcherError>
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
		self.publish(Ready { tx: u.tx, wallet, fee: Some(pay.fee) }, "reclaim", node.policy.children_hash().to_vec(),
			format!("a lowest node of {} owner(s), every one of whom released it", owners)).await?;
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
