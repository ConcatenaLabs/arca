//! The round: what turns pending participations into batches on-chain.
//!
//! At each round the runner gathers the pending participations whose
//! earliest round time has come, checks their coins again, takes those the
//! operator's wallet can fund in each asset (what the round pays for them,
//! batch outputs with their reserves and offboard outputs, then its own fee
//! and connector; one that does not fit waits, saying why, and delays no
//! other), and builds one tree per asset with `arca-covenant`'s builder ([`Tree::build`]): balanced
//! at radix 4, every node gated, RECLAIM on the lowest nodes, each leaf
//! behind its participation's hash-locked entry, the reserve at four times the
//! node's floor in the batch asset (one atom where the node does not accept
//! the asset for fees, so whoever unrolls attaches a fee coin). Each batch has
//! a sweep token of its own, issued as one explicit atom with no reissuance
//! token by one of the operator's coins, and a clock schedule of three steps
//! (28, 56 and 84 days after the round) with a notice of 36 hours.
//!
//! The round transaction pays, in order: each batch output followed by its
//! token's atom to the batch's first clock, then every offboard output, then
//! the connector output (`arca_covenant::ConnectorPolicy`), whose only spend
//! issues the round's connector asset, then change per asset and the one fee
//! output. It spends the operator's own coins and nothing else: a round that
//! carries forfeits takes no input of a third party, which could be spent
//! elsewhere and keep the round from returning after a rollback. It has
//! `nLockTime` 0 and final inputs, and is kept byte for byte, so the nursery
//! broadcasts it again unchanged after a rollback and it returns with its
//! txid, every forfeit signed for it still good.
//!
//! The fee is paid in one asset: the first of the round's own batch assets,
//! in the operator's order of preference, that the node accepts for fees now,
//! else the first asset of that list it accepts. Never another.
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
//! of whose forfeits the watcher claimed, or every forfeit of which is whole,
//! none of its coins taken on the chain otherwise, is released by the server
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
//! included. Any other re-run completes as an ordinary participation: its
//! forfeit for the new round is taken and checked, the preimage released
//! against it, and the coin left like any forfeited coin (a board lineage to
//! the board's dates, a batch leaf to its batch's expiry, either answered at
//! once if its owner exits). Nothing goes on the chain for a re-run that an
//! ordinary participation would not put there.
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
use arca_covenant::tree::{LeafSpec, ReserveRule, Tree, TreeParams};
use arca_covenant::{
	connector_asset, ClockSchedule, ConnectorPolicy, ExplicitOutput, LeafId, MedianTime, OffboardPolicy, RelativeTime, Template,
	WalletPolicy,
};
use sequentia_ext::AssetAmount;

use crate::chain::{ChainEvent, FinalityService};
use crate::coins;
use crate::fees;
use crate::nursery::{Nursery, NurseryKind};
use crate::params::Params;
use crate::store::{
	BatchRow, LeafKind, LeafState, NewBatch, NewBatchLeaf, NewCoin, NewOffboard, NewRerun, NewRound, NewScript, NewTreeScript,
	ParticipationRow, NurseryState, ParticipationState, RoundRow, RoundState, ScriptKind, Store, StoreError, StoredReserve, TreeScriptKind,
	WalletCoin, WantedKind,
};
use crate::wallet::{Wallet, WalletError};

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
}

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
	#[error("{0}")]
	Internal(String),
}

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
	/// What the nursery heard from the node.
	pub broadcast: String,
}

/// A batch as the operator publishes it: everything [`Tree::build`] takes,
/// and where the round put it.
#[derive(Debug, Clone)]
pub struct PublishedTree {
	pub round_txid: Txid,
	pub batch_vout: u32,
	pub token_vout: u32,
	pub connector_vout: u32,
	pub params: TreeParams,
	pub leaves: Vec<LeafSpec>,
	/// The latest entry of the signer's record, its running hash and the
	/// signer's signature over them, when the round was built: a witness of
	/// the record every wallet reading the tree keeps.
	pub signer_head: Option<(u64, [u8; 32], Option<[u8; 64]>)>,
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
	config: RoundConfig,
	/// One round at a time.
	running: Mutex<()>,
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
		config: RoundConfig) -> Arc<Rounds>
	{
		Arc::new(Rounds { store, finality, params, wallet, nursery, config, running: Mutex::new(()) })
	}

	pub fn config(&self) -> &RoundConfig {
		&self.config
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
	/// back.
	async fn still_good(&self, p: &ParticipationRow, now: MedianTime) -> Result<bool, RoundError> {
		if p.attempt > 0 {
			if let Some(why) = self.barred(p).await? {
				let voided = self.store.void_participation(&p.id, &why).await?;
				log::warn!("participation {} is never taken again (voided: {}): {}", crate::signer::hex(&p.id), voided, why);
				return Ok(false);
			}
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

	/// Builds the next round from the pending participations, if any: see
	/// the [module documentation](self). Returns `None` when nothing waits.
	pub async fn run_round(&self) -> Result<Option<Built>, RoundError> {
		let _one = self.running.lock().await;
		let now = self.now().await?;

		// The participations, whole, within the batch size.
		let mut chosen: Vec<ParticipationRow> = vec![];
		let mut counts: BTreeMap<AssetId, usize> = BTreeMap::new();
		for id in self.store.participations_in(ParticipationState::Pending).await? {
			let row = match self.store.participation(&id).await? {
				Some(r) => r,
				None => continue,
			};
			if row.not_before.is_some_and(|t| t > now.to_consensus_u32()) {
				continue;
			}
			let mut adds: BTreeMap<AssetId, usize> = BTreeMap::new();
			for o in &row.outputs {
				if matches!(o.kind, WantedKind::Leaf { .. }) {
					*adds.entry(AssetId::from_byte_array(o.asset)).or_default() += 1;
				}
			}
			if adds.iter().any(|(a, n)| counts.get(a).copied().unwrap_or(0) + n > self.config.max_batch_leaves) {
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
			for (a, n) in adds {
				*counts.entry(a).or_default() += n;
			}
			chosen.push(row);
		}
		// What the wallet can fund: a participation whose outputs do not fit
		// waits, saying why, and delays no other.
		let chosen = self.fundable(chosen, now).await?;
		// A re-run spends a coin that keeps it apart from every lost round of
		// its participation's; one with no such coin is never taken.
		let (mut chosen, ties) = self.tie_reruns(chosen).await?;
		loop {
			if chosen.is_empty() {
				return Ok(None);
			}
			match self.build_from(&chosen, now, &ties).await {
				// Short of an asset once the round's own fee and connector are
				// counted: the last participation wanting that asset waits.
				Err(RoundError::Wallet(WalletError::Insufficient { asset, need, have })) => {
					let a = asset.into_inner().to_byte_array();
					let i = match chosen.iter().rposition(|r| r.outputs.iter().any(|o| o.asset == a)) {
						Some(i) => i,
						None => return Err(RoundError::Wallet(WalletError::Insufficient { asset, need, have })),
					};
					let row = chosen.remove(i);
					self.wait(&row, asset, need, have).await?;
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
		let why = format!("the operator's wallet cannot fund it in a round now: the round would pay {} of asset {}, and the wallet \
			can spend {} of it; it runs once the wallet can", need, asset, have);
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
		let mut leaves: BTreeMap<AssetId, Vec<LeafSpec>> = BTreeMap::new();
		let mut pays: BTreeMap<AssetId, u64> = BTreeMap::new();
		for row in rows {
			for o in &row.outputs {
				let asset = AssetId::from_byte_array(o.asset);
				match &o.kind {
					WantedKind::Leaf { .. } => leaves.entry(asset).or_default().push(Self::spec(row, o)?),
					WantedKind::Offboard { margin, .. } => *pays.entry(asset).or_default() += o.value + margin,
				}
			}
		}
		let expiries = self.expiries(now)?;
		for (asset, specs) in leaves {
			let reserve = match self.floor(asset).await? {
				Some(f) => ReserveRule::FeeRate { floor_per_kvb: f, multiple: fees::MULTIPLE },
				None => ReserveRule::Fixed { node: 1, entry: 1 },
			};
			// The token's id changes no value: any asset stands in for it.
			let schedule = ClockSchedule::new(AssetId::from_byte_array([0xee; 32]), self.params.operator, self.config.notice, expiries.clone())
				.map_err(|e| RoundError::Internal(e.to_string()))?;
			let params = TreeParams {
				asset, chain: self.params.chain, schedule, burn: false, radix: self.config.radix, reserve,
				min_leaf: self.params.assets.get(&asset).map(|a| a.min_leaf).unwrap_or(1),
			};
			let tree = Tree::build(params, &specs).map_err(|e| RoundError::Internal(format!("the tree of asset {}: {}", asset, e)))?;
			*pays.entry(asset).or_default() += tree.batch_output().value;
		}
		Ok(pays)
	}

	/// The participations of `chosen` the wallet can fund now, in order: per
	/// asset, what a round with them pays must fit in what the wallet can
	/// spend of that asset. One that does not fit waits, saying why, and the
	/// ones after it are taken if they fit.
	async fn fundable(&self, chosen: Vec<ParticipationRow>, now: MedianTime) -> Result<Vec<ParticipationRow>, RoundError> {
		let balance = self.wallet.balance().await?;
		let have = |a: &AssetId| balance.get(a).copied().unwrap_or(0);
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
				Some((a, v)) => self.wait(&row, *a, *v, have(a)).await?,
				None => taken.push(row),
			}
		}
		Ok(taken)
	}

	/// The leaf `o` of `row` wants, as the tree builder takes it.
	fn spec(row: &ParticipationRow, o: &crate::store::ParticipationOutput) -> Result<LeafSpec, RoundError> {
		match &o.kind {
			WantedKind::Leaf { template, owner_key, owner_nonce, exit_delay_units, operator_nonce } => Ok(LeafSpec {
				template: template.parse::<Template>().map_err(|e| RoundError::Internal(e.to_string()))?,
				owner: elements::secp256k1_zkp::XOnlyPublicKey::from_slice(owner_key).map_err(|e| RoundError::Internal(e.to_string()))?,
				value: o.value,
				owner_nonce: *owner_nonce,
				operator_nonce: *operator_nonce,
				exit_delay: RelativeTime::from_units(*exit_delay_units).map_err(|e| RoundError::Internal(e.to_string()))?,
				unlock_hash: row.unlock_hash,
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
	/// every coin of `ties` a participation of `chosen` needs.
	async fn build_from(&self, chosen: &[ParticipationRow], now: MedianTime, ties: &[Tie]) -> Result<Option<Built>, RoundError> {
		let p = self.params.clone();
		let s = p.operator;

		// The leaves per asset, and the offboards.
		let mut groups: BTreeMap<AssetId, Vec<Planned>> = BTreeMap::new();
		let mut offboards: Vec<PlannedOffboard> = vec![];
		for (k, row) in chosen.iter().enumerate() {
			for (j, o) in row.outputs.iter().enumerate() {
				let asset = AssetId::from_byte_array(o.asset);
				match &o.kind {
					WantedKind::Leaf { .. } => {
						let spec = Self::spec(row, o)?;
						groups.entry(asset).or_default().push(Planned { participation: k, output: j as u16, spec });
					},
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

		// The fee asset: the round's own first, in the operator's order.
		let mut floors: BTreeMap<AssetId, Option<u64>> = BTreeMap::new();
		let round_assets: Vec<AssetId> = groups.keys().copied().chain(offboards.iter().map(|o| o.policy.destination.asset)).collect();
		for a in round_assets.iter().chain(p.fee_assets.iter()) {
			if !floors.contains_key(a) {
				let f = self.floor(*a).await?;
				floors.insert(*a, f);
			}
		}
		let accepted = |a: &AssetId| floors.get(a).copied().flatten().is_some();
		let fee_asset = p.fee_assets.iter().find(|a| round_assets.contains(a) && accepted(a))
			.or_else(|| p.fee_assets.iter().find(|a| accepted(a)))
			.copied()
			.ok_or_else(|| RoundError::NoFeeAsset(format!("{} batch asset(s), fee assets {:?}", groups.len(), p.fee_assets)))?;
		let fee_floor = floors[&fee_asset].expect("accepted");
		let connector = AssetAmount::new(fee_asset, fees::atoms_for(fee_floor, issuance_vsize(s, fee_asset), fees::MULTIPLE).max(1));

		// The schedule's times and each batch's reserve rule.
		let expiries = self.expiries(now)?;
		let reserves: BTreeMap<AssetId, ReserveRule> = groups.keys().map(|a| (*a, match floors[a] {
			Some(f) => ReserveRule::FeeRate { floor_per_kvb: f, multiple: fees::MULTIPLE },
			None => ReserveRule::Fixed { node: 1, entry: 1 },
		})).collect();
		let (radix, notice, chain) = (self.config.radix, self.config.notice, p.chain);

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
		let (built, trees) = self.wallet.build_round(groups.len(), fee_asset, connector, &forced, |tokens| {
			let mut outputs = vec![];
			let mut trees = vec![];
			for ((asset, leaves), token) in groups.iter().zip(tokens) {
				let schedule = ClockSchedule::new(*token, s, notice, expiries.clone()).map_err(|e| e.to_string())?;
				let params = TreeParams {
					asset: *asset, chain, schedule, burn: false, radix, reserve: reserves[asset],
					min_leaf: p.assets.get(asset).map(|a| a.min_leaf).unwrap_or(1),
				};
				let specs: Vec<LeafSpec> = leaves.iter().map(|l| l.spec).collect();
				let tree = Tree::build(params, &specs).map_err(|e| format!("the tree of asset {}: {}", asset, e))?;
				outputs.push(tree.batch_output());
				outputs.push(ExplicitOutput::new(*token, 1, tree.clock0_script_pubkey()));
				trees.push(tree);
			}
			for o in &offboards {
				outputs.push(o.policy.output(o.margin));
			}
			Ok((outputs, trees))
		}).await?;
		let tx = built.tx.clone();
		let txid = tx.txid();
		let c = built.connector_vout.expect("a round has a connector");
		let release = |e: RoundError| async move {
			if let Err(w) = self.wallet.release(&txid).await {
				log::error!("round {}: its coins could not be freed: {}", txid, w);
			}
			Err::<Option<Built>, RoundError>(e)
		};

		// Checked as a wallet would check it.
		let accept = WalletPolicy {
			min_exit_delay: p.min_exit_delay,
			max_exit_delay: p.max_exit_delay,
			..WalletPolicy::new(chain, s, now)
		};
		let mut new_batches = vec![];
		for (i, (tree, (asset, leaves))) in trees.iter().zip(&groups).enumerate() {
			let vout = 2 * i as u32;
			let mut new_leaves = vec![];
			for (j, (record, l)) in tree.records().into_iter().zip(leaves).enumerate() {
				let valid = match record.validate_round(&tx, &accept) {
					Ok(v) => v,
					Err(e) => return release(RoundError::Check(format!("leaf {} of batch {}: {}", j, i, e))).await,
				};
				if valid.batch_vout != vout {
					return release(RoundError::Check(format!("batch {} is at output {}, not {}", i, valid.batch_vout, vout))).await;
				}
				let row = &chosen[l.participation];
				let leaf_spk = valid.branch.leaf.script_pubkey();
				new_leaves.push(NewBatchLeaf {
					coin: NewCoin {
						leaf_id: valid.leaf_id.0,
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
					record: match record.to_bytes() {
						Ok(b) => b,
						Err(e) => return release(RoundError::Internal(e.to_string())).await,
					},
				});
			}
			// Every node and entry, so their outputs are seen once unrolled.
			let mut scripts = vec![];
			for (level, nodes) in tree.levels().iter().enumerate() {
				for (k, nd) in nodes.iter().enumerate() {
					scripts.push(NewTreeScript {
						script_pubkey: nd.output().script_pubkey.to_bytes(), kind: TreeScriptKind::Node,
						level: level as i16, idx: k as u32, value: nd.value,
					});
				}
			}
			for (k, l) in tree.leaves().iter().enumerate() {
				scripts.push(NewTreeScript {
					script_pubkey: l.entry.script_pubkey().to_bytes(), kind: TreeScriptKind::Entry,
					level: -1, idx: k as u32, value: l.entry_value,
				});
			}
			let tp = tree.params();
			new_batches.push(NewBatch {
				batch: BatchRow {
					round_id: 0,
					vout,
					asset: asset.into_inner().to_byte_array(),
					value: tree.batch_output().value,
					token: tp.schedule.token.into_inner().to_byte_array(),
					token_vout: vout + 1,
					issuer: (tx.input[i].previous_output.txid.to_byte_array(), tx.input[i].previous_output.vout),
					schedule: tp.schedule.encode(),
					burn: tp.burn,
					radix: tp.radix as u16,
					reserve: match tp.reserve {
						ReserveRule::FeeRate { floor_per_kvb, multiple } => StoredReserve::FeeRate { floor_per_kvb, multiple },
						ReserveRule::Fixed { node, entry } => StoredReserve::Fixed { node, entry },
					},
					min_leaf: tp.min_leaf,
				},
				leaves: new_leaves,
				scripts,
			});
		}
		if let Err(e) = (ConnectorPolicy { operator: s }).check(&tx, c) {
			return release(RoundError::Check(e.to_string())).await;
		}
		let mut new_offboards = vec![];
		for (k, o) in offboards.iter().enumerate() {
			let vout = 2 * trees.len() as u32 + k as u32;
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
		};
		let round_id = match self.store.insert_round(&new).await {
			Ok(id) => id,
			Err(e) => return release(e.into()).await,
		};
		let broadcast = self.submit(round_id, &tx, built.fee).await?;
		let batches: Vec<(AssetId, u32, usize)> = groups.iter().enumerate().map(|(i, (a, l))| (*a, 2 * i as u32, l.len())).collect();
		log::info!("round {} ({}): {} batch(es), {} offboard(s), {} participation(s), {} vB, fee {} of {}: {}",
			round_id, txid, batches.len(), offboards.len(), chosen.len(), tx.vsize(), built.fee.amount, fee_asset, broadcast);
		for row in chosen {
			self.store.set_waiting(&row.id, None).await?;
		}
		Ok(Some(Built {
			round_id, tx, batches, offboards: offboards.len(), participations: chosen.len(), connector_vout: c, broadcast,
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
		for r in self.store.rounds_in(RoundState::Built).await? {
			let tx: Transaction = deserialize(&r.tx).map_err(|e| RoundError::Internal(e.to_string()))?;
			let fee = AssetAmount::new(AssetId::from_byte_array(r.fee_asset), r.fee);
			self.submit(r.round_id, &tx, fee).await?;
		}
		// A round held as lost that is final again, before anything is
		// retired: the parent chain decides which round stands.
		for r in self.store.rounds_in(RoundState::Lost).await? {
			if self.finality.status(&Txid::from_byte_array(r.txid)).await.map_err(|e| RoundError::Chain(e.to_string()))?.is_final() {
				self.restore(&r).await?;
			}
		}
		let mut rows = self.store.rounds_in(RoundState::Broadcast).await?;
		rows.extend(self.store.rounds_in(RoundState::Final).await?);
		for r in rows {
			if self.nursery_lost(&r).await? {
				self.retire(&r).await?;
				continue;
			}
			self.check_round(&r).await?;
		}
		self.release_held().await?;
		self.expire().await?;
		self.void_overdue().await?;
		Ok(())
	}

	/// Releases every participation issued in a final round whose preimage
	/// is out, or which the operator can put out at will: one of its
	/// forfeits claimed by the watcher (whose claim reveals the preimage), or
	/// every forfeit of it whole, none of its coins taken on the chain
	/// otherwise than by its forfeit. Its new leaves are its owner's either
	/// way, so it is released and they are credited, as when the owner
	/// completes it itself; a forfeit step its owner can no longer finish (its
	/// coin on its way home on the chain, say) leaves nothing stranded.
	/// Returns them.
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
				match self.coin_taken_otherwise(&p).await? {
					None => "every forfeit of it is whole, so the operator can put its preimage out at will".to_string(),
					Some(how) => {
						log::warn!("participation {}: every forfeit of it is whole, but {}, otherwise than by its forfeit, so it is not \
							released", crate::signer::hex(&id), how);
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

	/// The first coin participation `p` gave up that the chain shows spent
	/// otherwise than by one of its forfeits in the watcher's log (its owner's
	/// claim once its exit delay ran, say), and how ([`Self::taken_otherwise`]):
	/// the operator can no longer take that coin by its forfeit. `None` when
	/// there is none.
	async fn coin_taken_otherwise(&self, p: &ParticipationRow) -> Result<Option<String>, RoundError> {
		let chain = |e: crate::chain::ChainError| RoundError::Chain(e.to_string());
		let mempool: HashSet<Txid> = self.finality.call(|c| c.mempool()).await.map_err(chain)?.into_iter().collect();
		for i in p.inputs.iter().filter(|i| !i.returned) {
			let mine: Vec<Txid> = self.store.watcher_txs("forfeit", &i.leaf_id).await?.iter().map(|w| Txid::from_byte_array(w.txid)).collect();
			if let Some(how) = self.taken_otherwise(&i.leaf_id, &mine, &mempool).await? {
				return Ok(Some(format!("coin {} was spent on the chain {}", LeafId(i.leaf_id), how)));
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
		let any_time = MedianTime::from_consensus(500_000_000).map_err(|e| RoundError::Internal(e.to_string()))?;
		let policy = WalletPolicy { horizon: 0, ..self.params.policy(any_time) };
		let mut earliest: Option<u32> = None;
		for i in &p.inputs {
			let c = match coins::resolve(&self.store, &policy, &LeafId(i.leaf_id)).await {
				Ok(c) => c,
				Err(coins::CoinError::Store(e)) => return Err(e.into()),
				Err(e) => {
					log::error!("participation {}: coin {} has no date the server can read: {}", crate::signer::hex(id), LeafId(i.leaf_id), e);
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
		let again = self.store.retire_round(r.round_id).await?;
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
		// A participation one of whose coins was spent on the chain otherwise
		// than by its forfeit for the round is its owner's again: its leaves
		// of the round are never credited.
		let uncredited = self.spent_otherwise(r.round_id).await?;
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
			burn: b.burn,
			radix: b.radix as usize,
			reserve: match b.reserve {
				StoredReserve::FeeRate { floor_per_kvb, multiple } => ReserveRule::FeeRate { floor_per_kvb, multiple },
				StoredReserve::Fixed { node, entry } => ReserveRule::Fixed { node, entry },
			},
			min_leaf: b.min_leaf,
		};
		let mut specs = Vec::with_capacity(leaves.len());
		for l in &leaves {
			specs.push(LeafSpec {
				template: l.template.parse::<Template>().map_err(|e| RoundError::Internal(e.to_string()))?,
				owner: elements::secp256k1_zkp::XOnlyPublicKey::from_slice(&l.owner_key).map_err(|e| RoundError::Internal(e.to_string()))?,
				value: l.value,
				owner_nonce: l.owner_nonce,
				operator_nonce: l.operator_nonce,
				exit_delay: RelativeTime::from_units(l.exit_delay_units).map_err(|e| RoundError::Internal(e.to_string()))?,
				unlock_hash: l.unlock_hash,
			});
		}
		let signer_head = self.store.round_signer_head(b.round_id).await?;
		Ok(Some(PublishedTree {
			round_txid: *txid, batch_vout: b.vout, token_vout: b.token_vout, connector_vout: round.connector_vout, params, leaves: specs,
			signer_head,
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
						match me.run_round().await {
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
