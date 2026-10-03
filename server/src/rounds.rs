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
//! A participation's coins are checked again when a round is built, under a
//! horizon of one day before their first expiry ([`Params::round_policy`]): a
//! participation accepted before its coins' exit deadline still runs if a
//! round takes it by then, and one whose coin has passed it can never run and
//! is voided, its coins given back.
//!
//! The owner of each participation in a round hands over its forfeits once
//! the round is final, and has a day to ([`Params::FORFEIT_DEADLINE`]): a
//! participation whose forfeits have not come a day after its round was found
//! final expires. The coins it gave up are the owner's again (a coin under a
//! forfeit signed for an earlier, lost round excepted), and its new leaves are
//! never credited: their preimage never goes out, and the operator sweeps them
//! with their batch at expiry.
//!
//! After a rollback the nursery broadcasts a round again unchanged; while it
//! is out of the chain its new leaves are uncredited, and they are credited
//! again once it is final again. A round that can never return (an input of
//! it spent by another transaction that is final) is retired: its new leaves
//! are lost, and its participations run again in a later round under new
//! unlock hashes and operator nonces, forfeit-first where their preimage had
//! gone out, the releases given for it retired.
//!
//! Each batch is published ([`Rounds::tree`]): its round, its output, its
//! token's output, the round's connector output, its asset, schedule, radix,
//! reserve rule and smallest leaf, and every leaf as the builder took it, so
//! a wallet, or a mirror, rebuilds every script of the tree and checks it
//! against the round transaction from that alone.

use std::collections::BTreeMap;
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
	BatchRow, LeafKind, LeafState, NewBatch, NewBatchLeaf, NewCoin, NewOffboard, NewRound, NewScript, NewTreeScript, ParticipationRow,
	NurseryState, ParticipationState, RoundRow, RoundState, ScriptKind, Store, StoreError, StoredReserve, TreeScriptKind, WantedKind,
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
		let policy = self.params.round_policy(now);
		for i in &p.inputs {
			match coins::check(&self.store, &policy, &LeafId(i.leaf_id), &p.id, Params::ROUND_HORIZON).await {
				Ok(_) => {},
				Err(coins::CoinError::Store(e)) => return Err(e.into()),
				Err(coins::CoinError::InvalidCoin {
					error: arca_covenant::TransferError::Record(arca_covenant::RecordError::ExpiryTooSoon { .. }), ..
				}) | Err(coins::CoinError::PastBoardDate { .. }) => {
					let voided = self.store.void_participation(&p.id).await?;
					log::warn!("participation {} can never run: coin {} is past its last round time (voided: {})",
						crate::signer::hex(&p.id), LeafId(i.leaf_id), voided);
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
				let voided = self.store.void_participation(&row.id).await?;
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
		let mut chosen = self.fundable(chosen, now).await?;
		loop {
			if chosen.is_empty() {
				return Ok(None);
			}
			match self.build_from(&chosen, now).await {
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

	/// Builds, checks, records and broadcasts the round of `chosen`.
	async fn build_from(&self, chosen: &[ParticipationRow], now: MedianTime) -> Result<Option<Built>, RoundError> {
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
		let (built, trees) = self.wallet.build_round(groups.len(), fee_asset, connector, |tokens| {
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

	/// One pass over every round not lost: a round recorded but never handed
	/// to the nursery goes to it; one the nursery found can never return is
	/// retired; one the finality service calls final is marked final, and the
	/// new leaves of its released participations are credited; one no longer
	/// final goes back to broadcast, its leaves uncredited. Then every
	/// participation whose forfeits are overdue expires.
	pub async fn pass(&self) -> Result<(), RoundError> {
		for r in self.store.rounds_in(RoundState::Built).await? {
			let tx: Transaction = deserialize(&r.tx).map_err(|e| RoundError::Internal(e.to_string()))?;
			let fee = AssetAmount::new(AssetId::from_byte_array(r.fee_asset), r.fee);
			self.submit(r.round_id, &tx, fee).await?;
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
		self.expire().await?;
		Ok(())
	}

	/// Expires every participation whose round was found final more than
	/// [`Params::FORFEIT_DEADLINE`] ago and whose forfeits have not come.
	/// Returns them.
	pub async fn expire(&self) -> Result<Vec<[u8; 32]>, RoundError> {
		let now = self.now().await?.to_consensus_u32();
		let expired = self.store.expire_participations(now.saturating_sub(Params::FORFEIT_DEADLINE)).await?;
		for id in &expired {
			log::warn!("participation {} expired: its forfeits did not come within a day of its round being final; \
				its coins are given back, its new leaves are never credited", crate::signer::hex(id));
		}
		Ok(expired)
	}

	/// Whether the nursery has found that the round can never return: a
	/// final transaction of another txid spent one of its inputs.
	async fn nursery_lost(&self, r: &RoundRow) -> Result<bool, RoundError> {
		Ok(self.store.nursery_get(&r.txid).await?.is_some_and(|n| n.state == NurseryState::Lost))
	}

	/// Retires a round that can never return: its unspent new leaves are
	/// lost, and its participations run again in a later round under new
	/// unlock hashes, forfeit-first where their preimage had gone out.
	async fn retire(&self, r: &RoundRow) -> Result<(), RoundError> {
		let again = self.store.retire_round(r.round_id).await?;
		log::warn!("round {} ({}) can never return: retired; {} participation(s) run again, {} of them forfeit-first",
			r.round_id, Txid::from_byte_array(r.txid), again.len(), again.iter().filter(|(_, f)| *f).count());
		Ok(())
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
		Ok(Some(PublishedTree {
			round_txid: *txid, batch_vout: b.vout, token_vout: b.token_vout, connector_vout: round.connector_vout, params, leaves: specs,
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
