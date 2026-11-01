use std::collections::HashSet;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use anyhow::Context;
use bdk_esplora::EsploraAsyncExt;
use bdk_wallet::chain::{Anchor, ChainPosition, CheckPoint, ConfirmationBlockTime, Indexer, TxUpdate};
use bdk_wallet::Wallet as BdkWallet;
use bdk_wallet::coin_selection::DefaultCoinSelectionAlgorithm;
use bdk_wallet::signer::SignerOrdering;
use bdk_wallet::{Balance, KeychainKind, LoadError, LocalOutput, TxBuilder, TxOrdering, Update};
use bitcoin::{
	Address, Amount, FeeRate, Network, Psbt, Script, Sequence, Transaction, TxOut,
	Txid, Weight, bip32, psbt,
};
use log::{debug, error, info, trace, warn};

use ark::vtxo::policy::signing::VtxoSigner;
use bitcoin_ext::{BlockHeight, DEEPLY_CONFIRMED, TransactionExt};
use bitcoin_ext::bdk::{CpfpInternalError, WalletExt};
use bitcoin_ext::cpfp::CpfpError;

use crate::Wallet;
use crate::chain::{ChainSource, ChainSourceClient};
use crate::exit::{ExitVtxo, ExitState};
use crate::onchain::{
	CpfpWalkEstimate, FundingShortfall, LocalUtxo, MakeCpfpFees, Utxo, OnchainWalletTrait,
	WalletTxInfo,
};
use crate::persist::BarkPersister;
use crate::psbtext::PsbtInputExt;

const STOP_GAP: usize = 50;
const PARALLEL_REQS: usize = 4;
const GENESIS_HEIGHT: u32 = 0;
/// Minimum age (by `last_seen`) a locally-unconfirmed tx must reach before a
/// sync is allowed to evict it for being absent from the node's mempool.
///
/// A tx is marked seen (`apply_unconfirmed_txs`) as soon as it's signed, not
/// once it's actually reached the node: e.g. a board's funding tx is applied
/// locally in `finish_psbt`, then only broadcast after a cosign round-trip
/// with the Ark server. Without this grace period, a sync landing in that gap
/// would see the tx as absent from the node's mempool and evict it, handing
/// its inputs back to the next coin selection while the "evicted" tx is still
/// in flight and about to land in the mempool anyway -- a self-inflicted
/// double-spend. A tx that's genuinely gone just gets evicted one sync later.
const ONCHAIN_EVICTION_GRACE_SECS: u64 = 30;

impl From<LocalOutput> for LocalUtxo {
	fn from(value: LocalOutput) -> Self {
		LocalUtxo {
			outpoint: value.outpoint,
			amount: value.txout.value,
			confirmation_height: value.chain_position.confirmation_height_upper_bound(),
		}
	}
}

/// Trait extension for TxBuilder to add exit outputs
///
/// When used, the resulting PSBT should be signed using
/// [crate::exit::Exit::sign_exit_claim_inputs].
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait TxBuilderExt: Send + Sync {
	async fn add_exit_claim_inputs(
		&mut self,
		wallet: &Wallet,
		exit_outputs: &[&ExitVtxo],
	) -> anyhow::Result<()>;
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<Cs: Send + Sync> TxBuilderExt for TxBuilder<'_, Cs> {
	async fn add_exit_claim_inputs(
		&mut self,
		wallet: &Wallet,
		exit_outputs: &[&ExitVtxo],
	) -> anyhow::Result<()> {
		self.version(2);

		for input in exit_outputs {
			if !matches!(input.state(), ExitState::Claimable(..)) {
				bail!("VTXO exit is not spendable");
			}

			// Claiming an exit needs the full vtxo: the PSBT input embeds the
			// serialized full bytes (including the genesis chain) so the
			// claim signer can reconstruct the spend.
			let vtxo = wallet.inner.db.get_full_vtxo(input.id()).await?
				.context(format!("Unable to load VTXO for exit: {}", input.id()))?;
			let mut psbt_in = psbt::Input::default();
			psbt_in.set_exit_claim_input(&vtxo);
			psbt_in.witness_utxo = Some(TxOut {
				script_pubkey: vtxo.output_script_pubkey(),
				value: vtxo.amount(),
			});

			let clause = wallet.find_signable_clause(&vtxo).await
				.context("Cannot sign vtxo")?;

			let witness_weight = {
				let witness_size = clause.witness_size(&vtxo);
				Weight::from_witness_data_size(witness_size as u64)
			};

			self.add_foreign_utxo_with_sequence(
				vtxo.point(),
				psbt_in,
				witness_weight,
				clause.sequence().unwrap_or(Sequence::ZERO),
			).expect("error adding foreign utxo for claim input");
		}

		Ok(())
	}
}

/// Map the internal BDK CPFP error onto the public [CpfpError] surface.
fn cpfp_internal_to_error(e: CpfpInternalError) -> CpfpError {
	match e {
		CpfpInternalError::General(s) => CpfpError::InternalError(s),
		CpfpInternalError::Create(e) => CpfpError::CreateError(e.to_string()),
		CpfpInternalError::Extract(e) => CpfpError::FinalizeError(e.to_string()),
		CpfpInternalError::Fee() => CpfpError::InternalError(CpfpInternalError::Fee().to_string()),
		CpfpInternalError::FinalizeError(s) => CpfpError::FinalizeError(s),
		CpfpInternalError::InsufficientConfirmedFunds(f) => {
			CpfpError::InsufficientConfirmedFunds {
				needed: f.needed, available: f.available,
			}
		},
		CpfpInternalError::NoFeeAnchor(txid) => CpfpError::NoFeeAnchor(txid),
		CpfpInternalError::Signer(e) => CpfpError::SigningError(e.to_string()),
	}
}

/// A throwaway, in-memory replica of a wallet, used only for fee estimation.
///
/// The broadcast-walk estimate inserts CPFP children as *confirmed*, which BDK can't undo. Running
/// it on a replica keeps that mutation off the live wallet.
pub struct EstimationWallet {
	inner: BdkWallet,
}

impl EstimationWallet {
	/// Build a replica from a snapshot of `wallet`'s live components (chain, tx graph, keychain
	/// index and locked outpoints — staged changes included), reusing its signers so the replica
	/// builds and signs transactions exactly like the original would.
	pub fn new(wallet: &BdkWallet) -> Result<EstimationWallet, LoadError> {
		let mut changeset = bdk_wallet::ChangeSet {
			network: Some(wallet.network()),
			local_chain: wallet.local_chain().initial_changeset(),
			tx_graph: wallet.tx_graph().initial_changeset(),
			indexer: wallet.spk_index().initial_changeset(),
			..Default::default()
		};
		for (keychain, descriptor) in wallet.keychains() {
			match keychain {
				KeychainKind::External => changeset.descriptor = Some(descriptor.clone()),
				KeychainKind::Internal => changeset.change_descriptor = Some(descriptor.clone()),
			}
		}
		changeset.locked_outpoints.outpoints = wallet.list_locked_outpoints()
			.map(|outpoint| (outpoint, true))
			.collect();

		let mut inner = BdkWallet::load()
			.check_network(wallet.network())
			.load_wallet_no_persist(changeset)?
			.expect("changeset carries a descriptor");

		// The changeset only carries public descriptors, so hand the original's signers over.
		for keychain in [KeychainKind::External, KeychainKind::Internal] {
			for signer in wallet.get_signers(keychain).signers() {
				inner.add_signer(keychain, SignerOrdering::default(), Arc::clone(signer));
			}
		}

		Ok(EstimationWallet { inner })
	}

	/// Insert a CPFP child into the replica as confirmed, anchored at its tip, so the next child
	/// can spend its change.
	fn apply_cpfp_child(&mut self, child: &Transaction) {
		let mut tx_update = TxUpdate::default();
		tx_update.txs.push(Arc::new(child.clone()));

		tx_update.anchors.insert((
			ConfirmationBlockTime {
				block_id: self.inner.latest_checkpoint().block_id(),
				confirmation_time: 0,
			},
			child.compute_txid(),
		));

		self.inner.apply_update(Update { tx_update, ..Default::default() })
			.expect("anchor block is the replica's own tip");
	}

	/// Build one CPFP child per parent, funding each from confirmed coins and recycling each
	/// child's change into the next (the serial order the packages really confirm in). Each child
	/// is returned with the exact package fee it commits, which an RBF minimum can push above
	/// rate × weight. Stops early when confirmed funds run out, reporting the shortfall.
	pub fn estimate_p2a_cpfp_walk(
		&mut self,
		parents: &[(Transaction, MakeCpfpFees)],
	) -> Result<CpfpWalkEstimate, CpfpInternalError> {
		let mut children = Vec::with_capacity(parents.len());
		for (parent, fees) in parents {
			let child = match self.inner.make_signed_p2a_cpfp(parent, *fees) {
				Ok(child) => child,
				Err(CpfpInternalError::InsufficientConfirmedFunds(e)) => {
					return Ok(CpfpWalkEstimate {
						children,
						shortfall: Some(FundingShortfall {
							needed: e.needed,
							available: e.available,
						}),
					});
				},
				Err(e) => return Err(e),
			};

			let (_, anchor_txout) = parent.fee_anchor()
				.expect("make_signed_p2a_cpfp succeeded on this parent");
			// The replica wallet knows all inputs but the anchor
			let funding_value = anchor_txout.value + child.input.iter()
				.filter_map(|input| {
					self.inner.tx_graph().get_txout(input.previous_output)
						.map(|txout| txout.value)
				})
				.sum::<Amount>();
			// The parent is zero-fee, so the child pays the whole package fee: everything its
			// inputs bring in beyond its own outputs.
			let fee = funding_value.checked_sub(child.output_value())
				.unwrap_or_default();

			self.apply_cpfp_child(&child);

			children.push((child, fee));
		}

		Ok(CpfpWalkEstimate { children, shortfall: None })
	}
}

/// A basic wrapper around the bdk wallet to showcase
/// how to use bark with an external onchain wallet.
///
/// Note: BDK wallet already implements all the traits
/// to be used as an onboard and exit wallet, so that
/// wrapper only needs to proxy the methods.
pub struct OnchainWallet {
	pub inner: BdkWallet,
	db: Arc<dyn BarkPersister>,
}

impl Deref for OnchainWallet {
	type Target = BdkWallet;

	fn deref(&self) -> &Self::Target {
		&self.inner
	}
}

impl DerefMut for OnchainWallet {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.inner
	}
}

impl OnchainWallet {
	pub async fn load_or_create(network: Network, seed: [u8; 64], db: Arc<dyn BarkPersister>) -> anyhow::Result<Self> {
		let xpriv = bip32::Xpriv::new_master(network, &seed).expect("valid seed");
		let desc = bdk_wallet::template::Bip86(xpriv, KeychainKind::External);

		let changeset = db.initialize_bdk_wallet().await.context("error reading bdk wallet state")?;
		let wallet_opt = bdk_wallet::Wallet::load()
			.descriptor(bdk_wallet::KeychainKind::External, Some(desc.clone()))
			.extract_keys()
			.check_network(network)
			.load_wallet_no_persist(changeset)?;

		let wallet = match wallet_opt {
			Some(wallet) => wallet,
			None => bdk_wallet::Wallet::create_single(desc)
				.network(network)
				.create_wallet_no_persist()?,
		};

		Ok(Self { inner: wallet, db })
	}

	/// The wallet of the seed's BIP84 account (`m/84'/coin'/0'`, receive and
	/// change): native segwit coins, the account a wallet that shares one
	/// address across Bitcoin and another chain already holds its BTC in.
	/// Given to [crate::Wallet] as its onchain wallet, it pays an exit's fees
	/// from those same coins, with no second on-chain wallet to fund.
	///
	/// Its first scan should be [OnchainWallet::initial_wallet_scan]: the
	/// account's coins sit at addresses this wallet has not revealed.
	pub async fn load_or_create_bip84(network: Network, seed: [u8; 64], db: Arc<dyn BarkPersister>) -> anyhow::Result<Self> {
		let xpriv = bip32::Xpriv::new_master(network, &seed).expect("valid seed");
		let desc = bdk_wallet::template::Bip84(xpriv, KeychainKind::External);
		let change = bdk_wallet::template::Bip84(xpriv, KeychainKind::Internal);

		let changeset = db.initialize_bdk_wallet().await.context("error reading bdk wallet state")?;
		let wallet_opt = bdk_wallet::Wallet::load()
			.descriptor(KeychainKind::External, Some(desc.clone()))
			.descriptor(KeychainKind::Internal, Some(change.clone()))
			.extract_keys()
			.check_network(network)
			.load_wallet_no_persist(changeset)?;

		let wallet = match wallet_opt {
			Some(wallet) => wallet,
			None => bdk_wallet::Wallet::create(desc, change)
				.network(network)
				.create_wallet_no_persist()?,
		};

		Ok(Self { inner: wallet, db })
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl OnchainWalletTrait for OnchainWallet {
	async fn balance(&self) -> Amount {
		self.inner.balance().total()
	}

	async fn address(&mut self) -> anyhow::Result<Address> {
		let ret = self.inner.reveal_next_address(bdk_wallet::KeychainKind::External).address;
		self.persist().await?;
		Ok(ret)
	}

	async fn sync(&mut self, chain: &ChainSource) -> anyhow::Result<()> {
		OnchainWallet::sync(self, chain).await
	}

	async fn is_mine(&self, spk: &Script) -> anyhow::Result<bool> {
		Ok(self.inner.is_mine(spk.to_owned()))
	}

	async fn register_tx(&mut self, tx: &Transaction) -> anyhow::Result<()> {
		self.inner.apply_unconfirmed_txs([(tx.clone(), bark_runtime::timestamp_secs())]);
		self.persist().await
	}

	async fn evict_tx(&mut self, txid: Txid) -> anyhow::Result<()> {
		self.inner.apply_evicted_txs([(txid, bark_runtime::timestamp_secs())]);
		self.persist().await
	}

	async fn prepare_tx(
		&mut self,
		destinations: &[(Address, Amount)],
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt> {
		let mut b = self.inner.build_tx();
		b.ordering(TxOrdering::Untouched);
		for (dest, amount) in destinations {
			b.add_recipient(dest.script_pubkey(), *amount);
		}
		b.fee_rate(fee_rate);
		b.finish().context("error building tx")
	}

	async fn prepare_drain_tx(
		&mut self,
		destination: Address,
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt> {
		let mut b = self.inner.build_tx();
		b.drain_to(destination.script_pubkey());
		b.fee_rate(fee_rate);
		b.drain_wallet();
		b.finish().context("error building tx")
	}

	async fn finish_psbt(&mut self, mut psbt: Psbt) -> anyhow::Result<Psbt> {
		#[allow(deprecated)]
		let opts = bdk_wallet::SignOptions {
			trust_witness_utxo: true,
			..Default::default()
		};
		let finalized = self.inner.sign(&mut psbt, opts).context("signing error")?;
		ensure!(finalized, "failed to succesfully sign the tx");
		let tx = psbt.clone().extract_tx()?;
		self.inner.apply_unconfirmed_txs([(tx, bark_runtime::timestamp_secs())]);
		self.persist().await?;
		Ok(psbt)
	}

	async fn make_signed_p2a_cpfp(
		&mut self,
		tx: &Transaction,
		fees: MakeCpfpFees,
	) -> Result<Transaction, CpfpError> {
		WalletExt::make_signed_p2a_cpfp(&mut self.inner, tx, fees)
			.inspect_err(|e| error!("Error creating signed P2A CPFP: {}", e))
			.map_err(cpfp_internal_to_error)
	}

	fn estimate_p2a_cpfp_walk(
		&self,
		parents: &[(Transaction, MakeCpfpFees)],
	) -> Result<CpfpWalkEstimate, CpfpError> {
		EstimationWallet::new(&self.inner)
			.map_err(|e| CpfpError::InternalError(format!("failed to build estimation wallet: {}", e)))
			.and_then(|mut w| w.estimate_p2a_cpfp_walk(parents).map_err(cpfp_internal_to_error))
			.inspect_err(|e| error!("Error estimating P2A CPFP walk: {}", e))
	}

	async fn store_signed_p2a_cpfp(&mut self, tx: &Transaction) -> anyhow::Result<(), CpfpError> {
		self.inner.apply_unconfirmed_txs([(tx.clone(), bark_runtime::timestamp_secs())]);
		trace!("Unconfirmed txs: {:?}", self.unconfirmed_txids().collect::<Vec<_>>());
		self.persist().await
			.map_err(|e| CpfpError::StoreError(e.to_string()))
	}
}

impl OnchainWallet {
	pub async fn sync(&mut self, chain: &ChainSource) -> anyhow::Result<()> {
		debug!("Starting wallet sync...");
		debug!("Starting balance: {}", self.inner.balance());
		trace!("Starting unconfirmed txs: {:?}", self.unconfirmed_txids().collect::<Vec<_>>());

		match chain.inner() {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { sync, .. } => {
				let prev_tip = self.inner.latest_checkpoint();
				self.inner_sync_bitcoind(sync, prev_tip).await?;
			},
			ChainSourceClient::Esplora(client) => {
				debug!("Syncing with esplora...");

				// Don't sync the entire transaction history of the wallet. We can safely filter out
				// anything deeply confirmed.
				let min_height = self.inner.latest_checkpoint()
					.height()
					.checked_sub(DEEPLY_CONFIRMED)
					.unwrap_or(0);

				let request = self.inner.start_sync_with_revealed_spks_at(bark_runtime::timestamp_secs())
					.outpoints(self.list_unspent().iter().map(|o| o.outpoint))
					.txids(self.inner.transactions().filter_map(|tx| {
						let fresh = match tx.chain_position {
							ChainPosition::Unconfirmed { .. } => true,
							ChainPosition::Confirmed { anchor, .. } => {
								anchor.anchor_block().height >= min_height
							},
						};
						if fresh {
							Some(tx.tx_node.txid)
						} else {
							None
						}
					}));

				let mut update = client.sync(request, PARALLEL_REQS).await?;

				// Esplora's indexer runs behind the mempool: a tx broadcast
				// moments ago can still be absent from its response and BDK
				// will report it as evicted. Drop such evictions here so we
				// don't hand a freshly-spent UTXO back to coin selection
				// before the tx actually confirms; see ONCHAIN_EVICTION_GRACE_SECS.
				let now = bark_runtime::timestamp_secs();
				let recently_seen: HashSet<Txid> = self.inner.transactions()
					.filter_map(|tx| match tx.chain_position {
						ChainPosition::Unconfirmed { last_seen: Some(seen), .. }
							if now.saturating_sub(seen) < ONCHAIN_EVICTION_GRACE_SECS => {
							Some(tx.tx_node.txid)
						},
						_ => None,
					})
					.collect();
				update.tx_update.evicted_ats.retain(|(txid, _)| {
					if recently_seen.contains(txid) {
						debug!("Not evicting recently-seen tx {} still within grace period", txid);
						false
					} else {
						true
					}
				});

				self.inner.apply_update(update)?;
				self.persist().await?;
				debug!("Finished syncing with esplora");
			},
		}

		debug!("Current balance: {}", self.inner.balance());
		trace!("Current unconfirmed txs: {:?}", self.unconfirmed_txids().collect::<Vec<_>>());
		self.rebroadcast_txs(chain, bark_runtime::timestamp_secs()).await?;

		Ok(())
	}

	pub fn balance(&self) -> Balance {
		self.inner.balance()
	}

	pub fn list_unspent(&self) -> Vec<LocalOutput> {
		self.inner.list_unspent().collect()
	}

	pub fn list_transactions(&self) -> Vec<Arc<Transaction>> {
		self.inner.transactions().map(|tx| tx.tx_node.tx).collect()
	}

	/// List every wallet transaction with fee, balance change, and confirmation.
	///
	/// Fees are `None` for txs whose foreign prevouts BDK has not indexed: see
	/// [`WalletTxInfo::onchain_fees`].
	pub fn list_transaction_infos(&self) -> anyhow::Result<Vec<WalletTxInfo>> {
		let mut out = Vec::new();
		for canon in self.inner.transactions() {
			let txid = canon.tx_node.txid;
			let tx = canon.tx_node.tx.clone();

			let confirmation = match canon.chain_position {
				ChainPosition::Confirmed { anchor, .. } => Some(anchor.block_id.into()),
				ChainPosition::Unconfirmed { .. } => None,
			};

			let (sent, received) = self.inner.sent_and_received(&tx);
			let balance_change = received.to_signed().context("received overflow")?
				- sent.to_signed().context("sent overflow")?;

			let onchain_fees = self.inner.calculate_fee(&tx).ok();

			// A P2A fee anchor is anyone-can-spend (BIP-431), so its spend
			// carries no signature: both witness and script_sig are empty.
			let is_cpfp = tx.input.iter()
				.any(|i| i.witness.is_empty() && i.script_sig.is_empty());

			out.push(WalletTxInfo {
				txid,
				tx,
				onchain_fees,
				balance_change,
				confirmation,
				is_cpfp,
			});
		}
		Ok(out)
	}

	pub fn utxos(&self) -> Vec<Utxo> {
		self.list_unspent().into_iter().map(|o| Utxo::Local(o.into())).collect()
	}

	pub async fn send(&mut self, chain: &ChainSource, dest: Address, amount: Amount, fee_rate: FeeRate
	)	-> anyhow::Result<Txid> {
		let psbt = self.prepare_tx(&[(dest, amount)], fee_rate).await?;
		let tx = self.finish_psbt(psbt).await?.extract_tx()?;
		chain.broadcast_tx(&tx).await?;
		Ok(tx.compute_txid())
	}

	pub async fn send_many(
		&mut self,
		chain: &ChainSource,
		destinations: &[(Address, Amount)],
		fee_rate: FeeRate,
	) -> anyhow::Result<Txid> {
		let pbst = self.prepare_tx(destinations, fee_rate).await?;
		let tx = self.finish_psbt(pbst).await?.extract_tx()?;
		chain.broadcast_tx(&tx).await?;
		Ok(tx.compute_txid())
	}


	pub async fn drain(
		&mut self,
		chain: &ChainSource,
		destination: Address,
		fee_rate: FeeRate,
	) -> anyhow::Result<Txid> {
		let psbt = self.prepare_drain_tx(destination, fee_rate).await?;
		let tx = self.finish_psbt(psbt).await?.extract_tx()?;
		chain.broadcast_tx(&tx).await?;
		Ok(tx.compute_txid())
	}

	pub fn build_tx(&mut self) -> TxBuilder<'_, DefaultCoinSelectionAlgorithm> {
		self.inner.build_tx()
	}

	#[cfg(feature = "bitcoind-rpc")]
	async fn inner_sync_bitcoind(
		&mut self,
		bitcoind_sync: &bitcoin_ext::rpc::BitcoinRpcClient,
		prev_tip: CheckPoint,
	) -> anyhow::Result<()> {
		debug!("Syncing with bitcoind, starting at block height {}...", prev_tip.height());
		// Checkpoints a reorg has orphaned cannot take a block below them, so
		// the emitter then restarts below the orphaned range, and the range
		// is applied in one update once it is all in hand (see
		// `ReorgRepair`): nothing of it lands, or is persisted, before.
		let plan_rpc = bitcoind_sync.clone();
		let plan_tip = prev_tip.clone();
		let plan = tokio::task::spawn_blocking(move || plan_reorg_repair(&plan_rpc, &plan_tip))
			.await.context("reorg repair task panicked")??;
		let mut repair = plan.map(|plan| {
			warn!("The wallet's chain left the node's above height {}: rescanning from height {}",
				plan.agreement.height, plan.resume.height + 1);
			ReorgRepair::new(plan)
		});
		let prev_tip = match &repair {
			Some(r) => r.emitter_start(),
			None => prev_tip,
		};
		// `bdk_bitcoind_rpc::Emitter` is sync-only upstream. Run it on a
		// blocking thread and stream blocks back over a channel so we can
		// persist progress incrementally and yield to the runtime.
		// NB We pass start_height=0 so the Emitter never skips blocks.
		// Using prev_tip.height() would cause the Emitter to jump from the
		// agreement point directly to prev_tip on the new chain after a deep
		// reorg, producing a gap that BDK cannot merge.
		let sync_rpc = bitcoind_sync.clone();
		let prev_tip_clone = prev_tip.clone();
		// Materialize the unconfirmed-tx iterator before crossing the thread
		// boundary; bdk's iterator borrows wallet state and is not Send.
		let unconfirmed: Vec<_> = self.unconfirmed_txs().collect();
		let (block_tx, mut block_rx) =
			tokio::sync::mpsc::channel::<bdk_bitcoind_rpc::BlockEvent<bitcoin::Block>>(8);
		let (mempool_tx, mempool_rx) =
			tokio::sync::oneshot::channel::<bdk_bitcoind_rpc::MempoolEvent>();
		let emitter_handle = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
			let mut emitter = bdk_bitcoind_rpc::Emitter::new(
				&sync_rpc, prev_tip_clone, 0, unconfirmed,
			);
			while let Some(em) = emitter.next_block()? {
				if block_tx.blocking_send(em).is_err() {
					return Ok(());
				}
			}
			drop(block_tx);
			let _ = mempool_tx.send(emitter.mempool()?);
			Ok(())
		});

		let mut count = 0;
		while let Some(em) = block_rx.recv().await {
			if let Some(r) = repair.as_mut() {
				let (height, connected_to) = (em.block_height(), em.connected_to());
				if r.push(em.block, height, connected_to)? {
					let update = r.update(&self.inner);
					self.inner.apply_update(update).context("applying the rescanned range")?;
					repair = None;
				}
				continue;
			}
			self.inner.apply_block_connected_to(
				&em.block, em.block_height(), em.connected_to(),
			)?;
			count += 1;

			if count % 10_000 == 0 {
				self.persist().await?;
				info!("Synced until block height {}", em.block_height());
			}
		}
		emitter_handle.await.context("wallet sync blocking task panicked")??;
		// The node's chain ended below the top of the range (it is shorter now).
		if let Some(r) = repair.take() {
			let update = r.update(&self.inner);
			self.inner.apply_update(update).context("applying the rescanned range")?;
		}

		if let Ok(mempool) = mempool_rx.await {
			let now = bark_runtime::timestamp_secs();
			let recently_seen: HashSet<Txid> = self.inner.transactions()
				.filter_map(|tx| match tx.chain_position {
					ChainPosition::Unconfirmed { last_seen: Some(seen), .. }
						if now.saturating_sub(seen) < ONCHAIN_EVICTION_GRACE_SECS => {
						Some(tx.tx_node.txid)
					},
					_ => None,
				})
				.collect();
			let evicted = mempool.evicted.into_iter().filter(|(txid, _)| {
				if recently_seen.contains(txid) {
					debug!("Not evicting recently-seen tx {} still within grace period", txid);
					false
				} else {
					true
				}
			});
			self.inner.apply_evicted_txs(evicted);
			self.inner.apply_unconfirmed_txs(mempool.update);
		}
		self.persist().await?;
		debug!("Finished syncing with bitcoind");

		Ok(())
	}

	async fn rebroadcast_txs(&mut self, chain: &ChainSource, sync_start: u64) -> anyhow::Result<Amount> {
		let balance = self.inner.balance();

		// Ultimately, let's try to rebroadcast all our unconfirmed txs.
		let transactions = self.inner.transactions().filter(|tx| {
			if let ChainPosition::Unconfirmed { last_seen, .. } = tx.chain_position {
				match last_seen {
					Some(last_seen) => last_seen < sync_start,
					None => true,
				}
			} else {
				false
			}
		}).collect::<Vec<_>>();

		for tx in transactions {
			if let Err(e) = chain.broadcast_tx(&tx.tx_node.tx).await {
				warn!("Error broadcasting tx {}: {}", tx.tx_node.txid, e);
			}
		}

		Ok(balance.total())
	}

	pub async fn initial_wallet_scan(
		&mut self,
		chain: &ChainSource,
		start_height: Option<BlockHeight>,
	) -> anyhow::Result<Amount> {
		info!("Starting initial wallet sync...");
		debug!("Starting balance: {}", self.inner.balance());

		match chain.inner() {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { rpc, sync } => {
				use bitcoind_async_client::traits::Reader;
				// Make sure we include the given start_height in the scan
				let height = start_height.unwrap_or(GENESIS_HEIGHT).saturating_sub(1);
				let block_hash = rpc.get_block_hash(height as u64).await?;
				self.inner.set_checkpoint(height, block_hash);
				self.inner_sync_bitcoind(sync, self.inner.latest_checkpoint()).await?;
			},
			// Esplora can't do a full scan from a given block height, so we can ignore start_height
			ChainSourceClient::Esplora(client) => {
				debug!("Starting full scan with esplora...");
				let request = self.inner.start_full_scan_at(bark_runtime::timestamp_secs());
				let update = client.full_scan(request, STOP_GAP, PARALLEL_REQS).await?;
				self.inner.apply_update(update)?;
				self.persist().await?;
				debug!("Finished scanning with esplora");
			},
		}

		debug!("Current balance: {}", self.inner.balance());
		self.rebroadcast_txs(chain, bark_runtime::timestamp_secs()).await
	}


	async fn persist(&mut self) -> anyhow::Result<()> {
		if let Some(stage) = self.inner.staged() {
			self.db.store_bdk_wallet_changeset(&*stage).await?;
			let _ = self.inner.take_staged();
		}
		Ok(())
	}
}

/// How far below the lowest orphaned checkpoint a repaired wallet rescans.
#[cfg(feature = "bitcoind-rpc")]
const REORG_RESCAN_MARGIN: u32 = 6;

/// A wallet whose newest checkpoints a reorg orphaned: where its chain agrees
/// with the node's, where to rescan from, and up to where.
#[cfg(feature = "bitcoind-rpc")]
#[derive(Debug, Clone, Copy)]
struct ReorgRepairPlan {
	/// The highest of the wallet's checkpoints the node agrees with.
	agreement: bdk_wallet::chain::BlockId,
	/// The node's block the rescan starts after: a few below the lowest
	/// orphaned checkpoint, never below `agreement`.
	resume: bdk_wallet::chain::BlockId,
	/// The highest orphaned checkpoint the node has a block at.
	top: BlockHeight,
}

/// The node's hash at `height`, or `None` above its tip.
#[cfg(feature = "bitcoind-rpc")]
fn node_block_hash<C: bitcoin_ext::rpc::RpcApi>(rpc: &C, height: BlockHeight) -> anyhow::Result<Option<bitcoin::BlockHash>> {
	use bitcoin_ext::rpc::{Error, jsonrpc};
	match rpc.get_block_hash(height as u64) {
		Ok(hash) => Ok(Some(hash)),
		// RPC_INVALID_PARAMETER: "Block height out of range"
		Err(Error::JsonRpc(jsonrpc::Error::Rpc(e))) if e.code == -8 => Ok(None),
		Err(e) => Err(e).context("getblockhash"),
	}
}

/// Whether the wallet's newest checkpoints have left the node's chain, and if
/// so the plan to bring it back. A wallet whose tip the node holds costs one
/// `getblockhash`.
///
/// BDK never applies a block below a checkpoint it cannot prove invalid, so a
/// wallet whose newest checkpoints were orphaned, with its next older one far
/// below (a fresh wallet holds only its birthday's above genesis), would fail
/// every block the emitter gave it ("cannot connect with the original
/// chain"), for good (arca#440).
#[cfg(feature = "bitcoind-rpc")]
fn plan_reorg_repair<C: bitcoin_ext::rpc::RpcApi>(
	rpc: &C,
	tip: &CheckPoint,
) -> anyhow::Result<Option<ReorgRepairPlan>> {
	let mut stale_below_tip = Vec::new();
	let mut any_stale = false;
	let mut agreement = None;
	for cp in tip.iter() {
		match node_block_hash(rpc, cp.height())? {
			Some(hash) if hash == cp.hash() => {
				agreement = Some(cp.block_id());
				break;
			},
			Some(_) => stale_below_tip.push(cp.height()),
			None => {},
		}
		any_stale = true;
	}
	if !any_stale {
		return Ok(None);
	}
	let agreement = agreement.context(
		"no checkpoint of the wallet, not even genesis, is on the node's chain: another network?")?;
	// Orphaned checkpoints all above the node's tip: the node is behind the
	// wallet, and there is nothing to replace them with yet.
	let (Some(&top), Some(&lowest)) = (stale_below_tip.iter().max(), stale_below_tip.iter().min()) else {
		return Ok(None);
	};
	let resume_height = lowest.saturating_sub(REORG_RESCAN_MARGIN + 1).max(agreement.height);
	let resume = if resume_height == agreement.height {
		agreement
	} else {
		let hash = node_block_hash(rpc, resume_height)?.context("the node's chain shrank while it was read")?;
		bdk_wallet::chain::BlockId { height: resume_height, hash }
	};
	Ok(Some(ReorgRepairPlan { agreement, resume, top }))
}

/// The blocks of a repair's range, gathered from the emitter until the range
/// is complete, then applied with the node's chain in one update.
///
/// Applying the replacement chain first and rescanning after would let an
/// interrupted rescan leave a tip that agrees with the node above blocks that
/// were never scanned, so a coin paid in them would never show (arca#451).
/// The chain is also taken from the blocks themselves, each checked to link
/// to the one before, so a reorg while it runs cannot leave a chain mixing
/// two branches: the range restarts where the emitter does, or the sync stops
/// and the next one plans again.
#[cfg(feature = "bitcoind-rpc")]
struct ReorgRepair {
	plan: ReorgRepairPlan,
	blocks: Vec<(bdk_wallet::chain::BlockId, bitcoin::Block)>,
}

#[cfg(feature = "bitcoind-rpc")]
impl ReorgRepair {
	fn new(plan: ReorgRepairPlan) -> Self {
		ReorgRepair { plan, blocks: Vec::new() }
	}

	/// Where the emitter starts: the agreement and the resume point only, so
	/// it checks both against the node and emits the range after them.
	fn emitter_start(&self) -> CheckPoint {
		let mut ids = vec![self.plan.agreement];
		if self.plan.resume.height > self.plan.agreement.height {
			ids.push(self.plan.resume);
		}
		CheckPoint::from_block_ids(ids).expect("ascending heights")
	}

	/// Takes the emitter's next block; true once the range is complete.
	fn push(
		&mut self,
		block: bitcoin::Block,
		height: BlockHeight,
		connected_to: bdk_wallet::chain::BlockId,
	) -> anyhow::Result<bool> {
		if connected_to.height < self.plan.resume.height {
			anyhow::bail!("the node's chain moved below height {} while the wallet rescanned it: \
				the next sync starts again", self.plan.resume.height);
		}
		// A reorg while it runs: the emitter goes back and offers the new
		// branch from there.
		self.blocks.retain(|(id, _)| id.height < height);
		let prev = self.blocks.last().map(|(id, _)| *id).unwrap_or(self.plan.resume);
		if prev.height + 1 != height || prev.hash != block.header.prev_blockhash {
			anyhow::bail!("block {} does not follow block {}: the next sync starts again", height, prev.height);
		}
		self.blocks.push((bdk_wallet::chain::BlockId { height, hash: block.block_hash() }, block));
		Ok(height >= self.plan.top)
	}

	/// One update: the node's chain from the agreement through every block
	/// in hand, and the transactions in them that touch the wallet.
	fn update(&self, wallet: &BdkWallet) -> Update {
		let mut ids = vec![self.plan.agreement];
		if self.plan.resume.height > self.plan.agreement.height {
			ids.push(self.plan.resume);
		}
		ids.extend(self.blocks.iter().map(|(id, _)| *id));
		let chain = CheckPoint::from_block_ids(ids).expect("linked, ascending heights");
		let mut tx_update = TxUpdate::<ConfirmationBlockTime>::default();
		// Outputs of transactions taken so far: a later one in the range that
		// spends them touches the wallet too, though its index cannot see it.
		let mut taken = HashSet::new();
		for (id, block) in &self.blocks {
			for tx in &block.txdata {
				let spends_taken = tx.input.iter().any(|i| taken.contains(&i.previous_output));
				if !spends_taken && !wallet.spk_index().inner().is_relevant(tx) {
					continue;
				}
				let txid = tx.compute_txid();
				taken.extend((0..tx.output.len() as u32).map(|vout| bitcoin::OutPoint::new(txid, vout)));
				tx_update.txs.push(Arc::new(tx.clone()));
				tx_update.anchors.insert((
					ConfirmationBlockTime { block_id: *id, confirmation_time: block.header.time as u64 },
					txid,
				));
			}
		}
		Update { chain: Some(chain), tx_update, ..Default::default() }
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use std::collections::HashSet;

	use bdk_wallet::chain::BlockId;
	use bdk_wallet::test_utils::{get_test_wpkh, insert_checkpoint, receive_output_in_latest_block};
	use bitcoin::{BlockHash, OutPoint};
	use bitcoin::hashes::Hash;

	/// A wallet with one confirmed UTXO per given amount.
	fn funded_wallet(amounts: &[Amount]) -> BdkWallet {
		let mut wallet = BdkWallet::create_single(get_test_wpkh())
			.network(Network::Regtest)
			.create_wallet_no_persist()
			.unwrap();
		insert_checkpoint(&mut wallet, BlockId { height: 1_000, hash: BlockHash::all_zeros() });
		for amount in amounts {
			receive_output_in_latest_block(&mut wallet, *amount);
		}
		wallet
	}

	/// A zero-fee v3 parent carrying a P2A fee anchor; `tag` makes its txid unique.
	fn p2a_parent(tag: u8) -> Transaction {
		Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![bitcoin::TxIn {
				previous_output: OutPoint::new(Txid::from_byte_array([tag; 32]), 0),
				..Default::default()
			}],
			output: vec![bitcoin_ext::fee::fee_anchor()],
		}
	}

	#[test]
	fn estimation_wallet_replicates_and_isolates() {
		let wallet = funded_wallet(&[Amount::from_sat(1_000), Amount::from_sat(1_001)]);
		let mut replica = EstimationWallet::new(&wallet).unwrap();

		assert_eq!(wallet.balance(), replica.inner.balance());
		assert_eq!(
			wallet.list_unspent().map(|u| u.outpoint).collect::<Vec<_>>(),
			replica.inner.list_unspent().map(|u| u.outpoint).collect::<Vec<_>>(),
		);
		assert_eq!(
			wallet.next_derivation_index(KeychainKind::External),
			replica.inner.next_derivation_index(KeychainKind::External),
		);

		// The replica must sign with the original's keys, and mutating it must not leak into
		// the original wallet.
		let parent = p2a_parent(1);
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(1).unwrap());
		let child = replica.inner.make_signed_p2a_cpfp(&parent, fees).unwrap();
		assert_eq!(wallet.balance().confirmed, Amount::from_sat(2_001));
		assert!(wallet.get_tx(child.compute_txid()).is_none());
	}

	/// With a single-coin wallet, every CPFP child after the first can only be funded by the
	/// previous child's change: the walk must model that serial recycling.
	#[test]
	fn cpfp_walk_recycles_change_serially() {
		let wallet = funded_wallet(&[Amount::from_sat(50_000)]);
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(10).unwrap());
		let parents = (1..=3).map(|tag| (p2a_parent(tag), fees)).collect::<Vec<_>>();

		let walk = EstimationWallet::new(&wallet).unwrap().estimate_p2a_cpfp_walk(&parents).unwrap();
		assert!(walk.shortfall.is_none());
		assert_eq!(walk.children.len(), 3);

		for (i, (child, fee)) in walk.children.iter().enumerate() {
			let anchor_point = parents[i].0.fee_anchor().unwrap().0;
			assert!(child.input.iter().any(|input| input.previous_output == anchor_point));
			assert_eq!(child.input.len(), 2, "anchor spend plus a single funding input");
			assert_eq!(child.output.len(), 1, "drain output only");
			// The parent is zero-fee, so the effective-rate child pays exactly the package fee.
			assert_eq!(*fee, fees.effective() * (parents[i].0.weight() + child.weight()));
			if i > 0 {
				let (prev_child, _) = &walk.children[i - 1];
				let prev_change = OutPoint::new(prev_child.compute_txid(), 0);
				assert!(
					child.input.iter().any(|input| input.previous_output == prev_change),
					"child {} must be funded by the previous child's change", i,
				);
				// Funded solely by the previous change, so the reported fee must be exactly
				// the value that change lost.
				assert_eq!(*fee, prev_child.output[0].value - child.output[0].value);
			}
		}

		// The walk runs against a replica; the wallet itself stays untouched.
		assert_eq!(wallet.balance().confirmed, Amount::from_sat(50_000));
		assert!(wallet.get_tx(walk.children[0].0.compute_txid()).is_none());
	}

	/// Whatever coins each child selects, no coin may fund two children: earlier estimation
	/// re-ran selection against the same unchanged wallet, double-counting the same UTXO.
	#[test]
	fn cpfp_walk_never_double_spends_across_children() {
		// NB identical amounts would produce identical funding txids and collapse into one UTXO.
		// No coin covers a ~1150-sat package fee plus non-dust change alone, so children have to
		// combine coins.
		let amounts = (0..5).map(|i| Amount::from_sat(1_000 + i)).collect::<Vec<_>>();
		let wallet = funded_wallet(&amounts);
		let original_coins = wallet.list_unspent()
			.map(|u| u.outpoint)
			.collect::<HashSet<_>>();
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(4).unwrap());
		let parents = (1..=2).map(|tag| (p2a_parent(tag), fees)).collect::<Vec<_>>();

		let walk = EstimationWallet::new(&wallet).unwrap().estimate_p2a_cpfp_walk(&parents).unwrap();
		assert!(walk.shortfall.is_none());
		assert_eq!(walk.children.len(), 2);

		let change_outputs = walk.children.iter()
			.map(|(child, _)| OutPoint::new(child.compute_txid(), 0))
			.collect::<HashSet<_>>();
		let mut spent = HashSet::new();
		for ((child, _), (parent, _)) in walk.children.iter().zip(&parents) {
			let anchor_point = parent.fee_anchor().unwrap().0;
			for input in &child.input {
				if input.previous_output == anchor_point {
					continue;
				}
				let coin = input.previous_output;
				assert!(
					original_coins.contains(&coin) || change_outputs.contains(&coin),
					"funding input {} must be a wallet coin or an earlier child's change", coin,
				);
				assert!(spent.insert(coin), "coin {} funds two children", coin);
			}
		}
	}

	#[test]
	fn cpfp_walk_reports_shortfall() {
		// 3000 sats fund the first ~2200-sat package but its change can't fund the second.
		let wallet = funded_wallet(&[Amount::from_sat(3_000)]);
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(10).unwrap());
		let parents = (1..=2).map(|tag| (p2a_parent(tag), fees)).collect::<Vec<_>>();

		let walk = EstimationWallet::new(&wallet).unwrap().estimate_p2a_cpfp_walk(&parents).unwrap();
		assert_eq!(walk.children.len(), 1);
		let (first_child, first_fee) = &walk.children[0];
		// The single coin funds the first child entirely, so wallet value splits exactly into
		// the reported fee and the change.
		assert_eq!(*first_fee + first_child.output[0].value, Amount::from_sat(3_000));
		let shortfall = walk.shortfall.expect("second bump must exceed the remaining change");
		assert!(shortfall.needed > shortfall.available);
		assert_eq!(shortfall.available, first_child.output[0].value);
	}

	/// A throwaway regtest bitcoind (`BITCOIND_EXEC`), stopped and removed on drop.
	#[cfg(feature = "bitcoind-rpc")]
	struct Regtest { child: std::process::Child, dir: std::path::PathBuf, url: String }

	#[cfg(feature = "bitcoind-rpc")]
	impl Regtest {
		fn start(exe: &str) -> Regtest {
			let port = || std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
			let (rpc_port, p2p_port) = (port(), port());
			let dir = std::env::temp_dir().join(format!("bark-reorg-{}-{}", std::process::id(), rpc_port));
			std::fs::create_dir_all(&dir).unwrap();
			let child = std::process::Command::new(exe)
				.args(["-regtest", "-listen=0", "-txindex=0", "-fallbackfee=0.0001", "-server=1"])
				.arg(format!("-datadir={}", dir.display()))
				.arg(format!("-rpcport={}", rpc_port)).arg(format!("-port={}", p2p_port))
				.stdout(std::process::Stdio::null()).spawn().expect("start bitcoind");
			Regtest { child, dir, url: format!("http://127.0.0.1:{}", rpc_port) }
		}
		fn client(&self, path: &str) -> bitcoin_ext::rpc::BitcoinRpcClient {
			let cookie = self.dir.join("regtest/.cookie");
			for _ in 0..300 {
				if cookie.exists() {
					let c = bitcoin_ext::rpc::BitcoinRpcClient::new(&format!("{}{}", self.url, path),
						bitcoin_ext::rpc::Auth::CookieFile(cookie.clone())).unwrap();
					if bitcoin_ext::rpc::RpcApi::get_block_count(&c).is_ok() {
						return c;
					}
				}
				std::thread::sleep(std::time::Duration::from_millis(100));
			}
			panic!("bitcoind did not answer");
		}
	}

	#[cfg(feature = "bitcoind-rpc")]
	impl Drop for Regtest {
		fn drop(&mut self) {
			let _ = self.child.kill();
			let _ = self.child.wait();
			let _ = std::fs::remove_dir_all(&self.dir);
		}
	}

	/// An RPC client that records each call, and can fail every `getblock`
	/// after some, or run a hook just before the `getblock` of some index.
	#[cfg(feature = "bitcoind-rpc")]
	struct Counted<'a> {
		inner: &'a bitcoin_ext::rpc::BitcoinRpcClient,
		calls: std::sync::Mutex<Vec<String>>,
		fail_getblock_after: Option<usize>,
		hook: std::sync::Mutex<Option<(usize, Box<dyn FnOnce() + Send + 'a>)>>,
	}

	#[cfg(feature = "bitcoind-rpc")]
	impl<'a> Counted<'a> {
		fn new(inner: &'a bitcoin_ext::rpc::BitcoinRpcClient) -> Self {
			Counted { inner, calls: Default::default(), fail_getblock_after: None, hook: Default::default() }
		}
		fn count(&self, cmd: &str) -> usize {
			self.calls.lock().unwrap().iter().filter(|c| *c == cmd).count()
		}
	}

	#[cfg(feature = "bitcoind-rpc")]
	impl<'a> bitcoin_ext::rpc::RpcApi for Counted<'a> {
		fn call<T: for<'b> serde::de::Deserialize<'b>>(&self, cmd: &str, args: &[serde_json::Value])
			-> Result<T, bitcoin_ext::rpc::Error>
		{
			let n = self.count(cmd);
			if cmd == "getblock" {
				let mut h = self.hook.lock().unwrap();
				if h.as_ref().map(|(at, _)| *at == n).unwrap_or(false) {
					let (_, f) = h.take().unwrap();
					f();
				}
				if self.fail_getblock_after.map(|k| n >= k).unwrap_or(false) {
					self.calls.lock().unwrap().push(cmd.to_string());
					return Err(bitcoin_ext::rpc::Error::ReturnedError("the connection dropped".into()));
				}
			}
			self.calls.lock().unwrap().push(cmd.to_string());
			bitcoin_ext::rpc::RpcApi::call(self.inner, cmd, args)
		}
	}

	/// The bitcoind sync as `inner_sync_bitcoind` does it, minus persistence
	/// and the mempool: the repair plan (unless `repair` is false, the sync
	/// before arca#440), the emitter, the repaired range applied in one
	/// update once complete, every later block with `apply_block_connected_to`.
	#[cfg(feature = "bitcoind-rpc")]
	fn emitter_sync<C: bitcoin_ext::rpc::RpcApi>(wallet: &mut BdkWallet, rpc: &C, repair: bool) -> anyhow::Result<()> {
		let plan = if repair { plan_reorg_repair(rpc, &wallet.latest_checkpoint())? } else { None };
		let mut repair = plan.map(ReorgRepair::new);
		let start = match &repair { Some(r) => r.emitter_start(), None => wallet.latest_checkpoint() };
		let mut emitter = bdk_bitcoind_rpc::Emitter::new(rpc, start, 0, Vec::<Arc<Transaction>>::new());
		while let Some(em) = emitter.next_block()? {
			if let Some(r) = repair.as_mut() {
				let (height, connected_to) = (em.block_height(), em.connected_to());
				if r.push(em.block, height, connected_to)? {
					let update = r.update(wallet);
					wallet.apply_update(update)?;
					repair = None;
				}
				continue;
			}
			wallet.apply_block_connected_to(&em.block, em.block_height(), em.connected_to())?;
		}
		if let Some(r) = repair.take() {
			let update = r.update(wallet);
			wallet.apply_update(update)?;
		}
		Ok(())
	}

	/// The heights whose checkpoint the node's chain does not hold.
	#[cfg(feature = "bitcoind-rpc")]
	fn off_chain(w: &BdkWallet, rpc: &bitcoin_ext::rpc::BitcoinRpcClient) -> Vec<u32> {
		use bitcoin_ext::rpc::RpcApi;
		let top = rpc.get_block_count().unwrap() as u32;
		let mut v: Vec<u32> = w.latest_checkpoint().iter()
			.filter(|cp| cp.height() > top || rpc.get_block_hash(cp.height() as u64).unwrap() != cp.hash())
			.map(|cp| cp.height()).collect();
		v.sort();
		v
	}

	/// A regtest node with 110 blocks, its miner's wallet, and how to mine.
	#[cfg(feature = "bitcoind-rpc")]
	fn reorg_setup(exe: &str) -> (Regtest, bitcoin_ext::rpc::BitcoinRpcClient, bitcoin_ext::rpc::BitcoinRpcClient) {
		use serde_json::json;
		let node = Regtest::start(exe);
		let rpc = node.client("");
		let _: serde_json::Value = bitcoin_ext::rpc::RpcApi::call(&rpc, "createwallet", &[json!("miner")]).unwrap();
		let miner = node.client("/wallet/miner");
		mine(&miner, 110);
		(node, rpc, miner)
	}

	#[cfg(feature = "bitcoind-rpc")]
	fn mine(miner: &bitcoin_ext::rpc::BitcoinRpcClient, n: u64) {
		use serde_json::json;
		let a: String = bitcoin_ext::rpc::RpcApi::call(miner, "getnewaddress", &[]).unwrap();
		let _: Vec<BlockHash> = bitcoin_ext::rpc::RpcApi::call(miner, "generatetoaddress", &[json!(n), json!(a)]).unwrap();
	}

	/// A wallet born at 105 (its checkpoint at 104, as `initial_wallet_scan`
	/// sets it), synced to the tip.
	#[cfg(feature = "bitcoind-rpc")]
	fn born(rpc: &bitcoin_ext::rpc::BitcoinRpcClient) -> BdkWallet {
		use bitcoin_ext::rpc::RpcApi;
		let mut w = BdkWallet::create_single(get_test_wpkh())
			.network(Network::Regtest).create_wallet_no_persist().unwrap();
		w.set_checkpoint(104, rpc.get_block_hash(104).unwrap());
		emitter_sync(&mut w, rpc, false).unwrap();
		assert_eq!(w.latest_checkpoint().height(), rpc.get_block_count().unwrap() as u32);
		w
	}

	/// A reorg from below the wallets' birthday: blocks 100 on are orphaned;
	/// the new branch pays `payee` 1 BTC at 103 and grows to 112.
	#[cfg(feature = "bitcoind-rpc")]
	fn reorg_paying(rpc: &bitcoin_ext::rpc::BitcoinRpcClient, miner: &bitcoin_ext::rpc::BitcoinRpcClient, payee: &mut BdkWallet) {
		use bitcoin_ext::rpc::RpcApi;
		use serde_json::json;
		let orphaned = rpc.get_block_hash(100).unwrap();
		let _: serde_json::Value = rpc.call("invalidateblock", &[json!(orphaned.to_string())]).unwrap();
		mine(miner, 3);
		let addr = payee.reveal_next_address(KeychainKind::External).address;
		let _: Txid = miner.call("sendtoaddress", &[json!(addr.to_string()), json!(1.0)]).unwrap();
		mine(miner, 10);
		assert_eq!(rpc.get_block_count().unwrap(), 112);
	}

	/// arca#440: a wallet born just before a reorg holds only genesis and the
	/// orphaned checkpoints from its birthday up. The plain sync then fails
	/// every block ("cannot connect with the original chain"), for good; with
	/// the repair it follows the node's chain and sees a coin paid there.
	#[cfg(feature = "bitcoind-rpc")]
	#[test]
	fn bitcoind_sync_survives_a_reorg_of_its_newest_checkpoints() {
		use bitcoin_ext::rpc::RpcApi;
		let Ok(exe) = std::env::var("BITCOIND_EXEC") else {
			eprintln!("BITCOIND_EXEC is not set: skipped");
			return;
		};
		let (_node, rpc, miner) = reorg_setup(&exe);
		let mut plain = born(&rpc);
		let mut repaired = born(&rpc);
		reorg_paying(&rpc, &miner, &mut repaired);

		let err = emitter_sync(&mut plain, &rpc, false).unwrap_err();
		eprintln!("the plain sync after the reorg: {err:#}");
		assert!(err.to_string().contains("cannot connect"), "the plain sync failed otherwise: {err:#}");

		emitter_sync(&mut repaired, &rpc, true).unwrap();
		assert_eq!(repaired.latest_checkpoint().height(), 112);
		assert_eq!(repaired.latest_checkpoint().hash(), rpc.get_block_hash(112).unwrap());
		assert_eq!(off_chain(&repaired, &rpc), Vec::<u32>::new());
		assert_eq!(repaired.balance().confirmed, Amount::from_sat(100_000_000));
		// And a second sync has nothing left to repair.
		assert!(plan_reorg_repair(&rpc, &repaired.latest_checkpoint()).unwrap().is_none());
		emitter_sync(&mut repaired, &rpc, true).unwrap();
	}

	/// A wallet whose tip the node holds costs the repair one call, also when
	/// the node is ahead of it.
	#[cfg(feature = "bitcoind-rpc")]
	#[test]
	fn reorg_repair_costs_a_healthy_wallet_one_call() {
		let Ok(exe) = std::env::var("BITCOIND_EXEC") else { eprintln!("BITCOIND_EXEC is not set: skipped"); return };
		let (_node, rpc, miner) = reorg_setup(&exe);
		let w = born(&rpc);
		for ahead in [0, 1] {
			mine(&miner, ahead);
			let c = Counted::new(&rpc);
			assert!(plan_reorg_repair(&c, &w.latest_checkpoint()).unwrap().is_none());
			assert_eq!(*c.calls.lock().unwrap(), vec!["getblockhash".to_string()], "node {ahead} ahead");
		}
	}

	/// arca#451 (a): the rescan of the repaired range stops two blocks in (the
	/// connection drops). Nothing of the range was applied, so the next sync
	/// plans the repair again and finds the coin paid in the range.
	#[cfg(feature = "bitcoind-rpc")]
	#[test]
	fn an_interrupted_rescan_is_redone_by_the_next_sync() {
		let Ok(exe) = std::env::var("BITCOIND_EXEC") else { eprintln!("BITCOIND_EXEC is not set: skipped"); return };
		let (_node, rpc, miner) = reorg_setup(&exe);
		let mut w = born(&rpc);
		let tip_before = w.latest_checkpoint().block_id();
		reorg_paying(&rpc, &miner, &mut w);

		let mut flaky = Counted::new(&rpc);
		flaky.fail_getblock_after = Some(2);
		let err = emitter_sync(&mut w, &flaky, true).unwrap_err();
		eprintln!("the interrupted sync: {err:#}");
		assert_eq!(w.latest_checkpoint().block_id(), tip_before, "part of the range was applied");
		assert!(plan_reorg_repair(&rpc, &w.latest_checkpoint()).unwrap().is_some());

		emitter_sync(&mut w, &rpc, true).unwrap();
		assert_eq!(w.latest_checkpoint().height(), 112);
		assert_eq!(off_chain(&w, &rpc), Vec::<u32>::new());
		assert_eq!(w.balance().confirmed, Amount::from_sat(100_000_000));
	}

	/// arca#451 (b): a second reorg, from 102, lands while the range is being
	/// rescanned. The range follows the emitter onto the new branch, and the
	/// wallet ends on the node's chain with nothing off it.
	#[cfg(feature = "bitcoind-rpc")]
	#[test]
	fn a_reorg_during_the_rescan_leaves_one_chain() {
		use bitcoin_ext::rpc::RpcApi;
		use serde_json::json;
		let Ok(exe) = std::env::var("BITCOIND_EXEC") else { eprintln!("BITCOIND_EXEC is not set: skipped"); return };
		let (_node, rpc, miner) = reorg_setup(&exe);
		let mut w = born(&rpc);
		reorg_paying(&rpc, &miner, &mut w);

		let c = Counted::new(&rpc);
		let (rpc2, miner2) = (rpc.clone(), miner.clone());
		*c.hook.lock().unwrap() = Some((5, Box::new(move || {
			let h = rpc2.get_block_hash(102).unwrap();
			let _: serde_json::Value = rpc2.call("invalidateblock", &[json!(h.to_string())]).unwrap();
			mine(&miner2, 13);
		})));
		let first = emitter_sync(&mut w, &c, true);
		assert!(c.hook.lock().unwrap().is_none(), "the second reorg never happened during the rescan");
		match first {
			Ok(()) => {},
			// Stopped by the move: the next sync starts again.
			Err(e) => {
				eprintln!("the sync during the second reorg: {e:#}");
				emitter_sync(&mut w, &rpc, true).unwrap();
			},
		}
		assert_eq!(w.latest_checkpoint().height(), rpc.get_block_count().unwrap() as u32);
		assert_eq!(off_chain(&w, &rpc), Vec::<u32>::new());
		// The coin was in 103 of the first new branch; the second reorg
		// orphaned that block, so the payment is back in the mempool at most.
		eprintln!("after both reorgs: confirmed {}", w.balance().confirmed);
	}
}
