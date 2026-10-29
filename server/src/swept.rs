//! 9. What a sweep took from its holders: the operator's debts for swept
//! coins ([`crate::owed`]).
//!
//! At each pass the watcher counts every sweep of its own that has become
//! final and is not counted yet: the coins it took from their holders, each
//! recorded as owed in one database transaction with the sweep. A counted
//! sweep that a rollback takes out of finality has its entries withdrawn,
//! and given back once it is final again. Then each claimed entry follows its
//! repayment participation: repaid once that is released, owed again once it
//! is void or expired.

use std::collections::{HashMap, HashSet};

use super::*;

use crate::store::NewOwed;

impl Watcher {
	/// Counts every sweep due, moves every counted one whose finality moved,
	/// and settles every claim: see the [module documentation](self).
	pub(super) async fn owed(&self) -> Result<(), WatcherError> {
		for (txid, now_final) in self.store.owed_sweeps_moved().await? {
			if self.store.set_owed_sweep(&txid, now_final).await? {
				log::warn!("watcher: sweep {} is {}: what it owes is {}", Txid::from_byte_array(txid),
					if now_final { "final again" } else { "no longer final" }, if now_final { "owed again" } else { "withdrawn meanwhile" });
			}
		}
		for (txid, token) in self.store.sweeps_to_count().await? {
			let r = self.count_sweep(&txid, &token).await;
			Self::item(&format!("the coins sweep {} took", Txid::from_byte_array(txid)), r)?;
		}
		let (repaid, again) = self.store.settle_owed().await?;
		if repaid > 0 || again > 0 {
			log::info!("watcher: owed: {} coin(s) repaid, {} owed again (their repayment void or expired)", repaid, again);
		}
		Ok(())
	}

	/// Records what `sweep`, final, took from holders: every live coin of a
	/// batch of `token` whose value a final sweep took, and every live coin
	/// resting on one through out-of-round transfers. A coin whose own output
	/// is on the chain is its holder's there, and nothing is owed for it.
	async fn count_sweep(&self, sweep: &[u8; 32], token: &[u8]) -> Result<(), WatcherError> {
		let mut seen = HashMap::new();
		let mut stack: Vec<([u8; 32], bool)> = vec![];
		let mut expiry: Option<u32> = None;
		for (round_txid, vout) in self.store.batches_of_token(token).await? {
			let Some((b, leaves)) = self.store.batch(&round_txid, vout).await? else { continue };
			let schedule = ClockSchedule::decode(&b.schedule).map_err(build("the schedule"))?;
			let first = schedule.expiries()[0].to_consensus_u32();
			expiry = Some(expiry.map_or(first, |e| e.min(first)));
			for bl in leaves {
				if self.swept_final(&bl.leaf_id, &mut seen).await? {
					// A claim leaf of a distribution nobody took up goes back to
					// its payer ([`returns`]); the coins a holder made of one are
					// the holder's.
					let claim = self.store.is_distribution(&bl.participation_id).await?;
					stack.push((bl.leaf_id, claim));
				}
			}
		}
		// Each coin is read as it stood just before its batch expired, as a
		// wallet reads a coin past its expiry: every authorisation it holds
		// was usable then.
		let Some(expiry) = expiry else { return self.record_counted(sweep, &[]).await };
		let as_of = MedianTime::from_consensus(expiry.saturating_sub(1)).map_err(build("a median time"))?;
		let policy = WalletPolicy { horizon: 0, ..self.params.taken_policy(as_of) };
		let mut visited = HashSet::new();
		let mut entries = vec![];
		let mut fees: HashMap<AssetId, crate::params::FeeSchedule> = HashMap::new();
		while let Some((leaf, claim)) = stack.pop() {
			if !visited.insert(leaf) {
				continue;
			}
			let Some(row) = self.store.leaf(&leaf).await? else { continue };
			match row.state {
				LeafState::Live if !claim => {},
				LeafState::Spent => {
					for o in self.store.transfer_outputs_of(&leaf).await? {
						stack.push((o, false));
					}
					continue;
				},
				_ => continue,
			}
			if !self.store.sightings_of(&row.script_pubkey).await?.is_empty() {
				continue;
			}
			// The coin as its record resolves; a record that does not resolve
			// (the round's bounds have changed since, say) is read from its
			// row, so one coin never keeps a sweep from being counted.
			let (owner, asset, value, owner_nonce) = match coins::resolve(&self.store, &policy, &LeafId(leaf)).await {
				Ok(c) => {
					if c.coin.leaf.htlc.is_some() {
						log::info!("watcher: the sweep {} took htlc-1 leaf {}, which its payment's own paths settle: nothing is owed for it",
							Txid::from_byte_array(*sweep), LeafId(leaf));
						continue;
					}
					let value = match crate::channels::owner_share(&self.store, &LeafId(leaf), &c.coin.leaf).await? {
						Some((share, _)) => share,
						None => c.coin.value,
					};
					let Some(nonce) = owner_nonce_of(&c.record) else { continue };
					(c.coin.leaf.owner.serialize(), c.coin.asset, value, nonce)
				},
				Err(coins::CoinError::Store(e)) => return Err(e.into()),
				Err(e) => {
					let Ok(record) = CoinRecord::from_bytes(&row.record) else {
						log::warn!("watcher: the sweep {} took coin {}, whose record cannot be read ({}): nothing is recorded for it",
							Txid::from_byte_array(*sweep), LeafId(leaf), e);
						continue;
					};
					if htlc_of(&record) || channel_of(&record) {
						log::warn!("watcher: the sweep {} took coin {}, whose record does not resolve ({}), an htlc-1 or channel-1 leaf: \
							nothing is recorded for it", Txid::from_byte_array(*sweep), LeafId(leaf), e);
						continue;
					}
					let Some(nonce) = owner_nonce_of(&record) else { continue };
					log::warn!("watcher: the sweep {} took coin {}, whose record does not resolve ({}): owed as its row holds it",
						Txid::from_byte_array(*sweep), LeafId(leaf), e);
					(row.owner_key, AssetId::from_byte_array(row.asset), row.value, nonce)
				},
			};
			if value == 0 {
				continue;
			}
			let schedule = match fees.get(&asset) {
				Some(s) => s.clone(),
				None => {
					// Priced at the asset's rate now; with no rate yet the sweep
					// is counted at a later pass, whole.
					let s = self.params.fees(&asset).map_err(WatcherError::Build)?;
					fees.insert(asset, s.clone());
					s
				},
			};
			entries.push(NewOwed {
				leaf_id: leaf,
				owner_key: owner,
				owner_nonce,
				asset: asset.into_inner().to_byte_array(),
				value,
				fee: crate::owed::late_fee(&schedule, value),
			});
		}
		self.record_counted(sweep, &entries).await
	}

	async fn record_counted(&self, sweep: &[u8; 32], entries: &[NewOwed]) -> Result<(), WatcherError> {
		let owed: u128 = entries.iter().map(|e| (e.value - e.fee) as u128).sum();
		if let Some(n) = self.store.record_owed(sweep, entries).await? {
			log::info!("watcher: sweep {} is final: {} coin(s) it took from their holders are owed, {} atoms after the late-refresh fee",
				Txid::from_byte_array(*sweep), n, owed);
		}
		Ok(())
	}
}

/// Whether a coin's own leaf is an `htlc-1` leaf, as its record names it.
fn htlc_of(record: &CoinRecord) -> bool {
	match record {
		CoinRecord::Leaf { record, .. } => record.htlc.is_some(),
		CoinRecord::Accumulator { record, .. } => record.htlc.is_some(),
		CoinRecord::Transfer(t) => t.leaf.htlc.is_some(),
		CoinRecord::Fill(_) | CoinRecord::Board(_) => false,
	}
}

/// Whether a coin is a `channel-1` leaf, whose owner's side only its
/// resolved policy gives.
fn channel_of(record: &CoinRecord) -> bool {
	matches!(record, CoinRecord::Leaf { record, .. } if record.channel.is_some())
}

/// The nonce a coin's owner key comes from, as its record names it.
fn owner_nonce_of(record: &CoinRecord) -> Option<[u8; 32]> {
	match record {
		CoinRecord::Leaf { record, .. } => Some(record.owner_nonce),
		CoinRecord::Accumulator { record, .. } => Some(record.owner_nonce),
		CoinRecord::Transfer(t) => Some(t.leaf.owner_nonce),
		CoinRecord::Fill(f) => Some(f.leaf.owner_nonce()),
		CoinRecord::Board(b) => Some(b.owner_nonce),
	}
}
