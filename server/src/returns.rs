//! 8. Returns: what no holder took up of a distribution goes back to its
//! payer ([`crate::participations::distributions`]).
//!
//! A `claim-1` leaf lapses by itself ([`arca_covenant::claim`]). Once its
//! distribution's deadline has passed, a claim leaf no holder took up (its
//! leaf live or pending, and the signer holding no spend under its salt) is
//! brought on the chain one step a pass, its path unrolled by the operator's
//! own authorisations (it is member 0 of every node) and its entry opened
//! with the distribution's preimage, as a coin is brought for its landing
//! ([`Watcher::bring_on_chain`]); once the leaf has waited its exit delay in
//! a block, its lapse pays the return script, its fee from the allowance
//! where the node takes the asset, else from a coin of the wallet's, the
//! whole value going back. The lapse is recorded against the claim as it is
//! published. A leaf that left the chain another way (its holder's exit) is
//! its holder's, and nothing more is done.
//!
//! The `vtxo-1` claim leaves of a distribution without a deadline:
//! A claim leaf is returned once a sweep of the watcher's that is final took
//! its value (spending the batch output, a node above the leaf, or the
//! leaf's entry) while the store records no spend of the leaf: its holder
//! never took it up, never gave it to a refresh, and never brought it on the
//! chain, where it would be the holder's alone and no sweep could take it.
//! The watcher pays the sum of such leaves of a distribution to its return
//! script, an explicit output in the distribution's asset, in a transaction
//! of the operator's wallet that pays its fee from the operator's own coins:
//! in the distribution's asset where the node takes it, else in the first of
//! the operator's fee assets it takes. The payment is recorded with the
//! claims it returns, whole, before the nursery broadcasts it; one recorded
//! and not in the nursery (the server stopped between the two) goes there at
//! the next pass, the same bytes. A sweep undone by a rollback undoes
//! nothing of a return made on it: the return is the operator's payment from
//! its own coins, and a holder who takes the leaf on the chain meanwhile
//! costs the operator that leaf, never the payer.

use super::*;

use crate::store::{ClaimRow, NurseryState, ReturnRow};
use crate::wallet::BuildRequest;
use crate::nursery::NurseryKind;

impl Watcher {
	/// Pays every return due: see the [module documentation](self).
	pub(super) async fn returns(&self) -> Result<(), WatcherError> {
		for r in self.store.returns().await? {
			if self.store.nursery_get(&r.txid).await?.is_none() {
				let tx: Transaction = deserialize(&r.tx).map_err(build("a recorded return"))?;
				let fee = AssetAmount::new(AssetId::from_byte_array(r.fee_asset), r.fee);
				self.nursery.submit(&tx, NurseryKind::Wallet, Some(fee)).await.map_err(|e| WatcherError::Nursery(e.to_string()))?;
			}
		}
		for id in self.store.distributions_open().await? {
			let r = self.return_of(&id).await;
			Self::item(&format!("the return of distribution {}", hex(&id)), r)?;
		}
		Ok(())
	}

	async fn return_of(&self, id: &[u8; 32]) -> Result<(), WatcherError> {
		let Some(d) = self.store.distribution(id).await? else { return Ok(()) };
		let open: Vec<&ClaimRow> = d.claims.iter()
			.filter(|c| c.returned_in.is_none() && c.lapsed_in.is_none()
				&& matches!(c.leaf_state, Some(LeafState::Live) | Some(LeafState::Pending))
				&& c.leaf_id.is_some())
			.collect();
		let mut due = vec![];
		let mut value: u64 = 0;
		// Each output's sweep is read once for the whole distribution: the
		// nursery may find a sweep final while the claims are gone through,
		// and every leaf that one sweep took is returned in one payment.
		let mut seen = HashMap::new();
		for c in open {
			if self.swept_final(&c.leaf_id.expect("filtered"), &mut seen).await? {
				due.push(c.idx);
				value = value.checked_add(c.value).ok_or_else(|| WatcherError::Build("a return above 2^64 atoms".into()))?;
			}
		}
		if due.is_empty() {
			return Ok(());
		}
		let asset = AssetId::from_byte_array(d.claims[0].asset);
		let mut fee_asset = None;
		for a in self.fee_assets(asset) {
			if self.accepted(a).await?.is_some() {
				fee_asset = Some(a);
				break;
			}
		}
		let fee_asset = fee_asset.ok_or_else(|| WatcherError::Build(format!("no asset of {:?} is accepted for fees by the node now",
			self.fee_assets(asset))))?;
		let output = ExplicitOutput::new(asset, value, Script::from(d.return_script.clone()));
		let built = self.wallet.build(&BuildRequest { outputs: vec![output], connector: None, fee_asset }).await?;
		let txid = built.tx.txid();
		let ret = ReturnRow {
			txid: txid.to_byte_array(),
			participation_id: *id,
			value,
			tx: serialize(&built.tx),
			fee_asset: built.fee.asset.into_inner().to_byte_array(),
			fee: built.fee.amount,
		};
		if !self.store.record_return(&ret, &due).await? {
			self.wallet.release(&txid).await?;
			return Ok(());
		}
		self.nursery.submit(&built.tx, NurseryKind::Wallet, Some(built.fee)).await.map_err(|e| WatcherError::Nursery(e.to_string()))?;
		log::info!("watcher: distribution {}: {} claim(s) no holder took up, {} of {}, paid back to its return script in {}", hex(id),
			due.len(), value, asset, txid);
		Ok(())
	}

	/// Lapses every claim-1 leaf no holder took up by its distribution's
	/// deadline: see the [module documentation](self).
	pub(super) async fn lapses(&self, now: MedianTime) -> Result<(), WatcherError> {
		for id in self.store.distributions_open().await? {
			let Some(d) = self.store.distribution(&id).await? else { continue };
			let Some(p) = self.store.participation(&id).await? else { continue };
			for c in &d.claims {
				let r = self.lapse_claim(&id, c, p.preimage, now).await;
				Self::item(&format!("the lapse of claim {} of distribution {}", c.idx, hex(&id)), r)?;
			}
		}
		Ok(())
	}

	/// One step of [`Watcher::lapses`] for the claim `c`: its leaf brought a
	/// step nearer the chain or, on the chain and its exit delay waited,
	/// lapsed.
	async fn lapse_claim(&self, id: &[u8; 32], c: &ClaimRow, preimage: [u8; 32], now: MedianTime) -> Result<(), WatcherError> {
		let (Some(lapse), Some(leaf)) = (&c.lapse, c.leaf_id) else { return Ok(()) };
		if c.lapsed_in.is_some() || c.returned_in.is_some() || now.to_consensus_u32() <= lapse.deadline.to_consensus_u32()
			|| !matches!(c.leaf_state, Some(LeafState::Live) | Some(LeafState::Pending))
		{
			return Ok(());
		}
		let coin = self.plan_leaf_coin(&leaf, preimage).await?;
		// A take-up co-signed before the deadline is its holder's way on.
		if !self.signer.under(&coin.leaf.salt).await?.is_empty() {
			return Ok(());
		}
		let script = coin.leaf.script_pubkey();
		let Some(at) = self.unspent_at(&script).await? else {
			// On the chain and spent (its holder's exit): nothing more.
			if !self.store.sightings_of(script.as_bytes()).await?.is_empty() {
				return Ok(());
			}
			log::info!("distribution {}: claim {} not taken up by its deadline {}: its leaf {} brought on the chain to lapse", hex(id),
				c.idx, lapse.deadline.to_consensus_u32(), coin.id);
			return self.bring_on_chain(&coin, now).await;
		};
		if let Some(w) = self.store.watcher_spend(&at.txid.to_byte_array(), at.vout).await? {
			if w.kind == "lapse" {
				self.store.record_lapse(id, c.idx, &w.txid).await?;
			}
			return Ok(());
		}
		if !self.confirmed(at).await? || !self.waited(at.txid, coin.leaf.exit_delay).await? {
			return Ok(());
		}
		let ret = lapse.return_script.clone();
		let (u, fee_coin, fee) = self.margin_or_coin(coin.asset, lapse.allowance, |fee| {
			let u = coin.leaf.lapse_tx(at, coin.value, &ret, fee).map_err(|e| e.to_string())?;
			let t = u.tx.clone();
			Ok((u, t))
		}).await?;
		let wallet = fee_coin.map(|c| (u.tx.input.len() - 1, c)).into_iter().collect();
		let published = self.publish(Ready { tx: u.tx, wallet, fee }, "lapse", leaf.to_vec(),
			format!("claim {} of distribution {}, not taken up by its deadline: its leaf {} at {} lapsed to the return script", c.idx, hex(id),
				coin.id, at)).await?;
		if let Some(txid) = published {
			self.store.record_lapse(id, c.idx, &txid.to_byte_array()).await?;
			log::info!("watcher: distribution {}: claim {} lapsed, {} of {} back to its return script in {}", hex(id), c.idx, coin.value,
				coin.asset, txid);
		}
		Ok(())
	}

	/// Whether a sweep of the watcher's that is final took the value of the
	/// batch leaf `leaf`: it spent the batch output, a node of the tree whose
	/// leaves include it, or its entry. Each output's sweep is read once into
	/// `seen`, so the leaves of one sweep get one answer.
	pub(super) async fn swept_final(&self, leaf: &[u8; 32], seen: &mut HashMap<OutPoint, bool>) -> Result<bool, WatcherError> {
		let Some(bl) = self.store.batch_leaf(leaf).await? else { return Ok(false) };
		let Some(round) = self.store.round(bl.round_id).await? else { return Ok(false) };
		let idx = bl.idx as usize;
		let mut above = vec![];
		if bl.kind == arca_covenant::BatchKind::Accumulator {
			// The batch output where its exits have left it, while it still
			// holds the leaf's slot, and the leaf's entry once an exit paid it.
			let acc = self.accumulator(&round, bl.vout).await?;
			if let Some((at, state, _)) = self.accumulator_now(&round, bl.vout, &acc).await? {
				if !state.bitmap.is_left(bl.idx as u16) {
					above.push(at);
				}
			}
			for s in self.store.tree_sightings(bl.round_id, bl.vout).await? {
				if s.kind == TreeScriptKind::Entry && s.idx as usize == idx {
					above.push(OutPoint::new(txid_of(&s.txid), s.vout));
				}
			}
		} else {
			let tree = self.tree(&round, bl.vout).await?;
			above.push(OutPoint::new(txid_of(&round.txid), bl.vout));
			for s in self.store.tree_sightings(bl.round_id, bl.vout).await? {
				let covers = match s.kind {
					TreeScriptKind::Node => tree.levels().get(s.level as usize).and_then(|l| l.get(s.idx as usize))
						.is_some_and(|n| n.leaves.contains(&idx)),
					TreeScriptKind::Entry => s.idx as usize == idx,
				};
				if covers {
					above.push(OutPoint::new(txid_of(&s.txid), s.vout));
				}
			}
		}
		for op in above {
			let swept = match seen.get(&op) {
				Some(s) => *s,
				None => {
					let s = self.store.watcher_spend(&op.txid.to_byte_array(), op.vout).await?
						.is_some_and(|w| w.kind == "sweep" && w.state == NurseryState::Final);
					seen.insert(op, s);
					s
				},
			};
			if swept {
				return Ok(true);
			}
		}
		Ok(false)
	}
}
