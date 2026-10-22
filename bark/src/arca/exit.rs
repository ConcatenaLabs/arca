//! The unilateral exit, from the coin's record alone, and `sync`.
//!
//! A coin goes on-chain without the operator: for a leaf of a batch, every
//! node from the batch output down by the owner's own unroll authorisations,
//! then the entry with the preimage; for a board, the owner's conversion; for
//! a coin a reassignment made, each coin it rests on, its checkpoint and the
//! reassignment, all from the pairs in the record. Then, once the exit delay
//! has run from the leaf's confirmation, the owner's claim to an on-chain
//! address of the wallet, one address for the exit however often it runs.
//!
//! The record says what the coin is; the chain says where its path is. Every
//! run starts from the lowest output of the path that is unspent in a block
//! or the mempool, matched by asset, value and script, never by transaction
//! id: a round that returned under another id after a rollback, a step
//! someone else published, or a board its owner converted is taken as the
//! chain holds it, and only what is still missing is built and broadcast.
//!
//! Each transaction pays its fee from what it carries for it (a node's
//! reserve, an entry's, a checkpoint's or reassignment's margin), in the
//! coin's asset, when the node accepts that asset for fees and the amount
//! covers the floor. Otherwise it takes an on-chain coin of the wallet's in
//! the fee asset the user names or, when none is named, in one the wallet
//! chooses among those the node takes for fees now: the asset moved first,
//! where the node takes it, and otherwise none preferred
//! ([`Wallet::choose_fee_asset`]); the reserve goes to the wallet's change.
//! An exit that needs a fee coin the wallet does not hold stops and says so:
//! that coin cannot come home until the wallet holds one.
//!
//! The claim of a leaf received over Lightning races the operator's refund,
//! valid beside it from the leaf's timeout (D76). From its broadcast its fee
//! rises at every wake as the timeout nears ([`bid_share_ppm`]), up to the
//! leaf's whole value (less twice the dust its own output keeps); when the
//! node no longer accepts the leaf's asset it is paid from an on-chain coin of
//! an asset it accepts; and past the timeout any refund of the leaf in the
//! mempool is replaced by a claim that pays more, up to the leaf's whole
//! value. A stall longer than the claim's margin still opens both in one
//! block, and then the fee race decides; such claims are broadcast whatever
//! their fee rate.
//!
//! An exit asks nothing of the coin's expiry: past it, the wallet goes on
//! trying until the chain says the coin is gone, since the operator sweeps
//! a batch only once its token has waited the notice. A coin whose path a
//! transaction outside it has cut (the operator's sweep of the batch it
//! rests on), once that transaction is final, is lost, and shown so.

use std::str::FromStr;

use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Script, Transaction, TxOut};
use serde_json::{json, Value};

use arca_covenant::spend::{FeeSource, KeySpend};
use arca_covenant::{CoinRecord, ExplicitOutput, HtlcDirection, UnrollTx, ValidCoin, ValidOrigin};

use super::chain::hex;
use super::keys::CHANGE;
use super::wallet::{sign, Home, Wallet};
use super::Error;

/// Where each output of a coin's path is now, from the chain's `locate`.
struct Here {
	outputs: Vec<TxOut>,
	at: Vec<Option<OutPoint>>,
}

impl Here {
	fn at(&self, o: &ExplicitOutput) -> Option<OutPoint> {
		let o = o.txout();
		self.outputs.iter().zip(&self.at).find(|(w, _)| **w == o).and_then(|(_, a)| *a)
	}

	/// Where `o` is: on the chain, or paid by a transaction of the exit
	/// built already. Two coins of one reassignment, or two leaves of one
	/// tree, share the steps above them, and each is built once.
	fn or_built(&self, txs: &[UnrollTx], o: &ExplicitOutput) -> Option<OutPoint> {
		self.at(o).or_else(|| {
			let o = o.txout();
			txs.iter().find_map(|u| u.tx.output.iter().position(|x| *x == o).map(|j| OutPoint::new(u.tx.txid(), j as u32)))
		})
	}
}

/// Who pays the fees an output's own reserve cannot.
pub(crate) struct Payer {
	asset: Option<AssetId>,
	/// The asset the exit moves, from which the wallet chooses the fee asset
	/// when none is named; `None` where nothing is to be chosen.
	pub(crate) moved: Option<AssetId>,
	coin: Option<(OutPoint, TxOut, Keypair)>,
	change: Option<(Script, Keypair)>,
	/// Coins the exit has already taken.
	used: Vec<OutPoint>,
	/// The least fee the next transaction pays, in the asset it pays in: a
	/// replacement's, which outbids the transaction it replaces.
	min_fee: u64,
}

impl Payer {
	/// A payer of fees in `asset`, when named.
	pub(crate) fn new(asset: Option<AssetId>) -> Payer {
		Payer { asset, moved: None, coin: None, change: None, used: vec![], min_fee: 0 }
	}
}

fn txs_fee(tx: &Transaction) -> Vec<(AssetId, u64)> {
	tx.output.iter().filter(|o| o.is_fee()).filter_map(|o| Some((o.asset.explicit()?, o.value.explicit()?))).collect()
}

/// The node's dust threshold for the claim's own output, a P2WPKH script,
/// in atoms of the reference unit: 98 vbytes to spend and hold it at the
/// default dust rate of 3,000 a kvB. A claim that pays its fee from the leaf
/// keeps twice this in the leaf's asset, whatever its fee.
const CLAIM_DUST_REFERENCE: u64 = 294;

/// D76: the share of a received leaf's value its claim pays in fees at
/// `now`, in millionths: from the claim's opening (`from`) to the leaf's
/// timeout, the square of the part of that time gone by (a quarter halfway,
/// nothing at the opening), and the whole value from the timeout on.
pub(crate) fn bid_share_ppm(from: u32, timeout: u32, now: u32) -> u64 {
	if now >= timeout {
		return 1_000_000;
	}
	if now <= from || timeout <= from {
		return 0;
	}
	let (gone, span) = ((now - from) as u128, (timeout - from) as u128);
	(gone * gone * 1_000_000 / (span * span)) as u64
}

/// The vsize a claim of `leaf` pays its own fee for: a plain leaf's exit is
/// about 220 vbytes; an `htlc-1` leaf's claim or refund, its longer script
/// and a received leaf's preimage in its witness, about 250, priced at 300.
fn claim_vsize(leaf: &arca_covenant::LeafPolicy) -> u64 {
	if leaf.htlc.is_some() { 300 } else { 220 }
}

impl Wallet {
	fn change_key(&self) -> Result<(Script, Keypair), Error> {
		let i = self.store.take_index(CHANGE)?;
		let k = self.keys.onchain(CHANGE, i)?;
		Ok((super::keys::p2wpkh(&k), k))
	}

	/// Whether `tx`, as built, pays at least the node's floor in one asset the
	/// node accepts.
	fn pays_floor(&self, tx: &Transaction) -> Result<bool, Error> {
		let fees = txs_fee(tx);
		if fees.len() != 1 {
			return Ok(false);
		}
		let (asset, paid) = fees[0];
		match self.chain.floor_per_kvb(asset)? {
			Some(f) => Ok(paid >= (tx.vsize() as u64).saturating_mul(f).div_ceil(1000)),
			None => Ok(false),
		}
	}

	/// The next fee coin of the payer's asset.
	fn fee_coin(&self, payer: &mut Payer) -> Result<(OutPoint, TxOut, Keypair), Error> {
		if let Some(c) = payer.coin.clone() {
			return Ok(c);
		}
		let asset = match (payer.asset, payer.moved) {
			(Some(a), _) => a,
			(None, Some(moved)) => {
				let a = self.choose_fee_asset(moved, &self.fee_holdings()?)?;
				payer.asset = Some(a);
				a
			},
			(None, None) => return Err(Error::Refused("this exit needs a fee coin: the asset it moves is not accepted for fees by the \
				node, or its reserve does not cover the floor; name an accepted asset the wallet holds on-chain (--fee-asset)".into())),
		};
		self.fee_for(asset, 1)?;
		let c = self.fee_candidates()?.into_iter()
			.filter(|(op, o, _)| o.asset.explicit() == Some(asset) && !payer.used.contains(op))
			.max_by_key(|(_, o, _)| o.value.explicit().unwrap_or(0))
			.ok_or_else(|| Error::Refused(format!("the wallet holds no on-chain coin of asset {} to pay the exit's fees with", asset)))?;
		Ok(c)
	}

	/// Builds one transaction of an exit: with the output's own reserve when
	/// that pays the floor, else with a fee coin, whose input it signs.
	pub(crate) fn with_fee(&self, payer: &mut Payer, build: &dyn Fn(&FeeSource) -> Result<UnrollTx, Error>) -> Result<UnrollTx, Error> {
		let u = build(&FeeSource::Reserve);
		if let Ok(u) = &u {
			if self.pays_floor(&u.tx)? {
				return Ok(u.clone());
			}
		}
		let (op, coin, key) = self.fee_coin(payer)?;
		let asset = payer.asset.expect("a fee coin has an asset");
		if payer.change.is_none() {
			payer.change = Some(self.change_key()?);
		}
		let (change, change_key) = payer.change.clone().expect("set");
		let mut fee = self.fee_for(asset, 400)?.max(payer.min_fee);
		loop {
			let src = FeeSource::Coin { outpoint: op, coin: coin.clone(), fee, change: change.clone() };
			let mut u = build(&src)?;
			let i = u.tx.input.iter().position(|t| t.previous_output == op).expect("the fee coin is an input");
			let needed = self.fee_for(asset, Self::signed_vsize(&u.tx, &[i]))?;
			if needed > fee {
				fee = needed;
				continue;
			}
			self.sign_p2wpkh(&mut u.tx, i, &coin, &key);
			payer.used.push(op);
			let txid = u.tx.txid();
			payer.coin = u.tx.output.iter().enumerate()
				.find(|(_, o)| o.script_pubkey == change && o.asset.explicit() == Some(asset))
				.map(|(j, o)| (OutPoint::new(txid, j as u32), o.clone(), change_key));
			if let Some(c) = &payer.coin {
				self.change_in_flight.borrow_mut().push(c.clone());
			}
			return Ok(u);
		}
	}

	/// A spend ending in the owner's key: built with the fee as `with_fee`
	/// chooses, signed by `key`.
	pub(crate) fn key_spend(&self, payer: &mut Payer, key: &Keypair, build: &dyn Fn(&FeeSource) -> Result<KeySpend, Error>) -> Result<UnrollTx, Error> {
		self.key_spend_with(payer, key, &[], build)
	}

	/// [`Self::key_spend`], its witness taking `after` past the signature: an
	/// `htlc-1` claim's preimage.
	pub(crate) fn key_spend_with(&self, payer: &mut Payer, key: &Keypair, after: &[Vec<u8>],
		build: &dyn Fn(&FeeSource) -> Result<KeySpend, Error>) -> Result<UnrollTx, Error>
	{
		let genesis = self.genesis.genesis_hash();
		self.with_fee(payer, &|f| {
			let ks = build(f)?;
			let sighash = ks.sighash(genesis).map_err(|e| Error::Refused(e.to_string()))?;
			let mut below = vec![sign(key, &sighash).as_ref().to_vec()];
			below.extend(after.iter().cloned());
			Ok(ks.finish(below))
		})
	}

	/// What a claim of `coin`'s leaf carries past its owner's signature: a
	/// leaf received over Lightning comes home by its owner's claim with the
	/// payment's preimage (which the operator then reads there).
	fn claim_witness(&self, coin: &ValidCoin, nonce: &[u8; 32]) -> Result<Vec<Vec<u8>>, Error> {
		Ok(match coin.leaf.htlc {
			Some(t) if t.direction == arca_covenant::HtlcDirection::Receive => vec![self.received_preimage(&t.payment_hash, nonce)?.to_vec()],
			_ => vec![],
		})
	}

	/// The owner's claim of `coin`'s leaf at `leaf_at` to `to`, signed by
	/// `key` and carrying `after`: the leaf's own value pays the claim's fee,
	/// at least `payer.min_fee`, unless a fee coin of `payer`'s does; the
	/// wallet never splits its own claim. An `htlc-1` leaf of a payment out
	/// of the tree comes home by its refund, after its timeout and its exit
	/// delay on the chain.
	fn claim_tx(&self, payer: &mut Payer, key: &Keypair, coin: &ValidCoin, leaf_at: OutPoint, to: &Script, after: &[Vec<u8>])
		-> Result<UnrollTx, Error>
	{
		let (asset, value, leaf) = (coin.asset, coin.value, coin.leaf);
		// A resting order's coin comes home by its landing, after the same
		// delay: the whole of it as SeqDEX's own order for the same terms,
		// which any taker fills on the chain, paying the order key's output;
		// a fee coin pays, as the landing keeps nothing for one.
		if let Some(o) = leaf.order_policy() {
			return self.with_fee(payer, &|f| o.landing_tx(leaf_at, value, f).map_err(|e| Error::Refused(e.to_string())));
		}
		let min_fee = payer.min_fee;
		self.key_spend_with(payer, key, after, &|f| {
			let out = match f {
				FeeSource::Reserve | FeeSource::Split { .. } => {
					let fee = self.fee_for(asset, claim_vsize(&leaf))?.max(min_fee);
					if fee >= value {
						return Err(Error::Refused(format!("the leaf's {} atoms do not cover its own claim's fee", value)));
					}
					ExplicitOutput::new(asset, value - fee, to.clone())
				},
				FeeSource::Coin { .. } | FeeSource::Burning { .. } => ExplicitOutput::new(asset, value, to.clone()),
			};
			match leaf.htlc {
				Some(t) if t.direction == arca_covenant::HtlcDirection::Send => leaf.refund_tx(leaf_at, asset, value, &[out], f),
				Some(_) => leaf.claim_tx(leaf_at, asset, value, &[out], f),
				_ => leaf.exit_tx(leaf_at, asset, value, &[out], f),
			}.map_err(|e| Error::Refused(e.to_string()))
		})
	}

	/// The asset a claim of `coin` pays its fee in now: the leaf's own when
	/// the node accepts it for fees, else the one named for the exit, else
	/// the one the wallet chooses among the accepted assets it holds on the
	/// chain ([`Self::choose_fee_asset`]).
	fn claim_fee_asset(&self, coin: &ValidCoin, named: Option<AssetId>) -> Result<AssetId, Error> {
		if self.chain.floor_per_kvb(coin.asset)?.is_some() {
			return Ok(coin.asset);
		}
		match named {
			Some(a) => Ok(a),
			None => self.choose_fee_asset(coin.asset, &self.fee_holdings()?),
		}
	}

	/// D76: what the claim of `coin`, a leaf received over Lightning, pays in
	/// fees now in `fee_asset`, at least, and the most it pays: from the
	/// claim's opening (`prior["claim_from"]`, else when it was first
	/// broadcast) a share of the leaf's value that grows as the leaf's
	/// timeout nears ([`bid_share_ppm`]), the whole value from the timeout
	/// on. Paid from the leaf itself, the whole value is the leaf's less what
	/// keeps its own output above the node's dust; paid from a coin of
	/// another asset, it is the leaf's value at the node's rates now, or at
	/// the rate the wallet kept when the node last accepted the leaf's asset
	/// (`prior["leaf_rate"]`). `None` for any other leaf, or one whose value
	/// the wallet cannot tell in `fee_asset`.
	fn claim_bid(&self, coin: &ValidCoin, prior: &Value, fee_asset: AssetId, now: u32) -> Result<Option<(u64, u64)>, Error> {
		let Some(t) = coin.leaf.htlc.filter(|t| t.direction == HtlcDirection::Receive) else { return Ok(None) };
		let timeout = t.timeout.to_consensus_u32();
		let from = prior["claim_from"].as_u64().or_else(|| prior["claimed_at"].as_u64()).map_or(now, |v| v.min(u32::MAX as u64) as u32);
		let rates = self.chain.fee_rates()?;
		let rate = |a: &AssetId| rates.get(a).copied().filter(|r| *r > 0);
		let fee_rate = rate(&fee_asset).ok_or_else(|| Self::not_accepted(fee_asset))? as u128;
		let max = if fee_asset == coin.asset {
			let keep = (2 * CLAIM_DUST_REFERENCE as u128 * 100_000_000).div_ceil(fee_rate).max(1);
			(coin.value as u128).saturating_sub(keep) as u64
		} else {
			let Some(leaf_rate) = rate(&coin.asset).or_else(|| prior["leaf_rate"].as_u64().filter(|r| *r > 0)) else { return Ok(None) };
			((coin.value as u128 * leaf_rate as u128 / fee_rate).min(u64::MAX as u128)) as u64
		};
		let bid = (max as u128 * bid_share_ppm(from, timeout, now) as u128 / 1_000_000) as u64;
		Ok(Some((bid, max)))
	}

	/// The least fee, in `asset`, a transaction of `size` vbytes pays to
	/// replace `old` in the node's mempool: what the node valued `old`'s fee
	/// at when it took it, in `asset` at its rate now (or what `old` paid in
	/// `asset`, if more), raised to `old`'s fee rate over the larger size,
	/// and the node's floor on `size` more, as the node asks of a
	/// replacement.
	fn outbid(&self, old: &Transaction, asset: AssetId, size: u64) -> Result<u64, Error> {
		let rate = self.chain.fee_rates()?.get(&asset).copied().filter(|r| *r > 0).ok_or_else(|| Self::not_accepted(asset))?;
		let floor = self.chain.floor_per_kvb(asset)?.ok_or_else(|| Self::not_accepted(asset))?;
		let paid = txs_fee(old).iter().filter(|(a, _)| *a == asset).map(|(_, v)| *v).sum::<u64>();
		let valued = self.chain.mempool_fee_value(&old.txid())?.unwrap_or(0);
		let old_now = ((valued as u128 * 100_000_000).div_ceil(rate as u128)).min(u64::MAX as u128) as u64;
		let old_fee = paid.max(old_now);
		let size = size.max(old.vsize() as u64);
		let by_rate = ((old_fee as u128 * size as u128).div_ceil(old.vsize().max(1) as u128)).min(u64::MAX as u128) as u64;
		Ok(by_rate.saturating_add(size.saturating_mul(floor).div_ceil(1000)).saturating_add(1))
	}

	/// D76: the leaf of `coin`, received over Lightning, whose output at
	/// `leaf_at` another transaction `other` spends in the mempool and in no
	/// block (the operator's refund, once the leaf's timeout has passed):
	/// replaced by the wallet's claim paying more, its bid now and at least
	/// what outbids `other`, up to the leaf's whole value. `None` for any
	/// other leaf, or a spend already in a block (a replacement cannot take
	/// it out: a rollback could, and the wallet tries again then).
	fn outbid_refund(&mut self, leaf_id: &str, coin: &ValidCoin, other: &Transaction, leaf_at: OutPoint, prior: &Value)
		-> Result<Option<Value>, Error>
	{
		if !coin.leaf.htlc.is_some_and(|t| t.direction == HtlcDirection::Receive) || self.chain.finality(&other.txid())?.in_chain() {
			return Ok(None);
		}
		let Some(claim_index) = prior["claim_index"].as_u64() else { return Ok(None) };
		let now = self.now()?.to_consensus_u32();
		let named = prior["fee_asset"].as_str().map(AssetId::from_str).transpose().map_err(|e| Error::Store(e.to_string()))?;
		let asset = self.claim_fee_asset(coin, named)?;
		let Some((bid, max)) = self.claim_bid(coin, prior, asset, now)? else { return Ok(None) };
		let need = self.outbid(other, asset, claim_vsize(&coin.leaf))?.max(bid);
		if need > max {
			return Err(Error::Refused(format!("coin {}'s output is spent in the mempool by {}, which is not the wallet's (the operator's \
				refund, the leaf's timeout past): outbidding it takes {} of asset {} in fees, more than the leaf's whole value ({}): a fee \
				race the wallet cannot win", leaf_id, other.txid(), need, asset, max)));
		}
		let row = self.store.coin(leaf_id)?.ok_or_else(|| Error::Store(format!("no coin {}", leaf_id)))?;
		let key = self.keys.leaf(&row.owner_nonce)?;
		let to = self.keys.onchain_script(super::keys::RECEIVE, claim_index as u32)?;
		let after = self.claim_witness(coin, &row.owner_nonce)?;
		let mut payer = Payer { asset: Some(asset), moved: Some(coin.asset), coin: None, change: None, used: vec![], min_fee: need };
		let new = self.claim_tx(&mut payer, &key, coin, leaf_at, &to, &after)?;
		let txid = self.chain.broadcast_any_fee(&new.tx).map_err(|e| Error::Refused(format!("coin {}'s output is spent in the mempool \
			by {}, which is not the wallet's; the node refused the claim that outbids it: {}", leaf_id, other.txid(), e)))?;
		let txs = self.store.exit(leaf_id)?.map(|e| e.1).unwrap_or_else(|| prior.to_string());
		self.store.set_exit(leaf_id, "claimed", &txs, Some(&txid.to_string()))?;
		let why = format!("claimed by {}, which replaced {} (not the wallet's, the operator's refund once the leaf's timeout passed) by \
			paying more in fees; the wallet replaces any refund again at every wake, up to the leaf's whole value, and follows the claim \
			until it is final", txid, other.txid());
		self.store.set_coin_state(leaf_id, "exiting", &why)?;
		Ok(Some(json!({"leaf_id": leaf_id, "state": "claimed", "claim": {"txid": txid.to_string(), "replaced": other.txid().to_string(),
			"fee": txs_fee(&new.tx).iter().map(|(a, v)| json!({"asset": a.to_string(), "amount": v.to_string()})).collect::<Vec<_>>()},
			"note": why})))
	}

	/// The wallet's own claim `old` of coin `leaf_id`'s leaf at `leaf_at`,
	/// to receive address `claim_index`, in the mempool and in no block:
	/// broadcast again, and replaced by one that pays more when it pays less
	/// than the node's floor now, or, for a leaf received over Lightning
	/// (D76), less than its bid now ([`Self::claim_bid`]): the share of the
	/// leaf's value the claim pays rises at every wake as the leaf's timeout
	/// nears, up to the whole value, and a claim paid in the leaf's asset
	/// once the node no longer accepts it is paid from a coin of an asset
	/// it accepts. The replacement outbids it as the node asks of a
	/// replacement ([`Self::outbid`]). Says what it did; `None` when the
	/// claim stands as it is.
	fn raise_claim(&mut self, leaf_id: &str, coin: &ValidCoin, old: &Transaction, leaf_at: OutPoint, prior: &Value, claim_index: u32)
		-> Result<Option<Value>, Error>
	{
		let now = self.now()?.to_consensus_u32();
		let named = prior["fee_asset"].as_str().map(AssetId::from_str).transpose().map_err(|e| Error::Store(e.to_string()))?;
		let paid = txs_fee(old);
		let asset = match self.claim_fee_asset(coin, named) {
			Ok(a) => a,
			Err(e) => {
				let _ = self.chain.broadcast_any_fee(old);
				if !self.pays_floor(old)? {
					self.store.refused(&format!("the claim of {}", leaf_id), &format!("its claim {} pays less than the node's floor now, \
						and no asset to pay a replacement in could be chosen: {}", old.txid(), e))?;
				}
				return Ok(None);
			},
		};
		let bid = self.claim_bid(coin, prior, asset, now)?;
		let pays = paid.iter().filter(|(a, _)| *a == asset).map(|(_, v)| *v).sum::<u64>();
		let short = match bid {
			Some((b, _)) => paid.len() != 1 || paid[0].0 != asset || pays < b,
			None => false,
		};
		if self.pays_floor(old)? && !short {
			// Broadcast again: a node that dropped it takes it back.
			let _ = self.chain.broadcast_any_fee(old);
			return Ok(None);
		}
		let row = self.store.coin(leaf_id)?.ok_or_else(|| Error::Store(format!("no coin {}", leaf_id)))?;
		let key = self.coin_key(&row.owner_nonce)?;
		let to = self.keys.onchain_script(super::keys::RECEIVE, claim_index)?;
		let after = self.claim_witness(coin, &row.owner_nonce)?;
		let mut need = self.outbid(old, asset, claim_vsize(&coin.leaf))?;
		if let Some((b, max)) = bid {
			if need > max {
				let _ = self.chain.broadcast_any_fee(old);
				return Ok(None);
			}
			need = need.max(b);
		}
		let mut payer = Payer { asset: Some(asset), moved: Some(coin.asset), coin: None, change: None, used: vec![], min_fee: need };
		let new = match self.claim_tx(&mut payer, &key, coin, leaf_at, &to, &after) {
			Ok(c) => c,
			Err(e) => {
				let _ = self.chain.broadcast_any_fee(old);
				self.store.refused(&format!("the claim of {}", leaf_id), &format!("its claim {} pays less than it should now, and no \
					replacement could be built: {}", old.txid(), e))?;
				return Ok(None);
			},
		};
		let reason = if short { "it paid less than its bid as the leaf's timeout nears" } else { "the node's floor rose above what it paid" };
		match self.chain.broadcast_any_fee(&new.tx) {
			Ok(txid) => {
				let txs = self.store.exit(leaf_id)?.map(|e| e.1).unwrap_or_else(|| prior.to_string());
				self.store.set_exit(leaf_id, "claimed", &txs, Some(&txid.to_string()))?;
				let why = format!("claimed by {}, which replaced {}: {}; the wallet follows the claim until it is final", txid, old.txid(),
					reason);
				self.store.set_coin_state(leaf_id, "exiting", &why)?;
				Ok(Some(json!({"leaf_id": leaf_id, "state": "claimed", "claim": {"txid": txid.to_string(), "replaced": old.txid().to_string(),
					"why": reason,
					"fee": txs_fee(&new.tx).iter().map(|(a, v)| json!({"asset": a.to_string(), "amount": v.to_string()})).collect::<Vec<_>>()}})))
			},
			Err(e) => {
				let _ = self.chain.broadcast_any_fee(old);
				self.store.refused(&format!("the claim of {}", leaf_id), &format!("its claim {} pays less than it should now ({}), and \
					the node refused its replacement {}: {}", old.txid(), reason, new.tx.txid(), e))?;
				Ok(None)
			},
		}
	}

	/// Every output on the way from the chain to `coin`'s leaf, the leaf's
	/// own last: for a leaf of a batch, the batch output, each node's and the
	/// entry's; for a board, the board output; for a coin a reassignment made,
	/// those of each coin it spends, that coin's leaf and its checkpoint; for
	/// a coin a fill made, the order coin's path and its leaf, then the same
	/// for each taker's coin.
	fn path_outputs(coin: &ValidCoin, out: &mut Vec<TxOut>) {
		match &coin.origin {
			ValidOrigin::Leaf { valid, .. } => {
				out.extend(valid.branch.nodes.iter().map(|n| n.output().txout()));
				out.push(valid.branch.entry_output().txout());
			},
			ValidOrigin::Board { record, .. } => out.push(record.output().txout()),
			ValidOrigin::Transfer { inputs, .. } => {
				for i in inputs {
					Self::path_outputs(&i.coin, out);
					out.push(i.checkpoint_output().txout());
				}
			},
			ValidOrigin::Fill { order, inputs, .. } => {
				Self::path_outputs(order, out);
				for i in inputs {
					Self::path_outputs(&i.coin, out);
					out.push(i.checkpoint_output().txout());
				}
			},
		}
		out.push(coin.output().txout());
	}

	/// Every transaction still needed to bring `coin` on-chain, in order, and
	/// where its leaf then is, starting from where the chain holds its path
	/// now (`here`, from [`Self::path_outputs`] and the chain's `locate`):
	/// the lowest output of the path that is unspent, so the plan follows
	/// whichever round now pays the batch output, a board's conversion, and
	/// every step someone else has already published; a step the plan has
	/// built already (a lineage reaching it twice) is not built again.
	fn bring(&self, coin: &ValidCoin, payer: &mut Payer, txs: &mut Vec<UnrollTx>, here: &Here) -> Result<OutPoint, Error> {
		if let Some(at) = here.or_built(txs, &coin.output()) {
			return Ok(at);
		}
		match &coin.origin {
			ValidOrigin::Leaf { valid, preimage, auths } => {
				let b = &valid.branch;
				let n = b.nodes.len();
				let start = match here.or_built(txs, &b.entry_output()) {
					Some(at) => Some((n, at)),
					None => (0..n).rev().find_map(|i| here.or_built(txs, &b.nodes[i].output()).map(|at| (i, at))),
				};
				let (from, mut at) = start.ok_or_else(|| Error::Refused(format!("nothing of the path of leaf {} is unspent on the chain: \
					no transaction in a block or the mempool pays its batch output, a node below it or its entry unspent", coin.id)))?;
				for (node, auth) in b.nodes.iter().zip(auths).skip(from) {
					let u = self.with_fee(payer, &|f| node.unroll_tx(at, auth, f).map_err(|e| Error::Refused(e.to_string())))?;
					at = OutPoint::new(u.tx.txid(), node.index as u32);
					txs.push(u);
				}
				let u = self.with_fee(payer, &|f| b.entry_tx(at, preimage, f).map_err(|e| Error::Refused(e.to_string())))?;
				let leaf = OutPoint::new(u.tx.txid(), 0);
				txs.push(u);
				Ok(leaf)
			},
			ValidOrigin::Board { record, .. } => {
				// The owner's conversion of its own board into the leaf.
				let board = here.at(&record.output()).ok_or_else(|| Error::Refused(format!("the board of {} is spent, and not by its \
					conversion into the coin's leaf", coin.id)))?;
				let key = self.keys.leaf(&record.owner_nonce)?;
				if key.x_only_public_key().0 != record.owner {
					return Err(Error::Refused("a board in the record is not this wallet's to convert".into()));
				}
				let policy = record.policy();
				let u = self.key_spend(payer, &key, &|f| policy.conversion(board, f).map_err(|e| Error::Refused(e.to_string())))?;
				let leaf = OutPoint::new(u.tx.txid(), 0);
				txs.push(u);
				Ok(leaf)
			},
			ValidOrigin::Transfer { inputs, index, .. } => {
				let cps = self.checkpoints(inputs, payer, txs, here)?;
				let u = self.with_fee(payer, &|f| coin.reassignment_tx(&cps, f).map_err(|e| Error::Refused(e.to_string())))?;
				let leaf = OutPoint::new(u.tx.txid(), *index as u32);
				txs.push(u);
				Ok(leaf)
			},
			ValidOrigin::Fill { order, inputs, index, .. } => {
				// The order coin by its fill path, each taker's coin through
				// its checkpoint, then the fill.
				let order_at = self.bring(order, payer, txs, here)?;
				let cps = self.checkpoints(inputs, payer, txs, here)?;
				let u = self.with_fee(payer, &|f| coin.fill_tx(order_at, &cps, f).map_err(|e| Error::Refused(e.to_string())))?;
				let leaf = OutPoint::new(u.tx.txid(), *index as u32);
				txs.push(u);
				Ok(leaf)
			},
		}
	}

	/// The checkpoint of each of `inputs` on the chain, building whatever is
	/// still missing of each coin's path and its checkpoint.
	fn checkpoints(&self, inputs: &[arca_covenant::ValidInput], payer: &mut Payer, txs: &mut Vec<UnrollTx>, here: &Here)
		-> Result<Vec<OutPoint>, Error>
	{
		let mut cps = vec![];
		for i in inputs {
			let cp = match here.or_built(txs, &i.checkpoint_output()) {
				Some(at) => at,
				None => {
					let u = match (i.coin.board(), here.or_built(txs, &i.coin.output())) {
						// A board not converted: its checkpoint spends the
						// board output itself.
						(Some((board, _)), None) if here.at(&board.output()).is_some() => {
							self.with_fee(payer, &|f| i.board_checkpoint_tx(f).map_err(|e| Error::Refused(e.to_string())))?
						},
						_ => {
							let at = self.bring(&i.coin, payer, txs, here)?;
							self.with_fee(payer, &|f| i.checkpoint_tx(at, f).map_err(|e| Error::Refused(e.to_string())))?
						},
					};
					let at = OutPoint::new(u.tx.txid(), 0);
					txs.push(u);
					at
				},
			};
			cps.push(cp);
		}
		Ok(cps)
	}

	/// Takes `leaf_id` on-chain from its record alone and claims it after the
	/// exit delay. Each call goes as far as the chain allows now, building
	/// what is still needed from where the chain holds the coin's path now;
	/// call again to go on. `fee_asset` pays whatever the coin's own reserves
	/// cannot, and is remembered for the exit's later steps. The claim goes to
	/// one address of the wallet's, chosen when the exit starts.
	pub fn exit(&mut self, leaf_id: &str, fee_asset: Option<AssetId>) -> Result<Value, Error> {
		self.exit_shown(leaf_id, fee_asset, None)
	}

	/// What a run of [`Self::exit`] of `leaf_id` would broadcast now, before
	/// anything is signed for the chain, broadcast or written: each
	/// transaction of the path still missing, its size and its fee (from its
	/// own reserve or from a fee coin of the wallet's, in `fee_asset` or the
	/// asset the wallet would choose), their fees by asset (`unroll`), and the
	/// claim's fee at the node's floor now, which the claim pays once the
	/// leaf is in a block and its exit delay has run. A program shows it,
	/// then runs the exit with the `unroll` it showed ([`Self::exit_shown`]).
	/// Refuses what the exit would refuse for the same reason.
	pub fn exit_quote(&mut self, leaf_id: &str, fee_asset: Option<AssetId>) -> Result<Value, Error> {
		let row = self.store.coin(leaf_id)?.ok_or_else(|| Error::Refused(format!("no coin {}", leaf_id)))?;
		if !matches!(row.state.as_str(), "live" | "pending" | "exiting" | "offered" | "given" | "forfeited" | "sending" | "paying" | "receiving") {
			return Err(Error::Refused(format!("coin {} is {}: there is nothing of the wallet's to exit", leaf_id, row.state)));
		}
		// An exit whose claim is out has nothing left to pay: `exit` follows
		// the claim until it is final.
		if let Some((state, _, Some(claim))) = self.store.exit(leaf_id)? {
			if state == "claimed" {
				return Ok(json!({
					"leaf_id": leaf_id, "asset": row.asset, "value": row.value.to_string(), "state": "claimed",
					"claim": {"txid": claim}, "steps": [], "unroll": {},
					"note": "the exit's claim is out: nothing is left to pay, and the exit follows the claim until it is final",
				}));
			}
		}
		let record = Self::record_of(&row)?;
		let now = self.now()?;
		let policy = self.followed_policy(row.expiry, now);
		let txs = self.accepted_bases(&record)?;
		let coin = self.resolve(&record, &txs, &policy).map_err(|e| Error::Refused(e.to_string()))?;
		let key = self.coin_key(&row.owner_nonce)?;
		let prior: Value = match self.store.exit(leaf_id)? {
			Some((_, j, _)) => serde_json::from_str(&j).map_err(|e| Error::Store(e.to_string()))?,
			None => json!({}),
		};
		let fee_asset = match fee_asset {
			Some(a) => Some(a),
			None => prior["fee_asset"].as_str().map(AssetId::from_str).transpose().map_err(|e| Error::Store(e.to_string()))?,
		};
		// No change index is taken for a quote: the change script's size is
		// that of every P2WPKH change.
		let dummy = self.keys.onchain(CHANGE, 0)?;
		let mut payer = Payer { asset: fee_asset, moved: Some(coin.asset), coin: None,
			change: Some((super::keys::p2wpkh(&dummy), dummy)), used: vec![], min_fee: 0 };
		let mut path = vec![];
		Self::path_outputs(&coin, &mut path);
		let here = Here { outputs: path.clone(), at: self.chain.locate(&path)? };
		let in_flight = self.change_in_flight.borrow().len();
		let mut built = vec![];
		let planned = self.bring(&coin, &mut payer, &mut built, &here);
		let leaf_at = match planned {
			Ok(at) => at,
			Err(e) => {
				self.change_in_flight.borrow_mut().truncate(in_flight);
				return Err(e);
			},
		};
		let steps: Vec<Value> = built.iter().map(|u| {
			let by_coin = u.tx.input.iter().any(|i| payer.used.contains(&i.previous_output));
			json!({"vsize": u.tx.vsize(), "fee": txs_fee(&u.tx).iter().map(|(a, v)| json!({"asset": a.to_string(), "amount": v.to_string()}))
				.collect::<Vec<_>>(), "paid_by": if by_coin { "a fee coin of the wallet's" } else { "its own reserve" }})
		}).collect();
		let unroll = Self::fees_by_asset(&built);
		// The claim as it would be built now (a receive leaf's preimage is
		// 32 bytes, whatever it is).
		let (asset, value, leaf) = (coin.asset, coin.value, coin.leaf);
		let to = Script::from(vec![0u8; 22]);
		let after = match leaf.htlc {
			Some(t) if t.direction == arca_covenant::HtlcDirection::Receive => vec![vec![0u8; 32]],
			_ => vec![],
		};
		let claim = self.claim_tx(&mut payer, &key, &coin, leaf_at, &to, &after);
		self.change_in_flight.borrow_mut().truncate(in_flight);
		let claim = match claim {
			Ok(c) => json!({"vsize": c.tx.vsize(), "fee": txs_fee(&c.tx).iter().map(|(a, v)| json!({"asset": a.to_string(), "amount": v.to_string()}))
				.collect::<Vec<_>>(), "pays": c.tx.output[0].value.explicit().map(|v| v.to_string())}),
			Err(e) => json!({"error": e.to_string()}),
		};
		Ok(json!({
			"leaf_id": leaf_id, "asset": asset.to_string(), "value": value.to_string(),
			"fee_asset": payer.asset.map(|a| a.to_string()), "steps": steps, "unroll": unroll, "claim": claim,
			"exit_delay_seconds": leaf.exit_delay.seconds(),
			"note": "the fees at the node's floor now, each in its asset's own atoms; the unroll is broadcast only on the fees shown, \
				and the claim pays the floor when it is made, once the leaf is in a block and its exit delay has run",
		}))
	}

	/// Every fee the transactions pay, by asset: `{asset: atoms}`.
	fn fees_by_asset(built: &[UnrollTx]) -> Value {
		let mut by: std::collections::BTreeMap<String, u64> = Default::default();
		for u in built {
			for (a, v) in txs_fee(&u.tx) {
				*by.entry(a.to_string()).or_default() += v;
			}
		}
		Value::Object(by.into_iter().map(|(a, v)| (a, json!(v.to_string()))).collect())
	}

	/// [`Self::exit`], broadcasting the path's transactions only when their
	/// fees by asset are `shown` (an [`Self::exit_quote`]'s `unroll`), when
	/// given; else a refusal naming the fees now, before anything is
	/// broadcast or the coin's state changed.
	pub fn exit_shown(&mut self, leaf_id: &str, fee_asset: Option<AssetId>, shown: Option<&Value>) -> Result<Value, Error> {
		let row = self.store.coin(leaf_id)?.ok_or_else(|| Error::Refused(format!("no coin {}", leaf_id)))?;
		// A coin handed over to a participation or a transfer is the wallet's
		// until the chain shows otherwise: one taken by a round or a
		// co-signed spend is `spent`, and is not exited.
		if !matches!(row.state.as_str(), "live" | "pending" | "exiting" | "offered" | "given" | "forfeited" | "sending" | "paying" | "receiving") {
			return Err(Error::Refused(format!("coin {} is {}: there is nothing of the wallet's to exit", leaf_id, row.state)));
		}
		// A leaf received under a hash the wallet did not make is claimed only
		// with that hash's preimage: before the wallet holds it, an exit
		// would bring the leaf to the chain with nothing to claim it by.
		if row.state != "exiting" && self.awaiting_preimage()?.contains(leaf_id) {
			return Err(Error::Refused(format!("coin {} is a leaf received under a payment hash the wallet did not make, claimed only with \
				that hash's preimage, which the wallet does not hold yet: nothing is broadcast; it can be exited once the preimage is in \
				hand", leaf_id)));
		}
		let record = Self::record_of(&row)?;
		let now = self.now()?;
		// An exit asks nothing of the expiry: it is what a wallet does when
		// time runs short, and past the expiry it goes on until the chain says
		// the coin is gone (a batch is swept only once its token has waited
		// its notice). The coin is the one the wallet accepted, checked as of
		// its expiry once that has passed; where its path is now is the
		// chain's.
		let policy = self.followed_policy(row.expiry, now);
		let txs = self.accepted_bases(&record)?;
		let coin = self.resolve(&record, &txs, &policy).map_err(|e| Error::Refused(e.to_string()))?;
		let key = self.coin_key(&row.owner_nonce)?;
		let prior: Value = match self.store.exit(leaf_id)? {
			Some((_, j, _)) => serde_json::from_str(&j).map_err(|e| Error::Store(e.to_string()))?,
			None => json!({}),
		};
		let fee_asset = match fee_asset {
			Some(a) => Some(a),
			None => prior["fee_asset"].as_str().map(AssetId::from_str).transpose().map_err(|e| Error::Store(e.to_string()))?,
		};
		let mut payer = Payer { asset: fee_asset, moved: Some(coin.asset), coin: None, change: None, used: vec![], min_fee: 0 };
		let mut path = vec![];
		Self::path_outputs(&coin, &mut path);
		let here = Here { outputs: path.clone(), at: self.chain.locate(&path)? };
		let mut built = vec![];
		let leaf_at = match self.bring(&coin, &mut payer, &mut built, &here) {
			Ok(at) => at,
			Err(e) => {
				// Nothing of the path is left unspent: someone else spent the coin.
				if here.at.iter().all(Option::is_none) {
					if let Some(v) = self.taken(leaf_id, &coin, &prior)? {
						return Ok(v);
					}
					// A transaction outside its path took a batch output it
					// rests on: the operator's sweep, past the batch's expiry and
					// notice. Once that is final the coin is gone.
					if let Some((why, by)) = self.swept(&coin)? {
						self.store.refused(&format!("exit of {}", leaf_id), &why)?;
						if self.chain.finality(&by)?.is_final() {
							self.store.set_coin_state(leaf_id, "lost", &format!("lost: {}; that spend is final", why))?;
							return Ok(json!({"leaf_id": leaf_id, "state": "lost", "spent_by": by.to_string(), "note": why}));
						}
						self.store.set_coin_state(leaf_id, &row.state, &format!("{}; that spend is not final yet", why))?;
						return Err(Error::Refused(why));
					}
				}
				// The path is cut: say where, when another spend cut it. Once
				// that spend is final the coin is lost, and shown so.
				return Err(match self.paid_elsewhere(&coin)? {
					Some((why, by)) => {
						self.store.refused(&format!("exit of {}", leaf_id), &why)?;
						if self.chain.finality(&by)?.is_final() {
							self.store.set_coin_state(leaf_id, "lost", &format!("lost: {}; that spend is final", why))?;
						} else {
							self.store.set_coin_state(leaf_id, &row.state, &format!("{}; that spend is not final yet", why))?;
						}
						Error::Refused(why)
					},
					None => e,
				});
			},
		};
		if let Some(shown) = shown {
			let now = Self::fees_by_asset(&built);
			if now != *shown {
				return Err(Error::Refused(format!("the exit's fees changed since they were shown; they are now {}", now)));
			}
		}
		self.let_go(leaf_id, &row.state)?;
		// One claim address for the exit, however many times it is run.
		let claim_index = match prior["claim_index"].as_u64() {
			Some(i) => i as u32,
			None => self.store.take_index(super::keys::RECEIVE)?,
		};
		let plan: Vec<Transaction> = built.into_iter().map(|u| u.tx).collect();
		// The fee asset named, or chosen while the plan was built, for the
		// exit's later steps.
		// What the claim's bid counts from (D76), kept across runs: when the
		// claim opens, when it was first broadcast, and the leaf's rate when
		// the node last accepted its asset.
		let kept: Vec<(&str, Value)> = ["claim_from", "claimed_at", "leaf_rate"].iter()
			.filter(|k| !prior[**k].is_null()).map(|k| (*k, prior[*k].clone())).collect();
		let received = coin.leaf.htlc.is_some_and(|t| t.direction == HtlcDirection::Receive);
		let record_exit = |state: &str, fee_asset: Option<AssetId>, s: &Wallet| -> Result<(), Error> {
			let mut v = json!({"txs": plan.iter().map(|t| hex(&elements::encode::serialize(t))).collect::<Vec<_>>(), "leaf": leaf_at.to_string(),
				"fee_asset": fee_asset.map(|a| a.to_string()), "claim_index": claim_index});
			for (k, x) in &kept {
				v[*k] = x.clone();
			}
			if received {
				if let Some(r) = s.chain.fee_rates()?.get(&coin.asset).copied().filter(|r| *r > 0) {
					v["leaf_rate"] = json!(r);
				}
			}
			s.store.set_exit(leaf_id, state, &v.to_string(), None)
		};
		record_exit("unrolling", payer.asset, self)?;
		if row.state != "exiting" {
			self.store.set_coin_state(leaf_id, "exiting", "its exit has started")?;
		}
		let mut steps = vec![];
		for t in &plan {
			match self.chain.broadcast(t) {
				Ok(txid) => steps.push(json!({"txid": txid.to_string(), "vsize": t.vsize(), "fee": txs_fee(t).iter()
					.map(|(a, v)| json!({"asset": a.to_string(), "amount": v.to_string()})).collect::<Vec<_>>()})),
				Err(e) => {
					self.store.refused(&format!("exit of {}", leaf_id), &e.to_string())?;
					return Ok(json!({"leaf_id": leaf_id, "state": "unrolling", "broadcast": steps, "error": e.to_string()}));
				},
			}
		}
		// The claim, once the leaf is in a block and its delay has run.
		let leaf_f = self.chain.finality(&leaf_at.txid)?;
		if !leaf_f.in_chain() {
			return Ok(json!({"leaf_id": leaf_id, "state": "unrolling", "broadcast": steps, "leaf": leaf_at.to_string(),
				"next": "the leaf's transaction is not in a block yet; run exit again once it is"}));
		}
		let to = self.keys.onchain_script(super::keys::RECEIVE, claim_index)?;
		let leaf = coin.leaf;
		// A received leaf whose preimage is not in hand yet waits on the chain
		// for it; the claim goes out once it is.
		let after = match self.claim_witness(&coin, &row.owner_nonce) {
			Ok(a) => a,
			Err(e) => return Ok(json!({"leaf_id": leaf_id, "state": "waiting", "broadcast": steps, "leaf": leaf_at.to_string(),
				"error": e.to_string()})),
		};
		// D76: a leaf received over Lightning: its claim pays its bid now,
		// which rises as the leaf's timeout nears.
		if received {
			let exit_now: Value = self.store.exit(leaf_id)?.and_then(|e| serde_json::from_str(&e.1).ok()).unwrap_or(Value::Null);
			if let Ok(asset) = self.claim_fee_asset(&coin, payer.asset) {
				if let Some((bid, _)) = self.claim_bid(&coin, &exit_now, asset, now.to_consensus_u32())? {
					payer.asset = Some(asset);
					payer.min_fee = payer.min_fee.max(bid);
				}
			}
		}
		let claim = self.claim_tx(&mut payer, &key, &coin, leaf_at, &to, &after);
		let claim = match claim {
			Ok(c) => c,
			Err(e) => return Ok(json!({"leaf_id": leaf_id, "state": "waiting", "broadcast": steps, "error": e.to_string()})),
		};
		match self.chain.broadcast_any_fee(&claim.tx) {
			Ok(txid) => {
				// The coin is exited once the claim is final; until then the
				// wallet follows it, and builds it again should it leave the
				// chain and the mempool.
				let txs = self.store.exit(leaf_id)?.expect("set").1;
				let txs = match serde_json::from_str::<Value>(&txs) {
					Ok(mut v) if v["claimed_at"].is_null() => {
						v["claimed_at"] = json!(now.to_consensus_u32());
						v.to_string()
					},
					_ => txs,
				};
				self.store.set_exit(leaf_id, "claimed", &txs, Some(&txid.to_string()))?;
				self.store.set_coin_state(leaf_id, "exiting", &format!("claimed by {}; the wallet follows the claim until it is final", txid))?;
				Ok(json!({"leaf_id": leaf_id, "state": "claimed", "broadcast": steps, "claim": {"txid": txid.to_string(),
					"vsize": claim.tx.vsize(), "pays": claim.tx.output[0].value.explicit().map(|v| v.to_string()),
					"to": self.chain.address(&to)?}}))
			},
			Err(e) if e.to_string().contains("non-BIP68-final") => {
				record_exit("waiting", payer.asset, self)?;
				// When the claim's delay ends, from the leaf's block, for the
				// schedule (`claim_from`); a refund of a payment out of the tree
				// waits for its timeout too.
				if let Some(h) = leaf_f.height() {
					if let Some(mtp) = self.chain.median_time_at(h)? {
						let mut from = mtp as u64 + leaf.exit_delay.seconds();
						if let Some(t) = leaf.htlc.filter(|t| t.direction == arca_covenant::HtlcDirection::Send) {
							from = from.max(t.timeout.to_consensus_u32() as u64);
						}
						if let Some((st, j, c)) = self.store.exit(leaf_id)? {
							let mut v: Value = serde_json::from_str(&j).map_err(|e| Error::Store(e.to_string()))?;
							v["claim_from"] = json!(from);
							self.store.set_exit(leaf_id, &st, &v.to_string(), c.as_deref())?;
						}
					}
				}
				Ok(json!({"leaf_id": leaf_id, "state": "waiting", "broadcast": steps,
					"next": format!("the exit delay of {} s runs from the leaf's confirmation; the node refused the claim before it: {}",
						leaf.exit_delay.seconds(), e)}))
			},
			Err(e) => Ok(json!({"leaf_id": leaf_id, "state": "waiting", "broadcast": steps, "error": e.to_string()})),
		}
	}

	/// What a coin handed over gives up when its exit starts: a coin given
	/// to a participation withdraws the wallet from it (it signs no forfeit
	/// for it from then on), and one in a transfer request the server never
	/// answered abandons the request (it is not posted again). A forfeit
	/// already signed stays watched.
	fn let_go(&mut self, leaf_id: &str, state: &str) -> Result<(), Error> {
		match state {
			"given" => {
				for (pid, _, given, _, pstate, _, _) in self.store.participations()? {
					if matches!(pstate.as_str(), "submitting" | "pending" | "issued") && given.contains(&format!("\"{}\"", leaf_id)) {
						self.store.set_participation(&pid, "withdrawn", None, None)?;
					}
				}
			},
			"sending" => {
				for (id, _, inputs) in self.store.transfers_in("requested")? {
					if inputs.contains(&format!("\"{}\"", leaf_id)) {
						self.store.set_transfer(id, "abandoned", &format!("the wallet exits coin {}", leaf_id))?;
					}
				}
			},
			_ => {},
		}
		Ok(())
	}

	/// Who spent `coin`, when nothing of its path is left unspent: its leaf or
	/// board, found on the chain, and the transaction that spends it. The
	/// operator's forfeit of it puts the coin back under that forfeit, which
	/// the wallet follows on the chain; its co-signed checkpoint means the
	/// transfer it was sent in stands; the wallet's own claim means it is
	/// exited. `None` when the coin's leaf is not on the chain at all.
	fn taken(&mut self, leaf_id: &str, coin: &ValidCoin, prior: &Value) -> Result<Option<Value>, Error> {
		let from = self.store.meta("birthday")?.and_then(|b| b.parse::<u64>().ok()).unwrap_or(0).saturating_sub(1000);
		let mut spots: Vec<OutPoint> = prior["leaf"].as_str().and_then(|l| OutPoint::from_str(l).ok()).into_iter().collect();
		if let Some((_, board)) = coin.board() {
			spots.push(board);
		}
		if spots.is_empty() {
			if let Some((tx, _)) = self.chain.find_payment(&coin.output().txout(), from)? {
				let vout = tx.output.iter().position(|o| *o == coin.output().txout()).expect("pays it") as u32;
				spots.push(OutPoint::new(tx.txid(), vout));
			}
		}
		for at in spots {
			if self.chain.unspent(&at)? {
				continue;
			}
			let h = self.chain.finality(&at.txid)?.height().unwrap_or(from);
			let Some((sp, _)) = self.chain.spender(&at, h)? else { continue };
			let txid = sp.txid().to_string();
			let row = self.store.coin(leaf_id)?.ok_or_else(|| Error::Store(format!("no coin {}", leaf_id)))?;
			for f in self.store.forfeits_of(leaf_id)? {
				let out = self.forfeit_of(&row, &f)?.output().txout();
				if sp.output.contains(&out) {
					let why = format!("the operator answered the exit with its forfeit for round {} ({}): the wallet takes the preimage \
						from a claim of it, or the refund once its delay has run", f.round, txid);
					self.store.atomically(|s| {
						if f.state == "void" {
							s.set_forfeit_state(&f.leaf_id, &f.round, "signed", "")?;
						}
						s.set_coin_state(leaf_id, "forfeited", &why)
					})?;
					return Ok(Some(json!({"leaf_id": leaf_id, "state": "forfeited", "spent_by": txid, "note": why})));
				}
			}
			if sp.output.first().is_some_and(|o| o.script_pubkey == coin.checkpoint().script_pubkey()) {
				let why = format!("taken on the chain by its co-signed checkpoint {}: the transfer it was sent in stands", txid);
				self.store.set_coin_spent(leaf_id, &format!("checkpoint {}", txid))?;
				return Ok(Some(json!({"leaf_id": leaf_id, "state": "spent", "spent_by": txid, "note": why})));
			}
			if let Some(i) = prior["claim_index"].as_u64() {
				let to = self.keys.onchain_script(super::keys::RECEIVE, i as u32)?;
				if sp.output.iter().any(|o| o.script_pubkey == to) {
					// The wallet's own claim: the coin is exited once it is final.
					let f = self.chain.finality(&sp.txid())?;
					if f.is_final() {
						self.store.set_coin_state(leaf_id, "exited", &format!("claimed by {}, final", txid))?;
						return Ok(Some(json!({"leaf_id": leaf_id, "state": "exited", "claim": txid})));
					}
					if f.in_chain() {
						// Mined: the schedule follows it at its finality's pace.
						if let Some((st, j, c)) = self.store.exit(leaf_id)? {
							let mut v: Value = serde_json::from_str(&j).map_err(|e| Error::Store(e.to_string()))?;
							if v["mined"] != json!(true) {
								v["mined"] = json!(true);
								self.store.set_exit(leaf_id, &st, &v.to_string(), c.as_deref())?;
							}
						}
					} else if let Some(v) = self.raise_claim(leaf_id, coin, &sp, at, prior, i as u32)? {
						return Ok(Some(v));
					}
					self.store.set_coin_state(leaf_id, "exiting", &format!("claimed by {}, which is {}; the wallet follows the claim until \
						it is final", txid, f.word()))?;
					return Ok(Some(json!({"leaf_id": leaf_id, "state": "claimed", "claim": {"txid": txid, "finality": f.word()}})));
				}
			}
			// D76: a leaf received over Lightning whose output another
			// transaction spends in the mempool (the operator's refund, its
			// timeout past) is claimed back by a claim paying more.
			if let Some(v) = self.outbid_refund(leaf_id, coin, &sp, at, prior)? {
				return Ok(Some(v));
			}
			return Err(Error::Refused(format!("coin {} was spent on the chain by {}, which is none of the wallet's and no spend it signed",
				leaf_id, txid)));
		}
		Ok(None)
	}

	/// When `coin` cannot reach the chain because a coin it rests on was spent
	/// otherwise: that coin's output (or its board's) spent on the chain by
	/// something other than `coin`'s checkpoint of it, or that checkpoint
	/// spent by a reassignment `coin` is no output of. The operator
	/// co-signed another spend of the coin, which reached the chain first.
	/// Says so, or `None`.
	fn paid_elsewhere(&self, coin: &ValidCoin) -> Result<Option<(String, elements::Txid)>, Error> {
		let (order, inputs) = match &coin.origin {
			ValidOrigin::Transfer { inputs, .. } => (None, inputs),
			ValidOrigin::Fill { order, inputs, .. } => (Some(order), inputs),
			ValidOrigin::Leaf { .. } | ValidOrigin::Board { .. } => return Ok(None),
		};
		let from = self.store.meta("birthday")?.and_then(|b| b.parse::<u64>().ok()).unwrap_or(0).saturating_sub(1000);
		let mine = coin.output().txout();
		let spent_by = |out: &TxOut| -> Result<Option<(Transaction, Transaction)>, Error> {
			let Some((tx, h)) = self.chain.find_payment(out, from)? else { return Ok(None) };
			let vout = tx.output.iter().position(|o| o == out).expect("pays it") as u32;
			Ok(self.chain.spender(&OutPoint::new(tx.txid(), vout), h)?.map(|(sp, _)| (tx, sp)))
		};
		let elsewhere = |id: &arca_covenant::LeafId, sp: &Transaction| (format!("coin {} it rests on is spent on the chain by {}, which \
			is not this coin's way out: the operator co-signed another spend of coin {} (a payment, or a forfeit), which reached the \
			chain first, so this coin cannot be brought on the chain", id, sp.txid(), id), sp.txid());
		// A fill's order coin, spent on the chain by anything but this fill
		// (another fill, a cancel, its landing), leaves this coin out.
		if let Some(o) = order {
			if let Some((_, sp)) = spent_by(&o.output().txout())? {
				if !sp.output.contains(&mine) {
					return Ok(Some(elsewhere(&o.id, &sp)));
				}
			}
			if let Some(why) = self.paid_elsewhere(o)? {
				return Ok(Some(why));
			}
		}
		for i in inputs {
			let cp = i.checkpoint_output().txout();
			let own = i.coin.output().txout();
			let mut sources = vec![own.clone()];
			if let Some((board, _)) = i.coin.board() {
				sources.push(board.output().txout());
			}
			for src in &sources {
				let Some((_, sp)) = spent_by(src)? else { continue };
				if sp.output.contains(&cp) {
					// This coin's checkpoint of it: then this coin's reassignment.
					if let Some((_, re)) = spent_by(&cp)? {
						if !re.output.contains(&mine) {
							return Ok(Some(elsewhere(&i.coin.id, &re)));
						}
					}
				} else if *src != own && sp.output.contains(&own) {
					// The board's conversion into the coin's leaf: the leaf is
					// looked at as well.
				} else {
					return Ok(Some(elsewhere(&i.coin.id, &sp)));
				}
			}
			if let Some(why) = self.paid_elsewhere(&i.coin)? {
				return Ok(Some(why));
			}
		}
		Ok(None)
	}

	/// When a batch output `coin` rests on, or a node or entry of its path
	/// below it, was spent on the chain by a transaction that is not the next
	/// step of that path (the operator's sweep, once the batch has expired and
	/// its token waited the notice): why, and that transaction. `None`
	/// otherwise, and for a coin resting on boards alone (a board has no
	/// sweep).
	pub(crate) fn swept(&self, coin: &ValidCoin) -> Result<Option<(String, elements::Txid)>, Error> {
		match &coin.origin {
			ValidOrigin::Leaf { valid, .. } => {
				let from = self.store.meta("birthday")?.and_then(|b| b.parse::<u64>().ok()).unwrap_or(0).saturating_sub(1000);
				let b = &valid.branch;
				let mut steps: Vec<TxOut> = b.nodes.iter().map(|n| n.output().txout()).collect();
				steps.push(b.entry_output().txout());
				steps.push(coin.output().txout());
				for pair in steps.windows(2) {
					let Some((tx, h)) = self.chain.find_payment(&pair[0], from)? else { continue };
					let vout = tx.output.iter().position(|o| *o == pair[0]).expect("pays it") as u32;
					let Some((sp, _)) = self.chain.spender(&OutPoint::new(tx.txid(), vout), h)? else { continue };
					if !sp.output.contains(&pair[1]) {
						return Ok(Some((format!("coin {} rests on output {}:{} of its batch, which {} spent on the chain: no step of the \
							coin's exit, but the operator's sweep of the batch past its expiry and notice", coin.id, tx.txid(), vout, sp.txid()),
							sp.txid())));
					}
				}
				Ok(None)
			},
			ValidOrigin::Transfer { inputs, .. } => {
				for i in inputs {
					if let Some(w) = self.swept(&i.coin)? {
						return Ok(Some(w));
					}
				}
				Ok(None)
			},
			ValidOrigin::Fill { order, inputs, .. } => {
				if let Some(w) = self.swept(order)? {
					return Ok(Some(w));
				}
				for i in inputs {
					if let Some(w) = self.swept(&i.coin)? {
						return Ok(Some(w));
					}
				}
				Ok(None)
			},
			ValidOrigin::Board { .. } => Ok(None),
		}
	}

	/// Whether a spend that is no step of `coin`'s exit, and is final, has cut
	/// its path: the operator's sweep of a batch it rests on
	/// ([`Self::swept`]), or another spend the operator co-signed of a coin it
	/// rests on ([`Self::paid_elsewhere`]). While it has, the coin is lost,
	/// whatever round it rests on stands; a rollback that leaves that spend
	/// not final makes it the wallet's again.
	pub(crate) fn cut_by_final_spend(&self, coin: &ValidCoin) -> Result<bool, Error> {
		for (_, by) in [self.swept(coin)?, self.paid_elsewhere(coin)?].into_iter().flatten() {
			if self.chain.finality(&by)?.is_final() {
				return Ok(true);
			}
		}
		Ok(false)
	}

	/// Moves on every exit the wallet has started, with the fee asset each was
	/// started with.
	pub(crate) fn progress_exits(&mut self) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		for c in self.store.coins_in("exiting")? {
			out.push(self.exit(&c.leaf_id, None).unwrap_or_else(|e| json!({"leaf_id": c.leaf_id, "error": e.to_string()})));
		}
		Ok(out)
	}

	/// The witness of the operator's signer's record and the server's `info`,
	/// patiently: one that fails for want of an answer (none, a timeout, a
	/// 5xx, `rate_limited`, an answer without the signer's proof) is tried
	/// again with back-off, from a second and doubling to sixteen, until one
	/// succeeds or [`Wallet::witness_patience`] has run, the last try a
	/// second past it, so a server restarting for that long is reached; a
	/// refusal, or a rollback proven, is not. One failed witness decides
	/// nothing. Returns the witness (or its last failure), why `info` fails if
	/// it does, and how many times it asked.
	fn reach_operator(&mut self) -> (Result<Value, Error>, Option<Error>, u32) {
		let start = web_time::Instant::now();
		let mut wait = std::time::Duration::from_secs(1);
		let mut tries = 0;
		loop {
			tries += 1;
			let w = self.witness();
			let info = match &w {
				Ok(v) if !v["rolled_back"].is_null() => return (w, None, tries),
				Ok(_) => match self.server_info() {
					Ok(_) => return (w, None, tries),
					Err(e @ Error::Unreachable(_)) => Some(e),
					Err(e) => return (w, Some(e), tries),
				},
				Err(Error::Unreachable(_)) => None,
				Err(_) => return (w, None, tries),
			};
			let spent = start.elapsed();
			if spent >= self.witness_patience {
				return (w, info, tries);
			}
			// The last wait ends a second past the patience, never before it.
			sequentia_ext::platform::sleep(wait.min(self.witness_patience - spent + std::time::Duration::from_secs(1)));
			super::chain::gap();
			wait = (wait * 2).min(std::time::Duration::from_secs(16));
		}
	}

	/// The exit steps whose date has come, asking nothing of the operator
	/// (D67): every leaf received over Lightning whose claim has had no
	/// co-signed answer by its home date taken home by its claim
	/// ([`Self::home_received`]), then every exit under way moved on
	/// ([`Self::progress_exits`]): an unroll broadcast again, a claim made
	/// once its delay has run, a claim broadcast again until it is mined,
	/// raised when the node's floor rose or, for a received leaf, as its
	/// timeout nears (D76), and a refund of a received leaf in the mempool
	/// replaced by a claim paying more. A coin whose refresh has not
	/// completed by its home date (D57) goes home after the operator is
	/// asked, so a refresh or payment it completes in the same `sync` keeps
	/// it. Returns the coins taken home and the exits moved on.
	fn exit_steps(&mut self) -> (Vec<Value>, Vec<Value>) {
		let home = self.home_received().map(|h| h.into_iter().filter(|v| !v["exit"].is_null()).collect())
			.unwrap_or_else(|e| vec![json!({"error": e.to_string()})]);
		let exits = self.progress_exits().unwrap_or_else(|e| vec![json!({"error": e.to_string()})]);
		if let Ok(now) = self.now() {
			let _ = self.store.set_meta(super::wallet::LAST_EXITS, &now.to_consensus_u32().to_string());
		}
		(home, exits)
	}

	/// Whether an exit step's date came after median time `since` and by
	/// `now`: a received leaf's home date, an exit's claim once its delay has
	/// run, or, two blocks after `since`, an unroll not yet in a block or a
	/// claim not yet mined. Asks nothing of the operator.
	fn exit_date_between(&self, since: u32, now: u32) -> Result<bool, Error> {
		let came = |t: u32| t > since && t <= now;
		for (_, at) in self.receive_home_dates()? {
			if came(at) {
				return Ok(true);
			}
		}
		for c in self.store.coins_in("exiting")? {
			let Some((state, j, _)) = self.store.exit(&c.leaf_id)? else { continue };
			let v: Value = serde_json::from_str(&j).unwrap_or(Value::Null);
			let due = match state.as_str() {
				"waiting" => v["claim_from"].as_u64().is_some_and(|t| came(t.min(u32::MAX as u64) as u32)),
				"claimed" => v["mined"] != json!(true) && now >= since.saturating_add(super::wallet::EXIT_STEP),
				_ => now >= since.saturating_add(super::wallet::EXIT_STEP),
			};
			if due {
				return Ok(true);
			}
		}
		Ok(false)
	}

	/// While `sync` asks the operator: the exit steps whose date came since
	/// they were last taken, taken at once, so an operator that answers
	/// slowly holds back no claim. A step of `sync`, and of each page of its
	/// mailbox read.
	pub(crate) fn exits_meanwhile(&mut self) {
		let Some(since) = *self.exit_watch.borrow() else { return };
		let Ok(now) = self.now().map(|n| n.to_consensus_u32()) else { return };
		if !self.exit_date_between(since, now).unwrap_or(false) {
			return;
		}
		let (home, exits) = self.exit_steps();
		*self.exit_watch.borrow_mut() = Some(now);
		let mut done = self.exits_done.borrow_mut();
		done.0.extend(home);
		done.1.extend(exits);
	}

	/// The exit steps whose date has come, and nothing else: no call to the
	/// operator (D67). For a client woken by its schedule's `next_exit_at`,
	/// which `sync` would also meet; `sync` takes the same steps before it
	/// asks the operator anything. What it says includes `schedule`.
	pub fn sync_exits(&mut self) -> Result<Value, Error> {
		let _ = self.recheck()?;
		let (home, exits) = self.exit_steps();
		let schedule = self.sync_schedule().unwrap_or_else(|e| json!({"error": e.to_string()}));
		Ok(json!({"home": home, "exits": exits, "schedule": schedule}))
	}

	/// Everything the wallet does on its own: first, before it asks the
	/// operator anything, the re-check of every coin against the chain and
	/// every exit step whose date has come ([`Self::sync_exits`]); then
	/// board registrations and transfer requests the server never
	/// answered, the mailbox, every participation as far as it can go, the
	/// refresh of every coin in its refresh window, every forfeit it signed
	/// without the preimage in hand, followed on the chain, every coin it
	/// cannot have refreshed in time taken home, and every exit it started
	/// (D57), moved on again. While it asks the operator, an exit step whose
	/// date comes is taken at once. What it says includes `schedule`
	/// ([`Wallet::sync_schedule`]): when it must run next.
	pub fn sync(&mut self) -> Result<Value, Error> {
		// The schedule's relative times count from this sync.
		let start = self.now()?.to_consensus_u32();
		self.store.set_meta(super::wallet::LAST_SYNC, &start.to_string())?;
		// D67: the re-check against the chain, then the exit steps whose date
		// has come, before the operator is asked anything, and the steps again
		// whenever one comes while it is.
		let recheck = self.recheck()?;
		let (mut early_home, mut early_exits) = self.exit_steps();
		*self.exit_watch.borrow_mut() = Some(start);
		*self.exits_done.borrow_mut() = (vec![], vec![]);
		let out = self.sync_asking(recheck);
		*self.exit_watch.borrow_mut() = None;
		let (h, e) = std::mem::take(&mut *self.exits_done.borrow_mut());
		early_home.extend(h);
		early_exits.extend(e);
		let mut out = out?;
		if !early_home.is_empty() {
			let mut all = Value::Array(early_home);
			if let (Some(a), Some(later)) = (all.as_array_mut(), out.get("home").and_then(|h| h.as_array())) {
				a.extend(later.iter().cloned());
			}
			out["home"] = all;
		}
		if !early_exits.is_empty() {
			let mut all = Value::Array(early_exits);
			if let (Some(a), Some(later)) = (all.as_array_mut(), out["exits"].as_array()) {
				a.extend(later.iter().cloned());
			}
			out["exits"] = all;
		}
		Ok(out)
	}

	/// The part of [`Self::sync`] that asks the operator, with every exit step
	/// whose date comes meanwhile taken at once ([`Self::exits_meanwhile`]).
	fn sync_asking(&mut self, recheck: Value) -> Result<Value, Error> {
		// The witness first, patiently: after a rollback of the operator's
		// signer's record the wallet does only what it does on the chain, and
		// while no witness succeeds it takes no coin and signs no spend
		// through the operator: it does only what it does on the chain.
		let (witness, info_failed, tries) = self.reach_operator();
		self.exits_meanwhile();
		let witnessed = witness.is_ok();
		let failed = witness.as_ref().err().map(|e| e.to_string());
		let mut witness = witness.unwrap_or_else(|e| json!({"error": e.to_string()}));
		if tries > 1 {
			witness["tries"] = json!(tries);
		}
		let gone = self.rolled_back()?.is_some();
		let talk = witnessed && !gone;
		let waiting = || json!({"note": "the witness of the operator's signer's record did not succeed: the wallet takes no coin and \
			signs no spend through the operator until one does"});
		let boards = if talk { self.retry_boards()? } else { vec![] };
		self.exits_meanwhile();
		let transfers = if talk { self.retry_transfers()? } else { vec![] };
		self.exits_meanwhile();
		// Payments over Lightning the operator has not decided: a paid one
		// closed with its preimage, a failed one taken back.
		let mut lightning = if talk { self.progress_lightning().map(Value::Array).unwrap_or_else(|e| json!({"error": e.to_string()})) }
			else { Value::Array(vec![]) };
		self.exits_meanwhile();
		// Payments received over Lightning: a held one's participation taken
		// up as the wallet's own, a leaf the wallet holds claimed.
		if talk {
			match self.progress_receives() {
				Ok(v) => if let Some(a) = lightning.as_array_mut() { a.extend(v) },
				Err(e) => lightning = json!({"error": e.to_string()}),
			}
		}
		self.exits_meanwhile();
		let mailbox = if talk || gone { self.mailbox().unwrap_or_else(|e| json!({"error": e.to_string()})) } else { waiting() };
		self.exits_meanwhile();
		// Every coin kept before the wallet named its mailbox key is bound to
		// it, so that a restore from the mnemonic finds it.
		let bound = if talk { self.bind_unbound().unwrap_or_else(|e| json!({"error": e.to_string()})) } else { Value::Null };
		self.exits_meanwhile();
		let participations = if talk {
			self.progress_participations().map(Value::Array).unwrap_or_else(|e| json!({"error": e.to_string()}))
		} else if gone { Value::Array(vec![]) } else { waiting() };
		self.exits_meanwhile();
		// Offline-refresh plans: each step whose round is final taken up, a
		// stopped plan cancelled.
		let plans = if talk { self.progress_plans().map(Value::Array).unwrap_or_else(|e| json!({"error": e.to_string()})) }
			else { Value::Array(vec![]) };
		self.exits_meanwhile();
		// Each order placed on the chain: its offboard recorded once released,
		// and unlocked by the wallet when the operator has not.
		let orders = self.progress_orders().map(Value::Array).unwrap_or_else(|e| json!({"error": e.to_string()}));
		self.exits_meanwhile();
		// Each order resting in the tree: published once its round is final
		// and its participation released; each fill the wallet sent and has
		// no answer to sent again.
		let resting = if talk { self.progress_resting().map(Value::Array).unwrap_or_else(|e| json!({"error": e.to_string()})) }
			else { Value::Array(vec![]) };
		self.exits_meanwhile();
		// A leaf received over Lightning that those participations brought
		// in is claimed at once.
		if talk {
			if let (Ok(v), Some(a)) = (self.progress_receives(), lightning.as_array_mut()) {
				a.extend(v.into_iter().filter(|s| s["state"] == "received" || s["state"] == "failed"));
			}
		}
		// D57: the refresh of every live coin in its refresh window, asked for
		// by the wallet itself.
		self.exits_meanwhile();
		let refresh = if talk && info_failed.is_none() {
			self.refresh_due().map(Value::Array).unwrap_or_else(|e| json!({"error": e.to_string()}))
		} else { Value::Array(vec![]) };
		self.exits_meanwhile();
		let forfeits = self.watch_forfeits().map(Value::Array).unwrap_or_else(|e| json!({"error": e.to_string()}));
		// D57: a coin the wallet cannot have refreshed goes home before its
		// date, whatever the reason: every coin whose refresh has not
		// completed a day before its exit date, and after a stop every coin
		// within three days of it. Before that day nothing is taken on the
		// chain because the operator does not answer: the coins are shown
		// with their dates, and sync tries again.
		let cannot = match (gone, failed) {
			(true, _) => None,
			(false, Some(e)) => Some(e),
			(false, None) => info_failed.map(|e| e.to_string()),
		};
		let (why, unreachable) = match (gone, cannot) {
			(true, _) => (Home::Stopped, Value::Null),
			(false, Some(e)) => {
				self.set_unreachable(Some(&e))?;
				let busy = e.contains("rate_limited");
				(Home::Unreachable(e.clone()), json!({"why": e, "note": self.spelling.say(if busy {
					"the server asks the wallet to slow down (rate_limited): nothing is decided on that; the wallet asks again at its next \
					sync. Nothing is taken on the chain for want of an answer before a coin's home_from (a day before its exit date); run \
					{sync} at least once a day while the wallet holds a coin off the chain or waits for a payment"
				} else {
					"the operator cannot be reached now: nothing is taken on the chain for that before a coin's home_from (a day before its \
					exit date, exit_by); from then sync takes it on the chain unless its refresh has completed. Run {sync} at least \
					once a day while the wallet holds a coin off the chain or waits for a payment"
				})}))
			},
			(false, None) => {
				self.set_unreachable(None)?;
				(Home::Answering, Value::Null)
			},
		};
		let home = self.home(true, &why).map(Value::Array).unwrap_or_else(|e| json!({"error": e.to_string()}));
		let exits = self.progress_exits().map(Value::Array).unwrap_or_else(|e| json!({"error": e.to_string()}));
		if let Ok(now) = self.now() {
			self.store.set_meta(super::wallet::LAST_EXITS, &now.to_consensus_u32().to_string())?;
		}
		let schedule = self.sync_schedule().unwrap_or_else(|e| json!({"error": e.to_string()}));
		let mut out = json!({"witness": witness, "boards": boards, "recheck": recheck, "transfers": transfers, "mailbox": mailbox,
			"participations": participations, "forfeits": forfeits, "exits": exits, "schedule": schedule});
		if refresh.as_array().is_none_or(|r| !r.is_empty()) {
			out["refresh"] = refresh;
		}
		if lightning.as_array().is_none_or(|l| !l.is_empty()) {
			out["lightning"] = lightning;
		}
		if orders.as_array().is_none_or(|o| !o.is_empty()) {
			out["orders"] = orders;
		}
		if resting.as_array().is_none_or(|o| !o.is_empty()) {
			out["resting"] = resting;
		}
		if plans.as_array().is_none_or(|p| !p.is_empty()) {
			out["plans"] = plans;
		}
		if !matches!(why, Home::Answering) || home.as_array().is_none_or(|h| !h.is_empty()) {
			out["home"] = home;
		}
		if !unreachable.is_null() {
			out["unreachable"] = unreachable;
		}
		if !bound["error"].is_null() || bound["bound"].as_u64().is_some_and(|n| n > 0)
			|| bound["not_bound"].as_array().is_some_and(|a| !a.is_empty())
		{
			out["bound"] = bound;
		}
		Ok(out)
	}

	/// The decoded coin record of `leaf_id`, for people.
	pub fn record(&self, leaf_id: &str) -> Result<Value, Error> {
		let row = self.store.coin(leaf_id)?.ok_or_else(|| Error::Refused(format!("no coin {}", leaf_id)))?;
		let r = Self::record_of(&row)?;
		let detail = match &r {
			CoinRecord::Leaf { record, .. } => record.to_json().map_err(|e| Error::Refused(e.to_string()))?,
			CoinRecord::Board(b) => b.to_json().map_err(|e| Error::Refused(e.to_string()))?,
			CoinRecord::Transfer(t) => json!({"inputs": t.inputs.len(), "outputs": t.outputs.len(), "index": t.index}),
			CoinRecord::Fill(f) => json!({"fill_of_order": true, "inputs": f.fill.inputs.len(), "outputs": f.fill.outputs.len(),
				"index": f.index, "partial": f.fill.partial}),
		};
		Ok(json!({"leaf_id": leaf_id, "kind": row.kind, "state": row.state, "record": hex(&row.record), "detail": detail}))
	}
}

#[cfg(test)]
mod test {
	use super::bid_share_ppm;

	#[test]
	fn a_claims_bid_grows_to_the_whole_value_at_the_timeout() {
		assert_eq!(bid_share_ppm(1_000, 2_000, 900), 0, "before the claim opens");
		assert_eq!(bid_share_ppm(1_000, 2_000, 1_000), 0, "at its opening");
		assert_eq!(bid_share_ppm(1_000, 2_000, 1_500), 250_000, "a quarter halfway");
		assert_eq!(bid_share_ppm(1_000, 2_000, 1_900), 810_000);
		assert_eq!(bid_share_ppm(1_000, 2_000, 2_000), 1_000_000, "the whole value at the timeout");
		assert_eq!(bid_share_ppm(1_000, 2_000, 9_000), 1_000_000, "and after it");
		assert_eq!(bid_share_ppm(2_000, 1_000, 900), 0, "an opening after the timeout bids nothing before the timeout");
	}
}
