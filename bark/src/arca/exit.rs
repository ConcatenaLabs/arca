//! The unilateral exit, from the coin's record alone, and `sync`.
//!
//! A coin goes on-chain without the operator: for a leaf of a batch, every
//! node from the batch output down by the owner's own unroll authorisations,
//! then the entry with the preimage; for a board, the owner's conversion; for
//! a coin a reassignment made, each coin it rests on, its checkpoint and the
//! reassignment, all from the pairs in the record. Then, once the exit delay
//! has run from the leaf's confirmation, the owner's claim to an on-chain
//! address of the wallet.
//!
//! Each transaction pays its fee from what it carries for it (a node's
//! reserve, an entry's, a checkpoint's or reassignment's margin), in the
//! coin's asset, when the node accepts that asset for fees and the amount
//! covers the floor. Otherwise it takes a coin of the wallet's in the fee
//! asset the user names, and the reserve goes to the wallet's change. No asset
//! is a fallback: an exit that needs a fee coin and has none named stops and
//! says so.

use std::str::FromStr;

use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Script, Transaction, TxOut};
use serde_json::{json, Value};

use arca_covenant::spend::{FeeSource, KeySpend};
use arca_covenant::{CoinRecord, ExplicitOutput, UnrollTx, ValidCoin, ValidOrigin, WalletPolicy};

use super::chain::{hex, unhex};
use super::keys::CHANGE;
use super::wallet::{sign, Wallet};
use super::Error;

/// Who pays the fees an output's own reserve cannot.
struct Payer {
	asset: Option<AssetId>,
	coin: Option<(OutPoint, TxOut, Keypair)>,
	change: Option<(Script, Keypair)>,
	/// Coins the exit has already taken.
	used: Vec<OutPoint>,
}

fn txs_fee(tx: &Transaction) -> Vec<(AssetId, u64)> {
	tx.output.iter().filter(|o| o.is_fee()).filter_map(|o| Some((o.asset.explicit()?, o.value.explicit()?))).collect()
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
		let asset = payer.asset.ok_or_else(|| Error::Refused("this exit needs a fee coin: the asset it moves is not accepted for fees \
			by the node, or its reserve does not cover the floor; name an accepted asset the wallet holds on-chain (--fee-asset)".into()))?;
		self.fee_for(asset, 1)?;
		let c = self.onchain_coins()?.into_iter()
			.filter(|(op, o, _, _)| o.asset.explicit() == Some(asset) && !payer.used.contains(op))
			.max_by_key(|(_, o, _, _)| o.value.explicit().unwrap_or(0))
			.ok_or_else(|| Error::Refused(format!("the wallet holds no on-chain coin of asset {} to pay the exit's fees with", asset)))?;
		Ok((c.0, c.1, c.2))
	}

	/// Builds one transaction of an exit: with the output's own reserve when
	/// that pays the floor, else with a fee coin, whose input it signs.
	fn with_fee(&self, payer: &mut Payer, build: &dyn Fn(&FeeSource) -> Result<UnrollTx, Error>) -> Result<UnrollTx, Error> {
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
		let mut fee = self.fee_for(asset, 400)?;
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
			return Ok(u);
		}
	}

	/// A spend ending in the owner's key: built with the fee as `with_fee`
	/// chooses, signed by `key`.
	fn key_spend(&self, payer: &mut Payer, key: &Keypair, build: &dyn Fn(&FeeSource) -> Result<KeySpend, Error>) -> Result<UnrollTx, Error> {
		let genesis = self.genesis.genesis_hash();
		self.with_fee(payer, &|f| {
			let ks = build(f)?;
			let sighash = ks.sighash(genesis).map_err(|e| Error::Refused(e.to_string()))?;
			Ok(ks.finish(vec![sign(key, &sighash).as_ref().to_vec()]))
		})
	}

	/// Every transaction that brings `coin` on-chain, in order, and where its
	/// leaf then is.
	fn bring(&self, coin: &ValidCoin, payer: &mut Payer, txs: &mut Vec<UnrollTx>) -> Result<OutPoint, Error> {
		match &coin.origin {
			ValidOrigin::Leaf { valid, preimage, auths } => {
				let mut at = OutPoint::new(valid.round_txid, valid.batch_vout);
				for (node, auth) in valid.branch.nodes.iter().zip(auths) {
					let u = self.with_fee(payer, &|f| node.unroll_tx(at, auth, f).map_err(|e| Error::Refused(e.to_string())))?;
					at = OutPoint::new(u.tx.txid(), node.index as u32);
					txs.push(u);
				}
				let u = self.with_fee(payer, &|f| valid.branch.entry_tx(at, preimage, f).map_err(|e| Error::Refused(e.to_string())))?;
				let leaf = OutPoint::new(u.tx.txid(), 0);
				txs.push(u);
				Ok(leaf)
			},
			ValidOrigin::Board { valid, record } => {
				// The owner's conversion of its own board into the leaf.
				let key = self.keys.leaf(&record.owner_nonce)?;
				if key.x_only_public_key().0 != record.owner {
					return Err(Error::Refused("a board in the record is not this wallet's to convert".into()));
				}
				let policy = record.policy();
				let board = valid.outpoint();
				let u = self.key_spend(payer, &key, &|f| policy.conversion(board, f).map_err(|e| Error::Refused(e.to_string())))?;
				let leaf = OutPoint::new(u.tx.txid(), 0);
				txs.push(u);
				Ok(leaf)
			},
			ValidOrigin::Transfer { inputs, index, .. } => {
				let mut cps = vec![];
				for i in inputs {
					let u = if i.coin.board().is_some() {
						self.with_fee(payer, &|f| i.board_checkpoint_tx(f).map_err(|e| Error::Refused(e.to_string())))?
					} else {
						let at = self.bring(&i.coin, payer, txs)?;
						self.with_fee(payer, &|f| i.checkpoint_tx(at, f).map_err(|e| Error::Refused(e.to_string())))?
					};
					cps.push(OutPoint::new(u.tx.txid(), 0));
					txs.push(u);
				}
				let u = self.with_fee(payer, &|f| coin.reassignment_tx(&cps, f).map_err(|e| Error::Refused(e.to_string())))?;
				let leaf = OutPoint::new(u.tx.txid(), *index as u32);
				txs.push(u);
				Ok(leaf)
			},
		}
	}

	/// Takes `leaf_id` on-chain from its record alone and claims it after the
	/// exit delay. Each call goes as far as the chain allows now; call again
	/// to go on. `fee_asset` pays whatever the coin's own reserves cannot.
	pub fn exit(&mut self, leaf_id: &str, fee_asset: Option<AssetId>) -> Result<Value, Error> {
		let row = self.store.coin(leaf_id)?.ok_or_else(|| Error::Refused(format!("no coin {}", leaf_id)))?;
		if !matches!(row.state.as_str(), "live" | "pending" | "exiting" | "offered") {
			return Err(Error::Refused(format!("coin {} is {}: there is nothing of the wallet's to exit", leaf_id, row.state)));
		}
		let record = Self::record_of(&row)?;
		let now = self.now()?;
		// An exit asks nothing of the expiry: it is what a wallet does when
		// time runs short.
		let policy = WalletPolicy { horizon: 0, ..self.receipt_policy(now) };
		let txs = self.base_txs(&record)?;
		let coin = record.resolve(&txs, &policy).map_err(|e| Error::Refused(e.to_string()))?;
		let key = self.keys.leaf(&row.owner_nonce)?;
		let mut payer = Payer { asset: fee_asset, coin: None, change: None, used: vec![] };
		let (plan, leaf_at): (Vec<Transaction>, OutPoint) = match self.store.exit(leaf_id)? {
			Some((_, txs, _)) => {
				let v: Value = serde_json::from_str(&txs).map_err(|e| Error::Store(e.to_string()))?;
				let plan = v["txs"].as_array().cloned().unwrap_or_default().iter()
					.map(|t| unhex(t.as_str().unwrap_or("")).and_then(|b| elements::encode::deserialize(&b).map_err(|e| Error::Store(e.to_string()))))
					.collect::<Result<Vec<Transaction>, _>>()?;
				let leaf_at = OutPoint::from_str(v["leaf"].as_str().unwrap_or("")).map_err(|e| Error::Store(e.to_string()))?;
				(plan, leaf_at)
			},
			None => {
				let mut built = vec![];
				let leaf_at = self.bring(&coin, &mut payer, &mut built)?;
				let plan: Vec<Transaction> = built.into_iter().map(|u| u.tx).collect();
				let v = json!({"txs": plan.iter().map(|t| hex(&elements::encode::serialize(t))).collect::<Vec<_>>(), "leaf": leaf_at.to_string()});
				self.store.set_exit(leaf_id, "unrolling", &v.to_string(), None)?;
				self.store.set_coin_state(leaf_id, "exiting", "its exit has started")?;
				(plan, leaf_at)
			},
		};
		let mut steps = vec![];
		for t in &plan {
			let f = self.chain.finality(&t.txid())?;
			if f.in_chain() || matches!(f, super::chain::Finality::NotInChain { in_mempool: true }) {
				steps.push(json!({"txid": t.txid().to_string(), "vsize": t.vsize(), "already": f.word()}));
				continue;
			}
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
			self.store.set_exit(leaf_id, "unrolling", &self.store.exit(leaf_id)?.expect("set").1, None)?;
			return Ok(json!({"leaf_id": leaf_id, "state": "unrolling", "broadcast": steps,
				"next": "the leaf's transaction is not in a block yet; run exit again once it is"}));
		}
		let to = self.new_script(super::keys::RECEIVE)?;
		let (asset, value) = (coin.asset, coin.value);
		let leaf = coin.leaf;
		let claim = self.key_spend(&mut payer, &key, &|f| {
			let out = match f {
				FeeSource::Reserve => {
					let fee = self.fee_for(asset, 220)?;
					if fee >= value {
						return Err(Error::Refused(format!("the leaf's {} atoms do not cover its own claim's fee", value)));
					}
					ExplicitOutput::new(asset, value - fee, to.clone())
				},
				FeeSource::Coin { .. } => ExplicitOutput::new(asset, value, to.clone()),
			};
			leaf.exit_tx(leaf_at, asset, value, &[out], f).map_err(|e| Error::Refused(e.to_string()))
		});
		let claim = match claim {
			Ok(c) => c,
			Err(e) => return Ok(json!({"leaf_id": leaf_id, "state": "waiting", "broadcast": steps, "error": e.to_string()})),
		};
		match self.chain.broadcast(&claim.tx) {
			Ok(txid) => {
				let txs = self.store.exit(leaf_id)?.expect("set").1;
				self.store.set_exit(leaf_id, "claimed", &txs, Some(&txid.to_string()))?;
				self.store.set_coin_state(leaf_id, "exited", &format!("claimed by {}", txid))?;
				Ok(json!({"leaf_id": leaf_id, "state": "claimed", "broadcast": steps, "claim": {"txid": txid.to_string(),
					"vsize": claim.tx.vsize(), "pays": claim.tx.output[0].value.explicit().map(|v| v.to_string()),
					"to": self.chain.address(&to)?}}))
			},
			Err(e) if e.to_string().contains("non-BIP68-final") => {
				let txs = self.store.exit(leaf_id)?.expect("set").1;
				self.store.set_exit(leaf_id, "waiting", &txs, None)?;
				Ok(json!({"leaf_id": leaf_id, "state": "waiting", "broadcast": steps,
					"next": format!("the exit delay of {} s runs from the leaf's confirmation; the node refused the claim before it: {}",
						leaf.exit_delay.seconds(), e)}))
			},
			Err(e) => Ok(json!({"leaf_id": leaf_id, "state": "waiting", "broadcast": steps, "error": e.to_string()})),
		}
	}

	/// Everything the wallet does on its own: the re-check of every coin
	/// against the chain, transfer requests the server never answered, the
	/// mailbox, and every participation as far as it can go.
	pub fn sync(&mut self) -> Result<Value, Error> {
		let recheck = self.recheck()?;
		let transfers = self.retry_transfers()?;
		let mailbox = self.mailbox().unwrap_or_else(|e| json!({"error": e.to_string()}));
		let participations = self.progress_participations().map(Value::Array).unwrap_or_else(|e| json!({"error": e.to_string()}));
		Ok(json!({"recheck": recheck, "transfers": transfers, "mailbox": mailbox, "participations": participations}))
	}

	/// The decoded coin record of `leaf_id`, for people.
	pub fn record(&self, leaf_id: &str) -> Result<Value, Error> {
		let row = self.store.coin(leaf_id)?.ok_or_else(|| Error::Refused(format!("no coin {}", leaf_id)))?;
		let r = Self::record_of(&row)?;
		let detail = match &r {
			CoinRecord::Leaf { record, .. } => record.to_json().map_err(|e| Error::Refused(e.to_string()))?,
			CoinRecord::Board(b) => b.to_json().map_err(|e| Error::Refused(e.to_string()))?,
			CoinRecord::Transfer(t) => json!({"inputs": t.inputs.len(), "outputs": t.outputs.len(), "index": t.index}),
		};
		Ok(json!({"leaf_id": leaf_id, "kind": row.kind, "state": row.state, "record": hex(&row.record), "detail": detail}))
	}
}
