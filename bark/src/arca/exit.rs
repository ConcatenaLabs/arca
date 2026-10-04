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

use super::chain::hex;
use super::keys::CHANGE;
use super::wallet::{sign, Wallet};
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
}

/// Who pays the fees an output's own reserve cannot.
pub(crate) struct Payer {
	asset: Option<AssetId>,
	coin: Option<(OutPoint, TxOut, Keypair)>,
	change: Option<(Script, Keypair)>,
	/// Coins the exit has already taken.
	used: Vec<OutPoint>,
}

impl Payer {
	/// A payer of fees in `asset`, when named.
	pub(crate) fn new(asset: Option<AssetId>) -> Payer {
		Payer { asset, coin: None, change: None, used: vec![] }
	}
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
	pub(crate) fn key_spend(&self, payer: &mut Payer, key: &Keypair, build: &dyn Fn(&FeeSource) -> Result<KeySpend, Error>) -> Result<UnrollTx, Error> {
		let genesis = self.genesis.genesis_hash();
		self.with_fee(payer, &|f| {
			let ks = build(f)?;
			let sighash = ks.sighash(genesis).map_err(|e| Error::Refused(e.to_string()))?;
			Ok(ks.finish(vec![sign(key, &sighash).as_ref().to_vec()]))
		})
	}

	/// Every output on the way from the chain to `coin`'s leaf, the leaf's
	/// own last: for a leaf of a batch, the batch output, each node's and the
	/// entry's; for a board, the board output; for a coin a reassignment made,
	/// those of each coin it spends, that coin's leaf and its checkpoint.
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
		}
		out.push(coin.output().txout());
	}

	/// Every transaction still needed to bring `coin` on-chain, in order, and
	/// where its leaf then is, starting from where the chain holds its path
	/// now (`here`, from [`Self::path_outputs`] and the chain's `locate`):
	/// the lowest output of the path that is unspent, so the plan follows
	/// whichever round now pays the batch output, a board's conversion, and
	/// every step someone else has already published.
	fn bring(&self, coin: &ValidCoin, payer: &mut Payer, txs: &mut Vec<UnrollTx>, here: &Here) -> Result<OutPoint, Error> {
		if let Some(at) = here.at(&coin.output()) {
			return Ok(at);
		}
		match &coin.origin {
			ValidOrigin::Leaf { valid, preimage, auths } => {
				let b = &valid.branch;
				let n = b.nodes.len();
				let start = match here.at(&b.entry_output()) {
					Some(at) => Some((n, at)),
					None => (0..n).rev().find_map(|i| here.at(&b.nodes[i].output()).map(|at| (i, at))),
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
				let mut cps = vec![];
				for i in inputs {
					let cp = match here.at(&i.checkpoint_output()) {
						Some(at) => at,
						None => {
							let u = match (i.coin.board(), here.at(&i.coin.output())) {
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
				let u = self.with_fee(payer, &|f| coin.reassignment_tx(&cps, f).map_err(|e| Error::Refused(e.to_string())))?;
				let leaf = OutPoint::new(u.tx.txid(), *index as u32);
				txs.push(u);
				Ok(leaf)
			},
		}
	}

	/// Takes `leaf_id` on-chain from its record alone and claims it after the
	/// exit delay. Each call goes as far as the chain allows now, building
	/// what is still needed from where the chain holds the coin's path now;
	/// call again to go on. `fee_asset` pays whatever the coin's own reserves
	/// cannot, and is remembered for the exit's later steps. The claim goes to
	/// one address of the wallet's, chosen when the exit starts.
	pub fn exit(&mut self, leaf_id: &str, fee_asset: Option<AssetId>) -> Result<Value, Error> {
		let row = self.store.coin(leaf_id)?.ok_or_else(|| Error::Refused(format!("no coin {}", leaf_id)))?;
		// A coin handed over to a participation or a transfer is the wallet's
		// until the chain shows otherwise: one taken by a round or a
		// co-signed spend is `spent`, and is not exited.
		if !matches!(row.state.as_str(), "live" | "pending" | "exiting" | "offered" | "given" | "forfeited" | "sending") {
			return Err(Error::Refused(format!("coin {} is {}: there is nothing of the wallet's to exit", leaf_id, row.state)));
		}
		let record = Self::record_of(&row)?;
		let now = self.now()?;
		// An exit asks nothing of the expiry: it is what a wallet does when
		// time runs short. The coin is the one the wallet accepted; where its
		// path is now is the chain's.
		let policy = WalletPolicy { horizon: 0, ..self.receipt_policy(now) };
		let txs = self.accepted_bases(&record)?;
		let coin = record.resolve(&txs, &policy).map_err(|e| Error::Refused(e.to_string()))?;
		let key = self.keys.leaf(&row.owner_nonce)?;
		let prior: Value = match self.store.exit(leaf_id)? {
			Some((_, j, _)) => serde_json::from_str(&j).map_err(|e| Error::Store(e.to_string()))?,
			None => json!({}),
		};
		let fee_asset = match fee_asset {
			Some(a) => Some(a),
			None => prior["fee_asset"].as_str().map(AssetId::from_str).transpose().map_err(|e| Error::Store(e.to_string()))?,
		};
		let mut payer = Payer { asset: fee_asset, coin: None, change: None, used: vec![] };
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
				}
				// The path is cut: say where, when another spend cut it.
				return Err(match self.paid_elsewhere(&coin)? {
					Some(why) => {
						self.store.refused(&format!("exit of {}", leaf_id), &why)?;
						Error::Refused(why)
					},
					None => e,
				});
			},
		};
		self.let_go(leaf_id, &row.state)?;
		// One claim address for the exit, however many times it is run.
		let claim_index = match prior["claim_index"].as_u64() {
			Some(i) => i as u32,
			None => self.store.take_index(super::keys::RECEIVE)?,
		};
		let plan: Vec<Transaction> = built.into_iter().map(|u| u.tx).collect();
		let record_exit = |state: &str, s: &Wallet| -> Result<(), Error> {
			let v = json!({"txs": plan.iter().map(|t| hex(&elements::encode::serialize(t))).collect::<Vec<_>>(), "leaf": leaf_at.to_string(),
				"fee_asset": fee_asset.map(|a| a.to_string()), "claim_index": claim_index});
			s.store.set_exit(leaf_id, state, &v.to_string(), None)
		};
		record_exit("unrolling", self)?;
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
		let (asset, value) = (coin.asset, coin.value);
		let leaf = coin.leaf;
		let claim = self.key_spend(&mut payer, &key, &|f| {
			// The leaf's own value pays the claim's fee unless a fee coin
			// does; the wallet never splits its own claim.
			let out = match f {
				FeeSource::Reserve | FeeSource::Split { .. } => {
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
				// The coin is exited once the claim is final; until then the
				// wallet follows it, and builds it again should it leave the
				// chain and the mempool.
				let txs = self.store.exit(leaf_id)?.expect("set").1;
				self.store.set_exit(leaf_id, "claimed", &txs, Some(&txid.to_string()))?;
				self.store.set_coin_state(leaf_id, "exiting", &format!("claimed by {}; the wallet follows the claim until it is final", txid))?;
				Ok(json!({"leaf_id": leaf_id, "state": "claimed", "broadcast": steps, "claim": {"txid": txid.to_string(),
					"vsize": claim.tx.vsize(), "pays": claim.tx.output[0].value.explicit().map(|v| v.to_string()),
					"to": self.chain.address(&to)?}}))
			},
			Err(e) if e.to_string().contains("non-BIP68-final") => {
				record_exit("waiting", self)?;
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
					self.store.set_coin_state(leaf_id, "exiting", &format!("claimed by {}, which is {}; the wallet follows the claim until \
						it is final", txid, f.word()))?;
					return Ok(Some(json!({"leaf_id": leaf_id, "state": "claimed", "claim": {"txid": txid, "finality": f.word()}})));
				}
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
	fn paid_elsewhere(&self, coin: &ValidCoin) -> Result<Option<String>, Error> {
		let ValidOrigin::Transfer { inputs, .. } = &coin.origin else { return Ok(None) };
		let from = self.store.meta("birthday")?.and_then(|b| b.parse::<u64>().ok()).unwrap_or(0).saturating_sub(1000);
		let mine = coin.output().txout();
		let spent_by = |out: &TxOut| -> Result<Option<(Transaction, Transaction)>, Error> {
			let Some((tx, h)) = self.chain.find_payment(out, from)? else { return Ok(None) };
			let vout = tx.output.iter().position(|o| o == out).expect("pays it") as u32;
			Ok(self.chain.spender(&OutPoint::new(tx.txid(), vout), h)?.map(|(sp, _)| (tx, sp)))
		};
		let elsewhere = |id: &arca_covenant::LeafId, sp: &Transaction| format!("coin {} it rests on is spent on the chain by {}, which \
			is not this coin's way out: the operator co-signed another spend of coin {} (a payment, or a forfeit), which reached the \
			chain first, so this coin cannot be brought on the chain", id, sp.txid(), id);
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

	/// Moves on every exit the wallet has started, with the fee asset each was
	/// started with.
	pub(crate) fn progress_exits(&mut self) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		for c in self.store.coins_in("exiting")? {
			out.push(self.exit(&c.leaf_id, None).unwrap_or_else(|e| json!({"leaf_id": c.leaf_id, "error": e.to_string()})));
		}
		Ok(out)
	}

	/// Everything the wallet does on its own: the re-check of every coin
	/// against the chain, board registrations and transfer requests the
	/// server never answered, the mailbox, every participation as far as it
	/// can go, every forfeit it signed without the preimage in hand, followed
	/// on the chain, and every exit it started.
	pub fn sync(&mut self) -> Result<Value, Error> {
		// The witness first: after a rollback of the operator's signer's
		// record the wallet does only what it does on the chain.
		let witness = self.witness().unwrap_or_else(|e| json!({"error": e.to_string()}));
		let gone = self.rolled_back()?.is_some();
		let boards = if gone { vec![] } else { self.retry_boards()? };
		let recheck = self.recheck()?;
		let transfers = if gone { vec![] } else { self.retry_transfers()? };
		let mailbox = self.mailbox().unwrap_or_else(|e| json!({"error": e.to_string()}));
		let participations = if gone { Value::Array(vec![]) } else {
			self.progress_participations().map(Value::Array).unwrap_or_else(|e| json!({"error": e.to_string()}))
		};
		let forfeits = self.watch_forfeits().map(Value::Array).unwrap_or_else(|e| json!({"error": e.to_string()}));
		let exits = self.progress_exits().map(Value::Array).unwrap_or_else(|e| json!({"error": e.to_string()}));
		Ok(json!({"witness": witness, "boards": boards, "recheck": recheck, "transfers": transfers, "mailbox": mailbox,
			"participations": participations, "forfeits": forfeits, "exits": exits}))
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
