//! Speeding up the wallet's transactions on the chain, and refreshing what
//! it receives out of round.
//!
//! **Speeding up.** A transaction the wallet needs (a step of an exit, its
//! claim, a coin coming home) can wait in the mempool for good: its fee was
//! set at the node's floor when it was broadcast, and the producers now take
//! only more, or the fee asset's price fell since. An exit's steps cannot be
//! replaced (their inputs signal no replacement, and an operator, a
//! watchtower or the wallet may each have broadcast them), so the wallet
//! speeds one up by a child: a transaction that spends an output of the
//! wallet's in the waiting transaction, or in one of its descendants, and
//! pays enough for itself and every ancestor still in the mempool, which the
//! producer adds by value in the reference unit whatever asset each pays in.
//! The child pays its fee in the asset of the output it spends when the node
//! accepts that asset for fees, and otherwise (or when that output is too
//! small) adds a coin of the wallet's on the chain in an accepted asset as a
//! second input. Its inputs signal replacement, so a later raise replaces it
//! instead of piling up children.
//!
//! An exit's steps leave the wallet that output: a step paid from its own
//! reserve pays the node's floor of it and gives the rest to the wallet's
//! change ([`super::exit::Payer::anchor`]). A coin of a supervised asset at an
//! address its issuer froze cannot be spent, so it speeds nothing up; the
//! wallet says so and looks for another output. A transaction in which
//! nothing is the wallet's (every step broadcast by someone else, from the
//! batch down to the leaf) cannot be sped up by the wallet at all, and the
//! refusal says that.
//!
//! [`Wallet::speed_up_exit`] runs at every `sync` for every exit under way:
//! a transaction it needs that has waited [`STUCK_BLOCKS`] blocks in the
//! mempool is sped up to twice the node's relay floor, and the rate doubles
//! at each further wait, at most [`MAX_RAISES`] times.
//!
//! **Refreshing what it receives.** A coin received out of round can be spent
//! twice by a sender up its lineage together with the operator, or taken by
//! a sender's exit of an earlier coin of its lineage, until it is refreshed
//! in a round. [`Wallet::refresh_received`] gives every such coin up in the
//! next round for a leaf of its own, at the operator's refresh fee, which
//! shortens that trust to one round's interval.

use std::str::FromStr;

use elements::secp256k1_zkp::Keypair;
use elements::{AssetId, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid};
use serde_json::{json, Value};

use arca_covenant::CoinRecord;

use super::chain::MempoolEntry;
use super::keys::{p2wpkh, CHANGE, RECEIVE};
use super::wallet::{owner_of, Wallet};
use super::Error;

/// Seconds a refresh of received coins may wait at the operator, for funds
/// or for its in-flight cap, before the wallet takes it back.
pub const WITHDRAW_AFTER: u64 = 120;
/// Seconds after taking a coin back from a refresh that waited before the
/// wallet gives it up in a refresh again.
pub const RETRY_AFTER: u64 = 600;

/// The wall-clock time, in seconds.
fn wall_now() -> u64 {
	web_time::SystemTime::now().duration_since(web_time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The store's key for the time a refresh of received coins was given up.
fn received_key(pid: &str) -> String {
	format!("refresh-received:{}", pid)
}

/// The store's key for the time a received coin was taken back from a
/// refresh that waited.
fn withdrawn_key(leaf_id: &str) -> String {
	format!("refresh-withdrawn:{}", leaf_id)
}

/// What the operator can fund now of the asset named `asset` for refreshes,
/// by its `info`: what a round can pay of it (`fundable`), within what its
/// in-flight cap leaves (`in_flight_cap` less `in_flight`), when it sets
/// one. `None` when the operator does not say what it can fund, or does not
/// serve the asset.
fn fundable_room(info: &Value, asset: &str) -> Option<u64> {
	let a = info["assets"].as_array()?.iter().find(|a| a["asset"].as_str() == Some(asset))?;
	let n = |k: &str| a[k].as_str().and_then(|v| v.parse::<u64>().ok());
	let fundable = n("fundable")?;
	Some(match n("in_flight_cap") {
		Some(cap) => fundable.min(cap.saturating_sub(n("in_flight").unwrap_or(0))),
		None => fundable,
	})
}

/// Blocks a transaction an exit needs waits in the mempool before the wallet
/// speeds it up, and again between two raises.
pub(crate) const STUCK_BLOCKS: u64 = 2;
/// Times the wallet raises the rate of one exit, doubling it each time.
pub(crate) const MAX_RAISES: u64 = 8;
/// The keys of an exit's record that keep its speeding up across runs: the
/// height each of its transactions was first seen in the mempool at, how
/// often it was raised, and the height of the last raise.
pub(crate) const SEEN: &str = "seen";
pub(crate) const RAISES: &str = "raises";
pub(crate) const RAISED_AT: &str = "raised_at";
/// Every transaction the exit broadcast, across its runs.
pub(crate) const STEPS: &str = "steps";
/// A child's inputs signal replacement (BIP125): a raise replaces it.
const REPLACEABLE: Sequence = Sequence(0xffff_fffd);
/// How far the on-chain key windows are searched past the last index used.
const KEY_GAP: u32 = 20;

/// An output of the wallet's in a waiting transaction, which a child spends.
struct Handle {
	outpoint: OutPoint,
	out: TxOut,
	key: Keypair,
	/// The transaction holding it, as the mempool ranks it.
	entry: MempoolEntry,
	/// A child of the wallet's that spends it already, which a raise
	/// replaces.
	earlier: Option<Transaction>,
}

fn value_of(o: &TxOut) -> Option<(AssetId, u64)> {
	Some((o.asset.explicit()?, o.value.explicit()?))
}

impl Wallet {
	/// The wallet's on-chain key whose P2WPKH script is `script`.
	fn onchain_key_of(&self, script: &Script) -> Result<Option<Keypair>, Error> {
		if !script.is_v0_p2wpkh() {
			return Ok(None);
		}
		for chain in [RECEIVE, CHANGE] {
			for i in 0..self.store.indices(chain)?.saturating_add(KEY_GAP) {
				let k = self.keys.onchain(chain, i)?;
				if p2wpkh(&k) == *script {
					return Ok(Some(k));
				}
			}
		}
		Ok(None)
	}

	/// Whether `tx` is a child of the wallet's: every input signals
	/// replacement and spends an output of the wallet's.
	fn is_own_child(&self, tx: &Transaction) -> Result<bool, Error> {
		if tx.input.is_empty() || tx.input.iter().any(|i| i.sequence != REPLACEABLE) {
			return Ok(false);
		}
		for i in &tx.input {
			let Some(prev) = self.chain.transaction(&i.previous_output.txid)? else { return Ok(false) };
			let Some(o) = prev.output.get(i.previous_output.vout as usize) else { return Ok(false) };
			if self.onchain_key_of(&o.script_pubkey)?.is_none() {
				return Ok(false);
			}
		}
		Ok(true)
	}

	/// The output a child of `txid` spends: one of the wallet's, unspent but
	/// for a child of its own, in `txid` or in one of its descendants in the
	/// mempool, the deepest first, so that the child lifts the most
	/// ancestors. A refusal saying why there is none.
	fn handles(&self, txid: Txid) -> Result<Vec<Handle>, Error> {
		let mempool = self.chain.mempool_txs()?;
		let mut candidates = vec![];
		for t in std::iter::once(txid).chain(self.chain.mempool_descendants(&txid)?) {
			let Some(tx) = mempool.iter().find(|m| m.txid() == t).cloned() else { continue };
			if t != txid && self.is_own_child(&tx)? {
				continue;
			}
			let Some(entry) = self.chain.mempool_entry(&t)? else { continue };
			candidates.push((tx, entry));
		}
		candidates.sort_by(|a, b| b.1.ancestor_vsize.cmp(&a.1.ancestor_vsize));
		let supervised = self.chain.supervised_assets()?;
		let mut frozen = None;
		let mut found = vec![];
		for (tx, entry) in candidates {
			for (j, o) in tx.output.iter().enumerate() {
				let Some((asset, _)) = value_of(o) else { continue };
				if o.is_fee() {
					continue;
				}
				let Some(key) = self.onchain_key_of(&o.script_pubkey)? else { continue };
				if supervised.contains(&asset) {
					let (f, paused) = self.chain.freeze_status(asset, &o.script_pubkey)?;
					if f || paused {
						frozen = Some(asset);
						continue;
					}
				}
				let outpoint = OutPoint::new(tx.txid(), j as u32);
				let spender = mempool.iter().find(|m| m.input.iter().any(|i| i.previous_output == outpoint)).cloned();
				let earlier = match spender {
					None => None,
					Some(s) if self.is_own_child(&s)? => Some(s),
					Some(_) => continue,
				};
				found.push(Handle { outpoint, out: o.clone(), key, entry, earlier });
			}
		}
		if !found.is_empty() {
			return Ok(found);
		}
		Err(Error::Refused(match frozen {
			Some(a) => format!("{} cannot be sped up: the only output of the wallet's in it is of asset {}, which its issuer froze at that \
				address, so it cannot be spent", txid, a),
			None => format!("{} cannot be sped up by this wallet: nothing in it or in what spends it in the mempool is the wallet's to \
				spend", txid),
		}))
	}

	/// Speeds up `txid`, which waits in the mempool: a child spending an
	/// output of the wallet's in it or in a descendant pays for itself and
	/// every ancestor still in the mempool at `rate` atoms of the reference
	/// unit per 1,000 vbytes (by default twice the node's relay floor), in
	/// `fee_asset` or, unnamed, in the asset of that output where the node
	/// accepts it and otherwise in one the wallet chooses among those it
	/// holds on the chain. A child of the wallet's already spending that
	/// output is replaced, outbid as the node asks. Refused above `max_fee`
	/// atoms of the fee asset, when given.
	pub fn speed_up(&mut self, txid: Txid, fee_asset: Option<AssetId>, rate: Option<u64>, max_fee: Option<u64>) -> Result<Value, Error> {
		let (in_block, in_mempool) = self.chain.whereabouts(&txid)?;
		if in_block {
			return Err(Error::Refused(format!("{} is in a block already: it needs no speeding up", txid)));
		}
		if !in_mempool {
			return Err(Error::Refused(format!("{} is not in the node's mempool: it cannot be sped up until it is broadcast again", txid)));
		}
		let floor = self.chain.relay_floor_value()?;
		let rate = rate.unwrap_or(floor.saturating_mul(2)).max(floor);
		let mut all = self.handles(txid)?.into_iter();
		let h = all.next().expect("one at least");
		// The package's other outputs of the wallet's, which pay before a coin
		// of the wallet's on the chain is added.
		let mut more: Vec<Handle> = all.filter(|o| o.earlier.is_none()).collect();
		let (h_asset, h_value) = value_of(&h.out).expect("an explicit output");
		let rates = self.chain.fee_rates()?;
		let accepted = |a: &AssetId| rates.get(a).copied().filter(|r| *r > 0);
		let fee_asset = match fee_asset {
			Some(a) => {
				accepted(&a).ok_or_else(|| Self::not_accepted(a))?;
				a
			},
			None if accepted(&h_asset).is_some() => h_asset,
			None => self.choose_fee_asset(h_asset, &self.fee_holdings()?)?,
		};
		let fee_rate = accepted(&fee_asset).expect("accepted") as u128;
		let earlier_value = match &h.earlier {
			Some(e) => self.chain.mempool_entry(&e.txid())?.map(|m| m.fee_value).unwrap_or(0),
			None => 0,
		};
		let (change, change_key) = self.change_key()?;
		let mut coin: Option<(OutPoint, TxOut, Keypair)> = None;
		let mut anchors: Vec<(OutPoint, TxOut, Keypair)> = vec![];
		let mut fee = 1u64;
		for _ in 0..32 {
			let mut inputs = vec![(h.outpoint, h.out.clone(), h.key)];
			inputs.extend(anchors.iter().cloned());
			if let Some(c) = &coin {
				inputs.push(c.clone());
			}
			let tx = Self::child_tx(&inputs, &change, fee_asset, fee)?;
			let vsize = Self::signed_vsize(&tx, &(0..inputs.len()).collect::<Vec<_>>());
			// The package's value at `rate`, less what its ancestors pay; at
			// least the child's own share, and past a child it replaces.
			let package = ((rate as u128 * (h.entry.ancestor_vsize + vsize) as u128).div_ceil(1000)) as u64;
			let mut need = package.saturating_sub(h.entry.ancestor_fee_value).max((rate as u128 * vsize as u128).div_ceil(1000) as u64);
			if h.earlier.is_some() {
				need = need.max(earlier_value.saturating_add((floor as u128 * vsize as u128).div_ceil(1000) as u64).saturating_add(1));
			}
			let need_atoms = ((need as u128 * 100_000_000).div_ceil(fee_rate)).min(u64::MAX as u128) as u64 + 1;
			if let Some(m) = max_fee {
				if need_atoms > m {
					return Err(Error::Refused(format!("speeding {} up to {} a kvB costs {} of asset {}, above the {} allowed", txid, rate,
						need_atoms, fee_asset, m)));
				}
			}
			let held: u64 = inputs.iter().filter_map(|(_, o, _)| value_of(o)).filter(|(a, _)| *a == fee_asset).map(|(_, v)| v).sum();
			if held < need_atoms {
				if coin.is_none() {
					if let Some(i) = more.iter().position(|o| o.out.asset.explicit() == Some(fee_asset)) {
						let o = more.remove(i);
						anchors.push((o.outpoint, o.out, o.key));
						continue;
					}
				}
				if coin.is_some() {
					return Err(Error::Refused(format!("speeding {} up needs {} of asset {}, more than the wallet's largest coin of it on the \
						chain and the output it spends hold", txid, need_atoms, fee_asset)));
				}
				let c = self.fee_candidates()?.into_iter()
					.filter(|(op, o, _)| *op != h.outpoint && o.asset.explicit() == Some(fee_asset))
					.max_by_key(|(_, o, _)| o.value.explicit().unwrap_or(0))
					.ok_or_else(|| Error::Refused(format!("speeding {} up needs a coin of an asset the network takes for fees, {}: the \
						wallet holds none on the chain{}", txid, fee_asset, if fee_asset == h_asset { " beyond the output it spends" } else { "" })))?;
				coin = Some(c);
				continue;
			}
			if fee >= need_atoms {
				let mut tx = tx;
				for (i, (_, o, k)) in inputs.iter().enumerate() {
					self.sign_p2wpkh(&mut tx, i, o, k);
				}
				let child = self.chain.broadcast_any_fee(&tx)?;
				let _ = change_key;
				return Ok(json!({
					"txid": txid.to_string(), "child": child.to_string(), "spends": format!("{}:{}", h.outpoint.txid, h.outpoint.vout),
					"second_input": coin.as_ref().map(|(op, _, _)| format!("{}:{}", op.txid, op.vout)),
					"other_outputs": anchors.iter().map(|(op, _, _)| format!("{}:{}", op.txid, op.vout)).collect::<Vec<_>>(),
					"replaced": h.earlier.as_ref().map(|e| e.txid().to_string()),
					"rate_per_kvb": rate, "fee": {"asset": fee_asset.to_string(), "amount": fee.to_string()},
					"package": {"vsize": h.entry.ancestor_vsize + vsize, "ancestors_paid": h.entry.ancestor_fee_value, "child_pays": need},
					"asset_of_output": h_asset.to_string(), "output_value": h_value.to_string(),
				}));
			}
			fee = need_atoms;
		}
		Err(Error::Refused(format!("no child of {} could be sized", txid)))
	}

	/// A child spending `inputs` (each an outpoint, its output and its key),
	/// paying `fee` of `fee_asset`, every other atom back to `change`, one
	/// output an asset. Change of the fee asset too small to be worth an
	/// output goes to the fee.
	fn child_tx(inputs: &[(OutPoint, TxOut, Keypair)], change: &Script, fee_asset: AssetId, fee: u64) -> Result<Transaction, Error> {
		let mut by: std::collections::BTreeMap<AssetId, u64> = Default::default();
		for (_, o, _) in inputs {
			let (a, v) = value_of(o).ok_or_else(|| Error::Refused("an input of the child is not explicit".into()))?;
			*by.entry(a).or_default() += v;
		}
		let mut fee = fee;
		let mut output = vec![];
		for (a, v) in by {
			let left = if a == fee_asset { v.saturating_sub(fee) } else { v };
			if a == fee_asset && left < super::exit::CHILD_DUST {
				fee = fee.saturating_add(left);
				continue;
			}
			if left > 0 {
				output.push(TxOut {
					asset: elements::confidential::Asset::Explicit(a),
					value: elements::confidential::Value::Explicit(left),
					nonce: elements::confidential::Nonce::Null,
					script_pubkey: change.clone(),
					witness: Default::default(),
				});
			}
		}
		output.push(TxOut::new_fee(fee, fee_asset));
		Ok(Transaction {
			version: 2,
			lock_time: elements::LockTime::ZERO,
			input: inputs.iter().map(|(op, _, _)| TxIn { previous_output: *op, sequence: REPLACEABLE, ..Default::default() }).collect(),
			output,
		})
	}

	/// The exit of `leaf_id` sped up when a transaction it needs has waited
	/// [`STUCK_BLOCKS`] blocks in the mempool (and as long since its last
	/// raise): its deepest waiting transaction, at twice the node's relay
	/// floor doubled once for each earlier raise, at most [`MAX_RAISES`]
	/// times. `None` when nothing waits that long.
	pub(crate) fn speed_up_exit(&mut self, leaf_id: &str) -> Result<Option<Value>, Error> {
		let Some((state, j, claim)) = self.store.exit(leaf_id)? else { return Ok(None) };
		let mut v: Value = serde_json::from_str(&j).map_err(|e| Error::Store(e.to_string()))?;
		let mut txids: Vec<Txid> = v[STEPS].as_array().into_iter().flatten()
			.filter_map(|t| t.as_str().and_then(|t| Txid::from_str(t).ok())).collect();
		for t in v["txs"].as_array().into_iter().flatten() {
			let bytes = super::chain::unhex(t.as_str().unwrap_or(""))?;
			let tx: Transaction = elements::encode::deserialize(&bytes).map_err(|e| Error::Store(e.to_string()))?;
			if !txids.contains(&tx.txid()) {
				txids.push(tx.txid());
			}
		}
		if let Some(c) = claim.as_deref().and_then(|c| Txid::from_str(c).ok()) {
			txids.push(c);
		}
		if txids.is_empty() {
			return Ok(None);
		}
		let tip = self.chain.tip()?.height;
		if !v[SEEN].is_object() {
			v[SEEN] = json!({});
		}
		let mut stuck = None;
		let mut changed = false;
		for t in &txids {
			let (in_block, in_mempool) = self.chain.whereabouts(t)?;
			if in_block || !in_mempool {
				continue;
			}
			let key = t.to_string();
			let first = match v[SEEN][&key].as_u64() {
				Some(h) => h,
				None => {
					v[SEEN][&key] = json!(tip);
					changed = true;
					tip
				},
			};
			if tip >= first + STUCK_BLOCKS {
				stuck = Some(*t);
			}
		}
		let raises = v[RAISES].as_u64().unwrap_or(0);
		let recent = v[RAISED_AT].as_u64().is_some_and(|h| tip < h + STUCK_BLOCKS);
		let save = |v: &Value, s: &Wallet| s.store.set_exit(leaf_id, &state, &v.to_string(), claim.as_deref());
		let Some(t) = stuck.filter(|_| !recent && raises < MAX_RAISES) else {
			if changed {
				save(&v, self)?;
			}
			return Ok(None);
		};
		let floor = self.chain.relay_floor_value()?;
		let rate = floor.saturating_mul(2u64.saturating_pow(raises as u32 + 1));
		let fee_asset = v["fee_asset"].as_str().and_then(|a| AssetId::from_str(a).ok());
		let r = match self.speed_up(t, fee_asset, Some(rate), None) {
			Ok(r) => r,
			// A fee asset the exit named that the node no longer takes:
			// the wallet chooses another.
			Err(_) if fee_asset.is_some() => self.speed_up(t, None, Some(rate), None)?,
			Err(e) => {
				self.store.refused(&format!("speeding up the exit of {}", leaf_id), &e.to_string())?;
				save(&v, self)?;
				return Err(e);
			},
		};
		v[RAISES] = json!(raises + 1);
		v[RAISED_AT] = json!(tip);
		save(&v, self)?;
		if let Some(row) = self.store.coin(leaf_id)? {
			self.store.set_coin_state(leaf_id, &row.state, &format!("its exit waited in the mempool for {} blocks: the wallet sped it up \
				by {} at {} a kvB", STUCK_BLOCKS, r["child"].as_str().unwrap_or(""), rate))?;
		}
		Ok(Some(r))
	}

	/// Whether a sender other than the wallet signed into the lineage of
	/// `record` since its last round or board: a coin received out of round,
	/// which its senders together with the operator could spend again until
	/// it is refreshed. The change of the wallet's own payment from a coin of
	/// a round is not.
	fn received_from_another(&self, record: &CoinRecord) -> Result<bool, Error> {
		let inputs: Vec<&CoinRecord> = match record {
			CoinRecord::Transfer(t) => t.inputs.iter().map(|i| &i.coin).collect(),
			CoinRecord::Fill(_) => return Ok(true),
			_ => return Ok(false),
		};
		for c in inputs {
			let (owner, nonce) = owner_of(c);
			if self.keys.leaf_xonly(&nonce)? != owner || self.received_from_another(c)? {
				return Ok(true);
			}
		}
		Ok(false)
	}

	/// Gives up in the operator's next round the coins the wallet received
	/// out of round and has not refreshed, for a leaf of its own, at the
	/// operator's refresh fee within `max_fee_ppm` (by default the wallet's
	/// bound): a coin held live and final, from a sender other than the
	/// wallet. Only with an operator that takes back a refresh that waits
	/// (`participations.withdraw` in its `info`), and in each asset only as
	/// much as the operator can fund now: what `fundable` says a round can
	/// pay of it, within what its in-flight cap leaves, if it sets one. A
	/// coin the wallet took back from a refresh that waited
	/// ([`Self::withdraw_waited`]) is left for [`RETRY_AFTER`] seconds.
	/// Answers what it gave up (`participations`), one per asset, and every
	/// coin it left as it is, with why (`left`).
	pub fn refresh_received(&mut self, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		let info = self.server_info()?;
		let withdraws = Self::operator_withdraws(&info);
		let wall = wall_now();
		let mut room: std::collections::BTreeMap<String, Option<u64>> = Default::default();
		let mut take = vec![];
		let mut left = vec![];
		for c in self.store.coins_in("live")? {
			if !matches!(c.kind.as_str(), "transfer" | "fill") || super::resting::is_order_coin(&c) {
				continue;
			}
			let record = Self::record_of(&c)?;
			if !self.received_from_another(&record)? {
				continue;
			}
			if !withdraws {
				left.push(json!({"leaf_id": c.leaf_id, "why": "the operator cannot take back a refresh that waits, so the wallet gives up \
					no received coin in one: it stays live, to pay with"}));
				continue;
			}
			if let Some(t) = self.store.meta(&withdrawn_key(&c.leaf_id))?.and_then(|t| t.parse::<u64>().ok()) {
				if wall < t.saturating_add(RETRY_AFTER) {
					left.push(json!({"leaf_id": c.leaf_id, "why": format!("taken back from a refresh that waited for the operator; \
						tried again {} s after", RETRY_AFTER)}));
					continue;
				}
			}
			// Each coin quoted alone first, so one the operator's schedule or
			// the wallet's bound refuses holds back no other.
			if let Err(e) = self.refresh_quote(std::slice::from_ref(&c.leaf_id), max_fee_ppm) {
				left.push(json!({"leaf_id": c.leaf_id, "why": e.to_string()}));
				continue;
			}
			let r = room.entry(c.asset.clone()).or_insert_with(|| fundable_room(&info, &c.asset));
			match r {
				Some(v) if *v >= c.value => {
					*v -= c.value;
					take.push(c.leaf_id.clone());
				},
				_ => left.push(json!({"leaf_id": c.leaf_id, "why": "the operator cannot fund its refresh now: it stays live, and is \
					given up once the operator can"})),
			}
		}
		if take.is_empty() {
			return Ok(json!({"participations": [], "left": left}));
		}
		let quote = self.refresh_quote(&take, max_fee_ppm)?;
		let mut out = self.participate(quote, None)?;
		for p in out["participations"].as_array().into_iter().flatten() {
			if let Some(pid) = p["participation"].as_str().filter(|_| p.get("error").is_none()) {
				self.store.set_meta(&received_key(pid), &wall.to_string())?;
			}
		}
		out["left"] = json!(left);
		out["refreshed"] = json!(take);
		Ok(out)
	}

	/// Takes back participation `pid`, a refresh of received coins
	/// ([`Self::refresh_received`]), once it has waited [`WITHDRAW_AFTER`]
	/// seconds and the operator's status `st` says it waits for funds or for
	/// the in-flight cap: its coins are live again, to pay with, and each is
	/// given up again no sooner than [`RETRY_AFTER`] seconds later. `None`
	/// for any other participation, or one that has not waited so long.
	pub(crate) fn withdraw_waited(&self, pid: &str, st: &Value) -> Result<Option<Value>, Error> {
		let Some(since) = self.store.meta(&received_key(pid))?.and_then(|t| t.parse::<u64>().ok()) else { return Ok(None) };
		let wall = wall_now();
		if st["waiting"].as_str().is_none() || wall < since.saturating_add(WITHDRAW_AFTER) {
			return Ok(None);
		}
		let mut v = self.withdraw_participation(pid)?;
		if v["state"] == "void" {
			for l in v["live_again"].as_array().cloned().unwrap_or_default() {
				if let Some(l) = l.as_str() {
					self.store.set_meta(&withdrawn_key(l), &wall.to_string())?;
				}
			}
			v["note"] = json!(format!("the refresh waited {} s for the operator ({}): taken back, its coins live again; given up again \
				no sooner than {} s from now", wall - since, st["waiting"].as_str().unwrap_or(""), RETRY_AFTER));
		}
		self.store.delete_meta(&received_key(pid))?;
		Ok(Some(v))
	}
}
