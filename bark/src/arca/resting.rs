//! Resting orders in the tree: an `order-3` leaf ([`arca_covenant::order`])
//! the wallet rests and then leaves, which takers fill in the tree while it
//! is away, under the operator's signature alone.
//!
//! **Resting.** [`Wallet::order_rest`] gives up leaves of the asset the order
//! sells in a participation that wants one `order-3` leaf of exactly the
//! order's amount (and a change leaf where the coins hold more). The leaf's
//! terms are SeqDEX's (the asset it is paid in, the rate, the lot), the
//! order it lands as on the chain (its fills on the chain pay the order key's
//! output, which the wallet scans, and its REFUND key is the order key), and
//! four credit keys of the wallet's, one for each fill along its lineage.
//! The wallet checks the leaf its round makes against exactly those terms
//! before it signs a forfeit. Once the participation is released, `sync`
//! publishes the order to the operator ([`Wallet::progress_resting`]): the
//! coin's record, the nonces of its credit keys and the wallet's mailbox,
//! signed by the leaf's key. The wallet can then stop.
//!
//! **Fills.** Each fill spends the order's coin by its fill path, under the
//! operator's signature over its outputs, which the leaf's program holds to
//! the terms: the maker's credit (a `vtxo-1` leaf under the next credit key,
//! paying at least the price) and, for a part fill, the order resting again
//! under a new salt and the same leaf key. Both come to the wallet's mailbox,
//! and `sync` takes them up: the credit under its credit key's nonce, the
//! remainder under the order's own, the coin it spent marked filled. Where
//! the order's coin rests on a lowest node with RECLAIM-D, `sync` then signs
//! its delegation into the fill, from the coin it took and the taker's leaves
//! the operator names, so that the node comes back once the fill's coins are
//! refreshed. The order resting again carries the order's key, which has
//! delegated, so the wallet never signs a release by it.
//!
//! **Taking.** [`Wallet::order_fill_resting`] fills another maker's order:
//! it reads the order (`order_state`), checks the coin it rests at against
//! its round before signing anything, and gives up coins of the asset the
//! order is paid in, each expiring no earlier than the order's coin (the
//! operator refuses others), through checkpoints into the credit, the
//! remainder, a leaf of what it takes and its change.
//!
//! **Cancel and home.** The maker cancels by spending the order's current
//! coin into a leaf of its own ([`Wallet::order_cancel_resting`]). An order's
//! coin is never paid on, refreshed by default or planned otherwise. Brought
//! on the chain (`exit`), it comes home by its landing: after its exit delay
//! the whole of it becomes SeqDEX's own order for the same terms, which any
//! taker fills on the chain.

use std::collections::BTreeSet;
use std::str::FromStr;

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, OutPoint};
use serde_json::{json, Value};

use arca_covenant::order::{publish_digest, OrderLeafTerms, OrderPolicy, OrderTerms, SeqdexOrder, CREDIT_KEYS};
use arca_covenant::record_json::{order_terms_from_json, order_terms_json};
use arca_covenant::script::sha256;
use arca_covenant::spend::{FeeSource, Pair, Rebindable};
use arca_covenant::{CoinRecord, ExplicitOutput, LeafId, NewLeaf, RelativeTime, Template, TransferPlan, ValidInput};

use super::chain::{hex, unhex, unhex32};
use super::client::{key_proof_digest, participation_id, Wanted};
use super::keys::ORDERS;
use super::pay::{In, Margins};
use super::round::{fee_within, refresh_fee, schedule_of, DEFAULT_MAX_FEE_PPM};
use super::store::{CoinRow, RestingRow};
use super::wallet::{sign, Wallet};
use super::{random32, Error};

/// The most orders one `order_state` read may name: the operator refuses a
/// read of more.
pub const ORDERS_PER_READ: usize = 100;

/// The orders of `ask`, each once, in reads of at most [`ORDERS_PER_READ`].
fn order_state_reads(ask: &[String]) -> Vec<Vec<String>> {
	let mut seen = BTreeSet::new();
	let once: Vec<String> = ask.iter().filter(|o| seen.insert(o.to_ascii_lowercase())).cloned().collect();
	once.chunks(ORDERS_PER_READ).map(|c| c.to_vec()).collect()
}

/// How long, beyond the operator's order margin, an order's REFUND must lie
/// ahead when it is rested: an hour, for its round and its forfeits. The
/// operator co-signs no fill within the margin of an order's REFUND.
pub const REST_MARGIN_SECONDS: u32 = 3_600;

/// The least lock read as a median time.
const TIME_LOCKS_FROM: u32 = 500_000_000;

/// The meta key of the fills the wallet sent and has no answer to yet.
const PENDING_FILLS: &str = "resting_fills_pending";

/// The meta key of the wallet's order coins whose delegation into the fill
/// that spent them is done.
const FILLS_DELEGATED: &str = "resting_fills_delegated";

/// What a maker asks: rest `amount` of `sell` for `want`, `rate_num` atoms of
/// `want` for every `rate_den` atoms of `sell` (each fill's price rounded
/// up), in fills of at least `min_lot`, its landed order refundable once the
/// chain's median time passes `expiry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestAsk {
	pub sell: AssetId,
	pub amount: u64,
	pub want: AssetId,
	pub rate_num: u64,
	pub rate_den: u64,
	pub min_lot: u64,
	pub expiry: u32,
}

struct RestPlan {
	coins: Vec<In>,
	fee: u64,
	change: u64,
}

/// Whether `row` is a resting order's coin (an `order-3` leaf, or an `order-2` leaf from before it): such a coin
/// is the order, and is spent only by a fill, a cancel or its landing.
pub(crate) fn is_order_coin(row: &CoinRow) -> bool {
	CoinRecord::from_bytes(&row.record).ok().and_then(|r| r.order_policy()).is_some()
}

fn parse_key(v: &Value, what: &str) -> Result<XOnlyPublicKey, Error> {
	XOnlyPublicKey::from_slice(&unhex(v.as_str().unwrap_or(""))?).map_err(|e| Error::Parse(format!("{}: {}", what, e)))
}

impl Wallet {
	/// What resting `ask` would cost, before anything is signed or asked of
	/// the operator but its published fees: the coins given up, the fee (each
	/// coin's refresh fee), the change and the order's full price. Refuses
	/// what [`Self::order_rest`] refuses for the same reason.
	pub fn order_rest_quote(&mut self, ask: &RestAsk, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		let _quote = self.quoting();
		let info = self.server_info()?;
		let q = self.rest_plan(&info, ask, max_fee_ppm).map(|(q, _)| q);
		self.quoted(q)
	}

	fn rest_plan(&mut self, info: &Value, ask: &RestAsk, max_fee_ppm: Option<u64>) -> Result<(Value, RestPlan), Error> {
		let (a, b) = (ask.sell, ask.want);
		let terms = OrderTerms { asset_a: a, asset_b: b, rate_num: ask.rate_num, rate_den: ask.rate_den, min_lot: ask.min_lot };
		terms.check().map_err(|e| Error::Refused(e.to_string()))?;
		if ask.amount < ask.min_lot {
			return Err(Error::Refused(format!("an order of {} is below its own min_lot of {}: no fill of it could be made", ask.amount,
				ask.min_lot)));
		}
		let full_price = terms.price(ask.amount).ok_or_else(|| Error::Refused(format!("the price of {} at {}/{} does not fit in 64 bits",
			ask.amount, ask.rate_num, ask.rate_den)))?;
		if ask.expiry < TIME_LOCKS_FROM {
			return Err(Error::Refused(format!("an expiry of {} is a height: a resting order's landed order is refundable from a median \
				time (500,000,000 and above)", ask.expiry)));
		}
		let now = self.now()?.to_consensus_u32();
		let margin_s = info["fills"]["order_margin_seconds"].as_u64().unwrap_or(21_600) as u32;
		let earliest = now.saturating_add(margin_s).saturating_add(REST_MARGIN_SECONDS);
		if ask.expiry < earliest {
			return Err(Error::Refused(format!("the order would be refundable from median time {}, and the operator co-signs no fill of an \
				order refundable within {} s: name an expiry of at least {} (the chain's median time is {})", ask.expiry, margin_s, earliest,
				now)));
		}
		Self::min_leaf(info, b)?;
		let min = Self::min_leaf(info, a)?;
		let schedule = schedule_of(info, a);
		// The coins, furthest from their exit date first, until they hold the
		// amount and the refresh fees, with no change or change of at least
		// the operator's smallest leaf.
		// A coin given up in a refresh that waits is taken back first when
		// the live coins fall short.
		self.free_when_short(a, ask.amount)?;
		let mut chosen: Vec<In> = vec![];
		let (mut total, mut fee) = (0u64, 0u64);
		let mut done = None;
		for c in self.coins_to_give(a)? {
			if chosen.len() == super::round::MAX_GIVEN {
				return Err(Self::too_many_coins(a, total, ask.amount.saturating_add(fee)));
			}
			let (record, held) = self.held(&c.row)?;
			let expiry = self.service_expiry(&record, &held)?;
			fee = fee.saturating_add(refresh_fee(&schedule, c.coin.value, expiry, now));
			total = total.saturating_add(c.coin.value);
			chosen.push(c);
			if let Some(change) = total.checked_sub(ask.amount.saturating_add(fee)).filter(|c| *c == 0 || *c >= min) {
				done = Some(change);
				break;
			}
		}
		let Some(change) = done else {
			return Err(self.short_of(a, ask.amount.saturating_add(fee).saturating_sub(total).max(1), format!("the wallet's live coins of \
				asset {} hold {} and the order of {} and its refresh fees need {}, with any change at least the operator's smallest leaf of \
				{}: board or receive more, or rest less", a, total, ask.amount, ask.amount.saturating_add(fee), min))?);
		};
		let bound = max_fee_ppm.unwrap_or(DEFAULT_MAX_FEE_PPM);
		if !fee_within(fee, ask.amount, bound) {
			return Err(Error::Refused(format!("resting the order costs {} of asset {}, above the wallet's bound of {} ppm of its amount {} \
				(raise it with max_fee_ppm)", fee, a, bound, ask.amount)));
		}
		let q = json!({
			"sell": a.to_string(), "amount": ask.amount.to_string(), "want": b.to_string(), "rate_num": ask.rate_num.to_string(),
			"rate_den": ask.rate_den.to_string(), "min_lot": ask.min_lot.to_string(), "expiry": ask.expiry,
			"full_price": full_price.to_string(),
			"fee": {"asset": a.to_string(), "amount": fee.to_string()},
			"gives": chosen.iter().map(|c| c.row.leaf_id.clone()).collect::<Vec<_>>(),
			"change": change.to_string(),
		});
		Ok((q, RestPlan { coins: chosen, fee, change }))
	}

	/// Rests `ask` in the tree (see the [module documentation](self)). With
	/// `shown`, it goes ahead only on the fee and the coins the program
	/// showed (a [`Self::order_rest_quote`]'s `fee` and `gives`). Answers the
	/// order, named by the participation that rests it until its round makes
	/// its coin; `sync` completes the participation and publishes the order.
	pub fn order_rest(&mut self, ask: &RestAsk, max_fee_ppm: Option<u64>, shown: Option<&Value>) -> Result<Value, Error> {
		self.witnessed_now()?;
		let info = self.server_info()?;
		let (quote, plan) = self.rest_plan(&info, ask, max_fee_ppm)?;
		if let Some(s) = shown {
			for k in ["fee", "gives"] {
				if s[k] != quote[k] {
					return Err(Error::Refused(format!("the order's {} changed since it was shown: it is now {}", k, quote[k])));
				}
			}
		}
		// The order's leaf key, its four credit keys, and the order key its
		// landed order pays and refunds to.
		let nonce = random32();
		let owner = self.keys.leaf_xonly(&nonce)?;
		let mut credit_nonces = [[0u8; 32]; CREDIT_KEYS];
		let mut credits = [[0u8; 32]; CREDIT_KEYS];
		for i in 0..CREDIT_KEYS {
			credit_nonces[i] = random32();
			credits[i] = self.keys.leaf_xonly(&credit_nonces[i])?.serialize();
		}
		let index = self.store.take_index(ORDERS)?;
		let pays = self.keys.order_script(index)?;
		let landed = SeqdexOrder {
			terms: OrderTerms { asset_a: ask.sell, asset_b: ask.want, rate_num: ask.rate_num, rate_den: ask.rate_den, min_lot: ask.min_lot },
			maker: sha256(pays.as_bytes()),
			expiry: ask.expiry,
			refund_key: self.keys.order(index)?.x_only_public_key().0,
			version: arca_covenant::order::SeqdexVersion::V2,
		};
		let terms = OrderLeafTerms { landed, credits };
		terms.check(ask.sell, &owner, &self.operator).map_err(|e| Error::Refused(e.to_string()))?;
		self.store.put_nonce(&nonce, &owner.serialize(), "resting order")?;
		for (i, n) in credit_nonces.iter().enumerate() {
			self.store.put_nonce(n, &credits[i], "order credit")?;
		}
		let terms_json = order_terms_json(&terms);
		let mut wanted = vec![Wanted::Leaf { asset: ask.sell, value: ask.amount, template: Template::Order3, owner, owner_nonce: nonce,
			exit_delay: self.exit_delay(), order: Some(terms), landing: None, channel: None }];
		let mut wanted_json = vec![json!({"nonce": hex(&nonce), "asset": ask.sell.to_string(), "value": ask.amount.to_string(),
			"order": terms_json})];
		if plan.change > 0 {
			let n = random32();
			let o = self.keys.leaf_xonly(&n)?;
			self.store.put_nonce(&n, &o.serialize(), "order change")?;
			wanted.push(Wanted::Leaf { asset: ask.sell, value: plan.change, template: Template::Vtxo1, owner: o, owner_nonce: n,
				exit_delay: self.exit_delay(), order: None, landing: None, channel: None });
			wanted_json.push(json!({"nonce": hex(&n), "asset": ask.sell.to_string(), "value": plan.change.to_string()}));
		}
		let fees = vec![(ask.sell, plan.fee)];
		let ids: Vec<LeafId> = plan.coins.iter().map(|c| c.coin.id).collect();
		let id = participation_id(&self.genesis, &self.operator, &ids, &wanted, &fees, None);
		let mut inputs = vec![];
		for c in &plan.coins {
			let k = self.coin_key(&c.row.owner_nonce)?;
			inputs.push(json!({"leaf_id": c.row.leaf_id, "attestation": hex(sign(&k, &id).as_ref())}));
		}
		let mut outputs = vec![];
		for w in &wanted {
			let mut j = w.json();
			if let Wanted::Leaf { owner_nonce, .. } = w {
				let k = self.keys.leaf(owner_nonce)?;
				j["leaf"]["key_proof"] = json!(hex(sign(&k, &key_proof_digest(&id)).as_ref()));
				let (mailbox, proof) = self.binding(&k)?;
				j["leaf"]["mailbox"] = json!(mailbox);
				j["leaf"]["mailbox_proof"] = json!(proof);
			}
			outputs.push(j);
		}
		let body = json!({"inputs": inputs, "outputs": outputs,
			"fees": fees.iter().map(|(a, v)| json!({"asset": a.to_string(), "amount": v.to_string()})).collect::<Vec<_>>()});
		let pid = hex(&id);
		let given: Vec<String> = plan.coins.iter().map(|c| c.row.leaf_id.clone()).collect();
		let row = RestingRow {
			id: pid.clone(), nonce, terms: wanted_json[0]["order"].to_string(), amount: ask.amount,
			credit_nonces: credit_nonces.iter().map(|n| hex(n)).collect(), order_leaf: None, state: "participating".into(),
		};
		self.store.atomically(|s| {
			s.put_participation(&pid, &body.to_string(), &serde_json::to_string(&given).expect("strings"),
				&Value::Array(wanted_json.clone()).to_string())?;
			for l in &given {
				s.set_coin_state(l, "given", &format!("resting order {}", pid))?;
			}
			s.put_resting(&row)
		})?;
		let answer = self.submit_participation_body(&pid, &body, &given)?;
		Ok(json!({"order": pid, "state": answer["state"], "terms": wanted_json[0]["order"], "amount": ask.amount.to_string(),
			"landed_pays": hex(pays.as_bytes()),
			"fee": quote["fee"], "gives": given, "change": plan.change.to_string(),
			"note": self.spelling.say("resting: once the operator's round makes the order's leaf and is final, {sync} hands over the \
				forfeits and publishes the order; takers then fill it in the tree while the wallet is away, and each {sync} after takes \
				up its credits and what rests")}))
	}

	/// Moves each resting order on as far as `sync` takes it: once its
	/// participation is released and the wallet holds its coin, publishes it;
	/// a participation that ended without its round is the end of the order.
	/// Then sends again each fill the wallet sent and has no answer to.
	pub(crate) fn progress_resting(&mut self) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		let parts = self.store.participations()?;
		for r in self.store.restings()? {
			if r.state != "participating" {
				continue;
			}
			let Some(p) = parts.iter().find(|p| p.0 == r.id) else { continue };
			let state = p.4.as_str();
			match state {
				"released" => {},
				"submitting" | "pending" | "issued" | "forfeiting" => continue,
				other => {
					self.store.set_resting(&r.id, None, "not_rested")?;
					out.push(json!({"order": r.id, "state": "not_rested", "note": format!("its participation is {}: the order was not rested, \
						and its coins are the wallet's", other)}));
					continue;
				},
			}
			let Some(leaf) = self.store.nonce(&r.nonce)?.and_then(|n| n.leaf_id) else { continue };
			match self.publish_resting(&r, &leaf) {
				Ok(v) => {
					self.store.set_resting(&r.id, Some(&leaf), "published")?;
					out.push(json!({"order": leaf, "state": v["state"], "published": true, "value": v["value"]}));
				},
				Err(e) => out.push(json!({"order": leaf, "state": "unpublished", "error": e.to_string()})),
			}
		}
		out.extend(self.retry_fills()?);
		out.extend(self.delegate_fills()?);
		Ok(out)
	}

	/// For each order coin of the wallet's that a fill spent, once the
	/// wallet holds a coin that fill made (its credit, or the order resting
	/// again): the order coin's delegation of its release into the fill, so
	/// that the lowest nodes it rests on come back once the fill's coins are
	/// refreshed. The taker's leaves come from the operator
	/// (`order_fill_delegation_terms`) and are checked against the fill's
	/// outputs in the coin's own record (`Delegation::for_filled_order`), so
	/// the delegation names exactly the outputs the operator signed. Each
	/// order coin is done once, and only the order's first coin delegates:
	/// an order resting again carries the same key, and a second delegation
	/// by it would stand in for the first ([`arca_covenant::ValidCoin::is_rest`]),
	/// so a node under a partly filled order comes back at its batch's expiry.
	fn delegate_fills(&mut self) -> Result<Vec<Value>, Error> {
		use arca_covenant::transfer::FillLeaf;
		let mut done: BTreeSet<String> = self.store.meta(FILLS_DELEGATED)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		let mut out = vec![];
		for row in self.store.coins()? {
			let Ok(CoinRecord::Fill(f)) = CoinRecord::from_bytes(&row.record) else { continue };
			if !matches!(f.leaf, FillLeaf::Credit { .. } | FillLeaf::Rest { .. }) {
				continue;
			}
			let Ok((_, a)) = self.held(&row) else { continue };
			let made = a.valid;
			let arca_covenant::ValidOrigin::Fill { order, .. } = &made.origin else { continue };
			let order_coin = order.id.to_string();
			if done.contains(&order_coin) {
				continue;
			}
			if order.release_nodes().is_empty() || order.is_rest() {
				done.insert(order_coin);
				continue;
			}
			match self.delegate_fill(&f.fill.order, &made, &order_coin) {
				Ok(v) => {
					done.insert(order_coin);
					out.push(v);
				},
				Err(e) => out.push(json!({"order_coin": order_coin, "delegated": false, "error": e.to_string()})),
			}
		}
		self.store.set_meta(FILLS_DELEGATED, &serde_json::to_string(&done).map_err(|e| Error::Store(e.to_string()))?)?;
		Ok(out)
	}

	/// The delegation of the order coin `order_coin` (whose record is
	/// `order_record`) into the fill that made `made`.
	fn delegate_fill(&self, order_record: &CoinRecord, made: &arca_covenant::ValidCoin, order_coin: &str) -> Result<Value, Error> {
		use arca_covenant::transfer::FillLeaf;
		let t = self.server.post("order_fill_delegation_terms", &json!({"order_coin": order_coin}))?;
		if t["delegated"] == true {
			return Ok(json!({"order_coin": order_coin, "delegated": true}));
		}
		let mut takers = vec![];
		for l in t["takers"].as_array().into_iter().flatten() {
			takers.push(NewLeaf {
				enclave: None, v2: false, htlc: None, landing: None,
				owner: parse_key(&l["owner"], "a taker's leaf")?,
				owner_nonce: unhex32(l["owner_nonce"].as_str().unwrap_or(""))?,
				creator_nonce: unhex32(l["creator_nonce"].as_str().unwrap_or(""))?,
				exit_delay: RelativeTime::from_units(l["exit_delay_units"].as_u64().unwrap_or(0) as u16).map_err(|e| Error::Parse(e.to_string()))?,
			});
		}
		let d = arca_covenant::Delegation::for_filled_order(made, &takers)
			.map_err(|e| Error::Refused(format!("the operator's terms for the fill of order coin {}: {}", order_coin, e)))?;
		// The order coin's key: the order's own, under its first coin's nonce.
		let nonce = match order_record {
			CoinRecord::Leaf { record, .. } => record.owner_nonce,
			CoinRecord::Fill(g) => match g.leaf {
				FillLeaf::Rest { owner_nonce } => owner_nonce,
				_ => return Err(Error::Refused(format!("order coin {} is no order's", order_coin))),
			},
			_ => return Err(Error::Refused(format!("order coin {} is no order's", order_coin))),
		};
		let key = self.coin_key(&nonce)?;
		if key.x_only_public_key().0 != d.from {
			return Err(Error::Keys(format!("the wallet's key for order coin {} is not the coin's", order_coin)));
		}
		let a = self.server.post("order_fill_delegation", &json!({"order_coin": order_coin,
			"signature": hex(sign(&key, &d.message().digest).as_ref())}))?;
		Ok(json!({"order_coin": order_coin, "delegated": true, "kept": a["kept"]}))
	}

	/// Publishes the resting order whose round made the coin `leaf`.
	fn publish_resting(&self, r: &RestingRow, leaf: &str) -> Result<Value, Error> {
		let row = self.store.coin(leaf)?.ok_or_else(|| Error::Store(format!("coin {} is gone", leaf)))?;
		let id = LeafId::from_str(leaf).map_err(|e| Error::Store(e.to_string()))?;
		let mut nonces = [[0u8; 32]; CREDIT_KEYS];
		for (i, n) in r.credit_nonces.iter().enumerate().take(CREDIT_KEYS) {
			nonces[i] = unhex32(n)?;
		}
		let mailbox = self.keys.mailbox()?.x_only_public_key().0;
		let key = self.keys.leaf(&r.nonce)?;
		let digest = publish_digest(&self.genesis, &self.operator, &id, &nonces, &mailbox);
		self.server.post("order_publish", &json!({
			"record": hex(&row.record), "credit_nonces": r.credit_nonces, "mailbox": hex(&mailbox.serialize()),
			"signature": hex(sign(&key, &digest).as_ref()),
		}))
	}

	/// How the wallet's resting orders stand, as the operator shows them, and
	/// with `ids` other orders by their ids; each of the wallet's own with
	/// the credits and the remainders the wallet holds of it.
	pub fn resting_orders(&self, ids: &[String]) -> Result<Value, Error> {
		let mine = self.store.restings()?;
		let mut ask: Vec<String> = mine.iter().filter_map(|r| r.order_leaf.clone()).collect();
		ask.extend(ids.iter().cloned());
		// Every order the wallet ever rested is asked after, so a busy maker
		// soon names more than one read may: they are read a chunk at a time.
		let mut states = vec![];
		for read in order_state_reads(&ask) {
			states.extend(self.server.post("order_state", &json!({"orders": read}))?["orders"].as_array().cloned().unwrap_or_default());
		}
		let served = Value::Array(states);
		let mut out = vec![];
		for r in &mine {
			let mut v = json!({"order": r.order_leaf, "rested_by": r.id, "state": r.state, "amount": r.amount.to_string()});
			if let Some(leaf) = &r.order_leaf {
				if let Some(s) = served.as_array().into_iter().flatten().find(|s| s["order"].as_str() == Some(leaf)) {
					v["operator"] = json!({"state": s["state"], "coin": s["coin"], "value": s["value"], "fills_left": s["fills_left"],
						"fills": s["fills"]});
				}
			}
			let mut credits = vec![];
			for n in &r.credit_nonces {
				let Some(leaf) = self.store.nonce(&unhex32(n)?)?.and_then(|x| x.leaf_id) else { continue };
				if let Some(c) = self.store.coin(&leaf)? {
					credits.push(json!({"leaf_id": c.leaf_id, "asset": c.asset, "value": c.value.to_string(), "state": c.state}));
				}
			}
			v["credits"] = json!(credits);
			out.push(v);
		}
		let others: Vec<Value> = served.as_array().into_iter().flatten()
			.filter(|s| ids.iter().any(|i| s["order"].as_str() == Some(i.as_str()))).cloned().collect();
		Ok(json!({"orders": out, "others": others}))
	}

	/// What filling `amount` (all of it when `None`) of another maker's
	/// resting order `order` would cost, before anything is signed: the
	/// order as the operator serves it now (`served`, the coin it rests at
	/// among it), what the fill takes and pays, its fee in the asset paid,
	/// the coins given up and the change. Refuses what
	/// [`Self::order_fill_resting`] refuses for the same reason.
	pub fn order_fill_resting_quote(&mut self, order: &str, amount: Option<u64>) -> Result<Value, Error> {
		let _quote = self.quoting();
		self.witnessed_now()?;
		let info = self.server_info()?;
		let o = self.served_order(order)?;
		let leaf = |w: &Wallet| -> Result<NewLeaf, Error> {
			let n = random32();
			Ok(NewLeaf { enclave: None, v2: false, owner: w.keys.leaf_xonly(&n)?, owner_nonce: n, creator_nonce: random32(), exit_delay: w.exit_delay(), htlc: None, landing: None })
		};
		let (got, change_leaf) = (leaf(self)?, leaf(self)?);
		let f = self.resting_fill_plan(&info, order, &o, amount, &got, &change_leaf)?;
		self.quoted(Ok(f.quote(order, &o)))
	}

	/// The order `order` as the operator serves it now, resting.
	fn served_order(&self, order: &str) -> Result<Value, Error> {
		let st = self.server.post("order_state", &json!({"orders": [order]}))?;
		let o = st["orders"].as_array().and_then(|a| a.first()).cloned()
			.ok_or_else(|| Error::Refused(format!("the operator has no resting order {} published", order)))?;
		if o["state"].as_str() != Some("resting") {
			return Err(Error::Refused(format!("order {} is {}: it takes no fill", order, o["state"])));
		}
		Ok(o)
	}

	/// The fill of `amount` of `order`, served as `o`, into the leaves `got`
	/// (what it takes) and `change_leaf` (the change): the order's coin
	/// checked against its round, the plan, and the wallet's coins.
	fn resting_fill_plan(&mut self, info: &Value, order: &str, o: &Value, amount: Option<u64>, got: &NewLeaf, change_leaf: &NewLeaf)
		-> Result<RestingFill, Error>
	{
		// The order's coin, from its record, checked against its round as a
		// coin received is: the fill rests on it.
		let asset_a = AssetId::from_str(o["asset"].as_str().unwrap_or("")).map_err(|e| Error::Parse(e.to_string()))?;
		let terms = order_terms_from_json(&o["terms"], asset_a).map_err(|e| Error::Parse(e.to_string()))?;
		let delay = RelativeTime::from_units(o["exit_delay_units"].as_u64().unwrap_or(0) as u16).map_err(|e| Error::Parse(e.to_string()))?;
		let policy = terms.policy(parse_key(&o["owner"], "the order's owner")?, self.operator, unhex32(o["salt"].as_str().unwrap_or(""))?,
			self.genesis, delay);
		let record = CoinRecord::from_bytes(&unhex(o["record"].as_str().unwrap_or(""))?)
			.map_err(|e| Error::Refused(format!("the order's record does not decode: {}", e)))?;
		let now = self.now()?;
		let held = self.assess(&record, &self.receipt_policy(now), None)?;
		// When the order's coin expires as the operator serves it: its first
		// expiry, or a board's service expiry where it rests on one.
		let order_expiry = self.service_expiry(&record, &held)?;
		let oc = held.valid;
		if oc.id.to_string() != o["coin"].as_str().unwrap_or("") || oc.leaf.order_policy() != Some(policy) {
			return Err(Error::Refused(format!("the operator serves order {} at coin {}, whose record is coin {} of other terms", order,
				o["coin"], oc.id)));
		}
		let filled = amount.unwrap_or(oc.value);
		let plan = policy.plan(oc.value, filled).map_err(|e| Error::Refused(e.to_string()))?;
		let asset_b = policy.terms().asset_b;
		let price = plan.credit.value;
		let m = Margins::of(info, asset_b)?;
		let min = Self::min_leaf(info, asset_b)?;
		Self::min_leaf(info, asset_a)?;
		// The coins: of the asset the order is paid in, expiring no earlier
		// than the order's coin as the operator counts it (a coin resting on a
		// board by the board's service expiry, when that comes first), until
		// they hold the price, every margin and change of none or at least the
		// smallest leaf.
		// A coin given up in a refresh that waits is taken back first when
		// the live coins fall short.
		self.free_when_short(asset_b, price)?;
		let mut chosen: Vec<In> = vec![];
		let mut kept = 0u64;
		let mut done = None;
		for mut c in self.coins_to_give(asset_b)? {
			if c.row.expiry < order_expiry {
				continue;
			}
			if chosen.len() == super::round::MAX_GIVEN {
				return Err(Self::too_many_coins(asset_b, kept, price));
			}
			let cp = self.checkpoint_margin_of(&c.coin, &m)?;
			let Some(v) = c.coin.value.checked_sub(cp).filter(|v| *v > 0) else { continue };
			c.checkpoint_value = v;
			kept = kept.saturating_add(v);
			chosen.push(c);
			let outs = fill_outputs(&plan, &policy, (got, filled), Some((change_leaf, asset_b, 1)), self);
			let fee = fill_margin(&oc, &plan, &chosen, &outs, &m)?;
			let need = price.saturating_add(fee);
			if let Some(change) = kept.checked_sub(need).filter(|c| *c == 0 || *c >= min) {
				done = Some((fee, change));
				break;
			}
		}
		let Some((fee, change)) = done else {
			return Err(self.short_of(asset_b, price.saturating_sub(kept).max(1), format!("the wallet's live coins of asset {} that expire \
				no earlier than the order's coin (median time {}) keep {} past their checkpoints; the fill of {} costs {} and its fee, with \
				change of none or at least {}", asset_b, order_expiry, kept, filled, price, min))?);
		};
		Ok(RestingFill { oc, policy, plan, filled, price, fee, change, chosen, asset_a, asset_b })
	}

	/// Fills `amount` (all of it when `None`) of another maker's resting
	/// order `order` in the tree (see the [module documentation](self)).
	/// With `shown` (an [`Self::order_fill_resting_quote`]'s answer), the fill
	/// is made of the order as the quote served it, at the coin it rested at
	/// then, and goes ahead only on the fee and the coins it showed: if the
	/// order has moved since (another taker filled it), the operator refuses
	/// it with `order_moved`, and a new quote names the coin it rests at now.
	pub fn order_fill_resting(&mut self, order: &str, amount: Option<u64>, shown: Option<&Value>) -> Result<Value, Error> {
		self.witnessed_now()?;
		let info = self.server_info()?;
		let o = match shown {
			Some(s) => {
				if s["order"].as_str() != Some(order) || !s["served"].is_object() {
					return Err(Error::Refused(format!("the quote shown is not a quote of a fill of order {}", order)));
				}
				s["served"].clone()
			},
			None => self.served_order(order)?,
		};
		// The fill request names no template: the operator makes the
		// taker's leaves vtxo-1.
		let got = self.own_vtxo1_leaf_for("resting order fill")?;
		let change_leaf = self.own_vtxo1_leaf_for("change")?;
		let f = self.resting_fill_plan(&info, order, &o, amount, &got, &change_leaf)?;
		if let Some(s) = shown {
			let q = f.quote(order, &o);
			for k in ["filled", "paid", "fee", "gives"] {
				if s[k] != q[k] {
					return Err(Error::Refused(format!("the fill's {} changed since it was shown: it is now {}", k, q[k])));
				}
			}
		}
		let RestingFill { oc, policy, plan, filled, price, fee, change, chosen, asset_a, asset_b } = f;
		let mailbox = self.keys.mailbox()?.x_only_public_key().0;
		let outputs = fill_outputs(&plan, &policy, (&got, filled), (change > 0).then_some((&change_leaf, asset_b, change)), self);
		let tplan = TransferPlan { inputs: chosen.iter().map(|c| (c.coin.clone(), c.checkpoint_value)).collect(), outputs: outputs.clone() };
		// The fill spends the order's coin at input 0 and the checkpoints
		// after it: a vtxo-2 checkpoint's pair names them all, its own index
		// one past its place among the checkpoints (`fill_tx`).
		let mut named = vec![oc.output().txout()];
		named.extend((0..chosen.len()).map(|j| tplan.checkpoint_output(j).txout()));
		// Each coin resting on a lowest node with RECLAIM-D delegates its
		// release into every output of the fill: the credit, the order resting
		// again, the taker's leaves.
		let mut takers = vec![got];
		if change > 0 {
			takers.push(change_leaf);
		}
		let mut inputs = vec![];
		for (k, c) in chosen.iter().enumerate() {
			let key = self.coin_key(&c.row.owner_nonce)?;
			let cp = sign(&key, &tplan.checkpoint_message(k).map_err(|e| Error::Refused(e.to_string()))?.digest);
			let re = sign(&key, &tplan.checkpoint(k).message_in(k as u32 + 1, &named, &outputs)
				.map_err(|e| Error::Refused(e.to_string()))?.digest);
			let mut input = json!({"leaf_id": c.row.leaf_id, "checkpoint_value": c.checkpoint_value.to_string(),
				"checkpoint_sig": hex(cp.as_ref()), "reassignment_sig": hex(re.as_ref())});
			if !c.coin.release_nodes().is_empty() && !c.coin.is_rest() {
				let d = arca_covenant::Delegation::for_fill(&c.coin.leaf, &policy, &outputs, &takers)
					.map_err(|e| Error::Refused(format!("the delegation: {}", e)))?;
				input["delegation_sig"] = json!(hex(sign(&key, &d.message().digest).as_ref()));
			}
			inputs.push(input);
		}
		let leaf_json = |asset: AssetId, value: u64, l: &NewLeaf| json!({
			"asset": asset.to_string(), "value": value.to_string(), "owner": hex(&l.owner.serialize()), "owner_nonce": hex(&l.owner_nonce),
			"creator_nonce": hex(&l.creator_nonce), "exit_delay_units": l.exit_delay.units(), "mailbox": hex(&mailbox.serialize()),
		});
		let mut taker = vec![leaf_json(asset_a, filled, &got)];
		if change > 0 {
			taker.push(leaf_json(asset_b, change, &change_leaf));
		}
		let body = json!({"order": order, "coin": oc.id.to_string(), "filled": filled.to_string(), "inputs": inputs, "outputs": taker});
		let given: Vec<String> = chosen.iter().map(|c| c.row.leaf_id.clone()).collect();
		self.store.atomically(|s| {
			for l in &given {
				s.set_coin_state(l, "sending", &format!("a fill of resting order {}", order))?;
			}
			let mut pending: Vec<Value> = s.meta(PENDING_FILLS)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
			pending.push(json!({"body": body, "given": given}));
			s.set_meta(PENDING_FILLS, &Value::Array(pending).to_string())
		})?;
		let answer = self.send_fill(&body, &given)?;
		Ok(json!({"order": order, "filled": filled.to_string(), "paid": price.to_string(), "fee": fee.to_string(),
			"change": change.to_string(), "gives": given, "answer": answer}))
	}

	/// Sends the fill `body`, giving up `given`, and takes up the coins it
	/// makes the wallet's; a refusal gives the coins back, and no answer
	/// leaves the fill to be sent again, byte for byte, by the next `sync`.
	fn send_fill(&mut self, body: &Value, given: &[String]) -> Result<Value, Error> {
		let forget = |w: &Wallet| -> Result<(), Error> {
			let pending: Vec<Value> = w.store.meta(PENDING_FILLS)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
			let left: Vec<Value> = pending.into_iter().filter(|p| p["body"] != *body).collect();
			w.store.set_meta(PENDING_FILLS, &Value::Array(left).to_string())
		};
		match self.server.post("order_fill", body) {
			Ok(done) => {
				// Each coin's record carries the fill, the operator's
				// signatures with it, and is checked as any coin received.
				let outs = done["outputs"].as_array().cloned().unwrap_or_default();
				let mine = body["outputs"].as_array().map_or(0, |a| a.len());
				let mut taken = vec![];
				for o in outs.iter().skip(outs.len().saturating_sub(mine)) {
					let bytes = unhex(o["record"].as_str().unwrap_or(""))?;
					taken.push(self.accept_coin(&bytes, o["leaf_id"].as_str().unwrap_or(""), "resting order fill")?);
				}
				forget(self)?;
				Ok(json!({"transfer_id": done["transfer_id"], "coins": taken}))
			},
			// Refused, and not taken: the coins are the wallet's again, and
			// the refusal is kept once, beside the others.
			Err(e @ Error::Server { .. }) => {
				self.store.atomically(|s| {
					for l in given {
						s.set_coin_state(l, "live", "")?;
					}
					s.refused(&format!("a fill of resting order {}", body["order"].as_str().unwrap_or("")), &e.to_string())
				})?;
				forget(self)?;
				Err(e)
			},
			Err(e) => Ok(json!({"state": "sent", "error": e.to_string(),
				"note": "the operator did not answer: the fill is sent again, unchanged, by the next sync"})),
		}
	}

	/// Sends again each fill the wallet sent and has no answer to.
	fn retry_fills(&mut self) -> Result<Vec<Value>, Error> {
		let pending: Vec<Value> = self.store.meta(PENDING_FILLS)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		let mut out = vec![];
		for p in pending {
			let given: Vec<String> = p["given"].as_array().into_iter().flatten().filter_map(|g| g.as_str().map(String::from)).collect();
			match self.send_fill(&p["body"], &given) {
				Ok(v) => out.push(json!({"fill_of": p["body"]["order"], "answer": v})),
				Err(e) => out.push(json!({"fill_of": p["body"]["order"], "refused": e.to_string()})),
			}
		}
		Ok(out)
	}

	/// The wallet's resting order `order` (the id the round's coin gave it)
	/// and the coin it rests at now, live.
	fn resting_to_cancel(&self, order: &str) -> Result<(RestingRow, CoinRow), Error> {
		let r = self.store.restings()?.into_iter().find(|r| r.order_leaf.as_deref() == Some(order) || r.id == order)
			.ok_or_else(|| Error::Refused(format!("the wallet rested no order {}", order)))?;
		let leaf = self.store.nonce(&r.nonce)?.and_then(|n| n.leaf_id)
			.ok_or_else(|| Error::Refused(format!("order {} has no coin yet: its round has not made it", order)))?;
		let row = self.store.coin(&leaf)?.ok_or_else(|| Error::Store(format!("coin {} is gone", leaf)))?;
		if row.state != "live" || !is_order_coin(&row) {
			return Err(Error::Refused(format!("order {} rests at coin {}, which is {}: nothing rests to cancel", order, leaf, row.state)));
		}
		Ok((r, row))
	}

	/// What cancelling the wallet's resting order `order` would give back,
	/// before anything is signed: the coin it rests at, what that coin
	/// holds, the leaf of the wallet's own it becomes and the fee (the
	/// transfer's margins, in the asset the order sells).
	pub fn order_cancel_resting_quote(&mut self, order: &str) -> Result<Value, Error> {
		let (_, row) = self.resting_to_cancel(order)?;
		let (coin, holds) = (row.leaf_id.clone(), row.value);
		let (asset, value, fee) = self.respend_quote(vec![row])?;
		Ok(json!({"order": order, "coin": coin, "holds": holds.to_string(), "gets": {"asset": asset.to_string(), "amount": value.to_string()},
			"fee": {"asset": asset.to_string(), "amount": fee.to_string()}}))
	}

	/// Cancels the wallet's resting order `order` (the id the round's coin
	/// gave it): its current coin spent into a leaf of the wallet's own.
	/// With `shown` (an [`Self::order_cancel_resting_quote`]'s answer), only
	/// for the coin and the fee it showed.
	pub fn order_cancel_resting(&mut self, order: &str, shown: Option<&Value>) -> Result<Value, Error> {
		let (r, row) = self.resting_to_cancel(order)?;
		let leaf = row.leaf_id.clone();
		if let Some(s) = shown {
			let q = self.order_cancel_resting_quote(order)?;
			for k in ["coin", "gets", "fee"] {
				if s[k] != q[k] {
					return Err(Error::Refused(format!("the cancel's {} changed since it was shown: it is now {}", k, q[k])));
				}
			}
		}
		let done = self.respend_to_self(vec![row])?;
		self.store.set_resting(&r.id, None, "cancelled")?;
		Ok(json!({"order": order, "state": "cancelled", "coin": leaf, "transfer": done}))
	}
}

/// A fill of a resting order the wallet would make: the order's coin, its
/// plan, and the wallet's coins and what they pay.
struct RestingFill {
	oc: arca_covenant::ValidCoin,
	policy: OrderPolicy,
	plan: arca_covenant::order::OrderFillPlan,
	filled: u64,
	price: u64,
	fee: u64,
	change: u64,
	chosen: Vec<In>,
	asset_a: AssetId,
	asset_b: AssetId,
}

impl RestingFill {
	/// The fill as a quote shows it, with the order as it was served.
	fn quote(&self, order: &str, served: &Value) -> Value {
		json!({
			"order": order, "coin": self.oc.id.to_string(), "rests": self.oc.value.to_string(),
			"filled": self.filled.to_string(), "gets": {"asset": self.asset_a.to_string(), "amount": self.filled.to_string()},
			"paid": self.price.to_string(), "fee": {"asset": self.asset_b.to_string(), "amount": self.fee.to_string()},
			"change": self.change.to_string(), "remainder": self.plan.rest.as_ref().map(|r| r.value.to_string()),
			"gives": self.chosen.iter().map(|c| c.row.leaf_id.clone()).collect::<Vec<_>>(),
			"served": served,
		})
	}
}

/// The outputs of a fill of `plan`: the credit, the remainder for a part
/// fill, the taker's leaf of what it takes, and its change.
fn fill_outputs(plan: &arca_covenant::order::OrderFillPlan, p: &OrderPolicy, got: (&NewLeaf, u64), change: Option<(&NewLeaf, AssetId, u64)>,
	w: &Wallet) -> Vec<ExplicitOutput>
{
	let mut out = vec![plan.credit.clone()];
	out.extend(plan.rest.clone());
	out.push(ExplicitOutput::new(p.terms().asset_a, got.1, got.0.policy(w.operator, w.genesis).script_pubkey()));
	if let Some((l, asset, v)) = change {
		out.push(ExplicitOutput::new(asset, v, l.policy(w.operator, w.genesis).script_pubkey()));
	}
	out
}

/// The margin a fill leaves for its fee, as the operator prices it: from the
/// fill transaction's size with every input it spends.
fn fill_margin(oc: &arca_covenant::ValidCoin, plan: &arca_covenant::order::OrderFillPlan, chosen: &[In], outputs: &[ExplicitOutput],
	m: &Margins) -> Result<u64, Error>
{
	let dummy = Signature::from_slice(&[1; 64]).expect("64 bytes");
	let pair = Pair { operator: dummy, owner: dummy };
	let sized: Vec<ValidInput> = chosen.iter().map(|c| ValidInput {
		coin: c.coin.clone(), checkpoint: c.coin.checkpoint(), checkpoint_value: c.checkpoint_value, checkpoint_pair: pair,
		reassignment_pair: pair,
	}).collect();
	let at = OutPoint::default();
	let u = arca_covenant::transfer::fill_tx(oc, &dummy, plan.rest.is_some(), &sized, outputs, at, &vec![at; sized.len()],
		&FeeSource::Reserve).map_err(|e| Error::Refused(e.to_string()))?;
	Ok(m.margin(u.tx.vsize()))
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn order_states_are_read_once_each_in_reads_of_at_most_a_hundred() {
		let mut ask: Vec<String> = (0..113).map(|i| format!("{:064x}", i)).collect();
		// The wallet's own orders asked again by id, one in capitals.
		ask.extend((0..10).map(|i| format!("{:064x}", i)));
		ask.push(format!("{:064X}", 10u32));
		let reads = order_state_reads(&ask);
		assert_eq!(reads.iter().map(|r| r.len()).collect::<Vec<_>>(), vec![100, 13]);
		let all: Vec<&String> = reads.iter().flatten().collect();
		assert_eq!(all.len(), 113, "each order once");
		assert!(reads.iter().all(|r| r.len() <= ORDERS_PER_READ));
		assert!(order_state_reads(&[]).is_empty(), "nothing asked, nothing read");
		assert_eq!(order_state_reads(&ask[..100]).len(), 1, "a hundred in one read");
	}
}
