//! Orders the wallet places on the chain: an ordinary SeqDEX order, made from
//! the wallet's leaves, that rests with its maker offline and is filled by
//! anyone.
//!
//! A maker who holds only leaves places an order by offboarding exactly the
//! order's amount into the address its terms make: a participation gives up
//! leaves of the asset the order sells and wants one offboard output, paying
//! SeqDEX's fill covenant for those terms (two leaves under the NUMS point,
//! FILL and REFUND), and a change leaf where the coins hold more. The
//! operator's round pays the offboard output, hash-locked; `sync` hands over
//! the forfeits once the round is final; the operator then unlocks it with the
//! preimage, and the order rests at that unlock's output 0, holding exactly its
//! amount, an ordinary on-chain order as SeqDEX's makers make them. Should the
//! operator not unlock it within [`UNLOCK_GRACE_SECONDS`] of the wallet holding
//! the preimage, the wallet unlocks it itself.
//!
//! From there the order is consensus and nothing else: anyone fills it under
//! FILL, an Arca taker through the operator's fill round (`take`), and each
//! fill pays the maker's credit at output `2k` and leaves the rest resting at
//! `2k+1` under the identical script. The credit is paid to a plain key: by
//! default the order's own key ([`super::keys::Keys::order`]), whose key-path
//! output the wallet scans and `board` spends. A program the wallet holds as
//! an Arca script is refused as the credit's program: a pair of rebindable
//! signatures over one credit would spend every other credit of the same
//! value under that script, and the filler chooses each credit's value. The
//! maker takes back what rests unfilled with the REFUND once the chain has
//! passed the order's `expiry_locktime`, a median time.
//!
//! Where an order rests, what filled it and what it was paid are read from the
//! chain each time they are asked for ([`Wallet::orders`]), never kept: a
//! rollback that takes a fill out of the chain takes it out of what the
//! wallet says. A leaf cannot carry the order itself: SeqDEX's FILL needs no
//! signature and no delay, so a fill, cancel or refresh made in the tree
//! could be undone by the maker bringing the leaf on the chain first.

use std::str::FromStr;

use elements::hashes::{sha256, Hash};
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, OutPoint, Script, Transaction, Txid};
use serde_json::{json, Value};

use arca_covenant::fill::FillOrder;
use arca_covenant::script::witness_program;
use arca_covenant::spend::FeeSource;
use arca_covenant::{ExplicitOutput, LeafId, OffboardPolicy, RelativeTime, Template};

use super::chain::{hex, unhex, unhex32};
use super::client::{key_proof_digest, participation_id, Wanted};
use super::keys::{ORDERS, RECEIVE};
use super::pay::{In, Margins};
use super::round::{fee_within, refresh_fee, schedule_of, DEFAULT_MAX_FEE_PPM};
use super::take::offboard_fee;
use super::wallet::{amount, sign, Wallet};
use super::{random32, Error};

/// How long, beyond the operator's order margin (`info.fills`), an order's
/// REFUND must lie ahead when it is placed: an hour, for its round, its
/// forfeits and its unlock. A take is refused within the margin of an
/// order's REFUND, so an order refundable sooner could never be taken.
pub const PLACE_MARGIN_SECONDS: u32 = 3_600;

/// How long after the wallet holds the preimage of its order's offboard
/// it leaves the unlock to the operator, by the chain's median time.
pub const UNLOCK_GRACE_SECONDS: u32 = 600;

/// How long an offer the wallet hands out for SeqDEX's relay lasts at most:
/// six days, within the relay's seven.
pub const RELAY_OFFER_SECONDS: u64 = 6 * 86_400;

/// The operator's order margin a relay offer ends before the REFUND opens,
/// unless the operator publishes another (`info.fills`): six hours, as a
/// take of the order is refused within it.
const ORDER_MARGIN_SECONDS: u64 = 21_600;

/// The least `expiry_locktime` read as a median time; below it a lock is a
/// height, which an order the wallet places never carries.
const TIME_LOCKS_FROM: u32 = 500_000_000;

/// What a maker asks: sell `amount` of `sell` for `want`, `rate_num` atoms of
/// `want` for every `rate_den` atoms of `sell` (each fill's price rounded up),
/// in fills of at least `min_lot`, refundable once the chain's median time
/// passes `expiry`, its credits paid to `maker_prog` (the order's own key
/// unless named).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderAsk {
	pub sell: AssetId,
	pub amount: u64,
	pub want: AssetId,
	pub rate_num: u64,
	pub rate_den: u64,
	pub min_lot: u64,
	pub expiry: u32,
	pub maker_prog: Option<[u8; 32]>,
}

/// An order's placement, planned: the coins given up, the fee, its parts,
/// and the change.
struct Plan {
	coins: Vec<In>,
	fee: u64,
	margin: u64,
	change: u64,
}

/// What the chain says of an order placed.
struct Standing {
	/// `waiting`, `in_round`, `not_placed`, `unlocking`, `resting`,
	/// `filled`, `refunded` or `spent`.
	state: &'static str,
	/// Where it rests now, and what it holds there.
	at: Option<(OutPoint, u64)>,
	fills: Vec<Value>,
	note: Option<String>,
}

fn outpoint_text(op: &OutPoint) -> String {
	format!("{}:{}", op.txid, op.vout)
}

fn parse_outpoint(s: &str) -> Result<OutPoint, Error> {
	let (t, v) = s.split_once(':').ok_or_else(|| Error::Store(format!("an outpoint {:?}", s)))?;
	Ok(OutPoint::new(Txid::from_str(t).map_err(|e| Error::Store(e.to_string()))?, v.parse().map_err(|_| Error::Store(format!("an outpoint {:?}", s)))?))
}

/// The program of `spk` when it is a version 1 witness program of 32 bytes.
fn v1_program(spk: &Script) -> Option<[u8; 32]> {
	match witness_program(spk) {
		Some((1, p)) => p.try_into().ok(),
		_ => None,
	}
}

impl Wallet {
	/// What placing `ask` would cost, before anything is signed, written or
	/// asked of the operator but its published fees: the coins given up, the
	/// fee (each coin's refresh fee, the offboard's fee by the sold asset's
	/// schedule, and the margin the offboard output holds for its unlock),
	/// the change, and the order's full price. Refuses what [`Self::order_place`]
	/// refuses for the same reason.
	pub fn order_quote(&mut self, ask: &OrderAsk, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		let info = self.server_info()?;
		self.order_plan(&info, ask, max_fee_ppm).map(|(q, _)| q)
	}

	fn order_plan(&mut self, info: &Value, ask: &OrderAsk, max_fee_ppm: Option<u64>) -> Result<(Value, Plan), Error> {
		let (a, b) = (ask.sell, ask.want);
		if a == b {
			return Err(Error::Refused(format!("an order sells one asset for another: it sells and wants asset {}", a)));
		}
		if let Some(p) = ask.maker_prog {
			self.check_maker_prog(&p)?;
		}
		// The terms, with a stand-in for the keys the order gets when it is
		// placed: no check below reads them.
		let terms = FillOrder { asset_a: a, asset_b: b, rate_num: ask.rate_num, rate_den: ask.rate_den,
			maker_prog: ask.maker_prog.unwrap_or([2; 32]), min_lot: ask.min_lot, expiry_locktime: ask.expiry, maker_x: [2; 32] };
		terms.check_arithmetic(ask.amount).map_err(|e| Error::Refused(e.to_string()))?;
		if ask.amount < ask.min_lot {
			return Err(Error::Refused(format!("an order of {} is below its own min_lot of {}: no fill of it could be made", ask.amount,
				ask.min_lot)));
		}
		// SeqDEX's relay lists a covenant order only at an exact price for
		// the whole of it: rate_num × amount = rate_den × want_amount.
		if (ask.amount as u128 * ask.rate_num as u128) % ask.rate_den as u128 != 0 {
			return Err(Error::Refused(format!("{} at {}/{} is no whole number of atoms of asset {}: SeqDEX's relay lists an order only when \
				rate_num × amount is a multiple of rate_den; place an amount that makes it one", ask.amount, ask.rate_num, ask.rate_den, b)));
		}
		// The REFUND: a median time, far enough ahead for a take.
		if ask.expiry < TIME_LOCKS_FROM {
			return Err(Error::Refused(format!("an expiry of {} is a height: an order the wallet places is refundable from a median time \
				(500,000,000 and above), which no anchor rollback moves", ask.expiry)));
		}
		let now = self.now()?.to_consensus_u32();
		let margin_s = info["fills"]["order_margin_seconds"].as_u64().unwrap_or(21_600) as u32;
		let earliest = now.saturating_add(margin_s).saturating_add(PLACE_MARGIN_SECONDS);
		if ask.expiry < earliest {
			return Err(Error::Refused(format!("the order would be refundable from median time {}, and the operator takes no take of an order \
				refundable within {} s: name an expiry of at least {} (the chain's median time is {})", ask.expiry, margin_s, earliest, now)));
		}
		Self::min_leaf(info, b)?;
		let min = Self::min_leaf(info, a)?;
		let schedule = schedule_of(info, a);
		// The margin the round's offboard output holds for its unlock, as the
		// operator prices it: the unlock's size does not depend on the keys.
		let m = Margins::of(info, a)?;
		let probe = OffboardPolicy { unlock_hash: [0; 32], destination: ExplicitOutput::new(a, ask.amount, terms.script_pubkey()),
			operator: self.operator, reclaim_delay: RelativeTime::from_units(1).map_err(|e| Error::Refused(e.to_string()))? };
		let margin = probe.unlock_margin(m.floor, m.multiple);
		let offboard = offboard_fee(&schedule, ask.amount).saturating_add(margin);
		// The coins, furthest from their exit date first and the largest
		// first among one date, until they hold the amount and the fee, with
		// no change or change of at least the operator's smallest leaf.
		let mut chosen: Vec<In> = vec![];
		let (mut total, mut refresh) = (0u64, 0u64);
		let mut done = None;
		for c in self.spendable_coins(a)? {
			let (record, held) = self.held(&c.row)?;
			let expiry = self.service_expiry(&record, &held)?;
			refresh = refresh.saturating_add(refresh_fee(&schedule, c.coin.value, expiry, now));
			total = total.saturating_add(c.coin.value);
			chosen.push(c);
			let fee = refresh.saturating_add(offboard);
			if let Some(change) = total.checked_sub(ask.amount.saturating_add(fee)).filter(|c| *c == 0 || *c >= min) {
				done = Some((fee, change));
				break;
			}
		}
		let Some((fee, change)) = done else {
			return Err(Error::Refused(format!("the wallet's live coins of asset {} hold {} and the order of {} and its fee need {} (refresh {}, \
				offboard {}), with any change at least the operator's smallest leaf of {}: board or receive more, or place less", a, total,
				ask.amount, ask.amount.saturating_add(refresh).saturating_add(offboard), refresh, offboard, min)));
		};
		let bound = max_fee_ppm.unwrap_or(DEFAULT_MAX_FEE_PPM);
		if !fee_within(fee, ask.amount, bound) {
			return Err(Error::Refused(format!("placing the order costs {} of asset {}, above the wallet's bound of {} ppm of its amount {} \
				(raise it with max_fee_ppm)", fee, a, bound, ask.amount)));
		}
		let full_price = terms.price(ask.amount).unwrap_or(0);
		let q = json!({
			"sell": a.to_string(), "amount": ask.amount.to_string(), "want": b.to_string(), "rate_num": ask.rate_num.to_string(),
			"rate_den": ask.rate_den.to_string(), "min_lot": ask.min_lot.to_string(), "expiry_locktime": ask.expiry,
			"full_price": full_price.to_string(),
			"credits_to": match ask.maker_prog { Some(p) => json!(hex(&p)), None => json!("the order's own key") },
			"fee": {"asset": a.to_string(), "amount": fee.to_string(), "refresh": refresh.to_string(),
				"offboard": offboard_fee(&schedule, ask.amount).to_string(), "unlock_margin": margin.to_string()},
			"gives": chosen.iter().map(|c| c.row.leaf_id.clone()).collect::<Vec<_>>(),
			"change": change.to_string(),
		});
		Ok((q, Plan { coins: chosen, fee, margin, change }))
	}

	/// Refuses `p` as the program an order's credits are paid to when it is
	/// no key (a credit there could never be spent), the program of an Arca
	/// script the wallet holds or held (a leaf, a board, a coin received, an
	/// output a forfeit of it made), or the credit program of another of its
	/// orders.
	fn check_maker_prog(&self, p: &[u8; 32]) -> Result<(), Error> {
		if XOnlyPublicKey::from_slice(p).is_err() {
			return Err(Error::Refused(format!("the maker program {} is no key: a credit paid there could never be spent", hex(p))));
		}
		for c in self.store.coins()? {
			// Every script a pair of the coin's rebindable signatures spends:
			// its leaf, its board output for a coin resting on a board, and
			// the checkpoint it moves into when transferred.
			let mut scripts = vec![];
			if let Ok(arca_covenant::CoinRecord::Board(b)) = Self::record_of(&c) {
				scripts.push(("board", b.output().script_pubkey));
			}
			if let Ok((_, a)) = self.held(&c) {
				scripts.push(("leaf", a.valid.output().script_pubkey));
				scripts.push(("checkpoint", a.valid.checkpoint().script_pubkey()));
			}
			if let Some((what, _)) = scripts.iter().find(|(_, s)| v1_program(s) == Some(*p)) {
				return Err(Error::Refused(format!("the maker program {} is the {} script of the wallet's coin {}, an Arca script: a pair of \
					rebindable signatures over one credit there would spend every other credit of the same value; credits go to a plain \
					key (the order's own unless named)", hex(p), what, c.leaf_id)));
			}
			for f in self.store.forfeits_of(&c.leaf_id)? {
				let Ok(ff) = self.forfeit_of(&c, &f) else { continue };
				if v1_program(&ff.output().script_pubkey) == Some(*p) {
					return Err(Error::Refused(format!("the maker program {} is the script of a forfeit of the wallet's coin {}, an Arca \
						script: credits go to a plain key (the order's own unless named)", hex(p), c.leaf_id)));
				}
			}
		}
		for (id, terms, index, _, _, _) in self.store.orders()? {
			let t = Self::order_terms(&terms)?;
			if t.maker_prog == *p || self.keys.order_program(index)? == *p {
				return Err(Error::Refused(format!("the maker program {} is the credit program of the wallet's order {}: each order's \
					credits go to a key of their own", hex(p), id)));
			}
		}
		Ok(())
	}

	fn order_terms(stored: &str) -> Result<FillOrder, Error> {
		let v: Value = serde_json::from_str(stored).map_err(|e| Error::Store(e.to_string()))?;
		FillOrder::from_relay(&v).map(|(_, t)| t).map_err(|e| Error::Store(e.to_string()))
	}

	/// Places `ask` (see the [module documentation](self)). With `shown`, it
	/// goes ahead only on the fee and the coins the program showed (an
	/// [`Self::order_quote`]'s `fee` and `gives`). Answers the order, named
	/// by the participation that places it, and its terms; `sync` completes
	/// it, and [`Self::orders`] says where it rests.
	pub fn order_place(&mut self, ask: &OrderAsk, max_fee_ppm: Option<u64>, shown: Option<&Value>) -> Result<Value, Error> {
		self.witnessed_now()?;
		let info = self.server_info()?;
		let (quote, plan) = self.order_plan(&info, ask, max_fee_ppm)?;
		if let Some(s) = shown {
			for k in ["fee", "gives"] {
				if s[k] != quote[k] {
					return Err(Error::Refused(format!("the order's {} changed since it was shown: it is now {}", k, quote[k])));
				}
			}
		}
		let index = self.store.take_index(ORDERS)?;
		let key = self.keys.order(index)?;
		let terms = FillOrder { asset_a: ask.sell, asset_b: ask.want, rate_num: ask.rate_num, rate_den: ask.rate_den,
			maker_prog: match ask.maker_prog { Some(p) => p, None => self.keys.order_program(index)? }, min_lot: ask.min_lot,
			expiry_locktime: ask.expiry, maker_x: key.x_only_public_key().0.serialize() };
		let destination = terms.script_pubkey();
		let mut wanted = vec![Wanted::Offboard { asset: ask.sell, value: ask.amount, script: destination.clone() }];
		let mut wanted_json = vec![json!({"offboard": {"asset": ask.sell.to_string(), "value": ask.amount.to_string(),
			"script": hex(destination.as_bytes()), "margin": plan.margin.to_string()}})];
		if plan.change > 0 {
			let nonce = random32();
			let owner = self.keys.leaf_xonly(&nonce)?;
			self.store.put_nonce(&nonce, &owner.serialize(), "order change")?;
			wanted.push(Wanted::Leaf { asset: ask.sell, value: plan.change, template: Template::Vtxo1, owner, owner_nonce: nonce,
				exit_delay: self.exit_delay(), order: None });
			wanted_json.push(json!({"nonce": hex(&nonce), "asset": ask.sell.to_string(), "value": plan.change.to_string()}));
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
		let stored = terms.to_relay(&OutPoint::default()).to_string();
		self.store.atomically(|s| {
			s.put_participation(&pid, &body.to_string(), &serde_json::to_string(&given).expect("strings"), &Value::Array(wanted_json.clone()).to_string())?;
			for l in &given {
				s.set_coin_state(l, "given", &format!("order {}", pid))?;
			}
			s.put_order(&pid, &stored, index, ask.amount)
		})?;
		let answer = self.submit_participation_body(&pid, &body, &given)?;
		Ok(json!({"order": pid, "state": answer["state"], "terms": Self::terms_json(&terms), "amount": ask.amount.to_string(),
			"fee": quote["fee"], "gives": given, "change": plan.change.to_string(),
			"note": self.spelling.say("placed: once the operator's round pays the order's offboard and is final, {sync} hands over the \
				forfeits; the operator then unlocks it into the order's address, where it rests on the chain. {orders} says where, with its \
				terms as SeqDEX's relay serves them")}))
	}

	/// The terms an order rests under, without the outpoint (the relay's
	/// field names).
	fn terms_json(t: &FillOrder) -> Value {
		let mut v = t.to_relay(&OutPoint::default());
		if let Some(o) = v.as_object_mut() {
			o.remove("covenant_txid");
			o.remove("covenant_vout");
		}
		v
	}

	/// Moves each order the wallet placed on as far as `sync` takes it: once
	/// its participation is released, the offboard output it was paid to is
	/// recorded; once the wallet has held the preimage for
	/// [`UNLOCK_GRACE_SECONDS`] and the operator has not unlocked the output
	/// into the order's address, the wallet unlocks it itself, its margin
	/// paying the fee where the node accepts the asset.
	pub(crate) fn progress_orders(&mut self) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		let parts = self.store.participations()?;
		let now = self.now()?.to_consensus_u32();
		for (id, terms, _, amount, placed_at, unlock_after) in self.store.orders()? {
			let Some((_, _, _, _, state, preimage, _)) = parts.iter().find(|p| p.0 == id) else { continue };
			let Some(at) = placed_at else {
				if state == "released" {
					let news: Value = serde_json::from_str(&self.store.participation_news(&id)?.unwrap_or_default())
						.map_err(|e| Error::Store(e.to_string()))?;
					let off = &news["offboards"][0];
					let (Some(round), Some(vout)) = (news["round"].as_str(), off["vout"].as_u64()) else { continue };
					let at = format!("{}:{}", round, vout);
					self.store.set_order_offboard(&id, &at, now.saturating_add(UNLOCK_GRACE_SECONDS))?;
					out.push(json!({"order": id, "state": "unlocking", "offboard": at}));
				}
				continue;
			};
			let off = parse_outpoint(&at)?;
			if !self.chain.unspent(&off)? || unlock_after.is_some_and(|t| now < t) {
				continue;
			}
			// The operator has not unlocked it: the wallet does, with the
			// preimage it holds.
			let Some(pre) = preimage.as_deref() else { continue };
			let t = Self::order_terms(&terms)?;
			match self.unlock_order(&id, &off, &t, amount, &unhex32(pre)?) {
				Ok(txid) => out.push(json!({"order": id, "unlocked": txid.to_string(),
					"note": "the operator had not unlocked the order's offboard: the wallet did, with the preimage it holds"})),
				Err(e) => out.push(json!({"order": id, "unlock": e.to_string()})),
			}
		}
		Ok(out)
	}

	/// The unlock of order `id`'s offboard output at `off` into the order's
	/// address, its margin the fee: where the node does not take the asset
	/// for fees the operator's watcher, which attaches a coin, unlocks it.
	fn unlock_order(&self, id: &str, off: &OutPoint, t: &FillOrder, amount: u64, preimage: &[u8; 32]) -> Result<Txid, Error> {
		let tx = self.chain.transaction(&off.txid)?.ok_or_else(|| Error::Node(format!("the node does not have round {}", off.txid)))?;
		let held = tx.output.get(off.vout as usize).and_then(|o| o.value.explicit())
			.ok_or_else(|| Error::Refused(format!("order {}: round {} has no explicit output {}", id, off.txid, off.vout)))?;
		let news: Value = serde_json::from_str(&self.store.participation_news(id)?.unwrap_or_default()).map_err(|e| Error::Store(e.to_string()))?;
		let units = news["offboards"][0]["reclaim_units"].as_u64().unwrap_or(0) as u16;
		let policy = OffboardPolicy {
			unlock_hash: sha256::Hash::hash(preimage).to_byte_array(),
			destination: ExplicitOutput::new(t.asset_a, amount, t.script_pubkey()), operator: self.operator,
			reclaim_delay: RelativeTime::from_units(units).map_err(|e| Error::Refused(e.to_string()))?,
		};
		if self.chain.floor_per_kvb(t.asset_a)?.is_none() {
			return Err(Error::Refused(format!("the node does not take asset {} for fees now: the operator's watcher unlocks the order, \
				attaching a coin of its own", t.asset_a)));
		}
		let u = policy.unlock_tx(*off, held, preimage, &FeeSource::Reserve).map_err(|e| Error::Refused(e.to_string()))?;
		self.chain.broadcast(&u.tx)
	}

	/// What the chain says of order `id` (its offboard at `placed_at`), as of
	/// now: followed from the offboard's unlock through every fill, by the
	/// leaf each spend took (FILL or REFUND), never from a record.
	fn order_standing(&self, t: &FillOrder, amount: u64, placed_at: Option<&str>, state: &str) -> Result<Standing, Error> {
		let wait = |s: &'static str, note: &str| Standing { state: s, at: None, fills: vec![], note: Some(note.to_string()) };
		let Some(at) = placed_at else {
			return Ok(match state {
				"submitting" | "pending" => wait("waiting", "waiting for the operator's round"),
				"issued" | "forfeiting" => wait("in_round", "in the operator's round: sync hands over the forfeits once it is final"),
				"released" => wait("unlocking", "released: the offboard is unlocked into the order's address next"),
				s => wait("not_placed", &format!("its participation is {}: the order was not placed, and its coins are the wallet's", s)),
			});
		};
		let off = parse_outpoint(at)?;
		let from = self.chain.finality(&off.txid)?.height().unwrap_or(0).saturating_sub(1);
		let Some((unlock, _)) = self.chain.spender(&off, from)? else {
			return Ok(wait("unlocking", &format!("the round's offboard output {} is not unlocked yet", at)));
		};
		let i = unlock.input.iter().position(|x| x.previous_output == off).expect("it spends it");
		let made = unlock.output.get(i).and_then(ExplicitOutput::from_txout);
		if made.as_ref().is_none_or(|o| o.script_pubkey != t.script_pubkey() || o.asset != t.asset_a || o.value != amount) {
			return Ok(Standing { state: "spent", at: None, fills: vec![], note: Some(format!("the offboard output {} was spent by {}, which pays \
				no order of these terms at its output {}: reclaimed by the operator after its delay", at, unlock.txid(), i)) });
		}
		let mut here = OutPoint::new(unlock.txid(), i as u32);
		let mut held = amount;
		let mut from = self.chain.finality(&unlock.txid())?.height().unwrap_or(from);
		let mut fills = vec![];
		loop {
			if self.chain.unspent(&here)? {
				let note = Some(format!("its transaction is {}", self.chain.finality(&here.txid)?.word()));
				return Ok(Standing { state: "resting", at: Some((here, held)), fills, note });
			}
			let Some((tx, h)) = self.chain.spender(&here, from)? else {
				return Ok(Standing { state: "spent", at: Some((here, held)), fills, note: Some("spent by a transaction the node no longer has".into()) });
			};
			let k = tx.input.iter().position(|x| x.previous_output == here).expect("it spends it");
			let w = &tx.input[k].witness.script_witness;
			let leaf = if w.len() >= 2 { w[w.len() - 2].as_slice() } else { &[] };
			let finality = self.chain.finality(&tx.txid())?.word();
			if leaf == t.refund_leaf().as_bytes() {
				return Ok(Standing { state: "refunded", at: None, fills, note: Some(format!("refunded by {} ({})", tx.txid(), finality)) });
			}
			if leaf != t.fill_leaf().as_bytes() {
				return Ok(Standing { state: "spent", at: None, fills, note: Some(format!("spent by {} through neither FILL nor REFUND", tx.txid())) });
			}
			let credit = tx.output.get(2 * k).and_then(|o| o.value.explicit()).unwrap_or(0);
			let rest = tx.output.get(2 * k + 1).and_then(ExplicitOutput::from_txout)
				.filter(|o| o.asset == t.asset_a && o.script_pubkey == t.script_pubkey()).map(|o| o.value);
			let remainder = rest.unwrap_or(0);
			fills.push(json!({"txid": tx.txid().to_string(), "k": k, "filled": (held - remainder.min(held)).to_string(),
				"credit_vout": 2 * k, "credited": credit.to_string(), "remainder": remainder.to_string(),
				"remainder_vout": rest.map(|_| 2 * k + 1), "finality": finality}));
			match rest {
				Some(v) => {
					here = OutPoint::new(tx.txid(), (2 * k + 1) as u32);
					held = v;
					from = h.unwrap_or(from);
				},
				None => return Ok(Standing { state: "filled", at: None, fills, note: None }),
			}
		}
	}

	/// The order resting at `at` holding `held`, as an offer on SeqDEX's
	/// relay, unsigned: what `seqob-relaycli post` signs with the maker's own
	/// relay key and posts. Its amounts are what the order holds there and
	/// its full price; it lasts until the earlier of six days from now and
	/// the operator's order margin before the REFUND opens. `None` when its
	/// full price is no whole number of atoms, which the relay does not list,
	/// or when it would expire within a minute.
	fn relay_offer(id: &str, t: &FillOrder, at: &OutPoint, held: u64, margin_s: u64) -> Option<Value> {
		let want = held as u128 * t.rate_num as u128;
		if want % t.rate_den as u128 != 0 {
			return None;
		}
		let now = web_time::SystemTime::now().duration_since(web_time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
		let expires = (now + RELAY_OFFER_SECONDS).min((t.expiry_locktime as u64).saturating_sub(margin_s));
		if expires < now + 60 {
			return None;
		}
		Some(json!({
			"offer_id": format!("arca-{}", &id[..id.len().min(16)]), "schema_version": 1,
			"pair": {"base_asset": t.asset_a.to_string(), "quote_asset": t.asset_b.to_string()},
			"trade_dir": "TRADE_DIR_SELL",
			"base_amount": held.to_string(), "offer_amount": held.to_string(), "offer_asset": t.asset_a.to_string(),
			"want_amount": ((want / t.rate_den as u128) as u64).to_string(), "want_asset": t.asset_b.to_string(),
			"allow_partial": true, "min_fill": t.min_lot.to_string(),
			"created_at_unix": now.to_string(), "expires_at_unix": expires.to_string(),
			"covenant": t.to_relay(at),
		}))
	}

	/// The chain's median time `seconds` from now: an order's expiry named
	/// as a delay.
	pub fn expiry_in(&self, seconds: u32) -> Result<u32, Error> {
		Ok(self.now()?.to_consensus_u32().saturating_add(seconds))
	}

	/// Every order the wallet placed, as the chain shows it now: its state
	/// (`waiting` for its round, `in_round`, `unlocking`, `resting`, `filled`,
	/// `refunded`, or `not_placed`), where it rests and what it holds there
	/// with its terms as SeqDEX's relay serves them (`relay`) and as an offer
	/// for it to post (`offer`, unsigned), each fill with
	/// what it credited, the credits unspent at its credit program, and
	/// when its REFUND opens. Asks the node only.
	pub fn orders(&self) -> Result<Value, Error> {
		let parts = self.store.participations()?;
		let mut out = vec![];
		for (id, terms, index, amount, placed_at, _) in self.store.orders()? {
			let t = Self::order_terms(&terms)?;
			let state = parts.iter().find(|p| p.0 == id).map(|p| p.4.clone()).unwrap_or_default();
			let s = self.order_standing(&t, amount, placed_at.as_deref(), &state)?;
			let own = t.maker_prog == self.keys.order_program(index)?;
			let credits: Vec<Value> = self.chain.coins_at(&[t.maker_script_pubkey()])?.into_iter()
				.map(|(op, o, h)| json!({"outpoint": outpoint_text(&op), "asset": o.asset.explicit().map(|a| a.to_string()),
					"value": o.value.explicit().map(|v| v.to_string()), "height": h})).collect();
			let mut v = json!({"order": id, "state": s.state, "amount": amount.to_string(), "terms": Self::terms_json(&t),
				"fills": s.fills, "credits": credits, "credits_to": if own { "the order's own key: board spends them" } else {
					"the program named when it was placed" },
				"refund_from": t.expiry_locktime});
			if let Some((at, held)) = s.at {
				v["rests_at"] = json!(outpoint_text(&at));
				v["holds"] = json!(held.to_string());
				if s.state == "resting" {
					v["relay"] = t.to_relay(&at);
					v["final"] = json!(self.chain.finality(&at.txid)?.is_final());
					v["offer"] = match Self::relay_offer(&id, &t, &at, held, ORDER_MARGIN_SECONDS) {
						Some(o) => o,
						None => json!({"note": "not listable on SeqDEX's relay as it rests: its full price is no whole number of atoms, \
							or its REFUND opens within the operator's order margin"}),
					};
				}
			}
			if let Some(n) = s.note {
				v["note"] = json!(n);
			}
			out.push(v);
		}
		Ok(Value::Array(out))
	}

	/// Takes back what order `id` holds where it rests, by its REFUND, once
	/// the chain's median time has passed its `expiry_locktime`: to a new
	/// address of the wallet's, the fee from the order's own value where the
	/// node takes its asset for fees, else from an on-chain coin of the
	/// wallet's in `fee_asset` (or one the node takes).
	pub fn order_refund(&mut self, id: &str, fee_asset: Option<AssetId>) -> Result<Value, Error> {
		let (_, terms, index, amount, placed_at, _) = self.store.orders()?.into_iter().find(|o| o.0 == id)
			.ok_or_else(|| Error::Refused(format!("the wallet placed no order {}", id)))?;
		let t = Self::order_terms(&terms)?;
		let state = self.store.participations()?.into_iter().find(|p| p.0 == id).map(|p| p.4).unwrap_or_default();
		let s = self.order_standing(&t, amount, placed_at.as_deref(), &state)?;
		let (Some((at, held)), "resting") = (s.at, s.state) else {
			return Err(Error::Refused(format!("order {} is {}: only an order resting on the chain is refunded", id, s.state)));
		};
		let now = self.now()?.to_consensus_u32();
		if now <= t.expiry_locktime {
			return Err(Error::Refused(format!("order {}'s REFUND opens once the chain's median time passes {}, and it is {}: until then the \
				order rests, and anyone may fill it", id, t.expiry_locktime, now)));
		}
		let to = self.new_script(RECEIVE)?;
		let key = self.keys.order(index)?;
		let tx = match self.chain.floor_per_kvb(t.asset_a)? {
			Some(_) if fee_asset.is_none_or(|a| a == t.asset_a) => {
				let mut fee = self.fee_for(t.asset_a, 250)?;
				loop {
					let ks = t.refund_tx(at, held, &[ExplicitOutput::new(t.asset_a, held - fee.min(held), to.clone())], &FeeSource::Reserve)
						.map_err(|e| Error::Refused(e.to_string()))?;
					let needed = self.fee_for(t.asset_a, Self::signed_vsize_with(&ks.tx, &[], &[0]))?;
					if needed > fee {
						fee = needed;
						continue;
					}
					let sg = arca_covenant::sign::sign_digest(&key, &ks.sighash(self.genesis.genesis_hash()).map_err(|e| Error::Refused(e.to_string()))?,
						&random32());
					break ks.finish(vec![sg.as_ref().to_vec()]).tx;
				}
			},
			_ => self.refund_with_coin(&t, at, held, &to, &key, fee_asset)?,
		};
		let txid = self.chain.broadcast(&tx)?;
		let value = tx.output.iter().find(|o| o.script_pubkey == to).and_then(|o| o.value.explicit()).unwrap_or(0);
		Ok(json!({"order": id, "refund": txid.to_string(), "asset": t.asset_a.to_string(), "value": value.to_string(),
			"address": self.chain.address(&to)?, "from": outpoint_text(&at)}))
	}

	/// The REFUND of the order at `at` with a fee coin of the wallet's: the
	/// whole of what the order holds to `to`, the fee from the coin.
	fn refund_with_coin(&self, t: &FillOrder, at: OutPoint, held: u64, to: &Script, key: &elements::secp256k1_zkp::Keypair,
		fee_asset: Option<AssetId>) -> Result<Transaction, Error>
	{
		let holdings = self.fee_holdings()?;
		let asset = match fee_asset {
			Some(a) => a,
			None => self.choose_fee_asset(t.asset_a, &holdings)?,
		};
		let (op, coin, ckey) = self.fee_candidates()?.into_iter().filter(|(_, o, _)| o.asset.explicit() == Some(asset))
			.max_by_key(|(_, o, _)| o.value.explicit().unwrap_or(0))
			.ok_or_else(|| Error::Refused(format!("the wallet holds no on-chain coin of asset {} to pay the REFUND's fee with", asset)))?;
		let change = self.new_script(super::keys::CHANGE)?;
		let mut fee = self.fee_for(asset, 400)?;
		loop {
			let src = FeeSource::Coin { outpoint: op, coin: coin.clone(), fee, change: change.clone() };
			let ks = t.refund_tx(at, held, &[ExplicitOutput::new(t.asset_a, held, to.clone())], &src).map_err(|e| Error::Refused(e.to_string()))?;
			let needed = self.fee_for(asset, Self::signed_vsize_with(&ks.tx, &[1], &[0]))?;
			if needed > fee {
				fee = needed;
				continue;
			}
			let sg = arca_covenant::sign::sign_digest(key, &ks.sighash(self.genesis.genesis_hash()).map_err(|e| Error::Refused(e.to_string()))?,
				&random32());
			let mut tx = ks.finish(vec![sg.as_ref().to_vec()]).tx;
			self.sign_p2wpkh(&mut tx, 1, &coin, &ckey);
			return Ok(tx);
		}
	}
}

/// Reads an order's terms from the command line or a program: `{sell,
/// amount, want, rate_num, rate_den, min_lot?, expiry, maker_prog?}`.
pub fn ask_of(a: &Value) -> Result<OrderAsk, Error> {
	let asset = |k: &str| -> Result<AssetId, Error> {
		AssetId::from_str(a[k].as_str().unwrap_or("")).map_err(|e| Error::Parse(format!("{}: {}", k, e)))
	};
	// A number, or a decimal string as 64-bit integers are written in JSON.
	let n = |k: &str| -> Result<u64, Error> {
		match &a[k] {
			Value::Number(x) => x.as_u64().ok_or_else(|| Error::Parse(format!("{}: {}", k, x))),
			Value::Null => Err(Error::Parse(format!("{} is missing", k))),
			v => amount(v, k),
		}
	};
	let amount_v = n("amount")?;
	let maker_prog = match a["maker_prog"].as_str().filter(|s| !s.is_empty()) {
		Some(h) => Some(unhex(h)?.try_into().map_err(|_| Error::Parse("maker_prog: 32 bytes of hex".into()))?),
		None => None,
	};
	Ok(OrderAsk {
		sell: asset("sell")?, amount: amount_v, want: asset("want")?, rate_num: n("rate_num")?, rate_den: n("rate_den")?,
		min_lot: if a["min_lot"].is_null() { amount_v } else { n("min_lot")? },
		expiry: u32::try_from(n("expiry")?).map_err(|_| Error::Parse("expiry: above 2^32".into()))?,
		maker_prog,
	})
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn an_ask_is_read_as_the_command_line_writes_it() {
		let a = AssetId::from_slice(&[1; 32]).unwrap();
		let b = AssetId::from_slice(&[2; 32]).unwrap();
		let v = json!({"sell": a.to_string(), "amount": "1000000", "want": b.to_string(), "rate_num": 3, "rate_den": "2",
			"expiry": 1_900_000_000u64});
		let ask = ask_of(&v).unwrap();
		assert_eq!((ask.amount, ask.rate_num, ask.rate_den, ask.min_lot, ask.expiry), (1_000_000, 3, 2, 1_000_000, 1_900_000_000));
		assert_eq!(ask.maker_prog, None);
		let mut w = v.clone();
		w["maker_prog"] = json!("11".repeat(32));
		assert_eq!(ask_of(&w).unwrap().maker_prog, Some([0x11; 32]));
		w["maker_prog"] = json!("11");
		assert!(ask_of(&w).is_err());
		w["expiry"] = json!(1u64 << 33);
		assert!(ask_of(&w).is_err());
	}

	#[test]
	fn the_relay_offer_sells_what_rests_at_its_full_price() {
		let a = AssetId::from_slice(&[1; 32]).unwrap();
		let b = AssetId::from_slice(&[2; 32]).unwrap();
		let now = web_time::SystemTime::now().duration_since(web_time::UNIX_EPOCH).unwrap().as_secs() as u32;
		let t = FillOrder { asset_a: a, asset_b: b, rate_num: 3, rate_den: 2, maker_prog: [3; 32], min_lot: 100_000,
			expiry_locktime: now + 48 * 3600, maker_x: [4; 32] };
		let at = OutPoint::new(Txid::from_str(&"ab".repeat(32)).unwrap(), 1);
		let o = Wallet::relay_offer(&"cd".repeat(32), &t, &at, 600_000, 21_600).unwrap();
		assert_eq!((o["offer_amount"].as_str(), o["want_amount"].as_str(), o["base_amount"].as_str()), (Some("600000"), Some("900000"),
			Some("600000")));
		assert_eq!((o["trade_dir"].as_str(), o["offer_asset"].as_str(), o["want_asset"].as_str()), (Some("TRADE_DIR_SELL"),
			Some(a.to_string().as_str()), Some(b.to_string().as_str())));
		assert_eq!(o["covenant"], t.to_relay(&at));
		assert_eq!(o["offer_id"], json!(format!("arca-{}", "cd".repeat(8))));
		// It ends six hours before the REFUND, inside the relay's seven days.
		assert_eq!(o["expires_at_unix"], json!((now as u64 + 42 * 3600).to_string()));
		// No whole price, or a REFUND inside the margin: not listable.
		assert!(Wallet::relay_offer("x", &t, &at, 600_001, 21_600).is_none());
		let soon = FillOrder { expiry_locktime: now + 3600, ..t.clone() };
		assert!(Wallet::relay_offer("x", &soon, &at, 600_000, 21_600).is_none());
	}

	#[test]
	fn a_v1_program_is_read_from_its_script() {
		let p = [7u8; 32];
		let s = elements::script::Builder::new().push_int(1).push_slice(&p).into_script();
		assert_eq!(v1_program(&s), Some(p));
		let v0 = elements::script::Builder::new().push_int(0).push_slice(&p).into_script();
		assert_eq!(v1_program(&v0), None);
		assert_eq!(parse_outpoint(&format!("{}:3", "ab".repeat(32))).unwrap().vout, 3);
		assert!(parse_outpoint("nope").is_err());
	}
}
