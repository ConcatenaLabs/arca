//! Taking an on-chain order: a fill of an order resting on the chain under
//! SeqDEX's fill covenant, paid with the wallet's coins and run in the
//! operator's round.
//!
//! The order sells one asset and is paid in another. The wallet gives up
//! coins of the asset the order is paid in, worth the order's price for the
//! fill and the operator's fee, for one leaf of what it fills in the asset
//! the order sells; the operator's round spends the order, credits its maker
//! on the chain, and pays the wallet's leaf into a batch. The wallet takes
//! nothing on the relay's word: it rebuilds the order's script from the terms
//! as the relay serves them and finds it on its own node at the order's
//! outpoint, unspent and final, holding what the take names, and the fill is
//! priced by the covenant's own arithmetic ([`arca_covenant::FillOrder`]).
//!
//! The coins it gives up hold exactly the price and the fee: where no live
//! coin holds that much, the wallet first pays itself that much out of round
//! from its coins of the asset, and gives up the coin that makes. Its fee is
//! what the operator's schedule asks for an offboard of the price in that
//! asset, bounded by the wallet as a refresh's fee is.
//!
//! A take asks something of the wallet once more before its round runs: a
//! round that fills orders pays their makers from the operator's coins, so
//! the operator broadcasts it only once every take in it has handed over its
//! forfeits. The take's status serves the round's transaction without its
//! witnesses; `sync` validates the new leaf against it, checks the round
//! fills the order as asked at the take's input, and signs the forfeit of
//! each coin given up, built against that new leaf. The preimage comes once
//! the round is final, at a later `sync`. A take whose forfeits do not come
//! in time is voided, its coins the wallet's again, so the wallet's schedule
//! ([`Wallet::sync_schedule`]) wakes it within the operator's round interval
//! and within half its forfeit window until the take is released.

use std::str::FromStr;

use elements::OutPoint;
use serde_json::{json, Value};

use arca_covenant::{ExplicitOutput, FillOrder, LeafId, RelativeTime, Take, TakeLeaf, Template};

use super::chain::hex;
use super::client::key_proof_digest;
use super::pay::{In, Out};
use super::round::{fee_within, schedule_of, DEFAULT_MAX_FEE_PPM};
use super::wallet::{sign, Wallet};
use super::{random32, Error};

/// An order as the wallet read it: where it rests, its terms, what it holds,
/// and the terms as they were handed to the wallet.
struct Order {
	at: OutPoint,
	terms: FillOrder,
	locked: u64,
	served: Value,
}

/// The fee the operator's schedule in `asset` asks for an offboard of
/// `value`: its parts per million, rounded up, and its fixed part.
pub(crate) fn offboard_fee(schedule: &Value, value: u64) -> u64 {
	let ppm = schedule["offboard_ppm"].as_u64().unwrap_or(0) as u128;
	let base = schedule["offboard_base"].as_str().and_then(|b| b.parse::<u64>().ok()).unwrap_or(0) as u128;
	((value as u128 * ppm).div_ceil(1_000_000) + base).min(u64::MAX as u128) as u64
}

fn outpoint_text(op: &OutPoint) -> String {
	format!("{}:{}", op.txid, op.vout)
}

impl Wallet {
	/// Reads `text`, the order as the relay serves it (its `CovenantTerms`,
	/// or an offer whose settlement is one, in the relay's JSON form), and
	/// finds it on the wallet's own node.
	fn read_order(&self, text: &str) -> Result<Order, Error> {
		let served: Value = serde_json::from_str(text.trim()).map_err(|e| Error::Parse(format!("the order: {}", e)))?;
		let (at, terms) = FillOrder::from_relay(&served).map_err(|e| Error::Refused(e.to_string()))?;
		let tx = self.chain.transaction(&at.txid)?
			.ok_or_else(|| Error::Refused(format!("order {}: the wallet's node knows no transaction {}", outpoint_text(&at), at.txid)))?;
		let out = tx.output.get(at.vout as usize)
			.ok_or_else(|| Error::Refused(format!("order {}: transaction {} has no output {}", outpoint_text(&at), at.txid, at.vout)))?;
		let shown = ExplicitOutput::from_txout(out)
			.ok_or_else(|| Error::Refused(format!("order {}: the output hides its asset or value", outpoint_text(&at))))?;
		if shown.script_pubkey != terms.script_pubkey() {
			return Err(Error::Refused(format!("order {}: the terms do not make the script on the chain there: they are not that \
				order's terms", outpoint_text(&at))));
		}
		if shown.asset != terms.asset_a {
			return Err(Error::Refused(format!("order {}: it holds asset {}, and its terms sell {}", outpoint_text(&at), shown.asset,
				terms.asset_a)));
		}
		if !self.chain.unspent(&at)? {
			return Err(Error::Refused(format!("order {} is spent, in a block or in the node's mempool: it was filled or refunded",
				outpoint_text(&at))));
		}
		let finality = self.chain.finality(&at.txid)?;
		if !finality.is_final() {
			return Err(Error::Refused(format!("order {} is {}: a round takes an order once its transaction is final", outpoint_text(&at),
				finality.word())));
		}
		Ok(Order { at, terms, locked: shown.value, served })
	}

	/// What a take of `amount` of the order `text` (all of it when none is
	/// named) would cost, before anything is signed or asked of the
	/// operator: the fill, the price the order asks, the operator's fee, what
	/// the coins given up hold, and whether the wallet must first pay itself
	/// a coin of that much. Refuses a fill the order's covenant would refuse,
	/// a fee above the wallet's bound (`max_fee_ppm` millionths of the price,
	/// 10,000 unless raised), and a leaf below the operator's smallest.
	pub fn take_quote(&self, text: &str, amount: Option<u64>, max_fee_ppm: Option<u64>) -> Result<Value, Error> {
		let o = self.read_order(text)?;
		let info = self.server_info()?;
		self.quote_of(&o, &info, amount, max_fee_ppm).map(|(q, _)| q)
	}

	fn quote_of(&self, o: &Order, info: &Value, amount: Option<u64>, max_fee_ppm: Option<u64>) -> Result<(Value, Option<String>), Error> {
		let (a, b) = (o.terms.asset_a, o.terms.asset_b);
		let min = Self::min_leaf(info, a)?;
		Self::min_leaf(info, b)?;
		let filled = amount.unwrap_or(o.locked);
		let plan = o.terms.plan(o.locked, filled).map_err(|e| Error::Refused(format!("order {}: {}", outpoint_text(&o.at), e)))?;
		if filled < min {
			return Err(Error::Refused(format!("a leaf of {} of asset {} is below the operator's smallest leaf {}", filled, a, min)));
		}
		let price = plan.credit.value;
		let fee = offboard_fee(&schedule_of(info, b), price);
		let bound = max_fee_ppm.unwrap_or(DEFAULT_MAX_FEE_PPM);
		if !fee_within(fee, price, bound) {
			return Err(Error::Refused(format!("the operator's fee for a take of a price of {} of asset {} is {}, above the wallet's bound \
				of {} ppm of the price (raise it with max_fee_ppm)", price, b, fee, bound)));
		}
		let need = price.checked_add(fee).ok_or_else(|| Error::Refused("the price and the fee overflow".into()))?;
		// A live coin of exactly that much, or a payment to itself first.
		let exact = self.spendable_coins(b)?.into_iter().find(|i| i.coin.value == need).map(|i| i.row.leaf_id);
		let q = json!({
			"order": outpoint_text(&o.at), "asset_a": a.to_string(), "asset_b": b.to_string(),
			"locked": o.locked.to_string(), "filled": filled.to_string(), "remainder": plan.remainder.to_string(),
			"price": price.to_string(), "fee": fee.to_string(), "gives": need.to_string(),
			"maker_script": hex(o.terms.maker_script_pubkey().as_bytes()),
			"coin": exact, "pays_itself_first": exact.is_none(),
		});
		Ok((q, exact))
	}

	/// Takes `amount` of the order `text` (all of it when none is named): see
	/// the [module documentation](self). With `shown`, the take goes ahead
	/// only on the fill, price and fee the program showed (a
	/// [`Self::take_quote`]'s). Answers the take as a participation, which
	/// `sync` completes.
	pub fn take(&mut self, text: &str, amount: Option<u64>, max_fee_ppm: Option<u64>, shown: Option<&Value>) -> Result<Value, Error> {
		self.witnessed_now()?;
		let o = self.read_order(text)?;
		let info = self.server_info()?;
		self.remember_fills(&info)?;
		let (quote, exact) = self.quote_of(&o, &info, amount, max_fee_ppm)?;
		if let Some(s) = shown {
			for k in ["order", "filled", "price", "fee"] {
				if s[k] != quote[k] {
					return Err(Error::Refused(format!("the take's {} changed since it was shown: it is now {}", k, quote[k])));
				}
			}
		}
		let b = o.terms.asset_b;
		let need: u64 = quote["gives"].as_str().unwrap_or("0").parse().map_err(|_| Error::Parse("the quote".into()))?;
		let filled: u64 = quote["filled"].as_str().unwrap_or("0").parse().map_err(|_| Error::Parse("the quote".into()))?;
		let fee: u64 = quote["fee"].as_str().unwrap_or("0").parse().map_err(|_| Error::Parse("the quote".into()))?;
		// The coin given up: one of exactly the price and the fee, the
		// wallet paying itself one first when it holds none.
		let (coin, paid_itself) = match exact {
			Some(l) => (l, None),
			None => {
				let own = self.own_leaf_for("take")?;
				let mailbox = self.keys.mailbox()?.x_only_public_key().0;
				let out = Out { asset: b, value: need, leaf: own, mailbox, until: None };
				let min_leaf = Self::min_leaf(&info, b)?;
				let explicit = ExplicitOutput::new(b, need, own.policy(self.operator, self.genesis).script_pubkey());
				let (inputs, _, change): (Vec<In>, u64, u64) = self.choose_coins(&info, b, need, &explicit, min_leaf)?;
				let mut outs = vec![out];
				if change > 0 {
					let back = self.own_leaf_for("change")?;
					outs.push(Out { asset: b, value: change, leaf: back, mailbox, until: None });
				}
				let paid = self.transfer_back(&inputs, &outs)?;
				let leaf = self.store.nonce(&own.owner_nonce)?.and_then(|n| n.leaf_id)
					.ok_or_else(|| Error::Refused("the coin the wallet paid itself for the take did not come".into()))?;
				(leaf, Some(paid))
			},
		};
		let row = self.store.coin(&coin)?.ok_or_else(|| Error::Store(format!("no coin {}", coin)))?;
		// The leaf wanted, under a fresh key the wallet holds.
		let nonce = random32();
		let owner = self.keys.leaf_xonly(&nonce)?;
		self.store.put_nonce(&nonce, &owner.serialize(), "take")?;
		let exit_delay: RelativeTime = self.exit_delay();
		let take = Take {
			order: o.at,
			terms: o.terms.clone(),
			locked: o.locked,
			filled,
			inputs: vec![LeafId::from_str(&coin).map_err(|e| Error::Store(e.to_string()))?],
			leaf: TakeLeaf { asset: o.terms.asset_a, value: filled, template: Template::Vtxo1, owner, owner_nonce: nonce, exit_delay },
			fee: (b, fee),
			not_before: None,
		};
		let id = take.id(&self.genesis, &self.operator);
		let coin_key = self.coin_key(&row.owner_nonce)?;
		let leaf_key = self.keys.leaf(&nonce)?;
		let (mailbox, proof) = self.binding(&leaf_key)?;
		let body = json!({
			"order": o.served.get("covenant").filter(|c| c.is_object()).cloned().unwrap_or_else(|| o.served.clone()),
			"locked": o.locked.to_string(),
			"filled": filled.to_string(),
			"inputs": [{"leaf_id": coin, "attestation": hex(sign(&coin_key, &id).as_ref())}],
			"leaf": {
				"asset": o.terms.asset_a.to_string(), "value": filled.to_string(), "template": Template::Vtxo1.to_string(),
				"owner": hex(&owner.serialize()), "owner_nonce": hex(&nonce), "exit_delay_units": exit_delay.units(),
				"key_proof": hex(sign(&leaf_key, &key_proof_digest(&id)).as_ref()), "mailbox": mailbox, "mailbox_proof": proof,
			},
			"fee": {"asset": b.to_string(), "amount": fee.to_string()},
		});
		let pid = hex(&id);
		let given = vec![coin.clone()];
		let wanted = json!([{"nonce": hex(&nonce), "asset": o.terms.asset_a.to_string(), "value": filled.to_string()}]);
		self.store.atomically(|s| {
			s.put_participation(&pid, &body.to_string(), &serde_json::to_string(&given).expect("strings"), &wanted.to_string())?;
			s.set_coin_state(&coin, "given", &format!("take {}", pid))
		})?;
		let answer = self.submit_participation_body(&pid, &body, &given)?;
		let mut out = json!({"take": pid, "state": answer["state"], "order": quote["order"], "filled": quote["filled"],
			"remainder": quote["remainder"], "price": quote["price"], "fee": quote["fee"], "asset_a": quote["asset_a"],
			"asset_b": quote["asset_b"], "gives": given, "wants": wanted,
			"note": self.spelling.say("taken: once the operator builds the round that fills the order, {sync} hands over the forfeit of \
				the coin given up (the round is broadcast once every take in it has), and takes the new leaf once the round is final")});
		if let Some(p) = paid_itself {
			out["paid_itself"] = p;
		}
		Ok(out)
	}

	/// Whether the participation of `body` is a take.
	pub(crate) fn is_take(body: &Value) -> bool {
		body.get("order").is_some_and(|o| o.is_object())
	}

	/// Checks that `round`, the round of the take `pid` whose status is `st`,
	/// fills the take's order as it asked, at the input the status names:
	/// the take's id covers that order and that fill, and the wallet signs
	/// no forfeit for another.
	pub(crate) fn check_take_round(&self, body: &Value, st: &Value, round: &elements::Transaction) -> Result<(), Error> {
		let (at, terms) = FillOrder::from_relay(&body["order"]).map_err(|e| Error::Store(e.to_string()))?;
		let locked: u64 = body["locked"].as_str().unwrap_or("0").parse().map_err(|_| Error::Store("a take's locked".into()))?;
		let filled: u64 = body["filled"].as_str().unwrap_or("0").parse().map_err(|_| Error::Store("a take's fill".into()))?;
		let k = st["fill"]["input"].as_u64()
			.ok_or_else(|| Error::Refused("the status names no input of the round for the take's order".into()))? as usize;
		if round.input.get(k).map(|i| i.previous_output) != Some(at) {
			return Err(Error::Refused(format!("input {} of round {} is not order {}", k, round.txid(), outpoint_text(&at))));
		}
		let f = terms.check(round, k, locked).map_err(|e| Error::Refused(format!("round {}: {}", round.txid(), e)))?;
		if f.filled != filled {
			return Err(Error::Refused(format!("round {} fills {} of order {}; the take asked {}", round.txid(), f.filled,
				outpoint_text(&at), filled)));
		}
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn the_fee_is_the_offboard_schedule_of_the_price() {
		assert_eq!(offboard_fee(&json!({"offboard_ppm": 0, "offboard_base": "1000"}), 999_000), 1_000);
		assert_eq!(offboard_fee(&json!({"offboard_ppm": 2_500, "offboard_base": "0"}), 1_000_001), 2_501);
		assert_eq!(offboard_fee(&json!({}), 5), 0);
	}
}
