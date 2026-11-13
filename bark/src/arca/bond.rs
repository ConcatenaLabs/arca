//! The operator's equivocation bond, as the wallet checks it before it takes
//! a payment out of round, and as `watch-bond` watches it.
//!
//! The bond ([`arca_covenant::bond`]) is a coin anyone burns with two
//! different messages the operator key signed under one coin's salt. The
//! operator names it in `info.bond`; the wallet trusts none of that until it
//! has checked it on its own node ([`Wallet::bond_standing`]): the scripts
//! rebuilt from the operator key the wallet pinned and the published
//! withdrawal key and delay, the coin at the bond's script, unspent,
//! explicit and final (`bonded`), or at its notice output (`noticed`, with
//! the time it can be withdrawn); anything else is `missing`.
//!
//! Once a wallet has seen a standing bond of its operator, or its operator
//! names one, it requires one from then on ([`Wallet::bond_gate`]): a receive
//! request, a swap offered or accepted, is refused while the bond is missing,
//! in notice, or worth less in the reference unit (at the wallet's own node's
//! rates) than what the wallet would then hold out of round. A wallet whose
//! operator never named a bond says so and goes on. A coin that arrives out
//! of round while the bond does not stand is still the wallet's: the mailbox
//! says so, and `sync` asks for its refresh at once, since a coin that has
//! been through a round has no out-of-round lineage left to double-sign.
//!
//! A wallet that takes payments out of round from many others at once (a
//! maker, a swap service, an LSP) may also set an instant budget
//! ([`Wallet::set_instant_budget`]): a share of the bond's value, at the
//! wallet's own node's rate, that it holds out of round at most, all assets
//! counted in the reference unit. Past it the wallet refuses a payment, and
//! takes it after its next round, once what it holds is refreshed; `sync`
//! asks for that refresh at once. Where the operator suggests a share
//! (`info.bond.instant_budget_ppm`), the wallet takes the lower of the two.
//! No budget is set unless the wallet's owner sets one: the library imposes
//! none, and values the bond at its node's rate whatever its asset.
//!
//! What counts against the budget is what the operator, with someone other
//! than the wallet, could take from it by signing a second spend: each coin
//! of `received` lineage ([`super::places::Lineage`]) at its whole value: a
//! payment received, and what a trade paid the wallet (change included)
//! when some checkpoint of the trade has no owner's exit. A coin of the
//! wallet's own lineage (its round's and boards' coins, its own change from
//! paying out of them) counts nothing, and neither does a coin of `trade`
//! lineage, what a trade with its owner's exit on every checkpoint paid it:
//! if that trade dies, the coin the wallet gave comes home by its exit. A
//! coin on its way into a swap whose checkpoint has its owner's exit is
//! judged by its own lineage, since it comes home if the swap never
//! completes; one whose checkpoint has none counts as a coin received out
//! of round does. A coin given to a round participation (a refresh, an
//! offboard, an order, a take, a distribution) is judged by its own lineage
//! too: the one thing the wallet signs that spends it is its forfeit, as for
//! any coin given up in a round, to the operator alone and claimable only
//! with that round's connector, whether signed once the round is final or
//! before it is broadcast (an operator with `forfeits_before_broadcast`).
//! `coin_places` names each coin counted (`at_risk`).
//!
//! The wallet keeps the operator's signature over every message of its
//! coins' lineage ([`arca_covenant::bond::cosigned_by`]) and writes it as
//! evidence lines ([`Wallet::bond_evidence`]): `{"salt", "form", "rest",
//! "signature"}`. [`Wallet::watch_bond`] takes its own and any other's, counts
//! only those whose signature the operator key made, compares them under each
//! salt, and reads every spend on the chain and in the mempool of a script
//! that carries a watched salt's `K`: for a salt of its own coins, only once
//! an output those coins descend from is spent, since every spend under the
//! salt starts there, and a few seconds of blocks a run. Two different messages under one salt
//! burn the bond: the slash, with a fee coin of the wallet's own, is sent, and
//! sent again on every run until its block is final.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, OutPoint, Transaction, TxOut, Txid};
use serde_json::{json, Value};

use arca_covenant::bond::{self, BondPolicy, Evidence, Form, Signed};
use arca_covenant::{RelativeTime, WalletPolicy};

use super::chain::{hex, unhex, unhex32};
use super::exit::Payer;
use super::{Error, Wallet};

/// The store's note of the first bond of its operator the wallet saw stand,
/// or named: from then on it requires one.
pub const BOND_SEEN: &str = "bond_seen";
/// The slashes the wallet sent, and their transactions: sent again until
/// final.
pub const BOND_SLASHES: &str = "bond_slashes";
/// The height `watch-bond` read the chain to.
pub const BOND_SCANNED: &str = "bond_scanned";
/// The salts `watch-bond` has read the chain for, to [`BOND_SCANNED`].
pub const BOND_SALTS: &str = "bond_salts";
/// The operator's signatures `watch-bond` read from the chain and the
/// mempool, as evidence lines.
pub const BOND_FOUND: &str = "bond_found";
/// The wallet's instant budget, in millionths of the bond's value, or
/// absent: see [`Wallet::set_instant_budget`].
pub const INSTANT_BUDGET: &str = "instant_budget";
/// How far back `watch-bond` reads the chain at the most: a salt handed in
/// by another is read for from there, and the wallet's own from the block of
/// the oldest transaction its coins rest on, when that is later.
pub const FIRST_SCAN: u64 = 20_000;
/// How many blocks `watch-bond` reads before it notes how far it read.
pub const SCAN_CHUNK: u64 = 128;
/// The store key prefix under which a coin's evidence is kept once read
/// (`watch_bond`), by its leaf id: a coin's record never changes.
pub const EVIDENCE_KEY: &str = "bond_evidence:";
/// How long one `watch-bond` reads blocks, and reads coins' evidence not
/// kept yet, before it stops and says more is left (`scanned.more`,
/// `evidence_unread`): the next run reads on from where it stopped.
pub const SCAN_SLICE: std::time::Duration = std::time::Duration::from_secs(5);

/// A coin's lifetime, the longest a coin the operator makes lives from its
/// round or board to its first expiry: a bond's notice must outlast it.
pub const LIFETIME: u64 = 28 * 86_400;
/// What a notice leaves beyond a lifetime and the longest exit delay.
pub const SLASH_MARGIN: u64 = 86_400;

/// The states of a coin the wallet holds that rest on an out-of-round
/// lineage the operator could double-sign.
const HELD: [&str; 5] = ["live", "offered", "sending", "given", "forfeited"];

/// Where the operator's bond stands, as the wallet's own node shows it.
#[derive(Debug, Clone)]
pub struct Standing {
	/// `none` (the operator names no bond), `bonded`, `noticed` or `missing`.
	pub state: &'static str,
	pub policy: Option<BondPolicy>,
	/// The coin that stands: the bond, or its notice output.
	pub coin: Option<(OutPoint, TxOut)>,
	pub asset: Option<AssetId>,
	pub value: Option<u64>,
	pub withdrawable_at: Option<u32>,
	pub why: String,
}

/// A wallet's instant budget against its operator's bond, in atoms of the
/// reference unit at the wallet's node's rates.
#[derive(Debug, Clone)]
struct Budget {
	own_ppm: u32,
	operator_ppm: Option<u32>,
	/// The share taken: the lower of the two.
	ppm: u32,
	/// The bond's value.
	bond: u128,
	/// The budget: `ppm` millionths of `bond`.
	value: u128,
	/// What the wallet holds out of round, the payment asked for with it.
	held: u128,
	/// The room left, `value` less `held`, in atoms of each asset the node
	/// prices.
	room_atoms: BTreeMap<AssetId, u64>,
}

/// What the wallet holds out of round against the most it may hold
/// ([`Wallet::exposure`]).
#[derive(Debug, Clone)]
pub(crate) struct Exposure {
	/// Out of round, in atoms of the reference unit, over every asset the
	/// node prices.
	pub held: u128,
	/// The instant budget, or the bond's value without one.
	pub limit: u128,
	/// The assets held out of round that the node does not price.
	pub unpriced: Vec<String>,
}

impl Standing {
	fn of(state: &'static str, policy: Option<BondPolicy>, why: impl Into<String>) -> Standing {
		Standing { state, policy, coin: None, asset: None, value: None, withdrawable_at: None, why: why.into() }
	}
}

/// One evidence line: a message the operator key signed under a salt.
pub fn evidence_line(salt: &[u8; 32], s: &Signed) -> Value {
	json!({"salt": hex(salt), "form": s.form.name(), "rest": hex(&s.rest), "signature": hex(s.signature.as_ref())})
}

/// An evidence line read back.
pub fn read_line(v: &Value) -> Result<([u8; 32], Signed), Error> {
	let salt = unhex32(v["salt"].as_str().unwrap_or_default())?;
	let form = v["form"].as_str().and_then(Form::from_name).ok_or_else(|| Error::Parse(format!("an evidence line's form: {}", v["form"])))?;
	let rest = unhex(v["rest"].as_str().unwrap_or_default())?;
	let signature = Signature::from_slice(&unhex(v["signature"].as_str().unwrap_or_default())?)
		.map_err(|e| Error::Parse(format!("an evidence line's signature: {}", e)))?;
	Ok((salt, Signed { form, rest, signature }))
}

/// The asset and amount of the coin a rebindable message's rest names: the
/// rest is `asset ‖ 01 01 ‖ value ‖ m ‖ m output hashes`, after a
/// landing leaf's landing program where the leaf is one
/// ([`arca_covenant::landing::PROGRAM_BYTES`]); its length says which.
fn coin_of_rest(rest: &[u8]) -> Option<(AssetId, u64)> {
	[0, arca_covenant::landing::PROGRAM_BYTES].into_iter().find_map(|at| {
		let r = rest.get(at..)?;
		let m = *r.get(42)? as usize;
		if r.len() != 43 + 32 * m || r[32] != 1 || r[33] != 1 {
			return None;
		}
		let mut a = [0u8; 32];
		a.copy_from_slice(&r[..32]);
		Some((AssetId::from_byte_array(a), u64::from_le_bytes(r[34..42].try_into().ok()?)))
	})
}

/// The watched salt a push of a leaf's collaborative script names: its
/// `K`, or a landing leaf's `K ‖ P`.
fn watched_push<'a>(push: &[u8], ks: &'a BTreeMap<[u8; 32], [u8; 32]>) -> Option<&'a [u8; 32]> {
	if push.len() != 32 && push.len() != 32 + arca_covenant::landing::PROGRAM_BYTES {
		return None;
	}
	ks.get(<&[u8; 32]>::try_from(&push[..32]).ok()?)
}

impl Wallet {
	/// The operator's bond as `info` names it and the wallet's own node
	/// shows it: see the [module documentation](self).
	pub(crate) fn bond_standing(&self, info: &Value) -> Result<Standing, Error> {
		let b = &info["bond"];
		if b.is_null() {
			return Ok(Standing::of("none", None, "the operator names no bond"));
		}
		let w = match b["withdraw_key"].as_str().map(XOnlyPublicKey::from_str) {
			Some(Ok(w)) => w,
			_ => return Ok(Standing::of("missing", None, format!("the bond's withdrawal key does not read: {}", b["withdraw_key"]))),
		};
		let d = match b["notice_units"].as_u64().and_then(|u| u16::try_from(u).ok()).map(RelativeTime::from_units) {
			Some(Ok(d)) => d,
			_ => return Ok(Standing::of("missing", None, format!("the bond's notice does not read: {}", b["notice_units"]))),
		};
		let policy = match BondPolicy::new(self.genesis, self.operator, w, d) {
			Ok(p) => p,
			Err(e) => return Ok(Standing::of("missing", None, e.to_string())),
		};
		let least = LIFETIME + Self::delay(self.cfg.max_exit_delay_units).seconds() + SLASH_MARGIN;
		if d.seconds() < least {
			return Ok(Standing::of("missing", Some(policy), format!("the bond's notice of {} s is shorter than a coin's lifetime, the longest \
				exit delay and a day, {} s: a coin paid out of round could outlive it", d.seconds(), least)));
		}
		if b["script_pubkey"].as_str() != Some(&hex(policy.script_pubkey().as_bytes())) {
			return Ok(Standing::of("missing", Some(policy), "the bond's script is not the one its terms and the operator key make"));
		}
		let Some(op) = b["outpoint"].as_str().and_then(|s| parse_outpoint(s).ok()) else {
			return Ok(Standing::of("missing", Some(policy), format!("the operator names no bond coin ({})", b["state"])));
		};
		// Where the bond coin is and whether it stands, read together.
		self.chain.read_ahead_of(std::slice::from_ref(&op.txid), std::slice::from_ref(&op));
		let Some(tx) = self.chain.transaction(&op.txid)? else {
			return Ok(Standing::of("missing", Some(policy), format!("this wallet's node holds no transaction {}", op.txid)));
		};
		let Some(out) = tx.output.get(op.vout as usize).cloned() else {
			return Ok(Standing::of("missing", Some(policy), format!("{} has no output {}", op.txid, op.vout)));
		};
		let (asset, value) = match (out.asset.explicit(), out.value.explicit()) {
			(Some(a), Some(v)) if out.script_pubkey == policy.script_pubkey() => (a, v),
			_ => return Ok(Standing::of("missing", Some(policy), format!("{}:{} is not an explicit coin at the bond's script", op.txid, op.vout))),
		};
		let mut s = Standing { asset: Some(asset), value: Some(value), ..Standing::of("bonded", Some(policy), "") };
		if self.chain.unspent(&op)? {
			if !self.chain.finality(&op.txid)?.is_final() {
				s.state = "missing";
				s.why = format!("the bond coin {}:{} is not final yet", op.txid, op.vout);
				return Ok(s);
			}
			s.coin = Some((op, out));
			s.why = format!("{}:{} is unspent and final", op.txid, op.vout);
			return Ok(s);
		}
		let notice = b["notice"].as_str().and_then(|n| parse_outpoint(n).ok());
		if let Some(n) = notice {
			if let Some(ntx) = self.chain.transaction(&n.txid)? {
				let o = ntx.output.get(n.vout as usize).cloned();
				let whole = o.as_ref().is_some_and(|o| o.script_pubkey == policy.notice_script_pubkey() && o.asset.explicit() == Some(asset)
					&& o.value.explicit() == Some(value)) && ntx.input.iter().any(|i| i.previous_output == op);
				if whole && self.chain.unspent(&n)? {
					s.state = "noticed";
					s.withdrawable_at = self.chain.coin_time(&n.txid)?.map(|t| t.saturating_add(d.seconds() as u32));
					s.coin = Some((n, o.expect("checked")));
					s.why = format!("the bond is in notice at {}:{}", n.txid, n.vout);
					return Ok(s);
				}
			}
		}
		s.state = "missing";
		s.why = format!("the bond coin {}:{} is spent{}", op.txid, op.vout, if notice.is_some() { ", and not into its notice output" } else { "" });
		Ok(s)
	}

	/// What the wallet holds at risk out of round, by asset: each coin the
	/// operator and someone else could take from it by signing twice
	/// ([`Self::at_risk_coins`]), not yet refreshed in a round.
	fn out_of_round(&self) -> Result<BTreeMap<AssetId, u64>, Error> {
		let mut out: BTreeMap<AssetId, u64> = BTreeMap::new();
		for c in self.at_risk_coins()? {
			let a = AssetId::from_str(&c.asset).map_err(|e| Error::Store(e.to_string()))?;
			*out.entry(a).or_default() = out.get(&a).copied().unwrap_or(0).saturating_add(c.value);
		}
		Ok(out)
	}

	/// The coins the wallet holds at risk out of round ([`Self::at_risk`]):
	/// what [`Self::out_of_round`] sums, and what `coin_places` names
	/// (`at_risk`).
	pub(crate) fn at_risk_coins(&self) -> Result<Vec<super::store::CoinRow>, Error> {
		let coins = self.store.coins_in_states(&HELD)?;
		let in_round = if coins.iter().any(|c| c.state == "given") { self.given_to_rounds()? } else { BTreeSet::new() };
		let mut out = vec![];
		for c in coins {
			if HELD.contains(&c.state.as_str()) && self.at_risk(&c, &in_round)? {
				out.push(c);
			}
		}
		Ok(out)
	}

	/// The coins a participation the wallet keeps open gives up, by leaf id:
	/// one not yet released, withdrawn, refused or lost.
	fn given_to_rounds(&self) -> Result<BTreeSet<String>, Error> {
		let mut out = BTreeSet::new();
		for (_, _, given, ..) in self.store.participations_not_in(&["released", "withdrawn", "refused", "lost"])? {
			let given: Vec<String> = serde_json::from_str(&given).map_err(|e| Error::Store(e.to_string()))?;
			out.extend(given);
		}
		Ok(out)
	}

	/// Whether the coin `c` is at risk out of round: whether the operator,
	/// with someone other than the wallet, could take it from the wallet by
	/// signing a second spend. `in_round` holds the coins open
	/// participations give up ([`Self::given_to_rounds`]).
	///
	/// - A coin of `received` lineage ([`super::places::Lineage`]): a
	///   payment received, or what a trade paid the wallet (change included)
	///   when some checkpoint of the trade has no owner's exit, is at risk at
	///   its whole value: another input's owner and the operator can spend it
	///   elsewhere, and every coin the reassignment made is void.
	/// - A coin of the wallet's own lineage (a round's or a board's, or its
	///   own change from paying out of one) is not: only the wallet's key
	///   spends it. Nor is a coin of `trade` lineage: what a trade with its
	///   owner's exit on every checkpoint paid the wallet. Should that trade
	///   die, the coin the wallet gave comes home by its exit.
	/// - A coin given to a round participation (`given`, and one of `in_round`)
	///   is judged by its own lineage, as while it is live. Over the coin the
	///   wallet signs digests under the participation's own tags (its
	///   attestation, a withdrawal, a decline), none of which spends it, and
	///   its forfeit, as for every coin given up in a round: to the operator
	///   alone and claimable only with that round's connector, whether signed
	///   once the round is final (the coin is then `forfeited`, judged so
	///   already) or before the round is broadcast, for an operator with
	///   `forfeits_before_broadcast` (a round then lost leaves the coin
	///   `given` with its forfeit signed).
	///   Nothing in a round gives another party a key to the coin's lineage.
	/// - A coin on its way into a swap or a fill (`offered`, `sending`, or a
	///   `given` coin no open participation names) whose checkpoint has its
	///   owner's exit is judged by its own lineage: if the trade never
	///   completes, the coin comes home by that exit. One whose checkpoint has
	///   none counts as a coin received out of round does, as it always has:
	///   should the trade die, it would stand in a checkpoint only the wallet
	///   and the operator can spend.
	fn at_risk(&self, c: &super::store::CoinRow, in_round: &BTreeSet<String>) -> Result<bool, Error> {
		let paid_out = c.kind == "transfer" || c.kind == "fill";
		let to_round = c.state == "given" && in_round.contains(&c.leaf_id);
		if matches!(c.state.as_str(), "offered" | "sending" | "given") && !to_round && !self.given_with_exit(c)? {
			return Ok(paid_out);
		}
		if !paid_out {
			return Ok(false);
		}
		let record = Self::record_of(c)?;
		Ok(self.lineage(&record) == super::places::Lineage::Received)
	}

	/// Whether the coin `c`, on its way into a swap, goes into a checkpoint
	/// with its owner's exit: its swap's acceptance signs so. A swap not yet
	/// accepted, and a fill, count as one without.
	fn given_with_exit(&self, c: &super::store::CoinRow) -> Result<bool, Error> {
		let Some(id) = c.note.strip_prefix("swap ") else { return Ok(false) };
		Ok(match self.store.swap(id)? {
			Some((_, _, Some(accept), _)) => serde_json::from_str::<Value>(&accept).is_ok_and(|a| a["checkpoint_exit"] == json!(true)),
			_ => false,
		})
	}

	/// `held` worth more than the bond's `value` of `asset`, and by how much,
	/// in the reference unit at the wallet's node's rates (in atoms where all
	/// is one asset). A value the node cannot price is refused, never guessed.
	fn exceeds(&self, held: &BTreeMap<AssetId, u64>, asset: AssetId, value: u64) -> Result<Option<String>, Error> {
		if held.keys().all(|a| *a == asset) {
			let h = held.get(&asset).copied().unwrap_or(0);
			return Ok((h > value).then(|| format!("{} atoms of asset {}, more than the bond's {}", h, asset, value)));
		}
		let rates = self.chain.fee_rates()?;
		let worth = |a: &AssetId, v: u64| -> Result<u128, Error> {
			let r = rates.get(a).ok_or_else(|| Error::Refused(format!("this wallet's node has no rate for asset {}, so it cannot weigh \
				what it holds out of round against the operator's bond; it takes no payment out of round until it can", a)))?;
			Ok(v as u128 * *r as u128 / 100_000_000)
		};
		let mut h = 0u128;
		for (a, v) in held {
			h += worth(a, *v)?;
		}
		let b = worth(&asset, value)?;
		Ok((h > b).then(|| format!("{} atoms of the reference unit at this node's rates, more than the bond's {}", h, b)))
	}

	/// Sets the wallet's instant budget: the share of the bond's value, in
	/// millionths (more than 0, at most 1,000,000), that it holds out of round
	/// at most; `None` sets none. See the [module documentation](self).
	pub fn set_instant_budget(&self, ppm: Option<u32>) -> Result<Value, Error> {
		match ppm {
			Some(p) if p == 0 || p > 1_000_000 => return Err(Error::Parse(format!(
				"an instant budget of {} millionths is not a share of the bond, more than 0 and at most 1,000,000", p))),
			Some(p) => self.store.set_meta(INSTANT_BUDGET, &p.to_string())?,
			None => self.store.set_meta(INSTANT_BUDGET, "")?,
		}
		Ok(json!({"instant_budget_ppm": ppm}))
	}

	/// [`Self::set_instant_budget`] from a share written as a decimal
	/// fraction (`"0.1"`), or `"off"`.
	pub fn set_instant_budget_text(&self, share: &str) -> Result<Value, Error> {
		if share == "off" {
			return self.set_instant_budget(None);
		}
		let f: f64 = share.parse().map_err(|_| Error::Parse(format!("an instant budget of {:?}: a share of the bond such as 0.1, or off", share)))?;
		if !(f > 0.0 && f <= 1.0) {
			return Err(Error::Parse(format!("an instant budget of {}: a share of the bond more than 0 and at most 1", share)));
		}
		self.set_instant_budget(Some(((f * 1_000_000.0).round() as u32).max(1)))
	}

	/// The instant budget the wallet set, in millionths of the bond.
	fn own_budget_ppm(&self) -> Result<Option<u32>, Error> {
		Ok(self.store.meta(INSTANT_BUDGET)?.and_then(|v| v.parse::<u32>().ok()).filter(|p| *p > 0 && *p <= 1_000_000))
	}

	/// The instant budget against a standing bond of `value` of `asset`, and
	/// what `held` is worth, both in the reference unit at the wallet's
	/// node's rates: `None` while the wallet sets no budget. The share is the
	/// lower of the wallet's own and the operator's suggestion. A value the
	/// node cannot price is refused, never guessed.
	fn budget(&self, info: &Value, held: &BTreeMap<AssetId, u64>, asset: AssetId, value: u64) -> Result<Option<Budget>, Error> {
		let Some(own) = self.own_budget_ppm()? else { return Ok(None) };
		let operator = info["bond"]["instant_budget_ppm"].as_u64().and_then(|p| u32::try_from(p).ok()).filter(|p| *p > 0);
		let ppm = operator.map_or(own, |o| o.min(own));
		let rates = self.chain.fee_rates()?;
		let worth = |a: &AssetId, v: u64| -> Result<u128, Error> {
			let r = rates.get(a).ok_or_else(|| Error::Refused(format!("this wallet's node has no rate for asset {}, so it cannot weigh \
				what it holds out of round against its instant budget; it takes no payment out of round until it can", a)))?;
			Ok(v as u128 * *r as u128 / 100_000_000)
		};
		let bond = worth(&asset, value)?;
		let mut h = 0u128;
		for (a, v) in held {
			h += worth(a, *v)?;
		}
		let value = bond * ppm as u128 / 1_000_000;
		// The room left in each asset the node prices, in its own atoms (rounded down).
		let room = value.saturating_sub(h);
		let room_atoms = rates.iter().filter(|(_, r)| **r > 0)
			.map(|(a, r)| (*a, (room * 100_000_000 / *r as u128).min(u64::MAX as u128) as u64)).collect();
		Ok(Some(Budget { own_ppm: own, operator_ppm: operator, ppm, bond, value, held: h, room_atoms }))
	}

	/// The bond's check before the wallet takes a payment out of round of
	/// `incoming` (the asset and amount, when the request names them): `Ok`
	/// with a note when the operator names no bond and the wallet never saw
	/// one; a refusal when the bond is required and does not stand, or does
	/// not cover what the wallet would hold out of round.
	pub(crate) fn bond_gate(&self, incoming: Option<(AssetId, u64)>) -> Result<Option<String>, Error> {
		// A wallet with an instant limit ([`super::places`]) never refuses a
		// payment here: what it counts at once is within its limit, and
		// anything past it, or that it cannot value, arrives and counts only
		// after its round, so the bond is the safety of nothing above the
		// limit. The refusal is said instead.
		let gate = self.bond_gate_strict(incoming);
		if self.own_instant_limit()?.is_some() {
			if let Err(Error::Refused(why)) = &gate {
				return Ok(Some(format!("{}; with an instant limit the payment is taken, and counts once its round has made it the \
					wallet's own", why)));
			}
		}
		gate
	}

	/// [`Self::bond_gate`] without an instant limit.
	fn bond_gate_strict(&self, incoming: Option<(AssetId, u64)>) -> Result<Option<String>, Error> {
		let info = self.server_info()?;
		let s = self.bond_standing(&info)?;
		let seen = self.store.meta(BOND_SEEN)?.is_some();
		if s.state == "none" && !seen {
			return Ok(Some("this operator posts no bond: a payment out of round rests on its sender and the operator not colluding, \
				until the coin is refreshed in a round".into()));
		}
		if s.state != "bonded" {
			if s.state != "none" || seen {
				self.store.set_meta(BOND_SEEN, &json!({"why": "required"}).to_string())?;
			}
			return Err(Error::Refused(format!("the operator's bond is {}: {}; the wallet takes no payment out of round from an operator \
				whose bond does not stand", if s.state == "none" { "gone" } else { s.state }, s.why)));
		}
		let (asset, value) = (s.asset.expect("bonded"), s.value.expect("bonded"));
		if !seen {
			let (op, _) = s.coin.as_ref().expect("bonded");
			self.store.set_meta(BOND_SEEN, &json!({"outpoint": format!("{}:{}", op.txid, op.vout)}).to_string())?;
		}
		let mut held = self.out_of_round()?;
		if let Some((a, v)) = incoming {
			*held.entry(a).or_default() = held.get(&a).copied().unwrap_or(0).saturating_add(v);
		}
		if let Some(why) = self.exceeds(&held, asset, value)? {
			return Err(Error::Refused(format!("with this payment the wallet would hold out of round {}: a double-sign would pay the \
				operator more than its bond costs it; have coins refreshed in a round first", why)));
		}
		if let Some(b) = self.budget(&info, &held, asset, value)? {
			if b.held > b.value {
				return Err(Error::Refused(format!("with this payment the wallet would hold out of round {} atoms of the reference unit at \
					this node's rates, past its instant budget of {} ({} millionths of the bond's {}): it takes the rest after the next round, \
					once what it holds is refreshed", b.held, b.value, b.ppm, b.bond)));
			}
		}
		Ok(None)
	}

	/// What the wallet holds out of round against the most it may hold, both
	/// in the reference unit at its node's rates, over every asset: its
	/// instant budget when it sets one, else the bond's whole value. The
	/// assets the node does not price are named apart (`unpriced`), the
	/// bond's own among them when the node has no rate for it (then `limit`
	/// is 0): they cannot be weighed, so a caller treats them as past any
	/// share. `None` while the operator posts no bond, or its bond does not
	/// stand (`sync` then refreshes every such coin by itself,
	/// [`Self::uncovered`]).
	pub(crate) fn exposure(&self) -> Result<Option<Exposure>, Error> {
		let info = self.server_info()?;
		let s = self.bond_standing(&info)?;
		if s.state != "bonded" {
			return Ok(None);
		}
		let (asset, value) = (s.asset.expect("bonded"), s.value.expect("bonded"));
		let rates = self.chain.fee_rates()?;
		let mut unpriced = vec![];
		let bond = match rates.get(&asset) {
			Some(rate) => value as u128 * *rate as u128 / 100_000_000,
			None => {
				unpriced.push(asset.to_string());
				0
			},
		};
		let operator = info["bond"]["instant_budget_ppm"].as_u64().and_then(|p| u32::try_from(p).ok()).filter(|p| *p > 0);
		let limit = match self.own_budget_ppm()? {
			Some(own) => bond * operator.map_or(own, |o| o.min(own)) as u128 / 1_000_000,
			None => bond,
		};
		let mut held = 0u128;
		for (a, v) in self.out_of_round()? {
			match rates.get(&a) {
				Some(r) => held += v as u128 * *r as u128 / 100_000_000,
				None if !unpriced.contains(&a.to_string()) => unpriced.push(a.to_string()),
				None => {},
			}
		}
		Ok(Some(Exposure { held, limit, unpriced }))
	}

	/// The coins that rest on an out-of-round lineage while the operator's
	/// bond does not stand or does not cover them: `sync` asks for their
	/// refresh at once. Empty while the operator never named a bond and the
	/// wallet never saw one.
	pub(crate) fn uncovered(&self) -> Result<Vec<String>, Error> {
		let held = self.out_of_round()?;
		if held.is_empty() {
			return Ok(vec![]);
		}
		let info = match self.server_info() {
			Ok(i) => i,
			Err(_) => return Ok(vec![]),
		};
		// A node or an operator that does not answer holds back no refresh
		// the coin's own dates ask for: the next sync looks again.
		let s = match self.bond_standing(&info) {
			Ok(s) => s,
			Err(_) => return Ok(vec![]),
		};
		if s.state == "none" && self.store.meta(BOND_SEEN)?.is_none() {
			return Ok(vec![]);
		}
		let covered = s.state == "bonded" && self.exceeds(&held, s.asset.expect("bonded"), s.value.expect("bonded")).ok().flatten().is_none()
			&& self.budget(&info, &held, s.asset.expect("bonded"), s.value.expect("bonded")).ok().flatten().is_none_or(|b| b.held <= b.value);
		if covered {
			return Ok(vec![]);
		}
		Ok(self.store.coins_in("live")?.into_iter()
			.filter(|c| (c.kind == "transfer" || c.kind == "fill") && c.state == "live")
			.map(|c| c.leaf_id).collect())
	}

	/// `arca bond`: the operator's bond as this wallet checks it, and what
	/// the wallet holds out of round against it.
	pub fn bond(&self) -> Result<Value, Error> {
		let info = self.server_info()?;
		let s = self.bond_standing(&info)?;
		if s.state == "bonded" && self.store.meta(BOND_SEEN)?.is_none() {
			let (op, _) = s.coin.as_ref().expect("bonded");
			self.store.set_meta(BOND_SEEN, &json!({"outpoint": format!("{}:{}", op.txid, op.vout)}).to_string())?;
		}
		let held = self.out_of_round()?;
		let covers = match (s.state, s.asset, s.value) {
			("bonded", Some(a), Some(v)) => match self.exceeds(&held, a, v) {
				Ok(None) => json!(true),
				Ok(Some(why)) => json!(format!("no: {}", why)),
				Err(e) => json!(format!("no: {}", e)),
			},
			_ => json!(false),
		};
		let budget = match (s.state, s.asset, s.value) {
			("bonded", Some(a), Some(v)) => match self.budget(&info, &held, a, v) {
				Ok(Some(b)) => json!({"ppm": b.ppm, "own_ppm": b.own_ppm, "operator_ppm": b.operator_ppm, "bond_value": b.bond.to_string(),
					"value": b.value.to_string(), "held_value": b.held.to_string(), "room": b.value.saturating_sub(b.held).to_string(),
					"room_atoms": b.room_atoms.iter().map(|(a, v)| (a.to_string(), json!(v.to_string()))).collect::<serde_json::Map<_, _>>()}),
				Ok(None) => Value::Null,
				Err(e) => json!({"error": e.to_string()}),
			},
			_ => match self.own_budget_ppm()? {
				Some(p) => json!({"ppm": p, "own_ppm": p, "value": "0", "room": "0"}),
				None => Value::Null,
			},
		};
		Ok(json!({
			"state": s.state, "why": s.why, "required": self.store.meta(BOND_SEEN)?.is_some(),
			"coin": s.coin.as_ref().map(|(op, _)| format!("{}:{}", op.txid, op.vout)),
			"asset": s.asset.map(|a| a.to_string()), "value": s.value.map(|v| v.to_string()), "withdrawable_at": s.withdrawable_at,
			"out_of_round": held.iter().map(|(a, v)| json!({"asset": a.to_string(), "value": v.to_string()})).collect::<Vec<_>>(),
			"covers": covers, "instant_budget": budget,
		}))
	}

	/// Every message the operator key signed that the wallet's coins rest
	/// on, as evidence lines: what the wallet hands a watcher.
	pub fn bond_evidence(&self) -> Result<Vec<Value>, Error> {
		Ok(self.evidence_by_coin()?.0.into_iter().map(|(line, _, _)| line).collect())
	}

	/// The evidence of every coin the wallet holds or held out of round:
	/// each line its operator co-signed under a salt, with the base
	/// transactions and root outputs of the coin's lineage. A coin's record
	/// never changes, so what it yields is kept in the store by its leaf id
	/// ([`EVIDENCE_KEY`]) once read, and read again only for coins not kept
	/// yet: at most for [`SCAN_SLICE`] a call, the rest at the next, so a
	/// wallet of a long history is never held for minutes ahead of a
	/// person's command. Answers the evidence and how many coins are left
	/// unread (their salts are watched from their own base once read, as a
	/// salt new to a run always is).
	fn evidence_by_coin(&self) -> Result<(Vec<(Value, Vec<Txid>, Vec<OutPoint>)>, usize), Error> {
		let now = self.now()?;
		let started = web_time::Instant::now();
		let mut seen: BTreeMap<([u8; 32], Vec<u8>), usize> = BTreeMap::new();
		let mut out: Vec<(Value, Vec<Txid>, Vec<OutPoint>)> = vec![];
		let mut left = 0usize;
		let mut keep: Vec<(String, String)> = vec![];
		for c in self.store.coins()? {
			if c.kind != "transfer" && c.kind != "fill" {
				continue;
			}
			let key = format!("{}{}", EVIDENCE_KEY, c.leaf_id);
			let kept: Option<Value> = self.store.meta(&key)?.and_then(|v| serde_json::from_str(&v).ok());
			let (lines, bases, roots): (Vec<Value>, Vec<Txid>, Vec<OutPoint>) = match kept {
				Some(k) => {
					let lines = k["lines"].as_array().cloned().unwrap_or_default();
					let bases = k["bases"].as_array().into_iter().flatten().filter_map(|t| t.as_str().and_then(|t| Txid::from_str(t).ok())).collect();
					let roots = k["roots"].as_array().into_iter().flatten().filter_map(|o| o.as_str().and_then(|o| OutPoint::from_str(o).ok())).collect();
					(lines, bases, roots)
				},
				None => {
					if started.elapsed() >= SCAN_SLICE {
						left += 1;
						continue;
					}
					let Ok(record) = Self::record_of(&c) else { continue };
					let Ok(txs) = self.base_txs(&record) else { continue };
					let policy: WalletPolicy = self.followed_policy(c.expiry, now);
					let Ok(valid) = self.resolve(&record, &txs, &policy) else { continue };
					let bases: Vec<Txid> = txs.iter().map(|t| t.txid()).collect();
					let roots = valid.roots();
					let lines: Vec<Value> = bond::cosigned_by(&valid).iter().map(|e| evidence_line(&e.salt, &e.signed)).collect();
					keep.push((key, json!({"lines": lines, "bases": bases.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
						"roots": roots.iter().map(|o| o.to_string()).collect::<Vec<_>>()}).to_string()));
					(lines, bases, roots)
				},
			};
			for line in lines {
				let Ok((salt, signed)) = read_line(&line) else { continue };
				match seen.get(&(salt, signed.rest.clone())) {
					Some(&i) => {
						out[i].1.extend(bases.iter().copied());
						out[i].2.extend(roots.iter().copied());
					},
					None => {
						seen.insert((salt, signed.rest.clone()), out.len());
						out.push((line, bases.clone(), roots.clone()));
					},
				}
			}
		}
		if !keep.is_empty() {
			let entries: Vec<(&str, String)> = keep.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
			self.store.set_metas(&entries)?;
		}
		Ok((out, left))
	}

	/// The lowest height of a block that holds one of `bases`; past the tip
	/// while none is in a block, as nothing that spends what they made can
	/// be in one either.
	fn lowest_block(&self, bases: &[Txid], tip: u64) -> Result<u64, Error> {
		let mut lowest = tip.saturating_add(1);
		for t in bases {
			if let Some((_, h)) = self.chain.tx_block(t)? {
				lowest = lowest.min(h);
			}
		}
		Ok(lowest)
	}

	/// `arca watch-bond`: see the [module documentation](self). `lines` are
	/// evidence lines handed to the wallet by others; `fee_asset` the asset a
	/// slash's fee is paid in (the bond's own first, as for an exit).
	pub fn watch_bond(&mut self, lines: &[Value], fee_asset: Option<AssetId>) -> Result<Value, Error> {
		let info = self.server_info()?;
		let s = self.bond_standing(&info)?;
		let Some(policy) = s.policy else {
			return Ok(json!({"state": s.state, "why": s.why, "slashed": []}));
		};
		// Every line counts only when the operator key signed it.
		let mut by_salt: BTreeMap<[u8; 32], Vec<Signed>> = BTreeMap::new();
		let (mut good, mut bad) = (0usize, 0usize);
		let (own, unread) = self.evidence_by_coin()?;
		// The signatures read from the chain and the mempool before: kept, so
		// a stretch of the chain noted as read is never read again.
		let mut found: Vec<Value> = self.store.meta(BOND_FOUND)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		// The transactions each of the wallet's own salts rests on: its
		// spends are in no block before theirs.
		let mut bases: BTreeMap<[u8; 32], Vec<Txid>> = BTreeMap::new();
		// And the outputs on the chain they descend from: a spend under the
		// salt is made only by spends that start at one of them.
		let mut roots: BTreeMap<[u8; 32], Vec<OutPoint>> = BTreeMap::new();
		let tagged = own.iter().map(|(v, b, r)| (v, Some((b, r)))).chain(lines.iter().chain(found.iter()).map(|v| (v, None)));
		for (v, b) in tagged {
			match read_line(v) {
				Ok((salt, signed)) if policy.verify(&salt, &signed) => {
					if let Some((b, r)) = b {
						bases.entry(salt).or_default().extend(b.iter().copied());
						roots.entry(salt).or_default().extend(r.iter().copied());
					}
					let list = by_salt.entry(salt).or_default();
					if !list.iter().any(|x| policy.digest_of(&salt, x) == policy.digest_of(&salt, &signed)) {
						list.push(signed);
					}
					good += 1;
				},
				_ => bad += 1,
			}
		}
		let mut from_chain = 0usize;
		let scanned = if by_salt.is_empty() {
			// No salt to watch: no block is read, and none is noted as read,
			// so the first coin the wallet takes is watched from its own base.
			json!({"from": null, "to": null, "blocks": 0, "mempool": false})
		} else {
			// The chain and the mempool: every spend of a script that pushes a
			// watched salt's K (or K ‖ P). A salt read before is read on from
			// where the last run stopped; a new one from the block of the
			// oldest transaction its coins rest on, a salt handed in by
			// another from `FIRST_SCAN` blocks back, and none further back.
			let ks: BTreeMap<[u8; 32], [u8; 32]> = by_salt.keys().map(|salt| (policy.chain.leaf_constant(salt), *salt)).collect();
			let tip = self.chain.tip()?.height;
			let oldest = tip.saturating_sub(FIRST_SCAN);
			let read_to = self.store.meta(BOND_SCANNED)?.and_then(|v| v.parse::<u64>().ok());
			let covered: BTreeSet<String> = match (read_to, self.store.meta(BOND_SALTS)?) {
				(None, _) => BTreeSet::new(),
				(Some(_), Some(v)) => serde_json::from_str(&v).unwrap_or_default(),
				// Read to a height by a wallet that noted no salts: the salts
				// it watches now are the ones it read for.
				(Some(_), None) => by_salt.keys().map(|s| hex(s)).collect(),
			};
			let mut from = tip.saturating_add(1);
			for salt in by_salt.keys() {
				let start = match read_to.filter(|_| covered.contains(&hex(salt))) {
					Some(h) => h.saturating_add(1),
					None => match bases.get(salt) {
						// The wallet's own salt: while every output its coins
						// descend from stands, nothing spends under it, and no
						// block is read for it; else from the block of a spent
						// one.
						Some(b) => {
							let lowest = self.lowest_block(b, tip)?;
							match self.chain.descendants_from(roots.get(salt).map(|r| r.as_slice()).unwrap_or(&[]), lowest)? {
								None if roots.get(salt).is_some_and(|r| !r.is_empty()) => tip.saturating_add(1),
								None => lowest,
								Some(h) => h.max(lowest),
							}
						},
						None => oldest,
					},
				};
				from = from.min(start.max(oldest));
			}
			let mut salts = covered;
			salts.extend(by_salt.keys().map(|s| hex(s)));
			let salts = serde_json::to_string(&salts).expect("a set");
			// A chunk at a time: its spends read, and what they show kept,
			// before its last height is noted, so a scan cut short goes on
			// from there. A salt new to this run lowers the note for the
			// others while its chunks below it are read: they are read
			// again, never skipped.
			// Each run reads for [`SCAN_SLICE`] at most, many blocks a
			// request, and says when more is left: the wallet is held while it
			// runs, and a person's command waits behind it.
			let started = web_time::Instant::now();
			let mut blocks = 0u64;
			let mut h = from;
			let mut more = false;
			while h <= tip {
				if blocks > 0 && started.elapsed() >= SCAN_SLICE {
					more = true;
					break;
				}
				let end = h.saturating_add(SCAN_CHUNK - 1).min(tip);
				let mut txs: Vec<Transaction> = vec![];
				self.chain.each_block_to(h, end, |_, b| {
					txs.extend(b.txdata.into_iter().skip(1));
					blocks += 1;
					Ok(false)
				})?;
				let new = self.read_spends(&txs, &policy, &ks, &mut by_salt)?;
				from_chain += self.keep_found(new, &mut found)?;
				self.store.set_meta(BOND_SALTS, &salts)?;
				self.store.set_meta(BOND_SCANNED, &end.to_string())?;
				h = end + 1;
			}
			if from > tip {
				self.store.set_meta(BOND_SALTS, &salts)?;
				self.store.set_meta(BOND_SCANNED, &tip.to_string())?;
			}
			let txs = self.chain.mempool_txs()?;
			let new = self.read_spends(&txs, &policy, &ks, &mut by_salt)?;
			from_chain += self.keep_found(new, &mut found)?;
			json!({"from": if from > tip { Value::Null } else { json!(from) }, "to": if more { json!(h - 1) } else { json!(tip) }, "blocks": blocks,
				"mempool": true, "more": more})
		};
		let conflicts: Vec<Evidence> = by_salt.iter().filter(|(_, l)| l.len() > 1)
			.map(|(salt, l)| Evidence { salt: *salt, a: l[0].clone(), b: l[1].clone() }).collect();
		// A slash for the first conflict, if the bond still stands and no
		// slash sent before spends it, and every slash sent before again
		// until final: the signatures read from the chain are kept, so the
		// conflict is found again on every run while the first slash waits.
		let mut slashes: BTreeMap<String, String> = self.store.meta(BOND_SLASHES)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		let spent_by_a_slash = |op: &OutPoint| slashes.values().any(|raw| unhex(raw).ok()
			.and_then(|b| elements::encode::deserialize::<Transaction>(&b).ok())
			.is_some_and(|t| t.input.iter().any(|i| i.previous_output == *op)));
		let bond_coin = s.coin.clone().filter(|(op, _)| !spent_by_a_slash(op));
		let mut slashed = vec![];
		if let (Some(e), Some((op, out))) = (conflicts.first(), bond_coin) {
			policy.check(e).map_err(|x| Error::Refused(x.to_string()))?;
			let mut payer = Payer::new(fee_asset);
			payer.moved = s.asset;
			let coins = [(op, out)];
			let u = self.with_fee(&mut payer, &|f| policy.slash_tx(&coins, e, f).map_err(|x| Error::Refused(x.to_string())))?;
			let txid = self.chain.broadcast(&u.tx)?;
			slashes.insert(txid.to_string(), hex(&elements::encode::serialize(&u.tx)));
			slashed.push(json!({"txid": txid.to_string(), "burned": s.value.map(|v| v.to_string()), "asset": s.asset.map(|a| a.to_string()),
				"salt": hex(&e.salt)}));
		}
		let mut resent = vec![];
		for (txid, raw) in &slashes {
			let t = Txid::from_str(txid).map_err(|e| Error::Store(e.to_string()))?;
			if self.chain.finality(&t)?.is_final() {
				continue;
			}
			if let Ok(tx) = elements::encode::deserialize::<Transaction>(&unhex(raw)?) {
				resent.push(json!({"txid": txid, "sent": self.chain.broadcast(&tx).map(|t| t.to_string()).map_err(|e| e.to_string()).is_ok()}));
			}
		}
		self.store.set_meta(BOND_SLASHES, &serde_json::to_string(&slashes).expect("a map"))?;
		Ok(json!({
			"state": s.state, "why": s.why, "evidence": {"lines": good, "refused": bad, "from_chain": from_chain, "salts": by_salt.len(), "unread": unread},
			"scanned": scanned,
			"conflicts": conflicts.iter().map(|e| json!({"salt": hex(&e.salt), "a": evidence_line(&e.salt, &e.a), "b": evidence_line(&e.salt, &e.b)}))
				.collect::<Vec<_>>(),
			"slashed": slashed, "resent": resent,
		}))
	}

	/// The operator's signatures under a watched salt that `txs` show and
	/// `by_salt` did not hold yet: each added to it, and answered.
	fn read_spends(&self, txs: &[Transaction], policy: &BondPolicy, ks: &BTreeMap<[u8; 32], [u8; 32]>,
		by_salt: &mut BTreeMap<[u8; 32], Vec<Signed>>) -> Result<Vec<([u8; 32], Signed)>, Error> {
		let mut found = vec![];
		for tx in txs {
			for (i, input) in tx.input.iter().enumerate() {
				// The items without an annex (BIP341), which the operator's
				// signature does not cover: a spend with one is the same.
				let w = arca_covenant::witness::without_annex(&input.witness.script_witness);
				// A vtxo-2 spend (arca/collab-2) names its salt in its data
				// leaf's bytes and signs the outputs its first n inputs spend,
				// read from the node.
				if let Some((salt, n, _)) = bond::collab2_spend(w).filter(|(salt, ..)| by_salt.contains_key(salt)) {
					let mut named = Vec::with_capacity(n as usize);
					for j in tx.input.iter().take(n as usize) {
						let prev = self.chain.transaction(&j.previous_output.txid)?
							.and_then(|t| t.output.get(j.previous_output.vout as usize).cloned());
						match prev {
							Some(o) => named.push(o),
							None => break,
						}
					}
					if let Some(signed) = bond::collab2_signed_in(&policy.chain, &salt, tx, i, &named) {
						if policy.verify(&salt, &signed) {
							let list = by_salt.get_mut(&salt).expect("watched");
							if !list.iter().any(|x| policy.digest_of(&salt, x) == policy.digest_of(&salt, &signed)) {
								list.push(signed.clone());
								found.push((salt, signed));
							}
						}
					}
					continue;
				}
				if w.len() != 5 {
					continue;
				}
				let script = elements::Script::from(w[3].clone());
				for ins in script.instructions().flatten() {
					let elements::script::Instruction::PushBytes(p) = ins else { continue };
					let Some(salt) = watched_push(p, &ks) else { continue };
					let Some((asset, value)) = by_salt[salt].iter().find(|x| x.form == Form::Rebind).and_then(|x| coin_of_rest(&x.rest)) else {
						continue;
					};
					let prevout = TxOut::new_fee(value, asset);
					if let Some(signed) = bond::rebind_signed_in(&policy.chain, salt, tx, i, &prevout) {
						if policy.verify(salt, &signed) {
							let list = by_salt.get_mut(salt).expect("watched");
							if !list.iter().any(|x| policy.digest_of(salt, x) == policy.digest_of(salt, &signed)) {
								list.push(signed.clone());
								found.push((*salt, signed));
							}
						}
					}
				}
			}
		}
		Ok(found)
	}

	/// Keeps `new`, signatures read from the chain or the mempool, among
	/// `found` and in the store; answers how many.
	fn keep_found(&self, new: Vec<([u8; 32], Signed)>, found: &mut Vec<Value>) -> Result<usize, Error> {
		if !new.is_empty() {
			found.extend(new.iter().map(|(salt, signed)| evidence_line(salt, signed)));
			self.store.set_meta(BOND_FOUND, &serde_json::to_string(found).expect("lines"))?;
		}
		Ok(new.len())
	}
}

/// `txid:vout`.
pub fn parse_outpoint(s: &str) -> Result<OutPoint, Error> {
	let (t, v) = s.split_once(':').ok_or_else(|| Error::Parse(format!("{:?} is not txid:vout", s)))?;
	Ok(OutPoint::new(Txid::from_str(t).map_err(|e| Error::Parse(e.to_string()))?, v.parse().map_err(|_| Error::Parse(format!("vout {:?}", v)))?))
}

#[cfg(test)]
mod test {
	use super::*;
	use arca_covenant::message::rebind_message;
	use arca_covenant::ExplicitOutput;

	fn rest_of(k: &[u8], asset: AssetId, value: u64, m: usize) -> Vec<u8> {
		let outs: Vec<ExplicitOutput> = (0..m).map(|i| ExplicitOutput::new(asset, 1_000 + i as u64, elements::Script::from(vec![0x51]))).collect();
		rebind_message(k, asset, value, &outs).unwrap().preimage[32..].to_vec()
	}

	#[test]
	fn a_rest_names_its_coin_with_or_without_a_landing_program() {
		let asset = AssetId::from_byte_array([9; 32]);
		let k = [3u8; 32];
		let mut kp = k.to_vec();
		kp.extend([0xab; arca_covenant::landing::PROGRAM_BYTES]);
		for m in [1, 2, 4] {
			assert_eq!(coin_of_rest(&rest_of(&k, asset, 77_000, m)), Some((asset, 77_000)), "a plain rest of {} outputs", m);
			assert_eq!(coin_of_rest(&rest_of(&kp, asset, 77_000, m)), Some((asset, 77_000)), "a landing rest of {} outputs", m);
		}
		let mut cut = rest_of(&k, asset, 77_000, 2);
		cut.pop();
		assert_eq!(coin_of_rest(&cut), None, "a rest one byte short names nothing");
		assert_eq!(coin_of_rest(&[]), None);
	}

	#[test]
	fn a_push_names_a_watched_salt_as_k_or_as_k_and_a_landing_program() {
		let (k, salt) = ([3u8; 32], [4u8; 32]);
		let ks: BTreeMap<[u8; 32], [u8; 32]> = [(k, salt)].into_iter().collect();
		let mut kp = k.to_vec();
		kp.extend([0xab; arca_covenant::landing::PROGRAM_BYTES]);
		assert_eq!(watched_push(&k, &ks), Some(&salt));
		assert_eq!(watched_push(&kp, &ks), Some(&salt));
		assert_eq!(watched_push(&kp[..40], &ks), None, "another length");
		assert_eq!(watched_push(&[5u8; 32], &ks), None, "another K");
	}
}
