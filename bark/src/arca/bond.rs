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
//! The wallet keeps the operator's signature over every message of its
//! coins' lineage ([`arca_covenant::bond::cosigned_by`]) and writes it as
//! evidence lines ([`Wallet::bond_evidence`]): `{"salt", "form", "rest",
//! "signature"}`. [`Wallet::watch_bond`] takes its own and any other's, counts
//! only those whose signature the operator key made, compares them under each
//! salt, and reads every spend on the chain and in the mempool of a script
//! that carries a watched salt's `K`. Two different messages under one salt
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
/// How far back the first `watch-bond` reads the chain.
pub const FIRST_SCAN: u64 = 20_000;

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
/// `landing-1` leaf's landing program where the leaf is one
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
/// `K`, or a `landing-1` leaf's `K ‖ P`.
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

	/// What the wallet holds on lineages paid out of round, by asset: its
	/// coins received by a reassignment or an in-tree fill, not yet refreshed
	/// in a round.
	fn out_of_round(&self) -> Result<BTreeMap<AssetId, u64>, Error> {
		let mut out: BTreeMap<AssetId, u64> = BTreeMap::new();
		for c in self.store.coins()? {
			if (c.kind == "transfer" || c.kind == "fill") && HELD.contains(&c.state.as_str()) {
				let a = AssetId::from_str(&c.asset).map_err(|e| Error::Store(e.to_string()))?;
				*out.entry(a).or_default() = out.get(&a).copied().unwrap_or(0).saturating_add(c.value);
			}
		}
		Ok(out)
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

	/// The bond's check before the wallet takes a payment out of round of
	/// `incoming` (the asset and amount, when the request names them): `Ok`
	/// with a note when the operator names no bond and the wallet never saw
	/// one; a refusal when the bond is required and does not stand, or does
	/// not cover what the wallet would hold out of round.
	pub(crate) fn bond_gate(&self, incoming: Option<(AssetId, u64)>) -> Result<Option<String>, Error> {
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
		Ok(None)
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
		let covered = s.state == "bonded" && self.exceeds(&held, s.asset.expect("bonded"), s.value.expect("bonded")).ok().flatten().is_none();
		if covered {
			return Ok(vec![]);
		}
		Ok(self.store.coins()?.into_iter()
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
		Ok(json!({
			"state": s.state, "why": s.why, "required": self.store.meta(BOND_SEEN)?.is_some(),
			"coin": s.coin.as_ref().map(|(op, _)| format!("{}:{}", op.txid, op.vout)),
			"asset": s.asset.map(|a| a.to_string()), "value": s.value.map(|v| v.to_string()), "withdrawable_at": s.withdrawable_at,
			"out_of_round": held.iter().map(|(a, v)| json!({"asset": a.to_string(), "value": v.to_string()})).collect::<Vec<_>>(),
			"covers": covers,
		}))
	}

	/// Every message the operator key signed that the wallet's coins rest
	/// on, as evidence lines: what the wallet hands a watcher.
	pub fn bond_evidence(&self) -> Result<Vec<Value>, Error> {
		let now = self.now()?;
		let mut seen = BTreeSet::new();
		let mut out = vec![];
		for c in self.store.coins()? {
			if c.kind != "transfer" && c.kind != "fill" {
				continue;
			}
			let Ok(record) = Self::record_of(&c) else { continue };
			let Ok(txs) = self.base_txs(&record) else { continue };
			let policy: WalletPolicy = self.followed_policy(c.expiry, now);
			let Ok(valid) = self.resolve(&record, &txs, &policy) else { continue };
			for e in bond::cosigned_by(&valid) {
				if seen.insert((e.salt, e.signed.rest.clone())) {
					out.push(evidence_line(&e.salt, &e.signed));
				}
			}
		}
		Ok(out)
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
		let own = self.bond_evidence()?;
		for v in own.iter().chain(lines) {
			match read_line(v) {
				Ok((salt, signed)) if policy.verify(&salt, &signed) => {
					let list = by_salt.entry(salt).or_default();
					if !list.iter().any(|x| policy.digest_of(&salt, x) == policy.digest_of(&salt, &signed)) {
						list.push(signed);
					}
					good += 1;
				},
				_ => bad += 1,
			}
		}
		// The chain and the mempool: every spend of a script that pushes a
		// watched salt's K (or K ‖ P).
		let ks: BTreeMap<[u8; 32], [u8; 32]> = by_salt.keys().map(|salt| (policy.chain.leaf_constant(salt), *salt)).collect();
		let tip = self.chain.tip()?.height;
		let from = match self.store.meta(BOND_SCANNED)?.and_then(|v| v.parse::<u64>().ok()) {
			Some(h) => h.saturating_add(1),
			None => tip.saturating_sub(FIRST_SCAN),
		};
		let mut txs: Vec<Transaction> = vec![];
		for h in from..=tip {
			if let Some(b) = self.chain.block_at(h)? {
				txs.extend(b.txdata.into_iter().skip(1));
			}
		}
		for t in self.chain.mempool()? {
			if let Some(tx) = self.chain.transaction(&t)? {
				txs.push(tx);
			}
		}
		let mut from_chain = 0usize;
		for tx in &txs {
			for (i, input) in tx.input.iter().enumerate() {
				let w = &input.witness.script_witness;
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
								list.push(signed);
								from_chain += 1;
							}
						}
					}
				}
			}
		}
		self.store.set_meta(BOND_SCANNED, &tip.to_string())?;
		let conflicts: Vec<Evidence> = by_salt.iter().filter(|(_, l)| l.len() > 1)
			.map(|(salt, l)| Evidence { salt: *salt, a: l[0].clone(), b: l[1].clone() }).collect();
		// A slash for the first conflict, if the bond still stands, and every
		// slash sent before again until final.
		let mut slashes: BTreeMap<String, String> = self.store.meta(BOND_SLASHES)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default();
		let mut slashed = vec![];
		if let (Some(e), Some((op, out))) = (conflicts.first(), s.coin.clone()) {
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
			"state": s.state, "why": s.why, "evidence": {"lines": good, "refused": bad, "from_chain": from_chain, "salts": by_salt.len()},
			"scanned": {"from": from, "to": tip, "mempool": true},
			"conflicts": conflicts.iter().map(|e| json!({"salt": hex(&e.salt), "a": evidence_line(&e.salt, &e.a), "b": evidence_line(&e.salt, &e.b)}))
				.collect::<Vec<_>>(),
			"slashed": slashed, "resent": resent,
		}))
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
