//! Locks between two holders: `htlc-2` ([`arca_covenant::lock`]).
//!
//! A payer's coin is locked to a payee under a payment hash until a
//! timeout `T`, out of round: the payee holds it at once, as any coin
//! received out of round, and claims it with the preimage; from `T` it
//! comes back to the payer. Nothing is fronted by the operator, and the
//! payer's refund rests on script, not on the operator. It is how a seller
//! of an asset locks its side of a purchase paid in BTC on a Bitcoin ark
//! ([`super::btc_swap`]).
//!
//! - **The payee asks** ([`Wallet::lock_request`]): a key and nonce of its
//!   own for the lock, its mailbox and exit delay, the asset, the value and
//!   the hash, and the earliest timeout it takes. It keeps nothing spendable
//!   until the lock comes.
//! - **The payer locks** ([`Wallet::lock_to`]): one transfer of its coins
//!   into the `htlc-2` leaf and its change. Its key for the refund is drawn
//!   from the leaf's creator nonce ([`refund_nonce`]), so a restore from the
//!   phrase finds the lock as its own. Its delay is the payee's and
//!   [`arca_covenant::lock::REFUND_DELAY_MARGIN_UNITS`] more, at least.
//!   It locks only from a coin whose lock can still be followed by its
//!   claim and its refund (two reassignments under the operator's depth
//!   limit).
//! - **Each side holds the record apart** from its spendable coins: the
//!   payee as `lock_in`, counted against its instant limit as a coin
//!   received; the payer as `lock_out`, its own value by script.
//! - **The payee's lock is held** ([`Wallet::lock_ready`]) once its record
//!   is the request's, its rounds final, inside the instant limit, and its
//!   home date far enough out: only then does a buyer pay.
//! - **The payee claims** with the preimage ([`Wallet::lock_claim`]), out of
//!   round, before `T` less the operator's claim margin; **the payer
//!   refunds** from `T` ([`Wallet::lock_refund`]). `sync` does both on its
//!   own ([`Wallet::progress_locks`]): the payee claims as soon as it holds
//!   the preimage (its own, or the operator's once the payer posted it), the
//!   payer refunds from `T` while the lock is open, and learns from the
//!   operator when the payee claimed.

use std::collections::BTreeMap;
use std::str::FromStr;

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::AssetId;
use serde_json::{json, Value};

use arca_covenant::lock::{LockSpend, LockTerms, REFUND_DELAY_MARGIN_UNITS};
use arca_covenant::{CoinRecord, ExplicitOutput, MedianTime, NewLeaf, RelativeTime};

use super::chain::{hex, unhex32};
use super::pay::{In, Out};
use super::places::{Place, Spend};
use super::store::CoinRow;
use super::wallet::{amount, sign, Wallet};
use super::{random32, Error};

/// Where the wallet keeps its locks: a map from `<role>/<hash>` (`payee` or
/// `payer`) to the lock's record.
pub(crate) const LOCKS: &str = "locks";

/// What a lock request's JSON says it is (`kind`).
pub const REQUEST_KIND: &str = "arca-lock-request";

/// The coin state of a lock the wallet holds as its payee.
pub const LOCK_IN: &str = "lock_in";
/// The coin state of a lock the wallet made as its payer.
pub const LOCK_OUT: &str = "lock_out";

/// The template the operator lists when it co-signs locks.
pub const TEMPLATE: &str = "htlc-2";

/// Blocks a step of the unroll takes, at most, on the payee's way home.
const STEP_BLOCKS: u64 = 2;

/// The unroll of a lock's path the specification allows at least, `u`, in
/// seconds: the operator's `info.locks.unroll_seconds` where it names one.
pub const UNROLL_SECONDS: u64 = 3_600;

/// Whether a lock at depth `hops` under `depth_limit`, resting on batches
/// whose earliest first expiry is `expiry` (`None` on boards alone), with
/// timeout `timeout`, payer's delay `refund_delay` and unroll `unroll`, is
/// one its payee can rely on: a claim adds one reassignment, so `hops + 1`
/// is within the limit; and the batches are not swept before the timeout,
/// the payer's delay and the unroll have passed (the operator's own rule,
/// which a payee checks rather than trusts). The reason, when not.
pub fn lock_fits(hops: usize, depth_limit: Option<usize>, expiry: Option<u64>, timeout: u64, refund_delay: u64, unroll: u64)
	-> Result<(), String>
{
	if let Some(limit) = depth_limit {
		if hops + 1 > limit {
			return Err(format!("is {} reassignments deep, and the operator's depth limit of {} leaves no room for its claim", hops, limit));
		}
	}
	if let Some(e) = expiry {
		if timeout + refund_delay + unroll > e {
			return Err(format!("rests on a batch that expires at median time {}, before its timeout {}, the payer's delay and the \
				unroll have passed: a sweep could take it", e, timeout));
		}
	}
	Ok(())
}

/// A lock's home date: its timeout `timeout` less the unroll of its path
/// (`steps` transactions, every node level and lineage step down to the
/// leaf, each given [`STEP_BLOCKS`] blocks of `block` seconds, and never less
/// than `unroll`), the payee's exit delay `exit_delay` and ten minutes.
pub fn lock_home_date(timeout: u64, exit_delay: u64, steps: u64, block: u64, unroll: u64) -> u64 {
	let path = steps.saturating_mul(STEP_BLOCKS).saturating_mul(block).max(unroll);
	timeout.saturating_sub(path + exit_delay + 600)
}

/// Whether the wallet's lock record `rec` as payer still stands: made or
/// being made, claimed, or ended by its refund after a claim could have been
/// made. Only a lock refused before anything was locked does not.
pub(crate) fn lock_stands(rec: &Value) -> bool {
	rec["state"] != "refused"
}

/// The operator's `lock_status` answer `st` for `hash`, read strictly:
/// whether it says the payment went through (it serves a preimage that
/// opens the hash, or calls a lock claimed). An answer of any other shape
/// than the server's (not an object, another hash or none, no list of
/// locks, a lock without its leaf, keys and timeout or in a state the
/// wallet does not know, a preimage not 32 bytes in hex or not opening the
/// hash) says nothing the wallet can read, and is [`Error::Unreachable`]:
/// it says nothing of what the operator did, and the caller asks again.
pub(crate) fn lock_status_went_through(st: &Value, hash: &str) -> Result<bool, Error> {
	let bad = |why: String| Error::Unreachable(format!("lock_status: the operator's answer is not a lock status of hash {}: {}", hash, why));
	let o = st.as_object().ok_or_else(|| bad(format!("{} is not an object", st)))?;
	if o.get("payment_hash").and_then(Value::as_str).map(str::to_ascii_lowercase).as_deref() != Some(hash) {
		return Err(bad(format!("it names hash {}", o.get("payment_hash").unwrap_or(&Value::Null))));
	}
	let locks = o.get("locks").and_then(Value::as_array).ok_or_else(|| bad("it holds no list of locks".into()))?;
	let hex32 = |v: Option<&Value>| v.and_then(Value::as_str).is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()));
	let mut claimed = false;
	for l in locks {
		if !(l.is_object() && hex32(l.get("leaf_id")) && hex32(l.get("payee")) && hex32(l.get("payer"))
			&& l.get("timeout").and_then(Value::as_u64).is_some_and(|t| t <= u32::MAX as u64))
		{
			return Err(bad(format!("lock {} is not of the form the operator gives", l)));
		}
		match l["state"].as_str() {
			Some("open" | "refunded") => {},
			Some("claimed") => claimed = true,
			_ => return Err(bad(format!("a lock is in a state the wallet does not know ({})", l["state"]))),
		}
	}
	let served = match o.get("preimage") {
		None | Some(Value::Null) => false,
		Some(Value::String(p)) => {
			let b = unhex32(p).map_err(|_| bad("its preimage is not 32 bytes in hex".into()))?;
			if hex(&sha256::Hash::hash(&b).to_byte_array()) != hash {
				return Err(bad("its preimage does not open the hash".into()));
			}
			true
		},
		Some(v) => return Err(bad(format!("its preimage {} is not a string", v))),
	};
	Ok(served || claimed)
}

/// Why the paid mark of the payee's lock record `rec` under `hash` stays,
/// or `None` when it may be cleared: the payment went through (the lock
/// claimed, its preimage known, `known` when the wallet learnt it elsewhere),
/// a payment of the wallet's own under the hash may still complete
/// (`paying`, said), or the lock's exit has started (`exiting`).
pub(crate) fn unpaid_refusal(hash: &str, rec: &Value, known: bool, paying: Option<&str>, exiting: bool) -> Option<String> {
	if rec["state"] == "claimed" {
		return Some(format!("the lock under hash {} is claimed: its payment went through", hash));
	}
	if known || !rec["preimage"].is_null() {
		return Some(format!("the preimage of hash {} is known, or the payment under it is recorded paid: the payment went through, \
			and the lock is claimed with the preimage", hash));
	}
	if let Some(p) = paying {
		return Some(format!("the payment under hash {} may still complete ({}): the lock stays marked paid until it has failed for good", hash, p));
	}
	if exiting && rec["paid"] == true {
		return Some(format!("the lock under hash {}'s exit has started: it is on its way to the chain, where its payer takes it back \
			from its timeout unless the preimage comes", hash));
	}
	None
}

/// Whether a lock whose transfer failed with `e` is to be recorded as
/// refused, nothing locked: the operator's own refusal, or a refusal of the
/// wallet's while every input is live still (`inputs_back`: nothing was
/// posted, or the operator's refusal put them back). A refusal of the
/// wallet's once the request was posted (an answer it does not accept, after
/// the operator may have co-signed the lock) leaves the request standing.
pub(crate) fn lock_refused(e: &Error, inputs_back: bool) -> bool {
	match e {
		Error::Server { .. } => true,
		Error::Refused(_) => inputs_back,
		_ => false,
	}
}

/// The nonce of the payer's key for the lock whose leaf's creator nonce is
/// `creator_nonce`: `SHA256("Arca/lock refund" ‖ creator_nonce)`. Drawn from
/// the leaf, which the payer makes, so a restore from the phrase finds the
/// key of every lock the wallet made in the lock's own record.
pub fn refund_nonce(creator_nonce: &[u8; 32]) -> [u8; 32] {
	let mut e = sha256::Hash::engine();
	e.input(b"Arca/lock refund");
	e.input(creator_nonce);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// The `htlc-2` terms of `record`'s coin, when it is a lock.
pub(crate) fn lock_terms(record: &CoinRecord) -> Option<(LockTerms, XOnlyPublicKey, [u8; 32], [u8; 32])> {
	match record {
		CoinRecord::Transfer(t) => t.leaf.lock.map(|l| (l, t.leaf.owner, t.leaf.owner_nonce, t.leaf.creator_nonce)),
		_ => None,
	}
}

fn key(role: &str, hash: &str) -> String {
	format!("{}/{}", role, hash)
}

fn wall_now() -> u64 {
	web_time::SystemTime::now().duration_since(web_time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Wallet {
	pub(crate) fn locks_map(&self) -> Result<BTreeMap<String, Value>, Error> {
		Ok(self.store.meta(LOCKS)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default())
	}

	pub(crate) fn set_lock(&self, role: &str, hash: &str, mut v: Value) -> Result<(), Error> {
		v["updated_at"] = json!(wall_now());
		let mut m = self.locks_map()?;
		m.insert(key(role, hash), v);
		self.store.set_meta(LOCKS, &serde_json::to_string(&m).expect("a map"))
	}

	/// The chain's median time, which a lock's timeout is in.
	pub fn median_time(&self) -> Result<u32, Error> {
		Ok(self.now()?.to_consensus_u32())
	}

	/// The wallet's lock as `role` (`payee` or `payer`) under `hash`.
	pub(crate) fn lock_rec(&self, role: &str, hash: &str) -> Result<Option<Value>, Error> {
		Ok(self.locks_map()?.get(&key(role, hash)).cloned())
	}

	/// Whether the operator co-signs `htlc-2` locks (`templates.list`).
	pub(crate) fn operator_locks(info: &Value) -> bool {
		info["templates"]["list"].as_array().is_some_and(|l| l.iter().any(|t| t == TEMPLATE))
	}

	/// The key and nonce of the wallet's that holds `record`'s coin: its
	/// owner's, or, for a lock the wallet made as its payer, its key for the
	/// refund ([`refund_nonce`]), when that is the wallet's and the owner's
	/// is not.
	pub(crate) fn holder_of(&self, record: &CoinRecord) -> Result<(XOnlyPublicKey, [u8; 32], bool), Error> {
		let (owner, nonce) = super::wallet::owner_of(record);
		if let Some((terms, _, _, creator)) = lock_terms(record) {
			if self.store.nonce(&nonce)?.is_none() {
				let n = refund_nonce(&creator);
				if self.keys.leaf_xonly(&n)? == terms.refunder {
					return Ok((terms.refunder, n, true));
				}
			}
		}
		Ok((owner, nonce, false))
	}

	/// The payee's side: asks for a lock of `value` of `asset` under `hash`,
	/// with a timeout no earlier than `min_timeout` (a median time) when
	/// named. Draws a key for the lock and keeps its nonce, and the lock's
	/// record; refused when the operator co-signs no lock. Returns the
	/// request the payer locks to ([`Self::lock_to`]).
	pub fn lock_request(&mut self, asset: AssetId, value: u64, hash: [u8; 32], min_timeout: Option<u32>) -> Result<Value, Error> {
		let info = self.server_info()?;
		if !Self::operator_locks(&info) {
			return Err(Error::Refused("the operator co-signs no htlc-2 lock (templates.list does not name it)".into()));
		}
		let min = Self::min_leaf(&info, asset)?;
		if value < min {
			return Err(Error::Refused(format!("{} is below the operator's smallest leaf in asset {}, {}", value, asset, min)));
		}
		let h = hex(&hash);
		if let Some(r) = self.lock_rec("payee", &h)? {
			if r["state"] != "asked" {
				return Err(Error::Refused(format!("the wallet holds a lock under hash {} already ({})", h, r["state"])));
			}
			return Ok(r["request"].clone());
		}
		let key = self.lock_key()?;
		self.lock_request_keyed(&key, asset, value, hash, min_timeout)
	}

	/// Whether a lock of `value` of `asset` fits the wallet's instant room
	/// now: always while it sets no instant limit; never while the node
	/// gives no rate for the asset.
	pub(crate) fn lock_fits_room(&self, asset: AssetId, value: u64) -> Result<bool, Error> {
		let Some(limit) = self.instant_limit()? else { return Ok(true) };
		let Some(rate) = self.chain.fee_rates()?.get(&asset).copied().filter(|r| *r > 0) else { return Ok(false) };
		let worth = value as u128 * rate as u128 / 100_000_000;
		let counted = self.places()?.counted;
		Ok(counted.saturating_add(worth) <= limit.value)
	}

	/// The key a payee draws for a lock before it knows the hash (a swap's
	/// maker that gives BTC, whose taker names the hash): what a lock
	/// request carries of it, its nonce kept for the lock.
	pub(crate) fn lock_key(&mut self) -> Result<Value, Error> {
		let nonce = random32();
		let owner = self.keys.leaf_xonly(&nonce)?;
		self.store.put_nonce(&nonce, &owner.serialize(), "lock")?;
		Ok(json!({"owner": hex(&owner.serialize()), "owner_nonce": hex(&nonce),
			"mailbox": hex(&self.keys.mailbox()?.x_only_public_key().0.serialize()), "exit_delay_units": self.cfg.exit_delay_units,
			"reads": arca_covenant::RECORD_FORMATS}))
	}

	/// [`Self::lock_request`] under a key drawn before ([`Self::lock_key`]).
	pub(crate) fn lock_request_keyed(&mut self, key: &Value, asset: AssetId, value: u64, hash: [u8; 32], min_timeout: Option<u32>)
		-> Result<Value, Error>
	{
		let h = hex(&hash);
		let nonce = key["owner_nonce"].as_str().unwrap_or("").to_string();
		let mut req = Self::lock_request_of(self, key, asset, value, &h);
		if let Some(t) = min_timeout {
			req["min_timeout"] = json!(t);
		}
		self.set_lock("payee", &h, json!({"role": "payee", "hash": h, "asset": asset.to_string(), "value": value.to_string(),
			"nonce": nonce, "min_timeout": min_timeout, "state": "asked", "request": req.clone(), "created_at": wall_now()}))?;
		Ok(req)
	}

	/// A lock request from a payee's key and the lock's terms.
	pub(crate) fn lock_request_of(&self, key: &Value, asset: AssetId, value: u64, hash: &str) -> Value {
		let mut req = key.clone();
		req["kind"] = json!(REQUEST_KIND);
		req["genesis_hash"] = json!(self.genesis.genesis_hash().to_string());
		req["operator"] = json!(self.operator.to_string());
		req["asset"] = json!(asset.to_string());
		req["value"] = json!(value.to_string());
		req["payment_hash"] = json!(hash);
		req
	}

	/// The payer's side: locks `value` of `asset` (the request's) to the
	/// payee of `request` ([`Self::lock_request`]) under its hash, until
	/// `timeout` (a median time), out of round. Refused before anything is
	/// signed when the operator co-signs no lock, the timeout is before the
	/// request's earliest or outside the operator's bounds, or the wallet
	/// holds no coin shallow enough that the lock can still be claimed and
	/// refunded. The lock is paid to another party, who could not give its
	/// value back if a trade it pays for died: it is paid as a cross-chain
	/// swap's leg is ([`Spend::CrossChain`]: no trade proceeds before their
	/// round).
	pub fn lock_to(&mut self, request: &Value, timeout: u32) -> Result<Value, Error> {
		let spend = Spend::CrossChain;
		if request["kind"].as_str() != Some(REQUEST_KIND) {
			return Err(Error::Parse("the text is no lock request".into()));
		}
		self.check_chain(request, "lock request")?;
		let info = self.server_info()?;
		if !Self::operator_locks(&info) {
			return Err(Error::Refused("the operator co-signs no htlc-2 lock (templates.list does not name it)".into()));
		}
		let asset = AssetId::from_str(request["asset"].as_str().unwrap_or("")).map_err(|e| Error::Parse(format!("the request's asset: {}", e)))?;
		let value = amount(&request["value"], "the request's value")?;
		let hash = unhex32(request["payment_hash"].as_str().unwrap_or(""))?;
		let h = hex(&hash);
		if let Some(r) = self.lock_rec("payer", &h)? {
			if !matches!(r["state"].as_str(), Some("refused")) {
				return Err(Error::Refused(format!("the wallet has locked under hash {} already ({})", h, r["state"])));
			}
		}
		// A payment of the wallet's over Lightning under the same hash gives
		// the same thing through the operator ([`super::lightning`]): locked
		// straight as well, the payee could claim both with the one preimage.
		// Only a payment whose coin came back no longer stands.
		if let Some(s) = self.sends()?.get(&h).filter(|s| s["state"] != "returned") {
			return Err(Error::Refused(format!("the wallet is paying under hash {} through the operator already ({}): locking it \
				straight as well would give it twice; nothing is signed", h, s["state"])));
		}
		let owner = XOnlyPublicKey::from_str(request["owner"].as_str().unwrap_or("")).map_err(|e| Error::Parse(format!("the request's key: {}", e)))?;
		let owner_nonce = unhex32(request["owner_nonce"].as_str().unwrap_or(""))?;
		let mailbox = XOnlyPublicKey::from_str(request["mailbox"].as_str().unwrap_or("")).map_err(|e| Error::Parse(format!("the request's mailbox: {}", e)))?;
		let d_q = u16::try_from(request["exit_delay_units"].as_u64().unwrap_or(0)).map_err(|_| Error::Parse("the request's exit delay".into()))?;
		let exit_delay = RelativeTime::from_units(d_q).map_err(|e| Error::Parse(e.to_string()))?;
		let max_units = info["exit_delay_units"]["max"].as_u64().unwrap_or(u16::MAX as u64);
		let d_p = (self.cfg.exit_delay_units as u32).max(d_q as u32 + REFUND_DELAY_MARGIN_UNITS as u32);
		if d_p as u64 > max_units {
			return Err(Error::Refused(format!("the payee's exit delay of {} units leaves the payer's refund delay {} units, past the \
				operator's most, {}", d_q, d_p, max_units)));
		}
		let refund_delay = RelativeTime::from_units(d_p as u16).map_err(|e| Error::Parse(e.to_string()))?;
		let now = self.now()?.to_consensus_u32();
		if let Some(min) = request["min_timeout"].as_u64() {
			if (timeout as u64) < min {
				return Err(Error::Refused(format!("the lock would time out at median time {}, before the payee's earliest, {}", timeout, min)));
			}
		}
		let unroll = info["locks"]["unroll_seconds"].as_u64().unwrap_or(3600);
		let least = now as u64 + exit_delay.seconds() + unroll;
		let most = now as u64 + info["locks"]["max_seconds"].as_u64().unwrap_or(14 * 86400);
		if (timeout as u64) < least || timeout as u64 > most {
			return Err(Error::Refused(format!("a lock's timeout lies from median time {} (the payee's delay and the unroll out) to {} \
				(the operator's furthest), and {} does not", least, most, timeout)));
		}
		let min = Self::min_leaf(&info, asset)?;
		if value < min {
			return Err(Error::Refused(format!("{} is below the operator's smallest leaf in asset {}, {}", value, asset, min)));
		}
		// The payer's key for the refund, from the leaf's creator nonce.
		let creator_nonce = random32();
		let rn = refund_nonce(&creator_nonce);
		let refunder = self.keys.leaf_xonly(&rn)?;
		let terms = LockTerms {
			payment_hash: hash, timeout: MedianTime::from_consensus(timeout).map_err(|e| Error::Parse(e.to_string()))?, refunder,
			refund_delay,
		};
		let leaf = NewLeaf { lock: Some(terms), owner, owner_nonce, creator_nonce, exit_delay, htlc: None, landing: None, v2: false };
		let own_mailbox = self.keys.mailbox()?.x_only_public_key().0;
		let to = Out { asset, value, leaf, mailbox, until: None, payer_mailbox: Some(own_mailbox) };
		let to_out = to.explicit(self);
		let reads = super::pay::Reads::of(request);
		// Only coins whose lock can be followed by its claim and its refund,
		// taken in the order a swap's and a Lightning lock's coins are
		// (`fit_order`, the smallest that pays alone first), and each
		// outliving the lock: its batches not swept before the timeout, the
		// payer's delay and the unroll have passed, as the operator requires.
		self.locking.set(true);
		let was = self.lock_until.replace(Some(super::pay::lock_outlives(timeout, refund_delay)));
		let chosen = self.choose(&info, asset, value, std::slice::from_ref(&to_out), true, min, 0, true, reads, spend);
		self.locking.set(false);
		// Refused only for the depth bound: said so, rather than what the
		// shallower coins alone fall short of.
		let chosen = match chosen {
			Err(e) => {
				let _quote = self.quoting();
				match self.choose(&info, asset, value, std::slice::from_ref(&to_out), true, min, 0, true, reads, spend) {
					Ok(_) => Err(Error::Refused(format!("the wallet's coins that cover this lock are too deep: a lock from them could not \
						be followed by both its claim and its refund under the operator's depth limit of {} reassignments; a round \
						refreshes them, and the payment can go through the operator meanwhile; nothing was signed",
						super::pay::depth_limit(&info).unwrap_or(0)))),
					Err(_) => Err(e),
				}
			},
			ok => ok,
		};
		self.lock_until.set(was);
		let (inputs, margin, change) = chosen?;
		self.store.put_nonce(&rn, &refunder.serialize(), "lock refund")?;
		let mut outs = vec![to];
		if change > 0 {
			let leaf = self.own_leaf_for("change")?;
			outs.push(Out { asset, value: change, leaf, mailbox: own_mailbox, until: None, payer_mailbox: None });
		}
		// Recorded before the transfer is asked, so a restart finds it.
		let mut rec = json!({"role": "payer", "hash": h, "asset": asset.to_string(), "value": value.to_string(), "timeout": timeout,
			"refund_nonce": hex(&rn), "payee": hex(&owner.serialize()), "state": "locking", "created_at": wall_now()});
		self.set_lock("payer", &h, rec.clone())?;
		match self.transfer_back(&inputs, &outs) {
			Ok(answer) => {
				let leaf_id = answer["outputs"].as_array().and_then(|o| o.first()).cloned().unwrap_or(Value::Null);
				rec["leaf_id"] = leaf_id.clone();
				rec["state"] = json!("locked");
				self.set_lock("payer", &h, rec.clone())?;
				Ok(json!({"payment_hash": h, "leaf_id": leaf_id, "asset": asset.to_string(), "value": value.to_string(), "timeout": timeout,
					"refund_delay_units": d_p, "inputs": inputs.iter().map(|i| i.row.leaf_id.clone()).collect::<Vec<_>>(),
					"margins": {"checkpoints": inputs.iter().map(|i| (i.coin.value - i.checkpoint_value).to_string()).collect::<Vec<_>>(),
						"reassignment": margin.to_string()},
					"change": if change > 0 { json!(change.to_string()) } else { Value::Null }, "transfer": answer}))
			},
			Err(e) => {
				// A refusal before anything was posted, or the operator's own,
				// leaves nothing locked; anything else (no answer, or a refusal
				// of the wallet's after the operator co-signed) leaves the
				// request standing, posted again by `sync`.
				let back = inputs.iter().all(|i| self.store.coin(&i.row.leaf_id).ok().flatten().is_some_and(|c| c.state == "live"));
				if lock_refused(&e, back) {
					rec["state"] = json!("refused");
					rec["why"] = json!(e.to_string());
					self.set_lock("payer", &h, rec)?;
				}
				Err(e)
			},
		}
	}

	/// The preimage of the lock the wallet holds as its payee under `hash`:
	/// its own, or the operator's once the payer posted it. Refused while
	/// neither has it: the lock is claimed on the chain only with it.
	pub(crate) fn lock_preimage(&self, hash: &str) -> Result<[u8; 32], Error> {
		if let Some(p) = self.lock_rec("payee", hash)?.and_then(|r| r["preimage"].as_str().map(String::from)) {
			return unhex32(&p);
		}
		let st = self.lock_status(hash).map_err(|e| Error::Refused(format!("the lock's preimage is not known, and the operator does 			not answer: {}", e)))?;
		match st["preimage"].as_str() {
			Some(p) => {
				let pre = unhex32(p)?;
				if hex(&sha256::Hash::hash(&pre).to_byte_array()) != hash {
					return Err(Error::Refused("the operator's preimage does not open the lock's hash".into()));
				}
				if let Some(mut r) = self.lock_rec("payee", hash)? {
					r["preimage"] = json!(p);
					self.set_lock("payee", hash, r)?;
				}
				Ok(pre)
			},
			None => Err(Error::Refused(format!("the preimage of hash {} is not known yet: the lock is claimed on the chain only with it", hash))),
		}
	}

	/// The coin row of the lock the wallet holds as `role` under `hash`.
	pub(crate) fn lock_row(&self, role: &str, hash: &str) -> Result<Option<CoinRow>, Error> {
		let state = if role == "payee" { LOCK_IN } else { LOCK_OUT };
		for c in self.store.coins_in(state)? {
			let Ok(record) = CoinRecord::from_bytes(&c.record) else { continue };
			if let Some((t, ..)) = lock_terms(&record) {
				if hex(&t.payment_hash) == hash {
					return Ok(Some(c));
				}
			}
		}
		Ok(None)
	}

	/// When the payee of a lock must start taking it home on the chain, a
	/// median time: its timeout, less the unroll of its whole path, its exit
	/// delay and a margin ([`lock_home_date`]). `unroll` is the operator's
	/// (`info.locks.unroll_seconds`), an hour when it says none.
	fn lock_home(&self, coin: &arca_covenant::ValidCoin, block: u64) -> Result<u64, Error> {
		let t = coin.leaf.lock.ok_or_else(|| Error::Refused("the coin is no lock".into()))?;
		let mut path = vec![];
		Self::path_outputs(coin, &mut path);
		let unroll = self.server.info().ok().and_then(|i| i["locks"]["unroll_seconds"].as_u64()).unwrap_or(UNROLL_SECONDS);
		Ok(lock_home_date(t.timeout.to_consensus_u32() as u64, coin.leaf.exit_delay.seconds(), path.len() as u64, block, unroll))
	}

	/// Whether the lock the wallet asked under `hash` is held: its record
	/// the request's (asset, value, hash, key, a timeout no earlier than the
	/// request's), its rounds final, inside the wallet's instant limit, and
	/// its home date ([`Self::lock_home`]) at least `need` seconds away.
	/// `{"ready": true, "home_in", ...}` when it is; `{"ready": false, "why"}`
	/// while it is not yet; refused when it never will be.
	pub fn lock_ready(&self, hash: &str, need: u64) -> Result<Value, Error> {
		let rec = self.lock_rec("payee", hash)?.ok_or_else(|| Error::Refused(format!("the wallet asked no lock under hash {}", hash)))?;
		let Some(row) = self.lock_row("payee", hash)? else {
			if let Some(c) = rec["leaf_id"].as_str().map(|l| self.store.coin(l)).transpose()?.flatten() {
				if c.state != LOCK_IN {
					if let Ok((_, a)) = self.held(&c) {
						let mut path = vec![];
						Self::path_outputs(&a.valid, &mut path);
						if self.chain.locate(&path)?.iter().all(Option::is_none) {
							return Err(Error::Refused(format!("the lock under hash {} rests on a coin spent elsewhere on the chain: it can \
								never come home, and nothing is to be paid for it", hash)));
						}
					}
				}
				if c.state == "exiting" {
					return Err(Error::Refused(format!("the lock under hash {} is being taken on the chain ({}): no spend of it is co-signed \
						any more; nothing is to be paid for it", hash, c.note)));
				}
				if c.state != LOCK_IN {
					return Err(Error::Refused(format!("the lock under hash {} is held no longer ({}: {}): nothing is to be paid for it", hash,
						c.state, c.note)));
				}
			}
			return Ok(json!({"payment_hash": hash, "ready": false, "why": "the lock has not come", "state": rec["state"]}));
		};
		let (_, a) = self.held(&row)?;
		let coin = &a.valid;
		let t = coin.leaf.lock.ok_or_else(|| Error::Refused("the lock is no htlc-2 coin".into()))?;
		let value = amount(&rec["value"], "the lock's value")?;
		if coin.asset.to_string() != rec["asset"].as_str().unwrap_or("") || coin.value != value
			|| rec["nonce"].as_str() != Some(&hex(&coin_nonce(&row)))
		{
			return Err(Error::Refused(format!("the lock under hash {} is not the one asked: {} of {}, asked {} of {}", hash, coin.value,
				coin.asset, value, rec["asset"])));
		}
		if let Some(min) = rec["min_timeout"].as_u64() {
			if (t.timeout.to_consensus_u32() as u64) < min {
				return Err(Error::Refused(format!("the lock times out at median time {}, before the earliest asked, {}",
					t.timeout.to_consensus_u32(), min)));
			}
		}
		if !a.all_final() {
			return Ok(json!({"payment_hash": hash, "ready": false, "why": format!("the lock's rounds are not final: {}", a.waiting())}));
		}
		// A lock is a coin received out of round: held only inside the
		// instant limit. A lock goes into no round, so one past it is never
		// held.
		if self.own_instant_limit()?.is_some() {
			let p = self.places()?;
			if p.of(&row.leaf_id) != Some(Place::Counted) {
				return Err(Error::Refused(format!("the lock under hash {} is past the wallet's instant limit: a lock goes into no round, so \
					it is never held; nothing is to be paid for it", hash)));
			}
		}
		// A lock whose whole path is spent on the chain (in a block or the
		// mempool) by something else, its input spent again by its payer and
		// a signer, can never come home: never held, and nothing is paid.
		let mut path = vec![];
		Self::path_outputs(coin, &mut path);
		let here = super::exit::Here { outputs: path.clone(), at: self.chain.locate(&path)? };
		if here.at.iter().all(Option::is_none) {
			return Err(Error::Refused(format!("the lock under hash {} rests on a coin spent elsewhere on the chain: it can never come \
				home, and nothing is to be paid for it", hash)));
		}
		// A sender up its lineage took an earlier coin on the chain (its payer
		// converting the board it locked from, say): the wallet answers by
		// bringing the lock on the chain ([`Self::watch_lineages`]), where its
		// scripts decide. A payment not made yet is not made for it.
		let mut seen = self.lineage_seen(coin, &here)?;
		for b in coin.boards() {
			if !self.chain.unspent(&b)? {
				seen.push(format!("the board at {} it rests on, spent", b));
			}
		}
		if !seen.is_empty() || row.state == "exiting" {
			return Err(Error::Refused(format!("the lock under hash {} is being taken on the chain ({}): its lineage reached the chain, so \
				no spend of it is co-signed any more; nothing is to be paid for it", hash,
				if seen.is_empty() { "its exit started".to_string() } else { seen.join("; ") })));
		}
		let info = self.server_info()?;
		// What the operator checks before it co-signs a lock, checked again
		// here, so that the payee trusts no operator for it: a claim can
		// still follow the lock under the depth limit, and the batches its
		// path rests on are not swept before the payer's refund could follow
		// the timeout on the chain, let alone before the payee's home date.
		let record = Self::record_of(&row)?;
		let unroll = info["locks"]["unroll_seconds"].as_u64().unwrap_or(UNROLL_SECONDS);
		lock_fits(coin.hops, super::pay::depth_limit(&info), super::pay::first_expiry(&record).map(|e| e as u64),
			t.timeout.to_consensus_u32() as u64, t.refund_delay.seconds(), unroll)
			.map_err(|why| Error::Refused(format!("the lock under hash {} {}: nothing is to be paid for it", hash, why)))?;
		let block = info["lightning"]["receive"]["block_seconds"].as_u64().unwrap_or(60).max(1);
		let home = self.lock_home(coin, block)?;
		let median = self.now()?.to_consensus_u32() as u64;
		let home_in = home.saturating_sub(median);
		if home_in < need {
			return Err(Error::Refused(format!("the lock under hash {} must start home in {} s, and the other side can take {} s: nothing \
				is to be paid for it", hash, home_in, need)));
		}
		Ok(json!({"payment_hash": hash, "ready": true, "leaf_id": row.leaf_id, "asset": coin.asset.to_string(), "value": coin.value.to_string(),
			"timeout": t.timeout.to_consensus_u32(), "home_in": home_in}))
	}

	/// The payee's claim of its lock under `hash` with `preimage`, out of
	/// round, into a leaf of its own. The operator co-signs it until the
	/// lock's timeout less its claim margin.
	pub fn lock_claim(&mut self, hash: &str, preimage: [u8; 32]) -> Result<Value, Error> {
		if hex(&sha256::Hash::hash(&preimage).to_byte_array()) != hash {
			return Err(Error::Refused(format!("the preimage does not open hash {}", hash)));
		}
		let row = self.lock_row("payee", hash)?.ok_or_else(|| Error::Refused(format!("the wallet holds no lock under hash {}", hash)))?;
		let mut rec = self.lock_rec("payee", hash)?.unwrap_or_else(|| json!({"role": "payee", "hash": hash}));
		rec["preimage"] = json!(hex(&preimage));
		self.set_lock("payee", hash, rec.clone())?;
		let answer = self.end_lock(row, LockSpend::Claim { preimage }, "lock claimed")?;
		rec["state"] = json!("claimed");
		rec["claimed_into"] = answer["outputs"].clone();
		self.set_lock("payee", hash, rec)?;
		// Anyone may post a preimage; the payer reads it there too.
		let _ = self.server.post("lock_preimage", &json!({"payment_hash": hash, "preimage": hex(&preimage)}));
		Ok(json!({"payment_hash": hash, "state": "claimed", "transfer": answer}))
	}

	/// The payer's refund of its lock under `hash`, out of round, into a leaf
	/// of its own: from the lock's timeout on.
	pub fn lock_refund(&mut self, hash: &str) -> Result<Value, Error> {
		let row = self.lock_row("payer", hash)?.ok_or_else(|| Error::Refused(format!("the wallet holds no lock of its own under hash {}", hash)))?;
		let record = Self::record_of(&row)?;
		let (t, ..) = lock_terms(&record).ok_or_else(|| Error::Refused("the coin is no lock".into()))?;
		let now = self.now()?.to_consensus_u32();
		if now < t.timeout.to_consensus_u32() {
			return Err(Error::Refused(format!("the lock under hash {} is refunded from median time {}; the chain's is {}", hash,
				t.timeout.to_consensus_u32(), now)));
		}
		let answer = self.end_lock(row, LockSpend::Refund, "lock refunded")?;
		let mut rec = self.lock_rec("payer", hash)?.unwrap_or_else(|| json!({"role": "payer", "hash": hash}));
		rec["state"] = json!("refunded");
		rec["refunded_into"] = answer["outputs"].clone();
		self.set_lock("payer", hash, rec)?;
		Ok(json!({"payment_hash": hash, "state": "refunded", "transfer": answer}))
	}

	/// Gives the lock coin `row` up by `spend` into a leaf of the wallet's
	/// own, its margins out of it.
	fn end_lock(&mut self, row: CoinRow, spend: LockSpend, purpose: &str) -> Result<Value, Error> {
		let (_, a) = self.held(&row)?;
		let coin = a.valid;
		let asset = coin.asset;
		let info = self.server_info()?;
		let m = super::pay::Margins::of(&info, asset)?;
		let cp = self.checkpoint_margin_of(&coin, &m)?;
		let own = self.own_leaf_for(purpose)?;
		let mailbox = self.keys.mailbox()?.x_only_public_key().0;
		let probe = Out { asset, value: 1, leaf: own, mailbox, until: None, payer_mailbox: None };
		let re = self.reassignment_margin_of(&coin, &probe, &m)?;
		let value = coin.value.checked_sub(cp + re).filter(|v| *v > 0)
			.ok_or_else(|| Error::Refused(format!("the lock's {} atoms do not cover its margins", coin.value)))?;
		let back = Out { value, ..probe };
		let input = In { lock: Some(spend), row, checkpoint_value: coin.value - cp, coin };
		self.transfer_back(&[input], &[back])
	}

	/// The operator's word on the locks under `hash` (`lock_status`).
	pub fn lock_status(&self, hash: &str) -> Result<Value, Error> {
		self.server.post("lock_status", &json!({"payment_hash": hash}))
	}

	/// Every lock the wallet takes part in, with its coin's state.
	pub fn locks(&self) -> Result<Value, Error> {
		let mut out = vec![];
		for (k, mut v) in self.locks_map()? {
			let (role, hash) = k.split_once('/').unwrap_or(("", ""));
			if let Some(row) = self.lock_row(role, hash)? {
				v["leaf_id"] = json!(row.leaf_id);
				v["coin_state"] = json!(row.state);
			}
			v.as_object_mut().map(|o| o.remove("request"));
			out.push(v);
		}
		Ok(json!(out))
	}

	/// Moves every open lock on, as `sync` does: the payee claims a lock it
	/// holds the preimage of (its own, handed in with
	/// [`Self::lock_preimage_known`], or the operator's once the payer posted
	/// it) while the operator still co-signs a claim; the payer marks a lock
	/// the payee claimed as paid, and refunds one still open from its
	/// timeout. Each step that fails is said and tried again at the next.
	pub(crate) fn progress_locks(&mut self, talk: bool) -> Result<Vec<Value>, Error> {
		self.adopt_locks()?;
		if !talk {
			return self.locks_home(talk);
		}
		// What the operator answers first, where it proves itself (a refund
		// from the timeout, a claim with its preimage): a lock it ended is
		// then not taken on the chain for nothing. The chain afterwards.
		let mut out = vec![];
		let now = self.now()?.to_consensus_u32() as u64;
		for (k, rec) in self.locks_map()? {
			let (role, hash) = k.split_once('/').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or_default();
			match (role.as_str(), rec["state"].as_str().unwrap_or("")) {
				("payee", "asked" | "held") => {
					let Some(row) = self.lock_row("payee", &hash)? else { continue };
					if rec["state"] == "asked" {
						let mut r = rec.clone();
						r["state"] = json!("held");
						r["leaf_id"] = json!(row.leaf_id);
						self.set_lock("payee", &hash, r)?;
					}
					let mut pre = rec["preimage"].as_str().map(unhex32).transpose()?;
					let st = self.lock_status(&hash).ok();
					// Refunded to its payer from its timeout: the lock is gone. The
					// operator's word is unsigned, so it ends nothing it could not
					// be true of: a refund opens only at the timeout, and a payee
					// holding the preimage claims, out of round or on the chain,
					// whatever the operator says ([`Self::locks_home`]).
					let theirs = st.as_ref().and_then(|s| s["locks"].as_array()).and_then(|l| l.iter().find(|x| x["leaf_id"] == row.leaf_id.as_str())).cloned();
					let timeout = Self::record_of(&row).ok().and_then(|r| lock_terms(&r)).map(|(t, ..)| t.timeout.to_consensus_u32() as u64);
					if theirs.as_ref().is_some_and(|l| l["state"] == "refunded") && (pre.is_some() || timeout.is_none_or(|t| now < t)) {
						out.push(json!({"payment_hash": hash, "role": "payee", "ignored": "the operator says the lock was refunded, which it cannot \
							be before its timeout, nor end a lock whose preimage the wallet holds: the lock stays held"}));
					} else if theirs.as_ref().is_some_and(|l| l["state"] == "refunded") {
						let mut r = self.lock_rec("payee", &hash)?.unwrap_or(rec.clone());
						r["state"] = json!("refunded");
						self.set_lock("payee", &hash, r)?;
						self.store.set_coin_spent(&row.leaf_id, "refunded to its payer from its timeout")?;
						out.push(json!({"payment_hash": hash, "role": "payee", "state": "refunded"}));
						continue;
					}
					if pre.is_none() {
						pre = st.as_ref().and_then(|s| s["preimage"].as_str()).map(unhex32).transpose()?;
					}
					let Some(p) = pre else { continue };
					out.push(match self.lock_claim(&hash, p) {
						Ok(v) => json!({"payment_hash": hash, "role": "payee", "claimed": v["transfer"]["outputs"]}),
						Err(e) => json!({"payment_hash": hash, "role": "payee", "error": e.to_string()}),
					});
				},
				("payer", "locked" | "locking") => {
					let Some(row) = self.lock_row("payer", &hash)? else { continue };
					if rec["state"] == "locking" {
						// The transfer asked was answered by a later post (`sync`).
						let mut r = rec.clone();
						r["state"] = json!("locked");
						r["leaf_id"] = json!(row.leaf_id);
						self.set_lock("payer", &hash, r)?;
					}
					let st = self.lock_status(&hash).ok();
					let theirs = st.as_ref().and_then(|s| s["locks"].as_array()).and_then(|l| l.iter().find(|x| x["leaf_id"] == row.leaf_id.as_str())).cloned();
					// Claimed by its payee: proven only by a preimage that opens the
					// hash, which the payer revealed by claiming what it sold for.
					let opened = st.as_ref().and_then(|s| s["preimage"].as_str()).and_then(|p| unhex32(p).ok())
						.is_some_and(|p| hex(&sha256::Hash::hash(&p).to_byte_array()) == hash);
					if theirs.as_ref().is_some_and(|l| l["state"] == "claimed") && !opened {
						out.push(json!({"payment_hash": hash, "role": "payer", "ignored": "the operator says the lock was claimed and serves no \
							preimage that opens its hash: the lock stays the wallet's"}));
					} else if theirs.as_ref().is_some_and(|l| l["state"] == "claimed") {
						let mut r = rec.clone();
						r["state"] = json!("claimed");
						r["preimage"] = st.as_ref().map(|s| s["preimage"].clone()).unwrap_or(Value::Null);
						self.set_lock("payer", &hash, r)?;
						self.store.set_coin_spent(&row.leaf_id, "claimed by its payee")?;
						out.push(json!({"payment_hash": hash, "role": "payer", "state": "claimed"}));
						continue;
					}
					if now >= rec["timeout"].as_u64().unwrap_or(u64::MAX) {
						out.push(match self.lock_refund(&hash) {
							Ok(v) => json!({"payment_hash": hash, "role": "payer", "refunded": v["transfer"]["outputs"]}),
							Err(e) => {
								// Refused or unanswered: the next sync takes it on the
								// chain by REFUND ([`Self::locks_home`]).
								let mut r = self.lock_rec("payer", &hash)?.unwrap_or(rec.clone());
								r["refund_tries"] = json!(r["refund_tries"].as_u64().unwrap_or(0) + 1);
								r["refund_error"] = json!(e.to_string());
								self.set_lock("payer", &hash, r)?;
								json!({"payment_hash": hash, "role": "payer", "error": e.to_string()})
							},
						});
					}
				},
				_ => {},
			}
		}
		out.extend(self.locks_home(talk)?);
		Ok(out)
	}

	/// Gives every lock coin the wallet holds without a lock record (a
	/// restore from the phrase found it in the mailbox) the record its side
	/// keeps: the payee's held, claimed once the preimage is known; the
	/// payer's locked, refunded from its timeout unless claimed.
	pub(crate) fn adopt_locks(&mut self) -> Result<(), Error> {
		for (state, role) in [(LOCK_IN, "payee"), (LOCK_OUT, "payer")] {
			for c in self.store.coins_in(state)? {
				let Ok(record) = CoinRecord::from_bytes(&c.record) else { continue };
				let Some((t, owner, ..)) = lock_terms(&record) else { continue };
				let h = hex(&t.payment_hash);
				if self.lock_rec(role, &h)?.is_some() {
					continue;
				}
				let mut rec = json!({"role": role, "hash": h, "asset": c.asset, "value": c.value.to_string(), "leaf_id": c.leaf_id,
					"timeout": t.timeout.to_consensus_u32(), "restored": true, "created_at": wall_now()});
				if role == "payee" {
					rec["state"] = json!("held");
					rec["nonce"] = json!(hex(&c.owner_nonce));
					// A restore cannot tell whether the lost device paid for it:
					// held as paid, so it is taken on the chain from its home date
					// unless claimed, and its claim there waits for the preimage.
					rec["paid"] = json!(true);
				} else {
					rec["state"] = json!("locked");
					rec["refund_nonce"] = json!(hex(&c.owner_nonce));
					rec["payee"] = json!(hex(&owner.serialize()));
				}
				self.set_lock(role, &h, rec)?;
			}
		}
		Ok(())
	}

	/// Takes on the chain every lock that must go there, whatever the
	/// operator does: the payee's, from its home date ([`Self::lock_home`]),
	/// once it holds the preimage or has paid for it (the claim then waits
	/// on the chain for the preimage); the payer's, from its timeout, once
	/// its refund out of round was refused or the operator does not answer
	/// (`talk` false). An exit already under way
	/// is followed by the schedule as any exit is.
	pub(crate) fn locks_home(&mut self, talk: bool) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		let now = self.now()?.to_consensus_u32() as u64;
		for (k, rec) in self.locks_map()? {
			let (role, hash) = k.split_once('/').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or_default();
			let Some(row) = self.lock_row(&role, &hash)? else { continue };
			if self.store.exit(&row.leaf_id)?.is_some() {
				continue;
			}
			let due = match role.as_str() {
				"payee" => {
					let owed = matches!(rec["state"].as_str(), Some("asked" | "held")) && (!rec["preimage"].is_null() || rec["paid"] == true);
					let (_, a) = self.held(&row)?;
					let home = self.lock_home(&a.valid, 60)?;
					owed && now >= home
				},
				_ => rec["state"] == "locked" && now >= rec["timeout"].as_u64().unwrap_or(u64::MAX)
					&& (!talk || rec["refund_tries"].as_u64().unwrap_or(0) >= 1),
			};
			if !due {
				continue;
			}
			out.push(match self.exit(&row.leaf_id, None) {
				Ok(v) => json!({"payment_hash": hash, "role": role, "on_chain": v}),
				Err(e) => json!({"payment_hash": hash, "role": role, "on_chain_error": e.to_string()}),
			});
		}
		Ok(out)
	}

	/// Notes that the payee's wallet pays for the preimage of `hash` (its
	/// BTC payment is going out): from the lock's home date it is taken on
	/// the chain unless claimed, and its claim there waits for the preimage.
	/// A program that pays the other leg itself marks it so before it pays,
	/// as the swap does ([`super::btc_swap`]); kept before it answers.
	/// Refused for a hash the wallet asked no lock under.
	pub fn lock_paid(&mut self, hash: &str) -> Result<Value, Error> {
		let mut r = self.lock_rec("payee", hash)?.ok_or_else(|| Error::Refused(format!("the wallet asked no lock under hash {}", hash)))?;
		r["paid"] = json!(true);
		self.set_lock("payee", hash, r)?;
		Ok(json!({"payment_hash": hash, "paid": true}))
	}

	/// Clears the mark [`Self::lock_paid`] set, once the wallet's payment
	/// for the preimage of `hash` has failed for good: the lock is then not
	/// taken on the chain at its home date, and goes back to its payer out of
	/// round from its timeout, as a lock never paid for does. Only the
	/// program that paid knows its payment failed for good, and it calls this
	/// on a definite failure alone, never while the payment is in flight or
	/// its state unknown: a lock left unmarked while its payment completes
	/// is claimed out of round only while the operator co-signs or serves the
	/// preimage. A separate command from `lock_paid`, so a library without it
	/// refuses the call rather than marking the lock paid.
	///
	/// Refused for a hash the wallet asked no lock under, and whenever the
	/// payment went through or may still: the lock claimed (by the wallet's
	/// record or the operator's), the preimage known (to the lock, the
	/// wallet's receive or payment under the hash, or served by the
	/// operator), a receive or payment of the wallet's recorded paid with no
	/// preimage, a payment of the wallet's own under the hash not definitely
	/// failed back (a Lightning payment through the operator not `failed`
	/// or `returned`; a BTC swap in any state but `offered`, `taken`,
	/// `lapsed`, `abandoned`, `btc_failed` or `cancelled`, a state it does
	/// not know included). Refused too once the lock's exit has started,
	/// which clearing the mark does not stop, and for a lock record in a
	/// state the wallet does not know. An operator that does not answer, or
	/// whose answer is not a lock status the wallet can read
	/// ([`lock_status_went_through`]), leaves the mark, with its error
	/// (unreachable, not a refusal): the caller asks again. A lock never
	/// marked paid is answered as it stands.
	pub fn lock_unpaid(&mut self, hash: &str) -> Result<Value, Error> {
		self.clear_lock_paid(hash, true)
	}

	/// [`Self::lock_unpaid`]; `swaps` false when the wallet's own BTC swap
	/// under the hash is the caller, having seen its payment fail for good.
	pub(crate) fn clear_lock_paid(&mut self, hash: &str, swaps: bool) -> Result<Value, Error> {
		let mut r = self.lock_rec("payee", hash)?.ok_or_else(|| Error::Refused(format!("the wallet asked no lock under hash {}", hash)))?;
		// A record in a state this wallet does not know says nothing of the
		// payment: the mark stays.
		if !matches!(r["state"].as_str(), Some("asked" | "held" | "claimed" | "refunded")) {
			return Err(Error::Refused(format!("the lock under hash {} is in a state this wallet does not know ({}): it stays marked as it is",
				hash, r["state"])));
		}
		let opens = |p: &str| super::chain::unhex32(p).is_ok_and(|b| hex(&sha256::Hash::hash(&b).to_byte_array()) == hash);
		let send = self.sends()?.get(hash).cloned();
		let receive = self.receives()?.get(hash).cloned();
		// The payment went through: a preimage that opens the hash, or a
		// record of the wallet's that says it was paid or received, with its
		// preimage or without.
		let known = [send.as_ref(), receive.as_ref()].into_iter().flatten().any(|v| v["preimage"].as_str().is_some_and(opens))
			|| send.as_ref().is_some_and(|s| s["state"] == "paid")
			|| receive.as_ref().is_some_and(|v| matches!(v["state"].as_str(), Some("received" | "claiming")));
		// A payment of the wallet's own under the hash ends nothing unless it
		// definitely failed back: any other state, a state the wallet does
		// not know or none, may still complete.
		let mut paying = send.as_ref().filter(|s| !matches!(s["state"].as_str(), Some("failed" | "returned")))
			.map(|s| format!("its Lightning payment through the operator is {}", s["state"].as_str().unwrap_or("of no known state")));
		if swaps && paying.is_none() {
			paying = self.btc_swaps_map()?.values().find(|s| s["hash"] == hash && !super::btc_swap::pays_nothing_more(s))
				.map(|s| format!("its BTC swap is {}", s["state"].as_str().unwrap_or("of no known state")));
		}
		// The lock's coin leaves `lock_in` once its exit starts: the record
		// names its leaf from the moment it was held.
		let leaf = match self.lock_row("payee", hash)? {
			Some(row) => Some(row.leaf_id),
			None => r["leaf_id"].as_str().map(String::from),
		};
		let exiting = match leaf {
			Some(l) => self.store.exit(&l)?.is_some(),
			None => false,
		};
		if let Some(why) = unpaid_refusal(hash, &r, known, paying.as_deref(), exiting) {
			return Err(Error::Refused(why));
		}
		let held = matches!(r["state"].as_str(), Some("asked" | "held"));
		if held && r["paid"] == true {
			// The operator serves the preimage once the payer posted it: the
			// payment went through whatever the caller saw. An operator that
			// does not answer leaves the mark, and its error is the answer, to
			// be asked again.
			let went = lock_status_went_through(&self.lock_status(hash)?, hash)?;
			if let Some(why) = unpaid_refusal(hash, &r, went, None, false) {
				return Err(Error::Refused(why));
			}
		}
		let was = r["paid"] == true;
		if was {
			r["paid"] = json!(false);
			r["unpaid_at"] = json!(wall_now());
			self.set_lock("payee", hash, r.clone())?;
		}
		Ok(json!({"payment_hash": hash, "paid": false, "was_paid": was, "state": r["state"]}))
	}

	/// Hands the payee's wallet the preimage of `hash`, learnt elsewhere (a
	/// BTC payment that settled): kept, posted to the operator, and the lock
	/// claimed at once when the wallet holds it.
	pub fn lock_preimage_known(&mut self, hash: &str, preimage: [u8; 32]) -> Result<Value, Error> {
		if hex(&sha256::Hash::hash(&preimage).to_byte_array()) != hash {
			return Err(Error::Refused(format!("the preimage does not open hash {}", hash)));
		}
		let mut rec = self.lock_rec("payee", hash)?.ok_or_else(|| Error::Refused(format!("the wallet asked no lock under hash {}", hash)))?;
		rec["preimage"] = json!(hex(&preimage));
		self.set_lock("payee", hash, rec)?;
		let _ = self.server.post("lock_preimage", &json!({"payment_hash": hash, "preimage": hex(&preimage)}));
		// The watchtowers have it too: should the wallet be gone before the
		// claim, a watchtower claims on the chain with it.
		let _ = self.towers_learn_preimage(hash, &preimage);
		match self.lock_row("payee", hash)? {
			Some(_) => self.lock_claim(hash, preimage),
			None => Ok(json!({"payment_hash": hash, "state": "preimage kept"})),
		}
	}
}

/// How long after a lock's timeout a payer's watchtower waits before it
/// takes a lock still open home on the chain, in seconds of median time: the
/// time the payer's wallet has to refund it out of round first.
pub const TOWER_REFUND_GRACE: u64 = 3_600;

/// The fees a lock's watchtower holds each ending at: the node's floor for
/// the ending when its wallet signed it, and twice, four and eight times
/// that. The watchtower broadcasts the cheapest the node takes then.
pub const ENDING_FEE_STEPS: [u64; 4] = [1, 2, 4, 8];

/// The id of the deposit of lock record `record` (binary form) for its
/// `role`'s side: the payee's and the payer's of one lock differ.
pub fn lock_deposit_id(record: &[u8], role: &str) -> [u8; 32] {
	super::tower::deposit_id(&[record, b"/lock/", role.as_bytes()].concat())
}

impl Wallet {
	/// The deposit of the lock coin `row` with a watchtower, `(id, body)`:
	/// the coin's record and the transactions it rests on, as any deposit,
	/// and the lock's ending signed beforehand by the key of the wallet's
	/// side, for the watchtower to broadcast while the wallet is away: the
	/// payee's CLAIM (its preimage, not under the signature, the watchtower
	/// puts in once it knows it) or the payer's REFUND, each paying to an
	/// on-chain address of the wallet's own, at each of [`ENDING_FEE_STEPS`].
	///
	/// Each ending is a signature of the message its path builds over its
	/// one output (`out` of the coin's asset to `to`), never an outpoint: it
	/// fits the leaf wherever the leaf's path brings it on the chain, however
	/// each step was paid for, and the watchtower adds a fee coin of its own
	/// when none pays the node's floor. `None` for a lock its side no longer
	/// holds open.
	pub(crate) fn lock_deposit(&mut self, row: &CoinRow) -> Result<Option<(String, Value)>, Error> {
		let role = if row.state == LOCK_IN { "payee" } else { "payer" };
		let record = Self::record_of(row)?;
		let (terms, ..) = lock_terms(&record).ok_or_else(|| Error::Refused("the coin is no lock".into()))?;
		let hash = hex(&terms.payment_hash);
		let mut rec = match self.lock_rec(role, &hash)? {
			Some(r) => r,
			None => return Ok(None),
		};
		let open = match role {
			"payee" => matches!(rec["state"].as_str(), Some("asked" | "held")),
			_ => matches!(rec["state"].as_str(), Some("locked" | "locking")),
		};
		if !open {
			return Ok(None);
		}
		let (_, a) = self.held(row)?;
		let coin = a.valid;
		let bytes = record.to_bytes().map_err(|e| Error::Refused(e.to_string()))?;
		let bases = self.accepted_bases(&record)?;
		let preimage = rec["preimage"].as_str().map(String::from);
		let id = hex(&lock_deposit_id(&bytes, role));
		// Signed once: an ending fits the leaf at any outpoint.
		if let Some((old_id, body)) = self.store.deposit(&row.leaf_id)? {
			let mut v: Value = serde_json::from_str(&body).map_err(|e| Error::Store(e.to_string()))?;
			if old_id == id && v["lock"]["endings"].as_array().is_some_and(|e| !e.is_empty()) && v["lock"]["leaf"].is_null() {
				if v["lock"]["preimage"].as_str() != preimage.as_deref() && preimage.is_some() {
					v["lock"]["preimage"] = json!(preimage);
				}
				return Ok(Some((id, v)));
			}
		}
		let key = self.coin_key(&row.owner_nonce)?;
		let index = match rec["tower_claim_index"].as_u64() {
			Some(i) => i as u32,
			None => {
				let i = self.store.take_index(super::keys::RECEIVE)?;
				rec["tower_claim_index"] = json!(i);
				self.set_lock(role, &hash, rec.clone())?;
				i
			},
		};
		let to = self.claim_script(&coin, index)?;
		let policy = coin.leaf.lock_policy().ok_or_else(|| Error::Refused("the coin is no lock".into()))?;
		let base = self.fee_for(coin.asset, super::exit::LOCK_ENDING_VSIZE)?.max(1);
		let mut endings = vec![];
		for k in ENDING_FEE_STEPS {
			let fee = base.saturating_mul(k);
			if fee >= coin.value {
				break;
			}
			let out = [ExplicitOutput::new(coin.asset, coin.value - fee, to.clone())];
			let m = if role == "payee" { policy.claim_message(coin.asset, coin.value, &out) } else { policy.refund_message(coin.asset, coin.value, &out) }
				.map_err(|e| Error::Refused(e.to_string()))?;
			endings.push(json!({"out": coin.value - fee, "sig": hex(sign(&key, &m.digest).as_ref())}));
		}
		if endings.is_empty() {
			return Err(Error::Refused(format!("the lock's {} atoms do not cover its ending's fee", coin.value)));
		}
		let block = self.server_info().ok().and_then(|i| i["lightning"]["receive"]["block_seconds"].as_u64()).unwrap_or(60).max(1);
		let act_from = match role {
			"payee" => self.lock_home(&coin, block)?,
			_ => terms.timeout.to_consensus_u32() as u64 + TOWER_REFUND_GRACE,
		};
		let body = json!({"genesis_hash": self.genesis.genesis_hash().to_string(), "record": hex(&bytes),
			"bases": bases.iter().map(|t| hex(&elements::encode::serialize(t))).collect::<Vec<_>>(),
			"lock": {"role": role, "payment_hash": hash, "holder": key.x_only_public_key().0.to_string(), "act_from": act_from,
				"to": hex(to.as_bytes()), "endings": endings, "preimage": preimage}});
		Ok(Some((id, body)))
	}

	/// Refreshes the deposit of every lock the wallet holds open
	/// ([`Self::lock_deposit`]): a deposit whose body changed is sent to
	/// every watchtower again. What could not be built is said.
	pub(crate) fn refresh_lock_deposits(&mut self) -> Result<Vec<Value>, Error> {
		let mut out = vec![];
		for state in [LOCK_IN, LOCK_OUT] {
			for row in self.store.coins_in(state)? {
				match self.lock_deposit(&row) {
					Ok(Some((id, body))) => {
						let text = body.to_string();
						if self.store.deposit(&row.leaf_id)?.is_none_or(|(i, b)| i != id || b != text) {
							self.store.put_deposit(&row.leaf_id, &id, &text)?;
							self.store.delete_deposit_sent_all(&row.leaf_id)?;
						}
					},
					Ok(None) => {},
					Err(e) => out.push(json!({"leaf_id": row.leaf_id, "error": format!("the lock's watchtower deposit: {}", e)})),
				}
			}
		}
		Ok(out)
	}

	/// Hands the preimage of `hash` to every watchtower the wallet names, for
	/// the locks it holds as payee under it: a watchtower that takes a lock
	/// home on the chain claims it with it. A watchtower that does not answer
	/// has it from the next deposit the wallet sends it.
	pub(crate) fn towers_learn_preimage(&mut self, hash: &str, preimage: &[u8; 32]) -> Vec<Value> {
		let named = self.tower_list().map(|(n, _)| n).unwrap_or_default();
		let body = json!({"payment_hash": hash, "preimage": hex(preimage)});
		named.iter().map(|t| match super::client::ServerClient::new(t).and_then(|c| c.post("lock_preimage", &body)) {
			Ok(v) => json!({"watchtower": t, "locks": v["locks"]}),
			Err(e) => json!({"watchtower": t, "error": e.to_string()}),
		}).collect()
	}
}

/// The nonce of the key that holds the coin `row` (the payee's, or the
/// payer's for the refund).
fn coin_nonce(row: &CoinRow) -> [u8; 32] {
	row.owner_nonce
}

#[cfg(test)]
mod test {
	use super::*;

	/// The payee refuses a lock the operator should not have co-signed.
	#[test]
	fn a_payee_checks_a_locks_depth_and_expiry_itself() {
		let t = 2_000_000_000u64;
		assert_eq!(lock_fits(3, Some(5), Some(t + 10_000), t, 4608, 3600), Ok(()));
		assert_eq!(lock_fits(4, Some(5), None, t, 4608, 3600), Ok(()));
		assert!(lock_fits(5, Some(5), None, t, 4608, 3600).unwrap_err().contains("depth limit of 5"));
		assert!(lock_fits(1, Some(5), Some(t + 8_207), t, 4608, 3600).unwrap_err().contains("expires"));
		assert_eq!(lock_fits(1, Some(5), Some(t + 8_208), t, 4608, 3600), Ok(()));
		assert!(lock_fits(1, Some(5), Some(t - 1), t, 4608, 3600).is_err());
	}

	/// The home date counts every transaction of the path, and never less
	/// than the specified hour.
	#[test]
	fn a_locks_home_date_counts_its_whole_path_and_at_least_the_hour() {
		let t = 2_000_000_000;
		// Three steps at 60 s blocks unroll in 360 s: the hour counts.
		assert_eq!(lock_home_date(t, 512, 3, 60, 3600), t - 3600 - 512 - 600);
		// Forty steps at 60 s blocks take 4,800 s: longer than the hour.
		assert_eq!(lock_home_date(t, 512, 40, 60, 3600), t - 4800 - 512 - 600);
		assert_eq!(lock_home_date(t, 512, 3, 600, 1800), t - 3600 - 512 - 600);
		assert_eq!(lock_home_date(100, 512, 3, 60, 3600), 0);
	}

	#[test]
	fn the_refund_nonce_is_the_creators_tagged() {
		let a = refund_nonce(&[1; 32]);
		assert_ne!(a, refund_nonce(&[2; 32]));
		assert_eq!(a, refund_nonce(&[1; 32]));
		assert_ne!(a, [1; 32]);
	}

	#[test]
	fn a_lock_is_recorded_refused_only_while_nothing_was_posted_or_the_operator_refused() {
		let server = Error::Server { call: "cosign_transfer".into(), status: 400, code: "refused".into(), message: "no".into() };
		assert!(lock_refused(&server, false), "the operator's refusal: nothing locked");
		assert!(lock_refused(&server, true));
		let mine = Error::Refused("the server's record of output L: bad".into());
		assert!(lock_refused(&mine, true), "the wallet's refusal before the post: every input live, nothing locked");
		assert!(!lock_refused(&mine, false), "the wallet's refusal after the post: the lock may stand, the request stands");
		assert!(!lock_refused(&Error::Unreachable("timeout".into()), true), "no answer: the request stands");
	}

	/// The paid mark is cleared only on a definite failure: never once the
	/// payment went through (the lock claimed, the preimage known anywhere),
	/// never while a payment of the wallet's under the hash may complete,
	/// never once the lock's exit has started.
	#[test]
	fn a_paid_mark_is_cleared_only_once_the_payment_failed_for_good() {
		let h = "ab".repeat(32);
		let paid = json!({"state": "held", "paid": true});
		assert_eq!(unpaid_refusal(&h, &paid, false, None, false), None, "failed for good: cleared");
		assert_eq!(unpaid_refusal(&h, &json!({"state": "held"}), false, None, false), None, "never marked: answered as it stands");
		assert_eq!(unpaid_refusal(&h, &json!({"state": "asked", "paid": true}), false, None, false), None);
		let claimed = unpaid_refusal(&h, &json!({"state": "claimed", "paid": true, "preimage": "00"}), false, None, false).unwrap();
		assert!(claimed.contains("is claimed"), "{}", claimed);
		let with_pre = unpaid_refusal(&h, &json!({"state": "held", "paid": true, "preimage": "00"}), false, None, false).unwrap();
		assert!(with_pre.contains("preimage") && with_pre.contains("is known"), "{}", with_pre);
		let elsewhere = unpaid_refusal(&h, &paid, true, None, false).unwrap();
		assert!(elsewhere.contains("is known"), "{}", elsewhere);
		let paying = unpaid_refusal(&h, &paid, false, Some("its BTC swap is paying"), false).unwrap();
		assert!(paying.contains("may still complete") && paying.contains("its BTC swap is paying"), "{}", paying);
		let exiting = unpaid_refusal(&h, &paid, false, None, true).unwrap();
		assert!(exiting.contains("exit has started"), "{}", exiting);
		assert_eq!(unpaid_refusal(&h, &json!({"state": "held"}), false, None, true), None, "never marked, exiting: nothing to clear");
		// The preimage outranks a payment still running: it went through.
		assert!(unpaid_refusal(&h, &paid, true, Some("x"), true).unwrap().contains("is known"));
	}

	/// Only a swap that will pay nothing more lets a mark be cleared: one
	/// paying, claiming, done, or in a state this wallet does not know (or
	/// none) may still pay or has paid.
	#[test]
	fn a_swap_pays_nothing_more_only_in_the_states_that_say_so() {
		for s in ["offered", "taken", "lapsed", "abandoned", "btc_failed", "cancelled"] {
			assert!(super::super::btc_swap::pays_nothing_more(&json!({"state": s})), "{}", s);
		}
		for s in ["paying", "claiming", "done", "locked", "claimed", "mystery", ""] {
			assert!(!super::super::btc_swap::pays_nothing_more(&json!({"state": s})), "{}", s);
		}
		assert!(!super::super::btc_swap::pays_nothing_more(&json!({})), "no state");
		assert!(!super::super::btc_swap::pays_nothing_more(&json!({"state": 3})), "a malformed state");
	}

	use super::super::wallet::{lock_status_for_tests as status, operator_answering, wallet_for_tests};

	const PRE: [u8; 32] = [0x42; 32];

	fn h() -> String {
		hex(&sha256::Hash::hash(&PRE).to_byte_array())
	}

	/// A wallet at `server` holding a lock under [`h`] marked paid.
	fn marked(server: &str) -> Wallet {
		let w = wallet_for_tests(server);
		w.set_lock("payee", &h(), json!({"role": "payee", "hash": h(), "state": "held", "paid": true})).unwrap();
		w
	}

	fn paid(w: &Wallet) -> Value {
		w.lock_rec("payee", &h()).unwrap().unwrap()["paid"].clone()
	}

	/// An operator that does not answer leaves the mark: its error is the
	/// answer, not a refusal, so the caller asks again.
	#[test]
	fn the_mark_stays_while_the_operator_cannot_be_asked() {
		let mut w = marked("http://127.0.0.1:1");
		match w.lock_unpaid(&h()) {
			Err(Error::Refused(why)) => panic!("refused, where the operator did not answer: {}", why),
			Err(e) => println!("lock_unpaid, the operator away: {}", e),
			Ok(v) => panic!("cleared with the operator away: {}", v),
		}
		assert_eq!(paid(&w), true, "still marked");
	}

	/// The operator serves the preimage (the payer posted it), or calls the
	/// lock claimed: the payment went through, whatever the caller saw.
	#[test]
	fn the_mark_stays_when_the_operator_serves_the_preimage_or_the_claim() {
		let mut w = marked(&operator_answering(status(&h(), &["open"], Some(hex(&PRE)))));
		let why = match w.lock_unpaid(&h()) { Err(Error::Refused(why)) => why, r => panic!("{:?}", r.map(|v| v.to_string())) };
		assert!(why.contains("is known"), "{}", why);
		assert_eq!(paid(&w), true);
		let mut w = marked(&operator_answering(status(&h(), &["claimed"], None)));
		assert!(matches!(w.lock_unpaid(&h()), Err(Error::Refused(_))), "the operator's claimed lock");
		assert_eq!(paid(&w), true);
	}

	/// An answer the wallet cannot read says nothing of the payment: not an
	/// object, no hash or another, no list of locks, a lock not of the
	/// operator's form or in a state the wallet does not know, a preimage
	/// that is not 32 bytes in hex or does not open the hash. Each is the
	/// operator's silence (unreachable, not a refusal, asked again), and the
	/// mark stays.
	#[test]
	fn the_mark_stays_on_an_operator_answer_it_cannot_read() {
		let mut mystery = status(&h(), &["open"], None);
		mystery["locks"][0]["state"] = json!("mystery");
		let mut no_leaf = status(&h(), &["open"], None);
		no_leaf["locks"][0].as_object_mut().unwrap().remove("leaf_id");
		let mut no_timeout = status(&h(), &["open"], None);
		no_timeout["locks"][0]["timeout"] = json!("soon");
		for answer in [json!({}), Value::Null, json!([]), json!("ok"), json!({"locks": [], "preimage": null}),
			json!({"payment_hash": "ab".repeat(32), "locks": []}), json!({"payment_hash": h(), "locks": "unreadable"}),
			json!({"payment_hash": h()}), mystery, no_leaf, no_timeout, json!({"payment_hash": h(), "locks": [null]}),
			status(&h(), &["open"], Some("zz".repeat(32))), status(&h(), &["open"], Some("ab".into())),
			status(&h(), &["open"], Some(hex(&[1; 32]))), json!({"payment_hash": h(), "locks": [], "preimage": 7})]
		{
			let mut w = marked(&operator_answering(answer.clone()));
			match w.lock_unpaid(&h()) {
				Err(Error::Unreachable(why)) => println!("{} -> {}", answer, why),
				r => panic!("{}: {:?}", answer, r.map(|v| v.to_string())),
			}
			assert_eq!(paid(&w), true, "still marked after {}", answer);
		}
	}

	/// A lock record in a state this wallet does not know keeps its mark,
	/// refused before the operator is asked.
	#[test]
	fn the_mark_stays_on_a_lock_state_the_wallet_does_not_know() {
		let op = operator_answering(status(&h(), &["open"], None));
		for st in [json!("mystery"), json!(7), Value::Null, json!(""), json!({"state": "held"})] {
			let mut w = wallet_for_tests(&op);
			let mut rec = json!({"role": "payee", "hash": h(), "paid": true});
			if !st.is_null() {
				rec["state"] = st.clone();
			}
			w.set_lock("payee", &h(), rec).unwrap();
			match w.lock_unpaid(&h()) {
				Err(Error::Refused(why)) => assert!(why.contains("does not know"), "{}: {}", st, why),
				r => panic!("{}: {:?}", st, r.map(|v| v.to_string())),
			}
			assert_eq!(paid(&w), true, "still marked in state {}", st);
		}
		// The states it knows: refunded is answered as it stands.
		let mut w = wallet_for_tests(&op);
		w.set_lock("payee", &h(), json!({"role": "payee", "hash": h(), "state": "refunded", "paid": true})).unwrap();
		assert_eq!(w.lock_unpaid(&h()).unwrap()["state"], "refunded");
	}

	/// The operator knows nothing of the payment: the mark is cleared, and
	/// asked again the lock is answered as it stands.
	#[test]
	fn the_mark_is_cleared_when_nothing_says_the_payment_went_through() {
		let op = operator_answering(status(&h(), &["open"], None));
		let mut w = marked(&op);
		let v = w.lock_unpaid(&h()).unwrap();
		assert_eq!((v["paid"].clone(), v["was_paid"].clone()), (json!(false), json!(true)), "{}", v);
		assert_eq!(paid(&w), false);
		assert_eq!(w.lock_unpaid(&h()).unwrap()["was_paid"], false);
	}

	/// A payment or swap of the wallet's under the hash that it cannot read
	/// as definitely failed keeps the mark: unknown, malformed or missing
	/// states, and a payment or receive recorded paid with no preimage.
	#[test]
	fn the_mark_stays_for_any_payment_or_swap_not_definitely_failed() {
		let op = operator_answering(status(&h(), &["open"], None));
		let refused = |set: &dyn Fn(&Wallet), want: &str| {
			let mut w = marked(&op);
			set(&w);
			match w.lock_unpaid(&h()) {
				Err(Error::Refused(why)) => assert!(why.contains(want), "wanted {:?}: {}", want, why),
				r => panic!("not refused (wanted {:?}): {:?}", want, r.map(|v| v.to_string())),
			}
			assert_eq!(paid(&w), true);
		};
		refused(&|w| w.set_send(&h(), json!({"state": "paid"})).unwrap(), "is known");
		refused(&|w| w.set_send(&h(), json!({"state": "paying"})).unwrap(), "may still complete");
		refused(&|w| w.set_send(&h(), json!({})).unwrap(), "of no known state");
		refused(&|w| w.set_send(&h(), json!({"state": "mystery"})).unwrap(), "may still complete");
		refused(&|w| w.set_receive(&h(), json!({"state": "received"})).unwrap(), "is known");
		refused(&|w| w.set_receive(&h(), json!({"state": "waiting", "preimage": hex(&PRE)})).unwrap(), "is known");
		for st in [json!("paying"), json!("claiming"), json!("done"), json!("mystery"), json!(7), Value::Null] {
			refused(&|w| w.set_btc_swap("s1", json!({"id": "s1", "role": "Q", "hash": h(), "state": st.clone()})).unwrap(), "may still complete");
		}
		// What definitely failed back, or never paid, lets it go.
		for (send, swap) in [(json!({"state": "failed"}), json!("taken")), (json!({"state": "returned"}), json!("btc_failed"))] {
			let mut w = marked(&op);
			w.set_send(&h(), send).unwrap();
			w.set_btc_swap("s1", json!({"id": "s1", "role": "Q", "hash": h(), "state": swap})).unwrap();
			assert_eq!(w.lock_unpaid(&h()).unwrap()["was_paid"], true);
		}
	}

	#[test]
	fn a_payers_lock_stands_unless_it_was_refused() {
		assert!(!lock_stands(&json!({"state": "refused"})));
		for s in ["locking", "locked", "claimed", "refunded"] {
			assert!(lock_stands(&json!({"state": s})), "{}", s);
		}
	}
}
