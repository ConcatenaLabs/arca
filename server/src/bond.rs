//! The operator's equivocation bond, as the server posts and names it.
//!
//! The bond ([`arca_covenant::bond`]) is a coin anyone burns with two
//! different messages the operator key `S` signed under one coin's salt. The
//! signer never signs two ([`crate::signer`]), so an honest operator's bond
//! is never burned; a wallet that receives a coin out of round checks the
//! bond first, on its own node.
//!
//! Its terms are the `[bond]` section of the configuration: the withdrawal
//! key `W` (never `S`, which the signer would sign for), the notice delay `D`
//! in 512-second units, the bond coin's `outpoint` once posted, and the
//! notice output's (`notice`) once a notice is given. `D` is at least a
//! coin's service life (a batch's lifetime, a board's, and the service
//! horizon of a batch without a sweep, whichever is longest), plus the
//! longest exit delay, plus a day ([`min_notice_seconds`]): after a notice
//! every wallet brings each coin it holds out of round into a round by that
//! coin's exit deadline, which falls within a service life of the notice
//! (a coin resting on a batch without a sweep that its holder leaves is
//! brought on the chain by the operator at the batch's horizon, so nothing
//! paid out of round outlives it), and the rest covers a coin taken home on
//! the chain instead and a slash's own confirmation. The server refuses to
//! start with a shorter one.
//!
//! `info.bond` names the bond as the server's node shows it now
//! ([`view`]): where the coin stands (`unposted`, `missing`, `unconfirmed`,
//! `bonded`, `noticed`, `spent`), its asset and value, its value in the
//! reference unit at the operator's rate for its asset, the key it binds, the
//! withdrawal key, the delay and the two scripts; in notice, the notice
//! output and when the bond can first be withdrawn. A bond coin spent other
//! than into the notice output the configuration names reads as `spent`: a
//! notice the operator does not name still reads as no bond.
//!
//! The operator posts the bond by paying its address from a node wallet it
//! names (`arcad <config> bond-post`), never one whose name marks it a
//! treasury, reserve, bridge, escrow or another service's
//! ([`refused_wallet`]), and gives the notice and the withdrawal with `W`'s
//! key from its file (`bond-notice`, `bond-withdraw`), the fee from the
//! operator's on-chain wallet.

use std::str::FromStr;
use std::sync::Arc;

use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, OutPoint, Transaction, Txid};
use serde::Deserialize;

use arca_covenant::{BondPolicy, Chain, RelativeTime};

use crate::chain::{ChainError, ChainSource, FinalityService};

/// The longest a coin the operator makes lives from its round or board to
/// its first expiry, in seconds: a batch's and a board's lifetime, and the
/// default service horizon of a batch without a sweep
/// ([`crate::params::COLLECT_AFTER_SECONDS`]).
pub const LIFETIME: u32 = 28 * 86_400;

/// The time a notice leaves beyond a lifetime and the longest exit delay,
/// in seconds: a slash's own confirmation.
pub const SLASH_MARGIN: u32 = 86_400;

/// The least notice delay, in seconds, for coins that live `lifetime` with
/// exit delays up to `max_exit`.
pub fn min_notice_seconds(lifetime: u32, max_exit: RelativeTime) -> u64 {
	lifetime as u64 + max_exit.seconds() + SLASH_MARGIN as u64
}

/// The `[bond]` section of the configuration.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BondSection {
	/// `W`, the withdrawal key, x-only hex.
	pub withdraw_key: String,
	/// `D`, the notice delay, in 512-second units.
	pub notice_units: u16,
	/// The bond coin, `txid:vout`, once posted.
	#[serde(default)]
	pub outpoint: Option<String>,
	/// The notice output, `txid:vout`, once a notice is given.
	#[serde(default)]
	pub notice: Option<String>,
}

/// The bond the configuration names: its policy and where its coins are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bond {
	pub policy: BondPolicy,
	pub outpoint: Option<OutPoint>,
	pub notice: Option<OutPoint>,
}

/// `txid:vout`, as the configuration and `info` write an outpoint.
pub fn outpoint_text(op: &OutPoint) -> String {
	format!("{}:{}", op.txid, op.vout)
}

/// `txid:vout`.
pub fn parse_outpoint(s: &str) -> Result<OutPoint, String> {
	let (t, v) = s.split_once(':').ok_or_else(|| format!("{:?} is not txid:vout", s))?;
	Ok(OutPoint::new(Txid::from_str(t).map_err(|e| format!("{:?}: {}", t, e))?, v.parse().map_err(|e| format!("{:?}: {}", v, e))?))
}

impl Bond {
	/// The bond of `s` on `chain` for the operator key `operator`, whose
	/// coins live `lifetime` seconds with exit delays up to `max_exit`.
	pub fn from_section(s: &BondSection, chain: Chain, operator: XOnlyPublicKey, lifetime: u32, max_exit: RelativeTime)
		-> Result<Bond, String>
	{
		let w = XOnlyPublicKey::from_str(&s.withdraw_key).map_err(|e| format!("withdraw_key: {}", e))?;
		let d = RelativeTime::from_units(s.notice_units).map_err(|e| format!("notice_units: {}", e))?;
		let least = min_notice_seconds(lifetime, max_exit);
		if d.seconds() < least {
			return Err(format!("notice_units: a notice of {} s is shorter than a coin's lifetime, the longest exit delay and a day, {} s \
				({} units): a coin paid out of round before the notice could outlive the bond", d.seconds(), least, least.div_ceil(512)));
		}
		let policy = BondPolicy::new(chain, operator, w, d).map_err(|e| e.to_string())?;
		Ok(Bond {
			policy,
			outpoint: s.outpoint.as_deref().map(parse_outpoint).transpose().map_err(|e| format!("outpoint: {}", e))?,
			notice: s.notice.as_deref().map(parse_outpoint).transpose().map_err(|e| format!("notice: {}", e))?,
		})
	}
}

/// Where the bond stands on the server's node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
	/// `unposted`, `missing`, `unconfirmed`, `bonded`, `noticed` or `spent`.
	pub state: &'static str,
	pub asset: Option<AssetId>,
	pub value: Option<u64>,
	/// Whether the coin that stands (the bond, or in notice the notice
	/// output) is final: certified, its anchor buried.
	pub final_: bool,
	/// In notice: the median time from which the withdrawal can confirm.
	pub withdrawable_at: Option<u64>,
	/// What the state rests on.
	pub why: String,
}

impl View {
	fn of(state: &'static str, why: impl Into<String>) -> View {
		View { state, asset: None, value: None, final_: false, withdrawable_at: None, why: why.into() }
	}
}

/// The output `op` of a transaction the node holds, if it is at `spk` with
/// an explicit asset and value.
fn output_at(c: &dyn ChainSource, op: &OutPoint, spk: &elements::Script) -> Result<Result<(AssetId, u64, Transaction), String>, ChainError> {
	let Some(tx) = c.transaction(&op.txid)? else { return Ok(Err(format!("the node holds no transaction {}", op.txid))) };
	let Some(o) = tx.output.get(op.vout as usize) else { return Ok(Err(format!("{} has no output {}", op.txid, op.vout))) };
	if o.script_pubkey != *spk {
		return Ok(Err(format!("{} is not at the bond's script for these terms", outpoint_text(op))));
	}
	match (o.asset.explicit(), o.value.explicit()) {
		(Some(a), Some(v)) => Ok(Ok((a, v, tx))),
		_ => Ok(Err(format!("{} hides its asset or value, which no slash can burn", outpoint_text(op)))),
	}
}

/// The median time from which a coin of `txid`, in a block, can be spent
/// under the relative lock `d` (BIP68: the median time of the block before
/// its own, plus `d`).
fn unlocks_at(c: &dyn ChainSource, txid: &Txid, d: RelativeTime) -> Result<Option<u64>, ChainError> {
	let Some(block) = c.tx_block(txid)? else { return Ok(None) };
	let h = c.header(&block)?;
	let Some(prev) = h.prev else { return Ok(None) };
	Ok(Some(c.header(&prev)?.median_time + d.seconds()))
}

/// Where `bond` stands on the node now: see the [module documentation](self).
pub fn read(c: &dyn ChainSource, bond: &Bond) -> Result<View, ChainError> {
	let p = &bond.policy;
	let Some(op) = bond.outpoint else { return Ok(View::of("unposted", "no bond coin is configured")) };
	let (asset, value, _) = match output_at(c, &op, &p.script_pubkey())? {
		Ok(x) => x,
		Err(why) => return Ok(View::of("missing", why)),
	};
	let mut v = View { asset: Some(asset), value: Some(value), ..View::of("bonded", format!("{} is unspent", outpoint_text(&op))) };
	if c.unspent(&op, false)?.is_some() {
		return Ok(v);
	}
	if c.tx_block(&op.txid)?.is_none() {
		v.state = "unconfirmed";
		v.why = format!("{} is in no block", op.txid);
		return Ok(v);
	}
	let Some(n) = bond.notice else {
		v.state = "spent";
		v.why = format!("{} is spent, and no notice is configured", outpoint_text(&op));
		return Ok(v);
	};
	let notice = match output_at(c, &n, &p.notice_script_pubkey())? {
		Ok((a, nv, tx)) if a == asset && nv == value && tx.input.iter().any(|i| i.previous_output == op) => tx,
		Ok(_) => {
			v.state = "spent";
			v.why = format!("{} is spent, and the notice output {} configured does not take it whole", outpoint_text(&op), outpoint_text(&n));
			return Ok(v);
		},
		Err(why) => {
			v.state = "spent";
			v.why = format!("{} is spent; the notice configured: {}", outpoint_text(&op), why);
			return Ok(v);
		},
	};
	if c.unspent(&n, false)?.is_some() {
		v.state = "noticed";
		v.withdrawable_at = unlocks_at(c, &notice.txid(), p.notice)?;
		v.why = format!("{} is unspent, the bond in notice", outpoint_text(&n));
	} else {
		v.state = "spent";
		v.why = format!("the notice output {} is spent: withdrawn or burned", outpoint_text(&n));
	}
	Ok(v)
}

/// [`read`], with finality: the coin that stands, watched and checked.
pub async fn view(finality: &Arc<FinalityService>, bond: &Bond) -> Result<View, ChainError> {
	let b = bond.clone();
	let mut v = finality.call(move |c| read(c, &b)).await?;
	let standing = match v.state {
		"bonded" => bond.outpoint,
		"noticed" => bond.notice,
		_ => None,
	};
	if let Some(op) = standing {
		v.final_ = finality.watch(op.txid, "bond").await.map(|f| f.is_final()).unwrap_or(false);
	}
	Ok(v)
}

/// Whether a node wallet named `name` may never post a bond, and why: a
/// treasury, a reserve, a bridge's, an escrow, or another service's.
pub fn refused_wallet(name: &str) -> Option<&'static str> {
	let n = name.to_ascii_lowercase();
	const MARKS: [(&str, &str); 12] = [
		("treasury", "a treasury"), ("reserve", "a reserve"), ("bridge", "a bridge's"), ("sbtc", "a bridge's"),
		("escrow", "an escrow"), ("service", "another service's"), ("faucet", "another service's"),
		("compages", "another service's"), ("seqpal", "another service's"), ("beacon", "another service's"),
		("pignus", "another service's"), ("levo", "another service's"),
	];
	MARKS.iter().find(|(m, _)| n.contains(m)).map(|(_, why)| *why)
}

/// Draws a new withdrawal key into `path`, a file only its owner can read,
/// refusing one that exists, and returns its x-only public key: what
/// `[bond] withdraw_key` names. Keep the file off the server, with its
/// backup: it alone gives the notice and withdraws the bond.
pub fn new_key(path: &std::path::Path) -> Result<XOnlyPublicKey, String> {
	use std::io::Write;
	use std::os::unix::fs::OpenOptionsExt;
	let mut secret = [0u8; 32];
	let key = loop {
		rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
		if let Ok(k) = elements::secp256k1_zkp::Keypair::from_seckey_slice(&elements::secp256k1_zkp::Secp256k1::new(), &secret) {
			break k;
		}
	};
	let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
		.map_err(|e| format!("{}: {}", path.display(), e))?;
	let hex: String = secret.iter().map(|b| format!("{:02x}", b)).collect();
	f.write_all(format!("{}\n", hex).as_bytes()).and_then(|_| f.sync_all()).map_err(|e| format!("{}: {}", path.display(), e))?;
	Ok(key.x_only_public_key().0)
}

#[cfg(test)]
mod test {
	use super::*;
	use elements::hashes::Hash;

	fn key(b: u8) -> XOnlyPublicKey {
		let k = elements::secp256k1_zkp::Keypair::from_seckey_slice(&elements::secp256k1_zkp::Secp256k1::new(), &[b; 32]).unwrap();
		k.x_only_public_key().0
	}

	#[test]
	fn the_notice_outlasts_a_lifetime_and_an_exit() {
		let max = RelativeTime::from_units(338).unwrap();
		assert_eq!(min_notice_seconds(LIFETIME, max), 28 * 86_400 + 338 * 512 + 86_400);
		let chain = Chain::new(elements::BlockHash::from_byte_array([1; 32]));
		let s = |units: u16| BondSection { withdraw_key: key(2).to_string(), notice_units: units, outpoint: None, notice: None };
		let least = min_notice_seconds(LIFETIME, max).div_ceil(512) as u16;
		assert!(Bond::from_section(&s(least - 1), chain, key(1), LIFETIME, max).unwrap_err().contains("shorter"));
		assert!(Bond::from_section(&s(least), chain, key(1), LIFETIME, max).is_ok());
		let same = BondSection { withdraw_key: key(1).to_string(), ..s(least) };
		assert!(Bond::from_section(&same, chain, key(1), LIFETIME, max).unwrap_err().contains("operator key"));
	}

	#[test]
	fn service_wallets_never_post() {
		for n in ["treasury2026", "sbtc-reserve", "bridge", "seqpal-escrow", "pignus-beacon-1", "faucet", "my-service"] {
			assert!(refused_wallet(n).is_some(), "{}", n);
		}
		for n in ["recovered", "operator", "bond"] {
			assert!(refused_wallet(n).is_none(), "{}", n);
		}
	}
}
