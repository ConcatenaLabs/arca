//! Watchtowers for coins on a Bitcoin ark: a coin whose holder is away is
//! brought on chain before its expiry, and paid to the holder's own address.
//!
//! On a Bitcoin ark the operator may sweep every tree output above a coin from
//! the coin's `expiry_height`. The coin's own output has no sweep clause: once
//! every transaction above it is confirmed, it is its holder's alone. Every
//! one of those transactions is already signed (the coin's `Vtxo<Full>` holds
//! them), each is a zero-fee v3 transaction with a pay-to-anchor (P2A)
//! output, and the anchor can be spent by anyone. So whoever holds the coin's
//! data can bring it on chain and choose nothing but the fee.
//!
//! **The deposit** a wallet gives each tower it names, for each coin worth
//! rescuing ([worth_rescuing]):
//! - the coin's `Vtxo<Full>`;
//! - a **claim** the holder signs ahead of time: a v3 transaction spending the
//!   coin's output by its exit clause (holder's key after the exit delta),
//!   paying the coin less a fixed rescue fee to the holder's own address, the
//!   rescue fee to the tower's payout address, and a zero-value P2A anchor.
//!   It pays no fee itself; the tower pays it through the anchor.
//!
//! The claim is signed `SIGHASH_DEFAULT`, which pins its one input, every
//! output and every amount. It moves that one coin to the holder's address
//! and the tower's fee, and nothing else; a claim with any output changed
//! fails its signature check.
//!
//! **The tower** ([tower::Tower], not on wasm) checks each deposit (the coin's
//! signatures against its anchor on chain, the claim's signature, its fee,
//! its anchor and its payout), and passes over its deposits at every block:
//! - from `expiry − M` ([RESCUE_MARGIN]) it broadcasts the coin's exit
//!   transactions level by level, each with a child spending its anchor,
//!   paid from the tower's own coins;
//! - once the coin's output is confirmed and its exit delta has passed, it
//!   broadcasts the claim with a child spending the claim's anchor;
//! - at once, whatever the expiry, when a coin paid out of round has an
//!   earlier holder's coin on chain (the transaction before one of the coin's
//!   arkoor levels, [ark::Vtxo::arkoor_levels]): that holder could claim it
//!   after their exit delta, so the rest of the coin's path must follow
//!   within it.
//!
//! A deposit is dropped when the holder withdraws it (a signature by the
//! coin's key over [withdraw_digest]) or replaces it with another claim for
//! the same coin. A deposit left behind for a coin its holder gave up costs
//! the tower its children's fees: the operator answers the old coin with the
//! forfeit or checkpoint its holder signed, and the claim then has nothing to
//! spend. The holder loses nothing.

#[cfg(all(not(target_arch = "wasm32"), feature = "onchain-bdk", feature = "sqlite"))]
pub mod tower;

use std::str::FromStr;

use anyhow::{anyhow, bail, Context};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{schnorr, Keypair, Message, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use bitcoin::transaction::Version;
use bitcoin::{absolute, Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness};
use serde_json::{json, Value};

use ark::{ProtocolEncoding, Vtxo, VtxoPolicy, SECP};
use ark::vtxo::Full;
use ark::vtxo::policy::clause::TapScriptClause;
use bitcoin_ext::fee::P2A_SCRIPT;

/// The blocks before a coin's expiry from which a tower brings it on chain: a
/// day, one block per level of the coin's exit with room for fees to rise.
pub const RESCUE_MARGIN: u32 = 144;

/// A coin is deposited when it is worth at least this many times its rescue
/// cost at the day's fast fee rate.
pub const WORTH_FACTOR: u64 = 20;

/// The virtual size a child spending a P2A anchor and one coin of the payer's
/// takes, about Bark's canonical child.
pub const CHILD_VB: u64 = 152;

/// The tag of the digest a coin's key signs to withdraw a deposit.
pub const WITHDRAW_TAG: &[u8] = b"Arca/btc-tower-withdraw";

/// The kind a tower's `info` names, so a wallet can tell a Bitcoin ark's
/// tower from an Arca one.
pub const KIND: &str = "bitcoin-ark-watchtower";

/// What a tower states in its `info`: the network it watches, where its
/// rescue fee goes, the least rate a deposit's fee must cover, and the arks
/// (their server keys) whose coins it takes; empty, any ark's.
#[derive(Debug, Clone)]
pub struct TowerTerms {
	pub network: Network,
	pub payout: Address,
	pub min_rate: FeeRate,
	pub margin: u32,
	pub arks: Vec<bitcoin::secp256k1::PublicKey>,
}

impl TowerTerms {
	/// The terms in a tower's `info` answer.
	pub fn from_info(info: &Value) -> anyhow::Result<TowerTerms> {
		if info["kind"].as_str() != Some(KIND) {
			bail!("it is not a Bitcoin ark watchtower");
		}
		let network = Network::from_str(info["network"].as_str().context("no network")?)
			.map_err(|e| anyhow!("network: {}", e))?;
		let payout = Address::from_str(info["payout"].as_str().context("no payout")?)
			.context("payout")?.require_network(network).context("payout is for another network")?;
		let min_rate = FeeRate::from_sat_per_vb(info["min_rate_sat_vb"].as_u64().context("no min_rate_sat_vb")?)
			.context("min_rate_sat_vb")?;
		let margin = info["margin"].as_u64().unwrap_or(RESCUE_MARGIN as u64) as u32;
		let arks = info["arks"].as_array().map(|a| a.iter().filter_map(|k| k.as_str())
			.filter_map(|k| bitcoin::secp256k1::PublicKey::from_str(k).ok()).collect()).unwrap_or_default();
		Ok(TowerTerms { network, payout, min_rate, margin, arks })
	}

	/// Whether the tower takes coins of the ark whose server key is `server`.
	pub fn watches(&self, server: &bitcoin::secp256k1::PublicKey) -> bool {
		self.arks.is_empty() || self.arks.contains(server)
	}
}

/// The coin's exit clause: its holder's key after its exit delta. Only coins
/// held by a plain key have one a tower can be given.
pub fn exit_clause(vtxo: &Vtxo<Full>) -> anyhow::Result<ark::vtxo::policy::clause::DelayedSignClause> {
	match vtxo.policy() {
		VtxoPolicy::Pubkey(p) => Ok(p.user_pubkey_claim_clause(vtxo.exit_delta())),
		_ => bail!("only a coin held by a plain key can be deposited"),
	}
}

/// The virtual size of the claim, signed.
fn claim_vbytes(vtxo: &Vtxo<Full>) -> anyhow::Result<u64> {
	let clause = exit_clause(vtxo)?;
	// outputs sized as the longest common address, a taproot one
	let p2tr = ScriptBuf::from_bytes([&[0x51u8, 0x20][..], &[0u8; 32][..]].concat());
	let dummy = template(vtxo, &p2tr, &p2tr, Amount::from_sat(330))?;
	let base = dummy.base_size() as u64;
	let wit = clause.witness_size(vtxo) as u64;
	// a segwit transaction: 4 per base byte, 1 per witness byte, plus marker and flag
	Ok((base * 4 + wit + 2).div_ceil(4))
}

/// The virtual bytes a rescue puts on chain: every exit transaction with its
/// child, and the claim with its child.
pub fn rescue_vbytes(vtxo: &Vtxo<Full>) -> anyhow::Result<u64> {
	let exits: u64 = vtxo.transactions().map(|i| i.tx.weight().to_vbytes_ceil() + CHILD_VB).sum();
	Ok(exits + claim_vbytes(vtxo)? + CHILD_VB)
}

/// What a rescue costs at `rate`.
pub fn rescue_cost(vtxo: &Vtxo<Full>, rate: FeeRate) -> anyhow::Result<Amount> {
	Ok(Amount::from_sat(rescue_vbytes(vtxo)?.saturating_mul(rate.to_sat_per_vb_ceil())))
}

/// Whether a coin is worth a deposit: at least [WORTH_FACTOR] times its rescue
/// cost at `fast`, the day's fast rate.
pub fn worth_rescuing(vtxo: &Vtxo<Full>, fast: FeeRate) -> bool {
	match rescue_cost(vtxo, fast) {
		Ok(c) => vtxo.amount().to_sat() >= c.to_sat().saturating_mul(WORTH_FACTOR),
		Err(_) => false,
	}
}

/// The rescue fee a deposit with `terms` carries: the rescue's cost at the
/// higher of `fast` and the tower's least rate.
pub fn rescue_fee(vtxo: &Vtxo<Full>, terms: &TowerTerms, fast: FeeRate) -> anyhow::Result<Amount> {
	rescue_cost(vtxo, fast.max(terms.min_rate))
}

fn template(vtxo: &Vtxo<Full>, holder: &ScriptBuf, payout: &ScriptBuf, fee: Amount) -> anyhow::Result<Transaction> {
	let clause = exit_clause(vtxo)?;
	let rest = vtxo.amount().checked_sub(fee).context("the fee is more than the coin")?;
	Ok(Transaction {
		version: Version(3),
		lock_time: absolute::LockTime::ZERO,
		input: vec![TxIn {
			previous_output: vtxo.point(),
			script_sig: ScriptBuf::new(),
			sequence: clause.sequence(),
			witness: Witness::new(),
		}],
		output: vec![
			TxOut { value: rest, script_pubkey: holder.clone() },
			TxOut { value: fee, script_pubkey: payout.clone() },
			TxOut { value: Amount::ZERO, script_pubkey: P2A_SCRIPT.clone() },
		],
	})
}

/// The unsigned claim: the coin to `holder` less `fee`, `fee` to `payout`, and
/// a zero-value anchor; no fee of its own.
pub fn claim_template(vtxo: &Vtxo<Full>, holder: &Address, payout: &Address, fee: Amount) -> anyhow::Result<Transaction> {
	let tx = template(vtxo, &holder.script_pubkey(), &payout.script_pubkey(), fee)?;
	if tx.output[0].value < Amount::from_sat(330) {
		bail!("the coin is too small to leave anything after the rescue fee");
	}
	Ok(tx)
}

/// The sighash the holder's key signs for input 0 of `tx` spending `vtxo` by
/// its exit clause.
fn claim_sighash(vtxo: &Vtxo<Full>, tx: &Transaction) -> anyhow::Result<(Message, ScriptBuf, ControlBlock)> {
	let clause = exit_clause(vtxo)?;
	let script = clause.tapscript();
	let cb = clause.control_block(vtxo);
	let leaf = TapLeafHash::from_script(&script, LeafVersion::TapScript);
	let prevouts = [vtxo.txout()];
	let sh = SighashCache::new(tx).taproot_script_spend_signature_hash(0, &Prevouts::All(&prevouts), leaf, TapSighashType::Default)
		.context("sighash")?;
	Ok((Message::from_digest(sh.to_byte_array()), script, cb))
}

/// Signs the claim with the coin's key.
pub fn sign_claim(vtxo: &Vtxo<Full>, tx: &mut Transaction, key: &Keypair) -> anyhow::Result<()> {
	if key.public_key() != vtxo.user_pubkey() {
		bail!("the key is not the coin's");
	}
	let (msg, script, cb) = claim_sighash(vtxo, tx)?;
	let sig = SECP.sign_schnorr_no_aux_rand(&msg, key);
	tx.input[0].witness = Witness::from_slice(&[&sig[..], script.as_bytes(), &cb.serialize()[..]]);
	Ok(())
}

/// Checks a claim as a tower takes it: it spends exactly the coin's output by
/// the holder's exit clause, under a valid signature by the coin's key, pays
/// no fee of its own, carries one zero-value anchor, and pays at least
/// `min_fee` to `payout`. Returns what it pays the tower.
pub fn check_claim(vtxo: &Vtxo<Full>, tx: &Transaction, payout: &ScriptBuf, min_fee: Amount) -> anyhow::Result<Amount> {
	if tx.version != Version(3) {
		bail!("the claim is not a v3 transaction");
	}
	if tx.input.len() != 1 || tx.input[0].previous_output != vtxo.point() {
		bail!("the claim does not spend exactly the coin");
	}
	let clause = exit_clause(vtxo)?;
	if tx.input[0].sequence != clause.sequence() {
		bail!("the claim's sequence is not the coin's exit delta");
	}
	let out: Amount = tx.output.iter().map(|o| o.value).sum();
	if out != vtxo.amount() {
		bail!("the claim must pay no fee of its own (outputs {} of a coin of {})", out, vtxo.amount());
	}
	let anchors = tx.output.iter().filter(|o| o.script_pubkey == *P2A_SCRIPT).count();
	if anchors != 1 || tx.output.iter().any(|o| o.script_pubkey == *P2A_SCRIPT && o.value != Amount::ZERO) {
		bail!("the claim needs exactly one zero-value anchor");
	}
	let paid: Amount = tx.output.iter().filter(|o| o.script_pubkey == *payout).map(|o| o.value).sum();
	if paid < min_fee {
		bail!("the claim pays the tower {} where a rescue of this coin costs {}", paid, min_fee);
	}
	let w = &tx.input[0].witness;
	if w.len() != 3 {
		bail!("the claim is not signed by the exit clause");
	}
	let (msg, script, cb) = claim_sighash(vtxo, tx)?;
	if w.nth(1) != Some(script.as_bytes()) || w.nth(2) != Some(&cb.serialize()[..]) {
		bail!("the claim does not spend by the holder's exit clause");
	}
	let sig = schnorr::Signature::from_slice(w.nth(0).unwrap_or(&[])).context("the claim's signature")?;
	let (pk, _) = vtxo.user_pubkey().x_only_public_key();
	SECP.verify_schnorr(&sig, &msg, &pk).map_err(|_| anyhow!("the claim's signature is not the coin's key's"))?;
	Ok(paid)
}

/// What a coin's key signs to withdraw the deposit whose claim is `claim`:
/// `SHA256(T ‖ T ‖ network magic ‖ claim txid)`, `T = SHA256(WITHDRAW_TAG)`.
/// It names one claim, so it withdraws that deposit at any tower and nothing
/// else.
pub fn withdraw_digest(network: Network, claim: &Txid) -> [u8; 32] {
	let t = sha256::Hash::hash(WITHDRAW_TAG);
	let mut e = sha256::Hash::engine();
	e.input(t.as_byte_array());
	e.input(t.as_byte_array());
	e.input(&network.magic().to_bytes());
	e.input(claim.as_byte_array());
	sha256::Hash::from_engine(e).to_byte_array()
}

/// The body of a withdrawal of the deposit of `claim`, signed by the coin's key.
pub fn withdrawal(network: Network, vtxo: &Vtxo<Full>, claim: &Txid, key: &Keypair) -> anyhow::Result<Value> {
	if key.public_key() != vtxo.user_pubkey() {
		bail!("the key is not the coin's");
	}
	let sig = SECP.sign_schnorr_no_aux_rand(&Message::from_digest(withdraw_digest(network, claim)), key);
	Ok(json!({"claim_txid": claim.to_string(), "sig": sig.to_string()}))
}

/// Checks a withdrawal's signature against the coin's key.
pub fn check_withdrawal(network: Network, user: &XOnlyPublicKey, claim: &Txid, sig: &str) -> anyhow::Result<()> {
	let sig = schnorr::Signature::from_str(sig).context("the signature")?;
	SECP.verify_schnorr(&sig, &Message::from_digest(withdraw_digest(network, claim)), user)
		.map_err(|_| anyhow!("the withdrawal is not signed by the coin's key"))
}

/// The body of a deposit.
pub fn deposit_body(vtxo: &Vtxo<Full>, claim: &Transaction) -> Value {
	json!({
		"vtxo": bitcoin::hex::DisplayHex::to_lower_hex_string(&vtxo.serialize()[..]),
		"claim": bitcoin::consensus::encode::serialize_hex(claim),
		"expiry_height": vtxo.expiry_height(),
	})
}

/// A deposit for one tower: the claim built and signed with the coin's key.
pub fn make_deposit(
	vtxo: &Vtxo<Full>,
	key: &Keypair,
	holder: &Address,
	terms: &TowerTerms,
	fast: FeeRate,
) -> anyhow::Result<(Value, Txid)> {
	if !terms.watches(&vtxo.server_pubkey()) {
		bail!("the tower does not watch this coin's ark");
	}
	let fee = rescue_fee(vtxo, terms, fast)?;
	let mut tx = claim_template(vtxo, holder, &terms.payout, fee)?;
	sign_claim(vtxo, &mut tx, key)?;
	let txid = tx.compute_txid();
	Ok((deposit_body(vtxo, &tx), txid))
}

/// The coin's outpoint, the one every claim spends.
pub fn coin_point(vtxo: &Vtxo<Full>) -> OutPoint {
	vtxo.point()
}

/// A deposit a tower holds for this wallet, as the program running the
/// wallet keeps it: the tower's URL, the coin's id and the claim's txid.
#[derive(Debug, Clone)]
pub struct Deposited {
	pub tower: String,
	pub vtxo: String,
	pub claim_txid: String,
}

impl crate::Wallet {
	/// What to send the towers named in `towers` (each with its terms from its
	/// `info`): a deposit for each coin worth rescuing at `fast` that a tower
	/// watching its ark does not hold yet, its claim paying `holder`; a
	/// withdrawal for each of `deposited` whose coin the wallet no longer
	/// holds in the ark; which coins are covered and by whom, which are too
	/// small to rescue, and which are within `2 × M` of expiry and so due for
	/// a refresh while the wallet is open.
	pub async fn btc_tower_plan(
		&self,
		holder: &Address,
		towers: &[(String, TowerTerms)],
		deposited: &[Deposited],
		fast: FeeRate,
	) -> anyhow::Result<Value> {
		use std::collections::HashSet;
		use crate::vtxo::VtxoStateKind;

		let net = self.network().await?;
		let tip = self.chain().tip().await?;
		let mut skipped = vec![];
		let towers: Vec<&(String, TowerTerms)> = towers.iter().filter(|(url, t)| {
			if t.network != net {
				skipped.push(json!({"tower": url, "reason": format!("it watches {}", t.network)}));
				false
			} else { true }
		}).collect();
		let held: HashSet<(&str, &str)> = deposited.iter().map(|d| (d.tower.as_str(), d.vtxo.as_str())).collect();
		let exiting = self.exit_mgr().get_exit_vtxo_ids().await;
		let live: Vec<_> = self.vtxos().await?.into_iter()
			.filter(|v| VtxoStateKind::UNSPENT_STATES.contains(&v.state.kind()))
			.filter(|v| !exiting.contains(&v.vtxo.id()))
			.collect();
		let live_ids: HashSet<String> = live.iter().map(|v| v.vtxo.id().to_string()).collect();

		let (mut deposit, mut covered, mut not_worth, mut refresh_due) = (vec![], vec![], vec![], vec![]);
		for v in &live {
			let full = self.get_full_vtxo(v.vtxo.id()).await?;
			let id = full.id().to_string();
			if full.expiry_height().saturating_sub(tip) <= 2 * RESCUE_MARGIN {
				refresh_due.push(json!(id));
			}
			if exit_clause(&full).is_err() {
				continue;
			}
			if !worth_rescuing(&full, fast) {
				not_worth.push(json!({"vtxo": id, "amount": full.amount().to_sat(),
					"rescue_cost": rescue_cost(&full, fast).map(|c| c.to_sat()).ok()}));
				continue;
			}
			let key = self.get_vtxo_key(&full).await?;
			let mut by = vec![];
			for (url, terms) in &towers {
				if !terms.watches(&full.server_pubkey()) {
					continue;
				}
				by.push(json!(url));
				if held.contains(&(url.as_str(), id.as_str())) {
					continue;
				}
				match make_deposit(&full, &key, holder, terms, fast) {
					Ok((body, txid)) => deposit.push(json!({"tower": url, "vtxo": id, "claim_txid": txid.to_string(), "body": body})),
					Err(e) => skipped.push(json!({"tower": url, "vtxo": id, "reason": e.to_string()})),
				}
			}
			covered.push(json!({"vtxo": id, "amount": full.amount().to_sat(), "expiry_height": full.expiry_height(),
				"rescued_from": full.expiry_height().saturating_sub(RESCUE_MARGIN), "towers": by}));
		}

		let mut withdraw = vec![];
		for d in deposited {
			if live_ids.contains(&d.vtxo) {
				continue;
			}
			let r: anyhow::Result<Value> = async {
				let id: ark::VtxoId = d.vtxo.parse().map_err(|_| anyhow!("not a coin id"))?;
				let full = self.get_full_vtxo(id).await?;
				let key = self.get_vtxo_key(&full).await?;
				let txid: Txid = d.claim_txid.parse().context("claim_txid")?;
				withdrawal(net, &full, &txid, &key)
			}.await;
			match r {
				Ok(body) => withdraw.push(json!({"tower": d.tower, "vtxo": d.vtxo, "claim_txid": d.claim_txid, "body": body})),
				Err(e) => skipped.push(json!({"tower": d.tower, "vtxo": d.vtxo, "reason": format!("cannot withdraw: {}", e)})),
			}
		}
		Ok(json!({
			"tip": tip, "fast_rate": fast.to_sat_per_vb_ceil(), "holder_address": holder.to_string(),
			"deposit": deposit, "withdraw": withdraw, "covered": covered, "not_worth": not_worth,
			"refresh_due": refresh_due, "skipped": skipped,
		}))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark::test_util::VTXO_VECTORS;
	use bitcoin::Sequence;

	fn addr(n: u8) -> Address {
		let k = Keypair::from_seckey_slice(&SECP, &[n; 32]).unwrap();
		Address::p2tr(&SECP, k.x_only_public_key().0, None, Network::Regtest)
	}

	fn terms() -> TowerTerms {
		TowerTerms {
			network: Network::Regtest,
			payout: addr(7),
			min_rate: FeeRate::from_sat_per_vb(1).unwrap(),
			margin: RESCUE_MARGIN,
			arks: vec![],
		}
	}

	#[test]
	fn a_claim_checks_and_any_change_fails() {
		let v = &VTXO_VECTORS.arkoor3_vtxo;
		let key = VTXO_VECTORS.arkoor3_user_key;
		let holder = addr(9);
		let t = terms();
		let rate = FeeRate::from_sat_per_vb(1).unwrap();
		let fee = rescue_fee(v, &t, rate).unwrap();
		let mut tx = claim_template(v, &holder, &t.payout, fee).unwrap();
		sign_claim(v, &mut tx, &key).unwrap();
		let payout = t.payout.script_pubkey();
		assert_eq!(check_claim(v, &tx, &payout, fee).unwrap(), fee);
		assert!(check_claim(v, &tx, &payout, fee + Amount::ONE_SAT).is_err());

		// each output changed in turn, the amounts kept summing to the coin
		let mut a = tx.clone();
		a.output[0].value -= Amount::ONE_SAT;
		a.output[1].value += Amount::ONE_SAT;
		assert!(check_claim(v, &a, &payout, fee).unwrap_err().to_string().contains("signature"));
		let mut b = tx.clone();
		b.output[0].script_pubkey = payout.clone();
		assert!(check_claim(v, &b, &payout, fee).unwrap_err().to_string().contains("signature"));
		let mut c = tx.clone();
		c.output.pop();
		assert!(check_claim(v, &c, &payout, fee).is_err());
		let mut d = tx.clone();
		d.input[0].sequence = Sequence::ZERO;
		assert!(check_claim(v, &d, &payout, fee).is_err());

		// a withdrawal names one claim
		let w = withdrawal(Network::Regtest, v, &tx.compute_txid(), &key).unwrap();
		let pk = v.user_pubkey().x_only_public_key().0;
		check_withdrawal(Network::Regtest, &pk, &tx.compute_txid(), w["sig"].as_str().unwrap()).unwrap();
		assert!(check_withdrawal(Network::Regtest, &pk, &a.compute_txid(), w["sig"].as_str().unwrap()).is_err());
		assert!(check_withdrawal(Network::Testnet4, &pk, &tx.compute_txid(), w["sig"].as_str().unwrap()).is_err());
	}

	#[test]
	fn the_worth_rule() {
		let v = &VTXO_VECTORS.round1_vtxo;
		let vb = rescue_vbytes(v).unwrap();
		assert!(vb > 400, "{}", vb);
		// a coin of 10,000 sat is not worth a rescue at 1 sat/vB of ~{vb} vB × 20
		assert!(!worth_rescuing(v, FeeRate::from_sat_per_vb(1).unwrap()));
	}
}
