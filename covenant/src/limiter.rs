//! The mint limiter an issuer-operated asset's reissuance token rests in.
//!
//! An issuer-operated batch is funded by reissuing its asset in the round that
//! makes it, and the reissuance token that allows it rests in the mint limiter
//! of sequentia-contracts (`templates/mint_limiter`, template
//! `77218080…557b`, program root [`LIMITER_CMR`]): a covenant that lets its
//! operator key mint at most an allowance per window of blocks and a cold key
//! brake it. Its output is
//!
//! ```text
//! P2TR(NUMS, TapBranch(TapLeaf_0xbe(limiter), H_TapData(params ‖ state)))
//! ```
//!
//! with the parameters ([`LimiterParams`]) and the state ([`LimiterState`]:
//! the amount minted in the current window, the blocks of the window behind
//! the coin, the brake) in the data leaf, big-endian, asset ids in internal
//! order. Every path but the recovery re-creates the coin at output 0 of the
//! spending transaction with the token's whole amount in the next state, and
//! the coin must be input 0.
//!
//! This module reads the limiter as a round needs it: the coin's script in a
//! state, the state a mint leads to ([`LimiterParams::mint`], the program's own
//! rule), what a spend of the coin did to it ([`LimiterParams::follow`]), and
//! the reissuance a round's input 0 carries ([`reissuance`]). It builds no
//! witness: the limiter's own tool signs and satisfies a mint
//! (`mint-limiter sign`), since the program signs `sig_all_hash`.

use std::str::FromStr;

use elements::confidential::Value;
use elements::hashes::sha256;
use elements::secp256k1_zkp::{Tweak, XOnlyPublicKey};
use elements::{AssetId, AssetIssuance, BlockHash, Script, Sequence, Transaction};

use crate::order::{tapdata, tapleaf, tapbranch};
use crate::script::asset_bytes;
use crate::taptree::{TapNode, TapOutput};

/// The commitment root of `sequentia/mint-limiter`, version 1.
pub const LIMITER_CMR: &str = "1238d68052662f890d4290c9c97d64ca964bf733a5771ba9821425a5473b09b9";

/// The template hash of `sequentia/mint-limiter`, version 1, as an instance
/// file names it.
pub const LIMITER_TEMPLATE: &str = "77218080daacd33cb636f1411920eb5f2d6ee805cb94d8d0651ce1808c0b557b";

/// The least age, in blocks, of a coin a mint spends.
pub const MIN_AGE: u16 = 2;

/// The blinding nonce a reissuance against an explicit token carries: any
/// value but zero marks a reissuance; this is one, as the limiter's tool
/// writes it.
pub const EXPLICIT_TOKEN_NONCE: [u8; 32] = {
	let mut n = [0u8; 32];
	n[31] = 1;
	n
};

/// Leaf version of a Simplicity leaf.
const SIMPLICITY: u8 = 0xbe;

/// Why a mint or an instance is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LimiterError {
	#[error("the instance: {0}")]
	Instance(String),
	#[error("the brake is on: no mint until the cold key lifts it")]
	Braked,
	#[error("a mint spends a coin at least {MIN_AGE} blocks old; this one is {0}")]
	TooYoung(u16),
	#[error("a mint of {amount} would bring the window's count to {count}, above its allowance of {allowance}")]
	OverAllowance { amount: u64, count: u64, allowance: u64 },
	#[error("a mint of zero is not a reissuance")]
	Zero,
}

/// An instance's parameters, fixed for its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LimiterParams {
	/// The asset the token reissues.
	pub asset: AssetId,
	/// The explicit reissuance token, the coin's own asset.
	pub token: AssetId,
	/// The key that signs mints.
	pub operator: XOnlyPublicKey,
	/// The key that brakes, lifts the brake and recovers.
	pub cold: XOnlyPublicKey,
	/// The window, in blocks.
	pub window: u16,
	/// The most minted in one window, in the asset's atoms.
	pub allowance: u64,
	/// How long the brake holds before a recovery, in units of 512 seconds.
	pub recovery_delay: u16,
}

/// The state a coin of an instance carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct LimiterState {
	/// Minted in the current window.
	pub minted: u64,
	/// Blocks of the current window behind the coin.
	pub elapsed: u16,
	/// Whether the brake is on.
	pub armed: bool,
}

/// What a spend of an instance's coin did, read from the spending
/// transaction ([`LimiterParams::follow`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimiterSpend {
	/// A mint of `amount`: the successor at output 0 in `next`.
	Mint { amount: u64, age: u16, next: LimiterState },
	/// The brake applied.
	Arm { next: LimiterState },
	/// The brake lifted.
	Disarm { next: LimiterState },
	/// The token taken out by the cold key: the instance has no coin any more.
	Recover,
}

impl LimiterSpend {
	/// The state of the successor at output 0, when the spend made one.
	pub fn next(&self) -> Option<LimiterState> {
		match self {
			LimiterSpend::Mint { next, .. } | LimiterSpend::Arm { next } | LimiterSpend::Disarm { next } => Some(*next),
			LimiterSpend::Recover => None,
		}
	}
}

fn unhex(s: &str) -> Result<Vec<u8>, LimiterError> {
	if s.len() % 2 != 0 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
		return Err(LimiterError::Instance(format!("{} is not hex", s)));
	}
	Ok((0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digits")).collect())
}

/// The program's commitment root.
pub fn limiter_cmr() -> [u8; 32] {
	unhex(LIMITER_CMR).expect("a constant").try_into().expect("32 bytes")
}

impl LimiterParams {
	/// The instance's parameters from the file `mint-limiter instance`
	/// writes (`{"instance": 2, "template_hash", "params", "genesis"}`),
	/// with the chain it names. Refuses another template, two equal keys, a
	/// window under two blocks, a zero allowance or recovery delay, as the
	/// tool does.
	#[cfg(feature = "json")]
	pub fn from_instance_json(text: &str) -> Result<(LimiterParams, BlockHash), LimiterError> {
		let v: serde_json::Value = serde_json::from_str(text).map_err(|e| LimiterError::Instance(e.to_string()))?;
		if v["instance"] != serde_json::json!(2) {
			return Err(LimiterError::Instance("not an instance file of format 2".into()));
		}
		if v["template_hash"].as_str() != Some(LIMITER_TEMPLATE) {
			return Err(LimiterError::Instance(format!("template {} is not the mint limiter {}", v["template_hash"], LIMITER_TEMPLATE)));
		}
		let p = &v["params"];
		let get = |k: &str| p[k].as_str().ok_or_else(|| LimiterError::Instance(format!("no parameter {}", k)));
		let asset = |k: &str| -> Result<AssetId, LimiterError> {
			let b: [u8; 32] = unhex(get(k)?)?.try_into().map_err(|_| LimiterError::Instance(format!("{} is not 32 bytes", k)))?;
			Ok(AssetId::from_inner(elements::hashes::sha256::Midstate::from_byte_array(b)))
		};
		let key = |k: &str| -> Result<XOnlyPublicKey, LimiterError> {
			XOnlyPublicKey::from_slice(&unhex(get(k)?)?).map_err(|e| LimiterError::Instance(format!("{}: {}", k, e)))
		};
		let num = |k: &str| -> Result<u64, LimiterError> {
			u64::from_str_radix(get(k)?, 16).map_err(|e| LimiterError::Instance(format!("{}: {}", k, e)))
		};
		let small = |k: &str| -> Result<u16, LimiterError> {
			u16::try_from(num(k)?).map_err(|_| LimiterError::Instance(format!("{} is above 65535", k)))
		};
		let params = LimiterParams {
			asset: asset("ASSET")?,
			token: asset("TOKEN")?,
			operator: key("OPERATOR_KEY")?,
			cold: key("COLD_KEY")?,
			window: small("WINDOW")?,
			allowance: num("ALLOWANCE")?,
			recovery_delay: small("RECOVERY_DELAY")?,
		};
		params.check()?;
		let genesis = BlockHash::from_str(v["genesis"].as_str().ok_or_else(|| LimiterError::Instance("no genesis".into()))?)
			.map_err(|e| LimiterError::Instance(format!("genesis: {}", e)))?;
		Ok((params, genesis))
	}

	/// Refuses an instance that cannot work: one key for both roles (the
	/// operator could lift its own brake), a window under two blocks, a zero
	/// allowance or recovery delay.
	pub fn check(&self) -> Result<(), LimiterError> {
		if self.operator == self.cold {
			return Err(LimiterError::Instance("the operator key and the cold key are one key".into()));
		}
		if self.window < MIN_AGE {
			return Err(LimiterError::Instance(format!("a window of {} blocks is shorter than {} blocks between mints", self.window, MIN_AGE)));
		}
		if self.allowance == 0 {
			return Err(LimiterError::Instance("an allowance of zero mints nothing".into()));
		}
		if self.recovery_delay == 0 {
			return Err(LimiterError::Instance("a recovery delay of zero".into()));
		}
		Ok(())
	}

	/// The data leaf's bytes in `state`: the parameters, then the state, in
	/// the program's order, big-endian, asset ids in internal order.
	pub fn data(&self, state: LimiterState) -> Vec<u8> {
		let mut b = Vec::with_capacity(32 * 4 + 2 + 8 + 2 + 8 + 2 + 1);
		b.extend(asset_bytes(self.asset));
		b.extend(asset_bytes(self.token));
		b.extend(self.operator.serialize());
		b.extend(self.cold.serialize());
		b.extend(self.window.to_be_bytes());
		b.extend(self.allowance.to_be_bytes());
		b.extend(self.recovery_delay.to_be_bytes());
		b.extend(state.minted.to_be_bytes());
		b.extend(state.elapsed.to_be_bytes());
		b.push(state.armed as u8);
		b
	}

	/// The coin's taproot output in `state`.
	pub fn taproot(&self, state: LimiterState) -> TapOutput {
		TapOutput::with_nodes(vec![(1, TapNode::Simplicity(limiter_cmr())), (1, TapNode::Hidden(tapdata(&self.data(state))))])
	}

	/// The coin's script in `state`.
	pub fn script_pubkey(&self, state: LimiterState) -> Script {
		self.taproot(state).script_pubkey()
	}

	/// The merkle root of the coin's tree in `state`: the program's leaf and
	/// the data leaf.
	pub fn merkle_root(&self, state: LimiterState) -> [u8; 32] {
		tapbranch(tapleaf(SIMPLICITY, &limiter_cmr()), tapdata(&self.data(state)))
	}

	/// The state a mint of `amount` from a coin `age` blocks old leads to,
	/// as the program computes it: once the blocks behind the coin and its
	/// age reach the window, the mint opens a new window and the count starts
	/// from its amount; otherwise the count grows by it. Refused when the
	/// brake is on, the coin is under two blocks old or the count would pass
	/// the allowance.
	pub fn mint(&self, state: LimiterState, age: u16, amount: u64) -> Result<LimiterState, LimiterError> {
		if amount == 0 {
			return Err(LimiterError::Zero);
		}
		if state.armed {
			return Err(LimiterError::Braked);
		}
		if age < MIN_AGE {
			return Err(LimiterError::TooYoung(age));
		}
		let ended = state.elapsed as u32 + age as u32 >= self.window as u32;
		let next = if ended {
			LimiterState { minted: amount, elapsed: 0, armed: false }
		} else {
			let minted = state.minted.checked_add(amount)
				.ok_or(LimiterError::OverAllowance { amount, count: u64::MAX, allowance: self.allowance })?;
			LimiterState { minted, elapsed: state.elapsed + age, armed: false }
		};
		if next.minted > self.allowance {
			return Err(LimiterError::OverAllowance { amount, count: next.minted, allowance: self.allowance });
		}
		Ok(next)
	}

	/// What is left of the allowance for a mint from a coin `age` blocks old
	/// in `state`: the whole allowance when that mint would open a new
	/// window; nothing while the brake is on or the coin is too young.
	pub fn room(&self, state: LimiterState, age: u16) -> u64 {
		if state.armed || age < MIN_AGE {
			return 0;
		}
		if state.elapsed as u32 + age as u32 >= self.window as u32 {
			self.allowance
		} else {
			self.allowance.saturating_sub(state.minted)
		}
	}

	/// The blocks until a mint from a coin `age` blocks old in `state`
	/// would open a new window.
	pub fn blocks_to_new_window(&self, state: LimiterState, age: u16) -> u32 {
		(self.window as u32).saturating_sub(state.elapsed as u32 + age as u32)
	}

	/// What `tx` did to the coin in `state` it spends at input `at`: a mint
	/// (input 0 reissues the asset, its sequence an age in blocks, and output
	/// 0 is the successor in the state the program computes), the brake
	/// applied or lifted (output 0 the successor with the brake changed), or
	/// otherwise, for a braked coin, the recovery. `None` when the
	/// transaction spends the coin by no path the program allows, which a
	/// block never holds.
	pub fn follow(&self, state: LimiterState, tx: &Transaction, at: usize) -> Option<LimiterSpend> {
		// The program requires its coin at input 0.
		if at != 0 {
			return None;
		}
		let input = tx.input.get(at)?;
		let out0 = tx.output.first().map(|o| &o.script_pubkey);
		let is = |s: LimiterState| out0 == Some(&self.script_pubkey(s));
		if input.has_issuance() {
			let seq = input.sequence.to_consensus_u32();
			if let (Value::Explicit(x), true) = (input.asset_issuance.amount, seq & (1 << 31 | 1 << 22) == 0) {
				let age = (seq & 0xffff) as u16;
				if let Ok(next) = self.mint(state, age, x) {
					if is(next) {
						return Some(LimiterSpend::Mint { amount: x, age, next });
					}
				}
			}
			return None;
		}
		if !state.armed && is(LimiterState { armed: true, ..state }) {
			return Some(LimiterSpend::Arm { next: LimiterState { armed: true, ..state } });
		}
		if state.armed && is(LimiterState { armed: false, ..state }) {
			return Some(LimiterSpend::Disarm { next: LimiterState { armed: false, ..state } });
		}
		state.armed.then_some(LimiterSpend::Recover)
	}
}

/// The issuance a round's input 0 carries to reissue `amount` of the asset
/// `entropy` names, against its explicit token: the explicit-token nonce,
/// the asset's entropy, the amount, no new tokens, denomination 8 (the
/// limiter's tool signs only beside issuances of 8, the only denomination
/// the PSET it reads carries).
pub fn reissuance(entropy: [u8; 32], amount: u64) -> AssetIssuance {
	AssetIssuance {
		asset_blinding_nonce: Tweak::from_slice(&EXPLICIT_TOKEN_NONCE).expect("one is below the curve order"),
		asset_entropy: entropy,
		amount: Value::Explicit(amount),
		inflation_keys: Value::Null,
		denomination: 8,
	}
}

/// The asset's issuance entropy from its hex as an RPC prints it
/// (`issueasset`'s `entropy`), in the form a reissuance carries.
pub fn entropy_from_hex(hex: &str) -> Result<[u8; 32], LimiterError> {
	let m = sha256::Midstate::from_str(hex).map_err(|e| LimiterError::Instance(format!("entropy: {}", e)))?;
	Ok(m.to_byte_array())
}

/// The asset `entropy` reissues.
pub fn asset_of_entropy(entropy: [u8; 32]) -> AssetId {
	AssetId::from_entropy(sha256::Midstate::from_byte_array(entropy))
}

/// The explicit reissuance token of the asset `entropy` names.
pub fn token_of_entropy(entropy: [u8; 32]) -> AssetId {
	AssetId::reissuance_token_from_entropy(sha256::Midstate::from_byte_array(entropy), false)
}

/// The sequence a mint's input carries: the coin's age in blocks.
pub fn age_sequence(age: u16) -> Sequence {
	Sequence(age as u32)
}
