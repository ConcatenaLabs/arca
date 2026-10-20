//! An on-chain order a round fills: SeqDEX's fill covenant.
//!
//! A maker rests an order on the chain as one taproot output holding `N`
//! atoms of the asset it sells (`asset_a`), with the NUMS point as its
//! internal key, so it has no key path, and two tapscript leaves:
//!
//! - **FILL**, which needs no signature. For the covenant spent at input
//!   `k`, it reads output `2k` as the maker's credit and output `2k+1` as the
//!   order's remainder, and nothing else of the transaction:
//!   - output `2k+1`, when it exists, must have an explicit asset. When that
//!     asset is `asset_a` it is the remainder: its scriptPubKey must be the
//!     covenant's own (the order rests again with its identical script), its
//!     value explicit and at least `min_lot`. Any other asset there, or no
//!     output at `2k+1`, makes the remainder zero: a full fill.
//!   - what is filled is the input's value less the remainder, at least
//!     `min_lot`; the price is `ceil(filled * rate_num / rate_den)` in
//!     `asset_b`, computed in the node's signed 64-bit arithmetic.
//!   - output `2k` must hold `asset_b`, explicitly, at least the price, paid
//!     to the maker's pinned program (`OP_1 <maker_prog>`).
//! - **REFUND**: `<expiry_locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <maker_x>
//!   OP_CHECKSIG`, the maker taking the order back once its lock has passed.
//!   The lock is SeqDEX's choice and may be a height; Arca only reads it, to
//!   know until when the order can be filled without the maker racing it.
//!
//! Every term is a constant of the FILL leaf and so committed in the output
//! key: whoever fills the order can satisfy the terms, never change them, and
//! the first spend of the output wins. A round fills orders under that rule
//! ([`FillOrder::check`]): covenant inputs first, at `0..n-1`, so that outputs
//! `0..2n-1` hold their credits and remainders, and the batch outputs after
//! them. A batch output carrying `asset_a` at a filled covenant's `2k+1`
//! would be read as an underpaid remainder whose script is not the
//! covenant's, and the fill refused; for a full fill, `2k+1` holds an
//! explicit output in another asset.
//!
//! The scripts here are SeqDEX's, byte for byte: `pkg/covenant` in
//! `ConcatenaLabs/seqdex` builds them in Go and pins them to the Python
//! builder its regtest suite proves (`test/regtest/seqob_covenant.py`); this
//! crate's tests pin these to the same golden vector. The relay serves an
//! order's terms as the `CovenantTerms` message of `offer.proto` in its JSON
//! form, which [`FillOrder::from_relay`] reads (with the `json` feature).

use elements::hashes::Hash;
use elements::opcodes::all::*;
use elements::script::Builder;
use elements::{AssetId, OutPoint, Script, Transaction};

use crate::script::{asset_bytes, witness_program, ExplicitOutput};
use crate::taptree::{leaf_hash, TapOutput, NUMS};

/// Why an order's terms, a fill of it, or a transaction spending it do not
/// hold.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FillError {
	#[error("the order's terms: {0}")]
	Terms(String),
	#[error("the order's internal key is not the NUMS point: its maker could spend it by the key path, so it is not a resting order")]
	NotNums,
	#[error("the order's merkle path does not prove its FILL leaf under its terms")]
	MerklePath,
	#[error("a fill of up to {locked} atoms overflows the FILL leaf's signed 64-bit arithmetic at the rate {num}/{den}: no fill of it can \
		succeed")]
	Arithmetic { locked: u64, num: u64, den: u64 },
	#[error("the fill: {0}")]
	Amount(String),
	#[error("the covenant at input {k}: {why}")]
	Spend { k: usize, why: String },
}

/// The terms of one resting order, as its FILL and REFUND leaves bake them
/// in. The names are the relay's (`CovenantTerms`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FillOrder {
	/// The asset the order holds and sells.
	pub asset_a: AssetId,
	/// The asset it is paid in.
	pub asset_b: AssetId,
	pub rate_num: u64,
	pub rate_den: u64,
	/// The version 1 witness program every fill credits.
	pub maker_prog: [u8; 32],
	/// The least a fill takes, and the least a remainder holds.
	pub min_lot: u64,
	/// The REFUND leaf's absolute lock.
	pub expiry_locktime: u32,
	/// The key that signs the maker's REFUND.
	pub maker_x: [u8; 32],
}

/// When an order's REFUND path opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefundLock {
	/// At this block height.
	Height(u32),
	/// Once the chain's median time reaches this.
	Time(u32),
}

/// A fill of an order, planned: what it takes and the outputs the FILL leaf
/// reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FillPlan {
	/// The atoms of `asset_a` taken.
	pub filled: u64,
	/// The atoms of `asset_a` that rest again; 0 for a full fill.
	pub remainder: u64,
	/// The maker's credit, at output `2k`: the price in `asset_b`, to the
	/// maker's program.
	pub credit: ExplicitOutput,
	/// The order resting again, at output `2k+1`, for a partial fill.
	pub rest: Option<ExplicitOutput>,
}

/// A fill as the FILL leaf judges a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Filled {
	pub filled: u64,
	pub remainder: u64,
	/// What the leaf requires output `2k` to pay at least.
	pub price: u64,
	/// What output `2k` pays.
	pub credited: u64,
}

/// The largest `filled * rate_num + rate_den - 1` the FILL leaf evaluates:
/// its arithmetic is signed 64-bit and fails on overflow.
pub const MAX_LEAF_PRODUCT: u128 = i64::MAX as u128;

/// The opcodes that push `2k` from the input's own index.
fn credit_index(b: Builder) -> Builder {
	b.push_opcode(OP_PUSHCURRENTINPUTINDEX).push_opcode(OP_DUP).push_opcode(OP_ADD)
}

/// The opcodes that push `2k+1`.
fn remainder_index(b: Builder) -> Builder {
	credit_index(b).push_opcode(OP_1ADD)
}

fn le8(n: u64) -> [u8; 8] {
	n.to_le_bytes()
}

impl FillOrder {
	/// The FILL leaf.
	pub fn fill_leaf(&self) -> Script {
		let mut b = Builder::new()
			// The covenant input's own value, explicit.
			.push_opcode(OP_PUSHCURRENTINPUTINDEX).push_opcode(OP_INSPECTINPUTVALUE)
			.push_int(1).push_opcode(OP_EQUALVERIFY);
		// The remainder: asset A at 2k+1, or nothing.
		b = remainder_index(b).push_opcode(OP_INSPECTNUMOUTPUTS).push_opcode(OP_LESSTHAN).push_opcode(OP_IF);
		b = remainder_index(b).push_opcode(OP_INSPECTOUTPUTASSET).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&asset_bytes(self.asset_a)).push_opcode(OP_EQUAL).push_opcode(OP_IF);
		b = remainder_index(b).push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY)
			.push_opcode(OP_PUSHCURRENTINPUTINDEX).push_opcode(OP_INSPECTINPUTSCRIPTPUBKEY)
			.push_opcode(OP_ROT).push_opcode(OP_EQUALVERIFY).push_opcode(OP_EQUALVERIFY);
		b = remainder_index(b).push_opcode(OP_INSPECTOUTPUTVALUE).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_opcode(OP_DUP).push_slice(&le8(self.min_lot)).push_opcode(OP_GREATERTHANOREQUAL64).push_opcode(OP_VERIFY)
			.push_opcode(OP_ELSE).push_slice(&le8(0)).push_opcode(OP_ENDIF)
			.push_opcode(OP_ELSE).push_slice(&le8(0)).push_opcode(OP_ENDIF);
		// What is filled, at least min_lot, and its price, rounded up.
		b = b.push_opcode(OP_SUB64).push_opcode(OP_VERIFY)
			.push_opcode(OP_DUP).push_slice(&le8(self.min_lot)).push_opcode(OP_GREATERTHANOREQUAL64).push_opcode(OP_VERIFY)
			.push_slice(&le8(self.rate_num)).push_opcode(OP_MUL64).push_opcode(OP_VERIFY)
			.push_slice(&le8(self.rate_den.wrapping_sub(1))).push_opcode(OP_ADD64).push_opcode(OP_VERIFY)
			.push_slice(&le8(self.rate_den)).push_opcode(OP_DIV64).push_opcode(OP_VERIFY).push_opcode(OP_NIP);
		// The credit at 2k: asset B, to the maker, at least the price.
		b = credit_index(b).push_opcode(OP_INSPECTOUTPUTASSET).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&asset_bytes(self.asset_b)).push_opcode(OP_EQUALVERIFY);
		b = credit_index(b).push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.maker_prog).push_opcode(OP_EQUALVERIFY);
		b = credit_index(b).push_opcode(OP_INSPECTOUTPUTVALUE).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_opcode(OP_SWAP).push_opcode(OP_GREATERTHANOREQUAL64);
		b.into_script()
	}

	/// The REFUND leaf.
	pub fn refund_leaf(&self) -> Script {
		Builder::new()
			.push_int(self.expiry_locktime as i64).push_opcode(OP_CLTV).push_opcode(OP_DROP)
			.push_slice(&self.maker_x).push_opcode(OP_CHECKSIG)
			.into_script()
	}

	/// The order's taproot output: the NUMS internal key and the two leaves.
	pub fn output(&self) -> TapOutput {
		TapOutput::new(vec![(1, self.fill_leaf()), (1, self.refund_leaf())])
	}

	/// The scriptPubKey the order rests at, and rests again at after a
	/// partial fill.
	pub fn script_pubkey(&self) -> Script {
		self.output().script_pubkey()
	}

	/// The control block that proves the FILL leaf.
	pub fn control_block(&self) -> Vec<u8> {
		self.output().control_block(&self.fill_leaf()).expect("the FILL leaf is a leaf of the order")
	}

	/// The merkle path of the FILL leaf: the REFUND leaf's hash.
	pub fn merkle_path(&self) -> [u8; 32] {
		leaf_hash(&self.refund_leaf()).to_byte_array()
	}

	/// The covenant input's witness: the FILL leaf and its control block,
	/// nothing else.
	pub fn witness(&self) -> Vec<Vec<u8>> {
		self.output().witness(&self.fill_leaf(), vec![])
	}

	/// `OP_1 <maker_prog>`: where every credit goes.
	pub fn maker_script_pubkey(&self) -> Script {
		Builder::new().push_int(1).push_slice(&self.maker_prog).into_script()
	}

	/// When the REFUND path opens.
	pub fn refund_lock(&self) -> RefundLock {
		if self.expiry_locktime < 500_000_000 {
			RefundLock::Height(self.expiry_locktime)
		} else {
			RefundLock::Time(self.expiry_locktime)
		}
	}

	/// Refuses terms no fill can satisfy: a rate or lot of zero, the same
	/// asset on both sides.
	pub fn check_terms(&self) -> Result<(), FillError> {
		if self.rate_num == 0 || self.rate_den == 0 || self.min_lot == 0 {
			return Err(FillError::Terms(format!("rate {}/{} and min_lot {}: each must be at least 1", self.rate_num, self.rate_den,
				self.min_lot)));
		}
		if self.asset_a == self.asset_b {
			return Err(FillError::Terms(format!("it sells and is paid in the same asset {}", self.asset_a)));
		}
		Ok(())
	}

	/// Whether every fill of an order holding `locked` stays within the FILL
	/// leaf's arithmetic. An order that does not can only be refunded.
	pub fn check_arithmetic(&self, locked: u64) -> Result<(), FillError> {
		self.check_terms()?;
		let product = locked as u128 * self.rate_num as u128 + self.rate_den as u128 - 1;
		if product > MAX_LEAF_PRODUCT || locked > i64::MAX as u64 {
			return Err(FillError::Arithmetic { locked, num: self.rate_num, den: self.rate_den });
		}
		Ok(())
	}

	/// The price of filling `filled` atoms: `ceil(filled * rate_num /
	/// rate_den)` atoms of `asset_b`, rounded in the maker's favour, as the
	/// leaf computes it. `None` where the leaf's arithmetic overflows.
	pub fn price(&self, filled: u64) -> Option<u64> {
		if self.rate_den == 0 {
			return None;
		}
		let product = filled as u128 * self.rate_num as u128 + self.rate_den as u128 - 1;
		if product > MAX_LEAF_PRODUCT {
			return None;
		}
		u64::try_from(product / self.rate_den as u128).ok()
	}

	/// The fill of `filled` atoms of an order holding `locked`: the credit
	/// at its price and, for a partial fill, the order resting again with
	/// what is left. Refuses a fill below `min_lot`, above what the order
	/// holds, or that leaves a remainder below `min_lot`, and an order whose
	/// arithmetic overflows.
	pub fn plan(&self, locked: u64, filled: u64) -> Result<FillPlan, FillError> {
		self.check_arithmetic(locked)?;
		if filled == 0 || filled > locked {
			return Err(FillError::Amount(format!("a fill of {} atoms of an order holding {}", filled, locked)));
		}
		if filled < self.min_lot {
			return Err(FillError::Amount(format!("a fill of {} atoms is below the order's min_lot of {}", filled, self.min_lot)));
		}
		let remainder = locked - filled;
		if remainder != 0 && remainder < self.min_lot {
			return Err(FillError::Amount(format!("a fill of {} atoms leaves {} resting, below the order's min_lot of {}: take all {} \
				or at most {}", filled, remainder, self.min_lot, locked, locked - self.min_lot)));
		}
		let price = self.price(filled).ok_or(FillError::Arithmetic { locked, num: self.rate_num, den: self.rate_den })?;
		if price == 0 {
			return Err(FillError::Amount(format!("a fill of {} atoms costs nothing at the rate {}/{}", filled, self.rate_num, self.rate_den)));
		}
		Ok(FillPlan {
			filled,
			remainder,
			credit: ExplicitOutput::new(self.asset_b, price, self.maker_script_pubkey()),
			rest: (remainder > 0).then(|| ExplicitOutput::new(self.asset_a, remainder, self.script_pubkey())),
		})
	}

	/// What the FILL leaf concludes of `tx` spending this order, holding
	/// `locked`, at input `k`: the fill it makes, or the rule it breaks. It
	/// follows the leaf step by step, reading only outputs `2k` and `2k+1`,
	/// so a round builder can see before it broadcasts that the node will
	/// take the spend; the node's interpreter remains the judge.
	pub fn check(&self, tx: &Transaction, k: usize, locked: u64) -> Result<Filled, FillError> {
		let fail = |why: String| FillError::Spend { k, why };
		let spk = self.script_pubkey();
		if k >= tx.input.len() {
			return Err(fail(format!("the transaction has {} inputs", tx.input.len())));
		}
		if locked > i64::MAX as u64 {
			return Err(fail(format!("it holds {} atoms, more than the leaf's arithmetic reads", locked)));
		}
		let (credit_at, rest_at) = (2 * k, 2 * k + 1);
		let remainder = match tx.output.get(rest_at) {
			None => 0,
			Some(o) => {
				let asset = o.asset.explicit().ok_or_else(|| fail(format!("output {} hides its asset, which the leaf reads", rest_at)))?;
				if asset != self.asset_a {
					0
				} else {
					if o.script_pubkey != spk {
						return Err(fail(format!("output {} holds the order's asset {} but pays another script than the order's own: \
							the leaf reads it as the remainder, which must rest again under the identical script", rest_at, asset)));
					}
					let v = o.value.explicit().ok_or_else(|| fail(format!("output {} hides the remainder's value", rest_at)))?;
					if v < self.min_lot {
						return Err(fail(format!("the remainder at output {} holds {}, below the order's min_lot of {}", rest_at, v,
							self.min_lot)));
					}
					v
				}
			},
		};
		let filled = (locked as i128) - (remainder as i128);
		if filled < self.min_lot as i128 {
			return Err(fail(format!("it fills {} atoms ({} held, {} resting again), below the order's min_lot of {}", filled, locked,
				remainder, self.min_lot)));
		}
		let filled = filled as u64;
		let price = self.price(filled).ok_or_else(|| fail(format!("the price of {} atoms overflows the leaf's arithmetic", filled)))?;
		let credit = tx.output.get(credit_at).ok_or_else(|| fail(format!("the transaction has no output {} for the maker's credit",
			credit_at)))?;
		match credit.asset.explicit() {
			Some(a) if a == self.asset_b => {},
			Some(a) => return Err(fail(format!("output {}, the maker's credit, holds asset {} and not {}", credit_at, a, self.asset_b))),
			None => return Err(fail(format!("output {}, the maker's credit, hides its asset", credit_at))),
		}
		match witness_program(&credit.script_pubkey) {
			Some((1, p)) if p == self.maker_prog => {},
			_ => return Err(fail(format!("output {}, the maker's credit, does not pay the maker's program", credit_at))),
		}
		let credited = credit.value.explicit().ok_or_else(|| fail(format!("output {}, the maker's credit, hides its value", credit_at)))?;
		if credited < price {
			return Err(fail(format!("output {} credits the maker {} of asset {}, and the fill of {} atoms costs {}", credit_at, credited,
				self.asset_b, filled, price)));
		}
		Ok(Filled { filled, remainder, price, credited })
	}
}

/// The outpoint of an order as the relay names it.
pub fn outpoint_of(txid: &str, vout: u32) -> Result<OutPoint, FillError> {
	use std::str::FromStr;
	let txid = elements::Txid::from_str(txid).map_err(|e| FillError::Terms(format!("covenant_txid {:?}: {}", txid, e)))?;
	Ok(OutPoint::new(txid, vout))
}

/// Whether `key` is the NUMS point.
pub fn is_nums(key: &[u8]) -> bool {
	key == NUMS
}

#[cfg(feature = "json")]
mod relay {
	//! The relay's JSON form of `CovenantTerms`: protobuf's JSON mapping with
	//! the field names as `offer.proto` spells them, 64-bit integers as
	//! decimal strings, bytes in base64.

	use elements::{AssetId, OutPoint};
	use serde_json::{json, Value};

	use super::{is_nums, outpoint_of, FillError, FillOrder};
	use crate::script::asset_bytes;

	const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	/// Base64 as protobuf's JSON mapping writes it: the standard alphabet,
	/// padded.
	pub fn base64(bytes: &[u8]) -> String {
		let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
		for chunk in bytes.chunks(3) {
			let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | (*b as u32) << (16 - 8 * i));
			for i in 0..4 {
				if i <= chunk.len() {
					out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
				} else {
					out.push('=');
				}
			}
		}
		out
	}

	/// Base64 as protobuf's JSON mapping reads it: the standard or the
	/// URL-safe alphabet, padded or not.
	pub fn unbase64(s: &str) -> Option<Vec<u8>> {
		let s = s.trim_end_matches('=');
		let mut out = Vec::with_capacity(s.len() * 3 / 4);
		let (mut acc, mut bits) = (0u32, 0u32);
		for c in s.bytes() {
			let v = match c {
				b'A'..=b'Z' => c - b'A',
				b'a'..=b'z' => c - b'a' + 26,
				b'0'..=b'9' => c - b'0' + 52,
				b'+' | b'-' => 62,
				b'/' | b'_' => 63,
				_ => return None,
			} as u32;
			acc = acc << 6 | v;
			bits += 6;
			if bits >= 8 {
				bits -= 8;
				out.push((acc >> bits & 0xff) as u8);
			}
		}
		// Leftover bits must be zero, and one leftover character is no byte.
		if bits >= 6 || acc & ((1 << bits) - 1) != 0 {
			return None;
		}
		Some(out)
	}

	fn hex(b: &[u8]) -> String {
		b.iter().map(|x| format!("{:02x}", x)).collect()
	}

	fn field<'a>(v: &'a Value, name: &str) -> Result<&'a Value, FillError> {
		match v.get(name) {
			Some(Value::Null) | None => Err(FillError::Terms(format!("{} is missing", name))),
			Some(f) => Ok(f),
		}
	}

	fn uint(v: &Value, name: &str) -> Result<u64, FillError> {
		match field(v, name)? {
			Value::String(s) => s.parse::<u64>().map_err(|e| FillError::Terms(format!("{} {:?}: {}", name, s, e))),
			Value::Number(n) => n.as_u64().ok_or_else(|| FillError::Terms(format!("{} {} is not an unsigned integer", name, n))),
			other => Err(FillError::Terms(format!("{} is {}, not an integer", name, other))),
		}
	}

	fn uint32(v: &Value, name: &str) -> Result<u32, FillError> {
		u32::try_from(uint(v, name)?).map_err(|_| FillError::Terms(format!("{} is above 2^32", name)))
	}

	fn bytes32(v: &Value, name: &str) -> Result<[u8; 32], FillError> {
		let s = field(v, name)?.as_str().ok_or_else(|| FillError::Terms(format!("{} is not a base64 string", name)))?;
		let b = unbase64(s).ok_or_else(|| FillError::Terms(format!("{} {:?} is not base64", name, s)))?;
		b.try_into().map_err(|b: Vec<u8>| FillError::Terms(format!("{} holds {} bytes, not 32", name, b.len())))
	}

	fn asset(v: &Value, name: &str) -> Result<AssetId, FillError> {
		let s = field(v, name)?.as_str().ok_or_else(|| FillError::Terms(format!("{} is not a hex string", name)))?;
		if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
			return Err(FillError::Terms(format!("{} {:?} is not 32 bytes of hex", name, s)));
		}
		let mut b = [0u8; 32];
		for (i, x) in b.iter_mut().enumerate() {
			*x = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digits");
		}
		// Internal byte order, as the introspection opcodes push it.
		Ok(AssetId::from_byte_array(b))
	}

	impl FillOrder {
		/// Reads an order as the relay serves it: the `CovenantTerms` object
		/// itself, or an offer whose settlement is one (under `covenant`).
		/// Refuses terms no fill can satisfy, a maker program other than a
		/// 32-byte version 1 one, an internal key other than NUMS (absent
		/// means NUMS, as the relay's takers read it), and a merkle path that
		/// does not prove the FILL leaf (an empty one proves nothing and is
		/// taken: the output key is rebuilt from the terms whatever it says).
		pub fn from_relay(v: &Value) -> Result<(OutPoint, FillOrder), FillError> {
			let t = match v.get("covenant") {
				Some(c) if c.is_object() => c,
				_ => match v.get("settlement").and_then(|s| s.get("covenant")) {
					Some(c) if c.is_object() => c,
					_ => v,
				},
			};
			let txid = field(t, "covenant_txid")?.as_str()
				.ok_or_else(|| FillError::Terms("covenant_txid is not a string".into()))?;
			let outpoint = outpoint_of(txid, uint32(t, "covenant_vout").or_else(|e| match t.get("covenant_vout") {
				// protobuf's JSON mapping leaves a zero out unless told otherwise.
				None => Ok(0),
				_ => Err(e),
			})?)?;
			let ver = uint(t, "maker_prog_ver")?;
			if ver != 1 {
				return Err(FillError::Terms(format!("maker_prog_ver {}: the FILL leaf credits a version 1 program", ver)));
			}
			let order = FillOrder {
				asset_a: asset(t, "asset_a")?,
				asset_b: asset(t, "asset_b")?,
				rate_num: uint(t, "rate_num")?,
				rate_den: uint(t, "rate_den")?,
				maker_prog: bytes32(t, "maker_prog")?,
				min_lot: uint(t, "min_lot")?,
				expiry_locktime: uint32(t, "expiry_locktime")?,
				maker_x: bytes32(t, "maker_x")?,
			};
			order.check_terms()?;
			match t.get("internal_key") {
				None | Some(Value::Null) => {},
				Some(Value::String(s)) if s.is_empty() => {},
				Some(_) => {
					if !is_nums(&bytes32(t, "internal_key")?) {
						return Err(FillError::NotNums);
					}
				},
			}
			match t.get("merkle_path") {
				None | Some(Value::Null) => {},
				Some(Value::Array(p)) if p.is_empty() => {},
				Some(Value::Array(p)) => {
					let ours = order.merkle_path();
					let theirs: Vec<Option<Vec<u8>>> = p.iter().map(|x| x.as_str().and_then(unbase64)).collect();
					if theirs.len() != 1 || theirs[0].as_deref() != Some(&ours[..]) {
						return Err(FillError::MerklePath);
					}
				},
				Some(_) => return Err(FillError::Terms("merkle_path is not a list".into())),
			}
			Ok((outpoint, order))
		}

		/// The order as the relay serves it, resting at `outpoint`.
		pub fn to_relay(&self, outpoint: &OutPoint) -> Value {
			json!({
				"covenant_txid": outpoint.txid.to_string(),
				"covenant_vout": outpoint.vout,
				"asset_a": hex(&asset_bytes(self.asset_a)),
				"asset_b": hex(&asset_bytes(self.asset_b)),
				"rate_num": self.rate_num.to_string(),
				"rate_den": self.rate_den.to_string(),
				"maker_prog": base64(&self.maker_prog),
				"maker_prog_ver": 1,
				"min_lot": self.min_lot.to_string(),
				"expiry_locktime": self.expiry_locktime,
				"maker_x": base64(&self.maker_x),
				"internal_key": base64(&crate::taptree::NUMS),
				"merkle_path": [base64(&self.merkle_path())],
			})
		}
	}

	#[cfg(test)]
	mod test {
		use super::*;

		#[test]
		fn base64_round_trips_as_protobuf_writes_it() {
			for n in 0..70usize {
				let b: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
				let s = base64(&b);
				assert_eq!(s.len() % 4, 0);
				assert_eq!(unbase64(&s).as_deref(), Some(&b[..]), "{}", n);
				assert_eq!(unbase64(s.trim_end_matches('=')).as_deref(), Some(&b[..]));
			}
			assert_eq!(base64(b"\xfb\xff"), "+/8=");
			assert_eq!(unbase64("-_8").as_deref(), Some(&b"\xfb\xff"[..]));
			assert_eq!(unbase64("A"), None);
			assert_eq!(unbase64("AB"), None, "leftover bits not zero");
			assert_eq!(unbase64("a$"), None);
		}
	}
}

#[cfg(feature = "json")]
pub use relay::{base64, unbase64};
