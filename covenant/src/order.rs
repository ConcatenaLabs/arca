//! A resting order in the tree: the `order-2` leaf.
//!
//! An `order-2` leaf holds an order's coin of `asset_a` while it rests in an
//! Arca tree. The operator fills it with the maker offline; nobody fills it
//! without the operator, the maker included; and one exit delay after it
//! reaches the chain anyone may land it as SeqDEX's own order for the same
//! terms. It is a taproot output with the NUMS internal key and four leaves:
//!
//! ```text
//! root = TapBranch( TapBranch(collab, land), TapBranch(fill, data) )
//!
//! collab  the rebindable two-party path every Arca leaf has (tapscript), the
//!         maker's leaf key and the operator's, under the coin's salt
//! land    <exit delay> OP_CHECKSEQUENCEVERIFY OP_DROP, then output 0 is the
//!         `seqdex/order` output for the same terms, in asset_a, explicit, no
//!         nonce, worth at least what the coin holds (tapscript, no signature)
//! fill    the Simplicity program `arca/order-2` (one commitment root for
//!         every order)
//! data    the hidden leaf H_TapData(parameters)
//! ```
//!
//! The parameters ([`OrderPolicy::data_bytes`], 346 bytes, big-endian, asset
//! ids in internal order): `asset_a`, `asset_b`, `rate_num`, `rate_den`,
//! `min_lot`, the maker's leaf key, the operator's key, the coin's salt, the
//! exit delay in 512-second units, the tapleaf hash of `land`, and the keys
//! of the next four credits.
//!
//! A **fill** ([`OrderPolicy::fill_witness`]) needs the operator's BIP340
//! signature over [`OrderPolicy::fill_digest`]: the coin by its salt, asset
//! and value, and outputs `0..m` by the chain's own commitment to each
//! (`output_hash`), `m` from 2 to 4. Like every Arca pair it holds whatever
//! outpoint an unroll gives the coin. With the coin at input `k`, output `2k`
//! is the maker's credit (`asset_b`, at least `ceil(filled × rate_num /
//! rate_den)`, to the `vtxo-1` leaf of the next credit key under a salt that
//! descends from the coin's, [`OrderPolicy::credit_leaf`]) and, for a partial
//! fill, output `2k+1` the remainder (`asset_a`, at least `min_lot`, at the
//! `order-2` leaf of the next salt with the credit keys moved up one,
//! [`OrderPolicy::next`]). A fill is at least `min_lot`. The program refuses
//! a fill once the credit keys are used up, so an order fills at most four
//! times along one lineage.
//!
//! So no credit shares a script with another along one lineage, and a pair
//! the maker signs over one credit never fits another: each has its own key
//! and its own salt. The leaf has no unsigned fill and no refund: both live in
//! the landed `seqdex/order` ([`SeqdexOrder`]).
//!
//! The witnesses are built with no compiler: each pruned program is one
//! constant per path ([`crate::order_programs`]), and the Simplicity witness
//! is the parameters, the signature, `m` and the path bit.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::{Message, Parity, Scalar, XOnlyPublicKey};
use elements::{AssetId, Script, Transaction, TxOut};

use crate::leaf::{rebindable_two_party, two_party_items, two_party_message, LeafPolicy};
use crate::message::{Chain, CsfsMessage};
use crate::order_programs as programs;
use crate::script::{asset_bytes, sha256, ExplicitOutput};
use crate::taptree::{nums, secp, NUMS};
use crate::time::RelativeTime;
use crate::Error;

/// How many credit keys an order carries: it fills at most this many times
/// along one lineage.
pub const CREDIT_KEYS: usize = 4;
/// The tag of the operator's fill signature.
pub const FILL_TAG: &[u8] = b"Arca/order-fill";
/// The tag of the remainder's salt.
pub const REST_TAG: &[u8] = b"Arca/order-rest";
/// The tag of a credit's salt.
pub const CREDIT_TAG: &[u8] = b"Arca/order-credit";
/// The parameters' length.
pub const DATA_BYTES: usize = 346;
/// The most outputs the operator's fill signature commits to.
pub const MAX_FILL_OUTPUTS: u8 = 4;

/// Leaf versions.
const TAPSCRIPT: u8 = 0xc4;
const SIMPLICITY: u8 = 0xbe;

fn unhex(s: &str) -> Vec<u8> {
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("a hex constant")).collect()
}

fn hash32(s: &str) -> [u8; 32] {
	unhex(s).try_into().expect("a 32-byte constant")
}

/// `arca/order-2`'s commitment root.
pub fn order_cmr() -> [u8; 32] {
	hash32(programs::ORDER_CMR)
}

/// `seqdex/order`'s commitment root.
pub fn seqdex_cmr() -> [u8; 32] {
	hash32(programs::SEQDEX_ORDER_CMR)
}

fn tagged(tag: &[u8], msg: &[u8]) -> [u8; 32] {
	let t = sha256(tag);
	let mut b = Vec::with_capacity(64 + msg.len());
	b.extend(t);
	b.extend(t);
	b.extend(msg);
	sha256(&b)
}

/// A leaf's hash at `version`: `script` is a tapscript, or for Simplicity the
/// commitment root.
pub fn tapleaf(version: u8, script: &[u8]) -> [u8; 32] {
	let mut b = vec![version];
	crate::encode::write_compact_size(&mut b, script.len() as u64);
	b.extend(script);
	tagged(b"TapLeaf/elements", &b)
}

pub fn tapbranch(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
	let (x, y) = if a < b { (a, b) } else { (b, a) };
	let mut m = x.to_vec();
	m.extend(y);
	tagged(b"TapBranch/elements", &m)
}

/// A hidden data leaf: `tagged("TapData", bytes)`.
pub fn tapdata(bytes: &[u8]) -> [u8; 32] {
	tagged(b"TapData", bytes)
}

/// The output key of the NUMS internal key and `root`, and its parity.
fn output_key(root: [u8; 32]) -> (XOnlyPublicKey, Parity) {
	let mut m = NUMS.to_vec();
	m.extend(root);
	let t = tagged(b"TapTweak/elements", &m);
	nums().add_tweak(secp(), &Scalar::from_be_bytes(t).expect("a tweak below the order")).expect("a tweak that is not the negated key")
}

fn v1_spk(key: &XOnlyPublicKey) -> Script {
	Builder::new().push_int(1).push_slice(&key.serialize()).into_script()
}

fn control_block(version: u8, root: [u8; 32], path: &[[u8; 32]]) -> Vec<u8> {
	let parity = output_key(root).1;
	let mut cb = vec![version | if parity == Parity::Odd { 1 } else { 0 }];
	cb.extend(NUMS);
	for p in path {
		cb.extend(p);
	}
	cb
}

/// The bit string of `bytes`, `extra` bits after it, padded to whole bytes.
fn pack(bytes: &[u8], extra: &[bool]) -> Vec<u8> {
	let mut out = bytes.to_vec();
	if !extra.is_empty() {
		let mut b = 0u8;
		for (i, bit) in extra.iter().enumerate() {
			if *bit {
				b |= 1 << (7 - i);
			}
		}
		assert!(extra.len() <= 8);
		out.push(b);
	}
	out
}

/// Why an order's terms, a fill of it or a transaction spending it do not
/// hold.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OrderError {
	#[error("the order's terms: {0}")]
	Terms(String),
	#[error("the fill: {0}")]
	Amount(String),
	#[error("the order at input {k}: {why}")]
	Spend { k: usize, why: String },
}

/// The price and lot of an order: SeqDEX's terms, which every fill pays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OrderTerms {
	/// The asset the order holds and sells.
	pub asset_a: AssetId,
	/// The asset it is paid in.
	pub asset_b: AssetId,
	pub rate_num: u64,
	pub rate_den: u64,
	/// The least a fill takes, and the least a remainder holds.
	pub min_lot: u64,
}

impl OrderTerms {
	/// Refuses terms no fill can satisfy.
	pub fn check(&self) -> Result<(), OrderError> {
		if self.rate_num == 0 || self.rate_den == 0 || self.min_lot == 0 {
			return Err(OrderError::Terms(format!("rate {}/{} and min_lot {}: each must be at least 1", self.rate_num, self.rate_den,
				self.min_lot)));
		}
		if self.asset_a == self.asset_b {
			return Err(OrderError::Terms(format!("it sells and is paid in the same asset {}", self.asset_a)));
		}
		Ok(())
	}

	/// The least a fill of `filled` atoms pays: `ceil(filled × rate_num /
	/// rate_den)`, which the program checks on 128-bit products. `None` when
	/// it does not fit in 64 bits, so no output can pay it.
	pub fn price(&self, filled: u64) -> Option<u64> {
		if self.rate_den == 0 {
			return None;
		}
		let p = (filled as u128 * self.rate_num as u128).div_ceil(self.rate_den as u128);
		u64::try_from(p).ok()
	}

	/// Whether `paid` pays for `filled`: `filled × rate_num ≤ paid × rate_den`.
	pub fn pays(&self, filled: u64, paid: u64) -> bool {
		filled as u128 * self.rate_num as u128 <= paid as u128 * self.rate_den as u128
	}
}

/// SeqDEX's own order, `seqdex/order` (sequentia-contracts): the output an
/// `order-2` leaf lands as, for the same terms.
///
/// `P2TR(NUMS, TapBranch(TapLeaf_0xbe(CMR), H_TapData(terms)))`, the terms
/// 156 bytes: `asset_a ‖ asset_b ‖ rate_num ‖ rate_den ‖ min_lot ‖
/// SHA256(maker's scriptPubKey) ‖ expiry ‖ refund key`. Any taker fills it on
/// the chain with no signature; its refund key takes it back once the chain
/// passes `expiry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeqdexOrder {
	pub terms: OrderTerms,
	/// SHA256 of the scriptPubKey every on-chain fill pays.
	pub maker: [u8; 32],
	/// The refund's lock time: a median time at or above 500,000,000.
	pub expiry: u32,
	pub refund_key: XOnlyPublicKey,
}

impl SeqdexOrder {
	/// The data leaf's 156 bytes.
	pub fn data_bytes(&self) -> Vec<u8> {
		let mut b = Vec::with_capacity(156);
		b.extend(asset_bytes(self.terms.asset_a));
		b.extend(asset_bytes(self.terms.asset_b));
		b.extend(self.terms.rate_num.to_be_bytes());
		b.extend(self.terms.rate_den.to_be_bytes());
		b.extend(self.terms.min_lot.to_be_bytes());
		b.extend(self.maker);
		b.extend(self.expiry.to_be_bytes());
		b.extend(self.refund_key.serialize());
		b
	}

	pub fn root(&self) -> [u8; 32] {
		tapbranch(tapleaf(SIMPLICITY, &seqdex_cmr()), tapdata(&self.data_bytes()))
	}

	pub fn script_pubkey(&self) -> Script {
		v1_spk(&output_key(self.root()).0)
	}

	pub fn program(&self) -> [u8; 32] {
		output_key(self.root()).0.serialize()
	}

	/// The control block of the order's program.
	pub fn control_block(&self) -> Vec<u8> {
		control_block(SIMPLICITY, self.root(), &[tapdata(&self.data_bytes())])
	}

	/// The witness of a fill of the order, part (`partial`) or whole: the
	/// terms and the path bits, the pruned program, the root, the control
	/// block. It signs nothing and depends on nothing in the transaction.
	pub fn fill_witness(&self, partial: bool) -> Vec<Vec<u8>> {
		let program = if partial { programs::SEQDEX_FILL } else { programs::SEQDEX_FILL_WHOLE };
		vec![pack(&self.data_bytes(), &[false, partial]), unhex(program), seqdex_cmr().to_vec(), self.control_block()]
	}
}

/// A leaf of an `order-2` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderPath {
	Collab,
	Land,
	Fill,
}

/// An `order-2` leaf's policy: everything its scriptPubKey commits to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OrderPolicy {
	/// The landed order: the terms every fill pays, and where the leaf lands.
	pub landed: SeqdexOrder,
	/// The maker's leaf key `A`, in the collaborative path.
	pub owner: XOnlyPublicKey,
	/// The operator's key `S`.
	pub operator: XOnlyPublicKey,
	/// Unique to this coin.
	pub salt: [u8; 32],
	pub chain: Chain,
	/// The landing's delay, and every credit's exit delay.
	pub exit_delay: RelativeTime,
	/// The keys of the next credits, the next first; all zero once used.
	pub credits: [[u8; 32]; CREDIT_KEYS],
}

/// A fill of an order, planned: what it takes and the outputs the program
/// reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderFillPlan {
	pub filled: u64,
	/// What rests again; 0 for a whole fill.
	pub remainder: u64,
	/// The maker's credit, at output `2k`.
	pub credit: ExplicitOutput,
	/// The order resting again, at output `2k+1`, for a partial fill.
	pub rest: Option<ExplicitOutput>,
}

/// A fill as the program judges a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderFilled {
	pub filled: u64,
	pub remainder: u64,
	pub price: u64,
	pub credited: u64,
}

/// The chain's commitment to an output (Simplicity's `output_hash`):
/// `SHA256(asset ‖ value ‖ nonce ‖ SHA256(scriptPubKey) ‖ SHA256(range
/// proof))`, the asset, value and nonce as the transaction encodes them (a
/// prefix byte, then the explicit value or the commitment) and an explicit
/// output's range proof empty.
pub fn output_hash(o: &TxOut) -> [u8; 32] {
	let mut b = Vec::with_capacity(33 + 33 + 33 + 64);
	b.extend(elements::encode::serialize(&o.asset));
	b.extend(elements::encode::serialize(&o.value));
	b.extend(elements::encode::serialize(&o.nonce));
	b.extend(sha256(o.script_pubkey.as_bytes()));
	b.extend(sha256(&o.witness.rangeproof.as_ref().map(|p| p.serialize()).unwrap_or_default()));
	sha256(&b)
}

impl OrderPolicy {
	/// `K` of the collaborative path.
	pub fn leaf_constant(&self) -> [u8; 32] {
		self.chain.leaf_constant(&self.salt)
	}

	pub fn terms(&self) -> &OrderTerms {
		&self.landed.terms
	}

	pub fn collab_script(&self) -> Script {
		rebindable_two_party(&self.owner, &self.operator, &self.leaf_constant())
	}

	/// The landing: one exit delay after the coin reaches the chain, output 0
	/// is the landed order, in `asset_a`, explicit, no nonce, worth at least
	/// the coin.
	pub fn landing_script(&self) -> Script {
		Builder::new()
			.push_int(self.exit_delay.to_sequence() as i64).push_opcode(OP_CSV).push_opcode(OP_DROP)
			.push_int(0).push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.landed.program()).push_opcode(OP_EQUALVERIFY)
			.push_int(0).push_opcode(OP_INSPECTOUTPUTASSET).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&asset_bytes(self.landed.terms.asset_a)).push_opcode(OP_EQUALVERIFY)
			.push_int(0).push_opcode(OP_INSPECTOUTPUTNONCE).push_int(0).push_opcode(OP_EQUALVERIFY)
			.push_int(0).push_opcode(OP_INSPECTOUTPUTVALUE).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_opcode(OP_PUSHCURRENTINPUTINDEX).push_opcode(OP_INSPECTINPUTVALUE).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_opcode(OP_GREATERTHANOREQUAL64)
			.into_script()
	}

	pub fn land_leaf(&self) -> [u8; 32] {
		tapleaf(TAPSCRIPT, self.landing_script().as_bytes())
	}

	fn collab_leaf(&self) -> [u8; 32] {
		tapleaf(TAPSCRIPT, self.collab_script().as_bytes())
	}

	/// The parameters: the data leaf's bytes, in the program's order.
	pub fn data_bytes(&self) -> Vec<u8> {
		let t = &self.landed.terms;
		let mut b = Vec::with_capacity(DATA_BYTES);
		b.extend(asset_bytes(t.asset_a));
		b.extend(asset_bytes(t.asset_b));
		b.extend(t.rate_num.to_be_bytes());
		b.extend(t.rate_den.to_be_bytes());
		b.extend(t.min_lot.to_be_bytes());
		b.extend(self.owner.serialize());
		b.extend(self.operator.serialize());
		b.extend(self.salt);
		b.extend(self.exit_delay.units().to_be_bytes());
		b.extend(self.land_leaf());
		for c in &self.credits {
			b.extend(c);
		}
		debug_assert_eq!(b.len(), DATA_BYTES);
		b
	}

	pub fn data_leaf(&self) -> [u8; 32] {
		tapdata(&self.data_bytes())
	}

	pub fn root(&self) -> [u8; 32] {
		tapbranch(tapbranch(self.collab_leaf(), self.land_leaf()), tapbranch(tapleaf(SIMPLICITY, &order_cmr()), self.data_leaf()))
	}

	pub fn output_key(&self) -> XOnlyPublicKey {
		output_key(self.root()).0
	}

	pub fn script_pubkey(&self) -> Script {
		v1_spk(&self.output_key())
	}

	pub fn program(&self) -> [u8; 32] {
		self.output_key().serialize()
	}

	/// The control block that proves `path`.
	pub fn control_block(&self, path: OrderPath) -> Vec<u8> {
		let right = tapbranch(tapleaf(SIMPLICITY, &order_cmr()), self.data_leaf());
		let left = tapbranch(self.collab_leaf(), self.land_leaf());
		match path {
			OrderPath::Collab => control_block(TAPSCRIPT, self.root(), &[self.land_leaf(), right]),
			OrderPath::Land => control_block(TAPSCRIPT, self.root(), &[self.collab_leaf(), right]),
			OrderPath::Fill => control_block(SIMPLICITY, self.root(), &[self.data_leaf(), left]),
		}
	}

	/// The remainder's policy: the next salt, the credit keys moved up one.
	pub fn next(&self) -> OrderPolicy {
		let mut b = sha256(REST_TAG).to_vec();
		b.extend(self.salt);
		let mut credits = [[0u8; 32]; CREDIT_KEYS];
		credits[..CREDIT_KEYS - 1].copy_from_slice(&self.credits[1..]);
		OrderPolicy { salt: sha256(&b), credits, ..*self }
	}

	/// How many more fills the program takes along this lineage.
	pub fn fills_left(&self) -> usize {
		self.credits.iter().take_while(|c| **c != [0u8; 32]).count()
	}

	/// The salt of the credit a fill of this coin pays.
	pub fn credit_salt(&self) -> [u8; 32] {
		let mut b = sha256(CREDIT_TAG).to_vec();
		b.extend(self.salt);
		sha256(&b)
	}

	/// The `vtxo-1` leaf a fill of this coin pays the maker's credit to, or
	/// `None` once the credit keys are used up.
	pub fn credit_leaf(&self) -> Option<LeafPolicy> {
		let key = XOnlyPublicKey::from_slice(&self.credits[0]).ok()?;
		Some(LeafPolicy { owner: key, operator: self.operator, salt: self.credit_salt(), chain: self.chain, exit_delay: self.exit_delay,
			htlc: None })
	}

	/// The message maker and operator sign to spend the coin by the
	/// collaborative path, holding `value_in` of `asset_a`, into `outputs`.
	pub fn collab_message(&self, value_in: u64, outputs: &[ExplicitOutput]) -> Result<CsfsMessage, Error> {
		two_party_message(&self.leaf_constant(), self.landed.terms.asset_a, value_in, outputs)
	}

	/// The full collaborative witness for `m` committed outputs.
	pub fn collab_witness(&self, operator_sig: &Signature, owner_sig: &Signature, m: u8) -> Vec<Vec<u8>> {
		let mut w = two_party_items(operator_sig, owner_sig, m);
		w.push(self.collab_script().to_bytes());
		w.push(self.control_block(OrderPath::Collab));
		w
	}

	/// The landing's witness: nothing but the script and its control block,
	/// over a version 2 transaction whose input sequence is the exit delay.
	pub fn landing_witness(&self) -> Vec<Vec<u8>> {
		vec![self.landing_script().to_bytes(), self.control_block(OrderPath::Land)]
	}

	/// The landed output for a coin holding `value`: the whole of it, as SeqDEX's order.
	pub fn landed_output(&self, value: u64) -> ExplicitOutput {
		ExplicitOutput::new(self.landed.terms.asset_a, value, self.landed.script_pubkey())
	}

	/// What the operator signs to fill a coin of this script holding
	/// `value_in`, into outputs `0..m` of the fill:
	/// `SHA256(T ‖ salt ‖ asset_a ‖ value_in ‖ m ‖ output_hash(0) ‖ … )`,
	/// `T = SHA256(SHA256("Arca/order-fill") ‖ genesis)`.
	pub fn fill_digest(&self, value_in: u64, outputs: &[TxOut]) -> Result<[u8; 32], OrderError> {
		if !(2..=MAX_FILL_OUTPUTS as usize).contains(&outputs.len()) {
			return Err(OrderError::Amount(format!("a fill commits to 2 to {} outputs, not {}", MAX_FILL_OUTPUTS, outputs.len())));
		}
		let mut t = sha256(FILL_TAG).to_vec();
		t.extend(self.chain.genesis_bytes());
		let mut b = sha256(&t).to_vec();
		b.extend(self.salt);
		b.extend(asset_bytes(self.landed.terms.asset_a));
		b.extend(value_in.to_be_bytes());
		b.push(outputs.len() as u8);
		for o in outputs {
			b.extend(output_hash(o));
		}
		Ok(sha256(&b))
	}

	/// The fill's witness: the parameters, the operator's signature, `m` and
	/// the path bit, then the pruned program, the root and the control block.
	pub fn fill_witness(&self, operator_sig: &Signature, m: u8, partial: bool) -> Result<Vec<Vec<u8>>, OrderError> {
		let program = match (partial, m) {
			(true, 2) => programs::ORDER_FILL_M2,
			(true, 3) => programs::ORDER_FILL_M3,
			(true, 4) => programs::ORDER_FILL_M4,
			(false, 2) => programs::ORDER_FILL_WHOLE_M2,
			(false, 3) => programs::ORDER_FILL_WHOLE_M3,
			(false, 4) => programs::ORDER_FILL_WHOLE_M4,
			_ => return Err(OrderError::Amount(format!("a fill commits to 2 to {} outputs, not {}", MAX_FILL_OUTPUTS, m))),
		};
		let mut w = self.data_bytes();
		w.extend(operator_sig.as_ref());
		w.push(m);
		Ok(vec![pack(&w, &[partial]), unhex(program), order_cmr().to_vec(), self.control_block(OrderPath::Fill)])
	}

	/// The fill of `filled` atoms of a coin holding `locked`: the credit at
	/// its price and, for a partial fill, the order resting again.
	pub fn plan(&self, locked: u64, filled: u64) -> Result<OrderFillPlan, OrderError> {
		let t = &self.landed.terms;
		t.check()?;
		let credit = self.credit_leaf().ok_or_else(|| OrderError::Amount(format!("the order has filled {} times along this lineage, \
			which is all its credit keys allow: it rests until its maker refreshes it", CREDIT_KEYS)))?;
		if filled == 0 || filled > locked {
			return Err(OrderError::Amount(format!("a fill of {} atoms of an order holding {}", filled, locked)));
		}
		if filled < t.min_lot {
			return Err(OrderError::Amount(format!("a fill of {} atoms is below the order's min_lot of {}", filled, t.min_lot)));
		}
		let remainder = locked - filled;
		if remainder != 0 && remainder < t.min_lot {
			return Err(OrderError::Amount(format!("a fill of {} atoms leaves {} resting, below the order's min_lot of {}: take all {} \
				or at most {}", filled, remainder, t.min_lot, locked, locked - t.min_lot)));
		}
		let price = t.price(filled).ok_or_else(|| OrderError::Amount(format!("the price of {} atoms does not fit in 64 bits", filled)))?;
		Ok(OrderFillPlan {
			filled,
			remainder,
			credit: ExplicitOutput::new(t.asset_b, price, credit.script_pubkey()),
			rest: (remainder > 0).then(|| ExplicitOutput::new(t.asset_a, remainder, self.next().script_pubkey())),
		})
	}

	/// What the program concludes of `tx` spending this coin, holding
	/// `locked`, at input `k`, with the operator's signature committing to
	/// `m` outputs: the fill it makes, or the rule it breaks. It follows the
	/// program step by step; the node's interpreter remains the judge.
	pub fn check(&self, tx: &Transaction, k: usize, locked: u64, m: u8, partial: bool, operator_sig: &Signature)
		-> Result<OrderFilled, OrderError>
	{
		let fail = |why: String| OrderError::Spend { k, why };
		let t = &self.landed.terms;
		if k >= tx.input.len() {
			return Err(fail(format!("the transaction has {} inputs", tx.input.len())));
		}
		if m as usize > tx.output.len() {
			return Err(fail(format!("the operator commits to {} outputs and the transaction has {}", m, tx.output.len())));
		}
		let digest = self.fill_digest(locked, &tx.output[..m as usize]).map_err(|e| fail(e.to_string()))?;
		secp().verify_schnorr(operator_sig, &Message::from_digest(digest), &self.operator)
			.map_err(|_| fail("the operator's signature is not over this fill of this coin".into()))?;
		let (credit_at, rest_at) = (2 * k, 2 * k + 1);
		let explicit = |i: usize| -> Result<(AssetId, u64, &Script), OrderError> {
			let o = tx.output.get(i).ok_or_else(|| fail(format!("the transaction has no output {}", i)))?;
			let a = o.asset.explicit().ok_or_else(|| fail(format!("output {} hides its asset", i)))?;
			let v = o.value.explicit().ok_or_else(|| fail(format!("output {} hides its value", i)))?;
			if !o.nonce.is_null() {
				return Err(fail(format!("output {} carries a nonce", i)));
			}
			Ok((a, v, &o.script_pubkey))
		};
		let remainder = if partial {
			let (a, v, spk) = explicit(rest_at)?;
			if a != t.asset_a {
				return Err(fail(format!("output {}, the remainder, holds {} and not the order's {}", rest_at, a, t.asset_a)));
			}
			if *spk != self.next().script_pubkey() {
				return Err(fail(format!("output {}, the remainder, does not rest as this order under its next salt", rest_at)));
			}
			if v < t.min_lot {
				return Err(fail(format!("the remainder at output {} holds {}, below the order's min_lot of {}", rest_at, v, t.min_lot)));
			}
			v
		} else {
			0
		};
		let filled = locked.checked_sub(remainder).ok_or_else(|| fail(format!("the remainder {} is more than the coin's {}", remainder,
			locked)))?;
		if filled < t.min_lot || filled == 0 {
			return Err(fail(format!("it fills {} atoms, below the order's min_lot of {}", filled, t.min_lot)));
		}
		let credit = self.credit_leaf().ok_or_else(|| fail("the order's credit keys are used up".into()))?;
		let (a, credited, spk) = explicit(credit_at)?;
		if a != t.asset_b {
			return Err(fail(format!("output {}, the maker's credit, holds {} and not {}", credit_at, a, t.asset_b)));
		}
		if *spk != credit.script_pubkey() {
			return Err(fail(format!("output {}, the maker's credit, does not pay the order's next credit leaf", credit_at)));
		}
		if !t.pays(filled, credited) {
			return Err(fail(format!("output {} credits the maker {} of {}, and the fill of {} atoms costs {}", credit_at, credited, t.asset_b,
				filled, t.price(filled).map(|p| p.to_string()).unwrap_or_else(|| "more than 64 bits".into()))));
		}
		Ok(OrderFilled { filled, remainder, price: t.price(filled).unwrap_or(u64::MAX), credited })
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use elements::hashes::Hash;
	use elements::secp256k1_zkp::{Keypair, SecretKey};
	use elements::BlockHash;

	fn key(label: &str) -> Keypair {
		Keypair::from_secret_key(secp(), &SecretKey::from_slice(&sha256(label.as_bytes())).unwrap())
	}

	fn order() -> OrderPolicy {
		let x = |l: &str| key(l).x_only_public_key().0;
		OrderPolicy {
			landed: SeqdexOrder {
				terms: OrderTerms { asset_a: AssetId::from_slice(&[1; 32]).unwrap(), asset_b: AssetId::from_slice(&[2; 32]).unwrap(),
					rate_num: 3, rate_den: 2, min_lot: 1_000 },
				maker: sha256(b"maker"),
				expiry: 1_800_000_000,
				refund_key: x("refund"),
			},
			owner: x("maker"),
			operator: x("operator"),
			salt: [9; 32],
			chain: Chain::new(BlockHash::from_byte_array([7; 32])),
			exit_delay: RelativeTime::from_units(254).unwrap(),
			credits: [x("c0").serialize(), x("c1").serialize(), x("c2").serialize(), x("c3").serialize()],
		}
	}

	#[test]
	fn the_parameters_are_346_bytes_and_the_keys_move_up() {
		let o = order();
		assert_eq!(o.data_bytes().len(), DATA_BYTES);
		let n = o.next();
		assert_eq!(n.credits[0], o.credits[1]);
		assert_eq!(n.credits[3], [0; 32]);
		assert_ne!(n.salt, o.salt);
		assert_eq!(o.fills_left(), 4);
		assert_eq!(o.next().next().next().next().fills_left(), 0);
		assert!(o.next().next().next().next().credit_leaf().is_none());
		assert_ne!(o.credit_leaf().unwrap().script_pubkey(), n.credit_leaf().unwrap().script_pubkey());
	}

	#[test]
	fn every_path_has_a_control_block_that_proves_it() {
		let o = order();
		for (path, version, leaf) in [
			(OrderPath::Collab, TAPSCRIPT, o.collab_leaf()),
			(OrderPath::Land, TAPSCRIPT, o.land_leaf()),
			(OrderPath::Fill, SIMPLICITY, tapleaf(SIMPLICITY, &order_cmr())),
		] {
			let cb = o.control_block(path);
			assert_eq!(cb[0] & 0xfe, version);
			assert_eq!(cb.len(), 33 + 64);
			let mut node = leaf;
			for p in cb[33..].chunks(32) {
				node = tapbranch(node, p.try_into().unwrap());
			}
			assert_eq!(node, o.root());
		}
	}
}
