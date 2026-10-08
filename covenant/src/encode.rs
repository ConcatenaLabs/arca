//! Binary encodings of the policies and the clock schedule.
//!
//! A server stores and serves these, and a client decodes them from the
//! server or a mirror, so every decoder takes untrusted bytes. Decoding
//! refuses anything that does not re-encode to the same bytes: a key that is
//! not a valid x-only point, a height where a median time belongs, a zero
//! delay, a count out of range, a flag byte other than 0 or 1, a
//! non-canonical length, and trailing bytes.
//!
//! Integers are little-endian. Counts of owners use Bitcoin's compact size,
//! in its shortest form.
//!
//! | Type | Encoding |
//! |---|---|
//! | [`Policy`] | version `0x01`, a type byte (1 a `vtxo-1` leaf, 6 an `htlc-1` leaf), then the policy |
//! | [`ClockSchedule`] | version `0x01`, `T` (32), `S` (32), `W` units (u16), step count (u8, 1 to 64), each `E` (u32) |
//! | [`LeafPolicy`] | `A`, `S`, salt, genesis hash (32 each), exit delay units (u16); for `htlc-1` then direction (u8: 0 send, 1 receive), payment hash (32), timeout (u32), operator delay units (u16) |
//! | [`NodePolicy`] | child count (u8, 1 to 6), each child (asset 32, value u64, program 32), `S`, owner count (compact size), owners, sweep, reclaim flag (u8) and, when set, the genesis hash |
//! | [`EntryPolicy`] | unlock hash, asset (32 each), value (u64), leaf program (32), sweep |
//! | [`ForfeitPolicy`] | unlock hash, `A`, `S` (32 each), refund delay units (u16), the leaf id given up (32), the connector asset (32) |
//! | [`CheckpointPolicy`] | `A`, `S`, salt, genesis hash (32 each), sweep |
//! | [`OffboardPolicy`] | unlock hash (32), destination asset (32), value (u64), script length (compact size, at most 10,000), script, `S` (32), reclaim delay units (u16) |
//! | [`Sweep`] | `T`, `R` program, `S` (32 each), flags (u8: bit 0 notice, bit 1 burn), and the notice units (u16) when bit 0 is set |
//!
//! Asset ids and the genesis hash are in internal byte order.

use elements::hashes::Hash;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, BlockHash};

use crate::clock::{ClockSchedule, MAX_STEPS};
use crate::gate::MAX_OWNERS;
use crate::htlc::{HtlcDirection, HtlcTerms};
use crate::message::Chain;
use crate::node::MAX_CHILDREN;
use crate::script::{asset_bytes, Child};
use crate::sweep::Sweep;
use crate::time::{MedianTime, RelativeTime};
use crate::offboard::MAX_DESTINATION;
use crate::script::ExplicitOutput;
use crate::{CheckpointPolicy, EntryPolicy, ForfeitPolicy, LeafPolicy, NodePolicy, OffboardPolicy};

/// The encoding version this crate writes and reads.
pub const VERSION: u8 = 0x01;

/// Why bytes do not decode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
	#[error("the data ends early")]
	UnexpectedEnd,
	#[error("{0} bytes follow the encoded value")]
	TrailingBytes(usize),
	#[error("unknown encoding version {0}")]
	Version(u8),
	#[error("unknown policy type {0}")]
	PolicyType(u8),
	#[error("not a valid x-only public key")]
	Key,
	#[error("invalid flag byte {0:#x}")]
	Flag(u8),
	#[error("a count of {0} is out of range")]
	Count(u64),
	#[error("a compact size is not in its shortest form")]
	NonCanonical,
	#[error(transparent)]
	Time(#[from] crate::time::TimeError),
	#[error(transparent)]
	Policy(#[from] crate::Error),
}

/// A cursor over bytes being decoded.
pub struct Reader<'a> {
	data: &'a [u8],
}

impl<'a> Reader<'a> {
	pub fn new(data: &'a [u8]) -> Reader<'a> {
		Reader { data }
	}

	pub fn remaining(&self) -> usize {
		self.data.len()
	}

	pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
		if self.data.len() < n {
			return Err(DecodeError::UnexpectedEnd);
		}
		let (head, tail) = self.data.split_at(n);
		self.data = tail;
		Ok(head)
	}

	pub fn u8(&mut self) -> Result<u8, DecodeError> {
		Ok(self.bytes(1)?[0])
	}

	pub fn u16(&mut self) -> Result<u16, DecodeError> {
		Ok(u16::from_le_bytes(self.bytes(2)?.try_into().unwrap()))
	}

	pub fn u32(&mut self) -> Result<u32, DecodeError> {
		Ok(u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
	}

	pub fn u64(&mut self) -> Result<u64, DecodeError> {
		Ok(u64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
	}

	pub fn array32(&mut self) -> Result<[u8; 32], DecodeError> {
		Ok(self.bytes(32)?.try_into().unwrap())
	}

	pub fn key(&mut self) -> Result<XOnlyPublicKey, DecodeError> {
		XOnlyPublicKey::from_slice(self.bytes(32)?).map_err(|_| DecodeError::Key)
	}

	pub fn asset(&mut self) -> Result<AssetId, DecodeError> {
		Ok(AssetId::from_byte_array(self.array32()?))
	}

	pub fn flag(&mut self) -> Result<bool, DecodeError> {
		match self.u8()? {
			0 => Ok(false),
			1 => Ok(true),
			f => Err(DecodeError::Flag(f)),
		}
	}

	/// Bitcoin's compact size, in its shortest form only.
	pub fn compact_size(&mut self) -> Result<u64, DecodeError> {
		let n = match self.u8()? {
			0xfd => {
				let n = self.u16()? as u64;
				if n < 0xfd { return Err(DecodeError::NonCanonical); }
				n
			},
			0xfe => {
				let n = self.u32()? as u64;
				if n <= 0xffff { return Err(DecodeError::NonCanonical); }
				n
			},
			0xff => {
				let n = self.u64()?;
				if n <= 0xffff_ffff { return Err(DecodeError::NonCanonical); }
				n
			},
			b => b as u64,
		};
		Ok(n)
	}

	pub fn median_time(&mut self) -> Result<MedianTime, DecodeError> {
		Ok(MedianTime::from_consensus(self.u32()?)?)
	}

	pub fn relative_time(&mut self) -> Result<RelativeTime, DecodeError> {
		Ok(RelativeTime::from_units(self.u16()?)?)
	}

	pub fn chain(&mut self) -> Result<Chain, DecodeError> {
		Ok(Chain::new(BlockHash::from_byte_array(self.array32()?)))
	}
}

pub(crate) fn write_compact_size(w: &mut Vec<u8>, n: u64) {
	match n {
		0..=0xfc => w.push(n as u8),
		0xfd..=0xffff => { w.push(0xfd); w.extend((n as u16).to_le_bytes()); },
		0x1_0000..=0xffff_ffff => { w.push(0xfe); w.extend((n as u32).to_le_bytes()); },
		_ => { w.push(0xff); w.extend(n.to_le_bytes()); },
	}
}

/// A value with a canonical binary encoding.
pub trait Encoding: Sized {
	fn encode_to(&self, w: &mut Vec<u8>);
	fn decode_from(r: &mut Reader) -> Result<Self, DecodeError>;

	fn encode(&self) -> Vec<u8> {
		let mut w = vec![];
		self.encode_to(&mut w);
		w
	}

	/// Decodes `data`, which must hold exactly one value.
	fn decode(data: &[u8]) -> Result<Self, DecodeError> {
		let mut r = Reader::new(data);
		let v = Self::decode_from(&mut r)?;
		if r.remaining() != 0 {
			return Err(DecodeError::TrailingBytes(r.remaining()));
		}
		Ok(v)
	}
}

impl Encoding for Sweep {
	fn encode_to(&self, w: &mut Vec<u8>) {
		w.extend(asset_bytes(self.token));
		w.extend(self.r_program);
		w.extend(self.operator.serialize());
		w.push(self.notice.is_some() as u8 | (self.burn as u8) << 1);
		if let Some(n) = self.notice {
			w.extend(n.units().to_le_bytes());
		}
	}

	fn decode_from(r: &mut Reader) -> Result<Sweep, DecodeError> {
		let token = r.asset()?;
		let r_program = r.array32()?;
		let operator = r.key()?;
		let flags = r.u8()?;
		if flags & !0b11 != 0 {
			return Err(DecodeError::Flag(flags));
		}
		let notice = if flags & 1 != 0 { Some(r.relative_time()?) } else { None };
		Ok(Sweep { token, r_program, operator, notice, burn: flags & 2 != 0 })
	}
}

impl Encoding for ClockSchedule {
	fn encode_to(&self, w: &mut Vec<u8>) {
		w.push(VERSION);
		w.extend(asset_bytes(self.token));
		w.extend(self.operator.serialize());
		w.extend(self.notice.units().to_le_bytes());
		w.push(self.expiries().len() as u8);
		for e in self.expiries() {
			w.extend(e.to_consensus_u32().to_le_bytes());
		}
	}

	/// Decodes a published schedule as it is, backwards or not: refusing a
	/// dishonest schedule is the client check's job ([`crate::check_round`]).
	fn decode_from(r: &mut Reader) -> Result<ClockSchedule, DecodeError> {
		let v = r.u8()?;
		if v != VERSION {
			return Err(DecodeError::Version(v));
		}
		let token = r.asset()?;
		let operator = r.key()?;
		let notice = r.relative_time()?;
		let n = r.u8()? as usize;
		if n == 0 || n > MAX_STEPS {
			return Err(DecodeError::Count(n as u64));
		}
		let mut expiries = Vec::with_capacity(n);
		for _ in 0..n {
			expiries.push(r.median_time()?);
		}
		Ok(ClockSchedule::new_unchecked(token, operator, notice, expiries)?)
	}
}

/// A leaf: `vtxo-1`'s fields, then `htlc-1`'s terms when it carries them.
/// Decoding reads a `vtxo-1` leaf; [`Policy`] reads either, by its type byte.
impl Encoding for LeafPolicy {
	fn encode_to(&self, w: &mut Vec<u8>) {
		w.extend(self.owner.serialize());
		w.extend(self.operator.serialize());
		w.extend(self.salt);
		w.extend(self.chain.genesis_bytes());
		w.extend(self.exit_delay.units().to_le_bytes());
		if let Some(t) = &self.htlc {
			t.encode_to(w);
		}
	}

	fn decode_from(r: &mut Reader) -> Result<LeafPolicy, DecodeError> {
		Ok(LeafPolicy {
			owner: r.key()?,
			operator: r.key()?,
			salt: r.array32()?,
			chain: r.chain()?,
			exit_delay: r.relative_time()?,
			htlc: None,
		})
	}
}

/// `htlc-1`'s terms: direction (u8), payment hash (32), timeout (u32),
/// operator delay units (u16).
impl Encoding for HtlcTerms {
	fn encode_to(&self, w: &mut Vec<u8>) {
		w.push(self.direction.byte());
		w.extend(self.payment_hash);
		w.extend(self.timeout.to_consensus_u32().to_le_bytes());
		w.extend(self.operator_delay.units().to_le_bytes());
	}

	fn decode_from(r: &mut Reader) -> Result<HtlcTerms, DecodeError> {
		let b = r.u8()?;
		let direction = HtlcDirection::from_byte(b).ok_or(DecodeError::Flag(b))?;
		Ok(HtlcTerms {
			direction,
			payment_hash: r.array32()?,
			timeout: r.median_time()?,
			operator_delay: r.relative_time()?,
		})
	}
}

impl Encoding for NodePolicy {
	fn encode_to(&self, w: &mut Vec<u8>) {
		w.push(self.children().len() as u8);
		for c in self.children() {
			w.extend(asset_bytes(c.asset));
			w.extend(c.value.to_le_bytes());
			w.extend(c.program);
		}
		w.extend(self.operator().serialize());
		write_compact_size(w, self.owners().len() as u64);
		for o in self.owners() {
			w.extend(o.serialize());
		}
		self.sweep().encode_to(w);
		match self.reclaim_chain() {
			None => w.push(0),
			Some(c) => { w.push(1); w.extend(c.genesis_bytes()); },
		}
	}

	fn decode_from(r: &mut Reader) -> Result<NodePolicy, DecodeError> {
		let n = r.u8()? as usize;
		if n == 0 || n > MAX_CHILDREN {
			return Err(DecodeError::Count(n as u64));
		}
		let mut children = Vec::with_capacity(n);
		for _ in 0..n {
			children.push(Child { asset: r.asset()?, value: r.u64()?, program: r.array32()? });
		}
		let operator = r.key()?;
		let owners_n = r.compact_size()?;
		// Each owner takes 32 bytes: refuse a count the data cannot hold
		// before allocating for it.
		if owners_n > MAX_OWNERS as u64 || owners_n.saturating_mul(32) > r.remaining() as u64 {
			return Err(DecodeError::Count(owners_n));
		}
		let mut owners = Vec::with_capacity(owners_n as usize);
		for _ in 0..owners_n {
			owners.push(r.key()?);
		}
		let sweep = Sweep::decode_from(r)?;
		let reclaim = if r.flag()? { Some(r.chain()?) } else { None };
		Ok(NodePolicy::new(children, operator, owners, sweep, reclaim)?)
	}
}

impl Encoding for EntryPolicy {
	fn encode_to(&self, w: &mut Vec<u8>) {
		w.extend(self.unlock_hash);
		w.extend(asset_bytes(self.asset));
		w.extend(self.value.to_le_bytes());
		w.extend(self.leaf_program);
		self.sweep.encode_to(w);
	}

	fn decode_from(r: &mut Reader) -> Result<EntryPolicy, DecodeError> {
		Ok(EntryPolicy {
			unlock_hash: r.array32()?,
			asset: r.asset()?,
			value: r.u64()?,
			leaf_program: r.array32()?,
			sweep: Sweep::decode_from(r)?,
		})
	}
}

impl Encoding for ForfeitPolicy {
	fn encode_to(&self, w: &mut Vec<u8>) {
		w.extend(self.unlock_hash);
		w.extend(self.owner.serialize());
		w.extend(self.operator.serialize());
		w.extend(self.refund_delay.units().to_le_bytes());
		w.extend(self.leaf_id.0);
		w.extend(asset_bytes(self.connector));
	}

	fn decode_from(r: &mut Reader) -> Result<ForfeitPolicy, DecodeError> {
		Ok(ForfeitPolicy {
			unlock_hash: r.array32()?,
			owner: r.key()?,
			operator: r.key()?,
			refund_delay: r.relative_time()?,
			leaf_id: crate::record::LeafId(r.array32()?),
			connector: r.asset()?,
		})
	}
}

impl Encoding for CheckpointPolicy {
	fn encode_to(&self, w: &mut Vec<u8>) {
		w.extend(self.owner.serialize());
		w.extend(self.operator.serialize());
		w.extend(self.salt);
		w.extend(self.chain.genesis_bytes());
		self.sweep.encode_to(w);
	}

	fn decode_from(r: &mut Reader) -> Result<CheckpointPolicy, DecodeError> {
		Ok(CheckpointPolicy {
			owner: r.key()?,
			operator: r.key()?,
			salt: r.array32()?,
			chain: r.chain()?,
			sweep: Sweep::decode_from(r)?,
		})
	}
}

impl Encoding for OffboardPolicy {
	fn encode_to(&self, w: &mut Vec<u8>) {
		w.extend(self.unlock_hash);
		w.extend(asset_bytes(self.destination.asset));
		w.extend(self.destination.value.to_le_bytes());
		let spk = self.destination.script_pubkey.as_bytes();
		write_compact_size(w, spk.len() as u64);
		w.extend(spk);
		w.extend(self.operator.serialize());
		w.extend(self.reclaim_delay.units().to_le_bytes());
	}

	fn decode_from(r: &mut Reader) -> Result<OffboardPolicy, DecodeError> {
		let unlock_hash = r.array32()?;
		let asset = r.asset()?;
		let value = r.u64()?;
		let len = r.compact_size()?;
		if len > MAX_DESTINATION as u64 {
			return Err(DecodeError::Count(len));
		}
		let script = elements::Script::from(r.bytes(len as usize)?.to_vec());
		Ok(OffboardPolicy {
			unlock_hash,
			destination: ExplicitOutput::new(asset, value, script),
			operator: r.key()?,
			reclaim_delay: r.relative_time()?,
		})
	}
}

/// Any of the output policies, tagged with its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
	/// A leaf, `vtxo-1` or `htlc-1`.
	Leaf(LeafPolicy),
	Node(NodePolicy),
	Entry(EntryPolicy),
	Forfeit(ForfeitPolicy),
	Checkpoint(CheckpointPolicy),
	Offboard(OffboardPolicy),
}

impl Policy {
	/// The scriptPubKey of the output the policy describes.
	pub fn script_pubkey(&self) -> elements::Script {
		match self {
			Policy::Leaf(p) => p.script_pubkey(),
			Policy::Node(p) => p.script_pubkey(),
			Policy::Entry(p) => p.script_pubkey(),
			Policy::Forfeit(p) => p.script_pubkey(),
			Policy::Checkpoint(p) => p.script_pubkey(),
			Policy::Offboard(p) => p.script_pubkey(),
		}
	}
}

impl Encoding for Policy {
	fn encode_to(&self, w: &mut Vec<u8>) {
		w.push(VERSION);
		match self {
			Policy::Leaf(p) => { w.push(if p.htlc.is_some() { 6 } else { 1 }); p.encode_to(w) },
			Policy::Node(p) => { w.push(2); p.encode_to(w) },
			Policy::Entry(p) => { w.push(3); p.encode_to(w) },
			Policy::Forfeit(p) => { w.push(4); p.encode_to(w) },
			Policy::Checkpoint(p) => { w.push(5); p.encode_to(w) },
			Policy::Offboard(p) => { w.push(7); p.encode_to(w) },
		}
	}

	fn decode_from(r: &mut Reader) -> Result<Policy, DecodeError> {
		let v = r.u8()?;
		if v != VERSION {
			return Err(DecodeError::Version(v));
		}
		Ok(match r.u8()? {
			1 => Policy::Leaf(LeafPolicy::decode_from(r)?),
			2 => Policy::Node(NodePolicy::decode_from(r)?),
			3 => Policy::Entry(EntryPolicy::decode_from(r)?),
			4 => Policy::Forfeit(ForfeitPolicy::decode_from(r)?),
			5 => Policy::Checkpoint(CheckpointPolicy::decode_from(r)?),
			6 => {
				let mut p = LeafPolicy::decode_from(r)?;
				let t = HtlcTerms::decode_from(r)?;
				t.check(p.exit_delay)?;
				p.htlc = Some(t);
				Policy::Leaf(p)
			},
			7 => Policy::Offboard(OffboardPolicy::decode_from(r)?),
			t => return Err(DecodeError::PolicyType(t)),
		})
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn compact_sizes_are_canonical() {
		for n in [0u64, 1, 0xfc, 0xfd, 0xffff, 0x1_0000, 0xffff_ffff, 0x1_0000_0000] {
			let mut w = vec![];
			write_compact_size(&mut w, n);
			assert_eq!(Reader::new(&w).compact_size(), Ok(n));
		}
		assert_eq!(Reader::new(&[0xfd, 0xfc, 0x00]).compact_size(), Err(DecodeError::NonCanonical));
		assert_eq!(Reader::new(&[0xfe, 0xff, 0xff, 0, 0]).compact_size(), Err(DecodeError::NonCanonical));
		assert_eq!(Reader::new(&[0xff, 1, 0, 0, 0, 0, 0, 0, 0]).compact_size(), Err(DecodeError::NonCanonical));
	}
}
