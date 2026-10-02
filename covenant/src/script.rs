//! Script building blocks: script numbers, the injective output record, and
//! the opcode sequences that read records from the transaction.
//!
//! The node's introspection opcodes push an output's fields in a fixed shape:
//! `OP_INSPECTOUTPUTASSET` the 32-byte asset id in internal byte order, then a
//! prefix byte (`0x01` for explicit); `OP_INSPECTOUTPUTVALUE` the amount as 8
//! bytes little-endian, then a prefix byte; `OP_INSPECTOUTPUTSCRIPTPUBKEY` the
//! witness program, then the witness version as a script number, or for a
//! script that is not a witness program `SHA256(scriptPubKey)` and -1. Every
//! record here appends `version + 2`, which is always exactly one non-zero
//! byte, so no two different outputs give the same record.

use elements::confidential::{Asset, Nonce, Value};
use elements::hashes::{sha256, Hash};
use elements::opcodes::all::*;
use elements::script::Builder;
use elements::{AssetId, Script, TxOut, TxOutWitness};

/// SHA256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
	sha256::Hash::hash(data).to_byte_array()
}

/// The minimal script-number encoding of `n`: the bytes a stack element
/// holds, without a push opcode. Zero is the empty element.
pub fn scriptnum(n: i64) -> Vec<u8> {
	if n == 0 {
		return vec![];
	}
	let neg = n < 0;
	let mut a = n.unsigned_abs();
	let mut out = vec![];
	while a > 0 {
		out.push((a & 0xff) as u8);
		a >>= 8;
	}
	let last = out.len() - 1;
	if out[last] & 0x80 != 0 {
		out.push(if neg { 0x80 } else { 0 });
	} else if neg {
		out[last] |= 0x80;
	}
	out
}

/// The asset id as the introspection opcodes push it: internal byte order,
/// the reverse of the hex that RPCs print.
pub fn asset_bytes(asset: AssetId) -> [u8; 32] {
	asset.into_inner().to_byte_array()
}

/// The witness version and program of a scriptPubKey, as the node reads them
/// (`CScript::IsWitnessProgram`): 4 to 42 bytes, a version opcode, then one
/// push that fills the rest.
pub fn witness_program(spk: &Script) -> Option<(u8, &[u8])> {
	let b = spk.as_bytes();
	if b.len() < 4 || b.len() > 42 {
		return None;
	}
	let version = match b[0] {
		0x00 => 0,
		v @ 0x51..=0x60 => v - 0x50,
		_ => return None,
	};
	if b[1] as usize + 2 != b.len() {
		return None;
	}
	Some((version, &b[2..]))
}

/// The injective record of an explicit output paying `spk`:
///
/// ```text
/// asset(32) ‖ 0x01 ‖ 0x01 ‖ value(8, LE) ‖ program ‖ (witness_version + 2)
/// ```
///
/// For a scriptPubKey that is not a witness program the program is
/// `SHA256(scriptPubKey)` and the last byte `0x01`.
pub fn record(asset: AssetId, value: u64, spk: &Script) -> Vec<u8> {
	let mut r = Vec::with_capacity(75);
	r.extend(asset_bytes(asset));
	r.extend([0x01, 0x01]);
	r.extend(value.to_le_bytes());
	match witness_program(spk) {
		Some((version, program)) => {
			r.extend(program);
			r.push(version + 2);
		},
		None => {
			r.extend(sha256(spk.as_bytes()));
			r.push(0x01);
		},
	}
	r
}

/// An output with an explicit asset and value: what a covenant pins and what
/// a rebindable signature commits to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExplicitOutput {
	pub asset: AssetId,
	pub value: u64,
	pub script_pubkey: Script,
}

impl ExplicitOutput {
	pub fn new(asset: AssetId, value: u64, script_pubkey: Script) -> ExplicitOutput {
		ExplicitOutput { asset, value, script_pubkey }
	}

	/// The output's fields, when its asset and value are explicit.
	pub fn from_txout(txout: &TxOut) -> Option<ExplicitOutput> {
		Some(ExplicitOutput {
			asset: txout.asset.explicit()?,
			value: txout.value.explicit()?,
			script_pubkey: txout.script_pubkey.clone(),
		})
	}

	/// Its injective record.
	pub fn record(&self) -> Vec<u8> {
		record(self.asset, self.value, &self.script_pubkey)
	}

	/// The transaction output: explicit asset and value, no nonce.
	pub fn txout(&self) -> TxOut {
		TxOut {
			asset: Asset::Explicit(self.asset),
			value: Value::Explicit(self.value),
			nonce: Nonce::Null,
			script_pubkey: self.script_pubkey.clone(),
			witness: TxOutWitness::default(),
		}
	}
}

/// A child a tree node pins: an explicit output paying a taproot program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Child {
	pub asset: AssetId,
	pub value: u64,
	/// The child's witness v1 program (its taproot output key).
	pub program: [u8; 32],
}

impl Child {
	pub fn new(asset: AssetId, value: u64, program: [u8; 32]) -> Child {
		Child { asset, value, program }
	}

	/// The child's scriptPubKey: `OP_1 <program>`.
	pub fn script_pubkey(&self) -> Script {
		Builder::new().push_int(1).push_slice(&self.program).into_script()
	}

	pub fn output(&self) -> ExplicitOutput {
		ExplicitOutput::new(self.asset, self.value, self.script_pubkey())
	}

	/// Its 75-byte injective record.
	pub fn record(&self) -> Vec<u8> {
		record(self.asset, self.value, &self.script_pubkey())
	}
}

/// `H`: SHA256 of the children's records, in order.
pub fn children_hash(children: &[Child]) -> [u8; 32] {
	let mut blob = Vec::with_capacity(75 * children.len());
	for c in children {
		blob.extend(c.record());
	}
	sha256(&blob)
}

/// Opcode sequences that read records, as extensions of the script builder.
pub(crate) trait BuilderExt: Sized {
	/// Leaves the record of output `i`.
	fn output_record(self, i: i64) -> Self;
	/// Leaves the record of the output at this input's own index.
	fn current_output_record(self) -> Self;
	/// Leaves `asset ‖ 0x01 ‖ 0x01 ‖ value` of this input: the record without
	/// its script part.
	fn current_input_record(self) -> Self;
	fn ops(self, ops: &[elements::opcodes::All]) -> Self;
}

impl BuilderExt for Builder {
	fn output_record(self, i: i64) -> Builder {
		self.push_int(i).ops(&[OP_INSPECTOUTPUTASSET, OP_CAT])
			.push_int(i).ops(&[OP_INSPECTOUTPUTVALUE, OP_SWAP, OP_CAT, OP_CAT])
			.push_int(i).ops(&[OP_INSPECTOUTPUTSCRIPTPUBKEY]).push_int(2).ops(&[OP_ADD, OP_CAT, OP_CAT])
	}

	fn current_output_record(self) -> Builder {
		self.ops(&[
			OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTASSET, OP_CAT,
			OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTVALUE, OP_SWAP, OP_CAT, OP_CAT,
			OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTSCRIPTPUBKEY,
		]).push_int(2).ops(&[OP_ADD, OP_CAT, OP_CAT])
	}

	fn current_input_record(self) -> Builder {
		self.ops(&[
			OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTASSET, OP_CAT,
			OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTVALUE, OP_SWAP, OP_CAT, OP_CAT,
		])
	}

	fn ops(mut self, ops: &[elements::opcodes::All]) -> Builder {
		for op in ops {
			self = self.push_opcode(*op);
		}
		self
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn script_numbers() {
		assert_eq!(scriptnum(0), Vec::<u8>::new());
		assert_eq!(scriptnum(1), vec![1]);
		assert_eq!(scriptnum(-1), vec![0x81]);
		assert_eq!(scriptnum(127), vec![0x7f]);
		assert_eq!(scriptnum(128), vec![0x80, 0x00]);
		assert_eq!(scriptnum(-128), vec![0x80, 0x80]);
		assert_eq!(scriptnum(255), vec![0xff, 0x00]);
		assert_eq!(scriptnum(256), vec![0x00, 0x01]);
		assert_eq!(scriptnum(4194558), vec![0xfe, 0x00, 0x40]);
	}

	#[test]
	fn records_are_injective_where_the_raw_version_is_not() {
		// v1 <P> and v0 <P ‖ 0x01> differ in their last byte.
		let a = AssetId::from_byte_array([7; 32]);
		let p = [9u8; 32];
		let v1 = Builder::new().push_int(1).push_slice(&p).into_script();
		let mut p33 = p.to_vec();
		p33.push(0x01);
		let v0 = Builder::new().push_int(0).push_slice(&p33).into_script();
		assert_ne!(record(a, 1, &v1), record(a, 1, &v0));
		assert_eq!(record(a, 1, &v1).len(), 75);
		assert_eq!(*record(a, 1, &v1).last().unwrap(), 3);
		assert_eq!(*record(a, 1, &v0).last().unwrap(), 2);
		// A fee output: SHA256 of the empty script, version -1.
		let fee = record(a, 5, &Script::new());
		assert_eq!(&fee[42..74], &sha256(&[])[..]);
		assert_eq!(fee[74], 1);
		// A 43-byte script whose second byte matches its length is not a
		// witness program to the node (programs are 2 to 40 bytes).
		let mut long = vec![0x51, 41];
		long.extend([0u8; 41]);
		assert!(witness_program(&Script::from(long)).is_none());
	}
}
