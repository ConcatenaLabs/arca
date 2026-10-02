//! Script verification under Sequentia's consensus rules, for tests.
//!
//! The verifier runs the Sequentia node's own script interpreter, linked from
//! the node's consensus library (see `build.rs`), so a verdict here is the
//! verdict the node reaches when it validates the same input in a block. It
//! covers everything the interpreter does: tapscript at leaf version `0xc4`
//! with the Elements introspection opcodes, `OP_CHECKSIGFROMSTACK`, `OP_CAT`
//! and the streaming SHA256 opcodes, the time locks, and Simplicity at leaf
//! version `0xbe`.
//!
//! What it does not check is everything outside the script: whether the
//! inputs exist and are unspent, the value balance, fees, the transaction's
//! own lock time and the relative locks of BIP68 against the chain. A test that
//! needs those runs the transaction against a node.
//!
//! The call shape matches the Bitcoin verifier the library's tests used before:
//! the outputs being spent, the index of the input, and the transaction.

use elements::encode::serialize;
use elements::{BlockHash, Transaction, TxOut};
use elements::hashes::Hash;

mod ffi {
	use std::os::raw::{c_char, c_int, c_uint, c_uchar};

	pub const ARCA_OK: c_int = 0;
	pub const ARCA_SCRIPT_INVALID: c_int = 1;
	pub const ARCA_ERR_TX_DESERIALIZE: c_int = 2;
	pub const ARCA_ERR_SPENT_DESERIALIZE: c_int = 3;
	pub const ARCA_ERR_TX_INDEX: c_int = 4;
	pub const ARCA_ERR_SPENT_COUNT: c_int = 5;

	extern "C" {
		pub fn arca_verify_input(
			genesis_hash: *const c_uchar,
			tx: *const c_uchar, tx_len: usize,
			spent: *const c_uchar, spent_len: usize,
			n_in: c_uint, flags: c_uint, script_error: *mut c_int,
		) -> c_int;
		pub fn arca_script_error_string(script_error: c_int) -> *const c_char;
		pub fn arca_standard_flags() -> c_uint;
		pub fn arca_consensus_flags() -> c_uint;
	}
}

/// Script verification flags, as the node's interpreter defines them.
pub mod flags {
	/// Every script rule a block enforces on a Sequentia chain whose
	/// deployments are all active, which is every chain run from genesis
	/// (taproot, Simplicity and its wider budget, `SIGHASH_RANGEPROOF`).
	pub fn consensus() -> u32 {
		unsafe { super::ffi::arca_consensus_flags() }
	}

	/// The node's standard script flags: what its mempool checks before it
	/// checks the block rules.
	pub fn standard() -> u32 {
		unsafe { super::ffi::arca_standard_flags() }
	}
}

/// Why an input did not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
	/// The interpreter rejected the script. `message` is the node's own text
	/// for the error, the one its RPCs print inside the reject reason.
	#[error("script verification failed: {message}")]
	Script {
		/// The node's `ScriptError` number.
		code: i32,
		/// The node's description of it.
		message: String,
		/// The flags the input was verified under.
		flags: u32,
	},
	/// The input index is past the transaction's inputs.
	#[error("input index {index} is out of range for a transaction with {inputs} inputs")]
	InputIndex { index: usize, inputs: usize },
	/// One spent output is needed for every input.
	#[error("{spent} spent outputs given for a transaction with {inputs} inputs")]
	SpentOutputCount { spent: usize, inputs: usize },
	/// The node could not decode the transaction's serialisation.
	#[error("the node could not decode the transaction")]
	TxDecode,
	/// The node could not decode the spent outputs.
	#[error("the node could not decode the spent outputs")]
	SpentOutputDecode,
}

/// A script verifier for one chain.
///
/// Signature hashes on Sequentia commit to the chain's genesis block hash, so
/// the verifier carries it.
#[derive(Debug, Clone)]
pub struct Verifier {
	genesis_hash: BlockHash,
	flag_sets: Vec<u32>,
}

impl Verifier {
	/// A verifier that applies the consensus rules of a block.
	pub fn consensus(genesis_hash: BlockHash) -> Verifier {
		Verifier { genesis_hash, flag_sets: vec![flags::consensus()] }
	}

	/// A verifier that applies the node's mempool script checks: the standard
	/// flags, then the block rules, as the node does on acceptance.
	pub fn standard(genesis_hash: BlockHash) -> Verifier {
		Verifier { genesis_hash, flag_sets: vec![flags::standard(), flags::consensus()] }
	}

	/// A verifier that applies exactly the given flags.
	pub fn with_flags(genesis_hash: BlockHash, flags: u32) -> Verifier {
		Verifier { genesis_hash, flag_sets: vec![flags] }
	}

	/// The genesis block hash the verifier signs against.
	pub fn genesis_hash(&self) -> BlockHash {
		self.genesis_hash
	}

	/// Verify input `input_idx` of `tx`, which spends `spent_outputs`
	/// (one per input, in input order).
	pub fn verify_input(
		&self,
		spent_outputs: &[TxOut],
		input_idx: usize,
		tx: &Transaction,
	) -> Result<(), Error> {
		if input_idx >= tx.input.len() {
			return Err(Error::InputIndex { index: input_idx, inputs: tx.input.len() });
		}
		if spent_outputs.len() != tx.input.len() {
			return Err(Error::SpentOutputCount {
				spent: spent_outputs.len(), inputs: tx.input.len(),
			});
		}
		let tx_bytes = serialize(tx);
		let spent_bytes = serialize(&spent_outputs.to_vec());
		let genesis = self.genesis_hash.to_byte_array();
		for &flags in &self.flag_sets {
			let mut script_error = 0;
			let ret = unsafe {
				ffi::arca_verify_input(
					genesis.as_ptr(),
					tx_bytes.as_ptr(), tx_bytes.len(),
					spent_bytes.as_ptr(), spent_bytes.len(),
					input_idx as u32, flags, &mut script_error,
				)
			};
			match ret {
				ffi::ARCA_OK => {},
				ffi::ARCA_SCRIPT_INVALID => return Err(Error::Script {
					code: script_error,
					message: script_error_string(script_error),
					flags,
				}),
				ffi::ARCA_ERR_TX_DESERIALIZE => return Err(Error::TxDecode),
				ffi::ARCA_ERR_SPENT_DESERIALIZE => return Err(Error::SpentOutputDecode),
				ffi::ARCA_ERR_TX_INDEX => unreachable!("index checked above"),
				ffi::ARCA_ERR_SPENT_COUNT => unreachable!("count checked above"),
				other => unreachable!("unknown verifier result {}", other),
			}
		}
		Ok(())
	}

	/// Verify every input of `tx`. On failure, returns the index of the
	/// first input that did not verify.
	pub fn verify_tx(&self, spent_outputs: &[TxOut], tx: &Transaction) -> Result<(), (usize, Error)> {
		for idx in 0..tx.input.len() {
			self.verify_input(spent_outputs, idx, tx).map_err(|e| (idx, e))?;
		}
		Ok(())
	}
}

/// Verify input `input_idx` of `tx` under the consensus rules of the chain
/// whose genesis block is `genesis_hash`.
pub fn verify_tx(
	genesis_hash: BlockHash,
	spent_outputs: &[TxOut],
	input_idx: usize,
	tx: &Transaction,
) -> Result<(), Error> {
	Verifier::consensus(genesis_hash).verify_input(spent_outputs, input_idx, tx)
}

/// The node's description of a script error number.
pub fn script_error_string(code: i32) -> String {
	unsafe {
		std::ffi::CStr::from_ptr(ffi::arca_script_error_string(code))
			.to_string_lossy().into_owned()
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn flags_match_the_node_headers() {
		// P2SH, DERSIG, NULLDUMMY, CLTV, CSV, WITNESS, TAPROOT,
		// SIGHASH_RANGEPROOF, SIMPLICITY, SIMPLICITY_BUDGET4
		assert_eq!(flags::consensus(), 0x01c2_0e15);
		// The mempool checks every block rule except the two that only widen
		// what a block accepts: SIGHASH_RANGEPROOF and the Simplicity budget.
		let widening = (1 << 22) | (1 << 24);
		assert_eq!(flags::standard() & flags::consensus(), flags::consensus() & !widening);
	}

	#[test]
	fn error_strings_come_from_the_node() {
		assert_eq!(script_error_string(0), "No error");
		assert_eq!(
			script_error_string(2),
			"Script evaluated without error but finished with a false/empty top stack element",
		);
	}

	#[test]
	fn argument_errors() {
		let tx = Transaction { version: 2, lock_time: elements::LockTime::ZERO, input: vec![], output: vec![] };
		let v = Verifier::consensus(BlockHash::all_zeros());
		assert_eq!(v.verify_input(&[], 0, &tx), Err(Error::InputIndex { index: 0, inputs: 0 }));
	}
}
