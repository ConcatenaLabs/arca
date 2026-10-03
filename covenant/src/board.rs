//! The board: an owner's own coins brought into Arca (`board-1`).
//!
//! The owner pays its coins to a board output. No tree is involved, so no
//! operator signature is needed. The board output carries two script leaves:
//!
//! ```text
//! collab:   the leaf's collaborative path: the owner's and the operator's
//!           rebindable signatures, exactly as on the leaf the board converts into
//! convert:  <A> OP_CHECKSIGVERIFY
//!           OP_0 OP_INSPECTOUTPUTASSET OP_1 OP_EQUALVERIFY <asset> OP_EQUALVERIFY
//!           OP_0 OP_INSPECTOUTPUTVALUE OP_1 OP_EQUALVERIFY <value_le8> OP_EQUALVERIFY
//!           OP_0 OP_INSPECTOUTPUTSCRIPTPUBKEY OP_1 OP_EQUALVERIFY <leaf program> OP_EQUAL
//! ```
//!
//! The owner alone can take the board only by converting it, with its
//! signature, into the standard leaf (`vtxo-1`) of the same value at output 0;
//! the leaf's exit delay then runs from the conversion. So every unilateral
//! exit of a board gives the full notice of a leaf, and nobody but the owner
//! can start it. The board holds exactly the leaf's value, and the conversion
//! pays its fee with a coin attached, in any accepted asset.
//!
//! Because the collaborative leaf is the leaf's own script and the board holds
//! the leaf's value, every pair the owner and the operator sign over the
//! leaf (a forfeit, a checkpoint) spends the coin in either form: the board
//! output as it is, or the leaf after a conversion. Off-chain spends of a
//! board are signed in advance, as for any leaf: the operator holding a
//! board's forfeit publishes it from the board output whenever it wants the
//! value, and answers a conversion by publishing it on the leaf within the
//! exit delay. A board's refresh needs no forfeit on-chain first.
//!
//! The leaf's salt is built from the owner's nonce and one the operator gave
//! it, as for every leaf ([`crate::leaf::leaf_salt`]), so the operator, which
//! never repeats its nonce, can tell the board's scripts were never funded
//! before. The operator credits the board once the transaction is final: its
//! block certified and its anchor buried; the risk of a board reorged away is
//! the operator's, which is why it waits.
//!
//! A converted board is an Arca leaf on-chain, and an Arca leaf on-chain is
//! never spent off-chain again: past its delay its owner can exit at once.
//!
//! [`BoardRecord`] is what the owner keeps and what the operator registers:
//! the leaf's parameters, its asset and value, the chain and the operator.
//! [`BoardRecord::tx`] builds the funding transaction from the owner's coins,
//! whose signatures are the owner's wallet's, [`BoardRecord::validate`] checks
//! the record against it under a wallet's policy, and [`BoardPolicy`] builds
//! the board output and its conversion.
//!
//! # The binary form, version 2
//!
//! ```text
//! u8    format version, 2
//! u8    template, 2 (board)           u8   template version, 1
//! [32]  owner key A
//! [32]  owner nonce                   the salt is SHA256("Arca/salt" ‖ owner nonce ‖ operator nonce)
//! [32]  operator nonce
//! u16   exit delay, 512-second units
//! [32]  asset, internal byte order
//! u64   value
//! [32]  genesis hash, internal byte order
//! [32]  operator key S
//! ```
//!
//! The leaf id of a board is the leaf id of a batch of no levels whose batch
//! output is the board output: the BIP340 tagged hash, tag `Arca/leaf-id`, of
//! `board program (32) ‖ 0x00 ‖ leaf program (32)`. A leaf of a batch always
//! has at least one level, so the two never meet.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, LockTime, OutPoint, Script, Transaction, TxIn, TxOut, Txid};

use crate::encode::{DecodeError, Reader};
use crate::leaf::{leaf_salt, LeafPolicy};
use crate::message::{Chain, CsfsMessage};
use crate::record::{LeafId, RecordError, Template, WalletPolicy, MAX_VALUE};
use crate::script::{asset_bytes, ExplicitOutput};
use crate::spend::{assemble, explicit_txout, margins, FeeSource, KeySpend, Rebindable, SpendError, UnrollTx, FINAL};
use crate::taptree::TapOutput;
use crate::time::RelativeTime;
use crate::Error;

/// The board record format this crate writes and reads.
pub const BOARD_RECORD_VERSION: u8 = 2;

/// A board output's policy: the leaf it converts into, and its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoardPolicy {
	/// The standard leaf the board converts into.
	pub leaf: LeafPolicy,
	pub asset: AssetId,
	/// The board's value, which the leaf holds after a conversion.
	pub value: u64,
}

impl BoardPolicy {
	/// The conversion: the owner's signature, then output 0 pinned to the
	/// leaf, holding the board's asset and value.
	pub fn convert_script(&self) -> Script {
		Builder::new().push_slice(&self.leaf.owner.serialize()).push_opcode(OP_CHECKSIGVERIFY)
			.push_int(0).push_opcode(OP_INSPECTOUTPUTASSET).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&asset_bytes(self.asset)).push_opcode(OP_EQUALVERIFY)
			.push_int(0).push_opcode(OP_INSPECTOUTPUTVALUE).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.value.to_le_bytes()).push_opcode(OP_EQUALVERIFY)
			.push_int(0).push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.leaf.program()).push_opcode(OP_EQUAL)
			.into_script()
	}

	/// `[collab, convert]`, both at depth 1; `collab` is the leaf's own.
	pub fn taproot(&self) -> TapOutput {
		TapOutput::new(vec![(1, self.leaf.collab_script()), (1, self.convert_script())])
	}

	pub fn script_pubkey(&self) -> Script {
		self.taproot().script_pubkey()
	}

	pub fn program(&self) -> [u8; 32] {
		self.taproot().program()
	}

	/// The board output.
	pub fn output(&self) -> ExplicitOutput {
		ExplicitOutput::new(self.asset, self.value, self.script_pubkey())
	}

	/// The leaf a conversion creates.
	pub fn leaf_output(&self) -> ExplicitOutput {
		ExplicitOutput::new(self.asset, self.value, self.leaf.script_pubkey())
	}

	/// The owner's conversion of the board at `board`: the leaf at output 0,
	/// the fee paid as `fee` says (the board holds no margin, so a coin of the
	/// owner's in any accepted asset pays it). The owner signs
	/// [`KeySpend::sighash`] and finishes it with `[signature]`.
	pub fn conversion(&self, board: OutPoint, fee: &FeeSource) -> Result<KeySpend, SpendError> {
		let u = assemble(LockTime::ZERO, vec![(board, self.output().txout(), FINAL)], &[self.leaf_output()], fee, FINAL)?;
		Ok(KeySpend::from_parts(u.tx, u.prevouts, self.taproot(), self.convert_script()))
	}

	/// The full conversion witness: the owner's signature.
	pub fn convert_witness(&self, owner_sig: &Signature) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.convert_script(), vec![owner_sig.as_ref().to_vec()])
	}
}

/// The board output's collaborative path is the leaf's: one pair spends the
/// coin as a board or as the leaf it converts into.
impl Rebindable for BoardPolicy {
	fn owner(&self) -> XOnlyPublicKey {
		self.leaf.owner
	}

	fn operator(&self) -> XOnlyPublicKey {
		self.leaf.operator
	}

	fn tap(&self) -> TapOutput {
		self.taproot()
	}

	fn collab(&self) -> Script {
		self.leaf.collab_script()
	}

	fn message(&self, asset_in: AssetId, value_in: u64, outputs: &[ExplicitOutput]) -> Result<CsfsMessage, Error> {
		self.leaf.message(asset_in, value_in, outputs)
	}
}

/// What the owner of a board keeps. See the [module documentation](self).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoardRecord {
	/// Always [`Template::Board1`].
	pub template: Template,
	/// The owner's key `A`.
	pub owner: XOnlyPublicKey,
	/// The owner's contribution to the leaf's salt.
	pub owner_nonce: [u8; 32],
	/// The operator's contribution to the leaf's salt.
	pub operator_nonce: [u8; 32],
	/// The exit delay of the leaf the board converts into.
	pub exit_delay: RelativeTime,
	pub asset: AssetId,
	pub value: u64,
	pub chain: Chain,
	/// The operator's key `S`.
	pub operator: XOnlyPublicKey,
}

/// What [`BoardRecord::validate`] returns for a board it accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidBoard {
	pub leaf_id: LeafId,
	/// The board transaction.
	pub txid: Txid,
	/// The index of the board output in it.
	pub vout: u32,
}

impl ValidBoard {
	/// Where the board output is.
	pub fn outpoint(&self) -> OutPoint {
		OutPoint::new(self.txid, self.vout)
	}
}

impl BoardRecord {
	/// The leaf's salt, rebuilt from the two nonces.
	pub fn salt(&self) -> [u8; 32] {
		leaf_salt(&self.owner_nonce, &self.operator_nonce)
	}

	/// The leaf the board converts into.
	pub fn leaf(&self) -> LeafPolicy {
		LeafPolicy {
			owner: self.owner, operator: self.operator, salt: self.salt(), chain: self.chain, exit_delay: self.exit_delay,
		}
	}

	/// The board output's policy.
	pub fn policy(&self) -> BoardPolicy {
		BoardPolicy { leaf: self.leaf(), asset: self.asset, value: self.value }
	}

	/// The board output the board transaction pays.
	pub fn output(&self) -> ExplicitOutput {
		self.policy().output()
	}

	/// The board's leaf id.
	pub fn leaf_id(&self) -> LeafId {
		LeafId::compute(&self.policy().program(), &[], &self.leaf().program())
	}

	/// The template and the value bounds: `board-1`, 1 to [`MAX_VALUE`].
	pub fn check(&self) -> Result<(), RecordError> {
		if self.template != Template::Board1 {
			return Err(RecordError::Template(self.template.to_string()));
		}
		if self.value == 0 || self.value > MAX_VALUE {
			return Err(RecordError::Value(self.value));
		}
		Ok(())
	}

	/// The wallet's check that the record is for its key and for the nonce it
	/// picked, as [`crate::LeafRecord::check_owner`].
	pub fn check_owner(&self, owner: &XOnlyPublicKey, owner_nonce: &[u8; 32]) -> Result<(), RecordError> {
		if self.owner != *owner {
			return Err(RecordError::NotOwner);
		}
		if self.owner_nonce != *owner_nonce {
			return Err(RecordError::OwnerNonce);
		}
		Ok(())
	}

	/// The board transaction: `coins`, the owner's own outputs (any assets,
	/// explicit), pay the board output at output 0; what is left of each
	/// asset goes to `change`, less `fee` of `fee_asset`, which goes to the
	/// fee output. The fee defaults to the board's own asset in a wallet,
	/// never to a privileged one. The inputs' witnesses are the owner's
	/// wallet's to add.
	pub fn tx(&self, coins: &[(OutPoint, TxOut)], fee_asset: AssetId, fee: u64, change: &Script) -> Result<UnrollTx, SpendError> {
		if self.value == 0 || self.value > MAX_VALUE {
			return Err(SpendError::Value(self.value));
		}
		let mut held = Vec::with_capacity(coins.len());
		for (_, o) in coins {
			match (o.asset.explicit(), o.value.explicit()) {
				(Some(a), Some(v)) => held.push((a, v)),
				_ => return Err(SpendError::NotExplicit),
			}
		}
		let left = margins(&held, &[self.output()])?;
		let in_fee_asset = left.iter().find(|(a, _)| *a == fee_asset).map(|(_, v)| *v).unwrap_or(0);
		if in_fee_asset < fee {
			return Err(SpendError::Overspend { asset: fee_asset, outputs: fee, available: in_fee_asset });
		}
		let mut output = vec![self.output().txout()];
		for (a, v) in left {
			let v = if a == fee_asset { v - fee } else { v };
			if v > 0 {
				output.push(explicit_txout(a, v, change.clone()));
			}
		}
		if fee > 0 {
			output.push(TxOut::new_fee(fee, fee_asset));
		}
		let tx = Transaction {
			version: 2,
			lock_time: LockTime::ZERO,
			input: coins.iter().map(|(op, _)| TxIn { previous_output: *op, sequence: FINAL, ..Default::default() }).collect(),
			output,
		};
		Ok(UnrollTx { tx, prevouts: coins.iter().map(|(_, o)| o.clone()).collect() })
	}

	/// Checks the record against the board transaction under `policy`: the
	/// chain and operator are the wallet's, the leaf's exit delay is within
	/// its bounds, and the transaction pays exactly one output equal to the
	/// board output the record rebuilds (asset, value and script). Whether
	/// the board is final (its block certified and its anchor buried) is for
	/// the caller to establish.
	pub fn validate(&self, board: &Transaction, policy: &WalletPolicy) -> Result<ValidBoard, RecordError> {
		self.check()?;
		if self.chain != policy.chain {
			return Err(RecordError::WrongChain);
		}
		if self.operator != policy.operator {
			return Err(RecordError::WrongOperator);
		}
		if !policy.exit_delay_ok(self.exit_delay) {
			return Err(RecordError::ExitDelay {
				delay: self.exit_delay.units(), min: policy.min_exit_delay.units(), max: policy.max_exit_delay.units(),
			});
		}
		let out = self.output();
		let found: Vec<u32> = board.output.iter().enumerate()
			.filter(|(_, o)| ExplicitOutput::from_txout(o).as_ref() == Some(&out))
			.map(|(i, _)| i as u32)
			.collect();
		match found[..] {
			[] => Err(RecordError::BoardOutputMissing),
			[vout] => Ok(ValidBoard { leaf_id: self.leaf_id(), txid: board.txid(), vout }),
			_ => Err(RecordError::BoardOutputRepeated(found.len())),
		}
	}

	/// The binary form.
	pub fn to_bytes(&self) -> Result<Vec<u8>, RecordError> {
		self.check()?;
		let mut w = Vec::with_capacity(205);
		w.extend([BOARD_RECORD_VERSION, self.template.id(), self.template.version()]);
		w.extend(self.owner.serialize());
		w.extend(self.owner_nonce);
		w.extend(self.operator_nonce);
		w.extend(self.exit_delay.units().to_le_bytes());
		w.extend(asset_bytes(self.asset));
		w.extend(self.value.to_le_bytes());
		w.extend(self.chain.genesis_bytes());
		w.extend(self.operator.serialize());
		Ok(w)
	}

	/// Reads the binary form, which must hold exactly one record.
	pub fn from_bytes(data: &[u8]) -> Result<BoardRecord, RecordError> {
		let mut r = Reader::new(data);
		let version = r.u8()?;
		if version != BOARD_RECORD_VERSION {
			return Err(RecordError::Version(version as u64));
		}
		let template_id = r.u8()?;
		let template_version = r.u8()?;
		let record = BoardRecord {
			template: Template::from_id(template_id, template_version)?,
			owner: r.key()?,
			owner_nonce: r.array32()?,
			operator_nonce: r.array32()?,
			exit_delay: r.relative_time()?,
			asset: r.asset()?,
			value: r.u64()?,
			chain: r.chain()?,
			operator: r.key()?,
		};
		if r.remaining() != 0 {
			return Err(DecodeError::TrailingBytes(r.remaining()).into());
		}
		record.check()?;
		Ok(record)
	}
}

#[cfg(feature = "json")]
mod json {
	use elements::hashes::Hash;
	use elements::{AssetId, BlockHash};
	use serde_json::{Map, Value};

	use super::{BoardRecord, BOARD_RECORD_VERSION};
	use crate::message::Chain;
	use crate::record::{RecordError, Template};
	use crate::record_json::{amount, bytes32, canonical_text, display, display32, hex, int, key, object, string, strict, units};
	use crate::script::asset_bytes;

	impl BoardRecord {
		/// The JSON form: the binary form's fields, named as the leaf
		/// record's are (`version`, `template`, `owner`, `owner_nonce`,
		/// `operator_nonce`, `exit_delay_units`, `asset`, `value`,
		/// `genesis_hash`, `operator`), with the same conventions.
		pub fn to_json(&self) -> Result<Value, RecordError> {
			self.check()?;
			let mut m = Map::new();
			m.insert("version".into(), BOARD_RECORD_VERSION.into());
			m.insert("template".into(), Value::String(self.template.to_string()));
			m.insert("owner".into(), Value::String(hex(&self.owner.serialize())));
			m.insert("owner_nonce".into(), Value::String(hex(&self.owner_nonce)));
			m.insert("operator_nonce".into(), Value::String(hex(&self.operator_nonce)));
			m.insert("exit_delay_units".into(), self.exit_delay.units().into());
			m.insert("asset".into(), Value::String(display(asset_bytes(self.asset))));
			m.insert("value".into(), Value::String(self.value.to_string()));
			m.insert("genesis_hash".into(), Value::String(display(self.chain.genesis_bytes())));
			m.insert("operator".into(), Value::String(hex(&self.operator.serialize())));
			Ok(Value::Object(m))
		}

		/// The canonical JSON text.
		pub fn to_json_string(&self) -> Result<String, RecordError> {
			Ok(canonical_text(&self.to_json()?))
		}

		/// Reads the JSON text, refusing a repeated key and trailing
		/// characters.
		pub fn from_json_str(text: &str) -> Result<BoardRecord, RecordError> {
			BoardRecord::from_json(&strict(text)?)
		}

		/// Reads the JSON form.
		pub fn from_json(v: &Value) -> Result<BoardRecord, RecordError> {
			let m = object(v, "board", &[
				"version", "template", "owner", "owner_nonce", "operator_nonce", "exit_delay_units", "asset", "value",
				"genesis_hash", "operator",
			])?;
			let version = int(m, "version", u64::MAX)?;
			if version != BOARD_RECORD_VERSION as u64 {
				return Err(RecordError::Version(version));
			}
			let template: Template = string(m, "template")?.parse()?;
			let record = BoardRecord {
				template,
				owner: key(m, "owner")?,
				owner_nonce: bytes32(m, "owner_nonce")?,
				operator_nonce: bytes32(m, "operator_nonce")?,
				exit_delay: units(m, "exit_delay_units")?,
				asset: AssetId::from_byte_array(display32(m, "asset")?),
				value: amount(m, "value")?,
				chain: Chain::new(BlockHash::from_byte_array(display32(m, "genesis_hash")?)),
				operator: key(m, "operator")?,
			};
			record.check()?;
			Ok(record)
		}
	}
}
