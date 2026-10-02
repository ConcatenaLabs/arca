//! The board: an owner's own coins paid to a leaf.
//!
//! The owner pays its coins to an output carrying the standard leaf script
//! (`vtxo-1`). No tree is involved, so no operator signature is needed. The
//! leaf's salt is built from the owner's nonce and one the operator gave it,
//! as for every leaf ([`crate::leaf::leaf_salt`]), so the operator, which
//! never repeats its nonce, can tell the board's script was never funded
//! before. The operator credits the board once the transaction is certified
//! and its anchor is buried; the risk of a board reorged away is the
//! operator's, which is why it waits.
//!
//! [`BoardRecord`] is what the owner keeps and what the operator registers:
//! the leaf's parameters, its asset and value, the chain and the operator.
//! [`BoardRecord::tx`] builds the funding transaction from the owner's coins,
//! whose signatures are the owner's wallet's, and
//! [`BoardRecord::validate`] checks the record against it.
//!
//! # A board leaf is on-chain from the start
//!
//! A leaf's exit delay runs from the confirmation of the output it spends. A
//! leaf in a batch reaches the chain only when someone unrolls it, so the
//! operator and any watcher have the whole delay to answer a stale exit with
//! the checkpoint or forfeit it holds. A board leaf confirms with the board:
//! once its delay has passed after that, the owner can exit at any moment,
//! and an exit races any off-chain spend of the same leaf with nothing to
//! wait for. So a board leaf takes no spend whose safety rests on an answer
//! in time. Its refresh into a round is a forfeit that is broadcast and
//! final before the operator hands over the preimage, and an offboard of it
//! the same; it is not transferred out of round with a checkpoint, because
//! the sender could exit it under the receiver.
//!
//! # The binary form, version 1
//!
//! ```text
//! u8    format version, 1
//! u8    template, 1 (vtxo)            u8   template version, 1
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
//! output is the leaf: the BIP340 tagged hash, tag `Arca/leaf-id`, of
//! `leaf program (32) ‖ 0x00 ‖ leaf program (32)`. A leaf of a batch always
//! has at least one level, so the two never meet.

use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, LockTime, OutPoint, Script, Transaction, TxIn, TxOut};

use crate::encode::{DecodeError, Reader};
use crate::leaf::{leaf_salt, LeafPolicy};
use crate::message::Chain;
use crate::record::{LeafId, RecordError, Template, MAX_VALUE};
use crate::script::{asset_bytes, ExplicitOutput};
use crate::spend::{explicit_txout, margins, SpendError, UnrollTx, FINAL};
use crate::time::RelativeTime;

/// The board record format this crate writes and reads.
pub const BOARD_RECORD_VERSION: u8 = 1;

/// What the owner of a board keeps. See the [module documentation](self).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoardRecord {
	pub template: Template,
	/// The owner's key `A`.
	pub owner: XOnlyPublicKey,
	/// The owner's contribution to the leaf's salt.
	pub owner_nonce: [u8; 32],
	/// The operator's contribution to the leaf's salt.
	pub operator_nonce: [u8; 32],
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
	/// The index of the leaf in the board transaction.
	pub vout: u32,
}

impl BoardRecord {
	/// The leaf's salt, rebuilt from the two nonces.
	pub fn salt(&self) -> [u8; 32] {
		leaf_salt(&self.owner_nonce, &self.operator_nonce)
	}

	/// The leaf's policy.
	pub fn leaf(&self) -> LeafPolicy {
		LeafPolicy {
			owner: self.owner, operator: self.operator, salt: self.salt(), chain: self.chain, exit_delay: self.exit_delay,
		}
	}

	/// The leaf output the board pays.
	pub fn output(&self) -> ExplicitOutput {
		ExplicitOutput::new(self.asset, self.value, self.leaf().script_pubkey())
	}

	/// The board's leaf id.
	pub fn leaf_id(&self) -> LeafId {
		let program = self.leaf().program();
		LeafId::compute(&program, &[], &program)
	}

	/// The value bounds: 1 to [`MAX_VALUE`].
	pub fn check(&self) -> Result<(), RecordError> {
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
	/// explicit), pay the leaf at output 0; what is left of each asset goes
	/// to `change`, less `fee` of `fee_asset`, which goes to the fee output.
	/// The fee defaults to the board's own asset in a wallet, never to a
	/// privileged one. The inputs' witnesses are the owner's wallet's to add.
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

	/// Checks the record against the board transaction: it pays exactly one
	/// output equal to the leaf the record rebuilds (asset, value and script).
	/// Whether the board is final (its block certified and its anchor
	/// buried) is for the caller to establish.
	pub fn validate(&self, board: &Transaction) -> Result<ValidBoard, RecordError> {
		self.check()?;
		let out = self.output();
		let found: Vec<u32> = board.output.iter().enumerate()
			.filter(|(_, o)| ExplicitOutput::from_txout(o).as_ref() == Some(&out))
			.map(|(i, _)| i as u32)
			.collect();
		match found[..] {
			[] => Err(RecordError::BoardOutputMissing),
			[vout] => Ok(ValidBoard { leaf_id: self.leaf_id(), vout }),
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
