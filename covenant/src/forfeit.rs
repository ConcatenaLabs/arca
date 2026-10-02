//! The forfeit output, bound to the leaf it replaces and to its round.
//!
//! An old leaf is spent through its collaborative path into a forfeit output:
//!
//! ```text
//! claim:   <leaf_id> OP_DROP
//!          OP_INSPECTINPUTASSET OP_1 OP_EQUALVERIFY <M> OP_EQUALVERIFY
//!          OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <h> OP_EQUALVERIFY
//!          <S> OP_CHECKSIG
//! refund:  <delay> OP_CHECKSEQUENCEVERIFY OP_DROP <A> OP_CHECKSIG
//! ```
//!
//! The claim's witness is, bottom to top, `<sig_S> <preimage> <k>`, where `k`
//! is the index of an input that holds the asset `M`, explicitly.
//!
//! The operator can take the old coin only by publishing the preimage that
//! unlocks the owner's new entry (or, for an offboard, the owner's on-chain
//! output). If it withholds the preimage, the owner recovers the old coin
//! after the delay. The refund delay must end before the new batch's exit
//! deadline; that ordering is a parameter rule the scripts do not enforce.
//!
//! Two more things bind the claim:
//!
//! - **The leaf given up.** `leaf_id` is the old leaf's id, which nothing
//!   else shares, so every forfeit output is unique to its leaf. Without it,
//!   two leaves given up in one participation (one `h`) of equal value had
//!   forfeit pairs over the same output, and one transaction that spent both
//!   leaves into a single forfeit output satisfied both: the operator kept the
//!   second leaf without revealing anything.
//! - **The round.** `M` is the connector asset: the asset that spending one
//!   named output of the round transaction, `(round_txid, c)`, would issue,
//!   with a zero contract hash ([`connector_asset`]). An asset's id follows
//!   from the issuing outpoint and the contract hash alone, so the owner
//!   computes `M` from the confirmed round before any issuance exists. The
//!   operator issues one atom of `M` only if it needs to claim a forfeit, by
//!   spending that output ([`connector_issuance`]), and uses the atom for
//!   every later claim. If the round is not in the chain, `(round_txid, c)`
//!   does not exist, `M` can never be issued and no forfeit of that round can
//!   be claimed: after a rollback that replaces the round, every owner takes
//!   the old coin back through the refund.
//!
//! [`Forfeit`] builds the transactions. The forfeit itself moves the old leaf
//! into the forfeit output by the leaf's collaborative path; owner and
//! operator sign it in advance ([`Forfeit::message`]), committing to the
//! forfeit output and leaving a margin of the leaf's value uncommitted for the
//! fee, so it can be broadcast whenever the old leaf reaches the chain,
//! whatever outpoint the unroll gave it. The operator's claim publishes the
//! preimage ([`Forfeit::claim`]); the owner's refund waits the delay
//! ([`Forfeit::refund`]). Each is signed once built, since an ordinary
//! signature commits to the transaction.

use elements::confidential::Value;
use elements::hashes::Hash;
use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::{XOnlyPublicKey, ZERO_TWEAK};
use elements::{AssetId, AssetIssuance, ContractHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid};

use crate::entry::hash_gate;
use crate::leaf::{exit_script, LeafPolicy};
use crate::message::CsfsMessage;
use crate::record::LeafId;
use crate::script::{asset_bytes, scriptnum, ExplicitOutput};
use crate::spend::{
	check_margin, collab_tx, margins, pay_fee, FeeSource, KeySpend, Pair, Rebindable, SpendError, UnrollTx, FINAL,
};
use crate::taptree::TapOutput;
use crate::time::RelativeTime;

/// The connector asset of a round: what spending its output `vout` would
/// issue with a zero contract hash.
pub fn connector_asset(round_txid: Txid, vout: u32) -> AssetId {
	AssetId::new_issuance(OutPoint::new(round_txid, vout), ContractHash::from_byte_array([0; 32]))
}

/// The operator's issuance of a round's connector asset: it spends the
/// round's connector output `connector`, which holds `coin`, issues one
/// explicit atom of the asset with no reissuance token, pays it to `to` at
/// output 0, then pays `outputs`; what is left of the connector pays the fee
/// as `fee` says. The connector's own witness is the operator's to add.
pub fn connector_issuance(
	connector: OutPoint,
	coin: &TxOut,
	to: Script,
	outputs: &[ExplicitOutput],
	fee: &FeeSource,
) -> Result<UnrollTx, SpendError> {
	let (asset, value) = match (coin.asset.explicit(), coin.value.explicit()) {
		(Some(a), Some(v)) => (a, v),
		_ => return Err(SpendError::NotExplicit),
	};
	let m = connector_asset(connector.txid, connector.vout);
	let mut all = vec![ExplicitOutput::new(m, 1, to)];
	all.extend_from_slice(outputs);
	let left = margins(&[(asset, value), (m, 1)], &all)?;
	let mut input = TxIn { previous_output: connector, sequence: FINAL, ..Default::default() };
	input.asset_issuance = AssetIssuance {
		asset_blinding_nonce: ZERO_TWEAK,
		asset_entropy: [0; 32],
		amount: Value::Explicit(1),
		inflation_keys: Value::Null,
		denomination: 0,
	};
	let mut tx = Transaction { version: 2, lock_time: LockTime::ZERO, input: vec![input], output: all.iter().map(|o| o.txout()).collect() };
	let mut prevouts = vec![coin.clone()];
	pay_fee(&mut tx, &mut prevouts, &left, fee, FINAL)?;
	Ok(UnrollTx { tx, prevouts })
}

/// A forfeit output's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ForfeitPolicy {
	/// `h`: the unlock hash of the owner's new entry (or offboard output).
	pub unlock_hash: [u8; 32],
	/// The owner `A` of the old leaf.
	pub owner: XOnlyPublicKey,
	/// The operator `S`.
	pub operator: XOnlyPublicKey,
	pub refund_delay: RelativeTime,
	/// The id of the leaf given up.
	pub leaf_id: LeafId,
	/// The connector asset `M` of the round the leaf is given up for.
	pub connector: AssetId,
}

impl ForfeitPolicy {
	pub fn claim_script(&self) -> Script {
		let b = Builder::new().push_slice(&self.leaf_id.0).push_opcode(OP_DROP)
			.push_opcode(OP_INSPECTINPUTASSET).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&asset_bytes(self.connector)).push_opcode(OP_EQUALVERIFY);
		hash_gate(b, &self.unlock_hash)
			.push_slice(&self.operator.serialize()).push_opcode(OP_CHECKSIG).into_script()
	}

	pub fn refund_script(&self) -> Script {
		exit_script(&self.owner, self.refund_delay)
	}

	/// `[claim, refund]`, both at depth 1.
	pub fn taproot(&self) -> TapOutput {
		TapOutput::new(vec![(1, self.claim_script()), (1, self.refund_script())])
	}

	pub fn script_pubkey(&self) -> Script {
		self.taproot().script_pubkey()
	}

	/// The items below the claim script: the operator's signature, the
	/// preimage, which the claim publishes, and the index of the input that
	/// holds the connector asset.
	pub fn claim_items(operator_sig: &Signature, preimage: &[u8; 32], k: u32) -> Vec<Vec<u8>> {
		vec![operator_sig.as_ref().to_vec(), preimage.to_vec(), scriptnum(k as i64)]
	}

	/// The full claim witness.
	pub fn claim_witness(&self, operator_sig: &Signature, preimage: &[u8; 32], k: u32) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.claim_script(), Self::claim_items(operator_sig, preimage, k))
	}

	/// The full refund witness: the owner's signature, on a version 2
	/// transaction whose input sequence is the refund delay.
	pub fn refund_witness(&self, owner_sig: &Signature) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.refund_script(), vec![owner_sig.as_ref().to_vec()])
	}
}

/// A leaf forfeited against an unlock hash: the old leaf, the forfeit output
/// it moves into, and the margin the signers leave for the fee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forfeit {
	/// The old leaf. Its owner and operator are the forfeit output's.
	pub leaf: LeafPolicy,
	/// The old leaf's asset and value.
	pub asset: AssetId,
	pub value: u64,
	pub policy: ForfeitPolicy,
	/// What the signers leave uncommitted: the forfeit output holds
	/// `value - margin`, and the margin pays the fee.
	pub margin: u64,
}

impl Forfeit {
	/// The input of [`Forfeit::claim`] that holds the connector asset.
	pub const CONNECTOR_INPUT: u32 = 1;

	/// The forfeit of `leaf`, whose id is `leaf_id` and which holds `value` of
	/// `asset`, against `unlock_hash`, for the round whose connector asset is
	/// `connector`, refundable to the owner after `refund_delay`.
	pub fn new(
		leaf: LeafPolicy,
		(asset, value): (AssetId, u64),
		leaf_id: LeafId,
		unlock_hash: [u8; 32],
		connector: AssetId,
		refund_delay: RelativeTime,
		margin: u64,
	) -> Result<Forfeit, SpendError> {
		check_margin(margin, value)?;
		let policy = ForfeitPolicy { unlock_hash, owner: leaf.owner, operator: leaf.operator, refund_delay, leaf_id, connector };
		Ok(Forfeit { leaf, asset, value, policy, margin })
	}

	/// The forfeit output: the leaf's value less the margin.
	pub fn output(&self) -> ExplicitOutput {
		ExplicitOutput::new(self.asset, self.value - self.margin, self.policy.script_pubkey())
	}

	/// What owner and operator sign: the old leaf's rebindable message over
	/// the forfeit output alone.
	pub fn message(&self) -> CsfsMessage {
		self.leaf.message(self.asset, self.value, &[self.output()]).expect("one output")
	}

	/// The server's check of a forfeit handed to it: both signatures sign
	/// [`Forfeit::message`].
	pub fn verify(&self, pair: &Pair) -> Result<(), SpendError> {
		self.leaf.verify(self.asset, self.value, &[self.output()], pair)
	}

	/// The forfeit transaction, spending the old leaf at `leaf_coin`.
	pub fn tx(&self, leaf_coin: OutPoint, pair: &Pair, fee: &FeeSource) -> Result<UnrollTx, SpendError> {
		collab_tx(&self.leaf, leaf_coin, self.asset, self.value, &[self.output()], pair, fee)
	}

	/// The operator's claim of the forfeit output at `forfeit_coin` into
	/// `outputs`, with the connector asset's coin `connector` as input 1
	/// ([`Forfeit::CONNECTOR_INPUT`]); that coin's whole value goes back to
	/// `connector_to`, for the next claim. Finish it with
	/// [`ForfeitPolicy::claim_items`]: the claim publishes the preimage. The
	/// connector coin's own witness is the operator's to add.
	pub fn claim(
		&self,
		forfeit_coin: OutPoint,
		connector: (OutPoint, TxOut),
		outputs: &[ExplicitOutput],
		connector_to: Script,
		fee: &FeeSource,
	) -> Result<KeySpend, SpendError> {
		let (m, held) = match (connector.1.asset.explicit(), connector.1.value.explicit()) {
			(Some(a), Some(v)) => (a, v),
			_ => return Err(SpendError::NotExplicit),
		};
		let mut all = outputs.to_vec();
		all.push(ExplicitOutput::new(m, held, connector_to));
		KeySpend::build(
			self.policy.taproot(), self.policy.claim_script(),
			vec![(forfeit_coin, self.output().txout(), FINAL), (connector.0, connector.1, FINAL)], &all, fee,
		)
	}

	/// The owner's refund of the forfeit output at `forfeit_coin` into
	/// `outputs`, the refund delay after the forfeit confirmed. Finish it
	/// with `[signature]`.
	pub fn refund(&self, forfeit_coin: OutPoint, outputs: &[ExplicitOutput], fee: &FeeSource) -> Result<KeySpend, SpendError> {
		KeySpend::build(
			self.policy.taproot(), self.policy.refund_script(),
			vec![(forfeit_coin, self.output().txout(), Sequence(self.policy.refund_delay.to_sequence()))], outputs, fee,
		)
	}
}
