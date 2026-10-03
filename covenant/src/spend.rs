//! Building the transactions that spend Arca's outputs outside the unroll.
//!
//! Every spend here has one shape. Input 0 spends an Arca output; outputs
//! `0..m` are the ones its path pins or its signers committed to; the rest of
//! the transaction is left open, so that whoever broadcasts can pay the fee:
//!
//! - a rebindable spend ([`Rebindable`], [`collab_tx`]): a leaf or a
//!   checkpoint spent by its collaborative path. Owner and operator sign the
//!   coin's asset and amount and the outputs, never the outpoint, so the pair
//!   ([`Pair`]) can be made before the coin is on-chain and survives any
//!   unroll;
//! - a spend whose path ends in `<key> OP_CHECKSIG` ([`KeySpend`]): an exit,
//!   a forfeit's claim or refund, an offboard's reclaim. Its signature
//!   commits to the whole transaction, so it is made once the transaction is
//!   built ([`KeySpend::sighash`]);
//! - a spend that needs no signature: an entry's or an offboard's unlock.
//!
//! The value of the spent coins that the pinned or committed outputs do not
//! take is the margin, counted per asset. With [`FeeSource::Reserve`] the
//! margin is the fee, which needs it to be in one asset. With
//! [`FeeSource::Coin`] the broadcaster attaches a coin in any asset a
//! producer accepts, which pays the fee in its own asset, and every margin
//! goes to the broadcaster's change: a transaction with fee outputs in two
//! assets is refused. Value no signature commits to belongs to whoever
//! broadcasts, which is why the signers commit to all of a coin but the
//! margin they intend as the fee.
//!
//! Transactions are version 2. Change and margins follow the committed
//! outputs in the order their assets first appear among the inputs, then the
//! fee coin's change, then the fee output, so a transaction is the same
//! whoever builds it.

use elements::confidential::{Asset, Nonce, Value};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, TxOutWitness};

use crate::checkpoint::CheckpointPolicy;
use crate::leaf::{two_party_items, two_party_message, LeafPolicy, MAX_OUTPUTS};
use crate::message::CsfsMessage;
use crate::script::ExplicitOutput;
use crate::sign::{script_spend_sighash, verify_digest};
use crate::taptree::TapOutput;
pub use crate::unroll::{FeeSource, UnrollError, UnrollTx};
use crate::Error;

/// The sequence of a final input: no lock of any kind.
pub const FINAL: Sequence = Sequence(0xffff_ffff);
/// The sequence of a fee coin attached to a spend under a relative lock: it
/// enables the lock time and puts no relative lock on the coin itself.
pub const FEE_COIN_SEQUENCE: Sequence = Sequence(0xffff_fffe);

/// Why a spend cannot be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpendError {
	#[error(transparent)]
	Fee(#[from] UnrollError),
	#[error("the outputs take {outputs} of asset {asset}, more than the {available} the inputs hold")]
	Overspend { asset: AssetId, outputs: u64, available: u64 },
	#[error("an amount does not fit in 64 bits")]
	Overflow,
	#[error("a value of {0} is out of range")]
	Value(u64),
	#[error("a spent coin's asset or value is not explicit")]
	NotExplicit,
	#[error("the {0}'s signature does not verify")]
	Signature(&'static str),
	#[error("a margin of {margin} leaves nothing of a coin of {value}")]
	Margin { margin: u64, value: u64 },
	#[error(transparent)]
	Policy(#[from] Error),
	#[error("the round is not the transaction the new leaf was validated against")]
	NotTheRound,
	#[error("output {0} of the round is not the operator's connector output")]
	Connector(u32),
	#[error("the leaf given up and the round are under different operators")]
	OtherOperator,
	#[error(transparent)]
	Offboard(#[from] crate::offboard::OffboardError),
	#[error("the board is not the coin the forfeit gives up")]
	OtherBoard,
	#[error("the coin has no lowest node of its own to release")]
	NoLowestNode,
	#[error("{0} holds nothing for a fee: attach a fee coin")]
	NeedsFeeCoin(&'static str),
	#[error("the schedule has no clock {step}; it has {steps}")]
	ClockStep { step: usize, steps: usize },
	#[error("clock {0} is the last: it has no roll")]
	LastClock(usize),
	#[error("a sweep takes at least one output")]
	NothingToSweep,
	#[error("swept output {0} carries no sweep behind this schedule's token, R and operator")]
	OtherBatch(usize),
	#[error("swept output {0} is not an output of the taproot given for it, or that taproot has no such sweep leaf")]
	NotSweepable(usize),
	#[error("a sweep takes burn-only outputs or others, never both")]
	MixedBurn,
	#[error("a burn-only sweep pays nothing but the burns, which it builds itself")]
	BurnOutputs,
	#[error("{given} signatures for a sweep of {needed} inputs")]
	SweepSignatures { given: usize, needed: usize },
}

pub(crate) fn explicit_txout(asset: AssetId, value: u64, script_pubkey: Script) -> TxOut {
	TxOut {
		asset: Asset::Explicit(asset),
		value: Value::Explicit(value),
		nonce: Nonce::Null,
		script_pubkey,
		witness: TxOutWitness::default(),
	}
}

/// What the inputs hold beyond the outputs, per asset, in the order each
/// asset first appears among the inputs; assets with nothing left are
/// omitted. Refuses outputs that take more of an asset than the inputs hold.
pub fn margins(inputs: &[(AssetId, u64)], outputs: &[ExplicitOutput]) -> Result<Vec<(AssetId, u64)>, SpendError> {
	let mut held: Vec<(AssetId, u64)> = vec![];
	for (a, v) in inputs {
		match held.iter_mut().find(|(x, _)| x == a) {
			Some((_, t)) => *t = t.checked_add(*v).ok_or(SpendError::Overflow)?,
			None => held.push((*a, *v)),
		}
	}
	let mut taken: Vec<(AssetId, u64)> = vec![];
	for o in outputs {
		match taken.iter_mut().find(|(x, _)| *x == o.asset) {
			Some((_, t)) => *t = t.checked_add(o.value).ok_or(SpendError::Overflow)?,
			None => taken.push((o.asset, o.value)),
		}
	}
	for (a, t) in &taken {
		let available = held.iter().find(|(x, _)| x == a).map(|(_, v)| *v).unwrap_or(0);
		if *t > available {
			return Err(SpendError::Overspend { asset: *a, outputs: *t, available });
		}
	}
	Ok(held.into_iter().filter_map(|(a, v)| {
		let left = v - taken.iter().find(|(x, _)| *x == a).map(|(_, t)| *t).unwrap_or(0);
		(left > 0).then_some((a, left))
	}).collect())
}

/// Adds the fee to `tx`, whose inputs hold `margins` beyond its outputs. A
/// fee coin is attached with `coin_sequence`.
pub(crate) fn pay_fee(
	tx: &mut Transaction,
	prevouts: &mut Vec<TxOut>,
	margins: &[(AssetId, u64)],
	fee: &FeeSource,
	coin_sequence: Sequence,
) -> Result<(), UnrollError> {
	match fee {
		FeeSource::Reserve => match margins {
			[] => {},
			[(asset, value)] => tx.output.push(TxOut::new_fee(*value, *asset)),
			_ => return Err(UnrollError::SeveralMarginAssets(margins.len())),
		},
		FeeSource::Coin { outpoint, coin, fee, change } => {
			let (coin_asset, value) = match (coin.asset.explicit(), coin.value.explicit()) {
				(Some(a), Some(v)) => (a, v),
				_ => return Err(UnrollError::FeeCoinNotExplicit),
			};
			if value < *fee {
				return Err(UnrollError::FeeCoinTooSmall { value, fee: *fee });
			}
			tx.input.push(TxIn { previous_output: *outpoint, sequence: coin_sequence, ..Default::default() });
			prevouts.push(coin.clone());
			for (asset, margin) in margins {
				tx.output.push(explicit_txout(*asset, *margin, change.clone()));
			}
			if value > *fee {
				tx.output.push(explicit_txout(coin_asset, value - fee, change.clone()));
			}
			tx.output.push(TxOut::new_fee(*fee, coin_asset));
		},
	}
	Ok(())
}

/// A transaction with `inputs` (each with the output it spends) and
/// `outputs`, the margins paying the fee as `fee` says.
pub(crate) fn assemble(
	lock_time: LockTime,
	inputs: Vec<(OutPoint, TxOut, Sequence)>,
	outputs: &[ExplicitOutput],
	fee: &FeeSource,
	coin_sequence: Sequence,
) -> Result<UnrollTx, SpendError> {
	let mut held = Vec::with_capacity(inputs.len());
	for (_, o, _) in &inputs {
		match (o.asset.explicit(), o.value.explicit()) {
			(Some(a), Some(v)) => held.push((a, v)),
			_ => return Err(SpendError::NotExplicit),
		}
	}
	let left = margins(&held, outputs)?;
	let mut tx = Transaction {
		version: 2,
		lock_time,
		input: inputs.iter().map(|(op, _, seq)| TxIn { previous_output: *op, sequence: *seq, ..Default::default() }).collect(),
		output: outputs.iter().map(|o| o.txout()).collect(),
	};
	let mut prevouts: Vec<TxOut> = inputs.into_iter().map(|(_, o, _)| o).collect();
	pay_fee(&mut tx, &mut prevouts, &left, fee, coin_sequence)?;
	Ok(UnrollTx { tx, prevouts })
}

/// The owner's and the operator's signatures over one rebindable message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pair {
	pub operator: Signature,
	pub owner: Signature,
}

/// An output with a rebindable collaborative path: a leaf or a checkpoint.
pub trait Rebindable {
	/// The owner's key `A`.
	fn owner(&self) -> XOnlyPublicKey;
	/// The operator's key `S`.
	fn operator(&self) -> XOnlyPublicKey;
	/// The output's taproot.
	fn tap(&self) -> TapOutput;
	/// The collaborative script leaf.
	fn collab(&self) -> Script;
	/// The message both sign to spend a coin of this output, holding
	/// `value_in` of `asset_in`, into `outputs` at indices `0..m`.
	fn message(&self, asset_in: AssetId, value_in: u64, outputs: &[ExplicitOutput]) -> Result<CsfsMessage, Error>;

	/// Whether `pair` signs that message, each signature by its own key.
	fn verify(&self, asset_in: AssetId, value_in: u64, outputs: &[ExplicitOutput], pair: &Pair) -> Result<(), SpendError> {
		let msg = self.message(asset_in, value_in, outputs)?;
		if !verify_digest(&pair.operator, &msg.digest, &self.operator()) {
			return Err(SpendError::Signature("operator"));
		}
		if !verify_digest(&pair.owner, &msg.digest, &self.owner()) {
			return Err(SpendError::Signature("owner"));
		}
		Ok(())
	}

	/// The full collaborative witness for `m` committed outputs.
	fn witness(&self, pair: &Pair, m: u8) -> Vec<Vec<u8>> {
		self.tap().witness(&self.collab(), two_party_items(&pair.operator, &pair.owner, m))
	}
}

impl Rebindable for LeafPolicy {
	fn owner(&self) -> XOnlyPublicKey {
		self.owner
	}

	fn operator(&self) -> XOnlyPublicKey {
		self.operator
	}

	fn tap(&self) -> TapOutput {
		self.taproot()
	}

	fn collab(&self) -> Script {
		self.collab_script()
	}

	fn message(&self, asset_in: AssetId, value_in: u64, outputs: &[ExplicitOutput]) -> Result<CsfsMessage, Error> {
		two_party_message(&self.leaf_constant(), asset_in, value_in, outputs)
	}
}

impl Rebindable for CheckpointPolicy {
	fn owner(&self) -> XOnlyPublicKey {
		self.owner
	}

	fn operator(&self) -> XOnlyPublicKey {
		self.operator
	}

	fn tap(&self) -> TapOutput {
		self.taproot()
	}

	fn collab(&self) -> Script {
		self.collab_script()
	}

	fn message(&self, asset_in: AssetId, value_in: u64, outputs: &[ExplicitOutput]) -> Result<CsfsMessage, Error> {
		two_party_message(&self.leaf_constant(), asset_in, value_in, outputs)
	}
}

/// The spend of `coin`, an output of `policy` holding `value` of `asset`, by
/// its collaborative path into `outputs` at indices `0..m`, signed by `pair`.
/// The coin's margin pays the fee as `fee` says. The pair is not checked
/// here: [`Rebindable::verify`] does that.
pub fn collab_tx<P: Rebindable>(
	policy: &P,
	coin: OutPoint,
	asset: AssetId,
	value: u64,
	outputs: &[ExplicitOutput],
	pair: &Pair,
	fee: &FeeSource,
) -> Result<UnrollTx, SpendError> {
	if outputs.is_empty() || outputs.len() > MAX_OUTPUTS as usize {
		return Err(Error::OutputCount(outputs.len()).into());
	}
	let spent = explicit_txout(asset, value, policy.tap().script_pubkey());
	let mut u = assemble(LockTime::ZERO, vec![(coin, spent, FINAL)], outputs, fee, FINAL)?;
	u.tx.input[0].witness.script_witness = policy.witness(pair, outputs.len() as u8);
	Ok(u)
}

/// A transaction that spends an Arca output at input 0 by a path that ends in
/// `<key> OP_CHECKSIG`, built and waiting for its signature: sign
/// [`KeySpend::sighash`], then [`KeySpend::finish`] with the items the path
/// takes below its script.
#[derive(Debug, Clone)]
pub struct KeySpend {
	pub tx: Transaction,
	/// The outputs the inputs spend, in input order.
	pub prevouts: Vec<TxOut>,
	/// The script leaf input 0 spends by.
	pub script: Script,
	tap: TapOutput,
}

impl KeySpend {
	/// The spend of `inputs[0]`, an output of `tap`, by `script`, with any
	/// further `inputs` the path needs, into `outputs`. Input 0's sequence is
	/// a relative lock or final; a fee coin follows it.
	pub(crate) fn build(
		tap: TapOutput,
		script: Script,
		inputs: Vec<(OutPoint, TxOut, Sequence)>,
		outputs: &[ExplicitOutput],
		fee: &FeeSource,
	) -> Result<KeySpend, SpendError> {
		let coin_sequence = if inputs[0].2 == FINAL { FINAL } else { FEE_COIN_SEQUENCE };
		let u = assemble(LockTime::ZERO, inputs, outputs, fee, coin_sequence)?;
		Ok(KeySpend { tx: u.tx, prevouts: u.prevouts, script, tap })
	}

	/// A spend assembled elsewhere in the crate, input 0 by `script` of `tap`.
	pub(crate) fn from_parts(tx: Transaction, prevouts: Vec<TxOut>, tap: TapOutput, script: Script) -> KeySpend {
		KeySpend { tx, prevouts, script, tap }
	}

	/// The Elements taproot signature hash of input 0 (`SIGHASH_DEFAULT`):
	/// what the key signs. An attached fee coin's own witness does not change
	/// it.
	pub fn sighash(&self, genesis_hash: BlockHash) -> Result<[u8; 32], Error> {
		script_spend_sighash(&self.tx, 0, &self.prevouts, &self.script, genesis_hash)
	}

	/// Puts `below` (bottom of the stack first), the script and its control
	/// block on input 0. A fee coin's witness is the broadcaster's to add.
	pub fn finish(mut self, below: Vec<Vec<u8>>) -> UnrollTx {
		self.tx.input[0].witness.script_witness = self.tap.witness(&self.script, below);
		UnrollTx { tx: self.tx, prevouts: self.prevouts }
	}
}

impl LeafPolicy {
	/// The exit claim of `coin`, this leaf on-chain holding `value` of
	/// `asset`, into `outputs`: input 0's sequence is the exit delay, so it
	/// confirms only that long after the leaf did. The owner signs
	/// [`KeySpend::sighash`] and finishes it with its signature.
	pub fn exit_tx(&self, coin: OutPoint, asset: AssetId, value: u64, outputs: &[ExplicitOutput], fee: &FeeSource)
		-> Result<KeySpend, SpendError>
	{
		let spent = explicit_txout(asset, value, self.script_pubkey());
		KeySpend::build(self.taproot(), self.exit_script(), vec![(coin, spent, Sequence(self.exit_delay.to_sequence()))], outputs, fee)
	}
}

/// What a pre-signed spend leaves for its fee: `multiple` times the relay
/// floor for a transaction of `vsize` vbytes, in the spent asset's atoms. The
/// specification sets `multiple` to 4.
pub fn margin_for(vsize: usize, floor_per_kvb: u64, multiple: u64) -> u64 {
	(vsize as u64).saturating_mul(floor_per_kvb).div_ceil(1000).saturating_mul(multiple)
}

/// Checks that `margin` leaves something of a coin of `value`.
pub(crate) fn check_margin(margin: u64, value: u64) -> Result<(), SpendError> {
	if margin >= value {
		return Err(SpendError::Margin { margin, value });
	}
	Ok(())
}
