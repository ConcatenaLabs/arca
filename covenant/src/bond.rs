//! The operator's equivocation bond.
//!
//! The operator key `S` co-signs every out-of-round spend, and each message it
//! signs under a coin's salt names that coin alone, which is spent once. So
//! two different messages `S` signed under one salt are proof that it signed
//! twice. The bond is a coin anyone holding that proof can burn.
//!
//! Every message `S` signs under a salt has one of two forms:
//!
//! - the rebindable message of a collaborative path ([`crate::message`]),
//!   `SHA256(K ‖ r)`, `K = SHA256(C ‖ salt)`, `C = SHA256("ArcaRbd1" ‖ genesis)`
//!   (a `landing-1` leaf's `r` starts with its landing program; a `vtxo-2`
//!   coin's `r` is the 70 bytes `k ‖ n ‖ I ‖ m ‖ O` of [`crate::collab`]);
//! - an `order-2` fill ([`crate::order`]), `SHA256(F ‖ salt ‖ r)`,
//!   `F = SHA256(SHA256("Arca/order-fill") ‖ genesis)`.
//!
//! The bond is an explicit taproot output with the NUMS internal key and two
//! leaves:
//!
//! ```text
//! SLASH:  [burn body]
//!         OP_SIZE <32> OP_EQUALVERIFY
//!         <C> OP_OVER OP_CAT OP_SHA256 <F> OP_ROT OP_CAT          # K, F ‖ salt
//!         OP_2DUP OP_TOALTSTACK OP_TOALTSTACK
//!         OP_ROT OP_IF OP_NIP OP_ELSE OP_DROP OP_ENDIF           # the first's prefix
//!         OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SWAP OP_CAT OP_SHA256  # d_a
//!         OP_DUP OP_TOALTSTACK <S> OP_DUP OP_TOALTSTACK OP_CHECKSIGFROMSTACKVERIFY
//!         OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
//!         OP_4 OP_ROLL OP_IF OP_NIP OP_ELSE OP_DROP OP_ENDIF     # the second's prefix
//!         OP_3 OP_ROLL OP_CAT OP_3 OP_ROLL OP_CAT OP_3 OP_ROLL OP_CAT OP_SHA256   # d_b
//!         OP_TUCK OP_EQUAL OP_NOT OP_VERIFY OP_SWAP OP_CHECKSIGFROMSTACK
//! NOTICE: [the output at this input's index is N's, of the whole amount] <W> OP_CHECKSIG
//! ```
//!
//! A notice moves the bond whole into `N`, an output with the same SLASH and
//! a WITHDRAW, `<D> OP_CHECKSEQUENCEVERIFY OP_DROP <W> OP_CHECKSIG`: the
//! withdrawal key `W` can only begin a withdrawal, in public, and take the
//! bond a delay `D` after that notice confirmed, while the slash stands
//! throughout.
//!
//! SLASH's witness, bottom to top, is
//! `<sig_b> <b3> <b2> <b1> <form_b> <sig_a> <a3> <a2> <a1> <form_a> <salt>`:
//! the salt, exactly 32 bytes; for each signature its form (empty for the
//! rebindable form, `0x01` for a fill) and the rest of its message after the
//! salt's prefix, in three chunks of at most 80 bytes, the most a tapscript
//! stack item may hold under relay policy. The script computes each digest
//! itself from the salt, so a signature `S` made over anything else (a
//! taproot signature hash, a record head) can never pass: those start with a
//! tag's hash, and a salt whose `K` equals one is a SHA256 preimage. It
//! requires the two digests to differ: two signatures over one digest are not
//! a double-sign.
//!
//! The burn body requires the output at the input's own index to be a bare
//! `OP_RETURN` carrying exactly the input's explicit amount of its asset, as
//! a burn-only sweep does ([`crate::sweep`]): a slash pays no one, so no one
//! profits from one. Its fee comes from a coin its broadcaster attaches.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, OutPoint, Script, Sequence, Transaction, TxOut};

use crate::issuer::burn;
use crate::message::Chain;
use crate::script::{sha256, BuilderExt, ExplicitOutput};
use crate::sign::verify_digest;
use crate::spend::{assemble, explicit_txout, KeySpend, SpendError, FINAL};
use crate::taptree::TapOutput;
use crate::time::RelativeTime;
use crate::unroll::{FeeSource, UnrollTx};

/// The most bytes a tapscript stack item may hold under relay policy.
pub const MAX_ITEM: usize = 80;
/// The chunks a remainder travels in.
pub const CHUNKS: usize = 3;
/// The longest remainder a slash takes.
pub const MAX_REST: usize = MAX_ITEM * CHUNKS;

/// The form of a message `S` signs under a salt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Form {
	/// A collaborative path's rebindable message, `SHA256(K ‖ rest)`.
	Rebind,
	/// An `order-2` fill, `SHA256(F ‖ salt ‖ rest)`.
	Fill,
}

impl Form {
	/// The witness item that selects it.
	pub fn item(self) -> Vec<u8> {
		match self {
			Form::Rebind => vec![],
			Form::Fill => vec![1],
		}
	}

	pub fn name(self) -> &'static str {
		match self {
			Form::Rebind => "rebind",
			Form::Fill => "fill",
		}
	}

	pub fn from_name(s: &str) -> Option<Form> {
		match s {
			"rebind" => Some(Form::Rebind),
			"fill" => Some(Form::Fill),
			_ => None,
		}
	}
}

/// One message `S` signed under a salt: its form, the rest of it after the
/// salt's prefix, and `S`'s signature over its digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signed {
	pub form: Form,
	pub rest: Vec<u8>,
	pub signature: Signature,
}

/// Two messages `S` signed under one salt: what a slash takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
	pub salt: [u8; 32],
	pub a: Signed,
	pub b: Signed,
}

/// Why evidence does not prove a double-sign, or a bond spend cannot be
/// built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BondError {
	#[error("the {0} message's rest is {1} bytes; a slash takes at most {max}", max = MAX_REST)]
	RestTooLong(&'static str, usize),
	#[error("S's signature over the {0} message does not verify")]
	Signature(&'static str),
	#[error("the two messages are one digest: two signatures over one message are not a double-sign")]
	SameDigest,
	#[error("the notice delay is a relative time of at least one unit")]
	Delay,
	#[error("the withdrawal key is the operator key S: the signer would sign the bond's paths")]
	WithdrawKeyIsOperator,
	#[error("a slash takes at least one bond coin")]
	NothingToSlash,
	#[error("coin {0} is not at the bond's script or its notice's")]
	NotABond(usize),
	#[error("a bond coin's asset or value is not explicit")]
	NotExplicit,
	#[error(transparent)]
	Spend(#[from] SpendError),
}

/// A bond: the chain it is on, the key it binds, the key that may withdraw
/// it and the delay a withdrawal waits after its notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BondPolicy {
	pub chain: Chain,
	/// `S`, the operator key it binds.
	pub operator: XOnlyPublicKey,
	/// `W`, the withdrawal key.
	pub withdraw: XOnlyPublicKey,
	/// `D`, the delay after the notice's confirmation.
	pub notice: RelativeTime,
}

/// Where a bond coin stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BondState {
	/// At the bond's own script: no notice given.
	Bonded,
	/// At the notice output: withdrawable a delay after it confirmed.
	Noticed,
}

/// The prefix of a message of `form` under `salt` on `chain`: `K` for the
/// rebindable form, `F ‖ salt` for a fill.
pub fn prefix(chain: &Chain, form: Form, salt: &[u8; 32]) -> Vec<u8> {
	match form {
		Form::Rebind => chain.leaf_constant(salt).to_vec(),
		Form::Fill => {
			let mut b = crate::order::fill_prefix(chain).to_vec();
			b.extend(salt);
			b
		},
	}
}

/// The digest of a message of `form` under `salt` whose rest is `rest`.
pub fn digest(chain: &Chain, form: Form, salt: &[u8; 32], rest: &[u8]) -> [u8; 32] {
	let mut b = prefix(chain, form, salt);
	b.extend(rest);
	sha256(&b)
}

/// The rest of a rebindable message's preimage ([`crate::CsfsMessage`]):
/// everything after `K`.
pub fn rebind_rest(preimage: &[u8]) -> Option<Vec<u8>> {
	(preimage.len() > 32).then(|| preimage[32..].to_vec())
}

/// The rest of a fill's preimage ([`crate::OrderPolicy::fill_preimage`]):
/// everything after `F ‖ salt`.
pub fn fill_rest(preimage: &[u8]) -> Option<Vec<u8>> {
	(preimage.len() > 64).then(|| preimage[64..].to_vec())
}

/// `rest` in [`CHUNKS`] chunks, first chunk first: the first [`MAX_ITEM`]
/// bytes, the next, and what is left.
pub fn chunks(rest: &[u8]) -> Result<[Vec<u8>; CHUNKS], usize> {
	if rest.len() > MAX_REST {
		return Err(rest.len());
	}
	let at = |i: usize| rest.len().min(i * MAX_ITEM);
	Ok([rest[..at(1)].to_vec(), rest[at(1)..at(2)].to_vec(), rest[at(2)..].to_vec()])
}

/// The output at this input's index carries exactly the input's explicit
/// amount of the input's explicit asset.
fn whole_at_current_output(b: Builder) -> Builder {
	b.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTVALUE]).push_int(1).push_opcode(OP_EQUALVERIFY)
		.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTVALUE]).push_int(1)
		.ops(&[OP_EQUALVERIFY, OP_EQUALVERIFY])
		.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTASSET]).push_int(1).push_opcode(OP_EQUALVERIFY)
		.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTASSET]).push_int(1)
		.ops(&[OP_EQUALVERIFY, OP_EQUALVERIFY])
}

impl BondPolicy {
	pub fn new(chain: Chain, operator: XOnlyPublicKey, withdraw: XOnlyPublicKey, notice: RelativeTime) -> Result<BondPolicy, BondError> {
		if withdraw == operator {
			return Err(BondError::WithdrawKeyIsOperator);
		}
		Ok(BondPolicy { chain, operator, withdraw, notice })
	}

	/// SLASH: see the [module documentation](self).
	pub fn slash_script(&self) -> Script {
		// Each constant is pushed once: K and F ‖ salt wait on the alt stack,
		// with the first digest and S, while the first signature is checked.
		let pick = [OP_IF, OP_NIP, OP_ELSE, OP_DROP, OP_ENDIF];
		whole_at_current_output(Builder::new())
			.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTSCRIPTPUBKEY]).push_int(-1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&sha256(&[OP_RETURN.into_u8()])).push_opcode(OP_EQUALVERIFY)
			.push_opcode(OP_SIZE).push_int(32).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.chain.tag()).ops(&[OP_OVER, OP_CAT, OP_SHA256])
			.push_slice(&crate::order::fill_prefix(&self.chain)).ops(&[OP_ROT, OP_CAT])
			.ops(&[OP_2DUP, OP_TOALTSTACK, OP_TOALTSTACK, OP_ROT]).ops(&pick)
			.ops(&[OP_SWAP, OP_CAT, OP_SWAP, OP_CAT, OP_SWAP, OP_CAT, OP_SHA256, OP_DUP, OP_TOALTSTACK])
			.push_slice(&self.operator.serialize()).ops(&[OP_DUP, OP_TOALTSTACK, OP_CHECKSIGFROMSTACKVERIFY])
			.ops(&[OP_FROMALTSTACK, OP_FROMALTSTACK, OP_FROMALTSTACK, OP_FROMALTSTACK]).push_int(4).push_opcode(OP_ROLL).ops(&pick)
			.push_int(3).ops(&[OP_ROLL, OP_CAT]).push_int(3).ops(&[OP_ROLL, OP_CAT]).push_int(3).ops(&[OP_ROLL, OP_CAT, OP_SHA256])
			.ops(&[OP_TUCK, OP_EQUAL, OP_NOT, OP_VERIFY, OP_SWAP, OP_CHECKSIGFROMSTACK])
			.into_script()
	}

	/// WITHDRAW, on the notice output.
	pub fn withdraw_script(&self) -> Script {
		Builder::new().push_int(self.notice.to_sequence() as i64).ops(&[OP_CSV, OP_DROP])
			.push_slice(&self.withdraw.serialize()).push_opcode(OP_CHECKSIG).into_script()
	}

	/// The notice output: SLASH and WITHDRAW.
	pub fn notice_taproot(&self) -> TapOutput {
		TapOutput::new(vec![(1, self.slash_script()), (1, self.withdraw_script())])
	}

	/// NOTICE, on the bond: the bond whole to the notice output.
	pub fn notice_script(&self) -> Script {
		whole_at_current_output(Builder::new())
			.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTSCRIPTPUBKEY]).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.notice_taproot().program()).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.withdraw.serialize()).push_opcode(OP_CHECKSIG)
			.into_script()
	}

	/// The bond's output: SLASH and NOTICE.
	pub fn taproot(&self) -> TapOutput {
		TapOutput::new(vec![(1, self.slash_script()), (1, self.notice_script())])
	}

	/// The bond's scriptPubKey: what the operator pays to post it.
	pub fn script_pubkey(&self) -> Script {
		self.taproot().script_pubkey()
	}

	/// The notice output's scriptPubKey.
	pub fn notice_script_pubkey(&self) -> Script {
		self.notice_taproot().script_pubkey()
	}

	/// Which of the bond's two outputs `spk` is, if either.
	pub fn state_of(&self, spk: &Script) -> Option<BondState> {
		if *spk == self.script_pubkey() {
			Some(BondState::Bonded)
		} else if *spk == self.notice_script_pubkey() {
			Some(BondState::Noticed)
		} else {
			None
		}
	}

	/// The digest of `signed` under `salt` on this bond's chain.
	pub fn digest_of(&self, salt: &[u8; 32], signed: &Signed) -> [u8; 32] {
		digest(&self.chain, signed.form, salt, &signed.rest)
	}

	/// Whether `signed` is `S`'s signature over its message under `salt`.
	pub fn verify(&self, salt: &[u8; 32], signed: &Signed) -> bool {
		verify_digest(&signed.signature, &self.digest_of(salt, signed), &self.operator)
	}

	/// Checks `e` as the slash will: each rest fits, each signature is `S`'s
	/// over its digest, and the digests differ.
	pub fn check(&self, e: &Evidence) -> Result<(), BondError> {
		for (name, s) in [("first", &e.a), ("second", &e.b)] {
			if s.rest.len() > MAX_REST {
				return Err(BondError::RestTooLong(name, s.rest.len()));
			}
			if !self.verify(&e.salt, s) {
				return Err(BondError::Signature(name));
			}
		}
		if self.digest_of(&e.salt, &e.a) == self.digest_of(&e.salt, &e.b) {
			return Err(BondError::SameDigest);
		}
		Ok(())
	}

	/// The items SLASH takes below its script, bottom of the stack first. It
	/// checks nothing but the chunks' sizes: a test can hand the script
	/// evidence the slash refuses.
	pub fn slash_items(e: &Evidence) -> Result<Vec<Vec<u8>>, BondError> {
		let a = chunks(&e.a.rest).map_err(|n| BondError::RestTooLong("first", n))?;
		let b = chunks(&e.b.rest).map_err(|n| BondError::RestTooLong("second", n))?;
		let [a1, a2, a3] = a;
		let [b1, b2, b3] = b;
		Ok(vec![
			e.b.signature.as_ref().to_vec(), b3, b2, b1, e.b.form.item(),
			e.a.signature.as_ref().to_vec(), a3, a2, a1, e.a.form.item(),
			e.salt.to_vec(),
		])
	}

	/// The SLASH witness of a coin in `state`.
	pub fn slash_witness(&self, state: BondState, e: &Evidence) -> Result<Vec<Vec<u8>>, BondError> {
		let tap = match state {
			BondState::Bonded => self.taproot(),
			BondState::Noticed => self.notice_taproot(),
		};
		Ok(tap.witness(&self.slash_script(), Self::slash_items(e)?))
	}

	/// The slash of `coins` (each a bond coin, bonded or in notice, with the
	/// output it is) on `e`: each burned whole at its own index, the fee from
	/// the coin `fee` names ([`FeeSource::Coin`]; the bond's value never pays
	/// it). The fee coin's own witness is the broadcaster's to add.
	pub fn slash_tx(&self, coins: &[(OutPoint, TxOut)], e: &Evidence, fee: &FeeSource) -> Result<UnrollTx, BondError> {
		if coins.is_empty() {
			return Err(BondError::NothingToSlash);
		}
		let mut burns = Vec::with_capacity(coins.len());
		let mut states = Vec::with_capacity(coins.len());
		for (i, (_, o)) in coins.iter().enumerate() {
			let state = self.state_of(&o.script_pubkey).ok_or(BondError::NotABond(i))?;
			let (asset, value) = match (o.asset.explicit(), o.value.explicit()) {
				(Some(a), Some(v)) => (a, v),
				_ => return Err(BondError::NotExplicit),
			};
			burns.push(burn(asset, value));
			states.push(state);
		}
		let inputs = coins.iter().map(|(op, o)| (*op, o.clone(), FINAL)).collect();
		let mut u = assemble(elements::LockTime::ZERO, inputs, &burns, fee, FINAL)?;
		for (i, state) in states.into_iter().enumerate() {
			u.tx.input[i].witness.script_witness = self.slash_witness(state, e)?;
		}
		Ok(u)
	}

	/// The notice of `coin`, the bond holding `value` of `asset`: the whole
	/// bond to the notice output at index 0, the fee from `fee`. `W` signs
	/// [`KeySpend::sighash`] and finishes it with its signature.
	pub fn notice_tx(&self, coin: OutPoint, asset: AssetId, value: u64, fee: &FeeSource) -> Result<KeySpend, BondError> {
		let spent = explicit_txout(asset, value, self.script_pubkey());
		let out = ExplicitOutput::new(asset, value, self.notice_script_pubkey());
		Ok(KeySpend::build(self.taproot(), self.notice_script(), vec![(coin, spent, FINAL)], &[out], fee)?)
	}

	/// The withdrawal of `coin`, the notice output holding `value` of `asset`,
	/// into `outputs`: input 0's sequence is the delay, so it confirms only `D`
	/// after the notice did. `W` signs [`KeySpend::sighash`] and finishes it.
	pub fn withdraw_tx(&self, coin: OutPoint, asset: AssetId, value: u64, outputs: &[ExplicitOutput], fee: &FeeSource)
		-> Result<KeySpend, BondError>
	{
		let spent = explicit_txout(asset, value, self.notice_script_pubkey());
		Ok(KeySpend::build(self.notice_taproot(), self.withdraw_script(),
			vec![(coin, spent, Sequence(self.notice.to_sequence()))], outputs, fee)?)
	}
}

/// A message `S` signed under a salt, as a holder or a watcher keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cosigned {
	pub salt: [u8; 32],
	pub signed: Signed,
}

/// Every message `S` co-signed that `coin` rests on, down its whole lineage:
/// for each input of each reassignment, the spend of its coin into its
/// checkpoint (under the coin's salt) and of the checkpoint into the
/// reassignment's outputs (under the checkpoint's salt); for an in-tree fill,
/// the fill itself (under the order coin's salt) and its taker inputs' two
/// each. A round's leaf and a board rest on no such message. What a holder
/// hands a watcher: one of these beside another message `S` signed under the
/// same salt is a slash ([`BondPolicy::check`]).
pub fn cosigned_by(coin: &crate::ValidCoin) -> Vec<Cosigned> {
	let mut out = vec![];
	cosigned_into(coin, &mut out);
	out
}

fn cosigned_inputs(inputs: &[crate::ValidInput], outputs: &[ExplicitOutput], before: &[TxOut], out: &mut Vec<Cosigned>) {
	use crate::Rebindable;
	let mut named = before.to_vec();
	named.extend(inputs.iter().map(|i| i.checkpoint_output().txout()));
	for (k, i) in inputs.iter().enumerate() {
		if let Ok(m) = i.coin.leaf.message(i.coin.asset, i.coin.value, &[i.checkpoint_output()]) {
			if let Some(rest) = rebind_rest(&m.preimage) {
				out.push(Cosigned { salt: i.coin.leaf.salt, signed: Signed { form: Form::Rebind, rest, signature: i.checkpoint_pair.operator } });
			}
		}
		if let Ok(m) = i.checkpoint.message_in((before.len() + k) as u32, &named, outputs) {
			if let Some(rest) = rebind_rest(&m.preimage) {
				out.push(Cosigned { salt: i.checkpoint.salt, signed: Signed { form: Form::Rebind, rest, signature: i.reassignment_pair.operator } });
			}
		}
		cosigned_into(&i.coin, out);
	}
}

fn cosigned_into(coin: &crate::ValidCoin, out: &mut Vec<Cosigned>) {
	match &coin.origin {
		crate::ValidOrigin::Leaf { .. } | crate::ValidOrigin::Board { .. } | crate::ValidOrigin::Accumulator { .. } => {},
		crate::ValidOrigin::Transfer { inputs, outputs, .. } => cosigned_inputs(inputs, outputs, &[], out),
		crate::ValidOrigin::Fill { order, signature, inputs, outputs, .. } => {
			let txouts: Vec<TxOut> = outputs.iter().map(|o| o.txout()).collect();
			if let Some(rest) = order.leaf.order_policy().and_then(|p| p.fill_preimage(order.value, &txouts).ok()).and_then(|b| fill_rest(&b)) {
				out.push(Cosigned { salt: order.leaf.salt, signed: Signed { form: Form::Fill, rest, signature: *signature } });
			}
			cosigned_into(order, out);
			cosigned_inputs(inputs, outputs, &[order.output().txout()], out);
		},
	}
}

/// What `S` signed for input `input` of `tx`, a collaborative spend of a
/// coin under `salt` (a leaf, a checkpoint, a board, `htlc-1` or `order-2`'s
/// collaborative path) found on the chain or in a mempool, `prevout` the
/// output it spends: the message rebuilt from the transaction and the coin,
/// and the operator's signature, the witness's first item. `None` when the
/// input is no such spend: its script pushes no `K` of `salt` (nor a
/// `landing-1` leaf's `K ‖ P`), its witness is
/// not `<sig_S> <sig_A> <m> <script> <control>`, or what it commits to is not
/// explicit. The caller checks the signature ([`BondPolicy::verify`]).
pub fn rebind_signed_in(chain: &Chain, salt: &[u8; 32], tx: &Transaction, input: usize, prevout: &TxOut) -> Option<Signed> {
	let w = &tx.input.get(input)?.witness.script_witness;
	if w.len() != 5 || w[0].len() != 64 || w[1].len() != 64 || w[2].len() != 1 {
		return None;
	}
	let k = chain.leaf_constant(salt);
	let script = Script::from(w[3].clone());
	// What the script pushes for its message: `K`, or a `landing-1` leaf's
	// `K ‖ P` ([`Chain::landing_prefix`]).
	let k = script.instructions().find_map(|i| match i {
		Ok(elements::script::Instruction::PushBytes(b))
			if b.starts_with(&k) && (b.len() == 32 || b.len() == 32 + crate::landing::PROGRAM_BYTES) => Some(b.to_vec()),
		_ => None,
	})?;
	let m = w[2][0] as usize;
	if m == 0 || m > crate::leaf::MAX_OUTPUTS as usize || tx.output.len() < m {
		return None;
	}
	let outputs: Vec<ExplicitOutput> = tx.output[..m].iter().map(ExplicitOutput::from_txout).collect::<Option<_>>()?;
	let (asset, value) = (prevout.asset.explicit()?, prevout.value.explicit()?);
	let message = crate::message::rebind_message(&k, asset, value, &outputs).ok()?;
	Some(Signed { form: Form::Rebind, rest: rebind_rest(&message.preimage)?, signature: Signature::from_slice(&w[0]).ok()? })
}

/// A spend by `arca/collab-2` ([`crate::collab`]), read from its witness:
/// the salt its data leaf names, how many inputs it names and how many
/// outputs it commits to. `None` when the witness is no such spend.
pub fn collab2_spend(witness: &[Vec<u8>]) -> Option<([u8; 32], u8, u8)> {
	// Read as the program sees it, past any annex (BIP341's rule): a valid
	// spend carries none, since the program refuses one.
	let w = crate::witness::without_annex(witness);
	if w.len() != 4 || w[2] != crate::collab::collab_cmr() || w[0].len() != crate::collab::DATA_BYTES + 2 + 128 {
		return None;
	}
	let salt: [u8; 32] = w[0][64..96].try_into().ok()?;
	Some((salt, w[0][96], w[0][97]))
}

/// What `S` signed for input `input` of `tx`, a spend under `salt` by
/// `arca/collab-2` (a `vtxo-2` leaf or its checkpoint) found on the chain or
/// in a mempool, `named` the outputs its first `n` inputs spend: the message
/// rebuilt from the transaction, and the operator's signature, the last 64
/// bytes of the Simplicity witness. `None` when the input is no such spend
/// under `salt`, `named` is not its first `n` inputs' outputs, or what it
/// commits to cannot be read. The caller checks the signature
/// ([`BondPolicy::verify`]).
pub fn collab2_signed_in(chain: &Chain, salt: &[u8; 32], tx: &Transaction, input: usize, named: &[TxOut]) -> Option<Signed> {
	let w = crate::witness::without_annex(&tx.input.get(input)?.witness.script_witness);
	let (found, n, m) = collab2_spend(w)?;
	if found != *salt || named.len() != n as usize || tx.output.len() < m as usize || m == 0 {
		return None;
	}
	let mut owner = [0u8; 32];
	owner.copy_from_slice(&w[0][..32]);
	let mut operator = [0u8; 32];
	operator.copy_from_slice(&w[0][32..64]);
	let c = crate::collab::Collab2 {
		owner: XOnlyPublicKey::from_slice(&owner).ok()?, operator: XOnlyPublicKey::from_slice(&operator).ok()?, salt: *salt, chain: *chain,
	};
	let message = c.message(input as u32, named, &tx.output[..m as usize]).ok()?;
	Some(Signed { form: Form::Rebind, rest: rebind_rest(&message.preimage)?, signature: Signature::from_slice(&w[0][162..226]).ok()? })
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::sign::sign_digest;
	use elements::hashes::Hash;
	use elements::secp256k1_zkp::Keypair;

	fn key(label: &str) -> Keypair {
		Keypair::from_seckey_slice(crate::taptree::secp(), &sha256(label.as_bytes())).unwrap()
	}

	fn policy() -> (BondPolicy, Keypair) {
		let s = key("S");
		let chain = Chain::new(elements::BlockHash::from_byte_array([7; 32]));
		let p = BondPolicy::new(chain, s.x_only_public_key().0, key("W").x_only_public_key().0,
			RelativeTime::from_units(5_400).unwrap()).unwrap();
		(p, s)
	}

	fn signed(p: &BondPolicy, s: &Keypair, form: Form, salt: &[u8; 32], rest: &[u8]) -> Signed {
		let d = digest(&p.chain, form, salt, rest);
		Signed { form, rest: rest.to_vec(), signature: sign_digest(s, &d, &[0; 32]) }
	}

	#[test]
	fn a_rebind_digest_is_the_leafs_message() {
		let (p, _) = policy();
		let salt = [3; 32];
		let k = p.chain.leaf_constant(&salt);
		let outs = [ExplicitOutput::new(AssetId::from_byte_array([9; 32]), 5, Script::from(vec![0x51]))];
		let m = crate::message::rebind_message(&k, AssetId::from_byte_array([9; 32]), 10, &outs).unwrap();
		let rest = rebind_rest(&m.preimage).unwrap();
		assert_eq!(rest.len(), 43 + 32);
		assert_eq!(digest(&p.chain, Form::Rebind, &salt, &rest), m.digest);
	}

	#[test]
	fn evidence_is_two_digests_under_one_salt() {
		let (p, s) = policy();
		let salt = [4; 32];
		let a = signed(&p, &s, Form::Rebind, &salt, &[1; 75]);
		let b = signed(&p, &s, Form::Rebind, &salt, &[2; 75]);
		assert_eq!(p.check(&Evidence { salt, a: a.clone(), b: b.clone() }), Ok(()));
		// A fill beside a cancel under one salt is a double-sign too.
		let f = signed(&p, &s, Form::Fill, &salt, &[5; 105]);
		assert_eq!(p.check(&Evidence { salt, a: a.clone(), b: f }), Ok(()));
		// One digest twice, with two signatures, is not.
		let a2 = Signed { signature: sign_digest(&s, &p.digest_of(&salt, &a), &[1; 32]), ..a.clone() };
		assert_ne!(a2.signature, a.signature);
		assert_eq!(p.check(&Evidence { salt, a: a.clone(), b: a2 }), Err(BondError::SameDigest));
		// Another salt's message, or another key's signature, does not verify.
		let other = signed(&p, &s, Form::Rebind, &[5; 32], &[2; 75]);
		assert_eq!(p.check(&Evidence { salt, a: a.clone(), b: other }), Err(BondError::Signature("second")));
		let stranger = signed(&p, &key("T"), Form::Rebind, &salt, &[2; 75]);
		assert_eq!(p.check(&Evidence { salt, a, b: stranger }), Err(BondError::Signature("second")));
	}

	#[test]
	fn rests_go_in_three_chunks_of_at_most_eighty_bytes() {
		for n in [0, 1, 75, 80, 81, 171, 240] {
			let r: Vec<u8> = (0..n).map(|i| i as u8).collect();
			let c = chunks(&r).unwrap();
			assert!(c.iter().all(|x| x.len() <= MAX_ITEM));
			assert_eq!(c.concat(), r);
		}
		assert_eq!(chunks(&[0; 241]), Err(241));
	}

	#[test]
	fn the_withdraw_key_is_never_s() {
		let (p, s) = policy();
		assert_eq!(BondPolicy::new(p.chain, s.x_only_public_key().0, s.x_only_public_key().0, p.notice),
			Err(BondError::WithdrawKeyIsOperator));
	}

	#[test]
	fn the_fill_prefix_is_no_other_message_s_signs() {
		// A fill-form slash computes F ‖ salt ‖ rest: F is not the start of
		// the unroll authorisation, nor the hash of a tag S signs under.
		let (p, _) = policy();
		let f = crate::order::fill_prefix(&p.chain);
		for tag in [&b"Arca/unroll"[..], b"Arca/release", b"ArcaRbd1"] {
			assert_ne!(&f[..tag.len()], tag);
		}
		for tag in [&b"TapSighash/elements"[..], b"Arca/record-head", b"sequentia-registry/arca-operator/v1"] {
			assert_ne!(f, sha256(tag));
		}
	}
}
