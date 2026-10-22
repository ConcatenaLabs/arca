//! `channel-1`: a leaf with a balance for each of owner and operator.
//!
//! A channel's state is `(n, a, s, F)`: its number, the owner's balance, the
//! operator's balance and the cumulative credit already folded into the
//! owner's ([`State`]); `a + s` is the leaf's value `V`. The leaf in the tree is
//! the output of state 0, `(0, V − capacity, capacity, 0)`, so a channel needs
//! no signed state to exist. Every channel output is a taproot output with the
//! NUMS internal key and the leaves `[collab, [update(n), settle(n)]]`:
//!
//! ```text
//! collab:     vtxo-1's collaborative path under the salt's K, the same in every state
//! update(n):  OP_SIZE <8> OP_EQUALVERIFY OP_DUP <n> OP_GREATERTHAN64 OP_VERIFY      # <sig_S> <sig_A> <m>
//!             <Q> OP_SWAP OP_CAT
//!             OP_PUSHCURRENTINPUTINDEX OP_INSPECTOUTPUTSCRIPTPUBKEY OP_1 OP_EQUALVERIFY OP_CAT
//!             OP_SHA256 OP_TUCK <A> OP_CHECKSIGFROMSTACKVERIFY <S> OP_CHECKSIGFROMSTACKVERIFY
//!             [the output at this input's index keeps its asset and value]
//! settle(n):  <exit delay> OP_CHECKSEQUENCEVERIFY OP_DROP
//!             [output 0: exactly a to OP_1 <A>; output 1: exactly s to the credit output of state n;
//!              both in the input's asset; a zero balance's half is left out and the other takes output 0]
//! ```
//!
//! `update(n)` takes a state `m > n` signed by both over
//! `SHA256(Q ‖ le8(m) ‖ P)` ([`ChannelPolicy::state_message`]),
//! `Q = SHA256(SHA256("ArcaChn1" ‖ genesis) ‖ salt)`, `P` the witness-v1
//! program of the output at the input's own index: one pair covers the move
//! and the state moved to, since `P` commits to its settle. The number is a
//! witness value, not a lock time. A pair for state `m` spends any output of
//! the channel in a state below `m`, at once, and nothing else.
//!
//! `collab` is the same in every state, so a pair made for the coin (its
//! forfeit, when it is given up in a round) spends it in whatever state it
//! reached on the chain; `settle` waits the exit delay, which is when that pair
//! answers it.
//!
//! The operator's balance lands in the **credit output** of the state
//! ([`ChannelPolicy::credit_taproot`]), `[claim(n), provider]`:
//!
//! ```text
//! claim(n):   OP_SIZE <8> OP_EQUALVERIFY                                             # <sig> <c>
//!             OP_DUP <N> OP_SWAP OP_CAT OP_SHA256 OP_ROT OP_SWAP <S> OP_CHECKSIGFROMSTACKVERIFY
//!             <B> OP_2DUP OP_GREATERTHAN64 OP_IF OP_NIP OP_ELSE OP_DROP OP_ENDIF        # min(c, B)
//!             <B> [this input's value] OP_SUB64 OP_VERIFY OP_SUB64 OP_VERIFY          # delta = min(c, B) − paid
//!             OP_DUP <0> OP_GREATERTHAN64 OP_VERIFY
//!             [output i: exactly delta to OP_1 <A>; unless the rest is 0, output i+1: the rest to this script]
//! provider:   <window> OP_CHECKSEQUENCEVERIFY OP_DROP <S> OP_CHECKSIG
//! ```
//!
//! A note is `S`'s signature over `SHA256(N ‖ le8(c))`
//! ([`ChannelPolicy::note_message`]), `N = SHA256(SHA256("ArcaCrd1" ‖ genesis) ‖
//! salt)`, `c` the cumulative credit since the channel opened; `B = s + F`.
//! What was paid is read from the chain, so the leaf keeps no state; the rest
//! returns to the same script, so a newer note is claimed against it; the cap
//! `min(c, B)` makes every older state worth at least the latest to the owner.
//!
//! No channel leaf takes a key from its witness; every number from a witness
//! is checked to be 8 bytes, nothing multiplies, and every sum is at most `V`.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, LockTime, OutPoint, Script, Sequence};

use crate::leaf::{rebindable_two_party, two_party_items};
use crate::message::{Chain, CsfsMessage};
use crate::script::{sha256, BuilderExt, ExplicitOutput};
use crate::spend::{assemble, explicit_txout, KeySpend, Pair, SpendError, FINAL};
use crate::taptree::TapOutput;
use crate::time::RelativeTime;
use crate::unroll::{FeeSource, UnrollTx};

/// The state message's domain tag.
pub const STATE_TAG: &[u8; 8] = b"ArcaChn1";
/// The credit note's domain tag.
pub const CREDIT_TAG: &[u8; 8] = b"ArcaCrd1";
/// The largest state number or amount an 8-byte script number holds.
pub const MAX_NUMBER: u64 = i64::MAX as u64;

/// Why a channel's terms, state or claim cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
	#[error("a channel-1 leaf's capacity of {capacity} is not below its value of {value}: its owner would open with nothing")]
	Capacity { capacity: u64, value: u64 },
	#[error("a channel-1 leaf's credit window of {window} units is shorter than its exit delay of {delay}")]
	Window { window: u16, delay: u16 },
	#[error("state {number}'s balances {owner} and {operator} do not add up to the channel's value of {value}")]
	Balances { number: u64, owner: u64, operator: u64, value: u64 },
	#[error("a state number or an amount above 2^63 - 1 does not fit the scripts' 64-bit arithmetic")]
	TooLarge,
	#[error("state {to} does not follow state {from}: an update needs a higher number")]
	NotNewer { from: u64, to: u64 },
	#[error("a note of {note} credits nothing more than the {paid} already paid from this credit output")]
	NothingToClaim { note: u64, paid: u64 },
	#[error("the credit output holds {value}, more than the {cap} its state owes")]
	CreditValue { value: u64, cap: u64 },
	#[error("the spend of the output of state {from} is not one of its leaves' spends: {why}")]
	Spend { from: u64, why: &'static str },
}

/// How a spend of a channel's output left it, as [`ChannelPolicy::read_spend`]
/// reads it from the spending input's witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelSpend {
	/// `update(n)`, into the output of state `to`, the witness's number.
	Update { to: u64 },
	/// `settle(n)`: the state's balances paid out.
	Settle,
	/// The collaborative path under `K`: a forfeit or another co-signed spend.
	Collab,
}

/// `Q = SHA256(SHA256("ArcaChn1" ‖ genesis) ‖ salt)`: the constant every
/// state message of the channel starts with.
pub fn state_constant(chain: &Chain, salt: &[u8; 32]) -> [u8; 32] {
	tagged_constant(STATE_TAG, chain, salt)
}

/// `N = SHA256(SHA256("ArcaCrd1" ‖ genesis) ‖ salt)`: the constant every
/// credit note of the channel starts with.
pub fn credit_constant(chain: &Chain, salt: &[u8; 32]) -> [u8; 32] {
	tagged_constant(CREDIT_TAG, chain, salt)
}

fn tagged_constant(tag: &[u8; 8], chain: &Chain, salt: &[u8; 32]) -> [u8; 32] {
	let mut b = tag.to_vec();
	b.extend(chain.genesis_bytes());
	let mut c = sha256(&b).to_vec();
	c.extend(salt);
	sha256(&c)
}

/// A channel's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct State {
	/// Its number: 0 for the leaf in the tree, then one higher for each state
	/// both sides sign.
	pub number: u64,
	/// The owner's balance `a`.
	pub owner: u64,
	/// The operator's balance `s`.
	pub operator: u64,
	/// `F`: the cumulative credit already folded into the owner's balance.
	pub folded: u64,
}

impl State {
	/// `B = s + F`: the most a note claims from this state's credit output,
	/// counting what was folded.
	pub fn credit_cap(&self) -> u64 {
		self.operator.saturating_add(self.folded)
	}

	/// The state after the owner pays `amount` to the operator and folds its
	/// credit up to the cumulative `note`: one number higher.
	pub fn pay(&self, amount: u64, note: u64) -> Option<State> {
		let fold = note.checked_sub(self.folded)?;
		let owner = self.owner.checked_add(fold)?.checked_sub(amount)?;
		let operator = self.operator.checked_sub(fold)?.checked_add(amount)?;
		Some(State { number: self.number.checked_add(1)?, owner, operator, folded: note.max(self.folded) })
	}
}

/// What a `channel-1` leaf's record keeps beside every leaf's terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Channel {
	/// The operator's opening balance `s_0`, below the leaf's value.
	pub capacity: u64,
	/// How long the operator waits, after a settle, before it may take its
	/// credit output: the owner's time to claim an unfolded note.
	pub window: RelativeTime,
}

impl Channel {
	/// The terms a leaf of `value` with this channel has.
	pub fn terms(&self, value: u64) -> ChannelTerms {
		ChannelTerms { value, capacity: self.capacity, window: self.window }
	}
}

/// A channel's terms as its scripts need them: the leaf's value, the
/// operator's opening balance and the credit window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelTerms {
	pub value: u64,
	pub capacity: u64,
	pub window: RelativeTime,
}

impl ChannelTerms {
	/// The record's form of these terms.
	pub fn channel(&self) -> Channel {
		Channel { capacity: self.capacity, window: self.window }
	}

	/// State 0: the leaf as the tree holds it.
	pub fn opening(&self) -> State {
		State { number: 0, owner: self.value - self.capacity, operator: self.capacity, folded: 0 }
	}

	/// The capacity is below the value and the window no shorter than the
	/// exit delay.
	pub fn check(&self, exit_delay: RelativeTime) -> Result<(), ChannelError> {
		if self.value > MAX_NUMBER {
			return Err(ChannelError::TooLarge);
		}
		if self.capacity >= self.value {
			return Err(ChannelError::Capacity { capacity: self.capacity, value: self.value });
		}
		if self.window.units() < exit_delay.units() {
			return Err(ChannelError::Window { window: self.window.units(), delay: exit_delay.units() });
		}
		Ok(())
	}

	/// A state's balances add up to the value, and its numbers fit.
	pub fn check_state(&self, state: &State) -> Result<(), ChannelError> {
		if state.number > MAX_NUMBER || state.folded > MAX_NUMBER || state.credit_cap() > MAX_NUMBER {
			return Err(ChannelError::TooLarge);
		}
		if state.owner.checked_add(state.operator) != Some(self.value) {
			return Err(ChannelError::Balances { number: state.number, owner: state.owner, operator: state.operator,
				value: self.value });
		}
		Ok(())
	}
}

/// A `channel-1` coin's policy: the leaf's keys, salt, chain and exit delay,
/// and its channel terms. Every script is a function of a [`State`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelPolicy {
	pub owner: XOnlyPublicKey,
	pub operator: XOnlyPublicKey,
	pub salt: [u8; 32],
	pub chain: Chain,
	/// The settle's delay: the leaf's exit delay.
	pub exit_delay: RelativeTime,
	pub terms: ChannelTerms,
}

impl ChannelPolicy {
	/// `Q`, over the salt.
	pub fn state_constant(&self) -> [u8; 32] {
		state_constant(&self.chain, &self.salt)
	}

	/// `N`, over the salt.
	pub fn credit_constant(&self) -> [u8; 32] {
		credit_constant(&self.chain, &self.salt)
	}

	/// State 0.
	pub fn opening(&self) -> State {
		self.terms.opening()
	}

	/// The collaborative path: `vtxo-1`'s, under the salt's `K`.
	pub fn collab_script(&self) -> Script {
		rebindable_two_party(&self.owner, &self.operator, &self.chain.leaf_constant(&self.salt))
	}

	/// `update(n)`.
	pub fn update_script(&self, n: u64) -> Script {
		let b = Builder::new().push_opcode(OP_SIZE).push_int(8).push_opcode(OP_EQUALVERIFY)
			.push_opcode(OP_DUP).push_slice(&n.to_le_bytes()).ops(&[OP_GREATERTHAN64, OP_VERIFY])
			.push_slice(&self.state_constant()).ops(&[OP_SWAP, OP_CAT])
			.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTSCRIPTPUBKEY]).push_int(1).ops(&[OP_EQUALVERIFY, OP_CAT])
			.ops(&[OP_SHA256, OP_TUCK]).push_slice(&self.owner.serialize()).push_opcode(OP_CHECKSIGFROMSTACKVERIFY)
			.push_slice(&self.operator.serialize()).push_opcode(OP_CHECKSIGFROMSTACKVERIFY);
		keep_at_current(b).into_script()
	}

	/// The credit output's two leaves for `state`: `[claim(n), provider]`.
	pub fn claim_script(&self, state: &State) -> Script {
		let b = state.credit_cap().to_le_bytes();
		let next = |b: Builder| b.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_1ADD]);
		let mut s = Builder::new().push_opcode(OP_SIZE).push_int(8).push_opcode(OP_EQUALVERIFY)
			.push_opcode(OP_DUP).push_slice(&self.credit_constant()).ops(&[OP_SWAP, OP_CAT, OP_SHA256, OP_ROT, OP_SWAP])
			.push_slice(&self.operator.serialize()).push_opcode(OP_CHECKSIGFROMSTACKVERIFY)
			.push_slice(&b).ops(&[OP_2DUP, OP_GREATERTHAN64, OP_IF, OP_NIP, OP_ELSE, OP_DROP, OP_ENDIF])
			.push_slice(&b).ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTVALUE]).push_int(1)
			.ops(&[OP_EQUALVERIFY, OP_SUB64, OP_VERIFY, OP_SUB64, OP_VERIFY, OP_DUP])
			.push_slice(&0u64.to_le_bytes()).ops(&[OP_GREATERTHAN64, OP_VERIFY])
			.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_DUP, OP_INSPECTOUTPUTSCRIPTPUBKEY]).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.owner.serialize()).push_opcode(OP_EQUALVERIFY);
		s = same_asset_at(s.push_opcode(OP_DUP));
		s = s.push_opcode(OP_INSPECTOUTPUTVALUE).push_int(1).ops(&[OP_EQUALVERIFY, OP_OVER, OP_EQUALVERIFY])
			.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTVALUE]).push_int(1).ops(&[OP_EQUALVERIFY, OP_SWAP, OP_SUB64, OP_VERIFY])
			.push_opcode(OP_DUP).push_slice(&0u64.to_le_bytes()).ops(&[OP_EQUAL, OP_NOTIF]);
		s = next(s).push_opcode(OP_INSPECTOUTPUTVALUE).push_int(1).ops(&[OP_EQUALVERIFY, OP_OVER, OP_EQUALVERIFY]);
		s = next(s).ops(&[OP_INSPECTOUTPUTSCRIPTPUBKEY, OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTSCRIPTPUBKEY,
			OP_ROT, OP_EQUALVERIFY, OP_EQUALVERIFY]);
		s = same_asset_at(next(s));
		s.ops(&[OP_ENDIF, OP_DROP]).push_int(1).into_script()
	}

	/// `<window> OP_CHECKSEQUENCEVERIFY OP_DROP <S> OP_CHECKSIG`.
	pub fn provider_script(&self) -> Script {
		Builder::new().push_int(self.terms.window.to_sequence() as i64).ops(&[OP_CSV, OP_DROP])
			.push_slice(&self.operator.serialize()).push_opcode(OP_CHECKSIG).into_script()
	}

	/// The credit output of `state`: `[claim(n), provider]`, both at depth 1.
	pub fn credit_taproot(&self, state: &State) -> TapOutput {
		TapOutput::new(vec![(1, self.claim_script(state)), (1, self.provider_script())])
	}

	/// `settle(n)`.
	pub fn settle_script(&self, state: &State) -> Script {
		let credit = self.credit_taproot(state).program();
		let owner = self.owner.serialize();
		let halves: Vec<(&[u8], u64)> = [(&owner[..], state.owner), (&credit[..], state.operator)]
			.into_iter().filter(|(_, v)| *v > 0).collect();
		let mut b = Builder::new().push_int(self.exit_delay.to_sequence() as i64).ops(&[OP_CSV, OP_DROP]);
		for (i, (program, value)) in halves.iter().enumerate() {
			let i = i as i64;
			b = b.push_int(i).push_opcode(OP_INSPECTOUTPUTSCRIPTPUBKEY).push_int(1).push_opcode(OP_EQUALVERIFY)
				.push_slice(program).push_opcode(OP_EQUALVERIFY);
			b = same_asset_at(b.push_int(i));
			b = b.push_int(i).push_opcode(OP_INSPECTOUTPUTVALUE).push_int(1).push_opcode(OP_EQUALVERIFY)
				.push_slice(&value.to_le_bytes())
				.push_opcode(if i as usize == halves.len() - 1 { OP_EQUAL } else { OP_EQUALVERIFY });
		}
		b.into_script()
	}

	/// The channel output of `state`: `[collab, [update(n), settle(n)]]`.
	pub fn taproot(&self, state: &State) -> TapOutput {
		TapOutput::new(vec![
			(1, self.collab_script()),
			(2, self.update_script(state.number)),
			(2, self.settle_script(state)),
		])
	}

	pub fn script_pubkey(&self, state: &State) -> Script {
		self.taproot(state).script_pubkey()
	}

	pub fn program(&self, state: &State) -> [u8; 32] {
		self.taproot(state).program()
	}

	/// What owner and operator sign for `state`: `SHA256(Q ‖ le8(n) ‖ P_n)`.
	/// The state's balances are checked against the channel's value first: a
	/// state is signed only for a program rebuilt from these terms.
	pub fn state_message(&self, state: &State) -> Result<CsfsMessage, ChannelError> {
		self.terms.check_state(state)?;
		let mut b = self.state_constant().to_vec();
		b.extend(state.number.to_le_bytes());
		b.extend(self.program(state));
		Ok(CsfsMessage { digest: sha256(&b), preimage: b })
	}

	/// What the operator signs for a cumulative credit `c`: `SHA256(N ‖ le8(c))`.
	pub fn note_message(&self, c: u64) -> Result<CsfsMessage, ChannelError> {
		if c > MAX_NUMBER {
			return Err(ChannelError::TooLarge);
		}
		let mut b = self.credit_constant().to_vec();
		b.extend(c.to_le_bytes());
		Ok(CsfsMessage { digest: sha256(&b), preimage: b })
	}

	/// What a claim of note `c` against a credit output of `state` holding
	/// `value_in` pays the owner (`delta`) and returns (`rest`), as the claim
	/// script computes them.
	pub fn claim_amounts(&self, state: &State, c: u64, value_in: u64) -> Result<(u64, u64), ChannelError> {
		let cap = state.credit_cap();
		if value_in > cap {
			return Err(ChannelError::CreditValue { value: value_in, cap });
		}
		let paid = cap - value_in;
		let m = c.min(cap);
		if m <= paid {
			return Err(ChannelError::NothingToClaim { note: c, paid });
		}
		let delta = m - paid;
		Ok((delta, value_in - delta))
	}

	/// The outputs a settle of `state` pays, in order: the owner's balance to
	/// `OP_1 <A>`, the operator's to the state's credit output, each left out
	/// when zero.
	pub fn settle_outputs(&self, asset: AssetId, state: &State) -> Vec<ExplicitOutput> {
		let mut v = vec![];
		if state.owner > 0 {
			v.push(ExplicitOutput::new(asset, state.owner, owner_script_pubkey(&self.owner)));
		}
		if state.operator > 0 {
			v.push(ExplicitOutput::new(asset, state.operator, self.credit_taproot(state).script_pubkey()));
		}
		v
	}

	/// The collaborative witness at the output of `state`: the pair owner and
	/// operator made for the coin (its forfeit, a checkpoint) over `m`
	/// outputs, which spends the coin in any state it reached.
	pub fn collab_witness(&self, state: &State, pair: &Pair, m: u8) -> Vec<Vec<u8>> {
		self.taproot(state).witness(&self.collab_script(), two_party_items(&pair.operator, &pair.owner, m))
	}

	/// The spend of `coin`, the channel's output of `state`, by its
	/// collaborative path into `outputs`, signed by `pair` over the coin's
	/// rebindable message ([`crate::LeafPolicy::collab_message`] of the leaf).
	pub fn collab_tx(&self, coin: OutPoint, asset: AssetId, state: &State, outputs: &[ExplicitOutput], pair: &Pair,
		fee: &FeeSource) -> Result<UnrollTx, SpendError>
	{
		if outputs.is_empty() || outputs.len() > crate::leaf::MAX_OUTPUTS as usize {
			return Err(crate::Error::OutputCount(outputs.len()).into());
		}
		let spent = explicit_txout(asset, self.terms.value, self.script_pubkey(state));
		let mut u = assemble(LockTime::ZERO, vec![(coin, spent, FINAL)], outputs, fee, FINAL)?;
		u.tx.input[0].witness.script_witness = self.collab_witness(state, pair, outputs.len() as u8);
		Ok(u)
	}

	/// The update witness from the output of `from` to the output of `to`.
	pub fn update_witness(&self, from: &State, to: &State, operator_sig: &Signature, owner_sig: &Signature) -> Vec<Vec<u8>> {
		self.taproot(from).witness(&self.update_script(from.number), vec![
			operator_sig.as_ref().to_vec(), owner_sig.as_ref().to_vec(), to.number.to_le_bytes().to_vec(),
		])
	}

	/// How the spend whose input carries `witness` left the channel's output
	/// of `from`: by which of its three leaves, and for an update the number
	/// it moved to. The leaf is the script the spend ran, the item below the
	/// control block, read through [`crate::witness::without_annex`]: an
	/// annex is the same spend (consensus drops it before the script runs),
	/// and nothing a channel signs covers one (the state message, the note
	/// and the collaborative pair are built over messages of their own), so
	/// anyone who relays or mines a spend can add one. A witness whose script
	/// is none of the output's leaves, or whose items do not fit that leaf,
	/// is refused, never taken for one of them.
	pub fn read_spend(&self, from: &State, witness: &[Vec<u8>]) -> Result<ChannelSpend, ChannelError> {
		let w = crate::witness::without_annex(witness);
		let refused = |why| ChannelError::Spend { from: from.number, why };
		let [items @ .., leaf, _control] = w else { return Err(refused("not a script-path spend")) };
		if leaf.as_slice() == self.update_script(from.number).as_bytes() {
			match items {
				[_, _, m] if m.len() == 8 => Ok(ChannelSpend::Update { to: u64::from_le_bytes(m[..].try_into().expect("8 bytes")) }),
				_ => Err(refused("an update's items are two signatures and an 8-byte number")),
			}
		} else if leaf.as_slice() == self.settle_script(from).as_bytes() {
			match items {
				[] => Ok(ChannelSpend::Settle),
				_ => Err(refused("a settle takes no items")),
			}
		} else if leaf.as_slice() == self.collab_script().as_bytes() {
			Ok(ChannelSpend::Collab)
		} else {
			Err(refused("its script is none of the output's leaves"))
		}
	}

	/// The settle witness of `state`: the script and its control block.
	pub fn settle_witness(&self, state: &State) -> Vec<Vec<u8>> {
		self.taproot(state).witness(&self.settle_script(state), vec![])
	}

	/// The claim witness of note `c` against the credit output of `state`.
	pub fn claim_witness(&self, state: &State, note: &Signature, c: u64) -> Vec<Vec<u8>> {
		self.credit_taproot(state).witness(&self.claim_script(state), vec![note.as_ref().to_vec(), c.to_le_bytes().to_vec()])
	}

	/// The spend of `coin`, the channel's output of `from` holding `value` of
	/// `asset`, by update into the output of `to` at index 0, signed by both;
	/// a fee coin pays.
	pub fn update_tx(&self, coin: OutPoint, asset: AssetId, from: &State, to: &State, operator_sig: &Signature,
		owner_sig: &Signature, fee: &FeeSource) -> Result<UnrollTx, SpendError>
	{
		if to.number <= from.number {
			return Err(SpendError::Channel(ChannelError::NotNewer { from: from.number, to: to.number }));
		}
		self.terms.check_state(to).map_err(SpendError::Channel)?;
		let value = self.terms.value;
		let spent = explicit_txout(asset, value, self.script_pubkey(from));
		let out = ExplicitOutput::new(asset, value, self.script_pubkey(to));
		let mut u = assemble(LockTime::ZERO, vec![(coin, spent, FINAL)], &[out], fee, FINAL)?;
		u.tx.input[0].witness.script_witness = self.update_witness(from, to, operator_sig, owner_sig);
		Ok(u)
	}

	/// The settle of `coin`, the channel's output of `state`, once the exit
	/// delay has passed since it confirmed; a fee coin pays.
	pub fn settle_tx(&self, coin: OutPoint, asset: AssetId, state: &State, fee: &FeeSource) -> Result<UnrollTx, SpendError> {
		self.terms.check_state(state).map_err(SpendError::Channel)?;
		let spent = explicit_txout(asset, self.terms.value, self.script_pubkey(state));
		let seq = Sequence(self.exit_delay.to_sequence());
		let mut u = assemble(LockTime::ZERO, vec![(coin, spent, seq)], &self.settle_outputs(asset, state), fee,
			crate::spend::FEE_COIN_SEQUENCE)?;
		u.tx.input[0].witness.script_witness = self.settle_witness(state);
		Ok(u)
	}

	/// The claim of note `c`, signed `note`, against `coin`, a credit output of
	/// `state` holding `value_in`: the owner's share at output 0, the rest at
	/// output 1 unless it is zero; a fee coin pays.
	pub fn claim_tx(&self, coin: OutPoint, asset: AssetId, state: &State, value_in: u64, c: u64, note: &Signature,
		fee: &FeeSource) -> Result<UnrollTx, SpendError>
	{
		let (delta, rest) = self.claim_amounts(state, c, value_in).map_err(SpendError::Channel)?;
		let tap = self.credit_taproot(state);
		let spent = explicit_txout(asset, value_in, tap.script_pubkey());
		let mut outs = vec![ExplicitOutput::new(asset, delta, owner_script_pubkey(&self.owner))];
		if rest > 0 {
			outs.push(ExplicitOutput::new(asset, rest, tap.script_pubkey()));
		}
		let mut u = assemble(LockTime::ZERO, vec![(coin, spent, FINAL)], &outs, fee, FINAL)?;
		u.tx.input[0].witness.script_witness = self.claim_witness(state, note, c);
		Ok(u)
	}

	/// The operator's spend of `coin`, a credit output of `state` holding
	/// `value`, once the window has passed: waiting for its signature
	/// ([`KeySpend::sighash`]).
	pub fn provider_tx(&self, coin: OutPoint, asset: AssetId, state: &State, value: u64, outputs: &[ExplicitOutput],
		fee: &FeeSource) -> Result<KeySpend, SpendError>
	{
		let tap = self.credit_taproot(state);
		let spent = explicit_txout(asset, value, tap.script_pubkey());
		KeySpend::build(tap, self.provider_script(), vec![(coin, spent, Sequence(self.terms.window.to_sequence()))],
			outputs, fee)
	}
}

/// Where a settle and a claim pay the owner: `OP_1 <A>`, a key-path output of
/// the leaf's own key, which the owner spends with that key's signature.
pub fn owner_script_pubkey(owner: &XOnlyPublicKey) -> Script {
	Builder::new().push_int(1).push_slice(&owner.serialize()).into_script()
}

/// The output at `index` (on the stack) is in this input's asset.
fn same_asset_at(b: Builder) -> Builder {
	b.ops(&[OP_INSPECTOUTPUTASSET, OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTASSET, OP_ROT, OP_EQUALVERIFY, OP_EQUALVERIFY])
}

/// The output at this input's index keeps the input's value and asset.
fn keep_at_current(b: Builder) -> Builder {
	b.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTVALUE, OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTVALUE,
			OP_ROT, OP_EQUALVERIFY, OP_EQUALVERIFY])
		.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTASSET, OP_PUSHCURRENTINPUTINDEX, OP_INSPECTINPUTASSET,
			OP_ROT, OP_EQUALVERIFY, OP_EQUAL])
}

#[cfg(test)]
mod test {
	use super::*;
	use elements::hashes::Hash;

	fn policy(value: u64, capacity: u64) -> ChannelPolicy {
		let key = |b: u8| elements::secp256k1_zkp::Keypair::from_seckey_slice(crate::taptree::secp(), &[b; 32]).unwrap()
			.x_only_public_key().0;
		ChannelPolicy {
			owner: key(1), operator: key(2), salt: [7; 32],
			chain: Chain::new(elements::BlockHash::from_byte_array([9; 32])),
			exit_delay: RelativeTime::from_units(254).unwrap(),
			terms: ChannelTerms { value, capacity, window: RelativeTime::from_units(300).unwrap() },
		}
	}

	#[test]
	fn the_claim_pays_the_cap_less_what_was_paid() {
		let p = policy(100, 40);
		// state 3: owner 65, operator 35, 20 folded; B = 55, the output holds 35, so 20 is paid
		let s = State { number: 3, owner: 65, operator: 35, folded: 20 };
		assert_eq!(p.claim_amounts(&s, 30, 35), Ok((10, 25)));
		assert_eq!(p.claim_amounts(&s, 55, 35), Ok((35, 0)));
		assert_eq!(p.claim_amounts(&s, 90, 35), Ok((35, 0)), "capped at B");
		assert_eq!(p.claim_amounts(&s, 20, 35), Err(ChannelError::NothingToClaim { note: 20, paid: 20 }));
		assert_eq!(p.claim_amounts(&s, 30, 25), Err(ChannelError::NothingToClaim { note: 30, paid: 30 }));
		assert!(matches!(p.claim_amounts(&s, 30, 56), Err(ChannelError::CreditValue { .. })));
	}

	#[test]
	fn a_stale_state_never_pays_the_owner_less_than_the_latest() {
		// From 60/40, the owner pays and folds credit in every order; the
		// operator signs a note c <= B of the latest. Settling any earlier
		// state with that note pays the owner at least the latest's take.
		let p = policy(100, 40);
		let mut states = vec![p.opening()];
		let mut note = 0;
		for (pay, credit) in [(10, 0), (0, 15), (5, 0), (0, 30), (20, 10), (0, 40)] {
			let last = *states.last().unwrap();
			let next = last.pay(pay, last.folded).unwrap();
			// the operator signs a note only within the latest state's cap
			let credit = credit.min(next.credit_cap() - note);
			note += credit;
			states.push(next);
			if credit > 0 {
				// fold it in the next state
				let f = next.pay(0, note).unwrap();
				states.push(f);
			}
		}
		let latest = *states.last().unwrap();
		let take = |s: &State| s.owner + p.claim_amounts(s, note, s.operator).map(|(d, _)| d).unwrap_or(0);
		for s in &states {
			p.terms.check_state(s).unwrap();
			assert!(take(s) >= take(&latest), "state {} pays {} < {}", s.number, take(s), take(&latest));
		}
	}

	#[test]
	fn terms_are_checked() {
		let delay = RelativeTime::from_units(254).unwrap();
		let t = |c, w| ChannelTerms { value: 100, capacity: c, window: RelativeTime::from_units(w).unwrap() };
		assert!(t(99, 254).check(delay).is_ok());
		assert!(matches!(t(100, 254).check(delay), Err(ChannelError::Capacity { .. })));
		assert!(matches!(t(10, 253).check(delay), Err(ChannelError::Window { .. })));
		let p = policy(100, 40);
		assert!(p.state_message(&State { number: 1, owner: 50, operator: 51, folded: 0 }).is_err());
		assert!(p.state_message(&State { number: 1, owner: 50, operator: 50, folded: 0 }).is_ok());
	}
}
