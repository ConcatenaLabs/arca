//! The leaf: a per-user output at the bottom of the tree.
//!
//! Two script leaves and no operator path. The leaf (`vtxo-1`) is spent by
//! owner and operator together, or by the owner alone after the exit delay:
//!
//! ```text
//! collab:  <A> and <S>, each a rebindable signature over the coin spent and the outputs they authorise
//! exit:    <delay> OP_CHECKSEQUENCEVERIFY OP_DROP <A> OP_CHECKSIG
//! ```
//!
//! The collaborative path verifies both signatures with
//! `OP_CHECKSIGFROMSTACK` over a message the script builds from the coin being
//! spent and outputs `0..m-1` ([`crate::message::rebind_message`]), so a pair
//! made before the tree is unrolled stays valid whatever outpoint the leaf ends
//! up at. One script serves every `m` from 1 to 4:
//!
//! ```text
//! # witness, bottom to top: <sig_S> <sig_A> <m>
//! OP_SIZE OP_1 OP_EQUALVERIFY OP_DUP OP_1 OP_5 OP_WITHIN OP_VERIFY
//! OP_DUP <K> <this input's asset and value> OP_CAT OP_SWAP OP_CAT OP_SWAP
//! <record 0> OP_SHA256 OP_ROT OP_SWAP OP_CAT OP_SWAP
//! { OP_DUP <j> OP_GREATERTHAN OP_IF <record j> OP_SHA256 OP_ROT OP_SWAP OP_CAT OP_SWAP OP_ENDIF }  # j = 1, 2, 3
//! OP_DROP OP_SHA256 OP_TUCK <A> OP_CHECKSIGFROMSTACKVERIFY <S> OP_CHECKSIGFROMSTACK
//! ```
//!
//! A pair is valid for every output that carries the leaf's script with the
//! same asset and amount, so the salt is unique to each leaf instance and a
//! leaf script is never funded twice. The salt has two contributions
//! ([`leaf_salt`]): `SHA256("Arca/salt" ‖ owner_nonce ‖ creator_nonce)`. The
//! owner's wallet picks its nonce fresh for every leaf it asks for, or
//! publishes it in a receive request; the leaf's creator adds the second. In
//! a round, and for a board, the creator is the operator. In a reassignment
//! it is the sender, whose wallet draws a fresh random nonce for every leaf it
//! creates, so that two reassignments paying one receive request still create
//! two different leaves and never commit to the same output
//! ([`crate::transfer`]). A wallet that never repeats a nonce is never given
//! the same leaf script twice, and neither is a creator that never repeats its
//! own. The script itself takes the salt as an opaque 32 bytes.
//!
//! An `htlc-1` leaf ([`crate::htlc`]) has the same collaborative path and, in
//! place of the exit, a claim with a preimage and a refund after a timeout,
//! each behind a relative delay: `[collab, [claim, refund]]`. Its owner's
//! delay is the exit delay; the operator's is in its [`HtlcTerms`].
//!
//! A `landing-1` leaf ([`crate::landing`]), the leaf of a supervised asset,
//! has the exit replaced by the landing, which pays only P2WPKH of the
//! owner's landing key, where a freeze of the asset binds; its collaborative
//! constant also commits to that key's program: `[collab, landing]`.
//!
//! A `channel-1` leaf ([`crate::channel`]) holds a balance for each of owner
//! and operator: it is the output of the channel's state 0,
//! `[collab, [update(0), settle(0)]]`, its collaborative path this very one.

use elements::opcodes::all::*;
use elements::script::Builder;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, Script};

use crate::channel::{ChannelPolicy, ChannelTerms};
use crate::htlc::{HtlcPath, HtlcTerms};
use crate::landing::LandingTerms;
use crate::message::{rebind_message, Chain, CsfsMessage};
use crate::script::{BuilderExt, ExplicitOutput};
use crate::order::{order_cmr, OrderLeafTerms, OrderPolicy};
use crate::taptree::{TapNode, TapOutput};
use crate::time::RelativeTime;
use crate::Error;

/// The most outputs a rebindable two-party spend commits to.
pub const MAX_OUTPUTS: u8 = 4;

/// The prefix of a leaf's salt.
pub const SALT_TAG: &[u8; 9] = b"Arca/salt";

/// A leaf's salt: `SHA256("Arca/salt" ‖ owner_nonce ‖ creator_nonce)`. The
/// creator's nonce is the operator's for a leaf of a round or a board, and the
/// sender's for a leaf a reassignment creates.
pub fn leaf_salt(owner_nonce: &[u8; 32], creator_nonce: &[u8; 32]) -> [u8; 32] {
	let mut b = Vec::with_capacity(SALT_TAG.len() + 64);
	b.extend(SALT_TAG);
	b.extend(owner_nonce);
	b.extend(creator_nonce);
	crate::script::sha256(&b)
}

/// The rebindable two-party script for the constant `k` (`K`, or a
/// `landing-1` leaf's `K ‖ P`), shared by the leaf and the checkpoint.
pub(crate) fn rebindable_two_party(owner: &XOnlyPublicKey, operator: &XOnlyPublicKey, k: &[u8]) -> Script {
	let slot = |b: Builder, j: i64| b.output_record(j).ops(&[OP_SHA256, OP_ROT, OP_SWAP, OP_CAT, OP_SWAP]);
	let mut b = Builder::new()
		.push_opcode(OP_SIZE).push_int(1).push_opcode(OP_EQUALVERIFY)
		.push_opcode(OP_DUP).push_int(1).push_int(MAX_OUTPUTS as i64 + 1).ops(&[OP_WITHIN, OP_VERIFY])
		.push_opcode(OP_DUP).push_slice(k).current_input_record().ops(&[OP_CAT, OP_SWAP, OP_CAT, OP_SWAP]);
	b = slot(b, 0);
	for j in 1..MAX_OUTPUTS as i64 {
		b = b.push_opcode(OP_DUP).push_int(j).ops(&[OP_GREATERTHAN, OP_IF]);
		b = slot(b, j).push_opcode(OP_ENDIF);
	}
	b.ops(&[OP_DROP, OP_SHA256]).two_party_csfs(owner, operator).into_script()
}

/// `OP_TUCK <A> OP_CHECKSIGFROMSTACKVERIFY <S> OP_CHECKSIGFROMSTACK`: both
/// signatures over the digest on top, `sig_S` below `sig_A`.
pub(crate) trait TwoPartyCsfs {
	fn two_party_csfs(self, owner: &XOnlyPublicKey, operator: &XOnlyPublicKey) -> Self;
}

impl TwoPartyCsfs for Builder {
	fn two_party_csfs(self, owner: &XOnlyPublicKey, operator: &XOnlyPublicKey) -> Builder {
		self.push_opcode(OP_TUCK).push_slice(&owner.serialize()).push_opcode(OP_CHECKSIGFROMSTACKVERIFY)
			.push_slice(&operator.serialize()).push_opcode(OP_CHECKSIGFROMSTACK)
	}
}

/// The message both parties sign for a rebindable two-party spend.
pub(crate) fn two_party_message(
	k: &[u8],
	asset_in: AssetId,
	value_in: u64,
	outputs: &[ExplicitOutput],
) -> Result<CsfsMessage, Error> {
	if outputs.is_empty() || outputs.len() > MAX_OUTPUTS as usize {
		return Err(Error::OutputCount(outputs.len()));
	}
	rebind_message(k, asset_in, value_in, outputs)
}

/// The witness items below a rebindable two-party script.
pub(crate) fn two_party_items(operator_sig: &Signature, owner_sig: &Signature, m: u8) -> Vec<Vec<u8>> {
	vec![operator_sig.as_ref().to_vec(), owner_sig.as_ref().to_vec(), vec![m]]
}

/// A leaf's policy: `vtxo-1`, or `htlc-1` when it carries [`HtlcTerms`],
/// `order-2` when it carries [`OrderLeafTerms`], `landing-1` when it carries
/// [`LandingTerms`], `channel-1` when it carries [`ChannelTerms`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeafPolicy {
	/// The owner's key `A`.
	pub owner: XOnlyPublicKey,
	/// The operator's key `S`.
	pub operator: XOnlyPublicKey,
	/// Unique to this leaf instance.
	pub salt: [u8; 32],
	pub chain: Chain,
	/// The owner's delay: its exit, or for `htlc-1` its own unilateral path
	/// (the refund out of the tree, the claim into it).
	pub exit_delay: RelativeTime,
	/// `htlc-1`'s hash-locked pair, in place of the exit; `None` for `vtxo-1`.
	pub htlc: Option<HtlcTerms>,
	/// `order-2`'s terms: the leaf is a resting order ([`crate::order`]),
	/// with the landing and the fill in place of the exit; `None` otherwise.
	pub order: Option<OrderLeafTerms>,
	/// `landing-1`'s terms: the exit pays only P2WPKH of the owner's landing
	/// key ([`crate::landing`]); `None` otherwise.
	pub landing: Option<LandingTerms>,
	/// `channel-1`'s terms: the leaf is the output of the channel's state 0
	/// ([`crate::channel`]); `None` otherwise.
	pub channel: Option<ChannelTerms>,
}

impl LeafPolicy {
	/// `K` for this leaf, over its salt.
	pub fn leaf_constant(&self) -> [u8; 32] {
		self.chain.leaf_constant(&self.salt)
	}

	/// What the collaborative script pushes and its message starts with:
	/// `K`, or for `landing-1` `K ‖ P` ([`Chain::landing_prefix`]).
	pub fn collab_prefix(&self) -> Vec<u8> {
		match &self.landing {
			Some(l) => self.chain.landing_prefix(&self.salt, &l.program),
			None => self.leaf_constant().to_vec(),
		}
	}

	pub fn collab_script(&self) -> Script {
		rebindable_two_party(&self.owner, &self.operator, &self.collab_prefix())
	}

	/// The exit of a `vtxo-1` leaf, or the landing of a `landing-1` leaf. An
	/// `htlc-1` leaf has none: its tree does not carry this script.
	pub fn exit_script(&self) -> Script {
		match &self.landing {
			Some(l) => l.script(&self.owner, self.exit_delay),
			None => exit_script(&self.owner, self.exit_delay),
		}
	}

	/// The claim of an `htlc-1` leaf.
	pub fn claim_script(&self) -> Result<Script, Error> {
		let t = self.htlc.ok_or(Error::NotAnHtlc("claim"))?;
		Ok(t.claim_script(&self.owner, &self.operator, self.exit_delay))
	}

	/// The refund of an `htlc-1` leaf.
	pub fn refund_script(&self) -> Result<Script, Error> {
		let t = self.htlc.ok_or(Error::NotAnHtlc("refund"))?;
		Ok(t.refund_script(&self.owner, &self.operator, self.exit_delay))
	}

	/// The script of an `htlc-1` path.
	pub fn htlc_script(&self, path: HtlcPath) -> Result<Script, Error> {
		match path {
			HtlcPath::Collab => Ok(self.collab_script()),
			HtlcPath::Claim => self.claim_script(),
			HtlcPath::Refund => self.refund_script(),
		}
	}

	/// `vtxo-1`: `[collab, exit]`, both at depth 1; `landing-1`: `[collab,
	/// landing]`, the same. `htlc-1`: `[collab, [claim, refund]]`. `order-2`:
	/// `[[collab, land], [fill, data]]` ([`crate::order`]). `channel-1`:
	/// `[collab, [update(0), settle(0)]]` ([`crate::channel`]).
	pub fn taproot(&self) -> TapOutput {
		if let Some(c) = self.channel_policy() {
			return c.taproot(&c.opening());
		}
		if let Some(o) = self.order_policy() {
			return TapOutput::with_nodes(vec![
				(2, TapNode::Tapscript(o.collab_script())),
				(2, TapNode::Tapscript(o.landing_script())),
				(2, TapNode::Simplicity(order_cmr())),
				(2, TapNode::Hidden(o.data_leaf())),
			]);
		}
		match self.htlc {
			None => TapOutput::new(vec![(1, self.collab_script()), (1, self.exit_script())]),
			Some(t) => TapOutput::new(vec![
				(1, self.collab_script()),
				(2, t.claim_script(&self.owner, &self.operator, self.exit_delay)),
				(2, t.refund_script(&self.owner, &self.operator, self.exit_delay)),
			]),
		}
	}

	/// The template it follows: `vtxo-1`, `htlc-1`, `order-2`, `landing-1`
	/// or `channel-1`.
	pub fn template(&self) -> crate::Template {
		if self.channel.is_some() {
			crate::Template::Channel1
		} else if self.order.is_some() {
			crate::Template::Order2
		} else if self.landing.is_some() {
			crate::Template::Landing1
		} else if self.htlc.is_some() {
			crate::Template::Htlc1
		} else {
			crate::Template::Vtxo1
		}
	}

	/// The channel a `channel-1` leaf opens; `None` for any other template.
	pub fn channel_policy(&self) -> Option<ChannelPolicy> {
		self.channel.map(|terms| ChannelPolicy {
			owner: self.owner, operator: self.operator, salt: self.salt, chain: self.chain, exit_delay: self.exit_delay, terms,
		})
	}

	/// The order an `order-2` leaf rests as; `None` for any other template.
	pub fn order_policy(&self) -> Option<OrderPolicy> {
		self.order.map(|t| t.policy(self.owner, self.operator, self.salt, self.chain, self.exit_delay))
	}

	pub fn script_pubkey(&self) -> Script {
		self.taproot().script_pubkey()
	}

	pub fn program(&self) -> [u8; 32] {
		self.taproot().program()
	}

	/// The message owner and operator sign to spend a coin of this leaf,
	/// holding `value_in` of `asset_in`, into `outputs` at indices `0..m`.
	pub fn collab_message(&self, asset_in: AssetId, value_in: u64, outputs: &[ExplicitOutput]) -> Result<CsfsMessage, Error> {
		two_party_message(&self.collab_prefix(), asset_in, value_in, outputs)
	}

	/// The full collaborative witness for `m` committed outputs.
	pub fn collab_witness(&self, operator_sig: &Signature, owner_sig: &Signature, m: u8) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.collab_script(), two_party_items(operator_sig, owner_sig, m))
	}

	/// The full exit witness: the owner's signature over the exit claim, a
	/// version 2 transaction whose input sequence is the exit delay. For a
	/// `landing-1` leaf it is the landing's witness.
	pub fn exit_witness(&self, owner_sig: &Signature) -> Vec<Vec<u8>> {
		self.taproot().witness(&self.exit_script(), vec![owner_sig.as_ref().to_vec()])
	}

	/// The full claim witness of an `htlc-1` leaf: the claimer's signature
	/// and the preimage, over a version 2 transaction whose input sequence is
	/// the claim's delay.
	pub fn claim_witness(&self, sig: &Signature, preimage: &[u8; 32]) -> Result<Vec<Vec<u8>>, Error> {
		Ok(self.taproot().witness(&self.claim_script()?, HtlcTerms::claim_items(sig, preimage)))
	}

	/// The full refund witness of an `htlc-1` leaf: the refunder's signature
	/// over a version 2 transaction whose lock time is at least the timeout
	/// and whose input sequence is the refund's delay.
	pub fn refund_witness(&self, sig: &Signature) -> Result<Vec<Vec<u8>>, Error> {
		Ok(self.taproot().witness(&self.refund_script()?, vec![sig.as_ref().to_vec()]))
	}
}

/// `<delay> OP_CHECKSEQUENCEVERIFY OP_DROP <key> OP_CHECKSIG`: the leaf's exit
/// and the forfeit's refund.
pub(crate) fn exit_script(key: &XOnlyPublicKey, delay: RelativeTime) -> Script {
	Builder::new().push_int(delay.to_sequence() as i64).ops(&[OP_CSV, OP_DROP])
		.push_slice(&key.serialize()).push_opcode(OP_CHECKSIG).into_script()
}
