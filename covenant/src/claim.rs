//! Claim trees: one round paying many holders, each under a key a payer
//! names.
//!
//! A payer names each holder by a 32-byte x-only key `A`: an address key the
//! holder already has (the x coordinate of a P2WPKH address's public key, or a
//! taproot address's output key, which is its program), or any key the holder
//! hands it. For each holder the payer draws a fresh 32-byte nonce `n`, and the
//! holder's leaf, an ordinary `vtxo-1` leaf, is owned by the claim key
//!
//! ```text
//! A' = lift_x(A) + t·G,   t = SHA256(T ‖ T ‖ A ‖ n),   T = SHA256("Arca/claim-key")
//! ```
//!
//! which the holder signs for with its secret for `A` plus `t`, as a taproot
//! output key is signed for, its parity handled as BIP340 handles it
//! ([`claim_key`], [`claim_keypair`]). `n` is the leaf's owner nonce too, so it
//! goes into the leaf's salt with the operator's nonce, as every leaf's does.
//!
//! The claim key is a key of its own for every claim: the same address can be
//! paid by any number of distributions while a leaf key never signs for
//! another leaf, the holder's address key itself signs nothing of the tree,
//! and since the server derives `A'` from `A` and `n` itself, naming a key
//! takes no key a wallet uses for its own leaves. The tweak hides nothing: the
//! published tree carries each leaf's owner key and owner nonce, so anyone who
//! knows an address key can test whether a claim was paid to it, as anyone can
//! see an on-chain payment to that address.
//!
//! A distribution ([`Distribution`]) is what the payer submits: the coins it
//! gives up, the asset, the claims, the script the unclaimed sum goes back to,
//! the fee and, for claims that lapse, the deadline. Its id
//! ([`Distribution::id`]) is what each coin's owner attests.
//!
//! # The claim leaf that lapses: `claim-1`
//!
//! A distribution with a deadline `D` ([`DistributionLapse`]) pays each holder
//! a `claim-1` leaf: `vtxo-1`'s collaborative path and exit under the claim
//! key, and a third path, LAPSE, which pays the payer back what its holder did
//! not take up by `D`, as a cheque lapses. The leaf never expires, so without
//! it a claim nobody takes up would stay its absent holder's for good:
//!
//! ```text
//! collab:  the leaf's collaborative path, vtxo-1's under the leaf's salt
//! exit:    <delay> OP_CHECKSEQUENCEVERIFY OP_DROP <A'> OP_CHECKSIG
//! lapse:   <D> OP_CHECKLOCKTIMEVERIFY OP_DROP <delay> OP_CHECKSEQUENCEVERIFY OP_DROP
//!          OP_PUSHCURRENTINPUTINDEX OP_INSPECTOUTPUTSCRIPTPUBKEY OP_2 OP_ADD OP_CAT OP_SHA256 <pin> OP_EQUALVERIFY
//!          OP_PUSHCURRENTINPUTINDEX OP_INSPECTOUTPUTASSET OP_1 OP_EQUALVERIFY <asset> OP_EQUALVERIFY
//!          OP_PUSHCURRENTINPUTINDEX OP_INSPECTOUTPUTVALUE OP_1 OP_EQUALVERIFY <min, u64 LE> OP_GREATERTHANOREQUAL64
//! ```
//!
//! as `[collab, [exit, lapse]]`. `pin` is `SHA256(program ‖ version + 2)` of
//! the return script, the script part of the injective output record
//! ([`script_pin`]), so any script can be the return; `min` is the leaf's value
//! less the fee allowance. The lapse needs no signature: once the median time
//! has passed `D` and the leaf has waited its exit delay on the chain, anyone
//! may spend it, and it can only pay the return script, at the input's own
//! index, explicitly in the leaf's asset. The payer, the operator's watcher or
//! a stranger who brings an unclaimed leaf on the chain lapses it alike, and
//! whatever of the allowance the fee leaves goes where the lapser says.
//!
//! - **Its own index.** Each lapse pins the output at its own input's index,
//!   so two claim leaves of one distribution, with one return script and one
//!   minimum, lapse in one transaction to two outputs, and one output never
//!   stands for both.
//! - **The exit delay, again.** The lapse waits the exit delay after the leaf
//!   confirms, as the exit does. A holder who took its claim up holds a coin
//!   resting on the leaf (its pair co-signed before `D`); if the leaf reaches
//!   the chain after `D`, that holder has the exit delay to answer with its
//!   pair, as it answers an exit, and nothing a holder holds is lapsed at once.
//! - **The holder's race.** A holder's exit and the lapse both wait the exit
//!   delay from the leaf's confirmation, and the lapse also waits for `D`. A
//!   holder who brings its leaf on the chain at least an exit delay before `D`
//!   exits before the lapse opens; later than that, both open together and the
//!   first to confirm takes the coin. A wallet takes its claims up well before
//!   `D` instead, which needs no chain at all.
//! - **What it authorises.** Nothing signs the lapse, so an annex or a fee coin
//!   anyone attaches changes nothing it pins. Its output is the return script
//!   only, in the leaf's asset only, so no lapse moves another coin, another
//!   leaf's value or another asset; a leaf exists on one chain, so no lapse
//!   runs on another. The collaborative path is `vtxo-1`'s under the leaf's
//!   own salt, so a pair for this leaf is valid for no other.
//! - **Fees.** The allowance pays the fee in the leaf's asset where the node
//!   takes it. Where it does not (the asset delisted), a coin of any accepted
//!   asset pays the fee and the return gets the whole value ([`LeafPolicy::lapse_tx`]).

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::{Keypair, Scalar, XOnlyPublicKey};
use elements::{AssetId, Script};

use elements::opcodes::all::*;
use elements::script::Builder;

use crate::message::Chain;
use crate::record::LeafId;
use crate::script::{asset_bytes as script_asset_bytes, BuilderExt, ExplicitOutput};
use crate::taptree::secp;
use crate::time::{MedianTime, RelativeTime};
#[allow(unused_imports)]
use crate::LeafPolicy;

/// The tag of a claim key's tweak.
pub const CLAIM_KEY_TAG: &[u8] = b"Arca/claim-key";

/// The tag of a distribution's id.
pub const DISTRIBUTION_TAG: &[u8] = b"Arca/distribution";

/// The most claims one distribution names: what its id counts in two bytes.
/// A server takes no more than one batch holds.
pub const MAX_CLAIMS: usize = u16::MAX as usize;

/// The most coins one distribution gives up.
pub const MAX_INPUTS: usize = 16;

/// The most bytes of a distribution's return script.
pub const MAX_RETURN_SCRIPT: usize = 10_000;

/// Why a claim key or a distribution cannot be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClaimError {
	#[error("the tweak of key {0} by its nonce is no scalar, or makes no key: draw another nonce")]
	Tweak(XOnlyPublicKey),
	#[error("the key pair given is for {given}, not the named key {named}")]
	NotTheNamedKey { named: XOnlyPublicKey, given: XOnlyPublicKey },
	#[error("a distribution names {0} claims; it names 1 to {max}", max = MAX_CLAIMS)]
	ClaimCount(usize),
	#[error("a distribution gives up {0} coins; it gives up 1 to {max}", max = MAX_INPUTS)]
	InputCount(usize),
	#[error("key {0} is named twice: a distribution pays each named key once")]
	NamedTwice(XOnlyPublicKey),
	#[error("claim {0} holds nothing")]
	Empty(usize),
	#[error("the return script has {0} bytes; it has 1 to {max}", max = MAX_RETURN_SCRIPT)]
	ReturnScript(usize),
	#[error("the fees name {0} assets, or one twice")]
	Fees(usize),
	#[error("claim {index} holds {value}, not above the lapse's fee allowance of {allowance}")]
	LapseAllowance { index: usize, value: u64, allowance: u64 },
}

/// Why a claim leaf's lapse cannot be built or does not fit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LapseError {
	#[error("a claim-1 leaf's allowance of {allowance} is not below its value of {value}: its lapse would hold nothing")]
	Allowance { allowance: u64, value: u64 },
	#[error("a claim-1 leaf's return script has {0} bytes; it has 1 to {max}", max = MAX_RETURN_SCRIPT)]
	ReturnScript(usize),
	#[error("the lapse's output at its input's index is not the return script, explicitly in the leaf's asset, holding at least {min}")]
	Output { min: u64 },
}

/// `SHA256(program ‖ version + 2)` of `script_pubkey`: the script part of the
/// injective output record ([`crate::script::record`]), the program being
/// `SHA256(script_pubkey)` and the version -1 for a script that is no witness
/// program. What a lapse pins of its return script.
pub fn script_pin(script_pubkey: &Script) -> [u8; 32] {
	let record = crate::script::record(AssetId::from_slice(&[0; 32]).expect("32 bytes"), 0, script_pubkey);
	crate::script::sha256(&record[42..])
}

/// A `claim-1` leaf's lapse, as its record keeps it: the deadline, the fee
/// allowance and the return script.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Lapse {
	/// `D`: the lapse waits for the chain's median time to pass it.
	pub deadline: MedianTime,
	/// How much of the leaf's value the lapse may leave out of its output:
	/// below the value.
	pub allowance: u64,
	/// The distribution's return script, the payer's.
	pub return_script: Script,
}

impl Lapse {
	/// The terms a leaf of `value` of `asset` lapses by.
	pub fn terms(&self, asset: AssetId, value: u64) -> Result<LapseTerms, LapseError> {
		if self.return_script.is_empty() || self.return_script.len() > MAX_RETURN_SCRIPT {
			return Err(LapseError::ReturnScript(self.return_script.len()));
		}
		if self.allowance >= value {
			return Err(LapseError::Allowance { allowance: self.allowance, value });
		}
		Ok(LapseTerms { deadline: self.deadline, pin: script_pin(&self.return_script), asset, min_value: value - self.allowance })
	}
}

/// What a `claim-1` leaf's lapse script checks: the deadline, and where the
/// output at its own index pays, in what, and at least how much.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LapseTerms {
	/// `D`, a median time.
	pub deadline: MedianTime,
	/// [`script_pin`] of the return script.
	pub pin: [u8; 32],
	/// The leaf's asset.
	pub asset: AssetId,
	/// The least the lapse's output holds: the leaf's value less the
	/// allowance.
	pub min_value: u64,
}

impl LapseTerms {
	/// The lapse script, its relative lock the leaf's exit delay.
	pub fn script(&self, delay: RelativeTime) -> Script {
		Builder::new()
			.push_int(self.deadline.to_consensus_u32() as i64).ops(&[OP_CLTV, OP_DROP])
			.push_int(delay.to_sequence() as i64).ops(&[OP_CSV, OP_DROP])
			.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTSCRIPTPUBKEY]).push_int(2).ops(&[OP_ADD, OP_CAT, OP_SHA256])
			.push_slice(&self.pin).push_opcode(OP_EQUALVERIFY)
			.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTASSET]).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&script_asset_bytes(self.asset)).push_opcode(OP_EQUALVERIFY)
			.ops(&[OP_PUSHCURRENTINPUTINDEX, OP_INSPECTOUTPUTVALUE]).push_int(1).push_opcode(OP_EQUALVERIFY)
			.push_slice(&self.min_value.to_le_bytes()).push_opcode(OP_GREATERTHANOREQUAL64)
			.into_script()
	}

	/// Checks `output` as the lapse script will check the output at its
	/// input's index.
	pub fn check_output(&self, output: &ExplicitOutput) -> Result<(), LapseError> {
		if script_pin(&output.script_pubkey) != self.pin || output.asset != self.asset || output.value < self.min_value {
			return Err(LapseError::Output { min: self.min_value });
		}
		Ok(())
	}

	/// Whether a lapse can confirm at the chain's median time `now`: once
	/// `now` has passed `D` (a lock time of `D` is final then).
	pub fn open_at(&self, now: MedianTime) -> bool {
		now.to_consensus_u32() > self.deadline.to_consensus_u32()
	}
}

/// The virtual size a lapse is priced at: one claim leaf spent by its lapse
/// into the return script and the fee output, 215 vbytes as measured on a
/// regtest node (`regtest/t27_claim_lapse.py`), and a little over.
pub const LAPSE_VSIZE: usize = 220;

/// The allowance that pays a lapse's fee at `multiple` times the relay floor
/// `floor_per_kvb` (the asset's atoms per 1,000 vbytes); nothing where the
/// node takes no fee in the asset (`None`), whose lapse a coin attached
/// pays. A payer's wallet names four times its node's floor; a server takes
/// no allowance below one time its own.
pub fn lapse_allowance(floor_per_kvb: Option<u64>, multiple: u64) -> u64 {
	floor_per_kvb.map_or(0, |f| crate::spend::margin_for(LAPSE_VSIZE, f, multiple))
}

/// A distribution's lapse: the deadline after which what nobody took up of
/// it goes back to its return script, and the allowance each lapse may leave
/// out for its fee. Every claim leaf of such a distribution is `claim-1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DistributionLapse {
	pub deadline: MedianTime,
	pub allowance: u64,
}

/// `t = SHA256(T ‖ T ‖ A ‖ n)`, `T = SHA256("Arca/claim-key")`, as 32 bytes.
pub fn claim_tweak(named: &XOnlyPublicKey, nonce: &[u8; 32]) -> [u8; 32] {
	let tag = sha256::Hash::hash(CLAIM_KEY_TAG);
	let mut e = sha256::Hash::engine();
	e.input(tag.as_byte_array());
	e.input(tag.as_byte_array());
	e.input(&named.serialize());
	e.input(nonce);
	sha256::Hash::from_engine(e).to_byte_array()
}

fn tweak_scalar(named: &XOnlyPublicKey, nonce: &[u8; 32]) -> Result<Scalar, ClaimError> {
	Scalar::from_be_bytes(claim_tweak(named, nonce)).map_err(|_| ClaimError::Tweak(*named))
}

/// The claim key `A'` of the key `named` and the nonce `nonce`.
pub fn claim_key(named: &XOnlyPublicKey, nonce: &[u8; 32]) -> Result<XOnlyPublicKey, ClaimError> {
	let t = tweak_scalar(named, nonce)?;
	named.add_tweak(secp(), &t).map(|(k, _)| k).map_err(|_| ClaimError::Tweak(*named))
}

/// The key pair that signs for the claim key of `named`'s x-only key and
/// `nonce`: `named` plus the tweak, the parity of each handled as BIP340
/// handles it. `named` may be any key pair whose x-only key the payer named,
/// whatever the parity of its own point: an on-chain address key, or a
/// taproot output key already tweaked.
pub fn claim_keypair(named: &Keypair, nonce: &[u8; 32]) -> Result<Keypair, ClaimError> {
	let a = named.x_only_public_key().0;
	let t = tweak_scalar(&a, nonce)?;
	named.add_xonly_tweak(secp(), &t).map_err(|_| ClaimError::Tweak(a))
}

/// Whether `pair` signs for the claim key `owner` of `named` and `nonce`: the
/// check a wallet makes before it takes a claim leaf as its own.
pub fn is_claim_key(owner: &XOnlyPublicKey, named: &XOnlyPublicKey, nonce: &[u8; 32]) -> bool {
	claim_key(named, nonce).is_ok_and(|k| k == *owner)
}

/// The key a taproot script names: its 32-byte program, `OP_1 <program>`.
/// `None` for any other script: a P2WPKH script names only its key's hash,
/// so a payer names the key itself.
pub fn named_of_script(script_pubkey: &Script) -> Option<XOnlyPublicKey> {
	let b = script_pubkey.as_bytes();
	if b.len() == 34 && b[0] == 0x51 && b[1] == 0x20 {
		XOnlyPublicKey::from_slice(&b[2..]).ok()
	} else {
		None
	}
}

/// One holder of a distribution: the key the payer names, the nonce it draws
/// for the holder, and what the holder's leaf holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Claim {
	pub named: XOnlyPublicKey,
	pub nonce: [u8; 32],
	pub value: u64,
}

impl Claim {
	/// The claim leaf's owner key ([`claim_key`]).
	pub fn owner(&self) -> Result<XOnlyPublicKey, ClaimError> {
		claim_key(&self.named, &self.nonce)
	}
}

/// What a payer submits: the coins it gives up, all in `asset`, for one
/// `vtxo-1` leaf per claim, each with `exit_delay`, in the asset's next round;
/// `return_script`, where the operator pays what no holder takes up; the fee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distribution {
	pub inputs: Vec<LeafId>,
	pub asset: AssetId,
	pub exit_delay: RelativeTime,
	pub claims: Vec<Claim>,
	pub return_script: Script,
	pub fees: Vec<(AssetId, u64)>,
	/// The earliest median time of a round it may run in.
	pub not_before: Option<MedianTime>,
	/// The deadline its claims lapse at; `None` for claims that are plain
	/// `vtxo-1` leaves, which a batch's sweep returns.
	pub lapse: Option<DistributionLapse>,
}

fn asset_bytes(a: AssetId) -> [u8; 32] {
	a.into_inner().to_byte_array()
}

impl Distribution {
	/// The bounds every distribution keeps, before any server's: 1 to
	/// [`MAX_INPUTS`] coins, 1 to [`MAX_CLAIMS`] claims, each holding
	/// something, no key named twice, a return script of 1 to
	/// [`MAX_RETURN_SCRIPT`] bytes, and no asset twice among the fees.
	pub fn check(&self) -> Result<(), ClaimError> {
		if self.inputs.is_empty() || self.inputs.len() > MAX_INPUTS {
			return Err(ClaimError::InputCount(self.inputs.len()));
		}
		if self.claims.is_empty() || self.claims.len() > MAX_CLAIMS {
			return Err(ClaimError::ClaimCount(self.claims.len()));
		}
		let mut named = std::collections::BTreeSet::new();
		for (i, c) in self.claims.iter().enumerate() {
			if c.value == 0 {
				return Err(ClaimError::Empty(i));
			}
			if !named.insert(c.named.serialize()) {
				return Err(ClaimError::NamedTwice(c.named));
			}
		}
		if self.return_script.is_empty() || self.return_script.len() > MAX_RETURN_SCRIPT {
			return Err(ClaimError::ReturnScript(self.return_script.len()));
		}
		let fee_assets: std::collections::BTreeSet<[u8; 32]> = self.fees.iter().map(|f| asset_bytes(f.0)).collect();
		if self.fees.len() > u8::MAX as usize || fee_assets.len() != self.fees.len() {
			return Err(ClaimError::Fees(self.fees.len()));
		}
		if let Some(l) = &self.lapse {
			if let Some((index, c)) = self.claims.iter().enumerate().find(|(_, c)| c.value <= l.allowance) {
				return Err(ClaimError::LapseAllowance { index, value: c.value, allowance: l.allowance });
			}
		}
		Ok(())
	}

	/// The lapse every claim leaf's record keeps; `None` for a distribution
	/// without a deadline, whose claims are `vtxo-1` leaves.
	pub fn claim_lapse(&self) -> Option<Lapse> {
		self.lapse.map(|l| Lapse { deadline: l.deadline, allowance: l.allowance, return_script: self.return_script.clone() })
	}

	/// What the claims hold together.
	pub fn total(&self) -> u128 {
		self.claims.iter().map(|c| c.value as u128).sum()
	}

	/// The id each coin's owner attests:
	///
	/// ```text
	/// SHA256(T ‖ T ‖ genesis_hash ‖ S ‖ body),   T = SHA256("Arca/distribution")
	/// body = n_in (u16), each leaf id given up
	///      ‖ asset ‖ exit delay units (u16)
	///      ‖ n_claims (u16), each claim: named key ‖ nonce ‖ value (u64)
	///      ‖ return script length (u16) ‖ return script
	///      ‖ n_fees (u8), each fee: asset ‖ amount (u64)
	///      ‖ 0, or 1 and the earliest round time (u32)
	///      ‖ for a distribution with a deadline only: 1, the deadline (u32)
	///        and the lapse's fee allowance (u64)
	/// ```
	///
	/// Integers little-endian, asset ids in internal byte order. Its tag is its
	/// own, so no attestation of a distribution is one of a participation or a
	/// take; the genesis hash and `S` keep it to one chain and one operator. A
	/// distribution that fails [`Distribution::check`] has no id a server
	/// takes, whatever this returns.
	pub fn id(&self, chain: &Chain, operator: &XOnlyPublicKey) -> [u8; 32] {
		let tag = sha256::Hash::hash(DISTRIBUTION_TAG);
		let mut e = sha256::Hash::engine();
		e.input(tag.as_byte_array());
		e.input(tag.as_byte_array());
		e.input(&chain.genesis_bytes());
		e.input(&operator.serialize());
		e.input(&(self.inputs.len() as u16).to_le_bytes());
		for i in &self.inputs {
			e.input(&i.0);
		}
		e.input(&asset_bytes(self.asset));
		e.input(&self.exit_delay.units().to_le_bytes());
		e.input(&(self.claims.len() as u16).to_le_bytes());
		for c in &self.claims {
			e.input(&c.named.serialize());
			e.input(&c.nonce);
			e.input(&c.value.to_le_bytes());
		}
		e.input(&(self.return_script.len() as u16).to_le_bytes());
		e.input(self.return_script.as_bytes());
		e.input(&[self.fees.len() as u8]);
		for (a, v) in &self.fees {
			e.input(&asset_bytes(*a));
			e.input(&v.to_le_bytes());
		}
		match self.not_before {
			Some(t) => {
				e.input(&[1]);
				e.input(&t.to_consensus_u32().to_le_bytes());
			},
			None => e.input(&[0]),
		}
		if let Some(l) = &self.lapse {
			e.input(&[1]);
			e.input(&l.deadline.to_consensus_u32().to_le_bytes());
			e.input(&l.allowance.to_le_bytes());
		}
		sha256::Hash::from_engine(e).to_byte_array()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::sign::{sign_digest, verify_digest};
	use elements::secp256k1_zkp::{Parity, SecretKey};

	fn pair(label: &str) -> Keypair {
		let s = SecretKey::from_slice(&sha256::Hash::hash(label.as_bytes()).to_byte_array()).unwrap();
		Keypair::from_secret_key(secp(), &s)
	}

	/// Key pairs whose own point has odd y and even y, as an address key may.
	fn of_parity(want: Parity) -> Keypair {
		(0..).map(|i| pair(&format!("address key {}", i))).find(|k| k.x_only_public_key().1 == want).unwrap()
	}

	#[test]
	fn the_claim_key_signs_with_the_named_key_plus_the_tweak_whatever_the_parity() {
		for parity in [Parity::Even, Parity::Odd] {
			let a = of_parity(parity);
			let named = a.x_only_public_key().0;
			for nonce in [[0u8; 32], [7; 32], [0xff; 32]] {
				let owner = claim_key(&named, &nonce).unwrap();
				let k = claim_keypair(&a, &nonce).unwrap();
				assert_eq!(k.x_only_public_key().0, owner, "the key pair signs for the published key");
				assert!(is_claim_key(&owner, &named, &nonce));
				let d = [0x5a; 32];
				let s = sign_digest(&k, &d, &[0; 32]);
				assert!(verify_digest(&s, &d, &owner));
				// The named key's own signature is not the claim key's.
				let wrong = sign_digest(&a, &d, &[0; 32]);
				assert!(!verify_digest(&wrong, &d, &owner));
				assert_ne!(owner, named);
			}
		}
	}

	#[test]
	fn the_claim_key_is_lift_x_of_the_named_key_plus_t_g() {
		// Independently of add_tweak: lift_x(A) is the even-y point, so a
		// secret for it is a or n - a; adding t gives the claim key's secret.
		let a = of_parity(Parity::Odd);
		let named = a.x_only_public_key().0;
		let nonce = [3u8; 32];
		let mut even_secret = a.secret_key();
		if a.x_only_public_key().1 == Parity::Odd {
			even_secret = even_secret.negate();
		}
		let t = Scalar::from_be_bytes(claim_tweak(&named, &nonce)).unwrap();
		let claim_secret = even_secret.add_tweak(&t).unwrap();
		let expect = Keypair::from_secret_key(secp(), &claim_secret).x_only_public_key().0;
		assert_eq!(claim_key(&named, &nonce).unwrap(), expect);
	}

	#[test]
	fn each_nonce_and_each_named_key_gives_a_key_of_its_own() {
		let a = pair("holder").x_only_public_key().0;
		let b = pair("another holder").x_only_public_key().0;
		let k = |named: &XOnlyPublicKey, n: u8| claim_key(named, &[n; 32]).unwrap();
		assert_ne!(k(&a, 1), k(&a, 2));
		assert_ne!(k(&a, 1), k(&b, 1));
		assert_eq!(k(&a, 1), k(&a, 1));
		assert!(!is_claim_key(&k(&a, 1), &a, &[2; 32]));
		assert!(!is_claim_key(&k(&a, 1), &b, &[1; 32]));
	}

	#[test]
	fn a_key_pair_for_another_key_signs_for_another_claim_key() {
		let a = pair("holder");
		let b = pair("payer");
		let named = a.x_only_public_key().0;
		let nonce = [9u8; 32];
		assert_ne!(claim_keypair(&b, &nonce).unwrap().x_only_public_key().0, claim_key(&named, &nonce).unwrap());
	}

	#[test]
	fn a_taproot_script_names_its_program_and_no_other_script_names_a_key() {
		let k = pair("taproot holder").x_only_public_key().0;
		let mut spk = vec![0x51, 0x20];
		spk.extend(k.serialize());
		assert_eq!(named_of_script(&Script::from(spk.clone())), Some(k));
		let mut wpkh = vec![0x00, 0x14];
		wpkh.extend([1u8; 20]);
		assert_eq!(named_of_script(&Script::from(wpkh)), None);
		spk[0] = 0x52;
		assert_eq!(named_of_script(&Script::from(spk)), None);
	}

	fn distribution() -> Distribution {
		Distribution {
			inputs: vec![LeafId([1; 32]), LeafId([2; 32])],
			asset: AssetId::from_slice(&[5; 32]).unwrap(),
			exit_delay: RelativeTime::from_units(254).unwrap(),
			claims: vec![
				Claim { named: pair("h1").x_only_public_key().0, nonce: [1; 32], value: 1_000 },
				Claim { named: pair("h2").x_only_public_key().0, nonce: [2; 32], value: 2_000 },
			],
			return_script: Script::from(vec![0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]),
			fees: vec![(AssetId::from_slice(&[5; 32]).unwrap(), 30)],
			not_before: None,
			lapse: None,
		}
	}

	#[test]
	fn the_id_commits_to_every_part() {
		let chain = Chain::new(elements::BlockHash::from_byte_array([0x11; 32]));
		let s = pair("operator").x_only_public_key().0;
		let d = distribution();
		assert!(d.check().is_ok());
		let id = d.id(&chain, &s);
		let mut seen = std::collections::BTreeSet::from([id]);
		let mut changed = |f: &dyn Fn(&mut Distribution)| {
			let mut x = distribution();
			f(&mut x);
			assert!(seen.insert(x.id(&chain, &s)), "a change left the id as it was");
		};
		changed(&|x| x.inputs.pop().map(|_| ()).unwrap());
		changed(&|x| x.inputs[0] = LeafId([3; 32]));
		changed(&|x| x.asset = AssetId::from_slice(&[6; 32]).unwrap());
		changed(&|x| x.exit_delay = RelativeTime::from_units(255).unwrap());
		changed(&|x| x.claims[0].value += 1);
		changed(&|x| x.claims[1].nonce = [3; 32]);
		changed(&|x| x.claims[1].named = pair("h3").x_only_public_key().0);
		changed(&|x| x.claims.swap(0, 1));
		changed(&|x| x.claims.pop().map(|_| ()).unwrap());
		changed(&|x| x.return_script = Script::from(vec![0x6a]));
		changed(&|x| x.fees[0].1 = 31);
		changed(&|x| x.fees.clear());
		changed(&|x| x.not_before = Some(MedianTime::from_consensus(1_800_000_000).unwrap()));
		let lapse = |t: u32, a: u64| Some(DistributionLapse { deadline: MedianTime::from_consensus(t).unwrap(), allowance: a });
		changed(&|x| x.lapse = lapse(1_800_000_000, 0));
		changed(&|x| x.lapse = lapse(1_800_000_001, 0));
		changed(&|x| x.lapse = lapse(1_800_000_000, 1));
		assert_ne!(d.id(&Chain::new(elements::BlockHash::from_byte_array([0x12; 32])), &s), id, "another chain");
		assert_ne!(d.id(&chain, &pair("another operator").x_only_public_key().0), id, "another operator");
	}

	#[test]
	fn a_distribution_keeps_its_bounds() {
		let mut d = distribution();
		d.claims[1].named = d.claims[0].named;
		assert_eq!(d.check(), Err(ClaimError::NamedTwice(d.claims[0].named)));
		let mut d = distribution();
		d.claims[0].value = 0;
		assert_eq!(d.check(), Err(ClaimError::Empty(0)));
		let mut d = distribution();
		d.inputs.clear();
		assert_eq!(d.check(), Err(ClaimError::InputCount(0)));
		let mut d = distribution();
		d.claims.clear();
		assert_eq!(d.check(), Err(ClaimError::ClaimCount(0)));
		let mut d = distribution();
		d.return_script = Script::new();
		assert_eq!(d.check(), Err(ClaimError::ReturnScript(0)));
		let mut d = distribution();
		d.fees.push(d.fees[0]);
		assert_eq!(d.check(), Err(ClaimError::Fees(2)));
		let mut d = distribution();
		d.lapse = Some(DistributionLapse { deadline: MedianTime::from_consensus(1_800_000_000).unwrap(), allowance: 1_000 });
		assert_eq!(d.check(), Err(ClaimError::LapseAllowance { index: 0, value: 1_000, allowance: 1_000 }));
		d.lapse = Some(DistributionLapse { deadline: MedianTime::from_consensus(1_800_000_000).unwrap(), allowance: 999 });
		assert!(d.check().is_ok());
	}
}
