//! Swept coins are repaid, never kept.
//!
//! A batch expires 28 days after its round, and after the public release and
//! the notice the operator sweeps whatever is left in it. A coin its holder
//! neither refreshed nor took home on the chain is taken by that sweep; the
//! operator owes it back. Expiry may delay a holder's coin and costs it the
//! published late-refresh fee, nothing more: the operator's policy, kept by
//! this server and published (`info.swept`), not a script, since a script
//! guarantee would need every abandoned leaf brought on the chain, which is
//! the cost expiry exists to avoid.
//!
//! **The record.** When a sweep of the watcher's is final, the watcher finds
//! every coin it took from its holder ([`crate::watcher`]): each leaf of the
//! swept batch whose value a final sweep took, and every coin resting on
//! one through out-of-round transfers, that is live (not given up in a
//! participation, forfeited, released, offboarded or spent), whose own
//! output is not on the chain, and that is its holder's outright (not an
//! `htlc-1` leaf, whose payment its own paths settle, and not a claim leaf of
//! a distribution nobody took up, which goes back to its payer). It records,
//! in one database transaction, an entry per coin: its owner key and the
//! nonce it comes from, its asset, its value (a channel coin's owner's side),
//! the late-refresh fee ([`late_fee`]) and the sweep. A rollback that takes
//! the sweep out of finality withdraws its entries until it is final again.
//! Entries never expire, and are kept as the rest of the state is kept.
//!
//! **The repayment.** The holder's wallet finds its entries (`owed`, proven
//! by its mailbox key) and claims each (`owed_claim`) with a signature of the
//! swept coin's owner key over [`claim_digest`], naming the one new leaf it
//! wants: in the coin's asset, holding exactly what is owed, under a fresh
//! key it proves it holds. The server records, with the claim, a
//! participation of its own making that gives up no coin and wants that
//! leaf, as it does for a payment received over Lightning; it runs in the
//! asset's next round, funded by the asset's pool (an issuer-operated asset's
//! by its mint, as its rounds are funded), and the wallet completes it as any
//! other, handing over its unroll authorisations with no forfeit. Its
//! preimage goes out only while the sweep is final. A participation that is
//! void or expires leaves the entry owed again, to be claimed anew. A second
//! claim of an entry is refused (`owed_claimed`), and so is a claim the coin's
//! owner key did not sign (`bad_signature`).
//!
//! The participation's id is an ordinary participation's
//! ([`crate::participations::participation_id`]) with no coin given up, one
//! leaf wanted and no fee, so the wallet computes it from the leaf it asks
//! for.

use elements::hashes::{sha256, Hash, HashEngine};
use elements::secp256k1_zkp::schnorr::Signature;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::AssetId;
use rand::RngCore;

use arca_covenant::sign::verify_digest;
use arca_covenant::{Chain, LeafId, Template};

use crate::params::{FeeSchedule, Params};
use crate::participations::{key_proof_digest, OutputRequest, ParticipationRequest};
use crate::store::{ClaimOutcome, NewParticipation, OwedState, ParticipationOutput, Store, StoreError, WantedKind};

/// The tag of the digest a swept coin's owner key signs to claim it.
pub const CLAIM_TAG: &[u8] = b"Arca/owed-claim";

/// What a swept coin's owner key signs to claim what is owed for it:
/// `SHA256(T ‖ T ‖ genesis ‖ S ‖ coin ‖ participation id)`,
/// `T = SHA256("Arca/owed-claim")`. It names the coin and the repayment
/// participation, whose id covers the one leaf wanted, so it claims that
/// coin into that leaf and nothing else, on one chain and from one
/// operator.
pub fn claim_digest(chain: &Chain, operator: &XOnlyPublicKey, coin: &LeafId, participation: &[u8; 32]) -> [u8; 32] {
	let t = sha256::Hash::hash(CLAIM_TAG);
	let mut e = sha256::Hash::engine();
	e.input(t.as_byte_array());
	e.input(t.as_byte_array());
	e.input(&chain.genesis_bytes());
	e.input(&operator.serialize());
	e.input(&coin.0);
	e.input(participation);
	sha256::Hash::from_engine(e).to_byte_array()
}

/// The late-refresh fee for a swept coin of `value`: the asset's refresh fee
/// at its full charge (its parts per million of the value, rounded up, and
/// its fixed part), the most a refresh made at any time costs. Never the
/// whole coin: at most its value less one atom.
pub fn late_fee(schedule: &FeeSchedule, value: u64) -> u64 {
	let fee = (value as u128 * schedule.refresh_ppm as u128).div_ceil(1_000_000) + schedule.refresh_base as u128;
	fee.min(value.saturating_sub(1) as u128) as u64
}

/// Why a claim was refused, or could not be handled.
#[derive(Debug, thiserror::Error)]
pub enum OwedError {
	#[error("no coin {0} is owed: a sweep that is final took no coin of that id from its holder")]
	Unknown(LeafId),
	#[error("coin {0} is owed once its sweep {1} is final again: a rollback took the sweep out of finality, and the coin is back in \
		its batch meanwhile")]
	Withdrawn(LeafId, String),
	#[error("coin {0} is {1} already{2}: an entry is repaid once")]
	Claimed(LeafId, &'static str, String),
	#[error("the claim is not signed by the swept coin's owner key over its claim digest")]
	BadSignature,
	#[error("the leaf wanted does not prove its key: its key proof is not the leaf key's over the participation's key-proof digest")]
	BadKeyProof,
	#[error("{0}")]
	OutOfBounds(String),
	#[error("the leaf wanted is a {0} leaf: a repayment is a vtxo-1 or vtxo-2 leaf, or landing-1 in a supervised asset")]
	Template(String),
	#[error("the key the leaf is wanted under owns a leaf, or is wanted already: every leaf has a key of its own")]
	KeyReused,
	#[error("the key the leaf is wanted under is the operator's")]
	OperatorKey,
	#[error(transparent)]
	Store(#[from] StoreError),
}

impl OwedError {
	pub fn code(&self) -> &'static str {
		match self {
			OwedError::Unknown(_) => "unknown_leaf",
			OwedError::Withdrawn(..) => "owed_withdrawn",
			OwedError::Claimed(..) => "owed_claimed",
			OwedError::BadSignature => "bad_signature",
			OwedError::BadKeyProof => "bad_attestation",
			OwedError::OutOfBounds(_) => "out_of_bounds",
			OwedError::Template(_) => "template",
			OwedError::KeyReused => "key_reused",
			OwedError::OperatorKey => "operator_key",
			OwedError::Store(_) => "internal",
		}
	}
}

/// A claim of what is owed for `coin`: the leaf wanted (an
/// [`OutputRequest::Leaf`]) with its key proof, and the coin's owner key's
/// signature over [`claim_digest`].
#[derive(Debug, Clone)]
pub struct ClaimRequest {
	pub coin: LeafId,
	pub leaf: OutputRequest,
	pub key_proof: Signature,
	pub signature: Signature,
}

/// The repayment participation's id for a claim wanting `leaf`.
pub fn repayment_id(chain: &Chain, operator: &XOnlyPublicKey, leaf: &OutputRequest) -> [u8; 32] {
	ParticipationRequest { inputs: vec![], outputs: vec![leaf.clone()], key_proofs: vec![], fees: vec![], not_before: None }
		.id(chain, operator)
}

/// Takes a claim: see the [module documentation](self). Returns the
/// repayment participation's id, recorded now or before for this very
/// claim.
pub async fn claim(store: &Store, params: &Params, req: &ClaimRequest) -> Result<[u8; 32], OwedError> {
	let entry = store.owed_entry(&req.coin.0).await?.ok_or(OwedError::Unknown(req.coin))?;
	let OutputRequest::Leaf { asset, value, template, owner, owner_nonce, exit_delay, order, landing, channel } = &req.leaf else {
		return Err(OwedError::Template("offboard".into()));
	};
	let id = repayment_id(&params.chain, &params.operator, &req.leaf);
	let coin_owner = XOnlyPublicKey::from_slice(&entry.owner_key).map_err(|e| StoreError::Corrupt(format!("owner key: {}", e)))?;
	if !verify_digest(&req.signature, &claim_digest(&params.chain, &params.operator, &req.coin, &id), &coin_owner) {
		return Err(OwedError::BadSignature);
	}
	match entry.state {
		OwedState::Claimed if entry.participation_id == Some(id) => return Ok(id),
		OwedState::Claimed | OwedState::Repaid => return Err(OwedError::Claimed(req.coin, entry.state.as_str(),
			entry.participation_id.map(|p| format!(" by participation {}", crate::signer::hex(&p))).unwrap_or_default())),
		OwedState::Withdrawn => return Err(OwedError::Withdrawn(req.coin, elements::Txid::from_byte_array(entry.sweep_txid).to_string())),
		OwedState::Owed => {},
	}
	// The leaf: in the coin's asset, holding exactly what is owed, a
	// template a round makes for a plain holding, within the bounds.
	if asset.into_inner().to_byte_array() != entry.asset {
		return Err(OwedError::OutOfBounds(format!("a leaf in asset {}; coin {} was of asset {}", asset, req.coin,
			AssetId::from_byte_array(entry.asset))));
	}
	if *value != entry.owed() {
		return Err(OwedError::OutOfBounds(format!("a leaf of {}; what is owed for coin {} is {} ({} less the late-refresh fee {})",
			value, req.coin, entry.owed(), entry.value, entry.fee)));
	}
	match (template, order, landing, channel) {
		(Template::Vtxo1 | Template::Vtxo2, None, None, None) | (Template::Landing1, None, Some(_), None) => {},
		_ => return Err(OwedError::Template(template.to_string())),
	}
	params.check_landing(*asset, *value, landing.as_ref()).map_err(OwedError::OutOfBounds)?;
	if !params.exit_delay_ok(*exit_delay) {
		return Err(OwedError::OutOfBounds(format!("an exit delay of {} units; the operator takes {} to {}", exit_delay.units(),
			params.min_exit_delay.units(), params.max_exit_delay.units())));
	}
	if *owner == params.operator {
		return Err(OwedError::OperatorKey);
	}
	if !verify_digest(&req.key_proof, &key_proof_digest(&id), owner) {
		return Err(OwedError::BadKeyProof);
	}
	let mut preimage = [0u8; 32];
	rand::rngs::OsRng.fill_bytes(&mut preimage);
	let p = NewParticipation {
		id,
		unlock_hash: arca_covenant::script::sha256(&preimage),
		preimage,
		not_before: None,
		refund_delay_units: params.refund_delay.units(),
		inputs: vec![],
		outputs: vec![ParticipationOutput {
			asset: entry.asset,
			value: *value,
			kind: WantedKind::Leaf {
				template: template.to_string(), owner_key: owner.serialize(), owner_nonce: *owner_nonce,
				exit_delay_units: exit_delay.units(), operator_nonce: [0; 32], htlc: None, order: None, landing: *landing, channel: None,
			},
			leaf_id: None,
		}],
		fees: vec![],
		fill: None,
		distribution: None,
	};
	match store.claim_owed(&req.coin.0, &p).await {
		Ok(ClaimOutcome::Claimed) => {
			log::info!("owed: coin {} claimed, {} of {} repaid by participation {}", req.coin, value, asset, crate::signer::hex(&id));
			Ok(id)
		},
		Ok(ClaimOutcome::Again) => Ok(id),
		Ok(ClaimOutcome::Unknown) => Err(OwedError::Unknown(req.coin)),
		Ok(ClaimOutcome::Withdrawn) => Err(OwedError::Withdrawn(req.coin, elements::Txid::from_byte_array(entry.sweep_txid).to_string())),
		Ok(ClaimOutcome::Taken(state, by)) => Err(OwedError::Claimed(req.coin, state.as_str(),
			by.map(|p| format!(" by participation {}", crate::signer::hex(&p))).unwrap_or_default())),
		Err(StoreError::KeyReused) | Err(StoreError::ParticipationExists) => Err(OwedError::KeyReused),
		Err(e) => Err(e.into()),
	}
}
