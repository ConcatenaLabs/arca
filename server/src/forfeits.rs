//! The forfeit swap: an owner hands over the forfeits of the coins it gave up
//! and gets the preimage that completes its new leaves; then it releases the
//! lowest nodes of the coins it gave up.
//!
//! `forfeit_leaves` is accepted only for a participation in a round the
//! finality service calls final. The forfeits must be exactly the coins the
//! participation gave up, one each, and the server verifies every one against
//! the forfeit it builds itself ([`Forfeit::new`]) from what it chose: the
//! participation's unlock hash, the connector asset of its round's connector
//! output (`M`, which exists only while that round is in the chain), the
//! coin's own leaf id (so no two forfeits can share an output), and the
//! refund delay and margin it published with the participation. A forfeit
//! signed for another hash, another round's connector, another coin, or with
//! another delay or margin, does not verify. Every coin given up must still
//! pass the coin check (nothing of its lineage on the chain, its boards
//! credited and unspent): a coin already on its way out on the chain is not
//! taken in exchange for a new leaf.
//!
//! With the forfeits, the owner hands over its unroll authorisation for every
//! node above each new leaf, so the server holds each new leaf's full coin
//! record (record, preimage, authorisations) and can serve it, and pass it on
//! inside any later transfer. The record must validate against the round as a
//! receiver checks a coin.
//!
//! The operator's half of each forfeit is signed by the signer, over the
//! message the server built, and checked. It is never returned: it leaves the
//! server only inside a forfeit the operator publishes, so an owner never
//! holds a forfeit it could publish itself. Then, in one database transaction,
//! the forfeits are stored, the new leaves' records filled in, the
//! participation released and its new leaves credited, and only then is the
//! preimage returned. The coins given up have been spent by the participation
//! since it was accepted. A participation run again forfeit-first, after a
//! round it was released in could not return, has its forfeits stored and its
//! preimage withheld: it goes out only once the forfeit is published and
//! claimed, which reveals it on the chain anyway.
//!
//! The step is idempotent: the same request again, for a released
//! participation, verifies every forfeit again and returns the same
//! preimage, whatever the chain has seen of the coins given up since (the
//! watcher publishes a forfeit when its coin comes on-chain).
//!
//! The forfeits are due within a day of the round being found final
//! ([`crate::params::Params::FORFEIT_DEADLINE`]): after that the
//! participation expires ([`crate::rounds`]), and a forfeit step for it is
//! refused (`not_in_round`), even one that was in flight when it expired.
//!
//! `release_leaves` takes an owner's release of the lowest node of a coin it
//! gave up: the owner's signature with the coin's key over
//! `SHA256("Arca/release" ‖ genesis_hash ‖ H ‖ M)`, `M` the connector asset of
//! the participation's round ([`arca_covenant::Release`]), which the request
//! may name. RECLAIM needs an atom of `M` among its inputs, and `M` exists only
//! while that round is in the chain, so a release is void with its round. A
//! release naming another `M` is refused (`wrong_round`), as is one whose
//! signature is over another message (`bad_signature`): the server checks it
//! over the round's own `M` whether the request names it or not. It is also refused for a coin with an open
//! out-of-round reassignment, whatever else holds
//! ([`crate::cosign::Cosigner::check_release`]: the release key is the key the
//! coin was built with, so its sender and the operator could otherwise void
//! the receiver's chain); for a coin not given up in the participation named;
//! before the participation's preimage went out; while the participation's
//! round is not final; and for a coin that has no lowest node (a board, or a
//! coin a reassignment made). Each release is stored with its round and `M`.
//! When a round can never return, the releases given for it are retired:
//! their `M` can never be issued.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use elements::hashes::Hash;
use elements::secp256k1_zkp::schnorr::Signature;
use elements::{AssetId, Transaction, Txid};

use arca_covenant::sign::verify_digest;
use arca_covenant::{
	connector_asset, CoinRecord, Forfeit, LeafId, LeafRecord, MedianTime, Pair, RelativeTime, Release, WalletPolicy,
};

use crate::coins::{self, CoinError};
use crate::cosign::{CosignError, Cosigner};
use crate::params::Params;
use crate::signer::{hex, SignerClient, SignerError};
use crate::store::{NewForfeit, ParticipationState, RoundState, Store, StoreError};

/// One coin's forfeit: its owner's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForfeitRequest {
	pub leaf_id: LeafId,
	pub signature: Signature,
}

/// One new leaf's unroll authorisations, from the batch output down: each a
/// signature by the leaf's owner key and its time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthsRequest {
	pub leaf_id: LeafId,
	pub auths: Vec<(Signature, MedianTime)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForfeitLeaves {
	pub participation_id: [u8; 32],
	pub forfeits: Vec<ForfeitRequest>,
	pub leaves: Vec<AuthsRequest>,
}

/// What `forfeit_leaves` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forfeited {
	pub participation_id: [u8; 32],
	pub state: ParticipationState,
	/// The preimage of the participation's unlock hash; `None` while a
	/// forfeit-first participation waits for its forfeit to be claimed.
	pub preimage: Option<[u8; 32]>,
	pub forfeit_first: bool,
}

/// One coin's release: the owner's signature, and the connector asset of the
/// round it names when the wallet names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseRequest {
	pub leaf_id: LeafId,
	pub connector: Option<AssetId>,
	pub signature: Signature,
}

/// Why a forfeit or a release was refused, or could not be handled.
#[derive(Debug, thiserror::Error)]
pub enum ForfeitError {
	#[error("no participation {0} is known")]
	Unknown(String),
	#[error("the participation is {0}: it is in no round whose forfeits it owes")]
	NotInRound(&'static str),
	#[error("the participation's round {0} is not final yet")]
	RoundNotFinal(Txid),
	#[error("the forfeits are not exactly the coins the participation gave up: {0}")]
	ForfeitSet(String),
	#[error("the forfeit of coin {0} does not verify: it is not the owner's signature over the move into the forfeit output for this participation's unlock hash, this round's connector asset and this coin")]
	BadForfeit(LeafId),
	#[error("the unroll authorisations are not one set for each new leaf: {0}")]
	LeafSet(String),
	#[error("new leaf {leaf}: {error}")]
	InvalidLeaf { leaf: LeafId, error: arca_covenant::TransferError },
	#[error(transparent)]
	Coin(CoinError),
	#[error("coin {0} was not given up in this participation")]
	NotParticipating(LeafId),
	#[error("no release is taken before the participation's preimage has gone out")]
	ReleaseEarly,
	#[error("coin {0} has no lowest node to release: it is a board, or a coin a reassignment made")]
	NoLowestNode(LeafId),
	#[error("coin {0}'s release is not its owner's signature over its lowest node's release message")]
	BadRelease(LeafId),
	#[error("coin {leaf}'s release names the connector asset {named}; the participation's round's is {round}")]
	WrongRound { leaf: LeafId, named: AssetId, round: AssetId },
	#[error(transparent)]
	Cosign(CosignError),
	#[error("the signer: {0}")]
	Signer(#[from] SignerError),
	#[error("the server has not followed the chain yet")]
	NotSynced,
	#[error(transparent)]
	Store(#[from] StoreError),
	#[error("{0}")]
	Internal(String),
}

impl ForfeitError {
	/// A stable name for the refusal.
	pub fn code(&self) -> &'static str {
		use ForfeitError::*;
		match self {
			Unknown(_) => "unknown_participation",
			NotInRound(_) => "not_in_round",
			RoundNotFinal(_) => "round_not_final",
			ForfeitSet(_) => "forfeit_set",
			BadForfeit(_) => "bad_forfeit",
			LeafSet(_) => "leaf_set",
			InvalidLeaf { .. } => "invalid_leaf",
			Coin(CoinError::OnChain { .. }) => "on_chain",
			Coin(CoinError::BoardNotFinal(_)) => "board_not_final",
			Coin(CoinError::RoundNotFinal(_)) => "round_not_final",
			Coin(CoinError::InvalidCoin { .. }) => "invalid_coin",
			Coin(_) => "internal",
			NotParticipating(_) => "not_participating",
			ReleaseEarly => "release_early",
			NoLowestNode(_) => "no_lowest_node",
			BadRelease(_) => "bad_signature",
			WrongRound { .. } => "wrong_round",
			Cosign(e) => e.code(),
			Signer(SignerError::AlreadySigned(_)) => "double_spend",
			Signer(_) => "signer_unavailable",
			NotSynced => "not_synced",
			Store(_) | Internal(_) => "internal",
		}
	}
}

impl From<CoinError> for ForfeitError {
	fn from(e: CoinError) -> ForfeitError {
		match e {
			CoinError::Store(s) => ForfeitError::Store(s),
			other => ForfeitError::Coin(other),
		}
	}
}

/// See the [module documentation](self).
pub struct Forfeits {
	store: Store,
	params: Arc<Params>,
	signer: SignerClient,
	cosigner: Arc<Cosigner>,
}

impl Forfeits {
	pub fn new(store: Store, params: Arc<Params>, signer: SignerClient, cosigner: Arc<Cosigner>) -> Arc<Forfeits> {
		Arc::new(Forfeits { store, params, signer, cosigner })
	}

	async fn now(&self) -> Result<MedianTime, ForfeitError> {
		let tip = self.store.tip_block().await?.ok_or(ForfeitError::NotSynced)?;
		MedianTime::from_consensus(tip.median_time as u32).map_err(|e| ForfeitError::Internal(e.to_string()))
	}

	/// Takes the forfeits of a participation and returns its preimage: see
	/// the [module documentation](self).
	pub async fn forfeit_leaves(&self, req: &ForfeitLeaves) -> Result<Forfeited, ForfeitError> {
		let id = req.participation_id;
		let p = self.store.participation(&id).await?.ok_or_else(|| ForfeitError::Unknown(hex(&id)))?;
		match p.state {
			ParticipationState::Issued | ParticipationState::Released => {},
			other => return Err(ForfeitError::NotInRound(other.as_str())),
		}
		let round_id = p.round_id.ok_or_else(|| ForfeitError::Internal("an issued participation without a round".into()))?;
		let round = self.store.round(round_id).await?.ok_or_else(|| ForfeitError::Internal(format!("round {} is not recorded", round_id)))?;
		let round_txid = Txid::from_byte_array(round.txid);
		if round.state != RoundState::Final {
			return Err(ForfeitError::RoundNotFinal(round_txid));
		}
		let round_tx: Transaction = elements::encode::deserialize(&round.tx).map_err(|e| ForfeitError::Internal(e.to_string()))?;
		let now = self.now().await?;

		// The forfeits: exactly the coins given up.
		let given: Vec<LeafId> = p.inputs.iter().map(|i| LeafId(i.leaf_id)).collect();
		let mut sigs: BTreeMap<LeafId, Signature> = BTreeMap::new();
		for f in &req.forfeits {
			if sigs.insert(f.leaf_id, f.signature).is_some() {
				return Err(ForfeitError::ForfeitSet(format!("coin {} is named twice", f.leaf_id)));
			}
		}
		if sigs.len() != given.len() || given.iter().any(|l| !sigs.contains_key(l)) {
			return Err(ForfeitError::ForfeitSet(format!(
				"{} forfeit(s) for the {} coin(s) given up ({})", sigs.len(), given.len(),
				given.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(", "))));
		}

		// Each forfeit, verified against the one the server builds.
		let m = connector_asset(round_txid, round.connector_vout);
		let refund = RelativeTime::from_units(p.refund_delay_units).map_err(|e| ForfeitError::Internal(e.to_string()))?;
		// A coin is taken until its expiry: what matters now is that it is
		// not past it, and that nothing of it is on the chain.
		let policy = WalletPolicy { horizon: 0, ..self.params.policy(now) };
		let mut built = Vec::with_capacity(given.len());
		for i in &p.inputs {
			let leaf = LeafId(i.leaf_id);
			// A participation already released took its forfeits once, each
			// coin checked then; asked again, it verifies them again but
			// does not ask of the chain what the forfeits since published
			// there (by the watcher, answering an owner) have changed.
			let checked = if p.state == ParticipationState::Released {
				coins::resolve(&self.store, &policy, &leaf).await?
			} else {
				coins::check(&self.store, &policy, &leaf, &id).await?
			};
			let c = &checked.coin;
			let f = Forfeit::new(c.leaf, (c.asset, c.value), c.id, p.unlock_hash, m, refund, i.margin)
				.map_err(|e| ForfeitError::Internal(e.to_string()))?;
			let owner_sig = sigs[&leaf];
			if !verify_digest(&owner_sig, &f.message().digest, &c.leaf.owner) {
				return Err(ForfeitError::BadForfeit(leaf));
			}
			built.push((leaf, c.clone(), f, owner_sig));
		}

		// The new leaves' authorisations: one set per new leaf, each record
		// valid against the round as a receiver checks a coin.
		let at = self.store.placement(&id, p.attempt).await?;
		let mut auths: BTreeMap<LeafId, &Vec<(Signature, MedianTime)>> = BTreeMap::new();
		for a in &req.leaves {
			if auths.insert(a.leaf_id, &a.auths).is_some() {
				return Err(ForfeitError::LeafSet(format!("leaf {} is named twice", a.leaf_id)));
			}
		}
		let new_ids: HashSet<LeafId> = at.leaves.iter().map(|(_, l, _, _)| LeafId(*l)).collect();
		if auths.len() != new_ids.len() || auths.keys().any(|l| !new_ids.contains(l)) {
			return Err(ForfeitError::LeafSet(format!("{} set(s) for the {} new leaf/leaves", auths.len(), new_ids.len())));
		}
		let receipt = self.params.policy(now);
		let mut records = Vec::with_capacity(new_ids.len());
		for (_, leaf, _, _) in &at.leaves {
			let leaf = LeafId(*leaf);
			let row = self.store.batch_leaf(&leaf.0).await?.ok_or_else(|| ForfeitError::Internal(format!("leaf {} is not in a batch", leaf)))?;
			let record = LeafRecord::from_bytes(&row.record).map_err(|e| ForfeitError::Internal(e.to_string()))?;
			let coin = CoinRecord::Leaf { record, preimage: p.preimage, auths: auths[&leaf].clone() };
			let valid = coin.resolve(std::slice::from_ref(&round_tx), &receipt).map_err(|error| ForfeitError::InvalidLeaf { leaf, error })?;
			if valid.id != leaf {
				return Err(ForfeitError::Internal(format!("the record of leaf {} gives the id {}", leaf, valid.id)));
			}
			records.push((leaf.0, coin.to_bytes().map_err(|e| ForfeitError::Internal(e.to_string()))?));
		}

		// The operator's half of each forfeit.
		let mut forfeits = Vec::with_capacity(built.len());
		for (leaf, c, f, owner_sig) in &built {
			let operator_sig = self.signer.rebind_forfeit(&c.leaf.owner, owner_sig, &c.leaf.salt, c.asset, c.value, &f.policy,
				&f.output()).await?;
			f.verify(&Pair { operator: operator_sig, owner: *owner_sig })
				.map_err(|_| ForfeitError::Internal("the signer signed another message than the server built".into()))?;
			forfeits.push(NewForfeit {
				leaf_id: leaf.0,
				owner_sig: *owner_sig.as_ref(),
				operator_sig: *operator_sig.as_ref(),
				refund_delay_units: p.refund_delay_units,
				margin: f.margin,
				unlock_hash: p.unlock_hash,
				connector_asset: m.into_inner().to_byte_array(),
			});
		}

		// Recorded, then the preimage. A participation that expired meanwhile
		// takes nothing.
		let release = !p.forfeit_first;
		let released = match self.store.complete_participation(&id, p.attempt, round_id, &forfeits, &records, release).await {
			Ok(r) => r,
			Err(StoreError::NotInRound(state)) => return Err(ForfeitError::NotInRound(state)),
			Err(e) => return Err(e.into()),
		};
		if released {
			log::info!("participation {} released: {} forfeit(s) in, preimage handed over", hex(&id), forfeits.len());
		} else {
			log::info!("participation {} runs forfeit-first: {} forfeit(s) in, preimage withheld", hex(&id), forfeits.len());
		}
		Ok(Forfeited {
			participation_id: id,
			state: if released { ParticipationState::Released } else { ParticipationState::Issued },
			preimage: released.then_some(p.preimage),
			forfeit_first: p.forfeit_first,
		})
	}

	/// Takes owners' releases of the lowest nodes of coins given up in the
	/// participation `id`: see the [module documentation](self). Returns the
	/// coins whose release is recorded.
	pub async fn release_leaves(&self, id: &[u8; 32], releases: &[ReleaseRequest]) -> Result<Vec<LeafId>, ForfeitError> {
		let p = self.store.participation(id).await?.ok_or_else(|| ForfeitError::Unknown(hex(id)))?;
		let mut done = vec![];
		for r in releases {
			// Never for a coin with an open reassignment, whatever else holds.
			self.cosigner.check_release(&r.leaf_id).await.map_err(ForfeitError::Cosign)?;
			if !p.inputs.iter().any(|i| i.leaf_id == r.leaf_id.0) {
				return Err(ForfeitError::NotParticipating(r.leaf_id));
			}
			if p.state != ParticipationState::Released {
				return Err(ForfeitError::ReleaseEarly);
			}
			// Its round must be final: a release given on the strength of a
			// round that may not stay is not taken.
			let round = self.store.round(p.round_id.unwrap_or_default()).await?
				.ok_or_else(|| ForfeitError::Internal("a released participation without its round".into()))?;
			if round.state != RoundState::Final {
				return Err(ForfeitError::RoundNotFinal(Txid::from_byte_array(round.txid)));
			}
			let row = self.store.leaf(&r.leaf_id.0).await?.ok_or_else(|| ForfeitError::Internal("a coin given up vanished".into()))?;
			let record = match CoinRecord::from_bytes(&row.record) {
				Ok(CoinRecord::Leaf { record, .. }) => record,
				Ok(_) => return Err(ForfeitError::NoLowestNode(r.leaf_id)),
				Err(e) => return Err(ForfeitError::Internal(e.to_string())),
			};
			let branch = record.branch().map_err(|e| ForfeitError::Internal(e.to_string()))?;
			let lowest = branch.nodes.last().ok_or(ForfeitError::NoLowestNode(r.leaf_id))?;
			if lowest.reclaim.is_none() {
				return Err(ForfeitError::NoLowestNode(r.leaf_id));
			}
			// The release names the connector asset of the participation's
			// round, so it is void if that round leaves the chain.
			let m = connector_asset(Txid::from_byte_array(round.txid), round.connector_vout);
			if let Some(named) = r.connector.filter(|n| *n != m) {
				return Err(ForfeitError::WrongRound { leaf: r.leaf_id, named, round: m });
			}
			let release = Release { chain: self.params.chain, node_hash: lowest.children_hash(), owner: record.owner, connector: m };
			if release.verify(&r.signature).is_err() {
				return Err(ForfeitError::BadRelease(r.leaf_id));
			}
			self.store.insert_release(&r.leaf_id.0, id, round.round_id, &lowest.children_hash(), &m.into_inner().to_byte_array(),
				r.signature.as_ref()).await?;
			done.push(r.leaf_id);
		}
		Ok(done)
	}

}
