//! Channel leaves (`channel-1`, [`arca_covenant::channel`]): the states the
//! operator co-signs and the credit notes it signs.
//!
//! A channel leaf holds a balance for each of its owner and the operator. A
//! round makes one ([`crate::participations`]): the owner's side counts
//! against the coins it gives up, the operator's side, at most the asset's
//! channel capacity ([`crate::params::Params::check_channel`]), the operator
//! funds. The leaf in the tree is the channel's state 0.
//!
//! **A payment between two channels of the operator** is one request
//! ([`Channels::update`]). The payer sends state `n + 1` of its channel,
//! signed: its balance down by the amount, the operator's up, and any credit
//! not yet folded folded in the same state. The server checks it against the
//! channel's latest state and its latest note, records it together with the
//! receiver's next note (the receiver's latest credit plus the amount, within
//! the operator's side of the receiver's latest state: the capacity already
//! there), then has the signer sign the note and then the state, and answers
//! with both. The receiver needs nothing more and need not be online: the
//! note is enforceable on the chain with nobody's help. The payer relies on
//! the operator for this one request; a request repeated after a lost answer
//! is answered from what was recorded. A request with no payment folds the
//! channel's credit into its owner's balance.
//!
//! Both channels must be live coins of rounds that are final, held by no
//! participation, and in one asset ([`crate::coins::check`]): a note against
//! a coin whose round could leave the chain is not final. While a state or a
//! note of a channel waits for the signer nothing else of it moves, and a
//! participation that gives up a channel coin is taken only if the state and
//! note it counted are still the latest ([`owner_share`]), so its owner's
//! side is counted once.
//!
//! **Closing into a round**: a channel coin given up in a participation
//! counts as its owner's side, the latest state's balance and every credit
//! not folded ([`owner_share`]); the forfeit gives up the whole coin, as any
//! coin's does. Any state output of the coin carries its collaborative leaf,
//! so the forfeit answers the coin on the chain whatever state it reaches.
//! A channel coin is refused anywhere else a coin is given up
//! ([`crate::coins::check_plain`]).

use std::sync::Arc;

use elements::secp256k1_zkp::schnorr::Signature;
use elements::AssetId;

use arca_covenant::sign::verify_digest;
use arca_covenant::{ChannelPolicy, LeafId, MedianTime, State, WalletPolicy};

use crate::coins::{self, Checked, CoinError};
use crate::params::Params;
use crate::signer::{SignerClient, SignerError};
use crate::store::{Begun, ChannelSeen, ChannelStateRow, NewChannelState, Store, StoreError};

/// Why a channel request is refused.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
	#[error("leaf {0} is not a channel-1 leaf")]
	NotAChannel(LeafId),
	#[error(transparent)]
	Coin(#[from] CoinError),
	#[error("{0}")]
	State(String),
	#[error("{0}")]
	Busy(String),
	#[error("the server has not followed the chain yet")]
	NotSynced,
	#[error("the operator's signer: {0}")]
	Signer(SignerError),
	#[error(transparent)]
	Store(StoreError),
	#[error("{0}")]
	Internal(String),
}

impl From<StoreError> for ChannelError {
	fn from(e: StoreError) -> ChannelError {
		match e {
			StoreError::ChannelBusy(l) => ChannelError::Busy(format!("channel {} has a state or a note waiting for the operator's \
				signer: ask again", l)),
			StoreError::ChannelState(s) => ChannelError::State(s),
			StoreError::LeafSpent(l) => ChannelError::Coin(CoinError::Spent(l.parse().unwrap_or(LeafId([0; 32])))),
			StoreError::LeafNotLive(l, s) => ChannelError::Coin(CoinError::NotLive(l.parse().unwrap_or(LeafId([0; 32])), s)),
			e => ChannelError::Store(e),
		}
	}
}

impl ChannelError {
	/// The refusal's code.
	pub fn code(&self) -> &'static str {
		match self {
			ChannelError::NotAChannel(_) => "template",
			ChannelError::Coin(CoinError::UnknownLeaf(_)) => "unknown_leaf",
			ChannelError::Coin(CoinError::Spent(_)) => "in_use",
			ChannelError::Coin(CoinError::NotLive(..)) => "not_live",
			ChannelError::Coin(CoinError::RoundNotFinal(_)) | ChannelError::Coin(CoinError::BoardNotFinal(_)) => "round_not_final",
			ChannelError::Coin(CoinError::OnChain { .. }) => "on_chain",
			ChannelError::Coin(_) => "invalid_coin",
			ChannelError::State(_) => "channel_state",
			ChannelError::Busy(_) => "conflict",
			ChannelError::NotSynced => "not_synced",
			ChannelError::Signer(SignerError::Declined(_)) => "channel_state",
			ChannelError::Signer(SignerError::AlreadySigned(_)) => "double_spend",
			ChannelError::Signer(_) => "signer_unavailable",
			ChannelError::Store(_) | ChannelError::Internal(_) => "internal",
		}
	}
}

/// A state the owner signed, and the payment it makes, if it makes one.
#[derive(Debug, Clone)]
pub struct Update {
	pub leaf: LeafId,
	pub state: State,
	pub owner_sig: Signature,
	/// The receiving channel and the amount.
	pub pay: Option<(LeafId, u64)>,
}

/// The operator's answer: its signature on the state, and for a payment the
/// receiver's note: its channel, the cumulative credit and the signature.
#[derive(Debug, Clone)]
pub struct Answer {
	pub operator_sig: Signature,
	pub note: Option<(LeafId, u64, Signature)>,
}

/// What the server holds of a channel: its terms and asset, its latest state
/// both sides signed (the opening, with no signatures, until there is one),
/// its latest signed note, and whether anything of it waits for the signer.
#[derive(Debug, Clone)]
pub struct View {
	pub policy: ChannelPolicy,
	pub asset: AssetId,
	pub state: State,
	/// The owner's and the operator's signatures on `state`.
	pub sigs: Option<(Signature, Signature)>,
	pub note: Option<(u64, Signature)>,
	pub pending: bool,
}

pub struct Channels {
	store: Store,
	params: Arc<Params>,
	signer: SignerClient,
}

fn sig(b: &[u8; 64]) -> Result<Signature, ChannelError> {
	Signature::from_slice(b).map_err(|e| ChannelError::Internal(e.to_string()))
}

/// The state a payment of `amount` and a fold up to `credit` take `from` to,
/// with what `to` must equal; `Err` says why it does not.
pub fn follows(from: &State, to: &State, amount: u64, credit: u64) -> Result<(), String> {
	if to.number != from.number + 1 {
		return Err(format!("state {} does not follow the channel's latest, {}", to.number, from.number));
	}
	if to.folded < from.folded || to.folded > credit {
		return Err(format!("state {} folds a credit of {}; the channel's credit is {} and {} of it is folded", to.number, to.folded,
			credit, from.folded));
	}
	let fold = to.folded - from.folded;
	if amount == 0 && fold == 0 {
		return Err(format!("state {} changes nothing", to.number));
	}
	let owner = from.owner.checked_add(fold).and_then(|o| o.checked_sub(amount));
	let operator = from.operator.checked_sub(fold).and_then(|o| o.checked_add(amount));
	match (owner, operator) {
		(Some(o), Some(s)) if o == to.owner && s == to.operator => Ok(()),
		(None, _) | (_, None) => Err(format!("a payment of {} is more than the owner's balance of {} and its credit", amount,
			from.owner + fold)),
		_ => Err(format!("state {} gives the owner {} and the operator {}; paying {} and folding {} from state {} gives {} and {}",
			to.number, to.owner, to.operator, amount, fold, from.number, owner.unwrap_or(0), operator.unwrap_or(0))),
	}
}

/// The owner's side of the channel coin `id` of `leaf`: its latest signed
/// state's balance and every signed credit not folded, with the state and
/// note it was read from; `None` for a coin that is no channel.
pub async fn owner_share(store: &Store, id: &LeafId, leaf: &arca_covenant::LeafPolicy) -> Result<Option<(u64, ChannelSeen)>, StoreError> {
	let Some(policy) = leaf.channel_policy() else { return Ok(None) };
	let state = match store.channel_latest_signed(&id.0).await? {
		Some(r) => r.state,
		None => policy.opening(),
	};
	let credit = store.channel_note_signed(&id.0).await?.map_or(0, |n| n.credit);
	let share = state.owner.saturating_add(credit.saturating_sub(state.folded));
	Ok(Some((share, ChannelSeen { leaf_id: id.0, number: state.number, credit })))
}

impl Channels {
	pub fn new(store: Store, params: Arc<Params>, signer: SignerClient) -> Arc<Channels> {
		Arc::new(Channels { store, params, signer })
	}

	async fn now(&self) -> Result<MedianTime, ChannelError> {
		let tip = self.store.tip_block().await?.ok_or(ChannelError::NotSynced)?;
		MedianTime::from_consensus(tip.median_time as u32).map_err(|e| ChannelError::Internal(e.to_string()))
	}

	/// The live channel coin `id`, checked as a coin given up is, and its
	/// channel.
	async fn live(&self, id: &LeafId, now: MedianTime) -> Result<(Checked, ChannelPolicy), ChannelError> {
		let c = coins::check(&self.store, &self.params.policy(now), id, &[0; 32],
			coins::BoardDates::Within(WalletPolicy::EXIT_DEADLINE)).await?;
		let policy = c.coin.leaf.channel_policy().ok_or(ChannelError::NotAChannel(*id))?;
		Ok((c, policy))
	}

	/// What the server holds of channel `id`.
	pub async fn view(&self, id: &LeafId) -> Result<View, ChannelError> {
		let now = self.now().await?;
		let c = coins::resolve(&self.store, &self.params.policy(now), id).await?;
		let policy = c.coin.leaf.channel_policy().ok_or(ChannelError::NotAChannel(*id))?;
		let latest = self.store.channel_latest(&id.0).await?;
		let signed = self.store.channel_latest_signed(&id.0).await?;
		let note = self.store.channel_note(&id.0).await?;
		let signed_note = self.store.channel_note_signed(&id.0).await?;
		let pending = latest.as_ref().is_some_and(|r| r.operator_sig.is_none()) || note.as_ref().is_some_and(|n| n.signature.is_none());
		let (state, sigs) = match signed {
			Some(r) => (r.state, Some((sig(&r.owner_sig)?, sig(&r.operator_sig.expect("signed"))?))),
			None => (policy.opening(), None),
		};
		let note = match signed_note {
			Some(n) => Some((n.credit, sig(&n.signature.expect("signed"))?)),
			None => None,
		};
		Ok(View { policy, asset: c.coin.asset, state, sigs, note, pending })
	}

	/// Co-signs `u`, a state of a live channel its owner signed, and for a
	/// payment signs the receiver's next note: see the [module
	/// documentation](self).
	pub async fn update(&self, u: &Update) -> Result<Answer, ChannelError> {
		let now = self.now().await?;
		let (payer, policy) = self.live(&u.leaf, now).await?;
		let message = policy.state_message(&u.state).map_err(|e| ChannelError::State(e.to_string()))?;
		if !verify_digest(&u.owner_sig, &message.digest, &policy.owner) {
			return Err(ChannelError::State(format!("the owner's signature over state {} does not verify", u.state.number)));
		}
		let receiver = match &u.pay {
			Some((to, amount)) => {
				if *to == u.leaf {
					return Err(ChannelError::State("a channel pays another channel, not itself".into()));
				}
				if *amount == 0 {
					return Err(ChannelError::State("a payment of nothing".into()));
				}
				let (rc, rp) = self.live(to, now).await?;
				if rc.coin.asset != payer.coin.asset {
					return Err(ChannelError::State(format!("channel {} holds asset {}, and channel {} asset {}: a payment between \
						channels stays in one asset", u.leaf, payer.coin.asset, to, rc.coin.asset)));
				}
				Some(rp)
			},
			None => None,
		};
		let amount = u.pay.map_or(0, |p| p.1);
		let opening = policy.opening();
		let r_opening = receiver.map(|r| r.opening());
		let new = NewChannelState { leaf_id: u.leaf.0, state: u.state, owner_sig: *u.owner_sig.as_ref(), pays: u.pay.map(|(t, a)| (t.0, a)),
			script_pubkey: policy.script_pubkey(&u.state).to_bytes() };
		let begun = self.store.begin_channel_state(&new, |latest, credit, recv| {
			let from = latest.map_or(opening, |r| r.state);
			follows(&from, &u.state, amount, credit)?;
			if let (Some((rstate, rcredit)), Some(ro)) = (recv, r_opening) {
				let rs = rstate.map_or(ro, |r| r.state);
				let after = rcredit.checked_add(amount).ok_or("the receiver's credit overflows")?;
				if after > rs.credit_cap() {
					return Err(format!("the receiving channel takes {} more at most: the operator's side of it is {} and {} is credited \
						already", rs.credit_cap().saturating_sub(rcredit), rs.operator, rcredit.saturating_sub(rs.folded)));
				}
			}
			Ok(())
		}).await?;
		let (state_sig, note) = match begun {
			Begun::New(credit) => (None, credit.map(|c| (c, None))),
			Begun::Again(row, note) => (row.operator_sig, note.map(|n| (n.credit, n.signature))),
		};
		// The payer's state is checked with the signer before the note is
		// signed: a state it refuses for good is dropped with nothing signed.
		if state_sig.is_none() && u.pay.is_some() {
			if let Err(e) = self.signer.check_channel_state(&policy, &u.state, &u.owner_sig).await {
				return Err(self.refused(&u.leaf, u.state.number, e).await);
			}
		}
		// The receiver's note first: a note signed with the payer's state
		// refused would be the operator's loss, never a holder's.
		let note = match (&u.pay, receiver, note) {
			(Some((to, _)), Some(rp), Some((credit, existing))) => {
				let s = match existing {
					Some(s) => sig(&s)?,
					None => {
						let (rstate, rsig) = self.signed_state(to, &rp).await?;
						match self.signer.channel_note(&rp, &rstate, rsig.as_ref(), credit).await {
							Ok(s) => {
								self.store.set_channel_note_sig(&to.0, credit, s.as_ref().try_into().expect("64 bytes")).await?;
								s
							},
							Err(e) => return Err(self.refused(&u.leaf, u.state.number, e).await),
						}
					},
				};
				Some((*to, credit, s))
			},
			_ => None,
		};
		let operator_sig = match state_sig {
			Some(s) => sig(&s)?,
			None => match self.signer.channel_state(&policy, &u.state, &u.owner_sig).await {
				Ok(s) => {
					self.store.set_channel_state_sig(&u.leaf.0, u.state.number, s.as_ref().try_into().expect("64 bytes")).await?;
					s
				},
				Err(e) => return Err(self.refused(&u.leaf, u.state.number, e).await),
			},
		};
		log::info!("channel {} state {}: owner {}, operator {}{}", u.leaf, u.state.number, u.state.owner, u.state.operator,
			match &note { Some((to, c, _)) => format!(", paid {} into channel {} (credit {})", amount, to, c), None => String::new() });
		Ok(Answer { operator_sig, note })
	}

	/// The latest signed state of channel `id` and its owner's signature, or
	/// its opening, which has none.
	async fn signed_state(&self, id: &LeafId, policy: &ChannelPolicy) -> Result<(State, Option<Signature>), ChannelError> {
		Ok(match self.store.channel_latest_signed(&id.0).await? {
			Some(ChannelStateRow { state, owner_sig, .. }) => (state, Some(sig(&owner_sig)?)),
			None => (policy.opening(), None),
		})
	}

	/// The signer refused the state or its note, or could not sign it: a
	/// state it refuses for good ([`SignerError::is_final`]) and its note are
	/// dropped, so the channel moves on (`channel_state`); any other stays,
	/// and the same request again completes it (`signer_unavailable`).
	async fn refused(&self, leaf: &LeafId, number: u64, e: SignerError) -> ChannelError {
		if e.is_final() {
			if let Err(d) = self.store.drop_channel_state(&leaf.0, number).await {
				log::error!("channel {} state {}: the signer refused it ({}), and it could not be dropped: {}", leaf, number, e, d);
			}
		}
		ChannelError::Signer(e)
	}
}

#[cfg(test)]
mod test {
	use super::*;

	/// A refusal the signer would repeat however often it is asked is final
	/// (`channel_state` or `double_spend`, a 4xx); every other answer of the
	/// signer says the same request may be signed later
	/// (`signer_unavailable`, a 503), and the state waits.
	#[test]
	fn a_refusal_for_good_is_final_and_any_other_waits() {
		let m = || "m".to_string();
		let cases = [
			(SignerError::Declined(m()), "channel_state", true),
			(SignerError::AlreadySigned(m()), "double_spend", true),
			(SignerError::Failed(m()), "signer_unavailable", false),
			(SignerError::Stopped(m()), "signer_unavailable", false),
			(SignerError::Record(m()), "signer_unavailable", false),
			(SignerError::Unreachable { path: m(), error: m() }, "signer_unavailable", false),
			(SignerError::Answer(m()), "signer_unavailable", false),
			(SignerError::Database(m()), "signer_unavailable", false),
		];
		for (e, code, fin) in cases {
			assert_eq!((ChannelError::Signer(e.clone()).code(), e.is_final()), (code, fin), "{:?}", e);
			let status = crate::http::status_of(code).as_u16();
			assert_eq!((400..500).contains(&status), fin, "{} is answered {}", code, status);
		}
	}

	#[test]
	fn a_state_follows_by_a_payment_and_a_fold() {
		let s = |n, a, o, f| State { number: n, owner: a, operator: o, folded: f };
		let from = s(3, 60, 40, 10);
		assert!(follows(&from, &s(4, 50, 50, 10), 10, 10).is_ok());
		assert!(follows(&from, &s(4, 65, 35, 15), 0, 15).is_ok(), "a fold alone");
		assert!(follows(&from, &s(4, 55, 45, 15), 10, 15).is_ok(), "a fold and a payment");
		assert!(follows(&from, &s(5, 50, 50, 10), 10, 10).is_err(), "a number skipped");
		assert!(follows(&from, &s(4, 60, 40, 10), 0, 10).is_err(), "nothing changes");
		assert!(follows(&from, &s(4, 70, 30, 20), 0, 15).is_err(), "folding more than the credit");
		assert!(follows(&from, &s(4, 51, 49, 10), 10, 10).is_err(), "balances off by one");
		assert!(follows(&from, &s(4, 0, 100, 10), 61, 10).is_err(), "paying more than the owner holds");
	}
}
