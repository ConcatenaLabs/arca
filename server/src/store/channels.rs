//! The states and credit notes of `channel-1` coins ([`crate::channels`]).
//!
//! A state or a note is recorded before the signer is asked for it, its
//! operator signature empty until the signer answers: the channel's coin row
//! is locked while it is recorded, its state checked live in the same
//! transaction, so a state, a payment into the channel and the coin's being
//! given up in a participation happen one at a time.

use tokio_postgres::GenericClient;

use super::{array32, Store, StoreError};

/// A state of a channel past its opening, as the store keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelStateRow {
	pub leaf_id: [u8; 32],
	pub state: arca_covenant::State,
	pub owner_sig: [u8; 64],
	/// The operator's signature; `None` while the signer has not answered.
	pub operator_sig: Option<[u8; 64]>,
	/// The channel a payment out of this state pays, and the amount.
	pub pays: Option<([u8; 32], u64)>,
}

/// A credit note of a channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelNoteRow {
	pub leaf_id: [u8; 32],
	pub credit: u64,
	pub signature: Option<[u8; 64]>,
	/// The payer's channel and state that made it.
	pub by: ([u8; 32], u64),
}

/// What a participation that gives up a channel coin read of it: its latest
/// signed state and note. The coin is given up only if they are still the
/// latest, and nothing of the channel waits for the signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelSeen {
	pub leaf_id: [u8; 32],
	pub number: u64,
	pub credit: u64,
}

/// A state to record, with the payment it makes, if it makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewChannelState {
	pub leaf_id: [u8; 32],
	pub state: arca_covenant::State,
	pub owner_sig: [u8; 64],
	/// A payment: the receiving channel and the amount. The receiver's note
	/// is its latest credit plus the amount.
	pub pays: Option<([u8; 32], u64)>,
	/// The state's output script: registered as the channel coin's, so the
	/// chain's outputs paying it are sighted as the coin's own.
	pub script_pubkey: Vec<u8>,
}

/// What [`Store::begin_channel_state`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Begun {
	/// Recorded now, with the receiver's new cumulative credit for a
	/// payment.
	New(Option<u64>),
	/// The same state, recorded before: its row and its note, signed or not.
	Again(ChannelStateRow, Option<ChannelNoteRow>),
}

const STATE_COLUMNS: &str = "leaf_id, number, owner_balance, operator_balance, folded, owner_sig, operator_sig, pays, amount";
const NOTE_COLUMNS: &str = "leaf_id, credit, signature, by_leaf, by_number";

fn u64_of(v: i64, what: &str) -> Result<u64, StoreError> {
	u64::try_from(v).map_err(|_| StoreError::Corrupt(format!("{} {}", what, v)))
}

fn i64_of(v: u64) -> Result<i64, StoreError> {
	i64::try_from(v).map_err(|_| StoreError::Corrupt(format!("an amount of {} does not fit", v)))
}

fn sig64(b: Vec<u8>, what: &str) -> Result<[u8; 64], StoreError> {
	b.try_into().map_err(|_| StoreError::Corrupt(format!("{} of the wrong length", what)))
}

fn state_row(r: &tokio_postgres::Row) -> Result<ChannelStateRow, StoreError> {
	let pays = match r.get::<_, Option<Vec<u8>>>(7) {
		Some(p) => Some((array32(p, "paid channel")?, u64_of(r.get(8), "amount")?)),
		None => None,
	};
	Ok(ChannelStateRow {
		leaf_id: array32(r.get(0), "leaf id")?,
		state: arca_covenant::State {
			number: u64_of(r.get(1), "number")?, owner: u64_of(r.get(2), "owner balance")?,
			operator: u64_of(r.get(3), "operator balance")?, folded: u64_of(r.get(4), "folded")?,
		},
		owner_sig: sig64(r.get(5), "owner signature")?,
		operator_sig: r.get::<_, Option<Vec<u8>>>(6).map(|s| sig64(s, "operator signature")).transpose()?,
		pays,
	})
}

fn note_row(r: &tokio_postgres::Row) -> Result<ChannelNoteRow, StoreError> {
	Ok(ChannelNoteRow {
		leaf_id: array32(r.get(0), "leaf id")?,
		credit: u64_of(r.get(1), "credit")?,
		signature: r.get::<_, Option<Vec<u8>>>(2).map(|s| sig64(s, "note signature")).transpose()?,
		by: (array32(r.get(3), "payer")?, u64_of(r.get(4), "payer's number")?),
	})
}

async fn latest_state<C: GenericClient>(c: &C, leaf: &[u8; 32]) -> Result<Option<ChannelStateRow>, StoreError> {
	let r = c.query_opt(&format!("SELECT {} FROM channel_state WHERE leaf_id = $1 ORDER BY number DESC LIMIT 1", STATE_COLUMNS),
		&[&&leaf[..]]).await?;
	r.as_ref().map(state_row).transpose()
}

async fn latest_note<C: GenericClient>(c: &C, leaf: &[u8; 32]) -> Result<Option<ChannelNoteRow>, StoreError> {
	let r = c.query_opt(&format!("SELECT {} FROM channel_note WHERE leaf_id = $1 ORDER BY credit DESC LIMIT 1", NOTE_COLUMNS),
		&[&&leaf[..]]).await?;
	r.as_ref().map(note_row).transpose()
}

/// Locks the coin row of `leaf` and requires it live.
async fn lock_live<C: GenericClient>(c: &C, leaf: &[u8; 32]) -> Result<(), StoreError> {
	let r = c.query_opt("SELECT state::text FROM leaf WHERE leaf_id = $1 FOR UPDATE", &[&&leaf[..]]).await?;
	match r.map(|r| r.get::<_, String>(0)).as_deref() {
		Some("live") => Ok(()),
		Some("spent") => Err(StoreError::LeafSpent(hex(leaf))),
		Some(_) => Err(StoreError::LeafNotLive(hex(leaf), "not live")),
		None => Err(StoreError::LeafUnknown(hex(leaf))),
	}
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Inside a participation's transaction: each channel coin it gives up is
/// still at the state and note it read, and nothing of it waits for the
/// signer. Locks each coin row first.
pub(crate) async fn check_seen<C: GenericClient>(c: &C, seen: &[ChannelSeen]) -> Result<(), StoreError> {
	for s in seen {
		c.query_opt("SELECT 1 FROM leaf WHERE leaf_id = $1 FOR UPDATE", &[&&s.leaf_id[..]]).await?;
		let st = latest_state(c, &s.leaf_id).await?;
		let note = latest_note(c, &s.leaf_id).await?;
		let number = st.as_ref().map_or(0, |r| r.state.number);
		let credit = note.as_ref().map_or(0, |n| n.credit);
		if st.as_ref().is_some_and(|r| r.operator_sig.is_none()) || note.as_ref().is_some_and(|n| n.signature.is_none()) {
			return Err(StoreError::ChannelBusy(hex(&s.leaf_id)));
		}
		if number != s.number || credit != s.credit {
			return Err(StoreError::ChannelBusy(hex(&s.leaf_id)));
		}
	}
	Ok(())
}

impl Store {
	/// The latest state of channel `leaf` past its opening, signed or not.
	pub async fn channel_latest(&self, leaf: &[u8; 32]) -> Result<Option<ChannelStateRow>, StoreError> {
		let conn = self.conn().await?;
		latest_state(&*conn, leaf).await
	}

	/// The latest signed state of channel `leaf` past its opening.
	pub async fn channel_latest_signed(&self, leaf: &[u8; 32]) -> Result<Option<ChannelStateRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(&format!("SELECT {} FROM channel_state WHERE leaf_id = $1 AND operator_sig IS NOT NULL
			ORDER BY number DESC LIMIT 1", STATE_COLUMNS), &[&&leaf[..]]).await?;
		r.as_ref().map(state_row).transpose()
	}

	/// Every state of channel `leaf` past its opening, signed or not, lowest
	/// number first.
	pub async fn channel_states(&self, leaf: &[u8; 32]) -> Result<Vec<ChannelStateRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!("SELECT {} FROM channel_state WHERE leaf_id = $1 ORDER BY number", STATE_COLUMNS),
			&[&&leaf[..]]).await?;
		rows.iter().map(state_row).collect()
	}

	/// Every output of a live channel coin's scripts sighted on the chain
	/// (its leaf, or the output of one of its states), where the channel has
	/// a state past its opening that both sides signed: `(leaf id, txid,
	/// vout)`, oldest first. The watcher answers an older state there with the
	/// latest ([`crate::watcher`]).
	pub async fn live_channel_sightings(&self) -> Result<Vec<([u8; 32], [u8; 32], u32)>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT a.leaf_id, s.txid, s.vout FROM script_sighting s
			 JOIN arca_script a ON a.script_pubkey = s.script_pubkey
			 JOIN leaf l ON l.leaf_id = a.leaf_id
			 WHERE a.kind = 'leaf' AND l.state = 'live'
			   AND EXISTS (SELECT 1 FROM channel_state c WHERE c.leaf_id = a.leaf_id AND c.operator_sig IS NOT NULL)
			 ORDER BY s.seen_at, s.txid, s.vout",
			&[],
		).await?;
		rows.iter().map(|r| Ok((array32(r.get(0), "leaf id")?, array32(r.get(1), "txid")?, r.get::<_, i32>(2) as u32))).collect()
	}

	/// The highest credit note of channel `leaf`, signed or not.
	pub async fn channel_note(&self, leaf: &[u8; 32]) -> Result<Option<ChannelNoteRow>, StoreError> {
		let conn = self.conn().await?;
		latest_note(&*conn, leaf).await
	}

	/// The highest signed credit note of channel `leaf`.
	pub async fn channel_note_signed(&self, leaf: &[u8; 32]) -> Result<Option<ChannelNoteRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(&format!("SELECT {} FROM channel_note WHERE leaf_id = $1 AND signature IS NOT NULL
			ORDER BY credit DESC LIMIT 1", NOTE_COLUMNS), &[&&leaf[..]]).await?;
		r.as_ref().map(note_row).transpose()
	}

	/// The note a payment from state `number` of channel `by` made.
	pub async fn channel_note_by(&self, by: &[u8; 32], number: u64) -> Result<Option<ChannelNoteRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(&format!("SELECT {} FROM channel_note WHERE by_leaf = $1 AND by_number = $2", NOTE_COLUMNS),
			&[&&by[..], &i64_of(number)?]).await?;
		r.as_ref().map(note_row).transpose()
	}

	/// Records `new`, the next state of its channel, and for a payment the
	/// receiver's note, whole or not at all: the payer's coin (and the
	/// receiver's) live and locked, `new` one above the channel's latest
	/// state, which is signed, and the receiver's note one above its latest,
	/// which is signed. The same state again is [`Begun::Again`].
	/// `check` judges `new` against the latest state, or the opening when
	/// there is none, and the latest credit of the payer and, for a payment,
	/// the receiver's latest state and credit, inside the transaction.
	pub async fn begin_channel_state<F>(&self, new: &NewChannelState, check: F) -> Result<Begun, StoreError>
	where
		F: FnOnce(Option<&ChannelStateRow>, u64, Option<(Option<&ChannelStateRow>, u64)>) -> Result<(), String>,
	{
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		// Lock the coin rows in leaf-id order.
		let mut leaves = vec![new.leaf_id];
		if let Some((to, ..)) = &new.pays {
			leaves.push(*to);
		}
		leaves.sort();
		for l in &leaves {
			lock_live(&t, l).await?;
		}
		let same = t.query_opt(&format!("SELECT {} FROM channel_state WHERE leaf_id = $1 AND number = $2", STATE_COLUMNS),
			&[&&new.leaf_id[..], &i64_of(new.state.number)?]).await?;
		if let Some(r) = same {
			let row = state_row(&r)?;
			// The same state, whatever the owner's signature (checked over the
			// same message before), and the same payment.
			if row.state == new.state && row.pays == new.pays {
				let note = t.query_opt(&format!("SELECT {} FROM channel_note WHERE by_leaf = $1 AND by_number = $2", NOTE_COLUMNS),
					&[&&new.leaf_id[..], &i64_of(new.state.number)?]).await?;
				let note = note.as_ref().map(note_row).transpose()?;
				t.commit().await?;
				return Ok(Begun::Again(row, note));
			}
			return Err(StoreError::ChannelState(format!("state {} of the channel is recorded already, another", new.state.number)));
		}
		let latest = latest_state(&t, &new.leaf_id).await?;
		if latest.as_ref().is_some_and(|r| r.operator_sig.is_none()) {
			return Err(StoreError::ChannelBusy(hex(&new.leaf_id)));
		}
		let credit = latest_note(&t, &new.leaf_id).await?;
		if credit.as_ref().is_some_and(|n| n.signature.is_none()) {
			return Err(StoreError::ChannelBusy(hex(&new.leaf_id)));
		}
		let credit = credit.map_or(0, |n| n.credit);
		let receiver = match &new.pays {
			Some((to, ..)) => {
				let st = latest_state(&t, to).await?;
				if st.as_ref().is_some_and(|r| r.operator_sig.is_none()) {
					return Err(StoreError::ChannelBusy(hex(to)));
				}
				let n = latest_note(&t, to).await?;
				if n.as_ref().is_some_and(|n| n.signature.is_none()) {
					return Err(StoreError::ChannelBusy(hex(to)));
				}
				Some((st, n.map_or(0, |n| n.credit)))
			},
			None => None,
		};
		check(latest.as_ref(), credit, receiver.as_ref().map(|(s, c)| (s.as_ref(), *c))).map_err(StoreError::ChannelState)?;
		let (pays, amount) = match &new.pays {
			Some((to, amount)) => (Some(to.to_vec()), *amount),
			None => (None, 0),
		};
		t.execute("INSERT INTO arca_script (script_pubkey, kind, leaf_id) VALUES ($1, 'leaf', $2) ON CONFLICT DO NOTHING",
			&[&new.script_pubkey, &&new.leaf_id[..]]).await?;
		t.execute("INSERT INTO channel_state (leaf_id, number, owner_balance, operator_balance, folded, owner_sig, pays, amount)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
			&[&&new.leaf_id[..], &i64_of(new.state.number)?, &i64_of(new.state.owner)?, &i64_of(new.state.operator)?,
				&i64_of(new.state.folded)?, &&new.owner_sig[..], &pays, &i64_of(amount)?]).await?;
		let mut made = None;
		if let (Some((to, amount)), Some((_, before))) = (&new.pays, &receiver) {
			let credit = before.checked_add(*amount).ok_or_else(|| StoreError::ChannelState("the credit overflows".into()))?;
			t.execute("INSERT INTO channel_note (leaf_id, credit, by_leaf, by_number) VALUES ($1, $2, $3, $4)",
				&[&&to[..], &i64_of(credit)?, &&new.leaf_id[..], &i64_of(new.state.number)?]).await?;
			made = Some(credit);
		}
		t.commit().await?;
		Ok(Begun::New(made))
	}

	/// The operator's signature on state `number` of channel `leaf`.
	pub async fn set_channel_state_sig(&self, leaf: &[u8; 32], number: u64, sig: &[u8; 64]) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute("UPDATE channel_state SET operator_sig = $3 WHERE leaf_id = $1 AND number = $2 AND operator_sig IS NULL",
			&[&&leaf[..], &i64_of(number)?, &&sig[..]]).await?;
		Ok(())
	}

	/// The operator's signature on the note of `credit` for channel `leaf`.
	pub async fn set_channel_note_sig(&self, leaf: &[u8; 32], credit: u64, sig: &[u8; 64]) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute("UPDATE channel_note SET signature = $3 WHERE leaf_id = $1 AND credit = $2 AND signature IS NULL",
			&[&&leaf[..], &i64_of(credit)?, &&sig[..]]).await?;
		Ok(())
	}

	/// Drops state `number` of channel `leaf` and the note it made, neither
	/// signed: the signer refused it.
	pub async fn drop_channel_state(&self, leaf: &[u8; 32], number: u64) -> Result<(), StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		t.execute("DELETE FROM channel_note WHERE by_leaf = $1 AND by_number = $2 AND signature IS NULL",
			&[&&leaf[..], &i64_of(number)?]).await?;
		t.execute("DELETE FROM channel_state WHERE leaf_id = $1 AND number = $2 AND operator_sig IS NULL",
			&[&&leaf[..], &i64_of(number)?]).await?;
		t.commit().await?;
		Ok(())
	}
}
