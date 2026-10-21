//! Offline refresh's plans: what a holder pre-signed for each step, and where
//! each step stands ([`crate::plans`]).

use super::participations::{draw_nonce, insert_participation_in, NewParticipation};
use super::{array32, hex, Store, StoreError};

/// Where a plan stands. See the schema for each state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanState {
	Open,
	Done,
	Cancelled,
	Stopped,
}

impl PlanState {
	pub fn as_str(self) -> &'static str {
		match self {
			PlanState::Open => "open",
			PlanState::Done => "done",
			PlanState::Cancelled => "cancelled",
			PlanState::Stopped => "stopped",
		}
	}

	fn parse(s: &str) -> Result<PlanState, StoreError> {
		Ok(match s {
			"open" => PlanState::Open,
			"done" => PlanState::Done,
			"cancelled" => PlanState::Cancelled,
			"stopped" => PlanState::Stopped,
			other => return Err(StoreError::Corrupt(format!("plan state {}", other))),
		})
	}
}

/// Where a step stands. See the schema for each state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepState {
	Waiting,
	Running,
	Done,
	Void,
}

impl StepState {
	pub fn as_str(self) -> &'static str {
		match self {
			StepState::Waiting => "waiting",
			StepState::Running => "running",
			StepState::Done => "done",
			StepState::Void => "void",
		}
	}

	fn parse(s: &str) -> Result<StepState, StoreError> {
		Ok(match s {
			"waiting" => StepState::Waiting,
			"running" => StepState::Running,
			"done" => StepState::Done,
			"void" => StepState::Void,
			other => return Err(StoreError::Corrupt(format!("plan step state {}", other))),
		})
	}
}

/// One step of a plan to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPlanStep {
	pub idx: u16,
	pub value: u64,
	pub fee: u64,
	pub owner_key: [u8; 32],
	pub owner_nonce: [u8; 32],
	pub operator_nonce: [u8; 32],
	pub exit_delay_units: u16,
	pub unlock_hash: [u8; 32],
	pub preimage: [u8; 32],
	pub holder_script: Vec<u8>,
	pub operator_script: Vec<u8>,
	pub margin: u64,
	pub old_half: [u8; 64],
	pub new_half: [u8; 64],
	pub key_proof: [u8; 64],
	pub mailbox_proof: [u8; 64],
	/// The id the step's participation will have, which its leaf's salt is
	/// promised to.
	pub participation_id: [u8; 32],
}

/// A plan to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPlan {
	pub plan_id: [u8; 32],
	pub coin: [u8; 32],
	pub asset: [u8; 32],
	pub value: u64,
	pub first_owner: [u8; 32],
	pub first_salt: [u8; 32],
	pub first_delay: u16,
	pub mailbox_key: [u8; 32],
	pub attestation: [u8; 64],
	/// The quote whose operator nonces the steps name.
	pub quote: [u8; 32],
	pub steps: Vec<NewPlanStep>,
}

/// A step as the database holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStepRow {
	pub step: NewPlanStep,
	pub state: StepState,
	pub reason: Option<String>,
	/// The step's participation, once it runs.
	pub participation: Option<[u8; 32]>,
	/// The leaf its round made, once it is in one.
	pub leaf_id: Option<[u8; 32]>,
}

/// A plan as the database holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRow {
	pub plan_id: [u8; 32],
	pub coin: [u8; 32],
	pub asset: [u8; 32],
	pub value: u64,
	pub first_owner: [u8; 32],
	pub first_salt: [u8; 32],
	pub first_delay: u16,
	pub mailbox_key: [u8; 32],
	pub attestation: [u8; 64],
	pub state: PlanState,
	pub reason: Option<String>,
	pub steps: Vec<PlanStepRow>,
}

impl PlanRow {
	/// The step whose turn it is: the first that is not done, while the plan
	/// is open.
	pub fn next(&self) -> Option<&PlanStepRow> {
		if self.state != PlanState::Open {
			return None;
		}
		self.steps.iter().find(|s| s.state != StepState::Done)
	}

	/// The coin the next step gives up: the plan's first coin, or the leaf
	/// the step before it made.
	pub fn current_coin(&self) -> Option<[u8; 32]> {
		let mut coin = Some(self.coin);
		for s in &self.steps {
			if s.state != StepState::Done {
				break;
			}
			coin = s.leaf_id;
		}
		coin
	}
}

fn sig64(v: Vec<u8>, what: &str) -> Result<[u8; 64], StoreError> {
	v.try_into().map_err(|_| StoreError::Corrupt(format!("{} is not 64 bytes", what)))
}

fn u64_of(v: i64, what: &str) -> Result<u64, StoreError> {
	u64::try_from(v).map_err(|_| StoreError::Corrupt(format!("{} {}", what, v)))
}

fn i64_of(v: u64) -> Result<i64, StoreError> {
	i64::try_from(v).map_err(|_| StoreError::Corrupt(format!("amount {}", v)))
}

async fn read_plan<C: tokio_postgres::GenericClient>(c: &C, id: &[u8; 32]) -> Result<Option<PlanRow>, StoreError> {
	let Some(r) = c.query_opt(
		"SELECT plan_id, coin, asset, value, first_owner, first_salt, first_delay, mailbox_key, attestation, state::text, reason
		 FROM plan WHERE plan_id = $1",
		&[&&id[..]],
	).await? else { return Ok(None) };
	let mut plan = PlanRow {
		plan_id: array32(r.get(0), "plan id")?,
		coin: array32(r.get(1), "coin")?,
		asset: array32(r.get(2), "asset")?,
		value: u64_of(r.get(3), "value")?,
		first_owner: array32(r.get(4), "owner")?,
		first_salt: array32(r.get(5), "salt")?,
		first_delay: r.get::<_, i32>(6) as u16,
		mailbox_key: array32(r.get(7), "mailbox key")?,
		attestation: sig64(r.get(8), "attestation")?,
		state: PlanState::parse(r.get(9))?,
		reason: r.get(10),
		steps: vec![],
	};
	for r in c.query(
		"SELECT s.idx, s.value, s.fee, s.owner_key, s.owner_nonce, s.operator_nonce, s.exit_delay_units, s.unlock_hash, s.preimage,
		        s.holder_script, s.operator_script, s.margin, s.old_half, s.new_half, s.key_proof, s.mailbox_proof,
		        s.participation_id, s.state::text, s.reason,
		        (SELECT o.leaf_id FROM participation_output o WHERE o.participation_id = s.participation_id AND o.idx = 0)
		 FROM plan_step s WHERE s.plan_id = $1 ORDER BY s.idx",
		&[&&id[..]],
	).await? {
		let participation: Option<Vec<u8>> = r.get(16);
		let leaf: Option<Vec<u8>> = r.get(19);
		let pid = participation.map(|p| array32(p, "participation id")).transpose()?;
		plan.steps.push(PlanStepRow {
			step: NewPlanStep {
				idx: r.get::<_, i16>(0) as u16,
				value: u64_of(r.get(1), "value")?,
				fee: u64_of(r.get(2), "fee")?,
				owner_key: array32(r.get(3), "owner key")?,
				owner_nonce: array32(r.get(4), "owner nonce")?,
				operator_nonce: array32(r.get(5), "operator nonce")?,
				exit_delay_units: r.get::<_, i32>(6) as u16,
				unlock_hash: array32(r.get(7), "unlock hash")?,
				preimage: array32(r.get(8), "preimage")?,
				holder_script: r.get(9),
				operator_script: r.get(10),
				margin: u64_of(r.get(11), "margin")?,
				old_half: sig64(r.get(12), "half")?,
				new_half: sig64(r.get(13), "half")?,
				key_proof: sig64(r.get(14), "key proof")?,
				mailbox_proof: sig64(r.get(15), "mailbox proof")?,
				participation_id: pid.unwrap_or([0; 32]),
			},
			state: StepState::parse(r.get(17))?,
			reason: r.get(18),
			participation: pid,
			leaf_id: leaf.map(|l| array32(l, "leaf id")).transpose()?,
		});
	}
	Ok(Some(plan))
}

impl Store {
	/// Draws `n` fresh operator nonces for a plan quote, each recorded as
	/// issued and taken by `quote` at once: a plan submitted later may name
	/// them for its steps, and nothing else ever takes them.
	pub async fn draw_quote_nonces(&self, quote: &[u8; 32], n: usize) -> Result<Vec<[u8; 32]>, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let mut out = Vec::with_capacity(n);
		for _ in 0..n {
			out.push(draw_nonce(&t, quote).await?);
		}
		t.commit().await?;
		Ok(out)
	}

	/// The script the quote `quote` names for the operator's share of every
	/// refund: `script` the first time, the one named before after that.
	pub async fn quote_script_or(&self, quote: &[u8; 32], script: &[u8]) -> Result<Vec<u8>, StoreError> {
		let conn = self.conn().await?;
		conn.execute("INSERT INTO plan_quote (quote_id, operator_script) VALUES ($1, $2) ON CONFLICT DO NOTHING",
			&[&&quote[..], &script]).await?;
		let r = conn.query_one("SELECT operator_script FROM plan_quote WHERE quote_id = $1", &[&&quote[..]]).await?;
		Ok(r.get(0))
	}

	/// The script the quote `quote` named, if there is such a quote.
	pub async fn quote_script(&self, quote: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt("SELECT operator_script FROM plan_quote WHERE quote_id = $1", &[&&quote[..]]).await?;
		Ok(r.map(|r| r.get(0)))
	}

	/// Every plan that is open or stopped: its current coin is held unswept.
	pub async fn unfinished_plans(&self) -> Result<Vec<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query("SELECT plan_id FROM plan WHERE state IN ('open', 'stopped') ORDER BY created_at, plan_id", &[]).await?;
		rows.into_iter().map(|r| array32(r.get(0), "plan id")).collect()
	}

	/// Whether the batch output of the batch the leaf `leaf` rests on is
	/// spent by a sweep of the watcher's whose transaction is final.
	pub async fn batch_swept_final(&self, leaf: &[u8; 32]) -> Result<bool, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(
			"SELECT 1 FROM batch_leaf bl JOIN round r ON r.round_id = bl.round_id
			 JOIN watcher_input wi ON wi.prev_txid = r.txid AND wi.prev_vout = bl.vout
			 JOIN watcher_tx w ON w.txid = wi.txid AND w.kind = 'sweep'
			 JOIN nursery_tx n ON n.txid = w.txid AND n.state = 'final'
			 WHERE bl.leaf_id = $1",
			&[&&leaf[..]],
		).await?;
		Ok(r.is_some())
	}

	/// Records a plan, whole or not at all: its coin live and named by no
	/// other open plan; each step's operator nonce one the quote took, now
	/// taken by the step; each step's key owning no leaf and wanted by no
	/// participation or other step; each step's salt new to the server and
	/// promised to the step's participation; and each step's key bound to
	/// the plan's mailbox key (a key bound already keeps its binding).
	pub async fn insert_plan(&self, p: &NewPlan) -> Result<(), StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let state: Option<String> = t.query_opt("SELECT state::text FROM leaf WHERE leaf_id = $1 FOR UPDATE", &[&&p.coin[..]]).await?
			.map(|r| r.get(0));
		match state.as_deref() {
			Some("live") => {},
			Some("spent") => return Err(StoreError::LeafSpent(hex(&p.coin))),
			Some(_) => return Err(StoreError::LeafNotLive(hex(&p.coin), "not live")),
			None => return Err(StoreError::LeafUnknown(hex(&p.coin))),
		}
		let r = t.execute(
			"INSERT INTO plan (plan_id, coin, asset, value, first_owner, first_salt, first_delay, mailbox_key, attestation)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
			&[&&p.plan_id[..], &&p.coin[..], &&p.asset[..], &i64_of(p.value)?, &&p.first_owner[..], &&p.first_salt[..],
				&(p.first_delay as i32), &&p.mailbox_key[..], &&p.attestation[..]],
		).await;
		if let Err(e) = r {
			if StoreError::is_unique(&e, "plan_pkey") {
				return Err(StoreError::PlanExists);
			}
			if StoreError::is_unique(&e, "plan_open_coin") {
				return Err(StoreError::CoinPlanned(hex(&p.coin)));
			}
			return Err(e.into());
		}
		for s in &p.steps {
			let used: Option<Option<Vec<u8>>> = t.query_opt("SELECT used_by FROM operator_nonce WHERE nonce = $1 FOR UPDATE",
				&[&&s.operator_nonce[..]]).await?.map(|r| r.get(0));
			match used {
				None => return Err(StoreError::NonceUnknown),
				Some(Some(by)) if by == p.quote => {},
				Some(_) => return Err(StoreError::NonceUsed),
			}
			t.execute("UPDATE operator_nonce SET used_by = $2, used_at = now() WHERE nonce = $1",
				&[&&s.operator_nonce[..], &&s.participation_id[..]]).await?;
			if t.query_opt("SELECT 1 FROM leaf WHERE owner_key = $1 AND state NOT IN ('lost', 'expired')", &[&&s.owner_key[..]]).await?.is_some()
				|| t.query_opt("SELECT 1 FROM participation_output WHERE owner_key = $1 AND kind = 'leaf'", &[&&s.owner_key[..]]).await?.is_some()
			{
				return Err(StoreError::KeyReused);
			}
			let salt = arca_covenant::leaf::leaf_salt(&s.owner_nonce, &s.operator_nonce);
			if !super::coins::promise_salt(&t, &salt, &s.participation_id).await? {
				return Err(StoreError::SaltReused(hex(&salt)));
			}
			if t.query_opt("SELECT 1 FROM participation WHERE unlock_hash = $1", &[&&s.unlock_hash[..]]).await?.is_some() {
				return Err(StoreError::UnlockHashReused);
			}
			let r = t.execute(
				"INSERT INTO plan_step (plan_id, idx, value, fee, owner_key, owner_nonce, operator_nonce, exit_delay_units, unlock_hash,
				 preimage, holder_script, operator_script, margin, old_half, new_half, key_proof, mailbox_proof)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
				&[&&p.plan_id[..], &(s.idx as i16), &i64_of(s.value)?, &i64_of(s.fee)?, &&s.owner_key[..], &&s.owner_nonce[..],
					&&s.operator_nonce[..], &(s.exit_delay_units as i32), &&s.unlock_hash[..], &&s.preimage[..], &s.holder_script,
					&s.operator_script, &i64_of(s.margin)?, &&s.old_half[..], &&s.new_half[..], &&s.key_proof[..], &&s.mailbox_proof[..]],
			).await;
			if let Err(e) = r {
				if StoreError::is_unique(&e, "plan_step_owner_key_key") {
					return Err(StoreError::KeyReused);
				}
				if StoreError::is_unique(&e, "plan_step_unlock_hash_key") {
					return Err(StoreError::UnlockHashReused);
				}
				return Err(e.into());
			}
			t.execute(
				"INSERT INTO leaf_mailbox (owner_key, mailbox_key, proof) VALUES ($1, $2, $3) ON CONFLICT (owner_key) DO NOTHING",
				&[&&s.owner_key[..], &&p.mailbox_key[..], &&s.mailbox_proof[..]],
			).await?;
		}
		t.commit().await?;
		Ok(())
	}

	/// The plan `id`, with its steps.
	pub async fn plan(&self, id: &[u8; 32]) -> Result<Option<PlanRow>, StoreError> {
		let conn = self.conn().await?;
		read_plan(&*conn, id).await
	}

	/// The plans whose leaves are bound to the mailbox `key`, the newest
	/// first.
	pub async fn plans_of_mailbox(&self, key: &[u8; 32]) -> Result<Vec<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query("SELECT plan_id FROM plan WHERE mailbox_key = $1 ORDER BY created_at DESC, plan_id", &[&&key[..]]).await?;
		rows.into_iter().map(|r| array32(r.get(0), "plan id")).collect()
	}

	/// Every open plan.
	pub async fn open_plans(&self) -> Result<Vec<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query("SELECT plan_id FROM plan WHERE state = 'open' ORDER BY created_at, plan_id", &[]).await?;
		rows.into_iter().map(|r| array32(r.get(0), "plan id")).collect()
	}

	/// The plan and step whose participation `id` is, if it is one.
	pub async fn plan_step_of(&self, id: &[u8; 32]) -> Result<Option<([u8; 32], u16)>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt("SELECT plan_id, idx FROM plan_step WHERE participation_id = $1", &[&&id[..]]).await?;
		r.map(|r| Ok((array32(r.get(0), "plan id")?, r.get::<_, i16>(1) as u16))).transpose()
	}

	/// The plans that name the coin `leaf`: as the coin a plan starts from, or
	/// as a leaf a step made. Whatever their state: a coin a plan named
	/// carries its holder's refund halves for as long as its script is
	/// unspent.
	pub async fn plans_naming(&self, leaf: &[u8; 32]) -> Result<Vec<([u8; 32], &'static str)>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT plan_id, 'first' FROM plan WHERE coin = $1
			 UNION SELECT s.plan_id, 'made' FROM plan_step s JOIN participation_output o
			   ON o.participation_id = s.participation_id AND o.idx = 0 WHERE o.leaf_id = $1",
			&[&&leaf[..]],
		).await?;
		rows.into_iter().map(|r| {
			let kind: &str = r.get(1);
			Ok((array32(r.get(0), "plan id")?, if kind == "first" { "first" } else { "made" }))
		}).collect()
	}

	/// Starts step `idx` of plan `plan`: records its participation `p`, its
	/// leaf under the operator nonce the plan named, and the step running.
	/// `false` when the step is not waiting any more.
	pub async fn start_step(&self, plan: &[u8; 32], idx: u16, p: &NewParticipation) -> Result<bool, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let state: Option<String> = t.query_opt(
			"SELECT s.state::text FROM plan_step s JOIN plan USING (plan_id) WHERE s.plan_id = $1 AND s.idx = $2 AND plan.state = 'open'
			 FOR UPDATE",
			&[&&plan[..], &(idx as i16)],
		).await?.map(|r| r.get(0));
		if state.as_deref() != Some("waiting") {
			return Ok(false);
		}
		insert_participation_in(&t, p, true).await?;
		t.execute(
			"UPDATE plan_step SET state = 'running', participation_id = $3, updated_at = now() WHERE plan_id = $1 AND idx = $2",
			&[&&plan[..], &(idx as i16), &&p.id[..]],
		).await?;
		t.commit().await?;
		Ok(true)
	}

	/// Completes step `idx` of plan `plan`, whose participation is issued in
	/// a final round: the participation released, the leaf its round made for
	/// the step credited (its record waits for the holder's unroll
	/// authorisations), the step done, and the plan done after its last step.
	/// `false` when the step is not running in a final round.
	pub async fn finish_step(&self, plan: &[u8; 32], idx: u16) -> Result<bool, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let r = t.query_opt(
			"SELECT s.participation_id FROM plan_step s JOIN participation p ON p.participation_id = s.participation_id
			 JOIN round r ON r.round_id = p.round_id
			 WHERE s.plan_id = $1 AND s.idx = $2 AND s.state = 'running' AND p.state = 'issued' AND r.state = 'final'
			 FOR UPDATE OF s, p",
			&[&&plan[..], &(idx as i16)],
		).await?;
		let Some(r) = r else { return Ok(false) };
		let pid: Vec<u8> = r.get(0);
		t.execute("UPDATE participation SET state = 'released', updated_at = now() WHERE participation_id = $1", &[&pid]).await?;
		t.execute(
			"UPDATE leaf SET state = 'live', updated_at = now() WHERE state = 'pending' AND leaf_id IN (
			   SELECT bl.leaf_id FROM batch_leaf bl JOIN participation p
			   ON p.participation_id = bl.participation_id AND p.attempt = bl.attempt AND p.round_id = bl.round_id
			   WHERE bl.participation_id = $1)",
			&[&pid],
		).await?;
		t.execute("UPDATE plan_step SET state = 'done', updated_at = now() WHERE plan_id = $1 AND idx = $2", &[&&plan[..], &(idx as i16)])
			.await?;
		t.execute(
			"UPDATE plan SET state = 'done', updated_at = now() WHERE plan_id = $1 AND state = 'open'
			 AND NOT EXISTS (SELECT 1 FROM plan_step WHERE plan_id = $1 AND state <> 'done')",
			&[&&plan[..]],
		).await?;
		t.commit().await?;
		Ok(true)
	}

	/// Step `idx` of plan `plan` can never run: the step void with `reason`,
	/// and the plan stopped with it, unless it was over already. Its
	/// participation, if it has one, is voided by the caller.
	pub async fn void_step(&self, plan: &[u8; 32], idx: u16, reason: &str) -> Result<bool, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		let n = t.execute(
			"UPDATE plan_step SET state = 'void', reason = $3, updated_at = now() WHERE plan_id = $1 AND idx = $2 AND state <> 'done'",
			&[&&plan[..], &(idx as i16), &reason],
		).await?;
		t.execute(
			"UPDATE plan SET state = 'stopped', reason = $2, updated_at = now() WHERE plan_id = $1 AND state = 'open'",
			&[&&plan[..], &format!("step {}: {}", idx, reason)],
		).await?;
		t.commit().await?;
		Ok(n == 1)
	}

	/// Cancels the steps of plan `plan` that have not started: the plan,
	/// open or stopped, cancelled with `reason`. `false` when a step is
	/// running (its round decides it first) or the plan is over.
	pub async fn cancel_plan(&self, plan: &[u8; 32], reason: &str) -> Result<bool, StoreError> {
		let mut conn = self.conn().await?;
		let t = conn.transaction().await?;
		if t.query_opt("SELECT 1 FROM plan_step WHERE plan_id = $1 AND state = 'running' FOR UPDATE", &[&&plan[..]]).await?.is_some() {
			return Ok(false);
		}
		let n = t.execute(
			"UPDATE plan SET state = 'cancelled', reason = $2, updated_at = now() WHERE plan_id = $1 AND state IN ('open', 'stopped')",
			&[&&plan[..], &reason],
		).await?;
		t.commit().await?;
		Ok(n == 1)
	}

	/// The coin record of a leaf a plan's step made, once its holder has
	/// handed over its unroll authorisations; a record already there stays.
	/// `false` when it was there.
	pub async fn set_plan_leaf_record(&self, leaf_id: &[u8; 32], record: &[u8]) -> Result<bool, StoreError> {
		let conn = self.conn().await?;
		let n = conn.execute("UPDATE leaf SET record = $2, updated_at = now() WHERE leaf_id = $1 AND kind = 'batch' AND record = ''::bytea",
			&[&&leaf_id[..], &record]).await?;
		Ok(n == 1)
	}
}
