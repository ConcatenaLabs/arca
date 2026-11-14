//! `sync` and `deposits` in slices (`budget_ms`).
//!
//! The library runs one command at a time, and a command runs to its end. A
//! program that answers others from the wallet (a maker's firm offer, a
//! page's trade) asks for `sync` and `deposits` with `budget_ms`: the
//! command stops at the first safe point past that many milliseconds,
//! answers `more: true`, and the next call with the same arguments goes on
//! where it stopped. Between two calls the program runs whatever it was
//! asked. Without `budget_ms` everything runs in one call, as it always has.
//!
//! **Safe points.** A slice stops only between two steps of `sync`, or
//! between two items of a long step ([`ITEMS`]): a participation, a coin's
//! refresh, a coin's deposit, a coin taken home, an exit moved on, a payment
//! over Lightning, a plan, an order. An item that has started runs to its
//! end, so nothing is ever cut between a signature and its record, between
//! handing over forfeits and recording it, or between a broadcast and its
//! record; nor are the deposits a trade's coins go to at once, before the
//! trade is reported done, which run outside the slice. Any other step runs
//! whole in one slice and runs once a pass.
//! Each step reads what it needs from the store and the operator when it
//! runs: nothing read in one slice is used in another, so a command run
//! between two slices (a payment, a refresh, a trade) is seen by every step
//! after it.
//!
//! **The resume point** is kept in the store ([`SYNC_RESUME`]): the step to
//! run next, the items of that step already done in this pass, and what the
//! steps done so far answered, each with the slice it ran in. A process that
//! stops between two slices goes on from there; one that stops inside a
//! slice goes on from the slice before, and each step it runs again finds
//! its finished items finished in the store. A resumed slice takes the
//! witness of the operator's signer's record again before it asks the
//! operator anything, and the re-check every other command takes at its
//! start: the lineage watch while the chain's tip is the one the last
//! complete re-check ran at, the whole re-check when it is not, so no slice
//! acts on a tip it has not looked at (its changes join the pass's). A
//! slice whose witness fails has waited out the witness's patience: it runs
//! the rest of the pass, as one call does, so the patience is paid once a
//! pass and the steps that take coins home when the operator cannot be
//! reached come in every pass.
//!
//! A resume point is kept for each set of arguments, so a caller that syncs
//! in slices with other arguments than another (`catch_up`, `deposits`)
//! goes on with its own pass and never drops the other's. A resume point
//! older than [`RESUME_FOR`] seconds of median time is dropped: the next
//! call with its arguments starts a whole pass, re-check included, and
//! answers `more` until that pass is done. A call without `budget_ms` runs
//! a whole pass at once and drops every resume point.
//!
//! **What a sliced pass answers.** Each slice but the last answers
//! `{"more": true, "next": <step>, "slice": <n>, "cost_by_step": ...,
//! "recheck": ...}`, `recheck` being the re-check that slice ran. The
//! last answers what one whole `sync` answers, and `slices`: each part is
//! what its step did, in the slice named in `cost_by_step.<step>.slice`;
//! it reports what was done then, not the coins as they stand now, which
//! `coins` and `balance` read.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use super::{Error, Wallet};

/// The store key of a sliced `sync`'s resume point.
pub const SYNC_RESUME: &str = "sync_resume";
/// The store key of a sliced `deposits`'s done items.
pub const DEPOSITS_RESUME: &str = "deposits_resume";
/// How long a resume point is good for, in seconds of median time: past
/// it the chain has moved on, and the pass starts again from the re-check.
pub const RESUME_FOR: u32 = 600;

/// The steps of `sync` after the witness, in the order they run.
pub const STEPS: [&str; 24] = ["owed deposits", "held", "boards", "transfers", "lightning", "receives", "mailbox", "locks", "catch up", "history",
	"bound", "owed", "participations", "plans", "orders", "offboards", "resting", "receives again", "refresh", "forfeits", "deposits",
	"home", "exits", "reboards"];
/// The steps cut between two of their items. Every other step runs whole
/// within one slice and is never run again in its pass, whatever it calls.
pub const ITEMS: [&str; 13] = ["owed deposits", "held", "lightning", "receives", "participations", "plans", "orders", "resting",
	"receives again", "refresh", "deposits", "home", "exits"];
/// The last step, which runs in the last slice: `schedule`.
pub const LAST: &str = "schedule";

/// A slice under way: when it ends, and the items of the current step done.
#[derive(Debug)]
pub(crate) struct Slice {
	pub deadline: web_time::Instant,
	/// The items of the step done in this pass, by key.
	pub done: BTreeSet<String>,
	/// Items started in this slice of the step.
	pub ran: usize,
	/// Whether the step stopped before its last item.
	pub cut: bool,
}

/// What a loop over a step's items does with the next one.
pub(crate) enum Item {
	/// Run it.
	Go,
	/// Done earlier in this pass: pass over it.
	Skip,
	/// The slice is spent: stop the step here.
	Stop,
}

/// Where a sliced pass stands: the store's [`SYNC_RESUME`].
#[derive(Debug, Clone)]
pub(crate) struct Resume {
	pub args: Value,
	/// The median time the pass started.
	pub started: u32,
	/// The exit steps' watch, as the last slice left it.
	pub watch: u32,
	/// The step to run next ([`STEPS`], or [`LAST`]).
	pub next: String,
	/// Its items done in this pass.
	pub done: BTreeSet<String>,
	/// What each step done so far answered.
	pub out: serde_json::Map<String, Value>,
	/// What each step cost, over every slice.
	pub cost: serde_json::Map<String, Value>,
	/// The slices run so far, this one included.
	pub slices: u64,
	/// What each step cost in this slice alone.
	pub last: serde_json::Map<String, Value>,
}

impl Resume {
	pub fn new(args: Value, started: u32) -> Resume {
		Resume { args, started, watch: started, next: STEPS[0].into(), done: BTreeSet::new(), out: serde_json::Map::new(),
			cost: serde_json::Map::new(), slices: 1, last: serde_json::Map::new() }
	}

	fn to_json(&self) -> Value {
		json!({"args": self.args, "started": self.started, "watch": self.watch, "next": self.next, "done": self.done,
			"out": self.out, "cost": self.cost, "slices": self.slices})
	}

	fn from_json(v: &Value) -> Option<Resume> {
		Some(Resume {
			args: v["args"].clone(),
			started: v["started"].as_u64()? as u32,
			watch: v["watch"].as_u64()? as u32,
			next: v["next"].as_str()?.to_string(),
			done: serde_json::from_value(v["done"].clone()).ok()?,
			out: v["out"].as_object()?.clone(),
			cost: v["cost"].as_object()?.clone(),
			slices: v["slices"].as_u64()?,
			last: serde_json::Map::new(),
		})
	}

	/// The position of step `name` in the pass.
	pub fn index(name: &str) -> usize {
		STEPS.iter().position(|s| *s == name).unwrap_or(STEPS.len())
	}

	/// Adds a slice's cost of each step to the pass's: times and requests
	/// summed, the slice the step ended in noted (`slice`).
	pub fn add_cost(&mut self, slice: Value) {
		let Value::Object(slice) = slice else { return };
		self.last = slice.clone();
		for (k, v) in &slice {
			let mut v = v.clone();
			if let Some(was) = self.cost.get(k) {
				for f in ["ms", "node", "operator", "operator_ms", "blocks"] {
					if let (Some(a), Some(b)) = (was[f].as_u64(), v[f].as_u64()) {
						v[f] = json!(a + b);
					}
				}
			}
			v["slice"] = json!(self.slices);
			self.cost.insert(k.clone(), v);
		}
	}
}

impl Wallet {
	/// The resume points of the passes under way, one an argument set, as
	/// kept: every entry, by its arguments.
	fn resumes(&self) -> Result<serde_json::Map<String, Value>, Error> {
		let kept = self.store.meta(SYNC_RESUME)?.and_then(|v| serde_json::from_str::<Value>(&v).ok());
		Ok(match kept {
			Some(Value::Object(m)) => m,
			_ => serde_json::Map::new(),
		})
	}

	fn keep_resumes(&self, m: &serde_json::Map<String, Value>) -> Result<(), Error> {
		if m.is_empty() {
			self.store.delete_meta(SYNC_RESUME)
		} else {
			self.store.set_meta(SYNC_RESUME, &Value::Object(m.clone()).to_string())
		}
	}

	/// The resume point of a sliced `sync` with arguments `args`, at median
	/// time `now`: `None` when there is none. Every resume point older than
	/// [`RESUME_FOR`], or that cannot be read, is dropped. A pass is kept for
	/// each argument set, so a caller never drops another's: two programs, or
	/// two loops of one, that sync in slices with other arguments each end
	/// their own passes.
	pub(crate) fn sync_resume(&self, now: u32, args: &Value) -> Result<Option<Resume>, Error> {
		let mut m = self.resumes()?;
		let before = m.len();
		m.retain(|_, v| Resume::from_json(v).is_some_and(|r| now >= r.started && now - r.started <= RESUME_FOR));
		if m.len() != before {
			self.keep_resumes(&m)?;
		}
		Ok(m.get(&args.to_string()).and_then(Resume::from_json))
	}

	pub(crate) fn keep_resume(&self, r: &Resume) -> Result<(), Error> {
		let mut m = self.resumes()?;
		m.insert(r.args.to_string(), r.to_json());
		self.keep_resumes(&m)
	}

	/// Drops the resume point of the pass with arguments `args`: it ended,
	/// or failed.
	pub(crate) fn drop_resume(&self, args: &Value) -> Result<(), Error> {
		let mut m = self.resumes()?;
		if m.remove(&args.to_string()).is_some() {
			self.keep_resumes(&m)?;
		}
		Ok(())
	}

	/// Whether a sliced pass is under way: `sync`'s schedule is due while
	/// one is.
	pub(crate) fn sync_in_slices(&self) -> Result<bool, Error> {
		Ok(!self.resumes()?.is_empty())
	}

	/// The next item `key` of the step under way: run, passed over (done
	/// earlier in this pass) or stopped at (the slice is spent, and at least
	/// one item ran in it). Always run outside a slice.
	pub(crate) fn slice_item(&self, key: &str) -> Item {
		let mut s = self.slice.borrow_mut();
		let Some(s) = s.as_mut() else { return Item::Go };
		if s.done.contains(key) {
			return Item::Skip;
		}
		if s.cut || (s.ran > 0 && web_time::Instant::now() >= s.deadline) {
			s.cut = true;
			return Item::Stop;
		}
		s.done.insert(key.to_string());
		s.ran += 1;
		Item::Go
	}

	/// Whether the step under way stopped before its last item.
	pub(crate) fn slice_cut(&self) -> bool {
		self.slice.borrow().as_ref().is_some_and(|s| s.cut)
	}

	/// `deposits`; with `budget_ms`, in slices: it stops at the first coin
	/// past the budget, answers `{"deposits": [...], "more": true}`, and the
	/// next call goes on; the last answers without `more`. Without it, the
	/// list as always.
	pub fn deposits_within(&mut self, budget_ms: Option<u64>) -> Result<Value, Error> {
		let Some(b) = budget_ms else {
			self.store.delete_meta(DEPOSITS_RESUME)?;
			return self.progress_deposits().map(Value::Array);
		};
		let now = self.now()?.to_consensus_u32();
		let kept: Value = self.store.meta(DEPOSITS_RESUME)?.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or(Value::Null);
		let fresh = kept["started"].as_u64().is_some_and(|t| (now as u64) >= t && (now as u64) - t <= RESUME_FOR as u64);
		let (started, done) = if fresh {
			(kept["started"].as_u64().unwrap_or(now as u64), serde_json::from_value(kept["done"].clone()).unwrap_or_default())
		} else { (now as u64, BTreeSet::new()) };
		*self.slice.borrow_mut() = Some(Slice { deadline: web_time::Instant::now() + std::time::Duration::from_millis(b), done, ran: 0,
			cut: false });
		let out = self.progress_deposits();
		let s = self.slice.borrow_mut().take().expect("set above");
		let out = out?;
		if s.cut {
			self.store.set_meta(DEPOSITS_RESUME, &json!({"started": started, "done": s.done}).to_string())?;
			return Ok(json!({"deposits": out, "more": true}));
		}
		self.store.delete_meta(DEPOSITS_RESUME)?;
		Ok(json!({"deposits": out}))
	}
}
