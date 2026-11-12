//! What the passes over the whole history read: not every coin, sighting,
//! board and forfeit the operator ever handled, but the items logged in
//! `pass_open` as they may have opened (schema step 49).
//!
//! Each pass ([`Pass`]) is one statement of the whole history: an item is
//! open when it is a row of that statement. The triggers of schema step 49
//! log an item in the transaction of every write that can make it a row,
//! whichever code path writes it, so the open items are exactly the rows of
//! the whole statement whose key is logged. Each read here is the whole
//! statement, word for word, with its rows limited to the keys logged, read
//! through the indexes. [`Store::prune_open`] removes the keys whose items are
//! closed and the copies of a key: a key it removes can become a row again
//! only through a new write, which logs it again in its own transaction, out
//! of the snapshot of the statement removing it.
//!
//! [`Store::recount_open`] runs a pass's whole statement and its logged read
//! in one snapshot: every row of the whole statement must be logged. Run once
//! at a pass's first read after the schema step (which logs nothing, so that
//! first count fills the log), and then every [`RECOUNT_EVERY`] a process
//! runs, when a row not logged is a write the triggers missed: it is logged,
//! so the passes act on it, and counted (`arca_pass_recount_missing_total`).

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use super::{Store, StoreError};

/// How often a pass's log is checked against its whole statement.
pub const RECOUNT_EVERY: Duration = Duration::from_secs(30 * 60);

/// The passes over the whole history whose open items are logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Pass {
	/// An output paying the leaf or the checkpoint of a coin given up, not
	/// spent by a final transaction of the watcher's
	/// ([`Store::spent_coin_sightings`]); by outpoint.
	Sighting,
	/// A coin of a transfer given up with a forfeit stored, not claimed by a
	/// final claim ([`Store::forfeited_transfer_coins`]); by leaf id.
	TransferForfeit,
	/// A forfeit of the watcher's not lost and not spent by a final
	/// transaction of the watcher's ([`Store::unclaimed_forfeits`]); by txid.
	Forfeit,
	/// A credited board whose coin is given up with a forfeit stored, its
	/// output not spent by a final transaction of the watcher's
	/// ([`Store::boards_to_recover`]); by leaf id.
	Board,
	/// A coin given up whose value is in flight ([`Store::in_flight`]); by
	/// leaf id.
	Flight,
}

/// The passes the watcher reads.
pub const WATCHER_PASSES: [Pass; 4] = [Pass::Sighting, Pass::TransferForfeit, Pass::Forfeit, Pass::Board];

impl Pass {
	pub fn name(self) -> &'static str {
		match self {
			Pass::Sighting => "sighting",
			Pass::TransferForfeit => "transfer_forfeit",
			Pass::Forfeit => "forfeit",
			Pass::Board => "board",
			Pass::Flight => "flight",
		}
	}

	/// The key of a row: an id, and an output (0 when the key has none).
	fn key(self) -> (&'static str, &'static str) {
		match self {
			Pass::Sighting => ("s.txid", "s.vout"),
			Pass::TransferForfeit => ("l.leaf_id", "0"),
			Pass::Forfeit => ("w.txid", "0"),
			Pass::Board => ("b.leaf_id", "0"),
			Pass::Flight => ("h.root", "0"),
		}
	}

	/// The whole statement's common table expressions (or nothing) and its
	/// `FROM … WHERE …`, its rows limited to the keys logged when `logged`.
	pub(crate) fn body(self, logged: bool) -> (String, String) {
		let only = |k: &str, v: &str| if logged {
			format!(" AND ({}, {}) IN (SELECT k, v FROM pass_open WHERE pass = '{}')", k, v, self.name())
		} else {
			String::new()
		};
		let (k, v) = self.key();
		match self {
			Pass::Sighting => (String::new(), format!(
				"FROM script_sighting s JOIN arca_script a ON a.script_pubkey = s.script_pubkey JOIN leaf l ON l.leaf_id = a.leaf_id
				 WHERE a.kind IN ('leaf', 'checkpoint') AND l.state = 'spent' AND NOT {}{}",
				super::watcher::spent_final("s.txid", "s.vout"), only(k, v))),
			Pass::TransferForfeit => (String::new(), format!(
				"FROM leaf l JOIN forfeit f ON f.leaf_id = l.leaf_id
				 WHERE l.kind = 'transfer' AND l.state = 'spent'
				   AND NOT EXISTS (SELECT 1 FROM watcher_tx fw
				                   JOIN watcher_input wi ON wi.prev_txid = fw.txid AND wi.prev_vout = 0
				                   JOIN watcher_tx cw ON cw.txid = wi.txid AND cw.kind = 'claim'
				                   JOIN nursery_tx n ON n.txid = cw.txid
				                   WHERE fw.kind = 'forfeit' AND fw.subject = l.leaf_id AND n.state = 'final'){}", only(k, v))),
			Pass::Forfeit => (String::new(), format!(
				"FROM watcher_tx w JOIN nursery_tx n ON n.txid = w.txid
				 WHERE w.kind = 'forfeit' AND n.state <> 'lost' AND NOT {}{}", super::watcher::spent_final("w.txid", "0"), only(k, v))),
			Pass::Board => (String::new(), format!(
				"FROM board b JOIN leaf l ON l.leaf_id = b.leaf_id
				 WHERE b.state = 'credited' AND l.state = 'spent'
				   AND EXISTS (SELECT 1 FROM forfeit f WHERE f.leaf_id = b.leaf_id) AND NOT {}{}",
				super::watcher::spent_final("b.txid", "b.vout"), only(k, v))),
			Pass::Flight => (super::pool::in_flight_with(if logged {
				" AND pi.leaf_id IN (SELECT k FROM pass_open WHERE pass = 'flight')"
			} else {
				""
			}), "FROM held h".into()),
		}
	}

	/// The keys of the whole statement's rows (`logged`: of those logged), as
	/// `keys (k, v)` after `WITH`, or after the statement's own expressions.
	fn keys_with(self, logged: bool) -> String {
		let (with, from) = self.body(logged);
		let (k, v) = self.key();
		let keys = format!("keys AS (SELECT DISTINCT {} AS k, ({})::INTEGER AS v {})", k, v, from);
		if with.is_empty() { format!("WITH {}", keys) } else { format!("{}, {}", with, keys) }
	}
}

/// Where the log of each pass stands in this process.
#[derive(Default)]
pub(crate) struct OpenState {
	/// When each pass's log was last checked against its whole statement;
	/// absent until its first read in this process.
	counted: BTreeMap<Pass, Instant>,
	/// The rows the recounts found that no trigger logged, by pass.
	missing: BTreeMap<Pass, u64>,
}

impl Store {
	/// Before a pass's first read in this process. The first ever (the
	/// schema step logs nothing) checks the log against the whole statement
	/// and logs every row, quietly, and records that it did
	/// (`watch_cursor` `open:<pass>`); after that a process reads the log as
	/// it stands, and its first recount comes [`RECOUNT_EVERY`] after its
	/// start.
	pub(crate) async fn open_ready(&self, pass: Pass) -> Result<(), StoreError> {
		if self.open.lock().unwrap_or_else(|e| e.into_inner()).counted.contains_key(&pass) {
			return Ok(());
		}
		let marker = format!("open:{}", pass.name());
		if self.watch_cursor(&marker).await?.is_none() {
			let t = Instant::now();
			let (whole, added) = self.recount_open(pass).await?;
			self.set_watch_cursor(&marker, 1).await?;
			log::info!("{} pass: its log of open items filled from the whole history: {} item(s), {} logged, in {} ms",
				pass.name(), whole, added, t.elapsed().as_millis());
		}
		self.open.lock().unwrap_or_else(|e| e.into_inner()).counted.entry(pass).or_insert_with(Instant::now);
		Ok(())
	}

	/// Prunes the logs of `passes`, and checks each against its whole
	/// statement when [`RECOUNT_EVERY`] has passed since it was last: a row
	/// of the whole statement not logged is an alarm (logged at error and
	/// counted), and is logged so the passes act on it.
	pub async fn keep_open(&self, passes: &[Pass]) -> Result<(), StoreError> {
		for &pass in passes {
			self.open_ready(pass).await?;
			let due = self.open.lock().unwrap_or_else(|e| e.into_inner()).counted.get(&pass)
				.map_or(true, |at| at.elapsed() >= RECOUNT_EVERY);
			if due {
				let (whole, added) = self.recount_open(pass).await?;
				let mut o = self.open.lock().unwrap_or_else(|e| e.into_inner());
				o.counted.insert(pass, Instant::now());
				if added > 0 {
					*o.missing.entry(pass).or_default() += added;
					log::error!("{} pass: the recount found {} of {} open item(s) no trigger logged; logged now, so the passes act on \
						them. A write path the schema's triggers miss: report it.", pass.name(), added, whole);
				}
			}
			self.prune_open(pass).await?;
		}
		Ok(())
	}

	/// Removes from the log of `pass` the keys whose items are closed, and
	/// every copy of a key but one. One at a time, under an advisory lock, so
	/// two prunes never each keep a copy the other removes.
	pub async fn prune_open(&self, pass: Pass) -> Result<(u64, u64), StoreError> {
		let mut conn = self.conn().await?;
		let tx = conn.transaction().await?;
		tx.execute("SELECT pg_advisory_xact_lock(hashtext('pass_open'))", &[]).await?;
		let copies = tx.execute(
			"DELETE FROM pass_open a USING pass_open b
			 WHERE a.pass = $1 AND b.pass = a.pass AND b.k = a.k AND b.v = a.v AND b.ctid < a.ctid", &[&pass.name()]).await?;
		let closed = tx.execute(
			&format!("{} DELETE FROM pass_open o WHERE o.pass = '{}'
			          AND NOT EXISTS (SELECT 1 FROM keys x WHERE x.k = o.k AND x.v = o.v)", pass.keys_with(true), pass.name()),
			&[],
		).await?;
		tx.commit().await?;
		Ok((closed, copies))
	}

	/// Runs the whole statement of `pass` and its logged read in one
	/// snapshot, and logs every row of the whole statement not logged.
	/// Returns how many rows the whole statement has, and how many it logged.
	pub async fn recount_open(&self, pass: Pass) -> Result<(u64, u64), StoreError> {
		let mut conn = self.conn().await?;
		let tx = conn.build_transaction().isolation_level(tokio_postgres::IsolationLevel::RepeatableRead).start().await?;
		let read = |logged: bool| format!("{} SELECT k, v FROM keys", pass.keys_with(logged));
		let whole: BTreeSet<(Vec<u8>, i32)> = tx.query(&read(false), &[]).await?.iter().map(|r| (r.get(0), r.get(1))).collect();
		let logged: BTreeSet<(Vec<u8>, i32)> = tx.query(&read(true), &[]).await?.iter().map(|r| (r.get(0), r.get(1))).collect();
		if let Some(extra) = logged.difference(&whole).next() {
			return Err(StoreError::Corrupt(format!("the {} pass's logged read has a row its whole statement has not: {:?}", pass.name(), extra)));
		}
		let missing: Vec<&(Vec<u8>, i32)> = whole.difference(&logged).collect();
		if !missing.is_empty() {
			let ks: Vec<&[u8]> = missing.iter().map(|(k, _)| &k[..]).collect();
			let vs: Vec<i32> = missing.iter().map(|(_, v)| *v).collect();
			tx.execute("INSERT INTO pass_open (pass, k, v) SELECT $1, k, v FROM unnest($2::BYTEA[], $3::INTEGER[]) x(k, v)",
				&[&pass.name(), &ks, &vs]).await?;
		}
		tx.commit().await?;
		Ok((whole.len() as u64, missing.len() as u64))
	}

	/// The recounts' alarm, in the text format Prometheus reads.
	pub fn open_metrics(&self) -> String {
		let o = self.open.lock().unwrap_or_else(|e| e.into_inner());
		let mut out = String::from("# HELP arca_pass_recount_missing_total Items a recount of a pass over the whole history found \
			that the log of open items lacked: a write the schema's triggers miss.\n# TYPE arca_pass_recount_missing_total counter\n");
		for pass in WATCHER_PASSES.iter().chain([Pass::Flight].iter()) {
			out.push_str(&format!("arca_pass_recount_missing_total{{pass=\"{}\"}} {}\n", pass.name(), o.missing.get(pass).copied().unwrap_or(0)));
		}
		out
	}
}
