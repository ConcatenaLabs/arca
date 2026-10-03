//! The wallet's store: one SQLite database in the wallet's directory.
//!
//! It keeps what the specification says a client stores, and the wallet's own
//! bookkeeping:
//!
//! - **every owner nonce the wallet has drawn**, with the key it gives and what
//!   it was for. A nonce is written before its key is handed out or signs
//!   anything, and is never deleted: a key signs for one leaf only, and a
//!   nonce used twice would give two leaves one key;
//! - **every coin it holds or has held**, by leaf id, with its coin record
//!   (from which its lineage and every transaction that brings it on-chain
//!   follow), its state and its salt. A salt is unique: the wallet refuses a
//!   coin at a salt it has held a coin under, since its old pairs would spend
//!   it;
//! - **every forfeit it signs**, written before the signature leaves the
//!   wallet: the coin, the round and connector output it is bound to, the
//!   unlock hash, the refund delay and the margin, so the wallet can find the
//!   forfeit's output on the chain, read a preimage from its claim, or take
//!   the refund, whatever the server says;
//! - the transactions its coins rest on (rounds, boards), its participations
//!   with the new leaves it validated for them, its transfer requests, its
//!   swaps, its mailbox cursor, its exits, the refusals it made, and its
//!   on-chain derivation indices.
//!
//! The mnemonic is not here; it is the `mnemonic` file beside the database.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

use super::Error;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nonce (
	nonce BLOB PRIMARY KEY,
	owner_key BLOB NOT NULL UNIQUE,
	purpose TEXT NOT NULL,
	state TEXT NOT NULL,
	leaf_id TEXT,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS coin (
	leaf_id TEXT PRIMARY KEY,
	owner_nonce BLOB NOT NULL REFERENCES nonce(nonce),
	kind TEXT NOT NULL,
	asset TEXT NOT NULL,
	value INTEGER NOT NULL,
	record BLOB NOT NULL,
	salt BLOB NOT NULL UNIQUE,
	state TEXT NOT NULL,
	note TEXT NOT NULL DEFAULT '',
	expiry INTEGER NOT NULL,
	bases TEXT NOT NULL,
	spent_by TEXT,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tx (txid TEXT PRIMARY KEY, raw BLOB NOT NULL, role TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS participation (
	id TEXT PRIMARY KEY,
	body TEXT NOT NULL,
	given TEXT NOT NULL,
	wanted TEXT NOT NULL,
	state TEXT NOT NULL,
	preimage TEXT,
	round TEXT,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS transfer (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	body TEXT NOT NULL,
	inputs TEXT NOT NULL,
	state TEXT NOT NULL,
	answer TEXT,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS swap (
	id TEXT PRIMARY KEY,
	role TEXT NOT NULL,
	offer TEXT NOT NULL,
	accept TEXT,
	state TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS mailbox (key BLOB PRIMARY KEY, cursor INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS mailbox_retry (leaf_id TEXT PRIMARY KEY, record BLOB NOT NULL, reason TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS exit (leaf_id TEXT PRIMARY KEY, state TEXT NOT NULL, txs TEXT NOT NULL, claim TEXT);
CREATE TABLE IF NOT EXISTS forfeit (
	leaf_id TEXT NOT NULL,
	participation TEXT NOT NULL,
	round TEXT NOT NULL,
	connector_vout INTEGER NOT NULL,
	unlock_hash TEXT NOT NULL,
	refund_units INTEGER NOT NULL,
	margin INTEGER NOT NULL,
	from_height INTEGER NOT NULL,
	state TEXT NOT NULL,
	note TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	PRIMARY KEY (leaf_id, round)
);
CREATE TABLE IF NOT EXISTS refusal (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, what TEXT NOT NULL, reason TEXT NOT NULL);
";

/// A coin as the store holds it.
#[derive(Debug, Clone)]
pub struct CoinRow {
	pub leaf_id: String,
	pub owner_nonce: [u8; 32],
	/// `board`, `batch` or `transfer`.
	pub kind: String,
	pub asset: String,
	pub value: u64,
	/// The coin record, binary form.
	pub record: Vec<u8>,
	pub salt: [u8; 32],
	/// `pending`, `live`, `offered`, `sending`, `given` (in a participation,
	/// no forfeit signed), `forfeited` (a forfeit signed, its preimage not in
	/// hand), `spent`, `exiting`, `exited` or `lost`.
	pub state: String,
	pub note: String,
	/// The earliest first expiry of the batches it rests on (median time);
	/// `u32::MAX` for a coin from boards alone.
	pub expiry: u32,
	/// The txids of the rounds and boards it rests on.
	pub bases: Vec<String>,
	pub spent_by: Option<String>,
}

/// A forfeit the wallet signed, as the store holds it.
#[derive(Debug, Clone)]
pub struct ForfeitRow {
	/// The coin given up.
	pub leaf_id: String,
	pub participation: String,
	/// The round it is bound to, and that round's connector output: the
	/// forfeit can be claimed only while that round is in the chain.
	pub round: String,
	pub connector_vout: u32,
	pub unlock_hash: String,
	pub refund_units: u16,
	pub margin: u64,
	/// The height the wallet reads the chain from for it.
	pub from_height: u64,
	/// `signed` (its preimage not in hand), `settled` (the preimage in hand:
	/// the coin was exchanged for the new leaves), `claimed` (the operator
	/// claimed it on the chain, publishing the preimage), `refunded` (the
	/// wallet took the refund) or `void` (its round can never return).
	pub state: String,
	pub note: String,
}

/// A nonce as the store holds it.
#[derive(Debug, Clone)]
pub struct NonceRow {
	pub nonce: [u8; 32],
	pub owner_key: [u8; 32],
	pub purpose: String,
	pub state: String,
	pub leaf_id: Option<String>,
}

pub struct Store {
	conn: Connection,
}

fn db(e: rusqlite::Error) -> Error {
	Error::Store(e.to_string())
}

fn now() -> i64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn arr32(v: Vec<u8>) -> Result<[u8; 32], Error> {
	v.try_into().map_err(|_| Error::Store("a 32-byte column holds another length".into()))
}

impl Store {
	/// Opens (creating if needed) the database at `path`.
	pub fn open(path: &Path) -> Result<Store, Error> {
		let conn = Connection::open(path).map_err(db)?;
		conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;").map_err(db)?;
		conn.execute_batch(SCHEMA).map_err(db)?;
		let store = Store { conn };
		store.add_column("participation", "news", "TEXT")?;
		Ok(store)
	}

	/// Adds `column` to `table` in a store made before it existed.
	fn add_column(&self, table: &str, column: &str, kind: &str) -> Result<(), Error> {
		let has: bool = self.conn.prepare(&format!("SELECT 1 FROM pragma_table_info('{}') WHERE name = ?1", table)).map_err(db)?
			.exists(params![column]).map_err(db)?;
		if !has {
			self.conn.execute_batch(&format!("ALTER TABLE {} ADD COLUMN {} {}", table, column, kind)).map_err(db)?;
		}
		Ok(())
	}

	// --- meta ---

	pub fn meta(&self, key: &str) -> Result<Option<String>, Error> {
		self.conn.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| r.get(0)).optional().map_err(db)
	}

	pub fn set_meta(&self, key: &str, value: &str) -> Result<(), Error> {
		self.conn.execute("INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2", params![key, value])
			.map_err(db)?;
		Ok(())
	}

	/// The next index of on-chain `chain`, taken.
	pub fn take_index(&self, chain: u32) -> Result<u32, Error> {
		let key = format!("onchain_next_{}", chain);
		let next: u32 = self.meta(&key)?.map(|v| v.parse().unwrap_or(0)).unwrap_or(0);
		self.set_meta(&key, &(next + 1).to_string())?;
		Ok(next)
	}

	/// How many indices of on-chain `chain` have been taken.
	pub fn indices(&self, chain: u32) -> Result<u32, Error> {
		Ok(self.meta(&format!("onchain_next_{}", chain))?.map(|v| v.parse().unwrap_or(0)).unwrap_or(0))
	}

	// --- nonces ---

	/// Records a nonce drawn for `purpose`, with its key, before the key is
	/// used. A nonce or key the store already holds is refused.
	pub fn put_nonce(&self, nonce: &[u8; 32], owner_key: &[u8; 32], purpose: &str) -> Result<(), Error> {
		self.conn.execute("INSERT INTO nonce (nonce, owner_key, purpose, state, created_at) VALUES (?1, ?2, ?3, 'pending', ?4)",
			params![&nonce[..], &owner_key[..], purpose, now()])
			.map_err(|e| Error::Store(format!("a nonce or key the wallet already holds: {}", e)))?;
		Ok(())
	}

	fn nonce_row(r: &rusqlite::Row) -> rusqlite::Result<(Vec<u8>, Vec<u8>, String, String, Option<String>)> {
		Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
	}

	fn to_nonce(t: (Vec<u8>, Vec<u8>, String, String, Option<String>)) -> Result<NonceRow, Error> {
		Ok(NonceRow { nonce: arr32(t.0)?, owner_key: arr32(t.1)?, purpose: t.2, state: t.3, leaf_id: t.4 })
	}

	pub fn nonce(&self, nonce: &[u8; 32]) -> Result<Option<NonceRow>, Error> {
		let t = self.conn.query_row("SELECT nonce, owner_key, purpose, state, leaf_id FROM nonce WHERE nonce = ?1",
			params![&nonce[..]], Self::nonce_row).optional().map_err(db)?;
		t.map(Self::to_nonce).transpose()
	}

	pub fn nonces(&self) -> Result<Vec<NonceRow>, Error> {
		let mut st = self.conn.prepare("SELECT nonce, owner_key, purpose, state, leaf_id FROM nonce ORDER BY created_at").map_err(db)?;
		let rows = st.query_map([], Self::nonce_row).map_err(db)?.collect::<Result<Vec<_>, _>>().map_err(db)?;
		rows.into_iter().map(Self::to_nonce).collect()
	}

	/// Marks a nonce used by `leaf_id`. A nonce is used once.
	pub fn use_nonce(&self, nonce: &[u8; 32], leaf_id: &str) -> Result<(), Error> {
		let n = self.conn.execute("UPDATE nonce SET state = 'used', leaf_id = ?2 WHERE nonce = ?1 AND state = 'pending'",
			params![&nonce[..], leaf_id]).map_err(db)?;
		if n != 1 {
			return Err(Error::Refused(format!("the owner nonce {} is not one the wallet is waiting on a leaf for", super::chain::hex(nonce))));
		}
		Ok(())
	}

	// --- coins ---

	pub fn put_coin(&self, c: &CoinRow) -> Result<(), Error> {
		self.conn.execute(
			"INSERT INTO coin (leaf_id, owner_nonce, kind, asset, value, record, salt, state, note, expiry, bases, spent_by, created_at)
			 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
			params![c.leaf_id, &c.owner_nonce[..], c.kind, c.asset, c.value as i64, c.record, &c.salt[..], c.state, c.note,
				c.expiry as i64, serde_json::to_string(&c.bases).expect("strings"), c.spent_by, now()],
		).map_err(|e| Error::Store(format!("cannot keep coin {}: {}", c.leaf_id, e)))?;
		Ok(())
	}

	fn coin_row(r: &rusqlite::Row) -> rusqlite::Result<CoinRow> {
		let nonce: Vec<u8> = r.get(1)?;
		let salt: Vec<u8> = r.get(6)?;
		let bases: String = r.get(10)?;
		Ok(CoinRow {
			leaf_id: r.get(0)?,
			owner_nonce: nonce.try_into().unwrap_or([0; 32]),
			kind: r.get(2)?,
			asset: r.get(3)?,
			value: r.get::<_, i64>(4)? as u64,
			record: r.get(5)?,
			salt: salt.try_into().unwrap_or([0; 32]),
			state: r.get(7)?,
			note: r.get(8)?,
			expiry: r.get::<_, i64>(9)? as u32,
			bases: serde_json::from_str(&bases).unwrap_or_default(),
			spent_by: r.get(11)?,
		})
	}

	const COIN_COLS: &'static str = "leaf_id, owner_nonce, kind, asset, value, record, salt, state, note, expiry, bases, spent_by";

	pub fn coin(&self, leaf_id: &str) -> Result<Option<CoinRow>, Error> {
		self.conn.query_row(&format!("SELECT {} FROM coin WHERE leaf_id = ?1", Self::COIN_COLS), params![leaf_id], Self::coin_row)
			.optional().map_err(db)
	}

	pub fn coin_by_salt(&self, salt: &[u8; 32]) -> Result<Option<CoinRow>, Error> {
		self.conn.query_row(&format!("SELECT {} FROM coin WHERE salt = ?1", Self::COIN_COLS), params![&salt[..]], Self::coin_row)
			.optional().map_err(db)
	}

	/// Every coin, oldest first.
	pub fn coins(&self) -> Result<Vec<CoinRow>, Error> {
		let mut st = self.conn.prepare(&format!("SELECT {} FROM coin ORDER BY created_at, leaf_id", Self::COIN_COLS)).map_err(db)?;
		let rows = st.query_map([], Self::coin_row).map_err(db)?.collect::<Result<Vec<_>, _>>().map_err(db)?;
		Ok(rows)
	}

	pub fn coins_in(&self, state: &str) -> Result<Vec<CoinRow>, Error> {
		Ok(self.coins()?.into_iter().filter(|c| c.state == state).collect())
	}

	pub fn set_coin_state(&self, leaf_id: &str, state: &str, note: &str) -> Result<(), Error> {
		self.conn.execute("UPDATE coin SET state = ?2, note = ?3 WHERE leaf_id = ?1", params![leaf_id, state, note]).map_err(db)?;
		Ok(())
	}

	pub fn set_coin_spent(&self, leaf_id: &str, by: &str) -> Result<(), Error> {
		self.conn.execute("UPDATE coin SET state = 'spent', spent_by = ?2, note = '' WHERE leaf_id = ?1", params![leaf_id, by]).map_err(db)?;
		Ok(())
	}

	/// The txids of the rounds and boards a coin rests on.
	pub fn set_coin_bases(&self, leaf_id: &str, bases: &[String]) -> Result<(), Error> {
		self.conn.execute("UPDATE coin SET bases = ?2 WHERE leaf_id = ?1", params![leaf_id, serde_json::to_string(bases).expect("strings")])
			.map_err(db)?;
		Ok(())
	}

	pub fn set_coin_record(&self, leaf_id: &str, record: &[u8]) -> Result<(), Error> {
		self.conn.execute("UPDATE coin SET record = ?2 WHERE leaf_id = ?1", params![leaf_id, record]).map_err(db)?;
		Ok(())
	}

	// --- transactions ---

	pub fn put_tx(&self, txid: &str, raw: &[u8], role: &str) -> Result<(), Error> {
		self.conn.execute("INSERT OR IGNORE INTO tx (txid, raw, role) VALUES (?1, ?2, ?3)", params![txid, raw, role]).map_err(db)?;
		Ok(())
	}

	pub fn tx(&self, txid: &str) -> Result<Option<Vec<u8>>, Error> {
		self.conn.query_row("SELECT raw FROM tx WHERE txid = ?1", params![txid], |r| r.get(0)).optional().map_err(db)
	}

	// --- participations ---

	pub fn put_participation(&self, id: &str, body: &str, given: &str, wanted: &str) -> Result<(), Error> {
		self.conn.execute("INSERT INTO participation (id, body, given, wanted, state, created_at) VALUES (?1, ?2, ?3, ?4, 'submitting', ?5)",
			params![id, body, given, wanted, now()]).map_err(db)?;
		Ok(())
	}

	/// `(id, body, given, wanted, state, preimage, round)` of every participation.
	#[allow(clippy::type_complexity)]
	pub fn participations(&self) -> Result<Vec<(String, String, String, String, String, Option<String>, Option<String>)>, Error> {
		let mut st = self.conn.prepare("SELECT id, body, given, wanted, state, preimage, round FROM participation ORDER BY created_at").map_err(db)?;
		let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)))
			.map_err(db)?.collect::<Result<Vec<_>, _>>().map_err(db)?;
		Ok(rows)
	}

	pub fn set_participation(&self, id: &str, state: &str, preimage: Option<&str>, round: Option<&str>) -> Result<(), Error> {
		self.conn.execute("UPDATE participation SET state = ?2, preimage = COALESCE(?3, preimage), round = COALESCE(?4, round) WHERE id = ?1",
			params![id, state, preimage, round]).map_err(db)?;
		Ok(())
	}

	/// The new leaves validated for participation `id`, with their nonces
	/// and the authorisations signed for them, before its forfeits went out.
	pub fn set_participation_news(&self, id: &str, news: &str) -> Result<(), Error> {
		self.conn.execute("UPDATE participation SET news = ?2 WHERE id = ?1", params![id, news]).map_err(db)?;
		Ok(())
	}

	pub fn participation_news(&self, id: &str) -> Result<Option<String>, Error> {
		Ok(self.conn.query_row("SELECT news FROM participation WHERE id = ?1", params![id], |r| r.get::<_, Option<String>>(0))
			.optional().map_err(db)?.flatten())
	}

	// --- forfeits ---

	/// Records a forfeit about to be signed. One coin has one forfeit per
	/// round.
	pub fn put_forfeit(&self, f: &ForfeitRow) -> Result<(), Error> {
		self.conn.execute("INSERT OR IGNORE INTO forfeit (leaf_id, participation, round, connector_vout, unlock_hash, refund_units, margin,
			from_height, state, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'signed', ?9)",
			params![f.leaf_id, f.participation, f.round, f.connector_vout, f.unlock_hash, f.refund_units, f.margin as i64, f.from_height as i64, now()])
			.map_err(db)?;
		Ok(())
	}

	fn forfeit_row(r: &rusqlite::Row) -> rusqlite::Result<ForfeitRow> {
		Ok(ForfeitRow {
			leaf_id: r.get(0)?, participation: r.get(1)?, round: r.get(2)?, connector_vout: r.get(3)?, unlock_hash: r.get(4)?,
			refund_units: r.get(5)?, margin: r.get::<_, i64>(6)? as u64, from_height: r.get::<_, i64>(7)? as u64, state: r.get(8)?,
			note: r.get(9)?,
		})
	}

	/// Every forfeit signed for coin `leaf_id`.
	pub fn forfeits_of(&self, leaf_id: &str) -> Result<Vec<ForfeitRow>, Error> {
		let mut st = self.conn.prepare("SELECT leaf_id, participation, round, connector_vout, unlock_hash, refund_units, margin, from_height,
			state, note FROM forfeit WHERE leaf_id = ?1 ORDER BY created_at").map_err(db)?;
		let rows = st.query_map(params![leaf_id], Self::forfeit_row).map_err(db)?.collect::<Result<Vec<_>, _>>().map_err(db)?;
		Ok(rows)
	}

	/// Every forfeit in `state`.
	pub fn forfeits_in(&self, state: &str) -> Result<Vec<ForfeitRow>, Error> {
		let mut st = self.conn.prepare("SELECT leaf_id, participation, round, connector_vout, unlock_hash, refund_units, margin, from_height,
			state, note FROM forfeit WHERE state = ?1 ORDER BY created_at").map_err(db)?;
		let rows = st.query_map(params![state], Self::forfeit_row).map_err(db)?.collect::<Result<Vec<_>, _>>().map_err(db)?;
		Ok(rows)
	}

	pub fn set_forfeit_state(&self, leaf_id: &str, round: &str, state: &str, note: &str) -> Result<(), Error> {
		self.conn.execute("UPDATE forfeit SET state = ?3, note = ?4 WHERE leaf_id = ?1 AND round = ?2", params![leaf_id, round, state, note])
			.map_err(db)?;
		Ok(())
	}

	// --- transfers ---

	pub fn put_transfer(&self, body: &str, inputs: &str) -> Result<i64, Error> {
		self.conn.execute("INSERT INTO transfer (body, inputs, state, created_at) VALUES (?1, ?2, 'requested', ?3)", params![body, inputs, now()])
			.map_err(db)?;
		Ok(self.conn.last_insert_rowid())
	}

	pub fn transfers_in(&self, state: &str) -> Result<Vec<(i64, String, String)>, Error> {
		let mut st = self.conn.prepare("SELECT id, body, inputs FROM transfer WHERE state = ?1 ORDER BY id").map_err(db)?;
		let rows = st.query_map(params![state], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map_err(db)?
			.collect::<Result<Vec<_>, _>>().map_err(db)?;
		Ok(rows)
	}

	pub fn set_transfer(&self, id: i64, state: &str, answer: &str) -> Result<(), Error> {
		self.conn.execute("UPDATE transfer SET state = ?2, answer = ?3 WHERE id = ?1", params![id, state, answer]).map_err(db)?;
		Ok(())
	}

	// --- swaps ---

	pub fn put_swap(&self, id: &str, role: &str, offer: &str) -> Result<(), Error> {
		self.conn.execute("INSERT INTO swap (id, role, offer, state, created_at) VALUES (?1, ?2, ?3, 'open', ?4)", params![id, role, offer, now()])
			.map_err(db)?;
		Ok(())
	}

	/// `(role, offer, accept, state)` of swap `id`.
	pub fn swap(&self, id: &str) -> Result<Option<(String, String, Option<String>, String)>, Error> {
		self.conn.query_row("SELECT role, offer, accept, state FROM swap WHERE id = ?1", params![id],
			|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).optional().map_err(db)
	}

	pub fn set_swap(&self, id: &str, state: &str, accept: Option<&str>) -> Result<(), Error> {
		self.conn.execute("UPDATE swap SET state = ?2, accept = COALESCE(?3, accept) WHERE id = ?1", params![id, state, accept]).map_err(db)?;
		Ok(())
	}

	// --- mailbox ---

	pub fn cursor(&self, key: &[u8; 32]) -> Result<i64, Error> {
		Ok(self.conn.query_row("SELECT cursor FROM mailbox WHERE key = ?1", params![&key[..]], |r| r.get(0)).optional().map_err(db)?.unwrap_or(0))
	}

	pub fn set_cursor(&self, key: &[u8; 32], cursor: i64) -> Result<(), Error> {
		self.conn.execute("INSERT INTO mailbox (key, cursor) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET cursor = ?2",
			params![&key[..], cursor]).map_err(db)?;
		Ok(())
	}

	/// A coin from the mailbox refused for a passing reason, kept to be
	/// checked again.
	pub fn keep_for_retry(&self, leaf_id: &str, record: &[u8], reason: &str) -> Result<(), Error> {
		self.conn.execute("INSERT INTO mailbox_retry (leaf_id, record, reason, at) VALUES (?1, ?2, ?3, ?4)
			ON CONFLICT(leaf_id) DO UPDATE SET reason = ?3, at = ?4", params![leaf_id, record, reason, now()]).map_err(db)?;
		Ok(())
	}

	/// `(leaf_id, record)` of every coin kept for another check.
	pub fn kept_for_retry(&self) -> Result<Vec<(String, Vec<u8>)>, Error> {
		let mut st = self.conn.prepare("SELECT leaf_id, record FROM mailbox_retry ORDER BY at").map_err(db)?;
		let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).map_err(db)?.collect::<Result<Vec<_>, _>>().map_err(db)?;
		Ok(rows)
	}

	pub fn drop_retry(&self, leaf_id: &str) -> Result<(), Error> {
		self.conn.execute("DELETE FROM mailbox_retry WHERE leaf_id = ?1", params![leaf_id]).map_err(db)?;
		Ok(())
	}

	// --- exits ---

	/// `(state, txs, claim)` of the exit of `leaf_id`.
	pub fn exit(&self, leaf_id: &str) -> Result<Option<(String, String, Option<String>)>, Error> {
		self.conn.query_row("SELECT state, txs, claim FROM exit WHERE leaf_id = ?1", params![leaf_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
			.optional().map_err(db)
	}

	pub fn set_exit(&self, leaf_id: &str, state: &str, txs: &str, claim: Option<&str>) -> Result<(), Error> {
		self.conn.execute("INSERT INTO exit (leaf_id, state, txs, claim) VALUES (?1, ?2, ?3, ?4)
			ON CONFLICT(leaf_id) DO UPDATE SET state = ?2, txs = ?3, claim = COALESCE(?4, claim)",
			params![leaf_id, state, txs, claim]).map_err(db)?;
		Ok(())
	}

	// --- refusals ---

	pub fn refused(&self, what: &str, reason: &str) -> Result<(), Error> {
		self.conn.execute("INSERT INTO refusal (at, what, reason) VALUES (?1, ?2, ?3)", params![now(), what, reason]).map_err(db)?;
		Ok(())
	}

	pub fn refusals(&self) -> Result<Vec<(i64, String, String)>, Error> {
		let mut st = self.conn.prepare("SELECT at, what, reason FROM refusal ORDER BY id").map_err(db)?;
		let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map_err(db)?.collect::<Result<Vec<_>, _>>().map_err(db)?;
		Ok(rows)
	}

	/// Runs `f` in one database transaction.
	pub fn atomically<T>(&mut self, f: impl FnOnce(&Store) -> Result<T, Error>) -> Result<T, Error> {
		self.conn.execute_batch("BEGIN IMMEDIATE").map_err(db)?;
		match f(self) {
			Ok(v) => {
				self.conn.execute_batch("COMMIT").map_err(db)?;
				Ok(v)
			},
			Err(e) => {
				let _ = self.conn.execute_batch("ROLLBACK");
				Err(e)
			},
		}
	}
}
