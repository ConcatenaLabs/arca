//! The chain as the finality service follows it: the active chain's blocks,
//! the watched transactions they hold, and what a scan of each block found.
//!
//! A block is connected in one database transaction with everything its scan
//! found, and disconnected in one with everything that rested on it, so a
//! crash between two blocks leaves the record whole and the next pass picks
//! up where it stopped.

use super::{array32, Store, StoreError};

/// One block of the active chain, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRow {
	pub hash: [u8; 32],
	pub height: u64,
	pub prev_hash: [u8; 32],
	pub anchor_height: u64,
	pub anchor_hash: [u8; 32],
	pub median_time: u64,
	pub certified: bool,
}

/// One output a scan saw.
#[derive(Debug, Clone)]
pub struct ScannedOutput {
	pub txid: [u8; 32],
	pub vout: u32,
	pub script_pubkey: Vec<u8>,
	/// Asset and value, when both are explicit and the nonce is empty; `None`
	/// for an output that hides either.
	pub explicit: Option<([u8; 32], u64)>,
}

/// What a scan of a block (or of the mempool) collects: every txid, every
/// output, every input's previous output.
#[derive(Debug, Clone, Default)]
pub struct Scan {
	pub txids: Vec<[u8; 32]>,
	pub outputs: Vec<ScannedOutput>,
	/// `(spent txid, spent vout, spending txid)` of every input.
	pub spends: Vec<([u8; 32], u32, [u8; 32])>,
}

impl Scan {
	pub fn add_tx(&mut self, tx: &elements::Transaction) {
		use elements::hashes::Hash;
		use sequentia_ext::TxOutExt;
		let txid = tx.txid().to_byte_array();
		self.txids.push(txid);
		for (i, o) in tx.output.iter().enumerate() {
			let explicit = match (o.is_explicit(), o.asset_amount()) {
				(true, Some(a)) => Some((a.asset.into_inner().to_byte_array(), a.amount)),
				_ => None,
			};
			self.outputs.push(ScannedOutput { txid, vout: i as u32, script_pubkey: o.script_pubkey.to_bytes(), explicit });
		}
		for i in &tx.input {
			if !i.is_coinbase() {
				self.spends.push((i.previous_output.txid.to_byte_array(), i.previous_output.vout, txid));
			}
		}
	}
}

const BLOCK_COLUMNS: &str = "hash, height, prev_hash, anchor_height, anchor_hash, median_time, certified";

fn block_row(r: &tokio_postgres::Row) -> Result<BlockRow, StoreError> {
	let n = |i: usize, what: &str| -> Result<u64, StoreError> {
		let v: i64 = r.get(i);
		u64::try_from(v).map_err(|_| StoreError::Corrupt(format!("{} {}", what, v)))
	};
	Ok(BlockRow {
		hash: array32(r.get(0), "block hash")?,
		height: n(1, "height")?,
		prev_hash: array32(r.get(2), "previous block hash")?,
		anchor_height: n(3, "anchor height")?,
		anchor_hash: array32(r.get(4), "anchor hash")?,
		median_time: n(5, "median time")?,
		certified: r.get(6),
	})
}

fn i64_of(v: u64) -> i64 {
	i64::try_from(v).expect("a chain height or time fits in i64")
}

/// Records what `scan` found inside `tx`: sightings of Arca scripts and spends
/// of watched outpoints, `seen_in` the mempool or a block.
async fn record_scan(tx: &tokio_postgres::Transaction<'_>, scan: &Scan, seen_in: &str) -> Result<(), StoreError> {
	let txids: Vec<Vec<u8>> = scan.outputs.iter().map(|o| o.txid.to_vec()).collect();
	let vouts: Vec<i32> = scan.outputs.iter().map(|o| o.vout as i32).collect();
	let scripts: Vec<Vec<u8>> = scan.outputs.iter().map(|o| o.script_pubkey.clone()).collect();
	tx.execute(
		"INSERT INTO script_sighting (script_pubkey, txid, vout, seen_in)
		 SELECT o.s, o.t, o.v, $4 FROM unnest($1::bytea[], $2::bytea[], $3::int4[]) AS o(s, t, v)
		 JOIN arca_script a ON a.script_pubkey = o.s
		 ON CONFLICT (script_pubkey, txid, vout) DO UPDATE SET seen_in = 'block'
		 WHERE EXCLUDED.seen_in = 'block'",
		&[&scripts, &txids, &vouts, &seen_in],
	).await?;
	let prev_txids: Vec<Vec<u8>> = scan.spends.iter().map(|(t, _, _)| t.to_vec()).collect();
	let prev_vouts: Vec<i32> = scan.spends.iter().map(|(_, v, _)| *v as i32).collect();
	let spenders: Vec<Vec<u8>> = scan.spends.iter().map(|(_, _, s)| s.to_vec()).collect();
	tx.execute(
		"UPDATE watched_outpoint w SET spent_by = s.by, spent_at = now()
		 FROM unnest($1::bytea[], $2::int4[], $3::bytea[]) AS s(t, v, by)
		 WHERE w.txid = s.t AND w.vout = s.v AND w.spent_by IS NULL",
		&[&prev_txids, &prev_vouts, &spenders],
	).await?;
	Ok(())
}

/// Records the wallet's coins a block holds: each explicit output paying one
/// of the wallet's scripts becomes a coin (again, if its transaction returns
/// in another block after a rollback), its transaction watched so the
/// finality service can say when the coin is final. An output paying the
/// wallet that hides its asset or value is refused, and recorded as refused:
/// the server is transparent at its boundary.
async fn record_wallet_coins(tx: &tokio_postgres::Transaction<'_>, scan: &Scan, block: &[u8; 32]) -> Result<(), StoreError> {
	let scripts: Vec<Vec<u8>> = scan.outputs.iter().map(|o| o.script_pubkey.clone()).collect();
	let ours = tx.query("SELECT script_pubkey FROM wallet_key WHERE script_pubkey = ANY($1)", &[&scripts]).await?;
	if ours.is_empty() {
		return Ok(());
	}
	let ours: std::collections::HashSet<Vec<u8>> = ours.iter().map(|r| r.get(0)).collect();
	for o in scan.outputs.iter().filter(|o| ours.contains(&o.script_pubkey)) {
		match o.explicit {
			Some((asset, value)) if value > 0 => {
				let value = i64::try_from(value).map_err(|_| StoreError::Corrupt(format!("value {}", value)))?;
				tx.execute(
					"INSERT INTO wallet_coin (txid, vout, asset, value, script_pubkey, found_in)
					 VALUES ($1, $2, $3, $4, $5, $6)
					 ON CONFLICT (txid, vout) DO UPDATE SET found_in = EXCLUDED.found_in",
					&[&&o.txid[..], &(o.vout as i32), &&asset[..], &value, &o.script_pubkey, &&block[..]],
				).await?;
				tx.execute("INSERT INTO watched_tx (txid, kind) VALUES ($1, 'wallet') ON CONFLICT DO NOTHING", &[&&o.txid[..]]).await?;
				tx.execute("INSERT INTO tx_block (txid, block_hash) VALUES ($1, $2) ON CONFLICT DO NOTHING",
					&[&&o.txid[..], &&block[..]]).await?;
			},
			Some(_) => {},
			None => {
				tx.execute(
					"INSERT INTO wallet_refused (txid, vout, script_pubkey, reason) VALUES ($1, $2, $3, $4)
					 ON CONFLICT DO NOTHING",
					&[&&o.txid[..], &(o.vout as i32), &o.script_pubkey,
						&"blinded: the server takes explicit coins only"],
				).await?;
			},
		}
	}
	Ok(())
}

impl Store {
	/// The highest block of the followed chain.
	pub async fn tip_block(&self) -> Result<Option<BlockRow>, StoreError> {
		let conn = self.conn().await?;
		let row = conn.query_opt(&format!("SELECT {} FROM block ORDER BY height DESC LIMIT 1", BLOCK_COLUMNS), &[]).await?;
		row.as_ref().map(block_row).transpose()
	}

	/// The lowest height the store follows from.
	pub async fn lowest_block_height(&self) -> Result<Option<u64>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_one("SELECT min(height) FROM block", &[]).await?;
		Ok(r.get::<_, Option<i64>>(0).map(|h| h as u64))
	}

	pub async fn block_by_hash(&self, hash: &[u8; 32]) -> Result<Option<BlockRow>, StoreError> {
		let conn = self.conn().await?;
		let row = conn.query_opt(&format!("SELECT {} FROM block WHERE hash = $1", BLOCK_COLUMNS), &[&&hash[..]]).await?;
		row.as_ref().map(block_row).transpose()
	}

	pub async fn block_at(&self, height: u64) -> Result<Option<BlockRow>, StoreError> {
		let conn = self.conn().await?;
		let row = conn.query_opt(&format!("SELECT {} FROM block WHERE height = $1", BLOCK_COLUMNS), &[&i64_of(height)]).await?;
		row.as_ref().map(block_row).transpose()
	}

	/// Connects `block` with what its scan found: the watched transactions it
	/// holds, the Arca scripts it pays, the watched outpoints it spends.
	pub async fn connect_block(&self, block: &BlockRow, scan: &Scan) -> Result<(), StoreError> {
		let mut conn = self.conn().await?;
		let tx = conn.transaction().await?;
		tx.execute(
			&format!("INSERT INTO block ({}) VALUES ($1, $2, $3, $4, $5, $6, $7)", BLOCK_COLUMNS),
			&[
				&&block.hash[..], &i64_of(block.height), &&block.prev_hash[..], &i64_of(block.anchor_height),
				&&block.anchor_hash[..], &i64_of(block.median_time), &block.certified,
			],
		).await?;
		let txids: Vec<Vec<u8>> = scan.txids.iter().map(|t| t.to_vec()).collect();
		tx.execute(
			"INSERT INTO tx_block (txid, block_hash) SELECT txid, $2 FROM watched_tx WHERE txid = ANY($1)
			 ON CONFLICT DO NOTHING",
			&[&txids, &&block.hash[..]],
		).await?;
		record_scan(&tx, scan, "block").await?;
		record_wallet_coins(&tx, scan, &block.hash).await?;
		tx.execute("INSERT INTO chain_event (kind, height, hash) VALUES ('connected', $1, $2)",
			&[&i64_of(block.height), &&block.hash[..]]).await?;
		tx.commit().await?;
		Ok(())
	}

	/// Disconnects the block `hash`, which must be the tip, and returns the
	/// watched transactions it held, with what each was watched for.
	pub async fn disconnect_block(&self, hash: &[u8; 32]) -> Result<Vec<([u8; 32], String)>, StoreError> {
		let mut conn = self.conn().await?;
		let tx = conn.transaction().await?;
		let row = tx.query_opt(&format!("SELECT {} FROM block WHERE hash = $1 FOR UPDATE", BLOCK_COLUMNS), &[&&hash[..]]).await?;
		let block = match row {
			Some(r) => block_row(&r)?,
			None => return Err(StoreError::Corrupt("disconnecting a block that is not stored".into())),
		};
		let held = tx.query(
			"SELECT t.txid, w.kind FROM tx_block t JOIN watched_tx w ON w.txid = t.txid WHERE t.block_hash = $1",
			&[&&hash[..]],
		).await?;
		let held = held.iter().map(|r| Ok((array32(r.get(0), "txid")?, r.get::<_, String>(1)))).collect::<Result<Vec<_>, StoreError>>()?;
		let higher = tx.query_one("SELECT count(*) FROM block WHERE height > $1", &[&i64_of(block.height)]).await?;
		if higher.get::<_, i64>(0) != 0 {
			return Err(StoreError::Corrupt("disconnecting a block below the tip".into()));
		}
		tx.execute("DELETE FROM block WHERE hash = $1", &[&&hash[..]]).await?;
		tx.execute("INSERT INTO chain_event (kind, height, hash) VALUES ('disconnected', $1, $2)",
			&[&i64_of(block.height), &&hash[..]]).await?;
		tx.commit().await?;
		Ok(held)
	}

	/// Sets whether the committee has certified the block `hash`.
	pub async fn set_certified(&self, hash: &[u8; 32], certified: bool) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute("UPDATE block SET certified = $2 WHERE hash = $1", &[&&hash[..], &certified]).await?;
		Ok(())
	}

	/// The blocks at `from` and above not yet certified, lowest first.
	pub async fn uncertified_from(&self, from: u64) -> Result<Vec<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query("SELECT hash FROM block WHERE height >= $1 AND NOT certified ORDER BY height",
			&[&i64_of(from)]).await?;
		rows.iter().map(|r| array32(r.get(0), "block hash")).collect()
	}

	/// The highest certified block at `height` or above, if any: a certified
	/// block certifies its ancestors too, since the chain cannot leave them
	/// without leaving it.
	pub async fn certified_at_or_above(&self, height: u64) -> Result<bool, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_one("SELECT EXISTS (SELECT 1 FROM block WHERE height >= $1 AND certified)", &[&i64_of(height)]).await?;
		Ok(r.get(0))
	}

	/// Watches `txid` for `kind`. Watching it again changes nothing.
	pub async fn watch_tx(&self, txid: &[u8; 32], kind: &str) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute("INSERT INTO watched_tx (txid, kind) VALUES ($1, $2) ON CONFLICT DO NOTHING", &[&&txid[..], &kind]).await?;
		Ok(())
	}

	/// Records that the stored block `block` holds the watched `txid`.
	pub async fn record_tx_block(&self, txid: &[u8; 32], block: &[u8; 32]) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute(
			"INSERT INTO tx_block (txid, block_hash) SELECT $1, $2
			 WHERE EXISTS (SELECT 1 FROM block WHERE hash = $2) AND EXISTS (SELECT 1 FROM watched_tx WHERE txid = $1)
			 ON CONFLICT DO NOTHING",
			&[&&txid[..], &&block[..]],
		).await?;
		Ok(())
	}

	/// The block of the followed chain that holds the watched `txid`.
	pub async fn tx_location(&self, txid: &[u8; 32]) -> Result<Option<BlockRow>, StoreError> {
		let conn = self.conn().await?;
		let columns = BLOCK_COLUMNS.split(", ").map(|c| format!("b.{}", c)).collect::<Vec<_>>().join(", ");
		let row = conn.query_opt(
			&format!("SELECT {} FROM block b JOIN tx_block t ON t.block_hash = b.hash WHERE t.txid = $1
				ORDER BY b.height LIMIT 1", columns),
			&[&&txid[..]],
		).await?;
		row.as_ref().map(block_row).transpose()
	}

	/// Records what a scan of the mempool found: sightings of Arca scripts
	/// and spends of watched outpoints.
	pub async fn record_mempool_scan(&self, scan: &Scan) -> Result<(), StoreError> {
		let mut conn = self.conn().await?;
		let tx = conn.transaction().await?;
		record_scan(&tx, scan, "mempool").await?;
		tx.commit().await?;
		Ok(())
	}

	/// Every connection and disconnection, in order: `(kind, height, hash)`.
	pub async fn chain_events(&self) -> Result<Vec<(String, u64, [u8; 32])>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query("SELECT kind, height, hash FROM chain_event ORDER BY seq", &[]).await?;
		rows.iter().map(|r| Ok((r.get(0), r.get::<_, i64>(1) as u64, array32(r.get(2), "block hash")?))).collect()
	}
}
