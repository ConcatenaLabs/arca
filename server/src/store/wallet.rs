//! The on-chain wallet's keys and coins.

use super::{array32, Store, StoreError};

/// A coin of the wallet's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletCoin {
	pub txid: [u8; 32],
	pub vout: u32,
	pub asset: [u8; 32],
	pub value: u64,
	pub script_pubkey: Vec<u8>,
	/// The derivation chain and index of the key that owns it.
	pub chain: u8,
	pub index: u32,
	/// Whether its transaction is in a block of the active chain.
	pub in_chain: bool,
	pub spent_by: Option<[u8; 32]>,
}

/// An output paying the wallet that it would not take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletRefusal {
	pub txid: [u8; 32],
	pub vout: u32,
	pub reason: String,
}

fn coin(r: &tokio_postgres::Row) -> Result<WalletCoin, StoreError> {
	let value: i64 = r.get(3);
	let spent: Option<Vec<u8>> = r.get(8);
	Ok(WalletCoin {
		txid: array32(r.get(0), "txid")?,
		vout: r.get::<_, i32>(1) as u32,
		asset: array32(r.get(2), "asset")?,
		value: value as u64,
		script_pubkey: r.get(4),
		chain: r.get::<_, i16>(5) as u8,
		index: r.get::<_, i32>(6) as u32,
		in_chain: r.get(7),
		spent_by: spent.map(|s| array32(s, "spending txid")).transpose()?,
	})
}

const COIN_QUERY: &str = "SELECT c.txid, c.vout, c.asset, c.value, c.script_pubkey, k.chain, k.idx, c.found_in IS NOT NULL, c.spent_by
	FROM wallet_coin c JOIN wallet_key k ON k.script_pubkey = c.script_pubkey";

impl Store {
	/// Records the script of key `index` on derivation chain `chain` as
	/// handed out. Recording it again changes nothing.
	pub async fn add_wallet_key(&self, chain: u8, index: u32, script_pubkey: &[u8]) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		conn.execute(
			"INSERT INTO wallet_key (chain, idx, script_pubkey) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
			&[&(chain as i16), &(index as i32), &script_pubkey],
		).await?;
		Ok(())
	}

	/// The next index not yet handed out on derivation chain `chain`.
	pub async fn next_wallet_index(&self, chain: u8) -> Result<u32, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_one("SELECT coalesce(max(idx) + 1, 0) FROM wallet_key WHERE chain = $1", &[&(chain as i16)]).await?;
		Ok(r.get::<_, i32>(0) as u32)
	}

	/// The wallet's coins not spent by any transaction it built, of `asset`
	/// or of every asset, in the active chain or not.
	pub async fn wallet_coins(&self, asset: Option<&[u8; 32]>) -> Result<Vec<WalletCoin>, StoreError> {
		let conn = self.conn().await?;
		let rows = match asset {
			Some(a) => conn.query(&format!("{} WHERE c.spent_by IS NULL AND c.asset = $1 ORDER BY c.value DESC", COIN_QUERY), &[&&a[..]]).await?,
			None => conn.query(&format!("{} WHERE c.spent_by IS NULL ORDER BY c.asset, c.value DESC", COIN_QUERY), &[]).await?,
		};
		rows.iter().map(coin).collect()
	}

	/// The wallet's coin at `txid:vout`, spent or not, if it is one.
	pub async fn wallet_coin_at(&self, txid: &[u8; 32], vout: u32) -> Result<Option<WalletCoin>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt(&format!("{} WHERE c.txid = $1 AND c.vout = $2", COIN_QUERY), &[&&txid[..], &(vout as i32)]).await?;
		r.as_ref().map(coin).transpose()
	}

	/// The wallet's coins that `txid` pays, spent or not.
	pub async fn wallet_coins_of_tx(&self, txid: &[u8; 32]) -> Result<Vec<WalletCoin>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!("{} WHERE c.txid = $1 ORDER BY c.vout", COIN_QUERY), &[&&txid[..]]).await?;
		rows.iter().map(coin).collect()
	}

	/// Marks `coins` spent by `txid`, all or none: a coin another
	/// transaction already took is refused.
	pub async fn spend_wallet_coins(&self, coins: &[([u8; 32], u32)], txid: &[u8; 32]) -> Result<bool, StoreError> {
		let mut conn = self.conn().await?;
		let tx = conn.transaction().await?;
		for (t, v) in coins {
			let n = tx.execute(
				"UPDATE wallet_coin SET spent_by = $3 WHERE txid = $1 AND vout = $2 AND spent_by IS NULL",
				&[&&t[..], &(*v as i32), &&txid[..]],
			).await?;
			if n != 1 {
				return Ok(false);
			}
		}
		tx.commit().await?;
		Ok(true)
	}

	/// Records the outputs of `tx`, a transaction of the watcher's the nursery
	/// holds, that pay the wallet: its change, spendable by the watcher's
	/// next transaction before any block holds it. A block that holds the
	/// transaction finds the coin there already.
	pub async fn record_pending_outputs(&self, tx: &elements::Transaction) -> Result<(), StoreError> {
		use elements::hashes::Hash;
		let conn = self.conn().await?;
		let txid = tx.txid().to_byte_array();
		for (vout, o) in tx.output.iter().enumerate() {
			let (asset, value) = match (o.asset.explicit(), o.value.explicit()) {
				(Some(a), Some(v)) if v > 0 && o.nonce.is_null() => (a.into_inner().to_byte_array(), v),
				_ => continue,
			};
			let value = i64::try_from(value).map_err(|_| StoreError::Corrupt(format!("value {}", value)))?;
			conn.execute(
				"INSERT INTO wallet_coin (txid, vout, asset, value, script_pubkey)
				 SELECT $1, $2, $3, $4, k.script_pubkey FROM wallet_key k WHERE k.script_pubkey = $5
				 ON CONFLICT (txid, vout) DO NOTHING",
				&[&&txid[..], &(vout as i32), &&asset[..], &value, &o.script_pubkey.as_bytes()],
			).await?;
		}
		Ok(())
	}

	/// The wallet's coins of `asset` that nothing spends whose transaction is
	/// the watcher's and pending in the nursery (in no block yet, or in one
	/// not final), each with how many of the watcher's transactions it rests
	/// on, its own included, whether or not a block holds them.
	pub async fn pending_change(&self, asset: &[u8; 32]) -> Result<Vec<(WalletCoin, u32)>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			&format!("{} JOIN watcher_tx w ON w.txid = c.txid JOIN nursery_tx n ON n.txid = c.txid
				WHERE c.spent_by IS NULL AND c.asset = $1 AND n.state = 'pending'
				ORDER BY c.value DESC", COIN_QUERY),
			&[&&asset[..]],
		).await?;
		let mut out = vec![];
		for r in &rows {
			let c = coin(r)?;
			let depth = conn.query_one(
				"WITH RECURSIVE anc(txid, d) AS (
				   SELECT $1::bytea, 0
				   UNION
				   SELECT wi.prev_txid, anc.d + 1 FROM anc
				   JOIN watcher_input wi ON wi.txid = anc.txid
				   JOIN nursery_tx n ON n.txid = wi.prev_txid AND n.state = 'pending'
				   WHERE anc.d < 50 AND NOT EXISTS (SELECT 1 FROM tx_block t WHERE t.txid = wi.prev_txid))
				 SELECT count(DISTINCT txid) FROM anc",
				&[&&c.txid[..]],
			).await?;
			out.push((c, depth.get::<_, i64>(0) as u32));
		}
		Ok(out)
	}

	/// Forgets the coins `txid` made that no block holds: the transaction
	/// can never confirm.
	pub async fn forget_pending_outputs(&self, txid: &[u8; 32]) -> Result<u64, StoreError> {
		let conn = self.conn().await?;
		Ok(conn.execute("DELETE FROM wallet_coin WHERE txid = $1 AND found_in IS NULL", &[&&txid[..]]).await?)
	}

	/// Frees the coins `txid` spent: the transaction will never confirm.
	pub async fn release_wallet_coins(&self, txid: &[u8; 32]) -> Result<u64, StoreError> {
		let conn = self.conn().await?;
		Ok(conn.execute("UPDATE wallet_coin SET spent_by = NULL WHERE spent_by = $1", &[&&txid[..]]).await?)
	}

	/// The outputs paying the wallet that it refused.
	pub async fn wallet_refusals(&self) -> Result<Vec<WalletRefusal>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query("SELECT txid, vout, reason FROM wallet_refused ORDER BY seen_at", &[]).await?;
		rows.iter().map(|r| Ok(WalletRefusal {
			txid: array32(r.get(0), "txid")?, vout: r.get::<_, i32>(1) as u32, reason: r.get(2),
		})).collect()
	}

	/// Every round's connector asset.
	pub async fn connector_assets(&self) -> Result<std::collections::HashSet<[u8; 32]>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query("SELECT connector_asset FROM connector_output", &[]).await?;
		rows.iter().map(|r| super::array32(r.get(0), "connector asset")).collect()
	}
}
