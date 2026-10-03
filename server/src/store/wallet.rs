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
}
