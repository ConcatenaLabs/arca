//! What the store keeps for RECLAIM-D ([`crate::delegations`]): each coin's
//! delegation of its release to the outputs of the reassignment it moved
//! into, and each holder's releases of the lowest nodes its coin rests on
//! (in `node_release`, beside the releases of batch leaves).

use super::{array32, Store, StoreError};

/// A coin's delegation, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationRow {
	pub transfer_id: [u8; 32],
	pub signature: [u8; 64],
}

/// A holder's release of one lowest node, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolderReleaseRow {
	pub round_id: i64,
	pub connector_asset: [u8; 32],
	pub signature: [u8; 64],
}

/// What spent a coin the server knows, as far as a reclaim cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpentBy {
	/// Nothing: it is live, or pending.
	Nothing,
	/// A reassignment the operator signed (a transfer, or an in-tree fill of
	/// a resting order): its id, and its outputs' leaf ids and owner keys in
	/// output order.
	Reassignment { transfer_id: [u8; 32], outputs: Vec<([u8; 32], [u8; 32])> },
	/// A participation, or anything else that is not a reassignment.
	Other,
}

fn sig64(v: Vec<u8>) -> Result<[u8; 64], StoreError> {
	v.try_into().map_err(|_| StoreError::Corrupt("signature".into()))
}

impl Store {
	/// Records `leaf_id`'s delegation into transfer `transfer_id`; a
	/// delegation already recorded for the coin stays as it was. Returns
	/// whether this one is new.
	pub async fn insert_delegation(&self, leaf_id: &[u8; 32], transfer_id: &[u8; 32], signature: &[u8; 64]) -> Result<bool, StoreError> {
		let conn = self.conn().await?;
		let n = conn.execute(
			"INSERT INTO delegation (leaf_id, transfer_id, signature) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
			&[&&leaf_id[..], &&transfer_id[..], &&signature[..]],
		).await?;
		Ok(n == 1)
	}

	/// The delegation recorded for `leaf_id`, if any.
	pub async fn delegation(&self, leaf_id: &[u8; 32]) -> Result<Option<DelegationRow>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt("SELECT transfer_id, signature FROM delegation WHERE leaf_id = $1", &[&&leaf_id[..]]).await?;
		r.map(|r| Ok(DelegationRow { transfer_id: array32(r.get(0), "transfer id")?, signature: sig64(r.get(1))? })).transpose()
	}

	/// What spent `leaf_id`: a signed reassignment that took it as an input
	/// (a transfer's, or a fill's order coin or taker input), with its
	/// outputs; or something else; or nothing.
	pub async fn spent_by(&self, leaf_id: &[u8; 32]) -> Result<SpentBy, StoreError> {
		let conn = self.conn().await?;
		let t = conn.query_opt(
			"SELECT ti.transfer_id FROM transfer_input ti JOIN transfer t USING (transfer_id)
			 WHERE ti.leaf_id = $1 AND (t.state = 'signed'
			   OR EXISTS (SELECT 1 FROM order_fill f WHERE f.transfer_id = ti.transfer_id AND f.signature IS NOT NULL))
			 UNION
			 SELECT f.transfer_id FROM order_fill f WHERE f.order_leaf = $1 AND f.signature IS NOT NULL",
			&[&&leaf_id[..]]).await?;
		if let Some(t) = t {
			let transfer_id = array32(t.get(0), "transfer id")?;
			let rows = conn.query(
				"SELECT o.leaf_id, l.owner_key FROM transfer_output o JOIN leaf l USING (leaf_id) WHERE o.transfer_id = $1 ORDER BY o.idx",
				&[&&transfer_id[..]]).await?;
			let outputs = rows.iter().map(|r| Ok((array32(r.get(0), "leaf id")?, array32(r.get(1), "owner key")?)))
				.collect::<Result<Vec<_>, StoreError>>()?;
			return Ok(SpentBy::Reassignment { transfer_id, outputs });
		}
		let r = conn.query_opt("SELECT state::TEXT FROM leaf WHERE leaf_id = $1", &[&&leaf_id[..]]).await?;
		Ok(match r.map(|r| r.get::<_, String>(0)) {
			Some(s) if s == "spent" => SpentBy::Other,
			_ => SpentBy::Nothing,
		})
	}

	/// The releases `leaf_id`'s holder signed of the lowest node whose
	/// children hash is `node_hash`, but those retired with a lost round.
	pub async fn holder_releases(&self, leaf_id: &[u8; 32], node_hash: &[u8; 32]) -> Result<Vec<HolderReleaseRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT round_id, connector_asset, signature FROM node_release
			 WHERE leaf_id = $1 AND node_hash = $2 AND NOT retired ORDER BY round_id",
			&[&&leaf_id[..], &&node_hash[..]]).await?;
		rows.iter().map(|r| Ok(HolderReleaseRow {
			round_id: r.get(0),
			connector_asset: array32(r.get(1), "connector asset")?,
			signature: sig64(r.get(2))?,
		})).collect()
	}

	/// Records the release by the sender of a paid Lightning payment of the
	/// lowest node whose children hash is `node_hash`, its `htlc-1` coin
	/// `leaf_id` resting on it, naming round `round_id` (whose connector
	/// asset is `connector_asset`). A release already recorded for the coin,
	/// round and node stays as it was. Returns whether this one is new.
	pub async fn insert_paid_send_release(&self, leaf_id: &[u8; 32], round_id: i64, node_hash: &[u8; 32], connector_asset: &[u8; 32],
		signature: &[u8; 64]) -> Result<bool, StoreError>
	{
		let conn = self.conn().await?;
		let n = conn.execute(
			"INSERT INTO node_release (leaf_id, round_id, participation_id, node_hash, connector_asset, signature)
			 VALUES ($1, $2, NULL, $3, $4, $5) ON CONFLICT DO NOTHING",
			&[&&leaf_id[..], &round_id, &&node_hash[..], &&connector_asset[..], &&signature[..]],
		).await?;
		Ok(n == 1)
	}

	/// The releases the sender of a paid Lightning payment signed of the
	/// lowest node whose children hash is `node_hash`, its `htlc-1` coin
	/// being `leaf_id`, naming a round that is final now. A round lost to a
	/// rollback takes its connector asset with it, so a release naming it is
	/// of no use until the round is final again.
	pub async fn paid_send_releases(&self, leaf_id: &[u8; 32], node_hash: &[u8; 32]) -> Result<Vec<HolderReleaseRow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT nr.round_id, nr.connector_asset, nr.signature FROM node_release nr JOIN round r USING (round_id)
			 WHERE nr.leaf_id = $1 AND nr.node_hash = $2 AND nr.participation_id IS NULL AND r.state = 'final'
			 ORDER BY nr.round_id",
			&[&&leaf_id[..], &&node_hash[..]]).await?;
		rows.iter().map(|r| Ok(HolderReleaseRow {
			round_id: r.get(0),
			connector_asset: array32(r.get(1), "connector asset")?,
			signature: sig64(r.get(2))?,
		})).collect()
	}

	/// Whether `leaf_id` is given up in a participation that has not
	/// completed yet (pending, or in a round and waiting for its forfeits):
	/// its holder's release can still come once it completes.
	pub async fn refresh_open(&self, leaf_id: &[u8; 32]) -> Result<bool, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_one(
			"SELECT EXISTS (SELECT 1 FROM participation_input pi JOIN participation p USING (participation_id)
			 WHERE pi.leaf_id = $1 AND pi.active AND p.state IN ('pending', 'issued'))",
			&[&&leaf_id[..]]).await?;
		Ok(r.get(0))
	}

	/// The latest round that is final, by id: the one a paid payment's
	/// sender is asked to name in its releases.
	pub async fn latest_final_round(&self) -> Result<Option<i64>, StoreError> {
		let conn = self.conn().await?;
		let r = conn.query_opt("SELECT round_id FROM round WHERE state = 'final' ORDER BY round_id DESC LIMIT 1", &[]).await?;
		Ok(r.map(|r| r.get(0)))
	}

	/// The batches with RECLAIM-D one of whose leaves moved into a
	/// reassignment with a delegation: each may come back by its holders'
	/// releases. By round and output.
	pub async fn batches_with_delegations(&self) -> Result<Vec<(i64, u32)>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"SELECT DISTINCT bl.round_id, bl.vout FROM delegation d JOIN batch_leaf bl ON bl.leaf_id = d.leaf_id
			 JOIN batch b ON b.round_id = bl.round_id AND b.vout = bl.vout WHERE b.delegated_reclaim
			 ORDER BY 1, 2", &[]).await?;
		Ok(rows.iter().map(|r| (r.get(0), r.get::<_, i32>(1) as u32)).collect())
	}

	/// Records the batch leaves the reclaim `txid` takes back.
	pub async fn insert_reclaimed_leaves(&self, txid: &[u8; 32], leaves: &[[u8; 32]]) -> Result<(), StoreError> {
		let conn = self.conn().await?;
		for l in leaves {
			conn.execute("INSERT INTO reclaimed_leaf (txid, leaf_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
				&[&&txid[..], &&l[..]]).await?;
		}
		Ok(())
	}
}
