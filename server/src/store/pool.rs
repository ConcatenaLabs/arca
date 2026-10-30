//! Where each asset's pool stands: what its batches hold until they come
//! back, and what flowed out and back in over the last hour.

use std::collections::BTreeMap;

use super::{array32, Store, StoreError};

/// One asset's pool flow, in atoms ([`Store::pool_flow`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PoolFlow {
	/// What the asset's live batches hold (rounds broadcast or final, not
	/// swept by a final sweep), less what reclaims of them paid back.
	pub locked: u64,
	/// Of that, the leaves whose holders released their lowest node, not
	/// reclaimed yet: back once every leaf of their batch is released.
	pub released: u64,
	/// Of that, the batches every leaf of which is released: the watcher
	/// unrolls and reclaims them on its next passes.
	pub reclaimable: u64,
	/// Of `locked`, the leaves paid on out of round (given up in a
	/// transfer): no release of their lowest node can come from their owner,
	/// so they come back only at their batch's expiry.
	pub transferred: u64,
	/// What the batches of the rounds built in the last hour, and their
	/// offboards, took out of the pool.
	pub drawn_last_hour: u64,
	/// What reclaims paid back to the wallet in the last hour.
	pub reclaimed_last_hour: u64,
	/// What sweeps of expired batches paid back in the last hour.
	pub swept_last_hour: u64,
}

impl Store {
	/// Each asset's pool flow, by asset: see [`PoolFlow`]. One read-only
	/// statement.
	pub async fn pool_flow(&self) -> Result<BTreeMap<[u8; 32], PoolFlow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"WITH live AS (
			   SELECT b.round_id, b.vout, b.asset, b.value FROM batch b JOIN round r USING (round_id)
			   WHERE r.state IN ('broadcast', 'final')
			     AND NOT EXISTS (SELECT 1 FROM watcher_tx w JOIN nursery_tx n USING (txid)
			                     WHERE w.kind = 'sweep' AND w.subject = b.token AND n.state = 'final')),
			 reclaimed_node AS (
			   SELECT DISTINCT w.subject AS node_hash, w.txid FROM watcher_tx w JOIN nursery_tx n USING (txid)
			   WHERE w.kind = 'reclaim' AND n.state <> 'lost'),
			 leaves AS (
			   SELECT bl.round_id, bl.vout, bl.value,
			          EXISTS (SELECT 1 FROM node_release nr WHERE nr.leaf_id = bl.leaf_id AND NOT nr.retired) AS released,
			          EXISTS (SELECT 1 FROM node_release nr JOIN reclaimed_node k USING (node_hash)
			                  WHERE nr.leaf_id = bl.leaf_id) AS reclaimed,
			          EXISTS (SELECT 1 FROM transfer_input ti WHERE ti.leaf_id = bl.leaf_id) AS transferred
			   FROM batch_leaf bl JOIN live USING (round_id, vout)),
			 per_batch AS (
			   SELECT l.round_id, l.vout,
			          coalesce(sum(l.value) FILTER (WHERE l.released AND NOT l.reclaimed), 0) AS released,
			          coalesce(sum(l.value) FILTER (WHERE l.transferred), 0) AS transferred,
			          bool_and(l.released) AS all_released
			   FROM leaves l GROUP BY 1, 2),
			 back AS (
			   SELECT x.round_id, x.vout, sum(c.value) AS v
			   FROM (SELECT DISTINCT b.round_id, b.vout, b.asset, k.txid FROM live b
			         JOIN batch_leaf bl USING (round_id, vout)
			         JOIN node_release nr ON nr.leaf_id = bl.leaf_id
			         JOIN reclaimed_node k ON k.node_hash = nr.node_hash) x
			   JOIN wallet_coin c ON c.txid = x.txid AND c.asset = x.asset
			   GROUP BY 1, 2),
			 locked AS (
			   SELECT b.asset, sum(b.value - coalesce(bk.v, 0)) AS locked, sum(coalesce(p.released, 0)) AS released,
			          sum(CASE WHEN p.all_released THEN coalesce(p.released, 0) ELSE 0 END) AS reclaimable,
			          sum(coalesce(p.transferred, 0)) AS transferred
			   FROM live b LEFT JOIN per_batch p USING (round_id, vout) LEFT JOIN back bk USING (round_id, vout)
			   GROUP BY 1),
			 drawn AS (
			   SELECT asset, sum(v) AS drawn FROM (
			     SELECT b.asset, b.value AS v FROM batch b JOIN round r USING (round_id)
			     WHERE r.state IN ('broadcast', 'final') AND r.created_at >= now() - interval '1 hour'
			     UNION ALL
			     SELECT po.asset, ro.value FROM round_offboard ro JOIN round r USING (round_id)
			     JOIN participation_output po ON po.participation_id = ro.participation_id AND po.idx = ro.output_idx
			     WHERE r.state IN ('broadcast', 'final') AND r.created_at >= now() - interval '1 hour') d
			   GROUP BY 1),
			 returned AS (
			   SELECT c.asset, coalesce(sum(c.value) FILTER (WHERE w.kind = 'reclaim'), 0) AS reclaimed,
			          coalesce(sum(c.value) FILTER (WHERE w.kind = 'sweep'), 0) AS swept
			   FROM wallet_coin c JOIN watcher_tx w USING (txid)
			   WHERE w.kind IN ('reclaim', 'sweep') AND c.found_in IS NOT NULL AND c.found_at >= now() - interval '1 hour'
			   GROUP BY 1)
			 SELECT a.asset, coalesce(l.locked, 0)::BIGINT, coalesce(l.released, 0)::BIGINT, coalesce(l.reclaimable, 0)::BIGINT,
			        coalesce(d.drawn, 0)::BIGINT, coalesce(r.reclaimed, 0)::BIGINT, coalesce(r.swept, 0)::BIGINT,
			        coalesce(l.transferred, 0)::BIGINT
			 FROM (SELECT asset FROM locked UNION SELECT asset FROM drawn UNION SELECT asset FROM returned) a
			 LEFT JOIN locked l USING (asset) LEFT JOIN drawn d USING (asset) LEFT JOIN returned r USING (asset)",
			&[],
		).await?;
		let mut out = BTreeMap::new();
		for r in &rows {
			let n = |i: usize| r.get::<_, i64>(i).max(0) as u64;
			out.insert(array32(r.get(0), "asset")?, PoolFlow {
				locked: n(1), released: n(2), reclaimable: n(3), drawn_last_hour: n(4), reclaimed_last_hour: n(5), swept_last_hour: n(6),
				transferred: n(7),
			});
		}
		Ok(out)
	}
}
