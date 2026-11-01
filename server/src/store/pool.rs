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
	/// Of that, the leaves whose holders released their lowest node, or their
	/// slot of an accumulator batch, not reclaimed yet: back once every leaf
	/// of their lowest node is released, a slot on its own.
	pub released: u64,
	/// Of that, the lowest nodes of tree batches every leaf of which is
	/// released: the watcher unrolls toward them and reclaims them on its
	/// next passes, whoever else rests on their batch. Leaves are laid into
	/// lowest nodes as the builder lays them ([`arca_covenant::tree::spread`]).
	/// A released slot of an accumulator batch is reclaimable on its own: the
	/// watcher releases it on its next pass.
	pub reclaimable: u64,
	/// Of `locked`, the leaves paid on out of round (given up in a
	/// transfer, or a resting order's coin a fill spent), not reclaimed yet: no release of their lowest node can come
	/// from their owner, so they come back by RECLAIM-D once every coin they
	/// became is refreshed and released ([`crate::delegations`]), or else at
	/// their batch's expiry.
	pub transferred: u64,
	/// What the batches of the rounds built in the last hour, and their
	/// offboards, took out of the pool.
	pub drawn_last_hour: u64,
	/// What reclaims paid back to the wallet in the last hour.
	pub reclaimed_last_hour: u64,
	/// What sweeps of expired batches paid back in the last hour.
	pub swept_last_hour: u64,
	/// What the operator fronted for refreshes and offboards whose old coins
	/// have not come back: each coin given up in a round broadcast or final,
	/// while a batch leaf of its asset it rests on (its own, or one up its
	/// lineage of reassignments) is in a batch neither reclaimed there nor
	/// swept. A coin resting on boards alone is not counted: its forfeit
	/// pays the operator back at once.
	pub in_flight: u64,
}

/// The common part of [`Store::in_flight`] and [`Store::in_flight_slots`]:
/// each coin given up in a round broadcast or final, its lineage up through
/// reassignments, and what has come back.
const IN_FLIGHT_WITH: &str = "
	WITH RECURSIVE given AS MATERIALIZED (
	   SELECT pi.leaf_id, pi.asset, pi.value FROM participation_input pi
	   JOIN participation p USING (participation_id) JOIN round r ON r.round_id = p.round_id
	   WHERE pi.active AND p.state IN ('issued', 'released') AND r.state IN ('broadcast', 'final')),
	 up (root, asset, leaf_id, depth) AS (
	   SELECT leaf_id, asset, leaf_id, 0 FROM given
	   UNION
	   SELECT u.root, u.asset, p.parent, u.depth + 1 FROM up u
	   JOIN transfer_output o ON o.leaf_id = u.leaf_id
	   JOIN LATERAL (SELECT ti.leaf_id AS parent FROM transfer_input ti WHERE ti.transfer_id = o.transfer_id
	                 UNION ALL SELECT f.order_leaf FROM order_fill f WHERE f.transfer_id = o.transfer_id) p ON true
	   WHERE u.depth < 8),
	 swept AS MATERIALIZED (
	   SELECT DISTINCT b.round_id, b.vout FROM batch b JOIN watcher_tx w ON w.subject = b.token JOIN nursery_tx n USING (txid)
	   WHERE w.kind = 'sweep' AND n.state = 'final'),
	 back AS MATERIALIZED (
	   SELECT rl.leaf_id FROM reclaimed_leaf rl JOIN nursery_tx n USING (txid) WHERE n.state <> 'lost'
	   UNION
	   SELECT nr.leaf_id FROM node_release nr JOIN watcher_tx w ON w.kind = 'reclaim' AND w.subject = nr.node_hash
	   JOIN nursery_tx n ON n.txid = w.txid WHERE n.state <> 'lost'
	   UNION
	   -- A leaf of a batch without a sweep, collected: brought down to its
	   -- leaf and forfeited on the chain, the forfeit final.
	   SELECT bl.leaf_id FROM batch_leaf bl JOIN batch b ON b.round_id = bl.round_id AND b.vout = bl.vout
	   JOIN watcher_tx w ON w.kind = 'forfeit' AND w.subject = bl.leaf_id JOIN nursery_tx n ON n.txid = w.txid
	   WHERE b.collect_mtp IS NOT NULL AND n.state = 'final'),
	 held AS MATERIALIZED (
	   SELECT u.root, bl.leaf_id, bl.round_id, bl.vout, bl.record FROM up u
	   JOIN batch_leaf bl ON bl.leaf_id = u.leaf_id JOIN batch b ON b.round_id = bl.round_id AND b.vout = bl.vout
	   JOIN round r ON r.round_id = b.round_id
	   WHERE b.asset = u.asset AND r.state IN ('broadcast', 'final')
	     AND NOT EXISTS (SELECT 1 FROM swept s WHERE s.round_id = bl.round_id AND s.vout = bl.vout)
	     AND NOT EXISTS (SELECT 1 FROM back k WHERE k.leaf_id = bl.leaf_id))";

/// The value in flight, by asset: each coin given up counted once, however
/// many of its batch leaves still hold value.
const IN_FLIGHT: &str = "SELECT g.asset, sum(g.value)::BIGINT FROM given g WHERE g.leaf_id IN (SELECT root FROM held) GROUP BY 1";

/// The batch leaves that hold value in flight: each one's id, batch and
/// leaf record.
const IN_FLIGHT_SLOTS: &str = "SELECT DISTINCT leaf_id, round_id, vout, record FROM held";

impl Store {
	/// Each asset's pool flow, by asset: see [`PoolFlow`]. One read-only
	/// statement.
	pub async fn pool_flow(&self) -> Result<BTreeMap<[u8; 32], PoolFlow>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(
			"WITH live AS (
			   SELECT b.round_id, b.vout, b.asset, b.value, b.radix, b.kind FROM batch b JOIN round r USING (round_id)
			   WHERE r.state IN ('broadcast', 'final')
			     AND NOT EXISTS (SELECT 1 FROM watcher_tx w JOIN nursery_tx n USING (txid)
			                     WHERE w.kind = 'sweep' AND w.subject = b.token AND n.state = 'final')),
			 reclaimed_node AS (
			   SELECT DISTINCT w.subject AS node_hash, w.txid FROM watcher_tx w JOIN nursery_tx n USING (txid)
			   WHERE w.kind = 'reclaim' AND n.state <> 'lost'),
			 leaves AS (
			   SELECT bl.round_id, bl.vout, bl.idx, bl.value, live.radix, live.kind,
			          (EXISTS (SELECT 1 FROM node_release nr WHERE nr.leaf_id = bl.leaf_id AND NOT nr.retired)
			           OR EXISTS (SELECT 1 FROM slot_release sr WHERE sr.leaf_id = bl.leaf_id AND NOT sr.retired)) AS released,
			          (EXISTS (SELECT 1 FROM node_release nr JOIN reclaimed_node k USING (node_hash)
			                  WHERE nr.leaf_id = bl.leaf_id)
			           OR EXISTS (SELECT 1 FROM reclaimed_leaf rl JOIN nursery_tx n USING (txid)
			                      WHERE rl.leaf_id = bl.leaf_id AND n.state <> 'lost')) AS reclaimed,
			          (EXISTS (SELECT 1 FROM transfer_input ti WHERE ti.leaf_id = bl.leaf_id)
			           OR EXISTS (SELECT 1 FROM order_fill f WHERE f.order_leaf = bl.leaf_id AND f.signature IS NOT NULL)) AS transferred
			   FROM batch_leaf bl JOIN live USING (round_id, vout)),
			 per_batch AS (
			   SELECT l.round_id, l.vout,
			          coalesce(sum(l.value) FILTER (WHERE l.released AND NOT l.reclaimed), 0) AS released,
			          coalesce(sum(l.value) FILTER (WHERE l.transferred AND NOT l.reclaimed), 0) AS transferred,
			          bool_and(l.released) AS all_released
			   FROM leaves l GROUP BY 1, 2),
			 sized AS (
			   SELECT l.*, count(*) OVER (PARTITION BY l.round_id, l.vout) AS n FROM leaves l WHERE l.kind = 'tree'),
			 spread AS (
			   SELECT s.*, (s.n + s.radix - 1) / s.radix AS k FROM sized s),
			 placed AS (
			   SELECT p.*, p.n / p.k AS q, p.n % p.k AS rem FROM spread p),
			 per_node AS (
			   SELECT p.round_id, p.vout,
			          CASE WHEN p.idx < p.rem * (p.q + 1) THEN p.idx / (p.q + 1) ELSE p.rem + (p.idx - p.rem * (p.q + 1)) / p.q END AS node,
			          coalesce(sum(p.value) FILTER (WHERE p.released AND NOT p.reclaimed), 0) AS released,
			          bool_and(p.released) AS all_released
			   FROM placed p GROUP BY 1, 2, 3),
			 node_back AS (
			   SELECT round_id, vout, sum(released) AS reclaimable FROM per_node WHERE all_released GROUP BY 1, 2
			   UNION ALL
			   -- A slot of an accumulator batch is released on its own.
			   SELECT l.round_id, l.vout, sum(l.value) FROM leaves l WHERE l.kind = 'accumulator' AND l.released AND NOT l.reclaimed
			   GROUP BY 1, 2),
			 back AS (
			   SELECT x.round_id, x.vout, sum(c.value) AS v
			   FROM (SELECT b.round_id, b.vout, b.asset, k.txid FROM live b
			         JOIN batch_leaf bl USING (round_id, vout)
			         JOIN node_release nr ON nr.leaf_id = bl.leaf_id
			         JOIN reclaimed_node k ON k.node_hash = nr.node_hash
			         UNION
			         SELECT b.round_id, b.vout, b.asset, k.txid FROM live b
			         JOIN batch_leaf bl USING (round_id, vout)
			         JOIN reclaimed_leaf k ON k.leaf_id = bl.leaf_id JOIN nursery_tx n ON n.txid = k.txid WHERE n.state <> 'lost') x
			   JOIN wallet_coin c ON c.txid = x.txid AND c.asset = x.asset
			   GROUP BY 1, 2),
			 locked AS (
			   SELECT b.asset, sum(b.value - coalesce(bk.v, 0)) AS locked, sum(coalesce(p.released, 0)) AS released,
			          sum(coalesce(nb.reclaimable, 0)) AS reclaimable,
			          sum(coalesce(p.transferred, 0)) AS transferred
			   FROM live b LEFT JOIN per_batch p USING (round_id, vout) LEFT JOIN back bk USING (round_id, vout)
			   LEFT JOIN (SELECT round_id, vout, sum(reclaimable) AS reclaimable FROM node_back GROUP BY 1, 2) nb USING (round_id, vout)
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
				transferred: n(7), in_flight: 0,
			});
		}
		for (asset, v) in self.in_flight().await? {
			out.entry(asset).or_default().in_flight = v;
		}
		Ok(out)
	}

	/// What is in flight of each asset ([`PoolFlow::in_flight`]), by asset.
	/// One read-only statement.
	pub async fn in_flight(&self) -> Result<BTreeMap<[u8; 32], u64>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!("{} {}", IN_FLIGHT_WITH, IN_FLIGHT), &[]).await?;
		rows.iter().map(|r| Ok((array32(r.get(0), "asset")?, r.get::<_, i64>(1).max(0) as u64))).collect()
	}

	/// The batch leaves whose value is in flight: each given up, or paid on
	/// and some coin it became given up, in a round broadcast or final, its
	/// batch neither reclaimed there nor swept. By leaf id, with its batch
	/// (round and output) and its leaf record. A tree's lowest nodes above
	/// them are the ones that hold fronted value.
	pub async fn in_flight_slots(&self) -> Result<Vec<([u8; 32], i64, u32, Vec<u8>)>, StoreError> {
		let conn = self.conn().await?;
		let rows = conn.query(&format!("{} {}", IN_FLIGHT_WITH, IN_FLIGHT_SLOTS), &[]).await?;
		rows.iter().map(|r| Ok((array32(r.get(0), "leaf id")?, r.get(1), r.get::<_, i32>(2) as u32, r.get(3)))).collect()
	}
}
