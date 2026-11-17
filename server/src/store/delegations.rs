//! What the store keeps for RECLAIM-D ([`crate::delegations`]): each coin's
//! delegation of its release to the outputs of the reassignment it moved
//! into, and each holder's releases of the lowest nodes its coin rests on
//! (in `node_release`, beside the releases of batch leaves).

use std::collections::{HashMap, HashSet};

use tokio_postgres::{GenericClient, Row};

use super::{array32, LeafRow, SendRow, Store, StoreError};

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

/// A delegation from its row (`transfer_id, signature, …`).
fn delegation_row(r: &Row) -> Result<DelegationRow, StoreError> {
	Ok(DelegationRow { transfer_id: array32(r.get(0), "transfer id")?, signature: sig64(r.get(1))? })
}

/// A release from its row (`round_id, connector_asset, signature, …`).
fn release_row(r: &Row) -> Result<HolderReleaseRow, StoreError> {
	Ok(HolderReleaseRow {
		round_id: r.get(0),
		connector_asset: array32(r.get(1), "connector asset")?,
		signature: sig64(r.get(2))?,
	})
}

/// What the store holds of many coins at once, as the reads of one coin at a
/// time ([`Store::spent_by`], [`Store::delegation`], [`Store::leaf`],
/// [`Store::holder_releases`], [`Store::paid_send_releases`],
/// [`Store::refresh_open`], [`Store::send_of_leaf`]) would each find it:
/// read in one round of statements over one connection
/// ([`Store::coin_reads`]), so a walk over a few hundred coins (the
/// operator's `holding_back`) costs a few statements and not a few for each
/// coin. Each answer is `None` for a coin not read here, and for a coin
/// whose rows the one-coin read would refuse (two reassignments spending
/// it), which the caller then asks the store after itself. Rows are kept as
/// read and made into their types only when asked for, by the same
/// functions the one-coin reads use, so a row those would find corrupt is
/// found corrupt here too, and only when the walk reaches it.
#[derive(Default)]
pub struct CoinReads {
	read: HashSet<[u8; 32]>,
	/// The reassignments that spent each coin: a signed transfer that took
	/// it as an input, or a fill signed with it as the order coin or a taker
	/// input.
	spending: HashMap<[u8; 32], Vec<[u8; 32]>>,
	/// Each reassignment's outputs that are coins, with their owner keys,
	/// in output order.
	outputs: HashMap<[u8; 32], Vec<([u8; 32], [u8; 32])>>,
	leaves: HashMap<[u8; 32], Row>,
	delegations: HashMap<[u8; 32], Row>,
	/// Each coin's releases not retired, by round, each with its node.
	releases: HashMap<[u8; 32], Vec<([u8; 32], Row)>>,
	/// Each coin's releases by a paid payment's sender naming a final round,
	/// by round, each with its node.
	paid_releases: HashMap<[u8; 32], Vec<([u8; 32], Row)>>,
	refresh_open: HashSet<[u8; 32]>,
	sends: HashMap<[u8; 32], Row>,
}

impl CoinReads {
	/// Whether `id`'s rows were read.
	pub fn has(&self, id: &[u8; 32]) -> bool {
		self.read.contains(id)
	}

	/// The coins read.
	pub fn coins(&self) -> impl Iterator<Item = &[u8; 32]> {
		self.read.iter()
	}

	/// Adds what `other` read.
	pub fn extend(&mut self, other: CoinReads) {
		self.read.extend(other.read);
		self.spending.extend(other.spending);
		self.outputs.extend(other.outputs);
		self.leaves.extend(other.leaves);
		self.delegations.extend(other.delegations);
		self.releases.extend(other.releases);
		self.paid_releases.extend(other.paid_releases);
		self.refresh_open.extend(other.refresh_open);
		self.sends.extend(other.sends);
	}

	/// [`Store::spent_by`].
	pub fn spent_by(&self, id: &[u8; 32]) -> Option<Result<SpentBy, StoreError>> {
		if !self.has(id) {
			return None;
		}
		match self.spending.get(id).map(Vec::as_slice) {
			Some([t]) => Some(Ok(SpentBy::Reassignment { transfer_id: *t, outputs: self.outputs.get(t).cloned().unwrap_or_default() })),
			Some(_) => None,
			None => Some(Ok(match self.leaves.get(id).map(|r| r.get::<_, &str>(8)) {
				Some("spent") => SpentBy::Other,
				_ => SpentBy::Nothing,
			})),
		}
	}

	/// [`Store::delegation`].
	pub fn delegation(&self, id: &[u8; 32]) -> Option<Result<Option<DelegationRow>, StoreError>> {
		self.has(id).then(|| self.delegations.get(id).map(delegation_row).transpose())
	}

	/// [`Store::leaf`].
	pub fn leaf(&self, id: &[u8; 32]) -> Option<Result<Option<LeafRow>, StoreError>> {
		self.has(id).then(|| self.leaves.get(id).map(super::coins::leaf_row).transpose())
	}

	/// [`Store::holder_releases`].
	pub fn holder_releases(&self, id: &[u8; 32], node_hash: &[u8; 32]) -> Option<Result<Vec<HolderReleaseRow>, StoreError>> {
		self.has(id).then(|| of_node(self.releases.get(id), node_hash))
	}

	/// [`Store::paid_send_releases`].
	pub fn paid_send_releases(&self, id: &[u8; 32], node_hash: &[u8; 32]) -> Option<Result<Vec<HolderReleaseRow>, StoreError>> {
		self.has(id).then(|| of_node(self.paid_releases.get(id), node_hash))
	}

	/// [`Store::refresh_open`].
	pub fn refresh_open(&self, id: &[u8; 32]) -> Option<bool> {
		self.has(id).then(|| self.refresh_open.contains(id))
	}

	/// [`Store::send_of_leaf`].
	pub fn send_of_leaf(&self, id: &[u8; 32]) -> Option<Result<Option<SendRow>, StoreError>> {
		self.has(id).then(|| self.sends.get(id).map(super::lightning::row_of).transpose())
	}
}

/// Of a coin's releases, those of `node_hash`, in the order read.
fn of_node(rows: Option<&Vec<([u8; 32], Row)>>, node_hash: &[u8; 32]) -> Result<Vec<HolderReleaseRow>, StoreError> {
	rows.into_iter().flatten().filter(|(n, _)| n == node_hash).map(|(_, r)| release_row(r)).collect()
}

/// The 32-byte id in column `i` of `r`.
fn id_at(r: &Row, i: usize) -> Result<[u8; 32], StoreError> {
	array32(r.get(i), "coin id")
}

/// [`Store::coin_reads`] on `conn`: a connection, or a transaction whose
/// snapshot every read of it sees ([`super::Snapshot`]).
pub(super) async fn coin_reads_on(conn: &(impl GenericClient + Sync), ids: &[[u8; 32]]) -> Result<CoinReads, StoreError> {
	let mut out = CoinReads { read: ids.iter().copied().collect(), ..CoinReads::default() };
	if ids.is_empty() {
		return Ok(out);
	}
	let asked: Vec<&[u8]> = ids.iter().map(|i| &i[..]).collect();
	// Sent together, so the connection carries them one after another
	// without waiting for each answer.
	let leaf_sql = format!("SELECT {} FROM leaf WHERE leaf_id = ANY($1::bytea[])", super::coins::LEAF_COLUMNS);
	let send_sql = format!("SELECT {} FROM lightning_send WHERE htlc_leaf_id = ANY($1::bytea[])", super::lightning::COLUMNS);
	let by: [&(dyn tokio_postgres::types::ToSql + Sync); 1] = [&asked];
	let (spending, leaves, delegations, releases, paid, open, sends) = tokio::try_join!(
		// As `spent_by`'s first statement, for every coin at once.
		conn.query(
			"SELECT DISTINCT leaf, transfer_id FROM (
			   SELECT ti.leaf_id AS leaf, ti.transfer_id FROM transfer_input ti JOIN transfer t USING (transfer_id)
			   WHERE ti.leaf_id = ANY($1::bytea[]) AND (t.state = 'signed'
			     OR EXISTS (SELECT 1 FROM order_fill f WHERE f.transfer_id = ti.transfer_id AND f.signature IS NOT NULL))
			   UNION
			   SELECT f.order_leaf, f.transfer_id FROM order_fill f WHERE f.order_leaf = ANY($1::bytea[]) AND f.signature IS NOT NULL) s",
			&by),
		conn.query(leaf_sql.as_str(), &by),
		conn.query("SELECT transfer_id, signature, leaf_id FROM delegation WHERE leaf_id = ANY($1::bytea[])", &by),
		conn.query(
			"SELECT round_id, connector_asset, signature, leaf_id, node_hash FROM node_release
			 WHERE leaf_id = ANY($1::bytea[]) AND NOT retired ORDER BY leaf_id, round_id",
			&by),
		conn.query(
			"SELECT nr.round_id, nr.connector_asset, nr.signature, nr.leaf_id, nr.node_hash FROM node_release nr JOIN round r USING (round_id)
			 WHERE nr.leaf_id = ANY($1::bytea[]) AND nr.participation_id IS NULL AND r.state = 'final' ORDER BY nr.leaf_id, nr.round_id",
			&by),
		conn.query(
			"SELECT DISTINCT pi.leaf_id FROM participation_input pi JOIN participation p USING (participation_id)
			 WHERE pi.leaf_id = ANY($1::bytea[]) AND pi.active AND p.state IN ('pending', 'issued')",
			&by),
		conn.query(send_sql.as_str(), &by),
	)?;
	for r in &spending {
		out.spending.entry(id_at(r, 0)?).or_default().push(array32(r.get(1), "transfer id")?);
	}
	// As `spent_by`'s second statement, for every reassignment found.
	let transfers: Vec<Vec<u8>> = out.spending.values().flatten().map(|t| t.to_vec()).collect::<HashSet<_>>().into_iter().collect();
	if !transfers.is_empty() {
		for r in conn.query(
			"SELECT o.transfer_id, o.leaf_id, l.owner_key FROM transfer_output o JOIN leaf l USING (leaf_id)
			 WHERE o.transfer_id = ANY($1::bytea[]) ORDER BY o.transfer_id, o.idx",
			&[&transfers]).await?
		{
			out.outputs.entry(array32(r.get(0), "transfer id")?).or_default()
				.push((array32(r.get(1), "leaf id")?, array32(r.get(2), "owner key")?));
		}
	}
	for r in leaves {
		out.leaves.insert(id_at(&r, 0)?, r);
	}
	for r in delegations {
		out.delegations.insert(id_at(&r, 2)?, r);
	}
	for r in releases {
		out.releases.entry(id_at(&r, 3)?).or_default().push((array32(r.get(4), "node hash")?, r));
	}
	for r in paid {
		out.paid_releases.entry(id_at(&r, 3)?).or_default().push((array32(r.get(4), "node hash")?, r));
	}
	for r in &open {
		out.refresh_open.insert(id_at(r, 0)?);
	}
	for r in sends {
		out.sends.insert(id_at(&r, 6)?, r);
	}
	Ok(out)
}

impl Store {
	/// The rows of each coin of `ids` that the one-coin reads of a reclaim's
	/// walk find ([`CoinReads`]), in one round of statements over one
	/// connection.
	pub async fn coin_reads(&self, ids: &[[u8; 32]]) -> Result<CoinReads, StoreError> {
		self.counters.read_ahead.fetch_add(ids.len() as u64, std::sync::atomic::Ordering::SeqCst);
		let conn = self.conn().await?;
		coin_reads_on(&**conn, ids).await
	}

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
		r.as_ref().map(delegation_row).transpose()
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
		rows.iter().map(release_row).collect()
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
		rows.iter().map(release_row).collect()
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
