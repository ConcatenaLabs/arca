//! The operator's `holding_back` read at a server's scale: a holder of many
//! live coins, each resting on a lowest node of a real batch tree whose
//! other slots are in every state the read tells apart (held by another
//! holder, at hand or away; given up in a refresh, released or still open
//! or neither; moved into a reassignment, with a delegation or without;
//! the `htlc-1` leaf of a paid payment out of the tree), among the rows
//! of an operator of the testnet's size.
//!
//! `a_read_of_64_coins_takes_a_few_statements` runs in every suite: the
//! number of statements one read makes does not grow with the coins asked.
//! So do the two lineage tests: below a node, a slot moved on in a tree of
//! payments four ways at every step, 87,380 coins in all, without
//! delegations or with them. The walk stops at the first undelegated step,
//! and a delegated tree past its steps' budget keeps the node; a read
//! ahead of it reads no more coins than the walk can
//! ([`server::delegations::WALK_READS`]), and takes a few milliseconds.
//! And `a_round_ending_is_seen_whole_or_not_at_all`: while a round ends in
//! one transaction (a refresh's participation released, with the releases
//! of the two coins it gave up), every read answers as before it or as
//! after it, never a mix of the two.
//! `holding_back_at_scale` is the measurement, run by hand: it prints what
//! each read of 64 coins and one read of every coin take, writes every
//! answer to `HB_ANSWERS` when set (so two revisions' answers can be
//! compared on the same data), and fails when a read of 64 coins takes more
//! than `HB_BAR_MS` (default 50 ms) at the median of the passes after
//! the first.

mod common;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use arca_covenant::{Chain, ClockSchedule, LeafSpec, ReserveRule, RelativeTime, Template, Tree, TreeParams};
use common::db::TestDb;
use elements::hashes::Hash;
use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey};
use elements::{AssetId, BlockHash};
use server::rounds::{holding_back, ActiveCoins};
use tokio_postgres::NoTls;

/// A deterministic stream of numbers, so every run builds the same rows.
struct Rng(u64);

impl Rng {
	fn next(&mut self) -> u64 {
		self.0 ^= self.0 << 13;
		self.0 ^= self.0 >> 7;
		self.0 ^= self.0 << 17;
		self.0
	}
	fn below(&mut self, n: u64) -> u64 {
		self.next() % n
	}
	fn chance(&mut self, percent: u64) -> bool {
		self.below(100) < percent
	}
}

fn h(label: &str) -> [u8; 32] {
	use elements::hashes::sha256;
	sha256::Hash::hash(label.as_bytes()).to_byte_array()
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// The rows to write, column by column, for one table.
#[derive(Default)]
struct Rows {
	leaf: Vec<(Vec<u8>, &'static str, i64, Vec<u8>, Vec<u8>, &'static str, Option<Vec<u8>>)>,
	round: Vec<(i64, &'static str)>,
	batch: Vec<(i64, i32, bool)>,
	batch_leaf: Vec<(Vec<u8>, i64, i32, i32, Vec<u8>, i64, Vec<u8>)>,
	transfer: Vec<Vec<u8>>,
	transfer_input: Vec<(Vec<u8>, i16, Vec<u8>)>,
	transfer_output: Vec<(Vec<u8>, i16, Vec<u8>, Vec<u8>)>,
	delegation: Vec<(Vec<u8>, Vec<u8>)>,
	participation: Vec<(Vec<u8>, &'static str)>,
	participation_input: Vec<(Vec<u8>, Vec<u8>)>,
	node_release: Vec<(Vec<u8>, i64, Option<Vec<u8>>, Vec<u8>)>,
	send: Vec<(Vec<u8>, Vec<u8>)>,
}

/// What a holder of `coins` live coins looks like to the operator: the
/// coins, in the order a wallet asks after them, with the keys that hold
/// them and those of other holders marked at hand.
struct Holder {
	coins: Vec<[u8; 32]>,
	others: Vec<[u8; 32]>,
	active: ActiveCoins,
}

/// How many leaves a batch under one of the testnet's large holders has,
/// by the counts read from the operator (361 of 490 hold one).
fn batch_size(rng: &mut Rng) -> usize {
	match rng.below(490) {
		0..=360 => 1,
		361..=403 => 2,
		404..=429 => 3,
		430..=449 => 4,
		450..=462 => 5 + rng.below(4) as usize,
		_ => 9 + rng.below(6) as usize,
	}
}

async fn session(url: &str) -> tokio_postgres::Client {
	let (client, conn) = tokio_postgres::connect(url, NoTls).await.expect("connect");
	tokio::spawn(async move {
		let _ = conn.await;
	});
	client
}

/// The rows of a testnet-sized operator that no read here reaches, by the
/// row counts of the testnet's operator, scaled by `scale`.
async fn background(c: &tokio_postgres::Client, scale: f64) {
	let n = |x: f64| (x * scale) as i64;
	let sql = format!(r#"
CREATE OR REPLACE FUNCTION hb(t text) RETURNS bytea LANGUAGE sql IMMUTABLE AS $f$ SELECT sha256(convert_to(t,'UTF8')) $f$;
INSERT INTO round (round_id, txid, tx, state, fee_asset, fee, created_mtp, final_mtp)
  SELECT 100000 + i, hb('bgr'||i), '\x00', 'final', hb('fee'), 1, 1700000000, 1700000000 FROM generate_series(1, {rounds}) i;
INSERT INTO connector_output (round_id, vout, asset, value, connector_asset)
  SELECT 100000 + i, 0, hb('fee'), 1, hb('bgc'||i) FROM generate_series(1, {rounds}) i;
INSERT INTO batch (round_id, vout, asset, value, token, token_vout, issuer_txid, issuer_vout, schedule, burn, radix,
    reserve_kind, reserve_a, reserve_b, min_leaf, kind, delegated_reclaim)
  SELECT 100000 + (i % {rounds}) + 1, 1 + i / {rounds}, hb('asset'), 1000, hb('bgt'||i), 0, hb('bgi'||i), 0, '\x00', false, 4,
    'fixed', 0, 0, 1, 'tree', true FROM generate_series(0, {batches} - 1) i;
INSERT INTO leaf (leaf_id, kind, asset, value, owner_key, script_pubkey, hops, record, state, spent_by)
  SELECT hb('bgl'||i), CASE WHEN i <= {batch_leaves} THEN 'batch'::leaf_kind ELSE 'transfer'::leaf_kind END, hb('asset'), 1000,
    hb('bgk'||i), hb('bgs'||i), 0, decode(repeat('ab', 450), 'hex'),
    CASE WHEN i % 7 = 0 THEN 'live'::leaf_state ELSE 'spent'::leaf_state END,
    CASE WHEN i % 7 = 0 THEN NULL ELSE hb('bgx'||i) END
  FROM generate_series(1, {leaves}) i;
INSERT INTO batch_leaf (leaf_id, round_id, vout, idx, participation_id, output_idx, attempt, template, owner_key, owner_nonce,
    operator_nonce, exit_delay_units, value, unlock_hash, record)
  SELECT hb('bgl'||i), 100000 + ((i - 1) % {batches}) % {rounds} + 1, 1 + ((i - 1) % {batches}) / {rounds}, (i - 1) / {batches},
    hb('bgp'||i), 0, 0, 'vtxo-1', hb('bgk'||i), hb('bgon'||i), hb('bgopn'||i), 1, 1000, hb('bgu'||i), decode(repeat('ab', 450), 'hex')
  FROM generate_series(1, {batch_leaves}) i;
INSERT INTO transfer (transfer_id, request_hash, state) SELECT hb('bgtr'||i), hb('bgrq'||i), 'signed' FROM generate_series(1, {transfers}) i;
INSERT INTO transfer_input (transfer_id, idx, leaf_id, checkpoint_value, checkpoint_owner_sig, reassignment_owner_sig)
  SELECT hb('bgtr'||(i % {transfers} + 1)), i / {transfers}, hb('bgl'||(i * 3 % {leaves} + 1)), 1, decode(repeat('00', 64), 'hex'),
    decode(repeat('00', 64), 'hex') FROM generate_series(0, {inputs} - 1) i ON CONFLICT DO NOTHING;
INSERT INTO transfer_output (transfer_id, idx, leaf_id, mailbox_key)
  SELECT hb('bgtr'||(i % {transfers} + 1)), i / {transfers}, hb('bgl'||({batch_leaves} + i + 1)), hb('bgm'||(i % 300))
  FROM generate_series(0, {outputs} - 1) i ON CONFLICT DO NOTHING;
INSERT INTO delegation (leaf_id, transfer_id, signature)
  SELECT hb('bgl'||(i * 3 % {leaves} + 1)), hb('bgtr'||(i % {transfers} + 1)), decode(repeat('00', 64), 'hex')
  FROM generate_series(0, {delegations} - 1) i ON CONFLICT DO NOTHING;
INSERT INTO participation (participation_id, unlock_hash, preimage, refund_delay_units, state)
  SELECT hb('bgp'||i), hb('bgpu'||i), hb('bgpp'||i), 1, 'released' FROM generate_series(1, {participations}) i;
INSERT INTO participation_input (participation_id, idx, leaf_id, active, asset, value, margin, attestation)
  SELECT hb('bgp'||(i % {participations} + 1)), i / {participations}, hb('bgl'||(i % {leaves} + 1)), i % 2 = 0, hb('asset'), 1000, 0, '\x00'
  FROM generate_series(0, {pinputs} - 1) i ON CONFLICT DO NOTHING;
INSERT INTO node_release (leaf_id, round_id, participation_id, node_hash, connector_asset, signature, retired)
  SELECT hb('bgl'||(i % {leaves} + 1)), 100000 + (i % {rounds}) + 1, NULL, hb('bgn'||(i % 36500)), hb('bgc'), decode(repeat('00', 64), 'hex'), false
  FROM generate_series(0, {releases} - 1) i ON CONFLICT DO NOTHING;
INSERT INTO leaf_mailbox (owner_key, mailbox_key, proof)
  SELECT hb('bgk'||i), hb('bgm'||(i % 300)), decode(repeat('00', 64), 'hex') FROM generate_series(1, {mailboxes}) i;
ANALYZE;
"#,
		rounds = n(31_367.0).max(1), batches = n(39_458.0).max(1), batch_leaves = n(56_021.0).max(1), leaves = n(111_629.0).max(2),
		transfers = n(13_299.0).max(1), inputs = n(25_974.0), outputs = n(34_755.0), delegations = n(23_258.0),
		participations = n(64_354.0).max(1), pinputs = n(127_005.0), releases = n(125_165.0), mailboxes = n(100_166.0));
	c.batch_execute(&sql).await.expect("the background rows");
}

/// A holder of `coins` live coins, written with every row the read follows.
async fn holder(c: &tokio_postgres::Client, coins: usize, seed: u64) -> Holder {
	let secp = Secp256k1::new();
	let mut rng = Rng(seed);
	let mut rows = Rows::default();
	let asset = AssetId::from_byte_array(h("holding back asset"));
	let operator = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&h("operator")).unwrap()).x_only_public_key().0;
	let chain = Chain::new(BlockHash::all_zeros());
	let mailbox = h("the holder's mailbox");
	let mut out = Holder { coins: vec![], others: vec![], active: ActiveCoins::default() };
	let mut n = 0u64;
	let mut fresh = |what: &str| {
		n += 1;
		h(&format!("{} {}", what, n))
	};
	let key = |label: [u8; 32]| -> [u8; 32] {
		Keypair::from_secret_key(&secp, &SecretKey::from_slice(&label).unwrap()).x_only_public_key().0.serialize()
	};
	let mut round_id = 1i64;
	while out.coins.len() < coins {
		let k = batch_size(&mut rng);
		let delegated = rng.chance(95);
		let state = match rng.below(100) {
			0..=93 => "final",
			94..=96 => "broadcast",
			97..=98 => "built",
			_ => "lost",
		};
		let params = TreeParams {
			asset, chain, schedule: ClockSchedule::never(operator), burn: false, delegated_reclaim: delegated, radix: 4,
			reserve: ReserveRule::Fixed { node: 330, entry: 330 }, min_leaf: 1,
		};
		let owners: Vec<[u8; 32]> = (0..k).map(|_| key(fresh("owner"))).collect();
		let specs: Vec<LeafSpec> = owners.iter().map(|o| LeafSpec {
			template: Template::Vtxo1,
			owner: elements::secp256k1_zkp::XOnlyPublicKey::from_slice(o).unwrap(),
			value: 10_000 + rng.below(90_000),
			owner_nonce: fresh("owner nonce"),
			operator_nonce: fresh("operator nonce"),
			exit_delay: RelativeTime::from_units(4).unwrap(),
			unlock_hash: fresh("unlock"),
			htlc: None, order: None, landing: None, channel: None, claim: None,
		}).collect();
		let tree = Tree::build(params, &specs).expect("a tree");
		let records: Vec<Vec<u8>> = tree.records().iter().map(|r| r.to_bytes().unwrap()).collect();
		let ids: Vec<[u8; 32]> = (0..k).map(|_| fresh("leaf")).collect();
		rows.round.push((round_id, state));
		rows.batch.push((round_id, 1, delegated));
		// The node each leaf rests on, as the server reads it.
		let node_of = |i: usize| arca_covenant::LeafRecord::from_bytes(&records[i]).unwrap().branch().unwrap()
			.nodes.last().unwrap().children_hash();
		// The holder's slots: one, or two of a larger batch.
		let mine = if k >= 2 && rng.chance(15) { 2 } else { 1 };
		for i in 0..k {
			let id = ids[i].to_vec();
			let value = specs[i].value as i64;
			rows.batch_leaf.push((id.clone(), round_id, 1, i as i32, owners[i].to_vec(), value, records[i].clone()));
			let node = node_of(i);
			if i < mine {
				if rng.chance(5) {
					// Paid on out of round: the holder holds the payment's change.
					let t = fresh("transfer");
					let (a, b) = (fresh("leaf"), fresh("leaf"));
					rows.leaf.push((id.clone(), "batch", value, owners[i].to_vec(), records[i].clone(), "spent", Some(t.to_vec())));
					rows.transfer.push(t.to_vec());
					rows.transfer_input.push((t.to_vec(), 0, id.clone()));
					rows.transfer_output.push((t.to_vec(), 0, a.to_vec(), mailbox.to_vec()));
					rows.transfer_output.push((t.to_vec(), 1, b.to_vec(), h("another mailbox").to_vec()));
					if delegated || rng.chance(50) {
						rows.delegation.push((id.clone(), t.to_vec()));
					}
					rows.leaf.push((a.to_vec(), "transfer", value / 2, key(fresh("owner")).to_vec(), vec![0xab; 200], "live", None));
					let other = key(fresh("owner"));
					rows.leaf.push((b.to_vec(), "transfer", value - value / 2, other.to_vec(), vec![0xab; 200], "live", None));
					if rng.chance(50) {
						out.active.mark([b], &[h("another mailbox")]);
					}
					out.others.push(b);
					out.coins.push(a);
				} else {
					rows.leaf.push((id.clone(), "batch", value, owners[i].to_vec(), records[i].clone(), "live", None));
					out.coins.push(ids[i]);
				}
				continue;
			}
			match rng.below(100) {
				// Held by another holder, at hand or away.
				0..=34 => {
					rows.leaf.push((id.clone(), "batch", value, owners[i].to_vec(), records[i].clone(), "live", None));
					match rng.below(10) {
						0..=4 => out.active.mark([ids[i]], &[h("another mailbox")]),
						5 => out.active.mark([ids[i]], &[mailbox]),
						_ => {},
					}
					out.others.push(ids[i]);
				},
				// Given up in a refresh: released, still open, or neither.
				35..=69 => {
					let p = fresh("participation");
					rows.leaf.push((id.clone(), "batch", value, owners[i].to_vec(), records[i].clone(), "spent", Some(p.to_vec())));
					match rng.below(10) {
						0..=5 => {
							rows.participation.push((p.to_vec(), "released"));
							rows.node_release.push((id.clone(), round_id + 1, Some(p.to_vec()), node.to_vec()));
						},
						6..=7 => {
							rows.participation.push((p.to_vec(), if rng.chance(50) { "pending" } else { "issued" }));
							rows.participation_input.push((p.to_vec(), id.clone()));
						},
						_ => rows.participation.push((p.to_vec(), "released")),
					}
				},
				// Moved into a reassignment, with its delegation or without.
				70..=94 => {
					let t = fresh("transfer");
					rows.leaf.push((id.clone(), "batch", value, owners[i].to_vec(), records[i].clone(), "spent", Some(t.to_vec())));
					rows.transfer.push(t.to_vec());
					rows.transfer_input.push((t.to_vec(), 0, id.clone()));
					if rng.chance(85) {
						rows.delegation.push((id.clone(), t.to_vec()));
					}
					for o in 0..2 {
						let l = fresh("leaf");
						rows.transfer_output.push((t.to_vec(), o, l.to_vec(), h("another mailbox").to_vec()));
						let v = value / 2;
						if rng.chance(60) {
							rows.leaf.push((l.to_vec(), "transfer", v, key(fresh("owner")).to_vec(), vec![0xab; 200], "live", None));
							if rng.chance(50) {
								out.active.mark([l], &[h("another mailbox")]);
							}
							out.others.push(l);
						} else {
							let p = fresh("participation");
							rows.leaf.push((l.to_vec(), "transfer", v, key(fresh("owner")).to_vec(), vec![0xab; 200], "spent", Some(p.to_vec())));
							rows.participation.push((p.to_vec(), "released"));
							rows.node_release.push((l.to_vec(), round_id + 1, Some(p.to_vec()), node.to_vec()));
						}
					}
				},
				// The htlc-1 leaf of a paid payment out of the tree, released.
				_ => {
					rows.leaf.push((id.clone(), "batch", value, owners[i].to_vec(), records[i].clone(), "live", None));
					rows.send.push((fresh("payment").to_vec(), id.clone()));
					rows.node_release.push((id.clone(), round_id, None, node.to_vec()));
					out.others.push(ids[i]);
				},
			}
		}
		round_id += 1;
	}
	// A round after the last, so a release can name it.
	rows.round.push((round_id, "final"));
	write(c, &rows).await;
	out
}

async fn write(c: &tokio_postgres::Client, r: &Rows) {
	macro_rules! col {
		($v:expr, $f:expr) => { $v.iter().map($f).collect::<Vec<_>>() };
	}
	c.execute("INSERT INTO round (round_id, txid, tx, state, fee_asset, fee, created_mtp, final_mtp)
		SELECT i, hb('r'||i), '\\x00', s, hb('fee'), 1, 1700000000, 1700000000 FROM unnest($1::bigint[], $2::text[]) AS u(i, s)",
		&[&col!(r.round, |x| x.0), &col!(r.round, |x| x.1)]).await.unwrap();
	c.execute("INSERT INTO connector_output (round_id, vout, asset, value, connector_asset)
		SELECT i, 0, hb('fee'), 1, hb('c'||i) FROM unnest($1::bigint[]) AS i", &[&col!(r.round, |x| x.0)]).await.unwrap();
	c.execute("INSERT INTO batch (round_id, vout, asset, value, token, token_vout, issuer_txid, issuer_vout, schedule, burn, radix,
		reserve_kind, reserve_a, reserve_b, min_leaf, kind, delegated_reclaim)
		SELECT i, v, hb('asset'), 1000, hb('t'||i||'.'||v), 0, hb('i'||i), 0, '\\x00', false, 4, 'fixed', 330, 330, 1, 'tree', d
		FROM unnest($1::bigint[], $2::int[], $3::bool[]) AS u(i, v, d)",
		&[&col!(r.batch, |x| x.0), &col!(r.batch, |x| x.1), &col!(r.batch, |x| x.2)]).await.unwrap();
	c.execute("INSERT INTO leaf (leaf_id, kind, asset, value, owner_key, script_pubkey, hops, record, state, spent_by)
		SELECT id, k::leaf_kind, hb('asset'), v, o, id, 0, rec, s::leaf_state, sb
		FROM unnest($1::bytea[], $2::text[], $3::bigint[], $4::bytea[], $5::bytea[], $6::text[], $7::bytea[]) AS u(id, k, v, o, rec, s, sb)",
		&[&col!(r.leaf, |x| x.0.clone()), &col!(r.leaf, |x| x.1), &col!(r.leaf, |x| x.2), &col!(r.leaf, |x| x.3.clone()),
		  &col!(r.leaf, |x| x.4.clone()), &col!(r.leaf, |x| x.5), &col!(r.leaf, |x| x.6.clone())]).await.unwrap();
	c.execute("INSERT INTO batch_leaf (leaf_id, round_id, vout, idx, participation_id, output_idx, attempt, template, owner_key,
		owner_nonce, operator_nonce, exit_delay_units, value, unlock_hash, record)
		SELECT id, ri, v, ix, hb('bp'||encode(id, 'hex')), 0, 0, 'vtxo-1', o, hb('on'||encode(id, 'hex')), hb('opn'||encode(id, 'hex')),
		  4, val, hb('u'||encode(id, 'hex')), rec
		FROM unnest($1::bytea[], $2::bigint[], $3::int[], $4::int[], $5::bytea[], $6::bigint[], $7::bytea[]) AS u(id, ri, v, ix, o, val, rec)",
		&[&col!(r.batch_leaf, |x| x.0.clone()), &col!(r.batch_leaf, |x| x.1), &col!(r.batch_leaf, |x| x.2), &col!(r.batch_leaf, |x| x.3),
		  &col!(r.batch_leaf, |x| x.4.clone()), &col!(r.batch_leaf, |x| x.5), &col!(r.batch_leaf, |x| x.6.clone())]).await.unwrap();
	c.execute("INSERT INTO transfer (transfer_id, request_hash, state) SELECT t, t, 'signed' FROM unnest($1::bytea[]) AS t",
		&[&r.transfer]).await.unwrap();
	c.execute("INSERT INTO transfer_input (transfer_id, idx, leaf_id, checkpoint_value, checkpoint_owner_sig, reassignment_owner_sig)
		SELECT t, i, l, 1, decode(repeat('00', 64), 'hex'), decode(repeat('00', 64), 'hex') FROM unnest($1::bytea[], $2::smallint[], $3::bytea[]) AS u(t, i, l)",
		&[&col!(r.transfer_input, |x| x.0.clone()), &col!(r.transfer_input, |x| x.1), &col!(r.transfer_input, |x| x.2.clone())]).await.unwrap();
	c.execute("INSERT INTO transfer_output (transfer_id, idx, leaf_id, mailbox_key)
		SELECT t, i, l, m FROM unnest($1::bytea[], $2::smallint[], $3::bytea[], $4::bytea[]) AS u(t, i, l, m)",
		&[&col!(r.transfer_output, |x| x.0.clone()), &col!(r.transfer_output, |x| x.1), &col!(r.transfer_output, |x| x.2.clone()),
		  &col!(r.transfer_output, |x| x.3.clone())]).await.unwrap();
	c.execute("INSERT INTO delegation (leaf_id, transfer_id, signature) SELECT l, t, decode(repeat('00', 64), 'hex')
		FROM unnest($1::bytea[], $2::bytea[]) AS u(l, t)",
		&[&col!(r.delegation, |x| x.0.clone()), &col!(r.delegation, |x| x.1.clone())]).await.unwrap();
	c.execute("INSERT INTO participation (participation_id, unlock_hash, preimage, refund_delay_units, state)
		SELECT p, p, p, 1, s::participation_state FROM unnest($1::bytea[], $2::text[]) AS u(p, s)",
		&[&col!(r.participation, |x| x.0.clone()), &col!(r.participation, |x| x.1)]).await.unwrap();
	c.execute("INSERT INTO participation_input (participation_id, idx, leaf_id, active, asset, value, margin, attestation)
		SELECT p, 0, l, true, hb('asset'), 1, 0, '\\x00' FROM unnest($1::bytea[], $2::bytea[]) AS u(p, l)",
		&[&col!(r.participation_input, |x| x.0.clone()), &col!(r.participation_input, |x| x.1.clone())]).await.unwrap();
	c.execute("INSERT INTO node_release (leaf_id, round_id, participation_id, node_hash, connector_asset, signature, retired)
		SELECT l, ri, p, nh, hb('c'||ri), decode(repeat('00', 64), 'hex'), false
		FROM unnest($1::bytea[], $2::bigint[], $3::bytea[], $4::bytea[]) AS u(l, ri, p, nh)",
		&[&col!(r.node_release, |x| x.0.clone()), &col!(r.node_release, |x| x.1), &col!(r.node_release, |x| x.2.clone()),
		  &col!(r.node_release, |x| x.3.clone())]).await.unwrap();
	c.execute("INSERT INTO lightning_send (payment_hash, asset, invoice, amount, fee, transfer_id, htlc_leaf_id, state)
		SELECT ph, hb('asset'), 'lnbc', 1, 0, ph, l, 'paid' FROM unnest($1::bytea[], $2::bytea[]) AS u(ph, l)",
		&[&col!(r.send, |x| x.0.clone()), &col!(r.send, |x| x.1.clone())]).await.unwrap();
	c.batch_execute("ANALYZE").await.unwrap();
}

/// A store whose rows are written as above, its constraints between tables
/// dropped so the rows need not be whole coins.
async fn prepared(scale: f64, coins: usize) -> (TestDb, Holder) {
	let db = TestDb::new().await;
	let c = session(&db.url).await;
	c.batch_execute(r#"
CREATE OR REPLACE FUNCTION hb(t text) RETURNS bytea LANGUAGE sql IMMUTABLE AS $f$ SELECT sha256(convert_to(t,'UTF8')) $f$;
DO $$ DECLARE r record; BEGIN
  FOR r IN SELECT conrelid::regclass t, conname FROM pg_constraint WHERE contype IN ('f', 'c') AND conrelid <> 0
    AND connamespace = 'public'::regnamespace LOOP
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', r.t, r.conname); END LOOP; END $$;
"#).await.expect("drop the constraints");
	if scale > 0.0 {
		background(&c, scale).await;
	}
	let holder = holder(&c, coins, 0x9e37_79b9_7f4a_7c15).await;
	(db, holder)
}

/// Asks after `ids`, returning the answer, the time it took and the
/// statements it made (the pool's checkouts).
async fn ask(db: &TestDb, holder: &Holder, ids: &[[u8; 32]]) -> (Vec<([u8; 32], u64)>, Duration, u64) {
	let before = db.store.pool_status().gets;
	let t = Instant::now();
	let answer = holding_back(&db.store, ids, &holder.active).await.expect("holding_back");
	(answer, t.elapsed(), db.store.pool_status().gets - before)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_of_64_coins_takes_a_few_statements() {
	let (db, holder) = prepared(0.0, 320).await;
	let mut named = 0;
	for chunk in holder.coins.chunks(64) {
		let (answer, _, statements) = ask(&db, &holder, chunk).await;
		named += answer.len();
		assert!(statements <= 24, "a read of {} coins made {} statements", chunk.len(), statements);
	}
	assert!(named > 0, "some coins are named, so the read follows every path");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement at a server's scale: run by hand, with HB_COINS, HB_SCALE, HB_BAR_MS and HB_ANSWERS"]
async fn holding_back_at_scale() {
	let coins: usize = std::env::var("HB_COINS").ok().and_then(|v| v.parse().ok()).unwrap_or(780);
	let scale: f64 = std::env::var("HB_SCALE").ok().and_then(|v| v.parse().ok()).unwrap_or(1.0);
	let bar = Duration::from_millis(std::env::var("HB_BAR_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(50));
	let t = Instant::now();
	let (db, holder) = prepared(scale, coins).await;
	if std::env::var("HB_KEEP").is_ok() {
		let ids: Vec<String> = holder.coins.iter().map(|c| format!("\\x{}", hex(c))).collect();
		std::fs::write(std::env::var("HB_KEEP").unwrap(), format!("{}\n{}\n", db.url, ids.join(","))).unwrap();
		std::mem::forget(db);
		return;
	}
	eprintln!("rows written in {:?}: {} coins, {} other holders' coins, background scale {}", t.elapsed(), holder.coins.len(),
		holder.others.len(), scale);

	let mut answers: BTreeMap<String, Vec<([u8; 32], u64)>> = BTreeMap::new();
	// The first pass, on a server that has just started; the reads timed
	// below are the passes after it, as a running server's are.
	let mut cold = vec![];
	for chunk in holder.coins.chunks(64) {
		cold.push(ask(&db, &holder, chunk).await.1);
	}
	cold.sort();
	eprintln!("first pass, reads of 64 coins: total {:?}, median {:?}, slowest {:?}", cold.iter().sum::<Duration>(),
		cold[cold.len() / 2], cold[cold.len() - 1]);
	let mut times = vec![];
	let mut statements = vec![];
	for (i, chunk) in holder.coins.chunks(64).enumerate() {
		let (a, d, s) = ask(&db, &holder, chunk).await;
		times.push(d);
		statements.push(s);
		answers.insert(format!("chunk {:02}", i), a);
	}
	let (all, all_time, all_statements) = ask(&db, &holder, &holder.coins).await;
	answers.insert("all".into(), all);
	// Mixed asks: the holder's coins with other holders', in other orders.
	let mut rng = Rng(7);
	let mut pool: Vec<[u8; 32]> = holder.coins.iter().chain(&holder.others).copied().collect();
	for i in 0..40 {
		for j in (1..pool.len()).rev() {
			pool.swap(j, rng.below(j as u64 + 1) as usize);
		}
		let n = 1 + rng.below(64) as usize;
		let (a, _, _) = ask(&db, &holder, &pool[..n]).await;
		answers.insert(format!("mixed {:02}", i), a);
	}

	let mut sorted = times.clone();
	sorted.sort();
	let total: Duration = times.iter().sum();
	let named: usize = answers.iter().filter(|(k, _)| k.starts_with("chunk")).map(|(_, v)| v.len()).sum();
	eprintln!("reads of 64 coins: {} reads, total {:?}, median {:?}, slowest {:?}, statements each {:?}", times.len(), total,
		sorted[sorted.len() / 2], sorted[sorted.len() - 1], statements);
	eprintln!("one read of all {} coins: {:?}, {} statements", holder.coins.len(), all_time, all_statements);
	eprintln!("coins named over the reads of 64: {}", named);
	if let Ok(path) = std::env::var("HB_ANSWERS") {
		let mut text = String::new();
		for (k, v) in &answers {
			for (id, back) in v {
				text.push_str(&format!("{} {} {}\n", k, hex(id), back));
			}
			text.push_str(&format!("{} end {}\n", k, v.len()));
		}
		std::fs::write(&path, text).expect("write the answers");
	}
	assert!(named > 0, "some coins are named, so the read follows every path");
	assert!(sorted[sorted.len() / 2] <= bar, "a read of 64 coins takes {:?} at the median, over the bar of {:?}",
		sorted[sorted.len() / 2], bar);
}

/// A node of two slots, `a` live and `b` moved on in a tree of payments
/// `depth` steps deep, each payment taking one coin and making four, with
/// the delegation of every coin into the payment that took it when
/// `delegated`: `(4^(depth+1) - 4) / 3` coins below `b`. Returns `a` and a
/// coin at the tree's last step.
async fn fanned_out(c: &tokio_postgres::Client, depth: u32, delegated: bool) -> ([u8; 32], [u8; 32]) {
	let secp = Secp256k1::new();
	let asset = AssetId::from_byte_array(h("holding back asset"));
	let operator = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&h("operator")).unwrap()).x_only_public_key().0;
	let params = TreeParams {
		asset, chain: Chain::new(BlockHash::all_zeros()), schedule: ClockSchedule::never(operator), burn: false, delegated_reclaim: true,
		radix: 4, reserve: ReserveRule::Fixed { node: 330, entry: 330 }, min_leaf: 1,
	};
	let owners: Vec<_> = ["fan owner a", "fan owner b"].iter()
		.map(|l| Keypair::from_secret_key(&secp, &SecretKey::from_slice(&h(l)).unwrap()).x_only_public_key().0).collect();
	let specs: Vec<LeafSpec> = owners.iter().enumerate().map(|(i, o)| LeafSpec {
		template: Template::Vtxo1, owner: *o, value: 50_000, owner_nonce: h(&format!("fan owner nonce {}", i)),
		operator_nonce: h(&format!("fan operator nonce {}", i)), exit_delay: RelativeTime::from_units(4).unwrap(),
		unlock_hash: h(&format!("fan unlock {}", i)), htlc: None, order: None, landing: None, channel: None, claim: None,
	}).collect();
	let tree = Tree::build(params, &specs).expect("a tree");
	let records: Vec<Vec<u8>> = tree.records().iter().map(|r| r.to_bytes().unwrap()).collect();
	let (a, b) = (h("fan.a"), h("fan.0.0"));
	let mut rows = Rows::default();
	// Round 1 is the one `prepared` writes after its holder's.
	rows.round.push((2, "final"));
	rows.batch.push((2, 1, true));
	for (i, (id, state, by)) in [(a, "live", None), (b, "spent", Some(h("fant.0.0").to_vec()))].into_iter().enumerate() {
		rows.batch_leaf.push((id.to_vec(), 2, 1, i as i32, owners[i].serialize().to_vec(), 50_000, records[i].clone()));
		rows.leaf.push((id.to_vec(), "batch", 50_000, owners[i].serialize().to_vec(), records[i].clone(), state, by));
	}
	write(c, &rows).await;
	// The coin `i` of step `l` is `fan.l.i`, and the payment that took it
	// `fant.l.i`, making the coins `4i` to `4i + 3` of step `l + 1`.
	c.batch_execute(&format!(r#"
CREATE TEMP TABLE fan AS SELECT l, i FROM generate_series(0, {last}) l CROSS JOIN LATERAL generate_series(0, (4 ^ l)::int - 1) i;
INSERT INTO transfer (transfer_id, request_hash, state) SELECT hb('fant.'||l||'.'||i), hb('fant.'||l||'.'||i), 'signed' FROM fan;
INSERT INTO transfer_input (transfer_id, idx, leaf_id, checkpoint_value, checkpoint_owner_sig, reassignment_owner_sig)
  SELECT hb('fant.'||l||'.'||i), 0, hb('fan.'||l||'.'||i), 1, decode(repeat('00', 64), 'hex'), decode(repeat('00', 64), 'hex') FROM fan;
INSERT INTO leaf (leaf_id, kind, asset, value, owner_key, script_pubkey, hops, record, state, spent_by)
  SELECT hb('fan.'||(l + 1)||'.'||(4 * i + j)), 'transfer', hb('asset'), 100, hb('fan key '||(l + 1)||'.'||(4 * i + j)), hb('fan.'||(l + 1)||'.'||(4 * i + j)), 0,
    decode(repeat('ab', 200), 'hex'),
    CASE WHEN l < {last} THEN 'spent'::leaf_state ELSE 'live'::leaf_state END,
    CASE WHEN l < {last} THEN hb('fant.'||(l + 1)||'.'||(4 * i + j)) END
  FROM fan, generate_series(0, 3) j;
INSERT INTO transfer_output (transfer_id, idx, leaf_id, mailbox_key)
  SELECT hb('fant.'||l||'.'||i), j, hb('fan.'||(l + 1)||'.'||(4 * i + j)), hb('fan mailbox') FROM fan, generate_series(0, 3) j;
{delegations}
ANALYZE;
"#, last = depth - 1, delegations = if delegated {
		"INSERT INTO delegation (leaf_id, transfer_id, signature) SELECT hb('fan.'||l||'.'||i), hb('fant.'||l||'.'||i), decode(repeat('00', 64), 'hex') FROM fan;"
	} else { "" })).await.expect("the tree of payments");
	(a, h(&format!("fan.{}.0", depth)))
}

/// A read of `a` (the node's live slot) and of `deep` (a coin at the last
/// step under its other slot) answers nothing, reads ahead no more coins
/// than the node's walk can, and takes a few milliseconds, as a read of a
/// node with no lineage does (the bar, 250 ms, is far above either and far
/// below a read of the whole tree).
async fn bounded_by_the_walk(delegated: bool) {
	let (db, _) = prepared(0.0, 0).await;
	let c = session(&db.url).await;
	let none = ActiveCoins::default();
	let depth = 8;
	let (a, deep) = fanned_out(&c, depth, delegated).await;
	let coins: i64 = c.query_one("SELECT count(*) FROM leaf", &[]).await.unwrap().get(0);
	assert!(coins >= 87_380, "the tree is written: {} coins", coins);
	for (what, ids) in [("the live slot", vec![a]), ("a coin at the last step", vec![deep]), ("both", vec![a, deep])] {
		let mut times = vec![];
		for _ in 0..5 {
			let before = db.store.coins_read_ahead();
			let t = Instant::now();
			let answer = holding_back(&db.store, &ids, &none).await.expect("holding_back");
			times.push(t.elapsed());
			let read = db.store.coins_read_ahead() - before;
			assert_eq!(answer, vec![], "{}: nothing is named", what);
			assert!(read as usize <= server::delegations::WALK_READS,
				"{} (delegated {}): {} coins read ahead, past the {} a walk can read", what, delegated, read, server::delegations::WALK_READS);
		}
		times.sort();
		eprintln!("{} (delegated {}): median {:?}, slowest {:?}", what, delegated, times[2], times[4]);
		assert!(times[2] <= Duration::from_millis(250), "{} (delegated {}): a read takes {:?} at the median", what, delegated, times[2]);
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_undelegated_lineage_is_not_read_ahead() {
	bounded_by_the_walk(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delegated_lineage_is_read_ahead_only_as_far_as_its_walk() {
	bounded_by_the_walk(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_round_ending_is_seen_whole_or_not_at_all() {
	let (db, _) = prepared(0.0, 0).await;
	let c = session(&db.url).await;
	let secp = Secp256k1::new();
	let operator = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&h("operator")).unwrap()).x_only_public_key().0;
	let params = TreeParams {
		asset: AssetId::from_byte_array(h("holding back asset")), chain: Chain::new(BlockHash::all_zeros()),
		schedule: ClockSchedule::never(operator), burn: false, delegated_reclaim: true, radix: 4,
		reserve: ReserveRule::Fixed { node: 330, entry: 330 }, min_leaf: 1,
	};
	let owners: Vec<_> = (0..3).map(|i| Keypair::from_secret_key(&secp, &SecretKey::from_slice(&h(&format!("ending owner {}", i))).unwrap())
		.x_only_public_key().0).collect();
	let specs: Vec<LeafSpec> = owners.iter().enumerate().map(|(i, o)| LeafSpec {
		template: Template::Vtxo1, owner: *o, value: 10_000 + 1_000 * i as u64, owner_nonce: h(&format!("ending owner nonce {}", i)),
		operator_nonce: h(&format!("ending operator nonce {}", i)), exit_delay: RelativeTime::from_units(4).unwrap(),
		unlock_hash: h(&format!("ending unlock {}", i)), htlc: None, order: None, landing: None, channel: None, claim: None,
	}).collect();
	let tree = Tree::build(params, &specs).expect("a tree");
	let records: Vec<Vec<u8>> = tree.records().iter().map(|r| r.to_bytes().unwrap()).collect();
	let node = arca_covenant::LeafRecord::from_bytes(&records[1]).unwrap().branch().unwrap().nodes.last().unwrap().children_hash();
	let ids: Vec<[u8; 32]> = (0..3).map(|i| h(&format!("ending.{}", i))).collect();
	let p = h("ending participation");
	// The holder's coin, live; the node's two other coins given up in one
	// refresh, still pending.
	let mut rows = Rows::default();
	rows.round.push((2, "final"));
	rows.batch.push((2, 1, true));
	for i in 0..3 {
		let (state, by) = if i == 0 { ("live", None) } else { ("spent", Some(p.to_vec())) };
		rows.batch_leaf.push((ids[i].to_vec(), 2, 1, i as i32, owners[i].serialize().to_vec(), specs[i].value as i64, records[i].clone()));
		rows.leaf.push((ids[i].to_vec(), "batch", specs[i].value as i64, owners[i].serialize().to_vec(), records[i].clone(), state, by));
	}
	rows.participation.push((p.to_vec(), "pending"));
	write(&c, &rows).await;
	c.execute("INSERT INTO participation_input (participation_id, idx, leaf_id, active, asset, value, margin, attestation)
		SELECT $1, i, l, true, hb('asset'), 1, 0, '\\x00' FROM unnest($2::bytea[], $3::smallint[]) AS u(l, i)",
		&[&&p[..], &vec![ids[1].to_vec(), ids[2].to_vec()], &vec![0i16, 1]]).await.unwrap();
	let before = format!("BEGIN; UPDATE participation SET state = 'pending' WHERE participation_id = '\\x{p}';
		DELETE FROM node_release WHERE participation_id = '\\x{p}'; COMMIT", p = hex(&p));
	let after = format!("BEGIN; UPDATE participation SET state = 'released' WHERE participation_id = '\\x{p}';
		INSERT INTO node_release (leaf_id, round_id, participation_id, node_hash, connector_asset, signature, retired)
		SELECT l, 2, '\\x{p}', '\\x{n}', hb('c2'), decode(repeat('00', 64), 'hex'), false FROM unnest(ARRAY['\\x{a}'::bytea, '\\x{b}'::bytea]) l;
		COMMIT", p = hex(&p), n = hex(&node), a = hex(&ids[1]), b = hex(&ids[2]));
	let none = ActiveCoins::default();
	let whole = vec![(ids[0], specs[1].value + specs[2].value)];
	for state in [&before, &after, &before] {
		c.batch_execute(state).await.unwrap();
		assert_eq!(holding_back(&db.store, &[ids[0]], &none).await.unwrap(), whole, "before and after the round ends, the coin is named");
	}
	let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
	let flipper = {
		let (url, stop) = (db.url.clone(), stop.clone());
		tokio::spawn(async move {
			let c = session(&url).await;
			let mut n = 0u64;
			while !stop.load(std::sync::atomic::Ordering::SeqCst) {
				c.batch_execute(if n % 2 == 0 { &after } else { &before }).await.unwrap();
				n += 1;
			}
			n
		})
	};
	let (mut reads, mut mixed) = (0u32, vec![]);
	let t = Instant::now();
	while t.elapsed() < Duration::from_secs(5) {
		let a = holding_back(&db.store, &[ids[0]], &none).await.unwrap();
		reads += 1;
		if a != whole {
			mixed.push(a);
		}
	}
	stop.store(true, std::sync::atomic::Ordering::SeqCst);
	let flips = flipper.await.unwrap();
	eprintln!("a round ending: {} reads over {} flips, {} answered neither as before nor as after", reads, flips, mixed.len());
	assert!(flips > 100 && reads > 100, "the round ended and came back {} times over {} reads", flips, reads);
	assert!(mixed.is_empty(), "{} of {} reads answered neither as before nor as after the round ended: {:?}", mixed.len(), reads,
		mixed.first());
}
