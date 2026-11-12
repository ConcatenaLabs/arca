-- What the operator's passes read instead of everything the operator ever
-- made.
--
-- The watcher acts on a batch (its reclaims, its collection, its expiry) only
-- when something about the batch has changed: a release or a consent of one of
-- its coins, a coin on it given up, paid on or spent, a round or a
-- participation moving, an output of it seen on the chain, a transaction of
-- the watcher's spending one of its outputs confirming, going final, going
-- back to the mempool or lost. Each such change is logged here against every
-- batch it concerns (a coin's own batch, and for a coin paid on out of round
-- every batch up its lineage) by the triggers below, in the transaction that
-- makes it, whichever code path writes it. The watcher reads the log by the
-- writing transaction's id from the oldest transaction still running at its
-- last read, so a change committed late is never skipped, and deletes what it
-- has acted on. A batch nothing touches is not read again.
CREATE TABLE IF NOT EXISTS watch_touch (
	xid      xid8 NOT NULL DEFAULT pg_current_xact_id(),
	round_id BIGINT NOT NULL,
	vout     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS watch_touch_by_xid ON watch_touch (xid);

-- Every transaction that may be held final (a final nursery transaction or
-- round, a credited board) while no block holds it: one a block's
-- disconnection took out of the chain, and one made final, or written final,
-- while no block held it. The passes that find a final transaction no longer
-- final read these rather than every final transaction there is
-- (`chain::unfinal_with`); the triggers below fill it in the transaction that
-- makes the change, whichever code path writes it, so it holds every such
-- transaction any snapshot can show, and the rounds pass removes the ones a
-- block holds again or that nothing holds final any more.
CREATE TABLE IF NOT EXISTS tx_unblocked (
	txid BYTEA NOT NULL
);
CREATE INDEX IF NOT EXISTS tx_unblocked_by_txid ON tx_unblocked (txid);

-- Where the watcher's reads stand, kept across restarts: the median time up
-- to which it has taken the batches whose dates came due (`due_mtp`), and
-- where its round of every batch has got to (`slice_round`, `slice_vout`).
CREATE TABLE IF NOT EXISTS watch_cursor (
	name  TEXT PRIMARY KEY,
	value BIGINT NOT NULL
);

-- The batches the coins `ids` rest on: each one's own batch, and every batch
-- up its lineage of reassignments and fills.
CREATE OR REPLACE FUNCTION watch_touch_leaves(ids BYTEA[]) RETURNS void LANGUAGE sql AS $$
	INSERT INTO watch_touch (round_id, vout)
	WITH RECURSIVE up (leaf_id, depth) AS (
		SELECT DISTINCT i, 0 FROM unnest(ids) i WHERE i IS NOT NULL
		UNION
		SELECT p.parent, u.depth + 1 FROM up u
		JOIN transfer_output o ON o.leaf_id = u.leaf_id
		JOIN LATERAL (SELECT ti.leaf_id AS parent FROM transfer_input ti WHERE ti.transfer_id = o.transfer_id
		              UNION ALL SELECT f.order_leaf FROM order_fill f WHERE f.transfer_id = o.transfer_id) p ON true
		WHERE u.depth < 64)
	SELECT DISTINCT bl.round_id, bl.vout FROM up JOIN batch_leaf bl ON bl.leaf_id = up.leaf_id
$$;

-- The batches the outpoints concern: a round's batch output or token output
-- (not its connector or offboard outputs), a node or an entry of a batch seen on the chain, and
-- the leaf or checkpoint of a coin seen there.
CREATE OR REPLACE FUNCTION watch_touch_outpoints(txids BYTEA[], vouts INTEGER[]) RETURNS void LANGUAGE sql AS $$
	INSERT INTO watch_touch (round_id, vout)
	SELECT b.round_id, b.vout FROM unnest(txids, vouts) o(txid, vout) JOIN round r ON r.txid = o.txid
	JOIN batch b ON b.round_id = r.round_id AND (b.vout = o.vout OR b.token_vout = o.vout)
	UNION
	SELECT ts.round_id, ts.batch_vout FROM unnest(txids, vouts) o(txid, vout)
	JOIN tree_sighting s ON s.txid = o.txid AND s.vout = o.vout JOIN tree_script ts ON ts.script_pubkey = s.script_pubkey;
	SELECT watch_touch_leaves(ARRAY(SELECT a.leaf_id FROM unnest(txids, vouts) o(txid, vout)
		JOIN script_sighting s ON s.txid = o.txid AND s.vout = o.vout JOIN arca_script a ON a.script_pubkey = s.script_pubkey));
$$;

-- The batches the transactions `txids` concern: a round's own batches, and
-- for a transaction of the watcher's, what its inputs spend and the coin it
-- acts for.
CREATE OR REPLACE FUNCTION watch_touch_txs(txids BYTEA[]) RETURNS void LANGUAGE sql AS $$
	INSERT INTO watch_touch (round_id, vout)
	SELECT b.round_id, b.vout FROM round r JOIN batch b ON b.round_id = r.round_id WHERE r.txid = ANY (txids);
	SELECT watch_touch_outpoints(x.t, x.v) FROM (SELECT array_agg(prev_txid) t, array_agg(prev_vout) v
		FROM watcher_input WHERE txid = ANY (txids)) x WHERE x.t IS NOT NULL;
	SELECT watch_touch_leaves(ARRAY(SELECT subject FROM watcher_tx WHERE txid = ANY (txids) AND length(subject) = 32));
$$;

-- What the triggers need to find their batches, and what the passes' own
-- reads need.
CREATE INDEX IF NOT EXISTS watcher_input_by_txid ON watcher_input (txid);
CREATE INDEX IF NOT EXISTS tree_sighting_by_outpoint ON tree_sighting (txid, vout);
CREATE INDEX IF NOT EXISTS script_sighting_by_outpoint ON script_sighting (txid, vout);
CREATE INDEX IF NOT EXISTS batch_leaf_by_participation ON batch_leaf (participation_id);
CREATE INDEX IF NOT EXISTS participation_by_round ON participation (round_id);
CREATE INDEX IF NOT EXISTS nursery_tx_not_final ON nursery_tx (state, created_at) WHERE state <> 'final';
CREATE INDEX IF NOT EXISTS round_by_created_mtp ON round (created_mtp);
CREATE INDEX IF NOT EXISTS batch_by_collect_mtp ON batch (collect_mtp);

-- The triggers: one statement each, over the rows it changed.
CREATE OR REPLACE FUNCTION watch_touch_rows() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	CASE TG_TABLE_NAME
	WHEN 'node_release', 'slot_release', 'delegation', 'forfeit', 'reclaimed_leaf', 'participation_input', 'transfer_output' THEN
		PERFORM watch_touch_leaves(ARRAY(SELECT leaf_id FROM touched));
	WHEN 'leaf' THEN
		PERFORM watch_touch_leaves(ARRAY(SELECT n.leaf_id FROM touched n JOIN untouched o USING (leaf_id)
			WHERE n.state IS DISTINCT FROM o.state OR n.spent_by IS DISTINCT FROM o.spent_by OR n.record IS DISTINCT FROM o.record));
	WHEN 'participation' THEN
		PERFORM watch_touch_leaves(ARRAY(
			SELECT i.leaf_id FROM touched n JOIN untouched o USING (participation_id) JOIN participation_input i USING (participation_id)
			WHERE n.state IS DISTINCT FROM o.state OR n.round_id IS DISTINCT FROM o.round_id OR n.attempt IS DISTINCT FROM o.attempt
			UNION ALL
			SELECT bl.leaf_id FROM touched n JOIN untouched o USING (participation_id) JOIN batch_leaf bl ON bl.participation_id = n.participation_id
			WHERE n.state IS DISTINCT FROM o.state OR n.round_id IS DISTINCT FROM o.round_id OR n.attempt IS DISTINCT FROM o.attempt));
	WHEN 'round' THEN
		INSERT INTO watch_touch (round_id, vout)
		SELECT b.round_id, b.vout FROM touched n JOIN untouched o USING (round_id) JOIN batch b ON b.round_id = n.round_id
		WHERE n.state IS DISTINCT FROM o.state;
		PERFORM watch_touch_leaves(ARRAY(SELECT i.leaf_id FROM touched n JOIN untouched o USING (round_id)
			JOIN participation p ON p.round_id = n.round_id JOIN participation_input i ON i.participation_id = p.participation_id
			WHERE n.state IS DISTINCT FROM o.state));
	WHEN 'batch' THEN
		INSERT INTO watch_touch (round_id, vout) SELECT round_id, vout FROM touched;
	WHEN 'tree_sighting' THEN
		INSERT INTO watch_touch (round_id, vout)
		SELECT DISTINCT ts.round_id, ts.batch_vout FROM touched n JOIN tree_script ts ON ts.script_pubkey = n.script_pubkey;
	WHEN 'script_sighting' THEN
		PERFORM watch_touch_leaves(ARRAY(SELECT a.leaf_id FROM touched n JOIN arca_script a ON a.script_pubkey = n.script_pubkey));
	WHEN 'nursery_tx' THEN
		PERFORM watch_touch_txs(ARRAY(SELECT n.txid FROM touched n JOIN untouched o USING (txid) WHERE n.state IS DISTINCT FROM o.state));
	WHEN 'tx_block' THEN
		PERFORM watch_touch_txs(ARRAY(SELECT txid FROM touched));
	WHEN 'transfer' THEN
		PERFORM watch_touch_leaves(ARRAY(
			SELECT i.leaf_id FROM touched n JOIN untouched o USING (transfer_id) JOIN transfer_input i USING (transfer_id)
			WHERE n.state IS DISTINCT FROM o.state
			UNION ALL
			SELECT x.leaf_id FROM touched n JOIN untouched o USING (transfer_id) JOIN transfer_output x USING (transfer_id)
			WHERE n.state IS DISTINCT FROM o.state));
	WHEN 'order_fill' THEN
		PERFORM watch_touch_leaves(ARRAY(SELECT order_leaf FROM touched UNION ALL
			SELECT x.leaf_id FROM touched n JOIN transfer_output x USING (transfer_id)));
	WHEN 'lightning_send' THEN
		PERFORM watch_touch_leaves(ARRAY(SELECT n.htlc_leaf_id FROM touched n JOIN untouched o USING (payment_hash)
			WHERE n.state IS DISTINCT FROM o.state));
	END CASE;
	RETURN NULL;
END $$;

-- A block's disconnection takes its watched transactions out of the chain:
-- logged for the passes that find a final transaction no longer final, and
-- their batches touched.
CREATE OR REPLACE FUNCTION watch_unblocked() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	INSERT INTO tx_unblocked (txid) SELECT DISTINCT txid FROM touched;
	PERFORM watch_touch_txs(ARRAY(SELECT txid FROM touched));
	RETURN NULL;
END $$;

-- A row written final (or credited) while no block holds its transaction:
-- logged for the same passes.
CREATE OR REPLACE FUNCTION final_unblocked() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	INSERT INTO tx_unblocked (txid)
	SELECT DISTINCT n.txid FROM touched n
	WHERE n.txid IS NOT NULL AND n.state::text = TG_ARGV[0]
	  AND NOT EXISTS (SELECT 1 FROM tx_block t WHERE t.txid = n.txid);
	RETURN NULL;
END $$;

DO $$
DECLARE
	t TEXT;
BEGIN
	-- Rows only ever inserted, or updated in place.
	FOREACH t IN ARRAY ARRAY['node_release', 'slot_release', 'delegation', 'forfeit', 'participation_input', 'tree_sighting', 'script_sighting']
	LOOP
		EXECUTE format('DROP TRIGGER IF EXISTS watch_touch_ins ON %I', t);
		EXECUTE format('CREATE TRIGGER watch_touch_ins AFTER INSERT ON %I REFERENCING NEW TABLE AS touched
			FOR EACH STATEMENT EXECUTE FUNCTION watch_touch_rows()', t);
		EXECUTE format('DROP TRIGGER IF EXISTS watch_touch_upd ON %I', t);
		EXECUTE format('CREATE TRIGGER watch_touch_upd AFTER UPDATE ON %I REFERENCING NEW TABLE AS touched
			FOR EACH STATEMENT EXECUTE FUNCTION watch_touch_rows()', t);
	END LOOP;
	FOREACH t IN ARRAY ARRAY['reclaimed_leaf', 'transfer_output', 'order_fill', 'batch', 'tx_block']
	LOOP
		EXECUTE format('DROP TRIGGER IF EXISTS watch_touch_ins ON %I', t);
		EXECUTE format('CREATE TRIGGER watch_touch_ins AFTER INSERT ON %I REFERENCING NEW TABLE AS touched
			FOR EACH STATEMENT EXECUTE FUNCTION watch_touch_rows()', t);
	END LOOP;
	DROP TRIGGER IF EXISTS watch_touch_upd ON order_fill;
	CREATE TRIGGER watch_touch_upd AFTER UPDATE ON order_fill REFERENCING NEW TABLE AS touched
		FOR EACH STATEMENT EXECUTE FUNCTION watch_touch_rows();
	-- Rows whose change of state matters: the old row beside the new.
	FOREACH t IN ARRAY ARRAY['leaf', 'participation', 'round', 'nursery_tx', 'transfer', 'lightning_send']
	LOOP
		EXECUTE format('DROP TRIGGER IF EXISTS watch_touch_upd ON %I', t);
		EXECUTE format('CREATE TRIGGER watch_touch_upd AFTER UPDATE ON %I REFERENCING OLD TABLE AS untouched NEW TABLE AS touched
			FOR EACH STATEMENT EXECUTE FUNCTION watch_touch_rows()', t);
	END LOOP;
	DROP TRIGGER IF EXISTS watch_unblocked ON tx_block;
	CREATE TRIGGER watch_unblocked AFTER DELETE ON tx_block REFERENCING OLD TABLE AS touched
		FOR EACH STATEMENT EXECUTE FUNCTION watch_unblocked();
	FOREACH t IN ARRAY ARRAY['nursery_tx:final', 'round:final', 'board:credited']
	LOOP
		EXECUTE format('DROP TRIGGER IF EXISTS final_unblocked_ins ON %I', split_part(t, ':', 1));
		EXECUTE format('CREATE TRIGGER final_unblocked_ins AFTER INSERT ON %I REFERENCING NEW TABLE AS touched
			FOR EACH STATEMENT EXECUTE FUNCTION final_unblocked(%L)', split_part(t, ':', 1), split_part(t, ':', 2));
		EXECUTE format('DROP TRIGGER IF EXISTS final_unblocked_upd ON %I', split_part(t, ':', 1));
		EXECUTE format('CREATE TRIGGER final_unblocked_upd AFTER UPDATE ON %I REFERENCING NEW TABLE AS touched
			FOR EACH STATEMENT EXECUTE FUNCTION final_unblocked(%L)', split_part(t, ':', 1), split_part(t, ':', 2));
	END LOOP;
END $$;

-- Every transaction held final in no block before the schema step.
INSERT INTO tx_unblocked (txid)
SELECT f.txid FROM (SELECT txid FROM nursery_tx WHERE state = 'final'
                    UNION SELECT txid FROM round WHERE state = 'final' AND txid IS NOT NULL
                    UNION SELECT txid FROM board WHERE state = 'credited') f
WHERE NOT EXISTS (SELECT 1 FROM tx_block t WHERE t.txid = f.txid);

-- Every batch of a round not lost is read once, by the first pass after the
-- schema step, as every pass read it before.
INSERT INTO watch_touch (round_id, vout)
SELECT b.round_id, b.vout FROM batch b JOIN round r ON r.round_id = b.round_id WHERE r.state <> 'lost';

-- What the passes over the whole history act on, logged as it may open: a
-- sighting of a coin given up that may need an answer (`sighting`, by
-- outpoint), a forfeited coin of a transfer whose forfeit may be unclaimed
-- (`transfer_forfeit`, by leaf id), a forfeit the watcher published that
-- may still be claimed (`forfeit`, by txid), a credited board the operator
-- may still have to recover (`board`, by leaf id), and a coin given up whose
-- value may be in flight (`flight`, by leaf id). The triggers below log an
-- item in the transaction of every write that can make it open, whichever
-- code path writes it; each pass reads the items logged, tests each by the
-- whole statement's own condition, and removes those the test closes. An
-- item closed matters again only through a new write, which logs it again
-- in its own transaction. A recount runs the whole statements now and then,
-- in one snapshot with the logged reads, and raises an alarm when they
-- disagree (`store::open`).
CREATE TABLE IF NOT EXISTS pass_open (
	pass TEXT NOT NULL,
	k    BYTEA NOT NULL,
	v    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS pass_open_by_key ON pass_open (pass, k, v);
CREATE INDEX IF NOT EXISTS arca_script_by_leaf ON arca_script (leaf_id);
CREATE INDEX IF NOT EXISTS batch_by_token ON batch (token);
CREATE INDEX IF NOT EXISTS board_by_outpoint ON board (txid, vout);

-- The coins given up that rest on the coins `ids`: each of them, and every
-- coin a transfer or a fill made of one of them, eight deep (the depth the
-- in-flight statement reads up a coin's lineage).
CREATE OR REPLACE FUNCTION pass_open_flight(ids BYTEA[]) RETURNS void LANGUAGE sql AS $$
	INSERT INTO pass_open (pass, k)
	WITH RECURSIVE down (leaf_id, depth) AS (
		SELECT DISTINCT i, 0 FROM unnest(ids) i WHERE i IS NOT NULL
		UNION
		SELECT o.leaf_id, d.depth + 1 FROM down d
		JOIN LATERAL (SELECT ti.transfer_id FROM transfer_input ti WHERE ti.leaf_id = d.leaf_id
		              UNION ALL SELECT f.transfer_id FROM order_fill f WHERE f.order_leaf = d.leaf_id) t ON true
		JOIN transfer_output o ON o.transfer_id = t.transfer_id
		WHERE d.depth < 8)
	SELECT DISTINCT 'flight', d.leaf_id FROM down d
	WHERE EXISTS (SELECT 1 FROM participation_input pi WHERE pi.leaf_id = d.leaf_id AND pi.active)
$$;

-- What a change to the coins `ids` (spent, or a forfeit stored) may open: the
-- sightings of their leaves and checkpoints, their forfeits, their boards.
CREATE OR REPLACE FUNCTION pass_open_leaves(ids BYTEA[]) RETURNS void LANGUAGE sql AS $$
	INSERT INTO pass_open (pass, k, v)
	SELECT 'sighting', s.txid, s.vout FROM arca_script a JOIN script_sighting s ON s.script_pubkey = a.script_pubkey
	WHERE a.leaf_id = ANY (ids) AND a.kind IN ('leaf', 'checkpoint')
	UNION ALL
	SELECT 'transfer_forfeit', l.leaf_id, 0 FROM leaf l WHERE l.leaf_id = ANY (ids) AND l.kind = 'transfer'
	UNION ALL
	SELECT 'board', b.leaf_id, 0 FROM board b WHERE b.leaf_id = ANY (ids)
$$;

-- What a transaction of the watcher's going in or out of the final state
-- (or out of the lost one) may open: what it spends (a sighting, a board's
-- output, a forfeit's output and the coin of that forfeit), the forfeit it
-- is, and the coins whose value it brought back (its own coin for a
-- forfeit, a sweep's batch, a reclaim's leaves).
CREATE OR REPLACE FUNCTION pass_open_txs(txids BYTEA[]) RETURNS void LANGUAGE sql AS $$
	INSERT INTO pass_open (pass, k, v)
	SELECT 'sighting', wi.prev_txid, wi.prev_vout FROM watcher_input wi WHERE wi.txid = ANY (txids)
	UNION ALL
	SELECT 'board', b.leaf_id, 0 FROM watcher_input wi JOIN board b ON b.txid = wi.prev_txid AND b.vout = wi.prev_vout
	WHERE wi.txid = ANY (txids)
	UNION ALL
	SELECT 'forfeit', wi.prev_txid, 0 FROM watcher_input wi WHERE wi.txid = ANY (txids) AND wi.prev_vout = 0
	UNION ALL
	SELECT 'transfer_forfeit', fw.subject, 0 FROM watcher_input wi JOIN watcher_tx fw ON fw.txid = wi.prev_txid AND fw.kind = 'forfeit'
	WHERE wi.txid = ANY (txids) AND wi.prev_vout = 0
	UNION ALL
	SELECT 'forfeit', w.txid, 0 FROM watcher_tx w WHERE w.txid = ANY (txids) AND w.kind = 'forfeit';
	SELECT pass_open_flight(ARRAY(
		SELECT w.subject FROM watcher_tx w WHERE w.txid = ANY (txids) AND w.kind = 'forfeit'
		UNION ALL
		SELECT bl.leaf_id FROM watcher_tx w JOIN batch b ON b.token = w.subject
		JOIN batch_leaf bl ON bl.round_id = b.round_id AND bl.vout = b.vout
		WHERE w.txid = ANY (txids) AND w.kind = 'sweep'
		UNION ALL
		SELECT rl.leaf_id FROM reclaimed_leaf rl WHERE rl.txid = ANY (txids)
		UNION ALL
		SELECT nr.leaf_id FROM watcher_tx w JOIN node_release nr ON nr.node_hash = w.subject
		WHERE w.txid = ANY (txids) AND w.kind = 'reclaim'));
$$;

CREATE OR REPLACE FUNCTION pass_open_rows() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	IF TG_OP = 'UPDATE' THEN
		CASE TG_TABLE_NAME
		WHEN 'nursery_tx' THEN
			PERFORM pass_open_txs(ARRAY(SELECT n.txid FROM touched n JOIN untouched o USING (txid) WHERE n.state IS DISTINCT FROM o.state));
		WHEN 'leaf' THEN
			PERFORM pass_open_leaves(ARRAY(SELECT n.leaf_id FROM touched n JOIN untouched o USING (leaf_id)
				WHERE n.state = 'spent' AND o.state IS DISTINCT FROM 'spent'));
		WHEN 'board' THEN
			INSERT INTO pass_open (pass, k) SELECT 'board', n.leaf_id FROM touched n JOIN untouched o USING (leaf_id)
			WHERE n.state = 'credited' AND (o.state IS DISTINCT FROM 'credited' OR n.txid IS DISTINCT FROM o.txid OR n.vout IS DISTINCT FROM o.vout);
		WHEN 'participation_input' THEN
			PERFORM pass_open_flight(ARRAY(SELECT n.leaf_id FROM touched n JOIN untouched o USING (participation_id, idx)
				WHERE n.active IS DISTINCT FROM o.active OR n.leaf_id IS DISTINCT FROM o.leaf_id));
		WHEN 'participation' THEN
			PERFORM pass_open_flight(ARRAY(SELECT i.leaf_id FROM touched n JOIN untouched o USING (participation_id)
				JOIN participation_input i ON i.participation_id = n.participation_id
				WHERE n.state IS DISTINCT FROM o.state OR n.round_id IS DISTINCT FROM o.round_id));
		WHEN 'round' THEN
			PERFORM pass_open_flight(ARRAY(
				SELECT i.leaf_id FROM touched n JOIN untouched o USING (round_id) JOIN participation p ON p.round_id = n.round_id
				JOIN participation_input i ON i.participation_id = p.participation_id WHERE n.state IS DISTINCT FROM o.state
				UNION ALL
				SELECT bl.leaf_id FROM touched n JOIN untouched o USING (round_id) JOIN batch_leaf bl ON bl.round_id = n.round_id
				WHERE n.state IS DISTINCT FROM o.state));
		WHEN 'batch' THEN
			PERFORM pass_open_flight(ARRAY(SELECT bl.leaf_id FROM touched n JOIN untouched o USING (round_id, vout)
				JOIN batch_leaf bl ON bl.round_id = n.round_id AND bl.vout = n.vout
				WHERE n.collect_mtp IS DISTINCT FROM o.collect_mtp OR n.token IS DISTINCT FROM o.token OR n.asset IS DISTINCT FROM o.asset));
		END CASE;
	ELSE
		CASE TG_TABLE_NAME
		WHEN 'nursery_tx', 'watcher_tx' THEN
			PERFORM pass_open_txs(ARRAY(SELECT txid FROM touched));
		WHEN 'script_sighting' THEN
			INSERT INTO pass_open (pass, k, v) SELECT 'sighting', txid, vout FROM touched;
		WHEN 'arca_script' THEN
			INSERT INTO pass_open (pass, k, v)
			SELECT 'sighting', s.txid, s.vout FROM touched n JOIN script_sighting s ON s.script_pubkey = n.script_pubkey;
		WHEN 'leaf' THEN
			PERFORM pass_open_leaves(ARRAY(SELECT leaf_id FROM touched WHERE state = 'spent'));
		WHEN 'forfeit' THEN
			PERFORM pass_open_leaves(ARRAY(SELECT leaf_id FROM touched));
		WHEN 'board' THEN
			INSERT INTO pass_open (pass, k) SELECT 'board', leaf_id FROM touched WHERE state = 'credited';
		WHEN 'participation_input', 'batch_leaf' THEN
			PERFORM pass_open_flight(ARRAY(SELECT leaf_id FROM touched));
		WHEN 'round' THEN
			PERFORM pass_open_flight(ARRAY(SELECT bl.leaf_id FROM touched n JOIN batch_leaf bl ON bl.round_id = n.round_id));
		WHEN 'transfer_input', 'transfer_output', 'order_fill' THEN
			PERFORM pass_open_flight(ARRAY(SELECT o.leaf_id FROM touched n JOIN transfer_output o ON o.transfer_id = n.transfer_id));
		END CASE;
	END IF;
	RETURN NULL;
END $$;

DO $$
DECLARE
	t TEXT;
BEGIN
	FOREACH t IN ARRAY ARRAY['nursery_tx', 'watcher_tx', 'script_sighting', 'arca_script', 'leaf', 'forfeit', 'board', 'participation_input',
		'batch_leaf', 'round', 'transfer_input', 'transfer_output', 'order_fill']
	LOOP
		EXECUTE format('DROP TRIGGER IF EXISTS pass_open_ins ON %I', t);
		EXECUTE format('CREATE TRIGGER pass_open_ins AFTER INSERT ON %I REFERENCING NEW TABLE AS touched
			FOR EACH STATEMENT EXECUTE FUNCTION pass_open_rows()', t);
	END LOOP;
	FOREACH t IN ARRAY ARRAY['nursery_tx', 'leaf', 'board', 'participation_input', 'participation', 'round', 'batch']
	LOOP
		EXECUTE format('DROP TRIGGER IF EXISTS pass_open_upd ON %I', t);
		EXECUTE format('CREATE TRIGGER pass_open_upd AFTER UPDATE ON %I REFERENCING OLD TABLE AS untouched NEW TABLE AS touched
			FOR EACH STATEMENT EXECUTE FUNCTION pass_open_rows()', t);
	END LOOP;
END $$;
