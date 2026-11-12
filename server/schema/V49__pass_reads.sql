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

-- Every watched transaction a block's disconnection takes out of the chain:
-- what the passes that find a final transaction no longer final read, rather
-- than every final transaction there is (`chain::unfinal_with`).
CREATE TABLE IF NOT EXISTS tx_unblocked (
	xid  xid8 NOT NULL DEFAULT pg_current_xact_id(),
	txid BYTEA NOT NULL,
	at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tx_unblocked_by_xid ON tx_unblocked (xid);

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

DO $$
DECLARE
	t TEXT;
BEGIN
	-- Rows only ever inserted, or updated in place.
	FOREACH t IN ARRAY ARRAY['node_release', 'slot_release', 'delegation', 'forfeit', 'participation_input', 'tree_sighting', 'script_sighting']
	LOOP
		EXECUTE format('CREATE TRIGGER watch_touch_ins AFTER INSERT ON %I REFERENCING NEW TABLE AS touched
			FOR EACH STATEMENT EXECUTE FUNCTION watch_touch_rows()', t);
		EXECUTE format('CREATE TRIGGER watch_touch_upd AFTER UPDATE ON %I REFERENCING NEW TABLE AS touched
			FOR EACH STATEMENT EXECUTE FUNCTION watch_touch_rows()', t);
	END LOOP;
	FOREACH t IN ARRAY ARRAY['reclaimed_leaf', 'transfer_output', 'order_fill', 'batch', 'tx_block']
	LOOP
		EXECUTE format('CREATE TRIGGER watch_touch_ins AFTER INSERT ON %I REFERENCING NEW TABLE AS touched
			FOR EACH STATEMENT EXECUTE FUNCTION watch_touch_rows()', t);
	END LOOP;
	CREATE TRIGGER watch_touch_upd AFTER UPDATE ON order_fill REFERENCING NEW TABLE AS touched
		FOR EACH STATEMENT EXECUTE FUNCTION watch_touch_rows();
	-- Rows whose change of state matters: the old row beside the new.
	FOREACH t IN ARRAY ARRAY['leaf', 'participation', 'round', 'nursery_tx', 'transfer', 'lightning_send']
	LOOP
		EXECUTE format('CREATE TRIGGER watch_touch_upd AFTER UPDATE ON %I REFERENCING OLD TABLE AS untouched NEW TABLE AS touched
			FOR EACH STATEMENT EXECUTE FUNCTION watch_touch_rows()', t);
	END LOOP;
	CREATE TRIGGER watch_unblocked AFTER DELETE ON tx_block REFERENCING OLD TABLE AS touched
		FOR EACH STATEMENT EXECUTE FUNCTION watch_unblocked();
END $$;

-- Every batch of a round not lost is read once, by the first pass after the
-- schema step, as every pass read it before.
INSERT INTO watch_touch (round_id, vout)
SELECT b.round_id, b.vout FROM batch b JOIN round r ON r.round_id = b.round_id WHERE r.state <> 'lost';
