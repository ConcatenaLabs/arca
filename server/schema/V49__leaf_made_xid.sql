-- Reads of `leaf_data` past a settled cursor (`since`): every leaf served to a
-- key, in the order it came to be served to that key, read past a cursor at
-- a cost that does not grow with the key's history.
--
-- A leaf's `seq` is drawn when it is inserted and seen when its transaction
-- commits, so a transaction that commits late shows a leaf behind one a
-- reader has read past already; and a leaf bound to a mailbox after it was
-- made (a claimed coin, a coin of a wallet older than its mailbox key) is
-- served to that mailbox from the binding on. So each leaf is kept once for
-- each key it is served to (`leaf_served`: its owner key, the mailbox its
-- owner key is bound to, the mailbox a transfer posted it to), with the
-- transaction that made it served there: the latest of the one that made
-- the leaf, the one that bound its key and the one that posted it
-- (`served_xid`). A read orders a key's leaves by that, then by `seq`, and
-- serves only those whose transaction is older than every one still running
-- (`pg_snapshot_xmin`): nothing can still appear behind its cursor.
--
-- `leaf.made_xid` and `leaf_mailbox.bound_xid` keep the two transactions,
-- for a leaf or a binding that comes second. Rows made before this read as
-- made by transaction 0. Adding a column with no default, then setting one,
-- rewrites nothing.
ALTER TABLE leaf ADD COLUMN made_xid xid8;
ALTER TABLE leaf ALTER COLUMN made_xid SET DEFAULT pg_current_xact_id();
ALTER TABLE leaf_mailbox ADD COLUMN bound_xid xid8;
ALTER TABLE leaf_mailbox ALTER COLUMN bound_xid SET DEFAULT pg_current_xact_id();

CREATE TABLE leaf_served (
	mailbox_key BYTEA NOT NULL,
	served_xid  xid8 NOT NULL,
	seq         BIGINT NOT NULL,
	leaf_id     BYTEA NOT NULL
);
INSERT INTO leaf_served (mailbox_key, served_xid, seq, leaf_id)
SELECT k, '0'::xid8, seq, leaf_id FROM (
	SELECT owner_key AS k, seq, leaf_id FROM leaf
	UNION SELECT m.mailbox_key, l.seq, l.leaf_id FROM leaf_mailbox m JOIN leaf l ON l.owner_key = m.owner_key
	UNION SELECT o.mailbox_key, l.seq, l.leaf_id FROM transfer_output o JOIN leaf l ON l.leaf_id = o.leaf_id) s;
ALTER TABLE leaf_served ADD PRIMARY KEY (mailbox_key, served_xid, seq);
ALTER TABLE leaf_served ADD CONSTRAINT leaf_served_once UNIQUE (mailbox_key, leaf_id);
ALTER TABLE leaf_served ADD CONSTRAINT leaf_served_leaf FOREIGN KEY (leaf_id) REFERENCES leaf (leaf_id) ON DELETE CASCADE;

-- Each trigger first claims the owner key (`leaf_served_claim`): a leaf and
-- its key's binding inserted by two transactions at once would otherwise
-- each read without the other's row, and the leaf would never be kept for
-- the mailbox. A claim is a row of the key, inserted with ON CONFLICT DO
-- NOTHING, so the second transaction to claim a key waits on the first's
-- row until the first ends; its INSERT, a statement after the claim, then
-- reads with a snapshot that holds the first's row.
--
-- A row, not a lock: an advisory lock a key takes a slot of PostgreSQL's
-- shared lock table (max_locks_per_transaction x max_connections, 6,400 at
-- the defaults) for each leaf of a transaction, which a round of several
-- full batches (all recorded in one transaction) fills; a lock on a bucket
-- of keys makes transactions that share no key wait on each other.
--
-- Only a leaf's transaction and its key's binding's ever claim one key
-- (keys are one to a leaf and one to a binding; a transfer's output is
-- claimed in its leaf's transaction). A transaction that claims several
-- keys (a round's leaves, a transfer's outputs, a plan's bindings) claims
-- them all first, in the keys' order (`leaf_served_claim_all`), so no two
-- transactions ever wait on each other's claims in a cycle.
--
-- A claim is deleted when its transaction commits (a deferred trigger): a
-- transaction waiting on it waits on the row its transaction inserted and
-- deleted, until that transaction ends, then claims the key itself. So the
-- table holds only the claims of transactions still running. It is
-- unlogged: a claim never outlives its transaction.
CREATE UNLOGGED TABLE leaf_served_claim (owner_key BYTEA PRIMARY KEY);
CREATE FUNCTION leaf_served_claim(owner BYTEA) RETURNS void LANGUAGE sql AS $$
	INSERT INTO leaf_served_claim (owner_key) VALUES (owner) ON CONFLICT DO NOTHING
$$;
CREATE FUNCTION leaf_served_claim_all(owners BYTEA[]) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
	k BYTEA;
BEGIN
	FOR k IN SELECT DISTINCT o FROM unnest(owners) o ORDER BY 1 LOOP
		PERFORM leaf_served_claim(k);
	END LOOP;
END $$;
CREATE FUNCTION leaf_served_claim_done() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	DELETE FROM leaf_served_claim WHERE owner_key = NEW.owner_key;
	RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER leaf_served_claim_done AFTER INSERT ON leaf_served_claim
	DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION leaf_served_claim_done();

-- A leaf is served to its owner key, and to the mailbox its key is bound to
-- already.
CREATE FUNCTION leaf_served_of_leaf() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	PERFORM leaf_served_claim(NEW.owner_key);
	INSERT INTO leaf_served (mailbox_key, served_xid, seq, leaf_id)
	SELECT s.k, GREATEST(COALESCE(NEW.made_xid, '0'::xid8), s.x, pg_current_xact_id()), NEW.seq, NEW.leaf_id FROM (
		SELECT NEW.owner_key AS k, '0'::xid8 AS x
		UNION ALL SELECT m.mailbox_key, COALESCE(m.bound_xid, '0'::xid8) FROM leaf_mailbox m WHERE m.owner_key = NEW.owner_key) s
	ON CONFLICT DO NOTHING;
	RETURN NULL;
END $$;
CREATE TRIGGER leaf_served_on_leaf AFTER INSERT ON leaf FOR EACH ROW EXECUTE FUNCTION leaf_served_of_leaf();

-- A binding serves every leaf of the key to the mailbox from then on.
CREATE FUNCTION leaf_served_of_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	PERFORM leaf_served_claim(NEW.owner_key);
	INSERT INTO leaf_served (mailbox_key, served_xid, seq, leaf_id)
	SELECT NEW.mailbox_key, GREATEST(COALESCE(l.made_xid, '0'::xid8), COALESCE(NEW.bound_xid, '0'::xid8), pg_current_xact_id()), l.seq, l.leaf_id
	FROM leaf l WHERE l.owner_key = NEW.owner_key
	ON CONFLICT DO NOTHING;
	RETURN NULL;
END $$;
CREATE TRIGGER leaf_served_on_binding AFTER INSERT ON leaf_mailbox FOR EACH ROW EXECUTE FUNCTION leaf_served_of_binding();

-- A transfer's output is served to the mailbox it is posted to.
CREATE FUNCTION leaf_served_of_output() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	PERFORM leaf_served_claim((SELECT owner_key FROM leaf WHERE leaf_id = NEW.leaf_id));
	INSERT INTO leaf_served (mailbox_key, served_xid, seq, leaf_id)
	SELECT NEW.mailbox_key, GREATEST(COALESCE(l.made_xid, '0'::xid8), pg_current_xact_id()), l.seq, l.leaf_id
	FROM leaf l WHERE l.leaf_id = NEW.leaf_id
	ON CONFLICT DO NOTHING;
	RETURN NULL;
END $$;
CREATE TRIGGER leaf_served_on_output AFTER INSERT ON transfer_output FOR EACH ROW EXECUTE FUNCTION leaf_served_of_output();

-- The epoch of the settled cursors: drawn once, and again by the server
-- when it starts on a database that is not the one its cursors were drawn
-- on. That is a database whose transaction counter is behind a transaction
-- its leaves were served at (restored from a dump, whose counter starts
-- again), which also sets every served transaction to 0; or one whose
-- identity (`identity`: the cluster's system identifier and its timeline)
-- changed since: restored from a dump into another cluster, or recovered to
-- an earlier point in time or promoted from a standby, whose counter runs on
-- from a point the wallets' cursors may lie past. A cursor names its epoch,
-- and one of another epoch reads from the first leaf.
CREATE TABLE leaf_cursor_epoch (
	one      BOOLEAN PRIMARY KEY CHECK (one),
	epoch    BYTEA NOT NULL CHECK (length(epoch) = 8),
	identity TEXT
);
