-- The watcher: what it must see on the chain, and what it publishes there.

------------------------------------------------------------------------------
-- The outputs above every leaf of a batch
------------------------------------------------------------------------------

-- Every node of a batch (the batch output among them) and every entry, by
-- script, as the round runner built them: so the finality service records
-- each output that pays one, and the watcher knows which of a batch's
-- outputs have been unrolled onto the chain. A node's script commits to its
-- children, so it is unique to its batch.
CREATE TABLE tree_script (
	script_pubkey BYTEA PRIMARY KEY,
	round_id      BIGINT NOT NULL,
	batch_vout    INTEGER NOT NULL,
	kind          TEXT NOT NULL CHECK (kind IN ('node', 'entry')),
	-- A node's level, the lowest nodes 0, and its index in that level; an
	-- entry's level is -1 and its index the leaf's.
	level         SMALLINT NOT NULL CHECK (level >= -1),
	idx           INTEGER NOT NULL CHECK (idx >= 0),
	value         BIGINT NOT NULL CHECK (value > 0),
	FOREIGN KEY (round_id, batch_vout) REFERENCES batch,
	UNIQUE (round_id, batch_vout, level, idx)
);

-- An output paying a node or entry script, seen in the mempool or in a
-- block. Like every sighting, it is never removed.
CREATE TABLE tree_sighting (
	script_pubkey BYTEA NOT NULL REFERENCES tree_script,
	txid          BYTEA NOT NULL CHECK (length(txid) = 32),
	vout          INTEGER NOT NULL CHECK (vout >= 0),
	seen_in       TEXT NOT NULL CHECK (seen_in IN ('mempool', 'block')),
	seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (script_pubkey, txid, vout)
);

------------------------------------------------------------------------------
-- What the watcher publishes
------------------------------------------------------------------------------

-- Every transaction the watcher built, kept broadcast by the nursery (kind
-- 'watcher'), with what it is and what it acts for: the leaf a forfeit, a
-- claim, a checkpoint or a reassignment answers, the batch output a release or
-- a sweep recovers, the node a reclaim or an unroll spends, the round whose
-- connector asset an issuance makes, the offboard output an unlock or a
-- reclaim spends.
CREATE TABLE watcher_tx (
	txid       BYTEA PRIMARY KEY CHECK (length(txid) = 32),
	kind       TEXT NOT NULL CHECK (kind IN (
		'forfeit', 'issue', 'claim', 'checkpoint', 'reassignment', 'release', 'sweep', 'reclaim', 'unroll', 'entry',
		'unlock', 'offboard_reclaim')),
	subject    BYTEA NOT NULL,
	detail     TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX watcher_tx_by_subject ON watcher_tx (kind, subject);

-- Every outpoint a watcher transaction spends, so the watcher never builds a
-- second spend of an outpoint while a spend of its own is in the nursery and
-- not lost.
CREATE TABLE watcher_input (
	prev_txid BYTEA NOT NULL CHECK (length(prev_txid) = 32),
	prev_vout INTEGER NOT NULL CHECK (prev_vout >= 0),
	txid      BYTEA NOT NULL REFERENCES watcher_tx,
	PRIMARY KEY (prev_txid, prev_vout, txid)
);

ALTER TABLE nursery_tx DROP CONSTRAINT nursery_tx_kind_check;
ALTER TABLE nursery_tx ADD CONSTRAINT nursery_tx_kind_check CHECK (kind IN ('board', 'wallet', 'round', 'watcher'));
