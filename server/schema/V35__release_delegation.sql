-- Release delegation: a lowest node whose coins were paid on out of round
-- comes back once the coins' current holders refresh and release it.
--
-- A batch built with RECLAIM-D on its lowest nodes says so; a batch that
-- predates it has none.
ALTER TABLE batch ADD COLUMN delegated_reclaim BOOLEAN NOT NULL DEFAULT false;

-- A coin's delegation of its release to the owner keys of every output of
-- the reassignment it moved into, in output order: its key's signature over
-- SHA256("Arca/delegate" ‖ genesis_hash ‖ K_1 ‖ … ‖ K_m). Taken with the
-- transfer, or afterwards for a coin a fill spent, and checked against the
-- outputs the server recorded for it. A coin is spent once, so it has one.
CREATE TABLE delegation (
	leaf_id     BYTEA PRIMARY KEY REFERENCES leaf,
	transfer_id BYTEA NOT NULL REFERENCES transfer,
	signature   BYTEA NOT NULL CHECK (length(signature) = 64),
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A holder's release names one lowest node of each it rests on, all for the
-- same round: one row per coin, round and node.
ALTER TABLE node_release DROP CONSTRAINT node_release_pkey;
ALTER TABLE node_release ADD PRIMARY KEY (leaf_id, round_id, node_hash);

-- Each batch leaf a reclaim took back, by the reclaim's transaction: what
-- `/v1/chain` counts as back once the reclaim is not lost.
CREATE TABLE reclaimed_leaf (
	txid    BYTEA NOT NULL CHECK (length(txid) = 32),
	leaf_id BYTEA NOT NULL REFERENCES leaf,
	PRIMARY KEY (txid, leaf_id)
);
CREATE INDEX reclaimed_leaf_by_leaf ON reclaimed_leaf (leaf_id);
