-- A resting order refreshed in a round: a participation gave up the coin it
-- rested at and made an order-3 leaf of the same order (the same landed
-- terms, the same value), which its maker then published. The order keeps
-- its id and goes on at the new coin, with the new coin's record and credit
-- keys. `fills_before` is how many fills the order had made before its
-- current lineage began: the credit keys of the coin it rests at are counted
-- from there.
ALTER TABLE resting_order ADD COLUMN fills_before INTEGER NOT NULL DEFAULT 0 CHECK (fills_before >= 0);

-- Each refresh of a resting order: the coin it rested at (`from_leaf`), the
-- coin it rests at after it (`to_leaf`), and how many fills it had made then.
CREATE TABLE resting_order_refresh (
	to_leaf      BYTEA PRIMARY KEY REFERENCES leaf (leaf_id),
	order_id     BYTEA NOT NULL REFERENCES resting_order,
	from_leaf    BYTEA NOT NULL UNIQUE REFERENCES leaf (leaf_id),
	fills_before INTEGER NOT NULL CHECK (fills_before >= 0),
	created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX resting_order_refresh_order ON resting_order_refresh (order_id);
