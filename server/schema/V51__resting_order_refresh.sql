-- A resting order refreshed in a round: a participation gave up the coin it
-- rested at and wanted an order-3 leaf of the same order (the same landed
-- terms, the same value), which its maker then published. The order keeps
-- its id and goes on at the new coin, with the new coin's record and credit
-- keys. `fills_before` is how many fills the order had made before its
-- current lineage began: the credit keys of the coin it rests at are counted
-- from there.
ALTER TABLE resting_order ADD COLUMN fills_before INTEGER NOT NULL DEFAULT 0 CHECK (fills_before >= 0);

-- Each refresh of a resting order, bound when the participation that
-- refreshes it is taken in: the participation, the index of the order-3 leaf
-- it wants for the order (`output_idx`), the order, and the coin it gives up
-- (`from_leaf`). Publication of the leaf a round made of that output, and of
-- no other, continues the order there: `to_leaf` and `fills_before` are set
-- then.
CREATE TABLE resting_order_refresh (
	participation_id BYTEA NOT NULL REFERENCES participation,
	output_idx       SMALLINT NOT NULL CHECK (output_idx >= 0),
	order_id         BYTEA NOT NULL REFERENCES resting_order,
	from_leaf        BYTEA NOT NULL REFERENCES leaf (leaf_id),
	to_leaf          BYTEA UNIQUE REFERENCES leaf (leaf_id),
	fills_before     INTEGER CHECK (fills_before IS NULL OR fills_before >= 0),
	created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	continued_at     TIMESTAMPTZ,
	PRIMARY KEY (participation_id, output_idx),
	UNIQUE (participation_id, from_leaf),
	CHECK ((to_leaf IS NULL) = (fills_before IS NULL))
);
CREATE INDEX resting_order_refresh_from ON resting_order_refresh (from_leaf);
CREATE INDEX resting_order_refresh_order ON resting_order_refresh (order_id);
