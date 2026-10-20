-- A take: a participation that asks the operator's round to fill an
-- on-chain order for it (SeqDEX's fill covenant). It gives up coins in the
-- asset the order is paid in and wants one leaf, of what it fills, in the
-- asset the order sells; its round spends the order and credits the maker on
-- the chain. Each row is the order a participation takes, as its id covers
-- it: the outpoint, the order's terms as the relay serves them, the script
-- they make, what the order holds there, the fill and its price.
--
-- One order is taken by one pending or issued participation at a time; the
-- store checks it under a lock on the order, since a participation's state,
-- not this row, says whether it still takes the order.
CREATE TABLE participation_fill (
	participation_id BYTEA PRIMARY KEY REFERENCES participation,
	order_txid       BYTEA NOT NULL CHECK (length(order_txid) = 32),
	order_vout       INTEGER NOT NULL CHECK (order_vout >= 0),
	terms            TEXT NOT NULL,
	script_pubkey    BYTEA NOT NULL,
	locked           BIGINT NOT NULL CHECK (locked > 0),
	filled           BIGINT NOT NULL CHECK (filled > 0 AND filled <= locked),
	price            BIGINT NOT NULL CHECK (price > 0)
);
CREATE INDEX participation_fill_by_order ON participation_fill (order_txid, order_vout);
