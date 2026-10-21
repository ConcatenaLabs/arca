-- A leaf wanted under order-2, a resting order: its order's terms, in the
-- leaf record's binary form of them (arca_covenant::OrderLeafTerms), without
-- the asset the order sells, which is the leaf's own.
ALTER TABLE participation_output ADD COLUMN order_terms BYTEA
	CHECK (order_terms IS NULL OR (kind = 'leaf' AND length(order_terms) = 252));

-- A resting order its maker published: the coin a round made of it (the
-- order's id), the record of that coin as the maker handed it over (with the
-- preimage of its entry and the maker's unroll authorisations, which every
-- coin a fill makes carries in its lineage), the nonces of its four credit
-- keys, the maker's mailbox, and the coin it rests at now.
CREATE TABLE resting_order (
	order_id      BYTEA PRIMARY KEY REFERENCES leaf (leaf_id),
	maker_key     BYTEA NOT NULL CHECK (length(maker_key) = 32),
	mailbox_key   BYTEA NOT NULL CHECK (length(mailbox_key) = 32),
	record        BYTEA NOT NULL,
	credit_nonces BYTEA NOT NULL CHECK (length(credit_nonces) = 128),
	current_leaf  BYTEA NOT NULL REFERENCES leaf (leaf_id),
	created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX resting_order_current ON resting_order (current_leaf);

-- Each fill of a resting order made in the tree. It is a transfer (the
-- taker's coins through their checkpoints, the fill's outputs as the
-- transfer's) that also spends the order's coin by its fill path, under the
-- operator's signature over the outputs; `order_leaf` is that coin, which
-- one fill spends at most. `seq` is the fill's place along the order's
-- lineage, from 0.
CREATE TABLE order_fill (
	transfer_id BYTEA PRIMARY KEY REFERENCES transfer,
	order_id    BYTEA NOT NULL REFERENCES resting_order,
	order_leaf  BYTEA NOT NULL UNIQUE REFERENCES leaf (leaf_id),
	seq         INTEGER NOT NULL CHECK (seq >= 0),
	filled      BIGINT NOT NULL CHECK (filled > 0),
	credited    BIGINT NOT NULL CHECK (credited > 0),
	partial     BOOLEAN NOT NULL,
	m           SMALLINT NOT NULL CHECK (m BETWEEN 2 AND 4),
	signature   BYTEA CHECK (signature IS NULL OR length(signature) = 64),
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE (order_id, seq)
);

-- The coins a fill makes for an order's maker are outside the one-key rule
-- (a key owns one leaf that is not lost or expired). The order resting again shares the
-- maker's leaf key with the order's first coin, each under its own salt, so
-- no signature for one fits another. A credit's key is public in the order's
-- terms from the start: a leaf anyone pays to it must not block the fill
-- that credits it.
ALTER TABLE leaf ADD COLUMN maker_coin BOOLEAN NOT NULL DEFAULT false;
DROP INDEX leaf_owner_key_key;
CREATE UNIQUE INDEX leaf_owner_key_key ON leaf (owner_key) WHERE state NOT IN ('lost', 'expired') AND NOT maker_coin;

-- The fill of a resting order, which the watcher publishes when the order's
-- coin, or a taker's checkpoint, comes on the chain after the fill.
ALTER TABLE watcher_tx DROP CONSTRAINT watcher_tx_kind_check;
ALTER TABLE watcher_tx ADD CONSTRAINT watcher_tx_kind_check CHECK (kind IN (
	'forfeit', 'issue', 'claim', 'checkpoint', 'reassignment', 'release', 'sweep', 'reclaim', 'unroll', 'entry',
	'unlock', 'offboard_reclaim', 'htlc_claim', 'htlc_refund', 'refund', 'fill'));
