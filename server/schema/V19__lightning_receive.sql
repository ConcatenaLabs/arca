-- Receiving over Lightning into the tree (server/src/lightning/receive.rs).

-- A leaf wanted under htlc-1: its terms (direction, payment hash, timeout,
-- operator delay) in arca-covenant's encoding. A round builds the leaf with
-- them; nothing else wants one.
ALTER TABLE participation_output ADD COLUMN htlc BYTEA
	CHECK (htlc IS NULL OR (kind = 'leaf' AND length(htlc) = 39));

-- One payment into the tree, by its payment hash, which the receiving
-- wallet chose: the operator never knows its preimage until the wallet,
-- holding its leaf, hands it over (or reveals it on the chain).
CREATE TABLE lightning_receive (
	payment_hash      BYTEA PRIMARY KEY CHECK (length(payment_hash) = 32),
	asset             BYTEA NOT NULL CHECK (length(asset) = 32),
	-- What the invoice asks, and the operator's fee out of it: the leaf
	-- holds the difference.
	amount            BIGINT NOT NULL CHECK (amount > 0),
	fee               BIGINT NOT NULL CHECK (fee >= 0 AND fee < amount),
	invoice           TEXT NOT NULL,
	-- When the invoice expires (Unix time).
	expires_at        BIGINT NOT NULL,
	-- The leaf the wallet asked for.
	owner_key         BYTEA NOT NULL UNIQUE CHECK (length(owner_key) = 32),
	owner_nonce       BYTEA NOT NULL CHECK (length(owner_nonce) = 32),
	exit_delay_units  INTEGER NOT NULL CHECK (exit_delay_units > 0),
	-- open: the invoice is out, nothing held; accepted: the payment is held
	-- and the leaf wanted in a round; claimed: the preimage is known;
	-- cancelled: the payment was (or is to be) failed back.
	state             TEXT NOT NULL CHECK (state IN ('open', 'accepted', 'claimed', 'cancelled')),
	participation_id  BYTEA UNIQUE REFERENCES participation,
	-- The leaf's timeout (a median time), and the earliest expiry height of
	-- the payment's held parts.
	timeout           BIGINT,
	htlc_expiry       BIGINT,
	preimage          BYTEA CHECK (preimage IS NULL OR length(preimage) = 32),
	-- Whether the node has settled the held payment with the preimage.
	settled           BOOLEAN NOT NULL DEFAULT false,
	-- Whether the node has failed the held payment back.
	failed_back       BOOLEAN NOT NULL DEFAULT false,
	reason            TEXT,
	created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
	CHECK (state NOT IN ('accepted', 'claimed') OR (participation_id IS NOT NULL AND timeout IS NOT NULL)),
	CHECK ((state = 'claimed') = (preimage IS NOT NULL)),
	CHECK (NOT settled OR preimage IS NOT NULL),
	CHECK (NOT (settled AND failed_back))
);

-- The output of a received htlc-1 leaf on the chain is watched, so the
-- preimage its owner's claim reveals there is read and the held payment
-- settled with it.
ALTER TABLE watched_outpoint DROP CONSTRAINT watched_outpoint_kind_check;
ALTER TABLE watched_outpoint ADD CONSTRAINT watched_outpoint_kind_check CHECK (kind IN ('board', 'nursery', 'receive'));

-- The watcher refunds a received htlc-1 leaf whose owner never claimed it,
-- once its timeout and the operator's delay have passed.
ALTER TABLE watcher_tx DROP CONSTRAINT watcher_tx_kind_check;
ALTER TABLE watcher_tx ADD CONSTRAINT watcher_tx_kind_check CHECK (kind IN (
	'forfeit', 'issue', 'claim', 'checkpoint', 'reassignment', 'release', 'sweep', 'reclaim', 'unroll', 'entry',
	'unlock', 'offboard_reclaim', 'htlc_claim', 'htlc_refund'));
