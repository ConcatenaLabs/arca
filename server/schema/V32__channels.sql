-- channel-1 (`channels.rs`): a leaf with a balance for each of owner and
-- operator.
--
-- A leaf wanted under channel-1: its terms, the operator's opening balance
-- (u64) and the credit window in 512-second units (u16), little-endian, as
-- the leaf record writes them.
ALTER TABLE participation_output ADD COLUMN channel BYTEA
	CHECK (channel IS NULL OR (kind = 'leaf' AND length(channel) = 10));

-- Each state of a channel past its opening, as the owner signed it and the
-- operator co-signs it. A state is recorded before the signer is asked, its
-- operator signature empty until the signer answers, so a request repeated
-- after an outage completes the same state, and no other takes its number.
-- A payment out of the channel names the channel it pays and the amount;
-- the receiver's note it made is in channel_note under the same request.
CREATE TABLE channel_state (
	leaf_id          BYTEA NOT NULL CHECK (length(leaf_id) = 32),
	number           BIGINT NOT NULL CHECK (number > 0),
	owner_balance    BIGINT NOT NULL CHECK (owner_balance >= 0),
	operator_balance BIGINT NOT NULL CHECK (operator_balance >= 0),
	folded           BIGINT NOT NULL CHECK (folded >= 0),
	owner_sig        BYTEA NOT NULL CHECK (length(owner_sig) = 64),
	operator_sig     BYTEA CHECK (operator_sig IS NULL OR length(operator_sig) = 64),
	pays             BYTEA CHECK (pays IS NULL OR length(pays) = 32),
	amount           BIGINT NOT NULL DEFAULT 0 CHECK (amount >= 0),
	created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (leaf_id, number)
);

-- Each credit note the operator signs a channel: the cumulative credit, and
-- the operator's signature, empty until the signer answers. `by` names the
-- payer's channel and state that made it.
CREATE TABLE channel_note (
	leaf_id    BYTEA NOT NULL CHECK (length(leaf_id) = 32),
	credit     BIGINT NOT NULL CHECK (credit > 0),
	signature  BYTEA CHECK (signature IS NULL OR length(signature) = 64),
	by_leaf    BYTEA NOT NULL CHECK (length(by_leaf) = 32),
	by_number  BIGINT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (leaf_id, credit)
);
CREATE UNIQUE INDEX channel_note_by ON channel_note (by_leaf, by_number);

-- The watcher's answer to an older state of a live channel coin on the
-- chain: the latest state both sides signed, published over it.
ALTER TABLE watcher_tx DROP CONSTRAINT watcher_tx_kind_check;
ALTER TABLE watcher_tx ADD CONSTRAINT watcher_tx_kind_check CHECK (kind IN (
	'forfeit', 'issue', 'claim', 'checkpoint', 'reassignment', 'release', 'sweep', 'reclaim', 'unroll', 'entry',
	'unlock', 'offboard_reclaim', 'htlc_claim', 'htlc_refund', 'refund', 'fill', 'landing', 'channel_update'));
