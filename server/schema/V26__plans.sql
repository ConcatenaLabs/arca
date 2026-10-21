-- Offline refresh: a plan a holder pre-signs so that the operator refreshes
-- one coin in later rounds without it (`plans.rs`, `arca_covenant::plan`).
--
-- Step i gives up the holder's coin L(i-1) for a new leaf L(i), which the
-- step's participation wants under the plan's owner key, owner nonce,
-- operator nonce and unlock hash, in a round near L(i-1)'s exit deadline.
-- In place of the forfeit the holder could not sign in advance, the operator
-- holds the step's refund: the holder's halves over L(i-1)'s and L(i)'s
-- collaborative paths, both committing to v(i) at the holder's address and
-- the rest less a margin at the operator's script.

-- A plan's quote: the operator nonces it drew are taken by the quote (in
-- operator_nonce.used_by) until a plan names them, and the script it named
-- for the operator's share of every refund.
CREATE TABLE plan_quote (
	quote_id        BYTEA PRIMARY KEY CHECK (length(quote_id) = 32),
	operator_script BYTEA NOT NULL CHECK (length(operator_script) > 0),
	created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- open: steps remain and the operator runs them;
-- done: every step ran;
-- cancelled: the holder cancelled the steps left;
-- stopped: a step can never run (its coin gone, its round lost); the steps
--   after it never run, and the coin it would have given up is the holder's.
CREATE TYPE plan_state AS ENUM ('open', 'done', 'cancelled', 'stopped');

CREATE TABLE plan (
	plan_id      BYTEA PRIMARY KEY CHECK (length(plan_id) = 32),
	-- L(0), the coin the plan starts from, and what the refund of step 1
	-- needs of it: its owner key, its salt and its exit delay.
	coin         BYTEA NOT NULL REFERENCES leaf,
	asset        BYTEA NOT NULL CHECK (length(asset) = 32),
	value        BIGINT NOT NULL CHECK (value > 0),
	first_owner  BYTEA NOT NULL CHECK (length(first_owner) = 32),
	first_salt   BYTEA NOT NULL CHECK (length(first_salt) = 32),
	first_delay  INTEGER NOT NULL CHECK (first_delay > 0),
	-- The mailbox key every leaf of the plan is bound to.
	mailbox_key  BYTEA NOT NULL CHECK (length(mailbox_key) = 32),
	-- L(0)'s owner's signature over the plan's id.
	attestation  BYTEA NOT NULL CHECK (length(attestation) = 64),
	state        plan_state NOT NULL DEFAULT 'open',
	reason       TEXT,
	created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- A coin starts one open plan at a time.
CREATE UNIQUE INDEX plan_open_coin ON plan (coin) WHERE state = 'open';
CREATE INDEX plan_by_mailbox ON plan (mailbox_key);

-- waiting: not yet run;
-- running: its participation is pending or in a round;
-- done: its round is final and its leaf credited;
-- void: it can never run.
CREATE TYPE plan_step_state AS ENUM ('waiting', 'running', 'done', 'void');

CREATE TABLE plan_step (
	plan_id          BYTEA NOT NULL REFERENCES plan,
	idx              SMALLINT NOT NULL CHECK (idx >= 1),
	-- L(i): what it holds, the fee the step costs, its owner key and both
	-- nonces of its salt, its exit delay, and the hash its entry is locked
	-- to with the preimage the holder handed over.
	value            BIGINT NOT NULL CHECK (value > 0),
	fee              BIGINT NOT NULL CHECK (fee >= 0),
	owner_key        BYTEA NOT NULL UNIQUE CHECK (length(owner_key) = 32),
	owner_nonce      BYTEA NOT NULL CHECK (length(owner_nonce) = 32),
	operator_nonce   BYTEA NOT NULL UNIQUE REFERENCES operator_nonce,
	exit_delay_units INTEGER NOT NULL CHECK (exit_delay_units > 0),
	unlock_hash      BYTEA NOT NULL UNIQUE CHECK (length(unlock_hash) = 32),
	preimage         BYTEA NOT NULL CHECK (length(preimage) = 32),
	-- The refund: the holder's address, the operator's script, the margin,
	-- and the holder's two halves.
	holder_script    BYTEA NOT NULL,
	operator_script  BYTEA NOT NULL,
	margin           BIGINT NOT NULL CHECK (margin > 0),
	old_half         BYTEA NOT NULL CHECK (length(old_half) = 64),
	new_half         BYTEA NOT NULL CHECK (length(new_half) = 64),
	-- A(i)'s signature over the plan's key digest, and its binding to the
	-- plan's mailbox key.
	key_proof        BYTEA NOT NULL CHECK (length(key_proof) = 64),
	mailbox_proof    BYTEA NOT NULL CHECK (length(mailbox_proof) = 64),
	participation_id BYTEA UNIQUE REFERENCES participation,
	state            plan_step_state NOT NULL DEFAULT 'waiting',
	reason           TEXT,
	updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (plan_id, idx),
	CHECK ((state = 'waiting') = (participation_id IS NULL) OR state = 'void')
);

-- The refund of a plan's step, which the watcher publishes when a coin the
-- step gave up comes on the chain.
ALTER TABLE watcher_tx DROP CONSTRAINT watcher_tx_kind_check;
ALTER TABLE watcher_tx ADD CONSTRAINT watcher_tx_kind_check CHECK (kind IN (
	'forfeit', 'issue', 'claim', 'checkpoint', 'reassignment', 'release', 'sweep', 'reclaim', 'unroll', 'entry',
	'unlock', 'offboard_reclaim', 'htlc_claim', 'htlc_refund', 'refund'));
