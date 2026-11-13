-- The htlc-2 locks between two holders (arca_covenant::lock) the operator
-- co-signed: one row per lock leaf, written when the transfer making it is
-- recorded, and how the lock ended. The operator co-signs one ending of a
-- lock: the claim, with the preimage, before the timeout less its margin, or
-- the refund, from the timeout. `ended_by` is the transfer that ended it; a
-- transfer dropped before it was signed opens its lock again. The preimage
-- is kept once anyone hands it over, and served to both holders.
CREATE TABLE swap_lock (
	leaf_id      BYTEA PRIMARY KEY,
	payment_hash BYTEA NOT NULL,
	payee        BYTEA NOT NULL,
	payer        BYTEA NOT NULL,
	timeout      BIGINT NOT NULL,
	made_by      BYTEA NOT NULL,
	state        TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'claimed', 'refunded')),
	ended_by     BYTEA,
	preimage     BYTEA,
	created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX swap_lock_hash ON swap_lock (payment_hash);
