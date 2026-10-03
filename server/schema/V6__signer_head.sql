-- The latest entry of the signer's record the server was given: its number
-- and running hash. Every rebind request names it, and the signer signs
-- nothing when its record ends before it, or holds another entry there: the
-- record has then been cut back, replaced by an older copy, or written by two
-- signers. One row, or none before the first signature.
CREATE TABLE signer_head (
	one        BOOLEAN PRIMARY KEY DEFAULT true CHECK (one),
	entry      BIGINT NOT NULL CHECK (entry > 0),
	hash       BYTEA NOT NULL CHECK (length(hash) = 32),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
