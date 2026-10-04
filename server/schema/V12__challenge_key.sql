-- The key of every challenge's keyed check (`server::auth`), drawn once and
-- kept, so a challenge issued before a restart, or by another server on the
-- same database, is taken. One row.
CREATE TABLE challenge_key (
	one        BOOLEAN PRIMARY KEY DEFAULT true CHECK (one),
	key        BYTEA NOT NULL CHECK (length(key) = 32),
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
