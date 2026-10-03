-- Every rebindable message the server asks the signer to sign, recorded
-- before it asks and in the same transaction as what the signature is for: a
-- transfer's two messages for each coin with the transfer, a forfeit's with
-- the forfeit. At start, every entry of the signer's record after the latest
-- one the database was given must be one of these: an entry the database
-- does not know means the database is older than what the signer has signed,
-- and the server does not start on it.
CREATE TABLE signer_message (
	owner      BYTEA NOT NULL CHECK (length(owner) = 32),
	salt       BYTEA NOT NULL CHECK (length(salt) = 32),
	digest     BYTEA NOT NULL CHECK (length(digest) = 32),
	kind       TEXT NOT NULL CHECK (kind IN ('spend', 'forfeit')),
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (owner, salt, digest)
);

-- A forfeit is stored, with its owner's half, before the signer is asked for
-- the operator's, which is filled in once signed: a forfeit the signer may
-- have signed is never one the database has not heard of.
ALTER TABLE forfeit ALTER COLUMN operator_sig DROP NOT NULL;
CREATE INDEX forfeit_unsigned ON forfeit (participation_id) WHERE operator_sig IS NULL;
