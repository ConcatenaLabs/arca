-- Re-serving a wallet's leaves to the key it restores with.
--
-- A wallet draws a fresh owner nonce, and so a fresh key, for every leaf, and
-- a wallet restored from its mnemonic alone knows none of those nonces. What
-- it does know is its mailbox key, which follows from the mnemonic and the
-- account. So each leaf the wallet asks for names that key, and the leaf's
-- owner key signs that it does (`auth::mailbox_binding_digest`): a board when
-- it is registered, a leaf a participation wants when it is submitted, any
-- leaf the wallet holds later (`bind_mailbox`). A transfer's output names its
-- receiver's mailbox already (`transfer_output.mailbox_key`). `leaf_data`
-- then serves, to a caller proving the mailbox key, every leaf whose owner key
-- is bound to it, and every transfer output posted to it. One owner key, one
-- binding: a key owns one leaf, and the leaves a participation run again
-- makes under the same keys share it.
CREATE TABLE leaf_mailbox (
	owner_key   BYTEA PRIMARY KEY CHECK (length(owner_key) = 32),
	mailbox_key BYTEA NOT NULL CHECK (length(mailbox_key) = 32),
	-- The owner key's BIP340 signature over the binding.
	proof       BYTEA NOT NULL CHECK (length(proof) = 64),
	bound_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX leaf_mailbox_by_mailbox ON leaf_mailbox (mailbox_key);
CREATE INDEX transfer_output_by_mailbox ON transfer_output (mailbox_key);
CREATE INDEX leaf_by_owner ON leaf (owner_key);

-- The order the server learned of each leaf in: the cursor `leaf_data` pages
-- by. Rows already there are numbered as they lie.
ALTER TABLE leaf ADD COLUMN seq BIGSERIAL;
CREATE UNIQUE INDEX leaf_seq ON leaf (seq);
