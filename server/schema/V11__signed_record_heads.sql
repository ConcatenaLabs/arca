-- The signer's signature over each head of its record the server hands
-- out (`server::signer::record_head_digest`): the latest the database was
-- given, each round's, and each transfer's, the entry of the record its
-- last signature was recorded as. A wallet keeps a head only with that
-- signature, and hands it back on every contact; one the record does not
-- hold proves a rollback, and stops the signer.
ALTER TABLE signer_head ADD COLUMN signature BYTEA CHECK (signature IS NULL OR length(signature) = 64);
ALTER TABLE round ADD COLUMN signer_sig BYTEA CHECK (signer_sig IS NULL OR length(signer_sig) = 64);
ALTER TABLE transfer ADD COLUMN signer_entry BIGINT CHECK (signer_entry IS NULL OR signer_entry > 0);
ALTER TABLE transfer ADD COLUMN signer_hash BYTEA CHECK (signer_hash IS NULL OR length(signer_hash) = 32);
ALTER TABLE transfer ADD COLUMN signer_sig BYTEA CHECK (signer_sig IS NULL OR length(signer_sig) = 64);
