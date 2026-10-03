-- The latest entry of the signer's record the database knew when a round
-- was built: published with the round's trees, so every wallet that reads
-- them holds a witness of the record outside the server.
ALTER TABLE round ADD COLUMN signer_entry BIGINT CHECK (signer_entry IS NULL OR signer_entry >= 0);
ALTER TABLE round ADD COLUMN signer_hash BYTEA CHECK (signer_hash IS NULL OR length(signer_hash) = 32);
