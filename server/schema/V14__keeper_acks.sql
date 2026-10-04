-- The keepers' acknowledgements of the heads of the signer's record the
-- server is handed: each keeper's key, the nonce of the request it answered
-- and its signature over the head and that nonce
-- (`server::keeper::ack_digest`). They travel with the head wherever it
-- goes (`info`, a witness, a transfer's answer, a mailbox record, a
-- published tree), and a wallet that pinned the keepers keeps no head and
-- takes no coin without them.
CREATE TABLE record_head_ack (
	entry BIGINT NOT NULL CHECK (entry >= 0),
	hash BYTEA NOT NULL CHECK (length(hash) = 32),
	keeper BYTEA NOT NULL CHECK (length(keeper) = 32),
	nonce BYTEA NOT NULL CHECK (length(nonce) = 32),
	signature BYTEA NOT NULL CHECK (length(signature) = 64),
	PRIMARY KEY (entry, hash, keeper)
);
