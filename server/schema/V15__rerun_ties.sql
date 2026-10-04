-- A round that runs again the participations of a round that went out of the
-- chain spends a coin that keeps the two apart: an input of the lost round
-- that is still unspent, or an output of a transaction that took one (or of
-- one descending from it through the operator's own coins). Whatever the
-- parent chain does, at most one of the two is in the chain. Each row is one
-- such coin: the round that spends it, the lost round it keeps out, and,
-- when it is not an input of the lost round, the transaction that took one.
CREATE TABLE round_rerun (
	round_id BIGINT NOT NULL REFERENCES round,
	replaces BIGINT NOT NULL REFERENCES round,
	tie_txid BYTEA NOT NULL CHECK (length(tie_txid) = 32),
	tie_vout INTEGER NOT NULL CHECK (tie_vout >= 0),
	via_txid BYTEA CHECK (via_txid IS NULL OR length(via_txid) = 32),
	PRIMARY KEY (round_id, replaces)
);
CREATE INDEX round_rerun_by_replaced ON round_rerun (replaces);
