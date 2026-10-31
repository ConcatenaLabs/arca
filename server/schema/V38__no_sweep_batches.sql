-- A batch without a sweep issues no token: its schedule names the one token
-- of every such batch, SHA256("Arca/no-sweep"), which no issuance creates and
-- no script names. Every other batch's token is still its own.
ALTER TABLE batch DROP CONSTRAINT IF EXISTS batch_token_key;
CREATE UNIQUE INDEX IF NOT EXISTS batch_token_issued ON batch (token)
	WHERE token <> '\xf69bd5c2240b32ea12609b16d05d2fcf53894f2e6b60eda0d229647f4feccf13'::bytea;

-- The service horizon of a batch without a sweep: the median time from which
-- the operator collects it on the chain and co-signs no off-chain spend of a
-- coin resting on it. None for a batch with a sweep, whose clock bounds it.
ALTER TABLE batch ADD COLUMN IF NOT EXISTS collect_mtp BIGINT CHECK (collect_mtp >= 0);
