-- A distribution: a participation that pays many holders in one round, each
-- an ordinary vtxo-1 leaf under the claim key of a key the payer names
-- (arca_covenant::claim: the named key tweaked by the claim's nonce, which is
-- the leaf's owner nonce). Its participation_output rows are the claim
-- leaves; this row adds where the operator pays what no holder takes up.
CREATE TABLE distribution (
	participation_id BYTEA PRIMARY KEY REFERENCES participation,
	-- The explicit output the unclaimed sum is paid to, in the
	-- distribution's asset.
	return_script    BYTEA NOT NULL CHECK (length(return_script) > 0),
	created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Each payment of unclaimed leaves to a distribution's payer: recorded with
-- its transaction before the nursery broadcasts it, so a restart sends the
-- same bytes again.
CREATE TABLE distribution_return (
	txid             BYTEA PRIMARY KEY CHECK (length(txid) = 32),
	participation_id BYTEA NOT NULL REFERENCES distribution,
	value            BIGINT NOT NULL CHECK (value > 0),
	tx               BYTEA NOT NULL,
	fee_asset        BYTEA NOT NULL CHECK (length(fee_asset) = 32),
	fee              BIGINT NOT NULL CHECK (fee >= 0),
	created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX distribution_return_by_distribution ON distribution_return (participation_id);

-- Each claim: the participation output that is its leaf, and the key the
-- payer named, by which a holder asks for it.
CREATE TABLE distribution_claim (
	participation_id BYTEA NOT NULL REFERENCES distribution,
	idx              SMALLINT NOT NULL CHECK (idx >= 0),
	named_key        BYTEA NOT NULL CHECK (length(named_key) = 32),
	-- The operator's payment that returned this claim's value to the payer,
	-- once a final sweep took the leaf with no spend of it recorded.
	returned_in      BYTEA REFERENCES distribution_return (txid),
	PRIMARY KEY (participation_id, idx),
	FOREIGN KEY (participation_id, idx) REFERENCES participation_output (participation_id, idx)
);
CREATE INDEX distribution_claim_by_key ON distribution_claim (named_key);
