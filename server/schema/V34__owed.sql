-- What the operator owes for the coins its sweeps took.
--
-- A sweep of an expired batch takes every coin left in it, and the operator
-- repays each coin that was still its holder's (live, neither given up nor
-- on the chain) as a new leaf in the asset's next round, less the published
-- late-refresh fee. An entry is recorded, for every such coin of a sweep at
-- once, when that sweep is final; a rollback that takes the sweep out of
-- finality withdraws its entries until it is final again. Entries never
-- expire.

-- Each sweep whose coins were counted: final, or withdrawn while a rollback
-- keeps it from being final.
CREATE TABLE owed_sweep (
	txid        BYTEA PRIMARY KEY REFERENCES watcher_tx,
	state       TEXT NOT NULL CHECK (state IN ('final', 'withdrawn')),
	recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One entry per coin a sweep took from its holder: the coin's owner key and
-- the nonce it comes from, its asset and value, the fee taken from it and
-- what is owed. owed: not yet claimed; claimed: a repayment participation
-- wants its new leaf; repaid: that participation is released.
CREATE TABLE owed (
	leaf_id          BYTEA PRIMARY KEY REFERENCES leaf,
	sweep_txid       BYTEA NOT NULL REFERENCES owed_sweep,
	owner_key        BYTEA NOT NULL CHECK (length(owner_key) = 32),
	owner_nonce      BYTEA NOT NULL CHECK (length(owner_nonce) = 32),
	asset            BYTEA NOT NULL CHECK (length(asset) = 32),
	value            BIGINT NOT NULL CHECK (value > 0),
	fee              BIGINT NOT NULL CHECK (fee >= 0 AND fee < value),
	state            TEXT NOT NULL CHECK (state IN ('owed', 'claimed', 'repaid')),
	participation_id BYTEA REFERENCES participation,
	created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
	CHECK ((state = 'owed') = (participation_id IS NULL))
);
CREATE INDEX owed_by_owner ON owed (owner_key);
CREATE INDEX owed_by_sweep ON owed (sweep_txid);
CREATE UNIQUE INDEX owed_by_participation ON owed (participation_id) WHERE participation_id IS NOT NULL;
