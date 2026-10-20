-- Each on-chain order a round fills: the covenant at input k, credited at
-- output 2k and resting again at 2k+1 after a partial fill, for the take
-- (a participation, at its attempt) the round runs.
CREATE TABLE round_fill (
	round_id         BIGINT NOT NULL REFERENCES round,
	k                INTEGER NOT NULL CHECK (k >= 0),
	participation_id BYTEA NOT NULL REFERENCES participation,
	attempt          INTEGER NOT NULL CHECK (attempt >= 0),
	PRIMARY KEY (round_id, k),
	UNIQUE (round_id, participation_id)
);
CREATE INDEX round_fill_by_participation ON round_fill (participation_id, attempt);
