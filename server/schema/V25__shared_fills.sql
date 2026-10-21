-- Several takes of one order in one round. A take that says it accepts a
-- round filling its order together with other takes (`shared`) stands beside
-- other such takes of the same order, as long as all of them together leave
-- what the order's FILL leaf takes: no more than the order holds, and nothing
-- resting below its minimum lot. A take that does not say so takes the order
-- alone, as before.
ALTER TABLE participation_fill ADD COLUMN shared BOOLEAN NOT NULL DEFAULT false;

-- A round fills an order at input k once, for every take of it the round
-- runs: one row per take, several with the same k.
ALTER TABLE round_fill DROP CONSTRAINT round_fill_pkey;
ALTER TABLE round_fill DROP CONSTRAINT round_fill_round_id_participation_id_key;
ALTER TABLE round_fill ADD PRIMARY KEY (round_id, participation_id);
CREATE INDEX round_fill_by_order ON round_fill (round_id, k);
