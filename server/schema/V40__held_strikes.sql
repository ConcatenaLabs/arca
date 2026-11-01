-- Coins kept out of shared held rounds (rounds that fill orders, or hold a
-- batch without a sweep, which go out only once every forfeit is in). A
-- participation whose forfeits did not come within the window is voided and
-- its round dropped; each coin it gave up is struck here (and a coin paid on
-- from one is caught through its lineage: see V41). A participation giving up a struck coin
-- waits until `until_mtp`, then runs only in a round of its own, so it never
-- holds back anyone else's; each strike doubles the wait. A round that goes
-- out with it clears the strike.
CREATE TABLE IF NOT EXISTS held_strike (
	leaf_id BYTEA PRIMARY KEY CHECK (length(leaf_id) = 32),
	strikes INTEGER NOT NULL CHECK (strikes > 0),
	until_mtp BIGINT NOT NULL CHECK (until_mtp >= 0)
);
