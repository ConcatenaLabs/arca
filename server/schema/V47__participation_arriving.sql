-- The coins a participation's wallet names as payments arriving: received
-- out of round and not yet counted as its own (past its instant limit), by
-- leaf id in hex, each one of the participation's inputs. A refresh that
-- gives up only coins received out of round and names some as arriving runs
-- ahead of other refreshes and is not held by the in-flight cap: its owner
-- is waiting on that round to have the payment at all.
ALTER TABLE participation ADD COLUMN IF NOT EXISTS arriving TEXT[] NOT NULL DEFAULT '{}';
