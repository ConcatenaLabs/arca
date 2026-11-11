-- The coins a participation's wallet names as payments arriving: received
-- out of round and not yet counted as its own (past its instant limit), by
-- leaf id in hex, each one of the participation's inputs. A refresh whose
-- names the operator's records bear out runs ahead of other refreshes and
-- past the in-flight cap, up to twice it: its owner is waiting on that round
-- to have the payment at all.
ALTER TABLE participation ADD COLUMN IF NOT EXISTS arriving TEXT[] NOT NULL DEFAULT '{}';
