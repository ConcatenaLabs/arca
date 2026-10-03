-- Why a pending participation did not run in the last round that could have
-- taken it (the operator's wallet could not fund its outputs, say); empty
-- once a round takes it.
ALTER TABLE participation ADD COLUMN waiting TEXT;
