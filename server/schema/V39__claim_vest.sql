-- Claim leaves that vest (arca_covenant::claim, vest-1): a distribution that
-- names a vest time pays vest-1 leaves, which no path moves before it.

-- A vest-1 leaf's vest time, a median time; NULL for every other leaf
-- wanted. Only a leaf with a lapse vests.
ALTER TABLE participation_output ADD COLUMN vest INTEGER CHECK (vest IS NULL OR (claim IS NOT NULL AND vest > 0));
