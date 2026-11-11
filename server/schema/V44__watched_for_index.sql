-- The outpoints watched for one transaction or leaf, by what they are watched
-- for. The nursery reads the spends of its transaction's inputs this way
-- (`conflicting_spends`: kind 'nursery', watched_for = the transaction) for
-- every transaction it holds on every pass. The primary key leads with the
-- outpoint, so without this index each read scanned the whole table: a pass
-- cost in proportion to everything the operator ever watched, times what the
-- nursery holds.
CREATE INDEX IF NOT EXISTS watched_outpoint_watched_for ON watched_outpoint (watched_for, kind);
