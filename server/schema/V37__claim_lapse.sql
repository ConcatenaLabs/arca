-- Claim leaves that lapse (arca_covenant::claim, claim-1): a distribution
-- that names a deadline pays claim-1 leaves, whose lapse pays the payer's
-- return script what no holder took up by then.

-- A claim-1 leaf's lapse, as the store keeps it: the deadline (u32 LE, a
-- median time), the fee allowance (u64 LE), then the return script. NULL for
-- every other leaf wanted.
ALTER TABLE participation_output ADD COLUMN claim BYTEA CHECK (claim IS NULL OR length(claim) > 12);

-- The lapse that paid a claim leaf back to its payer: the transaction the
-- watcher published, which spends the leaf itself by its lapse path.
ALTER TABLE distribution_claim ADD COLUMN lapsed_in BYTEA CHECK (lapsed_in IS NULL OR length(lapsed_in) = 32);

-- The watcher's lapse of a claim leaf nobody took up by its deadline.
ALTER TABLE watcher_tx DROP CONSTRAINT watcher_tx_kind_check;
ALTER TABLE watcher_tx ADD CONSTRAINT watcher_tx_kind_check CHECK (kind IN (
	'forfeit', 'issue', 'claim', 'checkpoint', 'reassignment', 'release', 'sweep', 'reclaim', 'unroll', 'entry',
	'unlock', 'offboard_reclaim', 'htlc_claim', 'htlc_refund', 'refund', 'fill', 'landing', 'channel_update', 'lapse'));
