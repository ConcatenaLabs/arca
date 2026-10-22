-- The operator's landing of a resting order whose maker is away at its
-- coin's exit deadline (`watcher.rs`): the coin moved whole into SeqDEX's
-- order for the same terms.
ALTER TABLE watcher_tx DROP CONSTRAINT watcher_tx_kind_check;
ALTER TABLE watcher_tx ADD CONSTRAINT watcher_tx_kind_check CHECK (kind IN (
	'forfeit', 'issue', 'claim', 'checkpoint', 'reassignment', 'release', 'sweep', 'reclaim', 'unroll', 'entry',
	'unlock', 'offboard_reclaim', 'htlc_claim', 'htlc_refund', 'refund', 'fill', 'landing'));
