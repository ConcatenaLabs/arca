-- What the passes that find a final transaction no longer final read
-- (`nursery_final_not_final`, `boards_credited_not_final`,
-- `rounds_final_not_final`, through `chain::unfinal_with`): the blocks that
-- fail a test of finality (those above the highest certified block, by the
-- height key, and those whose anchor is not yet buried, by anchor height),
-- the watched transactions those blocks hold (by block), and, for the
-- anti-join that finds one in no block, the transactions held final as
-- indexes of their own. Without them each pass joined every final
-- transaction to its block and sorted them all, a cost in proportion to
-- everything the operator ever held. The index by block also serves a
-- rollback, which reads and deletes the rows of the block it takes out.
CREATE INDEX IF NOT EXISTS tx_block_by_block ON tx_block (block_hash);
CREATE INDEX IF NOT EXISTS block_by_anchor ON block (anchor_height);
CREATE INDEX IF NOT EXISTS nursery_tx_final ON nursery_tx (txid) WHERE state = 'final';
CREATE INDEX IF NOT EXISTS board_credited ON board (txid) WHERE state = 'credited';
CREATE INDEX IF NOT EXISTS round_final ON round (txid) WHERE state = 'final';
