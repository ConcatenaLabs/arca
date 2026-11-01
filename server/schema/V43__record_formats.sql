-- The leaf record formats a participation's wallet names as ones it reads
-- (`arca_covenant::RECORD_FORMATS`), such as `accumulator-4`. The round
-- builder puts each leaf the participation wants only into a batch whose
-- record it reads: a participation that names none (a wallet older than the
-- field, or one the server made for a holder it cannot ask) is taken to read
-- those every wallet reads (`arca_covenant::FORMATS_EVERY_WALLET_READS`), so
-- its leaves go into a tree in a round of batches without a sweep, and never
-- into a slot of an accumulator batch, whose forfeits it could never sign.
ALTER TABLE participation ADD COLUMN IF NOT EXISTS record_formats TEXT[] NOT NULL DEFAULT '{}';
