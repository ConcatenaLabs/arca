-- The coin record formats a resting order's maker names as ones its wallet
-- reads (`arca_covenant::RECORD_FORMATS`), served with the order's state. A
-- taker asks for checkpoints with their owners' exit, and gives coins whose
-- record is of the newer format, only against a maker that reads `coin-2`;
-- an order published by an older build names none.
ALTER TABLE resting_order ADD COLUMN IF NOT EXISTS record_formats TEXT[] NOT NULL DEFAULT '{}';
