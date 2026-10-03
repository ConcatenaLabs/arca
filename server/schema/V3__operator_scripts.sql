-- The operator's own scripts the server watches the chain for, beside the
-- leaves, boards and checkpoints it records: its connector script, which
-- every round of this operator pays and nothing else does. A sighting of it
-- in a transaction that is not a round the database knows names a round the
-- database has lost (a restore from an older copy), and the server refuses
-- to serve until that is resolved. Such a row's leaf_id is all zeros.
ALTER TABLE arca_script DROP CONSTRAINT arca_script_kind_check;
ALTER TABLE arca_script ADD CONSTRAINT arca_script_kind_check CHECK (kind IN ('leaf', 'board', 'checkpoint', 'connector'));
